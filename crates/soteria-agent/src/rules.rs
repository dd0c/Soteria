//! Keep the `rules` table in step with the rules in effect, so the database
//! records which rule definitions and versions raised past alerts.

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use soteria_core::Severity;
use soteria_rules::RuleSet;
use soteria_store::now;

/// Record each rule's definition, bumping its version when it changed, and
/// mark rules that no longer exist as disabled. Changes are recorded as a
/// `rules.changed` event. Returns the ids that changed.
pub fn sync(conn: &Connection, rules: &RuleSet) -> rusqlite::Result<Vec<String>> {
    let ts = now();
    let tx = conn.unchecked_transaction()?;
    let mut changed = Vec::new();
    for r in rules.iter() {
        let definition = r.definition().to_string();
        let existing: Option<(i64, String)> = tx
            .query_row(
                "SELECT version, definition FROM rules WHERE id = ?1",
                [&r.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let version = match existing {
            Some((_, d)) if d == definition => continue,
            Some((v, _)) => v + 1,
            None => 1,
        };
        // The column needs one severity; rules whose severity varies with
        // the object record their usual one (the definition has the rest).
        let severity = r.severity.unwrap_or(Severity::Medium);
        tx.execute(
            "INSERT INTO rules (id, version, source, enabled, severity, definition, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET version = ?2, source = ?3, enabled = ?4, severity = ?5,
                                           definition = ?6, updated_at = ?7",
            params![
                r.id,
                version,
                r.origin.as_str(),
                r.enabled,
                severity.as_str(),
                definition,
                ts
            ],
        )?;
        if version > 1 || r.origin == soteria_rules::Origin::Admin || !r.enabled {
            changed.push(r.id.clone());
        }
    }
    // Rules removed from the rule files.
    let stale: Vec<String> = {
        let mut st = tx.prepare("SELECT id FROM rules WHERE enabled = 1")?;
        st.query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter(|id| rules.get(id).is_none())
            .collect()
    };
    for id in &stale {
        tx.execute(
            "UPDATE rules SET enabled = 0, version = version + 1, updated_at = ?2 WHERE id = ?1",
            params![id, ts],
        )?;
        changed.push(id.clone());
    }
    if !changed.is_empty() {
        crate::alerts::record_event(
            &tx,
            "agent",
            "rules.changed",
            Severity::Info,
            None,
            &json!({ "rules": changed, "files": rules.files }),
        )?;
    }
    tx.commit()?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria_store::Store;
    use std::path::Path;

    #[test]
    fn versions_follow_definition_changes() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = Store::create_or_migrate(&d.path().join("db")).unwrap();
        let c = s.connection();
        let builtin = RuleSet::builtin();
        assert!(
            sync(c, &builtin).unwrap().is_empty(),
            "first sync of defaults is not a change"
        );
        assert!(sync(c, &builtin).unwrap().is_empty());

        let mut admin = RuleSet::builtin();
        admin
            .add_toml(
                Path::new("/r.toml"),
                "[[override]]\nrule = \"FIM-011\"\nenabled = false\n\
                 [[rule]]\nid = \"L-1\"\ntitle = \"t\"\non = \"file\"\nseverity = \"high\"\npaths = [\"/etc/x\"]\n",
            )
            .unwrap();
        let changed = sync(c, &admin).unwrap();
        assert_eq!(changed, ["FIM-011", "L-1"]);
        let v: i64 = c
            .query_row("SELECT version FROM rules WHERE id = 'FIM-011'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(v, 2);

        // Removing the rule file disables the admin rule and restores FIM-011.
        let changed = sync(c, &builtin).unwrap();
        assert_eq!(changed, ["FIM-011", "L-1"]);
        let (enabled, v): (bool, i64) = c
            .query_row(
                "SELECT enabled, version FROM rules WHERE id = 'L-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(!enabled);
        assert_eq!(v, 2);
    }
}
