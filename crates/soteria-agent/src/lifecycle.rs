//! Alert lifecycle (FR-030): status changes, notes and suppressions.
//!
//! Evidence never changes: the schema rejects updates to it, and every
//! change is appended to `alert_history` with who made it.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::json;
use soteria_core::Severity;
use soteria_store::now;

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("no alert with id {0}")]
    NoSuchAlert(i64),
    #[error("no suppression with id {0}")]
    NoSuchSuppression(i64),
    #[error("alert {id} is already {status}")]
    Unchanged { id: i64, status: String },
    #[error("a note cannot be empty")]
    EmptyNote,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, LifecycleError>;

/// Statuses an administrator can set directly. `suppressed` is set by
/// [`suppress`], which also records why.
pub const SETTABLE: [&str; 4] = ["open", "acknowledged", "investigated", "closed"];

fn status_of(conn: &Connection, id: i64) -> Result<String> {
    conn.query_row("SELECT status FROM alerts WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .optional()?
    .ok_or(LifecycleError::NoSuchAlert(id))
}

/// Change an alert's status, optionally with a note. Returns the previous
/// status.
pub fn set_status(
    conn: &Connection,
    id: i64,
    to: &str,
    actor: &str,
    note: Option<&str>,
) -> Result<String> {
    let from = status_of(conn, id)?;
    if from == to {
        return Err(LifecycleError::Unchanged { id, status: from });
    }
    let ts = now();
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "UPDATE alerts SET status = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, to, ts],
    )?;
    tx.execute(
        "INSERT INTO alert_history (alert_id, ts, actor, action, from_status, to_status, note)
         VALUES (?1, ?2, ?3, 'status', ?4, ?5, ?6)",
        params![
            id,
            ts,
            actor,
            from,
            to,
            note.map(str::trim).filter(|n| !n.is_empty())
        ],
    )?;
    tx.commit()?;
    Ok(from)
}

pub fn add_note(conn: &Connection, id: i64, actor: &str, note: &str) -> Result<()> {
    status_of(conn, id)?;
    let note = note.trim();
    if note.is_empty() {
        return Err(LifecycleError::EmptyNote);
    }
    let ts = now();
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "UPDATE alerts SET updated_at = ?2 WHERE id = ?1",
        params![id, ts],
    )?;
    tx.execute(
        "INSERT INTO alert_history (alert_id, ts, actor, action, note) VALUES (?1, ?2, ?3, 'note', ?4)",
        params![id, ts, actor, note],
    )?;
    tx.commit()?;
    Ok(())
}

/// What a suppression covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The same rule on the same object (file or program).
    Object,
    /// The same rule on any object.
    Rule,
}

/// A stored suppression.
#[derive(Debug, Clone, Serialize)]
pub struct Suppression {
    pub id: i64,
    pub created_at: String,
    pub created_by: String,
    pub rule_id: Option<String>,
    pub object: Option<String>,
    pub reason: String,
    pub expires_at: Option<String>,
    pub enabled: bool,
}

/// Suppress a known benign detection (FR-030): mark the alert suppressed
/// and stop raising the same detection. Returns the suppression id.
pub fn suppress(
    conn: &Connection,
    alert_id: i64,
    actor: &str,
    reason: &str,
    scope: Scope,
    expires_at: Option<&str>,
) -> Result<i64> {
    let (rule_id, object, status): (String, Option<String>, String) = conn
        .query_row(
            "SELECT rule_id, object, status FROM alerts WHERE id = ?1",
            [alert_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .ok_or(LifecycleError::NoSuchAlert(alert_id))?;
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(LifecycleError::EmptyNote);
    }
    let matcher = match scope {
        Scope::Object => json!({ "object": object }),
        Scope::Rule => json!({}),
    };
    let ts = now();
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "INSERT INTO suppression_rules (created_at, created_by, rule_id, matcher, reason, expires_at, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
        params![ts, actor, rule_id, matcher.to_string(), reason, expires_at],
    )?;
    let sid = tx.last_insert_rowid();
    if status != "suppressed" {
        tx.execute(
            "UPDATE alerts SET status = 'suppressed', updated_at = ?2 WHERE id = ?1",
            params![alert_id, ts],
        )?;
        tx.execute(
            "INSERT INTO alert_history (alert_id, ts, actor, action, from_status, to_status, note)
             VALUES (?1, ?2, ?3, 'status', ?4, 'suppressed', ?5)",
            params![
                alert_id,
                ts,
                actor,
                status,
                format!("suppression {sid}: {reason}")
            ],
        )?;
    }
    tx.commit()?;
    Ok(sid)
}

/// Disable a suppression. Alerts it suppressed keep their status.
pub fn unsuppress(conn: &Connection, id: i64, actor: &str) -> Result<()> {
    let n = conn.execute(
        "UPDATE suppression_rules SET enabled = 0 WHERE id = ?1 AND enabled = 1",
        [id],
    )?;
    if n == 0 {
        return Err(LifecycleError::NoSuchSuppression(id));
    }
    crate::alerts::record_event(
        conn,
        "admin",
        "suppression.removed",
        Severity::Info,
        None,
        &json!({ "suppression": id, "actor": actor }),
    )?;
    Ok(())
}

pub fn suppressions(conn: &Connection, include_disabled: bool) -> Result<Vec<Suppression>> {
    let mut stmt = conn.prepare(
        "SELECT id, created_at, created_by, rule_id, matcher, reason, expires_at, enabled
         FROM suppression_rules WHERE (?1 OR enabled = 1) ORDER BY id",
    )?;
    let rows = stmt.query_map([include_disabled], |r| {
        let matcher: String = r.get(4)?;
        let object = serde_json::from_str::<serde_json::Value>(&matcher)
            .ok()
            .and_then(|m| m.get("object").and_then(|o| o.as_str().map(str::to_owned)));
        Ok(Suppression {
            id: r.get(0)?,
            created_at: r.get(1)?,
            created_by: r.get(2)?,
            rule_id: r.get(3)?,
            object,
            reason: r.get(5)?,
            expires_at: r.get(6)?,
            enabled: r.get::<_, i64>(7)? == 1,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The active suppression covering this detection, if any.
pub fn suppressed_by(
    conn: &Connection,
    rule_id: &str,
    object: &str,
) -> rusqlite::Result<Option<i64>> {
    conn.prepare_cached(
        "SELECT id FROM suppression_rules
         WHERE enabled = 1 AND (rule_id IS NULL OR rule_id = ?1)
           AND (expires_at IS NULL OR expires_at > ?3)
           AND (json_extract(matcher, '$.object') IS NULL OR json_extract(matcher, '$.object') = ?2)
         ORDER BY id LIMIT 1",
    )?
    .query_row(params![rule_id, object, now()], |r| r.get(0))
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria_store::Store;

    fn setup() -> (tempfile::TempDir, Store, i64) {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = Store::create_or_migrate(&d.path().join("db")).unwrap();
        s.connection()
            .execute(
                "INSERT INTO alerts (uuid, created_at, updated_at, severity, type, status, hostname, object, rule_id,
                                     reason, evidence, recommendation)
                 VALUES ('u1', 't', 't', 'high', 'execution', 'open', 'h', '/tmp/x', 'EXE-001', 'r', '{}', 'rec')",
                [],
            )
            .unwrap();
        let id = s.connection().last_insert_rowid();
        (d, s, id)
    }

    fn history(s: &Store, id: i64) -> Vec<(String, Option<String>, Option<String>)> {
        let mut st = s
            .connection()
            .prepare(
                "SELECT action, to_status, note FROM alert_history WHERE alert_id = ?1 ORDER BY id",
            )
            .unwrap();
        st.query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn status_changes_and_notes_are_recorded() {
        let (_d, s, id) = setup();
        let c = s.connection();
        assert_eq!(
            set_status(c, id, "acknowledged", "alice", Some("looking")).unwrap(),
            "open"
        );
        assert!(matches!(
            set_status(c, id, "acknowledged", "alice", None),
            Err(LifecycleError::Unchanged { .. })
        ));
        add_note(c, id, "bob", "  it was the backup job  ").unwrap();
        assert!(matches!(
            add_note(c, id, "bob", " "),
            Err(LifecycleError::EmptyNote)
        ));
        assert!(matches!(
            set_status(c, 999, "closed", "a", None),
            Err(LifecycleError::NoSuchAlert(999))
        ));
        let h = history(&s, id);
        assert_eq!(
            h[0],
            (
                "status".into(),
                Some("acknowledged".into()),
                Some("looking".into())
            )
        );
        assert_eq!(
            h[1],
            ("note".into(), None, Some("it was the backup job".into()))
        );
        // Evidence is untouched and still immutable.
        assert!(
            c.execute(
                "UPDATE alerts SET evidence = '{\"x\":1}' WHERE id = ?1",
                [id]
            )
            .is_err()
        );
    }

    #[test]
    fn suppression_matches_rule_and_object_until_removed() {
        let (_d, s, id) = setup();
        let c = s.connection();
        let sid = suppress(c, id, "alice", "build server", Scope::Object, None).unwrap();
        assert_eq!(status_of(c, id).unwrap(), "suppressed");
        assert_eq!(suppressed_by(c, "EXE-001", "/tmp/x").unwrap(), Some(sid));
        assert_eq!(suppressed_by(c, "EXE-001", "/tmp/y").unwrap(), None);
        assert_eq!(suppressed_by(c, "EXE-002", "/tmp/x").unwrap(), None);
        unsuppress(c, sid, "alice").unwrap();
        assert_eq!(suppressed_by(c, "EXE-001", "/tmp/x").unwrap(), None);
        assert!(matches!(
            unsuppress(c, sid, "alice"),
            Err(LifecycleError::NoSuchSuppression(_))
        ));

        let rule_wide = suppress(c, id, "alice", "noisy", Scope::Rule, None).unwrap();
        assert_eq!(
            suppressed_by(c, "EXE-001", "/anything").unwrap(),
            Some(rule_wide)
        );
        let listed = suppressions(c, true).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(!listed[0].enabled && listed[1].enabled);
        assert_eq!(listed[0].object.as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn expired_suppressions_do_not_apply() {
        let (_d, s, id) = setup();
        let c = s.connection();
        suppress(
            c,
            id,
            "alice",
            "temporary",
            Scope::Object,
            Some("2000-01-01T00:00:00.000Z"),
        )
        .unwrap();
        assert_eq!(suppressed_by(c, "EXE-001", "/tmp/x").unwrap(), None);
    }
}
