//! Alerts (FR-021, FR-028, FR-029): integrity alerts here, execution
//! alerts in [`crate::exec`].
//!
//! Every alert carries the rule that fired, a plain-language reason, the
//! approved and current state, and investigation guidance. Alerts are
//! de-duplicated: the same deviation (same object, rule and current state)
//! does not raise a second alert while the first is unresolved.

use std::os::unix::ffi::OsStrExt;

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use soteria_core::Severity;
use soteria_integrity::compare::{Change, ChangeKind};
use soteria_inventory::{FileRecord, hex, sha256_hex};
use soteria_rules::RuleSet;
use soteria_store::{new_id, now};

/// What decides whether a detection becomes an alert: the minimum severity
/// and the rules in effect (overrides and administrator rules).
#[derive(Debug, Clone, Copy)]
pub struct Policy<'r> {
    pub minimum: Severity,
    pub rules: &'r RuleSet,
}

/// Built-in rules only, with a minimum severity (tests and tools).
impl From<Severity> for Policy<'static> {
    fn from(minimum: Severity) -> Self {
        static BUILTIN: std::sync::OnceLock<RuleSet> = std::sync::OnceLock::new();
        Policy {
            minimum,
            rules: BUILTIN.get_or_init(RuleSet::builtin),
        }
    }
}

/// Statuses that count as unresolved for de-duplication.
const UNRESOLVED: &str = "('open', 'acknowledged', 'investigated')";

/// Where a detection came from, recorded in the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A filesystem event, re-verified (FR-015).
    FsEvent,
    /// A scheduled or startup full reconciliation scan (FR-016).
    Reconciliation,
    /// The periodic critical-file verification (FR-032).
    CriticalScan,
    /// A manual scan.
    Manual,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::FsEvent => "fs_event",
            Source::Reconciliation => "reconciliation",
            Source::CriticalScan => "critical_scan",
            Source::Manual => "manual_scan",
        }
    }
}

/// The built-in rule for a change, keyed on its most significant kind.
fn rule_for(kind: ChangeKind) -> &'static soteria_rules::Builtin {
    soteria_rules::builtin(match kind {
        ChangeKind::New => "FIM-001",
        ChangeKind::Missing => "FIM-002",
        ChangeKind::TypeChanged => "FIM-010",
        ChangeKind::ContentModified => "FIM-003",
        ChangeKind::PermissionModified => "FIM-004",
        ChangeKind::OwnerModified => "FIM-005",
        ChangeKind::CapabilityModified => "FIM-006",
        ChangeKind::SecurityLabelModified => "FIM-007",
        ChangeKind::SymlinkTargetModified => "FIM-008",
        ChangeKind::ExecutableStatusModified => "FIM-009",
        ChangeKind::MetadataModified => "FIM-011",
    })
}

/// Order of significance used to pick the rule for a multi-kind change.
const SIGNIFICANCE: [ChangeKind; 11] = [
    ChangeKind::TypeChanged,
    ChangeKind::ContentModified,
    ChangeKind::Missing,
    ChangeKind::New,
    ChangeKind::PermissionModified,
    ChangeKind::CapabilityModified,
    ChangeKind::OwnerModified,
    ChangeKind::SecurityLabelModified,
    ChangeKind::SymlinkTargetModified,
    ChangeKind::ExecutableStatusModified,
    ChangeKind::MetadataModified,
];

fn primary(kinds: &[ChangeKind]) -> ChangeKind {
    SIGNIFICANCE
        .into_iter()
        .find(|k| kinds.contains(k))
        .unwrap_or(ChangeKind::MetadataModified)
}

pub fn state_json(r: &FileRecord) -> Value {
    json!({
        "file_type": r.file_type.as_str(),
        "kind": r.kind.as_str(),
        "sha256": r.sha256,
        "size": r.size,
        "uid": r.uid,
        "gid": r.gid,
        "mode": format!("{:04o}", r.permissions()),
        "mtime_ns": r.mtime_ns,
        "inode": r.inode,
        "capabilities": r.capabilities.as_deref().map(hex),
        "security_label": r.security_label,
        "symlink_target": r.symlink_target.as_ref().map(|t| String::from_utf8_lossy(t.as_os_str().as_bytes()).into_owned()),
    })
}

/// An alert to record.
pub struct NewAlert<'a> {
    pub change: &'a Change,
    pub source: Source,
    pub baseline_version: u32,
    pub hostname: &'a str,
    /// The object is one of Soteria's own files (FR-036): any deviation
    /// beyond metadata is reported as SELF-001.
    pub own_file: bool,
}

/// Outcome of [`raise`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Raised {
    Created {
        id: i64,
        uuid: String,
    },
    /// An unresolved alert for the same deviation already exists.
    Duplicate {
        id: i64,
    },
    /// Below the configured minimum severity; recorded as an event only.
    BelowThreshold,
    /// Matched an administrator's suppression; recorded as an event only.
    Suppressed {
        suppression: i64,
    },
    /// The rule is disabled by an administrator override.
    Disabled,
}

/// Any alert, before de-duplication and threshold checks.
pub struct AlertSpec<'a> {
    pub alert_type: &'a str,
    pub rule_id: &'a str,
    pub severity: Severity,
    pub hostname: &'a str,
    pub object: &'a str,
    pub reason: &'a str,
    pub recommendation: &'a str,
    /// Evidence; a `fingerprint` field is added.
    pub evidence: Value,
    /// What makes two detections "the same" for de-duplication, together
    /// with the object and rule.
    pub identity: Value,
    pub event_id: Option<i64>,
}

/// Record an alert unless it is below `minimum` or an unresolved alert for
/// the same object, rule and identity exists.
pub fn insert<'r>(
    conn: &Connection,
    a: AlertSpec<'_>,
    policy: impl Into<Policy<'r>>,
) -> rusqlite::Result<Raised> {
    let policy = policy.into();
    // Built-in rules can be disabled or given a fixed severity.
    let Some(severity) = policy.rules.effective(a.rule_id, a.severity) else {
        return Ok(Raised::Disabled);
    };
    if severity < policy.minimum {
        return Ok(Raised::BelowThreshold);
    }
    // A suppressed detection is kept as an event, not an alert (FR-030).
    if let Some(suppression) = crate::lifecycle::suppressed_by(conn, a.rule_id, a.object)? {
        record_event(
            conn,
            "detection",
            "alert.suppressed",
            severity,
            None,
            &json!({ "rule": a.rule_id, "object": a.object, "suppression": suppression }),
        )?;
        return Ok(Raised::Suppressed { suppression });
    }
    let fingerprint = sha256_hex(
        json!({ "object": a.object, "rule": a.rule_id, "after": a.identity })
            .to_string()
            .as_bytes(),
    );
    let existing: Option<i64> = conn
        .query_row(
            &format!(
                "SELECT id FROM alerts WHERE object = ?1 AND rule_id = ?2 AND status IN {UNRESOLVED}
                 AND json_extract(evidence, '$.fingerprint') = ?3 LIMIT 1"
            ),
            params![a.object, a.rule_id, fingerprint],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(id) = existing {
        return Ok(Raised::Duplicate { id });
    }
    let mut evidence = a.evidence;
    if let Some(map) = evidence.as_object_mut() {
        map.insert("fingerprint".into(), Value::String(fingerprint));
    }
    let ts = now();
    let uuid = new_id();
    // A savepoint, so this also works inside a caller's transaction.
    conn.execute_batch("SAVEPOINT raise_alert")?;
    let result = (|| -> rusqlite::Result<i64> {
        conn.execute(
        "INSERT INTO alerts (uuid, created_at, updated_at, severity, type, status, hostname, object,
                             rule_id, reason, evidence, recommendation, event_id)
         VALUES (?1, ?2, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            uuid,
            ts,
            severity.as_str(),
            a.alert_type,
            a.hostname,
            a.object,
            a.rule_id,
            a.reason,
            evidence.to_string(),
            a.recommendation,
            a.event_id
        ],
    )?;
        let id = conn.last_insert_rowid();
        conn.execute(
        "INSERT INTO alert_history (alert_id, ts, actor, action, to_status) VALUES (?1, ?2, 'soteria', 'created', 'open')",
        params![id, ts],
    )?;
        Ok(id)
    })();
    match result {
        Ok(id) => {
            conn.execute_batch("RELEASE raise_alert")?;
            Ok(Raised::Created { id, uuid })
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO raise_alert; RELEASE raise_alert");
            Err(e)
        }
    }
}

/// Record an alert for a baseline deviation under its built-in rule, and
/// one for each administrator file rule it matches, unless duplicate,
/// disabled, suppressed or below the minimum. Returns the built-in rule's
/// outcome.
pub fn raise<'r>(
    conn: &Connection,
    a: &NewAlert<'_>,
    policy: impl Into<Policy<'r>>,
) -> rusqlite::Result<Raised> {
    let policy = policy.into();
    let c = a.change;
    let kind = primary(&c.kinds);
    let fim = rule_for(kind);
    let own = a.own_file && kind != ChangeKind::MetadataModified;
    let rule = if own {
        soteria_rules::builtin("SELF-001")
    } else {
        fim
    };
    let object = String::from_utf8_lossy(c.path.as_os_str().as_bytes()).into_owned();
    let before = c.before.as_ref().map(state_json);
    let after = c.after.as_ref().map(state_json);
    let kinds: Vec<&str> = c.kinds.iter().map(|k| k.as_str()).collect();
    let mut reason = if c.kinds.len() > 1 {
        format!("{} Also changed: {}.", fim.description, kinds.join(", "))
    } else {
        fim.description.to_owned()
    };
    if own {
        reason = format!("{} {reason}", rule.description);
    }
    let evidence = json!({
        "source": a.source.as_str(),
        "baseline_version": a.baseline_version,
        "changes": kinds,
        "baseline": before,
        "current": after,
        "actor": "unknown: filesystem events do not identify the process",
    });
    let identity = after.unwrap_or(Value::Null);
    let raised = insert(
        conn,
        AlertSpec {
            alert_type: "file_integrity",
            rule_id: rule.id,
            severity: if own { Severity::Critical } else { c.severity },
            hostname: a.hostname,
            object: &object,
            reason: &reason,
            recommendation: rule.recommendation,
            evidence: evidence.clone(),
            identity: identity.clone(),
            event_id: None,
        },
        policy,
    )?;
    for admin in policy
        .rules
        .file_matches(c.path.as_os_str().as_bytes(), &kinds)
    {
        let mut evidence = evidence.clone();
        evidence["builtin_rule"] = json!(rule.id);
        insert(
            conn,
            AlertSpec {
                alert_type: "file_integrity",
                rule_id: &admin.id,
                severity: admin.severity_for(c.severity),
                hostname: a.hostname,
                object: &object,
                reason: admin.reason.as_deref().unwrap_or(&reason),
                recommendation: &admin.recommendation,
                evidence,
                identity: identity.clone(),
                event_id: None,
            },
            policy,
        )?;
    }
    Ok(raised)
}

/// Record a raw event (sensor observation or system activity).
pub fn record_event(
    conn: &Connection,
    sensor: &str,
    event_type: &str,
    severity: Severity,
    path: Option<&std::path::Path>,
    data: &Value,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO events (ts, sensor, type, severity, path, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            now(),
            sensor,
            event_type,
            severity.as_str(),
            path.map(|p| p.as_os_str().as_bytes().to_vec()),
            data.to_string()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria_core::FileKind;
    use soteria_inventory::FileType;
    use soteria_store::Store;
    use std::path::PathBuf;

    fn rec(sha: &str) -> FileRecord {
        FileRecord {
            path: PathBuf::from("/usr/bin/ls"),
            file_type: FileType::Regular,
            kind: FileKind::ExecutableBinary,
            sha256: Some(sha.into()),
            size: 1,
            uid: 0,
            gid: 0,
            mode: 0o100755,
            mtime_ns: 0,
            ctime_ns: 0,
            inode: 1,
            device: 1,
            symlink_target: None,
            capabilities: None,
            security_label: None,
            error: None,
        }
    }

    fn change(after_sha: &str) -> Change {
        Change {
            path: PathBuf::from("/usr/bin/ls"),
            kinds: vec![ChangeKind::ContentModified],
            severity: Severity::High,
            before: Some(rec("aaa")),
            after: Some(rec(after_sha)),
        }
    }

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = Store::create_or_migrate(&d.path().join("db")).unwrap();
        (d, s)
    }

    fn alert<'a>(c: &'a Change) -> NewAlert<'a> {
        NewAlert {
            own_file: false,
            change: c,
            source: Source::FsEvent,
            baseline_version: 1,
            hostname: "host",
        }
    }

    #[test]
    fn creates_alert_with_full_evidence() {
        let (_d, s) = store();
        let c = change("bbb");
        let Raised::Created { id, .. } = raise(s.connection(), &alert(&c), Severity::Low).unwrap()
        else {
            panic!("not created");
        };
        let (rule, sev, reason, evidence, rec_text): (String, String, String, String, String) = s
            .connection()
            .query_row(
                "SELECT rule_id, severity, reason, evidence, recommendation FROM alerts WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(rule, "FIM-003");
        assert_eq!(sev, "high");
        assert!(reason.contains("content differs"));
        assert!(rec_text.contains("provenance"));
        let ev: Value = serde_json::from_str(&evidence).unwrap();
        assert_eq!(ev["baseline"]["sha256"], "aaa");
        assert_eq!(ev["current"]["sha256"], "bbb");
        assert_eq!(ev["current"]["mode"], "0755");
        assert_eq!(ev["source"], "fs_event");
        let history: i64 = s
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM alert_history WHERE alert_id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(history, 1);
    }

    #[test]
    fn same_deviation_is_not_raised_twice() {
        let (_d, s) = store();
        let c = change("bbb");
        let first = raise(s.connection(), &alert(&c), Severity::Low).unwrap();
        let Raised::Created { id, .. } = first else {
            panic!()
        };
        assert_eq!(
            raise(s.connection(), &alert(&c), Severity::Low).unwrap(),
            Raised::Duplicate { id }
        );
        // A further change to the same file is a new deviation.
        let c2 = change("ccc");
        assert!(matches!(
            raise(s.connection(), &alert(&c2), Severity::Low).unwrap(),
            Raised::Created { .. }
        ));
    }

    #[test]
    fn closed_alerts_do_not_suppress_new_ones() {
        let (_d, s) = store();
        let c = change("bbb");
        raise(s.connection(), &alert(&c), Severity::Low).unwrap();
        s.connection()
            .execute("UPDATE alerts SET status = 'closed'", [])
            .unwrap();
        assert!(matches!(
            raise(s.connection(), &alert(&c), Severity::Low).unwrap(),
            Raised::Created { .. }
        ));
    }

    #[test]
    fn respects_minimum_severity() {
        let (_d, s) = store();
        let c = change("bbb");
        assert_eq!(
            raise(s.connection(), &alert(&c), Severity::Critical).unwrap(),
            Raised::BelowThreshold
        );
    }

    #[test]
    fn rule_follows_most_significant_kind() {
        assert_eq!(
            primary(&[ChangeKind::OwnerModified, ChangeKind::ContentModified]),
            ChangeKind::ContentModified
        );
        assert_eq!(
            primary(&[ChangeKind::MetadataModified]),
            ChangeKind::MetadataModified
        );
    }
}
