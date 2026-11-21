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
use soteria_store::{new_id, now};

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

/// Rule, reason and guidance for a change, keyed on its most significant kind.
struct RuleText {
    id: &'static str,
    reason: &'static str,
    recommendation: &'static str,
}

fn rule_for(kind: ChangeKind) -> RuleText {
    match kind {
        ChangeKind::New => RuleText {
            id: "FIM-001",
            reason: "Object is not part of the approved baseline.",
            recommendation: "Identify what created it and when (package install, deployment, or an unknown process). \
                             Check its owner, permissions and content; approve it into a new baseline only if authorized.",
        },
        ChangeKind::Missing => RuleText {
            id: "FIM-002",
            reason: "Object in the approved baseline no longer exists.",
            recommendation: "Determine whether it was removed by package maintenance or deliberately deleted. \
                             Missing security tooling or logs can indicate anti-forensics.",
        },
        ChangeKind::TypeChanged => RuleText {
            id: "FIM-010",
            reason: "Object type changed (for example, a file replaced by a symlink).",
            recommendation: "Replacing files with links is a common way to redirect execution or reads. \
                             Inspect the new object and what it points to.",
        },
        ChangeKind::ContentModified => RuleText {
            id: "FIM-003",
            reason: "File content differs from the approved baseline.",
            recommendation: "Verify package provenance (rpm -V / dpkg --verify), review change history, \
                             and determine whether this change was authorized.",
        },
        ChangeKind::PermissionModified => RuleText {
            id: "FIM-004",
            reason: "Permissions differ from the approved baseline.",
            recommendation: "Check for added setuid/setgid bits or write access for other users, \
                             which can enable privilege escalation.",
        },
        ChangeKind::OwnerModified => RuleText {
            id: "FIM-005",
            reason: "Owner or group differs from the approved baseline.",
            recommendation: "Confirm the new owner is expected; ownership by an unprivileged user lets that user modify the file.",
        },
        ChangeKind::CapabilityModified => RuleText {
            id: "FIM-006",
            reason: "File capabilities differ from the approved baseline.",
            recommendation: "Review the capabilities with getcap; added capabilities grant privileges without setuid.",
        },
        ChangeKind::SecurityLabelModified => RuleText {
            id: "FIM-007",
            reason: "Security label (SELinux context) differs from the approved baseline.",
            recommendation: "Check the context with ls -Z and restorecon -n; a changed label can bypass MAC policy.",
        },
        ChangeKind::SymlinkTargetModified => RuleText {
            id: "FIM-008",
            reason: "Symbolic link points somewhere other than in the approved baseline.",
            recommendation: "Inspect the new target; redirected links can substitute binaries or configuration.",
        },
        ChangeKind::ExecutableStatusModified => RuleText {
            id: "FIM-009",
            reason: "Executable permission changed compared with the approved baseline.",
            recommendation: "Determine why the object became (non-)executable and whether it has since been run.",
        },
        ChangeKind::MetadataModified => RuleText {
            id: "FIM-011",
            reason: "File metadata (size, time or inode) changed without a content or permission change.",
            recommendation: "Usually benign (for example, a file rewritten with identical content). \
                             Correlate with maintenance activity.",
        },
    }
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
pub fn insert(conn: &Connection, a: AlertSpec<'_>, minimum: Severity) -> rusqlite::Result<Raised> {
    if a.severity < minimum {
        return Ok(Raised::BelowThreshold);
    }
    // A suppressed detection is kept as an event, not an alert (FR-030).
    if let Some(suppression) = crate::lifecycle::suppressed_by(conn, a.rule_id, a.object)? {
        record_event(
            conn,
            "detection",
            "alert.suppressed",
            a.severity,
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
            a.severity.as_str(),
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

/// Record an alert for a baseline deviation, unless it is a duplicate or
/// below `minimum`.
pub fn raise(conn: &Connection, a: &NewAlert<'_>, minimum: Severity) -> rusqlite::Result<Raised> {
    let c = a.change;
    let rule = rule_for(primary(&c.kinds));
    let object = String::from_utf8_lossy(c.path.as_os_str().as_bytes()).into_owned();
    let before = c.before.as_ref().map(state_json);
    let after = c.after.as_ref().map(state_json);
    let kinds: Vec<&str> = c.kinds.iter().map(|k| k.as_str()).collect();
    let reason = if c.kinds.len() > 1 {
        format!("{} Also changed: {}.", rule.reason, kinds.join(", "))
    } else {
        rule.reason.to_owned()
    };
    let evidence = json!({
        "source": a.source.as_str(),
        "baseline_version": a.baseline_version,
        "changes": kinds,
        "baseline": before,
        "current": after,
        "actor": "unknown: filesystem events do not identify the process",
    });
    insert(
        conn,
        AlertSpec {
            alert_type: "file_integrity",
            rule_id: rule.id,
            severity: c.severity,
            hostname: a.hostname,
            object: &object,
            reason: &reason,
            recommendation: rule.recommendation,
            evidence,
            identity: after.unwrap_or(Value::Null),
            event_id: None,
        },
        minimum,
    )
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
