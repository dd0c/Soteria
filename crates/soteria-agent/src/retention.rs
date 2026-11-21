//! Retention (SRS 5.6, `general.event_retention_days`): events and
//! execution records older than the retention period are deleted. Alerts,
//! their history, incidents, baselines and scan reports are kept, and so
//! are the events and execution records an alert refers to, so evidence
//! never disappears from under an alert.

use std::time::Duration;

use rusqlite::{Connection, params};
use serde::Serialize;
use serde_json::json;
use soteria_core::Severity;

/// Rows deleted per statement, so other work gets the database in between.
const CHUNK: i64 = 5_000;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Pruned {
    pub events: u64,
    pub processes: u64,
}

/// Delete events and execution records older than `keep`. Records a
/// `retention.pruned` event when anything was deleted.
pub fn prune(conn: &Connection, keep: Duration) -> rusqlite::Result<Pruned> {
    let cutoff = (chrono::Utc::now()
        - chrono::Duration::from_std(keep).unwrap_or(chrono::Duration::MAX))
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut pruned = Pruned::default();

    // Execution records an alert cites stay.
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS retention_keep_processes (id INTEGER PRIMARY KEY);
         DELETE FROM retention_keep_processes;
         INSERT OR IGNORE INTO retention_keep_processes
             SELECT json_extract(evidence, '$.process.id') FROM alerts
             WHERE json_extract(evidence, '$.process.id') IS NOT NULL;",
    )?;
    loop {
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "CREATE TEMP TABLE IF NOT EXISTS retention_batch (id INTEGER PRIMARY KEY)",
            [],
        )?;
        tx.execute("DELETE FROM retention_batch", [])?;
        let n = tx.execute(
            "INSERT INTO retention_batch
             SELECT id FROM processes
             WHERE ts < ?1 AND id NOT IN (SELECT id FROM retention_keep_processes)
             ORDER BY ts LIMIT ?2",
            params![cutoff, CHUNK],
        )?;
        if n == 0 {
            tx.commit()?;
            break;
        }
        // Lineage to a deleted parent is cut; the parent's program and
        // name stay on the child row.
        tx.execute(
            "UPDATE processes SET parent_id = NULL WHERE parent_id IN (SELECT id FROM retention_batch)",
            [],
        )?;
        pruned.processes += tx.execute(
            "DELETE FROM processes WHERE id IN (SELECT id FROM retention_batch)",
            [],
        )? as u64;
        tx.commit()?;
    }
    loop {
        let n = conn.execute(
            "DELETE FROM events WHERE id IN (
                 SELECT id FROM events
                 WHERE ts < ?1
                   AND id NOT IN (SELECT event_id FROM alerts WHERE event_id IS NOT NULL)
                   AND id NOT IN (SELECT event_id FROM processes WHERE event_id IS NOT NULL)
                 ORDER BY ts LIMIT ?2)",
            params![cutoff, CHUNK],
        )?;
        if n == 0 {
            break;
        }
        pruned.events += n as u64;
    }
    if pruned != Pruned::default() {
        crate::alerts::record_event(
            conn,
            "agent",
            "retention.pruned",
            Severity::Info,
            None,
            &json!({ "before": cutoff, "events": pruned.events, "processes": pruned.processes }),
        )?;
    }
    Ok(pruned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria_store::Store;

    #[test]
    fn old_records_go_but_evidence_stays() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = Store::create_or_migrate(&d.path().join("db")).unwrap();
        let c = s.connection();
        let event = |ts: &str| {
            c.execute(
                "INSERT INTO events (ts, sensor, type, severity) VALUES (?1, 'x', 'process.exec', 'info')",
                [ts],
            )
            .unwrap();
            c.last_insert_rowid()
        };
        let process = |ts: &str, ev: i64, parent: Option<i64>| {
            c.execute(
                "INSERT INTO processes (ts, pid, classification, rationale, severity, sensor, event_id, parent_id)
                 VALUES (?1, 1, 'trusted', '[]', 'info', 'execution', ?2, ?3)",
                params![ts, ev, parent],
            )
            .unwrap();
            c.last_insert_rowid()
        };
        let old = "2000-01-01T00:00:00.000Z";
        let e_old = event(old);
        let p_old = process(old, e_old, None);
        let e_cited = event(old);
        let p_cited = process(old, e_cited, None);
        let e_alert = event(old);
        let lone_old = event(old);
        // Newest last: a deleted row's id is not reused while a later one exists.
        let e_new = event(&soteria_store::now());
        let p_child = process(&soteria_store::now(), e_new, Some(p_old));
        c.execute(
            "INSERT INTO alerts (uuid, created_at, updated_at, severity, type, status, hostname, object, rule_id,
                                 reason, evidence, recommendation, event_id)
             VALUES ('u', ?1, ?1, 'high', 'execution', 'open', 'h', '/x', 'EXE-001', 'r', ?2, 'rec', ?3)",
            params![old, json!({ "process": { "id": p_cited } }).to_string(), e_alert],
        )
        .unwrap();

        let p = prune(c, Duration::from_secs(90 * 86400)).unwrap();
        assert_eq!(
            p,
            Pruned {
                events: 2,
                processes: 1
            }
        );
        let exists = |table: &str, id: i64| -> bool {
            c.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE id = ?1"),
                [id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
                == 1
        };
        assert!(
            !exists("processes", p_old) && !exists("events", e_old) && !exists("events", lone_old)
        );
        assert!(
            exists("processes", p_cited) && exists("events", e_cited) && exists("events", e_alert)
        );
        assert!(exists("processes", p_child) && exists("events", e_new));
        let parent: Option<i64> = c
            .query_row(
                "SELECT parent_id FROM processes WHERE id = ?1",
                [p_child],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(parent, None);
        assert_eq!(
            prune(c, Duration::from_secs(90 * 86400)).unwrap(),
            Pruned::default()
        );
    }
}
