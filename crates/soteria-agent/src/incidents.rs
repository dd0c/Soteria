//! Correlation of related alerts into incidents (FR-018).
//!
//! New alerts are examined in order, after they are recorded. An alert is
//! related to an earlier one, created within the correlation window, when:
//!
//! - both concern the same object (file or program);
//! - one is a file change and the other an execution of that file (for
//!   example, a program dropped into `/usr/local/bin` and then run);
//! - both are executions in the same login session by the same login user;
//! - one execution's parent is the other's process.
//!
//! A single alert is not an incident. When the second related alert
//! arrives, both join a new incident; later related alerts join it too. An
//! incident is open while any of its alerts is unresolved, and its severity
//! is the highest of its alerts.

use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use soteria_core::Severity;
use soteria_store::now;

/// Meta key: the highest alert id already correlated.
const CURSOR: &str = "correlated_through";

/// Alerts correlated per call at most, so a large backlog does not hold the
/// database for long.
const BATCH: usize = 500;

/// Correlate alerts recorded since the last call. Returns how many alerts
/// joined an incident.
pub fn correlate_pending(conn: &Connection, window: Duration) -> rusqlite::Result<usize> {
    let cursor: i64 = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [CURSOR], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let ids: Vec<i64> = {
        let mut st =
            conn.prepare_cached("SELECT id FROM alerts WHERE id > ?1 ORDER BY id LIMIT ?2")?;
        st.query_map(params![cursor, BATCH as i64], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    let Some(&last) = ids.last() else {
        return Ok(0);
    };
    let tx = conn.unchecked_transaction()?;
    let mut joined = 0;
    for id in ids {
        if correlate(&tx, id, window)?.is_some() {
            joined += 1;
        }
    }
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![CURSOR, last.to_string()],
    )?;
    tx.commit()?;
    Ok(joined)
}

struct AlertFacts {
    created_at: String,
    alert_type: String,
    object: Option<String>,
    exe: Option<String>,
    script: Option<String>,
    session: Option<i64>,
    auid: Option<i64>,
    parent_process: Option<i64>,
    incident: Option<i64>,
}

fn facts(conn: &Connection, id: i64) -> rusqlite::Result<AlertFacts> {
    conn.query_row(
        "SELECT created_at, type, object, evidence, incident_id FROM alerts WHERE id = ?1",
        [id],
        |r| {
            let evidence: Value =
                serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or(Value::Null);
            let p = &evidence["process"];
            Ok(AlertFacts {
                created_at: r.get(0)?,
                alert_type: r.get(1)?,
                object: r.get(2)?,
                exe: p["exe"].as_str().map(str::to_owned),
                script: p["script"].as_str().map(str::to_owned),
                session: p["session"].as_i64(),
                auid: p["auid"].as_i64(),
                parent_process: p["parent"]["process_id"].as_i64(),
                incident: r.get(4)?,
            })
        },
    )
}

/// Why two alerts are related, most specific first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Relation {
    ChangedThenRun,
    SameObject,
    ProcessTree,
    Session,
}

/// Group one alert with related earlier alerts. Returns the incident id.
pub fn correlate(conn: &Connection, id: i64, window: Duration) -> rusqlite::Result<Option<i64>> {
    let me = facts(conn, id)?;
    if me.incident.is_some() {
        return Ok(me.incident);
    }
    let since = DateTime::parse_from_rfc3339(&me.created_at)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
        - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::hours(1));
    let since = since.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let is_exec = me.alert_type == "execution";
    let mut st = conn.prepare_cached(
        "SELECT id, type, object, incident_id,
                json_extract(evidence, '$.process.exe'), json_extract(evidence, '$.process.script'),
                json_extract(evidence, '$.process.session'), json_extract(evidence, '$.process.auid'),
                json_extract(evidence, '$.process.id')
         FROM alerts
         WHERE id < ?1 AND created_at >= ?2 AND status != 'suppressed'
           AND (object = ?3 OR object = ?4 OR object = ?5
                OR (type = 'execution' AND (json_extract(evidence, '$.process.exe') = ?3
                                            OR json_extract(evidence, '$.process.script') = ?3))
                OR (?6 AND ?7 IS NOT NULL AND type = 'execution'
                    AND json_extract(evidence, '$.process.session') = ?7
                    AND json_extract(evidence, '$.process.auid') IS ?8)
                OR (?9 IS NOT NULL AND json_extract(evidence, '$.process.id') = ?9))
         ORDER BY id",
    )?;
    type Row = (
        i64,
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let rows: Vec<Row> = st
        .query_map(
            params![
                id,
                since,
                me.object,
                me.exe,
                me.script,
                is_exec,
                me.session,
                me.auid,
                me.parent_process
            ],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<_>>()?;
    if rows.is_empty() {
        return Ok(None);
    }

    // The strongest relation decides the incident's title.
    let mut best: Option<(Relation, String)> = None;
    for (_, t, object, _, exe, script, session, _, process) in &rows {
        let relation = if is_exec != (t == "execution")
            && (object.is_some() && (object == &me.exe || object == &me.script)
                || me.object.is_some() && (exe == &me.object || script == &me.object))
        {
            (
                Relation::ChangedThenRun,
                format!(
                    "Changed program executed: {}",
                    object.as_deref().or(me.object.as_deref()).unwrap_or("?")
                ),
            )
        } else if object.is_some() && object == &me.object {
            (
                Relation::SameObject,
                format!(
                    "Repeated detections on {}",
                    object.as_deref().unwrap_or("?")
                ),
            )
        } else if process.is_some() && *process == me.parent_process {
            (
                Relation::ProcessTree,
                format!(
                    "Suspicious process chain from {}",
                    exe.as_deref().or(object.as_deref()).unwrap_or("?")
                ),
            )
        } else if session.is_some() && *session == me.session {
            (
                Relation::Session,
                format!(
                    "Related detections in login session {}{}",
                    session.unwrap_or_default(),
                    me.auid
                        .map(|a| format!(" (login uid {a})"))
                        .unwrap_or_default()
                ),
            )
        } else {
            continue;
        };
        if best.as_ref().is_none_or(|b| relation.0 < b.0) {
            best = Some(relation);
        }
    }
    let Some((_, title)) = best else {
        return Ok(None);
    };

    let ts = now();
    let incident = match rows.iter().find_map(|r| r.3) {
        Some(existing) => existing,
        None => {
            conn.execute(
                "INSERT INTO incidents (created_at, updated_at, severity, title, status) VALUES (?1, ?1, 'info', ?2, 'open')",
                params![ts, title],
            )?;
            conn.last_insert_rowid()
        }
    };
    let mut members: Vec<i64> = rows.iter().filter(|r| r.3.is_none()).map(|r| r.0).collect();
    members.push(id);
    for m in members {
        conn.execute(
            "UPDATE alerts SET incident_id = ?2 WHERE id = ?1 AND incident_id IS NULL",
            params![m, incident],
        )?;
        conn.execute(
            "INSERT INTO alert_history (alert_id, ts, actor, action, note) VALUES (?1, ?2, 'soteria', 'note', ?3)",
            params![m, ts, format!("grouped into incident {incident}: {title}")],
        )?;
    }
    refresh(conn, incident)?;
    Ok(Some(incident))
}

/// Recompute an incident's severity and status from its alerts.
pub fn refresh(conn: &Connection, incident: i64) -> rusqlite::Result<()> {
    let (severities, unresolved): (Vec<String>, i64) = {
        let mut st = conn.prepare_cached("SELECT severity FROM alerts WHERE incident_id = ?1")?;
        let s = st
            .query_map([incident], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        let u = conn.query_row(
            "SELECT COUNT(*) FROM alerts WHERE incident_id = ?1 AND status IN ('open', 'acknowledged', 'investigated')",
            [incident],
            |r| r.get(0),
        )?;
        (s, u)
    };
    let severity = severities
        .iter()
        .filter_map(|s| s.parse::<Severity>().ok())
        .max()
        .unwrap_or(Severity::Info);
    let status = if unresolved > 0 { "open" } else { "closed" };
    conn.execute(
        "UPDATE incidents SET severity = ?2, status = ?3, updated_at = ?4
         WHERE id = ?1 AND (severity != ?2 OR status != ?3)",
        params![incident, severity.as_str(), status, now()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use soteria_store::Store;

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = Store::create_or_migrate(&d.path().join("db")).unwrap();
        (d, s)
    }

    fn add(s: &Store, ts: &str, kind: &str, sev: &str, object: &str, evidence: Value) -> i64 {
        let c = s.connection();
        c.execute(
            "INSERT INTO alerts (uuid, created_at, updated_at, severity, type, status, hostname, object, rule_id,
                                 reason, evidence, recommendation)
             VALUES (?1, ?2, ?2, ?3, ?4, 'open', 'h', ?5, 'R', 'r', ?6, 'rec')",
            params![soteria_store::new_id(), ts, sev, kind, object, evidence.to_string()],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    fn incident_of(s: &Store, id: i64) -> Option<i64> {
        s.connection()
            .query_row("SELECT incident_id FROM alerts WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap()
    }

    const H: Duration = Duration::from_secs(3600);

    #[test]
    fn changed_program_then_run_forms_an_incident() {
        let (_d, s) = store();
        let c = s.connection();
        let file = add(
            &s,
            "2026-11-21T10:00:00.000Z",
            "file_integrity",
            "medium",
            "/usr/local/bin/x",
            json!({}),
        );
        let unrelated = add(
            &s,
            "2026-11-21T10:00:01.000Z",
            "file_integrity",
            "low",
            "/etc/motd",
            json!({}),
        );
        assert_eq!(
            correlate_pending(c, H).unwrap(),
            0,
            "a single alert is not an incident"
        );
        let exec = add(
            &s,
            "2026-11-21T10:05:00.000Z",
            "execution",
            "high",
            "/usr/local/bin/x",
            json!({ "process": { "id": 7, "exe": "/usr/local/bin/x", "session": 3, "auid": 1000 } }),
        );
        assert_eq!(correlate_pending(c, H).unwrap(), 1);
        let inc = incident_of(&s, exec).unwrap();
        assert_eq!(incident_of(&s, file), Some(inc));
        assert_eq!(incident_of(&s, unrelated), None);
        let (title, sev, status): (String, String, String) = c
            .query_row(
                "SELECT title, severity, status FROM incidents WHERE id = ?1",
                [inc],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(title, "Changed program executed: /usr/local/bin/x");
        assert_eq!((sev.as_str(), status.as_str()), ("high", "open"));

        // A child process and a session neighbour join the same incident.
        let child = add(
            &s,
            "2026-11-21T10:05:01.000Z",
            "execution",
            "high",
            "/bin/sh",
            json!({ "process": { "id": 8, "exe": "/bin/sh", "parent": { "process_id": 7 } } }),
        );
        let neighbour = add(
            &s,
            "2026-11-21T10:06:00.000Z",
            "execution",
            "medium",
            "/tmp/y",
            json!({ "process": { "id": 9, "exe": "/tmp/y", "session": 3, "auid": 1000 } }),
        );
        // Another user's session is unrelated.
        let other = add(
            &s,
            "2026-11-21T10:06:00.000Z",
            "execution",
            "medium",
            "/tmp/z",
            json!({ "process": { "id": 10, "exe": "/tmp/z", "session": 3, "auid": 1001 } }),
        );
        correlate_pending(c, H).unwrap();
        assert_eq!(incident_of(&s, child), Some(inc));
        assert_eq!(incident_of(&s, neighbour), Some(inc));
        assert_eq!(incident_of(&s, other), None);

        // Closing every member closes the incident.
        c.execute(
            "UPDATE alerts SET status = 'closed' WHERE incident_id = ?1",
            [inc],
        )
        .unwrap();
        refresh(c, inc).unwrap();
        let status: String = c
            .query_row("SELECT status FROM incidents WHERE id = ?1", [inc], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(status, "closed");
    }

    #[test]
    fn alerts_outside_the_window_are_not_grouped() {
        let (_d, s) = store();
        let a = add(
            &s,
            "2026-11-21T08:00:00.000Z",
            "file_integrity",
            "high",
            "/etc/passwd",
            json!({}),
        );
        let b = add(
            &s,
            "2026-11-21T10:00:00.000Z",
            "file_integrity",
            "high",
            "/etc/passwd",
            json!({}),
        );
        correlate_pending(s.connection(), H).unwrap();
        assert_eq!(incident_of(&s, a), None);
        assert_eq!(incident_of(&s, b), None);
        let c = add(
            &s,
            "2026-11-21T10:30:00.000Z",
            "file_integrity",
            "high",
            "/etc/passwd",
            json!({}),
        );
        correlate_pending(s.connection(), H).unwrap();
        assert!(incident_of(&s, c).is_some());
        assert_eq!(incident_of(&s, b), incident_of(&s, c));
        assert_eq!(incident_of(&s, a), None);
    }
}
