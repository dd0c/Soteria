//! Interruptions of monitoring (FR-037): an agent that did not record a
//! clean stop was killed, crashed or lost power, and changes made while it
//! was down are only found by the startup scan.

use rusqlite::OptionalExtension;
use serde::Serialize;
use serde_json::json;
use soteria_core::Severity;
use soteria_store::Store;

use crate::alerts::{self, AlertSpec, Policy};

/// Meta key holding the agent's last heartbeat (written by the daemon).
pub const HEARTBEAT_KEY: &str = "agent_heartbeat";

/// How the previous run ended, when not cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interruption {
    /// The agent's last recorded state ("running", "failed", ...).
    pub last_state: String,
    pub last_state_at: String,
    /// The last heartbeat: about when monitoring stopped.
    pub last_seen: Option<String>,
}

/// Read how the previous run ended. Call before the new run records
/// anything. `None`: a clean stop, or the first run.
pub fn previous_run(store: &Store) -> rusqlite::Result<Option<Interruption>> {
    let conn = store.connection();
    let last: Option<(String, String)> = conn
        .query_row(
            "SELECT state, ts FROM sensor_health WHERE sensor = 'agent' ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((state, ts)) = last else {
        return Ok(None);
    };
    if state == "stopped" {
        return Ok(None);
    }
    let last_seen = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [HEARTBEAT_KEY],
            |r| r.get(0),
        )
        .optional()?;
    Ok(Some(Interruption {
        last_state: state,
        last_state_at: ts,
        last_seen,
    }))
}

/// Raise SELF-002 for an interrupted previous run.
pub fn report(
    store: &Store,
    hostname: &str,
    i: &Interruption,
    policy: Policy<'_>,
) -> rusqlite::Result<()> {
    let rule = soteria_rules::builtin("SELF-002");
    let since = i.last_seen.as_deref().unwrap_or(&i.last_state_at);
    let reason = format!(
        "{} Last state '{}'; last seen {since}.",
        rule.description, i.last_state
    );
    alerts::insert(
        store.connection(),
        AlertSpec {
            alert_type: "self_integrity",
            rule_id: rule.id,
            severity: rule.severity.unwrap_or(Severity::Medium),
            hostname,
            object: "soteria",
            reason: &reason,
            recommendation: rule.recommendation,
            evidence: json!({ "source": "startup", "previous_run": i }),
            identity: json!({ "since": since }),
            event_id: None,
        },
        policy,
    )?;
    alerts::record_event(
        store.connection(),
        "agent",
        "agent.interrupted",
        Severity::Medium,
        None,
        &json!(i),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_stops_and_first_runs_are_not_interruptions() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::create_or_migrate(&dir.path().join("db")).unwrap().0;
        assert_eq!(previous_run(&store).unwrap(), None);
        store.record_health("agent", "running", None).unwrap();
        store
            .set_meta(HEARTBEAT_KEY, "2026-11-21T10:00:00.000Z")
            .unwrap();
        let i = previous_run(&store).unwrap().unwrap();
        assert_eq!(i.last_state, "running");
        assert_eq!(i.last_seen.as_deref(), Some("2026-11-21T10:00:00.000Z"));
        report(&store, "h", &i, Severity::Low.into()).unwrap();
        // Reported once for the same interruption.
        report(&store, "h", &i, Severity::Low.into()).unwrap();
        let n: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM alerts WHERE rule_id = 'SELF-002'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        store.record_health("agent", "stopped", None).unwrap();
        assert_eq!(previous_run(&store).unwrap(), None);
    }
}
