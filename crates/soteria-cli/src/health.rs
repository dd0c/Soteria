//! Agent liveness as seen from the database. The daemon records state
//! changes in `sensor_health` and refreshes a heartbeat; a "running" state
//! with a stale heartbeat means the daemon died without shutting down.

use chrono::{DateTime, Utc};
use serde::Serialize;
use soteria_store::{Store, Summary};

pub const HEARTBEAT_KEY: &str = "agent_heartbeat";
pub const HEARTBEAT_INTERVAL_SECS: u64 = 15;
/// A heartbeat older than this means the agent is not responding.
pub const HEARTBEAT_STALE_SECS: i64 = 90;
/// A scan may hold the database (and so delay the heartbeat) for up to this
/// long before the agent is considered stuck.
pub const STALL_LIMIT_SECS: i64 = 30 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Running,
    NotResponding,
    Stopped,
    NeverStarted,
}

impl AgentState {
    pub fn label(self) -> &'static str {
        match self {
            AgentState::Running => "RUNNING",
            AgentState::NotResponding => "NOT RESPONDING",
            AgentState::Stopped => "STOPPED",
            AgentState::NeverStarted => "NEVER STARTED",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentHealth {
    pub state: AgentState,
    pub since: Option<String>,
    pub last_heartbeat: Option<String>,
}

pub fn agent_health(store: &Store, summary: &Summary) -> AgentHealth {
    let heartbeat = store.meta(HEARTBEAT_KEY).ok().flatten();
    let state = match summary.agent_state.as_deref() {
        None => AgentState::NeverStarted,
        Some("running") => {
            let fresh = heartbeat
                .as_deref()
                .and_then(|h| DateTime::parse_from_rfc3339(h).ok())
                .map(|t| (Utc::now() - t.with_timezone(&Utc)).num_seconds() <= HEARTBEAT_STALE_SECS)
                .unwrap_or(false);
            if fresh || scanning(store, heartbeat.as_deref()) {
                AgentState::Running
            } else {
                AgentState::NotResponding
            }
        }
        Some(_) => AgentState::Stopped,
    };
    AgentHealth {
        state,
        since: summary.agent_state_since.clone(),
        last_heartbeat: heartbeat,
    }
}

/// The agent writes no heartbeat while a scan holds the database. It still
/// counts as running if a scan started while the heartbeat was fresh and
/// has not exceeded the stall limit.
fn scanning(store: &Store, heartbeat: Option<&str>) -> bool {
    let Some(hb) = heartbeat.and_then(|h| DateTime::parse_from_rfc3339(h).ok()) else {
        return false;
    };
    let started: Option<String> = store
        .connection()
        .query_row(
            "SELECT started_at FROM scan_history WHERE status = 'running' ORDER BY started_at DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok();
    let Some(started) = started.and_then(|s| DateTime::parse_from_rfc3339(&s).ok()) else {
        return false;
    };
    let started = started.with_timezone(&Utc);
    (started - hb.with_timezone(&Utc)).num_seconds() <= HEARTBEAT_STALE_SECS
        && (Utc::now() - started).num_seconds() <= STALL_LIMIT_SECS
}
