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
            if fresh {
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
