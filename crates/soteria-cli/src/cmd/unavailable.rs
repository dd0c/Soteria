//! Commands whose functionality lands in a later milestone. They answer with
//! a clear message and exit code 7 instead of pretending to work (SRS 4.7).

use soteria_core::ExitStatus;

use crate::output::{CmdResult, Failure};

pub fn run(command: &str, milestone: &str) -> CmdResult {
    Err(Failure::new(
        ExitStatus::Unavailable,
        format!(
            "'soteria {command}' is not available in this build yet; it arrives with {milestone}"
        ),
    ))
}

/// Milestone names used in messages, matching docs/IMPLEMENTATION_PLAN.md.
pub const EXECUTION: &str = "milestone 4 (execution monitoring)";
pub const DETECTION: &str = "milestone 5 (detection and incidents)";
