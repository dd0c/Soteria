//! `soteria verify` (FR-017, FR-037, FR-038, SRS 9.3).
//!
//! Runs every check it can and lists each result, so one failure never hides
//! another. Checks that belong to later milestones are listed as skipped with
//! the reason, not silently omitted.

use serde::Serialize;
use soteria_config::{Config, IssueLevel, ValidateOptions, has_errors};
use soteria_core::{CheckState, ExitStatus};
use soteria_platform::{Platform, ProbeState, SupportLevel};
use soteria_store::{Store, StoreError};

use crate::cli::{Component, GlobalArgs, VerifyArgs};
use crate::health::{AgentState, agent_health};
use crate::output::{CmdResult, Output, Tone};

#[derive(Debug, Serialize)]
pub struct Check {
    pub component: &'static str,
    pub name: String,
    pub state: CheckState,
    pub detail: String,
}

#[derive(Debug, Serialize)]
struct Report {
    result: CheckState,
    checks: Vec<Check>,
}

struct Checks {
    list: Vec<Check>,
    exit: ExitStatus,
}

impl Checks {
    fn add(
        &mut self,
        component: &'static str,
        name: impl Into<String>,
        state: CheckState,
        detail: impl Into<String>,
    ) {
        self.list.push(Check {
            component,
            name: name.into(),
            state,
            detail: detail.into(),
        });
    }

    fn fail(
        &mut self,
        component: &'static str,
        name: impl Into<String>,
        detail: impl Into<String>,
        status: ExitStatus,
    ) {
        self.add(component, name, CheckState::Fail, detail);
        self.exit = self.exit.worst(status);
    }
}

pub fn run(args: &VerifyArgs, global: &GlobalArgs, out: &Output) -> CmdResult {
    let wanted = |c: Component| args.component.is_empty() || args.component.contains(&c);
    let mut checks = Checks {
        list: Vec::new(),
        exit: ExitStatus::Ok,
    };

    // Configuration is needed by most other checks, so it is always loaded.
    let config = match Config::load(&global.config) {
        Ok(cfg) => {
            let issues = cfg.validate(ValidateOptions::default());
            if wanted(Component::Config) {
                if has_errors(&issues) {
                    let n = issues
                        .iter()
                        .filter(|i| i.level == IssueLevel::Error)
                        .count();
                    checks.fail(
                        "config",
                        "valid",
                        format!("{n} error(s); run 'soteria config validate'"),
                        ExitStatus::ConfigInvalid,
                    );
                } else {
                    checks.add(
                        "config",
                        "valid",
                        CheckState::Pass,
                        global.config.display().to_string(),
                    );
                }
                for issue in issues.iter().filter(|i| i.level == IssueLevel::Warning) {
                    checks.add(
                        "config",
                        issue.field.clone(),
                        CheckState::Warn,
                        issue.message.clone(),
                    );
                }
            }
            (!has_errors(&issues)).then_some(cfg)
        }
        Err(e) => {
            checks.fail("config", "load", e.to_string(), ExitStatus::ConfigInvalid);
            None
        }
    };

    if wanted(Component::Platform) || wanted(Component::Sensors) {
        match Platform::detect() {
            Ok(p) => {
                if wanted(Component::Platform) {
                    let state = match p.support {
                        SupportLevel::Supported => CheckState::Pass,
                        _ => CheckState::Warn,
                    };
                    checks.add(
                        "platform",
                        "os",
                        state,
                        format!("{} ({})", p.display_name(), p.support),
                    );
                }
                if wanted(Component::Sensors) {
                    for probe in p.probe() {
                        let state = match probe.state {
                            ProbeState::Available => CheckState::Pass,
                            _ => CheckState::Warn,
                        };
                        checks.add("sensors", probe.name, state, probe.detail);
                    }
                }
            }
            Err(e) => checks.add("platform", "os", CheckState::Warn, e.to_string()),
        }
        if wanted(Component::Sensors) {
            checks.add(
                "sensors",
                "event_sensors",
                CheckState::Skipped,
                "filesystem and execution sensors arrive with milestones 3 and 4",
            );
        }
    }

    let store = match &config {
        Some(cfg)
            if wanted(Component::Database)
                || wanted(Component::Baseline)
                || wanted(Component::Service) =>
        {
            verify_database(cfg, wanted(Component::Database), &mut checks)
        }
        _ => None,
    };

    if wanted(Component::Baseline) {
        match &store {
            Some(s) => match s.summary() {
                Ok(sum) if sum.baseline_version.is_some() => checks.add(
                    "baseline",
                    "signature",
                    CheckState::Skipped,
                    "baseline signature verification arrives with milestone 2",
                ),
                Ok(_) => checks.add(
                    "baseline",
                    "established",
                    CheckState::Warn,
                    "no approved baseline; changes cannot be detected yet",
                ),
                Err(e) => checks.fail(
                    "baseline",
                    "read",
                    e.to_string(),
                    ExitStatus::IntegrityFailure,
                ),
            },
            None => checks.add(
                "baseline",
                "established",
                CheckState::Skipped,
                "database unavailable",
            ),
        }
    }

    if wanted(Component::Service) {
        match &store {
            Some(s) => {
                let health = s
                    .summary()
                    .map(|sum| agent_health(s, &sum))
                    .map(|h| h.state)
                    .unwrap_or(AgentState::NeverStarted);
                let (state, detail) = match health {
                    AgentState::Running => (CheckState::Pass, "agent is running and responding".to_owned()),
                    AgentState::NotResponding => (
                        CheckState::Fail,
                        "agent was running but stopped responding; check 'systemctl status soteria'".to_owned(),
                    ),
                    AgentState::Stopped => (CheckState::Warn, "agent is stopped".to_owned()),
                    AgentState::NeverStarted => (CheckState::Warn, "agent has never run on this host".to_owned()),
                };
                if state == CheckState::Fail {
                    checks.fail("service", "agent", detail, ExitStatus::IntegrityFailure);
                } else {
                    checks.add("service", "agent", state, detail);
                }
            }
            None => checks.add(
                "service",
                "agent",
                CheckState::Skipped,
                "database unavailable",
            ),
        }
        checks.add(
            "service",
            "self_integrity",
            CheckState::Skipped,
            "self-integrity monitoring arrives with milestone 6",
        );
    }

    let result = checks
        .list
        .iter()
        .map(|c| c.state)
        .filter(|s| *s != CheckState::Skipped)
        .max()
        .unwrap_or(CheckState::Pass);
    if result == CheckState::Warn {
        checks.exit = checks.exit.worst(ExitStatus::Findings);
    }

    if out.json {
        out.print_json(&Report {
            result,
            checks: checks.list,
        });
    } else {
        let width = checks
            .list
            .iter()
            .map(|c| c.component.len() + c.name.len() + 1)
            .max()
            .unwrap_or(0);
        for c in &checks.list {
            let label = format!("{}.{}", c.component, c.name);
            println!("{}  {label:<width$}  {}", out.check(c.state), c.detail);
        }
        let tone = match result {
            CheckState::Pass | CheckState::Skipped => Tone::Good,
            CheckState::Warn => Tone::Warn,
            CheckState::Fail => Tone::Bad,
        };
        println!("\nResult: {}", out.paint(tone, &result.to_string()));
    }
    Ok(checks.exit)
}

fn verify_database(cfg: &Config, report: bool, checks: &mut Checks) -> Option<Store> {
    let path = &cfg.general.database;
    let store = match Store::open_read_only(path) {
        Ok(s) => s,
        Err(e) => {
            let status = match e {
                StoreError::Missing(_) | StoreError::NeedsMigration { .. } => {
                    ExitStatus::NotInitialized
                }
                StoreError::PermissionDenied { .. } => ExitStatus::PermissionDenied,
                _ => ExitStatus::IntegrityFailure,
            };
            checks.fail("database", "open", e.to_string(), status);
            return None;
        }
    };
    if report {
        checks.add(
            "database",
            "schema",
            CheckState::Pass,
            format!("schema version {}", soteria_store::SCHEMA_VERSION),
        );
        match store.integrity_check() {
            Ok(p) if p.is_empty() => checks.add(
                "database",
                "integrity",
                CheckState::Pass,
                "SQLite integrity check passed",
            ),
            Ok(p) => checks.fail(
                "database",
                "integrity",
                p.join("; "),
                ExitStatus::IntegrityFailure,
            ),
            Err(e) => checks.fail(
                "database",
                "integrity",
                e.to_string(),
                ExitStatus::IntegrityFailure,
            ),
        }
        let perms = store.permission_problems();
        if perms.is_empty() {
            checks.add(
                "database",
                "permissions",
                CheckState::Pass,
                "owner-only access",
            );
        } else {
            checks.add(
                "database",
                "permissions",
                CheckState::Warn,
                perms.join("; "),
            );
        }
    }
    Some(store)
}
