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
use crate::context::{BaselineCheck, check_latest_baseline};
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
    }

    let store = match &config {
        Some(cfg)
            if wanted(Component::Database)
                || wanted(Component::Baseline)
                || wanted(Component::Sensors)
                || wanted(Component::Service) =>
        {
            verify_database(cfg, wanted(Component::Database), &mut checks)
        }
        _ => None,
    };

    // Event sensors as last reported by the agent.
    if wanted(Component::Sensors)
        && let Some(s) = &store
    {
        let sensors: Vec<_> = s
            .sensor_states()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.sensor != "agent" && s.sensor != "baseline")
            .collect();
        if sensors.is_empty() {
            checks.add(
                "sensors",
                "event_sensors",
                CheckState::Warn,
                "no sensor has reported yet; the monitoring service has not run",
            );
        }
        for sensor in sensors {
            let detail = format!(
                "{} since {}{}",
                sensor.state,
                sensor.since,
                sensor.detail.map(|d| format!(": {d}")).unwrap_or_default()
            );
            let name = format!("{}_sensor", sensor.sensor);
            match sensor.state.as_str() {
                "running" => checks.add("sensors", name, CheckState::Pass, detail),
                "disabled" => checks.add("sensors", name, CheckState::Skipped, detail),
                "failed" => checks.fail("sensors", name, detail, ExitStatus::Unavailable),
                _ => checks.add("sensors", name, CheckState::Warn, detail),
            }
        }
    }

    if wanted(Component::Baseline) {
        match (&store, &config) {
            (Some(s), Some(cfg)) => match check_latest_baseline(s, cfg) {
                Ok(BaselineCheck::None) => checks.add(
                    "baseline",
                    "established",
                    CheckState::Warn,
                    "no approved baseline; changes cannot be detected yet",
                ),
                Ok(BaselineCheck::Verified { version }) => checks.add(
                    "baseline",
                    "seal",
                    CheckState::Pass,
                    format!("baseline v{version} digest and signature verified"),
                ),
                Ok(BaselineCheck::Failed { version, problems }) => checks.fail(
                    "baseline",
                    "seal",
                    format!("baseline v{version}: {}", problems.join("; ")),
                    ExitStatus::IntegrityFailure,
                ),
                Ok(BaselineCheck::Unverifiable { version, reason }) => checks.fail(
                    "baseline",
                    "seal",
                    format!("baseline v{version} cannot be verified: {reason}"),
                    ExitStatus::IntegrityFailure,
                ),
                Err(f) => checks.fail("baseline", "seal", f.message, f.status),
            },
            _ => checks.add(
                "baseline",
                "seal",
                CheckState::Skipped,
                "database unavailable",
            ),
        }
        if let Some(s) = &store {
            let open: i64 = s
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM coverage_gaps WHERE closed_at IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or_default();
            if open == 0 {
                checks.add(
                    "coverage",
                    "gaps",
                    CheckState::Pass,
                    "no open coverage gaps",
                );
            } else {
                let mut stmt = s
                    .connection()
                    .prepare(
                        "SELECT kind, path, detail FROM coverage_gaps WHERE closed_at IS NULL
                         ORDER BY opened_at DESC, id LIMIT 20",
                    )
                    .ok();
                let rows: Vec<(String, Option<Vec<u8>>, String)> = stmt
                    .as_mut()
                    .and_then(|st| {
                        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                            .ok()
                            .map(|it| it.filter_map(Result::ok).collect())
                    })
                    .unwrap_or_default();
                checks.add(
                    "coverage",
                    "gaps",
                    CheckState::Warn,
                    format!("{open} open coverage gap(s)"),
                );
                for (kind, path, detail) in rows {
                    let path = path
                        .map(|p| String::from_utf8_lossy(&p).into_owned())
                        .unwrap_or_default();
                    checks.add(
                        "coverage",
                        kind,
                        CheckState::Warn,
                        format!("{path}: {detail}"),
                    );
                }
            }
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
