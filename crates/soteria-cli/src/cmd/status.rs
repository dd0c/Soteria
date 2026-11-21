//! `soteria status` (FR-039, SRS 6.1).
//!
//! Status always prints as much as it can determine. A missing database or
//! invalid configuration is shown in the report and reflected in the exit
//! code rather than aborting the command.

use std::path::PathBuf;

use serde::Serialize;
use soteria_config::{Config, IssueLevel, ValidateOptions, has_errors};
use soteria_core::{ExitStatus, Severity};
use soteria_platform::{Platform, ProbeState};
use soteria_store::{Store, StoreError, Summary};

use crate::cli::GlobalArgs;
use crate::health::{AgentHealth, AgentState, agent_health};
use crate::output::{CmdResult, Output, Tone};

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub version: &'static str,
    pub host: String,
    pub os: OsSection,
    pub protection: Protection,
    pub config: ConfigSection,
    pub database: DatabaseSection,
    pub baseline: BaselineSection,
    pub integrity: &'static str,
    pub monitoring: Option<AgentHealth>,
    pub indexed_files: Option<u64>,
    pub open_alerts: Option<AlertCounts>,
    pub last_full_scan: Option<String>,
    pub last_integrity_verification: Option<String>,
    pub coverage: Coverage,
}

#[derive(Debug, Serialize)]
pub struct OsSection {
    pub name: String,
    pub support: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protection {
    Active,
    Degraded,
    Inactive,
    NotInitialized,
}

impl Protection {
    fn label(self) -> &'static str {
        match self {
            Protection::Active => "ACTIVE",
            Protection::Degraded => "DEGRADED",
            Protection::Inactive => "INACTIVE",
            Protection::NotInitialized => "NOT INITIALIZED",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ConfigSection {
    pub path: PathBuf,
    pub state: &'static str,
    pub message: Option<String>,
    pub warnings: usize,
}

#[derive(Debug, Serialize)]
pub struct DatabaseSection {
    pub path: Option<PathBuf>,
    pub state: &'static str,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BaselineSection {
    pub established: bool,
    pub version: Option<u32>,
    pub approved_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AlertCounts {
    pub total: u64,
    pub by_severity: std::collections::BTreeMap<Severity, u64>,
}

#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    pub open_gaps: u64,
    pub disabled_monitors: Vec<String>,
    pub unavailable_capabilities: Vec<String>,
}

impl Coverage {
    fn total(&self) -> usize {
        self.open_gaps as usize + self.disabled_monitors.len() + self.unavailable_capabilities.len()
    }
}

pub fn run(global: &GlobalArgs, out: &Output) -> CmdResult {
    let (report, mut exit) = build(global);
    if out.json {
        out.print_json(&report);
    } else {
        print_text(&report, out);
    }
    if report.protection != Protection::Active
        || report.open_alerts.as_ref().is_some_and(|a| a.total > 0)
    {
        exit = exit.worst(ExitStatus::Findings);
    }
    Ok(exit)
}

fn build(global: &GlobalArgs) -> (StatusReport, ExitStatus) {
    let mut exit = ExitStatus::Ok;
    let mut coverage = Coverage::default();

    let platform = Platform::detect().ok();
    let os = match &platform {
        Some(p) => OsSection {
            name: p.display_name(),
            support: p.support.to_string(),
        },
        None => OsSection {
            name: "unknown".into(),
            support: "unknown".into(),
        },
    };
    if let Some(p) = &platform {
        for probe in p.probe() {
            if probe.state != ProbeState::Available {
                coverage
                    .unavailable_capabilities
                    .push(format!("{}: {}", probe.name, probe.detail));
            }
        }
    }

    // Configuration.
    let (config, config_section) = match Config::load(&global.config) {
        Ok(cfg) => {
            let issues = cfg.validate(ValidateOptions::default());
            let warnings = issues
                .iter()
                .filter(|i| i.level == IssueLevel::Warning)
                .count();
            if has_errors(&issues) {
                exit = exit.worst(ExitStatus::ConfigInvalid);
                (
                    None,
                    ConfigSection {
                        path: global.config.clone(),
                        state: "invalid",
                        message: Some("run 'soteria config validate' for details".into()),
                        warnings,
                    },
                )
            } else {
                let m = &cfg.monitoring;
                for (name, on) in [
                    ("execution", m.execution),
                    ("file_integrity", m.file_integrity),
                    ("configuration", m.configuration),
                    ("kernel", m.kernel),
                    ("persistence", m.persistence),
                    ("users", m.users),
                ] {
                    if !on {
                        coverage.disabled_monitors.push(name.to_owned());
                    }
                }
                (
                    Some(cfg),
                    ConfigSection {
                        path: global.config.clone(),
                        state: "valid",
                        message: None,
                        warnings,
                    },
                )
            }
        }
        Err(e) => {
            exit = exit.worst(ExitStatus::ConfigInvalid);
            (
                None,
                ConfigSection {
                    path: global.config.clone(),
                    state: "unusable",
                    message: Some(e.to_string()),
                    warnings: 0,
                },
            )
        }
    };

    // Database.
    let mut database = DatabaseSection {
        path: config.as_ref().map(|c| c.general.database.clone()),
        state: "unknown",
        message: None,
    };
    let mut summary: Option<Summary> = None;
    let mut agent = None;
    if let Some(cfg) = &config {
        match Store::open_read_only(&cfg.general.database) {
            Ok(store) => match store.summary() {
                Ok(s) => {
                    database.state = "ok";
                    agent = Some(agent_health(&store, &s));
                    summary = Some(s);
                }
                Err(e) => {
                    database.state = "error";
                    database.message = Some(e.to_string());
                    exit = exit.worst(ExitStatus::IntegrityFailure);
                }
            },
            Err(e) => {
                let (state, status) = match &e {
                    StoreError::Missing(_) | StoreError::NeedsMigration { .. } => {
                        ("not_initialized", ExitStatus::NotInitialized)
                    }
                    StoreError::PermissionDenied { .. } => {
                        ("permission_denied", ExitStatus::PermissionDenied)
                    }
                    _ => ("error", ExitStatus::IntegrityFailure),
                };
                database.state = state;
                database.message = Some(e.to_string());
                exit = exit.worst(status);
            }
        }
    }

    let baseline = BaselineSection {
        established: summary
            .as_ref()
            .is_some_and(|s| s.baseline_version.is_some()),
        version: summary.as_ref().and_then(|s| s.baseline_version),
        approved_at: summary
            .as_ref()
            .and_then(|s| s.baseline_approved_at.clone()),
    };
    if let Some(s) = &summary {
        coverage.open_gaps = s.open_coverage_gaps;
    }

    let running = agent
        .as_ref()
        .is_some_and(|a| a.state == AgentState::Running);
    let protection = if database.state == "not_initialized" {
        Protection::NotInitialized
    } else if running && baseline.established && coverage.total() == 0 {
        Protection::Active
    } else if running {
        Protection::Degraded
    } else {
        Protection::Inactive
    };

    let report = StatusReport {
        version: soteria_core::VERSION,
        host: soteria_platform::hostname(),
        os,
        protection,
        config: config_section,
        database,
        integrity: if baseline.established {
            // Sealed-baseline verification arrives with milestone 2.
            "UNVERIFIED"
        } else {
            "NO BASELINE"
        },
        baseline,
        monitoring: agent,
        indexed_files: summary.as_ref().map(|s| s.indexed_files),
        open_alerts: summary.as_ref().map(|s| AlertCounts {
            total: s.open_alert_total(),
            by_severity: s.open_alerts.clone(),
        }),
        last_full_scan: summary.as_ref().and_then(|s| s.last_full_scan.clone()),
        last_integrity_verification: summary.as_ref().and_then(|s| s.last_verification.clone()),
        coverage,
    };
    (report, exit)
}

fn print_text(r: &StatusReport, out: &Output) {
    let tone_for = |good: bool| if good { Tone::Good } else { Tone::Warn };
    println!("{}", out.paint(Tone::Bold, "SOTERIA HOST SECURITY"));
    println!("Host: {} | OS: {} ({})", r.host, r.os.name, r.os.support);

    let protection_tone = match r.protection {
        Protection::Active => Tone::Good,
        Protection::Degraded => Tone::Warn,
        _ => Tone::Bad,
    };
    let baseline = if r.baseline.established {
        format!("ESTABLISHED (v{})", r.baseline.version.unwrap_or_default())
    } else {
        "NOT ESTABLISHED".to_owned()
    };
    println!(
        "Protection: {} | Baseline: {}",
        out.paint(protection_tone, r.protection.label()),
        out.paint(tone_for(r.baseline.established), &baseline)
    );
    let monitoring = r
        .monitoring
        .as_ref()
        .map(|m| m.state.label())
        .unwrap_or("UNKNOWN");
    println!(
        "Integrity: {} | Monitoring: {}",
        out.paint(tone_for(r.integrity == "VERIFIED"), r.integrity),
        out.paint(tone_for(monitoring == "RUNNING"), monitoring)
    );

    let cfg_line = match &r.config.message {
        Some(m) => format!("{} ({m})", r.config.state),
        None if r.config.warnings > 0 => {
            format!("{} ({} warning(s))", r.config.state, r.config.warnings)
        }
        None => r.config.state.to_owned(),
    };
    println!("Configuration: {} [{}]", cfg_line, r.config.path.display());
    if let Some(path) = &r.database.path {
        let db = match &r.database.message {
            Some(m) => format!("{} ({m})", r.database.state),
            None => r.database.state.to_owned(),
        };
        println!("Database: {} [{}]", db, path.display());
    }

    if let Some(n) = r.indexed_files {
        println!("Indexed files: {}", group_thousands(n));
    }
    if let Some(a) = &r.open_alerts {
        let parts: Vec<String> = a
            .by_severity
            .iter()
            .rev()
            .map(|(sev, n)| format!("{n} {}", capitalize(sev.as_str())))
            .collect();
        if parts.is_empty() {
            println!("Open alerts: 0");
        } else {
            println!("Open alerts: {} ({})", a.total, parts.join(", "));
        }
    }
    if r.database.state == "ok" {
        println!(
            "Last full scan: {}",
            r.last_full_scan.as_deref().unwrap_or("never")
        );
        println!(
            "Last integrity verification: {}",
            r.last_integrity_verification.as_deref().unwrap_or("never")
        );
    }
    let gaps = r.coverage.total();
    if gaps == 0 {
        println!("Coverage: {}", out.paint(Tone::Good, "no known gaps"));
    } else {
        println!(
            "Coverage: {} (see `soteria verify`)",
            out.paint(Tone::Warn, &format!("{gaps} gap(s)"))
        );
    }
    if r.protection == Protection::NotInitialized {
        println!();
        println!("Soteria is not initialized on this host. Run: sudo soteria init");
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

fn group_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_thousands() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(48291), "48,291");
        assert_eq!(group_thousands(1234567), "1,234,567");
    }
}
