//! Shared domain types for Soteria.
//!
//! This crate holds the vocabulary every other component uses: severity levels
//! (FR-028), object classification (FR-002), and the documented CLI exit codes
//! (FR-042). It has no I/O and no platform dependencies.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Product version, shared by the CLI, daemon and database metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical configuration path (SRS 7). Packaging must not change it.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/soteria/soteria.toml";

/// Default database path (SRS 7, 8.1).
pub const DEFAULT_DATABASE_PATH: &str = "/var/lib/soteria/soteria.db";

/// Error returned when parsing one of the enums in this crate from text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} '{value}', expected one of: {expected}")]
pub struct ParseEnumError {
    pub kind: &'static str,
    pub value: String,
    pub expected: &'static str,
}

/// Event and alert severity (FR-028). Ordered from least to most severe, so
/// `Severity::High > Severity::Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Severity::ALL
            .into_iter()
            .find(|sev| sev.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| ParseEnumError {
                kind: "severity",
                value: s.to_owned(),
                expected: "critical, high, medium, low, info",
            })
    }
}

/// Classification of an indexed filesystem object (FR-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    ExecutableBinary,
    SharedLibrary,
    Script,
    KernelImage,
    KernelModule,
    Configuration,
    ServiceUnit,
    ScheduledJob,
    SecuritySensitive,
    Symlink,
    Directory,
    Other,
}

impl FileKind {
    pub const ALL: [FileKind; 12] = [
        FileKind::ExecutableBinary,
        FileKind::SharedLibrary,
        FileKind::Script,
        FileKind::KernelImage,
        FileKind::KernelModule,
        FileKind::Configuration,
        FileKind::ServiceUnit,
        FileKind::ScheduledJob,
        FileKind::SecuritySensitive,
        FileKind::Symlink,
        FileKind::Directory,
        FileKind::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::ExecutableBinary => "executable_binary",
            FileKind::SharedLibrary => "shared_library",
            FileKind::Script => "script",
            FileKind::KernelImage => "kernel_image",
            FileKind::KernelModule => "kernel_module",
            FileKind::Configuration => "configuration",
            FileKind::ServiceUnit => "service_unit",
            FileKind::ScheduledJob => "scheduled_job",
            FileKind::SecuritySensitive => "security_sensitive",
            FileKind::Symlink => "symlink",
            FileKind::Directory => "directory",
            FileKind::Other => "other",
        }
    }
}

impl fmt::Display for FileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FileKind {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        FileKind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| ParseEnumError {
                kind: "file kind",
                value: s.to_owned(),
                expected: "executable_binary, shared_library, script, kernel_image, \
                           kernel_module, configuration, service_unit, scheduled_job, \
                           security_sensitive, symlink, directory, other",
            })
    }
}

/// Documented CLI exit codes (FR-042). The numeric values are a stable
/// interface for scripts and must not be renumbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    /// Command succeeded and found nothing that needs attention.
    Ok = 0,
    /// Command succeeded and reports findings (changes, open alerts, gaps).
    Findings = 1,
    /// Invalid command-line usage.
    Usage = 2,
    /// Configuration is missing or invalid.
    ConfigInvalid = 3,
    /// Database, baseline or self-integrity verification failed.
    IntegrityFailure = 4,
    /// Soteria has not been initialized on this host.
    NotInitialized = 5,
    /// The command lacks the privileges it needs.
    PermissionDenied = 6,
    /// The feature is unavailable on this platform or in this build.
    Unavailable = 7,
    /// Unexpected internal error.
    Internal = 10,
}

impl ExitStatus {
    pub const ALL: [ExitStatus; 9] = [
        ExitStatus::Ok,
        ExitStatus::Findings,
        ExitStatus::Usage,
        ExitStatus::ConfigInvalid,
        ExitStatus::IntegrityFailure,
        ExitStatus::NotInitialized,
        ExitStatus::PermissionDenied,
        ExitStatus::Unavailable,
        ExitStatus::Internal,
    ];

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn description(self) -> &'static str {
        match self {
            ExitStatus::Ok => "success, nothing needs attention",
            ExitStatus::Findings => "success, findings reported (changes, alerts or coverage gaps)",
            ExitStatus::Usage => "invalid command-line usage",
            ExitStatus::ConfigInvalid => "configuration missing or invalid",
            ExitStatus::IntegrityFailure => {
                "database, baseline or self-integrity verification failed"
            }
            ExitStatus::NotInitialized => "Soteria is not initialized on this host",
            ExitStatus::PermissionDenied => "insufficient privileges",
            ExitStatus::Unavailable => "feature unavailable on this platform or in this build",
            ExitStatus::Internal => "internal error",
        }
    }

    /// The more serious of two statuses, used when a command performs several
    /// checks. Failures outrank findings, which outrank success.
    pub fn worst(self, other: ExitStatus) -> ExitStatus {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    fn rank(self) -> u8 {
        match self {
            ExitStatus::Ok => 0,
            ExitStatus::Findings => 1,
            ExitStatus::Unavailable => 2,
            ExitStatus::NotInitialized => 3,
            ExitStatus::Usage => 4,
            ExitStatus::PermissionDenied => 5,
            ExitStatus::ConfigInvalid => 6,
            ExitStatus::IntegrityFailure => 7,
            ExitStatus::Internal => 8,
        }
    }
}

/// Outcome of a single verification check, shared by `status`, `verify`
/// and the health monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Pass,
    /// Not checked yet or not applicable in this milestone.
    Skipped,
    Warn,
    Fail,
}

impl fmt::Display for CheckState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CheckState::Pass => "PASS",
            CheckState::Skipped => "SKIP",
            CheckState::Warn => "WARN",
            CheckState::Fail => "FAIL",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_from_info_to_critical() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_parses_case_insensitively() {
        assert_eq!("HIGH".parse::<Severity>().unwrap(), Severity::High);
        assert_eq!("info".parse::<Severity>().unwrap(), Severity::Info);
        assert!("severe".parse::<Severity>().is_err());
    }

    #[test]
    fn severity_round_trips_through_json() {
        for sev in Severity::ALL {
            let json = serde_json::to_string(&sev).unwrap();
            assert_eq!(json, format!("\"{}\"", sev.as_str()));
            assert_eq!(serde_json::from_str::<Severity>(&json).unwrap(), sev);
        }
    }

    #[test]
    fn file_kind_round_trips_through_str() {
        for kind in FileKind::ALL {
            assert_eq!(kind.as_str().parse::<FileKind>().unwrap(), kind);
        }
    }

    #[test]
    fn exit_codes_are_stable() {
        let codes: Vec<u8> = ExitStatus::ALL.iter().map(|s| s.code()).collect();
        assert_eq!(codes, vec![0, 1, 2, 3, 4, 5, 6, 7, 10]);
    }

    #[test]
    fn worst_prefers_failures_over_findings() {
        assert_eq!(
            ExitStatus::Ok.worst(ExitStatus::Findings),
            ExitStatus::Findings
        );
        assert_eq!(
            ExitStatus::Findings.worst(ExitStatus::IntegrityFailure),
            ExitStatus::IntegrityFailure
        );
        assert_eq!(
            ExitStatus::Internal.worst(ExitStatus::Ok),
            ExitStatus::Internal
        );
    }
}
