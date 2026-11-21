//! Configuration loading and validation (SRS 7, FR-043).
//!
//! Parsing is strict: unknown keys, wrong types and malformed durations are
//! errors with a file location, never silently ignored. Semantic checks run in
//! [`Config::validate`], which returns every problem found rather than stopping
//! at the first one. A configuration with any [`IssueLevel::Error`] must not be
//! used to run monitoring; callers refuse to start instead of falling back to
//! a weaker setup.

use std::collections::HashSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use soteria_core::Severity;

/// The configuration schema version this build understands (SRS 4.6).
pub const CONFIG_VERSION: u32 = 1;

/// The documented default configuration, as installed by the packages.
pub const DEFAULT_CONFIG_TOML: &str = include_str!("../../../packaging/config/soteria.toml");

const LOG_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration file {path} not found")]
    NotFound { path: PathBuf },
    #[error("cannot read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid configuration in {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

/// Top-level configuration (SRS 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Configuration schema version. Defaults to the current version.
    pub version: u32,
    pub general: General,
    pub monitoring: Monitoring,
    pub scanning: Scanning,
    pub paths: Paths,
    pub alerts: Alerts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct General {
    pub log_level: String,
    pub database: PathBuf,
    pub event_retention_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Monitoring {
    pub execution: bool,
    pub file_integrity: bool,
    pub configuration: bool,
    pub kernel: bool,
    pub persistence: bool,
    pub users: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Scanning {
    pub full_scan_interval: HumanDuration,
    pub critical_scan_interval: HumanDuration,
    pub kernel_scan_interval: HumanDuration,
    pub startup_scan: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Paths {
    pub include: Vec<PathBuf>,
    pub exclude: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Alerts {
    pub minimum_severity: Severity,
    pub journal: bool,
    pub email: bool,
    pub webhook: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: CONFIG_VERSION,
            general: General::default(),
            monitoring: Monitoring::default(),
            scanning: Scanning::default(),
            paths: Paths::default(),
            alerts: Alerts::default(),
        }
    }
}

impl Default for General {
    fn default() -> Self {
        General {
            log_level: "info".into(),
            database: PathBuf::from(soteria_core::DEFAULT_DATABASE_PATH),
            event_retention_days: 90,
        }
    }
}

impl Default for Monitoring {
    fn default() -> Self {
        Monitoring {
            execution: true,
            file_integrity: true,
            configuration: true,
            kernel: true,
            persistence: true,
            users: true,
        }
    }
}

impl Default for Scanning {
    fn default() -> Self {
        Scanning {
            full_scan_interval: HumanDuration::from_secs(24 * 3600),
            critical_scan_interval: HumanDuration::from_secs(6 * 3600),
            kernel_scan_interval: HumanDuration::from_secs(24 * 3600),
            startup_scan: true,
        }
    }
}

impl Default for Paths {
    fn default() -> Self {
        let include = [
            "/etc",
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/lib64",
            "/boot",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/usr/local/bin",
            "/usr/local/sbin",
        ];
        let exclude = ["/proc", "/sys", "/dev", "/run"];
        Paths {
            include: include.iter().map(PathBuf::from).collect(),
            exclude: exclude.iter().map(PathBuf::from).collect(),
        }
    }
}

impl Default for Alerts {
    fn default() -> Self {
        Alerts {
            minimum_severity: Severity::Low,
            journal: true,
            email: false,
            webhook: false,
        }
    }
}

/// A duration written in human form in TOML, such as `"6h"` or `"30m"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    pub const fn from_secs(secs: u64) -> Self {
        HumanDuration(Duration::from_secs(secs))
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", humantime::format_duration(self.0))
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        humantime::parse_duration(&text)
            .map(HumanDuration)
            .map_err(|e| {
                serde::de::Error::custom(format!(
                    "invalid duration '{text}' ({e}); use forms like \"30m\", \"6h\" or \"1d\""
                ))
            })
    }
}

/// How serious a validation finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueLevel {
    /// Informational, such as a configured path that does not exist here.
    Note,
    /// Allowed, but weakens or limits monitoring; always reported.
    Warning,
    /// The configuration must not be used.
    Error,
}

impl fmt::Display for IssueLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IssueLevel::Note => "note",
            IssueLevel::Warning => "warning",
            IssueLevel::Error => "error",
        })
    }
}

/// One validation finding, tied to the configuration key it concerns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub level: IssueLevel,
    pub field: String,
    pub message: String,
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.level, self.field, self.message)
    }
}

/// Options for [`Config::validate`].
#[derive(Debug, Clone, Copy)]
pub struct ValidateOptions {
    /// Check whether configured paths exist on this host. Missing paths are
    /// reported as notes, since a path may legitimately not exist on one
    /// distribution (for example `/usr/lib64` on Debian).
    pub check_paths_exist: bool,
}

impl Default for ValidateOptions {
    fn default() -> Self {
        ValidateOptions {
            check_paths_exist: true,
        }
    }
}

impl Config {
    /// Parse configuration from TOML text. `origin` is only used in messages.
    pub fn from_toml_str(text: &str, origin: &Path) -> Result<Config, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: origin.to_owned(),
            message: e.to_string().trim_end().to_owned(),
        })
    }

    /// Load configuration from a file. A missing file is an error: Soteria
    /// never silently runs on built-in defaults in place of the
    /// administrator's configuration.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                ConfigError::NotFound {
                    path: path.to_owned(),
                }
            } else {
                ConfigError::Read {
                    path: path.to_owned(),
                    source,
                }
            }
        })?;
        Config::from_toml_str(&text, path)
    }

    /// Serialize the effective configuration back to TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("configuration is always serializable")
    }

    /// Run semantic validation and return all findings, most severe first.
    pub fn validate(&self, opts: ValidateOptions) -> Vec<Issue> {
        let mut v = Validator::default();

        if self.version != CONFIG_VERSION {
            v.error(
                "version",
                format!(
                    "unsupported configuration version {}; this build supports version {}",
                    self.version, CONFIG_VERSION
                ),
            );
        }

        // [general]
        if !LOG_LEVELS.contains(&self.general.log_level.as_str()) {
            v.error(
                "general.log_level",
                format!(
                    "unknown log level '{}'; expected one of: {}",
                    self.general.log_level,
                    LOG_LEVELS.join(", ")
                ),
            );
        }
        v.absolute_path("general.database", &self.general.database);
        if self.general.database.as_os_str().is_empty() {
            v.error("general.database", "database path must not be empty");
        }
        if self.general.event_retention_days == 0 {
            v.error(
                "general.event_retention_days",
                "retention must be at least 1 day; 0 would discard evidence immediately",
            );
        }

        // [monitoring]
        let m = &self.monitoring;
        let switches = [
            ("execution", m.execution),
            ("file_integrity", m.file_integrity),
            ("configuration", m.configuration),
            ("kernel", m.kernel),
            ("persistence", m.persistence),
            ("users", m.users),
        ];
        for (name, enabled) in switches {
            if !enabled {
                v.warning(
                    format!("monitoring.{name}"),
                    "monitoring is disabled by configuration and will be reported as a coverage gap",
                );
            }
        }

        // [scanning]
        let s = &self.scanning;
        for (name, d) in [
            ("full_scan_interval", s.full_scan_interval),
            ("critical_scan_interval", s.critical_scan_interval),
            ("kernel_scan_interval", s.kernel_scan_interval),
        ] {
            let field = format!("scanning.{name}");
            if d.0.is_zero() {
                v.error(field, "interval must be greater than zero");
            } else if d.0 < Duration::from_secs(60) {
                v.error(field, format!("interval {d} is below the 1 minute minimum"));
            } else if d.0 > Duration::from_secs(7 * 24 * 3600) {
                v.warning(field, format!("interval {d} is longer than a week; changes missed by event sensors may go undetected for that long"));
            }
        }
        if s.critical_scan_interval > s.full_scan_interval {
            v.warning(
                "scanning.critical_scan_interval",
                format!(
                    "critical files are verified less often ({}) than the full inventory ({})",
                    s.critical_scan_interval, s.full_scan_interval
                ),
            );
        }
        if !s.startup_scan {
            v.warning(
                "scanning.startup_scan",
                "startup scan is disabled; changes made while Soteria was stopped are only found at the next scheduled scan",
            );
        }

        // [paths]
        let p = &self.paths;
        if p.include.is_empty() {
            let level = if m.file_integrity {
                IssueLevel::Error
            } else {
                IssueLevel::Warning
            };
            v.push(
                level,
                "paths.include",
                "no paths are included; nothing would be inventoried",
            );
        }
        let mut seen = HashSet::new();
        for (i, path) in p.include.iter().enumerate() {
            let field = format!("paths.include[{i}]");
            v.absolute_path(&field, path);
            if !seen.insert(normalize(path)) {
                v.warning(
                    &field,
                    format!("{} is listed more than once", path.display()),
                );
            }
            if let Some(ex) = p.exclude.iter().find(|ex| is_within(path, ex)) {
                v.warning(
                    &field,
                    format!(
                        "{} is entirely excluded by {}; nothing under it will be monitored",
                        path.display(),
                        ex.display()
                    ),
                );
            } else if opts.check_paths_exist && path.is_absolute() && !path.exists() {
                v.note(
                    &field,
                    format!(
                        "{} does not exist on this host and will be skipped",
                        path.display()
                    ),
                );
            }
        }
        for (i, path) in p.exclude.iter().enumerate() {
            v.absolute_path(&format!("paths.exclude[{i}]"), path);
        }

        // [alerts]
        if self.alerts.minimum_severity > Severity::Medium {
            v.warning(
                "alerts.minimum_severity",
                format!(
                    "alerts below '{}' are not raised; medium and low findings will only be stored as events",
                    self.alerts.minimum_severity
                ),
            );
        }
        for (name, enabled) in [
            ("email", self.alerts.email),
            ("webhook", self.alerts.webhook),
        ] {
            if enabled {
                v.warning(
                    format!("alerts.{name}"),
                    format!("{name} notifications are not available in this build; alerts are still stored locally and sent to journald"),
                );
            }
        }
        if !self.alerts.journal {
            v.note(
                "alerts.journal",
                "alerts are not written to journald; use 'soteria alerts' to review them",
            );
        }

        let mut issues = v.issues;
        issues.sort_by_key(|i| std::cmp::Reverse(i.level));
        issues
    }
}

/// True if any issue in the list is an error.
pub fn has_errors(issues: &[Issue]) -> bool {
    issues.iter().any(|i| i.level == IssueLevel::Error)
}

#[derive(Default)]
struct Validator {
    issues: Vec<Issue>,
}

impl Validator {
    fn push(&mut self, level: IssueLevel, field: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            level,
            field: field.into(),
            message: message.into(),
        });
    }
    fn error(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.push(IssueLevel::Error, field, message);
    }
    fn warning(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.push(IssueLevel::Warning, field, message);
    }
    fn note(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.push(IssueLevel::Note, field, message);
    }
    fn absolute_path(&mut self, field: &str, path: &Path) {
        if path.as_os_str().is_empty() {
            return;
        }
        if !path.is_absolute() {
            self.error(
                field,
                format!("{} must be an absolute path", path.display()),
            );
        } else if path.components().any(|c| c == Component::ParentDir) {
            self.error(field, format!("{} must not contain '..'", path.display()));
        }
    }
}

fn normalize(path: &Path) -> PathBuf {
    path.components().collect()
}

/// True if `path` is `ancestor` or lies below it.
fn is_within(path: &Path, ancestor: &Path) -> bool {
    normalize(path).starts_with(normalize(ancestor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::from_toml_str(text, Path::new("test.toml"))
    }

    fn no_fs() -> ValidateOptions {
        ValidateOptions {
            check_paths_exist: false,
        }
    }

    #[test]
    fn shipped_default_matches_built_in_default() {
        let cfg = parse(DEFAULT_CONFIG_TOML).expect("shipped config parses");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn default_config_has_no_errors_or_warnings() {
        let issues = Config::default().validate(no_fs());
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");
    }

    #[test]
    fn empty_file_uses_defaults() {
        assert_eq!(parse("").unwrap(), Config::default());
    }

    #[test]
    fn unknown_keys_are_rejected_with_location() {
        let err = parse("[general]\nlog_levle = \"info\"\n").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("log_levle"), "{msg}");
        assert!(msg.contains("line 2"), "{msg}");
    }

    #[test]
    fn unknown_sections_are_rejected() {
        assert!(parse("[monitorin]\nexecution = true\n").is_err());
    }

    #[test]
    fn bad_duration_is_a_parse_error() {
        let err = parse("[scanning]\nfull_scan_interval = \"daily\"\n").unwrap_err();
        assert!(
            err.to_string().contains("invalid duration 'daily'"),
            "{err}"
        );
    }

    #[test]
    fn bad_severity_is_a_parse_error() {
        assert!(parse("[alerts]\nminimum_severity = \"severe\"\n").is_err());
    }

    #[test]
    fn wrong_type_is_a_parse_error() {
        assert!(parse("[monitoring]\nexecution = \"yes\"\n").is_err());
    }

    #[test]
    fn semantic_errors_are_all_reported() {
        let cfg = parse(
            r#"
            [general]
            log_level = "loud"
            database = "soteria.db"
            event_retention_days = 0
            [scanning]
            full_scan_interval = "10s"
            [paths]
            include = ["etc", "/usr/../tmp"]
            "#,
        )
        .unwrap();
        let issues = cfg.validate(no_fs());
        let errors: Vec<&str> = issues
            .iter()
            .filter(|i| i.level == IssueLevel::Error)
            .map(|i| i.field.as_str())
            .collect();
        assert_eq!(
            errors,
            vec![
                "general.log_level",
                "general.database",
                "general.event_retention_days",
                "scanning.full_scan_interval",
                "paths.include[0]",
                "paths.include[1]",
            ]
        );
        assert!(has_errors(&issues));
    }

    #[test]
    fn disabling_monitoring_is_reported_not_silent() {
        let cfg = parse("[monitoring]\nexecution = false\n").unwrap();
        let issues = cfg.validate(no_fs());
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].level, IssueLevel::Warning);
        assert_eq!(issues[0].field, "monitoring.execution");
        assert!(!has_errors(&issues));
    }

    #[test]
    fn empty_include_is_an_error_when_integrity_monitoring_is_on() {
        let cfg = parse("[paths]\ninclude = []\n").unwrap();
        assert!(has_errors(&cfg.validate(no_fs())));
    }

    #[test]
    fn include_swallowed_by_exclude_is_warned() {
        let cfg = parse("[paths]\ninclude = [\"/run/foo\"]\nexclude = [\"/run\"]\n").unwrap();
        let issues = cfg.validate(no_fs());
        assert!(
            issues
                .iter()
                .any(|i| i.field == "paths.include[0]" && i.message.contains("entirely excluded"))
        );
    }

    #[test]
    fn exclude_prefix_matches_whole_components_only() {
        assert!(is_within(Path::new("/run/foo"), Path::new("/run")));
        assert!(is_within(Path::new("/run"), Path::new("/run")));
        assert!(!is_within(Path::new("/runtime"), Path::new("/run")));
    }

    #[test]
    fn missing_paths_are_notes_not_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let cfg = Config {
            paths: Paths {
                include: vec![dir.path().to_owned(), missing],
                exclude: vec![],
            },
            ..Config::default()
        };
        let issues = cfg.validate(ValidateOptions::default());
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].level, IssueLevel::Note);
        assert_eq!(issues[0].field, "paths.include[1]");
    }

    #[test]
    fn unavailable_notifications_are_warned() {
        let cfg = parse("[alerts]\nemail = true\n").unwrap();
        let issues = cfg.validate(no_fs());
        assert!(issues.iter().any(|i| i.field == "alerts.email"));
    }

    #[test]
    fn future_version_is_rejected() {
        let cfg = parse("version = 2\n").unwrap();
        assert!(has_errors(&cfg.validate(no_fs())));
    }

    #[test]
    fn missing_file_is_not_found() {
        let err = Config::load(Path::new("/nonexistent/soteria.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::NotFound { .. }));
    }

    #[test]
    fn effective_config_round_trips() {
        let cfg = Config::default();
        assert_eq!(parse(&cfg.to_toml()).unwrap(), cfg);
    }
}
