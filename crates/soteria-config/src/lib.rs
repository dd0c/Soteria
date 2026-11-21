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
    pub execution: Execution,
    pub baseline: Baseline,
    pub notifications: Notifications,
    pub alerts: Alerts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct General {
    pub log_level: String,
    pub database: PathBuf,
    pub event_retention_days: u32,
    /// Administrator detection rules (`*.toml`).
    pub rules_directory: PathBuf,
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

/// Email and webhook delivery settings (FR-031). Delivery is switched on by
/// `alerts.email` and `alerts.webhook`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Notifications {
    pub email: Email,
    pub webhook: Webhook,
}

/// How the SMTP connection is encrypted. Plain SMTP is not offered:
/// alerts carry evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    /// Plain connection upgraded with STARTTLS (usually port 587).
    Starttls,
    /// TLS from the start (usually port 465).
    Implicit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Email {
    /// SMTP relay, `host` or `host:port`.
    pub relay: String,
    pub tls: SmtpTls,
    pub from: String,
    pub to: Vec<String>,
    /// SMTP login; empty for none.
    pub username: String,
    /// File holding the SMTP password (root-only); required with a username.
    pub password_file: PathBuf,
    /// CA certificates (PEM) to trust instead of the system store.
    pub ca_file: PathBuf,
    pub minimum_severity: Severity,
    pub timeout: HumanDuration,
}

impl Default for Email {
    fn default() -> Self {
        Email {
            relay: String::new(),
            tls: SmtpTls::Starttls,
            from: String::new(),
            to: Vec::new(),
            username: String::new(),
            password_file: PathBuf::new(),
            ca_file: PathBuf::new(),
            minimum_severity: Severity::High,
            timeout: HumanDuration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Webhook {
    /// HTTPS endpoint that receives a JSON POST.
    pub url: String,
    /// File holding a bearer token sent as `Authorization: Bearer`.
    pub token_file: PathBuf,
    /// CA certificates (PEM) to trust instead of the system store.
    pub ca_file: PathBuf,
    pub minimum_severity: Severity,
    pub timeout: HumanDuration,
}

impl Default for Webhook {
    fn default() -> Self {
        Webhook {
            url: String::new(),
            token_file: PathBuf::new(),
            ca_file: PathBuf::new(),
            minimum_severity: Severity::High,
            timeout: HumanDuration::from_secs(10),
        }
    }
}

/// Split `host` or `host:port` (IPv6 in brackets) for SMTP.
pub fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        match after.strip_prefix(':') {
            Some(p) => (h, p.parse().ok()?),
            None if after.is_empty() => (h, default_port),
            None => return None,
        }
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (s, default_port),
        }
    };
    let valid = !host.is_empty()
        && port != 0
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(&b));
    valid.then(|| (host.to_owned(), port))
}

/// A plain email address, without display names or header-breaking bytes.
pub fn valid_address(a: &str) -> bool {
    let Some((local, domain)) = a.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && (domain.contains('.') || domain == "localhost")
        && a.bytes().all(|b| b.is_ascii_graphic() && !b"<>()[],;:\\\"".contains(&b))
}

/// How much of a command line is stored (NFR-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentPolicy {
    /// Arguments as executed.
    Full,
    /// Values that look like secrets (passwords, tokens, keys, URL
    /// credentials) are replaced with `[REDACTED]`.
    Redacted,
    /// Only the program name (argument 0).
    None,
}

/// Execution monitoring (FR-009..FR-012).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Execution {
    pub arguments: ArgumentPolicy,
    /// Stored command lines are cut to this many bytes.
    pub max_argument_bytes: usize,
    /// Executables larger than this are not hashed.
    pub hash_max_bytes: u64,
    /// Locations where execution is unusual (FR-011), in addition to hidden
    /// paths, deleted or memory-only programs, and files writable by
    /// non-root users.
    pub unusual_paths: Vec<PathBuf>,
    /// A program created or changed this recently counts as new.
    pub recent_change: HumanDuration,
}

impl Default for Execution {
    fn default() -> Self {
        Execution {
            arguments: ArgumentPolicy::Redacted,
            max_argument_bytes: 4096,
            hash_max_bytes: 256 << 20,
            unusual_paths: [
                "/tmp",
                "/var/tmp",
                "/dev/shm",
                "/run/user",
                "/dev/mqueue",
                "/home",
                "/root",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            recent_change: HumanDuration::from_secs(3600),
        }
    }
}

/// Baseline signing keys (FR-006). The private key is readable by root only;
/// the daemon only needs the public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Baseline {
    pub signing_key: PathBuf,
    pub public_key: PathBuf,
}

impl Default for Baseline {
    fn default() -> Self {
        Baseline {
            signing_key: PathBuf::from("/etc/soteria/keys/baseline.key"),
            public_key: PathBuf::from("/etc/soteria/keys/baseline.pub"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Alerts {
    pub minimum_severity: Severity,
    /// Related alerts this close together are grouped into incidents.
    pub correlation_window: HumanDuration,
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
            execution: Execution::default(),
            baseline: Baseline::default(),
            notifications: Notifications::default(),
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
            rules_directory: PathBuf::from("/etc/soteria/rules.d"),
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
            correlation_window: HumanDuration::from_secs(3600),
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
        v.absolute_path("general.rules_directory", &self.general.rules_directory);
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

        // [execution]
        let e = &self.execution;
        for (i, path) in e.unusual_paths.iter().enumerate() {
            v.absolute_path(&format!("execution.unusual_paths[{i}]"), path);
        }
        if e.max_argument_bytes < 64 {
            v.error(
                "execution.max_argument_bytes",
                "must be at least 64 so the program name and first arguments are kept",
            );
        }
        if e.arguments == ArgumentPolicy::Full {
            v.note(
                "execution.arguments",
                "command lines are stored unredacted and may contain passwords or tokens",
            );
        }
        if e.hash_max_bytes == 0 {
            v.warning(
                "execution.hash_max_bytes",
                "executables are never hashed; every execution is classified as unverified",
            );
        }

        // [baseline]
        v.absolute_path("baseline.signing_key", &self.baseline.signing_key);
        v.absolute_path("baseline.public_key", &self.baseline.public_key);
        if self.baseline.signing_key == self.baseline.public_key {
            v.error(
                "baseline.public_key",
                "the public key must be a different file from the signing key",
            );
        }

        // [notifications]
        let e = &self.notifications.email;
        v.absolute_path("notifications.email.password_file", &e.password_file);
        v.absolute_path("notifications.email.ca_file", &e.ca_file);
        if self.alerts.email {
            if split_host_port(&e.relay, 587).is_none() {
                v.error(
                    "notifications.email.relay",
                    format!("'{}' is not a valid relay; use host or host:port (alerts.email is on)", e.relay),
                );
            }
            if !valid_address(&e.from) {
                v.error("notifications.email.from", format!("'{}' is not a valid email address", e.from));
            }
            if e.to.is_empty() {
                v.error("notifications.email.to", "no recipients (alerts.email is on)");
            }
            for (i, to) in e.to.iter().enumerate() {
                if !valid_address(to) {
                    v.error(format!("notifications.email.to[{i}]"), format!("'{to}' is not a valid email address"));
                }
            }
            if e.username.is_empty() != e.password_file.as_os_str().is_empty() {
                v.error(
                    "notifications.email.password_file",
                    "username and password_file must be set together",
                );
            }
        }
        let w = &self.notifications.webhook;
        v.absolute_path("notifications.webhook.token_file", &w.token_file);
        v.absolute_path("notifications.webhook.ca_file", &w.ca_file);
        if self.alerts.webhook {
            let ok = w
                .url
                .strip_prefix("https://")
                .and_then(|rest| split_host_port(rest.split('/').next().unwrap_or(""), 443))
                .is_some()
                && !w.url.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control());
            if !ok {
                v.error(
                    "notifications.webhook.url",
                    format!("'{}' is not a valid https:// URL (alerts.webhook is on; plain http is not allowed)", w.url),
                );
            }
        }
        for (field, d) in [
            ("notifications.email.timeout", e.timeout),
            ("notifications.webhook.timeout", w.timeout),
        ] {
            if d.0 < Duration::from_secs(1) || d.0 > Duration::from_secs(300) {
                v.error(field, format!("{d} must be between 1 second and 5 minutes"));
            }
        }

        // [alerts]
        let w = self.alerts.correlation_window.0;
        if w < Duration::from_secs(60) || w > Duration::from_secs(7 * 24 * 3600) {
            v.error(
                "alerts.correlation_window",
                format!(
                    "{} must be between 1 minute and 7 days",
                    self.alerts.correlation_window
                ),
            );
        }
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
        assert!(parse("[notifications.email]\ntls = \"none\"\n").is_err());
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

    #[test]
    fn notification_settings_are_checked_when_enabled() {
        let errors = |text: &str| -> Vec<String> {
            Config::from_toml_str(text, Path::new("t"))
                .unwrap()
                .validate(ValidateOptions { check_paths_exist: false })
                .into_iter()
                .filter(|i| i.level == IssueLevel::Error)
                .map(|i| i.field)
                .collect()
        };
        // Configured but switched off: not checked.
        assert!(errors("[notifications.webhook]\nurl = \"http://x\"\n").is_empty());
        let e = errors("[alerts]\nemail = true\nwebhook = true\n");
        for f in ["notifications.email.relay", "notifications.email.from", "notifications.email.to", "notifications.webhook.url"] {
            assert!(e.contains(&f.to_owned()), "{f}: {e:?}");
        }
        let good = "[notifications.email]\nrelay = \"mail.example.com:587\"\nfrom = \"soteria@host.example.com\"\n\
                    to = [\"secops@example.com\"]\n[notifications.webhook]\nurl = \"https://hooks.example.com/x\"\n\
                    [alerts]\nemail = true\nwebhook = true\n";
        assert!(errors(good).is_empty(), "{:?}", errors(good));
        let e = errors(&good.replace("https://hooks", "http://hooks").replace("secops@example.com", "a@b.c\\r\\nBcc: x@y.z"));
        assert_eq!(e, ["notifications.email.to[0]", "notifications.webhook.url"]);
        let e = errors(&good.replace("relay = ", "username = \"u\"\nrelay = "));
        assert_eq!(e, ["notifications.email.password_file"]);
        assert_eq!(split_host_port("[::1]:25", 587), Some(("::1".into(), 25)));
        assert_eq!(split_host_port("mail", 587), Some(("mail".into(), 587)));
        assert_eq!(split_host_port("mail:x", 587), None);
    }
}
