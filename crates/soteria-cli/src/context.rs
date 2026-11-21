//! Shared helpers for commands: configuration, database and identity.

use std::path::Path;

use soteria_config::{Config, ConfigError, Issue, ValidateOptions, has_errors};
use soteria_core::ExitStatus;
use soteria_store::StoreError;

use crate::output::Failure;

/// Load and validate the configuration. Errors become a [`Failure`]; the
/// returned issues hold the remaining warnings and notes.
pub fn load_config(path: &Path) -> Result<(Config, Vec<Issue>), Failure> {
    let config = Config::load(path).map_err(config_failure)?;
    let issues = config.validate(ValidateOptions::default());
    if has_errors(&issues) {
        let detail: Vec<String> = issues
            .iter()
            .filter(|i| i.level == soteria_config::IssueLevel::Error)
            .map(|i| format!("  {}: {}", i.field, i.message))
            .collect();
        return Err(Failure::new(
            ExitStatus::ConfigInvalid,
            format!(
                "invalid configuration in {}:\n{}",
                path.display(),
                detail.join("\n")
            ),
        )
        .hint("run 'soteria config validate' for the full report"));
    }
    Ok((config, issues))
}

pub fn config_failure(e: ConfigError) -> Failure {
    let hint = match &e {
        ConfigError::NotFound { .. } => {
            Some("install the default with 'soteria config default > /etc/soteria/soteria.toml'")
        }
        _ => None,
    };
    let f = Failure::new(ExitStatus::ConfigInvalid, e.to_string());
    match hint {
        Some(h) => f.hint(h),
        None => f,
    }
}

pub fn store_failure(e: StoreError) -> Failure {
    match e {
        StoreError::Missing(_) => Failure::new(ExitStatus::NotInitialized, e.to_string()),
        StoreError::NeedsMigration { .. } => {
            Failure::new(ExitStatus::NotInitialized, e.to_string())
        }
        StoreError::PermissionDenied { .. } => {
            Failure::new(ExitStatus::PermissionDenied, e.to_string())
                .hint("run the command with sudo")
        }
        StoreError::TooNew { .. } => Failure::new(ExitStatus::IntegrityFailure, e.to_string()),
        other => Failure::new(
            ExitStatus::IntegrityFailure,
            format!("database error: {other}"),
        ),
    }
}

/// The invoking user, recorded for audit trails such as baseline approval
/// (FR-044). Reads `/proc/self/status` so no unsafe libc calls are needed.
#[derive(Debug, Clone)]
pub struct Identity {
    pub euid: u32,
    pub name: String,
    /// The administrator behind sudo, when present.
    pub sudo_user: Option<String>,
}

impl Identity {
    pub fn current() -> Identity {
        let euid = proc_euid().unwrap_or(u32::MAX);
        let name = user_name(euid).unwrap_or_else(|| euid.to_string());
        Identity {
            euid,
            name,
            sudo_user: std::env::var("SUDO_USER").ok().filter(|s| !s.is_empty()),
        }
    }

    pub fn is_root(&self) -> bool {
        self.euid == 0
    }

    /// Display form for audit records, such as "root (via sudo from alice)".
    pub fn describe(&self) -> String {
        match &self.sudo_user {
            Some(s) if self.is_root() => format!("{} (via sudo from {s})", self.name),
            _ => self.name.clone(),
        }
    }
}

/// Effective UID: the second field of the `Uid:` line.
fn proc_euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Look up an account in `/etc/passwd`: returns (uid, gid).
pub fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.len() >= 4 && f[0] == name).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))?
    })
}

fn user_name(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.len() >= 3 && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[0].to_owned())
    })
}
