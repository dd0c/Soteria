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

pub fn user_name(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        (f.len() >= 3 && f[2].parse::<u32>().ok() == Some(uid)).then(|| f[0].to_owned())
    })
}

/// Inventory scope from configuration.
pub fn scope(config: &Config) -> soteria_inventory::Scope {
    soteria_inventory::Scope {
        include: config.paths.include.clone(),
        exclude: config.paths.exclude.clone(),
    }
}

/// Open the database for writing (scans, baseline changes).
pub fn open_store(config: &Config) -> Result<soteria_store::Store, Failure> {
    soteria_store::Store::open(&config.general.database).map_err(store_failure)
}

pub fn open_store_read_only(config: &Config) -> Result<soteria_store::Store, Failure> {
    soteria_store::Store::open_read_only(&config.general.database).map_err(store_failure)
}

pub fn key_failure(e: soteria_integrity::keys::KeyError) -> Failure {
    use soteria_integrity::keys::KeyError;
    let status = match &e {
        KeyError::PermissionDenied(_) => ExitStatus::PermissionDenied,
        KeyError::PrivateMissing(_) | KeyError::PublicMissing(_) => ExitStatus::NotInitialized,
        KeyError::InsecurePermissions { .. } | KeyError::Malformed { .. } => {
            ExitStatus::IntegrityFailure
        }
        _ => ExitStatus::Internal,
    };
    Failure::new(status, e.to_string())
}

pub fn baseline_failure(e: soteria_integrity::baseline::BaselineError) -> Failure {
    use soteria_integrity::baseline::BaselineError;
    let status = match &e {
        BaselineError::NotFound(_) | BaselineError::NotDraft { .. } => ExitStatus::Usage,
        BaselineError::NoDraft | BaselineError::NoApproved | BaselineError::EmptyInventory => {
            ExitStatus::NotInitialized
        }
        BaselineError::Sqlite(_) => ExitStatus::Internal,
    };
    Failure::new(status, e.to_string())
}

/// Ask a yes/no question on the terminal. Returns None when stdin is not a
/// terminal, so callers can require an explicit flag instead.
pub fn confirm(question: &str) -> Option<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return None;
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).ok()?;
    Some(matches!(line.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

/// Outcome of checking the latest approved baseline's seal.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BaselineCheck {
    /// No baseline has been approved yet.
    None,
    Verified {
        version: u32,
    },
    Failed {
        version: u32,
        problems: Vec<String>,
    },
    /// The public key could not be loaded, so nothing was verified.
    Unverifiable {
        version: u32,
        reason: String,
    },
}

pub fn check_latest_baseline(
    store: &soteria_store::Store,
    config: &Config,
) -> Result<BaselineCheck, Failure> {
    use soteria_integrity::{baseline, keys};
    let Some(latest) = baseline::latest_approved(store).map_err(baseline_failure)? else {
        return Ok(BaselineCheck::None);
    };
    let key = match keys::load_verifier(&config.baseline.public_key) {
        Ok(k) => k,
        Err(e) => {
            return Ok(BaselineCheck::Unverifiable {
                version: latest.version,
                reason: e.to_string(),
            });
        }
    };
    let v = baseline::verify(store, latest.version, &key).map_err(baseline_failure)?;
    Ok(if v.valid {
        BaselineCheck::Verified { version: v.version }
    } else {
        BaselineCheck::Failed {
            version: v.version,
            problems: v.problems,
        }
    })
}
