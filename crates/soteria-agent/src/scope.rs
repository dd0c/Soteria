//! What the inventory, scans and the filesystem sensor cover.
//!
//! One function builds the scope for the daemon and for the CLI, so a
//! baseline created by `soteria baseline create` covers exactly what the
//! daemon watches.

use std::path::{Path, PathBuf};

use soteria_config::Config;
use soteria_inventory::{Scope, expand_pattern};

/// Unit file locations a package or administrator may use.
const UNIT_FILES: &[&str] = &[
    "/usr/lib/systemd/system/soteria.service",
    "/lib/systemd/system/soteria.service",
    "/etc/systemd/system/soteria.service",
    "/etc/systemd/system/soteria.service.d",
];

/// The kernel audit rule that reports executions (M4).
pub const AUDIT_RULES_FILE: &str = "/etc/audit/rules.d/soteria.rules";

/// Configured include and exclude paths, plus persistence locations
/// (FR-020) and Soteria's own files (FR-036) as optional roots.
pub fn for_config(config: &Config, config_path: Option<&Path>) -> Scope {
    let mut optional: Vec<PathBuf> = config
        .paths
        .persistence
        .iter()
        .flat_map(|p| expand_pattern(p))
        .collect();
    if config.paths.own_files {
        optional.extend(self_paths(config, config_path));
    }
    optional.sort();
    optional.dedup();
    Scope {
        include: config.paths.include.clone(),
        exclude: config.paths.exclude.clone(),
        optional,
    }
}

/// Soteria's own program, configuration, rules, keys and unit files.
/// Changes to them are reported as SELF-001 (FR-036).
pub fn self_paths(config: &Config, config_path: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && exe.is_absolute()
        && !exe.to_string_lossy().ends_with(" (deleted)")
    {
        paths.push(exe);
    }
    paths.push(
        config_path
            .map(Path::to_owned)
            .unwrap_or_else(|| PathBuf::from(soteria_core::DEFAULT_CONFIG_PATH)),
    );
    paths.push(config.general.rules_directory.clone());
    paths.push(config.baseline.signing_key.clone());
    paths.push(config.baseline.public_key.clone());
    paths.push(PathBuf::from(AUDIT_RULES_FILE));
    paths.extend(UNIT_FILES.iter().map(PathBuf::from));
    paths.retain(|p| p.is_absolute());
    paths
}

/// Whether `path` is one of Soteria's own files or inside one of its own
/// directories.
pub fn is_self_path(self_paths: &[PathBuf], path: &Path) -> bool {
    self_paths.iter().any(|s| path.starts_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_holds_existing_persistence_paths_and_own_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("home/alice/.ssh")).unwrap();
        let mut config = Config::default();
        config.paths.persistence = vec![
            dir.path().join("home/*/.ssh"),
            dir.path().join("home/*/.bashrc"),
        ];
        let cfg_path = dir.path().join("soteria.toml");
        let scope = for_config(&config, Some(&cfg_path));
        assert!(scope.optional.contains(&dir.path().join("home/alice/.ssh")));
        assert!(scope.optional.contains(&cfg_path));
        assert!(scope.optional.contains(&PathBuf::from(AUDIT_RULES_FILE)));
        assert!(!scope.optional.iter().any(|p| p.ends_with(".bashrc")));
        let own = self_paths(&config, Some(&cfg_path));
        assert!(is_self_path(
            &own,
            &config.general.rules_directory.join("x.toml")
        ));
        assert!(!is_self_path(&own, Path::new("/etc/passwd")));
    }
}
