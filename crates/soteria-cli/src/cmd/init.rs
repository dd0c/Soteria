//! `soteria init` (SRS 11.2).
//!
//! This build verifies prerequisites, detects platform capabilities and
//! creates or migrates the database. Inventory, baseline review and
//! approval are added to the same workflow in milestone 2.

use std::os::unix::fs::{DirBuilderExt, chown};
use std::path::Path;

use serde::Serialize;
use soteria_core::{CheckState, ExitStatus};
use soteria_platform::{Platform, ProbeState};
use soteria_store::Store;

use crate::cli::{GlobalArgs, InitArgs};
use crate::context::{Identity, load_config, lookup_user, store_failure};
use crate::output::{CmdResult, Failure, Output};

/// Service account that owns the state directory (SRS 8.2).
const SERVICE_USER: &str = "soteria";

#[derive(Debug, Serialize)]
struct Step {
    step: &'static str,
    state: CheckState,
    detail: String,
}

#[derive(Debug, Serialize)]
struct InitReport {
    steps: Vec<Step>,
    database: String,
    schema_version: u32,
    migrations_applied: Vec<u32>,
    next: &'static str,
}

const NEXT: &str = "Inventory and baseline approval are added to 'soteria init' in milestone 2.";

pub fn run(_args: &InitArgs, global: &GlobalArgs, out: &Output) -> CmdResult {
    let mut steps = Vec::new();
    let mut exit = ExitStatus::Ok;
    let mut push = |steps: &mut Vec<Step>, step, state, detail: String| {
        if state == CheckState::Warn {
            exit = exit.worst(ExitStatus::Findings);
        }
        steps.push(Step {
            step,
            state,
            detail,
        });
    };

    let who = Identity::current();
    push(
        &mut steps,
        "privileges",
        if who.is_root() {
            CheckState::Pass
        } else {
            CheckState::Warn
        },
        if who.is_root() {
            format!("running as {}", who.describe())
        } else {
            format!(
                "running as {} without root; system paths may be unreadable",
                who.describe()
            )
        },
    );

    let (config, issues) = load_config(&global.config)?;
    let warnings = issues
        .iter()
        .filter(|i| i.level == soteria_config::IssueLevel::Warning)
        .count();
    push(
        &mut steps,
        "configuration",
        if warnings == 0 {
            CheckState::Pass
        } else {
            CheckState::Warn
        },
        format!(
            "{} is valid ({warnings} warning(s))",
            global.config.display()
        ),
    );

    match Platform::detect() {
        Ok(p) => {
            let supported = p.support == soteria_platform::SupportLevel::Supported;
            push(
                &mut steps,
                "platform",
                if supported {
                    CheckState::Pass
                } else {
                    CheckState::Warn
                },
                format!("{} ({})", p.display_name(), p.support),
            );
            for probe in p.probe() {
                let state = if probe.state == ProbeState::Available {
                    CheckState::Pass
                } else {
                    CheckState::Warn
                };
                push(&mut steps, probe.name, state, probe.detail);
            }
        }
        Err(e) => push(&mut steps, "platform", CheckState::Warn, e.to_string()),
    }

    let db_path = &config.general.database;
    let created_dir = ensure_parent(db_path)?;
    let existed = db_path.exists();
    let (store, migrations) = Store::create_or_migrate(db_path).map_err(store_failure)?;
    store
        .set_meta("initialized_by", &who.describe())
        .and_then(|()| store.set_meta("initialized_at", &soteria_store::now()))
        .map_err(store_failure)?;
    push(
        &mut steps,
        "database",
        CheckState::Pass,
        match (existed, migrations.is_empty()) {
            (false, _) => format!("created {}", db_path.display()),
            (true, true) => format!(
                "{} is at schema version {}",
                db_path.display(),
                soteria_store::SCHEMA_VERSION
            ),
            (true, false) => format!(
                "migrated {} to schema version {}",
                db_path.display(),
                soteria_store::SCHEMA_VERSION
            ),
        },
    );

    // The daemon runs as the service account, so the database must belong
    // to it when root initializes the host.
    if who.is_root() {
        if let Some((uid, gid)) = lookup_user(SERVICE_USER) {
            let mut targets = vec![db_path.to_path_buf()];
            if created_dir {
                targets.extend(db_path.parent().map(Path::to_path_buf));
            }
            for t in &targets {
                chown(t, Some(uid), Some(gid)).map_err(|e| {
                    Failure::new(
                        ExitStatus::Internal,
                        format!("cannot hand {} to {SERVICE_USER}: {e}", t.display()),
                    )
                })?;
            }
            push(
                &mut steps,
                "ownership",
                CheckState::Pass,
                format!("database owned by {SERVICE_USER}"),
            );
        } else {
            push(
                &mut steps,
                "ownership",
                CheckState::Warn,
                format!(
                    "service account '{SERVICE_USER}' not found; install the package to create it"
                ),
            );
        }
    }

    let report = InitReport {
        steps,
        database: db_path.display().to_string(),
        schema_version: soteria_store::SCHEMA_VERSION,
        migrations_applied: migrations,
        next: NEXT,
    };
    if out.json {
        out.print_json(&report);
    } else {
        for s in &report.steps {
            println!("{}  {:<16} {}", out.check(s.state), s.step, s.detail);
        }
        println!("\n{NEXT}");
    }
    Ok(exit)
}

/// Create the database directory with restrictive permissions if it is
/// missing. Returns whether it was created.
fn ensure_parent(db: &Path) -> Result<bool, Failure> {
    let Some(parent) = db.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(false);
    };
    if parent.is_dir() {
        return Ok(false);
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o750)
        .create(parent)
        .map_err(|e| {
            let status = if e.kind() == std::io::ErrorKind::PermissionDenied {
                ExitStatus::PermissionDenied
            } else {
                ExitStatus::Internal
            };
            Failure::new(status, format!("cannot create {}: {e}", parent.display()))
                .hint("run with sudo")
        })?;
    Ok(true)
}
