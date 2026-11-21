//! `soteria init` (SRS 11.2, 10.3).
//!
//! Verifies prerequisites, detects platform capabilities, creates or migrates
//! the database, creates the baseline signing key, inventories the host,
//! prepares a draft baseline with coverage information for review, and asks
//! for explicit approval. Without approval the draft is kept and can be
//! approved later with `soteria baseline approve`.

use std::io::IsTerminal;
use std::os::unix::fs::{DirBuilderExt, chown};
use std::path::Path;

use serde::Serialize;
use soteria_core::{CheckState, ExitStatus};
use soteria_integrity::baseline::{self, BaselineInfo};
use soteria_integrity::keys;
use soteria_integrity::scan::{self, ScanReport, ScanResult, ScanTarget};
use soteria_platform::{Platform, ProbeState};
use soteria_store::Store;

use crate::cli::{GlobalArgs, InitArgs};
use crate::cmd::baseline::{approve, print_review};
use crate::context::{
    Identity, baseline_failure, key_failure, load_config, lookup_user, scope, store_failure,
};
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
    scan: Option<ScanReport>,
    baseline: Option<BaselineInfo>,
    next: Option<String>,
}

/// Collects steps and, in text mode, prints each one as it completes so the
/// administrator sees progress before the approval question.
struct Steps<'a> {
    out: &'a Output,
    list: Vec<Step>,
    exit: ExitStatus,
}

impl Steps<'_> {
    fn push(&mut self, step: &'static str, state: CheckState, detail: impl Into<String>) {
        let detail = detail.into();
        if state == CheckState::Warn {
            self.exit = self.exit.worst(ExitStatus::Findings);
        }
        if !self.out.json {
            println!("{}  {:<16} {}", self.out.check(state), step, detail);
        }
        self.list.push(Step {
            step,
            state,
            detail,
        });
    }
}

pub fn run(args: &InitArgs, global: &GlobalArgs, out: &Output) -> CmdResult {
    let mut steps = Steps {
        out,
        list: Vec::new(),
        exit: ExitStatus::Ok,
    };

    let who = Identity::current();
    if who.is_root() {
        steps.push(
            "privileges",
            CheckState::Pass,
            format!("running as {}", who.describe()),
        );
    } else {
        steps.push(
            "privileges",
            CheckState::Warn,
            format!(
                "running as {} without root; system paths may be unreadable and the baseline cannot be approved",
                who.describe()
            ),
        );
    }

    let (config, issues) = load_config(&global.config)?;
    let warnings = issues
        .iter()
        .filter(|i| i.level == soteria_config::IssueLevel::Warning)
        .count();
    steps.push(
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
            steps.push(
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
                steps.push(probe.name, state, probe.detail);
            }
        }
        Err(e) => steps.push("platform", CheckState::Warn, e.to_string()),
    }

    // Database.
    let db_path = &config.general.database;
    let created_dir = ensure_parent(db_path)?;
    let existed = db_path.exists();
    let (mut store, migrations) = Store::create_or_migrate(db_path).map_err(store_failure)?;
    store
        .set_meta("initialized_by", &who.describe())
        .and_then(|()| store.set_meta("initialized_at", &soteria_store::now()))
        .map_err(store_failure)?;
    steps.push(
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

    // Signing key (FR-006): created once, by root, never overwritten.
    let (sk, pk) = (&config.baseline.signing_key, &config.baseline.public_key);
    match (sk.exists(), pk.exists()) {
        (false, false) if who.is_root() => {
            let key = keys::generate(sk, pk).map_err(key_failure)?;
            steps.push(
                "signing_key",
                CheckState::Pass,
                format!(
                    "created baseline signing key {} ({})",
                    keys::key_id(&key),
                    sk.display()
                ),
            );
        }
        (false, false) => steps.push(
            "signing_key",
            CheckState::Warn,
            "no baseline signing key; run 'sudo soteria init' to create one",
        ),
        (true, true) => {
            let key = keys::load_verifier(pk).map_err(key_failure)?;
            steps.push(
                "signing_key",
                CheckState::Pass,
                format!("using existing baseline key {}", keys::key_id(&key)),
            );
        }
        (true, false) | (false, true) => {
            return Err(Failure::new(
                ExitStatus::IntegrityFailure,
                format!(
                    "only one half of the baseline key pair exists ({} / {}); restore the missing file instead of creating a new key",
                    sk.display(),
                    pk.display()
                ),
            ));
        }
    }

    // Inventory.
    if !out.json {
        println!("      {:<16} scanning configured paths...", "inventory");
    }
    let report = scan::run(&mut store, &scope(&config), &ScanTarget::Full, "full")
        .map_err(|e| Failure::new(ExitStatus::Internal, format!("inventory scan failed: {e}")))?;
    steps.push(
        "inventory",
        if report.result == ScanResult::Completed {
            CheckState::Pass
        } else {
            CheckState::Warn
        },
        format!(
            "{} objects checked, {} hashed, {} coverage gap(s)",
            report.checked, report.hashed, report.gap_count
        ),
    );

    // Baseline.
    let (baseline, next) = if let Some(existing) =
        baseline::latest_approved(&store).map_err(baseline_failure)?
    {
        steps.push(
            "baseline",
            CheckState::Pass,
            format!(
                "baseline v{} is already approved; not replacing it",
                existing.version
            ),
        );
        (
            Some(existing),
            Some("To record authorized changes, run 'soteria baseline create' and approve the new draft.".to_owned()),
        )
    } else {
        let draft = baseline::create_draft(&mut store, &who.describe(), Some("initial baseline"))
            .map_err(baseline_failure)?;
        steps.push(
            "baseline",
            CheckState::Pass,
            format!(
                "draft v{} prepared with {} objects",
                draft.version, draft.entry_count
            ),
        );
        if !out.json {
            println!();
            let review = baseline::review(&store, draft.version, 20).map_err(baseline_failure)?;
            print_review(out, &review);
            println!();
        }

        let interactive = std::io::stdin().is_terminal() && !out.json;
        let try_approve = who.is_root() && !args.non_interactive && (args.yes || interactive);
        if try_approve {
            match approve(&mut store, &config, draft.version, args.yes, out) {
                Ok(sealed) => {
                    steps.push(
                        "approval",
                        CheckState::Pass,
                        format!(
                            "baseline v{} approved by {} and sealed",
                            sealed.version,
                            sealed.approved_by.as_deref().unwrap_or("?")
                        ),
                    );
                    (Some(sealed), None)
                }
                Err(f) if f.status == ExitStatus::Usage => {
                    steps.push("approval", CheckState::Warn, f.message);
                    (Some(draft.clone()), Some(approve_hint(draft.version)))
                }
                Err(f) => return Err(f),
            }
        } else {
            steps.push(
                "approval",
                CheckState::Warn,
                format!("draft v{} is waiting for approval", draft.version),
            );
            (Some(draft.clone()), Some(approve_hint(draft.version)))
        }
    };

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
            steps.push(
                "ownership",
                CheckState::Pass,
                format!("database owned by {SERVICE_USER}"),
            );
        } else {
            steps.push(
                "ownership",
                CheckState::Warn,
                format!(
                    "service account '{SERVICE_USER}' not found; install the package to create it"
                ),
            );
        }
    }

    let exit = steps.exit;
    let report = InitReport {
        steps: steps.list,
        database: db_path.display().to_string(),
        schema_version: soteria_store::SCHEMA_VERSION,
        migrations_applied: migrations,
        scan: Some(report),
        baseline,
        next: next.clone(),
    };
    if out.json {
        out.print_json(&report);
    } else if let Some(n) = next {
        println!("\n{n}");
    } else {
        println!(
            "\nSoteria is initialized. Start monitoring with: sudo systemctl enable --now soteria"
        );
    }
    Ok(exit)
}

fn approve_hint(version: u32) -> String {
    format!(
        "Review it with 'soteria baseline review' and approve it with: sudo soteria baseline approve {version}"
    )
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
