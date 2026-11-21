//! `soteria baseline` (FR-005..FR-008, FR-044, SRS 10.3).

use serde::Serialize;
use soteria_core::ExitStatus;
use soteria_integrity::baseline::{self, Approver, BaselineInfo, Review};
use soteria_integrity::compare::{Change, ChangeSummary};
use soteria_integrity::keys;
use soteria_store::Store;

use crate::cli::{BaselineCommand, GlobalArgs};
use crate::context::{
    Identity, baseline_failure, confirm, key_failure, load_config, open_store, open_store_read_only,
};
use crate::display::print_changes;
use crate::output::{CmdResult, Failure, Output, Tone};

pub fn run(cmd: &BaselineCommand, global: &GlobalArgs, out: &Output) -> CmdResult {
    let (config, _) = load_config(&global.config)?;
    match cmd {
        BaselineCommand::List => {
            let store = open_store_read_only(&config)?;
            let list = baseline::list(&store).map_err(baseline_failure)?;
            if out.json {
                out.print_json(&list);
            } else if list.is_empty() {
                println!("No baselines yet. Create one with 'soteria baseline create'.");
            } else {
                for b in &list {
                    print_info_line(out, b);
                }
            }
            Ok(ExitStatus::Ok)
        }
        BaselineCommand::Show { version } => {
            let store = open_store_read_only(&config)?;
            let info = resolve(&store, *version, Pick::ApprovedThenDraft)?;
            let verification = match keys::load_verifier(&config.baseline.public_key) {
                Ok(key) if info.state != "draft" => {
                    Some(baseline::verify(&store, info.version, &key).map_err(baseline_failure)?)
                }
                _ => None,
            };
            let failed = verification.as_ref().is_some_and(|v| !v.valid);
            if out.json {
                #[derive(Serialize)]
                struct Show<'a> {
                    baseline: &'a BaselineInfo,
                    verification: &'a Option<baseline::Verification>,
                }
                out.print_json(&Show {
                    baseline: &info,
                    verification: &verification,
                });
            } else {
                print_info(out, &info);
                match &verification {
                    Some(v) if v.valid => {
                        println!("Seal:        {}", out.paint(Tone::Good, "VERIFIED"))
                    }
                    Some(v) => println!(
                        "Seal:        {} ({})",
                        out.paint(Tone::Bad, "FAILED"),
                        v.problems.join("; ")
                    ),
                    None if info.state == "draft" => println!("Seal:        not sealed (draft)"),
                    None => println!("Seal:        not verified (public key unavailable)"),
                }
            }
            Ok(if failed {
                ExitStatus::IntegrityFailure
            } else {
                ExitStatus::Ok
            })
        }
        BaselineCommand::Create { note } => {
            let mut store = open_store(&config)?;
            let who = Identity::current();
            let info = baseline::create_draft(&mut store, &who.describe(), note.as_deref())
                .map_err(baseline_failure)?;
            let review = baseline::review(&store, info.version, 50).map_err(baseline_failure)?;
            if out.json {
                out.print_json(&review);
            } else {
                print_review(out, &review);
                println!(
                    "\nDraft v{} created. Approve it with: sudo soteria baseline approve {}",
                    info.version, info.version
                );
            }
            Ok(ExitStatus::Ok)
        }
        BaselineCommand::Review { version, limit } => {
            let store = open_store_read_only(&config)?;
            let info = resolve(&store, *version, Pick::Draft)?;
            let review =
                baseline::review(&store, info.version, *limit).map_err(baseline_failure)?;
            if out.json {
                out.print_json(&review);
            } else {
                print_review(out, &review);
            }
            Ok(ExitStatus::Ok)
        }
        BaselineCommand::Approve { version, yes } => {
            let mut store = open_store(&config)?;
            let info = approve(&mut store, &config, *version, *yes, out)?;
            if out.json {
                out.print_json(&info);
            } else {
                println!(
                    "Baseline v{} approved by {} and sealed with key {}.",
                    info.version,
                    info.approved_by.as_deref().unwrap_or("?"),
                    info.key_id.as_deref().unwrap_or("?")
                );
            }
            Ok(ExitStatus::Ok)
        }
        BaselineCommand::Diff { from, to, limit } => {
            let store = open_store_read_only(&config)?;
            let mut summary = ChangeSummary::default();
            let mut changes: Vec<Change> = Vec::new();
            let collect = |c: Change| {
                summary.add(&c);
                changes.push(c);
            };
            match to {
                Some(to) => baseline::diff_versions(&store, *from, *to, collect),
                None => baseline::diff_current(&store, *from, collect),
            }
            .map_err(baseline_failure)?;
            changes.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
            if out.json {
                #[derive(Serialize)]
                struct Diff<'a> {
                    from: u32,
                    to: Option<u32>,
                    summary: &'a ChangeSummary,
                    changes: &'a [Change],
                }
                out.print_json(&Diff {
                    from: *from,
                    to: *to,
                    summary: &summary,
                    changes: &changes,
                });
            } else {
                let to_label = to
                    .map(|v| format!("v{v}"))
                    .unwrap_or_else(|| "current inventory".into());
                println!("Baseline v{from} compared with {to_label}:");
                print_changes(out, &changes[..changes.len().min(*limit)], &summary);
            }
            Ok(if summary.total > 0 {
                ExitStatus::Findings
            } else {
                ExitStatus::Ok
            })
        }
    }
}

/// Approve a draft after explicit confirmation (FR-044). Shared with init.
pub fn approve(
    store: &mut Store,
    config: &soteria_config::Config,
    version: u32,
    yes: bool,
    out: &Output,
) -> Result<BaselineInfo, Failure> {
    let who = Identity::current();
    if !who.is_root() {
        return Err(Failure::new(
            ExitStatus::PermissionDenied,
            "baseline approval requires root, because only root can read the signing key",
        )
        .hint("run: sudo soteria baseline approve <version>"));
    }
    let info = baseline::get(store, version).map_err(baseline_failure)?;
    if info.state != "draft" {
        return Err(baseline_failure(baseline::BaselineError::NotDraft {
            version,
            state: info.state,
        }));
    }
    if !yes {
        if out.json {
            return Err(Failure::new(
                ExitStatus::Usage,
                "use --yes to approve with --json",
            ));
        }
        match confirm(&format!(
            "Approve baseline v{version} ({} objects) as the trusted state of this host?",
            info.entry_count
        )) {
            Some(true) => {}
            Some(false) => return Err(Failure::new(ExitStatus::Usage, "approval cancelled")),
            None => {
                return Err(Failure::new(
                    ExitStatus::Usage,
                    "approval needs confirmation; pass --yes when not running on a terminal",
                ));
            }
        }
    }
    let signer = keys::load_signer(&config.baseline.signing_key).map_err(key_failure)?;
    let approver = Approver {
        name: who.describe(),
        uid: who.euid,
    };
    baseline::approve(store, version, &signer, &approver).map_err(baseline_failure)
}

enum Pick {
    Draft,
    ApprovedThenDraft,
}

fn resolve(store: &Store, version: Option<u32>, pick: Pick) -> Result<BaselineInfo, Failure> {
    if let Some(v) = version {
        return baseline::get(store, v).map_err(baseline_failure);
    }
    let found = match pick {
        Pick::Draft => baseline::current_draft(store).map_err(baseline_failure)?,
        Pick::ApprovedThenDraft => {
            match baseline::latest_approved(store).map_err(baseline_failure)? {
                Some(b) => Some(b),
                None => baseline::current_draft(store).map_err(baseline_failure)?,
            }
        }
    };
    found.ok_or_else(|| {
        Failure::new(ExitStatus::NotInitialized, "no baseline found")
            .hint("create one with 'soteria baseline create'")
    })
}

fn state_tone(state: &str) -> Tone {
    match state {
        "approved" => Tone::Good,
        "draft" => Tone::Warn,
        _ => Tone::Dim,
    }
}

fn print_info_line(out: &Output, b: &BaselineInfo) {
    println!(
        "v{:<4} {:<11} {:>8} objects  created {}  {}",
        b.version,
        out.paint(state_tone(&b.state), &b.state),
        b.entry_count,
        b.created_at,
        b.approved_by
            .as_deref()
            .map(|a| format!(
                "approved by {a} at {}",
                b.approved_at.as_deref().unwrap_or("?")
            ))
            .unwrap_or_default()
    );
}

fn print_info(out: &Output, b: &BaselineInfo) {
    println!("Baseline:    v{}", b.version);
    println!("State:       {}", out.paint(state_tone(&b.state), &b.state));
    println!("Objects:     {}", b.entry_count);
    println!("Created:     {} by {}", b.created_at, b.created_by);
    if let Some(p) = b.parent_version {
        println!("Parent:      v{p}");
    }
    if let Some(a) = &b.approved_by {
        println!(
            "Approved:    {} by {a} (uid {})",
            b.approved_at.as_deref().unwrap_or("?"),
            b.approved_uid.unwrap_or_default()
        );
    }
    if let Some(d) = &b.digest {
        println!("Digest:      {d}");
    }
    if let Some(k) = &b.key_id {
        println!("Signing key: {k}");
    }
    if let Some(n) = &b.note {
        println!("Note:        {n}");
    }
}

pub fn print_review(out: &Output, r: &Review) {
    print_info(out, &r.baseline);
    println!("\nObjects by kind:");
    for (kind, n) in &r.by_kind {
        println!("  {kind:<20} {n:>8}");
    }
    if r.open_coverage_gaps > 0 {
        println!(
            "\n{} open coverage gap(s): some objects could not be inspected. See 'soteria verify'.",
            out.paint(Tone::Warn, &r.open_coverage_gaps.to_string())
        );
    }
    match r.compared_to {
        Some(v) => {
            println!("\nDifferences from approved baseline v{v}:");
            print_changes(out, &r.top_changes, &r.changes);
        }
        None => println!("\nThis would be the first approved baseline for this host."),
    }
    println!("\n{}", out.paint(Tone::Warn, r.notice));
}
