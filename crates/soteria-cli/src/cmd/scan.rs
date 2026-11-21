//! `soteria scan` (FR-033, FR-034, FR-007).

use serde::Serialize;
use soteria_core::ExitStatus;
use soteria_integrity::baseline;
use soteria_integrity::compare::{Change, ChangeSummary};
use soteria_integrity::scan::{self, ScanReport, ScanResult, ScanTarget};

use crate::cli::{GlobalArgs, ScanArgs};
use crate::context::{
    BaselineCheck, baseline_failure, check_latest_baseline, load_config, open_store,
    open_store_read_only, scope,
};
use crate::display::{print_changes, print_scan_report};
use crate::output::{CmdResult, Failure, Output};

#[derive(Debug, Serialize)]
struct BaselineResult {
    version: u32,
    summary: ChangeSummary,
    changes: Vec<Change>,
}

#[derive(Debug, Serialize)]
struct Report {
    scan: ScanReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline: Option<BaselineResult>,
}

pub fn run(args: &ScanArgs, global: &GlobalArgs, out: &Output) -> CmdResult {
    let t = &args.target;
    let (config, _) = load_config(&global.config)?;
    if t.kernel {
        return kernel(&config, out);
    }
    let mut store = open_store(&config)?;
    let scope = scope(&config, &global.config);

    let (target, scan_type) = match (&t.dir, &t.file) {
        (Some(d), _) => (ScanTarget::Directory(absolute(d)?), "directory"),
        (_, Some(f)) => (ScanTarget::File(absolute(f)?), "file"),
        _ if t.baseline => (ScanTarget::Full, "baseline"),
        _ => (ScanTarget::Full, "full"),
    };

    // A baseline scan is only meaningful against a baseline whose seal holds.
    let mut baseline_version = None;
    if t.baseline {
        match check_latest_baseline(&store, &config)? {
            BaselineCheck::None => {
                return Err(Failure::new(
                    ExitStatus::NotInitialized,
                    "no approved baseline to compare against",
                )
                .hint("create and approve one with 'soteria baseline create' and 'soteria baseline approve'"));
            }
            BaselineCheck::Verified { version } => baseline_version = Some(version),
            BaselineCheck::Failed { version, problems } => {
                return Err(Failure::new(
                    ExitStatus::IntegrityFailure,
                    format!(
                        "baseline v{version} failed verification: {}",
                        problems.join("; ")
                    ),
                ));
            }
            BaselineCheck::Unverifiable { version, reason } => {
                return Err(Failure::new(
                    ExitStatus::IntegrityFailure,
                    format!("baseline v{version} cannot be verified: {reason}"),
                ));
            }
        }
    }

    let report = scan::run(&mut store, &scope, &target, scan_type)
        .map_err(|e| Failure::new(ExitStatus::Internal, format!("scan failed: {e}")))?;
    let mut exit = if report.result == ScanResult::CompletedWithGaps {
        ExitStatus::Findings
    } else {
        ExitStatus::Ok
    };

    let mut baseline_result = None;
    if let Some(version) = baseline_version {
        let mut summary = ChangeSummary::default();
        let mut changes = Vec::new();
        baseline::diff_current(&store, version, |c| {
            summary.add(&c);
            changes.push(c);
        })
        .map_err(baseline_failure)?;
        changes.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
        scan::record_baseline_result(&store, &report.id, version, &summary)
            .map_err(|e| Failure::new(ExitStatus::Internal, e.to_string()))?;
        if summary.total > 0 {
            exit = ExitStatus::Findings;
        }
        baseline_result = Some(BaselineResult {
            version,
            summary,
            changes,
        });
    }

    if out.json {
        out.print_json(&Report {
            scan: report,
            baseline: baseline_result,
        });
    } else {
        print_scan_report(out, &report);
        if let Some(b) = &baseline_result {
            println!("\nCompared with approved baseline v{}:", b.version);
            let shown = &b.changes[..b.changes.len().min(args.limit)];
            print_changes(out, shown, &b.summary);
        }
    }
    Ok(exit)
}

/// `soteria scan --kernel`: the running kernel and boot state, and what
/// changed since the agent last recorded it (FR-022..FR-024).
fn kernel(config: &soteria_config::Config, out: &Output) -> CmdResult {
    let store = open_store_read_only(config)?;
    let baseline = match check_latest_baseline(&store, config)? {
        BaselineCheck::Verified { version } => Some(version),
        _ => None,
    };
    let review = soteria_agent::kernel::review(&store, &Default::default(), baseline)
        .map_err(|e| Failure::new(ExitStatus::Internal, format!("kernel review failed: {e}")))?;
    let exit = if review.findings.is_empty() {
        ExitStatus::Ok
    } else {
        ExitStatus::Findings
    };
    if out.json {
        out.print_json(&review);
        return Ok(exit);
    }
    let c = &review.current;
    let onoff = |v: Option<bool>| match v {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    };
    println!("Kernel:        {} {}", c.release, c.version);
    println!(
        "Booted:        {}",
        c.boot_time.as_deref().unwrap_or("unknown")
    );
    println!("Command line:  {}", c.cmdline.join(" "));
    println!("Secure Boot:   {}", onoff(c.secure_boot));
    println!(
        "Lockdown:      {}",
        c.lockdown.as_deref().unwrap_or("unavailable")
    );
    println!(
        "Tainted:       {}",
        c.tainted.map_or("unknown".to_owned(), |t| t.to_string())
    );
    match &c.modules {
        Some(m) => println!("Modules:       {} loaded", m.len()),
        None => println!("Modules:       cannot be read"),
    }
    println!("Installed:     {}", c.installed.join(", "));
    for u in &review.unreadable {
        println!("Unreadable:    {u}");
    }
    if !review.recorded {
        println!("\nThe agent has not recorded kernel state yet; nothing to compare with.");
    } else if review.findings.is_empty() {
        println!("\nNo changes since the agent last recorded kernel state.");
    } else {
        println!("\nChanges since the agent last recorded kernel state:");
        for f in &review.findings {
            println!(
                "  [{}] {} {}",
                f.severity.as_str().to_uppercase(),
                f.rule,
                f.reason
            );
        }
    }
    Ok(exit)
}

fn absolute(p: &std::path::Path) -> Result<std::path::PathBuf, Failure> {
    std::path::absolute(p).map_err(|e| {
        Failure::new(
            ExitStatus::Usage,
            format!("invalid path {}: {e}", p.display()),
        )
    })
}
