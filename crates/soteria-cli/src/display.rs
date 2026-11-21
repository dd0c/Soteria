//! Shared text rendering for changes and scan reports.

use soteria_core::Severity;
use soteria_integrity::compare::{Change, ChangeSummary};
use soteria_integrity::scan::{ScanReport, ScanResult};

use crate::output::{Output, Tone};

pub fn severity_tone(s: Severity) -> Tone {
    match s {
        Severity::Critical | Severity::High => Tone::Bad,
        Severity::Medium => Tone::Warn,
        Severity::Low | Severity::Info => Tone::Dim,
    }
}

pub fn print_changes(out: &Output, changes: &[Change], summary: &ChangeSummary) {
    if summary.total == 0 {
        println!("No changes.");
        return;
    }
    for c in changes {
        let kinds: Vec<&str> = c.kinds.iter().map(|k| k.as_str()).collect();
        println!(
            "{}  {:<40} {}",
            out.paint(
                severity_tone(c.severity),
                &format!("{:<8}", c.severity.as_str().to_uppercase())
            ),
            kinds.join(","),
            c.path.display()
        );
    }
    if summary.total as usize > changes.len() {
        println!(
            "... and {} more (use --json for the full list)",
            summary.total as usize - changes.len()
        );
    }
    let by_sev: Vec<String> = summary
        .by_severity
        .iter()
        .rev()
        .map(|(s, n)| format!("{n} {s}"))
        .collect();
    println!("\n{} change(s): {}", summary.total, by_sev.join(", "));
}

pub fn print_scan_report(out: &Output, r: &ScanReport) {
    let result = match r.result {
        ScanResult::Completed => out.paint(Tone::Good, "completed"),
        ScanResult::CompletedWithGaps => out.paint(Tone::Warn, "completed with gaps"),
    };
    println!(
        "Scan {} ({}{})",
        r.id,
        r.scan_type,
        r.target
            .as_ref()
            .map(|t| format!(" {t}"))
            .unwrap_or_default()
    );
    println!("Started:  {}", r.started_at);
    println!(
        "Finished: {} ({:.1}s)",
        r.finished_at,
        r.duration_ms as f64 / 1000.0
    );
    println!(
        "Checked: {} | Hashed: {} | Skipped: {} | Errors: {}",
        r.checked, r.hashed, r.skipped, r.errors
    );
    let c = &r.inventory_changes;
    println!(
        "Inventory: {} added, {} changed, {} removed",
        c.added, c.changed, c.removed
    );
    if !r.excluded.is_empty() {
        println!("Excluded: {}", r.excluded.join(", "));
    }
    if r.gap_count > 0 {
        println!("Coverage gaps: {}", r.gap_count);
        for g in &r.gaps {
            println!("  {:<12} {}  ({})", g.kind.as_str(), g.path, g.detail);
        }
        if r.gap_count as usize > r.gaps.len() {
            println!("  ... and {} more", r.gap_count as usize - r.gaps.len());
        }
    }
    println!("Result: {result}");
}
