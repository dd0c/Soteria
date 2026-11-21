//! `soteria report`: scan reports (FR-034) and a host security summary.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use soteria_core::{ExitStatus, Severity};

use crate::cli::{GlobalArgs, ReportCommand, TimeRange};
use crate::context::{load_config, open_store_read_only};
use crate::output::{CmdResult, Failure, Output, Tone};
use crate::query::{internal, json_column, range};

#[derive(Debug, Serialize)]
struct ScanRow {
    id: i64,
    uuid: String,
    #[serde(rename = "type")]
    scan_type: String,
    target: Option<String>,
    started_at: String,
    finished_at: Option<String>,
    duration_ms: Option<i64>,
    status: String,
    result: Option<String>,
    checked: i64,
    skipped: i64,
    errors: i64,
    changes: i64,
    detail: serde_json::Value,
}

const SCAN_COLUMNS: &str = "id, uuid, type, target, started_at, finished_at, status, checked, skipped, errors, changes, detail";

fn scan_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ScanRow> {
    let started_at: String = r.get(4)?;
    let finished_at: Option<String> = r.get(5)?;
    let duration_ms = finished_at.as_deref().and_then(|f| {
        let a = chrono::DateTime::parse_from_rfc3339(&started_at).ok()?;
        let b = chrono::DateTime::parse_from_rfc3339(f).ok()?;
        Some((b - a).num_milliseconds())
    });
    let detail = json_column(&r.get::<_, String>(11)?);
    Ok(ScanRow {
        id: r.get(0)?,
        uuid: r.get(1)?,
        scan_type: r.get(2)?,
        target: r.get(3)?,
        started_at,
        finished_at,
        duration_ms,
        status: r.get(6)?,
        result: detail["result"].as_str().map(str::to_owned),
        checked: r.get(7)?,
        skipped: r.get(8)?,
        errors: r.get(9)?,
        changes: r.get(10)?,
        detail,
    })
}

pub fn run(cmd: &ReportCommand, global: &GlobalArgs, out: &Output) -> CmdResult {
    match cmd {
        ReportCommand::Scan { id } => scan(global, out, id),
        ReportCommand::Scans { range: r, limit } => scans(global, out, r, *limit),
        ReportCommand::Summary { range: r } => summary(global, out, r),
    }
}

fn scan(global: &GlobalArgs, out: &Output, id: &str) -> CmdResult {
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let conn = store.connection();
    let row = if id == "latest" {
        conn.query_row(
            &format!(
                "SELECT {SCAN_COLUMNS} FROM scan_history ORDER BY started_at DESC, id DESC LIMIT 1"
            ),
            [],
            scan_row,
        )
    } else {
        conn.query_row(
            &format!(
                "SELECT {SCAN_COLUMNS} FROM scan_history WHERE uuid = ?1 OR CAST(id AS TEXT) = ?1"
            ),
            [id],
            scan_row,
        )
    }
    .optional()
    .map_err(internal)?
    .ok_or_else(|| {
        Failure::new(ExitStatus::Usage, format!("no scan '{id}'"))
            .hint("list scans with 'soteria report scans'")
    })?;
    // Alerts raised while the scan ran, for context.
    let alerts: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= ?1 AND (?2 IS NULL OR created_at <= ?2)",
            params![row.started_at, row.finished_at],
            |r| r.get(0),
        )
        .map_err(internal)?;
    if out.json {
        out.print_json(&serde_json::json!({ "scan": row, "alerts_during_scan": alerts }));
        return Ok(ExitStatus::Ok);
    }
    let d = &row.detail;
    println!(
        "{}",
        out.paint(
            Tone::Bold,
            &format!("Scan report {} ({})", row.id, row.uuid)
        )
    );
    println!(
        "Type:      {}{}",
        row.scan_type,
        row.target
            .as_deref()
            .map(|t| format!(" {t}"))
            .unwrap_or_default()
    );
    println!("Started:   {}", row.started_at);
    match (&row.finished_at, row.duration_ms) {
        (Some(f), Some(ms)) => println!("Finished:  {f} ({:.1}s)", ms as f64 / 1000.0),
        _ => println!("Finished:  -"),
    }
    let result = row.result.clone().unwrap_or_else(|| row.status.clone());
    let tone = match result.as_str() {
        "completed" => Tone::Good,
        "completed_with_gaps" | "interrupted" => Tone::Warn,
        _ => Tone::Bad,
    };
    println!("Result:    {}", out.paint(tone, &result.replace('_', " ")));
    println!(
        "Checked:   {} | Skipped: {} | Errors: {} | Hashed: {}",
        row.checked,
        row.skipped,
        row.errors,
        d["hashed"].as_u64().unwrap_or(0)
    );
    let ic = &d["inventory_changes"];
    println!(
        "Changes:   {} ({} added, {} changed, {} removed in the inventory)",
        row.changes,
        ic["added"].as_u64().unwrap_or(0),
        ic["changed"].as_u64().unwrap_or(0),
        ic["removed"].as_u64().unwrap_or(0)
    );
    if let Some(v) = d["baseline_version"].as_u64() {
        let bc = &d["baseline_changes"];
        println!(
            "Baseline:  compared with v{v}: {} deviation(s)",
            bc["total"].as_u64().unwrap_or(0)
        );
    }
    if let Some(gaps) = d["gap_count"].as_u64().filter(|g| *g > 0) {
        println!("Gaps:      {gaps} path(s) could not be checked");
        for g in d["gaps"].as_array().into_iter().flatten() {
            println!(
                "           {} {} ({})",
                g["kind"].as_str().unwrap_or(""),
                g["path"].as_str().unwrap_or(""),
                g["detail"].as_str().unwrap_or("")
            );
        }
    }
    println!("Alerts raised while it ran: {alerts}");
    Ok(ExitStatus::Ok)
}

fn scans(global: &GlobalArgs, out: &Output, r: &TimeRange, limit: u32) -> CmdResult {
    let (since, until) = range(r)?;
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let mut st = store
        .connection()
        .prepare(&format!(
            "SELECT {SCAN_COLUMNS} FROM scan_history
             WHERE (?1 IS NULL OR started_at >= ?1) AND (?2 IS NULL OR started_at <= ?2)
             ORDER BY started_at DESC, id DESC LIMIT ?3"
        ))
        .map_err(internal)?;
    let rows: Vec<ScanRow> = st
        .query_map(params![since, until, limit], scan_row)
        .map_err(internal)?
        .collect::<rusqlite::Result<_>>()
        .map_err(internal)?;
    if out.json {
        out.print_json(&rows);
        return Ok(ExitStatus::Ok);
    }
    if rows.is_empty() {
        println!("No scans match.");
        return Ok(ExitStatus::Ok);
    }
    println!(
        "{}",
        out.paint(
            Tone::Bold,
            &format!(
                "{:>5}  {:<24}  {:<10}  {:<20}  {:>9}  {:>8}  {:>7}",
                "ID", "STARTED", "TYPE", "RESULT", "CHECKED", "CHANGES", "SECONDS"
            )
        )
    );
    for s in &rows {
        println!(
            "{:>5}  {:<24}  {:<10}  {:<20}  {:>9}  {:>8}  {:>7}",
            s.id,
            s.started_at,
            s.scan_type,
            s.result.as_deref().unwrap_or(&s.status),
            s.checked,
            s.changes,
            s.duration_ms
                .map(|m| format!("{:.1}", m as f64 / 1000.0))
                .unwrap_or_else(|| "-".into())
        );
    }
    Ok(ExitStatus::Ok)
}

#[derive(Debug, Serialize, Default)]
struct Summary {
    hostname: String,
    generated_at: String,
    since: String,
    until: Option<String>,
    baseline_version: Option<u32>,
    baseline_approved_at: Option<String>,
    /// Alerts raised in the period, by severity.
    alerts_raised: BTreeMap<String, i64>,
    /// Their current status.
    alerts_by_status: BTreeMap<String, i64>,
    top_rules: Vec<(String, i64)>,
    top_objects: Vec<(String, i64)>,
    /// Unresolved alerts of any age, by severity.
    open_alerts: BTreeMap<String, i64>,
    incidents_opened: i64,
    open_incidents: i64,
    suppressed_detections: i64,
    executions_by_classification: BTreeMap<String, i64>,
    file_changes: BTreeMap<String, i64>,
    scans: BTreeMap<String, i64>,
    last_full_scan: Option<String>,
    open_coverage_gaps: Vec<(String, String, i64)>,
    notification_failures: i64,
}

fn counts(
    conn: &Connection,
    sql: &str,
    p: impl rusqlite::Params,
) -> Result<Vec<(String, i64)>, Failure> {
    let mut st = conn.prepare(sql).map_err(internal)?;
    st.query_map(p, |r| {
        Ok((
            r.get::<_, Option<String>>(0)?.unwrap_or_else(|| "-".into()),
            r.get(1)?,
        ))
    })
    .map_err(internal)?
    .collect::<rusqlite::Result<_>>()
    .map_err(internal)
}

fn summary(global: &GlobalArgs, out: &Output, r: &TimeRange) -> CmdResult {
    let (since, until) = range(r)?;
    let since = since.unwrap_or_else(|| {
        (chrono::Utc::now() - chrono::Duration::days(7))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    });
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let conn = store.connection();
    let base = store
        .summary()
        .map_err(|e| Failure::new(ExitStatus::Internal, e.to_string()))?;
    let window = "?1 AND (?2 IS NULL OR {c} <= ?2)";
    let w = |col: &str| format!("{col} >= {}", window.replace("{c}", col));
    let p = params![since, until];

    let mut s = Summary {
        hostname: soteria_platform::hostname(),
        generated_at: soteria_store::now(),
        baseline_version: base.baseline_version,
        baseline_approved_at: base.baseline_approved_at.clone(),
        last_full_scan: base.last_full_scan.clone(),
        ..Summary::default()
    };
    s.alerts_raised = counts(
        conn,
        &format!(
            "SELECT severity, COUNT(*) FROM alerts WHERE {} GROUP BY severity",
            w("created_at")
        ),
        p,
    )?
    .into_iter()
    .collect();
    s.alerts_by_status = counts(
        conn,
        &format!(
            "SELECT status, COUNT(*) FROM alerts WHERE {} GROUP BY status",
            w("created_at")
        ),
        p,
    )?
    .into_iter()
    .collect();
    s.top_rules = counts(
        conn,
        &format!(
            "SELECT rule_id, COUNT(*) AS n FROM alerts WHERE {} GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT 10",
            w("created_at")
        ),
        p,
    )?;
    s.top_objects = counts(
        conn,
        &format!(
            "SELECT object, COUNT(*) AS n FROM alerts WHERE {} GROUP BY object ORDER BY n DESC, object LIMIT 10",
            w("created_at")
        ),
        p,
    )?;
    s.open_alerts = counts(
        conn,
        "SELECT severity, COUNT(*) FROM alerts WHERE status IN ('open', 'acknowledged', 'investigated') GROUP BY severity",
        [],
    )?
    .into_iter()
    .collect();
    let one = |sql: &str| -> Result<i64, Failure> {
        conn.query_row(sql, p, |r| r.get(0)).map_err(internal)
    };
    s.incidents_opened = one(&format!(
        "SELECT COUNT(*) FROM incidents WHERE {}",
        w("created_at")
    ))?;
    s.open_incidents = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE status = 'open'",
            [],
            |r| r.get(0),
        )
        .map_err(internal)?;
    s.suppressed_detections = one(&format!(
        "SELECT COUNT(*) FROM events WHERE type = 'alert.suppressed' AND {}",
        w("ts")
    ))?;
    s.notification_failures = one(&format!(
        "SELECT COUNT(*) FROM events WHERE type = 'notification.failed' AND {}",
        w("ts")
    ))?;
    s.executions_by_classification = counts(
        conn,
        &format!(
            "SELECT classification, COUNT(*) FROM processes WHERE {} GROUP BY classification",
            w("ts")
        ),
        p,
    )?
    .into_iter()
    .collect();
    s.file_changes = counts(
        conn,
        &format!(
            "SELECT type, COUNT(*) FROM events WHERE type LIKE 'file.%' AND {} GROUP BY type",
            w("ts")
        ),
        p,
    )?
    .into_iter()
    .collect();
    s.scans = counts(
        conn,
        &format!(
            "SELECT type || ':' || status, COUNT(*) FROM scan_history WHERE {} GROUP BY type, status",
            w("started_at")
        ),
        p,
    )?
    .into_iter()
    .collect();
    {
        let mut st = conn
            .prepare(
                "SELECT sensor, kind, COUNT(*) FROM coverage_gaps WHERE closed_at IS NULL
                 GROUP BY sensor, kind ORDER BY sensor, kind",
            )
            .map_err(internal)?;
        s.open_coverage_gaps = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(internal)?
            .collect::<rusqlite::Result<_>>()
            .map_err(internal)?;
    }
    s.since = since;
    s.until = until;

    if out.json {
        out.print_json(&s);
        return Ok(ExitStatus::Ok);
    }
    let sev_line = |m: &BTreeMap<String, i64>| -> String {
        let parts: Vec<String> = Severity::ALL
            .iter()
            .rev()
            .filter_map(|sev| m.get(sev.as_str()).map(|n| format!("{n} {sev}")))
            .collect();
        if parts.is_empty() {
            "none".into()
        } else {
            parts.join(", ")
        }
    };
    let map_line = |m: &BTreeMap<String, i64>| -> String {
        if m.is_empty() {
            "none".into()
        } else {
            m.iter()
                .map(|(k, v)| format!("{v} {k}"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    println!(
        "{}",
        out.paint(
            Tone::Bold,
            &format!("SOTERIA SECURITY SUMMARY: {}", s.hostname)
        )
    );
    println!(
        "Period: {} to {}",
        s.since,
        s.until.as_deref().unwrap_or("now")
    );
    println!(
        "Baseline: {}",
        match (&s.baseline_version, &s.baseline_approved_at) {
            (Some(v), Some(at)) => format!("v{v}, approved {at}"),
            (Some(v), None) => format!("v{v}"),
            _ => out.paint(Tone::Warn, "none approved"),
        }
    );
    println!();
    println!("{}", out.paint(Tone::Bold, "Alerts"));
    println!("  Raised in period:   {}", sev_line(&s.alerts_raised));
    println!("  Their status now:   {}", map_line(&s.alerts_by_status));
    println!("  Unresolved (all):   {}", sev_line(&s.open_alerts));
    println!(
        "  Incidents:          {} opened in period, {} open now",
        s.incidents_opened, s.open_incidents
    );
    println!(
        "  Suppressed:         {} detection(s) matched a suppression",
        s.suppressed_detections
    );
    if !s.top_rules.is_empty() {
        println!(
            "  Top rules:          {}",
            s.top_rules
                .iter()
                .map(|(r, n)| format!("{r} ({n})"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !s.top_objects.is_empty() {
        println!("  Most alerted objects:");
        for (o, n) in s.top_objects.iter().take(5) {
            println!("    {n:>5}  {o}");
        }
    }
    println!();
    println!("{}", out.paint(Tone::Bold, "Activity"));
    println!(
        "  Executions:         {}",
        map_line(&s.executions_by_classification)
    );
    println!("  File changes:       {}", map_line(&s.file_changes));
    println!("  Scans:              {}", map_line(&s.scans));
    println!(
        "  Last full scan:     {}",
        s.last_full_scan.as_deref().unwrap_or("never")
    );
    println!();
    println!("{}", out.paint(Tone::Bold, "Coverage"));
    if s.open_coverage_gaps.is_empty() {
        println!("  No open coverage gaps.");
    } else {
        for (sensor, kind, n) in &s.open_coverage_gaps {
            println!(
                "  {}",
                out.paint(Tone::Warn, &format!("{n} open {kind} gap(s) ({sensor})"))
            );
        }
        println!("  Details: soteria verify");
    }
    if s.notification_failures > 0 {
        println!(
            "  {}",
            out.paint(
                Tone::Warn,
                &format!("{} failed notification attempt(s); see soteria events --type notification.failed", s.notification_failures)
            )
        );
    }
    Ok(ExitStatus::Ok)
}
