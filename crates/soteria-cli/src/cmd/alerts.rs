//! `soteria alerts`: list and show alerts (FR-027, FR-029). Changing an
//! alert's status, notes, suppression and export arrive with milestone 5.

use serde::Serialize;
use soteria_core::{ExitStatus, Severity};

use crate::cli::{AlertsCommand, GlobalArgs};
use crate::cmd::unavailable::{self, DETECTION};
use crate::context::{load_config, open_store_read_only};
use crate::display::severity_tone;
use crate::output::{CmdResult, Failure, Output, Tone};
use crate::query::{internal, json_column, min_severity, range};

const STATUSES: [&str; 5] = [
    "open",
    "acknowledged",
    "investigated",
    "suppressed",
    "closed",
];

#[derive(Debug, Serialize)]
struct AlertRow {
    id: i64,
    uuid: String,
    created_at: String,
    updated_at: String,
    severity: String,
    #[serde(rename = "type")]
    alert_type: String,
    status: String,
    hostname: String,
    object: Option<String>,
    rule_id: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct HistoryRow {
    ts: String,
    actor: String,
    action: String,
    from_status: Option<String>,
    to_status: Option<String>,
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct AlertDetail {
    #[serde(flatten)]
    alert: AlertRow,
    evidence: serde_json::Value,
    recommendation: String,
    history: Vec<HistoryRow>,
}

#[derive(Debug, Serialize)]
struct Listing {
    total_matching: u64,
    shown: usize,
    alerts: Vec<AlertRow>,
}

const ROW_COLUMNS: &str =
    "id, uuid, created_at, updated_at, severity, type, status, hostname, object, rule_id, reason";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRow> {
    Ok(AlertRow {
        id: r.get(0)?,
        uuid: r.get(1)?,
        created_at: r.get(2)?,
        updated_at: r.get(3)?,
        severity: r.get(4)?,
        alert_type: r.get(5)?,
        status: r.get(6)?,
        hostname: r.get(7)?,
        object: r.get(8)?,
        rule_id: r.get(9)?,
        reason: r.get(10)?,
    })
}

pub fn run(cmd: &AlertsCommand, global: &GlobalArgs, out: &Output) -> CmdResult {
    match cmd {
        AlertsCommand::List {
            range: r,
            severity,
            status,
            limit,
        } => list(
            global,
            out,
            r,
            severity.as_deref(),
            status.as_deref(),
            *limit,
        ),
        AlertsCommand::Show { id } => show(global, out, *id),
        AlertsCommand::Ack { .. } => unavailable::run("alerts ack", DETECTION),
        AlertsCommand::Investigate { .. } => unavailable::run("alerts investigate", DETECTION),
        AlertsCommand::Note { .. } => unavailable::run("alerts note", DETECTION),
        AlertsCommand::Suppress { .. } => unavailable::run("alerts suppress", DETECTION),
        AlertsCommand::Export { .. } => unavailable::run("alerts export", DETECTION),
    }
}

fn list(
    global: &GlobalArgs,
    out: &Output,
    r: &crate::cli::TimeRange,
    severity: Option<&str>,
    status: Option<&str>,
    limit: u32,
) -> CmdResult {
    let (since, until) = range(r)?;
    let severities = min_severity(severity)?;
    if let Some(s) = status
        && !STATUSES.contains(&s)
    {
        return Err(Failure::new(
            ExitStatus::Usage,
            format!(
                "unknown status '{s}'; expected one of {}",
                STATUSES.join(", ")
            ),
        ));
    }
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let conn = store.connection();

    let filter = "(?1 IS NULL OR created_at >= ?1) AND (?2 IS NULL OR created_at <= ?2)
         AND (?3 IS NULL OR instr(?3, ',' || severity || ',') > 0)
         AND (?4 IS NULL OR status = ?4)";
    let params = rusqlite::params![since, until, severities, status];
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM alerts WHERE {filter}"),
            params,
            |r| r.get(0),
        )
        .map_err(internal)?;
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {ROW_COLUMNS} FROM alerts WHERE {filter} ORDER BY id DESC LIMIT {limit}"
        ))
        .map_err(internal)?;
    let alerts: Vec<AlertRow> = stmt
        .query_map(params, row)
        .map_err(internal)?
        .collect::<rusqlite::Result<_>>()
        .map_err(internal)?;
    let listing = Listing {
        total_matching: total as u64,
        shown: alerts.len(),
        alerts,
    };
    if out.json {
        out.print_json(&listing);
        return Ok(ExitStatus::Ok);
    }
    if listing.alerts.is_empty() {
        println!("No alerts match.");
        return Ok(ExitStatus::Ok);
    }
    println!(
        "{}",
        out.paint(
            Tone::Bold,
            &format!(
                "{:>6}  {:<8}  {:<12}  {:<8}  {:<24}  OBJECT",
                "ID", "SEVERITY", "STATUS", "RULE", "CREATED"
            )
        )
    );
    for a in &listing.alerts {
        let sev: Severity = a.severity.parse().unwrap_or(Severity::Info);
        println!(
            "{:>6}  {}  {:<12}  {:<8}  {:<24}  {}",
            a.id,
            out.paint(
                severity_tone(sev),
                &format!("{:<8}", a.severity.to_uppercase())
            ),
            a.status,
            a.rule_id,
            a.created_at,
            a.object.as_deref().unwrap_or("-")
        );
    }
    if listing.total_matching as usize > listing.shown {
        println!(
            "{} of {} matching alerts shown (newest); use --limit to see more.",
            listing.shown, listing.total_matching
        );
    }
    Ok(ExitStatus::Ok)
}

fn show(global: &GlobalArgs, out: &Output, id: u64) -> CmdResult {
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let conn = store.connection();
    let found = conn.query_row(
        &format!("SELECT {ROW_COLUMNS}, evidence, recommendation FROM alerts WHERE id = ?1"),
        [id as i64],
        |r| Ok((row(r)?, r.get::<_, String>(11)?, r.get::<_, String>(12)?)),
    );
    let (alert, evidence, recommendation) = match found {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Err(Failure::new(
                ExitStatus::Usage,
                format!("no alert with id {id}"),
            ));
        }
        Err(e) => return Err(internal(e)),
    };
    let mut stmt = conn
        .prepare(
            "SELECT ts, actor, action, from_status, to_status, note FROM alert_history
             WHERE alert_id = ?1 ORDER BY id",
        )
        .map_err(internal)?;
    let history: Vec<HistoryRow> = stmt
        .query_map([id as i64], |r| {
            Ok(HistoryRow {
                ts: r.get(0)?,
                actor: r.get(1)?,
                action: r.get(2)?,
                from_status: r.get(3)?,
                to_status: r.get(4)?,
                note: r.get(5)?,
            })
        })
        .map_err(internal)?
        .collect::<rusqlite::Result<_>>()
        .map_err(internal)?;
    let detail = AlertDetail {
        alert,
        evidence: json_column(&evidence),
        recommendation,
        history,
    };
    if out.json {
        out.print_json(&detail);
        return Ok(ExitStatus::Ok);
    }

    let a = &detail.alert;
    let sev: Severity = a.severity.parse().unwrap_or(Severity::Info);
    println!(
        "{} {}  {}",
        out.paint(Tone::Bold, &format!("Alert {}", a.id)),
        out.paint(severity_tone(sev), &a.severity.to_uppercase()),
        a.reason
    );
    let field = |k: &str, v: &str| println!("  {:<15} {v}", format!("{k}:"));
    field("Object", a.object.as_deref().unwrap_or("-"));
    field("Rule", &a.rule_id);
    field("Type", &a.alert_type);
    field("Status", &a.status);
    field("Host", &a.hostname);
    field("Created", &a.created_at);
    field("UUID", &a.uuid);
    println!();
    println!("{}", out.paint(Tone::Bold, "Evidence"));
    let pretty = serde_json::to_string_pretty(&detail.evidence).unwrap_or_default();
    for line in pretty.lines() {
        println!("  {line}");
    }
    println!();
    println!("{}", out.paint(Tone::Bold, "Recommendation"));
    println!("  {}", detail.recommendation);
    println!();
    println!("{}", out.paint(Tone::Bold, "History"));
    for h in &detail.history {
        let change = match (&h.from_status, &h.to_status) {
            (Some(f), Some(t)) => format!("{f} -> {t}"),
            (None, Some(t)) => t.clone(),
            _ => String::new(),
        };
        println!(
            "  {}  {:<10} {:<8} {} {}",
            h.ts,
            h.actor,
            h.action,
            change,
            h.note.as_deref().unwrap_or("")
        );
    }
    Ok(ExitStatus::Ok)
}
