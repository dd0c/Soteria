//! `soteria alerts`: view, search, manage and export alerts (FR-027,
//! FR-029, FR-030, FR-035).

use std::io::Write;
use std::time::Duration;

use serde::Serialize;
use soteria_agent::lifecycle::{self, LifecycleError, Scope};
use soteria_core::{ExitStatus, Severity};

use crate::cli::{AlertFilter, AlertsCommand, ExportFormat, GlobalArgs};
use crate::context::{Identity, load_config, open_store, open_store_read_only};
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

/// Administrative writes wait this long for the daemon to release the
/// database (a full scan holds it).
const ADMIN_BUSY_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Serialize)]
pub struct AlertRow {
    pub id: i64,
    pub uuid: String,
    pub created_at: String,
    pub updated_at: String,
    pub severity: String,
    #[serde(rename = "type")]
    pub alert_type: String,
    pub status: String,
    pub hostname: String,
    pub object: Option<String>,
    pub rule_id: String,
    pub reason: String,
    pub incident_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct HistoryRow {
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AlertDetail {
    #[serde(flatten)]
    pub alert: AlertRow,
    pub evidence: serde_json::Value,
    pub recommendation: String,
    pub history: Vec<HistoryRow>,
}

#[derive(Debug, Serialize)]
struct Listing {
    total_matching: u64,
    shown: usize,
    alerts: Vec<AlertRow>,
}

const ROW_COLUMNS: &str = "id, uuid, created_at, updated_at, severity, type, status, hostname, object, rule_id, reason, incident_id";

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
        incident_id: r.get(11)?,
    })
}

pub fn run(cmd: &AlertsCommand, global: &GlobalArgs, out: &Output) -> CmdResult {
    match cmd {
        AlertsCommand::List { filter, limit } => list(global, out, filter, *limit),
        AlertsCommand::Show { id } => show(global, out, *id),
        AlertsCommand::Ack { id, note } => {
            status(global, out, *id, "acknowledged", note.as_deref())
        }
        AlertsCommand::Investigate { id, note } => {
            status(global, out, *id, "investigated", note.as_deref())
        }
        AlertsCommand::Close { id, note } => status(global, out, *id, "closed", note.as_deref()),
        AlertsCommand::Reopen { id, note } => status(global, out, *id, "open", note.as_deref()),
        AlertsCommand::Note { id, text } => admin(global, out, |conn, actor| {
            lifecycle::add_note(conn, *id as i64, actor, text)?;
            Ok((
                format!("Note added to alert {id}."),
                serde_json::json!({ "alert": id, "noted": true }),
            ))
        }),
        AlertsCommand::Suppress {
            id,
            reason,
            all_objects,
            expires,
        } => {
            let expires_at = match expires {
                Some(e) => {
                    let d = humantime::parse_duration(e).map_err(|err| {
                        Failure::new(ExitStatus::Usage, format!("--expires: '{e}': {err}"))
                    })?;
                    let until = chrono::Utc::now()
                        + chrono::Duration::from_std(d).map_err(|_| {
                            Failure::new(ExitStatus::Usage, "--expires is too long")
                        })?;
                    Some(until.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                }
                None => None,
            };
            let scope = if *all_objects {
                Scope::Rule
            } else {
                Scope::Object
            };
            admin(global, out, |conn, actor| {
                let sid = lifecycle::suppress(
                    conn,
                    *id as i64,
                    actor,
                    reason,
                    scope,
                    expires_at.as_deref(),
                )?;
                let what = if *all_objects {
                    "on every object"
                } else {
                    "on this object"
                };
                let until = expires_at
                    .as_deref()
                    .map(|e| format!(" until {e}"))
                    .unwrap_or_default();
                Ok((
                    format!(
                        "Alert {id} suppressed. Suppression {sid} stops this rule {what}{until}; \
                         remove it with 'soteria alerts unsuppress {sid}'."
                    ),
                    serde_json::json!({ "alert": id, "suppression": sid, "expires_at": expires_at }),
                ))
            })
        }
        AlertsCommand::Suppressions { all } => suppressions(global, out, *all),
        AlertsCommand::Unsuppress { suppression_id } => admin(global, out, |conn, actor| {
            lifecycle::unsuppress(conn, *suppression_id as i64, actor)?;
            Ok((
                format!("Suppression {suppression_id} removed."),
                serde_json::json!({ "suppression": suppression_id, "removed": true }),
            ))
        }),
        AlertsCommand::Export {
            format,
            filter,
            output,
        } => export(global, *format, filter, output.as_deref()),
    }
}

fn lifecycle_failure(e: LifecycleError) -> Failure {
    match e {
        LifecycleError::NoSuchAlert(_)
        | LifecycleError::NoSuchSuppression(_)
        | LifecycleError::Unchanged { .. }
        | LifecycleError::EmptyNote => Failure::new(ExitStatus::Usage, e.to_string()),
        LifecycleError::Sqlite(e) => crate::context::store_failure(e.into()),
    }
}

/// Run a write as the current administrator, recorded by name.
fn admin(
    global: &GlobalArgs,
    out: &Output,
    f: impl FnOnce(&rusqlite::Connection, &str) -> Result<(String, serde_json::Value), LifecycleError>,
) -> CmdResult {
    let (config, _) = load_config(&global.config)?;
    let store = open_store(&config)?;
    store
        .set_busy_timeout(ADMIN_BUSY_TIMEOUT)
        .map_err(crate::context::store_failure)?;
    let actor = Identity::current().describe();
    let (text, json) = f(store.connection(), &actor).map_err(lifecycle_failure)?;
    if out.json {
        out.print_json(&json);
    } else {
        println!("{text}");
    }
    Ok(ExitStatus::Ok)
}

fn status(global: &GlobalArgs, out: &Output, id: u64, to: &str, note: Option<&str>) -> CmdResult {
    admin(global, out, |conn, actor| {
        let from = lifecycle::set_status(conn, id as i64, to, actor, note)?;
        Ok((
            format!("Alert {id}: {from} -> {to}."),
            serde_json::json!({ "alert": id, "from": from, "to": to }),
        ))
    })
}

/// SQL filter for [`AlertFilter`], with its parameters.
fn filter_sql(f: &AlertFilter) -> Result<(&'static str, Vec<rusqlite::types::Value>), Failure> {
    use rusqlite::types::Value;
    let (since, until) = range(&f.range)?;
    let severities = min_severity(f.severity.as_deref())?;
    if let Some(s) = &f.status
        && !STATUSES.contains(&s.as_str())
    {
        return Err(Failure::new(
            ExitStatus::Usage,
            format!(
                "unknown status '{s}'; expected one of {}",
                STATUSES.join(", ")
            ),
        ));
    }
    let text = |v: Option<String>| v.map(Value::Text).unwrap_or(Value::Null);
    Ok((
        "(?1 IS NULL OR created_at >= ?1) AND (?2 IS NULL OR created_at <= ?2)
         AND (?3 IS NULL OR instr(?3, ',' || severity || ',') > 0)
         AND (?4 IS NULL OR status = ?4)
         AND (?5 IS NULL OR rule_id = upper(?5))
         AND (?6 IS NULL OR instr(object, ?6) > 0)",
        vec![
            text(since),
            text(until),
            text(severities),
            text(f.status.clone()),
            text(f.rule.clone()),
            text(f.object.clone()),
        ],
    ))
}

fn query_rows(
    conn: &rusqlite::Connection,
    f: &AlertFilter,
    limit: Option<u32>,
) -> Result<(u64, Vec<AlertRow>), Failure> {
    let (filter, params) = filter_sql(f)?;
    let p = rusqlite::params_from_iter(params.iter());
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM alerts WHERE {filter}"),
            p,
            |r| r.get(0),
        )
        .map_err(internal)?;
    let limit = limit.map(|l| format!("LIMIT {l}")).unwrap_or_default();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {ROW_COLUMNS} FROM alerts WHERE {filter} ORDER BY id DESC {limit}"
        ))
        .map_err(internal)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), row)
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok((total as u64, rows))
}

fn list(global: &GlobalArgs, out: &Output, f: &AlertFilter, limit: u32) -> CmdResult {
    filter_sql(f)?; // usage errors before touching the database
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let (total, alerts) = query_rows(store.connection(), f, Some(limit))?;
    let listing = Listing {
        total_matching: total,
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

pub fn detail(conn: &rusqlite::Connection, alert: AlertRow) -> Result<AlertDetail, Failure> {
    let (evidence, recommendation): (String, String) = conn
        .query_row(
            "SELECT evidence, recommendation FROM alerts WHERE id = ?1",
            [alert.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(internal)?;
    let mut stmt = conn
        .prepare_cached(
            "SELECT ts, actor, action, from_status, to_status, note FROM alert_history
             WHERE alert_id = ?1 ORDER BY id",
        )
        .map_err(internal)?;
    let history = stmt
        .query_map([alert.id], |r| {
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
    Ok(AlertDetail {
        alert,
        evidence: json_column(&evidence),
        recommendation,
        history,
    })
}

fn show(global: &GlobalArgs, out: &Output, id: u64) -> CmdResult {
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let conn = store.connection();
    let alert = match conn.query_row(
        &format!("SELECT {ROW_COLUMNS} FROM alerts WHERE id = ?1"),
        [id as i64],
        row,
    ) {
        Ok(a) => a,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Err(Failure::new(
                ExitStatus::Usage,
                format!("no alert with id {id}"),
            ));
        }
        Err(e) => return Err(internal(e)),
    };
    let d = detail(conn, alert)?;
    if out.json {
        out.print_json(&d);
    } else {
        let mut stdout = std::io::stdout().lock();
        let _ = write_text(&mut stdout, &d, Some(out));
    }
    Ok(ExitStatus::Ok)
}

/// Human-readable rendering of one alert; `out` adds color.
fn write_text(w: &mut dyn Write, d: &AlertDetail, out: Option<&Output>) -> std::io::Result<()> {
    let paint = |tone: Tone, s: &str| match out {
        Some(o) => o.paint(tone, s),
        None => s.to_owned(),
    };
    let a = &d.alert;
    let sev: Severity = a.severity.parse().unwrap_or(Severity::Info);
    writeln!(
        w,
        "{} {}  {}",
        paint(Tone::Bold, &format!("Alert {}", a.id)),
        paint(severity_tone(sev), &a.severity.to_uppercase()),
        a.reason
    )?;
    let mut field = |k: &str, v: &str| writeln!(w, "  {:<15} {v}", format!("{k}:"));
    field("Object", a.object.as_deref().unwrap_or("-"))?;
    field("Rule", &a.rule_id)?;
    field("Type", &a.alert_type)?;
    field("Status", &a.status)?;
    field("Host", &a.hostname)?;
    field("Created", &a.created_at)?;
    field("UUID", &a.uuid)?;
    if let Some(i) = a.incident_id {
        field("Incident", &i.to_string())?;
    }
    writeln!(w)?;
    writeln!(w, "{}", paint(Tone::Bold, "Evidence"))?;
    let pretty = serde_json::to_string_pretty(&d.evidence).unwrap_or_default();
    for line in pretty.lines() {
        writeln!(w, "  {line}")?;
    }
    writeln!(w)?;
    writeln!(w, "{}", paint(Tone::Bold, "Recommendation"))?;
    writeln!(w, "  {}", d.recommendation)?;
    writeln!(w)?;
    writeln!(w, "{}", paint(Tone::Bold, "History"))?;
    for h in &d.history {
        let change = match (&h.from_status, &h.to_status) {
            (Some(f), Some(t)) => format!("{f} -> {t}"),
            (None, Some(t)) => t.clone(),
            _ => String::new(),
        };
        writeln!(
            w,
            "  {}  {:<24} {:<8} {} {}",
            h.ts,
            h.actor,
            h.action,
            change,
            h.note.as_deref().unwrap_or("")
        )?;
    }
    Ok(())
}

fn suppressions(global: &GlobalArgs, out: &Output, all: bool) -> CmdResult {
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let list = lifecycle::suppressions(store.connection(), all).map_err(lifecycle_failure)?;
    if out.json {
        out.print_json(&list);
        return Ok(ExitStatus::Ok);
    }
    if list.is_empty() {
        println!("No suppressions.");
        return Ok(ExitStatus::Ok);
    }
    for s in &list {
        let state = if s.enabled { "" } else { " (removed)" };
        println!(
            "{:>4}  {:<8}  {}  by {} on {}{}{}\n      {}",
            s.id,
            s.rule_id.as_deref().unwrap_or("*"),
            s.object.as_deref().unwrap_or("all objects"),
            s.created_by,
            s.created_at,
            s.expires_at
                .as_deref()
                .map(|e| format!(", expires {e}"))
                .unwrap_or_default(),
            state,
            s.reason
        );
    }
    Ok(ExitStatus::Ok)
}

fn export(
    global: &GlobalArgs,
    format: ExportFormat,
    f: &AlertFilter,
    output: Option<&std::path::Path>,
) -> CmdResult {
    filter_sql(f)?;
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let conn = store.connection();
    let (_, rows) = query_rows(conn, f, None)?;
    let mut details = Vec::with_capacity(rows.len());
    // Oldest first, as a record.
    for a in rows.into_iter().rev() {
        details.push(detail(conn, a)?);
    }

    let io =
        |e: std::io::Error| Failure::new(ExitStatus::Internal, format!("cannot write export: {e}"));
    let mut sink: Box<dyn Write> = match output {
        Some(p) => {
            use std::os::unix::fs::OpenOptionsExt;
            // Exports contain evidence; keep them private like the database.
            Box::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(p)
                    .map_err(|e| {
                        Failure::new(
                            ExitStatus::Usage,
                            format!("cannot create {}: {e}", p.display()),
                        )
                    })?,
            )
        }
        None => Box::new(std::io::stdout().lock()),
    };
    match format {
        ExportFormat::Json => {
            serde_json::to_writer_pretty(&mut sink, &details).map_err(|e| io(e.into()))?;
            writeln!(sink).map_err(io)?;
        }
        ExportFormat::Csv => write_csv(&mut sink, &details).map_err(io)?,
        ExportFormat::Text => {
            for (i, d) in details.iter().enumerate() {
                if i > 0 {
                    writeln!(sink, "\n{}\n", "-".repeat(72)).map_err(io)?;
                }
                write_text(&mut sink, d, None).map_err(io)?;
            }
        }
    }
    sink.flush().map_err(io)?;
    if let Some(p) = output {
        eprintln!("Exported {} alert(s) to {}", details.len(), p.display());
    }
    Ok(ExitStatus::Ok)
}

fn write_csv(w: &mut dyn Write, details: &[AlertDetail]) -> std::io::Result<()> {
    writeln!(
        w,
        "id,uuid,created_at,updated_at,severity,type,status,hostname,object,rule_id,reason,recommendation,incident_id,evidence,history"
    )?;
    for d in details {
        let a = &d.alert;
        let fields = [
            a.id.to_string(),
            a.uuid.clone(),
            a.created_at.clone(),
            a.updated_at.clone(),
            a.severity.clone(),
            a.alert_type.clone(),
            a.status.clone(),
            a.hostname.clone(),
            a.object.clone().unwrap_or_default(),
            a.rule_id.clone(),
            a.reason.clone(),
            d.recommendation.clone(),
            a.incident_id.map(|i| i.to_string()).unwrap_or_default(),
            d.evidence.to_string(),
            serde_json::to_string(&d.history).unwrap_or_default(),
        ];
        let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
        writeln!(w, "{}", line.join(","))?;
    }
    Ok(())
}

/// RFC 4180 quoting. Fields that a spreadsheet would run as a formula are
/// prefixed with a quote, so an exported path cannot inject one.
fn csv_field(v: &str) -> String {
    let v = if v.starts_with(['=', '+', '-', '@']) {
        format!("'{v}")
    } else {
        v.to_owned()
    };
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::csv_field;

    #[test]
    fn csv_quoting() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("=cmd()"), "'=cmd()");
        assert_eq!(csv_field("line\nbreak"), "\"line\nbreak\"");
    }
}
