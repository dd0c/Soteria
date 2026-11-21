//! `soteria events`: the normalized event history (FR-015, FR-036).

use serde::Serialize;
use soteria_core::{ExitStatus, Severity};

use crate::cli::{EventsArgs, GlobalArgs};
use crate::context::{load_config, open_store_read_only};
use crate::display::severity_tone;
use crate::output::{CmdResult, Output, Tone};
use crate::query::{internal, json_column, min_severity, path_text, range};

#[derive(Debug, Serialize)]
struct Event {
    id: i64,
    ts: String,
    sensor: String,
    #[serde(rename = "type")]
    event_type: String,
    severity: String,
    path: Option<String>,
    pid: Option<i64>,
    uid: Option<i64>,
    data: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Listing {
    total_matching: u64,
    shown: usize,
    events: Vec<Event>,
}

pub fn run(args: &EventsArgs, global: &GlobalArgs, out: &Output) -> CmdResult {
    let (since, until) = range(&args.range)?;
    let severities = min_severity(args.severity.as_deref())?;
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let conn = store.connection();

    let filter = "(?1 IS NULL OR ts >= ?1) AND (?2 IS NULL OR ts <= ?2)
         AND (?3 IS NULL OR type = ?3 OR type LIKE ?3 || '.%')
         AND (?4 IS NULL OR instr(?4, ',' || severity || ',') > 0)";
    let params = rusqlite::params![since, until, args.event_type, severities];
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM events WHERE {filter}"),
            params,
            |r| r.get(0),
        )
        .map_err(internal)?;
    // Newest first, so the limit keeps the most recent events.
    let mut stmt = conn
        .prepare(&format!(
            "SELECT id, ts, sensor, type, severity, path, pid, uid, data FROM events
             WHERE {filter} ORDER BY ts DESC, id DESC LIMIT {}",
            args.limit
        ))
        .map_err(internal)?;
    let mut events: Vec<Event> = stmt
        .query_map(params, |r| {
            Ok(Event {
                id: r.get(0)?,
                ts: r.get(1)?,
                sensor: r.get(2)?,
                event_type: r.get(3)?,
                severity: r.get(4)?,
                path: path_text(r.get(5)?),
                pid: r.get(6)?,
                uid: r.get(7)?,
                data: json_column(&r.get::<_, String>(8)?),
            })
        })
        .map_err(internal)?
        .collect::<rusqlite::Result<_>>()
        .map_err(internal)?;
    // Shown oldest first, like a log.
    events.reverse();

    let listing = Listing {
        total_matching: total as u64,
        shown: events.len(),
        events,
    };
    if out.json {
        out.print_json(&listing);
        return Ok(ExitStatus::Ok);
    }
    if listing.events.is_empty() {
        println!("No events match.");
        return Ok(ExitStatus::Ok);
    }
    for e in &listing.events {
        let sev: Severity = e.severity.parse().unwrap_or(Severity::Info);
        let detail = e
            .data
            .get("changes")
            .and_then(|c| c.as_array())
            .map(|c| {
                c.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        println!(
            "{}  {}  {:<16} {} {}",
            out.paint(Tone::Dim, &e.ts),
            out.paint(
                severity_tone(sev),
                &format!("{:<8}", e.severity.to_uppercase())
            ),
            e.event_type,
            e.path.as_deref().unwrap_or("-"),
            out.paint(Tone::Dim, &detail)
        );
    }
    if listing.total_matching as usize > listing.shown {
        println!(
            "{} of {} matching events shown (newest); use --limit or --since to see others.",
            listing.shown, listing.total_matching
        );
    }
    Ok(ExitStatus::Ok)
}
