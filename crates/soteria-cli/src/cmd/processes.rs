//! `soteria processes`: execution history search (FR-013).

use serde::Serialize;
use soteria_core::{ExitStatus, Severity};

use crate::cli::{GlobalArgs, ProcessesArgs};
use crate::context::{load_config, lookup_user, open_store_read_only, user_name};
use crate::display::severity_tone;
use crate::output::{CmdResult, Failure, Output, Tone};
use crate::query::{internal, json_column, min_severity, path_text, range};

const CLASSIFICATIONS: [&str; 5] = [
    "trusted",
    "known_modified",
    "unknown",
    "suspicious",
    "unverified",
];

#[derive(Debug, Serialize)]
struct Process {
    id: i64,
    ts: String,
    pid: i64,
    ppid: Option<i64>,
    uid: Option<i64>,
    user: Option<String>,
    euid: Option<i64>,
    gid: Option<i64>,
    /// Login user (unchanged by su/sudo).
    auid: Option<i64>,
    login_user: Option<String>,
    tty: Option<String>,
    session: Option<i64>,
    comm: Option<String>,
    exe: Option<String>,
    path: Option<String>,
    script: Option<String>,
    sha256: Option<String>,
    argv: serde_json::Value,
    cwd: Option<String>,
    classification: String,
    rationale: serde_json::Value,
    limitations: serde_json::Value,
    severity: String,
    parent_id: Option<i64>,
    parent_exe: Option<String>,
    parent_comm: Option<String>,
}

#[derive(Debug, Serialize)]
struct Listing {
    total_matching: u64,
    shown: usize,
    processes: Vec<Process>,
}

pub fn run(args: &ProcessesArgs, global: &GlobalArgs, out: &Output) -> CmdResult {
    let (since, until) = range(&args.range)?;
    let severities = min_severity(args.severity.as_deref())?;
    if let Some(c) = &args.classification
        && !CLASSIFICATIONS.contains(&c.as_str())
    {
        return Err(Failure::new(
            ExitStatus::Usage,
            format!(
                "unknown classification '{c}'; expected one of {}",
                CLASSIFICATIONS.join(", ")
            ),
        ));
    }
    let uid: Option<i64> = match &args.user {
        None => None,
        Some(u) => match u.parse::<u32>() {
            Ok(n) => Some(n.into()),
            Err(_) => Some(
                lookup_user(u)
                    .ok_or_else(|| Failure::new(ExitStatus::Usage, format!("unknown user '{u}'")))?
                    .0
                    .into(),
            ),
        },
    };
    // A value with a slash is a path (exact, or a directory prefix);
    // otherwise it matches the program name.
    let (exe_path, exe_dir, exe_name) = match &args.exe {
        Some(e) if e.contains('/') => {
            let p = std::path::absolute(e)
                .map_err(|err| Failure::new(ExitStatus::Usage, err.to_string()))?;
            let bytes = p.as_os_str().as_encoded_bytes().to_vec();
            let mut dir = bytes.clone();
            if !dir.ends_with(b"/") {
                dir.push(b'/');
            }
            (Some(bytes), Some(dir), None)
        }
        Some(e) => (None, None, Some(e.clone())),
        None => (None, None, None),
    };

    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;
    let conn = store.connection();

    let filter = "(?1 IS NULL OR ts >= ?1) AND (?2 IS NULL OR ts <= ?2)
         AND (?3 IS NULL OR instr(?3, ',' || severity || ',') > 0)
         AND (?4 IS NULL OR classification = ?4)
         AND (?5 IS NULL OR pid = ?5)
         AND (?6 IS NULL OR uid = ?6 OR euid = ?6 OR auid = ?6)
         AND (?7 IS NULL OR exe = ?7 OR path = ?7 OR script = ?7
              OR substr(exe, 1, length(?8)) = ?8 OR substr(script, 1, length(?8)) = ?8)
         AND (?9 IS NULL OR comm = ?9
              OR CAST(exe AS TEXT) LIKE '%/' || ?9 OR CAST(script AS TEXT) LIKE '%/' || ?9)";
    let params = rusqlite::params![
        since,
        until,
        severities,
        args.classification,
        args.pid,
        uid,
        exe_path,
        exe_dir,
        exe_name
    ];
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM processes WHERE {filter}"),
            params,
            |r| r.get(0),
        )
        .map_err(internal)?;
    let mut stmt = conn
        .prepare(&format!(
            "SELECT id, ts, pid, ppid, uid, euid, gid, auid, tty, session, comm, exe, path, script, sha256,
                    argv, cwd, classification, rationale, limitations, severity, parent_id, parent_exe, parent_comm
             FROM processes WHERE {filter} ORDER BY ts DESC, id DESC LIMIT {}",
            args.limit
        ))
        .map_err(internal)?;
    let mut processes: Vec<Process> = stmt
        .query_map(params, |r| {
            let uid: Option<i64> = r.get(4)?;
            let auid: Option<i64> = r.get(7)?;
            let json = |v: Option<String>| {
                v.map(|t| json_column(&t))
                    .unwrap_or(serde_json::Value::Null)
            };
            Ok(Process {
                id: r.get(0)?,
                ts: r.get(1)?,
                pid: r.get(2)?,
                ppid: r.get(3)?,
                user: uid.and_then(|u| user_name(u as u32)),
                uid,
                euid: r.get(5)?,
                gid: r.get(6)?,
                login_user: auid.and_then(|u| user_name(u as u32)),
                auid,
                tty: r.get(8)?,
                session: r.get(9)?,
                comm: r.get(10)?,
                exe: path_text(r.get(11)?),
                path: path_text(r.get(12)?),
                script: path_text(r.get(13)?),
                sha256: r.get(14)?,
                argv: json(r.get(15)?),
                cwd: path_text(r.get(16)?),
                classification: r.get(17)?,
                rationale: json(r.get(18)?),
                limitations: json(r.get(19)?),
                severity: r.get(20)?,
                parent_id: r.get(21)?,
                parent_exe: path_text(r.get(22)?),
                parent_comm: r.get(23)?,
            })
        })
        .map_err(internal)?
        .collect::<rusqlite::Result<_>>()
        .map_err(internal)?;
    processes.reverse();

    let listing = Listing {
        total_matching: total as u64,
        shown: processes.len(),
        processes,
    };
    if out.json {
        out.print_json(&listing);
        return Ok(ExitStatus::Ok);
    }
    if listing.processes.is_empty() {
        println!("No executions match.");
        return Ok(ExitStatus::Ok);
    }
    println!(
        "{}",
        out.paint(
            Tone::Bold,
            &format!(
                "{:<24}  {:>7}  {:>7}  {:<10}  {:<14}  {:<8}  COMMAND",
                "TIME", "PID", "PPID", "USER", "CLASS", "SEVERITY"
            )
        )
    );
    for p in &listing.processes {
        let sev: Severity = p.severity.parse().unwrap_or(Severity::Info);
        let user = p
            .user
            .clone()
            .or_else(|| p.uid.map(|u| u.to_string()))
            .unwrap_or_else(|| "-".into());
        let args: Vec<&str> = p
            .argv
            .as_array()
            .map(|a| a.iter().skip(1).filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let program = p.exe.as_deref().or(p.comm.as_deref()).unwrap_or("-");
        let class_tone = match p.classification.as_str() {
            "trusted" => Tone::Good,
            "suspicious" | "known_modified" => Tone::Bad,
            "unknown" => Tone::Warn,
            _ => Tone::Dim,
        };
        println!(
            "{:<24}  {:>7}  {:>7}  {:<10}  {}  {}  {} {}",
            p.ts,
            p.pid,
            p.ppid.map(|v| v.to_string()).unwrap_or_default(),
            user,
            out.paint(class_tone, &format!("{:<14}", p.classification)),
            out.paint(
                severity_tone(sev),
                &format!("{:<8}", p.severity.to_uppercase())
            ),
            program,
            args.join(" ")
        );
    }
    if listing.total_matching as usize > listing.shown {
        println!(
            "{} of {} matching executions shown (newest); use --limit or --since to see others.",
            listing.shown, listing.total_matching
        );
    }
    Ok(ExitStatus::Ok)
}
