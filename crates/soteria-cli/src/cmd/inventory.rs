//! `soteria inventory` (FR-001..FR-004).

use std::os::unix::ffi::OsStrExt;

use serde::Serialize;
use soteria_core::{ExitStatus, FileKind};

use crate::cli::{GlobalArgs, InventoryArgs};
use crate::context::{load_config, open_store_read_only};
use crate::output::{CmdResult, Failure, Output};

#[derive(Debug, Serialize)]
struct Entry {
    path: String,
    kind: String,
    file_type: String,
    sha256: Option<String>,
    size: i64,
    uid: i64,
    gid: i64,
    mode: String,
    symlink_target: Option<String>,
    has_capabilities: bool,
    security_label: Option<String>,
    first_seen: String,
    last_verified: String,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Listing {
    total_matching: u64,
    shown: usize,
    entries: Vec<Entry>,
}

pub fn run(args: &InventoryArgs, global: &GlobalArgs, out: &Output) -> CmdResult {
    let (config, _) = load_config(&global.config)?;
    let store = open_store_read_only(&config)?;

    let kind = match &args.kind {
        Some(k) => Some(
            k.parse::<FileKind>()
                .map_err(|e| Failure::new(ExitStatus::Usage, e.to_string()))?,
        ),
        None => None,
    };
    let (prefix, prefix_dir) = match &args.path {
        Some(p) => {
            let p = std::path::absolute(p)
                .map_err(|e| Failure::new(ExitStatus::Usage, e.to_string()))?;
            let bytes = p.as_os_str().as_bytes().to_vec();
            let mut dir = bytes.clone();
            if !dir.ends_with(b"/") {
                dir.push(b'/');
            }
            (Some(bytes), Some(dir))
        }
        None => (None, None),
    };

    let filter = "(?1 IS NULL OR kind = ?1)
         AND (?2 IS NULL OR path = ?2 OR substr(path, 1, length(?3)) = ?3)
         AND (?4 IS NULL OR sha256 = ?4)";
    let params = rusqlite::params![
        kind.map(|k| k.as_str()),
        prefix,
        prefix_dir,
        args.sha256.as_deref().map(str::to_ascii_lowercase)
    ];
    let internal = |e: rusqlite::Error| Failure::new(ExitStatus::Internal, e.to_string());
    let conn = store.connection();
    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM files WHERE {filter}"),
            params,
            |r| r.get(0),
        )
        .map_err(internal)?;
    let mut stmt = conn
        .prepare(&format!(
            "SELECT path, kind, file_type, sha256, size, uid, gid, mode, symlink_target,
                    capabilities IS NOT NULL, security_label, first_seen, last_verified, last_error
             FROM files WHERE {filter} ORDER BY path LIMIT {}",
            args.limit
        ))
        .map_err(internal)?;
    let lossy = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
    let entries: Vec<Entry> = stmt
        .query_map(params, |r| {
            Ok(Entry {
                path: lossy(r.get(0)?),
                kind: r.get(1)?,
                file_type: r.get(2)?,
                sha256: r.get(3)?,
                size: r.get::<_, Option<i64>>(4)?.unwrap_or_default(),
                uid: r.get::<_, Option<i64>>(5)?.unwrap_or_default(),
                gid: r.get::<_, Option<i64>>(6)?.unwrap_or_default(),
                mode: format!(
                    "{:04o}",
                    r.get::<_, Option<i64>>(7)?.unwrap_or_default() & 0o7777
                ),
                symlink_target: r.get::<_, Option<Vec<u8>>>(8)?.map(lossy),
                has_capabilities: r.get(9)?,
                security_label: r.get(10)?,
                first_seen: r.get(11)?,
                last_verified: r.get(12)?,
                error: r.get(13)?,
            })
        })
        .map_err(internal)?
        .collect::<rusqlite::Result<_>>()
        .map_err(internal)?;

    let listing = Listing {
        total_matching: total.max(0) as u64,
        shown: entries.len(),
        entries,
    };
    if out.json {
        out.print_json(&listing);
    } else {
        for e in &listing.entries {
            let hash = e
                .sha256
                .as_deref()
                .map(|h| &h[..12.min(h.len())])
                .unwrap_or("-");
            let target = e
                .symlink_target
                .as_deref()
                .map(|t| format!(" -> {t}"))
                .unwrap_or_default();
            println!(
                "{:<18} {} {:>5}:{:<5} {:>10} {:<12} {}{}",
                e.kind, e.mode, e.uid, e.gid, e.size, hash, e.path, target
            );
        }
        println!(
            "\n{} of {} matching object(s)",
            listing.shown, listing.total_matching
        );
    }
    Ok(ExitStatus::Ok)
}
