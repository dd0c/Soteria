//! Inventory scans: walk the filesystem, refresh the `files` table, record
//! coverage gaps and scan history (FR-001..004, FR-016, FR-017, FR-033,
//! FR-034).
//!
//! A scan runs in one transaction, so the inventory is never left half
//! updated. The `scan_history` row is committed as 'running' before the walk
//! starts; if the process dies, the daemon marks it 'interrupted' at the next
//! start (SRS 4.3).

use std::path::{Path, PathBuf};
use std::time::Instant;

use rusqlite::{Transaction, params};
use serde::Serialize;
use soteria_inventory::{FileRecord, Gap, GapKind, Scanner, Scope, Visitor, WalkStats};
use soteria_store::{Store, new_id, now};

use soteria_core::FileKind;

use crate::compare::{ChangeKind, diff_record};
use crate::rows::{self, COLUMNS, path_bytes, path_from_bytes};

/// Sensor name used for gaps found by scans.
pub const SCANNER: &str = "scanner";

/// Gaps listed individually in a report; the rest are counted.
const REPORT_GAP_LIMIT: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTarget {
    Full,
    Directory(PathBuf),
    File(PathBuf),
}

impl ScanTarget {
    fn covers(&self, path: &Path) -> bool {
        match self {
            ScanTarget::Full => true,
            ScanTarget::Directory(d) => path.starts_with(d),
            ScanTarget::File(f) => path == f,
        }
    }

    fn label(&self) -> Option<String> {
        match self {
            ScanTarget::Full => None,
            ScanTarget::Directory(p) | ScanTarget::File(p) => Some(p.display().to_string()),
        }
    }
}

/// Report for one scan (FR-034).
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub id: String,
    #[serde(rename = "type")]
    pub scan_type: String,
    pub target: Option<String>,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub result: ScanResult,
    pub checked: u64,
    pub hashed: u64,
    pub skipped: u64,
    pub errors: u64,
    /// Inventory changes since the previous scan (added, changed, removed).
    pub inventory_changes: InventoryChanges,
    pub excluded: Vec<String>,
    pub gap_count: u64,
    pub gaps: Vec<GapOut>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanResult {
    Completed,
    /// Completed, but some objects could not be inspected (see gaps).
    CompletedWithGaps,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct InventoryChanges {
    pub added: u64,
    pub changed: u64,
    pub removed: u64,
}

impl InventoryChanges {
    pub fn total(&self) -> u64 {
        self.added + self.changed + self.removed
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GapOut {
    pub kind: GapKind,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

struct Writer<'t> {
    tx: &'t Transaction<'t>,
    started: String,
    scan_id: String,
    /// Record each inventory change as an event. Off for the first scan of
    /// an empty inventory, where every object would be "created".
    record_events: bool,
    changes: InventoryChanges,
    gaps: Vec<Gap>,
    error: Option<rusqlite::Error>,
}

impl Writer<'_> {
    fn upsert(&mut self, r: &FileRecord) -> rusqlite::Result<()> {
        match load_file(self.tx, &r.path)? {
            None => {
                self.changes.added += 1;
                self.event(
                    "file.created",
                    &r.path,
                    &[ChangeKind::New],
                    r.sha256.as_deref(),
                )?;
            }
            Some(old) => {
                let kinds = diff_record(&old, r);
                if !kinds.is_empty() {
                    self.changes.changed += 1;
                    // Directory timestamps change with every entry; not news.
                    let churn =
                        kinds == [ChangeKind::MetadataModified] && r.kind == FileKind::Directory;
                    if !churn {
                        self.event("file.modified", &r.path, &kinds, r.sha256.as_deref())?;
                    }
                }
            }
        }
        upsert_file(self.tx, r, &self.started)
    }

    fn event(
        &self,
        event_type: &str,
        path: &Path,
        kinds: &[ChangeKind],
        sha256: Option<&str>,
    ) -> rusqlite::Result<()> {
        if self.record_events {
            record_scan_event(self.tx, &self.scan_id, event_type, path, kinds, sha256)?;
        }
        Ok(())
    }
}

/// Record an inventory change found by a scan as an event (sensor
/// "scanner"), so changes that no live event reported still appear in the
/// event history (FR-016).
fn record_scan_event(
    conn: &rusqlite::Connection,
    scan_id: &str,
    event_type: &str,
    path: &Path,
    kinds: &[ChangeKind],
    sha256: Option<&str>,
) -> rusqlite::Result<()> {
    let kinds: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    conn.prepare_cached(
        "INSERT INTO events (ts, sensor, type, severity, path, data) VALUES (?1, ?2, ?3, 'info', ?4, ?5)",
    )?
    .execute(params![
        now(),
        SCANNER,
        event_type,
        path_bytes(path),
        serde_json::json!({ "changes": kinds, "sha256": sha256, "scan": scan_id }).to_string()
    ])?;
    Ok(())
}

/// Current inventory record for one path.
pub fn load_file(conn: &rusqlite::Connection, path: &Path) -> rusqlite::Result<Option<FileRecord>> {
    conn.prepare_cached(&format!("SELECT {COLUMNS} FROM files WHERE path = ?1"))?
        .query_row([path_bytes(path)], |row| rows::from_row(row, 0))
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })
}

/// Insert or refresh one inventory record, keeping its first-seen time.
pub fn upsert_file(
    conn: &rusqlite::Connection,
    r: &FileRecord,
    verified_at: &str,
) -> rusqlite::Result<()> {
    let mut values: Vec<rusqlite::types::Value> = rows::params(r).into();
    values.push(verified_at.to_owned().into());
    values.push(r.error.clone().into());
    conn.prepare_cached(&format!(
        "INSERT INTO files ({COLUMNS}, first_seen, last_verified, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, ?17)
         ON CONFLICT(path) DO UPDATE SET
           kind = excluded.kind, file_type = excluded.file_type, sha256 = excluded.sha256,
           size = excluded.size, uid = excluded.uid, gid = excluded.gid, mode = excluded.mode,
           mtime_ns = excluded.mtime_ns, ctime_ns = excluded.ctime_ns, inode = excluded.inode,
           device = excluded.device, symlink_target = excluded.symlink_target,
           capabilities = excluded.capabilities, security_label = excluded.security_label,
           last_verified = excluded.last_verified, last_error = excluded.last_error"
    ))?
    .execute(rusqlite::params_from_iter(values))?;
    Ok(())
}

/// Remove one path from the inventory. Returns whether it was present.
pub fn delete_file(conn: &rusqlite::Connection, path: &Path) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM files WHERE path = ?1", [path_bytes(path)])? > 0)
}

impl Visitor for Writer<'_> {
    fn record(&mut self, record: FileRecord) {
        if self.error.is_none()
            && let Err(e) = self.upsert(&record)
        {
            self.error = Some(e);
        }
    }

    fn gap(&mut self, gap: Gap) {
        self.gaps.push(gap);
    }
}

/// Run an inventory scan and persist the result. `scan_type` is recorded in
/// `scan_history` ("full", "directory", "file" or "baseline").
pub fn run(
    store: &mut Store,
    scope: &Scope,
    target: &ScanTarget,
    scan_type: &str,
) -> Result<ScanReport, ScanError> {
    let id = new_id();
    let started = now();
    let clock = Instant::now();
    store.connection().execute(
        "INSERT INTO scan_history (uuid, type, target, started_at, status) VALUES (?1, ?2, ?3, ?4, 'running')",
        params![id, scan_type, target.label(), started],
    )?;

    let result = scan_in_transaction(store, scope, target, &started, &id);
    let (stats, changes, gaps) = match result {
        Ok(v) => v,
        Err(e) => {
            let _ = store.connection().execute(
                "UPDATE scan_history SET status = 'failed', finished_at = ?2, detail = ?3 WHERE uuid = ?1",
                params![id, now(), format!("{{\"error\":{:?}}}", e.to_string())],
            );
            return Err(e.into());
        }
    };

    let finished = now();
    let gap_count = gaps.len() as u64;
    let result = if gap_count == 0 {
        ScanResult::Completed
    } else {
        ScanResult::CompletedWithGaps
    };
    let report = ScanReport {
        id: id.clone(),
        scan_type: scan_type.to_owned(),
        target: target.label(),
        started_at: started,
        finished_at: finished.clone(),
        duration_ms: clock.elapsed().as_millis() as u64,
        result,
        checked: stats.checked,
        hashed: stats.hashed,
        skipped: stats.skipped,
        errors: stats.errors,
        inventory_changes: changes,
        excluded: scope
            .exclude
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        gap_count,
        gaps: gaps
            .iter()
            .take(REPORT_GAP_LIMIT)
            .map(|g| GapOut {
                kind: g.kind,
                path: g.path.display().to_string(),
                detail: g.detail.clone(),
            })
            .collect(),
    };
    store.connection().execute(
        "UPDATE scan_history SET status = 'completed', finished_at = ?2, checked = ?3, skipped = ?4,
                errors = ?5, changes = ?6, detail = ?7 WHERE uuid = ?1",
        params![
            id,
            finished,
            stats.checked as i64,
            stats.skipped as i64,
            stats.errors as i64,
            changes.total() as i64,
            serde_json::json!({
                "result": result,
                "hashed": stats.hashed,
                "bytes_hashed": stats.bytes_hashed,
                "inventory_changes": changes,
                "gaps": gap_count,
            })
            .to_string()
        ],
    )?;
    Ok(report)
}

type ScanOutput = (WalkStats, InventoryChanges, Vec<Gap>);

fn scan_in_transaction(
    store: &mut Store,
    scope: &Scope,
    target: &ScanTarget,
    started: &str,
    scan_id: &str,
) -> rusqlite::Result<ScanOutput> {
    let tx = store.connection_mut().transaction()?;
    let inventory_empty: bool =
        tx.query_row("SELECT NOT EXISTS (SELECT 1 FROM files)", [], |r| r.get(0))?;
    let mut writer = Writer {
        tx: &tx,
        started: started.to_owned(),
        scan_id: scan_id.to_owned(),
        record_events: !inventory_empty,
        changes: InventoryChanges::default(),
        gaps: Vec::new(),
        error: None,
    };
    let scanner = Scanner::new(scope);
    let stats = match target {
        ScanTarget::Full => scanner.walk_all(&mut writer),
        ScanTarget::Directory(p) | ScanTarget::File(p) => scanner.walk(p, &mut writer),
    };
    if let Some(e) = writer.error.take() {
        return Err(e);
    }
    let mut changes = writer.changes;
    let gaps = std::mem::take(&mut writer.gaps);

    // Remove objects that were not seen, unless they sit below something we
    // could not read: absence of evidence is not evidence of deletion.
    let blind: Vec<&Path> = gaps
        .iter()
        .filter(|g| g.kind == GapKind::Inaccessible)
        .map(|g| g.path.as_path())
        .collect();
    let stale: Vec<(i64, PathBuf)> = {
        let mut stmt = tx.prepare("SELECT id, path FROM files WHERE last_verified <> ?1")?;
        stmt.query_map([started], |r| Ok((r.get(0)?, path_from_bytes(r.get(1)?))))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (rowid, path) in stale {
        if target.covers(&path) && !blind.iter().any(|b| path.starts_with(b)) {
            tx.execute("DELETE FROM files WHERE id = ?1", [rowid])?;
            changes.removed += 1;
            record_scan_event(
                &tx,
                scan_id,
                "file.deleted",
                &path,
                &[ChangeKind::Missing],
                None,
            )?;
        }
    }

    // Replace this scan's share of the open coverage gaps.
    let open: Vec<(i64, Option<Vec<u8>>)> = {
        let mut stmt = tx.prepare(
            "SELECT id, path FROM coverage_gaps WHERE closed_at IS NULL AND sensor = ?1",
        )?;
        stmt.query_map([SCANNER], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (gap_id, path) in open {
        let covered = match path {
            Some(p) => target.covers(&path_from_bytes(p)),
            None => *target == ScanTarget::Full,
        };
        if covered {
            tx.execute(
                "UPDATE coverage_gaps SET closed_at = ?2 WHERE id = ?1",
                params![gap_id, started],
            )?;
        }
    }
    for g in &gaps {
        tx.execute(
            "INSERT INTO coverage_gaps (opened_at, kind, sensor, path, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![started, g.kind.as_str(), SCANNER, path_bytes(&g.path), g.detail],
        )?;
    }

    tx.commit()?;
    Ok((stats, changes, gaps))
}

/// Record baseline comparison results on an existing scan.
pub fn record_baseline_result(
    store: &Store,
    scan_id: &str,
    baseline_version: u32,
    summary: &crate::compare::ChangeSummary,
) -> rusqlite::Result<()> {
    store.connection().execute(
        "UPDATE scan_history SET changes = ?2,
                detail = json_set(detail, '$.baseline_version', ?3, '$.baseline_changes', json(?4))
         WHERE uuid = ?1",
        params![
            scan_id,
            summary.total as i64,
            baseline_version,
            serde_json::to_string(summary).expect("serializable")
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Store, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = Store::create_or_migrate(&dir.path().join("db")).unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/a"), b"a").unwrap();
        std::fs::write(root.join("bin/b"), b"b").unwrap();
        (dir, store, root)
    }

    fn scope(root: &Path) -> Scope {
        Scope {
            include: vec![root.to_owned()],
            exclude: vec![],
        }
    }

    fn count(store: &Store, sql: &str) -> i64 {
        store.connection().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn full_scan_populates_inventory_and_history() {
        let (_d, mut store, root) = setup();
        let report = run(&mut store, &scope(&root), &ScanTarget::Full, "full").unwrap();
        assert_eq!(report.checked, 4); // root, bin, a, b
        assert_eq!(report.hashed, 2);
        assert_eq!(report.inventory_changes.added, 4);
        assert_eq!(report.result, ScanResult::Completed);
        assert_eq!(count(&store, "SELECT COUNT(*) FROM files"), 4);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM scan_history WHERE status = 'completed'"
            ),
            1
        );
    }

    #[test]
    fn rescan_tracks_changes_and_removals() {
        let (_d, mut store, root) = setup();
        run(&mut store, &scope(&root), &ScanTarget::Full, "full").unwrap();
        std::fs::write(root.join("bin/a"), b"changed").unwrap();
        std::fs::remove_file(root.join("bin/b")).unwrap();
        std::fs::write(root.join("bin/c"), b"c").unwrap();
        let report = run(&mut store, &scope(&root), &ScanTarget::Full, "full").unwrap();
        let c = report.inventory_changes;
        assert_eq!((c.added, c.removed), (1, 1));
        assert!(c.changed >= 1); // a (and the directory's mtime)
        assert_eq!(count(&store, "SELECT COUNT(*) FROM files"), 4);
    }

    #[test]
    fn first_seen_survives_rescans() {
        let (_d, mut store, root) = setup();
        run(&mut store, &scope(&root), &ScanTarget::Full, "full").unwrap();
        let q = "SELECT first_seen || '|' || last_verified FROM files WHERE kind = 'other' LIMIT 1";
        let first: String = store.connection().query_row(q, [], |r| r.get(0)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        run(&mut store, &scope(&root), &ScanTarget::Full, "full").unwrap();
        let second: String = store.connection().query_row(q, [], |r| r.get(0)).unwrap();
        let (f1, v1) = first.split_once('|').unwrap();
        let (f2, v2) = second.split_once('|').unwrap();
        assert_eq!(f1, f2);
        assert_ne!(v1, v2);
    }

    #[test]
    fn directory_scan_only_touches_its_subtree() {
        let (_d, mut store, root) = setup();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/x"), b"x").unwrap();
        run(&mut store, &scope(&root), &ScanTarget::Full, "full").unwrap();
        std::fs::remove_file(root.join("etc/x")).unwrap();
        std::fs::remove_file(root.join("bin/a")).unwrap();
        let report = run(
            &mut store,
            &scope(&root),
            &ScanTarget::Directory(root.join("bin")),
            "directory",
        )
        .unwrap();
        assert_eq!(report.inventory_changes.removed, 1);
        // etc/x is outside the scanned directory and stays until a full scan.
        let n = count(&store, "SELECT COUNT(*) FROM files");
        assert_eq!(n, 5);
    }

    #[test]
    fn missing_roots_open_gaps_and_full_scans_close_them() {
        let (_d, mut store, root) = setup();
        let mut s = scope(&root);
        s.include.push(root.with_file_name("absent"));
        let report = run(&mut store, &s, &ScanTarget::Full, "full").unwrap();
        assert_eq!(report.result, ScanResult::CompletedWithGaps);
        assert_eq!(report.gaps[0].kind, GapKind::Missing);
        let open = "SELECT COUNT(*) FROM coverage_gaps WHERE closed_at IS NULL";
        assert_eq!(count(&store, open), 1);
        run(&mut store, &scope(&root), &ScanTarget::Full, "full").unwrap();
        assert_eq!(count(&store, open), 0);
    }

    #[test]
    fn file_scan_handles_deleted_file() {
        let (_d, mut store, root) = setup();
        run(&mut store, &scope(&root), &ScanTarget::Full, "full").unwrap();
        std::fs::remove_file(root.join("bin/a")).unwrap();
        let report = run(
            &mut store,
            &scope(&root),
            &ScanTarget::File(root.join("bin/a")),
            "file",
        )
        .unwrap();
        assert_eq!(report.inventory_changes.removed, 1);
    }
}
