//! SQLite storage layer (SRS 5.6).
//!
//! The schema is versioned with `PRAGMA user_version` and every migration is
//! applied in its own transaction together with a `schema_migrations` record,
//! so an interrupted upgrade leaves the database at the previous version
//! (SRS 11.3). A database written by a newer Soteria is refused rather than
//! guessed at.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use soteria_core::Severity;

/// Ordered migrations. Index + 1 is the schema version the migration produces.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_initial.sql")];

/// Schema version this build writes.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// Database files are readable and writable by their owner only (NFR-010).
const DB_FILE_MODE: u32 = 0o600;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database {0} does not exist; run 'soteria init' first")]
    Missing(PathBuf),
    #[error("permission denied opening database {path}: {source}")]
    PermissionDenied {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot create database {path}: {source}")]
    Create {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "database schema version {found} is newer than this build supports ({supported}); \
         upgrade Soteria instead of downgrading"
    )]
    TooNew { found: u32, supported: u32 },
    #[error(
        "database schema version {found} is out of date (current is {supported}); run 'soteria init' to migrate"
    )]
    NeedsMigration { found: u32, supported: u32 },
    #[error("migration to schema version {version} failed: {source}")]
    Migration {
        version: u32,
        #[source]
        source: rusqlite::Error,
    },
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Current time as RFC 3339 UTC text, the timestamp format used in the schema.
pub fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// An open Soteria database.
pub struct Store {
    conn: Connection,
    path: PathBuf,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish()
    }
}

impl Store {
    /// Create the database if needed and migrate it to [`SCHEMA_VERSION`].
    /// Used by `soteria init`. Returns the schema versions applied.
    pub fn create_or_migrate(path: &Path) -> Result<(Store, Vec<u32>)> {
        if !path.exists() {
            create_private_file(path)?;
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let mut store = Store::configure(conn, path)?;
        let applied = store.migrate()?;
        store.ensure_meta()?;
        Ok((store, applied))
    }

    /// Open an existing, fully migrated database for reading and writing.
    pub fn open(path: &Path) -> Result<Store> {
        Store::open_with(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
    }

    /// Open an existing database read-only, for CLI queries.
    pub fn open_read_only(path: &Path) -> Result<Store> {
        Store::open_with(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
    }

    fn open_with(path: &Path, flags: OpenFlags) -> Result<Store> {
        // Probe the file ourselves first so a missing file or a permission
        // problem gets a precise error rather than SQLite's generic one.
        if let Err(e) = std::fs::File::open(path) {
            return Err(match e.kind() {
                std::io::ErrorKind::NotFound => StoreError::Missing(path.to_owned()),
                std::io::ErrorKind::PermissionDenied => StoreError::PermissionDenied {
                    path: path.to_owned(),
                    source: e,
                },
                _ => StoreError::Create {
                    path: path.to_owned(),
                    source: e,
                },
            });
        }
        let conn = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        let store = Store::configure(conn, path)?;
        let found = store.schema_version()?;
        if found > SCHEMA_VERSION {
            return Err(StoreError::TooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found < SCHEMA_VERSION {
            return Err(StoreError::NeedsMigration {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(store)
    }

    fn configure(conn: Connection, path: &Path) -> Result<Store> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Rollback journal with full sync until WAL durability is validated
        // on all targets (SRS 5.6).
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        Ok(Store {
            conn,
            path: path.to_owned(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Direct access for crates that own a slice of the schema.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn schema_version(&self) -> Result<u32> {
        Ok(self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?)
    }

    /// Apply pending migrations, one transaction each.
    pub fn migrate(&mut self) -> Result<Vec<u32>> {
        let current = self.schema_version()?;
        if current > SCHEMA_VERSION {
            return Err(StoreError::TooNew {
                found: current,
                supported: SCHEMA_VERSION,
            });
        }
        let mut applied = Vec::new();
        for (idx, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            let version = idx as u32 + 1;
            let run = |conn: &mut Connection| -> rusqlite::Result<()> {
                let tx = conn.transaction()?;
                tx.execute_batch(sql)?;
                tx.execute(
                    "INSERT INTO schema_migrations (version, applied_at, soteria_version) VALUES (?1, ?2, ?3)",
                    params![version, now(), soteria_core::VERSION],
                )?;
                tx.pragma_update(None, "user_version", version)?;
                tx.commit()
            };
            run(&mut self.conn).map_err(|source| StoreError::Migration { version, source })?;
            applied.push(version);
        }
        Ok(applied)
    }

    fn ensure_meta(&self) -> Result<()> {
        if self.meta("host_id")?.is_none() {
            self.set_meta("host_id", &new_id())?;
            self.set_meta("created_at", &now())?;
        }
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Run SQLite's integrity and foreign-key checks (SRS 4.3, FR-038).
    /// Returns a list of problems; empty means the database is consistent.
    pub fn integrity_check(&self) -> Result<Vec<String>> {
        let mut problems = Vec::new();
        let mut stmt = self.conn.prepare("PRAGMA integrity_check")?;
        for row in stmt.query_map([], |r| r.get::<_, String>(0))? {
            let row = row?;
            if row != "ok" {
                problems.push(row);
            }
        }
        let mut stmt = self.conn.prepare("PRAGMA foreign_key_check")?;
        let fk = stmt.query_map([], |r| {
            Ok(format!(
                "foreign key violation in {} row {}",
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?.unwrap_or_default()
            ))
        })?;
        for row in fk {
            problems.push(row?);
        }
        let applied: u32 = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?;
        let version = self.schema_version()?;
        if applied != version {
            problems.push(format!(
                "schema version {version} does not match migration history ({applied})"
            ));
        }
        Ok(problems)
    }

    /// Check the database file's ownership-independent permissions: it must
    /// not be readable or writable by group or others (NFR-010).
    pub fn permission_problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        match std::fs::metadata(&self.path) {
            Ok(m) => {
                let mode = m.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    out.push(format!(
                        "database {} has mode {mode:o}; expected {DB_FILE_MODE:o}",
                        self.path.display()
                    ));
                }
            }
            Err(e) => out.push(format!("cannot stat {}: {e}", self.path.display())),
        }
        out
    }

    /// Record a sensor or service state change (FR-037).
    pub fn record_health(&self, sensor: &str, state: &str, detail: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sensor_health (ts, sensor, state, detail) VALUES (?1, ?2, ?3, ?4)",
            params![now(), sensor, state, detail],
        )?;
        Ok(())
    }

    /// The latest recorded state of each sensor (FR-039).
    pub fn sensor_states(&self) -> Result<Vec<SensorState>> {
        let mut stmt = self.conn.prepare(
            "SELECT h.sensor, h.state, h.ts, h.detail FROM sensor_health h
             WHERE h.id = (SELECT MAX(id) FROM sensor_health WHERE sensor = h.sensor)
             ORDER BY h.sensor",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SensorState {
                sensor: r.get(0)?,
                state: r.get(1)?,
                since: r.get(2)?,
                detail: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Time of the most recent event, if any.
    pub fn last_event_at(&self) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT MAX(ts) FROM events", [], |r| r.get(0))?)
    }

    /// Mark scans left in 'running' state by a crash as interrupted
    /// (SRS 4.3). Returns how many were found.
    pub fn mark_interrupted_scans(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE scan_history SET status = 'interrupted', finished_at = ?1 WHERE status = 'running'",
            [now()],
        )?)
    }

    /// Figures shown by `soteria status`.
    pub fn summary(&self) -> Result<Summary> {
        let count = |sql: &str| -> Result<u64> {
            Ok(self.conn.query_row(sql, [], |r| r.get::<_, i64>(0))?.max(0) as u64)
        };

        let mut open_alerts = BTreeMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT severity, COUNT(*) FROM alerts WHERE status IN ('open', 'acknowledged') GROUP BY severity",
        )?;
        for row in stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64))
        })? {
            let (sev, n) = row?;
            if let Ok(sev) = sev.parse::<Severity>() {
                open_alerts.insert(sev, n);
            }
        }

        let approved_baseline = self
            .conn
            .query_row(
                "SELECT version, approved_at FROM baseline_versions
                 WHERE state = 'approved' ORDER BY version DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .optional()?;

        let last_scan = |kind: &str| -> Result<Option<String>> {
            Ok(self
                .conn
                .query_row(
                    "SELECT finished_at FROM scan_history WHERE type = ?1 AND status = 'completed'
                     ORDER BY finished_at DESC LIMIT 1",
                    [kind],
                    |r| r.get(0),
                )
                .optional()?)
        };

        let last_agent = self
            .conn
            .query_row(
                "SELECT state, ts FROM sensor_health WHERE sensor = 'agent' ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;

        Ok(Summary {
            indexed_files: count("SELECT COUNT(*) FROM files")?,
            baseline_version: approved_baseline.as_ref().map(|b| b.0),
            baseline_approved_at: approved_baseline.and_then(|b| b.1),
            open_alerts,
            open_coverage_gaps: count(
                "SELECT COUNT(*) FROM coverage_gaps WHERE closed_at IS NULL",
            )?,
            last_full_scan: last_scan("full")?,
            // Any completed scan that compared against the baseline: manual
            // `scan --baseline`, the agent's reconciliation and critical scans.
            last_verification: self
                .conn
                .query_row(
                    "SELECT finished_at FROM scan_history WHERE status = 'completed'
                       AND (type IN ('baseline', 'critical')
                            OR json_extract(detail, '$.baseline_version') IS NOT NULL)
                     ORDER BY finished_at DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?,
            agent_state: last_agent.as_ref().map(|a| a.0.clone()),
            agent_state_since: last_agent.map(|a| a.1),
        })
    }
}

/// A sensor's latest recorded state.
#[derive(Debug, Clone, Serialize)]
pub struct SensorState {
    pub sensor: String,
    pub state: String,
    pub since: String,
    pub detail: Option<String>,
}

/// Figures shown by `soteria status`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub indexed_files: u64,
    pub baseline_version: Option<u32>,
    pub baseline_approved_at: Option<String>,
    pub open_alerts: BTreeMap<Severity, u64>,
    pub open_coverage_gaps: u64,
    pub last_full_scan: Option<String>,
    pub last_verification: Option<String>,
    pub agent_state: Option<String>,
    pub agent_state_since: Option<String>,
}

impl Summary {
    pub fn open_alert_total(&self) -> u64 {
        self.open_alerts.values().sum()
    }
}

/// Create an empty file with owner-only permissions, so the database is never
/// briefly world-readable.
fn create_private_file(path: &Path) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(DB_FILE_MODE)
        .open(path)
        .map(drop)
        .map_err(|source| match source.kind() {
            std::io::ErrorKind::PermissionDenied => StoreError::PermissionDenied {
                path: path.to_owned(),
                source,
            },
            _ => StoreError::Create {
                path: path.to_owned(),
                source,
            },
        })
}

/// 128-bit random identifier from the kernel CSPRNG, hex encoded. Used for
/// the host ID (future central management, SRS 4.4) and scan IDs.
pub fn new_id() -> String {
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("/dev/urandom is readable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let (store, applied) = Store::create_or_migrate(&dir.path().join("soteria.db")).unwrap();
        assert_eq!(applied, (1..=SCHEMA_VERSION).collect::<Vec<_>>());
        (dir, store)
    }

    #[test]
    fn creates_database_at_current_schema() {
        let (_d, store) = fresh();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(store.integrity_check().unwrap().is_empty());
        assert_eq!(store.meta("host_id").unwrap().unwrap().len(), 32);
    }

    #[test]
    fn database_file_is_private() {
        let (_d, store) = fresh();
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(store.permission_problems().is_empty());
    }

    #[test]
    fn loose_permissions_are_reported() {
        let (_d, store) = fresh();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(store.permission_problems().len(), 1);
    }

    #[test]
    fn migration_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("soteria.db");
        let host_id = Store::create_or_migrate(&path)
            .unwrap()
            .0
            .meta("host_id")
            .unwrap();
        let (again, applied) = Store::create_or_migrate(&path).unwrap();
        assert!(applied.is_empty());
        assert_eq!(again.meta("host_id").unwrap(), host_id);
    }

    #[test]
    fn open_rejects_missing_database() {
        let dir = tempfile::tempdir().unwrap();
        let err = Store::open(&dir.path().join("nope.db")).unwrap_err();
        assert!(matches!(err, StoreError::Missing(_)));
    }

    #[test]
    fn open_rejects_newer_schema() {
        let (_d, store) = fresh();
        store
            .connection()
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        let path = store.path().to_owned();
        drop(store);
        let err = Store::open(&path).unwrap_err();
        assert!(matches!(err, StoreError::TooNew { .. }));
    }

    #[test]
    fn open_rejects_unmigrated_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.db");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE x (y)")
            .unwrap();
        assert!(matches!(
            Store::open(&path).unwrap_err(),
            StoreError::NeedsMigration { found: 0, .. }
        ));
    }

    fn insert_alert(store: &Store) {
        store
            .connection()
            .execute(
                "INSERT INTO alerts (uuid, created_at, updated_at, severity, type, status, hostname,
                                     rule_id, reason, evidence, recommendation)
                 VALUES ('a1', ?1, ?1, 'high', 'file_integrity', 'open', 'host', 'R1',
                         'content changed', '{\"sha256\":\"x\"}', 'investigate')",
                [now()],
            )
            .unwrap();
    }

    #[test]
    fn alert_status_can_change_but_evidence_cannot() {
        let (_d, store) = fresh();
        insert_alert(&store);
        let c = store.connection();
        c.execute(
            "UPDATE alerts SET status = 'acknowledged', updated_at = ?1",
            [now()],
        )
        .unwrap();
        let err = c
            .execute("UPDATE alerts SET evidence = '{}'", [])
            .unwrap_err();
        assert!(err.to_string().contains("immutable"), "{err}");
        assert!(c.execute("DELETE FROM alerts", []).is_err());
    }

    #[test]
    fn alert_history_is_append_only() {
        let (_d, store) = fresh();
        insert_alert(&store);
        let c = store.connection();
        c.execute(
            "INSERT INTO alert_history (alert_id, ts, actor, action, note) VALUES (1, ?1, 'root', 'note', 'checked')",
            [now()],
        )
        .unwrap();
        assert!(
            c.execute("UPDATE alert_history SET note = 'x'", [])
                .is_err()
        );
        assert!(c.execute("DELETE FROM alert_history", []).is_err());
    }

    #[test]
    fn sealed_baselines_are_immutable() {
        let (_d, store) = fresh();
        let c = store.connection();
        c.execute(
            "INSERT INTO baseline_versions (id, version, state, created_at, created_by) VALUES (1, 1, 'draft', ?1, 'root')",
            [now()],
        )
        .unwrap();
        c.execute(
            "INSERT INTO baseline_entries (baseline_id, path, kind, file_type) VALUES (1, X'2F6574632F706173737764', 'configuration', 'regular')",
            [],
        )
        .unwrap();
        // Drafts can still be edited.
        c.execute("UPDATE baseline_entries SET sha256 = 'abc'", [])
            .unwrap();
        c.execute(
            "UPDATE baseline_versions SET state = 'approved', approved_at = ?1, approved_by = 'root', digest = 'd'",
            [now()],
        )
        .unwrap();
        assert!(
            c.execute("UPDATE baseline_entries SET sha256 = 'evil'", [])
                .is_err()
        );
        assert!(c.execute("DELETE FROM baseline_entries", []).is_err());
        assert!(
            c.execute("UPDATE baseline_versions SET digest = 'evil'", [])
                .is_err()
        );
        assert!(c.execute("DELETE FROM baseline_versions", []).is_err());
        assert!(
            c.execute(
                "INSERT INTO baseline_entries (baseline_id, path, kind, file_type) VALUES (1, X'2F78', 'other', 'regular')",
                [],
            )
            .is_err()
        );
        // Superseding an approved version is the one allowed transition.
        c.execute("UPDATE baseline_versions SET state = 'superseded'", [])
            .unwrap();
    }

    #[test]
    fn interrupted_scans_are_marked() {
        let (_d, store) = fresh();
        store
            .connection()
            .execute(
                "INSERT INTO scan_history (uuid, type, started_at, status) VALUES ('s1', 'full', ?1, 'running')",
                [now()],
            )
            .unwrap();
        assert_eq!(store.mark_interrupted_scans().unwrap(), 1);
        assert_eq!(store.mark_interrupted_scans().unwrap(), 0);
    }

    #[test]
    fn summary_of_empty_database() {
        let (_d, store) = fresh();
        store.record_health("agent", "running", None).unwrap();
        let s = store.summary().unwrap();
        assert_eq!(s.indexed_files, 0);
        assert_eq!(s.baseline_version, None);
        assert_eq!(s.open_alert_total(), 0);
        assert_eq!(s.agent_state.as_deref(), Some("running"));
    }

    #[test]
    fn summary_counts_open_alerts_by_severity() {
        let (_d, store) = fresh();
        insert_alert(&store);
        let s = store.summary().unwrap();
        assert_eq!(s.open_alerts.get(&Severity::High), Some(&1));
    }

    #[test]
    fn read_only_store_cannot_write() {
        let (_d, store) = fresh();
        let path = store.path().to_owned();
        drop(store);
        let ro = Store::open_read_only(&path).unwrap();
        assert!(ro.record_health("agent", "running", None).is_err());
    }

    #[test]
    fn corrupted_file_is_detected() {
        let (_d, store) = fresh();
        let path = store.path().to_owned();
        drop(store);
        // Overwrite a page in the middle of the file.
        let mut bytes = std::fs::read(&path).unwrap();
        let len = bytes.len();
        for b in &mut bytes[len / 2..len / 2 + 512] {
            *b = 0xFF;
        }
        std::fs::write(&path, bytes).unwrap();
        let result = Store::open(&path).and_then(|s| s.integrity_check());
        // Refusing to open is also an acceptable detection.
        if let Ok(problems) = result {
            assert!(!problems.is_empty(), "corruption not detected");
        }
    }
}
