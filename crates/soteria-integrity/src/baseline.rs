//! Baseline lifecycle (FR-005, FR-006, FR-008, FR-044, SRS 10.3).
//!
//! 1. `create_draft` snapshots the current inventory into a new draft
//!    version. Drafts are editable and prove nothing about the host.
//! 2. `review` summarizes a draft and how it differs from the approved
//!    baseline, with coverage gaps, for the administrator.
//! 3. `approve` seals a draft: a canonical SHA-256 digest over the version
//!    header and every entry is signed with the root-held Ed25519 key, the
//!    approver is recorded, and the previous approved version is superseded.
//!    Sealed versions are immutable (enforced by schema triggers).
//! 4. `verify` recomputes the digest and checks the signature with the
//!    public key, which is all the unprivileged daemon holds.

use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use soteria_inventory::{FileRecord, hex};
use soteria_store::{Store, now};

use crate::compare::{Change, ChangeSummary, merge};
use crate::keys::{BaselineSigner, key_id, verify_signature};
use crate::rows::{self, COLUMNS, path_bytes};
use ed25519_dalek::VerifyingKey;

const DIGEST_DOMAIN: &[u8] = b"soteria-baseline-v1";

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("baseline version {0} does not exist")]
    NotFound(u32),
    #[error("baseline version {version} is {state}; only drafts can be approved")]
    NotDraft { version: u32, state: String },
    #[error("no draft baseline exists; create one with 'soteria baseline create'")]
    NoDraft,
    #[error("no approved baseline exists yet")]
    NoApproved,
    #[error("the inventory is empty; run 'soteria scan' before creating a baseline")]
    EmptyInventory,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, BaselineError>;

#[derive(Debug, Clone, Serialize)]
pub struct BaselineInfo {
    pub version: u32,
    pub state: String,
    pub created_at: String,
    pub created_by: String,
    pub parent_version: Option<u32>,
    pub entry_count: u64,
    pub approved_at: Option<String>,
    pub approved_by: Option<String>,
    pub approved_uid: Option<u32>,
    pub digest: Option<String>,
    pub key_id: Option<String>,
    pub note: Option<String>,
    #[serde(skip)]
    id: i64,
    #[serde(skip)]
    signature: Option<Vec<u8>>,
}

const INFO_COLUMNS: &str = "id, version, state, created_at, created_by, parent_version, entry_count, \
                            approved_at, approved_by, approved_uid, digest, key_id, note, signature";

fn info_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<BaselineInfo> {
    Ok(BaselineInfo {
        id: r.get(0)?,
        version: r.get(1)?,
        state: r.get(2)?,
        created_at: r.get(3)?,
        created_by: r.get(4)?,
        parent_version: r.get(5)?,
        entry_count: r.get::<_, i64>(6)?.max(0) as u64,
        approved_at: r.get(7)?,
        approved_by: r.get(8)?,
        approved_uid: r.get(9)?,
        digest: r.get(10)?,
        key_id: r.get(11)?,
        note: r.get(12)?,
        signature: r.get(13)?,
    })
}

pub fn list(store: &Store) -> Result<Vec<BaselineInfo>> {
    let mut stmt = store.connection().prepare(&format!(
        "SELECT {INFO_COLUMNS} FROM baseline_versions ORDER BY version"
    ))?;
    let rows = stmt.query_map([], info_from_row)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn get(store: &Store, version: u32) -> Result<BaselineInfo> {
    store
        .connection()
        .query_row(
            &format!("SELECT {INFO_COLUMNS} FROM baseline_versions WHERE version = ?1"),
            [version],
            info_from_row,
        )
        .optional()?
        .ok_or(BaselineError::NotFound(version))
}

pub fn latest_approved(store: &Store) -> Result<Option<BaselineInfo>> {
    Ok(store
        .connection()
        .query_row(
            &format!(
                "SELECT {INFO_COLUMNS} FROM baseline_versions WHERE state = 'approved'
                 ORDER BY version DESC LIMIT 1"
            ),
            [],
            info_from_row,
        )
        .optional()?)
}

pub fn current_draft(store: &Store) -> Result<Option<BaselineInfo>> {
    Ok(store
        .connection()
        .query_row(
            &format!(
                "SELECT {INFO_COLUMNS} FROM baseline_versions WHERE state = 'draft'
                 ORDER BY version DESC LIMIT 1"
            ),
            [],
            info_from_row,
        )
        .optional()?)
}

/// Snapshot the current inventory as a new draft. An existing draft is
/// discarded: there is at most one draft at a time.
pub fn create_draft(
    store: &mut Store,
    created_by: &str,
    note: Option<&str>,
) -> Result<BaselineInfo> {
    let tx = store.connection_mut().transaction()?;
    let files: i64 = tx.query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))?;
    if files == 0 {
        return Err(BaselineError::EmptyInventory);
    }
    // Discard any previous draft (drafts are not evidence).
    tx.execute(
        "DELETE FROM baseline_entries WHERE baseline_id IN
           (SELECT id FROM baseline_versions WHERE state = 'draft')",
        [],
    )?;
    tx.execute("DELETE FROM baseline_versions WHERE state = 'draft'", [])?;

    let version: u32 = tx.query_row(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM baseline_versions",
        [],
        |r| r.get(0),
    )?;
    let parent: Option<u32> = tx
        .query_row(
            "SELECT version FROM baseline_versions WHERE state = 'approved' ORDER BY version DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    tx.execute(
        "INSERT INTO baseline_versions (version, state, created_at, created_by, parent_version, note)
         VALUES (?1, 'draft', ?2, ?3, ?4, ?5)",
        params![version, now(), created_by, parent, note],
    )?;
    let id = tx.last_insert_rowid();
    let entries = tx.execute(
        &format!(
            "INSERT INTO baseline_entries (baseline_id, {COLUMNS})
             SELECT ?1, {COLUMNS} FROM files ORDER BY path"
        ),
        [id],
    )?;
    tx.execute(
        "UPDATE baseline_versions SET entry_count = ?2 WHERE id = ?1",
        params![id, entries as i64],
    )?;
    tx.commit()?;
    get(store, version)
}

/// Review material for a baseline version (SRS 10.3 step 3).
#[derive(Debug, Serialize)]
pub struct Review {
    pub baseline: BaselineInfo,
    pub by_kind: std::collections::BTreeMap<String, u64>,
    pub open_coverage_gaps: u64,
    /// Differences from the previous approved version, if there is one.
    pub compared_to: Option<u32>,
    pub changes: ChangeSummary,
    /// The most severe differences, for display.
    pub top_changes: Vec<Change>,
    pub notice: &'static str,
}

const REVIEW_NOTICE: &str = "A baseline records the state of this host as it is now. It is not proof \
     that the host is clean: approve it only after you are satisfied the system has not been tampered with.";

pub fn review(store: &Store, version: u32, top: usize) -> Result<Review> {
    let info = get(store, version)?;
    let mut by_kind = std::collections::BTreeMap::new();
    {
        let mut stmt = store.connection().prepare(
            "SELECT kind, COUNT(*) FROM baseline_entries WHERE baseline_id = ?1 GROUP BY kind",
        )?;
        for row in stmt.query_map([info.id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })? {
            let (k, n) = row?;
            by_kind.insert(k, n.max(0) as u64);
        }
    }
    let open_coverage_gaps: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM coverage_gaps WHERE closed_at IS NULL",
        [],
        |r| r.get(0),
    )?;

    let parent = match info.parent_version {
        Some(p) => Some(get(store, p)?),
        None => None,
    };
    let mut changes = ChangeSummary::default();
    let mut top_changes = Vec::new();
    if let Some(parent) = &parent {
        diff_ids(store, parent.id, info.id, |c| {
            changes.add(&c);
            top_changes.push(c);
        })?;
        top_changes.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
        top_changes.truncate(top);
    }
    Ok(Review {
        baseline: info,
        by_kind,
        open_coverage_gaps: open_coverage_gaps.max(0) as u64,
        compared_to: parent.map(|p| p.version),
        changes,
        top_changes,
        notice: REVIEW_NOTICE,
    })
}

/// Who approved a baseline (FR-044).
#[derive(Debug, Clone)]
pub struct Approver {
    pub name: String,
    pub uid: u32,
}

/// Seal a draft with the signing key.
pub fn approve(
    store: &mut Store,
    version: u32,
    signer: &BaselineSigner,
    approver: &Approver,
) -> Result<BaselineInfo> {
    let host_id = store.meta("host_id").ok().flatten().unwrap_or_default();
    let tx = store.connection_mut().transaction()?;
    let mut info = tx
        .query_row(
            &format!("SELECT {INFO_COLUMNS} FROM baseline_versions WHERE version = ?1"),
            [version],
            info_from_row,
        )
        .optional()?
        .ok_or(BaselineError::NotFound(version))?;
    if info.state != "draft" {
        return Err(BaselineError::NotDraft {
            version,
            state: info.state,
        });
    }
    info.approved_at = Some(now());
    info.approved_by = Some(approver.name.clone());
    info.approved_uid = Some(approver.uid);
    info.key_id = Some(signer.key_id());

    let digest = compute_digest(&tx, &host_id, &info)?;
    let signature = signer.sign(&digest);

    tx.execute(
        "UPDATE baseline_versions SET state = 'superseded' WHERE state = 'approved'",
        [],
    )?;
    tx.execute(
        "UPDATE baseline_versions SET state = 'approved', approved_at = ?2, approved_by = ?3,
                approved_uid = ?4, digest = ?5, signature = ?6, key_id = ?7
         WHERE id = ?1",
        params![
            info.id,
            info.approved_at,
            info.approved_by,
            info.approved_uid,
            hex(&digest),
            signature,
            info.key_id
        ],
    )?;
    tx.execute(
        "INSERT INTO events (ts, sensor, type, severity, uid, data) VALUES (?1, 'integrity', 'baseline.approved', 'info', ?2, ?3)",
        params![
            now(),
            approver.uid,
            serde_json::json!({
                "version": version,
                "approved_by": approver.name,
                "entries": info.entry_count,
                "key_id": info.key_id,
                "digest": hex(&digest),
            })
            .to_string()
        ],
    )?;
    tx.commit()?;
    get(store, version)
}

/// Result of checking a sealed baseline (FR-006, FR-038).
#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    pub version: u32,
    pub valid: bool,
    pub problems: Vec<String>,
}

pub fn verify(store: &Store, version: u32, key: &VerifyingKey) -> Result<Verification> {
    let info = get(store, version)?;
    let mut problems = Vec::new();
    if info.state != "approved" && info.state != "superseded" {
        problems.push(format!(
            "version {version} is a {} and is not sealed",
            info.state
        ));
        return Ok(Verification {
            version,
            valid: false,
            problems,
        });
    }
    let host_id = store.meta("host_id").ok().flatten().unwrap_or_default();
    let digest = compute_digest(store.connection(), &host_id, &info)?;

    let entries: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM baseline_entries WHERE baseline_id = ?1",
        [info.id],
        |r| r.get(0),
    )?;
    if entries.max(0) as u64 != info.entry_count {
        problems.push(format!(
            "entry count is {entries} but {} were sealed",
            info.entry_count
        ));
    }
    if info.digest.as_deref() != Some(hex(&digest).as_str()) {
        problems.push("baseline content does not match its sealed digest".into());
    }
    let expected_key = key_id(key);
    if info.key_id.as_deref() != Some(expected_key.as_str()) {
        problems.push(format!(
            "sealed with key {} but the configured public key is {expected_key}",
            info.key_id.as_deref().unwrap_or("(none)")
        ));
    }
    match &info.signature {
        Some(sig) if verify_signature(key, &digest, sig) => {}
        Some(_) => problems.push("signature is invalid".into()),
        None => problems.push("signature is missing".into()),
    }
    Ok(Verification {
        version,
        valid: problems.is_empty(),
        problems,
    })
}

/// The approved state of one path in a baseline version, if recorded.
pub fn entry(store: &Store, version: u32, path: &std::path::Path) -> Result<Option<FileRecord>> {
    let info = get(store, version)?;
    Ok(store
        .connection()
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM baseline_entries WHERE baseline_id = ?1 AND path = ?2"
        ))?
        .query_row(params![info.id, path_bytes(path)], |r| rows::from_row(r, 0))
        .optional()?)
}

/// Paths of a version's entries whose kinds are in `kinds`, in path order.
pub fn entry_paths(
    store: &Store,
    version: u32,
    kinds: &[soteria_core::FileKind],
) -> Result<Vec<std::path::PathBuf>> {
    let info = get(store, version)?;
    let wanted: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    let mut stmt = store
        .connection()
        .prepare("SELECT path, kind FROM baseline_entries WHERE baseline_id = ?1 ORDER BY path")?;
    let rows = stmt.query_map([info.id], |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (path, kind) = row?;
        if wanted.contains(&kind.as_str()) {
            out.push(rows::path_from_bytes(path));
        }
    }
    Ok(out)
}

/// Compare two baseline versions (FR-008).
pub fn diff_versions(
    store: &Store,
    from: u32,
    to: u32,
    on_change: impl FnMut(Change),
) -> Result<()> {
    let a = get(store, from)?;
    let b = get(store, to)?;
    diff_ids(store, a.id, b.id, on_change)
}

/// Compare a baseline version with the current inventory (FR-007).
pub fn diff_current(store: &Store, version: u32, mut on_change: impl FnMut(Change)) -> Result<()> {
    let base = get(store, version)?;
    let conn = store.connection();
    let mut sa = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM baseline_entries WHERE baseline_id = ?1 ORDER BY path"
    ))?;
    let mut sb = conn.prepare(&format!("SELECT {COLUMNS} FROM files ORDER BY path"))?;
    let a = sa.query_map([base.id], |r| rows::from_row(r, 0))?;
    let b = sb.query_map([], |r| rows::from_row(r, 0))?;
    merge(a, b, |c| {
        on_change(c);
        Ok::<_, rusqlite::Error>(())
    })?;
    Ok(())
}

fn diff_ids(
    store: &Store,
    from_id: i64,
    to_id: i64,
    mut on_change: impl FnMut(Change),
) -> Result<()> {
    let conn = store.connection();
    let sql =
        format!("SELECT {COLUMNS} FROM baseline_entries WHERE baseline_id = ?1 ORDER BY path");
    let mut sa = conn.prepare(&sql)?;
    let mut sb = conn.prepare(&sql)?;
    let a = sa.query_map([from_id], |r| rows::from_row(r, 0))?;
    let b = sb.query_map([to_id], |r| rows::from_row(r, 0))?;
    merge(a, b, |c| {
        on_change(c);
        Ok::<_, rusqlite::Error>(())
    })?;
    Ok(())
}

/// Canonical digest of a baseline version: a domain tag, the host ID, the
/// version header and every entry in path order, each field length-prefixed
/// so no two different baselines can encode to the same byte stream.
fn compute_digest(
    tx: &rusqlite::Connection,
    host_id: &str,
    info: &BaselineInfo,
) -> rusqlite::Result<[u8; 32]> {
    let mut h = Sha256::new();
    field(&mut h, DIGEST_DOMAIN);
    field(&mut h, host_id.as_bytes());
    field(&mut h, &info.version.to_be_bytes());
    opt(
        &mut h,
        info.parent_version
            .map(|v| v.to_be_bytes().to_vec())
            .as_deref(),
    );
    field(&mut h, info.created_at.as_bytes());
    field(&mut h, info.created_by.as_bytes());
    opt(&mut h, info.approved_at.as_deref().map(str::as_bytes));
    opt(&mut h, info.approved_by.as_deref().map(str::as_bytes));
    opt(
        &mut h,
        info.approved_uid
            .map(|u| u.to_be_bytes().to_vec())
            .as_deref(),
    );
    opt(&mut h, info.key_id.as_deref().map(str::as_bytes));
    opt(&mut h, info.note.as_deref().map(str::as_bytes));
    field(&mut h, &info.entry_count.to_be_bytes());

    let mut stmt = tx.prepare(&format!(
        "SELECT {COLUMNS} FROM baseline_entries WHERE baseline_id = ?1 ORDER BY path"
    ))?;
    let entries = stmt.query_map([info.id], |r| rows::from_row(r, 0))?;
    for e in entries {
        encode_entry(&mut h, &e?);
    }
    Ok(h.finalize().into())
}

fn encode_entry(h: &mut Sha256, r: &FileRecord) {
    field(h, b"entry");
    field(h, path_bytes(&r.path));
    field(h, r.kind.as_str().as_bytes());
    field(h, r.file_type.as_str().as_bytes());
    opt(h, r.sha256.as_deref().map(str::as_bytes));
    field(h, &r.size.to_be_bytes());
    field(h, &r.uid.to_be_bytes());
    field(h, &r.gid.to_be_bytes());
    field(h, &r.mode.to_be_bytes());
    field(h, &r.mtime_ns.to_be_bytes());
    field(h, &r.ctime_ns.to_be_bytes());
    field(h, &r.inode.to_be_bytes());
    field(h, &r.device.to_be_bytes());
    opt(h, r.symlink_target.as_deref().map(path_bytes));
    opt(h, r.capabilities.as_deref());
    opt(h, r.security_label.as_deref().map(str::as_bytes));
}

fn field(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn opt(h: &mut Sha256, bytes: Option<&[u8]>) {
    match bytes {
        None => h.update([0u8]),
        Some(b) => {
            h.update([1u8]);
            field(h, b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use crate::scan::{self, ScanTarget};
    use soteria_inventory::Scope;
    use std::path::{Path, PathBuf};

    struct Fixture {
        _dir: tempfile::TempDir,
        store: Store,
        root: PathBuf,
        signer: BaselineSigner,
        public: VerifyingKey,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = Store::create_or_migrate(&dir.path().join("db")).unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/tool"), b"v1").unwrap();
        std::fs::write(root.join("bin/other"), b"o").unwrap();
        let sk = dir.path().join("k/baseline.key");
        let pk = dir.path().join("k/baseline.pub");
        let public = keys::generate(&sk, &pk).unwrap();
        let signer = keys::load_signer(&sk).unwrap();
        Fixture {
            _dir: dir,
            store,
            root,
            signer,
            public,
        }
    }

    fn scan(f: &mut Fixture) {
        let scope = Scope {
            include: vec![f.root.clone()],
            exclude: vec![],
        };
        scan::run(&mut f.store, &scope, &ScanTarget::Full, "full").unwrap();
    }

    fn admin() -> Approver {
        Approver {
            name: "root (via sudo from alice)".into(),
            uid: 0,
        }
    }

    fn approve_new(f: &mut Fixture) -> BaselineInfo {
        let draft = create_draft(&mut f.store, "root", None).unwrap();
        approve(&mut f.store, draft.version, &f.signer, &admin()).unwrap()
    }

    fn changes_now(f: &Fixture, version: u32) -> Vec<Change> {
        let mut out = Vec::new();
        diff_current(&f.store, version, |c| out.push(c)).unwrap();
        out
    }

    #[test]
    fn draft_requires_inventory() {
        let mut f = fixture();
        assert!(matches!(
            create_draft(&mut f.store, "root", None),
            Err(BaselineError::EmptyInventory)
        ));
    }

    #[test]
    fn approve_seals_and_verifies() {
        let mut f = fixture();
        scan(&mut f);
        let draft = create_draft(&mut f.store, "root", Some("initial")).unwrap();
        assert_eq!(draft.state, "draft");
        assert_eq!(draft.entry_count, 4);
        assert!(!verify(&f.store, 1, &f.public).unwrap().valid);

        let sealed = approve(&mut f.store, 1, &f.signer, &admin()).unwrap();
        assert_eq!(sealed.state, "approved");
        assert_eq!(
            sealed.approved_by.as_deref(),
            Some("root (via sudo from alice)")
        );
        assert_eq!(sealed.approved_uid, Some(0));
        let v = verify(&f.store, 1, &f.public).unwrap();
        assert!(v.valid, "{:?}", v.problems);
        assert_eq!(latest_approved(&f.store).unwrap().unwrap().version, 1);

        let events: i64 = f
            .store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'baseline.approved'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(events, 1);
    }

    #[test]
    fn cannot_approve_twice() {
        let mut f = fixture();
        scan(&mut f);
        let v = approve_new(&mut f).version;
        assert!(matches!(
            approve(&mut f.store, v, &f.signer, &admin()),
            Err(BaselineError::NotDraft { .. })
        ));
    }

    #[test]
    fn new_approval_supersedes_and_keeps_history() {
        let mut f = fixture();
        scan(&mut f);
        approve_new(&mut f);
        std::fs::write(f.root.join("bin/tool"), b"v2").unwrap();
        scan(&mut f);
        let second = approve_new(&mut f);
        assert_eq!(second.version, 2);
        assert_eq!(second.parent_version, Some(1));
        let states: Vec<String> = list(&f.store)
            .unwrap()
            .into_iter()
            .map(|b| b.state)
            .collect();
        assert_eq!(states, vec!["superseded", "approved"]);
        // Superseded versions still verify and can be compared (FR-008).
        assert!(verify(&f.store, 1, &f.public).unwrap().valid);
        let mut diffs = Vec::new();
        diff_versions(&f.store, 1, 2, |c| diffs.push(c)).unwrap();
        assert!(diffs.iter().any(|c| c.path.ends_with("bin/tool")));
    }

    #[test]
    fn detects_changes_against_baseline() {
        let mut f = fixture();
        scan(&mut f);
        let v = approve_new(&mut f).version;
        assert!(changes_now(&f, v).is_empty());

        std::fs::write(f.root.join("bin/tool"), b"tampered").unwrap();
        std::fs::remove_file(f.root.join("bin/other")).unwrap();
        std::fs::write(f.root.join("bin/new"), b"n").unwrap();
        scan(&mut f);
        let changes = changes_now(&f, v);
        let summary: Vec<(String, Vec<String>)> = changes
            .iter()
            .filter(|c| !c.path.ends_with("bin")) // directory mtime changes too
            .map(|c| {
                (
                    c.path.file_name().unwrap().to_string_lossy().into_owned(),
                    c.kinds.iter().map(|k| k.to_string()).collect(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                ("new".into(), vec!["new".into()]),
                ("other".into(), vec!["missing".into()]),
                ("tool".into(), vec!["content_modified".into()]),
            ]
        );
    }

    fn tamper(f: &Fixture, sql: &str) {
        // Simulate an attacker editing the database file directly: drop the
        // protective triggers first, as someone with file access could.
        let c = f.store.connection();
        for t in [
            "baseline_sealed_no_update",
            "baseline_entries_sealed_no_update",
            "baseline_entries_sealed_no_delete",
            "baseline_entries_sealed_no_insert",
        ] {
            c.execute(&format!("DROP TRIGGER {t}"), []).unwrap();
        }
        c.execute(sql, []).unwrap();
    }

    #[test]
    fn tampered_entry_fails_verification() {
        let mut f = fixture();
        scan(&mut f);
        approve_new(&mut f);
        tamper(
            &f,
            "UPDATE baseline_entries SET sha256 = 'forged' WHERE kind = 'other' AND sha256 IS NOT NULL",
        );
        let v = verify(&f.store, 1, &f.public).unwrap();
        assert!(!v.valid);
        assert!(v.problems.iter().any(|p| p.contains("digest")));
    }

    #[test]
    fn deleted_entry_fails_verification() {
        let mut f = fixture();
        scan(&mut f);
        approve_new(&mut f);
        tamper(
            &f,
            "DELETE FROM baseline_entries WHERE path = (SELECT MAX(path) FROM baseline_entries)",
        );
        assert!(!verify(&f.store, 1, &f.public).unwrap().valid);
    }

    #[test]
    fn forged_approver_fails_verification() {
        let mut f = fixture();
        scan(&mut f);
        approve_new(&mut f);
        tamper(&f, "UPDATE baseline_versions SET approved_by = 'mallory'");
        assert!(!verify(&f.store, 1, &f.public).unwrap().valid);
    }

    #[test]
    fn resealed_with_another_key_is_rejected() {
        let mut f = fixture();
        scan(&mut f);
        approve_new(&mut f);
        // A different key pair (for example, one an attacker generated).
        let dir = tempfile::tempdir().unwrap();
        let other = keys::generate(&dir.path().join("a"), &dir.path().join("b")).unwrap();
        let v = verify(&f.store, 1, &other).unwrap();
        assert!(!v.valid);
        assert!(v.problems.iter().any(|p| p.contains("sealed with key")));
    }

    #[test]
    fn review_reports_differences_from_parent() {
        let mut f = fixture();
        scan(&mut f);
        let first = create_draft(&mut f.store, "root", None).unwrap();
        let r = review(&f.store, first.version, 10).unwrap();
        assert_eq!(r.compared_to, None);
        assert_eq!(r.by_kind.values().sum::<u64>(), 4);
        approve(&mut f.store, first.version, &f.signer, &admin()).unwrap();

        std::fs::write(f.root.join("bin/tool"), b"v2").unwrap();
        scan(&mut f);
        let second = create_draft(&mut f.store, "root", None).unwrap();
        let r = review(&f.store, second.version, 10).unwrap();
        assert_eq!(r.compared_to, Some(1));
        assert!(r.changes.total >= 1);
        assert!(
            r.top_changes
                .iter()
                .any(|c| c.path.ends_with(Path::new("bin/tool")))
        );
    }

    #[test]
    fn new_draft_replaces_old_draft() {
        let mut f = fixture();
        scan(&mut f);
        create_draft(&mut f.store, "root", None).unwrap();
        let again = create_draft(&mut f.store, "root", None).unwrap();
        assert_eq!(again.version, 1);
        assert_eq!(list(&f.store).unwrap().len(), 1);
    }
}
