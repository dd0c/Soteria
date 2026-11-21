//! Mapping between [`FileRecord`] and rows of `files` / `baseline_entries`.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use rusqlite::Row;
use soteria_core::FileKind;
use soteria_inventory::{FileRecord, FileType};

/// Columns shared by `files` and `baseline_entries`, in this order.
pub const COLUMNS: &str = "path, kind, file_type, sha256, size, uid, gid, mode, mtime_ns, ctime_ns, \
                           inode, device, symlink_target, capabilities, security_label";

pub fn path_bytes(p: &Path) -> &[u8] {
    p.as_os_str().as_bytes()
}

pub fn path_from_bytes(b: Vec<u8>) -> PathBuf {
    PathBuf::from(OsString::from_vec(b))
}

/// SQLite integers are signed 64-bit; u64 fields are stored by bit pattern.
pub fn u64_to_sql(v: u64) -> i64 {
    v as i64
}

pub fn u64_from_sql(v: i64) -> u64 {
    v as u64
}

/// Read a record from a row selected with [`COLUMNS`] starting at `offset`.
pub fn from_row(row: &Row<'_>, offset: usize) -> rusqlite::Result<FileRecord> {
    let i = |n: usize| offset + n;
    let kind: String = row.get(i(1))?;
    let file_type: String = row.get(i(2))?;
    Ok(FileRecord {
        path: path_from_bytes(row.get(i(0))?),
        kind: kind.parse().unwrap_or(FileKind::Other),
        file_type: FileType::parse(&file_type),
        sha256: row.get(i(3))?,
        size: u64_from_sql(row.get::<_, Option<i64>>(i(4))?.unwrap_or_default()),
        uid: row.get::<_, Option<u32>>(i(5))?.unwrap_or_default(),
        gid: row.get::<_, Option<u32>>(i(6))?.unwrap_or_default(),
        mode: row.get::<_, Option<u32>>(i(7))?.unwrap_or_default(),
        mtime_ns: row.get::<_, Option<i64>>(i(8))?.unwrap_or_default(),
        ctime_ns: row.get::<_, Option<i64>>(i(9))?.unwrap_or_default(),
        inode: u64_from_sql(row.get::<_, Option<i64>>(i(10))?.unwrap_or_default()),
        device: u64_from_sql(row.get::<_, Option<i64>>(i(11))?.unwrap_or_default()),
        symlink_target: row.get::<_, Option<Vec<u8>>>(i(12))?.map(path_from_bytes),
        capabilities: row.get(i(13))?,
        security_label: row.get(i(14))?,
        error: None,
    })
}

/// Bind values for [`COLUMNS`].
pub fn params(r: &FileRecord) -> [rusqlite::types::Value; 15] {
    use rusqlite::types::Value;
    let opt_blob = |b: Option<&[u8]>| b.map(|b| Value::Blob(b.to_vec())).unwrap_or(Value::Null);
    let opt_text = |t: Option<&str>| t.map(|t| Value::Text(t.to_owned())).unwrap_or(Value::Null);
    [
        Value::Blob(path_bytes(&r.path).to_vec()),
        Value::Text(r.kind.as_str().to_owned()),
        Value::Text(r.file_type.as_str().to_owned()),
        opt_text(r.sha256.as_deref()),
        Value::Integer(u64_to_sql(r.size)),
        Value::Integer(r.uid.into()),
        Value::Integer(r.gid.into()),
        Value::Integer(r.mode.into()),
        Value::Integer(r.mtime_ns),
        Value::Integer(r.ctime_ns),
        Value::Integer(u64_to_sql(r.inode)),
        Value::Integer(u64_to_sql(r.device)),
        opt_blob(r.symlink_target.as_deref().map(path_bytes)),
        opt_blob(r.capabilities.as_deref()),
        opt_text(r.security_label.as_deref()),
    ]
}
