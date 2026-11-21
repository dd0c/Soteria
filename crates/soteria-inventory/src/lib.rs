//! Inventory engine: discovery, classification, metadata and hashing
//! (FR-001..FR-004).
//!
//! The scanner never follows symlinks, never crosses into excluded paths and
//! never opens anything that is not a regular file, so FIFOs and device nodes
//! cannot stall or disturb a scan. Everything it could not inspect is
//! returned as a [`Gap`] rather than skipped silently (FR-017).

pub mod classify;

use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use soteria_core::FileKind;

pub use classify::{Magic, classify};

/// Filesystem object type as reported by lstat(2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Unknown,
}

impl FileType {
    pub fn of(ft: std::fs::FileType) -> FileType {
        if ft.is_symlink() {
            FileType::Symlink
        } else if ft.is_dir() {
            FileType::Directory
        } else if ft.is_file() {
            FileType::Regular
        } else if ft.is_char_device() {
            FileType::CharDevice
        } else if ft.is_block_device() {
            FileType::BlockDevice
        } else if ft.is_fifo() {
            FileType::Fifo
        } else if ft.is_socket() {
            FileType::Socket
        } else {
            FileType::Unknown
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FileType::Regular => "regular",
            FileType::Directory => "directory",
            FileType::Symlink => "symlink",
            FileType::CharDevice => "char_device",
            FileType::BlockDevice => "block_device",
            FileType::Fifo => "fifo",
            FileType::Socket => "socket",
            FileType::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> FileType {
        match s {
            "regular" => FileType::Regular,
            "directory" => FileType::Directory,
            "symlink" => FileType::Symlink,
            "char_device" => FileType::CharDevice,
            "block_device" => FileType::BlockDevice,
            "fifo" => FileType::Fifo,
            "socket" => FileType::Socket,
            _ => FileType::Unknown,
        }
    }
}

/// Collected state of one object (FR-004). Paths are kept as raw bytes
/// (`PathBuf`) because Linux paths need not be UTF-8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileRecord {
    pub path: PathBuf,
    pub file_type: FileType,
    pub kind: FileKind,
    pub sha256: Option<String>,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    /// Full st_mode, including file type and setuid/setgid/sticky bits.
    pub mode: u32,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub inode: u64,
    pub device: u64,
    pub symlink_target: Option<PathBuf>,
    /// Raw `security.capability` extended attribute.
    pub capabilities: Option<Vec<u8>>,
    /// SELinux context (`security.selinux`), where the platform labels files.
    pub security_label: Option<String>,
    /// Why the object could not be fully inspected (for example, not hashed).
    pub error: Option<String>,
}

impl FileRecord {
    /// Permission bits including setuid, setgid and sticky.
    pub fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }

    pub fn is_executable(&self) -> bool {
        self.file_type == FileType::Regular && self.mode & 0o111 != 0
    }
}

/// Why coverage is incomplete for a path (FR-017).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// Could not read a directory or stat an object.
    Inaccessible,
    /// A regular file whose content could not be hashed.
    NotHashed,
    /// A configured include path does not exist.
    Missing,
    /// Other filesystem conditions, such as a file changing during hashing.
    Unsupported,
}

impl GapKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GapKind::Inaccessible => "inaccessible",
            GapKind::NotHashed => "not_hashed",
            GapKind::Missing => "missing",
            GapKind::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Gap {
    pub kind: GapKind,
    pub path: PathBuf,
    pub detail: String,
}

/// Counters for one walk (FR-034).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WalkStats {
    pub checked: u64,
    pub hashed: u64,
    pub skipped: u64,
    pub errors: u64,
    pub bytes_hashed: u64,
}

/// Configured scope of a scan.
#[derive(Debug, Clone)]
pub struct Scope {
    pub include: Vec<PathBuf>,
    pub exclude: Vec<PathBuf>,
}

impl Scope {
    pub fn is_excluded(&self, path: &Path) -> bool {
        self.exclude
            .iter()
            .any(|ex| starts_with_components(path, ex))
    }

    /// Include roots, minus ones nested inside another include or excluded,
    /// so nothing is walked twice.
    pub fn roots(&self) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = self
            .include
            .iter()
            .map(|p| normalize(p))
            .filter(|p| !self.is_excluded(p))
            .collect();
        roots.sort();
        roots.dedup();
        let all = roots.clone();
        roots.retain(|r| !all.iter().any(|o| o != r && starts_with_components(r, o)));
        roots
    }
}

fn normalize(p: &Path) -> PathBuf {
    p.components().filter(|c| *c != Component::CurDir).collect()
}

fn starts_with_components(path: &Path, prefix: &Path) -> bool {
    normalize(path).starts_with(normalize(prefix))
}

/// Walks a [`Scope`] and reports each object and each gap to callbacks, so
/// large inventories are streamed rather than held in memory (NFR-002).
pub struct Scanner<'a> {
    scope: &'a Scope,
    stats: WalkStats,
}

pub trait Visitor {
    fn record(&mut self, record: FileRecord);
    fn gap(&mut self, gap: Gap);
}

impl<'a> Scanner<'a> {
    pub fn new(scope: &'a Scope) -> Scanner<'a> {
        Scanner {
            scope,
            stats: WalkStats::default(),
        }
    }

    /// Walk every include root.
    pub fn walk_all(mut self, visitor: &mut dyn Visitor) -> WalkStats {
        for root in self.scope.roots() {
            self.walk_from(&root, visitor);
        }
        self.stats
    }

    /// Walk one directory tree or one file, still honouring exclusions.
    pub fn walk(mut self, root: &Path, visitor: &mut dyn Visitor) -> WalkStats {
        self.walk_from(&normalize(root), visitor);
        self.stats
    }

    fn walk_from(&mut self, root: &Path, visitor: &mut dyn Visitor) {
        if self.scope.is_excluded(root) {
            return;
        }
        match std::fs::symlink_metadata(root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.stats.skipped += 1;
                visitor.gap(Gap {
                    kind: GapKind::Missing,
                    path: root.to_owned(),
                    detail: "configured path does not exist".into(),
                });
                return;
            }
            Err(e) => {
                self.inaccessible(root, &e, visitor);
                return;
            }
            Ok(_) => {}
        }

        let mut stack = vec![root.to_owned()];
        while let Some(path) = stack.pop() {
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, // vanished mid-walk
                Err(e) => {
                    self.inaccessible(&path, &e, visitor);
                    continue;
                }
            };
            let record = inspect(&path, &meta);
            self.stats.checked += 1;
            if let Some(err) = &record.error {
                self.stats.errors += 1;
                visitor.gap(Gap {
                    kind: if record.file_type == FileType::Regular {
                        GapKind::NotHashed
                    } else {
                        GapKind::Unsupported
                    },
                    path: path.clone(),
                    detail: err.clone(),
                });
            }
            if record.sha256.is_some() {
                self.stats.hashed += 1;
                self.stats.bytes_hashed += record.size;
            }
            let is_dir = record.file_type == FileType::Directory;
            visitor.record(record);

            if is_dir {
                match std::fs::read_dir(&path) {
                    Ok(entries) => {
                        let mut children: Vec<PathBuf> = entries
                            .filter_map(|e| match e {
                                Ok(e) => Some(e.path()),
                                Err(err) => {
                                    self.inaccessible(&path, &err, visitor);
                                    None
                                }
                            })
                            .collect();
                        children.retain(|p| !self.scope.is_excluded(p));
                        // Reverse order so the stack yields paths in sorted order.
                        children.sort_unstable_by(|a, b| b.cmp(a));
                        stack.extend(children);
                    }
                    Err(e) => self.inaccessible(&path, &e, visitor),
                }
            }
        }
    }

    fn inaccessible(&mut self, path: &Path, err: &std::io::Error, visitor: &mut dyn Visitor) {
        self.stats.errors += 1;
        visitor.gap(Gap {
            kind: GapKind::Inaccessible,
            path: path.to_owned(),
            detail: err.to_string(),
        });
    }
}

/// Collect the full record for one path without following symlinks.
/// Returns `None` if the path does not exist.
pub fn inspect_path(path: &Path) -> std::io::Result<Option<FileRecord>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(inspect(path, &meta))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn inspect(path: &Path, meta: &Metadata) -> FileRecord {
    let file_type = FileType::of(meta.file_type());
    let mut record = FileRecord {
        path: path.to_owned(),
        file_type,
        kind: FileKind::Other,
        sha256: None,
        size: meta.len(),
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
        mtime_ns: meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
        ctime_ns: meta.ctime() * 1_000_000_000 + meta.ctime_nsec(),
        inode: meta.ino(),
        device: meta.dev(),
        symlink_target: None,
        capabilities: None,
        security_label: None,
        error: None,
    };

    if file_type == FileType::Symlink {
        match std::fs::read_link(path) {
            Ok(t) => record.symlink_target = Some(t),
            Err(e) => record.error = Some(format!("cannot read link target: {e}")),
        }
    }

    // Extended attributes are read without following symlinks (lgetxattr).
    record.security_label = xattr::get(path, "security.selinux")
        .ok()
        .flatten()
        .map(|v| String::from_utf8_lossy(v.strip_suffix(b"\0").unwrap_or(&v)).into_owned());
    record.capabilities = xattr::get(path, "security.capability").ok().flatten();

    let mut magic = Magic::Unknown;
    if file_type == FileType::Regular {
        match hash_regular(path, meta) {
            Ok((digest, head)) => {
                record.sha256 = Some(digest);
                magic = Magic::sniff(&head);
            }
            Err(e) => record.error = Some(format!("not hashed: {e}")),
        }
    }
    record.kind = classify(path, file_type, record.mode, magic);
    record
}

/// Hash a regular file, guarding against it being swapped or modified
/// between lstat and read. Returns the hex digest and up to 64 leading bytes.
fn hash_regular(path: &Path, before: &Metadata) -> std::io::Result<(String, Vec<u8>)> {
    // O_NOFOLLOW: never hash a symlink target in place of the link.
    // O_NONBLOCK: a FIFO swapped in after lstat cannot block the scan.
    let mut file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.ino() != before.ino() || opened.dev() != before.dev() {
        return Err(std::io::Error::other(
            "file was replaced while being inspected",
        ));
    }

    let mut hasher = Sha256::new();
    let mut head = Vec::with_capacity(64);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if head.len() < 64 {
            let take = (64 - head.len()).min(n);
            head.extend_from_slice(&buf[..take]);
        }
        hasher.update(&buf[..n]);
    }

    let after = file.metadata()?;
    if after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
    {
        return Err(std::io::Error::other("file changed while being hashed"));
    }
    Ok((hex(&hasher.finalize()), head))
}

/// Lower-case hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// SHA-256 of a byte string, hex encoded.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[derive(Default)]
    struct Collect {
        records: Vec<FileRecord>,
        gaps: Vec<Gap>,
    }

    impl Visitor for Collect {
        fn record(&mut self, r: FileRecord) {
            self.records.push(r);
        }
        fn gap(&mut self, g: Gap) {
            self.gaps.push(g);
        }
    }

    fn scope(include: &[&Path], exclude: &[&Path]) -> Scope {
        Scope {
            include: include.iter().map(|p| p.to_path_buf()).collect(),
            exclude: exclude.iter().map(|p| p.to_path_buf()).collect(),
        }
    }

    #[test]
    fn hashes_known_content() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("hello");
        std::fs::write(&f, b"hello\n").unwrap();
        let r = inspect_path(&f).unwrap().unwrap();
        assert_eq!(
            r.sha256.as_deref(),
            Some("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")
        );
        assert_eq!(r.size, 6);
        assert_eq!(r.file_type, FileType::Regular);
        assert!(r.error.is_none());
    }

    #[test]
    fn symlinks_are_recorded_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        let r = inspect_path(&link).unwrap().unwrap();
        assert_eq!(r.file_type, FileType::Symlink);
        assert_eq!(r.kind, FileKind::Symlink);
        assert_eq!(r.symlink_target.as_deref(), Some(target.as_path()));
        assert!(r.sha256.is_none());
    }

    #[test]
    fn fifos_are_not_opened() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !status.map(|s| s.success()).unwrap_or(false) {
            return; // mkfifo unavailable
        }
        let r = inspect_path(&fifo).unwrap().unwrap();
        assert_eq!(r.file_type, FileType::Fifo);
        assert!(r.sha256.is_none());
    }

    #[test]
    fn walk_respects_exclusions_and_reports_missing_roots() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a/skip")).unwrap();
        std::fs::write(root.join("a/one"), b"1").unwrap();
        std::fs::write(root.join("a/skip/two"), b"2").unwrap();
        let missing = root.join("nope");
        let s = scope(&[&root.join("a"), &missing], &[&root.join("a/skip")]);

        let mut c = Collect::default();
        let stats = Scanner::new(&s).walk_all(&mut c);
        let paths: Vec<_> = c.records.iter().map(|r| r.path.clone()).collect();
        assert_eq!(paths, vec![root.join("a"), root.join("a/one")]);
        assert_eq!(stats.checked, 2);
        assert_eq!(stats.hashed, 1);
        assert_eq!(c.gaps.len(), 1);
        assert_eq!(c.gaps[0].kind, GapKind::Missing);
    }

    #[test]
    fn nested_includes_are_walked_once() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/f"), b"x").unwrap();
        let s = scope(&[&root.join("a/b"), &root.join("a"), &root.join("a/")], &[]);
        assert_eq!(s.roots(), vec![root.join("a")]);
        let mut c = Collect::default();
        Scanner::new(&s).walk_all(&mut c);
        assert_eq!(c.records.len(), 3);
    }

    #[test]
    fn exclusion_matches_whole_components() {
        let s = scope(&[], &[Path::new("/run")]);
        assert!(s.is_excluded(Path::new("/run/x")));
        assert!(!s.is_excluded(Path::new("/runtime/x")));
    }

    #[test]
    fn unreadable_files_become_gaps() {
        // Root bypasses permission checks, so this only means something
        // for unprivileged runs.
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("secret");
        std::fs::write(&f, b"s").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = inspect_path(&f).unwrap().unwrap();
        if std::fs::File::open(&f).is_err() {
            assert!(r.sha256.is_none());
            assert!(r.error.as_deref().unwrap().starts_with("not hashed"));
            let s = scope(&[dir.path()], &[]);
            let mut c = Collect::default();
            Scanner::new(&s).walk_all(&mut c);
            assert_eq!(c.gaps[0].kind, GapKind::NotHashed);
        }
    }

    #[test]
    fn mode_and_executable_bit() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("run.sh");
        std::fs::write(&f, b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let r = inspect_path(&f).unwrap().unwrap();
        assert_eq!(r.permissions(), 0o4755);
        assert!(r.is_executable());
        assert_eq!(r.kind, FileKind::Script);
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
