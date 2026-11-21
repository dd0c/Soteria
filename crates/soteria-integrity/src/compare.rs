//! Baseline comparison (FR-007, FR-008).
//!
//! Both sides are streamed in path order and merged, so comparing large
//! inventories needs memory for one record per side, not the whole set.

use std::cmp::Ordering;
use std::fmt;

use serde::Serialize;
use soteria_core::{FileKind, Severity};
use soteria_inventory::FileRecord;

/// One way an object differs from its approved state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    New,
    Missing,
    TypeChanged,
    ContentModified,
    PermissionModified,
    OwnerModified,
    CapabilityModified,
    SecurityLabelModified,
    SymlinkTargetModified,
    ExecutableStatusModified,
    /// Size, modification time, inode or device changed without a content,
    /// permission or owner change (for example, a file rewritten in place).
    MetadataModified,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::New => "new",
            ChangeKind::Missing => "missing",
            ChangeKind::TypeChanged => "type_changed",
            ChangeKind::ContentModified => "content_modified",
            ChangeKind::PermissionModified => "permission_modified",
            ChangeKind::OwnerModified => "owner_modified",
            ChangeKind::CapabilityModified => "capability_modified",
            ChangeKind::SecurityLabelModified => "security_label_modified",
            ChangeKind::SymlinkTargetModified => "symlink_target_modified",
            ChangeKind::ExecutableStatusModified => "executable_status_modified",
            ChangeKind::MetadataModified => "metadata_modified",
        }
    }
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// All differences for one path.
#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub path: std::path::PathBuf,
    pub kinds: Vec<ChangeKind>,
    pub severity: Severity,
    pub before: Option<FileRecord>,
    pub after: Option<FileRecord>,
}

/// Differences between an approved record and the current one.
pub fn diff_record(before: &FileRecord, after: &FileRecord) -> Vec<ChangeKind> {
    let mut kinds = Vec::new();
    if before.file_type != after.file_type {
        kinds.push(ChangeKind::TypeChanged);
        return kinds;
    }
    // A record without a hash (unreadable at the time) cannot prove a
    // content change; that is reported as a coverage gap instead.
    if before.sha256.is_some() && after.sha256.is_some() && before.sha256 != after.sha256 {
        kinds.push(ChangeKind::ContentModified);
    }
    if before.permissions() != after.permissions() {
        kinds.push(ChangeKind::PermissionModified);
    }
    if before.uid != after.uid || before.gid != after.gid {
        kinds.push(ChangeKind::OwnerModified);
    }
    if before.capabilities != after.capabilities {
        kinds.push(ChangeKind::CapabilityModified);
    }
    if before.security_label != after.security_label {
        kinds.push(ChangeKind::SecurityLabelModified);
    }
    if before.symlink_target != after.symlink_target {
        kinds.push(ChangeKind::SymlinkTargetModified);
    }
    if before.is_executable() != after.is_executable() {
        kinds.push(ChangeKind::ExecutableStatusModified);
    }
    let metadata = before.size != after.size
        || before.mtime_ns != after.mtime_ns
        || before.inode != after.inode
        || before.device != after.device;
    if metadata && kinds.is_empty() {
        kinds.push(ChangeKind::MetadataModified);
    }
    kinds
}

fn high_value(kind: FileKind) -> bool {
    matches!(
        kind,
        FileKind::ExecutableBinary
            | FileKind::SharedLibrary
            | FileKind::KernelImage
            | FileKind::KernelModule
            | FileKind::SecuritySensitive
    )
}

fn persistence(kind: FileKind) -> bool {
    matches!(kind, FileKind::ScheduledJob | FileKind::ServiceUnit)
}

/// Initial severity for a change (FR-021). The rules engine in milestone 5
/// makes this configurable.
pub fn severity(
    kinds: &[ChangeKind],
    before: Option<&FileRecord>,
    after: Option<&FileRecord>,
) -> Severity {
    let kind = after.or(before).map(|r| r.kind).unwrap_or(FileKind::Other);
    let important =
        high_value(kind) || persistence(kind) || before.is_some_and(|b| high_value(b.kind));
    kinds
        .iter()
        .map(|k| match k {
            ChangeKind::PermissionModified => {
                let gained_setid = match (before, after) {
                    (Some(b), Some(a)) => a.mode & 0o6000 & !b.mode != 0,
                    _ => false,
                };
                if gained_setid {
                    Severity::Critical
                } else if important {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            ChangeKind::CapabilityModified => {
                if after.is_some_and(|a| a.capabilities.is_some()) {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            ChangeKind::New => match kind {
                _ if persistence(kind) || kind == FileKind::KernelModule => Severity::High,
                FileKind::ExecutableBinary | FileKind::Script | FileKind::SharedLibrary => {
                    Severity::Medium
                }
                FileKind::SecuritySensitive | FileKind::Configuration => Severity::Medium,
                FileKind::Directory => Severity::Info,
                _ => Severity::Low,
            },
            ChangeKind::Missing | ChangeKind::ContentModified | ChangeKind::TypeChanged => {
                if important {
                    Severity::High
                } else if matches!(kind, FileKind::Configuration | FileKind::Script) {
                    Severity::Medium
                } else {
                    Severity::Low
                }
            }
            ChangeKind::OwnerModified
            | ChangeKind::SecurityLabelModified
            | ChangeKind::SymlinkTargetModified => {
                if important {
                    Severity::High
                } else {
                    Severity::Medium
                }
            }
            ChangeKind::ExecutableStatusModified => Severity::Medium,
            ChangeKind::MetadataModified => Severity::Info,
        })
        .max()
        .unwrap_or(Severity::Info)
}

/// Merge two path-ordered streams and report every difference.
pub fn merge<A, B, E>(
    before: A,
    after: B,
    mut on_change: impl FnMut(Change) -> Result<(), E>,
) -> Result<(), E>
where
    A: IntoIterator<Item = Result<FileRecord, E>>,
    B: IntoIterator<Item = Result<FileRecord, E>>,
{
    let mut a = before.into_iter();
    let mut b = after.into_iter();
    let mut next_a = a.next().transpose()?;
    let mut next_b = b.next().transpose()?;
    loop {
        let order = match (&next_a, &next_b) {
            (None, None) => return Ok(()),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(x), Some(y)) => rows_order(x, y),
        };
        match order {
            Ordering::Less => {
                let old = next_a.take().expect("present");
                let kinds = vec![ChangeKind::Missing];
                on_change(Change {
                    path: old.path.clone(),
                    severity: severity(&kinds, Some(&old), None),
                    kinds,
                    before: Some(old),
                    after: None,
                })?;
                next_a = a.next().transpose()?;
            }
            Ordering::Greater => {
                let new = next_b.take().expect("present");
                let kinds = vec![ChangeKind::New];
                on_change(Change {
                    path: new.path.clone(),
                    severity: severity(&kinds, None, Some(&new)),
                    kinds,
                    before: None,
                    after: Some(new),
                })?;
                next_b = b.next().transpose()?;
            }
            Ordering::Equal => {
                let old = next_a.take().expect("present");
                let new = next_b.take().expect("present");
                let kinds = diff_record(&old, &new);
                if !kinds.is_empty() {
                    on_change(Change {
                        path: new.path.clone(),
                        severity: severity(&kinds, Some(&old), Some(&new)),
                        kinds,
                        before: Some(old),
                        after: Some(new),
                    })?;
                }
                next_a = a.next().transpose()?;
                next_b = b.next().transpose()?;
            }
        }
    }
}

/// Order matching SQLite's BLOB ordering (memcmp, then length).
fn rows_order(a: &FileRecord, b: &FileRecord) -> Ordering {
    use std::os::unix::ffi::OsStrExt;
    a.path
        .as_os_str()
        .as_bytes()
        .cmp(b.path.as_os_str().as_bytes())
}

/// Summary of a change list by kind and severity.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ChangeSummary {
    pub total: u64,
    pub by_kind: std::collections::BTreeMap<ChangeKind, u64>,
    pub by_severity: std::collections::BTreeMap<Severity, u64>,
}

impl ChangeSummary {
    pub fn add(&mut self, c: &Change) {
        self.total += 1;
        for k in &c.kinds {
            *self.by_kind.entry(*k).or_default() += 1;
        }
        *self.by_severity.entry(c.severity).or_default() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria_inventory::FileType;
    use std::path::PathBuf;

    fn rec(path: &str, kind: FileKind, sha: &str, mode: u32) -> FileRecord {
        FileRecord {
            path: PathBuf::from(path),
            file_type: FileType::Regular,
            kind,
            sha256: Some(sha.into()),
            size: 10,
            uid: 0,
            gid: 0,
            mode: 0o100000 | mode,
            mtime_ns: 1,
            ctime_ns: 1,
            inode: 1,
            device: 1,
            symlink_target: None,
            capabilities: None,
            security_label: None,
            error: None,
        }
    }

    fn run(before: Vec<FileRecord>, after: Vec<FileRecord>) -> Vec<Change> {
        let mut out = Vec::new();
        merge::<_, _, ()>(before.into_iter().map(Ok), after.into_iter().map(Ok), |c| {
            out.push(c);
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn identical_sets_have_no_changes() {
        let a = vec![rec("/usr/bin/a", FileKind::ExecutableBinary, "x", 0o755)];
        assert!(run(a.clone(), a).is_empty());
    }

    #[test]
    fn detects_new_missing_and_modified() {
        let before = vec![
            rec("/etc/a", FileKind::Configuration, "1", 0o644),
            rec("/usr/bin/b", FileKind::ExecutableBinary, "2", 0o755),
            rec("/usr/bin/c", FileKind::ExecutableBinary, "3", 0o755),
        ];
        let after = vec![
            rec("/etc/a", FileKind::Configuration, "1", 0o644),
            rec("/usr/bin/b", FileKind::ExecutableBinary, "CHANGED", 0o755),
            rec("/usr/bin/d", FileKind::ExecutableBinary, "4", 0o755),
        ];
        let changes = run(before, after);
        let got: Vec<(String, Vec<ChangeKind>, Severity)> = changes
            .iter()
            .map(|c| (c.path.display().to_string(), c.kinds.clone(), c.severity))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "/usr/bin/b".into(),
                    vec![ChangeKind::ContentModified],
                    Severity::High
                ),
                (
                    "/usr/bin/c".into(),
                    vec![ChangeKind::Missing],
                    Severity::High
                ),
                ("/usr/bin/d".into(), vec![ChangeKind::New], Severity::Medium),
            ]
        );
    }

    #[test]
    fn gaining_setuid_is_critical() {
        let before = rec("/usr/bin/x", FileKind::ExecutableBinary, "1", 0o755);
        let after = rec("/usr/bin/x", FileKind::ExecutableBinary, "1", 0o4755);
        let kinds = diff_record(&before, &after);
        assert_eq!(kinds, vec![ChangeKind::PermissionModified]);
        assert_eq!(
            severity(&kinds, Some(&before), Some(&after)),
            Severity::Critical
        );
    }

    #[test]
    fn executable_status_and_owner() {
        let before = rec("/etc/x", FileKind::Configuration, "1", 0o644);
        let mut after = rec("/etc/x", FileKind::Configuration, "1", 0o755);
        after.uid = 1000;
        assert_eq!(
            diff_record(&before, &after),
            vec![
                ChangeKind::PermissionModified,
                ChangeKind::OwnerModified,
                ChangeKind::ExecutableStatusModified
            ]
        );
    }

    #[test]
    fn capabilities_labels_and_links() {
        let before = rec("/usr/bin/ping", FileKind::ExecutableBinary, "1", 0o755);
        let mut after = before.clone();
        after.capabilities = Some(vec![1, 2, 3]);
        after.security_label = Some("system_u:object_r:bin_t:s0".into());
        let kinds = diff_record(&before, &after);
        assert_eq!(
            kinds,
            vec![
                ChangeKind::CapabilityModified,
                ChangeKind::SecurityLabelModified
            ]
        );
        assert_eq!(
            severity(&kinds, Some(&before), Some(&after)),
            Severity::High
        );

        let mut l1 = before.clone();
        l1.file_type = FileType::Symlink;
        l1.symlink_target = Some("/a".into());
        let mut l2 = l1.clone();
        l2.symlink_target = Some("/tmp/evil".into());
        assert_eq!(
            diff_record(&l1, &l2),
            vec![ChangeKind::SymlinkTargetModified]
        );
    }

    #[test]
    fn metadata_only_change_is_info() {
        let before = rec("/usr/share/x", FileKind::Other, "1", 0o644);
        let mut after = before.clone();
        after.mtime_ns = 99;
        after.inode = 7;
        let kinds = diff_record(&before, &after);
        assert_eq!(kinds, vec![ChangeKind::MetadataModified]);
        assert_eq!(
            severity(&kinds, Some(&before), Some(&after)),
            Severity::Info
        );
    }

    #[test]
    fn ctime_alone_is_not_a_change() {
        let before = rec("/usr/share/x", FileKind::Other, "1", 0o644);
        let mut after = before.clone();
        after.ctime_ns = 99;
        assert!(diff_record(&before, &after).is_empty());
    }

    #[test]
    fn missing_hash_does_not_claim_content_change() {
        let before = rec("/etc/shadow", FileKind::SecuritySensitive, "1", 0o000);
        let mut after = before.clone();
        after.sha256 = None;
        assert!(diff_record(&before, &after).is_empty());
    }

    #[test]
    fn type_change_short_circuits() {
        let before = rec("/usr/bin/x", FileKind::ExecutableBinary, "1", 0o755);
        let mut after = before.clone();
        after.file_type = FileType::Symlink;
        after.symlink_target = Some("/tmp/x".into());
        assert_eq!(diff_record(&before, &after), vec![ChangeKind::TypeChanged]);
    }

    #[test]
    fn new_persistence_is_high() {
        let r = rec(
            "/etc/systemd/system/evil.service",
            FileKind::ServiceUnit,
            "1",
            0o644,
        );
        assert_eq!(severity(&[ChangeKind::New], None, Some(&r)), Severity::High);
    }

    #[test]
    fn summary_counts() {
        let changes = run(
            vec![rec("/a", FileKind::Other, "1", 0o644)],
            vec![rec("/b", FileKind::Other, "1", 0o644)],
        );
        let mut s = ChangeSummary::default();
        changes.iter().for_each(|c| s.add(c));
        assert_eq!(s.total, 2);
        assert_eq!(s.by_kind[&ChangeKind::New], 1);
        assert_eq!(s.by_kind[&ChangeKind::Missing], 1);
    }
}
