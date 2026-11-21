//! Object classification (FR-002).
//!
//! Classification combines the path, the file type and mode, and the first
//! bytes of content. Locations that matter for persistence or security win
//! over content: a shell script in `/etc/cron.daily` is a scheduled job
//! first.

use std::path::Path;

use soteria_core::FileKind;

use crate::FileType;

/// Exact files and directory prefixes treated as security-sensitive
/// (FR-019). Directory entries end with '/'.
const SECURITY_SENSITIVE: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/",
    "/etc/pam.d/",
    "/etc/security/",
    "/etc/ssh/",
    "/etc/selinux/",
    "/etc/apparmor.d/",
    "/etc/apparmor/",
    "/etc/audit/",
    "/etc/login.defs",
    "/etc/environment",
    "/etc/profile",
    "/etc/profile.d/",
    "/etc/bashrc",
    "/etc/bash.bashrc",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d/",
    "/etc/shells",
    "/etc/nsswitch.conf",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/fstab",
    "/etc/modprobe.d/",
    "/etc/modules-load.d/",
    "/etc/sysctl.conf",
    "/etc/sysctl.d/",
    "/etc/default/grub",
    "/etc/grub.d/",
    "/boot/grub/",
    "/boot/grub2/",
    "/boot/loader/",
    "/etc/firewalld/",
    "/etc/nftables.conf",
    "/etc/apt/",
    "/etc/dnf/",
    "/etc/yum.repos.d/",
    "/etc/pki/rpm-gpg/",
    "/etc/soteria/",
];

const SCHEDULED: &[&str] = &[
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
    "/etc/at.allow",
    "/etc/at.deny",
    "/var/spool/at/",
];

const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/",
    "/usr/lib/systemd/",
    "/lib/systemd/",
    "/usr/local/lib/systemd/",
    "/run/systemd/",
];

const UNIT_SUFFIXES: &[&str] = &[
    ".service",
    ".timer",
    ".socket",
    ".path",
    ".mount",
    ".automount",
    ".target",
    ".slice",
    ".scope",
    ".swap",
    ".device",
];

const BIN_DIRS: &[&str] = &[
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/libexec/",
];

fn matches(path: &str, list: &[&str]) -> bool {
    list.iter().any(|p| {
        if p.ends_with('/') {
            path.starts_with(p)
        } else {
            path == *p
        }
    })
}

/// What the first bytes of a regular file say about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    /// ELF with `e_type` ET_EXEC.
    ElfExecutable,
    /// ELF with `e_type` ET_DYN: a shared library or a PIE executable.
    ElfShared,
    ElfOther,
    Shebang,
    Unknown,
}

impl Magic {
    pub fn sniff(head: &[u8]) -> Magic {
        if head.starts_with(b"\x7fELF") {
            if head.len() < 18 {
                return Magic::ElfOther;
            }
            // e_type is a 16-bit field at offset 16; byte 5 gives endianness.
            let e_type = if head[5] == 2 {
                u16::from_be_bytes([head[16], head[17]])
            } else {
                u16::from_le_bytes([head[16], head[17]])
            };
            return match e_type {
                2 => Magic::ElfExecutable,
                3 => Magic::ElfShared,
                _ => Magic::ElfOther,
            };
        }
        if head.starts_with(b"#!") {
            return Magic::Shebang;
        }
        Magic::Unknown
    }
}

/// Classify one object.
pub fn classify(path: &Path, file_type: FileType, mode: u32, magic: Magic) -> FileKind {
    match file_type {
        FileType::Symlink => return FileKind::Symlink,
        FileType::Directory => return FileKind::Directory,
        FileType::Regular => {}
        _ => return FileKind::Other,
    }
    let p = path.to_string_lossy();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();

    if matches(&p, SECURITY_SENSITIVE) {
        return FileKind::SecuritySensitive;
    }
    if matches(&p, SCHEDULED) {
        return FileKind::ScheduledJob;
    }
    if matches(&p, UNIT_DIRS) && UNIT_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return FileKind::ServiceUnit;
    }
    if p.starts_with("/boot/") && (name.starts_with("vmlinuz") || name.starts_with("vmlinux")) {
        return FileKind::KernelImage;
    }
    if (p.starts_with("/lib/modules/") || p.starts_with("/usr/lib/modules/"))
        && [".ko", ".ko.xz", ".ko.zst", ".ko.gz"]
            .iter()
            .any(|s| name.ends_with(s))
    {
        return FileKind::KernelModule;
    }

    let executable = mode & 0o111 != 0;
    let looks_like_library = name.ends_with(".so") || name.contains(".so.");
    match magic {
        Magic::ElfExecutable => return FileKind::ExecutableBinary,
        Magic::ElfShared => {
            // PIE executables are ET_DYN too; tell them apart by location,
            // name and execute permission.
            return if looks_like_library && !matches(&p, BIN_DIRS) {
                FileKind::SharedLibrary
            } else if executable || matches(&p, BIN_DIRS) {
                FileKind::ExecutableBinary
            } else {
                FileKind::SharedLibrary
            };
        }
        Magic::Shebang => return FileKind::Script,
        Magic::ElfOther | Magic::Unknown => {}
    }

    if p.starts_with("/etc/") {
        return FileKind::Configuration;
    }
    FileKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf(e_type: u16) -> Vec<u8> {
        let mut h = b"\x7fELF\x02\x01\x01".to_vec();
        h.resize(16, 0);
        h.extend_from_slice(&e_type.to_le_bytes());
        h
    }

    fn reg(path: &str, mode: u32, head: &[u8]) -> FileKind {
        classify(Path::new(path), FileType::Regular, mode, Magic::sniff(head))
    }

    #[test]
    fn sniffs_elf_types() {
        assert_eq!(Magic::sniff(&elf(2)), Magic::ElfExecutable);
        assert_eq!(Magic::sniff(&elf(3)), Magic::ElfShared);
        assert_eq!(Magic::sniff(&elf(1)), Magic::ElfOther);
        assert_eq!(Magic::sniff(b"\x7fELF"), Magic::ElfOther);
        assert_eq!(Magic::sniff(b"#!/bin/sh\n"), Magic::Shebang);
        assert_eq!(Magic::sniff(b"hello"), Magic::Unknown);
        let mut be = b"\x7fELF\x02\x02\x01".to_vec();
        be.resize(16, 0);
        be.extend_from_slice(&2u16.to_be_bytes());
        assert_eq!(Magic::sniff(&be), Magic::ElfExecutable);
    }

    #[test]
    fn classifies_binaries_and_libraries() {
        assert_eq!(
            reg("/usr/bin/ls", 0o755, &elf(3)),
            FileKind::ExecutableBinary
        );
        assert_eq!(
            reg("/usr/bin/static", 0o755, &elf(2)),
            FileKind::ExecutableBinary
        );
        assert_eq!(
            reg("/usr/lib64/libc.so.6", 0o755, &elf(3)),
            FileKind::SharedLibrary
        );
        assert_eq!(
            reg("/usr/lib/x86_64-linux-gnu/libz.so.1.3", 0o644, &elf(3)),
            FileKind::SharedLibrary
        );
        assert_eq!(
            reg("/usr/lib/foo/helper", 0o755, &elf(3)),
            FileKind::ExecutableBinary
        );
        assert_eq!(
            reg("/usr/bin/script", 0o755, b"#!/usr/bin/python3\n"),
            FileKind::Script
        );
    }

    #[test]
    fn location_beats_content() {
        assert_eq!(
            reg("/etc/cron.daily/logrotate", 0o755, b"#!/bin/sh\n"),
            FileKind::ScheduledJob
        );
        assert_eq!(
            reg("/etc/crontab", 0o644, b"SHELL=/bin/sh"),
            FileKind::ScheduledJob
        );
        assert_eq!(reg("/etc/shadow", 0o000, b""), FileKind::SecuritySensitive);
        assert_eq!(
            reg("/etc/sudoers.d/admins", 0o440, b""),
            FileKind::SecuritySensitive
        );
        assert_eq!(
            reg("/etc/ssh/sshd_config", 0o600, b""),
            FileKind::SecuritySensitive
        );
        assert_eq!(
            reg("/etc/profile.d/x.sh", 0o644, b"#!/bin/sh"),
            FileKind::SecuritySensitive
        );
    }

    #[test]
    fn classifies_units_kernels_and_config() {
        assert_eq!(
            reg("/usr/lib/systemd/system/sshd.service", 0o644, b"[Unit]"),
            FileKind::ServiceUnit
        );
        assert_eq!(
            reg("/etc/systemd/system/backup.timer", 0o644, b"[Timer]"),
            FileKind::ServiceUnit
        );
        assert_eq!(
            reg("/etc/systemd/journald.conf", 0o644, b"[Journal]"),
            FileKind::Configuration
        );
        assert_eq!(
            reg("/boot/vmlinuz-6.12.0", 0o755, b"MZ"),
            FileKind::KernelImage
        );
        assert_eq!(
            reg("/lib/modules/6.12.0/kernel/fs/ext4.ko.xz", 0o644, b""),
            FileKind::KernelModule
        );
        assert_eq!(
            reg("/usr/lib/modules/6.12.0/kernel/x.ko", 0o644, &elf(1)),
            FileKind::KernelModule
        );
        assert_eq!(reg("/etc/hostname", 0o644, b"web"), FileKind::Configuration);
        assert_eq!(
            reg("/usr/share/doc/readme", 0o644, b"text"),
            FileKind::Other
        );
    }

    #[test]
    fn non_regular_types() {
        let p = Path::new("/usr/bin/sh");
        assert_eq!(
            classify(p, FileType::Symlink, 0o777, Magic::Unknown),
            FileKind::Symlink
        );
        assert_eq!(
            classify(p, FileType::Directory, 0o755, Magic::Unknown),
            FileKind::Directory
        );
        assert_eq!(
            classify(p, FileType::Fifo, 0o644, Magic::Unknown),
            FileKind::Other
        );
    }

    #[test]
    fn prefix_matching_respects_directories() {
        assert!(matches("/etc/ssh/sshd_config", SECURITY_SENSITIVE));
        assert!(!matches("/etc/sshguard.conf", SECURITY_SENSITIVE));
        assert!(!matches("/etc/passwd-", SECURITY_SENSITIVE));
    }
}
