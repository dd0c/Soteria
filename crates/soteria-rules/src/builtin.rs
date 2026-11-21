//! The built-in rule catalogue. The detection logic lives in the agent;
//! this is what each rule means, and the text its alerts carry.

use soteria_core::Severity;

use crate::Category;

pub struct Builtin {
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    /// Fixed severity, or `None` when it depends on the object.
    pub severity: Option<Severity>,
    pub severity_note: Option<&'static str>,
    /// When the rule fires; also the alert reason for file rules.
    pub description: &'static str,
    pub recommendation: &'static str,
}

const BY_OBJECT: Option<&str> = Some(
    "depends on the object's category (critical binaries, authentication and boot files rank highest) and the kind of change",
);

pub const BUILTIN: &[Builtin] = &[
    Builtin {
        id: "FIM-001",
        title: "Object not in the approved baseline",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "Object is not part of the approved baseline.",
        recommendation: "Identify what created it and when (package install, deployment, or an unknown process). \
                         Check its owner, permissions and content; approve it into a new baseline only if authorized.",
    },
    Builtin {
        id: "FIM-002",
        title: "Baselined object missing",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "Object in the approved baseline no longer exists.",
        recommendation: "Determine whether it was removed by package maintenance or deliberately deleted. \
                         Missing security tooling or logs can indicate anti-forensics.",
    },
    Builtin {
        id: "FIM-003",
        title: "File content modified",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "File content differs from the approved baseline.",
        recommendation: "Verify package provenance (rpm -V / dpkg --verify), review change history, \
                         and determine whether this change was authorized.",
    },
    Builtin {
        id: "FIM-004",
        title: "Permissions modified",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "Permissions differ from the approved baseline.",
        recommendation: "Check for added setuid/setgid bits or write access for other users, \
                         which can enable privilege escalation.",
    },
    Builtin {
        id: "FIM-005",
        title: "Owner or group modified",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "Owner or group differs from the approved baseline.",
        recommendation: "Confirm the new owner is expected; ownership by an unprivileged user lets that user modify the file.",
    },
    Builtin {
        id: "FIM-006",
        title: "File capabilities modified",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "File capabilities differ from the approved baseline.",
        recommendation: "Review the capabilities with getcap; added capabilities grant privileges without setuid.",
    },
    Builtin {
        id: "FIM-007",
        title: "Security label modified",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "Security label (SELinux context) differs from the approved baseline.",
        recommendation: "Check the context with ls -Z and restorecon -n; a changed label can bypass MAC policy.",
    },
    Builtin {
        id: "FIM-008",
        title: "Symbolic link target modified",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "Symbolic link points somewhere other than in the approved baseline.",
        recommendation: "Inspect the new target; redirected links can substitute binaries or configuration.",
    },
    Builtin {
        id: "FIM-009",
        title: "Executable status modified",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "Executable permission changed compared with the approved baseline.",
        recommendation: "Determine why the object became (non-)executable and whether it has since been run.",
    },
    Builtin {
        id: "FIM-010",
        title: "Object type changed",
        category: Category::File,
        severity: None,
        severity_note: BY_OBJECT,
        description: "Object type changed (for example, a file replaced by a symlink).",
        recommendation: "Replacing files with links is a common way to redirect execution or reads. \
                         Inspect the new object and what it points to.",
    },
    Builtin {
        id: "FIM-011",
        title: "Metadata-only change",
        category: Category::File,
        severity: Some(Severity::Info),
        severity_note: None,
        description: "File metadata (size, time or inode) changed without a content or permission change.",
        recommendation: "Usually benign (for example, a file rewritten with identical content). \
                         Correlate with maintenance activity.",
    },
    Builtin {
        id: "EXE-001",
        title: "Program run from an unusual location",
        category: Category::Execution,
        severity: None,
        severity_note: Some(
            "medium for an unusual location (temporary, home, hidden, world-writable directories) or a new unknown \
             program; high when an unusual location combines with a hidden path, a new program, or one not in the baseline",
        ),
        description: "A program or script ran from an unusual location, or a program not in the baseline that \
                      was created or changed recently ran.",
        recommendation: "Location alone does not prove malice: developers and installers run programs from \
                         home and temporary directories. Check who started it (user, parent, terminal), what it is \
                         (hash, file type), and whether it was just downloaded.",
    },
    Builtin {
        id: "EXE-002",
        title: "Modified program executed",
        category: Category::Execution,
        severity: Some(Severity::High),
        severity_note: None,
        description: "A program ran whose content differs from the approved baseline.",
        recommendation: "Check whether a package update or administrator replaced this file (package \
                         manager logs, 'rpm -V' or 'dpkg --verify'). If the change is expected, re-baseline; otherwise \
                         treat the host as compromised.",
    },
    Builtin {
        id: "EXE-003",
        title: "Deleted or memory-only program executed",
        category: Category::Execution,
        severity: Some(Severity::High),
        severity_note: None,
        description: "A program ran that exists only in memory or was deleted from disk after it started.",
        recommendation: "Fileless or self-deleting programs are a common way to hide malware. Inspect the process \
                         (/proc/PID/exe, maps, network connections) before it exits, and identify its parent.",
    },
    Builtin {
        id: "EXE-004",
        title: "Service started a shell",
        category: Category::Execution,
        severity: Some(Severity::High),
        severity_note: None,
        description: "A network-facing service process (web, database, mail, DNS, file sharing) started a shell.",
        recommendation: "Network services rarely need a shell. This pattern is typical of command \
                         injection or a web shell. Review the service's access logs around this time and the \
                         shell's command line.",
    },
    Builtin {
        id: "EXE-005",
        title: "Recently changed script executed",
        category: Category::Execution,
        severity: Some(Severity::Medium),
        severity_note: None,
        description: "An interpreter ran a script that was created or changed recently.",
        recommendation: "Confirm the script change was intended (who changed it, and why). Recently \
                         modified scripts run by interpreters are a common persistence and execution technique.",
    },
    Builtin {
        id: "SELF-001",
        title: "Soteria's own files changed",
        category: Category::Integrity,
        severity: Some(Severity::Critical),
        severity_note: None,
        description: "One of Soteria's own files (program, configuration, rules, keys, audit rule or unit) changed.",
        recommendation: "Confirm an administrator made this change (package upgrade, configuration edit). \
                         An unexplained change may be an attempt to blind or reconfigure monitoring: check who had \
                         root access, compare with the package (rpm -V soteria / dpkg --verify soteria), and approve \
                         a new baseline only once explained.",
    },
    Builtin {
        id: "SELF-002",
        title: "Monitoring was interrupted",
        category: Category::Integrity,
        severity: Some(Severity::Medium),
        severity_note: None,
        description: "The agent did not stop cleanly last time; changes made while it was down are only found by the startup scan.",
        recommendation: "Check the journal (journalctl -u soteria) for a crash or kill around the reported time, \
                         and whether the host was rebooted. A deliberately killed agent can hide activity.",
    },
    Builtin {
        id: "INT-001",
        title: "Baseline failed verification",
        category: Category::Integrity,
        severity: Some(Severity::Critical),
        severity_note: None,
        description: "The approved baseline failed cryptographic verification.",
        recommendation: "Treat the database as tampered with until proven otherwise. Compare with an offline copy, \
                         check who had root access, and re-establish the baseline from a trusted state.",
    },
];

/// The catalogue entry for a built-in rule.
pub fn builtin(id: &str) -> &'static Builtin {
    BUILTIN
        .iter()
        .find(|b| b.id == id)
        .unwrap_or_else(|| panic!("no built-in rule {id}"))
}
