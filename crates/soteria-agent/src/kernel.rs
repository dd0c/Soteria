//! Kernel, module and boot monitoring (FR-022..FR-024).
//!
//! The agent reads the running kernel's state from `/proc` and `/sys` every
//! minute and compares it with the last snapshot:
//!
//! - KRN-001: a loaded module whose file is not in the approved baseline,
//!   or that has no file for the running kernel at all;
//! - KRN-002: the kernel became tainted by a proprietary, forced,
//!   out-of-tree or unsigned module;
//! - KRN-003: the kernel command line changed (at a new boot);
//! - KRN-004: Secure Boot was on and is now off;
//! - KRN-005: a different kernel is running.
//!
//! Each boot is recorded as a `kernel.boot` event with its time, kernel,
//! command line, Secure Boot and lockdown state. Polling cannot see a
//! module that is loaded and unloaded within a minute; the taint flags it
//! leaves behind can.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use soteria_core::Severity;

use crate::accounts::{Finding, Unreadable};

const FORMAT: u32 = 1;

/// Meta key holding the last snapshot.
pub const SNAPSHOT_KEY: &str = "kernel_snapshot";

/// The sensor name kernel state is reported under.
pub const SENSOR: &str = "kernel";

/// How often the kernel's state is read.
pub const POLL: Duration = Duration::from_secs(60);

/// The EFI variable holding the Secure Boot state.
const SECURE_BOOT_VAR: &str =
    "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Taint flags worth an alert: (bit, letter, meaning).
const TAINTS: &[(u32, char, &str)] = &[
    (0, 'P', "proprietary module loaded"),
    (1, 'F', "module force-loaded"),
    (12, 'O', "out-of-tree module loaded"),
    (13, 'E', "unsigned module loaded"),
];

/// Boot parameters that weaken security, matched as `name=` prefixes or
/// whole words.
const RISKY_PARAMS: &[&str] = &[
    "init=",
    "rdinit=",
    "selinux=0",
    "enforcing=0",
    "apparmor=0",
    "security=",
    "lsm=",
    "module.sig_enforce=0",
    "audit=0",
    "ima_appraise=",
    "lockdown=",
    "mitigations=off",
    "nokaslr",
    "rd.break",
    "single",
    "emergency",
    "systemd.debug-shell",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    pub size: u64,
    /// Taint letters from /proc/modules, such as "OE".
    pub taint: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub format: u32,
    pub release: String,
    pub version: String,
    /// Kernel command line, without BOOT_IMAGE= and initrd=.
    pub cmdline: Vec<String>,
    pub boot_id: String,
    /// Boot time, RFC 3339.
    pub boot_time: Option<String>,
    /// None where the firmware is not EFI.
    pub secure_boot: Option<bool>,
    /// Active lockdown mode, where the kernel has lockdown.
    pub lockdown: Option<String>,
    pub tainted: Option<u64>,
    /// None when /proc/modules is unavailable.
    pub modules: Option<BTreeMap<String, Module>>,
    /// Kernel images in /boot and module trees in /lib/modules.
    pub installed: Vec<String>,
}

/// Where kernel state is read from. `root` is `/` except in tests.
#[derive(Debug, Clone)]
pub struct Sources {
    pub root: PathBuf,
}

impl Default for Sources {
    fn default() -> Self {
        Sources {
            root: PathBuf::from("/"),
        }
    }
}

impl Sources {
    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel.trim_start_matches('/'))
    }

    fn read(&self, rel: &str) -> std::io::Result<String> {
        std::fs::read_to_string(self.path(rel)).map(|s| s.trim_end().to_owned())
    }

    pub fn snapshot(&self) -> (Snapshot, Vec<Unreadable>) {
        let mut gaps = Vec::new();
        let mut need = |rel: &str| -> Option<String> {
            match self.read(rel) {
                Ok(s) => Some(s),
                Err(e) => {
                    gaps.push(Unreadable {
                        path: PathBuf::from("/").join(rel),
                        detail: e.to_string(),
                    });
                    None
                }
            }
        };
        let release = need("proc/sys/kernel/osrelease").unwrap_or_default();
        let version = need("proc/sys/kernel/version").unwrap_or_default();
        let cmdline = need("proc/cmdline")
            .map(|c| normalize_cmdline(&c))
            .unwrap_or_default();
        let boot_id = need("proc/sys/kernel/random/boot_id").unwrap_or_default();
        let tainted = need("proc/sys/kernel/tainted").and_then(|t| t.trim().parse().ok());
        let modules = need("proc/modules").map(|m| parse_modules(&m));
        let boot_time = self.read("proc/stat").ok().and_then(|s| {
            let secs: i64 = s
                .lines()
                .find_map(|l| l.strip_prefix("btime "))?
                .trim()
                .parse()
                .ok()?;
            chrono::DateTime::from_timestamp(secs, 0)
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        });
        // Absent on BIOS systems and without efivarfs: unknown, not off.
        let secure_boot = std::fs::read(self.path(SECURE_BOOT_VAR))
            .ok()
            .and_then(|b| b.get(4).map(|v| *v == 1));
        let lockdown = self
            .read("sys/kernel/security/lockdown")
            .ok()
            .and_then(|l| {
                let start = l.find('[')?;
                let end = l[start..].find(']')? + start;
                Some(l[start + 1..end].to_owned())
            });
        let mut installed = Vec::new();
        for (dir, keep) in [
            (
                "boot",
                &(|n: &str| n.starts_with("vmlinuz") || n.starts_with("vmlinux"))
                    as &dyn Fn(&str) -> bool,
            ),
            ("lib/modules", &(|_: &str| true) as &dyn Fn(&str) -> bool),
        ] {
            if let Ok(entries) = std::fs::read_dir(self.path(dir)) {
                for e in entries.flatten() {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if keep(&n) {
                        installed.push(format!("/{dir}/{n}"));
                    }
                }
            }
        }
        installed.sort();
        (
            Snapshot {
                format: FORMAT,
                release,
                version,
                cmdline,
                boot_id,
                boot_time,
                secure_boot,
                lockdown,
                tainted,
                modules,
                installed,
            },
            gaps,
        )
    }

    /// Module name to file (as on the host) for a kernel release, from
    /// `modules.dep`.
    pub fn module_files(&self, release: &str) -> BTreeMap<String, PathBuf> {
        let base = format!("/lib/modules/{release}");
        let Ok(dep) = self.read(&format!("{base}/modules.dep")) else {
            return BTreeMap::new();
        };
        dep.lines()
            .filter_map(|l| l.split(':').next())
            .map(|rel| {
                let file = if rel.starts_with('/') {
                    PathBuf::from(rel)
                } else {
                    PathBuf::from(&base).join(rel)
                };
                (module_name(&file), file)
            })
            .collect()
    }
}

/// A module's name from its file: `kvm-intel.ko.xz` is `kvm_intel`.
fn module_name(file: &Path) -> String {
    let n = file.file_name().unwrap_or_default().to_string_lossy();
    let stem = n.split(".ko").next().unwrap_or(&n);
    stem.replace('-', "_")
}

fn normalize_cmdline(c: &str) -> Vec<String> {
    c.split_whitespace()
        .filter(|t| !t.starts_with("BOOT_IMAGE=") && !t.starts_with("initrd="))
        .map(str::to_owned)
        .collect()
}

fn parse_modules(text: &str) -> BTreeMap<String, Module> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let name = f.next()?.to_owned();
            let size = f.next()?.parse().ok()?;
            // Taint letters come last, in parentheses: "(OE)".
            let taint = l
                .rsplit_once('(')
                .and_then(|(_, t)| t.strip_suffix(')'))
                .filter(|t| t.chars().all(|c| c.is_ascii_uppercase()))
                .unwrap_or("")
                .to_owned();
            Some((name, Module { size, taint }))
        })
        .collect()
}

fn is_risky(param: &str) -> bool {
    RISKY_PARAMS.iter().any(|r| {
        if r.ends_with('=') {
            param.starts_with(r)
        } else {
            param == *r
        }
    })
}

fn finding(
    rule: &'static str,
    severity: Severity,
    object: &str,
    reason: String,
    evidence: Value,
) -> Finding {
    Finding {
        rule,
        severity,
        object: object.to_owned(),
        reason,
        evidence,
    }
}

/// Paths a baselined module file may be recorded under (merged /usr).
fn baselined(file: &Path, baseline: &BTreeSet<PathBuf>) -> bool {
    if baseline.contains(file) {
        return true;
    }
    file.strip_prefix("/lib")
        .map(|rel| baseline.contains(&Path::new("/usr/lib").join(rel)))
        .unwrap_or(false)
}

/// Differences that matter for security. `baseline` holds the module files
/// in the approved baseline; without one, KRN-001 only reports modules with
/// no file at all.
pub fn compare(
    old: Option<&Snapshot>,
    new: &Snapshot,
    files: &BTreeMap<String, PathBuf>,
    baseline: Option<&BTreeSet<PathBuf>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let object = format!("kernel:{}", new.release);

    if let Some(loaded) = &new.modules {
        let before = old.and_then(|o| o.modules.as_ref());
        for (name, m) in loaded {
            if before.is_some_and(|b| b.contains_key(name)) {
                continue;
            }
            let problem = match files.get(name) {
                None if files.is_empty() => None, // no modules.dep: cannot tell
                None => Some(format!(
                    "Kernel module '{name}' is loaded but has no module file for kernel {}.",
                    new.release
                )),
                Some(f) => match baseline {
                    Some(b) if !baselined(f, b) => Some(format!(
                        "Kernel module '{name}' was loaded from {}, which is not in the approved baseline.",
                        f.display()
                    )),
                    _ => None,
                },
            };
            if let Some(reason) = problem {
                let file = files.get(name);
                out.push(finding(
                    "KRN-001",
                    Severity::High,
                    &file.map(|f| f.display().to_string()).unwrap_or_else(|| format!("module:{name}")),
                    reason,
                    json!({ "module": name, "file": file, "size": m.size, "taint": m.taint, "release": new.release }),
                ));
            }
        }
    }

    if let Some(t) = new.tainted {
        let was = old.and_then(|o| o.tainted).unwrap_or(0);
        let added: Vec<String> = TAINTS
            .iter()
            .filter(|(bit, _, _)| t & (1 << bit) != 0 && was & (1 << bit) == 0)
            .map(|(_, letter, what)| format!("{letter} ({what})"))
            .collect();
        if !added.is_empty() {
            let modules: Vec<&String> = new
                .modules
                .iter()
                .flatten()
                .filter(|(_, m)| !m.taint.is_empty())
                .map(|(n, _)| n)
                .collect();
            out.push(finding(
                "KRN-002",
                Severity::High,
                &object,
                format!("The kernel is now tainted: {}.", added.join(", ")),
                json!({ "tainted": t, "previous": was, "flags": added, "tainting_modules": modules }),
            ));
        }
    }

    let Some(old) = old else { return out };

    if old.cmdline != new.cmdline {
        let added: Vec<&String> = new
            .cmdline
            .iter()
            .filter(|p| !old.cmdline.contains(p))
            .collect();
        let removed: Vec<&String> = old
            .cmdline
            .iter()
            .filter(|p| !new.cmdline.contains(p))
            .collect();
        let risky: Vec<&&String> = added.iter().filter(|p| is_risky(p)).collect();
        let mut reason = "The kernel command line changed".to_owned();
        if !added.is_empty() {
            reason.push_str(&format!("; added: {}", join(&added)));
        }
        if !removed.is_empty() {
            reason.push_str(&format!("; removed: {}", join(&removed)));
        }
        reason.push('.');
        out.push(finding(
            "KRN-003",
            if risky.is_empty() {
                Severity::Medium
            } else {
                Severity::High
            },
            "/proc/cmdline",
            reason,
            json!({ "before": old.cmdline, "after": new.cmdline, "weakening": risky }),
        ));
    }
    if old.secure_boot == Some(true) && new.secure_boot == Some(false) {
        out.push(finding(
            "KRN-004",
            Severity::High,
            "secure_boot",
            "Secure Boot was enabled at an earlier boot and is now disabled.".into(),
            json!({ "boot_id": new.boot_id, "boot_time": new.boot_time }),
        ));
    }
    if !old.release.is_empty() && old.release != new.release {
        out.push(finding(
            "KRN-005",
            Severity::Low,
            &object,
            format!(
                "The running kernel changed from {} to {}.",
                old.release, new.release
            ),
            json!({ "before": old.release, "after": new.release, "version": new.version }),
        ));
    }
    out
}

fn join(v: &[&String]) -> String {
    v.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")
}

/// The boot record (FR-024).
pub fn boot_record(s: &Snapshot) -> Value {
    json!({
        "boot_id": s.boot_id,
        "boot_time": s.boot_time,
        "release": s.release,
        "version": s.version,
        "cmdline": s.cmdline,
        "secure_boot": s.secure_boot,
        "lockdown": s.lockdown,
        "tainted": s.tainted,
        "modules": s.modules.as_ref().map(BTreeMap::len),
        "installed": s.installed,
    })
}

/// Module files in the approved baseline.
fn baseline_modules(
    store: &soteria_store::Store,
    version: u32,
) -> crate::Result<BTreeSet<PathBuf>> {
    Ok(soteria_integrity::baseline::entry_paths(
        store,
        version,
        &[soteria_core::FileKind::KernelModule],
    )?
    .into_iter()
    .collect())
}

/// What `soteria scan --kernel` shows: the current state and how it differs
/// from what the agent last recorded. Nothing is recorded or alerted.
#[derive(Debug, Serialize)]
pub struct Review {
    pub current: Snapshot,
    /// The agent has recorded kernel state before.
    pub recorded: bool,
    pub findings: Vec<Finding>,
    pub unreadable: Vec<String>,
}

pub fn review(
    store: &soteria_store::Store,
    sources: &Sources,
    baseline_version: Option<u32>,
) -> crate::Result<Review> {
    let (current, gaps) = sources.snapshot();
    let old: Option<Snapshot> = store
        .meta(SNAPSHOT_KEY)?
        .and_then(|t| serde_json::from_str(&t).ok())
        .filter(|s: &Snapshot| s.format == FORMAT);
    let files = sources.module_files(&current.release);
    let baseline = match baseline_version {
        Some(v) => Some(baseline_modules(store, v)?),
        None => None,
    };
    let findings = compare(old.as_ref(), &current, &files, baseline.as_ref());
    Ok(Review {
        recorded: old.is_some(),
        current,
        findings,
        unreadable: gaps
            .iter()
            .map(|g| format!("{}: {}", g.path.display(), g.detail))
            .collect(),
    })
}

impl crate::Agent {
    /// Read kernel state, record a new boot, and raise alerts for changes.
    pub(crate) fn check_kernel(&mut self) -> crate::Result<()> {
        let Some(sources) = self.kernel.clone() else {
            return Ok(());
        };
        let (new, gaps) = sources.snapshot();
        self.close_gaps(SENSOR, &["inaccessible"])?;
        for g in &gaps {
            self.open_gap("inaccessible", SENSOR, Some(&g.path), &g.detail)?;
        }
        let old: Option<Snapshot> = self
            .store
            .meta(SNAPSHOT_KEY)?
            .and_then(|t| serde_json::from_str(&t).ok())
            .filter(|s: &Snapshot| s.format == FORMAT);
        let conn = self.store.connection();
        if old.as_ref().is_none_or(|o| o.boot_id != new.boot_id) {
            crate::alerts::record_event(
                conn,
                SENSOR,
                "kernel.boot",
                Severity::Info,
                None,
                &boot_record(&new),
            )?;
        }
        if old.as_ref() != Some(&new) {
            let files = sources.module_files(&new.release);
            let baseline = match self.baseline {
                Some(v) => Some(baseline_modules(&self.store, v)?),
                None => None,
            };
            let policy = crate::alerts::Policy {
                minimum: self.config.alerts.minimum_severity,
                rules: &self.rules,
            };
            for f in compare(old.as_ref(), &new, &files, baseline.as_ref()) {
                let rule = soteria_rules::builtin(f.rule);
                let raised = crate::alerts::insert(
                    conn,
                    crate::alerts::AlertSpec {
                        alert_type: "kernel",
                        rule_id: f.rule,
                        severity: f.severity,
                        hostname: &self.hostname,
                        object: &f.object,
                        reason: &f.reason,
                        recommendation: rule.recommendation,
                        evidence: json!({ "source": "kernel", "detail": f.evidence }),
                        identity: f.evidence.clone(),
                        event_id: None,
                    },
                    policy,
                )?;
                if let crate::alerts::Raised::Created { id, .. } = raised
                    && self.config.alerts.journal
                {
                    tracing::warn!(
                        alert = id,
                        rule = f.rule,
                        "ALERT {id} [{}] {}",
                        f.severity.as_str().to_uppercase(),
                        f.reason
                    );
                }
            }
            let stored = serde_json::to_string(&new).expect("snapshot serializes");
            self.store.set_meta(SNAPSHOT_KEY, &stored)?;
        }
        let (state, detail) = if new.modules.is_none() {
            (
                "degraded",
                "loaded modules cannot be read (/proc/modules)".to_owned(),
            )
        } else {
            (
                "running",
                format!(
                    "kernel {}, {} modules loaded, Secure Boot {}",
                    new.release,
                    new.modules.as_ref().map_or(0, BTreeMap::len),
                    match new.secure_boot {
                        Some(true) => "on",
                        Some(false) => "off",
                        None => "unknown",
                    }
                ),
            )
        };
        self.health(SENSOR, state, Some(&detail));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Host(tempfile::TempDir);

    impl Host {
        fn new() -> Host {
            let h = Host(tempfile::tempdir().unwrap());
            h.write("proc/sys/kernel/osrelease", "6.1.0-test\n");
            h.write("proc/sys/kernel/version", "#1 SMP\n");
            h.write(
                "proc/cmdline",
                "BOOT_IMAGE=/vmlinuz-6.1.0-test root=/dev/sda1 ro quiet\n",
            );
            h.write("proc/sys/kernel/random/boot_id", "b1\n");
            h.write("proc/sys/kernel/tainted", "0\n");
            h.write("proc/stat", "cpu 1 2 3\nbtime 1795285908\n");
            h.write(
                "proc/modules",
                "xfs 1000 1 - Live 0x0000000000000000\next4 2000 2 - Live 0x0000000000000000\n",
            );
            h.write(
                "lib/modules/6.1.0-test/modules.dep",
                "kernel/fs/xfs/xfs.ko.xz:\nkernel/fs/ext4/ext4.ko.zst: kernel/fs/jbd2/jbd2.ko\n",
            );
            h.write("boot/vmlinuz-6.1.0-test", "");
            h.write(
                "sys/kernel/security/lockdown",
                "[none] integrity confidentiality\n",
            );
            h.write_bytes(SECURE_BOOT_VAR, &[6, 0, 0, 0, 1]);
            h
        }
        fn write(&self, rel: &str, text: &str) {
            self.write_bytes(rel, text.as_bytes());
        }
        fn write_bytes(&self, rel: &str, b: &[u8]) {
            let p = self.0.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b).unwrap();
        }
        fn snap(&self) -> Snapshot {
            Sources {
                root: self.0.path().to_owned(),
            }
            .snapshot()
            .0
        }
        fn files(&self, release: &str) -> BTreeMap<String, PathBuf> {
            Sources {
                root: self.0.path().to_owned(),
            }
            .module_files(release)
        }
    }

    fn rules(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.rule).collect()
    }

    #[test]
    fn reads_kernel_state() {
        let h = Host::new();
        let s = h.snap();
        assert_eq!(s.release, "6.1.0-test");
        assert_eq!(s.cmdline, ["root=/dev/sda1", "ro", "quiet"]);
        assert_eq!(s.boot_time.as_deref(), Some("2026-11-21T18:31:48Z"));
        assert_eq!(s.secure_boot, Some(true));
        assert_eq!(s.lockdown.as_deref(), Some("none"));
        assert_eq!(s.modules.as_ref().unwrap().len(), 2);
        assert_eq!(
            s.installed,
            ["/boot/vmlinuz-6.1.0-test", "/lib/modules/6.1.0-test"]
        );
        let files = h.files("6.1.0-test");
        assert_eq!(
            files["ext4"],
            PathBuf::from("/lib/modules/6.1.0-test/kernel/fs/ext4/ext4.ko.zst")
        );
    }

    #[test]
    fn unknown_modules_taint_and_boot_changes_are_reported() {
        let h = Host::new();
        let files = h.files("6.1.0-test");
        let base: BTreeSet<PathBuf> = files.values().cloned().collect();
        let first = h.snap();
        assert!(compare(None, &first, &files, Some(&base)).is_empty());

        // An out-of-tree, unsigned module loaded from nowhere.
        h.write(
            "proc/modules",
            "xfs 1000 1 - Live 0x0\next4 2000 2 - Live 0x0\nhidepid 300 0 - Live 0x0 (OE)\n",
        );
        h.write(
            "proc/sys/kernel/tainted",
            &format!("{}\n", (1 << 12) | (1 << 13)),
        );
        let second = h.snap();
        let f = compare(Some(&first), &second, &files, Some(&base));
        assert_eq!(rules(&f), ["KRN-001", "KRN-002"]);
        assert!(f[0].reason.contains("no module file"));
        assert!(f[1].reason.contains("O (out-of-tree") && f[1].reason.contains("E (unsigned"));
        // Same state again: nothing new.
        assert!(compare(Some(&second), &second, &files, Some(&base)).is_empty());

        // A module whose file is not in the baseline.
        let mut smaller = base.clone();
        smaller.remove(&files["xfs"]);
        let f = compare(None, &first, &files, Some(&smaller));
        assert_eq!(rules(&f), ["KRN-001"]);
        // Merged /usr: recorded under /usr/lib.
        let usr: BTreeSet<PathBuf> = base
            .iter()
            .map(|p| Path::new("/usr").join(p.strip_prefix("/").unwrap()))
            .collect();
        assert!(compare(None, &first, &files, Some(&usr)).is_empty());

        // Next boot: new kernel, SELinux off, Secure Boot off.
        h.write("proc/sys/kernel/osrelease", "6.2.0-test\n");
        h.write("proc/sys/kernel/random/boot_id", "b2\n");
        h.write(
            "proc/cmdline",
            "BOOT_IMAGE=/vmlinuz-6.2.0-test root=/dev/sda1 ro selinux=0\n",
        );
        h.write_bytes(SECURE_BOOT_VAR, &[6, 0, 0, 0, 0]);
        let third = h.snap();
        let f = compare(Some(&second), &third, &BTreeMap::new(), Some(&base));
        assert_eq!(rules(&f), ["KRN-003", "KRN-004", "KRN-005"]);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].reason.contains("added: selinux=0") && f[0].reason.contains("removed: quiet"));
    }

    #[test]
    fn parses_module_names_and_taints() {
        assert_eq!(module_name(Path::new("a/kvm-intel.ko.xz")), "kvm_intel");
        let m = parse_modules("nvidia 100 0 - Live 0x0 (POE)\nloop 5 0 - Live 0x0\n");
        assert_eq!(m["nvidia"].taint, "POE");
        assert_eq!(m["loop"].taint, "");
        assert!(is_risky("init=/bin/sh") && is_risky("single") && !is_risky("singleuser"));
    }
}
