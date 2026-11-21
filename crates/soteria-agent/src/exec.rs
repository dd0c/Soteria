//! Execution monitoring (FR-009..FR-012): classify each program launch,
//! flag unusual locations and suspicious chains, store it, and alert.
//!
//! Classification (FR-010) of the executed program image:
//! - `trusted`: in the approved baseline, and the hash matches.
//! - `known_modified`: in the baseline, but the hash differs.
//! - `unknown`: not in the baseline (hash recorded).
//! - `suspicious`: an unusual location, deleted or memory-only program, or a
//!   suspicious parent-child chain (rationale says which).
//! - `unverified`: could not be checked (no baseline, not hashable).
//!
//! Location alone never establishes maliciousness (FR-011): it raises a
//! medium alert, and only combinations (unknown or new program, hidden
//! path) raise high.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use serde::Serialize;
use serde_json::{Value, json};
use soteria_config::{ArgumentPolicy, Execution};
use soteria_core::Severity;
use soteria_integrity::baseline;
use soteria_integrity::scan::load_file;
use soteria_inventory::inspect_path;
use soteria_sensors::audit::{ExecEvent, SENSOR};
use soteria_store::Store;

use crate::alerts::{self, AlertSpec, Raised};

/// Shells: a service starting one of these is a classic sign of command
/// injection or a web shell (FR-012).
const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "ash", "busybox",
];

/// Interpreters whose first file argument is the program actually run.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "python", "python2", "python3", "perl",
    "ruby", "php", "node", "nodejs", "lua", "tclsh", "pwsh",
];

/// Network-facing services that should not normally start shells. Matched
/// against the start of the parent's program name.
const SERVICES: &[&str] = &[
    "httpd",
    "apache2",
    "nginx",
    "lighttpd",
    "php-fpm",
    "uwsgi",
    "gunicorn",
    "java",
    "tomcat",
    "node",
    "mysqld",
    "mariadbd",
    "postgres",
    "redis-server",
    "mongod",
    "named",
    "dnsmasq",
    "vsftpd",
    "proftpd",
    "smbd",
    "cupsd",
    "exim",
    "master",
    "dovecot",
    "squid",
    "haproxy",
    "memcached",
    "rpcbind",
];

const SECRET_WORDS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api-key",
    "api_key",
    "auth",
    "credential",
    "private-key",
    "private_key",
    "access-key",
    "access_key",
];

/// How many recent processes are remembered for lineage.
const LINEAGE_CAPACITY: usize = 32_768;
const HASH_CACHE_CAPACITY: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Trusted,
    KnownModified,
    Unknown,
    Suspicious,
    Unverified,
}

impl Classification {
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::Trusted => "trusted",
            Classification::KnownModified => "known_modified",
            Classification::Unknown => "unknown",
            Classification::Suspicious => "suspicious",
            Classification::Unverified => "unverified",
        }
    }
}

/// Why a location is unusual (FR-011).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Location {
    /// Configured unusual location that contains the file.
    pub unusual_path: Option<PathBuf>,
    pub hidden: bool,
    /// File or its directory is writable by a non-root user.
    pub user_writable: bool,
    /// Created or changed within `execution.recent_change`.
    pub recently_changed: bool,
    /// The program was deleted after it started.
    pub deleted: bool,
    /// The program exists only in memory (memfd).
    pub memory_only: bool,
}

impl Location {
    fn unusual(&self) -> bool {
        self.unusual_path.is_some() || self.hidden || self.user_writable
    }

    fn reasons(&self) -> Vec<String> {
        let mut r = Vec::new();
        if let Some(p) = &self.unusual_path {
            r.push(format!("located under {}", p.display()));
        }
        if self.hidden {
            r.push("hidden path".into());
        }
        if self.user_writable {
            r.push("writable by a non-root user".into());
        }
        if self.recently_changed {
            r.push("created or changed recently".into());
        }
        if self.deleted {
            r.push("deleted from disk while running".into());
        }
        if self.memory_only {
            r.push("runs from memory only (memfd)".into());
        }
        r
    }
}

struct Hit {
    rule: &'static str,
    severity: Severity,
    object: PathBuf,
    reason: String,
    recommendation: &'static str,
    identity: Value,
}

#[derive(Debug, Clone)]
struct ProcInfo {
    row_id: i64,
    exe: Option<PathBuf>,
    comm: Option<String>,
    time_ms: i64,
}

type FileKey = (u64, u64, u64, i64, i64);

/// Result of handling one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handled {
    pub process_id: i64,
    pub classification: Classification,
    pub severity: Severity,
    pub alerts: Vec<i64>,
}

pub struct ExecMonitor {
    cfg: Execution,
    hostname: String,
    minimum: Severity,
    lineage: HashMap<u32, ProcInfo>,
    hashes: HashMap<FileKey, Option<String>>,
}

impl ExecMonitor {
    pub fn new(cfg: Execution, hostname: String, minimum: Severity) -> ExecMonitor {
        ExecMonitor {
            cfg,
            hostname,
            minimum,
            lineage: HashMap::new(),
            hashes: HashMap::new(),
        }
    }

    /// Classify, store and alert on one execution.
    pub fn handle(
        &mut self,
        store: &Store,
        baseline_version: Option<u32>,
        ev: &ExecEvent,
    ) -> crate::Result<Handled> {
        let conn = store.connection();
        let now_ms = now_ms();
        let mut rationale: Vec<String> = Vec::new();
        let mut limitations: Vec<String> = Vec::new();

        // The program image.
        let (exe, mut exe_loc) = match &ev.exe {
            Some(e) => split_exe(e),
            None => (None, Location::default()),
        };
        let cwd = ev.cwd.clone();
        let resolve = |p: &Path| match (&cwd, p.is_absolute()) {
            (Some(c), false) => c.join(p),
            _ => p.to_owned(),
        };
        let invoked = ev.path.as_deref().map(resolve);
        let script = exe
            .as_deref()
            .and_then(|e| script_path(e, invoked.as_deref(), &ev.argv, &resolve));

        let mut sha256 = None;
        if let Some(e) = &exe {
            if exe_loc.deleted || exe_loc.memory_only {
                limitations
                    .push("the program file is not on disk, so it could not be hashed".into());
            } else {
                match self.hash(conn, e) {
                    Ok(Some((h, meta))) => {
                        sha256 = h;
                        if sha256.is_none() {
                            limitations.push(format!(
                                "not hashed: larger than execution.hash_max_bytes ({} bytes)",
                                self.cfg.hash_max_bytes
                            ));
                        }
                        self.location_from_meta(e, &meta, &mut exe_loc);
                    }
                    Ok(None) => limitations
                        .push("the program file disappeared before it could be read".into()),
                    Err(err) => limitations.push(format!("cannot read the program file: {err}")),
                }
            }
            self.location_from_path(e, &mut exe_loc);
        } else {
            limitations.push("the kernel did not report the program path".into());
        }

        // Baseline classification of the program image.
        let mut baseline_sha = None;
        let mut class = match (baseline_version, &exe) {
            (None, _) => {
                limitations.push("no approved baseline to compare with".into());
                Classification::Unverified
            }
            (_, None) => Classification::Unverified,
            (Some(v), Some(e)) => match baseline::entry(store, v, e)? {
                Some(approved) => {
                    baseline_sha = approved.sha256.clone();
                    match (&approved.sha256, &sha256) {
                        (Some(a), Some(b)) if a == b => {
                            rationale.push(format!("matches approved baseline v{v}"));
                            Classification::Trusted
                        }
                        (Some(_), Some(_)) => {
                            rationale.push(format!("content differs from approved baseline v{v}"));
                            Classification::KnownModified
                        }
                        _ => Classification::Unverified,
                    }
                }
                None if sha256.is_some() => {
                    rationale.push(format!("not part of approved baseline v{v}"));
                    Classification::Unknown
                }
                None => Classification::Unverified,
            },
        };

        // A script run by an interpreter is checked by location too.
        let mut script_loc = Location::default();
        if let Some(s) = &script {
            if let Ok(meta) = std::fs::metadata(s) {
                self.location_from_meta(s, &meta, &mut script_loc);
            }
            self.location_from_path(s, &mut script_loc);
        }

        // Lineage (FR-012).
        let parent = self.parent(ev.ppid);
        let parent_name = parent
            .as_ref()
            .and_then(|p| p.exe.as_deref().and_then(base_name).or(p.comm.clone()));

        let mut hits: Vec<Hit> = Vec::new();
        let exe_path = exe
            .clone()
            .unwrap_or_else(|| PathBuf::from(ev.comm.clone().unwrap_or_default()));
        let identity = json!({ "sha256": sha256 });

        if exe_loc.deleted || exe_loc.memory_only {
            hits.push(Hit {
                rule: "EXE-003",
                severity: Severity::High,
                object: exe_path.clone(),
                reason: format!(
                    "A program ran that {}.",
                    if exe_loc.memory_only {
                        "exists only in memory (fileless execution)"
                    } else {
                        "was deleted from disk after it started"
                    }
                ),
                recommendation: "Fileless or self-deleting programs are a common way to hide malware. Inspect the process \
                     (/proc/PID/exe, maps, network connections) before it exits, and identify its parent.",
                identity: json!({ "exe": exe_path, "comm": ev.comm }),
            });
        }
        if class == Classification::KnownModified {
            hits.push(Hit {
                rule: "EXE-002",
                severity: Severity::High,
                object: exe_path.clone(),
                reason: "A program ran whose content differs from the approved baseline.".into(),
                recommendation: "Check whether a package update or administrator replaced this file (package \
                     manager logs, 'rpm -V' or 'dpkg --verify'). If the change is expected, re-baseline; otherwise \
                     treat the host as compromised.",
                identity: identity.clone(),
            });
        }
        for (path, loc, what) in [
            (Some(&exe_path), &exe_loc, "program"),
            (script.as_ref(), &script_loc, "script"),
        ] {
            let Some(path) = path else { continue };
            // "New" needs a checked verdict: an unverified program (no baseline,
            // not hashable) is not known to be unknown.
            let new_unknown = loc.recently_changed && class == Classification::Unknown;
            if !loc.unusual() && !(new_unknown && what == "program") {
                continue;
            }
            // Location alone is medium; high needs a second signal: an
            // unknown or new program in an unusual place, or a hidden path.
            let unverified_program = what == "program" && class != Classification::Trusted;
            let serious = loc.unusual() && (loc.hidden || new_unknown || unverified_program);
            let reason = if loc.unusual() {
                format!(
                    "A {what} ran from an unusual location: {}.",
                    loc.reasons().join(", ")
                )
            } else {
                format!(
                    "A {what} that is not in the approved baseline and was created or changed recently ran."
                )
            };
            hits.push(Hit {
                rule: "EXE-001",
                severity: if serious { Severity::High } else { Severity::Medium },
                object: path.clone(),
                reason,
                recommendation: "Location alone does not prove malice: developers and installers run programs from \
                     home and temporary directories. Check who started it (user, parent, terminal), what it is \
                     (hash, file type), and whether it was just downloaded.",
                identity: json!({ "sha256": if what == "program" { sha256.clone() } else { None }, "what": what }),
            });
        }
        if let (Some(parent), Some(child)) = (&parent_name, exe.as_deref().and_then(base_name))
            && is_shell(&child)
            && is_service(parent)
        {
            hits.push(Hit {
                rule: "EXE-004",
                severity: Severity::High,
                object: exe_path.clone(),
                reason: format!("The service process '{parent}' started a shell ({child})."),
                recommendation: "Network services rarely need a shell. This pattern is typical of command \
                     injection or a web shell. Review the service's access logs around this time and the \
                     shell's command line.",
                identity: json!({ "parent": parent, "child": child }),
            });
        }
        if let Some(s) = &script
            && script_loc.recently_changed
            && !script_loc.unusual()
        {
            hits.push(Hit {
                rule: "EXE-005",
                severity: Severity::Medium,
                object: s.clone(),
                reason: "An interpreter ran a script that was created or changed recently.".into(),
                recommendation: "Confirm the script change was intended (who changed it, and why). Recently \
                     modified scripts run by interpreters are a common persistence and execution technique.",
                identity: json!({ "mtime": std::fs::metadata(s).ok().map(|m| m.mtime()) }),
            });
        }

        if !hits.is_empty() && class != Classification::KnownModified {
            class = Classification::Suspicious;
        }
        for h in &hits {
            rationale.push(h.reason.trim_end_matches('.').to_owned());
        }
        let severity = hits
            .iter()
            .map(|h| h.severity)
            .max()
            .unwrap_or(match class {
                Classification::Unknown => Severity::Low,
                _ => Severity::Info,
            });

        // Store the process and its event.
        let argv = render_argv(&ev.argv, self.cfg.arguments, self.cfg.max_argument_bytes);
        let ts = ms_to_rfc3339(ev.time_ms);
        let rules: Vec<&str> = hits.iter().map(|h| h.rule).collect();
        conn.execute(
            "INSERT INTO events (ts, sensor, type, severity, path, pid, uid, data) VALUES (?1, ?2, 'process.exec', ?3, ?4, ?5, ?6, ?7)",
            params![
                ts,
                SENSOR,
                severity.as_str(),
                exe.as_deref().map(path_bytes),
                ev.pid,
                ev.uid,
                json!({
                    "classification": class.as_str(),
                    "rules": rules,
                    "comm": ev.comm,
                    "ppid": ev.ppid,
                    "auid": ev.auid,
                })
                .to_string()
            ],
        )?;
        let event_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO processes (ts, pid, ppid, uid, euid, gid, exe, sha256, comm, argv, cwd, classification,
                                    rationale, severity, sensor, event_id, auid, session, tty, path, script,
                                    parent_exe, parent_comm, parent_id, limitations, audit_serial)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                     ?21, ?22, ?23, ?24, ?25, ?26)",
            params![
                ts,
                ev.pid,
                ev.ppid,
                ev.uid,
                ev.euid,
                ev.gid,
                exe.as_deref().map(path_bytes),
                sha256,
                ev.comm,
                argv.as_ref().map(|a| a.to_string()),
                ev.cwd.as_deref().map(path_bytes),
                class.as_str(),
                serde_json::to_string(&rationale).expect("serializable"),
                severity.as_str(),
                SENSOR,
                event_id,
                ev.auid,
                ev.session,
                ev.tty,
                invoked.as_deref().map(path_bytes),
                script.as_deref().map(path_bytes),
                parent.as_ref().and_then(|p| p.exe.as_deref().map(path_bytes)),
                parent.as_ref().and_then(|p| p.comm.clone()),
                parent.as_ref().and_then(|p| (p.row_id > 0).then_some(p.row_id)),
                (!limitations.is_empty()).then(|| serde_json::to_string(&limitations).expect("serializable")),
                ev.serial as i64,
            ],
        )?;
        let process_id = conn.last_insert_rowid();
        self.remember(
            ev.pid,
            ProcInfo {
                row_id: process_id,
                exe: exe.clone(),
                comm: ev.comm.clone(),
                time_ms: now_ms,
            },
        );

        // Alerts.
        let process = json!({
            "id": process_id,
            "time": ts,
            "pid": ev.pid,
            "ppid": ev.ppid,
            "uid": ev.uid,
            "euid": ev.euid,
            "gid": ev.gid,
            "auid": ev.auid,
            "tty": ev.tty,
            "session": ev.session,
            "comm": ev.comm,
            "exe": exe.as_deref().map(lossy),
            "path": invoked.as_deref().map(lossy),
            "script": script.as_deref().map(lossy),
            "cwd": ev.cwd.as_deref().map(lossy),
            "argv": argv,
            "parent": parent.as_ref().map(|p| json!({
                "exe": p.exe.as_deref().map(lossy),
                "comm": p.comm,
                "process_id": (p.row_id > 0).then_some(p.row_id),
            })),
        });
        let mut alert_ids = Vec::new();
        for h in hits {
            let object = lossy(&h.object);
            let raised = alerts::insert(
                conn,
                AlertSpec {
                    alert_type: "execution",
                    rule_id: h.rule,
                    severity: h.severity,
                    hostname: &self.hostname,
                    object: &object,
                    reason: &h.reason,
                    recommendation: h.recommendation,
                    evidence: json!({
                        "source": "exec_event",
                        "process": process,
                        "classification": class.as_str(),
                        "rationale": rationale,
                        "limitations": limitations,
                        "sha256": sha256,
                        "baseline_sha256": baseline_sha,
                        "baseline_version": baseline_version,
                        "location": { "program": exe_loc, "script": script.as_ref().map(|_| &script_loc) },
                    }),
                    identity: h.identity,
                    event_id: Some(event_id),
                },
                self.minimum,
            )?;
            if let Raised::Created { id, .. } = raised {
                alert_ids.push(id);
            }
        }
        Ok(Handled {
            process_id,
            classification: class,
            severity,
            alerts: alert_ids,
        })
    }

    /// Hash and metadata of a program, using the inventory or a cache when
    /// the file is unchanged. `Ok(None)` when the file is gone.
    fn hash(
        &mut self,
        conn: &Connection,
        path: &Path,
    ) -> std::io::Result<Option<(Option<String>, std::fs::Metadata)>> {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let key: FileKey = (
            meta.dev(),
            meta.ino(),
            meta.size(),
            meta.mtime_nsec_total(),
            meta.ctime_nsec_total(),
        );
        if let Some(h) = self.hashes.get(&key) {
            return Ok(Some((h.clone(), meta)));
        }
        let mut sha = None;
        if let Ok(Some(rec)) = load_file(conn, path)
            && rec.inode == key.1
            && rec.size == key.2
            && rec.mtime_ns == key.3
            && rec.ctime_ns == key.4
        {
            sha = rec.sha256;
        }
        if sha.is_none() && meta.size() <= self.cfg.hash_max_bytes {
            sha = inspect_path(path)?.and_then(|r| r.sha256);
        }
        if self.hashes.len() >= HASH_CACHE_CAPACITY {
            self.hashes.clear();
        }
        self.hashes.insert(key, sha.clone());
        Ok(Some((sha, meta)))
    }

    fn location_from_path(&self, path: &Path, loc: &mut Location) {
        loc.unusual_path = self
            .cfg
            .unusual_paths
            .iter()
            .find(|u| path.starts_with(u))
            .cloned();
        loc.hidden = path.components().any(
            |c| matches!(c, std::path::Component::Normal(n) if n.as_bytes().first() == Some(&b'.')),
        );
    }

    fn location_from_meta(&self, path: &Path, meta: &std::fs::Metadata, loc: &mut Location) {
        let writable = |m: &std::fs::Metadata| m.uid() != 0 || m.mode() & 0o022 != 0;
        let dir_writable = path
            .parent()
            .and_then(|d| std::fs::metadata(d).ok())
            // A sticky world-writable directory (like /tmp) is covered by
            // unusual_paths; only its owner could replace the file.
            .is_some_and(|d| d.uid() != 0 || (d.mode() & 0o022 != 0 && d.mode() & 0o1000 == 0));
        loc.user_writable = writable(meta) || dir_writable;
        let changed = meta.ctime().max(meta.mtime());
        let age = now_ms() / 1000 - changed;
        loc.recently_changed = age >= 0 && (age as u64) < self.cfg.recent_change.0.as_secs();
    }

    fn parent(&self, ppid: u32) -> Option<ProcInfo> {
        if let Some(p) = self.lineage.get(&ppid) {
            return Some(p.clone());
        }
        // Started before the agent: ask /proc while it still exists. Reading
        // another user's exe link may be refused; the name is always readable.
        let comm = std::fs::read_to_string(format!("/proc/{ppid}/comm"))
            .ok()
            .map(|c| c.trim_end().to_owned());
        let exe = std::fs::read_link(format!("/proc/{ppid}/exe")).ok();
        (comm.is_some() || exe.is_some()).then_some(ProcInfo {
            row_id: 0,
            exe,
            comm,
            time_ms: 0,
        })
    }

    fn remember(&mut self, pid: u32, info: ProcInfo) {
        if self.lineage.len() >= LINEAGE_CAPACITY {
            let cutoff = now_ms() - Duration::from_secs(3600).as_millis() as i64;
            self.lineage.retain(|_, p| p.time_ms >= cutoff);
            if self.lineage.len() >= LINEAGE_CAPACITY {
                self.lineage.clear();
            }
        }
        self.lineage.insert(pid, info);
    }
}

trait NanoTimes {
    fn mtime_nsec_total(&self) -> i64;
    fn ctime_nsec_total(&self) -> i64;
}

impl NanoTimes for std::fs::Metadata {
    fn mtime_nsec_total(&self) -> i64 {
        self.mtime() * 1_000_000_000 + self.mtime_nsec()
    }
    fn ctime_nsec_total(&self) -> i64 {
        self.ctime() * 1_000_000_000 + self.ctime_nsec()
    }
}

/// Split the kernel's exe value into a path and deleted/memfd flags.
fn split_exe(exe: &Path) -> (Option<PathBuf>, Location) {
    let mut loc = Location::default();
    let bytes = exe.as_os_str().as_bytes();
    let bytes = match bytes.strip_suffix(b" (deleted)") {
        Some(b) => {
            loc.deleted = true;
            b
        }
        None => bytes,
    };
    if bytes.starts_with(b"/memfd:") {
        loc.memory_only = true;
        loc.deleted = false;
    }
    (Some(PathBuf::from(OsStr::from_bytes(bytes))), loc)
}

/// The script an interpreter ran, if any: either the executed path itself
/// (a `#!` script) or the interpreter's first file argument.
fn script_path(
    exe: &Path,
    invoked: Option<&Path>,
    argv: &[Vec<u8>],
    resolve: &dyn Fn(&Path) -> PathBuf,
) -> Option<PathBuf> {
    let name = base_name(exe)?;
    if let Some(inv) = invoked {
        let same = std::fs::canonicalize(inv).ok().as_deref() == Some(exe) || inv == exe;
        if !same && inv.is_file() && !is_elf(inv) {
            return Some(inv.to_owned());
        }
    }
    if !is_interpreter(&name) {
        return None;
    }
    for a in argv.iter().skip(1) {
        if a.as_slice() == b"-c" || a.as_slice() == b"-e" || a.as_slice() == b"-m" {
            return None; // inline code or a module: no script file
        }
        if a.first() == Some(&b'-') {
            continue;
        }
        let p = resolve(Path::new(OsStr::from_bytes(a)));
        return p.is_file().then_some(p);
    }
    None
}

fn is_elf(p: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && magic == *b"\x7fELF"
}

fn base_name(p: &Path) -> Option<String> {
    p.file_name().map(|n| n.to_string_lossy().into_owned())
}

/// `python3.12` -> `python3`, so versioned interpreters match.
fn strip_version(name: &str) -> &str {
    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
}

fn is_interpreter(name: &str) -> bool {
    INTERPRETERS.contains(&name) || INTERPRETERS.contains(&strip_version(name))
}

fn is_shell(name: &str) -> bool {
    SHELLS.contains(&name)
}

fn is_service(name: &str) -> bool {
    SERVICES.iter().any(|s| name.starts_with(s))
}

/// Command line as stored (NFR-011).
pub fn render_argv(argv: &[Vec<u8>], policy: ArgumentPolicy, max_bytes: usize) -> Option<Value> {
    let args: Vec<String> = match policy {
        ArgumentPolicy::None => argv
            .iter()
            .take(1)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect(),
        ArgumentPolicy::Full => argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect(),
        ArgumentPolicy::Redacted => {
            let mut out = Vec::with_capacity(argv.len());
            let mut redact_next = false;
            for a in argv {
                let a = String::from_utf8_lossy(a).into_owned();
                if redact_next {
                    out.push("[REDACTED]".to_owned());
                    redact_next = false;
                    continue;
                }
                let (r, next) = redact(&a);
                redact_next = next;
                out.push(r);
            }
            out
        }
    };
    if argv.is_empty() {
        return None;
    }
    // Cut to the byte budget, keeping whole arguments where possible.
    let mut total = 0;
    let mut kept = Vec::new();
    let mut truncated = false;
    for a in args {
        if total + a.len() > max_bytes {
            let room = max_bytes.saturating_sub(total);
            let mut end = room.min(a.len());
            while !a.is_char_boundary(end) {
                end -= 1;
            }
            if end > 0 {
                kept.push(format!("{}…", &a[..end]));
            }
            truncated = true;
            break;
        }
        total += a.len();
        kept.push(a);
    }
    if truncated {
        kept.push("[TRUNCATED]".to_owned());
    }
    Some(Value::from(kept))
}

/// Redact one argument. Returns the stored text and whether the next
/// argument is a secret value (`--password VALUE`).
fn redact(arg: &str) -> (String, bool) {
    let lower = arg.to_ascii_lowercase();
    let secretish = |s: &str| SECRET_WORDS.iter().any(|w| s.contains(w));
    // URL credentials: scheme://user:pass@host
    if let Some(scheme_end) = arg.find("://") {
        let rest = &arg[scheme_end + 3..];
        if let Some(at) = rest.find('@')
            && let Some(colon) = rest[..at].find(':')
        {
            let start = scheme_end + 3 + colon + 1;
            let end = scheme_end + 3 + at;
            return (format!("{}[REDACTED]{}", &arg[..start], &arg[end..]), false);
        }
    }
    if let Some(eq) = arg.find('=') {
        let key = &lower[..eq];
        if secretish(key) {
            return (format!("{}=[REDACTED]", &arg[..eq]), false);
        }
        return (arg.to_owned(), false);
    }
    if lower.starts_with('-') && secretish(lower.trim_start_matches('-')) {
        return (arg.to_owned(), true);
    }
    (arg.to_owned(), false)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

fn ms_to_rfc3339(ms: i64) -> String {
    use chrono::{SecondsFormat, TimeZone, Utc};
    Utc.timestamp_millis_opt(ms)
        .single()
        .map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true))
        .unwrap_or_else(soteria_store::now)
}

fn path_bytes(p: &Path) -> Vec<u8> {
    p.as_os_str().as_bytes().to_vec()
}

fn lossy(p: &Path) -> String {
    String::from_utf8_lossy(p.as_os_str().as_bytes()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<Vec<u8>> {
        a.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn redacts_secrets() {
        let v = render_argv(
            &argv(&[
                "mysql",
                "--password=hunter2",
                "--token",
                "abc",
                "-u",
                "root",
                "https://bob:pw@example.com/x",
                "DB_PASSWORD=x",
                "--verbose",
            ]),
            ArgumentPolicy::Redacted,
            4096,
        )
        .unwrap();
        assert_eq!(
            v,
            json!([
                "mysql",
                "--password=[REDACTED]",
                "--token",
                "[REDACTED]",
                "-u",
                "root",
                "https://bob:[REDACTED]@example.com/x",
                "DB_PASSWORD=[REDACTED]",
                "--verbose"
            ])
        );
        assert_eq!(
            render_argv(&argv(&["ls", "-l"]), ArgumentPolicy::None, 4096).unwrap(),
            json!(["ls"])
        );
        assert_eq!(
            render_argv(&argv(&["a", "--password=x"]), ArgumentPolicy::Full, 4096).unwrap(),
            json!(["a", "--password=x"])
        );
    }

    #[test]
    fn truncates_long_command_lines() {
        let long = "x".repeat(100);
        let v = render_argv(&argv(&["prog", &long, "more"]), ArgumentPolicy::Full, 64).unwrap();
        let a = v.as_array().unwrap();
        assert_eq!(a[0], "prog");
        assert_eq!(a[1].as_str().unwrap().chars().count(), 61);
        assert_eq!(a.last().unwrap(), "[TRUNCATED]");
    }

    #[test]
    fn exe_flags() {
        let (p, l) = split_exe(Path::new("/tmp/x (deleted)"));
        assert_eq!(p.unwrap(), Path::new("/tmp/x"));
        assert!(l.deleted && !l.memory_only);
        let (_, l) = split_exe(Path::new("/memfd:payload (deleted)"));
        assert!(l.memory_only && !l.deleted);
    }

    #[test]
    fn names() {
        assert!(is_interpreter("python3.12"));
        assert!(is_interpreter("bash"));
        assert!(!is_interpreter("ls"));
        assert!(is_service("php-fpm8.2"));
        assert!(is_service("nginx"));
        assert!(!is_service("sshd"));
        assert!(is_shell("dash"));
    }

    #[test]
    fn finds_interpreter_scripts() {
        let d = tempfile::tempdir().unwrap();
        let s = d.path().join("job.py");
        std::fs::write(&s, "print(1)\n").unwrap();
        let resolve = |p: &Path| d.path().join(p);
        let py = Path::new("/usr/bin/python3");
        assert_eq!(
            script_path(py, Some(py), &argv(&["python3", "-u", "job.py"]), &resolve),
            Some(s.clone())
        );
        assert_eq!(
            script_path(py, Some(py), &argv(&["python3", "-c", "x"]), &resolve),
            None
        );
        // A #! script executed directly: PATH is the script, exe the interpreter.
        assert_eq!(
            script_path(py, Some(&s), &argv(&["job.py"]), &resolve),
            Some(s.clone())
        );
        assert_eq!(
            script_path(
                Path::new("/usr/bin/ls"),
                None,
                &argv(&["ls", "job.py"]),
                &resolve
            ),
            None
        );
    }
}
