//! Account and privilege monitoring (FR-025, FR-020).
//!
//! The agent keeps a snapshot of local accounts, groups, sudo rules and SSH
//! authorized keys, and compares a fresh one with it whenever one of their
//! files changes, at start and at each reconciliation. Each difference that
//! matters for security becomes an alert (ACC-001..ACC-010); the snapshot
//! then moves on, so each change is reported once. Password hashes are
//! never read into the snapshot: only whether a password is set, empty or
//! locked.
//!
//! Limitations: only local files are read (no LDAP or SSSD), and SSH keys
//! only in the default `~/.ssh/authorized_keys` and `authorized_keys2`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use soteria_core::Severity;

/// Snapshot format; a different one is replaced without comparison.
const FORMAT: u32 = 1;

/// Meta key holding the last snapshot.
pub const SNAPSHOT_KEY: &str = "accounts_snapshot";

/// Groups whose members can become root or read secrets, besides groups
/// named in sudo rules.
pub const PRIVILEGED_GROUPS: &[&str] = &[
    "root", "wheel", "sudo", "admin", "adm", "docker", "lxd", "disk", "shadow", "libvirt",
];

/// Shells that do not allow a login.
const NO_LOGIN: &[&str] = &[
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    /// "set", "empty", "locked" or "unknown" (shadow unreadable).
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub gid: u32,
    /// Listed members, plus users with it as primary group.
    pub members: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    pub key_type: String,
    pub comment: String,
    /// The file it is in.
    pub file: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub format: u32,
    pub users: BTreeMap<String, User>,
    pub groups: BTreeMap<String, Group>,
    /// Sudo principals (`alice`, `%wheel`, `#1000`) and the file granting
    /// them.
    pub sudo: BTreeMap<String, String>,
    /// SHA256 fingerprint (as `ssh-keygen -l`) by user.
    pub ssh_keys: BTreeMap<String, BTreeMap<String, Key>>,
}

/// Where account data is read from. `root` is `/` except in tests.
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

/// A source that could not be read, reported as a coverage gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    pub path: PathBuf,
    pub detail: String,
}

impl Sources {
    fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    /// Whether a change to `path` can change the snapshot.
    pub fn is_source(&self, path: &Path) -> bool {
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return false;
        };
        let rel = Path::new("/").join(rel);
        let s = rel.to_string_lossy();
        matches!(
            s.as_ref(),
            "/etc/passwd" | "/etc/shadow" | "/etc/group" | "/etc/gshadow" | "/etc/sudoers"
        ) || s.starts_with("/etc/sudoers.d/")
            || rel
                .file_name()
                .is_some_and(|n| n == "authorized_keys" || n == "authorized_keys2")
    }

    /// Read the current state.
    pub fn snapshot(&self) -> (Snapshot, Vec<Unreadable>) {
        let mut gaps = Vec::new();
        let mut read = |p: &str| -> Option<String> {
            let path = self.path(p);
            match std::fs::read_to_string(&path) {
                Ok(t) => Some(t),
                Err(e) => {
                    gaps.push(Unreadable {
                        path,
                        detail: e.to_string(),
                    });
                    None
                }
            }
        };
        let passwd = read("/etc/passwd").unwrap_or_default();
        let shadow = read("/etc/shadow");
        let group = read("/etc/group").unwrap_or_default();

        let mut s = Snapshot {
            format: FORMAT,
            ..Snapshot::default()
        };
        let shadow_state: BTreeMap<&str, &str> = shadow
            .as_deref()
            .unwrap_or("")
            .lines()
            .filter_map(|l| {
                let mut f = l.split(':');
                Some((f.next()?, f.next()?))
            })
            .collect();
        for line in passwd.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 || f[0].is_empty() || f[0].starts_with('#') {
                continue;
            }
            let (Ok(uid), Ok(gid)) = (f[2].parse(), f[3].parse()) else {
                continue;
            };
            let password = match f[1] {
                "" => "empty".to_owned(),
                "x" if shadow.is_none() => "unknown".to_owned(),
                "x" => password_state(shadow_state.get(f[0]).copied()),
                other => password_state(Some(other)),
            };
            s.users.insert(
                f[0].to_owned(),
                User {
                    uid,
                    gid,
                    home: f[5].to_owned(),
                    shell: f[6].to_owned(),
                    password,
                },
            );
        }
        for line in group.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 4 || f[0].is_empty() || f[0].starts_with('#') {
                continue;
            }
            let Ok(gid) = f[2].parse() else { continue };
            let mut members: BTreeSet<String> = f[3]
                .split(',')
                .map(str::trim)
                .filter(|m| !m.is_empty())
                .map(str::to_owned)
                .collect();
            members.extend(
                s.users
                    .iter()
                    .filter(|(_, u)| u.gid == gid)
                    .map(|(n, _)| n.clone()),
            );
            s.groups.insert(f[0].to_owned(), Group { gid, members });
        }

        let mut seen = BTreeSet::new();
        self.read_sudoers(
            &self.path("/etc/sudoers"),
            &mut s.sudo,
            &mut seen,
            0,
            &mut gaps,
        );

        for (name, u) in &s.users {
            if u.home.is_empty() || u.home == "/" || !u.home.starts_with('/') {
                continue;
            }
            for file in ["authorized_keys", "authorized_keys2"] {
                let shown = format!("{}/.ssh/{file}", u.home.trim_end_matches('/'));
                let path = self.path(&shown);
                let text = match std::fs::read_to_string(&path) {
                    Ok(t) => t,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => continue,
                    Err(e) => {
                        gaps.push(Unreadable {
                            path,
                            detail: e.to_string(),
                        });
                        continue;
                    }
                };
                for line in text.lines() {
                    if let Some((fp, key_type, comment)) = parse_key_line(line) {
                        s.ssh_keys.entry(name.clone()).or_default().insert(
                            fp,
                            Key {
                                key_type,
                                comment,
                                file: shown.clone(),
                            },
                        );
                    }
                }
            }
        }
        (s, gaps)
    }

    fn read_sudoers(
        &self,
        path: &Path,
        out: &mut BTreeMap<String, String>,
        seen: &mut BTreeSet<PathBuf>,
        depth: u32,
        gaps: &mut Vec<Unreadable>,
    ) {
        if depth > 8 || !seen.insert(path.to_owned()) {
            return;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && depth == 0 => return,
            Err(e) => {
                gaps.push(Unreadable {
                    path: path.to_owned(),
                    detail: e.to_string(),
                });
                return;
            }
        };
        let shown = self.shown(path);
        let mut aliases: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in logical_lines(&text) {
            let line = line.trim();
            let include = ["@includedir", "#includedir", "@include", "#include"]
                .iter()
                .find_map(|kw| line.strip_prefix(kw).map(|rest| (*kw, rest.trim())));
            if let Some((kw, target)) = include
                && !target.is_empty()
            {
                let target = target.trim_matches('"');
                let target = if target.starts_with('/') {
                    self.path(target)
                } else {
                    path.parent().unwrap_or(Path::new("/")).join(target)
                };
                if kw.ends_with("dir") {
                    let mut files: Vec<PathBuf> = std::fs::read_dir(&target)
                        .map(|d| d.flatten().map(|e| e.path()).collect())
                        .unwrap_or_default();
                    files.sort();
                    for f in files {
                        // sudo skips names with a dot or ending in '~'.
                        let name = f.file_name().unwrap_or_default().to_string_lossy();
                        if name.contains('.') || name.ends_with('~') {
                            continue;
                        }
                        self.read_sudoers(&f, out, seen, depth + 1, gaps);
                    }
                } else {
                    self.read_sudoers(&target, out, seen, depth + 1, gaps);
                }
                continue;
            }
            let line = strip_comment(line);
            if line.is_empty() {
                continue;
            }
            let first = line.split_whitespace().next().unwrap_or("");
            if first.starts_with("Defaults") {
                continue;
            }
            if first == "User_Alias" {
                for def in line["User_Alias".len()..].split(':') {
                    if let Some((name, list)) = def.split_once('=') {
                        aliases.insert(
                            name.trim().to_owned(),
                            list.split(',').map(|m| m.trim().to_owned()).collect(),
                        );
                    }
                }
                continue;
            }
            if matches!(
                first,
                "Runas_Alias" | "Host_Alias" | "Cmnd_Alias" | "Cmd_Alias"
            ) {
                continue;
            }
            // A user specification: "users hosts = (runas) commands".
            if !line.contains('=') {
                continue;
            }
            let users = user_list(line);
            for u in users.split(',').map(str::trim).filter(|u| !u.is_empty()) {
                let u = u.trim_start_matches('!');
                let expanded = aliases
                    .get(u)
                    .cloned()
                    .unwrap_or_else(|| vec![u.to_owned()]);
                for p in expanded {
                    if p != "ALL" || u == "ALL" {
                        out.entry(p).or_insert_with(|| shown.clone());
                    }
                }
            }
        }
    }

    /// A path as it is on the host (without the test root).
    fn shown(&self, path: &Path) -> String {
        match path.strip_prefix(&self.root) {
            Ok(rel) => Path::new("/").join(rel).to_string_lossy().into_owned(),
            Err(_) => path.to_string_lossy().into_owned(),
        }
    }
}

fn password_state(field: Option<&str>) -> String {
    match field {
        None => "unknown",
        Some("") => "empty",
        Some(p) if p.starts_with('!') || p.starts_with('*') => "locked",
        Some(_) => "set",
    }
    .to_owned()
}

/// Lines with backslash continuations joined.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if let Some(head) = line.strip_suffix('\\') {
            cur.push_str(head);
            cur.push(' ');
        } else {
            cur.push_str(line);
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Remove a comment. `#` followed by digits is a UID, not a comment.
fn strip_comment(line: &str) -> &str {
    let b = line.as_bytes();
    for (i, c) in b.iter().enumerate() {
        if *c == b'#' && !b.get(i + 1).is_some_and(u8::is_ascii_digit) {
            return line[..i].trim();
        }
    }
    line.trim()
}

/// The user list of a user specification: everything before the first
/// whitespace that is not inside a comma-separated list.
fn user_list(line: &str) -> String {
    let mut out = String::new();
    let mut after_comma = false;
    for c in line.chars() {
        if c.is_whitespace() {
            if after_comma {
                continue;
            }
            break;
        }
        after_comma = c == ',';
        out.push(c);
    }
    out
}

/// Fingerprint, type and comment of an authorized_keys line.
fn parse_key_line(line: &str) -> Option<(String, String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let tokens: Vec<&str> = split_respecting_quotes(line);
    let pos = tokens
        .iter()
        .position(|t| t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-"))?;
    let blob = base64_decode(tokens.get(pos + 1)?)?;
    let digest = Sha256::digest(&blob);
    let fp = format!("SHA256:{}", base64_encode_nopad(&digest));
    let comment = tokens
        .get(pos + 2..)
        .map(|c| c.join(" "))
        .unwrap_or_default();
    Some((fp, tokens[pos].to_owned(), comment))
}

fn split_respecting_quotes(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = None;
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => {
                quoted = !quoted;
                start.get_or_insert(i);
            }
            c if c.is_whitespace() && !quoted => {
                if let Some(s) = start.take() {
                    out.push(&line[s..i]);
                }
            }
            _ => {
                start.get_or_insert(i);
            }
        }
    }
    if let Some(s) = start {
        out.push(&line[s..]);
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = B64.iter().position(|b| *b == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn base64_encode_nopad(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// One security-relevant difference between two snapshots.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    /// The file the change is in, so it correlates with the file alert.
    pub object: String,
    pub reason: String,
    pub evidence: Value,
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

fn can_log_in(shell: &str) -> bool {
    !NO_LOGIN.contains(&shell)
}

/// Differences that matter for security, from `old` to `new`.
pub fn compare(old: &Snapshot, new: &Snapshot) -> Vec<Finding> {
    use Severity::*;
    let mut out = Vec::new();
    let passwd = "/etc/passwd";

    for (name, u) in &new.users {
        match old.users.get(name) {
            None => {
                let sev = if u.uid == 0 { Critical } else { Medium };
                out.push(finding(
                    "ACC-001",
                    sev,
                    passwd,
                    format!(
                        "Account '{name}' was created (UID {}, GID {}, shell {}).",
                        u.uid, u.gid, u.shell
                    ),
                    json!({ "user": name, "after": u }),
                ));
                if u.uid == 0 && name != "root" {
                    out.push(uid0(name, u, None));
                }
                if u.password == "empty" {
                    out.push(empty_password(name, u));
                }
            }
            Some(o) => {
                if o.uid != u.uid || o.gid != u.gid {
                    let sev = if u.uid == 0 || u.gid == 0 {
                        Critical
                    } else {
                        High
                    };
                    out.push(finding(
                        "ACC-003",
                        sev,
                        passwd,
                        format!(
                            "Account '{name}' changed from UID {}/GID {} to UID {}/GID {}.",
                            o.uid, o.gid, u.uid, u.gid
                        ),
                        json!({ "user": name, "before": o, "after": u }),
                    ));
                    if u.uid == 0 && o.uid != 0 && name != "root" {
                        out.push(uid0(name, u, Some(o)));
                    }
                }
                if o.shell != u.shell {
                    let sev = if !can_log_in(&o.shell) && can_log_in(&u.shell) {
                        High
                    } else {
                        Medium
                    };
                    out.push(finding(
                        "ACC-007",
                        sev,
                        passwd,
                        format!(
                            "Login shell of '{name}' changed from '{}' to '{}'.",
                            o.shell, u.shell
                        ),
                        json!({ "user": name, "before": o.shell, "after": u.shell }),
                    ));
                }
                if u.password == "empty" && o.password != "empty" {
                    out.push(empty_password(name, u));
                }
            }
        }
    }
    for (name, o) in &old.users {
        if !new.users.contains_key(name) {
            out.push(finding(
                "ACC-002",
                Medium,
                passwd,
                format!("Account '{name}' (UID {}) was deleted.", o.uid),
                json!({ "user": name, "before": o }),
            ));
        }
    }

    // Groups: creation, deletion and membership of privileged ones.
    let sudo_groups: BTreeSet<&str> = new
        .sudo
        .keys()
        .filter_map(|p| p.strip_prefix('%'))
        .collect();
    for (name, g) in &new.groups {
        let privileged =
            PRIVILEGED_GROUPS.contains(&name.as_str()) || sudo_groups.contains(name.as_str());
        match old.groups.get(name) {
            None => {
                out.push(finding(
                    "ACC-010",
                    Low,
                    "/etc/group",
                    format!("Group '{name}' (GID {}) was created.", g.gid),
                    json!({ "group": name, "after": g }),
                ));
                if privileged {
                    for m in &g.members {
                        out.push(privileged_member(name, m));
                    }
                }
            }
            Some(o) => {
                if privileged {
                    for m in g.members.difference(&o.members) {
                        out.push(privileged_member(name, m));
                    }
                }
                if o.gid != g.gid {
                    out.push(finding(
                        "ACC-003",
                        if g.gid == 0 { Critical } else { High },
                        "/etc/group",
                        format!(
                            "Group '{name}' changed from GID {} to GID {}.",
                            o.gid, g.gid
                        ),
                        json!({ "group": name, "before": o.gid, "after": g.gid }),
                    ));
                }
            }
        }
    }
    for (name, o) in &old.groups {
        if !new.groups.contains_key(name) {
            out.push(finding(
                "ACC-010",
                Low,
                "/etc/group",
                format!("Group '{name}' (GID {}) was deleted.", o.gid),
                json!({ "group": name, "before": o }),
            ));
        }
    }

    for (principal, file) in &new.sudo {
        if !old.sudo.contains_key(principal) {
            let who = match principal.strip_prefix('%') {
                Some(g) => format!("members of group '{g}'"),
                None => format!("'{principal}'"),
            };
            out.push(finding(
                "ACC-006",
                High,
                file,
                format!("Sudo rights were granted to {who} in {file}."),
                json!({ "principal": principal, "file": file }),
            ));
        }
    }

    let empty = BTreeMap::new();
    for (user, keys) in &new.ssh_keys {
        let before = old.ssh_keys.get(user).unwrap_or(&empty);
        let is_root = new.users.get(user).is_some_and(|u| u.uid == 0);
        for (fp, k) in keys {
            if !before.contains_key(fp) {
                out.push(finding(
                    "ACC-008",
                    if is_root { High } else { Medium },
                    &k.file,
                    format!(
                        "SSH key {fp} ({} {}) now allows logging in as '{user}'.",
                        k.key_type, k.comment
                    ),
                    json!({ "user": user, "fingerprint": fp, "key": k }),
                ));
            }
        }
    }
    out
}

fn uid0(name: &str, u: &User, before: Option<&User>) -> Finding {
    finding(
        "ACC-004",
        Severity::Critical,
        "/etc/passwd",
        format!("Account '{name}' now has UID 0: it has full root privileges."),
        json!({ "user": name, "before": before, "after": u }),
    )
}

fn empty_password(name: &str, u: &User) -> Finding {
    let sev = if can_log_in(&u.shell) {
        Severity::High
    } else {
        Severity::Medium
    };
    finding(
        "ACC-009",
        sev,
        "/etc/shadow",
        format!("Account '{name}' has an empty password."),
        json!({ "user": name, "shell": u.shell }),
    )
}

fn privileged_member(group: &str, member: &str) -> Finding {
    finding(
        "ACC-005",
        Severity::High,
        "/etc/group",
        format!("'{member}' was added to the privileged group '{group}'."),
        json!({ "group": group, "user": member }),
    )
}

/// Keys and sudo rights removed and other changes not worth an alert, as
/// one summary for the event log.
pub fn summary(old: &Snapshot, new: &Snapshot) -> Value {
    let removed_keys: Vec<String> = old
        .ssh_keys
        .iter()
        .flat_map(|(u, ks)| {
            ks.keys()
                .filter(|fp| !new.ssh_keys.get(u).is_some_and(|n| n.contains_key(*fp)))
                .map(move |fp| format!("{u}: {fp}"))
        })
        .collect();
    let revoked_sudo: Vec<&String> = old
        .sudo
        .keys()
        .filter(|p| !new.sudo.contains_key(*p))
        .collect();
    json!({
        "users": new.users.len(),
        "groups": new.groups.len(),
        "sudo_principals": new.sudo.len(),
        "ssh_keys": new.ssh_keys.values().map(BTreeMap::len).sum::<usize>(),
        "ssh_keys_removed": removed_keys,
        "sudo_revoked": revoked_sudo,
    })
}

/// The sensor name accounts are reported under.
pub const SENSOR: &str = "users";

impl crate::Agent {
    /// Compare accounts with the last snapshot and raise alerts for
    /// security-relevant changes. The first snapshot is recorded silently.
    pub(crate) fn check_accounts(&mut self) -> crate::Result<()> {
        let Some(sources) = self.accounts.clone() else {
            return Ok(());
        };
        self.accounts_due = false;
        let (new, gaps) = sources.snapshot();
        self.close_gaps(SENSOR, &["inaccessible"])?;
        for g in &gaps {
            self.open_gap("inaccessible", SENSOR, Some(&g.path), &g.detail)?;
        }
        let conn = self.store.connection();
        let old: Option<Snapshot> = self
            .store
            .meta(SNAPSHOT_KEY)?
            .and_then(|t| serde_json::from_str(&t).ok())
            .filter(|s: &Snapshot| s.format == FORMAT);
        let stored = serde_json::to_string(&new).expect("snapshot serializes");
        let Some(old) = old else {
            crate::alerts::record_event(
                conn,
                SENSOR,
                "accounts.recorded",
                Severity::Info,
                None,
                &summary(&new, &new),
            )?;
            self.store.set_meta(SNAPSHOT_KEY, &stored)?;
            self.health(SENSOR, "running", Some(&account_detail(&new, gaps.len())));
            return Ok(());
        };
        if old == new {
            self.health(SENSOR, "running", Some(&account_detail(&new, gaps.len())));
            return Ok(());
        }
        let policy = crate::alerts::Policy {
            minimum: self.config.alerts.minimum_severity,
            rules: &self.rules,
        };
        for f in compare(&old, &new) {
            let rule = soteria_rules::builtin(f.rule);
            let raised = crate::alerts::insert(
                conn,
                crate::alerts::AlertSpec {
                    alert_type: "account",
                    rule_id: f.rule,
                    severity: f.severity,
                    hostname: &self.hostname,
                    object: &f.object,
                    reason: &f.reason,
                    recommendation: rule.recommendation,
                    evidence: json!({ "source": "accounts", "detail": f.evidence }),
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
        crate::alerts::record_event(
            conn,
            SENSOR,
            "accounts.changed",
            Severity::Info,
            None,
            &summary(&old, &new),
        )?;
        self.store.set_meta(SNAPSHOT_KEY, &stored)?;
        self.health(SENSOR, "running", Some(&account_detail(&new, gaps.len())));
        Ok(())
    }
}

fn account_detail(s: &Snapshot, gaps: usize) -> String {
    let mut d = format!(
        "{} accounts, {} groups, {} sudo principals, {} SSH keys",
        s.users.len(),
        s.groups.len(),
        s.sudo.len(),
        s.ssh_keys.values().map(BTreeMap::len).sum::<usize>()
    );
    if gaps > 0 {
        d.push_str(&format!("; {gaps} source(s) unreadable"));
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real ed25519 public key blob (any valid base64 works).
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    struct Host {
        dir: tempfile::TempDir,
    }

    impl Host {
        fn new() -> Host {
            let h = Host {
                dir: tempfile::tempdir().unwrap(),
            };
            h.write(
                "etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\n\
                 daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n\
                 alice:x:1000:1000::/home/alice:/bin/bash\n",
            );
            h.write(
                "etc/shadow",
                "root:$6$abc:19000::::::\ndaemon:*:19000::::::\nalice:!:19000::::::\n",
            );
            h.write(
                "etc/group",
                "root:x:0:\nwheel:x:10:\nalice:x:1000:\nops:x:2000:\n",
            );
            h.write(
                "etc/sudoers",
                "Defaults env_reset\nroot ALL=(ALL) ALL\n%wheel ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n",
            );
            h
        }

        fn write(&self, rel: &str, text: &str) {
            let p = self.dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }

        fn sources(&self) -> Sources {
            Sources {
                root: self.dir.path().to_owned(),
            }
        }

        fn snap(&self) -> Snapshot {
            let (s, gaps) = self.sources().snapshot();
            assert!(gaps.is_empty(), "{gaps:?}");
            s
        }
    }

    fn rules(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.rule).collect()
    }

    #[test]
    fn reads_accounts_without_password_hashes() {
        let h = Host::new();
        let s = h.snap();
        assert_eq!(s.users["root"].password, "set");
        assert_eq!(s.users["alice"].password, "locked");
        assert!(s.groups["alice"].members.contains("alice"));
        assert_eq!(s.sudo.keys().collect::<Vec<_>>(), ["%wheel", "root"]);
        assert!(!serde_json::to_string(&s).unwrap().contains("$6$"));
    }

    #[test]
    fn reports_account_changes() {
        let h = Host::new();
        let before = h.snap();
        assert!(compare(&before, &before).is_empty());
        h.write(
            "etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1::/usr/sbin:/bin/sh\n\
             alice:x:1000:1000::/home/alice:/bin/bash\n\
             toor:x:0:0::/root:/bin/bash\n\
             bob:x:1001:1001::/home/bob:/bin/bash\n",
        );
        h.write(
            "etc/shadow",
            "root:$6$abc:19000::::::\ndaemon:*:19000::::::\nalice:!:19000::::::\ntoor:::::::\nbob:!:1::::::\n",
        );
        h.write("etc/group", "root:x:0:\nwheel:x:10:alice\nalice:x:1000:\n");
        h.write("etc/sudoers.d/ops", "bob ALL=(ALL) NOPASSWD: ALL # added\n");
        h.write("etc/sudoers.d/ignored.bak", "eve ALL=(ALL) ALL\n");
        h.write(
            "home/alice/.ssh/authorized_keys",
            &format!("# comment\nfrom=\"10.0.0.1\" {KEY} alice@laptop\n"),
        );
        let after = h.snap();
        let f = compare(&before, &after);
        let r = rules(&f);
        for want in [
            "ACC-001", "ACC-004", "ACC-009", "ACC-007", "ACC-005", "ACC-006", "ACC-008", "ACC-010",
        ] {
            assert!(r.contains(&want), "{want} missing from {r:?}");
        }
        let toor = f
            .iter()
            .find(|f| f.rule == "ACC-001" && f.reason.contains("toor"))
            .unwrap();
        assert_eq!(toor.severity, Severity::Critical);
        let shell = f.iter().find(|f| f.rule == "ACC-007").unwrap();
        assert_eq!(shell.severity, Severity::High, "nologin to a shell");
        let sudo = f.iter().find(|f| f.rule == "ACC-006").unwrap();
        assert_eq!(sudo.object, "/etc/sudoers.d/ops");
        assert!(!f.iter().any(|f| f.reason.contains("eve")));
        let key = f.iter().find(|f| f.rule == "ACC-008").unwrap();
        assert_eq!(key.object, "/home/alice/.ssh/authorized_keys");
        // Matches `ssh-keygen -lf` for this key.
        assert!(key.reason.contains("SHA256:"), "{}", key.reason);
        assert!(
            f.iter()
                .any(|f| f.rule == "ACC-010" && f.reason.contains("'ops'"))
        );
        // Nothing new: nothing reported.
        assert!(compare(&after, &after).is_empty());
        let removed = compare(&after, &before);
        assert!(rules(&removed).contains(&"ACC-002"));
        assert_eq!(
            summary(&after, &before)["ssh_keys_removed"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn sources_are_recognised() {
        let h = Host::new();
        let s = h.sources();
        let p = |r: &str| h.dir.path().join(r);
        assert!(s.is_source(&p("etc/passwd")));
        assert!(s.is_source(&p("etc/sudoers.d/x")));
        assert!(s.is_source(&p("home/alice/.ssh/authorized_keys")));
        assert!(!s.is_source(&p("etc/hosts")));
    }

    #[test]
    fn sudoers_parsing_details() {
        assert_eq!(
            strip_comment("#1000 ALL=(ALL) ALL # x"),
            "#1000 ALL=(ALL) ALL"
        );
        assert_eq!(user_list("alice, bob ALL = ALL"), "alice,bob");
        let h = Host::new();
        h.write(
            "etc/sudoers.d/aliases",
            "User_Alias ADMINS = carol, %ops\nADMINS ALL=(ALL) \\\n  ALL\n",
        );
        let s = h.snap();
        assert!(s.sudo.contains_key("carol") && s.sudo.contains_key("%ops"));
        assert!(!s.sudo.contains_key("ADMINS"));
    }

    #[test]
    fn fingerprint_matches_openssh() {
        let (fp, t, c) = parse_key_line(&format!("{KEY} me@host")).unwrap();
        assert_eq!(t, "ssh-ed25519");
        assert_eq!(c, "me@host");
        // As printed by `ssh-keygen -lf` for this key.
        assert_eq!(fp, "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU");
        assert!(parse_key_line("# ssh-rsa AAAA").is_none());
        assert!(parse_key_line("garbage").is_none());
    }
}
