//! Execution sensor based on the kernel audit multicast stream (FR-009).
//!
//! The daemon joins the read-only audit multicast group, which needs only
//! `CAP_AUDIT_READ` and coexists with `auditd`. The kernel only reports
//! executions when an audit rule asks for them; that rule ships as
//! `/etc/audit/rules.d/soteria.rules` and is loaded by auditd. Without it the
//! stream carries no executions, which the agent detects with a self-test
//! and reports as a coverage gap.
//!
//! Records of one audit event (SYSCALL, EXECVE, CWD, PATH, ...) share a
//! serial number and end with an EOE record. The sensor assembles them into
//! one [`ExecEvent`] per successful execve/execveat.
//!
//! Loss is never silent (NFR-006): a full socket buffer (ENOBUFS) and a full
//! agent queue are counted in [`AuditStats`].

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_AUDIT};
use serde::Serialize;

/// Sensor name used in health records and events.
pub const SENSOR: &str = "execution";

/// Audit multicast group for read-only listeners (AUDIT_NLGRP_READLOG).
const AUDIT_NLGRP_READLOG: u32 = 1;

const AUDIT_SYSCALL: u16 = 1300;
const AUDIT_PATH: u16 = 1302;
const AUDIT_CWD: u16 = 1307;
const AUDIT_EXECVE: u16 = 1309;
const AUDIT_EOE: u16 = 1320;

/// Events whose EOE never arrives are emitted after this long.
const STALE_AFTER: Duration = Duration::from_secs(2);
/// Bound on events being assembled, in case of a flood of partial events.
const MAX_PENDING: usize = 4096;
/// Requested socket receive buffer (capped by net.core.rmem_max).
const RECV_BUFFER: usize = 8 << 20;

/// One successful program execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecEvent {
    /// Event time from the kernel, milliseconds since the epoch.
    pub time_ms: i64,
    pub serial: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    /// Login UID (who logged in, unchanged by su/sudo); `None` when unset.
    pub auid: Option<u32>,
    pub session: Option<u32>,
    pub tty: Option<String>,
    pub comm: Option<String>,
    /// The program image the kernel loaded (the interpreter, for scripts).
    pub exe: Option<PathBuf>,
    /// The path that was executed, as given (PATH item 0), possibly relative.
    pub path: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    pub argv: Vec<Vec<u8>>,
    /// The audit rule key(s) that matched.
    pub key: Option<String>,
}

/// Counters shared with the agent. All monotonic.
#[derive(Debug, Default)]
pub struct AuditStats {
    /// Execution events assembled.
    pub received: AtomicU64,
    /// Events dropped because the agent queue was full.
    pub dropped: AtomicU64,
    /// Socket buffer overruns (ENOBUFS): the kernel dropped records.
    pub kernel_overflows: AtomicU64,
    /// Audit events that were not executions (other rules on the host).
    pub other_records: AtomicU64,
    pub running: AtomicBool,
    pub failure: Mutex<Option<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AuditSnapshot {
    pub received: u64,
    pub dropped: u64,
    pub kernel_overflows: u64,
    pub other_records: u64,
    pub running: bool,
    pub failure: Option<String>,
}

impl AuditStats {
    pub fn snapshot(&self) -> AuditSnapshot {
        AuditSnapshot {
            received: self.received.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            kernel_overflows: self.kernel_overflows.load(Ordering::Relaxed),
            other_records: self.other_records.load(Ordering::Relaxed),
            running: self.running.load(Ordering::Relaxed),
            failure: self.failure.lock().map(|f| f.clone()).unwrap_or(None),
        }
    }
}

/// Join the audit multicast group. Fails without `CAP_AUDIT_READ` or when
/// the kernel has no audit support.
pub fn open() -> std::io::Result<Socket> {
    let mut socket = Socket::new(NETLINK_AUDIT)?;
    socket.bind(&SocketAddr::new(0, AUDIT_NLGRP_READLOG))?;
    // Best effort: a bigger buffer absorbs bursts (e.g. a build with many
    // short-lived processes). Overruns are still counted.
    let _ = socket.set_rx_buf_sz(RECV_BUFFER);
    socket.set_non_blocking(true)?;
    Ok(socket)
}

/// Read the audit stream on a thread until `stop` is set.
pub fn spawn(
    socket: Socket,
    tx: SyncSender<ExecEvent>,
    stop: Arc<AtomicBool>,
    stats: Arc<AuditStats>,
) -> std::io::Result<JoinHandle<()>> {
    stats.running.store(true, Ordering::Relaxed);
    std::thread::Builder::new()
        .name("sensor-exec".into())
        .spawn(move || {
            let result = run(&socket, &tx, &stop, &stats);
            if let Err(e) = result
                && let Ok(mut f) = stats.failure.lock()
            {
                *f = Some(format!("audit stream read failed: {e}"));
            }
            stats.running.store(false, Ordering::Relaxed);
        })
}

fn run(
    socket: &Socket,
    tx: &SyncSender<ExecEvent>,
    stop: &AtomicBool,
    stats: &AuditStats,
) -> std::io::Result<()> {
    let mut assembler = Assembler::default();
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    while !stop.load(Ordering::Relaxed) {
        buf.clear();
        match socket.recv(&mut buf, 0) {
            Ok(_) => {
                for (msg_type, payload) in netlink_messages(&buf) {
                    for done in assembler.push(msg_type, payload, Instant::now()) {
                        deliver(done, tx, stats);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                for done in assembler.expire(Instant::now()) {
                    deliver(done, tx, stats);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
                stats.kernel_overflows.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// ENOBUFS on Linux (the same on every architecture Soteria supports).
const ENOBUFS: i32 = 105;

fn deliver(done: Assembled, tx: &SyncSender<ExecEvent>, stats: &AuditStats) {
    match done {
        Assembled::Exec(ev) => {
            stats.received.fetch_add(1, Ordering::Relaxed);
            match tx.try_send(*ev) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
        Assembled::Other => {
            stats.other_records.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Split a netlink datagram into (type, payload) messages.
pub fn netlink_messages(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        if len < 16 {
            break;
        }
        let end = (off + len).min(buf.len());
        out.push((ty, &buf[off + 16..end]));
        off += (len + 3) & !3;
    }
    out
}

/// Result of assembling one audit event.
#[derive(Debug, PartialEq, Eq)]
pub enum Assembled {
    Exec(Box<ExecEvent>),
    Other,
}

#[derive(Debug, Default)]
struct Partial {
    started: Option<Instant>,
    time_ms: i64,
    serial: u64,
    is_exec: bool,
    syscall: Option<Fields>,
    cwd: Option<Vec<u8>>,
    path0: Option<Vec<u8>>,
    args: Args,
}

#[derive(Debug, Default)]
struct Args {
    argc: Option<usize>,
    /// Argument index -> chunks (index -> bytes); whole arguments use chunk 0.
    parts: BTreeMap<usize, BTreeMap<usize, Vec<u8>>>,
}

/// Groups audit records by serial and emits completed events.
#[derive(Debug, Default)]
pub struct Assembler {
    pending: BTreeMap<u64, Partial>,
}

impl Assembler {
    /// Feed one record. Returns events completed by it.
    pub fn push(&mut self, msg_type: u16, payload: &[u8], now: Instant) -> Vec<Assembled> {
        let text = trim_nul(payload);
        let Some((time_ms, serial, body)) = parse_header(text) else {
            return Vec::new();
        };
        if msg_type == AUDIT_EOE {
            let mut out: Vec<Assembled> = self
                .pending
                .remove(&serial)
                .map(finish)
                .into_iter()
                .collect();
            out.extend(self.expire(now));
            return out;
        }
        let mut out = Vec::new();
        if !self.pending.contains_key(&serial) && self.pending.len() >= MAX_PENDING {
            // Emit the oldest rather than growing without bound.
            if let Some((_, p)) = self.pending.pop_first() {
                out.push(finish(p));
            }
        }
        let p = self.pending.entry(serial).or_insert_with(|| Partial {
            started: Some(now),
            time_ms,
            serial,
            ..Partial::default()
        });
        match msg_type {
            AUDIT_SYSCALL => p.syscall = Some(parse_fields(body)),
            AUDIT_EXECVE => {
                p.is_exec = true;
                p.args.add(&parse_fields(body));
            }
            AUDIT_CWD => p.cwd = parse_fields(body).string("cwd"),
            AUDIT_PATH => {
                let f = parse_fields(body);
                if f.raw("item") == Some(b"0".as_slice()) {
                    p.path0 = f.string("name");
                }
            }
            _ => {}
        }
        out
    }

    /// Emit events whose EOE has not arrived in time.
    pub fn expire(&mut self, now: Instant) -> Vec<Assembled> {
        let stale: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                p.started
                    .is_some_and(|s| now.duration_since(s) >= STALE_AFTER)
            })
            .map(|(k, _)| *k)
            .collect();
        stale
            .into_iter()
            .filter_map(|k| self.pending.remove(&k))
            .map(finish)
            .collect()
    }
}

fn finish(p: Partial) -> Assembled {
    let Some(sys) = p.syscall.filter(|_| p.is_exec) else {
        return Assembled::Other;
    };
    if sys.raw("success") == Some(b"no".as_slice()) {
        return Assembled::Other;
    }
    let num = |k: &str| sys.number(k);
    let path = |b: Vec<u8>| PathBuf::from(OsString::from_vec(b));
    Assembled::Exec(Box::new(ExecEvent {
        time_ms: p.time_ms,
        serial: p.serial,
        pid: num("pid").unwrap_or_default(),
        ppid: num("ppid").unwrap_or_default(),
        uid: num("uid").unwrap_or_default(),
        euid: num("euid").unwrap_or_default(),
        gid: num("gid").unwrap_or_default(),
        auid: num("auid").filter(|a| *a != u32::MAX),
        session: num("ses").filter(|s| *s != u32::MAX),
        tty: sys
            .raw("tty")
            .filter(|t| *t != b"(none)")
            .map(|t| String::from_utf8_lossy(t).into_owned()),
        comm: sys
            .string("comm")
            .map(|c| String::from_utf8_lossy(&c).into_owned()),
        exe: sys.string("exe").map(path),
        path: p.path0.map(path),
        cwd: p.cwd.map(path),
        argv: p.args.finish(),
        key: sys
            .string("key")
            .map(|k| String::from_utf8_lossy(&k).replace('\u{1}', ",")),
    }))
}

impl Args {
    fn add(&mut self, f: &Fields) {
        for (k, v) in &f.0 {
            if k == "argc" {
                self.argc = std::str::from_utf8(v).ok().and_then(|s| s.parse().ok());
                continue;
            }
            let Some(rest) = k.strip_prefix('a') else {
                continue;
            };
            if rest.ends_with("_len") {
                continue;
            }
            let (idx, chunk) = match rest.split_once('[') {
                Some((i, c)) => (i, c.trim_end_matches(']').parse::<usize>().ok()),
                None => (rest, Some(0)),
            };
            let (Ok(idx), Some(chunk)) = (idx.parse::<usize>(), chunk) else {
                continue;
            };
            self.parts.entry(idx).or_default().insert(chunk, decode(v));
        }
    }

    fn finish(self) -> Vec<Vec<u8>> {
        let n = self
            .argc
            .unwrap_or_else(|| self.parts.keys().next_back().map(|k| k + 1).unwrap_or(0));
        let mut parts = self.parts;
        (0..n)
            .map(|i| {
                parts
                    .remove(&i)
                    .map(|c| c.into_values().flatten().collect())
                    .unwrap_or_default()
            })
            .collect()
    }
}

fn trim_nul(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    &b[..end]
}

/// Parse `audit(1700000000.123:42): rest` into (ms, serial, rest).
pub fn parse_header(text: &[u8]) -> Option<(i64, u64, &[u8])> {
    let text = text.strip_prefix(b"audit(")?;
    let close = text.iter().position(|&c| c == b')')?;
    let inner = std::str::from_utf8(&text[..close]).ok()?;
    let (ts, serial) = inner.split_once(':')?;
    let (secs, millis) = ts.split_once('.').unwrap_or((ts, "0"));
    let ms = secs.parse::<i64>().ok()? * 1000 + millis.parse::<i64>().ok()?;
    let rest = text[close + 1..]
        .strip_prefix(b":")
        .unwrap_or(&text[close + 1..]);
    Some((ms, serial.parse().ok()?, rest))
}

/// Raw `key=value` pairs of one record, values still encoded.
#[derive(Debug, Default)]
pub struct Fields(Vec<(String, Vec<u8>)>);

impl Fields {
    pub fn raw(&self, key: &str) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// A string field: quoted text, or hex when it contains special bytes.
    pub fn string(&self, key: &str) -> Option<Vec<u8>> {
        self.raw(key).filter(|v| *v != b"(null)").map(decode)
    }

    pub fn number(&self, key: &str) -> Option<u32> {
        std::str::from_utf8(self.raw(key)?).ok()?.parse().ok()
    }
}

pub fn parse_fields(body: &[u8]) -> Fields {
    let mut out = Vec::new();
    let mut i = 0;
    let n = body.len();
    while i < n {
        while i < n && body[i] == b' ' {
            i += 1;
        }
        let ks = i;
        while i < n && body[i] != b'=' && body[i] != b' ' {
            i += 1;
        }
        if i >= n || body[i] != b'=' {
            continue;
        }
        let key = String::from_utf8_lossy(&body[ks..i]).into_owned();
        i += 1;
        let vs = i;
        if i < n && body[i] == b'"' {
            i += 1;
            while i < n && body[i] != b'"' {
                i += 1;
            }
            i = (i + 1).min(n);
        } else {
            while i < n && body[i] != b' ' {
                i += 1;
            }
        }
        out.push((key, body[vs..i].to_vec()));
    }
    Fields(out)
}

/// Decode an audit string value: `"text"` is literal; otherwise the value
/// is hex-encoded (used when the text contains spaces, quotes or control
/// bytes); anything else is returned as is.
pub fn decode(v: &[u8]) -> Vec<u8> {
    if v.len() >= 2 && v[0] == b'"' && v[v.len() - 1] == b'"' {
        return v[1..v.len() - 1].to_vec();
    }
    if !v.is_empty() && v.len().is_multiple_of(2) && v.iter().all(u8::is_ascii_hexdigit) {
        return v
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
    }
    v.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(a: &mut Assembler, records: &[(u16, &str)]) -> Vec<Assembled> {
        let now = Instant::now();
        records
            .iter()
            .flat_map(|(t, r)| a.push(*t, r.as_bytes(), now))
            .collect()
    }

    const ECHO: &[(u16, &str)] = &[
        (
            1300,
            "audit(1795285908.304:23): arch=c000003e syscall=59 success=yes exit=0 a0=7f items=2 ppid=32048 pid=32049 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm=\"echo\" exe=\"/usr/bin/echo\" key=\"soteria_exec\"",
        ),
        (
            1309,
            "audit(1795285908.304:23): argc=3 a0=\"/bin/echo\" a1=\"hello\" a2=68656C6C6F20776F726C64",
        ),
        (1307, "audit(1795285908.304:23): cwd=\"/home/user\""),
        (
            1302,
            "audit(1795285908.304:23): item=0 name=\"/bin/echo\" inode=209173 dev=fe:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL",
        ),
        (
            1302,
            "audit(1795285908.304:23): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=1 dev=fe:00 nametype=NORMAL",
        ),
        (
            1327,
            "audit(1795285908.304:23): proctitle=2F62696E2F6563686F",
        ),
        (1320, "audit(1795285908.304:23): "),
    ];

    #[test]
    fn assembles_an_execution() {
        let mut a = Assembler::default();
        let out = feed(&mut a, ECHO);
        assert_eq!(out.len(), 1);
        let Assembled::Exec(ev) = &out[0] else {
            panic!("{out:?}")
        };
        assert_eq!(ev.time_ms, 1_795_285_908_304);
        assert_eq!((ev.pid, ev.ppid, ev.uid, ev.euid), (32049, 32048, 0, 0));
        assert_eq!(ev.auid, Some(1000));
        assert_eq!(ev.session, Some(3));
        assert_eq!(ev.tty.as_deref(), Some("pts0"));
        assert_eq!(ev.comm.as_deref(), Some("echo"));
        assert_eq!(ev.exe, Some(PathBuf::from("/usr/bin/echo")));
        assert_eq!(ev.path, Some(PathBuf::from("/bin/echo")));
        assert_eq!(ev.cwd, Some(PathBuf::from("/home/user")));
        assert_eq!(
            ev.argv,
            vec![
                b"/bin/echo".to_vec(),
                b"hello".to_vec(),
                b"hello world".to_vec()
            ]
        );
        assert_eq!(ev.key.as_deref(), Some("soteria_exec"));
        assert!(a.pending.is_empty());
    }

    #[test]
    fn non_exec_events_and_failures_are_not_executions() {
        let mut a = Assembler::default();
        let out = feed(
            &mut a,
            &[
                (
                    1300,
                    "audit(1.000:5): syscall=49 success=yes pid=1 ppid=0 uid=0 comm=\"x\" exe=\"/x\"",
                ),
                (1320, "audit(1.000:5): "),
                (
                    1300,
                    "audit(1.000:6): syscall=59 success=no exit=-2 pid=2 ppid=1 uid=0 comm=\"x\" exe=\"/x\"",
                ),
                (1309, "audit(1.000:6): argc=1 a0=\"nope\""),
                (1320, "audit(1.000:6): "),
            ],
        );
        assert_eq!(out, vec![Assembled::Other, Assembled::Other]);
    }

    #[test]
    fn long_arguments_are_reassembled_from_chunks() {
        let mut a = Assembler::default();
        let out = feed(
            &mut a,
            &[
                (
                    1300,
                    "audit(2.5:9): syscall=59 success=yes pid=3 ppid=1 uid=0 euid=0 gid=0 auid=4294967295 ses=4294967295 tty=(none) comm=\"sh\" exe=\"/usr/bin/dash\" key=(null)",
                ),
                (1309, "audit(2.5:9): argc=2 a0=\"sh\" a1_len=6 a1[0]=616263"),
                (1309, "audit(2.5:9): a1[1]=\"def\""),
                (1320, "audit(2.5:9): "),
            ],
        );
        let Assembled::Exec(ev) = &out[0] else {
            panic!()
        };
        assert_eq!(ev.argv, vec![b"sh".to_vec(), b"abcdef".to_vec()]);
        assert_eq!(ev.auid, None);
        assert_eq!(ev.session, None);
        assert_eq!(ev.tty, None);
        assert_eq!(ev.key, None);
        assert_eq!(ev.time_ms, 2005);
    }

    #[test]
    fn interleaved_events_and_missing_eoe() {
        let mut a = Assembler::default();
        let t0 = Instant::now();
        a.push(
            1300,
            b"audit(1.0:1): syscall=59 success=yes pid=10 ppid=1 uid=0 exe=\"/a\"",
            t0,
        );
        a.push(
            1300,
            b"audit(1.0:2): syscall=59 success=yes pid=11 ppid=1 uid=0 exe=\"/b\"",
            t0,
        );
        a.push(1309, b"audit(1.0:2): argc=1 a0=\"b\"", t0);
        a.push(1309, b"audit(1.0:1): argc=1 a0=\"a\"", t0);
        let out = a.push(1320, b"audit(1.0:2): ", t0);
        let Assembled::Exec(ev) = &out[0] else {
            panic!()
        };
        assert_eq!(ev.pid, 11);
        assert!(a.expire(t0).is_empty());
        let out = a.expire(t0 + STALE_AFTER);
        let Assembled::Exec(ev) = &out[0] else {
            panic!()
        };
        assert_eq!(ev.pid, 10);
    }

    #[test]
    fn decodes_values() {
        assert_eq!(decode(b"\"a b\""), b"a b");
        assert_eq!(decode(b"2F746D70"), b"/tmp");
        assert_eq!(decode(b"(none)"), b"(none)");
        assert_eq!(decode(b"123"), b"123"); // odd length: not hex
        let f = parse_fields(b" a=1 b=\"x y\" c=(null) d");
        assert_eq!(f.raw("a"), Some(b"1".as_slice()));
        assert_eq!(f.string("b"), Some(b"x y".to_vec()));
        assert_eq!(f.string("c"), None);
    }

    #[test]
    fn splits_netlink_datagrams() {
        let mut buf = Vec::new();
        for (ty, body) in [(1300u16, b"abc".as_slice()), (1320, b"")] {
            let len = 16 + body.len();
            buf.extend((len as u32).to_ne_bytes());
            buf.extend(ty.to_ne_bytes());
            buf.extend([0u8; 10]);
            buf.extend(body);
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        let msgs = netlink_messages(&buf);
        assert_eq!(
            msgs,
            vec![(1300, b"abc".as_slice()), (1320, b"".as_slice())]
        );
    }
}

/// Needs root (CAP_AUDIT_READ) and a loaded execve audit rule:
/// `cargo test -p soteria-sensors -- --ignored live_audit_stream`
#[cfg(test)]
#[test]
#[ignore]
fn live_audit_stream() {
    let socket = open().expect("open audit socket");
    let (tx, rx) = std::sync::mpsc::sync_channel(1024);
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(AuditStats::default());
    let h = spawn(socket, tx, Arc::clone(&stop), Arc::clone(&stats)).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let child = std::process::Command::new("/bin/echo")
        .arg("soteria live test")
        .output()
        .unwrap();
    assert!(child.status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut found = None;
    while Instant::now() < deadline && found.is_none() {
        if let Ok(ev) = rx.recv_timeout(Duration::from_millis(100))
            && ev.argv.get(1).map(Vec::as_slice) == Some(b"soteria live test".as_slice())
        {
            found = Some(ev);
        }
    }
    stop.store(true, Ordering::Relaxed);
    h.join().unwrap();
    let ev = found.expect("execution event");
    assert_eq!(ev.ppid, std::process::id());
    assert!(ev.exe.unwrap().ends_with("echo"));
}
