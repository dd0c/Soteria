//! Filesystem sensor based on inotify (FR-014, SRS 5.5).
//!
//! inotify needs no privileges, so it works for the unprivileged daemon.
//! fanotify is deliberately not used: it needs CAP_SYS_ADMIN.
//!
//! The sensor watches every directory in scope and reports *paths* that may
//! have changed; it does not try to interpret the change. The agent
//! re-inspects each path and compares it with the baseline (FR-015), so a
//! missed or merged event costs at most a little latency, never a wrong
//! verdict.
//!
//! Nothing is lost silently (NFR-006): kernel queue overflows, a full
//! agent queue, and directories that cannot be watched (for example when
//! `fs.inotify.max_user_watches` is exhausted) are counted in
//! [`SensorStats`] and reported so the agent can open a coverage gap and
//! schedule a reconciliation scan.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use serde::Serialize;
use soteria_inventory::Scope;

/// Sensor name used in health records and events.
pub const SENSOR: &str = "fs";

/// A message from the sensor to the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEvent {
    /// Something at this path may have been created, modified, deleted,
    /// renamed, or had its metadata changed.
    Changed(PathBuf),
}

/// Counters shared with the agent. All monotonic.
#[derive(Debug, Default)]
pub struct SensorStats {
    pub received: AtomicU64,
    /// Events dropped because the agent queue was full.
    pub dropped: AtomicU64,
    /// IN_Q_OVERFLOW notifications: the kernel dropped events.
    pub kernel_overflows: AtomicU64,
    pub watches: AtomicU64,
    /// Directories that could not be watched.
    pub watch_failures: AtomicU64,
    pub running: AtomicBool,
    /// Last fatal error, if the sensor stopped.
    pub failure: Mutex<Option<String>>,
    /// Details of the most recent watch failures, for coverage reporting.
    pub unwatched: Mutex<Vec<(PathBuf, String)>>,
}

/// Point-in-time copy of [`SensorStats`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StatsSnapshot {
    pub received: u64,
    pub dropped: u64,
    pub kernel_overflows: u64,
    pub watches: u64,
    pub watch_failures: u64,
    pub running: bool,
    pub failure: Option<String>,
}

impl SensorStats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            kernel_overflows: self.kernel_overflows.load(Ordering::Relaxed),
            watches: self.watches.load(Ordering::Relaxed),
            watch_failures: self.watch_failures.load(Ordering::Relaxed),
            running: self.running.load(Ordering::Relaxed),
            failure: self.failure.lock().map(|f| f.clone()).unwrap_or(None),
        }
    }
}

/// Unwatched directories kept for reporting; the count is always exact.
const UNWATCHED_DETAIL_LIMIT: usize = 100;

const MASK: WatchMask = WatchMask::CREATE
    .union(WatchMask::DELETE)
    .union(WatchMask::MODIFY)
    .union(WatchMask::CLOSE_WRITE)
    .union(WatchMask::ATTRIB)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO)
    .union(WatchMask::DELETE_SELF)
    .union(WatchMask::MOVE_SELF)
    .union(WatchMask::DONT_FOLLOW)
    .union(WatchMask::EXCL_UNLINK)
    .union(WatchMask::ONLYDIR);

struct Watcher {
    inotify: Inotify,
    scope: Scope,
    dirs: HashMap<WatchDescriptor, PathBuf>,
    tx: SyncSender<FsEvent>,
    stats: Arc<SensorStats>,
}

impl Watcher {
    /// Watch `dir` and every directory below it. With `announce`, also
    /// report everything found, for directories created after the initial
    /// setup whose contents may predate their watch.
    fn watch_tree(&mut self, dir: &Path, announce: bool) {
        let mut stack = vec![dir.to_owned()];
        while let Some(d) = stack.pop() {
            if self.scope.is_excluded(&d) {
                continue;
            }
            match self.inotify.watches().add(&d, MASK) {
                Ok(wd) => {
                    if self.dirs.insert(wd, d.clone()).is_none() {
                        self.stats.watches.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    // ENOTDIR (ONLYDIR) or a vanished path are not failures.
                    if matches!(e.raw_os_error(), Some(20) | Some(2)) {
                        continue;
                    }
                    self.stats.watch_failures.fetch_add(1, Ordering::Relaxed);
                    let detail = if e.raw_os_error() == Some(28) {
                        "inotify watch limit reached (raise fs.inotify.max_user_watches)".to_owned()
                    } else {
                        e.to_string()
                    };
                    if let Ok(mut u) = self.stats.unwatched.lock()
                        && u.len() < UNWATCHED_DETAIL_LIMIT
                    {
                        u.push((d.clone(), detail));
                    }
                    continue;
                }
            }
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue; // reported by scans as an inaccessible path
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if self.scope.is_excluded(&path) {
                    continue;
                }
                if announce {
                    self.emit(path.clone());
                }
                // file_type() does not follow symlinks.
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    stack.push(path);
                }
            }
        }
    }

    fn emit(&self, path: PathBuf) {
        self.stats.received.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(FsEvent::Changed(path)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    fn run(&mut self, stop: &AtomicBool) {
        let mut buffer = vec![0u8; 64 * 1024];
        while !stop.load(Ordering::Relaxed) {
            let events = match self.inotify.read_events(&mut buffer) {
                Ok(events) => events,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.fail(format!("reading inotify events failed: {e}"));
                    return;
                }
            };
            let mut new_dirs = Vec::new();
            let mut changed = Vec::new();
            let mut gone = Vec::new();
            for event in events {
                if event.mask.contains(EventMask::Q_OVERFLOW) {
                    self.stats.kernel_overflows.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if event.mask.contains(EventMask::IGNORED) {
                    gone.push(event.wd.clone());
                    continue;
                }
                let Some(dir) = self.dirs.get(&event.wd) else {
                    continue;
                };
                let path = match event.name {
                    Some(name) => dir.join(name),
                    None => dir.clone(), // DELETE_SELF / MOVE_SELF / ATTRIB on the dir
                };
                if self.scope.is_excluded(&path) {
                    continue;
                }
                if event.mask.contains(EventMask::ISDIR)
                    && event
                        .mask
                        .intersects(EventMask::CREATE | EventMask::MOVED_TO)
                {
                    new_dirs.push(path.clone());
                }
                changed.push(path);
            }
            for wd in gone {
                if self.dirs.remove(&wd).is_some() {
                    self.stats.watches.fetch_sub(1, Ordering::Relaxed);
                }
            }
            for path in changed {
                self.emit(path);
            }
            for dir in new_dirs {
                self.watch_tree(&dir, true);
            }
        }
    }

    fn fail(&self, message: String) {
        tracing::error!(sensor = SENSOR, "{message}");
        if let Ok(mut f) = self.stats.failure.lock() {
            *f = Some(message);
        }
        self.stats.running.store(false, Ordering::Relaxed);
    }
}

/// Start the sensor thread. Watches are set up before this returns, so
/// changes made after it returns are reported.
pub fn spawn(
    scope: Scope,
    tx: SyncSender<FsEvent>,
    stop: Arc<AtomicBool>,
    stats: Arc<SensorStats>,
) -> std::io::Result<JoinHandle<()>> {
    let inotify = Inotify::init()?;
    let mut watcher = Watcher {
        inotify,
        scope: scope.clone(),
        dirs: HashMap::new(),
        tx,
        stats: Arc::clone(&stats),
    };
    for root in scope.roots() {
        if root.is_dir() {
            watcher.watch_tree(&root, false);
        }
    }
    stats.running.store(true, Ordering::Relaxed);
    std::thread::Builder::new()
        .name("soteria-fs".into())
        .spawn(move || {
            watcher.run(&stop);
            watcher.stats.running.store(false, Ordering::Relaxed);
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::mpsc::{Receiver, sync_channel};
    use std::time::Instant;

    struct Harness {
        _dir: tempfile::TempDir,
        root: PathBuf,
        rx: Receiver<FsEvent>,
        stop: Arc<AtomicBool>,
        stats: Arc<SensorStats>,
        handle: Option<JoinHandle<()>>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn start(capacity: usize, prepare: impl FnOnce(&Path), exclude: &[&str]) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        prepare(&root);
        let scope = Scope {
            include: vec![root.clone()],
            exclude: exclude.iter().map(|e| root.join(e)).collect(),
        };
        let (tx, rx) = sync_channel(capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(SensorStats::default());
        let handle = spawn(scope, tx, Arc::clone(&stop), Arc::clone(&stats)).unwrap();
        Harness {
            _dir: dir,
            root,
            rx,
            stop,
            stats,
            handle: Some(handle),
        }
    }

    impl Harness {
        /// Collect events until `want` has been seen or a timeout passes.
        fn collect_until(&self, want: &[PathBuf]) -> BTreeSet<PathBuf> {
            let mut seen = BTreeSet::new();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && !want.iter().all(|w| seen.contains(w)) {
                if let Ok(FsEvent::Changed(p)) = self.rx.recv_timeout(Duration::from_millis(100)) {
                    seen.insert(p);
                }
            }
            seen
        }
    }

    #[test]
    fn reports_create_modify_delete_and_chmod() {
        use std::os::unix::fs::PermissionsExt;
        let h = start(
            1024,
            |r| std::fs::write(r.join("existing"), b"1").unwrap(),
            &[],
        );
        let a = h.root.join("a");
        std::fs::write(&a, b"new").unwrap();
        std::fs::write(h.root.join("existing"), b"2").unwrap();
        std::fs::set_permissions(
            h.root.join("existing"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::remove_file(&a).unwrap();
        let seen = h.collect_until(&[a.clone(), h.root.join("existing")]);
        assert!(seen.contains(&a));
        assert!(seen.contains(&h.root.join("existing")));
    }

    #[test]
    fn follows_new_directories_and_their_contents() {
        let h = start(1024, |_| {}, &[]);
        let nested = h.root.join("new/deeper");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("early"), b"x").unwrap();
        // Give the sensor time to add the new watches, then write again.
        h.collect_until(&[nested.join("early")]);
        std::fs::write(nested.join("late"), b"y").unwrap();
        let seen = h.collect_until(&[nested.join("late")]);
        assert!(seen.contains(&nested.join("late")), "{seen:?}");
        assert!(h.stats.snapshot().watches >= 3);
    }

    #[test]
    fn renames_report_both_names() {
        let h = start(1024, |r| std::fs::write(r.join("old"), b"1").unwrap(), &[]);
        std::fs::rename(h.root.join("old"), h.root.join("new")).unwrap();
        let want = [h.root.join("old"), h.root.join("new")];
        let seen = h.collect_until(&want);
        assert!(want.iter().all(|w| seen.contains(w)), "{seen:?}");
    }

    #[test]
    fn excluded_paths_are_not_watched() {
        let h = start(
            1024,
            |r| std::fs::create_dir(r.join("skip")).unwrap(),
            &["skip"],
        );
        std::fs::write(h.root.join("skip/x"), b"x").unwrap();
        let marker = h.root.join("marker");
        std::fs::write(&marker, b"m").unwrap();
        let seen = h.collect_until(std::slice::from_ref(&marker));
        assert!(seen.contains(&marker));
        assert!(
            !seen.iter().any(|p| p.starts_with(h.root.join("skip"))),
            "{seen:?}"
        );
    }

    #[test]
    fn full_queue_is_counted_not_hidden() {
        let h = start(1, |_| {}, &[]);
        for i in 0..50 {
            std::fs::write(h.root.join(format!("f{i}")), b"x").unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while h.stats.snapshot().dropped == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let s = h.stats.snapshot();
        assert!(s.dropped > 0, "{s:?}");
        assert!(s.received > s.dropped);
    }

    #[test]
    fn stops_on_request() {
        let mut h = start(16, |_| {}, &[]);
        h.stop.store(true, Ordering::Relaxed);
        h.handle.take().unwrap().join().unwrap();
        assert!(!h.stats.snapshot().running);
    }
}
