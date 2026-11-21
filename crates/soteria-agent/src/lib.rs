//! Core agent: event processing, scheduled scans, alerts and health
//! (SRS 5.1 components 2, 10 and 12; FR-014..FR-017, FR-032, FR-036..FR-039).
//!
//! The daemon owns process lifecycle (signals, systemd notifications) and
//! calls [`Agent::step`] in a loop. Each step drains sensor events,
//! re-verifies paths whose events have settled, accounts for lost events,
//! and runs scans that are due.

pub mod alerts;
pub mod exec;
mod exec_sensor;
pub mod incidents;
pub mod lifecycle;
mod notify;
pub mod retention;
pub mod rules;
pub mod scope;
pub mod selfcheck;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use serde_json::json;
use soteria_config::Config;
use soteria_core::{FileKind, Severity};
use soteria_integrity::baseline;
use soteria_integrity::compare::{Change, ChangeKind, ChangeSummary, diff_record, severity};
use soteria_integrity::keys;
use soteria_integrity::scan::{self, ScanTarget, delete_file, load_file, upsert_file};
use soteria_inventory::{Scope, inspect_path};
use soteria_rules::RuleSet;
use soteria_sensors::audit::{self as exec_audit, AuditSnapshot};
use soteria_sensors::fs::{self as fs_sensor, FsEvent, SensorStats, StatsSnapshot};
use soteria_store::{Store, now};
use tracing::{error, info, warn};

use alerts::{NewAlert, Policy, Raised, Source};

/// How often old events and execution records are deleted.
const RETENTION_INTERVAL: Duration = Duration::from_secs(3600);
/// Delay before the first retention run after start.
const RETENTION_FIRST: Duration = Duration::from_secs(300);

/// Meta key holding the agent's latest health snapshot (FR-039).
pub const HEALTH_KEY: &str = "agent_health";

/// Kinds verified by the periodic critical-file scan (FR-032).
pub const CRITICAL_KINDS: [FileKind; 8] = [
    FileKind::ExecutableBinary,
    FileKind::Script,
    FileKind::SharedLibrary,
    FileKind::KernelImage,
    FileKind::KernelModule,
    FileKind::SecuritySensitive,
    FileKind::ScheduledJob,
    FileKind::ServiceUnit,
];

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Baseline(#[from] baseline::BaselineError),
    #[error(transparent)]
    Scan(#[from] scan::ScanError),
    #[error(transparent)]
    Rules(#[from] soteria_rules::RulesError),
}

pub type Result<T> = std::result::Result<T, AgentError>;

/// Tuning knobs; defaults suit production, tests shorten them.
#[derive(Debug, Clone)]
pub struct Options {
    /// Bounded sensor queue (NFR-006).
    pub queue_capacity: usize,
    /// Wait this long after the last event on a path before verifying it,
    /// so a file being written is checked once, when complete.
    pub settle: Duration,
    /// Never delay verification longer than this (NFR-004: two seconds).
    pub max_delay: Duration,
    /// Run a full reconciliation at start (also forced by config).
    pub startup_scan: bool,
    /// Join the kernel audit stream for executions. Tests that feed
    /// executions directly turn it off.
    pub exec_sensor: bool,
    /// The configuration file in use, monitored as one of Soteria's own
    /// files (FR-036). `None`: the default location.
    pub config_path: Option<PathBuf>,
    /// The previous run did not stop cleanly (FR-037): raise SELF-002.
    pub interrupted: Option<selfcheck::Interruption>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            queue_capacity: 65_536,
            settle: Duration::from_millis(250),
            max_delay: Duration::from_millis(1500),
            startup_scan: true,
            exec_sensor: true,
            config_path: None,
            interrupted: None,
        }
    }
}

/// Health snapshot written for `soteria status` (FR-039).
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub updated_at: String,
    pub fs_sensor: Option<StatsSnapshot>,
    pub fs_sensor_state: String,
    pub exec_sensor: Option<AuditSnapshot>,
    pub exec_sensor_state: String,
    pub executions_processed: u64,
    pub pending_paths: usize,
    pub events_processed: u64,
    pub last_event_at: Option<String>,
    pub baseline_version: Option<u32>,
    pub baseline_state: String,
    pub scan_state: String,
    pub last_reconciliation: Option<String>,
    pub next_full_scan_in_secs: u64,
    pub next_critical_scan_in_secs: u64,
}

struct Pending {
    first: Instant,
    last: Instant,
}

pub struct Agent {
    config: Config,
    store: Store,
    scope: Scope,
    hostname: String,
    options: Options,
    rx: Option<Receiver<FsEvent>>,
    stats: Arc<SensorStats>,
    sensor_stop: Arc<AtomicBool>,
    sensor: Option<JoinHandle<()>>,
    sensor_state: String,
    pending: HashMap<PathBuf, Pending>,
    baseline: Option<u32>,
    baseline_state: String,
    seen_loss: (u64, u64),
    reconcile_now: bool,
    next_full: Instant,
    next_critical: Instant,
    events_processed: u64,
    last_event_at: Option<String>,
    last_reconciliation: Option<String>,
    scan_state: String,
    exec: Option<exec_sensor::ExecState>,
    exec_sensor_state: String,
    executions_processed: u64,
    /// Execution classifier used without a live sensor (tests).
    spare_monitor: Option<exec::ExecMonitor>,
    /// Detection rules in effect (built-in, overrides, administrator rules).
    rules: Arc<RuleSet>,
    /// When old events and execution records are next deleted.
    next_retention: Instant,
    /// Email and webhook delivery, when enabled.
    notifier: Option<notify::Notifier>,
    /// Soteria's own files (FR-036).
    own_files: Vec<PathBuf>,
}

impl Agent {
    /// Start sensors and record what is and is not being monitored, so no
    /// capability is shown as active when it is not (SRS 4.7).
    pub fn start(config: Config, store: Store, options: Options) -> Result<Agent> {
        let scope = scope::for_config(&config, options.config_path.as_deref());
        // Invalid rules stop the agent: running without them would silently
        // weaken detection (FR-043).
        let rules = Arc::new(RuleSet::load(&config.general.rules_directory)?);
        rules::sync(store.connection(), &rules)?;
        if let Some(i) = &options.interrupted {
            selfcheck::report(
                &store,
                &soteria_platform::hostname(),
                i,
                Policy {
                    minimum: config.alerts.minimum_severity,
                    rules: &rules,
                },
            )?;
        }
        let now_i = Instant::now();
        let startup_scan = options.startup_scan && config.scanning.startup_scan;
        let mut agent = Agent {
            rules,
            // Not at once: the startup scan comes first.
            next_retention: now_i + RETENTION_FIRST,
            own_files: if config.paths.own_files {
                scope::self_paths(&config, options.config_path.as_deref())
            } else {
                Vec::new()
            },
            notifier: notify::Notifier::start(&config, &soteria_platform::hostname(), &store)?,
            next_full: if startup_scan {
                now_i
            } else {
                now_i + config.scanning.full_scan_interval.0
            },
            next_critical: now_i + config.scanning.critical_scan_interval.0,
            hostname: soteria_platform::hostname(),
            scope,
            options,
            rx: None,
            stats: Arc::new(SensorStats::default()),
            sensor_stop: Arc::new(AtomicBool::new(false)),
            sensor: None,
            sensor_state: "stopped".into(),
            pending: HashMap::new(),
            baseline: None,
            baseline_state: "unknown".into(),
            seen_loss: (0, 0),
            reconcile_now: false,
            events_processed: 0,
            last_event_at: None,
            last_reconciliation: None,
            scan_state: "idle".into(),
            exec: None,
            exec_sensor_state: "stopped".into(),
            executions_processed: 0,
            spare_monitor: None,
            config,
            store,
        };

        agent.refresh_baseline()?;

        // Monitors that arrive in later milestones are recorded as
        // unavailable rather than silently absent.
        let m = &agent.config.monitoring;
        let planned = [
            (
                "kernel",
                m.kernel,
                "kernel and boot monitoring arrives in a later release",
            ),
            (
                "persistence",
                m.persistence,
                "persistence monitoring arrives in a later release",
            ),
            (
                "users",
                m.users,
                "account monitoring arrives in a later release",
            ),
        ];
        for (sensor, enabled, detail) in planned {
            if enabled {
                agent.health(sensor, "unavailable", Some(detail));
            } else {
                agent.health(sensor, "disabled", Some("disabled by configuration"));
            }
        }
        if !agent.config.monitoring.configuration {
            agent.health(
                "configuration",
                "disabled",
                Some("disabled by configuration"),
            );
        }

        if agent.config.monitoring.execution {
            if agent.options.exec_sensor {
                agent.start_exec_sensor();
            }
        } else {
            agent.exec_sensor_state = "disabled".into();
            agent.health(
                exec_audit::SENSOR,
                "disabled",
                Some("execution monitoring disabled by configuration"),
            );
            agent.open_gap(
                "disabled",
                exec_audit::SENSOR,
                None,
                "execution monitoring is disabled by configuration",
            )?;
        }

        if agent.config.monitoring.file_integrity {
            agent.start_fs_sensor();
        } else {
            agent.sensor_state = "disabled".into();
            agent.health(
                fs_sensor::SENSOR,
                "disabled",
                Some("file_integrity monitoring disabled by configuration"),
            );
            agent.open_gap(
                "disabled",
                fs_sensor::SENSOR,
                None,
                "file integrity event monitoring is disabled by configuration",
            )?;
        }
        Ok(agent)
    }

    fn start_fs_sensor(&mut self) {
        let (tx, rx) = sync_channel(self.options.queue_capacity);
        match fs_sensor::spawn(
            self.scope.clone(),
            tx,
            Arc::clone(&self.sensor_stop),
            Arc::clone(&self.stats),
        ) {
            Ok(handle) => {
                self.rx = Some(rx);
                self.sensor = Some(handle);
                let s = self.stats.snapshot();
                let detail = format!(
                    "inotify; {} directories watched, {} unwatched",
                    s.watches, s.watch_failures
                );
                info!(sensor = fs_sensor::SENSOR, "{detail}");
                self.sensor_state = if s.watch_failures > 0 {
                    "degraded"
                } else {
                    "running"
                }
                .into();
                self.health(fs_sensor::SENSOR, &self.sensor_state.clone(), Some(&detail));
                let _ =
                    self.close_gaps(fs_sensor::SENSOR, &["sensor_down", "unwatched", "disabled"]);
                if s.watch_failures > 0 {
                    let unwatched = self
                        .stats
                        .unwatched
                        .lock()
                        .map(|u| u.clone())
                        .unwrap_or_default();
                    for (path, why) in &unwatched {
                        let _ = self.open_gap("unwatched", fs_sensor::SENSOR, Some(path), why);
                    }
                    if s.watch_failures as usize > unwatched.len() {
                        let _ = self.open_gap(
                            "unwatched",
                            fs_sensor::SENSOR,
                            None,
                            &format!(
                                "{} more directories could not be watched",
                                s.watch_failures as usize - unwatched.len()
                            ),
                        );
                    }
                }
            }
            Err(e) => {
                let detail = format!("cannot start inotify: {e}");
                error!(sensor = fs_sensor::SENSOR, "{detail}");
                self.sensor_state = "failed".into();
                self.health(fs_sensor::SENSOR, "failed", Some(&detail));
                let _ = self.open_gap("sensor_down", fs_sensor::SENSOR, None, &detail);
            }
        }
    }

    /// One iteration: wait up to `budget` for events, verify settled paths,
    /// account for losses and run due scans.
    pub fn step(&mut self, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        if let Some(rx) = &self.rx {
            loop {
                let wait = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(wait) {
                    Ok(FsEvent::Changed(path)) => {
                        let t = Instant::now();
                        self.pending
                            .entry(path)
                            .and_modify(|p| p.last = t)
                            .or_insert(Pending { first: t, last: t });
                        if Instant::now() >= deadline {
                            break;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(RecvTimeoutError::Disconnected) => {
                        self.rx = None;
                        break;
                    }
                }
            }
        } else {
            std::thread::sleep(budget);
        }

        self.drain_exec()?;
        self.check_exec_sensor()?;
        self.check_sensor()?;
        self.process_due()?;

        let now_i = Instant::now();
        if self.reconcile_now || now_i >= self.next_full {
            self.reconcile(Source::Reconciliation)?;
            self.next_full = Instant::now() + self.config.scanning.full_scan_interval.0;
            self.reconcile_now = false;
        } else if now_i >= self.next_critical {
            self.critical_scan()?;
            self.next_critical = Instant::now() + self.config.scanning.critical_scan_interval.0;
        }
        self.after_alerts()?;
        Ok(())
    }

    /// Work on alerts recorded since the last step: group related ones into
    /// incidents (FR-018).
    pub fn after_alerts(&mut self) -> Result<()> {
        incidents::correlate_pending(
            self.store.connection(),
            self.config.alerts.correlation_window.0,
        )?;
        if let Some(n) = self.notifier.as_mut() {
            n.step(&self.store)?;
        }
        if Instant::now() >= self.next_retention {
            self.prune()?;
        }
        Ok(())
    }

    /// Delete events and execution records past the retention period.
    pub fn prune(&mut self) -> Result<retention::Pruned> {
        let days = u64::from(self.config.general.event_retention_days);
        let pruned = retention::prune(self.store.connection(), Duration::from_secs(days * 86_400))?;
        if pruned != retention::Pruned::default() {
            info!(
                events = pruned.events,
                processes = pruned.processes,
                "deleted records older than {days} days"
            );
        }
        self.next_retention = Instant::now() + RETENTION_INTERVAL;
        Ok(pruned)
    }

    /// Verify every pending path now, regardless of settle time.
    pub fn flush(&mut self) -> Result<()> {
        let paths: Vec<PathBuf> = self.pending.drain().map(|(p, _)| p).collect();
        for p in paths {
            self.verify_path(&p, Source::FsEvent)?;
        }
        Ok(())
    }

    fn process_due(&mut self) -> Result<()> {
        let now_i = Instant::now();
        let (settle, max_delay) = (self.options.settle, self.options.max_delay);
        let due: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, p)| now_i - p.last >= settle || now_i - p.first >= max_delay)
            .map(|(path, _)| path.clone())
            .collect();
        for path in due {
            self.pending.remove(&path);
            self.verify_path(&path, Source::FsEvent)?;
        }
        Ok(())
    }

    /// Detect lost events and sensor failure (FR-017, NFR-006, SRS 5.5).
    fn check_sensor(&mut self) -> Result<()> {
        let s = self.stats.snapshot();
        let loss = (s.dropped, s.kernel_overflows);
        if loss != self.seen_loss {
            let dropped = s.dropped - self.seen_loss.0;
            let overflows = s.kernel_overflows - self.seen_loss.1;
            self.seen_loss = loss;
            let detail = format!(
                "events lost: {dropped} dropped by a full agent queue, {overflows} kernel queue overflow(s); reconciliation scheduled"
            );
            warn!(sensor = fs_sensor::SENSOR, "{detail}");
            self.open_gap("overflow", fs_sensor::SENSOR, None, &detail)?;
            self.health(fs_sensor::SENSOR, "degraded", Some(&detail));
            self.sensor_state = "degraded".into();
            self.reconcile_now = true;
        }
        if self.sensor.is_some() && !s.running {
            let detail = s
                .failure
                .unwrap_or_else(|| "filesystem sensor stopped unexpectedly".into());
            error!(sensor = fs_sensor::SENSOR, "{detail}");
            self.sensor = None;
            self.rx = None;
            self.sensor_state = "failed".into();
            self.health(fs_sensor::SENSOR, "failed", Some(&detail));
            self.open_gap("sensor_down", fs_sensor::SENSOR, None, &detail)?;
            alerts::record_event(
                self.store.connection(),
                "agent",
                "sensor.failed",
                Severity::High,
                None,
                &json!({ "sensor": fs_sensor::SENSOR, "detail": detail }),
            )?;
        }
        Ok(())
    }

    fn in_scope(&self, path: &Path) -> bool {
        !self.scope.is_excluded(path) && self.scope.include.iter().any(|r| path.starts_with(r))
    }

    /// Re-read one object, update the inventory, record an event if it
    /// changed, and raise an alert if it deviates from the baseline (FR-015).
    pub fn verify_path(&mut self, path: &Path, source: Source) -> Result<()> {
        if !self.in_scope(path) {
            return Ok(());
        }
        let current = match inspect_path(path) {
            Ok(r) => r,
            Err(e) => {
                self.open_gap(
                    "inaccessible",
                    fs_sensor::SENSOR,
                    Some(path),
                    &e.to_string(),
                )?;
                return Ok(());
            }
        };
        let conn = self.store.connection();
        let previous = load_file(conn, path)?;
        match &current {
            Some(r) => upsert_file(conn, r, &now())?,
            None => {
                delete_file(conn, path)?;
            }
        }
        let inventory_change = match (&previous, &current) {
            (None, None) => return Ok(()),
            (None, Some(_)) => vec![ChangeKind::New],
            (Some(_), None) => vec![ChangeKind::Missing],
            (Some(a), Some(b)) => diff_record(a, b),
        };

        // Compare with the approved state.
        let deviation = match self.baseline {
            Some(v) => {
                let approved = baseline::entry(&self.store, v, path)?;
                let kinds = match (&approved, &current) {
                    (None, None) => vec![],
                    (None, Some(_)) => vec![ChangeKind::New],
                    (Some(_), None) => vec![ChangeKind::Missing],
                    (Some(a), Some(b)) => diff_record(a, b),
                };
                (!kinds.is_empty()).then(|| Change {
                    path: path.to_owned(),
                    severity: severity(&kinds, approved.as_ref(), current.as_ref()),
                    kinds,
                    before: approved,
                    after: current.clone(),
                })
            }
            None => None,
        };

        // Record the observation, skipping directory timestamp churn.
        let is_dir_churn = inventory_change == [ChangeKind::MetadataModified]
            && current
                .as_ref()
                .is_some_and(|c| c.kind == FileKind::Directory);
        if !inventory_change.is_empty() && !is_dir_churn {
            let event_type = match (&previous, &current) {
                (None, _) => "file.created",
                (_, None) => "file.deleted",
                _ => "file.modified",
            };
            let sev = deviation
                .as_ref()
                .map(|d| d.severity)
                .unwrap_or(Severity::Info);
            let kinds: Vec<&str> = inventory_change.iter().map(|k| k.as_str()).collect();
            alerts::record_event(
                self.store.connection(),
                fs_sensor::SENSOR,
                event_type,
                sev,
                Some(path),
                &json!({
                    "changes": kinds,
                    "sha256": current.as_ref().and_then(|c| c.sha256.clone()),
                    "deviates_from_baseline": deviation.is_some(),
                }),
            )?;
            self.events_processed += 1;
            self.last_event_at = Some(now());
        }

        if let (Some(change), Some(version)) = (&deviation, self.baseline) {
            self.alert(change, source, version)?;
        }
        Ok(())
    }

    fn alert(&mut self, change: &Change, source: Source, version: u32) -> Result<()> {
        let new = NewAlert {
            change,
            source,
            baseline_version: version,
            hostname: &self.hostname,
            own_file: scope::is_self_path(&self.own_files, &change.path),
        };
        if let Raised::Created { id, .. } = alerts::raise(
            self.store.connection(),
            &new,
            Policy {
                minimum: self.config.alerts.minimum_severity,
                rules: &self.rules,
            },
        )? && self.config.alerts.journal
        {
            let kinds: Vec<&str> = change.kinds.iter().map(|k| k.as_str()).collect();
            let msg = format!(
                "ALERT {id} [{}] {}: {}",
                change.severity.as_str().to_uppercase(),
                change.path.display(),
                kinds.join(",")
            );
            if change.severity >= Severity::High {
                error!(alert = id, "{msg}");
            } else {
                warn!(alert = id, "{msg}");
            }
        }
        Ok(())
    }

    /// Check the approved baseline's seal. A baseline that fails is not
    /// used for comparison and raises a critical alert (FR-006, FR-038).
    fn refresh_baseline(&mut self) -> Result<()> {
        let Some(latest) = baseline::latest_approved(&self.store)? else {
            self.baseline = None;
            self.baseline_state = "none".into();
            self.health(
                "baseline",
                "none",
                Some("no approved baseline; only inventory changes are recorded"),
            );
            self.open_gap(
                "no_baseline",
                "baseline",
                None,
                "no approved baseline; deviations cannot be detected",
            )?;
            return Ok(());
        };
        let outcome = match keys::load_verifier(&self.config.baseline.public_key) {
            Ok(key) => {
                let v = baseline::verify(&self.store, latest.version, &key)?;
                if v.valid {
                    Ok(())
                } else {
                    Err(v.problems.join("; "))
                }
            }
            Err(e) => Err(format!("cannot load public key: {e}")),
        };
        match outcome {
            Ok(()) => {
                if self.baseline != Some(latest.version) {
                    info!(version = latest.version, "approved baseline verified");
                }
                self.baseline = Some(latest.version);
                self.baseline_state = "verified".into();
                self.health(
                    "baseline",
                    "verified",
                    Some(&format!("v{}", latest.version)),
                );
                self.close_gaps("baseline", &["no_baseline", "baseline_unverified"])?;
            }
            Err(problem) => {
                let detail = format!(
                    "baseline v{} failed verification: {problem}",
                    latest.version
                );
                error!("{detail}");
                self.baseline = None;
                self.baseline_state = "failed".into();
                self.health("baseline", "failed", Some(&detail));
                self.open_gap("baseline_unverified", "baseline", None, &detail)?;
                self.seal_alert(latest.version, &detail)?;
            }
        }
        Ok(())
    }

    fn seal_alert(&mut self, version: u32, detail: &str) -> Result<()> {
        let rule = soteria_rules::builtin("INT-001");
        let raised = alerts::insert(
            self.store.connection(),
            alerts::AlertSpec {
                alert_type: "baseline_integrity",
                rule_id: rule.id,
                severity: Severity::Critical,
                hostname: &self.hostname,
                object: &format!("baseline v{version}"),
                reason: rule.description,
                recommendation: rule.recommendation,
                evidence: json!({ "baseline_version": version, "detail": detail }),
                // One open alert per failed baseline, whatever the detail.
                identity: json!(null),
                event_id: None,
            },
            // A failed seal is always reported, whatever the minimum.
            Policy {
                minimum: Severity::Info,
                rules: &self.rules,
            },
        )?;
        if let Raised::Created { id, .. } = raised {
            error!(alert = id, "ALERT {id} [CRITICAL] {detail}");
        }
        Ok(())
    }

    /// Full reconciliation: rescan everything, compare with the baseline and
    /// alert on every deviation, including ones events missed (FR-016).
    pub fn reconcile(&mut self, source: Source) -> Result<()> {
        self.scan_state = "full_scan".into();
        self.refresh_baseline()?;
        let report = scan::run(&mut self.store, &self.scope, &ScanTarget::Full, "full")?;
        info!(
            checked = report.checked,
            gaps = report.gap_count,
            duration_ms = report.duration_ms,
            "reconciliation scan completed"
        );
        if let Some(version) = self.baseline {
            let mut changes = Vec::new();
            let mut summary = ChangeSummary::default();
            baseline::diff_current(&self.store, version, |c| {
                summary.add(&c);
                changes.push(c);
            })?;
            scan::record_baseline_result(&self.store, &report.id, version, &summary)?;
            for c in &changes {
                self.alert(c, source, version)?;
            }
        }
        // Everything has been re-verified, so earlier event losses are covered.
        self.close_gaps(fs_sensor::SENSOR, &["overflow", "inaccessible"])?;
        if self.sensor_state == "degraded" && self.stats.snapshot().watch_failures == 0 {
            self.sensor_state = "running".into();
            self.health(
                fs_sensor::SENSOR,
                "running",
                Some("recovered after reconciliation"),
            );
        }
        self.last_reconciliation = Some(now());
        self.scan_state = "idle".into();
        Ok(())
    }

    /// Re-verify the approved state of critical objects (FR-032).
    pub fn critical_scan(&mut self) -> Result<()> {
        self.refresh_baseline()?;
        let Some(version) = self.baseline else {
            return Ok(());
        };
        self.scan_state = "critical_scan".into();
        let id = soteria_store::new_id();
        let started = now();
        self.store.connection().execute(
            "INSERT INTO scan_history (uuid, type, started_at, status) VALUES (?1, 'critical', ?2, 'running')",
            params![id, started],
        )?;
        let paths = baseline::entry_paths(&self.store, version, &CRITICAL_KINDS)?;
        let before: i64 = self.count_alerts()?;
        for p in &paths {
            self.verify_path(p, Source::CriticalScan)?;
        }
        let raised = self.count_alerts()? - before;
        self.store.connection().execute(
            "UPDATE scan_history SET status = 'completed', finished_at = ?2, checked = ?3, changes = ?4 WHERE uuid = ?1",
            params![id, now(), paths.len() as i64, raised],
        )?;
        info!(
            checked = paths.len(),
            alerts = raised,
            "critical-file verification completed"
        );
        self.scan_state = "idle".into();
        Ok(())
    }

    fn count_alerts(&self) -> Result<i64> {
        Ok(self
            .store
            .connection()
            .query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))?)
    }

    fn health(&self, sensor: &str, state: &str, detail: Option<&str>) {
        if let Err(e) = self.store.record_health(sensor, state, detail) {
            error!("cannot record {sensor} health: {e}");
        }
    }

    /// Open a coverage gap unless an identical one is already open.
    fn open_gap(&self, kind: &str, sensor: &str, path: Option<&Path>, detail: &str) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let conn = self.store.connection();
        let path_bytes = path.map(|p| p.as_os_str().as_bytes().to_vec());
        let open: Option<i64> = conn
            .query_row(
                "SELECT id FROM coverage_gaps WHERE closed_at IS NULL AND kind = ?1 AND sensor = ?2 AND path IS ?3",
                params![kind, sensor, path_bytes],
                |r| r.get(0),
            )
            .optional()?;
        match open {
            Some(id) => {
                conn.execute(
                    "UPDATE coverage_gaps SET detail = ?2 WHERE id = ?1",
                    params![id, detail],
                )?;
            }
            None => {
                conn.execute(
                    "INSERT INTO coverage_gaps (opened_at, kind, sensor, path, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![now(), kind, sensor, path_bytes, detail],
                )?;
            }
        }
        Ok(())
    }

    fn close_gaps(&self, sensor: &str, kinds: &[&str]) -> Result<()> {
        for kind in kinds {
            self.store.connection().execute(
                "UPDATE coverage_gaps SET closed_at = ?3 WHERE closed_at IS NULL AND sensor = ?1 AND kind = ?2",
                params![sensor, kind, now()],
            )?;
        }
        Ok(())
    }

    /// Current health, also written to the database for `soteria status`.
    pub fn snapshot(&self) -> Health {
        let now_i = Instant::now();
        Health {
            updated_at: now(),
            fs_sensor: self.sensor.as_ref().map(|_| self.stats.snapshot()),
            fs_sensor_state: self.sensor_state.clone(),
            exec_sensor: self.exec.as_ref().map(|e| e.stats.snapshot()),
            exec_sensor_state: self.exec_sensor_state.clone(),
            executions_processed: self.executions_processed,
            pending_paths: self.pending.len(),
            events_processed: self.events_processed,
            last_event_at: self.last_event_at.clone(),
            baseline_version: self.baseline,
            baseline_state: self.baseline_state.clone(),
            scan_state: self.scan_state.clone(),
            last_reconciliation: self.last_reconciliation.clone(),
            next_full_scan_in_secs: self.next_full.saturating_duration_since(now_i).as_secs(),
            next_critical_scan_in_secs: self
                .next_critical
                .saturating_duration_since(now_i)
                .as_secs(),
        }
    }

    pub fn write_health(&self) {
        let h = serde_json::to_string(&self.snapshot()).expect("serializable");
        if let Err(e) = self.store.set_meta(HEALTH_KEY, &h) {
            error!("cannot write health snapshot: {e}");
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Stop the sensor thread and record the shutdown.
    pub fn shutdown(mut self) {
        self.sensor_stop.store(true, Ordering::Relaxed);
        if let Some(n) = self.notifier.as_mut() {
            n.shutdown();
        }
        if let Some(h) = self.sensor.take() {
            let _ = h.join();
        }
        if let Some(h) = self.exec.as_mut().and_then(|e| e.sensor.take()) {
            let _ = h.join();
        }
        self.health(fs_sensor::SENSOR, "stopped", Some("agent shutdown"));
        if self.exec.is_some() {
            self.health(exec_audit::SENSOR, "stopped", Some("agent shutdown"));
        }
    }
}

#[cfg(test)]
mod tests;
