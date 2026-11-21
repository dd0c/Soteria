//! Execution sensor lifecycle inside the agent: start, self-test, batches
//! of executions, loss and failure accounting.

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::json;
use soteria_core::Severity;
use soteria_sensors::audit::{self as exec_sensor, AuditStats, ExecEvent};
use soteria_store::now;
use tracing::{error, info, warn};

use crate::exec::ExecMonitor;
use crate::{Agent, Result, alerts};

/// Executions handled per step at most, so filesystem events and scans
/// still get their turn during an execution storm.
const EXEC_BATCH: usize = 5_000;
/// How long the self-test waits for its own process to appear.
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a failed self-test is retried.
const SELF_TEST_RETRY: Duration = Duration::from_secs(600);
/// Lost executions cannot be recovered by a scan, so a loss gap stays open
/// this long after the last loss.
const EXEC_LOSS_GAP: Duration = Duration::from_secs(3600);

pub(crate) struct ExecState {
    rx: Option<Receiver<ExecEvent>>,
    pub(crate) stats: Arc<AuditStats>,
    pub(crate) sensor: Option<JoinHandle<()>>,
    monitor: ExecMonitor,
    self_test: SelfTest,
    seen_loss: (u64, u64),
    last_loss: Option<Instant>,
}

enum SelfTest {
    Waiting { pid: u32, deadline: Instant },
    Passed,
    Failed { retry_at: Instant },
}

impl Agent {
    pub(crate) fn start_exec_sensor(&mut self) {
        let opened = exec_sensor::open().and_then(|socket| {
            let (tx, rx) = sync_channel(self.options.queue_capacity);
            let stats = Arc::new(AuditStats::default());
            let handle = exec_sensor::spawn(
                socket,
                tx,
                Arc::clone(&self.sensor_stop),
                Arc::clone(&stats),
            )?;
            Ok((rx, stats, handle))
        });
        match opened {
            Ok((rx, stats, handle)) => {
                let monitor = ExecMonitor::new(
                    self.config.execution.clone(),
                    self.hostname.clone(),
                    self.config.alerts.minimum_severity,
                );
                self.exec = Some(ExecState {
                    rx: Some(rx),
                    stats,
                    sensor: Some(handle),
                    monitor,
                    self_test: SelfTest::Passed,
                    seen_loss: (0, 0),
                    last_loss: None,
                });
                self.exec_sensor_state = "starting".into();
                self.health(
                    exec_sensor::SENSOR,
                    "starting",
                    Some("audit stream joined; waiting for the self-test"),
                );
                let _ = self.close_gaps(exec_sensor::SENSOR, &["sensor_down", "disabled"]);
                self.start_self_test();
            }
            Err(e) => {
                let detail = format!(
                    "cannot read the kernel audit stream: {e} (needs CAP_AUDIT_READ and a kernel with audit support)"
                );
                error!(sensor = exec_sensor::SENSOR, "{detail}");
                self.exec_sensor_state = "failed".into();
                self.health(exec_sensor::SENSOR, "failed", Some(&detail));
                let _ = self.open_gap("sensor_down", exec_sensor::SENSOR, None, &detail);
            }
        }
    }

    /// Run a harmless program and expect to see it in the audit stream.
    /// This proves the execve audit rule is loaded; listing audit rules
    /// would need CAP_AUDIT_CONTROL, which the agent does not have.
    fn start_self_test(&mut self) {
        let Some(exec) = self.exec.as_mut() else {
            return;
        };
        let program = ["/bin/true", "/usr/bin/true"]
            .into_iter()
            .find(|p| Path::new(p).exists());
        let spawned = program
            .ok_or_else(|| std::io::Error::other("no 'true' program found"))
            .and_then(|p| std::process::Command::new(p).spawn());
        exec.self_test = match spawned {
            Ok(mut child) => {
                let pid = child.id();
                let _ = child.wait();
                SelfTest::Waiting {
                    pid,
                    deadline: Instant::now() + SELF_TEST_TIMEOUT,
                }
            }
            Err(e) => {
                warn!(
                    sensor = exec_sensor::SENSOR,
                    "cannot run the execution self-test: {e}"
                );
                SelfTest::Failed {
                    retry_at: Instant::now() + SELF_TEST_RETRY,
                }
            }
        };
    }

    /// Handle queued executions in one transaction.
    pub(crate) fn drain_exec(&mut self) -> Result<()> {
        let Some(exec) = self.exec.as_mut() else {
            return Ok(());
        };
        let Some(rx) = &exec.rx else { return Ok(()) };
        let mut batch = Vec::new();
        let mut disconnected = false;
        while batch.len() < EXEC_BATCH {
            match rx.try_recv() {
                Ok(ev) => batch.push(ev),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if disconnected {
            // The sensor thread ended; check_exec_sensor reports why.
            exec.rx = None;
        }
        if batch.is_empty() {
            return Ok(());
        }
        let self_test_seen = matches!(exec.self_test, SelfTest::Waiting { pid, .. } if batch.iter().any(|e| e.pid == pid));

        let conn = self.store.connection();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let mut result = Ok(());
        for ev in &batch {
            if let Err(e) = exec.monitor.handle(&self.store, self.baseline, ev) {
                result = Err(e);
                break;
            }
        }
        if let Err(e) = result {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
        conn.execute_batch("COMMIT")?;
        self.executions_processed += batch.len() as u64;
        self.last_event_at = Some(now());

        if self_test_seen {
            exec.self_test = SelfTest::Passed;
            if self.exec_sensor_state != "running" {
                info!(
                    sensor = exec_sensor::SENSOR,
                    "execution self-test passed; execution monitoring is active"
                );
            }
            self.exec_sensor_state = "running".into();
            self.health(
                exec_sensor::SENSOR,
                "running",
                Some("kernel audit stream; execve audit rule active"),
            );
            self.close_gaps(exec_sensor::SENSOR, &["no_exec_rule"])?;
        }
        Ok(())
    }

    /// Self-test deadline, event loss and sensor failure.
    pub(crate) fn check_exec_sensor(&mut self) -> Result<()> {
        let Some(exec) = self.exec.as_mut() else {
            return Ok(());
        };
        let now_i = Instant::now();
        let s = exec.stats.snapshot();

        let mut problems: Vec<(&str, String)> = Vec::new();
        if let SelfTest::Waiting { deadline, .. } = exec.self_test
            && now_i >= deadline
        {
            exec.self_test = SelfTest::Failed {
                retry_at: now_i + SELF_TEST_RETRY,
            };
            problems.push((
                "no_exec_rule",
                "the audit stream carries no program executions, so the execve audit rule is not loaded \
                 (install auditd and /etc/audit/rules.d/soteria.rules, then run 'augenrules --load')"
                    .into(),
            ));
        }
        let retry = matches!(exec.self_test, SelfTest::Failed { retry_at } if now_i >= retry_at);

        let loss = (s.dropped, s.kernel_overflows);
        if loss != exec.seen_loss {
            let dropped = s.dropped - exec.seen_loss.0;
            let overflows = s.kernel_overflows - exec.seen_loss.1;
            exec.seen_loss = loss;
            exec.last_loss = Some(now_i);
            problems.push((
                "overflow",
                format!(
                    "execution events lost: {dropped} dropped by a full agent queue, {overflows} audit socket overrun(s)"
                ),
            ));
        }
        let loss_recovered = exec
            .last_loss
            .is_some_and(|t| now_i.duration_since(t) >= EXEC_LOSS_GAP);
        if loss_recovered {
            exec.last_loss = None;
        }
        let died = exec.sensor.is_some() && !s.running;
        if died {
            exec.sensor = None;
        }

        for (kind, detail) in problems {
            warn!(sensor = exec_sensor::SENSOR, "{detail}");
            self.open_gap(kind, exec_sensor::SENSOR, None, &detail)?;
            self.health(exec_sensor::SENSOR, "degraded", Some(&detail));
            self.exec_sensor_state = "degraded".into();
        }
        if loss_recovered {
            self.close_gaps(exec_sensor::SENSOR, &["overflow"])?;
        }
        if died {
            let detail = s
                .failure
                .unwrap_or_else(|| "execution sensor stopped unexpectedly".into());
            error!(sensor = exec_sensor::SENSOR, "{detail}");
            self.exec_sensor_state = "failed".into();
            self.health(exec_sensor::SENSOR, "failed", Some(&detail));
            self.open_gap("sensor_down", exec_sensor::SENSOR, None, &detail)?;
            alerts::record_event(
                self.store.connection(),
                "agent",
                "sensor.failed",
                Severity::High,
                None,
                &json!({ "sensor": exec_sensor::SENSOR, "detail": detail }),
            )?;
        } else if retry {
            self.start_self_test();
        }
        Ok(())
    }

    /// Feed executions directly (tests, and replay of recorded events).
    pub fn handle_exec(&mut self, ev: &ExecEvent) -> Result<crate::exec::Handled> {
        let monitor = match self.exec.as_mut() {
            Some(e) => &mut e.monitor,
            None => {
                let m = ExecMonitor::new(
                    self.config.execution.clone(),
                    self.hostname.clone(),
                    self.config.alerts.minimum_severity,
                );
                self.spare_monitor.get_or_insert(m)
            }
        };
        let handled = monitor.handle(&self.store, self.baseline, ev)?;
        self.executions_processed += 1;
        Ok(handled)
    }
}
