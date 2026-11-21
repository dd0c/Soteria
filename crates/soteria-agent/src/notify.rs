//! Delivery of new alerts by email and webhook (FR-031).
//!
//! Each channel keeps a cursor (the last alert id delivered) in the
//! database, so nothing is lost or repeated across restarts, and delivery
//! is at least once. Sending happens on a separate thread: a slow or
//! unreachable server never holds up monitoring. Failures are retried
//! with backoff and recorded as `notification.failed` events.

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use soteria_config::Config;
use soteria_core::Severity;
use soteria_notify::AlertNote;
use soteria_store::Store;
use tracing::{info, warn};

/// Alerts per message or request at most.
const BATCH: i64 = 50;
const FIRST_RETRY: Duration = Duration::from_secs(30);
const MAX_RETRY: Duration = Duration::from_secs(1800);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Email,
    Webhook,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Email => "email",
            Kind::Webhook => "webhook",
        }
    }

    fn cursor_key(self) -> String {
        format!("notified_through_{}", self.as_str())
    }
}

struct Job {
    channel: usize,
    alerts: Vec<AlertNote>,
}

struct Done {
    channel: usize,
    last_id: i64,
    count: usize,
    result: Result<(), String>,
}

struct Channel {
    kind: Kind,
    minimum: Severity,
    busy: bool,
    retry_at: Option<Instant>,
    failures: u32,
}

pub(crate) struct Notifier {
    channels: Vec<Channel>,
    jobs: Option<SyncSender<Job>>,
    done: Receiver<Done>,
    thread: Option<JoinHandle<()>>,
}

impl Notifier {
    /// Start the delivery thread when any channel is enabled.
    pub(crate) fn start(
        config: &Config,
        hostname: &str,
        store: &Store,
    ) -> rusqlite::Result<Option<Notifier>> {
        let mut channels = Vec::new();
        if config.alerts.email {
            channels.push(Channel {
                kind: Kind::Email,
                minimum: config
                    .notifications
                    .email
                    .minimum_severity
                    .max(config.alerts.minimum_severity),
                busy: false,
                retry_at: None,
                failures: 0,
            });
        }
        if config.alerts.webhook {
            channels.push(Channel {
                kind: Kind::Webhook,
                minimum: config
                    .notifications
                    .webhook
                    .minimum_severity
                    .max(config.alerts.minimum_severity),
                busy: false,
                retry_at: None,
                failures: 0,
            });
        }
        for kind in [Kind::Email, Kind::Webhook] {
            let enabled = channels.iter().any(|c| c.kind == kind);
            let conn = store.connection();
            if enabled {
                // A new channel starts with alerts raised from now on, not
                // the whole history.
                conn.execute(
                    "INSERT OR IGNORE INTO meta (key, value) SELECT ?1, COALESCE(MAX(id), 0) FROM alerts",
                    [kind.cursor_key()],
                )?;
                store
                    .record_health(kind.as_str(), "running", Some("notifications enabled"))
                    .map_err(store_err)?;
            } else {
                // Forget the cursor, so re-enabling does not send a backlog.
                conn.execute("DELETE FROM meta WHERE key = ?1", [kind.cursor_key()])?;
                store
                    .record_health(kind.as_str(), "disabled", Some("disabled by configuration"))
                    .map_err(store_err)?;
            }
        }
        if channels.is_empty() {
            return Ok(None);
        }
        let (jobs, job_rx) = sync_channel::<Job>(channels.len());
        let (done_tx, done) = sync_channel::<Done>(channels.len());
        let email = config.notifications.email.clone();
        let webhook = config.notifications.webhook.clone();
        let kinds: Vec<Kind> = channels.iter().map(|c| c.kind).collect();
        let host = hostname.to_owned();
        let thread = std::thread::Builder::new()
            .name("soteria-notify".into())
            .spawn(move || {
                for job in job_rx {
                    let last_id = job.alerts.last().map(|a| a.id).unwrap_or_default();
                    let result = match kinds[job.channel] {
                        Kind::Email => {
                            let (subject, body) = soteria_notify::email_text(&host, &job.alerts);
                            soteria_notify::send_email(&email, &host, &subject, &body)
                        }
                        Kind::Webhook => soteria_notify::post_webhook(
                            &webhook,
                            &soteria_notify::webhook_body(&host, &job.alerts),
                        ),
                    };
                    let done = Done {
                        channel: job.channel,
                        last_id,
                        count: job.alerts.len(),
                        result: result.map_err(|e| e.to_string()),
                    };
                    if done_tx.send(done).is_err() {
                        break;
                    }
                }
            })
            .expect("can spawn the notification thread");
        Ok(Some(Notifier {
            channels,
            jobs: Some(jobs),
            done,
            thread: Some(thread),
        }))
    }

    /// Record finished deliveries and hand out new alerts.
    pub(crate) fn step(&mut self, store: &Store) -> rusqlite::Result<()> {
        let conn = store.connection();
        loop {
            let d = match self.done.try_recv() {
                Ok(d) => d,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            };
            let ch = &mut self.channels[d.channel];
            ch.busy = false;
            let name = ch.kind.as_str();
            match d.result {
                Ok(()) => {
                    conn.execute(
                        "UPDATE meta SET value = ?2 WHERE key = ?1",
                        params![ch.kind.cursor_key(), d.last_id.to_string()],
                    )?;
                    if ch.failures > 0 {
                        info!(channel = name, "{name} notifications delivered again");
                    }
                    ch.failures = 0;
                    ch.retry_at = None;
                    store
                        .record_health(
                            name,
                            "running",
                            Some(&format!("delivered {} alert(s)", d.count)),
                        )
                        .map_err(store_err)?;
                }
                Err(e) => {
                    ch.failures += 1;
                    let wait = FIRST_RETRY
                        .saturating_mul(1 << (ch.failures - 1).min(10))
                        .min(MAX_RETRY);
                    ch.retry_at = Some(Instant::now() + wait);
                    let detail = format!(
                        "{name} delivery failed: {e}; retrying in {}s",
                        wait.as_secs()
                    );
                    warn!(channel = name, "{detail}");
                    store
                        .record_health(name, "failing", Some(&detail))
                        .map_err(store_err)?;
                    crate::alerts::record_event(
                        conn,
                        "agent",
                        "notification.failed",
                        Severity::Medium,
                        None,
                        &json!({ "channel": name, "error": e, "attempt": ch.failures, "alerts": d.count }),
                    )?;
                }
            }
        }
        let now = Instant::now();
        for (i, ch) in self.channels.iter_mut().enumerate() {
            if ch.busy || ch.retry_at.is_some_and(|t| now < t) {
                continue;
            }
            let cursor = cursor(conn, ch.kind)?;
            let alerts = pending(conn, cursor, ch.minimum)?;
            if alerts.is_empty() {
                // Skip past alerts below this channel's minimum.
                let max: i64 =
                    conn.query_row("SELECT COALESCE(MAX(id), 0) FROM alerts", [], |r| r.get(0))?;
                if max > cursor {
                    conn.execute(
                        "UPDATE meta SET value = ?2 WHERE key = ?1",
                        params![ch.kind.cursor_key(), max.to_string()],
                    )?;
                }
                continue;
            }
            if let Some(tx) = &self.jobs
                && tx.try_send(Job { channel: i, alerts }).is_ok()
            {
                ch.busy = true;
            }
        }
        Ok(())
    }

    /// Stop the thread; an attempt in progress is abandoned at its timeout.
    pub(crate) fn shutdown(&mut self) {
        self.jobs = None;
        if let Some(t) = self.thread.take()
            && t.is_finished()
        {
            let _ = t.join();
        }
    }
}

fn store_err(e: soteria_store::StoreError) -> rusqlite::Error {
    match e {
        soteria_store::StoreError::Sqlite(e) => e,
        other => rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
            other.to_string(),
        ))),
    }
}

fn cursor(conn: &Connection, kind: Kind) -> rusqlite::Result<i64> {
    Ok(conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [kind.cursor_key()],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0))
}

/// Alerts after `cursor` at or above `minimum`, oldest first.
fn pending(conn: &Connection, cursor: i64, minimum: Severity) -> rusqlite::Result<Vec<AlertNote>> {
    let severities: Vec<&str> = Severity::ALL
        .iter()
        .filter(|s| **s >= minimum)
        .map(|s| s.as_str())
        .collect();
    let list = format!(",{},", severities.join(","));
    let mut st = conn.prepare_cached(
        "SELECT id, uuid, created_at, severity, type, status, hostname, object, rule_id, reason, recommendation,
                incident_id
         FROM alerts
         WHERE id > ?1 AND instr(?2, ',' || severity || ',') > 0 AND status != 'suppressed'
         ORDER BY id LIMIT ?3",
    )?;
    st.query_map(params![cursor, list, BATCH], |r| {
        Ok(AlertNote {
            id: r.get(0)?,
            uuid: r.get(1)?,
            created_at: r.get(2)?,
            severity: r.get(3)?,
            alert_type: r.get(4)?,
            status: r.get(5)?,
            hostname: r.get(6)?,
            object: r.get(7)?,
            rule_id: r.get(8)?,
            reason: r.get(9)?,
            recommendation: r.get(10)?,
            incident_id: r.get(11)?,
        })
    })?
    .collect()
}
