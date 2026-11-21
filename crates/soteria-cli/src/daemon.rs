//! `soteria daemon`: the long-running agent started by `soteria.service`.
//!
//! The daemon owns the service lifecycle: strict configuration validation
//! before start, database checks, recording of start/stop and interrupted
//! scans, a heartbeat for `status`, and systemd readiness and watchdog
//! notifications. Monitoring itself is done by [`soteria_agent::Agent`],
//! which this loop drives.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use soteria_agent::{Agent, Options};
use soteria_core::ExitStatus;
use soteria_store::Store;
use tracing::{error, info, warn};

use crate::cli::GlobalArgs;
use crate::context::{load_config, store_failure};
use crate::health::{HEARTBEAT_INTERVAL_SECS, HEARTBEAT_KEY, STALL_LIMIT_SECS};
use crate::output::{CmdResult, Failure};
use crate::sdnotify;

const AGENT: &str = "agent";

pub fn run(global: &GlobalArgs) -> CmdResult {
    // Invalid configuration stops the service; it never falls back to a
    // weaker default (FR-043).
    // The failure is printed to stderr by main, which journald captures.
    let (config, issues) = load_config(&global.config)?;
    init_logging(&config.general.log_level);
    for issue in &issues {
        warn!(field = %issue.field, "{}", issue.message);
    }

    // The daemon owns the database: after a package upgrade it applies
    // pending schema migrations itself.
    let (store, migrated) =
        Store::open_and_migrate(&config.general.database).map_err(store_failure)?;
    if !migrated.is_empty() {
        info!(versions = ?migrated, "database schema migrated");
    }

    match store.integrity_check() {
        Ok(p) if p.is_empty() => {}
        Ok(p) => {
            let msg = format!("database integrity check failed: {}", p.join("; "));
            error!("{msg}");
            return Err(Failure::new(ExitStatus::IntegrityFailure, msg));
        }
        Err(e) => return Err(store_failure(e)),
    }

    let interrupted = store.mark_interrupted_scans().map_err(store_failure)?;
    if interrupted > 0 {
        warn!(
            count = interrupted,
            "found scans interrupted by an unexpected stop"
        );
        record(
            &store,
            "recovered",
            Some(&format!("{interrupted} interrupted scan(s) marked")),
        );
    }

    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&stop)).map_err(|e| {
            Failure::new(
                ExitStatus::Internal,
                format!("cannot install signal handler: {e}"),
            )
        })?;
    }

    // Starting the agent verifies the approved baseline's seal (FR-032):
    // a failed seal raises a critical alert but does not stop the agent,
    // which must keep reporting.
    let mut agent = Agent::start(config, store, Options::default()).map_err(|e| match e {
        soteria_agent::AgentError::Rules(e) => {
            Failure::new(ExitStatus::ConfigInvalid, e.to_string())
                .hint("check them with 'soteria rules validate'")
        }
        e => Failure::new(ExitStatus::Internal, format!("cannot start agent: {e}")),
    })?;

    record(
        agent.store(),
        "running",
        Some(&format!("version {}", soteria_core::VERSION)),
    );
    heartbeat(agent.store());
    agent.write_health();
    sdnotify::notify("READY=1\nSTATUS=Monitoring service running");
    info!(version = soteria_core::VERSION, "soteria agent started");

    // A full scan holds the database for its whole duration, so the systemd
    // watchdog is fed from a separate thread for as long as the main loop
    // keeps making progress. A loop stuck for longer than the stall limit
    // stops feeding it and systemd restarts the service.
    let epoch = Instant::now();
    let progress = Arc::new(AtomicU64::new(0));
    let watchdog = sdnotify::watchdog_interval().map(|w| {
        let (stop, progress) = (Arc::clone(&stop), Arc::clone(&progress));
        std::thread::Builder::new()
            .name("watchdog".into())
            .spawn(move || feed_watchdog(w / 2, epoch, &progress, &stop))
    });

    let beat = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);
    let mut last = Instant::now();
    let mut last_health = Instant::now();
    let mut failures = 0u32;
    while !stop.load(Ordering::Relaxed) {
        match agent.step(Duration::from_millis(250)) {
            Ok(()) => failures = 0,
            Err(e) => {
                failures += 1;
                error!("monitoring step failed: {e}");
                if failures >= MAX_CONSECUTIVE_FAILURES {
                    let msg = format!("giving up after {failures} consecutive failures: {e}");
                    record(agent.store(), "failed", Some(&msg));
                    stop.store(true, Ordering::Relaxed);
                    agent.shutdown();
                    return Err(Failure::new(ExitStatus::Internal, msg));
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        progress.store(epoch.elapsed().as_secs(), Ordering::Relaxed);
        if last.elapsed() >= beat {
            heartbeat(agent.store());
            last = Instant::now();
        }
        if last_health.elapsed() >= HEALTH_INTERVAL {
            agent.write_health();
            last_health = Instant::now();
        }
    }

    sdnotify::notify("STOPPING=1");
    if let Some(Ok(h)) = watchdog {
        let _ = h.join();
    }
    agent.write_health();
    record(agent.store(), "stopped", Some("clean shutdown"));
    agent.shutdown();
    info!("soteria agent stopped");
    Ok(ExitStatus::Ok)
}

/// How often the agent's health snapshot is refreshed for `status`.
const HEALTH_INTERVAL: Duration = Duration::from_secs(2);

/// Consecutive failed steps (for example a database that stays locked)
/// before the daemon exits and lets systemd restart it.
const MAX_CONSECUTIVE_FAILURES: u32 = 30;

fn feed_watchdog(tick: Duration, epoch: Instant, progress: &AtomicU64, stop: &AtomicBool) {
    let mut warned = false;
    while !stop.load(Ordering::Relaxed) {
        let idle = epoch
            .elapsed()
            .as_secs()
            .saturating_sub(progress.load(Ordering::Relaxed));
        if idle <= STALL_LIMIT_SECS as u64 {
            sdnotify::notify("WATCHDOG=1");
            warned = false;
        } else if !warned {
            error!(
                idle_secs = idle,
                "monitoring loop is stalled; no longer feeding the watchdog"
            );
            warned = true;
        }
        // Sleep in short slices so shutdown is prompt.
        let until = Instant::now() + tick;
        while Instant::now() < until && !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn record(store: &Store, state: &str, detail: Option<&str>) {
    record_sensor(store, AGENT, state, detail);
}

fn record_sensor(store: &Store, sensor: &str, state: &str, detail: Option<&str>) {
    if let Err(e) = store.record_health(sensor, state, detail) {
        error!("cannot record {sensor} state '{state}': {e}");
    }
}

fn heartbeat(store: &Store) {
    if let Err(e) = store.set_meta(HEARTBEAT_KEY, &soteria_store::now()) {
        error!("cannot write heartbeat: {e}");
    }
}

fn init_logging(level: &str) {
    // Under systemd, journald adds timestamps itself.
    let under_journald = std::env::var_os("JOURNAL_STREAM").is_some();
    let filter = tracing_subscriber::EnvFilter::try_from_env("SOTERIA_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false);
    let result = if under_journald {
        builder.without_time().with_ansi(false).try_init()
    } else {
        builder.try_init()
    };
    // Already initialized only happens in tests; nothing to do then.
    let _ = result;
}
