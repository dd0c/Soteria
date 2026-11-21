//! `soteria daemon`: the long-running agent started by `soteria.service`.
//!
//! Milestone 1 provides the service lifecycle only: strict configuration
//! validation before start, database checks, recording of start/stop and
//! interrupted scans, a heartbeat for `status`, and systemd readiness and
//! watchdog notifications. Sensors and scanning attach to this loop in later
//! milestones.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use soteria_core::ExitStatus;
use soteria_store::Store;
use tracing::{error, info, warn};

use crate::cli::GlobalArgs;
use crate::context::{BaselineCheck, check_latest_baseline, load_config, store_failure};
use crate::health::{HEARTBEAT_INTERVAL_SECS, HEARTBEAT_KEY};
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

    let store = Store::open(&config.general.database).map_err(store_failure)?;

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

    // Baseline integrity verification at service startup (FR-032). A failed
    // seal does not stop the agent, which must keep reporting, but it is
    // recorded and logged loudly.
    match check_latest_baseline(&store, &config) {
        Ok(BaselineCheck::None) => {
            warn!("no approved baseline; run 'sudo soteria init' to establish one");
            record_sensor(&store, "baseline", "none", None);
        }
        Ok(BaselineCheck::Verified { version }) => {
            info!(version, "approved baseline verified");
            record_sensor(&store, "baseline", "verified", Some(&format!("v{version}")));
        }
        Ok(BaselineCheck::Failed { version, problems }) => {
            let detail = format!("v{version}: {}", problems.join("; "));
            error!("baseline verification FAILED: {detail}");
            record_sensor(&store, "baseline", "failed", Some(&detail));
        }
        Ok(BaselineCheck::Unverifiable { version, reason }) => {
            let detail = format!("v{version}: {reason}");
            error!("baseline cannot be verified: {detail}");
            record_sensor(&store, "baseline", "unverifiable", Some(&detail));
        }
        Err(f) => error!("baseline verification error: {}", f.message),
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

    record(
        &store,
        "running",
        Some(&format!("version {}", soteria_core::VERSION)),
    );
    heartbeat(&store);
    sdnotify::notify("READY=1\nSTATUS=Monitoring service running");
    info!(version = soteria_core::VERSION, database = %config.general.database.display(), "soteria agent started");

    let watchdog = sdnotify::watchdog_interval();
    let beat = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);
    let tick = watchdog.map(|w| (w / 2).min(beat)).unwrap_or(beat);
    let mut last = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(250));
        if last.elapsed() >= tick {
            heartbeat(&store);
            if watchdog.is_some() {
                sdnotify::notify("WATCHDOG=1");
            }
            last = Instant::now();
        }
    }

    sdnotify::notify("STOPPING=1");
    record(&store, "stopped", Some("clean shutdown"));
    info!("soteria agent stopped");
    Ok(ExitStatus::Ok)
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
