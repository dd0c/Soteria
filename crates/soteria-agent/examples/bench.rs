//! Performance benchmark (SRS 12.4, NFR-001..NFR-006).
//!
//!     cargo run --release -p soteria-agent --example bench -- [files] [changes] [executions]
//!
//! Builds a synthetic tree in a temporary directory and measures:
//! - inventory: a full scan (discovery, metadata, SHA-256) of the tree;
//! - event latency: time from writing a file to its alert, for a burst of
//!   changes, through the real inotify sensor and agent loop;
//! - execution handling: synthetic audit events per second;
//! - idle CPU: agent CPU time over ten idle seconds;
//! - memory: the process's peak resident size.
//!
//! Results are printed as Markdown, ready for docs/BENCHMARKS.md.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use soteria_agent::{Agent, Options};
use soteria_config::Config;
use soteria_integrity::baseline::{self, Approver};
use soteria_integrity::keys;
use soteria_integrity::scan::{self, ScanTarget};
use soteria_inventory::Scope;
use soteria_sensors::audit::ExecEvent;
use soteria_store::Store;

fn arg(n: usize, default: usize) -> usize {
    std::env::args()
        .nth(n)
        .and_then(|a| a.parse().ok())
        .unwrap_or(default)
}

/// Peak resident memory and CPU time of all threads of this process.
fn usage() -> (u64, Duration) {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let hwm_kb = status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap_or(0);
    // CPU time of every thread, in nanoseconds (first field of schedstat).
    let mut ns = 0u64;
    if let Ok(tasks) = fs::read_dir("/proc/self/task") {
        for t in tasks.flatten() {
            ns += fs::read_to_string(t.path().join("schedstat"))
                .ok()
                .and_then(|s| s.split_whitespace().next()?.parse().ok())
                .unwrap_or(0);
        }
    }
    (hwm_kb, Duration::from_nanos(ns))
}

fn make_tree(root: &Path, files: usize) -> u64 {
    let mut bytes = 0;
    for i in 0..files {
        let dir = root.join(format!("d{:03}", i % 200));
        if i < 200 {
            fs::create_dir_all(&dir).unwrap();
        }
        // Mixed sizes: mostly small configuration-like files, some larger.
        let size = match i % 50 {
            0 => 1 << 20,
            1..=5 => 64 << 10,
            _ => 2 << 10,
        };
        let content = vec![(i % 251) as u8; size];
        fs::write(dir.join(format!("f{i}")), &content).unwrap();
        bytes += size as u64;
    }
    bytes
}

fn main() {
    let files = arg(1, 50_000);
    let changes = arg(2, 1_000);
    let executions = arg(3, 5_000);

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let t = Instant::now();
    let bytes = make_tree(&root, files);
    eprintln!(
        "tree: {files} files, {} MiB in {:?}",
        bytes >> 20,
        t.elapsed()
    );

    let db = dir.path().join("soteria.db");
    let sk = dir.path().join("baseline.key");
    let pk = dir.path().join("baseline.pub");
    keys::generate(&sk, &pk).unwrap();
    let mut config = Config::default();
    config.general.database = db.clone();
    config.general.rules_directory = dir.path().join("rules.d");
    config.paths.include = vec![root.clone()];
    config.paths.exclude = vec![];
    config.paths.persistence = vec![];
    config.paths.own_files = false;
    config.baseline.signing_key = sk.clone();
    config.baseline.public_key = pk;
    config.alerts.journal = false;
    config.execution.unusual_paths = vec![];

    // Inventory.
    let (mut store, _) = Store::create_or_migrate(&db).unwrap();
    let scope = Scope {
        include: vec![root.clone()],
        exclude: vec![],
        optional: vec![],
    };
    let cpu0 = usage().1;
    let t = Instant::now();
    let report = scan::run(&mut store, &scope, &ScanTarget::Full, "full").unwrap();
    let scan_time = t.elapsed();
    let scan_cpu = usage().1 - cpu0;
    let draft = baseline::create_draft(&mut store, "bench", None).unwrap();
    let signer = keys::load_signer(&sk).unwrap();
    baseline::approve(
        &mut store,
        draft.version,
        &signer,
        &Approver {
            name: "bench".into(),
            uid: 0,
        },
    )
    .unwrap();
    drop(store);
    let db_size = fs::metadata(&db).map(|m| m.len()).unwrap_or(0);

    // Agent with the real inotify sensor.
    let (store, _) = Store::create_or_migrate(&db).unwrap();
    let options = Options {
        startup_scan: false,
        exec_sensor: false,
        ..Options::default()
    };
    let mut agent = Agent::start(config, store, options).unwrap();
    for _ in 0..10 {
        agent.step(Duration::from_millis(50)).unwrap();
    }

    // Idle CPU.
    let (_, c0) = usage();
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        agent.step(Duration::from_millis(500)).unwrap();
    }
    let idle_cpu = (usage().1 - c0).as_secs_f64() / t.elapsed().as_secs_f64() * 100.0;

    // Event latency: change files, wait for every alert.
    let targets: Vec<PathBuf> = (0..changes)
        .map(|i| {
            root.join(format!(
                "d{:03}/f{}",
                i % 200,
                i * (files / changes.max(1)).max(1) % files
            ))
        })
        .collect();
    let count = |agent: &Agent| -> i64 {
        agent
            .store()
            .connection()
            .query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))
            .unwrap()
    };
    let before = count(&agent);
    let t = Instant::now();
    for p in &targets {
        fs::write(p, b"changed").unwrap();
    }
    let written = t.elapsed();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut distinct = targets.clone();
    distinct.sort();
    distinct.dedup();
    while count(&agent) - before < distinct.len() as i64 && Instant::now() < deadline {
        agent.step(Duration::from_millis(20)).unwrap();
    }
    let burst = t.elapsed();
    let raised = count(&agent) - before;

    // Single-change latency.
    let mut single = Vec::new();
    for i in 0..20 {
        let p = root.join(format!("d{:03}/single{i}", i % 200));
        let before = count(&agent);
        let t = Instant::now();
        fs::write(&p, b"new").unwrap();
        while count(&agent) == before && t.elapsed() < Duration::from_secs(10) {
            agent.step(Duration::from_millis(5)).unwrap();
        }
        single.push(t.elapsed());
    }
    single.sort();

    // Execution handling, committed in batches of 256 (the sensor commits whatever is queued, up to 5,000).
    let exe = targets[0].clone();
    let t = Instant::now();
    for i in 0..executions {
        if i % 256 == 0 {
            if i > 0 {
                agent.store().connection().execute_batch("COMMIT").unwrap();
            }
            agent
                .store()
                .connection()
                .execute_batch("BEGIN IMMEDIATE")
                .unwrap();
        }
        let ev = ExecEvent {
            time_ms: 1_795_285_908_304 + i as i64,
            serial: i as u64,
            pid: 10_000 + i as u32,
            ppid: 1,
            uid: 1000,
            euid: 1000,
            gid: 1000,
            auid: Some(1000),
            session: Some(1),
            tty: None,
            comm: Some("f".into()),
            exe: Some(exe.clone()),
            path: Some(exe.clone()),
            cwd: Some(PathBuf::from("/")),
            argv: vec![b"f".to_vec(), b"--flag".to_vec()],
            key: Some("soteria_exec".into()),
        };
        agent.handle_exec(&ev).unwrap();
    }
    if executions > 0 {
        agent.store().connection().execute_batch("COMMIT").unwrap();
    }
    let exec_rate = executions as f64 / t.elapsed().as_secs_f64();
    let (hwm_kb, _) = usage();
    agent.shutdown();

    let ms = |d: Duration| format!("{:.0} ms", d.as_secs_f64() * 1000.0);
    println!("| Measure | Result |");
    println!("|---|---|");
    println!(
        "| Full scan of {} objects ({} MiB) | {} ({:.0} objects/s, {} CPU) |",
        report.checked,
        bytes >> 20,
        ms(scan_time),
        report.checked as f64 / scan_time.as_secs_f64(),
        ms(scan_cpu)
    );
    println!(
        "| Database size after baseline | {:.1} MiB |",
        db_size as f64 / 1048576.0
    );
    println!("| Idle agent CPU | {idle_cpu:.2} % |");
    println!(
        "| Single change to alert (median / max of 20) | {} / {} |",
        ms(single[single.len() / 2]),
        ms(*single.last().unwrap())
    );
    println!(
        "| Burst of {} changes (written in {}) to all alerts | {} ({raised} alerts) |",
        distinct.len(),
        ms(written),
        ms(burst)
    );
    println!("| Execution events handled | {exec_rate:.0} per second |");
    println!("| Peak memory (whole process) | {} MiB |", hwm_kb / 1024);
}
