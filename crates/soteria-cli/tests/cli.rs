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
        env.write_config("");
        env
    }

    fn db(&self) -> PathBuf {
        self.dir.path().join("state").join("soteria.db")
    }

    /// Default configuration pointing at a temporary database, plus `extra`
    /// TOML appended to the [alerts] table (the last table in the file).
    fn write_config(&self, extra: &str) {
        let text = soteria_default_config()
            .replace("/var/lib/soteria/soteria.db", self.db().to_str().unwrap());
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
    assert_eq!(v["indexed_files"], 0);

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
        vec!["scan"],
        vec!["baseline", "list"],
        vec!["inventory"],
        vec!["events"],
        vec!["alerts", "list"],
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
