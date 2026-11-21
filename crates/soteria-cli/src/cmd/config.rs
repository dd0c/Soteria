//! `soteria config` (FR-043).

use serde::Serialize;
use soteria_config::{Config, IssueLevel, ValidateOptions, has_errors};
use soteria_core::ExitStatus;

use crate::cli::{ConfigCommand, GlobalArgs};
use crate::context::config_failure;
use crate::output::{CmdResult, Output, Tone};

pub fn run(cmd: &ConfigCommand, global: &GlobalArgs, out: &Output) -> CmdResult {
    match cmd {
        ConfigCommand::Default => {
            if out.json {
                out.print_json(&Config::default());
            } else {
                print!("{}", soteria_config::DEFAULT_CONFIG_TOML);
            }
            Ok(ExitStatus::Ok)
        }
        ConfigCommand::Show => {
            let config = Config::load(&global.config).map_err(config_failure)?;
            if out.json {
                out.print_json(&config);
            } else {
                println!("# Effective configuration from {}", global.config.display());
                print!("{}", config.to_toml());
            }
            Ok(ExitStatus::Ok)
        }
        ConfigCommand::Validate => validate(global, out),
        ConfigCommand::TestNotifications => test_notifications(global, out),
    }
}

fn validate(global: &GlobalArgs, out: &Output) -> CmdResult {
    let config = Config::load(&global.config).map_err(config_failure)?;
    let mut issues = config.validate(ValidateOptions::default());
    // Administrator rules are part of the configuration (FR-043).
    if let Err(e) = soteria_rules::RuleSet::load(&config.general.rules_directory) {
        for p in e.0 {
            issues.insert(
                0,
                soteria_config::Issue {
                    level: IssueLevel::Error,
                    field: format!("rules {}", p.file.display()),
                    message: p.message,
                },
            );
        }
    }
    let valid = !has_errors(&issues);
    let warnings = issues
        .iter()
        .filter(|i| i.level == IssueLevel::Warning)
        .count();

    if out.json {
        #[derive(Serialize)]
        struct Report<'a> {
            path: &'a std::path::Path,
            valid: bool,
            issues: &'a [soteria_config::Issue],
        }
        out.print_json(&Report {
            path: &global.config,
            valid,
            issues: &issues,
        });
    } else {
        for issue in &issues {
            let tone = match issue.level {
                IssueLevel::Error => Tone::Bad,
                IssueLevel::Warning => Tone::Warn,
                IssueLevel::Note => Tone::Dim,
            };
            println!(
                "{} {}: {}",
                out.paint(tone, &format!("{:<7}", issue.level.to_string())),
                issue.field,
                issue.message
            );
        }
        if valid {
            println!(
                "{} is {}{}",
                global.config.display(),
                out.paint(Tone::Good, "valid"),
                if warnings > 0 {
                    format!(" ({warnings} warning(s))")
                } else {
                    String::new()
                }
            );
        } else {
            println!(
                "{} is {}",
                global.config.display(),
                out.paint(Tone::Bad, "invalid")
            );
        }
    }

    Ok(if !valid {
        ExitStatus::ConfigInvalid
    } else if warnings > 0 {
        ExitStatus::Findings
    } else {
        ExitStatus::Ok
    })
}

/// Send one test message per enabled channel, from this process.
fn test_notifications(global: &GlobalArgs, out: &Output) -> CmdResult {
    let config = Config::load(&global.config).map_err(config_failure)?;
    let issues = config.validate(ValidateOptions::default());
    if has_errors(&issues) {
        return Err(crate::output::Failure::new(
            ExitStatus::ConfigInvalid,
            "the configuration is invalid; run 'soteria config validate'",
        ));
    }
    let host = soteria_platform::hostname();
    let note = soteria_notify::AlertNote {
        id: 0,
        uuid: "00000000-0000-0000-0000-000000000000".into(),
        created_at: soteria_store::now(),
        severity: "info".into(),
        alert_type: "test".into(),
        status: "open".into(),
        hostname: host.clone(),
        object: None,
        rule_id: "TEST".into(),
        reason: "Test notification sent by 'soteria config test-notifications'.".into(),
        recommendation: "No action needed.".into(),
        incident_id: None,
    };
    let mut results = Vec::new();
    if config.alerts.email {
        let (subject, body) = soteria_notify::email_text(&host, std::slice::from_ref(&note));
        let r = soteria_notify::send_email(&config.notifications.email, &host, &subject, &body);
        results.push(("email", r.map_err(|e| e.to_string())));
    }
    if config.alerts.webhook {
        let body = soteria_notify::webhook_body(&host, std::slice::from_ref(&note));
        let r = soteria_notify::post_webhook(&config.notifications.webhook, &body);
        results.push(("webhook", r.map_err(|e| e.to_string())));
    }
    let failed = results.iter().any(|(_, r)| r.is_err());
    if out.json {
        let list: Vec<_> = results
            .iter()
            .map(|(c, r)| serde_json::json!({ "channel": c, "delivered": r.is_ok(), "error": r.as_ref().err() }))
            .collect();
        out.print_json(&serde_json::json!({ "channels": list }));
    } else if results.is_empty() {
        println!("No notification channel is enabled (alerts.email and alerts.webhook are off).");
    } else {
        for (c, r) in &results {
            match r {
                Ok(()) => println!("{c}: {}", out.paint(Tone::Good, "delivered")),
                Err(e) => println!("{c}: {} ({e})", out.paint(Tone::Bad, "failed")),
            }
        }
    }
    Ok(if failed {
        ExitStatus::Findings
    } else {
        ExitStatus::Ok
    })
}
