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
    }
}

fn validate(global: &GlobalArgs, out: &Output) -> CmdResult {
    let config = Config::load(&global.config).map_err(config_failure)?;
    let issues = config.validate(ValidateOptions::default());
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
