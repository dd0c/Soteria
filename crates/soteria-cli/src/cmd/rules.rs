//! `soteria rules`: the detection rules in effect (SRS 6, FR-021).

use serde::Serialize;
use soteria_core::ExitStatus;
use soteria_rules::{Matcher, Rule, RuleSet};

use crate::cli::{GlobalArgs, RulesCommand};
use crate::context::load_config;
use crate::output::{CmdResult, Failure, Output, Tone};

#[derive(Serialize)]
struct Listing<'a> {
    directory: &'a std::path::Path,
    files: &'a [std::path::PathBuf],
    rules: Vec<&'a Rule>,
}

pub fn run(cmd: &RulesCommand, global: &GlobalArgs, out: &Output) -> CmdResult {
    let (config, _) = load_config(&global.config)?;
    let dir = &config.general.rules_directory;
    let set = RuleSet::load(dir).map_err(|e| {
        Failure::new(ExitStatus::ConfigInvalid, e.to_string())
            .hint("fix the rule files; the daemon refuses to start with invalid rules")
    })?;
    match cmd {
        RulesCommand::List => {
            let listing = Listing {
                directory: dir,
                files: &set.files,
                rules: set.iter().collect(),
            };
            if out.json {
                out.print_json(&listing);
                return Ok(ExitStatus::Ok);
            }
            println!(
                "{}",
                out.paint(
                    Tone::Bold,
                    &format!(
                        "{:<12}  {:<10}  {:<8}  {:<8}  {:<9}  TITLE",
                        "ID", "ON", "ORIGIN", "STATE", "SEVERITY"
                    )
                )
            );
            for r in &listing.rules {
                let state = if r.enabled {
                    out.paint(Tone::Good, &format!("{:<8}", "enabled"))
                } else {
                    out.paint(Tone::Dim, &format!("{:<8}", "disabled"))
                };
                println!(
                    "{:<12}  {:<10}  {:<8}  {}  {:<9}  {}{}",
                    r.id,
                    r.category.as_str(),
                    r.origin.as_str(),
                    state,
                    r.severity.map(|s| s.as_str()).unwrap_or("varies"),
                    r.title,
                    if r.file.is_some() && r.origin == soteria_rules::Origin::Builtin {
                        " (overridden)"
                    } else {
                        ""
                    }
                );
            }
            if set.files.is_empty() {
                println!("No administrator rule files in {}.", dir.display());
            } else {
                println!(
                    "Administrator rules from: {}",
                    set.files
                        .iter()
                        .map(|f| f.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            Ok(ExitStatus::Ok)
        }
        RulesCommand::Show { id } => {
            let r = set.get(&id.to_uppercase()).ok_or_else(|| {
                Failure::new(
                    ExitStatus::Usage,
                    format!("no rule '{id}'; see 'soteria rules list'"),
                )
            })?;
            if out.json {
                out.print_json(r);
                return Ok(ExitStatus::Ok);
            }
            println!(
                "{}",
                out.paint(Tone::Bold, &format!("Rule {}: {}", r.id, r.title))
            );
            println!("Applies to:     {}", r.category.as_str());
            println!("Origin:         {}", r.origin.as_str());
            println!(
                "State:          {}",
                if r.enabled { "enabled" } else { "disabled" }
            );
            match (r.severity, &r.severity_note) {
                (Some(s), _) => println!("Severity:       {s}"),
                (None, Some(n)) => println!("Severity:       varies: {n}"),
                (None, None) => println!("Severity:       varies"),
            }
            if let Some(f) = &r.file {
                println!("Defined in:     {}", f.display());
            }
            println!("Fires when:     {}", r.description);
            if let Some(reason) = &r.reason {
                println!("Alert reason:   {reason}");
            }
            match &r.matcher {
                Some(Matcher::File(m)) => {
                    println!("Paths:          {}", m.paths.join(", "));
                    if !m.changes.is_empty() {
                        println!("Changes:        {}", m.changes.join(", "));
                    }
                }
                Some(Matcher::Execution(m)) => {
                    for (name, v) in [
                        ("Programs", m.programs.join(", ")),
                        ("Parents", m.parents.join(", ")),
                        (
                            "UIDs",
                            m.uids
                                .iter()
                                .map(u32::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                        ("Classifications", m.classifications.join(", ")),
                        ("Arguments", m.arguments.join(", ")),
                    ] {
                        if !v.is_empty() {
                            println!("{:<16}{v}", format!("{name}:"));
                        }
                    }
                }
                None => {}
            }
            println!("Investigation:  {}", r.recommendation);
            Ok(ExitStatus::Ok)
        }
        RulesCommand::Validate => {
            let admin = set
                .iter()
                .filter(|r| r.origin == soteria_rules::Origin::Admin)
                .count();
            let overridden = set
                .iter()
                .filter(|r| r.origin == soteria_rules::Origin::Builtin && r.file.is_some())
                .count();
            if out.json {
                out.print_json(&serde_json::json!({
                    "valid": true,
                    "directory": dir,
                    "files": set.files,
                    "admin_rules": admin,
                    "overrides": overridden,
                }));
            } else {
                println!(
                    "Rules are {}: {} file(s), {admin} administrator rule(s), {overridden} built-in rule(s) overridden.",
                    out.paint(Tone::Good, "valid"),
                    set.files.len()
                );
                println!("Restart the daemon to apply changes: systemctl restart soteria");
            }
            Ok(ExitStatus::Ok)
        }
    }
}
