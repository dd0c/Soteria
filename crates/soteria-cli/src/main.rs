//! `soteria`: CLI and daemon entry point (SRS 6, 8.1).

mod cli;
mod cmd;
mod context;
mod daemon;
mod health;
mod output;
mod sdnotify;

use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command};
use cmd::unavailable::{self, DETECTION, EXECUTION, INTEGRITY, INVENTORY};
use output::{CmdResult, Output};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let out = Output::new(cli.json_output(), cli.global.color);
    let status = match dispatch(&cli, &out) {
        Ok(status) => status,
        Err(failure) => {
            failure.report(&out);
            failure.status
        }
    };
    ExitCode::from(status.code())
}

impl Cli {
    fn json_output(&self) -> bool {
        // The daemon logs to the journal; --json does not apply to it.
        self.global.json && !matches!(self.command, Command::Daemon)
    }
}

fn dispatch(cli: &Cli, out: &Output) -> CmdResult {
    let g = &cli.global;
    match &cli.command {
        Command::Status => cmd::status::run(g, out),
        Command::Init(args) => cmd::init::run(args, g, out),
        Command::Config(c) => cmd::config::run(c, g, out),
        Command::Verify(args) => cmd::verify::run(args, g, out),
        Command::Daemon => daemon::run(g),
        Command::Scan(_) => unavailable::run("scan", INVENTORY),
        Command::Baseline(_) => unavailable::run("baseline", INVENTORY),
        Command::Inventory(_) => unavailable::run("inventory", INVENTORY),
        Command::Events(_) => unavailable::run("events", INTEGRITY),
        Command::Processes(_) => unavailable::run("processes", EXECUTION),
        Command::Alerts(_) => unavailable::run("alerts", DETECTION),
        Command::Rules(_) => unavailable::run("rules", DETECTION),
        Command::Report(_) => unavailable::run("report", DETECTION),
    }
}
