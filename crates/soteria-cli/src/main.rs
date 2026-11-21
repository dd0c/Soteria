//! `soteria`: CLI and daemon entry point (SRS 6, 8.1).

mod cli;
mod cmd;
mod context;
mod daemon;
mod display;
mod health;
mod output;
mod query;
mod sdnotify;

use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command};
use cmd::unavailable::{self, DETECTION, EXECUTION};
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
        Command::Scan(args) => cmd::scan::run(args, g, out),
        Command::Baseline(c) => cmd::baseline::run(c, g, out),
        Command::Inventory(args) => cmd::inventory::run(args, g, out),
        Command::Events(args) => cmd::events::run(args, g, out),
        Command::Processes(_) => unavailable::run("processes", EXECUTION),
        Command::Alerts(c) => cmd::alerts::run(c, g, out),
        Command::Rules(_) => unavailable::run("rules", DETECTION),
        Command::Report(_) => unavailable::run("report", DETECTION),
    }
}
