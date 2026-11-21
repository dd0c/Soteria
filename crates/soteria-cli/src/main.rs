//! `soteria`: CLI and daemon entry point (SRS 6, 8.1).

/// `print!` and `println!` for this crate: like std's, but when stdout is
/// closed (`soteria alerts list | head`) the process ends quietly with the
/// status a shell reports for SIGPIPE (141), as other Unix tools do,
/// instead of panicking. Defined before the modules so it shadows std's in
/// all of them.
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::output::write_stdout(format_args!($($arg)*))
    };
}

macro_rules! println {
    () => {
        $crate::output::write_stdout(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output::write_stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}

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
        Command::Processes(args) => cmd::processes::run(args, g, out),
        Command::Alerts(c) => cmd::alerts::run(c, g, out),
        Command::Rules(c) => cmd::rules::run(c, g, out),
        Command::Report(c) => cmd::report::run(c, g, out),
    }
}
