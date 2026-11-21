//! Text and JSON output (FR-041, SRS 4.5).

use std::io::{IsTerminal, Write};

use serde::Serialize;
use soteria_core::{CheckState, ExitStatus};

use crate::cli::ColorChoice;

#[derive(Debug, Clone, Copy)]
pub struct Output {
    pub json: bool,
    color: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Dim,
    Bold,
}

impl Output {
    pub fn new(json: bool, choice: ColorChoice) -> Output {
        let color = !json
            && match choice {
                ColorChoice::Always => true,
                ColorChoice::Never => false,
                // Colors only on a terminal, and never when NO_COLOR is set.
                ColorChoice::Auto => {
                    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
                }
            };
        Output { json, color }
    }

    pub fn paint(&self, tone: Tone, text: &str) -> String {
        if !self.color {
            return text.to_owned();
        }
        let code = match tone {
            Tone::Good => "32",
            Tone::Warn => "33",
            Tone::Bad => "31;1",
            Tone::Dim => "2",
            Tone::Bold => "1",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }

    pub fn check(&self, state: CheckState) -> String {
        let tone = match state {
            CheckState::Pass => Tone::Good,
            CheckState::Skipped => Tone::Dim,
            CheckState::Warn => Tone::Warn,
            CheckState::Fail => Tone::Bad,
        };
        self.paint(tone, &state.to_string())
    }

    pub fn print_json<T: Serialize>(&self, value: &T) {
        let mut out = std::io::stdout().lock();
        if let Err(e) = serde_json::to_writer_pretty(&mut out, value)
            .map_err(std::io::Error::from)
            .and_then(|()| writeln!(out))
            .and_then(|()| out.flush())
        {
            exit_on_write_error(e);
        }
    }
}

/// Exit status a shell reports for a process ended by SIGPIPE.
pub const BROKEN_PIPE_EXIT: i32 = 128 + 13;

/// Write to stdout; see the `print!` macro in `main.rs`.
pub fn write_stdout(args: std::fmt::Arguments<'_>) {
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_fmt(args) {
        exit_on_write_error(e);
    }
}

/// End the process for a failed write to stdout.
pub fn exit_on_write_error(e: std::io::Error) -> ! {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(BROKEN_PIPE_EXIT);
    }
    eprintln!("soteria: error: cannot write output: {e}");
    std::process::exit(i32::from(ExitStatus::Internal.code()));
}

/// A command failure with the exit status it maps to.
#[derive(Debug)]
pub struct Failure {
    pub status: ExitStatus,
    pub message: String,
    pub hint: Option<String>,
}

impl Failure {
    pub fn new(status: ExitStatus, message: impl Into<String>) -> Failure {
        Failure {
            status,
            message: message.into(),
            hint: None,
        }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Failure {
        self.hint = Some(hint.into());
        self
    }

    pub fn report(&self, out: &Output) {
        if out.json {
            #[derive(Serialize)]
            struct ErrorBody<'a> {
                status: &'static str,
                exit_code: u8,
                kind: ExitStatus,
                message: &'a str,
                #[serde(skip_serializing_if = "Option::is_none")]
                hint: Option<&'a str>,
            }
            out.print_json(&ErrorBody {
                status: "error",
                exit_code: self.status.code(),
                kind: self.status,
                message: &self.message,
                hint: self.hint.as_deref(),
            });
        } else {
            eprintln!("soteria: error: {}", self.message);
            if let Some(hint) = &self.hint {
                eprintln!("hint: {hint}");
            }
        }
    }
}

pub type CmdResult = Result<ExitStatus, Failure>;
