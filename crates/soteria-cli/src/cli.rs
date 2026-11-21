//! Command-line definition (FR-040, SRS 6).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

const EXIT_CODES_HELP: &str = "\
Exit codes:
  0   success, nothing needs attention
  1   success, findings reported (changes, alerts or coverage gaps)
  2   invalid command-line usage
  3   configuration missing or invalid
  4   database, baseline or self-integrity verification failed
  5   Soteria is not initialized on this host
  6   insufficient privileges
  7   feature unavailable on this platform or in this build
  10  internal error";

#[derive(Debug, Parser)]
#[command(
    name = "soteria",
    version,
    about = "Linux host intrusion detection and integrity monitoring",
    after_help = EXIT_CODES_HELP,
    propagate_version = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Configuration file
    #[arg(
        long,
        global = true,
        env = "SOTERIA_CONFIG",
        value_name = "PATH",
        default_value = soteria_core::DEFAULT_CONFIG_PATH
    )]
    pub config: PathBuf,

    /// Print machine-readable JSON instead of text
    #[arg(long, global = true)]
    pub json: bool,

    /// When to use colors in text output
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto, value_name = "WHEN")]
    pub color: ColorChoice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show protection and monitoring status
    Status,

    /// Run the initial setup: prerequisites, database, inventory and baseline
    Init(InitArgs),

    /// Run integrity scans
    Scan(ScanArgs),

    /// View, compare, approve and manage baseline versions
    #[command(subcommand)]
    Baseline(BaselineCommand),

    /// List indexed objects
    Inventory(InventoryArgs),

    /// Search monitoring events
    Events(EventsArgs),

    /// Search and manage alerts
    #[command(subcommand)]
    Alerts(AlertsCommand),

    /// View execution history
    Processes(ProcessesArgs),

    /// List and inspect detection rules
    #[command(subcommand)]
    Rules(RulesCommand),

    /// Display and validate configuration
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Generate reports
    #[command(subcommand)]
    Report(ReportCommand),

    /// Verify service, database, baseline, sensors and coverage
    Verify(VerifyArgs),

    /// Run the monitoring service in the foreground (used by soteria.service)
    Daemon,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Do not prompt; leave the baseline as a draft for later approval
    #[arg(long, conflicts_with = "yes")]
    pub non_interactive: bool,
    /// Approve the initial baseline without asking (requires root)
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
#[group(multiple = false)]
pub struct ScanTargetArgs {
    /// Full inventory scan of all configured paths (default)
    #[arg(long)]
    pub full: bool,
    /// Scan one directory tree
    #[arg(long, value_name = "PATH")]
    pub dir: Option<PathBuf>,
    /// Scan one file
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
    /// Verify the current state against the approved baseline
    #[arg(long)]
    pub baseline: bool,
    /// Review kernel and boot state
    #[arg(long)]
    pub kernel: bool,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[command(flatten)]
    pub target: ScanTargetArgs,
    /// Maximum number of baseline changes to list in text output
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
}

#[derive(Debug, Subcommand)]
pub enum BaselineCommand {
    /// List baseline versions
    List,
    /// Show one baseline version
    Show {
        #[arg(id = "baseline_version", value_name = "VERSION")]
        version: Option<u32>,
    },
    /// Build a draft baseline from the current inventory
    Create {
        /// Note recorded with the draft
        #[arg(long)]
        note: Option<String>,
    },
    /// Review a draft baseline before approval
    Review {
        #[arg(id = "baseline_version", value_name = "VERSION")]
        version: Option<u32>,
        /// Maximum number of changes to list
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Approve and seal a draft baseline (requires root)
    Approve {
        #[arg(id = "baseline_version", value_name = "VERSION")]
        version: u32,
        /// Approve without asking for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Compare two baseline versions, or a version with the current inventory
    Diff {
        from: u32,
        to: Option<u32>,
        /// Maximum number of changes to list in text output
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

#[derive(Debug, Args)]
pub struct InventoryArgs {
    /// Only objects of this kind, such as executable_binary or service_unit
    #[arg(long)]
    pub kind: Option<String>,
    /// Only objects at or below this path
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Only objects with this SHA-256
    #[arg(long)]
    pub sha256: Option<String>,
    /// Maximum number of rows
    #[arg(long, default_value_t = 100)]
    pub limit: u32,
}

#[derive(Debug, Clone, Default, Args)]
pub struct TimeRange {
    /// Start time (RFC 3339) or age such as "2h"
    #[arg(long)]
    pub since: Option<String>,
    /// End time (RFC 3339) or age such as "30m"
    #[arg(long)]
    pub until: Option<String>,
}

#[derive(Debug, Args)]
pub struct EventsArgs {
    #[command(flatten)]
    pub range: TimeRange,
    /// Event type
    #[arg(long = "type")]
    pub event_type: Option<String>,
    /// Minimum severity
    #[arg(long)]
    pub severity: Option<String>,
    /// Maximum number of rows
    #[arg(long, default_value_t = 100)]
    pub limit: u32,
}

#[derive(Debug, Subcommand)]
pub enum AlertsCommand {
    /// List and filter alerts
    List {
        #[command(flatten)]
        filter: AlertFilter,
        /// Maximum number of rows
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Show one alert with its evidence and history
    Show { id: u64 },
    /// Acknowledge an alert (evidence is kept unchanged)
    Ack {
        id: u64,
        #[arg(long)]
        note: Option<String>,
    },
    /// Mark an alert as investigated
    Investigate {
        id: u64,
        #[arg(long)]
        note: Option<String>,
    },
    /// Close an alert (the same detection may be raised again)
    Close {
        id: u64,
        #[arg(long)]
        note: Option<String>,
    },
    /// Reopen an alert
    Reopen {
        id: u64,
        #[arg(long)]
        note: Option<String>,
    },
    /// Add a note to an alert
    Note { id: u64, text: String },
    /// Suppress a known benign detection
    Suppress {
        id: u64,
        /// Why this detection is benign (recorded with your name)
        #[arg(long)]
        reason: String,
        /// Suppress this rule for every object, not just this one
        #[arg(long)]
        all_objects: bool,
        /// Let the suppression lapse after this long, such as "30d"
        #[arg(long)]
        expires: Option<String>,
    },
    /// List suppressions
    Suppressions {
        /// Include removed suppressions
        #[arg(long)]
        all: bool,
    },
    /// Remove a suppression
    Unsuppress { suppression_id: u64 },
    /// List incidents (groups of related alerts)
    Incidents {
        /// Include closed incidents
        #[arg(long)]
        all: bool,
    },
    /// Show an incident and its alerts
    Incident { id: u64 },
    /// Export alerts with evidence and history
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        #[command(flatten)]
        filter: AlertFilter,
        /// Write to this file instead of standard output
        #[arg(long, short)]
        output: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Clone, Args)]
pub struct AlertFilter {
    #[command(flatten)]
    pub range: TimeRange,
    /// Minimum severity
    #[arg(long)]
    pub severity: Option<String>,
    /// open, acknowledged, investigated, suppressed or closed
    #[arg(long)]
    pub status: Option<String>,
    /// Rule ID, such as EXE-001
    #[arg(long)]
    pub rule: Option<String>,
    /// Text contained in the affected object (file or program path)
    #[arg(long)]
    pub object: Option<String>,
    /// Only alerts in this incident
    #[arg(long)]
    pub incident: Option<u64>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
    Text,
}

#[derive(Debug, Args)]
pub struct ProcessesArgs {
    #[command(flatten)]
    pub range: TimeRange,
    /// Executable name or path
    #[arg(long)]
    pub exe: Option<String>,
    /// User name or UID
    #[arg(long)]
    pub user: Option<String>,
    #[arg(long)]
    pub pid: Option<u32>,
    #[arg(long)]
    pub severity: Option<String>,
    /// trusted, known_modified, unknown, suspicious or unverified
    #[arg(long)]
    pub classification: Option<String>,
    /// Maximum number of rows
    #[arg(long, default_value_t = 100)]
    pub limit: u32,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// List detection rules
    List,
    /// Show one rule
    Show { id: String },
    /// Check the administrator rule files
    Validate,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the effective configuration
    Show,
    /// Validate the configuration file
    Validate,
    /// Print the default configuration
    Default,
    /// Send a test message to each enabled notification channel
    TestNotifications,
}

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    /// Report for one scan
    Scan { id: String },
    /// Host security summary
    Summary,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Only verify these components (default: all)
    #[arg(long, value_enum, value_delimiter = ',')]
    pub component: Vec<Component>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Component {
    Config,
    Platform,
    Database,
    Baseline,
    Service,
    Sensors,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }
}
