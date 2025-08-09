use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ironguard",
    about = "Advanced automated security scanner and hardening tool for CyberPatriot competitions",
    version,
    author = "CyberPatriot Team"
)]
pub struct Cli {
    /// Increase logging verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Configuration file path
    #[arg(short, long, default_value = "ironguard.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run security scan
    Scan {
        /// Automatically fix found vulnerabilities
        #[arg(short, long)]
        auto_fix: bool,

        /// Run in interactive TUI mode
        #[arg(short, long)]
        interactive: bool,

        /// Target to scan (IP, hostname, or 'local' for current system)
        #[arg(default_value = "local")]
        target: String,
    },
    /// Fix specific vulnerability by ID
    Fix {
        /// Vulnerability ID to fix
        vulnerability_id: String,
    },
    /// Generate or export reports
    Report {
        /// Output format
        #[arg(short, long, value_enum, default_value = "json")]
        format: ReportFormat,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Initialize default configuration
    Init,
    /// Show current configuration
    Show,
    /// Validate configuration
    Validate,
}

#[derive(ValueEnum, Clone)]
pub enum ReportFormat {
    /// JSON format
    Json,
    /// HTML report
    Html,
    /// Plain text
    Text,
    /// CSV format
    Csv,
    /// Markdown format
    Markdown,
}