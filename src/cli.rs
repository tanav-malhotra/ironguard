use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use crate::engine;

#[derive(Parser, Debug)]
#[command(
    name = "ironguard",
    version,
    about = "Ironguard AI - CyberPatriot hardening MVP",
    long_about = None,
    subcommand_required = false,
    arg_required_else_help = false
)]
struct Cli {
    /// Enable JSON logging to user profile directory
    #[arg(long, default_value_t = false)]
    log: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run deterministic script-based remediation
    Run {
        #[arg(value_enum)]
        mode: Option<RunMode>,

        /// Dry-run: preview commands without executing
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Path to ironguard.toml
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Launch minimal TUI
    Tui,

    /// Generate a commented ironguard.toml in the current directory
    Init {
        /// Optional output path (defaults to ./ironguard.toml)
        #[arg(long)]
        path: Option<PathBuf>,
        /// Overwrite if file exists
        #[arg(long, default_value_t = false)]
        overwrite: bool,
    },

    /// Discover README HTML and print basic directives (stub)
    Readme {
        /// Optional path to README HTML; if not provided, auto-discover on Desktop
        path: Option<PathBuf>,
    },

    /// Show status (stub)
    Status,

    /// AI-driven forensics solver (reads README, answers questions, runs scripts)
    Forensics {
        /// AI provider: openai | anthropic | openrouter | ollama | gemini
        #[arg(long, default_value = "gemini")]
        provider: String,

        /// Model identifier (e.g., gpt-5, gemini-2.5-pro)
        #[arg(long, default_value = "gemini-2.5-pro")]
        model: String,

        /// API key for provider (falls back to env var like OPENAI_API_KEY / ANTHROPIC_API_KEY)
        #[arg(long)]
        api_key: Option<String>,

        /// Time budget in seconds (goal: finish under 1 hour)
        #[arg(long, default_value_t = 3600)]
        time_budget: u64,

        /// Allow actual system command execution by the AI (otherwise dry-run)
        #[arg(long, default_value_t = false)]
        allow_exec: bool,

        /// Disable interactive TUI (non-interactive logs only)
        #[arg(long, default_value_t = false)]
        no_tui: bool,

        /// Optional explicit README path (otherwise auto-discover on Desktop)
        #[arg(long)]
        readme: Option<PathBuf>,

        /// Optional path to custom script to run during workflow
        #[arg(long)]
        script: Option<PathBuf>,
    },

    /// Post-hardening scan (installs tools if missing; inventory + security checks)
    Scan {
        /// Optional file path to submit hash to VirusTotal (no upload)
        #[arg(long)]
        vt_file: Option<PathBuf>,

        /// Optional URL to submit to VirusTotal URL scan
        #[arg(long)]
        vt_url: Option<String>,

        /// VirusTotal API key (or use VIRUSTOTAL_API_KEY env var)
        #[arg(long)]
        vt_api_key: Option<String>,

        /// Perform extended/full scans where supported
        #[arg(long, default_value_t = false)]
        full: bool,
    },

    /// Open ironguard.toml in an editor (creates if missing)
    Config {
        /// Optional path to config (defaults to ./ironguard.toml)
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
enum RunMode {
    Script,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    let mut logger = logging::init(cli.log)?;

    match cli.command {
        Commands::Run { mode, dry_run, config } => {
            let mode = mode.unwrap_or(RunMode::Script);
            // Load config: explicit path, else ./ironguard.toml, else bail
            let cfg = if let Some(path) = config {
                config::load_from_path(&path)?
            } else {
                let default_path = PathBuf::from("ironguard.toml");
                if default_path.exists() {
                    config::load_from_path(&default_path)?
                } else {
                    anyhow::bail!("No config provided and ./ironguard.toml not found. Run 'ironguard init' then edit the file.");
                }
            };
            // Enforce readiness gating
            config::validate_required_for_current_os(&cfg)?;

            match mode {
                RunMode::Script => {
                    let _ = logger.log_message("start", &format!("mode=script dry_run={}", dry_run));
                    if cfg!(target_os = "linux") {
                        let effective_dry_run = linux_effective_dry_run(dry_run);
                        let opts = engine::EngineOptions { dry_run: effective_dry_run };
                        if let Some(cfg) = Some(cfg) {
                            tokio::runtime::Handle::current().block_on(engine::linux::run_baseline_with_config(&opts, &cfg))?;
                        } else {
                            tokio::runtime::Handle::current().block_on(engine::linux::run_baseline(&opts))?;
                        }
                    } else if cfg!(target_os = "windows") {
                        let opts = engine::EngineOptions { dry_run };
                        tokio::runtime::Handle::current().block_on(engine::windows::run_baseline_with_config(&opts, &cfg))?;
                    } else {
                        println!("Unsupported OS");
                    }
                    let _ = logger.log_message("end", "mode=script completed");
                }
            }
        }
        Commands::Tui => {
            tui::run()?;
        }
        Commands::Init { path, overwrite } => {
            use std::fs;
            let out_path = path.unwrap_or_else(|| PathBuf::from("ironguard.toml"));
            if out_path.exists() && !overwrite {
                anyhow::bail!("{} already exists. Use --overwrite to replace.", out_path.display());
            }
            let tpl = if cfg!(target_os = "windows") {
                r#"# Ironguard Configuration (Windows)
#
# ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
# ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
# ██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
# ██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
# ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
# ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
#
# This file controls what Ironguard keeps and exposes to the system.
# Philosophy: strict whitelist. Anything not explicitly allowed/kept is removed or disabled.
#
# Users and admins (usernames). These are created if missing and secured.
# Admins get Administrators membership.
# admins = ["Administrator", "admin1"]
# users = ["user1", "user2"]

# Allowed services (tokens). Examples: "ssh", "apache", "nginx", "mysql", "postgres", "docker", "rdp", "w3svc".
# Anything not listed here is stopped/disabled and removed where safe.
# allowed_services = ["rdp", "w32time"]

# Keep packages/apps regardless of whitelist (package names, Appx names, or fuzzy tokens).
# Windows Appx examples: "Microsoft.WindowsStore", "Microsoft.DesktopAppInstaller"
# keep_packages = ["Microsoft.WindowsStore"]

# DANGEROUS: items listed here will be forcibly removed even if allowed or kept.
# force_remove = ["wireshark", "netcat"]

[firewall]
# TCP ports to allow (default SSH only if empty). Example: [22, 80, 443]
# allowed_ports = [3389]

[service_ports]
# Optional override per service. Examples:
# ssh = 22
# rdp = 3389

[password_policy]
# (Not used on Windows; reserved for Linux images)

[windows]
# allow_rdp = false
# ssh_key_only = true
# openssh_enabled = false

[security]
# disable_http = false
# enable_luks = false
# enable_bitlocker = false
# lockdown_cron = false
"#
            } else {
                r#"# Ironguard Configuration (Linux)
#
# ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
# ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
# ██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
# ██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
# ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
# ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
#
# This file controls what Ironguard keeps and exposes to the system.
# Philosophy: strict whitelist. Anything not explicitly allowed/kept is removed or disabled.
#
# Users and admins (usernames). These are created if missing and secured.
# Admins get sudo membership.
# admins = ["root", "admin1"]
# users = ["user1", "user2"]

# Allowed services. Examples: "ssh", "apache", "nginx", "mysql", "postgres", "docker".
# allowed_services = ["ssh"]

# Keep packages/apps regardless of whitelist (package names or tokens)
# Examples: "firefox", "chromium", "network-manager"
# keep_packages = ["firefox", "network-manager"]

# DANGEROUS: items listed here will be forcibly removed even if allowed or kept.
# force_remove = ["netcat", "telnetd"]

[firewall]
# allowed_ports = [22]

[service_ports]
# Optional override per service. Examples:
# ssh = 22

[password_policy]
# min_length = 12
# require_uppercase = true
# require_lowercase = true
# require_number = true
# require_symbol = true

[linux]
# knockd_enabled = false
# ssh_key_only = true

[security]
# disable_http = false
"#
            };
            fs::write(&out_path, tpl)?;
            println!("Wrote {}", out_path.display());
        }
        Commands::Readme { path } => {
            let readme_path = match path {
                Some(p) => Some(p),
                None => readme::discover_desktop_readme(),
            };
            match readme_path {
                Some(p) => {
                    println!("Found README: {}", p.display());
                    let directives = readme::extract_directives(&p)?;
                    println!("Directives (stub): {} keys", directives.len());
                    let _ = logger.log_message("readme", &format!("found path={}", p.display()));
                }
                None => {
                    println!("No README HTML found on Desktop.");
                    let _ = logger.log_message("readme", "not found on Desktop");
                }
            }
        }
        Commands::Status => {
            println!("Status: Ironguard MVP ready. Use 'ironguard run script [--dry-run]' or 'ironguard scan'.");
        }
        Commands::Forensics { provider, model, api_key, time_budget, allow_exec, no_tui, readme, script } => {
            let _ = logger.log_message("start", &format!(
                "mode=forensics provider={} model={} allow_exec={} tui={} time_budget_s={}",
                provider, model, allow_exec, !no_tui, time_budget
            ));

            let opts = crate::forensics::ForensicsOptions {
                provider,
                model,
                api_key,
                time_budget_secs: time_budget,
                allow_exec,
                readme_path: readme,
                use_tui: !no_tui,
                custom_script: script,
            };

            if cfg!(target_os = "linux") {
                tokio::runtime::Handle::current().block_on(crate::forensics::run(&opts, &mut logger))?;
            } else {
                println!("Forensics workflow currently targets Linux images. Windows support pending.");
            }
            let _ = logger.log_message("end", "mode=forensics completed");
        }
        Commands::Scan { vt_file, vt_url, vt_api_key, full } => {
            let _ = logger.log_message("start", "mode=scan extended");
            if cfg!(target_os = "linux") {
                tokio::runtime::Handle::current().block_on(scan_linux_extended(true, true, true, full, &mut logger))?;
            } else if cfg!(target_os = "windows") {
                tokio::runtime::Handle::current().block_on(scan_windows_extended(full, &mut logger))?;
            }
            if vt_file.is_some() || vt_url.is_some() {
                tokio::runtime::Handle::current().block_on(scan_virustotal(vt_file, vt_url, vt_api_key, &mut logger))?;
            }
            let _ = logger.log_message("end", "mode=scan completed");
        }
        Commands::Config { path } => {
            use std::{env, fs, process::Command as StdCommand};
            let out_path = path.unwrap_or_else(|| PathBuf::from("ironguard.toml"));
            if !out_path.exists() {
                let tpl = if cfg!(target_os = "windows") {
                    r#"# Ironguard Configuration (Windows)
#
# This file controls what Ironguard keeps and exposes to the system.
# Philosophy: strict whitelist. Anything not explicitly allowed/kept is removed or disabled.

# admins = ["Administrator", "admin1"]
# users = ["user1", "user2"]

# allowed_services = ["rdp", "w32time"]

# keep_packages = ["Microsoft.WindowsStore"]

# force_remove = ["wireshark", "netcat"]

[firewall]
# allowed_ports = [3389]

[service_ports]
# ssh = 22
# rdp = 3389

[windows]
# allow_rdp = false
# ssh_key_only = true
# openssh_enabled = false

[security]
# disable_http = false
# enable_bitlocker = false
# lockdown_cron = false
"#
                } else {
                    r#"# Ironguard Configuration (Linux)
#
# This file controls what Ironguard keeps and exposes to the system.
# Philosophy: strict whitelist. Anything not explicitly allowed/kept is removed or disabled.

# admins = ["root", "admin1"]
# users = ["user1", "user2"]

# allowed_services = ["ssh"]

# keep_packages = ["firefox", "network-manager"]

# force_remove = ["netcat", "telnetd"]

[firewall]
# allowed_ports = [22]

[service_ports]
# ssh = 22

[linux]
# knockd_enabled = false
# ssh_key_only = true

[security]
# disable_http = false
# enable_luks = false
# lockdown_cron = false
"#
                };
                fs::write(&out_path, tpl)?;
                println!("Wrote {}", out_path.display());
            }

            // Choose editor
            let editor_env = env::var("VISUAL").ok().or_else(|| env::var("EDITOR").ok());
            let cmd_and_args: (String, Vec<String>) = if cfg!(target_os = "windows") {
                if let Some(ed) = &editor_env {
                    let mut parts = ed.split_whitespace();
                    let prog = parts.next().unwrap_or("notepad").to_string();
                    let mut args: Vec<String> = parts.map(|s| s.to_string()).collect();
                    args.push(out_path.to_string_lossy().to_string());
                    (prog, args)
                } else {
                    ("notepad".to_string(), vec![out_path.to_string_lossy().to_string()])
                }
            } else if let Some(ed) = editor_env {
                let mut parts = ed.split_whitespace();
                let prog = parts.next().unwrap_or("vi").to_string();
                let mut args: Vec<String> = parts.map(|s| s.to_string()).collect();
                args.push(out_path.to_string_lossy().to_string());
                (prog, args)
            } else {
                // Fallback search
                let candidates = ["nvim", "vim", "vi"]; 
                let prog = candidates.iter().find(|p| which::which(p).is_ok()).unwrap_or(&"vi").to_string();
                (prog, vec![out_path.to_string_lossy().to_string()])
            };

            let status = StdCommand::new(&cmd_and_args.0).args(&cmd_and_args.1).status()?;
            if !status.success() {
                eprintln!("Editor exited with status: {:?}", status);
            }
        }
    }

    // Default path (no subcommand): one-shot secure run
    else {
        // Default behavior: launch TUI (AI workflow placeholder)
        tui::run()?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_effective_dry_run(user_dry_run: bool) -> bool {
    if user_dry_run { return true; }
    use std::process::Command as StdCommand;
    let is_root = StdCommand::new("id").arg("-u").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0").unwrap_or(false);
    if !is_root {
        eprintln!("[!] Ironguard must run as root. Enforcing dry-run. Press Ctrl+C and re-run with sudo.");
        true
    } else { false }
}

#[cfg(not(target_os = "linux"))]
fn linux_effective_dry_run(user_dry_run: bool) -> bool { user_dry_run }

pub mod logging {
    use std::{fs::{File, create_dir_all}, io::Write, path::PathBuf};
    use anyhow::Result;
    use chrono::Local;
    use directories::BaseDirs;
    use serde::Serialize;
    use serde_json::json;

    pub struct LogManager {
        pub session_dir: PathBuf,
        enabled: bool,
        file: Option<File>,
    }

    pub fn init(enabled: bool) -> Result<LogManager> {
        let base = BaseDirs::new();
        let home = base.map(|b| b.home_dir().to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
        let stamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let session_dir = home.join(".ironguard").join(stamp);
        if enabled {
            create_dir_all(&session_dir)?;
        }
        let file = if enabled {
            Some(File::create(session_dir.join("log.json"))?)
        } else { None };

        Ok(LogManager { session_dir, enabled, file })
    }

    impl LogManager {
        pub fn log_event<T: Serialize>(&mut self, event: &T) -> Result<()> {
            if !self.enabled { return Ok(()); }
            if let Some(f) = self.file.as_mut() {
                serde_json::to_writer(&mut *f, event)?;
                f.write_all(b"\n")?;
                f.flush()?;
            }
            Ok(())
        }

        pub fn log_message(&mut self, kind: &str, detail: &str) -> Result<()> {
            let event = json!({
                "ts": Local::now().to_rfc3339(),
                "kind": kind,
                "detail": detail,
            });
            self.log_event(&event)
        }
    }
}

pub mod config {
    use std::{fs, path::Path};
    use anyhow::{Context, Result};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct PasswordPolicy {
        pub min_length: Option<u8>,
        pub require_uppercase: Option<bool>,
        pub require_lowercase: Option<bool>,
        pub require_number: Option<bool>,
        pub require_symbol: Option<bool>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct FirewallConfig {
        pub allowed_ports: Option<Vec<u16>>, // e.g., [22]
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    #[serde(default)]
    pub struct Config {
        pub admins: Option<Vec<String>>,
        pub users: Option<Vec<String>>,
        pub allowed_services: Option<Vec<String>>,
        pub keep_packages: Option<Vec<String>>,
        /// Dangerous: items here will be forcibly removed even if allowed/kept. Use with caution.
        pub force_remove: Option<Vec<String>>,
        pub forbidden_software: Option<Vec<String>>,
        pub firewall: Option<FirewallConfig>,
        pub password_policy: Option<PasswordPolicy>,
        pub ai: Option<AiSettings>,
        pub windows: Option<WindowsConfig>,
        pub linux: Option<LinuxConfig>,
        /// Optional mapping from service name -> port number (e.g., { ssh=2222, rdp=3389 })
        pub service_ports: Option<HashMap<String, u16>>,
        /// Global security toggles
        pub security: Option<SecurityConfig>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    #[serde(default)]
    pub struct AiSettings {
        /// Preferred provider identifier (e.g., "gemini", "gpt-5", "grok-4")
        pub default_provider: Option<String>,
        /// Preferred model per provider
        pub default_model: Option<String>,
        /// Optional inline API key (development convenience only)
        pub api_key: Option<String>,
        /// Optional mapping of provider -> API key to support multi-provider configs
        pub api_keys: Option<std::collections::HashMap<String, String>>,
        /// Optional directory for persisting AI sessions (defaults to ~/.ironguard/sessions)
        pub session_store: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    #[serde(default)]
    pub struct WindowsConfig {
        pub allow_rdp: Option<bool>,
        /// If OpenSSH server is present and allowed, enforce key-only
        pub ssh_key_only: Option<bool>,
        /// Enable managing OpenSSH Server if present (default: false)
        pub openssh_enabled: Option<bool>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    #[serde(default)]
    pub struct LinuxConfig {
        pub knockd_enabled: Option<bool>,
        /// Enforce key-only (PasswordAuthentication no). Default true.
        pub ssh_key_only: Option<bool>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    #[serde(default)]
    pub struct SecurityConfig {
        /// If true, block HTTP/80 inbound and prefer HTTPS only
        pub disable_http: Option<bool>,
        /// If true, attempt to enable BitLocker on Windows (C:) - DANGEROUS, default false
        pub enable_bitlocker: Option<bool>,
        /// If true, attempt to enable LUKS on Linux - DANGEROUS, default false (not implemented)
        pub enable_luks: Option<bool>,
        /// If true, lock down cron (deny all by default)
        pub lockdown_cron: Option<bool>,
    }

    impl Config {
        pub fn validate(&self) -> Result<()> {
            // minimal sanity checks for MVP
            if let Some(ports) = self.firewall.as_ref().and_then(|f| f.allowed_ports.as_ref()) {
                for p in ports {
                    anyhow::ensure!(*p != 0, "invalid port: {}", p);
                }
            }
            if let Some(policy) = self.password_policy.as_ref() {
                if let Some(len) = policy.min_length {
                    anyhow::ensure!(len >= 8, "password min_length must be >= 8 for MVP");
                }
            }
            Ok(())
        }
    }

    pub fn validate_required_for_current_os(cfg: &Config) -> Result<()> {
        // Enforce that critical fields are present and non-empty, otherwise ask user to edit TOML
        let is_windows = cfg!(target_os = "windows");
        let admins = cfg.admins.as_ref().map(|v| v.iter().filter(|s| !s.trim().is_empty()).count()).unwrap_or(0);
        let users = cfg.users.as_ref().map(|v| v.iter().filter(|s| !s.trim().is_empty()).count()).unwrap_or(0);
        anyhow::ensure!(admins > 0, "Config incomplete: admins list is required. Edit ironguard.toml and retry.");
        anyhow::ensure!(users > 0, "Config incomplete: users list is required. Edit ironguard.toml and retry.");
        // OS-specific sanity: avoid cross-OS defaults
        if is_windows {
            if let Some(a) = &cfg.admins { anyhow::ensure!(!a.iter().any(|s| s == "root"), "Windows config: remove 'root' from admins."); }
        } else {
            if let Some(a) = &cfg.admins { anyhow::ensure!(!a.iter().any(|s| s == "Administrator"), "Linux config: remove 'Administrator' from admins."); }
        }
        Ok(())
    }

    pub fn load_from_path(path: &impl AsRef<Path>) -> Result<Config> {
        let content = fs::read_to_string(path).with_context(|| format!("reading {}", path.as_ref().display()))?;
        let cfg: Config = toml::from_str(&content).context("parsing toml")?;
        cfg.validate()?;
        Ok(cfg)
    }
}

pub mod tui {
    use anyhow::Result;
    use crossterm::{event::{self, Event, KeyCode}, terminal::{EnterAlternateScreen, LeaveAlternateScreen}, execute};
    use ratatui::{prelude::*, widgets::*};
    use std::io::{self, Stdout};

    pub fn run() -> Result<()> {
        let mut stdout = io::stdout();
        crossterm::terminal::enable_raw_mode()?;
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(io::stdout());
        let mut terminal = Terminal::new(backend)?;

        let res = run_app(&mut terminal);

        // teardown
        crossterm::terminal::disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen)?;
        res
    }

    fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        loop {
            terminal.draw(|f| {
                let size = f.size();
                let block = Block::default().title("Ironguard MVP").borders(Borders::ALL);
                let paragraph = Paragraph::new("Press q to quit\nRun scripts: 'ironguard run'\nAI TBA: this TUI will orchestrate the forensics workflow")
                    .block(block)
                    .alignment(Alignment::Left);
                f.render_widget(paragraph, size);
            })?;

            if event::poll(std::time::Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}

pub mod platforms {}

pub mod readme {
    use anyhow::Result;
    use std::{collections::HashMap, env, fs, path::{Path, PathBuf}};

    pub fn discover_desktop_readme() -> Option<PathBuf> {
        let home = env::var_os("USERPROFILE").map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(PathBuf::from))?;
        let desktop = home.join("Desktop");

        let mut strict: Option<PathBuf> = None;         // readme.html or readme.htm
        let mut stem_match: Option<PathBuf> = None;      // file_stem == readme
        let mut contains_match: Option<PathBuf> = None;  // filename contains readme
        let mut any_html: Option<PathBuf> = None;        // fallback to first HTML/HTM

        if let Ok(entries) = fs::read_dir(&desktop) {
            for e in entries.flatten() {
                let p = e.path();

                let file_name = match p.file_name() {
                    Some(n) => n.to_string_lossy().to_ascii_lowercase(),
                    None => continue,
                };

                let ext = p.extension().map(|s| s.to_string_lossy().to_ascii_lowercase());
                let is_html = matches!(ext.as_deref(), Some("html") | Some("htm"));
                if !is_html { continue; }

                if any_html.is_none() {
                    any_html = Some(p.clone());
                }

                if file_name == "readme.html" || file_name == "readme.htm" {
                    strict = Some(p.clone());
                    break; // best possible match
                }

                let stem = p.file_stem().map(|s| s.to_string_lossy().to_ascii_lowercase());
                if stem.as_deref() == Some("readme") && stem_match.is_none() {
                    stem_match = Some(p.clone());
                    continue;
                }

                if file_name.contains("readme") && contains_match.is_none() {
                    contains_match = Some(p.clone());
                }
            }
        }

        strict.or(stem_match).or(contains_match).or(any_html)
    }

    pub fn extract_directives(_path: &impl AsRef<Path>) -> Result<HashMap<String, String>> {
        // Stub: parse later with an HTML parser; return empty map for now
        Ok(HashMap::new())
    }
}

#[cfg(target_os = "linux")]
async fn scan_linux(inventory: bool, lynis: bool, malware: bool, logger: &mut logging::LogManager) -> anyhow::Result<()> {
    use tokio::fs;
    use tokio::process::Command;
    let out_dir = logger.session_dir.join("scan");
    let _ = fs::create_dir_all(&out_dir).await;
    if inventory {
        let _ = fs::write(out_dir.join("packages.txt"), Command::new("bash").arg("-lc").arg("dpkg -l || rpm -qa").output().await?.stdout).await;
        let _ = fs::write(out_dir.join("services.txt"), Command::new("bash").arg("-lc").arg("systemctl list-units --type=service --state=running || service --status-all").output().await?.stdout).await;
        let _ = fs::write(out_dir.join("ports.txt"), Command::new("bash").arg("-lc").arg("ss -tulpn || netstat -tulpn").output().await?.stdout).await;
        let _ = fs::write(out_dir.join("recent_files.txt"), Command::new("bash").arg("-lc").arg("find / -xdev -type f -mtime -3 2>/dev/null | head -n 1000").output().await?.stdout).await;
    }
    if lynis {
        // Run lynis if installed
        let _ = Command::new("bash").arg("-lc").arg("command -v lynis >/dev/null 2>&1 && sudo lynis audit system --quiet --no-colors --logfile \"".to_owned() + out_dir.join("lynis.log").to_string_lossy().as_ref() + "\" || true").status().await;
    }
    if malware {
        // Opt-in malware checks (can be slow)
        let _ = Command::new("bash").arg("-lc").arg("command -v clamscan >/dev/null 2>&1 && sudo freshclam && clamscan -r --infected --recursive / 2>/dev/null | head -n 200 > \"".to_owned() + out_dir.join("clamav.txt").to_string_lossy().as_ref() + "\" || true").status().await;
        let _ = Command::new("bash").arg("-lc").arg("command -v chkrootkit >/dev/null 2>&1 && sudo chkrootkit > \"".to_owned() + out_dir.join("chkrootkit.txt").to_string_lossy().as_ref() + "\" || true").status().await;
        let _ = Command::new("bash").arg("-lc").arg("command -v rkhunter >/dev/null 2>&1 && sudo rkhunter --check --sk > \"".to_owned() + out_dir.join("rkhunter.txt").to_string_lossy().as_ref() + "\" || true").status().await;
    }
    Ok(())
}


#[cfg(target_os = "linux")]
async fn scan_linux_extended(inventory: bool, lynis: bool, malware: bool, full: bool, logger: &mut logging::LogManager) -> anyhow::Result<()> {
    use tokio::fs;
    use tokio::process::Command;
    let out_dir = logger.session_dir.join("scan");
    let _ = fs::create_dir_all(&out_dir).await;
    // Attempt to install tools if missing (best-effort)
    let _ = Command::new("bash").arg("-lc").arg("command -v apt-get >/dev/null 2>&1 && sudo apt-get -y -q update && sudo apt-get -y -q install lynis clamav chkrootkit rkhunter || true").status().await;
    let _ = Command::new("bash").arg("-lc").arg("command -v dnf >/dev/null 2>&1 && sudo dnf -y install lynis clamav chkrootkit rkhunter || true").status().await;
    // Inventory
    if inventory { scan_linux(true, false, false, logger).await?; }
    // Lynis
    if lynis { let _ = Command::new("bash").arg("-lc").arg("command -v lynis >/dev/null 2>&1 && sudo lynis audit system --quiet --no-colors --logfile \"".to_owned() + out_dir.join("lynis.log").to_string_lossy().as_ref() + "\" || true").status().await; }
    // Malware tools
    if malware {
        let clam_cmd = if full { "sudo freshclam && clamscan -r --infected --recursive /" } else { "sudo freshclam && clamscan -r --infected --recursive / 2>/dev/null | head -n 200" };
        let _ = Command::new("bash").arg("-lc").arg(format!("command -v clamscan >/dev/null 2>&1 && {} > \"{}\" || true", clam_cmd, out_dir.join("clamav.txt").to_string_lossy())).status().await;
        let _ = Command::new("bash").arg("-lc").arg(format!("command -v chkrootkit >/dev/null 2>&1 && sudo chkrootkit > \"{}\" || true", out_dir.join("chkrootkit.txt").to_string_lossy())).status().await;
        let _ = Command::new("bash").arg("-lc").arg(format!("command -v rkhunter >/dev/null 2>&1 && sudo rkhunter --check --sk > \"{}\" || true", out_dir.join("rkhunter.txt").to_string_lossy())).status().await;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn scan_windows_extended(full: bool, logger: &mut logging::LogManager) -> anyhow::Result<()> {
    use tokio::fs;
    use tokio::process::Command;
    let out_dir = logger.session_dir.join("scan");
    let _ = fs::create_dir_all(&out_dir).await;
    // Windows Defender quick or full scan
    if full {
        let _ = Command::new("powershell").args(["-NoProfile","-ExecutionPolicy","Bypass","-Command","Start-MpScan -ScanType FullScan"]).status().await;
    } else {
        let _ = Command::new("powershell").args(["-NoProfile","-ExecutionPolicy","Bypass","-Command","Start-MpScan -ScanType QuickScan"]).status().await;
    }
    // Update signatures and output threat history
    let _ = Command::new("powershell").args(["-NoProfile","-ExecutionPolicy","Bypass","-Command","Update-MpSignature"]).status().await;
    let threats = Command::new("powershell").args(["-NoProfile","-ExecutionPolicy","Bypass","-Command","(Get-MpThreatDetection | Out-String)"]).output().await;
    if let Ok(o) = threats { let _ = fs::write(out_dir.join("defender_threats.txt"), o.stdout).await; }
    Ok(())
}

async fn scan_virustotal(vt_file: Option<std::path::PathBuf>, vt_url: Option<String>, vt_api_key: Option<String>, logger: &mut logging::LogManager) -> anyhow::Result<()> {
    use sha2::{Sha256, Digest};
    let out_dir = logger.session_dir.join("scan");
    let _ = tokio::fs::create_dir_all(&out_dir).await;
    let api_key = vt_api_key.or_else(|| std::env::var("VIRUSTOTAL_API_KEY").ok());
    if api_key.is_none() { return Ok(()); }
    let api_key = api_key.unwrap();
    if let Some(p) = vt_file {
        if let Ok(bytes) = tokio::fs::read(&p).await {
            let mut hasher = Sha256::new(); hasher.update(&bytes); let hash = format!("{:x}", hasher.finalize());
            let url = format!("https://www.virustotal.com/api/v3/files/{}", hash);
            let client = reqwest::Client::new();
            let res = client.get(&url).header("x-apikey", api_key.clone()).send().await;
            if let Ok(r) = res { let text = r.text().await.unwrap_or_default(); let _ = tokio::fs::write(out_dir.join("virustotal_file.json"), text).await; }
        }
    }
    if let Some(u) = vt_url {
        let client = reqwest::Client::new();
        // URL analyze; VT expects URL-id (base64url) for lookup; for simplicity, use analyze endpoint
        let res = client.post("https://www.virustotal.com/api/v3/urls").header("x-apikey", api_key).form(&[("url", u.as_str())]).send().await;
        if let Ok(r) = res { let text = r.text().await.unwrap_or_default(); let _ = tokio::fs::write(out_dir.join("virustotal_url.json"), text).await; }
    }
    Ok(())
}

