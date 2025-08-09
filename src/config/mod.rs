use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub scanners: ScannersConfig,
    pub fixes: FixesConfig,
    pub reporting: ReportingConfig,
    pub competition: CompetitionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Scanning timeout in seconds
    pub timeout: u64,
    /// Maximum concurrent scan tasks
    pub max_concurrent: usize,
    /// Enable debug mode
    pub debug: bool,
    /// Backup directory for changed files
    pub backup_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannersConfig {
    /// Enable user account scanner
    pub users: bool,
    /// Enable service scanner
    pub services: bool,
    /// Enable network scanner
    pub network: bool,
    /// Enable file system scanner
    pub filesystem: bool,
    /// Enable software vulnerability scanner
    pub software: bool,
    /// Enable system configuration scanner
    pub system: bool,
    /// Custom scanner configurations
    pub custom: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixesConfig {
    /// Enable automatic fixes (use with caution!)
    pub auto_fix_enabled: bool,
    /// Categories of fixes to apply automatically
    pub auto_fix_categories: Vec<String>,
    /// Always prompt before applying fixes
    pub require_confirmation: bool,
    /// Create system restore point before fixes (Windows)
    pub create_restore_point: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    /// Include system information in reports
    pub include_system_info: bool,
    /// Include evidence screenshots
    pub include_screenshots: bool,
    /// Report output directory
    pub output_dir: String,
    /// Automatically open reports after generation
    pub auto_open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetitionConfig {
    /// Competition-specific settings that override defaults
    pub custom_ssh_port: Option<u16>,
    pub custom_services: Vec<ServiceConfig>,
    pub allowed_users: Vec<String>,
    pub critical_files: Vec<String>,
    pub required_software: Vec<String>,
    pub forbidden_software: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub should_be_running: bool,
    pub custom_config: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                timeout: 300,
                max_concurrent: 4,
                debug: false,
                backup_dir: "./ironguard_backups".to_string(),
            },
            scanners: ScannersConfig {
                users: true,
                services: true,
                network: true,
                filesystem: true,
                software: true,
                system: true,
                custom: HashMap::new(),
            },
            fixes: FixesConfig {
                auto_fix_enabled: false,
                auto_fix_categories: vec![],
                require_confirmation: true,
                create_restore_point: true,
            },
            reporting: ReportingConfig {
                include_system_info: true,
                include_screenshots: false,
                output_dir: "./reports".to_string(),
                auto_open: false,
            },
            competition: CompetitionConfig {
                custom_ssh_port: None,
                custom_services: vec![],
                allowed_users: vec![],
                critical_files: vec![],
                required_software: vec![],
                forbidden_software: vec![],
            },
        }
    }
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;
        
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse configuration file")?;
        
        config.validate()?;
        Ok(config)
    }

    pub fn init_default() -> Result<()> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)
            .with_context(|| "Failed to serialize default configuration")?;
        
        fs::write("ironguard.toml", content)
            .with_context(|| "Failed to write default configuration file")?;
        
        Ok(())
    }

    pub fn to_string(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize configuration")
    }

    pub fn validate(&self) -> Result<()> {
        if self.general.timeout == 0 {
            anyhow::bail!("General timeout must be greater than 0");
        }
        
        if self.general.max_concurrent == 0 {
            anyhow::bail!("Max concurrent tasks must be greater than 0");
        }
        
        if let Some(port) = self.competition.custom_ssh_port {
            if port == 0 || port > 65535 {
                anyhow::bail!("Custom SSH port must be between 1 and 65535");
            }
        }
        
        Ok(())
    }
}