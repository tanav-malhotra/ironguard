use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tracing::{info, warn, error};

pub mod users;
pub mod services;
pub mod network;
pub mod filesystem;
pub mod software;
pub mod system;

use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub target: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub system_info: SystemInfo,
    pub scan_duration: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub level: VulnerabilityLevel,
    pub category: VulnerabilityCategory,
    pub evidence: Vec<String>,
    pub remediation: String,
    pub auto_fixable: bool,
    pub cve_ids: Vec<String>,
    pub score_impact: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityCategory {
    UserManagement,
    ServiceConfiguration,
    NetworkSecurity,
    FileSystemSecurity,
    SoftwareVulnerability,
    SystemConfiguration,
    AccessControl,
    Encryption,
    Logging,
    Malware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub architecture: String,
    pub kernel_version: String,
    pub uptime: u64,
    pub memory_total: u64,
    pub cpu_count: usize,
}

impl fmt::Display for VulnerabilityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulnerabilityLevel::Critical => write!(f, "CRITICAL"),
            VulnerabilityLevel::High => write!(f, "HIGH"),
            VulnerabilityLevel::Medium => write!(f, "MEDIUM"),
            VulnerabilityLevel::Low => write!(f, "LOW"),
            VulnerabilityLevel::Info => write!(f, "INFO"),
        }
    }
}

impl fmt::Display for VulnerabilityCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulnerabilityCategory::UserManagement => write!(f, "User Management"),
            VulnerabilityCategory::ServiceConfiguration => write!(f, "Service Configuration"),
            VulnerabilityCategory::NetworkSecurity => write!(f, "Network Security"),
            VulnerabilityCategory::FileSystemSecurity => write!(f, "File System Security"),
            VulnerabilityCategory::SoftwareVulnerability => write!(f, "Software Vulnerability"),
            VulnerabilityCategory::SystemConfiguration => write!(f, "System Configuration"),
            VulnerabilityCategory::AccessControl => write!(f, "Access Control"),
            VulnerabilityCategory::Encryption => write!(f, "Encryption"),
            VulnerabilityCategory::Logging => write!(f, "Logging"),
            VulnerabilityCategory::Malware => write!(f, "Malware"),
        }
    }
}

// Scanner enum to avoid dyn trait object issues with async methods
#[derive(Debug, Clone)]
pub enum ScannerType {
    Users(users::UserScanner),
    Services(services::ServiceScanner),
    Network(network::NetworkScanner),
    FileSystem(filesystem::FileSystemScanner),
    Software(software::SoftwareScanner),
    System(system::SystemScanner),
}

impl ScannerType {
    pub fn name(&self) -> &str {
        match self {
            Self::Users(s) => s.name(),
            Self::Services(s) => s.name(),
            Self::Network(s) => s.name(),
            Self::FileSystem(s) => s.name(),
            Self::Software(s) => s.name(),
            Self::System(s) => s.name(),
        }
    }
    
    pub fn description(&self) -> &str {
        match self {
            Self::Users(s) => s.description(),
            Self::Services(s) => s.description(),
            Self::Network(s) => s.description(),
            Self::FileSystem(s) => s.description(),
            Self::Software(s) => s.description(),
            Self::System(s) => s.description(),
        }
    }
    
    pub fn category(&self) -> VulnerabilityCategory {
        match self {
            Self::Users(s) => s.category(),
            Self::Services(s) => s.category(),
            Self::Network(s) => s.category(),
            Self::FileSystem(s) => s.category(),
            Self::Software(s) => s.category(),
            Self::System(s) => s.category(),
        }
    }
    
    pub async fn scan(&self) -> Result<Vec<Vulnerability>> {
        match self {
            Self::Users(s) => s.scan().await,
            Self::Services(s) => s.scan().await,
            Self::Network(s) => s.scan().await,
            Self::FileSystem(s) => s.scan().await,
            Self::Software(s) => s.scan().await,
            Self::System(s) => s.scan().await,
        }
    }
    
    pub async fn fix(&self, vulnerability: &Vulnerability) -> Result<()> {
        match self {
            Self::Users(s) => s.fix(vulnerability).await,
            Self::Services(s) => s.fix(vulnerability).await,
            Self::Network(s) => s.fix(vulnerability).await,
            Self::FileSystem(s) => s.fix(vulnerability).await,
            Self::Software(s) => s.fix(vulnerability).await,
            Self::System(s) => s.fix(vulnerability).await,
        }
    }
    
    pub fn can_fix(&self, vulnerability: &Vulnerability) -> bool {
        match self {
            Self::Users(s) => s.can_fix(vulnerability),
            Self::Services(s) => s.can_fix(vulnerability),
            Self::Network(s) => s.can_fix(vulnerability),
            Self::FileSystem(s) => s.can_fix(vulnerability),
            Self::Software(s) => s.can_fix(vulnerability),
            Self::System(s) => s.can_fix(vulnerability),
        }
    }
}

#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn category(&self) -> VulnerabilityCategory;
    
    async fn scan(&self) -> Result<Vec<Vulnerability>>;
    async fn fix(&self, vulnerability: &Vulnerability) -> Result<()>;
    fn can_fix(&self, vulnerability: &Vulnerability) -> bool;
}

pub struct ScannerEngine {
    config: Config,
    scanners: HashMap<String, ScannerType>,
}

impl ScannerEngine {
    pub fn new(config: Config) -> Result<Self> {
        let mut engine = Self {
            config: config.clone(),
            scanners: HashMap::new(),
        };
        
        // Register all scanners based on configuration
        if config.scanners.users {
            engine.register_scanner(ScannerType::Users(users::UserScanner::new(config.clone())?));
        }
        
        if config.scanners.services {
            engine.register_scanner(ScannerType::Services(services::ServiceScanner::new(config.clone())?));
        }
        
        if config.scanners.network {
            engine.register_scanner(ScannerType::Network(network::NetworkScanner::new(config.clone())?));
        }
        
        if config.scanners.filesystem {
            engine.register_scanner(ScannerType::FileSystem(filesystem::FileSystemScanner::new(config.clone())?));
        }
        
        if config.scanners.software {
            engine.register_scanner(ScannerType::Software(software::SoftwareScanner::new(config.clone())?));
        }
        
        if config.scanners.system {
            engine.register_scanner(ScannerType::System(system::SystemScanner::new(config.clone())?));
        }
        
        Ok(engine)
    }
    
    fn register_scanner(&mut self, scanner: ScannerType) {
        let name = scanner.name().to_string();
        self.scanners.insert(name, scanner);
    }
    
    pub async fn scan_all(&self, target: Option<String>) -> Result<ScanResults> {
        let start_time = std::time::Instant::now();
        let scan_id = uuid::Uuid::new_v4().to_string();
        let target = target.unwrap_or_else(|| "local".to_string());
        
        info!("Starting comprehensive security scan (ID: {})", scan_id);
        
        let mut all_vulnerabilities = Vec::new();
        
        // Run all scanners concurrently
        let mut scan_tasks = Vec::new();
        
        for (name, scanner) in &self.scanners {
            let scanner_name = name.clone();
            let scanner = scanner.clone();
            
            let task = tokio::spawn(async move {
                info!("Running {} scanner...", scanner_name);
                match scanner.scan().await {
                    Ok(vulns) => {
                        info!("{} scanner found {} vulnerabilities", scanner_name, vulns.len());
                        Ok(vulns)
                    }
                    Err(e) => {
                        error!("Scanner {} failed: {}", scanner_name, e);
                        Err(e)
                    }
                }
            });
            
            scan_tasks.push(task);
        }
        
        // Collect results
        for task in scan_tasks {
            match task.await? {
                Ok(mut vulns) => all_vulnerabilities.append(&mut vulns),
                Err(e) => warn!("Scanner task failed: {}", e),
            }
        }
        
        // Sort vulnerabilities by severity
        all_vulnerabilities.sort_by(|a, b| {
            use VulnerabilityLevel::*;
            let a_priority = match a.level {
                Critical => 0,
                High => 1,
                Medium => 2,
                Low => 3,
                Info => 4,
            };
            let b_priority = match b.level {
                Critical => 0,
                High => 1,
                Medium => 2,
                Low => 3,
                Info => 4,
            };
            a_priority.cmp(&b_priority)
        });
        
        let system_info = self.get_system_info().await?;
        let scan_duration = start_time.elapsed().as_secs_f64();
        
        let results = ScanResults {
            scan_id,
            timestamp: Utc::now(),
            target,
            vulnerabilities: all_vulnerabilities,
            system_info,
            scan_duration,
        };
        
        info!(
            "Scan completed in {:.2}s - Found {} vulnerabilities",
            scan_duration,
            results.vulnerabilities.len()
        );
        
        Ok(results)
    }
    
    pub async fn auto_fix(&self, results: &ScanResults) -> Result<()> {
        if !self.config.fixes.auto_fix_enabled {
            warn!("Auto-fix is disabled in configuration");
            return Ok(());
        }
        
        info!("Starting automated vulnerability remediation");
        
        let fixable_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.auto_fixable)
            .collect();
        
        info!("Found {} auto-fixable vulnerabilities", fixable_vulns.len());
        
        for vulnerability in fixable_vulns {
            if let Some(scanner) = self.find_scanner_for_vulnerability(vulnerability) {
                if scanner.can_fix(vulnerability) {
                    info!("Fixing vulnerability: {}", vulnerability.title);
                    match scanner.fix(vulnerability).await {
                        Ok(()) => info!("Successfully fixed: {}", vulnerability.title),
                        Err(e) => error!("Failed to fix {}: {}", vulnerability.title, e),
                    }
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn fix_specific(&self, _vulnerability_id: &str) -> Result<()> {
        // Implementation would load vulnerability by ID and fix it
        todo!("Implement specific vulnerability fixing")
    }
    
    pub async fn generate_report(&self, _results: &ScanResults) -> Result<()> {
        // Implementation would generate various report formats
        todo!("Implement report generation")
    }
    
    pub async fn export_report(&self, _format: crate::cli::ReportFormat, _output: Option<std::path::PathBuf>) -> Result<()> {
        // Implementation would export reports in different formats
        todo!("Implement report export")
    }
    
    fn find_scanner_for_vulnerability(&self, vulnerability: &Vulnerability) -> Option<&ScannerType> {
        // Find the appropriate scanner based on vulnerability category
        self.scanners.values().find(|scanner| {
            scanner.category() == vulnerability.category
        })
    }
    
    async fn get_system_info(&self) -> Result<SystemInfo> {
        use sysinfo::{System, SystemExt};
        
        let mut sys = System::new_all();
        sys.refresh_all();
        
        Ok(SystemInfo {
            hostname: sys.host_name().unwrap_or_else(|| "unknown".to_string()),
            os_type: std::env::consts::OS.to_string(),
            os_version: sys.os_version().unwrap_or_else(|| "unknown".to_string()),
            architecture: std::env::consts::ARCH.to_string(),
            kernel_version: sys.kernel_version().unwrap_or_else(|| "unknown".to_string()),
            uptime: sys.uptime(),
            memory_total: sys.total_memory(),
            cpu_count: sys.cpus().len(),
        })
    }
}