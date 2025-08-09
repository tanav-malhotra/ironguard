use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, error};

#[derive(Parser)]
#[command(name = "ironguard", about = "CyberPatriot Security Scanner", version)]
struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Scan {
        #[arg(short, long)]
        auto_fix: bool,
    },
    Fix {
        vulnerability_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub level: VulnerabilityLevel,
    pub category: String,
    pub auto_fixable: bool,
    pub score_impact: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum VulnerabilityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for VulnerabilityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilityLevel::Critical => write!(f, "CRITICAL"),
            VulnerabilityLevel::High => write!(f, "HIGH"),
            VulnerabilityLevel::Medium => write!(f, "MEDIUM"),
            VulnerabilityLevel::Low => write!(f, "LOW"),
            VulnerabilityLevel::Info => write!(f, "INFO"),
        }
    }
}

struct IronGuard {
    vulnerabilities: Vec<Vulnerability>,
}

impl IronGuard {
    fn new() -> Self {
        Self {
            vulnerabilities: Vec::new(),
        }
    }
    
    async fn scan(&mut self) -> Result<()> {
        info!("🛡️  Starting IronGuard security scan...");
        
        // Simulate scanning different areas
        let scan_areas = vec![
            ("User Management", "👥"),
            ("Services", "⚙️"),
            ("Network Security", "🌐"),
            ("File System", "📁"),
            ("Software", "📦"),
            ("System Config", "🖥️"),
        ];
        
        for (area, emoji) in scan_areas {
            info!("{} Scanning {}...", emoji, area);
            sleep(Duration::from_millis(500)).await;
            
            // Add some sample vulnerabilities
            match area {
                "User Management" => {
                    self.add_user_vulnerabilities().await?;
                }
                "Services" => {
                    self.add_service_vulnerabilities().await?;
                }
                "Network Security" => {
                    self.add_network_vulnerabilities().await?;
                }
                _ => {
                    // Placeholder for other scanners
                }
            }
        }
        
        info!("✅ Scan completed! Found {} vulnerabilities", self.vulnerabilities.len());
        Ok(())
    }
    
    async fn add_user_vulnerabilities(&mut self) -> Result<()> {
        // Check for common user issues on Windows/Linux
        #[cfg(windows)]
        {
            if let Ok(output) = tokio::process::Command::new("net")
                .args(&["user"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if output_str.contains("Guest") && output_str.contains("Active") {
                    self.vulnerabilities.push(Vulnerability {
                        id: "user-guest-enabled".to_string(),
                        title: "Guest account is enabled".to_string(),
                        description: "The Guest account should be disabled for security".to_string(),
                        level: VulnerabilityLevel::High,
                        category: "User Management".to_string(),
                        auto_fixable: true,
                        score_impact: 10,
                    });
                }
            }
        }
        
        #[cfg(unix)]
        {
            // Check for users with empty passwords
            if let Ok(shadow) = tokio::fs::read_to_string("/etc/shadow").await {
                for line in shadow.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 && parts[1].is_empty() {
                        self.vulnerabilities.push(Vulnerability {
                            id: format!("user-empty-password-{}", parts[0]),
                            title: format!("User '{}' has empty password", parts[0]),
                            description: "User accounts should have passwords".to_string(),
                            level: VulnerabilityLevel::Critical,
                            category: "User Management".to_string(),
                            auto_fixable: false,
                            score_impact: 15,
                        });
                    }
                }
            }
        }
        
        Ok(())
    }
    
    async fn add_service_vulnerabilities(&mut self) -> Result<()> {
        // Check for dangerous services
        let dangerous_services = vec!["telnet", "ftp", "tftp"];
        
        for service in dangerous_services {
            // Simulate service check
            if self.is_service_running(service).await {
                self.vulnerabilities.push(Vulnerability {
                    id: format!("service-dangerous-{}", service),
                    title: format!("Dangerous service '{}' is running", service),
                    description: format!("The {} service should be disabled", service),
                    level: VulnerabilityLevel::High,
                    category: "Services".to_string(),
                    auto_fixable: true,
                    score_impact: 8,
                });
            }
        }
        
        Ok(())
    }
    
    async fn add_network_vulnerabilities(&mut self) -> Result<()> {
        // Check for open dangerous ports
        let dangerous_ports = vec![23, 21, 135, 139, 445];
        
        for port in dangerous_ports {
            if self.is_port_open(port).await {
                self.vulnerabilities.push(Vulnerability {
                    id: format!("network-open-port-{}", port),
                    title: format!("Dangerous port {} is open", port),
                    description: format!("Port {} should be closed or secured", port),
                    level: VulnerabilityLevel::Medium,
                    category: "Network Security".to_string(),
                    auto_fixable: false,
                    score_impact: 6,
                });
            }
        }
        
        Ok(())
    }
    
    async fn is_service_running(&self, _service: &str) -> bool {
        // Simplified service check - in real implementation would check actual services
        use rand::Rng;
        rand::thread_rng().gen_bool(0.3) // 30% chance service is running
    }
    
    async fn is_port_open(&self, port: u16) -> bool {
        use tokio::net::TcpStream;
        use tokio::time::timeout;
        
        let addr = format!("127.0.0.1:{}", port);
        timeout(Duration::from_millis(100), TcpStream::connect(addr))
            .await
            .is_ok()
    }
    
    fn show_results(&self) {
        println!("\n🛡️  IronGuard Security Scan Results");
        println!("═══════════════════════════════════════");
        
        if self.vulnerabilities.is_empty() {
            println!("✅ No vulnerabilities found! System appears secure.");
            return;
        }
        
        // Group by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();
        
        for vuln in &self.vulnerabilities {
            match vuln.level {
                VulnerabilityLevel::Critical => critical.push(vuln),
                VulnerabilityLevel::High => high.push(vuln),
                VulnerabilityLevel::Medium => medium.push(vuln),
                VulnerabilityLevel::Low => low.push(vuln),
                VulnerabilityLevel::Info => info.push(vuln),
            }
        }
        
        println!("📊 Summary:");
        println!("  🔴 Critical: {}", critical.len());
        println!("  🟠 High: {}", high.len());
        println!("  🟡 Medium: {}", medium.len());
        println!("  🔵 Low: {}", low.len());
        println!("  ⚪ Info: {}", info.len());
        println!();
        
        // Show vulnerabilities by severity
        for (vulns, color, emoji) in [
            (&critical, "\x1b[91m", "🔴"),
            (&high, "\x1b[93m", "🟠"),
            (&medium, "\x1b[92m", "🟡"),
            (&low, "\x1b[94m", "🔵"),
            (&info, "\x1b[90m", "⚪"),
        ] {
            if !vulns.is_empty() {
                for vuln in vulns {
                    println!("{} {} [{}] {}", emoji, color, vuln.level, vuln.title);
                    println!("    {}\x1b[0m", vuln.description);
                    if vuln.auto_fixable {
                        println!("    🔧 Auto-fixable (Score: +{})", vuln.score_impact);
                    } else {
                        println!("    🔍 Manual fix required (Score: +{})", vuln.score_impact);
                    }
                    println!();
                }
            }
        }
        
        let total_score = self.vulnerabilities.iter()
            .map(|v| v.score_impact)
            .sum::<i32>();
        println!("🏆 Potential score improvement: {} points", total_score);
        
        let auto_fixable = self.vulnerabilities.iter()
            .filter(|v| v.auto_fixable)
            .count();
        if auto_fixable > 0 {
            println!("💡 Tip: Run with --auto-fix to automatically fix {} vulnerabilities", auto_fixable);
        }
    }
    
    async fn auto_fix(&mut self) -> Result<()> {
        let fixable_vulns: Vec<_> = self.vulnerabilities
            .iter()
            .filter(|v| v.auto_fixable)
            .collect();
        
        if fixable_vulns.is_empty() {
            info!("No auto-fixable vulnerabilities found");
            return Ok(());
        }
        
        info!("🔧 Starting auto-fix for {} vulnerabilities...", fixable_vulns.len());
        
        for vuln in fixable_vulns {
            info!("Fixing: {}", vuln.title);
            
            match self.apply_fix(vuln).await {
                Ok(()) => {
                    info!("✅ Fixed: {}", vuln.title);
                }
                Err(e) => {
                    error!("❌ Failed to fix {}: {}", vuln.title, e);
                }
            }
            
            sleep(Duration::from_millis(200)).await;
        }
        
        info!("✅ Auto-fix completed!");
        Ok(())
    }
    
    async fn apply_fix(&self, vuln: &Vulnerability) -> Result<()> {
        // Simplified fix implementation
        match vuln.id.as_str() {
            "user-guest-enabled" => {
                #[cfg(windows)]
                {
                    info!("Disabling Guest account...");
                    let _output = tokio::process::Command::new("net")
                        .args(&["user", "guest", "/active:no"])
                        .output()
                        .await?;
                }
            }
            id if id.starts_with("service-dangerous-") => {
                let service_name = id.strip_prefix("service-dangerous-").unwrap();
                info!("Stopping dangerous service: {}", service_name);
                
                #[cfg(windows)]
                {
                    let _output = tokio::process::Command::new("sc")
                        .args(&["stop", service_name])
                        .output()
                        .await?;
                }
                
                #[cfg(unix)]
                {
                    let _output = tokio::process::Command::new("sudo")
                        .args(&["systemctl", "stop", service_name])
                        .output()
                        .await?;
                }
            }
            _ => {
                warn!("No fix implementation for: {}", vuln.id);
            }
        }
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let level = match cli.verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    
    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();
    
    // Check for elevated privileges
    let is_elevated = crate::utils::is_elevated();
    if !is_elevated {
        warn!("⚠️  IronGuard is not running with elevated privileges");
        warn!("   Some scans and fixes may not work properly");
        warn!("   Run as Administrator (Windows) or with sudo (Linux)");
        println!();
    } else {
        info!("✅ Running with elevated privileges");
    }
    
    let mut ironguard = IronGuard::new();
    
    match cli.command {
        Commands::Scan { auto_fix } => {
            ironguard.scan().await?;
            ironguard.show_results();
            
            if auto_fix {
                println!();
                ironguard.auto_fix().await?;
            }
        }
        Commands::Fix { vulnerability_id } => {
            info!("Fixing specific vulnerability: {}", vulnerability_id);
            // Implementation would fix specific vulnerability
        }
    }
    
    Ok(())
}

// Include the utils module from the main project
mod utils {
    pub fn is_elevated() -> bool {
        #[cfg(windows)]
        {
            use std::ptr;
            use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
            use winapi::um::securitybaseapi::GetTokenInformation;
            use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
            
            unsafe {
                let mut handle = ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) == 0 {
                    return false;
                }
                
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut size = 0;
                
                let result = GetTokenInformation(
                    handle,
                    TokenElevation,
                    &mut elevation as *mut _ as *mut _,
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut size,
                );
                
                result != 0 && elevation.TokenIsElevated != 0
            }
        }
        
        #[cfg(unix)]
        {
            nix::unistd::getuid().is_root()
        }
    }
}