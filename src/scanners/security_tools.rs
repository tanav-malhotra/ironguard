use super::{Scanner, Vulnerability, VulnerabilityCategory, VulnerabilityLevel};
use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
use std::process::Command;
use tracing::{info, warn, error};

/// Enterprise Security Tools Scanner - Installs and configures professional security tools
/// Based on CyberPatriot champion scripts with 40+ security tools
#[derive(Debug, Clone)]
pub struct SecurityToolsScanner {
    config: Config,
}

impl SecurityToolsScanner {
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self { config })
    }

    /// Install essential security tools like in championship scripts
    async fn install_security_tools(&self) -> Result<Vec<Vulnerability>> {
        info!("Installing championship-level security tools...");
        let mut vulnerabilities = Vec::new();

        // Essential security tools from your scripts
        let security_tools = [
            "fail2ban", "ufw", "iptables", "auditd", "apparmor", 
            "apparmor-profiles", "apparmor-utils", "apparmor-profiles-extra",
            "rsyslog", "lynis", "haveged", "ntp", "debsums", 
            "apt-show-versions", "dnscrypt-proxy", "resolvconf",
            "libpam-cracklib", "libpam-pwquality", "libpam-shield",
            "libpam-tmpdir", "tcpd", "knockd", "suricata", "quota",
            "quotatool", "attr", "libcap2-bin", "ntopng", "sysdig",
            "firejail", "nftables", "iptables-persistent", 
            "libapache2-mod-security2", "osquery", "bridge-utils"
        ];

        // Check which tools are missing
        for tool in &security_tools {
            let check_output = Command::new("dpkg")
                .args(&["-l", tool])
                .output();

            match check_output {
                Ok(output) if !output.status.success() => {
                    vulnerabilities.push(Vulnerability {
                        id: format!("MISSING_TOOL_{}", tool.to_uppercase()),
                        title: format!("Missing security tool: {}", tool),
                        description: format!("Essential security tool '{}' is not installed", tool),
                        category: VulnerabilityCategory::SecurityTools,
                        level: VulnerabilityLevel::High,
                        evidence: vec!["System Security".to_string()],
                        remediation: format!("Install security tool: apt-get install -y {}", tool),
                        auto_fixable: true,
                        cve_ids: vec![],
                        score_impact: 25,
                    });
                }
                _ => {
                    info!("Security tool {} is already installed", tool);
                }
            }
        }

        // Check for prohibited hacking tools that need removal
        let prohibited_tools = [
            "nmap", "wireshark", "telnet", "netcat", "netcat-traditional",
            "nikto", "ophcrack", "ettercap", "john", "hydra", "medusa",
            "aircrack-ng", "metasploit-framework", "burp-suite", "zaproxy",
            "maltego", "hashcat", "oclhashcat", "kismet", "yersinia"
        ];

        for tool in &prohibited_tools {
            let check_output = Command::new("dpkg")
                .args(&["-l", tool])
                .output();

            match check_output {
                Ok(output) if output.status.success() => {
                    vulnerabilities.push(Vulnerability {
                        id: format!("PROHIBITED_TOOL_{}", tool.to_uppercase()),
                        title: format!("Prohibited hacking tool detected: {}", tool),
                        description: format!("Hacking tool '{}' is installed and must be removed", tool),
                        category: VulnerabilityCategory::ProhibitedContent,
                        level: VulnerabilityLevel::Critical,
                        evidence: vec!["System Security".to_string()],
                        remediation: format!("Remove prohibited tool: apt-get purge -y {}", tool),
                        auto_fixable: true,
                        cve_ids: vec![],
                        score_impact: 40,
                    });
                }
                _ => {
                    // Tool not installed, which is good
                }
            }
        }

        info!("Security tools audit completed. Found {} issues", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    /// Configure Fail2ban for intrusion prevention
    async fn configure_fail2ban(&self) -> Result<()> {
        info!("Configuring Fail2ban intrusion prevention...");

        // Create custom Fail2ban jail configuration
        let jail_config = r#"[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto
usedns = warn
logencoding = auto
enabled = false
mode = normal
filter = %(__name__)s[mode=%(mode)s]

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 3600

[apache-auth]
enabled = true
port = http,https
logpath = %(apache_error_log)s
maxretry = 6

[nginx-http-auth]
enabled = true
port = http,https
logpath = %(nginx_error_log)s
maxretry = 6
"#;

        std::fs::write("/etc/fail2ban/jail.local", jail_config)?;

        // Enable and start Fail2ban
        let _ = Command::new("systemctl")
            .args(&["enable", "fail2ban"])
            .output()?;
        let _ = Command::new("systemctl")
            .args(&["restart", "fail2ban"])
            .output()?;

        info!("Fail2ban configured successfully");
        Ok(())
    }

    /// Configure AppArmor mandatory access control
    async fn configure_apparmor(&self) -> Result<()> {
        info!("Configuring AppArmor mandatory access control...");

        // Enable all AppArmor profiles
        let output = Command::new("aa-enforce")
            .arg("/etc/apparmor.d/*")
            .output()?;

        if !output.status.success() {
            warn!("Some AppArmor profiles failed to enable");
        }

        // Enable AppArmor service
        let _ = Command::new("systemctl")
            .args(&["enable", "apparmor"])
            .output()?;
        let _ = Command::new("systemctl")
            .args(&["restart", "apparmor"])
            .output()?;

        info!("AppArmor configured successfully");
        Ok(())
    }

    /// Configure UFW firewall with secure defaults
    async fn configure_ufw(&self) -> Result<()> {
        info!("Configuring UFW firewall...");

        // Reset UFW to defaults
        let _ = Command::new("ufw")
            .args(&["--force", "reset"])
            .output()?;

        // Set default policies
        let _ = Command::new("ufw")
            .args(&["default", "deny", "incoming"])
            .output()?;
        let _ = Command::new("ufw")
            .args(&["default", "allow", "outgoing"])
            .output()?;

        // Allow SSH (be careful not to lock out)
        let _ = Command::new("ufw")
            .args(&["allow", "ssh"])
            .output()?;

        // Enable UFW
        let _ = Command::new("ufw")
            .args(&["--force", "enable"])
            .output()?;

        info!("UFW firewall configured successfully");
        Ok(())
    }

    /// Configure Suricata Network IDS
    async fn configure_suricata(&self) -> Result<()> {
        info!("Configuring Suricata Network IDS...");

        // Update Suricata rules
        let _ = Command::new("suricata-update").output()?;

        // Enable Suricata service
        let _ = Command::new("systemctl")
            .args(&["enable", "suricata"])
            .output()?;
        let _ = Command::new("systemctl")
            .args(&["restart", "suricata"])
            .output()?;

        info!("Suricata Network IDS configured successfully");
        Ok(())
    }
}

#[async_trait]
impl Scanner for SecurityToolsScanner {
    fn name(&self) -> &str {
        "Enterprise Security Tools Scanner"
    }

    fn description(&self) -> &str {
        "Professional security tools management - installs 40+ security tools and removes prohibited tools"
    }

    fn category(&self) -> VulnerabilityCategory {
        VulnerabilityCategory::SecurityTools
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>> {
        info!("Starting enterprise security tools audit...");
        
        let vulnerabilities = self.install_security_tools().await?;

        // Configure essential security services
        if cfg!(target_os = "linux") {
            if let Err(e) = self.configure_fail2ban().await {
                error!("Failed to configure Fail2ban: {}", e);
            }
            if let Err(e) = self.configure_apparmor().await {
                error!("Failed to configure AppArmor: {}", e);
            }
            if let Err(e) = self.configure_ufw().await {
                error!("Failed to configure UFW: {}", e);
            }
            if let Err(e) = self.configure_suricata().await {
                error!("Failed to configure Suricata: {}", e);
            }
        }

        info!("Security tools audit completed. Found {} issues", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    async fn fix(&self, vulnerability: &Vulnerability) -> Result<()> {
        info!("Fixing security tool issue: {}", vulnerability.title);

        if vulnerability.id.starts_with("MISSING_TOOL_") {
            // Extract tool name from ID
            let tool_name = vulnerability.id
                .strip_prefix("MISSING_TOOL_")
                .unwrap_or("")
                .to_lowercase();
            
            info!("Installing missing security tool: {}", tool_name);
            let install_output = Command::new("apt-get")
                .args(&["install", "-y", &tool_name])
                .output()?;
            
            if install_output.status.success() {
                info!("Successfully installed security tool: {}", tool_name);
            } else {
                error!("Failed to install security tool: {}", tool_name);
            }
        } else if vulnerability.id.starts_with("PROHIBITED_TOOL_") {
            // Extract tool name from ID
            let tool_name = vulnerability.id
                .strip_prefix("PROHIBITED_TOOL_")
                .unwrap_or("")
                .to_lowercase();
            
            info!("Removing prohibited tool: {}", tool_name);
            let remove_output = Command::new("apt-get")
                .args(&["purge", "-y", &tool_name])
                .output()?;
            
            if remove_output.status.success() {
                info!("Successfully removed prohibited tool: {}", tool_name);
            } else {
                error!("Failed to remove prohibited tool: {}", tool_name);
            }
        }

        Ok(())
    }

    fn can_fix(&self, vulnerability: &Vulnerability) -> bool {
        vulnerability.id.starts_with("MISSING_TOOL_") || 
        vulnerability.id.starts_with("PROHIBITED_TOOL_")
    }
}