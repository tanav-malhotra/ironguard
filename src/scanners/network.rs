use super::{Scanner, Vulnerability, VulnerabilityCategory, VulnerabilityLevel};
use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct NetworkScanner {
    config: Config,
}

impl NetworkScanner {
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self { config })
    }
    
    async fn scan_open_ports(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Common ports that should be checked
        let common_ports = vec![
            (21, "FTP", VulnerabilityLevel::High),
            (22, "SSH", VulnerabilityLevel::Low), // SSH is often needed
            (23, "Telnet", VulnerabilityLevel::Critical),
            (25, "SMTP", VulnerabilityLevel::Medium),
            (53, "DNS", VulnerabilityLevel::Low),
            (80, "HTTP", VulnerabilityLevel::Low),
            (110, "POP3", VulnerabilityLevel::Medium),
            (135, "RPC", VulnerabilityLevel::High),
            (139, "NetBIOS", VulnerabilityLevel::High),
            (143, "IMAP", VulnerabilityLevel::Medium),
            (389, "LDAP", VulnerabilityLevel::Medium),
            (443, "HTTPS", VulnerabilityLevel::Low),
            (445, "SMB", VulnerabilityLevel::High),
            (993, "IMAPS", VulnerabilityLevel::Low),
            (995, "POP3S", VulnerabilityLevel::Low),
            (1433, "SQL Server", VulnerabilityLevel::High),
            (1521, "Oracle", VulnerabilityLevel::High),
            (3306, "MySQL", VulnerabilityLevel::High),
            (3389, "RDP", VulnerabilityLevel::Medium),
            (5432, "PostgreSQL", VulnerabilityLevel::High),
            (5900, "VNC", VulnerabilityLevel::High),
            (6379, "Redis", VulnerabilityLevel::High),
        ];
        
        // Dangerous ports that should typically be closed
        let dangerous_ports = vec![
            (21, "FTP - File Transfer Protocol"),
            (23, "Telnet - Unencrypted remote access"),
            (135, "RPC - Remote Procedure Call"),
            (139, "NetBIOS - File sharing"),
            (445, "SMB - Server Message Block"),
            (1433, "SQL Server - Database"),
            (3306, "MySQL - Database"),
            (5432, "PostgreSQL - Database"),
            (5900, "VNC - Remote desktop"),
            (6379, "Redis - In-memory database"),
        ];
        
        for (port, service_name, default_level) in common_ports {
            if self.is_port_open_localhost(port).await {
                let level = if dangerous_ports.iter().any(|(p, _)| *p == port) {
                    VulnerabilityLevel::High
                } else {
                    default_level
                };
                
                let is_dangerous = dangerous_ports.iter().any(|(p, _)| *p == port);
                
                if is_dangerous {
                    vulnerabilities.push(Vulnerability {
                        id: format!("open-dangerous-port-{}", port),
                        title: format!("Dangerous port {} ({}) is open", port, service_name),
                        description: format!("Port {} is open and running {} which can be a security risk", port, service_name),
                        level: level.clone(),
                        category: VulnerabilityCategory::NetworkSecurity,
                        evidence: vec![format!("Port: {} ({}), Status: Open", port, service_name)],
                        remediation: format!("Close port {} or ensure the {} service is properly secured", port, service_name),
                        auto_fixable: false, // Port closing usually requires manual intervention
                        cve_ids: vec![],
                        score_impact: match level {
                            VulnerabilityLevel::Critical => 15,
                            VulnerabilityLevel::High => 10,
                            VulnerabilityLevel::Medium => 6,
                            _ => 3,
                        },
                    });
                }
            }
        }
        
        // Check for competition-specific port requirements
        if let Some(custom_ssh_port) = self.config.competition.custom_ssh_port {
            if !self.is_port_open_localhost(custom_ssh_port).await {
                vulnerabilities.push(Vulnerability {
                    id: format!("missing-custom-ssh-port-{}", custom_ssh_port),
                    title: format!("SSH not listening on required port {}", custom_ssh_port),
                    description: format!("Competition requires SSH to be available on port {}", custom_ssh_port),
                    level: VulnerabilityLevel::Medium,
                    category: VulnerabilityCategory::NetworkSecurity,
                    evidence: vec![format!("Expected SSH port: {}, Status: Closed", custom_ssh_port)],
                    remediation: format!("Configure SSH to listen on port {}", custom_ssh_port),
                    auto_fixable: true,
                    cve_ids: vec![],
                    score_impact: 8,
                });
            }
            
            // Ensure standard SSH port 22 is closed if custom port is required
            if custom_ssh_port != 22 && self.is_port_open_localhost(22).await {
                vulnerabilities.push(Vulnerability {
                    id: "ssh-standard-port-open".to_string(),
                    title: "SSH listening on standard port 22 when custom port is required".to_string(),
                    description: "SSH should only listen on the competition-specified port".to_string(),
                    level: VulnerabilityLevel::Medium,
                    category: VulnerabilityCategory::NetworkSecurity,
                    evidence: vec!["Port: 22 (SSH), Status: Open".to_string()],
                    remediation: "Disable SSH on port 22 and ensure it only runs on the custom port".to_string(),
                    auto_fixable: true,
                    cve_ids: vec![],
                    score_impact: 6,
                });
            }
        }
        
        Ok(vulnerabilities)
    }
    
    async fn scan_firewall_configuration(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        #[cfg(windows)]
        {
            vulnerabilities.extend(self.scan_windows_firewall().await?);
        }
        
        #[cfg(unix)]
        {
            vulnerabilities.extend(self.scan_unix_firewall().await?);
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(windows)]
    async fn scan_windows_firewall(&self) -> Result<Vec<Vulnerability>> {
        use crate::utils::execute_command;
        let mut vulnerabilities = Vec::new();
        
        // Check if Windows Firewall is enabled
        match execute_command("netsh", &["advfirewall", "show", "allprofiles"]).await {
            Ok(output) => {
                if output.contains("State                                 OFF") {
                    vulnerabilities.push(Vulnerability {
                        id: "windows-firewall-disabled".to_string(),
                        title: "Windows Firewall is disabled".to_string(),
                        description: "The Windows Firewall is turned off, which is a significant security risk".to_string(),
                        level: VulnerabilityLevel::Critical,
                        category: VulnerabilityCategory::NetworkSecurity,
                        evidence: vec!["Windows Firewall State: OFF".to_string()],
                        remediation: "Enable Windows Firewall for all profiles".to_string(),
                        auto_fixable: true,
                        cve_ids: vec![],
                        score_impact: 20,
                    });
                }
            }
            Err(e) => warn!("Failed to check Windows Firewall status: {}", e),
        }
        
        // Check for overly permissive firewall rules
        match execute_command("netsh", &["advfirewall", "firewall", "show", "rule", "name=all"]).await {
            Ok(output) => {
                for (line_num, line) in output.lines().enumerate() {
                    if line.contains("Action:") && line.contains("Allow") {
                        if output.lines().nth(line_num.saturating_sub(2)).unwrap_or("").contains("Any") ||
                           output.lines().nth(line_num.saturating_sub(1)).unwrap_or("").contains("Any") {
                            vulnerabilities.push(Vulnerability {
                                id: format!("permissive-firewall-rule-{}", line_num),
                                title: "Overly permissive firewall rule found".to_string(),
                                description: "Firewall rule allows traffic from any source or to any destination".to_string(),
                                level: VulnerabilityLevel::Medium,
                                category: VulnerabilityCategory::NetworkSecurity,
                                evidence: vec![format!("Rule line {}: {}", line_num, line)],
                                remediation: "Review and restrict firewall rules to specific addresses/ports".to_string(),
                                auto_fixable: false,
                                cve_ids: vec![],
                                score_impact: 5,
                            });
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to check Windows Firewall rules: {}", e),
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(unix)]
    async fn scan_unix_firewall(&self) -> Result<Vec<Vulnerability>> {
        use crate::utils::execute_command;
        let mut vulnerabilities = Vec::new();
        
        // Check iptables
        match execute_command("iptables", &["-L", "-n"]).await {
            Ok(output) => {
                // Check if iptables has any rules (basic check)
                let lines: Vec<&str> = output.lines().collect();
                if lines.len() < 10 { // Very few lines usually means no rules
                    vulnerabilities.push(Vulnerability {
                        id: "no-firewall-rules".to_string(),
                        title: "No firewall rules configured".to_string(),
                        description: "iptables appears to have no filtering rules configured".to_string(),
                        level: VulnerabilityLevel::High,
                        category: VulnerabilityCategory::NetworkSecurity,
                        evidence: vec!["iptables output shows minimal rules".to_string()],
                        remediation: "Configure appropriate iptables rules to filter traffic".to_string(),
                        auto_fixable: false,
                        cve_ids: vec![],
                        score_impact: 12,
                    });
                }
                
                // Check for dangerous ACCEPT rules
                for (line_num, line) in output.lines().enumerate() {
                    if line.contains("ACCEPT") && line.contains("0.0.0.0/0") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("permissive-iptables-rule-{}", line_num),
                            title: "Overly permissive iptables rule".to_string(),
                            description: "iptables rule accepts traffic from any source (0.0.0.0/0)".to_string(),
                            level: VulnerabilityLevel::Medium,
                            category: VulnerabilityCategory::NetworkSecurity,
                            evidence: vec![format!("Rule: {}", line)],
                            remediation: "Review and restrict iptables rules to specific networks".to_string(),
                            auto_fixable: false,
                            cve_ids: vec![],
                            score_impact: 6,
                        });
                    }
                }
            }
            Err(_) => {
                // Try ufw (Ubuntu Firewall)
                match execute_command("ufw", &["status"]).await {
                    Ok(output) => {
                        if output.contains("Status: inactive") {
                            vulnerabilities.push(Vulnerability {
                                id: "ufw-disabled".to_string(),
                                title: "UFW firewall is disabled".to_string(),
                                description: "Ubuntu Firewall (ufw) is not active".to_string(),
                                level: VulnerabilityLevel::High,
                                category: VulnerabilityCategory::NetworkSecurity,
                                evidence: vec!["UFW Status: inactive".to_string()],
                                remediation: "Enable UFW firewall with appropriate rules".to_string(),
                                auto_fixable: true,
                                cve_ids: vec![],
                                score_impact: 12,
                            });
                        }
                    }
                    Err(_) => {
                        debug!("No recognizable firewall found");
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    async fn scan_network_shares(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        #[cfg(windows)]
        {
            use crate::utils::execute_command;
            
            // Check for network shares
            match execute_command("net", &["share"]).await {
                Ok(output) => {
                    for line in output.lines() {
                        if !line.trim().is_empty() && !line.starts_with("Share name") && !line.starts_with("The command") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if let Some(share_name) = parts.first() {
                                if *share_name != "ADMIN$" && *share_name != "C$" && *share_name != "IPC$" {
                                    vulnerabilities.push(Vulnerability {
                                        id: format!("network-share-{}", share_name),
                                        title: format!("Network share '{}' is exposed", share_name),
                                        description: "Network shares can be exploited if not properly secured".to_string(),
                                        level: VulnerabilityLevel::Medium,
                                        category: VulnerabilityCategory::NetworkSecurity,
                                        evidence: vec![format!("Share: {}", line)],
                                        remediation: format!("Review and secure or remove the '{}' network share", share_name),
                                        auto_fixable: false,
                                        cve_ids: vec![],
                                        score_impact: 6,
                                    });
                                }
                            }
                        }
                    }
                }
                Err(e) => warn!("Failed to check network shares: {}", e),
            }
        }
        
        Ok(vulnerabilities)
    }
    
    async fn is_port_open_localhost(&self, port: u16) -> bool {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        timeout(Duration::from_millis(100), TcpStream::connect(addr))
            .await
            .is_ok()
    }
}

#[async_trait]
impl Scanner for NetworkScanner {
    fn name(&self) -> &str {
        "Network Security Scanner"
    }
    
    fn description(&self) -> &str {
        "Scans for network security issues including open ports, firewall configuration, and network shares"
    }
    
    fn category(&self) -> VulnerabilityCategory {
        VulnerabilityCategory::NetworkSecurity
    }
    
    async fn scan(&self) -> Result<Vec<Vulnerability>> {
        debug!("Starting network security scan");
        
        let mut all_vulnerabilities = Vec::new();
        
        // Run all network-related scans
        all_vulnerabilities.extend(self.scan_open_ports().await?);
        all_vulnerabilities.extend(self.scan_firewall_configuration().await?);
        all_vulnerabilities.extend(self.scan_network_shares().await?);
        
        debug!("Network scanner found {} vulnerabilities", all_vulnerabilities.len());
        Ok(all_vulnerabilities)
    }
    
    async fn fix(&self, vulnerability: &Vulnerability) -> Result<()> {
        debug!("Attempting to fix vulnerability: {}", vulnerability.id);
        
        // Implementation would fix specific vulnerabilities
        match vulnerability.id.split('-').next() {
            Some("firewall") => {
                self.fix_firewall_issue(vulnerability).await?;
            }
            Some("port") => {
                self.fix_port_issue(vulnerability).await?;
            }
            _ => {
                warn!("Unknown network vulnerability type for auto-fix: {}", vulnerability.id);
            }
        }
        
        Ok(())
    }
    
    fn can_fix(&self, vulnerability: &Vulnerability) -> bool {
        vulnerability.auto_fixable
    }
}

impl NetworkScanner {
    async fn fix_firewall_issue(&self, _vulnerability: &Vulnerability) -> Result<()> {
        debug!("Fixing firewall vulnerability (placeholder)");
        Ok(())
    }
    
    async fn fix_port_issue(&self, _vulnerability: &Vulnerability) -> Result<()> {
        debug!("Fixing port vulnerability (placeholder)");
        Ok(())
    }
}