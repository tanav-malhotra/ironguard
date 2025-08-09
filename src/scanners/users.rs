use super::{Scanner, Vulnerability, VulnerabilityCategory, VulnerabilityLevel};
use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashSet;
use tracing::{debug, warn};

pub struct UserScanner {
    config: Config,
}

impl UserScanner {
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self { config })
    }
    
    async fn scan_weak_passwords(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        #[cfg(windows)]
        {
            // Check for common weak passwords on Windows
            vulnerabilities.extend(self.scan_windows_passwords().await?);
        }
        
        #[cfg(unix)]
        {
            // Check for weak passwords on Unix systems
            vulnerabilities.extend(self.scan_unix_passwords().await?);
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(windows)]
    async fn scan_windows_passwords(&self) -> Result<Vec<Vulnerability>> {
        use crate::utils::execute_command;
        let mut vulnerabilities = Vec::new();
        
        // Check for users with no password expiration
        match execute_command("net", &["user"]).await {
            Ok(output) => {
                for line in output.lines() {
                    if line.contains("Password never expires") && line.contains("Yes") {
                        let username = line.split_whitespace().next().unwrap_or("unknown");
                        vulnerabilities.push(Vulnerability {
                            id: format!("weak-password-policy-{}", username),
                            title: format!("User '{}' has password that never expires", username),
                            description: "Password expiration is disabled, which is a security risk.".to_string(),
                            level: VulnerabilityLevel::Medium,
                            category: VulnerabilityCategory::UserManagement,
                            evidence: vec![format!("User account: {}", username)],
                            remediation: "Set password expiration policy for the user account.".to_string(),
                            auto_fixable: true,
                            cve_ids: vec![],
                            score_impact: 5,
                        });
                    }
                }
            }
            Err(e) => warn!("Failed to check Windows user passwords: {}", e),
        }
        
        // Check for empty passwords
        match execute_command("net", &["user"]).await {
            Ok(output) => {
                for line in output.lines() {
                    if !line.trim().is_empty() && !line.starts_with("User accounts") && !line.starts_with("The command") {
                        let username = line.split_whitespace().next().unwrap_or("");
                        if !username.is_empty() {
                            // Check individual user for empty password
                            if let Ok(user_info) = execute_command("net", &["user", username]).await {
                                if user_info.contains("Password required") && user_info.contains("No") {
                                    vulnerabilities.push(Vulnerability {
                                        id: format!("empty-password-{}", username),
                                        title: format!("User '{}' has no password", username),
                                        description: "User account has no password set, which is a critical security vulnerability.".to_string(),
                                        level: VulnerabilityLevel::Critical,
                                        category: VulnerabilityCategory::UserManagement,
                                        evidence: vec![format!("User account: {}", username)],
                                        remediation: "Set a strong password for the user account.".to_string(),
                                        auto_fixable: true,
                                        cve_ids: vec![],
                                        score_impact: 15,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to enumerate Windows users: {}", e),
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(unix)]
    async fn scan_unix_passwords(&self) -> Result<Vec<Vulnerability>> {
        use std::fs;
        let mut vulnerabilities = Vec::new();
        
        // Check /etc/shadow for weak password configurations
        if let Ok(shadow_content) = fs::read_to_string("/etc/shadow") {
            for line in shadow_content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    let username = parts[0];
                    let password_hash = parts[1];
                    
                    // Check for empty password
                    if password_hash.is_empty() || password_hash == "!" {
                        vulnerabilities.push(Vulnerability {
                            id: format!("empty-password-{}", username),
                            title: format!("User '{}' has no password or disabled account", username),
                            description: "User account has no password or is disabled.".to_string(),
                            level: VulnerabilityLevel::High,
                            category: VulnerabilityCategory::UserManagement,
                            evidence: vec![format!("User: {}, Hash: {}", username, password_hash)],
                            remediation: "Set a strong password or properly disable the account.".to_string(),
                            auto_fixable: false, // Requires manual intervention
                            cve_ids: vec![],
                            score_impact: 10,
                        });
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    async fn scan_unauthorized_users(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let allowed_users: HashSet<String> = self.config.competition.allowed_users.iter().cloned().collect();
        
        #[cfg(windows)]
        {
            vulnerabilities.extend(self.scan_windows_users(&allowed_users).await?);
        }
        
        #[cfg(unix)]
        {
            vulnerabilities.extend(self.scan_unix_users(&allowed_users).await?);
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(windows)]
    async fn scan_windows_users(&self, allowed_users: &HashSet<String>) -> Result<Vec<Vulnerability>> {
        use crate::utils::execute_command;
        let mut vulnerabilities = Vec::new();
        
        match execute_command("net", &["user"]).await {
            Ok(output) => {
                for line in output.lines() {
                    if !line.trim().is_empty() && !line.starts_with("User accounts") && !line.starts_with("The command") {
                        let username = line.split_whitespace().next().unwrap_or("").to_string();
                        if !username.is_empty() && !allowed_users.contains(&username) {
                            // Check if user is in administrators group
                            if let Ok(group_info) = execute_command("net", &["localgroup", "administrators"]).await {
                                if group_info.contains(&username) {
                                    vulnerabilities.push(Vulnerability {
                                        id: format!("unauthorized-admin-{}", username),
                                        title: format!("Unauthorized admin user '{}'", username),
                                        description: "User has administrative privileges but is not in the approved user list.".to_string(),
                                        level: VulnerabilityLevel::High,
                                        category: VulnerabilityCategory::UserManagement,
                                        evidence: vec![format!("User: {}, Group: Administrators", username)],
                                        remediation: "Remove user from administrators group or delete the account.".to_string(),
                                        auto_fixable: true,
                                        cve_ids: vec![],
                                        score_impact: 8,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to scan Windows users: {}", e),
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(unix)]
    async fn scan_unix_users(&self, allowed_users: &HashSet<String>) -> Result<Vec<Vulnerability>> {
        use std::fs;
        let mut vulnerabilities = Vec::new();
        
        // Check /etc/passwd for unauthorized users
        if let Ok(passwd_content) = fs::read_to_string("/etc/passwd") {
            for line in passwd_content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 7 {
                    let username = parts[0].to_string();
                    let uid: u32 = parts[2].parse().unwrap_or(0);
                    let shell = parts[6];
                    
                    // Check for unauthorized users with shell access
                    if uid >= 1000 && !allowed_users.contains(&username) && 
                       (shell.contains("bash") || shell.contains("sh") || shell.contains("zsh")) {
                        vulnerabilities.push(Vulnerability {
                            id: format!("unauthorized-user-{}", username),
                            title: format!("Unauthorized user '{}' with shell access", username),
                            description: "User has shell access but is not in the approved user list.".to_string(),
                            level: VulnerabilityLevel::Medium,
                            category: VulnerabilityCategory::UserManagement,
                            evidence: vec![format!("User: {}, UID: {}, Shell: {}", username, uid, shell)],
                            remediation: "Remove user or change shell to /bin/false.".to_string(),
                            auto_fixable: true,
                            cve_ids: vec![],
                            score_impact: 6,
                        });
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    async fn scan_sudo_privileges(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        #[cfg(unix)]
        {
            use std::fs;
            
            // Check sudoers file for dangerous configurations
            if let Ok(sudoers_content) = fs::read_to_string("/etc/sudoers") {
                for (line_num, line) in sudoers_content.lines().enumerate() {
                    let line = line.trim();
                    
                    // Check for NOPASSWD entries
                    if line.contains("NOPASSWD") && !line.starts_with('#') {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sudo-nopasswd-{}", line_num),
                            title: "Sudo NOPASSWD configuration found".to_string(),
                            description: "Sudo is configured to allow commands without password verification.".to_string(),
                            level: VulnerabilityLevel::High,
                            category: VulnerabilityCategory::AccessControl,
                            evidence: vec![format!("Line {}: {}", line_num + 1, line)],
                            remediation: "Remove NOPASSWD from sudo configuration.".to_string(),
                            auto_fixable: true,
                            cve_ids: vec![],
                            score_impact: 7,
                        });
                    }
                    
                    // Check for wildcard permissions
                    if line.contains("ALL=(ALL)") && !line.starts_with('#') {
                        vulnerabilities.push(Vulnerability {
                            id: format!("sudo-wildcard-{}", line_num),
                            title: "Overly permissive sudo configuration".to_string(),
                            description: "Sudo is configured with wildcard permissions allowing all commands.".to_string(),
                            level: VulnerabilityLevel::Medium,
                            category: VulnerabilityCategory::AccessControl,
                            evidence: vec![format!("Line {}: {}", line_num + 1, line)],
                            remediation: "Restrict sudo permissions to specific commands only.".to_string(),
                            auto_fixable: false,
                            cve_ids: vec![],
                            score_impact: 5,
                        });
                    }
                }
            }
        }
        
        Ok(vulnerabilities)
    }
}

#[async_trait]
impl Scanner for UserScanner {
    fn name(&self) -> &str {
        "User Management Scanner"
    }
    
    fn description(&self) -> &str {
        "Scans for user account security issues including weak passwords, unauthorized users, and privilege escalation vulnerabilities"
    }
    
    fn category(&self) -> VulnerabilityCategory {
        VulnerabilityCategory::UserManagement
    }
    
    async fn scan(&self) -> Result<Vec<Vulnerability>> {
        debug!("Starting user management security scan");
        
        let mut all_vulnerabilities = Vec::new();
        
        // Run all user-related scans
        all_vulnerabilities.extend(self.scan_weak_passwords().await?);
        all_vulnerabilities.extend(self.scan_unauthorized_users().await?);
        all_vulnerabilities.extend(self.scan_sudo_privileges().await?);
        
        debug!("User scanner found {} vulnerabilities", all_vulnerabilities.len());
        Ok(all_vulnerabilities)
    }
    
    async fn fix(&self, vulnerability: &Vulnerability) -> Result<()> {
        debug!("Attempting to fix vulnerability: {}", vulnerability.id);
        
        // Implementation would fix specific vulnerabilities
        // This is a simplified example
        match vulnerability.id.split('-').next() {
            Some("weak") | Some("empty") => {
                // Generate and set strong password
                self.fix_password_vulnerability(vulnerability).await?;
            }
            Some("unauthorized") => {
                // Remove unauthorized user or revoke privileges
                self.fix_unauthorized_user(vulnerability).await?;
            }
            Some("sudo") => {
                // Fix sudo configuration
                self.fix_sudo_configuration(vulnerability).await?;
            }
            _ => {
                warn!("Unknown vulnerability type for auto-fix: {}", vulnerability.id);
            }
        }
        
        Ok(())
    }
    
    fn can_fix(&self, vulnerability: &Vulnerability) -> bool {
        vulnerability.auto_fixable
    }
}

impl UserScanner {
    async fn fix_password_vulnerability(&self, _vulnerability: &Vulnerability) -> Result<()> {
        // Implementation would fix password-related vulnerabilities
        debug!("Fixing password vulnerability (placeholder)");
        Ok(())
    }
    
    async fn fix_unauthorized_user(&self, _vulnerability: &Vulnerability) -> Result<()> {
        // Implementation would fix unauthorized user issues
        debug!("Fixing unauthorized user vulnerability (placeholder)");
        Ok(())
    }
    
    async fn fix_sudo_configuration(&self, _vulnerability: &Vulnerability) -> Result<()> {
        // Implementation would fix sudo configuration issues
        debug!("Fixing sudo configuration vulnerability (placeholder)");
        Ok(())
    }
}