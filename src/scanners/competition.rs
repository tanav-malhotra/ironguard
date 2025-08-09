use super::{Scanner, Vulnerability, VulnerabilityCategory, VulnerabilityLevel};
use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

/// CyberPatriot Competition-Specific Scanner
/// Handles forensics questions, README parsing, prohibited content detection
#[derive(Debug, Clone)]
pub struct CompetitionScanner {
    config: Config,
}

impl CompetitionScanner {
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self { config })
    }

    /// Find prohibited media files (from your media_finder.sh script)
    async fn scan_prohibited_media(&self) -> Result<Vec<Vulnerability>> {
        info!("Scanning for prohibited media files...");
        let mut vulnerabilities = Vec::new();

        let media_extensions = [
            "mp3", "mp4", "wav", "avi", "mkv", "flac", "mov", "wmv", 
            "m4a", "aac", "ogg", "webm", "m4v", "3gp", "flv"
        ];

        // Scan common directories for media files
        let scan_paths = ["/home", "/tmp", "/var/tmp", "/opt"];

        for scan_path in &scan_paths {
            if !Path::new(scan_path).exists() {
                continue;
            }

            for ext in &media_extensions {
                let pattern = format!("*.{}", ext);
                let find_output = std::process::Command::new("find")
                    .args(&[scan_path, "-type", "f", "-name", &pattern])
                    .output();

                match find_output {
                    Ok(output) => {
                        let files = String::from_utf8_lossy(&output.stdout);
                        for file_path in files.lines() {
                            if !file_path.trim().is_empty() {
                                vulnerabilities.push(Vulnerability {
                                    id: format!("MEDIA_{}", vulnerabilities.len() + 1),
                                    title: format!("Prohibited media file detected"),
                                    description: format!("Found media file: {}", file_path),
                                    category: VulnerabilityCategory::ProhibitedContent,
                                    level: VulnerabilityLevel::High,
                                    evidence: vec![file_path.to_string()],
                                    remediation: format!("Review and remove if unauthorized: {}", file_path),
                                    auto_fixable: false,
                                    cve_ids: vec![],
                                    score_impact: 15,
                                });
                            }
                        }
                    }
                    Err(e) => warn!("Failed to search for .{} files in {}: {}", ext, scan_path, e),
                }
            }
        }

        // Save results to file like in your script
        let media_list: Vec<String> = vulnerabilities
            .iter()
            .filter_map(|v| v.evidence.first().cloned())
            .collect();
        
        if let Err(e) = fs::write("./media_files.txt", media_list.join("\n")) {
            warn!("Failed to write media_files.txt: {}", e);
        }

        info!("Media file scan completed. Found {} media files", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    /// Check for README file and parse competition requirements
    async fn check_readme_compliance(&self) -> Result<Vec<Vulnerability>> {
        info!("Checking README file compliance...");
        let mut vulnerabilities = Vec::new();

        // Look for README files in common locations
        let readme_locations = [
            "/home/*/Desktop/README*",
            "/root/Desktop/README*", 
            "/Desktop/README*",
            "README*"
        ];

        let mut readme_found = false;
        for pattern in &readme_locations {
            let glob_output = std::process::Command::new("find")
                .args(&["/", "-name", pattern, "-type", "f"])
                .output();

            if let Ok(output) = glob_output {
                let files = String::from_utf8_lossy(&output.stdout);
                if !files.trim().is_empty() {
                    readme_found = true;
                    info!("Found README file(s): {}", files.trim());
                    break;
                }
            }
        }

        if !readme_found {
            vulnerabilities.push(Vulnerability {
                id: "README_MISSING".to_string(),
                title: "README file not found".to_string(),
                description: "No README file found on Desktop - required for competition compliance".to_string(),
                category: VulnerabilityCategory::Competition,
                level: VulnerabilityLevel::Critical,
                evidence: vec!["Competition Requirements".to_string()],
                remediation: "Locate and read the README file for competition requirements".to_string(),
                auto_fixable: false,
                cve_ids: vec![],
                score_impact: 30,
            });
        }

        // Check for required users.txt and admins.txt files
        if !Path::new("./users.txt").exists() {
            vulnerabilities.push(Vulnerability {
                id: "USERS_TXT_MISSING".to_string(),
                title: "users.txt file missing".to_string(),
                description: "users.txt file required for user management not found".to_string(),
                category: VulnerabilityCategory::Competition,
                level: VulnerabilityLevel::High,
                evidence: vec!["User Management".to_string()],
                remediation: "Create users.txt with authorized users from README".to_string(),
                auto_fixable: true,
                cve_ids: vec![],
                score_impact: 20,
            });
        }

        if !Path::new("./admins.txt").exists() {
            vulnerabilities.push(Vulnerability {
                id: "ADMINS_TXT_MISSING".to_string(),
                title: "admins.txt file missing".to_string(),
                description: "admins.txt file required for admin management not found".to_string(),
                category: VulnerabilityCategory::Competition,
                level: VulnerabilityLevel::High,
                evidence: vec!["Admin Management".to_string()],
                remediation: "Create admins.txt with authorized administrators from README".to_string(),
                auto_fixable: true,
                cve_ids: vec![],
                score_impact: 20,
            });
        }

        info!("README compliance check completed. Found {} issues", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    /// Scan for suspicious scripts and executables
    async fn scan_suspicious_scripts(&self) -> Result<Vec<Vulnerability>> {
        info!("Scanning for suspicious scripts...");
        let mut vulnerabilities = Vec::new();

        // Look for recently modified scripts
        let script_extensions = ["sh", "py", "pl", "php", "js", "exe", "bat"];
        
        for ext in &script_extensions {
            let find_output = std::process::Command::new("find")
                .args(&["/home", "-name", &format!("*.{}", ext), "-type", "f", "-mtime", "-7"])
                .output();

            if let Ok(output) = find_output {
                let files = String::from_utf8_lossy(&output.stdout);
                for file_path in files.lines() {
                    if !file_path.trim().is_empty() {
                        // Check if script contains suspicious patterns
                        if let Ok(content) = fs::read_to_string(file_path) {
                            let suspicious_patterns = [
                                "nc -l", "netcat", "/bin/sh", "bash -i", "python -c",
                                "wget", "curl", "chmod +x", "rm -rf", "dd if="
                            ];

                            for pattern in &suspicious_patterns {
                                if content.contains(pattern) {
                                    vulnerabilities.push(Vulnerability {
                                        id: format!("SUSPICIOUS_SCRIPT_{}", vulnerabilities.len() + 1),
                                        title: "Suspicious script detected".to_string(),
                                        description: format!("Script {} contains suspicious pattern: {}", file_path, pattern),
                                        category: VulnerabilityCategory::ProhibitedContent,
                                        level: VulnerabilityLevel::Medium,
                                        evidence: vec![file_path.to_string()],
                                        remediation: "Review script for malicious content".to_string(),
                                        auto_fixable: false,
                                        cve_ids: vec![],
                                        score_impact: 10,
                                    });
                                    break; // Only report once per file
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("Suspicious script scan completed. Found {} issues", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    /// Check for unusual user files and directories
    async fn scan_user_anomalies(&self) -> Result<Vec<Vulnerability>> {
        info!("Scanning for user directory anomalies...");
        let mut vulnerabilities = Vec::new();

        // Find recently created files in user directories
        let find_output = std::process::Command::new("find")
            .args(&["/home", "-type", "f", "-ctime", "-1"])
            .output();

        if let Ok(output) = find_output {
            let files = String::from_utf8_lossy(&output.stdout);
            let recent_files: Vec<&str> = files.lines().collect();
            
            if recent_files.len() > 50 { // Threshold for suspicious activity
                vulnerabilities.push(Vulnerability {
                    id: "RECENT_FILES_ANOMALY".to_string(),
                    title: "Unusual number of recent files".to_string(),
                    description: format!("Found {} recently created files in user directories", recent_files.len()),
                    category: VulnerabilityCategory::Forensics,
                    level: VulnerabilityLevel::Medium,
                    evidence: vec!["User Directories".to_string()],
                    remediation: "Investigate recent file activity for potential data exfiltration".to_string(),
                    auto_fixable: false,
                    cve_ids: vec![],
                    score_impact: 15,
                });
            }

            // Save recent files list for forensics
            if let Err(e) = fs::write("./recent_files.txt", files.as_ref()) {
                warn!("Failed to write recent_files.txt: {}", e);
            }
        }

        info!("User anomaly scan completed. Found {} issues", vulnerabilities.len());
        Ok(vulnerabilities)
    }
}

#[async_trait]
impl Scanner for CompetitionScanner {
    fn name(&self) -> &str {
        "CyberPatriot Competition Scanner"
    }

    fn description(&self) -> &str {
        "Competition-specific scanner for forensics, README compliance, prohibited content, and user anomalies"
    }

    fn category(&self) -> VulnerabilityCategory {
        VulnerabilityCategory::Competition
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>> {
        info!("Starting CyberPatriot competition-specific scan...");
        let mut all_vulnerabilities = Vec::new();

        // Run all competition-specific scans
        if let Ok(mut media_vulns) = self.scan_prohibited_media().await {
            all_vulnerabilities.append(&mut media_vulns);
        }

        if let Ok(mut readme_vulns) = self.check_readme_compliance().await {
            all_vulnerabilities.append(&mut readme_vulns);
        }

        if let Ok(mut script_vulns) = self.scan_suspicious_scripts().await {
            all_vulnerabilities.append(&mut script_vulns);
        }

        if let Ok(mut anomaly_vulns) = self.scan_user_anomalies().await {
            all_vulnerabilities.append(&mut anomaly_vulns);
        }

        info!("Competition scan completed. Total issues found: {}", all_vulnerabilities.len());
        Ok(all_vulnerabilities)
    }

    async fn fix(&self, vulnerability: &Vulnerability) -> Result<()> {
        info!("Attempting to fix competition issue: {}", vulnerability.title);

        match vulnerability.id.as_str() {
            id if id.starts_with("MEDIA_") => {
                // For media files, prompt for manual review rather than auto-delete
                if let Some(file_path) = vulnerability.evidence.first() {
                    info!("Media file requires manual review: {}", file_path);
                }
                // Could implement interactive prompt here in TUI mode
            }
            "USERS_TXT_MISSING" => {
                let default_users = "# Add authorized users from README, one per line\n# Example:\n# alice\n# bob\n";
                fs::write("./users.txt", default_users)?;
                info!("Created template users.txt file");
            }
            "ADMINS_TXT_MISSING" => {
                let default_admins = "# Add authorized administrators from README, one per line\n# Example:\n# admin\n# root\n";
                fs::write("./admins.txt", default_admins)?;
                info!("Created template admins.txt file");
            }
            _ => {
                warn!("Manual investigation required for: {}", vulnerability.title);
            }
        }

        Ok(())
    }

    fn can_fix(&self, vulnerability: &Vulnerability) -> bool {
        matches!(vulnerability.id.as_str(), 
            "USERS_TXT_MISSING" | "ADMINS_TXT_MISSING")
    }
}