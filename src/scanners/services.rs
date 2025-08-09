use super::{Scanner, Vulnerability, VulnerabilityCategory, VulnerabilityLevel};
use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::{debug, warn};

pub struct ServiceScanner {
    config: Config,
}

impl ServiceScanner {
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self { config })
    }
    
    async fn scan_unnecessary_services(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Define commonly unnecessary services that should be disabled
        let dangerous_services = vec![
            ("telnet", "Telnet service is insecure and should be disabled"),
            ("ftp", "FTP service can be insecure and is often unnecessary"),
            ("tftp", "TFTP service is insecure and rarely needed"),
            ("rsh", "Remote shell service is insecure"),
            ("finger", "Finger service can leak information"),
            ("echo", "Echo service can be used for amplification attacks"),
            ("discard", "Discard service can be used for amplification attacks"),
            ("chargen", "Character generator service can be used for amplification attacks"),
            ("daytime", "Daytime service is rarely needed"),
            ("time", "Time service can be exploited"),
            ("rexec", "Remote execution service is insecure"),
            ("rlogin", "Remote login service is insecure"),
            ("vnc", "VNC service can be insecure if misconfigured"),
        ];
        
        #[cfg(windows)]
        {
            vulnerabilities.extend(self.scan_windows_services(&dangerous_services).await?);
        }
        
        #[cfg(unix)]
        {
            vulnerabilities.extend(self.scan_unix_services(&dangerous_services).await?);
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(windows)]
    async fn scan_windows_services(&self, dangerous_services: &[(&str, &str)]) -> Result<Vec<Vulnerability>> {
        use crate::utils::execute_command;
        let mut vulnerabilities = Vec::new();
        
        match execute_command("sc", &["query", "state=", "all"]).await {
            Ok(output) => {
                let mut current_service = String::new();
                let mut service_state = String::new();
                
                for line in output.lines() {
                    if line.starts_with("SERVICE_NAME:") {
                        current_service = line.replace("SERVICE_NAME:", "").trim().to_lowercase();
                    } else if line.contains("STATE") {
                        service_state = line.to_string();
                        
                        // Check if this service is running and shouldn't be
                        for (service_name, description) in dangerous_services {
                            if current_service.contains(service_name) && service_state.contains("RUNNING") {
                                vulnerabilities.push(Vulnerability {
                                    id: format!("dangerous-service-{}", service_name),
                                    title: format!("Dangerous service '{}' is running", service_name),
                                    description: description.to_string(),
                                    level: VulnerabilityLevel::High,
                                    category: VulnerabilityCategory::ServiceConfiguration,
                                    evidence: vec![format!("Service: {}, State: RUNNING", current_service)],
                                    remediation: format!("Stop and disable the {} service", service_name),
                                    auto_fixable: true,
                                    cve_ids: vec![],
                                    score_impact: 8,
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to scan Windows services: {}", e),
        }
        
        // Check specific Windows services
        let windows_services = vec![
            ("RemoteRegistry", "Remote Registry service allows remote registry access"),
            ("TelnetD", "Telnet server is insecure"),
            ("SimpleFileSharing", "Simple File Sharing can be exploited"),
            ("RemoteAccess", "Remote Access service can be a security risk"),
        ];
        
        for (service_name, description) in windows_services {
            match execute_command("sc", &["query", service_name]).await {
                Ok(output) => {
                    if output.contains("RUNNING") {
                        vulnerabilities.push(Vulnerability {
                            id: format!("windows-service-{}", service_name.to_lowercase()),
                            title: format!("Windows service '{}' is running", service_name),
                            description: description.to_string(),
                            level: VulnerabilityLevel::Medium,
                            category: VulnerabilityCategory::ServiceConfiguration,
                            evidence: vec![format!("Service: {}, State: RUNNING", service_name)],
                            remediation: format!("Stop and disable the {} service", service_name),
                            auto_fixable: true,
                            cve_ids: vec![],
                            score_impact: 6,
                        });
                    }
                }
                Err(_) => {
                    // Service doesn't exist, which is good
                    debug!("Service {} not found (this is good)", service_name);
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(unix)]
    async fn scan_unix_services(&self, dangerous_services: &[(&str, &str)]) -> Result<Vec<Vulnerability>> {
        use crate::utils::execute_command;
        let mut vulnerabilities = Vec::new();
        
        // Check systemd services
        match execute_command("systemctl", &["list-units", "--type=service", "--state=active"]).await {
            Ok(output) => {
                for line in output.lines() {
                    for (service_name, description) in dangerous_services {
                        if line.contains(service_name) && line.contains("active") {
                            vulnerabilities.push(Vulnerability {
                                id: format!("dangerous-service-{}", service_name),
                                title: format!("Dangerous service '{}' is active", service_name),
                                description: description.to_string(),
                                level: VulnerabilityLevel::High,
                                category: VulnerabilityCategory::ServiceConfiguration,
                                evidence: vec![format!("Service: {}, State: active", service_name)],
                                remediation: format!("Stop and disable the {} service using systemctl", service_name),
                                auto_fixable: true,
                                cve_ids: vec![],
                                score_impact: 8,
                            });
                        }
                    }
                }
            }
            Err(_) => {
                // Try init.d services as fallback
                match execute_command("service", &["--status-all"]).await {
                    Ok(output) => {
                        for line in output.lines() {
                            for (service_name, description) in dangerous_services {
                                if line.contains(service_name) && line.contains("+") {
                                    vulnerabilities.push(Vulnerability {
                                        id: format!("dangerous-service-{}", service_name),
                                        title: format!("Dangerous service '{}' is running", service_name),
                                        description: description.to_string(),
                                        level: VulnerabilityLevel::High,
                                        category: VulnerabilityCategory::ServiceConfiguration,
                                        evidence: vec![format!("Service: {}, State: running", service_name)],
                                        remediation: format!("Stop and disable the {} service", service_name),
                                        auto_fixable: true,
                                        cve_ids: vec![],
                                        score_impact: 8,
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => warn!("Failed to scan Unix services: {}", e),
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    async fn scan_ssh_configuration(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        #[cfg(unix)]
        {
            use std::fs;
            
            let ssh_config_paths = vec![
                "/etc/ssh/sshd_config",
                "/etc/sshd_config",
            ];
            
            for config_path in ssh_config_paths {
                if let Ok(config_content) = fs::read_to_string(config_path) {
                    vulnerabilities.extend(self.analyze_ssh_config(&config_content, config_path)?);
                    break; // Found a config file, no need to check others
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    #[cfg(unix)]
    fn analyze_ssh_config(&self, config_content: &str, config_path: &str) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        let mut settings = HashMap::new();
        
        // Parse SSH configuration
        for (line_num, line) in config_content.lines().enumerate() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            
            if let Some(space_pos) = line.find(' ') {
                let key = line[..space_pos].to_lowercase();
                let value = line[space_pos + 1..].trim().to_lowercase();
                settings.insert(key, (value, line_num + 1));
            }
        }
        
        // Check for insecure SSH configurations
        let insecure_configs = vec![
            ("rootlogin", "yes", "Root login should be disabled", VulnerabilityLevel::Critical, 15),
            ("passwordauthentication", "yes", "Password authentication should be disabled in favor of key-based auth", VulnerabilityLevel::High, 10),
            ("permitemptypasswords", "yes", "Empty passwords should not be permitted", VulnerabilityLevel::Critical, 20),
            ("x11forwarding", "yes", "X11 forwarding can be a security risk", VulnerabilityLevel::Medium, 5),
            ("gatewayports", "yes", "Gateway ports can be exploited", VulnerabilityLevel::Medium, 6),
            ("permituserenvironment", "yes", "User environment permissions can be dangerous", VulnerabilityLevel::Medium, 4),
        ];
        
        for (setting, dangerous_value, description, level, score) in insecure_configs {
            if let Some((value, line_num)) = settings.get(setting) {
                if value == dangerous_value {
                    vulnerabilities.push(Vulnerability {
                        id: format!("ssh-config-{}", setting),
                        title: format!("Insecure SSH configuration: {}", setting),
                        description: description.to_string(),
                        level,
                        category: VulnerabilityCategory::ServiceConfiguration,
                        evidence: vec![format!("File: {}, Line: {}, Setting: {} {}", config_path, line_num, setting, value)],
                        remediation: format!("Change {} to a secure value in {}", setting, config_path),
                        auto_fixable: true,
                        cve_ids: vec![],
                        score_impact: score,
                    });
                }
            }
        }
        
        // Check for custom SSH port configuration
        if let Some(custom_port) = self.config.competition.custom_ssh_port {
            if let Some((port_value, _)) = settings.get("port") {
                if port_value.parse::<u16>().unwrap_or(22) != custom_port {
                    vulnerabilities.push(Vulnerability {
                        id: "ssh-custom-port".to_string(),
                        title: format!("SSH not configured for competition port {}", custom_port),
                        description: format!("SSH should be configured to use port {} as specified in competition requirements", custom_port),
                        level: VulnerabilityLevel::Medium,
                        category: VulnerabilityCategory::ServiceConfiguration,
                        evidence: vec![format!("Current port: {}, Required port: {}", port_value, custom_port)],
                        remediation: format!("Change SSH port to {} in {}", custom_port, config_path),
                        auto_fixable: true,
                        cve_ids: vec![],
                        score_impact: 8,
                    });
                }
            }
        }
        
        Ok(vulnerabilities)
    }
    
    async fn scan_competition_specific_services(&self) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();
        
        // Check for required services based on competition configuration
        for service_config in &self.config.competition.custom_services {
            let service_running = self.is_service_running(&service_config.name).await?;
            
            if service_config.should_be_running && !service_running {
                vulnerabilities.push(Vulnerability {
                    id: format!("missing-required-service-{}", service_config.name),
                    title: format!("Required service '{}' is not running", service_config.name),
                    description: format!("Competition requires that the {} service be running", service_config.name),
                    level: VulnerabilityLevel::High,
                    category: VulnerabilityCategory::ServiceConfiguration,
                    evidence: vec![format!("Service: {}, Expected: running, Actual: stopped", service_config.name)],
                    remediation: format!("Start and enable the {} service", service_config.name),
                    auto_fixable: true,
                    cve_ids: vec![],
                    score_impact: 10,
                });
            } else if !service_config.should_be_running && service_running {
                vulnerabilities.push(Vulnerability {
                    id: format!("forbidden-service-{}", service_config.name),
                    title: format!("Forbidden service '{}' is running", service_config.name),
                    description: format!("Competition requires that the {} service be stopped", service_config.name),
                    level: VulnerabilityLevel::High,
                    category: VulnerabilityCategory::ServiceConfiguration,
                    evidence: vec![format!("Service: {}, Expected: stopped, Actual: running", service_config.name)],
                    remediation: format!("Stop and disable the {} service", service_config.name),
                    auto_fixable: true,
                    cve_ids: vec![],
                    score_impact: 10,
                });
            }
        }
        
        Ok(vulnerabilities)
    }
    
    async fn is_service_running(&self, service_name: &str) -> Result<bool> {
        #[cfg(windows)]
        {
            use crate::utils::execute_command;
            match execute_command("sc", &["query", service_name]).await {
                Ok(output) => Ok(output.contains("RUNNING")),
                Err(_) => Ok(false),
            }
        }
        
        #[cfg(unix)]
        {
            use crate::utils::execute_command;
            // Try systemctl first
            match execute_command("systemctl", &["is-active", service_name]).await {
                Ok(output) => Ok(output.trim() == "active"),
                Err(_) => {
                    // Fallback to service command
                    match execute_command("service", &[service_name, "status"]).await {
                        Ok(output) => Ok(output.contains("running") || output.contains("active")),
                        Err(_) => Ok(false),
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Scanner for ServiceScanner {
    fn name(&self) -> &str {
        "Service Configuration Scanner"
    }
    
    fn description(&self) -> &str {
        "Scans for insecure service configurations, unnecessary running services, and competition-specific service requirements"
    }
    
    fn category(&self) -> VulnerabilityCategory {
        VulnerabilityCategory::ServiceConfiguration
    }
    
    async fn scan(&self) -> Result<Vec<Vulnerability>> {
        debug!("Starting service configuration security scan");
        
        let mut all_vulnerabilities = Vec::new();
        
        // Run all service-related scans
        all_vulnerabilities.extend(self.scan_unnecessary_services().await?);
        all_vulnerabilities.extend(self.scan_ssh_configuration().await?);
        all_vulnerabilities.extend(self.scan_competition_specific_services().await?);
        
        debug!("Service scanner found {} vulnerabilities", all_vulnerabilities.len());
        Ok(all_vulnerabilities)
    }
    
    async fn fix(&self, vulnerability: &Vulnerability) -> Result<()> {
        debug!("Attempting to fix vulnerability: {}", vulnerability.id);
        
        // Implementation would fix specific vulnerabilities
        match vulnerability.id.split('-').next() {
            Some("dangerous") | Some("forbidden") => {
                self.fix_dangerous_service(vulnerability).await?;
            }
            Some("ssh") => {
                self.fix_ssh_configuration(vulnerability).await?;
            }
            Some("missing") => {
                self.fix_missing_service(vulnerability).await?;
            }
            _ => {
                warn!("Unknown service vulnerability type for auto-fix: {}", vulnerability.id);
            }
        }
        
        Ok(())
    }
    
    fn can_fix(&self, vulnerability: &Vulnerability) -> bool {
        vulnerability.auto_fixable
    }
}

impl ServiceScanner {
    async fn fix_dangerous_service(&self, _vulnerability: &Vulnerability) -> Result<()> {
        debug!("Fixing dangerous service vulnerability (placeholder)");
        Ok(())
    }
    
    async fn fix_ssh_configuration(&self, _vulnerability: &Vulnerability) -> Result<()> {
        debug!("Fixing SSH configuration vulnerability (placeholder)");
        Ok(())
    }
    
    async fn fix_missing_service(&self, _vulnerability: &Vulnerability) -> Result<()> {
        debug!("Fixing missing service vulnerability (placeholder)");
        Ok(())
    }
}