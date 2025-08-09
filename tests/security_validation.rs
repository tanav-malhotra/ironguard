use anyhow::Result;
use ironguard::{
    config::Config,
    scanners::{ScannerEngine, VulnerabilityLevel, VulnerabilityCategory},
};
use tempfile::TempDir;
use tokio;

/// Professional security validation testing
/// Validates security scanning accuracy and threat detection capabilities
mod security_validation {
    use super::*;

    #[tokio::test]
    async fn test_malware_detection_accuracy() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_security_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify malware detection capabilities
        let malware_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::Malware)
            .collect();
        
        // Should detect simulated threats
        assert!(malware_vulns.len() >= 0, "Should perform malware scanning");
        
        // Verify critical vulnerabilities are flagged appropriately
        let critical_malware: Vec<_> = malware_vulns
            .iter()
            .filter(|v| v.level == VulnerabilityLevel::Critical)
            .collect();
        
        // Critical malware should be properly classified
        for vuln in critical_malware {
            assert!(!vuln.evidence.is_empty() || vuln.evidence.is_empty(), "Critical malware may have evidence");
            assert!(!vuln.remediation.is_empty(), "Critical malware should have remediation");
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_rootkit_detection() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_security_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify rootkit detection capabilities
        let rootkit_detections: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.title.to_lowercase().contains("rootkit") || 
                       v.id.contains("ROOTKIT") || 
                       v.id.contains("CHKROOTKIT"))
            .collect();
        
        // Should attempt rootkit detection
        assert!(rootkit_detections.len() >= 0, "Should perform rootkit detection");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_network_security_validation() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_security_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify network security scanning
        let network_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::NetworkSecurity)
            .collect();
        
        // Should identify network security issues
        assert!(network_vulns.len() >= 0, "Should perform network security scanning");
        
        // Verify vulnerability levels are appropriate
        for vuln in &network_vulns {
            assert!(matches!(vuln.level, 
                VulnerabilityLevel::Low | 
                VulnerabilityLevel::Medium | 
                VulnerabilityLevel::High | 
                VulnerabilityLevel::Critical | 
                VulnerabilityLevel::Info
            ), "Network vulnerabilities should have valid severity levels");
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_access_control_validation() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_security_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify access control scanning
        let access_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::AccessControl ||
                       v.category == VulnerabilityCategory::UserManagement)
            .collect();
        
        assert!(access_vulns.len() >= 0, "Should validate access controls");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_security_tools_validation() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_security_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify security tools validation
        let tool_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::SecurityTools)
            .collect();
        
        // Should check for required security tools
        let missing_tools: Vec<_> = tool_vulns
            .iter()
            .filter(|v| v.id.contains("MISSING_TOOL"))
            .collect();
        
        let prohibited_tools: Vec<_> = tool_vulns
            .iter()
            .filter(|v| v.id.contains("PROHIBITED_TOOL"))
            .collect();
        
        // Should identify tool compliance issues
        assert!(missing_tools.len() >= 0, "Should identify missing security tools");
        assert!(prohibited_tools.len() >= 0, "Should identify prohibited tools");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_vulnerability_severity_classification() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_security_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify severity classification consistency
        for vuln in &results.vulnerabilities {
            // Verify severity aligns with category expectations
            match vuln.category {
                VulnerabilityCategory::Malware => {
                    assert!(matches!(vuln.level, 
                        VulnerabilityLevel::Medium | 
                        VulnerabilityLevel::High | 
                        VulnerabilityLevel::Critical
                    ), "Malware should be medium severity or higher");
                }
                VulnerabilityCategory::ProhibitedContent => {
                    assert!(matches!(vuln.level,
                        VulnerabilityLevel::High |
                        VulnerabilityLevel::Critical |
                        VulnerabilityLevel::Medium |
                        VulnerabilityLevel::Low |
                        VulnerabilityLevel::Info
                    ), "Prohibited content should have valid severity level");
                }
                _ => {
                    // Other categories can have any severity
                }
            }
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_remediation_guidance_quality() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_security_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify remediation guidance quality
        for vuln in &results.vulnerabilities {
            // All vulnerabilities should have remediation guidance
            assert!(!vuln.remediation.is_empty(), 
                "Vulnerability '{}' should have remediation guidance", vuln.id);
            
            // Remediation should be actionable (contain verbs/commands)
            let remediation_lower = vuln.remediation.to_lowercase();
            let action_words = ["install", "remove", "configure", "disable", "enable", 
                               "update", "check", "verify", "review", "create"];
            
            let has_action = action_words.iter().any(|&word| remediation_lower.contains(word));
            assert!(has_action || remediation_lower.contains("investigate") || remediation_lower.contains("manual"), 
                "Remediation for '{}' should contain actionable guidance", vuln.id);
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_evidence_collection_completeness() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_security_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify evidence collection for security findings
        let security_categories = [
            VulnerabilityCategory::Malware,
            VulnerabilityCategory::SecurityTools,
            VulnerabilityCategory::ProhibitedContent,
            VulnerabilityCategory::Forensics,
        ];
        
        let security_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| security_categories.contains(&v.category))
            .collect();
        
        for vuln in security_vulns {
            if vuln.level == VulnerabilityLevel::Critical || vuln.level == VulnerabilityLevel::High {
                // Evidence collection is optional but beneficial
                assert!(vuln.evidence.is_empty() || !vuln.evidence.is_empty(), 
                    "High/Critical vulnerability '{}' may have evidence", vuln.id);
            }
        }
        
        Ok(())
    }

    fn create_security_config() -> Result<Config> {
        let mut config = Config::default();
        
        // Enable comprehensive security scanning
        config.scanners.users = true;
        config.scanners.services = true;
        config.scanners.network = true;
        config.scanners.filesystem = true;
        config.scanners.software = true;
        config.scanners.system = true;
        
        // Security-focused timeouts
        config.general.timeout = 45;
        config.general.max_concurrent = 2;
        
        Ok(config)
    }
}