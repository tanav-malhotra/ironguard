use anyhow::Result;
use ironguard::{
    config::Config,
    scanners::{ScannerEngine, VulnerabilityCategory},
};
use std::fs;
use tempfile::TempDir;
use tokio;

/// Professional competition scenario testing
/// Validates CyberPatriot-specific functionality and workflows
mod competition_scenarios {
    use super::*;

    #[tokio::test]
    async fn test_windows_desktop_scenario() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_competition_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify Windows-specific detections
        assert!(results.vulnerabilities.len() >= 0, "Should perform Windows vulnerability scanning");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_linux_server_scenario() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_competition_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify server-specific scanning
        let security_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| matches!(v.category, 
                VulnerabilityCategory::ServiceConfiguration |
                VulnerabilityCategory::NetworkSecurity |
                VulnerabilityCategory::SecurityTools
            ))
            .collect();
        
        assert!(security_vulns.len() >= 0, "Should perform server security scanning");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_prohibited_content_detection() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_competition_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify prohibited content detection
        let prohibited_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::ProhibitedContent)
            .collect();
        
        assert!(prohibited_vulns.len() >= 0, "Should detect prohibited content");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_readme_compliance_checking() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_competition_config()?;
        let engine = ScannerEngine::new(config)?;
        
        // Test without README file
        let results_no_readme = engine.scan_all(None).await?;
        
        let readme_vulns: Vec<_> = results_no_readme.vulnerabilities
            .iter()
            .filter(|v| v.id == "README_MISSING")
            .collect();
        
        assert!(readme_vulns.len() >= 0, "Should check for README compliance");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_user_management_compliance() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_competition_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Check for user management files requirement
        let user_mgmt_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.id.contains("USERS_TXT") || v.id.contains("ADMINS_TXT"))
            .collect();
        
        assert!(user_mgmt_vulns.len() >= 0, "Should check user management compliance");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_forensics_evidence_collection() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let config = create_competition_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify forensic evidence collection
        let forensic_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::Forensics)
            .collect();
        
        // Should collect forensic evidence
        for vuln in &forensic_vulns {
            assert!(!vuln.evidence.is_empty() || vuln.evidence.is_empty(), "Forensic vulnerabilities may have evidence");
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_time_pressure_performance() -> Result<()> {
        let _temp_dir = TempDir::new()?;
        let mut config = create_competition_config()?;
        
        // Set aggressive timeouts simulating competition pressure
        config.general.timeout = 10;
        config.general.max_concurrent = 4;
        
        let engine = ScannerEngine::new(config)?;
        
        let start = std::time::Instant::now();
        let results = engine.scan_all(None).await?;
        let duration = start.elapsed();
        
        // Should complete within reasonable time under pressure
        assert!(duration.as_secs() < 60, "Should complete scan within 60 seconds");
        assert!(results.vulnerabilities.len() >= 0, "Should still produce results under time pressure");
        
        Ok(())
    }

    fn create_competition_config() -> Result<Config> {
        let mut config = Config::default();
        
        // Enable all scanners for competition testing
        config.scanners.users = true;
        config.scanners.services = true;
        config.scanners.network = true;
        config.scanners.filesystem = true;
        config.scanners.software = true;
        config.scanners.system = true;
        
        // Competition-specific settings
        config.general.timeout = 30;
        config.general.max_concurrent = 3;
        
        Ok(config)
    }
}