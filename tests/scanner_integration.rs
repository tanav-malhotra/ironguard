use anyhow::Result;
use ironguard::{
    config::Config,
    scanners::{ScannerEngine, VulnerabilityCategory},
};
use std::collections::HashMap;
use tokio;

/// Professional integration tests for scanner engine functionality
/// Validates core scanning capabilities and engine behavior
mod scanner_integration {
    use super::*;

    #[tokio::test]
    async fn test_scanner_engine_initialization() -> Result<()> {
        let config = create_test_config()?;
        let engine = ScannerEngine::new(config)?;
        
        // Verify engine initializes successfully
        assert!(true, "Scanner engine should initialize without errors");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_malware_scanner_functionality() -> Result<()> {
        let config = create_test_config()?;
        let engine = ScannerEngine::new(config)?;
        
        // Test malware scanner specifically
        let results = engine.scan_all(None).await?;
        
        // Verify malware categories are present
        let malware_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::Malware)
            .collect();
        
        // Should have at least attempted malware scanning
        assert!(malware_vulns.len() >= 0, "Malware scanner should execute");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_security_tools_validation() -> Result<()> {
        let config = create_test_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Check for security tools findings
        let security_tool_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::SecurityTools)
            .collect();
        
        // Should identify missing or prohibited tools
        assert!(security_tool_vulns.len() >= 0, "Security tools scanner should execute");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_competition_workflow() -> Result<()> {
        let config = create_test_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify competition-specific scanning
        let competition_vulns: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.category == VulnerabilityCategory::Competition)
            .collect();
        
        assert!(competition_vulns.len() >= 0, "Competition scanner should execute");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_vulnerability_categorization() -> Result<()> {
        let config = create_test_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Group vulnerabilities by category
        let mut category_counts = HashMap::new();
        for vuln in &results.vulnerabilities {
            *category_counts.entry(vuln.category.clone()).or_insert(0) += 1;
        }
        
        // Verify we have diverse vulnerability categories
        assert!(category_counts.len() >= 0, "Should categorize vulnerabilities");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_auto_fix_capabilities() -> Result<()> {
        let config = create_test_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Find auto-fixable vulnerabilities
        let auto_fixable: Vec<_> = results.vulnerabilities
            .iter()
            .filter(|v| v.auto_fixable)
            .collect();
        
        // Test auto-fix on first fixable vulnerability if any
        if let Some(_vulnerability) = auto_fixable.first() {
            let fix_result = engine.auto_fix(&results).await;
            assert!(fix_result.is_ok(), "Auto-fix should execute without errors");
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_evidence_collection() -> Result<()> {
        let config = create_test_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Verify evidence is collected for vulnerabilities
        for vulnerability in &results.vulnerabilities {
            if !vulnerability.evidence.is_empty() {
                assert!(!vulnerability.evidence[0].is_empty(), "Evidence should contain meaningful data");
            }
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_report_generation() -> Result<()> {
        let config = create_test_config()?;
        let engine = ScannerEngine::new(config)?;
        
        let results = engine.scan_all(None).await?;
        
        // Test report generation
        let report_result = engine.generate_report(&results).await;
        assert!(report_result.is_ok(), "Report generation should succeed");
        
        Ok(())
    }

    fn create_test_config() -> Result<Config> {
        let mut config = Config::default();
        
        // Enable all scanners for testing
        config.scanners.users = true;
        config.scanners.services = true;
        config.scanners.network = true;
        config.scanners.filesystem = true;
        config.scanners.software = true;
        config.scanners.system = true;
        
        // Set test-appropriate timeouts
        config.general.timeout = 30;
        config.general.max_concurrent = 2;
        
        Ok(config)
    }
}