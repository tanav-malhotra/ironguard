// IronGuard Ultimate - Basic Test Suite
// Tests for core functionality and competition scenarios

use ironguard::*;
use std::collections::HashMap;
use tempfile::TempDir;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_scanner_engine_creation() {
    let engine = scanners::ScannerEngine::new();
    assert!(engine.get_scanner_count() >= 0);
}

#[tokio::test]
async fn test_vulnerability_scoring() {
    let vuln = scanners::Vulnerability {
        id: "test-001".to_string(),
        title: "Test Vulnerability".to_string(),
        description: "Test description".to_string(),
        level: scanners::VulnerabilityLevel::High,
        category: "Test".to_string(),
        auto_fixable: true,
        score_impact: 15,
        evidence: Vec::new(),
        fix_commands: Vec::new(),
        references: Vec::new(),
    };
    
    assert_eq!(vuln.level, scanners::VulnerabilityLevel::High);
    assert_eq!(vuln.score_impact, 15);
    assert!(vuln.auto_fixable);
}

#[tokio::test]
async fn test_config_loading() {
    // Test configuration loading with fallback
    let config_result = config::Config::load_with_fallback().await;
    assert!(config_result.is_ok());
    
    let config = config_result.unwrap();
    assert!(config.general.timeout > 0);
    assert!(config.general.max_concurrent > 0);
}

#[tokio::test]
async fn test_backup_creation() {
    let temp_dir = TempDir::new().unwrap();
    let backup_manager = utils::backup::BackupManager::new(temp_dir.path());
    
    // Create a test file
    let test_file = temp_dir.path().join("test.txt");
    std::fs::write(&test_file, "test content").unwrap();
    
    // Test backup creation
    let backup_result = backup_manager.create_backup(&test_file).await;
    assert!(backup_result.is_ok());
}

#[tokio::test]
async fn test_user_scanner_basic() {
    let scanner = scanners::users::UserScanner::new();
    
    // Test scanner creation
    assert_eq!(scanner.get_name(), "UserScanner");
    
    // Test scanning (should not fail even on test system)
    let scan_result = scanner.scan().await;
    assert!(scan_result.is_ok());
}

#[tokio::test]
async fn test_service_scanner_basic() {
    let scanner = scanners::services::ServiceScanner::new();
    
    assert_eq!(scanner.get_name(), "ServiceScanner");
    
    let scan_result = scanner.scan().await;
    assert!(scan_result.is_ok());
}

#[tokio::test]
async fn test_network_scanner_basic() {
    let scanner = scanners::network::NetworkScanner::new();
    
    assert_eq!(scanner.get_name(), "NetworkScanner");
    
    let scan_result = scanner.scan().await;
    assert!(scan_result.is_ok());
}

#[tokio::test]
async fn test_filesystem_scanner_basic() {
    let scanner = scanners::filesystem::FileSystemScanner::new();
    
    assert_eq!(scanner.get_name(), "FileSystemScanner");
    
    let scan_result = scanner.scan().await;
    assert!(scan_result.is_ok());
}

#[tokio::test]
async fn test_software_scanner_basic() {
    let scanner = scanners::software::SoftwareScanner::new();
    
    assert_eq!(scanner.get_name(), "SoftwareScanner");
    
    let scan_result = scanner.scan().await;
    assert!(scan_result.is_ok());
}

#[tokio::test]
async fn test_system_scanner_basic() {
    let scanner = scanners::system::SystemScanner::new();
    
    assert_eq!(scanner.get_name(), "SystemScanner");
    
    let scan_result = scanner.scan().await;
    assert!(scan_result.is_ok());
}

#[tokio::test]
async fn test_database_operations() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = database::Database::new(&db_path).await.unwrap();
    
    // Test storing scan results
    let results = scanners::ScanResults {
        scan_id: "test-001".to_string(),
        timestamp: chrono::Utc::now(),
        vulnerabilities: Vec::new(),
        system_info: HashMap::new(),
        total_score: 0,
        categories: HashMap::new(),
    };
    
    let store_result = db.store_scan_results(&results).await;
    assert!(store_result.is_ok());
    
    // Test retrieving results
    let retrieved = db.get_scan_results("test-001").await;
    assert!(retrieved.is_ok());
}

#[tokio::test]
async fn test_crypto_utilities() {
    let test_data = "Hello, IronGuard!";
    
    // Test hashing
    let hash = utils::crypto::hash_sha256(test_data.as_bytes());
    assert_eq!(hash.len(), 64); // SHA256 hex string length
    
    // Test consistent hashing
    let hash2 = utils::crypto::hash_sha256(test_data.as_bytes());
    assert_eq!(hash, hash2);
}

#[tokio::test]
async fn test_system_info() {
    let sys_info = utils::system::get_system_info().await;
    assert!(sys_info.is_ok());
    
    let info = sys_info.unwrap();
    assert!(!info.os_type.is_empty());
    assert!(!info.hostname.is_empty());
}

#[test]
fn test_privilege_detection() {
    // Test privilege detection (should work on any system)
    let is_elevated = utils::system::is_elevated();
    // Just ensure it returns a boolean without panicking
    assert!(is_elevated == true || is_elevated == false);
}

#[tokio::test]
async fn test_parallel_scanning() {
    let engine = scanners::ScannerEngine::new();
    
    // Register test scanners
    engine.register_scanner("users", Box::new(scanners::users::UserScanner::new()));
    engine.register_scanner("services", Box::new(scanners::services::ServiceScanner::new()));
    
    // Test parallel scanning
    let results = engine.scan_all(None).await;
    assert!(results.is_ok());
    
    let scan_results = results.unwrap();
    assert!(!scan_results.scan_id.is_empty());
}

#[tokio::test]
async fn test_competition_mode() {
    // Test competition mode configuration
    let mut config = config::Config::default();
    config.general.competition_mode = true;
    config.general.timeout = 300;
    config.general.max_concurrent = 8;
    
    assert!(config.general.competition_mode);
    assert_eq!(config.general.timeout, 300);
    assert_eq!(config.general.max_concurrent, 8);
}

#[tokio::test]
async fn test_vulnerability_levels() {
    use scanners::VulnerabilityLevel;
    
    // Test vulnerability level ordering
    assert!(VulnerabilityLevel::Critical > VulnerabilityLevel::High);
    assert!(VulnerabilityLevel::High > VulnerabilityLevel::Medium);
    assert!(VulnerabilityLevel::Medium > VulnerabilityLevel::Low);
    assert!(VulnerabilityLevel::Low > VulnerabilityLevel::Info);
}

#[tokio::test]
async fn test_rollback_functionality() {
    let temp_dir = TempDir::new().unwrap();
    let rollback_manager = utils::backup::RollbackManager::new(temp_dir.path());
    
    // Test rollback preparation
    let prepare_result = rollback_manager.prepare_rollback("test-session").await;
    assert!(prepare_result.is_ok());
}

// Competition scenario simulation tests
#[tokio::test]
async fn test_competition_scenario_windows() {
    // Simulate Windows competition environment
    let engine = scanners::ScannerEngine::new();
    
    // Register Windows-specific scanners
    if cfg!(windows) {
        engine.register_scanner("users", Box::new(scanners::users::UserScanner::new()));
        engine.register_scanner("services", Box::new(scanners::services::ServiceScanner::new()));
        engine.register_scanner("network", Box::new(scanners::network::NetworkScanner::new()));
        
        let results = engine.scan_all(Some("windows".to_string())).await;
        assert!(results.is_ok());
    }
}

#[tokio::test]
async fn test_competition_scenario_linux() {
    // Simulate Linux competition environment
    let engine = scanners::ScannerEngine::new();
    
    // Register Linux-specific scanners
    if cfg!(unix) {
        engine.register_scanner("users", Box::new(scanners::users::UserScanner::new()));
        engine.register_scanner("services", Box::new(scanners::services::ServiceScanner::new()));
        engine.register_scanner("network", Box::new(scanners::network::NetworkScanner::new()));
        
        let results = engine.scan_all(Some("linux".to_string())).await;
        assert!(results.is_ok());
    }
}

#[tokio::test]
async fn test_performance_metrics() {
    let start_time = std::time::Instant::now();
    
    // Run a basic scan and measure performance
    let scanner = scanners::users::UserScanner::new();
    let _ = scanner.scan().await;
    
    let duration = start_time.elapsed();
    
    // Ensure scan completes within reasonable time (30 seconds max)
    assert!(duration.as_secs() < 30, "Scan took too long: {:?}", duration);
}

// Integration tests for complete workflows
#[tokio::test]
async fn test_complete_scan_workflow() {
    // Test the complete scan workflow as used in competition
    let engine = scanners::ScannerEngine::new();
    
    // Register all scanners
    engine.register_scanner("users", Box::new(scanners::users::UserScanner::new()));
    engine.register_scanner("services", Box::new(scanners::services::ServiceScanner::new()));
    engine.register_scanner("network", Box::new(scanners::network::NetworkScanner::new()));
    
    // Run scan
    let scan_result = engine.scan_all(None).await;
    assert!(scan_result.is_ok());
    
    let results = scan_result.unwrap();
    
    // Verify results structure
    assert!(!results.scan_id.is_empty());
    assert!(results.total_score >= 0);
    assert!(!results.categories.is_empty());
}

#[tokio::test]
async fn test_error_handling() {
    // Test error handling for various failure scenarios
    
    // Test invalid configuration
    let invalid_config_result = config::Config::load_from_file("nonexistent.toml").await;
    assert!(invalid_config_result.is_err());
    
    // Test invalid database path
    let invalid_db_result = database::Database::new("/invalid/path/test.db").await;
    assert!(invalid_db_result.is_err());
}

#[tokio::test]
async fn test_concurrent_operations() {
    // Test multiple concurrent scanning operations
    let engine = scanners::ScannerEngine::new();
    engine.register_scanner("users", Box::new(scanners::users::UserScanner::new()));
    
    // Run multiple scans concurrently
    let mut handles = Vec::new();
    
    for i in 0..3 {
        let engine_clone = engine.clone();
        let handle = tokio::spawn(async move {
            engine_clone.scan_all(Some(format!("test-{}", i))).await
        });
        handles.push(handle);
    }
    
    // Wait for all scans to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}