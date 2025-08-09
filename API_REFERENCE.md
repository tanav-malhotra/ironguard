# 📚 IronGuard API Reference

## 🎯 API Overview

IronGuard provides both programmatic APIs for integration and command-line interfaces for direct use. This reference covers all public interfaces, configuration options, and integration patterns.

## 🦀 Rust API Reference

### **🔍 Core Scanner API**

#### **Scanner Trait**
The foundation for all vulnerability detection modules.

```rust
use ironguard::scanners::{Scanner, Vulnerability, VulnerabilityCategory};
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Scanner: Send + Sync {
    /// Returns the human-readable name of the scanner
    fn name(&self) -> &str;
    
    /// Returns a detailed description of what this scanner detects
    fn description(&self) -> &str;
    
    /// Returns the vulnerability category this scanner focuses on
    fn category(&self) -> VulnerabilityCategory;
    
    /// Performs the security scan and returns found vulnerabilities
    /// 
    /// # Returns
    /// A Result containing a Vec of Vulnerability objects or an error
    async fn scan(&self) -> Result<Vec<Vulnerability>>;
    
    /// Attempts to fix a specific vulnerability
    /// 
    /// # Arguments
    /// * `vulnerability` - The vulnerability to fix
    /// 
    /// # Returns
    /// A Result indicating success or failure of the fix operation
    async fn fix(&self, vulnerability: &Vulnerability) -> Result<()>;
    
    /// Determines if this scanner can automatically fix a vulnerability
    /// 
    /// # Arguments
    /// * `vulnerability` - The vulnerability to check
    /// 
    /// # Returns
    /// true if the vulnerability can be automatically fixed, false otherwise
    fn can_fix(&self, vulnerability: &Vulnerability) -> bool;
}
```

#### **Vulnerability Structure**
Represents a detected security issue with comprehensive metadata.

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Unique identifier for this vulnerability
    pub id: String,
    
    /// Human-readable title describing the vulnerability
    pub title: String,
    
    /// Detailed description of the security issue
    pub description: String,
    
    /// Severity level of the vulnerability
    pub level: VulnerabilityLevel,
    
    /// Category classification for organizational purposes
    pub category: VulnerabilityCategory,
    
    /// Evidence supporting the vulnerability detection
    pub evidence: Vec<String>,
    
    /// Recommended remediation steps
    pub remediation: String,
    
    /// Whether this vulnerability can be automatically fixed
    pub auto_fixable: bool,
    
    /// Related CVE identifiers if applicable
    pub cve_ids: Vec<String>,
    
    /// Estimated impact on competition scoring
    pub score_impact: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VulnerabilityLevel {
    Critical,   // Immediate security risk
    High,       // Significant security concern
    Medium,     // Moderate security issue
    Low,        // Minor security improvement
    Info,       // Informational finding
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VulnerabilityCategory {
    UserManagement,         // User accounts and authentication
    ServiceConfiguration,   // System services and daemons
    NetworkSecurity,        // Network configuration and firewall
    FileSystemSecurity,     // File permissions and directory security
    SoftwareVulnerability,  // Installed software and updates
    SystemConfiguration,    // System settings and policies
    AccessControl,          // Permission and privilege management
    Encryption,             // Cryptographic configuration
    Logging,                // Audit and logging configuration
    Malware,                // Malware detection and removal
    SecurityTools,          // Security tool installation and config
    Competition,            // Competition-specific requirements
    ProhibitedContent,      // Unauthorized files and software
    Forensics,              // Forensic evidence and analysis
}
```

### **🔧 Scanner Engine API**

#### **ScannerEngine**
Central coordination point for all scanning operations.

```rust
use ironguard::{Config, scanners::ScannerEngine};

impl ScannerEngine {
    /// Creates a new scanner engine with the provided configuration
    /// 
    /// # Arguments
    /// * `config` - Configuration object containing scanner settings
    /// 
    /// # Returns
    /// A Result containing the configured ScannerEngine or an error
    pub fn new(config: Config) -> Result<Self>;
    
    /// Executes all configured scanners in parallel
    /// 
    /// # Arguments
    /// * `target` - Optional target specification (IP, hostname, or None for local)
    /// 
    /// # Returns
    /// A Result containing comprehensive scan results
    pub async fn scan_all(&self, target: Option<String>) -> Result<ScanResults>;
    
    /// Attempts to automatically fix all auto-fixable vulnerabilities
    /// 
    /// # Arguments
    /// * `results` - Scan results containing vulnerabilities to fix
    /// 
    /// # Returns
    /// A Result containing fix operation results
    pub async fn auto_fix(&self, results: &ScanResults) -> Result<FixResults>;
    
    /// Generates a comprehensive security report
    /// 
    /// # Arguments
    /// * `results` - Scan results to include in the report
    /// 
    /// # Returns
    /// A Result containing the generated report
    pub async fn generate_report(&self, results: &ScanResults) -> Result<Report>;
    
    /// Registers a new scanner with the engine
    /// 
    /// # Arguments
    /// * `scanner` - Scanner implementation to register
    pub fn register_scanner(&mut self, scanner: ScannerType);
    
    /// Lists all available scanners
    /// 
    /// # Returns
    /// A vector of scanner names and descriptions
    pub fn list_scanners(&self) -> Vec<(String, String)>;
}
```

#### **ScanResults Structure**
Comprehensive results from a security scanning operation.

```rust
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Unique identifier for this scan operation
    pub scan_id: String,
    
    /// Timestamp when the scan was performed
    pub timestamp: DateTime<Utc>,
    
    /// Target system that was scanned
    pub target: String,
    
    /// All vulnerabilities discovered during scanning
    pub vulnerabilities: Vec<Vulnerability>,
    
    /// System information from the scanned target
    pub system_info: SystemInfo,
    
    /// Total time taken for the scan operation (in seconds)
    pub scan_duration: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// System hostname
    pub hostname: String,
    
    /// Operating system type (Windows, Linux, etc.)
    pub os_type: String,
    
    /// Operating system version
    pub os_version: String,
    
    /// System architecture (x86, x64, ARM, etc.)
    pub architecture: String,
    
    /// Kernel version information
    pub kernel_version: String,
    
    /// System uptime in seconds
    pub uptime: u64,
    
    /// Total system memory in bytes
    pub memory_total: u64,
    
    /// Number of CPU cores
    pub cpu_count: usize,
}
```

### **⚙️ Configuration API**

#### **Configuration Structure**
Hierarchical configuration system for all IronGuard components.

```rust
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// General system-wide settings
    pub general: GeneralConfig,
    
    /// Scanner-specific configuration
    pub scanners: ScannersConfig,
    
    /// Auto-fix behavior settings
    pub fixes: FixesConfig,
    
    /// Reporting and output configuration
    pub reporting: ReportingConfig,
    
    /// Competition-specific settings
    pub competition: CompetitionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Maximum time to spend scanning (in seconds)
    pub timeout: u64,
    
    /// Maximum number of concurrent scan operations
    pub max_concurrent: usize,
    
    /// Enable debug logging and verbose output
    pub debug: bool,
    
    /// Directory for storing backup files
    pub backup_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannersConfig {
    /// Enable user account scanning
    pub users: bool,
    
    /// Enable service configuration scanning
    pub services: bool,
    
    /// Enable network security scanning
    pub network: bool,
    
    /// Enable file system scanning
    pub filesystem: bool,
    
    /// Enable software vulnerability scanning
    pub software: bool,
    
    /// Enable system configuration scanning
    pub system: bool,
    
    /// Custom scanner configurations
    pub custom: HashMap<String, serde_json::Value>,
}
```

#### **Configuration Management**
```rust
impl Config {
    /// Loads configuration from a file path
    /// 
    /// # Arguments
    /// * `path` - Path to the configuration file
    /// 
    /// # Returns
    /// A Result containing the loaded configuration or an error
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self>;
    
    /// Creates a default configuration
    /// 
    /// # Returns
    /// A configuration with sensible defaults
    pub fn default() -> Self;
    
    /// Validates the configuration for correctness
    /// 
    /// # Returns
    /// A Result indicating validation success or specific errors
    pub fn validate(&self) -> Result<()>;
    
    /// Saves the configuration to a file
    /// 
    /// # Arguments
    /// * `path` - Path where the configuration should be saved
    /// 
    /// # Returns
    /// A Result indicating save success or failure
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()>;
}
```

## 🖥️ Command-Line Interface (CLI) API

### **📋 Core Commands**

#### **Scanning Commands**
```bash
# Basic security scan
ironguard scan

# Scan with automatic fixes
ironguard scan --auto-fix

# Parallel scanning for speed
ironguard scan --parallel

# Interactive TUI mode
ironguard scan --interactive

# Scan specific target
ironguard scan --target 192.168.1.100

# Scan with custom configuration
ironguard scan --config custom.toml

# Dry run (no actual fixes)
ironguard scan --dry-run

# Verbose output for debugging
ironguard scan --verbose
```

#### **Fix Commands**
```bash
# Fix specific vulnerability by ID
ironguard fix VULN_001

# Fix all auto-fixable vulnerabilities
ironguard fix --all

# Fix vulnerabilities by category
ironguard fix --category users,services

# Fix with backup creation
ironguard fix --backup

# Interactive fix mode
ironguard fix --interactive

# Fix with confirmation prompts
ironguard fix --confirm
```

#### **Report Commands**
```bash
# Generate JSON report
ironguard report --format json

# Generate HTML report
ironguard report --format html --output report.html

# Generate PDF report
ironguard report --format pdf --output report.pdf

# Generate terminal report
ironguard report --format terminal

# Custom report template
ironguard report --template custom_template.html

# Include system information
ironguard report --include-system-info

# Report with scoring analysis
ironguard report --include-scoring
```

#### **Configuration Commands**
```bash
# Initialize default configuration
ironguard config init

# Show current configuration
ironguard config show

# Validate configuration file
ironguard config validate

# Edit configuration interactively
ironguard config edit

# Set specific configuration value
ironguard config set general.timeout 600

# Get specific configuration value
ironguard config get scanners.users

# Reset to defaults
ironguard config reset
```

### **🎯 Competition-Specific Commands**

#### **Competition Mode**
```bash
# Enable competition mode
ironguard competition enable

# Quick competition scan
ironguard competition quick-scan

# Full competition assessment
ironguard competition full-scan

# Competition report generation
ironguard competition report --format competition

# Set competition parameters
ironguard competition set-params --round 1 --team "TeamName"

# Competition time tracking
ironguard competition timer start
```

#### **Script Management**
```bash
# List available hardening scripts
ironguard scripts list

# Run specific script
ironguard scripts run password_policy

# Run all scripts in parallel
ironguard scripts run-all --parallel

# Custom script execution
ironguard scripts run custom_script.sh

# Script with parameters
ironguard scripts run firewall_config --port 8080

# Script dry run
ironguard scripts run network_hardening --dry-run
```

### **🔧 Advanced Commands**

#### **System Integration**
```bash
# System health check
ironguard system health

# System compatibility check
ironguard system compatibility

# Update IronGuard
ironguard update

# Check for updates
ironguard update check

# Install security tools
ironguard tools install

# List installed tools
ironguard tools list

# Tool status check
ironguard tools status
```

#### **Diagnostic Commands**
```bash
# Collect diagnostic information
ironguard diagnostics collect

# Run system diagnostics
ironguard diagnostics system

# Network diagnostics
ironguard diagnostics network

# Performance diagnostics
ironguard diagnostics performance

# Generate support bundle
ironguard diagnostics support-bundle
```

## 🌐 REST API (Future)

### **🔌 HTTP API Endpoints**

#### **Authentication**
```http
POST /api/v1/auth/login
Content-Type: application/json

{
    "username": "admin",
    "password": "secure_password",
    "mfa_token": "123456"
}
```

#### **Scanning Operations**
```http
# Start a new scan
POST /api/v1/scans
Content-Type: application/json

{
    "target": "local",
    "scanners": ["users", "services", "network"],
    "auto_fix": true,
    "parallel": true
}

# Get scan results
GET /api/v1/scans/{scan_id}

# List all scans
GET /api/v1/scans?limit=10&offset=0

# Get scan status
GET /api/v1/scans/{scan_id}/status
```

#### **Vulnerability Management**
```http
# Get vulnerability details
GET /api/v1/vulnerabilities/{vuln_id}

# Fix vulnerability
POST /api/v1/vulnerabilities/{vuln_id}/fix

# List vulnerabilities
GET /api/v1/vulnerabilities?category=users&level=high
```

## 📊 Configuration Schema

### **🔧 TOML Configuration Format**

#### **Complete Configuration Example**
```toml
# IronGuard Configuration File
# This file controls all aspects of IronGuard operation

[general]
# General system settings
timeout = 300                    # Scan timeout in seconds
max_concurrent = 4               # Maximum parallel operations
debug = false                    # Enable debug logging
backup_dir = "./backups"         # Backup directory for fixes

[scanners]
# Enable/disable specific scanners
users = true                     # User account scanning
services = true                  # Service configuration scanning
network = true                   # Network security scanning
filesystem = true                # File system scanning
software = true                  # Software vulnerability scanning
system = true                    # System configuration scanning

[scanners.custom]
# Custom scanner configurations
custom_scanner_1 = { enabled = true, severity = "high" }

[fixes]
# Auto-fix behavior configuration
auto_fix_enabled = true          # Enable automatic fixing
backup_before_fix = true         # Create backups before fixes
parallel_fixes = false           # Run fixes in parallel
confirmation_required = false    # Require user confirmation

# Categories that can be auto-fixed
allowed_categories = [
    "users",
    "services", 
    "software"
]

[reporting]
# Report generation settings
default_format = "json"          # Default report format
include_system_info = true       # Include system information
include_evidence = true          # Include evidence in reports
include_screenshots = false      # Include screenshots (if available)
output_dir = "./reports"         # Report output directory
auto_open = false               # Automatically open reports

[competition]
# Competition-specific settings
allowed_users = []               # List of allowed users
critical_files = []              # List of critical files to monitor

# Required/forbidden services
[[competition.custom_services]]
name = "ssh"
should_be_running = true

[[competition.custom_services]]
name = "telnet"
should_be_running = false

# Custom ports
custom_ssh_port = 22

# Scoring weights
[competition.scoring]
critical = 50                    # Points for critical vulnerabilities
high = 30                       # Points for high vulnerabilities
medium = 20                     # Points for medium vulnerabilities
low = 10                        # Points for low vulnerabilities
```

### **🔍 Environment Variable Override**

```bash
# Override configuration via environment variables
export IRONGUARD_GENERAL_TIMEOUT=600
export IRONGUARD_SCANNERS_USERS=false
export IRONGUARD_FIXES_AUTO_FIX_ENABLED=true
export IRONGUARD_DEBUG=true

# Run with environment overrides
ironguard scan
```

## 🧪 Testing API

### **🔬 Test Framework Integration**

#### **Unit Testing**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ironguard::testing::{MockConfig, TestEnvironment};

    #[tokio::test]
    async fn test_vulnerability_scanner() {
        let config = MockConfig::default();
        let scanner = UserScanner::new(config).unwrap();
        
        let results = scanner.scan().await.unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_config_validation() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }
}
```

#### **Integration Testing**
```rust
#[tokio::test]
async fn test_full_scan_workflow() {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let config = create_test_config(&temp_dir).unwrap();
    let engine = ScannerEngine::new(config).unwrap();
    
    let results = engine.scan_all(None).await.unwrap();
    assert!(results.vulnerabilities.len() >= 0);
    
    let fix_results = engine.auto_fix(&results).await.unwrap();
    assert!(fix_results.fixes_applied >= 0);
}
```

## 📈 Performance Monitoring API

### **⚡ Metrics Collection**

#### **Performance Metrics**
```rust
use ironguard::metrics::{MetricsCollector, ScanMetrics};

// Collect performance metrics during scanning
let metrics = MetricsCollector::new();
let scan_metrics = metrics.collect_scan_metrics().await;

println!("Scan duration: {}ms", scan_metrics.duration_ms);
println!("Memory usage: {}MB", scan_metrics.memory_usage_mb);
println!("Vulnerabilities found: {}", scan_metrics.vulnerabilities_found);
```

---

## 🔗 Integration Examples

### **🐍 Python Integration** (Future)
```python
import ironguard

# Python wrapper for IronGuard functionality
scanner = ironguard.Scanner()
results = scanner.scan_all()

for vuln in results.vulnerabilities:
    print(f"Found {vuln.level}: {vuln.title}")
    if vuln.auto_fixable:
        scanner.fix(vuln)
```

### **🌐 Web Dashboard Integration** (Future)
```javascript
// JavaScript API client
const ironguard = new IronGuardClient('http://localhost:8080');

// Start scan
const scanId = await ironguard.startScan({
    target: 'local',
    scanners: ['users', 'services', 'network']
});

// Monitor progress
const results = await ironguard.getScanResults(scanId);
console.log(`Found ${results.vulnerabilities.length} vulnerabilities`);
```

This comprehensive API reference provides all the interfaces needed to integrate IronGuard into educational environments, competition scenarios, and professional training programs. 🚀🛡️