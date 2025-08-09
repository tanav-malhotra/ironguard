pub mod cli;
pub mod config;
pub mod scanners;
pub mod tui;
pub mod utils;
pub mod fixes;
pub mod database;

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct IronGuard {
    config: config::Config,
}

impl IronGuard {
    pub fn new(config: config::Config) -> Self {
        Self { config }
    }
    
    pub async fn run_full_scan(&self) -> Result<scanners::ScanResults> {
        let engine = scanners::ScannerEngine::new(self.config.clone())?;
        engine.scan_all(None).await
    }
}

// Re-export commonly used types
pub use config::Config;
pub use scanners::{ScanResults, Vulnerability, VulnerabilityLevel};