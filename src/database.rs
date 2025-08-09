use anyhow::Result;
use rusqlite::{Connection, params};
use serde_json;
use std::path::Path;
use tracing::{debug, info};

use crate::scanners::{ScanResults, Vulnerability};

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }
    
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }
    
    fn initialize_schema(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_results (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_duration REAL NOT NULL,
                system_info TEXT NOT NULL,
                total_vulnerabilities INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                info_count INTEGER NOT NULL
            )",
            [],
        )?;
        
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                level TEXT NOT NULL,
                category TEXT NOT NULL,
                evidence TEXT NOT NULL,
                remediation TEXT NOT NULL,
                auto_fixable INTEGER NOT NULL,
                cve_ids TEXT NOT NULL,
                score_impact INTEGER NOT NULL,
                fixed INTEGER DEFAULT 0,
                fix_timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )",
            [],
        )?;
        
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS fix_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                fix_timestamp TEXT NOT NULL,
                fix_method TEXT NOT NULL,
                success INTEGER NOT NULL,
                error_message TEXT,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id),
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )",
            [],
        )?;
        
        info!("Database schema initialized");
        Ok(())
    }
    
    pub fn store_scan_results(&self, results: &ScanResults) -> Result<()> {
        debug!("Storing scan results with ID: {}", results.scan_id);
        
        // Count vulnerabilities by level
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;
        
        for vuln in &results.vulnerabilities {
            match vuln.level {
                crate::scanners::VulnerabilityLevel::Critical => critical_count += 1,
                crate::scanners::VulnerabilityLevel::High => high_count += 1,
                crate::scanners::VulnerabilityLevel::Medium => medium_count += 1,
                crate::scanners::VulnerabilityLevel::Low => low_count += 1,
                crate::scanners::VulnerabilityLevel::Info => info_count += 1,
            }
        }
        
        // Store scan summary
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_results 
             (id, timestamp, target, scan_duration, system_info, total_vulnerabilities,
              critical_count, high_count, medium_count, low_count, info_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                results.scan_id,
                results.timestamp.to_rfc3339(),
                results.target,
                results.scan_duration,
                serde_json::to_string(&results.system_info)?,
                results.vulnerabilities.len(),
                critical_count,
                high_count,
                medium_count,
                low_count,
                info_count
            ],
        )?;
        
        // Store individual vulnerabilities
        for vulnerability in &results.vulnerabilities {
            self.store_vulnerability(&results.scan_id, vulnerability)?;
        }
        
        info!("Stored {} vulnerabilities for scan {}", results.vulnerabilities.len(), results.scan_id);
        Ok(())
    }
    
    fn store_vulnerability(&self, scan_id: &str, vulnerability: &Vulnerability) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO vulnerabilities 
             (id, scan_id, title, description, level, category, evidence, remediation,
              auto_fixable, cve_ids, score_impact)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                vulnerability.id,
                scan_id,
                vulnerability.title,
                vulnerability.description,
                vulnerability.level.to_string(),
                vulnerability.category.to_string(),
                serde_json::to_string(&vulnerability.evidence)?,
                vulnerability.remediation,
                if vulnerability.auto_fixable { 1 } else { 0 },
                serde_json::to_string(&vulnerability.cve_ids)?,
                vulnerability.score_impact
            ],
        )?;
        Ok(())
    }
    
    pub fn get_latest_scan_results(&self) -> Result<Option<ScanResults>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, target, scan_duration, system_info 
             FROM scan_results 
             ORDER BY timestamp DESC 
             LIMIT 1"
        )?;
        
        let mut rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, f64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        
        if let Some(row) = rows.next() {
            let (scan_id, timestamp_str, target, scan_duration, system_info_str) = row?;
            
            let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)?
                .with_timezone(&chrono::Utc);
            let system_info = serde_json::from_str(&system_info_str)?;
            
            let vulnerabilities = self.get_vulnerabilities_for_scan(&scan_id)?;
            
            Ok(Some(ScanResults {
                scan_id,
                timestamp,
                target,
                vulnerabilities,
                system_info,
                scan_duration,
            }))
        } else {
            Ok(None)
        }
    }
    
    fn get_vulnerabilities_for_scan(&self, scan_id: &str) -> Result<Vec<Vulnerability>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, description, level, category, evidence, remediation,
                    auto_fixable, cve_ids, score_impact
             FROM vulnerabilities 
             WHERE scan_id = ?1
             ORDER BY 
                CASE level
                    WHEN 'CRITICAL' THEN 0
                    WHEN 'HIGH' THEN 1
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 3
                    WHEN 'INFO' THEN 4
                END"
        )?;
        
        let vulnerability_iter = stmt.query_map([scan_id], |row| {
            let level_str: String = row.get(3)?;
            let category_str: String = row.get(4)?;
            let evidence_str: String = row.get(5)?;
            let cve_ids_str: String = row.get(8)?;
            
            let level = match level_str.as_str() {
                "CRITICAL" => crate::scanners::VulnerabilityLevel::Critical,
                "HIGH" => crate::scanners::VulnerabilityLevel::High,
                "MEDIUM" => crate::scanners::VulnerabilityLevel::Medium,
                "LOW" => crate::scanners::VulnerabilityLevel::Low,
                _ => crate::scanners::VulnerabilityLevel::Info,
            };
            
            let category = match category_str.as_str() {
                "User Management" => crate::scanners::VulnerabilityCategory::UserManagement,
                "Service Configuration" => crate::scanners::VulnerabilityCategory::ServiceConfiguration,
                "Network Security" => crate::scanners::VulnerabilityCategory::NetworkSecurity,
                "File System Security" => crate::scanners::VulnerabilityCategory::FileSystemSecurity,
                "Software Vulnerability" => crate::scanners::VulnerabilityCategory::SoftwareVulnerability,
                "System Configuration" => crate::scanners::VulnerabilityCategory::SystemConfiguration,
                "Access Control" => crate::scanners::VulnerabilityCategory::AccessControl,
                "Encryption" => crate::scanners::VulnerabilityCategory::Encryption,
                "Logging" => crate::scanners::VulnerabilityCategory::Logging,
                _ => crate::scanners::VulnerabilityCategory::Malware,
            };
            
            Ok(Vulnerability {
                id: row.get(0)?,
                title: row.get(1)?,
                description: row.get(2)?,
                level,
                category,
                evidence: serde_json::from_str(&evidence_str).unwrap_or_default(),
                remediation: row.get(6)?,
                auto_fixable: row.get::<_, i32>(7)? != 0,
                cve_ids: serde_json::from_str(&cve_ids_str).unwrap_or_default(),
                score_impact: row.get(9)?,
            })
        })?;
        
        vulnerability_iter.collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to load vulnerabilities: {}", e))
    }
    
    pub fn mark_vulnerability_fixed(&self, vulnerability_id: &str, fix_method: &str) -> Result<()> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        
        // Update vulnerability as fixed
        self.conn.execute(
            "UPDATE vulnerabilities SET fixed = 1, fix_timestamp = ?1 WHERE id = ?2",
            params![timestamp, vulnerability_id],
        )?;
        
        // Record fix in history
        self.conn.execute(
            "INSERT INTO fix_history (vulnerability_id, scan_id, fix_timestamp, fix_method, success)
             SELECT ?1, scan_id, ?2, ?3, 1 FROM vulnerabilities WHERE id = ?1",
            params![vulnerability_id, timestamp, fix_method],
        )?;
        
        debug!("Marked vulnerability {} as fixed", vulnerability_id);
        Ok(())
    }
    
    pub fn record_fix_failure(&self, vulnerability_id: &str, fix_method: &str, error: &str) -> Result<()> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        
        self.conn.execute(
            "INSERT INTO fix_history (vulnerability_id, scan_id, fix_timestamp, fix_method, success, error_message)
             SELECT ?1, scan_id, ?2, ?3, 0, ?4 FROM vulnerabilities WHERE id = ?1",
            params![vulnerability_id, timestamp, fix_method, error],
        )?;
        
        debug!("Recorded fix failure for vulnerability {}: {}", vulnerability_id, error);
        Ok(())
    }
    
    pub fn get_scan_statistics(&self) -> Result<ScanStatistics> {
        let mut stmt = self.conn.prepare(
            "SELECT COUNT(*) as total_scans,
                    SUM(total_vulnerabilities) as total_vulnerabilities,
                    SUM(critical_count) as total_critical,
                    SUM(high_count) as total_high,
                    SUM(medium_count) as total_medium,
                    SUM(low_count) as total_low,
                    SUM(info_count) as total_info
             FROM scan_results"
        )?;
        
        let stats = stmt.query_row([], |row| {
            Ok(ScanStatistics {
                total_scans: row.get(0)?,
                total_vulnerabilities: row.get(1)?,
                critical_count: row.get(2)?,
                high_count: row.get(3)?,
                medium_count: row.get(4)?,
                low_count: row.get(5)?,
                info_count: row.get(6)?,
            })
        })?;
        
        Ok(stats)
    }
}

#[derive(Debug)]
pub struct ScanStatistics {
    pub total_scans: i32,
    pub total_vulnerabilities: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
}