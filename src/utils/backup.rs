use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use chrono::Utc;
use tracing::{debug, info};

pub struct BackupManager {
    backup_dir: PathBuf,
}

impl BackupManager {
    pub fn new<P: AsRef<Path>>(backup_dir: P) -> Result<Self> {
        let backup_dir = backup_dir.as_ref().to_path_buf();
        fs::create_dir_all(&backup_dir)?;
        
        Ok(Self { backup_dir })
    }
    
    /// Create a backup of a file before modifying it
    pub fn backup_file<P: AsRef<Path>>(&self, file_path: P) -> Result<PathBuf> {
        let file_path = file_path.as_ref();
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
            
        let backup_filename = format!("{}_{}.backup", filename, timestamp);
        let backup_path = self.backup_dir.join(backup_filename);
        
        fs::copy(file_path, &backup_path)?;
        info!("Created backup: {} -> {}", file_path.display(), backup_path.display());
        
        Ok(backup_path)
    }
    
    /// Restore a file from backup
    pub fn restore_file<P: AsRef<Path>>(&self, backup_path: P, target_path: P) -> Result<()> {
        let backup_path = backup_path.as_ref();
        let target_path = target_path.as_ref();
        
        fs::copy(backup_path, target_path)?;
        info!("Restored file: {} -> {}", backup_path.display(), target_path.display());
        
        Ok(())
    }
    
    /// List all backup files
    pub fn list_backups(&self) -> Result<Vec<PathBuf>> {
        let mut backups = Vec::new();
        
        for entry in fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("backup") {
                backups.push(path);
            }
        }
        
        backups.sort();
        Ok(backups)
    }
    
    /// Clean old backup files (keep only recent ones)
    pub fn cleanup_old_backups(&self, keep_count: usize) -> Result<()> {
        let mut backups = self.list_backups()?;
        backups.sort_by(|a, b| {
            fs::metadata(b)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                .cmp(&fs::metadata(a)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH))
        });
        
        if backups.len() > keep_count {
            for backup_to_remove in &backups[keep_count..] {
                fs::remove_file(backup_to_remove)?;
                debug!("Removed old backup: {}", backup_to_remove.display());
            }
        }
        
        Ok(())
    }
}