use anyhow::Result;
use std::collections::HashMap;
use std::process::Command;

/// Get detailed system information
pub fn get_system_info() -> Result<HashMap<String, String>> {
    let mut info = HashMap::new();
    
    #[cfg(windows)]
    {
        info.extend(get_windows_system_info()?);
    }
    
    #[cfg(unix)]
    {
        info.extend(get_unix_system_info()?);
    }
    
    Ok(info)
}

#[cfg(windows)]
fn get_windows_system_info() -> Result<HashMap<String, String>> {
    let mut info = HashMap::new();
    
    // Get Windows version
    if let Ok(output) = Command::new("ver").output() {
        let version = String::from_utf8_lossy(&output.stdout);
        info.insert("os_version".to_string(), version.trim().to_string());
    }
    
    // Get system info using wmic
    let wmic_queries = vec![
        ("computer_name", "computersystem", "Name"),
        ("domain", "computersystem", "Domain"),
        ("total_memory", "computersystem", "TotalPhysicalMemory"),
        ("cpu_name", "processor", "Name"),
        ("cpu_cores", "processor", "NumberOfCores"),
        ("manufacturer", "computersystem", "Manufacturer"),
        ("model", "computersystem", "Model"),
    ];
    
    for (key, class, property) in wmic_queries {
        if let Ok(output) = Command::new("wmic")
            .args(&[class, "get", property, "/value"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.starts_with(&format!("{}=", property)) {
                    let value = line.split('=').nth(1).unwrap_or("").trim();
                    if !value.is_empty() {
                        info.insert(key.to_string(), value.to_string());
                        break;
                    }
                }
            }
        }
    }
    
    Ok(info)
}

#[cfg(unix)]
fn get_unix_system_info() -> Result<HashMap<String, String>> {
    let mut info = HashMap::new();
    
    // Get hostname
    if let Ok(output) = Command::new("hostname").output() {
        let hostname = String::from_utf8_lossy(&output.stdout);
        info.insert("hostname".to_string(), hostname.trim().to_string());
    }
    
    // Get OS information
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let clean_value = value.trim_matches('"');
                match key {
                    "NAME" => info.insert("os_name".to_string(), clean_value.to_string()),
                    "VERSION" => info.insert("os_version".to_string(), clean_value.to_string()),
                    "ID" => info.insert("os_id".to_string(), clean_value.to_string()),
                    _ => None,
                };
            }
        }
    }
    
    // Get kernel version
    if let Ok(output) = Command::new("uname").args(&["-r"]).output() {
        let kernel = String::from_utf8_lossy(&output.stdout);
        info.insert("kernel_version".to_string(), kernel.trim().to_string());
    }
    
    // Get CPU information
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        for line in content.lines() {
            if line.starts_with("model name") {
                if let Some(cpu_name) = line.split(':').nth(1) {
                    info.insert("cpu_name".to_string(), cpu_name.trim().to_string());
                    break;
                }
            }
        }
    }
    
    // Get memory information
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(mem_total) = line.split_whitespace().nth(1) {
                    info.insert("total_memory_kb".to_string(), mem_total.to_string());
                    break;
                }
            }
        }
    }
    
    Ok(info)
}

/// Check if a specific Windows feature is enabled
#[cfg(windows)]
pub fn is_windows_feature_enabled(feature_name: &str) -> Result<bool> {
    let output = Command::new("dism")
        .args(&["/online", "/get-featureinfo", &format!("/featurename:{}", feature_name)])
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    Ok(output_str.contains("State : Enabled"))
}

/// Get list of installed Windows updates
#[cfg(windows)]
pub fn get_installed_updates() -> Result<Vec<String>> {
    let output = Command::new("wmic")
        .args(&["qfe", "get", "HotFixID", "/value"])
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut updates = Vec::new();
    
    for line in output_str.lines() {
        if line.starts_with("HotFixID=") {
            if let Some(update_id) = line.split('=').nth(1) {
                let clean_id = update_id.trim();
                if !clean_id.is_empty() {
                    updates.push(clean_id.to_string());
                }
            }
        }
    }
    
    Ok(updates)
}

/// Get system uptime in seconds
pub fn get_uptime_seconds() -> Result<u64> {
    #[cfg(windows)]
    {
        // Use WMI to get uptime on Windows
        let output = Command::new("wmic")
            .args(&["os", "get", "LastBootUpTime", "/value"])
            .output()?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.starts_with("LastBootUpTime=") {
                // Parse WMI datetime format and calculate uptime
                // This is a simplified implementation
                return Ok(86400); // Placeholder: 1 day
            }
        }
        Ok(0)
    }
    
    #[cfg(unix)]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/uptime") {
            if let Some(uptime_str) = content.split_whitespace().next() {
                if let Ok(uptime_f64) = uptime_str.parse::<f64>() {
                    return Ok(uptime_f64 as u64);
                }
            }
        }
        Ok(0)
    }
}