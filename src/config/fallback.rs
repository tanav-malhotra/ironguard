// IronGuard Ultimate - Configuration Fallback System
// Interactive prompts when configuration file is missing or invalid

use anyhow::Result;
use std::io::{self, Write};
use tracing::{info, warn};
use crate::config::Config;

pub struct InteractiveConfig {
    config: Config,
}

impl InteractiveConfig {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// Create configuration through interactive prompts
    pub async fn create_interactive_config() -> Result<Config> {
        info!("🔧 Configuration file not found or invalid.");
        info!("📋 Starting interactive configuration setup...");
        println!();
        println!("╔═══════════════════════════════════════════════════════════════╗");
        println!("║          🛡️  IronGuard Interactive Configuration           ║");
        println!("║                                                             ║");
        println!("║  No configuration file found. Let's set up IronGuard       ║");
        println!("║  for your competition environment!                         ║");
        println!("╚═══════════════════════════════════════════════════════════════╝");
        println!();

        let mut config = Config::default();

        // Basic configuration
        config.general.competition_mode = prompt_bool(
            "🏆 Are you setting up for a CyberPatriot competition?",
            true,
        )?;

        if config.general.competition_mode {
            warn!("⚠️  Competition mode enables aggressive scanning and auto-fixes!");
            warn!("   Only use on competition VMs, never on personal systems!");
        }

        config.general.timeout = prompt_number(
            "⏱️  Scan timeout in seconds (recommended: 300)",
            300,
            60,
            1800,
        )?;

        config.general.max_concurrent = prompt_number(
            "🔄 Maximum concurrent scans (recommended: 4-8)",
            4,
            1,
            16,
        )?;

        config.general.debug = prompt_bool(
            "🐛 Enable debug logging? (useful for troubleshooting)",
            false,
        )?;

        // Scanner configuration
        println!("\n📊 Scanner Configuration:");
        println!("   Configure which security scanners to enable...");

        config.scanners.users = prompt_bool(
            "👥 Enable User Management scanner? (password policies, accounts)",
            true,
        )?;

        config.scanners.services = prompt_bool(
            "⚙️  Enable Service scanner? (dangerous services, configurations)",
            true,
        )?;

        config.scanners.network = prompt_bool(
            "🌐 Enable Network scanner? (open ports, firewall)",
            true,
        )?;

        config.scanners.filesystem = prompt_bool(
            "📁 Enable Filesystem scanner? (permissions, dangerous files)",
            true,
        )?;

        config.scanners.software = prompt_bool(
            "📦 Enable Software scanner? (unauthorized programs)",
            true,
        )?;

        config.scanners.system = prompt_bool(
            "🖥️  Enable System scanner? (policies, configuration)",
            true,
        )?;

        if cfg!(windows) {
            config.scanners.windows_server = prompt_bool(
                "🖥️  Enable Windows Server scanner? (IIS, AD, DNS, DHCP)",
                true,
            )?;
        }

        // Auto-fix configuration
        println!("\n🔧 Automatic Fix Configuration:");
        println!("   Configure automatic vulnerability fixing...");

        config.fixes.auto_fix_enabled = prompt_bool(
            "⚠️  Enable automatic fixes? (DANGEROUS - only for competition VMs!)",
            false,
        )?;

        if config.fixes.auto_fix_enabled {
            warn!("🚨 AUTO-FIX ENABLED! This will automatically modify your system!");
            warn!("   Make sure you're on a competition VM, not a personal system!");
            
            config.fixes.require_confirmation = prompt_bool(
                "❓ Require confirmation before each fix? (recommended: yes)",
                true,
            )?;

            config.fixes.create_restore_point = prompt_bool(
                "💾 Create system restore point before fixes? (Windows only)",
                true,
            )?;
        }

        // Competition-specific configuration
        if config.general.competition_mode {
            println!("\n🏆 Competition-Specific Configuration:");
            println!("   Configure settings for your specific competition scenario...");

            config.competition.name = prompt_string(
                "📋 Competition name (e.g., 'CyberPatriot Nationals 2024')",
                "CyberPatriot Competition",
            )?;

            config.competition.round = prompt_string(
                "🎯 Competition round (e.g., 'Round 1', 'State', 'Nationals')",
                "Practice",
            )?;

            config.competition.time_limit = prompt_number(
                "⏰ Competition time limit in minutes (typical: 240 = 4 hours)",
                240,
                60,
                480,
            )?;

            // SSH configuration
            let custom_ssh = prompt_bool(
                "🔧 Does the competition use a custom SSH port? (check README)",
                false,
            )?;

            if custom_ssh {
                let ssh_port = prompt_number(
                    "🔌 Custom SSH port number (check competition README)",
                    2222,
                    1024,
                    65535,
                )?;
                config.competition.custom_ssh_port = Some(ssh_port as u16);
            }

            // User configuration
            println!("\n👥 User Account Configuration:");
            println!("   Configure allowed users based on competition README...");

            let mut users = Vec::new();
            loop {
                let user = prompt_string_optional(
                    "👤 Add allowed user (leave empty when done, check README for list)",
                )?;
                
                if user.is_empty() {
                    break;
                }
                users.push(user);
            }

            if !users.is_empty() {
                config.competition.allowed_users = users;
            }
        }

        // Network configuration
        println!("\n🌐 Network Configuration:");
        println!("   Configure network security settings...");

        let custom_ports = prompt_bool(
            "🔌 Configure custom required/forbidden ports? (check README)",
            false,
        )?;

        if custom_ports {
            println!("🔓 Required open ports (services that must be accessible):");
            let mut required_ports = Vec::new();
            loop {
                let port_input = prompt_string_optional(
                    "   Port number (leave empty when done)",
                )?;
                
                if port_input.is_empty() {
                    break;
                }
                
                if let Ok(port) = port_input.parse::<u16>() {
                    required_ports.push(port);
                } else {
                    println!("❌ Invalid port number. Please enter a number between 1-65535.");
                }
            }
            config.competition.network.required_open_ports = required_ports;

            println!("🔒 Forbidden ports (ports that should be closed):");
            let mut forbidden_ports = Vec::new();
            loop {
                let port_input = prompt_string_optional(
                    "   Port number (leave empty when done)",
                )?;
                
                if port_input.is_empty() {
                    break;
                }
                
                if let Ok(port) = port_input.parse::<u16>() {
                    forbidden_ports.push(port);
                } else {
                    println!("❌ Invalid port number. Please enter a number between 1-65535.");
                }
            }
            config.competition.network.required_closed_ports = forbidden_ports;
        }

        // Finalization
        println!("\n✅ Configuration Complete!");
        println!("📁 Configuration will be saved to: ~/.ironguard/ironguard.toml");
        println!("🔧 You can edit this file later or run configuration again.");
        
        let save_config = prompt_bool(
            "💾 Save this configuration for future use?",
            true,
        )?;

        if save_config {
            if let Err(e) = config.save_to_default_location().await {
                warn!("⚠️  Failed to save configuration: {}", e);
                warn!("   IronGuard will use these settings for this session only.");
            } else {
                info!("✅ Configuration saved successfully!");
            }
        }

        println!("\n🚀 Ready to start scanning!");
        println!("💡 Tip: Run 'ironguard scan --auto-fix --parallel' to begin!");

        Ok(config)
    }
}

// Helper functions for interactive prompts

fn prompt_bool(question: &str, default: bool) -> Result<bool> {
    let default_str = if default { "Y/n" } else { "y/N" };
    
    loop {
        print!("{} [{}]: ", question, default_str);
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        
        if input.is_empty() {
            return Ok(default);
        }
        
        match input.as_str() {
            "y" | "yes" | "true" | "1" => return Ok(true),
            "n" | "no" | "false" | "0" => return Ok(false),
            _ => println!("❌ Please enter 'y' for yes or 'n' for no."),
        }
    }
}

fn prompt_number<T>(question: &str, default: T, min: T, max: T) -> Result<T>
where
    T: std::str::FromStr + std::fmt::Display + PartialOrd + Copy,
    T::Err: std::fmt::Debug,
{
    loop {
        print!("{} (default: {}, range: {}-{}): ", question, default, min, max);
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input.is_empty() {
            return Ok(default);
        }
        
        match input.parse::<T>() {
            Ok(value) => {
                if value >= min && value <= max {
                    return Ok(value);
                } else {
                    println!("❌ Value must be between {} and {}.", min, max);
                }
            }
            Err(_) => println!("❌ Please enter a valid number."),
        }
    }
}

fn prompt_string(question: &str, default: &str) -> Result<String> {
    print!("{} (default: '{}'): ", question, default);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input.to_string())
    }
}

fn prompt_string_optional(question: &str) -> Result<String> {
    print!("{}: ", question);
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_interactive_config_creation() {
        // Test that interactive config can be created
        // (This test mainly ensures the function signature is correct)
        let config = Config::default();
        assert!(!config.general.competition_mode); // Default should be false for safety
    }
}