use anyhow::Result;
use clap::Parser;
use ironguard::{
    cli::{Cli, Commands},
    config::Config,
    scanners::ScannerEngine,
    tui::TuiApp,
    utils::logger,
};
use std::process;
use tracing::{info};
use chrono;

// Embedded GPL v3 License Text
const GPL_V3_LICENSE: &str = include_str!("../LICENSE");

// Comprehensive Legal Disclaimer
const LEGAL_DISCLAIMER: &str = r#"
═══════════════════════════════════════════════════════════════════════════════
🛡️  IRONGUARD ULTIMATE - COMPREHENSIVE LEGAL DISCLAIMER & LIABILITY NOTICE
═══════════════════════════════════════════════════════════════════════════════

⚖️  LEGAL DISCLAIMER - READ CAREFULLY BEFORE USE

This software (IronGuard Ultimate) is provided under the GNU General Public 
License v3.0 and comes with ABSOLUTELY NO WARRANTY of any kind. By using this 
software, you acknowledge and agree to the following terms:

📜 1. NO WARRANTY OR GUARANTEE
────────────────────────────────────────────────────────────────────────────
- This software is provided "AS IS" without warranty of any kind
- No guarantee of fitness for any particular purpose
- No warranty regarding accuracy, reliability, or safety
- No assurance that the software will meet your requirements
- Results may vary significantly between different systems and environments

🚫 2. COMPETITION & EDUCATIONAL USE LIABILITY
────────────────────────────────────────────────────────────────────────────
- You are SOLELY RESPONSIBLE for compliance with competition rules
- The author is NOT LIABLE if you are banned, disqualified, or penalized
- Use in CyberPatriot or other competitions is AT YOUR OWN RISK
- Educational use must comply with institutional policies
- You must verify all actions are permitted before execution

💥 3. SYSTEM DAMAGE & DATA LOSS LIABILITY
────────────────────────────────────────────────────────────────────────────
- This software modifies system configurations and security settings
- May cause system instability, crashes, or complete system failure
- Could result in permanent data loss or corruption
- May render systems unbootable or unusable
- The author is NOT RESPONSIBLE for any system damage
- You assume ALL RISK of data loss or system failure

🔧 4. NO TECHNICAL SUPPORT OBLIGATION
────────────────────────────────────────────────────────────────────────────
- The author has NO OBLIGATION to provide support, fixes, or assistance
- You are responsible for your own troubleshooting and problem resolution
- The author will NOT help fix systems damaged by this software
- No guarantee of response to bug reports or feature requests
- Community support is provided on a voluntary basis only

⚡ 5. DANGEROUS OPERATIONS WARNING
────────────────────────────────────────────────────────────────────────────
- This software performs potentially dangerous system operations
- Requires administrative/root privileges to function
- Modifies critical system files, services, and configurations
- Could permanently alter system behavior
- May conflict with existing security software or policies

🏢 6. ORGANIZATIONAL & PROFESSIONAL USE
────────────────────────────────────────────────────────────────────────────
- Use in corporate, government, or production environments is PROHIBITED
- Not suitable for mission-critical or production systems
- Intended for educational and competition environments ONLY
- You assume liability for any organizational damage or policy violations

🌐 7. THIRD-PARTY SOFTWARE & DEPENDENCIES
────────────────────────────────────────────────────────────────────────────
- This software may use third-party tools and dependencies
- The author is not responsible for third-party software behavior
- Third-party software may have separate license terms
- Updates may introduce new dependencies or change behavior

📊 8. ACCURACY OF SECURITY SCANNING
────────────────────────────────────────────────────────────────────────────
- Security scan results may contain false positives or false negatives
- Not suitable as sole security assessment tool
- Results should be verified by qualified security professionals
- Missing vulnerabilities could leave systems exposed

🔄 9. AUTOMATIC FIXES & MODIFICATIONS
────────────────────────────────────────────────────────────────────────────
- Automatic fix features may cause unintended system changes
- Could break legitimate software or system functionality
- May violate organizational security policies
- All automatic fixes are applied at your own risk

📋 10. COMPLIANCE & REGULATORY REQUIREMENTS
────────────────────────────────────────────────────────────────────────────
- You are responsible for compliance with all applicable laws
- Must comply with organizational policies and procedures
- Regulatory compliance (SOX, HIPAA, PCI-DSS, etc.) is your responsibility
- International usage must comply with local laws and export controls

⚠️  11. MAXIMUM LIABILITY LIMITATION
────────────────────────────────────────────────────────────────────────────
TO THE MAXIMUM EXTENT PERMITTED BY LAW:
- The author's liability is LIMITED TO ZERO DOLLARS ($0.00)
- No liability for direct, indirect, incidental, or consequential damages
- No liability for lost profits, data, time, or business opportunities
- No liability regardless of the theory of liability (contract, tort, etc.)
- These limitations apply even if the author has been advised of potential damages

🔒 12. INDEMNIFICATION
────────────────────────────────────────────────────────────────────────────
You agree to INDEMNIFY and HOLD HARMLESS the author from any claims, damages,
liabilities, costs, or expenses arising from your use of this software.

⚖️  13. JURISDICTION & DISPUTE RESOLUTION
────────────────────────────────────────────────────────────────────────────
- Governed by the laws where the author resides
- Any disputes subject to binding arbitration
- User responsible for their own legal costs
- GPL v3.0 license terms supersede conflicting provisions

📝 14. ACKNOWLEDGMENT OF UNDERSTANDING
────────────────────────────────────────────────────────────────────────────
By using this software, you acknowledge that you have read, understood, and 
agree to be bound by this disclaimer. If you do not agree to these terms, 
you must not use this software.

🎯 15. COMPETITION-SPECIFIC WARNINGS
────────────────────────────────────────────────────────────────────────────
- CyberPatriot teams: Verify all actions comply with current rule sets
- Different competition rounds may have different restrictions
- Rule changes may occur without notice
- Teams responsible for monitoring current competition guidelines
- Coaches and mentors should review all automated actions

💡 16. RECOMMENDED SAFETY PRACTICES
────────────────────────────────────────────────────────────────────────────
- Always backup your system before using this software
- Test in virtual machines or non-production environments first
- Have recovery plans for potential system failures
- Understand what each operation does before executing
- Consider using manual mode instead of automatic fixes

📞 17. NO EMERGENCY SUPPORT
────────────────────────────────────────────────────────────────────────────
- No emergency support or hotline available
- The author is not responsible for time-sensitive issues
- Competition deadlines do not create support obligations
- Plan accordingly and allow time for potential issues

This disclaimer is subject to change without notice. The most current version
is always embedded in the software. Your continued use constitutes acceptance
of any changes.

═══════════════════════════════════════════════════════════════════════════════
🚨 BY USING THIS SOFTWARE, YOU ACCEPT ALL RISKS AND WAIVE ALL CLAIMS AGAINST
   THE AUTHOR. IF YOU DO NOT ACCEPT THESE TERMS, DO NOT USE THIS SOFTWARE.
═══════════════════════════════════════════════════════════════════════════════

For the complete GNU GPL v3.0 license text, run: ironguard --license

Software Version: {version}
Disclaimer Version: 1.0
Last Updated: {date}
═══════════════════════════════════════════════════════════════════════════════
"#;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Handle special flags FIRST - before any other processing
    if cli.license {
        println!("{}", GPL_V3_LICENSE);
        return Ok(());
    }
    
    if cli.disclaimer {
        let disclaimer = LEGAL_DISCLAIMER
            .replace("{version}", env!("CARGO_PKG_VERSION"))
            .replace("{date}", &chrono::Utc::now().format("%Y-%m-%d").to_string());
        println!("{}", disclaimer);
        return Ok(());
    }
    
    // Initialize logging
    logger::init(cli.verbose)?;
    
    info!("IronGuard v{} - CyberPatriot Security Scanner", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let config = Config::load(&cli.config)?;

    match cli.command {
        Some(Commands::Scan { auto_fix, interactive, target }) => {
            if interactive {
                // Launch TUI interface
                let mut app = TuiApp::new(config).await?;
                app.run().await?;
            } else {
                // Run CLI scan
                let engine = ScannerEngine::new(config)?;
                let results = engine.scan_all(Some(target)).await?;
                
                if auto_fix {
                    info!("Auto-fixing detected vulnerabilities...");
                    engine.auto_fix(&results).await?;
                }
                
                engine.generate_report(&results).await?;
            }
        }
        Some(Commands::Fix { vulnerability_id }) => {
            let engine = ScannerEngine::new(config)?;
            engine.fix_specific(&vulnerability_id).await?;
        }
        Some(Commands::Report { format, output }) => {
            let engine = ScannerEngine::new(config)?;
            engine.export_report(format, output).await?;
        }
        Some(Commands::Config { action }) => {
            match action {
                ironguard::cli::ConfigAction::Init => {
                    Config::init_default()?;
                    info!("Configuration initialized successfully");
                }
                ironguard::cli::ConfigAction::Show => {
                    println!("{}", config.to_string()?);
                }
                ironguard::cli::ConfigAction::Validate => {
                    config.validate()?;
                    info!("Configuration is valid");
                }
            }
        }
        None => {
            // Default to TUI when no command specified
            let mut app = TuiApp::new(config).await?;
            app.run().await?;
        }
    }
    
    Ok(())
}