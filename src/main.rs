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
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    logger::init(cli.verbose)?;
    
    info!("IronGuard v{} - CyberPatriot Security Scanner", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let config = Config::load(&cli.config)?;
    
    match cli.command {
        Commands::Scan { auto_fix, interactive, target } => {
            if interactive {
                // Launch TUI interface
                let mut app = TuiApp::new(config).await?;
                app.run().await?;
            } else {
                // Run CLI scan
                let engine = ScannerEngine::new(config)?;
                let results = engine.scan_all(target).await?;
                
                if auto_fix {
                    info!("Auto-fixing detected vulnerabilities...");
                    engine.auto_fix(&results).await?;
                }
                
                engine.generate_report(&results).await?;
            }
        }
        Commands::Fix { vulnerability_id } => {
            let engine = ScannerEngine::new(config)?;
            engine.fix_specific(&vulnerability_id).await?;
        }
        Commands::Report { format, output } => {
            let engine = ScannerEngine::new(config)?;
            engine.export_report(format, output).await?;
        }
        Commands::Config { action } => {
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
    }
    
    Ok(())
}