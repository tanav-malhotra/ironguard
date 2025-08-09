use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    symbols::DOT,
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, time::interval};
use tracing::{debug, error, info};

use crate::{
    config::Config,
    scanners::{ScanResults, ScannerEngine, Vulnerability, VulnerabilityLevel},
};

#[derive(Debug)]
pub enum TuiEvent {
    Tick,
    Key(event::KeyEvent),
    ScanProgress { scanner: String, progress: f32 },
    ScanComplete { results: ScanResults },
    ScanError { error: String },
    FixProgress { vulnerability_id: String, progress: f32 },
    FixComplete { vulnerability_id: String },
    FixError { vulnerability_id: String, error: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    MainMenu,
    Scanning,
    Results,
    VulnerabilityDetail,
    Fixing,
    Settings,
    Help,
}

#[derive(Debug)]
pub struct AppData {
    pub scan_results: Option<ScanResults>,
    pub selected_vulnerability: Option<usize>,
    pub scan_progress: HashMap<String, f32>,
    pub overall_progress: f32,
    pub fix_progress: HashMap<String, f32>,
    pub status_message: String,
    pub auto_fix_enabled: bool,
}

impl Default for AppData {
    fn default() -> Self {
        Self {
            scan_results: None,
            selected_vulnerability: None,
            scan_progress: HashMap::new(),
            overall_progress: 0.0,
            fix_progress: HashMap::new(),
            status_message: "Ready to scan".to_string(),
            auto_fix_enabled: false,
        }
    }
}

pub struct TuiApp {
    config: Config,
    state: AppState,
    data: Arc<Mutex<AppData>>,
    selected_tab: usize,
    vulnerability_list_state: ListState,
    event_tx: mpsc::Sender<TuiEvent>,
    event_rx: mpsc::Receiver<TuiEvent>,
    should_quit: bool,
    last_tick: Instant,
}

impl TuiApp {
    pub async fn new(config: Config) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::channel(100);
        
        Ok(Self {
            config,
            state: AppState::MainMenu,
            data: Arc::new(Mutex::new(AppData::default())),
            selected_tab: 0,
            vulnerability_list_state: ListState::default(),
            event_tx,
            event_rx,
            should_quit: false,
            last_tick: Instant::now(),
        })
    }
    
    pub async fn run(&mut self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        // Setup event handling
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                if event::poll(Duration::from_millis(0)).unwrap_or(false) {
                    if let Ok(event) = event::read() {
                        if let Event::Key(key) = event {
                            if key.kind == KeyEventKind::Press {
                                let _ = event_tx.send(TuiEvent::Key(key)).await;
                            }
                        }
                    }
                }
                let _ = event_tx.send(TuiEvent::Tick).await;
            }
        });
        
        // Main event loop
        loop {
            terminal.draw(|f| self.ui(f))?;
            
            if let Ok(event) = self.event_rx.try_recv() {
                match event {
                    TuiEvent::Key(key) => {
                        if let Err(e) = self.handle_key(key).await {
                            error!("Error handling key event: {}", e);
                        }
                    }
                    TuiEvent::Tick => {
                        let now = Instant::now();
                        if now.duration_since(self.last_tick) >= Duration::from_millis(200) {
                            self.on_tick();
                            self.last_tick = now;
                        }
                    }
                    TuiEvent::ScanProgress { scanner, progress } => {
                        let mut data = self.data.lock().unwrap();
                        data.scan_progress.insert(scanner, progress);
                        data.overall_progress = data.scan_progress.values().sum::<f32>() / data.scan_progress.len() as f32;
                    }
                    TuiEvent::ScanComplete { results } => {
                        let mut data = self.data.lock().unwrap();
                        data.scan_results = Some(results);
                        data.status_message = format!("Scan completed - Found {} vulnerabilities", 
                            data.scan_results.as_ref().unwrap().vulnerabilities.len());
                        self.state = AppState::Results;
                    }
                    TuiEvent::ScanError { error } => {
                        let mut data = self.data.lock().unwrap();
                        data.status_message = format!("Scan error: {}", error);
                        self.state = AppState::MainMenu;
                    }
                    TuiEvent::FixProgress { vulnerability_id, progress } => {
                        let mut data = self.data.lock().unwrap();
                        data.fix_progress.insert(vulnerability_id, progress);
                    }
                    TuiEvent::FixComplete { vulnerability_id } => {
                        let mut data = self.data.lock().unwrap();
                        data.fix_progress.remove(&vulnerability_id);
                        data.status_message = format!("Fixed vulnerability: {}", vulnerability_id);
                    }
                    TuiEvent::FixError { vulnerability_id, error } => {
                        let mut data = self.data.lock().unwrap();
                        data.fix_progress.remove(&vulnerability_id);
                        data.status_message = format!("Fix error for {}: {}", vulnerability_id, error);
                    }
                }
            }
            
            if self.should_quit {
                break;
            }
        }
        
        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        
        Ok(())
    }
    
    fn ui<B: Backend>(&mut self, f: &mut Frame<B>) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Main content
                Constraint::Length(3), // Status bar
            ])
            .split(f.size());
        
        // Header
        self.render_header(f, chunks[0]);
        
        // Main content based on state
        match self.state {
            AppState::MainMenu => self.render_main_menu(f, chunks[1]),
            AppState::Scanning => self.render_scanning(f, chunks[1]),
            AppState::Results => self.render_results(f, chunks[1]),
            AppState::VulnerabilityDetail => self.render_vulnerability_detail(f, chunks[1]),
            AppState::Fixing => self.render_fixing(f, chunks[1]),
            AppState::Settings => self.render_settings(f, chunks[1]),
            AppState::Help => self.render_help(f, chunks[1]),
        }
        
        // Status bar
        self.render_status_bar(f, chunks[2]);
    }
    
    fn render_header<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let title = Paragraph::new("🛡️  IronGuard - CyberPatriot Security Scanner")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, area);
    }
    
    fn render_main_menu<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),  // Menu options
                Constraint::Min(0),     // System info
            ])
            .split(area);
        
        // Menu options
        let menu_items = vec![
            "🔍 [S] Start Full Security Scan",
            "🔧 [F] Quick Fix All Auto-Fixable Issues",
            "📊 [R] View Last Scan Results",
            "⚙️  [C] Configuration",
            "❓ [H] Help",
            "🚪 [Q] Quit",
        ];
        
        let menu_list: Vec<ListItem> = menu_items
            .iter()
            .map(|item| ListItem::new(Line::from(*item)))
            .collect();
        
        let menu = List::new(menu_list)
            .block(Block::default()
                .title("Main Menu")
                .borders(Borders::ALL))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD));
        
        f.render_widget(menu, chunks[0]);
        
        // System info
        let data = self.data.lock().unwrap();
        let system_info = format!(
            "System Ready\nAuto-fix: {}\nElevated: {}\nTarget: local",
            if data.auto_fix_enabled { "✅ Enabled" } else { "❌ Disabled" },
            if crate::utils::is_elevated() { "✅ Yes" } else { "❌ No" }
        );
        
        let info_block = Paragraph::new(system_info)
            .block(Block::default()
                .title("System Status")
                .borders(Borders::ALL))
            .style(Style::default().fg(Color::Green));
        
        f.render_widget(info_block, chunks[1]);
    }
    
    fn render_scanning<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Overall progress
                Constraint::Min(0),     // Individual scanner progress
            ])
            .split(area);
        
        let data = self.data.lock().unwrap();
        
        // Overall progress
        let overall_gauge = Gauge::default()
            .block(Block::default().title("Overall Progress").borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Cyan))
            .percent((data.overall_progress * 100.0) as u16)
            .label(format!("{:.1}%", data.overall_progress * 100.0));
        
        f.render_widget(overall_gauge, chunks[0]);
        
        // Individual scanner progress
        let scanner_items: Vec<ListItem> = data.scan_progress
            .iter()
            .map(|(scanner, progress)| {
                let progress_bar = "█".repeat((*progress * 20.0) as usize);
                let empty_bar = "░".repeat(20 - (*progress * 20.0) as usize);
                ListItem::new(Line::from(format!(
                    "{:<20} [{}{}] {:.1}%",
                    scanner,
                    progress_bar,
                    empty_bar,
                    progress * 100.0
                )))
            })
            .collect();
        
        let scanner_list = List::new(scanner_items)
            .block(Block::default()
                .title("Scanner Progress")
                .borders(Borders::ALL))
            .style(Style::default().fg(Color::White));
        
        f.render_widget(scanner_list, chunks[1]);
    }
    
    fn render_results<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(40), // Vulnerability list
                Constraint::Percentage(60), // Details
            ])
            .split(area);
        
        let data = self.data.lock().unwrap();
        
        if let Some(results) = &data.scan_results {
            // Vulnerability list
            let vulnerability_items: Vec<ListItem> = results.vulnerabilities
                .iter()
                .enumerate()
                .map(|(i, vuln)| {
                    let level_color = match vuln.level {
                        VulnerabilityLevel::Critical => Color::Red,
                        VulnerabilityLevel::High => Color::LightRed,
                        VulnerabilityLevel::Medium => Color::Yellow,
                        VulnerabilityLevel::Low => Color::Blue,
                        VulnerabilityLevel::Info => Color::Gray,
                    };
                    
                    let auto_fix_indicator = if vuln.auto_fixable { "🔧" } else { "🔍" };
                    
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{} ", auto_fix_indicator), Style::default().fg(Color::Green)),
                        Span::styled(format!("{:<8}", vuln.level), Style::default().fg(level_color)),
                        Span::styled(&vuln.title, Style::default().fg(Color::White)),
                    ]))
                })
                .collect();
            
            let vulnerability_list = List::new(vulnerability_items)
                .block(Block::default()
                    .title(format!("Vulnerabilities ({})", results.vulnerabilities.len()))
                    .borders(Borders::ALL))
                .style(Style::default().fg(Color::White))
                .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD));
            
            f.render_stateful_widget(vulnerability_list, chunks[0], &mut self.vulnerability_list_state);
            
            // Vulnerability details
            if let Some(selected) = self.vulnerability_list_state.selected() {
                if let Some(vuln) = results.vulnerabilities.get(selected) {
                    let details = format!(
                        "ID: {}\n\nDescription:\n{}\n\nCategory: {}\n\nEvidence:\n{}\n\nRemediation:\n{}\n\nScore Impact: {}",
                        vuln.id,
                        vuln.description,
                        vuln.category,
                        vuln.evidence.join("\n"),
                        vuln.remediation,
                        vuln.score_impact
                    );
                    
                    let details_block = Paragraph::new(details)
                        .block(Block::default()
                            .title("Vulnerability Details")
                            .borders(Borders::ALL))
                        .style(Style::default().fg(Color::White))
                        .wrap(Wrap { trim: true });
                    
                    f.render_widget(details_block, chunks[1]);
                }
            } else {
                let help_text = "Use ↑↓ to navigate vulnerabilities\nPress ENTER to view details\nPress F to fix selected vulnerability\nPress A to auto-fix all";
                let help_block = Paragraph::new(help_text)
                    .block(Block::default()
                        .title("Help")
                        .borders(Borders::ALL))
                    .style(Style::default().fg(Color::Gray));
                
                f.render_widget(help_block, chunks[1]);
            }
        }
    }
    
    fn render_vulnerability_detail<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        // Implementation for detailed vulnerability view
        let placeholder = Paragraph::new("Detailed vulnerability view (TODO)")
            .block(Block::default().title("Vulnerability Detail").borders(Borders::ALL));
        f.render_widget(placeholder, area);
    }
    
    fn render_fixing<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let data = self.data.lock().unwrap();
        
        if data.fix_progress.is_empty() {
            let message = Paragraph::new("No fixes in progress")
                .block(Block::default().title("Fix Progress").borders(Borders::ALL))
                .alignment(Alignment::Center);
            f.render_widget(message, area);
        } else {
            let fix_items: Vec<ListItem> = data.fix_progress
                .iter()
                .map(|(vuln_id, progress)| {
                    let progress_bar = "█".repeat((*progress * 30.0) as usize);
                    let empty_bar = "░".repeat(30 - (*progress * 30.0) as usize);
                    ListItem::new(Line::from(format!(
                        "{:<30} [{}{}] {:.1}%",
                        vuln_id,
                        progress_bar,
                        empty_bar,
                        progress * 100.0
                    )))
                })
                .collect();
            
            let fix_list = List::new(fix_items)
                .block(Block::default()
                    .title("Fix Progress")
                    .borders(Borders::ALL))
                .style(Style::default().fg(Color::Green));
            
            f.render_widget(fix_list, area);
        }
    }
    
    fn render_settings<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let placeholder = Paragraph::new("Settings configuration (TODO)")
            .block(Block::default().title("Settings").borders(Borders::ALL));
        f.render_widget(placeholder, area);
    }
    
    fn render_help<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let help_text = vec![
            "🛡️  IronGuard - CyberPatriot Security Scanner",
            "",
            "GLOBAL SHORTCUTS:",
            "  Q - Quit application",
            "  H - Show this help",
            "  ESC - Go back to main menu",
            "",
            "MAIN MENU:",
            "  S - Start full security scan",
            "  F - Quick fix all auto-fixable issues",
            "  R - View last scan results",
            "  C - Open configuration",
            "",
            "RESULTS VIEW:",
            "  ↑↓ - Navigate vulnerability list",
            "  ENTER - View vulnerability details",
            "  F - Fix selected vulnerability",
            "  A - Auto-fix all fixable vulnerabilities",
            "",
            "SCANNING:",
            "  ESC - Cancel scan (if supported)",
            "",
            "TIPS:",
            "  • Run with administrator/root privileges for best results",
            "  • Review auto-fixes before applying in competition",
            "  • Use configuration to customize for specific scenarios",
        ];
        
        let help_paragraph = Paragraph::new(help_text.join("\n"))
            .block(Block::default().title("Help").borders(Borders::ALL))
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });
        
        f.render_widget(help_paragraph, area);
    }
    
    fn render_status_bar<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let data = self.data.lock().unwrap();
        let status_paragraph = Paragraph::new(data.status_message.clone())
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Left)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(status_paragraph, area);
    }
    
    async fn handle_key(&mut self, key: event::KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.should_quit = true;
            }
            KeyCode::Char('h') | KeyCode::Char('H') => {
                self.state = AppState::Help;
            }
            KeyCode::Esc => {
                match self.state {
                    AppState::MainMenu => self.should_quit = true,
                    _ => self.state = AppState::MainMenu,
                }
            }
            _ => {
                match self.state {
                    AppState::MainMenu => self.handle_main_menu_key(key).await?,
                    AppState::Results => self.handle_results_key(key).await?,
                    _ => {}
                }
            }
        }
        Ok(())
    }
    
    async fn handle_main_menu_key(&mut self, key: event::KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.start_scan().await?;
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                self.quick_fix_all().await?;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                if self.data.lock().unwrap().scan_results.is_some() {
                    self.state = AppState::Results;
                }
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.state = AppState::Settings;
            }
            _ => {}
        }
        Ok(())
    }
    
    async fn handle_results_key(&mut self, key: event::KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Up => {
                let data = self.data.lock().unwrap();
                if let Some(results) = &data.scan_results {
                    let selected = self.vulnerability_list_state.selected().unwrap_or(0);
                    if selected > 0 {
                        self.vulnerability_list_state.select(Some(selected - 1));
                    }
                }
            }
            KeyCode::Down => {
                let data = self.data.lock().unwrap();
                if let Some(results) = &data.scan_results {
                    let selected = self.vulnerability_list_state.selected().unwrap_or(0);
                    if selected < results.vulnerabilities.len() - 1 {
                        self.vulnerability_list_state.select(Some(selected + 1));
                    }
                }
            }
            KeyCode::Enter => {
                self.state = AppState::VulnerabilityDetail;
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                self.fix_selected_vulnerability().await?;
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                self.auto_fix_all().await?;
            }
            _ => {}
        }
        Ok(())
    }
    
    async fn start_scan(&mut self) -> Result<()> {
        info!("Starting security scan from TUI");
        self.state = AppState::Scanning;
        
        let config = self.config.clone();
        let event_tx = self.event_tx.clone();
        
        tokio::spawn(async move {
            match ScannerEngine::new(config) {
                Ok(engine) => {
                    // Simulate progress updates
                    for (i, scanner_name) in ["Users", "Services", "Network", "FileSystem", "Software", "System"].iter().enumerate() {
                        for progress in (0..=100).step_by(20) {
                            let _ = event_tx.send(TuiEvent::ScanProgress {
                                scanner: scanner_name.to_string(),
                                progress: progress as f32 / 100.0,
                            }).await;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                    
                    match engine.scan_all(None).await {
                        Ok(results) => {
                            let _ = event_tx.send(TuiEvent::ScanComplete { results }).await;
                        }
                        Err(e) => {
                            let _ = event_tx.send(TuiEvent::ScanError { error: e.to_string() }).await;
                        }
                    }
                }
                Err(e) => {
                    let _ = event_tx.send(TuiEvent::ScanError { error: e.to_string() }).await;
                }
            }
        });
        
        Ok(())
    }
    
    async fn quick_fix_all(&mut self) -> Result<()> {
        info!("Starting quick fix of all auto-fixable issues");
        // Implementation would fix all auto-fixable vulnerabilities
        Ok(())
    }
    
    async fn fix_selected_vulnerability(&mut self) -> Result<()> {
        info!("Fixing selected vulnerability");
        // Implementation would fix the selected vulnerability
        Ok(())
    }
    
    async fn auto_fix_all(&mut self) -> Result<()> {
        info!("Auto-fixing all fixable vulnerabilities");
        // Implementation would auto-fix all fixable vulnerabilities
        Ok(())
    }
    
    fn on_tick(&mut self) {
        // Update UI state on each tick
    }
}