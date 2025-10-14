use std::{collections::HashMap, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use tokio::{fs, time};

use crate::cli::logging::LogManager;
use crate::ai::{AiConfig, ProviderKind, AiProvider, GeminiProvider};

#[derive(Clone, Debug)]
pub struct ForensicsOptions {
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub time_budget_secs: u64,
    pub allow_exec: bool,
    pub readme_path: Option<PathBuf>,
    pub use_tui: bool,
    pub custom_script: Option<PathBuf>,
}

pub async fn run(opts: &ForensicsOptions, logger: &mut LogManager) -> Result<()> {
    let deadline = time::Instant::now() + Duration::from_secs(opts.time_budget_secs);
    logger.log_message("forensics:start", &format!("provider={} model={} tui={} allow_exec={}", opts.provider, opts.model, opts.use_tui, opts.allow_exec)).ok();

    // Quick safety: if execution is allowed, prefer running as root (sudo)
    if opts.allow_exec && !is_root().await.unwrap_or(false) {
        logger.log_message("forensics:warn", "allow_exec=true but not running as root; some actions may fail").ok();
    }

    // 1) Discover README on Desktop (preferring SUDO_USER desktop when running as root)
    let readme = match &opts.readme_path { Some(p) => Some(p.clone()), None => discover_desktop_readme_for_sudo_user().await };
    if let Some(p) = &readme { logger.log_message("forensics:readme", &format!("found path={}", p.display())).ok(); }
    else { logger.log_message("forensics:readme", "not found").ok(); }

    // 2) Scan Desktop for forensics question files (name contains forensic|question)
    let desktop = discover_desktop_dir_for_sudo_user().await;
    let questions = if let Some(d) = &desktop { scan_for_questions(d).await.unwrap_or_default() } else { vec![] };
    logger.log_message("forensics:questions", &format!("found={}", questions.len())).ok();

    // 3) Initialize AI client (Gemini supported; others stubbed)
    let mut ai = AiClient::new(opts.provider.clone(), opts.model.clone(), opts.api_key.clone(), opts.allow_exec).await?;

    // 4) If TUI requested, start a minimal CLI status loop (stub pretty output)
    if opts.use_tui {
        // In a real implementation we would spin a task that renders frames/animations
        logger.log_message("forensics:tui", "enabled").ok();
    }

    // 5) Read README text if present and feed into planning
    if let Some(p) = &readme {
        if let Ok(txt) = fs::read_to_string(p).await { ai.push_context("readme", txt); }
    }

    // 6) Iterate questions: read content and let AI propose actions
    for q in &questions {
        if time::Instant::now() >= deadline { break; }
        let content = fs::read_to_string(q).await.unwrap_or_default();
        ai.push_context(&format!("question:{}", q.file_name().and_then(|s| s.to_str()).unwrap_or("unknown")), content);
        // Placeholder: have AI answer and optionally execute commands
        let _ = ai.answer_and_optionally_execute_with_timeout("solve_question", Duration::from_secs(90)).await;
    }

    // 7) Follow README directives (stub: detect known tokens later)
    let _ = ai.answer_and_optionally_execute_with_timeout("apply_readme_directives", Duration::from_secs(120)).await;

    // 8) Run our deterministic script if requested via option or present by convention
    if let Some(script) = &opts.custom_script {
        let _ = ai.exec_script(script).await;
    }

    // 9) Open score report if present and assess points
    if let Some(d) = &desktop {
        let score = find_score_report(d).await;
        if let Some(s) = &score { logger.log_message("forensics:score_report", &format!("found path={}", s.display())).ok(); }
        // 9a) If not at 100, attempt heuristic reverse-engineering (placeholder)
    let _ = ai.answer_and_optionally_execute_with_timeout("reverse_engineer_scoring_engine", Duration::from_secs(240)).await;
    }

    // 10) Penalty management: if points gained + penalties removed reaches 100, stop
    // MVP placeholder: we do not infer score deltas yet; this will query AI plan state
    let _ = ai.answer_and_optionally_execute_with_timeout("remove_penalties_after_100", Duration::from_secs(90)).await;

    logger.log_message("forensics:end", "completed").ok();
    Ok(())
}

async fn discover_desktop_dir_for_sudo_user() -> Option<PathBuf> {
    // Prefer SUDO_USER when running under sudo
    use std::env;
    if let Some(sudo_user) = env::var_os("SUDO_USER") {
        if let Some(home) = home_dir_for_user(&sudo_user) { return Some(home.join("Desktop")); }
    }
    // Fallback to current user's HOME/USERPROFILE
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from));
    home.map(|h| h.join("Desktop"))
}

async fn discover_desktop_readme_for_sudo_user() -> Option<PathBuf> {
    let desktop = discover_desktop_dir_for_sudo_user().await?;
    if let Ok(entries) = fs::read_dir(&desktop).await {
        let mut dir = entries;
        while let Ok(Some(e)) = dir.next_entry().await {
            let p = e.path();
            if let Some(ext) = p.extension() {
                let ext = ext.to_string_lossy().to_ascii_lowercase();
                if ext == "html" || ext == "htm" || ext == "md" || ext == "txt" {
                    if let Some(name) = p.file_stem().and_then(|s| s.to_str()) {
                        let n = name.to_ascii_lowercase();
                        if n.contains("readme") { return Some(p); }
                    }
                }
            }
        }
    }
    None
}

pub async fn scan_for_questions(desktop: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(desktop).await {
        let mut dir = entries;
        while let Ok(Some(e)) = dir.next_entry().await {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                let n = name.to_ascii_lowercase();
                // Treat filenames mentioning either forensic(s) or question(s) as candidates
                if (n.contains("forensic") || n.contains("forensics") || n.contains("question")) {
                    if p.is_file() { out.push(p); }
                }
            }
        }
    }
    Ok(out)
}

async fn find_score_report(desktop: &PathBuf) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir(desktop).await {
        let mut dir = entries;
        while let Ok(Some(e)) = dir.next_entry().await {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                let n = name.to_ascii_lowercase();
                if n.contains("score") && (n.ends_with(".html") || n.ends_with(".htm") || n.ends_with(".txt")) {
                    return Some(p);
                }
            }
        }
    }
    None
}

fn home_dir_for_user(user_os: &std::ffi::OsString) -> Option<PathBuf> {
    // Minimal lookup using /etc/passwd when on Unix; fallback ignored on Windows
    #[cfg(target_os = "linux")]
    {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::fs::File;
        let user = user_os.to_string_lossy().to_string();
        let rt = tokio::runtime::Handle::current();
        return rt.block_on(async move {
            if let Ok(f) = File::open("/etc/passwd").await {
                let mut lines = BufReader::new(f).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some((name, rest)) = line.split_once(":") {
                        if name == user {
                            if let Some(home_field) = rest.split(':').nth(4) {
                                return Some(PathBuf::from(home_field));
                            }
                        }
                    }
                }
            }
            None
        });
    }
    #[allow(unreachable_code)]
    None
}

async fn is_root() -> Result<bool> {
    use tokio::process::Command;
    if cfg!(target_os = "linux") {
        let out = Command::new("id").arg("-u").output().await?;
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            return Ok(s == "0");
        }
    }
    Ok(false)
}

// ----------------------------- AI Client Stub -----------------------------

struct AiClient {
    provider: String,
    model: String,
    api_key: Option<String>,
    allow_exec: bool,
    context: HashMap<String, String>,
    llm: Option<Box<dyn AiProvider>>, // only used when online
}

impl AiClient {
    async fn new(provider: String, model: String, api_key: Option<String>, allow_exec: bool) -> anyhow::Result<Self> {
        let kind = ProviderKind::parse(&provider);
        let llm: Option<Box<dyn AiProvider>> = match kind {
            ProviderKind::GoogleGemini => {
                let g = GeminiProvider::new(model.clone(), api_key.clone())?;
                Some(Box::new(g))
            }
            _ => None,
        };
        Ok(Self { provider, model, api_key, allow_exec, context: HashMap::new(), llm })
    }

    fn push_context(&mut self, key: &str, value: String) {
        self.context.insert(key.to_string(), value);
    }

    async fn answer_and_optionally_execute_with_timeout(&mut self, goal: &str, _timeout: Duration) -> Result<()> {
        if let Some(llm) = self.llm.as_ref() {
            let system = "You are a CyberPatriot forensics assistant. Propose minimal, safe commands and rationale.";
            let user = format!("Goal: {}\nContext keys: {}", goal, self.context.keys().cloned().collect::<Vec<_>>().join(", "));
            let _resp = llm.complete(system, &user).await.ok();
            // TODO: parse commands and run if allow_exec (future work)
        }
        Ok(())
    }

    async fn exec_script(&self, path: &PathBuf) -> Result<()> {
        if !self.allow_exec { return Ok(()); }
        if cfg!(target_os = "linux") {
            let p = path.to_string_lossy().to_string();
            exec("bash", &["-lc", &format!("chmod +x '{}' && '{}'", p, p)]).await?;
        }
        Ok(())
    }
}

async fn exec<S: AsRef<str>>(prog: S, args: &[S]) -> Result<()> {
    use tokio::process::Command;
    let prog_s = prog.as_ref();
    let args_s: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
    let status = Command::new(prog_s).args(&args_s).status().await
        .with_context(|| format!("running {} {}", prog_s, args_s.join(" ")))?;
    println!("[forensics:exec] {} {} -> {}", prog_s, args_s.join(" "), status);
    Ok(())
}


