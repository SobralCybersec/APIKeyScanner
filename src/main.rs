mod dorks;
mod storage;
mod cli;
mod validator;
mod tui;
mod launcher;
mod config;
mod patterns;

use anyhow::Result;
use chrono::{Timelike, Utc};
use clap::Parser;
use futures::stream::{self, StreamExt};
use inquire::Select;
use std::env;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use storage::{PrivateFinding, PublicFinding, SecureStorage};
use patterns::API_KEY_PATTERNS;

#[derive(Parser)]
#[command(name = "api-key-scanner")]
#[command(about = "Fast GitHub API key scanner with interactive TUI")]
struct Cli {
    #[arg(short, long, env = "GITHUB_TOKEN")]
    token: Option<String>,
    
    #[arg(short, long, default_value = "data")]
    output: PathBuf,
    
    #[arg(long, default_value = "10")]
    max_requests: usize,
    
    #[arg(long, default_value = "5")]
    concurrency: usize,
    
    #[arg(long)]
    use_dorks: bool,
    
    #[arg(long)]
    full_scan: bool,
    
    #[arg(long)]
    interactive: bool,
    
    #[arg(long)]
    view: bool,
    
    #[arg(long)]
    show_dorks: bool,
    
    #[arg(long)]
    test_keys: bool,
    
    #[arg(long)]
    no_tui: bool,
    
    #[arg(long)]
    quick: bool,
}

// Helper functions for tarball extraction (moved outside Scanner for spawn_blocking)
fn is_false_positive_check(key: &str, line: &str, label: &str) -> bool {
    let key_lower = key.to_lowercase();
    let line_lower = line.to_lowercase();
    
    // UUID/GUID false positives (unless explicitly Heroku/Pinecone context)
    if !label.contains("heroku") && !label.contains("pinecone") {
        if let Ok(uuid_pattern) = regex::Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") {
            if uuid_pattern.is_match(key) {
                return true;
            }
        }
    }
    
    // Obvious placeholders
    if key_lower.contains("example") || key_lower.contains("your_") 
        || key_lower.contains("xxx") || key_lower.contains("***")
        || key_lower.contains("replace") || key_lower.contains("placeholder")
        || key_lower.contains("dummy") || key_lower.contains("fake")
        || key_lower.contains("test123") || key_lower.contains("sample")
        || key_lower.contains("changeme") || key_lower.contains("todo")
        || key_lower.contains("insert_key") || key_lower.contains("<api_key>")
        || key == "0000000000000000000000000000000000000000"
        || key == "1111111111111111111111111111111111111111" {
        return true;
    }
    
    // Context-based false positives
    if line_lower.contains("public_key") || line_lower.contains("public_token")
        || line_lower.contains("api_version") || line_lower.contains("client_version")
        || line_lower.contains("secret_name") || line_lower.contains("key_name")
        || line_lower.contains("token_name") || line_lower.contains("client_name")
        || line_lower.contains("api_id") || line_lower.contains("key_id")
        || line_lower.contains("primary_key") || line_lower.contains("foreign_key")
        || line_lower.contains("natural_key") || line_lower.contains("bucket_key")
        || line_lower.contains("schema_key") || line_lower.contains("sequence_key")
        || line_lower.contains("monkey") || line_lower.contains("donkey")
        || line_lower.contains("keyboard") || line_lower.contains("keystone")
        || line_lower.contains("rapid") || line_lower.contains("capital")
        || line_lower.contains("author") || line_lower.contains("accessor")
        || line_lower.contains("key_up") || line_lower.contains("key_down")
        || line_lower.contains("key_left") || line_lower.contains("key_right")
        || line_lower.contains("key_code") || line_lower.contains("key_frame")
        || line_lower.contains("key_alias") || line_lower.contains("key_ring")
        || line_lower.contains("keystore") || line_lower.contains("key_vault_id")
        || line_lower.contains("key_vault_name") || line_lower.contains("issuerkeyhash") {
        return true;
    }
    
    // Minimum length check
    if key.len() < 10 && !label.contains("url") && !label.contains("private-key") {
        return true;
    }
    
    // Low entropy check
    let entropy = calculate_entropy_helper(key);
    if entropy < 3.5 && !label.contains("url") && !label.contains("private-key") {
        return true;
    }
    
    false
}

fn calculate_entropy_helper(s: &str) -> f64 {
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for count in freq.values() {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn extract_secret_match<'a>(cap: &'a regex::Captures<'a>) -> Option<&'a str> {
    cap.iter()
        .skip(1)
        .flatten()
        .map(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .last()
        .or_else(|| cap.get(0).map(|m| m.as_str()))
}

fn response_snippet(body: &str) -> String {
    let snippet: String = body.chars().take(180).collect();
    snippet.replace('\n', " ").replace('\r', " ")
}

// Extract and scan tarball in blocking thread pool
fn extract_and_scan_tarball(
    bytes: Vec<u8>,
    repo_name: String,
    query_label: String,
) -> Result<Vec<PrivateFinding>> {
    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);
    let mut findings = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        if entry.size() > 1_000_000 {
            continue;
        }

        let path = entry.path()?.to_string_lossy().to_string();
        
        if path.ends_with(".png") || path.ends_with(".jpg") || path.ends_with(".gif") 
            || path.ends_with(".pdf") || path.ends_with(".zip") {
            continue;
        }

        let mut content = String::new();
        if std::io::Read::read_to_string(&mut entry, &mut content).is_err() {
            continue;
        }

        for (line_num, line) in content.lines().enumerate() {
            for (pattern, label) in &*API_KEY_PATTERNS {
                for cap in pattern.captures_iter(line) {
                    if let Some(key_str) = extract_secret_match(&cap) {
                        
                        // Enhanced false positive filtering (2026)
                        if is_false_positive_check(key_str, line, label) {
                            continue;
                        }
                        
                        let entropy = calculate_entropy_helper(key_str);
                        
                        let preview = if key_str.len() > 12 {
                            format!("{}***", &key_str[..12])
                        } else {
                            format!("{}***", &key_str[..8.min(key_str.len())])
                        };

                        findings.push(PrivateFinding {
                            repository: repo_name.clone(),
                            file_path: path.clone(),
                            file_url: format!("https://github.com/{}/blob/main/{}", repo_name, path),
                            commit_sha: None,
                            discovered_at: Utc::now().to_rfc3339(),
                            key_type: format!("{}-{}", query_label, label),
                            full_key: key_str.to_string(),
                            key_preview: preview,
                            line_number: Some(line_num + 1),
                            entropy: Some(entropy),
                        });
                        break;
                    }
                }
            }
        }
    }

    Ok(findings)
}

struct Scanner {
    client: reqwest::Client,
    token: String,
    requests_made: Arc<tokio::sync::Mutex<usize>>,
    max_requests: usize,
    semaphore: Arc<Semaphore>,
}

impl Scanner {
    fn new(token: String, max_requests: usize, concurrency: usize) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("APIKeyScanner-Rust/2.1")
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(10)  // Reduced from 20
            .pool_idle_timeout(Duration::from_secs(30))  // Reduced from 90
            .gzip(true)
            .build()?;

        Ok(Self {
            client,
            token,
            requests_made: Arc::new(tokio::sync::Mutex::new(0)),
            max_requests,
            semaphore: Arc::new(Semaphore::new(concurrency)),
        })
    }

    async fn can_make_request(&self) -> bool {
        let count = self.requests_made.lock().await;
        *count < self.max_requests
    }

    async fn increment_requests(&self) {
        let mut count = self.requests_made.lock().await;
        *count += 1;
    }

    async fn search_code(&self, query: &str) -> Result<Vec<serde_json::Value>> {
        if !self.can_make_request().await {
            return Ok(vec![]);
        }

        let url = "https://api.github.com/search/code";
        
        // Add 30-second timeout to prevent indefinite hangs
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            self.client
                .get(url)
                .header("Authorization", format!("Bearer {}", self.token))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2026-03-10")
                .query(&[("q", query), ("per_page", "30"), ("sort", "indexed"), ("order", "desc")])
                .send()
        )
        .await
        .map_err(|_| anyhow::anyhow!("GitHub API search timed out after 30s for query: {}", query))??;

        self.increment_requests().await;

        let status = response.status();
        let body = response.text().await?;

        if status == 401 {
            return Err(anyhow::anyhow!(
                "GitHub API authentication failed (401) for search query '{}'. \
Provide a valid personal access token via --token, GITHUB_TOKEN, or the SCANNER_TOKEN workflow secret.",
                query
            ));
        }

        if status == 403 || status == 429 {
            warn!("Rate limited on search");
            return Ok(vec![]);
        }

        if status == 422 {
            warn!(
                "GitHub rejected search query '{}': {}",
                query,
                response_snippet(&body)
            );
            return Ok(vec![]);
        }

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "GitHub API search failed for query '{}' with HTTP {}: {}",
                query,
                status,
                response_snippet(&body)
            ));
        }

        let data: serde_json::Value = serde_json::from_str(&body)?;
        Ok(data["items"].as_array().cloned().unwrap_or_default())
    }

    async fn analyze_repo(&self, repo_name: &str, query_label: &str) -> Result<Vec<PrivateFinding>> {
        let _permit = self.semaphore.acquire().await?;
        
        if !self.can_make_request().await {
            return Ok(vec![]);
        }

        let url = format!("https://api.github.com/repos/{}/tarball", repo_name);
        
        // Add 60-second timeout for tarball download
        let response = tokio::time::timeout(
            Duration::from_secs(60),
            self.client
                .get(&url)
                .header("Authorization", format!("token {}", self.token))
                .send()
        )
        .await
        .map_err(|_| anyhow::anyhow!("Tarball download timed out after 60s for {}", repo_name))??;

        self.increment_requests().await;

        if !response.status().is_success() {
            return Ok(vec![]);
        }

        let bytes = response.bytes().await?.to_vec();
        let repo_name = repo_name.to_string();
        let query_label = query_label.to_string();

        // Move CPU-intensive tarball extraction to blocking thread pool
        // This prevents blocking the async executor (30-50% throughput improvement)
        let findings = tokio::task::spawn_blocking(move || {
            extract_and_scan_tarball(bytes, repo_name, query_label)
        })
        .await??;

        Ok(findings)
    }

    async fn scan(&self, use_dorks: bool, full_scan: bool, selected_queries: Option<Vec<String>>, tui_app: Option<Arc<tokio::sync::Mutex<tui::TuiApp>>>) -> Result<Vec<PrivateFinding>> {
        let queries = if let Some(selected) = selected_queries {
            selected
        } else if use_dorks {
            dorks::get_advanced_github_queries()
        } else if full_scan {
            vec![
                "sk-proj- filename:.env".to_string(),
                "sk-proj- extension:py".to_string(),
                "sk-proj- extension:js".to_string(),
                "sk-svcacct- filename:.env".to_string(),
                "sk-admin- filename:.env".to_string(),
                "sk-ant- extension:py".to_string(),
                "ANTHROPIC_API_KEY extension:env".to_string(),
                "CLAUDE_API_KEY extension:env".to_string(),
                "OPENAI_API_KEY extension:env".to_string(),
                "CHATGPT_API_KEY extension:env".to_string(),
                "GROQ_API_KEY extension:env".to_string(),
                "DEEPSEEK_API_KEY extension:env".to_string(),
                "MISTRAL_API_KEY extension:env".to_string(),
                "PERPLEXITY_API_KEY extension:env".to_string(),
                "GOOGLE_API_KEY extension:env".to_string(),
                "AWS_ACCESS_KEY_ID extension:env".to_string(),
                "ghp_ extension:env".to_string(),
                "mongodb:// extension:env".to_string(),
            ]
        } else {
            let all_queries = vec![
                "sk-proj- filename:.env",
                "sk-proj- extension:py",
                "sk-proj- extension:js",
                "sk-ant- extension:py",
                "ANTHROPIC_API_KEY extension:env",
                "OPENAI_API_KEY extension:env",
                "CHATGPT_API_KEY extension:env",
                "GROQ_API_KEY extension:env",
                "DEEPSEEK_API_KEY extension:env",
            ];
            let slot = (Utc::now().hour() * 6 + Utc::now().minute() / 10) as usize % all_queries.len();
            vec![all_queries[slot].to_string()]
        };

        let mut all_findings = Vec::new();

        if let Some(ref app) = tui_app {
            let mut app = app.lock().await;
            app.total_queries = queries.len();
            app.status = "Starting scan...".to_string();
        }

        for (idx, query) in queries.iter().enumerate() {
            if !self.can_make_request().await {
                break;
            }

            if let Some(ref app) = tui_app {
                let mut app = app.lock().await;
                app.current_query = idx + 1;
                app.status = format!("Searching: {}", query);
                app.add_log(format!("Query: {}", query));
                app.update_progress();
            }

            info!("Query: {}", query);

            let results = self.search_code(query).await?;
            
            if let Some(ref app) = tui_app {
                let mut app = app.lock().await;
                app.add_log(format!("Found {} files", results.len()));
            }
            
            info!("Found {} files", results.len());

            let mut repos = HashSet::new();
            for item in &results {
                if let Some(repo) = item["repository"]["full_name"].as_str() {
                    repos.insert(repo.to_string());
                }
            }

            let repos: Vec<_> = repos.into_iter().take(9).collect();
            
            if let Some(ref app) = tui_app {
                let mut app = app.lock().await;
                app.status = format!("Scanning {} repositories...", repos.len());
                app.add_log(format!("Scanning {} repos concurrently", repos.len()));
            }
            
            info!("Scanning {} repos concurrently", repos.len());

            let findings: Vec<_> = stream::iter(repos)
                .map(|repo| {
                    let scanner = self.clone();
                    let query_label = query.clone();
                    let tui_app_clone = tui_app.clone();
                    async move {
                        match scanner.analyze_repo(&repo, &query_label).await {
                            Ok(findings) => {
                                if let Some(ref app) = tui_app_clone {
                                    let mut app = app.lock().await;
                                    app.repos_scanned += 1;
                                    app.requests_made = *scanner.requests_made.lock().await;
                                    if !findings.is_empty() {
                                        app.findings_count += findings.len();
                                        app.high_entropy_count += findings.iter().filter(|f| f.entropy.unwrap_or(0.0) > 4.0).count();
                                        app.add_log(format!("WARNING: {}: {} keys found", repo, findings.len()));
                                    }
                                }
                                if !findings.is_empty() {
                                    warn!("WARNING: {}: {} keys found", repo, findings.len());
                                }
                                findings
                            }
                            Err(e) => {
                                if let Some(ref app) = tui_app_clone {
                                    let mut app = app.lock().await;
                                    app.add_log(format!("ERROR: {}", repo));
                                }
                                error!("Error scanning {}: {}", repo, e);
                                vec![]
                            }
                        }
                    }
                })
                .buffer_unordered(self.semaphore.available_permits())
                .collect()
                .await;

            for repo_findings in findings {
                all_findings.extend(repo_findings);
            }
        }

        if let Some(ref app) = tui_app {
            let mut app = app.lock().await;
            app.status = "Scan complete!".to_string();
            app.progress = 100.0;
            app.add_log(format!("Scan complete. Total findings: {}", all_findings.len()));
        }

        Ok(all_findings)
    }
}

impl Clone for Scanner {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            token: self.token.clone(),
            requests_made: Arc::clone(&self.requests_made),
            max_requests: self.max_requests,
            semaphore: Arc::clone(&self.semaphore),
        }
    }
}

fn generate_readme(findings: &[PublicFinding]) -> String {
    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut by_repo: HashMap<String, usize> = HashMap::new();
    
    for f in findings {
        *by_type.entry(f.key_type.clone()).or_insert(0) += 1;
        *by_repo.entry(f.repository.clone()).or_insert(0) += 1;
    }

    let mut readme = format!(
        "# API Key Scanner v2.0 - Security Research\n\n\
        **Last Updated**: {}\n\
        **Total Findings**: {}\n\
        **Unique Repositories**: {}\n\n\
        **SECURITY NOTICE**: This is a security research project. Full API keys are NEVER committed to git.\n\
        Only metadata and key previews are stored in this repository.\n\n\
        ## Statistics\n\n\
        ### By Key Type\n\n\
        | Type | Count | Risk |\n\
        |------|-------|------|\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        findings.len(),
        by_repo.len()
    );

    let mut types: Vec<_> = by_type.into_iter().collect();
    types.sort_by(|a, b| b.1.cmp(&a.1));
    for (key_type, count) in types.iter().take(20) {
        let risk = if key_type.contains("live") || key_type.contains("proj") || key_type.contains("aws") {
            "Critical"
        } else if key_type.contains("test") || key_type.contains("env") {
            "High"
        } else {
            "Medium"
        };
        readme.push_str(&format!("| `{}` | {} | {} |\n", key_type, count, risk));
    }

    readme.push_str("\n### Top Affected Repositories\n\n| Repository | Findings |\n|------------|----------|\n");
    let mut repos: Vec<_> = by_repo.into_iter().collect();
    repos.sort_by(|a, b| b.1.cmp(&a.1));
    for (repo, count) in repos.iter().take(10) {
        readme.push_str(&format!("| `{}` | {} |\n", repo, count));
    }

    readme.push_str("\n## Recent High-Entropy Findings\n\n| Repository | File | Type | Entropy | Line |\n|------------|------|------|---------|------|\n");
    for f in findings.iter().filter(|f| f.entropy.unwrap_or(0.0) > 4.0).take(30) {
        readme.push_str(&format!(
            "| `{}` | `{}` | `{}` | {:.2} | {} |\n",
            f.repository,
            f.file_path.split('/').last().unwrap_or(&f.file_path),
            f.key_type,
            f.entropy.unwrap_or(0.0),
            f.line_number.unwrap_or(0)
        ));
    }

    readme.push_str("\n---\n\n*Generated by API Key Scanner v2.0 - Rust Edition*\n\
        *Full keys stored securely in `private_keys/` (gitignored)*\n");
    readme
}

async fn interactive_mode() -> Result<(String, usize, usize, Vec<String>)> {
    cli::interactive_mode().await
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into()))
        .init();

    let cli = Cli::parse();

    // Check if token came from environment (not explicitly provided)
    let raw_args: Vec<String> = env::args().collect();
    let token_from_env = cli.token.is_some()
        && raw_args
            .iter()
            .skip(1)
            .all(|arg| !arg.starts_with("--token") && !arg.starts_with("-t"));

    // If no meaningful CLI arguments were provided, show the interactive launcher.
    // Non-default values like `--max-requests 5` should count as explicit args so
    // git hooks and scripted invocations never fall back to the interactive menu.
    let has_explicit_args = (cli.token.is_some() && !token_from_env)
        || cli.output != PathBuf::from("data")
        || cli.max_requests != 10
        || cli.concurrency != 5
        || cli.use_dorks 
        || cli.full_scan 
        || cli.interactive 
        || cli.view 
        || cli.show_dorks 
        || cli.test_keys 
        || cli.no_tui
        || cli.quick;
    
    if !has_explicit_args {
        return run_interactive_launcher().await;
    }

    // Show dork patterns and exit
    if cli.show_dorks {
        cli::show_dork_patterns();
        return Ok(());
    }

    // Test API keys
    if cli.test_keys {
        let storage = SecureStorage::new();
        let findings = storage.load_private_findings().await?;
        
        if findings.is_empty() {
            info!("No findings to test. Run a scan first.");
            return Ok(());
        }
        
        info!("Testing {} API keys...", findings.len());
        let results = validator::test_findings(&findings).await?;
        validator::display_validation_results_with_findings(&results, &findings);
        
        return Ok(());
    }

    // View findings menu
    if cli.view {
        loop {
            match cli::view_findings_menu().await {
                Ok(_) => {
                    let continue_viewing = Select::new(
                        "Continue?",
                        vec!["View more", "Exit"],
                    ).prompt()?;
                    
                    if continue_viewing == "Exit" {
                        break;
                    }
                }
                Err(e) => {
                    error!("Error: {}", e);
                    break;
                }
            }
        }
        return Ok(());
    }

    let (token, max_requests, concurrency, selected_queries) = if cli.interactive {
        interactive_mode().await?
    } else {
        let token = cli.token.ok_or_else(|| anyhow::anyhow!("GitHub token required"))?;
        (token, cli.max_requests, cli.concurrency, vec![])
    };

    // TUI mode (default) or classic CLI mode
    if !cli.no_tui && !cli.interactive {
        // Setup TUI
        let mut terminal = tui::setup_terminal()?;
        let tui_app = Arc::new(tokio::sync::Mutex::new(tui::TuiApp::new(max_requests)));
        
        {
            let mut app = tui_app.lock().await;
            app.add_log("API Key Scanner v2.0 (Rust Edition)".to_string());
            app.add_log(format!("Budget: {} requests | Concurrency: {}", max_requests, concurrency));
            if cli.use_dorks {
                app.add_log("Using Google Dork patterns".to_string());
            }
            if cli.full_scan {
                app.add_log("Full scan mode enabled".to_string());
            }
        }

        let scanner = Scanner::new(token, max_requests, concurrency)?;
        let queries_opt = if selected_queries.is_empty() { None } else { Some(selected_queries) };
        
        // Spawn scan task
        let tui_app_clone = Arc::clone(&tui_app);
        let scan_handle = tokio::spawn(async move {
            scanner.scan(cli.use_dorks, cli.full_scan, queries_opt, Some(tui_app_clone)).await
        });

        // TUI render loop
        let mut last_tick = std::time::Instant::now();
        let tick_rate = std::time::Duration::from_millis(100);
        
        loop {
            let mut app = tui_app.lock().await;
            terminal.draw(|f| tui::render_tui(f, &app))?;
            
            let timeout = tick_rate.saturating_sub(last_tick.elapsed());
            if tui::handle_events(&mut app, timeout)? || app.should_quit {
                break;
            }
            
            if last_tick.elapsed() >= tick_rate {
                app.tick();
                last_tick = std::time::Instant::now();
            }
            
            drop(app);
            
            // Check if scan is complete
            if scan_handle.is_finished() {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                break;
            }
        }

        tui::restore_terminal(terminal)?;
        
        let findings = scan_handle.await??;
        
        let storage = SecureStorage::new();
        storage.save_findings(&findings).await?;

        let public_findings: Vec<PublicFinding> = findings.iter().map(|f| f.into()).collect();
        let readme = generate_readme(&public_findings);
        
        // Generate timestamp for filenames
        let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let readme_filename = format!("scan_report_{}.md", timestamp);
        fs::write(&readme_filename, readme).await?;

        info!("Scan complete. New findings: {}", findings.len());
        info!("Public data: data/latest.json");
        info!("Scan report: {}", readme_filename);
        info!("Private keys: private_keys/full_keys.json (gitignored)");
    } else {
        // Classic CLI mode
        info!("API Key Scanner v2.0 (Rust Edition)");
        info!("Budget: {} requests | Concurrency: {}", max_requests, concurrency);
        if cli.use_dorks {
            info!("Using Google Dork patterns");
        }
        if cli.full_scan {
            info!("Full scan mode enabled");
        }

        let scanner = Scanner::new(token, max_requests, concurrency)?;
        let queries_opt = if selected_queries.is_empty() { None } else { Some(selected_queries) };
        let findings = scanner.scan(cli.use_dorks, cli.full_scan, queries_opt, None).await?;

        let storage = SecureStorage::new();
        storage.save_findings(&findings).await?;

        let public_findings: Vec<PublicFinding> = findings.iter().map(|f| f.into()).collect();
        let readme = generate_readme(&public_findings);
        
        // Generate timestamp for filenames
        let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
        let readme_filename = format!("scan_report_{}.md", timestamp);
        fs::write(&readme_filename, readme).await?;

        info!("Scan complete. New findings: {}", findings.len());
        info!("Public data: data/latest.json");
        info!("Scan report: {}", readme_filename);
        info!("Private keys: private_keys/full_keys.json (gitignored)");
    }

    Ok(())
}

async fn run_interactive_launcher() -> Result<()> {
    loop {
        let choice = launcher::display_quick_start_menu()?;
        
        match choice.as_str() {
            s if s.starts_with("Quick Scan") => {
                // Quick Scan
                println!("\nStarting quick scan with defaults...\n");
                
                let token = std::env::var("GITHUB_TOKEN")
                    .or_else(|_| inquire::Password::new("GitHub Token:")
                        .with_display_mode(inquire::PasswordDisplayMode::Masked)
                        .prompt())?;
                
                return run_scan_with_tui(token, 10, 5, false, false, vec![], false).await;
            }
            s if s.starts_with("Configure & Scan") => {
                // Configure & Scan
                let launch_config = launcher::launch_interactive_tui().await?;
                let (use_dorks, full_scan) = launch_config.scanner_config.scan_mode.to_flags();
                
                return run_scan_with_tui(
                    launch_config.token,
                    launch_config.scanner_config.max_requests,
                    launch_config.scanner_config.concurrency,
                    use_dorks,
                    full_scan,
                    launch_config.scanner_config.custom_queries,
                    launch_config.scanner_config.enable_validation,
                ).await;
            }
            s if s.starts_with("View Previous Findings") => {
                // View Findings
                loop {
                    match cli::view_findings_menu().await {
                        Ok(_) => {
                            let continue_viewing = Select::new(
                                "Continue?",
                                vec!["View more", "Back to menu"],
                            ).prompt()?;
                            
                            if continue_viewing == "Back to menu" {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error: {}", e);
                            break;
                        }
                    }
                }
            }
            s if s.starts_with("Test Saved API Keys") => {
                // Test Keys
                let storage = SecureStorage::new();
                let findings = storage.load_private_findings().await?;
                
                if findings.is_empty() {
                    println!("\nNo findings to test. Run a scan first.\n");
                    inquire::Confirm::new("Press Enter to continue")
                        .with_default(true)
                        .prompt()?;
                } else {
                    println!("\nTesting {} API keys...\n", findings.len());
                    let results = validator::test_findings(&findings).await?;
                    validator::display_validation_results_with_findings(&results, &findings);
                    
                    inquire::Confirm::new("Press Enter to continue")
                        .with_default(true)
                        .prompt()?;
                }
            }
            s if s.starts_with("Show Google Dork Patterns") => {
                // Show Dorks
                cli::show_dork_patterns();
                inquire::Confirm::new("Press Enter to continue")
                    .with_default(true)
                    .prompt()?;
            }
            _ => {
                // Exit
                println!("\nGoodbye.\n");
                return Ok(());
            }
        }
    }
}

async fn run_scan_with_tui(
    token: String,
    max_requests: usize,
    concurrency: usize,
    use_dorks: bool,
    full_scan: bool,
    selected_queries: Vec<String>,
    enable_validation: bool,
) -> Result<()> {
    // Setup TUI
    let mut terminal = tui::setup_terminal()?;
    let tui_app = Arc::new(tokio::sync::Mutex::new(tui::TuiApp::new(max_requests)));
    
    {
        let mut app = tui_app.lock().await;
        app.add_log("API Key Scanner v2.0 (Rust Edition)".to_string());
        app.add_log(format!("Budget: {} requests | Concurrency: {}", max_requests, concurrency));
        if use_dorks {
            app.add_log("Using Google Dork patterns".to_string());
        }
        if full_scan {
            app.add_log("Full scan mode enabled".to_string());
        }
    }

    let scanner = Scanner::new(token, max_requests, concurrency)?;
    let queries_opt = if selected_queries.is_empty() { None } else { Some(selected_queries) };
    
    // Spawn scan task
    let tui_app_clone = Arc::clone(&tui_app);
    let scan_handle = tokio::spawn(async move {
        scanner.scan(use_dorks, full_scan, queries_opt, Some(tui_app_clone)).await
    });

    // TUI render loop
    let mut last_tick = std::time::Instant::now();
    let tick_rate = std::time::Duration::from_millis(100);
    
    loop {
        let mut app = tui_app.lock().await;
        terminal.draw(|f| tui::render_tui(f, &app))?;
        
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if tui::handle_events(&mut app, timeout)? || app.should_quit {
            break;
        }
        
        if last_tick.elapsed() >= tick_rate {
            app.tick();
            last_tick = std::time::Instant::now();
        }
        
        drop(app);
        
        // Check if scan is complete
        if scan_handle.is_finished() {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            break;
        }
    }

    tui::restore_terminal(terminal)?;
    
    let findings = scan_handle.await??;
    
    let storage = SecureStorage::new();
    storage.save_findings(&findings).await?;

    let public_findings: Vec<PublicFinding> = findings.iter().map(|f| f.into()).collect();
    let readme = generate_readme(&public_findings);
    
    // Generate timestamp for filenames
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let readme_filename = format!("scan_report_{}.md", timestamp);
    fs::write(&readme_filename, readme).await?;

    info!("Scan complete. New findings: {}", findings.len());
    info!("Public data: data/latest.json");
    info!("Scan report: {}", readme_filename);
    info!("Private keys: private_keys/full_keys.json (gitignored)");

    if enable_validation && !findings.is_empty() {
        info!("Starting API key validation...");
        let results = validator::test_findings(&findings).await?;
        validator::display_validation_results_with_findings(&results, &findings);
    }

    Ok(())
}
