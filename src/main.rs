mod dorks;
mod storage;
mod cli;
mod validator;
mod tui;
mod launcher;
mod config;
mod patterns;
mod gpu_filter;

use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use futures::stream::{self, StreamExt};
use inquire::Select;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use storage::{PrivateFinding, PublicFinding, SecureStorage};
use patterns::API_KEY_PATTERNS;
use gpu_filter::GpuFilter;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "api-key-scanner")]
#[command(about = "Fast GitHub API key scanner with interactive TUI")]
struct Cli {
    #[arg(short, long, env = "GITHUB_TOKEN")]
    token: Option<String>,

    #[arg(short, long, default_value = "data")]
    output: PathBuf,

    #[arg(long, default_value = "200")]
    max_requests: usize,

    #[arg(long, default_value = "5")]
    concurrency: usize,

    #[arg(long)]
    max_minutes: Option<u64>,

    #[arg(long, default_value = "30")]
    max_repos_per_query: usize,

    /// Cap on total repos scanned across the whole run. Omit to scan all found.
    #[arg(long)]
    max_total_repos: Option<usize>,

    #[arg(long, default_value = "1")]
    query_loops: usize,

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

// ---------------------------------------------------------------------------
// False-positive filtering
// ---------------------------------------------------------------------------

/// Lightweight false-positive classifier that operates on borrowed slices.
/// No heap allocations except for the one-time regex compilation (cached via
/// `std::sync::LazyLock`).
struct FalsePositiveFilter;

impl FalsePositiveFilter {
    /// Returns `true` if the captured `key` should be discarded.
    fn is_false_positive(key: &str, line: &str, label: &str) -> bool {
        let kl = key.to_ascii_lowercase();
        let ll = line.to_ascii_lowercase();

        // UUID/GUID — only skip when not an explicitly UUID-shaped service.
        if !label.contains("heroku") && !label.contains("pinecone") {
            if Self::looks_like_uuid(key) {
                return true;
            }
        }

        if Self::is_placeholder(&kl) {
            return true;
        }

        if Self::has_benign_context(&ll) {
            return true;
        }

        // Too short to be a real key (URL and private-key patterns are exempt).
        let is_special = label.contains("url") || label.contains("private-key");
        if !is_special && key.len() < 10 {
            return true;
        }

        // Low Shannon entropy.
        if !is_special && calculate_entropy(key) < 3.5 {
            return true;
        }

        false
    }

    fn looks_like_uuid(key: &str) -> bool {
        static UUID_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
            )
            .expect("UUID regex is valid")
        });
        UUID_RE.is_match(key)
    }

    fn is_placeholder(kl: &str) -> bool {
        const PLACEHOLDERS: &[&str] = &[
            "example", "your_", "xxx", "***", "replace", "placeholder",
            "dummy", "fake", "test123", "sample", "changeme", "todo",
            "insert_key", "<api_key>",
        ];
        const EXACT: &[&str] = &[
            "0000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111",
        ];

        PLACEHOLDERS.iter().any(|p| kl.contains(p)) || EXACT.contains(&kl.as_ref())
    }

    fn has_benign_context(ll: &str) -> bool {
        const BENIGN: &[&str] = &[
            "public_key", "public_token", "api_version", "client_version",
            "secret_name", "key_name", "token_name", "client_name",
            "api_id", "key_id", "primary_key", "foreign_key",
            "natural_key", "bucket_key", "schema_key", "sequence_key",
            "monkey", "donkey", "keyboard", "keystone",
            "rapid", "capital", "author", "accessor",
            "key_up", "key_down", "key_left", "key_right",
            "key_code", "key_frame", "key_alias", "key_ring",
            "keystore", "key_vault_id", "key_vault_name", "issuerkeyhash",
        ];
        BENIGN.iter().any(|b| ll.contains(b))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Shannon entropy of a string.
fn calculate_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 128];
    let mut valid = 0usize;
    for b in s.bytes() {
        if (b as usize) < 128 {
            freq[b as usize] += 1;
            valid += 1;
        }
    }
    if valid == 0 {
        return 0.0;
    }
    let len = valid as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .fold(0.0, |acc, &c| {
            let p = c as f64 / len;
            acc - p * p.log2()
        })
}

/// Extract the last non-empty capture group, falling back to the full match.
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
    body.chars()
        .take(180)
        .collect::<String>()
        .replace('\n', " ")
        .replace('\r', " ")
}

fn strip_xml_tags(input: &str) -> String {
    static TAG_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"<[^>]+>").expect("xml tag regex is valid")
    });
    TAG_RE.replace_all(input, " ").into_owned()
}

fn extract_docx_text(bytes: &[u8]) -> String {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return String::new();
    };
    let parts = [
        "word/document.xml",
        "word/header1.xml",
        "word/header2.xml",
        "word/footer1.xml",
        "word/footer2.xml",
    ];
    parts.iter().fold(String::new(), |mut out, &name| {
        let Ok(mut file) = archive.by_name(name) else { return out };
        let mut xml = String::new();
        if file.read_to_string(&mut xml).is_ok() {
            out.push_str(&strip_xml_tags(&xml));
            out.push('\n');
        }
        out
    })
}

fn extract_pdf_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_ascii_graphic() || c.is_whitespace() { c } else { ' ' })
        .collect()
}

fn decode_content(path: &str, bytes: &[u8]) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".docx") {
        return extract_docx_text(bytes);
    }
    if lower.ends_with(".pdf") {
        return extract_pdf_text(bytes);
    }
    String::from_utf8(bytes.to_vec())
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Tarball scanning (CPU-bound — runs on the blocking thread pool)
// ---------------------------------------------------------------------------

const MAX_FILE_BYTES: u64 = 1_000_000;

static SKIP_EXTS: &[&str] = &[".png", ".jpg", ".gif", ".zip"];

fn extract_and_scan_tarball(
    bytes: Vec<u8>,
    repo_name: String,
    query_label: String,
    filter: &GpuFilter,
) -> Result<Vec<PrivateFinding>> {
    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);

    // Collect all scannable file contents first so rayon can parallelise them.
    let mut files: Vec<(String, String)> = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        if entry.size() > MAX_FILE_BYTES {
            continue;
        }

        let path = entry.path()?.to_string_lossy().to_string();
        if SKIP_EXTS.iter().any(|ext| path.ends_with(ext)) {
            continue;
        }

        let mut raw = Vec::new();
        if entry.read_to_end(&mut raw).is_err() {
            continue;
        }

        // GPU/SIMD pre-filter: skip files with no keyword hits at all.
        if !filter.has_any_keyword(&raw) {
            continue;
        }

        let content = decode_content(&path, &raw);
        if content.trim().is_empty() {
            continue;
        }
        files.push((path, content));
    }

    // Parallelise the regex scan across files using rayon.
    // Each thread gets its own regex cache via thread_local! inside the
    // regex crate, avoiding the shared-mutex contention described in
    // https://morestina.net/1827/multi-threaded-regex
    let findings: Vec<PrivateFinding> = files
        .par_iter()
        .flat_map(|(path, content)| {
            let mut local_findings: Vec<PrivateFinding> = Vec::new();
            let mut seen_keys: HashSet<String> = HashSet::new();

            for (line_num, line) in content.lines().enumerate() {
                for (pattern, label) in &*API_KEY_PATTERNS {
                    for cap in pattern.captures_iter(line) {
                        let Some(key_str) = extract_secret_match(&cap) else { continue };

                        if FalsePositiveFilter::is_false_positive(key_str, line, label) {
                            continue;
                        }

                        if !seen_keys.insert(key_str.to_string()) {
                            continue;
                        }

                        let entropy = calculate_entropy(key_str);
                        let show = 12.min(key_str.len()).max(8.min(key_str.len()));
                        let preview = format!("{}***", &key_str[..show]);

                        local_findings.push(PrivateFinding {
                            repository: repo_name.clone(),
                            file_path: path.clone(),
                            file_url: format!(
                                "https://github.com/{}/blob/main/{}",
                                repo_name, path
                            ),
                            commit_sha: None,
                            discovered_at: Utc::now().to_rfc3339(),
                            key_type: format!("{}-{}", query_label, label),
                            full_key: key_str.to_string(),
                            key_preview: preview,
                            line_number: Some(line_num + 1),
                            entropy: Some(entropy),
                        });
                    }
                }
            }
            local_findings
        })
        .collect();

    Ok(findings)
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Default queries — highest signal-to-noise queries for a quick run.
fn default_queries() -> Vec<String> {
    vec![
        // OpenAI
        "sk-proj- filename:.env".into(),
        "sk-proj- extension:py".into(),
        "sk-proj- extension:js".into(),
        "sk-proj- extension:ipynb".into(),
        "sk-svcacct- filename:.env".into(),
        "sk-admin- filename:.env".into(),
        "OPENAI_API_KEY extension:env".into(),
        "OPENAI_ADMIN_KEY extension:env".into(),
        "OPENAI_API_KEY extension:csv".into(),
        // Anthropic
        "sk-ant- filename:.env".into(),
        "sk-ant- extension:py".into(),
        "ANTHROPIC_API_KEY extension:env".into(),
        "ANTHROPIC_API_KEY extension:yaml".into(),
        "ANTHROPIC_API_KEY extension:csv".into(),
        "CLAUDE_API_KEY extension:env".into(),
        // 2026 AI providers
        "GROQ_API_KEY extension:env".into(),
        "DEEPSEEK_API_KEY extension:env".into(),
        "GEMINI_API_KEY extension:env".into(),
        "GOOGLE_API_KEY filename:.env".into(),
        // Cloud / infra
        "AWS_ACCESS_KEY_ID extension:env".into(),
        "ghp_ filename:.env".into(),
        "STRIPE_SECRET_KEY extension:env".into(),
        "DATABASE_URL extension:env".into(),
    ]
}

/// Full scan — delegates to the complete dork catalogue (same as --use-dorks).
/// Kept as a named function so ScanMode::FullScan has a distinct code path.
fn full_scan_queries() -> Vec<String> {
    dorks::get_advanced_github_queries()
}

/// The current latest GitHub REST API version (released 2026-03-10).
/// See: <https://github.blog/changelog/2026-03-12-rest-api-version-2026-03-10-is-now-available/>
const GITHUB_API_VERSION: &str = "2026-03-10";

struct Scanner {
    client: reqwest::Client,
    token: String,
    requests_made: Arc<Mutex<usize>>,
    max_requests: usize,
    concurrency: usize,
    semaphore: Arc<Semaphore>,
    started_at: Instant,
    max_duration: Option<Duration>,
    max_repos_per_query: usize,
    max_total_repos: Option<usize>,
    repos_scanned_total: Arc<Mutex<usize>>,
    query_loops: usize,
    /// Shared stop flag — set by the TUI 'q' key via the render loop.
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    /// GPU/SIMD pre-filter — shared across all concurrent repo scans.
    gpu_filter: Arc<GpuFilter>,
}

impl Scanner {
    fn new(
        token: String,
        max_requests: usize,
        concurrency: usize,
        max_duration: Option<Duration>,
        max_repos_per_query: usize,
        max_total_repos: Option<usize>,
        query_loops: usize,
        stop_flag: Arc<std::sync::atomic::AtomicBool>,
        gpu_filter: Arc<GpuFilter>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("APIKeyScanner-Rust/2.2")
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .gzip(true)
            .build()?;

        Ok(Self {
            client,
            token,
            requests_made: Arc::new(Mutex::new(0)),
            max_requests,
            concurrency,
            semaphore: Arc::new(Semaphore::new(concurrency)),
            started_at: Instant::now(),
            max_duration,
            max_repos_per_query,
            max_total_repos,
            repos_scanned_total: Arc::new(Mutex::new(0)),
            query_loops: query_loops.max(1),
            stop_flag,
            gpu_filter,
        })
    }

    #[inline]
    fn within_time_budget(&self) -> bool {
        self.max_duration
            .map_or(true, |limit| self.started_at.elapsed() < limit)
    }

    fn can_continue(&self) -> bool {
        if self.stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        if !self.within_time_budget() {
            return false;
        }
        // Reserve headroom: each remaining query needs at least 1 search
        // request + 1 tarball request, so stop issuing new work when the
        // budget is exhausted rather than mid-batch.
        if *self.requests_made.lock().expect("requests_made mutex poisoned") >= self.max_requests {
            return false;
        }
        if let Some(cap) = self.max_total_repos {
            if *self.repos_scanned_total.lock().expect("repos_scanned_total mutex poisoned") >= cap {
                return false;
            }
        }
        true
    }

    fn increment_repos_scanned(&self) {
        *self.repos_scanned_total.lock().expect("repos_scanned_total mutex poisoned") += 1;
    }

    fn repos_scanned_so_far(&self) -> usize {
        *self.repos_scanned_total.lock().expect("repos_scanned_total mutex poisoned")
    }

    fn increment_requests(&self) {
        *self.requests_made.lock().expect("requests_made mutex poisoned") += 1;
    }

    fn requests_so_far(&self) -> usize {
        *self.requests_made.lock().expect("requests_made mutex poisoned")
    }

    /// Search GitHub code and paginate through ALL result pages (up to
    /// `max_repos_per_query` unique repos). GitHub caps code search at 1 000
    /// total results (10 pages × 100 per page); we stop early once we have
    /// enough unique repos or hit the request budget.
    async fn search_code(&self, query: &str) -> Result<Vec<serde_json::Value>> {
        if !self.can_continue() {
            return Ok(vec![]);
        }

        let mut all_items: Vec<serde_json::Value> = Vec::new();
        let mut page = 1u32;

        loop {
            if !self.can_continue() {
                break;
            }

            let response = tokio::time::timeout(
                Duration::from_secs(30),
                self.client
                    .get("https://api.github.com/search/code")
                    .header("Authorization", format!("Bearer {}", self.token))
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                    .query(&[
                        ("q", query),
                        ("per_page", "100"),
                        ("page", &page.to_string()),
                        ("sort", "indexed"),
                        ("order", "desc"),
                    ])
                    .send(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("GitHub search timed out for query: {}", query))??;

            self.increment_requests();

            let status = response.status();

            // Respect rate-limit headers: back off and retry once.
            if status.as_u16() == 403 || status.as_u16() == 429 {
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(60);
                warn!("Rate limited — waiting {} s before retry", retry_after);
                tokio::time::sleep(Duration::from_secs(retry_after)).await;
                // Retry the same page once; if still limited, skip.
                continue;
            }

            let body = response.text().await?;

            match status.as_u16() {
                401 => return Err(anyhow::anyhow!(
                    "GitHub API authentication failed (401) for query '{}'. \
                     Provide a valid token via --token or GITHUB_TOKEN.",
                    query
                )),
                422 => {
                    warn!("GitHub rejected query '{}': {}", query, response_snippet(&body));
                    break;
                }
                s if s >= 400 => return Err(anyhow::anyhow!(
                    "GitHub search failed for '{}' with HTTP {}: {}",
                    query, status, response_snippet(&body)
                )),
                _ => {}
            }

            let data: serde_json::Value = serde_json::from_str(&body)?;
            let items = data["items"].as_array().cloned().unwrap_or_default();
            let page_len = items.len();
            all_items.extend(items);

            // Stop paginating when: last page was short, no more results, or
            // we already have enough unique repos to fill the per-query cap.
            let unique_repos = all_items
                .iter()
                .filter_map(|i| i["repository"]["full_name"].as_str())
                .collect::<HashSet<_>>()
                .len();

            if page_len < 100
                || unique_repos >= self.max_repos_per_query
                || page >= 10  // GitHub hard cap: 1 000 results
            {
                break;
            }

            page += 1;
            // GitHub recommends ≥1 s between authenticated search requests.
            tokio::time::sleep(Duration::from_millis(1_100)).await;
        }

        Ok(all_items)
    }

    async fn analyze_repo(
        &self,
        repo_name: &str,
        query_label: &str,
    ) -> Result<Vec<PrivateFinding>> {
        let _permit = self.semaphore.acquire().await?;

        if !self.can_continue() {
            return Ok(vec![]);
        }
        self.increment_repos_scanned();

        let url = format!("https://api.github.com/repos/{}/tarball", repo_name);

        let response = tokio::time::timeout(
            Duration::from_secs(60),
            self.client
                .get(&url)
                .header("Authorization", format!("token {}", self.token))
                .send(),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("Tarball download timed out after 60 s for {}", repo_name)
        })??;

        self.increment_requests();

        if !response.status().is_success() {
            return Ok(vec![]);
        }

        let bytes = response.bytes().await?.to_vec();
        let repo_name = repo_name.to_string();
        let query_label = query_label.to_string();
        let filter = Arc::clone(&self.gpu_filter);

        tokio::task::spawn_blocking(move || {
            extract_and_scan_tarball(bytes, repo_name, query_label, &filter)
        })
        .await?
    }

    async fn scan(
        &self,
        use_dorks: bool,
        full_scan: bool,
        selected_queries: Option<Vec<String>>,
        tui_app: Option<Arc<tokio::sync::Mutex<tui::TuiApp>>>,
        validate_every_n_repos: Option<usize>,
        enable_validation: bool,
    ) -> Result<Vec<PrivateFinding>> {
        let queries = selected_queries.unwrap_or_else(|| {
            if use_dorks {
                dorks::get_advanced_github_queries()
            } else if full_scan {
                full_scan_queries()
            } else {
                default_queries()
            }
        });

        if let Some(ref app) = tui_app {
            let mut app = app.lock().await;
            app.total_queries = queries.len() * self.query_loops;
            app.status = "Starting scan...".to_string();
        }

        let mut all_findings: Vec<PrivateFinding> = Vec::new();
        let mut query_counter = 0usize;
        // Track which N-repo boundary we last validated at.
        let mut last_checkpoint_repos = 0usize;

        'outer: for pass in 0..self.query_loops {
            for query in &queries {
                if !self.can_continue() {
                    break 'outer;
                }

                query_counter += 1;

                if let Some(ref app) = tui_app {
                    let mut app = app.lock().await;
                    app.current_query = query_counter;
                    app.status = format!("Searching (pass {}): {}", pass + 1, query);
                    app.add_log(format!(
                        "Query pass {}/{}: {}",
                        pass + 1,
                        self.query_loops,
                        query
                    ));
                    app.update_progress();
                }

                info!("Query pass {}/{}: {}", pass + 1, self.query_loops, query);

                let results = self.search_code(query).await?;

                let repo_count = results.len();
                if let Some(ref app) = tui_app {
                    app.lock().await.add_log(format!("Found {} files", repo_count));
                }
                info!("Found {} files", repo_count);

                // Deduplicate repositories and cap per query.
                let repos: Vec<String> = results
                    .iter()
                    .filter_map(|item| item["repository"]["full_name"].as_str().map(str::to_owned))
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .take(self.max_repos_per_query)
                    .collect();

                if let Some(ref app) = tui_app {
                    let mut app = app.lock().await;
                    app.status = format!("Scanning {} repositories...", repos.len());
                    app.add_log(format!("Scanning {} repos concurrently", repos.len()));
                }
                info!("Scanning {} repos concurrently", repos.len());

                let batch: Vec<_> = stream::iter(repos)
                    .map(|repo| {
                        let scanner = self.clone();
                        let query_label = query.clone();
                        let tui_ref = tui_app.clone();
                        async move {
                            match scanner.analyze_repo(&repo, &query_label).await {
                                Ok(findings) => {
                                    if let Some(ref app) = tui_ref {
                                        let mut app = app.lock().await;
                                        app.repos_scanned = scanner.repos_scanned_so_far();
                                        app.requests_made = scanner.requests_so_far();
                                        if !findings.is_empty() {
                                            app.findings_count += findings.len();
                                            app.high_entropy_count += findings
                                                .iter()
                                                .filter(|f| f.entropy.unwrap_or(0.0) > 4.0)
                                                .count();
                                            app.add_log(format!(
                                                "WARNING: {}: {} key(s) found",
                                                repo,
                                                findings.len()
                                            ));
                                        }
                                    }
                                    if !findings.is_empty() {
                                        warn!(
                                            "WARNING: {}: {} key(s) found",
                                            repo,
                                            findings.len()
                                        );
                                    }
                                    findings
                                }
                                Err(e) => {
                                    if let Some(ref app) = tui_ref {
                                        app.lock().await.add_log(format!("ERROR: {}", repo));
                                    }
                                    error!("Error scanning {}: {}", repo, e);
                                    vec![]
                                }
                            }
                        }
                    })
                    .buffer_unordered(self.concurrency)
                    .collect()
                    .await;

                for repo_findings in batch {
                    all_findings.extend(repo_findings);
                }

                // ── Mid-scan checkpoint: persist + validate every N repos ──
                if let Some(n) = validate_every_n_repos.filter(|&n| n > 0) {
                    let scanned = self.repos_scanned_so_far();
                    let current_checkpoint = scanned / n;
                    if current_checkpoint > last_checkpoint_repos / n {
                        last_checkpoint_repos = scanned;
                        info!("Checkpoint at {} repos — persisting {} finding(s)", scanned, all_findings.len());
                        if let Some(ref app) = tui_app {
                            app.lock().await.add_log(format!(
                                "Checkpoint: {} repos — {} finding(s) persisted",
                                scanned, all_findings.len()
                            ));
                        }
                        persist_and_report(&all_findings).await?;
                        if enable_validation && !all_findings.is_empty() {
                            let results = validator::test_findings(&all_findings).await?;
                            validator::display_validation_results_with_findings(&results, &all_findings);
                        }
                    }
                }
                // ─────────────────────────────────────────────────────────────
            }
        }

        if let Some(ref app) = tui_app {
            let mut app = app.lock().await;
            app.status = "Scan complete!".to_string();
            app.progress = 100.0;
            app.add_log(format!(
                "Scan complete. Total findings: {}",
                all_findings.len()
            ));
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
            concurrency: self.concurrency,
            semaphore: Arc::clone(&self.semaphore),
            started_at: self.started_at,
            max_duration: self.max_duration,
            max_repos_per_query: self.max_repos_per_query,
            max_total_repos: self.max_total_repos,
            repos_scanned_total: Arc::clone(&self.repos_scanned_total),
            query_loops: self.query_loops,
            stop_flag: Arc::clone(&self.stop_flag),
            gpu_filter: Arc::clone(&self.gpu_filter),
        }
    }
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

fn generate_readme(findings: &[PublicFinding]) -> String {
    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut by_repo: HashMap<String, usize> = HashMap::new();

    for f in findings {
        *by_type.entry(f.key_type.clone()).or_insert(0) += 1;
        *by_repo.entry(f.repository.clone()).or_insert(0) += 1;
    }

    let mut out = format!(
        "# API Key Scanner v2.2 - Security Research\n\n\
         **Last Updated**: {}\n\
         **Total Findings**: {}\n\
         **Unique Repositories**: {}\n\n\
         **SECURITY NOTICE**: This is a security research project. \
         Full API keys are NEVER committed to git.\n\
         Only metadata and key previews are stored in this repository.\n\n\
         ## Statistics\n\n\
         ### By Key Type\n\n\
         | Type | Count | Risk |\n\
         |------|-------|------|\n",
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        findings.len(),
        by_repo.len(),
    );

    let mut types: Vec<_> = by_type.into_iter().collect();
    types.sort_by(|a, b| b.1.cmp(&a.1));
    for (key_type, count) in types.iter().take(20) {
        let risk = if key_type.contains("live")
            || key_type.contains("proj")
            || key_type.contains("aws")
        {
            "Critical"
        } else if key_type.contains("test") || key_type.contains("env") {
            "High"
        } else {
            "Medium"
        };
        out.push_str(&format!("| `{}` | {} | {} |\n", key_type, count, risk));
    }

    out.push_str(
        "\n### Top Affected Repositories\n\n\
         | Repository | Findings |\n\
         |------------|----------|\n",
    );
    let mut repos: Vec<_> = by_repo.into_iter().collect();
    repos.sort_by(|a, b| b.1.cmp(&a.1));
    for (repo, count) in repos.iter().take(10) {
        out.push_str(&format!("| `{}` | {} |\n", repo, count));
    }

    out.push_str(
        "\n## Recent High-Entropy Findings\n\n\
         | Repository | File | Type | Entropy | Line |\n\
         |------------|------|------|---------|------|\n",
    );
    for f in findings
        .iter()
        .filter(|f| f.entropy.unwrap_or(0.0) > 4.0)
        .take(30)
    {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | {:.2} | {} |\n",
            f.repository,
            f.file_path.split('/').next_back().unwrap_or(&f.file_path),
            f.key_type,
            f.entropy.unwrap_or(0.0),
            f.line_number.unwrap_or(0),
        ));
    }

    out.push_str(
        "\n---\n\n\
         *Generated by API Key Scanner v2.2 - Rust Edition*\n\
         *Full keys stored securely in `private_keys/` (gitignored)*\n",
    );
    out
}

// ---------------------------------------------------------------------------
// Scan config — shared between TUI and CLI paths
// ---------------------------------------------------------------------------

struct ScanConfig {
    token: String,
    max_requests: usize,
    concurrency: usize,
    use_dorks: bool,
    full_scan: bool,
    selected_queries: Vec<String>,
    enable_validation: bool,
    max_minutes: Option<u64>,
    max_repos_per_query: usize,
    max_total_repos: Option<usize>,
    query_loops: usize,
    validate_every_n_repos: Option<usize>,
    endless_loop: bool,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    gpu_filter: Arc<GpuFilter>,
}

impl ScanConfig {
    fn build_scanner(&self) -> Result<Scanner> {
        Scanner::new(
            self.token.clone(),
            self.max_requests,
            self.concurrency,
            self.max_minutes.map(|m| Duration::from_secs(m * 60)),
            self.max_repos_per_query,
            self.max_total_repos,
            self.query_loops,
            Arc::clone(&self.stop_flag),
            Arc::clone(&self.gpu_filter),
        )
    }

    fn queries_opt(&self) -> Option<Vec<String>> {
        if self.selected_queries.is_empty() {
            None
        } else {
            Some(self.selected_queries.clone())
        }
    }
}

// ---------------------------------------------------------------------------
// TUI scan runner
// ---------------------------------------------------------------------------

async fn run_scan_with_tui(cfg: ScanConfig) -> Result<()> {
    let mut terminal = tui::setup_terminal()?;
    let tui_app = Arc::new(tokio::sync::Mutex::new(tui::TuiApp::new(cfg.max_requests)));
    let stop_flag = Arc::clone(&cfg.stop_flag);

    {
        let mut app = tui_app.lock().await;
        app.add_log("API Key Scanner v2.2 (Rust Edition)".to_string());
        app.add_log(format!(
            "Budget: {} req/pass | Concurrency: {}",
            cfg.max_requests, cfg.concurrency
        ));
        if cfg.endless_loop {
            app.add_log("Endless loop enabled — press 'q' to stop".to_string());
        }
        if let Some(m) = cfg.max_minutes {
            app.add_log(format!("Time budget: {} minute(s)", m));
        }
        if let Some(n) = cfg.validate_every_n_repos {
            app.add_log(format!("Checkpoint: persist+validate every {} repos", n));
        }
    }

    let tick = Duration::from_millis(100);
    let mut last_tick = Instant::now();
    let mut pass = 0usize;
    // Accumulate all findings across endless passes for the final report.
    let mut all_findings: Vec<PrivateFinding> = Vec::new();
    // Track keys already seen so we only validate/report truly new ones.
    let mut seen_keys: HashSet<String> = HashSet::new();

    'endless: loop {
        pass += 1;

        // Build a fresh Scanner each pass so request/repo counters reset.
        let scanner = cfg.build_scanner()?;
        let queries_opt = cfg.queries_opt();
        let (use_dorks, full_scan) = (cfg.use_dorks, cfg.full_scan);
        let validate_every = cfg.validate_every_n_repos;
        let enable_val = cfg.enable_validation;

        {
            let mut app = tui_app.lock().await;
            app.status = format!("Pass {} — starting scan...", pass);
            app.add_log(format!("=== Pass {} ===", pass));
        }

        let tui_app_clone = Arc::clone(&tui_app);
        let scan_handle = tokio::spawn(async move {
            scanner
                .scan(use_dorks, full_scan, queries_opt, Some(tui_app_clone), validate_every, enable_val)
                .await
        });

        // Render loop for this pass.
        loop {
            let (should_stop, do_save) = {
                let mut app = tui_app.lock().await;
                tui::render_tui(&mut terminal, &app);
                let timeout = tick.saturating_sub(last_tick.elapsed());
                tui::handle_events(&mut app, timeout)?;
                if last_tick.elapsed() >= tick {
                    app.tick();
                    last_tick = Instant::now();
                }
                let save = app.save_requested;
                if save { app.save_requested = false; }
                // Wire 'q' stop_requested into the atomic flag so the scanner
                // task sees it immediately via can_continue().
                if app.stop_requested {
                    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                (app.stop_requested, save)
            };

            // Bug fix: 's' saves the live in-memory accumulator, not stale disk snapshot.
            if do_save && !all_findings.is_empty() {
                let _ = persist_and_report(&all_findings).await;
                tui_app.lock().await.add_log(format!("Saved {} finding(s)", all_findings.len()));
            }

            if scan_handle.is_finished() || should_stop {
                break;
            }
        }

        // Wait for the scan task to finish its current batch (graceful stop).
        let pass_findings = scan_handle.await??;

        // Collect only findings whose key we haven't seen before.
        let new_findings: Vec<PrivateFinding> = pass_findings
            .into_iter()
            .filter(|f| seen_keys.insert(f.full_key.clone()))
            .collect();

        let new_count = new_findings.len();
        all_findings.extend(new_findings);

        {
            let mut app = tui_app.lock().await;
            app.add_log(format!("Pass {} done — {} new finding(s)", pass, new_count));
        }

        // Persist + validate after every pass (or on 'q' stop).
        // Bug fix: always persist+validate on stop regardless of enable_validation flag —
        // 'q' explicitly promises "saving & validating" in the TUI log message.
        let user_stopped = tui_app.lock().await.stop_requested;
        if !all_findings.is_empty() {
            persist_and_report(&all_findings).await?;
            if (cfg.enable_validation || user_stopped) && new_count > 0 {
                tui_app.lock().await.add_log(format!("Validating {} key(s)...", all_findings.len()));
                let results = validator::test_findings(&all_findings).await?;
                validator::display_validation_results_with_findings(&results, &all_findings);
            }
        }

        // Stop conditions (user_stopped already read above).
        if !cfg.endless_loop || user_stopped {
            break 'endless;
        }
        if new_count == 0 {
            tui_app.lock().await.add_log(
                "No new findings this pass — stopping endless loop".to_string()
            );
            break 'endless;
        }

        // Brief pause between passes to avoid hammering the API.
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    tui::restore_terminal(terminal)?;
    Ok(())
}

/// Persist findings to disk and write a timestamped scan report.
async fn persist_and_report(findings: &[PrivateFinding]) -> Result<()> {
    let storage = SecureStorage::new();
    storage.save_findings(findings).await?;

    let public: Vec<PublicFinding> = findings.iter().map(|f| f.into()).collect();
    let readme = generate_readme(&public);
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let filename = format!("scan_report_{}.md", timestamp);
    fs::write(&filename, readme).await?;

    info!("Scan complete. New findings: {}", findings.len());
    info!("Public data:    data/latest.json");
    info!("Scan report:    {}", filename);
    info!("Private keys:   private_keys/full_keys.json  (gitignored)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Interactive launcher
// ---------------------------------------------------------------------------

async fn run_interactive_launcher(gpu_filter: Arc<GpuFilter>) -> Result<()> {
    loop {
        let choice = launcher::display_quick_start_menu()?;

        match choice.as_str() {
            s if s.starts_with("Quick Scan") => {
                println!("\nStarting quick scan with defaults...\n");
                let token = std::env::var("GITHUB_TOKEN").or_else(|_| {
                    inquire::Password::new("GitHub Token:")
                        .with_display_mode(inquire::PasswordDisplayMode::Masked)
                        .prompt()
                })?;
                return run_scan_with_tui(ScanConfig {
                    token,
                    max_requests: 200,
                    concurrency: 5,
                    use_dorks: false,
                    full_scan: false,
                    selected_queries: vec![],
                    enable_validation: false,
                    max_minutes: None,
                    max_repos_per_query: 30,
                    max_total_repos: None,
                    query_loops: 1,
                    validate_every_n_repos: None,
                    endless_loop: false,
                    stop_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    gpu_filter: Arc::clone(&gpu_filter),
                })
                .await;
            }

            s if s.starts_with("Configure & Scan") => {
                let lc = launcher::launch_interactive_tui().await?;
                let (use_dorks, full_scan) = lc.scanner_config.scan_mode.to_flags();
                return run_scan_with_tui(ScanConfig {
                    token: lc.token,
                    max_requests: lc.scanner_config.max_requests,
                    concurrency: lc.scanner_config.concurrency,
                    use_dorks,
                    full_scan,
                    selected_queries: lc.scanner_config.custom_queries,
                    enable_validation: lc.scanner_config.enable_validation,
                    max_minutes: lc.scanner_config.max_minutes,
                    max_repos_per_query: lc.scanner_config.max_repos_per_query,
                    max_total_repos: lc.scanner_config.max_total_repos,
                    query_loops: lc.scanner_config.query_loops,
                    validate_every_n_repos: lc.scanner_config.validate_every_n_repos,
                    endless_loop: lc.scanner_config.endless_loop,
                    stop_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    gpu_filter: Arc::clone(&gpu_filter),
                })
                .await;
            }

            s if s.starts_with("View Previous Findings") => loop {
                match cli::view_findings_menu().await {
                    Ok(_) => {
                        let ans = Select::new("Continue?", vec!["View more", "Back to menu"])
                            .prompt()?;
                        if ans == "Back to menu" {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error: {}", e);
                        break;
                    }
                }
            },

            s if s.starts_with("Test Saved API Keys") => {
                let storage = SecureStorage::new();
                let findings = storage.load_private_findings().await?;
                if findings.is_empty() {
                    println!("\nNo findings to test. Run a scan first.\n");
                } else {
                    println!("\nTesting {} API key(s)...\n", findings.len());
                    let results = validator::test_findings(&findings).await?;
                    validator::display_validation_results_with_findings(&results, &findings);
                }
                inquire::Confirm::new("Press Enter to continue")
                    .with_default(true)
                    .prompt()?;
            }

            s if s.starts_with("Show Google Dork Patterns") => {
                cli::show_dork_patterns();
                inquire::Confirm::new("Press Enter to continue")
                    .with_default(true)
                    .prompt()?;
            }

            _ => {
                println!("\nGoodbye.\n");
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // Initialise the SIMD pre-filter once at startup.
    let gpu_filter = Arc::new(GpuFilter::init().await.unwrap_or_else(|e| {
        tracing::warn!("Pre-filter init failed ({}), retrying CPU-only", e);
        futures::executor::block_on(GpuFilter::init_cpu_only())
            .expect("CPU-only filter must always succeed")
    }));
    info!("SIMD pre-filter ready ({} literals)", 90);

    let cli = Cli::parse();

    // Detect whether the token came from the environment rather than an
    // explicit --token flag (so scripted invocations keep working).
    let raw_args: Vec<String> = env::args().collect();
    let token_from_env = cli.token.is_some()
        && raw_args
            .iter()
            .skip(1)
            .all(|a| !a.starts_with("--token") && !a.starts_with("-t"));

    let has_explicit_args = (cli.token.is_some() && !token_from_env)
        || cli.output != PathBuf::from("data")
        || cli.max_requests != 200
        || cli.concurrency != 5
        || cli.max_minutes.is_some()
        || cli.max_repos_per_query != 30
        || cli.query_loops != 1
        || cli.use_dorks
        || cli.full_scan
        || cli.interactive
        || cli.view
        || cli.show_dorks
        || cli.test_keys
        || cli.no_tui
        || cli.quick;

    if !has_explicit_args {
        return run_interactive_launcher(Arc::clone(&gpu_filter)).await;
    }

    // ---- Non-scan sub-commands ----

    if cli.show_dorks {
        cli::show_dork_patterns();
        return Ok(());
    }

    if cli.test_keys {
        let storage = SecureStorage::new();
        let findings = storage.load_private_findings().await?;
        if findings.is_empty() {
            info!("No findings to test. Run a scan first.");
            return Ok(());
        }
        info!("Testing {} API key(s)...", findings.len());
        let results = validator::test_findings(&findings).await?;
        validator::display_validation_results_with_findings(&results, &findings);
        return Ok(());
    }

    if cli.view {
        loop {
            match cli::view_findings_menu().await {
                Ok(_) => {
                    if Select::new("Continue?", vec!["View more", "Exit"]).prompt()? == "Exit" {
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

    // ---- Scan sub-commands ----

    let (token, max_requests, concurrency, selected_queries) = if cli.interactive {
        cli::interactive_mode().await?
    } else {
        let token = cli.token.ok_or_else(|| anyhow::anyhow!("GitHub token required"))?;
        (token, cli.max_requests, cli.concurrency, vec![])
    };

    let cfg = ScanConfig {
        token,
        max_requests,
        concurrency,
        use_dorks: cli.use_dorks,
        full_scan: cli.full_scan,
        selected_queries,
        enable_validation: false,
        max_minutes: cli.max_minutes,
        max_repos_per_query: cli.max_repos_per_query,
        max_total_repos: cli.max_total_repos,
        query_loops: cli.query_loops,
        validate_every_n_repos: None,
        endless_loop: false,
        stop_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        gpu_filter,
    };

    if cli.no_tui || cli.interactive {
        info!("API Key Scanner v2.2 (Rust Edition)");
        info!("Budget: {} req/pass | Concurrency: {}", cfg.max_requests, cfg.concurrency);
        if cfg.endless_loop { info!("Endless loop enabled — Ctrl-C to stop"); }

        let mut all_findings: Vec<PrivateFinding> = Vec::new();
        let mut seen_keys: HashSet<String> = HashSet::new();
        let mut pass = 0usize;

        loop {
            pass += 1;
            info!("=== Pass {} ===", pass);

            let scanner = cfg.build_scanner()?;
            let queries_opt = cfg.queries_opt();
            let pass_findings = scanner
                .scan(cfg.use_dorks, cfg.full_scan, queries_opt, None, cfg.validate_every_n_repos, cfg.enable_validation)
                .await?;

            let new_findings: Vec<PrivateFinding> = pass_findings
                .into_iter()
                .filter(|f| seen_keys.insert(f.full_key.clone()))
                .collect();

            let new_count = new_findings.len();
            info!("Pass {} done — {} new finding(s)", pass, new_count);
            all_findings.extend(new_findings);

            if !all_findings.is_empty() {
                persist_and_report(&all_findings).await?;
                if cfg.enable_validation && new_count > 0 {
                    let results = validator::test_findings(&all_findings).await?;
                    validator::display_validation_results_with_findings(&results, &all_findings);
                }
            }

            if !cfg.endless_loop { break; }
            if new_count == 0 {
                info!("No new findings — stopping endless loop");
                break;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    } else {
        run_scan_with_tui(cfg).await?;
    }

    Ok(())
}