use anyhow::Result;
use inquire::{Confirm, CustomType, MultiSelect, Password, Select, Text};
use crate::config::{ScannerConfig, ScanMode};

#[derive(Debug, Clone)]
pub struct LaunchConfig {
    pub token: String,
    pub scanner_config: ScannerConfig,
}

pub async fn launch_interactive_tui() -> Result<LaunchConfig> {
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║                                                           ║");
    println!("║        API Key Scanner v2.0 - Configuration              ║");
    println!("║                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    // Check if config exists
    let existing_config = if ScannerConfig::exists().await {
        let load = Confirm::new("Found existing config. Load it?")
            .with_default(true)
            .prompt()?;
        
        if load {
            Some(ScannerConfig::load().await?)
        } else {
            None
        }
    } else {
        None
    };

    let mut config = existing_config.unwrap_or_default();

    // Step 1: GitHub Token
    let token = get_github_token(config.github_token.as_deref())?;
    config.github_token = Some(token.clone());

    // Step 2: Scan Configuration
    let (max_requests, concurrency) = get_scan_limits(config.max_requests, config.concurrency)?;
    config.max_requests = max_requests;
    config.concurrency = concurrency;

    // Step 3: Output Path
    let output_path = get_output_path(&config.output_path)?;
    config.output_path = output_path;

    // Step 4: Scan Mode
    let scan_mode = get_scan_mode(&config.scan_mode)?;
    config.scan_mode = scan_mode.clone();

    // Step 5: Custom Queries (if selected)
    if scan_mode == ScanMode::CustomQueries {
        let selected_queries = get_custom_queries(&config.custom_queries)?;
        config.custom_queries = selected_queries;
    }

    // Step 6: Validation
    let enable_validation = get_validation_option(config.enable_validation)?;
    config.enable_validation = enable_validation;

    // Step 7: Save config
    let save_config = Confirm::new("Save this configuration for future use?")
        .with_default(true)
        .prompt()?;
    
    if save_config {
        config.save().await?;
        println!("Configuration saved to scanner-config.toml\n");
    }

    // Step 8: Confirmation
    display_config_summary(&config)?;

    let confirm = Confirm::new("Start scan with these settings?")
        .with_default(true)
        .prompt()?;

    if !confirm {
        return Err(anyhow::anyhow!("Scan cancelled by user"));
    }

    Ok(LaunchConfig {
        token,
        scanner_config: config,
    })
}

fn get_github_token(saved_token: Option<&str>) -> Result<String> {
    println!("Step 1/6: GitHub Authentication\n");
    
    let has_token = Confirm::new("Do you have a GitHub Personal Access Token?")
        .with_default(true)
        .with_help_message("Required for GitHub API access. Get one at: https://github.com/settings/tokens")
        .prompt()?;

    if !has_token {
        println!("\nYou need a GitHub token to use this scanner.");
        println!("   1. Go to: https://github.com/settings/tokens");
        println!("   2. Generate a new token (classic)");
        println!("   3. Select scopes: 'repo' (for private repos) or 'public_repo' (for public only)");
        println!("   4. Copy the token and paste it here\n");
    }

    if let Some(saved) = saved_token.filter(|token| !token.trim().is_empty()) {
        let reuse = Confirm::new("Reuse saved GitHub token from scanner-config.toml?")
            .with_default(true)
            .prompt()?;

        if reuse {
            println!("Saved token loaded\n");
            return Ok(saved.to_string());
        }
    }

    let token = Password::new("GitHub Token:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .with_help_message("Saved to scanner-config.toml only if you choose to save this configuration")
        .prompt()?;

    if token.is_empty() {
        return Err(anyhow::anyhow!("Token cannot be empty"));
    }

    println!("Token configured\n");
    Ok(token)
}

fn get_scan_limits(default_requests: usize, default_concurrency: usize) -> Result<(usize, usize)> {
    println!("Step 2/6: Scan Limits\n");

    let max_requests = CustomType::<usize>::new("Max API requests:")
        .with_default(default_requests)
        .with_help_message("GitHub API rate limit: 30 req/min authenticated, 10 req/min unauthenticated")
        .with_error_message("Please enter a valid number")
        .prompt()?;

    let concurrency = CustomType::<usize>::new("Concurrent repository scans:")
        .with_default(default_concurrency)
        .with_help_message("Higher = faster but more memory usage. Recommended: 3-10")
        .with_error_message("Please enter a valid number")
        .prompt()?;

    println!("Limits configured: {} requests, {} concurrent scans\n", max_requests, concurrency);
    Ok((max_requests, concurrency))
}

fn get_output_path(default_path: &str) -> Result<String> {
    println!("Step 3/6: Output Configuration\n");

    let use_default = Confirm::new("Use default output path (./data)?")
        .with_default(true)
        .prompt()?;

    let path = if use_default {
        default_path.to_string()
    } else {
        Text::new("Output directory:")
            .with_default(default_path)
            .with_help_message("Directory where findings will be saved")
            .prompt()?
    };

    println!("Output path: {}\n", path);
    Ok(path)
}

fn get_scan_mode(default_mode: &ScanMode) -> Result<ScanMode> {
    println!("Step 4/6: Scan Mode\n");

    let modes = vec![
        "Time-slotted (1 query, fast, recommended for frequent scans)",
        "Full scan (10 queries, comprehensive, ~5-10 minutes)",
        "Google Dorks (advanced patterns, thorough, ~10-20 minutes)",
        "Custom queries (select specific patterns)",
    ];

    let default_idx = match default_mode {
        ScanMode::TimeSlotted => 0,
        ScanMode::FullScan => 1,
        ScanMode::GoogleDorks => 2,
        ScanMode::CustomQueries => 3,
    };

    let selected = Select::new("Select scan mode:", modes)
        .with_starting_cursor(default_idx)
        .with_help_message("Use ↑↓ to navigate, Enter to select")
        .prompt()?;

    let mode = match selected {
        s if s.starts_with("Time-slotted") => ScanMode::TimeSlotted,
        s if s.starts_with("Full scan") => ScanMode::FullScan,
        s if s.starts_with("Google Dorks") => ScanMode::GoogleDorks,
        s if s.starts_with("Custom queries") => ScanMode::CustomQueries,
        _ => ScanMode::TimeSlotted,
    };

    println!("Mode selected: {:?}\n", mode);
    Ok(mode)
}

fn get_custom_queries(default_queries: &[String]) -> Result<Vec<String>> {
    println!("Custom Query Selection\n");

    let available_queries = vec![
        // AI/ML Providers
        ("OpenAI (sk-proj-)", "sk-proj- filename:.env"),
        ("OpenAI service account", "sk-svcacct- filename:.env"),
        ("OpenAI admin", "sk-admin- filename:.env"),
        ("OpenAI (Python)", "sk-proj- extension:py"),
        ("OpenAI (JavaScript)", "sk-proj- extension:js"),
        ("ChatGPT/OpenAI ENV", "CHATGPT_API_KEY extension:env"),
        ("Codex ENV", "CODEX_API_KEY extension:env"),
        ("Anthropic (Claude)", "sk-ant- extension:py"),
        ("Anthropic ENV", "ANTHROPIC_API_KEY extension:env"),
        ("Claude ENV", "CLAUDE_API_KEY extension:env"),
        ("OpenAI ENV", "OPENAI_API_KEY extension:env"),
        ("Google/Gemini ENV", "GOOGLE_API_KEY extension:env"),
        ("xAI (Grok)", "xai- extension:env"),
        ("Groq", "gsk_ extension:env"),
        ("Groq ENV", "GROQ_API_KEY extension:env"),
        ("DeepSeek", "DEEPSEEK_API_KEY extension:env"),
        ("Mistral", "MISTRAL_API_KEY extension:env"),
        ("Cohere", "COHERE_API_KEY extension:env"),
        ("Hugging Face", "HF_TOKEN extension:env"),
        ("Replicate", "REPLICATE_API_TOKEN extension:env"),
        ("Perplexity", "PPLX_API_KEY extension:env"),
        ("Together AI", "TOGETHER_API_KEY extension:env"),
        
        // Cloud Providers
        ("AWS Access Keys", "AKIA extension:env"),
        ("AWS Secrets", "AWS_SECRET_ACCESS_KEY extension:env"),
        ("Azure Keys", "AZURE extension:env"),
        ("Google Cloud", "GOOGLE_APPLICATION_CREDENTIALS extension:json"),
        
        // Development Tools
        ("GitHub Tokens", "ghp_ extension:env"),
        ("GitLab Tokens", "glpat- extension:env"),
        ("Vercel Tokens", "VERCEL_TOKEN extension:env"),
        ("Supabase Keys", "SUPABASE_KEY extension:env"),
        
        // Payment & APIs
        ("Stripe Live Keys", "sk_live_ extension:env"),
        ("Stripe Test Keys", "sk_test_ extension:env"),
        ("SendGrid Keys", "SG. extension:env"),
        ("Twilio Keys", "SK extension:env"),
        
        // Databases
        ("MongoDB URLs", "mongodb:// extension:env"),
        ("PostgreSQL URLs", "postgres:// extension:env"),
        ("MySQL URLs", "mysql:// extension:env"),
        ("Redis URLs", "redis:// extension:env"),
        
        // Private Keys
        ("SSH Private Keys", "BEGIN PRIVATE KEY extension:pem"),
        ("PGP Private Keys", "BEGIN PGP PRIVATE KEY"),
        ("JWT Secrets", "JWT_SECRET extension:env"),
    ];

    let options: Vec<String> = available_queries
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();

    let selected = MultiSelect::new("Select queries to run:", options)
        .with_help_message("Use Space to select, Enter to confirm. Select at least 1 query.")
        .prompt()?;

    if selected.is_empty() && default_queries.is_empty() {
        return Err(anyhow::anyhow!("At least one query must be selected"));
    }

    if selected.is_empty() {
        println!("Using {} saved queries\n", default_queries.len());
        return Ok(default_queries.to_vec());
    }

    let queries: Vec<String> = selected
        .iter()
        .filter_map(|name| {
            available_queries
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, query)| query.to_string())
        })
        .collect();

    println!("Selected {} queries\n", queries.len());
    Ok(queries)
}

fn get_validation_option(default_enabled: bool) -> Result<bool> {
    println!("Step 5/6: API Key Validation\n");

    let enable = Confirm::new("Enable live API key validation after scan?")
        .with_default(default_enabled)
        .with_help_message("Tests found keys against real APIs (may trigger alerts)")
        .prompt()?;

    if enable {
        println!("Warning: Live validation will test keys against real APIs");
        println!("   This may trigger security alerts for key owners\n");
        
        let confirm = Confirm::new("Are you sure you want to enable validation?")
            .with_default(false)
            .prompt()?;
        
        if confirm {
            println!("Validation enabled\n");
            Ok(true)
        } else {
            println!("Validation disabled\n");
            Ok(false)
        }
    } else {
        println!("Validation disabled\n");
        Ok(false)
    }
}

fn display_config_summary(config: &ScannerConfig) -> Result<()> {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                                                           ║");
    println!("║                  Configuration Summary                    ║");
    println!("║                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    println!("GitHub Token:        {}", if config.github_token.as_deref().is_some_and(|token| !token.trim().is_empty()) { "<saved>" } else { "<not saved>" });
    println!("Max Requests:        {}", config.max_requests);
    println!("Concurrency:         {}", config.concurrency);
    println!("Output Path:         {}", config.output_path);
    println!("Scan Mode:           {}", config.scan_mode.description());
    
    if !config.custom_queries.is_empty() {
        println!("Custom Queries:      {} selected", config.custom_queries.len());
    }
    
    println!("Validation:          {}", if config.enable_validation { "Enabled" } else { "Disabled" });
    
    println!("\nEstimated Time:");
    let estimated_time = match config.scan_mode {
        ScanMode::TimeSlotted => "~1-2 minutes",
        ScanMode::FullScan => "~5-10 minutes",
        ScanMode::GoogleDorks => "~10-20 minutes",
        ScanMode::CustomQueries => {
            if config.custom_queries.len() <= 3 {
                "~2-5 minutes"
            } else if config.custom_queries.len() <= 10 {
                "~5-10 minutes"
            } else {
                "~10-20 minutes"
            }
        }
    };
    println!("   {}", estimated_time);
    
    println!("\nOutput Files:");
    println!("   • data/latest.json (public findings)");
    println!("   • private_keys/full_keys.json (full keys, gitignored)");
    println!("   • README.md (statistics report)");
    
    if config.enable_validation {
        println!("   • validation_results.json (validation report)");
    }
    
    println!("\nConfig File: scanner-config.toml");
    
    println!();
    Ok(())
}

pub fn display_quick_start_menu() -> Result<String> {
    println!("\n╔═══════════════════════════════════════════════════════════╗");
    println!("║                                                           ║");
    println!("║           API Key Scanner v2.0 - Quick Start             ║");
    println!("║                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    let options = vec![
        "Quick Scan (use defaults, start immediately)",
        "Configure & Scan (customize all settings)",
        "View Previous Findings",
        "Test Saved API Keys",
        "Show Google Dork Patterns",
        "Exit",
    ];

    let selected = Select::new("What would you like to do?", options)
        .with_help_message("Use ↑↓ to navigate, Enter to select")
        .prompt()?;

    Ok(selected.to_string())
}
