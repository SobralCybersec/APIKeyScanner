use anyhow::Result;
use inquire::{Select, MultiSelect, Confirm, Text};
use crate::dorks::{DorkPattern, DorkSource, get_github_dorks, get_raw_github_dorks};
use crate::storage::{SecureStorage, PublicFinding, PrivateFinding};
use crate::validator;
use std::collections::HashMap;

pub async fn interactive_mode() -> Result<(String, usize, usize, Vec<String>)> {
    println!("\nAPI Key Scanner - Interactive Mode\n");

    let token = inquire::Password::new("GitHub Token:")
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()?;

    let max_requests = inquire::CustomType::<usize>::new("Max API requests:")
        .with_default(10)
        .prompt()?;

    let concurrency = inquire::CustomType::<usize>::new("Concurrent scans:")
        .with_default(5)
        .prompt()?;

    let scan_mode = Select::new(
        "Scan mode:",
        vec![
            "Baseline scan (all core queries)",
            "Full scan (10 queries)",
            "Google Dorks (advanced)",
            "Custom selection",
        ],
    )
    .prompt()?;

    let queries = if scan_mode == "Custom selection" {
        let available = vec![
            "sk-proj- filename:.env",
            "sk-proj- extension:py",
            "sk-proj- extension:js",
            "sk-svcacct- filename:.env",
            "sk-admin- filename:.env",
            "OPENAI_ADMIN_KEY extension:env",
            "OPENAI_PROJECT_API_KEY extension:env",
            "OPENAI_SERVICE_ACCOUNT_KEY extension:env",
            "sk-ant- extension:py",
            "ANTHROPIC_API_KEY extension:env",
            "ANTHROPIC_API_KEY extension:yaml",
            "CLAUDE_API_KEY extension:env",
            "CLAUDE_API_TOKEN extension:env",
            "OPENAI_API_KEY extension:env",
            "CHATGPT_API_KEY extension:env",
            "GROQ_API_KEY extension:env",
            "DEEPSEEK_API_KEY extension:env",
            "MISTRAL_API_KEY extension:env",
            "PERPLEXITY_API_KEY extension:env",
            "GOOGLE_API_KEY extension:env",
            "AWS_ACCESS_KEY_ID extension:env",
            "ghp_ extension:env",
            "mongodb:// extension:env",
        ];

        MultiSelect::new("Select queries to run:", available)
            .prompt()?
            .into_iter()
            .map(str::to_string)
            .collect()
    } else {
        vec![]
    };

    let confirm = Confirm::new("Start scan?")
        .with_default(true)
        .prompt()?;

    if !confirm {
        return Err(anyhow::anyhow!("Scan cancelled"));
    }

    Ok((token, max_requests, concurrency, queries))
}

pub async fn view_findings_menu() -> Result<()> {
    let storage = SecureStorage::new();

    let action = Select::new(
        "View findings:",
        vec![
            "Public findings",
            "Private findings (full keys)",
            "Test API keys",
            "Export to CSV",
            "Statistics",
            "Back",
        ],
    )
    .prompt()?;

    match action {
        "Public findings" => {
            let findings = storage.load_public_findings().await?;
            display_public_findings(&findings);
        }
        "Private findings (full keys)" => {
            let confirm = Confirm::new("⚠️  This will display FULL API keys. Continue?")
                .with_default(false)
                .prompt()?;

            if confirm {
                let findings = storage.load_private_findings().await?;
                display_private_findings(&findings);
            }
        }
        "Test API keys" => {
            let findings = storage.load_private_findings().await?;
            if findings.is_empty() {
                println!("\n⚠️  No findings to test. Run a scan first.\n");
            } else {
                println!("\nTesting {} API keys...\n", findings.len());
                let results = validator::test_findings(&findings).await?;
                validator::display_validation_results(&results);
            }
        }
        "Export to CSV" => {
            export_to_csv(&storage).await?;
        }
        "Statistics" => {
            show_statistics(&storage).await?;
        }
        _ => {}
    }

    Ok(())
}

fn display_public_findings(findings: &[PublicFinding]) {
    println!("\nPublic Findings ({} total)\n", findings.len());
    println!(
        "{:<40} {:<30} {:<20} {:<10}",
        "Repository", "File", "Type", "Entropy"
    );
    println!("{}", "-".repeat(100));

    for f in findings.iter().take(50) {
        let repo = truncate(&f.repository, 38);
        let file = truncate(
            f.file_path.split('/').next_back().unwrap_or(&f.file_path),
            28,
        );
        let key_type = truncate(&f.key_type, 18);
        let entropy = f
            .entropy
            .map(|e| format!("{:.2}", e))
            .unwrap_or_else(|| "N/A".to_string());

        println!("{:<40} {:<30} {:<20} {:<10}", repo, file, key_type, entropy);
    }

    if findings.len() > 50 {
        println!("\n... and {} more findings", findings.len() - 50);
    }
}

fn display_private_findings(findings: &[PrivateFinding]) {
    println!("\nPrivate Findings ({} total)\n", findings.len());
    println!("WARNING: Full API keys displayed below!\n");

    for (i, f) in findings.iter().take(20).enumerate() {
        println!("{}. Repository: {}", i + 1, f.repository);
        println!("   File: {}", f.file_path);
        println!("   Type: {}", f.key_type);
        println!("   Full Key: {}", f.full_key);
        println!("   Entropy: {:.2}", f.entropy.unwrap_or(0.0));
        println!();
    }

    if findings.len() > 20 {
        println!(
            "... and {} more findings (use export to see all)",
            findings.len() - 20
        );
    }
}

async fn export_to_csv(storage: &SecureStorage) -> Result<()> {
    let filename = Text::new("Export filename:")
        .with_default("findings.csv")
        .prompt()?;

    let include_full_keys = Confirm::new("Include full API keys?")
        .with_default(false)
        .prompt()?;

    if include_full_keys {
        let findings = storage.load_private_findings().await?;
        let mut csv =
            String::from("Repository,File,Type,Full Key,Preview,Entropy,Line,Discovered\n");

        for f in &findings {
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},{},\"{}\"\n",
                f.repository,
                f.file_path,
                f.key_type,
                f.full_key,
                f.key_preview,
                f.entropy.unwrap_or(0.0),
                f.line_number.unwrap_or(0),
                f.discovered_at
            ));
        }

        tokio::fs::write(&filename, csv).await?;
        println!("✅ Exported {} findings to {}", findings.len(), filename);
    } else {
        let findings = storage.load_public_findings().await?;
        let mut csv =
            String::from("Repository,File,Type,Preview,Entropy,Line,Discovered\n");

        for f in &findings {
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",{},{},\"{}\"\n",
                f.repository,
                f.file_path,
                f.key_type,
                f.key_preview,
                f.entropy.unwrap_or(0.0),
                f.line_number.unwrap_or(0),
                f.discovered_at
            ));
        }

        tokio::fs::write(&filename, csv).await?;
        println!("✅ Exported {} findings to {}", findings.len(), filename);
    }

    Ok(())
}

async fn show_statistics(storage: &SecureStorage) -> Result<()> {
    let findings = storage.load_public_findings().await?;

    let mut by_type: HashMap<String, usize> = HashMap::new();
    let mut by_repo: HashMap<String, usize> = HashMap::new();
    let mut high_entropy = 0usize;

    for f in &findings {
        *by_type.entry(f.key_type.clone()).or_insert(0) += 1;
        *by_repo.entry(f.repository.clone()).or_insert(0) += 1;
        if f.entropy.unwrap_or(0.0) > 4.0 {
            high_entropy += 1;
        }
    }

    println!("\nStatistics\n");
    println!("Total findings: {}", findings.len());
    println!("Unique repositories: {}", by_repo.len());
    println!("High entropy (>4.0): {}", high_entropy);
    println!("\nTop 10 key types:");

    let mut types: Vec<_> = by_type.into_iter().collect();
    types.sort_by(|a, b| b.1.cmp(&a.1));
    for (i, (key_type, count)) in types.iter().take(10).enumerate() {
        println!("  {}. {} - {} findings", i + 1, key_type, count);
    }

    println!("\nTop 10 affected repositories:");
    let mut repos: Vec<_> = by_repo.into_iter().collect();
    repos.sort_by(|a, b| b.1.cmp(&a.1));
    for (i, (repo, count)) in repos.iter().take(10).enumerate() {
        println!("  {}. {} - {} findings", i + 1, repo, count);
    }

    Ok(())
}

pub fn show_dork_patterns() {
    let dorks = get_github_dorks();
    let raw_dorks = get_raw_github_dorks();

    println!("\nGitHub Code-Search Dork Patterns\n");

    let mut by_category: HashMap<String, Vec<&DorkPattern>> = HashMap::new();
    for dork in &dorks {
        if matches!(dork.source, DorkSource::GithubCodeSearch) {
            by_category
                .entry(dork.category.clone())
                .or_default()
                .push(dork);
        }
    }

    for (category, patterns) in &by_category {
        println!("{} ({} patterns)", category, patterns.len());
        for pattern in patterns.iter().take(5) {
            println!("   • {} [{}]", pattern.name, pattern.risk_level);
        }
        if patterns.len() > 5 {
            println!("   ... and {} more", patterns.len() - 5);
        }
        println!();
    }

    println!("Web-Search Dorks (raw.githubusercontent.com) — {} patterns\n", raw_dorks.len());
    for dork in &raw_dorks {
        println!("   • {} [{}]", dork.name, dork.risk_level);
    }
    println!();
}

/// Truncate a string to `max_len` characters, appending `...` if needed.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}