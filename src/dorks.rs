//! GitHub code-search dork patterns for secret scanning.
//!
//! Two complementary surfaces are covered:
//!
//! 1. **GitHub code search** (`api.github.com/search/code`) — the primary
//!    scanner surface. Queries are tuned for the `indexed` sort so recently
//!    pushed secrets appear first.
//!
//! 2. **`raw.githubusercontent.com`** — a secondary surface searched via
//!    `path:` qualifiers. Raw file URLs persist even after a repository is
//!    privated or deleted because Google (and other search engines) may have
//!    already indexed them. Including raw-URL patterns in code-search queries
//!    surfaces scripts that embed raw-content fetch calls with credentials
//!    baked into the URL or the fetched file.
//!
//! Design rules:
//! - Every query in `get_advanced_github_queries` is unique (no duplicates).
//! - Queries target the extension/filename most likely to produce real secrets,
//!   not the most common extension overall.
//! - Jupyter notebooks (`.ipynb`) are a first-class target — AI/ML developers
//!   routinely commit API keys there.
//! - Docker Compose and Terraform files are included: environment variables
//!   in those files are very frequently exposed.
//! - `DorkPattern` carries a `source` field so callers can route raw-URL
//!   dorks to a different search surface (e.g., a Google Custom Search API)
//!   rather than the GitHub code-search API.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DorkSource {
    /// Standard GitHub code-search API query.
    GithubCodeSearch,
    /// Google/Bing dork targeting `raw.githubusercontent.com`.
    /// Use a web-search tool rather than the GitHub API for these.
    RawGitHubContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkPattern {
    pub name: String,
    pub query: String,
    pub category: String,
    pub risk_level: String,
    /// Where to direct this query.
    pub source: DorkSource,
}

impl DorkPattern {
    fn gh(name: &str, query: &str, category: &str, risk: &str) -> Self {
        Self {
            name: name.into(),
            query: query.into(),
            category: category.into(),
            risk_level: risk.into(),
            source: DorkSource::GithubCodeSearch,
        }
    }

    fn raw(name: &str, query: &str, category: &str, risk: &str) -> Self {
        Self {
            name: name.into(),
            query: query.into(),
            category: category.into(),
            risk_level: risk.into(),
            source: DorkSource::RawGitHubContent,
        }
    }
}

// ---------------------------------------------------------------------------
// Full dork catalogue (structured)
// ---------------------------------------------------------------------------

pub fn get_github_dorks() -> Vec<DorkPattern> {
    vec![
        // ----------------------------------------------------------------
        // OpenAI
        // ----------------------------------------------------------------
        DorkPattern::gh("OpenAI sk-proj in .env", "sk-proj- filename:.env", "OpenAI", "Critical"),
        DorkPattern::gh("OpenAI sk-proj in Python", "sk-proj- extension:py", "OpenAI", "Critical"),
        DorkPattern::gh("OpenAI sk-proj in JS/TS", "sk-proj- extension:js OR sk-proj- extension:ts", "OpenAI", "Critical"),
        DorkPattern::gh("OpenAI sk-proj in notebooks", "sk-proj- extension:ipynb", "OpenAI", "Critical"),
        DorkPattern::gh("OpenAI sk-svcacct in .env", "sk-svcacct- filename:.env", "OpenAI", "Critical"),
        DorkPattern::gh("OpenAI sk-admin in .env", "sk-admin- filename:.env", "OpenAI", "Critical"),
        DorkPattern::gh("OPENAI_API_KEY env", "OPENAI_API_KEY extension:env", "OpenAI", "Critical"),
        DorkPattern::gh("OPENAI_API_KEY yaml/toml", "OPENAI_API_KEY extension:yaml OR OPENAI_API_KEY extension:toml", "OpenAI", "Critical"),
        DorkPattern::gh("OPENAI_API_KEY JSON", "OPENAI_API_KEY extension:json", "OpenAI", "Critical"),
        DorkPattern::gh("OPENAI_API_KEY CSV", "OPENAI_API_KEY extension:csv", "OpenAI", "Critical"),
        DorkPattern::gh("OPENAI_API_KEY notebooks", "OPENAI_API_KEY extension:ipynb", "OpenAI", "Critical"),
        DorkPattern::gh("OPENAI_ADMIN_KEY env", "OPENAI_ADMIN_KEY extension:env", "OpenAI", "Critical"),
        DorkPattern::gh("OPENAI_ADMIN_KEY yaml", "OPENAI_ADMIN_KEY extension:yaml", "OpenAI", "Critical"),
        DorkPattern::gh("OPENAI project/svcacct env", "OPENAI_PROJECT_API_KEY extension:env OR OPENAI_SERVICE_ACCOUNT_KEY extension:env", "OpenAI", "Critical"),
        DorkPattern::gh("ChatGPT/GPT aliases env", "CHATGPT_API_KEY extension:env OR GPT_API_KEY extension:env OR CODEX_API_KEY extension:env", "OpenAI", "Critical"),

        // ----------------------------------------------------------------
        // Anthropic
        // ----------------------------------------------------------------
        DorkPattern::gh("ANTHROPIC_API_KEY env", "ANTHROPIC_API_KEY extension:env", "Anthropic", "Critical"),
        DorkPattern::gh("ANTHROPIC_API_KEY yaml/toml", "ANTHROPIC_API_KEY extension:yaml OR ANTHROPIC_API_KEY extension:toml", "Anthropic", "Critical"),
        DorkPattern::gh("ANTHROPIC_API_KEY JSON", "ANTHROPIC_API_KEY extension:json", "Anthropic", "Critical"),
        DorkPattern::gh("ANTHROPIC_API_KEY CSV", "ANTHROPIC_API_KEY extension:csv", "Anthropic", "Critical"),
        DorkPattern::gh("ANTHROPIC_API_KEY notebooks", "ANTHROPIC_API_KEY extension:ipynb", "Anthropic", "Critical"),
        DorkPattern::gh("sk-ant- in Python", "sk-ant- extension:py", "Anthropic", "Critical"),
        DorkPattern::gh("sk-ant- in JS/TS", "sk-ant- extension:js OR sk-ant- extension:ts", "Anthropic", "Critical"),
        DorkPattern::gh("sk-ant- in .env", "sk-ant- filename:.env", "Anthropic", "Critical"),
        DorkPattern::gh("CLAUDE_API_KEY env", "CLAUDE_API_KEY extension:env OR CLAUDE_API_TOKEN extension:env", "Anthropic", "Critical"),
        DorkPattern::gh("CLAUDE_CODE_API_KEY", "CLAUDE_CODE_API_KEY extension:env", "Anthropic", "Critical"),

        // ----------------------------------------------------------------
        // 2026 AI providers
        // ----------------------------------------------------------------
        DorkPattern::gh("Groq env", "GROQ_API_KEY extension:env OR gsk_ filename:.env", "AI Providers", "Critical"),
        DorkPattern::gh("DeepSeek env", "DEEPSEEK_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("Mistral env", "MISTRAL_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("Cohere env", "COHERE_API_KEY extension:env OR CO_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("Hugging Face token env", "HF_TOKEN extension:env OR HUGGINGFACE_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("Replicate token env", "REPLICATE_API_TOKEN extension:env OR r8_ filename:.env", "AI Providers", "Critical"),
        DorkPattern::gh("Perplexity env", "PERPLEXITY_API_KEY extension:env OR PPLX_API_KEY extension:env OR pplx- filename:.env", "AI Providers", "Critical"),
        DorkPattern::gh("Together AI env", "TOGETHER_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("AI21 env", "AI21_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("xAI Grok env", "XAI_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("Tavily env", "TAVILY_API_KEY extension:env OR tvly- filename:.env", "AI Providers", "Critical"),
        DorkPattern::gh("ElevenLabs env", "ELEVENLABS_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("Pinecone env", "PINECONE_API_KEY extension:env OR pcsk_ filename:.env", "AI Providers", "Critical"),
        DorkPattern::gh("LangSmith env", "LANGCHAIN_API_KEY extension:env OR LANGSMITH_API_KEY extension:env", "AI Providers", "High"),
        DorkPattern::gh("Weights & Biases env", "WANDB_API_KEY extension:env OR wandb_v1_ filename:.env", "AI Providers", "High"),
        DorkPattern::gh("Stability AI env", "STABILITY_API_KEY extension:env", "AI Providers", "High"),
        DorkPattern::gh("Fal.ai env", "FAL_KEY extension:env OR fal_ filename:.env", "AI Providers", "High"),
        DorkPattern::gh("Anthropic admin key", "ANTHROPIC_ADMIN_API_KEY extension:env OR sk-ant-admin- filename:.env", "Anthropic", "Critical"),

        // ----------------------------------------------------------------
        // 2026 new AI providers
        // ----------------------------------------------------------------
        DorkPattern::gh("Cerebras API key env", "CEREBRAS_API_KEY extension:env OR csk- filename:.env", "AI Providers", "Critical"),
        DorkPattern::gh("OpenRouter API key env", "OPENROUTER_API_KEY extension:env OR sk-or- filename:.env", "AI Providers", "Critical"),
        DorkPattern::gh("NVIDIA NIM API key env", "NVIDIA_API_KEY extension:env OR nvapi- filename:.env", "AI Providers", "Critical"),
        DorkPattern::gh("Fireworks AI key env", "FIREWORKS_API_KEY extension:env", "AI Providers", "Critical"),
        DorkPattern::gh("SiliconFlow key env", "SILICONFLOW_API_KEY extension:env", "AI Providers", "High"),
        DorkPattern::gh("Moonshot / Kimi key env", "MOONSHOT_API_KEY extension:env OR KIMI_API_KEY extension:env", "AI Providers", "High"),
        DorkPattern::gh("DeepInfra key env", "DEEPINFRA_API_KEY extension:env", "AI Providers", "High"),
        DorkPattern::gh("Cerebras key in notebooks", "CEREBRAS_API_KEY extension:ipynb", "AI Providers", "Critical"),
        DorkPattern::gh("OpenRouter key in notebooks", "OPENROUTER_API_KEY extension:ipynb", "AI Providers", "Critical"),

        // ----------------------------------------------------------------
        // Google / Gemini / Azure
        // ----------------------------------------------------------------
        DorkPattern::gh("Google API key env", "GOOGLE_API_KEY filename:.env", "Google", "Critical"),
        DorkPattern::gh("Gemini API key env", "GEMINI_API_KEY extension:env", "Google", "Critical"),
        DorkPattern::gh("AIza key in JS", "AIza extension:js", "Google", "Critical"),
        DorkPattern::gh("Azure OpenAI key env", "AZURE_OPENAI_KEY extension:env OR AZURE_OPENAI_API_KEY extension:yaml", "Azure", "Critical"),
        DorkPattern::gh("Azure AI Services key", "AZURE_COGNITIVE_KEY extension:env OR AZURE_AI_KEY extension:env", "Azure", "Critical"),

        // ----------------------------------------------------------------
        // AWS
        // ----------------------------------------------------------------
        DorkPattern::gh("AWS access key env", "AWS_ACCESS_KEY_ID extension:env", "AWS", "Critical"),
        DorkPattern::gh("AWS access key yaml", "aws_access_key_id extension:yaml", "AWS", "Critical"),
        DorkPattern::gh("AWS secret key env", "AWS_SECRET_ACCESS_KEY extension:env", "AWS", "Critical"),
        DorkPattern::gh("AKIA in env", "AKIA extension:env", "AWS", "Critical"),
        DorkPattern::gh("AWS keys in notebooks", "AWS_ACCESS_KEY_ID extension:ipynb", "AWS", "Critical"),

        // ----------------------------------------------------------------
        // GitHub tokens
        // ----------------------------------------------------------------
        DorkPattern::gh("GitHub PAT in env", "ghp_ filename:.env", "GitHub", "Critical"),
        DorkPattern::gh("GitHub fine-grained PAT", "github_pat_ filename:.env", "GitHub", "Critical"),
        DorkPattern::gh("GitHub PAT in txt", "ghp_ extension:txt", "GitHub", "Critical"),
        DorkPattern::gh("GitHub OAuth token", "gho_ filename:.env", "GitHub", "Critical"),
        DorkPattern::gh("GitHub server token yaml", "ghs_ extension:yaml", "GitHub", "Critical"),
        DorkPattern::gh("GITHUB_TOKEN env", "GITHUB_TOKEN extension:env", "GitHub", "Critical"),

        // ----------------------------------------------------------------
        // Cloud & infra
        // ----------------------------------------------------------------
        DorkPattern::gh("DigitalOcean token env", "DIGITALOCEAN_ACCESS_TOKEN extension:env OR dop_v1_ filename:.env", "Cloud", "Critical"),
        DorkPattern::gh("Vercel token env", "VERCEL_TOKEN filename:.env", "Cloud", "Critical"),
        DorkPattern::gh("Cloudflare API key env", "CLOUDFLARE_API_KEY extension:env OR CLOUDFLARE_API_TOKEN extension:env", "Cloud", "Critical"),
        DorkPattern::gh("Render API key env", "RENDER_API_KEY filename:.env", "Cloud", "High"),
        DorkPattern::gh("Netlify token env", "NETLIFY_AUTH_TOKEN filename:.env OR nfp_ filename:.env", "Cloud", "High"),
        DorkPattern::gh("Tailscale API key env", "TAILSCALE_API_KEY extension:env OR tskey- filename:.env", "Cloud", "High"),
        DorkPattern::gh("Mapbox secret token env", "MAPBOX_SECRET_ACCESS_TOKEN extension:env OR MAPBOX_ACCESS_TOKEN extension:env", "Cloud", "High"),
        DorkPattern::gh("Clerk secret key env", "CLERK_SECRET_KEY extension:env", "Cloud", "High"),
        DorkPattern::gh("Infisical token env", "INFISICAL_TOKEN extension:env", "Cloud", "Medium"),

        // ----------------------------------------------------------------
        // Databases
        // ----------------------------------------------------------------
        DorkPattern::gh("DATABASE_URL env", "DATABASE_URL extension:env", "Database", "High"),
        DorkPattern::gh("MongoDB URI env", "mongodb:// filename:.env", "Database", "High"),
        DorkPattern::gh("Postgres URI env", "postgresql:// extension:env", "Database", "High"),
        DorkPattern::gh("MySQL URI env", "mysql:// filename:.env", "Database", "High"),
        DorkPattern::gh("DB_PASSWORD env", "DB_PASSWORD extension:env", "Database", "High"),
        DorkPattern::gh("Snowflake password env", "SNOWFLAKE_PASSWORD extension:env", "Database", "High"),
        DorkPattern::gh("Databricks token env", "DATABRICKS_TOKEN filename:.env", "Database", "High"),
        DorkPattern::gh("Neon API key", "NEON_API_KEY filename:.env", "Database", "High"),
        DorkPattern::gh("PlanetScale token", "PLANETSCALE_TOKEN filename:.env", "Database", "High"),
        DorkPattern::gh("Supabase service key", "SUPABASE_SERVICE_KEY extension:env", "Database", "Critical"),

        // ----------------------------------------------------------------
        // SaaS / third-party services
        // ----------------------------------------------------------------
        DorkPattern::gh("Slack bot token", "xoxb- filename:.env", "SaaS", "Critical"),
        DorkPattern::gh("Slack user token", "xoxp- extension:env", "SaaS", "Critical"),
        DorkPattern::gh("SLACK_TOKEN env", "SLACK_TOKEN extension:env", "SaaS", "Critical"),
        DorkPattern::gh("Stripe live key", "sk_live_ filename:.env", "SaaS", "Critical"),
        DorkPattern::gh("Stripe test key env", "sk_test_ extension:env", "SaaS", "High"),
        DorkPattern::gh("STRIPE_SECRET_KEY env", "STRIPE_SECRET_KEY extension:env", "SaaS", "Critical"),
        DorkPattern::gh("SendGrid API key", "SG. extension:env OR SENDGRID_API_KEY extension:env", "SaaS", "High"),
        DorkPattern::gh("Twilio SID env", "TWILIO_AUTH_TOKEN extension:env OR TWILIO_API_KEY extension:env", "SaaS", "High"),
        DorkPattern::gh("PostHog API key", "POSTHOG_API_KEY filename:.env", "SaaS", "High"),
        DorkPattern::gh("Sentry auth token", "SENTRY_AUTH_TOKEN extension:env", "SaaS", "High"),
        DorkPattern::gh("Figma token env", "FIGMA_TOKEN filename:.env OR FIGMA_API_TOKEN filename:.env", "SaaS", "High"),
        DorkPattern::gh("Doppler token", "DOPPLER_TOKEN filename:.env", "SaaS", "High"),
        DorkPattern::gh("Airtable PAT", "pat extension:env OR AIRTABLE_API_KEY extension:env", "SaaS", "High"),
        DorkPattern::gh("Notion secret", "NOTION_API_KEY extension:env OR NOTION_TOKEN extension:env", "SaaS", "Medium"),
        DorkPattern::gh("Shopify PAT", "SHOPIFY_ACCESS_TOKEN extension:env OR shpat_ filename:.env", "SaaS", "Critical"),
        DorkPattern::gh("Brave Search key", "BRAVE_API_KEY extension:env", "SaaS", "Medium"),
        DorkPattern::gh("Lark app secret", "LARK_APP_SECRET extension:env", "SaaS", "High"),
        DorkPattern::gh("Salesforce secrets env", "SALESFORCE_ACCESS_TOKEN extension:env OR SALESFORCE_CLIENT_SECRET extension:env", "SaaS", "High"),
        DorkPattern::gh("Weights & Biases key", "WANDB_API_KEY extension:env", "SaaS", "High"),

        // ----------------------------------------------------------------
        // npm / CI / registries
        // ----------------------------------------------------------------
        DorkPattern::gh("npm token env", "npm_token extension:env OR NPM_TOKEN extension:env", "Registry", "High"),
        DorkPattern::gh("PyPI token", "PYPI_TOKEN extension:env OR TWINE_PASSWORD extension:env", "Registry", "High"),
        DorkPattern::gh("Docker Hub token", "DOCKER_PASSWORD extension:env OR dckr_pat_ filename:.env", "Registry", "High"),

        // ----------------------------------------------------------------
        // Private keys & certificates
        // ----------------------------------------------------------------
        DorkPattern::gh("RSA private key PEM", "BEGIN RSA PRIVATE KEY extension:pem", "Private Keys", "Critical"),
        DorkPattern::gh("OpenSSH private key", "BEGIN OPENSSH PRIVATE KEY extension:key", "Private Keys", "Critical"),
        DorkPattern::gh("PGP private key", "BEGIN PGP PRIVATE KEY BLOCK extension:asc", "Private Keys", "Critical"),

        // ----------------------------------------------------------------
        // MCP config surface (massive 2026 attack surface)
        // AI agent tools commit these JSON configs with hardcoded keys
        // ----------------------------------------------------------------
        DorkPattern::gh("MCP claude_desktop_config secrets", "mcpServers filename:claude_desktop_config.json", "MCP", "Critical"),
        DorkPattern::gh("MCP cursor config secrets", "mcpServers filename:mcp.json", "MCP", "Critical"),
        DorkPattern::gh("MCP vscode config secrets", "mcpServers path:.vscode/mcp.json", "MCP", "Critical"),
        DorkPattern::gh("MCP windsurf config secrets", "mcpServers path:.windsurf/mcp.json", "MCP", "Critical"),
        DorkPattern::gh("MCP config with hardcoded API key", "OPENAI_API_KEY filename:claude_desktop_config.json", "MCP", "Critical"),
        DorkPattern::gh("MCP config with GitHub token", "GITHUB_TOKEN filename:claude_desktop_config.json", "MCP", "Critical"),
        DorkPattern::gh("MCP config with Anthropic key", "ANTHROPIC_API_KEY filename:claude_desktop_config.json", "MCP", "Critical"),
        DorkPattern::gh("MCP config with DB URL", "DATABASE_URL filename:claude_desktop_config.json", "MCP", "Critical"),
        DorkPattern::gh("MCP config any key in mcp.json", "API_KEY filename:mcp.json", "MCP", "Critical"),

        // ----------------------------------------------------------------
        // Extended file surfaces (log, bak, backup, secret, ini, conf…)
        // ----------------------------------------------------------------
        DorkPattern::gh("API key in .log files", "API_KEY extension:log", "Extended Surface", "High"),
        DorkPattern::gh("Secret in .bak files", "password extension:bak OR api_key extension:bak", "Extended Surface", "High"),
        DorkPattern::gh("Secret in .backup files", "password extension:backup OR secret extension:backup", "Extended Surface", "High"),
        DorkPattern::gh("Secret in .secret files", "api_key extension:secret OR password extension:secret", "Extended Surface", "High"),
        DorkPattern::gh("Secret in .private files", "api_key extension:private OR secret extension:private", "Extended Surface", "High"),
        DorkPattern::gh("Secret in .key files", "PRIVATE KEY extension:key OR api_key extension:key", "Extended Surface", "High"),
        DorkPattern::gh("Secret in .envrc files", "export API_KEY extension:envrc OR export SECRET extension:envrc", "Extended Surface", "High"),
        DorkPattern::gh("Secret in .prod files", "API_KEY extension:prod OR SECRET extension:prod", "Extended Surface", "High"),
        DorkPattern::gh("Secret in .conf files", "api_key extension:conf OR password extension:conf", "Extended Surface", "Medium"),
        DorkPattern::gh("Secret in .ini files", "api_key extension:ini OR password extension:ini", "Extended Surface", "Medium"),

        // ----------------------------------------------------------------
        // GitHub Actions secrets surface
        // ----------------------------------------------------------------
        DorkPattern::gh("GH Actions hardcoded secret", "OPENAI_API_KEY path:.github/workflows", "CI/CD", "Critical"),
        DorkPattern::gh("GH Actions AWS key", "AWS_ACCESS_KEY_ID path:.github/workflows", "CI/CD", "Critical"),
        DorkPattern::gh("GH Actions Anthropic key", "ANTHROPIC_API_KEY path:.github/workflows", "CI/CD", "Critical"),
        DorkPattern::gh("GH Actions token hardcoded", "GITHUB_TOKEN path:.github/workflows extension:yml", "CI/CD", "High"),
        DorkPattern::gh("GH Actions generic secret", "API_KEY path:.github/workflows extension:yml", "CI/CD", "High"),

        // ----------------------------------------------------------------
        // Composite high-signal path: queries (modern GitHub search syntax)
        // Multi-extension OR chains — highest recall per query slot
        // ----------------------------------------------------------------
        DorkPattern::gh("OpenAI key multi-surface", "sk-proj- path:*.env OR sk-proj- path:*.yaml OR sk-proj- path:*.json", "Composite", "Critical"),
        DorkPattern::gh("Anthropic key multi-surface", "sk-ant- path:*.env OR sk-ant- path:*.yaml OR sk-ant- path:*.json", "Composite", "Critical"),
        DorkPattern::gh("AWS key multi-surface", "AWS_ACCESS_KEY_ID path:*.env OR AWS_ACCESS_KEY_ID path:*.conf OR AWS_ACCESS_KEY_ID path:*.ini", "Composite", "Critical"),
        DorkPattern::gh("DB URL multi-surface", "DATABASE_URL path:*.env OR DATABASE_URL path:*.conf OR DATABASE_URL path:*.ini", "Composite", "High"),
        DorkPattern::gh("Generic secret multi-surface", "api_key path:*.log OR api_key path:*.bak OR api_key path:*.backup", "Composite", "High"),
        DorkPattern::gh("Private key multi-surface", "BEGIN PRIVATE KEY path:*.pem OR BEGIN PRIVATE KEY path:*.key OR BEGIN PRIVATE KEY path:*.txt", "Composite", "Critical"),

        // ----------------------------------------------------------------
        // Shell / dotfile surface
        // ----------------------------------------------------------------
        DorkPattern::gh(".npmrc with auth token", "_auth filename:.npmrc", "Dotfiles", "High"),
        DorkPattern::gh(".dockercfg with auth", "auth filename:.dockercfg", "Dotfiles", "High"),
        DorkPattern::gh(".netrc with password", "password filename:.netrc", "Dotfiles", "Critical"),
        DorkPattern::gh(".bash_history with AWS", "aws_access_key filename:.bash_history", "Dotfiles", "Critical"),
        DorkPattern::gh(".bash_profile with AWS", "AWS filename:.bash_profile", "Dotfiles", "Critical"),
        DorkPattern::gh("Shell export with API key", "export API_KEY extension:sh", "Dotfiles", "High"),
        DorkPattern::gh("Shell export with secret", "export SECRET extension:sh OR export TOKEN extension:sh", "Dotfiles", "High"),

        // ----------------------------------------------------------------
        // Framework-specific secret files
        // ----------------------------------------------------------------
        DorkPattern::gh("Django SECRET_KEY", "SECRET_KEY filename:settings.py", "Framework", "Critical"),
        DorkPattern::gh("Rails SECRET_KEY_BASE", "SECRET_KEY_BASE filename:secrets.yml", "Framework", "Critical"),
        DorkPattern::gh("Rails master.key", "filename:master.key path:config", "Framework", "Critical"),
        DorkPattern::gh("Laravel .env APP_KEY", "APP_KEY filename:.env", "Framework", "High"),
        DorkPattern::gh("Phoenix prod secret", "filename:prod.secret.exs", "Framework", "Critical"),
        DorkPattern::gh("Jupyter notebook config token", "password filename:jupyter_notebook_config.json", "Framework", "High"),

        // ----------------------------------------------------------------
        // Slack webhook URLs (hardcoded in source)
        // ----------------------------------------------------------------
        DorkPattern::gh("Slack webhook URL in code", "hooks.slack.com/services/ extension:js", "SaaS", "High"),
        DorkPattern::gh("Slack webhook URL in Python", "hooks.slack.com/services/ extension:py", "SaaS", "High"),
        DorkPattern::gh("Slack webhook URL in env", "hooks.slack.com/services/ filename:.env", "SaaS", "High"),

        // ----------------------------------------------------------------
        // Config file surface area
        // ----------------------------------------------------------------
        DorkPattern::gh("API key in .env files", "API filename:.env", "Config", "High"),
        DorkPattern::gh("Secrets in docker-compose", "API_KEY filename:docker-compose.yml OR SECRET filename:docker-compose.yml", "Config", "High"),
        DorkPattern::gh("Secrets in Terraform vars", "sensitive extension:tfvars OR API_KEY extension:tfvars", "Config", "High"),
        DorkPattern::gh("Secrets in Kubernetes manifest", "stringData extension:yaml", "Config", "High"),
        DorkPattern::gh("JWT secret env", "JWT_SECRET filename:.env OR SECRET_KEY_BASE extension:env", "Config", "High"),

        // ----------------------------------------------------------------
        // Backup & data files
        // ----------------------------------------------------------------
        DorkPattern::gh("Password in backup", "password extension:bak", "Backup", "Medium"),
        DorkPattern::gh("SQL dump with credentials", "INSERT INTO users extension:sql", "Backup", "High"),

        // ----------------------------------------------------------------
        // raw.githubusercontent.com surface
        //
        // These are Google/Bing dorks — route them to a web-search tool,
        // not the GitHub code-search API.
        //
        // IMPORTANT: raw.githubusercontent.com serves files without file
        // extensions in the URL (e.g. /main/.env has no extension), so
        // `filetype:` does NOT work here. Use `inurl:` to match path
        // segments and `intext:` to match file content.
        // For broad Google searches (not scoped to raw.githubusercontent.com)
        // `filetype:env` DOES work and is included as separate entries below.
        // ----------------------------------------------------------------
        DorkPattern::raw(
            "Raw .env files with api_key",
            r#"site:raw.githubusercontent.com inurl:".env" intext:"api_key" -intext:"sample" -intext:"test""#,
            "Raw GitHub",
            "High",
        ),
        DorkPattern::raw(
            "Raw .env files with OPENAI_API_KEY",
            r#"site:raw.githubusercontent.com inurl:".env" intext:"OPENAI_API_KEY""#,
            "Raw GitHub",
            "Critical",
        ),
        DorkPattern::raw(
            "Raw .env files with ANTHROPIC_API_KEY",
            r#"site:raw.githubusercontent.com inurl:".env" intext:"ANTHROPIC_API_KEY""#,
            "Raw GitHub",
            "Critical",
        ),
        DorkPattern::raw(
            "Raw .env files with AWS keys",
            r#"site:raw.githubusercontent.com inurl:".env" intext:"AWS_ACCESS_KEY_ID" intext:"AWS_SECRET_ACCESS_KEY""#,
            "Raw GitHub",
            "Critical",
        ),
        DorkPattern::raw(
            "Raw YAML with secrets",
            r#"site:raw.githubusercontent.com (inurl:".yaml" OR inurl:".yml") (intext:"api_key" OR intext:"secret_key") -intext:"example""#,
            "Raw GitHub",
            "High",
        ),
        DorkPattern::raw(
            "Raw notebooks with API keys",
            r#"site:raw.githubusercontent.com inurl:".ipynb" (intext:"OPENAI_API_KEY" OR intext:"sk-")"#,
            "Raw GitHub",
            "Critical",
        ),
        DorkPattern::raw(
            "Raw docker-compose with secrets",
            r#"site:raw.githubusercontent.com inurl:"docker-compose" intext:"API_KEY""#,
            "Raw GitHub",
            "High",
        ),
        DorkPattern::raw(
            "Raw Terraform vars with secrets",
            r#"site:raw.githubusercontent.com inurl:".tfvars" intext:"key""#,
            "Raw GitHub",
            "High",
        ),
        DorkPattern::raw(
            "Raw scripts with embedded token URLs",
            r#"site:raw.githubusercontent.com intext:"raw.githubusercontent.com" intext:"token=""#,
            "Raw GitHub",
            "High",
        ),
        // ----------------------------------------------------------------
        // Broad Google filetype: dorks — search ALL of Google, not just
        // raw.githubusercontent.com. filetype: works here because Google
        // indexes these files with their extensions from any public host.
        // ----------------------------------------------------------------
        DorkPattern::raw(
            "Google: any .env with OPENAI_API_KEY",
            r#"filetype:env intext:"OPENAI_API_KEY" -intext:"example" -intext:"sample""#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Google: any .env with ANTHROPIC_API_KEY",
            r#"filetype:env intext:"ANTHROPIC_API_KEY""#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Google: any .env with AWS keys",
            r#"filetype:env intext:"AWS_ACCESS_KEY_ID" intext:"AWS_SECRET_ACCESS_KEY""#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Google: any .env with sk-proj-",
            r#"filetype:env intext:"sk-proj-""#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Google: any .env with STRIPE_SECRET_KEY",
            r#"filetype:env intext:"STRIPE_SECRET_KEY" -intext:"example""#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Google: any .env with DATABASE_URL",
            r#"filetype:env intext:"DATABASE_URL" (intext:"postgres" OR intext:"mysql" OR intext:"mongodb") -intext:"example""#,
            "Google Broad",
            "High",
        ),
        DorkPattern::raw(
            "Google: any .env with GITHUB_TOKEN",
            r#"filetype:env intext:"GITHUB_TOKEN" OR filetype:env intext:"ghp_""#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Google: any .env with GROQ or DEEPSEEK keys",
            r#"filetype:env (intext:"GROQ_API_KEY" OR intext:"DEEPSEEK_API_KEY" OR intext:"GEMINI_API_KEY")"#,
            "Google Broad",
            "Critical",
        ),
        // ----------------------------------------------------------------
        // 2026 new provider Google dorks
        // ----------------------------------------------------------------
        DorkPattern::raw(
            "Google: any .env with Cerebras/OpenRouter/NVIDIA keys",
            r#"filetype:env (intext:"CEREBRAS_API_KEY" OR intext:"OPENROUTER_API_KEY" OR intext:"NVIDIA_API_KEY")"#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Google: any .env with Fireworks/SiliconFlow/Moonshot keys",
            r#"filetype:env (intext:"FIREWORKS_API_KEY" OR intext:"SILICONFLOW_API_KEY" OR intext:"MOONSHOT_API_KEY")"#,
            "Google Broad",
            "High",
        ),
        // ----------------------------------------------------------------
        // MCP config Google dorks
        // ----------------------------------------------------------------
        DorkPattern::raw(
            "Google: MCP claude_desktop_config with secrets",
            r#"filetype:json intext:"mcpServers" (intext:"OPENAI_API_KEY" OR intext:"ANTHROPIC_API_KEY" OR intext:"GITHUB_TOKEN")"#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Raw MCP cursor config with secrets",
            r#"site:raw.githubusercontent.com inurl:".cursor/mcp.json" intext:"env""#,
            "Raw GitHub",
            "Critical",
        ),
        DorkPattern::raw(
            "Raw MCP vscode config with secrets",
            r#"site:raw.githubusercontent.com inurl:".vscode/mcp.json" intext:"env""#,
            "Raw GitHub",
            "Critical",
        ),
        // ----------------------------------------------------------------
        // Extended surface Google dorks
        // ----------------------------------------------------------------
        DorkPattern::raw(
            "Google: .log files with API keys",
            r#"filetype:log (intext:"api_key" OR intext:"API_KEY" OR intext:"secret_key") -intext:"example""#,
            "Google Broad",
            "High",
        ),
        DorkPattern::raw(
            "Google: .bak files with credentials",
            r#"filetype:bak (intext:"password" OR intext:"api_key" OR intext:"secret")"#,
            "Google Broad",
            "High",
        ),
        DorkPattern::raw(
            "Google: Django settings with SECRET_KEY",
            r#"filetype:py intext:"SECRET_KEY" intext:"DATABASES" -intext:"example""#,
            "Google Broad",
            "Critical",
        ),
        DorkPattern::raw(
            "Google: .npmrc with auth token",
            r#"filetype:npmrc intext:"_auth" OR filetype:npmrc intext:"authToken""#,
            "Google Broad",
            "High",
        ),
        DorkPattern::raw(
            "Google: Slack webhook hardcoded",
            r#"intext:"hooks.slack.com/services/" (filetype:js OR filetype:py OR filetype:env)"#,
            "Google Broad",
            "High",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Flat query list for the GitHub code-search scanner
// (only GithubCodeSearch source; raw.githubusercontent dorks need a different
// search surface and are filtered out automatically)
// ---------------------------------------------------------------------------

pub fn get_advanced_github_queries() -> Vec<String> {
    // Deduplicated and sorted by expected signal/noise ratio (highest first).
    // Each entry is unique — the original list had several verbatim duplicates.
    vec![
        // ---- OpenAI ----
        "sk-proj- filename:.env".into(),
        "sk-proj- extension:py".into(),
        "sk-proj- extension:js".into(),
        "sk-proj- extension:ts".into(),
        "sk-proj- extension:ipynb".into(),
        "sk-svcacct- filename:.env".into(),
        "sk-admin- filename:.env".into(),
        "OPENAI_API_KEY extension:env".into(),
        "OPENAI_API_KEY extension:yaml".into(),
        "OPENAI_API_KEY extension:toml".into(),
        "OPENAI_API_KEY extension:json".into(),
        "OPENAI_API_KEY extension:csv".into(),
        "OPENAI_API_KEY extension:ipynb".into(),
        "OPENAI_ADMIN_KEY extension:env".into(),
        "OPENAI_ADMIN_KEY extension:yaml".into(),
        "OPENAI_PROJECT_API_KEY extension:env".into(),
        "OPENAI_SERVICE_ACCOUNT_KEY extension:env".into(),
        "CHATGPT_API_KEY extension:env".into(),
        "CODEX_API_KEY extension:env".into(),
        "GPT_API_KEY extension:env".into(),

        // ---- Anthropic ----
        "ANTHROPIC_API_KEY extension:env".into(),
        "ANTHROPIC_API_KEY extension:yaml".into(),
        "ANTHROPIC_API_KEY extension:toml".into(),
        "ANTHROPIC_API_KEY extension:json".into(),
        "ANTHROPIC_API_KEY extension:csv".into(),
        "ANTHROPIC_API_KEY extension:ipynb".into(),
        "sk-ant- filename:.env".into(),
        "sk-ant- extension:py".into(),
        "sk-ant- extension:js".into(),
        "sk-ant- extension:ts".into(),
        "CLAUDE_API_KEY extension:env".into(),
        "CLAUDE_API_TOKEN extension:env".into(),
        "CLAUDE_CODE_API_KEY extension:env".into(),

        // ---- 2026 AI providers ----
        "GROQ_API_KEY extension:env".into(),
        "gsk_ filename:.env".into(),
        "DEEPSEEK_API_KEY extension:env".into(),
        "MISTRAL_API_KEY extension:env".into(),
        "COHERE_API_KEY extension:env".into(),
        "CO_API_KEY extension:env".into(),
        "HF_TOKEN extension:env".into(),
        "HUGGINGFACE_API_KEY extension:env".into(),
        "REPLICATE_API_TOKEN extension:env".into(),
        "r8_ filename:.env".into(),
        "PERPLEXITY_API_KEY extension:env".into(),
        "PPLX_API_KEY extension:env".into(),
        "TOGETHER_API_KEY extension:env".into(),
        "AI21_API_KEY extension:env".into(),
        "XAI_API_KEY extension:env".into(),
        "TAVILY_API_KEY extension:env".into(),
        "tvly- filename:.env".into(),
        "ELEVENLABS_API_KEY extension:env".into(),
        "PINECONE_API_KEY extension:env".into(),
        "pcsk_ filename:.env".into(),
        "LANGCHAIN_API_KEY extension:env".into(),
        "LANGSMITH_API_KEY extension:env".into(),
        "WANDB_API_KEY extension:env".into(),
        "wandb_v1_ filename:.env".into(),
        "STABILITY_API_KEY extension:env".into(),
        "FAL_KEY extension:env".into(),
        "fal_ filename:.env".into(),
        "ANTHROPIC_ADMIN_API_KEY extension:env".into(),
        "sk-ant-admin- filename:.env".into(),

        // ---- Google / Azure ----
        "GOOGLE_API_KEY filename:.env".into(),
        "GEMINI_API_KEY extension:env".into(),
        "AIza extension:js".into(),
        "AZURE_OPENAI_KEY extension:env".into(),
        "AZURE_OPENAI_API_KEY extension:yaml".into(),
        "AZURE_COGNITIVE_KEY extension:env".into(),

        // ---- AWS ----
        "AWS_ACCESS_KEY_ID filename:.env".into(),
        "AWS_ACCESS_KEY_ID extension:ipynb".into(),
        "AWS_SECRET_ACCESS_KEY filename:.env".into(),
        "AKIA extension:env".into(),
        "aws_access_key_id extension:yaml".into(),

        // ---- GitHub tokens ----
        "ghp_ filename:.env".into(),
        "github_pat_ filename:.env".into(),
        "ghp_ extension:txt".into(),
        "gho_ filename:.env".into(),
        "ghs_ extension:yaml".into(),
        "GITHUB_TOKEN extension:env".into(),

        // ---- Cloud infra ----
        "VERCEL_TOKEN filename:.env".into(),
        "CLOUDFLARE_API_KEY extension:env".into(),
        "CLOUDFLARE_API_TOKEN extension:env".into(),
        "DIGITALOCEAN_ACCESS_TOKEN extension:env".into(),
        "dop_v1_ filename:.env".into(),
        "RENDER_API_KEY filename:.env".into(),
        "NETLIFY_AUTH_TOKEN filename:.env".into(),
        "nfp_ filename:.env".into(),
        "TAILSCALE_API_KEY extension:env".into(),
        "tskey- filename:.env".into(),
        "MAPBOX_SECRET_ACCESS_TOKEN extension:env".into(),
        "CLERK_SECRET_KEY extension:env".into(),
        "INFISICAL_TOKEN extension:env".into(),

        // ---- Database ----
        "DATABASE_URL extension:env".into(),
        "mongodb:// filename:.env".into(),
        "postgresql:// extension:env".into(),
        "mysql:// filename:.env".into(),
        "DB_PASSWORD extension:env".into(),
        "SNOWFLAKE_PASSWORD extension:env".into(),
        "DATABRICKS_TOKEN filename:.env".into(),
        "NEON_API_KEY filename:.env".into(),
        "PLANETSCALE_TOKEN filename:.env".into(),
        "SUPABASE_SERVICE_KEY extension:env".into(),

        // ---- SaaS & comms ----
        "xoxb- filename:.env".into(),
        "xoxp- extension:env".into(),
        "SLACK_TOKEN extension:env".into(),
        "sk_live_ filename:.env".into(),
        "sk_test_ extension:env".into(),
        "STRIPE_SECRET_KEY extension:env".into(),
        "SENTRY_AUTH_TOKEN extension:env".into(),
        "POSTHOG_API_KEY filename:.env".into(),
        "FIGMA_TOKEN filename:.env".into(),
        "DOPPLER_TOKEN filename:.env".into(),
        "SHOPIFY_ACCESS_TOKEN extension:env".into(),
        "shpat_ filename:.env".into(),
        "LARK_APP_SECRET extension:env".into(),
        "BRAVE_API_KEY extension:env".into(),
        "SALESFORCE_ACCESS_TOKEN extension:env".into(),
        "SALESFORCE_CLIENT_SECRET extension:env".into(),

        // ---- Registries ----
        "NPM_TOKEN extension:env".into(),
        "PYPI_TOKEN extension:env".into(),
        "DOCKER_PASSWORD extension:env".into(),
        "dckr_pat_ filename:.env".into(),

        // ---- Config file surface ----
        "API_KEY filename:docker-compose.yml".into(),
        "SECRET filename:docker-compose.yml".into(),
        "API_KEY extension:tfvars".into(),
        "JWT_SECRET filename:.env".into(),
        "SECRET_KEY_BASE extension:env".into(),

        // ---- Private keys ----
        "BEGIN RSA PRIVATE KEY extension:pem".into(),
        "BEGIN OPENSSH PRIVATE KEY extension:key".into(),
        "BEGIN PRIVATE KEY filename:id_rsa".into(),

        // ---- 2026 new AI providers ----
        "CEREBRAS_API_KEY extension:env".into(),
        "csk- filename:.env".into(),
        "OPENROUTER_API_KEY extension:env".into(),
        "sk-or- filename:.env".into(),
        "NVIDIA_API_KEY extension:env".into(),
        "nvapi- filename:.env".into(),
        "FIREWORKS_API_KEY extension:env".into(),
        "SILICONFLOW_API_KEY extension:env".into(),
        "MOONSHOT_API_KEY extension:env".into(),
        "KIMI_API_KEY extension:env".into(),
        "DEEPINFRA_API_KEY extension:env".into(),
        "CEREBRAS_API_KEY extension:ipynb".into(),
        "OPENROUTER_API_KEY extension:ipynb".into(),

        // ---- MCP config surface ----
        "mcpServers filename:claude_desktop_config.json".into(),
        "mcpServers filename:mcp.json".into(),
        "OPENAI_API_KEY filename:claude_desktop_config.json".into(),
        "ANTHROPIC_API_KEY filename:claude_desktop_config.json".into(),
        "GITHUB_TOKEN filename:claude_desktop_config.json".into(),
        "DATABASE_URL filename:claude_desktop_config.json".into(),
        "API_KEY filename:mcp.json".into(),

        // ---- GitHub Actions surface ----
        "OPENAI_API_KEY path:.github/workflows".into(),
        "AWS_ACCESS_KEY_ID path:.github/workflows".into(),
        "ANTHROPIC_API_KEY path:.github/workflows".into(),
        "API_KEY path:.github/workflows extension:yml".into(),

        // ---- Extended file surfaces ----
        "API_KEY extension:log".into(),
        "api_key extension:bak".into(),
        "api_key extension:backup".into(),
        "api_key extension:secret".into(),
        "api_key extension:envrc".into(),
        "api_key extension:conf".into(),
        "api_key extension:ini".into(),
        "export API_KEY extension:sh".into(),

        // ---- Shell / dotfile surface ----
        "_auth filename:.npmrc".into(),
        "auth filename:.dockercfg".into(),
        "password filename:.netrc".into(),
        "aws_access_key filename:.bash_history".into(),
        "AWS filename:.bash_profile".into(),

        // ---- Framework secret files ----
        "SECRET_KEY filename:settings.py".into(),
        "SECRET_KEY_BASE filename:secrets.yml".into(),
        "filename:master.key path:config".into(),
        "APP_KEY filename:.env".into(),
        "filename:prod.secret.exs".into(),

        // ---- Slack webhooks ----
        "hooks.slack.com/services/ extension:js".into(),
        "hooks.slack.com/services/ extension:py".into(),
        "hooks.slack.com/services/ filename:.env".into(),

        // ---- Composite path: multi-surface ----
        "sk-proj- path:*.yaml".into(),
        "sk-ant- path:*.yaml".into(),
        "AWS_ACCESS_KEY_ID path:*.conf".into(),
        "DATABASE_URL path:*.conf".into(),
        "BEGIN PRIVATE KEY path:*.txt".into(),
    ]
}

// ---------------------------------------------------------------------------
// Helper: return only the raw.githubusercontent dorks (for web-search routing)
// ---------------------------------------------------------------------------

pub fn get_raw_github_dorks() -> Vec<DorkPattern> {
    get_github_dorks()
        .into_iter()
        .filter(|d| matches!(d.source, DorkSource::RawGitHubContent))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_duplicate_queries() {
        let queries = get_advanced_github_queries();
        let unique: HashSet<&String> = queries.iter().collect();
        assert_eq!(
            queries.len(),
            unique.len(),
            "duplicate queries found in get_advanced_github_queries()"
        );
    }

    #[test]
    fn no_empty_queries() {
        for q in get_advanced_github_queries() {
            assert!(!q.trim().is_empty(), "empty query found");
        }
    }

    #[test]
    fn raw_dorks_are_separated() {
        let raw = get_raw_github_dorks();
        assert!(!raw.is_empty(), "no raw.githubusercontent dorks found");
        // Only the "Raw GitHub" category dorks must reference raw.githubusercontent.com.
        // "Google Broad" dorks are intentionally site-unrestricted.
        let raw_github: Vec<_> = raw.iter().filter(|d| d.category == "Raw GitHub").collect();
        assert!(!raw_github.is_empty(), "no Raw GitHub category dorks found");
        for d in &raw_github {
            assert!(
                d.query.contains("raw.githubusercontent.com"),
                "Raw GitHub dork doesn't reference raw.githubusercontent.com: {}",
                d.query
            );
        }
    }

    #[test]
    fn github_dorks_include_2026_providers() {
        let dorks = get_github_dorks();
        let all_queries: Vec<&str> = dorks.iter().map(|d| d.query.as_str()).collect();
        let combined = all_queries.join("\n");

        for provider in &[
            "TAVILY", "ELEVENLABS", "LARK", "SHOPIFY", "DATABRICKS",
            "NEON", "SENTRY", "POSTHOG", "DEEPSEEK",
            "WANDB", "STABILITY", "FAL", "TAILSCALE", "MAPBOX",
            "CLERK", "SALESFORCE", "NETLIFY",
            // 2026 additions
            "CEREBRAS", "OPENROUTER", "NVIDIA", "FIREWORKS",
            "SILICONFLOW", "MOONSHOT", "DEEPINFRA",
            "mcpServers", "hooks.slack.com",
        ] {
            assert!(
                combined.contains(provider),
                "2026 provider '{}' missing from dork catalogue",
                provider
            );
        }
    }

    #[test]
    fn jupyter_notebooks_covered() {
        let queries = get_advanced_github_queries();
        let has_ipynb = queries.iter().any(|q| q.contains("ipynb"));
        assert!(has_ipynb, "no Jupyter notebook (.ipynb) query found");
    }

    #[test]
    fn terraform_and_compose_covered() {
        let queries = get_advanced_github_queries();
        let q = queries.join("\n");
        assert!(q.contains("tfvars"), "Terraform .tfvars query missing");
        assert!(q.contains("docker-compose"), "docker-compose query missing");
    }
}
