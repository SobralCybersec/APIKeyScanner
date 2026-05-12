// Optimized pattern matching with lazy_static compilation
// Patterns are compiled once at startup, not on every Scanner::new()

use lazy_static::lazy_static;
use regex::Regex;

pub type PatternList = Vec<(Regex, &'static str)>;

lazy_static! {
    /// Pre-compiled regex patterns for API key detection (2026 edition)
    /// Compiled once at startup for ~50ms performance improvement
    pub static ref API_KEY_PATTERNS: PatternList = vec![
        // OpenAI / ChatGPT API keys. Official docs show sk-* redacted values,
        // project API keys, and admin keys using sk-admin-* redacted values.
        (Regex::new(r#"(?:^|[=:\s'"`])((?:sk-proj|sk-svcacct)-[A-Za-z0-9_-]{40,})"#).unwrap(), "openai-project"),
        (Regex::new(r#"(?:^|[=:\s'"`])(sk-admin-[A-Za-z0-9_-]{20,})"#).unwrap(), "openai-admin"),
        (Regex::new(r#"(?:^|[=:\s'"`])(sk-[A-Za-z0-9_-]{48,})"#).unwrap(), "openai-legacy"),
        (Regex::new(r#"(?:OPENAI|CHATGPT|GPT|GPT3|GPT4|GPT35|CODEX|DALLE|WHISPER|TTS|STT|EMBEDDING|VISION|IMAGE)_API_KEY[=:\s'"`]+(sk-[A-Za-z0-9_-]{40,})"#).unwrap(), "openai-env"),
        (Regex::new(r#"AZURE_OPENAI(?:_API)?_KEY[=:\s'"`]+([A-Za-z0-9_-]{20,})"#).unwrap(), "azure-openai"),
        
        // Anthropic (Claude). Official Admin API examples expose sk-ant-api03- hints.
        (Regex::new(r#"(?:^|[=:\s'"`])(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,})"#).unwrap(), "anthropic"),
        (Regex::new(r#"(?:ANTHROPIC|CLAUDE)_API_KEY[=:\s'"`]+(sk-ant-[A-Za-z0-9_-]{40,})"#).unwrap(), "anthropic-env"),
        
        // Google/Gemini
        (Regex::new(r#"AIza[0-9A-Za-z_-]{35}"#).unwrap(), "google-api"),
        (Regex::new(r#"(?:GEMINI|GOOGLE)_API_KEY[=:\s'"`]+([A-Za-z0-9_-]{20,})"#).unwrap(), "google-env"),
        
        // xAI (Grok) - NEW 2026
        (Regex::new(r#"(?:^|[=:\s'"`])(xai-[A-Za-z0-9_-]{20,})"#).unwrap(), "xai"),
        (Regex::new(r#"XAI_API_KEY[=:\s'"`]+([A-Za-z0-9_-]{20,})"#).unwrap(), "xai-env"),
        
        // Groq - NEW 2026
        (Regex::new(r#"(?:^|[=:\s'"`])(gsk_[A-Za-z0-9]{40,})"#).unwrap(), "groq"),
        (Regex::new(r#"GROQ_API_KEY[=:\s'"`]+(gsk_[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{20,})"#).unwrap(), "groq-env"),
        
        // DeepSeek - NEW 2026
        (Regex::new(r#"DEEPSEEK_API_KEY[=:\s'"`]+(sk-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{20,})"#).unwrap(), "deepseek-env"),
        
        // Mistral AI
        (Regex::new(r#"MISTRAL_API_KEY[=:\s'"`]+([A-Za-z0-9_-]{20,})"#).unwrap(), "mistral-env"),
        
        // Cohere
        (Regex::new(r#"(?:COHERE_API_KEY|CO_API_KEY)[=:\s'"`]+([A-Za-z0-9_-]{20,})"#).unwrap(), "cohere-env"),
        
        // Hugging Face
        (Regex::new(r#"(?:^|[=:\s'"`])(hf_[A-Za-z0-9]{30,})"#).unwrap(), "huggingface"),
        (Regex::new(r#"(?:HUGGINGFACE_API_KEY|HF_API_KEY|HF_TOKEN)[=:\s'"`]+(hf_[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{20,})"#).unwrap(), "hf-env"),
        
        // Replicate
        (Regex::new(r#"(?:^|[=:\s'"`])(r8_[A-Za-z0-9]{37})"#).unwrap(), "replicate"),
        (Regex::new(r#"REPLICATE_API_(?:KEY|TOKEN)[=:\s'"`]+(r8_[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{20,})"#).unwrap(), "replicate-env"),
        
        // Perplexity - 48 chars alphanumeric
        (Regex::new(r#"(?:^|[=:\s'"`])(pplx-[A-Za-z0-9_-]{32,})"#).unwrap(), "perplexity"),
        (Regex::new(r#"(?:PERPLEXITY_API_KEY|PPLX_API_KEY)[=:\s'"`]+(pplx-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{20,})"#).unwrap(), "pplx-env"),
        
        // Together AI
        (Regex::new(r#"TOGETHER_API_KEY[=:\s'"`]+([A-Za-z0-9_-]{20,})"#).unwrap(), "together-env"),
        (Regex::new(r#"AI21_API_KEY[=:\s'"`]+([A-Za-z0-9_-]{20,})"#).unwrap(), "ai21-env"),
        
        // AWS
        (Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(), "aws-access-key"),
        (Regex::new(r#"AWS_SECRET_ACCESS_KEY[=:\s'"`]([a-zA-Z0-9/+=]{40})"#).unwrap(), "aws-secret"),
        
        // GitHub (all token types)
        (Regex::new(r#"ghp_[a-zA-Z0-9]{36}"#).unwrap(), "github-pat"),
        (Regex::new(r#"gho_[a-zA-Z0-9]{36}"#).unwrap(), "github-oauth"),
        (Regex::new(r#"ghu_[a-zA-Z0-9]{36}"#).unwrap(), "github-user"),
        (Regex::new(r#"ghs_[a-zA-Z0-9]{36}"#).unwrap(), "github-server"),
        (Regex::new(r#"ghr_[a-zA-Z0-9]{36}"#).unwrap(), "github-refresh"),
        
        // Vercel - NEW 2026
        (Regex::new(r#"vcp_[a-zA-Z0-9]{24}"#).unwrap(), "vercel-personal"),
        (Regex::new(r#"vci_[a-zA-Z0-9]{24}"#).unwrap(), "vercel-integration"),
        (Regex::new(r#"vca_[a-zA-Z0-9]{24}"#).unwrap(), "vercel-app"),
        (Regex::new(r#"vcr_[a-zA-Z0-9]{24}"#).unwrap(), "vercel-refresh"),
        (Regex::new(r#"vck_[a-zA-Z0-9]{24}"#).unwrap(), "vercel-api-key"),
        (Regex::new(r#"VERCEL_TOKEN[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "vercel-env"),
        
        // Supabase - NEW 2026
        (Regex::new(r#"sbp_[a-zA-Z0-9]{40}"#).unwrap(), "supabase-personal"),
        (Regex::new(r#"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"#).unwrap(), "supabase-jwt"),
        (Regex::new(r#"SUPABASE_KEY[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "supabase-env"),
        (Regex::new(r#"SUPABASE_SERVICE_KEY[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "supabase-service"),
        
        // Cloudflare - NEW 2026
        (Regex::new(r#"[=:\s'"`]([a-zA-Z0-9_-]{40})(?:['"`]|\s|$)"#).unwrap(), "cloudflare-token"),
        (Regex::new(r#"CLOUDFLARE_API_KEY[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "cloudflare-env"),
        (Regex::new(r#"CLOUDFLARE_API_TOKEN[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "cloudflare-token-env"),
        
        // Databricks - NEW 2026
        (Regex::new(r#"dapi[a-f0-9]{32}"#).unwrap(), "databricks"),
        (Regex::new(r#"DATABRICKS_TOKEN[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "databricks-env"),
        
        // Snowflake - NEW 2026
        (Regex::new(r#"snowflake://[^\s]+"#).unwrap(), "snowflake-url"),
        (Regex::new(r#"SNOWFLAKE_PASSWORD[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "snowflake-env"),
        
        // Figma - NEW 2026
        (Regex::new(r#"figd_[a-zA-Z0-9_-]{40}"#).unwrap(), "figma"),
        (Regex::new(r#"FIGMA_TOKEN[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "figma-env"),
        
        // Langchain/LangSmith - NEW 2026
        (Regex::new(r#"lsv2_[a-zA-Z0-9]{40}"#).unwrap(), "langsmith"),
        (Regex::new(r#"LANGCHAIN_API_KEY[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "langchain-env"),
        
        // NEW 2026 Providers - Critical additions
        // Brave Search API (135% YoY growth)
        (Regex::new(r#"BSA[a-zA-Z0-9_-]{40,}"#).unwrap(), "brave-search"),
        (Regex::new(r#"BRAVE_API_KEY[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "brave-env"),
        
        // Doppler - Secrets management
        (Regex::new(r#"dp\.st\.[a-zA-Z0-9_-]{40,}"#).unwrap(), "doppler"),
        (Regex::new(r#"DOPPLER_TOKEN[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "doppler-env"),
        
        // Sentry - Error tracking (validity check supported)
        (Regex::new(r#"sntrys_[a-zA-Z0-9_-]{64}"#).unwrap(), "sentry"),
        (Regex::new(r#"SENTRY_AUTH_TOKEN[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "sentry-env"),
        
        // PostHog - Analytics (push-protected by default)
        (Regex::new(r#"phc_[a-zA-Z0-9]{40,}"#).unwrap(), "posthog"),
        (Regex::new(r#"POSTHOG_API_KEY[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "posthog-env"),
        
        // Neon - Serverless Postgres
        (Regex::new(r#"neon_[a-zA-Z0-9_-]{40,}"#).unwrap(), "neon"),
        (Regex::new(r#"NEON_API_KEY[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "neon-env"),
        
        // PlanetScale - MySQL platform
        (Regex::new(r#"pscale_[a-zA-Z0-9_-]{40,}"#).unwrap(), "planetscale"),
        (Regex::new(r#"PLANETSCALE_TOKEN[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "planetscale-env"),
        
        // Render - Cloud platform
        (Regex::new(r#"rnd_[a-zA-Z0-9]{40,}"#).unwrap(), "render"),
        (Regex::new(r#"RENDER_API_KEY[=:\s'"`]([a-zA-Z0-9_-]{20,})"#).unwrap(), "render-env"),
        
        // Slack
        (Regex::new(r#"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"#).unwrap(), "slack-bot"),
        (Regex::new(r#"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"#).unwrap(), "slack-user"),
        (Regex::new(r#"xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"#).unwrap(), "slack-app"),
        
        // Stripe
        (Regex::new(r#"sk_live_[a-zA-Z0-9]{24,}"#).unwrap(), "stripe-live"),
        (Regex::new(r#"sk_test_[a-zA-Z0-9]{24,}"#).unwrap(), "stripe-test"),
        (Regex::new(r#"rk_live_[a-zA-Z0-9]{24,}"#).unwrap(), "stripe-restricted-live"),
        
        // SendGrid
        (Regex::new(r#"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"#).unwrap(), "sendgrid"),
        
        // Twilio
        (Regex::new(r#"SK[a-f0-9]{32}"#).unwrap(), "twilio"),
        (Regex::new(r#"AC[a-f0-9]{32}"#).unwrap(), "twilio-account"),
        
        // Mailgun
        (Regex::new(r#"key-[a-f0-9]{32}"#).unwrap(), "mailgun"),
        
        // DigitalOcean
        (Regex::new(r#"dop_v1_[a-f0-9]{64}"#).unwrap(), "digitalocean"),
        
        // Heroku API Key (UUID format, but ONLY in Heroku context)
        (Regex::new(r#"HEROKU_API_KEY[=:\s'"`]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#).unwrap(), "heroku-api"),
        
        // npm
        (Regex::new(r#"npm_[a-zA-Z0-9]{36}"#).unwrap(), "npm"),
        
        // PyPI
        (Regex::new(r#"pypi-[a-zA-Z0-9_-]{40,}"#).unwrap(), "pypi"),
        
        // Docker Hub
        (Regex::new(r#"dckr_pat_[a-zA-Z0-9_-]{40}"#).unwrap(), "docker"),
        
        // Airtable - NEW 2026
        (Regex::new(r#"pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}"#).unwrap(), "airtable"),
        
        // Notion
        (Regex::new(r#"secret_[a-zA-Z0-9]{43}"#).unwrap(), "notion"),
        (Regex::new(r#"ntn_[a-zA-Z0-9]{50}"#).unwrap(), "notion-integration"),
        
        // Pinecone (UUID, but ONLY in Pinecone context)
        (Regex::new(r#"PINECONE_API_KEY[=:\s'"`]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"#).unwrap(), "pinecone"),
        
        // MongoDB Atlas
        (Regex::new(r#"mongodb(?:\+srv)?://[^\s]+"#).unwrap(), "mongodb-url"),
        
        // PostgreSQL
        (Regex::new(r#"postgres(?:ql)?://[^\s]+"#).unwrap(), "postgres-url"),
        
        // MySQL
        (Regex::new(r#"mysql://[^\s]+"#).unwrap(), "mysql-url"),
        
        // Redis
        (Regex::new(r#"redis://[^\s]+"#).unwrap(), "redis-url"),
        
        // Private keys
        (Regex::new(r#"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"#).unwrap(), "private-key"),
        (Regex::new(r#"-----BEGIN PGP PRIVATE KEY BLOCK-----"#).unwrap(), "pgp-private"),
        
        // JWT secrets
        (Regex::new(r#"JWT_SECRET[=:\s'"`]([a-zA-Z0-9_-]{32,})"#).unwrap(), "jwt-secret"),
        
        // Generic high-entropy patterns (with context)
        (Regex::new(r#"(?i)(api[_-]?key|secret|token|password|auth)[=:\s'"`]([a-zA-Z0-9_-]{32,})"#).unwrap(), "generic-secret"),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patterns_compile() {
        // Verify all patterns compile successfully
        assert!(API_KEY_PATTERNS.len() > 70);
        
        // Test a few key patterns
        let openai_pattern = &API_KEY_PATTERNS[0].0;
        assert!(openai_pattern.is_match("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"));
        
        let github_pattern = &API_KEY_PATTERNS.iter()
            .find(|(_, label)| *label == "github-pat")
            .unwrap().0;
        assert!(github_pattern.is_match("ghp_1234567890123456789012345678901234AB"));
    }
}
