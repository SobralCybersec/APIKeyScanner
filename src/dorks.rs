// Google Dork patterns for GitHub secret scanning
// Based on 2026 OSINT research and bug bounty methodologies

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DorkPattern {
    pub name: String,
    pub query: String,
    pub category: String,
    pub risk_level: String,
}

pub fn get_github_dorks() -> Vec<DorkPattern> {
    vec![
        // OpenAI Keys (2026 patterns)
        DorkPattern {
            name: "OpenAI sk-proj keys in env files".to_string(),
            query: "sk-proj- filename:.env".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "OpenAI keys in Python".to_string(),
            query: "sk-proj- extension:py".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "OpenAI keys in JavaScript".to_string(),
            query: "sk-proj- extension:js".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "OpenAI API key env vars".to_string(),
            query: "OPENAI_API_KEY extension:env".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "ChatGPT/OpenAI aliases".to_string(),
            query: "(CHATGPT_API_KEY OR GPT_API_KEY OR CODEX_API_KEY) extension:env".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "OpenAI admin/service keys".to_string(),
            query: "(sk-admin- OR sk-svcacct-) extension:env".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        
        // Anthropic Keys
        DorkPattern {
            name: "Anthropic API keys".to_string(),
            query: "ANTHROPIC_API_KEY extension:env".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "Anthropic sk- keys".to_string(),
            query: "sk-ant- extension:py".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "Claude API aliases".to_string(),
            query: "CLAUDE_API_KEY extension:env".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        
        // 2026 AI providers
        DorkPattern {
            name: "Groq API keys".to_string(),
            query: "(GROQ_API_KEY OR gsk_) extension:env".to_string(),
            category: "AI Providers".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "DeepSeek API keys".to_string(),
            query: "DEEPSEEK_API_KEY extension:env".to_string(),
            category: "AI Providers".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "Mistral API keys".to_string(),
            query: "MISTRAL_API_KEY extension:env".to_string(),
            category: "AI Providers".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "Perplexity API keys".to_string(),
            query: "(PERPLEXITY_API_KEY OR PPLX_API_KEY OR pplx-) extension:env".to_string(),
            category: "AI Providers".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "Together AI keys".to_string(),
            query: "TOGETHER_API_KEY extension:env".to_string(),
            category: "AI Providers".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "Replicate tokens".to_string(),
            query: "(REPLICATE_API_TOKEN OR r8_) extension:env".to_string(),
            category: "AI Providers".to_string(),
            risk_level: "Critical".to_string(),
        },
        
        // Google/Gemini Keys
        DorkPattern {
            name: "Google API keys".to_string(),
            query: "GOOGLE_API_KEY extension:env".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "Gemini API keys".to_string(),
            query: "GEMINI_API_KEY extension:env".to_string(),
            category: "API Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        
        // AWS Keys
        DorkPattern {
            name: "AWS access keys in env".to_string(),
            query: "AWS_ACCESS_KEY_ID extension:env".to_string(),
            category: "Cloud Credentials".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "AWS secret keys".to_string(),
            query: "AWS_SECRET_ACCESS_KEY extension:env".to_string(),
            category: "Cloud Credentials".to_string(),
            risk_level: "Critical".to_string(),
        },
        
        // GitHub Tokens
        DorkPattern {
            name: "GitHub personal access tokens".to_string(),
            query: "ghp_ extension:env".to_string(),
            category: "GitHub Tokens".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "GitHub OAuth tokens".to_string(),
            query: "gho_ extension:txt".to_string(),
            category: "GitHub Tokens".to_string(),
            risk_level: "Critical".to_string(),
        },
        
        // Database Credentials
        DorkPattern {
            name: "Database passwords in env".to_string(),
            query: "DB_PASSWORD extension:env".to_string(),
            category: "Database".to_string(),
            risk_level: "High".to_string(),
        },
        DorkPattern {
            name: "MongoDB connection strings".to_string(),
            query: "mongodb:// extension:env".to_string(),
            category: "Database".to_string(),
            risk_level: "High".to_string(),
        },
        
        // Private Keys
        DorkPattern {
            name: "RSA private keys".to_string(),
            query: "BEGIN RSA PRIVATE KEY extension:pem".to_string(),
            category: "Private Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        DorkPattern {
            name: "SSH private keys".to_string(),
            query: "BEGIN OPENSSH PRIVATE KEY extension:key".to_string(),
            category: "Private Keys".to_string(),
            risk_level: "Critical".to_string(),
        },
        
        // Config Files
        DorkPattern {
            name: "Exposed .env files".to_string(),
            query: "API filename:.env".to_string(),
            category: "Config Files".to_string(),
            risk_level: "High".to_string(),
        },
        DorkPattern {
            name: "Config with secrets".to_string(),
            query: "secret extension:json".to_string(),
            category: "Config Files".to_string(),
            risk_level: "High".to_string(),
        },
        
        // Backup Files
        DorkPattern {
            name: "Backup files with credentials".to_string(),
            query: "password extension:bak".to_string(),
            category: "Backups".to_string(),
            risk_level: "Medium".to_string(),
        },
        DorkPattern {
            name: "SQL dumps".to_string(),
            query: "INSERT INTO users extension:sql".to_string(),
            category: "Backups".to_string(),
            risk_level: "High".to_string(),
        },
    ]
}

pub fn get_advanced_github_queries() -> Vec<String> {
    vec![
        // OpenAI API keys (2026 patterns: sk-proj-, sk-svcacct-)
        "sk-proj- filename:.env".to_string(),
        "sk-proj- extension:py".to_string(),
        "sk-proj- extension:js".to_string(),
        "sk-proj- extension:ts".to_string(),
        "sk-svcacct- filename:.env".to_string(),
        "sk-admin- filename:.env".to_string(),
        "OPENAI_API_KEY extension:env".to_string(),
        "CHATGPT_API_KEY extension:env".to_string(),
        "CODEX_API_KEY extension:env".to_string(),
        "GPT_API_KEY extension:env".to_string(),
        
        // Anthropic API keys (sk-ant-)
        "sk-ant- filename:.env".to_string(),
        "sk-ant- extension:py".to_string(),
        "sk-ant- extension:js".to_string(),
        "ANTHROPIC_API_KEY extension:env".to_string(),
        "CLAUDE_API_KEY extension:env".to_string(),
        
        // 2026 AI providers
        "GROQ_API_KEY extension:env".to_string(),
        "gsk_ filename:.env".to_string(),
        "DEEPSEEK_API_KEY extension:env".to_string(),
        "MISTRAL_API_KEY extension:env".to_string(),
        "COHERE_API_KEY extension:env".to_string(),
        "CO_API_KEY extension:env".to_string(),
        "HF_TOKEN extension:env".to_string(),
        "HUGGINGFACE_API_KEY extension:env".to_string(),
        "REPLICATE_API_TOKEN extension:env".to_string(),
        "r8_ filename:.env".to_string(),
        "PERPLEXITY_API_KEY extension:env".to_string(),
        "PPLX_API_KEY extension:env".to_string(),
        "TOGETHER_API_KEY extension:env".to_string(),
        "AI21_API_KEY extension:env".to_string(),
        "XAI_API_KEY extension:env".to_string(),
        
        // GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
        "ghp_ filename:.env".to_string(),
        "ghp_ extension:txt".to_string(),
        "gho_ filename:.env".to_string(),
        "ghs_ extension:yaml".to_string(),
        "GITHUB_TOKEN extension:env".to_string(),
        
        // AWS credentials
        "AWS_ACCESS_KEY_ID filename:.env".to_string(),
        "AWS_SECRET_ACCESS_KEY filename:.env".to_string(),
        "AKIA extension:env".to_string(),
        "aws_access_key_id extension:yaml".to_string(),
        
        // Google/Gemini API keys
        "GOOGLE_API_KEY filename:.env".to_string(),
        "GEMINI_API_KEY extension:env".to_string(),
        "AIza extension:js".to_string(),
        
        // Azure OpenAI keys (2026 pattern)
        "azure_openai_key filename:.env".to_string(),
        "AZURE_OPENAI_KEY extension:yaml".to_string(),
        
        // Database connection strings
        "mongodb:// filename:.env".to_string(),
        "postgresql:// extension:env".to_string(),
        "mysql:// filename:.env".to_string(),
        "DATABASE_URL extension:env".to_string(),
        
        // Private keys (high-precision patterns)
        "BEGIN RSA PRIVATE KEY extension:pem".to_string(),
        "BEGIN OPENSSH PRIVATE KEY extension:key".to_string(),
        "BEGIN PRIVATE KEY filename:id_rsa".to_string(),
        
        // Slack tokens
        "xoxb- filename:.env".to_string(),
        "xoxp- extension:env".to_string(),
        "SLACK_TOKEN extension:env".to_string(),
        
        // Stripe keys
        "sk_live_ filename:.env".to_string(),
        "sk_test_ extension:env".to_string(),
        "STRIPE_SECRET_KEY extension:env".to_string(),
        
        // JWT secrets
        "JWT_SECRET filename:.env".to_string(),
        "SECRET_KEY_BASE extension:env".to_string(),
        
        // 2026 new providers (from GitHub March 2026 update)
        "DEEPSEEK_API_KEY extension:env".to_string(),
        "PINECONE_API_KEY filename:.env".to_string(),
        "SENTRY_AUTH_TOKEN extension:env".to_string(),
        "POSTHOG_API_KEY filename:.env".to_string(),
        "SUPABASE_SERVICE_KEY extension:env".to_string(),
        "VERCEL_TOKEN filename:.env".to_string(),
        "SNOWFLAKE_PASSWORD extension:env".to_string(),
        "DATABRICKS_TOKEN filename:.env".to_string(),
    ]
}
