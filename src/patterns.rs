//! API key / secret regex patterns.
//!
//! Design rules (applied consistently):
//!
//! 1. Every capture group captures **only** the credential, not surrounding
//!    punctuation.  `extract_secret_match` in `main.rs` picks the last
//!    non-empty capture group, so multi-group patterns work fine.
//!
//! 2. Patterns are ordered from most-specific (fewest false positives) to
//!    least-specific.  The scanner breaks after the first match per line, so
//!    order matters for performance.
//!
//! 3. The old `cloudflare-token` generic 40-char pattern has been replaced
//!    with a context-anchored version — it was the single largest source of
//!    false positives in the codebase.
//!
//! 4. All patterns have been validated against ReDoS: no unbounded nested
//!    quantifiers, no catastrophic backtracking paths.
//!
//! 5. `raw.githubusercontent.com` URL patterns are included so the tarball
//!    scanner can detect embedded fetch/curl calls that expose credentials
//!    via raw file URLs.

use regex::Regex;
use std::sync::LazyLock;

pub type PatternList = Vec<(Regex, &'static str)>;

/// Compile a pattern, panicking at startup with a descriptive message on
/// failure (same behaviour as the previous `.unwrap()` calls, but clearer).
macro_rules! pat {
    ($re:expr, $label:expr) => {
        (
            Regex::new($re).unwrap_or_else(|e| {
                panic!("Failed to compile pattern for '{}': {}", $label, e)
            }),
            $label,
        )
    };
}

pub static API_KEY_PATTERNS: LazyLock<PatternList> = LazyLock::new(|| {
    vec![
        // ----------------------------------------------------------------
        // OpenAI / ChatGPT
        // ----------------------------------------------------------------
        // Canonical 2025+ format: T3BlbkFJ watermark embedded in the key
        pat!(
            r#"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,74}T3BlbkFJ[A-Za-z0-9_-]{20,74})\b"#,
            "openai-canonical"
        ),
        // Project / service-account keys  (sk-proj-*, sk-svcacct-*)
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])((sk-proj|sk-svcacct)-[A-Za-z0-9_-]{20,})"#,
            "openai-project"
        ),
        // Admin keys  (sk-admin-*)
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(sk-admin-[A-Za-z0-9_-]{20,})"#,
            "openai-admin"
        ),
        // Legacy sk- keys  (≥48 chars to reduce overlap with other sk- issuers)
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(sk-[A-Za-z0-9_-]{48,})"#,
            "openai-legacy"
        ),
        // Named env vars — broad family
        pat!(
            r#"(?:OPENAI|CHATGPT|GPT3?4?|GPT35|CODEX|DALLE|WHISPER|TTS|STT|EMBEDDING|VISION|IMAGE)_API_KEY\s*[=:]\s*['"`]?(sk-[A-Za-z0-9_-]{40,})"#,
            "openai-env"
        ),
        pat!(
            r#"(?:OPENAI|CHATGPT|GPT3?4?|GPT35|CODEX|DALLE|WHISPER|TTS|STT|EMBEDDING|VISION|IMAGE)_(?:KEY|TOKEN)\s*[=:]\s*['"`]?(sk-[A-Za-z0-9_-]{20,})"#,
            "openai-env-alias"
        ),
        pat!(
            r#"OPENAI_(?:PROJECT|SERVICE_ACCOUNT|SVCACCT)(?:_API)?_KEY\s*[=:]\s*['"`]?((sk-proj|sk-svcacct)-[A-Za-z0-9_-]{20,})"#,
            "openai-project-env"
        ),
        pat!(
            r#"OPENAI_ADMIN(?:_API)?_(?:KEY|TOKEN)\s*[=:]\s*['"`]?(sk-admin-[A-Za-z0-9_-]{20,})"#,
            "openai-admin-env"
        ),
        // Azure OpenAI (32-hex key format)
        pat!(
            r#"AZURE_OPENAI(?:_API)?_KEY\s*[=:]\s*['"`]?([A-Fa-f0-9]{32})"#,
            "azure-openai"
        ),
        // Azure AI Services (Cognitive Services, Form Recognizer, etc.)
        pat!(
            r#"AZURE_(?:COGNITIVE|AI|FORM_RECOGNIZER|COMPUTER_VISION|TEXT_ANALYTICS)_KEY\s*[=:]\s*['"`]?([A-Fa-f0-9]{32})"#,
            "azure-ai"
        ),

        // ----------------------------------------------------------------
        // Anthropic (Claude)
        // ----------------------------------------------------------------
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(sk-ant-[A-Za-z0-9_-]{20,})"#,
            "anthropic"
        ),
        pat!(
            r#"(?:ANTHROPIC|CLAUDE)(?:_API)?_(?:KEY|TOKEN)\s*[=:]\s*['"`]?(sk-ant-[A-Za-z0-9_-]{20,})"#,
            "anthropic-env"
        ),
        pat!(
            r#"CLAUDE_CODE_API_KEY\s*[=:]\s*['"`]?(sk-ant-[A-Za-z0-9_-]{20,})"#,
            "anthropic-claude-code-env"
        ),
        // Anthropic Admin API key (org management — added 2025)
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(sk-ant-admin-[A-Za-z0-9_-]{20,})"#,
            "anthropic-admin"
        ),
        pat!(
            r#"ANTHROPIC_ADMIN(?:_API)?_KEY\s*[=:]\s*['"`]?(sk-ant-admin-[A-Za-z0-9_-]{20,})"#,
            "anthropic-admin-env"
        ),
        // Anthropic session ID (short-lived, browser-issued)
        pat!(
            r#"ANTHROPIC_SESSION_ID\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "anthropic-session"
        ),

        // ----------------------------------------------------------------
        // Google / Gemini
        // ----------------------------------------------------------------
        // AIza* is specific enough to match without context
        pat!(r#"AIza[0-9A-Za-z_-]{35}"#, "google-api"),
        // OAuth2 bearer — long prefix ensures low FP rate
        pat!(r#"ya29\.[0-9A-Za-z_-]{80,}"#, "google-oauth"),
        pat!(
            r#"(?:GEMINI|GOOGLE)_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "google-env"
        ),

        // ----------------------------------------------------------------
        // xAI (Grok)
        // ----------------------------------------------------------------
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(xai-[A-Za-z0-9_-]{20,})"#,
            "xai"
        ),
        pat!(
            r#"XAI_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "xai-env"
        ),

        // ----------------------------------------------------------------
        // Groq  — gsk_ prefix + exactly 52 alphanumeric chars
        // ----------------------------------------------------------------
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(gsk_[A-Za-z0-9]{52})"#,
            "groq"
        ),
        pat!(
            r#"GROQ_API_KEY\s*[=:]\s*['"`]?(gsk_[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{20,})"#,
            "groq-env"
        ),

        // ----------------------------------------------------------------
        // DeepSeek
        // ----------------------------------------------------------------
        pat!(
            r#"DEEPSEEK_API_KEY\s*[=:]\s*['"`]?(sk-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{20,})"#,
            "deepseek-env"
        ),

        // ----------------------------------------------------------------
        // Mistral AI
        // ----------------------------------------------------------------
        pat!(
            r#"MISTRAL_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "mistral-env"
        ),

        // ----------------------------------------------------------------
        // Cohere
        // ----------------------------------------------------------------
        pat!(
            r#"(?:COHERE_API_KEY|CO_API_KEY)\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "cohere-env"
        ),

        // ----------------------------------------------------------------
        // Hugging Face  — hf_ prefix is canonical
        // ----------------------------------------------------------------
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(hf_[A-Za-z0-9]{30,})"#,
            "huggingface"
        ),
        pat!(
            r#"(?:HUGGINGFACE_API_KEY|HF_API_KEY|HF_TOKEN)\s*[=:]\s*['"`]?(hf_[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{20,})"#,
            "hf-env"
        ),

        // ----------------------------------------------------------------
        // Replicate  — r8_ prefix
        // ----------------------------------------------------------------
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(r8_[A-Za-z0-9]{37})"#,
            "replicate"
        ),
        pat!(
            r#"REPLICATE_API_(?:KEY|TOKEN)\s*[=:]\s*['"`]?(r8_[A-Za-z0-9]{20,}|[A-Za-z0-9_-]{20,})"#,
            "replicate-env"
        ),

        // ----------------------------------------------------------------
        // Perplexity  — pplx- prefix
        // ----------------------------------------------------------------
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(pplx-[A-Za-z0-9_-]{32,})"#,
            "perplexity"
        ),
        pat!(
            r#"(?:PERPLEXITY_API_KEY|PPLX_API_KEY)\s*[=:]\s*['"`]?(pplx-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{20,})"#,
            "pplx-env"
        ),

        // ----------------------------------------------------------------
        // Together AI / AI21
        // ----------------------------------------------------------------
        pat!(
            r#"TOGETHER_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "together-env"
        ),
        pat!(
            r#"AI21_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "ai21-env"
        ),

        // ----------------------------------------------------------------
        // Tavily (search API, popular in AI agents — 2026)
        // ----------------------------------------------------------------
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(tvly-[A-Za-z0-9_-]{32,})"#,
            "tavily"
        ),
        pat!(
            r#"TAVILY_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "tavily-env"
        ),

        // ----------------------------------------------------------------
        // ElevenLabs (voice AI — heavy usage in 2026 AI apps)
        // ----------------------------------------------------------------
        pat!(
            r#"(?:^|[=:\s'"` ,(\[{])(el_[A-Za-z0-9_-]{32,})"#,
            "elevenlabs"
        ),
        pat!(
            r#"ELEVENLABS_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "elevenlabs-env"
        ),

        // ----------------------------------------------------------------
        // AWS
        // ----------------------------------------------------------------
        // AKIA + 16 uppercase alphanumeric
        pat!(r#"AKIA[0-9A-Z]{16}"#, "aws-access-key"),
        // Secret must follow the access key (40-char base64-like)
        pat!(
            r#"AWS_SECRET_ACCESS_KEY\s*[=:]\s*['"`]?([a-zA-Z0-9/+=]{40})"#,
            "aws-secret"
        ),

        // ----------------------------------------------------------------
        // GitHub tokens — all canonical prefixes
        // ----------------------------------------------------------------
        pat!(r#"ghp_[a-zA-Z0-9]{36}"#, "github-pat"),
        pat!(r#"gho_[a-zA-Z0-9]{36}"#, "github-oauth"),
        pat!(r#"ghu_[a-zA-Z0-9]{36}"#, "github-user"),
        // Legacy short ghs_ (36 chars) and new stateless long format (~520 chars, 2026)
        pat!(r#"ghs_[a-zA-Z0-9]{36}"#, "github-server"),
        pat!(r#"ghs_[A-Za-z0-9_-]{100,}"#, "github-server-stateless"),
        pat!(r#"ghr_[a-zA-Z0-9]{36}"#, "github-refresh"),
        // Fine-grained PAT (github_pat_ + 82+ chars)
        pat!(r#"github_pat_[A-Za-z0-9_]{82,}"#, "github-fine-grained"),

        // ----------------------------------------------------------------
        // Vercel  — six token types added March 2026
        // ----------------------------------------------------------------
        pat!(r#"vcp_[a-zA-Z0-9]{24}"#, "vercel-personal"),
        pat!(r#"vci_[a-zA-Z0-9]{24}"#, "vercel-integration"),
        pat!(r#"vca_[a-zA-Z0-9]{24}"#, "vercel-app"),
        pat!(r#"vcr_[a-zA-Z0-9]{24}"#, "vercel-refresh"),
        pat!(r#"vck_[a-zA-Z0-9]{24}"#, "vercel-api-key"),
        // Support access token (also added Feb 2026)
        pat!(r#"vcs_[a-zA-Z0-9]{24}"#, "vercel-support"),
        pat!(
            r#"VERCEL_TOKEN\s*[=:]\s*['"`]?([a-zA-Z0-9_-]{20,})"#,
            "vercel-env"
        ),

        // ----------------------------------------------------------------
        // Supabase
        // ----------------------------------------------------------------
        pat!(r#"sbp_[a-zA-Z0-9]{40}"#, "supabase-personal"),
        // Publishable anon key (sb_publishable_ prefix, 2026)
        pat!(r#"sb_publishable_[a-zA-Z0-9_-]{20,}"#, "supabase-publishable"),
        // JWT tokens (service role / anon keys) — anchored base64url segments
        pat!(
            r#"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"#,
            "supabase-jwt"
        ),
        pat!(
            r#"SUPABASE_(?:SERVICE_ROLE_)?KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "supabase-env"
        ),
        pat!(
            r#"SUPABASE_SERVICE_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "supabase-service"
        ),

        // ----------------------------------------------------------------
        // Cloudflare
        //
        // The old generic 40-char pattern was the #1 FP generator.
        // Replaced with context-anchored versions only.
        // ----------------------------------------------------------------
        pat!(
            r#"CLOUDFLARE_(?:API_KEY|API_TOKEN|AUTH_KEY)\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "cloudflare-env"
        ),
        // Account-scoped token: CF_ prefix used by workers / wrangler
        pat!(
            r#"CF_(?:API_TOKEN|TOKEN)\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "cloudflare-wrangler"
        ),
        // Workers AI gateway token (cfut_ prefix, 2026)
        pat!(r#"cfut_[a-zA-Z0-9_-]{32,}"#, "cloudflare-workers-ai"),

        // ----------------------------------------------------------------
        // Databricks
        // ----------------------------------------------------------------
        // dapi + 32 hex chars
        pat!(r#"dapi[a-f0-9]{32}"#, "databricks"),
        pat!(
            r#"DATABRICKS_TOKEN\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "databricks-env"
        ),

        // ----------------------------------------------------------------
        // Snowflake
        // ----------------------------------------------------------------
        pat!(r#"snowflake://[^\s'"`,]+"#, "snowflake-url"),
        pat!(
            r#"SNOWFLAKE_PASSWORD\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "snowflake-env"
        ),

        // ----------------------------------------------------------------
        // Figma
        // ----------------------------------------------------------------
        pat!(r#"figd_[a-zA-Z0-9_-]{40}"#, "figma"),
        pat!(
            r#"FIGMA_(?:API_)?TOKEN\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "figma-env"
        ),

        // ----------------------------------------------------------------
        // LangChain / LangSmith
        // ----------------------------------------------------------------
        pat!(r#"lsv2_[a-zA-Z0-9]{40}"#, "langsmith"),
        pat!(
            r#"LANGCHAIN_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "langchain-env"
        ),
        pat!(
            r#"LANGSMITH_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "langsmith-env"
        ),

        // ----------------------------------------------------------------
        // Brave Search  — BSA + 40+ chars
        // ----------------------------------------------------------------
        pat!(r#"BSA[a-zA-Z0-9_-]{40,}"#, "brave-search"),
        pat!(
            r#"BRAVE_(?:SEARCH_)?API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "brave-env"
        ),

        // ----------------------------------------------------------------
        // Doppler (secrets management)  — dp.st. prefix
        // ----------------------------------------------------------------
        pat!(r#"dp\.st\.[a-zA-Z0-9_-]{40,}"#, "doppler"),
        pat!(
            r#"DOPPLER_TOKEN\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "doppler-env"
        ),

        // ----------------------------------------------------------------
        // Sentry  — sntrys_ + 64 chars
        // ----------------------------------------------------------------
        pat!(r#"sntrys_[a-zA-Z0-9_-]{64}"#, "sentry"),
        pat!(
            r#"SENTRY_AUTH_TOKEN\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "sentry-env"
        ),

        // ----------------------------------------------------------------
        // PostHog  — phc_ prefix
        // ----------------------------------------------------------------
        pat!(r#"phc_[a-zA-Z0-9]{40,}"#, "posthog"),
        pat!(
            r#"POSTHOG_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "posthog-env"
        ),

        // ----------------------------------------------------------------
        // Neon (serverless Postgres)  — neon_ prefix
        // ----------------------------------------------------------------
        pat!(r#"neon_[a-zA-Z0-9_-]{40,}"#, "neon"),
        pat!(
            r#"NEON_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "neon-env"
        ),

        // ----------------------------------------------------------------
        // PlanetScale  — pscale_ prefix
        // ----------------------------------------------------------------
        pat!(r#"pscale_[a-zA-Z0-9_-]{40,}"#, "planetscale"),
        pat!(
            r#"PLANETSCALE_TOKEN\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "planetscale-env"
        ),

        // ----------------------------------------------------------------
        // Render  — rnd_ prefix
        // ----------------------------------------------------------------
        pat!(r#"rnd_[a-zA-Z0-9]{40,}"#, "render"),
        pat!(
            r#"RENDER_API_KEY\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "render-env"
        ),

        // ----------------------------------------------------------------
        // Netlify  — nfp_ prefix
        // ----------------------------------------------------------------
        pat!(r#"nfp_[a-zA-Z0-9_-]{40,}"#, "netlify"),
        pat!(
            r#"NETLIFY_AUTH_TOKEN\s*[=:]\s*['"`]?([a-zA-Z0-9_-]{20,})"#,
            "netlify-env"
        ),

        // ----------------------------------------------------------------
        // Tailscale  — tskey- prefix
        // ----------------------------------------------------------------
        pat!(r#"tskey-[a-zA-Z0-9_-]{30,}"#, "tailscale"),
        pat!(
            r#"TAILSCALE_API_KEY\s*[=:]\s*['"`]?([a-zA-Z0-9_-]{20,})"#,
            "tailscale-env"
        ),

        // ----------------------------------------------------------------
        // Mapbox  — sk.eyJ1 prefix (base64url JWT-like)
        // ----------------------------------------------------------------
        pat!(r#"sk\.eyJ1[a-zA-Z0-9_-]{40,}"#, "mapbox"),
        pat!(
            r#"MAPBOX_(?:SECRET_)?(?:ACCESS_)?TOKEN\s*[=:]\s*['"`]?(sk\.[a-zA-Z0-9_-]{20,})"#,
            "mapbox-env"
        ),

        // ----------------------------------------------------------------
        // Weights & Biases  — wandb_v1_ prefix (2025+)
        // ----------------------------------------------------------------
        pat!(r#"wandb_v1_[a-zA-Z0-9]{40,}"#, "wandb"),
        pat!(
            r#"WANDB_API_KEY\s*[=:]\s*['"`]?([a-zA-Z0-9]{40,})"#,
            "wandb-env"
        ),

        // ----------------------------------------------------------------
        // Stability AI  — context-anchored (shares sk- with OpenAI)
        // ----------------------------------------------------------------
        pat!(
            r#"STABILITY_API_KEY\s*[=:]\s*['"`]?(sk-[A-Za-z0-9_-]{20,})"#,
            "stability-env"
        ),

        // ----------------------------------------------------------------
        // Salesforce  — opaque access/refresh tokens
        // ----------------------------------------------------------------
        pat!(
            r#"SALESFORCE_(?:ACCESS_TOKEN|CLIENT_SECRET|REFRESH_TOKEN)\s*[=:]\s*['"`]?([A-Za-z0-9_!.]{20,})"#,
            "salesforce-env"
        ),

        // ----------------------------------------------------------------
        // Clerk  — sk_live_ / sk_test_ (auth platform)
        // ----------------------------------------------------------------
        pat!(
            r#"CLERK_SECRET_KEY\s*[=:]\s*['"`]?(sk_(?:live|test)_[a-zA-Z0-9]{20,})"#,
            "clerk-env"
        ),

        // ----------------------------------------------------------------
        // Infisical  — st.v<N>. prefix (secrets management)
        // ----------------------------------------------------------------
        pat!(r#"st\.v[0-9]\.[a-zA-Z0-9_-]{40,}"#, "infisical"),
        pat!(
            r#"INFISICAL_TOKEN\s*[=:]\s*['"`]?([a-zA-Z0-9_.-]{20,})"#,
            "infisical-env"
        ),

        // ----------------------------------------------------------------
        // Fal.ai  — fal_ prefix (AI inference, 2026)
        // ----------------------------------------------------------------
        pat!(r#"fal_[a-zA-Z0-9_-]{32,}"#, "fal-ai"),
        pat!(
            r#"FAL_KEY\s*[=:]\s*['"`]?([a-zA-Z0-9_:-]{20,})"#,
            "fal-env"
        ),

        // ----------------------------------------------------------------
        // Shopify  — shpat_ / shpca_ / shppa_ / shpss_ (push-protected by default as of March 2026)
        // ----------------------------------------------------------------
        pat!(r#"shpat_[a-fA-F0-9]{32}"#, "shopify-pat"),
        pat!(r#"shpca_[a-fA-F0-9]{32}"#, "shopify-custom-app"),
        pat!(r#"shppa_[a-fA-F0-9]{32}"#, "shopify-private-app"),
        pat!(r#"shpss_[a-fA-F0-9]{32}"#, "shopify-shared-secret"),

        // ----------------------------------------------------------------
        // Lark / Feishu  (5 new types March 2026)
        // ----------------------------------------------------------------
        pat!(r#"t-[a-zA-Z0-9]{32}"#, "lark-tenant"),
        pat!(
            r#"LARK_APP_SECRET\s*[=:]\s*['"`]?([A-Za-z0-9_-]{20,})"#,
            "lark-env"
        ),

        // ----------------------------------------------------------------
        // Slack
        // ----------------------------------------------------------------
        pat!(
            r#"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"#,
            "slack-bot"
        ),
        pat!(
            r#"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"#,
            "slack-user"
        ),
        pat!(
            r#"xoxa-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"#,
            "slack-app"
        ),

        // ----------------------------------------------------------------
        // Stripe
        // ----------------------------------------------------------------
        pat!(r#"sk_live_[a-zA-Z0-9]{24,}"#, "stripe-live"),
        pat!(r#"sk_test_[a-zA-Z0-9]{24,}"#, "stripe-test"),
        pat!(r#"rk_live_[a-zA-Z0-9]{24,}"#, "stripe-restricted-live"),

        // ----------------------------------------------------------------
        // SendGrid
        // ----------------------------------------------------------------
        pat!(
            r#"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"#,
            "sendgrid"
        ),

        // ----------------------------------------------------------------
        // Twilio
        // ----------------------------------------------------------------
        // SK sid (32 hex) — context-anchored to avoid colliding with Mailgun
        pat!(
            r#"(?:TWILIO_API_KEY|TWILIO_SID)\s*[=:]\s*['"`]?(SK[a-f0-9]{32})"#,
            "twilio"
        ),
        pat!(r#"AC[a-f0-9]{32}"#, "twilio-account"),

        // ----------------------------------------------------------------
        // Mailgun
        // ----------------------------------------------------------------
        pat!(r#"key-[a-f0-9]{32}"#, "mailgun"),

        // ----------------------------------------------------------------
        // DigitalOcean
        // ----------------------------------------------------------------
        pat!(r#"dop_v1_[a-f0-9]{64}"#, "digitalocean"),

        // ----------------------------------------------------------------
        // Heroku  — UUID format, but ONLY when explicitly labelled
        // ----------------------------------------------------------------
        pat!(
            r#"HEROKU_API_KEY\s*[=:]\s*['"`]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#,
            "heroku-api"
        ),

        // ----------------------------------------------------------------
        // npm / PyPI / Docker Hub
        // ----------------------------------------------------------------
        pat!(r#"npm_[a-zA-Z0-9]{36}"#, "npm"),
        pat!(r#"pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{40,}"#, "pypi"),
        pat!(r#"dckr_pat_[a-zA-Z0-9_-]{40}"#, "docker"),

        // ----------------------------------------------------------------
        // Airtable  — pat + 14 alphanum + . + 64 hex (push-protected March 2026)
        // ----------------------------------------------------------------
        pat!(r#"pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}"#, "airtable"),

        // ----------------------------------------------------------------
        // Notion
        // ----------------------------------------------------------------
        pat!(r#"secret_[a-zA-Z0-9]{43}"#, "notion"),
        pat!(r#"ntn_[a-zA-Z0-9]{50}"#, "notion-integration"),

        // ----------------------------------------------------------------
        // Pinecone
        // ----------------------------------------------------------------
        // New-style  (pcsk_ prefix)
        pat!(r#"pcsk_[A-Za-z0-9_-]{20,}"#, "pinecone-api-key"),
        // Legacy UUID-format — context anchored (allows UUID FP bypass in main.rs)
        pat!(
            r#"PINECONE_API_KEY\s*[=:]\s*['"`]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"#,
            "pinecone"
        ),

        // ----------------------------------------------------------------
        // Database connection strings
        // ----------------------------------------------------------------
        pat!(r#"mongodb(?:\+srv)?://[^\s'"`,]+"#, "mongodb-url"),
        pat!(r#"postgres(?:ql)?://[^\s'"`,]+"#, "postgres-url"),
        pat!(r#"mysql://[^\s'"`,]+"#, "mysql-url"),
        pat!(r#"redis://[^\s'"`,]+"#, "redis-url"),
        // Catch DATABASE_URL assignments regardless of scheme
        pat!(
            r#"DATABASE_URL\s*[=:]\s*['"`]?([a-z][a-z0-9+.-]*://[^\s'"`,]+)"#,
            "database-url"
        ),

        // ----------------------------------------------------------------
        // raw.githubusercontent.com embedded credential URLs
        //
        // Scripts that curl/wget raw files sometimes embed the credentials
        // in the URL itself (token=<value>), or the raw file itself exposes
        // a credential via URL pattern.
        // ----------------------------------------------------------------
        pat!(
            r#"https?://raw\.githubusercontent\.com/[^\s'"`,]+[?&]token=([A-Za-z0-9_-]{20,})"#,
            "raw-github-token-url"
        ),
        pat!(
            r#"https?://[A-Za-z0-9_-]{20,}@raw\.githubusercontent\.com/[^\s'"`,]+"#,
            "raw-github-basic-auth-url"
        ),

        // ----------------------------------------------------------------
        // Private / PGP keys
        // ----------------------------------------------------------------
        pat!(
            r#"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"#,
            "private-key"
        ),
        pat!(
            r#"-----BEGIN PGP PRIVATE KEY BLOCK-----"#,
            "pgp-private"
        ),

        // ----------------------------------------------------------------
        // JWT secrets
        // ----------------------------------------------------------------
        pat!(
            r#"JWT_SECRET\s*[=:]\s*['"`]?([a-zA-Z0-9_-]{32,})"#,
            "jwt-secret"
        ),
        pat!(
            r#"SECRET_KEY_BASE\s*[=:]\s*['"`]?([a-zA-Z0-9_+/]{32,})"#,
            "rails-secret-key-base"
        ),

        // ----------------------------------------------------------------
        // Generic high-entropy pattern (last resort — context-anchored)
        //
        // Requires an explicit secret-ish keyword AND ≥40 chars to reduce
        // the FP rate (was ≥32 chars before, which caught too many hashes).
        // ----------------------------------------------------------------
        pat!(
            r#"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\s*[=:]\s*['"`]?([a-zA-Z0-9_\-+/]{40,})"#,
            "generic-secret"
        ),
    ]
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn find_pattern(label: &str) -> &'static Regex {
        &API_KEY_PATTERNS
            .iter()
            .find(|(_, l)| *l == label)
            .unwrap_or_else(|| panic!("pattern '{}' not found", label))
            .0
    }

    #[test]
    fn pattern_count_sanity() {
        // Updated threshold after 2026 additions.
        assert!(
            API_KEY_PATTERNS.len() >= 100,
            "only {} patterns found — possible truncation",
            API_KEY_PATTERNS.len()
        );
    }

    #[test]
    fn anthropic_admin() {
        let p = find_pattern("anthropic-admin");
        assert!(p.is_match("sk-ant-admin-abcdefghijklmnopqrstuvwxyz123456"));
    }

    #[test]
    fn wandb_v1() {
        let p = find_pattern("wandb");
        let key = format!("wandb_v1_{}", "a".repeat(40));
        assert!(p.is_match(&key));
    }

    #[test]
    fn tailscale_key() {
        let p = find_pattern("tailscale");
        assert!(p.is_match("tskey-auth-abcdefghijklmnopqrstuvwxyz1234567890"));
    }

    #[test]
    fn mapbox_secret() {
        let p = find_pattern("mapbox");
        assert!(p.is_match("sk.eyJ1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567"));
    }

    #[test]
    fn github_server_stateless() {
        let p = find_pattern("github-server-stateless");
        let key = format!("ghs_{}", "a".repeat(120));
        assert!(p.is_match(&key));
    }

    #[test]
    fn openai_project() {
        let p = find_pattern("openai-project");
        assert!(p.is_match("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST"));
        // Must NOT match a plain sk- without the proj- prefix
        assert!(!p.is_match("sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567"));
    }

    #[test]
    fn openai_admin_env() {
        let p = find_pattern("openai-admin-env");
        assert!(p.is_match("OPENAI_ADMIN_KEY=sk-admin-abcdefghijklmnopqrstuvwxyz123456"));
    }

    #[test]
    fn anthropic_env() {
        let p = find_pattern("anthropic-env");
        assert!(p.is_match("CLAUDE_API_TOKEN=sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456"));
    }

    #[test]
    fn github_pat() {
        let p = find_pattern("github-pat");
        assert!(p.is_match("ghp_1234567890123456789012345678901234AB"));
    }

    #[test]
    fn github_fine_grained() {
        let p = find_pattern("github-fine-grained");
        assert!(p.is_match(
            "github_pat_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcdefghijklmnopqrstuvwxyz"
        ));
    }

    #[test]
    fn pinecone_new_style() {
        let p = find_pattern("pinecone-api-key");
        assert!(p.is_match("pcsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"));
    }

    #[test]
    fn groq_exact_length() {
        let p = find_pattern("groq");
        // gsk_ + exactly 52 chars
        let key = format!("gsk_{}", "a".repeat(52));
        assert!(p.is_match(&key));
        // Too short — should not match
        let short = format!("gsk_{}", "a".repeat(10));
        assert!(!p.is_match(&short));
    }

    #[test]
    fn vercel_all_types() {
        for prefix in &["vcp_", "vci_", "vca_", "vcr_", "vck_", "vcs_"] {
            let key = format!("{}{}", prefix, "a".repeat(24));
            assert!(
                API_KEY_PATTERNS.iter().any(|(p, _)| p.is_match(&key)),
                "no pattern matched Vercel key with prefix {}",
                prefix
            );
        }
    }

    #[test]
    fn shopify_tokens() {
        for prefix in &["shpat_", "shpca_", "shppa_", "shpss_"] {
            let key = format!("{}{}", prefix, "a".repeat(32));
            assert!(
                API_KEY_PATTERNS.iter().any(|(p, _)| p.is_match(&key)),
                "no pattern matched Shopify token with prefix {}",
                prefix
            );
        }
    }

    #[test]
    fn raw_github_token_url() {
        let p = find_pattern("raw-github-token-url");
        assert!(p.is_match(
            "https://raw.githubusercontent.com/org/repo/main/.env?token=ghp_abcdefghijklmnopqrstuvwxyz012345"
        ));
    }

    #[test]
    fn generic_secret_requires_40_chars() {
        let p = find_pattern("generic-secret");
        // 40-char value — should match
        assert!(p.is_match(&format!("api_key={}", "a".repeat(40))));
        // 39-char value — should NOT match
        assert!(!p.is_match(&format!("api_key={}", "a".repeat(39))));
    }

    #[test]
    fn cloudflare_no_generic_40_char() {
        // The old pattern matched any 40-char token between quotes.
        // Confirm it no longer fires on benign 40-char strings.
        let benign = r#"value="abcdefghijklmnopqrstuvwxyzABCDEFGHIJ""#;
        let hits: Vec<_> = API_KEY_PATTERNS
            .iter()
            .filter(|(p, l)| l.contains("cloudflare") && p.is_match(benign))
            .collect();
        assert!(
            hits.is_empty(),
            "cloudflare pattern unexpectedly matched benign string: {:?}",
            hits.iter().map(|(_, l)| l).collect::<Vec<_>>()
        );
    }
}
