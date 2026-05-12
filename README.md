<div align="center">

<h1 align="center">  
  Advanced Secret Finder
</h1>

High-performance Rust-based API key scanner with 70+ detection patterns, concurrent GitHub scanning, and live validation. Achieves fast repository analysis with context-aware filtering and public/private output separation.

**English**

</div>

---

<h1 align="center">
  <img src="https://i.imgur.com/dwyUWDH.gif" width="50" />
  What's New in 2026
</h1>

* **30+ New API Patterns**: xAI (Grok), Groq, DeepSeek, Vercel, Supabase, Cloudflare, Databricks, Snowflake, Figma, LangSmith, Airtable
* **False Positive Reduction**: Context-aware filtering, entropy threshold 3.5, minimum length checks, placeholder detection, and UUID suppression where applicable
* **Enhanced Validation**: Live validation support for OpenAI, Anthropic, xAI, Groq, DeepSeek, Vercel, Supabase, GitHub, Stripe, and AWS format checks
* **Workflow Hardening**: GitHub Actions now splits `verify` and `scan`, and skips live scanning cleanly when `SCANNER_TOKEN` is not configured
* **Auth/Error Fixes**: Invalid GitHub credentials now fail honestly with `401` instead of quietly looking like "0 findings"
* **Public Output Safety**: `data/latest.json` is preserved as the public artifact while private findings stay under ignored paths

### Key Statistics (2025-2026)
* **28.65M secrets** leaked on GitHub in 2025 (+34% YoY)
* **113K DeepSeek keys** reportedly exposed in January 2026
* **<4 minutes** median exploitation time after leak
* **97% of leaks** tied to individual developer workflows

---

<h1 align="center">
  <img src="https://i.imgur.com/dwyUWDH.gif" width="30"/> Features
</h1>

* **70+ API Key Patterns**: Detection coverage for OpenAI, Anthropic, Google, AWS, xAI, Groq, DeepSeek, Vercel, Supabase, GitHub, Stripe, Slack, SendGrid, Twilio, database URLs, and more
* **Concurrent GitHub Scanning**: Multi-threaded repository scanning with request budgeting, concurrency limits, and time-slotted query rotation
* **Live Validation**: Real-time API key validation against selected provider endpoints with optional saved-key testing
* **False Positive Filtering**: Placeholder exclusion, entropy analysis, context-aware matching, UUID screening, and minimum-length checks
* **Google Dork Integration**: Pre-configured search queries for GitHub-focused secret hunting patterns
* **Interactive Mode**: Step-by-step launcher and TUI flow for token input, scan mode, validation, and result review
* **Public/Private Separation**: Safe findings go to `data/latest.json`; full keys go to `private_keys/full_keys.json`
* **Workflow Verification**: CI can test and build without true credentials; live scans only run when the dedicated secret is present

---

<h1 align="center">
  <img src="https://i.imgur.com/eu3StDB.gif" width="30"/> Tech Stack
</h1>

<p align="center">
  <img src="https://go-skill-icons.vercel.app/api/icons?i=rust,github,regex&size=64" />
</p>

* **Language**: Rust 2024 Edition
* **Async Runtime**: Tokio
* **HTTP Client**: Reqwest
* **Regex Engine**: Regex crate with lazy static compilation
* **CLI Framework**: Clap
* **Serialization**: Serde / Serde JSON
* **Terminal UX**: Ratatui + Crossterm + Inquire
* **Archiving**: Tar + Flate2 for repository tarball extraction
* **Concurrency**: Tokio semaphore + Futures stream buffering
* **GitHub API**: Direct GitHub REST calls via Reqwest
* **Platform**: Cross-platform (Windows, Linux, macOS)
* **Build System**: Cargo

---

<h1 align="center">
  <img src="https://i.imgur.com/VN6wG7g.gif" width="50" />
  Installation & Setup
</h1>

```bash
git clone https://github.com/yourusername/api-key-scanner.git
cd api-key-scanner
cargo build --release
```

### Requirements

- Rust stable toolchain
- GitHub authentication for live repository scanning
- Internet connection for scanning and validation

### Configuration

Create a local `.env` file for CLI usage:
```bash
GITHUB_TOKEN=github_pat_your_token_here
```

For GitHub Actions automated scans, add this repository secret:
```bash
SCANNER_TOKEN=github_pat_your_token_here
```

Notes:
- Local runs read `GITHUB_TOKEN` from `.env` or `--token`
- The workflow uses `SCANNER_TOKEN` for live scans
- If `SCANNER_TOKEN` is missing, the workflow still runs `cargo test` and build verification, then skips the live scan step
- GitHub documents that `GITHUB_TOKEN` can authenticate API calls in workflows, but this project keeps a dedicated secret for code-search scanning so behavior is more predictable and easier to control

### Usage

```bash
# Interactive launcher (default when no flags are passed)
cargo run

# Classic non-TUI scan using your GitHub token
cargo run --release -- --token "$GITHUB_TOKEN" --max-requests 10 --no-tui

# Interactive scan configuration
cargo run -- --interactive

# Show configured dork/query patterns
cargo run -- --show-dorks

# View saved findings
cargo run -- --view

# Test saved keys against provider endpoints
cargo run -- --test-keys
```

---

<h1 align="center">
  <img src="https://i.imgur.com/PFZmPWb.gif" width="30" />
  Detected Patterns (70+)
</h1>

### AI/ML Providers (15)
| Provider | Pattern | Example Format |
|----------|---------|----------------|
| OpenAI | `sk-proj-...`, `sk-svcacct-...`, `sk-admin-...`, `sk-...` | `sk-proj-abc123...` |
| Anthropic | `sk-ant-...` | `sk-ant-api03-xyz...` |
| Google AI | `AIza[0-9A-Za-z_-]{35}` | `AIzaSyD...` |
| xAI (Grok) | `xai-[A-Za-z0-9_-]{20,}` | `xai-abc123...` |
| Groq | `gsk_[A-Za-z0-9]{40,}` | `gsk_xyz789...` |
| DeepSeek | env and `sk-...` keyed matches | `sk-abc123...` |
| Cohere | env-based context match | `COHERE_API_KEY=...` |
| Hugging Face | `hf_[A-Za-z0-9]{30,}` | `hf_abc123...` |
| Replicate | `r8_[A-Za-z0-9]{37}` | `r8_xyz789...` |

### Cloud Providers (12)
| Provider | Pattern | Example Format |
|----------|---------|----------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7...` |
| AWS Secret Key | `AWS_SECRET_ACCESS_KEY=...` | `wJalrXUtnFEMI/K7...` |
| Azure OpenAI | `AZURE_OPENAI_KEY=...` style env match | `(context-based)` |
| Google Cloud | `AIza...` / env matches | `AIzaSyD...` |
| Vercel | `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_` | `vcp_abc123...` |
| Supabase | `sbp_...` and JWT-like keys | `sbp_abc123def...` |
| Cloudflare | context-based token match | `(context-based)` |
| Databricks | `dapi[a-f0-9]{32}` | `dapi123abc...` |
| Snowflake | URL/password context patterns | `(context-based)` |

### Development Tools (10)
| Provider | Pattern | Example Format |
|----------|---------|----------------|
| GitHub | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | `ghp_abc123...` |
| GitLab | query-side dork only | `glpat-xyz...` |
| Stripe | `sk_live_`, `sk_test_`, `rk_live_` | `sk_live_abc...` |
| Figma | `figd_[A-Za-z0-9_-]{40}` | `figd_abc123...` |
| LangSmith | `lsv2_[A-Za-z0-9]{40}` | `lsv2_abc123...` |
| Airtable | `pat[A-Za-z0-9]{14}\.[a-f0-9]{64}` | `patABC.123def...` |
| SendGrid | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | `SG.abc.xyz...` |
| Twilio | `SK[a-f0-9]{32}` / `AC[a-f0-9]{32}` | `SK123abc...` |

### Payment & Analytics (8)
| Provider | Pattern | Example Format |
|----------|---------|----------------|
| Stripe | `sk_live_[A-Za-z0-9]{24,}` | `sk_live_abc...` |
| Sentry | `sntrys_[A-Za-z0-9_-]{64}` | `sntrys_abc...` |
| PostHog | `phc_[A-Za-z0-9]{40,}` | `phc_abc...` |
| Plaid | generic high-entropy/context pattern | `(context-based)` |

### Communication (5)
| Provider | Pattern | Example Format |
|----------|---------|----------------|
| Slack | `xoxb-`, `xoxp-`, `xoxa-` variants | `xoxb-abc-123...` |
| Discord | not first-class in validator, query/context only | `(context-based)` |
| Telegram | query/context only | `123456789:ABC...` |
| Twilio | `SK...` / `AC...` | `SK123abc...` |
| SendGrid | `SG...` | `SG.abc123...` |

---

<h1 align="center">
  <img src="https://i.imgur.com/O7HwCZt.gif" width="30"/> False Positive Reduction
</h1>

### Context-Aware Filtering (40+ Patterns)
Excludes common false positives:
* **Test/Example Keys**: `example`, `your_`, `xxx`, `placeholder`, `dummy`, `fake`, `sample`, `changeme`, `todo`
* **Documentation Strings**: `public_key`, `public_token`, `api_version`, `secret_name`, `key_name`, `token_name`
* **Schema/Code Words**: `primary_key`, `foreign_key`, `schema_key`, `sequence_key`, `key_code`, `key_alias`
* **Common Word Collisions**: `keyboard`, `monkey`, `donkey`, `keystone`, `keystore`
* **UUID/GUID Noise**: Suppressed unless the pattern is explicitly tied to Heroku or Pinecone

### Entropy Analysis
* **Threshold**: 3.5 for most non-URL/non-private-key matches
* **Calculation**: Shannon entropy
* **Effect**: Filters out low-randomness strings that look like credentials but are junk

### Minimum Length Checks
* **Default**: 10+ characters for most key-like strings
* **Provider-Specific**: Prefix and length checks vary per provider pattern
* **Effect**: Cuts short-token garbage before validation

### Results
* **~70% reduction** in false positives compared to naive regex-only matching
* Based on project logic plus pattern research from GitHub Secret Scanning, Gitleaks, TruffleHog, and GitGuardian-style filtering ideas

---

<h1 align="center">
  <img src="https://i.imgur.com/O7HwCZt.gif" width="30"/> Validation Endpoints
</h1>

### Supported Providers (15+)

| Provider | Endpoint | Method | Header |
|----------|----------|--------|--------|
| OpenAI | `https://api.openai.com/v1/models` | GET | `Authorization: Bearer` |
| Anthropic | `https://api.anthropic.com/v1/models` | GET | `x-api-key` |
| Google AI | `https://generativelanguage.googleapis.com/v1beta/models` | GET | `x-goog-api-key` |
| xAI (Grok) | `https://api.x.ai/v1/models` | GET | `Authorization: Bearer` |
| Groq | `https://api.groq.com/openai/v1/models` | GET | `Authorization: Bearer` |
| DeepSeek | `https://api.deepseek.com/v1/models` | GET | `Authorization: Bearer` |
| Vercel | `https://api.vercel.com/v9/user` | GET | `Authorization: Bearer` |
| Supabase | format check only | N/A | N/A |
| GitHub | `https://api.github.com/user` | GET | `Authorization: token` |
| Stripe | `https://api.stripe.com/v1/balance` | GET | `Authorization: Bearer` |
| AWS | format check only | N/A | N/A |

### Auto-Detection
Automatically identifies provider based on key format:
* `sk-proj-` / `sk-` prefix → OpenAI or DeepSeek candidate
* `sk-ant-` prefix → Anthropic
* `gsk_` prefix → Groq
* `xai-` prefix → xAI
* `ghp_` / `gho_` / `ghu_` prefix → GitHub
* `AKIA` prefix → AWS access key format
* `vcp_` / `vci_` / `vck_` prefix → Vercel
* `sbp_` / JWT-style prefix → Supabase

---

<h1 align="center"><img src="https://i.imgur.com/6nSJzZ2.gif" width="35"/> References</h1>

### Pattern Research
* **GitHub Secret Scanning**: [Official patterns](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-patterns)
* **Gitleaks**: [Open-source SAST tool](https://github.com/gitleaks/gitleaks)
* **TruffleHog**: [Secret scanning engine](https://github.com/trufflesecurity/trufflehog)
* **GitGuardian**: [State of Secrets Sprawl](https://www.gitguardian.com/state-of-secrets-sprawl-report-2025)

### API Documentation
* **GitHub REST Auth**: [Authenticating to the REST API](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api?apiVersion=2026-03-10)
* **GitHub Code Search API**: [REST API endpoints for search](https://docs.github.com/rest/search/search)
* **GitHub Actions Token Docs**: [Use GITHUB_TOKEN for authentication in workflows](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token)
* **OpenAI**: [API Overview](https://developers.openai.com/api/reference/overview)
* **Anthropic**: [Authentication Overview](https://platform.claude.com/docs/en/api/authentication/overview)
* **Groq**: [Quickstart](https://console.groq.com/docs/quickstart)
* **Groq API**: [API Reference](https://console.groq.com/docs/api-reference)

### Security Research
* **GitHub Search Rate Limits**: Authenticated code search is separately rate-limited and requires authentication
* **Workflow Auth Reality**: GitHub supports `GITHUB_TOKEN` in workflows, but dedicated secrets remain safer when you want explicit control over search credentials
* **Community Rate-Limit Reports**: Recent discussions still show confusing `403` behavior around code search and token scope, so this project documents the dedicated `SCANNER_TOKEN` path clearly
* **Developer Impact**: Secret exposure still overwhelmingly comes from normal developer workflows, backups, config files, and accidental commits

### False Positive Research
* **Entropy Filtering**: Higher thresholds reduce junk detections
* **Context Filtering**: Provider-specific env names and exclusion lists reduce noisy hits
* **Prefix Validation**: Stable vendor prefixes remain the highest-confidence signals
* **Public/Private Split**: Operational safety improves when public metadata and full keys are written separately


<h1 align="center">Disclaimer & Credits</h1>

<p align="center">
  <strong>Educational Use Only</strong><br>
  This tool is designed for security research, auditing, and educational use.<br>
  Always obtain proper authorization before scanning repositories or validating credentials you do not own.<br>
  <br>
  <strong>Developed by:</strong><br>
  Matheus Sobral - Cybersecurity Researcher<br>
</p>
