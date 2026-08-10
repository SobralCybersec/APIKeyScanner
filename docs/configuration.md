# Configuration

Configuration is local TOML in `scanner-config.toml`. Missing files use
`ScannerConfig::default()`.

| Field | Default | Meaning |
| --- | --- | --- |
| `github_token` | unset | Token used by interactive configuration |
| `max_requests` | `200` | Per-pass request budget |
| `concurrency` | `5` | Concurrent repository scans |
| `max_minutes` | unset | Optional wall-clock limit |
| `max_repos_per_query` | `30` | Repository cap per query |
| `max_total_repos` | unset | Optional total repository cap |
| `query_loops` | `1` | Query passes |
| `output_path` | `data` | Public output directory |
| `scan_mode` | `time_slotted` | Query selection mode |
| `custom_queries` | `[]` | User-selected queries |
| `enable_validation` | `false` | Provider validation switch |
| `enable_tui` | `true` | Interactive terminal UI switch |
| `validate_every_n_repos` | unset | Optional validation checkpoint |
| `endless_loop` | `false` | Repeat until stopped or no new findings |

CLI flags override defaults. `GITHUB_TOKEN` supports scripted local runs;
GitHub Actions uses the separate `SCANNER_TOKEN` secret. No feature flags,
database migrations, IPC versions, or frontend state stores exist in this
project.

## Web search and passive subdomains

Web discovery uses API-backed providers; it does not scrape search-result HTML.
Configure one or more providers with environment variables:

| Variable | Backend |
| --- | --- |
| `EXA_API_KEY` | Exa semantic web search |
| `BRAVE_API_KEY` | Brave Web Search |
| `GOOGLE_API_KEY` + `GOOGLE_CSE_ID` | Google Custom Search JSON API |
| `BING_SEARCH_API_KEY` | Bing Web Search API |
| `GITLAB_TOKEN` | GitLab blob search |
| `WEB_SEARCH_PAGES` | Optional page count; default `1` |

Examples:

```bash
cargo run --release -- --web-search --no-tui
cargo run --release -- --discover-subdomains --domain example.com
cargo run --release -- --web-search --discover-subdomains --domain example.com --no-tui
```

Web dorks cover raw GitHub, GitHub Gists, GitLab, Sourcegraph, Bitbucket,
Pastebin, npm, PyPI, RubyGems, crates.io, CI logs, notebooks, Docker,
Terraform, and domain-scoped queries. Exa uses its JSON search API when
`EXA_API_KEY` is set; it normalizes semantic results into the same scanner
pipeline as the other providers. `crt.sh` discovery is
passive certificate-transparency lookup; discovered names are not treated as
live until separately resolved.
