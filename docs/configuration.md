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

