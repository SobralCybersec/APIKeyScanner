# Architecture

APIKeyScanner is a Rust command-line application. It has no database, browser UI,
IPC endpoint, JavaScript runtime, or server-side API.

## Modules

| Module | Responsibility |
| --- | --- |
| `main.rs` | CLI composition root, GitHub search, bounded concurrency, tarball extraction, reporting, TUI orchestration |
| `patterns.rs` | Compiled credential patterns and pattern tests |
| `gpu_filter.rs` | Shared Aho-Corasick literal prefilter |
| `dorks.rs` | Query catalogue and query validation tests |
| `storage.rs` | Public/private finding serialization and local persistence |
| `validator.rs` | Provider validation requests and validation reports |
| `config.rs` | TOML configuration model and defaults |
| `cli.rs` | Interactive menus and local finding views/exports |
| `launcher.rs` | Interactive configuration flow |
| `tui.rs` | Terminal state, rendering, input, and terminal restoration |

## Runtime flow

1. `main` loads environment/configuration and constructs one shared `reqwest::Client`.
2. `Scanner::search_code` paginates GitHub code search within request/time limits.
3. `Scanner::analyze_repo` bounds repository work with a semaphore and downloads one tarball.
4. Tarball extraction runs in `spawn_blocking`; Aho-Corasick rejects irrelevant files before Rayon regex work.
5. Findings are deduplicated per file, then persisted as public metadata and private local data.
6. Optional validation uses a separate bounded provider-client workflow.

## Boundaries and invariants

- Network calls stay async; tar/gzip/regex work stays off the async runtime.
- One `reqwest::Client` owns connection pooling for each scan.
- Request and repository counters are shared atomics.
- Full keys are excluded from public findings and remain in ignored private output.
- No database or IPC contract exists; local JSON/TOML files are the persistence boundary.
- Build scripts do not mutate the checkout; optional Git hooks are installed only by the explicit installer scripts.
