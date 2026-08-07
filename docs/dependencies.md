# Dependency policy and audit

Direct dependencies are listed only when application source imports them. The
lockfile remains committed and is regenerated after manifest changes.

| Dependency | Purpose | Required features |
| --- | --- | --- |
| `aho-corasick` | Literal prefilter before regex scanning | default |
| `anyhow` | Application boundary error propagation | default |
| `chrono` | Timestamps in findings and reports | default |
| `clap` | CLI parsing and environment-backed flags | `derive`, `env` |
| `crossterm` | Terminal UI and input | default |
| `dotenv` | Local `.env` loading | default |
| `flate2` | GitHub tarball gzip decoding | default |
| `futures` | Bounded unordered async streams | default |
| `inquire` | Interactive prompts | default |
| `rayon` | Parallel CPU-bound file scanning | default |
| `regex` | Credential pattern matching | default performance features |
| `reqwest` | GitHub/provider HTTP client | `rustls-tls`, `gzip`, no defaults |
| `serde` / `serde_json` | Typed JSON/TOML serialization | `serde/derive` |
| `tar` | Tarball extraction | default |
| `tokio` | Async runtime, filesystem, timers, synchronization | explicit runtime/fs/time/sync features |
| `toml` | Scanner configuration | default |
| `tracing` / `tracing-subscriber` | Structured diagnostics and filtering | `env-filter` |
| `zip` | DOCX extraction | `deflate`, no defaults |

Removed after source audit: direct `base64`, `sha2`, and `thiserror`; unused
Reqwest `json` and Chrono `serde` features were also removed. Transitive
packages may remain when required by other dependencies.

## Repeatable audit

```bash
cargo tree --depth 1
cargo tree --duplicates
cargo metadata --no-deps --format-version 1
grep -RIn --include='*.rs' -E 'base64|sha2|thiserror|\.json\(' src build.rs
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

`cargo-machete` is useful as a supplementary audit. `cargo-udeps` is optional
and nightly-only; neither replaces source review or compilation.

