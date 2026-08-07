# Testing and verification

## Local gates

```bash
cargo fmt --all -- --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --release --all-targets
cargo build --release
```

## Test layers

- Unit tests cover config defaults/round trips, dork invariants, pattern
  matching, and tarball extraction behavior.
- Integration smoke tests execute the binary with `--help` and `--show-dorks`;
  they require no token or network access.
- Release tests exercise the same suite with optimized code.
- A live GitHub/provider scan is an opt-in manual smoke test because it needs
  credentials and external services.

## Performance evidence

The tarball regression test is the stable CPU-path fixture. Compare repeated
release runs on the same fixture when changing extraction, filtering, regex,
or Rayon behavior. Network throughput is measured separately because GitHub
rate limits dominate wall-clock time.

