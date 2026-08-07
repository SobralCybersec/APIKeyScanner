# Release verification

1. Update `CHANGELOG.md` and package version together.
2. Run formatter, check, Clippy, debug tests, release tests, and release build.
3. Run CLI smoke tests without credentials.
4. Build on Linux and Windows through the CI matrix.
5. Inspect public output only; private output stays ignored and is removed from
   CI workspaces before publishing scan results.
6. Create a signed/annotated Git tag only after CI is green.

Release profile is intentionally size-oriented (`opt-level = "z"`, thin LTO,
one codegen unit, stripped symbols). Benchmark `opt-level = 3` before changing
it for throughput-sensitive releases.

