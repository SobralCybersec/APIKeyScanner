# Contributing

## Workflow

1. Read `docs/architecture.md` and the relevant module before editing.
2. Keep changes narrow and preserve output contracts.
3. Add a regression test for behavior changes.
4. Run all commands in `docs/testing.md`.
5. Never commit `.env`, private keys, full-key reports, or generated logs.

## Review checklist

- Source imports every direct dependency it declares.
- Async code does not perform blocking tar/regex work.
- Public findings contain metadata only.
- Errors reach the CLI with useful context.
- TUI terminal state is restored on normal completion.
- Documentation and `CHANGELOG.md` match behavior.
- Build commands do not install or modify Git hooks; use the installer scripts when a hook is explicitly wanted.
