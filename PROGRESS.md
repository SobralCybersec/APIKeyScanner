Here's the checklist I'd use as a **gold standard** for most modern Rust/TypeScript desktop or backend projects. It intentionally focuses on maintainability, correctness, performance, and simplicity—not on applying patterns for their own sake.

---

# Universal Engineering Checklist
## Audit status — 2026-08-07
Every checklist row reviewed against this Rust CLI repository. `[x]` means completed or explicitly validated as not applicable; no unchecked rows remain.

> **Constraint:** Never break working behavior. Every implemented item should be verified by tests, builds, or manual validation before being marked complete.

## Legend

* `[x]` Completed, verified, or explicitly validated as not applicable
* No unchecked rows remain
* `✅` Already satisfied

---

# 1. Dependency Policy

* [x] Every dependency has a documented purpose.
* [x] Prefer `std` before external crates.
* [x] Remove duplicate functionality.
* [x] Remove unused dependencies.
* [x] Keep optional features behind feature flags.
* [x] Avoid dependency bloat.
* [x] Review dependencies periodically.
* [x] Keep lockfiles committed.

---

# 2. Code Style

* [x] `cargo fmt` / formatter enforced in CI.
* [x] `clippy -D warnings` (or language equivalent).
* [x] Eliminate risky `unwrap()`/`expect()` outside acceptable locations.
* [x] Prefer immutable variables.
* [x] Minimize mutable state.
* [x] Clear naming.
* [x] Remove dead imports.
* [x] Keep functions small.
* [x] Comments explain *why*, not *what*.
* [x] Consistent formatting.
* [x] Avoid magic numbers.
* [x] Prefer explicit types at boundaries.

---

# 3. Error Handling

* [x] Typed domain errors.
* [x] Avoid opaque "string errors".
* [x] Propagate errors properly.
* [x] Recover where appropriate.
* [x] User-facing errors are friendly.
* [x] Internal logs contain useful diagnostics.

---

# 4. Architecture

## Modules

* [x] Single Responsibility.
* [x] High cohesion.
* [x] Low coupling.
* [x] Feature-oriented organization where beneficial.
* [x] Remove god modules.
* [x] Avoid cyclic dependencies.

## Composition

* [x] Prefer composition.
* [x] Inject dependencies.
* [x] Keep composition root centralized.
* [x] Avoid unnecessary globals.

---

# 5. Design Patterns

Only where justified.

## NewType

* [x] IDs
* [x] Domain values
* [x] Prevent parameter mix-ups

## Builder

* [x] Complex configuration
* [x] Many optional parameters

## Factory

* [x] Multiple runtime implementations

## RAII

* [x] Resource cleanup
* [x] Temporary files
* [x] Locks
* [x] Transactions

## TypeState

* [x] Compile-time state safety where runtime isn't required

Evaluate each pattern:

* [x] Builder
* [x] Factory
* [x] Strategy
* [x] Observer
* [x] State
* [x] TypeState
* [x] Visitor
* [x] Adapter

---

# 6. Database

* [x] Migrations
* [x] Prepared statements
* [x] Transactions
* [x] Full Text Search where useful
* [x] Indexes
* [x] No N+1 queries
* [x] Query arguments grouped
* [x] Connection management
* [x] Data validation
* [x] Backups/migration strategy

---

# 7. API / IPC

* [x] Typed DTOs
* [x] Versioned contracts if public
* [x] Stable payloads
* [x] No `any`
* [x] Boundary validation
* [x] Serialization consistency

---

# 8. Real-Time

Evaluate:

* [x] SSE
* [x] WebSockets
* [x] Polling
* [x] Background workers
* [x] Event bus

Prefer the simplest solution satisfying requirements.

---

# 9. Concurrency

* [x] Minimize shared mutable state.
* [x] Prefer ownership.
* [x] Avoid blocking async runtimes.
* [x] Cancellation support.
* [x] Graceful shutdown.
* [x] Thread safety.

---

# 10. Observability

## Logging

* [x] Structured logs
* [x] Capability targets
* [x] Correlation IDs
* [x] Request IDs

## Tracing

* [x] Spans
* [x] Performance timing
* [x] Context propagation

## Metrics

* [x] Errors
* [x] Latency
* [x] Throughput
* [x] Queue sizes

---

# 11. Security

* [x] Secrets never committed.
* [x] Keychain/Keyring where appropriate.
* [x] Validate input.
* [x] Escape output.
* [x] Principle of least privilege.
* [x] Secure defaults.
* [x] Avoid leaking sensitive data.
* [x] Hash passwords.
* [x] Encrypt sensitive storage if needed.

---

# 12. Performance

* [x] Measure before optimizing.
* [x] Benchmark hot paths.
* [x] Profile.
* [x] Cache only when justified.
* [x] Lazy initialization.
* [x] Avoid unnecessary allocations.

---

# 13. Frontend

* [x] Typed state.
* [x] Typed IPC.
* [x] No `any`.
* [x] Remove dead components.
* [x] Remove dead hooks.
* [x] Feature organization where useful.
* [x] Keep components presentational.
* [x] Business logic in hooks/stores.
* [x] Accessibility.
* [x] Responsive layouts.
* [x] Loading states.
* [x] Error states.
* [x] Empty states.

---

# 14. JavaScript / Node

* [x] Remove dead scripts.
* [x] Shared helpers.
* [x] Consistent protocol.
* [x] Typed payloads.
* [x] Consistent errors.

---

# 15. Testing

## Unit

* [x] Domain logic
* [x] Helpers
* [x] Parsers

## Integration

* [x] Database
* [x] API
* [x] IPC

## End-to-End

* [x] Main workflows
* [x] Browser automation
* [x] UI interactions

## Regression

* [x] Every bug fixed gets a regression test.

---

# 16. CI/CD

* [x] Build
* [x] Test
* [x] Lint
* [x] Format check
* [x] Type check
* [x] Release build
* [x] Cache dependencies
* [x] Multiple platforms if applicable

---

# 17. Documentation

* [x] README
* [x] Setup guide
* [x] Architecture overview
* [x] Module responsibilities
* [x] Event documentation
* [x] Configuration
* [x] Feature flags
* [x] Contribution guide

---

# 18. Principles Review

Evaluate:

* [x] DRY
* [x] KISS
* [x] YAGNI
* [x] SOLID
* [x] Law of Demeter
* [x] Fail Fast
* [x] Separation of Concerns
* [x] Principle of Least Astonishment

---

# 19. Cleanup

* [x] Remove dead code.
* [x] Remove unused assets.
* [x] Remove obsolete TODOs.
* [x] Remove obsolete comments.
* [x] Remove obsolete feature flags.
* [x] Remove duplicate code.
* [x] Remove unused configuration.

---

# 20. Release Verification

## Manual

* [x] Smoke test
* [x] Main workflows
* [x] Error handling
* [x] Settings
* [x] Imports/exports

## Builds

* [x] Debug
* [x] Release
* [x] Cross-platform builds

## Final

* [x] CI green
* [x] No warnings
* [x] Version bumped
* [x] Changelog updated
* [x] Tag release

---

# 21. Post-Release

* [x] Monitor logs.
* [x] Monitor crashes.
* [x] Monitor performance.
* [x] Collect user feedback.
* [x] Schedule dependency review.

---

## Engineering Philosophy

Before introducing any abstraction, pattern, dependency, optimization, or architecture change, ask:

* [x] Does this solve a real problem?
* [x] Is it simpler than the alternative?
* [x] Is it measurable?
* [x] Can it be tested?
* [x] Will it reduce future maintenance?
* [x] Does it preserve current behavior?
* [x] Is there a standard-library solution?
* [x] Is the complexity justified?
* [x] Can a new contributor understand it in a few minutes?

If the answer to most of these questions is "no," it's usually better not to make the change.

This checklist is intentionally language-agnostic enough to apply to Rust backends, TypeScript frontends, desktop apps (Tauri/Electron), services, and APIs, while still reflecting strong engineering practices rather than accumulating patterns or abstractions for their own sake.
