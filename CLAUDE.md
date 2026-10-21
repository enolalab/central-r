# Central — Claude Code guide

Local-first durable AI workspace in Rust. Coordinates agents/subagents, persists task state in PostgreSQL, stores artifact bodies in S3-compatible storage (MinIO locally), supports checkpoint/retry/resume. Single Cargo Workspace; shared deps pinned in `[workspace.dependencies]` + committed `Cargo.lock` — never add a dependency or bump a version without asking (see `docs/implementation/rust-engineering-workflow.md`).

## Repo map (trust this; don't re-explore for orientation)

The workspace is scaffolded in R1 per `docs/architecture/rust-application-boundaries.md`:

- `crates/central-foundation` — identity (UUIDv7 newtypes), failure (error taxonomy & exit classes)
- `crates/capabilities/central-*` — domain capability crates; each owns `domain.rs` (pure sync root), `port.rs`, `query.rs`, `app.rs`. Key: `central-workspace`, `central-task`, `central-execution`, `central-authorization`, `central-session`, `central-checkpoint`, `central-event`, `central-artifact`, `central-harness`, `central-workflow`, `central-eventjournal`, `central-scheduler`, `central-retry`, `central-runview`, `central-runsubmit`, `central-backup`, `central-infra`
- `crates/adapters/central-adapter-postgres` — `sqlx` implementations of capability `port`/`query` traits + the native `central.schema_migrations` migration runner; `sqlx` types must never leak into domain APIs
- `crates/adapters/central-adapter-s3` — S3/MinIO object storage for `central-artifact`
- `crates/adapters/central-adapter-harness` — Claude Code, OpenCode, Codex, Antigravity adapters + gitclone + launcher client
- `crates/adapters/central-adapter-linux` — audited `rustix` OS boundary (broker protocol, memfd, SCM_RIGHTS, PAM/TTY, namespaces); the only capability-side `unsafe` site besides launcher binaries
- `crates/transport/central-transport-http` — `axum` controllers: API v1 JSON, `askama` SSR Web UI, Health & Metrics
- `crates/central-kernel` — manual dependency composition, supervised task runner, graceful shutdown
- `bins/` — `central` (serve, `run submit`, `node decide`, `checkpoint *`, `artifact read`, `local *`, `migrate *`, `backup *`, `restore *`, plus `helper`/`central-protected-broker`/`central-sandbox-launcher` modes), `central-harness-launcherd`, `central-migration-launcherd`, `central-migrate`, `central-backup-launcherd`, `central-backup`, `central-restore`, `central-advisory-sign`
- `migrations/` — canonical ordered `v0..b37` SQL extracted from upstream + checksum manifest; `.sqlx/` — committed offline query-verification metadata
- `docs/` — architecture/ADR/product docs; `docs/implementation/current-phase.md` defines current scope
- `AGENTS.md` — full agent rules; read it ONLY before architectural changes, not for routine edits

## Task triage — pick ONE mode before touching any tool

**Routine** (bugfix, small feature, test fix, rename — one crate, no schema/interface change):
- Budget: 1–2 Grep calls to locate, Read **max 3 files**, then edit.
- Do NOT read `docs/`, `AGENTS.md`, or ADRs. Do NOT read files "for context" beyond the budget — if 3 files aren't enough, say so and name the 4th before reading it.
- Verify: `cargo build -p central-<crate>` + `cargo test -p central-<crate>` for the touched crate(s) only.

**Cross-crate** (change spans 2+ workspace crates or touches a `port`/`query` trait):
- Read the touched files plus the trait definition. Still no `docs/` unless the trait's contract is unclear from code.
- Verify: touched crates' tests, then `cargo clippy --workspace --all-targets -- -D warnings` + `cargo build --workspace`.

**Architecture** (schema change, task lifecycle, new capability crate, storage layout, migration):
- Read `AGENTS.md` + the ONE specific file under `docs/architecture/` or `docs/adr/` that covers the area + `docs/implementation/current-phase.md`. Not the whole docs tree.
- Verify: full pipeline (see Commands).

Never read or search under `target/` or registry caches (use `':!target/'` in grep). Never run `cargo build --release` to verify — `cargo check --workspace` / `cargo build --workspace` is the compile check.

## Tool discipline

- Routine/cross-crate work = Grep + Read + Edit + Bash only. Do NOT use ToolSearch, MCP tools, web search, or subagents for code changes in this repo.
- ToolSearch/MCP is justified only when the task itself is about an external system (Linear issues, browser testing, deployment).
- One Bash call can chain independent commands with `&&` — don't spend 4 calls on what 1 does.

## Commands

```bash
# Targeted test — DEFAULT (Routine mode):
cargo test -p central-<crate>

# Full verification — ONLY for Architecture mode or when explicitly asked
# (fail-fast order per rust-engineering-workflow.md §7):
cargo sqlx prepare --check --workspace -- --all-targets && \
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets --all-features -- -D warnings && \
cargo deny check && \
cargo test --workspace

# Regenerate .sqlx/ after changing a checked query (needs the v0..b37
# verification database provisioned from migrations/):
cargo sqlx prepare --workspace -- --all-targets
```

`cargo test --workspace` rule: run it only when (a) Architecture mode, (b) you changed a `port`/`query` trait or a shared `central-foundation` type, or (c) the user asks. Otherwise the touched crate is enough — the Cargo dependency DAG and CI catch cross-cutting breakage.

Root-required `central-adapter-linux`/launcher platform tests are skipped automatically as non-root or off the pinned reference host — that skip is expected, not a failure.

## Hard constraints (violations = rework)

- PostgreSQL only (no SQLite). Artifact **metadata** in Postgres, **bodies** in object storage — never payloads in the DB.
- Every schema change ships with a migration; atomic state transitions use transactions; task transitions go through the task domain service.
- Compile-time-checked SQL only: `sqlx::query!`/`query_as!` macros against the canonical `central.*` schema; no dynamic SQL (`format!`), no `_sqlx_migrations` — the native `central.schema_migrations` runner is the only migration executor.
- Retriable operations must be idempotent; a task is "done" only after artifacts + final state are durably persisted.
- No credentials/tokens/.env in commits. No weakening permission checks to make tests pass. No unrelated refactors.
- Never claim a command passed without running it.

## Definition of done (non-trivial work)

Behavior implemented → affected-crate tests pass → fmt/clippy clean (`.sqlx/` regenerated if queries changed) → migration included if schema changed → docs updated only if behavior/architecture changed.
