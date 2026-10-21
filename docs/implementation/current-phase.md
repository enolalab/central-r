# Current Phase

## Active slice: Phase R1 — Workspace Scaffold, Canonical SQL Extraction (`v0..b37`) & Durable Task/Execution Core

`central-rust` is delivered as the `R0`–`R6` vertical-slice sequence defined in [rust-vertical-slice-roadmap.md](rust-vertical-slice-roadmap.md) under Accepted [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md). **Phase R1 is the active implementation slice.** No Rust production code exists yet; the R0 documentation and contract baseline is the authority R1 implements against.

R1 scope (roadmap §4):

- Initialize the Cargo Workspace — root `Cargo.toml` (`[workspace.dependencies]`, `[workspace.lints]`), `rust-toolchain.toml`, `deny.toml` — per [rust-application-boundaries.md](../architecture/rust-application-boundaries.md).
- Implement `central-foundation` (UUIDv7 identity newtypes, Failure taxonomy and exit classes).
- Extract the complete `v0..b37` SQL schema from the upstream Go `internal/adapter/postgres/migrate/*.go` files into canonical ordered `.sql` files under `migrations/` with an immutable SHA-256 checksum manifest — statement-for-statement, no new DDL, no semantic change ([postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md)).
- Implement Central's native migration runner in `central-adapter-postgres`: `central.schema_migrations` checksum ledger, single-session `pg_advisory_lock`, version-zero `VerifiedEmptyTarget` atomic baseline installer, dirty data-backfill resume without generic `Force`, and `reapply_incremental_runtime_grants` after `pg_restore`. The `sqlx` `migrate` feature and `_sqlx_migrations` are prohibited.
- Build the core Phase 1 durable domains: `central-workspace`, `central-task`, `central-execution`, `central-event`, `central-checkpoint`, `central-authorization`, with `central-kernel` composition and `.sqlx/` offline query verification green across the workspace.

Verification for every R1 change follows the fail-fast pipeline in [rust-engineering-workflow.md](rust-engineering-workflow.md) §7 (`cargo sqlx prepare --check` → `cargo fmt --check` → `cargo clippy -D warnings` → `cargo deny check` → `cargo test --workspace`).

## Completed: Phase R0 — Documentation & Contract Baseline

Phase R0 is **Complete upon R0 acceptance** per the [governing spec](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md) §7. It ported every language-agnostic contract (product, API/Event v1, artifact, runtime, persistence, security, operations, Phase 1/2 slice dossiers), the immutable ADR ledger `0001`–`0042`, and the authoritative Phase 0/1/2 design specs, and it authored the Rust-specific contracts this repository runs on: `AGENTS.md`, `CLAUDE.md`, [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md), [rust-application-boundaries.md](../architecture/rust-application-boundaries.md), [postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md), [rust-engineering-workflow.md](rust-engineering-workflow.md), this file, and the [R-slice roadmap](rust-vertical-slice-roadmap.md).

## Upstream reference baseline (Phase 0–2)

`central-rust` reimplements the upstream Go `central` repository at full parity. The upstream baseline the ported contracts encode:

- **Phase 0 (Complete):** design-only gates G1–G10 produced the product, security, runtime, artifact, API/Event, persistence, application-boundary, local-topology, and slice-decomposition contracts now canonically ported here; ADRs `0001`–`0042` are retained unchanged as the immutable decision ledger.
- **Phase 1 (Complete at recorded evidence tiers):** Slices A–E delivered host authority, the first safe runnable environment (B01–B12), required recovery, destructive portable operations, and dependency maintenance; the Harness Control Plane (ADR 0035/ADR 0036) delivered Claude Code, OpenCode, Codex, and Antigravity adapters, capture, permission bridging, budgets, and cancel/resume/rerun (upstream phases 1a–3m). Upstream gate evidence — including the SC/SD/SE verdicts and their recorded evidence tiers — is archived in the upstream repository and is authoritative there, not copied here.
- **Phase 2 (Exit-complete at machine tier):** multi-agent workflow orchestration — workflow graph and event journal (`b33`), scheduler/workers (`b35`), subtree checkpoints (`b36`), retry/idempotency (`b37`), run submission, DAG run views, and the recovery test matrix — is specified by the Phase 2 spec series and slice dossiers ported under `docs/implementation/phase-2-slices/`.

Two upstream decisions shape everything below: [ADR 0035](../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md) froze the B09 loop coordinator (never ported — `central-harness` + `central-execution` carry the sequential-coordinator role instead), and [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md) replaces Go module/package boundaries with the Rust Cargo Workspace contract for this repository while preserving every other upstream decision.

## Remaining sequence

| Slice | Scope | Status |
| --- | --- | --- |
| R1 | Workspace scaffold, `v0..b37` extraction, native migration runner, durable Task/Execution core | **Active** |
| R2 | Verified artifact lifecycle, `central-adapter-s3` | Pending |
| R3 | Harness control plane, `central-session`, `central-transport-http`, `central-harness-launcherd` | Pending |
| R4 | Phase 2 orchestration (`workflow`, `eventjournal`, `scheduler`, `retry`, `runview`, `runsubmit`), recovery matrix | Pending |
| R5 | Host authority, protected broker, `central-adapter-linux`, Compose topology | Pending |
| R6 | Backup, restore, wipe, maintenance, launcher daemons | Pending |
