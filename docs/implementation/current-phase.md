# Current Phase

## Active slice: Phase R4 — Multi-Agent Workflow Orchestration

`central-rust` is delivered as the `R0`–`R6` vertical-slice sequence defined in [rust-vertical-slice-roadmap.md](rust-vertical-slice-roadmap.md) under Accepted [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md). **Phase R4 is the active implementation slice**; Phases R1–R3 are complete (see below) — R3 delivered the harness control plane, the session/SSR web surface, `central serve`, and `central-harness-launcherd`.

R4 scope (roadmap §7): Phase 2 orchestration parity — `central-workflow`, `central-eventjournal`, `central-scheduler`, `central-retry`, `central-runview`, `central-runsubmit`, the `b36` subtree-anchored checkpoints, and the 23-scenario recovery test matrix. R4 tasks T1–T9 (retry taxonomy, workflow graph domain, event journal, `b33`/`b35`/`b37` stores, scheduler claim/dispatch, `node decide`) already landed on this branch while gated on R3 T5/T12/T13; with R3 complete those gates are open and R4 T10–T14 (run submit, runview UI, subtree checkpoints, recovery matrix, acceptance) remain.

Verification for every R4 change follows the fail-fast pipeline in [rust-engineering-workflow.md](rust-engineering-workflow.md) §7 (`cargo sqlx prepare --check` → `cargo fmt --check` → `cargo clippy -D warnings` → `cargo deny check` → `cargo test --workspace`).

## Completed: Phase R3 — Harness Control Plane & `central serve`

Phase R3 delivered, per roadmap §6 and ADRs [0035](../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md)/[0036](../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md):

- `central-harness`: the harness control-plane domain — adapter identity/capabilities vocabulary, the session boundary, capture, permission bridging, budget metering, and the cancel/resume/rerun + ambiguity-resolution state machines.
- `central-adapter-harness`: the Claude Code, OpenCode, Codex, and Antigravity adapters (protocol codecs, argv grammars, probe pins), `gitclone` provision/capture, the CHL1 launcher client, and the `CENTRAL_LOCALEXEC` dev executor.
- `central-session`: bootstrap-generation exchange, session cookies, and CSRF token issuance/verification.
- `central-transport-http`: the API v1 JSON controllers and the `askama` SSR Web UI (bootstrap exchange, task list/detail, harness resolve and permission PRG flows, artifact preview/download), plus health/metrics with loopback-peer admission.
- `central-adapter-postgres`: the fenced execution/recovery stores — recovery epochs with bounded claim batches and degraded-epoch quarantine, step-attempt reconciliation, command receipts, and the outbox.
- `central-kernel`: the `central serve` composition — supervised listeners, the R2 artifact reconciler behind the recovery-coordinator fence, bootstrap reconciliation, bounded startup recovery, and graceful drain.
- `bins/central`: the `serve` verb plus harness/session/node CLI surfaces; `bins/central-harness-launcherd` ports the ADR 0036 socket-activated launcher.
- `scripts/r3-acceptance.sh` + `tests/acceptance/`: the Tier 4 Playwright SSR acceptance suite and its bounded end-to-end runner (provision → migrate → serve → seed → Playwright → teardown).
- Committed `.sqlx/` offline query metadata for every new checked statement; the §7 fail-fast pipeline and the `CENTRAL_TEST_DSN`/`CENTRAL_TEST_MINIO_ENDPOINT`-gated integration suites are green.

## Completed: Phase R2 — Verified Artifact Lifecycle & Object Storage

Phase R2 delivered, per roadmap §5 and the [R2 plan](../internal/superpowers/plans/2026-10-22-phase-r2-verified-artifact-lifecycle.md):

- `central-foundation`: UUIDv4 generation/edge identities (`content_generation`, lineage edge IDs) alongside the R1 UUIDv7 newtypes.
- `central-artifact`: the pure lifecycle domain (reserve → staging → verifying → promotion → finalize, plus `reserved`/`rejected`/`delete_pending`/`deleted` with tombstones), the bounded content classifier, the orchestrating `Service` (materialize, resume-verifying, deliver, two-phase delete), the fenced bounded `Reconciler` (large-claim pass, rejected-staging sweep, staging-lifetime expiry), and the `b34` lineage model plus produce/read-edge port/query contracts.
- `central-adapter-s3`: the S3/MinIO `ObjectStore` (staging upload, bounded reads, atomic create-only promotion, staging/ready removal) with the bounded `TransferLimiter` and per-transfer idle/total deadlines.
- `central-adapter-postgres::artifact`: the artifact `Store`, two-phase delete + `CompletionContributor`, `ReconciliationStore`, and `b34` lineage stores — including the SB-G4 `central_runtime` UPDATE-demotion fix on `artifact_reconciliation_claims` recorded in `docs/internal/tasks/`.
- `central-kernel`: `artifact_reconcile::ArtifactReconcilerComponent` — the supervised periodic fenced pass (claim → renew → reconcile on a bounded `tokio::time::Interval`, idle-until-shutdown without an epoch) with `ArtifactPass`/`ArtifactFenceSource` composition seams.
- Committed `.sqlx/` offline query metadata for every new checked statement; the §7 fail-fast pipeline and the `CENTRAL_TEST_DSN` PostgreSQL integration suites are green (the `CENTRAL_TEST_MINIO_ENDPOINT`-gated S3 test skips cleanly when no MinIO is provisioned).

## Completed: Phase R1 — Workspace Scaffold, Canonical SQL Extraction (`v0..b37`) & Durable Task/Execution Core

Phase R1 delivered, per roadmap §4 and the [R1 plan](../internal/superpowers/plans/2026-10-21-phase-r1-workspace-and-durable-core.md):

- Cargo Workspace scaffold — root `Cargo.toml` (`[workspace.dependencies]`, `[workspace.lints]`), `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml` — per [rust-application-boundaries.md](../architecture/rust-application-boundaries.md); `cargo deny check` clean.
- `central-foundation`: UUIDv7 identity newtypes, the Failure taxonomy and exit classes, and the `central.local-result/v1` result envelope.
- `migrations/`: the complete `v0..b37` ordered SQL corpus extracted statement-for-statement from the upstream Go-embedded DDL, plus the immutable SHA-256 checksum `manifest.json` ([postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md)).
- `central-adapter-postgres`: the native migration runner — `central.schema_migrations` checksum ledger, single-session `pg_advisory_lock`, version-zero `VerifiedEmptyTarget` atomic baseline installer, dirty data-backfill resume without generic `Force`, and `reapply_incremental_runtime_grants` after `pg_restore`; `_sqlx_migrations` absent — plus the durable stores for workspace, authorization, event, checkpoint, task, and execution.
- Core Phase 1 durable domains: `central-workspace`, `central-task`, `central-execution`, `central-event`, `central-checkpoint`, `central-authorization`.
- `central-kernel` composition root: manual dependency composition, supervised component lifecycle (`CancellationToken` + bounded settlement), profile-aware readiness, and the ready-proof lifecycle (publish, revoke, generation fencing).
- `bins/central` skeleton: `--version` and fail-closed `exit 5` (`UNSUPPORTED_IN_THIS_SLICE`) `central.local-result/v1` JSON for R2–R6 verbs; it depends only on `central-kernel` and `central-foundation`.
- Committed `.sqlx/` offline query metadata; the §7 fail-fast pipeline and the `CENTRAL_TEST_DSN` PostgreSQL integration suites are green (lease fencing, recovery epochs, retry, and the outbox covered).

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
| R1 | Workspace scaffold, `v0..b37` extraction, native migration runner, durable Task/Execution core | **Complete** |
| R2 | Verified artifact lifecycle, `central-adapter-s3` | **Complete** |
| R3 | Harness control plane, `central-session`, `central-transport-http`, `central-harness-launcherd` | **Complete** |
| R4 | Phase 2 orchestration (`workflow`, `eventjournal`, `scheduler`, `retry`, `runview`, `runsubmit`), recovery matrix | **Active** |
| R5 | Host authority, protected broker, `central-adapter-linux`, Compose topology | Pending |
| R6 | Backup, restore, wipe, maintenance, launcher daemons | Pending |
