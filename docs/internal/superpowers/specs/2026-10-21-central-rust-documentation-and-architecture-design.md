# Central-Rust Documentation Baseline & Architecture Design

- **Date:** 2026-10-21
- **Status:** Approved (Remediated after Full Spec Review)
- **Target Repository:** `$CENTRAL_RUST_SRC`
- **Source Repository:** `$CENTRAL_SRC`

## 1. Purpose and Scope

`central-rust` is a full-parity Rust reimplementation of `central`, a local-first durable AI workspace, coding-agent harness control plane (Phase 1), and multi-agent workflow orchestration engine (Phase 2).

Before writing Rust production code, `central-rust` requires an authoritative documentation and design-contract baseline (`docs/`, `AGENTS.md`, `CLAUDE.md`, and canonical SQL schema migrations) so that human developers and coding agents operate under the exact same domain invariants, security boundaries, wire formats, and database contracts proved in `central`, adapted cleanly to Rust idioms and compile-time guarantees.

This specification defines:
1. The **Canonical Mirror + Rust Gate 7 Replacement** documentation porting strategy (`§2`), accounting for 100% of `central/docs/` files and link-integrity rules.
2. The **Rust Application Boundaries** contract (`§3`: Cargo Workspace topology, Phase 1 + Phase 2 capability crates, four-layer role isolation, async trait `Send + Sync` bounds, HTTP/HTML resource and security header limits, and dependency baseline).
3. The **PostgreSQL Adapter Mapping & Migration Architecture** (`§4`) for `sqlx` (`0.8+`), extracting embedded DDL (`baseline.go`, `b08`..`b37`) while preserving Central's custom `central.schema_migrations` checksum ledger, single-session advisory locking, version-zero proof, and incremental runtime grant reapplication.
4. The **Rust Engineering Workflow** contract (`§5`: toolchain, offline SQL verification, linting, and supply-chain checks).
5. The **R-Slice Implementation Roadmap** (`§6`: `R0` through `R6`), prioritizing the active Harness Session Boundary (ADR 0035 / ADR 0036) and Phase 2 Multi-Agent Workflow Orchestration while preserving full host-security and backup/restore parity.
6. Measurable **Phase R0 Acceptance Criteria** (`§7`).

---

## 2. Documentation Porting Classification

### 2.1 Verbatim Language-Agnostic Contracts (Copy from `central`)

The following documents define language-independent product, domain, wire, persistence, security, and operational rules and are ported into `central-rust/docs/` preserving their canonical meaning:

- **Product (`docs/product/`):**
  - `vision.md`, `roadmap.md`, `phases.md`, `use-cases.md`, `web-ui-feature-spec.md`, `agent-orchestration-view-design.md`
- **API & Events (`docs/api/`, `docs/events/`):**
  - `api/v1.md`, `events/v1.md`
- **Artifacts (`docs/artifacts/`):**
  - `lifecycle.md`, `content-policy.md`
- **Runtime Contracts (`docs/runtime/`):**
  - `agent-runtime.md`, `checkpoints.md`, `tool-invocation.md`
- **Persistence Contracts (`docs/persistence/`):**
  - `postgresql.md`, `migrations-and-recovery.md`
- **Security Contracts (`docs/security/`):**
  - `threat-model.md`, `capability-policy.md`, `secret-reference.md`, `local-configuration-and-protected-state.md`, `gitleaks-triage.md`, `vuln-scan-2026-10.md`
- **Operations & Topology (`docs/operations/`, `docs/architecture/`, root `docs/`):**
  - `architecture/local-development-environment.md`, `architecture/online-mode.md`
  - `operations/harness-execution.md`, `operations/phase-2-run-submit.md`, `operations/local-backup-and-restore.md`, `operations/local-prerequisites.md`, `operations/local-security-authority.md`, `operations/maintenance-runbook.md`, `operations/user-install-guide.md`, `operations/user-install-guide.vi.md`, `operations/install-acceptance.md`, `operations/release-authority-custody.md`, `operations/campaign-serve-bringup.md`, `operations/central-local-infra-delivery-requirements.md`, `operations/console-bringup-probe.md`, `operations/ghcr-push-runbook.md`, `operations/one-click-install-agent-brief.md`, `operations/slice-c-maintainer-tasks.md`
  - `compatibility.md`, `known-limitations.md`
- **Implementation Dossiers & Process Guides (`docs/implementation/`):**
  - `phase-1-entry-reconciliation.md`, `phase-1-vertical-slice-backlog.md`, `spec-and-plan-guide.md`
  - `phase-1-slices/` (`slice-a-host-authority-foundation.md`, `slice-b-first-safe-runnable-environment.md`, `slice-c-required-recovery.md`, `slice-d-destructive-portable-operations.md`, `slice-e-dependency-maintenance.md`)
  - `phase-2-slices/` (`README.md`, `slice-a-workflow-graph-lineage.md`, `slice-b-scheduler-workers.md`, `slice-c-checkpoint-resume.md`, `slice-d-retry-idempotency.md`, `slice-e-graph-ui.md`, `slice-f-phase2-acceptance.md`)
- **Architecture Decision Records (`docs/adr/`):**
  - `template.md` and `0001` through `0042` (retained unmodified as the immutable historical decision ledger of the Central architecture).
- **Authoritative Technical Specs (`docs/internal/superpowers/specs/`):**
  - Phase 0 foundational specs:
    - `2026-07-12-phase-0-adr-governance-design.md`, `2026-07-12-phase-0-domain-lifecycle-design.md`, `2026-07-13-phase-0-adr-governance-correction-design.md`, `2026-07-13-phase-0-security-baseline-secret-reference-design.md`, `2026-07-14-phase-0-api-event-serialization-design.md`, `2026-07-14-phase-0-artifact-storage-content-policy-design.md`, `2026-07-14-phase-0-postgresql-persistence-design.md`, `2026-07-14-phase-0-runtime-contracts-design.md`, `2026-07-16-phase-0-local-development-environment-design.md`
  - Phase 1 Slice & Harness design specs:
    - `2026-09-27-harness-adapter-boundary-design.md`, `2026-09-27-harness-phase-1a-domain-design.md`, `2026-09-27-harness-phase-1b-persistence-design.md`, `2026-09-27-harness-phase-2a-claude-code-adapter-design.md`, `2026-09-27-harness-phase-2b-harness-launcher-design.md`, `2026-09-28-harness-phase-3a-serve-wiring-design.md` through `2026-09-30-harness-phase-3m-live-usage-display-design.md`
    - `2026-10-08-issue-111-launcher-killer-design.md`, `2026-10-09-issue-120-real-launcher-default-design.md`, `2026-10-09-issue-122-run-submission-entrypoint-design.md`, `2026-10-09-issue-124-bp4-serve-real-launcher-design.md`, `2026-10-10-issue-126-opencode-adapter-design.md`, `2026-10-10-issue-128-codex-adapter-design.md`, `2026-10-11-issue-129-antigravity-adapter-design.md`
  - Phase 2 Multi-Agent Workflow Orchestration specs:
    - `2026-10-07-phase-2-artifact-lineage.md`, `2026-10-07-phase-2-checkpoint-resume-format.md`, `2026-10-07-phase-2-concurrency-resource-limits.md`, `2026-10-07-phase-2-event-schema-reconstruction.md`, `2026-10-07-phase-2-idempotency-consistency.md`, `2026-10-07-phase-2-recovery-test-matrix.md`, `2026-10-07-phase-2-retry-timeout-error-taxonomy.md`, `2026-10-07-phase-2-spec-gate-design.md`, `2026-10-07-phase-2-task-leasing-worker-protocol.md`, `2026-10-07-phase-2-workflow-graph-scheduling-design.md`, `2026-10-08-phase-2-acceptance-design.md`

### 2.2 Rust-Adapted and Newly Authored Documents

The following documents are written or adapted specifically for `central-rust` (replacing Go-specific Gate 7 artifacts):

1. **`AGENTS.md` and `CLAUDE.md`:** Root instructions tailored to the Rust workspace, `cargo` workflow, and architectural invariants.
2. **`docs/README.md` & `docs/newcomer-guide.md`:** Updated index and orientation referencing Rust workspace crates, binaries, and active contracts.
3. **`docs/architecture/overview.md` & `docs/architecture/durable-execution.md`:** Updated kernel and boundary references for Rust.
4. **`docs/architecture/rust-application-boundaries.md`:** Replaces `go-application-boundaries.md`. Defines the Cargo Workspace DAG, capability crate layout (including Phase 1 and Phase 2 capabilities), trait boundaries, HTTP/HTML resource and security header limits, and multi-binary targets.
5. **`docs/persistence/postgresql-adapter-mapping.md`:** Updated from `pgx/v5` + `sqlc` to `sqlx` (`0.8+`) with `.sqlx/` offline compile-time query verification, Rust primitive/newtype mappings, and Central's native migration/grant-reapply architecture.
6. **`docs/implementation/rust-engineering-workflow.md`:** Replaces `go-engineering-workflow.md`. Defines `rust-toolchain.toml`, `cargo fmt`, `cargo clippy` lint gates, `cargo sqlx prepare --check`, `cargo deny check`, and test taxonomy.
7. **`docs/implementation/current-phase.md` & `docs/implementation/rust-vertical-slice-roadmap.md`:** Defines the `R0`–`R6` delivery sequence for `central-rust`.
8. **`docs/adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md` & `docs/adr/README.md`:** Records the architectural transition to the Rust Cargo Workspace, dependency baseline, and Harness-first (`ADR 0035`) + Phase 2 workflow execution priority, and updates the ADR index.

### 2.3 Excluded Files and Link-Integrity Policy

- **Excluded Files:**
  - `docs/architecture/go-application-boundaries.md` and `docs/implementation/go-engineering-workflow.md` (replaced by their `rust-*.md` counterparts).
  - `docs/prototypes/*` (static roadmap HTML prototype tied to Go gate commits).
  - Historical Go execution logs, review transcripts, plans, and gate evidence archives under `docs/internal/superpowers/reviews/`, `docs/internal/superpowers/plans/`, and `docs/internal/tasks/`.
- **Link-Integrity Rule:**
  - In all active top-level documentation (`docs/README.md`, `docs/newcomer-guide.md`, `docs/architecture/*`, `docs/persistence/*`, `docs/implementation/current-phase.md`), relative links to `go-application-boundaries.md` and `go-engineering-workflow.md` are rewritten to `rust-application-boundaries.md` and `rust-engineering-workflow.md`.
  - Links from active docs to omitted historical Go review/evidence files (`../internal/superpowers/reviews/...`) are either removed or annotated as historical references to the upstream Go reference repository (`central`), while historical ADRs (`0001`–`0042`) remain untouched as immutable records.

---

## 3. Rust Application Boundaries (`rust-application-boundaries.md`)

### 3.1 Dependency Baseline

| Concern | Crate Selection | Boundary | License |
| --- | --- | --- | --- |
| Async Runtime | `tokio` (v1, `rt-multi-thread`, `macros`, `net`, `process`, `signal`, `sync`, `time`, `fs`) + `tokio-util` | `central-kernel`, adapters, transport, binaries only (prohibited in domain root) | MIT |
| Async Trait Bounds | `trait-variant` (v0.1) | Capability `port` and `query` traits to enforce `: Send` futures across `tokio` multi-threaded executors | MIT / Apache-2.0 |
| HTTP Transport | `axum` (v0.8) + `tower` + `tower-http` + `rustls` | `central-transport-http` only | MIT / Apache-2.0 |
| Server-Rendered HTML | `askama` (compile-time typed templates with auto-escaping) | `central-transport-http` (`web` module) only | MIT / Apache-2.0 |
| PostgreSQL | `sqlx` (v0.8, features: `postgres`, `runtime-tokio`, `tls-rustls-ring`, `macros`, `uuid`, `time`, `json`; `migrate` feature disabled in favor of Central's native migration ledger) | `central-adapter-postgres` only | MIT / Apache-2.0 |
| Object Storage (S3/MinIO) | `aws-sdk-s3` + `aws-config` + `sha2` | `central-adapter-s3` only | Apache-2.0 |
| Linux Syscalls & IPC | `rustix` (or `nix`) (`fs`, `net`, `process`, `shm`/`mm` for `memfd_create`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`) | `central-adapter-linux` and launcher binaries only | Apache-2.0 / MIT |
| Identity (UUIDv7) | `uuid` (v1, `v7`, `serde`) | Wrapped privately inside `central-foundation::identity` | Apache-2.0 / MIT |
| Time | `time` (v0.3, `serde`, `formatting`, `parsing`, `macros`) | `central-foundation` and across workspace | MIT / Apache-2.0 |
| Serialization | `serde` + `serde_json` | Wire envelopes, event payloads, config schemas, adapters | MIT / Apache-2.0 |
| Cryptography | `ed25519-dalek`, `hmac`, `sha2`, `rand`, `zeroize` | Broker, advisory verification, CSRF/session/approval binding | BSD-3 / MIT / Apache-2.0 |
| Observability | `tracing` + `tracing-subscriber` (JSON) + `prometheus-client` | Kernel, observability adapter, operational HTTP endpoints | MIT / Apache-2.0 |

### 3.2 Cargo Workspace Topology & Compiler-Enforced Clean Architecture

`central-rust` enforces capability isolation across both Phase 1 (Single-Task & Harness Control Plane) and Phase 2 (Multi-Agent Workflow Orchestration) through the Cargo Workspace dependency graph:

```text
central-rust/
├── Cargo.toml                        # Workspace root, shared [workspace.dependencies] & [workspace.lints]
├── rust-toolchain.toml               # Pinned stable toolchain
├── deny.toml                         # cargo-deny license, advisory, and source policy
├── migrations/                       # Canonical forward-only SQL & migration definitions (v0..b37)
├── .sqlx/                            # Offline compile-time verification metadata for sqlx
├── crates/
│   ├── central-foundation/           # identity (UUIDv7 newtypes), failure (error taxonomy & exit classes)
│   ├── capabilities/
│   │   ├── central-workspace/        # domain (root), port, query, app
│   │   ├── central-task/             # domain (root), port, query, app
│   │   ├── central-execution/        # Phase 1 lease fencing, recovery epochs, retry, outbox
│   │   ├── central-authorization/    # capability policy, grants, approvals
│   │   ├── central-session/          # bootstrap exchange, session lifecycle, CSRF bindings
│   │   ├── central-checkpoint/       # Phase 1 & Phase 2 (b36) subtree-anchored checkpoints & resume preflight
│   │   ├── central-event/            # Phase 1 immutable event envelopes & seek-paginated feeds
│   │   ├── central-artifact/         # staging, SHA-256 verification, promotion, content policy, b34 lineage
│   │   ├── central-harness/          # ADR 0035 harness control plane (attempts, budgets, permissions, capture)
│   │   ├── central-workflow/         # Phase 2A (b33) workflow_nodes, workflow_edges, dynamic DAG expansion
│   │   ├── central-eventjournal/     # Phase 2A (b33) canonical run_events envelope, fold & reconstruction
│   │   ├── central-scheduler/        # Phase 2B (b35) ready queue, worker registration, node leases, missed-beat ladder
│   │   ├── central-retry/            # Phase 2D (b37) error taxonomy, budgets, timeout hierarchy, compensation, outbox
│   │   ├── central-runview/          # Phase 2E DAG projection, run lineage view, fleet probes
│   │   ├── central-runsubmit/        # Phase 2 run submission orchestration
│   │   ├── central-backup/           # backup/restore manifests, tickets, chunked inventory, quarantine
│   │   └── central-infra/            # local init, prepare, compose lifecycle, doctor, maintenance, advisory
│   ├── adapters/
│   │   ├── central-adapter-postgres/ # sqlx implementations of capability `port` & `query` traits + migration runner
│   │   ├── central-adapter-s3/       # S3/MinIO object storage adapter for `central-artifact`
│   │   ├── central-adapter-harness/  # Claude Code, OpenCode, Codex, and Antigravity adapters + gitclone + launcher client
│   │   └── central-adapter-linux/    # Protected broker protocol, memfd, SCM_RIGHTS, PAM/TTY, namespaces, cgroups
│   ├── transport/
│   │   └── central-transport-http/   # Axum controllers: API v1 JSON, Askama SSR Web UI (Tasks + Phase 2 Runs), Health & Metrics
│   └── central-kernel/               # Manual dependency composition, supervised task runner, graceful shutdown
└── bins/
    ├── central/                      # Main CLI (`serve`, `run submit`, `node decide`, `checkpoint *`, `artifact read`, `local *`, `migrate *`, `backup *`, `restore *`, helper/broker/sandbox-launcher modes)
    ├── central-harness-launcherd/    # Root socket-activated daemon launching isolated operator harness sessions (ADR 0036)
    ├── central-migration-launcherd/  # Dedicated migration launcher
    ├── central-migrate/              # Migration operator binary (`central-migrate` UID)
    ├── central-backup-launcherd/     # Backup/restore launcher daemon
    ├── central-backup/               # Backup operator binary
    ├── central-restore/              # Restore engine binary
    └── central-advisory-sign/        # Offline Ed25519 advisory signing tool
```

*Note on Launcher Binaries vs Modes (SR-F1):* Matching the upstream Go architecture, `central-harness-launcherd`, `central-migration-launcherd`, and `central-backup-launcherd` are standalone root-owned daemons, while `central-protected-broker`, the root infrastructure `helper`, and `central-sandbox-launcher` are dedicated execution modes of the main `central` binary invoked under locked socket/systemd boundaries.

### 3.3 Four-Layer Role Rules inside Every Capability Crate

Each capability crate under `crates/capabilities/central-<cap>/src/` is structured into four strict modules:
1. **`lib.rs` / `domain.rs` (Domain Root):**
   - Pure synchronous Rust (`no async`, no I/O traits).
   - Owns Aggregate snapshots, status enums, version expectations, domain invariants, and approved `ChangeSet` construction.
2. **`port.rs` (Command-Persistence & External-Effect Ports):**
   - Operation-oriented traits (`CommitChangeSet`, atomic conditional lease/fencing operations, external-effect dispatch).
   - All async traits are annotated with `#[trait_variant::make(Send)]` (or explicit `+ Send` future bounds) and require `Send + Sync + 'static` so they compose cleanly with multi-threaded `tokio` / `axum` handlers.
   - Never exposes CRUD table primitives or database transactions to callers.
3. **`query.rs` (Read Contracts):**
   - Consumer-side read traits (`Send + Sync` with `Send` futures), bounded request structs, safe read projections, and typed `SeekCursor` structs.
   - Offset pagination and unbounded queries are prohibited.
4. **`app.rs` (Service Layer):**
   - Orchestrates `load snapshot -> domain decision -> commit change-set` or `prepare durably -> invoke external adapter outside transaction -> settle outcome`.
   - No database transaction is ever held open across an external network, process, or object-storage call.

### 3.4 HTTP, SSR HTML, and Resource Boundaries (SR-F2)

`central-transport-http` enforces the exact Gate 7 and SB-G4 resource and security contracts:
- **Concurrency & Memory Caps:** Max 32 active non-streaming requests, 64 queued waiters, 5-second admission wait timeout, 2 MiB maximum request/response buffer, and 64 MiB aggregate buffered-response memory cap. Admission is acquired before reading request bodies or touching PostgreSQL.
- **Normative Security Headers:** Every HTML page, redirect, error, and panic recovery response sets `Content-Security-Policy` with `frame-ancestors 'none'` (no inline script/style), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` (per SB-G4 operator-flow amendment), and `Cache-Control: no-store`.
- **Accessibility & SSR UX:** Keyboard-only operation, semantic landmarks, visible focus, Post/Redirect/Get (PRG) for all HTML mutations, CSRF token + `Origin` validation, and restart-barrier enforcement on Cancel/Retry/Rerun/Resume.

---

## 4. PostgreSQL Adapter Mapping & Migration Architecture (`postgresql-adapter-mapping.md`)

1. **Schema Authority:** All relations live in the `central` schema (`central.workspaces`, `central.tasks`, `central.runs`, `central.harness_attempts`, `central.workflow_nodes`, `central.workflow_edges`, `central.run_events`, `central.session_attempts`, `central.resume_checkpoints`, `central.event_outbox`, etc.) and are always explicitly schema-qualified.
2. **Migration Extraction & Native Ledger (`SR-02`):**
   - In the upstream Go repository, DDL and role grants are embedded inside Go files (`internal/adapter/postgres/migrate/{baseline,b08..b37,reapply_incremental_runtime_grants}.go`) rather than standalone `.sql` files, and are governed by `central.schema_migrations` with SHA-256 checksum verification, version-zero `VerifiedEmptyTarget` broker proofs, and single-session advisory locks.
   - `central-rust` extracts the exact SQL DDL from `baseline.go` (`v0`) and `b08.go` through `b37_retry_idempotency.go` into canonical ordered SQL files under `central-rust/migrations/` (used both by the runtime migration installer and to provision a verification database for `cargo sqlx prepare`).
   - `central-adapter-postgres` implements Central's native migration runner (`central.schema_migrations` checksum ledger, single-session `pg_advisory_lock`, version-zero atomic baseline installer, dirty data-backfill resume without generic `Force`, and `reapply_incremental_runtime_grants` after `pg_restore`), **not** `sqlx`'s default `_sqlx_migrations` table.
3. **Compile-Time Checked SQL:**
   - Every leaf query uses `sqlx::query!` / `sqlx::query_as!` checked against the canonical PostgreSQL 16 `central.*` schema (`v0..b37`) and recorded in `.sqlx/` for offline builds (`SQLX_OFFLINE=true`).
   - Dynamic SQL string concatenation (`format!`) is strictly prohibited. Configurable ordering uses explicit Rust `enum` variants mapped to dedicated static queries.
4. **Type Mapping:**
   - `uuid` (`NOT NULL`) $\leftrightarrow$ `central_foundation::identity::*Id` wrapping `uuid::Uuid` (strictly validated as lowercase RFC 9562 UUIDv7 on parse, except the explicitly admitted sentinel workspace ID per `b20`).
   - `timestamptz` $\leftrightarrow$ `time::OffsetDateTime` (database-time authoritative via `now()` / `transaction_timestamp()`; caller timestamps are never authoritative).
   - `bigint` versions/counters $\leftrightarrow$ `i64` (validated non-negative into domain `Version(u64)` / `ByteCount(u64)`).
   - `bytea` hashes/digests $\leftrightarrow$ `[u8; 32]` or bounded `Vec<u8>` with algorithm prefix byte.
   - `jsonb` $\leftrightarrow$ `sqlx::types::Json<T>` for bounded (32 KiB, depth $\le 8$) schema-versioned immutable envelopes only.

---

## 5. Rust Engineering Workflow (`rust-engineering-workflow.md`)

1. **Workspace Lints (`Cargo.toml`):**
   - `unsafe_code = "forbid"` in all capability (`domain`, `port`, `query`, `app`), `transport`, `postgres`, and `s3` crates. Only `central-adapter-linux` and launcher binaries may encapsulate audited OS syscall boundaries via safe wrappers (`rustix`).
   - `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"`, `clippy::panic = "deny"`, `clippy::todo = "deny"`, `clippy::dbg_macro = "deny"` in non-test code.
2. **Mandatory Verification Pipeline:**
   - `cargo sqlx prepare --check --workspace -- --all-targets`
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo deny check` (verifies MIT/Apache-2.0/BSD-3 licenses, bans floating git dependencies, checks RustSec advisories)
   - `cargo test --workspace` (unit + deterministic PostgreSQL/MinIO integration suites)

---

## 6. R-Slice Implementation Roadmap (`current-phase.md` & `rust-vertical-slice-roadmap.md`)

- **Phase R0 — Documentation & Contract Baseline (Current Task):**
  - Port all language-agnostic docs (`§2.1`), ADRs `0001`–`0042`, and authoritative Phase 0/1/2 design specs.
  - Author `AGENTS.md`, `CLAUDE.md`, `ADR 0043`, `rust-application-boundaries.md`, `postgresql-adapter-mapping.md`, `rust-engineering-workflow.md`, `current-phase.md`, and `rust-vertical-slice-roadmap.md`.
- **Phase R1 — Workspace Scaffold, Canonical SQL Extraction (`v0..b37`) & Durable Task/Execution Core:**
  - Initialize Cargo workspace, `central-foundation` (UUIDv7, Failure taxonomy), extract and verify the complete `v0..b37` SQL schema from Go `internal/adapter/postgres/migrate/*.go`, implement the native `central.schema_migrations` runner and grant-reapply engine in `central-adapter-postgres`, and build core Phase 1 durable domains (`workspace`, `task`, `execution`, `event`, `checkpoint`, `authorization`).
- **Phase R2 — Verified Artifact Lifecycle & Object Storage:**
  - Implement `central-artifact` and `central-adapter-s3` (staging reservation, streaming SHA-256 & size check, atomic promotion, content policy, Task completion guard, and `b34` lineage).
- **Phase R3 — Harness Control Plane & `central serve` (ADR 0035, ADR 0036 & Multi-Harness Focus):**
  - Implement `central-harness` and `central-adapter-harness` supporting Claude Code, OpenCode (issue #126), Codex (issue #128), and Antigravity (issue #129), git shadow repo & per-Run clone, `harness.report`/`patch`/`commits` capture, permission approval bridge (`v31`), cost/wall-clock/token budgets (`v32`), and cancel/resume/rerun (Phases 3a–3m).
  - Implement `central-session`, `central-transport-http` (`axum` API v1 + `askama` SSR Web UI), and `central-harness-launcherd` (plus dev `localexec` behind explicit dev gate per issue #120).
- **Phase R4 — Multi-Agent Workflow Orchestration (Phase 2 Parity: Slices 2A–2F):**
  - Implement `central-workflow` & `central-eventjournal` (Slice 2A: `workflow_nodes`, `workflow_edges`, `run_events`, dynamic child expansion, `central artifact read`), `central-scheduler` & `central-runsubmit` (Slice 2B: `SKIP LOCKED` ready queue, worker registration, node leases, missed-beat ladder, `central run submit`), Phase 2 subtree checkpoints (Slice 2C), `central-retry` (Slice 2D: error taxonomy, timeout hierarchy, compensation, transactional `event_outbox`, `central node decide`), `central-runview` (Slice 2E: `/app/runs` DAG UI, `run_lineage`, fleet view), and the 23-scenario recovery matrix (Slice 2F).
- **Phase R5 — Host Authority, Protected Broker & Compose Topology (Slice A & B01–B07 Parity):**
  - Implement `central-adapter-linux`, `central-protected-broker` (`memfd` + `SCM_RIGHTS` + TLS leaf signing + XDG projections), PAM/TTY & `grant` ceremonies (ADR 0028), and `central local init/prepare/up/down/doctor/status`.
- **Phase R6 — Backup, Restore, Wipe & Maintenance (Slice C, D, E Parity):**
  - Implement `central-backup`, `central-restore`, `central-backup-launcherd`, `pg_dump`/`pg_restore` fd-3 adapters, restore capacity reserve gate (ADR 0018), quarantine resolution, authority reset, `wipe`, `prune`, and `security-rescue`.

---

## 7. Phase R0 Acceptance Criteria (`SR-04`)

Phase R0 (the documentation and architecture contract baseline) is complete and ready for Phase R1 implementation only when all of the following hold:

1. **Completeness of Ported Inventory:** Every file listed in `§2.1` and `§2.2` exists at its canonical path inside `$CENTRAL_RUST_SRC/`, and every excluded file in `§2.3` (`go-application-boundaries.md`, `go-engineering-workflow.md`) is absent.
2. **ADR Ledger Integrity:** `docs/adr/README.md` indexes `ADR 0001` through `ADR 0043` with accurate statuses, dates, and reciprocal links; `ADR 0043` is recorded as `Accepted`.
3. **Zero Broken Active Links to Replaced Go Contracts:** Searching active documentation (`docs/README.md`, `docs/newcomer-guide.md`, `docs/architecture/`, `docs/persistence/`, `docs/implementation/current-phase.md`, `AGENTS.md`, `CLAUDE.md`) returns zero references to `go-application-boundaries.md` or `go-engineering-workflow.md`.
4. **Gate 7 Contract Parity:**
   - `docs/architecture/rust-application-boundaries.md` defines the complete Cargo Workspace crate matrix (covering all Phase 1 and Phase 2 capabilities), four-layer role import rules, `Send + Sync` port rules, HTTP/HTML resource caps (32 active requests, 64 waiters, 2 MiB buffer, 64 MiB total), CSP/security headers, and binary/daemon boundaries.
   - `docs/persistence/postgresql-adapter-mapping.md` maps `sqlx` v0.8 types, `.sqlx/` offline verification, SQL construction rules, and Central's native `central.schema_migrations` + grant-reapply architecture across `v0..b37`.
   - `docs/implementation/rust-engineering-workflow.md` defines pinned toolchain, `cargo fmt`, `cargo clippy` (`unwrap_used`/`expect_used`/`unsafe_code` gates), `cargo sqlx prepare --check`, `cargo deny check`, and CI verification order.
