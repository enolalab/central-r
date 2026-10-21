# Central-Rust Documentation Baseline & Architecture Design

- **Date:** 2026-10-21
- **Status:** Draft (Pending User Review)
- **Target Repository:** `$CENTRAL_RUST_SRC`
- **Source Repository:** `$CENTRAL_SRC`

## 1. Purpose and Scope

`central-rust` is a full-parity Rust reimplementation of `central`, a local-first durable AI workspace and coding-agent harness control plane.

Before writing Rust production code, `central-rust` requires an authoritative documentation and design-contract baseline (`docs/`, `AGENTS.md`, `CLAUDE.md`, and SQL schema migrations) so that human developers and coding agents operate under the exact same domain invariants, security boundaries, wire formats, and database contracts proved in `central`, adapted cleanly to Rust idioms and compile-time guarantees.

This specification defines:
1. The **Canonical Mirror + Rust Gate 7 Replacement** documentation porting strategy.
2. The **Rust Application Boundaries** contract (Cargo Workspace topology, four-layer capability isolation, and dependency baseline).
3. The **PostgreSQL Adapter Mapping** adaptations for `sqlx` and Rust types.
4. The **Rust Engineering Workflow** contract (toolchain, offline SQL verification, linting, and supply-chain checks).
5. The **R-Slice Implementation Roadmap** (`R0` through `R5`), prioritizing the active Harness Session Boundary (ADR 0035 / ADR 0036) while preserving full host-security and backup/restore parity.

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
  - `threat-model.md`, `capability-policy.md`, `secret-reference.md`, `local-configuration-and-protected-state.md`
- **Operations & Topology (`docs/operations/`, `docs/architecture/`):**
  - `architecture/local-development-environment.md`, `architecture/online-mode.md`
  - `operations/harness-execution.md`, `operations/local-backup-and-restore.md`, `operations/local-prerequisites.md`, `operations/local-security-authority.md`, `operations/maintenance-runbook.md`, `operations/user-install-guide.md`, `operations/user-install-guide.vi.md`, `operations/install-acceptance.md`, `operations/release-authority-custody.md`, `compatibility.md`, `known-limitations.md`
- **Architecture Decision Records (`docs/adr/`):**
  - `README.md`, `template.md`, and `0001` through `0042` (retained as the immutable historical decision ledger of the Central architecture).
- **Selected Reference Specs (`docs/internal/superpowers/specs/`):**
  - Phase 0 domain/security/persistence/API specs and the Harness Adapter Boundary design specs (`2026-09-27-harness-adapter-boundary-design.md` through `2026-09-30-harness-phase-3m-live-usage-display-design.md`).
- **Authoritative SQL Schema (`migrations/`):**
  - All forward-only SQL migrations (`internal/adapter/postgres/migrate/migrations/` from `central`) copied verbatim so `central-rust` shares 100% database compatibility.

### 2.2 Rust-Adapted and Newly Authored Documents

The following documents are written specifically for `central-rust` (replacing Go-specific Gate 7 artifacts):

1. **`AGENTS.md` and `CLAUDE.md`:** Root instructions tailored to the Rust workspace, `cargo` workflow, and architectural invariants.
2. **`docs/README.md` & `docs/newcomer-guide.md`:** Updated index and orientation referencing Rust workspace crates and binaries.
3. **`docs/architecture/overview.md` & `docs/architecture/durable-execution.md`:** Updated kernel and boundary references for Rust.
4. **`docs/architecture/rust-application-boundaries.md`:** Replaces `go-application-boundaries.md`. Defines the Cargo Workspace DAG, capability crate layout, trait boundaries, and multi-binary targets.
5. **`docs/persistence/postgresql-adapter-mapping.md`:** Updated from `pgx/v5` + `sqlc` to `sqlx` (`0.8+`) with `.sqlx/` offline compile-time query verification and Rust primitive/newtype mappings.
6. **`docs/implementation/rust-engineering-workflow.md`:** Replaces `go-engineering-workflow.md`. Defines `rust-toolchain.toml`, `cargo fmt`, `cargo clippy` lint gates, `cargo sqlx prepare --check`, `cargo deny check`, and test taxonomy.
7. **`docs/implementation/current-phase.md` & `docs/implementation/rust-vertical-slice-roadmap.md`:** Defines the `R0`–`R5` delivery sequence for `central-rust`.
8. **`docs/adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md`:** Records the architectural transition to the Rust Cargo Workspace, dependency baseline, and Harness-first (`ADR 0035`) execution priority.

### 2.3 Excluded Historical Execution Artifacts

Go-specific execution logs, review transcripts, and gate evidence archives under `docs/internal/superpowers/reviews/`, `docs/internal/superpowers/plans/`, and `docs/internal/tasks/` are omitted from `central-rust` to prevent context pollution. Fresh directories are initialized for `central-rust` reviews and tasks.

---

## 3. Rust Application Boundaries (`rust-application-boundaries.md`)

### 3.1 Dependency Baseline

| Concern | Crate Selection | Boundary | License |
| --- | --- | --- | --- |
| Async Runtime | `tokio` (v1, `rt-multi-thread`, `macros`, `net`, `process`, `signal`, `sync`, `time`, `fs`) + `tokio-util` | `central-kernel`, adapters, transport, binaries only (prohibited in domain root) | MIT |
| HTTP Transport | `axum` (v0.8) + `tower` + `tower-http` + `rustls` | `central-transport-http` only | MIT / Apache-2.0 |
| Server-Rendered HTML | `askama` (compile-time typed templates with auto-escaping) | `central-transport-http` (`web` module) only | MIT / Apache-2.0 |
| PostgreSQL | `sqlx` (v0.8, `postgres`, `runtime-tokio-rustls`, `macros`, `migrate`) | `central-adapter-postgres` only | MIT / Apache-2.0 |
| Object Storage (S3/MinIO) | `aws-sdk-s3` + `aws-config` + `sha2` | `central-adapter-s3` only | Apache-2.0 |
| Linux Syscalls & IPC | `rustix` (or `nix`) (`fs`, `net`, `process`, `shm`/`mm` for `memfd_create`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`) | `central-adapter-linux` and launcher binaries only | Apache-2.0 / MIT |
| Identity (UUIDv7) | `uuid` (v1, `v7`, `serde`) | Wrapped privately inside `central-foundation::identity` | Apache-2.0 / MIT |
| Time | `time` (v0.3, `serde`, `formatting`, `parsing`) | `central-foundation` and across workspace | MIT / Apache-2.0 |
| Serialization | `serde` + `serde_json` | Wire envelopes, event payloads, config schemas, adapters | MIT / Apache-2.0 |
| Cryptography | `ed25519-dalek`, `hmac`, `sha2`, `rand`, `zeroize` | Broker, advisory verification, CSRF/session/approval binding | BSD-3 / MIT / Apache-2.0 |
| Observability | `tracing` + `tracing-subscriber` (JSON) + `prometheus-client` | Kernel, observability adapter, operational HTTP endpoints | MIT / Apache-2.0 |

### 3.2 Cargo Workspace Topology & Compiler-Enforced Clean Architecture

Instead of relying solely on external AST linters, `central-rust` enforces capability isolation through the Cargo Workspace dependency graph:

```text
central-rust/
├── Cargo.toml                      # Workspace root, shared [workspace.dependencies] & [workspace.lints]
├── rust-toolchain.toml             # Pinned stable toolchain
├── deny.toml                       # cargo-deny license, advisory, and source policy
├── migrations/                     # Canonical forward-only PostgreSQL migrations (v1..v32+)
├── .sqlx/                          # Offline compile-time verification metadata for sqlx
├── crates/
│   ├── central-foundation/         # identity (UUIDv7 newtypes), failure (error taxonomy & exit classes)
│   ├── capabilities/
│   │   ├── central-workspace/      # domain (root), port, query, app
│   │   ├── central-task/           # domain (root), port, query, app
│   │   ├── central-execution/      # lease fencing, recovery epochs, retry, outbox
│   │   ├── central-authorization/  # capability policy, grants, approvals
│   │   ├── central-session/        # bootstrap exchange, session lifecycle, CSRF bindings
│   │   ├── central-checkpoint/     # continuation envelopes & validation
│   │   ├── central-event/          # immutable event envelopes & seek-paginated feeds
│   │   ├── central-artifact/       # staging, SHA-256 verification, promotion, content policy
│   │   ├── central-harness/        # ADR 0035 harness control plane (attempts, budgets, permissions, capture)
│   │   ├── central-backup/         # backup/restore manifests, tickets, chunked inventory
│   │   └── central-infra/          # local init, prepare, compose lifecycle, doctor, maintenance
│   ├── adapters/
│   │   ├── central-adapter-postgres/ # sqlx implementations of capability `port` and `query` traits
│   │   ├── central-adapter-s3/       # S3/MinIO object storage adapter for `central-artifact`
│   │   ├── central-adapter-harness/  # Claude Code / OpenCode CLI protocol, git shadow clone, launcher client
│   │   └── central-adapter-linux/    # Protected broker protocol, memfd, SCM_RIGHTS, PAM/TTY, namespaces, cgroups
│   ├── transport/
│   │   └── central-transport-http/   # Axum controllers: API v1 JSON, Askama SSR Web UI, Health & Metrics
│   └── central-kernel/               # Manual dependency composition, supervised task runner, graceful shutdown
└── bins/
    ├── central/                      # Main CLI (`serve`, `local *`, `migrate *`, `backup *`, `restore *`, helper/broker modes)
    ├── central-harness-launcherd/    # Root socket-activated daemon launching isolated operator harness sessions (ADR 0036)
    ├── central-migration-launcherd/  # Dedicated migration launcher
    ├── central-migrate/              # Migration operator binary (`central-migrate` UID)
    ├── central-backup-launcherd/     # Backup/restore launcher daemon
    ├── central-backup/               # Backup operator binary
    ├── central-restore/              # Restore engine binary
    └── central-advisory-sign/        # Offline Ed25519 advisory signing tool
```

### 3.3 Four-Layer Role Rules inside Every Capability Crate

Each capability crate under `crates/capabilities/central-<cap>/src/` is structured into four strict modules:
1. **`lib.rs` / `domain.rs` (Domain Root):**
   - Pure synchronous Rust (`no async`, no I/O traits).
   - Owns Aggregate snapshots, status enums, version expectations, domain invariants, and approved `ChangeSet` construction.
2. **`port.rs` (Command-Persistence & External-Effect Ports):**
   - Operation-oriented traits (`CommitChangeSet`, atomic conditional lease/fencing operations, external-effect dispatch).
   - Never exposes CRUD table primitives or database transactions to callers.
3. **`query.rs` (Read Contracts):**
   - Consumer-side read traits, bounded request structs, safe read projections, and typed `SeekCursor` structs.
   - Offset pagination and unbounded queries are prohibited.
4. **`app.rs` (Service Layer):**
   - Orchestrates `load snapshot -> domain decision -> commit change-set` or `prepare durably -> invoke external adapter outside transaction -> settle outcome`.
   - No database transaction is ever held open across an external network, process, or object-storage call.

---

## 4. PostgreSQL Adapter Mapping for Rust (`postgresql-adapter-mapping.md`)

1. **Schema Authority:** All relations live in the `central` schema (`central.tasks`, `central.runs`, `central.harness_attempts`, etc.) and are always explicitly schema-qualified.
2. **Compile-Time Checked SQL:**
   - Every leaf query uses `sqlx::query!` / `sqlx::query_as!` checked against the canonical PostgreSQL 16 schema and recorded in `.sqlx/` for offline builds (`SQLX_OFFLINE=true`).
   - Dynamic SQL string concatenation (`format!`) is strictly prohibited. Configurable ordering uses explicit Rust `enum` variants mapped to dedicated static queries.
3. **Type Mapping:**
   - `uuid` (`NOT NULL`) $\leftrightarrow$ `central_foundation::identity::*Id` wrapping `uuid::Uuid` (strictly validated as lowercase RFC 9562 UUIDv7 on parse).
   - `timestamptz` $\leftrightarrow$ `time::OffsetDateTime` (database-time authoritative via `now()` / `transaction_timestamp()`; caller timestamps are never authoritative).
   - `bigint` versions/counters $\leftrightarrow$ `i64` (validated non-negative into domain `Version(u64)` / `ByteCount(u64)`).
   - `bytea` hashes/digests $\leftrightarrow$ `[u8; 32]` or bounded `Vec<u8>` with algorithm prefix byte.
   - `jsonb` $\leftrightarrow$ `sqlx::types::Json<T>` for bounded (32 KiB, depth $\le 8$) schema-versioned immutable envelopes only.

---

## 5. Rust Engineering Workflow (`rust-engineering-workflow.md`)

1. **Workspace Lints (`Cargo.toml`):**
   - `unsafe_code = "forbid"` in all capability (`domain`, `port`, `query`, `app`), `transport`, `postgres`, and `s3` crates. Only `central-adapter-linux` may encapsulate audited OS syscall boundaries via safe wrappers (`rustix`).
   - `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"`, `clippy::panic = "deny"`, `clippy::todo = "deny"`, `clippy::dbg_macro = "deny"` in non-test code.
2. **Mandatory Verification Pipeline:**
   - `cargo sqlx prepare --check --workspace -- --all-targets`
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo deny check` (verifies MIT/Apache-2.0 licenses, bans floating git dependencies, checks RustSec advisories)
   - `cargo test --workspace` (unit + deterministic PostgreSQL/MinIO integration suites)

---

## 6. R-Slice Implementation Roadmap (`current-phase.md` & `rust-vertical-slice-roadmap.md`)

- **Phase R0 — Documentation & Contract Baseline (Current Task):**
  - Port all language-agnostic docs, ADRs 0001–0042, and SQL migrations (`v1`–`v32+`).
  - Author `AGENTS.md`, `CLAUDE.md`, `ADR 0043`, `rust-application-boundaries.md`, `postgresql-adapter-mapping.md`, `rust-engineering-workflow.md`, `current-phase.md`, and `rust-vertical-slice-roadmap.md`.
- **Phase R1 — Workspace Scaffold, Foundation & Durable Task/Execution Core:**
  - Initialize Cargo workspace, `central-foundation` (UUIDv7, Failure taxonomy), `central-adapter-postgres` migration runner, and core durable domains (`workspace`, `task`, `execution`, `event`, `checkpoint`, `authorization`).
- **Phase R2 — Verified Artifact Lifecycle & Object Storage:**
  - Implement `central-artifact` and `central-adapter-s3` (staging reservation, streaming SHA-256 & size check, atomic promotion, content policy, Task completion guard).
- **Phase R3 — Harness Control Plane & `central serve` (ADR 0035 & 0036 Focus):**
  - Implement `central-harness` and `central-adapter-harness` (Claude Code adapter, shadow git repo & per-Run clone, `harness.report`/`patch`/`commits` capture, permission approval bridge, cost/wall-clock/token budgets, cancel/resume/rerun).
  - Implement `central-session` and `central-transport-http` (`axum` API v1 + `askama` SSR Web UI) and `central-harness-launcherd` (plus dev `localexec`).
- **Phase R4 — Host Authority, Protected Broker & Compose Topology (Slice A & B01–B07 Parity):**
  - Implement `central-adapter-linux`, `central-protected-broker` (`memfd` + `SCM_RIGHTS` + TLS leaf signing + XDG projections), PAM/TTY & `grant` ceremonies, and `central local init/prepare/up/down/doctor/status`.
- **Phase R5 — Backup, Restore, Wipe & Maintenance (Slice C, D, E Parity):**
  - Implement `central-backup`, `central-restore`, `central-backup-launcherd`, `pg_dump`/`pg_restore` fd-3 adapters, restore barriers, `wipe`, `prune`, and `security-rescue`.
