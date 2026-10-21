# ADR 0043: Adopt Rust workspace and harness-first porting strategy

- **Number:** 0043
- **Title:** Adopt Rust workspace and harness-first porting strategy
- **Status:** Accepted
- **Created:** 2026-10-21
- **Owners:** Central maintainer
- **Decision due:** 2026-10-21
- **Decision due history:** None
- **Implementation blocked at:** Phase R1 Cargo workspace scaffold, canonical SQL extraction (`v0`..`b37`), `central-adapter-postgres` migration-runner implementation, and every later `central-rust` R-slice; the upstream Go `central` repository is not blocked.
- **Decided by:** Central maintainer
- **Decision date:** 2026-10-21
- **Decision record:** Git status-transition commit; exact hash resolved by this file's Git history
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0008 (for the `central-rust` repository only; see "Amended ADR 0008 clauses")
- **Amended by:** None
- **Related:** [ADR 0004](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md), [ADR 0007](0007-adopt-postgresql-persistence-and-recovery-contracts.md), [ADR 0008](0008-adopt-capability-owned-go-application-boundaries.md), [ADR 0035](0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md), [ADR 0036](0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md), [Central-Rust documentation and architecture design](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md), [Phase R0 documentation baseline plan](../internal/superpowers/plans/2026-10-21-phase-r0-documentation-baseline.md), [ADR governance](README.md)

## Context

`central` is a local-first durable AI workspace written in Go. ADRs 0001–0042 record its durable Task/Run lifecycle (ADR 0001, ADR 0004), Phase 1 security policy and SecretReference model (ADR 0003, amended by the ADR 0028 grant-ceremony series), verified Artifact lifecycle (ADR 0005), local v1 API and Event serialization (ADR 0006), PostgreSQL persistence and recovery contracts (ADR 0007), capability-owned Go application boundaries (ADR 0008 and its amendments), local topology and root-owned launcher components (ADR 0009–0019 series, ADR 0036), and the harness-session adapter boundary that froze the B09 loop coordinator (ADR 0035, ADR 0036). Phase 2 specifications add multi-agent workflow orchestration: dynamic workflow graphs, `run_events` journaling, worker scheduling and node leases, subtree checkpoints, retry/idempotency, and run lineage views.

`central-rust` is a full-parity Rust reimplementation of `central`. It must preserve 100% of those durable execution, security and authority, artifact, harness (ADR 0035 / ADR 0036), and Phase 2 multi-agent workflow orchestration contracts. Three forces require a durable decision before Rust implementation begins:

1. ADR 0008 expresses Gate 7 application boundaries in Go terms — one Go module, Go package ownership, Gin, pgx/sqlc, and gate ownership of downstream slices. None of that compiles in a Cargo codebase, yet the underlying four-layer discipline (controller → service → usecase, infrastructure implementing capability-owned `port` and `query` contracts, no public Unit of Work, adapter isolation, manual composition) is exactly what `central-rust` must enforce. A Rust expression of the same boundaries is required, and the Cargo dependency graph can enforce at compile time what Go could only enforce by review and architecture-guard tests.
2. The upstream schema has no canonical SQL form: DDL and role grants are embedded in Go files (`internal/adapter/postgres/migrate/{baseline,b08..b37,reapply_incremental_runtime_grants}.go`) governed by `central.schema_migrations`. `central-rust` needs standalone `.sql` files both for the runtime migration installer and for `sqlx` compile-time query verification — without weakening the checksum ledger, advisory locking, version-zero proof, or grant-reapply contracts of ADR 0007.
3. The frozen B09 loop coordinator must never be re-implemented (ADR 0035), so the port must sequence the active Harness Control Plane and Phase 2 orchestration — the differentiated product surface — ahead of re-proving host-authority and backup/restore plumbing that is already decided upstream.

## Decision

### 1. Adopt a multi-crate Cargo Workspace enforcing Gate 7's four-layer capability boundaries at compile time

`central-rust` is one Cargo Workspace. Every capability owns one crate under `crates/capabilities/central-<cap>/` structured into exactly four modules carrying the Gate 7 roles:

- `domain.rs` — pure synchronous domain root: aggregates, status enums, version expectations, invariants, approved `ChangeSet` construction; no async, no I/O traits.
- `port.rs` — operation-oriented command-persistence and external-effect traits; every async trait is `#[trait_variant::make(Send)]` (or explicit `+ Send` future bounds) and `Send + Sync + 'static` for `tokio` multi-threaded executors; no CRUD table primitives or database transactions escape to callers.
- `query.rs` — declaration-only read contracts, bounded requests, safe projections, and typed `SeekCursor` pagination; offset pagination and unbounded queries are prohibited.
- `app.rs` — service layer orchestrating `load snapshot -> domain decision -> commit change-set` or `prepare durably -> invoke external adapter outside transaction -> settle outcome`; no database transaction is held open across an external network, process, or object-storage call.

The workspace DAG — not convention — prohibits boundary violations:

- `crates/central-foundation`: UUIDv7 identity newtypes and the typed failure taxonomy.
- `crates/capabilities/*`: Phase 1 (`workspace`, `task`, `execution`, `authorization`, `session`, `checkpoint`, `event`, `artifact`, `harness`, `backup`, `infra`) and Phase 2 (`workflow`, `eventjournal`, `scheduler`, `retry`, `runview`, `runsubmit`) capabilities.
- `crates/adapters/central-adapter-{postgres,s3,harness,linux}`: infrastructure implementing capability-owned `port`/`query` traits; prohibited from leaking `sqlx`, `aws-sdk-s3`, or `rustix` types into capability APIs.
- `crates/transport/central-transport-http`: `axum` API v1 controllers plus `askama` server-rendered Web UI, under the Gate 7/SB-G4 resource caps and security headers.
- `crates/central-kernel`: manual dependency composition, supervised task runner, graceful shutdown.
- `bins/`: the `central` CLI (including `serve` and the protected-broker, helper, and sandbox-launcher execution modes) and standalone daemons `central-harness-launcherd` (ADR 0036), `central-migration-launcherd`, `central-migrate`, `central-backup-launcherd`, `central-backup`, `central-restore`, `central-advisory-sign`.

`unsafe_code` is forbidden in every capability, transport, PostgreSQL, S3, and harness crate; only `central-adapter-linux` and the launcher and protected-execution-mode binaries may encapsulate audited syscall boundaries through `rustix`. The canonical crate matrix, import rules, and resource limits live in [rust-application-boundaries.md](../architecture/rust-application-boundaries.md).

### 2. Pin the Rust dependency baseline

The dependency baseline of the approved Central-Rust design (§3.1) is adopted; the full boundary and license table lives in [rust-application-boundaries.md](../architecture/rust-application-boundaries.md):

| Concern | Crate |
| --- | --- |
| Async runtime | `tokio` (v1: `rt-multi-thread`, `macros`, `net`, `process`, `signal`, `sync`, `time`, `fs`) + `tokio-util` — kernel, adapters, transport, binaries only |
| Async trait bounds | `trait-variant` (v0.1) — capability `port`/`query` traits |
| HTTP transport | `axum` (v0.8) + `tower` + `tower-http` + `rustls` — `central-transport-http` only |
| Server-rendered HTML | `askama` — `central-transport-http` web module only |
| PostgreSQL | `sqlx` (v0.8: `postgres`, `runtime-tokio`, `tls-rustls-ring`, `macros`, `uuid`, `time`, `json`; `migrate` feature disabled) — `central-adapter-postgres` only |
| Object storage | `aws-sdk-s3` + `aws-config` + `sha2` — `central-adapter-s3` only |
| Linux syscalls and IPC | `rustix` (`fs`, `net`, `process`, `shm`/`mm` for `memfd_create`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`) — `central-adapter-linux` and launcher and protected-execution-mode binaries only |
| Identity | `uuid` (v1: `v7`, `serde`) — wrapped inside `central-foundation::identity` |
| Time | `time` (v0.3: `serde`, `formatting`, `parsing`, `macros`) — workspace-wide |
| Serialization | `serde` + `serde_json` — wire envelopes, event payloads, config, adapters |
| Cryptography | `ed25519-dalek`, `hmac`, `sha2`, `rand`, `zeroize` — broker, advisory verification, CSRF/session/approval binding |
| Observability | `tracing` + `tracing-subscriber` (JSON) + `prometheus-client` — kernel, observability adapter, operational endpoints |

License policy is MIT / Apache-2.0 / BSD-3, enforced by `cargo deny check` per [rust-engineering-workflow.md](../implementation/rust-engineering-workflow.md).

### 3. Extract embedded SQL migrations into canonical `.sql` files preserving the native migration contracts

The exact DDL in `baseline.go` (`v0`) and `b08`..`b37` is extracted into canonical, ordered `.sql` files under `central-rust/migrations/`, consumed both by the runtime migration installer and by the verification database behind `cargo sqlx prepare`. The extraction changes the file format only; the migration *contracts* are preserved unchanged in `central-adapter-postgres`:

- the `central.schema_migrations` SHA-256 checksum ledger — not `sqlx`'s `_sqlx_migrations` table, and the `sqlx` `migrate` feature stays disabled;
- single-session advisory locking (`pg_advisory_lock`);
- the version-zero `VerifiedEmptyTarget` broker proof and atomic baseline installer;
- dirty data-backfill resume without a generic `Force`;
- `reapply_incremental_runtime_grants` after `pg_restore`.

Every leaf query uses `sqlx::query!` / `sqlx::query_as!` checked against the canonical `central.*` schema and recorded in `.sqlx/` for offline builds (`SQLX_OFFLINE=true`); dynamic SQL string concatenation is prohibited. The type-mapping and verification rules live in [postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md).

### 4. Execute the `R0`–`R6` harness-first delivery sequence

`central-rust` implements the following slices in order; [rust-vertical-slice-roadmap.md](../implementation/rust-vertical-slice-roadmap.md) owns the per-slice detail:

- **R0 — Documentation and contract baseline:** the ported `docs/` tree, this ADR, and the Rust contract documents it references.
- **R1 — Workspace scaffold, canonical SQL extraction (`v0`..`b37`), and durable Task/Execution core.**
- **R2 — Verified Artifact lifecycle and S3/MinIO adapter.**
- **R3 — Harness Control Plane and `central serve`** (ADR 0035 / ADR 0036): `central-harness`, Claude Code / OpenCode / Codex / Antigravity adapters, permission bridge, budgets, cancel/resume/rerun, `central-harness-launcherd`, `central-session`, and `central-transport-http`.
- **R4 — Multi-Agent Workflow Orchestration** (Phase 2 slices 2A–2F): `central-workflow`, `central-eventjournal`, `central-scheduler`, `central-retry`, `central-runview`, `central-runsubmit`, and the recovery matrix.
- **R5 — Host authority, protected broker, and Compose topology.**
- **R6 — Backup, restore, wipe, and maintenance.**

R3 and R4 precede R5/R6 because they carry the active product surface decided by ADR 0035/0036 and the Phase 2 specifications; the dev-only `localexec` launcher path lets R3 land before the full root-daemon topology arrives in R5. The frozen B09 loop coordinator is **not** ported: it remains frozen upstream per ADR 0035, has no Rust counterpart, and harness session attempts are the only agent-execution unit `central-rust` models. B09's historical tables ship inside the canonical schema for ledger parity, but no Rust code reads or writes them.

### Amended ADR 0008 clauses

| ADR 0008 clause | Effective rule in `central-rust` after this ADR |
| --- | --- |
| "one Go 1.26.5 module at `github.com/enolalabs/central`" | One Cargo Workspace (`crates/capabilities/*`, `crates/adapters/*`, `crates/transport/*`, `central-kernel`, `bins/*`), pinned by `rust-toolchain.toml` and shared `[workspace.dependencies]`. |
| "capability-owned modular-monolith boundaries and manual composition" | Retained: one crate per capability with manual composition in `central-kernel`; no framework auto-wiring or service locator. |
| "the four Clean Architecture roles as per-capability responsibilities, not global horizontal packages" | Retained as the `domain.rs` / `port.rs` / `query.rs` / `app.rs` module split inside every capability crate, enforced by the workspace dependency DAG and lints at compile time rather than by review alone. |
| "controller-to-service-to-usecase dependency direction with infrastructure implementing Usecase-owned `port` and declaration-only `app/query` contracts" | Retained: `central-transport-http` and `bins/*` controllers call `app.rs` services; adapter crates implement capability-owned `port`/`query` traits; only the parent service invokes query traits after surface-appropriate authorization; transport never receives a query trait or a concrete adapter. |
| "domain-approved change-set commits plus named atomic conditional ports, with no public Unit of Work" | Retained unchanged. |
| "Gin isolation, pgx/sqlc adapter isolation, typed safe failures, explicit external-effect prepare/invoke/settle protocols, and supervised component lifecycle" | `axum`/`askama` confined to `central-transport-http`; `sqlx` to `central-adapter-postgres`; `aws-sdk-s3` to `central-adapter-s3`; `rustix` to `central-adapter-linux` and the launcher and protected-execution-mode binaries. Typed safe failures, `prepare -> invoke outside transaction -> settle`, and supervised lifecycle are retained unchanged. |
| "the selected dependency and observability baseline" | Replaced by the pinned Rust baseline in decision item 2; `tracing` + `prometheus-client` preserve the observability contract. |
| "Gate 8 ownership of concrete local topology/protected stores and Gate 9 ownership of executable vertical slices" | Replaced by the `R0`–`R6` slice ownership in decision item 4. |

These ADR 0008 rejections are unchanged and carry into `central-rust`: global horizontal `controller/service/usecase/infrastructure` trees, generic repository/service packages, framework-dependent core types, auto-migrate-on-serve, and adapter-owned business rules.

### Governance note

This amendment is scoped to the `central-rust` repository. In the upstream `central` repository, ADR 0008 remains Accepted and continues to govern the Go codebase unchanged, including the ADR 0036 amendment that added `central-harness-launcher` to the effective local topology — which maps to `bins/central-harness-launcherd` here. The ADR 0008 file in this repository is an immutable upstream record; the reciprocal amendment relationship is recorded in this repository's ADR index (README.md) and in this ADR's `Amends` field.

## Consequences

### Benefits

- The Cargo dependency DAG enforces Gate 7 boundaries at compile time: adapter-to-domain leaks, transport-to-query bypasses, and undeclared cross-capability imports fail `cargo build`, not a later architecture review.
- `#[trait_variant::make(Send)]` port and query traits guarantee every boundary composes with the multi-threaded `tokio`/`axum` runtime without per-call-site `Send` debugging.
- Canonical `.sql` files make the full `v0`..`b37` schema inspectable, diffable, and directly reusable for `sqlx` offline verification — while the preserved `central.schema_migrations` ledger, advisory lock, `VerifiedEmptyTarget` proof, and grant reapply keep ADR 0007's contracts byte-for-byte intact.
- Harness-first sequencing lands the ADR 0035/0036 control plane and Phase 2 orchestration — Central's differentiated surface — before re-proving host-authority and backup/restore plumbing whose decisions are already durable.
- The frozen B09 coordinator is never ported, permanently eliminating ~5.7k lines of dead loop code plus its PostgreSQL binding from the implementation surface.
- The pinned baseline plus `cargo deny check` gives supply-chain, license, and RustSec-advisory gates equivalent to the upstream dependency-attestation discipline.

### Costs and limitations

- Rust code holds no B09 evidence even in frozen form; historical `b09_*` tables exist only as migrated schema. Operators auditing old B09 provider-turn history must read upstream `central`.
- This ADR forward-links `rust-application-boundaries.md`, `postgresql-adapter-mapping.md`, `rust-engineering-workflow.md`, and `rust-vertical-slice-roadmap.md`, which land in the remaining Phase R0 tasks; the links resolve at Phase R0 acceptance, and until then dependent implementation remains blocked exactly as `Implementation blocked at` states.
- The amendment is repository-scoped: readers must track that ADR 0008's effective decision differs between `central` (Go) and `central-rust` (Cargo Workspace), and the upstream ADR 0008 file cannot record the reciprocal `Amended by` because it is immutable.
- Full-parity porting risks semantic drift between the Go reference and Rust implementations; the mitigation is contract-level conformance to the ported specifications plus deterministic PostgreSQL/MinIO integration suites in each R-slice, not line-by-line transliteration.
- Async-trait `Send` machinery (`trait-variant`) adds an indirection layer over plain `async fn` in traits, and `sqlx` compile-time checking requires maintaining the `.sqlx/` offline metadata and a verification database provisioned from `migrations/`.
- Extracting DDL from Go sources is a manual, error-prone step; a checksum-equivalence check between extracted `.sql` files and the upstream Go-embedded statements is required before R1 claims parity.

## Alternatives considered

### Single-crate port mirroring the Go package layout

Rejected. Rust module visibility inside one crate cannot enforce adapter/transport isolation at the dependency level; only the Cargo DAG between crates makes the four-layer direction a compile error. A single crate would also serialize compilation of every capability and remove the per-crate `unsafe_code` boundary.

### Literal transliteration of the Go codebase, including the B09 coordinator

Rejected. ADR 0035 froze B09 precisely because per-turn loop orchestration contradicts Central's positioning; re-implementing it in Rust would resurrect a dead surface and block R3 on code with no production future.

### Adopt `sqlx`'s built-in migrator (`_sqlx_migrations`)

Rejected. It cannot express Central's checksum-ledger semantics, single-session advisory locking, version-zero `VerifiedEmptyTarget` proof, dirty-backfill resume, or `reapply_incremental_runtime_grants` after restore. ADR 0007's persistence and recovery contracts are preserved verbatim; only the file format of the DDL changes.

### Infrastructure-first ordering (port R5/R6 host authority and backup/restore before the harness plane)

Rejected. It reproduces plumbing whose decisions are already durable while delaying the only surfaces that deliver product value: harness sessions and Phase 2 orchestration. The dev-gated `localexec` path (per the upstream harness-launcher design) supplies R3's launcher dependency until `central-harness-launcherd` lands.

### Supersede ADR 0008 entirely

Rejected. Capability ownership, manual composition, the four-layer roles, change-set/conditional-port transaction patterns, adapter isolation, and the enumerated rejections remain correct; only the language-specific enforcement mechanism and dependency baseline change. A full replacement would have to re-litigate a decision that is still right.

## Follow-ups

- Phase R0 plan Tasks 3–5 author the linked Rust contracts (`rust-application-boundaries.md`, `postgresql-adapter-mapping.md`, `rust-engineering-workflow.md`, `current-phase.md`, `rust-vertical-slice-roadmap.md`) and adapt top-level orientation docs; Phase R0 acceptance requires all links from this ADR to resolve.
- R1: scaffold the Cargo Workspace, extract and checksum-verify `v0`..`b37` `.sql` files against the upstream Go-embedded statements, implement the native `central.schema_migrations` runner, and wire `cargo deny check` before the first adapter code lands.
- Central maintainer: decide per-R-slice acceptance evidence parity with upstream gate records before R3's first harness adapter is claimed live.
- ADR index: row added in this ADR's commit (done).

## References

- [Central-Rust documentation and architecture design (approved)](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md)
- [Phase R0 documentation baseline plan](../internal/superpowers/plans/2026-10-21-phase-r0-documentation-baseline.md)
- [ADR 0004 — Adopt staged single-agent runtime and verified adapter handoffs](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [ADR 0007 — Adopt PostgreSQL persistence and recovery contracts](0007-adopt-postgresql-persistence-and-recovery-contracts.md)
- [ADR 0008 — Adopt capability-owned Go application boundaries](0008-adopt-capability-owned-go-application-boundaries.md)
- [ADR 0035 — Freeze the B09 loop coordinator and adopt a harness-session adapter boundary](0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md)
- [ADR 0036 — Add a separate harness launcher for operator harness sessions](0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md)
- [Rust application boundaries contract](../architecture/rust-application-boundaries.md)
- [PostgreSQL adapter mapping (sqlx)](../persistence/postgresql-adapter-mapping.md)
- [Rust engineering workflow](../implementation/rust-engineering-workflow.md)
- [Rust vertical-slice roadmap](../implementation/rust-vertical-slice-roadmap.md)
- [ADR governance and index](README.md)
