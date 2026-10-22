# Phase R1 — Workspace Scaffold, Canonical SQL Extraction (`v0..b37`) & Durable Task/Execution Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete, verified Phase R1 vertical slice in `$CENTRAL_RUST_SRC` per [rust-vertical-slice-roadmap.md](../../implementation/rust-vertical-slice-roadmap.md) §4: initialize the Cargo Workspace with compiler-enforced boundary and lint rules, implement `central-foundation` (UUIDv7 newtypes + Failure taxonomy), extract the exact `v0..b37` SQL schema and checksum manifest into `migrations/`, implement the native `central.schema_migrations` runner/inspector/reset/grant-reapply engine in `central-adapter-postgres`, implement the core Phase 1 durable capability domains (`central-workspace`, `central-task`, `central-execution`, `central-event`, `central-checkpoint`, `central-authorization`) and their PostgreSQL `sqlx` adapters, wire `central-kernel` lifecycle supervision and `bins/central` skeleton, and commit offline `.sqlx/` query metadata with all 5 verification gates green.

**Architecture:**
- **Compiler-enforced Cargo Workspace DAG ([rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §1–§3):**
  - `crates/central-foundation` owns opaque RFC 9562 UUIDv7 newtypes (plus the explicit `b20` sentinel `WorkspaceId` constant/parser rule) and the `Failure` / stable exit-class (0/2/3/4/5/6/7) taxonomy.
  - Capability crates (`central-workspace`, `central-task`, `central-execution`, `central-event`, `central-checkpoint`, `central-authorization`, plus stub crates for R2–R6 capabilities so the workspace graph is complete) enforce the four-layer `domain.rs` (pure sync, no `tokio`) / `port.rs` (`#[trait_variant::make(Send)]`) / `query.rs` (`SeekCursor`, no offset) / `app.rs` structure.
  - Cyclic-edge inversion ([rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §2.2): `central-execution` depends on `central-task` (one-way) and owns the claimability-decoration query contract (`central-execution::query`) so `central-task` never imports `central-execution`.
  - `crates/adapters/central-adapter-postgres` implements the native `central.schema_migrations` ledger (`v0`, `v8`–`v14`, `v16`–`v37` — 30 migration records; `v15` absent), single-session `pg_advisory_lock`, version-zero `VerifiedEmptyTarget` baseline installer, `VerifyServeBaseline`, `ResetRunner`, `reapply_incremental_runtime_grants`, and the `sqlx::query!` / `sqlx::query_as!` stores for `central-workspace`, `central-task`, `central-execution`, `central-event`, `central-checkpoint`, and `central-authorization`.

**Tech Stack:** Rust stable (`rust-toolchain.toml`), `tokio` v1, `trait-variant` v0.1, `sqlx` v0.8 (`postgres`, `runtime-tokio`, `tls-rustls-ring`, `macros`, `uuid`, `time`, `json` — **no `migrate` feature**), `uuid` v1 (`v7`, `serde`), `time` v0.3, `serde` + `serde_json`, `sha2`, `hmac`, `rand`, `zeroize`, `tracing`, `cargo-deny`.

## Global Constraints

- **Source of Truth:** `$CENTRAL_SRC` (read-only reference for exact domain transitions, SQL DDL, checksum strings, error codes, and test scenarios).
- **Zero `unsafe` in R1 Domain/Postgres/Kernel Crates:** Every R1 crate (`central-foundation`, capabilities, `central-adapter-postgres`, `central-kernel`) sets `unsafe_code = "forbid"` via workspace lints.
- **No Unwraps in Production Targets:** `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::todo`, and `clippy::dbg_macro` are `deny` across all non-test targets.
- **No `sqlx::migrate!` or `_sqlx_migrations`:** The `sqlx` `migrate` feature is prohibited. Schema state is governed exclusively by `central.schema_migrations`, `central.migration_checksums`, and `central.migration_progress`.
- **Every Task Ends Green:** Each task below runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, and commits before advancing.

---

## File Structure

```text
central-rust/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── rustfmt.toml
├── deny.toml
├── .gitignore
├── migrations/
│   ├── manifest.json                                   # 30 ordered entries (v0, v8..v14, v16..v37) + checksums
│   ├── 0000_baseline_zero.sql
│   ├── 0008_b08_execution_evidence.sql
│   ├── 0009_b08_recovery_evidence_correction.sql
│   ├── 0010_b08_final_safety_correction.sql
│   ├── 0011_b09_provider_evidence.sql
│   ├── 0012_b09_provider_evidence_correction.sql
│   ├── 0013_b09_provider_evidence_response_id_correction.sql
│   ├── 0014_b10_artifact_lifecycle.sql
│   ├── 0016_b09_provider_tool_call_mapping_correction.sql
│   ├── 0017_b09_durable_context_authority.sql
│   ├── 0018_b09_provider_turn.sql
│   ├── 0019_b11_task_lineage.sql
│   ├── 0020_b20_sentinel_workspace_id.sql
│   ├── 0021_b21_task_input_spec_shape.sql
│   ├── 0022_b22_evidence_continuation_parent_grant.sql
│   ├── 0023_b23_turn_dispatch_reference.sql
│   ├── 0024_b24_b09_recovery_reconciliation.sql
│   ├── 0025_b25_recovery_audit.sql
│   ├── 0026_b26_recovery_bootstrap_registration.sql
│   ├── 0027_b27_recovery_abandonment.sql
│   ├── 0028_b28_quarantine_observation_source.sql
│   ├── 0029_b29_prune_log.sql
│   ├── 0030_b30_harness_attempts.sql
│   ├── 0031_b31_harness_permission_approvals.sql
│   ├── 0032_b32_task_attempt_budgets.sql
│   ├── 0033_b33_workflow_graph.sql
│   ├── 0034_b34_artifact_lineage.sql
│   ├── 0035_b35_scheduler_workers.sql
│   ├── 0036_b36_checkpoints.sql
│   ├── 0037_b37_retry_idempotency.sql
│   └── reapply_incremental_runtime_grants.sql
├── .sqlx/                                              # Committed offline sqlx query metadata
├── crates/
│   ├── central-foundation/
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, identity.rs, failure.rs}
│   ├── capabilities/
│   │   ├── central-workspace/src/{lib.rs, domain.rs, port.rs, query.rs, app.rs}
│   │   ├── central-authorization/src/{lib.rs, domain.rs, port.rs, query.rs, app.rs}
│   │   ├── central-event/src/{lib.rs, domain.rs, port.rs, query.rs, app.rs}
│   │   ├── central-checkpoint/src/{lib.rs, domain.rs, port.rs, query.rs, app.rs}
│   │   ├── central-task/src/{lib.rs, domain.rs, execution_facade.rs, port.rs, query.rs, app.rs}
│   │   └── central-execution/src/{lib.rs, domain.rs, harness_run.rs, resume.rs, port.rs, query.rs, app.rs}
│   ├── adapters/
│   │   └── central-adapter-postgres/
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── lib.rs
│   │           ├── error.rs
│   │           ├── migrate/{mod.rs, manifest.rs, baseline.rs, runner.rs, inspector.rs, reset_runner.rs, grants.rs, verify_shape.rs}
│   │           ├── workspace.rs
│   │           ├── authorization.rs
│   │           ├── event.rs
│   │           ├── checkpoint.rs
│   │           ├── task/{mod.rs, queries.rs, store.rs, event_log_store.rs, milestone_store.rs}
│   │           └── execution/{mod.rs, queries.rs, store.rs, dispatchable.rs, reconciliation_attempt.rs, failed_recovery_workspaces.rs}
│   └── central-kernel/
│       ├── Cargo.toml
│       └── src/{lib.rs, lifecycle.rs, readiness.rs, readyproof.rs}
└── bins/
    └── central/
        ├── Cargo.toml
        └── src/main.rs
```

---

### Task 1: Workspace Scaffold, Toolchain, Lints, `deny.toml` & `central-foundation`

**Files:**
- Create: `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, `.gitignore`, `Cargo.toml`
- Create: `crates/central-foundation/Cargo.toml`
- Create: `crates/central-foundation/src/{lib.rs, identity.rs, failure.rs}`

**Interfaces & Reference:**
- Reference: `$CENTRAL_SRC/internal/identity/identity.go`, `$CENTRAL_SRC/internal/failure/failure.go`, `$CENTRAL_SRC/internal/adapter/postgres/migrate/b20_sentinel_workspace_id.go`
- Produces in `central_foundation::identity`:
  - Macro-generated opaque UUIDv7 newtypes matching every ID in `central/internal/identity/identity.go`: `InstanceId`, `WorkspaceId`, `TaskId`, `RunId`, `StepId`, `StepAttemptId`, `ToolCallId`, `ToolCallAttemptId`, `ApprovalId`, `CheckpointId`, `ArtifactId`, `EventId`, `ExecutionEventId`, `SessionId`, `BootstrapGenerationId`, `OperationId`, `BackupId`, `RestoreTicketId`, `HarnessAttemptId`, `HarnessEventId`, `HarnessPermissionApprovalId`, `WorkflowNodeId`, `WorkflowEdgeId`, `RunEventId`, `SessionAttemptId`, `WorkerId`, `NodeLeaseId`, `ResumeCheckpointId`, `OutboxEventId`.
  - Strict lowercase RFC 9562 UUIDv7 parser (`parse_*` / `FromStr` / `serde::Deserialize`) rejecting uppercase hex, nil UUIDs, non-v7 versions, and non-RFC9562 variants.
  - Explicit `SENTINEL_WORKSPACE_ID` (`018f0000-0000-7000-8000-000000000001` per `b20_sentinel_workspace_id.go`) constant and helper on `WorkspaceId`.
- Produces in `central_foundation::failure`:
  - `FailureKind` enum (`Invalid`, `NotFound`, `Conflict`, `Denied`, `Unavailable`, `Ambiguous`, `Cancelled`, `Internal`), HTTP status mapping (`400`, `404`, `409`, `403`, `503`, `409`/`502`, `409`, `500`), stable CLI `ExitClass` (`0`, `2`, `3`, `4`, `5`, `6`, `7`), and structured `Failure` type with safe machine `code` and redacted `message`.

- [x] **Step 1: Write `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, `.gitignore`, and root `Cargo.toml`**
  Configure `[workspace.dependencies]` and `[workspace.lints]` per [rust-engineering-workflow.md](../../implementation/rust-engineering-workflow.md) §2–§6 (`unsafe_code = "forbid"`, `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"`, `clippy::panic = "deny"`, `clippy::todo = "deny"`, `clippy::dbg_macro = "deny"`).

- [x] **Step 2: Implement `crates/central-foundation` (`identity.rs` and `failure.rs`)**
  Implement all opaque ID newtypes (keeping `uuid::Uuid` private to `central-foundation`, exposing `as_bytes(&self) -> &[u8; 16]` and `from_Trusted_db_bytes([u8; 16])` for the postgres adapter boundary) and `failure.rs`.

- [x] **Step 3: Write unit tests in `central-foundation`**
  Test UUIDv7 generation, lowercase enforcement (uppercase rejected), nil rejection, v4 rejection, JSON round-trip, `SENTINEL_WORKSPACE_ID` validity, and `FailureKind` / `ExitClass` mappings.

- [x] **Step 4: Run verification and commit Task 1**
  Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo deny check`, and `cargo test -p central-foundation`. Commit: `feat(r1): initialize Cargo workspace and implement central-foundation`.

---

### Task 2: Canonical `v0..b37` SQL Extraction & Checksum Manifest

**Files:**
- Reference: `$CENTRAL_SRC/internal/adapter/postgres/migrate/{baseline.go, b08.go..b37_retry_idempotency.go, reapply_incremental_runtime_grants.go, baseline_test.go}`
- Create: `migrations/manifest.json`
- Create: `migrations/0000_baseline_zero.sql` through `migrations/0037_b37_retry_idempotency.sql` (30 SQL files) and `migrations/reapply_incremental_runtime_grants.sql`

**Interfaces & Constraints:**
- The 30 migration records in `migrations/manifest.json` must match the exact `(version, checksum)` chain in `TestBaselineInstallProducesExactMigrationChainThroughV37` (`baseline_test.go:131-162`):
  - `0: "baseline-zero"`, `8: "b08-execution-evidence"`, `9: "b08-recovery-evidence-correction"`, `10: "b08-final-safety-correction"`, `11: "b09-provider-evidence"`, `12: "b09-provider-evidence-correction"`, `13: "b09-provider-evidence-response-id-correction"`, `14: "b10-artifact-lifecycle"`, `16: "b09-provider-tool-call-mapping-correction"`, `17: "b09-durable-context-authority"`, `18: "b09-provider-turn"`, `19: "b11-task-lineage"`, `20: "b20-sentinel-workspace-id"`, `21: "b21-task-input-spec_shape"`, `22: "b22-evidence-continuation-parent-grant"`, `23: "b23-turn-dispatch-reference"`, `24: "b24-b09-recovery-reconciliation"`, `25: "b25-recovery-audit"`, `26: "b26-recovery-bootstrap-registration"`, `27: "b27-recovery-abandonment"`, `28: "b28-quarantine-observation-source"`, `29: "b29-prune-log"`, `30: "b30-harness-attempts"`, `31: "b31-harness-permission-approvals"`, `32: "b32-task-attempt-budgets"`, `33: "b33-workflow-graph"`, `34: "b34-artifact-lineage"`, `35: "b35-scheduler-workers"`, `36: "b36-checkpoints"`, `37: "b37-retry-idempotency"`.
- Every SQL statement (tables, columns, types, `CHECK` constraints, triggers, functions, indexes, `GRANT`/`REVOKE` statements, and column-level `GRANT UPDATE (...)`) is extracted statement-for-statement from the corresponding Go file.

- [x] **Step 1: Extract `0000_baseline_zero.sql` and `0008`–`0024` from `baseline.go` and `b08.go`..`b24_*.go`**
  Preserve exact DDL, role creation/grants, `central.schema_migrations` / `central.migration_checksums` inserts, and trigger definitions.

- [x] **Step 2: Extract `0025`–`0037` from `b25_*.go`..`b37_retry_idempotency.go` and `reapply_incremental_runtime_grants.sql`**
  Preserve all Slice C/D recovery tables (`b25`–`b29`), Harness tables (`b30`–`b32`), Phase 2 workflow/scheduler/checkpoint/retry tables (`b33`–`b37`), and the exact `reapplyIncrementalRuntimeGrants` statement sequence (including SC-DEF-71 B08 grants and SC-DEF-85 B09 column-only update revocations).

- [x] **Step 3: Write `migrations/manifest.json` with SHA-256 content hashes and canonical ledger checksum identifiers**
  Record each entry's `version`, `ledger_checksum` (the exact string stored in `central.schema_migrations.checksum`), `file`, and `sha256` of the `.sql` file bytes.

- [x] **Step 4: Verify SQL extraction completeness against a disposable PostgreSQL 16 database (or syntax/manifest test) and commit Task 2**
  Commit: `feat(r1): extract canonical v0..b37 SQL migrations and checksum manifest`.

---

### Task 3: Native Migration Runner, Inspector, Shape Verifier & Grant Reapply in `central-adapter-postgres`

**Files:**
- Reference: `$CENTRAL_SRC/internal/adapter/postgres/migrate/{baseline.go, runner.go, inspector.go, reset_runner.go, reapply_incremental_runtime_grants.go, errors.go, b08.go..b37_retry_idempotency.go}`
- Create: `crates/adapters/central-adapter-postgres/Cargo.toml`
- Create: `crates/adapters/central-adapter-postgres/src/{lib.rs, error.rs}`
- Create: `crates/adapters/central-adapter-postgres/src/migrate/{mod.rs, manifest.rs, baseline.rs, runner.rs, inspector.rs, reset_runner.rs, grants.rs, verify_shape.rs}`

**Interfaces:**
- `BaselineInstaller`: `verify_stock_target`, `install` (idempotent `v0..v37` installation on a single `PgConnection`), `verify_shape`, `baseline_manifest` (returns version 37 and the 30 checksums).
- `Runner`: `prepare_up` (acquires the two-phase advisory locks in canonical order, binds `SessionBinding` backend PID + session start time, verifies stock target), `commit_up` (verifies `SessionBinding` and `VerifiedEmptyTarget` proof via `BrokerProofService` trait, runs `BaselineInstaller::install` + `verify_shape`).
- `Inspector`: `inspect` (reads `PostgresMigrationFacts`), `verify_serve_baseline` (`SET TRANSACTION READ ONLY`, asserts `current_user == "central_runtime"`, verifies `v0..v37` migration chain and full schema/grant/epoch shape).
- `ResetRunner`: `delete_schema` (acquires advisory locks, verifies version-zero-only eligibility, consumes reset confirmation proof, drops `central*` schemas and roles, verifies stock target).
- `reapply_incremental_runtime_grants`: idempotent grant + column-grant + revoke synchronization after `pg_restore`.

- [x] **Step 1: Scaffold `central-adapter-postgres` and implement `error.rs` and `migrate/manifest.rs`**
  Map SQLSTATE codes (`23505`, `23503`, `23514`, `40001`, `40P01`, `55P03`, `57014`, `42501`) to sanitized `central_foundation::failure::Failure` categories without leaking raw query text or database internals.

- [x] **Step 2: Implement `BaselineInstaller`, `verify_shape.rs`, and `grants.rs`**
  Port `Install`, `VerifyStockTarget`, `VerifyShape` (covering `v0` through `b37` shape checks), and `reapply_incremental_runtime_grants`.

- [x] **Step 3: Implement `Runner`, `Inspector`, and `ResetRunner`**
  Port single-session `pg_advisory_lock` acquisition, session binding verification, `VerifyServeBaseline`, and version-zero `ResetRunner`.

- [x] **Step 4: Write unit and PostgreSQL integration tests for `central-adapter-postgres::migrate`**
  Port the key tests from `baseline_test.go`, `runner_test.go`, `inspector_test.go`, and `reapply_incremental_runtime_grants_test.go` (including `test_baseline_manifest_targets_latest_applied_migration_through_b37`, `test_baseline_install_produces_exact_migration_chain_through_v37`, `test_baseline_install_idempotent`, and `test_verify_stock_target_rejects_central`).

- [x] **Step 5: Run verification and commit Task 3**
  Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p central-adapter-postgres`. Commit: `feat(r1): implement native migration runner, inspector, and grant reapply in central-adapter-postgres`.

---

### Task 4: Support Durable Capability Crates (`central-workspace`, `central-authorization`, `central-event`, `central-checkpoint`)

**Files:**
- Reference:
  - `$CENTRAL_SRC/internal/authority/`
  - `$CENTRAL_SRC/internal/checkpoint/`
  - `$CENTRAL_SRC/internal/eventjournal/` and `docs/events/v1.md`
  - `docs/persistence/postgresql-adapter-mapping.md` §3.1–§3.2 (`workspaces`, `workspace_event_counters`), §3.8–§3.10 (`approvals`, `events`, `checkpoints`)
- Create:
  - `crates/capabilities/central-workspace/{Cargo.toml, src/{lib.rs, domain.rs, port.rs, query.rs, app.rs}}`
  - `crates/capabilities/central-authorization/{Cargo.toml, src/{lib.rs, domain.rs, port.rs, query.rs, app.rs}}`
  - `crates/capabilities/central-event/{Cargo.toml, src/{lib.rs, domain.rs, port.rs, query.rs, app.rs}}`
  - `crates/capabilities/central-checkpoint/{Cargo.toml, src/{lib.rs, domain.rs, port.rs, query.rs, app.rs}}`

- [x] **Step 1: Implement `central-workspace`**
  Implement `WorkspaceSnapshot` (`id`, `state: WorkspaceState { Active, Deleted }`, `owner_principal_id`, `quota_ready_bytes`, `quota_ready_count`, `quota_max_bytes`, `security_epoch`, `restore_epoch`), sentinel workspace constants, `port.rs` (`#[trait_variant::make(Send)]`), `query.rs`, and `app.rs` with synchronous domain unit tests.

- [x] **Step 2: Implement `central-authorization`**
  Port the authority and capability-policy domain from `internal/authority/domain.go` and `genesis.go` (capability taxonomy, policy decisions, approval records, effective grants, 24-hour expiry, and genesis authority records) into `domain.rs`, `port.rs`, `query.rs`, and `app.rs`.

- [x] **Step 3: Implement `central-event`**
  Implement the Phase 1 immutable `Event` envelope (`EventId`, `WorkspaceId`, ` sequence: u64`, entity/state transition metadata, correlation/causation, schema version, bounded payload) and seek-paginated `EventFeedRead` (`SeekCursor`, no offset) per `docs/events/v1.md`.

- [x] **Step 4: Implement `central-checkpoint`**
  Port the Phase 1 checkpoint continuation envelope and validation rules from `docs/runtime/checkpoints.md` and `internal/checkpoint/domain.go` (`domain.rs`, `port.rs`, `query.rs`, `app.rs`), keeping the crate ready for Phase 2 (`b36`) extensions in R4.

- [x] **Step 5: Run verification and commit Task 4**
  Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`. Commit: `feat(r1): implement workspace, authorization, event, and checkpoint capability crates`.

---

### Task 5: `central-task` Capability Crate (`domain`, `execution_facade`, `port`, `query`, `app`)

**Files:**
- Reference: `$CENTRAL_SRC/internal/task/{domain.go, contract.go, execution_facade.go, domain_test.go, execution_facade_test.go, cancel_unclaimed_test.go, budget_test.go, permission_policy_test.go, resume_reconciled_test.go}`, `$CENTRAL_SRC/internal/task/port/port.go`, `$CENTRAL_SRC/internal/task/app/{service.go, query/contracts.go, query/event_log.go}`
- Create: `crates/capabilities/central-task/{Cargo.toml, src/{lib.rs, domain.rs, execution_facade.rs, port.rs, query.rs, app.rs}}`

**Interfaces & Invariants:**
- All task and run state transitions (`SubmitTask`, `RequestCancellation`, `CancelUnclaimedTask`, `SettleCancellation`, `RetryFailedTask`, `RerunCancelledTask`, and the `ExecutionFacade` transitions `ClaimTask`, `WaitTask`, `ResumeWaitingTask`, `CompleteTask`, `FailTask`) live in pure synchronous `domain.rs` and `execution_facade.rs`.
- Includes Phase 3c `PermissionPolicy` (`Deny`, `Bridge`, `AutoAllow`), Phase 3d task budget bounds (`max_cost_micro_usd`, `wall_clock_seconds`), Phase 3e `CancelUnclaimedTask`, and Phase 3g `waiting -> running` transition for `ResumeReconciledAttempt`.
- **Cyclic-edge inversion:** `central-task::query` defines `TaskListRead`, `TaskDetailRead`, and `TaskEventLogRead` without importing `central-execution`; claimability decoration lives in `central-execution::query` (Task 6).

- [x] **Step 1: Port `domain.rs` and `execution_facade.rs` in `central-task`**
  Translate all status enums (`TaskStatus`, `RunStatus`, `WaitReason`), `TaskAggregate`, `RunSnapshot`, `TaskChangeSet`, version expectations, and transition evaluators from `internal/task/domain.go` and `execution_facade.go`.

- [x] **Step 2: Port `port.rs`, `query.rs`, and `app.rs` in `central-task`**
  Define `ChangeSetStore` (`commit_task_change_set`), `AggregateLoader` (`load_aggregate`), `TaskListRead` / `TaskDetailRead` / `TaskEventLogRead` (with typed `TaskSeekCursor`), and the `TaskService` in `app.rs`.

- [x] **Step 3: Port all unit tests from `internal/task/*_test.go`**
  Cover `domain_test`, `execution_facade_test`, `cancel_unclaimed_test`, `budget_test`, `permission_policy_test`, and `resume_reconciled_test`.

- [x] **Step 4: Run verification and commit Task 5**
  Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p central-task`. Commit: `feat(r1): implement central-task domain, execution facade, ports, queries, and service`.

---

### Task 6: `central-execution` Capability Crate (`domain`, `harness_run`, `resume`, `port`, `query`, `app`)

**Files:**
- Reference: `$CENTRAL_SRC/internal/execution/{domain.go, harness_run.go, resume.go, domain_test.go, harness_run_test.go, resume_test.go, cancel_lease_test.go, recovery_cancellation_test.go}`, `$CENTRAL_SRC/internal/execution/port/port.go`, `$CENTRAL_SRC/internal/execution/app/{service.go, recovery.go, query/turn_activity.go}`, `$CENTRAL_SRC/internal/task/app/query/claimability_decorator.go`
- Create: `crates/capabilities/central-execution/{Cargo.toml, src/{lib.rs, domain.rs, harness_run.rs, resume.rs, port.rs, query.rs, app.rs}}`

**Interfaces & Invariants:**
- Owns Phase 1 durable execution evidence (B08 + Harness Phase 3a–3l execution commands):
  - Lease credentials, `OwnershipToken` fencing, heartbeat renewal, lease expiry.
  - Step and `StepAttempt` lifecycle (`Prepared`, `Invoked`, `Responded`, `Reconciling`, `Succeeded`, `Failed`, `Cancelled`), `ToolCall` and `ToolCallAttempt` idempotency operation keys and input hashes.
  - Recovery epochs (`RecoveryEpoch`, `EvaluateRecovery`, `EvaluateRecoveryCancellation`, `ResumeRecoveryEpoch`), outbox workspace work scheduling, and command receipt fingerprinting (`RequestFingerprint`).
  - Harness execution transitions (`StartHarnessRun`, `SettleHarnessRun`, `ResolveReconciliation` for `Fail`, `Cancel`, and `Rerun`, `ResumeReconciledAttempt` creating `sequence + 1` Step, and failure reasons including `budget_cost`, `budget_wall_clock`, `budget_tokens`, `permission_bridge_unavailable`, `harness_not_launched`, `artifact_*`).
- Owns `ClaimabilityDecorator` in `central-execution::query` (resolving the Go `task/app/query -> execution` cycle cleanly per [rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §2.2).
- Note: B09-specific provider-turn runtime methods are omitted from active execution wiring per ADR 0035 / ADR 0043 (while B09 schema tables remain in `migrations/` from Task 2).

- [x] **Step 1: Port `domain.rs`, `harness_run.rs`, and `resume.rs` in `central-execution`**
  Implement pure synchronous command evaluators, `ExecutionChangeSet` (including completion-guard types consumed by `central-artifact` in R2), `RequestFingerprint` SHA-256 computation, and recovery evaluators.

- [x] **Step 2: Port `port.rs`, `query.rs` (including claimability decorator), and `app.rs` (`Service` + `RecoveryGate`)**
  Define `CompositeStore`, `ExecutionRead`, `LeaseCredentialValidator`, `RecoveryClaimabilityReader`, `OutboxStore`, `RecoveryStore`, and the application service/recovery coordinator.

- [x] **Step 3: Port unit tests from `internal/execution/*_test.go` and `internal/execution/app/*_test.go`**
  Verify lease fencing, idempotency receipt replay vs fingerprint conflict, recovery epoch state machine, `EvaluateRecoveryCancellation`, `StartHarnessRun`/`SettleHarnessRun`, and `ResumeReconciledAttempt`.

- [x] **Step 4: Run verification and commit Task 6**
  Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p central-execution`. Commit: `feat(r1): implement central-execution domain, harness-run transitions, recovery, and service`.

---

### Task 7: PostgreSQL `sqlx` Stores for Task, Execution, Workspace, Event, Checkpoint & Offline `.sqlx/` Metadata

**Files:**
- Reference:
  - `$CENTRAL_SRC/internal/adapter/postgres/task/{queries.go, store.go, event_log_store.go, milestone_store.go, store_test.go}`
  - `$CENTRAL_SRC/internal/adapter/postgres/execution/{queries.go, store.go, dispatchable.go, reconciliation_attempt.go, failed_recovery_workspaces.go, store_test.go}`
- Create/Modify in `crates/adapters/central-adapter-postgres/src/`:
  - `workspace.rs`, `authorization.rs`, `event.rs`, `checkpoint.rs`
  - `task/{mod.rs, queries.rs, store.rs, event_log_store.rs, milestone_store.rs}`
  - `execution/{mod.rs, queries.rs, store.rs, dispatchable.rs, reconciliation_attempt.rs, failed_recovery_workspaces.rs}`
- Create: `.sqlx/` (generated by `cargo sqlx prepare --workspace -- --all-targets`)

**Interfaces & Constraints:**
- Every leaf SQL statement uses `sqlx::query!` or `sqlx::query_as!` with explicit `central.*` schema qualification (`central.workspaces`, `central.tasks`, `central.runs`, `central.steps`, `central.step_attempts`, `central.events`, `central.workspace_event_counters`, `central.execution_ownership`, `central.execution_command_receipts`, `central.outbox_workspace_work`, `central.recovery_epochs`).
- Strictly follows global lock ordering (`workspaces` $\rightarrow$ `workspace_event_counters` $\rightarrow$ `tasks` $\rightarrow$ `runs` $\rightarrow$ `steps` $\rightarrow$ `step_attempts` $\rightarrow$ `execution_ownership` $\rightarrow$ `events` $\rightarrow$ `outbox_workspace_work` $\rightarrow$ `execution_command_receipts`) per [postgresql-adapter-mapping.md](../../persistence/postgresql-adapter-mapping.md) §6.

- [x] **Step 1: Implement `workspace.rs`, `authorization.rs`, `event.rs`, `checkpoint.rs`, and `task/*` in `central-adapter-postgres`**
  Implement `ChangeSetStore`, `AggregateLoader`, `TaskListRead`, `TaskDetailRead`, `TaskEventLogRead`, and `MilestoneStore` using static `sqlx::query!` / `sqlx::query_as!` leaf queries and atomic transaction coordinators.

- [x] **Step 2: Implement `execution/*` in `central-adapter-postgres`**
  Implement `CompositeStore` (fenced atomic commit of `ExecutionChangeSet` + `TaskChangeSet` + `execution_command_receipts` + `outbox_workspace_work` + `events`), `ExecutionRead`, `LeaseCredentialValidator`, `RecoveryClaimabilityReader`, `DispatchableRunReader`, and recovery epoch persistence.

- [x] **Step 3: Provision local PostgreSQL 16 verification schema, generate `.sqlx/`, and run Tier 2 PostgreSQL integration tests**
  Provision the verification DB using the `v0..b37` runner from Task 3, run `cargo sqlx prepare --workspace -- --all-targets` to populate `.sqlx/`, and run the deterministic PostgreSQL integration tests (`task/store_test`, `execution/store_test`, lease fencing, idempotency replay, recovery epoch transitions).

- [x] **Step 4: Run verification and commit Task 7**
  Run `cargo sqlx prepare --check --workspace -- --all-targets`, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p central-adapter-postgres`. Commit: `feat(r1): implement PostgreSQL sqlx stores for task/execution core and commit .sqlx metadata`.

---

### Task 8: `central-kernel` Composition Root, `bins/central` Skeleton & Phase R1 Acceptance Gate

**Files:**
- Reference: `$CENTRAL_SRC/internal/kernel/{lifecycle.go, readiness.go, readyproof.go}`, `$CENTRAL_SRC/docs/architecture/local-development-environment.md` §11
- Create:
  - `crates/central-kernel/{Cargo.toml, src/{lib.rs, lifecycle.rs, readiness.rs, readyproof.rs}}`
  - `bins/central/{Cargo.toml, src/main.rs}`
- Modify:
  - `docs/implementation/current-phase.md` (record R1 completion and advance active slice to R2 upon passing all checks)

**Interfaces & Constraints:**
- `central-kernel` implements manual dependency composition, supervised task lifecycle (`CancellationToken` + bounded settlement timeout per [rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §2.2 Kernel-edge rule), and profile-aware readiness reporting.
- `bins/central` parses top-level operator commands and returns canonical `exit 5` (`UNSUPPORTED_IN_THIS_SLICE`) with structured `central.local-result/v1` JSON for commands owned by R2–R6 (`serve`, `local *`, `migrate *`, `backup *`, `restore *`, `run *`, `node *`, `checkpoint *`, `artifact *`) until their owning R-slice lands.

- [x] **Step 1: Implement `crates/central-kernel` (`lifecycle.rs`, `readiness.rs`, `readyproof.rs`) and unit tests**
  Test supervised component startup, graceful cancellation propagation on `CancellationToken`, bounded settlement deadline, and terminal component failure triggering profile cancellation with `ExitClass::Terminal` (`exit 6`).

- [x] **Step 2: Implement `bins/central` CLI skeleton and exit-class contract tests**
  Wire `central-kernel` and `central-foundation`, implement `--version` and closed fail-closed `UNSUPPORTED_IN_THIS_SLICE` (`exit 5`) handling for deferred R2–R6 verbs.

- [x] **Step 3: Execute the Mandatory 5-Stage Fail-Fast Verification Pipeline ([rust-engineering-workflow.md](../../implementation/rust-engineering-workflow.md) §7)**
  Run in exact order:
  ```bash
  cargo sqlx prepare --check --workspace -- --all-targets
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo deny check
  cargo test --workspace
  ```
  Verify every Phase R1 acceptance criterion in [rust-vertical-slice-roadmap.md](../../implementation/rust-vertical-slice-roadmap.md) §4 passes.

- [x] **Step 4: Update `docs/implementation/current-phase.md` and commit Task 8**
  Update `current-phase.md` to mark Phase R1 Complete and Phase R2 Active. Commit: `feat(r1): implement central-kernel lifecycle, central CLI skeleton, and complete Phase R1`.
