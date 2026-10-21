# PostgreSQL Adapter Mapping — Canonical Contract

- **Status:** Adopted
- **Replaces:** Gate 7 PostgreSQL adapter mapping for the Rust codebase. The upstream `pgx/v5` + `sqlc` contract (same filename in `central/docs/persistence/`) is historical provenance only.
- **Governing documents:**
  - [Central-Rust Documentation and Architecture Design](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md) — governing spec (§4)
  - [ADR 0043 — Adopt Rust Workspace and Harness-First Porting Strategy](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md)
  - [Rust Application Boundaries — Canonical Contract](../architecture/rust-application-boundaries.md)
  - [PostgreSQL Persistence Contract](postgresql.md)
  - [Migration and Recovery Contract](migrations-and-recovery.md)
  - [ADR 0007 — Adopt PostgreSQL Persistence and Recovery Contracts](../adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md)
  - [ADR 0011 — Accepted](../adr/0011-amend-local-topology-for-dedicated-migration-operator.md) (local-topology adapter alignment)
- **Implementation target:** R-slices R1–R6 per [rust-application-boundaries.md](../architecture/rust-application-boundaries.md) §13 (R1 owns the Cargo workspace scaffold, canonical `v0`..`b37` SQL extraction, the native migration runner, and the durable Task/Execution core)

## 1. Purpose and authority

This document maps every accepted Usecase-owned `port.rs` and `query.rs` contract from the [canonical Rust application boundaries contract](../architecture/rust-application-boundaries.md) to a complete PostgreSQL 16 schema realization. It specifies tables, columns, types, constraints, indexes, role grants, transaction patterns, SQLSTATE mappings, and the SQL-construction policy that the PostgreSQL adapter crate `central-adapter-postgres` must conform to. This document creates no DDL, Rust source, `.sqlx/` metadata, or executable artifact. It is a normative design contract that R-slice implementation and acceptance testing must faithfully realize.

Every row in this document identifies the Clean Architecture boundary: the exact Usecase-owned `port.rs` or `query.rs` contract it serves, the parent-Service caller, the infrastructure implementation role, and the controller-visible safe outcome. A table row or index with no contract provenance fails acceptance validation.

This document does not change the accepted domain, runtime, security, Artifact, API, Event, backup, or migration meanings defined by the upstream gates and carried into the boundary contract. It only supplies a concrete PostgreSQL realization plan for those meanings.

**Terminology and provenance labels.** Three uniform renames are applied throughout this document and are themselves normative:

1. **Module paths.** Upstream Go package paths map to Rust crate modules: `task` port → `central-task::port`, `task` app → `central-task::app`, `task` `app/query` → `central-task::query`, and identically for every other capability. Two assignments differ from a mechanical prefix rename: the outbox claim/settle ports (upstream `event` port) and the execution-ownership lease ports (upstream `task` port) are owned by `central-execution::port` in Rust (`central-execution` carries Phase 1 lease fencing, retry, and outbox dispatch per the boundary contract §2.2), the provider/tool external-effect ports (upstream `agent` port) are owned by `central-harness::port`/`central-execution::port`, and the upstream agent execution component maps to `central-execution::app` under the `central-harness` + `central-execution` sequential-coordinator pair (boundary contract §6.4).
2. **Owner labels.** Upstream `Gate 9 — <capability>` evidence-owner labels appear here as `R-slice — <capability>`; per ADR 0043, the R0–R6 delivery sequence replaces Gate 9 ownership. Upstream `Gate 8` references appear as the R5 local-topology slice (see `local-development-environment.md`).
3. **Driver and query mechanism.** `pgx/v5` + `sqlc` are replaced by `sqlx` v0.8 with compile-time-checked query macros (§2.1). Upstream `sqlc` leaf-query names map to dedicated static `sqlx::query!`/`sqlx::query_as!` leaf queries inside `central-adapter-postgres`, and the upstream `golang-migrate` driver indirection is replaced by Central's native migration runner inside `central-adapter-postgres` (§9). The `sqlx` `migrate` feature and the `_sqlx_migrations` table are prohibited.

---

## 2. Schema, type, and construction policy

### 2.1 SQL-construction policy (normative)

1. **Bound parameters.** Every value in every SQL statement is a bound parameter (`$1`, `$2`, …). String concatenation, `format!`/`format_args!` for query construction, and parameter embedding in SQL text are prohibited.
2. **Schema qualification.** All application relations — tables, views, indexes, constraints, functions, triggers, and sequences — are fully `central`-schema-qualified (`central.tasks`, `central.events`, etc.). They are never resolved through `search_path`.
3. **Prohibited dynamic identifiers.** Dynamic identifier construction (`format!("central.{}", table_name)`), generic filter maps, and user-supplied column/table/index names are prohibited. Every column, table, constraint, and index referenced in application SQL is a fixed, reviewable literal.
4. **Ordering and identifier allowlists.** Where ordering is configurable (e.g., Task list projections), an explicit Rust `enum` maps to a fixed allowlist of column names. Each ordering variant receives its own dedicated static `sqlx` leaf query with a fixed `ORDER BY` clause. Handwritten coordinators may select among pre-declared static queries but may not construct ordering clauses dynamically.
5. **Application tables in `central` only.** No application table lives in `public`, `pg_catalog`, `information_schema`, or any user-created schema. The `central` schema is owned by the migration role and has privileges granted only as defined in §7.
6. **Compile-time-checked leaf queries (`sqlx`).** Every leaf query is a named, static `sqlx::query!` or `sqlx::query_as!` invocation inside `central-adapter-postgres`, checked at compile time against the canonical `central.*` schema (`v0`..`b37`, §2.5) and recorded in `.sqlx/` for offline builds (`SQLX_OFFLINE=true`). Each leaf name embeds the capability, operation, and read/write intent (e.g., `workspace::get_by_id`, `task::insert`, `event::seek_after_cursor`). Adapter-internal row and parameter types remain confined to `central-adapter-postgres` and are never exported or passed across the adapter boundary; the unchecked `sqlx::query()`/`sqlx::query_as()` function forms are not used for leaf queries because they bypass compile-time verification.
7. **Handwritten coordinators.** Compound transaction orchestration (multi-statement change-set commits, outbox claim/settle, Event range allocation, cross-aggregate finalizers) is handwritten inside `central-adapter-postgres` capability modules. These coordinators receive the same static-analysis scrutiny as macro-checked queries: every statement path is enumerable, every parameter is bound, every lock is in the global order, and every retry guard is explicit. `sqlx::Transaction`, `PgConnection`, `PgPool`, and `Executor` handles never appear in capability `port.rs`/`query.rs` signatures and never escape the adapter.
8. **Prohibited patterns.** Offset pagination (`OFFSET … LIMIT`), N+1 queries (iterating result rows to issue additional queries), readiness exact-count queries (`SELECT count(*)` on the readiness path), unbounded results (`SELECT …` without `LIMIT`), and `EXPLAIN` evidence below the full reference dataset are acceptance failures.
9. **Query-plan evidence.** Every blocking, discovery, and projection predicate must have a matching composite index. `EXPLAIN (ANALYZE, BUFFERS)` evidence on the reference dataset (10,000 Tasks, 50,000 Runs, 250,000 StepAttempt/ToolCallAttempt rows, 1,000,000 Events, 100,000 command receipts, 10,000 Artifact metadata rows) must show an index-backed bounded plan. The owning capability slice executes and records this evidence.

### 2.2 Type mapping

| Application concept | PostgreSQL type | Rust realization | Notes |
| --- | --- | --- | --- |
| Aggregate/session/Artifact/Event identity (opaque UUIDv7) | `uuid` not null | `central_foundation::identity::*Id` newtype wrapping `uuid::Uuid` | Stored as native 128-bit; parse validates canonical lowercase RFC 9562 variant 7; the explicitly admitted sentinel workspace ID (b20) is the only exception to UUIDv7 validation |
| Workspace identity | `uuid` not null | `central_foundation::identity::WorkspaceId` | Foreign key into every Workspace-scoped relation |
| Aggregate version | `bigint` not null default 0 | `i64` at the boundary, validated non-negative into domain `Version(u64)` | Non-negative; incremented per accepted mutation |
| Event sequence | `bigint` not null | `i64` | Workspace-local strictly increasing |
| Instant (created_at, updated_at, occurred_at) | `timestamptz` not null default `now()` | `time::OffsetDateTime` | Database-time authoritative |
| Deadline / expiry time | `timestamptz` not null | `Option<time::OffsetDateTime>` | Nullable where absent is a real state |
| Byte count / counter | `bigint` not null default 0 check (`>= 0`) | `i64` validated non-negative into `ByteCount(u64)` | Non-negative with constraint |
| Checksum / fingerprint / verifier hash | `bytea` not null | `[u8; 32]` or bounded `Vec<u8>` | SHA-256 bounded; prefixed with algorithm/version byte where required |
| Status / kind / state | `text` not null | Capability-owned status `enum` | `CHECK` constraint enumerating the full accepted vocabulary for that column |
| Event payload / Checkpoint metadata | `jsonb` | `sqlx::types::Json<T>` for bounded (32 KiB, depth ≤ 8) schema-versioned immutable envelopes only | Allowlisted versioned envelopes only |
| Opaque fencing token | `uuid` not null | Opaque fencing-token newtype | Generated at claim time; opaque to callers |
| Bootstrap generation | `bigint` not null | `i64` | Monotonically increasing per Workspace |

### 2.3 Nullability policy

Nullable columns represent a real absent state, never an empty-string or zero-value convention. Columns that must always have a value are `NOT NULL`. Columns whose absence has domain meaning (e.g., `first_used_at` for a session not yet used, `revoked_at` for an active session, `retry_at` for an outbox record never retried) are nullable without a default value. `text` columns never use `''` as a sentinel.

### 2.4 Representation rules

- `jsonb` is allowed only for bounded, allowlisted, versioned immutable envelopes: type-specific Event payloads and compatible Checkpoint metadata. Ownership, lifecycle state, versions, leases, fencing tokens, quota ledgers, and queried guards are never hidden in a generic JSON document.
- Aggregate `version` is a strictly increasing integer, never a UUID or text label.
- `timestamptz` values are always derived from database time (`now()`, `statement_timestamp()`, `transaction_timestamp()`, or `clock_timestamp()` as appropriate). No caller-supplied timestamp is accepted as a durable authority.
- Status columns use explicit `CHECK` constraints enumerating every legal value for the Phase 1 local MVP. A future status addition is an explicit forward migration.
- `sqlx::types::Json<T>` payloads deserialize into capability-owned, schema-versioned envelope types; `serde_json::Value` is never an adapter-boundary type.

### 2.5 Canonical `migrations/` extraction and `.sqlx/` offline verification (SR-02)

In the upstream Go repository, DDL and role grants are embedded inside Go files (`internal/adapter/postgres/migrate/{baseline,b08..b37,reapply_incremental_runtime_grants}.go`) rather than standalone `.sql` files. `central-rust` extracts the exact SQL DDL from `baseline.go` (`v0`) and `b08.go` through `b37_retry_idempotency.go` into canonical, ordered, version-controlled `.sql` files under the workspace-root `migrations/` directory, accompanied by an immutable SHA-256 checksum manifest. Extraction preserves statement order, statement boundaries, comments where load-bearing, and every role-grant statement; it introduces no new DDL and no semantic change to the `central.*` schema.

`migrations/` has exactly two consumers:

1. **The native migration installer** inside `central-adapter-postgres` (§9), which executes the extracted `.sql` files under the `central.schema_migrations` ledger.
2. **The compile-time verification schema.** `migrations/` provisions a local PostgreSQL 16 verification database at `v0`..`b37`; `cargo sqlx prepare --workspace -- --all-targets` checks every `sqlx::query!`/`sqlx::query_as!` leaf query against that schema and writes the `.sqlx/` metadata directory. `.sqlx/` is committed to the repository so that workspace builds resolve query metadata offline (`SQLX_OFFLINE=true`); CI re-verifies it with `cargo sqlx prepare --check --workspace -- --all-targets`. See [rust-engineering-workflow.md](../implementation/rust-engineering-workflow.md).

**Dependency declaration.** `central-adapter-postgres` depends on `sqlx` v0.8+ with exactly this feature set and no others: `postgres`, `runtime-tokio`, `tls-rustls-ring`, `macros`, `uuid`, `time`, `json`. The `migrate` feature is disabled workspace-wide; `sqlx::migrate!`, `sqlx::migrate::Migrator`, the `sqlx migrate` CLI, and the `_sqlx_migrations` table are prohibited. `central.schema_migrations`, `central.migration_checksums`, and `central.migration_progress` are the only migration-ledger relations.

### 2.6 Native migration ledger and runner (SR-02)

`central-adapter-postgres` implements Central's native migration runner — explicitly **not** `sqlx`'s `_sqlx_migrations` machinery and no external migration framework:

- **Checksum ledger.** `central.schema_migrations` records every applied version with its SHA-256 checksum; `central.migration_checksums` is the append-only checksum history; `central.migration_progress` carries data-backfill cursors. Verification compares recorded checksums against the `migrations/` manifest.
- **Single-session `pg_advisory_lock`.** All mutation executes on exactly one non-rebinding `central_migration` session holding the common target-exclusive and migration-specific advisory locks (§9.2).
- **Version-zero atomic baseline installer.** First-time provisioning consumes a `VerifiedEmptyTarget` broker proof and commits the entire baseline — `schema_migrations`, checksum history, initial application schema, epoch-zero markers, initial bootstrap registration — in one transaction (§9.3).
- **Dirty data-backfill resume without generic `Force`.** An interrupted `data_backfill` migration is resumed only through the recognized `ResumableMigration` path, which revalidates the exact operation and continues after the last committed cursor; there is no generic force/dirty-clear path (§9.4–§9.6).
- **`reapply_incremental_runtime_grants` after `pg_restore`.** The extracted grant-reapply statements run idempotently after every database-replacement restore so runtime role grants match the incremental grant history (§9, §10).

The full runner protocol, lock ordering, inspector rules, and prohibition matrix are defined in §9.

---

## 3. Table, column, constraint, and index inventory

All tables live in the `central` schema. The schema owner is `central_migration`. Columns are listed as `name` → `type` [`constraints`]. Every constraint name follows `{table}_{role}` (e.g., `tasks_pkey`, `events_workspace_sequence_unique`). Foreign keys use `{table}_{referenced_table}_fkey`.

### 3.1 Workspace

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `state` | `text` | `NOT NULL CHECK (state IN ('active', 'deleted'))` |
| `owner_principal_id` | `text` | `NOT NULL` |
| `quota_ready_bytes` | `bigint` | `NOT NULL DEFAULT 0 CHECK (quota_ready_bytes >= 0)` |
| `quota_ready_count` | `bigint` | `NOT NULL DEFAULT 0 CHECK (quota_ready_count >= 0)` |
| `quota_max_bytes` | `bigint` | `NOT NULL DEFAULT 10737418240 CHECK (quota_max_bytes > 0)` |
| `security_epoch` | `bigint` | `NOT NULL DEFAULT 0` |
| `restore_epoch` | `bigint` | `NOT NULL DEFAULT 0` |

**Unique constraint:** `workspaces_pkey` on `(id)`.

**Indexes:**
- None beyond the primary key. Workspace lookup is always by `id`.

**Clean Architecture boundary:**
- `query.rs` contract: `SessionStatusRead` (`central-session::query`) → workspace-owned defense-in-depth predicate on every query.
- `port.rs` contract: Workspace quota ledger (`central-artifact::port`) → row lock for capacity reserve/settle/release.

### 3.2 Workspace event counter

| Column | Type | Constraints |
| --- | --- | --- |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `last_event_sequence` | `bigint` | `NOT NULL DEFAULT 0 CHECK (last_event_sequence >= 0)` |

**Unique constraint:** `workspace_event_counters_pkey` on `(workspace_id)`.

**Indexes:**
- Primary key is the only index. Only one row per Workspace.

**Clean Architecture boundary:**
- `port.rs` contract: Event sequence allocation within change-set commit. The PostgreSQL adapter atomically increments `last_event_sequence` by the Event count in the same transaction as state mutation, Event append, outbox reference creation, and receipt insert. This is a performance-critical single-row counter update with a row lock, never a `SEQUENCE`.

### 3.3 Task

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `status` | `text` | `NOT NULL CHECK (status IN ('queued', 'running', 'waiting_for_approval', 'waiting_for_input', 'completed', 'failed', 'cancelled'))` |
| `title` | `text` | `NOT NULL` |
| `input_spec` | `jsonb` | Not null; bounded 32 KiB, depth ≤ 8 |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `correlation_id` | `uuid` | `NULL` |
| `causation_id` | `uuid` | `NULL` |
| `idempotency_key` | `text` | `NULL` |
| `failure_reason` | `text` | `NULL` |
| `retry_eligible_at` | `timestamptz` | `NULL` |
| `retry_count` | `bigint` | `NOT NULL DEFAULT 0 CHECK (retry_count >= 0)` |
| `expiry_at` | `timestamptz` | `NULL` |

**Unique constraints:**
- `tasks_workspace_id_idempotency_key_unique` on `(workspace_id, idempotency_key)` where `idempotency_key` is a nullable bounded text column derived from the application command scope/key.

**Indexes:**
- `tasks_workspace_status_created_idx` on `(workspace_id, status, created_at DESC)` — Task list projection; covering index for `TaskListRead`.
- `tasks_workspace_id_idx` on `(workspace_id, id)` — Task detail lookup; `TaskDetailRead`.
- `tasks_retry_eligible_idx` on `(workspace_id, retry_eligible_at)` where `retry_eligible_at IS NOT NULL` — atomic conditional retry-eligibility scan.
- `tasks_cleanup_expiry_idx` on `(workspace_id, expiry_at)` where `expiry_at IS NOT NULL AND status IN ('completed', 'failed', 'cancelled')` — cleanup eligibility.

**Clean Architecture boundary:**
- `port.rs` contract: `central-task::port` → Task change-set commit (create, transition, cancel, retry, resume). Domain produces `TaskChangeSet`; adapter commits with version CAS, constraint enforcement, and Event/receipt append.
- `query.rs` contract: `TaskListRead` (`central-task::query`) → `central-task::app` Service → `ListTasks`; `TaskDetailRead` (`central-task::query`) → `central-task::app` Service → `GetTaskDetail`.

### 3.4 Run

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `task_id` | `uuid` | `NOT NULL REFERENCES central.tasks(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `status` | `text` | `NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'))` |
| `run_index` | `bigint` | `NOT NULL CHECK (run_index >= 0)` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `failure_reason` | `text` | `NULL` |
| `capacity_run_ready_bytes` | `bigint` | `NOT NULL DEFAULT 0 CHECK (capacity_run_ready_bytes >= 0)` |

**Unique constraints:**
- `runs_workspace_task_index_unique` on `(workspace_id, task_id, run_index)`.

**Indexes:**
- `runs_task_id_idx` on `(workspace_id, task_id, created_at DESC, id DESC)` — stable descending `RunSeekCursor{CreatedAt, RunID}` pagination for the Task detail projection; `TaskDetailRead`.
- `runs_status_idx` on `(workspace_id, status)` — reconciliation discovery.
- `runs_cleanup_idx` on `(workspace_id, status, updated_at)` — cleanup eligibility; covering pattern for terminal runs past retention.

**Clean Architecture boundary:**
- `port.rs` contract: `central-task::port` → Run is a child aggregate within the Task execution chain. Run state transitions occur only within the Task change-set commit.
- `query.rs` contract: `TaskDetailRead` (`central-task::query`) → embedded `RunSummary` list in projection.

### 3.5 Step

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `run_id` | `uuid` | `NOT NULL REFERENCES central.runs(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `status` | `text` | `NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'))` |
| `step_index` | `bigint` | `NOT NULL CHECK (step_index >= 0)` |
| `step_kind` | `text` | `NOT NULL CHECK (step_kind IN ('approval', 'provider', 'tool', 'checkpoint'))` |
| `provider_operation` | `text` | `NULL` |
| `tool_operation` | `text` | `NULL` |
| `approval_capability` | `text` | `NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `failure_reason` | `text` | `NULL` |

**Unique constraints:**
- `steps_workspace_run_index_unique` on `(workspace_id, run_id, step_index)`.

**Indexes:**
- `steps_run_id_idx` on `(workspace_id, run_id, step_index ASC)` — Task detail projection.
- `steps_status_idx` on `(workspace_id, status)` — reconciliation.

**Clean Architecture boundary:**
- `port.rs` contract: `central-task::port` → Step transitions within the Task change-set commit. `step_kind` determines whether the sequential coordinator invokes an authorization, provider, or tool adapter.

### 3.6 StepAttempt

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `step_id` | `uuid` | `NOT NULL REFERENCES central.steps(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `status` | `text` | `NOT NULL CHECK (status IN ('prepared', 'invoked', 'succeeded', 'retryable_failure', 'terminal_failure', 'cancelled', 'ambiguous'))` |
| `attempt_index` | `bigint` | `NOT NULL CHECK (attempt_index >= 0)` |
| `adapter_identity` | `text` | `NOT NULL` |
| `adapter_revision` | `text` | `NOT NULL` |
| `operation_key` | `text` | `NOT NULL` |
| `manifest_hash` | `bytea` | `NOT NULL` |
| `budget_config` | `jsonb` | Not null; bounded |
| `authority_deadline` | `timestamptz` | `NOT NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `outcome_kind` | `text` | `NULL CHECK (outcome_kind IN ('success', 'retryable', 'terminal', 'cancelled', 'ambiguous'))` |
| `outcome_evidence` | `jsonb` | `NULL` |
| `failure_reason` | `text` | `NULL` |

**Unique constraints:**
- `step_attempts_workspace_step_attempt_unique` on `(workspace_id, step_id, attempt_index)`.

**Indexes:**
- `step_attempts_step_id_idx` on `(workspace_id, step_id, attempt_index ASC)` — Task detail.
- `step_attempts_status_idx` on `(workspace_id, status)` — recovery/reconciliation.

**Clean Architecture boundary:**
- `port.rs` contract: `central-task::port` → StepAttempt is the provider/physical-attempt evidence record. `central-execution::app` prepares the attempt durably through `central-task::port`, then the sequential coordinator invokes the `central-harness::port` provider adapter outside the transaction and settles the outcome through a `central-task::port` settlement method. No adapter can create, advance, or correct an attempt directly.

### 3.7 ToolCall

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `step_id` | `uuid` | `NOT NULL REFERENCES central.steps(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `status` | `text` | `NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed'))` |
| `tool_index` | `bigint` | `NOT NULL CHECK (tool_index >= 0)` |
| `tool_identity` | `text` | `NOT NULL` |
| `tool_operation` | `text` | `NOT NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `failure_reason` | `text` | `NULL` |

**Unique constraints:**
- `tool_calls_workspace_step_tool_unique` on `(workspace_id, step_id, tool_index)`.

**Indexes:**
- `tool_calls_step_id_idx` on `(workspace_id, step_id, tool_index ASC)`.

**Clean Architecture boundary:**
- `port.rs` contract: `central-task::port` → ToolCall is owned by the Task domain as ToolCallAttempt evidence within the execution chain.

### 3.8 ToolCallAttempt

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `tool_call_id` | `uuid` | `NOT NULL REFERENCES central.tool_calls(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `status` | `text` | `NOT NULL CHECK (status IN ('prepared', 'invoked', 'succeeded', 'retryable_failure', 'terminal_failure', 'cancelled', 'ambiguous'))` |
| `attempt_index` | `bigint` | `NOT NULL CHECK (attempt_index >= 0)` |
| `adapter_identity` | `text` | `NOT NULL` |
| `adapter_revision` | `text` | `NOT NULL` |
| `operation_key` | `text` | `NOT NULL` |
| `manifest_hash` | `bytea` | `NOT NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `outcome_kind` | `text` | `NULL CHECK (outcome_kind IN ('success', 'retryable', 'terminal', 'cancelled', 'ambiguous'))` |
| `outcome_evidence` | `jsonb` | `NULL` |
| `failure_reason` | `text` | `NULL` |

**Unique constraints:**
- `tool_call_attempts_workspace_tc_attempt_unique` on `(workspace_id, tool_call_id, attempt_index)`.

**Indexes:**
- `tool_call_attempts_tool_call_id_idx` on `(workspace_id, tool_call_id, attempt_index ASC)`.
- `tool_call_attempts_status_idx` on `(workspace_id, status)` — recovery.

**Clean Architecture boundary:**
- `port.rs` contract: `central-task::port` → ToolCallAttempt is the tool/physical-attempt evidence record, analogous to StepAttempt for tools.

### 3.9 Artifact

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `task_id` | `uuid` | `NOT NULL REFERENCES central.tasks(id)` |
| `run_id` | `uuid` | `NOT NULL REFERENCES central.runs(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `state` | `text` | `NOT NULL CHECK (state IN ('reserved', 'staging', 'verifying', 'ready', 'delete_pending', 'deleted', 'quarantined'))` |
| `media_type` | `text` | `NULL` |
| `size` | `bigint` | `NOT NULL DEFAULT 0 CHECK (size >= 0)` |
| `staging_generation` | `uuid` | `NOT NULL` |
| `object_key` | `text` | `NOT NULL` |
| `checksum_algorithm` | `text` | `NULL` |
| `checksum_value` | `bytea` | `NULL` |
| `sensitivity` | `text` | `NOT NULL CHECK (sensitivity IN ('unrestricted', 'restricted', 'sensitive'))` |
| `disposition` | `text` | `NOT NULL CHECK (disposition IN ('inline', 'attachment'))` |
| `lineage_artifact_id` | `uuid` | `NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `ready_at` | `timestamptz` | `NULL` |
| `delete_intent_at` | `timestamptz` | `NULL` |
| `deleted_at` | `timestamptz` | `NULL` |
| `quarantined_reason` | `text` | `NULL` |

**Unique constraints:**
- `artifacts_workspace_staging_generation_unique` on `(workspace_id, staging_generation)`.
- `artifacts_workspace_object_key_unique` on `(workspace_id, object_key)`.

**Indexes:**
- `artifacts_task_id_idx` on `(workspace_id, task_id, updated_at DESC)` — `ArtifactSummaryRead` projection.
- `artifacts_state_expiry_idx` on `(workspace_id, state, created_at)` where `state IN ('reserved', 'staging', 'verifying')` — Artifact lifecycle reconciliation and stale-reservation cleanup.
- `artifacts_delete_pending_idx` on `(workspace_id, state)` where `state = 'delete_pending'` — deletion reconciliation.
- `artifacts_quarantine_idx` on `(workspace_id, state)` where `state = 'quarantined'` — operator quarantine resolution.
- `artifacts_object_key_seek_idx` on `(workspace_id, object_key, id)` — backup/restore database inventory seek.

**Clean Architecture boundary:**
- `port.rs` contract: `central-artifact::port` → Artifact reserve, stage, verify, promote (no-overwrite), finalize, delete-intent, two-phase delete, quarantine. Artifact finalization is a composite change-set that may embed Task/Run/Step completion-guard mutations. The `central-artifact::app` Service produces the composite change set; `central-artifact::port` defines the adapter commit contract.
- `port.rs` contract: `central-artifact::port` → body-store interface (S3-neutral upload, inspect, promote, open, delete).
- `query.rs` contract: `ArtifactSummaryRead` (`central-artifact::query`) → `central-artifact::app` Service → `ListArtifactSummaries`.

### 3.10 Artifact tombstone

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `artifact_id` | `uuid` | `NOT NULL` |
| `object_key` | `text` | `NOT NULL` |
| `staging_generation` | `uuid` | `NOT NULL` |
| `checksum_algorithm` | `text` | `NULL` |
| `checksum_value` | `bytea` | `NULL` |
| `size_at_deletion` | `bigint` | `NOT NULL DEFAULT 0` |
| `deletion_reason` | `text` | `NOT NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |

**Unique constraints:**
- `artifact_tombstones_artifact_id_unique` on `(workspace_id, artifact_id)`.

**Indexes:**
- None beyond primary key. Tombstones are append-only and retained for the MVP lifetime.

**Clean Architecture boundary:**
- `port.rs` contract: `central-artifact::port` → tombstone insert is part of the two-phase Artifact deletion (delete-intent → tombstone → capacity release). `central_runtime` and `central_outbox` have no UPDATE/DELETE on this table. Tombstones prevent object-key and staging-generation reuse.

### 3.11 Event

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `event_sequence` | `bigint` | `NOT NULL CHECK (event_sequence >= 0)` |
| `event_type` | `text` | `NOT NULL` |
| `aggregate_id` | `uuid` | `NOT NULL` |
| `aggregate_version` | `bigint` | `NOT NULL CHECK (aggregate_version >= 0)` |
| `command_id` | `uuid` | `NULL` |
| `run_id` | `uuid` | `NULL` |
| `payload` | `jsonb` | Not null; 32 KiB maximum; depth ≤ 8 |
| `correlation_id` | `uuid` | `NULL` |
| `causation_id` | `uuid` | `NULL` |
| `occurred_at` | `timestamptz` | `NOT NULL DEFAULT now()` |

**Unique constraints:**
- `events_workspace_sequence_unique` on `(workspace_id, event_sequence)`.

**Indexes:**
- `events_workspace_sequence_idx` on `(workspace_id, event_sequence)` — Event seek pagination; covering index for `EventSeekRead`. This is the only query path for Events in Phase 1; the unique constraint doubles as the ordering constraint. Explicit covering index avoids a secondary sort.
- `events_aggregate_idx` on `(workspace_id, aggregate_id, event_sequence)` — aggregate-scoped Event replay for recovery (used by Checkpoint reconstruction).
- `events_run_idx` on `(workspace_id, run_id, event_sequence)` where `run_id IS NOT NULL` — Run-scoped event feed.

**Clean Architecture boundary:**
- `query.rs` contract: `EventSeekRead` (`central-event::query`) → `central-event::app` Service → `SeekEvents`.
- `port.rs` contract: Event append within change-set commits. Events are never created through a standalone port. The PostgreSQL adapter inserts Events, allocates the sequence from `workspace_event_counters`, and the `(workspace_id, event_sequence)` unique constraint enforces ordering. `central_runtime` and `central_outbox` may INSERT Events (within an authorized change-set commit) and SELECT from Events; they may not UPDATE or DELETE Events.

### 3.12 Outbox

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `event_id` | `uuid` | `NOT NULL REFERENCES central.events(id)` |
| `delivery_state` | `text` | `NOT NULL CHECK (delivery_state IN ('pending', 'claimed', 'delivered', 'dead_letter'))` |
| `due_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `retry_at` | `timestamptz` | `NULL` |
| `owner_identity` | `text` | `NULL` |
| `fencing_token` | `uuid` | `NULL` |
| `lease_expiry` | `timestamptz` | `NULL` |
| `attempt_count` | `bigint` | `NOT NULL DEFAULT 0 CHECK (attempt_count >= 0)` |
| `failure_reason` | `text` | `NULL` |
| `dead_letter_evidence` | `text` | `NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |

**Unique constraints:**
- `outbox_workspace_event_unique` on `(workspace_id, event_id)` — one outbox row per Event.

**Indexes:**
- `outbox_claim_idx` on `(workspace_id, delivery_state, due_at)` — outbox claim scan; `FOR UPDATE SKIP LOCKED` with `WHERE (delivery_state = 'pending' OR (delivery_state = 'claimed' AND lease_expiry < now())) AND due_at <= now() ORDER BY due_at ASC LIMIT $1`.
- `outbox_owner_lease_idx` on `(workspace_id, owner_identity, lease_expiry)` — heartbeat/renew lookup by owner.
- `outbox_delivered_cleanup_idx` on `(workspace_id, delivery_state, updated_at)` where `delivery_state = 'delivered' AND updated_at < now() - interval '7 days'` — cleanup eligibility.
- `outbox_dead_letter_cleanup_idx` on `(workspace_id, delivery_state, updated_at)` where `delivery_state = 'dead_letter' AND updated_at < now() - interval '30 days'` — cleanup eligibility.

**Clean Architecture boundary:**
- `port.rs` contract: `central-execution::port` → outbox claim/settle/heartbeat/renew/fail/release. These are atomic conditional operations. Claim uses `FOR UPDATE SKIP LOCKED`, generates a fencing token, and sets `owner_identity`/`lease_expiry`. Every state-changing operation (renew, complete, fail, release) requires matching `owner_identity`, `fencing_token`, and unexpired `lease_expiry`.
- `port.rs` contract: outbox record creation within change-set commits (one outbox row per Event intent).
- `central_outbox` role has read/write on this table and read-only on Events.

### 3.13 Command receipt

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `command_scope` | `text` | `NOT NULL` |
| `idempotency_key` | `text` | `NOT NULL` |
| `input_fingerprint` | `bytea` | `NOT NULL` |
| `expected_aggregate_versions` | `jsonb` | Not null; version vector map |
| `result_kind` | `text` | `NOT NULL` |
| `result_reference` | `uuid` | `NULL` |
| `correlation_id` | `uuid` | `NULL` |
| `causation_id` | `uuid` | `NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `expiry_at` | `timestamptz` | `NOT NULL` |

**Unique constraints:**
- `command_receipts_scope_key_unique` on `(workspace_id, command_scope, idempotency_key)`.

**Indexes:**
- `command_receipts_cleanup_idx` on `(workspace_id, expiry_at)` where `expiry_at < now() - interval '7 days'` — cleanup eligibility (retained 7 days after expiry).
- `command_receipts_scope_key_idx` — the unique constraint serves as the primary lookup index.

**Clean Architecture boundary:**
- `port.rs` contract: Receipt check/insert within every change-set commit. Receipt is checked first: if a matching receipt exists with identical fingerprint, the original result is returned idempotently; if fingerprint differs, the command fails with a structured mismatch failure. Receipt insert, state mutation, Event append, and outbox creation commit together atomically.

### 3.14 Execution ownership

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `owner_scope` | `text` | `NOT NULL` |
| `owner_identity` | `text` | `NOT NULL` |
| `fencing_token` | `uuid` | `NOT NULL` |
| `lease_expiry` | `timestamptz` | `NOT NULL` |
| `heartbeat_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `claimed_run_id` | `uuid` | `NULL REFERENCES central.runs(id)` |
| `claimed_step_id` | `uuid` | `NULL REFERENCES central.steps(id)` |
| `claimed_step_attempt_id` | `uuid` | `NULL REFERENCES central.step_attempts(id)` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |

**Unique constraints:**
- `execution_ownership_scope_unique` on `(workspace_id, owner_scope)`.

**Indexes:**
- `execution_ownership_expiry_idx` on `(workspace_id, lease_expiry)` — startup recovery scan for expired leases.

**Clean Architecture boundary:**
- `port.rs` contract: `central-execution::port` → execution-ownership claim/renew/heartbeat/complete/fail/release. These are atomic conditional operations. Claim requires no existing owner with unexpired lease. Every state-changing operation requires matching `owner_identity`, `fencing_token`, and unexpired `lease_expiry`.

### 3.15 Capacity reservation

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `run_id` | `uuid` | `NOT NULL REFERENCES central.runs(id)` |
| `artifact_id` | `uuid` | `NOT NULL REFERENCES central.artifacts(id)` |
| `staging_generation` | `uuid` | `NOT NULL` |
| `reserved_bytes` | `bigint` | `NOT NULL CHECK (reserved_bytes >= 0)` |
| `state` | `text` | `NOT NULL CHECK (state IN ('reserved', 'settled', 'released'))` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `settled_at` | `timestamptz` | `NULL` |
| `released_at` | `timestamptz` | `NULL` |

**Unique constraints:**
- `capacity_reservations_artifact_unique` on `(workspace_id, artifact_id)`.
- `capacity_reservations_staging_gen_unique` on `(workspace_id, staging_generation)`.

**Indexes:**
- `capacity_reservations_state_cleanup_idx` on `(workspace_id, state, created_at)` where `state = 'released' AND created_at < now() - interval '7 days'` — cleanup eligibility.

**Clean Architecture boundary:**
- `port.rs` contract: `central-artifact::port` → reserve, settle, release, cleanup. Reserve atomically checks Workspace and Run quota, increments reserved counters, and creates the reservation in `reserved` state before any object-store call. Settle atomically rechecks quotas and transitions to `settled`. Release atomically decrements counters and transitions to `released`. Exactly-once: already settled/released reservations reject further mutation idempotently. Row lock on the Workspace capacity ledger (the `workspaces.quota_ready_bytes`/`quota_ready_count` columns) and the Run counter (`runs.capacity_run_ready_bytes`) prevents over-admission.

### 3.16 Bootstrap generation

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `generation` | `bigint` | `NOT NULL CHECK (generation >= 0)` |
| `verifier_hash` | `bytea` | `NOT NULL` |
| `state` | `text` | `NOT NULL CHECK (state IN ('active', 'consumed'))` |
| `principal_identity` | `text` | `NOT NULL` |
| `candidate_id` | `uuid` | `NULL` |
| `candidate_digest` | `bytea` | `NULL` |
| `registered_generation` | `bigint` | `NULL` |
| `throttle_failure_window_start` | `timestamptz` | `NULL` |
| `throttle_failure_count` | `bigint` | `NOT NULL DEFAULT 0` |
| `throttle_next_eligible` | `timestamptz` | `NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `consumed_at` | `timestamptz` | `NULL` |

**Unique constraints:**
- `bootstrap_generations_workspace_generation_unique` on `(workspace_id, generation)`.

**Indexes:**
- `bootstrap_generations_active_idx` on `(workspace_id, state)` where `state = 'active'` — bootstrap exchange lookup for the current active generation.

**Clean Architecture boundary:**
- `port.rs` contract: `central-session::port` → bootstrap exchange commit (single-use linearization point). The exchange locks and revalidates the active generation; consumes it; allocates the next generation; binds the caller's exact candidate ID/generation/digest; creates a `pending_bootstrap` session; and records rotation evidence — all in one atomic transaction. The verifier hash is SHA-256. No plaintext token or CSRF value is ever stored.

### 3.17 Session

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `token_hash` | `bytea` | `NOT NULL` |
| `csrf_hash` | `bytea` | `NOT NULL` |
| `principal_identity` | `text` | `NOT NULL` |
| `lifecycle_state` | `text` | `NOT NULL CHECK (lifecycle_state IN ('pending_bootstrap', 'delivery_pending', 'active', 'revoked', 'expired'))` |
| `security_epoch` | `bigint` | `NOT NULL DEFAULT 0` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `last_seen_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `idle_expiry` | `timestamptz` | `NOT NULL` |
| `absolute_expiry` | `timestamptz` | `NOT NULL` |
| `revoked_at` | `timestamptz` | `NULL` |
| `first_use_deadline` | `timestamptz` | `NULL` |
| `first_used_at` | `timestamptz` | `NULL` |
| `previous_session_id` | `uuid` | `NULL` |
| `rotation_at` | `timestamptz` | `NULL` |
| `delivery_outcome` | `text` | `NULL` |

**Unique constraints:**
- `sessions_token_hash_unique` on `(token_hash)` — global uniqueness for token hash.

**Indexes:**
- `sessions_workspace_principal_idx` on `(workspace_id, principal_identity, lifecycle_state)` — session lookup by principal.
- `sessions_cleanup_idx` on `(workspace_id, lifecycle_state, idle_expiry)` where `lifecycle_state IN ('revoked', 'expired') AND idle_expiry < now() - interval '24 hours'` — cleanup eligibility.
- `sessions_pending_bootstrap_idx` on `(workspace_id, lifecycle_state)` where `lifecycle_state = 'pending_bootstrap'` — bootstrap recovery.
- `sessions_delivery_pending_idx` on `(workspace_id, lifecycle_state)` where `lifecycle_state = 'delivery_pending'` — delivery recovery.
- `sessions_first_use_idx` on `(workspace_id, lifecycle_state, first_use_deadline)` where `lifecycle_state = 'active' AND first_used_at IS NULL` — first-use deadline revocation.

**Clean Architecture boundary:**
- `port.rs` contract: `central-session::port` → create (within bootstrap exchange), validate, refresh, revoke, cleanup. Session creation is part of the bootstrap exchange transaction. Validation atomically compares token hash, requires active/non-revoked/non-expired state, current security epoch match, and — for bootstrap-created sessions — `first_used_at IS NOT NULL OR database_time <= first_use_deadline`. The first successful validation writes `first_used_at` and `last_seen_at` in the same statement. Refresh atomically revokes the old session and creates its replacement in one transaction. Revoke atomically sets the revocation flag. Cleanup removes only already-revoked-or-expired rows past the 24-hour retention window; it never revives a session.
- `query.rs` contract: `SessionStatusRead` (`central-session::query`) → `central-session::app` Service → `ValidateSession`. `BootstrapStatusRead` (`central-session::query`) → `central-session::app` Service → `ValidateSession` (pre-Workspace bootstrap status).

### 3.18 Approval

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `capability_identity` | `text` | `NOT NULL` |
| `scope` | `text` | `NOT NULL` |
| `action` | `text` | `NOT NULL CHECK (action IN ('grant', 'revoke'))` |
| `actor_identity` | `text` | `NOT NULL` |
| `authority_identity` | `text` | `NOT NULL` |
| `reason` | `text` | `NOT NULL` |
| `state` | `text` | `NOT NULL CHECK (state IN ('active', 'revoked', 'suspended', 'expired'))` |
| `suspend_reason` | `text` | `NULL` |
| `security_epoch` | `bigint` | `NOT NULL DEFAULT 0` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `expiry_at` | `timestamptz` | `NULL` |

**Unique constraints:**
- None beyond primary key. Approvals are version-tracked per identity.

**Indexes:**
- `approvals_workspace_capability_idx` on `(workspace_id, capability_identity, state)` — capability grant lookup.
- `approvals_workspace_actor_idx` on `(workspace_id, actor_identity, state)` — approvals-by-actor; `ApprovalSummaryRead`.
- `approvals_security_epoch_idx` on `(workspace_id, security_epoch)` — restore authority reset predicate.

**Clean Architecture boundary:**
- `port.rs` contract: `central-authorization::port` → Approval record create/update within change-set commits. Grant/revoke/suspend are domain decisions.
- `query.rs` contract: `ApprovalSummaryRead` (`central-authorization::query`) → `central-authorization::app` Service → `ListApprovals`.

### 3.19 Secret-use audit evidence

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `secret_reference_id` | `text` | `NOT NULL` |
| `actor_identity` | `text` | `NOT NULL` |
| `operation_identity` | `text` | `NOT NULL` |
| `authorization_outcome` | `text` | `NOT NULL` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |

**Unique constraints:** None.

**Indexes:**
- `secret_use_workspace_ref_idx` on `(workspace_id, secret_reference_id, created_at DESC)` — audit trail.
- `secret_use_workspace_actor_idx` on `(workspace_id, actor_identity, created_at DESC)` — operator audit.

**Clean Architecture boundary:**
- `port.rs` contract: `central-authorization::port` → secret-use evidence append. No plaintext secret, bootstrap/session/CSRF value, or backend locator enters this record.

### 3.20 Checkpoint

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NOT NULL REFERENCES central.workspaces(id)` |
| `run_id` | `uuid` | `NOT NULL REFERENCES central.runs(id)` |
| `step_id` | `uuid` | `NULL REFERENCES central.steps(id)` |
| `version` | `bigint` | `NOT NULL DEFAULT 0 CHECK (version >= 0)` |
| `checkpoint_kind` | `text` | `NOT NULL CHECK (checkpoint_kind IN ('run_start', 'run_complete', 'step_boundary', 'external_effect', 'recovery'))` |
| `metadata` | `jsonb` | Not null; bounded |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |

**Unique constraints:**
- `checkpoints_workspace_run_kind_unique` on `(workspace_id, run_id, checkpoint_kind, created_at)`.

**Indexes:**
- `checkpoints_run_id_idx` on `(workspace_id, run_id, created_at DESC)` — run recovery snapshot.
- `checkpoints_recovery_idx` on `(workspace_id, checkpoint_kind, created_at)` where `checkpoint_kind IN ('step_boundary', 'external_effect')` — startup recovery.

**Clean Architecture boundary:**
- `port.rs` contract: `central-checkpoint::port` → immutable checkpoint recording within change-set commits. Checkpoints are recovery evidence owned by the sequential coordinator.

### 3.21 Migration history (schema_migrations)

| Column | Type | Constraints |
| --- | --- | --- |
| `version` | `bigint` | `PRIMARY KEY` |
| `checksum` | `text` | `NOT NULL` |
| `dirty` | `boolean` | `NOT NULL DEFAULT false` |
| `applied_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `operator_identity` | `text` | `NULL` |

**Unique constraints:** `schema_migrations_pkey` on `(version)`.

**Indexes:** None beyond primary key. Single-row lookup by version.

**Clean Architecture boundary:**
- `MigrationInspector` port: `central-backup::port` → read-only inspection. `central_runtime` has SELECT-only on this table. `central_migration` has INSERT/UPDATE. No role may DELETE migration history rows.

### 3.22 Migration checksum history

| Column | Type | Constraints |
| --- | --- | --- |
| `version` | `bigint` | `NOT NULL REFERENCES central.schema_migrations(version)` |
| `checksum` | `text` | `NOT NULL` |
| `recorded_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `operation_id` | `uuid` | `NULL` |

**Unique constraints:** `migration_checksums_version_recorded_unique` on `(version, recorded_at)`.

**Indexes:** None beyond unique constraint.

**Clean Architecture boundary:**
- Append-only, immutable. Migration runner appends at each successful migration. `central_runtime` has SELECT-only. `central_migration` has INSERT-only.

### 3.23 Migration progress (data backfill)

| Column | Type | Constraints |
| --- | --- | --- |
| `operation_id` | `uuid` | `NOT NULL` |
| `version` | `bigint` | `NOT NULL REFERENCES central.schema_migrations(version)` |
| `progress_version` | `bigint` | `NOT NULL DEFAULT 1` |
| `cursor_page` | `bigint` | `NOT NULL DEFAULT 0` |
| `batch_count` | `bigint` | `NOT NULL DEFAULT 0` |
| `records_processed` | `bigint` | `NOT NULL DEFAULT 0` |
| `checksum_accumulator` | `bytea` | `NOT NULL` |
| `source_checksum` | `text` | `NOT NULL` |
| `classification` | `text` | `NOT NULL CHECK (classification = 'data_backfill')` |
| `safety_binding_digest` | `bytea` | `NOT NULL` |
| `last_committed_at` | `timestamptz` | `NOT NULL DEFAULT now()` |

**Unique constraints:** `migration_progress_operation_version_unique` on `(operation_id, version)`.

**Indexes:**
- `migration_progress_version_state_idx` on `(version, operation_id)` — resume lookup for dirty backfill.

**Clean Architecture boundary:**
- `MigrationInspector` port: read-only inspection. `central_migration` writes progress. The runner reads progress to resume after interruption.

### 3.24 Restore / security epoch markers

Two marker rows exist per-initialized-target, managed by migration and restore operations:

| Column | Type | Constraints |
| --- | --- | --- |
| `id` | `uuid` | `PRIMARY KEY` |
| `workspace_id` | `uuid` | `NULL` |
| `restore_epoch` | `bigint` | `NOT NULL DEFAULT 0` |
| `security_epoch` | `bigint` | `NOT NULL DEFAULT 0` |
| `created_at` | `timestamptz` | `NOT NULL DEFAULT now()` |
| `updated_at` | `timestamptz` | `NOT NULL DEFAULT now()` |

**Clean Architecture boundary:**
- `central-backup::port` → installed during initial provisioning and after every restore authority reset. `central_migration` writes; `central_runtime` reads during preflight. Every serve profile reads the epoch markers and compares them against the external operator-state record.

---

## 4. Index matrix

### 4.1 Unique indexes

| Table | Index name | Columns | Guarantee |
| --- | --- | --- | --- |
| `workspace_event_counters` | `workspace_event_counters_pkey` | `(workspace_id)` | One counter per Workspace |
| `tasks` | `tasks_workspace_id_idempotency_key_unique` | `(workspace_id, idempotency_key)` | One receipt-able command identity per Workspace |
| `runs` | `runs_workspace_task_index_unique` | `(workspace_id, task_id, run_index)` | One run index per Task |
| `steps` | `steps_workspace_run_index_unique` | `(workspace_id, run_id, step_index)` | One step index per Run |
| `step_attempts` | `step_attempts_workspace_step_attempt_unique` | `(workspace_id, step_id, attempt_index)` | One attempt index per Step |
| `tool_calls` | `tool_calls_workspace_step_tool_unique` | `(workspace_id, step_id, tool_index)` | One tool index per Step |
| `tool_call_attempts` | `tool_call_attempts_workspace_tc_attempt_unique` | `(workspace_id, tool_call_id, attempt_index)` | One attempt index per ToolCall |
| `artifacts` | `artifacts_workspace_staging_generation_unique` | `(workspace_id, staging_generation)` | No staging-generation reuse |
| `artifacts` | `artifacts_workspace_object_key_unique` | `(workspace_id, object_key)` | No object-key reuse |
| `artifact_tombstones` | `artifact_tombstones_artifact_id_unique` | `(workspace_id, artifact_id)` | One tombstone per Artifact |
| `events` | `events_workspace_sequence_unique` | `(workspace_id, event_sequence)` | One sequence number per Workspace |
| `outbox` | `outbox_workspace_event_unique` | `(workspace_id, event_id)` | One outbox row per Event |
| `command_receipts` | `command_receipts_scope_key_unique` | `(workspace_id, command_scope, idempotency_key)` | One receipt per command identity |
| `execution_ownership` | `execution_ownership_scope_unique` | `(workspace_id, owner_scope)` | One owner per scope |
| `capacity_reservations` | `capacity_reservations_artifact_unique` | `(workspace_id, artifact_id)` | One reservation per Artifact |
| `capacity_reservations` | `capacity_reservations_staging_gen_unique` | `(workspace_id, staging_generation)` | No generation reuse |
| `bootstrap_generations` | `bootstrap_generations_workspace_generation_unique` | `(workspace_id, generation)` | One generation number per Workspace |
| `sessions` | `sessions_token_hash_unique` | `(token_hash)` | Global unique session token hash |
| `checkpoints` | `checkpoints_workspace_run_kind_unique` | `(workspace_id, run_id, checkpoint_kind, created_at)` | Ordered checkpoint for recovery |

### 4.2 Seek indexes

| Index name | Columns | Query shape | Bounded row estimate | EXPLAIN owner |
| --- | --- | --- | --- | --- |
| `events_workspace_sequence_idx` | `(workspace_id, event_sequence)` | `SELECT … FROM central.events WHERE workspace_id = $1 AND event_sequence > $2 ORDER BY event_sequence ASC LIMIT $3` | ≤ 250 | R-slice — `central-event` |
| `tasks_workspace_status_created_idx` | `(workspace_id, status, created_at DESC)` | `SELECT … FROM central.tasks WHERE workspace_id = $1 [AND status = $2] ORDER BY created_at DESC LIMIT $3` | ≤ 250 | R-slice — `central-task` |
| `artifacts_task_id_idx` | `(workspace_id, task_id, updated_at DESC)` | `SELECT … FROM central.artifacts WHERE workspace_id = $1 AND task_id = $2 ORDER BY updated_at DESC LIMIT $3` | ≤ 250 | R-slice — `central-artifact` |
| `approvals_workspace_capability_idx` | `(workspace_id, capability_identity, state)` | `SELECT … FROM central.approvals WHERE workspace_id = $1 [AND capability_identity = $2] [AND state = $3]` | ≤ 20 | R-slice — `central-authorization` |
| `checkpoints_run_id_idx` | `(workspace_id, run_id, created_at DESC)` | `SELECT … FROM central.checkpoints WHERE workspace_id = $1 AND run_id = $2 ORDER BY created_at DESC LIMIT $3` | ≤ 50 | R-slice — `central-checkpoint` |
| `artifacts_object_key_seek_idx` | `(workspace_id, object_key, id)` | `SELECT … FROM central.artifacts WHERE workspace_id = $1 AND (object_key, id) > ($2, $3) ORDER BY object_key, id LIMIT 1000` | ≤ 1000 per chunk | R-slice — `central-backup` |
| `secret_use_workspace_ref_idx` | `(workspace_id, secret_reference_id, created_at DESC)` | `SELECT … FROM central.secret_use_evidence WHERE workspace_id = $1 AND secret_reference_id = $2 ORDER BY created_at DESC LIMIT $3` | ≤ 100 | R-slice — `central-authorization` |

### 4.3 Blocking-EXISTS indexes

Preflight blocking checks use `EXISTS` with these indexes:

| Index name | Columns | Query intent | EXPLAIN owner |
| --- | --- | --- | --- |
| `events_workspace_sequence_idx` | (seek index, re-used) | `SELECT EXISTS (SELECT 1 FROM central.events WHERE workspace_id = $1 AND event_sequence > $2 LIMIT 1)` for cursor-expired detection | R-slice — preflight |
| `tasks_retry_eligible_idx` | `(workspace_id, retry_eligible_at)` partial | `SELECT EXISTS (SELECT 1 FROM central.tasks WHERE workspace_id = $1 AND retry_eligible_at IS NOT NULL AND retry_eligible_at <= now() LIMIT 1)` | R-slice — preflight |
| `execution_ownership_expiry_idx` | `(workspace_id, lease_expiry)` | `SELECT EXISTS (SELECT 1 FROM central.execution_ownership WHERE workspace_id = $1 AND lease_expiry < now() LIMIT 1)` | R-slice — preflight |
| `sessions_pending_bootstrap_idx` | (partial index) | `SELECT EXISTS (SELECT 1 FROM central.sessions WHERE workspace_id = $1 AND lifecycle_state = 'pending_bootstrap' LIMIT 1)` | R-slice — preflight |

### 4.4 Claim / ownership / fencing indexes

| Index name | Columns | Operation | Concurrency pattern | EXPLAIN owner |
| --- | --- | --- | --- | --- |
| `outbox_claim_idx` | `(workspace_id, delivery_state, due_at)` | `FOR UPDATE SKIP LOCKED` outbox claim | Multi-worker; skip-locked for non-conflicting rows | R-slice — `central-event` |
| `outbox_owner_lease_idx` | `(workspace_id, owner_identity, lease_expiry)` | Outbox heartbeat/renew by owner | Single-owner lookup; fencing-token match enforced in WHERE | R-slice — `central-event` |
| `execution_ownership_expiry_idx` | (re-used) | Expired-lease recovery; new claim | Startup recovery scan; `FOR UPDATE` with bounded timeout | R-slice — `central-task` |

### 4.5 Expiry / cleanup / reconciliation indexes

| Index name | Columns | Partial predicate | Cleanup window | EXPLAIN owner |
| --- | --- | --- | --- | --- |
| `outbox_delivered_cleanup_idx` | `(workspace_id, delivery_state, updated_at)` | `delivery_state = 'delivered'` | 7 days | R-slice — cleanup |
| `outbox_dead_letter_cleanup_idx` | `(workspace_id, delivery_state, updated_at)` | `delivery_state = 'dead_letter'` | 30 days | R-slice — cleanup |
| `sessions_cleanup_idx` | `(workspace_id, lifecycle_state, idle_expiry)` | `lifecycle_state IN ('revoked', 'expired')` | 24 hours | R-slice — cleanup |
| `capacity_reservations_state_cleanup_idx` | `(workspace_id, state, created_at)` | `state = 'released'` | 7 days | R-slice — cleanup |
| `command_receipts_cleanup_idx` | `(workspace_id, expiry_at)` | `expiry_at < now() - interval '7 days'` | 7 days | R-slice — cleanup |
| `artifacts_state_expiry_idx` | `(workspace_id, state, created_at)` | `state IN ('reserved', 'staging', 'verifying')` | 7 days | R-slice — `central-artifact` |
| `artifacts_delete_pending_idx` | `(workspace_id, state)` | `state = 'delete_pending'` | Reconciliation | R-slice — `central-artifact` |
| `tasks_cleanup_expiry_idx` | `(workspace_id, expiry_at)` | `expiry_at IS NOT NULL AND status IN ('completed', 'failed', 'cancelled')` | Configured Task-retention policy; cleanup is disabled while `expiry_at` is `NULL`, and the R5 local-topology slice must select the concrete duration without changing this predicate | R-slice — `central-task` |

### 4.6 Migration-progress indexes

| Index name | Columns | Operation | EXPLAIN owner |
| --- | --- | --- | --- |
| `migration_progress_version_state_idx` | `(version, operation_id)` | Data-backfill resume: `SELECT … FROM central.migration_progress WHERE version = $1 AND operation_id = $2` | R-slice — migration |

### 4.7 Reconciliation indexes

Recovery/reconciliation discovery uses the existing partial indexes (`tasks_retry_eligible_idx`, `execution_ownership_expiry_idx`, `artifacts_state_expiry_idx`, `sessions_pending_bootstrap_idx`, `sessions_delivery_pending_idx`, `sessions_first_use_idx`, `steps_status_idx`, `step_attempts_status_idx`) combined with `LIMIT N+1` and a typed seek cursor. Every reconciliation predicate must have its matching composite index and bounded `EXPLAIN` at the reference dataset.

### 4.8 Capacity indexes

The Workspace capacity ledger is a single-row per Workspace (`workspaces_pkey`). Reservation operations row-lock the Workspace row by `id` and the Run row by `runs_pkey`. No additional index is needed; the primary-key row lock suffices for the per-Workspace linearization.

---

## 5. Contract-to-query matrix

This matrix names every accepted contract (port or `query.rs` interface), the parent-Service caller, the implementation adapter leaf, role/pool, transaction isolation, expected-version predicate, lock order, Event/outbox/receipt effects, result mapping, retry/indeterminate behavior, typed seek cursor, page bound, SQL round trips, rows examined/returned, stable continuation, matching composite index, and `EXPLAIN` evidence owner.

### 5.1 Domain-approved change-set commits

| # | Contract | Capability port | Parent Service caller | Adapter leaf | Role / pool | Isolation | Expected-version predicate | Lock order | Events / outbox / receipt effects | Result mapping | Retry / indeterminate behavior | SQL round trips | Rows examined / returned | Matching index | EXPLAIN owner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C1 | CreateTask | `central-task::port` | `central-task::app` | Handwritten `task::commit_change_set` | `central_runtime` / serving data | `READ COMMITTED` | `WHERE tasks.version = $expected` CAS | Workspace counter row lock → Task insert → Event inserts → outbox inserts → receipt insert | Up to 8 Event inserts; up to 8 outbox inserts; 1 receipt insert; counter increment | Domain-aggregate result + Event/receipt correlation | Rollback retry (same change set only; no re-decide). Indeterminate COMMIT → receipt/reconciliation. Version conflict → no retry. | ≤ 3 (receipt check + counter lock + mutation) | ≤ 1 receipt + ≤ 8 Events + ≤ 8 outbox ≤ 17 total | `tasks_workspace_id_idempotency_key_unique`, `workspace_event_counters_pkey`, `events_workspace_sequence_unique` | R-slice — `central-task` |
| C2 | TransitionTask (cancel/retry/resume) | `central-task::port` | `central-task::app` | Handwritten `task::commit_change_set` | `central_runtime` / serving data | `READ COMMITTED` | `WHERE tasks.version = $expected` CAS | Task row lock → Run/Step row locks per completion guard → counter lock → Event inserts → outbox inserts → receipt insert | As C1 (≤ 32 Events for fan-out) | Domain-aggregate result | Version conflict: no retry. Indeterminate COMMIT: receipt replay. | ≤ 4 | Varies; ≤ 32 Events + 1 receipt | `tasks_workspace_id_idempotency_key_unique`, `runs_pkey`, aggregate indexes | R-slice — `central-task` |
| C3 | FinalizeArtifact (ready + optional Task completion guard) | `central-artifact::port` | `central-artifact::app` | Handwritten `artifact::commit_finalize_change_set` | `central_runtime` / serving data | `READ COMMITTED` | `WHERE artifacts.version = $expected AND artifacts.state IN ('staging', 'verifying') AND tasks.version = $expected` | Artifact row lock → Task/Run/Step locks (if completion guard) → counter lock → Event inserts → outbox inserts → receipt insert | Artifact state → ready; task state update (if guard); Events; outbox | Artifact lifecycle result + optional aggregate-completion | Delete-intent conflict: no transition. Version conflict on any aggregate: no partial commit. Quota conflict at settlement: reject. | ≤ 5 | 1 Artifact + ≤ 3 aggregates + ≤ 8 Events + 1 receipt | `artifacts_pkey`, `tasks_pkey`, `runs_pkey` | R-slice — `central-artifact` |
| C4 | DeleteArtifactIntent | `central-artifact::port` | `central-artifact::app` | Handwritten `artifact::commit_delete_intent_change_set` | `central_runtime` / serving data | `READ COMMITTED` | `WHERE artifacts.version = $expected AND artifacts.state NOT IN ('delete_pending', 'deleted')` | Artifact row lock → tombstone insert → Event insert | Artifact state → `delete_pending`; tombstone insert | Artifact lifecycle result | Already delete_pending: idempotent. Version conflict: no state change. | ≤ 3 | 1 Artifact + 1 tombstone + 1 Event | `artifacts_pkey`, `artifact_tombstones_artifact_id_unique` | R-slice — `central-artifact` |
| C5 | BootstrapExchange | `central-session::port` | `central-session::app` | Handwritten `session::exchange_bootstrap` | `central_runtime` / serving data | `READ COMMITTED` | `WHERE bootstrap_generations.generation = $current AND bootstrap_generations.state = 'active' AND bootstrap_generations.verifier_hash = $presented_digest` | Bootstrap generation row lock → session insert → rotation evidence | One generation consumed; one generation registered; one `pending_bootstrap` session created; rotation evidence appended | Bootstrap exchange result (no cookie yet; transport builds cookie separately) | Single-use: consumed generation never reactivated. Concurrent loser creates no session, cleans only own candidate. Throttle: invalid attempt advances counters only. | ≤ 2 (verify + commit) | 1 generation + 1 session + 1 rotation record | `bootstrap_generations_active_idx` | R-slice — `central-session` |
| C6 | ActivateBootstrapSession | `central-session::port` | `central-session::app` | Handwritten `session::activate_delivery` | `central_runtime` / serving data | `READ COMMITTED` | `WHERE sessions.lifecycle_state = 'delivery_pending' AND sessions.id = $exact_session` | Session row lock → state change | Session → `active`; `first_use_deadline` installed | Delivery outcome | Candidate/generation/digest match required; mismatch fails closed. Hook failure discards response buffer. | 1 | 1 session | `sessions_delivery_pending_idx` | R-slice — `central-session` |
| C7 | ResolveApproval | `central-authorization::port` | `central-authorization::app` | Handwritten `authorization::commit_approval_change_set` | `central_runtime` / serving data | `READ COMMITTED` | `WHERE approvals.version = $expected` CAS | Approval row lock | Approval state change; Event insert | Approval decision result | Expired/superseded: conflict. Version conflict: no state change. | ≤ 2 | 1 approval + 1 Event | `approvals_pkey` | R-slice — `central-authorization` |

### 5.2 Atomic conditional ports

| # | Contract | Capability port | Parent Service caller | Adapter leaf | Role / pool | Predicate evaluated at linearization point | Lock / SKIP LOCKED | Result mapping | Retry / stale-owner | SQL round trips | Rows returned | EXPLAIN owner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | ClaimOutbox | `central-execution::port` | `central-execution::app` (outbox component) | Handwritten `outbox::claim_due` | `central_outbox` / outbox pool | `WHERE (delivery_state = 'pending' OR (delivery_state = 'claimed' AND lease_expiry < now())) AND due_at <= now() ORDER BY due_at ASC LIMIT $1` | `FOR UPDATE SKIP LOCKED` | Claimed rows with new fencing token; empty set when none | Finite retry with bounded timeout; no eligible rows = empty (not failure) | 1 | ≤ `$1` | R-slice — `central-event` |
| A2 | SettleOutbox (complete/fail/release) | `central-execution::port` | `central-execution::app` (outbox component) | Handwritten `outbox::settle` | `central_outbox` / outbox pool | `WHERE outbox.id = $1 AND owner_identity = $2 AND fencing_token = $3 AND lease_expiry >= now()` | Row lock (implicit via UPDATE) | Delivered/dead-letter/pending outcome | Stale token or expired lease: structured stale-fencing rejection | 1 | 1 | R-slice — `central-event` |
| A3 | ClaimExecutionOwnership | `central-execution::port` | `central-execution::app` (execution component) | Handwritten `lease::claim` | `central_runtime` / runtime-general | `WHERE execution_ownership.workspace_id = $1 AND execution_ownership.owner_scope = $2 AND NOT EXISTS (SELECT 1 FROM central.execution_ownership WHERE workspace_id = $1 AND owner_scope = $2 AND lease_expiry >= now())` | Row lock (UPSERT with predicate) | Claimed ownership with new fencing token; conflict when unexpired lease exists | Stale-owner: existing unexpired lease blocks claim. Finite retry. | 1 | 1 | R-slice — `central-task` |
| A4 | SettleExecutionOwnership (renew/heartbeat/complete/fail/release) | `central-execution::port` | `central-execution::app` (execution component) | Handwritten `lease::settle` | `central_runtime` / runtime-general | `WHERE execution_ownership.id = $1 AND owner_identity = $2 AND fencing_token = $3 AND lease_expiry >= now()` | Row lock (implicit) | Renewed/completed/failed/released outcome | Stale token or expired lease: structured stale-fencing rejection | 1 | 1 | R-slice — `central-task` |
| A5 | ReserveArtifactCapacity | `central-artifact::port` | `central-artifact::app` | Handwritten `capacity::reserve` | `central_runtime` / serving data | `SELECT quota_ready_bytes + $reserved <= quota_max_bytes` (Workspace row lock); `SELECT capacity_run_ready_bytes + $reserved <= run_cap` (Run row lock) | Workspace row lock → Run row lock | Reservation in `reserved` state; counters incremented | Quota exceeded: structured limit failure. Fingerprint mismatch: fail closed. | ≤ 3 | 1 workspace + 1 run + 1 reservation insert | R-slice — `central-artifact` |
| A6 | SettleArtifactReservation | `central-artifact::port` | `central-artifact::app` | Handwritten `capacity::settle` | `central_runtime` / serving data | `WHERE reservations.state = 'reserved' AND reservations.artifact_id = $1` | Reservation row lock → Workspace row lock → Run row lock | Reservation → `settled`; ready-byte/count incremented | Already settled: idempotent. Quota exceeded at settlement: reject. | ≤ 3 | 1 reservation + 1 workspace + 1 run | R-slice — `central-artifact` |
| A7 | ReleaseArtifactReservation | `central-artifact::port` | `central-artifact::app` | Handwritten `capacity::release` | `central_runtime` / serving data | `WHERE reservations.state = 'reserved' OR reservations.state = 'released'` (cleanup only) | Reservation row lock → Workspace → Run (for decrement) | Reservation → `released`; counters decremented | Already released: idempotent. Counter would go negative: constraint failure. | ≤ 3 | 1 reservation + 1 workspace + 1 run | R-slice — `central-artifact` |
| A8 | ValidateSession | `central-session::port` | `central-session::app` | Handwritten `session::validate` | `central_runtime` / serving data | `WHERE sessions.token_hash = $presented_digest AND sessions.workspace_id = $workspace AND sessions.lifecycle_state = 'active' AND sessions.security_epoch = $epoch AND sessions.absolute_expiry >= now() AND (sessions.first_used_at IS NOT NULL OR now() <= sessions.first_use_deadline)` | Row lock (implicit via UPDATE of `last_seen_at`, `first_used_at`) | Session valid; `last_seen_at` updated; `first_used_at` set on first use | Expired/invalid/revoked/wrong-epoch: structured denial | 1 | 1 | R-slice — `central-session` |
| A9 | RevokeSession | `central-session::port` | `central-session::app` | Handwritten `session::revoke` | `central_runtime` / serving data | `WHERE sessions.id = $1 AND sessions.lifecycle_state IN ('active', 'delivery_pending')` | Row lock → revocation flag + timestamp | Session revoked | Already revoked: idempotent. Not found: no effect. | 1 | 1 | R-slice — `central-session` |
| A10 | ExpireInactiveSessions (time-driven) | `central-session::port` | `central-session::app` (cleanup) | Handwritten `session::expire_inactive` | `central_runtime` / cleanup pool | `WHERE sessions.lifecycle_state = 'active' AND sessions.idle_expiry < now()` | Batch with `LIMIT` and cursor; no row lock needed (idle-expiry atomic) | Sessions marked `expired` | Idempotent; cursor-based batch. | ≤ 2 per batch | ≤ 100 per batch | R-slice — `central-session` |
| A11 | ExpireUnusedBootstrapSessions (first-use deadline) | `central-session::port` | `central-session::app` (cleanup) | Handwritten `session::expire_first_use` | `central_runtime` / cleanup pool | `WHERE sessions.lifecycle_state = 'active' AND sessions.first_used_at IS NULL AND sessions.first_use_deadline < now()` | Batch with `LIMIT` and cursor | Sessions revoked | Idempotent; cursor-based batch. | ≤ 2 per batch | ≤ 100 per batch | R-slice — `central-session` |
| A12 | CleanupEligibleRecords | various ports | respective capability cleanup | Handwritten per-record-type | `central_runtime` / cleanup pool | Per-cleanup-type predicates with `LIMIT $1` and typed cursor | Batch with cursor; no row lock beyond implicit UPDATE | Records removed; cleanup evidence recorded | Idempotent; resumable; cursor-bounded. Never deletes ready Artifact, Event, tombstone, or required recovery evidence. | 1 per batch per type | ≤ 100 per batch | R-slice — cleanup |

### 5.3 `query.rs` read contracts

| # | Contract | Capability query interface | Parent Service caller | Adapter leaf | Role / pool | Isolation | Page bound | SQL round trips | Rows examined / returned | Seek cursor | Matching index | EXPLAIN owner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Q1 | `TaskListRead` | `central-task::query` | `central-task::app` → `ListTasks` | static `sqlx::query_as!` `task::list_by_workspace` | `central_runtime` / serving data | `READ COMMITTED` (read-only) | Default 100, hard 250 | ≤ 2 | ≤ 250 / ≤ 250 | `TaskListCursor{ task_id, status, updated_at }` | `tasks_workspace_status_created_idx` | R-slice — `central-task` |
| Q2 | `TaskDetailRead` | `central-task::query` | `central-task::app` → `GetTaskDetail` | Handwritten `task::get_detail` (Task + bounded Runs only) | `central_runtime` / serving data | `READ COMMITTED` (read-only) | Runs default 10, hard 25 | ≤ 2 | ≤ 26 / ≤ 26 | request `run_cursor: Option<RunSeekCursor>`; result `next_run_cursor: Option<RunSeekCursor>` | `tasks_workspace_id_idx`, `runs_task_id_idx` | R-slice — `central-task` |
| Q3 | `EventSeekRead` | `central-event::query` | `central-event::app` → `SeekEvents` | static `sqlx::query_as!` `event::seek_after_cursor` | `central_runtime` / serving data | `READ COMMITTED` (read-only) | Default 100, hard 250 | 1 | ≤ 250 / ≤ 250 | `EventSeekCursor{ event_sequence: i64 }` | `events_workspace_sequence_idx` | R-slice — `central-event` |
| Q4 | `ArtifactSummaryRead` | `central-artifact::query` | `central-artifact::app` → `ListArtifactSummaries` | static `sqlx::query_as!` `artifact::list_by_task` | `central_runtime` / serving data | `READ COMMITTED` (read-only) | Default 100, hard 250 | ≤ 2 | ≤ 250 / ≤ 250 | `ArtifactSummaryCursor{ artifact_id, updated_at }` | `artifacts_task_id_idx` | R-slice — `central-artifact` |
| Q5 | `ApprovalSummaryRead` | `central-authorization::query` | `central-authorization::app` → `ListApprovals` | static `sqlx::query_as!` `authorization::list_by_actor` | `central_runtime` / serving data | `READ COMMITTED` (read-only) | N/A (Task-scoped; ≤ 10 expected) | ≤ 2 | ≤ 20 / ≤ 10 | N/A | `approvals_workspace_actor_idx` | R-slice — `central-authorization` |
| Q6 | `BootstrapStatusRead` | `central-session::query` | `central-session::app` → `ValidateSession` | static `sqlx::query_as!` `session::get_bootstrap_status` | `central_runtime` / serving data | `READ COMMITTED` (read-only) | N/A (singleton) | 1 | ≤ 5 / ≤ 1 | N/A | `bootstrap_generations_active_idx` | R-slice — `central-session` |
| Q7 | `SessionStatusRead` | `central-session::query` | `central-session::app` → `ValidateSession` | static `sqlx::query_as!` `session::get_session_status` | `central_runtime` / serving data | `READ COMMITTED` (read-only) | N/A (singleton) | 1 | ≤ 3 / ≤ 1 | N/A | `sessions_token_hash_unique` | R-slice — `central-session` |
| Q8 | `MigrationStatusRead` | `central-backup::query` | `central-backup::app` → `InspectMigrationStatus` | Handwritten `migrate::inspect_status` | `central_runtime` / read-only operator (coexisting) | `READ COMMITTED` (read-only) | N/A (singleton) | 1 | ≤ 20 / ≤ 5 | N/A | `schema_migrations_pkey`, `migration_progress_version_state_idx` | R-slice — CLI migrate |
| Q9 | `BackupStatusRead` | `central-backup::query` | `central-backup::app` → `InspectBackupStatus` | Handwritten `backup::inspect_status` | `central_runtime` / read-only operator | `READ COMMITTED` (read-only) | N/A (singleton) | 1 | ≤ 10 / ≤ 3 | N/A | Protected operator state (external) | R-slice — CLI backup |
| Q10 | `RestoreStatusRead` | `central-backup::query` | `central-backup::app` → `InspectRestoreStatus` | Handwritten `restore::inspect_status` | `central_runtime` / read-only operator | `READ COMMITTED` (read-only) | N/A (singleton) | 1 | ≤ 15 / ≤ 5 | N/A | Protected operator state (external) + epoch markers | R-slice — CLI restore |

### 5.4 Read-only operator ports

| # | Contract | Capability port | Parent Service caller | Adapter leaf | Role / pool | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | `MigrationInspector` | `central-backup::port` | `central-backup::app` (migration coordinator) | Handwritten `migrate::inspect` | `central_runtime` / coexisting read-only operator | Read-only. Never constructs the `MigrationRunner`. Never creates/ensures tables. |
| R2 | `ProtectedOperatorStateInspector` | `central-backup::port` | `central-backup::app` (migration/backup/restore coordinator) | Handwritten `operatorstate::inspect` | `central_runtime` or direct filesystem access via the R5 local-topology binding | Read-only external operator-state inspection. |

### 5.5 Migration mutation ports

| # | Contract | Capability port | Parent Service caller | Adapter leaf | Role / session | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| M1 | `MigrationRunner::up` (version-zero provisioning) | `central-backup::port` | `central-backup::app` (migration coordinator) | Handwritten `migrate::provision` | `central_migration` / single non-rebinding session | Consumes `VerifiedEmptyTarget`. Creates entire initial schema, history, epochs, bootstrap in one transaction. Native runner only; no external migration framework. |
| M2 | `MigrationRunner::up` (initialized metadata) | `central-backup::port` | `central-backup::app` (migration coordinator) | Handwritten `migrate::run_metadata` (native runner) | `central_migration` / single non-rebinding session | Single bounded DDL transaction inside the native runner. |
| M3 | `MigrationRunner::up` (initialized data backfill) | `central-backup::port` | `central-backup::app` (migration coordinator) | Handwritten `migrate::run_backfill` | `central_migration` / single non-rebinding session | Records `dirty=true` on `central.schema_migrations` first. Batch coordinator on same session. Clean ledger transition on completion. |
| M4 | `MigrationRunner::resume` (data backfill) | `central-backup::port` | `central-backup::app` (migration coordinator) | Handwritten `migrate::resume_backfill` | `central_migration` / single non-rebinding session | Consumes `ResumableMigration`. Invokes backfill coordinator directly (not a fresh `up` pass). Resumes from last committed cursor. |

---

## 6. Global row-lock order and named compound transactions

### 6.1 Global row-lock order

To prevent deadlock, every transaction that acquires multiple row locks must acquire them in this fixed order:

1. **Bootstrap generation** (`central.bootstrap_generations`) — first, because it is the single-use linearization point for session creation.
2. **Workspace** (`central.workspaces`) — capacity ledger and epoch markers.
3. **Task** (`central.tasks`) — aggregate root for the execution chain.
4. **Run** (`central.runs`) — child of Task.
5. **Step** (`central.steps`) — child of Run.
6. **Artifact** (`central.artifacts`) — may embed Task/Run/Step completion guards.
7. **Approval** (`central.approvals`) — independent aggregate.
8. **Execution ownership** (`central.execution_ownership`) — fencing-token record.
9. **Session** (`central.sessions`) — after all aggregate locks.
10. **Outbox** (`central.outbox`) — claim/settle; not locked with other aggregates in the same transaction.

### 6.2 Named compound transactions

Every compound transaction has an explicit name and documented lock acquisition plan. The PostgreSQL adapter must realize each as a single atomic `COMMIT` or a documented bounded sequence.

#### T1: Task transition (create / cancel / retry / resume)

- **Owning capability:** `central-task::app`
- **Port:** `central-task::port::CommitChangeSet`
- **Lock order:** Workspace counter (`workspace_event_counters`) → Task → (Run → Step if completion guard) → Artifact (if completion guard)
- **Isolation:** `READ COMMITTED`
- **Atomic writes:** Task state + version, Run/Step state if applicable, Workspace counter increment, Event inserts (≤ 32), outbox inserts, command receipt insert.
- **Expected version:** CAS on Task (and any affected Run/Step/Artifact).
- **Idempotency:** Receipt unique constraint; matching receipt returns prior result.
- **Rollback:** No Event sequence consumed. Version conflict returns to caller.

#### T2: Artifact finalization with Task completion guard

- **Owning capability:** `central-artifact::app` (coordinator); `task` domain provides completion-guard types.
- **Port:** `central-artifact::port::CommitFinalizeChangeSet`
- **Lock order:** Artifact → Task → Run → Step (if guard) → Workspace counter → Event inserts → outbox inserts → receipt insert.
- **Isolation:** `READ COMMITTED`
- **Atomic writes:** Artifact state → ready + checksum/lineage; aggregate completion guard state update; Event/outbox/receipt.
- **Expected version:** CAS on Artifact and all affected aggregates.
- **Conflict:** Delete-intent or version mismatch on any aggregate → no partial commit.

#### T3: Quota settlement (reserve / settle / release)

- **Owning capability:** `central-artifact::app`
- **Port:** `central-artifact::port::ReserveCapacity` / `central-artifact::port::SettleReservation` / `central-artifact::port::ReleaseReservation`
- **Lock order:** Workspace capacity ledger (`workspaces.quota_ready_bytes`, `quota_ready_count`) → Run counter (`runs.capacity_run_ready_bytes`) → Reservation row.
- **Isolation:** `READ COMMITTED` with explicit `SELECT … FOR UPDATE` on Workspace and Run rows.
- **Atomic writes:** Reservation state + Workspace counter + Run counter.
- **Exactly-once:** Already settled/released reservations reject further mutation idempotently.

#### T4: Command receipt replay

- **Owning capability:** Every capability whose port accepts change-set commits.
- **Port:** Receipt check is embedded in every change-set commit before state mutation.
- **Lock order:** Receipt row lock (via unique-constraint `INSERT … ON CONFLICT`).
- **Isolation:** `READ COMMITTED`.
- **Behavior:** Matching `(workspace_id, command_scope, idempotency_key)` with identical fingerprint → return prior result + Event/outcome correlation (no new state). Changed fingerprint → structured mismatch failure (no mutation).

#### T5: Event range allocation

- **Owning capability:** Any capability that produces Events.
- **Port:** Event sequence allocation is part of every change-set commit.
- **Lock order:** Workspace counter (`workspace_event_counters`) row lock → Event inserts → outbox inserts → receipt insert.
- **Method:** `UPDATE central.workspace_event_counters SET last_event_sequence = last_event_sequence + $event_count WHERE workspace_id = $1`. The updated value determines the allocated range. Events are inserted with `event_sequence BETWEEN $start AND $end`. The unique constraint `events_workspace_sequence_unique` enforces ordering.
- **Rollback behavior:** The counter UPDATE is within the same transaction; rollback restores the pre-transaction counter value. Rejected commands consume no sequence.

#### T6: Bootstrap rotation

- **Owning capability:** `central-session::app`
- **Port:** `central-session::port::ExchangeBootstrap`
- **Lock order:** Bootstrap generation → Session.
- **Isolation:** `READ COMMITTED` with explicit row lock on active generation.
- **Atomic writes:** Consume old generation (state → `consumed`); allocate next generation (insert with new verifier_hash, candidate binding); create `pending_bootstrap` session; record rotation evidence.
- **Single-use:** Consumed generation never reactivated. Concurrent loser creates no session.

#### T7: Execution ownership claim and fence

- **Owning capability:** `central-execution::app` (execution component)
- **Port:** `central-execution::port::ClaimExecutionOwnership`, `central-execution::port::SettleExecutionOwnership`
- **Lock order:** Execution ownership row only. No cross-aggregate lock.
- **Isolation:** `READ COMMITTED` with predicate-based UPSERT (claim) or row-lock UPDATE (settle).
- **Fencing:** Claim generates new `fencing_token` UUID. Settle requires matching `owner_identity`, `fencing_token`, and unexpired `lease_expiry`.

#### T8: Outbox claim and fencing

- **Owning capability:** `central-execution::app` (outbox component)
- **Port:** `central-execution::port::ClaimDueOutbox`, `central-execution::port::SettleOutbox`
- **Lock order:** Outbox row only. `FOR UPDATE SKIP LOCKED` for claim; implicit row lock for settle.
- **Isolation:** `READ COMMITTED`.
- **Fencing:** Claim generates new `fencing_token`. Settle requires matching token and unexpired lease.

#### T9: Cleanup (batch per record type)

- **Owning capability:** Each capability owning the permanent state.
- **Port:** Atomic conditional cleanup operations.
- **Lock order:** Cleanup-targeted record only (no cross-record lock).
- **Isolation:** `READ COMMITTED`.
- **Behavior:** `DELETE … WHERE {cleanup predicate} LIMIT $page_size` or `UPDATE … WHERE {cleanup predicate} LIMIT $page_size`. Cursor-based idempotent batch. Evidence-before-release: cleanup evidence record inserted before row deletion.

---

## 7. Three-role grant matrix

Exactly three database roles exist. Pool partitioning for runtime-general, runtime-settlement, outbox, and cleanup is capacity isolation within `central_runtime`; it is not a fourth role or additional privilege class. All pool variants authenticate as `central_runtime`.

### 7.1 `central_runtime` — runtime, cleanup, serving, read-only operators

| Schema object class | SELECT | INSERT | UPDATE | DELETE | TRUNCATE | REFERENCES | TRIGGER |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `workspaces` | Yes | Yes (provisioning-only) | Yes | No | No | Yes | No |
| `workspace_event_counters` | Yes | No | Yes | No | No | Yes | No |
| `tasks` | Yes | Yes | Yes | Yes (cleanup only) | No | Yes | No |
| `runs` | Yes | Yes | Yes | No | No | Yes | No |
| `steps` | Yes | Yes | Yes | No | No | Yes | No |
| `step_attempts` | Yes | Yes | Yes (terminal settlement only) | No | No | Yes | No |
| `tool_calls` | Yes | Yes | Yes | No | No | Yes | No |
| `tool_call_attempts` | Yes | Yes | Yes (terminal settlement only) | No | No | Yes | No |
| `artifacts` | Yes | Yes | Yes | No | No | Yes | No |
| `artifact_tombstones` | Yes | No | No | No | No | No | No |
| `events` | Yes | Yes (in change-set commit only) | No | No | No | Yes | No |
| `outbox` | Yes | Yes (in change-set commit only) | No | Yes (cleanup only) | No | Yes | No |
| `command_receipts` | Yes | Yes (in change-set commit only) | No | Yes (cleanup only) | No | Yes | No |
| `execution_ownership` | Yes | Yes | Yes | Yes (cleanup) | No | Yes | No |
| `capacity_reservations` | Yes | Yes | Yes | Yes (cleanup) | No | Yes | No |
| `bootstrap_generations` | Yes | Yes | Yes | No | No | No | No |
| `sessions` | Yes | Yes | Yes | Yes (cleanup) | No | Yes | No |
| `approvals` | Yes | Yes | Yes | No | No | Yes | No |
| `secret_use_evidence` | Yes | Yes | No | No | No | No | No |
| `checkpoints` | Yes | Yes | No | No | No | Yes | No |
| `schema_migrations` | Yes | No | No | No | No | No | No |
| `migration_checksums` | Yes | No | No | No | No | No | No |
| `migration_progress` | Yes | No | No | No | No | No | No |
| `restore_epoch_markers` | Yes | No | No | No | No | No | No |

**Prohibited operations for `central_runtime`:**
- Any UPDATE or DELETE on `events`, `artifact_tombstones`, `schema_migrations`, `migration_checksums`, `migration_progress`, `restore_epoch_markers`.
- Any TRUNCATE on any table.
- Any DDL (CREATE, ALTER, DROP).
- Any GRANT/REVOKE.
- Cascade-deletion of Events or tombstones.

**Pool partitioning (all authenticate as `central_runtime`):**

| Pool | Max connections | Purpose | Can it borrow from other pools? |
| --- | --- | --- | --- |
| Serving data | 12 (default) / 16 (hard) | API/HTML queries and commands | No |
| Shared-lock control | 1 (default) / 4 (hard) | Advisory lock holder for serve profile lifetime | No |
| Runtime-general | 6 (default) / 8 (hard) | Execution, reconciliation, outbox dispatch | No |
| Runtime-settlement | 2 (exactly) | Terminal settlement of external effects | No — dedicated, may not be borrowed by runtime-general, cleanup, or outbox |
| Outbox | 3 (default) / 4 (hard) | Outbox claim/settle | No — authenticates as `central_outbox`, not `central_runtime` |
| Cleanup | 1 (default) / 2 (hard) | Periodic cleanup batches | No |
| Coexisting read-only operator | 2 (default) / 4 (hard) | Migration verify/status, backup verify, restore verify (database reads) | No |
| Mutually exclusive mutation operator | 4 (default) / 8 (hard) | `migrate up/resume`, `backup create`, `restore apply` | Only when serving data pools are absent |

### 7.2 `central_outbox` — outbox worker

| Schema object class | SELECT | INSERT | UPDATE | DELETE | Notes |
| --- | --- | --- | --- | --- | --- |
| `outbox` | Yes | No (only via change-set commit via `central_runtime`) | Yes (claim/settle states) | No | `FOR UPDATE SKIP LOCKED` on claim |
| `events` | Yes (referenced by outbox) | No | No | No | Read-only on referenced Events |
| All other tables | No | No | No | No | No access |

**Prohibited operations for `central_outbox`:**
- UPDATE or DELETE on Events, tombstones, or any table other than `outbox`.
- INSERT on any table (outbox rows are created during change-set commits by `central_runtime`).
- Any DDL, GRANT, or REVOKE.

### 7.3 `central_migration` — migration execution

| Schema object class | SELECT | INSERT | UPDATE | DELETE | Notes |
| --- | --- | --- | --- | --- | --- |
| All application tables | Yes | Yes | Yes | Yes | Full DDL; forward-only |
| `schema_migrations` | Yes | Yes | Yes (dirty/clean) | No | Append-only migration history |
| `migration_checksums` | Yes | Yes | No | No | Append-only |
| `migration_progress` | Yes | Yes | Yes | No | Data-backfill cursor |
| `restore_epoch_markers` | Yes | Yes | Yes | No | Epoch installation/reset |
| All indexes/constraints | CREATE, ALTER | — | — | DROP (forward corrective only) | Forward-only |

**Scope:** Only migration execution and the database/schema replacement portion of confirmed offline `restore apply` load `central_migration`. Post-restore verification and quarantine return to `central_runtime`.

**Prohibited operations for `central_migration`:**
- Destructive down migrations (DROP of data-bearing columns without forward corrective path).
- DELETE of migration history rows.
- Generic `Force` or `Drop` operations.
- Rewriting or erasing Event rows, Artifact lineage, tombstone rows, or audit history.

### 7.4 Ownership

- `central_migration` owns the `central` schema and all objects within it.
- `central_runtime` and `central_outbox` receive only the exact table/column grants listed above.
- No `central serve` profile loads `central_migration` credentials. No backup or restore operation loads `central_outbox`.

### 7.5 Grant application

Grants use `GRANT {privileges} ON central.{table} TO {role}`. Column-level grants apply where a role may read but not write specific columns (e.g., `central_runtime` may read `migration_checksums.checksum` but not write it). Default privileges on the `central` schema do not auto-grant future tables; each new table requires an explicit grant statement in its migration.

---

## 8. Installation-wide connection budget and topology validation

### 8.1 Connection budget

| Component | Default | Hard cap | Role |
| --- | --- | --- | --- |
| Installation-wide total | 16 | 24 | (cross-role sum) |
| Serving data pool | 12 | 16 | `central_runtime` |
| Shared-lock control connections | 1 | 4 | `central_runtime` |
| Coexisting read-only operator | 2 | 4 | `central_runtime` |
| Mutually exclusive mutation operator | 4 | 8 | `central_migration` or `central_runtime` (read-only) |
| Runtime-general pool | 6 | 8 | `central_runtime` |
| Runtime-settlement pool | 2 | 2 (exactly; hard) | `central_runtime` |
| Outbox pool | 3 | 4 | `central_outbox` |
| Cleanup pool | 1 | 2 | `central_runtime` |
| Pool acquisition timeout | 2 s | 5 s | — |

### 8.2 Topology validation inputs

Every process that connects to the target must record its pool configurations. A cross-topology validation function (owned by the composition root) accepts all declared pool sizes and profile types and must reject any concurrent combination where:

1. **Total cap exceeded:** Sum of all pools + control connections > 16 (default) or 24 (hard).
2. **Too many profiles:** More than 4 serving profiles / control connections.
3. **Pool overflow:** Any serving pool exceeds its single installation-wide allocation.
4. **Settlement pool wrong size:** Runtime-settlement maximum != 2.
5. **Settlement pool misuse:** Any pool other than runtime-settlement routes to the settlement pool.
6. **Artifact resource cap exceeded:** Active transfers > 8, waiters > 32, wait deadline > 30 s, or copy buffer × concurrency > 8 MiB.
7. **Non-streaming HTTP cap exceeded:** Active requests > 32, waiters > 64, wait deadline > 5 s, or active × buffer > 64 MiB.
8. **Inventory cap exceeded:** Workers > 2, spool > 8 MiB per worker, worker × spool > 16 MiB.
9. **Any installed value exceeds its canonical-boundary maximum.**

### 8.3 Valid topology combinations

| Profile combination | Shared lock | Serving data | Operator read | Operator mutation | Runtime-gen | Runtime-settlement | Outbox | Cleanup | Total | Valid? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Single serve (all components) | 1 | 12 | — | — | 0 (unused; serving handles commands) | 2 | 3 | 1 | 19 | Yes (≤ 24) |
| Serve (no outbox/cleanup) + operator read | 1 | 12 | 2 | — | 0 | 2 | 0 | 0 | 17 | Yes (≤ 24) |
| Serve + operator coexisting read | 1 | 12 | 4 | — | 0 | 2 | 0 | 0 | 19 | Yes (≤ 24) |
| Operator mutation only (no serve) | — | — | — | 4 | — | — | — | — | 4 | Yes (≤ 24) |
| Operator mutation (8 conn) + read | — | — | 2 | 8 | — | — | — | — | 10 | Yes (≤ 24) |
| Two serve profiles (co-located) | 2 | 8 + 8 | — | — | 0 | 2 + 2 | 3 | 1 | 26 | **Invalid** — total > 24 |
| Serve with settlement borrowed by general | 1 | 12 | — | — | 2 (borrowed from settlement) | 2 | 3 | 1 | 21 | **Invalid** — non-settlement pool uses settlement pool |
| Serve with Artifact active = 10 | 1 | 12 | — | — | 0 | 2 | 3 | 1 | 19 | **Invalid** — Artifact active > 8 hard cap |

**The serving composition (R1 slice onward) must reproduce these topology validations as executable startup checks.** Every invalid combination must fail startup with a safe diagnostic before any connection pool is constructed.

---

## 9. Migration inspector, provisioning, and path prohibitions

### 9.1 Read-only `MigrationInspector`

- **Port:** `central-backup::port::MigrationInspector`
- **Role:** `central_runtime` (read-only pool, explicitly read-only transaction)
- **Operation:** Queries allowlisted PostgreSQL catalogs (`pg_catalog`, `information_schema`) plus existing Central `schema_migrations`, `migration_checksums`, and `migration_progress` relations only when those relations already exist.
- **Never:** constructs the `MigrationRunner`; loads `central_migration`; creates or ensures a schema/version table; takes a mutating lock; writes evidence.
- **Safe outcomes:** Typed `uninitialized` (no `central` schema or migration history); `compatible` (all applied versions match checksum history); `dirty` (exact version/source/checksum/classification/progress evidence for recognized data-backfill interruption); `incompatible` (checksum mismatch, unknown dirty version, too-new schema, or unreadable state).
- **`migrate status` composition:** Additionally invokes `ProtectedOperatorStateInspector` (read-only) to cross-check target, operation, provisioning phase, epochs, and candidate digest. Mismatch never becomes resumable.

### 9.2 `MigrationRunner` — Central-owned single-session driver

- **Used only by:** `migrate up` and `migrate resume`. Never constructed by `migrate verify`, `migrate status`, or `central serve` preflight.
- **Session:** Exactly one non-rebinding `central_migration` PostgreSQL session.
- **Lock acquisition sequence on that session:** Common target-exclusive advisory lock (default 30 s, hard 5 min) → exclusive protected operator-state ownership (provisioning only; nonblocking compare/claim) → migration-specific session-level advisory lock (default 15 s, hard 60 s). Combined budget: default 45 s, hard 6 min.
- **Safety-precondition consumption:** Consumes exactly one of `VerifiedEmptyTarget`, verified backup/checkpoint evidence, or `ResumableMigration`.
- **Session lifecycle:** Runner owns cancellation hook that closes the session. No migration state is stored outside the runner-owned session and `central.schema_migrations`. Session loss prevents further SQL and releases both locks. No second connection, reconnect, or background acquisition may carry mutation authority.

### 9.3 External `initializing` provisioning protocol

- **Before PostgreSQL mutation:** Under common target-exclusive + exclusive protected operator-state ownership, the runner durably writes an integrity-protected external `initializing` record (outside PostgreSQL and Artifact store) in `recorded` phase. It binds target identity, safe operation ID, hidden nonce, epoch zero, protocol version, and embedded baseline digest. No candidate at this phase.
- **Candidate staging:** The runner generates one create-only bootstrap candidate in the R5 local-topology protected store and atomically replaces the external record to `candidate_staged` with exact candidate ID/digest.
- **Baseline commit:** Only after `candidate_staged`, a Central-owned installer consumes `VerifiedEmptyTarget` and executes one transaction on the lock-owning session: creates the `schema_migrations` relation, append-only checksum history, complete initial application schema, epoch-zero restore/security markers, exact initial bootstrap registration, and baseline version/checksums.
- **Readiness:** After read-only exact-baseline verification, the exact registered candidate activates in the protected store. The external record atomically transitions to `ready` only when target, operation, candidate, digest, and both epoch-zero markers match.

### 9.4 `ResumableMigration` and dirty-data-backfill path

- **Evidence binding:** `ResumableMigration` binds original consumed safety evidence, exact target, operation ID, migration version/source/checksum/classification, dirty state, progress-schema version, last committed cursor, and last batch evidence.
- **Resume path:** `migrate resume --operation=<id>` reacquires the same lock order. The runner invokes the exact embedded backfill coordinator directly (not a fresh `up` pass). The coordinator resumes after the last committed cursor, applies each bounded idempotent batch atomically, and advances progress.
- **Completion:** After final cursor and invariants are verified, the runner authorizes the single dirty-to-clean ledger transition on `central.schema_migrations`.
- **Rejection:** A metadata migration dirty state, missing/changed progress, changed source/checksum, unknown dirty version, already-clean version, completed/superseded operation, or mismatched target remains class `5` and requires forward correction or restore.

### 9.5 Ledger transition constraints

- **Acceptable transitions:** the runner's normal clean lifecycle (a `(version, checksum, dirty = false)` row appended to `central.schema_migrations` at the end of each migration's single transaction) and the runner-authorized exact completed-backfill dirty-to-clean transition (the same row updated to `dirty = false` only after completion verification).
- **Rejected transitions:** Any `dirty = true` write outside the expected dirty-marking transition at data-backfill start; any ledger write for an unknown version; any ledger write from a caller other than the authorized runner on its lock-owning session.
- **No generic dirty-state clearing.** A dirty version is resolved only through the recognized data-backfill resume path or forward corrective migration.

### 9.6 Prohibited `Force`, `Drop`, and generic-migration paths

- **`Force`:** No command, migration verb, or operator action accepts a generic force flag that clears a dirty ledger state. Only the recognized data-backfill resume path may complete a dirty version.
- **`Drop`:** No migration verb drops the database or schema through application code; any such request is denied with a typed destructive-operation rejection.
- **Generic `sqlx` migrations:** `sqlx::migrate!`, `Migrator`, and the `sqlx` `migrate` feature are prohibited (the feature is disabled in the dependency set). The runner never reads, creates, or writes a `_sqlx_migrations` table; `central.schema_migrations` is the only migration ledger.
- **External migration tools:** No external migration framework (e.g., a generic `migrate` CLI binary) executes Central schema changes. All migration execution goes through the `central migrate` verbs and the Central-owned runner bound to the single non-rebinding session.
- **Auto-migrate:** `central serve` never auto-migrates. Only `migrate up` and `migrate resume` load `central_migration`.

---

## 10. Backup and restore role usage

### 10.1 Advisory lock matrix

| Operation | Lock type | Connection type | Role | Duration |
| --- | --- | --- | --- | --- |
| `central serve` (every profile) | Shared target-advisory lock | Dedicated control connection | `central_runtime` | Profile lifetime; loss cancels profile |
| `migrate verify` / `migrate status` / `restore verify` (target read) | Shared target-advisory lock | Read-only operator pool | `central_runtime` | Invocation/slice duration |
| `backup verify` (target read) | Shared target-advisory lock | Read-only operator pool | `central_runtime` | Invocation duration |
| `backup status` / `restore status` | None | Protected operator-state only | N/A (external store read) | Invocation duration |
| `migrate up` / `migrate resume` | Exclusive target-advisory lock + migration-specific lock | Single non-rebinding session | `central_migration` | Through mutation completion |
| `backup create` / `backup resume` (accepted-point) | Exclusive target-advisory lock | Dedicated control connection | `central_runtime` | Through manifest seal; lock loss → terminal |
| `restore apply` / `restore resume` (pre-ready) | Exclusive target-advisory lock + exclusive operator-state ownership | Mixed: `central_migration` for DB replacement; then `central_runtime` | `central_migration` (DB replace only), `central_runtime` (verify/quarantine) | Through readiness |

### 10.2 Operator-state and epoch mapping

Protected operator state is stored outside both the PostgreSQL target and the Artifact object store (the R5 local-topology slice owns concrete location and permissions). Every initialized target has matching restore/security epoch markers inside PostgreSQL (`central.workspaces.restore_epoch` and `central.workspaces.security_epoch`).

- **External record fields:** opaque target identity, monotonic restore epoch, monotonic security epoch, operation nonce, protocol version, state (`absent`, `initializing`, `ready`, `applying`, `verifying`, `quarantined`), transition timestamp.
- **Legal state transitions:**
  - Before initialization: `absent → initializing → ready` (version-zero provisioning only).
  - After initialization: `ready → applying → verifying → ready` (restore path), with `verifying → quarantined → verifying` (discrepancy repair).
  - `initializing` is never a restore state. `applying`/`verifying`/`quarantined` can never initialize an empty target.

### 10.3 Inventory cursors and chunks

- **Database enumeration:** Composite seek cursor over `(workspace_id, object_key, artifact_id)` using index `artifacts_object_key_seek_idx`.
- **Object enumeration:** Canonical key `start-after`; never persists an opaque provider continuation token as durable authority.
- **Chunk encoding:** At most 1,000 records per chunk; each record at most 4 KiB. Chunk is create-only under `(operation_id, chunk_ordinal, content_hash)` identity with own checksum.
- **Worker/spool budget:** Default 1 worker, hard 2. Default 8 MiB spool per worker, hard 8 MiB.
- **Work slice:** Default 100 pages or 5 minutes; hard 1,000 pages or 30 minutes.

### 10.4 Quarantine

After restore verification, any Artifact whose checksum, size, or state differs from the verified manifest enters `quarantined` state. A quarantined Artifact retains its tombstone-resistant identity and staging generation but cannot become `ready`, be downloaded, or be referenced as a completion guard. Operator resolution goes through an accepted quarantine-resolution path (not described here; future Phase 2+ work). Restore cannot reach `ready` while any quarantined record exists.

### 10.5 Post-restore authority reset

One idempotent PostgreSQL transaction executed under `central_migration` (DB replacement) or `central_runtime` (post-replacement verify/reset phase):

1. Installs matching `restore_epoch` and `security_epoch` markers in PostgreSQL (`central.workspaces`).
2. Revokes all active and pending sessions (`lifecycle_state IN ('active', 'pending_bootstrap', 'delivery_pending')`).
3. Consumes/cancels restored bootstrap exchanges and generations.
4. Expires all claims, leases, and fencing tokens (`execution_ownership.lease_expiry = now()`; `outbox.lease_expiry = now()` for all `claimed` rows).
5. Suspends every effective grant: `UPDATE central.approvals SET state = 'suspended', suspend_reason = 'restore_review_required' WHERE state = 'active'`.
6. Disables every SecretReference pending reconciliation (external binding authority; not a PostgreSQL column).
7. Registers the exact fresh bootstrap candidate/generation/digest.
8. Appends bounded safe reset evidence.

After reset, every authentication, grant/protected-use, claim, lease, and fence predicate compares the current `security_epoch`. A mismatch fails closed.

---

## 11. SQLSTATE, constraint, timeout, deadlock, and redaction mappings

### 11.1 SQLSTATE to failure mapping

Adapters classify `sqlx` errors (`sqlx::Error` and the underlying `sqlx::error::DatabaseError` SQLSTATE payload) before returning. Raw SQLSTATE detail, query text, and connection facts never cross the adapter boundary.

| SQLSTATE class | Error condition | Adapter mapping | Application failure | Retry? |
| --- | --- | --- | --- | --- |
| `23505` | Unique violation | Receipt replay → return prior result. Other unique violations → structured conflict. | `FailureConflict` for business constraint; prior result for receipt replay. | No (replay is idempotent, not retry) |
| `23503` | Foreign key violation | Structured cross-Workspace or missing-aggregate failure. | `FailureDenied` (cross-Workspace) or `FailureInvalid` (missing aggregate). | No |
| `23514` | Check violation | Structured domain invariant failure. | `FailureInvalid` — field-level rejection with bounded reason. | No |
| `23502` | Not-null violation | Structured data-integrity failure. | `FailureInternal` — always indicates a bug. | No |
| `40001` | Serialization failure | PostgreSQL guarantees rollback. Adapter retries the same approved change set or conditional request only (no re-decide, no external effect, no changed input). | Transparent to caller if retry succeeds within budget; `FailureConflict` if exhausted. | Yes (bounded, same input only) |
| `40P01` | Deadlock detected | PostgreSQL rolls back one transaction. Adapter retries the same approved change set (no re-decide). | Transparent if retry succeeds; `FailureConflict` if exhausted. | Yes (bounded, same input only) |
| `57014` | Statement timeout | Query cancelled by server. | `FailureUnavailable` (retryable with backoff). | Yes (backoff) |
| `55P03` | Lock not available | Lock timeout. | `FailureUnavailable` or `FailureConflict` depending on operation. | Yes (backoff for transient; no for business conflict) |
| `08006` | Connection failure | Pool connection lost. | `FailureUnavailable` with bounded retry. | Yes (backoff) |
| `57P01` | Admin shutdown | Database stopping. | `FailureUnavailable`; shutdown in progress. | Yes (after restart) |
| `53300` | Too many connections | Pool exhausted. | `FailureUnavailable` with `Retry-After`. | Yes (backoff) |
| `08003` / `08007` | Connection does not exist / transaction resolution unknown | Connection lost during or immediately after `COMMIT`. PostgreSQL may or may not have committed the transaction. | `FailureAmbiguous` (indeterminate commit). Resolved through receipt/reconciliation path. | No (resolved via receipt replay) |
| `XX000` | Internal error | Unexpected PostgreSQL internal error. | `FailureInternal`. | No |
| Others | Unclassified | Sanitized generic failure; raw error detail never exposed. | `FailureInternal` with safe bounded context. | No |

### 11.2 Constraint violation handling

- Unique violations on `command_receipts_scope_key_unique` are the receipt-replay path. An `INSERT … ON CONFLICT (workspace_id, command_scope, idempotency_key) DO NOTHING RETURNING …` pattern detects replay atomically without first checking then inserting.
- Unique violations on `events_workspace_sequence_unique` indicate a bug in sequence allocation; mapped to `FailureInternal`.
- Foreign key violations on cross-Workspace references (e.g., an Event referencing an Artifact in another Workspace) are caught by the composite Workspace-scoped FK constraint; mapped to `FailureDenied`.
- Check violations on status columns indicate an invalid transition attempted; mapped to `FailureInvalid` with the bounded rejected-value fact.

### 11.3 Timeout behavior

| Timeout source | Default | Behavior |
| --- | --- | --- |
| Statement timeout (DDL) | 30 s | Abort DDL, return class `4` with safe phase reason |
| Statement timeout (data) | 5 s | Abort query, return `FailureUnavailable` |
| Lock timeout | `SET lock_timeout` per operation (≤ 5 min hard) | Abort lock acquisition, return `FailureConflict` or `FailureUnavailable` |
| Pool acquisition timeout | 2 s (5 s hard) | Abort before pool handoff; `FailureUnavailable` with bounded `Retry-After`. No SQL executed. |
| Common target-exclusive lock | 30 s (5 min hard) | Class `4` migration timeout |
| Migration-specific lock | 15 s (60 s hard) | Class `4` migration timeout |
| `idle_in_transaction_session_timeout` | Configured per pool (≤ 10 s) | Terminate idle-in-transaction sessions; mapped to `FailureInternal` for the owning operation |

### 11.4 Deadlock and serialization failure handling

PostgreSQL guarantees that `40001` (serialization_failure) and `40P01` (deadlock_detected) roll back the losing transaction. The adapter may retry the exact same approved change set or conditional request up to a bounded number of times (default 3, hard 5) with exponential backoff between attempts. The adapter:

- Never reloads domain state or re-invokes domain decision logic.
- Never changes the change set input, expected versions, Event intents, or receipt binding.
- Never crosses an external-effect boundary (no external calls are made during a PostgreSQL transaction).
- Records the retry count in safe observation telemetry.
- Returns `FailureConflict` after exhausting the retry budget.

### 11.5 Commit-indeterminate mapping

When the PostgreSQL connection is lost during `COMMIT` (SQLSTATE `08003`, `08007`, or a connection-level error after `commit` is invoked), the adapter cannot determine whether the transaction committed or rolled back. The adapter:

1. Immediately marks the operation outcome as `ambiguous` in its internal state.
2. Returns `FailureAmbiguous` to the caller.
3. The caller does not retry the command; instead it transitions to the receipt/reconciliation path.
4. The receipt replay path — checking for an existing receipt with the same `(workspace_id, command_scope, idempotency_key)` on a fresh connection — resolves the ambiguity: a found receipt means the original commit succeeded; absence means it rolled back.

Work items (execution ownership, outbox claims) use their fencing-token model instead of receipts: a lost connection during claim settlement may leave the record in an ambiguous state; the next claim cycle reclaims expired leases.

### 11.6 Redaction rules

Every error response constructed by an adapter must redact:

- Raw SQLSTATE detail string.
- Query text or parameter values.
- Object keys, bucket names, or S3/MinIO URIs.
- Provider or tool API endpoint URLs, request bodies, or response bodies.
- Secret locator paths, key identifiers, or protected-store filenames.
- Bootstrap/session/CSRF token values or hashes.
- Connection strings, DSNs, or database user names.
- Advisory lock keys or internal connection identifiers.
- Unbounded error messages from external SDKs.

Safe error responses contain: a `FailureKind` enum, an optional bounded stable reason code, and an optional bounded human-readable message. The message is a curated string, never produced by formatting the raw error (no `{raw_error}` interpolation).

---

## 12. Map of boundary resource rows

Every resource row from the [canonical Rust application boundaries contract §4.6](../architecture/rust-application-boundaries.md#46-resource-matrix) is realized in this adapter mapping:

| Boundary resource row | This document location |
| --- | --- |
| Installation-wide total 16/24 | §8.1 connection budget |
| Serving data pool 12/16 | §8.1 |
| Shared-lock control 1/4 | §8.1 |
| Coexisting read-only operator 2/4 | §8.1 |
| Mutually exclusive mutation operator 4/8 | §8.1 |
| Runtime-general pool 6/8 | §8.1 |
| Runtime-settlement pool 2/2 | §8.1 |
| Outbox pool 3/4 | §8.1 |
| Cleanup pool 1/2 | §8.1 |
| Pool acquisition timeout 2 s/5 s | §8.1 |
| Common target-exclusive 30 s/5 min | §9.2 |
| Migration-specific 15 s/60 s | §9.2 |
| Total migration lock 45 s/6 min | §9.2 |
| Artifact active/waiter/deadline/buffer | §8.2 topology validation |
| Non-streaming HTTP active/waiter/deadline/buffer | §8.2 topology validation |
| Inventory worker/spool/page/slice | §10.3 |
| Preflight elapsed/discovery page | Implicit in §4.3 and §4.4 (EXISTS indexes + LIMIT N+1) |
| Settlement shutdown grace/total | Not in PostgreSQL adapter (kernel/component lifecycle; see canonical boundary contract §9.5) |
| Every valid/invalid topology combination | §8.3 |

---

## 13. References

- [Rust Application Boundaries — Canonical Contract](../architecture/rust-application-boundaries.md)
- [Central-Rust Documentation and Architecture Design](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md)
- [Rust Engineering Workflow](../implementation/rust-engineering-workflow.md)
- [ADR 0043 — Adopt Rust Workspace and Harness-First Porting Strategy](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md)
- [PostgreSQL Persistence Contract](postgresql.md)
- [Migration and Recovery Contract](migrations-and-recovery.md)
- [ADR 0007 — Adopt PostgreSQL Persistence and Recovery Contracts](../adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md)
- [ADR 0001 — Adopt Durable Task Domain and Lifecycle](../adr/0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0003 — Phase 1 Security Policy and SecretReference Model](../adr/0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [ADR 0004 — Staged Single-Agent Runtime and Verified Adapter Handoffs](../adr/0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [ADR 0005 — Verified Artifact Lifecycle and Safe Content Delivery](../adr/0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md)
- [ADR 0006 — Local v1 API and Event Serialization](../adr/0006-adopt-local-v1-api-and-event-serialization.md)

---

## 14. ADR 0011 local-topology adapter alignment

**Accepted ADR 0011 (upstream provenance; R5 realization).** This section maps the adapter-level realization rules from this contract onto the local topology. It preserves every language-independent adapter contract; the topology is a realization of those contracts, not a replacement.

### Tool parenting

Every host-side operator tool — `pg_dump` 16.14, `pg_restore` 16.14 — is invoked as a child process of the `central` binary. The `central` binary sets the child's environment, connects it to the PostgreSQL target using the tmpfs-delivered credential, and never passes the connection string or password as a command-line argument. The binary is the process parent; the tool never receives Docker socket access, Compose project authority, or container-execution capability. The `PGOPTIONS` environment variable carries the required lock/statement timeout settings (`-c lock_timeout=… -c statement_timeout=…`) and never exposes sensitive configuration.

### Two-permit phases

The `restore verify` → `restore apply` flow uses two distinct permission phases:

1. **Verify phase (class `central_runtime`):** `restore verify` authenticates to PostgreSQL as `central_runtime` through a read-only coexisting operator pool. It reads the schema/checksum history, epoch markers, and protected operator-state. It never loads `central_migration` credentials or takes a mutating lock. It issues the expiring single-use verification ticket through the helper-owned protected operator state.

2. **Apply phase (mixed):** The database/schema replacement substep of `restore apply` receives `central_migration` through the verified `central-migrate` SCM_RIGHTS handoff for exactly the duration of the `pg_restore` invocation and the subsequent epoch-marker/authority-reset transaction. Post-replacement verification, inventory comparison, quarantine, and readiness-transition substeps authenticate as `central_runtime`. No single process, pool, or connection lifetime spans both phases. The descriptor is closed immediately after the database replacement substep commits or fails; a new `restore apply` invocation must reacquire it through fresh PAM and the broker handoff.

### Three-role credential delivery

The three database roles defined in §7 retain separate broker-controlled credential delivery:

- `/run/central-infra/<instance-id>/secrets/pg-central-runtime` → `central_runtime`
- `/run/central-infra/<instance-id>/secrets/pg-central-outbox` → `central_outbox`
- sealed SCM_RIGHTS descriptor to verified `central-migrate` → `central_migration`

The runtime/outbox files are `0400`, owned by the locked numeric UID/GID of exactly one consuming identity. The migration descriptor is bound to the verified `central-migrate` peer and is never exposed as a pathname. The `central serve` process receives only the `central_runtime` file through the broker handoff. Migration and restore-apply processes receive `central_migration` only for their invocation lifetime. `central_outbox` is delivered only to the Compose outbox service and is never visible to `central serve`, migration, or restore processes. Every pool defined in §7.1 authenticates using one of these three exact credential bindings.

### PGOPTIONS and connection construction

All application PostgreSQL connections use `sqlx` (`sqlx::postgres::PgPool` / `PgConnection`) with connection strings constructed from the tmpfs-delivered credential file, the fixed `127.0.0.1:55432` host/port, and the `central` database. Application code never reads a `PGPASSWORD` environment variable, a `.pgpass` file, or a DSN from configuration. The `PGOPTIONS` mechanism for timeout settings applies only to the host-side `pg_dump`/`pg_restore` child processes; in-process adapter connections apply `statement_timeout` and `lock_timeout` session settings configured per pool.

### Local operator modes

The ADR 0009 local operator modes — `local init`, `local status`, `local prepare`, `local up`, `local down`, `local doctor`, `local trust install`, `local security update`, `local browser status/restart`, `local runtime status/restart`, `local maintenance wipe/status` — are realized by the R5 `central-adapter-linux` adapter implementing extended versions of the `central-backup::port` operator-state, migration-inspector, and backup/restore coordinator interfaces. The local adapter mediates all infrastructure authority through the root-owned helper protocol (fresh PAM + operation-specific request + physical-seat TTY confirmation for mutating operations). It never calls Docker, Compose, `pg_dump`, `pg_restore`, MinIO client, or the S3 adapter directly — every dependency-side effect is routed through the helper, which invokes the exact pinned Docker/Compose/tool binaries with operation-scoped authority.

### No-auto-migrate enforcement

The adapter enforces the no-auto-migrate rule at the connection-construction level: any attempt to construct a `central_migration` connection from a `central serve` profile or a non-migration operator mode fails with `FailureDenied` before any TCP handshake. The pool-partitioning topology in §8.1 physically separates migration connections from serving connections; a serving pool simply has no `central_migration` credential binding available.
