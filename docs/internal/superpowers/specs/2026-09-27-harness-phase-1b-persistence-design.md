# Harness Phase 1b: Persistence (v30 + PostgreSQL store) — Design

Date: 2026-09-27
Status: Reviewed — [spec review](../reviews/2026-09-27-harness-phase-1b-spec-review.md) findings applied
Governing decision: [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md) (Accepted)
Governing specs: [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md) §6–§7; [Phase 1a design](2026-09-27-harness-phase-1a-domain-design.md) §13
Inputs: [Phase 1a final review — Follow-ups, "Phase 1b spec inputs"](../reviews/2026-09-27-harness-phase-1a-final-review.md)

## 1. Goal

Make harness session attempts durable:

- migration **v30** creates `central.harness_attempts` and `central.harness_events`;
- a PostgreSQL store behind a domain-owned port (`internal/harness/port`) creates, loads and updates attempts with compare-and-swap on **version and fence**;
- each normalized event is recorded **atomically** with the attempt mutation it causes;
- the domain gains the fields and rules this needs, plus the 1b follow-ups the phase 1a final review recorded.

No serve wiring, no real adapter, no object-storage body capture. Those arrive in phase 2 and 3.

**Success criteria:**

- On a fresh PostgreSQL 16.14 target, `migrate.BaselineInstaller.Install` produces the exact chain through **v30**. `VerifyServeBaseline`, running as `central_runtime`, passes, and so does the v30 shape verifier.
- All migrate tests pass live: `go test -p=1 ./internal/adapter/postgres/migrate/` with `CENTRAL_TEST_PG_URL` set. That includes the stale b24–b28 fixtures and the baseline chain test, which this phase repairs. Pure unit tests pass without a database.
- The live store tests pass as `central_runtime`:
  - create, load and save round-trip every domain field;
  - a version conflict returns `ErrVersionConflict` and a fence conflict returns `ErrFenceMismatch`;
  - a second live attempt for a run is rejected;
  - `AppendEvent` is atomic and idempotent on replay.
- The rest is clean:
  - `go test ./internal/harness/... ./internal/adapter/harness/... ./internal/adapter/postgres/harness/...` passes with `-race`;
  - archguard is clean;
  - `go vet ./...` and `go build ./...` are clean.

## 2. Prerequisite discovered during brainstorming: v29 is broken on a live database

A live run of the migrate package on `main` (`a89d49f`), against PostgreSQL 16.14 with `testdata/b05-reference-host/init.sql`, fails every fresh install:

```
b29 prune log: catalog prune_log: b08 recovery correction: invalid column prune_log.batch_seq
```

**Root cause.** The v29 catalog declares `udt: "int4"`. `b08RecoveryCanonicalColumnType` maps only `bool`, `int8` and `timestamptz`, so `int4` is compared as-is against `format_type`'s output, `integer`, and the check fails.

So `central migrate up` cannot reach v29 on `main` today, and v30 cannot be installed on top of it. With `int4 → integer` added (probed, then reverted), four live failures remain, all stale test fixtures:

- `TestBaselineInstallProducesExactMigrationChainThroughV28` still expects the chain to end at v28.
- `TestApplyB24…`, `TestApplyB25…` and `TestApplyB26…` build a "clean v24/v25/v26 target" by deleting only v25/v26 rows and tables. They leave the v27–v29 rows in place, so the b29 classifier rejects the chain.

In addition, `BaselineManifest` (`m/baseline.go:1104-1140`) still pins v28 and omits the `b29-prune-log` checksum. `composeStatus` would therefore report drift on v29 targets.

**Decision.** Repair these as **Task 0** of this phase, in their own commits:

- add the `int4 → integer` mapping;
- move `BaselineManifest` to v29 with its checksum;
- update the baseline chain test to v29, then to v30;
- make the b24–b26 fixtures remove every later version (v27+) before rewinding.

The fix weakens no check. It is covered by the live tests failing before and passing after. It is recorded under `tasks/`, as AGENTS.md's delegation rule requires for fixes found in flight.

## 3. Decisions (brainstorming; recommended option taken per the maintainer's workflow)

| # | Question | Decision | Reason |
| --- | --- | --- | --- |
| 1 | Storage shape? | **Typed columns** in `central.harness_attempts`, not a jsonb blob. | Repo convention: text CHECK enums, bounded text, int8 counters. The catalog verifier pins every column. The read model and recovery queries need the columns. |
| 2 | Store events? | **Yes: bounded metadata only**, in `central.harness_events` with PK `(attempt_id, seq)`. Columns are kind, ids, statuses, raw size and SHA-256. There is **no** payload content. | Governing spec §6 requires this ("no payloads in the DB"). The PK makes replay idempotent. The digest lets phase 2 link the raw frame in object storage. |
| 3 | Atomic event cursor? | `AppendEvent(expected, next, record)` inserts the event row and compare-and-swaps the attempt **in one transaction**. `next.LastEventSeq` must equal `record.Seq`. | This closes the final-review follow-up: a crash can never leave the cursor ahead of, or behind, the recorded events. |
| 4 | Concurrency control? | **Optimistic version plus fence compare-and-swap.** `Attempt.Version` is a persistence revision owned by the store. Domain mutators copy it unchanged; `Prepare` sets 0. `Save`/`AppendEvent` require `next.Version == expected.Version`, write under `WHERE version = $expected AND fence_generation = $expectedFence` after a `SELECT … FOR UPDATE` that distinguishes the two conflict kinds, store `version = expected.Version + 1`, and **return the stored attempt** carrying the new version. | A fence alone does not serialize two writers under one lease (final review). A store-owned revision stays correct when one event drives several mutators (e.g. `RecordProgress` + `RevealSession`). Returning the stored attempt means callers never reuse a stale copy. |
| 5 | Check the live execution lease (`central.execution_ownership`) in the store? | **No, not in 1b.** The store enforces the attempt's own version and fence. Binding to the run's live lease is the phase 3 app service's job, in the transaction that holds the lease. | That would couple the harness store to the execution tables and their token hash. The fence is still a CAS, so a stale holder is rejected once recovery refences. |
| 6 | Workspace scoping? | Add `WorkspaceID identity.WorkspaceID` to `Attempt` and `PrepareInput`. `PrepareResume` requires it to match. Every table carries `workspace_id`, with composite FKs `(workspace_id, run_id) → central.runs(workspace_id, id)` and `(workspace_id, attempt_id) → harness_attempts(workspace_id, id)`, all `ON DELETE RESTRICT`. | Every Central table is workspace-scoped (b08 composite-unique convention). |
| 7 | At most one live attempt per run? | Enforced in the DB by a **partial unique index** `(workspace_id, run_id) WHERE state IN ('prepared','launching','running','awaiting_permission','ambiguous')`. Its violation maps to `ErrLiveAttemptExists`. | Governing spec §7 invariant. The DB is the only place it cannot be raced. |
| 8 | Usage semantics (final-review I5)? | `Attempt.Usage` is **scope-normalized cumulative**. It is set by a new mutator, `ApplyUsage(fence, report, at)`: the first report adopts the scope; a different scope → `ErrInvalidEvent`; `step` accumulates; `run`/`session_cumulative` replace, and any counter decrease → `ErrInvalidEvent`. `RecordProgress(fence, seq, at)` no longer takes usage. | A zero `Usage` no longer wipes the snapshot. Budgets (§13) need a cumulative number. |
| 9 | Launch invariants (final review)? | `Validate` requires `SandboxScopeID` and `HarnessVersion` in `launching`, `running`, `awaiting_permission`, `succeeded`, `interrupted`, `killed` and `budget_exhausted`, because those are reachable only through `Launch`. `failed`, `ambiguous` and `resolved` stay optional, because they are reachable from `prepared`. `port.StartSpec.Validate` requires `Env.SandboxScopeID`. | Rows loaded from the DB are then checked for the scope id that reconcile needs. |
| 10 | Timestamp and fence monotonicity (final review)? | `guard` rejects `at` before `UpdatedAt` (`ErrInvalidAttempt`). `PrepareResume` requires `in.Fence.Generation >= prev.Fence.Generation` (`ErrFenceMismatch`). | Closes the two reproduced gaps. |
| 11 | Where does the store port live? | `internal/harness/port/store.go` defines the `AttemptStore` interface; domain sentinels live in `internal/harness`. The adapter lives in `internal/adapter/postgres/harness`. | archguard: `internal/harness/**` may import only identity, failure and harness, and no pgx. Adapter isolation allows `postgres/harness` → `harness`, `harness/port`, `identity`. |
| 12 | Runtime privileges? | `central_runtime` gets `SELECT, INSERT, UPDATE` on `harness_attempts` and `SELECT, INSERT` on `harness_events`. No DELETE, no TRUNCATE. The ACL specs follow `b08FinalMutableRelationACL`, with an insert-only variant for events. | Least privilege, and consistent with the b08/b10 runtime grants. `reapply_incremental_runtime_grants` must carry them verbatim. |
| 13 | Integer column types? | **`bigint` (int8) for every integer column**, including exit code and seq. | This avoids a second int4 surprise, and it matches every other catalog. |

**Approaches considered:**

- **(A, chosen)** Dedicated typed tables, plus a store adapter behind a domain port.
- **(B)** Reuse the B09 execution-evidence tables. Rejected: those model provider and tool attempts, which ADR 0035 froze.
- **(C)** A single jsonb document per attempt. Rejected: the catalog verifier cannot pin its shape, it goes against repo conventions, and it cannot be queried or indexed for the live-attempt invariant.

## 4. Domain changes (`internal/harness`)

- **`Attempt`:**
  - adds `WorkspaceID identity.WorkspaceID`, after `ID`;
  - adds `Version int64` (≥ 0; `Prepare` sets 0).
- **`PrepareInput`:** adds `WorkspaceID`. `PrepareResume` also requires a matching workspace and `in.Fence.Generation >= prev.Fence.Generation`.
- **Versioning:** mutators never change `Version` (decision 4). The idempotent no-ops still return the receiver unchanged: same-id `RevealSession`, equal-seq `RecordProgress`, and an `ApplyUsage` that changes nothing.
- **`(Attempt) Equal(b Attempt) bool`:** value equality over every field. `Terminal.ExitCode` is compared by value, not pointer. Time fields are compared with `time.Equal` after `Truncate(time.Microsecond)`, the PostgreSQL `timestamptz` precision. The store writes times truncated to the microsecond, so a stored-then-loaded attempt is `Equal` to the one written.
- **`RecordProgress(fence, seq, at)`:** usage is removed from the signature.
- **`ApplyUsage(fence, report Usage, at)`:**
  - allowed in `launching`, `running` and `awaiting_permission`;
  - applies the rules of decision 8 and validates the report;
  - `Estimated` is sticky once true.
- **`Validate` additions:**
  - `WorkspaceID` must be non-zero, and `Version` ≥ 0;
  - the launch invariants of decision 9.
- **`guard`:** also rejects `at.Before(a.UpdatedAt)`.
- **New sentinels:**
  - `ErrAttemptNotFound`;
  - `ErrVersionConflict`;
  - `ErrLiveAttemptExists`;
  - `ErrEventConflict`, for the same `(attempt, seq)` with a different digest.
- **`EventRecord` and `RecordOf(e Event) (EventRecord, error)`:**
  - `RecordOf` is pure. It validates the event, then derives the record.
  - Fields: `Attempt`, `Seq`, `Kind`, `At`, `HarnessSessionID`, `RawSize int64`, `RawSHA256 [32]byte`.
  - Optional ids and statuses: `ToolCallID`, `ToolName`, `ToolStatus`, `PermissionRequestID`, `PermissionOutcome`, `TerminalStatus`.
  - No `Text`, `Input`, `Output`, `Resources`, `Plan`, `Warning`, `Retry` or `Terminal.Reason` content is copied.
  - Its `String`/`GoString` print no digests beyond a short prefix.

The phase 1a fake end-to-end test and `apply` helper are updated for the new `RecordProgress`/`ApplyUsage` split and the `WorkspaceID` input. For every event the helper calls `RecordProgress(fence, e.Seq, at)` first. For a `UsageReport` it then calls `ApplyUsage(fence, p.Usage, at)`, followed by the kind-specific mutator. Their behavior assertions do not change.

## 5. Schema v30 (architectural contract)

Both tables use schema `central`. Owner is `central_migration`. Every column is `NOT NULL` unless marked nullable, and every text column has an `octet_length` bound.

### `central.harness_attempts`

| Column | Type | Notes |
| --- | --- | --- |
| `workspace_id` | uuid | FK `(workspace_id, run_id)` → `central.runs(workspace_id, id)` ON DELETE RESTRICT |
| `id` | uuid | PRIMARY KEY; UNIQUE `(workspace_id, id)` |
| `run_id` | uuid | |
| `kind` | text | ≤ 64 (charset and non-emptiness are enforced by the domain) |
| `adapter_version` | text | ≤ 128 |
| `harness_version` | text, nullable | ≤ 128 |
| `harness_session_id` | text, nullable | ≤ 512 |
| `resume_of` | uuid, nullable | FK `(workspace_id, resume_of)` → `harness_attempts(workspace_id, id)` ON DELETE RESTRICT |
| `resume_session_id` | text, nullable | ≤ 512; CHECK `(resume_of IS NULL) = (resume_session_id IS NULL)` |
| `workspace_path` | text | ≤ 4096 |
| `base_sha` | text | ≤ 128 |
| `permission` | text | CHECK IN (`deny`, `bridge`, `auto_allow`) |
| `sandbox_scope_id` | text, nullable | ≤ 256 |
| `fence_generation` | bigint | CHECK ≥ 1 |
| `version` | bigint | CHECK ≥ 0 |
| `state` | text | CHECK IN (the 11 states) |
| `pending_permission` | text, nullable | ≤ 512 |
| `terminal_status` | text, nullable | CHECK IN (the 6 terminal statuses) |
| `terminal_reason` | text, nullable | ≤ 4096 |
| `terminal_exit_code` | bigint, nullable | |
| `resolution_kind` | text, nullable | CHECK IN (`resume`, `rerun`, `abandon`) |
| `resolution_decided_by` | text, nullable | ≤ 256 |
| `ambiguity_reason` | text, nullable | ≤ 4096 |
| `last_event_seq` | bigint | CHECK ≥ 0 |
| `usage_tokens_in`, `usage_tokens_out`, `usage_cache_read`, `usage_cache_write`, `usage_cost_micro_usd` | bigint | each CHECK ≥ 0 |
| `usage_scope` | text, nullable | CHECK IN (`step`, `run`, `session_cumulative`) |
| `usage_estimated` | boolean | |
| `prepared_at`, `updated_at` | timestamptz | |
| `ended_at` | timestamptz, nullable | |

**Index:** `harness_attempts_one_live_per_run_idx`, a UNIQUE index on `(workspace_id, run_id)` WHERE `state IN ('prepared','launching','running','awaiting_permission','ambiguous')`.

### `central.harness_events`

| Column | Type | Notes |
| --- | --- | --- |
| `workspace_id` | uuid | FK `(workspace_id, attempt_id)` → `harness_attempts(workspace_id, id)` ON DELETE RESTRICT |
| `attempt_id` | uuid | PRIMARY KEY `(attempt_id, seq)` |
| `seq` | bigint | CHECK ≥ 1 |
| `kind` | text | CHECK IN (the 12 event kinds) |
| `at` | timestamptz | |
| `harness_session_id` | text, nullable | ≤ 512 |
| `raw_size` | bigint | CHECK ≥ 1 |
| `raw_sha256` | bytea | CHECK `octet_length = 32` |
| `tool_call_id`, `tool_name` | text, nullable | ≤ 512 / ≤ 256 |
| `tool_status` | text, nullable | CHECK IN (`ok`, `error`, `denied`, `cut_off`) |
| `permission_request_id` | text, nullable | ≤ 512 |
| `permission_outcome` | text, nullable | CHECK IN (`allow`, `deny`, `timeout`) |
| `terminal_status` | text, nullable | CHECK IN (the 6 terminal statuses) |

**CHECK shapes.** Only shapes with precedent in this package are used:

- `octet_length(col) <= N` upper bounds ("≤ N" in the tables above);
- `= 32` for the digest;
- `IN (...)` enums, emitted through `b08StateCheckDefinitions`;
- `>= 0` / `>= 1` numeric bounds;
- the `resume_of`/`resume_session_id` pairing.

There is no regex operator and no ranged `octet_length`. Non-emptiness and charsets are domain rules, enforced by `Validate` on every write and load. Before the DDL is final, the plan must capture every new constraint's live `pg_get_constraintdef` output and every index's `pg_get_indexdef` output on PostgreSQL 16.14, and encode those exact strings (plus known deparse variants) as the catalog's canonical definitions. That avoids a repeat of the v29 `int4` surprise.

**Deliberately absent from both tables:**

- **No triggers** (the relation verifier rejects them).
- **No sequences.**
- **No state and terminal consistency CHECKs beyond the enums.** The domain's `Validate` runs on every load and rejects inconsistent rows.

## 6. Migration v30 mechanics

The file is `internal/adapter/postgres/migrate/b30_harness_attempts.go`, with version `30` and checksum `"b30-harness-attempts"`. It follows the b29 pattern exactly:

- classifier bounds `< 22 || > 24`, delegating to the b29 classifier (which must be clean);
- a dirty intent is recorded before the DDL;
- the DDL runs in one transaction with `synchronous_commit` on, and is idempotent (`IF NOT EXISTS`, then `REVOKE`/`GRANT`);
- the shape is verified (relation behavior with exact ACLs, then the final catalog) before the clean marker.

**Registration.** Every place the exploration found:

1. The outer gate `case 2, …, 24` and the inner switch in `m/b08.go`: `case 23` becomes ambiguous (with v15 ending at v29, or without v15 ending at v30), and a new `case 24` covers with-v15 ending at v30.
2. b29's forward edge. Remove "terminal migration", then add the monotone fast path and the `ApplyB30` call, mirroring b28 → b29.
3. The chain verifier and the shape verifier in `m/inspector.go`, plus its doc comment.
4. `reapply_incremental_runtime_grants.go`.
5. `BaselineManifest`, moved to v30 with both the b29 and b30 checksums.
6. The predecessor tests that pin the terminal chain verifier (b25–b28 integration tests) and the baseline chain test.

## 7. Store port and adapter

**Port.** `internal/harness/port/store.go`:

```go
type AttemptStore interface {
    Create(ctx context.Context, a harness.Attempt) error                               // a.Version == 0
    Load(ctx context.Context, ws identity.WorkspaceID, id identity.HarnessAttemptID) (harness.Attempt, error)
    LiveAttemptForRun(ctx context.Context, ws identity.WorkspaceID, run identity.RunID) (harness.Attempt, bool, error)
    Save(ctx context.Context, expected, next harness.Attempt) (harness.Attempt, error)       // returns stored attempt (Version+1)
    AppendEvent(ctx context.Context, expected, next harness.Attempt, rec harness.EventRecord) (harness.Attempt, error)
}
```

**Adapter.** `internal/adapter/postgres/harness` provides `Store` with `var _ port.AttemptStore = (*Store)(nil)`. It follows the task store's transaction pattern: `set_config` for lock, statement and idle timeouts.

**`Create`:**
- requires `a.Validate()` and `a.Version == 0`;
- INSERTs the row;
- maps a unique violation on the live index to `ErrLiveAttemptExists`;
- on a PK violation, loads the stored row: if `stored.Equal(a)`, `Create` returns nil, so a retried create is idempotent (repo hard constraint); otherwise it returns `ErrVersionConflict`;
- maps an FK violation (unknown run) to `ErrInvalidAttempt`.

**`Save`:**
- requires identical `ID`, `WorkspaceID` and `RunID`; `next.Version == expected.Version`; `!next.Equal(expected)` (no empty writes); and `next.Validate()`;
- in one transaction, runs `SELECT version, fence_generation … FOR UPDATE`. A missing row → `ErrAttemptNotFound`, a version mismatch → `ErrVersionConflict`, and a fence mismatch against `expected.Fence` → `ErrFenceMismatch`;
- then runs `UPDATE … SET …, version = $expected+1 WHERE workspace_id AND id AND version=$expected AND fence_generation=$expectedFence`, requiring `RowsAffected == 1`, and returns `next` with `Version = expected.Version+1`;
- maps a live-index violation to `ErrLiveAttemptExists`.

**`AppendEvent`:**
- requires everything `Save` requires, plus `rec.Attempt == next.ID` and `next.LastEventSeq == rec.Seq`;
- runs in one transaction:
  1. `INSERT` the event row, with `ON CONFLICT (attempt_id, seq) DO NOTHING`.
  2. If the row already existed, the outcome depends on the stored digest. A different digest → `ErrEventConflict`. The same digest while the stored `last_event_seq >= rec.Seq` → idempotent replay: the attempt is not touched, and the **currently stored attempt** is returned, so the caller continues from fresh state and never reuses its `next` as a new `expected`. The same digest while the attempt lags → `ErrEventConflict`, which should never happen.
  3. Otherwise, apply `Save`'s compare-and-swap in the same transaction and return the stored attempt. `next.LastEventSeq == rec.Seq > expected.LastEventSeq` guarantees the write is never empty.

**`Load` / `LiveAttemptForRun`:**
- scan every column into domain types (`identity.Parse*`);
- run `Validate()`, returning `ErrInvalidAttempt` wrapped as corrupt storage.

**Errors:**
- driver errors are sanitized to SQLSTATE only, following the execution store's `sanitizeDatabaseFailure` pattern;
- no pgx or pgconn type crosses the port;
- no error text includes paths, reasons or session ids beyond ids already printable.

## 8. Testing

**Unit tests (no DB):**
- domain changes: versioning; `ApplyUsage` rules; launch invariants; monotonicity; `RecordOf` never copying sensitive fields; `EventRecord` printing;
- v30 classification and registration (`cleanV30Records`, the admits-every-length test, and the b08 gate), plus DDL string checks;
- the store's parameterized queries, following `TestTaskQueriesAreParameterized`, covering the event insert/lookup and `ON CONFLICT` queries too;
- a dedicated unit test for the rewritten `b08.go` gate: `case 23` is ambiguous (with v15 ending at v29, or without v15 ending at v30) and `case 24` covers with-v15 ending at v30. The code's own comment records that a missed gate once broke the v22 addition.

**Live tests (`CENTRAL_TEST_PG_URL`; skipped otherwise):**
- migrate package: every existing and new test, including the v30 apply, dirty resume, shape verification and serve-baseline verification;
- store: the store under test runs as `central_runtime` (`CENTRAL_TEST_PG_RUNTIME_URL`) against a target migrated to v30. A second connection, as `central_migration` (`CENTRAL_TEST_PG_URL`), migrates the target and seeds workspace, task and run rows, following the `task/store_test.go` `seedWorkspace` pattern, because runtime is not granted INSERT on those tables for seeding. The test then exercises every rule in §7, including the stored-then-loaded `Equal` round-trip.

**Local recipe:**

```bash
docker run -d --name central-1b-pg -p 127.0.0.1:55433:5432 \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -v "$PWD/testdata/b05-reference-host/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" \
  postgres:16.14-bookworm
```

The URLs are `central_migration` / `central_runtime` / `central_outbox` at `127.0.0.1:55433/central`. Run live packages with `-p=1`.

## 9. Out of scope

- Serve wiring and the harness app service (phase 3), including binding the attempt fence to the live execution lease (decision 5).
- Object-storage capture of raw frames and transcripts (phase 2 artifact capture).
- A recovery listing of non-terminal attempts (phase 3 reconcile).
- The resume-new-session-id decision (phase 2).
- Env denylist hardening and archguard scope for an app service (phase 2).
- Fixing archguard `domain-purity`'s normalization.
- Pre-existing C06 and recovery failures unrelated to migrations.
