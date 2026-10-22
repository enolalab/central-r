//! The task change-set coordinator and the list/detail read stores —
//! the port of `internal/adapter/postgres/task/store.go`.
//!
//! [`Store::commit_task_change_set`] runs the whole mutation in one
//! bounded transaction, in upstream's statement order: replay-receipt
//! read → run-version-map validation → event-sequence block
//! reservation → task INSERT/CAS-UPDATE → per-run INSERT/CAS-UPDATE →
//! `central.events` append → command-receipt INSERT → commit. Any
//! failure before `tx.commit` rolls the whole unit back — the counter
//! reservation included — so a rejected command consumes no sequence
//! and writes no partial state.

use central_foundation::failure::Failure;
use central_foundation::identity::{ArtifactId, RunId, TaskId, WorkspaceId};
use central_task::domain::{
    CommitResult, NO_EXISTING_VERSION, Run, Task, TaskAggregate, TaskChangeSet, codes,
};
use central_task::port::{
    AggregateLoader, ChangeSetStore, CommitTaskChangeSetRequest, LoadedAggregate,
};
use central_task::query::{
    ArtifactRef, RunSeekCursor, RunSummary, TaskDetail, TaskDetailProjection, TaskDetailRead,
    TaskDetailRequest, TaskListProjection, TaskListRead, TaskListRequest, TaskSeekCursor,
    TaskSummary, normalize_task_detail_run_page_size, normalize_task_list_page_size,
};
use sqlx::{PgPool, Postgres, Transaction};

use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::{PG_DATA_CORRUPT, begin_tx, opt_uuid_of, usize_as_i64, uuid_of};
use crate::task::event_log_store::HIDDEN_TASK_EVENT_KINDS;
use crate::task::queries::{
    RunRow, TaskRow, command_input_fingerprint, encode_task_input, event_intent_payload,
    expected_aggregate_versions, run_from_row, task_from_row, waiting_reason_of,
    waiting_reason_value,
};
use crate::task::{DUPLICATE_IDEMPOTENCY_KEY, IDEMPOTENCY_CONFLICT, conflict, invalid};

fn corrupt(what: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, what)
}

fn not_found() -> Failure {
    Failure::not_found(codes::TASK_NOT_FOUND, "task not found in this workspace")
}

fn version_conflict(what: &'static str) -> Failure {
    Failure::conflict(codes::VERSION_CONFLICT, what)
}

/// PostgreSQL-backed task change-set store — the durable write side
/// (`CommitTaskChangeSet`, `LoadAggregate`, `RunByKey`).
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

/// The workspace task list read store.
#[derive(Debug, Clone)]
pub struct ListStore {
    pool: PgPool,
}

/// The task detail read store.
#[derive(Debug, Clone)]
pub struct DetailStore {
    pool: PgPool,
}

impl Store {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// `RunByKey` — reads one run by the spec-5
    /// `(workspace_id, run_key)` submit coordinate (issue #122 resume
    /// path). An absent row reports [`codes::TASK_NOT_FOUND`]; an
    /// empty key or nil workspace is a caller bug and reports
    /// `invalid`.
    pub async fn run_by_key(
        &self,
        workspace_id: WorkspaceId,
        run_key: &str,
    ) -> Result<Run, Failure> {
        if workspace_id.is_nil() || run_key.is_empty() {
            return Err(invalid("run lookup requires workspace and key"));
        }
        let mut tx = begin_tx(&self.pool).await?;
        let row = sqlx::query_as!(
            RunRow,
            "SELECT id, workspace_id, task_id, version, status, run_index, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             COALESCE(ownership_token, '') AS \"ownership_token!\", \
             run_key, request_fingerprint, created_at, updated_at \
             FROM central.runs \
             WHERE workspace_id = $1 AND run_key = $2",
            uuid_of(workspace_id.as_bytes()),
            run_key,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("task: read run by key")?;
        let run = match row {
            Some(row) => run_from_row(row)?,
            None => return Err(not_found()),
        };
        tx.commit().await.ctx("task: commit run-by-key read")?;
        Ok(run)
    }
}

impl ChangeSetStore for Store {
    async fn commit_task_change_set(
        &self,
        req: CommitTaskChangeSetRequest,
    ) -> Result<CommitResult, Failure> {
        if req.workspace_id.is_nil() {
            return Err(invalid("missing workspace"));
        }
        let change_set = &req.change_set;
        if change_set.task.id.is_nil() {
            return Err(invalid("missing task in change set"));
        }
        if change_set.task.workspace_id != req.workspace_id {
            return Err(invalid("workspace mismatch"));
        }

        let mut tx = begin_tx(&self.pool).await?;

        let replay = if req
            .idempotency_key
            .as_deref()
            .is_some_and(|k| !k.is_empty())
        {
            replay_by_receipt(&mut tx, &req).await?
        } else {
            None
        };
        if let Some(replay) = replay {
            return Ok(replay);
        }

        validate_run_version_map(change_set)?;

        let mut first_event_sequence = 0i64;
        if !change_set.events.is_empty() {
            first_event_sequence = reserve_event_sequence_block(
                &mut tx,
                uuid_of(req.workspace_id.as_bytes()),
                i64::try_from(change_set.events.len()).unwrap_or(i64::MAX),
            )
            .await?;
        }

        let written_task = persist_task(&mut tx, change_set, &req).await?;
        let mut written_runs = Vec::with_capacity(change_set.runs.len());
        for run in &change_set.runs {
            written_runs.push(
                persist_run(
                    &mut tx,
                    uuid_of(change_set.task.workspace_id.as_bytes()),
                    run,
                    change_set.run_expected_versions.get(&run.id).copied(),
                )
                .await?,
            );
        }

        if !change_set.events.is_empty() {
            persist_events(&mut tx, change_set, &req, first_event_sequence).await?;
        }

        if req
            .idempotency_key
            .as_deref()
            .is_some_and(|k| !k.is_empty())
        {
            persist_receipt(&mut tx, &req, change_set, written_task.id).await?;
        }

        tx.commit().await.ctx("task: commit task change set")?;

        Ok(CommitResult {
            task: written_task,
            runs: written_runs,
            events: change_set.events.clone(),
        })
    }
}

impl AggregateLoader for Store {
    async fn load_aggregate(
        &self,
        workspace_id: WorkspaceId,
        task_id: TaskId,
    ) -> Result<LoadedAggregate, Failure> {
        if workspace_id.is_nil() || task_id.is_nil() {
            return Err(invalid("missing workspace or task id"));
        }
        let mut tx = begin_tx(&self.pool).await?;

        let task_row = read_task_row(&mut tx, workspace_id, task_id, false).await?;
        let task = task_row.ok_or_else(not_found).and_then(task_from_row)?;

        let mut current_run = None;
        let mut run_version = None;
        if let Some(run_id) = task.current_run_id {
            let run_row = read_run_row(&mut tx, workspace_id, run_id, false)
                .await?
                .ok_or_else(|| corrupt("the current run row is missing for a stored task"))?;
            let run = run_from_row(run_row)?;
            run_version = Some(run.version);
            current_run = Some(run);
        }

        let task_version = task.version;
        tx.commit().await.ctx("task: commit load-aggregate read")?;
        Ok(LoadedAggregate {
            aggregate: TaskAggregate { task, current_run },
            task_version,
            run_version,
        })
    }
}

// ---------------------------------------------------------------------------
// Leaf statements — the upstream query constants, inlined per call site.
// Every task-statement SELECT projects the same `scanTask` column list;
// every run-statement SELECT projects `scanRun` (the `"...!"` aliases
// pin the COALESCE'd columns as non-null for `query_as!`).
// ---------------------------------------------------------------------------

/// `queryReadTask` / `queryReadTaskForUpdate` — `for_update` locks the
/// row for the CAS read-modify-write path.
async fn read_task_row(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    task_id: TaskId,
    for_update: bool,
) -> Result<Option<TaskRow>, Failure> {
    let workspace = uuid_of(workspace_id.as_bytes());
    let task = uuid_of(task_id.as_bytes());
    // The two statements differ only in their locking clause; keeping
    // both as literals preserves compile-time checking for each.
    let row = if for_update {
        sqlx::query_as!(
            TaskRow,
            "SELECT id, workspace_id, version, status, current_run_id, \
             last_run_index, retry_count, retry_eligible_at, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             input_spec::text AS \"input_spec!\", title, \
             created_at, updated_at, parent_task_id, permission_policy, \
             COALESCE(budget_cost_micro_usd, 0) AS \"budget_cost_micro_usd!\", \
             COALESCE(budget_wall_clock_seconds, 0) AS \"budget_wall_clock_seconds!\" \
             FROM central.tasks \
             WHERE workspace_id = $1 AND id = $2 FOR UPDATE",
            workspace,
            task,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("task: read task for update")?
    } else {
        sqlx::query_as!(
            TaskRow,
            "SELECT id, workspace_id, version, status, current_run_id, \
             last_run_index, retry_count, retry_eligible_at, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             input_spec::text AS \"input_spec!\", title, \
             created_at, updated_at, parent_task_id, permission_policy, \
             COALESCE(budget_cost_micro_usd, 0) AS \"budget_cost_micro_usd!\", \
             COALESCE(budget_wall_clock_seconds, 0) AS \"budget_wall_clock_seconds!\" \
             FROM central.tasks \
             WHERE workspace_id = $1 AND id = $2",
            workspace,
            task,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("task: read task")?
    };
    Ok(row)
}

/// `queryReadRunForUpdate` / `queryReadCurrentRun` — same projection,
/// `for_update` selects the locking form.
async fn read_run_row(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    run_id: RunId,
    for_update: bool,
) -> Result<Option<RunRow>, Failure> {
    let workspace = uuid_of(workspace_id.as_bytes());
    let run = uuid_of(run_id.as_bytes());
    let row = if for_update {
        sqlx::query_as!(
            RunRow,
            "SELECT id, workspace_id, task_id, version, status, run_index, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             COALESCE(ownership_token, '') AS \"ownership_token!\", \
             run_key, request_fingerprint, created_at, updated_at \
             FROM central.runs \
             WHERE workspace_id = $1 AND id = $2 FOR UPDATE",
            workspace,
            run,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("task: read run for update")?
    } else {
        sqlx::query_as!(
            RunRow,
            "SELECT id, workspace_id, task_id, version, status, run_index, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             COALESCE(ownership_token, '') AS \"ownership_token!\", \
             run_key, request_fingerprint, created_at, updated_at \
             FROM central.runs \
             WHERE workspace_id = $1 AND id = $2",
            workspace,
            run,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("task: read run")?
    };
    Ok(row)
}

/// `queryReserveEventSequenceBlock` — one contiguous block of
/// workspace-local sequences inside the caller's transaction, so a
/// rollback restores the counter.
async fn reserve_event_sequence_block(
    tx: &mut Transaction<'_, Postgres>,
    workspace: uuid::Uuid,
    count: i64,
) -> Result<i64, Failure> {
    if count <= 0 {
        return Err(invalid("event sequence block must be positive"));
    }
    sqlx::query_scalar!(
        "INSERT INTO central.workspace_event_counters \
         (workspace_id, last_event_sequence) \
         VALUES ($1, $2) \
         ON CONFLICT (workspace_id) DO UPDATE \
         SET last_event_sequence = \
             central.workspace_event_counters.last_event_sequence + \
             EXCLUDED.last_event_sequence \
         RETURNING last_event_sequence - $2 + 1",
        workspace,
        count,
    )
    .fetch_one(&mut **tx)
    .await
    .ctx("task: reserve event sequence block")?
    .ok_or_else(|| corrupt("the sequence reservation returned NULL"))
}

/// `validateRunVersionMap` — every run row must carry an expected
/// version, and a create must name a task id.
fn validate_run_version_map(change_set: &TaskChangeSet) -> Result<(), Failure> {
    for run in &change_set.runs {
        if !change_set.run_expected_versions.contains_key(&run.id) {
            return Err(invalid("missing run expected version"));
        }
    }
    if change_set.expected_task_version == NO_EXISTING_VERSION && change_set.task.id.is_nil() {
        return Err(invalid("task id missing"));
    }
    Ok(())
}

/// `persistTask` — the task row write: INSERT on
/// [`NO_EXISTING_VERSION`], otherwise a `FOR UPDATE` read + optimistic
/// version check + CAS update.
async fn persist_task(
    tx: &mut Transaction<'_, Postgres>,
    change_set: &TaskChangeSet,
    req: &CommitTaskChangeSetRequest,
) -> Result<Task, Failure> {
    let change = &change_set.task;
    let workspace = uuid_of(change.workspace_id.as_bytes());
    let task_id = uuid_of(change.id.as_bytes());
    let correlation = opt_uuid_of(req.correlation_id, |i| i.as_bytes());
    let causation = opt_uuid_of(req.causation_id, |i| i.as_bytes());

    if change_set.expected_task_version == NO_EXISTING_VERSION {
        let input_json: serde_json::Value = serde_json::from_str(&encode_task_input(&change.input))
            .map_err(|_| invalid("task input cannot be stored"))?;
        // The policy is always written explicitly (harness phase 3c
        // decision 3): the column default must never choose it.
        if !change.permission_policy.known() {
            return Err(invalid("task permission policy is unknown"));
        }
        // A zero budget field writes as NULL — the serve default
        // applies (harness phase 3d decision 2); a set field must be
        // in range.
        change.budget.validate()?;
        let result = sqlx::query!(
            "INSERT INTO central.tasks (\
             id, workspace_id, version, status, current_run_id, \
             last_run_index, retry_count, retry_eligible_at, \
             waiting_reason, failure_reason, input_spec, title, \
             correlation_id, causation_id, idempotency_key, \
             parent_task_id, permission_policy, \
             budget_cost_micro_usd, budget_wall_clock_seconds, \
             created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                     $13, $14, NULLIF($15, ''), $16, $17, \
                     NULLIF($18::bigint, 0), NULLIF($19::integer, 0), \
                     clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (id) DO NOTHING",
            task_id,
            workspace,
            change.version,
            change.status.as_str(),
            opt_uuid_of(change.current_run_id, |i| i.as_bytes()),
            change.last_run_index,
            change.retry_count,
            change.retry_eligible_at,
            waiting_reason_value(change.waiting_reason),
            change.failure_reason,
            input_json,
            change.title,
            correlation,
            causation,
            req.idempotency_key.as_deref(),
            opt_uuid_of(change.parent_task_id, |i| i.as_bytes()),
            change.permission_policy.as_str(),
            change.budget.cost_micro_usd,
            change.budget.wall_clock_seconds,
        )
        .execute(&mut **tx)
        .await
        .ctx("task: insert task")?;
        if result.rows_affected() != 1 {
            return Err(version_conflict("task already exists"));
        }
        let inserted = read_task_row(tx, change.workspace_id, change.id, false)
            .await?
            .ok_or_else(|| corrupt("a freshly inserted task row cannot be re-read"))?;
        return task_from_row(inserted);
    }

    let existing = read_task_row(tx, change.workspace_id, change.id, true)
        .await?
        .ok_or_else(not_found)
        .and_then(task_from_row)?;
    if existing.version != change_set.expected_task_version {
        return Err(version_conflict("task version mismatch"));
    }

    let result = sqlx::query!(
        "UPDATE central.tasks \
         SET version = $3, status = $4, current_run_id = $5, \
             last_run_index = $6, retry_count = $7, retry_eligible_at = $8, \
             waiting_reason = $9, failure_reason = $10, \
             correlation_id = $11, causation_id = $12, \
             updated_at = clock_timestamp() \
         WHERE workspace_id = $1 AND id = $2 AND version = $13",
        workspace,
        task_id,
        change.version,
        change.status.as_str(),
        opt_uuid_of(change.current_run_id, |i| i.as_bytes()),
        change.last_run_index,
        change.retry_count,
        change.retry_eligible_at,
        waiting_reason_value(change.waiting_reason),
        change.failure_reason,
        correlation,
        causation,
        change_set.expected_task_version,
    )
    .execute(&mut **tx)
    .await
    .ctx("task: update task")?;
    if result.rows_affected() != 1 {
        return Err(version_conflict("task version mismatch"));
    }

    read_task_row(tx, change.workspace_id, change.id, false)
        .await?
        .ok_or_else(|| corrupt("a freshly updated task row cannot be re-read"))
        .and_then(task_from_row)
}

/// `persistRun` — per-run CAS: INSERT on [`NO_EXISTING_VERSION`],
/// otherwise `FOR UPDATE` + version check + CAS update. A `23505` on
/// insert is the `(workspace_id, run_key)` submit-dedup coordinate —
/// [`DUPLICATE_IDEMPOTENCY_KEY`].
async fn persist_run(
    tx: &mut Transaction<'_, Postgres>,
    workspace: uuid::Uuid,
    run: &Run,
    expected_version: Option<i64>,
) -> Result<Run, Failure> {
    let expected = expected_version.ok_or_else(|| invalid("missing run expected version"))?;
    let run_id = uuid_of(run.id.as_bytes());

    if expected == NO_EXISTING_VERSION {
        let result = sqlx::query!(
            "INSERT INTO central.runs (\
             id, workspace_id, task_id, version, status, run_index, \
             waiting_reason, failure_reason, ownership_token, \
             run_key, request_fingerprint, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                     clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (id) DO NOTHING",
            run_id,
            workspace,
            uuid_of(run.task_id.as_bytes()),
            run.version,
            run.status.as_str(),
            run.index,
            waiting_reason_value(run.waiting_reason),
            run.failure_reason,
            run.ownership_token,
            run.run_key.as_deref(),
            run.request_fingerprint.as_ref().map(<[u8; 32]>::as_slice),
        )
        .execute(&mut **tx)
        .await
        .map_err(|err| {
            let failure = classify_sqlx(&err);
            if failure.code() == crate::error::codes::PG_UNIQUE_VIOLATION {
                return conflict(
                    DUPLICATE_IDEMPOTENCY_KEY,
                    "the run_key is already recorded in this workspace",
                );
            }
            Failure::new(
                failure.kind(),
                failure.code(),
                format!("task: insert run: {}", failure.message()),
            )
        })?;
        if result.rows_affected() != 1 {
            return Err(version_conflict("run already exists"));
        }
        return read_run_row(tx, run.workspace_id, run.id, true)
            .await?
            .ok_or_else(not_found)
            .and_then(run_from_row);
    }

    let existing = read_run_row(tx, run.workspace_id, run.id, true)
        .await?
        .ok_or_else(not_found)
        .and_then(run_from_row)?;
    if existing.version != expected {
        return Err(version_conflict("run version mismatch"));
    }

    let result = sqlx::query!(
        "UPDATE central.runs \
         SET version = $3, status = $4, run_index = $5, \
             waiting_reason = $6, failure_reason = $7, ownership_token = $8, \
             updated_at = clock_timestamp() \
         WHERE workspace_id = $1 AND id = $2 AND version = $9",
        workspace,
        run_id,
        run.version,
        run.status.as_str(),
        run.index,
        waiting_reason_value(run.waiting_reason),
        run.failure_reason,
        run.ownership_token,
        expected,
    )
    .execute(&mut **tx)
    .await
    .ctx("task: update run")?;
    if result.rows_affected() != 1 {
        return Err(version_conflict("run version mismatch"));
    }
    read_run_row(tx, run.workspace_id, run.id, true)
        .await?
        .ok_or_else(not_found)
        .and_then(run_from_row)
}

/// `persistEvents` — appends the change set's intents in statement
/// order onto the reserved sequence block; one `command_id` links the
/// batch. `producer_id` is the task lifecycle writer.
async fn persist_events(
    tx: &mut Transaction<'_, Postgres>,
    change_set: &TaskChangeSet,
    req: &CommitTaskChangeSetRequest,
    first_sequence: i64,
) -> Result<(), Failure> {
    let workspace = uuid_of(req.workspace_id.as_bytes());
    let task_id = uuid_of(change_set.task.id.as_bytes());
    let command_id = uuid::Uuid::now_v7();
    let correlation = opt_uuid_of(req.correlation_id, |i| i.as_bytes());
    let causation = opt_uuid_of(req.causation_id, |i| i.as_bytes());
    for (offset, intent) in change_set.events.iter().enumerate() {
        let sequence = first_sequence + usize_as_i64(offset);
        let payload = event_intent_payload(intent);
        sqlx::query!(
            "INSERT INTO central.events (\
             id, workspace_id, event_sequence, event_type, aggregate_id, \
             aggregate_version, command_id, run_id, payload, \
             correlation_id, causation_id, occurred_at, task_id, kind, \
             state, producer_id, policy_version, eligible_after, legal_hold) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                     clock_timestamp(), $5, $4, 'recorded', \
                     'central.task.lifecycle.v1', 1, \
                     clock_timestamp() + interval '90 days', false)",
            uuid::Uuid::now_v7(),
            workspace,
            sequence,
            intent.kind.as_str(),
            task_id,
            change_set.task.version,
            command_id,
            opt_uuid_of(intent.run_id, |i| i.as_bytes()),
            payload,
            correlation,
            causation,
        )
        .execute(&mut **tx)
        .await
        .ctx("task: insert event")?;
    }
    Ok(())
}

/// `persistReceipt` — the `(workspace_id, command_scope,
/// idempotency_key)` dedup row; the receipt insert riding the same
/// transaction is what makes a committed result replayable.
async fn persist_receipt(
    tx: &mut Transaction<'_, Postgres>,
    req: &CommitTaskChangeSetRequest,
    change_set: &TaskChangeSet,
    task_id: TaskId,
) -> Result<(), Failure> {
    let fingerprint = command_input_fingerprint(change_set);
    let expected = expected_aggregate_versions(change_set);
    let key = req.idempotency_key.as_deref().unwrap_or("");
    let row = sqlx::query!(
        "INSERT INTO central.command_receipts (\
         id, workspace_id, command_scope, idempotency_key, \
         input_fingerprint, expected_aggregate_versions, \
         result_kind, result_reference, correlation_id, causation_id, \
         expiry_at) \
         VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 clock_timestamp() + interval '7 days') \
         ON CONFLICT (workspace_id, command_scope, idempotency_key) \
         DO NOTHING \
         RETURNING id",
        uuid_of(req.workspace_id.as_bytes()),
        req.command_scope,
        key,
        fingerprint,
        expected,
        "commit_task_change_set",
        uuid_of(task_id.as_bytes()),
        opt_uuid_of(req.correlation_id, |i| i.as_bytes()),
        opt_uuid_of(req.causation_id, |i| i.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("task: insert command receipt")?;
    if row.is_none() {
        // A same-key receipt landed between the replay read and this
        // insert — the original transaction committed a different
        // payload view or raced; it cannot be replayed from this one.
        return Err(conflict(
            IDEMPOTENCY_CONFLICT,
            "idempotent replay is unavailable",
        ));
    }
    Ok(())
}

/// `replayByReceipt` — a stored receipt with an identical input
/// fingerprint replays the original committed result; a differing
/// fingerprint on the same `(workspace, scope, key)` conflicts.
async fn replay_by_receipt(
    tx: &mut Transaction<'_, Postgres>,
    req: &CommitTaskChangeSetRequest,
) -> Result<Option<CommitResult>, Failure> {
    let key = req.idempotency_key.as_deref().unwrap_or("");
    let row = sqlx::query!(
        "SELECT input_fingerprint, expected_aggregate_versions, result_reference \
         FROM central.command_receipts \
         WHERE workspace_id = $1 AND command_scope = $2 AND idempotency_key = $3",
        uuid_of(req.workspace_id.as_bytes()),
        req.command_scope,
        key,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("task: read command receipt")?;
    let Some(receipt) = row else {
        return Ok(None);
    };
    let current = command_input_fingerprint(&req.change_set);
    if receipt.input_fingerprint != current {
        return Err(conflict(
            IDEMPOTENCY_CONFLICT,
            "idempotent request fingerprint mismatch",
        ));
    }
    let Some(result_ref) = receipt.result_reference else {
        return Ok(None);
    };
    let task_row = sqlx::query_as!(
        TaskRow,
        "SELECT id, workspace_id, version, status, current_run_id, \
         last_run_index, retry_count, retry_eligible_at, \
         COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
         COALESCE(failure_reason, '') AS \"failure_reason!\", \
         input_spec::text AS \"input_spec!\", title, \
         created_at, updated_at, parent_task_id, permission_policy, \
         COALESCE(budget_cost_micro_usd, 0) AS \"budget_cost_micro_usd!\", \
         COALESCE(budget_wall_clock_seconds, 0) AS \"budget_wall_clock_seconds!\" \
         FROM central.tasks \
         WHERE workspace_id = $1 AND id = $2",
        uuid_of(req.workspace_id.as_bytes()),
        result_ref,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("task: replay read task")?;
    let task = match task_row {
        Some(row) => task_from_row(row)?,
        None => return Err(not_found()),
    };
    let run_rows = sqlx::query_as!(
        RunRow,
        "SELECT id, workspace_id, task_id, version, status, run_index, \
         COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
         COALESCE(failure_reason, '') AS \"failure_reason!\", \
         COALESCE(ownership_token, '') AS \"ownership_token!\", \
         run_key, request_fingerprint, created_at, updated_at \
         FROM central.runs \
         WHERE workspace_id = $1 AND task_id = $2 \
         ORDER BY created_at DESC, id DESC",
        uuid_of(req.workspace_id.as_bytes()),
        result_ref,
    )
    .fetch_all(&mut **tx)
    .await
    .ctx("task: replay read runs")?;
    let mut runs = Vec::with_capacity(run_rows.len());
    for row in run_rows {
        runs.push(run_from_row(row)?);
    }
    Ok(Some(CommitResult {
        task,
        runs,
        events: Vec::new(),
    }))
}

// ---------------------------------------------------------------------------
// TaskListRead — the upstream `queryReadTaskList` keyset page.
// ---------------------------------------------------------------------------

impl ListStore {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// The `scanTaskSummary` projection row.
struct TaskSummaryRow {
    id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    status: String,
    current_run_id: Option<uuid::Uuid>,
    waiting_reason: String,
    retry_count: i64,
    title: String,
    failure_reason: String,
    retry_eligible_at: Option<time::OffsetDateTime>,
    updated_at: time::OffsetDateTime,
    created_at: time::OffsetDateTime,
}

fn summary_from_row(row: TaskSummaryRow) -> Result<TaskSummary, Failure> {
    Ok(TaskSummary {
        task_id: TaskId::from_trusted_db_bytes(*row.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
        status: central_task::domain::TaskStatus::parse(&row.status)
            .map_err(|_| corrupt("a stored task status is outside the domain vocabulary"))?,
        current_run_id: row
            .current_run_id
            .map(|u| RunId::from_trusted_db_bytes(*u.as_bytes())),
        waiting_reason: waiting_reason_of(&row.waiting_reason)?,
        retry_count: row.retry_count,
        title: row.title,
        failure_reason: row.failure_reason,
        retry_eligible_at: row.retry_eligible_at,
        updated_at: row.updated_at,
        created_at: row.created_at,
    })
}

impl TaskListRead for ListStore {
    async fn read(&self, req: TaskListRequest) -> Result<TaskListProjection, Failure> {
        central_task::query::validate_task_list_request(&req)?;
        let mut tx = begin_tx(&self.pool).await?;

        let page_size = i64::from(normalize_task_list_page_size(req.page_size));
        // A cursor binds all three seek legs; the head page binds
        // NULLs and the `$3 IS NULL` arm admits every row — upstream's
        // `(status, updated_at, id)` keyset predicate.
        let (status, updated_at, task_id) = match req.cursor {
            Some(c) => (
                Some(c.status.as_str().to_owned()),
                Some(c.updated_at),
                Some(uuid_of(c.task_id.as_bytes())),
            ),
            None => (None, None, None),
        };
        let rows = sqlx::query_as!(
            TaskSummaryRow,
            "SELECT id, workspace_id, status, current_run_id, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             retry_count, title, \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             retry_eligible_at, updated_at, created_at \
             FROM central.tasks \
             WHERE workspace_id = $1 \
               AND ($3::text IS NULL OR (status > $3 \
                    OR (status = $3 AND (updated_at, id) < ($4, $5)))) \
             ORDER BY status ASC, updated_at DESC, id DESC \
             LIMIT $2",
            uuid_of(req.workspace_id.as_bytes()),
            page_size,
            status,
            updated_at,
            task_id,
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("task: read task list")?;

        let mut tasks = Vec::with_capacity(rows.len());
        for row in rows {
            tasks.push(summary_from_row(row)?);
        }
        // Upstream cursor rule: a full page emits a seek cursor; the
        // last page is detected by the empty next read.
        let next_cursor = if tasks.len() as i64 == page_size {
            tasks.last().map(|last| TaskSeekCursor {
                task_id: last.task_id,
                status: last.status,
                updated_at: last.updated_at,
            })
        } else {
            None
        };
        tx.commit().await.ctx("task: commit task-list read")?;
        Ok(TaskListProjection { tasks, next_cursor })
    }
}

// ---------------------------------------------------------------------------
// TaskDetailRead — the upstream `queryReadTaskDetail*` fan-out.
// ---------------------------------------------------------------------------

impl DetailStore {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl TaskDetailRead for DetailStore {
    async fn read(&self, req: TaskDetailRequest) -> Result<TaskDetailProjection, Failure> {
        central_task::query::validate_task_detail_request(&req)?;
        let mut tx = begin_tx(&self.pool).await?;

        let page_size = i64::from(normalize_task_detail_run_page_size(req.run_page_size));
        let task_row = read_task_row(&mut tx, req.workspace_id, req.task_id, false)
            .await?
            .ok_or_else(not_found)
            .and_then(task_from_row)?;

        // Run keyset — `(created_at, id)` descending; a NULL cursor
        // pair admits the head page, as upstream's `any` binds did.
        let (cursor_at, cursor_run) = match req.run_cursor {
            Some(c) => (Some(c.created_at), Some(uuid_of(c.run_id.as_bytes()))),
            None => (None, None),
        };
        let run_rows = sqlx::query_as!(
            RunRow,
            "SELECT id, workspace_id, task_id, version, status, run_index, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             COALESCE(ownership_token, '') AS \"ownership_token!\", \
             run_key, request_fingerprint, created_at, updated_at \
             FROM central.runs \
             WHERE workspace_id = $1 AND task_id = $2 \
               AND ($4::timestamptz IS NULL OR (created_at, id) < ($4, $5)) \
             ORDER BY created_at DESC, id DESC \
             LIMIT $3",
            uuid_of(req.workspace_id.as_bytes()),
            uuid_of(req.task_id.as_bytes()),
            page_size,
            cursor_at,
            cursor_run,
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("task: read task detail runs")?;

        let mut runs = Vec::with_capacity(run_rows.len());
        for row in run_rows {
            let run = run_from_row(row)?;
            runs.push(RunSummary {
                run_id: run.id,
                task_id: run.task_id,
                workspace_id: run.workspace_id,
                status: run.status,
                index: run.index,
                waiting_reason: run.waiting_reason,
                failure_reason: run.failure_reason,
                updated_at: run.updated_at,
                created_at: run.created_at,
            });
        }

        // Current-run artifact legs — absent current run ⇒ no
        // artifacts (upstream's zero-RunID early outs).
        let mut required_artifact_id = None;
        let mut artifacts = Vec::new();
        if let Some(current_run) = task_row.current_run_id {
            let artifact_row = sqlx::query!(
                "SELECT id FROM central.artifacts \
                 WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                   AND state = 'ready' AND delete_intent_at IS NULL \
                 ORDER BY (required_role IS NOT DISTINCT FROM 'harness.report') DESC, \
                          updated_at DESC, id DESC \
                 LIMIT 1",
                uuid_of(req.workspace_id.as_bytes()),
                uuid_of(req.task_id.as_bytes()),
                uuid_of(current_run.as_bytes()),
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("task: read task detail ready artifact")?;
            required_artifact_id =
                artifact_row.map(|r| ArtifactId::from_trusted_db_bytes(*r.id.as_bytes()));

            let artifact_rows = sqlx::query!(
                "SELECT id, COALESCE(required_role, '') AS \"required_role!\", size \
                 FROM central.artifacts \
                 WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                   AND state = 'ready' AND delete_intent_at IS NULL \
                 ORDER BY CASE required_role \
                     WHEN 'harness.report' THEN 0 \
                     WHEN 'harness.patch' THEN 1 \
                     WHEN 'harness.commits' THEN 2 ELSE 3 END, \
                   created_at, id \
                 LIMIT $4",
                uuid_of(req.workspace_id.as_bytes()),
                uuid_of(req.task_id.as_bytes()),
                uuid_of(current_run.as_bytes()),
                usize_as_i64(central_task::query::MAX_TASK_DETAIL_ARTIFACTS),
            )
            .fetch_all(&mut *tx)
            .await
            .ctx("task: read task detail artifacts")?;
            for row in artifact_rows {
                artifacts.push(ArtifactRef {
                    id: ArtifactId::from_trusted_db_bytes(*row.id.as_bytes()),
                    role: row.required_role,
                    verified_size: row.size,
                });
            }
        }

        let hidden: Vec<String> = HIDDEN_TASK_EVENT_KINDS
            .iter()
            .map(|k| (*k).to_owned())
            .collect();
        let event_revision = sqlx::query_scalar!(
            "SELECT COALESCE(MAX(event_sequence), 0) \
             FROM central.events \
             WHERE workspace_id = $1 AND aggregate_id = $2 \
               AND kind <> ALL($3::text[])",
            uuid_of(req.workspace_id.as_bytes()),
            uuid_of(req.task_id.as_bytes()),
            &hidden[..],
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("task: read task detail event revision")?
        .unwrap_or(0);

        let next_run_cursor = if runs.len() as i64 == page_size {
            runs.last().map(|last| RunSeekCursor {
                created_at: last.created_at,
                run_id: last.run_id,
            })
        } else {
            None
        };

        let detail = TaskDetail {
            task_id: task_row.id,
            workspace_id: task_row.workspace_id,
            status: task_row.status,
            title: task_row.title,
            input: task_row.input,
            current_run_id: task_row.current_run_id,
            retry_count: task_row.retry_count,
            failure_reason: task_row.failure_reason,
            waiting_reason: task_row.waiting_reason,
            updated_at: task_row.updated_at,
            created_at: task_row.created_at,
            parent_task_id: task_row.parent_task_id,
            permission_policy: task_row.permission_policy,
            budget: task_row.budget,
            required_artifact_id,
            artifacts,
            projection_revision: task_row.version,
            event_revision,
        };
        tx.commit().await.ctx("task: commit task-detail read")?;
        Ok(TaskDetailProjection {
            task: detail,
            runs,
            next_run_cursor,
        })
    }
}
