//! Row readers for the execution store — the `query_as!` projections
//! upstream scans by hand (`readTask`, `readRun`, `readStep`,
//! `readAttempt`, `readToolCalls`, `readToolAttempts`, `readLease`,
//! `readPersistedLeaseForUpdate`, `readApproval`) plus the recovery
//! epoch/workspace row readers and the `RecoveryClaimabilityReader`
//! port.
//!
//! uuid columns decode as `Uuid` (the task adapter's convention), not
//! upstream's `::text` + `ParseXID` — identity reconstruction goes
//! through `from_trusted_db_bytes`, and drifted vocabularies are
//! `pg_data_corrupt`.

use central_execution::domain::{
    Approval, ApprovalState, ApprovalSubject, AttemptState, Claimability, Lease, Step, StepAttempt,
    StepState, ToolCall, ToolCallAttempt, ToolCallState,
};
use central_execution::domain::{InvocationId, LogicalOperationId, PhysicalAttemptId};
use central_execution::port::RecoveryClaimabilityReader;
use central_execution::resume::{self, RecoveryEpoch, RecoveryEpochState, RecoveryWorkspaceWork};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ApprovalId, RunId, StepAttemptId, StepId, TaskId, ToolCallAttemptId, ToolCallId, WorkspaceId,
};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

use super::store::Store;
use super::{conflict, corrupt, invalid, uuid_of};
use crate::error::SqlxContext;
use crate::task::queries::{RunRow, TaskRow, run_from_row, task_from_row};

// ---------------------------------------------------------------------------
// Row projections — every SELECT lists its columns explicitly; uuid
// columns decode as `Uuid`.
// ---------------------------------------------------------------------------

pub(crate) struct StepRow {
    pub id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    pub run_id: uuid::Uuid,
    pub version: i64,
    pub sequence: i64,
    pub state: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

fn step_from_row(r: StepRow) -> Result<Step, Failure> {
    Ok(Step {
        id: StepId::from_trusted_db_bytes(*r.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        task_id: TaskId::from_trusted_db_bytes(*r.task_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
        version: r.version,
        sequence: r.sequence,
        state: StepState::parse(&r.state)
            .ok_or_else(|| corrupt("a stored step state is outside the domain vocabulary"))?,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

pub(crate) struct AttemptRow {
    pub id: uuid::Uuid,
    pub step_id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    pub run_id: uuid::Uuid,
    pub logical_operation_id: uuid::Uuid,
    pub physical_attempt_id: uuid::Uuid,
    pub invocation_id: Option<uuid::Uuid>,
    pub predecessor_id: Option<uuid::Uuid>,
    pub version: i64,
    pub sequence: i64,
    pub state: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

fn attempt_from_row(r: AttemptRow) -> Result<StepAttempt, Failure> {
    Ok(StepAttempt {
        id: StepAttemptId::from_trusted_db_bytes(*r.id.as_bytes()),
        step_id: StepId::from_trusted_db_bytes(*r.step_id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        task_id: TaskId::from_trusted_db_bytes(*r.task_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
        logical_operation_id: LogicalOperationId(*r.logical_operation_id.as_bytes()),
        physical_attempt_id: PhysicalAttemptId(*r.physical_attempt_id.as_bytes()),
        invocation_id: r
            .invocation_id
            .map_or_else(InvocationId::default, |u| InvocationId(*u.as_bytes())),
        predecessor_id: r.predecessor_id.map_or_else(
            || StepAttemptId::from_trusted_db_bytes([0; 16]),
            |u| StepAttemptId::from_trusted_db_bytes(*u.as_bytes()),
        ),
        version: r.version,
        sequence: r.sequence,
        state: AttemptState::parse(&r.state)
            .ok_or_else(|| corrupt("a stored attempt state is outside the domain vocabulary"))?,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

pub(crate) struct ToolCallRow {
    pub id: uuid::Uuid,
    pub step_attempt_id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    pub run_id: uuid::Uuid,
    pub logical_operation_id: uuid::Uuid,
    pub version: i64,
    pub sequence: i64,
    pub state: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

fn tool_call_from_row(r: ToolCallRow) -> Result<ToolCall, Failure> {
    Ok(ToolCall {
        id: ToolCallId::from_trusted_db_bytes(*r.id.as_bytes()),
        step_attempt_id: StepAttemptId::from_trusted_db_bytes(*r.step_attempt_id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        task_id: TaskId::from_trusted_db_bytes(*r.task_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
        logical_operation_id: LogicalOperationId(*r.logical_operation_id.as_bytes()),
        version: r.version,
        sequence: r.sequence,
        state: ToolCallState::parse(&r.state)
            .ok_or_else(|| corrupt("a stored tool call state is outside the domain vocabulary"))?,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

pub(crate) struct ToolAttemptRow {
    pub id: uuid::Uuid,
    pub tool_call_id: uuid::Uuid,
    pub step_attempt_id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    pub run_id: uuid::Uuid,
    pub logical_operation_id: uuid::Uuid,
    pub physical_attempt_id: uuid::Uuid,
    pub invocation_id: Option<uuid::Uuid>,
    pub predecessor_id: Option<uuid::Uuid>,
    pub version: i64,
    pub sequence: i64,
    pub state: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

fn tool_attempt_from_row(r: ToolAttemptRow) -> Result<ToolCallAttempt, Failure> {
    Ok(ToolCallAttempt {
        id: ToolCallAttemptId::from_trusted_db_bytes(*r.id.as_bytes()),
        tool_call_id: ToolCallId::from_trusted_db_bytes(*r.tool_call_id.as_bytes()),
        step_attempt_id: StepAttemptId::from_trusted_db_bytes(*r.step_attempt_id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        task_id: TaskId::from_trusted_db_bytes(*r.task_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
        logical_operation_id: LogicalOperationId(*r.logical_operation_id.as_bytes()),
        physical_attempt_id: PhysicalAttemptId(*r.physical_attempt_id.as_bytes()),
        invocation_id: r
            .invocation_id
            .map_or_else(InvocationId::default, |u| InvocationId(*u.as_bytes())),
        predecessor_id: r.predecessor_id.map_or_else(
            || ToolCallAttemptId::from_trusted_db_bytes([0; 16]),
            |u| ToolCallAttemptId::from_trusted_db_bytes(*u.as_bytes()),
        ),
        version: r.version,
        sequence: r.sequence,
        state: AttemptState::parse(&r.state).ok_or_else(|| {
            corrupt("a stored tool attempt state is outside the domain vocabulary")
        })?,
        created_at: r.created_at,
        updated_at: r.updated_at,
    })
}

pub(crate) struct ApprovalRow {
    pub id: uuid::Uuid,
    pub workspace_id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    pub run_id: uuid::Uuid,
    pub step_id: uuid::Uuid,
    pub state: String,
    pub subject_version: i64,
    pub logical_operation_id: uuid::Uuid,
    pub operation_digest: Vec<u8>,
    pub expected_step_version: i64,
    pub decision_actor: Option<String>,
    pub decision_reason: Option<String>,
    pub decision_id: Option<uuid::Uuid>,
    pub predecessor_approval_id: Option<uuid::Uuid>,
    pub version: i64,
    pub recorded_at: OffsetDateTime,
    pub decided_at: Option<OffsetDateTime>,
}

fn approval_from_row(r: ApprovalRow) -> Result<Approval, Failure> {
    let digest: [u8; 32] = r
        .operation_digest
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("a stored approval operation_digest is not 32 bytes"))?;
    Ok(Approval {
        id: ApprovalId::from_trusted_db_bytes(*r.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        task_id: TaskId::from_trusted_db_bytes(*r.task_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
        step_id: StepId::from_trusted_db_bytes(*r.step_id.as_bytes()),
        state: ApprovalState::parse(&r.state)
            .ok_or_else(|| corrupt("a stored approval state is outside the domain vocabulary"))?,
        subject: ApprovalSubject {
            version: r.subject_version,
            logical_operation_id: LogicalOperationId(*r.logical_operation_id.as_bytes()),
            operation_digest: digest,
            expected_step_version: r.expected_step_version,
        },
        actor: r.decision_actor.unwrap_or_default(),
        reason_code: r.decision_reason.unwrap_or_default(),
        decision_id: r.decision_id.map_or([0; 16], |u| *u.as_bytes()),
        predecessor_id: r.predecessor_approval_id.map_or_else(
            || ApprovalId::from_trusted_db_bytes([0; 16]),
            |u| ApprovalId::from_trusted_db_bytes(*u.as_bytes()),
        ),
        version: r.version,
        recorded_at: r.recorded_at,
        decided_at: r.decided_at.unwrap_or(central_execution::domain::ZERO_TIME),
    })
}

/// Upstream `persistedLease` — the verifier never leaves the adapter.
pub(crate) struct PersistedLease {
    pub verifier: [u8; 32],
    pub generation: i64,
    pub expires_at: OffsetDateTime,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
}

// ---------------------------------------------------------------------------
// Task / run reads — reuse the task adapter's projections verbatim.
// ---------------------------------------------------------------------------

pub(crate) async fn read_task(
    tx: &mut Transaction<'_, Postgres>,
    workspace: WorkspaceId,
    id: TaskId,
    for_update: bool,
) -> Result<central_task::domain::Task, Failure> {
    let ws = uuid_of(workspace.as_bytes());
    let task = uuid_of(id.as_bytes());
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
            ws,
            task,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read task for update")?
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
            ws,
            task,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read task")?
    };
    row.ok_or_else(|| conflict("TASK_NOT_FOUND"))
        .and_then(task_from_row)
}

pub(crate) async fn read_run(
    tx: &mut Transaction<'_, Postgres>,
    workspace: WorkspaceId,
    task: TaskId,
    id: RunId,
    for_update: bool,
) -> Result<central_task::domain::Run, Failure> {
    let ws = uuid_of(workspace.as_bytes());
    let task_id = uuid_of(task.as_bytes());
    let run = uuid_of(id.as_bytes());
    let row = if for_update {
        sqlx::query_as!(
            RunRow,
            "SELECT id, workspace_id, task_id, version, status, run_index, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             COALESCE(ownership_token, '') AS \"ownership_token!\", \
             run_key, request_fingerprint, created_at, updated_at \
             FROM central.runs \
             WHERE workspace_id = $1 AND task_id = $2 AND id = $3 FOR UPDATE",
            ws,
            task_id,
            run,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read run for update")?
    } else {
        sqlx::query_as!(
            RunRow,
            "SELECT id, workspace_id, task_id, version, status, run_index, \
             COALESCE(waiting_reason, '') AS \"waiting_reason!\", \
             COALESCE(failure_reason, '') AS \"failure_reason!\", \
             COALESCE(ownership_token, '') AS \"ownership_token!\", \
             run_key, request_fingerprint, created_at, updated_at \
             FROM central.runs \
             WHERE workspace_id = $1 AND task_id = $2 AND id = $3",
            ws,
            task_id,
            run,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read run")?
    };
    row.ok_or_else(|| conflict("RUN_NOT_FOUND"))
        .and_then(run_from_row)
}

// ---------------------------------------------------------------------------
// Step / attempt reads.
// ---------------------------------------------------------------------------

pub(crate) async fn read_step(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
    tid: TaskId,
    rid: RunId,
    id: StepId,
    for_update: bool,
) -> Result<Step, Failure> {
    let (w, t, r, s) = (
        uuid_of(ws.as_bytes()),
        uuid_of(tid.as_bytes()),
        uuid_of(rid.as_bytes()),
        uuid_of(id.as_bytes()),
    );
    let row = if for_update {
        sqlx::query_as!(
            StepRow,
            "SELECT id, workspace_id, task_id, run_id, version, sequence, state, \
             created_at, updated_at FROM central.steps \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 AND id = $4 \
             FOR UPDATE",
            w,
            t,
            r,
            s,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read step for update")?
    } else {
        sqlx::query_as!(
            StepRow,
            "SELECT id, workspace_id, task_id, run_id, version, sequence, state, \
             created_at, updated_at FROM central.steps \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 AND id = $4",
            w,
            t,
            r,
            s,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read step")?
    };
    row.ok_or_else(|| conflict("STATE_SCOPE_MISMATCH"))
        .and_then(step_from_row)
}

pub(crate) async fn read_attempt(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
    tid: TaskId,
    rid: RunId,
    sid: StepId,
    id: StepAttemptId,
    for_update: bool,
) -> Result<StepAttempt, Failure> {
    let (w, t, r, s, a) = (
        uuid_of(ws.as_bytes()),
        uuid_of(tid.as_bytes()),
        uuid_of(rid.as_bytes()),
        uuid_of(sid.as_bytes()),
        uuid_of(id.as_bytes()),
    );
    let row = if for_update {
        sqlx::query_as!(
            AttemptRow,
            "SELECT id, step_id, workspace_id, task_id, run_id, \
             logical_operation_id, physical_attempt_id, invocation_id, \
             predecessor_id, version, sequence, state, created_at, updated_at \
             FROM central.step_attempts \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5 FOR UPDATE",
            w,
            t,
            r,
            s,
            a,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read attempt for update")?
    } else {
        sqlx::query_as!(
            AttemptRow,
            "SELECT id, step_id, workspace_id, task_id, run_id, \
             logical_operation_id, physical_attempt_id, invocation_id, \
             predecessor_id, version, sequence, state, created_at, updated_at \
             FROM central.step_attempts \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5",
            w,
            t,
            r,
            s,
            a,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read attempt")?
    };
    row.ok_or_else(|| conflict("STATE_SCOPE_MISMATCH"))
        .and_then(attempt_from_row)
}

pub(crate) async fn read_tool_calls(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
    attempt: StepAttemptId,
) -> Result<Vec<ToolCall>, Failure> {
    let rows = sqlx::query_as!(
        ToolCallRow,
        "SELECT id, step_attempt_id, workspace_id, task_id, run_id, \
         logical_operation_id, version, sequence, state, created_at, updated_at \
         FROM central.tool_calls \
         WHERE workspace_id = $1 AND step_attempt_id = $2 \
         ORDER BY sequence, id LIMIT 100",
        uuid_of(ws.as_bytes()),
        uuid_of(attempt.as_bytes()),
    )
    .fetch_all(&mut **tx)
    .await
    .ctx("execution: read tool calls")?;
    rows.into_iter().map(tool_call_from_row).collect()
}

pub(crate) async fn read_tool_attempts(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
    parent: StepAttemptId,
) -> Result<Vec<ToolCallAttempt>, Failure> {
    let rows = sqlx::query_as!(
        ToolAttemptRow,
        "SELECT id, tool_call_id, step_attempt_id, workspace_id, task_id, run_id, \
         logical_operation_id, physical_attempt_id, invocation_id, predecessor_id, \
         version, sequence, state, created_at, updated_at \
         FROM central.tool_call_attempts \
         WHERE workspace_id = $1 AND step_attempt_id = $2 \
         ORDER BY sequence, id LIMIT 100",
        uuid_of(ws.as_bytes()),
        uuid_of(parent.as_bytes()),
    )
    .fetch_all(&mut **tx)
    .await
    .ctx("execution: read tool attempts")?;
    rows.into_iter().map(tool_attempt_from_row).collect()
}

/// `readLease` — the credential-free projection; expired rows still read.
pub(crate) async fn read_lease(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
    run: RunId,
    for_update: bool,
) -> Result<Lease, Failure> {
    struct LeaseRow {
        fencing_generation: i64,
        lease_expires_at: OffsetDateTime,
    }
    let (w, r) = (uuid_of(ws.as_bytes()), uuid_of(run.as_bytes()));
    let row = if for_update {
        sqlx::query_as!(
            LeaseRow,
            "SELECT fencing_generation, lease_expires_at FROM central.execution_ownership \
             WHERE workspace_id = $1 AND run_id = $2 FOR UPDATE",
            w,
            r,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read lease for update")?
    } else {
        sqlx::query_as!(
            LeaseRow,
            "SELECT fencing_generation, lease_expires_at FROM central.execution_ownership \
             WHERE workspace_id = $1 AND run_id = $2",
            w,
            r,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read lease")?
    };
    Ok(row
        .map(|l| Lease {
            workspace_id: ws,
            run_id: run,
            credential: Default::default(),
            generation: l.fencing_generation,
            expires_at: l.lease_expires_at,
            updated_at: l.lease_expires_at,
        })
        .unwrap_or_else(|| Lease {
            workspace_id: ws,
            run_id: run,
            credential: Default::default(),
            generation: 0,
            expires_at: central_execution::domain::ZERO_TIME,
            updated_at: central_execution::domain::ZERO_TIME,
        }))
}

/// `readPersistedLeaseForUpdate` — the verifier-bearing lock row used
/// by the fenced paths; `None` means no ownership row exists.
pub(crate) async fn read_persisted_lease_for_update(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
    run: RunId,
) -> Result<Option<PersistedLease>, Failure> {
    struct Row {
        lease_token_hash: Vec<u8>,
        fencing_generation: i64,
        lease_expires_at: OffsetDateTime,
        claimed_step_id: Option<uuid::Uuid>,
        claimed_step_attempt_id: Option<uuid::Uuid>,
    }
    let row = sqlx::query_as!(
        Row,
        "SELECT lease_token_hash, fencing_generation, lease_expires_at, \
         claimed_step_id, claimed_step_attempt_id \
         FROM central.execution_ownership \
         WHERE workspace_id = $1 AND run_id = $2 FOR UPDATE",
        uuid_of(ws.as_bytes()),
        uuid_of(run.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: read persisted lease")?;
    let Some(row) = row else { return Ok(None) };
    let verifier: [u8; 32] = row
        .lease_token_hash
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("a stored lease verifier is not 32 bytes"))?;
    Ok(Some(PersistedLease {
        verifier,
        generation: row.fencing_generation,
        expires_at: row.lease_expires_at,
        step_id: row.claimed_step_id.map_or_else(
            || StepId::from_trusted_db_bytes([0; 16]),
            |u| StepId::from_trusted_db_bytes(*u.as_bytes()),
        ),
        attempt_id: row.claimed_step_attempt_id.map_or_else(
            || StepAttemptId::from_trusted_db_bytes([0; 16]),
            |u| StepAttemptId::from_trusted_db_bytes(*u.as_bytes()),
        ),
    }))
}

/// `readApproval` — the latest execution-kind approval for the step.
pub(crate) async fn read_approval(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
    tid: TaskId,
    rid: RunId,
    sid: StepId,
) -> Result<Option<Approval>, Failure> {
    let row = sqlx::query_as!(
        ApprovalRow,
        "SELECT id AS \"id!\", workspace_id AS \"workspace_id!\", \
         task_id AS \"task_id!\", run_id AS \"run_id!\", step_id AS \"step_id!\", \
         state AS \"state!\", subject_version AS \"subject_version!\", \
         logical_operation_id AS \"logical_operation_id!\", \
         operation_digest AS \"operation_digest!\", \
         expected_step_version AS \"expected_step_version!\", \
         decision_actor, decision_reason, decision_id, \
         predecessor_approval_id, version AS \"version!\", \
         recorded_at AS \"recorded_at!\", decided_at \
         FROM central.approvals \
         WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 AND step_id = $4 \
         AND approval_kind = 'execution' \
         ORDER BY recorded_at DESC, id DESC LIMIT 1",
        uuid_of(ws.as_bytes()),
        uuid_of(tid.as_bytes()),
        uuid_of(rid.as_bytes()),
        uuid_of(sid.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: read approval")?;
    row.map(approval_from_row).transpose()
}

// ---------------------------------------------------------------------------
// Event counter + recovery epoch/workspace readers.
// ---------------------------------------------------------------------------

/// `queryLockEventCounter` — upsert + row lock, the first lock in the
/// documented order (and the workspace existence proof).
pub(crate) async fn lock_event_counter(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
) -> Result<i64, Failure> {
    let row = sqlx::query!(
        "INSERT INTO central.workspace_event_counters (workspace_id, last_event_sequence) \
         VALUES ($1, 0) \
         ON CONFLICT (workspace_id) DO UPDATE \
         SET last_event_sequence = central.workspace_event_counters.last_event_sequence \
         RETURNING last_event_sequence",
        uuid_of(ws.as_bytes()),
    )
    .fetch_one(&mut **tx)
    .await
    .ctx("execution: lock workspace event counter")?;
    Ok(row.last_event_sequence)
}

/// `queryReserveEventSequence` — bumps the counter inside the lock.
pub(crate) async fn reserve_event_sequence(
    tx: &mut Transaction<'_, Postgres>,
    ws: WorkspaceId,
) -> Result<i64, Failure> {
    let row = sqlx::query!(
        "UPDATE central.workspace_event_counters \
         SET last_event_sequence = last_event_sequence + 1 \
         WHERE workspace_id = $1 \
         RETURNING last_event_sequence",
        uuid_of(ws.as_bytes()),
    )
    .fetch_one(&mut **tx)
    .await
    .ctx("execution: reserve event sequence")?;
    Ok(row.last_event_sequence)
}

/// `queryDBNow` — `clock_timestamp()` for lease expiry comparisons.
pub(crate) async fn db_now(tx: &mut Transaction<'_, Postgres>) -> Result<OffsetDateTime, Failure> {
    let row = sqlx::query!("SELECT clock_timestamp() AS \"now!\"")
        .fetch_one(&mut **tx)
        .await
        .ctx("execution: read database time")?;
    Ok(row.now)
}

struct EpochRow {
    epoch_generation: i64,
    coordinator_fence: i64,
    state: String,
    snapshot_at: OffsetDateTime,
    scheduler_cursor: Option<uuid::Uuid>,
    workspace_count: i64,
    processed_count: i64,
    retry_attempt: i64,
}

fn epoch_from_row(r: EpochRow) -> RecoveryEpoch {
    RecoveryEpoch {
        generation: r.epoch_generation,
        coordinator_fence: central_execution::resume::RecoveryCoordinatorFence {
            generation: r.coordinator_fence,
        },
        state: match r.state.as_str() {
            "open" => RecoveryEpochState::RecoveryEpochOpen,
            "running" => RecoveryEpochState::RecoveryEpochRunning,
            "degraded" => RecoveryEpochState::RecoveryEpochDegraded,
            "completed" => RecoveryEpochState::RecoveryEpochCompleted,
            _ => RecoveryEpochState::RecoveryEpochFailed,
        },
        scheduler_cursor: r.scheduler_cursor.map_or_else(
            || WorkspaceId::from_trusted_db_bytes([0; 16]),
            |u| WorkspaceId::from_trusted_db_bytes(*u.as_bytes()),
        ),
        workspace_count: r.workspace_count,
        processed_count: r.processed_count,
        // Upstream ClaimCycle mirrors ProcessedCount durably.
        claim_cycle: r.processed_count,
        retry_attempt: r.retry_attempt,
        snapshot_at: r.snapshot_at,
    }
}

/// `queryLockRecoveryEpochForClaim` — same lock but admits 'completed'.
pub(crate) async fn read_locked_recovery_epoch_for_claim(
    tx: &mut Transaction<'_, Postgres>,
    generation: i64,
    fence: i64,
    domain: &str,
) -> Result<RecoveryEpoch, Failure> {
    let row = sqlx::query_as!(
        EpochRow,
        "SELECT epoch_generation, coordinator_fence, state, snapshot_at, \
         scheduler_cursor, workspace_count, processed_count, retry_attempt \
         FROM central.recovery_epochs \
         WHERE epoch_generation = $1 AND coordinator_fence = $2 \
         AND coordinator_domain = $3 FOR UPDATE",
        generation,
        fence,
        domain,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: lock recovery epoch for claim")?;
    row.map(epoch_from_row)
        .ok_or_else(|| conflict("STALE_RECOVERY_FENCE"))
}

/// `queryFindIncompleteRecoveryEpoch` — the latest non-completed epoch
/// for the domain; `None` when none exists (not an error).
pub(crate) async fn read_incomplete_recovery_epoch(
    tx: &mut Transaction<'_, Postgres>,
    domain: &str,
) -> Result<Option<RecoveryEpoch>, Failure> {
    let row = sqlx::query_as!(
        EpochRow,
        "SELECT epoch_generation, coordinator_fence, state, snapshot_at, \
         scheduler_cursor, workspace_count, processed_count, retry_attempt \
         FROM central.recovery_epochs \
         WHERE coordinator_domain = $1 AND state IN ('open','running','degraded','failed') \
         ORDER BY epoch_generation DESC LIMIT 1 FOR UPDATE",
        domain,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: find incomplete recovery epoch")?;
    Ok(row.map(epoch_from_row))
}

/// `queryAssertRecoveryEpochDomain` — existence check under the fence.
pub(crate) async fn assert_recovery_epoch_domain(
    tx: &mut Transaction<'_, Postgres>,
    generation: i64,
    fence: i64,
    domain: &str,
) -> Result<(), Failure> {
    let row = sqlx::query!(
        "SELECT 1 AS one FROM central.recovery_epochs \
         WHERE epoch_generation = $1 AND coordinator_fence = $2 AND coordinator_domain = $3",
        generation,
        fence,
        domain,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("execution: assert recovery epoch domain")?;
    if row.is_none() {
        return Err(conflict("STALE_RECOVERY_FENCE"));
    }
    Ok(())
}

struct WorkRow {
    workspace_id: uuid::Uuid,
    delivery_state: String,
    watermark_created_at: OffsetDateTime,
    watermark_run_id: uuid::Uuid,
    cursor_created_at: OffsetDateTime,
    cursor_run_id: Option<uuid::Uuid>,
}

fn work_from_row(r: WorkRow, generation: i64) -> RecoveryWorkspaceWork {
    RecoveryWorkspaceWork {
        epoch_generation: generation,
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        state: match r.delivery_state.as_str() {
            "claimed" => resume::RecoveryWorkspaceState::RecoveryWorkspaceClaimed,
            "completed" => resume::RecoveryWorkspaceState::RecoveryWorkspaceCompleted,
            "failed" => resume::RecoveryWorkspaceState::RecoveryWorkspaceFailed,
            _ => resume::RecoveryWorkspaceState::RecoveryWorkspacePending,
        },
        watermark_created_at: r.watermark_created_at,
        watermark_run_id: RunId::from_trusted_db_bytes(*r.watermark_run_id.as_bytes()),
        cursor_created_at: r.cursor_created_at,
        cursor_run_id: r.cursor_run_id.map_or_else(
            || RunId::from_trusted_db_bytes([0; 16]),
            |u| RunId::from_trusted_db_bytes(*u.as_bytes()),
        ),
        scanned_count: 0,
        reconciled_count: 0,
        retry_attempt: 0,
        failure_class: String::new(),
        failure_reason: String::new(),
    }
}

/// `selectRecoveryWorkspaceBatch` — round-robin over pending work from
/// the epoch's scheduler cursor, wrapping once.
pub(crate) async fn select_recovery_workspace_batch(
    tx: &mut Transaction<'_, Postgres>,
    generation: i64,
    cursor: WorkspaceId,
    limit: i64,
    domain: &str,
) -> Result<Vec<RecoveryWorkspaceWork>, Failure> {
    if limit <= 0 {
        return Ok(Vec::new());
    }
    if cursor.is_nil() {
        let rows = sqlx::query_as!(
            WorkRow,
            "SELECT work.workspace_id, work.delivery_state, work.watermark_created_at, \
             work.watermark_run_id, \
             COALESCE(work.cursor_created_at, work.watermark_created_at) AS \"cursor_created_at!\", \
             work.cursor_run_id \
             FROM central.recovery_epoch_workspaces AS work \
             JOIN central.recovery_epochs AS epoch \
               ON epoch.epoch_generation = work.epoch_generation \
              AND epoch.coordinator_domain = $3 \
             WHERE work.epoch_generation = $1 AND work.delivery_state = 'pending' \
               AND (work.retry_not_before IS NULL OR work.retry_not_before <= clock_timestamp()) \
             ORDER BY work.workspace_id LIMIT $2 FOR UPDATE OF work SKIP LOCKED",
            generation,
            limit,
            domain,
        )
        .fetch_all(&mut **tx)
        .await
        .ctx("execution: select recovery workspaces")?;
        return Ok(rows
            .into_iter()
            .map(|r| work_from_row(r, generation))
            .collect());
    }
    let cur = uuid_of(cursor.as_bytes());
    let mut rows = sqlx::query_as!(
        WorkRow,
        "SELECT work.workspace_id, work.delivery_state, work.watermark_created_at, \
         work.watermark_run_id, \
         COALESCE(work.cursor_created_at, work.watermark_created_at) AS \"cursor_created_at!\", \
         work.cursor_run_id \
         FROM central.recovery_epoch_workspaces AS work \
         JOIN central.recovery_epochs AS epoch \
           ON epoch.epoch_generation = work.epoch_generation \
          AND epoch.coordinator_domain = $4 \
         WHERE work.epoch_generation = $1 AND work.delivery_state = 'pending' \
           AND (work.retry_not_before IS NULL OR work.retry_not_before <= clock_timestamp()) \
           AND work.workspace_id > $2 \
         ORDER BY work.workspace_id LIMIT $3 FOR UPDATE OF work SKIP LOCKED",
        generation,
        cur,
        limit,
        domain,
    )
    .fetch_all(&mut **tx)
    .await
    .ctx("execution: select recovery workspaces after cursor")?;
    if rows.len() as i64 == limit {
        return Ok(rows
            .into_iter()
            .map(|r| work_from_row(r, generation))
            .collect());
    }
    let wrapped = sqlx::query_as!(
        WorkRow,
        "SELECT work.workspace_id, work.delivery_state, work.watermark_created_at, \
         work.watermark_run_id, \
         COALESCE(work.cursor_created_at, work.watermark_created_at) AS \"cursor_created_at!\", \
         work.cursor_run_id \
         FROM central.recovery_epoch_workspaces AS work \
         JOIN central.recovery_epochs AS epoch \
           ON epoch.epoch_generation = work.epoch_generation \
          AND epoch.coordinator_domain = $4 \
         WHERE work.epoch_generation = $1 AND work.delivery_state = 'pending' \
           AND (work.retry_not_before IS NULL OR work.retry_not_before <= clock_timestamp()) \
           AND work.workspace_id <= $2 \
         ORDER BY work.workspace_id LIMIT $3 FOR UPDATE OF work SKIP LOCKED",
        generation,
        cur,
        limit - rows.len() as i64,
        domain,
    )
    .fetch_all(&mut **tx)
    .await
    .ctx("execution: select recovery workspaces before cursor")?;
    rows.extend(wrapped);
    Ok(rows
        .into_iter()
        .map(|r| work_from_row(r, generation))
        .collect())
}

// ---------------------------------------------------------------------------
// RecoveryClaimabilityReader — the durable recovery admission gate.
// ---------------------------------------------------------------------------

struct ClaimabilityRow {
    epoch_generation: i64,
    coordinator_fence: i64,
    state: String,
    delivery_state: String,
    watermark_created_at: OffsetDateTime,
    watermark_run_id: uuid::Uuid,
    created_at: OffsetDateTime,
    run_id: uuid::Uuid,
    reconciled_epoch: i64,
}

impl RecoveryClaimabilityReader for Store {
    /// `RecoveryClaimability` — the latest non-completed epoch covering
    /// the workspace delegates the bar to the domain evaluator; no row
    /// means no epoch ever covered the workspace (claimable).
    async fn recovery_claimability(
        &self,
        scope: central_execution::domain::TrustedScope,
        task_id: TaskId,
        run_id: RunId,
    ) -> Result<Claimability, Failure> {
        if scope.workspace_id.is_nil() || task_id.is_nil() || run_id.is_nil() {
            return Err(invalid("INVALID_RECOVERY_CLAIMABILITY"));
        }
        let mut tx = super::begin(&self.pool).await?;
        let row = sqlx::query_as!(
            ClaimabilityRow,
            "SELECT e.epoch_generation, e.coordinator_fence, e.state, w.delivery_state, \
             w.watermark_created_at, w.watermark_run_id, \
             r.created_at, r.id AS run_id, r.reconciled_epoch \
             FROM central.runs r \
             JOIN central.recovery_epoch_workspaces w ON w.workspace_id = r.workspace_id \
             JOIN central.recovery_epochs e ON e.epoch_generation = w.epoch_generation \
             WHERE r.workspace_id = $1 AND r.task_id = $2 AND r.id = $3 \
               AND e.state <> 'completed' \
             ORDER BY e.epoch_generation DESC LIMIT 1",
            uuid_of(scope.workspace_id.as_bytes()),
            uuid_of(task_id.as_bytes()),
            uuid_of(run_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: read recovery claimability")?;
        let Some(row) = row else {
            tx.commit()
                .await
                .ctx("execution: commit recovery claimability")?;
            return Ok(Claimability {
                claimable: true,
                epoch_generation: 0,
                reason: String::new(),
            });
        };
        let epoch = RecoveryEpoch {
            generation: row.epoch_generation,
            coordinator_fence: central_execution::resume::RecoveryCoordinatorFence {
                generation: row.coordinator_fence,
            },
            state: match row.state.as_str() {
                "open" => RecoveryEpochState::RecoveryEpochOpen,
                "running" => RecoveryEpochState::RecoveryEpochRunning,
                "degraded" => RecoveryEpochState::RecoveryEpochDegraded,
                "completed" => RecoveryEpochState::RecoveryEpochCompleted,
                _ => RecoveryEpochState::RecoveryEpochFailed,
            },
            scheduler_cursor: WorkspaceId::from_trusted_db_bytes([0; 16]),
            workspace_count: 0,
            processed_count: 0,
            claim_cycle: 0,
            retry_attempt: 0,
            snapshot_at: central_execution::domain::ZERO_TIME,
        };
        let work = RecoveryWorkspaceWork {
            epoch_generation: row.epoch_generation,
            workspace_id: scope.workspace_id,
            state: match row.delivery_state.as_str() {
                "claimed" => resume::RecoveryWorkspaceState::RecoveryWorkspaceClaimed,
                "completed" => resume::RecoveryWorkspaceState::RecoveryWorkspaceCompleted,
                "failed" => resume::RecoveryWorkspaceState::RecoveryWorkspaceFailed,
                _ => resume::RecoveryWorkspaceState::RecoveryWorkspacePending,
            },
            watermark_created_at: row.watermark_created_at,
            watermark_run_id: RunId::from_trusted_db_bytes(*row.watermark_run_id.as_bytes()),
            cursor_created_at: central_execution::domain::ZERO_TIME,
            cursor_run_id: RunId::from_trusted_db_bytes([0; 16]),
            scanned_count: 0,
            reconciled_count: 0,
            retry_attempt: 0,
            failure_class: String::new(),
            failure_reason: String::new(),
        };
        let decision = resume::recovery_claimability(
            &epoch,
            &work,
            row.created_at,
            RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
            row.reconciled_epoch,
        );
        tx.commit()
            .await
            .ctx("execution: commit recovery claimability")?;
        Ok(decision)
    }
}
