//! Shared row projections, reconstruction and encoding helpers for the
//! harness stores — the port of upstream `queries.go`'s
//! `attemptColumns`/`approvalColumns` select lists,
//! `scanAttempt`/`scanApproval`, `attemptArgs`/`budgetArgs`/`eventArgs`,
//! `storedTime`/`nullText`, and the invalid-text SQLSTATE mapping.
//!
//! uuid columns decode as `Uuid` (the adapter's convention), not
//! upstream's `::text` + `ParseXID`; a row the domain refuses is
//! `pg_data_corrupt`/`internal`, not the upstream `ErrInvalid*` sentinel.

use central_foundation::failure::Failure;
use central_foundation::identity::{
    HarnessAttemptId, HarnessPermissionApprovalId, RunId, TaskId, WorkspaceId,
};
use central_harness::approval::{ApprovalState, InputMac, PermissionApproval};
use central_harness::attempt::Attempt;
use central_harness::budget::Budget;
use central_harness::domain::{
    Fence, Kind, PermissionPolicy, Resolution, ResolutionKind, State, Terminal, TerminalStatus,
    Workspace, codes,
};
use central_harness::event::{EventKind, PermissionOutcome, ToolStatus, Usage, UsageScope};
use central_harness::record::EventRecord;
use time::{Duration, OffsetDateTime};

use crate::store_support::{PG_DATA_CORRUPT, i64_as_u64, u64_as_i64};

/// Upstream `constraintLiveAttempt` — the partial unique index enforcing
/// one live attempt per run (migration b30).
pub(crate) const CONSTRAINT_LIVE_ATTEMPT: &str = "harness_attempts_one_live_per_run_idx";

/// A stored row the domain would never write — corrupt durable state,
/// `internal`, never a caller sentinel.
pub(crate) fn corrupt(what: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, what)
}

/// Upstream `isInvalidValueSQLState`: a CHECK violation or one of the
/// invalid-text SQLSTATEs PostgreSQL raises for a string it cannot store
/// as text (an embedded NUL byte), not through a CHECK constraint.
pub(crate) fn is_invalid_value_sqlstate(code: &str) -> bool {
    matches!(code, "23514" | "22001" | "22021" | "22P05")
}

/// The database error's SQLSTATE, when the error carries one.
pub(crate) fn db_sqlstate(err: &sqlx::Error) -> Option<String> {
    if let sqlx::Error::Database(db) = err {
        db.code().map(|c| c.into_owned())
    } else {
        None
    }
}

/// The violated constraint's name, when the error carries one.
pub(crate) fn db_constraint(err: &sqlx::Error) -> Option<String> {
    if let sqlx::Error::Database(db) = err {
        db.constraint().map(str::to_owned)
    } else {
        None
    }
}

/// Upstream `storedTime`: PostgreSQL `timestamptz` keeps microsecond
/// precision — floor to whole microseconds, as Go's `Truncate` does.
pub(crate) fn stored_time(t: OffsetDateTime) -> OffsetDateTime {
    let nanos = t.unix_timestamp_nanos();
    OffsetDateTime::from_unix_timestamp_nanos(nanos.div_euclid(1_000) * 1_000).unwrap_or(t)
}

/// Upstream `nullText`: `""` binds SQL `NULL`.
pub(crate) fn nonempty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// The `bigint` bind for a `u64` seq — `u64_as_i64` under the event
/// sentinel (upstream refuses `seq > math.MaxInt64` on both the attempt
/// and the record).
pub(crate) fn seq_as_i64(seq: u64) -> Result<i64, Failure> {
    u64_as_i64(seq, codes::INVALID_EVENT)
}

/// The `bigint` bind for the attempt cursor — `INVALID_ATTEMPT`, as
/// upstream `attemptArgs`.
pub(crate) fn cursor_as_i64(seq: u64) -> Result<i64, Failure> {
    u64_as_i64(seq, codes::INVALID_ATTEMPT)
}

/// Upstream `budgetArgs`' whole-seconds rule: the wall clock is stored
/// in whole seconds, so a budget that would not read back equal is
/// refused rather than rounded.
pub(crate) fn budget_wall_clock_seconds(b: &Budget) -> Result<i32, Failure> {
    if b.wall_clock.whole_nanoseconds() % 1_000_000_000 != 0 {
        return Err(Failure::invalid(
            codes::INVALID_ATTEMPT,
            "budget wall clock must be whole seconds",
        ));
    }
    i32::try_from(b.wall_clock.whole_seconds()).map_err(|_| {
        Failure::invalid(
            codes::INVALID_ATTEMPT,
            "budget wall clock exceeds the stored range",
        )
    })
}

// ---------------------------------------------------------------------------
// attemptColumns — the 38-column select list every attempt read scans
// (compile-checked literals inline at each call site; upstream builds
// them by concatenating `attemptColumns`). Nullable text/uuid columns
// read as Option<> and rebuild as "" / None, the domain's "absent"
// values.
// ---------------------------------------------------------------------------

pub(crate) struct AttemptRow {
    pub workspace_id: uuid::Uuid,
    pub id: uuid::Uuid,
    pub run_id: uuid::Uuid,
    pub kind: String,
    pub adapter_version: String,
    pub harness_version: Option<String>,
    pub harness_session_id: Option<String>,
    pub resume_of: Option<uuid::Uuid>,
    pub resume_session_id: Option<String>,
    pub workspace_path: String,
    pub base_sha: String,
    pub permission: String,
    pub sandbox_scope_id: Option<String>,
    pub fence_generation: i64,
    pub version: i64,
    pub state: String,
    pub pending_permission: Option<String>,
    pub terminal_status: Option<String>,
    pub terminal_reason: Option<String>,
    pub terminal_exit_code: Option<i64>,
    pub resolution_kind: Option<String>,
    pub resolution_decided_by: Option<String>,
    pub ambiguity_reason: Option<String>,
    pub last_event_seq: i64,
    pub usage_tokens_in: i64,
    pub usage_tokens_out: i64,
    pub usage_cache_read: i64,
    pub usage_cache_write: i64,
    pub usage_cost_micro_usd: i64,
    pub usage_scope: Option<String>,
    pub usage_estimated: bool,
    pub prepared_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub ended_at: Option<OffsetDateTime>,
    pub budget_cost_micro_usd: i64,
    pub budget_wall_clock_seconds: i32,
    pub budget_cost_defaulted: bool,
    pub budget_wall_clock_defaulted: bool,
}

/// Upstream `scanAttempt`: rebuilds the aggregate and re-validates it;
/// a row the domain refuses is corrupt durable state.
pub(crate) fn attempt_from_row(r: AttemptRow) -> Result<Attempt, Failure> {
    let exit_code = match r.terminal_exit_code {
        Some(code) => Some(
            i32::try_from(code)
                .map_err(|_| corrupt("a stored terminal exit code is outside the i32 range"))?,
        ),
        None => None,
    };
    let a = Attempt {
        id: HarnessAttemptId::from_trusted_db_bytes(*r.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
        kind: Kind::new(r.kind),
        adapter_version: r.adapter_version,
        harness_version: r.harness_version.unwrap_or_default(),
        harness_session_id: r.harness_session_id.unwrap_or_default(),
        resume_of: r
            .resume_of
            .map(|u| HarnessAttemptId::from_trusted_db_bytes(*u.as_bytes())),
        resume_session_id: r.resume_session_id.unwrap_or_default(),
        workspace: Workspace {
            path: r.workspace_path,
            base_sha: r.base_sha,
        },
        permission: PermissionPolicy::parse(&r.permission),
        sandbox_scope_id: r.sandbox_scope_id.unwrap_or_default(),
        fence: Fence {
            generation: r.fence_generation,
        },
        version: r.version,
        state: State::parse(&r.state),
        pending_permission: r.pending_permission.unwrap_or_default(),
        terminal: Terminal {
            status: TerminalStatus::parse(r.terminal_status.as_deref().unwrap_or_default()),
            reason: r.terminal_reason.unwrap_or_default(),
            exit_code,
        },
        resolution: Resolution {
            kind: ResolutionKind::parse(r.resolution_kind.as_deref().unwrap_or_default()),
            decided_by: r.resolution_decided_by.unwrap_or_default(),
        },
        ambiguity_reason: r.ambiguity_reason.unwrap_or_default(),
        last_event_seq: i64_as_u64(r.last_event_seq, "event cursor")?,
        usage: Usage {
            tokens_in: r.usage_tokens_in,
            tokens_out: r.usage_tokens_out,
            cache_read: r.usage_cache_read,
            cache_write: r.usage_cache_write,
            cost_micro_usd: r.usage_cost_micro_usd,
            scope: UsageScope::parse(r.usage_scope.as_deref().unwrap_or_default()),
            estimated: r.usage_estimated,
        },
        budget: Budget {
            cost_micro_usd: r.budget_cost_micro_usd,
            wall_clock: Duration::seconds(i64::from(r.budget_wall_clock_seconds)),
            cost_defaulted: r.budget_cost_defaulted,
            wall_clock_defaulted: r.budget_wall_clock_defaulted,
        },
        prepared_at: r.prepared_at,
        updated_at: r.updated_at,
        ended_at: r.ended_at,
    };
    a.validate()
        .map_err(|_| corrupt("a stored harness attempt failed domain validation"))?;
    Ok(a)
}

// ---------------------------------------------------------------------------
// approvalColumns — the select list every approval read scans.
// ---------------------------------------------------------------------------

pub(crate) struct ApprovalRow {
    pub workspace_id: uuid::Uuid,
    pub id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
    pub task_id: uuid::Uuid,
    pub run_id: uuid::Uuid,
    pub request_id: String,
    pub tool_call_id: Option<String>,
    pub tool_name: String,
    pub input_mac: Vec<u8>,
    pub input_size: i64,
    pub state: String,
    pub requested_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub decided_at: Option<OffsetDateTime>,
    pub decided_by: Option<String>,
    pub version: i64,
}

/// Upstream `scanApproval`: rebuilds the approval and re-validates it;
/// a row the domain refuses is corrupt durable state.
pub(crate) fn approval_from_row(r: ApprovalRow) -> Result<PermissionApproval, Failure> {
    let mac: [u8; 32] = r
        .input_mac
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("a stored approval input MAC is not 32 bytes"))?;
    let a = PermissionApproval {
        id: HarnessPermissionApprovalId::from_trusted_db_bytes(*r.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*r.workspace_id.as_bytes()),
        attempt_id: HarnessAttemptId::from_trusted_db_bytes(*r.attempt_id.as_bytes()),
        task_id: TaskId::from_trusted_db_bytes(*r.task_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*r.run_id.as_bytes()),
        request_id: r.request_id,
        tool_call_id: r.tool_call_id.unwrap_or_default(),
        tool_name: r.tool_name,
        input_mac: InputMac(mac),
        input_size: r.input_size,
        state: ApprovalState::parse(&r.state),
        requested_at: r.requested_at,
        expires_at: r.expires_at,
        decided_at: r.decided_at,
        decided_by: r.decided_by.unwrap_or_default(),
        version: r.version,
    };
    a.validate()
        .map_err(|_| corrupt("a stored permission approval failed domain validation"))?;
    Ok(a)
}

// ---------------------------------------------------------------------------
// The event-record projection — bounded metadata only (a raw frame and
// every payload byte stay out of the table).
// ---------------------------------------------------------------------------

pub(crate) struct EventRecordRow {
    pub attempt_id: uuid::Uuid,
    pub seq: i64,
    pub kind: String,
    pub at: OffsetDateTime,
    pub harness_session_id: Option<String>,
    pub raw_size: i64,
    pub raw_sha256: Vec<u8>,
    pub tool_call_id: Option<String>,
    pub tool_name: Option<String>,
    pub tool_status: Option<String>,
    pub permission_request_id: Option<String>,
    pub permission_outcome: Option<String>,
    pub terminal_status: Option<String>,
}

pub(crate) fn event_record_from_row(r: EventRecordRow) -> Result<EventRecord, Failure> {
    let digest: [u8; 32] = r
        .raw_sha256
        .as_slice()
        .try_into()
        .map_err(|_| corrupt("a stored event digest is not 32 bytes"))?;
    let rec = EventRecord {
        attempt: HarnessAttemptId::from_trusted_db_bytes(*r.attempt_id.as_bytes()),
        seq: i64_as_u64(r.seq, "event seq")?,
        kind: EventKind::parse(&r.kind),
        at: r.at,
        harness_session_id: r.harness_session_id.unwrap_or_default(),
        raw_size: r.raw_size,
        raw_sha256: digest,
        tool_call_id: r.tool_call_id.unwrap_or_default(),
        tool_name: r.tool_name.unwrap_or_default(),
        tool_status: ToolStatus::parse(r.tool_status.as_deref().unwrap_or_default()),
        permission_request_id: r.permission_request_id.unwrap_or_default(),
        permission_outcome: PermissionOutcome::parse(
            r.permission_outcome.as_deref().unwrap_or_default(),
        ),
        terminal_status: TerminalStatus::parse(r.terminal_status.as_deref().unwrap_or_default()),
    };
    rec.validate()
        .map_err(|_| corrupt("a stored event record failed domain validation"))?;
    Ok(rec)
}
