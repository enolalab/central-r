//! PostgreSQL composite execution store — port of
//! `internal/adapter/postgres/execution/`.
//!
//! [`Store`] keeps every `sqlx` type inside the adapter and implements
//! the `central-execution` ports:
//!
//! - [`port::CompositeStore`] — the single fenced, idempotent commit
//!   seam (change set + task transition + events + outbox + receipt).
//! - [`port::ExecutionRead`] / [`port::CompositeExecutionStore`] —
//!   authoritative snapshot reads and pre-read receipt replay.
//! - [`port::LeaseCredentialValidator`] — bearer validation against
//!   the durable ownership row without exposing the verifier.
//! - [`port::RecoveryClaimabilityReader`] / [`port::RecoveryStore`] —
//!   the coordinator-fenced recovery epoch machinery.
//! - [`port::DispatchableRunReader`] — harness phase 3a decision 1.
//! - [`port::OutboxStore`] / [`port::B09EvidenceStore`] — the narrowed
//!   Rust-side publication and evidence-reference lanes.
//!
//! Lock ordering (postgresql-adapter-mapping §6, upstream `commitNew`):
//! `workspace_event_counters` → `tasks` → `runs` →
//! `execution_ownership` → `steps` → `step_attempts` → `tool_calls` →
//! `tool_call_attempts` → `approvals` → `checkpoints` → `events` →
//! `outbox` → `outbox_workspace_work` → `execution_command_receipts`.
//! Upstream's receipt advisory lock serializes the idempotency
//! identity before the counter lock, exactly as `Commit` does here.
//!
//! Upstream divergence notes:
//!
//! - `pgx` binds text that is cast to `uuid`; `sqlx` binds `Uuid`
//!   values directly. Upstream's `''` sentinel on `NULLIF($n,'')::uuid`
//!   parameters becomes a bound `Option<Uuid>` — `None` is SQL `NULL`.
//! - `LOCK TABLE` and `pg_advisory_xact_lock` are runtime statements
//!   (not leaf queries), so they use `sqlx::query`, consistent with
//!   `store_support::begin_tx`'s `set_config` precedent.
//! - The Rust port carries no `ReadB09Admission`, outbox scheduler
//!   claim, or metrics surface.

use central_execution::domain::{
    ExpectedVersions, InvocationId, LogicalOperationId, PhysicalAttemptId, ZERO_TIME,
};
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{ApprovalId, RunId, StepAttemptId, StepId, ToolCallAttemptId};
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

mod completion_receipt;
mod dispatchable;
mod failed_recovery_workspaces;
mod queries;
mod reconciliation_attempt;
mod store;

pub(crate) use queries::{lock_event_counter, reserve_event_sequence};
pub use store::Store;
pub(crate) use store::go_rfc3339_local;

use crate::error::classify_sqlx;
use crate::store_support::{PG_DATA_CORRUPT, uuid_of};

// ---------------------------------------------------------------------------
// Failure constructors — the adapter mirrors upstream `failure(Class, Reason)`
// with FailureKind::{Invalid, Conflict, Denied} plus a corruption classifier.
// ---------------------------------------------------------------------------

pub(crate) fn failure(kind: FailureKind, code: &'static str) -> Failure {
    Failure::new(kind, code, "execution store refused")
}

pub(crate) fn invalid(code: &'static str) -> Failure {
    failure(FailureKind::Invalid, code)
}

pub(crate) fn conflict(code: &'static str) -> Failure {
    failure(FailureKind::Conflict, code)
}

pub(crate) fn denied(code: &'static str) -> Failure {
    failure(FailureKind::Denied, code)
}

pub(crate) fn corrupt(what: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, what)
}

// ---------------------------------------------------------------------------
// Constants (upstream store.go const block + recovery vocabulary).
// ---------------------------------------------------------------------------

/// `resumeReconciledAttemptScope` — harness phase 3g decision 2. The
/// reconciled-attempt commit scope; its change-set exceptions apply to
/// this scope only (upstream `resumeReconciledAttemptScope`).
pub(crate) const RESUME_ATTEMPT_SCOPE: &str = "execution.resume_reconciled_attempt";
/// The `commandScope` `ResumeRecoveryEpoch` binds its receipt identity
/// to (upstream's function-local `commandScope`, *not* a commit scope).
pub(crate) const RESUME_SCOPE: &str = "execution.resume_recovery";
/// The deployment-wide recovery coordinator domain token.
pub(crate) const RECOVERY_DOMAIN: &str = "central.execution.recovery.v1";
/// Recovery scan page size (upstream `scanRecoveryWorkspaceBatch(ctx, req, 100)`).
pub(crate) const RECOVERY_SCAN_BATCH: i64 = 100;
/// Bounded per-workspace scan retry budget (upstream `recoveryRetryLimit`).
pub(crate) const RECOVERY_RETRY_LIMIT: i64 = 5;
/// Coordinator-handle renewal cadence inside `waitForRecoveryRetry`.
pub(crate) const RECOVERY_RENEW_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Transaction openers.
// ---------------------------------------------------------------------------

/// Upstream `begin` — a bounded READ COMMITTED transaction with the
/// advisory timeouts plus `synchronous_commit = on`.
pub(crate) async fn begin(pool: &PgPool) -> Result<Transaction<'static, Postgres>, Failure> {
    let mut tx = crate::store_support::begin_tx(pool).await?;
    sqlx::query("SELECT set_config('synchronous_commit', 'on', true)")
        .execute(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    Ok(tx)
}

/// Upstream `beginRecovery` — REPEATABLE READ must be declared before
/// the first snapshot-taking statement, so this cannot reuse [`begin`]'s
/// order. The `recovery_epochs` table lock (SHARE ROW EXCLUSIVE) is the
/// publication boundary: claims take ROW EXCLUSIVE, which stays mutually
/// compatible while epoch publication snapshots the workspace rows.
pub(crate) async fn begin_recovery(
    pool: &PgPool,
) -> Result<Transaction<'static, Postgres>, Failure> {
    let mut tx = pool.begin().await.map_err(|e| classify_sqlx(&e))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("SET LOCAL lock_timeout = '2s'")
        .execute(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    sqlx::query("LOCK TABLE central.recovery_epochs IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .map_err(|e| classify_sqlx(&e))?;
    for (name, value) in [
        ("statement_timeout", "5s"),
        ("idle_in_transaction_session_timeout", "10s"),
        ("synchronous_commit", "on"),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(|e| classify_sqlx(&e))?;
    }
    Ok(tx)
}

/// Upstream `beginRecoveryScan` — identical to [`begin`]; kept as a
/// named boundary because upstream classifies its failures differently
/// (retryable scan failures vs. commit failures).
pub(crate) async fn begin_recovery_scan(
    pool: &PgPool,
) -> Result<Transaction<'static, Postgres>, Failure> {
    begin(pool).await
}

// ---------------------------------------------------------------------------
// CSPRNG lease/claim secrets (upstream `newLeaseSecret`).
// ---------------------------------------------------------------------------

/// Mints one raw 256-bit bearer + its SHA-256 verifier. Only the
/// verifier is ever persisted.
pub(crate) fn new_lease_secret() -> Result<([u8; 32], [u8; 32]), Failure> {
    let token: [u8; 32] = rand::random();
    Ok((token, sha256(&token)))
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    {
        use sha2::Digest;
        sha2::Sha256::digest(bytes)
    }
    .into()
}

/// Constant-time equality (upstream `subtle.ConstantTimeCompare`).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Identity → uuid bindings. `Option<Uuid>` binds SQL NULL; upstream's
// `zeroX(id)`/`uuidForX` sentinels collapse into these.
// ---------------------------------------------------------------------------

/// Logical/physical ids are opaque `[u8;16]` — same uuid representation.
pub(crate) fn uuid_for_logical(id: &LogicalOperationId) -> uuid::Uuid {
    uuid_of(&id.0)
}

pub(crate) fn uuid_for_physical(id: &PhysicalAttemptId) -> uuid::Uuid {
    uuid_of(&id.0)
}

pub(crate) fn uuid_for_invocation(id: &InvocationId) -> Option<uuid::Uuid> {
    (!id.is_nil()).then(|| uuid_of(&id.0))
}

/// Upstream `invocationGeneration` — generation 1 iff an invocation
/// identity exists; `None` binds NULL.
pub(crate) fn invocation_generation(id: &InvocationId) -> Option<i64> {
    (!id.is_nil()).then_some(1)
}

pub(crate) fn opt_step_uuid(id: StepId) -> Option<uuid::Uuid> {
    (!id.is_nil()).then(|| uuid_of(id.as_bytes()))
}

pub(crate) fn opt_attempt_uuid(id: StepAttemptId) -> Option<uuid::Uuid> {
    (!id.is_nil()).then(|| uuid_of(id.as_bytes()))
}

pub(crate) fn opt_tool_attempt_uuid(id: ToolCallAttemptId) -> Option<uuid::Uuid> {
    (!id.is_nil()).then(|| uuid_of(id.as_bytes()))
}

pub(crate) fn opt_approval_uuid(id: ApprovalId) -> Option<uuid::Uuid> {
    (!id.is_nil()).then(|| uuid_of(id.as_bytes()))
}

pub(crate) fn opt_run_uuid(id: RunId) -> Option<uuid::Uuid> {
    (!id.is_nil()).then(|| uuid_of(id.as_bytes()))
}

/// Upstream `nullTime` — Go's zero `time.Time` binds NULL.
pub(crate) fn null_time(t: OffsetDateTime) -> Option<OffsetDateTime> {
    (t != ZERO_TIME).then_some(t)
}

/// Upstream `waitReason` — `None` binds `''` (NULLIF'd to NULL).
pub(crate) fn wait_reason_value(
    reason: Option<central_task::domain::WaitingReason>,
) -> &'static str {
    reason.map_or("", central_task::domain::WaitingReason::as_str)
}

// ---------------------------------------------------------------------------
// Canonical encodings.
// ---------------------------------------------------------------------------

/// Upstream `expectedDigest` — SHA-256 over Go's `json.Marshal` of
/// `ExpectedVersions` (`{"Task":1,"Run":2,...}`, field order fixed).
pub(crate) fn expected_digest(v: &ExpectedVersions) -> [u8; 32] {
    let encoded = format!(
        "{{\"Task\":{},\"Run\":{},\"Step\":{},\"Attempt\":{},\"ToolCall\":{},\"ToolAttempt\":{},\"Approval\":{}}}",
        v.task, v.run, v.step, v.attempt, v.tool_call, v.tool_attempt, v.approval
    );
    sha256(encoded.as_bytes())
}

/// Go `encoding/json` string escapes applied to serialized payloads
/// (`<`, `>`, `&`, U+2028, U+2029) so stored bytes match upstream.
pub(crate) fn go_json_escapes(payload: &[u8]) -> Vec<u8> {
    const U2028: [u8; 3] = [0xE2, 0x80, 0xA8];
    const U2029: [u8; 3] = [0xE2, 0x80, 0xA9];
    let mut out = Vec::with_capacity(payload.len() + 16);
    let mut i = 0;
    while i < payload.len() {
        match payload[i] {
            b'<' => {
                out.extend_from_slice(b"\\u003c");
                i += 1;
            }
            b'>' => {
                out.extend_from_slice(b"\\u003e");
                i += 1;
            }
            b'&' => {
                out.extend_from_slice(b"\\u0026");
                i += 1;
            }
            0xE2 if payload.len() - i >= 3 && payload[i + 1..i + 3] == U2028[1..] => {
                out.extend_from_slice(b"\\u2028");
                i += 3;
            }
            0xE2 if payload.len() - i >= 3 && payload[i + 1..i + 3] == U2029[1..] => {
                out.extend_from_slice(b"\\u2029");
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Recovery retry backoff (upstream jitterRecoveryBackoff /
// recoveryRetryBackoff).
// ---------------------------------------------------------------------------
