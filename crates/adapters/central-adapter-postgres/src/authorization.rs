//! PostgreSQL store for `central-authorization`: [`ApprovalStore`]
//! (load + version-guarded commit + batch commit over
//! `central.approvals`), [`SecretUseEvidenceLog`] (immutable append to
//! `central.secret_use_evidence`), and [`ApprovalSummaryRead`] (seek
//! pagination by `(updated_at, id) DESC`).
//!
//! Optimistic-lock discipline (adapter-mapping §5 C7): every guarded
//! update repeats `version = $expected` in its `WHERE` clause; a
//! zero-row result is a stale decision and surfaces as `Conflict`,
//! never a blind re-write. `commit_approval_change_sets` runs the
//! whole batch inside ONE transaction — the first guard failure rolls
//! every change back, matching the upstream single-statement reset
//! sweep's atomicity (`UPDATE … SET state='suspended' WHERE
//! state='active'`).
//!
//! `updated_at` is database-authoritative (`clock_timestamp()`), the
//! b08 `recorded_at` follows the same rule when the record leaves it
//! unset. `created_at` stamps at insert; the rest of the record is the
//! domain's verbatim decision.
//!
//! `GenesisStore` is deliberately absent here: genesis binding and
//! receipt storage is host bootstrap state, not a `central.*` table —
//! no genesis relations exist in the authoritative migration corpus
//! and upstream wires `GenesisPort` outside PostgreSQL.

use central_authorization::domain::{
    ApprovalAction, ApprovalChangeSet, ApprovalKind, ApprovalRecord, ApprovalState,
    SecretUseEvidence, codes,
};
use central_authorization::port::{ApprovalStore, SecretUseEvidenceLog};
use central_authorization::query::{
    ApprovalCursor, ApprovalSummary, ApprovalSummaryPage, ApprovalSummaryRead,
    ApprovalSummaryRequest,
};
use central_foundation::failure::Failure;
use central_foundation::identity::{ApprovalId, RunId, StepId, TaskId, WorkspaceId};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::error::SqlxContext;
use crate::store_support::{
    PG_DATA_CORRUPT, begin_tx, i64_as_u64, opt_uuid_of, u64_as_i64, usize_as_i64, uuid_of,
};

/// Conflict code for a stale optimistic-lock guard — the persisted
/// version moved past the decision's `expected_version`.
const APPROVAL_VERSION_CONFLICT: &str = "approval_version_conflict";

/// PostgreSQL-backed authorization store.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Binds the store to a `central_runtime`-authorized pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// The complete `central.approvals` row in ordinal order — one
/// projection shared by every read so the legs can never drift.
struct ApprovalRow {
    id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    version: i64,
    capability_identity: Option<String>,
    scope: Option<String>,
    action: Option<String>,
    actor_identity: Option<String>,
    authority_identity: Option<String>,
    reason: Option<String>,
    state: String,
    suspend_reason: Option<String>,
    security_epoch: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    expiry_at: Option<OffsetDateTime>,
    approval_kind: String,
    task_id: Option<uuid::Uuid>,
    run_id: Option<uuid::Uuid>,
    step_id: Option<uuid::Uuid>,
    subject_version: Option<i64>,
    logical_operation_id: Option<uuid::Uuid>,
    operation_digest: Option<Vec<u8>>,
    expected_step_version: Option<i64>,
    decision_actor: Option<String>,
    decision_reason: Option<String>,
    decision_id: Option<uuid::Uuid>,
    decided_at: Option<OffsetDateTime>,
    predecessor_approval_id: Option<uuid::Uuid>,
    recorded_at: Option<OffsetDateTime>,
}

/// The shared `SELECT` column list (written longhand inside each
/// checked query — macros cannot interpolate a const, so the ordinal
/// order above is the single convention every statement follows).
fn opt_bytes(id: Option<uuid::Uuid>) -> Option<[u8; 16]> {
    id.map(|u| u.into_bytes())
}

fn corrupt(what: &'static str) -> Failure {
    Failure::internal(PG_DATA_CORRUPT, what)
}

impl TryFrom<ApprovalRow> for ApprovalRecord {
    type Error = Failure;

    fn try_from(row: ApprovalRow) -> Result<Self, Self::Error> {
        let action = row
            .action
            .map(|a| {
                ApprovalAction::parse(&a)
                    .map_err(|_| corrupt("a stored approval action is malformed"))
            })
            .transpose()?;
        let operation_digest = row
            .operation_digest
            .map(|d| {
                <[u8; 32]>::try_from(d.as_slice())
                    .map_err(|_| corrupt("a stored operation digest is not 32 bytes"))
            })
            .transpose()?;
        Ok(Self {
            id: ApprovalId::from_trusted_db_bytes(row.id.into_bytes()),
            workspace_id: WorkspaceId::from_trusted_db_bytes(row.workspace_id.into_bytes()),
            version: i64_as_u64(row.version, "version")?,
            approval_kind: ApprovalKind::parse(&row.approval_kind)
                .map_err(|_| corrupt("a stored approval kind is malformed"))?,
            capability_identity: row.capability_identity,
            scope: row.scope,
            action,
            actor_identity: row.actor_identity,
            authority_identity: row.authority_identity,
            reason: row.reason,
            state: ApprovalState::parse(&row.state)
                .map_err(|_| corrupt("a stored approval state is malformed"))?,
            suspend_reason: row.suspend_reason,
            security_epoch: i64_as_u64(row.security_epoch, "security_epoch")?,
            task_id: row
                .task_id
                .map(|u| TaskId::from_trusted_db_bytes(u.into_bytes())),
            run_id: row
                .run_id
                .map(|u| RunId::from_trusted_db_bytes(u.into_bytes())),
            step_id: row
                .step_id
                .map(|u| StepId::from_trusted_db_bytes(u.into_bytes())),
            subject_version: row
                .subject_version
                .map(|v| i64_as_u64(v, "subject_version"))
                .transpose()?,
            logical_operation_id: opt_bytes(row.logical_operation_id),
            operation_digest,
            expected_step_version: row
                .expected_step_version
                .map(|v| i64_as_u64(v, "expected_step_version"))
                .transpose()?,
            decision_actor: row.decision_actor,
            decision_reason: row.decision_reason,
            decision_id: opt_bytes(row.decision_id),
            decided_at: row.decided_at,
            predecessor_approval_id: row
                .predecessor_approval_id
                .map(|u| ApprovalId::from_trusted_db_bytes(u.into_bytes())),
            recorded_at: row.recorded_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expiry_at: row.expiry_at,
        })
    }
}

/// Binds one record into the guarded `UPDATE` — a shared fragment of
/// every commit so the leg order stays identical between single and
/// batch commits. Returns the bound values in statement order.
struct UpdateBind {
    approval_kind: &'static str,
    action: Option<&'static str>,
    version: i64,
    security_epoch: i64,
    subject_version: Option<i64>,
    expected_step_version: Option<i64>,
}

fn bind_legs(record: &ApprovalRecord) -> Result<UpdateBind, Failure> {
    Ok(UpdateBind {
        approval_kind: record.approval_kind.as_str(),
        action: record.action.map(ApprovalAction::as_str),
        version: u64_as_i64(record.version, codes::APPROVAL_INVALID)?,
        security_epoch: u64_as_i64(record.security_epoch, codes::APPROVAL_INVALID)?,
        subject_version: record
            .subject_version
            .map(|v| u64_as_i64(v, codes::APPROVAL_INVALID))
            .transpose()?,
        expected_step_version: record
            .expected_step_version
            .map(|v| u64_as_i64(v, codes::APPROVAL_INVALID))
            .transpose()?,
    })
}

impl ApprovalStore for Store {
    async fn load_approval(
        &self,
        workspace_id: WorkspaceId,
        approval_id: ApprovalId,
    ) -> Result<ApprovalRecord, Failure> {
        let row = sqlx::query_as!(
            ApprovalRow,
            "SELECT id, workspace_id, version, capability_identity, scope, \
             action, actor_identity, authority_identity, reason, state, \
             suspend_reason, security_epoch, created_at, updated_at, \
             expiry_at, approval_kind, task_id, run_id, step_id, \
             subject_version, logical_operation_id, operation_digest, \
             expected_step_version, decision_actor, decision_reason, \
             decision_id, decided_at, predecessor_approval_id, recorded_at \
             FROM central.approvals \
             WHERE workspace_id = $1 AND id = $2",
            uuid_of(workspace_id.as_bytes()),
            uuid_of(approval_id.as_bytes()),
        )
        .fetch_optional(&self.pool)
        .await
        .ctx("authorization: load approval")?;
        let row = row.ok_or_else(|| {
            Failure::not_found(codes::APPROVAL_NOT_FOUND, "the approval does not exist")
        })?;
        ApprovalRecord::try_from(row)
    }

    async fn commit_approval_change_set(
        &self,
        change_set: ApprovalChangeSet,
    ) -> Result<(), Failure> {
        let next = change_set.next;
        let legs = bind_legs(&next)?;
        let result = sqlx::query!(
            "UPDATE central.approvals SET \
             version = $3, approval_kind = $4, capability_identity = $5, \
             scope = $6, action = $7, actor_identity = $8, \
             authority_identity = $9, reason = $10, state = $11, \
             suspend_reason = $12, security_epoch = $13, task_id = $14, \
             run_id = $15, step_id = $16, subject_version = $17, \
             logical_operation_id = $18, operation_digest = $19, \
             expected_step_version = $20, decision_actor = $21, \
             decision_reason = $22, decision_id = $23, decided_at = $24, \
             predecessor_approval_id = $25, \
             recorded_at = COALESCE($26, clock_timestamp()), \
             expiry_at = $27, updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND version = $28",
            uuid_of(next.workspace_id.as_bytes()),
            uuid_of(next.id.as_bytes()),
            legs.version,
            legs.approval_kind,
            next.capability_identity,
            next.scope,
            legs.action,
            next.actor_identity,
            next.authority_identity,
            next.reason,
            next.state.as_str(),
            next.suspend_reason,
            legs.security_epoch,
            opt_uuid_of(next.task_id, |i| i.as_bytes()),
            opt_uuid_of(next.run_id, |i| i.as_bytes()),
            opt_uuid_of(next.step_id, |i| i.as_bytes()),
            legs.subject_version,
            next.logical_operation_id.map(uuid::Uuid::from_bytes),
            next.operation_digest.as_ref().map(|d| &d[..]),
            legs.expected_step_version,
            next.decision_actor,
            next.decision_reason,
            next.decision_id.map(uuid::Uuid::from_bytes),
            next.decided_at,
            opt_uuid_of(next.predecessor_approval_id, |i| i.as_bytes()),
            next.recorded_at,
            next.expiry_at,
            u64_as_i64(change_set.expected_version, codes::APPROVAL_INVALID)?,
        )
        .execute(&self.pool)
        .await
        .ctx("authorization: commit approval change set")?;
        if result.rows_affected() == 0 {
            return Err(Failure::conflict(
                APPROVAL_VERSION_CONFLICT,
                "the approval row moved past the decision's expected version",
            ));
        }
        Ok(())
    }

    async fn commit_approval_change_sets(
        &self,
        change_sets: Vec<ApprovalChangeSet>,
    ) -> Result<(), Failure> {
        if change_sets.is_empty() {
            return Ok(());
        }
        let mut tx = begin_tx(&self.pool).await?;
        for change_set in change_sets {
            let next = change_set.next;
            let legs = bind_legs(&next)?;
            let result = sqlx::query!(
                "UPDATE central.approvals SET \
                 version = $3, approval_kind = $4, capability_identity = $5, \
                 scope = $6, action = $7, actor_identity = $8, \
                 authority_identity = $9, reason = $10, state = $11, \
                 suspend_reason = $12, security_epoch = $13, task_id = $14, \
                 run_id = $15, step_id = $16, subject_version = $17, \
                 logical_operation_id = $18, operation_digest = $19, \
                 expected_step_version = $20, decision_actor = $21, \
                 decision_reason = $22, decision_id = $23, decided_at = $24, \
                 predecessor_approval_id = $25, \
                 recorded_at = COALESCE($26, clock_timestamp()), \
                 expiry_at = $27, updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND id = $2 AND version = $28",
                uuid_of(next.workspace_id.as_bytes()),
                uuid_of(next.id.as_bytes()),
                legs.version,
                legs.approval_kind,
                next.capability_identity,
                next.scope,
                legs.action,
                next.actor_identity,
                next.authority_identity,
                next.reason,
                next.state.as_str(),
                next.suspend_reason,
                legs.security_epoch,
                opt_uuid_of(next.task_id, |i| i.as_bytes()),
                opt_uuid_of(next.run_id, |i| i.as_bytes()),
                opt_uuid_of(next.step_id, |i| i.as_bytes()),
                legs.subject_version,
                next.logical_operation_id.map(uuid::Uuid::from_bytes),
                next.operation_digest.as_ref().map(|d| &d[..]),
                legs.expected_step_version,
                next.decision_actor,
                next.decision_reason,
                next.decision_id.map(uuid::Uuid::from_bytes),
                next.decided_at,
                opt_uuid_of(next.predecessor_approval_id, |i| i.as_bytes()),
                next.recorded_at,
                next.expiry_at,
                u64_as_i64(change_set.expected_version, codes::APPROVAL_INVALID)?,
            )
            .execute(&mut *tx)
            .await
            .ctx("authorization: commit batched approval change set")?;
            if result.rows_affected() == 0 {
                // The first guard failure aborts the whole batch — the
                // transaction drop rolls every earlier update back.
                return Err(Failure::conflict(
                    APPROVAL_VERSION_CONFLICT,
                    "a batched approval decision ran against a stale version",
                ));
            }
        }
        tx.commit()
            .await
            .ctx("authorization: commit approval batch transaction")
    }

    async fn insert_approval(&self, record: ApprovalRecord) -> Result<(), Failure> {
        let legs = bind_legs(&record)?;
        sqlx::query!(
            "INSERT INTO central.approvals \
             (id, workspace_id, version, capability_identity, scope, \
              action, actor_identity, authority_identity, reason, state, \
              suspend_reason, security_epoch, created_at, updated_at, \
              expiry_at, approval_kind, task_id, run_id, step_id, \
              subject_version, logical_operation_id, operation_digest, \
              expected_step_version, decision_actor, decision_reason, \
              decision_id, decided_at, predecessor_approval_id, recorded_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                     clock_timestamp(), clock_timestamp(), $13, $14, $15, \
                     $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, \
                     COALESCE($27, clock_timestamp()))",
            uuid_of(record.id.as_bytes()),
            uuid_of(record.workspace_id.as_bytes()),
            legs.version,
            record.capability_identity,
            record.scope,
            legs.action,
            record.actor_identity,
            record.authority_identity,
            record.reason,
            record.state.as_str(),
            record.suspend_reason,
            legs.security_epoch,
            record.expiry_at,
            legs.approval_kind,
            opt_uuid_of(record.task_id, |i| i.as_bytes()),
            opt_uuid_of(record.run_id, |i| i.as_bytes()),
            opt_uuid_of(record.step_id, |i| i.as_bytes()),
            legs.subject_version,
            record.logical_operation_id.map(uuid::Uuid::from_bytes),
            record.operation_digest.as_ref().map(|d| &d[..]),
            legs.expected_step_version,
            record.decision_actor,
            record.decision_reason,
            record.decision_id.map(uuid::Uuid::from_bytes),
            record.decided_at,
            opt_uuid_of(record.predecessor_approval_id, |i| i.as_bytes()),
            record.recorded_at,
        )
        .execute(&self.pool)
        .await
        .ctx("authorization: insert approval")?;
        Ok(())
    }

    async fn load_workspace_approvals(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ApprovalRecord>, Failure> {
        let rows = sqlx::query_as!(
            ApprovalRow,
            "SELECT id, workspace_id, version, capability_identity, scope, \
             action, actor_identity, authority_identity, reason, state, \
             suspend_reason, security_epoch, created_at, updated_at, \
             expiry_at, approval_kind, task_id, run_id, step_id, \
             subject_version, logical_operation_id, operation_digest, \
             expected_step_version, decision_actor, decision_reason, \
             decision_id, decided_at, predecessor_approval_id, recorded_at \
             FROM central.approvals \
             WHERE workspace_id = $1 \
             ORDER BY id ASC",
            uuid_of(workspace_id.as_bytes()),
        )
        .fetch_all(&self.pool)
        .await
        .ctx("authorization: load workspace approvals")?;
        rows.into_iter().map(ApprovalRecord::try_from).collect()
    }
}

impl SecretUseEvidenceLog for Store {
    async fn append_secret_use(&self, evidence: SecretUseEvidence) -> Result<(), Failure> {
        sqlx::query!(
            "INSERT INTO central.secret_use_evidence \
             (id, workspace_id, secret_reference_id, actor_identity, \
              operation_identity, authorization_outcome, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp())",
            uuid_of(evidence.id.as_bytes()),
            uuid_of(evidence.workspace_id.as_bytes()),
            evidence.secret_reference_id,
            evidence.actor_identity,
            evidence.operation_identity,
            evidence.authorization_outcome,
        )
        .execute(&self.pool)
        .await
        .ctx("authorization: append secret-use evidence")?;
        Ok(())
    }
}

impl ApprovalSummaryRead for Store {
    async fn read_page(
        &self,
        request: &ApprovalSummaryRequest,
    ) -> Result<ApprovalSummaryPage, Failure> {
        let limit = request.validate()?;
        let cursor_updated = request.cursor.as_ref().map(|c| c.updated_at);
        let cursor_id = request.cursor.as_ref().map(|c| uuid_of(c.id.as_bytes()));

        // Seek over (updated_at, id) DESC — strict tuple comparison,
        // no OFFSET; limit+1 rows price `next_cursor` in one query.
        let rows = sqlx::query!(
            "SELECT id, capability_identity, scope, action, actor_identity, \
             state, suspend_reason, reason, authority_identity, \
             created_at, updated_at, expiry_at \
             FROM central.approvals \
             WHERE workspace_id = $1 \
               AND actor_identity = $2 \
               AND ($3::uuid IS NULL OR task_id = $3) \
               AND ($4::timestamptz IS NULL OR \
                    (updated_at, id) < ($4::timestamptz, $5::uuid)) \
             ORDER BY updated_at DESC, id DESC \
             LIMIT $6",
            uuid_of(request.workspace_id.as_bytes()),
            request.approver,
            opt_uuid_of(request.task_id, |i| i.as_bytes()),
            cursor_updated,
            cursor_id,
            usize_as_i64(limit) + 1,
        )
        .fetch_all(&self.pool)
        .await
        .ctx("authorization: read approval summary page")?;

        let has_more = rows.len() > limit;
        let mut approvals = Vec::with_capacity(limit.min(rows.len()));
        for row in rows.into_iter().take(limit) {
            approvals.push(ApprovalSummary {
                approval_id: ApprovalId::from_trusted_db_bytes(row.id.into_bytes()),
                capability_identity: row.capability_identity.unwrap_or_default(),
                scope: row.scope.unwrap_or_default(),
                action: row.action.unwrap_or_default(),
                state: row.state,
                suspend_reason: row.suspend_reason,
                reason: row.reason.unwrap_or_default(),
                authority_identity: row.authority_identity.unwrap_or_default(),
                created_at: row.created_at,
                updated_at: row.updated_at,
                expiry_at: row.expiry_at,
            });
        }
        let next_cursor = if has_more {
            approvals.last().map(|summary| ApprovalCursor {
                updated_at: summary.updated_at,
                id: summary.approval_id,
            })
        } else {
            None
        };
        Ok(ApprovalSummaryPage {
            approvals,
            next_cursor,
        })
    }
}
