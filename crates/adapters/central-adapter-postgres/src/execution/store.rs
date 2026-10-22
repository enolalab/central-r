//! The composite execution `Store` — port of upstream
//! `internal/adapter/postgres/execution/store.go`.
//!
//! `Commit` is the single fenced, idempotent write seam: advisory
//! receipt lock → receipt replay check → workspace event-counter lock →
//! task/run/step/attempt/lease fence checks → change-set application in
//! the documented lock order → events → outbox (+ workspace work) →
//! receipt insert, all inside one `synchronous_commit = on`
//! transaction. `ReadExecution`, `LookupReceipt`, `ValidateLease`,
//! `PublishOutbox`, `CommitB09Evidence`, and the `RecoveryStore`
//! surface round out the port set.

use central_execution::domain::{
    Approval, EventIntent, ExecutionState, ExpectedVersions, Lease, LeaseCredential,
    LogicalOperationId, OutboxIntent, Step, StepAttempt, StepAttemptAssertion, ToolCall,
    ToolCallAttempt, TrustedScope, ZERO_TIME,
};
use central_execution::harness_run::B09EvidenceReference;
use central_execution::port::{
    B09EvidenceStore, ClaimRecoveryWorkspaceRequest, CommitRequest, CommitResult,
    CompleteRecoveryWorkspaceRequest, CompositeExecutionStore, CompositeStore, DurableResult,
    ExecutionRead, ExecutionReadRequest, ExecutionReadResult, LeaseCredentialValidator,
    LeaseValidationRequest, OutboxStore, ReceiptLookupRequest, ReceiptLookupResult,
    RecoveryCoordinatorAcquireRequest, RecoveryCoordinatorLease, RecoveryStore,
    RecoveryWorkspaceClaim, ResumeRecoveryEpochRequest, StartRecoveryEpochRequest,
};
use central_execution::resume::{
    self, RecoveryCoordinatorFence, RecoveryEpoch, RecoveryEpochState, RecoveryWorkspaceState,
    RecoveryWorkspaceWork,
};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ExecutionEventId, RunId, StepAttemptId, StepId, TaskId, WorkspaceId,
};
use central_task::domain::TaskChangeSet;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use super::queries::{
    assert_recovery_epoch_domain, db_now, lock_event_counter, read_attempt,
    read_incomplete_recovery_epoch, read_locked_recovery_epoch_for_claim,
    read_persisted_lease_for_update, read_run, read_step, read_task, read_tool_attempts,
    read_tool_calls, reserve_event_sequence, select_recovery_workspace_batch,
};
use super::{
    RECOVERY_DOMAIN, RECOVERY_SCAN_BATCH, RESUME_SCOPE, begin, begin_recovery, begin_recovery_scan,
    conflict, corrupt, ct_eq, denied, expected_digest, go_json_escapes, invalid,
    invocation_generation, new_lease_secret, null_time, opt_approval_uuid, opt_attempt_uuid,
    opt_run_uuid, opt_step_uuid, opt_tool_attempt_uuid, sha256, uuid_for_invocation,
    uuid_for_logical, uuid_for_physical, uuid_of, wait_reason_value,
};
use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::opt_uuid_of;
use crate::task::queries::event_intent_payload;

/// PostgreSQL execution composite store — a thin `PgPool` holder;
/// every port method opens its own bounded transaction.
pub struct Store {
    pub(crate) pool: PgPool,
}

impl Store {
    /// `New`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // -----------------------------------------------------------------
    // Receipt identity (upstream lockReceiptIdentity / readReceipt /
    // insertReceipt).
    // -----------------------------------------------------------------

    /// `pg_advisory_xact_lock(hashtextextended(ws:scope:key, 8248))` —
    /// serializes concurrent commits on one receipt identity.
    async fn lock_receipt_identity(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        scope: &str,
        key: &str,
    ) -> Result<(), Failure> {
        sqlx::query!(
            "SELECT pg_advisory_xact_lock(\
             hashtextextended($1 || ':' || $2 || ':' || $3, 8248))",
            ws.to_string(),
            scope,
            key,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: lock receipt identity")?;
        Ok(())
    }

    /// The canonical receipt-result JSON (`result_payload`) — typed
    /// DurableResult rendered with Go field names.
    fn encode_result_payload(result: &DurableResult, logical: LogicalOperationId) -> Vec<u8> {
        let approval = result.approval_action.as_ref().map(|a| {
            serde_json::json!({
                "Action": a.action.map_or("", |x| x.as_str()),
                "Authorized": a.authorized,
                "RequiredCapability": a.required_capability.map_or("", |c| c.as_str()),
                "StepID": a.step_id.to_string(),
                "ApprovalID": a.approval_id.to_string(),
                "LogicalOperationID": a.logical_operation_id.0
                    .iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "ApprovalSubjectVersion": a.approval_subject_version,
                "ExpectedVersions": {
                    "Task": a.expected_versions.task,
                    "Run": a.expected_versions.run,
                    "Step": a.expected_versions.step,
                    "Attempt": a.expected_versions.attempt,
                    "ToolCall": a.expected_versions.tool_call,
                    "ToolAttempt": a.expected_versions.tool_attempt,
                    "Approval": a.expected_versions.approval,
                },
            })
        });
        serde_json::to_vec(&serde_json::json!({
            "WorkspaceID": result.workspace_id.to_string(),
            "TaskID": result.task_id.to_string(),
            "RunID": result.run_id.to_string(),
            "StepID": result.step_id.to_string(),
            "AttemptID": result.attempt_id.to_string(),
            "LogicalOperationID": logical.0.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "EventID": result.event_id.to_string(),
            "EventKind": result.event_kind,
            "ApprovalAction": approval,
        }))
        .unwrap_or_default()
    }

    /// Decodes a stored `result_payload`; corrupt rows are internal.
    fn decode_result_payload(
        payload: &serde_json::Value,
        binding: &central_execution::port::ReceiptBinding,
        event_id: uuid::Uuid,
        event_kind: &str,
    ) -> Result<DurableResult, Failure> {
        let approval_action = payload.get("ApprovalAction").and_then(|a| {
            if a.is_null() {
                return None;
            }
            Some(
                central_execution::domain::ApprovalSuccessorActionDescriptor {
                    action: a
                        .get("Action")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|_| central_execution::domain::ApprovalAction::ActionResolveApproval),
                    authorized: a
                        .get("Authorized")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    required_capability: a
                        .get("RequiredCapability")
                        .and_then(|v| v.as_str())
                        .and_then(|s| match s {
                            "executor" => Some(central_execution::domain::Capability::Executor),
                            "approver" => Some(central_execution::domain::Capability::Approver),
                            "workspace_operator" => {
                                Some(central_execution::domain::Capability::WorkspaceOperator)
                            }
                            "recovery_coordinator" => {
                                Some(central_execution::domain::Capability::RecoveryCoordinator)
                            }
                            _ => None,
                        }),
                    step_id: a
                        .get("StepID")
                        .and_then(|v| v.as_str())
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())
                        .map_or_else(
                            || StepId::from_trusted_db_bytes([0; 16]),
                            |u| StepId::from_trusted_db_bytes(*u.as_bytes()),
                        ),
                    approval_id: a
                        .get("ApprovalID")
                        .and_then(|v| v.as_str())
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())
                        .map_or_else(
                            || {
                                central_foundation::identity::ApprovalId::from_trusted_db_bytes(
                                    [0; 16],
                                )
                            },
                            |u| {
                                central_foundation::identity::ApprovalId::from_trusted_db_bytes(
                                    *u.as_bytes(),
                                )
                            },
                        ),
                    logical_operation_id: LogicalOperationId([0; 16]),
                    approval_subject_version: a
                        .get("ApprovalSubjectVersion")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0),
                    expected_versions: ExpectedVersions::default(),
                },
            )
        });
        Ok(DurableResult {
            workspace_id: binding_task_ws(payload)?,
            task_id: binding.task_id,
            run_id: binding.run_id,
            step_id: binding.step_id,
            attempt_id: binding.attempt_id,
            event_id: ExecutionEventId::from_trusted_db_bytes(*event_id.as_bytes()),
            event_kind: event_kind.to_owned(),
            approval_action,
        })
    }

    /// `readReceipt` — `None` when no row exists for the identity.
    async fn read_receipt(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        scope: &str,
        key: &str,
    ) -> Result<Option<ReceiptRow>, Failure> {
        sqlx::query_as!(
            ReceiptRow,
            "SELECT request_fingerprint, principal_id, capability, \
             expected_version_digest, result_reference, result_payload, \
             task_id, run_id, step_id, step_attempt_id, logical_operation_id \
             FROM central.execution_command_receipts \
             WHERE workspace_id = $1 AND command_scope = $2 AND idempotency_key = $3",
            uuid_of(ws.as_bytes()),
            scope,
            key,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read receipt")
    }

    /// `insertReceipt` — `ON CONFLICT DO NOTHING`; a zero row count is
    /// surfaced by the caller as a lost race (defensive — the advisory
    /// lock already serializes the identity).
    async fn insert_receipt(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
        digest: [u8; 32],
    ) -> Result<(), Failure> {
        let payload =
            Self::encode_result_payload(&req.result, req.receipt_binding.logical_operation);
        sqlx::query!(
            "INSERT INTO central.execution_command_receipts (\
             id, workspace_id, command_scope, idempotency_key, request_fingerprint, \
             principal_id, capability, expected_version_digest, result_reference, \
             result_payload, task_id, run_id, step_id, step_attempt_id, \
             logical_operation_id, created_at, expires_at, eligible_after) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, \
             $11, $12, $13, $14, $15, clock_timestamp(), \
             clock_timestamp() + interval '7 days', \
             clock_timestamp() + interval '90 days') \
             ON CONFLICT (workspace_id, command_scope, idempotency_key) DO NOTHING",
            uuid::Uuid::now_v7(),
            uuid_of(req.scope.workspace_id.as_bytes()),
            req.command_scope,
            req.idempotency_key,
            &req.fingerprint[..],
            req.principal_id,
            req.capability.as_str(),
            &digest[..],
            uuid_of(req.result.event_id.as_bytes()),
            serde_json::from_slice::<serde_json::Value>(&payload).unwrap_or_default(),
            uuid_of(req.receipt_binding.task_id.as_bytes()),
            opt_run_uuid(req.receipt_binding.run_id),
            opt_step_uuid(req.receipt_binding.step_id),
            opt_attempt_uuid(req.receipt_binding.attempt_id),
            uuid_for_logical(&req.receipt_binding.logical_operation),
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: insert receipt")?;
        Ok(())
    }

    /// Receipt replay equality — fingerprint + principal + capability +
    /// expected-version digest + the full binding. Any drift is
    /// `REASON_REQUEST_CONFLICT` (upstream behavior).
    fn receipt_matches(
        row: &ReceiptRow,
        req_fp: &[u8; 32],
        principal: &str,
        capability: central_execution::domain::Capability,
        digest: &[u8; 32],
        binding: &central_execution::port::ReceiptBinding,
    ) -> bool {
        row.request_fingerprint == req_fp
            && row.principal_id == principal
            && row.capability == capability.as_str()
            && row.expected_version_digest == digest
            && row.task_id == Some(uuid_of(binding.task_id.as_bytes()))
            && row.run_id == Some(uuid_of(binding.run_id.as_bytes()))
            && row.step_id == opt_step_uuid(binding.step_id)
            && row.step_attempt_id == opt_attempt_uuid(binding.attempt_id)
            && row.logical_operation_id == Some(uuid_for_logical(&binding.logical_operation))
    }

    // -----------------------------------------------------------------
    // Optimistic row guards (upstream lockReceipt*Target + CAS writes).
    // -----------------------------------------------------------------

    async fn lock_step_target(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        tid: TaskId,
        rid: RunId,
        sid: StepId,
    ) -> Result<i64, Failure> {
        let row = sqlx::query!(
            "SELECT version FROM central.steps \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 AND id = $4 \
             FOR UPDATE",
            uuid_of(ws.as_bytes()),
            uuid_of(tid.as_bytes()),
            uuid_of(rid.as_bytes()),
            uuid_of(sid.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock step target")?;
        row.map(|r| r.version)
            .ok_or_else(|| conflict("STATE_SCOPE_MISMATCH"))
    }

    async fn lock_attempt_target(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        tid: TaskId,
        rid: RunId,
        sid: StepId,
        aid: StepAttemptId,
    ) -> Result<i64, Failure> {
        let row = sqlx::query!(
            "SELECT version FROM central.step_attempts \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5 FOR UPDATE",
            uuid_of(ws.as_bytes()),
            uuid_of(tid.as_bytes()),
            uuid_of(rid.as_bytes()),
            uuid_of(sid.as_bytes()),
            uuid_of(aid.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock attempt target")?;
        row.map(|r| r.version)
            .ok_or_else(|| conflict("STATE_SCOPE_MISMATCH"))
    }

    async fn lock_tool_call_target(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        tid: TaskId,
        rid: RunId,
        parent: StepAttemptId,
        id: central_foundation::identity::ToolCallId,
    ) -> Result<i64, Failure> {
        let row = sqlx::query!(
            "SELECT version FROM central.tool_calls \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_attempt_id = $4 AND id = $5 FOR UPDATE",
            uuid_of(ws.as_bytes()),
            uuid_of(tid.as_bytes()),
            uuid_of(rid.as_bytes()),
            uuid_of(parent.as_bytes()),
            uuid_of(id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock tool call target")?;
        row.map(|r| r.version)
            .ok_or_else(|| conflict("STATE_SCOPE_MISMATCH"))
    }

    async fn lock_tool_attempt_target(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        tid: TaskId,
        rid: RunId,
        parent: StepAttemptId,
        call: central_foundation::identity::ToolCallId,
        id: central_foundation::identity::ToolCallAttemptId,
    ) -> Result<i64, Failure> {
        let row = sqlx::query!(
            "SELECT version FROM central.tool_call_attempts \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_attempt_id = $4 AND tool_call_id = $5 AND id = $6 \
             FOR UPDATE",
            uuid_of(ws.as_bytes()),
            uuid_of(tid.as_bytes()),
            uuid_of(rid.as_bytes()),
            uuid_of(parent.as_bytes()),
            uuid_of(call.as_bytes()),
            uuid_of(id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock tool attempt target")?;
        row.map(|r| r.version)
            .ok_or_else(|| conflict("STATE_SCOPE_MISMATCH"))
    }

    // -----------------------------------------------------------------
    // Recovery claim admission — upstream enforceRecoveryClaimAdmission
    // (runs inside the commit transaction for lease-granting commands).
    // -----------------------------------------------------------------

    async fn enforce_recovery_claim_admission(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        tid: TaskId,
        rid: RunId,
    ) -> Result<(), Failure> {
        sqlx::query("LOCK TABLE central.recovery_epochs IN ROW EXCLUSIVE MODE")
            .execute(&mut **tx)
            .await
            .map_err(|e| classify_sqlx(&e))?;
        // Latest epoch covering the workspace (any state).
        let epoch_row = sqlx::query!(
            "SELECT e.epoch_generation, e.coordinator_fence, e.state \
             FROM central.recovery_epochs e \
             WHERE EXISTS ( \
               SELECT 1 FROM central.recovery_epoch_workspaces w \
               WHERE w.epoch_generation = e.epoch_generation AND w.workspace_id = $1 \
             ) ORDER BY e.epoch_generation DESC LIMIT 1 FOR UPDATE OF e",
            uuid_of(ws.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock latest recovery claim epoch")?;
        let Some(epoch_row) = epoch_row else {
            return Ok(()); // no epoch ever covered this workspace
        };
        let work_row = sqlx::query!(
            "SELECT delivery_state, watermark_created_at, watermark_run_id \
             FROM central.recovery_epoch_workspaces \
             WHERE epoch_generation = $1 AND workspace_id = $2 FOR UPDATE",
            epoch_row.epoch_generation,
            uuid_of(ws.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock recovery claim workspace")?;
        let Some(work_row) = work_row else {
            return Ok(());
        };
        let run_row = sqlx::query!(
            "SELECT created_at, reconciled_epoch FROM central.runs \
             WHERE workspace_id = $1 AND task_id = $2 AND id = $3",
            uuid_of(ws.as_bytes()),
            uuid_of(tid.as_bytes()),
            uuid_of(rid.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read recovery admission run")?;
        let Some(run_row) = run_row else {
            return Err(conflict("RUN_NOT_FOUND"));
        };
        let epoch = RecoveryEpoch {
            generation: epoch_row.epoch_generation,
            coordinator_fence: RecoveryCoordinatorFence {
                generation: epoch_row.coordinator_fence,
            },
            state: epoch_state(&epoch_row.state),
            scheduler_cursor: WorkspaceId::from_trusted_db_bytes([0; 16]),
            workspace_count: 0,
            processed_count: 0,
            claim_cycle: 0,
            retry_attempt: 0,
            snapshot_at: ZERO_TIME,
        };
        let work = RecoveryWorkspaceWork {
            epoch_generation: epoch_row.epoch_generation,
            workspace_id: ws,
            state: work_state(&work_row.delivery_state),
            watermark_created_at: work_row.watermark_created_at,
            watermark_run_id: RunId::from_trusted_db_bytes(*work_row.watermark_run_id.as_bytes()),
            cursor_created_at: ZERO_TIME,
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
            run_row.created_at,
            rid,
            run_row.reconciled_epoch,
        );
        if !decision.claimable {
            return Err(conflict("RECOVERY_QUARANTINED"));
        }
        Ok(())
    }

    /// `enforceLeaseFence` — the evaluator-proven bearer must match the
    /// durable verifier, generation, unexpired window and claim target.
    async fn enforce_lease_fence(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        rid: RunId,
        sid: StepId,
        aid: StepAttemptId,
        credential: &LeaseCredential,
        generation: i64,
    ) -> Result<(), Failure> {
        let persisted = read_persisted_lease_for_update(tx, ws, rid).await?;
        let Some(lease) = persisted else {
            return Err(denied("LEASE_FENCED"));
        };
        if lease.generation != generation
            || !ct_eq(&sha256(&credential.0), &lease.verifier)
            || (!lease.step_id.is_nil() && lease.step_id != sid)
            || (!lease.attempt_id.is_nil() && lease.attempt_id != aid)
        {
            return Err(denied("LEASE_FENCED"));
        }
        if db_now(tx).await? >= lease.expires_at {
            return Err(denied("LEASE_FENCED"));
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Change-set application (upstream applyChangeSet — lock order §6).
    // -----------------------------------------------------------------

    async fn apply_step(tx: &mut Transaction<'_, Postgres>, step: &Step) -> Result<(), Failure> {
        let (w, t, r, s) = (
            uuid_of(step.workspace_id.as_bytes()),
            uuid_of(step.task_id.as_bytes()),
            uuid_of(step.run_id.as_bytes()),
            uuid_of(step.id.as_bytes()),
        );
        let version =
            Self::lock_step_target(tx, step.workspace_id, step.task_id, step.run_id, step.id).await;
        match version {
            Err(_) => {
                // Row absent → insert (upstream insertStep).
                let done = sqlx::query!(
                    "INSERT INTO central.steps (\
                     id, workspace_id, task_id, run_id, version, state, \
                     logical_operation_id, sequence, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, \
                     clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (id) DO NOTHING",
                    s,
                    w,
                    t,
                    r,
                    step.version,
                    step.state.as_str(),
                    uuid::Uuid::now_v7(),
                    step.sequence,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert step")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Ok(version) if version == step.version.saturating_sub(1) || version == step.version => {
                let done = sqlx::query!(
                    "UPDATE central.steps \
                     SET version = $5, state = $6, sequence = $7, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                     AND id = $4 AND version = $8",
                    w,
                    t,
                    r,
                    s,
                    step.version,
                    step.state.as_str(),
                    step.sequence,
                    version,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update step")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Ok(_) => Err(conflict("VERSION_CONFLICT")),
        }
    }

    async fn apply_attempt(
        tx: &mut Transaction<'_, Postgres>,
        a: &StepAttempt,
    ) -> Result<(), Failure> {
        let (w, s, t, r, id) = (
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.step_id.as_bytes()),
            uuid_of(a.task_id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
            uuid_of(a.id.as_bytes()),
        );
        let version =
            Self::lock_attempt_target(tx, a.workspace_id, a.task_id, a.run_id, a.step_id, a.id)
                .await;
        match version {
            Err(_) => {
                let done = sqlx::query!(
                    "INSERT INTO central.step_attempts (\
                     id, workspace_id, step_id, task_id, run_id, version, \
                     logical_operation_id, physical_attempt_id, invocation_id, \
                     invocation_generation, predecessor_id, sequence, state, \
                     created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                     CASE WHEN $9::uuid IS NULL THEN NULL ELSE $10::bigint END, \
                     $11, $12, $13, clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (id) DO NOTHING",
                    id,
                    w,
                    s,
                    t,
                    r,
                    a.version,
                    uuid_for_logical(&a.logical_operation_id),
                    uuid_for_physical(&a.physical_attempt_id),
                    uuid_for_invocation(&a.invocation_id),
                    invocation_generation(&a.invocation_id),
                    opt_attempt_uuid(a.predecessor_id),
                    a.sequence,
                    a.state.as_str(),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert attempt")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Ok(version) if version == a.version.saturating_sub(1) || version == a.version => {
                let done = sqlx::query!(
                    "UPDATE central.step_attempts \
                     SET version = $6, invocation_id = $7, \
                     invocation_generation = CASE WHEN $7::uuid IS NULL THEN NULL ELSE $8::bigint END, \
                     state = $9, outcome = COALESCE($10::jsonb, outcome), \
                     context = COALESCE($11::jsonb, context), \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                     AND step_id = $4 AND id = $5 AND version = $12",
                    w, t, r, s, id, a.version,
                    uuid_for_invocation(&a.invocation_id),
                    invocation_generation(&a.invocation_id),
                    a.state.as_str(),
                    Option::<serde_json::Value>::None,
                    Option::<serde_json::Value>::None,
                    version,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update attempt")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Ok(_) => Err(conflict("VERSION_CONFLICT")),
        }
    }

    async fn apply_tool_call(
        tx: &mut Transaction<'_, Postgres>,
        c: &ToolCall,
    ) -> Result<(), Failure> {
        let (w, parent, t, r, id) = (
            uuid_of(c.workspace_id.as_bytes()),
            uuid_of(c.step_attempt_id.as_bytes()),
            uuid_of(c.task_id.as_bytes()),
            uuid_of(c.run_id.as_bytes()),
            uuid_of(c.id.as_bytes()),
        );
        let version = Self::lock_tool_call_target(
            tx,
            c.workspace_id,
            c.task_id,
            c.run_id,
            c.step_attempt_id,
            c.id,
        )
        .await;
        match version {
            Err(_) => {
                let done = sqlx::query!(
                    "INSERT INTO central.tool_calls (\
                     id, workspace_id, step_id, step_attempt_id, task_id, run_id, \
                     version, logical_operation_id, sequence, state, \
                     created_at, updated_at) \
                     SELECT $1, $2, a.step_id, $3, $4, $5, $6, $7, $8, $9, \
                     clock_timestamp(), clock_timestamp() \
                     FROM central.step_attempts a \
                     WHERE a.workspace_id = $2 AND a.id = $3 \
                     ON CONFLICT (id) DO NOTHING",
                    id,
                    w,
                    parent,
                    t,
                    r,
                    c.version,
                    uuid_for_logical(&c.logical_operation_id),
                    c.sequence,
                    c.state.as_str(),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert tool call")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Ok(version) if version == c.version.saturating_sub(1) || version == c.version => {
                let done = sqlx::query!(
                    "UPDATE central.tool_calls \
                     SET version = $6, sequence = $7, state = $8, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                     AND step_attempt_id = $4 AND id = $5 AND version = $9",
                    w,
                    t,
                    r,
                    parent,
                    id,
                    c.version,
                    c.sequence,
                    c.state.as_str(),
                    version,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update tool call")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Ok(_) => Err(conflict("VERSION_CONFLICT")),
        }
    }

    async fn apply_tool_attempt(
        tx: &mut Transaction<'_, Postgres>,
        a: &ToolCallAttempt,
    ) -> Result<(), Failure> {
        let (w, call, parent, t, r, id) = (
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.tool_call_id.as_bytes()),
            uuid_of(a.step_attempt_id.as_bytes()),
            uuid_of(a.task_id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
            uuid_of(a.id.as_bytes()),
        );
        let version = Self::lock_tool_attempt_target(
            tx,
            a.workspace_id,
            a.task_id,
            a.run_id,
            a.step_attempt_id,
            a.tool_call_id,
            a.id,
        )
        .await;
        match version {
            Err(_) => {
                let done = sqlx::query!(
                    "INSERT INTO central.tool_call_attempts (\
                     id, workspace_id, tool_call_id, step_attempt_id, task_id, run_id, \
                     version, logical_operation_id, physical_attempt_id, invocation_id, \
                     invocation_generation, predecessor_id, sequence, state, \
                     created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                     CASE WHEN $10::uuid IS NULL THEN NULL ELSE $11::bigint END, \
                     $12, $13, $14, clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (id) DO NOTHING",
                    id,
                    w,
                    call,
                    parent,
                    t,
                    r,
                    a.version,
                    uuid_for_logical(&a.logical_operation_id),
                    uuid_for_physical(&a.physical_attempt_id),
                    uuid_for_invocation(&a.invocation_id),
                    invocation_generation(&a.invocation_id),
                    opt_tool_attempt_uuid(a.predecessor_id),
                    a.sequence,
                    a.state.as_str(),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert tool attempt")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Ok(version) if version == a.version.saturating_sub(1) || version == a.version => {
                let done = sqlx::query!(
                    "UPDATE central.tool_call_attempts \
                     SET version = $7, invocation_id = $8, \
                     invocation_generation = CASE WHEN $8::uuid IS NULL THEN NULL ELSE $9::bigint END, \
                     state = $10, outcome = COALESCE($11::jsonb, outcome), \
                     context = COALESCE($12::jsonb, context), \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                     AND step_attempt_id = $4 AND tool_call_id = $5 AND id = $6 \
                     AND version = $13",
                    w, t, r, parent, call, id, a.version,
                    uuid_for_invocation(&a.invocation_id),
                    invocation_generation(&a.invocation_id),
                    a.state.as_str(),
                    Option::<serde_json::Value>::None,
                    Option::<serde_json::Value>::None,
                    version,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update tool attempt")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Ok(_) => Err(conflict("VERSION_CONFLICT")),
        }
    }

    async fn apply_approval(
        tx: &mut Transaction<'_, Postgres>,
        a: &Approval,
    ) -> Result<(), Failure> {
        let (w, t, r, s, id) = (
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.task_id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
            uuid_of(a.step_id.as_bytes()),
            uuid_of(a.id.as_bytes()),
        );
        let locked = sqlx::query!(
            "SELECT version FROM central.approvals \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 AND step_id = $4 \
             AND id = $5 AND approval_kind = 'execution' FOR UPDATE",
            w,
            t,
            r,
            s,
            id,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock approval")?;
        match locked {
            None => {
                let done = sqlx::query!(
                    "INSERT INTO central.approvals (\
                     id, workspace_id, version, state, approval_kind, task_id, run_id, \
                     step_id, subject_version, logical_operation_id, operation_digest, \
                     expected_step_version, decision_actor, decision_reason, decision_id, \
                     decided_at, predecessor_approval_id, recorded_at, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, 'execution', $5, $6, $7, $8, $9, $10, $11, \
                     NULLIF($12, ''), NULLIF($13, ''), $14, $15, $16, \
                     clock_timestamp(), clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (id) DO NOTHING",
                    id,
                    w,
                    a.version,
                    a.state.as_str(),
                    t,
                    r,
                    s,
                    a.subject.version,
                    uuid_for_logical(&a.subject.logical_operation_id),
                    &a.subject.operation_digest[..],
                    a.subject.expected_step_version,
                    a.actor,
                    a.reason_code,
                    opt_uuid_of((a.decision_id != [0; 16]).then_some(a.decision_id), |d| &d,),
                    null_time(a.decided_at),
                    opt_approval_uuid(a.predecessor_id),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert approval")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Some(row) if row.version == a.version.saturating_sub(1) || row.version == a.version => {
                let done = sqlx::query!(
                    "UPDATE central.approvals \
                     SET version = $6, state = $7, decision_actor = NULLIF($8, ''), \
                     decision_reason = NULLIF($9, ''), decision_id = $10, \
                     decided_at = $11, updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                     AND step_id = $4 AND id = $5 AND version = $12 \
                     AND approval_kind = 'execution'",
                    w,
                    t,
                    r,
                    s,
                    id,
                    a.version,
                    a.state.as_str(),
                    a.actor,
                    a.reason_code,
                    opt_uuid_of((a.decision_id != [0; 16]).then_some(a.decision_id), |d| &d,),
                    null_time(a.decided_at),
                    row.version,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update approval")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
                Ok(())
            }
            Some(_) => Err(conflict("VERSION_CONFLICT")),
        }
    }

    async fn apply_checkpoint(
        tx: &mut Transaction<'_, Postgres>,
        c: &central_execution::domain::Checkpoint,
    ) -> Result<(), Failure> {
        sqlx::query!(
            "INSERT INTO central.checkpoints (\
             id, workspace_id, task_id, run_id, step_id, step_attempt_id, \
             producer_id, producer_version, schema_version, checksum, payload, \
             resume_compatible, validated, policy_version, recorded_at, \
             eligible_after, legal_hold, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 1, \
             clock_timestamp(), clock_timestamp() + interval '90 days', false, \
             clock_timestamp()) \
             ON CONFLICT (id) DO NOTHING",
            uuid_of(c.id.as_bytes()),
            uuid_of(c.workspace_id.as_bytes()),
            uuid_of(c.task_id.as_bytes()),
            uuid_of(c.run_id.as_bytes()),
            uuid_of(c.step_id.as_bytes()),
            uuid_of(c.step_attempt_id.as_bytes()),
            "",
            c.producer_version,
            c.schema_version,
            &c.checksum[..],
            &c.payload[..],
            c.resume_compatible,
            c.validated,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: insert checkpoint")?;
        Ok(())
    }

    /// `applySettlements` — the durable outcome/context lives on the
    /// attempt row (B08 columns `outcome`/`context`, bounded 256 KiB).
    async fn apply_settlement(
        tx: &mut Transaction<'_, Postgres>,
        s: &central_execution::domain::Settlement,
    ) -> Result<(), Failure> {
        let outcome = serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&s.outcome))
            .unwrap_or_default();
        let context = (!s.context.is_empty()).then(|| {
            serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&s.context))
                .unwrap_or_default()
        });
        sqlx::query!(
            "UPDATE central.step_attempts \
             SET outcome = $6::jsonb, context = COALESCE($7::jsonb, context), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5",
            uuid_of(s.workspace_id.as_bytes()),
            uuid_of(s.task_id.as_bytes()),
            uuid_of(s.run_id.as_bytes()),
            uuid_of(s.step_id.as_bytes()),
            uuid_of(s.attempt_id.as_bytes()),
            outcome,
            context,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: apply settlement")?;
        Ok(())
    }

    async fn apply_tool_settlement(
        tx: &mut Transaction<'_, Postgres>,
        s: &central_execution::domain::ToolSettlement,
    ) -> Result<(), Failure> {
        let outcome = serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&s.outcome))
            .unwrap_or_default();
        let context = (!s.context.is_empty()).then(|| {
            serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&s.context))
                .unwrap_or_default()
        });
        sqlx::query!(
            "UPDATE central.tool_call_attempts \
             SET outcome = $7::jsonb, context = COALESCE($8::jsonb, context), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_attempt_id = $4 AND tool_call_id = $5 AND id = $6",
            uuid_of(s.workspace_id.as_bytes()),
            uuid_of(s.task_id.as_bytes()),
            uuid_of(s.run_id.as_bytes()),
            uuid_of(s.attempt_id.as_bytes()),
            uuid_of(s.tool_call_id.as_bytes()),
            uuid_of(s.tool_attempt_id.as_bytes()),
            outcome,
            context,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: apply tool settlement")?;
        Ok(())
    }

    /// `applyLeases` — insert / claim-expired / heartbeat per durable
    /// lease fact, fenced by the change-set generation.
    async fn apply_lease(
        tx: &mut Transaction<'_, Postgres>,
        scope: &TrustedScope,
        lease: &Lease,
    ) -> Result<(), Failure> {
        let persisted =
            read_persisted_lease_for_update(tx, lease.workspace_id, lease.run_id).await?;
        let (w, r) = (
            uuid_of(lease.workspace_id.as_bytes()),
            uuid_of(lease.run_id.as_bytes()),
        );
        let verifier = sha256(&lease.credential.0);
        match persisted {
            None => {
                sqlx::query!(
                    "INSERT INTO central.execution_ownership (\
                     id, workspace_id, owner_scope, owner_identity, heartbeat_at, \
                     claimed_run_id, claimed_step_id, claimed_step_attempt_id, \
                     run_id, lease_token_hash, fencing_generation, lease_expires_at, \
                     created_at, updated_at) \
                     VALUES ($1, $2, 'execution', $3, clock_timestamp(), \
                     $4, $5, $6, $4, $7, $8, $9, clock_timestamp(), clock_timestamp())",
                    uuid::Uuid::now_v7(),
                    w,
                    scope.principal_id,
                    r,
                    Option::<uuid::Uuid>::None,
                    Option::<uuid::Uuid>::None,
                    &verifier[..],
                    lease.generation,
                    lease.expires_at,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert lease")?;
                Ok(())
            }
            Some(row) if ct_eq(&verifier, &row.verifier) && row.generation == lease.generation => {
                let done = sqlx::query!(
                    "UPDATE central.execution_ownership \
                     SET heartbeat_at = clock_timestamp(), lease_expires_at = $3, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND run_id = $2 \
                     AND lease_token_hash = $4 AND fencing_generation = $5 \
                     AND lease_expires_at > clock_timestamp()",
                    w,
                    r,
                    lease.expires_at,
                    &verifier[..],
                    lease.generation,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: heartbeat lease")?
                .rows_affected();
                if done != 1 {
                    return Err(denied("LEASE_FENCED"));
                }
                Ok(())
            }
            Some(row) => {
                // Fencing take-over is only legal past expiry.
                let done = sqlx::query!(
                    "UPDATE central.execution_ownership \
                     SET owner_identity = $3, heartbeat_at = clock_timestamp(), \
                     claimed_step_id = $4, claimed_step_attempt_id = $5, \
                     lease_token_hash = $6, fencing_generation = $7, \
                     lease_expires_at = $8, updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND run_id = $2 \
                     AND fencing_generation = $9 \
                     AND lease_expires_at <= clock_timestamp()",
                    w,
                    r,
                    scope.principal_id,
                    opt_step_uuid(row.step_id),
                    opt_attempt_uuid(row.attempt_id),
                    &verifier[..],
                    lease.generation,
                    lease.expires_at,
                    row.generation,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: claim expired lease")?
                .rows_affected();
                if done != 1 {
                    return Err(denied("LEASE_FENCED"));
                }
                Ok(())
            }
        }
    }

    async fn apply_lease_release(
        tx: &mut Transaction<'_, Postgres>,
        release: &central_execution::domain::LeaseRelease,
    ) -> Result<(), Failure> {
        let verifier = sha256(&release.credential.0);
        let done = sqlx::query!(
            "UPDATE central.execution_ownership \
             SET claimed_run_id = run_id, claimed_step_id = NULL, \
             claimed_step_attempt_id = NULL, owner_scope = NULL, owner_identity = NULL, \
             heartbeat_at = clock_timestamp(), lease_expires_at = clock_timestamp(), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND run_id = $2 \
             AND lease_token_hash = $3 AND fencing_generation = $4 \
             AND lease_expires_at > clock_timestamp()",
            uuid_of(release.workspace_id.as_bytes()),
            uuid_of(release.run_id.as_bytes()),
            &verifier[..],
            release.generation,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: release lease")?
        .rows_affected();
        if done != 1 {
            return Err(denied("LEASE_FENCED"));
        }
        Ok(())
    }

    async fn apply_lease_assertion(
        tx: &mut Transaction<'_, Postgres>,
        assertion: &central_execution::domain::LeaseAssertion,
    ) -> Result<(), Failure> {
        if !assertion.no_active {
            return Ok(());
        }
        let row = sqlx::query!(
            "SELECT NOT EXISTS ( \
               SELECT 1 FROM central.execution_ownership \
               WHERE workspace_id = $1 AND run_id = $2 \
               AND lease_expires_at > clock_timestamp() \
             ) AS \"ok!\"",
            uuid_of(assertion.workspace_id.as_bytes()),
            uuid_of(assertion.run_id.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("execution: assert no active lease")?;
        if !row.ok {
            return Err(conflict("LEASE_ACTIVE"));
        }
        Ok(())
    }

    async fn apply_attempt_assertion(
        tx: &mut Transaction<'_, Postgres>,
        a: &StepAttemptAssertion,
    ) -> Result<(), Failure> {
        let row = sqlx::query!(
            "SELECT 1 AS one FROM central.step_attempts \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5 AND logical_operation_id = $6 \
             AND version = $7 AND state = $8 FOR UPDATE",
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.task_id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
            uuid_of(a.step_id.as_bytes()),
            uuid_of(a.id.as_bytes()),
            uuid_for_logical(&a.logical_operation_id),
            a.version,
            a.state.as_str(),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: assert attempt")?;
        if row.is_none() {
            return Err(conflict("VERSION_CONFLICT"));
        }
        Ok(())
    }

    /// `applyTaskTransition` — embedded task change set with the same
    /// CAS + event insertion the task adapter performs.
    async fn apply_task_transition(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        change_set: &TaskChangeSet,
    ) -> Result<(), Failure> {
        let (w, t) = (
            uuid_of(ws.as_bytes()),
            uuid_of(change_set.task.id.as_bytes()),
        );
        let task = &change_set.task;
        let done = sqlx::query!(
            "UPDATE central.tasks \
             SET version = $3, status = $4, current_run_id = $5, \
             last_run_index = $6, retry_count = $7, retry_eligible_at = $8, \
             waiting_reason = NULLIF($9, ''), failure_reason = NULLIF($10, ''), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND version = $11",
            w,
            t,
            task.version,
            task.status.as_str(),
            opt_uuid_of(task.current_run_id, |i| i.as_bytes()),
            task.last_run_index,
            task.retry_count,
            null_time(task.retry_eligible_at.unwrap_or(ZERO_TIME)),
            wait_reason_value(task.waiting_reason),
            task.failure_reason,
            change_set.expected_task_version,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: apply task transition")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }
        for run in &change_set.runs {
            let expected = change_set
                .run_expected_versions
                .get(&run.id)
                .copied()
                .unwrap_or(0);
            if expected <= 0 {
                sqlx::query!(
                    "INSERT INTO central.runs (\
                     id, workspace_id, task_id, version, status, run_index, \
                     waiting_reason, failure_reason, ownership_token, \
                     run_key, request_fingerprint, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), \
                     NULLIF($9, ''), NULLIF($10, ''), $11, \
                     clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (id) DO NOTHING",
                    uuid_of(run.id.as_bytes()),
                    w,
                    t,
                    run.version,
                    run.status.as_str(),
                    run.index,
                    wait_reason_value(run.waiting_reason),
                    run.failure_reason,
                    run.ownership_token,
                    run.run_key,
                    run.request_fingerprint.as_ref().map(|f| &f[..]),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert transitioned run")?;
            } else {
                let done = sqlx::query!(
                    "UPDATE central.runs \
                     SET version = $4, status = $5, run_index = $6, \
                     waiting_reason = NULLIF($7, ''), failure_reason = NULLIF($8, ''), \
                     ownership_token = NULLIF($9, ''), updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 \
                     AND id = $3 AND version = $10",
                    w,
                    t,
                    uuid_of(run.id.as_bytes()),
                    run.version,
                    run.status.as_str(),
                    run.index,
                    wait_reason_value(run.waiting_reason),
                    run.failure_reason,
                    run.ownership_token,
                    expected,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update transitioned run")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("VERSION_CONFLICT"));
                }
            }
        }
        // Task lifecycle events ride the same event_sequence lane.
        for intent in &change_set.events {
            let sequence = reserve_event_sequence(tx, ws).await?;
            let payload = event_intent_payload(intent);
            sqlx::query!(
                "INSERT INTO central.events (\
                 id, workspace_id, event_sequence, event_type, aggregate_id, \
                 aggregate_version, command_id, run_id, payload, \
                 occurred_at, task_id, kind, state, producer_id, \
                 policy_version, eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, \
                 clock_timestamp(), $5, $4, 'recorded', \
                 'central.task.lifecycle.v1', 1, \
                 clock_timestamp() + interval '90 days', false)",
                uuid::Uuid::now_v7(),
                w,
                sequence,
                intent.kind.as_str(),
                t,
                task.version,
                opt_uuid_of(intent.run_id, |i| i.as_bytes()),
                payload,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: insert task event")?;
        }
        Ok(())
    }

    /// `applyEvents` — one sequence reservation per intent; the
    /// `(workspace, sequence)` unique index is the order proof.
    async fn apply_events(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        aggregate_version: i64,
        producer: &str,
        events: &[EventIntent],
    ) -> Result<(), Failure> {
        let w = uuid_of(ws.as_bytes());
        for intent in events {
            let sequence = reserve_event_sequence(tx, ws).await?;
            sqlx::query!(
                "INSERT INTO central.events (\
                 id, workspace_id, event_sequence, event_type, aggregate_id, \
                 aggregate_version, command_id, run_id, payload, occurred_at, \
                 task_id, step_id, attempt_id, kind, state, producer_id, \
                 policy_version, eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8::jsonb, \
                 clock_timestamp(), $5, $9, $10, $4, 'recorded', $11, 1, \
                 clock_timestamp() + interval '90 days', false)",
                uuid_of(intent.id.as_bytes()),
                w,
                sequence,
                intent.kind,
                uuid_of(intent.task_id.as_bytes()),
                aggregate_version,
                opt_run_uuid(intent.run_id),
                serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&intent.payload))
                    .unwrap_or_default(),
                opt_step_uuid(intent.step_id),
                opt_attempt_uuid(intent.attempt_id),
                producer,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: insert event")?;
        }
        Ok(())
    }

    /// `applyOutbox` — pending rows dedup'd by
    /// `(workspace, catalog_type, deduplication_key)`; a conflicting row
    /// is a caller-visible conflict, and each touched workspace's
    /// scheduler row moves in the same transaction.
    async fn apply_outbox(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        intents: &[OutboxIntent],
    ) -> Result<(), Failure> {
        let w = uuid_of(ws.as_bytes());
        let mut touched = std::collections::BTreeSet::new();
        for intent in intents {
            let done = sqlx::query!(
                "INSERT INTO central.outbox (\
                 id, workspace_id, event_id, delivery_state, due_at, attempt_count, \
                 created_at, updated_at, catalog_type, deduplication_key, \
                 producer_id, payload, visible_at, policy_version, \
                 eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, 'pending', clock_timestamp(), 0, \
                 clock_timestamp(), clock_timestamp(), $4, $5, $6, $7::jsonb, \
                 clock_timestamp(), 1, clock_timestamp() + interval '7 days', false)",
                uuid_of(intent.id.as_bytes()),
                w,
                uuid_of(intent.event_id.as_bytes()),
                intent.catalog_type,
                intent.deduplication_key,
                intent.producer_id,
                serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&intent.payload))
                    .unwrap_or_default(),
            )
            .execute(&mut **tx)
            .await;
            match done {
                Ok(r) => {
                    touched.insert(intent.workspace_id);
                    let _ = r;
                }
                Err(e) => return Err(classify_sqlx(&e)),
            }
        }
        for workspace in touched {
            sqlx::query!(
                "INSERT INTO central.outbox_workspace_work (workspace_id, next_visible_at) \
                 VALUES ($1, clock_timestamp()) \
                 ON CONFLICT (workspace_id) DO UPDATE \
                 SET next_visible_at = LEAST(\
                   central.outbox_workspace_work.next_visible_at, \
                   EXCLUDED.next_visible_at), \
                 version = central.outbox_workspace_work.version + 1",
                uuid_of(workspace.as_bytes()),
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: upsert outbox workspace work")?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Recovery coordinator helpers.
    // -----------------------------------------------------------------

    /// `lockRecoveryCoordinator` — validates the presented lease
    /// (domain + instance + fence + verifier + unexpired) and locks it.
    async fn lock_recovery_coordinator(
        tx: &mut Transaction<'_, Postgres>,
        lease: &RecoveryCoordinatorLease,
    ) -> Result<(), Failure> {
        let verifier = sha256(&lease.claim_token);
        let row = sqlx::query!(
            "SELECT fencing_generation FROM central.recovery_coordinators \
             WHERE recovery_domain = $1 AND instance_id = $2 \
             AND fencing_generation = $3 AND state = 'claimed' \
             AND lease_token_hash = $4 \
             AND lease_expires_at > clock_timestamp() FOR UPDATE",
            lease.recovery_domain,
            lease.instance_id.to_string(),
            lease.fence.generation,
            &verifier[..],
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock recovery coordinator")?;
        if row.is_none() {
            return Err(denied("RECOVERY_COORDINATOR_FENCED"));
        }
        Ok(())
    }

    /// `renewRecoveryCoordinator` — extends the held lease inside the
    /// fencing transaction.
    async fn renew_recovery_coordinator(
        tx: &mut Transaction<'_, Postgres>,
        lease: &RecoveryCoordinatorLease,
    ) -> Result<OffsetDateTime, Failure> {
        let verifier = sha256(&lease.claim_token);
        let row = sqlx::query!(
            "UPDATE central.recovery_coordinators \
             SET lease_expires_at = clock_timestamp() + interval '30 seconds', \
             updated_at = clock_timestamp() \
             WHERE recovery_domain = $1 AND instance_id = $2 \
             AND fencing_generation = $3 AND state = 'claimed' \
             AND lease_token_hash = $4 \
             RETURNING lease_expires_at",
            lease.recovery_domain,
            lease.instance_id.to_string(),
            lease.fence.generation,
            &verifier[..],
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: renew recovery coordinator")?;
        row.map(|r| r.lease_expires_at)
            .ok_or_else(|| denied("RECOVERY_COORDINATOR_FENCED"))
    }

    /// `scanRecoveryWorkspace` — the adapter-owned bounded keyset scan:
    /// reconciles every pre-watermark run in the claimed workspace.
    async fn scan_recovery_workspace(
        tx: &mut Transaction<'_, Postgres>,
        generation: i64,
        work: &RecoveryWorkspaceWork,
        cursor_created_at: Option<OffsetDateTime>,
        cursor_run_id: Option<uuid::Uuid>,
        claim_hash: &[u8; 32],
        domain: &str,
    ) -> Result<(), Failure> {
        let ws = uuid_of(work.workspace_id.as_bytes());
        // A NULL cursor means the scan starts from the watermark's
        // first run (upstream `cursor IS NULL` predicate arm).
        let mut cursor_at = cursor_created_at;
        let mut cursor_run = cursor_run_id;
        loop {
            let runs = sqlx::query!(
                "SELECT r.id, r.task_id, r.created_at, r.version \
                 FROM central.runs r \
                 JOIN central.recovery_epoch_workspaces w \
                   ON w.epoch_generation = $1 AND w.workspace_id = r.workspace_id \
                 JOIN central.recovery_epochs e \
                   ON e.epoch_generation = w.epoch_generation AND e.coordinator_domain = $6 \
                 WHERE r.workspace_id = $2 AND r.reconciled_epoch < $1 \
                   AND (r.created_at < w.watermark_created_at \
                        OR (r.created_at = w.watermark_created_at AND r.id <= w.watermark_run_id)) \
                   AND ($3::timestamptz IS NULL \
                        OR r.created_at > $3::timestamptz \
                        OR (r.created_at = $3::timestamptz AND r.id > $4::uuid)) \
                 ORDER BY r.created_at, r.id LIMIT $5",
                generation,
                ws,
                cursor_at,
                cursor_run,
                RECOVERY_SCAN_BATCH,
                domain,
            )
            .fetch_all(&mut **tx)
            .await
            .ctx("execution: select recovery runs")?;
            if runs.is_empty() {
                return Ok(());
            }
            for run in &runs {
                Self::reconcile_recovery_run(tx, generation, work.workspace_id, run.id, domain)
                    .await?;
                let done = sqlx::query!(
                    "UPDATE central.runs \
                     SET reconciled_epoch = $1, updated_at = clock_timestamp() \
                     WHERE workspace_id = $2 AND id = $3 \
                     AND reconciled_epoch < $1 \
                     AND EXISTS (SELECT 1 FROM central.recovery_epochs epoch \
                       WHERE epoch.epoch_generation = $1 AND epoch.coordinator_domain = $4)",
                    generation,
                    ws,
                    run.id,
                    domain,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: mark run reconciled")?;
                if done.rows_affected() == 0 {
                    return Err(conflict("STALE_RECOVERY_FENCE"));
                }
                sqlx::query!(
                    "UPDATE central.recovery_epoch_workspaces AS work \
                     SET cursor_created_at = $4, cursor_run_id = $5, \
                     scanned_count = scanned_count + 1, \
                     reconciled_count = reconciled_count + 1, \
                     claim_expires_at = clock_timestamp() + interval '30 seconds', \
                     retry_not_before = NULL, failure_class = NULL, failure_reason = NULL, \
                     updated_at = clock_timestamp() \
                     WHERE work.epoch_generation = $1 AND work.workspace_id = $2 \
                     AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
                     AND EXISTS (SELECT 1 FROM central.recovery_epochs epoch \
                       WHERE epoch.epoch_generation = work.epoch_generation \
                         AND epoch.coordinator_domain = $6)",
                    generation,
                    ws,
                    &claim_hash[..],
                    run.created_at,
                    run.id,
                    domain,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: advance recovery scan")?;
                cursor_at = Some(run.created_at);
                cursor_run = Some(run.id);
            }
        }
    }

    /// `reconcileRun` — one pre-watermark run: cancel its prepared
    /// successor or quarantine the live attempt/step/tool chain, expire
    /// the run lease past its grace, then mark task+run waiting on
    /// reconciliation.
    async fn reconcile_recovery_run(
        tx: &mut Transaction<'_, Postgres>,
        _generation: i64,
        workspace_id: WorkspaceId,
        run_id: uuid::Uuid,
        _domain: &str,
    ) -> Result<(), Failure> {
        let ws = uuid_of(workspace_id.as_bytes());
        // The newest live attempt candidate decides the disposition.
        let candidate = sqlx::query!(
            "SELECT a.id, a.step_id FROM central.step_attempts a \
             WHERE a.workspace_id = $1 AND a.run_id = $2 \
             AND a.state IN ('prepared','invoked','settling','reconciliation') \
             ORDER BY a.updated_at DESC, a.id DESC LIMIT 1",
            ws,
            run_id,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read recovery attempt candidate")?;
        // The lease grace (expiry + 5s) must have passed before the run
        // can be rewritten — otherwise the row waits.
        let lease = sqlx::query!(
            "SELECT lease_expires_at, clock_timestamp() AS \"now!\" \
             FROM central.execution_ownership \
             WHERE workspace_id = $1 AND run_id = $2 \
             AND lease_expires_at + interval '5 seconds' > clock_timestamp() \
             FOR UPDATE",
            ws,
            run_id,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read recovery lease")?;
        if lease.is_some() {
            return Err(conflict("RECOVERY_LEASE_GRACE"));
        }
        if let Some(c) = candidate {
            sqlx::query!(
                "UPDATE central.step_attempts \
                 SET state = 'cancelled', version = version + 1, \
                 updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND run_id = $2 AND id = $3 AND state = 'prepared'",
                ws,
                run_id,
                c.id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: cancel prepared attempt")?;
            sqlx::query!(
                "UPDATE central.step_attempts \
                 SET state = 'reconciliation', version = version + 1, \
                 updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND run_id = $2 AND id = $3 \
                 AND state IN ('invoked','settling')",
                ws,
                run_id,
                c.id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: reconcile attempt")?;
            sqlx::query!(
                "UPDATE central.steps \
                 SET state = 'cancelled', version = version + 1, \
                 updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND run_id = $2 AND id = $3 \
                 AND state IN ('queued','running','waiting')",
                ws,
                run_id,
                c.step_id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: cancel prepared step")?;
            sqlx::query!(
                "UPDATE central.steps \
                 SET state = 'reconciliation', version = version + 1, \
                 updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND run_id = $2 AND id = $3 \
                 AND state <> 'reconciliation' AND state <> 'cancelled'",
                ws,
                run_id,
                c.step_id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: reconcile step")?;
            sqlx::query!(
                "UPDATE central.tool_call_attempts \
                 SET state = 'reconciliation', version = version + 1, \
                 updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND run_id = $2 \
                 AND state IN ('invoked','settling')",
                ws,
                run_id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: reconcile tool attempts")?;
            sqlx::query!(
                "UPDATE central.tool_calls \
                 SET state = 'reconciliation', version = version + 1, \
                 updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND run_id = $2 \
                 AND state IN ('invoked','settling')",
                ws,
                run_id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: reconcile tool calls")?;
        }
        sqlx::query!(
            "UPDATE central.execution_ownership \
             SET claimed_run_id = run_id, claimed_step_id = NULL, \
             claimed_step_attempt_id = NULL, owner_scope = NULL, owner_identity = NULL, \
             heartbeat_at = clock_timestamp(), lease_expires_at = clock_timestamp(), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND run_id = $2 \
             AND lease_expires_at + interval '5 seconds' <= clock_timestamp()",
            ws,
            run_id,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: expire recovery lease")?;
        // Task + run wait on reconciliation (version bumps only on an
        // actual state change — upstream's conditional increment).
        let task_id = sqlx::query!(
            "SELECT task_id FROM central.runs WHERE workspace_id = $1 AND id = $2",
            ws,
            run_id,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read run task")?;
        sqlx::query!(
            "UPDATE central.tasks \
             SET status = 'waiting', waiting_reason = 'reconciliation', \
             version = version + CASE \
               WHEN status = 'waiting' AND waiting_reason = 'reconciliation' THEN 0 ELSE 1 END, \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 \
             AND status IN ('queued','running','waiting')",
            ws,
            task_id.map(|t| t.task_id).unwrap_or_default(),
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: wait recovery task")?;
        sqlx::query!(
            "UPDATE central.runs \
             SET status = 'waiting', waiting_reason = 'reconciliation', \
             version = version + CASE \
               WHEN status = 'waiting' AND waiting_reason = 'reconciliation' THEN 0 ELSE 1 END, \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 \
             AND status IN ('queued','running','waiting')",
            ws,
            run_id,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: wait recovery run")?;
        Ok(())
    }
}

struct ReceiptRow {
    request_fingerprint: Vec<u8>,
    principal_id: String,
    capability: String,
    expected_version_digest: Vec<u8>,
    result_reference: uuid::Uuid,
    result_payload: serde_json::Value,
    task_id: Option<uuid::Uuid>,
    run_id: Option<uuid::Uuid>,
    step_id: Option<uuid::Uuid>,
    step_attempt_id: Option<uuid::Uuid>,
    logical_operation_id: Option<uuid::Uuid>,
}

fn binding_task_ws(payload: &serde_json::Value) -> Result<WorkspaceId, Failure> {
    payload
        .get("WorkspaceID")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .map(|u| WorkspaceId::from_trusted_db_bytes(*u.as_bytes()))
        .ok_or_else(|| corrupt("a stored receipt payload is missing WorkspaceID"))
}

fn epoch_state(state: &str) -> RecoveryEpochState {
    match state {
        "open" => RecoveryEpochState::RecoveryEpochOpen,
        "running" => RecoveryEpochState::RecoveryEpochRunning,
        "degraded" => RecoveryEpochState::RecoveryEpochDegraded,
        "completed" => RecoveryEpochState::RecoveryEpochCompleted,
        _ => RecoveryEpochState::RecoveryEpochFailed,
    }
}

fn work_state(state: &str) -> RecoveryWorkspaceState {
    match state {
        "claimed" => RecoveryWorkspaceState::RecoveryWorkspaceClaimed,
        "completed" => RecoveryWorkspaceState::RecoveryWorkspaceCompleted,
        "failed" => RecoveryWorkspaceState::RecoveryWorkspaceFailed,
        _ => RecoveryWorkspaceState::RecoveryWorkspacePending,
    }
}

impl CompositeStore for Store {
    /// `IssueLeaseCredential` — mints the raw 256-bit bearer; only its
    /// SHA-256 verifier is ever persisted.
    fn issue_lease_credential(&self) -> Result<LeaseCredential, Failure> {
        let (raw, _verifier) = new_lease_secret()?;
        LeaseCredential::new(&raw)
    }

    /// `Commit` — the atomic fenced commit (see module docs for the
    /// lock order). Receipt replay returns `replayed: true`.
    async fn commit(&self, request: CommitRequest) -> Result<CommitResult, Failure> {
        // CommitRequest.validate (upstream Validate): scope/key/fence.
        if request.scope.workspace_id.is_nil()
            || request.command_scope.trim().is_empty()
            || request.idempotency_key.trim().is_empty()
            || request.principal_id != request.scope.principal_id
            || request.receipt_binding.task_id.is_nil()
        {
            return Err(invalid("INVALID_COMMIT_REQUEST"));
        }
        if request.lease_credential.valid() == (request.lease_generation <= 0)
            || (request.lease_credential.valid() && request.assert_no_active_lease)
        {
            return Err(invalid("INVALID_COMMAND_FENCE"));
        }
        let ws = request.scope.workspace_id;
        let binding = &request.receipt_binding;
        let expected = request.expected_versions;
        let digest = expected_digest(&expected);

        let mut tx = begin(&self.pool).await?;
        Self::lock_receipt_identity(
            &mut tx,
            ws,
            &request.command_scope,
            &request.idempotency_key,
        )
        .await?;
        // Exact replay — the receipt row is the durable result.
        if let Some(row) = Self::read_receipt(
            &mut tx,
            ws,
            &request.command_scope,
            &request.idempotency_key,
        )
        .await?
        {
            if !Self::receipt_matches(
                &row,
                &request.fingerprint,
                &request.principal_id,
                request.capability,
                &digest,
                binding,
            ) {
                return Err(conflict("REASON_REQUEST_CONFLICT"));
            }
            let payload = row.result_payload.clone();
            let result = Self::decode_result_payload(&payload, binding, row.result_reference, "")?;
            // Recover the stored event kind for the replayed result.
            let kind = sqlx::query!(
                "SELECT kind FROM central.events WHERE workspace_id = $1 AND id = $2",
                uuid_of(ws.as_bytes()),
                row.result_reference,
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("execution: read receipt event")?
            .map(|r| r.kind)
            .unwrap_or_default();
            tx.commit().await.ctx("execution: commit replay")?;
            return Ok(CommitResult {
                result: DurableResult {
                    event_kind: kind,
                    ..result
                },
                replayed: true,
            });
        }
        // Lock order step 1: workspace event counter (also proves the
        // workspace row exists via FK).
        lock_event_counter(&mut tx, ws).await.map_err(|e| {
            if e.code() == crate::error::codes::PG_FOREIGN_KEY_VIOLATION {
                conflict("WORKSPACE_NOT_FOUND")
            } else {
                e
            }
        })?;
        // Tasks → runs.
        let task = read_task(&mut tx, ws, binding.task_id, true).await?;
        if expected.task > 0 && task.version != expected.task {
            return Err(conflict("VERSION_CONFLICT"));
        }
        let run = read_run(&mut tx, ws, binding.task_id, binding.run_id, true).await?;
        if expected.run > 0 && run.version != expected.run {
            return Err(conflict("VERSION_CONFLICT"));
        }
        // Command fence policy.
        if request.require_recovery_claimable {
            Self::enforce_recovery_claim_admission(&mut tx, ws, binding.task_id, binding.run_id)
                .await?;
        }
        if request.lease_credential.valid() {
            Self::enforce_lease_fence(
                &mut tx,
                ws,
                binding.run_id,
                binding.step_id,
                binding.attempt_id,
                &request.lease_credential,
                request.lease_generation,
            )
            .await?;
        }
        if request.assert_no_active_lease {
            Self::apply_lease_assertion(
                &mut tx,
                &central_execution::domain::LeaseAssertion {
                    workspace_id: ws,
                    run_id: binding.run_id,
                    no_active: true,
                },
            )
            .await?;
        }
        // Expected-version guards on the rest of the binding.
        if expected.step > 0 && !binding.step_id.is_nil() {
            let v = Self::lock_step_target(
                &mut tx,
                ws,
                binding.task_id,
                binding.run_id,
                binding.step_id,
            )
            .await?;
            if v != expected.step {
                return Err(conflict("VERSION_CONFLICT"));
            }
        }
        if expected.attempt > 0 && !binding.attempt_id.is_nil() {
            let v = Self::lock_attempt_target(
                &mut tx,
                ws,
                binding.task_id,
                binding.run_id,
                binding.step_id,
                binding.attempt_id,
            )
            .await?;
            if v != expected.attempt {
                return Err(conflict("VERSION_CONFLICT"));
            }
        }
        // Change set — the documented order.
        let cs = &request.change_set;
        if let Some(transition) = &cs.task_transition {
            Self::apply_task_transition(&mut tx, ws, &transition.change_set).await?;
        }
        for step in &cs.steps {
            Self::apply_step(&mut tx, step).await?;
        }
        for attempt in &cs.attempts {
            Self::apply_attempt(&mut tx, attempt).await?;
        }
        for call in &cs.tool_calls {
            Self::apply_tool_call(&mut tx, call).await?;
        }
        for attempt in &cs.tool_attempts {
            Self::apply_tool_attempt(&mut tx, attempt).await?;
        }
        for approval in &cs.approvals {
            Self::apply_approval(&mut tx, approval).await?;
        }
        for checkpoint in &cs.checkpoints {
            Self::apply_checkpoint(&mut tx, checkpoint).await?;
        }
        for settlement in &cs.settlements {
            Self::apply_settlement(&mut tx, settlement).await?;
        }
        for settlement in &cs.tool_settlements {
            Self::apply_tool_settlement(&mut tx, settlement).await?;
        }
        // Reconciliation records are carried by the emitted events;
        // the state transitions they cause are already in steps/attempts.
        for lease in &cs.leases {
            Self::apply_lease(&mut tx, &request.scope, lease).await?;
        }
        for release in &cs.lease_releases {
            Self::apply_lease_release(&mut tx, release).await?;
        }
        for assertion in &cs.lease_assertions {
            Self::apply_lease_assertion(&mut tx, assertion).await?;
        }
        for assertion in &cs.attempt_assertions {
            Self::apply_attempt_assertion(&mut tx, assertion).await?;
        }
        let aggregate_version = cs
            .task_transition
            .as_ref()
            .map_or(task.version, |t| t.change_set.task.version);
        Self::apply_events(
            &mut tx,
            ws,
            aggregate_version,
            &request.principal_id,
            &cs.events,
        )
        .await?;
        Self::apply_outbox(&mut tx, ws, &cs.outbox).await?;
        Self::insert_receipt(&mut tx, &request, digest).await?;
        tx.commit().await.ctx("execution: commit")?;
        Ok(CommitResult {
            result: request.result,
            replayed: false,
        })
    }
}

impl ExecutionRead for Store {
    /// `ReadExecution` — the authoritative snapshot; missing optional
    /// rows are `None`/empty, a missing task or run is a conflict.
    async fn read_execution(
        &self,
        request: ExecutionReadRequest,
    ) -> Result<ExecutionReadResult, Failure> {
        let ws = request.workspace_id;
        if ws.is_nil() || ws != request.scope.workspace_id {
            return Err(invalid("INVALID_READ_REQUEST"));
        }
        let mut tx = begin(&self.pool).await?;
        let task = read_task(&mut tx, ws, request.task_id, false).await?;
        // `run_id` absent selects the task's current run (upstream
        // readExecution treats a nil selector as "current").
        let run_id = if request.run_id.is_nil() {
            task.current_run_id
                .unwrap_or_else(|| RunId::from_trusted_db_bytes([0; 16]))
        } else {
            request.run_id
        };
        let run = if run_id.is_nil() {
            None
        } else {
            Some(read_run(&mut tx, ws, request.task_id, run_id, false).await?)
        };
        let step = if request.step_id.is_nil() {
            None
        } else {
            Some(read_step(&mut tx, ws, request.task_id, run_id, request.step_id, false).await?)
        };
        let attempt = if request.attempt_id.is_nil() {
            None
        } else {
            Some(
                read_attempt(
                    &mut tx,
                    ws,
                    request.task_id,
                    run_id,
                    request.step_id,
                    request.attempt_id,
                    false,
                )
                .await?,
            )
        };
        let tool_calls = match &attempt {
            Some(a) => read_tool_calls(&mut tx, ws, a.id).await?,
            None => Vec::new(),
        };
        let tool_attempts = match &attempt {
            Some(a) => read_tool_attempts(&mut tx, ws, a.id).await?,
            None => Vec::new(),
        };
        let lease = super::queries::read_lease(&mut tx, ws, run_id, false)
            .await
            .ok()
            .filter(|l| l.generation > 0);
        let approval = if request.step_id.is_nil() {
            None
        } else {
            super::queries::read_approval(&mut tx, ws, request.task_id, run_id, request.step_id)
                .await?
        };
        tx.commit().await.ctx("execution: commit read")?;
        Ok(ExecutionReadResult {
            state: ExecutionState {
                task: central_task::domain::TaskAggregate {
                    task,
                    current_run: run,
                },
                step,
                attempt,
                tool_calls,
                tool_attempts,
                lease,
                approval,
            },
        })
    }
}

impl CompositeExecutionStore for Store {
    /// `LookupReceipt` — the pre-read replay path; identical identity
    /// lock + equality rules as `Commit`'s replay check.
    async fn lookup_receipt(
        &self,
        request: ReceiptLookupRequest,
    ) -> Result<ReceiptLookupResult, Failure> {
        let ws = request.scope.workspace_id;
        if ws.is_nil()
            || request.command_scope.trim().is_empty()
            || request.idempotency_key.trim().is_empty()
        {
            return Err(invalid("INVALID_RECEIPT_LOOKUP"));
        }
        let mut tx = begin(&self.pool).await?;
        Self::lock_receipt_identity(
            &mut tx,
            ws,
            &request.command_scope,
            &request.idempotency_key,
        )
        .await?;
        let Some(row) = Self::read_receipt(
            &mut tx,
            ws,
            &request.command_scope,
            &request.idempotency_key,
        )
        .await?
        else {
            tx.commit().await.ctx("execution: commit lookup")?;
            return Ok(ReceiptLookupResult::default());
        };
        let digest = expected_digest(&request.expected_versions);
        if !Self::receipt_matches(
            &row,
            &request.fingerprint,
            &request.principal_id,
            request.capability,
            &digest,
            &request.binding,
        ) {
            return Err(conflict("REASON_REQUEST_CONFLICT"));
        }
        let event = sqlx::query!(
            "SELECT kind FROM central.events WHERE workspace_id = $1 AND id = $2",
            uuid_of(ws.as_bytes()),
            row.result_reference,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: read receipt event")?
        .ok_or_else(|| corrupt("a stored receipt references a missing event"))?;
        let payload = row.result_payload.clone();
        let result = Self::decode_result_payload(
            &payload,
            &request.binding,
            row.result_reference,
            &event.kind,
        )?;
        tx.commit().await.ctx("execution: commit lookup")?;
        Ok(ReceiptLookupResult {
            found: true,
            result: Some(result),
        })
    }
}

impl LeaseCredentialValidator for Store {
    /// `ValidateLease` — bearer + generation + expiry + claim target
    /// against the durable ownership row; the verifier never leaves.
    async fn validate_lease(&self, request: LeaseValidationRequest) -> Result<(), Failure> {
        if request.workspace_id.is_nil() || request.workspace_id != request.scope.workspace_id {
            return Err(invalid("INVALID_LEASE_VALIDATION"));
        }
        let mut tx = begin(&self.pool).await?;
        let result = Self::enforce_lease_fence(
            &mut tx,
            request.workspace_id,
            request.run_id,
            request.step_id,
            request.attempt_id,
            &request.lease_credential,
            request.lease_generation,
        )
        .await;
        if result.is_ok() {
            tx.commit().await.ctx("execution: commit validate lease")?;
        }
        result
    }
}

impl OutboxStore for Store {
    /// `PublishOutbox` — marks each committed intent's row dispatched.
    async fn publish_outbox(
        &self,
        scope: TrustedScope,
        intents: Vec<OutboxIntent>,
    ) -> Result<(), Failure> {
        if scope.workspace_id.is_nil() {
            return Err(invalid("INVALID_SCOPE"));
        }
        let mut tx = begin(&self.pool).await?;
        for intent in &intents {
            sqlx::query!(
                "UPDATE central.outbox \
                 SET delivery_state = 'dispatched', delivered_at = clock_timestamp(), \
                 updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND id = $2 \
                 AND delivery_state IN ('pending','claimed')",
                uuid_of(scope.workspace_id.as_bytes()),
                uuid_of(intent.id.as_bytes()),
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: publish outbox")?;
        }
        tx.commit().await.ctx("execution: commit publish")?;
        Ok(())
    }
}

impl B09EvidenceStore for Store {
    /// `CommitB09Evidence` — persists the completion receipt's typed
    /// references into `provider_completion_references`.
    async fn commit_b09_evidence(
        &self,
        scope: TrustedScope,
        attempt_id: StepAttemptId,
        references: Vec<B09EvidenceReference>,
    ) -> Result<(), Failure> {
        if scope.workspace_id.is_nil() || attempt_id.is_nil() {
            return Err(invalid("INVALID_B09_EVIDENCE"));
        }
        let mut tx = begin(&self.pool).await?;
        let ws = uuid_of(scope.workspace_id.as_bytes());
        // Advisory lock mirrors upstream b09ReceiptLockIdentity.
        sqlx::query!(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 8248))",
            format!("b09:{}:{}", scope.workspace_id, attempt_id),
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: lock b09 receipt identity")?;
        let receipt = sqlx::query!(
            "SELECT id FROM central.execution_completion_receipts \
             WHERE workspace_id = $1 AND step_attempt_id = $2",
            ws,
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: read completion receipt")?
        .ok_or_else(|| conflict("COMPLETION_RECEIPT_NOT_FOUND"))?;
        for reference in &references {
            sqlx::query!(
                "INSERT INTO central.provider_completion_references (\
                 workspace_id, completion_receipt_id, evidence_kind, evidence_id) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (workspace_id, completion_receipt_id, evidence_kind, evidence_id) \
                 DO NOTHING",
                ws,
                receipt.id,
                reference.kind,
                reference.id,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: insert completion reference")?;
        }
        tx.commit().await.ctx("execution: commit b09 evidence")?;
        Ok(())
    }
}

impl RecoveryStore for Store {
    /// `AcquireRecoveryCoordinator` — takes or renews the deployment
    /// lease; a held lease by another instance yields its row only
    /// past expiry (the ON CONFLICT guard raises the fence).
    async fn acquire_recovery_coordinator(
        &self,
        request: RecoveryCoordinatorAcquireRequest,
    ) -> Result<RecoveryCoordinatorLease, Failure> {
        if request.recovery_domain != RECOVERY_DOMAIN || request.instance_id.is_nil() {
            return Err(invalid("INVALID_RECOVERY_COORDINATOR_REQUEST"));
        }
        let (token, verifier) = new_lease_secret()?;
        let mut tx = begin(&self.pool).await?;
        let row = sqlx::query!(
            "INSERT INTO central.recovery_coordinators (\
             recovery_domain, instance_id, lease_token_hash, fencing_generation, \
             lease_expires_at, state, created_at, updated_at) \
             VALUES ($1, $2, $3, 1, clock_timestamp() + interval '30 seconds', \
             'claimed', clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (recovery_domain) DO UPDATE \
             SET instance_id = EXCLUDED.instance_id, \
             lease_token_hash = EXCLUDED.lease_token_hash, \
             fencing_generation = CASE \
               WHEN central.recovery_coordinators.lease_expires_at <= clock_timestamp() \
                 OR central.recovery_coordinators.instance_id <> EXCLUDED.instance_id \
               THEN central.recovery_coordinators.fencing_generation + 1 \
               ELSE central.recovery_coordinators.fencing_generation END, \
             lease_expires_at = clock_timestamp() + interval '30 seconds', \
             state = 'claimed', updated_at = clock_timestamp() \
             WHERE central.recovery_coordinators.lease_expires_at <= clock_timestamp() \
                OR central.recovery_coordinators.instance_id = EXCLUDED.instance_id \
             RETURNING fencing_generation, lease_expires_at",
            request.recovery_domain,
            request.instance_id.to_string(),
            &verifier[..],
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: acquire recovery coordinator")?;
        let Some(row) = row else {
            return Err(denied("RECOVERY_COORDINATOR_FENCED"));
        };
        tx.commit().await.ctx("execution: commit coordinator")?;
        Ok(RecoveryCoordinatorLease {
            recovery_domain: request.recovery_domain,
            instance_id: request.instance_id,
            fence: RecoveryCoordinatorFence {
                generation: row.fencing_generation,
            },
            expires_at: row.lease_expires_at,
            claim_token: token.to_vec(),
        })
    }

    /// `StartRecoveryEpoch` — REPEATABLE READ publication: adopt the
    /// latest incomplete epoch under a new fence, or mint generation
    /// `max+1` and snapshot every workspace's latest-run watermark.
    async fn start_recovery_epoch(
        &self,
        request: StartRecoveryEpochRequest,
    ) -> Result<RecoveryEpoch, Failure> {
        if request.lease.recovery_domain != RECOVERY_DOMAIN {
            return Err(invalid("INVALID_RECOVERY_EPOCH_REQUEST"));
        }
        let mut tx = begin_recovery(&self.pool).await?;
        Self::lock_recovery_coordinator(&mut tx, &request.lease).await?;
        let incomplete =
            read_incomplete_recovery_epoch(&mut tx, &request.lease.recovery_domain).await?;
        let epoch = if let Some(existing) = incomplete {
            // Take the incomplete epoch over under the held fence.
            sqlx::query!(
                "UPDATE central.recovery_epochs \
                 SET coordinator_fence = $3, updated_at = clock_timestamp() \
                 WHERE epoch_generation = $1 AND coordinator_domain = $2 \
                 AND state IN ('open','running','degraded','failed')",
                existing.generation,
                request.lease.recovery_domain,
                request.lease.fence.generation,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: take over recovery epoch")?;
            RecoveryEpoch {
                coordinator_fence: request.lease.fence,
                ..existing
            }
        } else {
            let row = sqlx::query!(
                "SELECT COALESCE(max(epoch_generation), 0) + 1 AS \"next_gen!\" \
                 FROM central.recovery_epochs",
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("execution: next epoch generation")?;
            let inserted = sqlx::query!(
                "INSERT INTO central.recovery_epochs (\
                 epoch_generation, coordinator_domain, coordinator_fence, state, \
                 snapshot_at, workspace_count, processed_count, retry_attempt, \
                 created_at, updated_at) \
                 VALUES ($1, $2, $3, 'running', clock_timestamp(), 0, 0, 0, \
                 clock_timestamp(), clock_timestamp()) \
                 RETURNING snapshot_at",
                row.next_gen,
                request.lease.recovery_domain,
                request.lease.fence.generation,
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("execution: insert recovery epoch")?;
            // Watermark every workspace by its newest run at snapshot.
            sqlx::query!(
                "INSERT INTO central.recovery_epoch_workspaces (\
                 epoch_generation, workspace_id, delivery_state, watermark_created_at, \
                 watermark_run_id, created_at, updated_at) \
                 SELECT $1, source.workspace_id, 'pending', source.created_at, source.id, \
                 clock_timestamp(), clock_timestamp() \
                 FROM ( \
                   SELECT DISTINCT ON (workspace_id) workspace_id, created_at, id \
                   FROM central.runs WHERE created_at <= $2 \
                   ORDER BY workspace_id, created_at DESC, id DESC \
                 ) AS source \
                 WHERE EXISTS ( \
                   SELECT 1 FROM central.recovery_epochs AS epoch \
                   WHERE epoch.epoch_generation = $1 AND epoch.coordinator_domain = $3) \
                 ON CONFLICT (epoch_generation, workspace_id) DO NOTHING",
                row.next_gen,
                inserted.snapshot_at,
                request.lease.recovery_domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: insert recovery watermarks")?;
            let count = sqlx::query!(
                "SELECT count(*) AS \"count!\" \
                 FROM central.recovery_epoch_workspaces AS work \
                 JOIN central.recovery_epochs AS epoch \
                   ON epoch.epoch_generation = work.epoch_generation \
                  AND epoch.coordinator_domain = $2 \
                 WHERE work.epoch_generation = $1",
                row.next_gen,
                request.lease.recovery_domain,
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("execution: count recovery workspaces")?;
            sqlx::query!(
                "UPDATE central.recovery_epochs \
                 SET workspace_count = $2, updated_at = clock_timestamp() \
                 WHERE epoch_generation = $1 AND coordinator_domain = $3",
                row.next_gen,
                count.count,
                request.lease.recovery_domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: set workspace count")?;
            RecoveryEpoch {
                generation: row.next_gen,
                coordinator_fence: request.lease.fence,
                state: RecoveryEpochState::RecoveryEpochRunning,
                scheduler_cursor: WorkspaceId::from_trusted_db_bytes([0; 16]),
                workspace_count: count.count,
                processed_count: 0,
                claim_cycle: 0,
                retry_attempt: 0,
                snapshot_at: inserted.snapshot_at,
            }
        };
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        tx.commit().await.ctx("execution: commit start epoch")?;
        Ok(epoch)
    }

    /// `ClaimRecoveryWorkspaces` — requeues expired claims, then claims
    /// a round-robin page of pending workspaces under the epoch lock.
    async fn claim_recovery_workspaces(
        &self,
        request: ClaimRecoveryWorkspaceRequest,
    ) -> Result<Vec<RecoveryWorkspaceClaim>, Failure> {
        if request.lease.recovery_domain != RECOVERY_DOMAIN || request.batch_size == 0 {
            return Err(invalid("INVALID_RECOVERY_CLAIM_REQUEST"));
        }
        let mut tx = begin_recovery_scan(&self.pool).await?;
        Self::lock_recovery_coordinator(&mut tx, &request.lease).await?;
        // Requeue expired claims (bounded retry → failed).
        sqlx::query!(
            "WITH requeued AS ( \
             UPDATE central.recovery_epoch_workspaces AS work \
             SET delivery_state = CASE \
                   WHEN retry_attempt >= 4 THEN 'failed' ELSE 'pending' END, \
                claim_token_hash = NULL, claim_expires_at = NULL, \
                retry_attempt = LEAST(retry_attempt + 1, 5), \
                retry_not_before = CASE \
                  WHEN retry_attempt >= 4 THEN NULL \
                  ELSE clock_timestamp() + LEAST( \
                    interval '5 seconds', \
                    interval '100 milliseconds' * power(2, retry_attempt)) END, \
                failure_class = CASE \
                  WHEN retry_attempt >= 4 THEN 'retry_exhausted' ELSE 'claim_expired' END, \
                failure_reason = CASE \
                  WHEN retry_attempt >= 4 THEN 'recovery retry budget exhausted' \
                  ELSE 'recovery Workspace claim expired' END, \
                updated_at = clock_timestamp() \
             WHERE work.epoch_generation = $1 AND delivery_state = 'claimed' \
               AND claim_expires_at <= clock_timestamp() \
               AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
                 WHERE epoch.epoch_generation = work.epoch_generation \
                   AND epoch.coordinator_domain = $2) \
             RETURNING delivery_state) \
             SELECT count(*) FILTER (WHERE delivery_state = 'failed') AS \"failed!\" \
             FROM requeued",
            request.epoch_generation,
            request.lease.recovery_domain,
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("execution: requeue expired claims")?;
        let epoch = read_locked_recovery_epoch_for_claim(
            &mut tx,
            request.epoch_generation,
            request.lease.fence.generation,
            &request.lease.recovery_domain,
        )
        .await?;
        if matches!(
            epoch.state,
            RecoveryEpochState::RecoveryEpochCompleted | RecoveryEpochState::RecoveryEpochFailed
        ) {
            tx.commit().await.ctx("execution: commit claim")?;
            return Ok(Vec::new());
        }
        let batch = select_recovery_workspace_batch(
            &mut tx,
            request.epoch_generation,
            epoch.scheduler_cursor,
            i64::from(request.batch_size),
            &request.lease.recovery_domain,
        )
        .await?;
        let mut claims = Vec::with_capacity(batch.len());
        let mut last_cursor = epoch.scheduler_cursor;
        for work in &batch {
            let (token, verifier) = new_lease_secret()?;
            let done = sqlx::query!(
                "UPDATE central.recovery_epoch_workspaces AS work \
                 SET delivery_state = 'claimed', claim_token_hash = $3, \
                 claim_expires_at = clock_timestamp() + interval '30 seconds', \
                 updated_at = clock_timestamp() \
                 WHERE work.epoch_generation = $1 AND work.workspace_id = $2 \
                 AND work.delivery_state = 'pending' \
                 AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
                   WHERE epoch.epoch_generation = work.epoch_generation \
                     AND epoch.coordinator_domain = $4)",
                request.epoch_generation,
                uuid_of(work.workspace_id.as_bytes()),
                &verifier[..],
                request.lease.recovery_domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: claim recovery workspace")?
            .rows_affected();
            if done != 1 {
                continue; // lost a race — skip, keep batching
            }
            last_cursor = work.workspace_id;
            claims.push(RecoveryWorkspaceClaim {
                epoch: epoch.clone(),
                work: RecoveryWorkspaceWork {
                    state: RecoveryWorkspaceState::RecoveryWorkspaceClaimed,
                    ..work.clone()
                },
                coordinator_lease: request.lease.clone(),
                claim_token: token.to_vec(),
                claimed: true,
                completed: false,
                retry_after: time::Duration::ZERO,
            });
        }
        if !claims.is_empty() {
            sqlx::query!(
                "UPDATE central.recovery_epochs \
                 SET scheduler_cursor = $2, processed_count = processed_count + $3, \
                 state = CASE WHEN state = 'open' THEN 'running' ELSE state END, \
                 updated_at = clock_timestamp() \
                 WHERE epoch_generation = $1 AND coordinator_domain = $4",
                request.epoch_generation,
                uuid_of(last_cursor.as_bytes()),
                i64::try_from(claims.len())
                    .map_err(|_| invalid("INVALID_RECOVERY_CLAIM_REQUEST"))?,
                request.lease.recovery_domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: advance recovery cursor")?;
        }
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        tx.commit().await.ctx("execution: commit claim")?;
        Ok(claims)
    }

    /// `CompleteRecoveryWorkspace` — verifies the claim token, runs
    /// the adapter-owned scan, then completes or degrades the row and
    /// closes the epoch when no incomplete workspaces remain.
    async fn complete_recovery_workspace(
        &self,
        request: CompleteRecoveryWorkspaceRequest,
    ) -> Result<(), Failure> {
        if request.lease.recovery_domain != RECOVERY_DOMAIN
            || request.workspace_id.is_nil()
            || request.claim_token.is_empty()
        {
            return Err(invalid("INVALID_RECOVERY_COMPLETE_REQUEST"));
        }
        let claim_hash = sha256(&request.claim_token);
        let mut tx = begin_recovery_scan(&self.pool).await?;
        Self::lock_recovery_coordinator(&mut tx, &request.lease).await?;
        assert_recovery_epoch_domain(
            &mut tx,
            request.epoch_generation,
            request.lease.fence.generation,
            &request.lease.recovery_domain,
        )
        .await?;
        // Lock the claimed row under the exact claim token.
        let work_row = sqlx::query!(
            "SELECT work.delivery_state, work.watermark_created_at, work.watermark_run_id, \
             work.cursor_created_at, work.cursor_run_id, work.scanned_count, \
             work.reconciled_count \
             FROM central.recovery_epoch_workspaces AS work \
             JOIN central.recovery_epochs AS epoch \
               ON epoch.epoch_generation = work.epoch_generation \
              AND epoch.coordinator_domain = $4 \
             WHERE work.epoch_generation = $1 AND work.workspace_id = $2 \
             AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
             FOR UPDATE OF work",
            request.epoch_generation,
            uuid_of(request.workspace_id.as_bytes()),
            &claim_hash[..],
            request.lease.recovery_domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: lock recovery workspace claim")?;
        let Some(work_row) = work_row else {
            return Err(denied("RECOVERY_CLAIM_FENCED"));
        };
        let work = RecoveryWorkspaceWork {
            epoch_generation: request.epoch_generation,
            workspace_id: request.workspace_id,
            state: RecoveryWorkspaceState::RecoveryWorkspaceClaimed,
            watermark_created_at: work_row.watermark_created_at,
            watermark_run_id: RunId::from_trusted_db_bytes(*work_row.watermark_run_id.as_bytes()),
            cursor_created_at: work_row
                .cursor_created_at
                .unwrap_or(work_row.watermark_created_at),
            cursor_run_id: work_row.cursor_run_id.map_or_else(
                || RunId::from_trusted_db_bytes([0; 16]),
                |u| RunId::from_trusted_db_bytes(*u.as_bytes()),
            ),
            scanned_count: work_row.scanned_count,
            reconciled_count: work_row.reconciled_count,
            retry_attempt: 0,
            failure_class: String::new(),
            failure_reason: String::new(),
        };
        if request.degraded {
            sqlx::query!(
                "UPDATE central.recovery_epoch_workspaces AS work \
                 SET delivery_state = 'failed', claim_token_hash = NULL, \
                 claim_expires_at = NULL, retry_not_before = NULL, \
                 failure_class = $4, failure_reason = $5, \
                 updated_at = clock_timestamp() \
                 WHERE work.epoch_generation = $1 AND work.workspace_id = $2 \
                 AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
                 AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
                   WHERE epoch.epoch_generation = work.epoch_generation \
                     AND epoch.coordinator_domain = $6)",
                request.epoch_generation,
                uuid_of(request.workspace_id.as_bytes()),
                &claim_hash[..],
                request.failure_class,
                request.failure_reason,
                request.lease.recovery_domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: fail recovery workspace")?;
        } else {
            Self::scan_recovery_workspace(
                &mut tx,
                request.epoch_generation,
                &work,
                work_row.cursor_created_at,
                work_row.cursor_run_id,
                &claim_hash,
                &request.lease.recovery_domain,
            )
            .await?;
            sqlx::query!(
                "UPDATE central.recovery_epoch_workspaces AS work \
                 SET delivery_state = 'completed', claim_token_hash = NULL, \
                 claim_expires_at = NULL, retry_not_before = NULL, \
                 failure_class = NULL, failure_reason = NULL, \
                 updated_at = clock_timestamp() \
                 WHERE work.epoch_generation = $1 AND work.workspace_id = $2 \
                 AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
                 AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
                   WHERE epoch.epoch_generation = work.epoch_generation \
                     AND epoch.coordinator_domain = $4)",
                request.epoch_generation,
                uuid_of(request.workspace_id.as_bytes()),
                &claim_hash[..],
                request.lease.recovery_domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: finish recovery workspace")?;
        }
        // Close the epoch when nothing incomplete remains.
        let remaining = sqlx::query!(
            "SELECT count(*) AS \"count!\" \
             FROM central.recovery_epoch_workspaces AS work \
             JOIN central.recovery_epochs AS epoch \
               ON epoch.epoch_generation = work.epoch_generation \
              AND epoch.coordinator_domain = $2 \
             WHERE work.epoch_generation = $1 \
             AND work.delivery_state IN ('pending','claimed','failed')",
            request.epoch_generation,
            request.lease.recovery_domain,
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("execution: count incomplete workspaces")?;
        if remaining.count == 0 {
            sqlx::query!(
                "UPDATE central.recovery_epochs \
                 SET state = 'completed', completed_at = clock_timestamp(), \
                 updated_at = clock_timestamp() \
                 WHERE epoch_generation = $1 AND coordinator_domain = $2",
                request.epoch_generation,
                request.lease.recovery_domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: finish recovery epoch")?;
        } else if request.degraded {
            sqlx::query!(
                "UPDATE central.recovery_epochs \
                 SET state = 'degraded', updated_at = clock_timestamp() \
                 WHERE epoch_generation = $1 AND coordinator_domain = $2 \
                 AND state <> 'completed'",
                request.epoch_generation,
                request.lease.recovery_domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: degrade recovery epoch")?;
        }
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        tx.commit().await.ctx("execution: commit complete")?;
        Ok(())
    }

    /// `ResumeRecoveryEpoch` — operator resume of a degraded epoch:
    /// fenced CAS on the durable row, requeue failed workspaces,
    /// durable `execution.recovery.resumed` event + outbox + receipt.
    async fn resume_recovery_epoch(
        &self,
        request: ResumeRecoveryEpochRequest,
    ) -> Result<RecoveryEpoch, Failure> {
        let command = &request.command;
        if request.lease.recovery_domain != RECOVERY_DOMAIN
            || command.epoch_generation <= 0
            || command.idempotency_key.trim().is_empty()
            || command.acknowledgement_reason.trim().is_empty()
        {
            return Err(invalid("INVALID_RECOVERY_RESUME_REQUEST"));
        }
        let ws = command.scope.workspace_id;
        let mut tx = begin_recovery_scan(&self.pool).await?;
        Self::lock_receipt_identity(&mut tx, ws, RESUME_SCOPE, &command.idempotency_key).await?;
        // Resume-receipt replay.
        let existing = sqlx::query!(
            "SELECT request_fingerprint, result_reference \
             FROM central.execution_command_receipts \
             WHERE workspace_id = $1 AND command_scope = $2 AND idempotency_key = $3",
            uuid_of(ws.as_bytes()),
            RESUME_SCOPE,
            command.idempotency_key,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: read resume receipt")?;
        if let Some(receipt) = existing {
            if receipt.request_fingerprint != command.fingerprint {
                return Err(conflict("REASON_REQUEST_CONFLICT"));
            }
            let epoch = read_locked_recovery_epoch_for_claim(
                &mut tx,
                command.epoch_generation,
                command.coordinator_fence.generation,
                &request.lease.recovery_domain,
            )
            .await?;
            tx.commit().await.ctx("execution: commit resume replay")?;
            return Ok(epoch);
        }
        Self::lock_recovery_coordinator(&mut tx, &request.lease).await?;
        let done = sqlx::query!(
            "UPDATE central.recovery_epochs \
             SET state = 'running', retry_attempt = retry_attempt + 1, \
             failure_class = NULL, failure_reason = NULL, updated_at = clock_timestamp() \
             WHERE epoch_generation = $1 AND coordinator_fence = $2 \
             AND coordinator_domain = $6 AND state = $3 \
             AND retry_attempt = $4 \
             AND scheduler_cursor IS NOT DISTINCT FROM $5 \
             RETURNING snapshot_at, scheduler_cursor, workspace_count, processed_count",
            command.epoch_generation,
            command.coordinator_fence.generation,
            resume_epoch_state_value(command.expected_state),
            command.expected_retry_attempt,
            opt_uuid_of(
                (!command.expected_cursor.is_nil()).then_some(command.expected_cursor),
                |c| c.as_bytes(),
            ),
            request.lease.recovery_domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: resume recovery epoch")?;
        let Some(epoch_row) = done else {
            return Err(conflict("STALE_RECOVERY_FENCE"));
        };
        sqlx::query!(
            "UPDATE central.recovery_epoch_workspaces AS work \
             SET delivery_state = 'pending', retry_attempt = retry_attempt + 1, \
             failure_class = NULL, failure_reason = NULL, \
             claim_token_hash = NULL, claim_expires_at = NULL, retry_not_before = NULL, \
             updated_at = clock_timestamp() \
             WHERE work.epoch_generation = $1 AND delivery_state = 'failed' \
             AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
               WHERE epoch.epoch_generation = work.epoch_generation \
                 AND epoch.coordinator_domain = $2)",
            command.epoch_generation,
            request.lease.recovery_domain,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: requeue failed workspaces")?;
        // Durable resume event + outbox + receipt.
        let sequence = reserve_event_sequence(&mut tx, ws).await?;
        let event_id = uuid::Uuid::now_v7();
        let payload = serde_json::json!({
            "EpochGeneration": command.epoch_generation,
            "CoordinatorFence": command.coordinator_fence.generation,
            "AcknowledgementReason": command.acknowledgement_reason,
            "PrincipalID": command.scope.principal_id,
        });
        sqlx::query!(
            "INSERT INTO central.events (\
             id, workspace_id, event_sequence, event_type, aggregate_id, \
             aggregate_version, command_id, run_id, payload, occurred_at, \
             task_id, step_id, attempt_id, kind, state, producer_id, \
             policy_version, eligible_after, legal_hold) \
             VALUES ($1, $2, $3, 'execution.recovery.resumed', $2, $4, \
             $1, NULL, $5, clock_timestamp(), NULL, NULL, NULL, \
             'execution.recovery.resumed', 'recorded', $6, 1, \
             clock_timestamp() + interval '90 days', false)",
            event_id,
            uuid_of(ws.as_bytes()),
            sequence,
            command.epoch_generation,
            payload,
            command.scope.principal_id,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: insert resume event")?;
        sqlx::query!(
            "INSERT INTO central.outbox (\
             id, workspace_id, event_id, delivery_state, due_at, attempt_count, \
             created_at, updated_at, catalog_type, deduplication_key, \
             producer_id, payload, visible_at, policy_version, \
             eligible_after, legal_hold) \
             VALUES ($1, $2, $3, 'pending', clock_timestamp(), 0, \
             clock_timestamp(), clock_timestamp(), 'execution.recovery.resumed', \
             $4, $5, $6, clock_timestamp(), 1, \
             clock_timestamp() + interval '7 days', false)",
            uuid::Uuid::now_v7(),
            uuid_of(ws.as_bytes()),
            event_id,
            format!("{}:{}", RESUME_SCOPE, command.idempotency_key),
            command.scope.principal_id,
            payload,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: insert resume outbox")?;
        sqlx::query!(
            "INSERT INTO central.execution_command_receipts (\
             id, workspace_id, command_scope, idempotency_key, request_fingerprint, \
             principal_id, capability, expected_version_digest, result_reference, \
             result_payload, created_at, expires_at, eligible_after) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, '{}'::jsonb, \
             clock_timestamp(), clock_timestamp() + interval '7 days', \
             clock_timestamp() + interval '90 days') \
             ON CONFLICT (workspace_id, command_scope, idempotency_key) DO NOTHING",
            uuid::Uuid::now_v7(),
            uuid_of(ws.as_bytes()),
            RESUME_SCOPE,
            command.idempotency_key,
            &command.fingerprint[..],
            command.scope.principal_id,
            command.capability.as_str(),
            &expected_digest(&ExpectedVersions::default())[..],
            event_id,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: insert resume receipt")?;
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        let epoch = RecoveryEpoch {
            generation: command.epoch_generation,
            coordinator_fence: command.coordinator_fence,
            state: RecoveryEpochState::RecoveryEpochRunning,
            scheduler_cursor: epoch_row.scheduler_cursor.map_or_else(
                || WorkspaceId::from_trusted_db_bytes([0; 16]),
                |u| WorkspaceId::from_trusted_db_bytes(*u.as_bytes()),
            ),
            workspace_count: epoch_row.workspace_count,
            processed_count: epoch_row.processed_count,
            claim_cycle: epoch_row.processed_count,
            retry_attempt: command.expected_retry_attempt + 1,
            snapshot_at: epoch_row.snapshot_at,
        };
        tx.commit().await.ctx("execution: commit resume")?;
        Ok(epoch)
    }

    /// `ListFailedRecoveryWorkspaces` — read-only; the implementation
    /// lives in `failed_recovery_workspaces.rs` with the upstream file
    /// split.
    async fn list_failed_recovery_workspaces(
        &self,
        epoch_generation: i64,
        limit: u32,
    ) -> Result<central_execution::port::FailedRecoveryWorkspaces, Failure> {
        self.list_failed_recovery_workspaces_page(epoch_generation, limit)
            .await
    }
}

fn resume_epoch_state_value(state: RecoveryEpochState) -> &'static str {
    match state {
        RecoveryEpochState::RecoveryEpochOpen => "open",
        RecoveryEpochState::RecoveryEpochRunning => "running",
        RecoveryEpochState::RecoveryEpochDegraded => "degraded",
        RecoveryEpochState::RecoveryEpochCompleted => "completed",
        _ => "failed",
    }
}
