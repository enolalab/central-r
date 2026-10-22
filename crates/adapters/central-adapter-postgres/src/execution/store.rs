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
    AttemptState, ExecutionState, ExpectedVersions, LeaseCredential, LogicalOperationId,
    NIL_APPROVAL_ID, NIL_STEP_ID, OutboxIntent, Step, StepAttempt, StepAttemptAssertion, StepState,
    TrustedScope, ZERO_TIME,
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
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ExecutionEventId, RunId, StepAttemptId, StepId, TaskId, WorkspaceId,
};
use central_task::domain::TaskChangeSet;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

use super::queries::{
    db_now, lock_event_counter, read_attempt, read_incomplete_recovery_epoch,
    read_locked_recovery_epoch, read_locked_recovery_epoch_for_claim,
    read_persisted_lease_for_update, read_run, read_step, read_task, read_tool_attempts,
    read_tool_calls, reserve_event_sequence, select_recovery_workspace_batch,
};
use super::{
    RECOVERY_DOMAIN, RECOVERY_RENEW_INTERVAL, RECOVERY_RETRY_LIMIT, RECOVERY_SCAN_BATCH,
    RESUME_ATTEMPT_SCOPE, RESUME_SCOPE, begin, begin_recovery, begin_recovery_scan, conflict,
    corrupt, ct_eq, denied, expected_digest, go_json_escapes, invalid, invocation_generation,
    new_lease_secret, null_time, opt_approval_uuid, opt_attempt_uuid, opt_run_uuid, opt_step_uuid,
    opt_tool_attempt_uuid, sha256, uuid_for_invocation, uuid_for_logical, uuid_for_physical,
    uuid_of, wait_reason_value,
};
use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::opt_uuid_of;

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

    /// The canonical receipt-result JSON (`result_payload`) — upstream
    /// stores exactly `{"approval_action":{...}}` (`omitempty` → `{}`
    /// without a descriptor); every other durable-result leg is
    /// rebound from the receipt binding and its event row at replay.
    fn encode_result_payload(result: &DurableResult) -> Vec<u8> {
        let Some(a) = result.approval_action.as_ref() else {
            return serde_json::to_vec(&serde_json::json!({})).unwrap_or_default();
        };
        serde_json::to_vec(&serde_json::json!({
            "approval_action": {
                "Authorized": a.authorized,
                "Action": a.action.map_or("", |x| x.as_str()),
                "RequiredCapability": a.required_capability.map_or("", |c| c.as_str()),
                "StepID": a.step_id.to_string(),
                "ApprovalID": a.approval_id.to_string(),
                "LogicalOperationID": a.logical_operation_id.0,
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
            },
        }))
        .unwrap_or_default()
    }

    /// Decodes a stored `result_payload`; corrupt rows are internal.
    /// Upstream rebinds the durable result from the request workspace,
    /// the receipt binding, and the event row's legs — only the
    /// approval descriptor travels inside the payload
    /// (`durableResultFromStrings` + the `approval_action` unmarshal).
    fn decode_result_payload(
        payload: &serde_json::Value,
        ws: WorkspaceId,
        binding: &central_execution::port::ReceiptBinding,
        event_id: uuid::Uuid,
        event_kind: &str,
    ) -> Result<DurableResult, Failure> {
        Ok(DurableResult {
            workspace_id: ws,
            task_id: binding.task_id,
            run_id: binding.run_id,
            step_id: binding.step_id,
            attempt_id: binding.attempt_id,
            event_id: ExecutionEventId::from_trusted_db_bytes(*event_id.as_bytes()),
            event_kind: event_kind.to_owned(),
            approval_action: Self::decode_approval_action(payload)?,
        })
    }

    /// Upstream's `json.Unmarshal(resultPayload, &persisted)` — every
    /// descriptor field is read back exactly (including
    /// `LogicalOperationID` and `ExpectedVersions`); a malformed row is
    /// the same `dbFailure("decode receipt payload")` upstream raises.
    fn decode_approval_action(
        payload: &serde_json::Value,
    ) -> Result<Option<central_execution::domain::ApprovalSuccessorActionDescriptor>, Failure> {
        let Some(a) = payload.get("approval_action") else {
            return Ok(None);
        };
        if a.is_null() {
            return Ok(None);
        }
        let field = |key: &str| a.get(key).and_then(|v| v.as_str());
        // `StepID`/`ApprovalID` unmarshal through the strict v7
        // identity parsers upstream — nil or malformed text fails the
        // decode rather than silently zeroing the id.
        let step_id = StepId::parse(field("StepID").unwrap_or_default())
            .map_err(|_| corrupt("a stored receipt descriptor step id is invalid"))?;
        let approval_id = central_foundation::identity::ApprovalId::parse(
            field("ApprovalID").unwrap_or_default(),
        )
        .map_err(|_| corrupt("a stored receipt descriptor approval id is invalid"))?;
        // `LogicalOperationID` is a Go `[16]byte` — a JSON array of
        // exactly 16 numbers.
        let logical = match a.get("LogicalOperationID") {
            None => LogicalOperationId([0; 16]),
            Some(v) => {
                let digits = v.as_array().filter(|arr| arr.len() == 16).ok_or_else(|| {
                    corrupt("a stored receipt descriptor logical id is malformed")
                })?;
                let mut bytes = [0u8; 16];
                for (dst, digit) in bytes.iter_mut().zip(digits.iter()) {
                    *dst = u8::try_from(digit.as_u64().unwrap_or(u64::MAX)).map_err(|_| {
                        corrupt("a stored receipt descriptor logical id is malformed")
                    })?;
                }
                LogicalOperationId(bytes)
            }
        };
        let versions = a.get("ExpectedVersions");
        let version_at = |key: &str| {
            versions
                .and_then(|v| v.get(key))
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
        };
        Ok(Some(
            central_execution::domain::ApprovalSuccessorActionDescriptor {
                action: field("Action").and_then(central_execution::domain::ApprovalAction::parse),
                authorized: a
                    .get("Authorized")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                required_capability: field("RequiredCapability").and_then(|s| match s {
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
                step_id,
                approval_id,
                logical_operation_id: logical,
                approval_subject_version: a
                    .get("ApprovalSubjectVersion")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0),
                expected_versions: ExpectedVersions {
                    task: version_at("Task"),
                    run: version_at("Run"),
                    step: version_at("Step"),
                    attempt: version_at("Attempt"),
                    tool_call: version_at("ToolCall"),
                    tool_attempt: version_at("ToolAttempt"),
                    approval: version_at("Approval"),
                },
            },
        ))
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
    /// a lost insert race → `IDEMPOTENCY_CONFLICT` (defensive — the
    /// advisory lock already serializes the identity).
    async fn insert_receipt(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
        digest: [u8; 32],
    ) -> Result<(), Failure> {
        let payload = Self::encode_result_payload(&req.result);
        let done = sqlx::query!(
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
        .ctx("execution: insert receipt")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("IDEMPOTENCY_CONFLICT"));
        }
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

    /// `lockAndValidateReceiptTarget` — step and attempt are locked
    /// `FOR UPDATE` and re-validated against the binding: exact
    /// expected versions, the shared logical operation, and the
    /// insertion shapes. `execution.prepare` and
    /// `execution.start_harness_run` bind their inserted rows instead.
    async fn lock_and_validate_receipt_target(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        if req.command_scope == "execution.prepare"
            || req.command_scope == "execution.start_harness_run"
        {
            return Self::lock_and_validate_prepared_receipt_target(tx, req).await;
        }
        let ws = req.scope.workspace_id;
        let binding = &req.receipt_binding;
        let step = sqlx::query!(
            "SELECT logical_operation_id, version FROM central.steps \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND id = $4 FOR UPDATE",
            uuid_of(ws.as_bytes()),
            uuid_of(binding.task_id.as_bytes()),
            uuid_of(binding.run_id.as_bytes()),
            uuid_of(binding.step_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock receipt step target")?
        .ok_or_else(|| invalid("STATE_SCOPE_MISMATCH"))?;
        let attempt = sqlx::query!(
            "SELECT logical_operation_id, version FROM central.step_attempts \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5 FOR UPDATE",
            uuid_of(ws.as_bytes()),
            uuid_of(binding.task_id.as_bytes()),
            uuid_of(binding.run_id.as_bytes()),
            uuid_of(binding.step_id.as_bytes()),
            uuid_of(binding.attempt_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock receipt attempt target")?
        .ok_or_else(|| invalid("STATE_SCOPE_MISMATCH"))?;
        let want = uuid_for_logical(&binding.logical_operation);
        if step.logical_operation_id != want || attempt.logical_operation_id != want {
            return Err(invalid("STATE_SCOPE_MISMATCH"));
        }
        if step.version != req.expected_versions.step
            || attempt.version != req.expected_versions.attempt
        {
            return Err(conflict("EXPECTED_VERSION_CONFLICT"));
        }
        if req.command_scope == "execution.create_approval_successor" {
            return Self::lock_and_validate_approval_successor_predecessor(tx, req).await;
        }
        Ok(())
    }

    /// `lockAndValidateApprovalSuccessorPredecessor` — the successor's
    /// predecessor approval is locked `FOR UPDATE` and its version must
    /// equal `expected_versions.approval`. A missing predecessor (or a
    /// change set that is not exactly one successor carrying one) is
    /// `STATE_SCOPE_MISMATCH`; a version drift is the CAS conflict.
    async fn lock_and_validate_approval_successor_predecessor(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        if req.change_set.approvals.len() != 1 {
            return Err(invalid("STATE_SCOPE_MISMATCH"));
        }
        let successor = &req.change_set.approvals[0];
        if successor.predecessor_id.is_nil() {
            return Err(invalid("STATE_SCOPE_MISMATCH"));
        }
        let binding = &req.receipt_binding;
        let predecessor_version = sqlx::query!(
            "SELECT version FROM central.approvals \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5 AND approval_kind = 'execution' \
             FOR UPDATE",
            uuid_of(req.scope.workspace_id.as_bytes()),
            uuid_of(binding.task_id.as_bytes()),
            uuid_of(binding.run_id.as_bytes()),
            uuid_of(binding.step_id.as_bytes()),
            uuid_of(successor.predecessor_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock approval successor predecessor")?
        .ok_or_else(|| invalid("STATE_SCOPE_MISMATCH"))?
        .version;
        if predecessor_version != req.expected_versions.approval {
            return Err(conflict("EXPECTED_VERSION_CONFLICT"));
        }
        Ok(())
    }

    /// `lockAndValidatePreparedReceiptTarget` — a prepare/claim commit
    /// binds the Step and StepAttempt it inserts; an existing-step
    /// prepare additionally locks that step and checks its fence.
    async fn lock_and_validate_prepared_receipt_target(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        if req.expected_versions.attempt != 0
            || req.change_set.steps.len() != 1
            || req.change_set.attempts.len() != 1
        {
            return Err(invalid("STATE_SCOPE_MISMATCH"));
        }
        let step = &req.change_set.steps[0];
        let attempt = &req.change_set.attempts[0];
        let binding = &req.receipt_binding;
        if step.id != binding.step_id
            || step.workspace_id != req.scope.workspace_id
            || step.task_id != binding.task_id
            || step.run_id != binding.run_id
            || attempt.id != binding.attempt_id
            || attempt.workspace_id != req.scope.workspace_id
            || attempt.task_id != binding.task_id
            || attempt.run_id != binding.run_id
            || attempt.step_id != binding.step_id
            || attempt.logical_operation_id != binding.logical_operation
            || attempt.version != 1
        {
            return Err(invalid("STATE_SCOPE_MISMATCH"));
        }
        if req.expected_versions.step == 0 {
            if step.version != 1 {
                return Err(invalid("STATE_SCOPE_MISMATCH"));
            }
            return Ok(());
        }
        let row = sqlx::query!(
            "SELECT logical_operation_id, version FROM central.steps \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND id = $4 FOR UPDATE",
            uuid_of(req.scope.workspace_id.as_bytes()),
            uuid_of(binding.task_id.as_bytes()),
            uuid_of(binding.run_id.as_bytes()),
            uuid_of(binding.step_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: lock prepared receipt step target")?
        .ok_or_else(|| invalid("STATE_SCOPE_MISMATCH"))?;
        if row.logical_operation_id != uuid_for_logical(&binding.logical_operation) {
            return Err(invalid("STATE_SCOPE_MISMATCH"));
        }
        if row.version != req.expected_versions.step {
            return Err(conflict("EXPECTED_VERSION_CONFLICT"));
        }
        Ok(())
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
            // Upstream: the latest epoch exists but never recorded this
            // workspace — a hard admission failure, not a pass.
            return Err(conflict("RECOVERY_WORKSPACE_NOT_FOUND"));
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
            // Upstream passes `decision.Reason` — the domain's only
            // non-claimable reason (`RECOVERY_QUARANTINE`, no `-D`).
            return Err(conflict("RECOVERY_QUARANTINE"));
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

    /// `persistSteps` — the evaluator's expected step version is the
    /// CAS fence: `expected.step == 0` means insert, otherwise update
    /// under `version = expected`. The approval-successor and resume
    /// scopes also insert the non-bound step they carry.
    async fn persist_steps(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        for row in &req.change_set.steps {
            if row.workspace_id != req.scope.workspace_id {
                return Err(denied("SCOPE_MISMATCH"));
            }
            let insert = req.expected_versions.step == 0
                || ((req.command_scope == "execution.create_approval_successor"
                    || req.command_scope == RESUME_ATTEMPT_SCOPE)
                    && row.id != req.receipt_binding.step_id);
            let done = if insert {
                let logical = Self::inserted_step_logical_operation(req, row)?;
                sqlx::query!(
                    "INSERT INTO central.steps (\
                     id, workspace_id, task_id, run_id, version, state, \
                     logical_operation_id, sequence, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, \
                     clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (id) DO NOTHING",
                    uuid_of(row.id.as_bytes()),
                    uuid_of(row.workspace_id.as_bytes()),
                    uuid_of(row.task_id.as_bytes()),
                    uuid_of(row.run_id.as_bytes()),
                    row.version,
                    row.state.as_str(),
                    uuid_for_logical(&logical),
                    row.sequence,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert step")?
                .rows_affected()
            } else {
                sqlx::query!(
                    "UPDATE central.steps \
                     SET version = $5, state = $6, sequence = $7, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                     AND id = $4 AND version = $8",
                    uuid_of(row.workspace_id.as_bytes()),
                    uuid_of(row.task_id.as_bytes()),
                    uuid_of(row.run_id.as_bytes()),
                    uuid_of(row.id.as_bytes()),
                    row.version,
                    row.state.as_str(),
                    row.sequence,
                    req.expected_versions.step,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update step")?
                .rows_affected()
            };
            if done != 1 {
                return Err(conflict("EXPECTED_VERSION_CONFLICT"));
            }
        }
        Ok(())
    }

    /// `insertedStepLogicalOperation` — the bound step takes the
    /// binding's logical operation; approval-successor and resume
    /// steps take the logical operation of the row that created them.
    fn inserted_step_logical_operation(
        req: &CommitRequest,
        step: &Step,
    ) -> Result<LogicalOperationId, Failure> {
        if step.id == req.receipt_binding.step_id {
            return Ok(req.receipt_binding.logical_operation);
        }
        if req.command_scope == "execution.create_approval_successor" {
            for approval in &req.change_set.approvals {
                if approval.step_id == step.id && !approval.subject.logical_operation_id.is_nil() {
                    return Ok(approval.subject.logical_operation_id);
                }
            }
        }
        if req.command_scope == RESUME_ATTEMPT_SCOPE {
            for attempt in &req.change_set.attempts {
                if attempt.step_id == step.id && !attempt.logical_operation_id.is_nil() {
                    return Ok(attempt.logical_operation_id);
                }
            }
        }
        Err(invalid("STATE_SCOPE_MISMATCH"))
    }

    /// `persistAttempts` — `expected.attempt == 0` inserts every row,
    /// otherwise each row updates under `version = expected`. Rows
    /// carrying a settlement were already updated by
    /// [`Self::persist_settlements`] and are skipped here.
    async fn persist_attempts(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        Self::validate_attempt_inserts(req)?;
        if req.command_scope == RESUME_ATTEMPT_SCOPE {
            return Self::persist_resumed_attempts(tx, req).await;
        }
        for row in &req.change_set.attempts {
            if Self::has_settlement(&req.change_set.settlements, row.id) {
                continue;
            }
            if row.workspace_id != req.scope.workspace_id {
                return Err(denied("SCOPE_MISMATCH"));
            }
            if req.expected_versions.attempt == 0 {
                Self::insert_attempt_row(tx, row).await?;
            } else {
                Self::update_attempt_row(tx, row, req.expected_versions.attempt).await?;
            }
        }
        Ok(())
    }

    /// `persistResumedAttempts` — the resume scope updates the binding's
    /// row first, then inserts the other rows: the active-run unique
    /// index is not deferrable, so the predecessor must leave the
    /// active states before the successor enters them.
    async fn persist_resumed_attempts(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        for update in [true, false] {
            for row in &req.change_set.attempts {
                if (row.id == req.receipt_binding.attempt_id) != update
                    || Self::has_settlement(&req.change_set.settlements, row.id)
                {
                    continue;
                }
                if row.workspace_id != req.scope.workspace_id {
                    return Err(denied("SCOPE_MISMATCH"));
                }
                if update {
                    Self::update_attempt_row(tx, row, req.expected_versions.attempt).await?;
                } else {
                    Self::insert_attempt_row(tx, row).await?;
                }
            }
        }
        Ok(())
    }

    async fn insert_attempt_row(
        tx: &mut Transaction<'_, Postgres>,
        a: &StepAttempt,
    ) -> Result<(), Failure> {
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
            uuid_of(a.id.as_bytes()),
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.step_id.as_bytes()),
            uuid_of(a.task_id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
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
            return Err(conflict("EXPECTED_VERSION_CONFLICT"));
        }
        Ok(())
    }

    async fn update_attempt_row(
        tx: &mut Transaction<'_, Postgres>,
        a: &StepAttempt,
        expected: i64,
    ) -> Result<(), Failure> {
        let done = sqlx::query!(
            "UPDATE central.step_attempts \
             SET version = $6, invocation_id = $7, \
             invocation_generation = CASE WHEN $7::uuid IS NULL THEN NULL ELSE $8::bigint END, \
             state = $9, outcome = COALESCE($10::jsonb, outcome), \
             context = COALESCE($11::jsonb, context), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
             AND step_id = $4 AND id = $5 AND version = $12",
            uuid_of(a.workspace_id.as_bytes()),
            uuid_of(a.task_id.as_bytes()),
            uuid_of(a.run_id.as_bytes()),
            uuid_of(a.step_id.as_bytes()),
            uuid_of(a.id.as_bytes()),
            a.version,
            uuid_for_invocation(&a.invocation_id),
            invocation_generation(&a.invocation_id),
            a.state.as_str(),
            Option::<serde_json::Value>::None,
            Option::<serde_json::Value>::None,
            expected,
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: update attempt")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("EXPECTED_VERSION_CONFLICT"));
        }
        Ok(())
    }

    /// `validateAttemptInserts` — a recovery successor (predecessor
    /// set) may only be inserted when the same change set moves that
    /// predecessor to `cancelled`. The resume scope's inserted rows are
    /// checked by `validateResumedAttemptInserts` instead.
    fn validate_attempt_inserts(req: &CommitRequest) -> Result<(), Failure> {
        if req.command_scope == RESUME_ATTEMPT_SCOPE {
            return Self::validate_resumed_attempt_inserts(req);
        }
        if req.expected_versions.attempt != 0 {
            return Ok(());
        }
        for row in &req.change_set.attempts {
            if row.predecessor_id.is_nil()
                || Self::has_settlement(&req.change_set.settlements, row.id)
            {
                continue;
            }
            let cancelled =
                req.change_set.attempts.iter().any(|o| {
                    o.id == row.predecessor_id && o.state == AttemptState::AttemptCancelled
                });
            if !cancelled {
                return Err(invalid("INVALID_LOGICAL_OPERATION_REUSE"));
            }
        }
        Ok(())
    }

    /// `validateResumedAttemptInserts` — every inserted (non-binding)
    /// row must be a never-invoked prepared successor at version 1,
    /// sequence 1, whose predecessor is the binding's row moving to
    /// failed in the same change set.
    fn validate_resumed_attempt_inserts(req: &CommitRequest) -> Result<(), Failure> {
        for row in &req.change_set.attempts {
            if row.id == req.receipt_binding.attempt_id
                || Self::has_settlement(&req.change_set.settlements, row.id)
            {
                continue;
            }
            let failed_predecessor = req.change_set.attempts.iter().any(|o| {
                o.id == row.predecessor_id
                    && o.id == req.receipt_binding.attempt_id
                    && o.state == AttemptState::AttemptFailed
            });
            if row.predecessor_id.is_nil()
                || !failed_predecessor
                || row.version != 1
                || row.sequence != 1
                || row.state != AttemptState::AttemptPrepared
                || !row.invocation_id.is_nil()
            {
                return Err(invalid("INVALID_LOGICAL_OPERATION_REUSE"));
            }
        }
        Ok(())
    }

    fn has_settlement(rows: &[central_execution::domain::Settlement], id: StepAttemptId) -> bool {
        rows.iter().any(|row| row.attempt_id == id)
    }

    fn has_tool_settlement(
        rows: &[central_execution::domain::ToolSettlement],
        id: central_foundation::identity::ToolCallAttemptId,
    ) -> bool {
        rows.iter().any(|row| row.tool_attempt_id == id)
    }

    /// `persistToolCalls` — `expected.tool_call == 0` inserts, else
    /// updates under `version = expected`.
    async fn persist_tool_calls(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        for row in &req.change_set.tool_calls {
            let done = if req.expected_versions.tool_call == 0 {
                sqlx::query!(
                    "INSERT INTO central.tool_calls (\
                     id, workspace_id, step_id, step_attempt_id, task_id, run_id, \
                     version, logical_operation_id, sequence, state, \
                     created_at, updated_at) \
                     SELECT $1, $2, a.step_id, $3, $4, $5, $6, $7, $8, $9, \
                     clock_timestamp(), clock_timestamp() \
                     FROM central.step_attempts a \
                     WHERE a.workspace_id = $2 AND a.id = $3 \
                     ON CONFLICT (id) DO NOTHING",
                    uuid_of(row.id.as_bytes()),
                    uuid_of(row.workspace_id.as_bytes()),
                    uuid_of(row.step_attempt_id.as_bytes()),
                    uuid_of(row.task_id.as_bytes()),
                    uuid_of(row.run_id.as_bytes()),
                    row.version,
                    uuid_for_logical(&row.logical_operation_id),
                    row.sequence,
                    row.state.as_str(),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert tool call")?
                .rows_affected()
            } else {
                sqlx::query!(
                    "UPDATE central.tool_calls \
                     SET version = $6, sequence = $7, state = $8, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                     AND step_attempt_id = $4 AND id = $5 AND version = $9",
                    uuid_of(row.workspace_id.as_bytes()),
                    uuid_of(row.task_id.as_bytes()),
                    uuid_of(row.run_id.as_bytes()),
                    uuid_of(row.step_attempt_id.as_bytes()),
                    uuid_of(row.id.as_bytes()),
                    row.version,
                    row.sequence,
                    row.state.as_str(),
                    req.expected_versions.tool_call,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update tool call")?
                .rows_affected()
            };
            if done != 1 {
                return Err(conflict("EXPECTED_VERSION_CONFLICT"));
            }
        }
        Ok(())
    }

    /// `persistToolAttempts` — `expected.tool_attempt == 0` inserts,
    /// else updates under `version = expected`; settled rows were
    /// already written by [`Self::persist_settlements`].
    async fn persist_tool_attempts(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        for row in &req.change_set.tool_attempts {
            if Self::has_tool_settlement(&req.change_set.tool_settlements, row.id) {
                continue;
            }
            let done = if req.expected_versions.tool_attempt == 0 {
                sqlx::query!(
                    "INSERT INTO central.tool_call_attempts (\
                     id, workspace_id, tool_call_id, step_attempt_id, task_id, run_id, \
                     version, logical_operation_id, physical_attempt_id, invocation_id, \
                     invocation_generation, predecessor_id, sequence, state, \
                     created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                     CASE WHEN $10::uuid IS NULL THEN NULL ELSE $11::bigint END, \
                     $12, $13, $14, clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (id) DO NOTHING",
                    uuid_of(row.id.as_bytes()),
                    uuid_of(row.workspace_id.as_bytes()),
                    uuid_of(row.tool_call_id.as_bytes()),
                    uuid_of(row.step_attempt_id.as_bytes()),
                    uuid_of(row.task_id.as_bytes()),
                    uuid_of(row.run_id.as_bytes()),
                    row.version,
                    uuid_for_logical(&row.logical_operation_id),
                    uuid_for_physical(&row.physical_attempt_id),
                    uuid_for_invocation(&row.invocation_id),
                    invocation_generation(&row.invocation_id),
                    opt_tool_attempt_uuid(row.predecessor_id),
                    row.sequence,
                    row.state.as_str(),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert tool attempt")?
                .rows_affected()
            } else {
                sqlx::query!(
                    "UPDATE central.tool_call_attempts \
                     SET version = $7, invocation_id = $8, \
                     invocation_generation = CASE WHEN $8::uuid IS NULL THEN NULL ELSE $9::bigint END, \
                     state = $10, outcome = COALESCE($11::jsonb, outcome), \
                     context = COALESCE($12::jsonb, context), \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                     AND step_attempt_id = $4 AND tool_call_id = $5 AND id = $6 \
                     AND version = $13",
                    uuid_of(row.workspace_id.as_bytes()),
                    uuid_of(row.task_id.as_bytes()),
                    uuid_of(row.run_id.as_bytes()),
                    uuid_of(row.step_attempt_id.as_bytes()),
                    uuid_of(row.tool_call_id.as_bytes()),
                    uuid_of(row.id.as_bytes()),
                    row.version,
                    uuid_for_invocation(&row.invocation_id),
                    invocation_generation(&row.invocation_id),
                    row.state.as_str(),
                    Option::<serde_json::Value>::None,
                    Option::<serde_json::Value>::None,
                    req.expected_versions.tool_attempt,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update tool attempt")?
                .rows_affected()
            };
            if done != 1 {
                return Err(conflict("EXPECTED_VERSION_CONFLICT"));
            }
        }
        Ok(())
    }

    /// `persistApprovals` — `expected.approval == 0` inserts, else
    /// updates under `version = expected`; the approval-successor
    /// scope additionally inserts rows carrying a predecessor.
    async fn persist_approvals(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        for a in &req.change_set.approvals {
            let insert = req.expected_versions.approval == 0
                || (req.command_scope == "execution.create_approval_successor"
                    && !a.predecessor_id.is_nil());
            let (w, t, r, s, id) = (
                uuid_of(a.workspace_id.as_bytes()),
                uuid_of(a.task_id.as_bytes()),
                uuid_of(a.run_id.as_bytes()),
                uuid_of(a.step_id.as_bytes()),
                uuid_of(a.id.as_bytes()),
            );
            let done = if insert {
                sqlx::query!(
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
                .rows_affected()
            } else {
                sqlx::query!(
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
                    req.expected_versions.approval,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: update approval")?
                .rows_affected()
            };
            if done != 1 {
                return Err(conflict("EXPECTED_VERSION_CONFLICT"));
            }
        }
        Ok(())
    }

    /// `persistCheckpoints` — insert-only; a duplicate is a conflict.
    async fn persist_checkpoints(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        for c in &req.change_set.checkpoints {
            let done = sqlx::query!(
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
                req.principal_id,
                c.producer_version,
                c.schema_version,
                &c.checksum[..],
                &c.payload[..],
                c.resume_compatible,
                c.validated,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: insert checkpoint")?
            .rows_affected();
            if done != 1 {
                return Err(conflict("CHECKPOINT_CONFLICT"));
            }
        }
        Ok(())
    }

    /// `persistSettlements` — the bounded terminal evidence is
    /// materialized before the matching attempt's state projection:
    /// each settlement updates its attempt row with the validated
    /// outcome/context under `version = expected`.
    async fn persist_settlements(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        for settlement in &req.change_set.settlements {
            let (outcome, context) =
                Self::encoded_settlement(&settlement.outcome, &settlement.context)?;
            let row = req
                .change_set
                .attempts
                .iter()
                .find(|a| a.id == settlement.attempt_id)
                .ok_or_else(|| invalid("SETTLEMENT_ATTEMPT_MISMATCH"))?;
            let done = sqlx::query!(
                "UPDATE central.step_attempts \
                 SET version = $6, invocation_id = $7, \
                 invocation_generation = CASE WHEN $7::uuid IS NULL THEN NULL ELSE $8::bigint END, \
                 state = $9, outcome = COALESCE($10::jsonb, outcome), \
                 context = COALESCE($11::jsonb, context), \
                 updated_at = clock_timestamp() \
                 WHERE workspace_id = $1 AND task_id = $2 AND run_id = $3 \
                 AND step_id = $4 AND id = $5 AND version = $12",
                uuid_of(row.workspace_id.as_bytes()),
                uuid_of(row.task_id.as_bytes()),
                uuid_of(row.run_id.as_bytes()),
                uuid_of(row.step_id.as_bytes()),
                uuid_of(row.id.as_bytes()),
                row.version,
                uuid_for_invocation(&row.invocation_id),
                invocation_generation(&row.invocation_id),
                row.state.as_str(),
                outcome,
                context,
                req.expected_versions.attempt,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: persist settlement")?
            .rows_affected();
            if done != 1 {
                return Err(conflict("EXPECTED_VERSION_CONFLICT"));
            }
        }
        for settlement in &req.change_set.tool_settlements {
            let (outcome, context) =
                Self::encoded_settlement(&settlement.outcome, &settlement.context)?;
            let row = req
                .change_set
                .tool_attempts
                .iter()
                .find(|a| a.id == settlement.tool_attempt_id)
                .ok_or_else(|| invalid("TOOL_SETTLEMENT_ATTEMPT_MISMATCH"))?;
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
                uuid_of(row.workspace_id.as_bytes()),
                uuid_of(row.task_id.as_bytes()),
                uuid_of(row.run_id.as_bytes()),
                uuid_of(row.step_attempt_id.as_bytes()),
                uuid_of(row.tool_call_id.as_bytes()),
                uuid_of(row.id.as_bytes()),
                row.version,
                uuid_for_invocation(&row.invocation_id),
                invocation_generation(&row.invocation_id),
                row.state.as_str(),
                outcome,
                context,
                req.expected_versions.tool_attempt,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: persist tool settlement")?
            .rows_affected();
            if done != 1 {
                return Err(conflict("EXPECTED_VERSION_CONFLICT"));
            }
        }
        Ok(())
    }

    /// `encodedSettlement` — outcome is required JSON; context may be
    /// absent or valid JSON. Anything else is invalid evidence.
    fn encoded_settlement(
        outcome: &[u8],
        context: &[u8],
    ) -> Result<(serde_json::Value, Option<serde_json::Value>), Failure> {
        let outcome_json = serde_json::from_slice::<serde_json::Value>(&go_json_escapes(outcome));
        let context_ok = context.is_empty()
            || serde_json::from_slice::<serde_json::Value>(&go_json_escapes(context)).is_ok();
        if outcome_json.is_err() || !context_ok {
            return Err(invalid("INVALID_SETTLEMENT_EVIDENCE"));
        }
        let context_json = (!context.is_empty()).then(|| {
            serde_json::from_slice::<serde_json::Value>(&go_json_escapes(context))
                .unwrap_or_default()
        });
        Ok((outcome_json.unwrap_or_default(), context_json))
    }

    /// `persistLeases` — insert / claim-expired / heartbeat per durable
    /// lease fact, fenced by the change-set generation; the persisted
    /// expiry is the fixed 30-second renewal window, and a stale fence
    /// is a conflict.
    async fn persist_leases(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        for lease in &req.change_set.leases {
            let persisted =
                read_persisted_lease_for_update(tx, lease.workspace_id, lease.run_id).await?;
            let (w, r) = (
                uuid_of(lease.workspace_id.as_bytes()),
                uuid_of(lease.run_id.as_bytes()),
            );
            let verifier = sha256(&lease.credential.0);
            match persisted {
                None => {
                    if lease.generation != 1 {
                        return Err(conflict("STALE_LEASE_FENCE"));
                    }
                    sqlx::query!(
                        "INSERT INTO central.execution_ownership (\
                         id, workspace_id, owner_scope, owner_identity, heartbeat_at, \
                         claimed_run_id, claimed_step_id, claimed_step_attempt_id, \
                         run_id, lease_token_hash, fencing_generation, lease_expires_at, \
                         created_at, updated_at) \
                         VALUES ($1, $2, $3, $4, clock_timestamp(), \
                         $5, $6, $7, $5, $8, $9, \
                         clock_timestamp() + interval '30 seconds', \
                         clock_timestamp(), clock_timestamp())",
                        uuid::Uuid::now_v7(),
                        w,
                        format!("run:{}", uuid::Uuid::from_bytes(*lease.run_id.as_bytes())),
                        req.principal_id,
                        r,
                        opt_step_uuid(req.result.step_id),
                        opt_attempt_uuid(req.result.attempt_id),
                        &verifier[..],
                        lease.generation,
                    )
                    .execute(&mut **tx)
                    .await
                    .ctx("execution: insert lease")?;
                }
                Some(row)
                    if row.generation == lease.generation && ct_eq(&verifier, &row.verifier) =>
                {
                    let done = sqlx::query!(
                        "UPDATE central.execution_ownership \
                         SET heartbeat_at = clock_timestamp(), \
                         lease_expires_at = clock_timestamp() + interval '30 seconds', \
                         updated_at = clock_timestamp() \
                         WHERE workspace_id = $1 AND run_id = $2 \
                         AND lease_token_hash = $3 AND fencing_generation = $4 \
                         AND lease_expires_at > clock_timestamp()",
                        w,
                        r,
                        &verifier[..],
                        lease.generation,
                    )
                    .execute(&mut **tx)
                    .await
                    .ctx("execution: heartbeat lease")?
                    .rows_affected();
                    if done != 1 {
                        return Err(conflict("STALE_LEASE_FENCE"));
                    }
                }
                Some(row) if lease.generation == row.generation + 1 => {
                    let done = sqlx::query!(
                        "UPDATE central.execution_ownership \
                         SET owner_identity = $3, heartbeat_at = clock_timestamp(), \
                         claimed_step_id = $4, claimed_step_attempt_id = $5, \
                         lease_token_hash = $6, fencing_generation = $7, \
                         lease_expires_at = clock_timestamp() + interval '30 seconds', \
                         updated_at = clock_timestamp() \
                         WHERE workspace_id = $1 AND run_id = $2 \
                         AND fencing_generation = $8 \
                         AND lease_expires_at <= clock_timestamp()",
                        w,
                        r,
                        req.principal_id,
                        opt_step_uuid(req.result.step_id),
                        opt_attempt_uuid(req.result.attempt_id),
                        &verifier[..],
                        lease.generation,
                        row.generation,
                    )
                    .execute(&mut **tx)
                    .await
                    .ctx("execution: claim expired lease")?
                    .rows_affected();
                    if done != 1 {
                        return Err(conflict("STALE_LEASE_FENCE"));
                    }
                }
                Some(_) => return Err(conflict("STALE_LEASE_FENCE")),
            }
        }
        for release in &req.change_set.lease_releases {
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
                return Err(conflict("STALE_LEASE_FENCE"));
            }
        }
        Ok(())
    }

    /// `assertNoActiveLease` — the request/change-set fence that no
    /// unexpired lease exists on the run.
    async fn assert_no_active_lease(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        rid: RunId,
    ) -> Result<(), Failure> {
        let row = sqlx::query!(
            "SELECT NOT EXISTS ( \
               SELECT 1 FROM central.execution_ownership \
               WHERE workspace_id = $1 AND run_id = $2 \
               AND lease_expires_at > clock_timestamp() \
             ) AS \"ok!\"",
            uuid_of(ws.as_bytes()),
            uuid_of(rid.as_bytes()),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("execution: assert no active lease")?;
        if !row.ok {
            return Err(conflict("ACTIVE_LEASE_CONFLICT"));
        }
        Ok(())
    }

    /// `persistAttemptAssertions` — each assertion pins the parent
    /// attempt's identity, logical operation, version and state.
    async fn persist_attempt_assertions(
        tx: &mut Transaction<'_, Postgres>,
        assertions: &[StepAttemptAssertion],
    ) -> Result<(), Failure> {
        for a in assertions {
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
                return Err(conflict("EXPECTED_VERSION_CONFLICT"));
            }
        }
        Ok(())
    }

    /// `applyTaskChangeSet` — the embedded task transition: the task
    /// row and each run row update under their expected versions; a
    /// missing row or version drift is a conflict. Task lifecycle
    /// events are persisted by [`Self::persist_evidence`].
    async fn apply_task_transition(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        change_set: &TaskChangeSet,
    ) -> Result<(), Failure> {
        if change_set.task.id.is_nil() {
            return Ok(());
        }
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
            return Err(conflict("EXPECTED_VERSION_CONFLICT"));
        }
        for run in &change_set.runs {
            let Some(expected) = change_set.run_expected_versions.get(&run.id).copied() else {
                return Err(invalid("MISSING_RUN_EXPECTED_VERSION"));
            };
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
                return Err(conflict("EXPECTED_VERSION_CONFLICT"));
            }
        }
        Ok(())
    }

    /// `persistEvidence` — task-transition events first (each with a
    /// `task.lifecycle` outbox intent), then the command's event and
    /// outbox intents, then reconciliation evidence events. One
    /// sequence reservation per row; the `(workspace, sequence)` unique
    /// index is the order proof.
    async fn persist_evidence(
        tx: &mut Transaction<'_, Postgres>,
        req: &CommitRequest,
    ) -> Result<(), Failure> {
        let ws = req.scope.workspace_id;
        let w = uuid_of(ws.as_bytes());
        let transition = req
            .change_set
            .task_transition
            .as_ref()
            .map(|t| &t.change_set);
        let task_version = transition
            .filter(|c| !c.task.id.is_nil())
            .map_or(req.expected_versions.task, |c| c.task.version);
        let task_events: &[central_task::domain::TaskEventIntent] =
            transition.map_or(&[], |c| &c.events);
        for intent in task_events {
            let sequence = reserve_event_sequence(tx, ws).await?;
            let id = uuid::Uuid::now_v7();
            let mut payload = serde_json::json!({
                "schema_version": 1,
                "type": intent.kind.as_str(),
                "occurred_at": go_rfc3339_local(intent.occurred_at),
            });
            if let Some(reason) = intent.reason {
                payload["reason"] = serde_json::Value::from(reason.as_str());
            }
            if !intent.detail.is_empty() {
                payload["detail"] = serde_json::Value::from(intent.detail.as_str());
            }
            let run = opt_uuid_of(intent.run_id, |i| i.as_bytes());
            sqlx::query!(
                "INSERT INTO central.events (\
                 id, workspace_id, event_sequence, event_type, aggregate_id, \
                 aggregate_version, command_id, run_id, payload, occurred_at, \
                 task_id, step_id, attempt_id, kind, state, producer_id, \
                 policy_version, eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, \
                 $8, $9::jsonb, clock_timestamp(), $5, NULL, NULL, \
                 $4, 'recorded', $10, 1, \
                 clock_timestamp() + interval '90 days', false)",
                id,
                w,
                sequence,
                intent.kind.as_str(),
                uuid_of(intent.task_id.as_bytes()),
                task_version,
                id,
                run,
                payload,
                req.principal_id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: insert task event")?;
            let dedup = format!(
                "task:{}:{}:{}:{}",
                uuid::Uuid::from_bytes(*intent.task_id.as_bytes()),
                task_version,
                intent.kind.as_str(),
                run.unwrap_or_default()
            );
            let outbox_payload = serde_json::json!({
                "schema_version": 1,
                "event_id": id,
                "catalog_type": "task.lifecycle",
                "deduplication_key": dedup,
            });
            sqlx::query!(
                "INSERT INTO central.outbox (\
                 id, workspace_id, event_id, delivery_state, due_at, attempt_count, \
                 created_at, updated_at, catalog_type, deduplication_key, \
                 producer_id, payload, visible_at, policy_version, \
                 eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, 'pending', clock_timestamp(), 0, \
                 clock_timestamp(), clock_timestamp(), 'task.lifecycle', $4, $5, \
                 $6::jsonb, clock_timestamp(), 1, \
                 clock_timestamp() + interval '7 days', false)",
                uuid::Uuid::now_v7(),
                w,
                id,
                dedup,
                req.principal_id,
                outbox_payload,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: insert task outbox")?;
            Self::upsert_outbox_workspace_work(tx, ws).await?;
        }
        for event in &req.change_set.events {
            let sequence = reserve_event_sequence(tx, ws).await?;
            sqlx::query!(
                "INSERT INTO central.events (\
                 id, workspace_id, event_sequence, event_type, aggregate_id, \
                 aggregate_version, command_id, run_id, payload, occurred_at, \
                 task_id, step_id, attempt_id, kind, state, producer_id, \
                 policy_version, eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, $4, $5, $6, $1, $7, $8::jsonb, \
                 clock_timestamp(), $5, $9, $10, $4, 'recorded', $11, 1, \
                 clock_timestamp() + interval '90 days', false)",
                uuid_of(event.id.as_bytes()),
                uuid_of(event.workspace_id.as_bytes()),
                sequence,
                event.kind,
                uuid_of(event.task_id.as_bytes()),
                task_version,
                opt_run_uuid(event.run_id),
                serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&event.payload))
                    .unwrap_or_default(),
                opt_step_uuid(event.step_id),
                opt_attempt_uuid(event.attempt_id),
                req.principal_id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: insert event")?;
        }
        let mut touched = std::collections::BTreeSet::new();
        for outbox in &req.change_set.outbox {
            sqlx::query!(
                "INSERT INTO central.outbox (\
                 id, workspace_id, event_id, delivery_state, due_at, attempt_count, \
                 created_at, updated_at, catalog_type, deduplication_key, \
                 producer_id, payload, visible_at, policy_version, \
                 eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, 'pending', clock_timestamp(), 0, \
                 clock_timestamp(), clock_timestamp(), $4, $5, $6, $7::jsonb, \
                 clock_timestamp(), 1, clock_timestamp() + interval '7 days', false)",
                uuid_of(outbox.id.as_bytes()),
                uuid_of(outbox.workspace_id.as_bytes()),
                uuid_of(outbox.event_id.as_bytes()),
                outbox.catalog_type,
                outbox.deduplication_key,
                outbox.producer_id,
                serde_json::from_slice::<serde_json::Value>(&go_json_escapes(&outbox.payload))
                    .unwrap_or_default(),
            )
            .execute(&mut **tx)
            .await
            .map_err(|e| classify_sqlx(&e))?;
            touched.insert(outbox.workspace_id);
        }
        for workspace in touched {
            Self::upsert_outbox_workspace_work(tx, workspace).await?;
        }
        for reconciliation in &req.change_set.reconciliations {
            let sequence = reserve_event_sequence(tx, ws).await?;
            let evidence: Vec<serde_json::Value> = reconciliation
                .evidence
                .iter()
                .map(|e| serde_json::json!({"kind": e.kind.as_str(), "reference": e.reference}))
                .collect();
            let payload = serde_json::json!({
                "schema_version": 1,
                "disposition": reconciliation.disposition.as_str(),
                "evidence": evidence,
            });
            let id = uuid::Uuid::now_v7();
            sqlx::query!(
                "INSERT INTO central.events (\
                 id, workspace_id, event_sequence, event_type, aggregate_id, \
                 aggregate_version, command_id, run_id, payload, occurred_at, \
                 task_id, step_id, attempt_id, kind, state, producer_id, \
                 policy_version, eligible_after, legal_hold) \
                 VALUES ($1, $2, $3, 'execution.reconciliation.evidence', $4, $5, \
                 $1, $6, $7::jsonb, clock_timestamp(), $4, $8, $9, \
                 'execution.reconciliation.evidence', 'recorded', $10, 1, \
                 clock_timestamp() + interval '90 days', false)",
                id,
                uuid_of(reconciliation.workspace_id.as_bytes()),
                sequence,
                uuid_of(reconciliation.task_id.as_bytes()),
                req.expected_versions.task,
                uuid_of(reconciliation.run_id.as_bytes()),
                payload,
                uuid_of(reconciliation.step_id.as_bytes()),
                uuid_of(reconciliation.attempt_id.as_bytes()),
                req.principal_id,
            )
            .execute(&mut **tx)
            .await
            .ctx("execution: insert reconciliation evidence")?;
        }
        Ok(())
    }

    /// `queryUpsertOutboxWorkspaceWork` — nudge the outbox scheduler's
    /// workspace row forward in the same transaction.
    async fn upsert_outbox_workspace_work(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
    ) -> Result<(), Failure> {
        sqlx::query!(
            "INSERT INTO central.outbox_workspace_work (workspace_id, next_visible_at) \
             VALUES ($1, clock_timestamp()) \
             ON CONFLICT (workspace_id) DO UPDATE \
             SET next_visible_at = LEAST(\
               central.outbox_workspace_work.next_visible_at, \
               EXCLUDED.next_visible_at), \
             version = central.outbox_workspace_work.version + 1",
            uuid_of(ws.as_bytes()),
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: upsert outbox workspace work")?;
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
            return Err(conflict("STALE_RECOVERY_FENCE"));
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
            .ok_or_else(|| conflict("STALE_RECOVERY_FENCE"))
    }

    // -----------------------------------------------------------------
    // Per-run recovery decisions — the upstream
    // `persistRecoveryRunDecision` port. Each run's task/run/step/
    // attempt rows are locked `FOR UPDATE` (lock order task → run →
    // step → attempt) and the evaluated domain decision is persisted in
    // the same transaction as the scan-cursor advance.
    // -----------------------------------------------------------------

    /// Harness phase 3e decision 4 — a cancelling task/run never waits
    /// on reconciliation; the cancel intent is already durable.
    fn recovery_keeps_cancelling(
        task: &central_task::domain::Task,
        run: &central_task::domain::Run,
    ) -> bool {
        task.status == central_task::domain::TaskStatus::Cancelling
            && run.status == central_task::domain::RunStatus::Cancelling
    }

    /// `recoveryRunHasActiveLease` — `Some(retry_at)` when a lease (or
    /// its 5-second stale grace) still protects the run.
    async fn active_recovery_lease_grace(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        run_id: RunId,
    ) -> Result<Option<OffsetDateTime>, Failure> {
        let row = sqlx::query!(
            "SELECT lease_expires_at + interval '5 seconds' AS \"grace!\" \
             FROM central.execution_ownership \
             WHERE workspace_id = $1 AND run_id = $2 \
             AND lease_expires_at + interval '5 seconds' > clock_timestamp() \
             FOR UPDATE",
            uuid_of(ws.as_bytes()),
            uuid_of(run_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read active recovery lease")?;
        Ok(row.map(|r| r.grace))
    }

    /// `queryExpireRecoveryLease` — clears the claim fields and stamps
    /// the lease expired; only fires past the grace window.
    async fn expire_recovery_lease(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        run_id: RunId,
    ) -> Result<(), Failure> {
        sqlx::query!(
            "UPDATE central.execution_ownership \
             SET claimed_run_id = run_id, claimed_step_id = NULL, \
             claimed_step_attempt_id = NULL, owner_scope = NULL, owner_identity = NULL, \
             heartbeat_at = clock_timestamp(), lease_expires_at = clock_timestamp(), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND run_id = $2 \
             AND lease_expires_at + interval '5 seconds' <= clock_timestamp()",
            uuid_of(ws.as_bytes()),
            uuid_of(run_id.as_bytes()),
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: expire recovery lease")?;
        Ok(())
    }

    /// `readRecoveryCompletionReceipt` — the attempt-scoped receipt,
    /// joined to the locked attempt's invocation identity. `None`
    /// covers both "no receipt" and contradictory evidence (upstream
    /// wraps validation contradictions into the not-settled path).
    async fn read_recovery_completion_receipt(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        attempt_id: StepAttemptId,
    ) -> Result<Option<central_execution::harness_run::CompletionReceipt>, Failure> {
        // Upstream `queryReadCompletionReceipt` — every receipt
        // identity leg joins to the owning attempt, so a receipt that
        // outlived (or was rekeyed under) a different attempt row does
        // not match.
        let row = sqlx::query!(
            "SELECT r.id, r.task_id, r.run_id, r.step_id, \
             r.logical_operation_id, r.physical_attempt_id, r.invocation_id, \
             r.invocation_generation, r.final_state, r.outcome::text AS \"outcome!\", \
             r.context::text AS \"context?\", r.producer_id \
             FROM central.execution_completion_receipts r \
             JOIN central.step_attempts a \
               ON a.workspace_id = r.workspace_id AND a.id = r.step_attempt_id \
               AND a.task_id = r.task_id AND a.run_id = r.run_id \
               AND a.step_id = r.step_id \
               AND a.logical_operation_id = r.logical_operation_id \
               AND a.physical_attempt_id = r.physical_attempt_id \
               AND a.invocation_id = r.invocation_id \
               AND a.invocation_generation = r.invocation_generation \
             WHERE r.workspace_id = $1 AND r.step_attempt_id = $2",
            uuid_of(ws.as_bytes()),
            uuid_of(attempt_id.as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read recovery completion receipt")?;
        let Some(row) = row else {
            return Ok(None);
        };
        // Any decode/validation drift is contradictory evidence — the
        // caller falls back to the reconciliation-required path.
        let receipt = (|| -> Result<central_execution::harness_run::CompletionReceipt, Failure> {
            let final_state = central_execution::domain::AttemptState::parse(&row.final_state)
                .ok_or_else(|| corrupt("a stored receipt final_state is outside the vocabulary"))?;
            let outcome = serde_json::from_str::<serde_json::Value>(&row.outcome)
                .ok()
                .and_then(|v| serde_json::to_vec(&v).ok())
                .ok_or_else(|| corrupt("a stored receipt outcome is not JSON"))?;
            let context = match &row.context {
                Some(raw) => serde_json::from_str::<serde_json::Value>(raw)
                    .ok()
                    .and_then(|v| serde_json::to_vec(&v).ok())
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            Ok(central_execution::harness_run::CompletionReceipt {
                workspace_id: ws,
                task_id: TaskId::from_trusted_db_bytes(*row.task_id.as_bytes()),
                run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
                step_id: StepId::from_trusted_db_bytes(*row.step_id.as_bytes()),
                attempt_id,
                logical_operation_id: LogicalOperationId(*row.logical_operation_id.as_bytes()),
                physical_attempt_id: central_execution::domain::PhysicalAttemptId(
                    *row.physical_attempt_id.as_bytes(),
                ),
                invocation_id: central_execution::domain::InvocationId(
                    *row.invocation_id.as_bytes(),
                ),
                invocation_generation: row.invocation_generation,
                final_state,
                outcome,
                context,
                b09_references: Vec::new(),
                producer_id: row.producer_id,
            })
        })();
        let mut receipt = match receipt {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        let references = sqlx::query!(
            "SELECT evidence_kind, evidence_id \
             FROM central.provider_completion_references \
             WHERE workspace_id = $1 AND completion_receipt_id = $2 \
             ORDER BY evidence_kind, evidence_id",
            uuid_of(ws.as_bytes()),
            row.id,
        )
        .fetch_all(&mut **tx)
        .await
        .ctx("execution: read recovery receipt evidence")?;
        receipt.b09_references = references
            .into_iter()
            .map(|r| B09EvidenceReference {
                kind: r.evidence_kind,
                id: r.evidence_id,
            })
            .collect();
        if receipt.validate().is_err() {
            return Ok(None);
        }
        Ok(Some(receipt))
    }

    /// `persistRecoveryCompletion` — evaluate the durable completion
    /// receipt against the locked aggregate and persist the whole
    /// evaluated change set. `Ok(None)` = "not settled": the caller
    /// takes the reconciliation-required path (upstream maps any
    /// domain rejection there — contradictory evidence, not adapter
    /// failure).
    async fn persist_recovery_completion(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        task: &central_task::domain::Task,
        run: &central_task::domain::Run,
        current: &StepAttempt,
    ) -> Result<Option<(String, i64)>, Failure> {
        let Some(receipt) = Self::read_recovery_completion_receipt(tx, ws, current.id).await?
        else {
            return Ok(None);
        };
        let step = read_step(tx, ws, task.id, run.id, current.step_id, true).await?;
        let attempt =
            read_attempt(tx, ws, task.id, run.id, current.step_id, current.id, true).await?;
        let tool_calls = read_tool_calls(tx, ws, current.id).await?;
        let tool_attempts = read_tool_attempts(tx, ws, current.id).await?;
        let now = db_now(tx).await?;
        let state = ExecutionState {
            task: central_task::domain::TaskAggregate {
                task: task.clone(),
                current_run: Some(run.clone()),
            },
            step: Some(step),
            attempt: Some(attempt),
            tool_calls,
            tool_attempts,
            lease: None,
            approval: None,
        };
        let change = match central_execution::harness_run::evaluate_recovery_completion(
            &state, &receipt, now,
        ) {
            Ok(change) => change,
            // Any domain rejection is contradictory durable evidence —
            // upstream returns not-settled so the run reconciles.
            Err(_) => return Ok(None),
        };
        let req = Self::recovery_commit_request(
            ws,
            ExpectedVersions {
                task: task.version,
                run: run.version,
                step: state.step.as_ref().map_or(0, |s| s.version),
                attempt: state.attempt.as_ref().map_or(0, |a| a.version),
                tool_call: state.tool_calls.first().map_or(0, |c| c.version),
                tool_attempt: state.tool_attempts.first().map_or(0, |a| a.version),
                ..ExpectedVersions::default()
            },
            change,
        )?;
        if let Some(transition) = &req.change_set.task_transition {
            Self::apply_task_transition(tx, ws, &transition.change_set).await?;
        }
        Self::persist_steps(tx, &req).await?;
        Self::persist_settlements(tx, &req).await?;
        Self::persist_attempts(tx, &req).await?;
        Self::persist_tool_calls(tx, &req).await?;
        Self::persist_tool_attempts(tx, &req).await?;
        Self::persist_evidence(tx, &req).await?;
        Self::expire_recovery_lease(tx, ws, run.id).await?;
        let version = req
            .change_set
            .task_transition
            .as_ref()
            .map_or(task.version, |t| t.change_set.task.version);
        Ok(Some((
            format!("completion_{}", receipt.final_state.as_str()),
            version,
        )))
    }

    /// The synthetic recovery `CommitRequest` — same shape upstream
    /// builds for `persistRecovery*`: the recovery coordinator scope,
    /// the domain's evaluated change set, and the locked rows'
    /// versions as the CAS fence.
    fn recovery_commit_request(
        ws: WorkspaceId,
        expected: ExpectedVersions,
        change_set: central_execution::domain::ExecutionChangeSet,
    ) -> Result<CommitRequest, Failure> {
        Ok(CommitRequest {
            scope: TrustedScope::new(
                "central.execution.recovery.v1",
                ws,
                &[central_execution::domain::Capability::RecoveryCoordinator],
            )
            .map_err(|_| invalid("INVALID_RECOVERY_SCOPE"))?,
            command_scope: String::new(),
            idempotency_key: String::new(),
            fingerprint: [0; 32],
            principal_id: "central.execution.recovery.v1".to_owned(),
            capability: central_execution::domain::Capability::RecoveryCoordinator,
            receipt_binding: central_execution::port::ReceiptBinding {
                task_id: central_foundation::identity::TaskId::from_trusted_db_bytes([0; 16]),
                run_id: RunId::from_trusted_db_bytes([0; 16]),
                step_id: StepId::from_trusted_db_bytes([0; 16]),
                attempt_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
                logical_operation: LogicalOperationId([0; 16]),
            },
            expected_versions: expected,
            require_recovery_claimable: false,
            lease_credential: LeaseCredential::default(),
            lease_generation: 0,
            assert_no_active_lease: false,
            result: central_execution::port::DurableResult {
                workspace_id: ws,
                task_id: central_foundation::identity::TaskId::from_trusted_db_bytes([0; 16]),
                run_id: RunId::from_trusted_db_bytes([0; 16]),
                step_id: StepId::from_trusted_db_bytes([0; 16]),
                attempt_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
                event_id: central_foundation::identity::ExecutionEventId::from_trusted_db_bytes(
                    [0; 16],
                ),
                event_kind: String::new(),
                approval_action: None,
            },
            change_set,
        })
    }

    /// `persistRecoveryCancellation` — `evaluate_recovery_cancellation`
    /// for a prepared attempt in a cancelling task/run. The emitted
    /// no-active-lease assertions are re-checked inside this
    /// transaction; a live lease is a contradiction that quarantines.
    async fn persist_recovery_cancellation(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        task: &central_task::domain::Task,
        run: &central_task::domain::Run,
        step: &Step,
        current: &StepAttempt,
    ) -> Result<i64, Failure> {
        let tool_calls = read_tool_calls(tx, ws, current.id).await?;
        let tool_attempts = read_tool_attempts(tx, ws, current.id).await?;
        let now = db_now(tx).await?;
        let change = central_execution::harness_run::evaluate_recovery_cancellation(
            &ExecutionState {
                task: central_task::domain::TaskAggregate {
                    task: task.clone(),
                    current_run: Some(run.clone()),
                },
                step: Some(step.clone()),
                attempt: Some(current.clone()),
                tool_calls: tool_calls.clone(),
                tool_attempts: tool_attempts.clone(),
                lease: None,
                approval: None,
            },
            now,
        )?;
        for assertion in &change.lease_assertions {
            if !assertion.no_active || assertion.workspace_id != ws || assertion.run_id != run.id {
                return Err(invalid("INVALID_LEASE_ASSERTION"));
            }
            let absent = sqlx::query!(
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
            .ctx("execution: assert no active recovery lease")?;
            if !absent.ok {
                return Err(conflict("ACTIVE_LEASE_CONFLICT"));
            }
        }
        let req = Self::recovery_commit_request(
            ws,
            ExpectedVersions {
                task: task.version,
                run: run.version,
                step: step.version,
                attempt: current.version,
                tool_call: tool_calls.first().map_or(0, |c| c.version),
                tool_attempt: tool_attempts.first().map_or(0, |a| a.version),
                ..ExpectedVersions::default()
            },
            change,
        )?;
        if let Some(transition) = &req.change_set.task_transition {
            Self::apply_task_transition(tx, ws, &transition.change_set).await?;
        }
        Self::persist_steps(tx, &req).await?;
        Self::persist_attempts(tx, &req).await?;
        Self::persist_tool_calls(tx, &req).await?;
        Self::persist_tool_attempts(tx, &req).await?;
        Self::persist_evidence(tx, &req).await?;
        Self::expire_recovery_lease(tx, ws, run.id).await?;
        Ok(req
            .change_set
            .task_transition
            .as_ref()
            .map_or(task.version, |t| t.change_set.task.version))
    }

    /// `persistRecoveryWaitingState` — the task-domain `Wait`
    /// transition onto `reconciliation`; a no-op when the aggregate
    /// already waits (or keeps cancelling) and
    /// `TASK_TRANSITION_REJECTED` when the domain refuses.
    async fn persist_recovery_waiting_state(
        tx: &mut Transaction<'_, Postgres>,
        ws: WorkspaceId,
        task: &central_task::domain::Task,
        run: &central_task::domain::Run,
    ) -> Result<i64, Failure> {
        if Self::recovery_keeps_cancelling(task, run) {
            return Ok(task.version);
        }
        let already = task.status == central_task::domain::TaskStatus::Waiting
            && run.status == central_task::domain::RunStatus::Waiting
            && task.waiting_reason == Some(central_task::domain::WaitingReason::Reconciliation)
            && run.waiting_reason == Some(central_task::domain::WaitingReason::Reconciliation);
        if already {
            return Ok(task.version);
        }
        let now = db_now(tx).await?;
        let transition = central_task::execution_facade::evaluate_execution_transition(
            central_task::execution_facade::ExecutionTransition::Wait(
                central_task::execution_facade::ExecutionWaitRequest {
                    aggregate: central_task::domain::TaskAggregate {
                        task: task.clone(),
                        current_run: Some(run.clone()),
                    },
                    reason: Some(central_task::domain::WaitingReason::Reconciliation),
                    detail: "recovery requires reconciliation".to_owned(),
                    now,
                    expected_task_version: task.version,
                    expected_run_version: run.version,
                },
            ),
        )
        .map_err(|_| denied("TASK_TRANSITION_REJECTED"))?;
        Self::apply_task_transition(tx, ws, &transition.change_set).await?;
        // Upstream `persistRecoveryWaitingState`: the transition is not
        // durable until its evidence is — the `task.wait` event plus a
        // `task.lifecycle` outbox row written by `persistEvidence`
        // under the recovery trusted scope.
        let new_version = transition.change_set.task.version;
        let req = Self::recovery_commit_request(
            ws,
            ExpectedVersions {
                task: task.version,
                run: run.version,
                ..ExpectedVersions::default()
            },
            central_execution::domain::ExecutionChangeSet {
                task_transition: Some(transition),
                ..central_execution::domain::ExecutionChangeSet::default()
            },
        )?;
        Self::persist_evidence(tx, &req).await?;
        Ok(new_version)
    }

    /// `persistRecoveryRunDecision` — the per-run decision ladder. The
    /// task and run rows are already locked by the caller; this locks
    /// step/attempt next (upstream lock order) and returns
    /// `(decision, step_id, attempt_id, aggregate_version)` for the
    /// evidence row.
    async fn persist_recovery_run_decision(
        tx: &mut Transaction<'_, Postgres>,
        epoch_generation: i64,
        ws: WorkspaceId,
        task: &central_task::domain::Task,
        run: &central_task::domain::Run,
    ) -> Result<(String, Option<StepId>, Option<StepAttemptId>, i64), Failure> {
        let w = uuid_of(ws.as_bytes());
        let rid = uuid_of(run.id.as_bytes());
        let candidate = sqlx::query!(
            "SELECT a.id, a.step_id FROM central.step_attempts a \
             WHERE a.workspace_id = $1 AND a.run_id = $2 \
             AND a.state IN ('prepared','invoked','settling','reconciliation') \
             ORDER BY a.updated_at DESC, a.id DESC LIMIT 1",
            w,
            rid,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("execution: read recovery attempt candidate")?;
        let Some(candidate) = candidate else {
            return Ok((
                "verified_no_unsettled_attempt".to_owned(),
                None,
                None,
                task.version,
            ));
        };
        let step_id = StepId::from_trusted_db_bytes(*candidate.step_id.as_bytes());
        let attempt_id = StepAttemptId::from_trusted_db_bytes(*candidate.id.as_bytes());
        let step = read_step(tx, ws, task.id, run.id, step_id, true).await?;
        let current = read_attempt(tx, ws, task.id, run.id, step_id, attempt_id, true).await?;
        use central_execution::domain::AttemptState;
        match current.state {
            AttemptState::AttemptPrepared => {
                // Phase 3e decision 5: a cancellation that beat
                // `MarkInvoked` settles before any successor handling.
                if Self::recovery_keeps_cancelling(task, run) {
                    let version =
                        Self::persist_recovery_cancellation(tx, ws, task, run, &step, &current)
                            .await?;
                    return Ok((
                        "cancellation_settled".to_owned(),
                        Some(step_id),
                        Some(attempt_id),
                        version,
                    ));
                }
                if !current.predecessor_id.is_nil() {
                    return Ok((
                        "prepared_successor_preserved".to_owned(),
                        Some(step_id),
                        Some(attempt_id),
                        task.version,
                    ));
                }
                // Phase 3e decision 3: mint the fenced prepared
                // successor. The predecessor's state-guarded update
                // runs before the insert because the non-deferrable
                // one-active-attempt index cannot see both rows.
                let successor = central_execution::harness_run::cancel_prepared_for_recovery(
                    &current,
                    central_execution::harness_run::RecoveryFence {
                        generation: epoch_generation,
                        successor_id: StepAttemptId::new(),
                    },
                )?;
                let done = sqlx::query!(
                    "UPDATE central.step_attempts \
                     SET state = 'cancelled', version = version + 1, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND run_id = $2 \
                     AND id = $3 AND state = 'prepared'",
                    w,
                    rid,
                    uuid_of(current.id.as_bytes()),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: cancel prepared recovery attempt")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("RECOVERY_ATTEMPT_CHANGED"));
                }
                let done = sqlx::query!(
                    "INSERT INTO central.step_attempts (\
                     id, workspace_id, step_id, task_id, run_id, version, \
                     logical_operation_id, physical_attempt_id, invocation_id, \
                     invocation_generation, predecessor_id, sequence, state, \
                     created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, \
                     $9, $10, $11, clock_timestamp(), clock_timestamp()) \
                     ON CONFLICT (id) DO NOTHING",
                    uuid_of(successor.id.as_bytes()),
                    uuid_of(successor.workspace_id.as_bytes()),
                    uuid_of(successor.step_id.as_bytes()),
                    uuid_of(successor.task_id.as_bytes()),
                    uuid_of(successor.run_id.as_bytes()),
                    successor.version,
                    uuid_for_logical(&successor.logical_operation_id),
                    uuid_for_physical(&successor.physical_attempt_id),
                    opt_attempt_uuid(successor.predecessor_id),
                    successor.sequence,
                    successor.state.as_str(),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: insert prepared recovery successor")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("RECOVERY_SUCCESSOR_CONFLICT"));
                }
                Self::expire_recovery_lease(tx, ws, run.id).await?;
                Ok((
                    "prepared_successor_created".to_owned(),
                    Some(step_id),
                    Some(successor.id),
                    task.version,
                ))
            }
            AttemptState::AttemptInvoked | AttemptState::AttemptSettling => {
                if let Some((decision, version)) =
                    Self::persist_recovery_completion(tx, ws, task, run, &current).await?
                {
                    return Ok((decision, Some(step_id), Some(attempt_id), version));
                }
                // Ambiguous chain — move the whole projection to
                // reconciliation (upstream `queryReconcile*` exact-row
                // checks), wait on it, then expire the lease.
                let done = sqlx::query!(
                    "UPDATE central.steps \
                     SET state = 'reconciliation', version = version + 1, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND run_id = $2 AND id = $3 \
                     AND state <> 'reconciliation'",
                    w,
                    rid,
                    uuid_of(step_id.as_bytes()),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: reconcile recovery step")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("RECOVERY_STEP_CHANGED"));
                }
                let done = sqlx::query!(
                    "UPDATE central.step_attempts \
                     SET state = 'reconciliation', version = version + 1, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND run_id = $2 AND id = $3 \
                     AND state IN ('invoked','settling')",
                    w,
                    rid,
                    uuid_of(attempt_id.as_bytes()),
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: reconcile ambiguous recovery attempt")?
                .rows_affected();
                if done != 1 {
                    return Err(conflict("RECOVERY_ATTEMPT_CHANGED"));
                }
                sqlx::query!(
                    "UPDATE central.tool_calls \
                     SET state = 'reconciliation', version = version + 1, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND run_id = $2 \
                     AND state IN ('invoked','settling')",
                    w,
                    rid,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: reconcile recovery tool calls")?;
                sqlx::query!(
                    "UPDATE central.tool_call_attempts \
                     SET state = 'reconciliation', version = version + 1, \
                     updated_at = clock_timestamp() \
                     WHERE workspace_id = $1 AND run_id = $2 \
                     AND state IN ('invoked','settling')",
                    w,
                    rid,
                )
                .execute(&mut **tx)
                .await
                .ctx("execution: reconcile recovery tool attempts")?;
                let version = Self::persist_recovery_waiting_state(tx, ws, task, run).await?;
                Self::expire_recovery_lease(tx, ws, run.id).await?;
                let decision = if Self::recovery_keeps_cancelling(task, run) {
                    "reconciliation_required_cancelling"
                } else {
                    "reconciliation_required"
                };
                Ok((
                    decision.to_owned(),
                    Some(step_id),
                    Some(attempt_id),
                    version,
                ))
            }
            AttemptState::AttemptReconciliation => {
                if step.state != central_execution::domain::StepState::StepReconciliation {
                    return Err(invalid("INVALID_RECOVERY_STEP_STATE"));
                }
                let version = Self::persist_recovery_waiting_state(tx, ws, task, run).await?;
                Ok((
                    "reconciliation_preserved".to_owned(),
                    Some(step_id),
                    Some(attempt_id),
                    version,
                ))
            }
            _ => Err(invalid("INVALID_RECOVERY_ATTEMPT_STATE")),
        }
    }

    /// `recoveryDecisionRequiresReconciliation` — only the two
    /// reconciliation-required decisions emit outbox work (upstream
    /// `reconciliation_preserved` deliberately does not re-emit).
    fn recovery_decision_requires_reconciliation(decision: &str) -> bool {
        matches!(
            decision,
            "reconciliation_required" | "reconciliation_required_cancelling"
        )
    }

    /// `insertRecoveryRunEvidence` — the durable
    /// `execution.recovery.<decision>` event plus, for
    /// reconciliation-required decisions, the
    /// `execution.reconciliation.required` outbox row and workspace
    /// work upsert — all inside the scan transaction.
    #[allow(clippy::too_many_arguments)]
    async fn insert_recovery_run_evidence(
        tx: &mut Transaction<'_, Postgres>,
        epoch_generation: i64,
        ws: WorkspaceId,
        task_id: TaskId,
        run_id: RunId,
        step_id: Option<StepId>,
        attempt_id: Option<StepAttemptId>,
        decision: &str,
        aggregate_version: i64,
    ) -> Result<(), Failure> {
        // Upstream locks the workspace event counter once per batch;
        // re-locking inside the same transaction is a no-op.
        lock_event_counter(tx, ws).await?;
        let sequence = reserve_event_sequence(tx, ws).await?;
        #[derive(serde::Serialize)]
        struct RecoveryRunEvidence<'a> {
            schema_version: u8,
            epoch_generation: i64,
            decision: &'a str,
            run_id: String,
        }
        let event_id = uuid::Uuid::now_v7();
        let payload = serde_json::to_vec(&RecoveryRunEvidence {
            schema_version: 1,
            epoch_generation,
            decision,
            run_id: run_id.to_string(),
        })
        .map_err(|_| corrupt("recovery run evidence payload is not encodable"))?;
        let kind = format!("execution.recovery.{decision}");
        sqlx::query!(
            "INSERT INTO central.events (\
             id, workspace_id, event_sequence, event_type, aggregate_id, \
             aggregate_version, command_id, run_id, payload, occurred_at, \
             task_id, step_id, attempt_id, kind, state, producer_id, \
             policy_version, eligible_after, legal_hold) \
             VALUES ($1, $2, $3, $4, $5, $6, $1, $7, $8::jsonb, \
             clock_timestamp(), $5, $9, $10, $4, 'recorded', \
             'central.execution.recovery.v1', 1, \
             clock_timestamp() + interval '90 days', false)",
            event_id,
            uuid_of(ws.as_bytes()),
            sequence,
            kind,
            uuid_of(task_id.as_bytes()),
            aggregate_version,
            uuid_of(run_id.as_bytes()),
            serde_json::from_slice::<serde_json::Value>(&payload).unwrap_or_default(),
            opt_uuid_of(step_id, |i| i.as_bytes()),
            opt_uuid_of(attempt_id, |i| i.as_bytes()),
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: insert recovery run evidence")?;
        if !Self::recovery_decision_requires_reconciliation(decision) {
            return Ok(());
        }
        let outbox_id = uuid::Uuid::now_v7();
        let deduplication_key = format!("recovery:{epoch_generation}:{run_id}");
        // Go marshals map keys sorted — BTreeMap gives the identical
        // byte layout upstream persists.
        let outbox_payload = serde_json::to_vec(&serde_json::json!({
            "catalog_type": central_execution::domain::OUTBOX_RECONCILIATION_REQUIRED,
            "deduplication_key": deduplication_key,
            "event_id": event_id.to_string(),
            "schema_version": 1,
        }))
        .map_err(|_| corrupt("recovery outbox payload is not encodable"))?;
        sqlx::query!(
            "INSERT INTO central.outbox (\
             id, workspace_id, event_id, delivery_state, due_at, attempt_count, \
             created_at, updated_at, catalog_type, deduplication_key, \
             producer_id, payload, visible_at, policy_version, \
             eligible_after, legal_hold) \
             VALUES ($1, $2, $3, 'pending', clock_timestamp(), 0, \
             clock_timestamp(), clock_timestamp(), $4, $5, \
             'central.execution.recovery.v1', $6::jsonb, \
             clock_timestamp(), 1, clock_timestamp() + interval '7 days', false)",
            outbox_id,
            uuid_of(ws.as_bytes()),
            event_id,
            central_execution::domain::OUTBOX_RECONCILIATION_REQUIRED,
            deduplication_key,
            serde_json::from_slice::<serde_json::Value>(&outbox_payload).unwrap_or_default(),
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: insert recovery reconciliation outbox")?;
        sqlx::query!(
            "INSERT INTO central.outbox_workspace_work (workspace_id, next_visible_at) \
             VALUES ($1, clock_timestamp()) \
             ON CONFLICT (workspace_id) DO UPDATE \
             SET next_visible_at = LEAST(\
               central.outbox_workspace_work.next_visible_at, \
               EXCLUDED.next_visible_at), \
             version = central.outbox_workspace_work.version + 1",
            uuid_of(ws.as_bytes()),
        )
        .execute(&mut **tx)
        .await
        .ctx("execution: upsert recovery outbox work")?;
        Ok(())
    }

    /// `scanRecoveryWorkspaceBatch` — one bounded keyset batch in its
    /// own fenced transaction (upstream: renew coordinator lease → lock
    /// epoch → lock + renew the claim row → select ≤ `batch` runs →
    /// per-run decision + evidence + cursor advance + reconciled mark).
    /// Returns the remaining-work verdict; a live lease grace aborts
    /// the batch (rollback) and reports the database-derived wait.
    async fn scan_recovery_workspace_batch(
        &self,
        request: &CompleteRecoveryWorkspaceRequest,
    ) -> Result<RecoveryBatchOutcome, Failure> {
        let claim_hash = sha256(&request.claim_token);
        let domain = request.lease.recovery_domain.as_str();
        let ws = request.workspace_id;
        let mut tx = begin_recovery_scan(&self.pool).await?;
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        let epoch = read_locked_recovery_epoch(
            &mut tx,
            request.epoch_generation,
            request.lease.fence.generation,
            domain,
        )
        .await?;
        if !matches!(
            epoch.state,
            RecoveryEpochState::RecoveryEpochOpen | RecoveryEpochState::RecoveryEpochRunning
        ) {
            return Err(conflict("RECOVERY_EPOCH_QUARANTINED"));
        }
        // `queryLockRecoveryWorkspaceClaim` — the claim row under the
        // presented token, `FOR UPDATE OF work`.
        let work_row = sqlx::query!(
            "SELECT work.cursor_created_at, work.cursor_run_id \
             FROM central.recovery_epoch_workspaces AS work \
             JOIN central.recovery_epochs AS epoch \
               ON epoch.epoch_generation = work.epoch_generation \
              AND epoch.coordinator_domain = $4 \
             WHERE work.epoch_generation = $1 AND work.workspace_id = $2 \
             AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
             FOR UPDATE OF work",
            request.epoch_generation,
            uuid_of(ws.as_bytes()),
            &claim_hash[..],
            domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: lock recovery workspace claim")?
        .ok_or_else(|| conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"))?;
        // `queryRenewRecoveryWorkspaceClaim` — extends the claim TTL.
        let renewed = sqlx::query!(
            "UPDATE central.recovery_epoch_workspaces AS work \
             SET claim_expires_at = clock_timestamp() + interval '30 seconds', \
             updated_at = clock_timestamp() \
             WHERE work.epoch_generation = $1 AND workspace_id = $2 \
             AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
             AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
               WHERE epoch.epoch_generation = work.epoch_generation \
                 AND epoch.coordinator_domain = $4) \
             RETURNING claim_expires_at",
            request.epoch_generation,
            uuid_of(ws.as_bytes()),
            &claim_hash[..],
            domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: renew recovery workspace claim")?;
        if renewed.is_none() {
            return Err(conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"));
        }
        // `querySelectRecoveryRunsAfterCursor` — the watermark-bounded
        // keyset page (a NULL cursor reads from the watermark's start).
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
            request.epoch_generation,
            uuid_of(ws.as_bytes()),
            work_row.cursor_created_at,
            work_row.cursor_run_id,
            RECOVERY_SCAN_BATCH,
            domain,
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("execution: select recovery run batch")?;
        if !runs.is_empty() {
            // Upstream locks the workspace event counter once per batch.
            lock_event_counter(&mut tx, ws).await?;
        }
        for row in &runs {
            let task_id = TaskId::from_trusted_db_bytes(*row.task_id.as_bytes());
            let run_id = RunId::from_trusted_db_bytes(*row.id.as_bytes());
            // Lock order: task → run (both `FOR UPDATE`) before the
            // candidate's step/attempt locks inside the decision.
            let task = read_task(&mut tx, ws, task_id, true).await?;
            let run = read_run(&mut tx, ws, task_id, run_id, true).await?;
            if let Some(retry_at) = Self::active_recovery_lease_grace(&mut tx, ws, run_id).await? {
                // A live lease (or grace) is not a failure: the batch
                // tx rolls back untouched and the caller schedules the
                // lease wait without spending the retry budget.
                return Ok(RecoveryBatchOutcome::LeaseWait(retry_at));
            }
            let (decision, step_id, attempt_id, aggregate_version) =
                Self::persist_recovery_run_decision(
                    &mut tx,
                    request.epoch_generation,
                    ws,
                    &task,
                    &run,
                )
                .await?;
            Self::insert_recovery_run_evidence(
                &mut tx,
                request.epoch_generation,
                ws,
                task_id,
                run_id,
                step_id,
                attempt_id,
                &decision,
                aggregate_version,
            )
            .await?;
            // `queryAdvanceRecoveryWorkspaceScan` — cursor + counters +
            // claim renewal in one fenced statement.
            let done = sqlx::query!(
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
                request.epoch_generation,
                uuid_of(ws.as_bytes()),
                &claim_hash[..],
                row.created_at,
                row.id,
                domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: advance recovery workspace scan")?
            .rows_affected();
            if done != 1 {
                return Err(conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"));
            }
            // `queryMarkRecoveryRunReconciled` — exactly one row or the
            // run changed under us.
            let done = sqlx::query!(
                "UPDATE central.runs \
                 SET reconciled_epoch = $1, updated_at = clock_timestamp() \
                 WHERE workspace_id = $2 AND id = $3 \
                 AND reconciled_epoch < $1 \
                 AND EXISTS (SELECT 1 FROM central.recovery_epochs epoch \
                   WHERE epoch.epoch_generation = $1 AND epoch.coordinator_domain = $4)",
                request.epoch_generation,
                uuid_of(ws.as_bytes()),
                row.id,
                domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: mark recovery run reconciled")?
            .rows_affected();
            if done != 1 {
                return Err(conflict("RECOVERY_RUN_CHANGED"));
            }
        }
        // `queryCountRecoveryRunsRemaining` — the workspace completes
        // only when no pre-watermark run remains unreconciled.
        let remaining = sqlx::query!(
            "SELECT count(*) AS \"count!\" \
             FROM central.runs r \
             JOIN central.recovery_epoch_workspaces w \
               ON w.epoch_generation = $1 AND w.workspace_id = r.workspace_id \
             JOIN central.recovery_epochs e \
               ON e.epoch_generation = w.epoch_generation AND e.coordinator_domain = $3 \
             WHERE r.workspace_id = $2 AND r.reconciled_epoch < $1 \
               AND (r.created_at < w.watermark_created_at \
                    OR (r.created_at = w.watermark_created_at AND r.id <= w.watermark_run_id))",
            request.epoch_generation,
            uuid_of(ws.as_bytes()),
            domain,
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("execution: count recovery runs remaining")?
        .count;
        if remaining == 0 {
            // `queryFinishRecoveryWorkspace`.
            let done = sqlx::query!(
                "UPDATE central.recovery_epoch_workspaces AS work \
                 SET delivery_state = 'completed', claim_token_hash = NULL, \
                 claim_expires_at = NULL, retry_not_before = NULL, \
                 failure_class = NULL, failure_reason = NULL, \
                 updated_at = clock_timestamp() \
                 WHERE work.epoch_generation = $1 AND work.workspace_id = $2 \
                 AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
                 AND EXISTS (SELECT 1 FROM central.recovery_epochs epoch \
                   WHERE epoch.epoch_generation = work.epoch_generation \
                     AND epoch.coordinator_domain = $4)",
                request.epoch_generation,
                uuid_of(ws.as_bytes()),
                &claim_hash[..],
                domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: finish recovery workspace")?
            .rows_affected();
            if done != 1 {
                return Err(conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"));
            }
            // `queryCountIncompleteRecoveryWorkspaces` +
            // `queryFinishRecoveryEpoch` — the epoch completes when no
            // pending/claimed/failed workspace remains.
            let incomplete = sqlx::query!(
                "SELECT count(*) AS \"count!\" \
                 FROM central.recovery_epoch_workspaces AS work \
                 JOIN central.recovery_epochs AS epoch \
                   ON epoch.epoch_generation = work.epoch_generation \
                  AND epoch.coordinator_domain = $2 \
                 WHERE work.epoch_generation = $1 \
                 AND work.delivery_state IN ('pending','claimed','failed')",
                request.epoch_generation,
                domain,
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("execution: count incomplete recovery workspaces")?
            .count;
            sqlx::query!(
                "UPDATE central.recovery_epochs \
                 SET state = $2, \
                 completed_at = CASE WHEN $3 THEN clock_timestamp() ELSE NULL END, \
                 updated_at = clock_timestamp() \
                 WHERE epoch_generation = $1 AND coordinator_domain = $4",
                request.epoch_generation,
                if incomplete == 0 {
                    "completed"
                } else {
                    "running"
                },
                incomplete == 0,
                domain,
            )
            .execute(&mut *tx)
            .await
            .ctx("execution: finish recovery epoch")?;
        }
        tx.commit()
            .await
            .ctx("execution: commit recovery scan batch")?;
        Ok(RecoveryBatchOutcome::Progress {
            completed: remaining == 0,
        })
    }

    /// `scheduleRecoveryWorkspaceRetry` — bumps `retry_attempt` and
    /// records the bounded backoff under the held claim. `Ok(None)`
    /// means the budget is spent and the caller quarantines.
    async fn schedule_recovery_workspace_retry(
        &self,
        request: &CompleteRecoveryWorkspaceRequest,
    ) -> Result<Option<std::time::Duration>, Failure> {
        let claim_hash = sha256(&request.claim_token);
        let domain = request.lease.recovery_domain.as_str();
        let mut tx = begin(&self.pool).await?;
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        read_locked_recovery_epoch(
            &mut tx,
            request.epoch_generation,
            request.lease.fence.generation,
            domain,
        )
        .await?;
        let current = sqlx::query!(
            "SELECT work.retry_attempt \
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
            domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: read recovery retry attempt")?
        .ok_or_else(|| conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"))?;
        if current.retry_attempt >= RECOVERY_RETRY_LIMIT {
            tx.commit()
                .await
                .ctx("execution: commit exhausted recovery retry")?;
            return Ok(None);
        }
        // Upstream `recoveryRetryBackoff(current+1, …)`: `attempt < 1`
        // clamps to one, then `attempt - 1` doublings — net
        // `100ms << current` with a 5s cap plus ≤25% jitter.
        let base_ms = 100i64.saturating_mul(
            2i64.saturating_pow(u32::try_from(current.retry_attempt).unwrap_or(31).min(31)),
        );
        let jitter_ms = base_ms / 4 * i64::from(uuid::Uuid::now_v7().as_bytes()[0]) / 255;
        let delay_ms = (base_ms + jitter_ms).clamp(100, 5000);
        let attempt = sqlx::query!(
            "UPDATE central.recovery_epoch_workspaces AS work \
             SET retry_attempt = retry_attempt + 1, \
             retry_not_before = clock_timestamp() + $4::interval, \
             failure_class = $5, failure_reason = $6, \
             claim_expires_at = clock_timestamp() + interval '30 seconds', \
             updated_at = clock_timestamp() \
             WHERE work.epoch_generation = $1 AND workspace_id = $2 \
             AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
             AND work.retry_attempt < 5 \
             AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
               WHERE epoch.epoch_generation = work.epoch_generation \
                 AND epoch.coordinator_domain = $7) \
             RETURNING retry_attempt",
            request.epoch_generation,
            uuid_of(request.workspace_id.as_bytes()),
            &claim_hash[..],
            sqlx::postgres::types::PgInterval::try_from(std::time::Duration::from_millis(
                delay_ms as u64,
            ))
            .unwrap_or_default(),
            "retryable_database",
            "transient recovery scan failure",
            domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: schedule recovery retry")?
        .ok_or_else(|| conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"))?;
        if attempt.retry_attempt > RECOVERY_RETRY_LIMIT {
            return Err(invalid("INVALID_RECOVERY_RETRY_STATE"));
        }
        tx.commit().await.ctx("execution: commit recovery retry")?;
        Ok(Some(std::time::Duration::from_millis(delay_ms as u64)))
    }

    /// `scheduleRecoveryWorkspaceLeaseWait` — records the
    /// database-derived point the run may be inspected again. A live
    /// lease is not a failure and never consumes the retry budget.
    async fn schedule_recovery_workspace_lease_wait(
        &self,
        request: &CompleteRecoveryWorkspaceRequest,
        due: OffsetDateTime,
    ) -> Result<std::time::Duration, Failure> {
        let claim_hash = sha256(&request.claim_token);
        let domain = request.lease.recovery_domain.as_str();
        let mut tx = begin(&self.pool).await?;
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        read_locked_recovery_epoch(
            &mut tx,
            request.epoch_generation,
            request.lease.fence.generation,
            domain,
        )
        .await?;
        let row = sqlx::query!(
            "UPDATE central.recovery_epoch_workspaces AS work \
             SET retry_not_before = GREATEST($4::timestamptz, clock_timestamp()), \
             failure_class = 'lease_grace', \
             failure_reason = 'execution lease recovery grace is active', \
             claim_expires_at = clock_timestamp() + interval '30 seconds', \
             updated_at = clock_timestamp() \
             WHERE work.epoch_generation = $1 AND workspace_id = $2 \
             AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
             AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
               WHERE epoch.epoch_generation = work.epoch_generation \
                 AND epoch.coordinator_domain = $5) \
             RETURNING retry_not_before, clock_timestamp() AS \"now!\"",
            request.epoch_generation,
            uuid_of(request.workspace_id.as_bytes()),
            &claim_hash[..],
            due,
            domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: schedule recovery lease wait")?
        .ok_or_else(|| conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"))?;
        tx.commit()
            .await
            .ctx("execution: commit recovery lease wait")?;
        let delay = row
            .retry_not_before
            .map(|t| (t - row.now).whole_milliseconds())
            .unwrap_or(0);
        Ok(std::time::Duration::from_millis(
            u64::try_from(delay.max(0)).unwrap_or(0),
        ))
    }

    /// `renewRecoveryHandles` — the mid-wait coordinator renew plus
    /// claim refresh so a long lease wait cannot let the fences lapse.
    async fn renew_recovery_handles(
        &self,
        request: &CompleteRecoveryWorkspaceRequest,
    ) -> Result<(), Failure> {
        let claim_hash = sha256(&request.claim_token);
        let domain = request.lease.recovery_domain.as_str();
        let mut tx = begin(&self.pool).await?;
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        read_locked_recovery_epoch(
            &mut tx,
            request.epoch_generation,
            request.lease.fence.generation,
            domain,
        )
        .await?;
        let renewed = sqlx::query!(
            "UPDATE central.recovery_epoch_workspaces AS work \
             SET claim_expires_at = clock_timestamp() + interval '30 seconds', \
             updated_at = clock_timestamp() \
             WHERE work.epoch_generation = $1 AND workspace_id = $2 \
             AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
             AND EXISTS (SELECT 1 FROM central.recovery_epochs AS epoch \
               WHERE epoch.epoch_generation = work.epoch_generation \
                 AND epoch.coordinator_domain = $4) \
             RETURNING claim_expires_at",
            request.epoch_generation,
            uuid_of(request.workspace_id.as_bytes()),
            &claim_hash[..],
            domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: renew recovery workspace claim")?;
        if renewed.is_none() {
            return Err(conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"));
        }
        tx.commit()
            .await
            .ctx("execution: commit recovery renewal")?;
        Ok(())
    }

    /// `waitForRecoveryRetry` — sleeps the scheduled delay in
    /// renewal-interval chunks, re-fencing the handles between chunks.
    async fn wait_for_recovery_retry(
        &self,
        request: &CompleteRecoveryWorkspaceRequest,
        delay: std::time::Duration,
    ) -> Result<(), Failure> {
        let mut remaining = delay;
        while !remaining.is_zero() {
            let chunk = remaining.min(RECOVERY_RENEW_INTERVAL);
            tokio::time::sleep(chunk).await;
            remaining = remaining.saturating_sub(chunk);
            if !remaining.is_zero() {
                self.renew_recovery_handles(request).await?;
            }
        }
        Ok(())
    }

    /// `failRecoveryWorkspace` — the degraded path in its own
    /// transaction (upstream: renew lease, lock epoch, fail the claimed
    /// row, degrade the epoch).
    async fn fail_recovery_workspace(
        &self,
        request: &CompleteRecoveryWorkspaceRequest,
    ) -> Result<(), Failure> {
        let claim_hash = sha256(&request.claim_token);
        let domain = request.lease.recovery_domain.as_str();
        let mut tx = begin(&self.pool).await?;
        Self::renew_recovery_coordinator(&mut tx, &request.lease).await?;
        read_locked_recovery_epoch(
            &mut tx,
            request.epoch_generation,
            request.lease.fence.generation,
            domain,
        )
        .await?;
        let done = sqlx::query!(
            "UPDATE central.recovery_epoch_workspaces AS work \
             SET delivery_state = 'failed', claim_token_hash = NULL, \
             claim_expires_at = NULL, retry_not_before = NULL, \
             failure_class = $4, failure_reason = $5, \
             updated_at = clock_timestamp() \
             WHERE work.epoch_generation = $1 AND work.workspace_id = $2 \
             AND work.delivery_state = 'claimed' AND work.claim_token_hash = $3 \
             AND EXISTS (SELECT 1 FROM central.recovery_epochs epoch \
               WHERE epoch.epoch_generation = work.epoch_generation \
                 AND epoch.coordinator_domain = $6)",
            request.epoch_generation,
            uuid_of(request.workspace_id.as_bytes()),
            &claim_hash[..],
            request.failure_class.trim(),
            request.failure_reason.trim(),
            domain,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: fail recovery workspace")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("RECOVERY_WORKSPACE_NOT_CLAIMED"));
        }
        sqlx::query!(
            "UPDATE central.recovery_epochs \
             SET state = 'degraded', completed_at = NULL, \
             updated_at = clock_timestamp() \
             WHERE epoch_generation = $1 AND coordinator_domain = $2",
            request.epoch_generation,
            domain,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: degrade recovery epoch")?;
        tx.commit()
            .await
            .ctx("execution: commit failed recovery workspace")?;
        Ok(())
    }
}

/// The scan batch verdict — `Progress` carries whether the workspace's
/// pre-watermark runs are all reconciled; `LeaseWait` aborts the batch
/// (its transaction rolls back untouched) and reports the
/// database-derived instant recovery may inspect the run again.
enum RecoveryBatchOutcome {
    Progress { completed: bool },
    LeaseWait(OffsetDateTime),
}

/// `isRetryableRecoveryScan` — the sanitized-Failure equivalent:
/// ambiguous (serialization/deadlock/lock-timeout), unavailable
/// (connection/resource), and cancelled (`57014`) kinds are the
/// retryable lane; every domain failure quarantines instead.
fn is_retryable_recovery_scan(err: &Failure) -> bool {
    matches!(
        err.kind(),
        FailureKind::Ambiguous | FailureKind::Unavailable | FailureKind::Cancelled
    )
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

impl Store {
    /// `commandEventKind` — the closed command→event table. Unknown
    /// scopes answer `None`; `execution.complete_with_receipt` is the
    /// Rust app's receipt-driven settle and shares `execution.settle`'s
    /// evidence shape (upstream has no caller for it — the in-scan
    /// completion path persists its change set directly).
    fn command_event_kind(scope: &str) -> Option<&'static str> {
        use central_execution::domain as d;
        Some(match scope {
            "execution.prepare" => d::EVENT_ATTEMPT_PREPARED,
            "execution.claim" => d::EVENT_ATTEMPT_CLAIMED,
            "execution.heartbeat" => d::EVENT_ATTEMPT_HEARTBEAT,
            "execution.mark_invoked" => d::EVENT_ATTEMPT_INVOKED,
            "execution.prepare_tool_call" => d::EVENT_TOOL_CALL_PREPARED,
            "execution.mark_tool_call_invoked" => d::EVENT_TOOL_CALL_INVOKED,
            "execution.settle_tool_call" => d::EVENT_TOOL_CALL_SETTLED,
            "execution.settle" | "execution.complete_with_receipt" => d::EVENT_ATTEMPT_SETTLED,
            "execution.cancel" | "execution.settle_cancellation" => d::EVENT_ATTEMPT_CANCELLED,
            "execution.enter_reconciliation" => d::EVENT_ATTEMPT_RECONCILIATION,
            "execution.schedule_retry" => d::EVENT_ATTEMPT_RETRY_SCHEDULED,
            "execution.record_checkpoint" => d::EVENT_CHECKPOINT_RECORDED,
            "execution.record_approval" => d::EVENT_APPROVAL_RECORDED,
            "execution.resolve_approval" => d::EVENT_APPROVAL_RESOLVED,
            "execution.expire_approval" => d::EVENT_APPROVAL_EXPIRED,
            "execution.create_approval_successor" => d::EVENT_APPROVAL_SUCCESSOR,
            "execution.resolve_reconciliation" => d::EVENT_RECONCILIATION_RESOLVED,
            "execution.start_harness_run" => d::EVENT_HARNESS_RUN_STARTED,
            "execution.abandon_prepared" => d::EVENT_ATTEMPT_ABANDONED,
            "execution.resume_reconciled_attempt" => d::EVENT_ATTEMPT_RESUMED,
            _ => return None,
        })
    }

    /// `commandOutboxCatalog` — the closed command→catalog table.
    fn command_outbox_catalog(scope: &str) -> Option<&'static str> {
        use central_execution::domain as d;
        Some(match scope {
            "execution.prepare" => d::OUTBOX_ATTEMPT_PREPARED,
            "execution.claim"
            | "execution.heartbeat"
            | "execution.mark_invoked"
            | "execution.start_harness_run" => d::OUTBOX_ATTEMPT_CLAIMED,
            "execution.prepare_tool_call" => d::OUTBOX_TOOL_CALL_PREPARED,
            "execution.mark_tool_call_invoked" => d::OUTBOX_TOOL_CALL_INVOKED,
            "execution.settle_tool_call" => d::OUTBOX_TOOL_CALL_SETTLED,
            "execution.settle"
            | "execution.cancel"
            | "execution.settle_cancellation"
            | "execution.resolve_reconciliation"
            | "execution.schedule_retry"
            | "execution.abandon_prepared"
            | "execution.resume_reconciled_attempt"
            | "execution.complete_with_receipt" => d::OUTBOX_ATTEMPT_SETTLED,
            "execution.enter_reconciliation" => d::OUTBOX_RECONCILIATION_REQUIRED,
            "execution.record_checkpoint" => d::OUTBOX_CHECKPOINT_RECORDED,
            "execution.record_approval"
            | "execution.resolve_approval"
            | "execution.expire_approval"
            | "execution.create_approval_successor" => d::OUTBOX_APPROVAL_RECORDED,
            _ => return None,
        })
    }

    /// `validateReceiptBinding` — the binding must name the same
    /// durable target the result carries.
    fn validate_receipt_binding(
        binding: &central_execution::port::ReceiptBinding,
        result: &DurableResult,
    ) -> Result<(), Failure> {
        if binding.task_id.is_nil()
            || binding.run_id.is_nil()
            || binding.step_id.is_nil()
            || binding.attempt_id.is_nil()
            || binding.logical_operation.is_nil()
            || binding.task_id != result.task_id
            || binding.run_id != result.run_id
            || binding.step_id != result.step_id
            || binding.attempt_id != result.attempt_id
        {
            return Err(invalid("INVALID_RECEIPT_BINDING"));
        }
        Ok(())
    }

    /// `validateAttemptOwnership` — every `attempts` row belongs to the
    /// result's step. The reconciled-attempt scope alone may carry
    /// exactly one row outside it: the new attempt, inside a step the
    /// same change set inserts (`changeSetCarriesStep`).
    fn validate_attempt_ownership(req: &CommitRequest) -> Result<(), Failure> {
        let result = &req.result;
        let mut foreign = 0usize;
        for row in &req.change_set.attempts {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
            {
                return Err(denied("SCOPE_MISMATCH"));
            }
            if row.step_id == result.step_id {
                continue;
            }
            if req.command_scope != RESUME_ATTEMPT_SCOPE
                || !Self::change_set_carries_step(req, row.step_id)
            {
                return Err(denied("SCOPE_MISMATCH"));
            }
            foreign += 1;
        }
        if req.command_scope == RESUME_ATTEMPT_SCOPE && foreign != 1 {
            return Err(denied("SCOPE_MISMATCH"));
        }
        Ok(())
    }

    /// `changeSetCarriesStep` — the change set carries a `steps` row
    /// with this id other than the result's step.
    fn change_set_carries_step(req: &CommitRequest, id: StepId) -> bool {
        if id == req.result.step_id {
            return false;
        }
        req.change_set.steps.iter().any(|step| step.id == id)
    }

    /// `validateResumedStepShape` — under the reconciled-attempt scope
    /// the change set carries exactly two step rows: the binding step
    /// and one inserted step at `sequence + 1`, version 1, running,
    /// bound to the same workspace/task/run. The old step holds exactly
    /// the binding's attempt row; the new attempt carries a logical
    /// operation different from the binding's.
    fn validate_resumed_step_shape(req: &CommitRequest) -> Result<(), Failure> {
        if req.command_scope != RESUME_ATTEMPT_SCOPE {
            return Ok(());
        }
        let binding = &req.receipt_binding;
        let mut bound = Vec::new();
        let mut inserted = Vec::new();
        for row in &req.change_set.steps {
            if row.id == binding.step_id {
                bound.push(row);
            } else {
                inserted.push(row);
            }
        }
        if bound.len() != 1 || inserted.len() != 1 {
            return Err(denied("SCOPE_MISMATCH"));
        }
        let (old, next) = (bound[0], inserted[0]);
        if next.sequence != old.sequence + 1
            || next.version != 1
            || next.state != StepState::StepRunning
            || next.workspace_id != old.workspace_id
            || next.task_id != old.task_id
            || next.run_id != old.run_id
        {
            return Err(denied("SCOPE_MISMATCH"));
        }
        let mut in_old_step = 0usize;
        for row in &req.change_set.attempts {
            if row.step_id == old.id {
                if row.id != binding.attempt_id {
                    return Err(denied("SCOPE_MISMATCH"));
                }
                in_old_step += 1;
            } else if row.step_id == next.id {
                if row.logical_operation_id == binding.logical_operation {
                    return Err(denied("SCOPE_MISMATCH"));
                }
            } else {
                // Unreachable for legitimate change sets — every attempt
                // is in the old or the inserted step
                // (`validate_attempt_ownership`).
                return Err(denied("SCOPE_MISMATCH"));
            }
        }
        if in_old_step != 1 {
            return Err(denied("SCOPE_MISMATCH"));
        }
        Ok(())
    }

    /// `validateChangeSetOwnership` — every durable record binds to the
    /// result's workspace/task/run, events are unique and carry the
    /// result's event leg with a matching kind, and outbox intents
    /// reference an event in the same change set on the same workspace.
    fn validate_change_set_ownership(req: &CommitRequest) -> Result<(), Failure> {
        let cs = &req.change_set;
        let result = &req.result;
        let scope_err = || denied("SCOPE_MISMATCH");
        // Events: unique ids, result-bound legs (including step and
        // attempt), and the result's event leg must be present.
        let mut events: std::collections::BTreeMap<
            ExecutionEventId,
            &central_execution::domain::EventIntent,
        > = std::collections::BTreeMap::new();
        let mut result_leg = false;
        for row in &cs.events {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
                || row.step_id != result.step_id
                || row.attempt_id != result.attempt_id
            {
                return Err(scope_err());
            }
            if events.insert(row.id, row).is_some() {
                return Err(invalid("DUPLICATE_EVENT"));
            }
            if row.id == result.event_id && row.kind == result.event_kind {
                result_leg = true;
            }
        }
        if !result_leg {
            return Err(invalid("INVALID_DURABLE_RESULT"));
        }
        for row in &cs.outbox {
            match events.get(&row.event_id) {
                Some(event)
                    if row.workspace_id == result.workspace_id
                        && event.workspace_id == row.workspace_id => {}
                _ => return Err(invalid("OUTBOX_EVENT_MISMATCH")),
            }
        }
        for row in &cs.steps {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
            {
                return Err(scope_err());
            }
        }
        Self::validate_attempt_ownership(req)?;
        Self::validate_resumed_step_shape(req)?;
        for row in &cs.tool_calls {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
                || row.step_attempt_id != result.attempt_id
            {
                return Err(scope_err());
            }
        }
        for row in &cs.tool_attempts {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
                || row.step_attempt_id != result.attempt_id
            {
                return Err(scope_err());
            }
        }
        for row in &cs.checkpoints {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
                || row.step_id != result.step_id
                || row.step_attempt_id != result.attempt_id
            {
                return Err(scope_err());
            }
        }
        for row in &cs.approvals {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
                || row.step_id != result.step_id
            {
                return Err(scope_err());
            }
        }
        for row in &cs.leases {
            if row.workspace_id != result.workspace_id || row.run_id != result.run_id {
                return Err(scope_err());
            }
        }
        for row in &cs.lease_releases {
            if row.workspace_id != result.workspace_id || row.run_id != result.run_id {
                return Err(scope_err());
            }
        }
        for row in &cs.lease_assertions {
            if row.workspace_id != result.workspace_id || row.run_id != result.run_id {
                return Err(scope_err());
            }
        }
        for row in &cs.settlements {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
                || row.step_id != result.step_id
                || row.attempt_id != result.attempt_id
            {
                return Err(scope_err());
            }
        }
        for row in &cs.tool_settlements {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
                || row.step_id != result.step_id
                || row.attempt_id != result.attempt_id
            {
                return Err(scope_err());
            }
        }
        for row in &cs.reconciliations {
            if row.workspace_id != result.workspace_id
                || row.task_id != result.task_id
                || row.run_id != result.run_id
                || row.step_id != result.step_id
                || row.attempt_id != result.attempt_id
            {
                return Err(scope_err());
            }
        }
        if let Some(transition) = &cs.task_transition {
            let change = &transition.change_set;
            if !change.task.id.is_nil()
                && (change.task.workspace_id != result.workspace_id
                    || change.task.id != result.task_id)
            {
                return Err(scope_err());
            }
            for row in &change.events {
                if row.task_id != result.task_id || row.run_id != Some(result.run_id) {
                    return Err(scope_err());
                }
            }
            for row in &change.runs {
                if row.workspace_id != result.workspace_id
                    || row.task_id != result.task_id
                    || row.id != result.run_id
                {
                    return Err(scope_err());
                }
            }
        }
        Ok(())
    }

    /// `validateApprovalActionBinding` — the persisted approval action
    /// is only legal on the successor scope and must equal the one
    /// legal descriptor for the caller's scope: without `Approver` it
    /// is exactly `{RequiredCapability: Approver}` (every other field
    /// zero); with it, the descriptor the evaluator bound to the
    /// successor rows.
    fn validate_approval_action_binding(req: &CommitRequest) -> Result<(), Failure> {
        if req.command_scope != "execution.create_approval_successor" {
            if req.result.approval_action.is_some() {
                return Err(invalid("INVALID_DURABLE_RESULT"));
            }
            return Ok(());
        }
        let Some(action) = &req.result.approval_action else {
            return Err(invalid("INVALID_DURABLE_RESULT"));
        };
        if req.change_set.steps.len() != 1 || req.change_set.approvals.len() != 1 {
            return Err(invalid("INVALID_DURABLE_RESULT"));
        }
        let mut expected = central_execution::domain::ApprovalSuccessorActionDescriptor {
            action: None,
            authorized: false,
            required_capability: Some(central_execution::domain::Capability::Approver),
            step_id: NIL_STEP_ID,
            approval_id: NIL_APPROVAL_ID,
            logical_operation_id: LogicalOperationId([0; 16]),
            approval_subject_version: 0,
            expected_versions: ExpectedVersions::default(),
        };
        if req
            .scope
            .allows(central_execution::domain::Capability::Approver)
        {
            let step = &req.change_set.steps[0];
            let approval = &req.change_set.approvals[0];
            expected.authorized = true;
            expected.action =
                Some(central_execution::domain::ApprovalAction::ActionResolveApproval);
            expected.step_id = step.id;
            expected.approval_id = approval.id;
            expected.logical_operation_id = approval.subject.logical_operation_id;
            expected.approval_subject_version = approval.subject.version;
            expected.expected_versions = ExpectedVersions {
                step: step.version,
                attempt: 0,
                tool_call: 0,
                tool_attempt: 0,
                approval: approval.version,
                ..req.expected_versions
            };
        }
        if *action != expected {
            return Err(invalid("INVALID_DURABLE_RESULT"));
        }
        Ok(())
    }

    /// `validateCommandFencePolicy` — the event/outbox evidence legs
    /// must match the closed scope tables, and each scope family's
    /// lease-intent shape is enforced exactly as upstream.
    fn validate_command_fence_policy(req: &CommitRequest) -> Result<(), Failure> {
        let cs = &req.change_set;
        if cs.events.len() != 1
            || cs.outbox.len() != 1
            || Some(cs.events[0].kind) != Self::command_event_kind(&req.command_scope)
            || Some(cs.outbox[0].catalog_type) != Self::command_outbox_catalog(&req.command_scope)
        {
            return Err(invalid("COMMAND_SCOPE_EVIDENCE_MISMATCH"));
        }
        let active =
            req.lease_credential.valid() && req.lease_generation > 0 && !req.assert_no_active_lease;
        let no_active = req.assert_no_active_lease
            && !req.lease_credential.valid()
            && req.lease_generation == 0;
        let mut change_asserts_no_active = false;
        for assertion in &cs.lease_assertions {
            if assertion.workspace_id == req.scope.workspace_id
                && assertion.run_id == req.result.run_id
                && assertion.no_active
            {
                change_asserts_no_active = true;
            }
        }
        let change_releases_lease = !cs.lease_releases.is_empty();
        match req.command_scope.as_str() {
            "execution.heartbeat"
            | "execution.mark_invoked"
            | "execution.prepare_tool_call"
            | "execution.mark_tool_call_invoked"
            | "execution.settle_tool_call"
            | "execution.record_checkpoint" => {
                if !active || change_releases_lease || change_asserts_no_active {
                    return Err(invalid("LEASE_FENCE_REQUIRED"));
                }
            }
            "execution.settle"
            | "execution.enter_reconciliation"
            | "execution.schedule_retry"
            | "execution.abandon_prepared" => {
                if !active || !change_releases_lease || change_asserts_no_active {
                    return Err(invalid("LEASE_FENCE_REQUIRED"));
                }
            }
            "execution.cancel"
            | "execution.settle_cancellation"
            | "execution.resolve_reconciliation"
            | "execution.resolve_approval"
            | "execution.expire_approval" => {
                if !(active != no_active)
                    || no_active != change_asserts_no_active
                    || active != change_releases_lease
                {
                    return Err(invalid("LEASE_FENCE_REQUIRED"));
                }
            }
            "execution.claim" | "execution.start_harness_run" => {
                if active
                    || no_active
                    || cs.leases.len() != 1
                    || !cs.leases[0].credential.valid()
                    || change_releases_lease
                    || change_asserts_no_active
                {
                    return Err(invalid("LEASE_GRANT_REQUIRED"));
                }
            }
            "execution.prepare"
            | "execution.record_approval"
            | "execution.create_approval_successor"
            | "execution.resume_reconciled_attempt" => {
                if !no_active
                    || !change_asserts_no_active
                    || active
                    || !cs.leases.is_empty()
                    || change_releases_lease
                {
                    return Err(invalid("LEASE_FENCE_REQUIRED"));
                }
            }
            _ => return Err(invalid("UNSUPPORTED_COMMAND_SCOPE")),
        }
        Ok(())
    }

    /// `validateRequest` — the full pre-transaction request gate
    /// upstream runs before the advisory lock: metadata, fence
    /// pairing, durable result, change-set ownership, the domain's
    /// change-set revalidation, approval action, command fence policy,
    /// claim-admission pairing, and the receipt binding.
    fn validate_request(req: &CommitRequest) -> Result<(), Failure> {
        if req.scope.workspace_id.is_nil()
            || req.scope.principal_id != req.principal_id
            || !req.scope.allows(req.capability)
            || req.command_scope.trim().is_empty()
            || req.idempotency_key.trim().is_empty()
            || !central_execution::domain::fingerprint_valid(&req.fingerprint)
        {
            return Err(invalid("INVALID_COMMAND_METADATA"));
        }
        if req.lease_credential.valid() != (req.lease_generation != 0)
            || (req.assert_no_active_lease && req.lease_generation != 0)
        {
            return Err(invalid("INVALID_LEASE_FENCE"));
        }
        if req.result.workspace_id != req.scope.workspace_id || req.result.event_id.is_nil() {
            return Err(invalid("INVALID_DURABLE_RESULT"));
        }
        Self::validate_change_set_ownership(req)?;
        // The persistence boundary revalidates the evaluator-approved
        // change set — a direct adapter caller cannot smuggle oversized
        // or unknown nested payloads through.
        central_execution::domain::build_execution_change_set(req.change_set.clone())?;
        Self::validate_approval_action_binding(req)?;
        Self::validate_command_fence_policy(req)?;
        let grants_lease = req.command_scope == "execution.claim"
            || req.command_scope == "execution.start_harness_run";
        if grants_lease != req.require_recovery_claimable {
            return Err(invalid("INVALID_RECOVERY_CLAIM_ADMISSION"));
        }
        Self::validate_receipt_binding(&req.receipt_binding, &req.result)
    }
}

/// RFC3339Nano for persisted event payloads (Go `time.Time` JSON form):
/// seconds always, fractional digits only when nonzero with trailing
/// zeros stripped — `time`'s Rfc3339 already emits a fractional part,
/// so the base is built seconds-only to avoid a doubled fraction.
fn go_rfc3339_local(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    let base = t
        .format(&time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]"
        ))
        .unwrap_or_default();
    let nanos = t.nanosecond();
    if nanos == 0 {
        return format!("{base}Z");
    }
    let mut frac = format!("{nanos:09}");
    while frac.ends_with('0') {
        frac.pop();
    }
    format!("{base}.{frac}Z")
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
        // `validateRequest` — the full pre-transaction gate (upstream
        // runs it before the advisory lock so a malformed request
        // never opens a write transaction).
        Self::validate_request(&request)?;
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
            // Upstream `replayReceipt` reads the referenced event and
            // re-binds its legs against the receipt's stored binding —
            // a missing event is corruption, never a silent "" kind.
            let event = sqlx::query!(
                "SELECT kind, task_id, run_id, step_id, attempt_id \
                 FROM central.events WHERE workspace_id = $1 AND id = $2",
                uuid_of(ws.as_bytes()),
                row.result_reference,
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("execution: read receipt event")?
            .ok_or_else(|| corrupt("a stored receipt references a missing event"))?;
            if event.task_id != Some(uuid_of(binding.task_id.as_bytes()))
                || event.run_id != Some(uuid_of(binding.run_id.as_bytes()))
                || event.step_id != opt_step_uuid(binding.step_id)
                || event.attempt_id != opt_attempt_uuid(binding.attempt_id)
            {
                return Err(conflict("REASON_REQUEST_CONFLICT"));
            }
            let payload = row.result_payload.clone();
            let result = Self::decode_result_payload(
                &payload,
                ws,
                binding,
                row.result_reference,
                &event.kind,
            )?;
            tx.commit().await.ctx("execution: commit replay")?;
            return Ok(CommitResult {
                result,
                replayed: true,
            });
        }
        // `enforceRecoveryClaimAdmission` — a claim-scoped commit is
        // only admissible while the run stays claimable in the open
        // epoch's view.
        if request.require_recovery_claimable {
            Self::enforce_recovery_claim_admission(&mut tx, ws, binding.task_id, binding.run_id)
                .await?;
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
        // `lockAndCheckTaskRun` — the task transition may rebind the
        // aggregate ids; both rows are locked and version-checked.
        let transition = request
            .change_set
            .task_transition
            .as_ref()
            .map(|t| &t.change_set);
        let task_id = transition
            .map(|c| c.task.id)
            .filter(|id| !id.is_nil())
            .unwrap_or(binding.task_id);
        let run_id = transition
            .and_then(|c| c.runs.first())
            .map_or(binding.run_id, |r| r.id);
        if task_id.is_nil() || run_id.is_nil() {
            return Err(invalid("STATE_SCOPE_MISMATCH"));
        }
        let task = read_task(&mut tx, ws, task_id, true).await?;
        if task.version != expected.task {
            return Err(conflict("EXPECTED_VERSION_CONFLICT"));
        }
        let _run = read_run(&mut tx, ws, task_id, run_id, true).await?;
        if _run.version != expected.run {
            return Err(conflict("EXPECTED_VERSION_CONFLICT"));
        }
        // `enforceFence` — an active lease must present its proven
        // bearer; an asserted-absent lease must stay absent.
        if request.lease_generation != 0 {
            let persisted = read_persisted_lease_for_update(&mut tx, ws, binding.run_id).await?;
            let Some(lease) = persisted else {
                return Err(conflict("STALE_LEASE_FENCE"));
            };
            let now = db_now(&mut tx).await?;
            let presented = sha256(&request.lease_credential.0);
            if lease.generation != request.lease_generation
                || !ct_eq(&lease.verifier, &presented)
                || lease.expires_at <= now
                || lease.step_id != binding.step_id
                || lease.attempt_id != binding.attempt_id
            {
                return Err(conflict("STALE_LEASE_FENCE"));
            }
        }
        if request.assert_no_active_lease {
            Self::assert_no_active_lease(&mut tx, ws, binding.run_id).await?;
        }
        // `lockAndValidateReceiptTarget` — locks step + attempt and
        // proves the binding's identities against the durable rows
        // (logical operation, exact expected versions, the
        // prepared/start-harness insertion shape).
        Self::lock_and_validate_receipt_target(&mut tx, &request).await?;
        // Change set — the upstream `commitNew` order.
        if let Some(transition) = &request.change_set.task_transition {
            Self::apply_task_transition(&mut tx, ws, &transition.change_set).await?;
        }
        Self::persist_steps(&mut tx, &request).await?;
        Self::persist_settlements(&mut tx, &request).await?;
        Self::persist_attempts(&mut tx, &request).await?;
        Self::persist_tool_calls(&mut tx, &request).await?;
        Self::persist_tool_attempts(&mut tx, &request).await?;
        Self::persist_attempt_assertions(&mut tx, &request.change_set.attempt_assertions).await?;
        Self::persist_approvals(&mut tx, &request).await?;
        Self::persist_checkpoints(&mut tx, &request).await?;
        Self::persist_leases(&mut tx, &request).await?;
        Self::persist_evidence(&mut tx, &request).await?;
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
            "SELECT kind, task_id, run_id, step_id, attempt_id \
             FROM central.events WHERE workspace_id = $1 AND id = $2",
            uuid_of(ws.as_bytes()),
            row.result_reference,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: read receipt event")?
        .ok_or_else(|| corrupt("a stored receipt references a missing event"))?;
        if event.task_id != Some(uuid_of(request.binding.task_id.as_bytes()))
            || event.run_id != Some(uuid_of(request.binding.run_id.as_bytes()))
            || event.step_id != opt_step_uuid(request.binding.step_id)
            || event.attempt_id != opt_attempt_uuid(request.binding.attempt_id)
        {
            return Err(conflict("REASON_REQUEST_CONFLICT"));
        }
        let payload = row.result_payload.clone();
        let result = Self::decode_result_payload(
            &payload,
            ws,
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

    /// `CompleteRecoveryWorkspace` — the batch loop upstream drives:
    /// each bounded keyset batch commits in its own fenced
    /// transaction. A live lease grace is scheduled and waited without
    /// spending the retry budget; a retryable scan failure takes the
    /// bounded backoff lane; anything else quarantines the workspace
    /// (and degrades the epoch) unless it is a pure fence/claim loss.
    async fn complete_recovery_workspace(
        &self,
        request: CompleteRecoveryWorkspaceRequest,
    ) -> Result<(), Failure> {
        // `validateRecoveryLease` + the request envelope checks.
        if request.lease.recovery_domain.trim().is_empty()
            || request.lease.instance_id.is_nil()
            || request.lease.fence.generation <= 0
            || request.lease.claim_token.len() != 32
        {
            return Err(invalid("INVALID_RECOVERY_COORDINATOR"));
        }
        if request.epoch_generation <= 0
            || request.workspace_id.is_nil()
            || request.claim_token.len() != 32
        {
            return Err(invalid("INVALID_RECOVERY_WORKSPACE"));
        }
        if request.degraded {
            if request.failure_class.trim().is_empty() || request.failure_reason.trim().is_empty() {
                return Err(invalid("INVALID_RECOVERY_FAILURE"));
            }
            return self.fail_recovery_workspace(&request).await;
        }
        loop {
            match self.scan_recovery_workspace_batch(&request).await {
                Ok(RecoveryBatchOutcome::Progress { completed: true }) => return Ok(()),
                Ok(RecoveryBatchOutcome::Progress { completed: false }) => {}
                Ok(RecoveryBatchOutcome::LeaseWait(retry_at)) => {
                    let delay = self
                        .schedule_recovery_workspace_lease_wait(&request, retry_at)
                        .await?;
                    self.wait_for_recovery_retry(&request, delay).await?;
                }
                Err(err) => {
                    // Retryable database failure → the bounded backoff
                    // lane; an exhausted budget quarantines.
                    if is_retryable_recovery_scan(&err) {
                        let scheduled = self.schedule_recovery_workspace_retry(&request).await?;
                        if let Some(delay) = scheduled {
                            self.wait_for_recovery_retry(&request, delay).await?;
                            continue;
                        }
                        let mut failed = request.clone();
                        failed.degraded = true;
                        failed.failure_class = "retry_exhausted".to_owned();
                        failed.failure_reason = "recovery retry budget exhausted".to_owned();
                        self.fail_recovery_workspace(&failed).await?;
                        return Err(conflict("RECOVERY_WORKSPACE_QUARANTINED"));
                    }
                    // Fence/claim losses surface as-is; every other
                    // failure quarantines the workspace + epoch.
                    if err.code() != "STALE_RECOVERY_FENCE"
                        && err.code() != "RECOVERY_WORKSPACE_NOT_CLAIMED"
                    {
                        let mut failed = request.clone();
                        failed.degraded = true;
                        failed.failure_class = "scan_error".to_owned();
                        failed.failure_reason = "recovery workspace scan failed".to_owned();
                        self.fail_recovery_workspace(&failed).await?;
                        return Err(conflict("RECOVERY_WORKSPACE_QUARANTINED"));
                    }
                    return Err(err);
                }
            }
        }
    }

    /// `ResumeRecoveryEpoch` — operator resume of a degraded epoch:
    /// fenced CAS on the durable row, requeue failed workspaces,
    /// durable `execution.recovery.resumed` event + outbox + receipt.
    /// A stored receipt replays its persisted event verbatim — the
    /// live epoch row is never re-read as the replayed answer.
    async fn resume_recovery_epoch(
        &self,
        request: ResumeRecoveryEpochRequest,
    ) -> Result<RecoveryEpoch, Failure> {
        let command = &request.command;
        command.validate()?;
        // `validateRecoveryLease` — the lease shape check before any
        // store mutation.
        if request.lease.recovery_domain.trim().is_empty()
            || request.lease.instance_id.is_nil()
            || !request.lease.fence.valid()
            || request.lease.claim_token.len() != 32
        {
            return Err(invalid("INVALID_RECOVERY_COORDINATOR"));
        }
        if command.coordinator_fence.generation != request.lease.fence.generation {
            return Err(conflict("STALE_RECOVERY_FENCE"));
        }
        let ws = command.scope.workspace_id;
        let mut tx = begin(&self.pool).await?;
        Self::lock_recovery_coordinator(&mut tx, &request.lease).await?;
        // `assertRecoveryEpochDomain` — the fenced epoch must exist.
        let epoch_exists = sqlx::query!(
            "SELECT 1 AS \"one!\" FROM central.recovery_epochs \
             WHERE epoch_generation = $1 AND coordinator_fence = $2 \
             AND coordinator_domain = $3",
            command.epoch_generation,
            request.lease.fence.generation,
            request.lease.recovery_domain,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: assert recovery epoch domain")?;
        if epoch_exists.is_none() {
            return Err(conflict("STALE_RECOVERY_FENCE"));
        }
        Self::lock_receipt_identity(&mut tx, ws, RESUME_SCOPE, &command.idempotency_key).await?;
        let expected = recovery_resume_expected_digest(command);
        // `queryReadRecoveryResumeReceipt` — a stored receipt is the
        // durable result; replay it only when every receipt leg
        // matches (fingerprint, expected digest, principal, capability).
        let existing = sqlx::query!(
            "SELECT request_fingerprint, principal_id, capability, \
             expected_version_digest, result_reference, result_payload \
             FROM central.execution_command_receipts \
             WHERE workspace_id = $1 AND command_scope = $2 AND idempotency_key = $3",
            uuid_of(ws.as_bytes()),
            RESUME_SCOPE,
            command.idempotency_key,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("execution: read recovery resume receipt")?;
        if let Some(receipt) = existing {
            if !ct_eq(&receipt.request_fingerprint, &command.fingerprint)
                || !ct_eq(&receipt.expected_version_digest, &expected)
                || receipt.principal_id != command.scope.principal_id
                || receipt.capability != command.capability.as_str()
            {
                return Err(conflict("IDEMPOTENCY_CONFLICT"));
            }
            let persisted = decode_recovery_resume_receipt(&receipt.result_payload)
                .map_err(|_| conflict("IDEMPOTENCY_CONFLICT"))?;
            if persisted.recovery_epoch_generation != command.epoch_generation
                || persisted.recovery_event_id != receipt.result_reference.to_string()
            {
                return Err(conflict("IDEMPOTENCY_CONFLICT"));
            }
            let payload = sqlx::query!(
                "SELECT payload::text AS \"payload!\" FROM central.events \
                 WHERE workspace_id = $1 AND id = $2 \
                 AND kind = 'execution.recovery.resumed'",
                uuid_of(ws.as_bytes()),
                receipt.result_reference,
            )
            .fetch_one(&mut *tx)
            .await
            .ctx("execution: read recovery resume result")?
            .payload;
            let epoch = decode_recovery_resume_result(&payload, command)?;
            tx.commit()
                .await
                .ctx("execution: commit recovery resume replay")?;
            return Ok(epoch);
        }
        // No receipt — guard the durable epoch against the command's
        // optimistic expectations before mutating anything.
        let current = read_locked_recovery_epoch(
            &mut tx,
            command.epoch_generation,
            request.lease.fence.generation,
            &request.lease.recovery_domain,
        )
        .await?;
        if current.state != command.expected_state
            || current.scheduler_cursor != command.expected_cursor
            || current.retry_attempt != command.expected_retry_attempt
        {
            return Err(conflict("RECOVERY_RESUME_EXPECTATION_CONFLICT"));
        }
        // `queryRequeueFailedRecoveryWorkspaces` — a resumable epoch
        // must actually requeue at least one failed row.
        let requeued = sqlx::query!(
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
        .ctx("execution: requeue failed recovery workspaces")?
        .rows_affected();
        if requeued == 0 {
            return Err(conflict("RECOVERY_EPOCH_NOT_RESUMABLE"));
        }
        // `queryResumeRecoveryEpoch` — the fenced CAS. The cursor binds
        // as text exactly like upstream (`ExpectedCursor.String()` →
        // `NULLIF($5,'')::uuid`), so a nil cursor compares to the nil
        // uuid, never to NULL.
        let cursor = command.expected_cursor.to_string();
        let tag = sqlx::query!(
            "UPDATE central.recovery_epochs \
             SET state = 'running', retry_attempt = retry_attempt + 1, \
             failure_class = NULL, failure_reason = NULL, updated_at = clock_timestamp() \
             WHERE epoch_generation = $1 AND coordinator_fence = $2 \
             AND coordinator_domain = $6 AND state = $3 \
             AND retry_attempt = $4 \
             AND scheduler_cursor IS NOT DISTINCT FROM NULLIF($5, '')::uuid",
            command.epoch_generation,
            request.lease.fence.generation,
            resume_epoch_state_value(command.expected_state),
            command.expected_retry_attempt,
            cursor,
            request.lease.recovery_domain,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: resume recovery epoch")?
        .rows_affected();
        if tag != 1 {
            return Err(conflict("RECOVERY_EPOCH_NOT_RESUMABLE"));
        }
        let epoch = read_locked_recovery_epoch(
            &mut tx,
            command.epoch_generation,
            request.lease.fence.generation,
            &request.lease.recovery_domain,
        )
        .await?;
        let deduplication_key = format!(
            "recovery-resume:{}:{}",
            command.epoch_generation, command.idempotency_key
        );
        let sequence = reserve_event_sequence(&mut tx, ws).await?;
        let event_id = uuid::Uuid::now_v7();
        let payload = encode_recovery_resume_result(command, &epoch)?;
        sqlx::query!(
            "INSERT INTO central.events (\
             id, workspace_id, event_sequence, event_type, aggregate_id, \
             aggregate_version, command_id, run_id, payload, occurred_at, \
             task_id, step_id, attempt_id, kind, state, producer_id, \
             policy_version, eligible_after, legal_hold) \
             VALUES ($1, $2, $3, 'execution.recovery.resumed', $2, $4, \
             $1, NULL, $5::jsonb, clock_timestamp(), NULL, NULL, NULL, \
             'execution.recovery.resumed', 'recorded', $6, 1, \
             clock_timestamp() + interval '90 days', false)",
            event_id,
            uuid_of(ws.as_bytes()),
            sequence,
            command.epoch_generation,
            serde_json::from_slice::<serde_json::Value>(&payload).unwrap_or_default(),
            command.scope.principal_id,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: insert recovery resume event")?;
        sqlx::query!(
            "INSERT INTO central.outbox (\
             id, workspace_id, event_id, delivery_state, due_at, attempt_count, \
             created_at, updated_at, catalog_type, deduplication_key, \
             producer_id, payload, visible_at, policy_version, \
             eligible_after, legal_hold) \
             VALUES ($1, $2, $3, 'pending', clock_timestamp(), 0, \
             clock_timestamp(), clock_timestamp(), 'execution.recovery.resumed', \
             $4, $5, $6::jsonb, clock_timestamp(), 1, \
             clock_timestamp() + interval '7 days', false)",
            uuid::Uuid::now_v7(),
            uuid_of(ws.as_bytes()),
            event_id,
            deduplication_key,
            command.scope.principal_id,
            serde_json::from_slice::<serde_json::Value>(&payload).unwrap_or_default(),
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: insert recovery resume outbox")?;
        Self::upsert_outbox_workspace_work(&mut tx, ws).await?;
        let receipt_payload = serde_json::json!({
            "schema_version": 1,
            "recovery_epoch_generation": epoch.generation,
            "recovery_event_id": event_id.to_string(),
        });
        sqlx::query!(
            "INSERT INTO central.execution_command_receipts (\
             id, workspace_id, command_scope, idempotency_key, request_fingerprint, \
             principal_id, capability, expected_version_digest, result_reference, \
             result_payload, created_at, expires_at, eligible_after) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, \
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
            &expected[..],
            event_id,
            receipt_payload,
        )
        .execute(&mut *tx)
        .await
        .ctx("execution: insert recovery resume receipt")?;
        tx.commit().await.ctx("execution: commit recovery resume")?;
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

/// `recoveryResumeExpectedDigest` — sha256 over the exact
/// `gen:fence:state:cursor:retry` tuple the command binds; a receipt
/// replay only answers a command whose expectations hash identically.
fn recovery_resume_expected_digest(
    command: &central_execution::resume::ResumeRecoveryEpochCommand,
) -> [u8; 32] {
    sha256(
        format!(
            "{}:{}:{}:{}:{}",
            command.epoch_generation,
            command.coordinator_fence.generation,
            command.expected_state.as_str(),
            command.expected_cursor,
            command.expected_retry_attempt,
        )
        .as_bytes(),
    )
}

/// Upstream `recoveryResumeResultPayload` — the durable
/// `execution.recovery.resumed` event/outbox body.
#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryResumeResultPayload {
    schema_version: i64,
    epoch_generation: i64,
    coordinator_fence: i64,
    state: String,
    scheduler_cursor: String,
    workspace_count: i64,
    processed_count: i64,
    retry_attempt: i64,
    snapshot_at: String,
    acknowledgement_reason: String,
    request_fingerprint: String,
}

/// Upstream `recoveryResumeReceiptPayload` — the receipt's stored
/// `result_payload`; the event reference is what replays.
#[derive(serde::Deserialize)]
struct RecoveryResumeReceiptPayload {
    schema_version: i64,
    recovery_epoch_generation: i64,
    recovery_event_id: String,
}

/// `encodeRecoveryResumeResult` — the full epoch snapshot the
/// `execution.recovery.resumed` event/outbox rows carry verbatim.
fn encode_recovery_resume_result(
    command: &central_execution::resume::ResumeRecoveryEpochCommand,
    epoch: &RecoveryEpoch,
) -> Result<Vec<u8>, Failure> {
    serde_json::to_vec(&RecoveryResumeResultPayload {
        schema_version: 1,
        epoch_generation: epoch.generation,
        coordinator_fence: epoch.coordinator_fence.generation,
        state: epoch.state.as_str().to_owned(),
        scheduler_cursor: epoch.scheduler_cursor.to_string(),
        workspace_count: epoch.workspace_count,
        processed_count: epoch.processed_count,
        retry_attempt: epoch.retry_attempt,
        snapshot_at: go_rfc3339_local(epoch.snapshot_at),
        acknowledgement_reason: command.acknowledgement_reason.trim().to_owned(),
        request_fingerprint: command
            .fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    })
    .map_err(|_| corrupt("encode recovery resume evidence"))
}

/// `decodeRecoveryResumeReceipt` — structural validation only; the
/// caller compares generation and event reference against the receipt.
fn decode_recovery_resume_receipt(
    payload: &serde_json::Value,
) -> Result<RecoveryResumeReceiptPayload, Failure> {
    let parsed: RecoveryResumeReceiptPayload = serde_json::from_value(payload.clone())
        .map_err(|_| corrupt("decode recovery resume receipt"))?;
    if parsed.schema_version != 1
        || parsed.recovery_epoch_generation <= 0
        || parsed.recovery_event_id.is_empty()
    {
        return Err(corrupt("decode recovery resume receipt"));
    }
    ExecutionEventId::parse(&parsed.recovery_event_id)
        .map_err(|_| corrupt("parse recovery resume receipt event"))?;
    Ok(parsed)
}

/// `decodeRecoveryResumeResult` — rebuilds the epoch from the stored
/// event payload, cross-checked against the command; any drift is
/// upstream's `dbFailure` (internal), not a conflict.
fn decode_recovery_resume_result(
    raw: &str,
    command: &central_execution::resume::ResumeRecoveryEpochCommand,
) -> Result<RecoveryEpoch, Failure> {
    let payload: RecoveryResumeResultPayload =
        serde_json::from_str(raw).map_err(|_| corrupt("decode recovery resume result"))?;
    let fingerprint: String = command
        .fingerprint
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if payload.schema_version != 1
        || payload.epoch_generation != command.epoch_generation
        || payload.coordinator_fence != command.coordinator_fence.generation
        || payload.state != "running"
        || payload.retry_attempt != command.expected_retry_attempt + 1
        || payload.acknowledgement_reason != command.acknowledgement_reason.trim()
        || payload.request_fingerprint != fingerprint
        || payload.workspace_count < 0
        || payload.processed_count < 0
    {
        return Err(corrupt("decode recovery resume result"));
    }
    let snapshot_at = OffsetDateTime::parse(
        &payload.snapshot_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|_| corrupt("parse recovery resume snapshot"))?;
    let cursor = if payload.scheduler_cursor.is_empty() {
        WorkspaceId::from_trusted_db_bytes([0; 16])
    } else {
        WorkspaceId::parse(&payload.scheduler_cursor)
            .map_err(|_| corrupt("parse recovery resume cursor"))?
    };
    if cursor != command.expected_cursor {
        return Err(corrupt("decode recovery resume cursor"));
    }
    Ok(RecoveryEpoch {
        generation: payload.epoch_generation,
        coordinator_fence: RecoveryCoordinatorFence {
            generation: payload.coordinator_fence,
        },
        state: RecoveryEpochState::RecoveryEpochRunning,
        scheduler_cursor: cursor,
        workspace_count: payload.workspace_count,
        processed_count: payload.processed_count,
        claim_cycle: payload.processed_count,
        retry_attempt: payload.retry_attempt,
        snapshot_at,
    })
}
