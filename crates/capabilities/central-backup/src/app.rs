//! `internal/backup/app/migration_coordinator.go` — the migration
//! coordinator: provisions the version-zero baseline through the
//! protected provisioning-record journal, resumes in-flight
//! operations, reports status, and gates the version-zero-only reset
//! ceremony.
//!
//! The coordinator is deliberately conn-agnostic: upstream composes it
//! over `port.MigrationRunner`/`port.MigrationInspector`/
//! `port.ResetRunner`, so the Rust port is generic over one session
//! type `S` implementing all three erased traits — the kernel
//! production `MigrationSession` adapts the R1 postgres adapters, and
//! tests drive the same code over fakes exactly as upstream's
//! coordinator test file.
//!
//! Upstream `backup.Failure{Class, Reason, Remediation, SafeDetails}`
//! becomes `central_foundation::failure::Failure`: `Reason` is the
//! stable machine `code`, the remediation and the one safe `detail`
//! fold into `message`, and the class picks the kind by its upstream
//! exit-class semantics — `ClassAction`→`Denied` (7),
//! `ClassResumable`→`Internal` (6), `ClassUnsupported`→`Conflict` (5).
//! Plain `fmt.Errorf("…: %w")` wraps upstream become
//! [`Failure::internal`] — except that an underlying classified
//! failure keeps its kind and code (upstream `errors.As` survives
//! wrapping), so [`wrap`] prefixes the message while preserving them.

use central_foundation::failure::{Failure, FailureKind};

use crate::domain::{
    BaselineManifest, ExternalRecordState, Operation, ProvisioningPhase, ResetConfirmation,
    SessionBinding, TargetIdentity, VerifiedEmptyTarget,
};
use crate::port::{
    BoxFuture, CommitUpRequest, DynBrokerProofService, IssueEmptyTargetProofRequest,
    MigrationInspector, MigrationRunner, PostgresMigrationFacts, PrepareUpRequest,
    ProtectedOperatorState, ProtectedOperatorStateInspector, ResetRequest, ResetRunner,
    ResumeRequest,
};

/// Result alias for the app layer.
pub type Result<T> = core::result::Result<T, Failure>;

/// The `backup.ErrRecordAbsent` sentinel's machine code — a missing
/// provisioning record is a `not_found` failure carrying it.
pub const RECORD_ABSENT_CODE: &str = "record_absent";

/// `backup.Failure{Class: ClassAction}` — an operator action is
/// required before the verb can run (exit 7 upstream).
fn action_failure(reason: &'static str, message: impl Into<String>) -> Failure {
    Failure::new(FailureKind::Denied, reason, message.into())
}

/// `backup.Failure{Class: ClassResumable}` — a resumable in-flight
/// operation blocks the verb (exit 6 upstream).
fn resumable_failure(reason: &'static str, message: impl Into<String>) -> Failure {
    Failure::new(FailureKind::Internal, reason, message.into())
}

/// `backup.Failure{Class: ClassUnsupported}` — the requested transition
/// is unsupported for this target state (exit 5 upstream).
fn unsupported_failure(reason: &'static str, message: impl Into<String>) -> Failure {
    Failure::new(FailureKind::Conflict, reason, message.into())
}

/// Upstream's `fmt.Errorf("<ctx>: %w", err)` — the failure stays
/// classified (`errors.As` sees through the wrap), so the Rust port
/// keeps kind+code and only prefixes the message. Unclassified store
/// errors keep whatever kind the port returned; upstream's plain
/// `error` maps to the terminal class (6) — `Internal` — and ports
/// already answer `Failure`s in that vocabulary.
fn wrap(context: &str, err: Failure) -> Failure {
    Failure::new(
        err.kind(),
        err.code(),
        format!("{context}: {}", err.message()),
    )
}

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

/// A zeroed proof for the repair leg of `resume` — upstream's Go zero
/// value; the runner only consults `proof`/`session_binding` on the
/// fresh-install leg, which always supplies a broker-issued proof.
fn empty_proof() -> VerifiedEmptyTarget {
    VerifiedEmptyTarget {
        operation_id: uuid::Uuid::nil(),
        session_binding: SessionBinding::default(),
        empty_fingerprint: String::new(),
        baseline_digest: String::new(),
        issued_at: time::OffsetDateTime::UNIX_EPOCH,
        expires_at: time::OffsetDateTime::UNIX_EPOCH,
        hmac: String::new(),
    }
}

// ---------------------------------------------------------------------------
// `app` types (upstream `ProvisioningRecord`, `MigrationStatus`,
// `VerifyResult` — migration_coordinator.go's file-level declarations)
// ---------------------------------------------------------------------------

/// `app.ProvisioningRecord` — the journal-backed provisioning record
/// the broker store owns.
#[derive(Debug, Clone, Default)]
pub struct ProvisioningRecord {
    /// Target the record binds.
    pub target: TargetIdentity,
    /// Operation the record tracks.
    pub operation_id: uuid::Uuid,
    /// External record state string (`"initializing"`, `"ready"`,
    /// `"absent"`… upstream keeps this free-form).
    pub state: String,
    /// Provisioning phase string (free-form — `reset_*` journal phases
    /// do not map to the closed enum).
    pub phase: String,
    /// Candidate identity.
    pub candidate_id: uuid::Uuid,
    /// Candidate manifest digest.
    pub candidate_digest: String,
    /// Baseline manifest digest.
    pub baseline_digest: String,
    /// Epoch-zero marker set.
    pub epoch_zero_markers: Vec<String>,
    /// Session binding persisted at prepare time.
    pub session_binding: SessionBinding,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Creation time.
    pub created_at: Option<time::OffsetDateTime>,
    /// Last update time.
    pub updated_at: Option<time::OffsetDateTime>,
}

/// `app.ReplaceProvisioningRecordRequest` — the CAS write.
#[derive(Debug, Clone)]
pub struct ReplaceProvisioningRecordRequest {
    /// Target the record binds.
    pub target: TargetIdentity,
    /// Revision the caller read.
    pub expected_revision: u64,
    /// The record to persist.
    pub next: ProvisioningRecord,
    /// Journal intent label (`"reset_started"`, `"database_removed"`,
    /// `"reset_complete"`, empty otherwise).
    pub journal_intent: String,
}

/// `app.ProvisioningRecordStore` — the broker-backed journal seam.
/// Upstream declares it in the app file; the broker migration-authority
/// client (R6 task 2) is the production implementation.
pub trait ProvisioningRecordStore: Send + Sync {
    /// `ReadProvisioningRecord`.
    fn read_provisioning_record<'a>(
        &'a self,
        target: &'a TargetIdentity,
    ) -> BoxFuture<'a, Result<ProvisioningRecord>>;
    /// `ReplaceProvisioningRecord` — CAS on `expected_revision`.
    fn replace_provisioning_record<'a>(
        &'a self,
        req: ReplaceProvisioningRecordRequest,
    ) -> BoxFuture<'a, Result<ProvisioningRecord>>;
    /// `CreateProvisioningRecord`.
    fn create_provisioning_record<'a>(
        &'a self,
        target: &'a TargetIdentity,
        record: ProvisioningRecord,
    ) -> BoxFuture<'a, Result<ProvisioningRecord>>;
}

/// The migration-authority seam the dedicated operator is composed
/// over — upstream's broker migration-authority client implements
/// proofs, the protected-state inspector, and the provisioning journal
/// store on one helper/broker connection. `central-migrate` takes it
/// from `central-kernel::migrate_compose`; until the R6 task-2 daemon
/// exists, production answers [`crate::app::NullMigrationAuthority`]
/// semantics (fail closed, never a local fallback).
pub trait MigrationAuthority:
    DynBrokerProofService + ProtectedOperatorStateInspector + ProvisioningRecordStore
{
}

impl<T> MigrationAuthority for T where
    T: DynBrokerProofService + ProtectedOperatorStateInspector + ProvisioningRecordStore
{
}

/// The Task-1 fail-closed authority. Production `central-migrate` is
/// composed over the broker migration-authority client (R6 task 2);
/// until then the operator's read-only surface answers the honest
/// "no protected record" projection — upstream's
/// `MigrationOperatorInspector` answers `ExternalRecordAbsent` for an
/// absent record, and the store's read answers `record_absent` — while
/// every mutating leg (`create`/`replace`/proofs) is `unavailable`.
/// A missing socket is never turned into a local fallback.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullMigrationAuthority;

fn authority_unavailable() -> Failure {
    Failure::unavailable(
        "migration_authority_unavailable",
        "broker migration authority is unavailable",
    )
}

impl ProtectedOperatorStateInspector for NullMigrationAuthority {
    fn inspect_operator_state<'a>(&'a self) -> BoxFuture<'a, Result<ProtectedOperatorState>> {
        Box::pin(async move {
            Ok(ProtectedOperatorState {
                record_state: ExternalRecordState::Absent,
                ..ProtectedOperatorState::default()
            })
        })
    }
}

impl ProvisioningRecordStore for NullMigrationAuthority {
    fn read_provisioning_record<'a>(
        &'a self,
        _target: &'a TargetIdentity,
    ) -> BoxFuture<'a, Result<ProvisioningRecord>> {
        Box::pin(async move {
            Err(Failure::not_found(
                RECORD_ABSENT_CODE,
                "provisioning record is absent",
            ))
        })
    }
    fn replace_provisioning_record<'a>(
        &'a self,
        _req: ReplaceProvisioningRecordRequest,
    ) -> BoxFuture<'a, Result<ProvisioningRecord>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
    fn create_provisioning_record<'a>(
        &'a self,
        _target: &'a TargetIdentity,
        _record: ProvisioningRecord,
    ) -> BoxFuture<'a, Result<ProvisioningRecord>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
}

impl DynBrokerProofService for NullMigrationAuthority {
    fn issue_empty_target_proof<'a>(
        &'a self,
        _req: &'a IssueEmptyTargetProofRequest,
    ) -> BoxFuture<'a, Result<VerifiedEmptyTarget>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
    fn verify_empty_target<'a>(
        &'a self,
        _target: &'a TargetIdentity,
        _proof: &'a VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
    fn consume_empty_proof<'a>(&'a self, _proof: VerifiedEmptyTarget) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
    fn consume_verified_empty_target<'a>(
        &'a self,
        _target: &'a TargetIdentity,
        _proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
    fn issue_reset_confirmation<'a>(
        &'a self,
        _req: &'a crate::port::IssueResetConfirmationRequest,
    ) -> BoxFuture<'a, Result<ResetConfirmation>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
    fn verify_reset_confirmation<'a>(
        &'a self,
        _confirmation: &'a ResetConfirmation,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
    fn consume_reset_confirmation<'a>(
        &'a self,
        _confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        _target: &'a TargetIdentity,
        _confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Err(authority_unavailable()) })
    }
}

/// `app.MigrationStatus` — the status projection.
#[derive(Debug, Clone)]
pub struct MigrationStatus {
    /// `central` schema exists and carries applied versions.
    pub initialized: bool,
    /// Operator-ready: clean ledger, ready external record.
    pub ready: bool,
    /// `READY`/`PROVISION_REQUIRED`/`RESUME_REQUIRED`/`REPAIR_REQUIRED`.
    pub safe_next_action: String,
    /// Read-only PostgreSQL facts.
    pub details: PostgresMigrationFacts,
    /// Protected record projection.
    pub operator_state: ProtectedOperatorState,
}

/// `app.VerifyResult` — the checksum/shape audit result.
#[derive(Debug, Clone, Default)]
pub struct VerifyResult {
    /// Every applied checksum matches the expected manifest.
    pub matches: bool,
    /// Human-readable drift lines, upstream's formats.
    pub drifts: Vec<String>,
}

/// `broker.MigrationOperatorResult` — the typed, durable result the
/// dedicated operator produces. Status and verify consumers must use
/// this evidence rather than infer a successful result from a
/// completed launch; the field names and `omitempty` rules are the
/// upstream wire contract.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MigrationOperatorResult {
    /// The closed command (`up|resume|status|verify|reset`).
    pub command: String,
    /// External record state after the verb.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    /// Terminal provisioning phase.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub phase: String,
    /// Operator-safe next action.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub safe_next_action: String,
    /// `status` detail — schema initialized.
    #[serde(default, skip_serializing_if = "is_false")]
    pub initialized: bool,
    /// `status` detail — operator ready.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ready: bool,
    /// `verify` detail — no drift.
    #[serde(default, skip_serializing_if = "is_false")]
    pub matches: bool,
    /// `verify` detail — drift lines.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drifts: Vec<String>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

// ---------------------------------------------------------------------------
// MigrationCoordinator
// ---------------------------------------------------------------------------

/// `app.MigrationCoordinator` — generic over the one session `S`
/// upstream wires from a single non-rebinding PostgreSQL connection.
/// `S` is the session's erased triple (runner + inspector + reset
/// runner); upstream's `resetRunner` field is separate but composed
/// from the same adapters, and its `nil` guard cannot be nil in the
/// Rust port because the session trait always supplies it.
pub struct MigrationCoordinator<'a, S>
where
    S: MigrationRunner + MigrationInspector + ResetRunner,
{
    /// The session: runner, inspector, and reset runner over the one
    /// `central_migration` connection.
    pub session: &'a mut S,
    /// Protected-record read (upstream `operatorInspector`, bound to
    /// one target at composition).
    pub operator_inspector: &'a dyn ProtectedOperatorStateInspector,
    /// Journal store (upstream `recordStore`).
    pub record_store: &'a dyn ProvisioningRecordStore,
    /// Broker proof service; `None` is upstream's `proofService == nil`
    /// and every proof-bound leg fails closed — the Rust migration
    /// runner is strictly proof-bound, so upstream's proofless
    /// embedded `runner.Up` leg has no Rust equivalent.
    pub proof_service: Option<&'a dyn DynBrokerProofService>,
    /// SHA-256 of the checksum manifest.
    pub baseline_digest: String,
    /// Expected baseline manifest for the drift audit.
    pub expected_manifest: BaselineManifest,
    operation_id: Option<uuid::Uuid>,
}

impl<'a, S> MigrationCoordinator<'a, S>
where
    S: MigrationRunner + MigrationInspector + ResetRunner,
{
    /// `NewMigrationCoordinator`.
    pub fn new(
        session: &'a mut S,
        operator_inspector: &'a dyn ProtectedOperatorStateInspector,
        record_store: &'a dyn ProvisioningRecordStore,
        baseline_digest: impl Into<String>,
        proof_service: Option<&'a dyn DynBrokerProofService>,
        expected_manifest: BaselineManifest,
    ) -> Self {
        Self {
            session,
            operator_inspector,
            record_store,
            proof_service,
            baseline_digest: baseline_digest.into(),
            expected_manifest,
            operation_id: None,
        }
    }

    /// `BindOperationID` pins the coordinator to the helper-authorized
    /// migration operation: every protected broker RPC is tied to the
    /// launch operation, never a process-local replacement UUID.
    pub fn bind_operation_id(&mut self, operation_id: uuid::Uuid) {
        self.operation_id = Some(operation_id);
    }

    /// `readBoth` — pg facts first, then the bound operator's
    /// protected-state read (upstream ordering); both are read-only.
    async fn read_both(&mut self) -> Result<(PostgresMigrationFacts, ProtectedOperatorState)> {
        let facts = self
            .session
            .inspect()
            .await
            .map_err(|e| wrap("read inspectors: pg facts", e))?;
        let op_state = self
            .operator_inspector
            .inspect_operator_state()
            .await
            .map_err(|e| wrap("read inspectors: operator state", e))?;
        Ok((facts, op_state))
    }

    /// `isProvisioningRecordAbsent`.
    async fn is_provisioning_record_absent(&self, target: &TargetIdentity) -> Result<bool> {
        match self.record_store.read_provisioning_record(target).await {
            Ok(_) => Ok(false),
            Err(err) if err.code() == RECORD_ABSENT_CODE => Ok(true),
            Err(err) => Err(wrap("read provisioning record", err)),
        }
    }

    /// `Up` — provision the version-zero baseline: journal `recorded`
    /// → `candidate_staged`, prepare the locked session, persist its
    /// binding, take the one-use broker proof, commit, then journal
    /// `baseline_installed` → `candidate_active` → `ready`.
    pub async fn up(&mut self, target: &TargetIdentity) -> Result<Operation> {
        let (facts, op_state) = self.read_both().await?;

        if facts.initialized {
            if op_state.record_state == ExternalRecordState::Ready && facts.dirty.is_none() {
                return Ok(Operation {
                    operation_id: op_state.operation_id,
                    target: target.clone(),
                    record_state: ExternalRecordState::Ready,
                    started_at: Some(now()),
                    finalized_at: Some(now()),
                    ..Operation::default()
                });
            }
            return Err(resumable_failure(
                "REPAIR_REQUIRED",
                format!(
                    "migrate resume --operation={} (target initialized in non-ready state, operationID={})",
                    op_state.operation_id, op_state.operation_id
                ),
            ));
        }

        let op_id = self.operation_id.unwrap_or_else(uuid::Uuid::now_v7);

        if self
            .is_provisioning_record_absent(target)
            .await
            .map_err(|e| wrap("up: check provisioning record", e))?
        {
            let rec = ProvisioningRecord {
                target: target.clone(),
                operation_id: op_id,
                state: "initializing".into(),
                phase: ProvisioningPhase::Recorded.as_str().into(),
                baseline_digest: self.baseline_digest.clone(),
                created_at: Some(now()),
                updated_at: Some(now()),
                ..ProvisioningRecord::default()
            };
            self.record_store
                .create_provisioning_record(target, rec)
                .await
                .map_err(|e| wrap("up: create provisioning record", e))?;
        }

        let candidate_id = uuid::Uuid::now_v7();
        {
            let current = self
                .record_store
                .read_provisioning_record(target)
                .await
                .map_err(|e| wrap("up: read after create", e))?;
            if current.phase == ProvisioningPhase::Recorded.as_str() {
                let mut next = current.clone();
                next.phase = ProvisioningPhase::CandidateStaged.as_str().into();
                next.candidate_id = candidate_id;
                next.candidate_digest = self.baseline_digest.clone();
                next.updated_at = Some(now());
                self.record_store
                    .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                        target: target.clone(),
                        expected_revision: current.revision,
                        next,
                        journal_intent: String::new(),
                    })
                    .await
                    .map_err(|e| wrap("up: stage candidate", e))?;
            }
        }

        // Upstream's `proofService == nil` leg runs the embedded
        // proofless `runner.Up`; the Rust runner is strictly
        // proof-bound (there is no proofless `UpRequest`), so the
        // honest port of that branch is a fail-closed refusal.
        let Some(proofs) = self.proof_service else {
            return Err(Failure::unavailable(
                "proof_service_required",
                "up: broker proof service is required for baseline installation",
            ));
        };

        let prepare = self
            .session
            .prepare_up(&PrepareUpRequest {
                operation_id: op_id,
                target: target.clone(),
            })
            .await
            .map_err(|e| wrap("up: prepare (locks + stock check)", e))?;
        {
            let current = self
                .record_store
                .read_provisioning_record(target)
                .await
                .map_err(|e| wrap("up: read for session binding", e))?;
            let mut next = current.clone();
            next.session_binding = prepare.session_binding.clone();
            self.record_store
                .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                    target: target.clone(),
                    expected_revision: current.revision,
                    next,
                    journal_intent: String::new(),
                })
                .await
                .map_err(|e| wrap("up: persist session binding", e))?;
        }

        let proof = proofs
            .issue_empty_target_proof(&IssueEmptyTargetProofRequest {
                operation_id: op_id,
                target: target.clone(),
                session_binding: prepare.session_binding.clone(),
                baseline_digest: self.baseline_digest.clone(),
            })
            .await
            .map_err(|e| wrap("up: issue proof", e))?;

        self.session
            .commit_up(&CommitUpRequest {
                operation_id: op_id,
                target: target.clone(),
                session_binding: prepare.session_binding.clone(),
                proof,
            })
            .await
            .map_err(|e| wrap("up: commit baseline", e))?;

        for phase in [
            ProvisioningPhase::BaselineInstalled,
            ProvisioningPhase::CandidateActive,
        ] {
            let current = self
                .record_store
                .read_provisioning_record(target)
                .await
                .map_err(|e| wrap("up: read for phase advance", e))?;
            let mut next = current.clone();
            next.phase = phase.as_str().into();
            next.updated_at = Some(now());
            self.record_store
                .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                    target: target.clone(),
                    expected_revision: current.revision,
                    next,
                    journal_intent: String::new(),
                })
                .await
                .map_err(|e| wrap("up: cas phase advance", e))?;
        }

        {
            let current = self
                .record_store
                .read_provisioning_record(target)
                .await
                .map_err(|e| wrap("up: read for ready", e))?;
            let mut next = current.clone();
            next.state = "ready".into();
            next.phase = String::new();
            next.updated_at = Some(now());
            self.record_store
                .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                    target: target.clone(),
                    expected_revision: current.revision,
                    next,
                    journal_intent: String::new(),
                })
                .await
                .map_err(|e| wrap("up: cas ready", e))?;
        }

        Ok(Operation {
            operation_id: op_id,
            target: target.clone(),
            embedded_baseline_digest: self.baseline_digest.clone(),
            record_state: ExternalRecordState::Ready,
            provisioning_phase: ProvisioningPhase::CandidateActive,
            started_at: Some(now()),
            finalized_at: Some(now()),
        })
    }

    /// `Resume` — continue an in-flight operation. A pre-baseline
    /// record on an uninitialized target installs the baseline
    /// (`baseline_installed`); a repair leg requires the recorded
    /// target/session identity to still hold.
    pub async fn resume(&mut self, operation_id: uuid::Uuid) -> Result<Operation> {
        let (_facts0, op_state) = self.read_both().await?;
        let facts = _facts0;

        if op_state.operation_id != operation_id {
            return Err(unsupported_failure(
                "OPERATION_MISMATCH",
                format!(
                    "verify operation ID and retry (requested={}, recorded={})",
                    operation_id, op_state.operation_id
                ),
            ));
        }

        if !facts.initialized && op_state.provisioning_phase.is_pre_baseline() {
            self.resume_from_pre_baseline(&op_state).await?;
            return Ok(Operation {
                operation_id,
                target: op_state.target.clone(),
                record_state: op_state.record_state,
                provisioning_phase: ProvisioningPhase::BaselineInstalled,
                started_at: Some(now()),
                ..Operation::default()
            });
        }

        if !repair_still_valid(&facts, &op_state) {
            return Err(unsupported_failure(
                "REPAIR_LOST_CAUSE",
                "reset and re-provision (target or session identity changed since operation started)",
            ));
        }

        let current_phase = match op_state.provisioning_phase {
            ProvisioningPhase::Recorded => ProvisioningPhase::CandidateStaged,
            ProvisioningPhase::CandidateStaged => ProvisioningPhase::BaselineInstalled,
            ProvisioningPhase::BaselineInstalled => ProvisioningPhase::CandidateActive,
            ProvisioningPhase::CandidateActive => {
                if op_state.record_state != ExternalRecordState::Ready {
                    return self.advance_to_ready(&op_state).await;
                }
                return Ok(Operation {
                    operation_id,
                    target: op_state.target.clone(),
                    record_state: ExternalRecordState::Ready,
                    provisioning_phase: ProvisioningPhase::CandidateActive,
                    started_at: Some(now()),
                    finalized_at: Some(now()),
                    ..Operation::default()
                });
            }
            ProvisioningPhase::None => {
                return Err(unsupported_failure(
                    "UNKNOWN_PHASE",
                    format!(
                        "check status and retry (phase={})",
                        op_state.provisioning_phase.as_str()
                    ),
                ));
            }
        };

        let target = op_state.target.clone();
        let resume_req = if op_state.provisioning_phase.is_pre_baseline() {
            self.fresh_resume_request(operation_id, &target, &op_state.session_binding)
                .await?
        } else {
            ResumeRequest {
                operation_id,
                target: target.clone(),
                expected_session_binding: op_state.session_binding.clone(),
                session_binding: SessionBinding::default(),
                proof: empty_proof(),
            }
        };
        self.session
            .resume(&resume_req)
            .await
            .map_err(|e| wrap("resume: run baseline", e))?;

        let current = self
            .record_store
            .read_provisioning_record(&target)
            .await
            .map_err(|e| wrap("resume: read record", e))?;
        let mut next = current.clone();
        next.phase = current_phase.as_str().into();
        next.updated_at = Some(now());
        self.record_store
            .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                target: target.clone(),
                expected_revision: current.revision,
                next,
                journal_intent: String::new(),
            })
            .await
            .map_err(|e| wrap("resume: advance phase", e))?;

        Ok(Operation {
            operation_id,
            target,
            record_state: op_state.record_state,
            provisioning_phase: current_phase,
            started_at: Some(now()),
            ..Operation::default()
        })
    }

    /// `resumeFromPreBaseline` — install the baseline for a
    /// pre-baseline record on an uninitialized target, then journal
    /// `baseline_installed`.
    async fn resume_from_pre_baseline(&mut self, op_state: &ProtectedOperatorState) -> Result<()> {
        let target = op_state.target.clone();
        let resume_req = self
            .fresh_resume_request(op_state.operation_id, &target, &op_state.session_binding)
            .await
            .map_err(|e| wrap("resume from pre-baseline", e))?;
        self.session
            .resume(&resume_req)
            .await
            .map_err(|e| wrap("resume from pre-baseline: run baseline", e))?;

        let current = self
            .record_store
            .read_provisioning_record(&target)
            .await
            .map_err(|e| wrap("resume from pre-baseline: read record", e))?;
        let mut next = current.clone();
        next.phase = ProvisioningPhase::BaselineInstalled.as_str().into();
        next.updated_at = Some(now());
        self.record_store
            .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                target,
                expected_revision: current.revision,
                next,
                journal_intent: String::new(),
            })
            .await
            .map_err(|e| wrap("resume from pre-baseline: advance to baseline_installed", e))?;
        Ok(())
    }

    /// `freshResumeRequest` — a new same-session proof immediately
    /// before a resume path that may install the baseline. The
    /// persisted session identity only proves the instance; it is
    /// never reused as mutation authority.
    async fn fresh_resume_request(
        &mut self,
        operation_id: uuid::Uuid,
        target: &TargetIdentity,
        expected: &SessionBinding,
    ) -> Result<ResumeRequest> {
        let Some(proofs) = self.proof_service else {
            return Err(Failure::unavailable(
                "proof_service_required",
                "resume: broker proof service is required for baseline installation",
            ));
        };
        let prepared = self
            .session
            .prepare_up(&PrepareUpRequest {
                operation_id,
                target: target.clone(),
            })
            .await
            .map_err(|e| wrap("resume: prepare fresh mutation session", e))?;
        let proof = proofs
            .issue_empty_target_proof(&IssueEmptyTargetProofRequest {
                operation_id,
                target: target.clone(),
                session_binding: prepared.session_binding.clone(),
                baseline_digest: self.baseline_digest.clone(),
            })
            .await
            .map_err(|e| wrap("resume: issue fresh empty-target proof", e))?;
        Ok(ResumeRequest {
            operation_id,
            target: target.clone(),
            expected_session_binding: expected.clone(),
            session_binding: prepared.session_binding,
            proof,
        })
    }

    /// `advanceToReady` — the `candidate_active` + non-ready record
    /// leg: journal `ready` and finalize.
    async fn advance_to_ready(&mut self, op_state: &ProtectedOperatorState) -> Result<Operation> {
        let target = op_state.target.clone();
        let current = self
            .record_store
            .read_provisioning_record(&target)
            .await
            .map_err(|e| wrap("advance to ready: read", e))?;
        let mut next = current.clone();
        next.state = "ready".into();
        next.phase = String::new();
        next.updated_at = Some(now());
        self.record_store
            .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                target: target.clone(),
                expected_revision: current.revision,
                next,
                journal_intent: String::new(),
            })
            .await
            .map_err(|e| wrap("advance to ready: cas", e))?;
        Ok(Operation {
            operation_id: op_state.operation_id,
            target,
            record_state: ExternalRecordState::Ready,
            started_at: Some(now()),
            finalized_at: Some(now()),
            ..Operation::default()
        })
    }

    /// `Reset` — the version-zero-only destructive reset. Lock
    /// acquisition is delegated to the runner/session, which acquires
    /// the canonical locks internally before the delete leg.
    pub async fn reset(
        &mut self,
        operation_id: uuid::Uuid,
        confirmation: ResetConfirmation,
    ) -> Result<()> {
        if self.proof_service.is_none() {
            return Err(Failure::internal(
                "proof_service_not_configured",
                "reset: proof service not configured",
            ));
        }

        if confirmation.expires_at <= now() {
            return Err(unsupported_failure(
                "CONFIRMATION_EXPIRED",
                "request a new reset confirmation",
            ));
        }

        if confirmation.operation_id != operation_id {
            return Err(unsupported_failure(
                "CONFIRMATION_OPERATION_MISMATCH",
                format!(
                    "request a reset confirmation for the correct operation (requested={}, confirmation={})",
                    operation_id, confirmation.operation_id
                ),
            ));
        }

        let (facts, op_state) = self
            .read_both()
            .await
            .map_err(|e| wrap("reset: inspect state", e))?;

        for v in &facts.applied_versions {
            if v.version != 0 {
                return Err(unsupported_failure(
                    "RESET_NOT_ZERO_EPOCH",
                    format!(
                        "reset is only allowed for version-zero targets; use restore/rollback for later versions (version={})",
                        v.version
                    ),
                ));
            }
        }
        if op_state.operation_id != operation_id {
            return Err(unsupported_failure(
                "RESET_OPERATION_MISMATCH",
                "verify operation ID matches current protected-record state",
            ));
        }

        if confirmation.operation_id != op_state.operation_id {
            return Err(unsupported_failure(
                "CONFIRMATION_TARGET_MISMATCH",
                format!(
                    "confirmation must match the current operation ID on the target (confirmation={}, current={})",
                    confirmation.operation_id, op_state.operation_id
                ),
            ));
        }

        let target = op_state.target.clone();
        let rec = self
            .record_store
            .read_provisioning_record(&target)
            .await
            .map_err(|e| wrap("reset: read record", e))?;

        let mut r = rec.clone();
        r.phase = "reset_started".into();
        r.updated_at = Some(now());
        self.record_store
            .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                target: target.clone(),
                expected_revision: rec.revision,
                next: r,
                journal_intent: "reset_started".into(),
            })
            .await
            .map_err(|e| wrap("reset: journal reset_started", e))?;

        self.session
            .delete_schema(&ResetRequest {
                target: target.clone(),
                confirmation,
            })
            .await
            .map_err(|e| wrap("reset: delete schema", e))?;

        {
            let current = self
                .record_store
                .read_provisioning_record(&target)
                .await
                .map_err(|e| wrap("reset: read after delete", e))?;
            let mut next = current.clone();
            next.phase = "database_removed".into();
            next.updated_at = Some(now());
            self.record_store
                .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                    target: target.clone(),
                    expected_revision: current.revision,
                    next,
                    journal_intent: "database_removed".into(),
                })
                .await
                .map_err(|e| wrap("reset: journal database_removed", e))?;
        }

        {
            let current = self
                .record_store
                .read_provisioning_record(&target)
                .await
                .map_err(|e| wrap("reset: read for complete", e))?;
            let mut next = current.clone();
            next.phase = "reset_complete".into();
            next.state = "absent".into();
            next.operation_id = uuid::Uuid::nil();
            next.updated_at = Some(now());
            self.record_store
                .replace_provisioning_record(ReplaceProvisioningRecordRequest {
                    target,
                    expected_revision: current.revision,
                    next,
                    journal_intent: "reset_complete".into(),
                })
                .await
                .map_err(|e| wrap("reset: journal reset_complete", e))?;
        }

        Ok(())
    }

    /// `Status` — the operator-facing migration status.
    pub async fn status(&mut self) -> Result<MigrationStatus> {
        let (facts, op_state) = self.read_both().await?;
        Ok(self.compose_status(facts, op_state))
    }

    /// `Preflight` — the serving-time B05 status check: one status read
    /// over the dedicated read-only connection; never retries, never
    /// materializes the migration operator's mutation session.
    pub async fn preflight(&mut self) -> Result<()> {
        let status = self
            .status()
            .await
            .map_err(|e| wrap("preflight: status", e))?;
        if status.ready {
            return Ok(());
        }
        let reason: &'static str = match status.safe_next_action.as_str() {
            "RESUME_REQUIRED" => "RESUME_REQUIRED",
            "REPAIR_REQUIRED" => "REPAIR_REQUIRED",
            "PROVISION_REQUIRED" => "PROVISION_REQUIRED",
            _ => "MIGRATION_REQUIRED",
        };
        let failure = match reason {
            "RESUME_REQUIRED" => resumable_failure(
                reason,
                "repair the B05 migration state before starting central serve",
            ),
            "PROVISION_REQUIRED" | "MIGRATION_REQUIRED" => action_failure(
                reason,
                "repair the B05 migration state before starting central serve",
            ),
            // `REPAIR_REQUIRED` and unknown status actions are
            // incompatible until explicitly classified.
            _ => unsupported_failure(
                reason,
                "repair the B05 migration state before starting central serve",
            ),
        };
        Err(failure)
    }

    /// `composeStatus` — the pure status projection.
    fn compose_status(
        &self,
        facts: PostgresMigrationFacts,
        op_state: ProtectedOperatorState,
    ) -> MigrationStatus {
        let mut status = MigrationStatus {
            initialized: facts.initialized,
            ready: false,
            safe_next_action: String::new(),
            details: facts.clone(),
            operator_state: op_state,
        };

        if !facts.initialized {
            status.safe_next_action = "PROVISION_REQUIRED".into();
            return status;
        }

        if facts.dirty.is_some() {
            status.safe_next_action = "RESUME_REQUIRED".into();
            return status;
        }

        if status.operator_state.record_state != ExternalRecordState::Ready {
            status.safe_next_action = "REPAIR_REQUIRED".into();
            return status;
        }

        let drifts = self.manifest_drifts(&facts, true);
        if !drifts.is_empty() {
            status.safe_next_action = "REPAIR_REQUIRED".into();
            return status;
        }

        status.ready = true;
        status.safe_next_action = "READY".into();
        status
    }

    /// The checksum audit shared by `compose_status` and `verify`;
    /// `status_format` selects upstream's two drift-line formats
    /// (`"version %d has empty checksum"`/`"does not match manifest"`
    /// for status, `"version %d: empty checksum"`/`"checksum mismatch
    /// (got %s)"` for verify).
    fn manifest_drifts(&self, facts: &PostgresMigrationFacts, status_format: bool) -> Vec<String> {
        let expected = &self.expected_manifest.checksums;
        let digest = self.expected_manifest.digest();
        let mut drifts = Vec::new();
        for v in &facts.applied_versions {
            if v.checksum.is_empty() {
                drifts.push(if status_format {
                    format!("version {} has empty checksum", v.version)
                } else {
                    format!("version {}: empty checksum", v.version)
                });
                continue;
            }
            if !expected.is_empty() {
                let matched = expected.values().any(|cs| *cs == v.checksum) || v.checksum == digest;
                if !matched {
                    drifts.push(if status_format {
                        format!(
                            "version {} checksum {} does not match manifest",
                            v.version, v.checksum
                        )
                    } else {
                        format!(
                            "version {}: checksum mismatch (got {})",
                            v.version, v.checksum
                        )
                    });
                }
            }
        }
        drifts
    }

    /// `Verify` — the read-only checksum/shape audit. An uninitialized
    /// target is an action failure; drift is reported in the result,
    /// not as an error.
    pub async fn verify(&mut self) -> Result<VerifyResult> {
        let facts = self
            .session
            .inspect()
            .await
            .map_err(|e| wrap("verify: inspect", e))?;

        if !facts.initialized {
            return Err(action_failure(
                "PROVISION_REQUIRED",
                "run migrate up before verify (initialized=false)",
            ));
        }

        let drifts = self.manifest_drifts(&facts, false);
        Ok(VerifyResult {
            matches: drifts.is_empty(),
            drifts,
        })
    }
}

/// `repairStillValid` — the repair leg may run only while the recorded
/// target/session identity still describes the live target.
fn repair_still_valid(facts: &PostgresMigrationFacts, op_state: &ProtectedOperatorState) -> bool {
    if !facts.initialized {
        return false;
    }
    if op_state.operation_id.is_nil() {
        return false;
    }
    if op_state.target.database.is_empty() && op_state.target.system_id.is_empty() {
        return false;
    }
    if facts.epochs.migration.epoch != 0 || facts.epochs.security.epoch != 0 {
        return false;
    }
    if !facts.applied_versions.is_empty() {
        for v in &facts.applied_versions {
            if v.version != 0 {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Fake-session coordinator matrix — upstream `migration_coordinator_test.go`'s
// provisioning/resume/status/verify/reset rows over in-memory fakes.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::domain::CANONICAL_LOCK_ORDER;
    use crate::port::{
        DirtyEvidence, EpochMarkers, IssueResetConfirmationRequest, PrepareUpResult, ResumeResult,
        UpRequest, UpResult, VersionChecksum,
    };

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "local".into(),
            database_oid: "16400".into(),
            database: "central".into(),
            config_hash: "auto".into(),
            epoch: 0,
        }
    }

    fn binding() -> SessionBinding {
        SessionBinding {
            backend_pid: 42,
            backend_start: "2026-10-23 00:00:00 UTC".into(),
            boot_id: "boot".into(),
            lock_identities: CANONICAL_LOCK_ORDER
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    fn manifest() -> BaselineManifest {
        BaselineManifest {
            version: 0,
            checksums: [("sha:v0".to_owned(), "sha:v0".to_owned())]
                .into_iter()
                .collect(),
        }
    }

    fn clean_facts() -> PostgresMigrationFacts {
        PostgresMigrationFacts {
            initialized: true,
            applied_versions: vec![VersionChecksum {
                version: 0,
                checksum: "sha:v0".into(),
            }],
            dirty: None,
            epochs: EpochMarkers::default(),
        }
    }

    /// The session fake — `MigrationRunner + MigrationInspector +
    /// ResetRunner` on one object, like `MigrationSession` over one
    /// connection. `&mut self` is exclusive, so call capture needs no
    /// lock.
    struct FakeSession {
        facts: PostgresMigrationFacts,
        calls: Vec<String>,
        binding: SessionBinding,
    }

    impl FakeSession {
        fn new(facts: PostgresMigrationFacts) -> Self {
            Self {
                facts,
                calls: Vec::new(),
                binding: binding(),
            }
        }
    }

    impl MigrationRunner for FakeSession {
        fn prepare_up<'a>(
            &'a mut self,
            req: &'a PrepareUpRequest,
        ) -> BoxFuture<'a, Result<PrepareUpResult>> {
            Box::pin(async move {
                self.calls.push("prepare_up".to_owned());
                Ok(PrepareUpResult {
                    operation_id: req.operation_id,
                    session_binding: self.binding.clone(),
                })
            })
        }
        fn commit_up<'a>(
            &'a mut self,
            req: &'a CommitUpRequest,
        ) -> BoxFuture<'a, Result<UpResult>> {
            Box::pin(async move {
                self.calls.push("commit_up".to_owned());
                Ok(UpResult {
                    operation_id: req.operation_id,
                    record_state: ExternalRecordState::Ready,
                    session_binding: req.session_binding.clone(),
                })
            })
        }
        fn up<'a>(&'a mut self, _req: &'a UpRequest) -> BoxFuture<'a, Result<UpResult>> {
            Box::pin(async move {
                self.calls.push("up".to_owned());
                Err(Failure::internal(
                    "embedded_up_unreachable",
                    "the proofless embedded leg must not run when proofs exist",
                ))
            })
        }
        fn resume<'a>(&'a mut self, req: &'a ResumeRequest) -> BoxFuture<'a, Result<ResumeResult>> {
            Box::pin(async move {
                self.calls.push("resume".to_owned());
                Ok(ResumeResult {
                    operation_id: req.operation_id,
                    record_state: ExternalRecordState::Ready,
                    final_phase: ProvisioningPhase::CandidateActive,
                })
            })
        }
    }

    impl MigrationInspector for FakeSession {
        fn inspect<'a>(&'a mut self) -> BoxFuture<'a, Result<PostgresMigrationFacts>> {
            Box::pin(async move {
                self.calls.push("inspect".to_owned());
                Ok(self.facts.clone())
            })
        }
    }

    impl ResetRunner for FakeSession {
        fn delete_schema<'a>(&'a mut self, _req: &'a ResetRequest) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.calls.push("delete_schema".to_owned());
                Ok(())
            })
        }
    }

    /// The protected-state inspector — returns the configured
    /// projection verbatim.
    struct FakeOperatorState(ProtectedOperatorState);
    impl ProtectedOperatorStateInspector for FakeOperatorState {
        fn inspect_operator_state<'a>(&'a self) -> BoxFuture<'a, Result<ProtectedOperatorState>> {
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }

    /// The journal fake — an in-memory record plus a write journal of
    /// `"write:state:phase"` entries, mirroring the upstream fake the
    /// coordinator matrix asserts transitions on.
    #[derive(Default)]
    struct FakeStore {
        record: Mutex<Option<ProvisioningRecord>>,
        journal: Mutex<Vec<String>>,
        fail_writes: bool,
    }

    impl ProvisioningRecordStore for FakeStore {
        fn read_provisioning_record<'a>(
            &'a self,
            _target: &'a TargetIdentity,
        ) -> BoxFuture<'a, Result<ProvisioningRecord>> {
            Box::pin(async move {
                match &*self.record.lock().unwrap() {
                    Some(rec) => Ok(rec.clone()),
                    None => Err(Failure::not_found(
                        RECORD_ABSENT_CODE,
                        "provisioning record is absent",
                    )),
                }
            })
        }
        fn replace_provisioning_record<'a>(
            &'a self,
            req: ReplaceProvisioningRecordRequest,
        ) -> BoxFuture<'a, Result<ProvisioningRecord>> {
            Box::pin(async move {
                if self.fail_writes {
                    return Err(Failure::unavailable("store_down", "store unavailable"));
                }
                self.journal.lock().unwrap().push(format!(
                    "replace:{}:{}@{}",
                    req.next.state, req.next.phase, req.expected_revision
                ));
                let mut next = req.next;
                next.revision = req.expected_revision + 1;
                *self.record.lock().unwrap() = Some(next.clone());
                Ok(next)
            })
        }
        fn create_provisioning_record<'a>(
            &'a self,
            _target: &'a TargetIdentity,
            record: ProvisioningRecord,
        ) -> BoxFuture<'a, Result<ProvisioningRecord>> {
            Box::pin(async move {
                if self.fail_writes {
                    return Err(Failure::unavailable("store_down", "store unavailable"));
                }
                self.journal
                    .lock()
                    .unwrap()
                    .push(format!("create:{}:{}", record.state, record.phase));
                let mut rec = record;
                rec.revision = 1;
                *self.record.lock().unwrap() = Some(rec.clone());
                Ok(rec)
            })
        }
    }

    /// The proof seam — every issue/verify/consume succeeds and the
    /// issued artifacts carry the bound identities back.
    struct FakeProofs;
    impl DynBrokerProofService for FakeProofs {
        fn issue_empty_target_proof<'a>(
            &'a self,
            req: &'a IssueEmptyTargetProofRequest,
        ) -> BoxFuture<'a, Result<VerifiedEmptyTarget>> {
            Box::pin(async move {
                Ok(VerifiedEmptyTarget {
                    operation_id: req.operation_id,
                    session_binding: req.session_binding.clone(),
                    empty_fingerprint: "fp".into(),
                    baseline_digest: req.baseline_digest.clone(),
                    issued_at: now(),
                    expires_at: now(),
                    hmac: "h".into(),
                })
            })
        }
        fn verify_empty_target<'a>(
            &'a self,
            _target: &'a TargetIdentity,
            _proof: &'a VerifiedEmptyTarget,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn consume_empty_proof<'a>(
            &'a self,
            _proof: VerifiedEmptyTarget,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn consume_verified_empty_target<'a>(
            &'a self,
            _target: &'a TargetIdentity,
            _proof: VerifiedEmptyTarget,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn issue_reset_confirmation<'a>(
            &'a self,
            req: &'a IssueResetConfirmationRequest,
        ) -> BoxFuture<'a, Result<ResetConfirmation>> {
            Box::pin(async move {
                Ok(ResetConfirmation {
                    operation_id: req.operation_id,
                    target_fingerprint: req.target_fingerprint.clone(),
                    nonce: vec![1],
                    expires_at: now(),
                    hmac: "h".into(),
                })
            })
        }
        fn verify_reset_confirmation<'a>(
            &'a self,
            _confirmation: &'a ResetConfirmation,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn consume_reset_confirmation<'a>(
            &'a self,
            _confirmation: ResetConfirmation,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn consume_verified_reset_confirmation<'a>(
            &'a self,
            _target: &'a TargetIdentity,
            _confirmation: ResetConfirmation,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move { Ok(()) })
        }
    }

    fn coordinator<'a>(
        session: &'a mut FakeSession,
        op_state: &'a dyn ProtectedOperatorStateInspector,
        store: &'a dyn ProvisioningRecordStore,
        proofs: Option<&'a dyn DynBrokerProofService>,
    ) -> MigrationCoordinator<'a, FakeSession> {
        let mut c = MigrationCoordinator::new(
            session,
            op_state,
            store,
            "sha256:v0-baseline",
            proofs,
            manifest(),
        );
        c.bind_operation_id(uuid::Uuid::now_v7());
        c
    }

    #[tokio::test]
    async fn status_uninitialized_is_provision_required() {
        let mut session = FakeSession::new(PostgresMigrationFacts {
            initialized: false,
            applied_versions: vec![],
            dirty: None,
            epochs: EpochMarkers::default(),
        });
        let op = FakeOperatorState(ProtectedOperatorState::default());
        let store = FakeStore::default();
        let status = coordinator(&mut session, &op, &store, None)
            .status()
            .await
            .unwrap();
        assert!(!status.initialized);
        assert!(!status.ready);
        assert_eq!(status.safe_next_action, "PROVISION_REQUIRED");
    }

    #[tokio::test]
    async fn status_clean_ready_record_is_ready() {
        let mut session = FakeSession::new(clean_facts());
        let op = FakeOperatorState(ProtectedOperatorState {
            record_state: ExternalRecordState::Ready,
            ..ProtectedOperatorState::default()
        });
        let store = FakeStore::default();
        let status = coordinator(&mut session, &op, &store, None)
            .status()
            .await
            .unwrap();
        assert!(status.initialized);
        assert!(status.ready);
        assert_eq!(status.safe_next_action, "READY");
    }

    #[tokio::test]
    async fn status_dirty_is_resume_required() {
        let mut facts = clean_facts();
        facts.dirty = Some(DirtyEvidence {
            version: 3,
            reason: "checksum".into(),
            detected_at: now(),
        });
        let mut session = FakeSession::new(facts);
        let op = FakeOperatorState(ProtectedOperatorState {
            record_state: ExternalRecordState::Ready,
            ..ProtectedOperatorState::default()
        });
        let store = FakeStore::default();
        let status = coordinator(&mut session, &op, &store, None)
            .status()
            .await
            .unwrap();
        assert!(!status.ready);
        assert_eq!(status.safe_next_action, "RESUME_REQUIRED");
    }

    #[tokio::test]
    async fn status_clean_facts_but_quarantined_record_is_repair() {
        let mut session = FakeSession::new(clean_facts());
        let op = FakeOperatorState(ProtectedOperatorState {
            record_state: ExternalRecordState::Quarantined,
            ..ProtectedOperatorState::default()
        });
        let store = FakeStore::default();
        let status = coordinator(&mut session, &op, &store, None)
            .status()
            .await
            .unwrap();
        assert!(!status.ready);
        assert_eq!(status.safe_next_action, "REPAIR_REQUIRED");
    }

    #[tokio::test]
    async fn status_manifest_drift_is_repair_required() {
        let mut facts = clean_facts();
        facts.applied_versions.push(VersionChecksum {
            version: 7,
            checksum: "rogue".into(),
        });
        let mut session = FakeSession::new(facts);
        let op = FakeOperatorState(ProtectedOperatorState {
            record_state: ExternalRecordState::Ready,
            ..ProtectedOperatorState::default()
        });
        let store = FakeStore::default();
        let status = coordinator(&mut session, &op, &store, None)
            .status()
            .await
            .unwrap();
        assert!(!status.ready);
        assert_eq!(status.safe_next_action, "REPAIR_REQUIRED");
    }

    #[tokio::test]
    async fn verify_uninitialized_is_denied_provision_required() {
        let mut session = FakeSession::new(PostgresMigrationFacts {
            initialized: false,
            applied_versions: vec![],
            dirty: None,
            epochs: EpochMarkers::default(),
        });
        let op = FakeOperatorState(ProtectedOperatorState::default());
        let store = FakeStore::default();
        let err = coordinator(&mut session, &op, &store, None)
            .verify()
            .await
            .unwrap_err();
        assert_eq!(err.code(), "PROVISION_REQUIRED");
        assert_eq!(err.kind(), FailureKind::Denied);
    }

    #[tokio::test]
    async fn verify_reports_drift_lines_in_verify_format() {
        let mut facts = clean_facts();
        facts.applied_versions.push(VersionChecksum {
            version: 2,
            checksum: "tampered".into(),
        });
        facts.applied_versions.push(VersionChecksum {
            version: 5,
            checksum: String::new(),
        });
        let mut session = FakeSession::new(facts);
        let op = FakeOperatorState(ProtectedOperatorState::default());
        let store = FakeStore::default();
        let result = coordinator(&mut session, &op, &store, None)
            .verify()
            .await
            .unwrap();
        assert!(!result.matches);
        assert_eq!(
            result.drifts,
            vec![
                "version 2: checksum mismatch (got tampered)".to_owned(),
                "version 5: empty checksum".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn up_journals_the_full_transition_sequence() {
        let mut session = FakeSession::new(PostgresMigrationFacts {
            initialized: false,
            applied_versions: vec![],
            dirty: None,
            epochs: EpochMarkers::default(),
        });
        let op = FakeOperatorState(ProtectedOperatorState::default());
        let store = FakeStore::default();
        let proofs = FakeProofs;
        let operation = coordinator(&mut session, &op, &store, Some(&proofs))
            .up(&target())
            .await
            .unwrap();
        assert_eq!(operation.record_state, ExternalRecordState::Ready);
        assert_eq!(
            operation.provisioning_phase,
            ProvisioningPhase::CandidateActive
        );
        // Journal order: recorded → candidate_staged → session-binding
        // persist (same phase) → baseline_installed → candidate_active
        // → ready.
        let journal = store.journal.lock().unwrap().clone();
        assert_eq!(
            journal,
            vec![
                "create:initializing:recorded",
                "replace:initializing:candidate_staged@1",
                "replace:initializing:candidate_staged@2",
                "replace:initializing:baseline_installed@3",
                "replace:initializing:candidate_active@4",
                "replace:ready:@5",
            ]
        );
        assert_eq!(session.calls, vec!["inspect", "prepare_up", "commit_up"]);
    }

    #[tokio::test]
    async fn up_fails_closed_without_proof_service() {
        let mut session = FakeSession::new(PostgresMigrationFacts {
            initialized: false,
            applied_versions: vec![],
            dirty: None,
            epochs: EpochMarkers::default(),
        });
        let op = FakeOperatorState(ProtectedOperatorState::default());
        let store = FakeStore::default();
        let err = coordinator(&mut session, &op, &store, None)
            .up(&target())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "proof_service_required");
        // The journal already carries the recorded intent — the
        // refusal leaves durable evidence behind, never a rollback.
        assert!(store.journal.lock().unwrap()[0].starts_with("create:initializing:recorded"));
    }

    #[tokio::test]
    async fn up_propagates_store_unavailability_at_create() {
        let mut session = FakeSession::new(PostgresMigrationFacts {
            initialized: false,
            applied_versions: vec![],
            dirty: None,
            epochs: EpochMarkers::default(),
        });
        let op = FakeOperatorState(ProtectedOperatorState::default());
        let store = FakeStore {
            fail_writes: true,
            ..FakeStore::default()
        };
        let err = coordinator(&mut session, &op, &store, Some(&FakeProofs))
            .up(&target())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "store_down");
        assert_eq!(err.kind(), FailureKind::Unavailable);
    }

    #[tokio::test]
    async fn up_on_initialized_ready_target_is_idempotent() {
        let op_id = uuid::Uuid::now_v7();
        let mut session = FakeSession::new(clean_facts());
        let op = FakeOperatorState(ProtectedOperatorState {
            record_state: ExternalRecordState::Ready,
            operation_id: op_id,
            ..ProtectedOperatorState::default()
        });
        let store = FakeStore::default();
        let operation = coordinator(&mut session, &op, &store, None)
            .up(&target())
            .await
            .unwrap();
        assert_eq!(operation.operation_id, op_id);
        assert_eq!(operation.record_state, ExternalRecordState::Ready);
        // No journal writes, no runner calls beyond the read.
        assert_eq!(session.calls, vec!["inspect"]);
    }

    #[tokio::test]
    async fn up_on_initialized_non_ready_is_resumable_repair() {
        let op_id = uuid::Uuid::now_v7();
        let mut session = FakeSession::new(clean_facts());
        let op = FakeOperatorState(ProtectedOperatorState {
            record_state: ExternalRecordState::Quarantined,
            operation_id: op_id,
            ..ProtectedOperatorState::default()
        });
        let store = FakeStore::default();
        let err = coordinator(&mut session, &op, &store, None)
            .up(&target())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "REPAIR_REQUIRED");
        assert_eq!(err.kind(), FailureKind::Internal);
    }
}
