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

        // Upstream `IsExpired` is `now.After(ExpiresAt)` — strict.
        if confirmation.expires_at < now() {
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

// ---------------------------------------------------------------------------
// R6 Task 3 — backup & recovery coordinators (C01–C05 orchestration)
//
// `internal/backup/app/{backup_coordinator,restore_coordinator,
// restore_verifier,authority_reset}.go`. The coordinators are
// deliberately controllers over ports: only the protected journals own
// ticket consumption and durable phase changes, only the engine owns
// external effects, and only the broker/database reset ports produce
// authority evidence. They never carry locators, credentials, adapter
// types, or the broker HMAC key: every environment fact arrives
// through `port` traits and every persisted transition goes through
// the domain's closed methods, so a coordinator cannot manufacture a
// checkpoint the state machine would reject.
// ---------------------------------------------------------------------------

use crate::backup::capacity::{check_backup_admission, check_backup_continuation};
use crate::backup::inventory::{InventoryChunk, InventoryEntry, new_inventory_chunk};
use crate::backup::manifest::new_seal_root_manifest;
use crate::backup::operation::{
    BackupOperation, BackupPhase, BackupSealProposal, DumpEvidence, backup_failure,
};
use crate::port::{
    BackupAdmissionSnapshot, BackupDumper, BackupEnvironmentProbe, BackupJournalStore,
    BackupSealVerifier, BackupSealer, BrokerAuthorityReset, ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH,
    MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES, PostgresAuthorityReset, ReadyArtifactCursor,
    ReadyArtifactSource, RecoveryRepositoryStore, RecoveryRepositoryVerifier,
    RestoreAdmissionFacts, RestoreAdmissionInspector, RestoreEngine, RestoreJournalStore,
    RestoreTargetExclusion, RestoreTicketIssuer,
};
use crate::recovery::operation::{
    RestoreAbandonAuthorization, RestoreApplyAuthorization, RestoreCheckpoint, RestoreOperation,
    RestorePhase, RestoreTicket, new_restore_operation,
};
use crate::recovery::refusal::{
    RestoreRefusalReason, classify_restore_refusal, sanitize_restore_refusal_cause,
};

/// `errors.Join` — upstream joins the release failure onto the
/// primary error; the primary classification survives, the release
/// failure is appended to the message.
fn join(primary: Failure, secondary: Failure) -> Failure {
    Failure::new(
        primary.kind(),
        primary.code(),
        format!(
            "{}; additionally: {}",
            primary.message(),
            secondary.message()
        ),
    )
}

// ---------------------------------------------------------------------------
// BackupCoordinator (backup_coordinator.go)
// ---------------------------------------------------------------------------

/// `app.BackupResult` — safe worker evidence. Publication is a
/// diagnostic result, not terminal authority: the helper
/// independently recomputes it after this worker exits before the
/// broker may seal the operation.
#[derive(Debug, Clone)]
pub struct BackupResult {
    /// The operation at its furthest checkpoint.
    pub operation: BackupOperation,
    /// The canonical seal root (present once inventory completed).
    pub manifest: Option<crate::backup::manifest::SealRootManifest>,
    /// The seal publication receipt (present once sealing finished).
    pub publication: Option<crate::repository::BackupSealPublication>,
}

/// `app.BackupCoordinator` composes the C01/C02 backup flow around
/// durable ports. It never materializes a credential, chooses a
/// repository path, or treats an unsealed manifest as restorable. Any
/// failure after admission transitions the operation to `failed`
/// best-effort while retaining all immutable evidence.
pub struct BackupCoordinator<'a> {
    /// Protected backup journal (`CreateBackup`/`ReadBackup`/CAS).
    pub journal: &'a dyn BackupJournalStore,
    /// Trusted environment (atomic admission + continuity snapshots).
    pub environment: &'a dyn BackupEnvironmentProbe,
    /// Sealed-media repository sink (backup-scoped writes).
    pub repository: &'a dyn RecoveryRepositoryStore,
    /// Ready-artifact metadata + body source.
    pub artifacts: &'a dyn ReadyArtifactSource,
    /// Pinned `pg_dump` stream.
    pub dumper: &'a dyn BackupDumper,
    /// Worker-facing broker seal commit.
    pub sealer: &'a dyn BackupSealer,
    /// Installed admission envelope.
    pub profile: crate::backup::capacity::RecoveryProfile,
    /// `coordinator.now` — the wall clock; tests pin it so evidence
    /// freshness and the `proposed_at` instant are deterministic.
    pub now: Box<dyn Fn() -> time::OffsetDateTime>,
}

/// `errors.Is(err, errUnrecoverableArtifactBody)` — the classified
/// signal `copy_artifact_body` produces after every attempt found the
/// body disagreeing with its sealed metadata.
const ERR_UNRECOVERABLE_ARTIFACT_BODY: &str = "backup_artifact_body_unrecoverable";
/// `errArtifactTransferExhausted` — the retry budget spent on
/// ordinary transfer failures.
const ERR_ARTIFACT_TRANSFER_EXHAUSTED: &str = "backup_artifact_transfer_exhausted";

impl<'a> BackupCoordinator<'a> {
    /// `NewBackupCoordinator` — `nil` dependencies cannot arrive
    /// through references; the clock defaults to the wall clock.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        journal: &'a dyn BackupJournalStore,
        environment: &'a dyn BackupEnvironmentProbe,
        repository: &'a dyn RecoveryRepositoryStore,
        artifacts: &'a dyn ReadyArtifactSource,
        dumper: &'a dyn BackupDumper,
        sealer: &'a dyn BackupSealer,
        profile: crate::backup::capacity::RecoveryProfile,
    ) -> Self {
        Self {
            journal,
            environment,
            repository,
            artifacts,
            dumper,
            sealer,
            profile,
            now: Box::new(time::OffsetDateTime::now_utc),
        }
    }

    /// `NewBackupCoordinator`'s `valid` — profile validity.
    fn valid(&self) -> Result<()> {
        self.profile.validate()
    }

    /// `Run` — admits a new planned operation and drives it once to
    /// publication-ready sealing or `failed`. The post-reap helper
    /// owns terminal completion. There is deliberately no
    /// post-admission resume path: a later invocation must create a
    /// new consistent point and a new `BackupOperation`.
    ///
    /// Like upstream, the partial result is returned alongside the
    /// failure — hence `Err(BackupRunFailure)` rather than a bare
    /// [`Failure`].
    pub fn run(
        &self,
        operation: BackupOperation,
    ) -> core::result::Result<BackupResult, BackupRunFailure> {
        if let Err(err) = self.valid() {
            return Err(BackupRunFailure {
                result: Box::new(BackupResult {
                    operation: operation.clone(),
                    manifest: None,
                    publication: None,
                }),
                failure: err,
            });
        }
        if operation.phase != BackupPhase::Planned
            || !crate::wire::is_zero_time(operation.accepted_at)
        {
            return Err(BackupRunFailure {
                result: Box::new(BackupResult {
                    operation,
                    manifest: None,
                    publication: None,
                }),
                failure: Failure::internal(
                    "backup_create",
                    "backup create: operation must be planned",
                ),
            });
        }
        let admission = match self.admit(&operation) {
            Ok(admission) => admission,
            Err(failure) => {
                return Err(BackupRunFailure {
                    result: Box::new(BackupResult {
                        operation,
                        manifest: None,
                        publication: None,
                    }),
                    failure,
                });
            }
        };
        if let Err(err) = self.journal.create_backup(&operation) {
            return Err(BackupRunFailure {
                result: Box::new(BackupResult {
                    operation,
                    manifest: None,
                    publication: None,
                }),
                failure: wrap("backup create: persist planned operation", err),
            });
        }
        let admitted = operation
            .accept(admission.facts)
            .map_err(|err| BackupRunFailure {
                result: Box::new(BackupResult {
                    operation: operation.clone(),
                    manifest: None,
                    publication: None,
                }),
                failure: wrap("backup create: persist admitted", err),
            })?;
        if let Err(err) = self.journal.compare_and_swap_backup(&operation, &admitted) {
            return Err(BackupRunFailure {
                result: Box::new(BackupResult {
                    operation,
                    manifest: None,
                    publication: None,
                }),
                failure: wrap("backup create: persist admitted", err),
            });
        }
        self.run_admitted(admitted)
    }

    /// `admit` — one atomic environment snapshot gates everything:
    /// accepted-point facts validity and freshness, capacity
    /// admission, required throughput evidence, deadline
    /// plausibility, and the observed target-lock/authority-receipt
    /// fence.
    fn admit(&self, operation: &BackupOperation) -> Result<BackupAdmissionSnapshot> {
        let snapshot = self
            .environment
            .admission_snapshot(operation)
            .map_err(|e| wrap("backup create: read admission evidence", e))?;
        if snapshot.facts.validate().is_err() || snapshot.facts.database_time < operation.created_at
        {
            return Err(Failure::new(
                FailureKind::Denied,
                "BACKUP_ACCEPTED_FACTS_INVALID",
                "recovery admission refused: BACKUP_ACCEPTED_FACTS_INVALID",
            ));
        }
        check_backup_admission(&self.profile, &snapshot.capacity)
            .map_err(|check| check.into_failure())?;
        snapshot
            .throughput
            .valid_at((self.now)(), &self.profile)
            .map_err(|check| check.into_failure())?;
        crate::recovery::profile::check_backup_deadline_plausibility(
            &self.profile,
            &snapshot.capacity,
            &snapshot.throughput,
        )
        .map_err(|check| check.into_failure())?;
        if !snapshot.target_lock_held || !snapshot.authority_receipt_held {
            return Err(Failure::new(
                FailureKind::Denied,
                "BACKUP_AUTHORITY_OR_LOCK_REQUIRED",
                "recovery admission refused: BACKUP_AUTHORITY_OR_LOCK_REQUIRED",
            ));
        }
        Ok(snapshot)
    }

    /// `runAdmitted`.
    fn run_admitted(
        &self,
        operation: BackupOperation,
    ) -> core::result::Result<BackupResult, BackupRunFailure> {
        if self.guard(&operation, 0).is_err() {
            return Err(self.fail(operation, backup_failure::CONTINUITY_LOST));
        }
        if self.repository.bind_backup(&operation).is_err() {
            return Err(self.fail(operation, backup_failure::REPOSITORY_BIND));
        }
        let dumping = match self.advance(&operation, BackupPhase::Dumping) {
            Ok(dumping) => dumping,
            Err(failure) => {
                return Err(BackupRunFailure {
                    result: Box::new(BackupResult {
                        operation,
                        manifest: None,
                        publication: None,
                    }),
                    failure,
                });
            }
        };
        let mut dump_stream = match self.dumper.start_dump(&dumping) {
            Ok(stream) => stream,
            Err(_) => return Err(self.fail(dumping, backup_failure::DUMP_START)),
        };
        let dump_evidence = {
            let mut guarded = self.guarded(&dumping, &mut *dump_stream);
            self.repository.write_dump(
                dumping.backup_id,
                &mut guarded,
                self.profile.max_database_bytes as i64,
            )
        };
        let close_err = dump_stream.close();
        let dump_evidence = match (dump_evidence, close_err) {
            (Ok(evidence), Ok(())) => evidence,
            _ => return Err(self.fail(dumping, backup_failure::DUMP_WRITE)),
        };
        if self.guard(&dumping, 0).is_err() {
            return Err(self.fail(dumping, backup_failure::CONTINUITY_LOST));
        }

        let inventory = match self.advance(&dumping, BackupPhase::Inventory) {
            Ok(inventory) => inventory,
            Err(failure) => {
                return Err(BackupRunFailure {
                    result: Box::new(BackupResult {
                        operation: dumping,
                        manifest: None,
                        publication: None,
                    }),
                    failure,
                });
            }
        };
        let manifest = match self.copy_inventory(&inventory, dump_evidence) {
            Ok(manifest) => manifest,
            Err(err) if err.code() == ERR_UNRECOVERABLE_ARTIFACT_BODY => {
                return Err(self.fail(inventory, backup_failure::CORRUPTED_UNRECOVERABLE_BODY));
            }
            Err(_) => return Err(self.fail(inventory, backup_failure::INVENTORY_WRITE)),
        };
        if self.guard(&inventory, 0).is_err() {
            return Err(self.fail(inventory, backup_failure::CONTINUITY_LOST));
        }

        let sealing = match self.advance(&inventory, BackupPhase::Sealing) {
            Ok(sealing) => sealing,
            Err(failure) => {
                return Err(BackupRunFailure {
                    result: Box::new(BackupResult {
                        operation: inventory,
                        manifest: Some(manifest),
                        publication: None,
                    }),
                    failure,
                });
            }
        };
        let file_tree = match self.repository.write_manifest(&manifest) {
            Ok(file_tree) => file_tree,
            Err(_) => return Err(self.fail(sealing, backup_failure::MANIFEST_WRITE)),
        };
        if self.guard(&sealing, 0).is_err() {
            return Err(self.fail(sealing, backup_failure::CONTINUITY_LOST));
        }
        let root_manifest_json = match manifest.canonical_json() {
            Ok(json) => json,
            Err(_) => return Err(self.fail(sealing, backup_failure::SEAL_PROPOSAL)),
        };
        let proposal = BackupSealProposal {
            operation_id: sealing.operation_id,
            backup_id: sealing.backup_id,
            target: sealing.target.clone(),
            accepted_at: sealing.accepted_at,
            repository_binding_id: sealing.accepted_facts.repository_binding_id,
            target_fingerprint: sealing.accepted_facts.target_fingerprint.clone(),
            config_fingerprint: sealing.accepted_facts.config_fingerprint.clone(),
            payload_epoch_id: sealing.accepted_facts.payload_epoch_id,
            root_manifest_json,
            manifest_digest: manifest.digest,
            file_tree_digest: file_tree.digest,
            proposed_at: (self.now)(),
        };
        if proposal.validate().is_err() {
            return Err(self.fail(sealing, backup_failure::SEAL_PROPOSAL));
        }
        let companion = match self.sealer.seal_backup(&proposal) {
            Ok(companion) => companion,
            Err(_) => return Err(self.fail(sealing, backup_failure::SEAL)),
        };
        if companion.verify().is_err()
            || companion.operation_id != proposal.operation_id
            || companion.backup_id != proposal.backup_id
            || companion.repository_binding_id != proposal.repository_binding_id
            || companion.target_fingerprint != proposal.target_fingerprint
            || companion.config_fingerprint != proposal.config_fingerprint
            || companion.payload_epoch_id != proposal.payload_epoch_id
            || companion.root_manifest_digest != proposal.manifest_digest
            || companion.file_tree_digest != proposal.file_tree_digest
        {
            return Err(self.fail(sealing, backup_failure::SEAL_RESPONSE));
        }
        let publication = match self
            .repository
            .write_seal_companion(sealing.backup_id, &companion)
        {
            Ok(publication) if publication.binds(&companion) => publication,
            _ => return Err(self.fail(sealing, backup_failure::SEAL_PUBLICATION)),
        };
        Ok(BackupResult {
            operation: sealing,
            manifest: Some(manifest),
            publication: Some(publication),
        })
    }

    /// `copyInventory` — bounded canonical pages of ready-artifact
    /// metadata; each page becomes one immutable chunk after every
    /// body it names was written and verified.
    fn copy_inventory(
        &self,
        operation: &BackupOperation,
        dump: DumpEvidence,
    ) -> Result<crate::backup::manifest::SealRootManifest> {
        let mut cursor = ReadyArtifactCursor::default();
        let mut previous_id = uuid::Uuid::nil();
        let mut total_bytes: u64 = 0;
        let mut total_count: u64 = 0;
        let mut chunks: Vec<InventoryChunk> = Vec::new();
        loop {
            let page = self.artifacts.list_ready_artifacts(
                operation,
                cursor,
                MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES,
            )?;
            if page.entries.len() > MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES
                || (!page.complete && page.entries.is_empty())
            {
                return Err(Failure::internal(
                    "backup_inventory_page",
                    "invalid backup inventory page",
                ));
            }
            if page.complete {
                if !page.next_cursor.artifact_id.is_nil() {
                    return Err(Failure::internal(
                        "backup_inventory_page",
                        "invalid completed backup inventory page",
                    ));
                }
            } else if page.next_cursor.artifact_id.is_nil()
                || page.next_cursor.artifact_id != page.entries[page.entries.len() - 1].artifact_id
            {
                return Err(Failure::internal(
                    "backup_inventory_cursor",
                    "invalid backup inventory cursor",
                ));
            }

            let mut canonical = page.entries.clone();
            canonical.sort_by_key(|entry| entry.artifact_id.to_string());
            for (i, entry) in canonical.iter().enumerate() {
                if entry.validate().is_err()
                    || (i > 0 && canonical[i - 1].artifact_id == entry.artifact_id)
                    || (!previous_id.is_nil()
                        && previous_id.to_string() >= entry.artifact_id.to_string())
                    || total_count >= self.profile.max_record_count
                    || entry.size < 0
                    || entry.size as u64 > self.profile.max_object_bytes.saturating_sub(total_bytes)
                {
                    return Err(Failure::internal(
                        "backup_inventory_entry",
                        "invalid backup inventory entry",
                    ));
                }
                previous_id = entry.artifact_id;
                total_count += 1;
                total_bytes += entry.size as u64;
            }

            for entry in &canonical {
                if let Err(err) = self.copy_artifact_body(operation, entry) {
                    if err.code() == ERR_UNRECOVERABLE_ARTIFACT_BODY {
                        return Err(err);
                    }
                    return Err(Failure::internal(
                        "backup_artifact_copy",
                        "backup artifact copy failed",
                    ));
                }
                if self.guard(operation, 0).is_err() {
                    return Err(Failure::internal(
                        "backup_continuity",
                        "backup continuity guard refused",
                    ));
                }
            }

            if !canonical.is_empty() {
                let chunk = new_inventory_chunk(chunks.len() as u32, canonical.clone())?;
                self.repository.write_chunk(operation.backup_id, &chunk)?;
                chunks.push(chunk);
                if self.guard(operation, 0).is_err() {
                    return Err(Failure::internal(
                        "backup_continuity",
                        "backup continuity guard refused",
                    ));
                }
            }
            if page.complete {
                break;
            }
            cursor = page.next_cursor;
        }
        new_seal_root_manifest(operation, dump, &chunks)
    }

    /// `copyArtifactBody` — three attempts; a complete body that
    /// disagrees with its sealed metadata is counted toward the
    /// unrecoverable classification only when the stream closed
    /// cleanly.
    fn copy_artifact_body(
        &self,
        operation: &BackupOperation,
        entry: &InventoryEntry,
    ) -> Result<()> {
        const MAXIMUM_ATTEMPTS: usize = 3;
        let mut evidence_mismatch_attempts = 0usize;
        for _attempt in 0..MAXIMUM_ATTEMPTS {
            let Ok(mut body) = self.artifacts.open_ready_artifact(operation, entry) else {
                continue;
            };
            let copy_result = {
                let mut guarded = self.guarded(operation, &mut *body);
                self.repository
                    .write_artifact_body(operation.backup_id, entry, &mut guarded)
            };
            let close_result = body.close();
            if copy_result.is_ok() && close_result.is_ok() {
                return Ok(());
            }
            if copy_result
                .as_ref()
                .err()
                .is_some_and(|e| e.code() == ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH)
                && close_result.is_ok()
            {
                evidence_mismatch_attempts += 1;
            }
        }
        if evidence_mismatch_attempts == MAXIMUM_ATTEMPTS {
            return Err(Failure::internal(
                ERR_UNRECOVERABLE_ARTIFACT_BODY,
                "backup artifact body is unrecoverable",
            ));
        }
        Err(Failure::internal(
            ERR_ARTIFACT_TRANSFER_EXHAUSTED,
            "backup artifact transfer retry budget exhausted",
        ))
    }

    /// `guarded` — wraps a reader so no more than one write quantum
    /// passes between continuity samples.
    fn guarded<'g>(
        &'g self,
        operation: &'g BackupOperation,
        reader: &'g mut dyn std::io::Read,
    ) -> GuardedReader<'g> {
        GuardedReader {
            reader,
            quantum: self.profile.write_quantum,
            since: 0,
            guard: Box::new(move |bytes_since_last_guard| {
                self.guard(operation, bytes_since_last_guard)
            }),
        }
    }

    /// `guard` — one fresh continuity snapshot for this exact
    /// operation; the conservative (larger) of the environment's and
    /// the reader's byte counts wins.
    fn guard(&self, operation: &BackupOperation, bytes_since_last_guard: u64) -> Result<()> {
        let mut snapshot = self.environment.continuation_snapshot(operation)?;
        if bytes_since_last_guard > snapshot.bytes_since_last_guard {
            snapshot.bytes_since_last_guard = bytes_since_last_guard;
        }
        check_backup_continuation(&self.profile, operation, &snapshot, (self.now)())
    }

    /// `advance` — the domain transition, then CAS.
    fn advance(&self, operation: &BackupOperation, phase: BackupPhase) -> Result<BackupOperation> {
        let next = operation.advance(phase, (self.now)())?;
        self.journal
            .compare_and_swap_backup(operation, &next)
            .map_err(|e| wrap(&format!("backup create: persist {}", phase.as_str()), e))?;
        Ok(next)
    }

    /// `fail` — records the closed terminal reason best-effort, then
    /// returns the resumable failure.
    fn fail(&self, mut operation: BackupOperation, reason: &'static str) -> BackupRunFailure {
        if operation.phase.can_transition(BackupPhase::Failed)
            && let Ok(failed) = operation.fail(reason, (self.now)())
            && self
                .journal
                .compare_and_swap_backup(&operation, &failed)
                .is_ok()
        {
            operation = failed;
        }
        BackupRunFailure {
            result: Box::new(BackupResult {
                operation,
                manifest: None,
                publication: None,
            }),
            failure: Failure::new(
                FailureKind::Internal,
                reason,
                "preserve recovery evidence and create a new backup operation",
            ),
        }
    }
}

/// Upstream `Run`'s `(BackupResult, error)` pair as one error type:
/// the partial result is always available to the caller.
#[derive(Debug)]
pub struct BackupRunFailure {
    /// The operation's furthest reached state (and evidence).
    /// Boxed so `run`'s error variant stays small.
    pub result: Box<BackupResult>,
    /// The classified failure.
    pub failure: Failure,
}

/// `backupGuardedReader` — limits every underlying read to the next
/// recovery quantum and samples the environment before continuing.
/// It avoids trusting a process or object-store reader to provide
/// naturally small chunks.
struct GuardedReader<'a> {
    reader: &'a mut dyn std::io::Read,
    quantum: u64,
    since: u64,
    guard: Box<dyn FnMut(u64) -> Result<()> + 'a>,
}

impl std::io::Read for GuardedReader<'_> {
    fn read(&mut self, p: &mut [u8]) -> std::io::Result<usize> {
        if self.quantum == 0 {
            return Err(std::io::Error::other(
                "backup guarded reader is unavailable",
            ));
        }
        if self.since == self.quantum {
            (self.guard)(self.since).map_err(|e| std::io::Error::other(e.message().to_owned()))?;
            self.since = 0;
        }
        let remaining = self.quantum - self.since;
        let p = if (p.len() as u64) > remaining {
            &mut p[..remaining as usize]
        } else {
            p
        };
        let n = self.reader.read(p)?;
        if n > 0 {
            self.since += n as u64;
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// RestoreCoordinator (restore_coordinator.go)
// ---------------------------------------------------------------------------

/// `app.RestoreCoordinator` drives the C04/C05 recovery barrier. It
/// is deliberately a controller over ports: only the protected
/// journal owns ticket consumption and durable phase changes, and
/// only the engine owns external effects.
pub struct RestoreCoordinator<'a> {
    /// Protected restore journal (begin/resume/abandon/read/CAS).
    pub journal: &'a dyn RestoreJournalStore,
    /// The destructive engine (exclusion, apply, projection,
    /// inventory, quarantine projection, authority reset).
    pub engine: &'a dyn RestoreEngine,
    /// `coordinator.now` — tests pin it for ticket/authorization
    /// freshness.
    pub now: Box<dyn Fn() -> time::OffsetDateTime>,
}

/// `continueOperation`'s `(operation, err)` pair as one error type:
/// upstream always returns the furthest-checkpointed protected record
/// alongside the failure so the operator can inspect progress. The
/// `Option` is upstream's zero record — `None` when no protected
/// record existed yet.
#[derive(Debug)]
pub struct RestoreStepFailure {
    /// The furthest checkpointed operation. Boxed so the
    /// `RestoreStep` error variant stays small.
    pub operation: Option<Box<RestoreOperation>>,
    /// The classified failure.
    pub failure: Failure,
}

impl RestoreStepFailure {
    /// Packs the in-flight record with a failure.
    fn at(operation: RestoreOperation, failure: Failure) -> Self {
        Self {
            operation: Some(Box::new(operation)),
            failure,
        }
    }

    /// A failure before any protected record existed.
    fn bare(failure: Failure) -> Self {
        Self {
            operation: None,
            failure,
        }
    }
}

/// `Apply`/`Resume`/`Abandon` result — the record rides with the
/// failure exactly as upstream returns `(record, err)`.
pub type RestoreStep = core::result::Result<RestoreOperation, RestoreStepFailure>;

impl<'a> RestoreCoordinator<'a> {
    /// `NewRestoreCoordinator` — `nil` dependencies cannot arrive
    /// through references; the clock defaults to the wall clock.
    pub fn new(journal: &'a dyn RestoreJournalStore, engine: &'a dyn RestoreEngine) -> Self {
        Self {
            journal,
            engine,
            now: Box::new(time::OffsetDateTime::now_utc),
        }
    }

    /// `Apply` — atomically starts the known verified operation in
    /// protected state, then advances it as far as its effects can be
    /// proven. It never retries a ticket: a second `apply` must be
    /// rejected by `RestoreJournalStore` as a replay.
    pub fn apply(
        &self,
        ticket: &RestoreTicket,
        authorization: &RestoreApplyAuthorization,
    ) -> RestoreStep {
        let now = (self.now)();
        if !authorization.valid_at(now) || !authorization.binds(ticket) {
            return Err(RestoreStepFailure::bare(action_failure(
                "RESTORE_FRESH_CONFIRMATION_REQUIRED",
                "complete a fresh PAM and trusted-TTY restore confirmation for this exact ticket",
            )));
        }
        let prospective = match new_restore_operation(ticket, now) {
            Ok(prospective) => prospective,
            Err(err) => {
                return Err(RestoreStepFailure::bare(wrap(
                    "restore apply: invalid protected operation",
                    err,
                )));
            }
        };
        let exclusion = match self.acquire_target_exclusion(&prospective) {
            Ok(exclusion) => exclusion,
            Err(err) => return Err(RestoreStepFailure::bare(err)),
        };
        let now = (self.now)();
        let prospective = match new_restore_operation(ticket, now) {
            Ok(prospective) => prospective,
            Err(_) => {
                let _ = release_target_exclusion(&*exclusion);
                return Err(RestoreStepFailure::bare(action_failure(
                    "RESTORE_FRESH_CONFIRMATION_REQUIRED",
                    "complete a fresh restore verification and trusted-TTY confirmation after acquiring target exclusion",
                )));
            }
        };
        if !authorization.valid_at(now) || !authorization.binds(ticket) {
            let _ = release_target_exclusion(&*exclusion);
            return Err(RestoreStepFailure::bare(action_failure(
                "RESTORE_FRESH_CONFIRMATION_REQUIRED",
                "complete a fresh restore verification and trusted-TTY confirmation after acquiring target exclusion",
            )));
        }
        let operation = match self.journal.begin_restore(ticket, authorization, now) {
            Ok(operation) => operation,
            Err(err) => {
                let err = match release_target_exclusion(&*exclusion) {
                    Ok(()) => err,
                    Err(release_err) => join(
                        wrap("restore apply: begin protected operation", err),
                        release_err,
                    ),
                };
                return Err(RestoreStepFailure::bare(wrap(
                    "restore apply: begin protected operation",
                    err,
                )));
            }
        };
        if operation != prospective {
            let _ = release_target_exclusion(&*exclusion);
            return Err(RestoreStepFailure::at(
                operation,
                Failure::internal(
                    "restore_apply",
                    "restore apply: protected operation binding mismatch",
                ),
            ));
        }
        self.continue_under_target_exclusion(operation, &*exclusion)
    }

    /// `Resume` — consumes a new helper-issued PAM/TTY authorization
    /// and continues only its exact durable operation. An operation
    /// ID is a selector, never recovery authority, and a confirmation
    /// used by `apply` cannot be replayed.
    pub fn resume(
        &self,
        operation_id: uuid::Uuid,
        authorization: &RestoreApplyAuthorization,
    ) -> RestoreStep {
        if operation_id.is_nil() {
            return Err(RestoreStepFailure::bare(Failure::internal(
                "restore_coordinator",
                "restore coordinator is unavailable",
            )));
        }
        let now = (self.now)();
        if !authorization.valid_at(now) || authorization.operation_id != operation_id {
            return Err(RestoreStepFailure::bare(action_failure(
                "RESTORE_FRESH_CONFIRMATION_REQUIRED",
                "complete a fresh PAM and trusted-TTY restore confirmation for this exact operation",
            )));
        }
        let protected = match self.journal.read_restore(operation_id) {
            Ok(protected) => protected,
            Err(err) => {
                return Err(RestoreStepFailure::bare(wrap(
                    "restore resume: read protected operation",
                    err,
                )));
            }
        };
        if !protected.is_resumable() {
            return Err(RestoreStepFailure::at(
                protected,
                unsupported_failure(
                    "RESTORE_OPERATION_NOT_RESUMABLE",
                    "inspect the protected recovery status and use restore verify for a new operation when appropriate",
                ),
            ));
        }
        let exclusion = match self.acquire_target_exclusion(&protected) {
            Ok(exclusion) => exclusion,
            Err(err) => return Err(RestoreStepFailure::at(protected, err)),
        };
        let now = (self.now)();
        if !authorization.valid_at(now) || authorization.operation_id != operation_id {
            let _ = release_target_exclusion(&*exclusion);
            return Err(RestoreStepFailure::at(
                protected,
                action_failure(
                    "RESTORE_FRESH_CONFIRMATION_REQUIRED",
                    "complete a fresh PAM and trusted-TTY restore confirmation after acquiring target exclusion",
                ),
            ));
        }
        let operation = match self
            .journal
            .resume_restore(operation_id, authorization, now)
        {
            Ok(operation) => operation,
            Err(err) => {
                let err = match release_target_exclusion(&*exclusion) {
                    Ok(()) => err,
                    Err(release_err) => join(
                        wrap("restore resume: consume protected authorization", err),
                        release_err,
                    ),
                };
                return Err(RestoreStepFailure::at(
                    protected,
                    wrap("restore resume: consume protected authorization", err),
                ));
            }
        };
        if !operation.is_resumable()
            || operation.operation_id != protected.operation_id
            || operation.ticket_id != protected.ticket_id
            || operation.backup_id != protected.backup_id
            || operation.target != protected.target
            || operation.target_fingerprint != protected.target_fingerprint
            || operation.manifest_digest != protected.manifest_digest
            || operation.payload_epoch_id != protected.payload_epoch_id
            || operation.database_schema_version != protected.database_schema_version
            || operation.capacity_evidence_digest != protected.capacity_evidence_digest
            || operation.security_epoch != protected.security_epoch
            || operation.restore_epoch != protected.restore_epoch
        {
            let _ = release_target_exclusion(&*exclusion);
            return Err(RestoreStepFailure::at(
                operation,
                Failure::internal(
                    "restore_resume",
                    "restore resume: protected operation binding mismatch",
                ),
            ));
        }
        self.continue_under_target_exclusion(operation, &*exclusion)
    }

    /// `Abandon` — ends a stuck-but-resumable operation with ADR
    /// 0016's terminal outcome. It acquires no target exclusion and
    /// runs no engine: abandonment touches neither PostgreSQL nor the
    /// repository, only the protected journal, so fencing the target
    /// would be ceremony over nothing. For the same reason it
    /// releases no capacity reserve — the phase change alone is what
    /// the sweep's terminal-outcome trigger reads.
    ///
    /// It refuses a non-resumable operation before consuming the
    /// authorization, so an operator who abandons an already-ready or
    /// already-abandoned operation spends their ceremony on nothing
    /// and is told why.
    pub fn abandon(
        &self,
        operation_id: uuid::Uuid,
        authorization: &RestoreAbandonAuthorization,
    ) -> RestoreStep {
        if operation_id.is_nil() {
            return Err(RestoreStepFailure::bare(Failure::internal(
                "restore_coordinator",
                "restore coordinator is unavailable",
            )));
        }
        let now = (self.now)();
        if !authorization.valid_at(now) || authorization.operation_id != operation_id {
            return Err(RestoreStepFailure::bare(action_failure(
                "RESTORE_FRESH_CONFIRMATION_REQUIRED",
                "complete a fresh PAM and trusted-TTY abandonment confirmation for this exact operation",
            )));
        }
        let protected = match self.journal.read_restore(operation_id) {
            Ok(protected) => protected,
            Err(err) => {
                return Err(RestoreStepFailure::bare(wrap(
                    "restore abandon: read protected operation",
                    err,
                )));
            }
        };
        if !protected.is_resumable() {
            return Err(RestoreStepFailure::at(
                protected,
                unsupported_failure(
                    "RESTORE_OPERATION_NOT_RESUMABLE",
                    "inspect the protected recovery status; a completed or already-abandoned operation has no outcome left to give up",
                ),
            ));
        }
        let abandoned = match self
            .journal
            .abandon_restore(operation_id, authorization, now)
        {
            Ok(abandoned) => abandoned,
            Err(err) => {
                return Err(RestoreStepFailure::at(
                    protected,
                    wrap("restore abandon: publish terminal outcome", err),
                ));
            }
        };
        if abandoned.operation_id != operation_id
            || abandoned.phase != RestorePhase::Abandoned
            || !abandoned.is_terminal()
        {
            return Err(RestoreStepFailure::at(
                abandoned,
                Failure::internal(
                    "restore_abandon",
                    "restore abandon: protected operation binding mismatch",
                ),
            ));
        }
        Ok(abandoned)
    }

    /// `continueOperation` — the checkpoint machine: one audit
    /// projection ahead of every non-trivial step, every persisted
    /// transition through the domain's closed methods, every CAS
    /// through the protected journal. Every failure path returns the
    /// furthest-checkpointed record inside [`RestoreStepFailure`].
    fn continue_operation(
        &self,
        mut operation: RestoreOperation,
        exclusion: &dyn RestoreTargetExclusion,
    ) -> RestoreStep {
        loop {
            if let Err(err) = assert_target_exclusion(exclusion) {
                return Err(RestoreStepFailure::at(operation, err));
            }
            if operation.last_checkpoint != RestoreCheckpoint::TicketConsumed
                && self.engine.project_restore_operation(&operation).is_err()
            {
                return Err(RestoreStepFailure::at(
                    operation,
                    resumable_failure(
                        "RESTORE_AUDIT_PROJECTION_FAILED",
                        "repair the recovery audit projection and resume the exact protected operation",
                    ),
                ));
            }
            match operation.phase {
                RestorePhase::Applying => {
                    if operation.last_checkpoint == RestoreCheckpoint::TicketConsumed {
                        if let Err(err) = self.engine.restore_database(&operation) {
                            // The pinned pg_restore adapter's own
                            // sanitized reason (state/media/capacity/
                            // engine), if it returned one, rides in the
                            // message — an operator sees why the
                            // replacement failed, never a raw adapter
                            // error.
                            let remediation = match sanitize_restore_refusal_cause(&err) {
                                Some(cause) => format!(
                                    "resolve the recorded restore failure and resume the exact operation (cause: {})",
                                    cause.as_str()
                                ),
                                None => "resolve the recorded restore failure and resume the exact operation".to_owned(),
                            };
                            return Err(RestoreStepFailure::at(
                                operation,
                                resumable_failure(
                                    "RESTORE_DATABASE_REPLACEMENT_FAILED",
                                    remediation,
                                ),
                            ));
                        }
                        if let Err(err) = assert_target_exclusion(exclusion) {
                            return Err(RestoreStepFailure::at(operation, err));
                        }
                        let next = match operation.record_database_replaced((self.now)()) {
                            Ok(next) => next,
                            Err(err) => return Err(RestoreStepFailure::at(operation, err)),
                        };
                        if let Err(err) = self.journal.compare_and_swap_restore(&operation, &next) {
                            return Err(RestoreStepFailure::at(
                                operation,
                                wrap("restore apply: persist replacement checkpoint", err),
                            ));
                        }
                        operation = next;
                        continue;
                    }
                    if operation.last_checkpoint != RestoreCheckpoint::DatabaseReplaced {
                        return Err(RestoreStepFailure::at(
                            operation,
                            Failure::internal(
                                "restore_apply",
                                "restore apply: invalid applying checkpoint",
                            ),
                        ));
                    }
                    let next = match operation.begin_verification((self.now)()) {
                        Ok(next) => next,
                        Err(err) => return Err(RestoreStepFailure::at(operation, err)),
                    };
                    if let Err(err) = self.journal.compare_and_swap_restore(&operation, &next) {
                        return Err(RestoreStepFailure::at(
                            operation,
                            wrap("restore apply: persist verification barrier", err),
                        ));
                    }
                    operation = next;
                }
                RestorePhase::Verifying => match operation.last_checkpoint {
                    RestoreCheckpoint::DatabaseReplaced => {
                        let findings = match self.engine.verify_inventory(&operation) {
                            Ok(findings) => findings,
                            Err(_) => {
                                return Err(RestoreStepFailure::at(
                                    operation,
                                    resumable_failure(
                                        "RESTORE_INVENTORY_VERIFICATION_FAILED",
                                        "resolve the recorded verification failure and resume the exact operation",
                                    ),
                                ));
                            }
                        };
                        // Findings are durable BEFORE the journal
                        // records inventory_verified — a crash between
                        // them leaves the operation resumable with the
                        // full typed finding set already safe.
                        let unresolved = match self
                            .engine
                            .record_quarantine_findings(&operation, &findings)
                        {
                            Ok(unresolved) => unresolved,
                            Err(_) => {
                                return Err(RestoreStepFailure::at(
                                    operation,
                                    resumable_failure(
                                        "RESTORE_QUARANTINE_PROJECTION_FAILED",
                                        "repair the typed recovery quarantine projection and resume the exact operation",
                                    ),
                                ));
                            }
                        };
                        let next = match operation.record_inventory_verified((self.now)()) {
                            Ok(next) => next,
                            Err(err) => return Err(RestoreStepFailure::at(operation, err)),
                        };
                        if let Err(err) = self.journal.compare_and_swap_restore(&operation, &next) {
                            return Err(RestoreStepFailure::at(
                                operation,
                                wrap("restore apply: persist inventory checkpoint", err),
                            ));
                        }
                        operation = next;
                        if unresolved > 0 {
                            // This checkpoint must be projected here,
                            // before enter_quarantine advances past
                            // it: the loop's top-of-iteration
                            // projection only ever sees the next
                            // iteration's state, and this branch
                            // returns rather than looping back — so
                            // without this call the projection would
                            // skip straight from database_replaced to
                            // quarantined, a transition
                            // `validProjectedTransition` correctly
                            // refuses (upstream SC-DEF-72).
                            if self.engine.project_restore_operation(&operation).is_err() {
                                return Err(RestoreStepFailure::at(
                                    operation,
                                    resumable_failure(
                                        "RESTORE_AUDIT_PROJECTION_FAILED",
                                        "repair the recovery audit projection and resume the exact protected operation",
                                    ),
                                ));
                            }
                            let next = match operation.enter_quarantine((self.now)()) {
                                Ok(next) => next,
                                Err(err) => {
                                    return Err(RestoreStepFailure::at(operation, err));
                                }
                            };
                            if let Err(err) =
                                self.journal.compare_and_swap_restore(&operation, &next)
                            {
                                return Err(RestoreStepFailure::at(
                                    operation,
                                    wrap("restore apply: persist quarantine barrier", err),
                                ));
                            }
                            return Err(RestoreStepFailure::at(
                                next,
                                quarantine_required_failure(unresolved),
                            ));
                        }
                    }
                    RestoreCheckpoint::InventoryVerified => {
                        let receipt = match self.engine.reset_authority(&operation) {
                            Ok(receipt) => receipt,
                            Err(_) => {
                                return Err(RestoreStepFailure::at(
                                    operation,
                                    resumable_failure(
                                        "RESTORE_AUTHORITY_RESET_FAILED",
                                        "resolve the authority reset failure and resume the exact operation",
                                    ),
                                ));
                            }
                        };
                        if receipt.validate_for(&operation).is_err() {
                            return Err(RestoreStepFailure::at(
                                operation,
                                resumable_failure(
                                    "RESTORE_AUTHORITY_RESET_FAILED",
                                    "resolve the invalid authority-reset evidence and resume the exact operation",
                                ),
                            ));
                        }
                        let next = match operation.record_authority_reset(&receipt) {
                            Ok(next) => next,
                            Err(err) => return Err(RestoreStepFailure::at(operation, err)),
                        };
                        if let Err(err) = self.journal.compare_and_swap_restore(&operation, &next) {
                            return Err(RestoreStepFailure::at(
                                operation,
                                wrap("restore apply: persist authority reset", err),
                            ));
                        }
                        operation = next;
                    }
                    RestoreCheckpoint::AuthorityReset => return Ok(operation),
                    _ => {
                        return Err(RestoreStepFailure::at(
                            operation,
                            Failure::internal(
                                "restore_apply",
                                "restore apply: invalid verification checkpoint",
                            ),
                        ));
                    }
                },
                RestorePhase::Quarantined => {
                    let findings = match self.engine.verify_inventory(&operation) {
                        Ok(findings) => findings,
                        Err(_) => {
                            return Err(RestoreStepFailure::at(
                                operation,
                                resumable_failure(
                                    "RESTORE_INVENTORY_VERIFICATION_FAILED",
                                    "complete Artifact re-ingest or delete finalization, then resume the exact operation for a fresh inventory pass",
                                ),
                            ));
                        }
                    };
                    let unresolved = match self
                        .engine
                        .record_quarantine_findings(&operation, &findings)
                    {
                        Ok(unresolved) => unresolved,
                        Err(_) => {
                            return Err(RestoreStepFailure::at(
                                operation,
                                resumable_failure(
                                    "RESTORE_QUARANTINE_PROJECTION_FAILED",
                                    "repair the typed recovery quarantine projection and resume the exact operation",
                                ),
                            ));
                        }
                    };
                    if unresolved != 0 {
                        return Err(RestoreStepFailure::at(
                            operation,
                            quarantine_required_failure(unresolved),
                        ));
                    }
                    let next = match operation.resume_verification(0, (self.now)()) {
                        Ok(next) => next,
                        Err(err) => return Err(RestoreStepFailure::at(operation, err)),
                    };
                    if let Err(err) = self.journal.compare_and_swap_restore(&operation, &next) {
                        return Err(RestoreStepFailure::at(
                            operation,
                            wrap("restore resume: persist quarantine resolution", err),
                        ));
                    }
                    operation = next;
                }
                _ => {
                    return Err(RestoreStepFailure::at(
                        operation,
                        Failure::internal(
                            "restore_apply",
                            "restore apply: protected operation is not resumable",
                        ),
                    ));
                }
            }
        }
    }

    /// `acquireTargetExclusion` — runs before `begin_restore` so a
    /// live serving profile cannot coexist with a newly published
    /// `applying` barrier. The lease is then retained through
    /// replacement, verification, quarantine checks and authority
    /// reset; only a successfully released lease may be followed by
    /// `ready`.
    fn acquire_target_exclusion(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Box<dyn RestoreTargetExclusion>> {
        let exclusion = self.engine.acquire_restore_target_exclusion(operation);
        let Ok(exclusion) = exclusion else {
            return Err(action_failure(
                "RESTORE_TARGET_EXCLUSION_REQUIRED",
                "stop the serving profile and acquire the target-exclusive recovery lock, then retry the exact operation",
            ));
        };
        if exclusion.assert_held().is_err() {
            let _ = release_target_exclusion(&*exclusion);
            return Err(resumable_failure(
                "RESTORE_TARGET_EXCLUSION_LOST",
                "reacquire the target-exclusive recovery lock before starting the protected operation",
            ));
        }
        Ok(exclusion)
    }

    /// `continueUnderTargetExclusion` — release, then `mark_ready`,
    /// then the audit projection, then the protected CAS — in that
    /// exact order.
    fn continue_under_target_exclusion(
        &self,
        operation: RestoreOperation,
        exclusion: &dyn RestoreTargetExclusion,
    ) -> RestoreStep {
        let (checkpointed, run_err) = match self.continue_operation(operation, exclusion) {
            Ok(checkpointed) => (Some(checkpointed), None),
            Err(step) => (step.operation.map(|boxed| *boxed), Some(step.failure)),
        };
        let release_result = release_target_exclusion(exclusion);
        if let Some(mut run_err) = run_err {
            if let Err(release_err) = release_result {
                run_err = join(run_err, release_err);
            }
            return Err(RestoreStepFailure {
                operation: checkpointed.map(Box::new),
                failure: run_err,
            });
        }
        if let Err(release_err) = release_result {
            return Err(RestoreStepFailure {
                operation: checkpointed.map(Box::new),
                failure: release_err,
            });
        }
        let Some(checkpointed) = checkpointed else {
            return Err(RestoreStepFailure::bare(Failure::internal(
                "restore_apply",
                "restore apply: protected operation binding mismatch",
            )));
        };
        let next = match checkpointed.mark_ready((self.now)()) {
            Ok(next) => next,
            Err(err) => {
                return Err(RestoreStepFailure::at(
                    checkpointed,
                    wrap("restore apply: mark ready", err),
                ));
            }
        };
        // Project ready before publishing it in the external journal.
        // A projection ahead of the journal remains blocked by the
        // external barrier; the inverse would let serve observe ready
        // without complete in-database evidence.
        if self.engine.project_restore_operation(&next).is_err() {
            return Err(RestoreStepFailure::at(
                checkpointed,
                resumable_failure(
                    "RESTORE_AUDIT_PROJECTION_FAILED",
                    "repair the recovery audit projection and resume the exact protected operation",
                ),
            ));
        }
        if let Err(err) = self.journal.compare_and_swap_restore(&checkpointed, &next) {
            return Err(RestoreStepFailure::at(
                checkpointed,
                wrap("restore apply: persist ready state", err),
            ));
        }
        Ok(next)
    }
}

/// `assertTargetExclusion`.
fn assert_target_exclusion(exclusion: &dyn RestoreTargetExclusion) -> Result<()> {
    if exclusion.assert_held().is_err() {
        return Err(resumable_failure(
            "RESTORE_TARGET_EXCLUSION_LOST",
            "reacquire the target-exclusive recovery lock and resume the exact protected operation",
        ));
    }
    Ok(())
}

/// `releaseTargetExclusion` — a failed release is itself a resumable
/// failure, never silently dropped.
fn release_target_exclusion(exclusion: &dyn RestoreTargetExclusion) -> Result<()> {
    if exclusion.release().is_err() {
        return Err(resumable_failure(
            "RESTORE_TARGET_EXCLUSION_RELEASE_FAILED",
            "reconcile the target lock and resume the exact protected operation before serving",
        ));
    }
    Ok(())
}

/// `quarantineRequiredFailure` — the `unresolved_quarantines` safe
/// detail folds into the message (the `Failure` vocabulary has no
/// detail map).
fn quarantine_required_failure(unresolved: u64) -> Failure {
    Failure::new(
        FailureKind::Denied,
        "RESTORE_QUARANTINE_RESOLUTION_REQUIRED",
        format!(
            "resolve every quarantined Artifact through re-ingest or delete-intent/finalization, then resume the exact operation (unresolved_quarantines: {unresolved})"
        ),
    )
}

// ---------------------------------------------------------------------------
// AuthorityResetCoordinator (authority_reset.go)
// ---------------------------------------------------------------------------

/// `app.AuthorityResetCoordinator` joins the broker and PostgreSQL
/// halves of C05 in the only legal order: protected draft, atomic
/// database reset/registration, exact broker activation, then
/// aggregate database evidence. The aggregate receipt comes back from
/// the finalizing port — it is never constructed here.
pub struct AuthorityResetCoordinator<'a> {
    /// Broker side of the reset.
    pub broker: &'a dyn BrokerAuthorityReset,
    /// PostgreSQL side of the reset (reset + finalize).
    pub database: &'a dyn PostgresAuthorityReset,
}

impl<'a> AuthorityResetCoordinator<'a> {
    /// `NewAuthorityResetCoordinator` — `nil` dependencies cannot
    /// arrive through references.
    pub fn new(
        broker: &'a dyn BrokerAuthorityReset,
        database: &'a dyn PostgresAuthorityReset,
    ) -> Self {
        Self { broker, database }
    }

    /// `ResetAuthority` — the operation must be `verifying` at
    /// `inventory_verified`; every stage's evidence is validated
    /// against the exact operation before the next runs.
    pub fn reset_authority(
        &self,
        operation: &RestoreOperation,
    ) -> Result<crate::recovery::operation::AuthorityResetReceipt> {
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Verifying
            || operation.last_checkpoint != RestoreCheckpoint::InventoryVerified
        {
            return Err(Failure::internal(
                "authority_reset",
                "recovery authority reset is unavailable",
            ));
        }
        let draft = self
            .broker
            .prepare_recovery_broker_authority(operation)
            .map_err(|_| {
                Failure::internal("authority_reset", "recovery broker authority reset failed")
            })?;
        if draft.validate_for(operation).is_err() {
            return Err(Failure::internal(
                "authority_reset",
                "recovery broker authority reset evidence is invalid",
            ));
        }
        let registration = self
            .database
            .reset_database_authority(operation, &draft)
            .map_err(|_| {
                Failure::internal(
                    "authority_reset",
                    "recovery database authority reset failed",
                )
            })?;
        if registration.validate_for(operation, &draft).is_err() {
            return Err(Failure::internal(
                "authority_reset",
                "recovery database authority reset failed",
            ));
        }
        let activation = self
            .broker
            .activate_recovery_bootstrap(operation, &registration)
            .map_err(|_| {
                Failure::internal("authority_reset", "recovery bootstrap activation failed")
            })?;
        if activation.validate_for(operation, &registration).is_err() {
            return Err(Failure::internal(
                "authority_reset",
                "recovery bootstrap activation failed",
            ));
        }
        let receipt = self
            .database
            .finalize_database_authority_reset(operation, &registration, &activation)
            .map_err(|_| {
                Failure::internal(
                    "authority_reset",
                    "recovery authority reset finalization failed",
                )
            })?;
        if receipt.validate_for(operation).is_err() {
            return Err(Failure::internal(
                "authority_reset",
                "recovery authority reset finalization failed",
            ));
        }
        Ok(receipt)
    }
}

// ---------------------------------------------------------------------------
// RestoreVerifier (restore_verifier.go)
// ---------------------------------------------------------------------------

/// `maximumRestoreTicketLifetime` — upstream pins 15 minutes.
pub const MAXIMUM_RESTORE_TICKET_LIFETIME: time::Duration = time::Duration::minutes(15);

/// `app.RestoreVerificationResult` — safe to publish to an operator
/// controller. It intentionally omits the protected ticket's HMAC and
/// hidden nonce.
#[derive(Debug, Clone)]
pub struct RestoreVerificationResult {
    /// Operation identity the ticket binds.
    pub operation_id: uuid::Uuid,
    /// Verified backup identity.
    pub backup_id: uuid::Uuid,
    /// `sha256:`-prefixed manifest digest.
    pub manifest_digest: String,
    /// Ticket expiry instant (UTC).
    pub expires_at: time::OffsetDateTime,
}

/// `app.RestoreVerifier` implements C03's non-mutating admission
/// path. The broker issues and stores the one-use ticket; this
/// service never hands its secret material to a transport or CLI
/// layer.
pub struct RestoreVerifier<'a> {
    /// `RecoveryRepositoryVerifier` — one full sealed-media walk.
    pub repository: &'a dyn RecoveryRepositoryVerifier,
    /// `BackupSealVerifier` — the broker's seal attestation.
    pub seals: &'a dyn BackupSealVerifier,
    /// `RestoreAdmissionInspector` — trusted admission facts.
    pub inspector: &'a dyn RestoreAdmissionInspector,
    /// `RestoreTicketIssuer` — the broker-owned ticket mint.
    pub issuer: &'a dyn RestoreTicketIssuer,
    /// Installed admission envelope.
    pub profile: crate::backup::capacity::RecoveryProfile,
    /// `verifier.now` — tests pin it for ticket-freshness checks.
    pub now: Box<dyn Fn() -> time::OffsetDateTime>,
}

impl<'a> RestoreVerifier<'a> {
    /// `NewRestoreVerifier` — `nil` dependencies cannot arrive through
    /// references; the clock defaults to the wall clock.
    pub fn new(
        repository: &'a dyn RecoveryRepositoryVerifier,
        seals: &'a dyn BackupSealVerifier,
        inspector: &'a dyn RestoreAdmissionInspector,
        issuer: &'a dyn RestoreTicketIssuer,
        profile: crate::backup::capacity::RecoveryProfile,
    ) -> Self {
        Self {
            repository,
            seals,
            inspector,
            issuer,
            profile,
            now: Box::new(time::OffsetDateTime::now_utc),
        }
    }

    /// `Verify` — confirms immutable backup evidence and current
    /// target facts before a broker records a ticket. It does not
    /// mutate the target database, recovery repository, Artifact
    /// lifecycle, or authority state.
    pub fn verify(&self, backup_id: uuid::Uuid) -> Result<RestoreVerificationResult> {
        if backup_id.is_nil() {
            return Err(RestoreRefusalReason::EngineUnavailable.into_failure());
        }
        if let Err(err) = self.profile.validate() {
            return Err(classify_restore_refusal(
                Some(&err),
                RestoreRefusalReason::EngineUnavailable,
            )
            .into_failure());
        }
        let verification = match self.repository.verify_backup(backup_id, &self.profile) {
            Ok(verification) => verification,
            Err(err) => {
                // The sealed recovery evidence itself could not be
                // read: a media-integrity refusal.
                return Err(classify_restore_refusal(
                    Some(&err),
                    RestoreRefusalReason::MediaInvalid,
                )
                .into_failure());
            }
        };
        if verification.backup_id != backup_id
            || verification.manifest_digest == [0u8; 32]
            || verification.seal_companion_digest == [0u8; 32]
            || verification.file_tree_digest == [0u8; 32]
            || verification.repository_manifest_digest == [0u8; 32]
            || verification.repository_revision == 0
        {
            return Err(RestoreRefusalReason::MediaInvalid.into_failure());
        }
        if let Err(err) = self.seals.verify_backup_seal(
            backup_id,
            verification.manifest_digest,
            verification.seal_companion_digest,
            verification.file_tree_digest,
            verification.repository_manifest_digest,
            verification.repository_revision,
        ) {
            // An unsealed or mismatched broker seal is the same
            // media-integrity class as a corrupt evidence file.
            return Err(
                classify_restore_refusal(Some(&err), RestoreRefusalReason::MediaInvalid)
                    .into_failure(),
            );
        }
        // The inspector receives the evidence this verify already
        // walked for rather than walking the same dump and artifact
        // bodies again; it must still re-establish the binding itself.
        let facts = match self
            .inspector
            .inspect_restore_admission(backup_id, &verification)
        {
            Ok(facts) => facts,
            Err(err) => {
                // The admission inspector is where capacity headroom
                // is judged; today its only production implementation
                // reports capacity-reserve authority unavailable for
                // every cause, so this bucket is accurate for the
                // interface as currently composed.
                return Err(classify_restore_refusal(
                    Some(&err),
                    RestoreRefusalReason::CapacityInsufficient,
                )
                .into_failure());
            }
        };
        if !valid_restore_admission_facts(&facts) {
            return Err(
                classify_restore_refusal(None, RestoreRefusalReason::CapacityInsufficient)
                    .into_failure(),
            );
        }
        let now = (self.now)();
        let manifest_digest = format!(
            "sha256:{}",
            crate::wire::hex_encode(&verification.manifest_digest)
        );
        let ticket =
            match self
                .issuer
                .issue_restore_ticket(backup_id, &manifest_digest, &facts, now)
            {
                Ok(ticket) => ticket,
                Err(err) => {
                    return Err(classify_restore_refusal(
                        Some(&err),
                        RestoreRefusalReason::StateInvalid,
                    )
                    .into_failure());
                }
            };
        if !ticket_matches(&ticket, backup_id, &manifest_digest, &facts, now) {
            // The issued ticket does not bind the exact facts just
            // verified: the protected authority state does not permit
            // this ticket to be published.
            return Err(RestoreRefusalReason::StateInvalid.into_failure());
        }
        Ok(RestoreVerificationResult {
            operation_id: ticket.operation_id,
            backup_id: ticket.backup_id,
            manifest_digest,
            expires_at: ticket.expires_at.to_offset(time::UtcOffset::UTC),
        })
    }
}

/// `validRestoreAdmissionFacts`.
fn valid_restore_admission_facts(facts: &RestoreAdmissionFacts) -> bool {
    facts.target.is_valid()
        && !facts.target_fingerprint.is_empty()
        && !facts.config_fingerprint.is_empty()
        && crate::wire::is_v7(facts.payload_epoch_id)
        && facts.database_schema_version == crate::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION
        && valid_restore_admission_digest(&facts.capacity_evidence_digest)
        && facts.tool_version == "pg_restore-16.14"
}

/// `ticketMatches` — the issued ticket must bind exactly the verified
/// facts, be unexpired, and live within the pinned lifetime.
fn ticket_matches(
    ticket: &RestoreTicket,
    backup_id: uuid::Uuid,
    manifest_digest: &str,
    facts: &RestoreAdmissionFacts,
    now: time::OffsetDateTime,
) -> bool {
    if ticket.is_expired_at(now)
        || ticket.expires_at - ticket.issued_at > MAXIMUM_RESTORE_TICKET_LIFETIME
    {
        return false;
    }
    if ticket.backup_id != backup_id
        || ticket.target != facts.target
        || ticket.target_fingerprint != facts.target_fingerprint
        || ticket.manifest_digest != manifest_digest
        || ticket.security_epoch != facts.security_epoch
        || ticket.restore_epoch != facts.restore_epoch
        || ticket.config_fingerprint != facts.config_fingerprint
        || ticket.payload_epoch_id != facts.payload_epoch_id
        || ticket.database_schema_version != facts.database_schema_version
        || ticket.capacity_evidence_digest != facts.capacity_evidence_digest
        || ticket.tool_version != facts.tool_version
    {
        return false;
    }
    !ticket.operation_id.is_nil() && !ticket.ticket_id.is_nil() && !ticket.hmac.is_empty()
}

/// `validRestoreAdmissionDigest` — `sha256:` + 64 lowercase hex whose
/// re-encoding round-trips.
fn valid_restore_admission_digest(value: &str) -> bool {
    crate::wire::valid_sha256_fingerprint(value)
}

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

// ---------------------------------------------------------------------------
// Coordinator matrices — upstream `backup_coordinator_test.go`,
// `restore_coordinator_test.go`, `restore_verifier_test.go`, and
// `authority_reset_test.go` over in-memory port fakes.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coordinator_tests {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::io::Read as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::backup::capacity::{
        BackupContinuitySnapshot, CapacitySnapshot, DeviceCapacitySnapshot,
        default_recovery_profile,
    };
    use crate::backup::inventory::InventoryEntry;
    use crate::backup::operation::{BACKUP_DATABASE_SCHEMA_VERSION, BackupAcceptedFacts};
    use crate::backup::operation::{new_backup_accepted_facts, new_backup_operation};
    use crate::domain::TargetIdentity;
    use crate::port::{
        BackupAdmissionSnapshot, ReadClose, ReadyArtifactPage, RecoveryVerificationEvidence,
        RestoreAdmissionFacts,
    };
    use crate::recovery::operation::{
        AuthorityResetReceipt, RESTORE_ABANDON_ACKNOWLEDGEMENT, RecoveryBootstrapActivation,
        RecoveryBootstrapDraft, RecoveryBootstrapRegistration, RestoreAbandonAuthorization,
        RestoreApplyAuthorization, RestoreTicket,
    };
    use crate::recovery::profile::{
        BACKUP_THROUGHPUT_CLEANUP_CLEAN, BACKUP_THROUGHPUT_RECEIPT_SCHEMA,
        BACKUP_TRANSFER_ENVELOPE_VERSION, ThroughputEvidence, ThroughputEvidenceBinding,
    };
    use crate::recovery::quarantine::{
        QuarantineFinding, QuarantineObservationSource, QuarantineReason,
    };
    use crate::repository::{BackupFileTreeEvidence, BackupSealCompanion, BackupSealPublication};
    use sha2::{Digest as _, Sha256};
    use time::macros::datetime;
    use uuid::Uuid;

    // ------------------------------------------------------------------
    // Shared fixtures
    // ------------------------------------------------------------------

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn fingerprint(value: &str) -> String {
        format!(
            "sha256:{}",
            crate::wire::hex_encode(&sha256(value.as_bytes()))
        )
    }

    fn digest_words(value: &str) -> String {
        fingerprint(value)
    }

    fn test_target() -> TargetIdentity {
        TargetIdentity {
            system_id: "system".into(),
            database_oid: "1".into(),
            database: "central".into(),
            config_hash: "sha256:config".into(),
            epoch: 7,
        }
    }

    /// `recoveryTestTicket`.
    fn recovery_test_ticket(now: time::OffsetDateTime) -> RestoreTicket {
        RestoreTicket {
            ticket_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            backup_id: Uuid::now_v7(),
            target: test_target(),
            target_fingerprint: "sha256:target".into(),
            manifest_digest: "sha256:manifest".into(),
            security_epoch: 11,
            restore_epoch: 4,
            config_fingerprint: "sha256:configuration".into(),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            capacity_evidence_digest:
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            tool_version: "pg_restore-16.14".into(),
            hidden_nonce: b"opaque-nonce".to_vec(),
            issued_at: now - time::Duration::seconds(1),
            expires_at: now + time::Duration::minutes(15),
            hmac: "broker-hmac".into(),
        }
    }

    /// `recoveryTestAuthorization`.
    fn recovery_test_authorization(ticket: &RestoreTicket) -> RestoreApplyAuthorization {
        RestoreApplyAuthorization {
            authorization_id: Uuid::now_v7(),
            operation_id: ticket.operation_id,
            ticket_id: ticket.ticket_id,
            issued_at: ticket.issued_at,
            expires_at: ticket.expires_at,
        }
    }

    /// `resumeTestAuthorization`.
    fn resume_test_authorization(operation: &RestoreOperation) -> RestoreApplyAuthorization {
        let now = time::OffsetDateTime::now_utc();
        RestoreApplyAuthorization {
            authorization_id: Uuid::now_v7(),
            operation_id: operation.operation_id,
            ticket_id: operation.ticket_id,
            issued_at: now - time::Duration::seconds(1),
            expires_at: now + time::Duration::minutes(1),
        }
    }

    /// `abandonTestAuthorization`.
    fn abandon_test_authorization(operation_id: Uuid) -> RestoreAbandonAuthorization {
        let now = time::OffsetDateTime::now_utc();
        RestoreAbandonAuthorization {
            authorization_id: Uuid::now_v7(),
            operation_id,
            issued_at: now - time::Duration::seconds(1),
            expires_at: now + time::Duration::minutes(2),
            acknowledgement: RESTORE_ABANDON_ACKNOWLEDGEMENT.into(),
        }
    }

    /// `acceptedBackupFacts`.
    fn accepted_backup_facts(at: time::OffsetDateTime) -> BackupAcceptedFacts {
        new_backup_accepted_facts(
            at,
            &fingerprint("target"),
            &fingerprint("config"),
            Uuid::now_v7(),
            Uuid::now_v7(),
            &fingerprint("lock-proof"),
        )
        .unwrap()
    }

    /// `coordinatorThroughputEvidence`.
    fn coordinator_throughput_evidence(at: time::OffsetDateTime) -> ThroughputEvidence {
        const DUMP_ELAPSED: i64 = 64;
        const OBJECT_ELAPSED: i64 = 96;
        let probe_elapsed = time::Duration::seconds(1 + DUMP_ELAPSED + OBJECT_ELAPSED);
        let archive = crate::backup::capacity::MINIMUM_DUMP_PROBE_ARCHIVE_BYTES;
        let object_payload = crate::backup::capacity::OBJECT_PROBE_PAYLOAD_BYTES;
        ThroughputEvidence {
            schema_version: BACKUP_THROUGHPUT_RECEIPT_SCHEMA.into(),
            receipt_id: Uuid::now_v7(),
            probe_operation_id: Uuid::now_v7(),
            probe_started_at: at - probe_elapsed,
            probe_completed_at: at,
            probe_elapsed,
            measured_at: at,
            expires_at: at + crate::backup::capacity::default_recovery_profile().throughput_max_age,
            binding: ThroughputEvidenceBinding {
                instance_id: Uuid::now_v7(),
                payload_epoch_id: Uuid::now_v7(),
                target_fingerprint: fingerprint("target"),
                repository_binding_id: Uuid::now_v7(),
                device_mount_set_digest: fingerprint("devices"),
                host_profile_digest: fingerprint("host"),
                dependency_provisioning_digest: fingerprint("provisioning"),
                postgres_image_digest: fingerprint("postgres"),
                minio_image_digest: fingerprint("minio"),
                pg_dump_tool_digest: fingerprint("pg_dump"),
                pg_dump_tool_version: "16.14".into(),
                config_digest: fingerprint("config"),
                minio_backup_policy_digest: fingerprint("policy"),
                fixture_digest: fingerprint("fixture"),
                transfer_envelope_version: BACKUP_TRANSFER_ENVELOPE_VERSION.into(),
                transfer_envelope_digest: fingerprint("envelope"),
            },
            dump_archive_bytes: archive,
            dump_work_bytes: archive * 2,
            dump_elapsed: time::Duration::seconds(DUMP_ELAPSED),
            fixture_load_elapsed: time::Duration::seconds(1),
            dump_bytes_per_sec: archive * 2 / DUMP_ELAPSED as u64,
            object_payload_bytes: object_payload,
            object_work_bytes: object_payload * 3,
            object_elapsed: time::Duration::seconds(OBJECT_ELAPSED),
            object_bytes_per_sec: object_payload * 3 / OBJECT_ELAPSED as u64,
            cleanup_state: BACKUP_THROUGHPUT_CLEANUP_CLEAN.into(),
            cleanup_verified_at: at,
        }
    }

    /// `io.NopCloser(bytes.NewReader(payload))` — a `ReadClose` whose
    /// close is observable.
    struct SliceReadClose {
        cursor: std::io::Cursor<Vec<u8>>,
        close_calls: Option<Arc<AtomicUsize>>,
        close_err: Option<Failure>,
    }

    impl std::io::Read for SliceReadClose {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.cursor.read(buf)
        }
    }

    impl ReadClose for SliceReadClose {
        fn close(self: Box<Self>) -> Result<()> {
            if let Some(calls) = &self.close_calls {
                calls.fetch_add(1, Ordering::SeqCst);
            }
            match self.close_err {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }
    }

    // ------------------------------------------------------------------
    // backupJournalFake
    // ------------------------------------------------------------------

    #[derive(Default)]
    struct BackupJournalFake {
        created: Mutex<bool>,
        current: Mutex<Option<BackupOperation>>,
        transitions: Mutex<Vec<BackupPhase>>,
        fail_phase: Mutex<Option<BackupPhase>>,
    }

    impl BackupJournalStore for BackupJournalFake {
        fn create_backup(&self, operation: &BackupOperation) -> Result<()> {
            let mut created = self.created.lock().unwrap();
            if *created || operation.phase != BackupPhase::Planned {
                return Err(Failure::conflict(
                    "backup_journal",
                    "journal create conflict",
                ));
            }
            *created = true;
            *self.current.lock().unwrap() = Some(operation.clone());
            Ok(())
        }

        fn read_backup(&self, operation_id: Uuid) -> Result<BackupOperation> {
            let current = self.current.lock().unwrap();
            match current.as_ref() {
                Some(op) if *self.created.lock().unwrap() && op.operation_id == operation_id => {
                    Ok(op.clone())
                }
                _ => Err(Failure::conflict("backup_journal", "journal read conflict")),
            }
        }

        fn compare_and_swap_backup(
            &self,
            expected: &BackupOperation,
            next: &BackupOperation,
        ) -> Result<()> {
            let mut current = self.current.lock().unwrap();
            if !*self.created.lock().unwrap() || current.as_ref() != Some(expected) {
                return Err(Failure::conflict(
                    "backup_journal",
                    "journal compare and swap conflict",
                ));
            }
            if self
                .fail_phase
                .lock()
                .unwrap()
                .is_some_and(|p| p == next.phase)
            {
                return Err(Failure::internal(
                    "backup_journal",
                    "journal write unavailable",
                ));
            }
            *current = Some(next.clone());
            self.transitions.lock().unwrap().push(next.phase);
            Ok(())
        }
    }

    // ------------------------------------------------------------------
    // backupEnvironmentFake
    // ------------------------------------------------------------------

    struct BackupEnvironmentFake {
        facts: BackupAcceptedFacts,
        capacity: CapacitySnapshot,
        throughput: Mutex<ThroughputEvidence>,
        fail_after_continuations: Mutex<usize>,
        continuations: Mutex<usize>,
        bytes_since_last_guard: Mutex<u64>,
    }

    impl BackupEnvironmentProbe for BackupEnvironmentFake {
        fn admission_snapshot(
            &self,
            _operation: &BackupOperation,
        ) -> Result<BackupAdmissionSnapshot> {
            Ok(BackupAdmissionSnapshot {
                facts: self.facts.clone(),
                capacity: self.capacity.clone(),
                throughput: self.throughput.lock().unwrap().clone(),
                target_lock_held: true,
                authority_receipt_held: true,
            })
        }

        fn continuation_snapshot(
            &self,
            _operation: &BackupOperation,
        ) -> Result<BackupContinuitySnapshot> {
            let mut continuations = self.continuations.lock().unwrap();
            *continuations += 1;
            let fail_after = *self.fail_after_continuations.lock().unwrap();
            Ok(BackupContinuitySnapshot {
                capacity: self.capacity.clone(),
                target_lock_held: fail_after == 0 || *continuations < fail_after,
                authority_receipt_held: true,
                bytes_since_last_guard: *self.bytes_since_last_guard.lock().unwrap(),
            })
        }
    }

    // ------------------------------------------------------------------
    // backupRepositoryFake
    // ------------------------------------------------------------------

    #[derive(Default)]
    struct BackupRepositoryFake {
        bound: Mutex<Option<BackupOperation>>,
        dump: Mutex<Option<DumpEvidence>>,
        partial_dump: Mutex<Vec<u8>>,
        bodies: Mutex<BTreeMap<Uuid, Vec<u8>>>,
        chunks: Mutex<Vec<InventoryChunk>>,
        manifest: Mutex<Option<crate::backup::manifest::SealRootManifest>>,
        companion: Mutex<Option<BackupSealCompanion>>,
    }

    impl RecoveryRepositoryStore for BackupRepositoryFake {
        fn bind_backup(&self, operation: &BackupOperation) -> Result<()> {
            // `backup.NewBackupBinding` — the bound shape check.
            if operation.validate().is_err()
                || operation.phase == BackupPhase::Planned
                || operation.accepted_facts.validate().is_err()
            {
                return Err(Failure::invalid(
                    "backup_recovery",
                    "invalid recovery backup binding",
                ));
            }
            *self.bound.lock().unwrap() = Some(operation.clone());
            Ok(())
        }

        fn write_dump(
            &self,
            _backup_id: Uuid,
            source: &mut dyn std::io::Read,
            maximum_size: i64,
        ) -> Result<DumpEvidence> {
            let mut payload = Vec::new();
            let read_result = source
                .take((maximum_size + 1) as u64)
                .read_to_end(&mut payload);
            *self.partial_dump.lock().unwrap() = payload.clone();
            if read_result.is_err() || payload.len() as i64 > maximum_size {
                return Err(Failure::internal("backup_repository", "dump write failed"));
            }
            let evidence = DumpEvidence {
                size: payload.len() as i64,
                digest: sha256(&payload),
            };
            *self.dump.lock().unwrap() = Some(evidence);
            Ok(evidence)
        }

        fn write_artifact_body(
            &self,
            _backup_id: Uuid,
            entry: &InventoryEntry,
            source: &mut dyn std::io::Read,
        ) -> Result<()> {
            let mut payload = Vec::new();
            source
                .read_to_end(&mut payload)
                .map_err(|_| Failure::internal("backup_repository", "body write failed"))?;
            if payload.len() as i64 != entry.size || sha256(&payload) != entry.checksum {
                return Err(Failure::internal(
                    ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH,
                    "backup artifact evidence mismatch",
                ));
            }
            self.bodies
                .lock()
                .unwrap()
                .insert(entry.artifact_id, payload);
            Ok(())
        }

        fn write_chunk(&self, _backup_id: Uuid, chunk: &InventoryChunk) -> Result<()> {
            self.chunks.lock().unwrap().push(chunk.clone());
            Ok(())
        }

        fn write_manifest(
            &self,
            manifest: &crate::backup::manifest::SealRootManifest,
        ) -> Result<BackupFileTreeEvidence> {
            *self.manifest.lock().unwrap() = Some(manifest.clone());
            let payload = manifest.canonical_json()?;
            let mut tree = b"file-tree|".to_vec();
            tree.extend_from_slice(&payload);
            Ok(BackupFileTreeEvidence {
                digest: sha256(&tree),
            })
        }

        fn write_seal_companion(
            &self,
            _backup_id: Uuid,
            companion: &BackupSealCompanion,
        ) -> Result<BackupSealPublication> {
            companion.verify()?;
            if companion.root_manifest_digest
                != self
                    .manifest
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|m| m.digest)
                    .unwrap_or([0u8; 32])
            {
                return Err(Failure::invalid("backup_repository", "invalid companion"));
            }
            *self.companion.lock().unwrap() = Some(companion.clone());
            Ok(BackupSealPublication {
                operation_id: companion.operation_id,
                backup_id: companion.backup_id,
                repository_binding_id: companion.repository_binding_id,
                root_manifest_digest: companion.root_manifest_digest,
                seal_companion_digest: companion.digest,
                file_tree_digest: companion.file_tree_digest,
                repository_manifest_digest: sha256(b"repository manifest"),
                repository_revision: 1,
            })
        }

        fn read_inventory_chunk(&self, _backup_id: Uuid, ordinal: u32) -> Result<InventoryChunk> {
            self.chunks
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.ordinal == ordinal)
                .cloned()
                .ok_or_else(|| Failure::not_found("backup_repository", "chunk absent"))
        }

        fn read_seal_root(&self, _backup_id: Uuid) -> Result<Vec<u8>> {
            self.manifest
                .lock()
                .unwrap()
                .as_ref()
                .ok_or_else(|| Failure::not_found("backup_repository", "manifest absent"))?
                .canonical_json()
        }
    }

    // ------------------------------------------------------------------
    // backupDumperFake / backupArtifactSourceFake / backupSealerFake
    // ------------------------------------------------------------------

    struct BackupDumperFake {
        payload: Vec<u8>,
        calls: Mutex<usize>,
    }

    impl BackupDumper for BackupDumperFake {
        fn start_dump(&self, _operation: &BackupOperation) -> Result<Box<dyn ReadClose>> {
            *self.calls.lock().unwrap() += 1;
            Ok(Box::new(SliceReadClose {
                cursor: std::io::Cursor::new(self.payload.clone()),
                close_calls: None,
                close_err: None,
            }))
        }
    }

    #[derive(Default)]
    struct BackupArtifactSourceFake {
        entries: Mutex<Vec<InventoryEntry>>,
        bodies: Mutex<BTreeMap<Uuid, Vec<u8>>>,
        attempt_bodies: Mutex<BTreeMap<Uuid, VecDeque<Vec<u8>>>>,
        opens: Mutex<usize>,
        list_calls: Mutex<usize>,
        open_err: Mutex<Option<Failure>>,
    }

    impl ReadyArtifactSource for BackupArtifactSourceFake {
        fn list_ready_artifacts(
            &self,
            _operation: &BackupOperation,
            after: ReadyArtifactCursor,
            maximum_entries: usize,
        ) -> Result<ReadyArtifactPage> {
            *self.list_calls.lock().unwrap() += 1;
            if maximum_entries == 0 || maximum_entries > MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES {
                return Err(Failure::invalid("backup_inventory", "invalid page limit"));
            }
            let entries = self.entries.lock().unwrap();
            let mut canonical = entries.clone();
            canonical.sort_by_key(|entry| entry.artifact_id.to_string());
            let mut start = 0usize;
            while start < canonical.len()
                && !after.artifact_id.is_nil()
                && canonical[start].artifact_id.to_string() <= after.artifact_id.to_string()
            {
                start += 1;
            }
            let end = (start + maximum_entries).min(canonical.len());
            let page_entries = canonical[start..end].to_vec();
            let complete = end == canonical.len();
            let mut page = ReadyArtifactPage {
                entries: page_entries,
                next_cursor: ReadyArtifactCursor::default(),
                complete,
            };
            if !complete {
                page.next_cursor.artifact_id = page.entries[page.entries.len() - 1].artifact_id;
            }
            Ok(page)
        }

        fn open_ready_artifact(
            &self,
            _operation: &BackupOperation,
            entry: &InventoryEntry,
        ) -> Result<Box<dyn ReadClose>> {
            *self.opens.lock().unwrap() += 1;
            if let Some(err) = self.open_err.lock().unwrap().clone() {
                return Err(err);
            }
            if let Some(attempts) = self
                .attempt_bodies
                .lock()
                .unwrap()
                .get_mut(&entry.artifact_id)
                && let Some(payload) = attempts.pop_front()
            {
                return Ok(Box::new(SliceReadClose {
                    cursor: std::io::Cursor::new(payload),
                    close_calls: None,
                    close_err: None,
                }));
            }
            match self.bodies.lock().unwrap().get(&entry.artifact_id) {
                Some(payload) => Ok(Box::new(SliceReadClose {
                    cursor: std::io::Cursor::new(payload.clone()),
                    close_calls: None,
                    close_err: None,
                })),
                None => Err(Failure::not_found("backup_artifact", "body absent")),
            }
        }
    }

    #[derive(Default)]
    struct BackupSealerFake {
        calls: Mutex<usize>,
        proposal: Mutex<Option<BackupSealProposal>>,
        err: Mutex<Option<Failure>>,
    }

    impl BackupSealer for BackupSealerFake {
        fn seal_backup(&self, proposal: &BackupSealProposal) -> Result<BackupSealCompanion> {
            *self.calls.lock().unwrap() += 1;
            *self.proposal.lock().unwrap() = Some(proposal.clone());
            if let Some(err) = self.err.lock().unwrap().clone() {
                return Err(err);
            }
            let envelope = sha256(b"test authority envelope");
            let hmac = sha256(b"test companion hmac");
            let mut companion = BackupSealCompanion {
                authority_envelope_id: format!("sha256:{}", crate::wire::hex_encode(&envelope)),
                backup_id: proposal.backup_id,
                operation_id: proposal.operation_id,
                repository_binding_id: proposal.repository_binding_id,
                target_fingerprint: proposal.target_fingerprint.clone(),
                config_fingerprint: proposal.config_fingerprint.clone(),
                payload_epoch_id: proposal.payload_epoch_id,
                root_manifest_digest: proposal.manifest_digest,
                file_tree_digest: proposal.file_tree_digest,
                sealed_at: proposal.proposed_at,
                hmac: crate::wire::hex_encode(&hmac),
                digest: [0u8; 32],
            };
            companion.digest = sha256(&companion.canonical_json()?);
            Ok(companion)
        }
    }

    /// `newBackupCoordinatorFixture`.
    struct BackupFixture {
        coordinator: BackupCoordinator<'static>,
        journal: &'static BackupJournalFake,
        environment: &'static BackupEnvironmentFake,
        repository: &'static BackupRepositoryFake,
        dumper: &'static BackupDumperFake,
        sealer: &'static BackupSealerFake,
        source: &'static BackupArtifactSourceFake,
        operation: BackupOperation,
        profile: crate::backup::capacity::RecoveryProfile,
    }

    fn new_backup_coordinator_fixture() -> BackupFixture {
        let now = datetime!(2026-08-09 12:00:00 UTC);
        let profile = default_recovery_profile();
        let operation =
            new_backup_operation(Uuid::now_v7(), Uuid::now_v7(), test_target(), now).unwrap();
        let first_id = Uuid::now_v7();
        let second_id = Uuid::now_v7();
        let first_body = b"first body".to_vec();
        let second_body = b"second body".to_vec();
        let entries = vec![
            InventoryEntry {
                artifact_id: second_id,
                checksum: sha256(&second_body),
                size: second_body.len() as i64,
            },
            InventoryEntry {
                artifact_id: first_id,
                checksum: sha256(&first_body),
                size: first_body.len() as i64,
            },
        ];
        let environment = Box::leak(Box::new(BackupEnvironmentFake {
            facts: accepted_backup_facts(now),
            capacity: CapacitySnapshot {
                devices: vec![DeviceCapacitySnapshot {
                    device_id: "recovery-device".into(),
                    free_bytes: profile.survival_reserve + profile.free_floor + 1,
                }],
                ..Default::default()
            },
            throughput: Mutex::new(coordinator_throughput_evidence(now)),
            fail_after_continuations: Mutex::new(0),
            continuations: Mutex::new(0),
            bytes_since_last_guard: Mutex::new(0),
        }));
        let journal = Box::leak(Box::new(BackupJournalFake::default()));
        let repository = Box::leak(Box::new(BackupRepositoryFake::default()));
        let dumper = Box::leak(Box::new(BackupDumperFake {
            payload: b"pg_dump evidence".to_vec(),
            calls: Mutex::new(0),
        }));
        let sealer = Box::leak(Box::new(BackupSealerFake::default()));
        let source = Box::leak(Box::new(BackupArtifactSourceFake {
            entries: Mutex::new(entries),
            bodies: Mutex::new(
                [(first_id, first_body), (second_id, second_body)]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        }));
        let mut coordinator = BackupCoordinator::new(
            journal,
            environment,
            repository,
            source,
            dumper,
            sealer,
            profile,
        );
        coordinator.now = Box::new(move || now);
        BackupFixture {
            coordinator,
            journal,
            environment,
            repository,
            dumper,
            sealer,
            source,
            operation,
            profile,
        }
    }

    // ------------------------------------------------------------------
    // backup_coordinator_test.go matrix
    // ------------------------------------------------------------------

    #[test]
    fn backup_publishes_evidence_without_terminalizing_seal() {
        let fixture = new_backup_coordinator_fixture();
        let result = fixture.coordinator.run(fixture.operation.clone()).unwrap();
        assert_eq!(result.operation.phase, BackupPhase::Sealing);
        assert_eq!(
            fixture
                .journal
                .current
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .phase,
            BackupPhase::Sealing
        );
        assert_eq!(*fixture.sealer.calls.lock().unwrap(), 1);
        let proposal = fixture.sealer.proposal.lock().unwrap().clone().unwrap();
        let manifest = result.manifest.as_ref().unwrap();
        assert_eq!(proposal.backup_id, fixture.operation.backup_id);
        assert_eq!(proposal.manifest_digest, manifest.digest);
        assert_eq!(fixture.repository.bodies.lock().unwrap().len(), 2);
        assert_eq!(fixture.repository.chunks.lock().unwrap().len(), 1);
        assert_eq!(
            fixture
                .repository
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .digest,
            manifest.digest
        );
        let companion = fixture
            .repository
            .companion
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        companion.verify().unwrap();
        assert_eq!(companion.root_manifest_digest, manifest.digest);
        assert!(result.publication.as_ref().unwrap().binds(&companion));
        assert_eq!(fixture.journal.transitions.lock().unwrap().len(), 4);
    }

    #[test]
    fn backup_rejects_before_persisting_when_admission_evidence_is_invalid() {
        let fixture = new_backup_coordinator_fixture();
        let low = fixture.profile.min_throughput_bps - 1;
        fixture
            .environment
            .throughput
            .lock()
            .unwrap()
            .dump_bytes_per_sec = low;
        fixture
            .coordinator
            .run(fixture.operation.clone())
            .unwrap_err();
        assert!(!*fixture.journal.created.lock().unwrap());
        assert_eq!(*fixture.dumper.calls.lock().unwrap(), 0);
        assert_eq!(*fixture.sealer.calls.lock().unwrap(), 0);
    }

    #[test]
    fn backup_fails_and_preserves_unsealed_evidence_after_continuity_loss() {
        let mut fixture = new_backup_coordinator_fixture();
        fixture.coordinator.profile.write_quantum = 4;
        *fixture.environment.fail_after_continuations.lock().unwrap() = 4;
        let step = fixture
            .coordinator
            .run(fixture.operation.clone())
            .unwrap_err();
        assert_eq!(step.failure.kind(), FailureKind::Internal);
        assert_eq!(step.result.operation.phase, BackupPhase::Failed);
        assert_eq!(
            fixture
                .journal
                .current
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .phase,
            BackupPhase::Failed
        );
        assert_eq!(*fixture.sealer.calls.lock().unwrap(), 0);
        assert!(!fixture.repository.partial_dump.lock().unwrap().is_empty());
    }

    #[test]
    fn backup_guard_preserves_repository_growth_measurement() {
        let fixture = new_backup_coordinator_fixture();
        let mut profile = fixture.profile;
        profile.write_quantum = 4;
        *fixture.environment.bytes_since_last_guard.lock().unwrap() = profile.write_quantum + 1;
        let mut coordinator = BackupCoordinator::new(
            fixture.journal,
            fixture.environment,
            fixture.repository,
            fixture.source,
            fixture.dumper,
            fixture.sealer,
            profile,
        );
        let pinned = fixture.coordinator.now;
        coordinator.now = pinned;
        let operation = fixture
            .operation
            .accept(fixture.environment.facts.clone())
            .unwrap();
        let err = coordinator.guard(&operation, 0).unwrap_err();
        assert_eq!(err.code(), "WRITE_QUANTUM_EXCEEDED");
    }

    #[test]
    fn backup_leaves_manifest_unsealed_when_broker_seal_fails() {
        let fixture = new_backup_coordinator_fixture();
        *fixture.sealer.err.lock().unwrap() =
            Some(Failure::internal("broker", "broker unavailable"));
        let step = fixture
            .coordinator
            .run(fixture.operation.clone())
            .unwrap_err();
        assert_eq!(step.result.operation.phase, BackupPhase::Failed);
        assert_eq!(
            fixture
                .journal
                .current
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .phase,
            BackupPhase::Failed
        );
        assert_eq!(*fixture.sealer.calls.lock().unwrap(), 1);
        assert_ne!(
            fixture
                .repository
                .manifest
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .digest,
            [0u8; 32]
        );
    }

    #[test]
    fn backup_seals_dump_only_backup() {
        let fixture = new_backup_coordinator_fixture();
        let source = Box::leak(Box::new(BackupArtifactSourceFake::default()));
        let mut coordinator = BackupCoordinator::new(
            fixture.journal,
            fixture.environment,
            fixture.repository,
            source,
            fixture.dumper,
            fixture.sealer,
            fixture.profile,
        );
        let pinned = fixture.coordinator.now;
        coordinator.now = pinned;
        let result = coordinator.run(fixture.operation.clone()).unwrap();
        assert_eq!(result.operation.phase, BackupPhase::Sealing);
        assert!(result.manifest.as_ref().unwrap().chunks.is_empty());
        assert!(fixture.repository.bodies.lock().unwrap().is_empty());
        assert_eq!(*fixture.sealer.calls.lock().unwrap(), 1);
    }

    #[test]
    fn backup_rejects_invalid_inventory_before_reading_any_body() {
        let fixture = new_backup_coordinator_fixture();
        {
            let mut entries = fixture.source.entries.lock().unwrap();
            let dup = entries[0];
            entries.push(dup);
        }
        let step = fixture
            .coordinator
            .run(fixture.operation.clone())
            .unwrap_err();
        assert_eq!(step.result.operation.phase, BackupPhase::Failed);
        assert_eq!(*fixture.source.opens.lock().unwrap(), 0);
        assert!(fixture.repository.bodies.lock().unwrap().is_empty());
    }

    #[test]
    fn backup_retries_body_at_most_three_times() {
        let fixture = new_backup_coordinator_fixture();
        let (entry, correct) = {
            let entries = fixture.source.entries.lock().unwrap();
            let entry = if entries[1].artifact_id.to_string() < entries[0].artifact_id.to_string() {
                entries[1]
            } else {
                entries[0]
            };
            let correct = fixture
                .source
                .bodies
                .lock()
                .unwrap()
                .get(&entry.artifact_id)
                .unwrap()
                .clone();
            (entry, correct)
        };
        fixture.source.attempt_bodies.lock().unwrap().insert(
            entry.artifact_id,
            VecDeque::from(vec![
                b"wrong body".to_vec(),
                b"still wrong".to_vec(),
                correct,
            ]),
        );
        let result = fixture.coordinator.run(fixture.operation.clone()).unwrap();
        assert_eq!(result.operation.phase, BackupPhase::Sealing);
        assert_eq!(*fixture.source.opens.lock().unwrap(), 4);

        let failed = new_backup_coordinator_fixture();
        let failed_entry = {
            let entries = failed.source.entries.lock().unwrap();
            if entries[1].artifact_id.to_string() < entries[0].artifact_id.to_string() {
                entries[1]
            } else {
                entries[0]
            }
        };
        let correct = failed
            .source
            .bodies
            .lock()
            .unwrap()
            .get(&failed_entry.artifact_id)
            .unwrap()
            .clone();
        failed.source.attempt_bodies.lock().unwrap().insert(
            failed_entry.artifact_id,
            VecDeque::from(vec![
                b"bad-one".to_vec(),
                b"bad-two".to_vec(),
                b"bad-three".to_vec(),
                correct,
            ]),
        );
        let step = failed
            .coordinator
            .run(failed.operation.clone())
            .unwrap_err();
        assert_eq!(step.result.operation.phase, BackupPhase::Failed);
        assert_eq!(*failed.source.opens.lock().unwrap(), 3);
        assert_eq!(*failed.sealer.calls.lock().unwrap(), 0);
        assert_eq!(
            step.failure.code(),
            crate::backup::operation::backup_failure::CORRUPTED_UNRECOVERABLE_BODY
        );
        assert_eq!(
            step.result.operation.failure_reason,
            crate::backup::operation::backup_failure::CORRUPTED_UNRECOVERABLE_BODY
        );
        assert_eq!(
            failed
                .journal
                .current
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .failure_reason,
            crate::backup::operation::backup_failure::CORRUPTED_UNRECOVERABLE_BODY
        );
    }

    #[test]
    fn backup_does_not_misclassify_transport_failure_as_corruption() {
        let fixture = new_backup_coordinator_fixture();
        *fixture.source.open_err.lock().unwrap() = Some(Failure::internal(
            "artifact",
            "object transport unavailable",
        ));
        let step = fixture
            .coordinator
            .run(fixture.operation.clone())
            .unwrap_err();
        assert_eq!(
            step.failure.code(),
            crate::backup::operation::backup_failure::INVENTORY_WRITE
        );
        assert_eq!(
            step.result.operation.failure_reason,
            crate::backup::operation::backup_failure::INVENTORY_WRITE
        );
        assert_eq!(*fixture.source.opens.lock().unwrap(), 3);
    }

    #[test]
    fn backup_seeks_inventory_in_bounded_chunk_pages() {
        let fixture = new_backup_coordinator_fixture();
        let source = Box::leak(Box::new(BackupArtifactSourceFake::default()));
        {
            let mut entries = source.entries.lock().unwrap();
            let mut bodies = source.bodies.lock().unwrap();
            for _ in 0..MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES + 1 {
                let id = Uuid::now_v7();
                let body = id.to_string().into_bytes();
                entries.push(InventoryEntry {
                    artifact_id: id,
                    checksum: sha256(&body),
                    size: body.len() as i64,
                });
                bodies.insert(id, body);
            }
        }
        let mut coordinator = BackupCoordinator::new(
            fixture.journal,
            fixture.environment,
            fixture.repository,
            source,
            fixture.dumper,
            fixture.sealer,
            fixture.profile,
        );
        let pinned = fixture.coordinator.now;
        coordinator.now = pinned;
        let result = coordinator.run(fixture.operation.clone()).unwrap();
        let manifest = result.manifest.unwrap();
        assert_eq!(result.operation.phase, BackupPhase::Sealing);
        assert_eq!(*source.list_calls.lock().unwrap(), 2);
        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(
            manifest.chunks[0].entries.len(),
            MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES
        );
        assert_eq!(manifest.chunks[1].entries.len(), 1);
    }

    // ------------------------------------------------------------------
    // recoveryJournalFake / recoveryEngineFake
    // ------------------------------------------------------------------

    /// Test hook applied to the resumed record (upstream mutates
    /// the journal row directly).
    type OperationEdit = Box<dyn Fn(&mut RestoreOperation) + Send>;

    #[derive(Default)]
    struct RecoveryJournalFake {
        operations: Mutex<BTreeMap<Uuid, RestoreOperation>>,
        consumed: Mutex<BTreeSet<Uuid>>,
        authorized: Mutex<BTreeSet<Uuid>>,
        resume_edit: Mutex<Option<OperationEdit>>,
    }

    impl RestoreJournalStore for RecoveryJournalFake {
        fn begin_restore(
            &self,
            ticket: &RestoreTicket,
            authorization: &RestoreApplyAuthorization,
            at: time::OffsetDateTime,
        ) -> Result<RestoreOperation> {
            if !authorization.valid_at(at) || !authorization.binds(ticket) {
                return Err(Failure::invalid(
                    "restore_journal",
                    "fresh authorization required",
                ));
            }
            let mut consumed = self.consumed.lock().unwrap();
            if consumed.contains(&ticket.ticket_id) {
                return Err(Failure::invalid(
                    "restore_journal",
                    "ticket already consumed",
                ));
            }
            let operation = new_restore_operation(ticket, at)?;
            consumed.insert(ticket.ticket_id);
            self.operations
                .lock()
                .unwrap()
                .insert(operation.operation_id, operation.clone());
            Ok(operation)
        }

        fn read_restore(&self, operation_id: Uuid) -> Result<RestoreOperation> {
            self.operations
                .lock()
                .unwrap()
                .get(&operation_id)
                .cloned()
                .ok_or_else(|| Failure::not_found("restore_journal", "operation absent"))
        }

        fn resume_restore(
            &self,
            operation_id: Uuid,
            authorization: &RestoreApplyAuthorization,
            at: time::OffsetDateTime,
        ) -> Result<RestoreOperation> {
            let operations = self.operations.lock().unwrap();
            let mut authorized = self.authorized.lock().unwrap();
            let Some(mut op) = operations.get(&operation_id).cloned() else {
                return Err(Failure::invalid(
                    "restore_journal",
                    "fresh resume authorization required",
                ));
            };
            if !op.is_resumable()
                || !authorization.valid_at(at)
                || authorization.operation_id != operation_id
                || authorization.ticket_id != op.ticket_id
                || authorized.contains(&authorization.authorization_id)
            {
                return Err(Failure::invalid(
                    "restore_journal",
                    "fresh resume authorization required",
                ));
            }
            authorized.insert(authorization.authorization_id);
            drop(authorized);
            drop(operations);
            if let Some(edit) = self.resume_edit.lock().unwrap().as_ref() {
                edit(&mut op);
            }
            Ok(op)
        }

        fn abandon_restore(
            &self,
            operation_id: Uuid,
            authorization: &RestoreAbandonAuthorization,
            at: time::OffsetDateTime,
        ) -> Result<RestoreOperation> {
            let mut operations = self.operations.lock().unwrap();
            let mut authorized = self.authorized.lock().unwrap();
            let Some(op) = operations.get(&operation_id).cloned() else {
                return Err(Failure::invalid(
                    "restore_journal",
                    "fresh abandon authorization required",
                ));
            };
            if !authorization.valid_at(at)
                || authorization.operation_id != operation_id
                || authorized.contains(&authorization.authorization_id)
            {
                return Err(Failure::invalid(
                    "restore_journal",
                    "fresh abandon authorization required",
                ));
            }
            let abandoned = op.abandon(authorization, at)?;
            authorized.insert(authorization.authorization_id);
            operations.insert(operation_id, abandoned.clone());
            Ok(abandoned)
        }

        fn compare_and_swap_restore(
            &self,
            expected: &RestoreOperation,
            next: &RestoreOperation,
        ) -> Result<()> {
            let mut operations = self.operations.lock().unwrap();
            match operations.get(&expected.operation_id) {
                Some(current)
                    if current == expected && expected.validate_transition_to(next).is_ok() =>
                {
                    operations.insert(expected.operation_id, next.clone());
                    Ok(())
                }
                _ => Err(Failure::conflict(
                    "restore_journal",
                    "stale protected record",
                )),
            }
        }
    }

    /// `restoreTargetExclusionFake` — the Arc lets tests preset and
    /// inspect the same exclusion the coordinator holds.
    #[derive(Default)]
    struct TargetExclusionFake {
        assert_err: Mutex<Option<Failure>>,
        release_err: Mutex<Option<Failure>>,
        assert_calls: AtomicUsize,
        release_calls: AtomicUsize,
    }

    struct ExclusionHandle(Arc<TargetExclusionFake>);

    impl RestoreTargetExclusion for ExclusionHandle {
        fn assert_held(&self) -> Result<()> {
            self.0.assert_calls.fetch_add(1, Ordering::SeqCst);
            match self.0.assert_err.lock().unwrap().clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        fn release(&self) -> Result<()> {
            self.0.release_calls.fetch_add(1, Ordering::SeqCst);
            match self.0.release_err.lock().unwrap().clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }
    }

    #[derive(Default)]
    struct RecoveryEngineFake {
        restore_err: Mutex<Option<Failure>>,
        verify_err: Mutex<Option<Failure>>,
        projection_quarantine_err: Mutex<Option<Failure>>,
        reset_err: Mutex<Option<Failure>>,
        projection_err: Mutex<Option<Failure>>,
        inventory_count: Mutex<u64>,
        restore_calls: AtomicUsize,
        verify_calls: AtomicUsize,
        quarantine_projection_calls: AtomicUsize,
        reset_calls: AtomicUsize,
        projection_calls: AtomicUsize,
        exclusion: Mutex<Option<Arc<TargetExclusionFake>>>,
        exclusion_err: Mutex<Option<Failure>>,
        exclusion_op: Mutex<Option<RestoreOperation>>,
    }

    impl RestoreEngine for RecoveryEngineFake {
        fn acquire_restore_target_exclusion(
            &self,
            operation: &RestoreOperation,
        ) -> Result<Box<dyn RestoreTargetExclusion>> {
            *self.exclusion_op.lock().unwrap() = Some(operation.clone());
            if let Some(err) = self.exclusion_err.lock().unwrap().clone() {
                return Err(err);
            }
            let mut exclusion = self.exclusion.lock().unwrap();
            if exclusion.is_none() {
                *exclusion = Some(Arc::new(TargetExclusionFake::default()));
            }
            Ok(Box::new(ExclusionHandle(
                exclusion.as_ref().unwrap().clone(),
            )))
        }

        fn restore_database(&self, _operation: &RestoreOperation) -> Result<()> {
            self.restore_calls.fetch_add(1, Ordering::SeqCst);
            match self.restore_err.lock().unwrap().clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        fn project_restore_operation(&self, _operation: &RestoreOperation) -> Result<()> {
            self.projection_calls.fetch_add(1, Ordering::SeqCst);
            match self.projection_err.lock().unwrap().clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }

        fn verify_inventory(&self, operation: &RestoreOperation) -> Result<Vec<QuarantineFinding>> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.verify_err.lock().unwrap().clone() {
                return Err(err);
            }
            let count = *self.inventory_count.lock().unwrap();
            Ok((0..count)
                .map(|index| {
                    let mut checksum = [0u8; 32];
                    checksum[0] = (index + 1) as u8;
                    QuarantineFinding {
                        quarantine_id: Uuid::now_v7(),
                        operation_id: operation.operation_id,
                        artifact_id: Uuid::now_v7(),
                        reason: QuarantineReason::MissingBody,
                        observation_source: QuarantineObservationSource::ObjectPresence,
                        expected_checksum: Some(checksum),
                        observed_checksum: None,
                        expected_size: Some(index as i64 + 1),
                        observed_size: None,
                        created_at: operation.updated_at,
                    }
                })
                .collect())
        }

        fn record_quarantine_findings(
            &self,
            _operation: &RestoreOperation,
            findings: &[QuarantineFinding],
        ) -> Result<u64> {
            self.quarantine_projection_calls
                .fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.projection_quarantine_err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(findings.len() as u64)
        }

        fn unresolved_quarantine_count(&self, _operation: &RestoreOperation) -> Result<u64> {
            Ok(0)
        }

        fn reset_authority(&self, operation: &RestoreOperation) -> Result<AuthorityResetReceipt> {
            self.reset_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.reset_err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(AuthorityResetReceipt {
                operation_id: operation.operation_id,
                previous_restore_epoch: operation.restore_epoch - 1,
                new_restore_epoch: operation.restore_epoch,
                previous_security_epoch: operation.security_epoch,
                new_security_epoch: operation.security_epoch + 1,
                broker_receipt_hash: "sha256:broker-receipt".into(),
                database_receipt_hash: "sha256:database-receipt".into(),
                bootstrap_candidate_id: Uuid::now_v7(),
                bootstrap_generation: 7,
                bootstrap_activation_receipt_hash: "sha256:bootstrap-activation".into(),
                aggregate_receipt_hash: "sha256:reset-receipt".into(),
                completed_at: operation.updated_at,
            })
        }
    }

    fn restore_coordinator<'a>(
        journal: &'a RecoveryJournalFake,
        engine: &'a RecoveryEngineFake,
    ) -> RestoreCoordinator<'a> {
        RestoreCoordinator::new(journal, engine)
    }

    /// `failure.reason` assertion: upstream `backup.Failure{Reason}` ≙
    /// [`Failure::code`]; `Class` ≙ `kind`.
    fn failure_of(step: &RestoreStepFailure) -> &Failure {
        &step.failure
    }

    // ------------------------------------------------------------------
    // restore_coordinator_test.go matrix
    // ------------------------------------------------------------------

    #[test]
    fn restore_consumes_one_ticket_and_reaches_ready_only_after_all_boundaries() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let op = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap();
        assert!(op.serving_allowed());
        assert_eq!(op.phase, RestorePhase::Ready);
        assert_eq!(op.revision, 6);
        assert_eq!(engine.restore_calls.load(Ordering::SeqCst), 1);
        assert_eq!(engine.verify_calls.load(Ordering::SeqCst), 1);
        assert_eq!(engine.reset_calls.load(Ordering::SeqCst), 1);
        // Every post-replacement state plus ready.
        assert_eq!(engine.projection_calls.load(Ordering::SeqCst), 5);
        // A consumed ticket must not begin a second restore.
        assert!(
            coordinator
                .apply(&ticket, &recovery_test_authorization(&ticket))
                .is_err()
        );
        // A completed operation is not resumable.
        assert!(
            coordinator
                .resume(op.operation_id, &resume_test_authorization(&op))
                .is_err()
        );
    }

    #[test]
    fn restore_requires_fresh_authorization_bound_to_the_exact_ticket() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(
                &ticket,
                &RestoreApplyAuthorization {
                    authorization_id: Uuid::nil(),
                    operation_id: Uuid::nil(),
                    ticket_id: Uuid::nil(),
                    issued_at: crate::wire::zero_time(),
                    expires_at: crate::wire::zero_time(),
                },
            )
            .unwrap_err();
        let failure = failure_of(&step);
        assert_eq!(failure.kind(), FailureKind::Denied);
        assert_eq!(failure.code(), "RESTORE_FRESH_CONFIRMATION_REQUIRED");
        assert!(journal.operations.lock().unwrap().is_empty());
        assert_eq!(engine.restore_calls.load(Ordering::SeqCst), 0);

        let mut other = recovery_test_authorization(&ticket);
        other.operation_id = Uuid::now_v7();
        let step = coordinator.apply(&ticket, &other).unwrap_err();
        assert_eq!(
            failure_of(&step).code(),
            "RESTORE_FRESH_CONFIRMATION_REQUIRED"
        );
    }

    #[test]
    fn restore_resume_rejects_admission_binding_substitution() {
        let cases: Vec<(&str, OperationEdit)> = vec![
            (
                "payload epoch",
                Box::new(|op: &mut RestoreOperation| op.payload_epoch_id = Uuid::now_v7()),
            ),
            (
                "database schema",
                Box::new(|op: &mut RestoreOperation| {
                    op.database_schema_version = "central.schema-manifest/v2".into()
                }),
            ),
            (
                "capacity evidence",
                Box::new(|op: &mut RestoreOperation| {
                    op.capacity_evidence_digest =
                        "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
                            .into()
                }),
            ),
        ];
        for (name, mutate) in cases {
            let journal = RecoveryJournalFake::default();
            let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());
            let operation =
                new_restore_operation(&ticket, time::OffsetDateTime::now_utc()).unwrap();
            journal
                .operations
                .lock()
                .unwrap()
                .insert(operation.operation_id, operation.clone());
            *journal.resume_edit.lock().unwrap() = Some(mutate);
            let engine = RecoveryEngineFake::default();
            let coordinator = restore_coordinator(&journal, &engine);
            assert!(
                coordinator
                    .resume(
                        operation.operation_id,
                        &resume_test_authorization(&operation)
                    )
                    .is_err(),
                "substituted admission binding was accepted on resume ({name})"
            );
        }
    }

    #[test]
    fn restore_refuses_database_replacement_without_live_target_exclusion() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.exclusion_err.lock().unwrap() = Some(Failure::internal("engine", "target busy"));
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        let failure = failure_of(&step);
        assert_eq!(failure.code(), "RESTORE_TARGET_EXCLUSION_REQUIRED");
        assert_eq!(failure.kind(), FailureKind::Denied);
        assert!(step.operation.is_none());
        assert!(journal.operations.lock().unwrap().is_empty());
        assert_eq!(engine.restore_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn restore_keeps_barrier_when_audit_projection_fails() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.projection_err.lock().unwrap() =
            Some(Failure::internal("audit", "audit store unavailable"));
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        assert_eq!(failure_of(&step).code(), "RESTORE_AUDIT_PROJECTION_FAILED");
        let operation = step.operation.as_ref().unwrap();
        assert_eq!(operation.phase, RestorePhase::Applying);
        assert_eq!(
            operation.last_checkpoint,
            RestoreCheckpoint::DatabaseReplaced
        );
        assert!(!operation.serving_allowed());
        let stored = journal
            .operations
            .lock()
            .unwrap()
            .get(&operation.operation_id)
            .cloned()
            .unwrap();
        assert_eq!(stored, **operation);
    }

    #[test]
    fn restore_does_not_publish_applying_after_pre_admission_target_exclusion_loss() {
        let journal = RecoveryJournalFake::default();
        let exclusion = Arc::new(TargetExclusionFake::default());
        *exclusion.assert_err.lock().unwrap() = Some(Failure::internal("lock", "lease lost"));
        let engine = RecoveryEngineFake::default();
        *engine.exclusion.lock().unwrap() = Some(exclusion.clone());
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        assert_eq!(failure_of(&step).code(), "RESTORE_TARGET_EXCLUSION_LOST");
        assert!(step.operation.is_none());
        assert!(journal.operations.lock().unwrap().is_empty());
        assert_eq!(exclusion.release_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn restore_keeps_non_ready_barrier_when_target_exclusion_cannot_release() {
        let journal = RecoveryJournalFake::default();
        let exclusion = Arc::new(TargetExclusionFake::default());
        *exclusion.release_err.lock().unwrap() =
            Some(Failure::internal("lock", "unlock uncertain"));
        let engine = RecoveryEngineFake::default();
        *engine.exclusion.lock().unwrap() = Some(exclusion.clone());
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        assert_eq!(
            failure_of(&step).code(),
            "RESTORE_TARGET_EXCLUSION_RELEASE_FAILED"
        );
        let op = step.operation.as_ref().unwrap();
        assert_eq!(op.phase, RestorePhase::Verifying);
        assert_eq!(op.last_checkpoint, RestoreCheckpoint::AuthorityReset);
        assert!(!op.serving_allowed());
        assert_eq!(exclusion.release_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn restore_preserves_applying_barrier_after_database_failure_then_resumes_exact_operation() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.restore_err.lock().unwrap() =
            Some(Failure::internal("engine", "pg_restore failed"));
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        let failure = failure_of(&step);
        assert_eq!(failure.kind(), FailureKind::Internal);
        assert_eq!(failure.code(), "RESTORE_DATABASE_REPLACEMENT_FAILED");
        let op = step.operation.as_ref().unwrap();
        assert_eq!(op.phase, RestorePhase::Applying);
        assert_eq!(op.last_checkpoint, RestoreCheckpoint::TicketConsumed);
        assert!(!op.serving_allowed());

        *engine.restore_err.lock().unwrap() = None;
        let op = coordinator
            .resume(op.operation_id, &resume_test_authorization(op))
            .unwrap();
        assert!(op.serving_allowed());
        assert_eq!(engine.restore_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn restore_preserves_the_engines_own_refusal_reason() {
        for cause in [
            RestoreRefusalReason::MediaInvalid,
            RestoreRefusalReason::CapacityInsufficient,
        ] {
            let journal = RecoveryJournalFake::default();
            let engine = RecoveryEngineFake::default();
            *engine.restore_err.lock().unwrap() = Some(cause.into_failure());
            let coordinator = restore_coordinator(&journal, &engine);
            let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());
            let step = coordinator
                .apply(&ticket, &recovery_test_authorization(&ticket))
                .unwrap_err();
            // `Cause: backup.SanitizeRestoreRefusalCause(err)` — the
            // typed cause rides in the remediation message since
            // `Failure` carries no error chain.
            assert!(
                step.failure.message().contains(cause.as_str()),
                "sanitized cause {} missing from {:?}",
                cause.as_str(),
                step.failure.message()
            );
        }
        // A raw, unclassified adapter error must never surface as a
        // cause and its locator must never reach the message.
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.restore_err.lock().unwrap() = Some(Failure::internal(
            "adapter",
            "adapter detail naming /var/lib/central-protected/v1",
        ));
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());
        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        assert!(!step.failure.message().contains("/var/lib"));
        assert_eq!(step.failure.code(), "RESTORE_DATABASE_REPLACEMENT_FAILED");
    }

    #[test]
    fn restore_resume_requires_fresh_authorization_and_rejects_replay() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.restore_err.lock().unwrap() =
            Some(Failure::internal("engine", "pg_restore failed"));
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        let op = step.operation.clone().unwrap();
        assert!(op.is_resumable());
        // An operation ID alone never authorizes a resume.
        assert!(
            coordinator
                .resume(
                    op.operation_id,
                    &RestoreApplyAuthorization {
                        authorization_id: Uuid::nil(),
                        operation_id: Uuid::nil(),
                        ticket_id: Uuid::nil(),
                        issued_at: crate::wire::zero_time(),
                        expires_at: crate::wire::zero_time(),
                    }
                )
                .is_err()
        );
        *engine.restore_err.lock().unwrap() = None;
        let authorization = resume_test_authorization(&op);
        let completed = coordinator.resume(op.operation_id, &authorization).unwrap();
        assert!(completed.serving_allowed());
        // Replay the consumed authorization against the still-resumable
        // pre-completion record: the journal must refuse the replay.
        journal
            .operations
            .lock()
            .unwrap()
            .insert(op.operation_id, (*op).clone());
        assert!(coordinator.resume(op.operation_id, &authorization).is_err());
    }

    #[test]
    fn restore_blocks_on_quarantine_until_typed_resolution_completes() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.inventory_count.lock().unwrap() = 2;
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        let failure = failure_of(&step);
        assert_eq!(failure.kind(), FailureKind::Denied);
        assert_eq!(failure.code(), "RESTORE_QUARANTINE_RESOLUTION_REQUIRED");
        let op = step.operation.as_ref().unwrap();
        assert_eq!(op.phase, RestorePhase::Quarantined);
        assert!(!op.serving_allowed());
        let step = coordinator
            .resume(op.operation_id, &resume_test_authorization(op))
            .unwrap_err();
        assert_eq!(
            failure_of(&step).code(),
            "RESTORE_QUARANTINE_RESOLUTION_REQUIRED"
        );
        *engine.inventory_count.lock().unwrap() = 0;
        let op = coordinator
            .resume(op.operation_id, &resume_test_authorization(op))
            .unwrap();
        assert!(op.serving_allowed());
        // Initial pass plus two quarantine reconciliation passes.
        assert_eq!(engine.verify_calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn restore_requires_durable_typed_quarantine_projection_before_inventory_checkpoint() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.projection_quarantine_err.lock().unwrap() =
            Some(Failure::internal("audit", "audit unavailable"));
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        assert_eq!(
            failure_of(&step).code(),
            "RESTORE_QUARANTINE_PROJECTION_FAILED"
        );
        let operation = step.operation.as_ref().unwrap();
        assert_eq!(operation.phase, RestorePhase::Verifying);
        assert_eq!(
            operation.last_checkpoint,
            RestoreCheckpoint::DatabaseReplaced
        );
        assert_eq!(engine.quarantine_projection_calls.load(Ordering::SeqCst), 1);
        assert_eq!(engine.reset_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn restore_abandon_ends_a_stuck_operation_without_touching_the_target() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.restore_err.lock().unwrap() =
            Some(Failure::internal("engine", "pg_restore failed"));
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());

        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        let stuck = step.operation.clone().unwrap();
        assert!(stuck.is_resumable());
        let restore_calls = engine.restore_calls.load(Ordering::SeqCst);
        let abandoned = coordinator
            .abandon(
                stuck.operation_id,
                &abandon_test_authorization(stuck.operation_id),
            )
            .unwrap();
        assert_eq!(abandoned.phase, RestorePhase::Abandoned);
        assert!(abandoned.is_terminal());
        assert!(!abandoned.serving_allowed());
        // No further engine effect — abandonment touches only the
        // protected journal.
        assert_eq!(engine.restore_calls.load(Ordering::SeqCst), restore_calls);
        assert!(engine.exclusion_op.lock().unwrap().is_some());
        assert_eq!(
            journal
                .operations
                .lock()
                .unwrap()
                .get(&stuck.operation_id)
                .unwrap()
                .phase,
            RestorePhase::Abandoned
        );
    }

    #[test]
    fn restore_abandon_refuses_a_non_resumable_operation() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());
        let ready = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap();
        let step = coordinator
            .abandon(
                ready.operation_id,
                &abandon_test_authorization(ready.operation_id),
            )
            .unwrap_err();
        assert_eq!(failure_of(&step).code(), "RESTORE_OPERATION_NOT_RESUMABLE");
        // The authorization was not consumed by a refused abandon.
        assert!(
            !journal
                .authorized
                .lock()
                .unwrap()
                .contains(&abandon_test_authorization(ready.operation_id).authorization_id)
        );
    }

    #[test]
    fn restore_abandon_requires_a_fresh_operation_bound_authorization() {
        let journal = RecoveryJournalFake::default();
        let engine = RecoveryEngineFake::default();
        *engine.restore_err.lock().unwrap() =
            Some(Failure::internal("engine", "pg_restore failed"));
        let coordinator = restore_coordinator(&journal, &engine);
        let ticket = recovery_test_ticket(time::OffsetDateTime::now_utc());
        let step = coordinator
            .apply(&ticket, &recovery_test_authorization(&ticket))
            .unwrap_err();
        let stuck = step.operation.clone().unwrap();

        // Wrong operation binding.
        let wrong = abandon_test_authorization(Uuid::now_v7());
        let step = coordinator.abandon(stuck.operation_id, &wrong).unwrap_err();
        assert_eq!(
            failure_of(&step).code(),
            "RESTORE_FRESH_CONFIRMATION_REQUIRED"
        );
        // Wrong acknowledgement text.
        let mut bad_text = abandon_test_authorization(stuck.operation_id);
        bad_text.acknowledgement = "not-the-acknowledgement".into();
        assert!(coordinator.abandon(stuck.operation_id, &bad_text).is_err());
        // The operation remains resumable, not abandoned.
        assert!(
            journal
                .operations
                .lock()
                .unwrap()
                .get(&stuck.operation_id)
                .unwrap()
                .is_resumable()
        );
    }

    // ------------------------------------------------------------------
    // restore_verifier_test.go fakes + matrix
    // ------------------------------------------------------------------

    #[derive(Default)]
    struct RecoveryRepositoryVerifierFake {
        evidence: Mutex<Option<RecoveryVerificationEvidence>>,
        err: Mutex<Option<Failure>>,
        calls: AtomicUsize,
    }

    impl RecoveryRepositoryVerifier for RecoveryRepositoryVerifierFake {
        fn verify_backup(
            &self,
            _backup_id: Uuid,
            _profile: &crate::backup::capacity::RecoveryProfile,
        ) -> Result<RecoveryVerificationEvidence> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(self.evidence.lock().unwrap().clone().unwrap())
        }
    }

    #[derive(Default)]
    struct BackupSealVerifierFake {
        err: Mutex<Option<Failure>>,
    }

    impl BackupSealVerifier for BackupSealVerifierFake {
        fn verify_backup_seal(
            &self,
            _backup_id: Uuid,
            _manifest_digest: [u8; 32],
            _seal_companion_digest: [u8; 32],
            _file_tree_digest: [u8; 32],
            _repository_manifest_digest: [u8; 32],
            _repository_revision: u64,
        ) -> Result<()> {
            match self.err.lock().unwrap().clone() {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }
    }

    #[derive(Default)]
    struct RestoreInspectorFake {
        facts: Mutex<Option<RestoreAdmissionFacts>>,
        err: Mutex<Option<Failure>>,
        calls: AtomicUsize,
        got_backup_id: Mutex<Uuid>,
        got_evidence: Mutex<Option<RecoveryVerificationEvidence>>,
    }

    impl RestoreAdmissionInspector for RestoreInspectorFake {
        fn inspect_restore_admission(
            &self,
            backup_id: Uuid,
            evidence: &RecoveryVerificationEvidence,
        ) -> Result<RestoreAdmissionFacts> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.got_backup_id.lock().unwrap() = backup_id;
            *self.got_evidence.lock().unwrap() = Some(evidence.clone());
            if let Some(err) = self.err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(self.facts.lock().unwrap().clone().unwrap())
        }
    }

    #[derive(Default)]
    struct RestoreIssuerFake {
        ticket: Mutex<Option<RestoreTicket>>,
        err: Mutex<Option<Failure>>,
        calls: AtomicUsize,
        got_backup_id: Mutex<Uuid>,
        got_digest: Mutex<String>,
    }

    impl RestoreTicketIssuer for RestoreIssuerFake {
        fn issue_restore_ticket(
            &self,
            backup_id: Uuid,
            manifest_digest: &str,
            _facts: &RestoreAdmissionFacts,
            _now: time::OffsetDateTime,
        ) -> Result<RestoreTicket> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.got_backup_id.lock().unwrap() = backup_id;
            *self.got_digest.lock().unwrap() = manifest_digest.to_owned();
            if let Some(err) = self.err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(self.ticket.lock().unwrap().clone().unwrap())
        }
    }

    /// `restoreVerifierFixture`.
    struct VerifierFixture {
        verifier: RestoreVerifier<'static>,
        repository: &'static RecoveryRepositoryVerifierFake,
        seals: &'static BackupSealVerifierFake,
        inspector: &'static RestoreInspectorFake,
        issuer: &'static RestoreIssuerFake,
        backup_id: Uuid,
        manifest_digest: String,
        ticket: RestoreTicket,
    }

    fn manifest_for_test(
        operation_id: Uuid,
        backup_id: Uuid,
        repository_binding_id: Uuid,
    ) -> crate::backup::manifest::SealRootManifest {
        crate::backup::manifest::SealRootManifest {
            backup_id,
            operation_id,
            repository_binding_id,
            accepted_facts: accepted_backup_facts(datetime!(2026-08-09 12:00:00 UTC)),
            dump: DumpEvidence {
                size: 1,
                digest: sha256(b"dump"),
            },
            chunks: Vec::new(),
            digest: sha256(b"manifest"),
        }
    }

    fn new_restore_verifier_fixture() -> VerifierFixture {
        let now = datetime!(2026-08-09 12:00:00 UTC);
        let backup_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let repository_binding_id = Uuid::now_v7();
        let manifest = manifest_for_test(operation_id, backup_id, repository_binding_id);
        let manifest_digest = format!("sha256:{}", crate::wire::hex_encode(&manifest.digest));
        let facts = RestoreAdmissionFacts {
            target: test_target(),
            target_fingerprint: "sha256:target".into(),
            security_epoch: 2,
            restore_epoch: 3,
            config_fingerprint: "sha256:config-fingerprint".into(),
            payload_epoch_id: Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            capacity_evidence_digest: digest_words("capacity-evidence"),
            tool_version: "pg_restore-16.14".into(),
        };
        let ticket = RestoreTicket {
            ticket_id: Uuid::now_v7(),
            operation_id: Uuid::now_v7(),
            backup_id,
            target: facts.target.clone(),
            target_fingerprint: facts.target_fingerprint.clone(),
            manifest_digest: manifest_digest.clone(),
            security_epoch: facts.security_epoch,
            restore_epoch: facts.restore_epoch,
            config_fingerprint: facts.config_fingerprint.clone(),
            payload_epoch_id: facts.payload_epoch_id,
            database_schema_version: facts.database_schema_version.clone(),
            capacity_evidence_digest: facts.capacity_evidence_digest.clone(),
            tool_version: facts.tool_version.clone(),
            hidden_nonce: b"hidden".to_vec(),
            issued_at: now,
            expires_at: now + MAXIMUM_RESTORE_TICKET_LIFETIME,
            hmac: "broker-hmac".into(),
        };
        let repository = Box::leak(Box::new(RecoveryRepositoryVerifierFake {
            evidence: Mutex::new(Some(RecoveryVerificationEvidence {
                operation_id,
                backup_id,
                repository_binding_id,
                manifest_digest: manifest.digest,
                seal_companion_digest: sha256(b"companion"),
                file_tree_digest: sha256(b"tree"),
                repository_manifest_digest: sha256(b"repository manifest"),
                repository_revision: 1,
                dump: DumpEvidence {
                    size: 1,
                    digest: sha256(b"dump"),
                },
                artifact_count: 0,
                object_bytes: 0,
                manifest,
            })),
            ..Default::default()
        }));
        let seals = Box::leak(Box::new(BackupSealVerifierFake::default()));
        let inspector = Box::leak(Box::new(RestoreInspectorFake {
            facts: Mutex::new(Some(facts.clone())),
            ..Default::default()
        }));
        let issuer = Box::leak(Box::new(RestoreIssuerFake {
            ticket: Mutex::new(Some(ticket.clone())),
            ..Default::default()
        }));
        let mut verifier = RestoreVerifier::new(
            repository,
            seals,
            inspector,
            issuer,
            default_recovery_profile(),
        );
        verifier.now = Box::new(move || now);
        VerifierFixture {
            verifier,
            repository,
            seals,
            inspector,
            issuer,
            backup_id,
            manifest_digest,
            ticket,
        }
    }

    #[test]
    fn verifier_issues_only_bound_redacted_ticket_result() {
        let fixture = new_restore_verifier_fixture();
        let result = fixture.verifier.verify(fixture.backup_id).unwrap();
        assert_eq!(result.operation_id, fixture.ticket.operation_id);
        assert_eq!(result.backup_id, fixture.backup_id);
        assert_eq!(result.manifest_digest, fixture.manifest_digest);
        assert_eq!(result.expires_at, fixture.ticket.expires_at);
        assert_eq!(fixture.issuer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *fixture.issuer.got_backup_id.lock().unwrap(),
            fixture.backup_id
        );
        assert_eq!(
            *fixture.issuer.got_digest.lock().unwrap(),
            fixture.manifest_digest
        );
    }

    #[test]
    fn verifier_rejects_invalid_evidence_or_facts_before_ticket_issue() {
        // corrupt evidence
        {
            let fixture = new_restore_verifier_fixture();
            *fixture.repository.err.lock().unwrap() = Some(Failure::internal("repo", "corrupt"));
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // missing broker seal
        {
            let fixture = new_restore_verifier_fixture();
            *fixture.seals.err.lock().unwrap() = Some(Failure::internal("seal", "unsealed"));
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // wrong backup
        {
            let fixture = new_restore_verifier_fixture();
            fixture
                .repository
                .evidence
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .backup_id = Uuid::now_v7();
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // wrong tool
        {
            let fixture = new_restore_verifier_fixture();
            fixture
                .inspector
                .facts
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .tool_version = "pg_restore-17".into();
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // missing target
        {
            let fixture = new_restore_verifier_fixture();
            fixture
                .inspector
                .facts
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .target
                .database = String::new();
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // missing payload epoch
        {
            let fixture = new_restore_verifier_fixture();
            fixture
                .inspector
                .facts
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .payload_epoch_id = Uuid::nil();
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // wrong database schema
        {
            let fixture = new_restore_verifier_fixture();
            fixture
                .inspector
                .facts
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .database_schema_version = "central.schema-manifest/v2".into();
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // invalid capacity evidence
        {
            let fixture = new_restore_verifier_fixture();
            fixture
                .inspector
                .facts
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .capacity_evidence_digest = "sha256:short".into();
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
    }

    #[test]
    fn verifier_classifies_distinct_refusal_causes() {
        // repository I/O → media-invalid class bucket
        let fixture = new_restore_verifier_fixture();
        *fixture.repository.err.lock().unwrap() = Some(Failure::internal("repo", "read failed"));
        let err = fixture.verifier.verify(fixture.backup_id).unwrap_err();
        assert_eq!(err.code(), RestoreRefusalReason::MediaInvalid.as_str());

        // inspector (capacity authority) → capacity class bucket
        let fixture = new_restore_verifier_fixture();
        *fixture.inspector.err.lock().unwrap() = Some(Failure::internal(
            "capacity",
            "reserve authority unavailable",
        ));
        let err = fixture.verifier.verify(fixture.backup_id).unwrap_err();
        assert_eq!(
            err.code(),
            RestoreRefusalReason::CapacityInsufficient.as_str()
        );

        // broker issue → state-invalid class bucket
        let fixture = new_restore_verifier_fixture();
        *fixture.issuer.err.lock().unwrap() =
            Some(Failure::internal("broker", "journal unavailable"));
        let err = fixture.verifier.verify(fixture.backup_id).unwrap_err();
        assert_eq!(err.code(), RestoreRefusalReason::StateInvalid.as_str());
    }

    #[test]
    fn verifier_rejects_ticket_substitution_or_unsafe_lifetime() {
        // Substituted backup binding.
        {
            let fixture = new_restore_verifier_fixture();
            let mut ticket = fixture.ticket.clone();
            ticket.backup_id = Uuid::now_v7();
            *fixture.issuer.ticket.lock().unwrap() = Some(ticket);
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // Lifetime beyond the pin.
        {
            let fixture = new_restore_verifier_fixture();
            let mut ticket = fixture.ticket.clone();
            ticket.expires_at =
                ticket.issued_at + MAXIMUM_RESTORE_TICKET_LIFETIME + time::Duration::minutes(1);
            *fixture.issuer.ticket.lock().unwrap() = Some(ticket);
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
        // Missing HMAC.
        {
            let fixture = new_restore_verifier_fixture();
            let mut ticket = fixture.ticket.clone();
            ticket.hmac = String::new();
            *fixture.issuer.ticket.lock().unwrap() = Some(ticket);
            assert!(fixture.verifier.verify(fixture.backup_id).is_err());
        }
    }

    #[test]
    fn verifier_reads_sealed_evidence_once_and_forwards_it() {
        let fixture = new_restore_verifier_fixture();
        fixture.verifier.verify(fixture.backup_id).unwrap();
        assert_eq!(fixture.repository.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.inspector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *fixture.inspector.got_backup_id.lock().unwrap(),
            fixture.backup_id
        );
        let want = fixture.repository.evidence.lock().unwrap().clone().unwrap();
        let got = fixture
            .inspector
            .got_evidence
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(got.operation_id, want.operation_id);
        assert_eq!(got.backup_id, want.backup_id);
        assert_eq!(got.repository_binding_id, want.repository_binding_id);
        assert_eq!(got.manifest_digest, want.manifest_digest);
        assert_eq!(got.seal_companion_digest, want.seal_companion_digest);
        assert_eq!(got.file_tree_digest, want.file_tree_digest);
        assert_eq!(
            got.repository_manifest_digest,
            want.repository_manifest_digest
        );
        assert_eq!(got.repository_revision, want.repository_revision);
        assert_eq!(got.dump, want.dump);
        assert_eq!(got.artifact_count, want.artifact_count);
        assert_eq!(got.object_bytes, want.object_bytes);
        assert_eq!(got.manifest.backup_id, want.manifest.backup_id);
        assert_eq!(got.manifest.operation_id, want.manifest.operation_id);
        assert_eq!(
            got.manifest.repository_binding_id,
            want.manifest.repository_binding_id
        );
        assert_eq!(got.manifest.digest, want.manifest.digest);
    }

    // ------------------------------------------------------------------
    // authority_reset_test.go fakes + matrix
    // ------------------------------------------------------------------

    #[derive(Default)]
    struct BrokerResetFake {
        draft_err: Mutex<Option<Failure>>,
        activation_err: Mutex<Option<Failure>>,
        prepare_calls: AtomicUsize,
        activate_calls: AtomicUsize,
    }

    fn digest32(value: &str) -> [u8; 32] {
        sha256(value.as_bytes())
    }

    impl BrokerAuthorityReset for BrokerResetFake {
        fn prepare_recovery_broker_authority(
            &self,
            operation: &RestoreOperation,
        ) -> Result<RecoveryBootstrapDraft> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.draft_err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(RecoveryBootstrapDraft {
                operation_id: operation.operation_id,
                draft_id: Uuid::now_v7(),
                candidate_id: Uuid::now_v7(),
                verifier_hash: digest32("verifier"),
                candidate_digest: digest32("candidate"),
                broker_receipt_hash: digest_words("broker-receipt"),
                created_at: operation.updated_at,
            })
        }

        fn activate_recovery_bootstrap(
            &self,
            operation: &RestoreOperation,
            registration: &RecoveryBootstrapRegistration,
        ) -> Result<RecoveryBootstrapActivation> {
            self.activate_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.activation_err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(RecoveryBootstrapActivation {
                operation_id: operation.operation_id,
                draft_id: registration.draft_id,
                candidate_id: registration.candidate_id,
                generation: registration.generation,
                database_receipt_hash: registration.database_receipt_hash.clone(),
                activation_receipt_hash: digest_words("activation"),
                activated_at: registration.registered_at,
            })
        }
    }

    #[derive(Default)]
    struct PostgresResetFake {
        reset_calls: AtomicUsize,
        finalize_calls: AtomicUsize,
        reset_err: Mutex<Option<Failure>>,
        finalize_err: Mutex<Option<Failure>>,
    }

    impl PostgresAuthorityReset for PostgresResetFake {
        fn reset_database_authority(
            &self,
            _operation: &RestoreOperation,
            draft: &RecoveryBootstrapDraft,
        ) -> Result<RecoveryBootstrapRegistration> {
            self.reset_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.reset_err.lock().unwrap().clone() {
                return Err(err);
            }
            Ok(RecoveryBootstrapRegistration {
                operation_id: draft.operation_id,
                draft_id: draft.draft_id,
                candidate_id: draft.candidate_id,
                generation: 7,
                verifier_hash: draft.verifier_hash,
                candidate_digest: draft.candidate_digest,
                broker_receipt_hash: draft.broker_receipt_hash.clone(),
                database_receipt_hash: digest_words("database-receipt"),
                registered_at: draft.created_at,
            })
        }

        fn finalize_database_authority_reset(
            &self,
            operation: &RestoreOperation,
            registration: &RecoveryBootstrapRegistration,
            activation: &RecoveryBootstrapActivation,
        ) -> Result<AuthorityResetReceipt> {
            self.finalize_calls.fetch_add(1, Ordering::SeqCst);
            if let Some(err) = self.finalize_err.lock().unwrap().clone() {
                return Err(err);
            }
            // The database-side finalizer owns aggregate-receipt
            // construction — the canonical 11-field payload hash.
            crate::recovery::operation::new_authority_reset_receipt(
                operation,
                registration,
                activation,
                operation.updated_at + time::Duration::milliseconds(1),
            )
        }
    }

    /// An operation at the `verifying`/`inventory_verified` stage —
    /// built by driving the domain transitions like a real restore.
    fn verifying_operation() -> RestoreOperation {
        let now = time::OffsetDateTime::now_utc();
        let ticket = recovery_test_ticket(now);
        let op = new_restore_operation(&ticket, now).unwrap();
        let op = op.record_database_replaced(now).unwrap();
        let op = op.begin_verification(now).unwrap();
        op.record_inventory_verified(now).unwrap()
    }

    #[test]
    fn authority_reset_commits_broker_before_database() {
        let broker = BrokerResetFake::default();
        let database = PostgresResetFake::default();
        let coordinator = AuthorityResetCoordinator::new(&broker, &database);
        let operation = verifying_operation();

        let receipt = coordinator.reset_authority(&operation).unwrap();
        assert_eq!(receipt.operation_id, operation.operation_id);
        assert_eq!(receipt.new_restore_epoch, operation.restore_epoch);
        assert_eq!(receipt.new_security_epoch, operation.security_epoch + 1);
        assert!(receipt.aggregate_receipt_hash.starts_with("sha256:"));
        assert_eq!(broker.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(database.reset_calls.load(Ordering::SeqCst), 1);
        assert_eq!(broker.activate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(database.finalize_calls.load(Ordering::SeqCst), 1);
        receipt.validate_for(&operation).unwrap();
    }

    #[test]
    fn authority_reset_never_runs_database_after_broker_failure() {
        let broker = BrokerResetFake::default();
        *broker.draft_err.lock().unwrap() =
            Some(Failure::internal("broker", "protected journal unavailable"));
        let database = PostgresResetFake::default();
        let coordinator = AuthorityResetCoordinator::new(&broker, &database);
        let operation = verifying_operation();
        assert!(coordinator.reset_authority(&operation).is_err());
        assert_eq!(database.reset_calls.load(Ordering::SeqCst), 0);
        assert_eq!(database.finalize_calls.load(Ordering::SeqCst), 0);
        assert_eq!(broker.activate_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authority_reset_does_not_finalize_after_bootstrap_activation_failure() {
        let broker = BrokerResetFake::default();
        *broker.activation_err.lock().unwrap() =
            Some(Failure::internal("broker", "bootstrap activation failed"));
        let database = PostgresResetFake::default();
        let coordinator = AuthorityResetCoordinator::new(&broker, &database);
        let operation = verifying_operation();
        assert!(coordinator.reset_authority(&operation).is_err());
        assert_eq!(database.finalize_calls.load(Ordering::SeqCst), 0);
    }
}
