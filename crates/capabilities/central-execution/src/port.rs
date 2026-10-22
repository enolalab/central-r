//! Execution ports — the async boundary contracts ported from
//! `central/internal/execution/port/port.go`.
//!
//! The composite store is the single atomic commit seam: one call
//! persists the execution change set, the embedded task transition,
//! durable event + outbox intents, lease upserts/releases/assertions,
//! and the idempotent command receipt — or none of them.

use central_foundation::failure::Failure;
use central_foundation::identity::{RunId, StepAttemptId, StepId, TaskId, WorkspaceId};
use central_task::domain as task;
use time::OffsetDateTime;

use crate::domain::{
    Capability, CommandEnvelope, EvaluationMetadata, ExecutionChangeSet, ExecutionState,
    ExpectedVersions, LeaseCredential, LogicalOperationId, RequestFingerprint, TrustedScope,
};
use crate::harness_run::B09References;
use crate::resume::{RecoveryEpoch, RecoveryWorkspaceWork};

/// `ExecutionReadRequest` — the authoritative-state load every command
/// performs before evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionReadRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
}

/// `ExecutionReadResult` — the authoritative snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionReadResult {
    /// The loaded execution state (missing rows are `None`/empty).
    pub state: ExecutionState,
}

/// Loads the authoritative execution state for a command selector.
/// A read failure means *no* evaluation and *no* commit.
#[trait_variant::make(Send)]
pub trait ExecutionRead {
    /// `ExecutionRead`.
    async fn read_execution(
        &self,
        request: ExecutionReadRequest,
    ) -> Result<ExecutionReadResult, Failure>;
}

/// `ReceiptBinding` — the durable receipt's binding fields replay must
/// reproduce exactly.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReceiptBinding {
    pub task_id: Option<TaskId>,
    pub run_id: Option<RunId>,
    pub step_id: Option<StepId>,
    pub attempt_id: Option<StepAttemptId>,
    pub logical_operation: Option<LogicalOperationId>,
}

/// `ReceiptLookupRequest` — idempotent receipt probe issued *before*
/// the authoritative state read.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceiptLookupRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    /// The command's durable scope (`execution.*`).
    pub command_scope: String,
    /// Client idempotency key.
    pub idempotency_key: String,
    /// Canonical request fingerprint.
    pub fingerprint: RequestFingerprint,
    pub principal_id: String,
    pub capability: Capability,
    /// Selector binding the receipt replays.
    pub binding: ReceiptBinding,
    /// Expected versions the receipt was committed under.
    pub expected_versions: ExpectedVersions,
}

/// `ReceiptLookupResult` — `found` + the previously committed durable
/// result.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReceiptLookupResult {
    /// Whether a matching receipt exists.
    pub found: bool,
    /// The stored durable result (meaningful when `found`).
    pub result: Option<DurableResult>,
}

/// `LeaseValidationRequest` — ask the authoritative lease store whether
/// `credential` fences `generation` for (workspace, run) at `now`.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseValidationRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    pub workspace_id: WorkspaceId,
    pub run_id: RunId,
    pub credential: LeaseCredential,
    pub generation: i64,
    /// The validation instant.
    pub now: OffsetDateTime,
}

/// Validates a presented lease credential against the authoritative
/// lease store. Separate from [`ExecutionRead`] because validating a
/// credential is a security boundary, not a data read — services that
/// cannot reach a validator must fail closed.
#[trait_variant::make(Send)]
pub trait LeaseCredentialValidator {
    /// `ValidateLeaseCredential`.
    async fn validate_lease_credential(
        &self,
        request: LeaseValidationRequest,
    ) -> Result<bool, Failure>;
}

/// `DurableResult` — the receipt-committed outcome a replay returns
/// verbatim (no new lease credential is minted).
#[derive(Debug, Clone, PartialEq)]
pub struct DurableResult {
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    /// The committed durable event id.
    pub event_id: central_foundation::identity::ExecutionEventId,
    /// The committed event kind (`attempt_settled`, ...).
    pub event_kind: String,
    /// Optional approval action surfaced to B11.
    pub approval_action: Option<crate::domain::ApprovalAction>,
}

/// `CommitRequest` — one atomic composite commit.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    /// The command's durable scope.
    pub command_scope: String,
    /// Client idempotency key.
    pub idempotency_key: String,
    /// Canonical request fingerprint.
    pub fingerprint: RequestFingerprint,
    pub principal_id: String,
    pub capability: Capability,
    /// Selector + expected versions + caller state.
    pub envelope: CommandEnvelope,
    /// The evaluated change set (task transition included).
    pub change_set: ExecutionChangeSet,
    /// The lease credential the commit binds (zero when absent).
    pub lease_credential: LeaseCredential,
    /// The fenced lease generation.
    pub lease_generation: i64,
    /// Assert no active lease exists at commit time.
    pub assert_no_active_lease: bool,
    /// Assert the run is still recovery-claimable.
    pub require_recovery_claimable: bool,
    /// The durable result stored on the receipt.
    pub result: DurableResult,
}

/// `CommitResult` — receipt replay or first commit.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitResult {
    /// The durable result (identical on replay).
    pub result: DurableResult,
    /// True when the commit was a receipt replay, not a fresh write.
    pub replayed: bool,
}

/// The single atomic commit seam for execution + task transitions.
#[trait_variant::make(Send)]
pub trait CompositeStore {
    /// `Commit` — applies the change set or returns the durable replay.
    async fn commit(&self, request: CommitRequest) -> Result<CommitResult, Failure>;
}

/// `CompletionChangeSetRequest` — a completing pass commits its own
/// change set under the same composite rules (B10).
#[derive(Debug, Clone, PartialEq)]
pub struct CompletionChangeSetRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    /// The evaluated change set.
    pub change_set: ExecutionChangeSet,
}

/// Commits the completing pass's change set after receipt validation.
#[trait_variant::make(Send)]
pub trait CompletionChangeSetStore {
    /// `CommitCompletionChangeSet`.
    async fn commit_completion_change_set(
        &self,
        request: CompletionChangeSetRequest,
    ) -> Result<(), Failure>;
}

impl Default for DurableResult {
    /// Zero/nil identities — Go's zero-value receipt.
    fn default() -> Self {
        use central_foundation::identity::*;
        Self {
            workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
            task_id: TaskId::from_trusted_db_bytes([0; 16]),
            run_id: RunId::from_trusted_db_bytes([0; 16]),
            step_id: StepId::from_trusted_db_bytes([0; 16]),
            attempt_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
            event_id: ExecutionEventId::from_trusted_db_bytes([0; 16]),
            event_kind: String::new(),
            approval_action: None,
        }
    }
}

/// `OutboxStore` — drains committed outbox intents (B-side transport).
#[trait_variant::make(Send)]
pub trait OutboxStore {
    /// `PublishOutbox` — the adapter delivers committed intents; the
    /// domain only ever *produces* them inside a change set.
    async fn publish_outbox(
        &self,
        scope: TrustedScope,
        intents: Vec<crate::domain::OutboxIntent>,
    ) -> Result<(), Failure>;
}

/// Typed B09 evidence store — filesystem page hashes and provider-turn
/// ids persist through this dedicated lane, never folded into generic
/// execution payloads (B09 stays a narrow border).
#[trait_variant::make(Send)]
pub trait B09EvidenceStore {
    /// `CommitB09Evidence` — persists the receipt's typed evidence
    /// references atomically with the settlement.
    async fn commit_b09_evidence(
        &self,
        scope: TrustedScope,
        attempt_id: StepAttemptId,
        references: B09References,
    ) -> Result<(), Failure>;
}

// ---------------------------------------------------------------------------
// Recovery contracts (upstream RecoveryStore + coordinator fence ops).
// ---------------------------------------------------------------------------

/// `RecoveryCoordinatorLease` — the coordinator's durable hold on an
/// epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryCoordinatorLease {
    /// Epoch under coordination.
    pub epoch_generation: i64,
    /// Fence generation held.
    pub fence_generation: i64,
    /// Lease expiry — renew before this or lose the fence.
    pub expires_at: OffsetDateTime,
}

/// `RecoveryCoordinatorAcquireRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryCoordinatorAcquireRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    /// Epoch to coordinate.
    pub epoch_generation: i64,
    /// Fence the coordinator wants (strictly greater than current).
    pub fence_generation: i64,
    /// Acquisition instant.
    pub now: OffsetDateTime,
    /// Lease duration.
    pub ttl: time::Duration,
}

/// `StartRecoveryEpochRequest` — opens a fresh epoch snapshotting the
/// failed-run watermark.
#[derive(Debug, Clone, PartialEq)]
pub struct StartRecoveryEpochRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    /// The epoch generation to open (`0` = next).
    pub generation: i64,
    /// Snapshot instant.
    pub now: OffsetDateTime,
}

/// `ClaimRecoveryWorkspaceRequest` — claims pending work inside the
/// epoch under the coordinator fence.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimRecoveryWorkspaceRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    /// Epoch + fence held.
    pub epoch_generation: i64,
    /// Epoch + fence held.
    pub fence_generation: i64,
    /// Claim instant.
    pub now: OffsetDateTime,
    /// Max workspaces to claim.
    pub limit: u32,
}

/// `RecoveryWorkspaceClaim` — claimed work plus the loaded epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryWorkspaceClaim {
    /// The epoch under coordination.
    pub epoch: RecoveryEpoch,
    /// The claimed work row.
    pub work: RecoveryWorkspaceWork,
}

/// `CompleteRecoveryWorkspaceRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteRecoveryWorkspaceRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    /// Epoch + fence held.
    pub epoch_generation: i64,
    /// Epoch + fence held.
    pub fence_generation: i64,
    /// The work row to close.
    pub workspace_id: WorkspaceId,
    /// Whether recovery failed for the workspace.
    pub failed: bool,
    /// Completion instant.
    pub now: OffsetDateTime,
}

/// `ResumeRecoveryEpochRequest` — operator resume of a degraded epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeRecoveryEpochRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    /// The resume command (already fingerprint-validated upstream of
    /// the store).
    pub command: crate::resume::ResumeRecoveryEpochCommand,
    /// Commit instant.
    pub now: OffsetDateTime,
}

/// `FailedRecoveryWorkspaces` — the operator-facing failed-work page.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FailedRecoveryWorkspaces {
    /// Failed work rows.
    pub workspaces: Vec<RecoveryWorkspaceWork>,
    /// Resume cursor (opaque; empty when done).
    pub next_cursor: String,
}

/// `ArtifactWorkClaim` — an artifact-producing work unit the recovery
/// lane claims for B11/B12 follow-up.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactWorkClaim {
    /// The claim's workspace.
    pub workspace_id: WorkspaceId,
    /// The claimed run.
    pub run_id: RunId,
    /// Claim expiry.
    pub expires_at: OffsetDateTime,
}

/// `RecoveryStore` — durable recovery-epoch operations; every mutation
/// is fenced by the coordinator lease.
#[trait_variant::make(Send)]
pub trait RecoveryStore {
    /// `AcquireRecoveryCoordinator` — takes/renews the epoch fence.
    async fn acquire_recovery_coordinator(
        &self,
        request: RecoveryCoordinatorAcquireRequest,
    ) -> Result<RecoveryCoordinatorLease, Failure>;
    /// `StartRecoveryEpoch`.
    async fn start_recovery_epoch(
        &self,
        request: StartRecoveryEpochRequest,
    ) -> Result<RecoveryEpoch, Failure>;
    /// `LoadRecoveryEpoch`.
    async fn load_recovery_epoch(
        &self,
        scope: TrustedScope,
        generation: i64,
    ) -> Result<RecoveryEpoch, Failure>;
    /// `ClaimRecoveryWorkspaces` — claims pending work rows.
    async fn claim_recovery_workspaces(
        &self,
        request: ClaimRecoveryWorkspaceRequest,
    ) -> Result<Vec<RecoveryWorkspaceClaim>, Failure>;
    /// `RenewRecoveryWorkspaceClaim`.
    async fn renew_recovery_workspace_claim(
        &self,
        scope: TrustedScope,
        epoch_generation: i64,
        workspace_id: WorkspaceId,
        fence_generation: i64,
        now: OffsetDateTime,
    ) -> Result<(), Failure>;
    /// `CompleteRecoveryWorkspace`.
    async fn complete_recovery_workspace(
        &self,
        request: CompleteRecoveryWorkspaceRequest,
    ) -> Result<(), Failure>;
    /// `ResumeRecoveryEpoch`.
    async fn resume_recovery_epoch(
        &self,
        request: ResumeRecoveryEpochRequest,
    ) -> Result<RecoveryEpoch, Failure>;
    /// `ListFailedRecoveryWorkspaces`.
    async fn list_failed_recovery_workspaces(
        &self,
        scope: TrustedScope,
        epoch_generation: i64,
        cursor: &str,
        limit: u32,
    ) -> Result<FailedRecoveryWorkspaces, Failure>;
    /// `ClaimArtifactWork` — claims artifact-producing recovery work.
    async fn claim_artifact_work(
        &self,
        scope: TrustedScope,
        epoch_generation: i64,
        fence_generation: i64,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<ArtifactWorkClaim>, Failure>;
}

/// `RecoveryClaimabilityReader` — the read the claimability decorator
/// issues per run; on failure the decorator fails closed
/// (`RECOVERY_STATUS_UNAVAILABLE`).
#[trait_variant::make(Send)]
pub trait RecoveryClaimabilityReader {
    /// `RecoveryClaimability` — returns `(epoch, work, reconciled
    /// generation)` for the run's workspace, or `None` when no epoch
    /// covers it.
    async fn recovery_claimability_for(
        &self,
        scope: TrustedScope,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> Result<Option<(RecoveryEpoch, RecoveryWorkspaceWork, i64)>, Failure>;
}

/// `Clock` — the single time source services depend on.
#[trait_variant::make(Send)]
pub trait Clock {
    /// `Now`.
    fn now(&self) -> OffsetDateTime;
}

/// `CompositeExecutionStore` — the façade services consume: read +
/// receipt + commit. Adapters implement the three traits; services
/// take `S: ExecutionRead + CompositeStore`.
#[trait_variant::make(Send)]
pub trait CompositeExecutionStore: ExecutionRead + CompositeStore {
    /// `LookupReceipt` — the receipt probe before authoritative reads.
    async fn lookup_receipt(
        &self,
        request: ReceiptLookupRequest,
    ) -> Result<ReceiptLookupResult, Failure>;
}

/// Bundle of resolved selector + guards + metadata an app method
/// carries internally — mirrors the upstream `(envelope, meta)` pair.
#[derive(Debug, Clone, PartialEq)]
pub struct Invocation {
    /// The command envelope (selector, guards, caller state).
    pub envelope: CommandEnvelope,
    /// Evaluation metadata (now, identities, fingerprint).
    pub meta: EvaluationMetadata,
}

/// The task domain's aggregate, re-exported for signature clarity.
pub type TaskAggregate = task::TaskAggregate;
