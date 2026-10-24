//! Execution ports — the async boundary contracts ported from
//! `central/internal/execution/port/port.go`.
//!
//! The composite store is the single atomic commit seam: one call
//! persists the execution change set, the embedded task transition,
//! durable event + outbox intents, lease upserts/releases/assertions,
//! and the idempotent command receipt — or none of them.

use central_foundation::failure::Failure;
use central_foundation::identity::{InstanceId, RunId, StepAttemptId, StepId, TaskId, WorkspaceId};
use central_task::domain as task;
use time::OffsetDateTime;

use crate::domain::{
    Capability, Claimability, CommandEnvelope, EvaluationMetadata, ExecutionChangeSet,
    ExecutionState, ExpectedVersions, LeaseCredential, LogicalOperationId, RequestFingerprint,
    TrustedScope,
};
use crate::harness_run::{
    B09EvidenceReference, CompletionReceipt, DispatchableRun, ListDispatchableRunsRequest,
};
use crate::resume::{
    RecoveryCoordinatorFence, RecoveryEpoch, RecoveryEpochState, RecoveryWorkspaceState,
    RecoveryWorkspaceWork,
};

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

/// `ReceiptBinding` — the immutable execution target attached to one
/// command receipt. Exact replay must match every selector and logical
/// operation; a request fingerprint alone is not an authority or
/// target binding.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceiptBinding {
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    pub logical_operation: LogicalOperationId,
}

/// `ReceiptLookupRequest` — the trusted, principal-bound idempotency
/// lookup performed *before* loading mutable execution state. An
/// adapter returns a conflict when an existing key is bound to a
/// different fingerprint.
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

/// `ReceiptLookupResult` — an exact durable replay result. `found` is
/// false only when no receipt exists for the trusted receipt identity.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReceiptLookupResult {
    /// Whether a matching receipt exists.
    pub found: bool,
    /// The stored durable result (meaningful when `found`).
    pub result: Option<DurableResult>,
}

/// `LeaseValidationRequest` — asks the authoritative adapter to
/// validate a transient lease bearer without returning its persisted
/// verifier.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseValidationRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    pub lease_credential: LeaseCredential,
    pub lease_generation: i64,
}

/// `LeaseCredentialValidator` — implemented by adapters that can check
/// a transient lease bearer against the current durable ownership row.
/// The validation is deliberately separate from `ExecutionRead`
/// because durable reads cannot expose lease credentials; an error
/// means the bearer is not authoritative.
#[trait_variant::make(Send)]
pub trait LeaseCredentialValidator {
    /// `ValidateLease`.
    async fn validate_lease(&self, request: LeaseValidationRequest) -> Result<(), Failure>;
}

/// `DurableResult` — the complete immutable command-result correlation
/// retained by a receipt. It uses typed domain identities so an exact
/// replay never degrades into an adapter-owned reference that callers
/// must reinterpret.
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
    /// Present only for an approval-successor command. Persisted with
    /// the receipt so replay never re-reads mutable "latest" approval
    /// state.
    pub approval_action: Option<crate::domain::ApprovalSuccessorActionDescriptor>,
}

/// `CommitRequest` — binds a command receipt to its trusted authority
/// and the evaluated immutable evidence. The adapter must recheck all
/// selectors and guards atomically. `lease_credential` and
/// `lease_generation` are non-zero together only after evaluation
/// proves a current active lease; `assert_no_active_lease` is the
/// mutually exclusive evaluator-produced absence predicate.
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
    /// Receipt binding + optimistic guards (never a caller envelope).
    pub receipt_binding: ReceiptBinding,
    /// Receipt binding + optimistic guards (never a caller envelope).
    pub expected_versions: ExpectedVersions,
    /// Mandatory for `execution.claim` and
    /// `execution.start_harness_run` (the lease-granting commands) and
    /// forbidden for every other command. The composite store rechecks
    /// the latest durable recovery epoch and reconciled run inside the
    /// commit transaction.
    pub require_recovery_claimable: bool,
    /// The evaluator-proven fence; zero when no active lease applies.
    pub lease_credential: LeaseCredential,
    /// The evaluator-proven fence; zero when no active lease applies.
    pub lease_generation: i64,
    /// Assert no active lease exists at commit time.
    pub assert_no_active_lease: bool,
    /// The durable result stored on the receipt.
    pub result: DurableResult,
    /// The evaluated change set (task transition included).
    pub change_set: ExecutionChangeSet,
}

/// `CommitResult` — receipt replay or first commit. `replayed` reports
/// that `result` came from an exact retained receipt rather than a new
/// commit.
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
    /// `IssueLeaseCredential` — mints one raw 256-bit lease bearer; only
    /// its verifier hash is ever persisted.
    fn issue_lease_credential(&self) -> Result<LeaseCredential, Failure>;
    /// `Commit` — applies the change set or returns the durable replay.
    async fn commit(&self, request: CommitRequest) -> Result<CommitResult, Failure>;
}

/// `CompletionChangeSetRequest` — the narrow B08 boundary for a
/// completion candidate. It carries no caller-authored
/// `ExecutionState`; the application service loads the authoritative
/// snapshot before accepting the candidate.
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

impl CompletionChangeSetRequest {
    /// Upstream `CompletionChangeSetRequest.Validate`.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.scope.workspace_id.is_nil()
            || self.scope.workspace_id != self.workspace_id
            || self.task_id.is_nil()
            || self.run_id.is_nil()
            || self.step_id.is_nil()
            || self.attempt_id.is_nil()
        {
            return Err(Failure::new(
                central_foundation::failure::FailureKind::Denied,
                "SCOPE_MISMATCH",
                "completion request refused",
            ));
        }
        Ok(())
    }
}

/// Commits the completing pass's change set after receipt validation.
///
/// Deliberately unimplemented in `central-adapter-postgres`: upstream
/// has no `CommitCompletionChangeSet` store method — the completion
/// candidate is validated by `ValidateCompletionChangeSet` (an
/// app-layer port) and then commits through the single atomic
/// [`CompositeStore::commit`] seam with its receipt. This trait is
/// reserved forward surface; an adapter impl lands with its first
/// caller (same deferral class as `central-authorization`'s
/// `GenesisStore`).
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

/// Typed B09 evidence store — the allowlisted durable evidence
/// references persist through this dedicated lane, never folded into
/// generic execution payloads (B09 stays a narrow border).
#[trait_variant::make(Send)]
pub trait B09EvidenceStore {
    /// `CommitB09Evidence` — persists the receipt's typed evidence
    /// references atomically with the settlement.
    async fn commit_b09_evidence(
        &self,
        scope: TrustedScope,
        attempt_id: StepAttemptId,
        references: Vec<B09EvidenceReference>,
    ) -> Result<(), Failure>;
}

// ---------------------------------------------------------------------------
// Recovery contracts (upstream RecoveryStore + coordinator fence ops).
// ---------------------------------------------------------------------------

/// `RecoveryCoordinatorAcquireRequest` — identifies the one
/// deployment-wide lease; the adapter generates and stores only the
/// token verifier. `fence` (on the lease) is the fencing fact passed
/// to every later recovery write.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryCoordinatorAcquireRequest {
    /// The coordinator domain token — always
    /// `central.execution.recovery.v1`.
    pub recovery_domain: String,
    /// The coordinating process identity.
    pub instance_id: InstanceId,
}

/// `RecoveryCoordinatorLease` — the coordinator's durable hold.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryCoordinatorLease {
    /// Echoed domain token.
    pub recovery_domain: String,
    /// The coordinating process identity.
    pub instance_id: InstanceId,
    /// The fence generation held.
    pub fence: RecoveryCoordinatorFence,
    /// Lease expiry — renew before this or lose the fence.
    pub expires_at: OffsetDateTime,
    /// The raw 256-bit coordinator bearer. Only its SHA-256 verifier is
    /// stored; every later recovery write presents this token.
    pub claim_token: Vec<u8>,
}

/// `StartRecoveryEpochRequest` — opens a fresh epoch snapshotting the
/// failed-run watermark under the held lease.
#[derive(Debug, Clone, PartialEq)]
pub struct StartRecoveryEpochRequest {
    /// The coordinator lease fencing the open.
    pub lease: RecoveryCoordinatorLease,
    /// Bounded workspaces scanned per pass.
    pub batch_size: u32,
}

/// `ClaimRecoveryWorkspaceRequest` — claims pending work inside the
/// epoch under the coordinator lease.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimRecoveryWorkspaceRequest {
    /// The coordinator lease fencing the claim.
    pub lease: RecoveryCoordinatorLease,
    /// Epoch under coordination.
    pub epoch_generation: i64,
    /// Max workspaces to claim.
    pub batch_size: u32,
}

/// `RecoveryWorkspaceClaim` — one durable round-robin item. An empty
/// `work.workspace_id` means the epoch is complete or no item is
/// currently ready.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryWorkspaceClaim {
    /// The epoch under coordination.
    pub epoch: RecoveryEpoch,
    /// The claimed work row.
    pub work: RecoveryWorkspaceWork,
    /// The coordinator lease the claim was minted under.
    pub coordinator_lease: RecoveryCoordinatorLease,
    /// An opaque 256-bit runtime credential; its SHA-256 verifier is
    /// the only stored representation. Callers must present it to
    /// complete exactly this workspace claim.
    pub claim_token: Vec<u8>,
    /// Whether a work row was claimed.
    pub claimed: bool,
    /// Whether the claimed row is already complete.
    pub completed: bool,
    /// Database-derived delay returned only for an unclaimed,
    /// incomplete placeholder; prevents busy-polling.
    pub retry_after: time::Duration,
}

impl Default for RecoveryWorkspaceClaim {
    /// The Go `port.RecoveryWorkspaceClaim{}` zero value `ClaimNext`
    /// returns on an empty batch — callers detect exhaustion via
    /// `claimed == false`, never via an error.
    fn default() -> Self {
        Self {
            epoch: RecoveryEpoch {
                generation: 0,
                coordinator_fence: RecoveryCoordinatorFence::default(),
                state: RecoveryEpochState::default(),
                scheduler_cursor: WorkspaceId::from_trusted_db_bytes([0; 16]),
                workspace_count: 0,
                processed_count: 0,
                claim_cycle: 0,
                retry_attempt: 0,
                snapshot_at: crate::domain::ZERO_TIME,
            },
            work: RecoveryWorkspaceWork {
                epoch_generation: 0,
                workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
                state: RecoveryWorkspaceState::default(),
                watermark_created_at: crate::domain::ZERO_TIME,
                watermark_run_id: RunId::from_trusted_db_bytes([0; 16]),
                cursor_created_at: crate::domain::ZERO_TIME,
                cursor_run_id: RunId::from_trusted_db_bytes([0; 16]),
                scanned_count: 0,
                reconciled_count: 0,
                retry_attempt: 0,
                failure_class: String::new(),
                failure_reason: String::new(),
            },
            coordinator_lease: RecoveryCoordinatorLease {
                recovery_domain: String::new(),
                instance_id: InstanceId::from_trusted_db_bytes([0; 16]),
                fence: RecoveryCoordinatorFence::default(),
                expires_at: crate::domain::ZERO_TIME,
                claim_token: Vec::new(),
            },
            claim_token: Vec::new(),
            claimed: false,
            completed: false,
            retry_after: time::Duration::ZERO,
        }
    }
}

/// `CompleteRecoveryWorkspaceRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteRecoveryWorkspaceRequest {
    /// The coordinator lease fencing the completion.
    pub lease: RecoveryCoordinatorLease,
    /// Epoch under coordination.
    pub epoch_generation: i64,
    /// The work row to close.
    pub workspace_id: WorkspaceId,
    /// The claim token presented for this exact claim.
    pub claim_token: Vec<u8>,
    /// Fail-closed scan acknowledgement. A successful request ignores
    /// caller-authored cursor/count facts and runs the adapter-owned
    /// bounded keyset scanner.
    pub degraded: bool,
    /// Coarse failure bucket persisted on a degraded row.
    pub failure_class: String,
    /// Operator-visible failure detail persisted on a degraded row.
    pub failure_reason: String,
}

/// `ResumeRecoveryEpochRequest` — operator resume of a degraded epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeRecoveryEpochRequest {
    /// The resume command (already validated upstream of the store).
    pub command: crate::resume::ResumeRecoveryEpochCommand,
    /// The coordinator lease fencing the resume.
    pub lease: RecoveryCoordinatorLease,
}

/// Bounds one `list_failed_recovery_workspaces` page.
pub const MAX_FAILED_RECOVERY_WORKSPACES: u32 = 250;

/// `FailedRecoveryWorkspaces` — the first page of an epoch's failed
/// workspace rows in ascending workspace-id order, and `total`, the
/// number of failed rows the epoch has in all.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FailedRecoveryWorkspaces {
    /// Failed workspace ids.
    pub ids: Vec<WorkspaceId>,
    /// Total failed rows in the epoch.
    pub total: i64,
}

/// `ArtifactWorkClaim` — the single B10 artifact-reconciliation work
/// item carried by the existing `recovery_coordinator` lease. It is
/// derived from — and fenced by — exactly the lease and epoch the
/// coordinator already holds, so `fence` and `claim_token` are that
/// lease's own fencing generation and raw 256-bit bearer.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactWorkClaim {
    /// The coordinator fence backing the claim.
    pub fence: RecoveryCoordinatorFence,
    /// The epoch the claim belongs to.
    pub epoch_generation: i64,
    /// The lease's raw 256-bit bearer, passed through unchanged.
    pub claim_token: Vec<u8>,
    /// Claim expiry (the lease expiry).
    pub expires_at: OffsetDateTime,
    /// False when no live lease backs the claim; a false value must
    /// never mutate durable artifact state.
    pub claimed: bool,
}

/// `RecoveryStore` — durable recovery-epoch operations; every mutation
/// is fenced by the coordinator lease.
#[trait_variant::make(Send)]
pub trait RecoveryStore {
    /// `AcquireRecoveryCoordinator` — takes/renews the deployment-wide
    /// coordinator lease.
    async fn acquire_recovery_coordinator(
        &self,
        request: RecoveryCoordinatorAcquireRequest,
    ) -> Result<RecoveryCoordinatorLease, Failure>;
    /// `StartRecoveryEpoch`.
    async fn start_recovery_epoch(
        &self,
        request: StartRecoveryEpochRequest,
    ) -> Result<RecoveryEpoch, Failure>;
    /// `ClaimRecoveryWorkspaces` — claims pending work rows. The
    /// scan's minted change sets (including the `lease_assertions`
    /// `no_active` predicate `harness_run::evaluate_recovery` emits)
    /// must be enforced inside the same claim transaction — upstream's
    /// adapter mint writes no separate assertion row but expires the
    /// lease atomically.
    async fn claim_recovery_workspaces(
        &self,
        request: ClaimRecoveryWorkspaceRequest,
    ) -> Result<Vec<RecoveryWorkspaceClaim>, Failure>;
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
    /// `ListFailedRecoveryWorkspaces` — read-only: it takes no
    /// coordinator lease and changes nothing.
    async fn list_failed_recovery_workspaces(
        &self,
        epoch_generation: i64,
        limit: u32,
    ) -> Result<FailedRecoveryWorkspaces, Failure>;
}

/// `RecoveryClaimabilityReader` — supplies the durable recovery gate
/// for a run. It is separate from an aggregate read because
/// claimability is an admission decision derived from recovery
/// epoch/workspace facts, not caller state.
#[trait_variant::make(Send)]
pub trait RecoveryClaimabilityReader {
    /// `RecoveryClaimability`.
    async fn recovery_claimability(
        &self,
        scope: TrustedScope,
        task_id: TaskId,
        run_id: RunId,
    ) -> Result<Claimability, Failure>;
}

/// `DispatchableRunReader` lists the Runs the harness dispatcher may
/// start (harness phase 3a decision 1), across every Workspace, oldest
/// Task first. It is a read-only projection: admission is still decided
/// by the fenced `StartHarnessRun` or Claim commit.
#[trait_variant::make(Send)]
pub trait DispatchableRunReader {
    /// `ListDispatchableRuns`.
    async fn list_dispatchable_runs(
        &self,
        request: ListDispatchableRunsRequest,
    ) -> Result<Vec<DispatchableRun>, Failure>;
}

/// `CompletionReceiptStore` records bounded immutable evidence after an
/// invocation and before settlement (upstream `port.CompletionReceiptStore`).
/// A future external-effect owner may call this boundary; B08 itself
/// performs no provider or Tool invocation.
#[trait_variant::make(Send)]
pub trait CompletionReceiptStore {
    /// `RecordCompletionReceipt`.
    async fn record_completion_receipt(
        &self,
        request: RecordCompletionReceiptRequest,
    ) -> Result<(), Failure>;
}

/// `RecordCompletionReceiptRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordCompletionReceiptRequest {
    /// The authenticated scope.
    pub scope: TrustedScope,
    /// The immutable completion evidence.
    pub receipt: CompletionReceipt,
    /// The held lease bearer fencing the write.
    pub lease_credential: LeaseCredential,
    /// The held lease generation fencing the write.
    pub lease_generation: i64,
}

/// `Clock` — the single time source services depend on.
///
/// Not a store port: no PostgreSQL impl is expected. Upstream wires
/// `retryport.SystemClock` at the composition root; the Rust
/// equivalent lands when a binary composes the execution services.
#[trait_variant::make(Send)]
pub trait Clock {
    /// `Now`.
    fn now(&self) -> OffsetDateTime;
}

/// `CompositeExecutionStore` — the façade services consume: read +
/// receipt + commit. Adapters implement the traits; services take
/// `S: ExecutionRead + CompositeStore` (+ `LeaseCredentialValidator`
/// for the lease-validation method).
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

/// `port.ExecutionMetricsSnapshot` — only aggregates and durations. It
/// never contains IDs, payloads, principals, tokens, or error strings,
/// so it is safe to project through serving monitors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecutionMetricsSnapshot {
    /// `RecoveryBatchDuration` nanoseconds.
    pub recovery_batch_nanos: i64,
    /// `RecoveredRows`.
    pub recovered_rows: i64,
    /// `RecoveryLockWait` nanoseconds.
    pub recovery_lock_nanos: i64,
    /// `SchedulerQueueDepth`.
    pub scheduler_queue_depth: i64,
    /// `PoolWait` nanoseconds.
    pub pool_wait_nanos: i64,
    /// `OldestRecordAge` nanoseconds.
    pub oldest_record_nanos: i64,
    /// `TableRowCount`.
    pub table_row_count: i64,
    /// `HeldRecordCount`.
    pub held_record_count: i64,
    /// `PendingOutboxCount`.
    pub pending_outbox_count: i64,
    /// `ReconciliationBacklog`.
    pub reconciliation_backlog: i64,
}

/// The task domain's aggregate, re-exported for signature clarity.
pub type TaskAggregate = task::TaskAggregate;
