//! Execution domain — pure synchronous port of
//! `central/internal/execution/domain.go`.
//!
//! No async, no I/O, no clock reads: every evaluator receives the
//! authoritative [`ExecutionState`], the command's optimistic
//! [`ExpectedVersions`], and [`EvaluationMetadata`] carrying `now`,
//! identities, and evidence ids. Output is an [`ExecutionChangeSet`]
//! the adapter commits atomically — the domain never persists.

use std::collections::{BTreeMap, BTreeSet};

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ApprovalId, ExecutionEventId, OutboxId, RunId, StepAttemptId, StepId, TaskId,
    ToolCallAttemptId, ToolCallId, WorkspaceId,
};
use central_task::domain as task;
use central_task::execution_facade::{self, ExecutionTransition, ExecutionTransitionResult};
use sha2::Digest;
use time::{Duration, OffsetDateTime};

// ---------------------------------------------------------------------------
// Limits and retention (pinned by upstream domain_test.go).
// ---------------------------------------------------------------------------

/// Event payloads cap at 64 KiB.
pub const EVENT_PAYLOAD_MAX_BYTES: usize = 64 * 1024;
/// Outbox catalog payloads cap at 64 KiB.
pub const OUTBOX_PAYLOAD_MAX_BYTES: usize = 64 * 1024;
/// Completion outcome payloads cap at 256 KiB.
pub const OUTCOME_PAYLOAD_MAX_BYTES: usize = 256 * 1024;
/// Invocation context payloads cap at 256 KiB.
pub const CONTEXT_PAYLOAD_MAX_BYTES: usize = 256 * 1024;
/// Checkpoint evidence payloads cap at 1 MiB.
pub const CHECKPOINT_PAYLOAD_MAX_BYTES: usize = 1024 * 1024;

/// Reconciliation evidence caps.
pub const MAX_RECONCILIATION_EVIDENCE: usize = 32;
pub const MAX_RECONCILIATION_EVIDENCE_REFERENCE_BYTES: usize = 4 * 1024;
pub const MAX_RECONCILIATION_EVIDENCE_TOTAL_BYTES: usize = 64 * 1024;

/// Default executor lease length.
pub const DEFAULT_LEASE_DURATION: Duration = Duration::seconds(30);

/// Default retention: operational rows seven days, evidence ninety.
pub const RETENTION_OPERATIONAL: Duration = Duration::days(7);
pub const RETENTION_EVIDENCE: Duration = Duration::days(90);

/// Go's zero `time.Time` sentinel (0001-01-01T00:00:00Z).
pub const ZERO_TIME: OffsetDateTime = match OffsetDateTime::from_unix_timestamp(-62_135_596_800) {
    Ok(t) => t,
    Err(_) => unreachable!(),
};

/// The lease credential is exactly 32 bytes / 256 bits of entropy.
pub const LEASE_CREDENTIAL_BYTES: usize = 32;

/// Nil sentinels — Go `uuid.Nil` used for absent optional identities.
/// Foundation ids have no `Default` by design; zero bytes reconstruct
/// the upstream sentinel at the domain boundary.
pub const NIL_STEP_ATTEMPT_ID: StepAttemptId = StepAttemptId::from_trusted_db_bytes([0; 16]);
/// Nil `ToolCallId`.
pub const NIL_TOOL_CALL_ID: ToolCallId = ToolCallId::from_trusted_db_bytes([0; 16]);
/// Nil `ToolCallAttemptId`.
pub const NIL_TOOL_CALL_ATTEMPT_ID: ToolCallAttemptId =
    ToolCallAttemptId::from_trusted_db_bytes([0; 16]);
/// Nil `StepId`.
pub const NIL_STEP_ID: StepId = StepId::from_trusted_db_bytes([0; 16]);
/// Nil `ApprovalId`.
pub const NIL_APPROVAL_ID: ApprovalId = ApprovalId::from_trusted_db_bytes([0; 16]);

// ---------------------------------------------------------------------------
// Failure reasons — the `Failure{Class, Reason}` port. `kind` is upstream
// `Class`; `code` is upstream `Reason`.
// ---------------------------------------------------------------------------

fn failure(kind: FailureKind, reason: &'static str) -> Failure {
    Failure::new(kind, reason, "execution evaluation refused")
}

// ---------------------------------------------------------------------------
// Identity newtypes the execution aggregate owns (upstream `domain.go`
// IDs are bare random `[16]byte` values — UUIDv7 bytes are used here so
// generation never blocks on crypto/rand plumbing, uniqueness preserved).
// ---------------------------------------------------------------------------

macro_rules! opaque_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            /// Fresh random identifier (UUIDv7 bytes — 122 bits unique).
            #[must_use]
            pub fn new() -> Self {
                Self(*uuid::Uuid::now_v7().as_bytes())
            }
            /// Zero is the Go `{}` sentinel — `valid()` is false.
            #[must_use]
            pub fn is_nil(&self) -> bool {
                self.0 == [0u8; 16]
            }
        }
    };
}

opaque_id!(
    LogicalOperationId,
    "Idempotency identity shared across retry successors of one logical operation."
);
opaque_id!(
    PhysicalAttemptId,
    "Identity of one physical execution attempt (checkpoint lineage + runtime assertions)."
);
opaque_id!(
    InvocationId,
    "Identity of one invoked in-flight window (response/settlement correlation)."
);
opaque_id!(
    ProviderTurnId,
    "B09 provider-turn identity (receipt correlation only — B09 runtime paths are not wired)."
);

impl std::fmt::Display for LogicalOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", uuid::Uuid::from_bytes(self.0))
    }
}
impl std::fmt::Display for PhysicalAttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", uuid::Uuid::from_bytes(self.0))
    }
}
impl std::fmt::Display for InvocationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", uuid::Uuid::from_bytes(self.0))
    }
}
impl std::fmt::Display for ProviderTurnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", uuid::Uuid::from_bytes(self.0))
    }
}

// ---------------------------------------------------------------------------
// Capabilities and trusted scope.
// ---------------------------------------------------------------------------

/// Closed capability vocabulary the execution commands authorize under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// Runs execution attempts.
    Executor,
    /// Approves or rejects gated operations.
    Approver,
    /// Operator lane — cancellation, reconciliation, approvals successor.
    WorkspaceOperator,
    /// Coordinator fence for recovery epochs.
    RecoveryCoordinator,
}

impl Capability {
    /// Stable machine name (upstream `Capability` string value).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Executor => "executor",
            Self::Approver => "approver",
            Self::WorkspaceOperator => "workspace_operator",
            Self::RecoveryCoordinator => "recovery_coordinator",
        }
    }
}

/// The trusted scope a transport adapter authenticates; the execution
/// domain treats it as input — it never widens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedScope {
    /// Authenticated principal (subject).
    pub principal_id: String,
    /// The workspace every command selects.
    pub workspace_id: WorkspaceId,
    /// Closed capability set.
    pub capabilities: BTreeSet<Capability>,
}

impl TrustedScope {
    /// Builds a scope; refuses a blank principal or nil workspace.
    pub fn new(
        principal_id: &str,
        workspace_id: WorkspaceId,
        capabilities: &[Capability],
    ) -> Result<Self, Failure> {
        if principal_id.trim().is_empty() || workspace_id.is_nil() {
            return Err(failure(FailureKind::Invalid, "INVALID_SCOPE"));
        }
        let mut set = BTreeSet::new();
        for cap in capabilities {
            set.insert(*cap);
        }
        Ok(Self {
            principal_id: principal_id.to_string(),
            workspace_id,
            capabilities: set,
        })
    }
    /// Whether the scope holds `capability`.
    #[must_use]
    pub fn allows(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

// ---------------------------------------------------------------------------
// Request fingerprint — SHA-256 over the canonical request encoding.
// ---------------------------------------------------------------------------

/// SHA-256 digest binding a command receipt to one canonical request.
pub type RequestFingerprint = [u8; 32];

/// Hashes the canonical request encoding.
#[must_use]
pub fn new_request_fingerprint(canonical: &[u8]) -> RequestFingerprint {
    sha2::Sha256::digest(canonical).into()
}

/// `FailureReason` — the bounded vocabulary lives in `harness_run`;
/// the alias keeps command fields ergonomic (`""` = absent).
pub type FailureReason = &'static str;

/// Whether the fingerprint was supplied (non-zero).
#[must_use]
pub fn fingerprint_valid(fingerprint: &RequestFingerprint) -> bool {
    *fingerprint != [0u8; 32]
}

// ---------------------------------------------------------------------------
// State vocabularies.
// ---------------------------------------------------------------------------

macro_rules! closed_state {
    ($name:ident, $($variant:ident => $value:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $(#[doc = concat!("`", $value, "`")] $variant),+
        }
        impl $name {
            /// The persisted string form.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
            /// Parses the persisted form; `None` on anything else.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($value => Some(Self::$variant)),+ , _ => None }
            }
            /// All variants in declaration order.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[$(Self::$variant),+]
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

closed_state! {
    StepState,
    StepQueued => "queued",
    StepRunning => "running",
    StepWaiting => "waiting",
    StepSettling => "settling",
    StepReconciliation => "reconciliation",
    StepSucceeded => "succeeded",
    StepFailed => "failed",
    StepCancelled => "cancelled",
}

closed_state! {
    AttemptState,
    AttemptPrepared => "prepared",
    AttemptInvoked => "invoked",
    AttemptSettling => "settling",
    AttemptReconciliation => "reconciliation",
    AttemptSucceeded => "succeeded",
    AttemptFailed => "failed",
    AttemptCancelled => "cancelled",
}

closed_state! {
    ToolCallState,
    ToolCallQueued => "queued",
    ToolCallPrepared => "prepared",
    ToolCallInvoked => "invoked",
    ToolCallSettling => "settling",
    ToolCallReconciliation => "reconciliation",
    ToolCallSucceeded => "succeeded",
    ToolCallFailed => "failed",
    ToolCallCancelled => "cancelled",
}

closed_state! {
    ApprovalState,
    ApprovalPending => "pending",
    ApprovalApproved => "approved",
    ApprovalRejected => "rejected",
    ApprovalExpired => "expired",
    ApprovalSuperseded => "superseded",
}

closed_state! {
    ReconciliationDisposition,
    ReconciliationResume => "resume",
    ReconciliationConfirmSucceeded => "confirm_succeeded",
    ReconciliationConfirmFailed => "confirm_failed",
    ReconciliationCancel => "cancel",
}

closed_state! {
    ReconciliationEvidenceKind,
    ReconciliationEvidenceCompletionReceipt => "completion_receipt",
    ReconciliationEvidenceCheckpoint => "checkpoint",
    ReconciliationEvidenceEvent => "event",
    ReconciliationEvidenceOperatorAttestation => "operator_attestation",
}

closed_state! {
    ApprovalAction,
    ActionResolveApproval => "resolve_approval",
}

impl StepState {
    /// Closed transition table.
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        use StepState as S;
        matches!(
            (self, to),
            (S::StepQueued, S::StepRunning)
                | (S::StepQueued, S::StepCancelled)
                | (S::StepRunning, S::StepWaiting)
                | (S::StepRunning, S::StepSettling)
                | (S::StepRunning, S::StepReconciliation)
                | (S::StepRunning, S::StepFailed)
                | (S::StepRunning, S::StepCancelled)
                | (S::StepWaiting, S::StepRunning)
                | (S::StepWaiting, S::StepCancelled)
                | (S::StepWaiting, S::StepReconciliation)
                | (S::StepSettling, S::StepSucceeded)
                | (S::StepSettling, S::StepFailed)
                | (S::StepSettling, S::StepReconciliation)
                | (S::StepSettling, S::StepCancelled)
        )
    }
    /// Whether the state is terminal.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::StepSucceeded | Self::StepFailed | Self::StepCancelled
        )
    }
}

impl AttemptState {
    /// Closed transition table.
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        use AttemptState as A;
        matches!(
            (self, to),
            (A::AttemptPrepared, A::AttemptInvoked)
                | (A::AttemptPrepared, A::AttemptCancelled)
                | (A::AttemptPrepared, A::AttemptReconciliation)
                | (A::AttemptInvoked, A::AttemptSettling)
                | (A::AttemptInvoked, A::AttemptReconciliation)
                | (A::AttemptSettling, A::AttemptSucceeded)
                | (A::AttemptSettling, A::AttemptFailed)
                | (A::AttemptSettling, A::AttemptReconciliation)
        )
    }
    /// Whether the state is terminal.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::AttemptSucceeded | Self::AttemptFailed | Self::AttemptCancelled
        )
    }
    /// Whether the attempt was invoked (owns an invocation identity).
    #[must_use]
    pub fn requires_invocation(self) -> bool {
        matches!(
            self,
            Self::AttemptInvoked
                | Self::AttemptSettling
                | Self::AttemptSucceeded
                | Self::AttemptFailed
        )
    }
}

impl ToolCallState {
    /// Closed transition table.
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        use ToolCallState as T;
        matches!(
            (self, to),
            (T::ToolCallQueued, T::ToolCallPrepared)
                | (T::ToolCallQueued, T::ToolCallCancelled)
                | (T::ToolCallPrepared, T::ToolCallInvoked)
                | (T::ToolCallPrepared, T::ToolCallCancelled)
                | (T::ToolCallPrepared, T::ToolCallReconciliation)
                | (T::ToolCallInvoked, T::ToolCallSettling)
                | (T::ToolCallInvoked, T::ToolCallReconciliation)
                | (T::ToolCallSettling, T::ToolCallSucceeded)
                | (T::ToolCallSettling, T::ToolCallFailed)
                | (T::ToolCallSettling, T::ToolCallReconciliation)
        )
    }
    /// Whether the state is terminal.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ToolCallSucceeded | Self::ToolCallFailed | Self::ToolCallCancelled
        )
    }
    /// Whether the state carries an invocation identity when an
    /// attempt inside it does.
    #[must_use]
    pub fn requires_invocation(self) -> bool {
        matches!(
            self,
            Self::ToolCallInvoked | Self::ToolCallSucceeded | Self::ToolCallFailed
        )
    }
}

impl ReconciliationDisposition {
    /// Dispositions an operator may commit (resume goes through the
    /// dedicated resume command, never `ResolveReconciliation`).
    #[must_use]
    pub fn is_resolvable(self) -> bool {
        !matches!(self, Self::ReconciliationResume)
    }
}

// ---------------------------------------------------------------------------
// Claimability — the decoration central-execution owns for task reads.
// ---------------------------------------------------------------------------

/// Whether a run is claimable in the recovery epoch's view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claimability {
    /// False means the run is barred.
    pub claimable: bool,
    /// The epoch generation this answer was evaluated under.
    pub epoch_generation: i64,
    /// Machine reason when `!claimable` (`RECOVERY_*`).
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Domain records.
// ---------------------------------------------------------------------------

/// One logical step of a run.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub id: StepId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub version: i64,
    pub sequence: i64,
    pub state: StepState,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// One physical attempt of a [`Step`].
#[derive(Debug, Clone, PartialEq)]
pub struct StepAttempt {
    pub id: StepAttemptId,
    pub step_id: StepId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    /// Logical operation shared by recovery successors.
    pub logical_operation_id: LogicalOperationId,
    /// Unique physical attempt identity.
    pub physical_attempt_id: PhysicalAttemptId,
    /// Set once invoked; links response/settlement evidence.
    pub invocation_id: InvocationId,
    /// The cancelled attempt this prepared successor replaces.
    pub predecessor_id: StepAttemptId,
    pub version: i64,
    pub sequence: i64,
    pub state: AttemptState,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// One tool call owned by a [`StepAttempt`].
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: ToolCallId,
    pub step_attempt_id: StepAttemptId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub logical_operation_id: LogicalOperationId,
    pub version: i64,
    pub sequence: i64,
    pub state: ToolCallState,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// One physical attempt of a [`ToolCall`].
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallAttempt {
    pub id: ToolCallAttemptId,
    pub tool_call_id: ToolCallId,
    pub step_attempt_id: StepAttemptId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub logical_operation_id: LogicalOperationId,
    pub physical_attempt_id: PhysicalAttemptId,
    pub invocation_id: InvocationId,
    /// The cancelled attempt this prepared successor replaces.
    pub predecessor_id: ToolCallAttemptId,
    pub version: i64,
    pub sequence: i64,
    pub state: AttemptState,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Stable subject an approval binds to.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalSubject {
    pub version: i64,
    pub logical_operation_id: LogicalOperationId,
    /// Digest of the operation the approval gates.
    pub operation_digest: RequestFingerprint,
    /// Step version the approval was recorded against.
    pub expected_step_version: i64,
}

/// Durable approval record.
#[derive(Debug, Clone, PartialEq)]
pub struct Approval {
    pub id: ApprovalId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub state: ApprovalState,
    pub subject: ApprovalSubject,
    /// The approval this one succeeds (resubmission lineage).
    pub predecessor_id: ApprovalId,
    /// Deciding principal (set on resolution).
    pub actor: String,
    /// Bounded free-form operator reason for the decision.
    pub reason_code: String,
    /// Derived from the decision event id.
    pub decision_id: [u8; 16],
    pub decided_at: OffsetDateTime,
    pub version: i64,
    pub recorded_at: OffsetDateTime,
}

/// Durable checkpoint row (schema_version 1 payload).
#[derive(Debug, Clone, PartialEq)]
pub struct Checkpoint {
    pub id: central_foundation::identity::CheckpointId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub step_attempt_id: StepAttemptId,
    pub producer_version: String,
    pub schema_version: i64,
    /// `schema_version`-validated JSON, ≤ [`CHECKPOINT_PAYLOAD_MAX_BYTES`].
    pub payload: Vec<u8>,
    /// `sha256.Sum256(payload)` — integrity bound at mint time.
    pub checksum: [u8; 32],
    pub resume_compatible: bool,
    pub validated: bool,
    pub recorded_at: OffsetDateTime,
}

/// Terminal settlement evidence for a step attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct Settlement {
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    pub invocation_id: InvocationId,
    pub final_state: AttemptState,
    /// `schema_version`-validated JSON, ≤ [`OUTCOME_PAYLOAD_MAX_BYTES`].
    pub outcome: Vec<u8>,
    /// Optional invocation context snapshot, ≤ [`CONTEXT_PAYLOAD_MAX_BYTES`].
    pub context: Vec<u8>,
    pub settled_at: OffsetDateTime,
}

/// Terminal settlement evidence for a tool-call attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSettlement {
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    /// The owning step attempt.
    pub attempt_id: StepAttemptId,
    pub tool_call_id: ToolCallId,
    pub tool_attempt_id: ToolCallAttemptId,
    pub step_attempt_id: StepAttemptId,
    pub invocation_id: InvocationId,
    pub final_state: AttemptState,
    pub outcome: Vec<u8>,
    /// Optional invocation context snapshot, ≤ [`CONTEXT_PAYLOAD_MAX_BYTES`].
    pub context: Vec<u8>,
    pub settled_at: OffsetDateTime,
}

/// One reconciliation evidence item.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconciliationEvidence {
    pub kind: ReconciliationEvidenceKind,
    pub reference: String,
}

/// Durable reconciliation record.
#[derive(Debug, Clone, PartialEq)]
pub struct Reconciliation {
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    pub disposition: ReconciliationDisposition,
    pub evidence: Vec<ReconciliationEvidence>,
    pub resolved_at: OffsetDateTime,
}

/// The lease row — fencing credential + expiry.
#[derive(Debug, Clone, PartialEq)]
pub struct Lease {
    pub workspace_id: WorkspaceId,
    pub run_id: RunId,
    /// Hash of the issued credential; empty on a recovered row.
    pub credential: LeaseCredential,
    pub generation: i64,
    pub expires_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// The persisted lease row omits the credential upstream stores only as
/// the verifier hash — `credential` present means the full credential.
impl Lease {
    /// Whether the lease is unexpired at `now`.
    #[must_use]
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.expires_at > now
    }
    /// `ValidateProjection` — the durable, credential-free portion of a
    /// lease. Persisted reads intentionally omit `credential`.
    pub fn validate_projection(&self) -> Result<(), Failure> {
        if self.workspace_id.is_nil()
            || self.run_id.is_nil()
            || self.generation <= 0
            || self.expires_at == ZERO_TIME
        {
            return Err(failure(FailureKind::Invalid, "INVALID_LEASE_PROJECTION"));
        }
        Ok(())
    }
    /// `Validate` — a full lease including its fencing verifier.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.workspace_id.is_nil()
            || self.run_id.is_nil()
            || !self.credential.valid()
            || self.generation <= 0
            || self.expires_at == ZERO_TIME
        {
            return Err(failure(FailureKind::Invalid, "INVALID_LEASE"));
        }
        Ok(())
    }
}

/// Exactly 256 bits of lease credential entropy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LeaseCredential(pub [u8; LEASE_CREDENTIAL_BYTES]);

impl LeaseCredential {
    /// Rejects anything that is not exactly 32 non-zero bytes.
    pub fn new(raw: &[u8]) -> Result<Self, Failure> {
        if raw.len() != LEASE_CREDENTIAL_BYTES {
            return Err(failure(FailureKind::Invalid, "INVALID_LEASE_CREDENTIAL"));
        }
        let mut credential = Self([0u8; LEASE_CREDENTIAL_BYTES]);
        credential.0.copy_from_slice(raw);
        if !credential.valid() {
            return Err(failure(FailureKind::Invalid, "INVALID_LEASE_CREDENTIAL"));
        }
        Ok(credential)
    }
    /// Non-zero means usable.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.0 != [0u8; LEASE_CREDENTIAL_BYTES]
    }
}

/// Intent to release the lease under its fence.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseRelease {
    pub workspace_id: WorkspaceId,
    pub run_id: RunId,
    pub credential: LeaseCredential,
    pub generation: i64,
}

impl LeaseRelease {
    /// `LeaseRelease.validate` — explicit fenced delete intent.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.workspace_id.is_nil()
            || self.run_id.is_nil()
            || !self.credential.valid()
            || self.generation <= 0
        {
            return Err(failure(FailureKind::Invalid, "INVALID_LEASE_RELEASE"));
        }
        Ok(())
    }
}

/// Intent to assert lease state atomically at commit.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseAssertion {
    pub workspace_id: WorkspaceId,
    pub run_id: RunId,
    /// True: the commit fails if any unexpired lease exists.
    pub no_active: bool,
}

/// `StepAttemptAssertion` — the parent attempt row pinned at commit.
#[derive(Debug, Clone, PartialEq)]
pub struct StepAttemptAssertion {
    pub id: StepAttemptId,
    pub step_id: StepId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub logical_operation_id: LogicalOperationId,
    pub version: i64,
    pub state: AttemptState,
}

/// `assertionFor` — snapshot of the parent attempt for the commit fence.
pub(crate) fn assertion_for(attempt: &StepAttempt) -> StepAttemptAssertion {
    StepAttemptAssertion {
        id: attempt.id,
        step_id: attempt.step_id,
        workspace_id: attempt.workspace_id,
        task_id: attempt.task_id,
        run_id: attempt.run_id,
        logical_operation_id: attempt.logical_operation_id,
        version: attempt.version,
        state: attempt.state,
    }
}

/// Durable event intent (committed to `events`).
#[derive(Debug, Clone, PartialEq)]
pub struct EventIntent {
    pub id: ExecutionEventId,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    /// Set when the event describes a tool call.
    pub tool_call_id: ToolCallId,
    /// Set when the event describes a tool-call attempt.
    pub tool_attempt_id: ToolCallAttemptId,
    pub kind: EventKind,
    /// `schema_version`-validated JSON, ≤ [`EVENT_PAYLOAD_MAX_BYTES`].
    pub payload: Vec<u8>,
    pub occurred_at: OffsetDateTime,
}

/// Outbox work intent (committed to `outbox_workspace_work`).
#[derive(Debug, Clone, PartialEq)]
pub struct OutboxIntent {
    pub id: OutboxId,
    pub workspace_id: WorkspaceId,
    /// The event this intent fans out.
    pub event_id: ExecutionEventId,
    /// The catalog event type (e.g. `attempt_settled`).
    pub catalog_type: OutboxCatalogType,
    /// `schema_version`-validated JSON, ≤ [`OUTBOX_PAYLOAD_MAX_BYTES`].
    pub payload: Vec<u8>,
    /// `command_scope:idempotency_key` — exactly-once dedup.
    pub deduplication_key: String,
    /// Producer identity for the delivery lane.
    pub producer_id: String,
    pub created_at: OffsetDateTime,
}

/// Execution event vocabulary (`events.kind`).
pub type EventKind = &'static str;

pub const EVENT_ATTEMPT_PREPARED: EventKind = "attempt_prepared";
pub const EVENT_ATTEMPT_CLAIMED: EventKind = "attempt_claimed";
pub const EVENT_ATTEMPT_HEARTBEAT: EventKind = "attempt_heartbeat";
pub const EVENT_ATTEMPT_INVOKED: EventKind = "attempt_invoked";
pub const EVENT_TOOL_CALL_PREPARED: EventKind = "tool_call_prepared";
pub const EVENT_TOOL_CALL_INVOKED: EventKind = "tool_call_invoked";
pub const EVENT_TOOL_CALL_SETTLED: EventKind = "tool_call_settled";
pub const EVENT_ATTEMPT_SETTLED: EventKind = "attempt_settled";
pub const EVENT_ATTEMPT_CANCELLED: EventKind = "attempt_cancelled";
pub const EVENT_ATTEMPT_RETRY_SCHEDULED: EventKind = "attempt_retry_scheduled";
pub const EVENT_ATTEMPT_RECONCILIATION: EventKind = "attempt_reconciliation";
pub const EVENT_ATTEMPT_RECOVERED: EventKind = "attempt_recovered";
pub const EVENT_CHECKPOINT_RECORDED: EventKind = "checkpoint_recorded";
pub const EVENT_APPROVAL_RECORDED: EventKind = "approval_recorded";
pub const EVENT_APPROVAL_RESOLVED: EventKind = "approval_resolved";
pub const EVENT_APPROVAL_EXPIRED: EventKind = "approval_expired";
pub const EVENT_APPROVAL_SUCCESSOR: EventKind = "approval_successor";
pub const EVENT_RECONCILIATION_RESOLVED: EventKind = "reconciliation_resolved";
pub const EVENT_HARNESS_RUN_STARTED: EventKind = "harness_run_started";
pub const EVENT_ATTEMPT_ABANDONED: EventKind = "attempt_abandoned";
pub const EVENT_ATTEMPT_RESUMED: EventKind = "attempt_resumed";

/// Outbox catalog event types — the persisted allowlist.
pub type OutboxCatalogType = &'static str;

pub const OUTBOX_ATTEMPT_PREPARED: OutboxCatalogType = "execution.attempt.prepared";
pub const OUTBOX_ATTEMPT_CLAIMED: OutboxCatalogType = "execution.attempt.claimed";
pub const OUTBOX_ATTEMPT_SETTLED: OutboxCatalogType = "execution.attempt.settled";
pub const OUTBOX_TOOL_CALL_PREPARED: OutboxCatalogType = "execution.tool_call.prepared";
pub const OUTBOX_TOOL_CALL_INVOKED: OutboxCatalogType = "execution.tool_call.invoked";
pub const OUTBOX_TOOL_CALL_SETTLED: OutboxCatalogType = "execution.tool_call.settled";
pub const OUTBOX_CHECKPOINT_RECORDED: OutboxCatalogType = "execution.checkpoint.recorded";
pub const OUTBOX_APPROVAL_RECORDED: OutboxCatalogType = "execution.approval.recorded";
pub const OUTBOX_RECONCILIATION_REQUIRED: OutboxCatalogType = "execution.reconciliation.required";

/// `OutboxCatalogType.valid()` — the persisted allowlist.
#[must_use]
pub fn outbox_catalog_type_valid(catalog: &str) -> bool {
    matches!(
        catalog,
        OUTBOX_ATTEMPT_PREPARED
            | OUTBOX_ATTEMPT_CLAIMED
            | OUTBOX_ATTEMPT_SETTLED
            | OUTBOX_TOOL_CALL_PREPARED
            | OUTBOX_TOOL_CALL_INVOKED
            | OUTBOX_TOOL_CALL_SETTLED
            | OUTBOX_CHECKPOINT_RECORDED
            | OUTBOX_APPROVAL_RECORDED
            | OUTBOX_RECONCILIATION_REQUIRED
    )
}

/// The commit-scope dedup coordinate for each event kind
/// (upstream `commandScope`).
#[must_use]
pub fn command_scope(kind: EventKind) -> &'static str {
    match kind {
        EVENT_ATTEMPT_PREPARED => "execution.prepare",
        EVENT_ATTEMPT_CLAIMED => "execution.claim",
        EVENT_ATTEMPT_HEARTBEAT => "execution.heartbeat",
        EVENT_ATTEMPT_INVOKED => "execution.mark_invoked",
        EVENT_ATTEMPT_RETRY_SCHEDULED => "execution.schedule_retry",
        EVENT_ATTEMPT_RECONCILIATION => "execution.enter_reconciliation",
        EVENT_TOOL_CALL_PREPARED => "execution.prepare_tool_call",
        EVENT_TOOL_CALL_INVOKED => "execution.mark_tool_call_invoked",
        EVENT_TOOL_CALL_SETTLED => "execution.settle_tool_call",
        EVENT_ATTEMPT_SETTLED => "execution.settle",
        EVENT_ATTEMPT_CANCELLED => "execution.cancel",
        EVENT_CHECKPOINT_RECORDED => "execution.record_checkpoint",
        EVENT_APPROVAL_RECORDED => "execution.record_approval",
        EVENT_APPROVAL_RESOLVED => "execution.resolve_approval",
        EVENT_APPROVAL_EXPIRED => "execution.expire_approval",
        EVENT_APPROVAL_SUCCESSOR => "execution.create_approval_successor",
        EVENT_RECONCILIATION_RESOLVED => "execution.resolve_reconciliation",
        EVENT_HARNESS_RUN_STARTED => "execution.start_harness_run",
        EVENT_ATTEMPT_ABANDONED => "execution.abandon_prepared",
        EVENT_ATTEMPT_RESUMED => "execution.resume_reconciled_attempt",
        _ => "execution.unknown",
    }
}

// ---------------------------------------------------------------------------
// Payload sanitizer — Go `encoding/json` canonical form: keys sorted,
// strings HTML-escaped, schema shape enforced.
// ---------------------------------------------------------------------------

/// Rewrites the JSON literal bytes Go's `encoding/json` escapes in
/// strings: `<`→`<`, `>`→`>`, `&`→`&`,
/// U+2028→`\u2028`, U+2029→`\u2029`. Byte-rewrite is safe because none
/// of these bytes are JSON structural characters.
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

/// Payload shape allowlist (upstream `payloadSchema`): key → child
/// schema; `Leaf` is a scalar field.
#[derive(Clone, Copy)]
pub(crate) enum SchemaNode {
    Leaf,
    Children(PayloadSchema),
}

pub(crate) type PayloadSchema = &'static [(&'static str, SchemaNode)];

const METADATA_SCHEMA: PayloadSchema = &[
    ("producer_version", SchemaNode::Leaf),
    ("schema_version", SchemaNode::Leaf),
    ("source", SchemaNode::Leaf),
    ("sequence", SchemaNode::Leaf),
];

const EVENT_PAYLOAD_SCHEMA: PayloadSchema = &[
    ("schema_version", SchemaNode::Leaf),
    ("type", SchemaNode::Leaf),
    ("reason_code", SchemaNode::Leaf),
    ("state", SchemaNode::Leaf),
    ("sequence", SchemaNode::Leaf),
    ("occurred_at", SchemaNode::Leaf),
    ("logical_operation_id", SchemaNode::Leaf),
    ("attempt_id", SchemaNode::Leaf),
    ("invocation_id", SchemaNode::Leaf),
    ("message", SchemaNode::Leaf),
    ("detail", SchemaNode::Leaf),
    ("metadata", SchemaNode::Children(METADATA_SCHEMA)),
];

const OUTBOX_PAYLOAD_SCHEMA: PayloadSchema = &[
    ("schema_version", SchemaNode::Leaf),
    ("event_id", SchemaNode::Leaf),
    ("catalog_type", SchemaNode::Leaf),
    ("deduplication_key", SchemaNode::Leaf),
    ("metadata", SchemaNode::Children(METADATA_SCHEMA)),
];

pub(crate) const OUTCOME_PAYLOAD_SCHEMA: PayloadSchema = &[
    ("schema_version", SchemaNode::Leaf),
    ("status", SchemaNode::Leaf),
    ("summary", SchemaNode::Leaf),
    ("reason_code", SchemaNode::Leaf),
    ("metadata", SchemaNode::Children(METADATA_SCHEMA)),
];

pub(crate) const CONTEXT_PAYLOAD_SCHEMA: PayloadSchema = &[
    ("schema_version", SchemaNode::Leaf),
    ("summary", SchemaNode::Leaf),
    ("state", SchemaNode::Leaf),
    ("metadata", SchemaNode::Children(METADATA_SCHEMA)),
];

const CONTINUATION_SCHEMA: PayloadSchema = &[
    ("state", SchemaNode::Leaf),
    ("cursor", SchemaNode::Leaf),
    ("sequence", SchemaNode::Leaf),
    ("summary", SchemaNode::Leaf),
    ("metadata", SchemaNode::Children(METADATA_SCHEMA)),
];

const CHECKPOINT_PAYLOAD_SCHEMA: PayloadSchema = &[
    ("schema_version", SchemaNode::Leaf),
    ("producer_version", SchemaNode::Leaf),
    ("continuation", SchemaNode::Children(CONTINUATION_SCHEMA)),
    ("metadata", SchemaNode::Children(METADATA_SCHEMA)),
];

const SENSITIVE_PAYLOAD_KEYS: &[&str] = &[
    "access_token",
    "api_key",
    "api_token",
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "secret_key",
    "token",
];

/// `sanitizeObject` — case-insensitive sensitive-key refusal plus
/// schema allowlist traversal.
fn sanitize_object(
    object: &serde_json::Map<String, serde_json::Value>,
    schema: PayloadSchema,
) -> Result<(), Failure> {
    for (key, value) in object {
        if SENSITIVE_PAYLOAD_KEYS.contains(&key.to_lowercase().as_str()) {
            return Err(failure(FailureKind::Invalid, "UNSANITIZED_PAYLOAD"));
        }
        let child_schema = schema
            .iter()
            .find(|(name, _)| *name == key.as_str())
            .map(|(_, child)| *child);
        let Some(child_schema) = child_schema else {
            return Err(failure(FailureKind::Invalid, "UNKNOWN_PAYLOAD_FIELD"));
        };
        match value {
            serde_json::Value::Object(map) => {
                let SchemaNode::Children(inner) = child_schema else {
                    return Err(failure(FailureKind::Invalid, "UNKNOWN_PAYLOAD_FIELD"));
                };
                sanitize_object(map, inner)?;
            }
            serde_json::Value::Array(items) => {
                let SchemaNode::Children(inner) = child_schema else {
                    return Err(failure(FailureKind::Invalid, "UNKNOWN_PAYLOAD_FIELD"));
                };
                for item in items {
                    let serde_json::Value::Object(map) = item else {
                        return Err(failure(FailureKind::Invalid, "UNKNOWN_PAYLOAD_FIELD"));
                    };
                    sanitize_object(map, inner)?;
                }
            }
            _ => {
                if matches!(child_schema, SchemaNode::Children(_)) {
                    return Err(failure(FailureKind::Invalid, "UNKNOWN_PAYLOAD_FIELD"));
                }
            }
        }
    }
    Ok(())
}

/// `sanitizePayload` — parses, schema-checks, and re-encodes the payload
/// in Go canonical form (sorted keys, HTML-escaped strings). Bare
/// scalars are refused; error codes are the upstream vocabulary.
pub(crate) fn sanitize_payload(
    raw: &[u8],
    limit: usize,
    schema: PayloadSchema,
) -> Result<Vec<u8>, Failure> {
    if raw.len() > limit {
        return Err(failure(FailureKind::Invalid, "PAYLOAD_TOO_LARGE"));
    }
    let value: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(value) => value,
        Err(_) => return Err(failure(FailureKind::Invalid, "INVALID_PAYLOAD")),
    };
    let serde_json::Value::Object(object) = &value else {
        return Err(failure(FailureKind::Invalid, "INVALID_PAYLOAD"));
    };
    sanitize_object(object, schema)?;
    let mut encoded =
        serde_json::to_vec(&value).map_err(|_| failure(FailureKind::Invalid, "INVALID_PAYLOAD"))?;
    encoded = go_json_escapes(&encoded);
    if encoded.len() > limit {
        return Err(failure(FailureKind::Invalid, "PAYLOAD_TOO_LARGE"));
    }
    Ok(encoded)
}

/// `validateOptionalPayload` — empty means absent; a present payload
/// must be schema-clean and already in Go canonical byte form.
pub(crate) fn validate_optional_payload(
    payload: &[u8],
    limit: usize,
    schema: PayloadSchema,
) -> Result<(), Failure> {
    if payload.is_empty() {
        return Ok(());
    }
    let sanitized = sanitize_payload(payload, limit, schema)?;
    if sanitized != payload {
        return Err(failure(FailureKind::Invalid, "UNSANITIZED_PAYLOAD"));
    }
    Ok(())
}

/// `NewEventPayload` — sanitized ≤64 KiB event body.
pub fn new_event_payload(raw: &[u8]) -> Result<Vec<u8>, Failure> {
    sanitize_payload(raw, EVENT_PAYLOAD_MAX_BYTES, EVENT_PAYLOAD_SCHEMA)
}

/// `NewOutboxPayload` — sanitized ≤64 KiB outbox body.
pub fn new_outbox_payload(raw: &[u8]) -> Result<Vec<u8>, Failure> {
    sanitize_payload(raw, OUTBOX_PAYLOAD_MAX_BYTES, OUTBOX_PAYLOAD_SCHEMA)
}

/// `NewOutcomePayload` — sanitized ≤256 KiB settlement body.
pub fn new_outcome_payload(raw: &[u8]) -> Result<Vec<u8>, Failure> {
    sanitize_payload(raw, OUTCOME_PAYLOAD_MAX_BYTES, OUTCOME_PAYLOAD_SCHEMA)
}

/// `NewContextPayload` — sanitized ≤256 KiB invocation context.
pub fn new_context_payload(raw: &[u8]) -> Result<Vec<u8>, Failure> {
    sanitize_payload(raw, CONTEXT_PAYLOAD_MAX_BYTES, CONTEXT_PAYLOAD_SCHEMA)
}

/// `NewCheckpoint` — bounded immutable inline continuation evidence:
/// mints the identity and binds `sha256(payload)` as the checksum.
/// All selector and producer fields stay zero — the recording command
/// binds them.
pub fn new_checkpoint(payload: &[u8]) -> Result<Checkpoint, Failure> {
    use central_foundation::identity::{RunId, StepAttemptId, StepId, TaskId, WorkspaceId};
    let sanitized = sanitize_payload(
        payload,
        CHECKPOINT_PAYLOAD_MAX_BYTES,
        CHECKPOINT_PAYLOAD_SCHEMA,
    )?;
    let checksum: [u8; 32] = sha2::Sha256::digest(&sanitized).into();
    Ok(Checkpoint {
        id: central_foundation::identity::CheckpointId::new(),
        workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
        task_id: TaskId::from_trusted_db_bytes([0; 16]),
        run_id: RunId::from_trusted_db_bytes([0; 16]),
        step_id: StepId::from_trusted_db_bytes([0; 16]),
        step_attempt_id: StepAttemptId::from_trusted_db_bytes([0; 16]),
        producer_version: String::new(),
        schema_version: 0,
        payload: sanitized,
        checksum,
        resume_compatible: false,
        validated: false,
        recorded_at: ZERO_TIME,
    })
}

/// `NewCheckpointPayload` — the checkpoint payload half only.
pub fn new_checkpoint_payload(raw: &[u8]) -> Result<Vec<u8>, Failure> {
    sanitize_payload(raw, CHECKPOINT_PAYLOAD_MAX_BYTES, CHECKPOINT_PAYLOAD_SCHEMA)
}

// ---------------------------------------------------------------------------
// Evidence serialization — identical to Go `json.Marshal` output:
// sorted keys, HTML escapes, RFC3339Nano timestamps.
// ---------------------------------------------------------------------------

/// Go `time.Time.Format(RFC3339Nano)` for a UTC instant: `Z` suffix,
/// fractional seconds trimmed of trailing zeros.
pub(crate) fn format_rfc3339_nano(t: OffsetDateTime) -> String {
    let utc = t.to_offset(time::UtcOffset::UTC);
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
    );
    let nanos = utc.nanosecond();
    if nanos == 0 {
        return format!("{base}Z");
    }
    let frac = format!("{nanos:09}");
    let trimmed = frac.trim_end_matches('0');
    format!("{base}.{trimmed}Z")
}

/// `mustJSON` — serializes an object in Go canonical byte form.
pub(crate) fn must_json(map: serde_json::Map<String, serde_json::Value>) -> Vec<u8> {
    let encoded =
        serde_json::to_vec(&serde_json::Value::Object(map)).unwrap_or_else(|_| b"{}".to_vec());
    go_json_escapes(&encoded)
}

/// `withEvidence` — appends the durable event + outbox intent to the
/// change set. The event payload's `logical_operation_id` is the Go
/// `%x` rendering (32 lowercase hex chars).
#[allow(clippy::too_many_arguments)]
pub(crate) fn with_evidence(
    envelope: &CommandEnvelope,
    meta: &EvaluationMetadata,
    mut change: ExecutionChangeSet,
    kind: EventKind,
    catalog: OutboxCatalogType,
    state: &str,
    reason: &str,
) -> Result<ExecutionChangeSet, Failure> {
    let mut payload = serde_json::Map::new();
    payload.insert("schema_version".to_string(), serde_json::json!(1));
    payload.insert("type".to_string(), serde_json::json!(kind));
    payload.insert("reason_code".to_string(), serde_json::json!(reason));
    payload.insert("state".to_string(), serde_json::json!(state));
    payload.insert(
        "occurred_at".to_string(),
        serde_json::json!(format_rfc3339_nano(meta.now)),
    );
    payload.insert(
        "logical_operation_id".to_string(),
        serde_json::json!(
            envelope
                .logical_operation
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
    );
    payload.insert(
        "attempt_id".to_string(),
        serde_json::json!(envelope.attempt_id.to_string()),
    );
    let event_payload = new_event_payload(&must_json(payload))?;

    let deduplication_key = format!("{}:{}", command_scope(kind), meta.idempotency_key);
    let mut outbox_payload = serde_json::Map::new();
    outbox_payload.insert("schema_version".to_string(), serde_json::json!(1));
    outbox_payload.insert(
        "event_id".to_string(),
        serde_json::json!(meta.event_id.to_string()),
    );
    outbox_payload.insert("catalog_type".to_string(), serde_json::json!(catalog));
    outbox_payload.insert(
        "deduplication_key".to_string(),
        serde_json::json!(deduplication_key),
    );
    let outbox_payload = new_outbox_payload(&must_json(outbox_payload))?;

    change.events.push(EventIntent {
        id: meta.event_id,
        workspace_id: envelope.workspace_id,
        task_id: envelope.task_id,
        run_id: envelope.run_id,
        step_id: envelope.step_id,
        attempt_id: envelope.attempt_id,
        tool_call_id: NIL_TOOL_CALL_ID,
        tool_attempt_id: NIL_TOOL_CALL_ATTEMPT_ID,
        kind,
        payload: event_payload,
        occurred_at: meta.now,
    });
    change.outbox.push(OutboxIntent {
        id: meta.outbox_id,
        workspace_id: envelope.workspace_id,
        event_id: meta.event_id,
        catalog_type: catalog,
        payload: outbox_payload,
        deduplication_key,
        producer_id: meta.producer_id.clone(),
        created_at: meta.now,
    });
    Ok(change)
}

/// `withToolEvidence` — `with_evidence` plus tool ids on the event.
#[allow(clippy::too_many_arguments)]
pub(crate) fn with_tool_evidence(
    envelope: &CommandEnvelope,
    meta: &EvaluationMetadata,
    change: ExecutionChangeSet,
    tool_call_id: ToolCallId,
    tool_attempt_id: ToolCallAttemptId,
    kind: EventKind,
    catalog: OutboxCatalogType,
    state: &str,
    reason: &str,
) -> Result<ExecutionChangeSet, Failure> {
    if tool_call_id.is_nil() || tool_attempt_id.is_nil() {
        return Err(failure(FailureKind::Invalid, "INVALID_TOOL_CALL_IDENTITY"));
    }
    let mut result = with_evidence(envelope, meta, change, kind, catalog, state, reason)?;
    if let Some(event) = result.events.last_mut() {
        event.tool_call_id = tool_call_id;
        event.tool_attempt_id = tool_attempt_id;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// ExecutionState — the authoritative snapshot a command evaluates
// against (upstream `ExecutionState`).
// ---------------------------------------------------------------------------

/// The durable state a command envelope carries/selects.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionState {
    /// The task aggregate (task + current run).
    pub task: task::TaskAggregate,
    /// The current step, when one exists.
    pub step: Option<Step>,
    /// The active step attempt, when one exists.
    pub attempt: Option<StepAttempt>,
    /// Tool calls under the attempt.
    pub tool_calls: Vec<ToolCall>,
    /// Tool-call attempts under the attempt.
    pub tool_attempts: Vec<ToolCallAttempt>,
    /// The run's lease row, when one exists (expired or active).
    pub lease: Option<Lease>,
    /// The step's open approval, when one exists.
    pub approval: Option<Approval>,
}

// ---------------------------------------------------------------------------
// ExpectedVersions + EvaluationMetadata + CommandEnvelope.
// ---------------------------------------------------------------------------

/// The optimistic guards the caller asserts; `0` means "absent".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpectedVersions {
    pub task: i64,
    pub run: i64,
    pub step: i64,
    pub attempt: i64,
    pub tool_call: i64,
    pub tool_attempt: i64,
    pub approval: i64,
}

/// Evaluation facts the application supplies — the domain's clock and
/// evidence identity source.
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationMetadata {
    pub principal_id: String,
    pub capability: Capability,
    pub idempotency_key: String,
    pub fingerprint: RequestFingerprint,
    pub now: OffsetDateTime,
    pub event_id: ExecutionEventId,
    pub outbox_id: OutboxId,
    pub producer_id: String,
}

/// The selector + guard every command embeds.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandEnvelope {
    pub scope: TrustedScope,
    pub workspace_id: WorkspaceId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub step_id: StepId,
    pub attempt_id: StepAttemptId,
    pub logical_operation: LogicalOperationId,
    pub expected: ExpectedVersions,
    /// Digest of the operation an approval gates.
    pub operation_digest: RequestFingerprint,
    /// Fenced commands carry the lease credential.
    pub lease_credential: LeaseCredential,
    /// Fenced commands carry the asserted generation.
    pub lease_generation: i64,
    /// Unfenced commands assert no active lease exists.
    pub assert_no_active_lease: bool,
    /// Caller-side state hint — the service always replaces it with
    /// authoritative state before evaluation.
    pub state: ExecutionState,
}

// ---------------------------------------------------------------------------
// Change set — the atomic write unit.
// ---------------------------------------------------------------------------

/// All durable mutations one command produces; validated by
/// [`build_execution_change_set`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecutionChangeSet {
    pub steps: Vec<Step>,
    pub attempts: Vec<StepAttempt>,
    pub tool_calls: Vec<ToolCall>,
    pub tool_attempts: Vec<ToolCallAttempt>,
    pub approvals: Vec<Approval>,
    pub checkpoints: Vec<Checkpoint>,
    pub settlements: Vec<Settlement>,
    pub tool_settlements: Vec<ToolSettlement>,
    pub reconciliations: Vec<Reconciliation>,
    pub leases: Vec<Lease>,
    pub lease_releases: Vec<LeaseRelease>,
    pub lease_assertions: Vec<LeaseAssertion>,
    pub attempt_assertions: Vec<StepAttemptAssertion>,
    pub events: Vec<EventIntent>,
    pub outbox: Vec<OutboxIntent>,
    /// The task-domain half of the atomic commit (`None` = untouched).
    pub task_transition: Option<ExecutionTransitionResult>,
}

impl ExecutionChangeSet {
    /// `NewExecutionChangeSet`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// build_execution_change_set — the gate every mutation passes through.
// ---------------------------------------------------------------------------

/// `BuildExecutionChangeSet` — validates every record before returning
/// any approved mutation. It never truncates or silently sanitizes
/// persistence input.
pub fn build_execution_change_set(
    candidate: ExecutionChangeSet,
) -> Result<ExecutionChangeSet, Failure> {
    validate_attempt_identities(
        &candidate.attempts,
        &candidate.tool_attempts,
        &resumed_attempts(&candidate.reconciliations),
    )?;
    validate_active_attempt_cardinality(&candidate.attempts, &candidate.tool_attempts)?;
    let mut hierarchy_parents: Vec<StepAttempt> = candidate.attempts.clone();
    let mut parent_ids: BTreeSet<StepAttemptId> = candidate.attempts.iter().map(|a| a.id).collect();
    for assertion in &candidate.attempt_assertions {
        if assertion.id.is_nil()
            || assertion.step_id.is_nil()
            || assertion.workspace_id.is_nil()
            || assertion.task_id.is_nil()
            || assertion.run_id.is_nil()
            || assertion.logical_operation_id.is_nil()
            || assertion.version <= 0
            || assertion.state != AttemptState::AttemptInvoked
        {
            return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_ASSERTION"));
        }
        if !parent_ids.insert(assertion.id) {
            return Err(failure(
                FailureKind::Conflict,
                "DUPLICATE_ATTEMPT_ASSERTION",
            ));
        }
        hierarchy_parents.push(StepAttempt {
            id: assertion.id,
            step_id: assertion.step_id,
            workspace_id: assertion.workspace_id,
            task_id: assertion.task_id,
            run_id: assertion.run_id,
            logical_operation_id: assertion.logical_operation_id,
            physical_attempt_id: PhysicalAttemptId::default(),
            invocation_id: InvocationId::default(),
            predecessor_id: NIL_STEP_ATTEMPT_ID,
            version: assertion.version,
            sequence: 0,
            state: assertion.state,
            created_at: ZERO_TIME,
            updated_at: ZERO_TIME,
        });
    }
    validate_tool_hierarchy(
        &hierarchy_parents,
        &candidate.tool_calls,
        &candidate.tool_attempts,
    )?;
    let hierarchy_parents_by_id: BTreeMap<StepAttemptId, &StepAttempt> =
        hierarchy_parents.iter().map(|p| (p.id, p)).collect();
    let attempts_by_id: BTreeMap<StepAttemptId, &StepAttempt> =
        candidate.attempts.iter().map(|a| (a.id, a)).collect();
    for settlement in &candidate.settlements {
        if settlement.workspace_id.is_nil()
            || settlement.task_id.is_nil()
            || settlement.run_id.is_nil()
            || settlement.step_id.is_nil()
            || settlement.attempt_id.is_nil()
            || settlement.invocation_id.is_nil()
            || !matches!(
                settlement.final_state,
                AttemptState::AttemptSucceeded | AttemptState::AttemptFailed
            )
            || settlement.settled_at == ZERO_TIME
            || settlement.outcome.is_empty()
        {
            return Err(failure(FailureKind::Invalid, "INVALID_SETTLEMENT"));
        }
        let attempt = attempts_by_id.get(&settlement.attempt_id);
        if attempt.is_none_or(|a| {
            a.workspace_id != settlement.workspace_id
                || a.task_id != settlement.task_id
                || a.run_id != settlement.run_id
                || a.step_id != settlement.step_id
                || a.invocation_id != settlement.invocation_id
                || a.state != settlement.final_state
        }) {
            return Err(failure(FailureKind::Invalid, "SETTLEMENT_ATTEMPT_MISMATCH"));
        }
        validate_optional_payload(
            &settlement.outcome,
            OUTCOME_PAYLOAD_MAX_BYTES,
            OUTCOME_PAYLOAD_SCHEMA,
        )?;
        validate_optional_payload(
            &settlement.context,
            CONTEXT_PAYLOAD_MAX_BYTES,
            CONTEXT_PAYLOAD_SCHEMA,
        )?;
    }
    let tool_calls_by_id: BTreeMap<ToolCallId, &ToolCall> =
        candidate.tool_calls.iter().map(|c| (c.id, c)).collect();
    let tool_attempts_by_id: BTreeMap<ToolCallAttemptId, &ToolCallAttempt> =
        candidate.tool_attempts.iter().map(|a| (a.id, a)).collect();
    for settlement in &candidate.tool_settlements {
        if settlement.workspace_id.is_nil()
            || settlement.task_id.is_nil()
            || settlement.run_id.is_nil()
            || settlement.step_id.is_nil()
            || settlement.attempt_id.is_nil()
            || settlement.tool_call_id.is_nil()
            || settlement.tool_attempt_id.is_nil()
            || settlement.invocation_id.is_nil()
            || !matches!(
                settlement.final_state,
                AttemptState::AttemptSucceeded | AttemptState::AttemptFailed
            )
            || settlement.settled_at == ZERO_TIME
            || settlement.outcome.is_empty()
        {
            return Err(failure(FailureKind::Invalid, "INVALID_TOOL_SETTLEMENT"));
        }
        let call = tool_calls_by_id.get(&settlement.tool_call_id);
        let attempt = tool_attempts_by_id.get(&settlement.tool_attempt_id);
        let parent = hierarchy_parents_by_id.get(&settlement.attempt_id);
        let mismatch = match (call, attempt, parent) {
            (Some(call), Some(attempt), Some(parent)) => {
                call.step_attempt_id != settlement.attempt_id
                    || attempt.step_attempt_id != settlement.attempt_id
                    || attempt.tool_call_id != settlement.tool_call_id
                    || call.workspace_id != settlement.workspace_id
                    || call.task_id != settlement.task_id
                    || call.run_id != settlement.run_id
                    || parent.step_id != settlement.step_id
                    || parent.workspace_id != settlement.workspace_id
                    || parent.task_id != settlement.task_id
                    || parent.run_id != settlement.run_id
                    || attempt.invocation_id != settlement.invocation_id
                    || Some(call.state) != tool_call_terminal_state(settlement.final_state)
                    || attempt.state != settlement.final_state
            }
            _ => true,
        };
        if mismatch {
            return Err(failure(
                FailureKind::Invalid,
                "TOOL_SETTLEMENT_ATTEMPT_MISMATCH",
            ));
        }
        validate_optional_payload(
            &settlement.outcome,
            OUTCOME_PAYLOAD_MAX_BYTES,
            OUTCOME_PAYLOAD_SCHEMA,
        )?;
        validate_optional_payload(
            &settlement.context,
            CONTEXT_PAYLOAD_MAX_BYTES,
            CONTEXT_PAYLOAD_SCHEMA,
        )?;
    }
    for reconciliation in &candidate.reconciliations {
        if reconciliation.workspace_id.is_nil()
            || reconciliation.task_id.is_nil()
            || reconciliation.run_id.is_nil()
            || reconciliation.step_id.is_nil()
            || reconciliation.attempt_id.is_nil()
            || reconciliation.resolved_at == ZERO_TIME
        {
            return Err(failure(
                FailureKind::Invalid,
                "INVALID_RECONCILIATION_EVIDENCE",
            ));
        }
        let attempt = attempts_by_id.get(&reconciliation.attempt_id);
        let want_state = reconciliation_attempt_state(reconciliation.disposition);
        if attempt.is_none_or(|a| {
            a.workspace_id != reconciliation.workspace_id
                || a.task_id != reconciliation.task_id
                || a.run_id != reconciliation.run_id
                || a.step_id != reconciliation.step_id
                || a.state != want_state
        }) {
            return Err(failure(
                FailureKind::Invalid,
                "RECONCILIATION_ATTEMPT_MISMATCH",
            ));
        }
        clone_and_validate_evidence(&reconciliation.evidence)?;
    }
    for lease in &candidate.leases {
        lease.validate()?;
    }
    for release in &candidate.lease_releases {
        release.validate()?;
    }
    for assertion in &candidate.lease_assertions {
        if assertion.workspace_id.is_nil() || assertion.run_id.is_nil() || !assertion.no_active {
            return Err(failure(FailureKind::Invalid, "INVALID_LEASE_ASSERTION"));
        }
    }
    for release in &candidate.lease_releases {
        for assertion in &candidate.lease_assertions {
            if release.workspace_id == assertion.workspace_id && release.run_id == assertion.run_id
            {
                return Err(failure(FailureKind::Invalid, "CONFLICTING_LEASE_INTENT"));
            }
        }
    }
    for checkpoint in &candidate.checkpoints {
        if checkpoint.payload.len() > CHECKPOINT_PAYLOAD_MAX_BYTES {
            return Err(failure(FailureKind::Invalid, "PAYLOAD_TOO_LARGE"));
        }
        if sha2::Sha256::digest(&checkpoint.payload).as_slice() != checkpoint.checksum {
            return Err(failure(
                FailureKind::Invalid,
                "CHECKPOINT_CHECKSUM_MISMATCH",
            ));
        }
        let sanitized = sanitize_payload(
            &checkpoint.payload,
            CHECKPOINT_PAYLOAD_MAX_BYTES,
            CHECKPOINT_PAYLOAD_SCHEMA,
        )?;
        if checkpoint.payload != sanitized {
            return Err(failure(FailureKind::Invalid, "UNSANITIZED_PAYLOAD"));
        }
    }
    for event in &candidate.events {
        if event.payload.len() > EVENT_PAYLOAD_MAX_BYTES {
            return Err(failure(FailureKind::Invalid, "PAYLOAD_TOO_LARGE"));
        }
        let sanitized = new_event_payload(&event.payload)?;
        if event.payload != sanitized {
            return Err(failure(FailureKind::Invalid, "UNSANITIZED_PAYLOAD"));
        }
    }
    for intent in &candidate.outbox {
        if !outbox_catalog_type_valid(intent.catalog_type) {
            return Err(failure(FailureKind::Invalid, "INVALID_OUTBOX_CATALOG"));
        }
        if intent.payload.len() > OUTBOX_PAYLOAD_MAX_BYTES {
            return Err(failure(FailureKind::Invalid, "PAYLOAD_TOO_LARGE"));
        }
        let sanitized = new_outbox_payload(&intent.payload)?;
        if intent.payload != sanitized {
            return Err(failure(FailureKind::Invalid, "UNSANITIZED_PAYLOAD"));
        }
    }
    Ok(candidate)
}

/// `reconciliationAttemptState` — the attempt state a disposition
/// settles ("" upstream maps to `AttemptPrepared` here for the
/// impossible default arm).
fn reconciliation_attempt_state(disposition: ReconciliationDisposition) -> AttemptState {
    match disposition {
        ReconciliationDisposition::ReconciliationConfirmSucceeded => AttemptState::AttemptSucceeded,
        ReconciliationDisposition::ReconciliationConfirmFailed
        | ReconciliationDisposition::ReconciliationResume => AttemptState::AttemptFailed,
        ReconciliationDisposition::ReconciliationCancel => AttemptState::AttemptCancelled,
    }
}

/// `resumedAttempts` — the StepAttempts a resume Reconciliation of the
/// same change set closes.
fn resumed_attempts(reconciliations: &[Reconciliation]) -> BTreeSet<StepAttemptId> {
    reconciliations
        .iter()
        .filter(|r| {
            r.disposition == ReconciliationDisposition::ReconciliationResume
                && !r.attempt_id.is_nil()
        })
        .map(|r| r.attempt_id)
        .collect()
}

/// `attemptIdentityRecord` — one record in the logical-operation reuse
/// group (`kind` is `"step"` or `"tool"`).
#[derive(Debug, Clone)]
struct AttemptIdentityRecord {
    kind: &'static str,
    id: String,
    predecessor_id: String,
    workspace_id: WorkspaceId,
    task_id: TaskId,
    run_id: RunId,
    step_id: StepId,
    step_attempt_id: StepAttemptId,
    tool_call_id: ToolCallId,
    logical_operation: LogicalOperationId,
    invocation_id: InvocationId,
    state: AttemptState,
    sequence: i64,
    version: i64,
    /// Marks a record read from persisted state rather than proposed
    /// by a change set.
    authoritative: bool,
}

type LogicalOperationKey = (RunId, LogicalOperationId);

/// `validateAttemptIdentities` — the change-set entry point.
fn validate_attempt_identities(
    step_attempts: &[StepAttempt],
    tool_attempts: &[ToolCallAttempt],
    resumed: &BTreeSet<StepAttemptId>,
) -> Result<(), Failure> {
    validate_attempt_identities_from(step_attempts, tool_attempts, false, resumed)
}

/// `validateAttemptIdentitiesFrom` — `authoritative` marks step attempts
/// read from persisted state (command evaluation) rather than proposed
/// by a change set.
fn validate_attempt_identities_from(
    step_attempts: &[StepAttempt],
    tool_attempts: &[ToolCallAttempt],
    authoritative: bool,
    resumed: &BTreeSet<StepAttemptId>,
) -> Result<(), Failure> {
    let mut physical_ids: BTreeSet<PhysicalAttemptId> = BTreeSet::new();
    let mut invocation_ids: BTreeSet<InvocationId> = BTreeSet::new();
    let mut step_attempt_ids: BTreeSet<StepAttemptId> = BTreeSet::new();
    let mut step_attempts_by_id: BTreeMap<StepAttemptId, &StepAttempt> = BTreeMap::new();
    let mut tool_attempt_ids: BTreeSet<ToolCallAttemptId> = BTreeSet::new();
    let mut logical_operations: BTreeMap<LogicalOperationKey, Vec<AttemptIdentityRecord>> =
        BTreeMap::new();

    for attempt in step_attempts {
        if attempt.id.is_nil()
            || attempt.step_id.is_nil()
            || attempt.workspace_id.is_nil()
            || attempt.task_id.is_nil()
            || attempt.run_id.is_nil()
            || attempt.logical_operation_id.is_nil()
            || attempt.physical_attempt_id.is_nil()
        {
            return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_IDENTITY"));
        }
        if !step_attempt_ids.insert(attempt.id) {
            return Err(failure(
                FailureKind::Conflict,
                "DUPLICATE_PHYSICAL_ATTEMPT_ID",
            ));
        }
        step_attempts_by_id.insert(attempt.id, attempt);
        validate_attempt_identity_values(
            attempt.logical_operation_id,
            attempt.physical_attempt_id,
            attempt.invocation_id,
            attempt.state,
            &mut physical_ids,
            &mut invocation_ids,
        )?;
        let mut predecessor = String::new();
        if !attempt.predecessor_id.is_nil() {
            if attempt.predecessor_id == attempt.id {
                return Err(failure(
                    FailureKind::Invalid,
                    "INVALID_LOGICAL_OPERATION_REUSE",
                ));
            }
            predecessor = attempt.predecessor_id.to_string();
        }
        logical_operations
            .entry((attempt.run_id, attempt.logical_operation_id))
            .or_default()
            .push(AttemptIdentityRecord {
                kind: "step",
                id: attempt.id.to_string(),
                predecessor_id: predecessor,
                workspace_id: attempt.workspace_id,
                task_id: attempt.task_id,
                run_id: attempt.run_id,
                step_id: attempt.step_id,
                step_attempt_id: NIL_STEP_ATTEMPT_ID,
                tool_call_id: NIL_TOOL_CALL_ID,
                logical_operation: attempt.logical_operation_id,
                invocation_id: attempt.invocation_id,
                state: attempt.state,
                sequence: attempt.sequence,
                version: attempt.version,
                authoritative,
            });
    }

    for attempt in tool_attempts {
        if attempt.id.is_nil()
            || attempt.tool_call_id.is_nil()
            || attempt.step_attempt_id.is_nil()
            || attempt.workspace_id.is_nil()
            || attempt.task_id.is_nil()
            || attempt.run_id.is_nil()
            || attempt.logical_operation_id.is_nil()
            || attempt.physical_attempt_id.is_nil()
        {
            return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_IDENTITY"));
        }
        if !tool_attempt_ids.insert(attempt.id) {
            return Err(failure(
                FailureKind::Conflict,
                "DUPLICATE_PHYSICAL_ATTEMPT_ID",
            ));
        }
        validate_attempt_identity_values(
            attempt.logical_operation_id,
            attempt.physical_attempt_id,
            attempt.invocation_id,
            attempt.state,
            &mut physical_ids,
            &mut invocation_ids,
        )?;
        let mut predecessor = String::new();
        if !attempt.predecessor_id.is_nil() {
            if attempt.predecessor_id == attempt.id {
                return Err(failure(
                    FailureKind::Invalid,
                    "INVALID_LOGICAL_OPERATION_REUSE",
                ));
            }
            predecessor = attempt.predecessor_id.to_string();
        }
        logical_operations
            .entry((attempt.run_id, attempt.logical_operation_id))
            .or_default()
            .push(AttemptIdentityRecord {
                kind: "tool",
                id: attempt.id.to_string(),
                predecessor_id: predecessor,
                workspace_id: attempt.workspace_id,
                task_id: attempt.task_id,
                run_id: attempt.run_id,
                step_id: NIL_STEP_ID,
                step_attempt_id: attempt.step_attempt_id,
                tool_call_id: attempt.tool_call_id,
                logical_operation: attempt.logical_operation_id,
                invocation_id: attempt.invocation_id,
                state: attempt.state,
                sequence: attempt.sequence,
                version: attempt.version,
                authoritative: false,
            });
    }

    for records in logical_operations.values() {
        // Harness phase 3g decision 2 (review note (b)): the reuse check
        // groups by logical id and cannot see a resume successor's
        // predecessor, which has another logical id.
        if records.len() == 1
            && is_scoped_resume_successor(&records[0], &step_attempts_by_id, resumed)
        {
            continue;
        }
        validate_logical_operation_reuse(records)?;
    }
    Ok(())
}

/// `validateAttemptIdentityValues` — the shared physical/invocation
/// uniqueness rules (Rust enums guarantee `state.valid()`).
fn validate_attempt_identity_values(
    logical_id: LogicalOperationId,
    physical_id: PhysicalAttemptId,
    invocation_id: InvocationId,
    state: AttemptState,
    physical_ids: &mut BTreeSet<PhysicalAttemptId>,
    invocation_ids: &mut BTreeSet<InvocationId>,
) -> Result<(), Failure> {
    if logical_id.0 == physical_id.0 {
        return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_IDENTITY"));
    }
    if !physical_ids.insert(physical_id) {
        return Err(failure(
            FailureKind::Conflict,
            "DUPLICATE_PHYSICAL_ATTEMPT_ID",
        ));
    }
    let invocation_required = matches!(
        state,
        AttemptState::AttemptInvoked
            | AttemptState::AttemptSettling
            | AttemptState::AttemptSucceeded
            | AttemptState::AttemptFailed
    );
    if (invocation_required && invocation_id.is_nil())
        || (state == AttemptState::AttemptPrepared && !invocation_id.is_nil())
    {
        return Err(failure(FailureKind::Invalid, "INVALID_INVOCATION_IDENTITY"));
    }
    if invocation_id.is_nil() {
        return Ok(());
    }
    if logical_id.0 == invocation_id.0 || physical_id.0 == invocation_id.0 {
        return Err(failure(FailureKind::Invalid, "INVALID_INVOCATION_IDENTITY"));
    }
    if !invocation_ids.insert(invocation_id) {
        return Err(failure(FailureKind::Conflict, "DUPLICATE_INVOCATION_ID"));
    }
    Ok(())
}

/// `validateLogicalOperationReuse` — a logical operation id may appear
/// once, or exactly as a cancelled→prepared successor pair.
fn validate_logical_operation_reuse(records: &[AttemptIdentityRecord]) -> Result<(), Failure> {
    if records.len() == 1 {
        // A change set may create a recovery successor only together
        // with its cancelled predecessor. A lone successor StepAttempt is
        // legitimate only once it exists (authoritative), or when a later
        // command proposes it at version >= 2.
        let record = &records[0];
        if !record.predecessor_id.is_empty()
            && (record.kind != "step" || (!record.authoritative && record.version < 2))
        {
            return Err(failure(
                FailureKind::Invalid,
                "INVALID_LOGICAL_OPERATION_REUSE",
            ));
        }
        return Ok(());
    }
    if records.len() != 2 {
        return Err(failure(
            FailureKind::Invalid,
            "INVALID_LOGICAL_OPERATION_REUSE",
        ));
    }
    let (mut predecessor, mut successor) = (&records[0], &records[1]);
    if !predecessor.predecessor_id.is_empty() && successor.predecessor_id.is_empty() {
        std::mem::swap(&mut predecessor, &mut successor);
    }
    if !predecessor.predecessor_id.is_empty()
        || successor.predecessor_id != predecessor.id
        || predecessor.kind != successor.kind
        || predecessor.workspace_id != successor.workspace_id
        || predecessor.task_id != successor.task_id
        || predecessor.run_id != successor.run_id
        || predecessor.step_id != successor.step_id
        || predecessor.step_attempt_id != successor.step_attempt_id
        || predecessor.tool_call_id != successor.tool_call_id
        || predecessor.logical_operation != successor.logical_operation
        || predecessor.state != AttemptState::AttemptCancelled
        || successor.state != AttemptState::AttemptPrepared
        || successor.sequence != predecessor.sequence + 1
    {
        return Err(failure(
            FailureKind::Invalid,
            "INVALID_LOGICAL_OPERATION_REUSE",
        ));
    }
    if !predecessor.invocation_id.is_nil() {
        return Err(failure(FailureKind::Denied, "RECONCILIATION_REQUIRED"));
    }
    Ok(())
}

/// `isScopedResumeSuccessor` — the lone new StepAttempt of a
/// ResumeReconciledAttempt change set (prepared v1 seq1, never invoked,
/// predecessor closed failed by a resume Reconciliation in the same
/// change set, different step and logical id).
fn is_scoped_resume_successor(
    record: &AttemptIdentityRecord,
    by_id: &BTreeMap<StepAttemptId, &StepAttempt>,
    resumed: &BTreeSet<StepAttemptId>,
) -> bool {
    if record.kind != "step"
        || record.authoritative
        || record.predecessor_id.is_empty()
        || record.state != AttemptState::AttemptPrepared
        || record.version != 1
        || record.sequence != 1
        || !record.invocation_id.is_nil()
    {
        return false;
    }
    for id in resumed {
        if id.to_string() != record.predecessor_id {
            continue;
        }
        return by_id.get(id).is_some_and(|p| {
            p.state == AttemptState::AttemptFailed
                && !p.invocation_id.is_nil()
                && p.workspace_id == record.workspace_id
                && p.task_id == record.task_id
                && p.run_id == record.run_id
                && p.step_id != record.step_id
                && p.logical_operation_id != record.logical_operation
        });
    }
    false
}

/// `validateToolHierarchy` — calls must belong to a parent attempt and
/// children may not advance beyond their parents.
fn validate_tool_hierarchy(
    step_attempts: &[StepAttempt],
    tool_calls: &[ToolCall],
    tool_attempts: &[ToolCallAttempt],
) -> Result<(), Failure> {
    let mut parents: BTreeMap<StepAttemptId, &StepAttempt> = BTreeMap::new();
    let mut logical_owners: BTreeSet<LogicalOperationKey> = BTreeSet::new();
    for parent in step_attempts {
        parents.insert(parent.id, parent);
        logical_owners.insert((parent.run_id, parent.logical_operation_id));
    }
    let mut calls: BTreeMap<ToolCallId, &ToolCall> = BTreeMap::new();
    for call in tool_calls {
        if call.id.is_nil()
            || call.step_attempt_id.is_nil()
            || call.workspace_id.is_nil()
            || call.task_id.is_nil()
            || call.run_id.is_nil()
            || call.logical_operation_id.is_nil()
        {
            return Err(failure(FailureKind::Invalid, "INVALID_TOOL_CALL_IDENTITY"));
        }
        if calls.insert(call.id, call).is_some() {
            return Err(failure(FailureKind::Conflict, "DUPLICATE_TOOL_CALL_ID"));
        }
        if !logical_owners.insert((call.run_id, call.logical_operation_id)) {
            return Err(failure(
                FailureKind::Invalid,
                "INVALID_LOGICAL_OPERATION_REUSE",
            ));
        }
        let parent = parents.get(&call.step_attempt_id);
        if !parent.is_some_and(|p| tool_call_matches_parent(call, p)) {
            return Err(failure(FailureKind::Invalid, "PARENT_ATTEMPT_MISMATCH"));
        }
        if !tool_call_state_allowed_by_parent(call.state, parents[&call.step_attempt_id].state) {
            return Err(failure(
                FailureKind::Conflict,
                "CHILD_ADVANCES_BEYOND_PARENT",
            ));
        }
    }
    let mut recovery_predecessors: BTreeSet<ToolCallAttemptId> = BTreeSet::new();
    for successor in tool_attempts {
        if !successor.predecessor_id.is_nil() {
            recovery_predecessors.insert(successor.predecessor_id);
        }
    }
    for child in tool_attempts {
        let parent = parents.get(&child.step_attempt_id);
        if !parent.is_some_and(|p| tool_attempt_matches_parent(child, p)) {
            return Err(failure(FailureKind::Invalid, "PARENT_ATTEMPT_MISMATCH"));
        }
        let call = calls.get(&child.tool_call_id);
        if !call.is_some_and(|c| tool_attempt_matches_call(child, c)) {
            return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
        }
        if recovery_predecessors.contains(&child.id) {
            continue;
        }
        let parent_state = parents[&child.step_attempt_id].state;
        if !attempt_state_allowed_by_parent(child.state, parent_state) {
            if parent_state.is_terminal() {
                return Err(failure(
                    FailureKind::Conflict,
                    "PARENT_TERMINAL_STATE_MISMATCH",
                ));
            }
            return Err(failure(
                FailureKind::Conflict,
                "CHILD_ADVANCES_BEYOND_PARENT",
            ));
        }
        if !tool_attempt_follows_call(child.state, calls[&child.tool_call_id].state) {
            return Err(failure(FailureKind::Conflict, "TOOL_CALL_STATE_MISMATCH"));
        }
    }
    Ok(())
}

fn tool_call_matches_parent(call: &ToolCall, parent: &StepAttempt) -> bool {
    call.step_attempt_id == parent.id
        && call.workspace_id == parent.workspace_id
        && call.task_id == parent.task_id
        && call.run_id == parent.run_id
}

fn tool_attempt_matches_parent(attempt: &ToolCallAttempt, parent: &StepAttempt) -> bool {
    attempt.step_attempt_id == parent.id
        && attempt.workspace_id == parent.workspace_id
        && attempt.task_id == parent.task_id
        && attempt.run_id == parent.run_id
}

fn tool_attempt_matches_call(attempt: &ToolCallAttempt, call: &ToolCall) -> bool {
    attempt.tool_call_id == call.id
        && attempt.step_attempt_id == call.step_attempt_id
        && attempt.workspace_id == call.workspace_id
        && attempt.task_id == call.task_id
        && attempt.run_id == call.run_id
        && attempt.logical_operation_id == call.logical_operation_id
}

fn tool_call_state_allowed_by_parent(child: ToolCallState, parent: AttemptState) -> bool {
    use ToolCallState as T;
    match parent {
        AttemptState::AttemptPrepared => {
            matches!(child, T::ToolCallQueued | T::ToolCallPrepared)
        }
        AttemptState::AttemptInvoked => {
            matches!(
                child,
                T::ToolCallQueued | T::ToolCallPrepared | T::ToolCallInvoked
            ) || child.is_terminal()
        }
        AttemptState::AttemptSettling => {
            matches!(
                child,
                T::ToolCallQueued | T::ToolCallPrepared | T::ToolCallInvoked | T::ToolCallSettling
            ) || child.is_terminal()
        }
        AttemptState::AttemptReconciliation => {
            child == T::ToolCallReconciliation || child.is_terminal()
        }
        AttemptState::AttemptSucceeded => child == T::ToolCallSucceeded,
        AttemptState::AttemptFailed => child == T::ToolCallFailed,
        AttemptState::AttemptCancelled => child == T::ToolCallCancelled,
    }
}

fn attempt_state_allowed_by_parent(child: AttemptState, parent: AttemptState) -> bool {
    use AttemptState as A;
    match parent {
        A::AttemptPrepared => child == A::AttemptPrepared,
        A::AttemptInvoked => {
            matches!(child, A::AttemptPrepared | A::AttemptInvoked) || child.is_terminal()
        }
        A::AttemptSettling => {
            matches!(
                child,
                A::AttemptPrepared | A::AttemptInvoked | A::AttemptSettling
            ) || child.is_terminal()
        }
        A::AttemptReconciliation => child == A::AttemptReconciliation || child.is_terminal(),
        A::AttemptSucceeded | A::AttemptFailed | A::AttemptCancelled => child == parent,
    }
}

fn tool_attempt_follows_call(attempt: AttemptState, call: ToolCallState) -> bool {
    use AttemptState as A;
    match call {
        ToolCallState::ToolCallPrepared => attempt == A::AttemptPrepared,
        ToolCallState::ToolCallInvoked => attempt == A::AttemptInvoked,
        ToolCallState::ToolCallSettling => attempt == A::AttemptSettling,
        ToolCallState::ToolCallSucceeded => attempt == A::AttemptSucceeded,
        ToolCallState::ToolCallFailed => attempt == A::AttemptFailed,
        ToolCallState::ToolCallCancelled => attempt == A::AttemptCancelled,
        ToolCallState::ToolCallReconciliation => attempt == A::AttemptReconciliation,
        ToolCallState::ToolCallQueued => false,
    }
}

/// `ValidateActiveAttemptCardinality` — at most one non-terminal
/// StepAttempt per Run / ToolCallAttempt per ToolCall.
fn validate_active_attempt_cardinality(
    step_attempts: &[StepAttempt],
    tool_attempts: &[ToolCallAttempt],
) -> Result<(), Failure> {
    let mut active_runs: BTreeSet<RunId> = BTreeSet::new();
    for attempt in step_attempts {
        if attempt.state.is_terminal() {
            continue;
        }
        if !active_runs.insert(attempt.run_id) {
            return Err(failure(FailureKind::Conflict, "ACTIVE_ATTEMPT_CONFLICT"));
        }
    }
    let mut active_calls: BTreeSet<ToolCallId> = BTreeSet::new();
    for attempt in tool_attempts {
        if attempt.state.is_terminal() {
            continue;
        }
        if !active_calls.insert(attempt.tool_call_id) {
            return Err(failure(FailureKind::Conflict, "ACTIVE_ATTEMPT_CONFLICT"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Command types — the sealed command set of upstream domain.go.
// ---------------------------------------------------------------------------

macro_rules! envelope_command {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name {
            /// Selector, guards, and caller-state envelope.
            pub envelope: CommandEnvelope,
        }
        impl std::ops::Deref for $name {
            type Target = CommandEnvelope;
            fn deref(&self) -> &CommandEnvelope {
                &self.envelope
            }
        }
        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut CommandEnvelope {
                &mut self.envelope
            }
        }
    };
}

envelope_command!(
    ClaimCommand,
    "execution.claim — takes or renews the run lease."
);
envelope_command!(
    HeartbeatCommand,
    "execution.heartbeat — renews the held lease."
);

macro_rules! deref_envelope {
    ($name:ident) => {
        impl std::ops::Deref for $name {
            type Target = CommandEnvelope;
            fn deref(&self) -> &CommandEnvelope {
                &self.envelope
            }
        }
        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut CommandEnvelope {
                &mut self.envelope
            }
        }
    };
}

/// execution.cancel — operator-settles a requested cancellation.
#[derive(Debug, Clone, PartialEq)]
pub struct CancelCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    /// The bounded cancellation reason (`operator_request`, ...).
    pub reason_code: String,
}
deref_envelope!(CancelCommand);

/// execution.resolve_approval — approver decision on a pending approval.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolveApprovalCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub approval_id: ApprovalId,
    /// `approved` or `rejected` only.
    pub decision: ApprovalState,
}
deref_envelope!(ResolveApprovalCommand);

/// execution.expire_approval — expires a pending approval.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpireApprovalCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub approval_id: ApprovalId,
}
deref_envelope!(ExpireApprovalCommand);

/// execution.prepare — creates the step and first prepared attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct PrepareCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub physical_attempt_id: PhysicalAttemptId,
    pub step_sequence: i64,
    pub attempt_sequence: i64,
    /// Approval subject version the caller binds (approval-gated ops).
    pub approval_subject_version: i64,
    /// Step version the approval subject was recorded against.
    pub approval_expected_step_version: i64,
}
deref_envelope!(PrepareCommand);

/// execution.mark_invoked — prepared → invoked under the lease.
#[derive(Debug, Clone, PartialEq)]
pub struct MarkInvokedCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    /// Fresh invocation identity for the in-flight window.
    pub invocation_id: InvocationId,
    /// Approval subject version the caller binds (approval-gated ops).
    pub approval_subject_version: i64,
    /// Step version the approval subject was recorded against.
    pub approval_expected_step_version: i64,
}
deref_envelope!(MarkInvokedCommand);

/// execution.schedule_retry — closes the attempt and schedules a retry.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduleRetryCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    /// Delay before the retry becomes eligible.
    pub retry_after: Duration,
    /// The bounded reason code recorded on the failure.
    pub reason_code: String,
    /// Required when the attempt was invoked — the failed outcome.
    pub outcome: Vec<u8>,
    /// Optional invocation context snapshot.
    pub context: Vec<u8>,
}
deref_envelope!(ScheduleRetryCommand);

/// execution.enter_reconciliation — parks the attempt in reconciliation.
#[derive(Debug, Clone, PartialEq)]
pub struct EnterReconciliationCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    /// Why reconciliation was required (bounded vocabulary).
    pub reason_code: ProviderReconciliationReason,
}
deref_envelope!(EnterReconciliationCommand);

/// `ProviderReconciliationReason` — the closed safe explanation for an
/// ambiguous provider outcome (upstream `ProviderReconciliationReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderReconciliationReason {
    /// The provider acknowledged ambiguous delivery.
    AmbiguousDelivery,
    /// The provider's response mismatched the request.
    ResponseMismatch,
    /// The provider handoff failed.
    HandoffFailed,
}

impl ProviderReconciliationReason {
    /// Persisted string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AmbiguousDelivery => "ambiguous_delivery",
            Self::ResponseMismatch => "response_mismatch",
            Self::HandoffFailed => "handoff_failed",
        }
    }
    /// Upstream `valid()` — the closed allowlist.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ambiguous_delivery" => Some(Self::AmbiguousDelivery),
            "response_mismatch" => Some(Self::ResponseMismatch),
            "handoff_failed" => Some(Self::HandoffFailed),
            _ => None,
        }
    }
    /// Whether the reason is inside the closed vocabulary.
    #[must_use]
    pub const fn valid(self) -> bool {
        matches!(
            self,
            Self::AmbiguousDelivery | Self::ResponseMismatch | Self::HandoffFailed
        )
    }
}

/// execution.prepare_tool_call — mints a tool call + prepared attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct PrepareToolCallCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub tool_call_id: ToolCallId,
    pub tool_attempt_id: ToolCallAttemptId,
    pub tool_logical_operation_id: LogicalOperationId,
    pub physical_attempt_id: PhysicalAttemptId,
    pub call_sequence: i64,
    pub attempt_sequence: i64,
    /// Approval subject version the caller binds (approval-gated ops).
    pub approval_subject_version: i64,
    /// Step version the approval subject was recorded against.
    pub approval_expected_step_version: i64,
}
deref_envelope!(PrepareToolCallCommand);

/// execution.mark_tool_call_invoked — tool call attempt → invoked.
#[derive(Debug, Clone, PartialEq)]
pub struct MarkToolCallInvokedCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub tool_call_id: ToolCallId,
    pub tool_attempt_id: ToolCallAttemptId,
    pub tool_logical_operation_id: LogicalOperationId,
    pub invocation_id: InvocationId,
    /// Approval subject version the caller binds (approval-gated ops).
    pub approval_subject_version: i64,
    /// Step version the approval subject was recorded against.
    pub approval_expected_step_version: i64,
}
deref_envelope!(MarkToolCallInvokedCommand);

/// execution.settle_tool_call — terminal outcome for a tool attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct SettleToolCallCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub tool_call_id: ToolCallId,
    pub tool_attempt_id: ToolCallAttemptId,
    pub tool_logical_operation_id: LogicalOperationId,
    pub final_state: AttemptState,
    pub outcome: Vec<u8>,
    /// Optional invocation context snapshot.
    pub context: Vec<u8>,
}
deref_envelope!(SettleToolCallCommand);

/// execution.settle — terminal outcome for the step attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct SettleCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub final_state: AttemptState,
    pub outcome: Vec<u8>,
    /// Optional invocation context snapshot.
    pub context: Vec<u8>,
    /// Bounded failure vocabulary (empty defaults to `execution_failed`).
    pub reason_code: FailureReason,
}
deref_envelope!(SettleCommand);

/// execution.record_checkpoint — checkpoint evidence under the lease.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordCheckpointCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    /// The checkpoint record (id + sanitized payload).
    pub checkpoint: Checkpoint,
}
deref_envelope!(RecordCheckpointCommand);

/// execution.record_approval — registers a pending approval gate.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordApprovalCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    /// The pending approval record (id + subject).
    pub approval: Approval,
}
deref_envelope!(RecordApprovalCommand);

/// execution.create_approval_successor — mints the successor step +
/// pending approval bound to a fresh logical operation.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateApprovalSuccessorCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub approval_id: ApprovalId,
    pub successor_step_id: StepId,
    pub successor_approval_id: ApprovalId,
    /// The successor's subject (version bumped).
    pub subject: ApprovalSubject,
}
deref_envelope!(CreateApprovalSuccessorCommand);

/// execution.resolve_reconciliation — operator disposition.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolveReconciliationCommand {
    /// Selector, guards, and caller-state envelope.
    pub envelope: CommandEnvelope,
    pub disposition: ReconciliationDisposition,
    pub evidence: Vec<ReconciliationEvidence>,
}
deref_envelope!(ResolveReconciliationCommand);

// ---------------------------------------------------------------------------
// Transition helpers (upstream TransitionStep/TransitionAttempt/
// TransitionToolCall/MarkAttemptInvoked/Resolve*Reconciliation).
// ---------------------------------------------------------------------------

/// `TransitionStep` — closed transition; bumps version.
pub fn transition_step(current: Step, to: StepState) -> Result<Step, Failure> {
    if !current.state.can_transition(to) {
        return Err(failure(FailureKind::Denied, "INVALID_TRANSITION"));
    }
    let mut next = current;
    next.state = to;
    next.version += 1;
    Ok(next)
}

/// `TransitionAttempt` — closed transition; bumps version.
pub fn transition_attempt(current: StepAttempt, to: AttemptState) -> Result<StepAttempt, Failure> {
    if !current.state.can_transition(to) {
        return Err(failure(FailureKind::Denied, "INVALID_TRANSITION"));
    }
    let mut next = current;
    next.state = to;
    next.version += 1;
    Ok(next)
}

/// `TransitionToolCall` — closed transition; bumps version.
pub fn transition_tool_call(current: ToolCall, to: ToolCallState) -> Result<ToolCall, Failure> {
    if !current.state.can_transition(to) {
        return Err(failure(FailureKind::Denied, "INVALID_TRANSITION"));
    }
    let mut next = current;
    next.state = to;
    next.version += 1;
    Ok(next)
}

/// `TransitionApproval` — pending → approved|rejected|expired|superseded.
pub fn transition_approval(current: Approval, to: ApprovalState) -> Result<Approval, Failure> {
    if current.state != ApprovalState::ApprovalPending {
        return Err(failure(FailureKind::Denied, "IMMUTABLE_APPROVAL"));
    }
    if to == ApprovalState::ApprovalPending {
        return Err(failure(FailureKind::Denied, "INVALID_TRANSITION"));
    }
    let mut next = current;
    next.state = to;
    next.version += 1;
    Ok(next)
}

/// `MarkAttemptInvoked` — prepared → invoked with an invocation id.
pub fn mark_attempt_invoked(
    current: StepAttempt,
    invocation_id: InvocationId,
) -> Result<StepAttempt, Failure> {
    if current.state != AttemptState::AttemptPrepared {
        return Err(failure(FailureKind::Denied, "IMMUTABLE_ATTEMPT"));
    }
    if invocation_id.is_nil() || !current.invocation_id.is_nil() {
        return Err(failure(FailureKind::Invalid, "INVALID_INVOCATION_ID"));
    }
    let mut next = current;
    next.state = AttemptState::AttemptInvoked;
    next.invocation_id = invocation_id;
    next.version += 1;
    Ok(next)
}

/// `transitionStepTo` — the reconciliation-aware step helper.
pub(crate) fn transition_step_to(current: Step, target: StepState) -> Result<Step, Failure> {
    if current.state == target {
        return Ok(current);
    }
    let mut current = current;
    if current.state == StepState::StepRunning && target == StepState::StepFailed {
        current = transition_step(current, StepState::StepSettling)?;
    }
    transition_step(current, target)
}

/// `ResolveAttemptReconciliation` — reconciliation → terminal state.
pub fn resolve_attempt_reconciliation(
    current: StepAttempt,
    disposition: ReconciliationDisposition,
) -> Result<StepAttempt, Failure> {
    if current.state != AttemptState::AttemptReconciliation {
        return Err(failure(FailureKind::Denied, "RECONCILIATION_NOT_REQUIRED"));
    }
    let to = match disposition {
        ReconciliationDisposition::ReconciliationConfirmSucceeded => AttemptState::AttemptSucceeded,
        ReconciliationDisposition::ReconciliationConfirmFailed
        | ReconciliationDisposition::ReconciliationResume => AttemptState::AttemptFailed,
        ReconciliationDisposition::ReconciliationCancel => AttemptState::AttemptCancelled,
    };
    let mut next = current;
    next.state = to;
    next.version += 1;
    Ok(next)
}

/// `ResolveStepReconciliation`.
pub fn resolve_step_reconciliation(
    current: Step,
    disposition: ReconciliationDisposition,
) -> Result<Step, Failure> {
    if current.state != StepState::StepReconciliation {
        return Err(failure(FailureKind::Denied, "RECONCILIATION_NOT_REQUIRED"));
    }
    let to = match disposition {
        ReconciliationDisposition::ReconciliationConfirmSucceeded => StepState::StepSucceeded,
        ReconciliationDisposition::ReconciliationConfirmFailed
        | ReconciliationDisposition::ReconciliationResume => StepState::StepFailed,
        ReconciliationDisposition::ReconciliationCancel => StepState::StepCancelled,
    };
    let mut next = current;
    next.state = to;
    next.version += 1;
    Ok(next)
}

/// `ResolveToolCallReconciliation` — resume is never a tool outcome.
pub fn resolve_tool_call_reconciliation(
    current: ToolCall,
    disposition: ReconciliationDisposition,
) -> Result<ToolCall, Failure> {
    if current.state != ToolCallState::ToolCallReconciliation {
        return Err(failure(FailureKind::Denied, "RECONCILIATION_NOT_REQUIRED"));
    }
    let to = match disposition {
        ReconciliationDisposition::ReconciliationConfirmSucceeded => {
            ToolCallState::ToolCallSucceeded
        }
        ReconciliationDisposition::ReconciliationConfirmFailed => ToolCallState::ToolCallFailed,
        ReconciliationDisposition::ReconciliationCancel => ToolCallState::ToolCallCancelled,
        ReconciliationDisposition::ReconciliationResume => {
            return Err(failure(FailureKind::Invalid, "INVALID_DISPOSITION"));
        }
    };
    let mut next = current;
    next.state = to;
    next.version += 1;
    Ok(next)
}

/// `InheritParentAttemptState` — a settling tool attempt takes its
/// parent's terminal state.
pub fn inherit_parent_attempt_state(
    child: ToolCallAttempt,
    parent: &StepAttempt,
) -> Result<ToolCallAttempt, Failure> {
    let matches_parent = child.step_attempt_id == parent.id
        && child.workspace_id == parent.workspace_id
        && child.task_id == parent.task_id
        && child.run_id == parent.run_id;
    if !matches_parent {
        return Err(failure(FailureKind::Invalid, "PARENT_ATTEMPT_MISMATCH"));
    }
    if !parent.state.is_terminal() {
        return Err(failure(FailureKind::Invalid, "PARENT_NOT_TERMINAL"));
    }
    if child.state == parent.state {
        return Ok(child);
    }
    if child.state != AttemptState::AttemptSettling {
        return Err(failure(
            FailureKind::Conflict,
            "PARENT_TERMINAL_STATE_MISMATCH",
        ));
    }
    let mut next = child;
    next.state = parent.state;
    next.version += 1;
    Ok(next)
}

// ---------------------------------------------------------------------------
// Lease helpers.
// ---------------------------------------------------------------------------

/// `activeFencedLease` — the fenced-lease check every lease-holding
/// command applies. An absent, expired, or mismatched row is
/// `STALE_LEASE_FENCE`.
pub(crate) fn active_fenced_lease(
    envelope: &CommandEnvelope,
    now: OffsetDateTime,
) -> Result<Lease, Failure> {
    let Some(lease) = &envelope.state.lease else {
        return Err(failure(FailureKind::Conflict, "STALE_LEASE_FENCE"));
    };
    if lease.workspace_id != envelope.workspace_id
        || lease.run_id != envelope.run_id
        || !envelope.lease_credential.valid()
        || lease.generation != envelope.lease_generation
        || lease.expires_at <= now
    {
        return Err(failure(FailureKind::Conflict, "STALE_LEASE_FENCE"));
    }
    let mut lease = lease.clone();
    lease.credential = envelope.lease_credential;
    Ok(lease)
}

/// `noActiveLeaseAssertion` — asserts no unexpired lease exists.
pub(crate) fn no_active_lease_assertion(
    envelope: &CommandEnvelope,
    now: OffsetDateTime,
) -> Result<LeaseAssertion, Failure> {
    let active = envelope
        .state
        .lease
        .as_ref()
        .is_some_and(|l| l.expires_at > now);
    if active || !envelope.assert_no_active_lease {
        return Err(failure(
            FailureKind::Conflict,
            "LEASE_STATE_ASSERTION_REQUIRED",
        ));
    }
    Ok(LeaseAssertion {
        workspace_id: envelope.workspace_id,
        run_id: envelope.run_id,
        no_active: true,
    })
}

/// `releaseFor`.
pub(crate) fn release_for(lease: &Lease) -> LeaseRelease {
    LeaseRelease {
        workspace_id: lease.workspace_id,
        run_id: lease.run_id,
        credential: lease.credential,
        generation: lease.generation,
    }
}

// ---------------------------------------------------------------------------
// validateEvaluation — the shared gate (upstream validateEvaluation).
// ---------------------------------------------------------------------------

pub(crate) fn validate_evaluation(
    envelope: &CommandEnvelope,
    meta: &EvaluationMetadata,
    required: Capability,
    require_attempt: bool,
    allow_missing_step: bool,
) -> Result<(), Failure> {
    if meta.principal_id.trim().is_empty()
        || meta.principal_id != envelope.scope.principal_id
        || meta.capability != required
        || !envelope.scope.allows(required)
        || meta.idempotency_key.trim().is_empty()
        || !fingerprint_valid(&meta.fingerprint)
        || meta.now == ZERO_TIME
        || meta.event_id.is_nil()
        || meta.outbox_id.is_nil()
        || meta.producer_id.trim().is_empty()
    {
        return Err(failure(FailureKind::Invalid, "INVALID_COMMAND_METADATA"));
    }
    if envelope.scope.workspace_id != envelope.workspace_id
        || envelope.workspace_id.is_nil()
        || envelope.task_id.is_nil()
        || envelope.run_id.is_nil()
        || envelope.step_id.is_nil()
        || envelope.logical_operation.is_nil()
    {
        return Err(failure(FailureKind::Denied, "SCOPE_MISMATCH"));
    }
    let aggregate = &envelope.state.task;
    let Some(run) = &aggregate.current_run else {
        return Err(failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"));
    };
    if aggregate.task.id != envelope.task_id
        || aggregate.task.workspace_id != envelope.workspace_id
        || aggregate.task.current_run_id != Some(envelope.run_id)
        || run.id != envelope.run_id
        || run.task_id != envelope.task_id
        || run.workspace_id != envelope.workspace_id
    {
        return Err(failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"));
    }
    if envelope.expected.task <= 0
        || envelope.expected.run <= 0
        || envelope.expected.task != aggregate.task.version
        || envelope.expected.run != run.version
    {
        return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
    }
    match &envelope.state.step {
        None => {
            if !allow_missing_step || envelope.expected.step != 0 {
                return Err(failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"));
            }
        }
        Some(step) => {
            if step.id != envelope.step_id
                || step.workspace_id != envelope.workspace_id
                || step.task_id != envelope.task_id
                || step.run_id != envelope.run_id
            {
                return Err(failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"));
            }
            if envelope.expected.step <= 0 || envelope.expected.step != step.version {
                return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
            }
        }
    }
    if let Some(lease) = &envelope.state.lease
        && (lease.workspace_id != envelope.workspace_id || lease.run_id != envelope.run_id)
    {
        return Err(failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"));
    }
    if let Some(approval) = &envelope.state.approval
        && (approval.workspace_id != envelope.workspace_id
            || approval.task_id != envelope.task_id
            || approval.run_id != envelope.run_id
            || approval.step_id != envelope.step_id)
    {
        return Err(failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"));
    }
    match &envelope.state.attempt {
        None => {
            if require_attempt
                || !envelope.state.tool_calls.is_empty()
                || !envelope.state.tool_attempts.is_empty()
            {
                return Err(failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"));
            }
        }
        Some(attempt) => {
            if envelope.attempt_id.is_nil()
                || attempt.id != envelope.attempt_id
                || attempt.step_id != envelope.step_id
                || attempt.workspace_id != envelope.workspace_id
                || attempt.task_id != envelope.task_id
                || attempt.run_id != envelope.run_id
                || attempt.logical_operation_id != envelope.logical_operation
            {
                return Err(failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"));
            }
            if envelope.expected.attempt <= 0 || envelope.expected.attempt != attempt.version {
                return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
            }
            validate_snapshot(&envelope.state)?;
        }
    }
    Ok(())
}

/// Identity/cardinality/hierarchy re-validation of the state snapshot
/// (`validateAttemptIdentitiesFrom` authoritative + cardinality + tool
/// hierarchy — upstream `validateEvaluation` tail).
fn validate_snapshot(state: &ExecutionState) -> Result<(), Failure> {
    let step_attempts: &[StepAttempt] = match &state.attempt {
        Some(attempt) => std::slice::from_ref(attempt),
        None => &[],
    };
    validate_attempt_identities_from(step_attempts, &state.tool_attempts, true, &BTreeSet::new())?;
    validate_active_attempt_cardinality(step_attempts, &state.tool_attempts)?;
    validate_tool_hierarchy(step_attempts, &state.tool_calls, &state.tool_attempts)
}

/// `validateApprovedSubject` — the binding every approval-gated
/// mutation re-checks.
pub(crate) fn validate_approved_subject(
    approval: &Approval,
    logical_operation_id: LogicalOperationId,
    operation_digest: RequestFingerprint,
    subject_version: i64,
    expected_step_version: i64,
) -> Result<(), Failure> {
    if approval.state != ApprovalState::ApprovalApproved
        || logical_operation_id.is_nil()
        || approval.subject.logical_operation_id != logical_operation_id
        || !fingerprint_valid(&approval.subject.operation_digest)
        || !fingerprint_valid(&operation_digest)
        || approval.subject.operation_digest != operation_digest
        || subject_version <= 0
        || approval.subject.version != subject_version
        || expected_step_version <= 0
        || approval.subject.expected_step_version != expected_step_version
    {
        return Err(failure(FailureKind::Denied, "APPROVAL_SUBJECT_MISMATCH"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tool-hierarchy helpers.
// ---------------------------------------------------------------------------

pub(crate) fn selected_tool_state(
    state: &ExecutionState,
    call_id: ToolCallId,
    attempt_id: ToolCallAttemptId,
    logical_operation_id: LogicalOperationId,
) -> Result<(ToolCall, ToolCallAttempt), Failure> {
    if call_id.is_nil() || attempt_id.is_nil() || logical_operation_id.is_nil() {
        return Err(failure(FailureKind::Invalid, "INVALID_TOOL_CALL_IDENTITY"));
    }
    let calls: Vec<&ToolCall> = state
        .tool_calls
        .iter()
        .filter(|c| c.id == call_id)
        .collect();
    let attempts: Vec<&ToolCallAttempt> = state
        .tool_attempts
        .iter()
        .filter(|a| a.id == attempt_id)
        .collect();
    if calls.len() != 1 || attempts.len() != 1 {
        return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
    }
    let call = calls[0];
    let attempt = attempts[0];
    if call.logical_operation_id != logical_operation_id
        || attempt.logical_operation_id != logical_operation_id
        || attempt.tool_call_id != call.id
        || attempt.step_attempt_id != call.step_attempt_id
    {
        return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
    }
    Ok((call.clone(), attempt.clone()))
}

pub(crate) fn ensure_no_other_active_tool(
    state: &ExecutionState,
    selected_call: ToolCallId,
    selected_attempt: ToolCallAttemptId,
) -> Result<(), Failure> {
    for call in &state.tool_calls {
        if call.id != selected_call && !call.state.is_terminal() {
            return Err(failure(FailureKind::Conflict, "PRIOR_TOOL_CALL_ACTIVE"));
        }
    }
    for attempt in &state.tool_attempts {
        if attempt.id != selected_attempt && !attempt.state.is_terminal() {
            return Err(failure(FailureKind::Conflict, "PRIOR_TOOL_CALL_ACTIVE"));
        }
    }
    Ok(())
}

fn tool_call_terminal_state(state: AttemptState) -> Option<ToolCallState> {
    match state {
        AttemptState::AttemptSucceeded => Some(ToolCallState::ToolCallSucceeded),
        AttemptState::AttemptFailed => Some(ToolCallState::ToolCallFailed),
        AttemptState::AttemptCancelled => Some(ToolCallState::ToolCallCancelled),
        _ => None,
    }
}

fn terminalize_tool_call(
    current: ToolCall,
    final_state: AttemptState,
) -> Result<ToolCall, Failure> {
    let Some(to) = tool_call_terminal_state(final_state) else {
        return Err(failure(FailureKind::Invalid, "INVALID_SETTLEMENT"));
    };
    if current.state == to {
        return Ok(current);
    }
    if final_state == AttemptState::AttemptCancelled
        && matches!(
            current.state,
            ToolCallState::ToolCallQueued | ToolCallState::ToolCallPrepared
        )
    {
        return transition_tool_call(current, ToolCallState::ToolCallCancelled);
    }
    match current.state {
        ToolCallState::ToolCallInvoked => {
            let settling = transition_tool_call(current, ToolCallState::ToolCallSettling)?;
            transition_tool_call(settling, to)
        }
        ToolCallState::ToolCallSettling => transition_tool_call(current, to),
        _ => Err(failure(FailureKind::Conflict, "CHILD_NOT_SETTLEABLE")),
    }
}

fn terminalize_tool_attempt(
    current: ToolCallAttempt,
    final_state: AttemptState,
) -> Result<ToolCallAttempt, Failure> {
    if current.state == final_state {
        return Ok(current);
    }
    if final_state == AttemptState::AttemptCancelled
        && current.state == AttemptState::AttemptPrepared
    {
        let mut next = current;
        next.state = AttemptState::AttemptCancelled;
        next.version += 1;
        return Ok(next);
    }
    match current.state {
        AttemptState::AttemptInvoked | AttemptState::AttemptSettling => {
            let mut next = current;
            if next.state == AttemptState::AttemptInvoked {
                next.state = AttemptState::AttemptSettling;
                next.version += 1;
            }
            next.state = final_state;
            next.version += 1;
            Ok(next)
        }
        _ => Err(failure(FailureKind::Conflict, "CHILD_NOT_SETTLEABLE")),
    }
}

/// `terminalizeToolHierarchy`.
pub(crate) fn terminalize_tool_hierarchy(
    calls: &[ToolCall],
    attempts: &[ToolCallAttempt],
    final_state: AttemptState,
    now: OffsetDateTime,
) -> Result<(Vec<ToolCall>, Vec<ToolCallAttempt>), Failure> {
    if tool_call_terminal_state(final_state).is_none() {
        return Err(failure(FailureKind::Invalid, "INVALID_SETTLEMENT"));
    }
    let mut next_calls = Vec::with_capacity(calls.len());
    let mut next_attempts = Vec::with_capacity(attempts.len());
    for call in calls {
        let mut next_call = terminalize_tool_call(call.clone(), final_state)?;
        next_call.updated_at = now;
        next_calls.push(next_call);
        match attempts.iter().find(|a| a.tool_call_id == call.id) {
            Some(attempt) => {
                let mut next_attempt = terminalize_tool_attempt(attempt.clone(), final_state)?;
                next_attempt.updated_at = now;
                next_attempts.push(next_attempt);
            }
            None => {
                if call.state == ToolCallState::ToolCallQueued
                    && final_state == AttemptState::AttemptCancelled
                {
                    continue;
                }
                return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
            }
        }
    }
    if next_attempts.len() != attempts.len() {
        return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
    }
    Ok((next_calls, next_attempts))
}

/// `reconcileToolHierarchy`.
pub(crate) fn reconcile_tool_hierarchy(
    calls: &[ToolCall],
    attempts: &[ToolCallAttempt],
    now: OffsetDateTime,
) -> Result<(Vec<ToolCall>, Vec<ToolCallAttempt>), Failure> {
    let mut next_calls = Vec::with_capacity(calls.len());
    let mut next_attempts = Vec::with_capacity(attempts.len());
    for call in calls {
        let mut next_call = call.clone();
        if !call.state.is_terminal() && call.state != ToolCallState::ToolCallReconciliation {
            next_call = transition_tool_call(next_call, ToolCallState::ToolCallReconciliation)?;
        }
        next_call.updated_at = now;
        next_calls.push(next_call);
        match attempts.iter().find(|a| a.tool_call_id == call.id) {
            Some(attempt) => {
                let mut next_attempt = attempt.clone();
                if !attempt.state.is_terminal()
                    && attempt.state != AttemptState::AttemptReconciliation
                {
                    next_attempt.state = AttemptState::AttemptReconciliation;
                    next_attempt.version += 1;
                }
                next_attempt.updated_at = now;
                next_attempts.push(next_attempt);
            }
            None => {
                if call.state.is_terminal() {
                    continue;
                }
                return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
            }
        }
    }
    if next_attempts.len() != attempts.len() {
        return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
    }
    Ok((next_calls, next_attempts))
}

/// `resolveToolHierarchyReconciliation`.
pub(crate) fn resolve_tool_hierarchy_reconciliation(
    calls: &[ToolCall],
    attempts: &[ToolCallAttempt],
    disposition: ReconciliationDisposition,
    now: OffsetDateTime,
) -> Result<(Vec<ToolCall>, Vec<ToolCallAttempt>), Failure> {
    let final_state = match disposition {
        ReconciliationDisposition::ReconciliationConfirmSucceeded => AttemptState::AttemptSucceeded,
        ReconciliationDisposition::ReconciliationConfirmFailed => AttemptState::AttemptFailed,
        ReconciliationDisposition::ReconciliationCancel => AttemptState::AttemptCancelled,
        ReconciliationDisposition::ReconciliationResume => {
            return Err(failure(FailureKind::Invalid, "INVALID_DISPOSITION"));
        }
    };
    let mut next_calls = Vec::with_capacity(calls.len());
    let mut next_attempts = Vec::with_capacity(attempts.len());
    for call in calls {
        let mut next_call = resolve_tool_call_reconciliation(call.clone(), disposition)?;
        let Some(attempt) = attempts.iter().find(|a| a.tool_call_id == call.id) else {
            return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
        };
        if attempt.state != AttemptState::AttemptReconciliation {
            return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
        }
        let mut next_attempt = attempt.clone();
        next_attempt.state = final_state;
        next_attempt.version += 1;
        next_call.updated_at = now;
        next_attempt.updated_at = now;
        next_calls.push(next_call);
        next_attempts.push(next_attempt);
    }
    if next_attempts.len() != attempts.len() {
        return Err(failure(FailureKind::Invalid, "TOOL_CALL_ATTEMPT_MISMATCH"));
    }
    Ok((next_calls, next_attempts))
}

// ---------------------------------------------------------------------------
// Task-transition helpers (upstream settlementTaskTransition /
// reconciliationTaskTransition / decisionIDFromEvent).
// ---------------------------------------------------------------------------

pub(crate) fn settlement_task_transition(
    aggregate: task::TaskAggregate,
    expected: ExpectedVersions,
    final_state: AttemptState,
    reason: &str,
    now: OffsetDateTime,
) -> Result<ExecutionTransitionResult, Failure> {
    let request = match final_state {
        AttemptState::AttemptSucceeded => {
            ExecutionTransition::Complete(execution_facade::ExecutionCompleteRequest {
                aggregate,
                now,
                expected_task_version: expected.task,
                expected_run_version: expected.run,
            })
        }
        AttemptState::AttemptFailed => {
            ExecutionTransition::Fail(execution_facade::ExecutionFailRequest {
                aggregate,
                reason: if reason.is_empty() {
                    "execution_failed".to_string()
                } else {
                    reason.to_string()
                },
                now,
                expected_task_version: expected.task,
                expected_run_version: expected.run,
            })
        }
        _ => return Err(failure(FailureKind::Invalid, "INVALID_SETTLEMENT")),
    };
    execution_facade::evaluate_execution_transition(request).map_err(|e| {
        Failure::new(
            FailureKind::Denied,
            "TASK_TRANSITION_REJECTED",
            format!("task transition denied: {}", e.message()),
        )
    })
}

pub(crate) fn cancellation_task_transition(
    aggregate: task::TaskAggregate,
    expected: ExpectedVersions,
    now: OffsetDateTime,
) -> Result<ExecutionTransitionResult, Failure> {
    execution_facade::evaluate_execution_transition(ExecutionTransition::SettleCancellation(
        execution_facade::ExecutionSettleCancellationRequest {
            aggregate,
            now,
            expected_task_version: expected.task,
            expected_run_version: expected.run,
        },
    ))
    .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))
}

pub(crate) fn reconciliation_task_transition(
    aggregate: task::TaskAggregate,
    expected: ExpectedVersions,
    disposition: ReconciliationDisposition,
    now: OffsetDateTime,
) -> Result<ExecutionTransitionResult, Failure> {
    match disposition {
        ReconciliationDisposition::ReconciliationConfirmSucceeded => {
            settlement_task_transition(aggregate, expected, AttemptState::AttemptSucceeded, "", now)
        }
        ReconciliationDisposition::ReconciliationConfirmFailed => settlement_task_transition(
            aggregate,
            expected,
            AttemptState::AttemptFailed,
            "operator_resolved",
            now,
        ),
        ReconciliationDisposition::ReconciliationCancel => {
            cancellation_task_transition(aggregate, expected, now)
        }
        ReconciliationDisposition::ReconciliationResume => {
            Err(failure(FailureKind::Invalid, "INVALID_DISPOSITION"))
        }
    }
}

/// `decisionIDFromEvent` — sha256("approval-decision:"+event id)[:16].
pub(crate) fn decision_id_from_event(event_id: ExecutionEventId) -> [u8; 16] {
    let sum = sha2::Sha256::digest(format!("approval-decision:{event_id}").as_bytes());
    let mut decision = [0u8; 16];
    decision.copy_from_slice(&sum[..16]);
    decision
}

// ---------------------------------------------------------------------------
// Command enum + dispatch (upstream `EvaluateCommand`).
// ---------------------------------------------------------------------------

/// The sealed command set — every execution mutation.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// `execution.prepare`.
    Prepare(PrepareCommand),
    /// `execution.claim`.
    Claim(ClaimCommand),
    /// `execution.heartbeat`.
    Heartbeat(HeartbeatCommand),
    /// `execution.mark_invoked`.
    MarkInvoked(MarkInvokedCommand),
    /// `execution.schedule_retry`.
    ScheduleRetry(ScheduleRetryCommand),
    /// `execution.enter_reconciliation`.
    EnterReconciliation(EnterReconciliationCommand),
    /// `execution.settle_cancellation`.
    SettleCancellation(crate::harness_run::SettleCancellationCommand),
    /// `execution.prepare_tool_call`.
    PrepareToolCall(PrepareToolCallCommand),
    /// `execution.mark_tool_call_invoked`.
    MarkToolCallInvoked(MarkToolCallInvokedCommand),
    /// `execution.settle_tool_call`.
    SettleToolCall(SettleToolCallCommand),
    /// `execution.settle`.
    Settle(SettleCommand),
    /// `execution.cancel`.
    Cancel(CancelCommand),
    /// `execution.record_checkpoint`.
    RecordCheckpoint(RecordCheckpointCommand),
    /// `execution.record_approval`.
    RecordApproval(RecordApprovalCommand),
    /// `execution.resolve_approval`.
    ResolveApproval(ResolveApprovalCommand),
    /// `execution.expire_approval`.
    ExpireApproval(ExpireApprovalCommand),
    /// `execution.create_approval_successor`.
    CreateApprovalSuccessor(CreateApprovalSuccessorCommand),
    /// `execution.resolve_reconciliation`.
    ResolveReconciliation(ResolveReconciliationCommand),
    /// `execution.start_harness_run`.
    StartHarnessRun(crate::harness_run::StartHarnessRunCommand),
    /// `execution.abandon_prepared`.
    AbandonPrepared(crate::harness_run::AbandonPreparedCommand),
    /// `execution.resume_reconciled_attempt`.
    ResumeReconciledAttempt(crate::resume::ResumeReconciledAttemptCommand),
}

/// `EvaluateCommand` — evaluates a command and gates the result
/// through [`build_execution_change_set`].
pub fn evaluate_command(
    command: Command,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    let change = match command {
        Command::Prepare(cmd) => evaluate_prepare(&cmd, meta),
        Command::Claim(cmd) => evaluate_claim(&cmd, meta),
        Command::Heartbeat(cmd) => evaluate_heartbeat(&cmd, meta),
        Command::MarkInvoked(cmd) => evaluate_mark_invoked(&cmd, meta),
        Command::ScheduleRetry(cmd) => evaluate_schedule_retry(&cmd, meta),
        Command::EnterReconciliation(cmd) => evaluate_enter_reconciliation(&cmd, meta),
        Command::SettleCancellation(cmd) => {
            crate::harness_run::evaluate_settle_cancellation(&cmd, meta)
        }
        Command::PrepareToolCall(cmd) => evaluate_prepare_tool_call(&cmd, meta),
        Command::MarkToolCallInvoked(cmd) => evaluate_mark_tool_call_invoked(&cmd, meta),
        Command::SettleToolCall(cmd) => evaluate_settle_tool_call(&cmd, meta),
        Command::Settle(cmd) => evaluate_settle(&cmd, meta),
        Command::Cancel(cmd) => evaluate_cancel(&cmd, meta),
        Command::RecordCheckpoint(cmd) => evaluate_record_checkpoint(&cmd, meta),
        Command::RecordApproval(cmd) => evaluate_record_approval(&cmd, meta),
        Command::ResolveApproval(cmd) => evaluate_resolve_approval(&cmd, meta, false),
        Command::ExpireApproval(cmd) => evaluate_resolve_approval(
            &ResolveApprovalCommand {
                envelope: cmd.envelope.clone(),
                approval_id: cmd.approval_id,
                decision: ApprovalState::ApprovalExpired,
            },
            meta,
            true,
        ),
        Command::CreateApprovalSuccessor(cmd) => evaluate_create_approval_successor(&cmd, meta),
        Command::ResolveReconciliation(cmd) => evaluate_resolve_reconciliation(&cmd, meta),
        Command::StartHarnessRun(cmd) => crate::harness_run::evaluate_start_harness_run(&cmd, meta),
        Command::AbandonPrepared(cmd) => crate::harness_run::evaluate_abandon_prepared(&cmd, meta),
        Command::ResumeReconciledAttempt(cmd) => {
            crate::resume::evaluate_resume_reconciled_attempt(&cmd, meta)
        }
    }?;
    build_execution_change_set(change)
}

// ---------------------------------------------------------------------------
// Evaluators — one per command, upstream order.
// ---------------------------------------------------------------------------

fn evaluate_prepare(
    cmd: &PrepareCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, false, true)?;
    if cmd.envelope.attempt_id.is_nil()
        || cmd.physical_attempt_id.is_nil()
        || cmd.step_sequence <= 0
        || cmd.attempt_sequence <= 0
    {
        return Err(failure(FailureKind::Invalid, "INVALID_ATTEMPT_IDENTITY"));
    }
    if cmd.state.attempt.is_some() {
        return Err(failure(FailureKind::Conflict, "ACTIVE_ATTEMPT_CONFLICT"));
    }
    if cmd.expected.attempt != 0 {
        return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
    }
    if let Some(approval) = &cmd.state.approval {
        if approval.state == ApprovalState::ApprovalPending {
            return Err(failure(FailureKind::Denied, "APPROVAL_REQUIRED"));
        }
        validate_approved_subject(
            approval,
            cmd.envelope.logical_operation,
            cmd.envelope.operation_digest,
            cmd.approval_subject_version,
            cmd.approval_expected_step_version,
        )?;
    }
    let step = match &cmd.state.step {
        None => {
            if cmd.expected.step != 0 {
                return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
            }
            Step {
                id: cmd.step_id,
                workspace_id: cmd.workspace_id,
                task_id: cmd.task_id,
                run_id: cmd.run_id,
                version: 1,
                sequence: cmd.step_sequence,
                state: StepState::StepRunning,
                created_at: meta.now,
                updated_at: meta.now,
            }
        }
        Some(current) => {
            let mut step = transition_step(current.clone(), StepState::StepRunning)?;
            if cmd.step_sequence != step.sequence {
                return Err(failure(FailureKind::Invalid, "STEP_SEQUENCE_MISMATCH"));
            }
            step.updated_at = meta.now;
            step
        }
    };
    let attempt = StepAttempt {
        id: cmd.attempt_id,
        step_id: cmd.step_id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        logical_operation_id: cmd.logical_operation,
        physical_attempt_id: cmd.physical_attempt_id,
        invocation_id: InvocationId::default(),
        predecessor_id: NIL_STEP_ATTEMPT_ID,
        version: 1,
        sequence: cmd.attempt_sequence,
        state: AttemptState::AttemptPrepared,
        created_at: meta.now,
        updated_at: meta.now,
    };
    let assertion = no_active_lease_assertion(&cmd.envelope, meta.now)?;
    with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            steps: vec![step],
            attempts: vec![attempt],
            lease_assertions: vec![assertion],
            ..ExecutionChangeSet::default()
        },
        EVENT_ATTEMPT_PREPARED,
        OUTBOX_ATTEMPT_PREPARED,
        AttemptState::AttemptPrepared.as_str(),
        "",
    )
}

fn evaluate_claim(
    cmd: &ClaimCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    let attempt_state = cmd
        .state
        .attempt
        .as_ref()
        .map_or(AttemptState::AttemptPrepared, |a| a.state);
    if !matches!(
        attempt_state,
        AttemptState::AttemptPrepared
            | AttemptState::AttemptInvoked
            | AttemptState::AttemptSettling
    ) {
        return Err(failure(FailureKind::Denied, "IMMUTABLE_ATTEMPT"));
    }
    if let Some(approval) = &cmd.state.approval
        && approval.state == ApprovalState::ApprovalPending
    {
        return Err(failure(FailureKind::Denied, "APPROVAL_REQUIRED"));
    }
    let mut next_generation = 1i64;
    if let Some(current) = &cmd.state.lease {
        if current.expires_at > meta.now {
            return Err(failure(FailureKind::Conflict, "ACTIVE_LEASE_CONFLICT"));
        }
        next_generation = current.generation + 1;
    }
    if !cmd.lease_credential.valid() || cmd.lease_generation != next_generation {
        return Err(failure(FailureKind::Conflict, "STALE_LEASE_FENCE"));
    }
    let lease = Lease {
        workspace_id: cmd.workspace_id,
        run_id: cmd.run_id,
        credential: cmd.lease_credential,
        generation: cmd.lease_generation,
        expires_at: meta.now + DEFAULT_LEASE_DURATION,
        updated_at: meta.now,
    };
    with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            leases: vec![lease],
            ..ExecutionChangeSet::default()
        },
        EVENT_ATTEMPT_CLAIMED,
        OUTBOX_ATTEMPT_CLAIMED,
        attempt_state.as_str(),
        "",
    )
}

fn evaluate_heartbeat(
    cmd: &HeartbeatCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    let mut lease = active_fenced_lease(&cmd.envelope, meta.now)?;
    lease.expires_at = meta.now + DEFAULT_LEASE_DURATION;
    lease.updated_at = meta.now;
    let state_str = cmd.state.attempt.as_ref().map_or("", |a| a.state.as_str());
    with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            leases: vec![lease],
            ..ExecutionChangeSet::default()
        },
        EVENT_ATTEMPT_HEARTBEAT,
        OUTBOX_ATTEMPT_CLAIMED,
        state_str,
        "",
    )
}

fn evaluate_mark_invoked(
    cmd: &MarkInvokedCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    active_fenced_lease(&cmd.envelope, meta.now)?;
    if let Some(approval) = &cmd.state.approval {
        validate_approved_subject(
            approval,
            cmd.envelope.logical_operation,
            cmd.envelope.operation_digest,
            cmd.approval_subject_version,
            cmd.approval_expected_step_version,
        )?;
    }
    let attempt = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    let mut attempt = mark_attempt_invoked(attempt, cmd.invocation_id)?;
    attempt.updated_at = meta.now;
    with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            attempts: vec![attempt],
            ..ExecutionChangeSet::default()
        },
        EVENT_ATTEMPT_INVOKED,
        OUTBOX_ATTEMPT_CLAIMED,
        AttemptState::AttemptInvoked.as_str(),
        "",
    )
}

fn evaluate_schedule_retry(
    cmd: &ScheduleRetryCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    let lease = active_fenced_lease(&cmd.envelope, meta.now)?;
    if cmd.reason_code.trim().is_empty()
        || cmd.reason_code.len() > 128
        || cmd.retry_after < Duration::ZERO
        || cmd.retry_after > Duration::hours(24)
    {
        return Err(failure(FailureKind::Invalid, "INVALID_RETRY_SCHEDULE"));
    }
    let mut attempt = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    let mut step = cmd
        .state
        .step
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    let mut final_state = AttemptState::AttemptCancelled;
    let mut settlement = None;
    match attempt.state {
        AttemptState::AttemptPrepared => {
            attempt = transition_attempt(attempt, AttemptState::AttemptCancelled)?;
            step = transition_step_to(step, StepState::StepCancelled)?;
        }
        AttemptState::AttemptInvoked | AttemptState::AttemptSettling => {
            if cmd.outcome.is_empty() {
                return Err(failure(FailureKind::Invalid, "OUTCOME_REQUIRED"));
            }
            validate_optional_payload(
                &cmd.outcome,
                OUTCOME_PAYLOAD_MAX_BYTES,
                OUTCOME_PAYLOAD_SCHEMA,
            )?;
            validate_optional_payload(
                &cmd.context,
                CONTEXT_PAYLOAD_MAX_BYTES,
                CONTEXT_PAYLOAD_SCHEMA,
            )?;
            if attempt.state == AttemptState::AttemptInvoked {
                attempt = transition_attempt(attempt, AttemptState::AttemptSettling)?;
            }
            attempt = transition_attempt(attempt, AttemptState::AttemptFailed)?;
            step = transition_step_to(step, StepState::StepFailed)?;
            final_state = AttemptState::AttemptFailed;
            settlement = Some(Settlement {
                workspace_id: cmd.workspace_id,
                task_id: cmd.task_id,
                run_id: cmd.run_id,
                step_id: cmd.step_id,
                attempt_id: cmd.attempt_id,
                invocation_id: attempt.invocation_id,
                final_state,
                outcome: cmd.outcome.clone(),
                context: cmd.context.clone(),
                settled_at: meta.now,
            });
        }
        _ => return Err(failure(FailureKind::Conflict, "RETRY_ATTEMPT_NOT_ACTIVE")),
    }
    step.updated_at = meta.now;
    attempt.updated_at = meta.now;
    let (tool_calls, tool_attempts) = terminalize_tool_hierarchy(
        &cmd.state.tool_calls,
        &cmd.state.tool_attempts,
        final_state,
        meta.now,
    )?;
    let task_transition = execution_facade::evaluate_execution_transition(
        ExecutionTransition::ScheduleRetry(execution_facade::ExecutionScheduleRetryRequest {
            aggregate: cmd.state.task.clone(),
            reason: Some(task::WaitingReason::RetryDelay),
            retry_at: Some(meta.now + cmd.retry_after),
            now: meta.now,
            failure_note: cmd.reason_code.clone(),
            expected_task_version: cmd.expected.task,
            expected_run_version: cmd.expected.run,
        }),
    )
    .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
    let mut change = ExecutionChangeSet {
        steps: vec![step],
        attempts: vec![attempt],
        tool_calls,
        tool_attempts,
        lease_releases: vec![release_for(&lease)],
        task_transition: Some(task_transition),
        ..ExecutionChangeSet::default()
    };
    if let Some(settlement) = settlement {
        change.settlements = vec![settlement];
    }
    with_evidence(
        &cmd.envelope,
        meta,
        change,
        EVENT_ATTEMPT_RETRY_SCHEDULED,
        OUTBOX_ATTEMPT_SETTLED,
        final_state.as_str(),
        &cmd.reason_code,
    )
}

fn evaluate_enter_reconciliation(
    cmd: &EnterReconciliationCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    if !cmd.reason_code.valid() {
        return Err(failure(
            FailureKind::Invalid,
            "INVALID_RECONCILIATION_REASON",
        ));
    }
    let lease = active_fenced_lease(&cmd.envelope, meta.now)?;
    let mut attempt = transition_attempt(
        cmd.state
            .attempt
            .clone()
            .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?,
        AttemptState::AttemptReconciliation,
    )?;
    let mut step = transition_step(
        cmd.state
            .step
            .clone()
            .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?,
        StepState::StepReconciliation,
    )?;
    let (tool_calls, tool_attempts) =
        reconcile_tool_hierarchy(&cmd.state.tool_calls, &cmd.state.tool_attempts, meta.now)?;
    let task_transition = execution_facade::evaluate_execution_transition(
        ExecutionTransition::Wait(execution_facade::ExecutionWaitRequest {
            aggregate: cmd.state.task.clone(),
            reason: Some(task::WaitingReason::Reconciliation),
            detail: cmd.reason_code.as_str().to_string(),
            now: meta.now,
            expected_task_version: cmd.expected.task,
            expected_run_version: cmd.expected.run,
        }),
    )
    .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
    attempt.updated_at = meta.now;
    step.updated_at = meta.now;
    with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            steps: vec![step],
            attempts: vec![attempt],
            tool_calls,
            tool_attempts,
            lease_releases: vec![release_for(&lease)],
            task_transition: Some(task_transition),
            ..ExecutionChangeSet::default()
        },
        EVENT_ATTEMPT_RECONCILIATION,
        OUTBOX_RECONCILIATION_REQUIRED,
        AttemptState::AttemptReconciliation.as_str(),
        cmd.reason_code.as_str(),
    )
}

fn evaluate_prepare_tool_call(
    cmd: &PrepareToolCallCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    active_fenced_lease(&cmd.envelope, meta.now)?;
    let parent = cmd
        .state
        .attempt
        .as_ref()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if parent.state != AttemptState::AttemptInvoked {
        return Err(failure(FailureKind::Denied, "PARENT_ATTEMPT_NOT_INVOKED"));
    }
    if cmd.tool_call_id.is_nil()
        || cmd.tool_attempt_id.is_nil()
        || cmd.tool_logical_operation_id.is_nil()
        || cmd.physical_attempt_id.is_nil()
        || cmd.call_sequence <= 0
        || cmd.attempt_sequence != 1
    {
        return Err(failure(FailureKind::Invalid, "INVALID_TOOL_CALL_IDENTITY"));
    }
    if cmd.expected.tool_call != 0 || cmd.expected.tool_attempt != 0 {
        return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
    }
    ensure_no_other_active_tool(&cmd.state, NIL_TOOL_CALL_ID, NIL_TOOL_CALL_ATTEMPT_ID)?;
    let mut next_call_sequence = 1i64;
    for call in &cmd.state.tool_calls {
        if call.id == cmd.tool_call_id
            || call.logical_operation_id == cmd.tool_logical_operation_id
            || call.sequence == cmd.call_sequence
        {
            return Err(failure(FailureKind::Conflict, "TOOL_CALL_CONFLICT"));
        }
        if call.sequence >= next_call_sequence {
            next_call_sequence = call.sequence + 1;
        }
    }
    for attempt in &cmd.state.tool_attempts {
        if attempt.id == cmd.tool_attempt_id
            || attempt.logical_operation_id == cmd.tool_logical_operation_id
            || attempt.physical_attempt_id == cmd.physical_attempt_id
        {
            return Err(failure(FailureKind::Conflict, "TOOL_CALL_CONFLICT"));
        }
    }
    if cmd.call_sequence != next_call_sequence {
        return Err(failure(
            FailureKind::Conflict,
            "TOOL_CALL_SEQUENCE_CONFLICT",
        ));
    }
    if let Some(approval) = &cmd.state.approval {
        if approval.state == ApprovalState::ApprovalPending {
            return Err(failure(FailureKind::Denied, "APPROVAL_REQUIRED"));
        }
        validate_approved_subject(
            approval,
            cmd.tool_logical_operation_id,
            cmd.envelope.operation_digest,
            cmd.approval_subject_version,
            cmd.approval_expected_step_version,
        )?;
    }
    let call = ToolCall {
        id: cmd.tool_call_id,
        step_attempt_id: cmd.attempt_id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        logical_operation_id: cmd.tool_logical_operation_id,
        version: 1,
        sequence: cmd.call_sequence,
        state: ToolCallState::ToolCallPrepared,
        created_at: meta.now,
        updated_at: meta.now,
    };
    let attempt = ToolCallAttempt {
        id: cmd.tool_attempt_id,
        tool_call_id: cmd.tool_call_id,
        step_attempt_id: cmd.attempt_id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        logical_operation_id: cmd.tool_logical_operation_id,
        physical_attempt_id: cmd.physical_attempt_id,
        invocation_id: InvocationId::default(),
        predecessor_id: NIL_TOOL_CALL_ATTEMPT_ID,
        version: 1,
        sequence: cmd.attempt_sequence,
        state: AttemptState::AttemptPrepared,
        created_at: meta.now,
        updated_at: meta.now,
    };
    with_tool_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            tool_calls: vec![call],
            tool_attempts: vec![attempt],
            attempt_assertions: vec![assertion_for(parent)],
            ..ExecutionChangeSet::default()
        },
        cmd.tool_call_id,
        cmd.tool_attempt_id,
        EVENT_TOOL_CALL_PREPARED,
        OUTBOX_TOOL_CALL_PREPARED,
        ToolCallState::ToolCallPrepared.as_str(),
        "",
    )
}

fn evaluate_mark_tool_call_invoked(
    cmd: &MarkToolCallInvokedCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    active_fenced_lease(&cmd.envelope, meta.now)?;
    let parent = cmd
        .state
        .attempt
        .as_ref()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if parent.state != AttemptState::AttemptInvoked {
        return Err(failure(FailureKind::Denied, "PARENT_ATTEMPT_NOT_INVOKED"));
    }
    let (call, attempt) = selected_tool_state(
        &cmd.state,
        cmd.tool_call_id,
        cmd.tool_attempt_id,
        cmd.tool_logical_operation_id,
    )?;
    ensure_no_other_active_tool(&cmd.state, call.id, attempt.id)?;
    if cmd.expected.tool_call <= 0
        || cmd.expected.tool_attempt <= 0
        || cmd.expected.tool_call != call.version
        || cmd.expected.tool_attempt != attempt.version
    {
        return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
    }
    if let Some(approval) = &cmd.state.approval {
        validate_approved_subject(
            approval,
            cmd.tool_logical_operation_id,
            cmd.envelope.operation_digest,
            cmd.approval_subject_version,
            cmd.approval_expected_step_version,
        )?;
    }
    let mut next_call = transition_tool_call(call, ToolCallState::ToolCallInvoked)?;
    if attempt.state != AttemptState::AttemptPrepared
        || cmd.invocation_id.is_nil()
        || !attempt.invocation_id.is_nil()
    {
        return Err(failure(FailureKind::Denied, "IMMUTABLE_ATTEMPT"));
    }
    let mut next_attempt = attempt;
    next_attempt.state = AttemptState::AttemptInvoked;
    next_attempt.invocation_id = cmd.invocation_id;
    next_attempt.version += 1;
    next_call.updated_at = meta.now;
    next_attempt.updated_at = meta.now;
    with_tool_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            tool_calls: vec![next_call],
            tool_attempts: vec![next_attempt],
            attempt_assertions: vec![assertion_for(parent)],
            ..ExecutionChangeSet::default()
        },
        cmd.tool_call_id,
        cmd.tool_attempt_id,
        EVENT_TOOL_CALL_INVOKED,
        OUTBOX_TOOL_CALL_INVOKED,
        ToolCallState::ToolCallInvoked.as_str(),
        "",
    )
}

fn evaluate_settle_tool_call(
    cmd: &SettleToolCallCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    active_fenced_lease(&cmd.envelope, meta.now)?;
    let parent = cmd
        .state
        .attempt
        .as_ref()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if parent.state != AttemptState::AttemptInvoked {
        return Err(failure(FailureKind::Denied, "PARENT_ATTEMPT_NOT_INVOKED"));
    }
    if !matches!(
        cmd.final_state,
        AttemptState::AttemptSucceeded | AttemptState::AttemptFailed
    ) {
        return Err(failure(FailureKind::Invalid, "INVALID_TOOL_SETTLEMENT"));
    }
    if cmd.outcome.is_empty() {
        return Err(failure(FailureKind::Invalid, "OUTCOME_REQUIRED"));
    }
    validate_optional_payload(
        &cmd.outcome,
        OUTCOME_PAYLOAD_MAX_BYTES,
        OUTCOME_PAYLOAD_SCHEMA,
    )?;
    validate_optional_payload(
        &cmd.context,
        CONTEXT_PAYLOAD_MAX_BYTES,
        CONTEXT_PAYLOAD_SCHEMA,
    )?;
    let (call, attempt) = selected_tool_state(
        &cmd.state,
        cmd.tool_call_id,
        cmd.tool_attempt_id,
        cmd.tool_logical_operation_id,
    )?;
    ensure_no_other_active_tool(&cmd.state, call.id, attempt.id)?;
    if cmd.expected.tool_call <= 0
        || cmd.expected.tool_attempt <= 0
        || cmd.expected.tool_call != call.version
        || cmd.expected.tool_attempt != attempt.version
    {
        return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
    }
    let (tool_calls, tool_attempts) =
        terminalize_tool_hierarchy(&[call], &[attempt], cmd.final_state, meta.now)?;
    let settlement = ToolSettlement {
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        step_id: cmd.step_id,
        attempt_id: cmd.attempt_id,
        tool_call_id: cmd.tool_call_id,
        tool_attempt_id: cmd.tool_attempt_id,
        step_attempt_id: cmd.attempt_id,
        invocation_id: tool_attempts[0].invocation_id,
        final_state: cmd.final_state,
        outcome: cmd.outcome.clone(),
        context: cmd.context.clone(),
        settled_at: meta.now,
    };
    with_tool_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            tool_calls: tool_calls.clone(),
            tool_attempts,
            tool_settlements: vec![settlement],
            attempt_assertions: vec![assertion_for(parent)],
            ..ExecutionChangeSet::default()
        },
        cmd.tool_call_id,
        cmd.tool_attempt_id,
        EVENT_TOOL_CALL_SETTLED,
        OUTBOX_TOOL_CALL_SETTLED,
        tool_calls[0].state.as_str(),
        "",
    )
}

fn evaluate_settle(
    cmd: &SettleCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    let lease = active_fenced_lease(&cmd.envelope, meta.now)?;
    if !matches!(
        cmd.final_state,
        AttemptState::AttemptSucceeded | AttemptState::AttemptFailed
    ) {
        return Err(failure(FailureKind::Invalid, "INVALID_SETTLEMENT"));
    }
    let reason = crate::harness_run::settlement_failure_reason(cmd.final_state, cmd.reason_code)?;
    if cmd.outcome.is_empty() {
        return Err(failure(FailureKind::Invalid, "OUTCOME_REQUIRED"));
    }
    validate_optional_payload(
        &cmd.outcome,
        OUTCOME_PAYLOAD_MAX_BYTES,
        OUTCOME_PAYLOAD_SCHEMA,
    )?;
    validate_optional_payload(
        &cmd.context,
        CONTEXT_PAYLOAD_MAX_BYTES,
        CONTEXT_PAYLOAD_SCHEMA,
    )?;
    let mut attempt = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if attempt.state == AttemptState::AttemptInvoked {
        attempt = transition_attempt(attempt, AttemptState::AttemptSettling)?;
    }
    attempt = transition_attempt(attempt, cmd.final_state)?;
    attempt.updated_at = meta.now;
    let mut step = cmd
        .state
        .step
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    if step.state == StepState::StepRunning {
        step = transition_step(step, StepState::StepSettling)?;
    }
    let step_final = if cmd.final_state == AttemptState::AttemptFailed {
        StepState::StepFailed
    } else {
        StepState::StepSucceeded
    };
    step = transition_step(step, step_final)?;
    step.updated_at = meta.now;
    let task_transition = settlement_task_transition(
        cmd.state.task.clone(),
        cmd.expected,
        cmd.final_state,
        reason,
        meta.now,
    )?;
    let (tool_calls, tool_attempts) = terminalize_tool_hierarchy(
        &cmd.state.tool_calls,
        &cmd.state.tool_attempts,
        cmd.final_state,
        meta.now,
    )?;
    let change = ExecutionChangeSet {
        steps: vec![step],
        attempts: vec![attempt.clone()],
        tool_calls,
        tool_attempts,
        settlements: vec![Settlement {
            workspace_id: cmd.workspace_id,
            task_id: cmd.task_id,
            run_id: cmd.run_id,
            step_id: cmd.step_id,
            attempt_id: cmd.attempt_id,
            invocation_id: attempt.invocation_id,
            final_state: cmd.final_state,
            outcome: cmd.outcome.clone(),
            context: cmd.context.clone(),
            settled_at: meta.now,
        }],
        lease_releases: vec![release_for(&lease)],
        task_transition: Some(task_transition),
        ..ExecutionChangeSet::default()
    };
    with_evidence(
        &cmd.envelope,
        meta,
        change,
        EVENT_ATTEMPT_SETTLED,
        OUTBOX_ATTEMPT_SETTLED,
        cmd.final_state.as_str(),
        reason,
    )
}

fn evaluate_cancel(
    cmd: &CancelCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(
        &cmd.envelope,
        meta,
        Capability::WorkspaceOperator,
        true,
        false,
    )?;
    let attempt = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    let mut attempt = match transition_attempt(attempt.clone(), AttemptState::AttemptCancelled) {
        Ok(a) => a,
        Err(e) => {
            if matches!(
                attempt.state,
                AttemptState::AttemptInvoked | AttemptState::AttemptSettling
            ) {
                return Err(failure(FailureKind::Denied, "RECONCILIATION_REQUIRED"));
            }
            return Err(e);
        }
    };
    attempt.updated_at = meta.now;
    let mut step = transition_step(
        cmd.state
            .step
            .clone()
            .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?,
        StepState::StepCancelled,
    )?;
    step.updated_at = meta.now;
    let task_transition =
        cancellation_task_transition(cmd.state.task.clone(), cmd.expected, meta.now)?;
    let (tool_calls, tool_attempts) = terminalize_tool_hierarchy(
        &cmd.state.tool_calls,
        &cmd.state.tool_attempts,
        AttemptState::AttemptCancelled,
        meta.now,
    )?;
    let mut change = ExecutionChangeSet {
        steps: vec![step],
        attempts: vec![attempt],
        tool_calls,
        tool_attempts,
        task_transition: Some(task_transition),
        ..ExecutionChangeSet::default()
    };
    let active = cmd
        .state
        .lease
        .as_ref()
        .is_some_and(|l| l.expires_at > meta.now);
    if active {
        let lease = active_fenced_lease(&cmd.envelope, meta.now)?;
        change.lease_releases = vec![release_for(&lease)];
    } else {
        let assertion = no_active_lease_assertion(&cmd.envelope, meta.now)?;
        change.lease_assertions = vec![assertion];
    }
    with_evidence(
        &cmd.envelope,
        meta,
        change,
        EVENT_ATTEMPT_CANCELLED,
        OUTBOX_ATTEMPT_SETTLED,
        AttemptState::AttemptCancelled.as_str(),
        &cmd.reason_code,
    )
}

fn evaluate_record_checkpoint(
    cmd: &RecordCheckpointCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Executor, true, false)?;
    active_fenced_lease(&cmd.envelope, meta.now)?;
    let mut checkpoint = cmd.checkpoint.clone();
    if checkpoint.id.is_nil() {
        return Err(failure(FailureKind::Invalid, "INVALID_CHECKPOINT_IDENTITY"));
    }
    checkpoint.workspace_id = cmd.workspace_id;
    checkpoint.task_id = cmd.task_id;
    checkpoint.run_id = cmd.run_id;
    checkpoint.step_id = cmd.step_id;
    checkpoint.step_attempt_id = cmd.attempt_id;
    checkpoint.recorded_at = meta.now;
    let state_str = cmd.state.attempt.as_ref().map_or("", |a| a.state.as_str());
    with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            checkpoints: vec![checkpoint],
            ..ExecutionChangeSet::default()
        },
        EVENT_CHECKPOINT_RECORDED,
        OUTBOX_CHECKPOINT_RECORDED,
        state_str,
        "",
    )
}

fn evaluate_record_approval(
    cmd: &RecordApprovalCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Approver, false, false)?;
    let mut approval = cmd.approval.clone();
    if approval.id.is_nil()
        || approval.subject.version <= 0
        || approval.subject.logical_operation_id != cmd.envelope.logical_operation
        || !fingerprint_valid(&approval.subject.operation_digest)
        || !fingerprint_valid(&cmd.envelope.operation_digest)
        || approval.subject.operation_digest != cmd.envelope.operation_digest
        || approval.subject.expected_step_version != cmd.expected.step
        || approval.state != ApprovalState::ApprovalPending
    {
        return Err(failure(FailureKind::Invalid, "APPROVAL_SUBJECT_MISMATCH"));
    }
    approval.workspace_id = cmd.workspace_id;
    approval.task_id = cmd.task_id;
    approval.run_id = cmd.run_id;
    approval.step_id = cmd.step_id;
    approval.version = 1;
    approval.recorded_at = meta.now;
    let mut step = transition_step(
        cmd.state
            .step
            .clone()
            .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?,
        StepState::StepWaiting,
    )?;
    step.updated_at = meta.now;
    let task_transition = execution_facade::evaluate_execution_transition(
        ExecutionTransition::Wait(execution_facade::ExecutionWaitRequest {
            aggregate: cmd.state.task.clone(),
            reason: Some(task::WaitingReason::Approval),
            detail: "execution approval required".to_string(),
            now: meta.now,
            expected_task_version: cmd.expected.task,
            expected_run_version: cmd.expected.run,
        }),
    )
    .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
    let assertion = no_active_lease_assertion(&cmd.envelope, meta.now)?;
    with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            steps: vec![step.clone()],
            approvals: vec![approval],
            lease_assertions: vec![assertion],
            task_transition: Some(task_transition),
            ..ExecutionChangeSet::default()
        },
        EVENT_APPROVAL_RECORDED,
        OUTBOX_APPROVAL_RECORDED,
        step.state.as_str(),
        "",
    )
}

fn evaluate_resolve_approval(
    cmd: &ResolveApprovalCommand,
    meta: &EvaluationMetadata,
    expiration: bool,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(&cmd.envelope, meta, Capability::Approver, false, false)?;
    let approval_state = cmd
        .state
        .approval
        .as_ref()
        .ok_or_else(|| failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"))?;
    if approval_state.id != cmd.approval_id || cmd.expected.approval != approval_state.version {
        return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
    }
    if expiration && cmd.decision != ApprovalState::ApprovalExpired {
        return Err(failure(FailureKind::Invalid, "INVALID_APPROVAL_DECISION"));
    }
    if !expiration
        && !matches!(
            cmd.decision,
            ApprovalState::ApprovalApproved | ApprovalState::ApprovalRejected
        )
    {
        return Err(failure(FailureKind::Invalid, "INVALID_APPROVAL_DECISION"));
    }
    let mut approval = transition_approval(approval_state.clone(), cmd.decision)?;
    approval.actor = meta.principal_id.clone();
    approval.decision_id = decision_id_from_event(meta.event_id);
    approval.decided_at = meta.now;
    let mut change = ExecutionChangeSet {
        approvals: vec![approval],
        ..ExecutionChangeSet::default()
    };
    if cmd.decision == ApprovalState::ApprovalApproved {
        let task_transition = execution_facade::evaluate_execution_transition(
            ExecutionTransition::ResumeSameRun(execution_facade::ExecutionResumeSameRunRequest {
                aggregate: cmd.state.task.clone(),
                now: meta.now,
                expected_task_version: cmd.expected.task,
                expected_run_version: cmd.expected.run,
            }),
        )
        .map_err(|_| failure(FailureKind::Denied, "TASK_TRANSITION_REJECTED"))?;
        change.task_transition = Some(task_transition);
    } else if matches!(
        cmd.decision,
        ApprovalState::ApprovalRejected | ApprovalState::ApprovalExpired
    ) {
        let mut step = transition_step(
            cmd.state
                .step
                .clone()
                .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?,
            StepState::StepCancelled,
        )?;
        step.updated_at = meta.now;
        change.steps = vec![step];
        if let Some(attempt) = &cmd.state.attempt {
            let mut attempt =
                match transition_attempt(attempt.clone(), AttemptState::AttemptCancelled) {
                    Ok(a) => a,
                    Err(e) => {
                        if matches!(
                            attempt.state,
                            AttemptState::AttemptInvoked | AttemptState::AttemptSettling
                        ) {
                            return Err(failure(FailureKind::Denied, "RECONCILIATION_REQUIRED"));
                        }
                        return Err(e);
                    }
                };
            attempt.updated_at = meta.now;
            let (tool_calls, tool_attempts) = terminalize_tool_hierarchy(
                &cmd.state.tool_calls,
                &cmd.state.tool_attempts,
                AttemptState::AttemptCancelled,
                meta.now,
            )?;
            change.attempts = vec![attempt];
            change.tool_calls = tool_calls;
            change.tool_attempts = tool_attempts;
            if cmd.state.lease.is_some() {
                let lease = active_fenced_lease(&cmd.envelope, meta.now)?;
                change.lease_releases = vec![release_for(&lease)];
            } else {
                let assertion = no_active_lease_assertion(&cmd.envelope, meta.now)?;
                change.lease_assertions = vec![assertion];
            }
        }
    }
    if change.lease_releases.is_empty() && change.lease_assertions.is_empty() {
        let assertion = no_active_lease_assertion(&cmd.envelope, meta.now)?;
        change.lease_assertions = vec![assertion];
    }
    let kind = if expiration {
        EVENT_APPROVAL_EXPIRED
    } else {
        EVENT_APPROVAL_RESOLVED
    };
    let state_str = cmd.state.step.as_ref().map_or("", |s| s.state.as_str());
    with_evidence(
        &cmd.envelope,
        meta,
        change,
        kind,
        OUTBOX_APPROVAL_RECORDED,
        state_str,
        cmd.decision.as_str(),
    )
}

fn evaluate_create_approval_successor(
    cmd: &CreateApprovalSuccessorCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(
        &cmd.envelope,
        meta,
        Capability::WorkspaceOperator,
        false,
        false,
    )?;
    let prior = cmd
        .state
        .approval
        .as_ref()
        .filter(|a| {
            a.id == cmd.approval_id
                && matches!(
                    a.state,
                    ApprovalState::ApprovalRejected | ApprovalState::ApprovalExpired
                )
        })
        .ok_or_else(|| failure(FailureKind::Denied, "APPROVAL_SUCCESSOR_NOT_ALLOWED"))?;
    if cmd.expected.approval != prior.version {
        return Err(failure(FailureKind::Conflict, "EXPECTED_VERSION_CONFLICT"));
    }
    let step_sequence = cmd.state.step.as_ref().map_or(0, |s| s.sequence);
    if cmd.successor_step_id.is_nil()
        || cmd.successor_approval_id.is_nil()
        || cmd.subject.version <= prior.subject.version
        || cmd.subject.logical_operation_id.is_nil()
        || cmd.subject.logical_operation_id == prior.subject.logical_operation_id
        || !fingerprint_valid(&cmd.subject.operation_digest)
        || !fingerprint_valid(&cmd.envelope.operation_digest)
        || cmd.subject.operation_digest != cmd.envelope.operation_digest
        || cmd.subject.expected_step_version != 1
    {
        return Err(failure(FailureKind::Invalid, "APPROVAL_SUBJECT_MISMATCH"));
    }
    let step = Step {
        id: cmd.successor_step_id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        version: 1,
        sequence: step_sequence + 1,
        state: StepState::StepQueued,
        created_at: meta.now,
        updated_at: meta.now,
    };
    let approval = Approval {
        id: cmd.successor_approval_id,
        workspace_id: cmd.workspace_id,
        task_id: cmd.task_id,
        run_id: cmd.run_id,
        step_id: step.id,
        state: ApprovalState::ApprovalPending,
        subject: cmd.subject.clone(),
        predecessor_id: prior.id,
        actor: String::new(),
        reason_code: String::new(),
        decision_id: [0u8; 16],
        decided_at: ZERO_TIME,
        version: 1,
        recorded_at: meta.now,
    };
    let assertion = no_active_lease_assertion(&cmd.envelope, meta.now)?;
    with_evidence(
        &cmd.envelope,
        meta,
        ExecutionChangeSet {
            steps: vec![step],
            approvals: vec![approval],
            lease_assertions: vec![assertion],
            ..ExecutionChangeSet::default()
        },
        EVENT_APPROVAL_SUCCESSOR,
        OUTBOX_APPROVAL_RECORDED,
        StepState::StepQueued.as_str(),
        "",
    )
}

fn evaluate_resolve_reconciliation(
    cmd: &ResolveReconciliationCommand,
    meta: &EvaluationMetadata,
) -> Result<ExecutionChangeSet, Failure> {
    validate_evaluation(
        &cmd.envelope,
        meta,
        Capability::WorkspaceOperator,
        true,
        false,
    )?;
    let evidence = clone_and_validate_evidence(&cmd.evidence)?;
    let attempt_src = cmd
        .state
        .attempt
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    let mut attempt = resolve_attempt_reconciliation(attempt_src, cmd.disposition)?;
    attempt.updated_at = meta.now;
    let step_src = cmd
        .state
        .step
        .clone()
        .ok_or_else(|| failure(FailureKind::Invalid, "STATE_SCOPE_MISMATCH"))?;
    let mut step = resolve_step_reconciliation(step_src, cmd.disposition)?;
    step.updated_at = meta.now;
    let task_transition = reconciliation_task_transition(
        cmd.state.task.clone(),
        cmd.expected,
        cmd.disposition,
        meta.now,
    )?;
    let (tool_calls, tool_attempts) = resolve_tool_hierarchy_reconciliation(
        &cmd.state.tool_calls,
        &cmd.state.tool_attempts,
        cmd.disposition,
        meta.now,
    )?;
    let mut change = ExecutionChangeSet {
        steps: vec![step],
        attempts: vec![attempt.clone()],
        tool_calls,
        tool_attempts,
        reconciliations: vec![Reconciliation {
            workspace_id: cmd.workspace_id,
            task_id: cmd.task_id,
            run_id: cmd.run_id,
            step_id: cmd.step_id,
            attempt_id: cmd.attempt_id,
            disposition: cmd.disposition,
            evidence,
            resolved_at: meta.now,
        }],
        task_transition: Some(task_transition),
        ..ExecutionChangeSet::default()
    };
    let active = cmd
        .state
        .lease
        .as_ref()
        .is_some_and(|l| l.expires_at > meta.now);
    if active {
        let lease = active_fenced_lease(&cmd.envelope, meta.now)?;
        change.lease_releases = vec![release_for(&lease)];
    } else {
        let assertion = no_active_lease_assertion(&cmd.envelope, meta.now)?;
        change.lease_assertions = vec![assertion];
    }
    with_evidence(
        &cmd.envelope,
        meta,
        change,
        EVENT_RECONCILIATION_RESOLVED,
        OUTBOX_ATTEMPT_SETTLED,
        attempt.state.as_str(),
        cmd.disposition.as_str(),
    )
}

/// `cloneAndValidateReconciliationEvidence` — Rust values are owned, so
/// "clone" is free; the bound and item checks are identical.
pub(crate) fn clone_and_validate_evidence(
    evidence: &[ReconciliationEvidence],
) -> Result<Vec<ReconciliationEvidence>, Failure> {
    if evidence.is_empty() {
        return Err(failure(
            FailureKind::Invalid,
            "RECONCILIATION_EVIDENCE_REQUIRED",
        ));
    }
    if evidence.len() > MAX_RECONCILIATION_EVIDENCE {
        return Err(failure(
            FailureKind::Invalid,
            "RECONCILIATION_EVIDENCE_TOO_LARGE",
        ));
    }
    let mut total = 0usize;
    let mut out = Vec::with_capacity(evidence.len());
    for item in evidence {
        let reference = item.reference.trim().to_string();
        if reference.is_empty() {
            return Err(failure(
                FailureKind::Invalid,
                "INVALID_RECONCILIATION_EVIDENCE",
            ));
        }
        if reference.len() > MAX_RECONCILIATION_EVIDENCE_REFERENCE_BYTES {
            return Err(failure(
                FailureKind::Invalid,
                "RECONCILIATION_EVIDENCE_TOO_LARGE",
            ));
        }
        total += item.kind.as_str().len() + reference.len();
        if total > MAX_RECONCILIATION_EVIDENCE_TOTAL_BYTES {
            return Err(failure(
                FailureKind::Invalid,
                "RECONCILIATION_EVIDENCE_TOO_LARGE",
            ));
        }
        out.push(ReconciliationEvidence {
            kind: item.kind,
            reference,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Descriptors + retention (upstream Describe*/RetentionPolicy).
// ---------------------------------------------------------------------------

/// `ExpectedVersions` derived from state (upstream expectedVersionsFor).
#[must_use]
pub fn expected_versions_for(state: &ExecutionState) -> ExpectedVersions {
    let mut expected = ExpectedVersions {
        task: state.task.task.version,
        ..ExpectedVersions::default()
    };
    if let Some(run) = &state.task.current_run {
        expected.run = run.version;
    }
    if let Some(step) = &state.step {
        expected.step = step.version;
    }
    if let Some(attempt) = &state.attempt {
        expected.attempt = attempt.version;
    }
    if let Some(approval) = &state.approval {
        expected.approval = approval.version;
    }
    expected
}

/// One resolvable reconciliation action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationAction {
    pub disposition: ReconciliationDisposition,
    pub required_evidence: Vec<ReconciliationEvidenceKind>,
}

/// The descriptor an operator UI renders for a reconciling attempt.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReconciliationActionDescriptor {
    pub authorized: bool,
    pub requires_active_lease_fence: bool,
    pub requires_no_active_lease: bool,
    pub lease_generation: i64,
    pub expected_versions: ExpectedVersions,
    pub actions: Vec<ReconciliationAction>,
}

/// `DescribeReconciliationActions`.
#[must_use]
pub fn describe_reconciliation_actions(
    scope: &TrustedScope,
    state: &ExecutionState,
    now: OffsetDateTime,
) -> ReconciliationActionDescriptor {
    let mut descriptor = ReconciliationActionDescriptor {
        expected_versions: expected_versions_for(state),
        ..ReconciliationActionDescriptor::default()
    };
    let authorized = now != ZERO_TIME
        && scope.allows(Capability::WorkspaceOperator)
        && state.step.is_some()
        && state.attempt.is_some()
        && state.step.as_ref().is_some_and(|s| {
            s.workspace_id == scope.workspace_id && s.state == StepState::StepReconciliation
        })
        && state.attempt.as_ref().is_some_and(|a| {
            a.workspace_id == scope.workspace_id && a.state == AttemptState::AttemptReconciliation
        });
    if !authorized {
        return descriptor;
    }
    descriptor.authorized = true;
    if let Some(lease) = &state.lease
        && lease.workspace_id == scope.workspace_id
        && lease.expires_at > now
        && lease.generation > 0
    {
        descriptor.requires_active_lease_fence = true;
        descriptor.lease_generation = lease.generation;
        return finish_actions(descriptor);
    }
    descriptor.requires_no_active_lease = true;
    finish_actions(descriptor)
}

fn finish_actions(
    mut descriptor: ReconciliationActionDescriptor,
) -> ReconciliationActionDescriptor {
    descriptor.actions = vec![
        ReconciliationAction {
            disposition: ReconciliationDisposition::ReconciliationConfirmSucceeded,
            required_evidence: vec![
                ReconciliationEvidenceKind::ReconciliationEvidenceCompletionReceipt,
            ],
        },
        ReconciliationAction {
            disposition: ReconciliationDisposition::ReconciliationConfirmFailed,
            required_evidence: vec![
                ReconciliationEvidenceKind::ReconciliationEvidenceCompletionReceipt,
            ],
        },
        ReconciliationAction {
            disposition: ReconciliationDisposition::ReconciliationCancel,
            required_evidence: vec![
                ReconciliationEvidenceKind::ReconciliationEvidenceOperatorAttestation,
            ],
        },
    ];
    descriptor
}

/// The approval-successor action descriptor returned to B11's lane.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalSuccessorActionDescriptor {
    pub action: Option<ApprovalAction>,
    pub authorized: bool,
    pub required_capability: Option<Capability>,
    pub step_id: StepId,
    pub approval_id: ApprovalId,
    pub logical_operation_id: LogicalOperationId,
    pub approval_subject_version: i64,
    pub expected_versions: ExpectedVersions,
}

/// `DescribeApprovalSuccessorAction`.
#[must_use]
pub fn describe_approval_successor_action(
    scope: &TrustedScope,
    state: &ExecutionState,
    step: &Step,
    approval: &Approval,
) -> ApprovalSuccessorActionDescriptor {
    let mut descriptor = ApprovalSuccessorActionDescriptor {
        action: None,
        authorized: false,
        required_capability: Some(Capability::Approver),
        step_id: NIL_STEP_ID,
        approval_id: NIL_APPROVAL_ID,
        logical_operation_id: LogicalOperationId::default(),
        approval_subject_version: 0,
        expected_versions: ExpectedVersions::default(),
    };
    let authorized = scope.allows(Capability::Approver)
        && step.workspace_id == scope.workspace_id
        && approval.workspace_id == scope.workspace_id
        && approval.state == ApprovalState::ApprovalPending
        && approval.step_id == step.id
        && !approval.subject.logical_operation_id.is_nil()
        && approval.subject.version > 0;
    if !authorized {
        return descriptor;
    }
    descriptor.authorized = true;
    descriptor.action = Some(ApprovalAction::ActionResolveApproval);
    descriptor.step_id = step.id;
    descriptor.approval_id = approval.id;
    descriptor.logical_operation_id = approval.subject.logical_operation_id;
    descriptor.approval_subject_version = approval.subject.version;
    descriptor.expected_versions = expected_versions_for(state);
    descriptor.expected_versions.step = step.version;
    descriptor.expected_versions.attempt = 0;
    descriptor.expected_versions.tool_call = 0;
    descriptor.expected_versions.tool_attempt = 0;
    descriptor.expected_versions.approval = approval.version;
    descriptor
}

/// Retention classes (upstream `RetentionClass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionClass {
    /// Mutable operational rows.
    Operational,
    /// Evidence rows.
    Evidence,
}

/// A record the retention policy evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionRecord {
    pub class: RetentionClass,
    /// `None` is Go's zero `time.Time` — never eligible.
    pub recorded_at: Option<OffsetDateTime>,
    pub legal_hold: bool,
}

/// `RetentionPolicy` — deletion eligibility windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub version: i64,
    pub operational_period: Duration,
    pub evidence_period: Duration,
}

/// `DefaultRetentionPolicy` — 7d operational / 90d evidence.
#[must_use]
pub const fn default_retention_policy() -> RetentionPolicy {
    RetentionPolicy {
        version: 1,
        operational_period: RETENTION_OPERATIONAL,
        evidence_period: RETENTION_EVIDENCE,
    }
}

impl RetentionPolicy {
    /// `EligibleAt` — `None` under a legal hold, unknown class, or an
    /// unrecorded row.
    #[must_use]
    pub fn eligible_at(&self, record: RetentionRecord) -> Option<OffsetDateTime> {
        if record.legal_hold {
            return None;
        }
        let recorded_at = record.recorded_at?;
        Some(match record.class {
            RetentionClass::Operational => recorded_at + self.operational_period,
            RetentionClass::Evidence => recorded_at + self.evidence_period,
        })
    }
}
