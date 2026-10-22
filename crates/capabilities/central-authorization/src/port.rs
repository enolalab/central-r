//! Command-persistence and evidence ports for `central-authorization`.
//!
//! Operation-oriented contracts (rust-application-boundaries.md §2.4):
//! no SQL text, no transaction handles, no table mirroring. The
//! application layer calls these after a pure domain evaluation has
//! produced a decision/change set; the adapter (Task 7) implements
//! them over `central.approvals`, `central.secret_use`, and the genesis
//! binding/receipt storage.
//!
//! Every trait is `Send + Sync + 'static` and generated through
//! `#[trait_variant::make(Send)]` so implementations are object-safe
//! behind `Arc<dyn …>`.

use central_foundation::failure::Failure;
use central_foundation::identity::{ApprovalId, OperationId, WorkspaceId};

use crate::domain::{
    ApprovalChangeSet, ApprovalRecord, GenesisReceipt, GenesisStatus, InstanceBinding,
    SecretUseEvidence,
};

/// Load + guarded-commit port for capability-grant approval records.
///
/// `commit_approval_change_set` performs the optimistic-lock write:
/// it fails with `FailureKind::Conflict` when the stored row's version
/// no longer equals `ApprovalChangeSet::expected_version` — the only
/// way a decision escapes the version it was evaluated against.
#[trait_variant::make(Send)]
pub trait ApprovalStore: Send + Sync + 'static {
    /// Loads one approval record by identity inside its Workspace.
    /// `FailureKind::NotFound`/`codes::APPROVAL_NOT_FOUND` when absent.
    async fn load_approval(
        &self,
        workspace_id: WorkspaceId,
        approval_id: ApprovalId,
    ) -> Result<ApprovalRecord, Failure>;

    /// Atomically persists an already-evaluated change set under its
    /// optimistic-lock guard.
    async fn commit_approval_change_set(
        &self,
        change_set: ApprovalChangeSet,
    ) -> Result<(), Failure>;

    /// Inserts a fresh record (`version == 0`). Conflict when the
    /// identity already exists.
    async fn insert_approval(&self, record: ApprovalRecord) -> Result<(), Failure>;

    /// Loads every approval row of one Workspace — used by the
    /// post-restore authority reset to suspend all `active` grants.
    /// Bounded by the caller's reset protocol, not by pagination.
    async fn load_workspace_approvals(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ApprovalRecord>, Failure>;
}

/// Append-only audit port for `central.secret_use` evidence rows
/// (§3.19). Evidence is immutable — there is no update path by
/// contract.
#[trait_variant::make(Send)]
pub trait SecretUseEvidenceLog: Send + Sync + 'static {
    /// Appends one validated evidence row.
    async fn append_secret_use(&self, evidence: SecretUseEvidence) -> Result<(), Failure>;
}

/// Genesis binding/receipt port (upstream `internal/authority`
/// genesis store): the durable instance binding, the committed
/// receipt, and the operation's current status.
#[trait_variant::make(Send)]
pub trait GenesisStore: Send + Sync + 'static {
    /// Loads the durable [`InstanceBinding`], if genesis has bound this
    /// host. `Ok(None)` before first genesis.
    async fn load_instance_binding(&self) -> Result<Option<InstanceBinding>, Failure>;

    /// Persists the instance binding established at genesis.
    async fn store_instance_binding(&self, binding: InstanceBinding) -> Result<(), Failure>;

    /// Loads the genesis status of one operation — phase plus receipt
    /// when committed.
    async fn load_genesis_status(
        &self,
        operation_id: OperationId,
    ) -> Result<GenesisStatus, Failure>;

    /// Commits the genesis receipt of one operation. The caller passes
    /// the [`InstanceId`] the receipt binds; the adapter enforces the
    /// at-most-once commit.
    async fn commit_genesis_receipt(&self, receipt: GenesisReceipt) -> Result<(), Failure>;
}
