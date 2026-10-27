//! Backup/migration ports (ports `internal/backup/port/migration_port.go`;
//! rust-application-boundaries.md §2.3).
//!
//! The migration-domain contracts live here, owned by the
//! backup/lifecycle capability — not by the PostgreSQL adapter that
//! implements them. `sqlx` types never appear; the adapter maps its
//! session/row types at the boundary.

use central_foundation::failure::Failure;

use crate::domain::{ExternalRecordState, ProvisioningPhase};
use crate::domain::{ResetConfirmation, SessionBinding, TargetIdentity, VerifiedEmptyTarget};

/// Broker proof service — the authorization boundary between the migration
/// runner/reset runner and the broker that signs one-use proofs. Ports
/// `port.BrokerProofService`; upstream ships no in-crate implementation,
/// so this crate only defines the contract (tests use fakes exactly as
/// upstream does).
#[trait_variant::make(Send)]
pub trait BrokerProofService {
    /// Issue an empty-target proof for `req`.
    async fn issue_empty_target_proof(
        &self,
        req: IssueEmptyTargetProofRequest,
    ) -> Result<VerifiedEmptyTarget, Failure>;
    /// Verify (without consuming) `proof` against `target`.
    async fn verify_empty_target(
        &self,
        target: &TargetIdentity,
        proof: &VerifiedEmptyTarget,
    ) -> Result<(), Failure>;
    /// Consume `proof` once.
    async fn consume_empty_proof(&self, proof: VerifiedEmptyTarget) -> Result<(), Failure>;
    /// Verify and consume `proof` against `target` in one step.
    async fn consume_verified_empty_target(
        &self,
        target: &TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> Result<(), Failure>;
    /// Issue a reset confirmation for `req`.
    async fn issue_reset_confirmation(
        &self,
        req: IssueResetConfirmationRequest,
    ) -> Result<ResetConfirmation, Failure>;
    /// Verify (without consuming) `confirmation`.
    async fn verify_reset_confirmation(
        &self,
        confirmation: &ResetConfirmation,
    ) -> Result<(), Failure>;
    /// Consume `confirmation` once.
    async fn consume_reset_confirmation(
        &self,
        confirmation: ResetConfirmation,
    ) -> Result<(), Failure>;
    /// Verify and consume `confirmation` against `target` in one step.
    async fn consume_verified_reset_confirmation(
        &self,
        target: &TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> Result<(), Failure>;
}

/// `port.UpRequest`.
#[derive(Debug, Clone)]
pub struct UpRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target the proof binds to.
    pub target: TargetIdentity,
    /// SHA-256 of the checksum manifest.
    pub embedded_baseline_digest: String,
    /// Broker-issued empty-target proof.
    pub proof: VerifiedEmptyTarget,
}

/// `port.PrepareUpRequest`.
#[derive(Debug, Clone)]
pub struct PrepareUpRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target identity.
    pub target: TargetIdentity,
}

/// `port.PrepareUpResult`.
#[derive(Debug, Clone)]
pub struct PrepareUpResult {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Captured session binding for the commit phase.
    pub session_binding: SessionBinding,
}

/// `port.CommitUpRequest`.
#[derive(Debug, Clone)]
pub struct CommitUpRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target identity.
    pub target: TargetIdentity,
    /// Binding captured by `prepare_up`.
    pub session_binding: SessionBinding,
    /// Broker-issued empty-target proof.
    pub proof: VerifiedEmptyTarget,
}

/// `port.UpResult`.
#[derive(Debug, Clone)]
pub struct UpResult {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// External record state after commit.
    pub record_state: ExternalRecordState,
    /// Session binding the mutation ran under.
    pub session_binding: SessionBinding,
}

/// `port.ResumeRequest`.
#[derive(Debug, Clone)]
pub struct ResumeRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target identity.
    pub target: TargetIdentity,
    /// Binding recorded when the operation started.
    pub expected_session_binding: SessionBinding,
    /// Binding captured for a fresh install leg.
    pub session_binding: SessionBinding,
    /// Broker proof (required only on the fresh-install leg).
    pub proof: VerifiedEmptyTarget,
}

/// `port.ResumeResult`.
#[derive(Debug, Clone)]
pub struct ResumeResult {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// External record state after resume.
    pub record_state: ExternalRecordState,
    /// Terminal provisioning phase.
    pub final_phase: ProvisioningPhase,
}

/// `port.ResetRequest`.
#[derive(Debug, Clone)]
pub struct ResetRequest {
    /// Target identity.
    pub target: TargetIdentity,
    /// Broker reset confirmation.
    pub confirmation: ResetConfirmation,
}

/// `port.IssueEmptyTargetProofRequest`.
#[derive(Debug, Clone)]
pub struct IssueEmptyTargetProofRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target identity.
    pub target: TargetIdentity,
    /// Session binding to bind the proof to.
    pub session_binding: SessionBinding,
    /// Baseline digest to bind.
    pub baseline_digest: String,
}

/// `port.IssueResetConfirmationRequest`.
#[derive(Debug, Clone)]
pub struct IssueResetConfirmationRequest {
    /// Operation identity.
    pub operation_id: uuid::Uuid,
    /// Target fingerprint to bind.
    pub target_fingerprint: String,
}

/// Object-safe boxed future the erased port traits return.
/// `#[trait_variant]` traits are not object-safe (return-position
/// `impl Future` cannot build a vtable), so the operator-facing seams
/// are written in this form directly. The futures are deliberately
/// **not** `Send`: the coordinator drives them on the one task that
/// owns the `&mut` session (upstream's conn-bound flow), and rustc
/// cannot prove the sqlx adapters' `async fn` futures `Send` across
/// all captured lifetimes. The trait *objects* stay `Send`/`Sync` —
/// they may be shared in `Arc`; their futures just may not migrate
/// threads mid-await.
pub type BoxFuture<'a, T> = core::pin::Pin<Box<dyn core::future::Future<Output = T> + 'a>>;

/// `port.MigrationRunner` — the single-session two-phase driver
/// contract, object-safe. The concrete
/// `central-adapter-postgres::migrate::Runner` implements it over the
/// one non-rebinding `central_migration` session.
pub trait MigrationRunner: Send {
    /// `PrepareUp` — locks + session binding + stock-target check.
    fn prepare_up<'a>(
        &'a mut self,
        req: &'a PrepareUpRequest,
    ) -> BoxFuture<'a, Result<PrepareUpResult, Failure>>;
    /// `CommitUp` — same-session binding + proof consume + install.
    fn commit_up<'a>(
        &'a mut self,
        req: &'a CommitUpRequest,
    ) -> BoxFuture<'a, Result<UpResult, Failure>>;
    /// `Up` — prepare then commit.
    fn up<'a>(&'a mut self, req: &'a UpRequest) -> BoxFuture<'a, Result<UpResult, Failure>>;
    /// `Resume` — repair leg or fresh-install leg.
    fn resume<'a>(
        &'a mut self,
        req: &'a ResumeRequest,
    ) -> BoxFuture<'a, Result<ResumeResult, Failure>>;
}

/// `port.MigrationInspector` — the read-only facts surface.
pub trait MigrationInspector: Send {
    /// `Inspect` — `central` schema facts; dirty evidence and a
    /// non-terminal chain are failures, not facts.
    fn inspect<'a>(&'a mut self) -> BoxFuture<'a, Result<PostgresMigrationFacts, Failure>>;
}

/// `port.ProtectedOperatorStateInspector` — the protected provisioning
/// record read the coordinator's status path needs. The inspector is
/// bound to one target at composition time (upstream `Inspect(ctx)`
/// takes no target); an absent record answers [`ProtectedOperatorState`]
/// with [`ExternalRecordState::Absent`], never an error.
pub trait ProtectedOperatorStateInspector: Send + Sync {
    /// `Inspect` — the bound target's protected record projection.
    fn inspect_operator_state<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<ProtectedOperatorState, Failure>>;
}

/// `port.ResetRunner` — the version-zero-only reset driver.
pub trait ResetRunner: Send {
    /// `DeleteSchema` — locked, confirmation-bound, version-zero-only.
    fn delete_schema<'a>(&'a mut self, req: &'a ResetRequest)
    -> BoxFuture<'a, Result<(), Failure>>;
}

/// Object-safe erase of [`BrokerProofService`] for the coordinator's
/// stored seam — the broker authority client (R6 task 2) implements
/// the `trait_variant` surface; this is its object-safe twin with the
/// identical method set.
pub trait DynBrokerProofService: Send + Sync {
    /// `IssueEmptyTargetProof`.
    fn issue_empty_target_proof<'a>(
        &'a self,
        req: &'a IssueEmptyTargetProofRequest,
    ) -> BoxFuture<'a, Result<VerifiedEmptyTarget, Failure>>;
    /// `VerifyEmptyTarget`.
    fn verify_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: &'a VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ConsumeEmptyProof`.
    fn consume_empty_proof<'a>(
        &'a self,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ConsumeVerifiedEmptyTarget`.
    fn consume_verified_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `IssueResetConfirmation`.
    fn issue_reset_confirmation<'a>(
        &'a self,
        req: &'a IssueResetConfirmationRequest,
    ) -> BoxFuture<'a, Result<ResetConfirmation, Failure>>;
    /// `VerifyResetConfirmation`.
    fn verify_reset_confirmation<'a>(
        &'a self,
        confirmation: &'a ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ConsumeResetConfirmation`.
    fn consume_reset_confirmation<'a>(
        &'a self,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>>;
    /// `ConsumeVerifiedResetConfirmation`.
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        target: &'a TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>>;
}

impl<T: BrokerProofService + Send + Sync> DynBrokerProofService for T {
    fn issue_empty_target_proof<'a>(
        &'a self,
        req: &'a IssueEmptyTargetProofRequest,
    ) -> BoxFuture<'a, Result<VerifiedEmptyTarget, Failure>> {
        Box::pin(BrokerProofService::issue_empty_target_proof(
            self,
            req.clone(),
        ))
    }
    fn verify_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: &'a VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::verify_empty_target(self, target, proof))
    }
    fn consume_empty_proof<'a>(
        &'a self,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::consume_empty_proof(self, proof))
    }
    fn consume_verified_empty_target<'a>(
        &'a self,
        target: &'a TargetIdentity,
        proof: VerifiedEmptyTarget,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::consume_verified_empty_target(
            self, target, proof,
        ))
    }
    fn issue_reset_confirmation<'a>(
        &'a self,
        req: &'a IssueResetConfirmationRequest,
    ) -> BoxFuture<'a, Result<ResetConfirmation, Failure>> {
        Box::pin(BrokerProofService::issue_reset_confirmation(
            self,
            req.clone(),
        ))
    }
    fn verify_reset_confirmation<'a>(
        &'a self,
        confirmation: &'a ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::verify_reset_confirmation(
            self,
            confirmation,
        ))
    }
    fn consume_reset_confirmation<'a>(
        &'a self,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::consume_reset_confirmation(
            self,
            confirmation,
        ))
    }
    fn consume_verified_reset_confirmation<'a>(
        &'a self,
        target: &'a TargetIdentity,
        confirmation: ResetConfirmation,
    ) -> BoxFuture<'a, Result<(), Failure>> {
        Box::pin(BrokerProofService::consume_verified_reset_confirmation(
            self,
            target,
            confirmation,
        ))
    }
}

/// `port.ProtectedOperatorState` — the broker's projection of the
/// protected provisioning record; the coordinator keys every mutating
/// decision on it.
#[derive(Debug, Clone, Default)]
pub struct ProtectedOperatorState {
    /// External record state.
    pub record_state: ExternalRecordState,
    /// In-flight provisioning phase, if any.
    pub provisioning_phase: ProvisioningPhase,
    /// Target the record binds.
    pub target: TargetIdentity,
    /// Operation identity recorded on the target.
    pub operation_id: uuid::Uuid,
    /// Optimistic-concurrency revision.
    pub revision: u64,
    /// Session binding captured when the operation started.
    pub session_binding: SessionBinding,
    /// Last record update.
    pub detected_at: Option<time::OffsetDateTime>,
}

/// `port.VersionChecksum` — one `schema_migrations` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionChecksum {
    /// Migration version.
    pub version: i32,
    /// Ledger checksum.
    pub checksum: String,
}

/// `port.DirtyEvidence` — a dirty migration record.
#[derive(Debug, Clone)]
pub struct DirtyEvidence {
    /// Dirty version.
    pub version: i32,
    /// Reason text (the dirty record's checksum).
    pub reason: String,
    /// Detection time.
    pub detected_at: time::OffsetDateTime,
}

/// `port.EpochMarker`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpochMarker {
    /// Epoch number.
    pub epoch: u64,
    /// Epoch digest.
    pub digest: String,
}

/// `port.EpochMarkers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpochMarkers {
    /// Migration (restore) epoch.
    pub migration: EpochMarker,
    /// Security epoch.
    pub security: EpochMarker,
}

/// `port.PostgresMigrationFacts` — the inspector's read-only findings.
#[derive(Debug, Clone)]
pub struct PostgresMigrationFacts {
    /// `central` schema exists and carries applied versions.
    pub initialized: bool,
    /// Applied `(version, checksum)` rows in version order.
    pub applied_versions: Vec<VersionChecksum>,
    /// Dirty evidence, when a dirty record exists.
    pub dirty: Option<DirtyEvidence>,
    /// Latest epoch markers.
    pub epochs: EpochMarkers,
}

/// Read-only facts behind the version-zero reset gate
/// (`backup.VersionZeroEligibility`-equivalent facts the reset runner
/// exposes to the broker).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionZeroEligibility {
    /// The `central` schema exists.
    pub installed: bool,
    /// Any `schema_migrations` ownership records exist.
    pub has_schema_ownership: bool,
    /// Records are exactly the clean `baseline-zero` v0 row.
    pub clean_version_zero_only: bool,
}

// ---------------------------------------------------------------------------
// R6 Task 3 — backup/recovery ports (`internal/backup/port/recovery_port.go`)
//
// Every trait below is the store/client seam a future PostgreSQL,
// object-store, or broker adapter implements. None carries a path,
// object key, DSN, credential, process identity, or broker secret —
// the same locator-free contract the domain records enforce. Methods
// are synchronous like the domain; an adapter that needs async I/O
// owns the bridging, exactly as the migration ports keep `sqlx` out.
// ---------------------------------------------------------------------------

use crate::backup::capacity::{BackupContinuitySnapshot, CapacitySnapshot, RecoveryProfile};
use crate::backup::inventory::{InventoryChunk, InventoryEntry, MAXIMUM_INVENTORY_CHUNK_ENTRIES};
use crate::backup::manifest::SealRootManifest;
use crate::backup::operation::{BackupAcceptedFacts, BackupOperation, DumpEvidence};
use crate::recovery::operation::{
    AuthorityResetReceipt, RecoveryBootstrapActivation, RecoveryBootstrapDraft,
    RecoveryBootstrapRegistration, RestoreAbandonAuthorization, RestoreApplyAuthorization,
    RestoreOperation, RestoreTicket,
};
use crate::recovery::profile::ThroughputEvidence;
use crate::recovery::quarantine::QuarantineFinding;
use crate::repository::{BackupFileTreeEvidence, BackupSealCompanion, BackupSealPublication};

/// `port.ErrBackupArtifactEvidenceMismatch` — the adapter-neutral
/// signal that a complete Artifact body disagreed with its immutable
/// database size or checksum. The application may classify repeated
/// occurrences as corrupted; transport, capacity, authority, and
/// repository I/O errors must not use this code and therefore cannot
/// be mislabeled as data corruption. An adapter signals it by
/// returning a [`Failure`] whose [`Failure::code`] equals this value.
pub const ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH: &str = "backup_artifact_evidence_mismatch";

/// `io.ReadCloser` — a body stream whose close may fail. The
/// coordinator distinguishes a clean copy+close from either half
/// failing (upstream `copyArtifactBody` checks both), so the close is
/// explicit rather than `Drop`.
pub trait ReadClose: std::io::Read + Send {
    /// `Close` — terminal flush/fence; its error is itself evidence.
    fn close(self: Box<Self>) -> Result<(), Failure>;
}

/// `port.BackupAdmissionSnapshot` — one atomic, trusted admission
/// observation. Facts become part of the protected operation before
/// any dump write; the remaining fields prove the C02 resource and
/// authority preconditions at that same boundary. The environment
/// must produce all five fields under the same held evidence set —
/// split reads would admit a snapshot no instant ever contained.
#[derive(Debug, Clone)]
pub struct BackupAdmissionSnapshot {
    /// Accepted-point trusted facts.
    pub facts: BackupAcceptedFacts,
    /// Fresh capacity census.
    pub capacity: CapacitySnapshot,
    /// The throughput receipt measured against this environment.
    /// Required — admission cannot pass on missing evidence.
    pub throughput: ThroughputEvidence,
    /// The target-exclusive lock was observed held at snapshot time.
    pub target_lock_held: bool,
    /// The authority acceptance receipt was observed held at snapshot
    /// time.
    pub authority_receipt_held: bool,
}

/// `port.RestoreAdmissionFacts` bind the protected target authority,
/// sealed payload and schema identity, current installed
/// configuration, and fresh trusted capacity evidence. None may be
/// supplied by CLI values.
#[derive(Debug, Clone)]
pub struct RestoreAdmissionFacts {
    /// Destination target identity.
    pub target: TargetIdentity,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// Security epoch.
    pub security_epoch: u64,
    /// Restore epoch.
    pub restore_epoch: u64,
    /// `sha256:`-prefixed config fingerprint.
    pub config_fingerprint: String,
    /// Payload epoch (v7 UUID).
    pub payload_epoch_id: uuid::Uuid,
    /// Pinned schema version.
    pub database_schema_version: String,
    /// `sha256:`-prefixed capacity evidence digest.
    pub capacity_evidence_digest: String,
    /// Pinned dump tool version (`"pg_restore-16.14"`).
    pub tool_version: String,
}

/// `port.RecoveryVerificationEvidence` — the adapter-neutral result
/// of one full verification walk of a sealed backup. It carries the
/// complete sealed root manifest, not only the digests, because C03
/// admission needs the accepted facts and the sealed media quantities
/// too — and re-reading them is a second SHA-256 walk of the whole
/// dump and every artifact body, which at the profile's admitted
/// floor throughput costs as much as the first. Locator-free: opaque
/// identities, fingerprints, sizes, and checksums only.
#[derive(Debug, Clone)]
pub struct RecoveryVerificationEvidence {
    /// Backup operation identity.
    pub operation_id: uuid::Uuid,
    /// Sealed backup identity.
    pub backup_id: uuid::Uuid,
    /// Repository binding identity.
    pub repository_binding_id: uuid::Uuid,
    /// Seal-root manifest digest.
    pub manifest_digest: [u8; 32],
    /// Seal companion digest.
    pub seal_companion_digest: [u8; 32],
    /// Immutable file-tree digest.
    pub file_tree_digest: [u8; 32],
    /// Published repository manifest digest.
    pub repository_manifest_digest: [u8; 32],
    /// Published repository manifest revision.
    pub repository_revision: u64,
    /// Dump evidence.
    pub dump: DumpEvidence,
    /// Sealed artifact count.
    pub artifact_count: u64,
    /// Sealed object bytes.
    pub object_bytes: u64,
    /// The complete verified seal-root manifest.
    pub manifest: SealRootManifest,
}

/// `port.ReadyArtifactCursor` — the opaque, stable seek position for
/// the globally unique Artifact identity. Artifact IDs are
/// application-generated UUIDs, so the cursor reveals neither an
/// object key nor a backing-store locator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadyArtifactCursor {
    /// Last entry's artifact identity (nil = from the start).
    pub artifact_id: uuid::Uuid,
}

/// `port.ReadyArtifactPage` — one bounded, canonical metadata page.
/// `complete` is authoritative: an empty incomplete page is invalid,
/// while an empty complete first page is the valid inventory of an
/// instance with no ready Artifacts. `next_cursor` is meaningful only
/// when `complete` is false and must name the final entry in
/// `entries`.
#[derive(Debug, Clone)]
pub struct ReadyArtifactPage {
    /// Page entries.
    pub entries: Vec<InventoryEntry>,
    /// Resume position for the next page.
    pub next_cursor: ReadyArtifactCursor,
    /// No more pages.
    pub complete: bool,
}

/// `port.MaximumReadyArtifactPageEntries` — the largest PostgreSQL
/// metadata page a C01 worker may hold. It deliberately matches one
/// immutable inventory chunk, so the application service can write
/// and release one complete page before requesting the next seek
/// position.
pub const MAXIMUM_READY_ARTIFACT_PAGE_ENTRIES: usize = MAXIMUM_INVENTORY_CHUNK_ENTRIES;

/// `port.BackupJournal` — the durable operation authority for an
/// ordinary backup. It persists the accepted consistent point before
/// a dump starts and uses CAS for every phase, so a lost controller
/// cannot mistake unsealed evidence for a completed backup.
pub trait BackupJournalStore: Send + Sync {
    /// `CreateBackup` — persists the planned operation; a duplicate
    /// identity must refuse.
    fn create_backup(&self, operation: &BackupOperation) -> Result<(), Failure>;
    /// `ReadBackup` — the durable record; absent is an error.
    fn read_backup(&self, operation_id: uuid::Uuid) -> Result<BackupOperation, Failure>;
    /// `CompareAndSwapBackup` — the store must require
    /// `current == expected` and validate
    /// `expected.validate_transition_to(next)` under its lock before
    /// writing `next`.
    fn compare_and_swap_backup(
        &self,
        expected: &BackupOperation,
        next: &BackupOperation,
    ) -> Result<(), Failure>;
}

/// `port.BackupEnvironment` — fresh, safe measurements without
/// revealing repository paths or credentials. The coordinator
/// requires a new snapshot at every phase boundary and no more than
/// one write quantum apart.
pub trait BackupEnvironmentProbe: Send + Sync {
    /// `AdmissionSnapshot` — the atomic facts+capacity+throughput+
    /// lock/receipt observation for this exact operation.
    fn admission_snapshot(
        &self,
        operation: &BackupOperation,
    ) -> Result<BackupAdmissionSnapshot, Failure>;
    /// `ContinuationSnapshot` — the continuity guard for this exact
    /// operation.
    fn continuation_snapshot(
        &self,
        operation: &BackupOperation,
    ) -> Result<BackupContinuitySnapshot, Failure>;
}

/// `port.ReadyArtifactSource` — metadata and stream bodies for ready
/// artifacts through the dedicated recovery identity. No live object
/// key crosses this capability boundary.
pub trait ReadyArtifactSource: Send + Sync {
    /// `ListReadyArtifacts`.
    fn list_ready_artifacts(
        &self,
        operation: &BackupOperation,
        after: ReadyArtifactCursor,
        limit: usize,
    ) -> Result<ReadyArtifactPage, Failure>;
    /// `OpenReadyArtifact`.
    fn open_ready_artifact(
        &self,
        operation: &BackupOperation,
        entry: &InventoryEntry,
    ) -> Result<Box<dyn ReadClose>, Failure>;
}

/// `port.BackupDumper` — starts the pinned `pg_dump` invocation whose
/// output is consumed once by the repository. The returned stream
/// carries no credential value.
pub trait BackupDumper: Send + Sync {
    /// `StartDump`.
    fn start_dump(&self, operation: &BackupOperation) -> Result<Box<dyn ReadClose>, Failure>;
}

/// `port.BackupSealer` — the worker-facing broker commit. It may
/// issue the exact seal companion, but it deliberately cannot perform
/// the terminal sealed transition: only the post-reap helper
/// attestation boundary can do that.
pub trait BackupSealer: Send + Sync {
    /// `SealBackup`.
    fn seal_backup(
        &self,
        proposal: &crate::backup::operation::BackupSealProposal,
    ) -> Result<BackupSealCompanion, Failure>;
}

/// `port.BackupRepository` — stores only immutable recovery evidence
/// beneath the helper-selected recovery root. Its implementation must
/// reject arbitrary paths and overwrites, and every write carries the
/// exact `backup_id` it binds.
pub trait RecoveryRepositoryStore: Send + Sync {
    /// `BindBackup` — binds this exact operation's backup identity;
    /// every later write must carry it.
    fn bind_backup(&self, operation: &BackupOperation) -> Result<(), Failure>;
    /// `WriteDump(backupID, source, maximumBytes)` — persists the dump
    /// bytes, refusing past `maximum_bytes`, and returns their
    /// evidence.
    fn write_dump(
        &self,
        backup_id: uuid::Uuid,
        source: &mut dyn std::io::Read,
        maximum_bytes: i64,
    ) -> Result<DumpEvidence, Failure>;
    /// `WriteArtifactBody(backupID, entry, source)` — persists one
    /// artifact body; a complete body that disagrees with `entry`'s
    /// size or checksum is
    /// [`ERR_BACKUP_ARTIFACT_EVIDENCE_MISMATCH`], not an I/O failure.
    fn write_artifact_body(
        &self,
        backup_id: uuid::Uuid,
        entry: &InventoryEntry,
        source: &mut dyn std::io::Read,
    ) -> Result<(), Failure>;
    /// `WriteChunk(backupID, chunk)` — persists an immutable inventory
    /// chunk under its sealed identity.
    fn write_chunk(&self, backup_id: uuid::Uuid, chunk: &InventoryChunk) -> Result<(), Failure>;
    /// `WriteManifest` — persists the canonical root manifest and
    /// returns the file-tree evidence the seal proposal binds;
    /// callers never supply the digest.
    fn write_manifest(
        &self,
        manifest: &SealRootManifest,
    ) -> Result<BackupFileTreeEvidence, Failure>;
    /// `WriteSealCompanion` — persists the broker-issued companion and
    /// returns the publication receipt for the exact companion and
    /// root index revision durably synchronized.
    fn write_seal_companion(
        &self,
        backup_id: uuid::Uuid,
        companion: &BackupSealCompanion,
    ) -> Result<BackupSealPublication, Failure>;
    /// Reads an immutable inventory chunk back for
    /// verification/restore; backup-scoped like every other access.
    fn read_inventory_chunk(
        &self,
        backup_id: uuid::Uuid,
        ordinal: u32,
    ) -> Result<InventoryChunk, Failure>;
    /// Reads the canonical seal root bytes; backup-scoped.
    fn read_seal_root(&self, backup_id: uuid::Uuid) -> Result<Vec<u8>, Failure>;
}

/// `port.RecoveryRepositoryVerifier` — reads only sealed repository
/// evidence. Its implementation must not repair, delete, or enumerate
/// paths outside the exact backup ID supplied by the controller.
pub trait RecoveryRepositoryVerifier: Send + Sync {
    /// `VerifyBackup` — one full verification walk of the sealed
    /// backup; the result is checked again downstream rather than
    /// trusted.
    fn verify_backup(
        &self,
        backup_id: uuid::Uuid,
        profile: &RecoveryProfile,
    ) -> Result<RecoveryVerificationEvidence, Failure>;
}

/// `port.RecoveryInventorySource` — the exact ordered, sealed
/// Artifact inventory for C04 verification. Implementations must
/// revalidate the repository seal and all referenced immutable
/// evidence before returning; callers never receive repository paths
/// or object keys.
pub trait RecoveryInventorySource: Send + Sync {
    /// `ReadVerifiedInventory`.
    fn read_verified_inventory(
        &self,
        backup_id: uuid::Uuid,
        profile: &RecoveryProfile,
    ) -> Result<Vec<InventoryEntry>, Failure>;
}

/// `port.BackupSealVerifier` — the broker-side counterpart required
/// before C03 can issue a restore ticket. Repository hashes alone are
/// insufficient: an unsealed or locally fabricated manifest must
/// never become restorable.
pub trait BackupSealVerifier: Send + Sync {
    /// `VerifyBackupSeal`.
    #[allow(clippy::too_many_arguments)]
    fn verify_backup_seal(
        &self,
        backup_id: uuid::Uuid,
        manifest_digest: [u8; 32],
        seal_companion_digest: [u8; 32],
        file_tree_digest: [u8; 32],
        repository_manifest_digest: [u8; 32],
        repository_revision: u64,
    ) -> Result<(), Failure>;
}

/// `port.RestoreAdmissionInspector` — judges the destination against
/// evidence that has already been verified once. Implementations must
/// not accept the evidence on trust: it arrives as a parameter, so an
/// implementation is required to re-establish, from authority it owns
/// rather than from the value it was handed, that the evidence names
/// the backup asked for, belongs to its own repository binding, and
/// is the one the broker sealed.
pub trait RestoreAdmissionInspector: Send + Sync {
    /// `InspectRestoreAdmission`.
    fn inspect_restore_admission(
        &self,
        backup_id: uuid::Uuid,
        evidence: &RecoveryVerificationEvidence,
    ) -> Result<RestoreAdmissionFacts, Failure>;
}

/// `port.RestoreTicketIssuer` — broker-owned. Issue persists the
/// one-use protected ticket — minting the fresh operation/ticket IDs,
/// the 32-byte hidden nonce, the epochs/fingerprints binding, and the
/// ticket HMAC — before returning it to the verifier; callers must
/// never render the returned nonce or HMAC to an operator result.
pub trait RestoreTicketIssuer: Send + Sync {
    /// `IssueRestoreTicket`.
    fn issue_restore_ticket(
        &self,
        backup_id: uuid::Uuid,
        manifest_digest: &str,
        facts: &RestoreAdmissionFacts,
        now: time::OffsetDateTime,
    ) -> Result<RestoreTicket, Failure>;
}

/// `port.RestoreJournal` — the protected, external source of truth
/// for recovery. Its `begin_restore` atomically validates and
/// consumes a broker ticket while publishing `applying`, before any
/// database mutation. PostgreSQL projections may mirror these records
/// but cannot replace this interface.
pub trait RestoreJournalStore: Send + Sync {
    /// `BeginRestore` — consumes both the verified ticket and a fresh
    /// helper-issued apply authorization under the same protected
    /// operation lock (ticket HMAC + one-use consumption included).
    /// A ticket by itself is insufficient authority to start
    /// destructive replacement. Returns the durable record.
    fn begin_restore(
        &self,
        ticket: &RestoreTicket,
        authorization: &RestoreApplyAuthorization,
        at: time::OffsetDateTime,
    ) -> Result<RestoreOperation, Failure>;
    /// `ResumeRestore` — consumes a new helper-issued PAM/TTY
    /// authorization before returning the exact resumable protected
    /// operation. Reading an operation ID alone is never sufficient
    /// authority to continue destructive recovery.
    fn resume_restore(
        &self,
        operation_id: uuid::Uuid,
        authorization: &RestoreApplyAuthorization,
        at: time::OffsetDateTime,
    ) -> Result<RestoreOperation, Failure>;
    /// `AbandonRestore` — consumes a fresh helper-issued abandonment
    /// authorization and publishes ADR 0016's terminal outcome for
    /// exactly its operation, under the same protected lock that
    /// consumes the authorization.
    fn abandon_restore(
        &self,
        operation_id: uuid::Uuid,
        authorization: &RestoreAbandonAuthorization,
        at: time::OffsetDateTime,
    ) -> Result<RestoreOperation, Failure>;
    /// `ReadRestore` — the durable record; absent is an error.
    fn read_restore(&self, operation_id: uuid::Uuid) -> Result<RestoreOperation, Failure>;
    /// `CompareAndSwapRestore` — the store must require
    /// `current == expected` and run
    /// [`RestoreOperation::validate_transition_to`] under its lock
    /// before writing `next`, so a caller-supplied record can never
    /// skip checkpoints or manufacture a security-epoch advance.
    fn compare_and_swap_restore(
        &self,
        expected: &RestoreOperation,
        next: &RestoreOperation,
    ) -> Result<(), Failure>;
}

/// `port.RestoreBarrierInspector` — the read-only startup view of
/// the external recovery journal. It reports the one non-ready
/// restore that blocks serving; an unreadable, corrupt, or ambiguous
/// journal must be returned as an error so startup fails closed.
pub trait RestoreBarrierInspector: Send + Sync {
    /// `InspectRestoreBarrier` — `(operation, active)`.
    fn inspect_restore_barrier(&self) -> Result<(RestoreOperation, bool), Failure>;
}

/// `port.RestoreTargetExclusion` — the restore-time fence for the
/// exact protected PostgreSQL target. It must be backed by an
/// external durable lock, rather than a process-local mutex: a lost
/// lease leaves the operation applying and prevents its replacement
/// checkpoint from being published.
pub trait RestoreTargetExclusion: Send {
    /// `AssertHeld` — refuses when the external lease is lost.
    fn assert_held(&self) -> Result<(), Failure>;
    /// `Release` — the terminal, once-only release.
    fn release(&self) -> Result<(), Failure>;
}

/// `port.RestoreQuarantineStore` persists only typed, locator-free
/// mismatches. During quarantine, `record_quarantine_findings`
/// receives a complete fresh inventory result and resolves only prior
/// findings absent from that result. Thus resolution is evidence of
/// the ordinary Artifact re-ingest or delete-intent/finalization
/// capability, never a caller-selected flag clear.
pub trait RestoreQuarantineStore: Send + Sync {
    /// `RecordQuarantineFindings` — persists the complete fresh
    /// finding set and returns the surviving unresolved count.
    fn record_quarantine_findings(
        &self,
        operation: &RestoreOperation,
        findings: &[QuarantineFinding],
    ) -> Result<u64, Failure>;
    /// `UnresolvedQuarantineCount`.
    fn unresolved_quarantine_count(&self, operation: &RestoreOperation) -> Result<u64, Failure>;
}

/// `port.RecoveryBrokerAuthorityResetter` — invalidates broker-owned
/// authority, stages a protected fresh bootstrap draft, and later
/// activates only the exact generation registered by PostgreSQL.
/// Plaintext never crosses this port.
pub trait BrokerAuthorityReset: Send + Sync {
    /// `PrepareRecoveryBrokerAuthority` — the protected fresh
    /// bootstrap draft.
    fn prepare_recovery_broker_authority(
        &self,
        operation: &RestoreOperation,
    ) -> Result<RecoveryBootstrapDraft, Failure>;
    /// `ActivateRecoveryBootstrap` — activates only the exact
    /// database-registered generation; re-keys broker TLS and
    /// invalidates sessions, grants, claims, leases, fences, provider
    /// bindings, and secret references inside the broker.
    fn activate_recovery_bootstrap(
        &self,
        operation: &RestoreOperation,
        registration: &RecoveryBootstrapRegistration,
    ) -> Result<RecoveryBootstrapActivation, Failure>;
}

/// `port.RecoveryDatabaseAuthorityResetter` — performs the single
/// PostgreSQL C05 reset transaction and registers the fresh
/// generation before broker activation. Finalize appends aggregate
/// evidence only after exact protected activation.
pub trait PostgresAuthorityReset: Send + Sync {
    /// `ResetDatabaseAuthority` — registers the draft's exact
    /// generation inside the same transaction that invalidates all
    /// restored authority; returns the database receipt.
    fn reset_database_authority(
        &self,
        operation: &RestoreOperation,
        draft: &RecoveryBootstrapDraft,
    ) -> Result<RecoveryBootstrapRegistration, Failure>;
    /// `FinalizeDatabaseAuthorityReset` — inside one protected
    /// transaction: verifies the exact `verifying`/`inventory_verified`
    /// projection, chooses `completed_at` once
    /// (`GREATEST(clock_timestamp(), activation.activated_at)`, UTC,
    /// truncated to microseconds), builds the canonical 11-field
    /// aggregate via
    /// [`crate::recovery::operation::new_authority_reset_receipt`],
    /// and persists the receipt — replaying the stored receipt on
    /// retry. The caller never supplies `completed_at` or the
    /// aggregate hash.
    fn finalize_database_authority_reset(
        &self,
        operation: &RestoreOperation,
        registration: &RecoveryBootstrapRegistration,
        activation: &RecoveryBootstrapActivation,
    ) -> Result<AuthorityResetReceipt, Failure>;
}

/// `port.RestoreEngine` — owns mutation and verification boundaries.
/// Every method is idempotent for the supplied operation/checkpoint:
/// a coordinator restart invokes the exact same protected operation,
/// never a freshly derived one.
pub trait RestoreEngine: Send + Sync {
    /// `AcquireRestoreTargetExclusion` — the target-exclusive C04
    /// barrier. A lock acquisition belongs to exactly one protected
    /// operation and must not allow a caller-selected target or
    /// operation to be substituted.
    fn acquire_restore_target_exclusion(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Box<dyn RestoreTargetExclusion>, Failure>;
    /// `RestoreDatabase` — the `pg_restore`-equivalent apply under
    /// the helper barrier. A refusal should carry one of the closed
    /// [`crate::recovery::refusal`] reasons as its code so the
    /// coordinator can surface it as the sanitized cause.
    fn restore_database(&self, operation: &RestoreOperation) -> Result<(), Failure>;
    /// `ProjectRestoreOperation` — mirrors the broker-owned state into
    /// PostgreSQL after database replacement. The broker remains
    /// authoritative, but every later effect and the final ready
    /// transition require this idempotent audit projection to be
    /// caught up first.
    fn project_restore_operation(&self, operation: &RestoreOperation) -> Result<(), Failure>;
    /// `VerifyInventory` — re-reads every restored object body for
    /// inventory comparison.
    fn verify_inventory(
        &self,
        operation: &RestoreOperation,
    ) -> Result<Vec<QuarantineFinding>, Failure>;
    /// `RecordQuarantineFindings` — mandatory even for an empty
    /// inventory result: the durable typed projection, rather than an
    /// engine-local count, is authoritative for the quarantine
    /// barrier. Returns the surviving unresolved count.
    fn record_quarantine_findings(
        &self,
        operation: &RestoreOperation,
        findings: &[QuarantineFinding],
    ) -> Result<u64, Failure>;
    /// `UnresolvedQuarantineCount`.
    fn unresolved_quarantine_count(&self, operation: &RestoreOperation) -> Result<u64, Failure>;
    /// `ResetAuthority` — the broker+database C05 reset producing the
    /// aggregate receipt.
    fn reset_authority(
        &self,
        operation: &RestoreOperation,
    ) -> Result<AuthorityResetReceipt, Failure>;
}

/// `port.RecoveryProfiles` — the installed profile lookup.
pub trait RecoveryProfileSource: Send + Sync {
    /// The installed admission envelope.
    fn installed_profile(&self) -> Result<RecoveryProfile, Failure>;
}
