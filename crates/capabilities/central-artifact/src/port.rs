//! Adapter-neutral persistence, object-storage, classification, and
//! completion contracts for the B10 Artifact lifecycle and the b34
//! lineage model — the port of `central/internal/artifact/port/port.go`
//! plus the lineage store interfaces upstream declares in
//! `lineage.go` and the two-phase deletion store the Rust slice adds
//! (`docs/artifacts/lifecycle.md` §Delete intent and tombstone).
//!
//! Contains no `sqlx`, `aws-sdk-s3`, or `tokio` types: the PostgreSQL
//! implementations live in `central-adapter-postgres` and the
//! object-store implementation in `central-adapter-s3`. Every trait is
//! `#[trait_variant::make(Send)]` with `Send + Sync + 'static` so trait
//! objects compose with multi-threaded `tokio`/`axum` handlers
//! (rust-application-boundaries.md §2.3).
//!
//! Error surface: every port returns `central_foundation::failure::Failure`
//! — the workspace-wide closed taxonomy. Adapters classify and sanitize
//! their SDK errors before returning (§2.4); the object-store adapter's
//! own closed `Failure { op, class, reason }` converts at this boundary
//! with the class mapped onto `FailureKind` and the reason carried as
//! the stable machine `code`, so the composition-root
//! `ObjectFailureClassifier` can recover the `ObjectFailureClass`
//! without parsing text.

use std::time::Duration;

use central_execution::domain::ExecutionChangeSet;
use central_foundation::failure::Failure;
use central_foundation::identity::{ArtifactId, RunId, WorkflowNodeId, WorkspaceId};
use time::OffsetDateTime;

use crate::domain::{
    Artifact, ArtifactTombstone, BeginUploadResult, CommandIdentity, FinalizeResult, Outcome,
    PromotionResult, RejectResult, ReserveResult, State, VerifiedResult,
};
use crate::lineage::{AttemptFinalization, LineageArtifact, ProduceEdge, ReadEdge};

// ---------------------------------------------------------------------------
// Transfer bounds: a generic body ceiling distinct from the B09 report class
// ---------------------------------------------------------------------------

/// Process-wide streaming bound: at most two object-store transfers
/// (upload, verification read, post-promotion read) run concurrently.
pub const MAX_CONCURRENT_TRANSFERS: usize = 2;

/// The 256 KiB copy-buffer *target*, achievable only where a transfer is
/// a plain copy. The streamed unknown-length staging upload goes through
/// S3 multipart, whose 5 MiB part-size floor (`StagingPartSizeBytes`) is
/// a deliberate, documented deviation from this literal value — and
/// still bounds the whole adapter to ~10 MiB in flight at
/// [`MAX_CONCURRENT_TRANSFERS`] `= 2`.
pub const TRANSFER_COPY_BUFFER_BYTES: usize = 256 * 1024;

/// Per-transfer idle deadline for every object-store transfer.
pub const TRANSFER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-transfer total deadline for every object-store transfer.
pub const TRANSFER_TOTAL_DEADLINE: Duration = Duration::from_secs(10 * 60);

/// The generic hard ceiling for any Artifact body handled by this port —
/// for example, the dedicated large-Artifact reconciliation claim. It is
/// deliberately distinct from the much smaller B09 required-report class
/// (`domain::DEFAULT_REQUIRED_REPORT_MAX_BYTES` /
/// `domain::HARD_REQUIRED_REPORT_MAX_BYTES`, 1 MiB/10 MiB): this ceiling
/// bounds any Artifact body regardless of required-report policy.
pub const MAX_ARTIFACT_BODY_BYTES: i64 = 4 * 1024 * 1024 * 1024;

/// One held transfer permit (upstream `TransferLimiter`'s
/// `release func()` result, made RAII). Dropping the guard returns the
/// permit to the limiter; `release` makes the return explicit. The
/// concrete permit is idempotent — the permit is returned exactly once
/// however the guard ends.
pub trait TransferPermit: Send + 'static {
    /// Returns the permit to the limiter. Identical to dropping the
    /// guard; a concrete permit is a single-use token, so this is
    /// naturally idempotent.
    fn release(self: Box<Self>) {
        drop(self);
    }
}

/// Bounds the process-wide count of concurrent object-store transfers
/// (upstream `TransferLimiter`). `acquire` waits until a permit is
/// available; the returned [`TransferPermit`] guard must be held for the
/// duration of the transfer and released exactly once — dropping it is
/// that release.
#[trait_variant::make(Send)]
pub trait TransferLimiter: Send + Sync + 'static {
    /// Acquires one transfer permit, blocking until available or the
    /// caller's cancellation (future drop) resolves the wait.
    async fn acquire(&self) -> Result<Box<dyn TransferPermit>, Failure>;
}

/// The boxed `Send` future a [`ByteStream`] method returns. `ByteStream`
/// is hand-written rather than `#[trait_variant::make(Send)]` exactly so
/// it stays `dyn`-compatible — `ObjectStore::read` must hand back
/// `Box<dyn ByteStream>` — while still carrying the §2.3-required
/// explicit `+ Send` future bounds.
pub type ByteStreamFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The capability-owned asynchronous byte stream crossing the object-store
/// port boundary (upstream's `io.ReadCloser`), so `central-artifact`
/// streams object bodies without importing `tokio::io::AsyncRead`.
/// Cancellation is delivered by future drop: dropping an in-flight
/// `read_chunk`/`close` future must leave no partial effect beyond the
/// adapter's own cleanup.
pub trait ByteStream: Send {
    /// Reads up to `buf.len()` bytes into `buf`, returning the byte count
    /// actually read. `Ok(0)` signals end of stream (upstream `io.EOF`).
    fn read_chunk<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> ByteStreamFuture<'a, Result<usize, Failure>>;

    /// Closes the stream, releasing the underlying transfer permit and
    /// any connection resources. Idempotent — closing an already-closed
    /// stream is a no-op.
    fn close<'a>(&'a mut self) -> ByteStreamFuture<'a, Result<(), Failure>>;
}

// ---------------------------------------------------------------------------
// ObjectStore
// ---------------------------------------------------------------------------

/// An opaque object-store locator scoped to one bucket-relative key
/// (upstream `ObjectRef`). It never carries a raw filename or
/// caller-supplied path segment: the key is always one of the two opaque
/// forms `domain`'s key derivation produces (`v1/staging/...`,
/// `v1/ready/...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRef {
    /// The opaque bucket-relative key.
    pub key: String,
}

/// Safe, opaque object evidence (upstream `ObjectInfo`). It never exposes
/// a delivery URL or a raw locator beyond the object's own opaque key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    /// The object's byte length.
    pub size: i64,
    /// The store's entity tag for the object, when exposed.
    pub etag: String,
    /// The store's version evidence for the object, when exposed.
    pub version: String,
}

/// One staging-upload request (upstream `UploadRequest`). The body is a
/// synchronous reader — upload bodies are local, already-materialized
/// bytes (a workspace file or buffer), never a network stream; the
/// streamed download direction uses [`ByteStream`].
pub struct UploadRequest {
    /// The destination staging key.
    pub reference: ObjectRef,
    /// The body bytes to stream up.
    pub body: Box<dyn std::io::Read + Send>,
    /// The declared body ceiling (`max_bytes + 1` sentinel enforcement
    /// lives in the adapter).
    pub max_bytes: i64,
}

/// The durable upload evidence (upstream `UploadResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadResult {
    /// Evidence of the landed staging object.
    pub info: ObjectInfo,
}

/// The streamed Artifact body port (upstream `ObjectStore`). It uploads
/// only to a staging key, reads for verification, creates a ready object
/// only through an atomic create-only precondition, and removes staging
/// or delete-pending objects. It never infers readiness from object
/// existence and never exposes an object URL.
///
/// Restore and backup fixture operations are *not* on this surface:
/// `restore_body_create_only` and `open_backup_throughput_fixture` remain
/// inherent methods on the concrete S3 adapter, consumed through narrow
/// local interfaces — matching upstream, where they are `minio.Store`
/// methods rather than `port.ObjectStore` members.
#[trait_variant::make(Send)]
pub trait ObjectStore: Send + Sync + 'static {
    /// Streams `request.body` to `request.reference` — which must be a
    /// staging key — bounded by `request.max_bytes`.
    async fn upload(&self, request: UploadRequest) -> Result<UploadResult, Failure>;

    /// Opens `reference` for a bounded read, returning the body stream
    /// and the object's safe evidence (upstream's
    /// `(io.ReadCloser, ObjectInfo, error)` triple).
    async fn read(
        &self,
        reference: ObjectRef,
    ) -> Result<(Box<dyn ByteStream>, ObjectInfo), Failure>;

    /// Atomically creates `destination` (a ready key) from `source` (a
    /// staging key) under a create-only precondition — never a
    /// read-then-write and never an overwrite. A precondition conflict
    /// means an existing ready object won the race and is authoritative.
    async fn promote_create_only(
        &self,
        source: ObjectRef,
        destination: ObjectRef,
    ) -> Result<ObjectInfo, Failure>;

    /// Removes a staging object for reconciliation — restricted to
    /// rejected, expired, or proven orphan staging keys.
    async fn remove_staging(&self, reference: ObjectRef) -> Result<(), Failure>;

    /// Removes a ready object whose durable record is `delete_pending`.
    /// Called only after `TwoPhaseDeleteStore::mark_delete_pending` made
    /// the delete intent durable; the record must never serve the body
    /// again regardless of this call's outcome.
    async fn remove_ready_for_delete(&self, reference: ObjectRef) -> Result<(), Failure>;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// The PostgreSQL-backed persistence port for every non-completion
/// Artifact lifecycle transition (upstream `Store`): reservation
/// admission and replay, staged upload and verification recording, and
/// promotion recording. It never calls object storage, and it never
/// applies a required Artifact's ready transition or Task-domain
/// completion — [`CompletionContributor`] owns that atomic commit
/// exclusively. Each method re-validates the caller's already
/// pure-evaluated result against durable state and returns the exact
/// prior result on a replay instead of a new transition.
#[trait_variant::make(Send)]
pub trait Store: Send + Sync + 'static {
    /// Admits a domain-evaluated reservation (quota + insert), returning
    /// the durable result — the journaled row on an idempotent replay.
    async fn reserve_artifact(&self, result: ReserveResult) -> Result<ReserveResult, Failure>;

    /// Records the reserved-to-staging transition under the command
    /// identity's expected version.
    async fn record_begin_upload(
        &self,
        result: BeginUploadResult,
    ) -> Result<BeginUploadResult, Failure>;

    /// Records the verification outcome (verifying or rejected) under the
    /// command identity's expected version.
    async fn record_verification(&self, result: VerifiedResult) -> Result<VerifiedResult, Failure>;

    /// Records the promotion (ready key + content generation) under the
    /// command identity's expected version.
    async fn record_promotion(&self, result: PromotionResult) -> Result<PromotionResult, Failure>;

    /// Persists an already pure-evaluated reject and releases the
    /// reservation exactly once (upstream `RecordRejection`) — the
    /// immediate durable rejection path for a cause known before
    /// verification, so capacity is freed at once rather than held for
    /// the reconciler's staging-lifetime sweep.
    async fn record_rejection(&self, result: RejectResult) -> Result<RejectResult, Failure>;

    /// Returns the current durable lifecycle snapshot for one Artifact
    /// (upstream `LoadArtifact`): state, version, ownership chain,
    /// derived keys, and verified evidence. A plain read that applies no
    /// transition and takes no lock — a caller must still submit its
    /// intended transition through the command-stage methods above,
    /// which revalidate under lock.
    async fn load_artifact(
        &self,
        workspace_id: WorkspaceId,
        artifact_id: ArtifactId,
    ) -> Result<Artifact, Failure>;
}

/// The durable two-phase workspace-scoped deletion port
/// (`docs/artifacts/lifecycle.md` §Delete intent and tombstone;
/// adapter-mapping §3.9–§3.10). It owns the `delete_pending` intent
/// transition, the atomic `deleted` + tombstone settlement, and the
/// tombstone existence probe the idempotent settle path consults. The
/// object removal between the two commits is [`ObjectStore`]'s, outside
/// any PostgreSQL transaction.
#[trait_variant::make(Send)]
pub trait TwoPhaseDeleteStore: Send + Sync + 'static {
    /// Persists the domain-evaluated `delete_pending` snapshot
    /// (`domain::mark_delete_pending`'s output). The commit revalidates
    /// `(workspace_id, artifact_id)` and `version = next.version - 1`
    /// under lock — the version-and-state check is what makes delete
    /// intent win any uncommitted finalization — and returns the durable
    /// snapshot, never a second transition.
    async fn mark_delete_pending(&self, next: Artifact) -> Result<Artifact, Failure>;

    /// Atomically persists the domain-evaluated `deleted` snapshot and
    /// its tombstone (`domain::complete_deletion`'s output pair) in one
    /// commit. A replay under the same artifact identity returns the
    /// journaled settlement — `TwoPhaseDeleteResult.replayed` — never a
    /// second tombstone.
    async fn complete_deletion_with_tombstone(
        &self,
        next: Artifact,
        tombstone: ArtifactTombstone,
    ) -> Result<TwoPhaseDeleteResult, Failure>;

    /// Whether a tombstone already exists for `(workspace_id,
    /// artifact_id)` — the probe a retried settlement consults before
    /// attempting a second commit.
    async fn has_tombstone(
        &self,
        workspace_id: WorkspaceId,
        artifact_id: ArtifactId,
    ) -> Result<bool, Failure>;
}

/// The durable result of a two-phase deletion settlement commit.
#[derive(Debug, Clone, PartialEq)]
pub struct TwoPhaseDeleteResult {
    /// The committed `deleted` snapshot.
    pub artifact: Artifact,
    /// The journaled tombstone.
    pub tombstone: ArtifactTombstone,
    /// `true` when the result came from the journaled prior settlement
    /// rather than a new commit — the idempotent-replay marker.
    pub replayed: bool,
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

/// Bounds the classification input to a caller-known size and a reader
/// over the already-staged body (upstream `ClassifyRequest`); a
/// [`Classifier`] never receives an unbounded stream.
/// `declared_media_type` is a hint only.
pub struct ClassifyRequest {
    /// The producer-declared media type hint.
    pub declared_media_type: String,
    /// The declared body size.
    pub size: i64,
    /// A bounded reader over the staged body.
    pub body: Box<dyn std::io::Read + Send>,
}

/// The safe, sanitized content-policy decision (upstream
/// `ClassifyResult`). `rejection_code` is a closed reason code; it is
/// empty when the content is accepted.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassifyResult {
    /// The detected media type — the classifier's own sniffed verdict,
    /// never the declared hint.
    pub detected_media_type: String,
    /// Whether the body is suspected of disclosing secret material.
    pub secret_disclosure: bool,
    /// A closed rejection reason (`domain::FAILURE_CODE_*`), empty on
    /// acceptance.
    pub rejection_code: String,
}

/// Applies bounded content classification to a fully staged body before
/// promotion (upstream `Classifier`), including the content-policy
/// secret-disclosure decision.
#[trait_variant::make(Send)]
pub trait Classifier: Send + Sync + 'static {
    /// Classifies one staged body under its declared bounds.
    async fn classify(&self, request: ClassifyRequest) -> Result<ClassifyResult, Failure>;
}

// ---------------------------------------------------------------------------
// CompletionContributor
// ---------------------------------------------------------------------------

/// The durable idempotency record for one Finalize command (upstream
/// `ArtifactCommandReceipt`). A replay under the same identity returns
/// the original [`CommitResult`] instead of a new transition, quota
/// effect, or Event.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactCommandReceipt {
    /// The caller idempotency key.
    pub idempotency_key: String,
    /// The finalize command identity.
    pub identity: CommandIdentity,
}

/// The atomic finalize-plus-completion change committed in one
/// PostgreSQL transaction for a required Artifact (upstream
/// `ArtifactChangeSet`). It carries only the already pure-evaluated
/// Finalize result; no adapter may derive or mutate this data
/// independently.
#[derive(Debug, Clone)]
pub struct ArtifactChangeSet {
    /// The domain-evaluated finalize result.
    pub finalize: FinalizeResult,
    /// The durable idempotency receipt to journal.
    pub receipt: ArtifactCommandReceipt,
}

/// The durable result of a completion commit (upstream `CommitResult`).
/// `replayed` reports that `outcome` came from an exact retained receipt
/// rather than a new commit.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitResult {
    /// The outcome the Task domain consumes.
    pub outcome: Outcome,
    /// Whether the result is a receipt replay.
    pub replayed: bool,
}

/// Commits the atomic finalize-plus-completion transaction for a
/// required Artifact (upstream `CompletionContributor`). It is the only
/// path that may combine an Artifact ready transition with a Task-domain
/// execution change set; the Artifact adapter never applies a Task
/// lifecycle transition independently. No object-store call may occur
/// while this commit's locks are held.
#[trait_variant::make(Send)]
pub trait CompletionContributor: Send + Sync + 'static {
    /// Commits `change` (the artifact half) and `exec_change` (the
    /// lease-fenced execution half) atomically.
    async fn commit_artifact(
        &self,
        change: ArtifactChangeSet,
        exec_change: ExecutionChangeSet,
    ) -> Result<CommitResult, Failure>;
}

// ---------------------------------------------------------------------------
// ReconciliationStore
// ---------------------------------------------------------------------------

/// The typed keyset seek position for the bounded incomplete-Artifact
/// reconciliation scan (upstream `ReconciliationCursor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciliationCursor {
    /// The workspace at the scan boundary.
    pub workspace_id: WorkspaceId,
    /// The artifact `created_at` at the scan boundary.
    pub created_at: OffsetDateTime,
    /// The artifact identity at the scan boundary.
    pub artifact_id: ArtifactId,
}

/// One bounded claim sweep over incomplete Artifacts (upstream
/// `ClaimIncompleteRequest`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimIncompleteRequest {
    /// The resume position of the keyset scan.
    pub cursor: ReconciliationCursor,
    /// Maximum claims this call returns.
    pub batch_size: usize,
    /// The claiming pass's opaque fence token.
    pub claim_token: Vec<u8>,
    /// How long each written claim lease lives.
    pub lease_duration: Duration,
    /// The claiming pass's own coordinator fencing generation, recorded
    /// on every claim row it writes. It must be positive: a claim written
    /// under a placeholder generation would make durable claim rows
    /// indistinguishable between coordinator generations. Fencing itself
    /// is enforced by the lease and claim-token hash; this value is what
    /// makes the recorded ownership meaningful.
    pub coordinator_generation: i64,
}

/// One fenced, leased Artifact claimed for reconciliation (upstream
/// `IncompleteClaim`). It is never proof of readiness by itself.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IncompleteClaim {
    /// The claimed artifact.
    pub artifact_id: ArtifactId,
    /// Its owning workspace.
    pub workspace_id: WorkspaceId,
    /// Its lifecycle state at claim time. `None` is the honest encoding
    /// of upstream's empty-string `State` sentinel: the dedicated large
    /// claim carries no recorded state, so the reconciler's
    /// moved-under-the-claim check is skipped for it by construction.
    pub state: Option<State>,
    /// When the claim lease expires.
    pub lease_expires_at: OffsetDateTime,
    /// The artifact's durable creation time. Claims arrive in ascending
    /// `created_at` order within a workspace, so the first claim of a
    /// pass is that workspace's oldest incomplete Artifact — the backlog
    /// age the health monitor reports.
    pub created_at: OffsetDateTime,
}

/// One claim-sweep result (upstream `ClaimIncompleteResult`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimIncompleteResult {
    /// The leased claims, oldest-first within each workspace.
    pub claims: Vec<IncompleteClaim>,
    /// The keyset position the next sweep resumes from.
    pub next_cursor: ReconciliationCursor,
    /// The database-derived instant this batch was claimed at. Backlog
    /// ages are measured against it, never against a process clock.
    pub observed_at: OffsetDateTime,
    /// Workspaces the round-robin resolver passed over because their
    /// durable ID is not a parseable `WorkspaceId` — a defensive guard
    /// (no known production path writes such a row); skipped and counted
    /// rather than failed so unparseable rows cannot starve the scan.
    /// Safe diagnostics only: it is never body, key, or ID material.
    pub skipped_workspaces: usize,
    /// `true` when the bounded skip walk gave up before reaching a
    /// parseable workspace — without it an empty backlog is
    /// indistinguishable from a stalled scan.
    pub skip_budget_exhausted: bool,
}

/// One dedicated large-Artifact claim attempt (upstream
/// `ClaimLargeRequest`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimLargeRequest {
    /// The claiming pass's opaque fence token.
    pub claim_token: Vec<u8>,
    /// How long the claim lease lives.
    pub lease_duration: Duration,
}

/// The durable dedicated claim for one large Artifact that exceeded a
/// normal reconciliation pass's remaining byte/time budget (upstream
/// `LargeClaim`). `None` — no eligible claim — replaces upstream's
/// `Found: bool`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LargeClaim {
    /// The claimed artifact.
    pub artifact_id: ArtifactId,
    /// Its owning workspace.
    pub workspace_id: WorkspaceId,
    /// When the claim lease expires.
    pub lease_expires_at: OffsetDateTime,
}

/// Bounded reconciliation progress journaled between sweeps (upstream
/// `ReconciliationProgress`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReconciliationProgress {
    /// The scan position reached.
    pub cursor: ReconciliationCursor,
    /// Artifacts processed so far this pass.
    pub processed_count: i64,
    /// The reconciler cycle this progress belongs to.
    pub cycle: i64,
}

/// Records the durable large-Artifact claim for one candidate that would
/// exceed a normal pass's remaining byte or time budget (upstream
/// `RecordLargeClaimRequest`).
///
/// The recorded claim is left immediately eligible rather than leased to
/// the deferring pass: the deferring pass is explicitly not doing the
/// work, so the same one-worker scheduler must be able to pick the claim
/// up on a later pass and run it alone under its own fence.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordLargeClaimRequest {
    /// The candidate's workspace.
    pub workspace_id: WorkspaceId,
    /// The candidate artifact.
    pub artifact_id: ArtifactId,
    /// The artifact version the deferring pass observed. A record that
    /// moved on is a non-mutating conflict, not an error.
    pub expected_version: i64,
    /// The deferring pass's coordinator fencing generation.
    pub coordinator_generation: i64,
    /// The deferring pass's fence token.
    pub claim_token: Vec<u8>,
}

/// Asks for one reserved/staging record to be expired if, and only if,
/// database-derived time says it has outlived `lifetime` and the caller
/// still holds the active reconciliation claim on it (upstream
/// `ExpireStagingRequest`).
#[derive(Debug, Clone, PartialEq)]
pub struct ExpireStagingRequest {
    /// The record's workspace.
    pub workspace_id: WorkspaceId,
    /// The record's artifact.
    pub artifact_id: ArtifactId,
    /// The artifact version the claiming pass observed.
    pub expected_version: i64,
    /// The fence token the pass holds on this record.
    pub claim_token: Vec<u8>,
    /// The installed staging lifetime to compare against — measured on
    /// the database clock inside the adapter's statement.
    pub lifetime: Duration,
}

/// Whether the expiry transition was actually applied (upstream
/// `ExpireStagingResult`). `expired` is `false` — with a `Ok` result —
/// for every non-mutating conflict: a record younger than `lifetime`, a
/// state or version that moved under the claim, or a stale/absent claim.
/// Only `expired` permits the caller to remove the staging object.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpireStagingResult {
    /// Whether the durable expiry transition was applied.
    pub expired: bool,
    /// The outcome the rejection produced.
    pub outcome: Outcome,
}

/// Identifies the dedicated large-Artifact claim to remove (upstream
/// `ReleaseLargeClaimRequest`). `claim_token` is the fence the
/// processing pass held.
#[derive(Debug, Clone, PartialEq)]
pub struct ReleaseLargeClaimRequest {
    /// The claim's workspace.
    pub workspace_id: WorkspaceId,
    /// The claim's artifact.
    pub artifact_id: ArtifactId,
    /// The fence the processing pass held.
    pub claim_token: Vec<u8>,
}

/// Bounds one rejected-staging cleanup sweep (upstream
/// `ClaimRejectedStagingRequest`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimRejectedStagingRequest {
    /// Maximum claims this sweep returns.
    pub batch_size: usize,
    /// The sweep pass's fence token.
    pub claim_token: Vec<u8>,
}

/// One rejected Artifact whose staging object has not yet been removed
/// (upstream `RejectedStagingClaim`). `staging_key` is always the
/// record's own derived staging-role key; a ready key can never appear
/// here.
#[derive(Debug, Clone, PartialEq)]
pub struct RejectedStagingClaim {
    /// The artifact's workspace.
    pub workspace_id: WorkspaceId,
    /// The rejected artifact.
    pub artifact_id: ArtifactId,
    /// The staging-role key awaiting removal.
    pub staging_key: String,
}

/// One rejected-staging sweep result (upstream
/// `ClaimRejectedStagingResult`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimRejectedStagingResult {
    /// The rejected artifacts whose staging objects await removal.
    pub claims: Vec<RejectedStagingClaim>,
}

/// Records one rejected Artifact's staging-object removal so the cleanup
/// sweep never revisits it (upstream `ClearStagingKeyRequest`).
#[derive(Debug, Clone, PartialEq)]
pub struct ClearStagingKeyRequest {
    /// The record's workspace.
    pub workspace_id: WorkspaceId,
    /// The record's artifact.
    pub artifact_id: ArtifactId,
    /// The fence the sweep held.
    pub claim_token: Vec<u8>,
}

/// The fenced claim and bounded-cursor operations consumed by the
/// periodic Artifact reconciliation pass (upstream
/// `ReconciliationStore`). It never treats object-store listing as proof
/// of readiness and never lets an unfenced or stale claim mutate durable
/// state.
#[trait_variant::make(Send)]
pub trait ReconciliationStore: Send + Sync + 'static {
    /// Claims the next bounded batch of incomplete Artifacts under the
    /// pass's fence.
    async fn claim_incomplete(
        &self,
        request: ClaimIncompleteRequest,
    ) -> Result<ClaimIncompleteResult, Failure>;

    /// Claims the one durable dedicated large-Artifact claim currently
    /// eligible, if any.
    async fn claim_large(&self, request: ClaimLargeRequest) -> Result<Option<LargeClaim>, Failure>;

    /// Journals the pass's scan progress.
    async fn record_progress(&self, progress: ReconciliationProgress) -> Result<(), Failure>;

    /// Promotes one Artifact to a durable dedicated large-Artifact claim
    /// so the normal cursor can advance past it. Safe to call repeatedly
    /// for the same Artifact.
    async fn record_large_claim(&self, request: RecordLargeClaimRequest) -> Result<(), Failure>;

    /// Applies the staging-lifetime expiry transition. The age comparison
    /// is made against database-derived time inside the adapter's own
    /// statement; no caller clock participates in the decision.
    async fn expire_staging(
        &self,
        request: ExpireStagingRequest,
    ) -> Result<ExpireStagingResult, Failure>;

    /// Removes the durable dedicated large-Artifact claim the caller just
    /// processed. Without it a claim row outlives the Artifact it
    /// describes: `claim_large` would keep re-selecting the same resolved
    /// record every lease interval, and accumulated stale rows would
    /// starve normal reconciliation. Idempotent — never an error when the
    /// row is already gone.
    async fn release_large_claim(&self, request: ReleaseLargeClaimRequest) -> Result<(), Failure>;

    /// Returns rejected Artifacts that still carry an unremoved staging
    /// object, so staging cleanup actually covers the rejected case.
    /// Rows leave the scan permanently once `clear_staging_key` records
    /// the removal, so repeated passes drain rather than rescan.
    async fn claim_rejected_staging(
        &self,
        request: ClaimRejectedStagingRequest,
    ) -> Result<ClaimRejectedStagingResult, Failure>;

    /// Records that a rejected Artifact's staging object has been
    /// removed. It only ever clears the staging-role key of an already
    /// rejected record; a ready key is never touched, and a non-rejected
    /// record is a non-mutating conflict rather than an error.
    async fn clear_staging_key(&self, request: ClearStagingKeyRequest) -> Result<(), Failure>;
}

// ---------------------------------------------------------------------------
// Lineage stores (b34)
// ---------------------------------------------------------------------------

/// Commits the spec-5 §5 single visibility boundary (upstream
/// `internal/adapter/postgres/artifact/finalize.go`
/// `FinalizeAttemptArtifact`): keyed `(attempt_id, artifact_name)` on
/// `central.artifact_finalizations`, one transaction lands the key row,
/// the artifact's `verifying` → `ready` transition, the journaled
/// produce edge, and the `artifact_finalized` run event with its
/// `event_outbox` row.
///
/// It is deliberately NOT the B10 [`CompletionContributor`] path:
/// `CommitArtifact` is the Phase-1 receipt-dedup finalize keyed
/// `(workspace, finalize, receipt key)` that also settles
/// `ExecutionChangeSet`s; this port touches no Phase-1 execution rows.
///
/// The capability hands over an already pure-evaluated
/// [`AttemptFinalization`] change set; the implementation re-validates
/// every bound coordinate against durable state inside the transaction:
/// the attempt's durable run/node must equal `change.run_id` /
/// `change.node_id`, and the artifact row's `workspace_id` / `run_id` /
/// `required_role` / `content_generation` / `checksum_value` must match
/// the attempt's coordinates and the caller's binding. The run-event
/// envelope is the adapter's own mapping — the capability carries no
/// journal types.
#[trait_variant::make(Send)]
pub trait AttemptFinalizationStore: Send + Sync + 'static {
    /// Commits `change` atomically and returns the finalized artifact
    /// id. A same-checksum replay of the `(attempt_id, artifact_name)`
    /// key is idempotent: it returns the RECORDED artifact id — which
    /// may differ from `change.artifact_id` — after journaling
    /// `command_deduped`. A different checksum under the same key, or a
    /// produce edge journaled under a different attempt, is
    /// `ARTIFACT_ALREADY_FINALIZED`.
    async fn finalize_attempt_artifact(
        &self,
        change: AttemptFinalization,
    ) -> Result<ArtifactId, Failure>;
}

/// Persists produce edges (upstream `ProduceEdgeStore`).
/// `insert_produce_edge` must dedupe on `artifact_id`: when the edge
/// already exists it returns the journaled row, so `record_produce` is
/// an idempotent success rather than an error.
#[trait_variant::make(Send)]
pub trait ProduceEdgeStore: Send + Sync + 'static {
    /// Inserts one produce edge, deduplicated on `edge.artifact_id`.
    async fn insert_produce_edge(&self, edge: ProduceEdge) -> Result<ProduceEdge, Failure>;
}

/// Persists read edges (upstream `ReadEdgeStore`). `insert_read_edge`
/// must dedupe on `(run_id, reader_node_id, attempt_id, artifact_id)`: a
/// retry after an ambiguous outcome replays against the journaled edge
/// instead of double-counting. Operator edges (`None` reader/attempt)
/// never dedupe — every operator read is a distinct observable event.
#[trait_variant::make(Send)]
pub trait ReadEdgeStore: Send + Sync + 'static {
    /// Inserts one read edge, deduplicated on the attempt-scoped tuple.
    async fn insert_read_edge(&self, edge: ReadEdge) -> Result<ReadEdge, Failure>;
}

/// The read side of the lineage store (upstream `LineageReader`):
/// per-artifact, per-node, and per-run edge projections plus the graph
/// inputs the ancestors/descendants walks consume.
#[trait_variant::make(Send)]
pub trait LineageReader: Send + Sync + 'static {
    /// The single produce edge for one artifact, when journaled.
    async fn produce_edge_for_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<ProduceEdge>, Failure>;

    /// Every read edge journaling a read of one artifact.
    async fn read_edges_for_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Vec<ReadEdge>, Failure>;

    /// Every read edge one node journaled, unioned across its attempts.
    async fn read_edges_for_node(&self, node_id: WorkflowNodeId) -> Result<Vec<ReadEdge>, Failure>;

    /// Every produce edge one node journaled, attributed per attempt.
    async fn produce_edges_for_node(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<ProduceEdge>, Failure>;

    /// Every produce edge journaled inside one run.
    async fn produce_edges_for_run(&self, run_id: RunId) -> Result<Vec<ProduceEdge>, Failure>;

    /// Every read edge journaled inside one run.
    async fn read_edges_for_run(&self, run_id: RunId) -> Result<Vec<ReadEdge>, Failure>;
}

/// The lineage read-authorization store surface (upstream `ReadStore`):
/// artifact resolution by id or (producer node key, name), plus the two
/// scope inputs the attempt-scope rule consumes.
#[trait_variant::make(Send)]
pub trait ReadStore: Send + Sync + 'static {
    /// Resolves one artifact identity to its read-authorization
    /// projection (upstream `FindArtifact`'s `(LineageArtifact, bool)`).
    async fn find_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<LineageArtifact>, Failure>;

    /// Returns the artifacts produced under producer node key
    /// `node_key` carrying the required-role `name`, restricted to
    /// `run_id` when `Some` (operator resolution may address any run's
    /// graph).
    async fn resolve_produced(
        &self,
        run_id: Option<RunId>,
        node_key: &str,
        name: &str,
    ) -> Result<Vec<LineageArtifact>, Failure>;

    /// The node's declared read set: its `artifact`-kind in-edges
    /// unioned with its spec's `input_artifact_refs`.
    async fn declared_scope(&self, node_id: WorkflowNodeId) -> Result<Vec<ArtifactId>, Failure>;

    /// The set of artifacts produced inside the run (the journaled
    /// produce edges), used to bound undeclared-but-authorized reads to
    /// in-run artifacts.
    async fn run_produced_artifacts(&self, run_id: RunId) -> Result<Vec<ArtifactId>, Failure>;
}
