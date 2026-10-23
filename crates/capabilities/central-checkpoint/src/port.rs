//! Persistence ports for `central-checkpoint`.
//!
//! Checkpoints are immutable (adapter-mapping §5: INSERT and SELECT
//! only, no UPDATE/DELETE on `central.checkpoints`). The ports are
//! therefore append/load/GC-delete operations — never mutation.
//! Resume-checkpoint writes (b36 readiness) dedupe on the caller's
//! `(attempt_id, checkpoint_seq)` coordinate via the fingerprint the
//! domain computes.

use central_foundation::failure::Failure;
use central_foundation::identity::{
    CheckpointId, ResumeCheckpointId, RunId, WorkflowNodeId, WorkspaceId,
};
use time::OffsetDateTime;

use crate::domain::{Checkpoint, DecodedToken, GcClass, ResumeCheckpoint};

/// Append + ordered-load port for Phase-1 checkpoint records.
///
/// `load_run_checkpoints` returns rows newest-first
/// (`checkpoints_run_id_idx`, bounded ≤ 50) — the recovery snapshot a
/// resume preflight consults.
#[trait_variant::make(Send)]
pub trait CheckpointStore: Send + Sync + 'static {
    /// Appends one immutable, checksum-bound record. A duplicate
    /// identity is a `conflict`.
    async fn append_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), Failure>;

    /// Loads the newest `limit` records of one Run, newest-first.
    /// `limit` is caller-bounded (≤ [`crate::query::MAX_CHECKPOINT_PAGE`]).
    async fn load_run_checkpoints(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
        limit: usize,
    ) -> Result<Vec<Checkpoint>, Failure>;

    /// Loads one record by identity — the migration-lineage and
    /// preflight path.
    async fn load_checkpoint(
        &self,
        workspace_id: WorkspaceId,
        checkpoint_id: CheckpointId,
    ) -> Result<Option<Checkpoint>, Failure>;
}

/// The b36 readiness port: deduplicated resume-checkpoint writes,
/// token resolution, GC selection, and delete.
#[trait_variant::make(Send)]
pub trait ResumeCheckpointStore: Send + Sync + 'static {
    /// Inserts a resume checkpoint under its
    /// `(attempt_id, checkpoint_seq)` idempotency coordinate. A
    /// coordinate already carrying a row whose
    /// [`ResumeCheckpoint::fingerprint`] differs conflicts with
    /// `DUPLICATE_IDEMPOTENCY_KEY`; an identical retry is a no-op
    /// returning the recorded row.
    async fn insert_deduplicated(
        &self,
        checkpoint: ResumeCheckpoint,
    ) -> Result<ResumeCheckpoint, Failure>;

    /// Resolves a decoded resume token to its record — the staleness
    /// check happens in the domain ([`ResumeCheckpoint::token_matches`])
    /// after this load returns the row the token names.
    async fn load_resume_checkpoint(
        &self,
        workspace_id: WorkspaceId,
        checkpoint_id: ResumeCheckpointId,
    ) -> Result<Option<ResumeCheckpoint>, Failure>;

    /// Lists GC candidates for the anchors under consideration —
    /// every row of those anchors, per the [`crate::domain::gc_pick`]
    /// contract.
    async fn list_gc_candidates(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ResumeCheckpoint>, Failure>;

    /// Deletes the selected ids (the `gc_pick` output) and returns the
    /// count actually removed — journaled `checkpoint_gc_collected`
    /// per id by the caller.
    async fn delete_checkpoints(
        &self,
        workspace_id: WorkspaceId,
        ids: &[ResumeCheckpointId],
    ) -> Result<usize, Failure>;

    /// The decoded-token boundary helper: shape-validates the opaque
    /// token in the domain, then resolves it. Kept on the port so a
    /// caller cannot accidentally resolve an unparsed string — the
    /// decode is always [`crate::domain::decode_resume_token`]'s.
    fn decode_token(&self, token: &str) -> Result<DecodedToken, Failure> {
        crate::domain::decode_resume_token(token)
    }
}

// ---------------------------------------------------------------------------
// Digester — workspace content binding (upstream `port.Digester`)
// ---------------------------------------------------------------------------

/// Hashes workspace state for checkpoint binding and resume preflight
/// (spec D3 check 3). `path` is the anchor attempt's recorded
/// `workspace_path`; `kind` its `workspace_kind` column value
/// (`"worktree"`/`"code"` or `"directory"`/`"plain"`). The production
/// implementation walks the filesystem / runs a hardened git — the
/// checkpoint capability injects it so no adapter type crosses this
/// boundary (upstream `internal/adapter/workspace/digest` behind
/// `port.Digester`). The boxed-future signature keeps the trait
/// dyn-compatible: stores hold `Arc<dyn Digester>`.
pub trait Digester: Send + Sync + 'static {
    /// Returns the deterministic `sha256:<hex>` content digest of the
    /// workspace at `path` under the `kind` scheme.
    fn digest<'a>(
        &'a self,
        path: &'a str,
        kind: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, Failure>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// Clock — deterministic evaluation instants (upstream `port.Clock`)
// ---------------------------------------------------------------------------

/// Supplies application-owned timestamps for token expiry and GC
/// evaluation. PostgreSQL remains authoritative for timestamps
/// committed inside the store's own transactions; the clock feeds
/// caller-side evaluation only.
pub trait Clock: Send + Sync + 'static {
    /// The current evaluation instant.
    fn now(&self) -> OffsetDateTime;
}

/// The default real [`Clock`]: UTC wall time (upstream `SystemClock`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Any `Fn() -> OffsetDateTime` is a [`Clock`] — the closure form of
/// upstream's `Now func() time.Time` field.
impl<F> Clock for F
where
    F: Fn() -> OffsetDateTime + Send + Sync + 'static,
{
    fn now(&self) -> OffsetDateTime {
        self()
    }
}

// ---------------------------------------------------------------------------
// ResumeStore — the orchestration seam (upstream `*pgcheckpoint.Store`'s
// public surface, narrowed onto `command.CheckpointBackend` for the CLI)
// ---------------------------------------------------------------------------

/// One GC pass's outcome — the `(int, error)` pair upstream
/// `Store.Collect` returns, shaped so a partial pass still reports its
/// deleted count: per-anchor failures land in `failures` (upstream's
/// `errors.Join`) while `collected` keeps the rows that did delete.
/// `Err` itself means the pass could not enumerate its anchors.
#[derive(Debug, Default, Clone)]
pub struct CollectOutcome {
    /// Rows actually deleted across all anchors.
    pub collected: usize,
    /// Per-anchor pass failures — the pass continued past each one.
    pub failures: Vec<Failure>,
}

impl CollectOutcome {
    /// Whether any anchor's pass failed — upstream's non-nil joined
    /// error, which the CLI reports as `CHECKPOINT_GC_PARTIAL` and the
    /// janitor logs without dying.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }
}

/// The GC surface the janitor drives each tick (upstream
/// `app.CollectStore`): one pass applies the retention-class rules over
/// every anchor and reports the deleted row count. The PostgreSQL
/// store implements it; the narrow trait keeps the janitor free of the
/// full resume surface.
#[trait_variant::make(Send)]
pub trait CollectStore: Send + Sync + 'static {
    /// Runs one garbage-collection pass at `now`.
    async fn collect(&self, now: OffsetDateTime) -> Result<CollectOutcome, Failure>;
}

/// The Phase-2C orchestration surface (upstream `*Store`'s exported
/// methods + `command.CheckpointBackend`): anchor resolution, the
/// quiescent-boundary write, token resolution and the all-or-nothing
/// preflight, the subtree resume transaction, retention-class GC,
/// pin/unpin, and the run/anchor listings. Every mutating method
/// commits its state change and its journaled events in ONE
/// transaction; a refused write still commits its `checkpoint_refused`
/// row alone.
#[trait_variant::make(Send)]
pub trait ResumeStore: CollectStore {
    /// Resolves the anchor a `checkpoint create` covers (upstream
    /// `AnchorFor`): an explicit `node_key` inside the run, or the
    /// run's unique depth-0 root when `node_key` is empty — zero or
    /// several roots refuses `CHECKPOINT_ANCHOR_AMBIGUOUS` so the
    /// operator passes `--node` explicitly.
    async fn anchor_for(&self, run_id: RunId, node_key: &str) -> Result<WorkflowNodeId, Failure>;

    /// Writes one durable checkpoint at the `(run_id, node_id)` anchor
    /// (upstream `WriteCheckpoint`). `checkpoint_seq` is the
    /// caller-supplied `(attempt_id, checkpoint_seq)` idempotency
    /// coordinate: an identical replay returns the recorded row and
    /// journals `command_deduped`; a differing payload refuses
    /// `DUPLICATE_IDEMPOTENCY_KEY`. `actor` empty resolves to
    /// `"operator"`.
    async fn write_checkpoint(
        &self,
        run_id: RunId,
        node_id: WorkflowNodeId,
        actor: &str,
        gc_class: GcClass,
        checkpoint_seq: i64,
    ) -> Result<ResumeCheckpoint, Failure>;

    /// Decodes the opaque token, loads the row it names, and verifies
    /// the row's content digest still satisfies the embedded prefix
    /// (spec D3 check 1). Absent, expired, or content-drifted rows fail
    /// `RESUME_TOKEN_STALE`. Resolution journals nothing (upstream
    /// `ResolveToken`).
    async fn resolve_token(&self, token: &str) -> Result<ResumeCheckpoint, Failure>;

    /// Runs the spec-D3 check ladder and returns the resolved
    /// checkpoint on success (upstream `ResumePreflight`). Every spec
    /// violation journals `resume_failed` with its reason code and
    /// leaves run state untouched; checks that resolve no row cannot
    /// journal — a run-scoped envelope needs a `run_id`.
    async fn resume_preflight(&self, token: &str) -> Result<ResumeCheckpoint, Failure>;

    /// Performs the all-or-nothing subtree resume for the token
    /// (upstream `ResumeSubtree`): preflight first, then under the
    /// run-row lock `resume_started`, the per-node state matrix, and
    /// `resume_completed` — one commit. Nodes returned to `ready` are
    /// picked up by the existing claim path as fresh attempts with new
    /// `attempt_seq` values; ambiguous work parks
    /// `RESUME_REQUIRES_OPERATOR_DECISION`. Replay is idempotent.
    /// `actor` empty resolves to `"operator"`.
    async fn resume_subtree(&self, token: &str, actor: &str) -> Result<(), Failure>;

    /// Rewrites one checkpoint's `gc_class` — the pin/unpin operator
    /// path (upstream `UpdateGCClass`). GC bookkeeping is
    /// digest-exempt, so the flip can never stale a live token. An
    /// absent row is an `invalid` `CHECKPOINT_NOT_FOUND`, never a
    /// silent no-op.
    async fn update_gc_class(
        &self,
        checkpoint_id: ResumeCheckpointId,
        class: GcClass,
    ) -> Result<(), Failure>;

    /// The checkpoints of one `(run_id, node_id)` anchor, newest first
    /// (upstream `ListByAnchor`).
    async fn list_by_anchor(
        &self,
        run_id: RunId,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<ResumeCheckpoint>, Failure>;

    /// Every checkpoint of one run, newest first (upstream
    /// `ListCheckpoints` — the `checkpoint list` projection).
    async fn list_checkpoints(&self, run_id: RunId) -> Result<Vec<ResumeCheckpoint>, Failure>;

    /// Reads one checkpoint by id (upstream `LoadCheckpoint`) —
    /// `invalid` `CHECKPOINT_NOT_FOUND` when the row is absent.
    async fn load_resume_checkpoint_by_id(
        &self,
        checkpoint_id: ResumeCheckpointId,
    ) -> Result<ResumeCheckpoint, Failure>;
}
