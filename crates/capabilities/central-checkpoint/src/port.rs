//! Persistence ports for `central-checkpoint`.
//!
//! Checkpoints are immutable (adapter-mapping §5: INSERT and SELECT
//! only, no UPDATE/DELETE on `central.checkpoints`). The ports are
//! therefore append/load/GC-delete operations — never mutation.
//! Resume-checkpoint writes (b36 readiness) dedupe on the caller's
//! `(attempt_id, checkpoint_seq)` coordinate via the fingerprint the
//! domain computes.

use central_foundation::failure::Failure;
use central_foundation::identity::{CheckpointId, ResumeCheckpointId, RunId, WorkspaceId};

use crate::domain::{Checkpoint, DecodedToken, ResumeCheckpoint};

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
