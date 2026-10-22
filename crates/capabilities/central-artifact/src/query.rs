//! Bounded read contract for `central-artifact`:
//! `ArtifactSummaryRead` — the per-Task artifact list consumed by the
//! `central-artifact::app` `ListArtifactSummaries` service
//! (adapter-mapping §3.9 `artifacts_task_id_idx`,
//! rust-application-boundaries.md §2.3/§3.4, surface matrix §4.7.7).
//!
//! Declaration-only: typed seek pagination over
//! `(workspace_id, task_id, updated_at DESC)` with a `(updated_at,
//! artifact_id)` keyset cursor — never offset, never an unbounded scan.
//! Projections carry only safe display facts: no object keys, no staging
//! generations, no authority tokens.

use central_foundation::failure::Failure;
use central_foundation::identity::{ArtifactId, RunId, TaskId, WorkspaceId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::domain::{Disposition, Sensitivity, State};

/// Default page size for [`ArtifactListRequest`] when `page_size` is `0`.
pub const DEFAULT_ARTIFACT_PAGE_SIZE: u32 = 100;
/// Hard ceiling on one artifact summary page.
pub const MAX_ARTIFACT_PAGE_SIZE: u32 = 250;

/// The typed keyset seek cursor for the artifact summary list
/// (`artifacts_task_id_idx` ordering `updated_at DESC`): the boundary
/// row's `updated_at` plus its `artifact_id` tiebreaker. `None` on the
/// request asks for the head page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSeekCursor {
    /// The boundary row's `updated_at`.
    pub updated_at: OffsetDateTime,
    /// The boundary row's artifact identity.
    pub artifact_id: ArtifactId,
}

/// A workspace- and task-scoped keyset list request.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactListRequest {
    /// The owning workspace — mandatory isolation scope.
    pub workspace_id: WorkspaceId,
    /// The task whose artifacts are listed — mandatory per the
    /// `artifacts_task_id_idx` covering index.
    pub task_id: TaskId,
    /// Continuation boundary; `None` requests the head page.
    pub cursor: Option<ArtifactSeekCursor>,
    /// Requested page size; `0` normalizes to
    /// [`DEFAULT_ARTIFACT_PAGE_SIZE`], values above
    /// [`MAX_ARTIFACT_PAGE_SIZE`] clamp to it.
    pub page_size: u32,
}

/// Validates the mandatory workspace/task isolation scope.
pub fn validate_artifact_list_request(req: &ArtifactListRequest) -> Result<(), Failure> {
    if req.workspace_id.is_nil() || req.task_id.is_nil() {
        return Err(Failure::invalid(
            "ARTIFACT_LIST_SCOPE_REQUIRED",
            "the artifact list requires a workspace and task scope",
        ));
    }
    Ok(())
}

/// Clamps a requested page size into
/// `[1, MAX_ARTIFACT_PAGE_SIZE]`, defaulting `0` to
/// [`DEFAULT_ARTIFACT_PAGE_SIZE`].
#[must_use]
pub const fn normalize_artifact_page_size(page_size: u32) -> u32 {
    if page_size == 0 {
        DEFAULT_ARTIFACT_PAGE_SIZE
    } else if page_size > MAX_ARTIFACT_PAGE_SIZE {
        MAX_ARTIFACT_PAGE_SIZE
    } else {
        page_size
    }
}

/// A safe, immutable artifact summary projection row (§4.7.7: "Artifact
/// identity, media type, size displayed" plus the lifecycle,
/// sensitivity, and disposition facts the download action needs).
///
/// It deliberately exposes no `staging_key`/`ready_key`, no
/// `staging_generation`/`content_generation`, no `version` fencing
/// token, and no authority material — object locators and generations
/// never cross the read boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactSummaryView {
    /// The artifact identity.
    pub artifact_id: ArtifactId,
    /// The owning task.
    pub task_id: TaskId,
    /// The producing run.
    pub run_id: RunId,
    /// Current lifecycle state.
    pub state: State,
    /// Persisted sensitivity classification (drives preview eligibility).
    pub sensitivity: Sensitivity,
    /// Persisted delivery disposition.
    pub disposition: Disposition,
    /// The detected media type recorded at verification (`None` until a
    /// body has been classified — never the producer-declared hint).
    pub media_type: Option<String>,
    /// Verified full-body size in bytes (`0` until verified).
    pub verified_size: i64,
    /// The required-output role (`""` when none) — display only; the UI
    /// maps it to its own fixed label.
    pub required_role: String,
    /// The producer identity.
    pub producer_id: String,
    /// Durable creation timestamp.
    pub created_at: OffsetDateTime,
    /// Durable last-update timestamp — also the cursor's sort key.
    pub updated_at: OffsetDateTime,
    /// When the artifact finalized (`None` until `ready`).
    pub ready_at: Option<OffsetDateTime>,
}

/// The bounded list response payload.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactListProjection {
    /// One page of artifact summaries, `updated_at DESC`.
    pub artifacts: Vec<ArtifactSummaryView>,
    /// Forward-only continuation; `None` = end of list.
    pub next_cursor: Option<ArtifactSeekCursor>,
}

/// The read contract behind `ListArtifactSummaries`. Consumed only by
/// `central-artifact::app` after the surface-appropriate authorization
/// decision; implemented by `central-adapter-postgres` in a single
/// bounded round trip.
#[trait_variant::make(Send)]
pub trait ArtifactSummaryRead: Send + Sync + 'static {
    /// Reads one bounded `updated_at DESC` page of task-scoped artifact
    /// summaries.
    async fn list_artifacts(
        &self,
        request: &ArtifactListRequest,
    ) -> Result<ArtifactListProjection, Failure>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const V7_A: &str = "018f3b2a-1c4d-7e9f-8a1b-2c3d4e5f6a7b";
    const V7_B: &str = "0190a1b2-c3d4-7e5f-9a8b-7c6d5e4f3a2b";

    fn request() -> ArtifactListRequest {
        ArtifactListRequest {
            workspace_id: WorkspaceId::parse(V7_A).unwrap(),
            task_id: TaskId::parse(V7_B).unwrap(),
            cursor: None,
            page_size: 0,
        }
    }

    /// `page_size` clamps into the bounded range: `0` defaults to 100,
    /// values above 250 clamp (§3.4 `page_size` bound).
    #[test]
    fn page_size_normalizes_into_bounds() {
        assert_eq!(normalize_artifact_page_size(0), 100);
        assert_eq!(normalize_artifact_page_size(1), 1);
        assert_eq!(normalize_artifact_page_size(50), 50);
        assert_eq!(normalize_artifact_page_size(100), 100);
        assert_eq!(normalize_artifact_page_size(250), 250);
        assert_eq!(normalize_artifact_page_size(251), 250);
        assert_eq!(normalize_artifact_page_size(u32::MAX), 250);
    }

    #[test]
    fn request_validation_accepts_scoped_request() {
        validate_artifact_list_request(&request()).unwrap();
    }

    /// A missing workspace or task scope fails closed — the mandatory
    /// isolation scope is never inferred.
    #[test]
    fn request_validation_rejects_missing_scope() {
        for req in [
            ArtifactListRequest {
                workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
                ..request()
            },
            ArtifactListRequest {
                task_id: TaskId::from_trusted_db_bytes([0; 16]),
                ..request()
            },
        ] {
            let failure = validate_artifact_list_request(&req).unwrap_err();
            assert_eq!(failure.code(), "ARTIFACT_LIST_SCOPE_REQUIRED");
        }
    }

    /// The seek cursor round-trips its boundary `(updated_at,
    /// artifact_id)` pair.
    #[test]
    fn seek_cursor_carries_keyset_boundary() {
        let cursor = ArtifactSeekCursor {
            updated_at: OffsetDateTime::UNIX_EPOCH,
            artifact_id: ArtifactId::parse(V7_A).unwrap(),
        };
        let mut req = request();
        req.cursor = Some(cursor);
        assert_eq!(req.cursor, Some(cursor));
    }
}
