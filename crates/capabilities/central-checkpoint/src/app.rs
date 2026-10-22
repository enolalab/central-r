//! Checkpoint Service — orchestration only
//! (rust-application-boundaries.md §2.2).
//!
//! Writes seal domain intents and append them immutably; resume
//! preflight loads the record, shape-decodes the token, and runs the
//! ordered compatibility verification in the domain. GC lists
//! candidates, runs the pure [`gc_pick`] selection, and deletes the
//! result. No transaction is opened here; the adapter owns atomicity.

use central_foundation::failure::Failure;
use central_foundation::identity::{CheckpointId, ResumeCheckpointId, WorkspaceId};
use time::OffsetDateTime;

use crate::domain::{
    self, Checkpoint, CheckpointIntent, CompatibilityFacts, ResumeCheckpoint, codes,
};
use crate::port::{CheckpointStore, ResumeCheckpointStore};
use crate::query::{RunCheckpointPage, RunCheckpointRead, RunCheckpointRequest};

/// The checkpoint capability Service.
pub struct CheckpointService<S, R, Q>
where
    S: CheckpointStore,
    R: ResumeCheckpointStore,
    Q: RunCheckpointRead,
{
    store: S,
    resume: R,
    read: Q,
}

/// The outcome of a resume-token preflight.
#[derive(Debug, Clone, PartialEq)]
pub enum ResumePreflight {
    /// The token resolves to a live, content-matching record.
    Ready(Box<ResumeCheckpoint>),
    /// The token is stale — unknown id, content drift, or malformed
    /// shape (`RESUME_TOKEN_STALE`).
    Stale(Failure),
    /// No checkpoint exists for the token's id.
    NotFound,
}

impl<S, R, Q> CheckpointService<S, R, Q>
where
    S: CheckpointStore,
    R: ResumeCheckpointStore,
    Q: RunCheckpointRead,
{
    /// Wires the service against its ports.
    pub const fn new(store: S, resume: R, read: Q) -> Self {
        Self {
            store,
            resume,
            read,
        }
    }

    /// Seals a continuation intent and appends the immutable record.
    /// The boundary-legality check is the caller's earlier gate — this
    /// method assumes a quiescent boundary was already proven or is
    /// not required for the kind (e.g. `run_start`/`run_complete` are
    /// always quiescent points).
    pub async fn record_checkpoint(
        &self,
        intent: CheckpointIntent,
        now: OffsetDateTime,
    ) -> Result<Checkpoint, Failure> {
        let checkpoint = intent.seal(now)?;
        self.store.append_checkpoint(checkpoint.clone()).await?;
        Ok(checkpoint)
    }

    /// Loads one record and runs the ordered compatibility
    /// verification — the pre-resume gate. A missing record is
    /// `not_found`; a failed check is the check's structured denial.
    pub async fn verify_for_resume(
        &self,
        workspace_id: WorkspaceId,
        checkpoint_id: CheckpointId,
        facts: &CompatibilityFacts,
    ) -> Result<Checkpoint, Failure> {
        let checkpoint = self
            .store
            .load_checkpoint(workspace_id, checkpoint_id)
            .await?
            .ok_or_else(|| {
                Failure::not_found(codes::NOT_FOUND, "the checkpoint is not recorded")
            })?;
        checkpoint.verify_compatibility(facts)?;
        Ok(checkpoint)
    }

    /// The per-run recovery snapshot read.
    pub async fn run_checkpoints(
        &self,
        request: &RunCheckpointRequest,
    ) -> Result<RunCheckpointPage, Failure> {
        request.validate()?;
        self.read.read_page(request).await
    }

    /// Inserts a resume checkpoint under its idempotency coordinate —
    /// the b36 write path. Boundary legality for the anchor is the
    /// caller's earlier [`domain::boundary_legal`] gate.
    pub async fn write_resume_checkpoint(
        &self,
        checkpoint: ResumeCheckpoint,
    ) -> Result<ResumeCheckpoint, Failure> {
        self.resume.insert_deduplicated(checkpoint).await
    }

    /// Resolves an opaque resume token: decode → load → content match.
    /// A well-formed token naming a missing or mutated record is
    /// `Stale`, never a crash; a malformed token is `Stale` with the
    /// decode failure.
    pub async fn resume_preflight(
        &self,
        workspace_id: WorkspaceId,
        token: &str,
    ) -> Result<ResumePreflight, Failure> {
        let decoded = match self.resume.decode_token(token) {
            Ok(d) => d,
            Err(failure) => return Ok(ResumePreflight::Stale(failure)),
        };
        let Some(record) = self
            .resume
            .load_resume_checkpoint(workspace_id, decoded.checkpoint_id)
            .await?
        else {
            return Ok(ResumePreflight::NotFound);
        };
        if !record.token_matches(&decoded.digest_prefix) {
            return Ok(ResumePreflight::Stale(Failure::invalid(
                codes::RESUME_TOKEN_STALE,
                "the token no longer matches the record's content",
            )));
        }
        Ok(ResumePreflight::Ready(Box::new(record)))
    }

    /// GC sweep: list candidates → pure [`gc_pick`] selection → delete.
    /// Returns the ids actually removed for journaling.
    pub async fn collect_garbage(
        &self,
        workspace_id: WorkspaceId,
        now: OffsetDateTime,
    ) -> Result<Vec<ResumeCheckpointId>, Failure> {
        let candidates = self.resume.list_gc_candidates(workspace_id).await?;
        let selected = domain::gc_pick(&candidates, now);
        self.resume
            .delete_checkpoints(workspace_id, &selected)
            .await?;
        Ok(selected)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;
    use crate::domain::{
        CheckpointKind, CheckpointPayload, DEFAULT_INLINE_PAYLOAD_LIMIT, GRAPH_SCHEMA_VERSION,
        GcClass, RESUME_FORMAT_VERSION, ResumeCheckpoint,
    };
    use central_foundation::failure::FailureKind;
    use central_foundation::identity::{
        ArtifactId, RunId, SessionAttemptId, TaskId, WorkflowNodeId,
    };
    use time::Duration;

    const T0: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let waker = core::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                core::task::Poll::Ready(v) => return v,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Default)]
    struct StubStore {
        rows: Mutex<BTreeMap<CheckpointId, Checkpoint>>,
    }

    impl CheckpointStore for StubStore {
        async fn append_checkpoint(&self, checkpoint: Checkpoint) -> Result<(), Failure> {
            self.rows.lock().unwrap().insert(checkpoint.id, checkpoint);
            Ok(())
        }
        async fn load_run_checkpoints(
            &self,
            _workspace_id: WorkspaceId,
            _run_id: RunId,
            _limit: usize,
        ) -> Result<Vec<Checkpoint>, Failure> {
            Ok(Vec::new())
        }
        async fn load_checkpoint(
            &self,
            _workspace_id: WorkspaceId,
            checkpoint_id: CheckpointId,
        ) -> Result<Option<Checkpoint>, Failure> {
            Ok(self.rows.lock().unwrap().get(&checkpoint_id).cloned())
        }
    }

    #[derive(Default)]
    struct StubResume {
        rows: Mutex<BTreeMap<ResumeCheckpointId, ResumeCheckpoint>>,
    }

    impl ResumeCheckpointStore for StubResume {
        async fn insert_deduplicated(
            &self,
            checkpoint: ResumeCheckpoint,
        ) -> Result<ResumeCheckpoint, Failure> {
            let mut rows = self.rows.lock().unwrap();
            if let Some(existing) = rows
                .values()
                .find(|r| {
                    r.attempt_id == checkpoint.attempt_id
                        && r.checkpoint_seq == checkpoint.checkpoint_seq
                })
                .cloned()
            {
                if existing.fingerprint() != checkpoint.fingerprint() {
                    return Err(Failure::conflict(
                        codes::DUPLICATE_IDEMPOTENCY,
                        "the coordinate carries a different record",
                    ));
                }
                return Ok(existing);
            }
            let id = checkpoint.id;
            rows.insert(id, checkpoint.clone());
            Ok(checkpoint)
        }
        async fn load_resume_checkpoint(
            &self,
            _workspace_id: WorkspaceId,
            checkpoint_id: ResumeCheckpointId,
        ) -> Result<Option<ResumeCheckpoint>, Failure> {
            Ok(self.rows.lock().unwrap().get(&checkpoint_id).cloned())
        }
        async fn list_gc_candidates(
            &self,
            _workspace_id: WorkspaceId,
        ) -> Result<Vec<ResumeCheckpoint>, Failure> {
            Ok(self.rows.lock().unwrap().values().cloned().collect())
        }
        async fn delete_checkpoints(
            &self,
            _workspace_id: WorkspaceId,
            ids: &[ResumeCheckpointId],
        ) -> Result<usize, Failure> {
            let mut rows = self.rows.lock().unwrap();
            let mut n = 0;
            for id in ids {
                n += usize::from(rows.remove(id).is_some());
            }
            Ok(n)
        }
    }

    struct StubRead;

    impl RunCheckpointRead for StubRead {
        async fn read_page(
            &self,
            _request: &RunCheckpointRequest,
        ) -> Result<RunCheckpointPage, Failure> {
            Ok(RunCheckpointPage {
                checkpoints: Vec::new(),
                next_boundary: None,
            })
        }
    }

    fn service() -> CheckpointService<StubStore, StubResume, StubRead> {
        CheckpointService::new(StubStore::default(), StubResume::default(), StubRead)
    }

    fn payload() -> CheckpointPayload {
        CheckpointPayload::sanitize(
            br#"{"schema_version":1,"producer_version":"1.0","continuation":{"state":"ready","cursor":"c1","sequence":7,"summary":"done","metadata":{"source":"executor"}},"metadata":{"schema_version":1}}"#,
            DEFAULT_INLINE_PAYLOAD_LIMIT,
        )
        .unwrap()
    }

    fn intent() -> CheckpointIntent {
        CheckpointIntent {
            workspace_id: WorkspaceId::new(),
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: None,
            step_attempt_id: None,
            kind: CheckpointKind::StepBoundary,
            producer_id: "central-executor".into(),
            producer_version: "1.0".into(),
            schema_version: 1,
            policy_fingerprint: "sha256:aa".into(),
            agent_revision_fingerprint: "sha256:bb".into(),
            payload: payload(),
            metadata: None,
            eligible_after: T0 + Duration::days(90),
            legal_hold: false,
            source_checkpoint_id: None,
        }
    }

    fn resume(id_seq: i64, gc: GcClass, created: OffsetDateTime) -> ResumeCheckpoint {
        let row = ResumeCheckpoint {
            id: ResumeCheckpointId::new(),
            workspace_id: WorkspaceId::new(),
            run_id: RunId::new(),
            node_id: WorkflowNodeId::new(),
            attempt_id: SessionAttemptId::new(),
            checkpoint_seq: id_seq,
            format_version: RESUME_FORMAT_VERSION.into(),
            graph_schema_version: GRAPH_SCHEMA_VERSION.into(),
            event_watermark: 10,
            harness_session_id: None,
            workspace_digest: None,
            workspace_path: None,
            completed_nodes: vec!["n1".into()],
            finalized_artifacts: vec![ArtifactId::new()],
            in_flight_nodes: Vec::new(),
            gc_class: gc,
            created_at: created,
            expires_at: None,
            content_digest: String::new(),
        };
        let digest = row.digest();
        ResumeCheckpoint {
            content_digest: digest,
            ..row
        }
    }

    #[test]
    fn record_checkpoint_seals_checksum_and_appends() {
        let svc = service();
        let checkpoint = block_on(svc.record_checkpoint(intent(), T0)).unwrap();
        assert_eq!(checkpoint.kind, CheckpointKind::StepBoundary);
        assert!(checkpoint.validated);
        assert_eq!(
            domain::payload_checksum(checkpoint.payload.as_bytes()),
            checkpoint.checksum
        );
    }

    #[test]
    fn verify_for_resume_runs_the_ordered_checks() {
        let svc = service();
        let checkpoint = block_on(svc.record_checkpoint(intent(), T0)).unwrap();
        let facts = CompatibilityFacts {
            lease_held: true,
            reader_schema_version: domain::CURRENT_SCHEMA_VERSION,
            producer_known: true,
            agent_revision_matches: true,
            policy_fingerprint_matches: true,
            artifacts_ready: true,
            evidence_consistent: true,
        };
        block_on(svc.verify_for_resume(checkpoint.workspace_id, checkpoint.id, &facts)).unwrap();

        let bad = CompatibilityFacts {
            policy_fingerprint_matches: false,
            ..facts
        };
        let err = block_on(svc.verify_for_resume(checkpoint.workspace_id, checkpoint.id, &bad))
            .unwrap_err();
        assert_eq!(err.code(), codes::POLICY_MISMATCH);

        let missing =
            block_on(svc.verify_for_resume(checkpoint.workspace_id, CheckpointId::new(), &facts))
                .unwrap_err();
        assert_eq!(missing.kind(), FailureKind::NotFound);
    }

    #[test]
    fn resume_preflight_decodes_loads_and_content_matches() {
        let svc = service();
        let row = resume(1, GcClass::Pinned, T0);
        let token = row.encode_token();
        let ws = row.workspace_id;
        block_on(svc.write_resume_checkpoint(row)).unwrap();

        match block_on(svc.resume_preflight(ws, &token)).unwrap() {
            ResumePreflight::Ready(_) => {}
            other => assert!(
                matches!(other, ResumePreflight::Ready(_)),
                "expected a ready preflight"
            ),
        }
        match block_on(svc.resume_preflight(ws, "ckpt.garbage.xx")).unwrap() {
            ResumePreflight::Stale(f) => assert_eq!(f.code(), codes::RESUME_TOKEN_STALE),
            other => assert!(
                matches!(other, ResumePreflight::Stale(_)),
                "expected a stale preflight"
            ),
        }
        let forged = format!("ckpt.{}.{}", ResumeCheckpointId::new(), "ab".repeat(16));
        assert_eq!(
            block_on(svc.resume_preflight(ws, &forged)).unwrap(),
            ResumePreflight::NotFound
        );
    }

    #[test]
    fn deduplicate_rejects_same_coordinate_different_fingerprint() {
        let svc = service();
        let a = resume(9, GcClass::Supersedeable, T0);
        let ws = a.workspace_id;
        let run = a.run_id;
        let node = a.node_id;
        let attempt = a.attempt_id;
        block_on(svc.write_resume_checkpoint(a)).unwrap();

        let mut b = resume(9, GcClass::Supersedeable, T0);
        b.workspace_id = ws;
        b.run_id = run;
        b.node_id = node;
        b.attempt_id = attempt; // same coordinate, different content
        let err = block_on(svc.write_resume_checkpoint(b)).unwrap_err();
        assert_eq!(err.code(), codes::DUPLICATE_IDEMPOTENCY);
    }

    #[test]
    fn gc_collects_selected_ids_only() {
        let svc = service();
        let ws = WorkspaceId::new();
        // One anchor, four supersedeable rows — oldest pushed past
        // keep-latest=3.
        let run = RunId::new();
        let node = WorkflowNodeId::new();
        for i in 0..4 {
            let mut row = resume(
                i64::from(i),
                GcClass::Supersedeable,
                T0 + Duration::minutes(i64::from(i)),
            );
            row.workspace_id = ws;
            row.run_id = run;
            row.node_id = node;
            block_on(svc.write_resume_checkpoint(row)).unwrap();
        }
        let mut pinned = resume(50, GcClass::Pinned, T0 - Duration::days(400));
        pinned.workspace_id = ws;
        block_on(svc.write_resume_checkpoint(pinned)).unwrap();
        let mut terminal = resume(51, GcClass::RunTerminal, T0 - Duration::days(31));
        terminal.workspace_id = ws;
        block_on(svc.write_resume_checkpoint(terminal)).unwrap();

        let removed = block_on(svc.collect_garbage(ws, T0 + Duration::days(1))).unwrap();
        assert_eq!(removed.len(), 2, "oldest supersedeable + aged run_terminal");
    }
}
