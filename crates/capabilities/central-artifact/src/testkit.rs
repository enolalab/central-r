//! Shared in-memory fakes for the `central-artifact` test suite — the
//! ports of upstream `service_test.go`'s `fakeStore`/`fakeObjects`/
//! `fakeClassifier`/`fakeCompletion`, `reconciler_test.go`'s
//! `fakeReconciliationStore`/`fakeRecords`, and `lineage_test.go`'s
//! `fakeLineageStore`, plus the unsafe-free `block_on` the async tests
//! drive them through. Compiled only under `#[cfg(test)]`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io::Read as _;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use central_execution::domain::ExecutionChangeSet;
use central_foundation::failure::Failure;
use central_foundation::identity::{ArtifactId, RunId, WorkflowNodeId, WorkspaceId};
use time::OffsetDateTime;

use crate::app::{ResumeLifecycle, ResumeResult};
use crate::domain::{
    Artifact, ArtifactTombstone, BeginUploadResult, FAILURE_CODE_STAGING_EXPIRED, Outcome,
    OutcomeKind, PromotionResult, RejectResult, ReserveResult, VerifiedResult,
};
use crate::lineage::{LineageArtifact, ProduceEdge, ReadEdge};
use crate::port::{
    ArtifactChangeSet, ByteStream, ByteStreamFuture, ClaimIncompleteRequest, ClaimIncompleteResult,
    ClaimLargeRequest, ClaimRejectedStagingRequest, ClaimRejectedStagingResult, Classifier,
    ClassifyRequest, ClassifyResult, ClearStagingKeyRequest, CommitResult, CompletionContributor,
    ExpireStagingRequest, ExpireStagingResult, LargeClaim, LineageReader, ObjectInfo, ObjectRef,
    ObjectStore, ProduceEdgeStore, ReadEdgeStore, ReadStore, ReconciliationProgress,
    ReconciliationStore, RecordLargeClaimRequest, RejectedStagingClaim, ReleaseLargeClaimRequest,
    Store, TwoPhaseDeleteResult, TwoPhaseDeleteStore, UploadRequest, UploadResult,
};

/// A state cell shared between a fake and the fixture that cloned it —
/// what upstream's `*journal`/`f.objects` pointer fields express. Every
/// fake derives `Clone`, so the service can own a clone while the test
/// still observes the same interior.
type Shared<T> = Arc<Mutex<T>>;

/// Wraps a value in shared interior state.
fn shared<T>(value: T) -> Shared<T> {
    Arc::new(Mutex::new(value))
}

/// Runs an immediately-ready future to completion (the fakes never
/// yield). `Waker::noop` keeps this unsafe-free — the same pattern
/// `central-execution`'s test suite uses.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

// ---------------------------------------------------------------------------
// Journal — upstream's `journal`, the ordered call log the ordering
// invariants are asserted against.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub(crate) struct Journal {
    steps: Shared<Vec<String>>,
}

impl Journal {
    pub(crate) fn record(&self, step: &str) {
        self.steps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(step.to_owned());
    }

    pub(crate) fn steps(&self) -> Vec<String> {
        self.steps.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(crate) fn clear(&self) {
        self.steps.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub(crate) fn index(&self, step: &str) -> Option<usize> {
        self.steps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .position(|s| s == step)
    }

    pub(crate) fn has(&self, step: &str) -> bool {
        self.index(step).is_some()
    }
}

// ---------------------------------------------------------------------------
// SliceStream — the ByteStream over an in-memory body.
// ---------------------------------------------------------------------------

pub(crate) struct SliceStream {
    inner: std::io::Cursor<Vec<u8>>,
    closed: bool,
}

impl SliceStream {
    pub(crate) fn new(body: Vec<u8>) -> Self {
        Self {
            inner: std::io::Cursor::new(body),
            closed: false,
        }
    }
}

impl ByteStream for SliceStream {
    fn read_chunk<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> ByteStreamFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            if self.closed {
                return Err(Failure::internal(
                    "ARTIFACT_TEST_STREAM_CLOSED",
                    "read after close",
                ));
            }
            self.inner.read(buf).map_err(|_| {
                Failure::unavailable("ARTIFACT_TEST_STREAM_READ", "in-memory read failed")
            })
        })
    }

    fn close<'a>(&'a mut self) -> ByteStreamFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            self.closed = true;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// FakeObjects — upstream `fakeObjects` (service + reconciler tests).
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FakeObjects {
    pub(crate) journal: Journal,
    pub(crate) objects: Shared<HashMap<String, Vec<u8>>>,
    pub(crate) versions: Shared<HashMap<String, String>>,

    /// Per-key injected read failure (upstream `readErr map[string]error`).
    pub(crate) read_err: Shared<HashMap<String, Failure>>,
    pub(crate) upload_err: Shared<Option<Failure>>,
    pub(crate) promote_err: Shared<Option<Failure>>,
    /// Rewrites the ready object's bytes at promotion so the second
    /// verification observes different evidence.
    pub(crate) mutate_ready: Shared<Option<Vec<u8>>>,
    /// Replaces the ready object's version evidence at promotion,
    /// standing in for an object replaced under the ready key.
    pub(crate) rewrite_ready_version: Shared<Option<String>>,
    /// Models an object store exposing neither a version nor an ETag —
    /// an explicitly supported configuration.
    pub(crate) no_version_evidence: Shared<bool>,
    /// Models a transient object-store failure on cleanup.
    pub(crate) remove_err: Shared<Option<Failure>>,
    /// Models a slow object store so a sweep's time ceiling is observable.
    pub(crate) remove_delay: Shared<Duration>,

    pub(crate) removed_staging: Shared<Vec<String>>,
    pub(crate) removed_ready: Shared<Vec<String>>,
}

impl FakeObjects {
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            objects: shared(HashMap::new()),
            versions: shared(HashMap::new()),
            read_err: shared(HashMap::new()),
            upload_err: shared(None),
            promote_err: shared(None),
            mutate_ready: shared(None),
            rewrite_ready_version: shared(None),
            no_version_evidence: shared(false),
            remove_err: shared(None),
            remove_delay: shared(Duration::ZERO),
            removed_staging: shared(Vec::new()),
            removed_ready: shared(Vec::new()),
        }
    }

    /// Installs a staging object plus its version evidence directly —
    /// upstream's `f.objects.objects[key] = body` fixture path.
    pub(crate) fn put(&self, key: &str, body: &[u8], version: &str) {
        self.objects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_owned(), body.to_vec());
        self.versions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_owned(), version.to_owned());
    }
}

impl ObjectStore for FakeObjects {
    async fn upload(&self, request: UploadRequest) -> Result<UploadResult, Failure> {
        self.journal.record("object.Upload");
        if let Some(failure) = self
            .upload_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        let mut body = Vec::new();
        request
            .body
            .take((request.max_bytes + 1) as u64)
            .read_to_end(&mut body)
            .map_err(|_| {
                Failure::internal("ARTIFACT_TEST_BODY_READ", "in-memory upload body failed")
            })?;
        let size = body.len() as i64;
        self.objects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(request.reference.key.clone(), body);
        self.versions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(request.reference.key, "v-staging".to_owned());
        Ok(UploadResult {
            info: ObjectInfo {
                size,
                etag: String::new(),
                version: "v-staging".to_owned(),
            },
        })
    }

    async fn read(
        &self,
        reference: ObjectRef,
    ) -> Result<(Box<dyn ByteStream>, ObjectInfo), Failure> {
        if reference.key.contains("/ready/") {
            self.journal.record("object.ReadReady");
        } else {
            self.journal.record("object.ReadStaging");
        }
        if let Some(failure) = self
            .read_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&reference.key)
            .cloned()
        {
            return Err(failure);
        }
        let objects = self.objects.lock().unwrap_or_else(|e| e.into_inner());
        let versions = self.versions.lock().unwrap_or_else(|e| e.into_inner());
        let body = objects
            .get(&reference.key)
            .ok_or_else(|| Failure::internal("ARTIFACT_TEST_OBJECT_MISSING", "object missing"))?;
        let info = ObjectInfo {
            size: body.len() as i64,
            etag: String::new(),
            version: versions.get(&reference.key).cloned().unwrap_or_default(),
        };
        Ok((Box::new(SliceStream::new(body.clone())), info))
    }

    async fn promote_create_only(
        &self,
        source: ObjectRef,
        destination: ObjectRef,
    ) -> Result<ObjectInfo, Failure> {
        self.journal.record("object.Promote");
        if let Some(failure) = self
            .promote_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        let mut objects = self.objects.lock().unwrap_or_else(|e| e.into_inner());
        let mut versions = self.versions.lock().unwrap_or_else(|e| e.into_inner());
        let mut body = objects.get(&source.key).cloned().ok_or_else(|| {
            Failure::internal("ARTIFACT_TEST_OBJECT_MISSING", "staging object missing")
        })?;
        if let Some(mutated) = self
            .mutate_ready
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            body = mutated;
        }
        let version = "v-ready".to_owned();
        // The rewrite models an object replaced under the ready key:
        // only the *stored* evidence changes — the promote call's own
        // ObjectInfo keeps reporting the version it actually created, so
        // the second verification observes the divergence.
        let stored_version = self
            .rewrite_ready_version
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| version.clone());
        let size = body.len() as i64;
        if *self
            .no_version_evidence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            objects.insert(destination.key.clone(), body);
            versions.insert(destination.key, String::new());
            return Ok(ObjectInfo {
                size,
                etag: String::new(),
                version: String::new(),
            });
        }
        objects.insert(destination.key.clone(), body);
        versions.insert(destination.key, stored_version);
        Ok(ObjectInfo {
            size,
            etag: String::new(),
            version,
        })
    }

    async fn remove_staging(&self, reference: ObjectRef) -> Result<(), Failure> {
        self.journal.record("object.RemoveStaging");
        let delay = *self.remove_delay.lock().unwrap_or_else(|e| e.into_inner());
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        if let Some(failure) = self
            .remove_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        self.removed_staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(reference.key.clone());
        self.objects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&reference.key);
        Ok(())
    }

    async fn remove_ready_for_delete(&self, reference: ObjectRef) -> Result<(), Failure> {
        self.journal.record("object.RemoveReady");
        if let Some(failure) = self
            .remove_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        self.removed_ready
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(reference.key.clone());
        self.objects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&reference.key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FakeStore — upstream `fakeStore` (service tests): command stages return
// the input result; `artifacts` backs load_artifact for delivery and
// delete scenarios and is populated by the test, never by the command
// stages — materialization must not reread durable state mid-command.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FakeStore {
    pub(crate) journal: Journal,

    pub(crate) reserve_err: Shared<Option<Failure>>,
    pub(crate) begin_err: Shared<Option<Failure>>,
    pub(crate) verify_err: Shared<Option<Failure>>,
    pub(crate) promote_err: Shared<Option<Failure>>,
    pub(crate) reject_err: Shared<Option<Failure>>,
    /// The last verified result the store saw (upstream `verifiedSeen`).
    pub(crate) verified: Shared<Option<VerifiedResult>>,
    /// The last rejected result the store saw (upstream `rejectedSeen`).
    pub(crate) rejected: Shared<Option<RejectResult>>,

    /// Caller-populated snapshots for `load_artifact`.
    pub(crate) artifacts: Shared<HashMap<ArtifactId, Artifact>>,
    pub(crate) tombstones: Shared<HashMap<ArtifactId, ArtifactTombstone>>,
    pub(crate) load_err: Shared<Option<Failure>>,
    pub(crate) delete_pending_err: Shared<Option<Failure>>,
    pub(crate) complete_err: Shared<Option<Failure>>,
}

impl FakeStore {
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            reserve_err: shared(None),
            begin_err: shared(None),
            verify_err: shared(None),
            promote_err: shared(None),
            reject_err: shared(None),
            verified: shared(None),
            rejected: shared(None),
            artifacts: shared(HashMap::new()),
            tombstones: shared(HashMap::new()),
            load_err: shared(None),
            delete_pending_err: shared(None),
            complete_err: shared(None),
        }
    }
}

impl Store for FakeStore {
    async fn reserve_artifact(&self, result: ReserveResult) -> Result<ReserveResult, Failure> {
        self.journal.record("store.Reserve");
        if let Some(failure) = self
            .reserve_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        Ok(result)
    }

    async fn record_begin_upload(
        &self,
        result: BeginUploadResult,
    ) -> Result<BeginUploadResult, Failure> {
        self.journal.record("store.BeginUpload");
        if let Some(failure) = self
            .begin_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        Ok(result)
    }

    async fn record_verification(&self, result: VerifiedResult) -> Result<VerifiedResult, Failure> {
        self.journal.record("store.Verify");
        *self.verified.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());
        if let Some(failure) = self
            .verify_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        Ok(result)
    }

    async fn record_promotion(&self, result: PromotionResult) -> Result<PromotionResult, Failure> {
        self.journal.record("store.Promote");
        if let Some(failure) = self
            .promote_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        Ok(result)
    }

    async fn record_rejection(&self, result: RejectResult) -> Result<RejectResult, Failure> {
        self.journal.record("store.Reject");
        *self.rejected.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());
        if let Some(failure) = self
            .reject_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        Ok(result)
    }

    async fn load_artifact(
        &self,
        _workspace_id: WorkspaceId,
        artifact_id: ArtifactId,
    ) -> Result<Artifact, Failure> {
        self.journal.record("store.Load");
        if let Some(failure) = self
            .load_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        self.artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&artifact_id)
            .cloned()
            .ok_or_else(|| {
                Failure::internal(
                    "ARTIFACT_TEST_UNEXPECTED_LOAD",
                    "materialization must not reread durable state",
                )
            })
    }
}

impl TwoPhaseDeleteStore for FakeStore {
    async fn mark_delete_pending(&self, next: Artifact) -> Result<Artifact, Failure> {
        self.journal.record("store.DeletePending");
        if let Some(failure) = self
            .delete_pending_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        self.artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(next.artifact_id, next.clone());
        Ok(next)
    }

    async fn complete_deletion_with_tombstone(
        &self,
        next: Artifact,
        tombstone: ArtifactTombstone,
    ) -> Result<TwoPhaseDeleteResult, Failure> {
        self.journal.record("store.CompleteDeletion");
        if let Some(failure) = self
            .complete_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        self.artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(next.artifact_id, next.clone());
        self.tombstones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(next.artifact_id, tombstone.clone());
        Ok(TwoPhaseDeleteResult {
            artifact: next,
            tombstone,
            replayed: false,
        })
    }

    async fn has_tombstone(
        &self,
        _workspace_id: WorkspaceId,
        artifact_id: ArtifactId,
    ) -> Result<bool, Failure> {
        Ok(self
            .tombstones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&artifact_id))
    }
}

// ---------------------------------------------------------------------------
// FakeClassifier + FakeCompletion — upstream `fakeClassifier`/`fakeCompletion`.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FakeClassifier {
    pub(crate) journal: Journal,
    pub(crate) result: Shared<ClassifyResult>,
    pub(crate) err: Shared<Option<Failure>>,
    /// Captures exactly what the classifier was handed, proving
    /// classification runs over the staged body rather than the caller
    /// stream.
    pub(crate) saw_bytes: Shared<Vec<u8>>,
}

impl FakeClassifier {
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            result: shared(ClassifyResult {
                detected_media_type: crate::classifier::MEDIA_TYPE_MARKDOWN.to_owned(),
                secret_disclosure: false,
                rejection_code: String::new(),
            }),
            err: shared(None),
            saw_bytes: shared(Vec::new()),
        }
    }
}

impl Classifier for FakeClassifier {
    async fn classify(&self, mut request: ClassifyRequest) -> Result<ClassifyResult, Failure> {
        self.journal.record("classifier.Classify");
        let mut body = Vec::new();
        request.body.read_to_end(&mut body).map_err(|_| {
            Failure::internal("ARTIFACT_TEST_BODY_READ", "in-memory classify body failed")
        })?;
        *self.saw_bytes.lock().unwrap_or_else(|e| e.into_inner()) = body;
        if let Some(failure) = self.err.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Err(failure);
        }
        Ok(self
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }
}

#[derive(Clone)]
pub(crate) struct FakeCompletion {
    pub(crate) journal: Journal,
    /// The change set the last commit saw.
    pub(crate) change: Shared<Option<ArtifactChangeSet>>,
    pub(crate) exec: Shared<Option<ExecutionChangeSet>>,
    pub(crate) result: Shared<Option<CommitResult>>,
    pub(crate) err: Shared<Option<Failure>>,
    pub(crate) replayed: Shared<bool>,
}

impl FakeCompletion {
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            change: shared(None),
            exec: shared(None),
            result: shared(None),
            err: shared(None),
            replayed: shared(false),
        }
    }
}

impl CompletionContributor for FakeCompletion {
    async fn commit_artifact(
        &self,
        change: ArtifactChangeSet,
        exec_change: ExecutionChangeSet,
    ) -> Result<CommitResult, Failure> {
        self.journal.record("completion.Commit");
        *self.change.lock().unwrap_or_else(|e| e.into_inner()) = Some(change.clone());
        *self.exec.lock().unwrap_or_else(|e| e.into_inner()) = Some(exec_change);
        if let Some(failure) = self.err.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Err(failure);
        }
        let replayed = *self.replayed.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(result) = self
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Ok(result);
        }
        // Upstream: `if f.result.Outcome.Kind == "" { return the
        // finalize's own outcome }` — a fake with no canned result
        // commits the ready transition.
        Ok(CommitResult {
            outcome: change.finalize.outcome,
            replayed,
        })
    }
}

// ---------------------------------------------------------------------------
// FakeRecords — upstream `fakeRecords` (reconciler tests): only
// `load_artifact` and `record_promotion` are legal reconciliation-pass
// calls; every other command stage fails loudly.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FakeRecords {
    pub(crate) journal: Journal,
    pub(crate) artifacts: Shared<HashMap<ArtifactId, Artifact>>,
    pub(crate) load_err: Shared<Option<Failure>>,
    /// Models a single unlucky item — a row briefly unreadable — without
    /// failing every other item in the same pass.
    pub(crate) load_err_for: Shared<HashMap<ArtifactId, Failure>>,
    /// Models per-item work so the pass's own time budget is observable.
    pub(crate) delay: Shared<Duration>,
}

impl FakeRecords {
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            artifacts: shared(HashMap::new()),
            load_err: shared(None),
            load_err_for: shared(HashMap::new()),
            delay: shared(Duration::ZERO),
        }
    }

    fn unexpected(&self, stage: &str) -> Failure {
        self.journal.record(&format!("records.{stage}"));
        Failure::internal(
            "ARTIFACT_TEST_UNEXPECTED_STAGE",
            "reconciliation must not drive a command stage",
        )
    }
}

impl Store for FakeRecords {
    async fn reserve_artifact(&self, _result: ReserveResult) -> Result<ReserveResult, Failure> {
        Err(self.unexpected("Reserve"))
    }

    async fn record_begin_upload(
        &self,
        _result: BeginUploadResult,
    ) -> Result<BeginUploadResult, Failure> {
        Err(self.unexpected("BeginUpload"))
    }

    async fn record_verification(
        &self,
        _result: VerifiedResult,
    ) -> Result<VerifiedResult, Failure> {
        Err(self.unexpected("Verify"))
    }

    async fn record_promotion(&self, result: PromotionResult) -> Result<PromotionResult, Failure> {
        self.journal.record("records.Promote");
        self.artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(result.artifact.artifact_id, result.artifact.clone());
        Ok(result)
    }

    async fn record_rejection(&self, _result: RejectResult) -> Result<RejectResult, Failure> {
        Err(self.unexpected("Reject"))
    }

    async fn load_artifact(
        &self,
        _workspace_id: WorkspaceId,
        artifact_id: ArtifactId,
    ) -> Result<Artifact, Failure> {
        self.journal.record("records.Load");
        let delay = *self.delay.lock().unwrap_or_else(|e| e.into_inner());
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        if let Some(failure) = self
            .load_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        if let Some(failure) = self
            .load_err_for
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&artifact_id)
            .cloned()
        {
            return Err(failure);
        }
        self.artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&artifact_id)
            .cloned()
            .ok_or_else(|| Failure::internal("ARTIFACT_TEST_MISSING", "artifact missing"))
    }
}

// ---------------------------------------------------------------------------
// FakeLifecycle — upstream `fakeLifecycle`: the reconciler's
// ResumeLifecycle port, capturing each resumed record and answering a
// canned ResumeResult.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FakeLifecycle {
    pub(crate) journal: Journal,
    /// Every Artifact `resume_verifying` was asked to resolve.
    pub(crate) calls: Shared<Vec<Artifact>>,
    /// The canned result a successful resume returns.
    pub(crate) result: Shared<ResumeResult>,
    pub(crate) err: Shared<Option<Failure>>,
}

impl FakeLifecycle {
    pub(crate) fn new(journal: Journal) -> Self {
        Self {
            journal,
            calls: shared(Vec::new()),
            result: shared(ResumeResult {
                outcome: Outcome {
                    kind: OutcomeKind::Ready,
                    failure_code: String::new(),
                },
                resolved: true,
                bytes_moved: 0,
            }),
            err: shared(None),
        }
    }
}

impl ResumeLifecycle for FakeLifecycle {
    async fn resume_verifying(&self, current: Artifact) -> Result<ResumeResult, Failure> {
        self.journal.record("lifecycle.Resume");
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(current);
        if let Some(failure) = self.err.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Err(failure);
        }
        Ok(self
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }
}

// ---------------------------------------------------------------------------
// FakeReconciliationStore — upstream `fakeReconciliationStore`.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FakeReconciliationStore {
    pub(crate) journal: Journal,

    /// Batches served one at a time, in order (upstream `incomplete`).
    pub(crate) incomplete: Shared<VecDeque<ClaimIncompleteResult>>,
    pub(crate) incomplete_err: Shared<Option<Failure>>,
    pub(crate) claim_reqs: Shared<Vec<ClaimIncompleteRequest>>,

    pub(crate) large: Shared<Option<LargeClaim>>,
    pub(crate) large_err: Shared<Option<Failure>>,
    pub(crate) large_calls: Shared<usize>,

    pub(crate) progress: Shared<Vec<ReconciliationProgress>>,
    pub(crate) progress_err: Shared<Option<Failure>>,

    pub(crate) large_claim_reqs: Shared<Vec<RecordLargeClaimRequest>>,
    pub(crate) large_recorded: Shared<Vec<ArtifactId>>,
    pub(crate) large_record_err: Shared<Option<Failure>>,

    pub(crate) expire_reqs: Shared<Vec<ExpireStagingRequest>>,
    pub(crate) expired: Shared<Vec<ArtifactId>>,
    pub(crate) expire_err: Shared<Option<Failure>>,

    pub(crate) released_large: Shared<Vec<ArtifactId>>,
    pub(crate) release_err: Shared<Option<Failure>>,

    /// Rejected-staging rows, self-draining like the adapter's scan:
    /// `clear_staging_key` removes them permanently.
    pub(crate) rejected_staging: Shared<Vec<RejectedStagingClaim>>,
    pub(crate) rejected_scan_err: Shared<Option<Failure>>,
    pub(crate) rejected_scan_calls: Shared<usize>,
    pub(crate) cleared_staging: Shared<Vec<ArtifactId>>,
    pub(crate) clear_err: Shared<Option<Failure>>,

    /// The database-derived instant reported for each claimed batch.
    pub(crate) observed_at: OffsetDateTime,

    /// The durable age the store itself measures for each Artifact —
    /// the adapter's database-derived comparison.
    pub(crate) age: Shared<HashMap<ArtifactId, Duration>>,
    pub(crate) stale_claim: Shared<HashSet<ArtifactId>>,
}

impl FakeReconciliationStore {
    pub(crate) fn new(journal: Journal, observed_at: OffsetDateTime) -> Self {
        Self {
            journal,
            incomplete: shared(VecDeque::new()),
            incomplete_err: shared(None),
            claim_reqs: shared(Vec::new()),
            large: shared(None),
            large_err: shared(None),
            large_calls: shared(0),
            progress: shared(Vec::new()),
            progress_err: shared(None),
            large_claim_reqs: shared(Vec::new()),
            large_recorded: shared(Vec::new()),
            large_record_err: shared(None),
            expire_reqs: shared(Vec::new()),
            expired: shared(Vec::new()),
            expire_err: shared(None),
            released_large: shared(Vec::new()),
            release_err: shared(None),
            rejected_staging: shared(Vec::new()),
            rejected_scan_err: shared(None),
            rejected_scan_calls: shared(0),
            cleared_staging: shared(Vec::new()),
            clear_err: shared(None),
            observed_at,
            age: shared(HashMap::new()),
            stale_claim: shared(HashSet::new()),
        }
    }
}

impl ReconciliationStore for FakeReconciliationStore {
    async fn claim_incomplete(
        &self,
        request: ClaimIncompleteRequest,
    ) -> Result<ClaimIncompleteResult, Failure> {
        self.journal.record("claim.Incomplete");
        self.claim_reqs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.clone());
        if let Some(failure) = self
            .incomplete_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        let mut out = self
            .incomplete
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
            .unwrap_or_else(|| ClaimIncompleteResult {
                claims: Vec::new(),
                next_cursor: request.cursor,
                observed_at: OffsetDateTime::UNIX_EPOCH,
                skipped_workspaces: 0,
                skip_budget_exhausted: false,
            });
        if out.observed_at == OffsetDateTime::UNIX_EPOCH && !out.claims.is_empty() {
            out.observed_at = self.observed_at;
        }
        Ok(out)
    }

    async fn claim_large(
        &self,
        _request: ClaimLargeRequest,
    ) -> Result<Option<LargeClaim>, Failure> {
        self.journal.record("claim.Large");
        *self.large_calls.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        if let Some(failure) = self
            .large_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        Ok(*self.large.lock().unwrap_or_else(|e| e.into_inner()))
    }

    async fn record_progress(&self, progress: ReconciliationProgress) -> Result<(), Failure> {
        self.journal.record("claim.Progress");
        self.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(progress);
        if let Some(failure) = self
            .progress_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        Ok(())
    }

    async fn record_large_claim(&self, request: RecordLargeClaimRequest) -> Result<(), Failure> {
        self.journal.record("claim.RecordLargeClaim");
        self.large_claim_reqs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.clone());
        if let Some(failure) = self
            .large_record_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        if self
            .stale_claim
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&request.artifact_id)
        {
            return Ok(());
        }
        self.large_recorded
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.artifact_id);
        Ok(())
    }

    /// The adapter's database-side age comparison: the store, not the
    /// caller, decides whether the record has outlived `lifetime`.
    async fn expire_staging(
        &self,
        request: ExpireStagingRequest,
    ) -> Result<ExpireStagingResult, Failure> {
        self.journal.record("claim.ExpireStaging");
        self.expire_reqs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.clone());
        if let Some(failure) = self
            .expire_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        if self
            .stale_claim
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&request.artifact_id)
        {
            return Ok(ExpireStagingResult {
                expired: false,
                // The non-mutating case carries no meaningful outcome —
                // upstream's `ExpireStagingResult{}` zero value.
                outcome: Outcome {
                    kind: OutcomeKind::Retryable,
                    failure_code: String::new(),
                },
            });
        }
        let ages = self.age.lock().unwrap_or_else(|e| e.into_inner());
        let Some(age) = ages.get(&request.artifact_id).copied() else {
            return Ok(ExpireStagingResult {
                expired: false,
                outcome: Outcome {
                    kind: OutcomeKind::Retryable,
                    failure_code: String::new(),
                },
            });
        };
        if age < request.lifetime {
            return Ok(ExpireStagingResult {
                expired: false,
                outcome: Outcome {
                    kind: OutcomeKind::Retryable,
                    failure_code: String::new(),
                },
            });
        }
        drop(ages);
        self.expired
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.artifact_id);
        Ok(ExpireStagingResult {
            expired: true,
            outcome: Outcome {
                kind: OutcomeKind::Retryable,
                failure_code: FAILURE_CODE_STAGING_EXPIRED.to_owned(),
            },
        })
    }

    async fn release_large_claim(&self, request: ReleaseLargeClaimRequest) -> Result<(), Failure> {
        self.journal.record("claim.ReleaseLargeClaim");
        if let Some(failure) = self
            .release_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        self.released_large
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.artifact_id);
        // A released claim is gone: a later claim_large in the same
        // fixture must not find it again, exactly as the adapter's
        // DELETE guarantees.
        let mut large = self.large.lock().unwrap_or_else(|e| e.into_inner());
        if large.is_some_and(|claim| claim.artifact_id == request.artifact_id) {
            *large = None;
        }
        Ok(())
    }

    async fn claim_rejected_staging(
        &self,
        request: ClaimRejectedStagingRequest,
    ) -> Result<ClaimRejectedStagingResult, Failure> {
        self.journal.record("claim.RejectedStaging");
        *self
            .rejected_scan_calls
            .lock()
            .unwrap_or_else(|e| e.into_inner()) += 1;
        if let Some(failure) = self
            .rejected_scan_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        let claims = self
            .rejected_staging
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The adapter hands back rows, not a live view of its own scan:
        // ClearStagingKey compacts the backing list in place, so the
        // caller gets a copy.
        let out: Vec<RejectedStagingClaim> =
            claims.iter().take(request.batch_size).cloned().collect();
        Ok(ClaimRejectedStagingResult { claims: out })
    }

    async fn clear_staging_key(&self, request: ClearStagingKeyRequest) -> Result<(), Failure> {
        self.journal.record("claim.ClearStagingKey");
        if let Some(failure) = self
            .clear_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        self.cleared_staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.artifact_id);
        self.rejected_staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|claim| claim.artifact_id != request.artifact_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FakeLineageStore — upstream `fakeLineageStore`: produce inserts dedupe
// on ArtifactId, read inserts dedupe on (run, reader, attempt, artifact)
// with the operator NULL pair never deduping — the b34 append-only
// contract.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FakeLineageStore {
    pub(crate) produces: Shared<Vec<ProduceEdge>>,
    pub(crate) reads: Shared<Vec<ReadEdge>>,
    pub(crate) declared_by_node: Shared<HashMap<WorkflowNodeId, Vec<ArtifactId>>>,
    pub(crate) artifacts_by_id: Shared<HashMap<ArtifactId, LineageArtifact>>,
    /// What `resolve_produced` returns regardless of node key/name —
    /// upstream's fake ignores the selector too.
    pub(crate) resolved_produced: Shared<Vec<LineageArtifact>>,
    pub(crate) insert_produce_err: Shared<Option<Failure>>,
    pub(crate) insert_read_err: Shared<Option<Failure>>,
}

impl FakeLineageStore {
    pub(crate) fn new() -> Self {
        Self {
            produces: shared(Vec::new()),
            reads: shared(Vec::new()),
            declared_by_node: shared(HashMap::new()),
            artifacts_by_id: shared(HashMap::new()),
            resolved_produced: shared(Vec::new()),
            insert_produce_err: shared(None),
            insert_read_err: shared(None),
        }
    }
}

impl ProduceEdgeStore for FakeLineageStore {
    async fn insert_produce_edge(&self, edge: ProduceEdge) -> Result<ProduceEdge, Failure> {
        if let Some(failure) = self
            .insert_produce_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        let mut produces = self.produces.lock().unwrap_or_else(|e| e.into_inner());
        // unique(artifact_id): idempotent replay returns the journaled
        // edge.
        if let Some(existing) = produces.iter().find(|e| e.artifact_id == edge.artifact_id) {
            return Ok(*existing);
        }
        produces.push(edge);
        Ok(edge)
    }
}

impl ReadEdgeStore for FakeLineageStore {
    async fn insert_read_edge(&self, edge: ReadEdge) -> Result<ReadEdge, Failure> {
        if let Some(failure) = self
            .insert_read_err
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(failure);
        }
        let mut reads = self.reads.lock().unwrap_or_else(|e| e.into_inner());
        // Attempt-scoped dedupe: never double-count a retry after an
        // ambiguous outcome. The operator NULL pair is never equal under
        // UNIQUE — every operator read journals a distinct event.
        if edge.reader_node_id.is_some()
            && let Some(existing) = reads.iter().find(|e| {
                e.reader_node_id.is_some()
                    && e.run_id == edge.run_id
                    && e.reader_node_id == edge.reader_node_id
                    && e.attempt_id == edge.attempt_id
                    && e.artifact_id == edge.artifact_id
            })
        {
            return Ok(existing.clone());
        }
        reads.push(edge.clone());
        Ok(edge)
    }
}

impl LineageReader for FakeLineageStore {
    async fn produce_edge_for_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<ProduceEdge>, Failure> {
        Ok(self
            .produces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|e| e.artifact_id == artifact_id)
            .copied())
    }

    async fn read_edges_for_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Vec<ReadEdge>, Failure> {
        Ok(self
            .reads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.artifact_id == artifact_id)
            .cloned()
            .collect())
    }

    async fn read_edges_for_node(&self, node_id: WorkflowNodeId) -> Result<Vec<ReadEdge>, Failure> {
        Ok(self
            .reads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.reader_node_id == Some(node_id))
            .cloned()
            .collect())
    }

    async fn produce_edges_for_node(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<ProduceEdge>, Failure> {
        Ok(self
            .produces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.node_id == node_id)
            .copied()
            .collect())
    }

    async fn produce_edges_for_run(&self, run_id: RunId) -> Result<Vec<ProduceEdge>, Failure> {
        Ok(self
            .produces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.run_id == run_id)
            .copied()
            .collect())
    }

    async fn read_edges_for_run(&self, run_id: RunId) -> Result<Vec<ReadEdge>, Failure> {
        Ok(self
            .reads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.run_id == run_id)
            .cloned()
            .collect())
    }
}

impl ReadStore for FakeLineageStore {
    async fn find_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<LineageArtifact>, Failure> {
        Ok(self
            .artifacts_by_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&artifact_id)
            .cloned())
    }

    async fn resolve_produced(
        &self,
        _run_id: Option<RunId>,
        _node_key: &str,
        _name: &str,
    ) -> Result<Vec<LineageArtifact>, Failure> {
        Ok(self
            .resolved_produced
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    async fn declared_scope(&self, node_id: WorkflowNodeId) -> Result<Vec<ArtifactId>, Failure> {
        Ok(self
            .declared_by_node
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&node_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn run_produced_artifacts(&self, run_id: RunId) -> Result<Vec<ArtifactId>, Failure> {
        Ok(self
            .produces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|e| e.run_id == run_id)
            .map(|e| e.artifact_id)
            .collect())
    }
}
