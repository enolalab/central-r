//! The B10 Artifact lifecycle application services — the port of
//! `central/internal/artifact/app/service.go` plus the store-consuming
//! lineage operations of `internal/artifact/lineage.go`.
//!
//! It owns no persistence, object-storage, or classification
//! implementation: every dependency arrives as one of the adapter-neutral
//! traits in [`crate::port`], and every state decision is delegated to the
//! pure functions in [`crate::domain`]. This module therefore imports
//! neither `sqlx` nor `aws-sdk-s3`, and never a concrete adapter.
//!
//! The use cases living here:
//!
//! - [`Service::materialize_required_report`] is the single entry point
//!   B09's coordinator calls after it has durably recorded a valid final
//!   report as execution evidence. It reserves, stages, verifies,
//!   promotes, re-verifies, and finalizes the required-report Artifact,
//!   returning one classified [`Outcome`] for B08.
//! - [`Service::resume_verifying`] is the non-interactive crash-recovery
//!   half of the same command sequence, driven by the reconciler.
//! - [`Service::deliver_ready_artifact`] and
//!   [`Service::prepare_authorized_download`] implement the delivery
//!   guards and the opaque one-shot download capability of
//!   `rust-application-boundaries.md` §2.4/§3.4.
//! - [`Service::delete_artifact_two_phase`] drives the two-phase
//!   workspace-scoped deletion (`docs/artifacts/lifecycle.md` §Delete
//!   intent and tombstone).
//! - The `record_produce`/`record_read`/`produced`/`read_by`/`ancestors`/
//!   `descendants`/`run_lineage_for_run`/`authorize_read` free functions
//!   are the async, store-consuming halves of the b34 lineage model.

use std::collections::{HashSet, VecDeque};
use std::fmt;

use central_execution::domain::ExecutionChangeSet;
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ArtifactId, ArtifactTombstoneId, ContentGeneration, ProduceEdgeId, ReadEdgeId, RunId,
    StagingGeneration, StepAttemptId, StepId, TaskId, ToolCallAttemptId, WorkflowNodeId,
    WorkspaceId,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::domain::{
    self, Artifact, ArtifactTombstone, BeginUploadInput, CommandIdentity, CompleteDeletionInput,
    Disposition, FAILURE_CODE_CHECKSUM_INVALID, FAILURE_CODE_SIZE_LIMIT_EXCEEDED,
    FAILURE_CODE_UPLOAD_NON_DELIVERY, FinalizeInput, Limits, MarkDeletePendingInput, Outcome,
    OutcomeKind, PromotionInput, RejectInput, ReserveInput, State, VerifiedInput, begin_upload,
    complete_deletion, evaluate_delivery_policy, finalize, mark_delete_pending, promotion, reject,
    reserve, verified,
};
use crate::lineage::{
    FinalizeAttemptInput, LineageArtifact, ProduceEdge, REASON_ARTIFACT_NOT_FINALIZED,
    REASON_ARTIFACT_READ_UNRESOLVED, REASON_ARTIFACT_SCOPE_DENIED,
    REASON_LINEAGE_ARTIFACT_REQUIRED, REASON_LINEAGE_NODE_REQUIRED, REASON_LINEAGE_RUN_REQUIRED,
    REASON_LINEAGE_STORE_UNAVAILABLE, ReadAuthorization, ReadEdge, ReadRequest, ReadScope,
    ReadSelector, RunLineage,
};
use crate::port::{
    ArtifactChangeSet, ArtifactCommandReceipt, AttemptFinalizationStore, ByteStream, Classifier,
    ClassifyRequest, ClassifyResult, CompletionContributor, LineageReader, ObjectInfo, ObjectRef,
    ObjectStore, ProduceEdgeStore, ReadEdgeStore, ReadStore, Store, TRANSFER_COPY_BUFFER_BYTES,
    TwoPhaseDeleteStore, UploadRequest,
};

// ---------------------------------------------------------------------------
// Object-store failure classification
// ---------------------------------------------------------------------------

/// The closed failure taxonomy the object-store adapter reports (upstream
/// `ObjectFailureClass`). It is redeclared here rather than imported because
/// this capability must depend on `central-adapter-s3` only through
/// [`ObjectStore`]: the composition root is the sole layer permitted to
/// know the concrete adapter type, so it supplies the mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFailureClass {
    /// The unknown class (upstream `ObjectFailureUnknown`). It is
    /// deliberately treated exactly like [`Self::Ambiguous`]: an
    /// unclassified object-store error is never assumed safe to retry.
    Unknown,
    /// A caller-side contract violation detected before any request
    /// reached the object store.
    Invalid,
    /// Known non-delivery: the object is absent.
    NotFound,
    /// Known non-delivery: a create-only precondition lost to an existing
    /// object, which is authoritative.
    Conflict,
    /// Known non-delivery: the runtime principal may not perform this
    /// operation.
    Denied,
    /// Known non-delivery: the body exceeded its declared ceiling and was
    /// never committed.
    LimitExceeded,
    /// Known non-delivery: the store rejected the request before
    /// accepting a body.
    Unavailable,
    /// The transfer's fate is unknown, so the caller must reconcile
    /// rather than blindly retry.
    Ambiguous,
}

/// Maps an object-store adapter error to the closed class the service
/// branches on (upstream `ObjectFailureClassifier`). A classifier that
/// returns [`ObjectFailureClass::Unknown`] fails safe to ambiguity.
pub trait ObjectFailureClassifier: Send + Sync + 'static {
    /// Classifies one adapter-sanitized [`Failure`]. A synchronous, pure
    /// mapping — never a store call.
    fn classify_object_failure(&self, failure: &Failure) -> ObjectFailureClass;
}

impl<F> ObjectFailureClassifier for F
where
    F: Fn(&Failure) -> ObjectFailureClass + Send + Sync + 'static,
{
    fn classify_object_failure(&self, failure: &Failure) -> ObjectFailureClass {
        self(failure)
    }
}

/// The conservative default classifier (upstream's nil `ObjectFailures`):
/// every object-store error is ambiguous, so nothing is ever assumed safe
/// to retry.
#[derive(Debug, Default, Clone, Copy)]
pub struct AmbiguousObjectFailures;

impl ObjectFailureClassifier for AmbiguousObjectFailures {
    fn classify_object_failure(&self, _failure: &Failure) -> ObjectFailureClass {
        ObjectFailureClass::Ambiguous
    }
}

/// Resolves an object-store error to a class, defaulting to ambiguity
/// (upstream `classifyObject`). Cancellation and deadline expiry are
/// equally ambiguous: the request may already have been accepted.
fn classify_object<F: ObjectFailureClassifier>(
    classifier: &F,
    failure: &Failure,
) -> ObjectFailureClass {
    match classifier.classify_object_failure(failure) {
        ObjectFailureClass::Unknown => ObjectFailureClass::Ambiguous,
        class => class,
    }
}

/// Maps a classified object-store failure to the [`Outcome`] B08 consumes
/// (upstream `outcomeForObjectFailure`).
///
/// Known non-delivery (the write certainly did not land) is retryable only
/// through a fresh reservation and staging generation. Limit and contract
/// violations are terminal. Everything else — including every unclassified
/// error — is ambiguous and belongs to reconciliation, never a blind
/// retry.
fn outcome_for_object_failure(class: ObjectFailureClass) -> Outcome {
    match class {
        ObjectFailureClass::LimitExceeded => Outcome {
            kind: OutcomeKind::Terminal,
            failure_code: FAILURE_CODE_SIZE_LIMIT_EXCEEDED.to_owned(),
        },
        ObjectFailureClass::Invalid => Outcome {
            kind: OutcomeKind::Terminal,
            failure_code: FAILURE_CODE_OBJECT_CONTRACT_VIOLATION.to_owned(),
        },
        ObjectFailureClass::NotFound
        | ObjectFailureClass::Conflict
        | ObjectFailureClass::Denied
        | ObjectFailureClass::Unavailable => Outcome {
            kind: OutcomeKind::Retryable,
            failure_code: FAILURE_CODE_OBJECT_NON_DELIVERY.to_owned(),
        },
        _ => Outcome {
            kind: OutcomeKind::Reconciliation,
            failure_code: FAILURE_CODE_OBJECT_AMBIGUOUS.to_owned(),
        },
    }
}

/// Whether a classified object-store failure proves the write did not land
/// (upstream `isKnownNonDelivery`). Only these classes justify an
/// immediate durable rejection: an ambiguous result may still have landed,
/// so it belongs to reconciliation rather than to a transition that frees
/// capacity now.
fn is_known_non_delivery(class: ObjectFailureClass) -> bool {
    matches!(
        class,
        ObjectFailureClass::NotFound
            | ObjectFailureClass::Conflict
            | ObjectFailureClass::Denied
            | ObjectFailureClass::Unavailable
    )
}

/// Closed, safe failure codes this service adds to the ones
/// [`crate::domain`] already defines (upstream's `failureCode*`
/// constants). None can carry a body byte, name, locator, or secret.
const FAILURE_CODE_OBJECT_CONTRACT_VIOLATION: &str = "OBJECT_CONTRACT_VIOLATION";
const FAILURE_CODE_OBJECT_NON_DELIVERY: &str = "OBJECT_NON_DELIVERY";
const FAILURE_CODE_OBJECT_AMBIGUOUS: &str = "OBJECT_RESULT_AMBIGUOUS";
/// The promoted object's version evidence changed between promotion and
/// the second verification: the object under the ready key is not the one
/// that was promoted.
const FAILURE_CODE_READY_OBJECT_VERSION_MISMATCH: &str = "READY_OBJECT_VERSION_MISMATCH";

/// The closed denial a refused download reports. Delivery denials are
/// deliberately indistinguishable — cross-workspace, non-ready,
/// delete-intent, and oversized all fail the same way from the outside,
/// and the capability surfaces one closed code rather than a different
/// machine answer per guard.
const CODE_ARTIFACT_DOWNLOAD_DENIED: &str = "ARTIFACT_DOWNLOAD_DENIED";

fn download_denied() -> Failure {
    Failure::denied(
        CODE_ARTIFACT_DOWNLOAD_DENIED,
        "the artifact download was refused",
    )
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Materializes required-report Artifacts (upstream `Service`). It holds
/// no mutable state: one call owns exactly one Artifact's lifecycle from
/// reservation to a classified outcome.
///
/// Type parameters are the adapter-neutral ports: `S` the durable
/// [`Store`] (plus [`TwoPhaseDeleteStore`] for the deletion operation),
/// `O` the [`ObjectStore`], `C` the [`Classifier`], `P` the
/// [`CompletionContributor`], and `F` the [`ObjectFailureClassifier`]
/// (defaulting to [`AmbiguousObjectFailures`] — the same conservative
/// default upstream's nil `ObjectFailures` installs).
pub struct Service<S, O, C, P, F = AmbiguousObjectFailures> {
    store: S,
    objects: O,
    classifier: C,
    completion: P,
    failures: F,

    new_artifact_id: fn() -> ArtifactId,
    new_staging: fn() -> StagingGeneration,
    new_content: fn() -> ContentGeneration,
}

impl<S, O, C, P> Service<S, O, C, P> {
    /// Constructs the service over its four required ports (upstream
    /// `NewService`). The nil-check upstream performs is a compile-time
    /// property here: generic arguments cannot be absent.
    pub fn new(store: S, objects: O, classifier: C, completion: P) -> Self {
        Self {
            store,
            objects,
            classifier,
            completion,
            failures: AmbiguousObjectFailures,
            new_artifact_id: ArtifactId::new,
            new_staging: StagingGeneration::new,
            new_content: ContentGeneration::new,
        }
    }

    /// Installs a concrete object-failure classifier — the composition
    /// root's adapter-error mapping (upstream `ServiceConfig.ObjectFailures`).
    pub fn with_failure_classifier<F>(self, failures: F) -> Service<S, O, C, P, F>
    where
        F: ObjectFailureClassifier,
    {
        Service {
            store: self.store,
            objects: self.objects,
            classifier: self.classifier,
            completion: self.completion,
            failures,
            new_artifact_id: self.new_artifact_id,
            new_staging: self.new_staging,
            new_content: self.new_content,
        }
    }
}

impl<S, O, C, P, F> Service<S, O, C, P, F> {
    /// Pins the opaque identity generators — the test hooks upstream's
    /// `ServiceConfig` carries so a scenario can pin what a real run mints
    /// randomly.
    #[must_use]
    pub fn with_generators(
        mut self,
        artifact_id: fn() -> ArtifactId,
        staging: fn() -> StagingGeneration,
        content: fn() -> ContentGeneration,
    ) -> Self {
        self.new_artifact_id = artifact_id;
        self.new_staging = staging;
        self.new_content = content;
        self
    }
}

impl<S, O, C, P, F> Service<S, O, C, P, F>
where
    S: Store,
    O: ObjectStore,
    C: Classifier,
    P: CompletionContributor,
    F: ObjectFailureClassifier,
{
    /// Resolves an object-store error to a class through the installed
    /// classifier, defaulting to ambiguity.
    fn classify_object(&self, failure: &Failure) -> ObjectFailureClass {
        classify_object(&self.failures, failure)
    }

    /// Applies the immediate durable rejection for a cause known before
    /// verification, releasing the reservation exactly once, and returns
    /// the durable [`Outcome`] (upstream `rejectStaged`). The store
    /// reports an exact replay rather than a second transition, so
    /// capacity can never be released twice.
    async fn reject_staged(
        &self,
        current: &Artifact,
        reason: &'static str,
    ) -> Result<Outcome, Failure> {
        let rejected = reject(&RejectInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            reason,
        })?;
        let stored = self.store.record_rejection(rejected).await?;
        Ok(stored.outcome)
    }

    /// Reads the staged object back in full under one transfer permit,
    /// bounded to the installed limit plus one byte so an over-limit body
    /// is detected rather than buffered without bound, and classifies it
    /// (upstream `verifyStagedBody`).
    ///
    /// A [`StagedVerification::Outcome`] is terminal, rejected, or
    /// ambiguous and ends the pass.
    async fn verify_staged_body(
        &self,
        current: &Artifact,
        declared_media_type: &str,
    ) -> Result<StagedVerification, Failure> {
        let mut reader = match self
            .objects
            .read(ObjectRef {
                key: current.staging_key.clone(),
            })
            .await
        {
            Ok((reader, _info)) => reader,
            Err(failure) => {
                return Ok(StagedVerification::Outcome(outcome_for_object_failure(
                    self.classify_object(&failure),
                )));
            }
        };

        // The required-report class caps at 10 MiB, so buffering limit+1
        // bytes is bounded by policy and lets the hash and the classifier
        // both see exactly the bytes that landed.
        let cap = usize::try_from(current.limits.max_bytes.max(0))
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        let mut body = Vec::new();
        let read = read_bounded(reader.as_mut(), cap, &mut body).await;
        let _ = reader.close().await;
        if let Err(failure) = read {
            return Ok(StagedVerification::Outcome(outcome_for_object_failure(
                self.classify_object(&failure),
            )));
        }
        if body.len() as i64 > current.limits.max_bytes {
            // A stream-cap breach is a named must-reject failure class:
            // reject durably now so the reservation is released exactly
            // once here rather than being held until the staging-lifetime
            // sweep 24 hours later.
            let outcome = self
                .reject_staged(current, FAILURE_CODE_SIZE_LIMIT_EXCEEDED)
                .await?;
            return Ok(StagedVerification::Outcome(outcome));
        }

        let size = body.len() as i64;
        let checksum: [u8; 32] = Sha256::digest(&body).into();
        let class = self
            .classifier
            .classify(ClassifyRequest {
                declared_media_type: declared_media_type.to_owned(),
                size,
                body: Box::new(std::io::Cursor::new(body)),
            })
            .await?;
        Ok(StagedVerification::Classified {
            size,
            checksum,
            class,
        })
    }

    /// Re-reads the promoted object and requires the exact size and
    /// checksum already approved, plus — when both are available — the
    /// same object version the promotion observed (upstream
    /// `verifyReadyObject`). A mismatch is an integrity failure and is
    /// terminal; it never completes and never overwrites the ready key.
    ///
    /// `bytes_moved` is the number of ready-object bytes this call
    /// actually moved — what the reconciliation pass charges against its
    /// byte budget: a read that never got a body back moved nothing and
    /// must not be billed as though it had transferred the Artifact's
    /// whole declared ceiling.
    async fn verify_ready_object(&self, current: &Artifact, expected_version: &str) -> ReadyCheck {
        let (mut reader, info) = match self
            .objects
            .read(ObjectRef {
                key: current.ready_key.clone(),
            })
            .await
        {
            Ok(opened) => opened,
            Err(failure) => {
                return ReadyCheck {
                    ready_version: String::new(),
                    bytes_moved: 0,
                    outcome: Some(outcome_for_object_failure(self.classify_object(&failure))),
                };
            }
        };

        if info.size != current.verified_size {
            let _ = reader.close().await;
            return ReadyCheck {
                ready_version: String::new(),
                bytes_moved: 0,
                outcome: Some(Outcome {
                    kind: OutcomeKind::Terminal,
                    failure_code: FAILURE_CODE_CHECKSUM_INVALID.to_owned(),
                }),
            };
        }
        // "Where supported": the version check runs only when both the
        // promotion and this read produced evidence. An object store that
        // exposes none is still fully verified by size and checksum.
        let observed = object_version(&info);
        if !expected_version.is_empty() && !observed.is_empty() && expected_version != observed {
            let _ = reader.close().await;
            return ReadyCheck {
                ready_version: String::new(),
                bytes_moved: 0,
                outcome: Some(Outcome {
                    kind: OutcomeKind::Terminal,
                    failure_code: FAILURE_CODE_READY_OBJECT_VERSION_MISMATCH.to_owned(),
                }),
            };
        }
        let mut hasher = Sha256::new();
        let cap = u64::try_from(current.verified_size.max(0))
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let (copied, failure) = hash_bounded(reader.as_mut(), cap, &mut hasher).await;
        let _ = reader.close().await;
        let bytes_moved = copied as i64;
        if let Some(failure) = failure {
            return ReadyCheck {
                ready_version: String::new(),
                bytes_moved,
                outcome: Some(outcome_for_object_failure(self.classify_object(&failure))),
            };
        }
        if copied as i64 != current.verified_size {
            return ReadyCheck {
                ready_version: String::new(),
                bytes_moved,
                outcome: Some(Outcome {
                    kind: OutcomeKind::Terminal,
                    failure_code: FAILURE_CODE_CHECKSUM_INVALID.to_owned(),
                }),
            };
        }
        let got: [u8; 32] = hasher.finalize().into();
        if got != current.verified_checksum {
            return ReadyCheck {
                ready_version: String::new(),
                bytes_moved,
                outcome: Some(Outcome {
                    kind: OutcomeKind::Terminal,
                    failure_code: FAILURE_CODE_CHECKSUM_INVALID.to_owned(),
                }),
            };
        }
        ReadyCheck {
            ready_version: observed,
            bytes_moved,
            outcome: None,
        }
    }
}

/// One `verify_staged_body` result (upstream's `(body, class, outcome,
/// error)` quadruple folded into the two shapes a caller can act on).
enum StagedVerification {
    /// The staged body was read and classified; the verify transition may
    /// consume the recomputed evidence.
    Classified {
        /// Recomputed full-body size.
        size: i64,
        /// Recomputed full-body SHA-256.
        checksum: [u8; 32],
        /// The classifier's sanitized policy decision.
        class: ClassifyResult,
    },
    /// A terminal, rejected, or ambiguous outcome that ends the pass.
    Outcome(Outcome),
}

/// One `verify_ready_object` result (upstream's `(readyVersion,
/// bytesMoved, outcome)` triple).
struct ReadyCheck {
    /// The object-version evidence the read exposed (empty when the store
    /// exposes none).
    ready_version: String,
    /// The ready-object bytes this call actually moved.
    bytes_moved: i64,
    /// `Some` when the second verification produced a terminal or
    /// ambiguous outcome.
    outcome: Option<Outcome>,
}

/// Returns the object-version evidence an [`ObjectInfo`] carries,
/// preferring an explicit version and falling back to an ETag (upstream
/// `objectVersion`). Both empty means the object store exposes no version
/// evidence at all — a supported configuration: binding and revalidating
/// it is conditional on support.
fn object_version(info: &ObjectInfo) -> String {
    if !info.version.is_empty() {
        return info.version.clone();
    }
    info.etag.clone()
}

/// Reads up to `cap` bytes from `stream` into `out` — the bounded
/// `io.ReadAll(io.LimitReader(...))` equivalent. `Ok(0)` from
/// [`ByteStream::read_chunk`] is the end-of-stream signal.
async fn read_bounded(
    stream: &mut dyn ByteStream,
    cap: usize,
    out: &mut Vec<u8>,
) -> Result<usize, Failure> {
    let mut buf = vec![0u8; cap.clamp(1, TRANSFER_COPY_BUFFER_BYTES)];
    loop {
        let remaining = cap.saturating_sub(out.len());
        if remaining == 0 {
            break;
        }
        let want = remaining.min(buf.len());
        match stream.read_chunk(&mut buf[..want]).await {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(failure) => return Err(failure),
        }
    }
    Ok(out.len())
}

/// Streams up to `cap` bytes through `hasher`, returning the bytes copied
/// so far even on a mid-stream failure — upstream `io.Copy`'s
/// partial-count semantics, which the budget charge depends on.
async fn hash_bounded(
    stream: &mut dyn ByteStream,
    cap: u64,
    hasher: &mut Sha256,
) -> (u64, Option<Failure>) {
    let mut copied = 0u64;
    let mut buf = vec![0u8; (cap.max(1) as usize).min(TRANSFER_COPY_BUFFER_BYTES)];
    loop {
        let remaining = cap - copied;
        if remaining == 0 {
            break;
        }
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        match stream.read_chunk(&mut buf[..want]).await {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                copied += n as u64;
            }
            Err(failure) => return (copied, Some(failure)),
        }
    }
    (copied, None)
}

/// B09's handoff (upstream `MaterializeRequest`). `body` is the bounded
/// reader over the already-recorded final response; the trusted
/// Workspace/Task/Run/Step/StepAttempt/producer chain comes from B08's
/// coordinator, never from model output.
pub struct MaterializeRequest {
    /// Owning workspace.
    pub workspace_id: WorkspaceId,
    /// Producer chain: task.
    pub task_id: TaskId,
    /// Producer chain: run.
    pub run_id: RunId,
    /// Producer chain: step.
    pub step_id: StepId,
    /// Producer chain: step attempt.
    pub step_attempt_id: StepAttemptId,
    /// Optional tool-call attempt (`None` = no associated Tool call).
    pub tool_call_attempt_id: Option<ToolCallAttemptId>,
    /// Producer identity.
    pub producer_id: String,
    /// Optional required-output role.
    pub required_role: String,
    /// The installed limits snapshot.
    pub limits: Limits,
    /// The producer-declared media type — a hint only.
    pub declared_media_type: String,
    /// The bounded reader over the already-recorded final response.
    /// `Option` encodes upstream's nil-reader check: `None` fails
    /// validation rather than staging an empty body.
    pub body: Option<Box<dyn std::io::Read + Send>>,
    /// The one stable operation identity bound to the B09 final response,
    /// producer chain, and report content hash. It is the reservation
    /// idempotency key and the finalize receipt key, so a resumed handoff
    /// replays rather than creating a second report Artifact.
    pub operation_id: String,
    /// The reservation's own identity. `None` mints a fresh random one —
    /// the correct behaviour for any caller without a stable operation
    /// identity to derive it from. A caller that does have one must
    /// supply it through `domain::derive_reservation_identity`, because
    /// the reservation receipt's fingerprint covers both identities.
    pub artifact_id: Option<ArtifactId>,
    /// The reservation's staging generation (`None` = mint fresh).
    pub staging_generation: Option<StagingGeneration>,
    /// The B08-evaluated execution change set committed atomically with
    /// the ready transition. B10 never authors it.
    pub completion: ExecutionChangeSet,
}

impl MaterializeRequest {
    /// Upstream `MaterializeRequest.validate` — the closed caller-contract
    /// checks that must pass before any port is touched.
    fn validate(&self) -> Result<(), Failure> {
        if self.workspace_id.is_nil()
            || self.task_id.is_nil()
            || self.run_id.is_nil()
            || self.step_id.is_nil()
            || self.step_attempt_id.is_nil()
            || self.producer_id.is_empty()
        {
            return Err(Failure::invalid(
                "ARTIFACT_MATERIALIZE_IDENTITY_INCOMPLETE",
                "materialization requires the complete producer identity chain",
            ));
        }
        if self.body.is_none() {
            return Err(Failure::invalid(
                "ARTIFACT_MATERIALIZE_BODY_REQUIRED",
                "materialization requires a bounded body reader",
            ));
        }
        if self.operation_id.is_empty() {
            return Err(Failure::invalid(
                "ARTIFACT_MATERIALIZE_OPERATION_REQUIRED",
                "materialization requires a stable operation identity",
            ));
        }
        self.limits.validate()?;
        // A caller that pins the reservation identities must pin valid
        // ones — a nil inside `Some` is a corrupted-value edge that fails
        // closed rather than minting over the caller's intent.
        if self.artifact_id.is_some_and(|id| id.is_nil())
            || self
                .staging_generation
                .is_some_and(|generation| generation.is_nil())
        {
            return Err(Failure::invalid(
                "ARTIFACT_MATERIALIZE_IDENTITY_INCOMPLETE",
                "a pinned reservation identity must be non-nil",
            ));
        }
        Ok(())
    }
}

impl<S, O, C, P, F> Service<S, O, C, P, F>
where
    S: Store,
    O: ObjectStore,
    C: Classifier,
    P: CompletionContributor,
    F: ObjectFailureClassifier,
{
    /// Drives one required-report Artifact from reservation to a
    /// classified outcome (upstream `MaterializeRequiredReport`).
    ///
    /// The returned `Err` is reserved for a caller contract violation or
    /// a dependency error the service could not classify; every lifecycle
    /// rejection or ambiguity is reported through the [`Outcome`] with an
    /// `Ok` result, so B08 never has to interpret an error to decide
    /// retryability.
    pub async fn materialize_required_report(
        &self,
        request: MaterializeRequest,
    ) -> Result<Outcome, Failure> {
        request.validate()?;
        let Some(body) = request.body else {
            return Err(Failure::invalid(
                "ARTIFACT_MATERIALIZE_BODY_REQUIRED",
                "materialization requires a bounded body reader",
            ));
        };

        // 1. Reserve. Admission and quota headroom are checked against
        //    the declared maximum body size in one PostgreSQL
        //    transaction.
        //
        //    A caller that pinned the reservation identities keeps them:
        //    they are part of the receipt fingerprint, so re-minting them
        //    here would make every replay of a stable OperationID look
        //    like a different command.
        let artifact_id = request
            .artifact_id
            .unwrap_or_else(|| (self.new_artifact_id)());
        let staging = request
            .staging_generation
            .unwrap_or_else(|| (self.new_staging)());
        let reserved = reserve(&ReserveInput {
            workspace_id: request.workspace_id,
            artifact_id,
            staging_generation: staging,
            limits: request.limits,
            idempotency_key: &request.operation_id,
            task_id: request.task_id,
            run_id: request.run_id,
            step_id: request.step_id,
            step_attempt_id: request.step_attempt_id,
            tool_call_attempt_id: request.tool_call_attempt_id,
            producer_id: &request.producer_id,
            required_role: &request.required_role,
        })?;
        let stored_reserve = self.store.reserve_artifact(reserved).await?;
        let mut current = stored_reserve.artifact;

        // 2. BeginUpload records staging *before* the first body byte
        //    moves, so a crash mid-transfer always leaves a durable
        //    record the reconciler can find. The transfer itself happens
        //    outside any transaction.
        let begun = begin_upload(&BeginUploadInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
        })?;
        let stored_begin = self.store.record_begin_upload(begun).await?;
        current = stored_begin.artifact;

        if let Err(failure) = self
            .objects
            .upload(UploadRequest {
                reference: ObjectRef {
                    key: current.staging_key.clone(),
                },
                body,
                max_bytes: current.limits.max_bytes,
            })
            .await
        {
            let class = self.classify_object(&failure);
            if is_known_non_delivery(class) {
                // Known non-delivery: the body certainly never landed, so
                // there is nothing to reconcile and nothing staged to
                // clean up. Reject now so the reservation is released
                // immediately rather than being held until the
                // reconciler's staging-lifetime sweep. The rejection
                // transition is the single capacity release.
                return self
                    .reject_staged(&current, FAILURE_CODE_UPLOAD_NON_DELIVERY)
                    .await;
            }
            return Ok(outcome_for_object_failure(class));
        }

        // 3. Verify by rereading the full staged body: recompute size and
        //    SHA-256 from the bytes that actually landed, never from the
        //    caller's stream, then classify under the bounded content
        //    policy.
        let (size, checksum, class) = match self
            .verify_staged_body(&current, &request.declared_media_type)
            .await?
        {
            StagedVerification::Classified {
                size,
                checksum,
                class,
            } => (size, checksum, class),
            StagedVerification::Outcome(outcome) => return Ok(outcome),
        };

        // The classifier's policy decision is carried *into* the verify
        // transition rather than evaluated after it. A rejection
        // therefore commits atomically as part of the same transition and
        // never reaches the verifying state, which the reconciler
        // deliberately never revisits.
        let verified = verified(&VerifiedInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size,
            checksum,
            secret_disclosure: class.secret_disclosure,
            rejection_code: &class.rejection_code,
        })?;
        let stored_verify = self.store.record_verification(verified).await?;
        current = stored_verify.artifact;
        if let Some(outcome) = stored_verify.outcome {
            // A rejected body released its reservation exactly once
            // inside the verification transaction. No promotion may
            // follow.
            return Ok(outcome);
        }

        // 4. Promote. The durable promotion record is written first so a
        //    ready object can never exist without durable metadata
        //    describing it.
        let promoted = promotion(&PromotionInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            content_generation: (self.new_content)(),
        })?;
        let stored_promote = self.store.record_promotion(promoted).await?;
        current = stored_promote.artifact;

        let promoted_info = match self
            .objects
            .promote_create_only(
                ObjectRef {
                    key: current.staging_key.clone(),
                },
                ObjectRef {
                    key: current.ready_key.clone(),
                },
            )
            .await
        {
            Ok(info) => info,
            Err(failure) => {
                // A create-only conflict means an object already occupies
                // this generation-unique ready key — necessarily this
                // Artifact's own earlier attempt. The existing object is
                // authoritative, so fall through to the second
                // verification rather than overwriting it.
                if self.classify_object(&failure) != ObjectFailureClass::Conflict {
                    return Ok(outcome_for_object_failure(self.classify_object(&failure)));
                }
                // The conflicting object's own evidence is unknown to
                // this pass, so there is nothing to bind and nothing to
                // revalidate against.
                ObjectInfo {
                    size: 0,
                    etag: String::new(),
                    version: String::new(),
                }
            }
        };

        // 5. Second verification: re-read the ready object and require
        //    exactly the size and checksum already approved, plus — where
        //    the object store exposes it — the same object version the
        //    promotion observed. Only after this may the Artifact
        //    complete anything.
        let check = self
            .verify_ready_object(&current, &object_version(&promoted_info))
            .await;
        if let Some(outcome) = check.outcome {
            return Ok(outcome);
        }
        let ready_version = if check.ready_version.is_empty() {
            // The read exposed no version evidence; fall back to whatever
            // the promotion reported. Both empty simply means this object
            // store does not support object versions, which is explicitly
            // allowed.
            object_version(&promoted_info)
        } else {
            check.ready_version
        };

        let finalized = finalize(&FinalizeInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: current.verified_size,
            checksum: current.verified_checksum,
            ready_object_version: ready_version,
        })?;

        // 6. Finalize atomically with the Task-domain completion
        //    contribution. No object-store call occurs from here on: this
        //    commit's locks are the last thing the pass holds.
        let committed = self
            .completion
            .commit_artifact(
                ArtifactChangeSet {
                    receipt: ArtifactCommandReceipt {
                        idempotency_key: request.operation_id.clone(),
                        identity: finalized.identity.clone(),
                    },
                    finalize: finalized,
                },
                request.completion,
            )
            .await;
        match committed {
            Ok(result) => Ok(result.outcome),
            Err(failure)
                if matches!(
                    failure.kind(),
                    FailureKind::Ambiguous | FailureKind::Cancelled
                ) =>
            {
                // Uncertainty about whether the commit landed is
                // reconciliation work, never a blind retry that could
                // double-complete a Task.
                Ok(Outcome {
                    kind: OutcomeKind::Reconciliation,
                    failure_code: FAILURE_CODE_OBJECT_AMBIGUOUS.to_owned(),
                })
            }
            Err(failure) => Err(failure),
        }
    }

    /// Re-enters the materialization command sequence for an Artifact the
    /// durable record shows reached `verifying`, driving it from wherever
    /// it actually got to (upstream `ResumeVerifying`).
    ///
    /// This is the crash-recovery half of
    /// [`Self::materialize_required_report`]. `record_verification` has
    /// already durably written `verified_size` and `verified_checksum`,
    /// so the resume needs no fresh upload and no fresh verification of
    /// the caller's stream: the durable row carries every fact the
    /// remaining commands consume. Two windows are distinguished by the
    /// row itself:
    ///
    /// - No ready key or content generation: the crash landed between
    ///   Verify and Promote. The resume mints a promotion, records it
    ///   durably first, then creates the ready object create-only —
    ///   exactly the ordering `materialize_required_report` uses.
    /// - A ready key already present: the crash landed between Promote
    ///   and the finalize commit, so the ready object may already exist.
    ///   Nothing is re-uploaded or re-promoted; the object is simply
    ///   re-read and confirmed.
    ///
    /// Either way the second verification is what authorizes
    /// finalization, and it checks the object against the evidence
    /// already durably recorded rather than against anything this pass
    /// computed. A ready object that is absent, unreadable, or disagrees
    /// with that evidence is genuinely ambiguous: the record "records
    /// reconciliation evidence and remains non-ready" — the resume
    /// commits nothing and leaves it for a later pass rather than forcing
    /// a resolution it cannot prove.
    pub async fn resume_verifying(&self, current: Artifact) -> Result<ResumeResult, Failure> {
        if current.state != State::Verifying {
            return Err(Failure::invalid(
                "ARTIFACT_RESUME_REQUIRES_VERIFYING",
                "resume requires a verifying artifact",
            ));
        }
        if current.verified_size <= 0 || current.verified_checksum == [0; 32] {
            // A `verifying` row without the evidence RecordVerification
            // writes is a shape this service never produces. There is
            // nothing to revalidate against, so nothing may be concluded.
            return Ok(ambiguous_resume());
        }

        let mut current = current;
        let mut promoted_info = ObjectInfo {
            size: 0,
            etag: String::new(),
            version: String::new(),
        };
        if current.ready_key.is_empty()
            || current
                .content_generation
                .is_none_or(|generation| generation.is_nil())
        {
            let promoted = promotion(&PromotionInput {
                workspace_id: current.workspace_id,
                artifact_id: current.artifact_id,
                current: current.clone(),
                expected: current.version,
                content_generation: (self.new_content)(),
            })?;
            let stored_promote = self.store.record_promotion(promoted).await?;
            current = stored_promote.artifact;

            match self
                .objects
                .promote_create_only(
                    ObjectRef {
                        key: current.staging_key.clone(),
                    },
                    ObjectRef {
                        key: current.ready_key.clone(),
                    },
                )
                .await
            {
                Ok(info) => promoted_info = info,
                Err(failure) => {
                    // A create-only conflict means an object already
                    // occupies this generation-unique ready key —
                    // necessarily this Artifact's own earlier attempt —
                    // and is authoritative, so fall through to the second
                    // verification instead of overwriting it. Anything
                    // else is not proof of anything and stays in
                    // reconciliation.
                    if self.classify_object(&failure) != ObjectFailureClass::Conflict {
                        return Ok(ambiguous_resume());
                    }
                }
            }
        }

        let check = self
            .verify_ready_object(&current, &object_version(&promoted_info))
            .await;
        if let Some(_outcome) = check.outcome {
            // The ready object could not be confirmed against the durable
            // evidence. The record stays exactly as it is; a later pass
            // re-observes it.
            let mut ambiguous = ambiguous_resume();
            ambiguous.bytes_moved = check.bytes_moved;
            return Ok(ambiguous);
        }
        let ready_version = if check.ready_version.is_empty() {
            object_version(&promoted_info)
        } else {
            check.ready_version
        };

        let finalized = finalize(&FinalizeInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            size: current.verified_size,
            checksum: current.verified_checksum,
            ready_object_version: ready_version,
        })?;

        // The resume contributes no execution change set. It is not
        // B08's coordinator and holds none of the authority-bound
        // evidence a settlement requires, so it makes the Artifact
        // durably ready — releasing its capacity and completing the
        // required output's own half — and leaves B08's recovery to
        // observe it. Synthesizing a Task transition here would be
        // exactly the double-completion this whole lifecycle exists to
        // prevent.
        let committed = self
            .completion
            .commit_artifact(
                ArtifactChangeSet {
                    receipt: ArtifactCommandReceipt {
                        idempotency_key: resume_receipt_key(&finalized.identity),
                        identity: finalized.identity.clone(),
                    },
                    finalize: finalized,
                },
                ExecutionChangeSet::new(),
            )
            .await;
        match committed {
            Ok(result) => Ok(ResumeResult {
                outcome: result.outcome,
                resolved: true,
                bytes_moved: check.bytes_moved,
            }),
            Err(failure)
                if matches!(
                    failure.kind(),
                    FailureKind::Ambiguous | FailureKind::Cancelled
                ) =>
            {
                let mut ambiguous = ambiguous_resume();
                ambiguous.bytes_moved = check.bytes_moved;
                Ok(ambiguous)
            }
            Err(failure) => Err(failure),
        }
    }

    /// Revalidates Workspace ownership, ready state, delete intent, and
    /// the size bound before ever touching the object store — every
    /// guard is re-checked here against a fresh durable read, not trusted
    /// from an earlier read the caller may be holding (upstream
    /// `DeliverReadyArtifact`).
    ///
    /// The returned `Err` is reserved for a caller contract violation or
    /// a dependency error the service could not classify; every guard
    /// denial is reported through [`DeliverArtifactOutcome::Denied`].
    pub async fn deliver_ready_artifact(
        &self,
        request: &DeliverReadyArtifactRequest,
    ) -> Result<DeliverArtifactOutcome, Failure> {
        deliver_ready_artifact(&self.store, &self.objects, request).await
    }

    /// Performs the initial durable authorization/open sequence for one
    /// download and returns the opaque one-shot capability
    /// (`rust-application-boundaries.md` §2.4/§3.4). No object-store call
    /// happens here — the body is opened only when the caller consumes
    /// the capability.
    ///
    /// The capability performs final synchronous revalidation through
    /// [`Self::deliver_ready_artifact`] on [`AuthorizedDownload::start`],
    /// immediately before the transport commits headers and copies the
    /// first byte.
    pub async fn prepare_authorized_download(
        &self,
        request: AuthorizedDownloadRequest,
    ) -> Result<AuthorizedDownload<'_, S, O>, Failure> {
        request.validate()?;
        let deliver = request.deliverable();
        match load_deliverable(&self.store, &deliver).await? {
            Deliverable::Denied(_) => Err(download_denied()),
            Deliverable::Ready(_) => Ok(AuthorizedDownload {
                store: &self.store,
                objects: &self.objects,
                request: deliver,
                requested_disposition: request.requested_disposition,
                detected_media_type: request
                    .detected_media_type
                    .map(|value| crate::classifier::normalize_media_type(&value)),
            }),
        }
    }
}

/// One non-interactive resume attempt's contribution to the
/// reconciliation pass that drove it (upstream `ResumeResult`).
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeResult {
    /// The classified result. A resume that could not prove what happened
    /// reports [`OutcomeKind::Reconciliation`] and changes nothing
    /// durable.
    pub outcome: Outcome,
    /// Reports that the Artifact reached a terminal durable state —
    /// ready — during this attempt, so it leaves the incomplete cursor
    /// for good.
    pub resolved: bool,
    /// The number of object bytes this attempt actually re-read. It is
    /// the honest budget charge: an attempt that read nothing costs the
    /// pass nothing, so a permanently unconfirmable record cannot consume
    /// the pass's whole byte budget tick after tick.
    pub bytes_moved: i64,
}

/// The `verifying`-record resume half of the lifecycle [`Service`]: the
/// one operation a reconciliation pass consumes (upstream's
/// `ReconcilerConfig.Lifecycle *Service` dependency, narrowed so the pass
/// never depends on the interactive entry points).
#[trait_variant::make(Send)]
pub trait ResumeLifecycle: Send + Sync + 'static {
    /// Re-enters the materialization command sequence for one `verifying`
    /// record.
    async fn resume_verifying(&self, current: Artifact) -> Result<ResumeResult, Failure>;
}

impl<S, O, C, P, F> ResumeLifecycle for Service<S, O, C, P, F>
where
    S: Store,
    O: ObjectStore,
    C: Classifier,
    P: CompletionContributor,
    F: ObjectFailureClassifier,
{
    async fn resume_verifying(&self, current: Artifact) -> Result<ResumeResult, Failure> {
        Service::resume_verifying(self, current).await
    }
}

fn ambiguous_resume() -> ResumeResult {
    ResumeResult {
        outcome: Outcome {
            kind: OutcomeKind::Reconciliation,
            failure_code: FAILURE_CODE_OBJECT_AMBIGUOUS.to_owned(),
        },
        resolved: false,
        bytes_moved: 0,
    }
}

/// Derives the finalize receipt key for a reconciler-driven resume
/// (upstream `resumeReceiptKey`).
///
/// A resume has no caller-supplied operation identity: the stable B09
/// identity belongs to the handoff that crashed, and this pass is not
/// that handoff. The [`CommandIdentity`] is however fully self-describing
/// — Workspace, Artifact, expected version, content generation, ready
/// key, and the verified size and checksum — so hashing it yields a key
/// that is identical for every resume attempt against the same durable
/// state and different for any other. Two resume passes therefore replay
/// against one receipt rather than racing to two, and the adapter's own
/// in-transaction state check remains the authority that only one
/// finalization can ever apply.
fn resume_receipt_key(identity: &CommandIdentity) -> String {
    let sum = Sha256::digest(
        [
            "central.b10.reconcile-finalize/v1".to_owned(),
            identity.stage.as_str().to_owned(),
            identity.workspace_id.to_string(),
            identity.artifact_id.to_string(),
            identity.expected_version.to_string(),
            identity.content_generation.map_or_else(
                // A nil `Option` never reaches this key — finalize
                // requires a promotion — but upstream's zero-value
                // ContentGeneration formats as the nil UUID text.
                || "00000000-0000-0000-0000-000000000000".to_owned(),
                |generation| generation.to_string(),
            ),
            identity.ready_key.clone(),
            identity.verified_size.to_string(),
            to_hex(&identity.verified_checksum),
        ]
        .join("\x00"),
    );
    format!("b10-resume-{}", to_hex(&sum))
}

/// Lowercase hex — upstream `hex.EncodeToString`.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Read-only delivery of an already-ready Artifact
// ---------------------------------------------------------------------------

/// One operator/session request to stream a ready Artifact's body
/// (upstream `DeliverReadyArtifactRequest`). `workspace_id` selects the
/// durable row to load; `requesting_session_workspace_id` is the caller's
/// own session Workspace and is revalidated against the loaded row's real
/// `workspace_id` independently of whatever selector the caller
/// supplied — ownership is never trusted from the request alone.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeliverReadyArtifactRequest {
    /// The durable row selector's workspace.
    pub workspace_id: WorkspaceId,
    /// The artifact to deliver.
    pub artifact_id: ArtifactId,
    /// The requesting session's own workspace.
    pub requesting_session_workspace_id: WorkspaceId,
}

impl DeliverReadyArtifactRequest {
    fn validate(&self) -> Result<(), Failure> {
        if self.workspace_id.is_nil()
            || self.artifact_id.is_nil()
            || self.requesting_session_workspace_id.is_nil()
        {
            return Err(Failure::invalid(
                "ARTIFACT_DELIVERY_REQUEST_INCOMPLETE",
                "delivery requires a workspace, artifact, and requesting session",
            ));
        }
        Ok(())
    }
}

/// The result of one delivery attempt (upstream
/// `DeliverArtifactOutcome`). A denied outcome never carries a body:
/// `reason` is intentionally generic — never echoed to an HTTP caller
/// verbatim — so cross-workspace, non-ready, delete-intent, and oversized
/// all fail the same way from the outside.
pub enum DeliverArtifactOutcome {
    /// Every durable guard passed; the body stream is open under one
    /// transfer permit.
    Allowed {
        /// The opened body stream.
        body: Box<dyn ByteStream>,
        /// The object's safe evidence.
        info: ObjectInfo,
        /// The durable snapshot the guards were evaluated against,
        /// boxed so this variant stays pointer-sized next to `Denied`.
        artifact: Box<Artifact>,
    },
    /// A guard denied delivery — `reason` is a closed generic token.
    Denied {
        /// `"not found"` | `"not ready"` | `"delete intent"` |
        /// `"size bound"` | `"unavailable"`.
        reason: &'static str,
    },
}

/// The durable-only half of the delivery decision: the validated snapshot
/// or the closed denial token.
enum Deliverable {
    Ready(Box<Artifact>),
    Denied(&'static str),
}

/// Loads the durable snapshot and applies every guard that must pass
/// before the object store may be touched — the shared front half of
/// `deliver_ready_artifact` and `prepare_authorized_download`.
async fn load_deliverable<S: Store>(
    store: &S,
    request: &DeliverReadyArtifactRequest,
) -> Result<Deliverable, Failure> {
    let current = store
        .load_artifact(request.workspace_id, request.artifact_id)
        .await?;

    // 1. Workspace ownership: the loaded row's real WorkspaceID must
    //    equal the requesting session's own Workspace.
    if current.workspace_id != request.requesting_session_workspace_id {
        return Ok(Deliverable::Denied("not found"));
    }
    // 2. Must be durably ready.
    if current.state != State::Ready {
        return Ok(Deliverable::Denied("not ready"));
    }
    // 3. No delete intent.
    if current.delete_intent_at.is_some() {
        return Ok(Deliverable::Denied("delete intent"));
    }
    // 4. Size bound.
    if current.verified_size > current.limits.max_bytes {
        return Ok(Deliverable::Denied("size bound"));
    }
    Ok(Deliverable::Ready(Box::new(current)))
}

/// The free-function delivery core [`Service::deliver_ready_artifact`]
/// delegates to and [`AuthorizedDownload::start`] revalidates through —
/// kept store/object-generic so the one-shot capability needs no access
/// to the rest of the service.
async fn deliver_ready_artifact<S: Store, O: ObjectStore>(
    store: &S,
    objects: &O,
    request: &DeliverReadyArtifactRequest,
) -> Result<DeliverArtifactOutcome, Failure> {
    request.validate()?;
    let current = match load_deliverable(store, request).await? {
        Deliverable::Denied(reason) => return Ok(DeliverArtifactOutcome::Denied { reason }),
        Deliverable::Ready(current) => current,
    };

    // Only now touch the object store.
    match objects
        .read(ObjectRef {
            key: current.ready_key.clone(),
        })
        .await
    {
        Ok((body, info)) => Ok(DeliverArtifactOutcome::Allowed {
            body,
            info,
            artifact: current,
        }),
        // Every classified object-store failure collapses to the same
        // generic denial: a delivery caller gets no more information
        // than "the body could not be produced", regardless of whether
        // the underlying cause was a missing object, a denied read, or
        // an ambiguous result.
        Err(_) => Ok(DeliverArtifactOutcome::Denied {
            reason: "unavailable",
        }),
    }
}

// ---------------------------------------------------------------------------
// The one-shot authorized download (rust-application-boundaries.md §2.4/§3.4)
// ---------------------------------------------------------------------------

/// A `Content-Type` value the delivery policy itself produced — the
/// explicit type the transport must set verbatim. It is constructed only
/// inside this module from [`evaluate_delivery_policy`]'s closed output,
/// so it is never a producer-declared hint and never sniffed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeMediaType(String);

impl SafeMediaType {
    /// The explicit media type string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SafeMediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One download/preivew request the service turns into an opaque
/// one-shot capability (§2.4: the request carries only authenticated
/// Workspace/Artifact identity and transport-independent authority
/// evidence).
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizedDownloadRequest {
    /// The durable row selector's workspace.
    pub workspace_id: WorkspaceId,
    /// The artifact to download.
    pub artifact_id: ArtifactId,
    /// The requesting session's own workspace — revalidated against the
    /// loaded row, never trusted from the selector alone.
    pub requesting_session_workspace_id: WorkspaceId,
    /// The delivery disposition the caller requests
    /// ([`Disposition::Attachment`] for a download,
    /// [`Disposition::Inline`] for a preview). The policy may only ever
    /// downgrade it to attachment.
    pub requested_disposition: Disposition,
    /// The durable detected media-type evidence resolved through the
    /// read projection (`ArtifactSummaryRead.media_type`), normalized for
    /// comparison. `None` — or a non-allowlisted value — yields the
    /// octet-stream fallback. It is durable evidence the caller resolved,
    /// never a producer-declared hint: the delivery policy re-evaluates
    /// it against the preview allowlist regardless.
    pub detected_media_type: Option<String>,
}

impl AuthorizedDownloadRequest {
    fn validate(&self) -> Result<(), Failure> {
        if self.workspace_id.is_nil()
            || self.artifact_id.is_nil()
            || self.requesting_session_workspace_id.is_nil()
        {
            return Err(Failure::invalid(
                "ARTIFACT_DOWNLOAD_REQUEST_INCOMPLETE",
                "download requires a workspace, artifact, and requesting session",
            ));
        }
        Ok(())
    }

    /// The delivery request the guards evaluate.
    fn deliverable(&self) -> DeliverReadyArtifactRequest {
        DeliverReadyArtifactRequest {
            workspace_id: self.workspace_id,
            artifact_id: self.artifact_id,
            requesting_session_workspace_id: self.requesting_session_workspace_id,
        }
    }
}

/// The opened download [`AuthorizedDownload::start`] hands the transport:
/// the body stream plus the explicit header decisions it must set
/// verbatim. Zero bytes are ever produced outside `body`.
pub struct StartedDownload {
    /// The opened body stream under one transfer permit.
    pub body: Box<dyn ByteStream>,
    /// The explicit `Content-Type` the transport must set.
    pub media_type: SafeMediaType,
    /// The durably verified body length (`Content-Length`).
    pub size: u64,
    /// The `Content-Disposition` decision the transport must apply.
    pub disposition: Disposition,
}

/// The opaque one-shot download capability (§3.4). It is deliberately
/// `!Clone` — it simply does not implement `Clone` — and [`Self::start`]
/// consumes it by value, so a second call is impossible at compile time.
/// It carries no body and no stream: only the durable selectors and the
/// request evidence the final revalidation needs.
pub struct AuthorizedDownload<'a, S, O> {
    store: &'a S,
    objects: &'a O,
    request: DeliverReadyArtifactRequest,
    requested_disposition: Disposition,
    detected_media_type: Option<String>,
}

impl<'a, S, O> AuthorizedDownload<'a, S, O>
where
    S: Store,
    O: ObjectStore,
{
    /// Performs the final synchronous revalidation immediately before the
    /// transport commits headers and copies the first byte (§3.4). Every
    /// denial and error — including a stale durable snapshot — produces
    /// the closed zero-byte failure and never a partially opened stream.
    ///
    /// Consuming `self` by value is what makes the capability one-shot.
    pub async fn start(self) -> Result<StartedDownload, Failure> {
        match deliver_ready_artifact(self.store, self.objects, &self.request).await? {
            DeliverArtifactOutcome::Allowed { body, artifact, .. } => {
                // The header decisions are evaluated against the *fresh*
                // durable snapshot — never the one `prepare` validated —
                // because sensitivity and disposition are durable fields
                // a delete intent or reclassification could move under
                // the capability.
                let decision = evaluate_delivery_policy(
                    self.detected_media_type.as_deref(),
                    artifact.sensitivity,
                    self.requested_disposition,
                    artifact.verified_size,
                );
                Ok(StartedDownload {
                    body,
                    media_type: SafeMediaType(decision.media_type.to_owned()),
                    size: artifact.verified_size.max(0) as u64,
                    disposition: decision.disposition,
                })
            }
            DeliverArtifactOutcome::Denied { .. } => Err(download_denied()),
        }
    }
}

// ---------------------------------------------------------------------------
// Two-phase workspace-scoped deletion
// ---------------------------------------------------------------------------

/// One workspace-scoped deletion request — the input to
/// [`Service::delete_artifact_two_phase`].
#[derive(Debug, Clone, PartialEq)]
pub struct TwoPhaseDeleteRequest {
    /// The durable row selector's workspace.
    pub workspace_id: WorkspaceId,
    /// The artifact to delete.
    pub artifact_id: ArtifactId,
    /// The requesting session's own workspace — revalidated against the
    /// loaded row's real workspace; a cross-workspace delete is a
    /// structured authorization denial, exactly like delivery.
    pub requesting_session_workspace_id: WorkspaceId,
    /// Fresh tombstone identity minted by the caller — a deletion retry
    /// supplies the same identity so the settlement dedupes rather than
    /// writing a second tombstone.
    pub tombstone_id: ArtifactTombstoneId,
    /// The closed deletion reason — durable, never caller-freeform
    /// markup.
    pub deletion_reason: String,
    /// The durable delete-intent timestamp (caller-supplied durable
    /// evidence; the service never reads a clock).
    pub delete_intent_at: OffsetDateTime,
    /// The durable deletion-completion timestamp.
    pub deleted_at: OffsetDateTime,
}

impl TwoPhaseDeleteRequest {
    fn validate(&self) -> Result<(), Failure> {
        if self.workspace_id.is_nil()
            || self.artifact_id.is_nil()
            || self.requesting_session_workspace_id.is_nil()
        {
            return Err(Failure::invalid(
                "ARTIFACT_DELETION_IDENTITY_INCOMPLETE",
                "deletion requires a workspace, artifact, and requesting session",
            ));
        }
        if self.tombstone_id.is_nil() {
            return Err(Failure::invalid(
                "INVALID_TOMBSTONE_IDENTITY",
                "deletion requires a fresh tombstone identity",
            ));
        }
        if self.deletion_reason.is_empty() {
            return Err(Failure::invalid(
                "INVALID_DELETION_REASON",
                "deletion requires a closed deletion reason",
            ));
        }
        Ok(())
    }
}

impl<S, O, C, P, F> Service<S, O, C, P, F>
where
    S: Store + TwoPhaseDeleteStore,
    O: ObjectStore,
    C: Classifier,
    P: CompletionContributor,
    F: ObjectFailureClassifier,
{
    /// Drives the two-phase workspace-scoped deletion
    /// (`docs/artifacts/lifecycle.md` §Delete intent and tombstone):
    ///
    /// 1. `mark_delete_pending` makes the delete intent durable — the
    ///    record can never serve the body again from this commit on, and
    ///    delete intent wins any uncommitted finalization through the
    ///    version-and-state check.
    /// 2. The object body is removed *outside* any PostgreSQL
    ///    transaction.
    /// 3. `complete_deletion_with_tombstone` atomically settles the
    ///    `deleted` record and its immutable [`ArtifactTombstone`].
    ///
    /// The operation is idempotent under the same artifact and tombstone
    /// identity: a `delete_pending` record resumes at object removal, and
    /// an already-`deleted` record with its tombstone journaled returns
    /// the settled tombstone. A ready artifact is the only startable
    /// state — non-ready records are released through rejection and
    /// staging cleanup instead. Cross-workspace ownership is revalidated
    /// against the loaded durable row, exactly like delivery.
    pub async fn delete_artifact_two_phase(
        &self,
        request: &TwoPhaseDeleteRequest,
    ) -> Result<ArtifactTombstone, Failure> {
        request.validate()?;
        let mut current = self
            .store
            .load_artifact(request.workspace_id, request.artifact_id)
            .await?;
        if current.workspace_id != request.requesting_session_workspace_id {
            return Err(Failure::denied(
                "WORKSPACE_CHAIN_MISMATCH",
                "the artifact's workspace does not match the requesting session",
            ));
        }

        match current.state {
            State::Deleted => {
                // The settlement already committed. A retry under the
                // same artifact and tombstone identity returns the
                // journaled evidence — provided the tombstone was
                // actually written, which the probe answers.
                if !self
                    .store
                    .has_tombstone(request.workspace_id, request.artifact_id)
                    .await?
                {
                    return Err(Failure::conflict(
                        "ARTIFACT_DELETION_SETTLEMENT_INCOMPLETE",
                        "the artifact is deleted but its tombstone settlement is missing",
                    ));
                }
                return Ok(reconstructed_tombstone(&current, request));
            }
            State::DeletePending => {
                // The intent commit already landed — resume at the
                // object-removal half.
            }
            State::Ready => {
                let next = mark_delete_pending(&MarkDeletePendingInput {
                    workspace_id: current.workspace_id,
                    artifact_id: current.artifact_id,
                    current: current.clone(),
                    expected: current.version,
                    delete_intent_at: request.delete_intent_at,
                })?;
                current = self.store.mark_delete_pending(next).await?;
            }
            _ => {
                return Err(Failure::conflict(
                    "INVALID_TRANSITION",
                    "only a ready artifact can enter the delete-pending phase",
                ));
            }
        }

        // The object removal happens outside any PostgreSQL transaction,
        // between the two durable commits. A delete-pending record's body
        // lives at its ready key; the staging-key fallback mirrors the
        // tombstone's own evidence choice.
        let object_key = if current.ready_key.is_empty() {
            current.staging_key.clone()
        } else {
            current.ready_key.clone()
        };
        self.objects
            .remove_ready_for_delete(ObjectRef { key: object_key })
            .await?;

        let (deleted, tombstone) = complete_deletion(&CompleteDeletionInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current: current.clone(),
            expected: current.version,
            tombstone_id: request.tombstone_id,
            deletion_reason: &request.deletion_reason,
            deleted_at: request.deleted_at,
        })?;
        let result = self
            .store
            .complete_deletion_with_tombstone(deleted, tombstone)
            .await?;
        Ok(result.tombstone)
    }
}

/// Rebuilds the journaled tombstone for an already-`deleted` artifact —
/// the same value [`complete_deletion`] produced for the original
/// settlement, because a retry under the same artifact and tombstone
/// identity is definitionally the same tombstone.
fn reconstructed_tombstone(
    current: &Artifact,
    request: &TwoPhaseDeleteRequest,
) -> ArtifactTombstone {
    let verified_body = current.verified_checksum != [0; 32];
    ArtifactTombstone {
        id: request.tombstone_id,
        workspace_id: current.workspace_id,
        artifact_id: current.artifact_id,
        object_key: if current.ready_key.is_empty() {
            current.staging_key.clone()
        } else {
            current.ready_key.clone()
        },
        staging_generation: current.staging_generation,
        checksum_algorithm: verified_body.then(|| domain::CHECKSUM_ALGORITHM_SHA256.to_owned()),
        checksum_value: verified_body.then_some(current.verified_checksum),
        size_at_deletion: current.verified_size,
        deletion_reason: request.deletion_reason.clone(),
    }
}

// ---------------------------------------------------------------------------
// spec-5 §5 attempt-scoped finalization — the single visibility boundary
// (upstream internal/adapter/postgres/artifact/finalize.go)
// ---------------------------------------------------------------------------

impl<S, O, C, P, F> Service<S, O, C, P, F>
where
    S: AttemptFinalizationStore,
{
    /// Commits the spec-5 §5 single visibility boundary for one
    /// attempt-produced artifact (upstream `FinalizeAttemptArtifact`).
    ///
    /// The service's half is evaluation only: the caller's
    /// [`FinalizeAttemptInput`] becomes the artifact-owned
    /// [`AttemptFinalization`][crate::lineage::AttemptFinalization]
    /// change set (nil identities, an empty
    /// artifact name, or a nil content generation is
    /// [`REASON_INVALID_FINALIZE_INPUT`][crate::lineage::REASON_INVALID_FINALIZE_INPUT]),
    /// which the store maps inside
    /// one transaction to the `artifact_finalizations` key row, the
    /// `verifying` → `ready` transition, the journaled produce edge, and
    /// the `artifact_finalized` run event.
    ///
    /// `central-artifact` deliberately holds no journal types: the
    /// run-event envelope is the adapter's mapping, keeping the
    /// capability free of the `central-eventjournal` edge.
    ///
    /// Returns the finalized artifact id — on a same-checksum replay the
    /// RECORDED id, which may differ from `input.artifact_id`.
    pub async fn finalize_attempt_artifact(
        &self,
        input: FinalizeAttemptInput,
    ) -> Result<ArtifactId, Failure> {
        let change = crate::lineage::attempt_finalization(&input).map_err(Failure::from)?;
        self.store.finalize_attempt_artifact(change).await
    }
}

// ---------------------------------------------------------------------------
// b34 lineage — the async, store-consuming operations
// (upstream internal/artifact/lineage.go)
// ---------------------------------------------------------------------------

/// Maps a closed lineage reason into the foundation taxonomy — the same
/// `domain::Failure` → `Failure` conversion every port error crosses.
fn lineage_failure(class: domain::FailureClass, reason: &'static str) -> Failure {
    domain::Failure::new(class, reason).into()
}

/// Journals the produce edge for a finalized artifact (upstream
/// `RecordProduce`). The edge ID is minted when the caller leaves it nil;
/// the store's `artifact_id` dedupe makes a repeated call return the
/// originally journaled edge. `None` for `store` reports
/// [`REASON_LINEAGE_STORE_UNAVAILABLE`] — the honest encoding of
/// upstream's nil-interface check.
pub async fn record_produce<S: ProduceEdgeStore>(
    store: Option<&S>,
    mut edge: ProduceEdge,
) -> Result<ProduceEdge, Failure> {
    let Some(store) = store else {
        return Err(lineage_failure(
            domain::FailureClass::Invalid,
            REASON_LINEAGE_STORE_UNAVAILABLE,
        ));
    };
    if edge.id.is_nil() {
        edge.id = ProduceEdgeId::new();
    }
    edge.validate()?;
    store.insert_produce_edge(edge).await
}

/// Journals one released read (upstream `RecordRead`). The edge ID is
/// minted when nil; the store's attempt-scoped dedupe makes a retry after
/// an ambiguous outcome return the originally journaled edge rather than
/// double-counting.
pub async fn record_read<S: ReadEdgeStore>(
    store: Option<&S>,
    mut edge: ReadEdge,
) -> Result<ReadEdge, Failure> {
    let Some(store) = store else {
        return Err(lineage_failure(
            domain::FailureClass::Invalid,
            REASON_LINEAGE_STORE_UNAVAILABLE,
        ));
    };
    if edge.id.is_nil() {
        edge.id = ReadEdgeId::new();
    }
    edge.validate()?;
    store.insert_read_edge(edge).await
}

/// Returns the artifacts a node produced, attributed per attempt
/// (upstream `Produced`).
pub async fn produced<R: LineageReader>(
    store: &R,
    node_id: WorkflowNodeId,
) -> Result<Vec<ProduceEdge>, Failure> {
    if node_id.is_nil() {
        return Err(lineage_failure(
            domain::FailureClass::Invalid,
            REASON_LINEAGE_NODE_REQUIRED,
        ));
    }
    store.produce_edges_for_node(node_id).await
}

/// Returns the read edges one node journaled, unioned across its attempts
/// (upstream `ReadBy` — the attempt column is kept for forensics, per
/// spec OQ-4).
pub async fn read_by<R: LineageReader>(
    store: &R,
    node_id: WorkflowNodeId,
) -> Result<Vec<ReadEdge>, Failure> {
    if node_id.is_nil() {
        return Err(lineage_failure(
            domain::FailureClass::Invalid,
            REASON_LINEAGE_NODE_REQUIRED,
        ));
    }
    store.read_edges_for_node(node_id).await
}

/// Walks upstream from one artifact (upstream `Ancestors`): its produce
/// edge names the producing node; every artifact that node read recurses
/// the same way, back to the run root. The result holds each upstream
/// produce edge exactly once, in breadth-first discovery order. A cycle
/// in journaled edges terminates the walk rather than looping — the
/// visited set is the bound.
pub async fn ancestors<R: LineageReader>(
    store: &R,
    artifact_id: ArtifactId,
) -> Result<Vec<ProduceEdge>, Failure> {
    if artifact_id.is_nil() {
        return Err(lineage_failure(
            domain::FailureClass::Invalid,
            REASON_LINEAGE_ARTIFACT_REQUIRED,
        ));
    }
    let mut out = Vec::new();
    let mut seen = HashSet::from([artifact_id]);
    let mut queue = VecDeque::from([artifact_id]);
    while let Some(next) = queue.pop_front() {
        let Some(edge) = store.produce_edge_for_artifact(next).await? else {
            continue;
        };
        out.push(edge);
        for read in store.read_edges_for_node(edge.node_id).await? {
            if seen.insert(read.artifact_id) {
                queue.push_back(read.artifact_id);
            }
        }
    }
    Ok(out)
}

/// Walks downstream from one artifact (upstream `Descendants`): every
/// node that read it may itself have produced artifacts, which recurses
/// the same way. Operator reads (`reader_node_id == None`) produce
/// nothing downstream and are skipped. The result holds each downstream
/// produce edge exactly once, in breadth-first discovery order.
pub async fn descendants<R: LineageReader>(
    store: &R,
    artifact_id: ArtifactId,
) -> Result<Vec<ProduceEdge>, Failure> {
    if artifact_id.is_nil() {
        return Err(lineage_failure(
            domain::FailureClass::Invalid,
            REASON_LINEAGE_ARTIFACT_REQUIRED,
        ));
    }
    let mut out = Vec::new();
    let mut seen = HashSet::from([artifact_id]);
    let mut queue = VecDeque::from([artifact_id]);
    while let Some(next) = queue.pop_front() {
        for read in store.read_edges_for_artifact(next).await? {
            let Some(reader_node_id) = read.reader_node_id else {
                continue; // operator reads produce nothing downstream
            };
            for edge in store.produce_edges_for_node(reader_node_id).await? {
                if seen.insert(edge.artifact_id) {
                    out.push(edge);
                    queue.push_back(edge.artifact_id);
                }
            }
        }
    }
    Ok(out)
}

/// Returns the full journaled lineage of one run (upstream
/// `RunLineageForRun`) — every produce and read edge inside it.
pub async fn run_lineage_for_run<R: LineageReader>(
    store: &R,
    run_id: RunId,
) -> Result<RunLineage, Failure> {
    if run_id.is_nil() {
        return Err(lineage_failure(
            domain::FailureClass::Invalid,
            REASON_LINEAGE_RUN_REQUIRED,
        ));
    }
    let produced = store.produce_edges_for_run(run_id).await?;
    let read = store.read_edges_for_run(run_id).await?;
    Ok(RunLineage { produced, read })
}

/// Resolves the selector, enforces the finalized-only visibility
/// contract, computes the declared classification, and refuses
/// out-of-scope reads (upstream `AuthorizeRead`). It performs no body
/// fetch and journals nothing: the caller releases bytes first, then
/// journals via [`record_read`] (or reports the reason code on a
/// refusal).
///
/// The attempt-scope authorized set is the union of the node's declared
/// read set (artifact in-edges plus `input_artifact_refs`) and the
/// artifacts produced inside the run: a read inside the declared set is
/// journaled declared, a read of another in-run artifact is allowed and
/// journaled undeclared (declare-or-flag), and anything else is refused
/// [`REASON_ARTIFACT_SCOPE_DENIED`]. The operator reader is authorized
/// for any finalized artifact and is journaled undeclared — there is no
/// declared set to satisfy.
pub async fn authorize_read<S: ReadStore>(
    store: Option<&S>,
    request: ReadRequest,
) -> Result<ReadAuthorization, Failure> {
    let Some(store) = store else {
        return Err(lineage_failure(
            domain::FailureClass::Invalid,
            REASON_LINEAGE_STORE_UNAVAILABLE,
        ));
    };
    request.validate()?;

    let resolved: LineageArtifact = match &request.selector {
        ReadSelector::ByArtifactId(artifact_id) => {
            store.find_artifact(*artifact_id).await?.ok_or_else(|| {
                lineage_failure(
                    domain::FailureClass::Denied,
                    REASON_ARTIFACT_READ_UNRESOLVED,
                )
            })?
        }
        ReadSelector::ByProduced {
            from_node_key,
            name,
        } => {
            // Attempt resolution is confined to its own run's graph;
            // operator resolution may address any run's.
            let run_id = match request.scope {
                ReadScope::Attempt { run_id, .. } => Some(run_id),
                ReadScope::Operator => None,
            };
            let matches = store.resolve_produced(run_id, from_node_key, name).await?;
            if matches.len() != 1 {
                return Err(lineage_failure(
                    domain::FailureClass::Denied,
                    REASON_ARTIFACT_READ_UNRESOLVED,
                ));
            }
            let mut matches = matches;
            matches.remove(0)
        }
    };

    // Only finalized artifacts are visible to graph consumers and reads:
    // reserved/staging/verifying are invisible, rejected is permanently
    // unreadable.
    if resolved.state != State::Ready {
        return Err(lineage_failure(
            domain::FailureClass::Conflict,
            REASON_ARTIFACT_NOT_FINALIZED,
        ));
    }

    let mut authorization = ReadAuthorization {
        artifact: resolved,
        scope: request.scope,
        declared: false,
    };
    let ReadScope::Attempt {
        run_id, node_id, ..
    } = request.scope
    else {
        return Ok(authorization);
    };

    let declared = store.declared_scope(node_id).await?;
    let mut authorized: HashSet<ArtifactId> = declared.into_iter().collect();
    if authorized.contains(&authorization.artifact.id) {
        authorization.declared = true;
        return Ok(authorization);
    }
    let in_run = store.run_produced_artifacts(run_id).await?;
    authorized.extend(in_run);
    if !authorized.contains(&authorization.artifact.id) {
        return Err(lineage_failure(
            domain::FailureClass::Denied,
            REASON_ARTIFACT_SCOPE_DENIED,
        ));
    }
    Ok(authorization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        CommandStage, FAILURE_CODE_SECRET_DISCLOSURE, FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE,
        Sensitivity,
    };
    use crate::lineage::{
        REASON_INVALID_FINALIZE_INPUT, REASON_LINEAGE_PRODUCE_EDGE_INCOMPLETE, ReadEdge,
    };
    use crate::testkit::{
        FakeClassifier, FakeCompletion, FakeLineageStore, FakeObjects, FakeStore, Journal, block_on,
    };
    use central_foundation::identity::SessionAttemptId;

    const BODY: &[u8] = b"# report\nall good\n";
    /// A valid 64-char lowercase hex checksum for journaled read edges.
    const CHECKSUM_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// The shared fixture — one journal every fake writes into, so the
    /// cross-port ordering invariants upstream asserts hold verbatim.
    struct Fixture {
        journal: Journal,
        store: FakeStore,
        objects: FakeObjects,
        classifier: FakeClassifier,
        completion: FakeCompletion,
        service: Service<FakeStore, FakeObjects, FakeClassifier, FakeCompletion>,
    }

    fn fixture() -> Fixture {
        let journal = Journal::default();
        let store = FakeStore::new(journal.clone());
        let objects = FakeObjects::new(journal.clone());
        let classifier = FakeClassifier::new(journal.clone());
        let completion = FakeCompletion::new(journal.clone());
        let service = Service::new(
            store.clone(),
            objects.clone(),
            classifier.clone(),
            completion.clone(),
        );
        Fixture {
            journal,
            store,
            objects,
            classifier,
            completion,
            service,
        }
    }

    fn materialize_request(body: &[u8]) -> MaterializeRequest {
        MaterializeRequest {
            workspace_id: WorkspaceId::new(),
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: StepId::new(),
            step_attempt_id: StepAttemptId::new(),
            tool_call_attempt_id: None,
            producer_id: "producer".to_owned(),
            required_role: "report".to_owned(),
            limits: Limits::default(),
            declared_media_type: "text/markdown".to_owned(),
            body: Some(Box::new(std::io::Cursor::new(body.to_vec()))),
            operation_id: "op-1".to_owned(),
            artifact_id: None,
            staging_generation: None,
            completion: ExecutionChangeSet::new(),
        }
    }

    /// A durable snapshot at an arbitrary lifecycle state — the shape
    /// `FakeStore.artifacts`/`FakeRecords.artifacts` are populated with.
    fn artifact_at(state: State) -> Artifact {
        let workspace_id = WorkspaceId::new();
        let artifact_id = ArtifactId::new();
        Artifact {
            workspace_id,
            artifact_id,
            state,
            version: 1,
            staging_generation: StagingGeneration::new(),
            staging_key: format!("v1/staging/{workspace_id}/{artifact_id}/gen"),
            content_generation: None,
            ready_key: String::new(),
            limits: Limits::default(),
            verified_size: 0,
            verified_checksum: [0; 32],
            ready_object_version: String::new(),
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: StepId::new(),
            step_attempt_id: StepAttemptId::new(),
            tool_call_attempt_id: None,
            producer_id: "producer".to_owned(),
            required_role: String::new(),
            sensitivity: Sensitivity::Unrestricted,
            disposition: Disposition::Inline,
            delete_intent_at: None,
            deleted_at: None,
        }
    }

    /// A `verifying` record carrying the durable evidence
    /// `record_verification` would have written for `body`.
    fn verifying_artifact(body: &[u8]) -> Artifact {
        let mut artifact = artifact_at(State::Verifying);
        artifact.verified_size = body.len() as i64;
        artifact.verified_checksum = Sha256::digest(body).into();
        artifact
    }

    /// A ready record whose body lives at `ready_key` in the object fake.
    fn ready_artifact(body: &[u8]) -> Artifact {
        let mut artifact = artifact_at(State::Ready);
        let generation = ContentGeneration::new();
        artifact.content_generation = Some(generation);
        artifact.ready_key = format!(
            "v1/ready/{}/{}/{}",
            artifact.workspace_id, artifact.artifact_id, generation
        );
        artifact.verified_size = body.len() as i64;
        artifact.verified_checksum = Sha256::digest(body).into();
        artifact.ready_object_version = "v-ready".to_owned();
        artifact
    }

    /// An object-failure classifier that reports every error as known
    /// non-delivery — the shape the composition root installs for an
    /// adapter that can prove the write never landed.
    struct NonDeliveryFailures;

    impl ObjectFailureClassifier for NonDeliveryFailures {
        fn classify_object_failure(&self, _failure: &Failure) -> ObjectFailureClass {
            ObjectFailureClass::Unavailable
        }
    }

    /// An object-failure classifier that reports a create-only conflict:
    /// the destination key is already occupied — the shape the
    /// composition root installs for an adapter whose
    /// `promote_create_only` precondition lost to an existing object.
    struct ConflictFailures;

    impl ObjectFailureClassifier for ConflictFailures {
        fn classify_object_failure(&self, _failure: &Failure) -> ObjectFailureClass {
            ObjectFailureClass::Conflict
        }
    }

    /// The pinned content generation the conflict tests install through
    /// `with_generators`, so the earlier attempt's object can be placed
    /// under the ready key before the service mints it. A plain `fn` —
    /// the generator hooks are function pointers, not closures.
    fn pinned_content() -> ContentGeneration {
        ContentGeneration::from_trusted_db_bytes([0xC0; 16])
    }

    /// Reads a whole `ByteStream` to the end — the test-side drain.
    fn drain(mut stream: Box<dyn ByteStream>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 4096];
        loop {
            match block_on(stream.read_chunk(&mut buf)) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        let _ = block_on(stream.close());
        out
    }

    // ------------------------------------------------------------------
    // Materialization: ordering, idempotency evidence, policy outcomes
    // ------------------------------------------------------------------

    #[test]
    fn materialize_finalizes_only_after_second_verification() {
        let f = fixture();
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Ready, outcome.kind);

        // The durable record precedes the object it describes at every
        // stage: Reserve→BeginUpload→Upload→read-staging→Verify→
        // Promote→object promote→read-ready→Commit, with the completion
        // commit strictly last.
        let order = [
            "store.Reserve",
            "store.BeginUpload",
            "object.Upload",
            "object.ReadStaging",
            "classifier.Classify",
            "store.Verify",
            "store.Promote",
            "object.Promote",
            "object.ReadReady",
            "completion.Commit",
        ];
        let mut previous = 0usize;
        for step in order {
            let index = f
                .journal
                .index(step)
                .unwrap_or_else(|| unreachable!("missing journal step {step}"));
            assert!(index >= previous, "{step} out of order");
            previous = index;
        }
        let last = f.journal.steps().last().cloned().unwrap_or_default();
        assert_eq!("completion.Commit", last);
    }

    #[test]
    fn materialize_binds_ready_version_and_receipt() {
        let f = fixture();
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Ready, outcome.kind);

        let change = f
            .completion
            .change
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("commit captured no change set");
        assert_eq!("v-ready", change.finalize.artifact.ready_object_version);
        // The finalize receipt is bound to the caller's operation
        // identity — the same key a resumed handoff replays under.
        assert_eq!("op-1", change.receipt.idempotency_key);
        assert_eq!(CommandStage::Finalize, change.receipt.identity.stage);
    }

    #[test]
    fn materialize_version_change_is_terminal() {
        let f = fixture();
        // The ready object is replaced under the key between promotion
        // and the second verification: the read observes a different
        // version than the promote returned.
        *f.objects
            .rewrite_ready_version
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some("v-replaced".to_owned());
        // `rewrite_ready_version` must only rewrite the *stored*
        // evidence; the promote call's own ObjectInfo stays honest.
        *f.objects
            .mutate_ready
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;

        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Terminal, outcome.kind);
        assert!(
            outcome.failure_code == FAILURE_CODE_READY_OBJECT_VERSION_MISMATCH
                || outcome.failure_code == FAILURE_CODE_CHECKSUM_INVALID,
            "unexpected terminal code {}",
            outcome.failure_code
        );
        assert!(!f.journal.has("completion.Commit"));
    }

    #[test]
    fn materialize_no_version_evidence_still_finalizes() {
        let f = fixture();
        *f.objects
            .no_version_evidence
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Ready, outcome.kind);
    }

    #[test]
    fn materialize_second_verification_disagreement_is_terminal() {
        let f = fixture();
        *f.objects
            .mutate_ready
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(b"tampered".to_vec());
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Terminal, outcome.kind);
        assert_eq!(FAILURE_CODE_CHECKSUM_INVALID, outcome.failure_code);
        assert!(!f.journal.has("completion.Commit"));
    }

    #[test]
    fn materialize_secret_disclosure_rejects_inside_verify() {
        let f = fixture();
        *f.classifier
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = ClassifyResult {
            detected_media_type: "text/markdown".to_owned(),
            secret_disclosure: true,
            rejection_code: FAILURE_CODE_SECRET_DISCLOSURE.to_owned(),
        };
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Terminal, outcome.kind);
        assert_eq!(FAILURE_CODE_SECRET_DISCLOSURE, outcome.failure_code);
        // The rejection commits atomically inside the verify transition:
        // the record is rejected, never verifying — so the reconciler
        // never revisits it and no promotion or completion follows.
        let verified = f
            .store
            .verified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("verify recorded no rejection");
        assert_eq!(State::Rejected, verified.artifact.state);
        assert!(!f.journal.has("store.Promote"));
        assert!(!f.journal.has("completion.Commit"));
    }

    #[test]
    fn materialize_content_policy_rejects_atomically() {
        let f = fixture();
        *f.classifier
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = ClassifyResult {
            detected_media_type: "application/octet-stream".to_owned(),
            secret_disclosure: false,
            rejection_code: FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE.to_owned(),
        };
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Terminal, outcome.kind);
        assert_eq!(FAILURE_CODE_UNSUPPORTED_MEDIA_TYPE, outcome.failure_code);
        let verified = f
            .store
            .verified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("verify not recorded");
        assert_eq!(State::Rejected, verified.artifact.state);
        assert!(!f.journal.has("store.Promote"));
    }

    #[test]
    fn materialize_unknown_classifier_code_fails_closed() {
        let f = fixture();
        *f.classifier
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = ClassifyResult {
            detected_media_type: "text/plain".to_owned(),
            secret_disclosure: false,
            rejection_code: "NOT_A_CLOSED_CODE".to_owned(),
        };
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        );
        assert!(outcome.is_err(), "unknown code must fail closed");
        assert!(!f.journal.has("store.Promote"));
        assert!(!f.journal.has("completion.Commit"));
    }

    #[test]
    fn materialize_oversize_rejects_immediately() {
        let f = fixture();
        let mut request = materialize_request(&[b'x'; 64]);
        request.limits = Limits { max_bytes: 8 };
        let outcome = block_on(f.service.materialize_required_report(request))
            .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Terminal, outcome.kind);
        assert_eq!(FAILURE_CODE_SIZE_LIMIT_EXCEEDED, outcome.failure_code);
        let rejected = f
            .store
            .rejected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("oversize was not durably rejected");
        assert_eq!(State::Rejected, rejected.artifact.state);
        assert!(!f.journal.has("store.Promote"));
    }

    #[test]
    fn materialize_ambiguous_upload_is_reconciliation() {
        let f = fixture();
        *f.objects
            .upload_err
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Failure::internal(
            "S3_TIMEOUT",
            "the object store timed out",
        ));
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        // The default failure classifier treats everything as ambiguous:
        // the write may have landed, so it belongs to reconciliation.
        assert_eq!(OutcomeKind::Reconciliation, outcome.kind);
        assert_eq!(FAILURE_CODE_OBJECT_AMBIGUOUS, outcome.failure_code);
        assert!(!f.journal.has("store.Verify"));
    }

    #[test]
    fn materialize_known_non_delivery_rejects_retryable() {
        let journal = Journal::default();
        let store = FakeStore::new(journal.clone());
        let objects = FakeObjects::new(journal.clone());
        let classifier = FakeClassifier::new(journal.clone());
        let completion = FakeCompletion::new(journal.clone());
        *objects.upload_err.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Failure::internal("S3_DOWN", "the bucket is unreachable"));
        let service = Service::new(store.clone(), objects, classifier, completion)
            .with_failure_classifier(NonDeliveryFailures);

        let outcome = block_on(service.materialize_required_report(materialize_request(BODY)))
            .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Retryable, outcome.kind);
        assert_eq!(FAILURE_CODE_UPLOAD_NON_DELIVERY, outcome.failure_code);
        assert!(journal.has("store.Reject"));
        let rejected = store
            .rejected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .expect("non-delivery was not durably rejected");
        assert_eq!(State::Rejected, rejected.artifact.state);
    }

    #[test]
    fn materialize_rejects_invalid_requests() {
        let f = fixture();

        // Missing bounded body reader.
        let mut request = materialize_request(BODY);
        request.body = None;
        assert!(block_on(f.service.materialize_required_report(request)).is_err());

        // Empty operation identity.
        let mut request = materialize_request(BODY);
        request.operation_id = String::new();
        assert!(block_on(f.service.materialize_required_report(request)).is_err());

        // Nil workspace.
        let mut request = materialize_request(BODY);
        request.workspace_id = WorkspaceId::from_trusted_db_bytes([0; 16]);
        assert!(block_on(f.service.materialize_required_report(request)).is_err());

        // Limit above the hard required-report ceiling.
        let mut request = materialize_request(BODY);
        request.limits = Limits {
            max_bytes: domain::HARD_REQUIRED_REPORT_MAX_BYTES + 1,
        };
        assert!(block_on(f.service.materialize_required_report(request)).is_err());

        // A pinned nil artifact identity fails closed rather than
        // minting over the caller's intent.
        let mut request = materialize_request(BODY);
        request.artifact_id = Some(ArtifactId::from_trusted_db_bytes([0; 16]));
        assert!(block_on(f.service.materialize_required_report(request)).is_err());

        // None of them may have touched a port.
        assert!(f.journal.steps().is_empty());
    }

    #[test]
    fn materialize_completion_commit_replay_still_reports_ready() {
        let f = fixture();
        *f.completion
            .replayed
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        // A receipt replay returns the durable prior outcome — still
        // ready, never a second transition.
        assert_eq!(OutcomeKind::Ready, outcome.kind);
    }

    #[test]
    fn materialize_ambiguous_commit_is_reconciliation_not_retry() {
        let f = fixture();
        *f.completion.err.lock().unwrap_or_else(|e| e.into_inner()) = Some(Failure::ambiguous(
            "COMMIT_AMBIGUOUS",
            "the finalize commit outcome is unknown",
        ));
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        assert_eq!(OutcomeKind::Reconciliation, outcome.kind);
        assert_eq!(FAILURE_CODE_OBJECT_AMBIGUOUS, outcome.failure_code);
    }

    #[test]
    fn materialize_promote_conflict_falls_through_to_second_verification() {
        let journal = Journal::default();
        let store = FakeStore::new(journal.clone());
        let objects = FakeObjects::new(journal.clone());
        let classifier = FakeClassifier::new(journal.clone());
        let completion = FakeCompletion::new(journal.clone());
        let service = Service::new(store, objects.clone(), classifier, completion)
            .with_failure_classifier(ConflictFailures)
            .with_generators(ArtifactId::new, StagingGeneration::new, pinned_content);

        let mut request = materialize_request(BODY);
        let artifact_id = ArtifactId::new();
        request.artifact_id = Some(artifact_id);
        // A create-only conflict means the generation-unique ready key
        // is already occupied — necessarily by this Artifact's own
        // earlier attempt. That object is authoritative: place it, fail
        // the promote with a conflict, and the pass must still verify
        // and finalize against it rather than reporting a failure.
        let ready_key = format!(
            "v1/ready/{}/{}/{}",
            request.workspace_id,
            artifact_id,
            pinned_content()
        );
        objects.put(&ready_key, BODY, "v-ready");
        *objects
            .promote_err
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Failure::conflict(
            "S3_PRECONDITION_FAILED",
            "the ready key is already occupied",
        ));

        let outcome = block_on(service.materialize_required_report(request))
            .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        // The conflict falls through to the second verification, which
        // confirms the occupying object: the Artifact completes ready,
        // never reconciliation.
        assert_eq!(OutcomeKind::Ready, outcome.kind);
        assert!(journal.has("object.Promote"));
        assert!(journal.has("object.ReadReady"));
        assert!(journal.has("completion.Commit"));
    }

    #[test]
    fn materialize_promote_failure_is_reconciliation_not_overwrite() {
        let f = fixture();
        *f.objects
            .promote_err
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Failure::ambiguous(
            "S3_PROMOTE_AMBIGUOUS",
            "the promote outcome is unknown",
        ));
        let outcome = block_on(
            f.service
                .materialize_required_report(materialize_request(BODY)),
        )
        .unwrap_or_else(|e| unreachable!("materialize failed: {e:?}"));
        // The default classifier cannot prove the promote's fate: not a
        // conflict, so the pass must not fall through — it reports
        // reconciliation and never re-reads or overwrites the ready key.
        assert_eq!(OutcomeKind::Reconciliation, outcome.kind);
        assert_eq!(FAILURE_CODE_OBJECT_AMBIGUOUS, outcome.failure_code);
        assert!(f.journal.has("object.Promote"));
        assert!(!f.journal.has("object.ReadReady"));
        assert!(!f.journal.has("completion.Commit"));
    }

    // ------------------------------------------------------------------
    // resume_verifying — the crash-recovery half
    // ------------------------------------------------------------------

    #[test]
    fn resume_pre_promotion_promotes_and_finalizes() {
        let f = fixture();
        let artifact = verifying_artifact(BODY);
        // The staged body exists; no ready key — the crash landed
        // between Verify and Promote.
        f.objects.put(&artifact.staging_key, BODY, "v-staging");

        let result = block_on(f.service.resume_verifying(artifact))
            .unwrap_or_else(|e| unreachable!("resume failed: {e:?}"));
        assert!(result.resolved);
        assert_eq!(OutcomeKind::Ready, result.outcome.kind);
        assert!(f.journal.has("store.Promote"));
        assert!(f.journal.has("object.Promote"));
        assert!(f.journal.has("object.ReadReady"));
        assert!(f.journal.has("completion.Commit"));
        // A resume re-enters at promotion: no re-upload, no re-verify.
        assert!(!f.journal.has("object.Upload"));
        assert!(!f.journal.has("store.Verify"));
        assert!(!f.journal.has("store.BeginUpload"));
    }

    #[test]
    fn resume_post_promotion_only_reverifies() {
        let f = fixture();
        let mut artifact = verifying_artifact(BODY);
        let generation = ContentGeneration::new();
        artifact.content_generation = Some(generation);
        artifact.ready_key = format!(
            "v1/ready/{}/{}/{}",
            artifact.workspace_id, artifact.artifact_id, generation
        );
        // The ready object already landed — the crash was between
        // Promote and the finalize commit.
        f.objects.put(&artifact.ready_key, BODY, "v-ready");

        let result = block_on(f.service.resume_verifying(artifact))
            .unwrap_or_else(|e| unreachable!("resume failed: {e:?}"));
        assert!(result.resolved);
        assert_eq!(OutcomeKind::Ready, result.outcome.kind);
        assert!(f.journal.has("object.ReadReady"));
        assert!(f.journal.has("completion.Commit"));
        assert!(!f.journal.has("store.Promote"));
        assert!(!f.journal.has("object.Promote"));
    }

    #[test]
    fn resume_unconfirmed_ready_object_stays_reconciliation() {
        let f = fixture();
        let mut artifact = verifying_artifact(BODY);
        let generation = ContentGeneration::new();
        artifact.content_generation = Some(generation);
        artifact.ready_key = format!(
            "v1/ready/{}/{}/{}",
            artifact.workspace_id, artifact.artifact_id, generation
        );
        // No ready object exists: the promote's create-only never
        // landed, or landed under an unknown outcome. Ambiguous — the
        // record stays verifying for a later pass.
        let result = block_on(f.service.resume_verifying(artifact))
            .unwrap_or_else(|e| unreachable!("resume failed: {e:?}"));
        assert!(!result.resolved);
        assert_eq!(OutcomeKind::Reconciliation, result.outcome.kind);
        assert!(!f.journal.has("completion.Commit"));
    }

    #[test]
    fn resume_verifying_requires_verifying_state() {
        let f = fixture();
        let artifact = artifact_at(State::Ready);
        let result = block_on(f.service.resume_verifying(artifact));
        assert!(result.is_err());
    }

    #[test]
    fn resume_without_verified_evidence_is_ambiguous() {
        let f = fixture();
        // A verifying row with no recorded size/checksum is a shape the
        // service never produces: nothing may be concluded.
        let artifact = artifact_at(State::Verifying);
        let result = block_on(f.service.resume_verifying(artifact))
            .unwrap_or_else(|e| unreachable!("resume failed: {e:?}"));
        assert!(!result.resolved);
        assert_eq!(OutcomeKind::Reconciliation, result.outcome.kind);
        assert!(!f.journal.has("completion.Commit"));
    }

    #[test]
    fn resume_promote_conflict_falls_through_to_second_verification() {
        let journal = Journal::default();
        let store = FakeStore::new(journal.clone());
        let objects = FakeObjects::new(journal.clone());
        let classifier = FakeClassifier::new(journal.clone());
        let completion = FakeCompletion::new(journal.clone());
        let service = Service::new(store, objects.clone(), classifier, completion)
            .with_failure_classifier(ConflictFailures)
            .with_generators(ArtifactId::new, StagingGeneration::new, pinned_content);

        let artifact = verifying_artifact(BODY);
        // The crash landed between Verify and Promote, but the earlier
        // attempt's promote actually landed: when the resume retries it
        // create-only the generation-unique ready key is already
        // occupied, and that object is authoritative.
        objects.put(&artifact.staging_key, BODY, "v-staging");
        let ready_key = format!(
            "v1/ready/{}/{}/{}",
            artifact.workspace_id,
            artifact.artifact_id,
            pinned_content()
        );
        objects.put(&ready_key, BODY, "v-ready");
        *objects
            .promote_err
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Failure::conflict(
            "S3_PRECONDITION_FAILED",
            "the ready key is already occupied",
        ));

        let result = block_on(service.resume_verifying(artifact))
            .unwrap_or_else(|e| unreachable!("resume failed: {e:?}"));
        // The conflict falls through to the second verification, which
        // confirms the occupying object: the resume resolves ready
        // rather than parking the record in reconciliation.
        assert!(result.resolved);
        assert_eq!(OutcomeKind::Ready, result.outcome.kind);
        assert!(journal.has("store.Promote"));
        assert!(journal.has("object.Promote"));
        assert!(journal.has("object.ReadReady"));
        assert!(journal.has("completion.Commit"));
    }

    #[test]
    fn resume_promote_failure_stays_reconciliation() {
        let f = fixture();
        let artifact = verifying_artifact(BODY);
        f.objects.put(&artifact.staging_key, BODY, "v-staging");
        *f.objects
            .promote_err
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Failure::ambiguous(
            "S3_PROMOTE_AMBIGUOUS",
            "the promote outcome is unknown",
        ));
        let result = block_on(f.service.resume_verifying(artifact))
            .unwrap_or_else(|e| unreachable!("resume failed: {e:?}"));
        // Not a conflict: nothing proves the ready key is occupied by
        // this Artifact's own work, so the record stays verifying in
        // reconciliation — the ready key is never re-read as
        // authoritative.
        assert!(!result.resolved);
        assert_eq!(OutcomeKind::Reconciliation, result.outcome.kind);
        assert!(!f.journal.has("object.ReadReady"));
        assert!(!f.journal.has("completion.Commit"));
    }

    // ------------------------------------------------------------------
    // Delivery guards and the one-shot authorized download
    // ------------------------------------------------------------------

    fn deliver_request(artifact: &Artifact) -> DeliverReadyArtifactRequest {
        DeliverReadyArtifactRequest {
            workspace_id: artifact.workspace_id,
            artifact_id: artifact.artifact_id,
            requesting_session_workspace_id: artifact.workspace_id,
        }
    }

    #[test]
    fn deliver_ready_artifact_streams_body() {
        let f = fixture();
        let artifact = ready_artifact(BODY);
        f.objects.put(&artifact.ready_key, BODY, "v-ready");
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());

        let outcome = block_on(
            f.service
                .deliver_ready_artifact(&deliver_request(&artifact)),
        )
        .unwrap_or_else(|e| unreachable!("deliver failed: {e:?}"));
        let DeliverArtifactOutcome::Allowed { body, info, .. } = outcome else {
            unreachable!("ready artifact was denied");
        };
        assert_eq!(BODY.to_vec(), drain(body));
        assert_eq!(BODY.len() as i64, info.size);
    }

    #[test]
    fn deliver_denied_never_touches_the_object_store() {
        let f = fixture();
        let cases: Vec<(Artifact, &'static str)> = vec![
            // Cross-workspace: the loaded row's real workspace differs
            // from the requesting session's.
            {
                let artifact = ready_artifact(BODY);
                (artifact, "not found")
            },
            // Not yet ready.
            (artifact_at(State::Verifying), "not ready"),
            // Delete intent is durable: the body must never be served
            // again regardless of the object store's state.
            {
                let mut artifact = ready_artifact(BODY);
                artifact.delete_intent_at = Some(OffsetDateTime::now_utc());
                (artifact, "delete intent")
            },
            // Above the installed size bound.
            {
                let mut artifact = ready_artifact(BODY);
                artifact.verified_size = artifact.limits.max_bytes + 1;
                (artifact, "size bound")
            },
        ];
        for (mut artifact, reason) in cases {
            f.journal.clear();
            if reason == "not found" {
                artifact.workspace_id = WorkspaceId::new();
            }
            let request = DeliverReadyArtifactRequest {
                workspace_id: artifact.workspace_id,
                artifact_id: artifact.artifact_id,
                // The session claims a *different* workspace than the
                // row's real one for the first case.
                requesting_session_workspace_id: if reason == "not found" {
                    WorkspaceId::new()
                } else {
                    artifact.workspace_id
                },
            };
            f.store
                .artifacts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(artifact.artifact_id, artifact);
            let outcome = block_on(f.service.deliver_ready_artifact(&request))
                .unwrap_or_else(|e| unreachable!("deliver failed: {e:?}"));
            let DeliverArtifactOutcome::Denied { reason: got } = outcome else {
                unreachable!("{reason} case was allowed");
            };
            assert_eq!(reason, got);
            // Denied delivery performs zero object-store calls.
            assert!(
                !f.journal.has("object.ReadReady"),
                "{reason} read an object"
            );
        }
    }

    #[test]
    fn authorized_download_revalidates_on_start() {
        let f = fixture();
        let artifact = ready_artifact(BODY);
        f.objects.put(&artifact.ready_key, BODY, "v-ready");
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());

        let download = block_on(
            f.service
                .prepare_authorized_download(AuthorizedDownloadRequest {
                    workspace_id: artifact.workspace_id,
                    artifact_id: artifact.artifact_id,
                    requesting_session_workspace_id: artifact.workspace_id,
                    requested_disposition: Disposition::Inline,
                    detected_media_type: Some("text/markdown".to_owned()),
                }),
        )
        .unwrap_or_else(|e| unreachable!("prepare failed: {e:?}"));
        let started =
            block_on(download.start()).unwrap_or_else(|e| unreachable!("start failed: {e:?}"));
        assert_eq!("text/markdown", started.media_type.as_str());
        assert_eq!(Disposition::Inline, started.disposition);
        assert_eq!(BODY.len() as u64, started.size);
        assert_eq!(BODY.to_vec(), drain(started.body));
    }

    #[test]
    fn authorized_download_denies_cross_workspace_with_zero_bytes() {
        let f = fixture();
        let artifact = ready_artifact(BODY);
        f.objects.put(&artifact.ready_key, BODY, "v-ready");
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());

        let result = block_on(
            f.service
                .prepare_authorized_download(AuthorizedDownloadRequest {
                    workspace_id: artifact.workspace_id,
                    artifact_id: artifact.artifact_id,
                    requesting_session_workspace_id: WorkspaceId::new(),
                    requested_disposition: Disposition::Attachment,
                    detected_media_type: None,
                }),
        );
        assert!(result.is_err(), "cross-workspace download was prepared");
        assert!(!f.journal.has("object.ReadReady"));
    }

    #[test]
    fn authorized_download_downgrades_sensitive_inline() {
        let f = fixture();
        let mut artifact = ready_artifact(BODY);
        artifact.sensitivity = Sensitivity::Sensitive;
        f.objects.put(&artifact.ready_key, BODY, "v-ready");
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());

        let download = block_on(
            f.service
                .prepare_authorized_download(AuthorizedDownloadRequest {
                    workspace_id: artifact.workspace_id,
                    artifact_id: artifact.artifact_id,
                    requesting_session_workspace_id: artifact.workspace_id,
                    requested_disposition: Disposition::Inline,
                    detected_media_type: Some("text/markdown".to_owned()),
                }),
        )
        .unwrap_or_else(|e| unreachable!("prepare failed: {e:?}"));
        let started =
            block_on(download.start()).unwrap_or_else(|e| unreachable!("start failed: {e:?}"));
        // Sensitivity may only ever downgrade a requested disposition.
        assert_eq!(Disposition::Attachment, started.disposition);
    }

    // ------------------------------------------------------------------
    // Two-phase workspace-scoped deletion
    // ------------------------------------------------------------------

    fn delete_request(artifact: &Artifact) -> TwoPhaseDeleteRequest {
        TwoPhaseDeleteRequest {
            workspace_id: artifact.workspace_id,
            artifact_id: artifact.artifact_id,
            requesting_session_workspace_id: artifact.workspace_id,
            tombstone_id: ArtifactTombstoneId::new(),
            deletion_reason: "OPERATOR_DELETE".to_owned(),
            delete_intent_at: OffsetDateTime::now_utc(),
            deleted_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn delete_two_phase_orders_intent_object_settlement() {
        let f = fixture();
        let artifact = ready_artifact(BODY);
        f.objects.put(&artifact.ready_key, BODY, "v-ready");
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());

        let tombstone = block_on(
            f.service
                .delete_artifact_two_phase(&delete_request(&artifact)),
        )
        .unwrap_or_else(|e| unreachable!("delete failed: {e:?}"));
        assert_eq!(artifact.artifact_id, tombstone.artifact_id);
        assert_eq!(artifact.ready_key, tombstone.object_key);

        // Delete intent commits before the object body is removed, and
        // the settlement lands last.
        let pending = f.journal.index("store.DeletePending").unwrap_or(0);
        let removed = f.journal.index("object.RemoveReady").unwrap_or(0);
        let settled = f.journal.index("store.CompleteDeletion").unwrap_or(0);
        assert!(
            pending < removed && removed < settled,
            "deletion out of order"
        );
        let removed_keys = f
            .objects
            .removed_ready
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(vec![artifact.ready_key.clone()], removed_keys.clone());
        // The durable record ends deleted.
        let stored = f
            .store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&artifact.artifact_id)
            .cloned()
            .expect("record missing");
        assert_eq!(State::Deleted, stored.state);
    }

    #[test]
    fn delete_pending_record_resumes_at_object_removal() {
        let f = fixture();
        let mut artifact = ready_artifact(BODY);
        artifact.state = State::DeletePending;
        artifact.delete_intent_at = Some(OffsetDateTime::now_utc());
        f.objects.put(&artifact.ready_key, BODY, "v-ready");
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());

        let tombstone = block_on(
            f.service
                .delete_artifact_two_phase(&delete_request(&artifact)),
        )
        .unwrap_or_else(|e| unreachable!("delete failed: {e:?}"));
        assert_eq!(artifact.artifact_id, tombstone.artifact_id);
        // The intent commit is skipped — it already landed.
        assert!(!f.journal.has("store.DeletePending"));
        assert!(f.journal.has("object.RemoveReady"));
        assert!(f.journal.has("store.CompleteDeletion"));
    }

    #[test]
    fn deleted_record_replays_journaled_tombstone() {
        let f = fixture();
        let mut artifact = ready_artifact(BODY);
        artifact.state = State::Deleted;
        artifact.deleted_at = Some(OffsetDateTime::now_utc());
        let tombstone = ArtifactTombstone {
            id: ArtifactTombstoneId::new(),
            workspace_id: artifact.workspace_id,
            artifact_id: artifact.artifact_id,
            object_key: artifact.ready_key.clone(),
            staging_generation: artifact.staging_generation,
            checksum_algorithm: Some("sha256".to_owned()),
            checksum_value: Some(artifact.verified_checksum),
            size_at_deletion: artifact.verified_size,
            deletion_reason: "OPERATOR_DELETE".to_owned(),
        };
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());
        f.store
            .tombstones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, tombstone);

        let request = delete_request(&artifact);
        let returned = block_on(f.service.delete_artifact_two_phase(&request))
            .unwrap_or_else(|e| unreachable!("delete failed: {e:?}"));
        // The replay returns the settlement under the request's own
        // tombstone identity — the caller's retry identity.
        assert_eq!(request.tombstone_id, returned.id);
        assert_eq!(artifact.artifact_id, returned.artifact_id);
        // No second object removal, no second settlement commit.
        assert!(!f.journal.has("object.RemoveReady"));
        assert!(!f.journal.has("store.CompleteDeletion"));
    }

    #[test]
    fn deleted_record_missing_tombstone_is_conflict() {
        let f = fixture();
        let mut artifact = ready_artifact(BODY);
        artifact.state = State::Deleted;
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());
        let result = block_on(
            f.service
                .delete_artifact_two_phase(&delete_request(&artifact)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn delete_cross_workspace_and_non_ready_fail() {
        let f = fixture();
        let artifact = ready_artifact(BODY);
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());

        // Cross-workspace: structured denial, nothing removed.
        let mut request = delete_request(&artifact);
        request.requesting_session_workspace_id = WorkspaceId::new();
        let result = block_on(f.service.delete_artifact_two_phase(&request));
        assert!(result.is_err());
        assert!(!f.journal.has("store.DeletePending"));

        // Non-ready: only a ready artifact may enter the delete phase.
        let staging = artifact_at(State::Staging);
        f.store
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(staging.artifact_id, staging.clone());
        let result = block_on(
            f.service
                .delete_artifact_two_phase(&delete_request(&staging)),
        );
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // b34 lineage — edges, walks, read authorization
    // ------------------------------------------------------------------

    fn produce_edge(
        run_id: RunId,
        node_id: WorkflowNodeId,
        artifact_id: ArtifactId,
    ) -> ProduceEdge {
        ProduceEdge {
            id: ProduceEdgeId::new(),
            run_id,
            node_id,
            attempt_id: SessionAttemptId::new(),
            artifact_id,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    fn read_edge(
        run_id: RunId,
        reader: Option<WorkflowNodeId>,
        artifact_id: ArtifactId,
    ) -> ReadEdge {
        ReadEdge {
            id: ReadEdgeId::new(),
            run_id,
            reader_node_id: reader,
            attempt_id: reader.map(|_| SessionAttemptId::new()),
            artifact_id,
            declared: true,
            checksum: CHECKSUM_HEX.to_owned(),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn record_produce_mints_identity_and_dedupes() {
        let store = FakeLineageStore::new();
        let edge = produce_edge(RunId::new(), WorkflowNodeId::new(), ArtifactId::new());
        let edge = ProduceEdge {
            id: ProduceEdgeId::from_trusted_db_bytes([0; 16]),
            ..edge
        };
        let journaled = block_on(record_produce(Some(&store), edge))
            .unwrap_or_else(|e| unreachable!("record_produce failed: {e:?}"));
        assert!(!journaled.id.is_nil(), "edge id must be minted");

        // A replay under the same artifact returns the journaled edge.
        let again = block_on(record_produce(Some(&store), journaled))
            .unwrap_or_else(|e| unreachable!("record_produce failed: {e:?}"));
        assert_eq!(journaled, again);
        assert_eq!(
            1,
            store
                .produces
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len()
        );

        // A nil store reports the honest closed reason.
        let err = block_on(record_produce(None::<&FakeLineageStore>, journaled)).unwrap_err();
        assert_eq!(REASON_LINEAGE_STORE_UNAVAILABLE, err.code());

        // An incomplete edge (nil run) fails validation closed.
        let mut bad = journaled;
        bad.run_id = RunId::from_trusted_db_bytes([0; 16]);
        let err = block_on(record_produce(Some(&store), bad)).unwrap_err();
        assert_eq!(REASON_LINEAGE_PRODUCE_EDGE_INCOMPLETE, err.code());
    }

    #[test]
    fn record_read_dedupes_attempt_scope_never_operator() {
        let store = FakeLineageStore::new();
        let run_id = RunId::new();
        let node = WorkflowNodeId::new();
        let artifact = ArtifactId::new();
        let edge = read_edge(run_id, Some(node), artifact);

        let first = block_on(record_read(Some(&store), edge.clone()))
            .unwrap_or_else(|e| unreachable!("record_read failed: {e:?}"));
        let replay = block_on(record_read(Some(&store), edge))
            .unwrap_or_else(|e| unreachable!("record_read failed: {e:?}"));
        assert_eq!(first.id, replay.id);
        assert_eq!(
            1,
            store.reads.lock().unwrap_or_else(|e| e.into_inner()).len()
        );

        // The operator NULL pair never dedupes: each read is a distinct
        // observable event.
        let operator = read_edge(run_id, None, artifact);
        block_on(record_read(Some(&store), operator.clone()))
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        block_on(record_read(Some(&store), operator)).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(
            3,
            store.reads.lock().unwrap_or_else(|e| e.into_inner()).len()
        );

        let err = block_on(record_read(None::<&FakeLineageStore>, first)).unwrap_err();
        assert_eq!(REASON_LINEAGE_STORE_UNAVAILABLE, err.code());
    }

    #[test]
    fn produced_and_read_by_union_node_edges() {
        let store = FakeLineageStore::new();
        let node = WorkflowNodeId::new();
        let run_id = RunId::new();
        let artifact = ArtifactId::new();
        let edge = produce_edge(run_id, node, artifact);
        block_on(record_produce(Some(&store), edge)).unwrap_or_else(|e| unreachable!("{e:?}"));
        let read = read_edge(run_id, Some(node), artifact);
        block_on(record_read(Some(&store), read)).unwrap_or_else(|e| unreachable!("{e:?}"));

        let produced_edges =
            block_on(produced(&store, node)).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(1, produced_edges.len());
        assert_eq!(artifact, produced_edges[0].artifact_id);
        let read_edges = block_on(read_by(&store, node)).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(1, read_edges.len());
        assert_eq!(artifact, read_edges[0].artifact_id);

        // A nil node is a closed invalid, never a panic.
        let err = block_on(produced(
            &store,
            WorkflowNodeId::from_trusted_db_bytes([0; 16]),
        ))
        .unwrap_err();
        assert_eq!(REASON_LINEAGE_NODE_REQUIRED, err.code());
        let err = block_on(read_by(
            &store,
            WorkflowNodeId::from_trusted_db_bytes([0; 16]),
        ))
        .unwrap_err();
        assert_eq!(REASON_LINEAGE_NODE_REQUIRED, err.code());
    }

    #[test]
    fn ancestors_walks_bfs_with_cycle_guard() {
        let store = FakeLineageStore::new();
        let run_id = RunId::new();
        let node_a = WorkflowNodeId::new();
        let node_b = WorkflowNodeId::new();
        let a1 = ArtifactId::new();
        let a2 = ArtifactId::new();
        // a2 produced by node_b, which read a1; a1 produced by node_a,
        // which read a2 — a cycle. The walk must terminate.
        let edge_b = produce_edge(run_id, node_b, a2);
        let edge_a = produce_edge(run_id, node_a, a1);
        block_on(record_produce(Some(&store), edge_b)).unwrap_or_else(|e| unreachable!("{e:?}"));
        block_on(record_produce(Some(&store), edge_a)).unwrap_or_else(|e| unreachable!("{e:?}"));
        block_on(record_read(
            Some(&store),
            read_edge(run_id, Some(node_b), a1),
        ))
        .unwrap_or_else(|e| unreachable!("{e:?}"));
        block_on(record_read(
            Some(&store),
            read_edge(run_id, Some(node_a), a2),
        ))
        .unwrap_or_else(|e| unreachable!("{e:?}"));

        let walked = block_on(ancestors(&store, a2)).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(2, walked.len(), "BFS must visit each produce edge once");
        assert_eq!(a2, walked[0].artifact_id);
        assert_eq!(a1, walked[1].artifact_id);

        // A nil artifact fails closed.
        let err = block_on(ancestors(
            &store,
            ArtifactId::from_trusted_db_bytes([0; 16]),
        ))
        .unwrap_err();
        assert_eq!(REASON_LINEAGE_ARTIFACT_REQUIRED, err.code());
    }

    #[test]
    fn descendants_walks_bfs_skipping_operator_reads() {
        let store = FakeLineageStore::new();
        let run_id = RunId::new();
        let node = WorkflowNodeId::new();
        let a1 = ArtifactId::new();
        let a2 = ArtifactId::new();
        let a3 = ArtifactId::new();
        // node read a1 then produced a2 — a2 is a descendant of a1.
        block_on(record_read(Some(&store), read_edge(run_id, Some(node), a1)))
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        let edge_2 = produce_edge(run_id, node, a2);
        block_on(record_produce(Some(&store), edge_2)).unwrap_or_else(|e| unreachable!("{e:?}"));
        // An operator read of a1 produces nothing downstream — skipped.
        block_on(record_read(Some(&store), read_edge(run_id, None, a1)))
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        // A second read edge from node to a1 itself — dedupe by tuple
        // would keep one; a different artifact read yields more output.
        let node2 = WorkflowNodeId::new();
        block_on(record_read(
            Some(&store),
            read_edge(run_id, Some(node2), a2),
        ))
        .unwrap_or_else(|e| unreachable!("{e:?}"));
        let edge_3 = produce_edge(run_id, node2, a3);
        block_on(record_produce(Some(&store), edge_3)).unwrap_or_else(|e| unreachable!("{e:?}"));

        let descendants =
            block_on(descendants(&store, a1)).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(2, descendants.len());
        assert_eq!(a2, descendants[0].artifact_id);
        assert_eq!(a3, descendants[1].artifact_id);
    }

    #[test]
    fn run_lineage_for_run_returns_both_edge_sets() {
        let store = FakeLineageStore::new();
        let run_id = RunId::new();
        let node = WorkflowNodeId::new();
        let artifact = ArtifactId::new();
        block_on(record_produce(
            Some(&store),
            produce_edge(run_id, node, artifact),
        ))
        .unwrap_or_else(|e| unreachable!("{e:?}"));
        block_on(record_read(
            Some(&store),
            read_edge(run_id, Some(node), artifact),
        ))
        .unwrap_or_else(|e| unreachable!("{e:?}"));
        // Edges from a different run never leak in.
        block_on(record_produce(
            Some(&store),
            produce_edge(RunId::new(), node, ArtifactId::new()),
        ))
        .unwrap_or_else(|e| unreachable!("{e:?}"));

        let lineage =
            block_on(run_lineage_for_run(&store, run_id)).unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(1, lineage.produced.len());
        assert_eq!(1, lineage.read.len());

        let err = block_on(run_lineage_for_run(
            &store,
            RunId::from_trusted_db_bytes([0; 16]),
        ))
        .unwrap_err();
        assert_eq!(REASON_LINEAGE_RUN_REQUIRED, err.code());
    }

    fn lineage_artifact(artifact_id: ArtifactId, run_id: RunId, state: State) -> LineageArtifact {
        LineageArtifact {
            id: artifact_id,
            workspace_id: WorkspaceId::new(),
            run_id,
            state,
            ready_key: "v1/ready/x".to_owned(),
            checksum: CHECKSUM_HEX.to_owned(),
        }
    }

    #[test]
    fn authorize_read_declared_scope_marks_declared() {
        let store = FakeLineageStore::new();
        let run_id = RunId::new();
        let node = WorkflowNodeId::new();
        let artifact = ArtifactId::new();
        store
            .artifacts_by_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                artifact,
                lineage_artifact(artifact, RunId::new(), State::Ready),
            );
        store
            .declared_by_node
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(node, vec![artifact]);

        let authorization = block_on(authorize_read(
            Some(&store),
            ReadRequest {
                scope: ReadScope::Attempt {
                    run_id,
                    node_id: node,
                    attempt_id: SessionAttemptId::new(),
                },
                selector: ReadSelector::ByArtifactId(artifact),
            },
        ))
        .unwrap_or_else(|e| unreachable!("authorize failed: {e:?}"));
        assert!(authorization.declared);
        assert_eq!(artifact, authorization.artifact.id);
    }

    #[test]
    fn authorize_read_in_run_undeclared_is_allowed_flagged() {
        let store = FakeLineageStore::new();
        let run_id = RunId::new();
        let node = WorkflowNodeId::new();
        let artifact = ArtifactId::new();
        // Not in the declared set, but produced inside the same run.
        store
            .artifacts_by_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact, lineage_artifact(artifact, run_id, State::Ready));
        block_on(record_produce(
            Some(&store),
            produce_edge(run_id, WorkflowNodeId::new(), artifact),
        ))
        .unwrap_or_else(|e| unreachable!("{e:?}"));

        let authorization = block_on(authorize_read(
            Some(&store),
            ReadRequest {
                scope: ReadScope::Attempt {
                    run_id,
                    node_id: node,
                    attempt_id: SessionAttemptId::new(),
                },
                selector: ReadSelector::ByArtifactId(artifact),
            },
        ))
        .unwrap_or_else(|e| unreachable!("authorize failed: {e:?}"));
        // Declare-or-flag: permitted, journaled undeclared.
        assert!(!authorization.declared);
    }

    #[test]
    fn authorize_read_out_of_scope_is_denied() {
        let store = FakeLineageStore::new();
        let run_id = RunId::new();
        let artifact = ArtifactId::new();
        // A finalized artifact produced by a *different* run, outside
        // the declared set.
        store
            .artifacts_by_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                artifact,
                lineage_artifact(artifact, RunId::new(), State::Ready),
            );

        let err = block_on(authorize_read(
            Some(&store),
            ReadRequest {
                scope: ReadScope::Attempt {
                    run_id,
                    node_id: WorkflowNodeId::new(),
                    attempt_id: SessionAttemptId::new(),
                },
                selector: ReadSelector::ByArtifactId(artifact),
            },
        ))
        .unwrap_err();
        assert_eq!(REASON_ARTIFACT_SCOPE_DENIED, err.code());
    }

    #[test]
    fn authorize_read_operator_reads_any_finalized() {
        let store = FakeLineageStore::new();
        let artifact = ArtifactId::new();
        store
            .artifacts_by_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                artifact,
                lineage_artifact(artifact, RunId::new(), State::Ready),
            );

        let authorization = block_on(authorize_read(
            Some(&store),
            ReadRequest {
                scope: ReadScope::Operator,
                selector: ReadSelector::ByArtifactId(artifact),
            },
        ))
        .unwrap_or_else(|e| unreachable!("authorize failed: {e:?}"));
        // The operator has no declared set: authorized, journaled
        // undeclared.
        assert!(!authorization.declared);
    }

    #[test]
    fn authorize_read_only_finalized_is_visible() {
        let store = FakeLineageStore::new();
        let artifact = ArtifactId::new();
        for state in [State::Reserved, State::Verifying, State::Rejected] {
            store
                .artifacts_by_id
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(artifact, lineage_artifact(artifact, RunId::new(), state));
            let err = block_on(authorize_read(
                Some(&store),
                ReadRequest {
                    scope: ReadScope::Operator,
                    selector: ReadSelector::ByArtifactId(artifact),
                },
            ))
            .unwrap_err();
            assert_eq!(REASON_ARTIFACT_NOT_FINALIZED, err.code(), "{state:?}");
        }
    }

    #[test]
    fn authorize_read_unresolved_selector_is_denied() {
        let store = FakeLineageStore::new();
        let artifact = ArtifactId::new();
        // ByArtifactId: nothing journaled for it.
        let err = block_on(authorize_read(
            Some(&store),
            ReadRequest {
                scope: ReadScope::Operator,
                selector: ReadSelector::ByArtifactId(artifact),
            },
        ))
        .unwrap_err();
        assert_eq!(REASON_ARTIFACT_READ_UNRESOLVED, err.code());

        // ByProduced: zero or multiple matches are equally unresolved.
        let err = block_on(authorize_read(
            Some(&store),
            ReadRequest {
                scope: ReadScope::Operator,
                selector: ReadSelector::ByProduced {
                    from_node_key: "node".to_owned(),
                    name: "report".to_owned(),
                },
            },
        ))
        .unwrap_err();
        assert_eq!(REASON_ARTIFACT_READ_UNRESOLVED, err.code());

        *store
            .resolved_produced
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = vec![
            lineage_artifact(ArtifactId::new(), RunId::new(), State::Ready),
            lineage_artifact(ArtifactId::new(), RunId::new(), State::Ready),
        ];
        let err = block_on(authorize_read(
            Some(&store),
            ReadRequest {
                scope: ReadScope::Operator,
                selector: ReadSelector::ByProduced {
                    from_node_key: "node".to_owned(),
                    name: "report".to_owned(),
                },
            },
        ))
        .unwrap_err();
        assert_eq!(REASON_ARTIFACT_READ_UNRESOLVED, err.code());
    }

    #[test]
    fn authorize_read_nil_store_reports_unavailable() {
        let err = block_on(authorize_read(
            None::<&FakeLineageStore>,
            ReadRequest {
                scope: ReadScope::Operator,
                selector: ReadSelector::ByArtifactId(ArtifactId::new()),
            },
        ))
        .unwrap_err();
        assert_eq!(REASON_LINEAGE_STORE_UNAVAILABLE, err.code());
    }

    // -----------------------------------------------------------------
    // spec-5 §5 attempt-scoped finalization — the capability half
    // -----------------------------------------------------------------

    fn finalize_attempt_input() -> FinalizeAttemptInput {
        FinalizeAttemptInput {
            attempt_id: SessionAttemptId::new(),
            artifact_name: "report".to_owned(),
            artifact_id: ArtifactId::new(),
            run_id: RunId::new(),
            node_id: WorkflowNodeId::new(),
            checksum: [0xAA; 32],
            payload_fingerprint: [0xBB; 32],
            content_generation: ContentGeneration::new(),
        }
    }

    /// The service hands the store the evaluated `AttemptFinalization`
    /// change set — the capability's side of the boundary never sees a
    /// journal type (upstream `FinalizeAttemptArtifact`'s commit half
    /// lives in the adapter).
    #[test]
    fn finalize_attempt_artifact_passes_evaluated_change_set_to_store() {
        let f = fixture();
        let input = finalize_attempt_input();
        let returned = block_on(f.service.finalize_attempt_artifact(input.clone())).unwrap();
        assert_eq!(input.artifact_id, returned);
        assert!(f.journal.has("store.FinalizeAttempt"));
        let changes = f
            .store
            .finalizations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(1, changes.len());
        let change = &changes[0];
        assert_eq!(input.attempt_id, change.attempt_id);
        assert_eq!(input.artifact_name, change.artifact_name);
        assert_eq!(input.artifact_id, change.artifact_id);
        assert_eq!(input.run_id, change.run_id);
        assert_eq!(input.node_id, change.node_id);
        assert_eq!(input.checksum, change.checksum);
        assert_eq!(input.payload_fingerprint, change.payload_fingerprint);
        assert_eq!(input.content_generation, change.content_generation);
    }

    /// An empty artifact name is `INVALID_FINALIZE_INPUT` before any
    /// store call — upstream's `attemptID == uuid.Nil || artifactID ==
    /// uuid.Nil || name == ""` guard evaluated in the capability.
    #[test]
    fn finalize_attempt_artifact_rejects_empty_name_without_store_call() {
        let f = fixture();
        let mut input = finalize_attempt_input();
        input.artifact_name = String::new();
        let err = block_on(f.service.finalize_attempt_artifact(input)).unwrap_err();
        assert_eq!(REASON_INVALID_FINALIZE_INPUT, err.code());
        assert_eq!(FailureKind::Invalid, err.kind());
        assert!(!f.journal.has("store.FinalizeAttempt"));
    }

    /// A same-checksum replay returns the RECORDED artifact id the
    /// store answers with, which may differ from the passed id.
    #[test]
    fn finalize_attempt_artifact_returns_recorded_id_on_replay() {
        let f = fixture();
        let input = finalize_attempt_input();
        let recorded = ArtifactId::new();
        *f.store
            .finalize_attempt_result
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(recorded);
        let returned = block_on(f.service.finalize_attempt_artifact(input)).unwrap();
        assert_eq!(recorded, returned);
    }

    /// A store verdict (e.g. `ARTIFACT_ALREADY_FINALIZED`) propagates
    /// unchanged — the service adds no mapping of its own.
    #[test]
    fn finalize_attempt_artifact_propagates_store_failure() {
        let f = fixture();
        *f.store
            .finalize_attempt_err
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Failure::conflict(
            "ARTIFACT_ALREADY_FINALIZED",
            "already finalized",
        ));
        let err = block_on(
            f.service
                .finalize_attempt_artifact(finalize_attempt_input()),
        )
        .unwrap_err();
        assert_eq!("ARTIFACT_ALREADY_FINALIZED", err.code());
    }
}
