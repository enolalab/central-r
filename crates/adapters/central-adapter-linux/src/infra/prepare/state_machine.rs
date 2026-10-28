//! `PrepareState` — the port of upstream `dependencyprepare/app/service.go`
//! and `progress.go`: the durable, resumable dependency-prepare state
//! machine.
//!
//! One operation walks the checkpoints `capacity_admitted → acquiring →
//! verified_inputs → build_one → build_two → compared → attested →
//! candidate_staged → promotion_admitted → selector_switched → completed`,
//! journalling the fine-grained phase and the deadline after every
//! transition so a crash resumes exactly.
//!
//! Resume rule: build output lives only in memory for one pass, so every
//! checkpoint before candidate staging rewinds to the *capacity*
//! checkpoint and rebuilds under the original deadline — unverified output
//! can never become the input to a candidate. From candidate staging
//! onward the staged candidate on disk is the evidence and the switch is
//! repeated exactly (or the candidate is quarantined). The rewind goes to
//! capacity, not acquisition, so a resumed pass repeats the host
//! preconditions a first pass checks.
//!
//! Evidence ordering is the point of the machine: attestations are issued
//! only after the two independent builds compared equal and bind that
//! layout; the proven build is loaded into the image store only after
//! comparison *and* attestation re-validated, and before the candidate is
//! staged; promotion admission is taken fresh immediately before the
//! selector moves.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use central_foundation::failure::Failure;
use central_infra::authority::{PrepareOperation, PrepareOperationPhase};
use central_infra::domain::{
    AcquisitionKind, AdmissionBinding, AttestationFact, Candidate, ComparisonFact,
    DependencyReceipt, OciInventory, PreparePhase, PreparedDependencySet, PreparedMode,
    acquisition_kind_for, codes, inventory_digest, new_admission_binding, selector_token,
    service_mode_for_selector, valid_operation_id, validate_attestation_facts,
    validate_independent_builds,
};
use central_infra::prepare::{
    AttestationMaterials, BuildRequest, ImageLoadRequest, Lock, MAX_PROGRESS_EVENTS,
    OPERATION_BUDGET, PrepareResult, ProgressEvent, SafeCounters, StageTiming, append_stage_timing,
    builder_identity, new_build_request, prepare_codes, release_trust_materials,
    subject_from_inventory, validate_loaded_image, with_safe_next_action,
};
use time::OffsetDateTime;

use super::attestation::Attestor;
use super::image_load::ImageLoader;
use super::journal::FileJournal;
use super::{BuildKit, CandidateStore, CapacityChecker, Comparator, Fetcher, OpDeadline};
use crate::helper::prepare::AdvisoryAdmission;

const RESUME_EXIT_CODE: i32 = 6;

// ---------------------------------------------------------------------------
// Ports (`dependencyprepare/port`)
// ---------------------------------------------------------------------------

/// `port.AdmissionVerifier` — a fresh advisory-currency check that answers
/// with the receipt binding. It answers only for currency; the token that
/// authorises a specific selector is derived by the state machine.
pub trait AdmissionVerifier: Send + Sync {
    /// `VerifyCurrent`.
    ///
    /// # Errors
    /// Any refusal to admit.
    fn verify_current(
        &self,
        deadline: OpDeadline,
        admission: &AdvisoryAdmission,
    ) -> Result<AdmissionBinding, Failure>;
}

/// `port.Builder`.
pub trait Builder: Send + Sync {
    /// `Build` — one hermetic build.
    ///
    /// # Errors
    /// Any build failure.
    fn build(&self, deadline: OpDeadline, req: &BuildRequest) -> Result<OciInventory, Failure>;
}

/// `port.Fetcher`.
pub trait SourceFetcher: Send + Sync {
    /// `Fetch`.
    ///
    /// # Errors
    /// Any acquisition failure.
    fn fetch(&self, deadline: OpDeadline, selector: &str) -> Result<Candidate, Failure>;
    /// `StageSource` — place the verified source into the build context.
    ///
    /// # Errors
    /// Any staging failure.
    fn stage_source(
        &self,
        deadline: OpDeadline,
        selector: &str,
        dest: &std::path::Path,
    ) -> Result<(), Failure>;
}

/// `port.CapacityChecker`.
pub trait CapacityGate: Send + Sync {
    /// `HasCapacity`.
    ///
    /// # Errors
    /// Any check failure.
    fn has_capacity(&self, deadline: OpDeadline, selector: &str) -> Result<bool, Failure>;
}

/// The staging half of `port.CandidateStore` the machine consumes.
pub trait CandidateSink: Send + Sync {
    /// `Stage`.
    ///
    /// # Errors
    /// Any staging failure.
    fn stage(&self, deadline: OpDeadline, candidate: &Candidate) -> Result<Candidate, Failure>;
    /// `Recover` — repeat exactly the staged switch, or quarantine.
    ///
    /// # Errors
    /// Any switch or quarantine failure.
    fn recover(
        &self,
        deadline: OpDeadline,
        candidate_id: &str,
        binding: &AdmissionBinding,
    ) -> Result<DependencyReceipt, Failure>;
}

/// `port.OCIComparator`.
pub trait OciComparator: Send + Sync {
    /// `Compare`.
    ///
    /// # Errors
    /// A mismatch or incomplete inventory.
    fn compare(&self, a: &OciInventory, b: &OciInventory) -> Result<ComparisonFact, Failure>;
}

/// `port.ProgressReporter` — a progress event may carry only a phase name,
/// counts and durations, never a path, URL, command line or builder output.
pub trait ProgressReporter: Send + Sync {
    /// `Report`. A failure is the reporter's own problem: progress is an
    /// observation of the operation, never a precondition of it.
    fn report(&self, event: &ProgressEvent);
}

impl Builder for BuildKit {
    fn build(&self, deadline: OpDeadline, req: &BuildRequest) -> Result<OciInventory, Failure> {
        BuildKit::build(self, deadline, req)
    }
}

impl SourceFetcher for Fetcher {
    fn fetch(&self, deadline: OpDeadline, selector: &str) -> Result<Candidate, Failure> {
        Fetcher::fetch(self, deadline, selector)
    }

    fn stage_source(
        &self,
        deadline: OpDeadline,
        selector: &str,
        dest: &std::path::Path,
    ) -> Result<(), Failure> {
        Fetcher::stage_source(self, deadline, selector, dest)
    }
}

impl CapacityGate for CapacityChecker {
    fn has_capacity(&self, deadline: OpDeadline, selector: &str) -> Result<bool, Failure> {
        CapacityChecker::has_capacity(self, deadline, selector)
    }
}

impl CandidateSink for CandidateStore {
    fn stage(&self, deadline: OpDeadline, candidate: &Candidate) -> Result<Candidate, Failure> {
        CandidateStore::stage(self, deadline, candidate)
    }

    fn recover(
        &self,
        deadline: OpDeadline,
        candidate_id: &str,
        binding: &AdmissionBinding,
    ) -> Result<DependencyReceipt, Failure> {
        CandidateStore::recover(self, deadline, candidate_id, binding)
    }
}

impl OciComparator for Comparator {
    fn compare(&self, a: &OciInventory, b: &OciInventory) -> Result<ComparisonFact, Failure> {
        Comparator::compare(self, a, b)
    }
}

/// The injectable clock (`port.Clock`).
pub type Clock = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// A cooperative cancellation flag — the synchronous stand-in for
/// `ctx.Done()`.
pub type CancelFlag = Arc<AtomicBool>;

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// `MapAuthorityPhase` — projects a checkpoint onto the coarse phase an
/// operator sees. One-way and lossy by design: the journal records the
/// authority phase itself and nothing maps back through this.
#[must_use]
pub fn map_authority_phase(phase: PrepareOperationPhase) -> PreparePhase {
    use PrepareOperationPhase as P;
    match phase {
        P::CapacityAdmitted | P::Acquiring => PreparePhase::Acquiring,
        P::VerifiedInputs => PreparePhase::Pending,
        P::BuildOne | P::BuildTwo | P::Compared | P::Attested => PreparePhase::Building,
        P::CandidateStaged | P::PromotionAdmitted | P::SelectorSwitched => PreparePhase::Staging,
        P::Completed => PreparePhase::Ready,
        P::Failed | P::Cancelled => PreparePhase::Failed,
    }
}

const fn is_settlement_checkpoint(phase: PrepareOperationPhase) -> bool {
    matches!(
        phase,
        PrepareOperationPhase::PromotionAdmitted
            | PrepareOperationPhase::SelectorSwitched
            | PrepareOperationPhase::Completed
    )
}

fn failure_text(e: &Failure) -> String {
    e.message().to_owned()
}

/// `preparedDependencySet` — assembles the set the candidate is staged
/// with and binds it to the build this operation performed (ADR 0024
/// Decision 1, Option 1B): the acquired mode is promoted as what was
/// built, every other mode is inherited from the lock unchanged. Defined
/// only for a selector acquired by building; a published selector here is
/// a bug in the acquisition branch and is refused rather than silently
/// falling back to lock inheritance.
///
/// # Errors
/// `UNKNOWN_SELECTOR`, `BUILD_REQUEST_INVALID`, `OCI_INVENTORY_INVALID`,
/// `PREPARED_IDENTITY_DRIFT`, `MISSING_SERVICE_MODE`, or a B03 refusal.
pub fn prepared_dependency_set(
    lock: &Lock,
    selector: &str,
    built: &OciInventory,
    comparison: &ComparisonFact,
) -> Result<PreparedDependencySet, Failure> {
    let prepared_mode = service_mode_for_selector(selector)?;
    if acquisition_kind_for(selector)? != AcquisitionKind::Built {
        return Err(Failure::invalid(
            codes::BUILD_REQUEST_INVALID,
            format!(
                "dependencyprepare: invalid build request: {selector:?} is admitted as a published image, so mode {prepared_mode} has no built identity to promote"
            ),
        ));
    }
    if built.index_digest.is_empty()
        || built.manifest_digest.is_empty()
        || built.config_digest.is_empty()
    {
        return Err(Failure::invalid(
            codes::OCI_INVENTORY_INVALID,
            format!(
                "dependencyprepare: invalid OCI inventory: build produced no identity for {prepared_mode}"
            ),
        ));
    }
    if comparison.index_digest != built.index_digest
        || comparison.inventory_digest != inventory_digest(built)
    {
        return Err(Failure::invalid(
            prepare_codes::PREPARED_IDENTITY_DRIFT,
            format!(
                "dependencyprepare: prepared identity drift: mode {prepared_mode} was built as {} but the comparison proved {}",
                built.index_digest, comparison.index_digest
            ),
        ));
    }
    let mut matched = false;
    let modes = lock
        .modes
        .iter()
        .map(|locked| {
            let inventory = if locked.mode == prepared_mode {
                matched = true;
                built.clone()
            } else {
                locked.inventory.clone()
            };
            PreparedMode {
                mode: locked.mode,
                inventory,
            }
        })
        .collect();
    if !matched {
        return Err(Failure::invalid(
            codes::MISSING_SERVICE_MODE,
            format!("dependencyprepare: lock has no mode {prepared_mode} to promote"),
        ));
    }
    let set = PreparedDependencySet { modes };
    set.validate_b03()?;
    Ok(set)
}

/// `attestationMaterials` — the binding every attestation must carry: the
/// lock, the source archive and commit, the locked bases, both builder
/// identities, the exact invocation, and the operation.
///
/// # Errors
/// A refusal of the trust materials, shared roots, differing invocations,
/// or an under-bound result.
pub fn attestation_materials(
    op: &PrepareOperation,
    lock: &Lock,
    one: &BuildRequest,
    two: &BuildRequest,
) -> Result<AttestationMaterials, Failure> {
    let mut materials = release_trust_materials(lock).map_err(|e| {
        Failure::invalid(
            codes::ATTESTATION_INVALID,
            format!("attestation materials: {}", e.message()),
        )
    })?;
    validate_independent_builds((&one.root_a, &one.root_b), (&two.root_a, &two.root_b)).map_err(
        |e| {
            Failure::invalid(
                codes::ATTESTATION_INVALID,
                format!("attestation materials: {}", e.message()),
            )
        },
    )?;
    if one.invocation_digest() != two.invocation_digest() {
        return Err(Failure::invalid(
            codes::ATTESTATION_INVALID,
            "attestation materials: the two builds ran different invocations",
        ));
    }
    materials.builder_identity_a = builder_identity(&one.root_a);
    materials.builder_identity_b = builder_identity(&two.root_a);
    materials.invocation_digest = one.invocation_digest();
    materials.operation_id.clone_from(&op.operation_id);
    materials.validate()?;
    Ok(materials)
}

// ---------------------------------------------------------------------------
// Progress tracker (`app/progress.go`)
// ---------------------------------------------------------------------------

/// The machine's own view of how far it has got — the only producer of
/// [`ProgressEvent`]. Everything it emits is a phase name, a count, or a
/// duration.
struct ProgressTracker {
    reporter: Option<Arc<dyn ProgressReporter>>,
    clock: Clock,
    start: OffsetDateTime,
    phase_at: OffsetDateTime,
    sent: usize,
    counters: SafeCounters,
    timings: Vec<StageTiming>,
}

impl ProgressTracker {
    fn new(reporter: Option<Arc<dyn ProgressReporter>>, clock: &Clock) -> Self {
        let now = clock();
        Self {
            reporter,
            clock: Arc::clone(clock),
            start: now,
            phase_at: now,
            sent: 0,
            counters: SafeCounters::default(),
            timings: Vec::new(),
        }
    }

    /// `report` — one event for the phase just entered. The bound belongs
    /// to the operation: a twenty-minute prepare cannot grow an unbounded
    /// stream on the root helper's side of the socket.
    fn report(&mut self, phase: PreparePhase) {
        let Some(reporter) = &self.reporter else {
            return;
        };
        if self.sent >= MAX_PROGRESS_EVENTS {
            return;
        }
        self.sent += 1;
        reporter.report(&ProgressEvent {
            phase,
            at: (self.clock)(),
            elapsed: self.elapsed(),
            safe_counters: self.counters.clone(),
        });
    }

    fn elapsed(&self) -> Duration {
        ((self.clock)() - self.start).unsigned_abs()
    }

    /// `closeStage` — how long the phase that just finished took; capped
    /// by `append_stage_timing` because a resumed operation re-enters
    /// phases.
    fn close_stage(&mut self, phase: PreparePhase) {
        let now = (self.clock)();
        append_stage_timing(
            &mut self.timings,
            phase,
            (now - self.phase_at).unsigned_abs(),
        );
        self.phase_at = now;
    }

    /// `decorate` — stamp a result with what the operation measured.
    fn decorate(&self, mut result: PrepareResult) -> PrepareResult {
        result.stage_timings.clone_from(&self.timings);
        result.counters = self.counters.resources();
        result.elapsed_ms = i64::try_from(self.elapsed().as_millis()).unwrap_or(i64::MAX);
        with_safe_next_action(result)
    }
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

/// What one pass of the loop holds in memory. Build evidence lives only for
/// the duration of a pass: an interrupted operation must rebuild rather than
/// inherit it.
#[derive(Default)]
struct Pass {
    request_one: Option<BuildRequest>,
    request_two: Option<BuildRequest>,
    inventory_a: Option<OciInventory>,
    inventory_b: Option<OciInventory>,
    comparison: Option<ComparisonFact>,
    facts: Vec<AttestationFact>,
    promotion: AdmissionBinding,
    /// Whether this pass produced the candidate it is about to settle. A
    /// resumed operation settling a candidate an earlier pass staged is a
    /// retention, not an acquisition.
    staged_here: bool,
}

/// `app.Service`.
pub struct PrepareState {
    journal: Arc<FileJournal>,
    verifier: Arc<dyn AdmissionVerifier>,
    builder: Arc<dyn Builder>,
    candidates: Arc<dyn CandidateSink>,
    lock: Lock,
    fetcher: Arc<dyn SourceFetcher>,
    capacity: Arc<dyn CapacityGate>,
    comparator: Option<Arc<dyn OciComparator>>,
    attestor: Option<Arc<dyn Attestor>>,
    image_loader: Option<Arc<dyn ImageLoader>>,
    reporter: Option<Arc<dyn ProgressReporter>>,
    selectors: Vec<String>,
    build_dir: PathBuf,
    clock: Clock,
    cancel: CancelFlag,
}

impl PrepareState {
    /// `NewService`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        journal: Arc<FileJournal>,
        verifier: Arc<dyn AdmissionVerifier>,
        builder: Arc<dyn Builder>,
        candidates: Arc<dyn CandidateSink>,
        lock: Lock,
        fetcher: Arc<dyn SourceFetcher>,
        capacity: Arc<dyn CapacityGate>,
        selectors: Vec<String>,
        build_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            journal,
            verifier,
            builder,
            candidates,
            lock,
            fetcher,
            capacity,
            comparator: None,
            attestor: None,
            image_loader: None,
            reporter: None,
            selectors,
            build_dir: build_dir.into(),
            clock: Arc::new(OffsetDateTime::now_utc),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// `WithAttestation` — the comparator and the attestor. Both are
    /// required before an operation can pass its comparison and attestation
    /// checkpoints: a service without them refuses to promote rather than
    /// treating an unproven build as proven.
    #[must_use]
    pub fn with_attestation(
        mut self,
        comparator: Arc<dyn OciComparator>,
        attestor: Arc<dyn Attestor>,
    ) -> Self {
        self.comparator = Some(comparator);
        self.attestor = Some(attestor);
        self
    }

    /// `WithImageLoader` — the step that makes the proven build resolvable
    /// in the host's image store. Without it the service refuses to stage
    /// rather than promoting a reference that resolves to nothing.
    #[must_use]
    pub fn with_image_loader(mut self, loader: Arc<dyn ImageLoader>) -> Self {
        self.image_loader = Some(loader);
        self
    }

    /// The progress sink (`port.ProgressReporter`).
    #[must_use]
    pub fn with_reporter(mut self, reporter: Arc<dyn ProgressReporter>) -> Self {
        self.reporter = Some(reporter);
        self
    }

    /// Replace the clock (tests).
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The cancellation flag (`ctx.Done()`); setting it makes the next loop
    /// iteration journal the operation terminal as `CONTEXT_CANCELLED`.
    #[must_use]
    pub fn with_cancel(mut self, cancel: CancelFlag) -> Self {
        self.cancel = cancel;
        self
    }

    /// The journal this service records into.
    #[must_use]
    pub fn journal(&self) -> &FileJournal {
        &self.journal
    }

    fn now(&self) -> OffsetDateTime {
        (self.clock)()
    }

    fn new_op(
        &self,
        id_suffix: &str,
        selector: &str,
        admission: &AdvisoryAdmission,
    ) -> PrepareOperation {
        let now = self.now();
        PrepareOperation {
            operation_id: format!("prepare-{}{id_suffix}", now.unix_timestamp_nanos()),
            phase: PrepareOperationPhase::CapacityAdmitted,
            admission_id: admission.receipt_id.clone(),
            selector: selector.to_owned(),
            deadline: now + OPERATION_BUDGET,
            reason: String::new(),
            reused: 0,
            acquired: 0,
            receipt_id: String::new(),
            created_at: now,
        }
    }

    /// `Prepare` — initiates a new operation, or signals that an unsettled
    /// one requires resume. One prepare at a time: the second caller is told
    /// the first must be resolved.
    pub fn prepare(&self, admission: &AdvisoryAdmission) -> PrepareResult {
        if let Some(op) = self.journal.unsettled() {
            return self.resume_required(&op);
        }
        self.start(admission)
    }

    /// `PrepareOne` — the full state machine for a single selector,
    /// bypassing the unsettled-operation guard, for outer-loop drivers that
    /// iterate over selectors.
    pub fn prepare_one(&self, admission: &AdvisoryAdmission, selector: &str) -> PrepareResult {
        let op = self.new_op(&format!("-{selector}"), selector, admission);
        if let Err(e) = self.journal.record(&op) {
            return self.terminal(&op, format!("RECORD_FAILED: {}", failure_text(&e)));
        }
        self.run(op)
    }

    /// `Resume` — settles an exact journalled operation. The ID is a trust
    /// boundary value (it arrives as `--resume=<id>`): an ID that is not a
    /// single safe path component is refused here, and the journal refuses
    /// it again on its side.
    pub fn resume(&self, id: &str) -> PrepareResult {
        if let Err(e) = valid_operation_id(id) {
            return self.terminal(
                &blank_op(),
                format!("INVALID_INVOCATION: {}", failure_text(&e)),
            );
        }
        let op = match self.journal.exact(id) {
            Ok(op) => op,
            Err(e) => {
                return self.terminal(
                    &blank_named(id),
                    format!("INVALID_INVOCATION: {}", failure_text(&e)),
                );
            }
        };
        if op.operation_id != id {
            return self.terminal(
                &blank_named(id),
                "INVALID_OPERATION_RECORD: journalled operation names a different ID".to_owned(),
            );
        }
        self.settle(op)
    }

    fn resume_required(&self, op: &PrepareOperation) -> PrepareResult {
        let mut r = result_from_op(op);
        r.exit_code = RESUME_EXIT_CODE;
        r.resume_required = true;
        r.reason = format!(
            "unsettled operation {} at phase {}",
            op.operation_id,
            op.phase.as_str()
        );
        with_safe_next_action(r)
    }

    fn start(&self, admission: &AdvisoryAdmission) -> PrepareResult {
        let Some(selector) = self.selectors.first() else {
            return self.terminal(&blank_op(), "NO_SELECTORS_CONFIGURED".to_owned());
        };
        let op = self.new_op("", selector, admission);
        if let Err(e) = self.journal.record(&op) {
            return self.terminal(&op, format!("RECORD_FAILED: {}", failure_text(&e)));
        }
        self.run(op)
    }

    fn settle(&self, mut op: PrepareOperation) -> PrepareResult {
        if op.phase.is_terminal() {
            // Terminal is not the same as completed: only a completed
            // operation settles successfully; failed and cancelled report
            // the failure they recorded. Built from the operation so the
            // counters it recorded survive a repeat call.
            let mut r = result_from_op(&op);
            r.exit_code = i32::from(op.phase != PrepareOperationPhase::Completed);
            return with_safe_next_action(r);
        }
        if !is_settlement_checkpoint(op.phase) {
            op.phase = PrepareOperationPhase::CapacityAdmitted;
        } else if op.receipt_id.is_empty() {
            return self.terminal(
                &op,
                "RESUME_UNSAFE_CHECKPOINT: settlement checkpoint names no staged candidate"
                    .to_owned(),
            );
        }
        self.run(op)
    }

    fn run(&self, op: PrepareOperation) -> PrepareResult {
        let mut progress = ProgressTracker::new(self.reporter.clone(), &self.clock);
        progress.report(map_authority_phase(op.phase));
        let result = self.run_phases(op, &mut progress);
        progress.decorate(result)
    }

    /// `failure`: journal the operation failed and hand back the
    /// operator-facing result. It takes the operation, not a result, so the
    /// record carries everything the operation knew.
    fn terminal(&self, op: &PrepareOperation, reason: String) -> PrepareResult {
        let mut op = op.clone();
        op.phase = PrepareOperationPhase::Failed;
        op.reason.clone_from(&reason);
        let mut r = result_from_op(&op);
        r.exit_code = 1;
        r.phase = PreparePhase::Failed;
        if !op.operation_id.is_empty()
            && let Err(e) = self.journal.record(&op)
        {
            r.reason = format!("{reason}; RECORD_FAILED: {}", failure_text(&e));
        }
        with_safe_next_action(r)
    }

    fn promotion_binding(
        &self,
        deadline: OpDeadline,
        op: &PrepareOperation,
    ) -> Result<AdmissionBinding, Failure> {
        if op.admission_id.is_empty() {
            return Err(Failure::invalid(
                codes::ADMISSION_BINDING_INVALID,
                format!("operation {:?} carries no admission", op.operation_id),
            ));
        }
        let admission = AdvisoryAdmission {
            receipt_id: op.admission_id.clone(),
        };
        let binding = self.verifier.verify_current(deadline, &admission)?;
        new_admission_binding(&binding.admission_receipt_id, &selector_token(&op.selector))
    }

    fn verify_admission(&self, deadline: OpDeadline, op: &PrepareOperation) -> Result<(), Failure> {
        if op.admission_id.is_empty() {
            return Err(Failure::invalid(
                codes::ADMISSION_BINDING_INVALID,
                format!("operation {:?} carries no admission", op.operation_id),
            ));
        }
        self.verifier
            .verify_current(
                deadline,
                &AdvisoryAdmission {
                    receipt_id: op.admission_id.clone(),
                },
            )
            .map(|_| ())
    }

    /// The request one hermetic build runs: the selector, the lock-pinned
    /// recipe, and every entitlement denied. The two builds share selector,
    /// recipe and entitlements — so their invocation identity is identical,
    /// which is what makes the comparison meaningful — and share no path at
    /// all (sharing roots would make the layouts compare equal whether or
    /// not the build was reproducible).
    fn build_request(&self, op: &PrepareOperation, ordinal: &str) -> Result<BuildRequest, Failure> {
        if acquisition_kind_for(&op.selector)? != AcquisitionKind::Built {
            return Err(Failure::invalid(
                codes::BUILD_REQUEST_INVALID,
                format!(
                    "dependencyprepare: invalid build request: {:?} is not built from a recipe",
                    op.selector
                ),
            ));
        }
        let recipe = self.lock.minio_recipe();
        if recipe.is_empty() {
            return Err(Failure::invalid(
                codes::BUILD_REQUEST_INVALID,
                format!(
                    "dependencyprepare: invalid build request: lock carries no recipe for {:?}",
                    op.selector
                ),
            ));
        }
        let root = self.build_dir.join(&op.operation_id).join(ordinal);
        new_build_request(
            &op.selector,
            recipe,
            &root.join("a").to_string_lossy(),
            &root.join("b").to_string_lossy(),
            false,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn run_phases(
        &self,
        mut op: PrepareOperation,
        progress: &mut ProgressTracker,
    ) -> PrepareResult {
        use PrepareOperationPhase as P;
        let mut phase = op.phase;
        let mut pass = Pass::default();

        // A selector this service has no acquisition path for is refused
        // before capacity, fetch, or build.
        match acquisition_kind_for(&op.selector) {
            Err(e) => return self.terminal(&op, format!("UNKNOWN_SELECTOR: {}", failure_text(&e))),
            Ok(AcquisitionKind::Built) => {}
            Ok(AcquisitionKind::Published) => {
                return self.terminal(
                    &op,
                    format!(
                        "SELECTOR_ACQUISITION_UNIMPLEMENTED: {:?} is admitted as a published image, not built; this service implements only the hermetic build path",
                        op.selector
                    ),
                );
            }
        }
        // A record that lost its deadline is refused by name, not by expiry.
        if op.deadline.year() <= 1 {
            return self.terminal(
                &op,
                "INVALID_OPERATION_RECORD: operation carries no deadline".to_owned(),
            );
        }

        loop {
            if self.cancel.load(Ordering::SeqCst) {
                progress.report(PreparePhase::Failed);
                return self.terminal(&op, "CONTEXT_CANCELLED: operation cancelled".to_owned());
            }
            let now = self.now();
            if now > op.deadline {
                progress.report(PreparePhase::Failed);
                return self.terminal(&op, "DEADLINE_EXCEEDED".to_owned());
            }
            let deadline = OpDeadline::after((op.deadline - now).unsigned_abs());

            match phase {
                P::CapacityAdmitted => {
                    match self.capacity.has_capacity(deadline, &op.selector) {
                        Err(e) => {
                            return self.terminal(
                                &op,
                                format!("CAPACITY_CHECK_FAILED: {}", failure_text(&e)),
                            );
                        }
                        Ok(false) => return self.terminal(&op, "CAPACITY_UNAVAILABLE".to_owned()),
                        Ok(true) => {}
                    }
                    // Asking whether the image store can resolve by manifest
                    // digest costs seconds here; after a fetch and two
                    // hermetic builds it costs the whole budget. A courtesy
                    // to the operator, not the correctness gate: the gate is
                    // the post-load inspection at the staging checkpoint.
                    let Some(loader) = &self.image_loader else {
                        return self.terminal(&op, "LOAD_UNCONFIGURED".to_owned());
                    };
                    if let Err(e) = loader.supported(deadline) {
                        return self.terminal(
                            &op,
                            format!("IMAGE_STORE_UNSUPPORTED: {}", failure_text(&e)),
                        );
                    }
                    phase = P::Acquiring;
                }
                P::Acquiring => {
                    let candidate = match self.fetcher.fetch(deadline, &op.selector) {
                        Ok(c) => c,
                        Err(e) => {
                            return self
                                .terminal(&op, format!("FETCH_FAILED: {}", failure_text(&e)));
                        }
                    };
                    op.selector = candidate.selector;
                    op.acquired += 1;
                    progress.counters.fetched += 1;
                    progress.counters.bytes_read += candidate.source_bytes;
                    phase = P::VerifiedInputs;
                }
                P::VerifiedInputs => {
                    if let Err(e) = self.verify_admission(deadline, &op) {
                        return self.terminal(&op, format!("VERIFY_FAILED: {}", failure_text(&e)));
                    }
                    phase = P::BuildOne;
                }
                P::BuildOne => {
                    progress.counters.build_count += 1;
                    let req = match self.build_request(&op, "one") {
                        Ok(r) => r,
                        Err(e) => {
                            return self
                                .terminal(&op, format!("BUILD_ONE_FAILED: {}", failure_text(&e)));
                        }
                    };
                    if let Err(e) =
                        self.fetcher
                            .stage_source(deadline, &op.selector, &req.context_dir())
                    {
                        return self.terminal(
                            &op,
                            format!("BUILD_ONE_FAILED: stage source: {}", failure_text(&e)),
                        );
                    }
                    match self.builder.build(deadline, &req) {
                        Ok(inv) => pass.inventory_a = Some(inv),
                        Err(e) => {
                            return self
                                .terminal(&op, format!("BUILD_ONE_FAILED: {}", failure_text(&e)));
                        }
                    }
                    pass.request_one = Some(req);
                    progress.counters.built += 1;
                    phase = P::BuildTwo;
                }
                P::BuildTwo => {
                    progress.counters.build_count += 1;
                    let req = match self.build_request(&op, "two") {
                        Ok(r) => r,
                        Err(e) => {
                            return self
                                .terminal(&op, format!("BUILD_TWO_FAILED: {}", failure_text(&e)));
                        }
                    };
                    // Asserted rather than assumed: the comparison is only
                    // evidence of reproducibility if the builds were
                    // independent.
                    let Some(one) = &pass.request_one else {
                        return self.terminal(&op, "BUILD_TWO_FAILED: no first build".to_owned());
                    };
                    if let Err(e) = validate_independent_builds(
                        (&one.root_a, &one.root_b),
                        (&req.root_a, &req.root_b),
                    ) {
                        return self
                            .terminal(&op, format!("BUILD_TWO_FAILED: {}", failure_text(&e)));
                    }
                    if let Err(e) =
                        self.fetcher
                            .stage_source(deadline, &op.selector, &req.context_dir())
                    {
                        return self.terminal(
                            &op,
                            format!("BUILD_TWO_FAILED: stage source: {}", failure_text(&e)),
                        );
                    }
                    match self.builder.build(deadline, &req) {
                        Ok(inv) => pass.inventory_b = Some(inv),
                        Err(e) => {
                            return self
                                .terminal(&op, format!("BUILD_TWO_FAILED: {}", failure_text(&e)));
                        }
                    }
                    pass.request_two = Some(req);
                    progress.counters.built += 1;
                    phase = P::Compared;
                }
                P::Compared => {
                    let Some(comparator) = &self.comparator else {
                        return self.terminal(&op, "COMPARE_UNCONFIGURED".to_owned());
                    };
                    let (Some(a), Some(b)) = (&pass.inventory_a, &pass.inventory_b) else {
                        return self.terminal(&op, "COMPARE_FAILED: no build evidence".to_owned());
                    };
                    let fact = match comparator
                        .compare(a, b)
                        .and_then(|f| f.validate().map(|()| f))
                    {
                        Ok(f) => f,
                        Err(e) => {
                            return self
                                .terminal(&op, format!("COMPARE_FAILED: {}", failure_text(&e)));
                        }
                    };
                    pass.comparison = Some(fact);
                    progress.counters.compared += 1;
                    phase = P::Attested;
                }
                // Attestations are generated and verified only after the two
                // builds have been proven equal, and they bind that exact
                // layout.
                P::Attested => {
                    let Some(attestor) = &self.attestor else {
                        return self.terminal(&op, "ATTEST_UNCONFIGURED".to_owned());
                    };
                    let (Some(inv), Some(one), Some(two), Some(comparison)) = (
                        &pass.inventory_a,
                        &pass.request_one,
                        &pass.request_two,
                        &pass.comparison,
                    ) else {
                        return self.terminal(&op, "ATTEST_FAILED: no build evidence".to_owned());
                    };
                    let subject = subject_from_inventory(&op.selector, inv);
                    let verified = attestation_materials(&op, &self.lock, one, two)
                        .and_then(|m| attestor.attest(deadline, &subject, &m))
                        .and_then(|facts| {
                            validate_attestation_facts(&facts, &subject.index_digest)?;
                            Ok(facts)
                        });
                    let facts = match verified {
                        Ok(f) => f,
                        Err(e) => {
                            return self
                                .terminal(&op, format!("ATTEST_FAILED: {}", failure_text(&e)));
                        }
                    };
                    if let Err(e) = persist_op_artifacts(
                        &self.build_dir,
                        &op.operation_id,
                        &one.export_path().to_string_lossy(),
                        comparison,
                    ) {
                        return self.terminal(&op, format!("ATTEST_FAILED: {}", failure_text(&e)));
                    }
                    pass.facts = facts;
                    phase = P::CandidateStaged;
                }
                P::CandidateStaged => {
                    let (Some(inv), Some(one), Some(comparison)) =
                        (&pass.inventory_a, &pass.request_one, &pass.comparison)
                    else {
                        return self.terminal(&op, "STAGE_FAILED: no build evidence".to_owned());
                    };
                    if let Err(e) = comparison.validate() {
                        return self.terminal(&op, format!("STAGE_FAILED: {}", failure_text(&e)));
                    }
                    let prepared =
                        match prepared_dependency_set(&self.lock, &op.selector, inv, comparison) {
                            Ok(p) => p,
                            Err(e) => {
                                return self.terminal(
                                    &op,
                                    format!("PROMOTION_REJECTED: {}", failure_text(&e)),
                                );
                            }
                        };
                    if let Err(e) =
                        validate_attestation_facts(&pass.facts, &comparison.index_digest)
                    {
                        return self.terminal(&op, format!("STAGE_FAILED: {}", failure_text(&e)));
                    }
                    // The proven build becomes resolvable on this host here,
                    // and only here. Not earlier: nothing before the
                    // comparison proved anything, and the attestation is
                    // issued over this exact layout, so loading before it
                    // could leave the image store holding an image whose
                    // attestation then failed. Not later: a staged candidate
                    // must be resolvable — loading after the selector switch
                    // would leave a window where the active receipt names an
                    // image the host cannot resolve, and a crash in that
                    // window resumes at a settlement checkpoint that never
                    // rebuilds and so never loads. Build one's export is
                    // loaded because inventory A is the identity the
                    // attestation binds and the receipt promotes. Resume
                    // safety follows from `settle`: every pre-staging phase
                    // rewinds to capacity, so a resumed pass re-proves
                    // equality before re-loading, and repeating the load is
                    // a no-op onto the same name and digest.
                    let Some(loader) = &self.image_loader else {
                        return self.terminal(&op, "LOAD_UNCONFIGURED".to_owned());
                    };
                    let load_req = ImageLoadRequest {
                        selector: op.selector.clone(),
                        export: one.export_path().to_string_lossy().into_owned(),
                        proven: inv.clone(),
                    };
                    if let Err(e) = load_req.validate() {
                        return self.terminal(&op, format!("LOAD_FAILED: {}", failure_text(&e)));
                    }
                    let loaded = match loader.load(deadline, &load_req) {
                        Ok(l) => l,
                        Err(e) => {
                            return self
                                .terminal(&op, format!("LOAD_FAILED: {}", failure_text(&e)));
                        }
                    };
                    if let Err(e) = validate_loaded_image(&loaded, inv) {
                        return self
                            .terminal(&op, format!("LOAD_UNRESOLVABLE: {}", failure_text(&e)));
                    }
                    let staged = self.candidates.stage(
                        deadline,
                        &Candidate {
                            operation_id: op.operation_id.clone(),
                            selector: op.selector.clone(),
                            phase: Some(PreparePhase::Staging),
                            dependency_set: prepared,
                            comparison: comparison.clone(),
                            attestations: pass.facts.clone(),
                            ..Candidate::default()
                        },
                    );
                    match staged {
                        Ok(c) => op.receipt_id = c.id,
                        Err(e) => {
                            return self
                                .terminal(&op, format!("STAGE_FAILED: {}", failure_text(&e)));
                        }
                    }
                    pass.staged_here = true;
                    progress.counters.staged += 1;
                    phase = P::PromotionAdmitted;
                }
                // Promotion admission is a fresh authority check taken while
                // lifecycle ownership is still held and immediately before
                // the selector moves.
                P::PromotionAdmitted => {
                    match self.promotion_binding(deadline, &op) {
                        Ok(b) => pass.promotion = b,
                        Err(e) => {
                            return self.terminal(
                                &op,
                                format!("PROMOTION_REJECTED: {}", failure_text(&e)),
                            );
                        }
                    }
                    phase = P::SelectorSwitched;
                }
                P::SelectorSwitched => {
                    if op.receipt_id.is_empty() {
                        return self.terminal(
                            &op,
                            "SWITCH_FAILED: operation names no staged candidate".to_owned(),
                        );
                    }
                    if pass.promotion.is_zero() {
                        // Reached only on a resume that re-enters at this
                        // checkpoint: take the promotion admission now,
                        // never skip it.
                        match self.promotion_binding(deadline, &op) {
                            Ok(b) => pass.promotion = b,
                            Err(e) => {
                                return self
                                    .terminal(&op, format!("SWITCH_FAILED: {}", failure_text(&e)));
                            }
                        }
                    }
                    // Recover repeats exactly the switch the staged candidate
                    // was prepared for, reading selector and dependency set
                    // back from the staged manifest, not this loop's copy.
                    let receipt =
                        match self
                            .candidates
                            .recover(deadline, &op.receipt_id, &pass.promotion)
                        {
                            Ok(r) => r,
                            Err(e) => {
                                return self
                                    .terminal(&op, format!("SWITCH_FAILED: {}", failure_text(&e)));
                            }
                        };
                    if let Err(e) = receipt.validate_b03() {
                        return self.terminal(
                            &op,
                            format!("SWITCH_REINSPECTION_FAILED: {}", failure_text(&e)),
                        );
                    }
                    if !pass.staged_here {
                        // Settled a candidate an earlier pass staged and the
                        // interruption preserved: a retention, not an
                        // acquisition.
                        op.reused += 1;
                    }
                    op.receipt_id = receipt.id;
                    phase = P::Completed;
                }
                P::Completed => {
                    "completed".clone_into(&mut op.reason);
                    let mut r = result_from_op(&op);
                    r.exit_code = 0;
                    r.phase = PreparePhase::Ready;
                    let _ = self.journal.record(&op);
                    return r;
                }
                P::Failed | P::Cancelled => {
                    return self.terminal(&op, "INVALID_PHASE".to_owned());
                }
            }

            progress.close_stage(map_authority_phase(op.phase));
            op.phase = phase;
            progress.report(map_authority_phase(phase));
            if let Err(e) = self.journal.record(&op) {
                return self.terminal(&op, format!("RECORD_FAILED: {}", failure_text(&e)));
            }
        }
    }
}

/// `persistOpArtifacts` — writes the export bundle's build-side inputs
/// beside the builds: the proven comparison and build one's export path.
/// The attestor persists the envelopes itself; the exporter reads all three
/// from here.
///
/// # Errors
/// `OPERATION_ID_INVALID` or `internal` on a write failure.
pub fn persist_op_artifacts(
    build_dir: &std::path::Path,
    operation_id: &str,
    export_path: &str,
    comparison: &ComparisonFact,
) -> Result<(), Failure> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    valid_operation_id(operation_id)?;
    let dir = build_dir.join(operation_id);
    let io = |what: &str, e: std::io::Error| {
        Failure::internal("PREPARE_ARTIFACTS", format!("{what}: {e}"))
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| io("create op artifact dir", e))?;
    let write = |name: &str, data: &[u8]| -> Result<(), Failure> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join(name))
            .map_err(|e| io(&format!("persist {name}"), e))?;
        std::io::Write::write_all(&mut f, data).map_err(|e| io(&format!("persist {name}"), e))
    };
    let raw = serde_json::to_vec(comparison)
        .map_err(|e| Failure::internal("PREPARE_ARTIFACTS", format!("encode comparison: {e}")))?;
    write("comparison.json", &raw)?;
    write(
        "build-one-export.txt",
        format!("{export_path}\n").as_bytes(),
    )
}

/// Go's `time.Time{}` — January 1, year 1 — which `IsZero` checks upstream.
const GO_ZERO_TIME: OffsetDateTime = time::macros::datetime!(0001-01-01 0:00 UTC);

fn blank_named(id: &str) -> PrepareOperation {
    PrepareOperation {
        operation_id: id.to_owned(),
        phase: PrepareOperationPhase::Failed,
        admission_id: String::new(),
        selector: String::new(),
        deadline: GO_ZERO_TIME,
        reason: String::new(),
        reused: 0,
        acquired: 0,
        receipt_id: String::new(),
        created_at: GO_ZERO_TIME,
    }
}

fn blank_op() -> PrepareOperation {
    blank_named("")
}

fn result_from_op(op: &PrepareOperation) -> PrepareResult {
    PrepareResult {
        exit_code: 0,
        reason: op.reason.clone(),
        operation_id: op.operation_id.clone(),
        receipt_id: op.receipt_id.clone(),
        phase: map_authority_phase(op.phase),
        resume_required: false,
        reused: i64::from(op.reused),
        acquired: i64::from(op.acquired),
        safe_next_action: central_infra::prepare::SafeNextAction::None,
        stage_timings: Vec::new(),
        counters: central_infra::prepare::ResourceCounters::default(),
        elapsed_ms: 0,
        admission_id: op.admission_id.clone(),
        selector: op.selector.clone(),
        deadline: op.deadline,
        created_at: op.created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::prepare::LockAdapter;
    use crate::infra::prepare::attestation::{AttestationService, AttestationSigner};
    use crate::infra::prepare::image_load::{DockerExec, DockerImageLoader};
    use central_infra::prepare::{AttestationTrustPolicy, TrustedKey};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    type Log = Arc<Mutex<Vec<String>>>;

    fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    fn built() -> OciInventory {
        OciInventory {
            index_digest: digest('1'),
            manifest_digest: digest('2'),
            config_digest: digest('3'),
            layers: vec![],
        }
    }

    struct Verifier {
        calls: AtomicUsize,
        fail_from: usize,
    }

    impl AdmissionVerifier for Verifier {
        fn verify_current(
            &self,
            _: OpDeadline,
            admission: &AdvisoryAdmission,
        ) -> Result<AdmissionBinding, Failure> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if n >= self.fail_from {
                return Err(Failure::denied("ADVISORY", "advisory no longer current"));
            }
            new_admission_binding(&admission.receipt_id, "unused")
        }
    }

    struct FakeBuilder {
        log: Log,
        second: Option<OciInventory>,
        calls: AtomicUsize,
    }

    impl Builder for FakeBuilder {
        fn build(&self, _: OpDeadline, _: &BuildRequest) -> Result<OciInventory, Failure> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            self.log
                .lock()
                .expect("log")
                .push(format!("build{}", n + 1));
            match (&self.second, n) {
                (Some(other), 1) => Ok(other.clone()),
                _ => Ok(built()),
            }
        }
    }

    struct FakeFetcher;

    impl SourceFetcher for FakeFetcher {
        fn fetch(&self, _: OpDeadline, _: &str) -> Result<Candidate, Failure> {
            Ok(Candidate {
                selector: "minio".to_owned(),
                source_bytes: 100,
                ..Candidate::default()
            })
        }

        fn stage_source(&self, _: OpDeadline, _: &str, _: &std::path::Path) -> Result<(), Failure> {
            Ok(())
        }
    }

    struct Capacity(bool);

    impl CapacityGate for Capacity {
        fn has_capacity(&self, _: OpDeadline, _: &str) -> Result<bool, Failure> {
            Ok(self.0)
        }
    }

    struct Sink {
        log: Log,
        staged: Mutex<Option<Candidate>>,
    }

    impl CandidateSink for Sink {
        fn stage(&self, _: OpDeadline, c: &Candidate) -> Result<Candidate, Failure> {
            self.log.lock().expect("log").push("stage".to_owned());
            c.dependency_set.validate_b03()?;
            let mut staged = c.clone();
            staged.id = "cand-1".to_owned();
            *self.staged.lock().expect("staged") = Some(staged.clone());
            Ok(staged)
        }

        fn recover(
            &self,
            _: OpDeadline,
            id: &str,
            binding: &AdmissionBinding,
        ) -> Result<DependencyReceipt, Failure> {
            self.log.lock().expect("log").push(format!("recover:{id}"));
            assert!(!binding.is_zero());
            let set = self
                .staged
                .lock()
                .expect("staged")
                .as_ref()
                .map(|c| c.dependency_set.clone());
            Ok(DependencyReceipt {
                id: id.to_owned(),
                dependency_set: set.unwrap_or_else(|| {
                    prepared_dependency_set(
                        LockAdapter::new().expect("lock").lock(),
                        "minio",
                        &built(),
                        &Comparator.compare(&built(), &built()).expect("cmp"),
                    )
                    .expect("set")
                }),
                ..DependencyReceipt::default()
            })
        }
    }

    struct Fixture {
        state: PrepareState,
        log: Log,
        root: PathBuf,
        journal: Arc<FileJournal>,
        builds: Arc<FakeBuilder>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct Opts {
        capacity_denied: bool,
        no_loader: bool,
        classic_store: bool,
        no_attestor: bool,
        no_comparator: bool,
        mismatched_build: bool,
        verifier_fail_from: Option<usize>,
    }

    fn fixture(opts: &Opts) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "central-pp-sm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let journal = Arc::new(FileJournal::new(root.join("journal")).expect("journal"));
        let log: Log = Arc::default();
        let lock = LockAdapter::new().expect("lock").lock().clone();
        let builds = Arc::new(FakeBuilder {
            log: Arc::clone(&log),
            second: opts.mismatched_build.then(|| OciInventory {
                index_digest: digest('9'),
                ..built()
            }),
            calls: AtomicUsize::new(0),
        });
        let sink = Arc::new(Sink {
            log: Arc::clone(&log),
            staged: Mutex::new(None),
        });
        let mut state = PrepareState::new(
            Arc::clone(&journal),
            Arc::new(Verifier {
                calls: AtomicUsize::new(0),
                fail_from: opts.verifier_fail_from.unwrap_or(usize::MAX),
            }),
            Arc::clone(&builds) as Arc<dyn Builder>,
            sink,
            lock,
            Arc::new(FakeFetcher),
            Arc::new(Capacity(!opts.capacity_denied)),
            vec!["minio".to_owned()],
            root.join("build"),
        );
        if !opts.no_comparator {
            state.comparator = Some(Arc::new(Comparator));
        }
        if !opts.no_attestor {
            let seed = [5u8; 32];
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let mut private = seed.to_vec();
            private.extend_from_slice(&key.verifying_key().to_bytes());
            let signer = AttestationSigner::from_private_key("k1", &private).expect("signer");
            let policy = AttestationTrustPolicy {
                keys: vec![TrustedKey {
                    key_id: "k1".to_owned(),
                    public_key: signer.public_key_hex(),
                    expires_at: None,
                    revoked: false,
                }],
            };
            state.attestor = Some(Arc::new(
                AttestationService::new(signer, policy).expect("service"),
            ));
        }
        if !opts.no_loader {
            let classic = opts.classic_store;
            let exec_log = Arc::clone(&log);
            let exec: DockerExec = Box::new(move |_, args, _, _| {
                exec_log
                    .lock()
                    .expect("log")
                    .push(format!("docker:{}", args[0]));
                match args[0].as_str() {
                    "info" if classic => Ok(br#"[["x","y"]]"#.to_vec()),
                    "info" => Ok(br#"[["driver-type","io.containerd.snapshotter.v1"]]"#.to_vec()),
                    "image" => Ok(format!("{}\n", digest('2')).into_bytes()),
                    _ => Ok(Vec::new()),
                }
            });
            state.image_loader = Some(Arc::new(
                DockerImageLoader::new("/usr/bin/docker").with_exec(exec),
            ));
        }
        Fixture {
            state,
            log,
            root,
            journal,
            builds,
        }
    }

    fn admission() -> AdvisoryAdmission {
        AdvisoryAdmission {
            receipt_id: "adm-1".to_owned(),
        }
    }

    fn seed_op(f: &Fixture, id: &str, phase: PrepareOperationPhase, receipt: &str) {
        let now = OffsetDateTime::now_utc();
        f.journal
            .record(&PrepareOperation {
                operation_id: id.to_owned(),
                phase,
                admission_id: "adm-1".to_owned(),
                selector: "minio".to_owned(),
                deadline: now + Duration::from_secs(600),
                reason: String::new(),
                reused: 0,
                acquired: 1,
                receipt_id: receipt.to_owned(),
                created_at: now,
            })
            .expect("seed");
    }

    fn events(f: &Fixture) -> Vec<String> {
        f.log.lock().expect("log").clone()
    }

    #[test]
    fn happy_path_loads_before_staging_and_completes() {
        let f = fixture(&Opts::default());
        let r = f.state.prepare(&admission());
        assert_eq!(r.exit_code, 0, "{}", r.reason);
        assert_eq!(r.phase, PreparePhase::Ready);
        assert_eq!(r.receipt_id, "cand-1");
        assert_eq!((r.acquired, r.reused), (1, 0));
        assert_eq!(
            (
                r.counters.fetched,
                r.counters.built,
                r.counters.compared,
                r.counters.staged
            ),
            (1, 2, 1, 1)
        );
        assert_eq!(r.counters.bytes_read, 100);
        assert!(!r.stage_timings.is_empty());
        let ev = events(&f);
        let pos = |needle: &str| ev.iter().position(|e| e == needle).expect(needle);
        assert!(pos("build2") < pos("docker:load"), "{ev:?}");
        assert!(
            pos("docker:tag") < pos("stage"),
            "load+pin precede staging: {ev:?}"
        );
        assert!(pos("stage") < pos("recover:cand-1"), "{ev:?}");
        let op = f.journal.exact(&r.operation_id).expect("journalled");
        assert_eq!(op.phase, PrepareOperationPhase::Completed);
        assert!(f.journal.unsettled().is_none());
        let dir = f.root.join("build").join(&r.operation_id);
        assert!(dir.join("comparison.json").is_file());
        assert!(dir.join("build-one-export.txt").is_file());
    }

    #[test]
    fn independent_build_roots_and_attestation_binding() {
        let f = fixture(&Opts::default());
        let op = blank_named("prepare-x");
        let one = f.state.build_request(&op, "one");
        assert!(one.is_err(), "blank selector is refused");
        let mut op = blank_named("prepare-x");
        op.selector = "minio".to_owned();
        let one = f.state.build_request(&op, "one").expect("one");
        let two = f.state.build_request(&op, "two").expect("two");
        assert_ne!(one.root_a, two.root_a);
        assert_eq!(one.invocation_digest(), two.invocation_digest());
        let m = attestation_materials(&op, &f.state.lock, &one, &two).expect("materials");
        assert_eq!(m.operation_id, "prepare-x");
        assert_ne!(m.builder_identity_a, m.builder_identity_b);
        let same = attestation_materials(&op, &f.state.lock, &one, &one);
        assert!(same.is_err(), "shared roots are refused");
    }

    #[test]
    fn mismatched_builds_fail_before_attestation_load_or_stage() {
        let f = fixture(&Opts {
            mismatched_build: true,
            ..Opts::default()
        });
        let r = f.state.prepare(&admission());
        assert_eq!(r.exit_code, 1);
        assert!(r.reason.starts_with("COMPARE_FAILED"), "{}", r.reason);
        let ev = events(&f);
        assert!(
            !ev.iter().any(|e| e == "stage" || e == "docker:load"),
            "{ev:?}"
        );
        assert_eq!(
            f.journal.exact(&r.operation_id).expect("op").phase,
            PrepareOperationPhase::Failed
        );
    }

    #[test]
    fn missing_ports_refuse_to_promote() {
        for (opts, want) in [
            (
                Opts {
                    no_comparator: true,
                    ..Opts::default()
                },
                "COMPARE_UNCONFIGURED",
            ),
            (
                Opts {
                    no_attestor: true,
                    ..Opts::default()
                },
                "ATTEST_UNCONFIGURED",
            ),
            (
                Opts {
                    no_loader: true,
                    ..Opts::default()
                },
                "LOAD_UNCONFIGURED",
            ),
            (
                Opts {
                    capacity_denied: true,
                    ..Opts::default()
                },
                "CAPACITY_UNAVAILABLE",
            ),
            (
                Opts {
                    classic_store: true,
                    ..Opts::default()
                },
                "IMAGE_STORE_UNSUPPORTED",
            ),
        ] {
            let f = fixture(&opts);
            let r = f.state.prepare(&admission());
            assert_eq!(r.exit_code, 1);
            assert!(r.reason.starts_with(want), "{want}: {}", r.reason);
            assert!(!events(&f).iter().any(|e| e == "stage"));
        }
    }

    #[test]
    fn unsettled_operation_requires_resume() {
        let f = fixture(&Opts::default());
        seed_op(&f, "prepare-live", PrepareOperationPhase::BuildOne, "");
        let r = f.state.prepare(&admission());
        assert_eq!(r.exit_code, RESUME_EXIT_CODE);
        assert!(r.resume_required);
        assert_eq!(r.operation_id, "prepare-live");
        assert_eq!(
            r.safe_next_action,
            central_infra::prepare::SafeNextAction::Resume
        );
    }

    #[test]
    fn resume_before_staging_rewinds_to_capacity_and_rebuilds() {
        let f = fixture(&Opts::default());
        seed_op(&f, "prepare-live", PrepareOperationPhase::BuildTwo, "");
        let r = f.state.resume("prepare-live");
        assert_eq!(r.exit_code, 0, "{}", r.reason);
        assert_eq!(f.builds.calls.load(Ordering::SeqCst), 2, "rebuilt both");
        assert!(
            events(&f).iter().any(|e| e == "docker:info"),
            "capacity checkpoint repeated"
        );
    }

    #[test]
    fn resume_at_a_settlement_checkpoint_repeats_the_switch_without_rebuilding() {
        let f = fixture(&Opts::default());
        seed_op(
            &f,
            "prepare-live",
            PrepareOperationPhase::PromotionAdmitted,
            "cand-1",
        );
        let r = f.state.resume("prepare-live");
        assert_eq!(r.exit_code, 0, "{}", r.reason);
        assert_eq!(f.builds.calls.load(Ordering::SeqCst), 0);
        assert_eq!(r.reused, 1, "settling a survived candidate is a retention");
        assert_eq!(events(&f), ["recover:cand-1"]);
    }

    #[test]
    fn settlement_checkpoint_without_a_candidate_is_unsafe() {
        let f = fixture(&Opts::default());
        seed_op(
            &f,
            "prepare-live",
            PrepareOperationPhase::SelectorSwitched,
            "",
        );
        let r = f.state.resume("prepare-live");
        assert_eq!(r.exit_code, 1);
        assert!(
            r.reason.starts_with("RESUME_UNSAFE_CHECKPOINT"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn terminal_operations_settle_by_what_they_recorded() {
        let f = fixture(&Opts::default());
        seed_op(&f, "done", PrepareOperationPhase::Completed, "cand-1");
        seed_op(&f, "broken", PrepareOperationPhase::Failed, "");
        seed_op(&f, "stopped", PrepareOperationPhase::Cancelled, "");
        assert_eq!(f.state.resume("done").exit_code, 0);
        assert_eq!(f.state.resume("broken").exit_code, 1);
        assert_eq!(f.state.resume("stopped").exit_code, 1);
        assert!(events(&f).is_empty(), "nothing re-executed");
    }

    #[test]
    fn resume_refuses_unsafe_and_unknown_ids_without_touching_paths() {
        let f = fixture(&Opts::default());
        for id in ["", "..", "../escape", "a/b"] {
            let r = f.state.resume(id);
            assert_eq!(r.exit_code, 1, "{id:?}");
            assert!(
                r.reason.starts_with("INVALID_INVOCATION"),
                "{id:?}: {}",
                r.reason
            );
        }
        assert!(!f.root.join("escape.json").exists());
        let r = f.state.resume("never-recorded");
        assert!(r.reason.starts_with("INVALID_INVOCATION"), "{}", r.reason);
    }

    #[test]
    fn deadline_cancellation_and_lost_deadline_fail_by_name() {
        let f = fixture(&Opts::default());
        let now = OffsetDateTime::now_utc();
        let mut op = blank_named("prepare-late");
        op.phase = PrepareOperationPhase::CapacityAdmitted;
        op.selector = "minio".to_owned();
        op.admission_id = "adm-1".to_owned();
        op.created_at = now;
        op.deadline = now - Duration::from_secs(1);
        f.journal.record(&op).expect("record");
        let r = f.state.resume("prepare-late");
        assert_eq!(r.reason, "DEADLINE_EXCEEDED");

        op.operation_id = "prepare-nodeadline".to_owned();
        op.deadline = GO_ZERO_TIME;
        f.journal.record(&op).expect("record");
        let r = f.state.resume("prepare-nodeadline");
        assert!(
            r.reason.starts_with("INVALID_OPERATION_RECORD"),
            "{}",
            r.reason
        );

        let flag: CancelFlag = Arc::new(AtomicBool::new(true));
        let mut f2 = fixture(&Opts::default());
        f2.state.cancel = flag;
        let r = f2.state.prepare(&admission());
        assert!(r.reason.starts_with("CONTEXT_CANCELLED"), "{}", r.reason);
    }

    #[test]
    fn published_selector_is_not_built_by_this_service() {
        let f = fixture(&Opts::default());
        let r = f.state.prepare_one(&admission(), "postgresql");
        assert!(
            r.reason.starts_with("SELECTOR_ACQUISITION_UNIMPLEMENTED"),
            "{}",
            r.reason
        );
        let r = f.state.prepare_one(&admission(), "mystery");
        assert!(r.reason.starts_with("UNKNOWN_SELECTOR"), "{}", r.reason);
        assert!(events(&f).is_empty());
    }

    #[test]
    fn promotion_admission_is_taken_fresh_and_refusal_leaves_the_candidate_unswitched() {
        let f = fixture(&Opts {
            verifier_fail_from: Some(2),
            ..Opts::default()
        });
        let r = f.state.prepare(&admission());
        assert!(r.reason.starts_with("PROMOTION_REJECTED"), "{}", r.reason);
        let ev = events(&f);
        assert!(ev.iter().any(|e| e == "stage"));
        assert!(!ev.iter().any(|e| e.starts_with("recover")), "{ev:?}");
    }

    #[test]
    fn prepared_set_promotes_only_the_built_mode_and_inherits_the_rest() {
        let lock = LockAdapter::new().expect("lock").lock().clone();
        let cmp = Comparator.compare(&built(), &built()).expect("cmp");
        let set = prepared_dependency_set(&lock, "minio", &built(), &cmp).expect("set");
        let promoted: Vec<_> = set
            .modes
            .iter()
            .filter(|m| m.inventory == built())
            .collect();
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].mode, central_infra::domain::ServiceMode::Minio);
        for (got, locked) in set.modes.iter().zip(&lock.modes) {
            if got.mode != central_infra::domain::ServiceMode::Minio {
                assert_eq!(got.inventory, locked.inventory);
            }
        }
        assert!(prepared_dependency_set(&lock, "postgresql", &built(), &cmp).is_err());
        assert!(prepared_dependency_set(&lock, "other", &built(), &cmp).is_err());
        let mut drift = cmp.clone();
        drift.index_digest = digest('7');
        assert_eq!(
            prepared_dependency_set(&lock, "minio", &built(), &drift)
                .expect_err("drift")
                .code(),
            prepare_codes::PREPARED_IDENTITY_DRIFT
        );
        let incomplete = OciInventory {
            config_digest: String::new(),
            ..built()
        };
        assert!(prepared_dependency_set(&lock, "minio", &incomplete, &cmp).is_err());
    }

    #[test]
    fn authority_phase_projection_is_the_documented_one() {
        use PrepareOperationPhase as P;
        for (p, want) in [
            (P::CapacityAdmitted, PreparePhase::Acquiring),
            (P::Acquiring, PreparePhase::Acquiring),
            (P::VerifiedInputs, PreparePhase::Pending),
            (P::BuildOne, PreparePhase::Building),
            (P::Attested, PreparePhase::Building),
            (P::CandidateStaged, PreparePhase::Staging),
            (P::SelectorSwitched, PreparePhase::Staging),
            (P::Completed, PreparePhase::Ready),
            (P::Failed, PreparePhase::Failed),
            (P::Cancelled, PreparePhase::Failed),
        ] {
            assert_eq!(map_authority_phase(p), want, "{p:?}");
        }
    }

    #[test]
    fn progress_is_bounded_and_carries_only_safe_fields() {
        struct Sink(Mutex<Vec<ProgressEvent>>);
        impl ProgressReporter for Sink {
            fn report(&self, e: &ProgressEvent) {
                self.0.lock().expect("sink").push(e.clone());
            }
        }
        let sink = Arc::new(Sink(Mutex::default()));
        let mut f = fixture(&Opts::default());
        f.state.reporter = Some(Arc::clone(&sink) as Arc<dyn ProgressReporter>);
        let r = f.state.prepare(&admission());
        assert_eq!(r.exit_code, 0);
        let events = sink.0.lock().expect("sink");
        assert!(!events.is_empty() && events.len() <= MAX_PROGRESS_EVENTS);
        assert_eq!(events.last().expect("last").phase, PreparePhase::Ready);
    }
}
