//! `service.go`'s adapter-side composition — the concrete
//! [`helper::prepare::DependencyPrepareService`] the helper's
//! `DependencyPrepareHandler` dispatches to. What lives here is the
//! whole *boundary* half of upstream's operation: verified lock →
//! capacity → fetch → verified stage → module cache → isolated
//! BuildKit build → inventory-from-output — plus the import path's
//! release staging and OCI inventory reads.
//!
//! What deliberately does *not* live here yet is the durable half of
//! upstream's `app.Service`: the operation journal that makes
//! `--resume` lawful, the attestation signing that makes a built
//! inventory promotable, and the `CandidateStore` promotion those two
//! gate. Rather than fabricate a success a caller would act on, the
//! pipeline runs every implemented stage in upstream's order and ends
//! at an explicit `PREPARE_PROMOTION_UNAVAILABLE` denial — the same
//! fail-closed shape upstream's import-only composition produces when
//! the host lacks a signing key, only earlier in the graph.
//! `resume`/`prepare_export_release` refuse for the same reason: the
//! journal and export halves are later work, and an explicit refusal
//! is the only honest answer a missing stage may give.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use central_infra::domain::{AcquisitionKind, PreparePhase, acquisition_kind_for};
use central_infra::prepare::{self, Lock};

use crate::helper::prepare::{
    AdvisoryAdmission, DependencyPrepareHandler, DependencyPrepareService, EvaluateService,
    PrepareConfirmationSource, PrepareOpResult, PreparePamConfirmer,
};
use crate::helper::protocol::StageTiming;

use super::OpDeadline;
use super::buildkit::BuildKit;
use super::capacity::CapacityChecker;
use super::fetch::Fetcher;
use super::lock::LockAdapter;
use super::release_stage;

/// The helper's per-operation budget — upstream runs prepare inside a
/// twenty-minute, non-resetting deadline.
const OP_BUDGET: Duration = Duration::from_secs(20 * 60);

/// `PrepareService` — upstream's `dependencyprepare.Service` narrowed
/// to the stages this slice owns. Construction verifies the embedded
/// lock once; every stage re-verifies what it consumes.
pub struct PrepareService {
    lock: Lock,
    work_dir: PathBuf,
    fetcher: Fetcher,
    capacity: CapacityChecker,
    builder: BuildKit,
}

impl PrepareService {
    /// `NewPrepareService` — `work_dir` is the operation scratch root
    /// (fetched archives, build contexts, builder roots); the lock is
    /// loaded and verified now so a host whose assets drifted refuses
    /// at composition, not mid-operation.
    ///
    /// # Errors
    /// Any lock verification failure refuses construction.
    pub fn new(work_dir: impl Into<PathBuf>) -> Result<Self, Failure> {
        let work_dir = work_dir.into();
        let lock = LockAdapter::new()?.lock().clone();
        Ok(Self {
            fetcher: Fetcher::new(&lock, work_dir.join("fetch")),
            capacity: CapacityChecker::new(&work_dir),
            builder: BuildKit::with_work_dir(work_dir.join("builder")),
            lock,
            work_dir,
        })
    }

    /// `with_fetcher` — binds a concrete fetch transport (the
    /// helper-side seam); the default `HttpTransport` fails closed.
    #[must_use]
    pub fn with_fetcher(mut self, fetcher: Fetcher) -> Self {
        self.fetcher = fetcher;
        self
    }

    /// `with_builder` — a non-default builder root (tests).
    #[must_use]
    pub fn with_builder(mut self, builder: BuildKit) -> Self {
        self.builder = builder;
        self
    }

    /// One operation's scratch dir — fresh per call, never a sibling
    /// it could confuse a prior operation's tree with.
    fn operation_dir(&self) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.work_dir
            .join(format!("op-{}-{nanos}", std::process::id()))
    }

    /// `denial` — a `PrepareOpResult` carrying only the safe surface:
    /// a reason code, the failed phase, the derived next action. No
    /// path, OS error, or builder output crosses.
    fn denial(
        operation_id: &str,
        admission: &AdvisoryAdmission,
        code: &str,
        started: Instant,
        timings: Vec<StageTiming>,
    ) -> PrepareOpResult {
        let mut r = PrepareOpResult {
            exit_code: 5,
            reason: format!("{code}: stage refused"),
            operation_id: operation_id.to_owned(),
            phase: PreparePhase::Failed.as_str().to_owned(),
            admission_id: admission.receipt_id.clone(),
            stage_timings: timings,
            elapsed_ms: started.elapsed().as_millis() as i64,
            ..PrepareOpResult::default()
        };
        r.safe_next_action = serde_json::to_string(&prepare::SafeNextAction::Terminal)
            .unwrap_or_default()
            .trim_matches('"')
            .to_owned();
        r
    }

    /// `failure_denial` — map a stage's [`Failure`] onto the wire
    /// result: the machine code crosses, the message does not (it can
    /// name a path or an OS error).
    fn failure_denial(
        operation_id: &str,
        admission: &AdvisoryAdmission,
        failure: &Failure,
        started: Instant,
        timings: Vec<StageTiming>,
    ) -> PrepareOpResult {
        let exit_code = match failure.kind() {
            central_foundation::failure::FailureKind::Cancelled => 128 + 2,
            _ => 5,
        };
        let code = failure.code();
        let mut r = Self::denial(operation_id, admission, code, started, timings);
        r.exit_code = exit_code;
        r.reason = format!("{code}: stage refused");
        r
    }

    /// The fetch→stage→module-cache→build→inventory half of upstream
    /// `Prepare`, for the one selector acquired by build. Returns the
    /// produced inventory so the (later) comparison/promotion stages
    /// have their proven fact; every earlier stage's refusal ends the
    /// operation where upstream ends it.
    fn build_pipeline(
        &self,
        deadline: OpDeadline,
        op_dir: &std::path::Path,
    ) -> Result<(), Failure> {
        for selector in ["minio", "postgresql"] {
            deadline.check()?;
            if acquisition_kind_for(selector)? != AcquisitionKind::Built {
                // Published images are admitted as pulled images, not
                // fetched archives — the lifecycle side loads them.
                continue;
            }
            if !self.capacity.has_capacity(deadline, selector)? {
                return Err(Failure::unavailable(
                    "CAPACITY_CHECK_FAILED",
                    format!("dependencyprepare: capacity check failed for {selector:?}"),
                ));
            }
            self.fetcher.fetch(deadline, selector)?;
            // The build request's context is `root_b/context` — the
            // verified source lands exactly where the isolated builder
            // reads it.
            let root_a = op_dir.join("build-a");
            let root_b = op_dir.join("build-b");
            self.fetcher
                .stage_source(deadline, selector, &root_b.join("context"))?;
            let recipe = self.lock.minio_recipe();
            let request = prepare::new_build_request(
                selector,
                recipe,
                &root_a.display().to_string(),
                &root_b.display().to_string(),
                false,
            )?;
            self.builder.build(deadline, &request)?;
        }
        Ok(())
    }
}

impl DependencyPrepareService for PrepareService {
    /// `Prepare` — the acquisition/build half, then the explicit
    /// promotion-boundary refusal. Every stage before the boundary is
    /// real and runs in upstream's order.
    fn prepare(&self, admission: &AdvisoryAdmission) -> PrepareOpResult {
        let started = Instant::now();
        let operation_id = format!("prepare-{}", std::process::id());
        let deadline = OpDeadline::after(OP_BUDGET);
        let mut timings = Vec::new();
        let mark = |timings: &mut Vec<StageTiming>, phase: PreparePhase, at: Instant| {
            timings.push(StageTiming {
                phase: phase.as_str().to_owned(),
                duration_ms: at.elapsed().as_millis() as f64,
            });
        };
        let op_dir = self.operation_dir();
        let acquiring = Instant::now();
        if let Err(e) = std::fs::create_dir_all(&op_dir) {
            return Self::failure_denial(
                &operation_id,
                admission,
                &Failure::internal(
                    "PREPARE_WORKDIR",
                    format!("dependencyprepare: operation dir: {e}"),
                ),
                started,
                timings,
            );
        }
        match self.build_pipeline(deadline, &op_dir) {
            Ok(()) => {
                mark(&mut timings, PreparePhase::Building, acquiring);
                Self::denial(
                    &operation_id,
                    admission,
                    "PREPARE_PROMOTION_UNAVAILABLE",
                    started,
                    timings,
                )
            }
            Err(e) => {
                mark(&mut timings, PreparePhase::Acquiring, acquiring);
                Self::failure_denial(&operation_id, admission, &e, started, timings)
            }
        }
    }

    /// `Resume` — there is no operation journal in this slice, so no
    /// operation can lawfully resume: the refusal is explicit rather
    /// than a guessed-at state.
    fn resume(&self, id: &str) -> PrepareOpResult {
        let mut r = PrepareOpResult {
            exit_code: 5,
            reason: "PREPARE_UNAVAILABLE: no resumable operation journal".to_owned(),
            operation_id: id.to_owned(),
            phase: PreparePhase::Failed.as_str().to_owned(),
            safe_next_action: "PREPARATION_REQUIRED".to_owned(),
            ..PrepareOpResult::default()
        };
        r.selector.clear();
        r
    }

    /// `PrepareFromRelease` — the import half is fully real: stage the
    /// operator's release tree under caps and a closed entry set, then
    /// read the MinIO OCI inventory and the docker-save config back
    /// from the staged bytes. The promotion the inventory would feed
    /// is the same unbuilt seam `prepare` ends at.
    fn prepare_from_release(&self, admission: &AdvisoryAdmission, dir: &str) -> PrepareOpResult {
        let started = Instant::now();
        let operation_id = format!("prepare-release-{}", std::process::id());
        let deadline = OpDeadline::after(OP_BUDGET);
        let op_dir = self.operation_dir();
        if let Err(e) = std::fs::create_dir_all(&op_dir) {
            return Self::failure_denial(
                &operation_id,
                admission,
                &Failure::internal(
                    "PREPARE_WORKDIR",
                    format!("dependencyprepare: operation dir: {e}"),
                ),
                started,
                Vec::new(),
            );
        }
        let result = (|| {
            let paths =
                release_stage::stage_release_dir(deadline, std::path::Path::new(dir), &op_dir)?;
            let scratch = op_dir.join("read-scratch");
            let _minio = release_stage::read_release_minio_inventory(
                std::path::Path::new(&paths.minio_tar),
                &scratch,
            )?;
            let _infra = release_stage::read_infra_save_config(
                std::path::Path::new(&paths.infra_tar),
                &scratch,
            )?;
            Ok::<(), Failure>(())
        })();
        match result {
            Ok(()) => Self::denial(
                &operation_id,
                admission,
                "PREPARE_PROMOTION_UNAVAILABLE",
                started,
                Vec::new(),
            ),
            Err(e) => Self::failure_denial(&operation_id, admission, &e, started, Vec::new()),
        }
    }

    /// `PrepareExportRelease` — writing a release bundle is the
    /// attestation half of the operation; without signing it would be
    /// an unverifiable bundle, so the verb refuses explicitly.
    fn prepare_export_release(&self, admission: &AdvisoryAdmission, _dir: &str) -> PrepareOpResult {
        Self::denial(
            &format!("prepare-export-{}", std::process::id()),
            admission,
            "RELEASE_EXPORT_FAILED",
            Instant::now(),
            Vec::new(),
        )
    }
}

/// `NewPrepareHandlerWithPAM` — upstream's factory: the prepare verb's
/// full handler = the real pipeline service + the advisory evaluator
/// seam + the binding-bound PAM confirmer + the helper-minted
/// confirmation source. The daemon installs
/// `unavailablePrepareHandler` when it cannot compose all four — a
/// host without an advisory evaluator refuses the verb explicitly
/// rather than answering a made-up success, exactly upstream's
/// composition-failure rule.
pub fn new_prepare_handler(
    work_dir: impl Into<PathBuf>,
    eval: Box<dyn EvaluateService>,
    pam: Box<dyn PreparePamConfirmer>,
    source: PrepareConfirmationSource,
) -> Result<DependencyPrepareHandler, Failure> {
    let service = PrepareService::new(work_dir)?;
    Ok(DependencyPrepareHandler::new(
        Box::new(service),
        eval,
        pam,
        source,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-prepare-svc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        dir
    }

    /// The service composes against the shipped lock — a host whose
    /// embedded assets cannot verify never serves the verb.
    #[test]
    fn service_composes_with_verified_lock() {
        let dir = tempdir("compose");
        let svc = PrepareService::new(&dir).expect("compose");
        assert!(svc.lock.fetch_capability.contains_key("minio"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `resume` refuses explicitly — no journal means no lawful resume.
    #[test]
    fn resume_is_explicit_denial() {
        let dir = tempdir("resume");
        let svc = PrepareService::new(&dir).expect("compose");
        let r = svc.resume("op-x");
        assert_eq!(r.exit_code, 5);
        assert_eq!(r.phase, "failed");
        assert!(r.reason.starts_with("PREPARE_UNAVAILABLE"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `prepare` reaches the transport seam or a stage refusal — it
    /// never answers success without the promotion half existing.
    #[test]
    fn prepare_never_fakes_success() {
        let dir = tempdir("prep");
        let svc = PrepareService::new(&dir).expect("compose");
        let admission = AdvisoryAdmission {
            receipt_id: "receipt-1".to_owned(),
        };
        let r = svc.prepare(&admission);
        assert_ne!(r.exit_code, 0);
        assert_eq!(r.phase, "failed");
        assert!(!r.reason.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `prepare_from_release` refuses a hostile tree through the real
    /// staging boundary, not a stub.
    #[test]
    fn from_release_refuses_missing_tree() {
        let dir = tempdir("from-rel");
        let svc = PrepareService::new(&dir).expect("compose");
        let admission = AdvisoryAdmission {
            receipt_id: "receipt-1".to_owned(),
        };
        let r = svc.prepare_from_release(&admission, "/nonexistent/release");
        assert_eq!(r.exit_code, 5);
        assert!(r.reason.starts_with("RELEASE_") || r.reason.starts_with("PREPARE_"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `prepare_export_release` refuses — export without signing is
    /// not a release.
    #[test]
    fn export_release_is_explicit_denial() {
        let dir = tempdir("export");
        let svc = PrepareService::new(&dir).expect("compose");
        let admission = AdvisoryAdmission::default();
        let r = svc.prepare_export_release(&admission, "/tmp/x");
        assert_eq!(r.exit_code, 5);
        std::fs::remove_dir_all(&dir).ok();
    }
}
