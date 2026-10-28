//! `PrepareService` + `NewPrepareHandler` — the port of upstream
//! `factory_linux.go`: the helper-facing driver that owns the
//! unsettled-operation guard and iterates the selectors, while every
//! selector's actual work is the [`PrepareState`] machine's.
//!
//! Composition (`new_prepare_handler`): the verified lock, the operator's
//! attestation key (a MISSING key yields an import-only handler — releases
//! import, nothing builds, fresh prepares refuse immediately instead of
//! after a fetch and two builds; any other key failure refuses the
//! composition), the real advisory-currency verifier over the same evaluator
//! the handler uses, the file journal, the protected candidate store, the
//! docker image loader, and the release import/export services.
//!
//! The work directory and the dependency root are deliberately separate: the
//! work directory is scratch the operation owns (fetches, builder roots, the
//! journal); the dependency root is the protected store B03 reads its active
//! receipt from. They must differ — the protected store is not scratch space.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use central_foundation::failure::Failure;
use central_infra::domain::PreparePhase;
use central_infra::prepare::{PrepareResult, prepare_codes, with_safe_next_action};

use crate::helper::prepare::{
    AdvisoryAdmission, DependencyPrepareHandler, DependencyPrepareService, EvaluateService,
    PrepareConfirmationSource, PrepareOpResult, PreparePamConfirmer,
};
use crate::helper::protocol::{ResourceCounters, StageTiming};

use super::OpDeadline;
use super::admission::{AdvisoryAdmissionVerifier, SharedEvaluate};
use super::attestation::{
    AttestationService, AttestationSigner, AttestationVerifier, Attestor, attestation_key_path,
    load_attestation_signer,
};
use super::buildkit::BuildKit;
use super::capacity::CapacityChecker;
use super::export::ReleaseExportService;
use super::fetch::Fetcher;
use super::image_load::{DockerImageLoader, ImageLoader, image_loader_for};
use super::journal::FileJournal;
use super::lock::LockAdapter;
use super::oci::Comparator;
use super::release::ReleaseImportService;
use super::state_machine::PrepareState;
use super::store::CandidateStore;

/// `preparedSelectors` — what this helper can actually prepare: the
/// selectors with a hermetic build path. PostgreSQL is deliberately absent:
/// it is admitted as the accepted published OCI identity chain, a different
/// acquisition. The state machine refuses a published selector on its own
/// too, so a future list cannot smuggle one back in.
const PREPARED_SELECTORS: [&str; 1] = ["minio"];

/// `PrepareRoots` — the two directories a prepare handler works in.
#[derive(Debug, Clone)]
pub struct PrepareRoots {
    /// Scratch the operation owns: fetches, builder roots, the journal.
    pub work_dir: PathBuf,
    /// The protected store B03 reads its active receipt from.
    pub dependency_root: PathBuf,
}

impl PrepareRoots {
    fn validate(&self) -> Result<(), Failure> {
        let bad = |m: &str| Failure::invalid("PREPARE_FACTORY", format!("factory: {m}"));
        if self.work_dir.as_os_str().is_empty() {
            return Err(bad("work directory is required"));
        }
        if self.dependency_root.as_os_str().is_empty() {
            return Err(bad("dependency root is required"));
        }
        if self.work_dir == self.dependency_root {
            return Err(bad(
                "work directory and dependency root must differ; the protected store is not scratch space",
            ));
        }
        Ok(())
    }
}

/// `PrepareService`.
pub struct PrepareService {
    journal: Arc<FileJournal>,
    state: PrepareState,
    selectors: Vec<String>,
    exporter: Option<ReleaseExportService>,
    keyless: bool,
}

fn to_op_result(r: &PrepareResult) -> PrepareOpResult {
    PrepareOpResult {
        exit_code: i64::from(r.exit_code),
        reason: r.reason.clone(),
        operation_id: r.operation_id.clone(),
        receipt_id: r.receipt_id.clone(),
        phase: r.phase.as_str().to_owned(),
        resume_required: r.resume_required,
        reused: r.reused,
        acquired: r.acquired,
        safe_next_action: r.safe_next_action.as_str().to_owned(),
        stage_timings: r
            .stage_timings
            .iter()
            .map(|t| StageTiming {
                phase: t.phase.clone(),
                duration_ms: t.duration_ms,
            })
            .collect(),
        counters: ResourceCounters {
            fetched: r.counters.fetched,
            built: r.counters.built,
            compared: r.counters.compared,
            staged: r.counters.staged,
            bytes_read: r.counters.bytes_read,
        },
        elapsed_ms: r.elapsed_ms,
        admission_id: r.admission_id.clone(),
        selector: r.selector.clone(),
    }
}

fn failed(reason: impl Into<String>, extra: impl FnOnce(&mut PrepareResult)) -> PrepareOpResult {
    let mut r = base_result(PreparePhase::Failed);
    r.exit_code = 1;
    r.reason = reason.into();
    extra(&mut r);
    to_op_result(&with_safe_next_action(r))
}

fn base_result(phase: PreparePhase) -> PrepareResult {
    PrepareResult {
        exit_code: 0,
        reason: String::new(),
        operation_id: String::new(),
        receipt_id: String::new(),
        phase,
        resume_required: false,
        reused: 0,
        acquired: 0,
        safe_next_action: central_infra::prepare::SafeNextAction::None,
        stage_timings: Vec::new(),
        counters: central_infra::prepare::ResourceCounters::default(),
        elapsed_ms: 0,
        admission_id: String::new(),
        selector: String::new(),
        deadline: time::OffsetDateTime::UNIX_EPOCH,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

impl PrepareService {
    fn unsettled_result(&self) -> Option<PrepareOpResult> {
        let op = self.journal.unsettled()?;
        let mut r = base_result(super::state_machine::map_authority_phase(op.phase));
        r.operation_id = op.operation_id.clone();
        r.receipt_id = op.receipt_id.clone();
        r.selector = op.selector.clone();
        r.resume_required = true;
        r.reason = format!(
            "unsettled operation {} at phase {}",
            op.operation_id,
            op.phase.as_str()
        );
        Some(to_op_result(&with_safe_next_action(r)))
    }

    /// Drives every selector through `one`, aggregating exactly as upstream:
    /// the first failure returns; the last selector's measurements are
    /// carried through (this driver runs no phases itself, so the only
    /// honest timings and counters are the ones the operation it drove
    /// recorded).
    fn drive(
        &self,
        admission: &AdvisoryAdmission,
        one: impl Fn(&str) -> PrepareResult,
    ) -> PrepareOpResult {
        let mut last: Option<PrepareResult> = None;
        let mut acquired = 0;
        let mut elapsed_ms = 0;
        for selector in &self.selectors {
            let result = one(selector);
            if result.phase == PreparePhase::Failed {
                return to_op_result(&result);
            }
            if result.phase == PreparePhase::Skipped {
                continue;
            }
            acquired = result.acquired;
            elapsed_ms += result.elapsed_ms;
            last = Some(result);
        }
        let Some(last) = last.filter(|_| acquired != 0) else {
            // No operation ran, so there is no operation to name: a minted
            // identifier no journal had ever heard of could never be resumed.
            let mut r = base_result(PreparePhase::Skipped);
            r.reason = "NO_SELECTORS".to_owned();
            return to_op_result(&with_safe_next_action(r));
        };
        let mut r = base_result(PreparePhase::Ready);
        r.operation_id = last.operation_id;
        r.receipt_id = last.receipt_id;
        r.selector = last.selector;
        r.acquired = acquired;
        r.admission_id.clone_from(&admission.receipt_id);
        r.stage_timings = last.stage_timings;
        r.counters = last.counters;
        r.elapsed_ms = elapsed_ms;
        to_op_result(&with_safe_next_action(r))
    }
}

impl DependencyPrepareService for PrepareService {
    fn prepare(&self, admission: &AdvisoryAdmission) -> PrepareOpResult {
        if self.keyless {
            // No attestation key: a build is impossible, so the refusal is
            // immediate rather than after a fetch and two twenty-minute
            // builds. From-release imports bypass this (no key needed).
            return failed("PREPARE_UNAVAILABLE", |_| {});
        }
        if let Some(unsettled) = self.unsettled_result() {
            return unsettled;
        }
        self.drive(admission, |selector| {
            self.state.prepare_one(admission, selector)
        })
    }

    fn resume(&self, id: &str) -> PrepareOpResult {
        to_op_result(&self.state.resume(id))
    }

    fn prepare_from_release(&self, admission: &AdvisoryAdmission, dir: &str) -> PrepareOpResult {
        if let Some(unsettled) = self.unsettled_result() {
            return unsettled;
        }
        self.drive(admission, |selector| {
            self.state
                .prepare_one_from_release(admission, selector, Path::new(dir))
        })
    }

    /// `PrepareExportRelease` — runs the standard full prepare to
    /// completion, then assembles a release from that operation's
    /// artifacts. The prepare keeps its journaling and resume behavior; only
    /// the post-completion assembly is new, and it is unjournalled — a failed
    /// assembly names the completed prepare it could not export, and a re-run
    /// re-prepares.
    fn prepare_export_release(&self, admission: &AdvisoryAdmission, dir: &str) -> PrepareOpResult {
        let Some(exporter) = &self.exporter else {
            return failed("EXPORT_UNCONFIGURED", |_| {});
        };
        if let Err(e) = exporter.check_export_dir(Path::new(dir)) {
            return failed(format!("EXPORT_DIR_UNUSABLE: {}", e.message()), |_| {});
        }
        let result = self.prepare(admission);
        if result.phase != PreparePhase::Ready.as_str() {
            return result;
        }
        if result.selector != "minio" {
            // Unreachable today (the selector list pins ["minio"]); a future
            // selector would silently export the wrong operation's artifacts.
            return failed(
                format!(
                    "EXPORT_FAILED: no minio operation to export (selector {:?})",
                    result.selector
                ),
                |r| {
                    r.operation_id.clone_from(&result.operation_id);
                    r.selector.clone_from(&result.selector);
                },
            );
        }
        match exporter.export_release(
            OpDeadline::after(central_infra::prepare::OPERATION_BUDGET),
            &result.operation_id,
            Path::new(dir),
        ) {
            Ok(()) => result,
            Err(e) => {
                let label = if e.code() == prepare_codes::RELEASE_EXPORT_DIR_UNUSABLE {
                    "EXPORT_DIR_UNUSABLE"
                } else {
                    "EXPORT_FAILED"
                };
                failed(format!("{label}: {}", e.message()), |r| {
                    r.operation_id.clone_from(&result.operation_id);
                    r.receipt_id.clone_from(&result.receipt_id);
                    r.selector.clone_from(&result.selector);
                })
            }
        }
    }
}

/// `NewPrepareHandlerWithSigner` — composes the whole prepare graph around
/// an optional attestation signer (`None` → import-only).
///
/// # Errors
/// An invalid root pair, a lock or trust-policy verification failure, an
/// untrusted signing key, or an uncreatable work directory.
pub fn compose_prepare_service(
    roots: &PrepareRoots,
    eval: Arc<dyn EvaluateService>,
    signer: Option<AttestationSigner>,
) -> Result<PrepareService, Failure> {
    roots.validate()?;
    let lock = LockAdapter::new()?.lock().clone();
    let policy = lock.attestation_trust.clone();
    policy.validate().map_err(|e| {
        Failure::invalid(
            "PREPARE_FACTORY",
            format!("factory: attestation trust: {}", e.message()),
        )
    })?;
    let keyless = signer.is_none();
    let build_dir = roots.work_dir.join("build");
    let attestor: Option<Arc<dyn Attestor>> = match signer {
        Some(s) => Some(Arc::new(
            AttestationService::new(s, policy.clone())?.with_artifact_dir(&build_dir),
        )),
        None => None,
    };
    let fetches_dir = roots.work_dir.join("fetches");
    std::fs::create_dir_all(&fetches_dir).map_err(|e| {
        Failure::internal(
            "PREPARE_FACTORY",
            format!("factory: create fetches dir: {e}"),
        )
    })?;
    let journal = Arc::new(FileJournal::new(roots.work_dir.join("journal"))?);
    // The loader is never left absent: a host with no docker is not an
    // unconfigured service, it is a host that cannot prepare. It gets a loader
    // that fails closed at the capacity checkpoint, naming the missing binary,
    // in seconds. The infra side takes the deliberate `None` instead: every
    // use fails closed on it, and the Supported gate runs before any import
    // reaches the infra load.
    let loader: Arc<dyn ImageLoader> = Arc::from(image_loader_for(DockerImageLoader::from_path()));
    let release_verifier = AttestationVerifier::new(policy);
    let importer = ReleaseImportService::new(
        lock.clone(),
        release_verifier.clone(),
        Arc::new(DockerImageLoaderShim::new()),
        DockerImageLoader::from_path().ok(),
    );
    let exporter = DockerImageLoader::from_path().ok().map(|docker| {
        ReleaseExportService::new(lock.clone(), release_verifier.clone(), docker, &build_dir)
    });
    let verifier = Arc::new(AdvisoryAdmissionVerifier::new(eval));
    let store = Arc::new(CandidateStore::new(
        Some(LockAdapter::with_lock(lock.clone())),
        &roots.dependency_root,
    ));
    let mut state = PrepareState::new(
        Arc::clone(&journal),
        verifier,
        Arc::new(BuildKit::with_work_dir(&build_dir)),
        store,
        lock.clone(),
        Arc::new(Fetcher::new(&lock, &fetches_dir)),
        Arc::new(CapacityChecker::new(&roots.work_dir)),
        PREPARED_SELECTORS.map(str::to_owned).to_vec(),
        &build_dir,
    )
    .with_image_loader(loader)
    .with_release_importer(Arc::new(importer));
    if let Some(attestor) = attestor {
        state = state.with_attestation(Arc::new(Comparator), attestor);
    }
    Ok(PrepareService {
        journal,
        state,
        selectors: PREPARED_SELECTORS.map(str::to_owned).to_vec(),
        exporter,
        keyless,
    })
}

/// A second, independent image loader for the import service (the state
/// machine owns the first); both resolve docker the same way.
struct DockerImageLoaderShim(Box<dyn ImageLoader>);

impl DockerImageLoaderShim {
    fn new() -> Self {
        Self(image_loader_for(DockerImageLoader::from_path()))
    }
}

impl ImageLoader for DockerImageLoaderShim {
    fn supported(&self, deadline: OpDeadline) -> Result<(), Failure> {
        self.0.supported(deadline)
    }

    fn load(
        &self,
        deadline: OpDeadline,
        req: &central_infra::prepare::ImageLoadRequest,
    ) -> Result<central_infra::prepare::LoadedImage, Failure> {
        self.0.load(deadline, req)
    }
}

/// `NewPrepareHandlerWithPAM` — loads the attestation signing key from the
/// operator's state directory. The key is never generated here and never
/// lives in the work directory. A MISSING key yields an import-only handler;
/// any other key failure (corrupt file, untrusted key) fails the factory
/// rather than silently going keyless.
///
/// # Errors
/// Any composition failure; the daemon then installs the unavailable
/// handler and journals the reason at startup, never onto the wire.
pub fn new_prepare_handler(
    roots: &PrepareRoots,
    eval: Box<dyn EvaluateService>,
    pam: Box<dyn PreparePamConfirmer>,
    source: PrepareConfirmationSource,
) -> Result<DependencyPrepareHandler, Failure> {
    let eval: Arc<dyn EvaluateService> = Arc::from(eval);
    let key_path = attestation_key_path();
    let signer = match std::fs::symlink_metadata(&key_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "factory: no attestation signing key at {}: import-only prepare handler",
                key_path.display()
            );
            None
        }
        _ => Some(load_attestation_signer(&key_path).map_err(|e| {
            Failure::invalid(
                "PREPARE_FACTORY",
                format!(
                    "factory: attestation signing key ({}, override with {}): {}",
                    key_path.display(),
                    super::attestation::ATTESTATION_KEY_ENV,
                    e.message()
                ),
            )
        })?),
    };
    let service =
        compose_prepare_service(roots, Arc::new(SharedEvaluate(Arc::clone(&eval))), signer)?;
    Ok(DependencyPrepareHandler::new(
        Box::new(service),
        Box::new(SharedEvaluate(eval)),
        pam,
        source,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::prepare::AdvisoryResult;

    struct Eval;

    impl EvaluateService for Eval {
        fn evaluate(&self) -> Result<(AdvisoryResult, AdvisoryAdmission), Failure> {
            Ok((
                AdvisoryResult {
                    state: "current".to_owned(),
                    code: String::new(),
                },
                AdvisoryAdmission {
                    receipt_id: "fresh".to_owned(),
                },
            ))
        }
    }

    fn roots(tag: &str) -> PrepareRoots {
        let base = std::env::temp_dir().join(format!(
            "central-prepare-svc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        PrepareRoots {
            work_dir: base.join("work"),
            dependency_root: base.join("deps"),
        }
    }

    fn keyless(tag: &str) -> (PrepareRoots, PrepareService) {
        let r = roots(tag);
        std::fs::create_dir_all(&r.work_dir).expect("work");
        let svc = compose_prepare_service(&r, Arc::new(Eval), None).expect("compose");
        (r, svc)
    }

    fn cleanup(r: &PrepareRoots) {
        if let Some(base) = r.work_dir.parent() {
            let _ = std::fs::remove_dir_all(base);
        }
    }

    fn admission() -> AdvisoryAdmission {
        AdvisoryAdmission {
            receipt_id: "adm".to_owned(),
        }
    }

    #[test]
    fn roots_must_be_distinct_and_present() {
        let r = roots("roots");
        for bad in [
            PrepareRoots {
                work_dir: PathBuf::new(),
                ..r.clone()
            },
            PrepareRoots {
                dependency_root: PathBuf::new(),
                ..r.clone()
            },
            PrepareRoots {
                dependency_root: r.work_dir.clone(),
                ..r.clone()
            },
        ] {
            assert!(compose_prepare_service(&bad, Arc::new(Eval), None).is_err());
        }
    }

    #[test]
    fn keyless_host_refuses_a_fresh_prepare_immediately() {
        let (r, svc) = keyless("keyless");
        let res = svc.prepare(&admission());
        assert_eq!(res.exit_code, 1);
        assert_eq!(res.phase, "failed");
        assert_eq!(res.reason, "PREPARE_UNAVAILABLE");
        assert_eq!(res.safe_next_action, "TERMINAL_FAILURE");
        cleanup(&r);
    }

    #[test]
    fn resume_goes_through_the_state_machine_not_a_blanket_denial() {
        let (r, svc) = keyless("resume");
        let res = svc.resume("../escape");
        assert_eq!(res.exit_code, 1);
        assert!(
            res.reason.starts_with("INVALID_INVOCATION"),
            "{}",
            res.reason
        );
        let res = svc.resume("never-recorded");
        assert!(
            res.reason.starts_with("INVALID_INVOCATION"),
            "{}",
            res.reason
        );
        cleanup(&r);
    }

    #[test]
    fn an_unsettled_operation_makes_prepare_from_release_require_resume() {
        let (r, svc) = keyless("unsettled");
        let now = time::OffsetDateTime::now_utc();
        svc.journal
            .record(&central_infra::authority::PrepareOperation {
                operation_id: "prepare-live".to_owned(),
                phase: central_infra::authority::PrepareOperationPhase::BuildOne,
                admission_id: "adm".to_owned(),
                selector: "minio".to_owned(),
                deadline: now + time::Duration::minutes(5),
                reason: String::new(),
                reused: 0,
                acquired: 1,
                receipt_id: String::new(),
                created_at: now,
            })
            .expect("seed");
        let res = svc.prepare_from_release(&admission(), "/rel");
        assert!(res.resume_required);
        assert_eq!(res.operation_id, "prepare-live");
        assert_eq!(res.safe_next_action, "RESUME_REQUIRED");
        cleanup(&r);
    }

    #[test]
    fn from_release_refuses_a_missing_tree_through_the_real_boundary() {
        let (r, svc) = keyless("from-rel");
        let res = svc.prepare_from_release(&admission(), "/nonexistent/release");
        assert_eq!(res.exit_code, 1);
        assert_eq!(res.phase, "failed");
        assert!(!res.reason.is_empty());
        cleanup(&r);
    }

    #[test]
    fn export_refuses_an_unusable_dir_before_any_prepare() {
        let (r, svc) = keyless("export");
        let res = svc.prepare_export_release(&admission(), "relative/dir");
        assert_eq!(res.exit_code, 1);
        assert!(
            res.reason.starts_with("EXPORT_DIR_UNUSABLE")
                || res.reason.starts_with("EXPORT_UNCONFIGURED"),
            "{}",
            res.reason
        );
        cleanup(&r);
    }
}
