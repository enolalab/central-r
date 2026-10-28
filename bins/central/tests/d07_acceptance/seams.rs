//! The `d07_*` fixture seams upstream declares beside the harness:
//! the shared advisory dial, the installed/candidate evaluators, the
//! idempotent-cleanup counter, the repository-backed checkpoint
//! verifier, and the fixture-sealed `backup-create` answer. These are
//! the same explicit domain seams upstream stubs — the transport,
//! matrix, deny-safe gate, and handlers are always production code.
//!
//! Each dial struct is `Clone` over shared `Arc` state so one dial can
//! be boxed into several handler seams and still read by the
//! scenario — upstream's pointer-shared `*d07Evaluator` semantics.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use central_adapter_linux::helper::audit::{AdvisoryVerdict, AuditAdvisoryEvaluator};
use central_adapter_linux::helper::backup::{
    BackupCreateRequest, BackupCreateResult, BackupCreator,
};
use central_adapter_linux::helper::delete::DeleteAdvisoryEvaluator;
use central_adapter_linux::helper::prepare::{AdvisoryAdmission, AdvisoryResult};
use central_adapter_linux::helper::prune::PruneAdvisoryEvaluator;
use central_adapter_linux::helper::rescue::{
    RescueAdvisoryEvaluator, RescueCandidateEvaluator, RescueCleanup,
};
use central_adapter_linux::helper::wipe::{WipeAdvisoryEvaluator, WipeCheckpointVerifier};
use central_adapter_linux::helper::{PeerIdentity, Response};
use central_backup::backup::capacity::default_recovery_profile;
use central_foundation::failure::Failure;
use central_infra::advisory::{Code, Outcome, State};
use uuid::Uuid;

/// `d07Evaluator` — the mutable B01 stub every destructive-gated D07
/// handler shares: one dial turns the whole server's advisory view
/// Current or Denied.
#[derive(Debug, Clone)]
pub(crate) struct D07Evaluator {
    state: Arc<Mutex<State>>,
}

impl D07Evaluator {
    pub(crate) fn new(state: State) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }
    pub(crate) fn set(&self, state: State) {
        *self.state.lock().unwrap() = state;
    }
    fn verdict(&self) -> (AdvisoryResult, AdvisoryAdmission) {
        let state = *self.state.lock().unwrap();
        (
            AdvisoryResult {
                state: state.as_str().to_owned(),
                code: String::new(),
            },
            AdvisoryAdmission::default(),
        )
    }
}

impl WipeAdvisoryEvaluator for D07Evaluator {
    fn evaluate(&self) -> Result<(AdvisoryResult, AdvisoryAdmission), Failure> {
        Ok(self.verdict())
    }
}

impl DeleteAdvisoryEvaluator for D07Evaluator {
    fn evaluate(&self) -> Result<(AdvisoryResult, AdvisoryAdmission), Failure> {
        Ok(self.verdict())
    }
}

impl PruneAdvisoryEvaluator for D07Evaluator {
    fn evaluate(&self) -> Result<(AdvisoryResult, AdvisoryAdmission), Failure> {
        Ok(self.verdict())
    }
}

impl AuditAdvisoryEvaluator for D07Evaluator {
    fn evaluate(&self) -> Result<AdvisoryVerdict, Failure> {
        Ok(if *self.state.lock().unwrap() == State::Current {
            AdvisoryVerdict::Current
        } else {
            AdvisoryVerdict::NotCurrent
        })
    }
}

/// `d07InstalledState` — the installed-advisory dial for D06 rescue.
/// A non-current installed state carries `ADVISORY_HARD_EXPIRED`, the
/// only code the acceptance path distinguishes.
#[derive(Debug, Clone)]
pub(crate) struct D07InstalledState {
    state: Arc<Mutex<State>>,
}

impl D07InstalledState {
    pub(crate) fn new(state: State) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }
    pub(crate) fn set(&self, state: State) {
        *self.state.lock().unwrap() = state;
    }
}

impl RescueAdvisoryEvaluator for D07InstalledState {
    fn evaluate(&self) -> Result<Outcome, Failure> {
        let state = *self.state.lock().unwrap();
        let code = if state == State::Current {
            Code::Unset
        } else {
            Code::HardExpired
        };
        Ok(Outcome::new(state, code))
    }
}

/// `d07CandidateState` — the B01 candidate-evaluator dial; counts the
/// calls like upstream's `d07CandidateState.calls`.
#[derive(Debug, Clone)]
pub(crate) struct D07CandidateState {
    outcome: Arc<Mutex<Outcome>>,
    pub calls: Arc<AtomicI32>,
}

impl D07CandidateState {
    pub(crate) fn new(outcome: Outcome) -> Self {
        Self {
            outcome: Arc::new(Mutex::new(outcome)),
            calls: Arc::new(AtomicI32::new(0)),
        }
    }
    pub(crate) fn set(&self, outcome: Outcome) {
        *self.outcome.lock().unwrap() = outcome;
    }
}

impl RescueCandidateEvaluator for D07CandidateState {
    fn evaluate_candidate(&self, _candidate: &[u8]) -> Result<Outcome, Failure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.outcome.lock().unwrap().clone())
    }
}

/// `d07Cleanup` — records invocation; production's lifecycle down is
/// covered by the lifecycle suite, D07 asserts the rescue reached it.
#[derive(Debug, Clone)]
pub(crate) struct D07Cleanup {
    pub calls: Arc<AtomicI32>,
}

impl D07Cleanup {
    pub(crate) fn new(calls: Arc<AtomicI32>) -> Self {
        Self { calls }
    }
}

impl RescueCleanup for D07Cleanup {
    fn cleanup(&self) -> Result<(), Failure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// `d07Checkpoint` — verifies wipe checkpoints against the fixture
/// repository for real: a checkpoint that is not sealed here refuses
/// exactly as in production.
#[derive(Debug)]
pub(crate) struct D07Checkpoint {
    pub repo: std::path::PathBuf,
}

impl WipeCheckpointVerifier for D07Checkpoint {
    fn verify_sealed(
        &self,
        _deadline: Instant,
        backup_id: &str,
        _peer: &PeerIdentity,
    ) -> Result<(), Failure> {
        let id = Uuid::parse_str(backup_id).map_err(|_| {
            Failure::unavailable("wipe_checkpoint", "wipe: checkpoint id unparseable")
        })?;
        let repository = crate::harness::open_repo_ro(&self.repo)?;
        repository
            .verify_backup(id, &default_recovery_profile())
            .map(|_| ())
    }
}

/// `d07BackupCreate` — answers the wipe flow's checkpoint step with a
/// fixture-sealed backup. Backup CREATION is C01's tested behavior,
/// not D01's; D07's contract is that the wipe verifies the checkpoint
/// it is given, which the real `D07Checkpoint` enforces. Upstream
/// fakes the in-process client (`SetBackupCreateClientForProcess`);
/// the port installs the same stand-in server-side so the socket,
/// matrix, and deny-safe gate stay real.
#[derive(Debug)]
pub(crate) struct D07BackupCreate {
    pub backup_id: String,
}

impl BackupCreator for D07BackupCreate {
    fn create_backup(
        &self,
        _deadline: Instant,
        request: BackupCreateRequest,
        _peer: &PeerIdentity,
    ) -> Response {
        Response::new(request.operation_id.clone(), "success", 0, "ok").with_result(
            &BackupCreateResult {
                operation_id: request.operation_id,
                backup_id: self.backup_id.clone(),
                phase: "sealed".to_owned(),
            },
        )
    }
}
