//! `migration_launch.go` — the broker's durable launch-evidence and
//! outcome store for the `central-migrate` operator (ADR 0011).
//!
//! Evidence lives under `<broker-root>/migration-launches/` as
//! `<evidence-id>.json`; `LoadAndConsume` renames it to
//! `<evidence-id>.json.consumed` (atomic, `RENAME_NOREPLACE`) so a
//! replay or crash can never disclose a second credential. Outcomes
//! live under `<broker-root>/migration-launch-outcomes/` with a
//! per-outcome `flock` serializing every read-check-write
//! transition.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use central_backup::app::MigrationOperatorResult;
use central_foundation::failure::Failure;
use central_infra::domain::{MIGRATION_LAUNCH_BINDING_HMAC_DOMAIN, MigrationLaunchBinding};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::durable;
use super::signing::SigningService;
use crate::sys::peercred::PeerCred;

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_migration_launch", msg)
}

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("broker_migration_launch_denied", msg)
}

/// `migrationLaunchDirectory`.
const LAUNCH_DIR: &str = "migration-launches";
/// `migrationLaunchOutcomeDirectory`.
const OUTCOME_DIR: &str = "migration-launch-outcomes";

/// `MigrationLaunchOutcomeState` — upstream's `string` type; the five
/// closed values serialize as their lowercase wire names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MigrationLaunchOutcomeState {
    /// Evidence issued, nothing reported yet.
    Issued,
    /// The operator reported the launch started.
    Started,
    /// Terminal success.
    Succeeded,
    /// Terminal failure.
    Failed,
    /// Terminal — evidence was consumed but no terminal report ever
    /// arrived; recovery must reconcile, never infer success.
    Ambiguous,
}

/// `MigrationLaunchOutcome` — broker-owned durable execution
/// evidence. A missing terminal state is intentionally ambiguous.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationLaunchOutcome {
    /// The launch evidence identity.
    pub launch_evidence_id: String,
    /// The operation the launch was issued for.
    pub operation_id: String,
    /// `issued|started|succeeded|failed|ambiguous`.
    pub state: MigrationLaunchOutcomeState,
    /// Failure reason, when present.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Operator-safe next action.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub safe_next_action: String,
    /// The dedicated operator's typed result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_result: Option<MigrationOperatorResult>,
    /// Last broker update.
    #[serde(with = "super::wire::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl MigrationLaunchOutcome {
    /// `outcome.Terminal()`.
    fn terminal(&self) -> bool {
        matches!(
            self.state,
            MigrationLaunchOutcomeState::Succeeded
                | MigrationLaunchOutcomeState::Failed
                | MigrationLaunchOutcomeState::Ambiguous
        )
    }
}

/// `MigrationLaunchStore` — private `0700` directories re-validated
/// at every sensitive access, exactly like upstream.
pub struct MigrationLaunchStore {
    root: PathBuf,
    outcome_root: PathBuf,
    signing: Arc<SigningService>,
}

fn valid_evidence_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok()
}

fn dir_label(name: &str) -> String {
    format!("migration launch {name}")
}

impl MigrationLaunchStore {
    /// `NewMigrationLaunchStore` — create + validate both private
    /// roots under `broker_root`.
    pub fn new(broker_root: &Path, signing: Arc<SigningService>) -> Result<Self, Failure> {
        let root = broker_root.join(LAUNCH_DIR);
        durable::mkdir_p(&root, durable::PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("create root: {e}")))?;
        durable::validate_private_directory(&root, &dir_label("root"))?;
        let outcome_root = broker_root.join(OUTCOME_DIR);
        durable::mkdir_p(&outcome_root, durable::PRIVATE_DIRECTORY_MODE)
            .map_err(|e| internal(format!("create outcome root: {e}")))?;
        durable::validate_private_directory(&outcome_root, &dir_label("outcome root"))?;
        Ok(Self {
            root,
            outcome_root,
            signing,
        })
    }

    /// `Issue` — sign and atomically persist launch evidence. Only the
    /// broker creates the evidence ID, nonce, and HMAC.
    pub fn issue(
        &self,
        mut binding: MigrationLaunchBinding,
    ) -> Result<MigrationLaunchBinding, Failure> {
        if !binding.launch_evidence_id.is_empty()
            || !binding.nonce.is_empty()
            || !binding.hmac.is_empty()
        {
            return Err(denied(
                "migration launch store: broker fields must be empty on issue",
            ));
        }
        binding.launch_evidence_id = uuid::Uuid::now_v7().to_string();
        let mut nonce = [0u8; 32];
        rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
            .map_err(|e| internal(format!("issue nonce: {e}")))?;
        binding.nonce = nonce.to_vec();
        binding.hmac = self.signing.fingerprint(
            MIGRATION_LAUNCH_BINDING_HMAC_DOMAIN,
            &binding.canonical_payload(),
        );
        binding
            .validate(OffsetDateTime::now_utc())
            .map_err(|e| internal(format!("invalid evidence: {}", e.message())))?;

        self.write(&binding)?;
        let outcome = MigrationLaunchOutcome {
            launch_evidence_id: binding.launch_evidence_id.clone(),
            operation_id: binding.operation_id.to_string(),
            state: MigrationLaunchOutcomeState::Issued,
            reason: String::new(),
            safe_next_action: String::new(),
            operator_result: None,
            updated_at: OffsetDateTime::now_utc(),
        };
        if let Err(e) = self.write_outcome(&outcome) {
            // Never leave usable authority without its authoritative
            // outcome state.
            let _ = durable::remove_file(&self.active_path(&binding.launch_evidence_id));
            let _ = durable::sync_dir(&self.root);
            return Err(e);
        }
        Ok(binding)
    }

    /// `LoadAndConsume` — validate durable evidence, then atomically
    /// rename it to a tombstone so no second credential can be
    /// disclosed.
    pub fn load_and_consume(&self, evidence_id: &str) -> Result<MigrationLaunchBinding, Failure> {
        if !valid_evidence_id(evidence_id) {
            return Err(denied("migration launch store: invalid evidence ID"));
        }
        let binding = self.load(&self.active_path(evidence_id))?;
        if binding.launch_evidence_id != evidence_id {
            return Err(denied("migration launch store: evidence ID mismatch"));
        }
        binding.validate(OffsetDateTime::now_utc()).map_err(|e| {
            denied(format!(
                "migration launch store: invalid evidence: {}",
                e.message()
            ))
        })?;
        let expected = self.signing.fingerprint(
            MIGRATION_LAUNCH_BINDING_HMAC_DOMAIN,
            &binding.canonical_payload(),
        );
        if !ct_eq(expected.as_bytes(), binding.hmac.as_bytes()) {
            return Err(denied("migration launch store: HMAC verification failed"));
        }
        durable::validate_private_directory(&self.root, &dir_label("root"))?;
        durable::rename_noreplace(
            &self.active_path(evidence_id),
            &self.tombstone_path(evidence_id),
        )
        .map_err(|e| {
            // ENOENT or EEXIST — already consumed or unavailable.
            let _ = e;
            denied("migration launch store: evidence already consumed or unavailable")
        })?;
        durable::sync_dir(&self.root)?;
        Ok(binding)
    }

    /// `LoadConsumedAndValidate` — revalidate a consumed launch for a
    /// subsequent authority RPC. Only the tombstone is accepted, so an
    /// operator cannot use authority before the descriptor handoff.
    pub fn load_consumed_and_validate(
        &self,
        evidence_id: &str,
        peer: &PeerCred,
    ) -> Result<MigrationLaunchBinding, Failure> {
        if !valid_evidence_id(evidence_id) {
            return Err(denied("migration launch store: invalid evidence ID"));
        }
        let binding = self.load(&self.tombstone_path(evidence_id))?;
        if binding.launch_evidence_id != evidence_id {
            return Err(denied("migration launch store: evidence ID mismatch"));
        }
        binding.validate(OffsetDateTime::now_utc()).map_err(|e| {
            denied(format!(
                "migration launch store: invalid evidence: {}",
                e.message()
            ))
        })?;
        let expected = self.signing.fingerprint(
            MIGRATION_LAUNCH_BINDING_HMAC_DOMAIN,
            &binding.canonical_payload(),
        );
        if !ct_eq(expected.as_bytes(), binding.hmac.as_bytes()) {
            return Err(denied("migration launch store: HMAC verification failed"));
        }
        self.validate_peer(&binding, peer)?;
        Ok(binding)
    }

    /// `ValidatePeer` — every process-identity field of the consumed
    /// evidence plus the kernel process start time.
    pub fn validate_peer(
        &self,
        binding: &MigrationLaunchBinding,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        if peer.pid.as_raw_pid() <= 0 {
            return Err(denied("migration launch store: missing peer credentials"));
        }
        if peer.uid.as_raw() != binding.peer_uid
            || peer.gid.as_raw() != binding.peer_gid
            || peer.pid.as_raw_pid() != binding.peer_pid
        {
            return Err(denied("migration launch store: peer identity mismatch"));
        }
        let (executable, start) = verify_peer_process(peer.pid.as_raw_pid())
            .map_err(|e| internal(format!("migration launch store: verify peer process: {e}")))?;
        if executable != binding.executable {
            return Err(denied("migration launch store: peer executable mismatch"));
        }
        if start != binding.process_start {
            return Err(denied(
                "migration launch store: peer process start mismatch",
            ));
        }
        Ok(())
    }

    /// `ReportOutcomeWithResult` — monotonic transitions from the
    /// exact consumed launch identity only.
    pub fn report_outcome(
        &self,
        evidence_id: &str,
        peer: &PeerCred,
        state: MigrationLaunchOutcomeState,
        reason: &str,
        result: Option<MigrationOperatorResult>,
    ) -> Result<(), Failure> {
        if !matches!(
            state,
            MigrationLaunchOutcomeState::Started
                | MigrationLaunchOutcomeState::Succeeded
                | MigrationLaunchOutcomeState::Failed
        ) {
            return Err(denied("migration launch store: invalid reported outcome"));
        }
        let binding = self.load_consumed_and_validate(evidence_id, peer)?;
        self.transition_outcome(
            evidence_id,
            &binding.operation_id.to_string(),
            state,
            reason,
            result,
        )
    }

    /// `FailConsumed` — the broker's internal fail-safe for a
    /// consumed launch whose descriptor handoff could not complete.
    /// No peer revalidation: the broker is settling its own failure.
    pub fn fail_consumed(
        &self,
        binding: &MigrationLaunchBinding,
        reason: &str,
    ) -> Result<(), Failure> {
        if binding.launch_evidence_id.is_empty() || binding.operation_id.is_nil() {
            return Err(denied(
                "migration launch store: invalid consumed launch binding",
            ));
        }
        self.transition_outcome(
            &binding.launch_evidence_id,
            &binding.operation_id.to_string(),
            MigrationLaunchOutcomeState::Failed,
            reason,
            None,
        )
    }

    /// `ReconcileUnreported` — settle a consumed launch whose
    /// operator died or expired before reporting `started`. A dead or
    /// expired peer is terminally ambiguous; never infer success.
    pub fn reconcile_unreported(
        &self,
        evidence_id: &str,
        operation_id: &str,
    ) -> Result<MigrationLaunchOutcome, Failure> {
        let lock = self.lock_outcome(evidence_id)?;
        let result = self.reconcile_locked(evidence_id, operation_id);
        durable::unlock_and_close(lock);
        result
    }

    fn reconcile_locked(
        &self,
        evidence_id: &str,
        operation_id: &str,
    ) -> Result<MigrationLaunchOutcome, Failure> {
        let outcome = self.read_outcome(evidence_id, operation_id)?;
        if outcome.state != MigrationLaunchOutcomeState::Issued {
            return Ok(outcome);
        }
        let binding = self
            .load(&self.tombstone_path(evidence_id))
            .map_err(|_| denied("migration launch store: consumed launch binding unavailable"))?;
        if binding.operation_id.to_string() != operation_id {
            return Err(denied(
                "migration launch store: consumed launch binding unavailable",
            ));
        }
        // If the recorded peer process still matches the binding and
        // the deadline hasn't passed, the operator may still be
        // running — keep `issued`.
        if let Ok((executable, start)) = verify_peer_process(binding.peer_pid)
            && executable == binding.executable
            && start == binding.process_start
            && OffsetDateTime::now_utc() < binding.deadline
        {
            return Ok(outcome);
        }
        let reconciled = MigrationLaunchOutcome {
            state: MigrationLaunchOutcomeState::Ambiguous,
            reason: "operator exited or launch authority expired before reporting started"
                .to_owned(),
            safe_next_action: "RUN_CENTRAL_MIGRATE_RESUME_WITH_OPERATION_ID".to_owned(),
            updated_at: OffsetDateTime::now_utc(),
            ..outcome
        };
        self.write_outcome(&reconciled)?;
        Ok(reconciled)
    }

    /// `ReadOutcome` — the durable outcome for `(evidence, operation)`.
    pub fn read_outcome(
        &self,
        evidence_id: &str,
        operation_id: &str,
    ) -> Result<MigrationLaunchOutcome, Failure> {
        if !valid_evidence_id(evidence_id) || operation_id.is_empty() {
            return Err(denied("migration launch store: invalid outcome lookup"));
        }
        durable::validate_private_directory(&self.outcome_root, &dir_label("outcome root"))?;
        let payload = durable::read_file(&self.outcome_path(evidence_id))
            .map_err(|e| internal(format!("migration launch store: read outcome: {e}")))?;
        let outcome: MigrationLaunchOutcome = serde_json::from_slice(&payload)
            .map_err(|e| internal(format!("migration launch store: decode outcome: {e}")))?;
        if outcome.launch_evidence_id != evidence_id || outcome.operation_id != operation_id {
            return Err(denied("migration launch store: outcome binding mismatch"));
        }
        Ok(outcome)
    }

    /// `transitionOutcome` — the outcome lock serializes every
    /// read-check-write so two concurrent reporters can't overwrite
    /// each other's terminal evidence.
    fn transition_outcome(
        &self,
        evidence_id: &str,
        operation_id: &str,
        state: MigrationLaunchOutcomeState,
        reason: &str,
        result: Option<MigrationOperatorResult>,
    ) -> Result<(), Failure> {
        let lock = self.lock_outcome(evidence_id)?;
        let r = (|| {
            let mut outcome = self.read_outcome(evidence_id, operation_id)?;
            if outcome.terminal() {
                if outcome.state == state && outcome.reason == reason {
                    return Ok(());
                }
                return Err(denied(
                    "migration launch store: terminal outcome already recorded",
                ));
            }
            if outcome.state == MigrationLaunchOutcomeState::Issued
                && !matches!(
                    state,
                    MigrationLaunchOutcomeState::Started | MigrationLaunchOutcomeState::Failed
                )
            {
                return Err(denied(
                    "migration launch store: launch must start before succeeding",
                ));
            }
            outcome.state = state;
            outcome.reason = reason.to_owned();
            outcome.operator_result = result;
            outcome.updated_at = OffsetDateTime::now_utc();
            self.write_outcome(&outcome)
        })();
        durable::unlock_and_close(lock);
        r
    }

    fn lock_outcome(&self, evidence_id: &str) -> Result<OwnedFd, Failure> {
        if !valid_evidence_id(evidence_id) {
            return Err(denied("migration launch store: invalid outcome lock"));
        }
        durable::validate_private_directory(&self.outcome_root, &dir_label("outcome root"))?;
        durable::open_lock(&self.outcome_lock_path(evidence_id))
    }

    /// `writeOutcome` — temp `0600` + fsync + atomic replace rename +
    /// dir sync.
    fn write_outcome(&self, outcome: &MigrationLaunchOutcome) -> Result<(), Failure> {
        durable::validate_private_directory(&self.outcome_root, &dir_label("outcome root"))?;
        let payload = serde_json::to_vec(outcome)
            .map_err(|e| internal(format!("migration launch store: encode outcome: {e}")))?;
        let tmp = durable::unique_tmp(&self.outcome_root, ".outcome-")?;
        let result = (|| -> Result<(), Failure> {
            let mut file = durable::open_exclusive(&tmp, durable::PRIVATE_FILE_MODE)
                .map_err(|e| internal(format!("migration launch store: create outcome: {e}")))?;
            file.write_all(&payload)
                .and_then(|()| file.sync_all())
                .map_err(|e| internal(format!("migration launch store: write outcome: {e}")))?;
            drop(file);
            durable::rename_replace(&tmp, &self.outcome_path(&outcome.launch_evidence_id))
        })();
        if result.is_err() {
            let _ = durable::remove_file(&tmp);
        }
        result?;
        durable::sync_dir(&self.outcome_root)
    }

    /// `write` — temp `0600` + fsync + `RENAME_NOREPLACE` publish +
    /// dir sync (`publishMigrationLaunchEvidence`).
    fn write(&self, binding: &MigrationLaunchBinding) -> Result<(), Failure> {
        durable::validate_private_directory(&self.root, &dir_label("root"))?;
        let payload = serde_json::to_vec(binding)
            .map_err(|e| internal(format!("migration launch store: encode evidence: {e}")))?;
        let tmp = durable::unique_tmp(&self.root, ".launch-")?;
        let target = self.active_path(&binding.launch_evidence_id);
        let result = (|| -> Result<(), Failure> {
            let mut file = durable::open_exclusive(&tmp, durable::PRIVATE_FILE_MODE)
                .map_err(|e| internal(format!("migration launch store: create evidence: {e}")))?;
            file.write_all(&payload)
                .and_then(|()| file.sync_all())
                .map_err(|e| internal(format!("migration launch store: write evidence: {e}")))?;
            drop(file);
            durable::rename_noreplace(&tmp, &target).map_err(|e| {
                if e.message().contains("exist") || e.message().contains("File exists") {
                    denied("migration launch store: evidence ID collision")
                } else {
                    internal(format!(
                        "migration launch store: publish evidence: {}",
                        e.message()
                    ))
                }
            })
        })();
        if result.is_err() {
            let _ = durable::remove_file(&tmp);
        }
        result?;
        durable::sync_dir(&self.root)
    }

    /// `load` — `O_RDONLY|O_NOFOLLOW`, private-file shape check,
    /// decode.
    fn load(&self, path: &Path) -> Result<MigrationLaunchBinding, Failure> {
        durable::validate_private_directory(&self.root, &dir_label("root"))?;
        let file = durable::open_read(path).map_err(|e| {
            if e == rustix::io::Errno::NOENT {
                denied("migration launch store: evidence unavailable")
            } else {
                internal(format!("migration launch store: open evidence: {e}"))
            }
        })?;
        let meta = rustix::fs::fstat(&file)
            .map_err(|e| internal(format!("migration launch store: stat evidence: {e}")))?;
        durable::validate_private_file(&meta, "evidence")?;
        use std::io::Read as _;
        let mut file = file;
        let mut payload = Vec::new();
        file.read_to_end(&mut payload)
            .map_err(|e| internal(format!("migration launch store: read evidence: {e}")))?;
        serde_json::from_slice(&payload)
            .map_err(|e| internal(format!("migration launch store: decode evidence: {e}")))
    }

    fn active_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    fn tombstone_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json.consumed"))
    }

    fn outcome_path(&self, id: &str) -> PathBuf {
        self.outcome_root.join(format!("{id}.json"))
    }

    fn outcome_lock_path(&self, id: &str) -> PathBuf {
        self.outcome_root.join(format!("{id}.lock"))
    }
}

/// `verifyPeerProcess` — `/proc/<pid>/exe` resolved plus the
/// `starttime` field (22nd) of `/proc/<pid>/stat`, which lives after
/// the last `)` because the comm field can contain spaces/parens.
pub fn verify_peer_process(pid: i32) -> Result<(String, String), Failure> {
    // `readlinkat` (267 — allow-listed, SC-DEF-36) instead of
    // `canonicalize`, whose multi-component resolution emits `statx`.
    let exe = rustix::fs::readlinkat(
            rustix::fs::CWD,
            format!("/proc/{pid}/exe"),
            Vec::new(),
        )
        .map_err(|e| internal(format!("resolve exe symlink: {e}")))?
        .to_string_lossy()
        .into_owned();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| internal(format!("read stat: {e}")))?;
    let paren = stat
        .rfind(')')
        .ok_or_else(|| internal("parse stat: unexpected format"))?;
    let fields: Vec<&str> = stat[paren + 1..].split_whitespace().collect();
    if fields.len() < 20 {
        return Err(internal("parse stat: insufficient fields"));
    }
    Ok((exe, fields[19].to_owned()))
}

/// `hmac.Equal` — length-independent constant-time compare.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
