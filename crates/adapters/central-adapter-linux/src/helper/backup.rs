//! `helper/backup_launch.go` + `helper/backup_read.go` +
//! `helper/backup_read_client_linux.go` +
//! `cmd/central/backup_helper_composition.go`'s descriptor seams —
//! the root helper's `backup-create`, `backup-verify`, and
//! `backup-status` verbs.
//!
//! `backup-create` runs upstream's full authority sequence: PAM
//! ceremony → fixed descriptor → throughput gate → CBL1 launch →
//! broker launch evidence → operation-bound MinIO handoff → commit →
//! wait/reap → retained-lock assertions → broker reap evidence →
//! helper re-attestation → broker attested seal → release. Every
//! refusal between launch and commit aborts the worker; every refusal
//! after commit releases the retained target lock. No request field
//! can select a path, descriptor, target, credential, or flag.
//!
//! `backup-verify`/`backup-status` are the descriptor-bound,
//! locator-free reads: repository evidence is verified in the helper
//! and then bound to the broker journal's sealed record, or the
//! operation projection is read straight from the broker.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use central_backup::backup::capacity::RecoveryProfile;
use central_backup::backup::operation::{BackupOperation, BackupPhase};
use central_backup::repository::{
    BackupRepositoryAttestation, BackupTargetLockAttestation, RepositoryBinding,
    new_backup_target_lock_attestation,
};
use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::PeerIdentity;
use super::lifecycle::LifecycleConfirmer;
use super::protocol::{Request, Response, read_response, strict_decode, write_request};
use crate::broker::backup_launch::{BackupLaunchAuthority, BackupLaunchEvidence};

/// `centralBackupExecutable` — the fixed worker binary the native
/// supervisor launches; a request can never name another.
pub const CENTRAL_BACKUP_EXECUTABLE: &str = "/usr/lib/central/central-backup";
/// `authority.CentralRuntimeUID` — the worker and repository owner.
pub const CENTRAL_RUNTIME_UID: u32 = crate::broker::protocol::CENTRAL_RUNTIME_UID;
/// `authority.CentralRuntimeGID`.
pub const CENTRAL_RUNTIME_GID: u32 = crate::broker::protocol::CENTRAL_RUNTIME_GID;
/// `backupCreateDeadline` — the transport's bound on one create.
pub const BACKUP_CREATE_DEADLINE: Duration = Duration::from_secs(2 * 60 * 60);
/// `backupVerifyDeadline`.
pub const BACKUP_VERIFY_DEADLINE: Duration = Duration::from_secs(2 * 60);
/// `abortBackupLaunch`/`releaseBackupTargetLock`'s fresh cleanup
/// budget — never the possibly-expired request's.
const CLEANUP_BUDGET: Duration = Duration::from_secs(30);

/// The exact launch environment — `BackupProcessSpec.Env` must carry
/// exactly this set, in order, like the migration spec's.
const BACKUP_LAUNCH_ENVIRONMENT: [&str; 3] =
    ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"];

fn invalid() -> Failure {
    Failure::invalid("helper_backup", "helper: invalid backup request")
}

fn unavailable(what: &str) -> Failure {
    Failure::internal("helper_backup", format!("helper: {what} unavailable"))
}

fn is_v7(id: Uuid) -> bool {
    id.get_version_num() == 7
}

fn budget(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

// ---------------------------------------------------------------------------
// Requests/results — `helper/protocol.go`'s closed typed payloads.
// ---------------------------------------------------------------------------

/// `BackupCreateRequest` — only the enclosing operation ID; the helper
/// owns the descriptor, process identity, executable, deadline, and
/// environment.
#[derive(Debug, Clone)]
pub struct BackupCreateRequest {
    pub operation_id: String,
}

/// `BackupVerifyRequest` — the sealed backup the caller claims.
#[derive(Debug, Clone)]
pub struct BackupVerifyRequest {
    pub backup_id: String,
}

/// `BackupStatusRequest` — the enclosing operation ID only.
#[derive(Debug, Clone)]
pub struct BackupStatusRequest {
    pub operation_id: String,
}

/// `BackupVerifyResult` — the locator-free verification projection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVerifyResult {
    pub operation_id: String,
    pub backup_id: String,
    pub phase: String,
    pub verified: bool,
}

/// `BackupStatusResult` — the locator-free operation projection. The
/// broker's `backup_read_status` result marshals the same shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupStatusResult {
    pub operation_id: String,
    pub backup_id: String,
    pub phase: String,
    pub reason: String,
}

/// `ParseBackupCreateRequest` — `operation_id` non-empty, payload
/// absent or exactly an empty object.
pub fn parse_backup_create_request(req: &Request) -> Result<BackupCreateRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing backup operation".to_owned());
    }
    super::protocol::payload_is_empty_object(req.payload_bytes())?;
    Ok(BackupCreateRequest {
        operation_id: req.operation_id.clone(),
    })
}

/// `ParseBackupVerifyRequest` — a strict `{backup_id}` whose value
/// must equal the enclosing operation ID.
pub fn parse_backup_verify_request(req: &Request) -> Result<BackupVerifyRequest, String> {
    if req.operation_id.is_empty() || req.payload_bytes().is_empty() {
        return Err("helper: missing backup verify request".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        backup_id: String,
    }
    let wire: Wire = strict_decode(req.payload_bytes())
        .map_err(|e| format!("helper: invalid backup verify request: {e}"))?;
    if wire.backup_id.is_empty() || wire.backup_id != req.operation_id {
        return Err("helper: invalid backup verify request".to_owned());
    }
    Ok(BackupVerifyRequest {
        backup_id: wire.backup_id,
    })
}

/// `ParseBackupStatusRequest` — `operation_id` non-empty, payload
/// absent or exactly `{}`.
pub fn parse_backup_status_request(req: &Request) -> Result<BackupStatusRequest, String> {
    if req.operation_id.is_empty() {
        return Err("helper: missing backup status request".to_owned());
    }
    let trimmed: &[u8] = {
        let p = req.payload_bytes();
        let s = p
            .iter()
            .position(|c| !c.is_ascii_whitespace())
            .unwrap_or(p.len());
        let e = p
            .iter()
            .rposition(|c| !c.is_ascii_whitespace())
            .map_or(s, |i| i + 1);
        &p[s..e.max(s)]
    };
    if !trimmed.is_empty() && trimmed != b"{}" {
        return Err("helper: invalid backup status request".to_owned());
    }
    Ok(BackupStatusRequest {
        operation_id: req.operation_id.clone(),
    })
}

// ---------------------------------------------------------------------------
// Backup-create — `backup_launch.go`.
// ---------------------------------------------------------------------------

/// `BackupLaunchEvidenceIssuer` — the broker-facing seam; the broker,
/// not the helper or caller, mints the opaque evidence identity.
pub trait BackupLaunchEvidenceIssuer: Send + Sync {
    fn issue_backup_launch(
        &self,
        deadline: Instant,
        evidence: &BackupLaunchEvidence,
    ) -> Result<BackupLaunchAuthority, Failure>;
}

/// `BackupThroughputGate` — admits a normal backup only after fresh
/// C02 evidence has been verified or produced for the exact
/// helper-opened repository. Invoked after PAM and descriptor
/// validation, before any worker or MinIO credential exists.
pub trait BackupThroughputGate: Send + Sync {
    fn require_backup_throughput(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        descriptor: &BackupRepositoryDescriptor,
    ) -> Result<(), Failure>;
}

/// `BackupMinioCredentialPreparer` — provisions the operation-bound,
/// read-only MinIO credential while the native worker is still held
/// behind commit. Helper-owned: neither the CLI nor the worker may
/// select the provisioner, credential scope, root secret, or target.
pub trait BackupMinioCredentialPreparer: Send + Sync {
    fn prepare_backup_minio(
        &self,
        deadline: Instant,
        authority: &BackupLaunchAuthority,
        expires_at: OffsetDateTime,
    ) -> Result<(), Failure>;
}

/// `BackupRepositoryDescriptor` — selected by trusted helper
/// composition. No request field can influence the descriptor or
/// binding.
pub struct BackupRepositoryDescriptor {
    pub fd: OwnedFd,
    pub binding: RepositoryBinding,
}

/// `BackupRepositoryDescriptorSource`.
pub trait BackupRepositoryDescriptorSource: Send + Sync {
    fn open_backup_repository(&self) -> Result<BackupRepositoryDescriptor, Failure>;
}

/// `BackupRepositoryAttestor` — recomputes the sealed repository's
/// physical evidence under the exclusive lock, post-reap.
pub trait BackupRepositoryAttestor: Send + Sync {
    fn attest_backup_repository(
        &self,
        descriptor: &BackupRepositoryDescriptor,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        backup_id: Uuid,
        attested_at: OffsetDateTime,
    ) -> Result<BackupRepositoryAttestation, Failure>;
}

/// `BackupLaunchReaper` — the broker-facing post-reap evidence seam.
pub trait BackupLaunchReaper: Send + Sync {
    fn mark_backup_launch_reaped(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        target_lock_proof: [u8; 32],
        reaped_at: OffsetDateTime,
    ) -> Result<(), Failure>;
}

/// `backupport.BackupSealAttestationCompleter` — the broker-facing
/// terminal-seal transition. The helper supplies its own re-derived
/// attestation and retained-lock assertion; the worker's claims are
/// never accepted.
pub trait BackupSealAttestationCompleter: Send + Sync {
    fn complete_attested_backup_seal(
        &self,
        deadline: Instant,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        attestation: &BackupRepositoryAttestation,
        target_lock: &BackupTargetLockAttestation,
    ) -> Result<BackupOperation, Failure>;
}

/// `BackupProcessMode` — the closed launch-mode set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupProcessMode {
    /// `backup-create`.
    Create,
    /// `throughput-probe`.
    ThroughputProbe,
}

impl BackupProcessMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "backup-create",
            Self::ThroughputProbe => "throughput-probe",
        }
    }
}

/// `BackupProcessSpec` — the complete fixed launch policy; every
/// field is composition-supplied, never caller-supplied.
pub struct BackupProcessSpec<'a> {
    pub executable: &'a str,
    pub mode: BackupProcessMode,
    pub operation_id: Uuid,
    pub repository_fd: BorrowedFd<'a>,
    pub uid: u32,
    pub gid: u32,
    /// Evidence expiry — upstream's `time.Time` deadline.
    pub deadline: OffsetDateTime,
    pub env: &'a [&'a str],
}

/// `BackupProcess` — the observed child identity. `pidfd` is owned;
/// dropping the process releases it, upstream's `CloseIdentity`.
pub struct BackupProcess {
    pub launch_id: Uuid,
    pub pid: i32,
    pub pidfd: OwnedFd,
    pub process_start: String,
    pub executable: String,
}

/// `BackupProcessOutcome` — the locator-free worker result.
pub struct BackupProcessOutcome {
    pub succeeded: bool,
    pub target_lock_proof: [u8; 32],
}

/// `BackupProcessCensus` — the supervisor's own count of other live
/// processes and held offline permits, excluding the queried launch.
pub struct BackupProcessCensus {
    pub live_processes: u32,
    pub held_permits: u32,
}

/// `BackupProcessLauncher` — the native supervisor seam.
pub trait BackupProcessLauncher: Send + Sync {
    fn launch(&self, spec: &BackupProcessSpec<'_>) -> Result<BackupProcess, Failure>;
    fn commit(&self, deadline: Instant, launch_id: Uuid, evidence_id: Uuid) -> Result<(), Failure>;
    fn wait_and_reap(
        &self,
        deadline: Instant,
        launch_id: Uuid,
    ) -> Result<BackupProcessOutcome, Failure>;
    fn assert_target_lock_retained(
        &self,
        deadline: Instant,
        launch_id: Uuid,
    ) -> Result<[u8; 32], Failure>;
    fn release_and_reap(&self, deadline: Instant, launch_id: Uuid) -> Result<(), Failure>;
    fn abort(&self, deadline: Instant, launch_id: Uuid) -> Result<(), Failure>;
    fn census(&self, deadline: Instant, launch_id: Uuid) -> Result<BackupProcessCensus, Failure>;
}

/// `BackupCreator` — the `Server::backup_create` field type.
pub trait BackupCreator: Send + Sync {
    fn create_backup(
        &self,
        deadline: Instant,
        request: BackupCreateRequest,
        peer: &PeerIdentity,
    ) -> Response;
}

/// `BackupCreateHandler` — the complete post-reap authority sequence.
/// The worker may write and request a companion but never receives
/// the capability that can terminalize the protected seal. Each seam
/// is an `Option` so upstream's `h == nil || h.x == nil` completeness
/// gate (`BACKUP_CREATE_AUTHORIZATION_REQUIRED`) stays reachable.
pub struct BackupCreateHandler {
    pam: Option<Box<dyn LifecycleConfirmer>>,
    throughput: Option<Box<dyn BackupThroughputGate>>,
    issuer: Option<Box<dyn BackupLaunchEvidenceIssuer>>,
    minio: Option<Box<dyn BackupMinioCredentialPreparer>>,
    source: Option<Box<dyn BackupRepositoryDescriptorSource>>,
    launcher: Option<Box<dyn BackupProcessLauncher>>,
    attestor: Option<Box<dyn BackupRepositoryAttestor>>,
    reaper: Option<Box<dyn BackupLaunchReaper>>,
    completer: Option<Box<dyn BackupSealAttestationCompleter>>,
    now: Option<fn() -> OffsetDateTime>,
}

impl BackupCreateHandler {
    /// `NewBackupCreateHandler` — every seam installed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pam: Box<dyn LifecycleConfirmer>,
        throughput: Box<dyn BackupThroughputGate>,
        issuer: Box<dyn BackupLaunchEvidenceIssuer>,
        minio: Box<dyn BackupMinioCredentialPreparer>,
        source: Box<dyn BackupRepositoryDescriptorSource>,
        launcher: Box<dyn BackupProcessLauncher>,
        attestor: Box<dyn BackupRepositoryAttestor>,
        reaper: Box<dyn BackupLaunchReaper>,
        completer: Box<dyn BackupSealAttestationCompleter>,
    ) -> Self {
        Self {
            pam: Some(pam),
            throughput: Some(throughput),
            issuer: Some(issuer),
            minio: Some(minio),
            source: Some(source),
            launcher: Some(launcher),
            attestor: Some(attestor),
            reaper: Some(reaper),
            completer: Some(completer),
            now: Some(OffsetDateTime::now_utc),
        }
    }

    /// The honest production constructor for a composition that
    /// cannot yet produce every seam: `None` fields keep upstream's
    /// `h.* == nil` completeness gate reachable, so the verb answers
    /// `BACKUP_CREATE_AUTHORIZATION_REQUIRED` — never a made-up
    /// success and never a refusal outside the closed set.
    #[allow(clippy::too_many_arguments)]
    pub fn new_incomplete(
        pam: Option<Box<dyn LifecycleConfirmer>>,
        throughput: Option<Box<dyn BackupThroughputGate>>,
        issuer: Option<Box<dyn BackupLaunchEvidenceIssuer>>,
        minio: Option<Box<dyn BackupMinioCredentialPreparer>>,
        source: Option<Box<dyn BackupRepositoryDescriptorSource>>,
        launcher: Option<Box<dyn BackupProcessLauncher>>,
        attestor: Option<Box<dyn BackupRepositoryAttestor>>,
        reaper: Option<Box<dyn BackupLaunchReaper>>,
        completer: Option<Box<dyn BackupSealAttestationCompleter>>,
    ) -> Self {
        Self {
            pam,
            throughput,
            issuer,
            minio,
            source,
            launcher,
            attestor,
            reaper,
            completer,
            now: Some(OffsetDateTime::now_utc),
        }
    }

    /// `launcher` defaults to the native CBL1 client when `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn with_native_launcher(
        pam: Box<dyn LifecycleConfirmer>,
        throughput: Box<dyn BackupThroughputGate>,
        issuer: Box<dyn BackupLaunchEvidenceIssuer>,
        minio: Box<dyn BackupMinioCredentialPreparer>,
        source: Box<dyn BackupRepositoryDescriptorSource>,
        launcher: Option<Box<dyn BackupProcessLauncher>>,
        attestor: Box<dyn BackupRepositoryAttestor>,
        reaper: Box<dyn BackupLaunchReaper>,
        completer: Box<dyn BackupSealAttestationCompleter>,
    ) -> Self {
        Self::new(
            pam,
            throughput,
            issuer,
            minio,
            source,
            launcher.unwrap_or_else(|| Box::new(NativeBackupProcessLauncher::new())),
            attestor,
            reaper,
            completer,
        )
    }

    /// The test seam for `h.now`.
    #[doc(hidden)]
    pub fn set_now(&mut self, now: fn() -> OffsetDateTime) {
        self.now = Some(now);
    }
}

/// `abortBackupLaunch` — synchronous abort on a fresh budget; a
/// nil launch ID is the upstream "abort unavailable" refusal.
fn abort_backup_launch(launcher: &dyn BackupProcessLauncher, launch_id: Uuid) -> bool {
    if launch_id.is_nil() {
        return false;
    }
    launcher
        .abort(Instant::now() + CLEANUP_BUDGET, launch_id)
        .is_ok()
}

/// `releaseBackupTargetLock` — same fresh-budget release.
fn release_backup_target_lock(launcher: &dyn BackupProcessLauncher, launch_id: Uuid) -> bool {
    if launch_id.is_nil() {
        return false;
    }
    launcher
        .release_and_reap(Instant::now() + CLEANUP_BUDGET, launch_id)
        .is_ok()
}

/// Upstream's `released` flag + deferred `ReleaseAndReap` — an RAII
/// guard so the retained target lock cannot survive a `?` return.
struct ReleaseGuard<'a> {
    launcher: &'a dyn BackupProcessLauncher,
    launch_id: Uuid,
    released: bool,
}

impl Drop for ReleaseGuard<'_> {
    fn drop(&mut self) {
        if !self.released {
            release_backup_target_lock(self.launcher, self.launch_id);
        }
    }
}

impl BackupCreator for BackupCreateHandler {
    fn create_backup(
        &self,
        deadline: Instant,
        request: BackupCreateRequest,
        peer: &PeerIdentity,
    ) -> Response {
        let Ok(operation_id) = Uuid::parse_str(&request.operation_id) else {
            return Response::denied(&request.operation_id, 2, "INVALID_BACKUP_CREATE_REQUEST");
        };
        if peer.pid <= 0 {
            return Response::denied(&request.operation_id, 2, "INVALID_BACKUP_CREATE_REQUEST");
        }
        // `h == nil || h.pam == nil || …` — upstream's completeness
        // gate, exactly before the ceremony.
        let (
            Some(pam),
            Some(throughput),
            Some(issuer),
            Some(minio),
            Some(source),
            Some(launcher),
            Some(attestor),
            Some(reaper),
            Some(completer),
            Some(now),
        ) = (
            &self.pam,
            &self.throughput,
            &self.issuer,
            &self.minio,
            &self.source,
            &self.launcher,
            &self.attestor,
            &self.reaper,
            &self.completer,
            self.now,
        )
        else {
            return Response::denied(
                &request.operation_id,
                7,
                "BACKUP_CREATE_AUTHORIZATION_REQUIRED",
            );
        };
        let confirmation = match pam.confirm(*peer, Some(deadline), &request.operation_id) {
            Ok(token) => token,
            Err(_) => {
                return Response::denied(&request.operation_id, 7, "AUTHORITY_DENIED");
            }
        };
        if !pam.verify_and_consume(&confirmation) {
            return Response::denied(&request.operation_id, 7, "AUTHORITY_DENIED");
        }
        let descriptor = match source.open_backup_repository() {
            Ok(d)
                if d.binding.verify().is_ok()
                    && d.binding.owner_uid == CENTRAL_RUNTIME_UID
                    && d.binding.owner_gid == CENTRAL_RUNTIME_GID =>
            {
                d
            }
            _ => {
                return Response::new(
                    &request.operation_id,
                    "error",
                    6,
                    "BACKUP_REPOSITORY_AUTHORITY_UNAVAILABLE",
                );
            }
        };
        if throughput
            .require_backup_throughput(deadline, operation_id, &descriptor)
            .is_err()
        {
            return Response::new(
                &request.operation_id,
                "error",
                3,
                "THROUGHPUT_EVIDENCE_REQUIRED",
            );
        }
        let launch_deadline = now() + BACKUP_CREATE_DEADLINE;
        let process = match launcher.launch(&BackupProcessSpec {
            executable: CENTRAL_BACKUP_EXECUTABLE,
            mode: BackupProcessMode::Create,
            operation_id,
            repository_fd: descriptor.fd.as_fd(),
            uid: CENTRAL_RUNTIME_UID,
            gid: CENTRAL_RUNTIME_GID,
            deadline: launch_deadline,
            env: &BACKUP_LAUNCH_ENVIRONMENT,
        }) {
            Ok(p) => p,
            Err(_) => {
                return Response::new(
                    &request.operation_id,
                    "error",
                    6,
                    "BACKUP_WORKER_LAUNCH_FAILED",
                );
            }
        };
        // `process.CloseIdentity` — the OwnedFd drop releases it.
        if process.launch_id.is_nil()
            || process.pid <= 0
            || process.process_start.is_empty()
            || process.executable != CENTRAL_BACKUP_EXECUTABLE
        {
            let _ = abort_backup_launch(launcher.as_ref(), process.launch_id);
            return Response::new(
                &request.operation_id,
                "error",
                6,
                "BACKUP_WORKER_IDENTITY_UNAVAILABLE",
            );
        }
        let authority_receipt = match issuer.issue_backup_launch(
            deadline,
            &BackupLaunchEvidence {
                supervisor_launch_id: process.launch_id,
                pid: process.pid,
                process_start: process.process_start.clone(),
                executable: process.executable.clone(),
                mode: BackupProcessMode::Create.as_str().to_owned(),
                operation_id: request.operation_id.clone(),
                repository_binding: descriptor.binding.clone(),
                expires_at: launch_deadline,
            },
        ) {
            Ok(a)
                if !a.launch_evidence_id.is_nil()
                    && a.operation_id == operation_id
                    && !a.backup_id.is_nil() =>
            {
                a
            }
            _ => {
                let _ = abort_backup_launch(launcher.as_ref(), process.launch_id);
                return Response::new(
                    &request.operation_id,
                    "error",
                    6,
                    "BACKUP_LAUNCH_EVIDENCE_FAILED",
                );
            }
        };
        if minio
            .prepare_backup_minio(deadline, &authority_receipt, launch_deadline)
            .is_err()
        {
            let _ = abort_backup_launch(launcher.as_ref(), process.launch_id);
            return Response::new(
                &request.operation_id,
                "error",
                6,
                "BACKUP_MINIO_CREDENTIAL_PROVISION_FAILED",
            );
        }
        if launcher
            .commit(
                deadline,
                process.launch_id,
                authority_receipt.launch_evidence_id,
            )
            .is_err()
        {
            let _ = abort_backup_launch(launcher.as_ref(), process.launch_id);
            return Response::new(
                &request.operation_id,
                "error",
                6,
                "BACKUP_LAUNCH_COMMIT_FAILED",
            );
        }
        let outcome = match launcher.wait_and_reap(deadline, process.launch_id) {
            Ok(o) if o.succeeded => o,
            _ => {
                let _ = abort_backup_launch(launcher.as_ref(), process.launch_id);
                return Response::new(&request.operation_id, "error", 6, "BACKUP_WORKER_FAILED");
            }
        };
        // From here the lock is released on every exit until the
        // explicit `released` disarm below — upstream's deferred
        // `releaseBackupTargetLock`.
        let mut guard = ReleaseGuard {
            launcher: launcher.as_ref(),
            launch_id: process.launch_id,
            released: false,
        };
        let retention = match launcher.assert_target_lock_retained(deadline, process.launch_id) {
            Ok(p) if p != [0u8; 32] && p == outcome.target_lock_proof => p,
            _ => {
                return Response::new(
                    &request.operation_id,
                    "error",
                    6,
                    "BACKUP_TARGET_LOCK_RETENTION_LOST",
                );
            }
        };
        let reaped_at = now();
        if reaper
            .mark_backup_launch_reaped(
                deadline,
                operation_id,
                authority_receipt.launch_evidence_id,
                retention,
                reaped_at,
            )
            .is_err()
        {
            return Response::new(
                &request.operation_id,
                "error",
                6,
                "BACKUP_WORKER_REAP_EVIDENCE_FAILED",
            );
        }
        let attested_at = now();
        let attestation = match attestor.attest_backup_repository(
            &descriptor,
            authority_receipt.launch_evidence_id,
            operation_id,
            authority_receipt.backup_id,
            attested_at,
        ) {
            Ok(a)
                if a.verify().is_ok()
                    && a.launch_evidence_id == authority_receipt.launch_evidence_id
                    && a.operation_id == operation_id
                    && a.backup_id == authority_receipt.backup_id =>
            {
                a
            }
            _ => {
                return Response::new(
                    &request.operation_id,
                    "error",
                    6,
                    "BACKUP_POST_REAP_ATTESTATION_FAILED",
                );
            }
        };
        let retained_proof = match launcher.assert_target_lock_retained(deadline, process.launch_id)
        {
            Ok(p) if p == retention => p,
            _ => {
                return Response::new(
                    &request.operation_id,
                    "error",
                    6,
                    "BACKUP_TARGET_LOCK_RETENTION_LOST",
                );
            }
        };
        let lock_attestation = match new_backup_target_lock_attestation(
            process.launch_id,
            authority_receipt.launch_evidence_id,
            operation_id,
            authority_receipt.backup_id,
            retained_proof,
            now(),
        ) {
            Ok(a) => a,
            Err(_) => {
                return Response::new(
                    &request.operation_id,
                    "error",
                    6,
                    "BACKUP_TARGET_LOCK_RETENTION_LOST",
                );
            }
        };
        let sealed = match completer.complete_attested_backup_seal(
            deadline,
            operation_id,
            authority_receipt.launch_evidence_id,
            &attestation,
            &lock_attestation,
        ) {
            Ok(s)
                if s.validate().is_ok()
                    && s.operation_id == operation_id
                    && s.backup_id == authority_receipt.backup_id
                    && s.phase == BackupPhase::Sealed =>
            {
                s
            }
            _ => {
                return Response::new(
                    &request.operation_id,
                    "error",
                    6,
                    "BACKUP_SEAL_COMPLETION_UNKNOWN",
                );
            }
        };
        if launcher
            .release_and_reap(deadline, process.launch_id)
            .is_err()
        {
            return Response::new(
                &request.operation_id,
                "error",
                6,
                "BACKUP_TARGET_LOCK_RELEASE_UNKNOWN",
            );
        }
        guard.released = true;
        /// `struct{OperationID, BackupID, Phase}` — upstream's
        /// anonymous create result, declaration order.
        #[derive(Serialize)]
        struct BackupCreateResult {
            operation_id: String,
            backup_id: String,
            phase: String,
        }
        Response::new(&request.operation_id, "success", 0, "").with_result(&BackupCreateResult {
            operation_id: sealed.operation_id.to_string(),
            backup_id: sealed.backup_id.to_string(),
            phase: sealed.phase.as_str().to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// `nativeBackupProcessLauncher` — the CBL1 adapter.
// ---------------------------------------------------------------------------

/// `nativeBackupLauncherClient` — the seam `NativeBackupProcessLauncher`
/// wraps; the production impl is [`crate::backup_launcher::Client`].
pub trait NativeBackupLauncherClient: Send + Sync {
    fn launch(
        &self,
        budget: Duration,
        request: &crate::backup_launcher::Request<'_>,
    ) -> Result<crate::backup_launcher::LaunchResult, Failure>;
    fn commit(&self, budget: Duration, launch_id: Uuid, evidence_id: Uuid) -> Result<(), Failure>;
    fn wait_and_reap(
        &self,
        budget: Duration,
        launch_id: Uuid,
    ) -> Result<crate::backup_launcher::Outcome, Failure>;
    fn assert_retained(&self, budget: Duration, launch_id: Uuid) -> Result<[u8; 32], Failure>;
    fn release_and_reap(&self, budget: Duration, launch_id: Uuid) -> Result<(), Failure>;
    fn abort(&self, budget: Duration, launch_id: Uuid) -> Result<(), Failure>;
    fn census(
        &self,
        budget: Duration,
        launch_id: Uuid,
    ) -> Result<crate::backup_launcher::Census, Failure>;
}

impl NativeBackupLauncherClient for crate::backup_launcher::Client {
    fn launch(
        &self,
        budget: Duration,
        request: &crate::backup_launcher::Request<'_>,
    ) -> Result<crate::backup_launcher::LaunchResult, Failure> {
        crate::backup_launcher::Client::launch(self, budget, request)
    }
    fn commit(&self, budget: Duration, launch_id: Uuid, evidence_id: Uuid) -> Result<(), Failure> {
        crate::backup_launcher::Client::commit(self, budget, launch_id, evidence_id)
    }
    fn wait_and_reap(
        &self,
        budget: Duration,
        launch_id: Uuid,
    ) -> Result<crate::backup_launcher::Outcome, Failure> {
        crate::backup_launcher::Client::wait_and_reap(self, budget, launch_id)
    }
    fn assert_retained(&self, budget: Duration, launch_id: Uuid) -> Result<[u8; 32], Failure> {
        crate::backup_launcher::Client::assert_retained(self, budget, launch_id)
    }
    fn release_and_reap(&self, budget: Duration, launch_id: Uuid) -> Result<(), Failure> {
        crate::backup_launcher::Client::release_and_reap(self, budget, launch_id)
    }
    fn abort(&self, budget: Duration, launch_id: Uuid) -> Result<(), Failure> {
        crate::backup_launcher::Client::abort(self, budget, launch_id)
    }
    fn census(
        &self,
        budget: Duration,
        launch_id: Uuid,
    ) -> Result<crate::backup_launcher::Census, Failure> {
        crate::backup_launcher::Client::census(self, budget, launch_id)
    }
}

/// `nativeBackupProcessLauncher` — adapts the closed supervisor
/// protocol to the helper boundary. It never forks, selects a
/// program, or transports a path.
pub struct NativeBackupProcessLauncher {
    client: Box<dyn NativeBackupLauncherClient>,
}

impl Default for NativeBackupProcessLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeBackupProcessLauncher {
    /// `newNativeBackupProcessLauncher` / `NewBackupProcessLauncher`.
    pub fn new() -> Self {
        Self {
            client: Box::new(crate::backup_launcher::Client::new()),
        }
    }

    /// The test seam — a configurable client.
    #[doc(hidden)]
    pub fn with_client(client: Box<dyn NativeBackupLauncherClient>) -> Self {
        Self { client }
    }

    fn abort_with_budget(&self, launch_id: Uuid) -> Result<(), Failure> {
        self.client.abort(CLEANUP_BUDGET, launch_id)
    }
}

/// `nativeBackupLaunchMode`.
fn native_backup_launch_mode(mode: BackupProcessMode) -> crate::backup_launcher::Mode {
    match mode {
        BackupProcessMode::Create => crate::backup_launcher::Mode::BackupCreate,
        BackupProcessMode::ThroughputProbe => crate::backup_launcher::Mode::ThroughputProbe,
    }
}

/// `exactBackupLaunchEnvironment` — the spec's env must carry exactly
/// the fixed set, in order.
fn exact_backup_launch_environment(env: &[&str]) -> bool {
    env == BACKUP_LAUNCH_ENVIRONMENT
}

/// The `2h` worker budget every CBL1 call gets from the operation
/// deadline — the socket read/write bound `dial(budget)` applies.
fn cbl1_budget(deadline: Instant) -> Duration {
    budget(deadline)
}

impl BackupProcessLauncher for NativeBackupProcessLauncher {
    fn launch(&self, spec: &BackupProcessSpec<'_>) -> Result<BackupProcess, Failure> {
        if spec.executable != CENTRAL_BACKUP_EXECUTABLE
            || spec.operation_id.is_nil()
            || spec.uid != CENTRAL_RUNTIME_UID
            || spec.gid != CENTRAL_RUNTIME_GID
            || spec.deadline == OffsetDateTime::UNIX_EPOCH
            || !exact_backup_launch_environment(spec.env)
        {
            return Err(invalid());
        }
        let mode = native_backup_launch_mode(spec.mode);
        let result = self.client.launch(
            cbl1_budget(Instant::now() + BACKUP_CREATE_DEADLINE),
            &crate::backup_launcher::Request {
                mode,
                operation_id: spec.operation_id,
                repository_fd: spec.repository_fd,
            },
        )?;
        if result.mode != mode {
            // `result.PIDFD` drops here — upstream's `unix.Close`.
            let _ = self.abort_with_budget(result.launch_id);
            return Err(unavailable("native backup launch mode acknowledgement"));
        }
        let pidfd = result.pidfd;
        let executable = super::migration_launch::migration_process_executable(result.pid as i32)
            .inspect_err(|_| {
            let _ = self.abort_with_budget(result.launch_id);
        })?;
        let start = super::migration_launch::migration_process_start(result.pid as i32)
            .inspect_err(|_| {
                let _ = self.abort_with_budget(result.launch_id);
            })?;
        Ok(BackupProcess {
            launch_id: result.launch_id,
            pid: result.pid as i32,
            pidfd,
            process_start: start,
            executable,
        })
    }

    fn commit(&self, deadline: Instant, launch_id: Uuid, evidence_id: Uuid) -> Result<(), Failure> {
        self.client
            .commit(cbl1_budget(deadline), launch_id, evidence_id)
    }

    fn wait_and_reap(
        &self,
        deadline: Instant,
        launch_id: Uuid,
    ) -> Result<BackupProcessOutcome, Failure> {
        let outcome = self
            .client
            .wait_and_reap(cbl1_budget(deadline), launch_id)?;
        Ok(BackupProcessOutcome {
            succeeded: outcome.succeeded,
            target_lock_proof: outcome.target_lock_proof,
        })
    }

    fn assert_target_lock_retained(
        &self,
        deadline: Instant,
        launch_id: Uuid,
    ) -> Result<[u8; 32], Failure> {
        let proof = self
            .client
            .assert_retained(cbl1_budget(deadline), launch_id)?;
        if proof == [0u8; 32] {
            return Err(unavailable("native backup target lock"));
        }
        Ok(proof)
    }

    fn release_and_reap(&self, deadline: Instant, launch_id: Uuid) -> Result<(), Failure> {
        self.client
            .release_and_reap(cbl1_budget(deadline), launch_id)
    }

    fn abort(&self, deadline: Instant, launch_id: Uuid) -> Result<(), Failure> {
        self.client.abort(cbl1_budget(deadline), launch_id)
    }

    fn census(&self, deadline: Instant, launch_id: Uuid) -> Result<BackupProcessCensus, Failure> {
        let census = self.client.census(cbl1_budget(deadline), launch_id)?;
        Ok(BackupProcessCensus {
            live_processes: census.live_processes,
            held_permits: census.held_permits,
        })
    }
}

// ---------------------------------------------------------------------------
// `fixedBackupRepositorySource` + `descriptorBackupRepositoryAttestor`
// — `cmd/central/backup_helper_composition.go`'s trusted seams.
// ---------------------------------------------------------------------------

/// `fixedBackupRepositorySource` — constructed only by the root
/// helper. The operator request and runtime worker never supply or
/// observe the root path; they receive only the already-open
/// descriptor and its immutable binding.
pub struct FixedBackupRepositorySource {
    pub root: PathBuf,
    pub instance_id: String,
}

impl BackupRepositoryDescriptorSource for FixedBackupRepositorySource {
    fn open_backup_repository(&self) -> Result<BackupRepositoryDescriptor, Failure> {
        if self.root.as_os_str().is_empty() || !self.root.is_absolute() {
            return Err(unavailable("backup repository authority"));
        }
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            &self.root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| unavailable("backup repository authority"))?;
        let binding = crate::backup::repository::inspect_repository_descriptor(&fd)
            .map_err(|_| unavailable("backup repository authority"))?;
        if !self.instance_id.is_empty() && binding.instance_id != self.instance_id {
            return Err(unavailable("backup repository authority"));
        }
        Ok(BackupRepositoryDescriptor { fd, binding })
    }
}

/// `descriptorBackupRepositoryAttestor` — independently reopens the
/// helper's retained descriptor only after the native supervisor has
/// reaped the worker tree; the adapter recomputes all physical
/// evidence under the exclusive lock.
pub struct DescriptorBackupRepositoryAttestor {
    pub profile: RecoveryProfile,
}

impl BackupRepositoryAttestor for DescriptorBackupRepositoryAttestor {
    fn attest_backup_repository(
        &self,
        descriptor: &BackupRepositoryDescriptor,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        backup_id: Uuid,
        attested_at: OffsetDateTime,
    ) -> Result<BackupRepositoryAttestation, Failure> {
        if descriptor.binding.verify().is_err()
            || self.profile.validate().is_err()
            || launch_evidence_id.is_nil()
            || operation_id.is_nil()
            || backup_id.is_nil()
            || attested_at == OffsetDateTime::UNIX_EPOCH
        {
            return Err(unavailable("backup repository attestation"));
        }
        let repository = crate::backup::repository::Repository::from_descriptor(
            descriptor.fd.as_fd(),
            &descriptor.binding,
        )
        .map_err(|_| unavailable("backup repository attestation"))?;
        let attestation = repository
            .attest_sealed_publication(
                launch_evidence_id,
                operation_id,
                backup_id,
                &self.profile,
                attested_at,
            )
            .map_err(|_| unavailable("backup repository attestation"))?;
        let _ = repository.close();
        if attestation.verify().is_err() {
            return Err(unavailable("backup repository attestation"));
        }
        Ok(attestation)
    }
}

// ---------------------------------------------------------------------------
// Backup-verify/status — `backup_read.go`.
// ---------------------------------------------------------------------------

/// `BackupReadAuthority` — the broker-facing read seam.
pub trait BackupReadAuthority: Send + Sync {
    /// `VerifyBackupSeal` — bind the helper-verified physical evidence
    /// to the journal's sealed record.
    #[allow(clippy::too_many_arguments)] // upstream evidence fields
    fn verify_backup_seal(
        &self,
        deadline: Instant,
        backup_id: Uuid,
        manifest_digest: [u8; 32],
        seal_companion_digest: [u8; 32],
        file_tree_digest: [u8; 32],
        repository_manifest_digest: [u8; 32],
        repository_revision: u64,
    ) -> Result<(), Failure>;
    /// `ReadBackupStatus` — the operation's stable projection.
    fn read_backup_status(
        &self,
        deadline: Instant,
        operation_id: Uuid,
    ) -> Result<BackupStatusResult, Failure>;
}

/// `BackupReader` — the `Server::backup_read` field type.
pub trait BackupReader: Send + Sync {
    fn verify_backup(
        &self,
        deadline: Instant,
        request: BackupVerifyRequest,
        peer: &PeerIdentity,
    ) -> Response;
    fn read_backup_status(
        &self,
        deadline: Instant,
        request: BackupStatusRequest,
        peer: &PeerIdentity,
    ) -> Response;
}

/// `BackupReadHandler` — the fixed descriptor-bound read path. No PAM
/// dependency; it exposes only locator-free verification/status
/// projections.
pub struct BackupReadHandler {
    source: Option<Box<dyn BackupRepositoryDescriptorSource>>,
    authority: Option<Box<dyn BackupReadAuthority>>,
    profile: RecoveryProfile,
}

impl BackupReadHandler {
    /// `NewBackupReadHandler` — both seams installed.
    pub fn new(
        source: Box<dyn BackupRepositoryDescriptorSource>,
        authority: Box<dyn BackupReadAuthority>,
        profile: RecoveryProfile,
    ) -> Self {
        Self {
            source: Some(source),
            authority: Some(authority),
            profile,
        }
    }
}

fn backup_read_response<T: Serialize>(
    operation_id: &str,
    outcome: &str,
    exit_code: i64,
    reason: &str,
    result: Option<&T>,
) -> Response {
    let mut resp = Response::new(operation_id, outcome, exit_code, reason);
    if let Some(value) = result {
        match serde_json::to_string(value)
            .ok()
            .and_then(|s| serde_json::value::RawValue::from_string(s).ok())
        {
            Some(raw) => resp.result = Some(raw),
            None => {
                return Response::new(operation_id, "error", 6, "BACKUP_READ_RESULT_INVALID");
            }
        }
    }
    resp
}

/// `validBackupStatusProjection` — the stable phase/reason vocabulary
/// the broker's answer must carry.
fn valid_backup_status_projection(operation_id: Uuid, result: &BackupStatusResult) -> bool {
    let (Ok(result_op), Ok(backup_id)) = (
        Uuid::parse_str(&result.operation_id),
        Uuid::parse_str(&result.backup_id),
    ) else {
        return false;
    };
    if result_op != operation_id || backup_id.is_nil() || !is_v7(backup_id) {
        return false;
    }
    match result.phase.as_str() {
        "sealed" => result.reason == "BACKUP_SEALED",
        "failed" => result.reason == "BACKUP_FAILED",
        "planned" | "admitted" | "dumping" | "inventory" | "sealing" => {
            result.reason == "BACKUP_IN_PROGRESS"
        }
        _ => false,
    }
}

impl BackupReader for BackupReadHandler {
    fn verify_backup(
        &self,
        deadline: Instant,
        request: BackupVerifyRequest,
        peer: &PeerIdentity,
    ) -> Response {
        let Ok(backup_id) = Uuid::parse_str(&request.backup_id) else {
            return backup_read_response::<()>(
                &request.backup_id,
                "denied",
                2,
                "INVALID_BACKUP_VERIFY_REQUEST",
                None,
            );
        };
        if backup_id.is_nil() || !is_v7(backup_id) || peer.pid <= 0 {
            return backup_read_response::<()>(
                &request.backup_id,
                "denied",
                2,
                "INVALID_BACKUP_VERIFY_REQUEST",
                None,
            );
        }
        // `h == nil || h.source == nil || h.authority == nil ||
        // h.profile.Validate() != nil || ctx == nil || ctx.Err() != nil`
        let (Some(source), Some(authority)) = (&self.source, &self.authority) else {
            return backup_read_response::<()>(
                &request.backup_id,
                "error",
                6,
                "BACKUP_VERIFY_FAILED",
                None,
            );
        };
        if self.profile.validate().is_err() {
            return backup_read_response::<()>(
                &request.backup_id,
                "error",
                6,
                "BACKUP_VERIFY_FAILED",
                None,
            );
        }
        let descriptor = match source.open_backup_repository() {
            Ok(d) if d.binding.verify().is_ok() => d,
            _ => {
                return backup_read_response::<()>(
                    &request.backup_id,
                    "error",
                    6,
                    "BACKUP_VERIFY_FAILED",
                    None,
                );
            }
        };
        let repository = match crate::backup::repository::Repository::read_only_from_descriptor(
            descriptor.fd.as_fd(),
            &descriptor.binding,
        ) {
            Ok(r) => r,
            Err(_) => {
                return backup_read_response::<()>(
                    &request.backup_id,
                    "error",
                    6,
                    "BACKUP_VERIFY_FAILED",
                    None,
                );
            }
        };
        let evidence = repository.verify_backup(backup_id, &self.profile);
        let _ = repository.close();
        let Ok(evidence) = evidence else {
            return backup_read_response::<()>(
                &request.backup_id,
                "error",
                6,
                "BACKUP_VERIFY_FAILED",
                None,
            );
        };
        if evidence.backup_id != backup_id
            || evidence.operation_id.is_nil()
            || !is_v7(evidence.operation_id)
            || authority
                .verify_backup_seal(
                    deadline,
                    backup_id,
                    evidence.manifest_digest,
                    evidence.seal_companion_digest,
                    evidence.file_tree_digest,
                    evidence.repository_manifest_digest,
                    evidence.repository_revision,
                )
                .is_err()
        {
            return backup_read_response::<()>(
                &request.backup_id,
                "error",
                6,
                "BACKUP_VERIFY_FAILED",
                None,
            );
        }
        backup_read_response(
            &request.backup_id,
            "success",
            0,
            "",
            Some(&BackupVerifyResult {
                operation_id: evidence.operation_id.to_string(),
                backup_id: backup_id.to_string(),
                phase: "sealed".to_owned(),
                verified: true,
            }),
        )
    }

    fn read_backup_status(
        &self,
        deadline: Instant,
        request: BackupStatusRequest,
        peer: &PeerIdentity,
    ) -> Response {
        let Ok(operation_id) = Uuid::parse_str(&request.operation_id) else {
            return backup_read_response::<()>(
                &request.operation_id,
                "denied",
                2,
                "INVALID_BACKUP_STATUS_REQUEST",
                None,
            );
        };
        if operation_id.is_nil() || !is_v7(operation_id) || peer.pid <= 0 {
            return backup_read_response::<()>(
                &request.operation_id,
                "denied",
                2,
                "INVALID_BACKUP_STATUS_REQUEST",
                None,
            );
        }
        // `h == nil || h.authority == nil || ctx == nil || ctx.Err() != nil`
        let Some(authority) = &self.authority else {
            return backup_read_response::<()>(
                &request.operation_id,
                "error",
                6,
                "BACKUP_STATUS_FAILED",
                None,
            );
        };
        let result = authority.read_backup_status(deadline, operation_id);
        match result {
            Ok(result) if valid_backup_status_projection(operation_id, &result) => {
                backup_read_response(&request.operation_id, "success", 0, "", Some(&result))
            }
            _ => backup_read_response::<()>(
                &request.operation_id,
                "error",
                6,
                "BACKUP_STATUS_FAILED",
                None,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// `backup_read_client_linux.go` — the unprivileged operator client.
// ---------------------------------------------------------------------------

/// `BackupOperatorClientError` — the stable exit class from the
/// helper boundary; helper diagnostics are never retained.
#[derive(Debug)]
pub struct BackupOperatorClientError {
    exit_code: i64,
}

impl std::fmt::Display for BackupOperatorClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("helper: backup read failed")
    }
}

impl std::error::Error for BackupOperatorClientError {}

impl BackupOperatorClientError {
    /// `ExitCode`.
    pub fn exit_code(&self) -> i64 {
        self.exit_code
    }
}

fn backup_operator_error(exit_code: i64) -> BackupOperatorClientError {
    let exit_code = if !(2..=7).contains(&exit_code) {
        6
    } else {
        exit_code
    };
    BackupOperatorClientError { exit_code }
}

/// `BackupOperatorClient` — `NewBackupOperatorClient`'s linux
/// implementation: the unprivileged CLI's whole view of the backup
/// read verbs.
pub struct BackupOperatorClient {
    socket_path: String,
}

impl BackupOperatorClient {
    /// `NewBackupOperatorClient`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `VerifyBackup`.
    pub fn verify_backup(
        &self,
        backup_id: &str,
    ) -> Result<BackupVerifyResult, BackupOperatorClientError> {
        if !valid_backup_read_uuid(backup_id) {
            return Err(backup_operator_error(2));
        }
        #[derive(Serialize)]
        struct Payload<'a> {
            backup_id: &'a str,
        }
        let payload = serde_json::to_string(&Payload { backup_id })
            .ok()
            .and_then(|s| serde_json::value::RawValue::from_string(s).ok());
        let result: BackupVerifyResult = self.call(&Request {
            operation_id: backup_id.to_owned(),
            verb: super::verb::BACKUP_VERIFY.to_owned(),
            payload,
        })?;
        if result.backup_id != backup_id
            || !valid_backup_read_uuid(&result.operation_id)
            || result.phase != "sealed"
            || !result.verified
        {
            return Err(backup_operator_error(6));
        }
        Ok(result)
    }

    /// `ReadBackupStatus`.
    pub fn read_backup_status(
        &self,
        operation_id: &str,
    ) -> Result<BackupStatusResult, BackupOperatorClientError> {
        if !valid_backup_read_uuid(operation_id) {
            return Err(backup_operator_error(2));
        }
        let result: BackupStatusResult = self.call(&Request {
            operation_id: operation_id.to_owned(),
            verb: super::verb::BACKUP_STATUS.to_owned(),
            payload: None,
        })?;
        let Ok(parsed) = Uuid::parse_str(operation_id) else {
            return Err(backup_operator_error(2));
        };
        if result.operation_id != operation_id
            || !valid_backup_read_uuid(&result.backup_id)
            || !valid_backup_status_projection(parsed, &result)
        {
            return Err(backup_operator_error(6));
        }
        Ok(result)
    }

    /// `call` — one bounded request/response exchange. A 5s dial
    /// bound plus 5s read/write bounds keep the whole exchange
    /// bounded (upstream's `net.Dialer{Timeout: 5s}`); the broker-
    /// bound verbs never block on a human.
    fn call<T: for<'de> Deserialize<'de> + Serialize>(
        &self,
        request: &Request,
    ) -> Result<T, BackupOperatorClientError> {
        if self.socket_path.is_empty() {
            return Err(backup_operator_error(3));
        }
        let mut conn = std::os::unix::net::UnixStream::connect(&self.socket_path)
            .map_err(|_| backup_operator_error(3))?;
        let bound = Duration::from_secs(5);
        let _ = conn.set_read_timeout(Some(bound));
        let _ = conn.set_write_timeout(Some(bound));
        write_request(&mut conn, request).map_err(|_| backup_operator_error(3))?;
        let response = read_response(&mut conn).map_err(|_| backup_operator_error(3))?;
        if response.operation_id != request.operation_id
            || response.outcome != "success"
            || response.exit_code != 0
        {
            return Err(backup_operator_error(response.exit_code));
        }
        let payload = response
            .result
            .as_ref()
            .map(|r| r.get().as_bytes().to_vec())
            .unwrap_or_default();
        decode_exact_backup_read_result(&payload).map_err(|_| backup_operator_error(6))
    }
}

/// `decodeExactBackupReadResult` — strict decode plus the canonical
/// re-marshal byte-equality check.
pub fn decode_exact_backup_read_result<T: for<'de> Deserialize<'de> + Serialize>(
    payload: &[u8],
) -> Result<T, Failure> {
    if payload.is_empty() {
        return Err(Failure::invalid(
            "helper_backup",
            "helper: backup read result is invalid",
        ));
    }
    let decoded: T = strict_decode(payload)
        .map_err(|_| Failure::invalid("helper_backup", "helper: backup read result is invalid"))?;
    let canonical = serde_json::to_vec(&decoded).map_err(|_| {
        Failure::invalid(
            "helper_backup",
            "helper: backup read result is not canonical",
        )
    })?;
    if canonical != payload {
        return Err(Failure::invalid(
            "helper_backup",
            "helper: backup read result is not canonical",
        ));
    }
    Ok(decoded)
}

/// `validBackupReadUUID` — parse + non-nil + v7 + canonical string.
fn valid_backup_read_uuid(value: &str) -> bool {
    match Uuid::parse_str(value) {
        Ok(id) => !id.is_nil() && is_v7(id) && id.to_string() == value,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::protocol::Request;

    fn req(operation_id: &str, payload: Option<&str>) -> Request {
        Request {
            operation_id: operation_id.to_owned(),
            verb: "v".to_owned(),
            payload: payload
                .and_then(|p| serde_json::value::RawValue::from_string(p.to_owned()).ok()),
        }
    }

    /// `ParseBackupCreateRequest` — absent/`{}` payloads admit; any
    /// other payload is refused.
    #[test]
    fn backup_create_request_rejects_payloads() {
        assert!(parse_backup_create_request(&req("op", None)).is_ok());
        assert!(parse_backup_create_request(&req("op", Some("{}"))).is_ok());
        assert!(parse_backup_create_request(&req("op", Some("{\"x\":1}"))).is_err());
        assert!(parse_backup_create_request(&req("", None)).is_err());
    }

    /// `ParseBackupVerifyRequest` — the payload's `backup_id` must
    /// equal the envelope operation ID; unknown fields and missing
    /// payloads refuse.
    #[test]
    fn backup_verify_request_binds_backup_id_to_operation() {
        assert!(parse_backup_verify_request(&req("b-1", Some("{\"backup_id\":\"b-1\"}"))).is_ok());
        assert!(parse_backup_verify_request(&req("b-1", Some("{\"backup_id\":\"b-2\"}"))).is_err());
        assert!(parse_backup_verify_request(&req("b-1", Some("{}"))).is_err());
        assert!(
            parse_backup_verify_request(&req("b-1", Some("{\"backup_id\":\"b-1\",\"x\":1}")))
                .is_err()
        );
        assert!(parse_backup_verify_request(&req("b-1", None)).is_err());
        assert!(parse_backup_verify_request(&req("", Some("{\"backup_id\":\"b-1\"}"))).is_err());
    }

    /// `ParseBackupStatusRequest` — same empty-payload grammar as
    /// create.
    #[test]
    fn backup_status_request_rejects_payloads() {
        assert!(parse_backup_status_request(&req("op", None)).is_ok());
        assert!(parse_backup_status_request(&req("op", Some("{}"))).is_ok());
        assert!(parse_backup_status_request(&req("op", Some("{\"x\":1}"))).is_err());
        assert!(parse_backup_status_request(&req("", None)).is_err());
    }

    /// `validBackupStatusProjection` — the exact phase→reason map and
    /// v7 binding.
    #[test]
    fn backup_status_projection_is_closed() {
        let op = Uuid::now_v7();
        let backup = Uuid::now_v7();
        let base = BackupStatusResult {
            operation_id: op.to_string(),
            backup_id: backup.to_string(),
            phase: String::new(),
            reason: String::new(),
        };
        for (phase, reason) in [
            ("sealed", "BACKUP_SEALED"),
            ("failed", "BACKUP_FAILED"),
            ("planned", "BACKUP_IN_PROGRESS"),
            ("admitted", "BACKUP_IN_PROGRESS"),
            ("dumping", "BACKUP_IN_PROGRESS"),
            ("inventory", "BACKUP_IN_PROGRESS"),
            ("sealing", "BACKUP_IN_PROGRESS"),
        ] {
            let mut r = base.clone();
            r.phase = phase.to_owned();
            r.reason = reason.to_owned();
            assert!(valid_backup_status_projection(op, &r), "{phase}");
        }
        // Wrong reason, wrong op, non-v7 backup, unknown phase all refuse.
        let mut r = base.clone();
        r.phase = "sealed".into();
        r.reason = "BACKUP_FAILED".into();
        assert!(!valid_backup_status_projection(op, &r));
        let mut r = base.clone();
        r.phase = "sealed".into();
        r.reason = "BACKUP_SEALED".into();
        r.operation_id = Uuid::now_v7().to_string();
        assert!(!valid_backup_status_projection(op, &r));
        let mut r = base.clone();
        r.phase = "sealed".into();
        r.reason = "BACKUP_SEALED".into();
        r.backup_id = Uuid::nil().to_string();
        assert!(!valid_backup_status_projection(op, &r));
        let mut r = base.clone();
        r.phase = "weird".into();
        assert!(!valid_backup_status_projection(op, &r));
    }

    /// `decodeExactBackupReadResult` — strict decode plus canonical
    /// round-trip; whitespace/key reorder refuse exactly like Go's
    /// byte-equality check.
    #[test]
    fn backup_read_result_decode_is_exact() {
        let ok =
            b"{\"operation_id\":\"o\",\"backup_id\":\"b\",\"phase\":\"sealed\",\"verified\":true}";
        let decoded: BackupVerifyResult = decode_exact_backup_read_result(ok).unwrap();
        assert!(decoded.verified);
        assert!(
            decode_exact_backup_read_result::<BackupVerifyResult>(
                b"{ \"operation_id\":\"o\",\"backup_id\":\"b\",\"phase\":\"sealed\",\"verified\":true}"
            )
            .is_err()
        );
        assert!(
            decode_exact_backup_read_result::<BackupVerifyResult>(
                b"{\"operation_id\":\"o\",\"backup_id\":\"b\",\"phase\":\"sealed\",\"verified\":true,\"x\":1}"
            )
            .is_err()
        );
        assert!(decode_exact_backup_read_result::<BackupVerifyResult>(b"").is_err());
        assert!(decode_exact_backup_read_result::<BackupVerifyResult>(b"null").is_err());
    }
}
