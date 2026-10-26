//! `cmd/central/browser_runtime.go` plus the `fileReadyProofSource` and
//! `protectedBootstrapPresenter` halves of `serve_composition.go` /
//! `main.go` — the managed-browser runtime boundary: the stored
//! ready-proof source, the `central-browser` chromium launch, and the
//! launch-bound approval file. Everything here runs inside the
//! root-owned helper; every refusal collapses to `authority.ErrDenied`.

use super::PeerIdentity;
use super::browser::{
    BootstrapPresenter, BrowserLauncher, FIXED_BROWSER_ORIGIN, ManagedBrowserLaunch,
    ManagedBrowserLauncher, ManagedBrowserProcess, ManagedBrowserState,
    ManagedBrowserStateForLaunch, ReadyProof, ReadyProofSource, write_controlling_tty,
};
use crate::broker::wire::{b64_raw_decode, b64_raw_encode};
use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use time::OffsetDateTime;
use zeroize::Zeroizing;

fn denied() -> Failure {
    super::err_denied()
}

fn os_failure(op: &'static str, e: std::io::Error) -> Failure {
    Failure::internal("browser_runtime_os", format!("helper: {op}: {e}"))
}

// -- serve_composition.go env-path helpers ---------------------------

/// `CENTRAL_READY_PROOF_PATH` — the file the supervisor's publisher
/// writes; production `/run/central/ready-proof.json`.
pub const ENV_READY_PROOF_PATH: &str = "CENTRAL_READY_PROOF_PATH";
const DEFAULT_READY_PROOF_PATH: &str = "/run/central/ready-proof.json";

/// `CENTRAL_RUNTIME_GENERATION_PATH` — upstream
/// `runtimeGenerationPath`; defaults to `<ready proof>.generation`.
pub const ENV_RUNTIME_GENERATION_PATH: &str = "CENTRAL_RUNTIME_GENERATION_PATH";

/// `CENTRAL_BROKER_SOCKET` — the reference-host override for the
/// protected broker's socket; production is
/// [`crate::broker::PRODUCTION_SOCKET_PATH`].
pub const ENV_BROKER_SOCKET: &str = "CENTRAL_BROKER_SOCKET";

/// `readyProofPath`.
pub fn ready_proof_path(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    env(ENV_READY_PROOF_PATH)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_READY_PROOF_PATH))
}

/// `runtimeGenerationPath`.
pub fn runtime_generation_path(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    if let Some(v) = env(ENV_RUNTIME_GENERATION_PATH).filter(|v| !v.is_empty()) {
        return PathBuf::from(v);
    }
    let mut p = ready_proof_path(env).into_os_string();
    p.push(".generation");
    PathBuf::from(p)
}

/// `brokerSocketPath`.
pub fn broker_socket_path(env: &dyn Fn(&str) -> Option<String>) -> String {
    env(ENV_BROKER_SOCKET)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| crate::broker::PRODUCTION_SOCKET_PATH.to_owned())
}

// -- browserApprovalPath / removeBrowserApproval (main.go) ------------

/// `CENTRAL_BROWSER_APPROVAL_PATH` — the reference-host override;
/// production resolves `/run/central/browser-approved`.
pub const ENV_BROWSER_APPROVAL_PATH: &str = "CENTRAL_BROWSER_APPROVAL_PATH";

const DEFAULT_BROWSER_APPROVAL_PATH: &str = "/run/central/browser-approved";

/// `browserApprovalPath` — env override, then the production path.
pub fn browser_approval_path(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    env(ENV_BROWSER_APPROVAL_PATH)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BROWSER_APPROVAL_PATH))
}

/// `removeBrowserApproval` — the startup clear; absent is not an error.
pub fn remove_browser_approval(path: &Path) -> Result<(), Failure> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(os_failure("remove browser approval", e)),
    }
}

// -- fileReadyProofSource (serve_composition.go) ----------------------

/// `storedReadyProof` — the on-disk JSON the file publisher writes;
/// the only place the nonce is material (raw-standard base64).
#[derive(Deserialize)]
struct StoredReadyProof {
    launch_id: String,
    runtime_generation: String,
    nonce: String,
    /// Go `time.Time` — RFC3339(Nano); a missing field unmarshals to
    /// the zero time upstream, so `None` means "unset" not "invalid".
    #[serde(default, with = "time::serde::rfc3339::option")]
    expires_at: Option<OffsetDateTime>,
}

/// `ErrReady{Revoked,Mismatch,Expired}` as failure codes — upstream's
/// sentinel split, preserved for the audit line even though the
/// handler collapses all three to `AUTHORITY_DENIED`.
fn ready_failure(class: &'static str) -> Failure {
    let code = match class {
        "revoked" => "ready_proof_revoked",
        "mismatch" => "ready_proof_mismatch",
        _ => "ready_proof_expired",
    };
    Failure::denied(code, format!("kernel: ready proof {class}"))
}

/// `fileReadyProofSource` — reads the supervisor's stored proof from
/// the two root-owned files (`path` + `generationPath`).
#[derive(Debug, Clone)]
pub struct FileReadyProofSource {
    path: PathBuf,
    generation_path: PathBuf,
}

impl FileReadyProofSource {
    /// `generation_path` empty names "no sidecar", upstream's `""`.
    pub fn new(path: impl Into<PathBuf>, generation_path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            generation_path: generation_path.into(),
        }
    }
}

impl ReadyProofSource for FileReadyProofSource {
    /// `Current` — read → parse → nonce decode → generation sidecar →
    /// completeness/expiry, upstream's error order verbatim:
    /// revoked on an unreadable file, mismatch on any malformed or
    /// generation-inconsistent content, expired on an incomplete or
    /// dead proof.
    fn current(&self) -> Result<ReadyProof, Failure> {
        let data = std::fs::read(&self.path).map_err(|_| ready_failure("revoked"))?;
        let stored: StoredReadyProof =
            serde_json::from_slice(&data).map_err(|_| ready_failure("mismatch"))?;
        let raw = b64_raw_decode(&stored.nonce).unwrap_or_default();
        let nonce: [u8; 32] = raw.try_into().map_err(|_| ready_failure("mismatch"))?;
        let expires_at = stored.expires_at.unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let proof = ReadyProof {
            launch_id: stored.launch_id,
            runtime_generation: stored.runtime_generation,
            nonce,
            expires_at,
        };
        if !self.generation_path.as_os_str().is_empty() {
            let generation =
                std::fs::read(&self.generation_path).map_err(|_| ready_failure("mismatch"))?;
            if String::from_utf8_lossy(&generation).trim() != proof.runtime_generation {
                return Err(ready_failure("mismatch"));
            }
        }
        if proof.launch_id.is_empty()
            || proof.runtime_generation.is_empty()
            || proof.runtime_generation != proof.launch_id
            || proof.is_expired(OffsetDateTime::now_utc())
        {
            return Err(ready_failure("expired"));
        }
        Ok(proof)
    }
}

// -- managedBrowserLauncher / approval file (browser_runtime.go) ------

/// `managedBrowserApproval` — the launch-bound approval record; the
/// deadline rides RFC3339 like Go's `time.Time` JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ManagedBrowserApproval {
    launch_id: String,
    proof_digest: String,
    presentation_generation: u64,
    #[serde(with = "time::serde::rfc3339")]
    presentation_deadline: OffsetDateTime,
    pid: i32,
    process_start_time: u64,
}

/// `proofDigest` — `base64.RawStd(SHA256(nonce))`; the approval file
/// binds the launch without persisting the nonce itself.
pub fn proof_digest(proof: &ReadyProof) -> String {
    let digest = Sha256::digest(proof.nonce);
    b64_raw_encode(&digest)
}

/// `processIdentity` — `/proc/<pid>/stat`: start-time (field 22, the
/// 20th field after the `)` — `fields[19]` upstream) and state.
#[derive(Debug, Clone, Copy)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub start_time: u64,
    pub state: u8,
}

/// `readProcessIdentity` — the stat tail after the last `)`; a short
/// or unparseable record is an error, upstream-fashion.
pub fn read_process_identity(pid: i32) -> Result<ProcessIdentity, Failure> {
    let data =
        std::fs::read(format!("/proc/{pid}/stat")).map_err(|e| os_failure("read stat", e))?;
    let text = String::from_utf8_lossy(&data);
    let Some(paren) = text.rfind(')') else {
        return Err(Failure::internal(
            "browser_runtime_stat",
            "invalid process stat",
        ));
    };
    let fields: Vec<&str> = text[paren + 1..].split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(Failure::internal(
            "browser_runtime_stat",
            "invalid process stat fields",
        ));
    }
    let start_time = fields[19].parse::<u64>().map_err(|e| {
        os_failure(
            "parse stat start time",
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
        )
    })?;
    let state = fields[0].as_bytes().first().copied().unwrap_or_default();
    Ok(ProcessIdentity {
        pid,
        start_time,
        state,
    })
}

/// `processAlive` — nonzero pid, non-zombie, `kill(pid, 0)` succeeds,
/// and a re-read stat shows the same start time still not a zombie.
pub fn process_alive(identity: ProcessIdentity) -> bool {
    if identity.pid <= 0 || identity.state == b'Z' {
        return false;
    }
    let Some(pid) = rustix::process::Pid::from_raw(identity.pid) else {
        return false;
    };
    if rustix::process::test_kill_process(pid).is_err() {
        return false;
    }
    match read_process_identity(identity.pid) {
        Ok(current) => current.start_time == identity.start_time && current.state != b'Z',
        Err(_) => false,
    }
}

/// `writeBrowserApproval` — `path + ".tmp"` then rename, mode `0600`
/// on the fresh file, tmp removed on rename failure.
fn write_browser_approval(path: &Path, approval: &ManagedBrowserApproval) -> Result<(), Failure> {
    let data = serde_json::to_vec(approval).map_err(|_| denied())?;
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| os_failure("write approval tmp", e))?;
        f.write_all(&data)
            .map_err(|e| os_failure("write approval", e))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        os_failure("rename approval", e)
    })
}

fn remove_browser_approval_if(
    path: &Path,
    expected: &ManagedBrowserApproval,
) -> Result<(), Failure> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(os_failure("read approval", e)),
    };
    let Ok(current) = serde_json::from_slice::<ManagedBrowserApproval>(&data) else {
        return Ok(());
    };
    if &current != expected {
        return Ok(());
    }
    remove_browser_approval(path)
}

/// `authority.BrowserIdentity` — the locked no-login identity the
/// managed profile belongs to (upstream `internal/authority/identity.go`).
pub const BROWSER_IDENTITY: &str = "central-browser";

/// `managedBrowserLauncher` — the chromium launch bound to one
/// proof-and-presentation lease.
#[derive(Debug, Clone)]
pub struct ChromiumManagedLauncher {
    approval_path: PathBuf,
}

impl ChromiumManagedLauncher {
    pub fn new(approval_path: impl Into<PathBuf>) -> Self {
        Self {
            approval_path: approval_path.into(),
        }
    }
}

impl BrowserLauncher for ChromiumManagedLauncher {
    /// `Open` — the plain arm is unreachable in production.
    fn open(&self, _origin: &str) -> Result<(), Failure> {
        Err(Failure::denied(
            "browser_launch_managed",
            "managed browser launch requires a current proof and presentation lease",
        ))
    }
}

impl ManagedBrowserLauncher for ChromiumManagedLauncher {
    /// `OpenManaged` — origin/proof/lease gate, launch, identity read,
    /// approval write, detached reaper. The one divergence from
    /// upstream's `exec.Command` is the credential drop: the contract
    /// (ADR 0009, local-development-environment §2.2) names
    /// `central-browser` as the profile owner, resolved through the
    /// audited `sys::nss` boundary like every other locked identity.
    fn open_managed(
        &self,
        origin: &str,
        launch: &ManagedBrowserLaunch,
    ) -> Result<ManagedBrowserProcess, Failure> {
        let deadline = OffsetDateTime::from_unix_timestamp(launch.lease.deadline_unix)
            .map_err(|_| denied())?;
        let now = OffsetDateTime::now_utc();
        let proof_ok = launch
            .proof
            .as_ref()
            .is_some_and(|p| !p.launch_id.is_empty());
        if origin != FIXED_BROWSER_ORIGIN
            || !proof_ok
            || launch.lease.generation == 0
            || !(deadline > now)
        {
            return Err(denied());
        }
        let proof = launch.proof.as_ref().ok_or_else(denied)?;
        let creds = crate::sys::nss::getpwnam_str(BROWSER_IDENTITY).ok_or_else(denied)?;
        let mut cmd = Command::new("chromium");
        cmd.arg(format!("--app={FIXED_BROWSER_ORIGIN}"))
            .arg("--user-data-dir=/run/central/chromium")
            .arg("--disable-extensions")
            .arg("--disable-sync")
            .arg("--no-first-run")
            .arg("--no-default-browser-check");
        // `SysProcAttr.Credential` — setgroups(0) → setgid → setuid,
        // installed through the audited `pre_exec` wrapper (this module
        // is `forbid(unsafe_code)`).
        crate::sys::audited::command_run_as(&mut cmd, creds.uid, creds.gid);
        let mut child = cmd.spawn().map_err(|e| os_failure("spawn chromium", e))?;
        // `readyTimer` = 100ms — the synchronous port's bounded wait.
        std::thread::sleep(Duration::from_millis(100));
        let identity = read_process_identity(child.id() as i32)
            .ok()
            .filter(|i| process_alive(*i));
        let Some(identity) = identity else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(denied());
        };
        let approval = ManagedBrowserApproval {
            launch_id: proof.launch_id.clone(),
            proof_digest: proof_digest(proof),
            presentation_generation: launch.lease.generation,
            presentation_deadline: deadline,
            pid: identity.pid,
            process_start_time: identity.start_time,
        };
        if write_browser_approval(&self.approval_path, &approval).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(denied());
        }
        // `go func() { cmd.Wait(); removeBrowserApprovalIf(...) }` —
        // detached after the bounded startup window.
        let approval_path = self.approval_path.clone();
        std::thread::spawn(move || {
            let _ = child.wait();
            let _ = remove_browser_approval_if(&approval_path, &approval);
        });
        Ok(ManagedBrowserProcess {
            pid: identity.pid,
            start_time: identity.start_time,
        })
    }
}

/// `managedBrowserState` — the approval-file state check.
#[derive(Debug, Clone)]
pub struct FileManagedBrowserState {
    path: PathBuf,
}

impl FileManagedBrowserState {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ManagedBrowserState for FileManagedBrowserState {
    /// `Approved` — the unbound check never admits.
    fn approved(&self) -> Result<bool, Failure> {
        Err(Failure::denied(
            "browser_approval_unbound",
            "browser approval requires current ready proof",
        ))
    }
}

impl ManagedBrowserStateForLaunch for FileManagedBrowserState {
    /// `ApprovedFor` — every check is read-only and returns `false`,
    /// never an error, for absent/malformed/mismatched/dead input.
    fn approved_for(&self, launch: &ManagedBrowserLaunch) -> Result<bool, Failure> {
        let Ok(data) = std::fs::read(&self.path) else {
            return Ok(false);
        };
        let Ok(approval) = serde_json::from_slice::<ManagedBrowserApproval>(&data) else {
            return Ok(false);
        };
        let Some(proof) = &launch.proof else {
            return Ok(false);
        };
        if approval.launch_id != proof.launch_id
            || approval.proof_digest != proof_digest(proof)
            || approval.presentation_generation == 0
            || !(OffsetDateTime::now_utc() < approval.presentation_deadline)
        {
            return Ok(false);
        }
        Ok(process_alive(ProcessIdentity {
            pid: approval.pid,
            start_time: approval.process_start_time,
            state: 0,
        }))
    }
}

// -- protectedBootstrapPresenter (main.go) ----------------------------

/// `bootstrapValueProducer` — the narrow handoff from the protected
/// broker's staged bootstrap flow. Implementations return a
/// request-scoped copy only; callers must not persist or log it.
pub trait BootstrapValueProducer: Send + Sync {
    fn produce(&self) -> Result<Zeroizing<Vec<u8>>, Failure>;
}

impl BootstrapValueProducer for crate::broker::bootstrap_session::BootstrapPresenter {
    fn produce(&self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        Self::produce(self)
    }
}

/// The `write` seam's shape — upstream's `func(context.Context,
/// []byte) error` (`helper.WriteControllingTTY` or
/// `opts.bootstrapWriter`).
type TtyWriter = Box<dyn Fn(&PeerIdentity, &[u8]) -> Result<(), Failure> + Send + Sync>;

/// `protectedBootstrapPresenter` — produce the broker-held value and
/// write it to the authenticated peer's controlling TTY. `write` is
/// the seam upstream's `opts.bootstrapWriter` fills in tests.
pub struct ProtectedBootstrapPresenter<P> {
    producer: P,
    write: TtyWriter,
}

impl<P> ProtectedBootstrapPresenter<P> {
    /// `write: nil` upstream → `helper.WriteControllingTTY`.
    pub fn new(producer: P) -> Self {
        Self {
            producer,
            write: Box::new(write_controlling_tty),
        }
    }

    /// The test seam — upstream's `opts.bootstrapWriter`.
    pub fn with_writer(producer: P, write: TtyWriter) -> Self {
        Self { producer, write }
    }
}

impl<P: BootstrapValueProducer + Send + Sync> BootstrapPresenter
    for ProtectedBootstrapPresenter<P>
{
    /// `Present` — produce bounds `1..=4096`, then the controlling-TTY
    /// write with the trailing newline.
    fn present(&self, peer: &PeerIdentity) -> Result<(), Failure> {
        let data = self.producer.produce().map_err(|_| denied())?;
        if data.is_empty() || data.len() > 4096 {
            return Err(denied());
        }
        let mut line = Vec::with_capacity(data.len() + 1);
        line.extend_from_slice(&data);
        line.push(b'\n');
        (self.write)(peer, &line)
    }
}

#[cfg(test)]
mod tests {
    use super::super::browser::PresentationLease;
    use super::*;
    use std::sync::{Arc, Mutex};
    use time::format_description::well_known::Rfc3339;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-browser-runtime-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn proof(launch: &str, nonce: u8, secs: i64) -> ReadyProof {
        ReadyProof {
            launch_id: launch.into(),
            runtime_generation: launch.into(),
            nonce: [nonce; 32],
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(secs),
        }
    }

    fn write_proof(dir: &Path, p: &ReadyProof, nonce_b64: &str, generation: Option<&str>) {
        let expires = p.expires_at.format(&Rfc3339).unwrap();
        std::fs::write(
            dir.join("ready-proof.json"),
            format!(
                r#"{{"launch_id":"{}","runtime_generation":"{}","nonce":"{}","expires_at":"{}"}}"#,
                p.launch_id, p.runtime_generation, nonce_b64, expires
            ),
        )
        .unwrap();
        if let Some(g) = generation {
            std::fs::write(dir.join("ready-proof.json.generation"), g).unwrap();
        }
    }

    /// `Current` fails closed upstream-fashion: absent file → revoked;
    /// bad json / bad nonce / sidecar drift → mismatch; incomplete or
    /// dead proof → expired.
    #[test]
    fn file_proof_source_revoked_mismatch_expired() {
        let dir = tempdir("proof-src");
        let src = FileReadyProofSource::new(
            dir.join("ready-proof.json"),
            dir.join("ready-proof.json.generation"),
        );
        // Absent file → revoked.
        let e = src.current().unwrap_err();
        assert_eq!(e.code(), "ready_proof_revoked");
        // Malformed JSON → mismatch.
        std::fs::write(dir.join("ready-proof.json"), b"{nope").unwrap();
        assert_eq!(src.current().unwrap_err().code(), "ready_proof_mismatch");
        // Bad nonce (wrong decoded length) → mismatch.
        let p = proof("launch-x", 9, 3600);
        write_proof(&dir, &p, "c2hvcnQ", None);
        assert_eq!(src.current().unwrap_err().code(), "ready_proof_mismatch");
        // Generation sidecar drift → mismatch.
        write_proof(
            &dir,
            &p,
            &b64_raw_encode(&p.nonce),
            Some("other-generation\n"),
        );
        assert_eq!(src.current().unwrap_err().code(), "ready_proof_mismatch");
        // Launch id ≠ generation → expired.
        let mut bad = p.clone();
        bad.runtime_generation = "different".into();
        write_proof(&dir, &bad, &b64_raw_encode(&bad.nonce), Some("different\n"));
        assert_eq!(src.current().unwrap_err().code(), "ready_proof_expired");
        // Expired deadline → expired.
        let dead = proof("launch-x", 9, -1);
        write_proof(
            &dir,
            &dead,
            &b64_raw_encode(&dead.nonce),
            Some("launch-x\n"),
        );
        assert_eq!(src.current().unwrap_err().code(), "ready_proof_expired");
        // The honest current proof loads.
        write_proof(&dir, &p, &b64_raw_encode(&p.nonce), Some("launch-x\n"));
        let loaded = src.current().unwrap();
        assert!(loaded.equal(&p));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `proofDigest` — `RawStd(SHA256(nonce))`.
    #[test]
    fn proof_digest_matches_sha256_rawstd() {
        let p = proof("l", 0xab, 60);
        let expect = {
            let d = Sha256::digest([0xab; 32]);
            b64_raw_encode(&d)
        };
        assert_eq!(proof_digest(&p), expect);
        assert!(!expect.contains('='));
    }

    /// `writeBrowserApproval`/`removeBrowserApprovalIf` — 0600 file,
    /// foreign record left alone, matching record removed.
    #[test]
    fn approval_write_and_guarded_remove() {
        let dir = tempdir("approval");
        let path = dir.join("browser-approved");
        let approval = ManagedBrowserApproval {
            launch_id: "l".into(),
            proof_digest: "d".into(),
            presentation_generation: 7,
            presentation_deadline: OffsetDateTime::now_utc() + time::Duration::seconds(60),
            pid: 42,
            process_start_time: 99,
        };
        write_browser_approval(&path, &approval).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // A different expected record leaves the file.
        let mut other = approval.clone();
        other.pid = 43;
        remove_browser_approval_if(&path, &other).unwrap();
        assert!(path.exists());
        // The matching record removes it.
        remove_browser_approval_if(&path, &approval).unwrap();
        assert!(!path.exists());
        // Malformed file is left alone; missing file is a no-op.
        std::fs::write(&path, b"{bad").unwrap();
        remove_browser_approval_if(&path, &approval).unwrap();
        assert!(path.exists());
        remove_browser_approval(&path).unwrap();
        remove_browser_approval(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `readProcessIdentity`/`processAlive` — this process is a live
    /// identity; a guaranteed-absent pid is not.
    #[test]
    fn process_identity_alive_and_dead() {
        let me = read_process_identity(std::process::id() as i32).unwrap();
        assert_eq!(me.pid, std::process::id() as i32);
        assert_ne!(me.state, b'Z');
        assert!(process_alive(me));
        assert!(!process_alive(ProcessIdentity {
            pid: 0,
            start_time: 0,
            state: b'S'
        }));
        assert!(!process_alive(ProcessIdentity {
            pid: i32::MAX,
            start_time: 0,
            state: b'S'
        }));
        assert!(!process_alive(ProcessIdentity {
            pid: 1,
            start_time: u64::MAX,
            state: b'S'
        }));
    }

    /// `OpenManaged` — the gate fails closed before any spawn:
    /// origin, proof, generation, and deadline each deny.
    #[test]
    fn open_managed_gate_denies_before_spawn() {
        let dir = tempdir("gate");
        let launcher = ChromiumManagedLauncher::new(dir.join("browser-approved"));
        let good = ManagedBrowserLaunch {
            proof: Some(proof("l", 1, 60)),
            lease: PresentationLease {
                generation: 3,
                deadline_unix: OffsetDateTime::now_utc().unix_timestamp() + 60,
            },
        };
        // Wrong origin.
        assert!(launcher.open_managed("https://evil.test", &good).is_err());
        // Missing proof / empty launch id.
        let mut bad = good.clone();
        bad.proof = None;
        assert!(launcher.open_managed(FIXED_BROWSER_ORIGIN, &bad).is_err());
        bad.proof = Some(proof("", 1, 60));
        assert!(launcher.open_managed(FIXED_BROWSER_ORIGIN, &bad).is_err());
        // Generation zero.
        let mut bad = good.clone();
        bad.lease.generation = 0;
        assert!(launcher.open_managed(FIXED_BROWSER_ORIGIN, &bad).is_err());
        // Past / boundary deadline.
        let mut bad = good.clone();
        bad.lease.deadline_unix = OffsetDateTime::now_utc().unix_timestamp() - 1;
        assert!(launcher.open_managed(FIXED_BROWSER_ORIGIN, &bad).is_err());
        bad.lease.deadline_unix = OffsetDateTime::now_utc().unix_timestamp();
        assert!(launcher.open_managed(FIXED_BROWSER_ORIGIN, &bad).is_err());
        assert!(!dir.join("browser-approved").exists());
        // The plain Open arm refuses even the fixed origin.
        assert!(launcher.open(FIXED_BROWSER_ORIGIN).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `ApprovedFor` — absent, malformed, and mismatched approvals all
    /// answer `false`; `Approved` always refuses.
    #[test]
    fn approved_for_reads_and_compares() {
        let dir = tempdir("state");
        let path = dir.join("browser-approved");
        let state = FileManagedBrowserState::new(&path);
        let p = proof("l", 5, 60);
        let launch = ManagedBrowserLaunch {
            proof: Some(p.clone()),
            lease: Default::default(),
        };
        assert!(!state.approved_for(&launch).unwrap());
        assert!(state.approved().is_err());
        std::fs::write(&path, b"{bad").unwrap();
        assert!(!state.approved_for(&launch).unwrap());
        // A matching digest but a dead process (pid 1 start_time bogus
        // is never equal after re-read).
        let approval = ManagedBrowserApproval {
            launch_id: p.launch_id.clone(),
            proof_digest: proof_digest(&p),
            presentation_generation: 1,
            presentation_deadline: OffsetDateTime::now_utc() + time::Duration::seconds(60),
            pid: 1,
            process_start_time: u64::MAX,
        };
        write_browser_approval(&path, &approval).unwrap();
        assert!(!state.approved_for(&launch).unwrap());
        // Wrong launch id → false.
        std::fs::write(
            &path,
            serde_json::to_vec(&ManagedBrowserApproval {
                launch_id: "other".into(),
                ..approval.clone()
            })
            .unwrap(),
        )
        .unwrap();
        assert!(!state.approved_for(&launch).unwrap());
        // Missing proof → false.
        let no_proof = ManagedBrowserLaunch {
            proof: None,
            lease: Default::default(),
        };
        assert!(!state.approved_for(&no_proof).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `browserApprovalPath` — env override wins; default otherwise.
    #[test]
    fn approval_path_env() {
        assert_eq!(
            browser_approval_path(
                &|k| (k == ENV_BROWSER_APPROVAL_PATH).then(|| "/tmp/x".to_owned())
            ),
            PathBuf::from("/tmp/x")
        );
        assert_eq!(
            browser_approval_path(&|_| None),
            PathBuf::from(DEFAULT_BROWSER_APPROVAL_PATH)
        );
    }

    struct FixedProducer(Vec<u8>);
    impl BootstrapValueProducer for FixedProducer {
        fn produce(&self) -> Result<Zeroizing<Vec<u8>>, Failure> {
            Ok(Zeroizing::new(self.0.clone()))
        }
    }

    /// `Present` — the value goes to the writer with the newline;
    /// empty and oversized produces deny before writing.
    #[test]
    fn protected_presenter_bounds_and_write() {
        let peer = PeerIdentity {
            uid: 1000,
            gid: 1000,
            pid: 4321,
        };
        let writes: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&writes);
        let presenter = ProtectedBootstrapPresenter::with_writer(
            FixedProducer(b"value".to_vec()),
            Box::new(move |_peer, data| {
                sink.lock().unwrap().push(data.to_vec());
                Ok(())
            }),
        );
        BootstrapPresenter::present(&presenter, &peer).unwrap();
        assert_eq!(writes.lock().unwrap().as_slice(), &[b"value\n".to_vec()]);

        let forbidden: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let forbidden_sink = Arc::clone(&forbidden);
        let empty = ProtectedBootstrapPresenter::with_writer(
            FixedProducer(Vec::new()),
            Box::new(move |_p, _d| {
                forbidden_sink.lock().unwrap().push(Vec::new());
                Ok(())
            }),
        );
        assert!(BootstrapPresenter::present(&empty, &peer).is_err());
        let forbidden_sink = Arc::clone(&forbidden);
        let big = ProtectedBootstrapPresenter::with_writer(
            FixedProducer(vec![0u8; 4097]),
            Box::new(move |_p, _d| {
                forbidden_sink.lock().unwrap().push(Vec::new());
                Ok(())
            }),
        );
        assert!(BootstrapPresenter::present(&big, &peer).is_err());
        assert!(forbidden.lock().unwrap().is_empty());
    }

    /// `WriteControllingTTY` — a missing/dead peer pid refuses before
    /// any terminal probing.
    #[test]
    fn write_tty_requires_live_peer() {
        let dead = PeerIdentity {
            uid: 0,
            gid: 0,
            pid: i32::MAX,
        };
        assert!(write_controlling_tty(&dead, b"x").is_err());
        let unset = PeerIdentity {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        assert!(write_controlling_tty(&unset, b"x").is_err());
    }
}
