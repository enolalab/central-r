//! `internal/backuplauncher/protocol_linux.go` — the client half of
//! the native backup launcher protocol (CBL1). The peer selects the
//! executable, identity, environment, socket, and target lock; the
//! caller supplies only the operation UUID, the mode, and a
//! descriptor-bound repository directory.
//!
//! Wire shape (see `bins/central-backup-launcherd/src/protocol.rs`):
//!
//! - magic `CBL1`, version `2`
//! - launch request 24 B: mode byte at 6, operation UUID at 8, one
//!   `SCM_RIGHTS` directory descriptor
//! - commit request 40 B: launch UUID at 8, evidence UUID at 24
//! - id requests 24 B (abort/wait/assert/release/census): launch UUID
//! - ack 12 B; launch response 28 B (pidfd as exactly one fd);
//!   wait response 48 B; retained assertion 44 B; census 16 B.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::time::Duration;

use central_foundation::failure::{Failure, FailureKind};
use rustix::net::{
    AddressFamily, ReturnFlags, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
};

use crate::sys::{peercred::peercred, scm_rights};

/// `SocketPath` — the fixed root-owned launcher socket.
pub const SOCKET_PATH: &str = "/run/central/backup-launcher.sock";

const MAGIC: &[u8; 4] = b"CBL1";
const VERSION: u8 = 2;
const LAUNCH_REQUEST_SIZE: usize = 24;
const COMMIT_REQUEST_SIZE: usize = 40;
const ID_REQUEST_SIZE: usize = 24;
const RESPONSE_SIZE: usize = 12;
const LAUNCH_RESPONSE_SIZE: usize = 28;
const WAIT_RESPONSE_SIZE: usize = 48;
const RETAINED_RESPONSE_SIZE: usize = 44;
const CENSUS_RESPONSE_SIZE: usize = 16;

const OP_LAUNCH: u8 = 1;
const OP_COMMIT: u8 = 2;
const OP_ABORT: u8 = 3;
const OP_WAIT: u8 = 4;
const OP_ASSERT: u8 = 5;
const OP_RELEASE: u8 = 6;
const OP_CENSUS: u8 = 7;

const STATUS_OK: u8 = 0;
const STATUS_DENIED: u8 = 1;

/// `workerSucceeded`/`workerExited`/`workerSignaled` wire values.
const WORKER_SUCCEEDED: u8 = 1;
const WORKER_EXITED: u8 = 2;
const WORKER_SIGNALED: u8 = 3;

fn err(msg: impl Into<String>) -> Failure {
    Failure::internal("backup_launcher", msg.into())
}

fn denied() -> Failure {
    Failure::denied("backup_launcher", "backup launcher: request denied")
}

/// `Mode` — the closed launch-mode set. `BackupCreate` is the zero
/// value upstream normalizes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    BackupCreate,
    ThroughputProbe,
}

impl Mode {
    fn wire(self) -> u8 {
        match self {
            Mode::BackupCreate => 1,
            Mode::ThroughputProbe => 2,
        }
    }
    fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(Mode::BackupCreate),
            2 => Some(Mode::ThroughputProbe),
            _ => None,
        }
    }
}

/// `Request` — the complete caller-controlled launch surface. The
/// repository descriptor must be a `FD_CLOEXEC` directory.
pub struct Request<'a> {
    pub mode: Mode,
    pub operation_id: uuid::Uuid,
    pub repository_fd: BorrowedFd<'a>,
}

/// `Result` — the newly launched backup monitor. Caller owns `pidfd`.
pub struct LaunchResult {
    pub launch_id: uuid::Uuid,
    pub pid: u32,
    pub pidfd: OwnedFd,
    pub mode: Mode,
}

/// `Outcome` — the waited worker's locator-free result.
pub struct Outcome {
    pub succeeded: bool,
    pub exit_code: i32,
    pub signal: i32,
    pub target_lock_proof: [u8; 32],
}

/// `Census` — other live processes and held permits, excluding the
/// named launch.
pub struct Census {
    pub live_processes: u32,
    pub held_permits: u32,
}

struct Response {
    opcode: u8,
    status: u8,
    mode: u8,
    outcome: u8,
    pid: u32,
    launch_id: uuid::Uuid,
    exit_code: i32,
    signal: i32,
    proof: [u8; 32],
}

/// `Client` connects only to the fixed root-owned launcher socket.
pub struct Client {
    socket_path: String,
    expected_peer_uid: u32,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// `NewClient` — the production socket and the root peer check.
    pub fn new() -> Self {
        Self {
            socket_path: SOCKET_PATH.to_owned(),
            expected_peer_uid: 0,
        }
    }

    /// `newClient` — the test seam; configurable socket path and
    /// expected launcher UID. Production composition calls
    /// [`Client::new`].
    #[doc(hidden)]
    pub fn for_test(socket_path: impl Into<String>, expected_peer_uid: u32) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_peer_uid,
        }
    }

    fn dial(&self, budget: Duration) -> Result<OwnedFd, Failure> {
        if self.socket_path.is_empty() {
            return Err(err("backup launcher: invalid client"));
        }
        let addr = SocketAddrUnix::new(&self.socket_path)
            .map_err(|e| err(format!("backup launcher: socket path: {e}")))?;
        let sock = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|e| err(format!("backup launcher: socket: {e}")))?;
        connect(&sock, &addr).map_err(|e| {
            if e == rustix::io::Errno::INVAL || e == rustix::io::Errno::PFNOSUPPORT {
                err(format!(
                    "backup launcher: dial did not return seqpacket connection: {e}"
                ))
            } else {
                err(format!("backup launcher: connect: {e}"))
            }
        })?;
        rustix::net::sockopt::set_socket_timeout(
            &sock,
            rustix::net::sockopt::Timeout::Recv,
            Some(budget),
        )
        .map_err(|e| err(format!("backup launcher: set deadline: {e}")))?;
        rustix::net::sockopt::set_socket_timeout(
            &sock,
            rustix::net::sockopt::Timeout::Send,
            Some(budget),
        )
        .map_err(|e| err(format!("backup launcher: set deadline: {e}")))?;
        let peer =
            peercred(&sock).map_err(|e| err(format!("backup launcher: inspect peer: {e}")))?;
        if peer.pid.as_raw_pid() <= 0 || peer.uid.as_raw() != self.expected_peer_uid {
            return Err(Failure::denied(
                "backup_launcher",
                "backup launcher: launcher peer is not root",
            ));
        }
        Ok(sock)
    }

    fn recv<const N: usize>(&self, sock: &OwnedFd) -> Result<([u8; N], Vec<OwnedFd>), Failure> {
        let mut data = [0u8; N];
        let recv = scm_rights::recv(sock, &mut data)
            .map_err(|e| err(format!("backup launcher: receive response: {e}")))?;
        if recv
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            return Err(err("backup launcher: truncated response"));
        }
        if recv.bytes != N {
            return Err(err("backup launcher: malformed response"));
        }
        Ok((data, recv.fds))
    }

    fn request_frame(&self, budget: Duration, frame: &[u8]) -> Result<OwnedFd, Failure> {
        let sock = self.dial(budget)?;
        rustix::net::send(&sock, frame, rustix::net::SendFlags::empty())
            .map_err(|e| err(format!("backup launcher: write request: {e}")))?;
        Ok(sock)
    }

    /// `Launch` — ask the fixed launcher to start the fixed backup
    /// worker with the caller's descriptor-bound repository.
    pub fn launch(&self, budget: Duration, request: &Request<'_>) -> Result<LaunchResult, Failure> {
        let frame = encode_launch_request(request)?;
        validate_repository_fd(request.repository_fd)?;
        let sock = self.dial(budget)?;
        scm_rights::send(&sock, &frame, &[request.repository_fd])
            .map_err(|e| err(format!("backup launcher: write launch request: {e}")))?;
        let (data, fds) = self.recv::<LAUNCH_RESPONSE_SIZE>(&sock)?;
        let resp = decode_launch_response(&data)?;
        if resp.status != STATUS_OK {
            return Err(denied());
        }
        if Mode::from_wire(resp.mode) != Some(request.mode) {
            return Err(err("backup launcher: launch mode acknowledgement mismatch"));
        }
        let [pidfd]: [OwnedFd; 1] = fds
            .try_into()
            .map_err(|_| err("backup launcher: expected exactly one pidfd"))?;
        if resp.pid == 0 {
            return Err(err("backup launcher: invalid child PID"));
        }
        ensure_pidfd(&pidfd)?;
        Ok(LaunchResult {
            launch_id: resp.launch_id,
            pid: resp.pid,
            pidfd,
            mode: request.mode,
        })
    }

    /// `Commit` — bind an admitted launch to the broker evidence.
    /// Exact retries are idempotent server-side, so reconcile once
    /// before surfacing an ambiguous failure, exactly like upstream.
    pub fn commit(
        &self,
        budget: Duration,
        launch_id: uuid::Uuid,
        evidence_id: uuid::Uuid,
    ) -> Result<(), Failure> {
        let frame = encode_commit_request(launch_id, evidence_id)?;
        let mut last = err("backup launcher: invalid client");
        for _ in 0..2 {
            match self.request_ack(budget, &frame, OP_COMMIT) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == FailureKind::Denied => return Err(e),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// `Abort` — terminate and reap an admitted but uncommitted launch.
    pub fn abort(&self, budget: Duration, launch_id: uuid::Uuid) -> Result<(), Failure> {
        let frame = encode_id_request(OP_ABORT, launch_id)?;
        self.request_ack(budget, &frame, OP_ABORT)
    }

    /// `WaitAndReap` — block until the worker finishes and the monitor
    /// reports; returns only the locator-free outcome.
    pub fn wait_and_reap(
        &self,
        budget: Duration,
        launch_id: uuid::Uuid,
    ) -> Result<Outcome, Failure> {
        let frame = encode_id_request(OP_WAIT, launch_id)?;
        let sock = self.request_frame(budget, &frame)?;
        let (data, fds) = self.recv::<WAIT_RESPONSE_SIZE>(&sock)?;
        if !fds.is_empty() {
            return Err(err("backup launcher: wait response included descriptors"));
        }
        let resp = decode_wait_response(&data)?;
        if resp.status != STATUS_OK {
            return Err(denied());
        }
        Ok(Outcome {
            succeeded: resp.outcome == WORKER_SUCCEEDED,
            exit_code: resp.exit_code,
            signal: resp.signal,
            target_lock_proof: resp.proof,
        })
    }

    /// `AssertRetained` — prove the monitor still owns the target
    /// lock; returns only the 32-byte proof digest.
    pub fn assert_retained(
        &self,
        budget: Duration,
        launch_id: uuid::Uuid,
    ) -> Result<[u8; 32], Failure> {
        let frame = encode_id_request(OP_ASSERT, launch_id)?;
        let sock = self.request_frame(budget, &frame)?;
        let (data, fds) = self.recv::<RETAINED_RESPONSE_SIZE>(&sock)?;
        if !fds.is_empty() {
            return Err(err(
                "backup launcher: retained assertion included descriptors",
            ));
        }
        decode_retained_response(&data)
    }

    /// `Census` — counts of other live processes and held permits;
    /// never denies.
    pub fn census(&self, budget: Duration, launch_id: uuid::Uuid) -> Result<Census, Failure> {
        let frame = encode_id_request(OP_CENSUS, launch_id)?;
        let sock = self.request_frame(budget, &frame)?;
        let (data, fds) = self.recv::<CENSUS_RESPONSE_SIZE>(&sock)?;
        if !fds.is_empty() {
            return Err(err("backup launcher: census response included descriptors"));
        }
        decode_census_response(&data)
    }

    /// `ReleaseAndReap` — close the retained target-lock socket and
    /// return only after the monitor itself has exited and been
    /// reaped.
    pub fn release_and_reap(&self, budget: Duration, launch_id: uuid::Uuid) -> Result<(), Failure> {
        let frame = encode_id_request(OP_RELEASE, launch_id)?;
        self.request_ack(budget, &frame, OP_RELEASE)
    }

    fn request_ack(&self, budget: Duration, frame: &[u8], expected: u8) -> Result<(), Failure> {
        let sock = self.request_frame(budget, frame)?;
        let (data, fds) = self.recv::<RESPONSE_SIZE>(&sock)?;
        if !fds.is_empty() {
            return Err(err("backup launcher: acknowledgement included descriptors"));
        }
        let resp = decode_response(&data)?;
        if resp.opcode != expected {
            return Err(err("backup launcher: unexpected response opcode"));
        }
        if resp.status != STATUS_OK || resp.pid != 0 {
            return Err(denied());
        }
        Ok(())
    }
}

fn encode_launch_request(request: &Request<'_>) -> Result<[u8; LAUNCH_REQUEST_SIZE], Failure> {
    if request.operation_id.is_nil() {
        return Err(err("backup launcher: operation ID is required"));
    }
    let mut frame = [0u8; LAUNCH_REQUEST_SIZE];
    frame[..4].copy_from_slice(MAGIC);
    frame[4] = VERSION;
    frame[5] = OP_LAUNCH;
    frame[6] = request.mode.wire();
    frame[8..24].copy_from_slice(request.operation_id.as_bytes());
    Ok(frame)
}

fn encode_commit_request(
    launch_id: uuid::Uuid,
    evidence_id: uuid::Uuid,
) -> Result<[u8; COMMIT_REQUEST_SIZE], Failure> {
    if launch_id.is_nil() || evidence_id.is_nil() {
        return Err(err("backup launcher: launch and evidence IDs are required"));
    }
    let mut frame = [0u8; COMMIT_REQUEST_SIZE];
    frame[..4].copy_from_slice(MAGIC);
    frame[4] = VERSION;
    frame[5] = OP_COMMIT;
    frame[8..24].copy_from_slice(launch_id.as_bytes());
    frame[24..40].copy_from_slice(evidence_id.as_bytes());
    Ok(frame)
}

fn encode_id_request(op: u8, launch_id: uuid::Uuid) -> Result<[u8; ID_REQUEST_SIZE], Failure> {
    if launch_id.is_nil() {
        return Err(err("backup launcher: launch ID is required"));
    }
    let mut frame = [0u8; ID_REQUEST_SIZE];
    frame[..4].copy_from_slice(MAGIC);
    frame[4] = VERSION;
    frame[5] = op;
    frame[8..24].copy_from_slice(launch_id.as_bytes());
    Ok(frame)
}

fn decode_response(frame: &[u8]) -> Result<Response, Failure> {
    if frame.len() != RESPONSE_SIZE || &frame[..4] != MAGIC {
        return Err(err("backup launcher: malformed response"));
    }
    if frame[4] != VERSION {
        return Err(err("backup launcher: unsupported response version"));
    }
    if !matches!(
        frame[5],
        OP_LAUNCH | OP_COMMIT | OP_ABORT | OP_WAIT | OP_ASSERT | OP_RELEASE | OP_CENSUS
    ) {
        return Err(err("backup launcher: unknown response opcode"));
    }
    if frame[7] != 0 && frame[5] != OP_LAUNCH {
        return Err(err("backup launcher: non-zero response reserved byte"));
    }
    if frame[6] != STATUS_OK && frame[6] != STATUS_DENIED {
        return Err(err("backup launcher: unknown response status"));
    }
    Ok(Response {
        opcode: frame[5],
        status: frame[6],
        mode: 0,
        outcome: 0,
        pid: u32::from_be_bytes(frame[8..12].try_into().unwrap_or([0; 4])),
        launch_id: uuid::Uuid::nil(),
        exit_code: 0,
        signal: 0,
        proof: [0u8; 32],
    })
}

fn decode_launch_response(frame: &[u8; LAUNCH_RESPONSE_SIZE]) -> Result<Response, Failure> {
    let mut base = [0u8; RESPONSE_SIZE];
    base.copy_from_slice(&frame[..RESPONSE_SIZE]);
    let mode = base[7];
    base[7] = 0;
    let mut resp = decode_response(&base)?;
    if resp.opcode != OP_LAUNCH {
        return Err(err("backup launcher: unexpected launch response opcode"));
    }
    if resp.status == STATUS_OK {
        if mode == 0 || Mode::from_wire(mode).is_none() {
            return Err(err("backup launcher: invalid launch mode acknowledgement"));
        }
    } else if mode != 0 {
        return Err(err("backup launcher: malformed denied launch response"));
    }
    let launch_id = uuid::Uuid::from_bytes(
        frame[12..28]
            .try_into()
            .map_err(|_| err("backup launcher: invalid launch ID"))?,
    );
    if resp.status == STATUS_OK && launch_id.is_nil() {
        return Err(err("backup launcher: invalid launch ID"));
    }
    resp.launch_id = launch_id;
    resp.mode = mode;
    Ok(resp)
}

fn decode_wait_response(frame: &[u8; WAIT_RESPONSE_SIZE]) -> Result<Response, Failure> {
    if &frame[..4] != MAGIC || frame[4] != VERSION || frame[5] != OP_WAIT {
        return Err(err("backup launcher: malformed wait response"));
    }
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&frame[16..48]);
    let resp = Response {
        opcode: OP_WAIT,
        status: frame[6],
        mode: 0,
        outcome: frame[7],
        pid: 0,
        launch_id: uuid::Uuid::nil(),
        exit_code: i32::from_be_bytes(frame[8..12].try_into().unwrap_or([0; 4])),
        signal: i32::from_be_bytes(frame[12..16].try_into().unwrap_or([0; 4])),
        proof,
    };
    if resp.status != STATUS_OK && resp.status != STATUS_DENIED {
        return Err(err("backup launcher: unknown wait response status"));
    }
    if resp.status == STATUS_DENIED {
        if resp.outcome != 0 && resp.outcome != WORKER_SUCCEEDED
            || resp.exit_code != 0
            || resp.signal != 0
            || resp.proof != [0u8; 32]
        {
            return Err(err("backup launcher: malformed denied wait response"));
        }
        return Ok(resp);
    }
    match resp.outcome {
        WORKER_SUCCEEDED => {
            if resp.exit_code != 0 || resp.signal != 0 || resp.proof == [0u8; 32] {
                return Err(err("backup launcher: malformed successful worker outcome"));
            }
        }
        WORKER_EXITED => {
            if resp.exit_code <= 0 || resp.signal != 0 || resp.proof != [0u8; 32] {
                return Err(err("backup launcher: malformed exited worker outcome"));
            }
        }
        WORKER_SIGNALED => {
            if resp.exit_code != 0 || resp.signal <= 0 || resp.proof != [0u8; 32] {
                return Err(err("backup launcher: malformed signaled worker outcome"));
            }
        }
        _ => return Err(err("backup launcher: unknown worker outcome")),
    }
    Ok(resp)
}

fn decode_retained_response(frame: &[u8; RETAINED_RESPONSE_SIZE]) -> Result<[u8; 32], Failure> {
    if &frame[..4] != MAGIC || frame[4] != VERSION || frame[5] != OP_ASSERT || frame[7] != 0 {
        return Err(err("backup launcher: malformed retained assertion"));
    }
    let status = frame[6];
    if status != STATUS_OK && status != STATUS_DENIED {
        return Err(err("backup launcher: unknown retained assertion status"));
    }
    if u32::from_be_bytes(frame[8..12].try_into().unwrap_or([0; 4])) != 0 {
        return Err(err(
            "backup launcher: non-zero retained assertion reserved field",
        ));
    }
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&frame[12..44]);
    if status != STATUS_OK {
        if proof != [0u8; 32] {
            return Err(err("backup launcher: malformed denied retained assertion"));
        }
        return Err(denied());
    }
    if proof == [0u8; 32] {
        return Err(err("backup launcher: retained assertion omitted proof"));
    }
    Ok(proof)
}

fn decode_census_response(frame: &[u8; CENSUS_RESPONSE_SIZE]) -> Result<Census, Failure> {
    if &frame[..4] != MAGIC || frame[4] != VERSION || frame[5] != OP_CENSUS || frame[7] != 0 {
        return Err(err("backup launcher: malformed census response"));
    }
    if frame[6] != STATUS_OK {
        return Err(err("backup launcher: unexpected census status"));
    }
    Ok(Census {
        live_processes: u32::from_be_bytes(frame[8..12].try_into().unwrap_or([0; 4])),
        held_permits: u32::from_be_bytes(frame[12..16].try_into().unwrap_or([0; 4])),
    })
}

/// `validateRepositoryFD` — a `FD_CLOEXEC` directory descriptor.
fn validate_repository_fd(fd: BorrowedFd<'_>) -> Result<(), Failure> {
    let stat = rustix::fs::fstat(fd).map_err(|e| {
        err(format!(
            "backup launcher: inspect repository descriptor: {e}"
        ))
    })?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode as _).is_dir() {
        return Err(err(
            "backup launcher: repository descriptor is not a directory",
        ));
    }
    let flags = rustix::io::fcntl_getfd(fd).map_err(|e| {
        err(format!(
            "backup launcher: inspect repository descriptor flags: {e}"
        ))
    })?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(err(
            "backup launcher: repository descriptor lacks FD_CLOEXEC",
        ));
    }
    Ok(())
}

/// `ensurePIDFD` — `FD_CLOEXEC` plus a zero-signal probe.
fn ensure_pidfd<Fd: AsFd>(fd: Fd) -> Result<(), Failure> {
    let flags = rustix::io::fcntl_getfd(&fd)
        .map_err(|e| err(format!("backup launcher: inspect pidfd: {e}")))?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(err("backup launcher: received pidfd lacks FD_CLOEXEC"));
    }
    match crate::sys::audited::pidfd_send_signal(fd.as_fd().as_raw_fd(), 0) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::PERM) => Ok(()),
        Err(e) => Err(err(format!(
            "backup launcher: expected exactly one pidfd: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_shapes() {
        let op = uuid::Uuid::from_bytes([0x11; 16]);
        let f = encode_id_request(OP_WAIT, op).expect("id frame");
        assert_eq!(&f[..8], b"CBL1\x02\x04\x00\x00");
        assert_eq!(&f[8..], op.as_bytes());

        let evidence = uuid::Uuid::from_bytes([0x33; 16]);
        let f = encode_commit_request(op, evidence).expect("commit frame");
        assert_eq!(&f[..8], b"CBL1\x02\x02\x00\x00");
        assert_eq!(&f[8..24], op.as_bytes());
        assert_eq!(&f[24..40], evidence.as_bytes());
    }

    #[test]
    fn encode_refuses_nil_ids() {
        assert!(encode_id_request(OP_ABORT, uuid::Uuid::nil()).is_err());
        assert!(encode_commit_request(uuid::Uuid::nil(), uuid::Uuid::now_v7()).is_err());
    }

    #[test]
    fn decode_wait_shapes() {
        // denied wait: all-zero trailer.
        let mut f = [0u8; WAIT_RESPONSE_SIZE];
        f[..4].copy_from_slice(MAGIC);
        f[4] = VERSION;
        f[5] = OP_WAIT;
        f[6] = STATUS_DENIED;
        assert!(decode_wait_response(&f).is_ok());
        // ok+succeeded needs a non-zero proof.
        f[6] = STATUS_OK;
        f[7] = WORKER_SUCCEEDED;
        assert!(decode_wait_response(&f).is_err());
        f[16..48].fill(0xAB);
        assert!(decode_wait_response(&f).is_ok());
        // exited needs a positive exit code and zero proof.
        f[7] = WORKER_EXITED;
        f[8..12].copy_from_slice(&3i32.to_be_bytes());
        assert!(decode_wait_response(&f).is_err());
        f[16..48].fill(0);
        assert!(decode_wait_response(&f).is_ok());
    }

    #[test]
    fn decode_retained_and_census() {
        let mut f = [0u8; RETAINED_RESPONSE_SIZE];
        f[..4].copy_from_slice(MAGIC);
        f[4] = VERSION;
        f[5] = OP_ASSERT;
        f[6] = STATUS_DENIED;
        assert!(decode_retained_response(&f).is_err());
        f[6] = STATUS_OK;
        assert!(decode_retained_response(&f).is_err());
        f[12..44].fill(0xCD);
        assert!(decode_retained_response(&f).is_ok());

        let mut c = [0u8; CENSUS_RESPONSE_SIZE];
        c[..4].copy_from_slice(MAGIC);
        c[4] = VERSION;
        c[5] = OP_CENSUS;
        c[8..12].copy_from_slice(&2u32.to_be_bytes());
        c[12..16].copy_from_slice(&1u32.to_be_bytes());
        let census = decode_census_response(&c).expect("census");
        assert_eq!(census.live_processes, 2);
        assert_eq!(census.held_permits, 1);
    }

    #[test]
    fn decode_launch_binds_id_and_mode() {
        let launch = uuid::Uuid::from_bytes([0x44; 16]);
        let mut f = [0u8; LAUNCH_RESPONSE_SIZE];
        f[..4].copy_from_slice(MAGIC);
        f[4] = VERSION;
        f[5] = OP_LAUNCH;
        f[6] = STATUS_OK;
        f[7] = 1;
        f[8..12].copy_from_slice(&4321u32.to_be_bytes());
        f[12..28].copy_from_slice(launch.as_bytes());
        let r = decode_launch_response(&f).expect("launch response");
        assert_eq!(r.pid, 4321);
        assert_eq!(r.mode, 1);
        // Denied launch with a mode byte is malformed.
        f[6] = STATUS_DENIED;
        assert!(decode_launch_response(&f).is_err());
    }
}
