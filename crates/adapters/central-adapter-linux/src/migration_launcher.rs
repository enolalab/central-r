//! `internal/migrationlauncher/protocol_linux.go` — the intentionally
//! small client side of the native migration launcher protocol
//! (CML1). It is not a general process-launch API: the peer selects
//! the executable, identity, environment, and socket.
//!
//! Wire shape (see `bins/central-migration-launcherd/src/protocol.rs`
//! for the server half):
//!
//! - magic `CML1`, version `1`
//! - launch request 24 B: command byte at offset 6, operation UUID at 8
//! - commit request 40 B: launch UUID at 8, evidence UUID at 24
//! - abort request 24 B: launch UUID at 8
//! - ack response 12 B; launch response 28 B (pid BE at 8, launch UUID
//!   at 12), the pidfd arriving as exactly one `SCM_RIGHTS` descriptor.

use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::Duration;

use central_foundation::failure::{Failure, FailureKind};
use rustix::net::{
    AddressFamily, ReturnFlags, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
};

use crate::sys::{peercred::peercred, scm_rights};

/// `SocketPath` — the fixed root-owned launcher socket.
pub const SOCKET_PATH: &str = "/run/central/migration-launcher.sock";

const MAGIC: &[u8; 4] = b"CML1";
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_SIZE: usize = 24;
const COMMIT_REQUEST_SIZE: usize = 40;
const RESPONSE_SIZE: usize = 12;
const LAUNCH_RESPONSE_SIZE: usize = 28;

const OP_LAUNCH: u8 = 1;
const OP_COMMIT: u8 = 2;
const OP_ABORT: u8 = 3;

const STATUS_OK: u8 = 0;
const STATUS_DENIED: u8 = 1;

fn err(msg: impl Into<String>) -> Failure {
    Failure::internal("migration_launcher", msg.into())
}

fn denied() -> Failure {
    Failure::denied("migration_launcher", "migration launcher: request denied")
}

/// `Command` — the closed migration operation grammar. It accepts no
/// flags, paths, DSNs, identities, or environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Up,
    Resume,
    Status,
    Verify,
    Reset,
}

impl Command {
    fn wire(self) -> u8 {
        match self {
            Command::Up => 1,
            Command::Resume => 2,
            Command::Status => 3,
            Command::Verify => 4,
            Command::Reset => 5,
        }
    }

    /// The argv token the daemon re-derives from the byte.
    pub fn as_str(self) -> &'static str {
        match self {
            Command::Up => "up",
            Command::Resume => "resume",
            Command::Status => "status",
            Command::Verify => "verify",
            Command::Reset => "reset",
        }
    }
}

/// `Request` — the complete caller-controlled protocol surface.
pub struct Request {
    pub command: Command,
    pub operation_id: uuid::Uuid,
}

/// `Result` — the newly launched migration process. The caller owns
/// `pidfd`.
pub struct LaunchResult {
    pub launch_id: uuid::Uuid,
    pub pid: u32,
    pub pidfd: OwnedFd,
}

struct Response {
    opcode: u8,
    status: u8,
    pid: u32,
    launch_id: uuid::Uuid,
}

/// `Client` connects only to the fixed root-owned launcher socket.
pub struct Client {
    socket_path: String,
    /// The UID the launcher peer must report via `SO_PEERCRED` —
    /// `0` in production (`validateRootPeer`); tests against a
    /// test-build daemon set the daemon's own UID.
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

    /// `newClient` — the test seam; same wire, configurable socket
    /// path and expected launcher UID. `#[doc(hidden)]` like the rest
    /// of this crate's test seams: production composition calls
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
            return Err(err("migration launcher: invalid client"));
        }
        let addr = SocketAddrUnix::new(&self.socket_path)
            .map_err(|e| err(format!("migration launcher: socket path: {e}")))?;
        let sock = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|e| err(format!("migration launcher: socket: {e}")))?;
        connect(&sock, &addr).map_err(|e| {
            if e == rustix::io::Errno::INVAL || e == rustix::io::Errno::PFNOSUPPORT {
                err(format!(
                    "migration launcher: dial did not return seqpacket connection: {e}"
                ))
            } else {
                err(format!("migration launcher: connect: {e}"))
            }
        })?;
        // `conn.SetDeadline(ctx.Deadline)` — a per-request absolute
        // budget, expressed here as read/write timeouts.
        rustix::net::sockopt::set_socket_timeout(
            &sock,
            rustix::net::sockopt::Timeout::Recv,
            Some(budget),
        )
        .map_err(|e| err(format!("migration launcher: set deadline: {e}")))?;
        rustix::net::sockopt::set_socket_timeout(
            &sock,
            rustix::net::sockopt::Timeout::Send,
            Some(budget),
        )
        .map_err(|e| err(format!("migration launcher: set deadline: {e}")))?;
        // `peerCredentials` + `validateRootPeer` — the listener's own
        // identity is verified before any request bytes are written.
        let peer =
            peercred(&sock).map_err(|e| err(format!("migration launcher: inspect peer: {e}")))?;
        if peer.pid.as_raw_pid() <= 0 || peer.uid.as_raw() != self.expected_peer_uid {
            return Err(Failure::denied(
                "migration_launcher",
                "migration launcher: launcher peer is not root",
            ));
        }
        Ok(sock)
    }

    /// `Launch` — ask the fixed launcher to start the fixed migration
    /// operator.
    pub fn launch(&self, budget: Duration, request: &Request) -> Result<LaunchResult, Failure> {
        let frame = encode_request(request)?;
        let sock = self.dial(budget)?;
        rustix::net::send(&sock, &frame, rustix::net::SendFlags::empty())
            .map_err(|e| err(format!("migration launcher: write request: {e}")))?;
        let mut data = [0u8; LAUNCH_RESPONSE_SIZE + 1];
        let recv = scm_rights::recv(&sock, &mut data)
            .map_err(|e| err(format!("migration launcher: receive response: {e}")))?;
        if recv
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            return Err(err("migration launcher: truncated response"));
        }
        let resp = decode_launch_response(&data[..recv.bytes])?;
        if resp.status != STATUS_OK {
            return Err(denied());
        }
        let [pidfd]: [OwnedFd; 1] = recv
            .fds
            .try_into()
            .map_err(|_| err("migration launcher: expected exactly one pidfd"))?;
        if resp.pid == 0 {
            return Err(err("migration launcher: invalid child PID"));
        }
        ensure_pidfd(&pidfd)?;
        Ok(LaunchResult {
            launch_id: resp.launch_id,
            pid: resp.pid,
            pidfd,
        })
    }

    /// `Commit` — bind an admitted launch to the broker evidence minted
    /// for it. Replay of the exact immutable pair is idempotent
    /// server-side, so reconcile once before surfacing an ambiguous
    /// failure, exactly like upstream.
    pub fn commit(
        &self,
        budget: Duration,
        launch_id: uuid::Uuid,
        evidence_id: uuid::Uuid,
    ) -> Result<(), Failure> {
        let frame = encode_commit_request(launch_id, evidence_id)?;
        let mut last = err("migration launcher: invalid client");
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
        let frame = encode_abort_request(launch_id)?;
        self.request_ack(budget, &frame, OP_ABORT)
    }

    fn request_ack(&self, budget: Duration, frame: &[u8], expected: u8) -> Result<(), Failure> {
        let sock = self.dial(budget)?;
        rustix::net::send(&sock, frame, rustix::net::SendFlags::empty())
            .map_err(|e| err(format!("migration launcher: write request: {e}")))?;
        let mut data = [0u8; RESPONSE_SIZE + 1];
        let recv = scm_rights::recv(&sock, &mut data)
            .map_err(|e| err(format!("migration launcher: receive response: {e}")))?;
        if recv
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            return Err(err("migration launcher: truncated response"));
        }
        if !recv.fds.is_empty() {
            return Err(err(
                "migration launcher: acknowledgement included descriptors",
            ));
        }
        let resp = decode_response(&data[..recv.bytes])?;
        if resp.opcode != expected {
            return Err(err("migration launcher: unexpected response opcode"));
        }
        if resp.status != STATUS_OK || resp.pid != 0 {
            return Err(denied());
        }
        Ok(())
    }
}

fn encode_request(request: &Request) -> Result<[u8; REQUEST_SIZE], Failure> {
    if request.operation_id.is_nil() {
        return Err(err("migration launcher: operation ID is required"));
    }
    let mut frame = [0u8; REQUEST_SIZE];
    frame[..4].copy_from_slice(MAGIC);
    frame[4] = PROTOCOL_VERSION;
    frame[5] = OP_LAUNCH;
    frame[6] = request.command.wire();
    frame[8..24].copy_from_slice(request.operation_id.as_bytes());
    Ok(frame)
}

fn encode_commit_request(
    launch_id: uuid::Uuid,
    evidence_id: uuid::Uuid,
) -> Result<[u8; COMMIT_REQUEST_SIZE], Failure> {
    if launch_id.is_nil() || evidence_id.is_nil() {
        return Err(err(
            "migration launcher: launch and evidence IDs are required",
        ));
    }
    let mut frame = [0u8; COMMIT_REQUEST_SIZE];
    frame[..4].copy_from_slice(MAGIC);
    frame[4] = PROTOCOL_VERSION;
    frame[5] = OP_COMMIT;
    frame[8..24].copy_from_slice(launch_id.as_bytes());
    frame[24..40].copy_from_slice(evidence_id.as_bytes());
    Ok(frame)
}

fn encode_abort_request(launch_id: uuid::Uuid) -> Result<[u8; REQUEST_SIZE], Failure> {
    if launch_id.is_nil() {
        return Err(err("migration launcher: launch ID is required"));
    }
    let mut frame = [0u8; REQUEST_SIZE];
    frame[..4].copy_from_slice(MAGIC);
    frame[4] = PROTOCOL_VERSION;
    frame[5] = OP_ABORT;
    frame[8..24].copy_from_slice(launch_id.as_bytes());
    Ok(frame)
}

fn decode_response(frame: &[u8]) -> Result<Response, Failure> {
    if frame.len() != RESPONSE_SIZE || &frame[..4] != MAGIC {
        return Err(err("migration launcher: malformed response"));
    }
    if frame[4] != PROTOCOL_VERSION {
        return Err(err("migration launcher: unsupported response version"));
    }
    if !matches!(frame[5], OP_LAUNCH | OP_COMMIT | OP_ABORT) {
        return Err(err("migration launcher: unknown response opcode"));
    }
    if frame[7] != 0 {
        return Err(err("migration launcher: non-zero response reserved byte"));
    }
    if frame[6] != STATUS_OK && frame[6] != STATUS_DENIED {
        return Err(err("migration launcher: unknown response status"));
    }
    Ok(Response {
        opcode: frame[5],
        status: frame[6],
        pid: u32::from_be_bytes(frame[8..12].try_into().unwrap_or([0; 4])),
        launch_id: uuid::Uuid::nil(),
    })
}

fn decode_launch_response(frame: &[u8]) -> Result<Response, Failure> {
    if frame.len() != LAUNCH_RESPONSE_SIZE {
        return Err(err("migration launcher: malformed launch response"));
    }
    let mut resp = decode_response(&frame[..RESPONSE_SIZE])?;
    let launch_id = uuid::Uuid::from_bytes(
        frame[12..28]
            .try_into()
            .map_err(|_| err("migration launcher: invalid launch ID"))?,
    );
    if resp.status == STATUS_OK && launch_id.is_nil() {
        return Err(err("migration launcher: invalid launch ID"));
    }
    resp.launch_id = launch_id;
    Ok(resp)
}

/// `ensurePIDFD` — `FD_CLOEXEC` is required, and a zero-signal
/// `pidfd_send_signal` proves the descriptor is a pidfd (EPERM passes;
/// the migration child is owned by another locked identity).
fn ensure_pidfd<Fd: AsFd>(fd: Fd) -> Result<(), Failure> {
    let flags = rustix::io::fcntl_getfd(&fd)
        .map_err(|e| err(format!("migration launcher: inspect pidfd: {e}")))?;
    if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(err("migration launcher: received pidfd lacks FD_CLOEXEC"));
    }
    match crate::sys::audited::pidfd_send_signal(fd.as_fd().as_raw_fd(), 0) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::PERM) => Ok(()),
        Err(e) => Err(err(format!(
            "migration launcher: expected exactly one pidfd: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_shapes() {
        let op = uuid::Uuid::from_bytes([0x11; 16]);
        let f = encode_request(&Request {
            command: Command::Verify,
            operation_id: op,
        })
        .expect("launch frame");
        assert_eq!(&f[..8], b"CML1\x01\x01\x04\x00");
        assert_eq!(&f[8..], op.as_bytes());

        let launch = uuid::Uuid::from_bytes([0x22; 16]);
        let evidence = uuid::Uuid::from_bytes([0x33; 16]);
        let f = encode_commit_request(launch, evidence).expect("commit frame");
        assert_eq!(&f[..8], b"CML1\x01\x02\x00\x00");
        assert_eq!(&f[8..24], launch.as_bytes());
        assert_eq!(&f[24..40], evidence.as_bytes());

        let f = encode_abort_request(launch).expect("abort frame");
        assert_eq!(&f[..8], b"CML1\x01\x03\x00\x00");
        assert_eq!(&f[8..24], launch.as_bytes());
    }

    #[test]
    fn encode_refuses_nil_ids() {
        assert!(
            encode_request(&Request {
                command: Command::Up,
                operation_id: uuid::Uuid::nil(),
            })
            .is_err()
        );
        assert!(encode_commit_request(uuid::Uuid::nil(), uuid::Uuid::now_v7()).is_err());
        assert!(encode_abort_request(uuid::Uuid::nil()).is_err());
    }

    #[test]
    fn decode_response_shapes() {
        // denied commit ack: opcode 2, status 1, pid 0.
        let mut f = [0u8; 12];
        f[..4].copy_from_slice(MAGIC);
        f[4] = PROTOCOL_VERSION;
        f[5] = OP_COMMIT;
        f[6] = STATUS_DENIED;
        let r = decode_response(&f).expect("denied ack decodes");
        assert_eq!(r.opcode, OP_COMMIT);
        assert_eq!(r.status, STATUS_DENIED);
        assert_eq!(r.pid, 0);

        // Reserved byte must be zero.
        f[7] = 1;
        assert!(decode_response(&f).is_err());

        // Short frame is malformed.
        assert!(decode_response(&f[..11]).is_err());
    }

    #[test]
    fn decode_launch_response_binds_id() {
        let launch = uuid::Uuid::from_bytes([0x44; 16]);
        let mut f = [0u8; 28];
        f[..4].copy_from_slice(MAGIC);
        f[4] = PROTOCOL_VERSION;
        f[5] = OP_LAUNCH;
        f[6] = STATUS_OK;
        f[8..12].copy_from_slice(&4321u32.to_be_bytes());
        f[12..28].copy_from_slice(launch.as_bytes());
        let r = decode_launch_response(&f).expect("launch response");
        assert_eq!(r.pid, 4321);
        assert_eq!(r.launch_id, launch);

        // An OK response with a nil launch ID refuses.
        f[12..28].fill(0);
        assert!(decode_launch_response(&f).is_err());
    }
}
