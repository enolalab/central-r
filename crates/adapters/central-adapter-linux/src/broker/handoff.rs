//! `handoff_linux.go` + `secret_bootstrap_transport_linux.go` — the
//! broker's descriptor-custody transport for the B04/B05 secret
//! materialization protocol.
//!
//! Custody invariants (unchanged from upstream):
//!
//! - Plaintext secret material is written ONLY through a peer-sent
//!   destination descriptor that passes the strict inbound shape:
//!   regular file, `nlink <= 1`, root-owned, exactly `0400`, empty, on
//!   tmpfs — `sys::memfd::validate_destination` over
//!   `sys::scm_rights::recv_marker_descriptor`, upstream's
//!   `ReceiveDescriptor` sequence.
//! - [`write_value_to_descriptor`] is upstream's
//!   `WriteValueToDescriptor`: close-on-exec, strip exactly one
//!   trailing newline, append exactly one, a single full write, fsync,
//!   and *always* close — every error path closes the fd.
//! - `scm_rights::recv` refuses malformed ancillary data and closes
//!   every received descriptor on every rejection path — the
//!   `validateReceivedDescriptor`/`closeReceivedDescriptors` contract.
//! - The denial frame `0x02` and the ACK frame `[0x01|len|uid|gid|
//!   "b04-ok:"+hmac]` keep upstream's byte shape.

use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;

use central_foundation::failure::Failure;
use rustix::io::Errno;
use rustix::process::Uid;

use central_infra::domain::{HandoffReceipt, HandoffRequest};

use super::signing::SigningService;
use crate::sys::{memfd, scm_rights};

fn internal(msg: impl Into<String>) -> Failure {
    Failure::internal("broker_handoff", msg)
}

fn os_failure(step: &str, e: Errno) -> Failure {
    internal(format!("transport: {step}: {e}"))
}

/// `HandoffService` — sealed memfd-backed value holders for
/// `SCM_RIGHTS` handoff to the runtime (upstream `handoff_linux.go`).
/// The descriptor-custody work is `sys::memfd::create_sealed`
/// verbatim; this wrapper keeps upstream's service shape so
/// `Service.handoff` composes like `NewHandoffService()`.
#[derive(Debug, Default)]
pub struct HandoffService;

impl HandoffService {
    /// `NewHandoffService`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// `Handoff` — a sealed, `0600`, `MFD_CLOEXEC` memfd containing
    /// `value`. The caller owns the returned descriptor.
    ///
    /// # Errors
    /// `sys_memfd_invalid` when `value` is empty or exceeds the
    /// 64 KiB bound; `sys_memfd_os` on syscall failure.
    pub fn handoff(&self, value: &[u8]) -> Result<OwnedFd, Failure> {
        memfd::create_sealed("central-secret", value)
    }
}

/// `ReceiveDescriptor` — the strict inbound destination descriptor:
/// one `0x01` marker byte carrying exactly one `SCM_RIGHTS` fd, then
/// the fstat/fstatfs shape checks (regular file, `nlink <= 1`,
/// root-owned, `0400`, empty, tmpfs). Every malformed ancillary shape
/// is refused inside `scm_rights::recv` with every received fd closed;
/// a shape refusal closes the descriptor here exactly like upstream's
/// per-check `unix.Close`.
///
/// # Errors
/// `sys_scm_rights_*` for the ancillary-shape refusals;
/// `broker_handoff` wrapping `sys_memfd_*` for the descriptor-shape
/// refusals.
pub(crate) fn receive_descriptor(
    conn: &crate::broker::deadline::DeadlineStream,
) -> Result<OwnedFd, Failure> {
    let fd = conn.recv_marker_descriptor()?;
    memfd::validate_destination(&fd, Uid::ROOT)
        .map_err(|e| internal(format!("transport: {}", e.message())))?;
    Ok(fd)
}

/// `WriteValueToDescriptor` — writes `value` to the validated fd,
/// fsyncs, and closes it. The helper must not access the fd until the
/// broker has closed it.
///
/// Exactly one trailing newline, regardless of whether the resolved
/// value already carried one (SC-DEF-39/41: the pgpass purposes store
/// their value pre-formatted with its trailing newline; appending a
/// second doubled it for `central-migrate`'s descriptor reader).
///
/// # Errors
/// `broker_handoff` on write, short write, or fsync failure — the fd
/// is closed on every path because the `OwnedFd` drops.
pub fn write_value_to_descriptor(fd: OwnedFd, value: &[u8]) -> Result<(), Failure> {
    // `syscall.CloseOnExec` — received fds already carry
    // MSG_CMSG_CLOEXEC; upstream sets it explicitly and so do we
    // (idempotent).
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)
        .map_err(|e| os_failure("fcntl(FD_CLOEXEC)", e))?;
    let mut buf = value.to_vec();
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    buf.push(b'\n');
    // Upstream issues a single unix.Write and treats a short write as
    // an error — no write loop.
    let n = rustix::io::write(&fd, &buf).map_err(|e| os_failure("write fd", e))?;
    if n != buf.len() {
        return Err(internal(format!(
            "transport: short write (wrote {n}, expected {})",
            buf.len()
        )));
    }
    rustix::fs::fsync(&fd).map_err(|e| os_failure("fsync fd", e))?;
    drop(fd); // upstream's final `unix.Close(fd)` — the helper reads now.
    Ok(())
}

/// `ReadTransportFrame` — a single framed byte from the connection.
pub fn read_transport_frame(conn: &mut impl Read) -> Result<u8, Failure> {
    let mut frame = [0u8; 1];
    conn.read_exact(&mut frame)
        .map_err(|e| internal(format!("transport: read frame: {e}")))?;
    Ok(frame[0])
}

/// `WriteTransportFrame` — a single framed byte to the connection.
pub fn write_transport_frame(conn: &mut impl Write, byte: u8) -> Result<(), Failure> {
    conn.write_all(&[byte])
        .map_err(|e| internal(format!("transport: write frame: {e}")))
}

/// `SendDescriptor` — an acknowledgement byte plus the mount-ready
/// opaque metadata, sent back to the lifecycle helper.
pub fn send_descriptor(mut conn: &UnixStream, ack: u8, opaque_token: &[u8]) -> Result<(), Failure> {
    let mut frame = Vec::with_capacity(1 + opaque_token.len());
    frame.push(ack);
    frame.extend_from_slice(opaque_token);
    conn.write_all(&frame)
        .map_err(|e| internal(format!("B04 transport: write: {e}")))
}

/// `sendB04Descriptor` — the outbound descriptor send: marker `0x01`
/// plus `fd` in a single `SCM_RIGHTS` message.
pub fn send_b04_descriptor(conn: &UnixStream, fd: impl AsFd) -> Result<(), Failure> {
    let sent = scm_rights::send(conn, &[scm_rights::TRANSPORT_MARKER], &[fd.as_fd()])?;
    if sent != 1 {
        return Err(internal("B04 transport: sendmsg short write"));
    }
    Ok(())
}

/// `ComputeMaterializeReceiptHMAC` — the `b04-materialize` fingerprint
/// over the colon-joined request payload.
pub fn compute_materialize_receipt_hmac(signing: &SigningService, req: &HandoffRequest) -> String {
    let payload = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        req.binding_id,
        req.operation_id,
        req.receipt_id,
        req.purpose.as_str(),
        req.peer_uid,
        req.peer_pid,
        req.service,
        req.target,
        req.uid,
        req.gid
    );
    signing.fingerprint("b04-materialize", payload.as_bytes())
}

/// `handleB04MaterializeTransport` step 7 — the same `b04-materialize`
/// fingerprint as [`compute_materialize_receipt_hmac`], but over the
/// *returned receipt* (upstream `service.go` recomputes it inline over
/// `receipt` fields, never the request). On a resume the durable
/// receipt's `receipt_id` predates the one freshly minted into the
/// request, so hashing the request would prove a receipt that was
/// never persisted while `opaque_token` carries the persisted record's
/// HMAC — the ACK frame must name the durable identity.
pub fn compute_materialize_receipt_hmac_for_receipt(
    signing: &SigningService,
    receipt: &HandoffReceipt,
) -> String {
    let payload = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        receipt.binding_id,
        receipt.operation_id,
        receipt.receipt_id,
        receipt.purpose.as_str(),
        receipt.peer_uid,
        receipt.peer_pid,
        receipt.service,
        receipt.target,
        receipt.uid,
        receipt.gid
    );
    signing.fingerprint("b04-materialize", payload.as_bytes())
}

/// `DefaultTransport` — a complete transport handler for a single B04
/// materialization: validate FD, write value, acknowledge.
pub struct DefaultTransport {
    /// The broker's persistent HMAC identity.
    pub signing: std::sync::Arc<SigningService>,
}

#[cfg(test)]
impl DefaultTransport {
    /// `HandleMaterialize` — receive+validate the destination
    /// descriptor (denial frame `0x02` on any refusal), write the
    /// value, then emit the ACK frame `[0x01|len|uid|gid|proof]`.
    pub(crate) fn handle_materialize(
        &self,
        conn: &crate::broker::deadline::DeadlineStream,
        req: &HandoffRequest,
        secret: &[u8],
    ) -> Result<(), Failure> {
        let fd = match receive_descriptor(conn) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = write_transport_frame(&mut &*conn, 0x02);
                return Err(e);
            }
        };
        if let Err(e) = write_value_to_descriptor(fd, secret) {
            let _ = write_transport_frame(&mut &*conn, 0x02);
            return Err(e);
        }

        let receipt_hmac = compute_materialize_receipt_hmac(&self.signing, req);
        let mut opaque_proof = Vec::with_capacity("b04-ok:".len() + receipt_hmac.len());
        opaque_proof.extend_from_slice(b"b04-ok:");
        opaque_proof.extend_from_slice(receipt_hmac.as_bytes());

        // Frame: 0x01 ack marker(1), length(2), uid(2), gid(2), opaque
        // proof(N) — upstream's `binary.BigEndian` uint16s.
        let mut frame = Vec::with_capacity(7 + opaque_proof.len());
        frame.push(0x01);
        frame.extend_from_slice(&(opaque_proof.len() as u16).to_be_bytes());
        frame.extend_from_slice(&1000u16.to_be_bytes());
        frame.extend_from_slice(&1000u16.to_be_bytes());
        frame.extend_from_slice(&opaque_proof);
        (&*conn)
            .write_all(&frame)
            .map_err(|e| internal(format!("B04 transport: write ack: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{MemfdFlags, Mode, fchmod, memfd_create};
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    fn pair() -> (UnixStream, UnixStream) {
        let (a, b) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        (a.into(), b.into())
    }

    fn empty_memfd_0400() -> OwnedFd {
        let fd = memfd_create(
            "central-test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .expect("memfd");
        fchmod(&fd, Mode::from_bits_retain(0o400)).expect("fchmod");
        fd
    }

    #[test]
    fn handoff_service_creates_sealed_bounded_fd() {
        let svc = HandoffService::new();
        assert!(svc.handoff(b"").is_err());
        assert!(
            svc.handoff(&vec![0u8; (memfd::MAX_VALUE_BYTES + 1) as usize])
                .is_err()
        );
        let fd = svc.handoff(b"minio-root").expect("handoff fd");
        let mut file = std::fs::File::from(fd);
        let mut got = Vec::new();
        file.read_to_end(&mut got).expect("read");
        assert_eq!(got, b"minio-root");
        assert!(rustix::io::write(&file, b"x").is_err());
    }

    #[test]
    fn write_value_closes_fd_on_success() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt as _;
        let fd = empty_memfd_0400();
        let raw = fd.as_raw_fd();
        let orig_inode = rustix::fs::fstat(&fd).expect("fstat memfd").st_ino;
        write_value_to_descriptor(fd, b"secret").expect("write");
        // The descriptor number is closed — /proc self lookup fails.
        // Under parallel tests the number can be reassigned to an
        // unrelated open before the lookup runs, so a resolving
        // lookup is only a failure when it still names this memfd
        // (same inode); anything else is reuse, not a leaked fd.
        if let Ok(f) = std::fs::File::open(format!("/proc/self/fd/{raw}")) {
            let inode = f.metadata().expect("fd metadata").ino();
            assert_ne!(inode, orig_inode, "memfd {orig_inode} is still open at fd {raw}");
        }
    }

    #[test]
    fn write_value_through_socketpair_round_trip() {
        let (a, b) = pair();
        let fd = empty_memfd_0400();
        send_b04_descriptor(&a, &fd).expect("send descriptor");
        let received = scm_rights::recv_marker_descriptor(&b).expect("recv");
        // The destination-shape check runs against the owner — the
        // test process's own uid rather than the production root uid.
        memfd::validate_destination(&received, rustix::process::geteuid())
            .expect("destination shape");
        write_value_to_descriptor(received, b"credential-body\n").expect("write value");
        // The SCM_RIGHTS'd description shares the file offset the
        // broker-side write advanced — the helper seeks before read.
        rustix::fs::seek(&fd, rustix::fs::SeekFrom::Start(0)).expect("rewind");
        let mut file = std::fs::File::from(fd);
        let mut got = Vec::new();
        file.read_to_end(&mut got).expect("helper read");
        assert_eq!(got, b"credential-body\n");
    }

    #[test]
    fn write_value_strips_one_newline_then_appends_one() {
        let (a, b) = pair();
        let fd = empty_memfd_0400();
        send_b04_descriptor(&a, &fd).expect("send");
        let received = scm_rights::recv_marker_descriptor(&b).expect("recv");
        // `bytes.TrimSuffix(value, "\n")` removes exactly one suffix —
        // a value ending in two newlines keeps one of them before the
        // appended newline, yielding exactly two at the end.
        write_value_to_descriptor(received, b"pgpass-line\n\n").expect("write");
        rustix::fs::seek(&fd, rustix::fs::SeekFrom::Start(0)).expect("rewind");
        let mut file = std::fs::File::from(fd);
        let mut got = Vec::new();
        file.read_to_end(&mut got).expect("read");
        assert_eq!(got, b"pgpass-line\n\n");
    }

    #[test]
    fn transport_frames_round_trip() {
        let (mut a, mut b) = pair();
        write_transport_frame(&mut a, 0x03).expect("write frame");
        assert_eq!(read_transport_frame(&mut b).expect("read frame"), 0x03);
    }

    #[test]
    fn send_descriptor_writes_ack_then_token() {
        let (a, mut b) = pair();
        send_descriptor(&a, 0x01, b"opaque-token").expect("send descriptor");
        let mut buf = [0u8; 13];
        b.read_exact(&mut buf).expect("read frame");
        assert_eq!(&buf, b"\x01opaque-token");
    }

    /// The ACK frame's byte shape and the denial frame on descriptor
    /// refusal. The success branch needs a root-owned descriptor, so
    /// non-root runs exercise upstream's denial path instead — the
    /// refusal itself is the tested invariant there.
    #[test]
    fn default_transport_ack_and_denial() {
        let (a, b) = pair();
        let signing = std::sync::Arc::new(SigningService::new());
        let transport = DefaultTransport {
            signing: signing.clone(),
        };
        let req = HandoffRequest {
            binding_id: central_foundation::identity::SecretBindingId::new(),
            peer_uid: 0,
            peer_pid: 4242,
            operation_id: central_foundation::identity::OperationId::new(),
            receipt_id: central_foundation::identity::HandoffReceiptId::new(),
            receipt_hmac: String::new(),
            fencing_token: 1,
            purpose: central_infra::domain::Purpose::MinioRoot,
            service: "minio".to_owned(),
            target: "/run/secrets/minio-root-password".to_owned(),
            uid: 1000,
            gid: 1000,
        };
        let is_root = rustix::process::geteuid().as_raw() == 0;
        let helper = std::thread::spawn(move || {
            let fd = empty_memfd_0400();
            send_b04_descriptor(&b, &fd).expect("send fd");
            // Read the broker's reply frame: success → 7+proof bytes;
            // refusal → one 0x02 byte. Read the marker byte first.
            let mut marker = [0u8; 1];
            (&b).read_exact(&mut marker).expect("marker");
            let mut rest = Vec::new();
            if marker[0] == 0x01 {
                let mut hdr = [0u8; 6];
                (&b).read_exact(&mut hdr).expect("ack header");
                let len = u16::from_be_bytes([hdr[0], hdr[1]]) as usize;
                rest.extend_from_slice(&hdr);
                let mut proof = vec![0u8; len];
                (&b).read_exact(&mut proof).expect("proof");
                rest.extend_from_slice(&proof);
            }
            (fd, marker[0], rest)
        });
        let conn = crate::broker::deadline::DeadlineStream::new(
            a.into(),
            std::time::Duration::from_secs(60),
        )
        .expect("deadline stream");
        let result = transport.handle_materialize(&conn, &req, b"root-password");
        let (fd, marker, rest) = helper.join().expect("join");
        if is_root {
            result.expect("materialize succeeds as root");
            assert_eq!(marker, 0x01);
            // hdr[0..2] proof len, hdr[2..4] uid=1000, hdr[4..6]
            // gid=1000, then "b04-ok:<64-hex>".
            assert_eq!(&rest[2..4], &1000u16.to_be_bytes());
            assert_eq!(&rest[4..6], &1000u16.to_be_bytes());
            let proof_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            let proof = &rest[6..6 + proof_len];
            assert!(proof.starts_with(b"b04-ok:"));
            assert_eq!(proof.len(), "b04-ok:".len() + 64);
            rustix::fs::seek(&fd, rustix::fs::SeekFrom::Start(0)).expect("rewind");
            let mut file = std::fs::File::from(fd);
            let mut got = Vec::new();
            file.read_to_end(&mut got).expect("helper read");
            assert_eq!(got, b"root-password\n");
        } else {
            // Non-root test host: the root-ownership check refuses the
            // destination descriptor and the peer sees the 0x02 denial
            // frame. That IS the custody behavior being verified.
            result.unwrap_err();
            assert_eq!(marker, 0x02);
            drop(fd);
        }
    }
}
