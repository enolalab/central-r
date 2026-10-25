//! `SCM_RIGHTS` descriptor transfer — the primitive under upstream's
//! `sendB04Descriptor`/`sendB05Descriptor` (hand-off out),
//! `ReceiveDescriptor`/`SendDescriptor` (transports in/out), and
//! `extractSingleDescriptor` + `validateReceivedDescriptor` (the strict
//! inbound shapes).
//!
//! [`send`]/[`recv`] are the raw pair — arbitrary data plus up to
//! [`MAX_FDS`] descriptors in one `sendmsg`/`recvmsg`. [`recv_one`] and
//! [`recv_marker_descriptor`] are the broker's strict receivers: exactly
//! one `SCM_RIGHTS` message, exactly one descriptor, no other ancillary
//! data, no truncation — the `expected exactly 1 SCM_RIGHTS` and
//! `expected single descriptor` refusals upstream. Everything about the
//! checks is upstream-verbatim; the only difference is `Failure` codes.
//!
//! `SOCK_STREAM` callers hand the framing bytes with `data`; seqpacket
//! callers get the whole frame. `RECV_FLAGS` keeps `MSG_CMSG_CLOEXEC`
//! upstream's close-on-exec-by-default for received descriptors.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use central_foundation::failure::Failure;
use rustix::cmsg_space;
use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};

/// The largest descriptor set one control message may carry — upstream
/// only ever moves one, but the buffers admit four so a malicious
/// "extra descriptor" case is *received* (and then refused by
/// [`recv_one`]) instead of being silently `CTRUNC`'d into a different
/// error shape.
pub const MAX_FDS: usize = 4;

/// `RECV_FLAGS` — upstream `handoff_linux.go:48`: close-on-exec for
/// every descriptor the kernel hands us.
const RECV_FLAGS: RecvFlags = RecvFlags::CMSG_CLOEXEC;

/// The B04 materialize marker upstream's `validateReceivedDescriptor`
/// demands (`buf[0] != 0x01 → materialize FD marker mismatch`).
pub const TRANSPORT_MARKER: u8 = 0x01;

/// The outcome of one [`recv`].
pub struct Recv {
    /// Data bytes the message carried.
    pub bytes: usize,
    /// `msghdr.msg_flags` — check [`ReturnFlags::CTRUNC`].
    pub flags: ReturnFlags,
    /// Descriptors across every `SCM_RIGHTS` control message, in order.
    pub fds: Vec<OwnedFd>,
    /// Number of `SCM_RIGHTS` control messages the datagram carried.
    pub rights_msgs: usize,
    /// Number of non-rights control messages (`SCM_CREDENTIALS`, …).
    pub other_msgs: usize,
}

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("sys_scm_rights_denied", msg.into())
}

fn os_failure(step: &str, e: Errno) -> Failure {
    Failure::internal("sys_scm_rights_os", format!("{step}: {e}"))
}

fn invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("sys_scm_rights_invalid", msg.into())
}

/// `sendmsg` one byte-slice with `fds` in a single `SCM_RIGHTS`
/// control message — `sendB04Descriptor`'s `unix.Sendmsg`. Returns the
/// data bytes written; a short write is the caller's refusal, as
/// upstream.
///
/// # Errors
/// `sys_scm_rights_invalid` when `fds` is longer than [`MAX_FDS`];
/// `sys_scm_rights_os` on the `sendmsg` failure.
pub fn send<Fd: AsFd>(sock: Fd, data: &[u8], fds: &[BorrowedFd<'_>]) -> Result<usize, Failure> {
    if fds.len() > MAX_FDS {
        return Err(invalid(format!(
            "descriptor count {} exceeds MAX_FDS {}",
            fds.len(),
            MAX_FDS
        )));
    }
    let iov = [IoSlice::new(data)];
    let mut space = [MaybeUninit::<u8>::uninit(); cmsg_space!(ScmRights(MAX_FDS))];
    let mut ctl = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() && !ctl.push(SendAncillaryMessage::ScmRights(fds)) {
        return Err(invalid(
            "control buffer could not encode the descriptor set",
        ));
    }
    sendmsg(sock, &iov, &mut ctl, SendFlags::empty()).map_err(|e| os_failure("sendmsg", e))
}

/// `recvmsg` once into `data`, collecting every received descriptor —
/// `unix.Recvmsg` + `unix.ParseSocketControlMessage`.
///
/// The receiver decides strictness; [`recv_one`] enforces the broker's
/// inbound shape. A `CTRUNC` in `flags` means the kernel dropped part
/// of the control data — treat the message as untrusted.
///
/// # Errors
/// `sys_scm_rights_os` on the `recvmsg` failure (including `EAGAIN`
/// for the caller to map into a timeout retry policy).
pub fn recv<Fd: AsFd>(sock: Fd, data: &mut [u8]) -> Result<Recv, Failure> {
    let mut iov = [IoSliceMut::new(data)];
    // Room for the malformed shapes the strict checks refuse — a
    // too-small buffer would surface them as CTRUNC instead of the
    // named refusal upstream reports (`expected exactly one
    // SCM_RIGHTS` / `unexpected ancillary data`).
    let mut space = [MaybeUninit::<u8>::uninit();
        cmsg_space!(ScmRights(MAX_FDS), ScmRights(MAX_FDS), ScmCredentials(1))];
    let mut cmsg = RecvAncillaryBuffer::new(&mut space);
    let ret =
        recvmsg(sock, &mut iov, &mut cmsg, RECV_FLAGS).map_err(|e| os_failure("recvmsg", e))?;
    let mut fds = Vec::new();
    let mut rights_msgs = 0usize;
    let mut other_msgs = 0usize;
    for msg in cmsg.drain() {
        match msg {
            RecvAncillaryMessage::ScmRights(rights) => {
                rights_msgs += 1;
                fds.extend(rights);
            }
            _ => other_msgs += 1,
        }
    }
    Ok(Recv {
        bytes: ret.bytes,
        flags: ret.flags,
        fds,
        rights_msgs,
        other_msgs,
    })
}

/// `extractSingleDescriptor` + `validateReceivedDescriptor` — the strict
/// inbound shape: the data frame read into `data`, no truncation, no
/// non-rights ancillary data, exactly one `SCM_RIGHTS` message with
/// exactly one descriptor.
///
/// Returns `(bytes, fd)` — the caller owns the frame's payload framing
/// (marker check, JSON decode, …); [`recv_marker_descriptor`] is the
/// B04-shaped specialization.
///
/// # Errors
/// `sys_scm_rights_denied` for every malformed shape upstream refuses;
/// `sys_scm_rights_os` when `recvmsg` itself fails.
pub fn recv_one<Fd: AsFd>(sock: Fd, data: &mut [u8]) -> Result<(usize, OwnedFd), Failure> {
    let r = recv(sock, data)?;
    if r.flags.intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC) {
        return Err(denied("truncated ancillary data or oversized data frame"));
    }
    if r.other_msgs != 0 {
        return Err(denied(format!(
            "unexpected ancillary data ({} non-rights messages)",
            r.other_msgs
        )));
    }
    if r.rights_msgs != 1 {
        return Err(denied(format!(
            "expected exactly one SCM_RIGHTS control message (got {})",
            r.rights_msgs
        )));
    }
    if r.fds.len() != 1 {
        return Err(denied(format!(
            "expected single descriptor over protected socket (got {})",
            r.fds.len()
        )));
    }
    match r.fds.into_iter().next() {
        Some(fd) => Ok((r.bytes, fd)),
        // The `len() != 1` check above makes this unreachable; keep the
        // shape total anyway.
        None => Err(denied("expected single descriptor over protected socket")),
    }
}

/// `ReceiveDescriptor`'s marker gate — one `[TRANSPORT_MARKER]` byte
/// and one descriptor. Upstream rejects when the frame is not exactly
/// `0x01`.
///
/// # Errors
/// The [`recv_one`] refusals plus `sys_scm_rights_denied` when the
/// single data byte is not [`TRANSPORT_MARKER`].
pub fn recv_marker_descriptor<Fd: AsFd>(sock: Fd) -> Result<OwnedFd, Failure> {
    let mut data = [0u8; 1];
    let (bytes, fd) = recv_one(sock, &mut data)?;
    if bytes != 1 || data[0] != TRANSPORT_MARKER {
        return Err(denied("materialize FD marker mismatch"));
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use rustix::net::{AddressFamily, SocketFlags, SocketType, UCred, socketpair};

    use crate::sys::memfd;

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair")
    }

    /// The B04 round trip: a sealed handoff descriptor over a
    /// socketpair, strict-validated on receipt, value intact.
    #[test]
    fn send_recv_round_trip() {
        let (a, b) = pair();
        let value = b"broker-secret";
        let handoff = memfd::create_sealed("central-test", value).expect("handoff memfd");
        let sent = send(&a, &[TRANSPORT_MARKER], &[handoff.as_fd()]).expect("sendmsg");
        assert_eq!(sent, 1);

        let fd = recv_marker_descriptor(&b).expect("recv marker+fd");
        memfd::validate_sealed(&fd, rustix::process::geteuid()).expect("sealed shape");
        let mut buf = Vec::new();
        std::fs::File::from(fd).read_to_end(&mut buf).expect("read");
        assert_eq!(buf, value);
    }

    /// Two descriptors in one SCM_RIGHTS message — `extractSingleFd`'s
    /// `expected single descriptor`.
    #[test]
    fn recv_one_rejects_extra_fd() {
        let (a, b) = pair();
        let f1 = memfd::create_sealed("t", b"x").expect("fd1");
        let f2 = memfd::create_sealed("t", b"y").expect("fd2");
        send(&a, &[TRANSPORT_MARKER], &[f1.as_fd(), f2.as_fd()]).expect("sendmsg");
        let mut data = [0u8; 8];
        let err = recv_one(&b, &mut data).unwrap_err();
        assert_eq!(err.code(), "sys_scm_rights_denied");
        assert!(err.message().contains("single descriptor"));
    }

    /// Two separate SCM_RIGHTS messages of one fd each — upstream's
    /// `expected exactly one SCM_RIGHTS control message` (scms != 1).
    /// The kernel is free to coalesce consecutive rights cmsgs into
    /// one; when it does, the same malformed shape lands on the
    /// `nFDs != 1` refusal instead. Either named refusal holds the
    /// invariant — two descriptors are never admitted.
    #[test]
    fn recv_one_rejects_two_rights_messages() {
        let (a, b) = pair();
        let f1 = memfd::create_sealed("t", b"x").expect("fd1");
        let f2 = memfd::create_sealed("t", b"y").expect("fd2");
        let iov = [IoSlice::new(&[TRANSPORT_MARKER])];
        let mut space = [MaybeUninit::<u8>::uninit(); cmsg_space!(ScmRights(1), ScmRights(1))];
        let mut ctl = SendAncillaryBuffer::new(&mut space);
        let r1 = [f1.as_fd()];
        let r2 = [f2.as_fd()];
        assert!(ctl.push(SendAncillaryMessage::ScmRights(&r1)));
        assert!(ctl.push(SendAncillaryMessage::ScmRights(&r2)));
        sendmsg(&a, &iov, &mut ctl, SendFlags::empty()).expect("sendmsg");
        let mut data = [0u8; 8];
        let err = recv_one(&b, &mut data).unwrap_err();
        assert_eq!(err.code(), "sys_scm_rights_denied");
        assert!(
            err.message().contains("exactly one SCM_RIGHTS")
                || err.message().contains("single descriptor"),
            "want a strict-shape refusal, got: {}",
            err.message()
        );
    }

    /// A non-rights control message — `SCM_CREDENTIALS` — beside the
    /// descriptor is upstream's `unexpected ancillary data`.
    #[test]
    fn recv_one_rejects_unexpected_cmsg() {
        let (a, b) = pair();
        // The peer must ask for credentials; the kernel then appends a
        // SCM_CREDENTIALS cmsg to the datagram.
        rustix::net::sockopt::set_socket_passcred(&b, true).expect("SO_PASSCRED");
        let f = memfd::create_sealed("t", b"x").expect("fd");
        let iov = [IoSlice::new(&[TRANSPORT_MARKER])];
        let mut space = [MaybeUninit::<u8>::uninit(); cmsg_space!(ScmRights(1), ScmCredentials(1))];
        let mut ctl = SendAncillaryBuffer::new(&mut space);
        let rights = [f.as_fd()];
        assert!(ctl.push(SendAncillaryMessage::ScmRights(&rights)));
        assert!(ctl.push(SendAncillaryMessage::ScmCredentials(UCred {
            pid: rustix::process::getpid(),
            uid: rustix::process::geteuid(),
            gid: rustix::process::getegid(),
        })));
        sendmsg(&a, &iov, &mut ctl, SendFlags::empty()).expect("sendmsg");
        let mut data = [0u8; 8];
        let err = recv_one(&b, &mut data).unwrap_err();
        assert!(err.message().contains("unexpected ancillary data"));
    }

    /// No descriptor at all — `validateReceivedDescriptor`'s `no
    /// descriptors` / `nFDs != 1` shape.
    #[test]
    fn recv_one_rejects_no_fd() {
        let (a, b) = pair();
        send(&a, &[TRANSPORT_MARKER], &[]).expect("sendmsg");
        let mut data = [0u8; 8];
        let err = recv_one(&b, &mut data).unwrap_err();
        assert!(err.message().contains("exactly one SCM_RIGHTS"));
    }

    /// The marker byte is the B04 transport's frame check — a wrong
    /// byte is `materialize FD marker mismatch`.
    #[test]
    fn recv_marker_descriptor_rejects_bad_marker() {
        let (a, b) = pair();
        let f = memfd::create_sealed("t", b"x").expect("fd");
        send(&a, &[0x7f], &[f.as_fd()]).expect("sendmsg");
        let err = recv_marker_descriptor(&b).unwrap_err();
        assert!(err.message().contains("marker mismatch"));
    }

    /// A frame longer than the receive buffer sets `MSG_TRUNC` on a
    /// seqpacket pair — `recv_one` refuses truncation outright.
    #[test]
    fn recv_one_rejects_truncated_frame() {
        let (a, b) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("seqpacket pair");
        let f = memfd::create_sealed("t", b"x").expect("fd");
        send(&a, &[0u8; 32], &[f.as_fd()]).expect("sendmsg");
        let mut data = [0u8; 4];
        let err = recv_one(&b, &mut data).unwrap_err();
        assert!(err.message().contains("truncated"));
    }

    /// Received descriptors land with close-on-exec — the upstream
    /// `MSG_CMSG_CLOEXEC` flag.
    #[test]
    fn received_fd_is_cloexec() {
        let (a, b) = pair();
        let f = memfd::create_sealed("t", b"x").expect("fd");
        send(&a, &[TRANSPORT_MARKER], &[f.as_fd()]).expect("sendmsg");
        let mut data = [0u8; 8];
        let (_, fd) = recv_one(&b, &mut data).expect("recv_one");
        let flags = rustix::io::fcntl_getfd(&fd).expect("F_GETFD");
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }
}
