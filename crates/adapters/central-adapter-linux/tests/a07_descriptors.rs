//! A07 — descriptor smuggling denials (threat T17/T20, upstream
//! `extractSingleDescriptor`/`validateReceivedDescriptor`,
//! `memfd_linux.go`, `pidfd` checks).
//!
//! Every malformed `SCM_RIGHTS` shape the B04/B10 descriptor plane
//! refuses, the sealed-memfd shape checks, the marker byte, and the
//! pidfd kind check — exercised over real `socketpair(2)` ancillary
//! data plus the `Recv` shape gate for the flags a socket cannot be
//! made to produce on demand (`CTRUNC`, a second rights cmsg).

// `allow-*-in-tests` only reaches `#[test]` fns — the fixture helpers
// in this binary unwrap/expect deliberately: an unbuildable fixture
// is the failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod a07;

use a07::*;
use central_adapter_linux::sys::{memfd, scm_rights};
use central_foundation::failure::FailureKind;
use rustix::cmsg_space;
use rustix::fd::AsFd;
use rustix::net::{
    AddressFamily, ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage, SocketFlags, SocketType,
    socketpair,
};
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd};

fn pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("socketpair")
}

/// `SOCK_SEQPACKET` — the production transport; packet boundaries are
/// what make a short read surface `MSG_TRUNC` at all (a stream socket
/// just leaves the rest queued).
fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
    socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("seqpacket socketpair")
}

fn deny_msg(err: &central_foundation::failure::Failure) -> String {
    assert_eq!(err.code(), "sys_scm_rights_denied");
    assert_eq!(err.kind(), FailureKind::Denied);
    err.message().to_owned()
}

/// Two descriptors in one `SCM_RIGHTS` — the exact smuggle upstream's
/// `expected single descriptor` check exists for.
#[test]
fn scm_rights_extra_descriptor_denied() {
    let (a, b) = pair();
    let mem = memfd::create_sealed("a07", b"payload").expect("sealed memfd");
    let mem2 = memfd::create_sealed("a07b", b"payload").expect("sealed memfd");
    scm_rights::send(
        &a,
        &[scm_rights::TRANSPORT_MARKER],
        &[mem.as_fd(), mem2.as_fd()],
    )
    .expect("send");
    let mut data = [0u8; 4];
    let err = scm_rights::recv_one(&b, &mut data).unwrap_err();
    assert_eq!(
        deny_msg(&err),
        "expected single descriptor over protected socket (got 2)"
    );
}

/// A plain byte with no ancillary data at all — `rights_msgs == 0` —
/// is refused by the same closed message.
#[test]
fn scm_rights_missing_rights_cmsg_denied() {
    let (a, b) = pair();
    std::os::unix::net::UnixStream::from(a)
        .write_all(&[scm_rights::TRANSPORT_MARKER])
        .expect("write byte");
    let mut data = [0u8; 4];
    let err = scm_rights::recv_one(&b, &mut data).unwrap_err();
    assert_eq!(
        deny_msg(&err),
        "expected exactly one SCM_RIGHTS control message (got 0)"
    );
}

/// A non-rights control message (`SCM_CREDENTIALS`) riding beside the
/// rights message is refused as `unexpected ancillary data` — a
/// credential cmsg is not a descriptor. The kernel only delivers an
/// explicit credentials cmsg when the receiver opted in with
/// `SO_PASSCRED`, so the receiver enables it for the smuggle to land.
#[test]
fn scm_rights_non_rights_cmsg_denied() {
    let (a, b) = pair();
    rustix::net::sockopt::set_socket_passcred(&b, true).expect("passcred");
    let mem = memfd::create_sealed("a07", b"payload").expect("sealed memfd");
    // Send one datagram carrying both SCM_RIGHTS and SCM_CREDENTIALS.
    let mut space = [MaybeUninit::<u8>::uninit(); cmsg_space!(ScmRights(1), ScmCredentials(1))];
    let mut buf = SendAncillaryBuffer::new(&mut space);
    let cred = rustix::net::UCred {
        pid: rustix::process::getpid(),
        uid: rustix::process::geteuid(),
        gid: rustix::process::getegid(),
    };
    assert!(buf.push(SendAncillaryMessage::ScmCredentials(cred)));
    let rights = [mem.as_fd()];
    assert!(buf.push(SendAncillaryMessage::ScmRights(&rights)));
    rustix::net::sendmsg(
        &a,
        &[std::io::IoSlice::new(&[scm_rights::TRANSPORT_MARKER])],
        &mut buf,
        rustix::net::SendFlags::empty(),
    )
    .expect("sendmsg");
    let mut data = [0u8; 4];
    let err = scm_rights::recv_one(&b, &mut data).unwrap_err();
    assert_eq!(
        deny_msg(&err),
        "unexpected ancillary data (1 non-rights messages)"
    );
}

/// An oversized data frame truncates: `MSG_TRUNC` on receive refuses
/// before any descriptor is looked at.
#[test]
fn scm_rights_truncated_data_denied() {
    let (a, b) = seqpacket_pair();
    let mem = memfd::create_sealed("a07", b"payload").expect("sealed memfd");
    scm_rights::send(&a, &[scm_rights::TRANSPORT_MARKER; 8], &[mem.as_fd()]).expect("send");
    let mut data = [0u8; 2]; // smaller than the 8-byte message → TRUNC
    let err = scm_rights::recv_one(&b, &mut data).unwrap_err();
    assert_eq!(
        deny_msg(&err),
        "truncated ancillary data or oversized data frame"
    );
}

/// `validate_one` over a fabricated `Recv` — the two shapes a socket
/// cannot be driven to produce on demand (a second rights cmsg, and
/// the CTRUNC flag the kernel sets when ancillary space runs out).
#[test]
fn scm_rights_shape_gate_denies_fabricated_shapes() {
    let mem = memfd::create_sealed("a07", b"payload").expect("sealed memfd");
    // Two SCM_RIGHTS cmsgs.
    let r = scm_rights::Recv {
        bytes: 1,
        flags: ReturnFlags::empty(),
        fds: vec![mem.as_fd().try_clone_to_owned().unwrap()],
        rights_msgs: 2,
        other_msgs: 0,
    };
    let err = scm_rights::validate_one(r).unwrap_err();
    assert_eq!(
        deny_msg(&err),
        "expected exactly one SCM_RIGHTS control message (got 2)"
    );
    // CTRUNC — the kernel dropped part of the rights data.
    let r = scm_rights::Recv {
        bytes: 1,
        flags: ReturnFlags::CTRUNC,
        fds: Vec::new(),
        rights_msgs: 1,
        other_msgs: 0,
    };
    let err = scm_rights::validate_one(r).unwrap_err();
    assert_eq!(
        deny_msg(&err),
        "truncated ancillary data or oversized data frame"
    );
}

/// The transport marker is the one byte `0x01`; anything else is the
/// exact `materialize FD marker mismatch` refusal.
#[test]
fn scm_rights_marker_mismatch_denied() {
    let (a, b) = pair();
    let mem = memfd::create_sealed("a07", b"payload").expect("sealed memfd");
    scm_rights::send(&a, &[0x00], &[mem.as_fd()]).expect("send");
    let err = scm_rights::recv_marker_descriptor(&b).unwrap_err();
    assert_eq!(deny_msg(&err), "materialize FD marker mismatch");

    // The right marker round-trips: one byte, one descriptor.
    let (a, b) = pair();
    scm_rights::send(&a, &[scm_rights::TRANSPORT_MARKER], &[mem.as_fd()]).expect("send");
    let fd = scm_rights::recv_marker_descriptor(&b).expect("descriptor");
    assert!(fd.as_raw_fd() >= 0);
}

// ---------------------------------------------------------------------------
// Sealed memfd — the payload descriptor's shape is authority
// ---------------------------------------------------------------------------

/// An unsealed memfd is refused: `F_SEAL_WRITE` is the proof the
/// provisioning payload can no longer be mutated.
#[test]
fn memfd_unsealed_descriptor_denied() {
    let fd = rustix::fs::memfd_create("a07-open", rustix::fs::MemfdFlags::empty())
        .expect("memfd_create");
    rustix::io::write(&fd, b"payload").expect("fill memfd");
    let err = memfd::validate_sealed(&fd, rustix::process::Uid::from_raw(euid())).unwrap_err();
    assert_denial(
        &err,
        FailureKind::Denied,
        "sys_memfd_denied",
        "write-sealed",
    );

    // A partial seal set is not the contract: `SHRINK` without
    // `WRITE` still lets the payload's bytes be rewritten.
    // `ALLOW_SEALING` — without it `F_ADD_SEALS` itself is EPERM.
    let fd = rustix::fs::memfd_create("a07-partial", rustix::fs::MemfdFlags::ALLOW_SEALING)
        .expect("memfd_create");
    rustix::io::write(&fd, b"payload").expect("fill memfd");
    rustix::fs::fcntl_add_seals(&fd, rustix::fs::SealFlags::SHRINK).expect("add seal");
    let err = memfd::validate_sealed(&fd, rustix::process::Uid::from_raw(euid())).unwrap_err();
    assert_eq!(err.message(), "fd is not write-sealed");
}

/// A descriptor owned by a different uid is refused — the memfd must
/// belong to the identity that provisioned it.
#[test]
fn memfd_wrong_owner_denied() {
    let fd = memfd::create_sealed("a07", b"payload").expect("sealed memfd");
    let err = memfd::validate_sealed(&fd, rustix::process::Uid::from_raw(euid() + 1)).unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sys_memfd_denied", "");
}

/// A regular file is not a memfd — the fs-type check refuses it.
#[test]
fn memfd_regular_file_denied() {
    let scratch = Scratch::new("memfd-file");
    let path = scratch.file("plain.bin", b"payload", 0o600);
    let fd = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .expect("open");
    let err = memfd::validate_sealed(&fd, rustix::process::Uid::from_raw(euid())).unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sys_memfd_denied", "");
}

/// The sealed descriptor must carry a non-empty payload within
/// `MAX_VALUE_BYTES` — both bounds refuse before any descriptor is
/// created.
#[test]
fn memfd_create_bounds_refuse() {
    for value in [
        b"".as_slice(),
        vec![0u8; (memfd::MAX_VALUE_BYTES + 1) as usize].as_slice(),
    ] {
        let err = memfd::create_sealed("a07", value).unwrap_err();
        assert_eq!(err.code(), "sys_memfd_invalid");
    }
}

/// The destination the payload lands in must be an empty, owner-only
/// `0400` file — anything else is refused before a byte is written.
#[test]
fn memfd_destination_shape_denied() {
    let scratch = Scratch::new("memfd-dst");
    let owner = rustix::process::Uid::from_raw(euid());
    // Non-empty destination.
    let p = scratch.file("dst-nonempty", b"existing", 0o400);
    let fd = rustix::fs::open(
        &p,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .expect("open");
    let err = memfd::validate_destination(&fd, owner).unwrap_err();
    assert_eq!(err.code(), "sys_memfd_denied");
    assert!(err.message().contains("not empty"), "{}", err.message());
    // Wrong mode (group-readable).
    let p = scratch.file("dst-mode", b"", 0o440);
    let fd = rustix::fs::open(
        &p,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .expect("open");
    let err = memfd::validate_destination(&fd, owner).unwrap_err();
    assert_denial(&err, FailureKind::Denied, "sys_memfd_denied", "");
}

// ---------------------------------------------------------------------------
// pidfd — a descriptor handle must name a process, not a file
// ---------------------------------------------------------------------------

/// `is_pidfd` refuses a regular-file descriptor with
/// `sys_pidfd_invalid`; a real pidfd on this process passes and
/// reports alive.
#[test]
fn pidfd_kind_and_liveness() {
    let scratch = Scratch::new("pidfd");
    let p = scratch.file("plain", b"x", 0o600);
    let fd = rustix::fs::open(
        &p,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .expect("open");
    let err = central_adapter_linux::sys::pidfd::is_pidfd(&fd).unwrap_err();
    assert_eq!(err.code(), "sys_pidfd_invalid");
    assert!(err.message().contains("not a pidfd"), "{}", err.message());

    let pidfd = central_adapter_linux::sys::pidfd::open(rustix::process::getpid()).expect("pidfd");
    central_adapter_linux::sys::pidfd::is_pidfd(&pidfd).expect("is pidfd");
    assert!(central_adapter_linux::sys::pidfd::alive(&pidfd).expect("alive"));
}
