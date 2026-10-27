//! `cbl-test-worker` — the test-only stand-in for `central-backup`
//! (upstream `test_worker.c`, built only with the `test-build`
//! feature). It verifies the fixed launch contract — argv[0], the
//! three-element environment, FD3 evidence read, FD4 the repository
//! directory, FD5 a `SOCK_SEQPACKET` handoff, nothing above FD6 —
//! then optionally hands a target-lock socket over FD5 (`CBW1`).
//!
//! Repository flag files steer the fixture, exactly like upstream:
//! `fail`/`probe-fail` exit 9, `hang`/`probe-hang` block forever,
//! `missing-handoff` closes FD5 (exit 40), `wrong-type` sends a
//! `SOCK_STREAM` socket, `wrong-endpoint` connects to port 55433,
//! `zero-proof` sends a nil digest, `malformed` sends a 39-byte
//! frame. The C binary takes `*_OUTPUT_PATH` build defines; this
//! worker's environment is pinned to the launcher's fixed three
//! entries, so its observability outputs are repo-relative files
//! instead (`out-evidence`, `out-operation`, `out-mode`,
//! `out-proof`, `out-descendant`, `out-descendant-ready`) — same
//! verification, no extra environment.

use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::process::ExitCode;

#[allow(dead_code)]
mod sys;

const RETAINED_PORT: u16 = 55432;
const WRONG_PORT: u16 = 55433;

/// The repo-relative observability files (upstream's `*_OUTPUT_PATH`
/// defines, fixed here because the worker env is pinned).
const OUT_EVIDENCE: &str = "out-evidence";
const OUT_OPERATION: &str = "out-operation";
const OUT_MODE: &str = "out-mode";
const OUT_PROOF: &str = "out-proof";
const OUT_DESCENDANT: &str = "out-descendant";
const OUT_DESCENDANT_READY: &str = "out-descendant-ready";

fn write_all(fd: RawFd, bytes: &[u8]) -> Result<(), ()> {
    let borrowed = sys::borrow(fd);
    let mut written = 0usize;
    while written < bytes.len() {
        match rustix::io::write(borrowed, &bytes[written..]) {
            Ok(0) => return Err(()),
            Ok(n) => written += n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// `write_file` — `openat(4, name, O_WRONLY|O_CREAT|O_TRUNC, 0600)`.
fn write_repo_file(name: &str, bytes: &[u8]) -> Result<(), ()> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::openat(
        sys::borrow(4),
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| ())?;
    write_all(fd.as_raw_fd(), bytes)?;
    drop(fd);
    Ok(())
}

/// `repository_flag` — flag file presence inside the repository dir.
fn repository_flag(name: &str) -> bool {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::openat(
        sys::borrow(4),
        name,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .is_ok()
}

/// `connected_target` — a `SOCK_STREAM` to `127.0.0.1:port`.
fn connected_target(port: u16) -> Result<std::os::fd::OwnedFd, ()> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    let fd = rustix::net::socket_with(
        AddressFamily::INET,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| ())?;
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port);
    rustix::net::connect(&fd, &addr).map_err(|_| ())?;
    Ok(fd)
}

/// `handoff_target_lock` — the `CBW1` offer + acknowledgement check.
/// Returns the upstream exit-code number on failure.
fn handoff_target_lock(probe: bool) -> i32 {
    use std::io::IoSlice;
    use std::mem::MaybeUninit;

    use rustix::net::{RecvFlags, SendAncillaryMessage, SendFlags, sendmsg};

    if repository_flag("missing-handoff") {
        sys::close(5);
        return 40;
    }
    let mut wrong_other: Option<std::os::fd::OwnedFd> = None;
    let target = if repository_flag("wrong-type") {
        match rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        ) {
            Ok((a, b)) => {
                wrong_other = Some(b);
                a
            }
            Err(_) => return 41,
        }
    } else {
        let port = if repository_flag("wrong-endpoint") {
            WRONG_PORT
        } else {
            RETAINED_PORT
        };
        match connected_target(port) {
            Ok(fd) => fd,
            Err(()) => return 42,
        }
    };
    let mut frame = [0u8; 40];
    frame[0..4].copy_from_slice(b"CBW1");
    frame[4] = 1;
    frame[5] = 1;
    for (i, v) in frame[8..40].iter_mut().enumerate() {
        *v = (i as u8).wrapping_add(if probe { 33 } else { 1 });
    }
    if repository_flag("zero-proof") {
        frame[8..40].fill(0);
    }
    let len = if repository_flag("malformed") { 39 } else { 40 };
    let iov = [IoSlice::new(&frame[..len])];
    let fds = [target.as_fd()];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return 43;
    }
    let handoff = sys::borrow(5);
    match sendmsg(handoff, &iov, &mut control, SendFlags::NOSIGNAL) {
        Ok(n) if n == len => {}
        _ => return 43,
    }
    drop(target);
    drop(wrong_other);
    let mut ack = [0u8; 40];
    let bytes = match rustix::net::recv(handoff, &mut ack, RecvFlags::empty()) {
        Ok((n, _)) => n,
        Err(_) => return 44,
    };
    if bytes != 40 || ack[0..4] != *b"CBW1" || ack[4] != 1 || ack[5] != 2 || ack[7] != 0 {
        return 44;
    }
    if ack[6] != 0 {
        return 45;
    }
    if ack[8..40] != frame[8..40] {
        return 46;
    }
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&ack[8..40]);
    if write_repo_file(OUT_PROOF, &proof).is_err() {
        return 47;
    }
    0
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let create = args.len() == 3 && args[1] == "create";
    let probe = args.len() == 3 && args[1] == "throughput-probe";
    if args.len() != 3 || args[0] != "central-backup" || (!create && !probe) || args[2].len() != 36
    {
        return 20;
    }
    let envs: Vec<(String, String)> = std::env::vars().collect();
    let get = |k: &str| envs.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
    if get("PATH") != Some("/usr/sbin:/usr/bin:/sbin:/bin")
        || get("LANG") != Some("C")
        || get("LC_ALL") != Some("C")
    {
        return 21;
    }
    if envs.len() != 3 {
        return 22;
    }
    // The CLOEXEC bit must be set immediately so descendants never
    // inherit the handoff (upstream's F_GETFD|F_SETFD pair).
    let handoff = sys::borrow(5);
    let flags = match rustix::io::fcntl_getfd(handoff) {
        Ok(f) => f,
        Err(_) => return 23,
    };
    if rustix::io::fcntl_setfd(handoff, flags | rustix::io::FdFlags::CLOEXEC).is_err() {
        return 23;
    }
    match rustix::net::sockopt::socket_type(handoff) {
        Ok(rustix::net::SocketType::SEQPACKET) => {}
        _ => return 23,
    }
    for fd in 6..128i32 {
        if rustix::io::fcntl_getfd(sys::borrow(fd)).is_ok() {
            return 23;
        }
    }
    let repo = sys::borrow(4);
    match rustix::fs::fstat(repo) {
        Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
        _ => return 24,
    }
    let evid = sys::borrow(3);
    let mut evidence = [0u8; 16];
    let mut total = 0usize;
    while total < 16 {
        match rustix::io::read(evid, &mut evidence[total..]) {
            Ok(0) => return 25,
            Ok(n) => total += n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return 25,
        }
    }
    let mut extra = [0u8; 1];
    match rustix::io::read(evid, &mut extra) {
        Ok(0) => {}
        _ => return 26,
    }
    if write_repo_file(OUT_EVIDENCE, &evidence).is_err() {
        return 27;
    }
    if write_repo_file(OUT_OPERATION, args[2].as_bytes()).is_err() {
        return 28;
    }
    if write_repo_file(OUT_MODE, args[1].as_bytes()).is_err() {
        return 35;
    }
    let marker_name = if create {
        "worker-marker"
    } else {
        "probe-marker"
    };
    {
        use rustix::fs::{Mode, OFlags};
        let marker = match rustix::fs::openat(
            repo,
            marker_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(f) => f,
            Err(_) => return 29,
        };
        if write_all(marker.as_raw_fd(), b"created").is_err() {
            return 29;
        }
    }
    if repository_flag(if create { "fail" } else { "probe-fail" }) {
        return 9;
    }
    if repository_flag(if create { "hang" } else { "probe-hang" }) {
        loop {
            sys::pause();
        }
    }
    let descendant = match sys::fork() {
        Ok(sys::Fork::Parent(p)) => p,
        Ok(sys::Fork::Child) => {
            if sys::setsid().is_err() {
                sys::exit(32);
            }
            if write_repo_file(OUT_DESCENDANT_READY, b"ready").is_err() {
                sys::exit(33);
            }
            loop {
                sys::pause();
            }
        }
        Err(_) => return 30,
    };
    // Upstream's `DESCENDANT_READY_PATH` poll — now a repo-relative
    // flag file.
    let mut ready = false;
    for _ in 0..100 {
        if repository_flag(OUT_DESCENDANT_READY) {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if !ready {
        return 34;
    }
    let text = format!("{descendant}");
    if write_repo_file(OUT_DESCENDANT, text.as_bytes()).is_err() {
        return 31;
    }
    handoff_target_lock(probe)
}

fn main() -> ExitCode {
    ExitCode::from(run() as u8)
}
