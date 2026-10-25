//! `SO_PEERCRED` — upstream `handoff_linux.go`'s `verifyPeer`
//! (`getsockopt` → `pid`/`uid`/`gid`, then the expected-uid check the
//! handoff broker runs before trusting a descriptor's provenance).
//!
//! [`PeerCred::verify_uid`] is the `cred.Uid != peerUID` refusal;
//! [`PeerCred::verify_pid`] is the `cred.Pid != peerPID` form the
//! session-registry call sites use (upstream
//! `daemon_peercred_linux.go` / `dispatch_peercred_linux.go`).

use std::os::fd::AsFd;

use central_foundation::failure::Failure;
use rustix::io::Errno;
use rustix::net::sockopt::socket_peercred;
use rustix::process::{Gid, Pid, Uid};

/// The kernel-attested `SO_PEERCRED` triple for a connected AF_UNIX
/// socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    /// The peer's process id at connect time.
    pub pid: Pid,
    /// The peer's effective uid at connect time.
    pub uid: Uid,
    /// The peer's effective gid at connect time.
    pub gid: Gid,
}

impl PeerCred {
    /// `cred.Uid != peerUID → permission denied` — the handoff
    /// broker's peer check.
    ///
    /// # Errors
    /// `sys_peercred_denied` when the peer uid is not `expected`.
    pub fn verify_uid(self, expected: Uid) -> Result<(), Failure> {
        if self.uid != expected {
            return Err(Failure::denied(
                "sys_peercred_denied",
                format!("peer credential uid {} mismatch", self.uid.as_raw()),
            ));
        }
        Ok(())
    }

    /// The `cred.Pid != peerPID` form — the session-registry peer
    /// check.
    ///
    /// # Errors
    /// `sys_peercred_denied` when the peer pid is not `expected`.
    pub fn verify_pid(self, expected: Pid) -> Result<(), Failure> {
        if self.pid != expected {
            return Err(Failure::denied(
                "sys_peercred_denied",
                format!("peer credential pid {} mismatch", self.pid.as_raw_pid()),
            ));
        }
        Ok(())
    }
}

fn os_failure(step: &str, e: Errno) -> Failure {
    Failure::internal("sys_peercred_os", format!("{step}: {e}"))
}

/// `getsockopt(SO_PEERCRED)` on a connected AF_UNIX socket.
///
/// # Errors
/// `sys_peercred_os` when the socket is not connected or the
/// `getsockopt` fails.
pub fn peercred<Fd: AsFd>(sock: Fd) -> Result<PeerCred, Failure> {
    let cred = socket_peercred(sock).map_err(|e| os_failure("getsockopt(SO_PEERCRED)", e))?;
    Ok(PeerCred {
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// `verifyPeer` — `peercred` plus the expected-uid refusal.
///
/// # Errors
/// `sys_peercred_denied` when the peer is not `expected_uid`;
/// `sys_peercred_os` on the `getsockopt` failure.
pub fn verify_peer<Fd: AsFd>(sock: Fd, expected_uid: Uid) -> Result<PeerCred, Failure> {
    let cred = peercred(sock)?;
    cred.verify_uid(expected_uid)?;
    Ok(cred)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::OwnedFd;

    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair")
    }

    /// `verifyPeer` sees this process's own credentials on the other
    /// end of a self-connected pair — pid/uid/gid all attested.
    #[test]
    fn peercred_reports_self() {
        let (a, b) = pair();
        let cred = peercred(&a).expect("peercred");
        assert_eq!(cred.pid, rustix::process::getpid());
        assert_eq!(cred.uid, rustix::process::geteuid());
        assert_eq!(cred.gid, rustix::process::getegid());
        let _ = b;
    }

    /// The expected-uid check passes for the real peer and refuses a
    /// different uid — upstream's `peer credential mismatch`.
    #[test]
    fn verify_peer_uid() {
        let (a, _b) = pair();
        verify_peer(&a, rustix::process::geteuid()).expect("self uid");

        let other = if rustix::process::geteuid().is_root() {
            Uid::from_raw(1)
        } else {
            Uid::ROOT
        };
        let err = verify_peer(&a, other).unwrap_err();
        assert_eq!(err.code(), "sys_peercred_denied");
        assert!(err.message().contains("uid"));
    }

    /// The pid form refuses a pid the peer is not.
    #[test]
    fn verify_peer_pid() {
        let (a, _b) = pair();
        let cred = peercred(&a).expect("peercred");
        cred.verify_pid(rustix::process::getpid())
            .expect("self pid");
        let err = cred
            .verify_pid(rustix::process::Pid::from_raw(1).expect("pid 1"))
            .unwrap_err();
        assert!(err.message().contains("pid"));
    }
}
