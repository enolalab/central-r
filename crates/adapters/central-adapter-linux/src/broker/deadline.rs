//! `conn.SetDeadline(now + CONNECTION_DEADLINE)` — upstream's
//! one-second absolute deadline over the framed exchange, realized on
//! allow-listed syscalls only.
//!
//! Upstream's deadline is a property of Go's netpoller: the runtime
//! arms a timer and the `epoll` wait returns when either the fd is
//! ready or the deadline fires — `epoll` is already on the broker's
//! seccomp allow-list. The first naive port reached for
//! `SO_RCVTIMEO`/`SO_SNDTIMEO` (`setsockopt`, 54 — not listed),
//! `UnixStream`'s `set_nonblocking` (`ioctl(FIONBIO)`, 16 — not
//! listed), and `recvfrom`/`sendto` (45/44 — not listed), so a
//! hardened broker died with `SIGSYS` at its first connection.
//!
//! [`DeadlineStream`] carries the same observable contract on
//! primitives the filter already admits (ADR 0044): `fcntl(F_SETFL,
//! O_NONBLOCK)` (72), plain `read`/`write`/`recvmsg` (0/1/47), and a
//! bounded `nanosleep` cadence — the same cadence `serve`'s own
//! nonblocking accept loop already uses. `EAGAIN`/`EINTR` retry until
//! `Instant` crosses `deadline`; `TimedOut` is the refusal upstream's
//! deadline produces.

use std::io::{Error, ErrorKind, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;

/// The `EAGAIN` retry cadence — 1 ms keeps the 1 s deadline accurate
/// to ~0.1 % while a silent peer costs at most a thousand cheap
/// `nanosleep`s.
const RETRY_WAIT: Duration = Duration::from_millis(1);

/// A stream socket's owned fd plus the absolute instant past which
/// any read or write refuses with `TimedOut`. `O_NONBLOCK` is set at
/// construction (`fcntl`, not `ioctl`); every IO op retries `EAGAIN`
/// at [`RETRY_WAIT`] until `deadline`.
pub(crate) struct DeadlineStream {
    fd: OwnedFd,
    deadline: Instant,
}

impl DeadlineStream {
    /// Take `fd` nonblocking under a deadline `within` from now.
    ///
    /// # Errors
    /// `broker` on the `fcntl` failure.
    pub(crate) fn new(fd: OwnedFd, within: Duration) -> Result<Self, Failure> {
        let flags = fcntl_getfl(&fd).map_err(|e| {
            Failure::internal("broker", format!("broker: connection deadline: {e}"))
        })?;
        fcntl_setfl(&fd, flags | OFlags::NONBLOCK).map_err(|e| {
            Failure::internal("broker", format!("broker: connection deadline: {e}"))
        })?;
        Ok(Self {
            fd,
            deadline: Instant::now() + within,
        })
    }

    /// `true` while the deadline is still ahead — sleeps one cadence
    /// step (never past `deadline`) so callers retry, not spin.
    fn still_waiting(&self) -> bool {
        let now = Instant::now();
        if now >= self.deadline {
            return false;
        }
        // `thread::sleep` emits `clock_nanosleep` (230) — the
        // allow-listed primitive is `nanosleep` (35) (ADR 0044).
        crate::sys::audited::nanosleep(RETRY_WAIT.min(self.deadline - now));
        true
    }

    fn timed_out() -> Failure {
        Failure::internal("broker", "broker: connection deadline exceeded")
    }

    /// One strict `SCM_RIGHTS` frame under the deadline —
    /// `scm_rights::recv_one`'s checks over an `EAGAIN`-retried
    /// `recvmsg`.
    ///
    /// # Errors
    /// The [`crate::sys::scm_rights::validate_one`] refusals,
    /// `broker` on `recvmsg` failure or the deadline expiring.
    pub(crate) fn recv_one(&self, data: &mut [u8]) -> Result<(usize, OwnedFd), Failure> {
        loop {
            match crate::sys::scm_rights::recv_raw(&self.fd, data) {
                Ok(r) => return crate::sys::scm_rights::validate_one(r),
                Err(Errno::AGAIN) | Err(Errno::INTR) => {
                    if !self.still_waiting() {
                        return Err(Self::timed_out());
                    }
                }
                Err(e) => {
                    return Err(Failure::internal("broker", format!("broker: recvmsg: {e}")));
                }
            }
        }
    }

    /// `ReceiveDescriptor`'s marker gate under the deadline — one
    /// [`crate::sys::scm_rights::TRANSPORT_MARKER`] byte and one
    /// descriptor.
    ///
    /// # Errors
    /// [`Self::recv_one`]'s plus `sys_scm_rights_denied` when the byte
    /// is not the marker.
    pub(crate) fn recv_marker_descriptor(&self) -> Result<OwnedFd, Failure> {
        let mut data = [0u8; 1];
        let (bytes, fd) = self.recv_one(&mut data)?;
        if bytes != 1 || data[0] != crate::sys::scm_rights::TRANSPORT_MARKER {
            return Err(Failure::denied(
                "sys_scm_rights_denied",
                "materialize FD marker mismatch",
            ));
        }
        Ok(fd)
    }
}

impl AsFd for DeadlineStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self).read(buf)
    }
}

/// `read(2)` on the nonblocking fd — `EAGAIN`/`EINTR` retry under the
/// deadline, `TimedOut` past it. Unix-stream `read` is what Go emits
/// for a `net.Conn`; `recvfrom` is never needed on a connected
/// `SOCK_STREAM`.
impl Read for &DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match rustix::io::read(self.as_fd(), &mut *buf) {
                Ok(n) => return Ok(n),
                Err(Errno::AGAIN) | Err(Errno::INTR) => {
                    if !self.still_waiting() {
                        return Err(Error::from(ErrorKind::TimedOut));
                    }
                }
                Err(e) => return Err(Error::from(e)),
            }
        }
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `write(2)` on the nonblocking fd — same deadline policy as
/// [`Read`]. A Unix socket carries no `sendto` address per call.
impl Write for &DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            match rustix::io::write(self.as_fd(), buf) {
                Ok(n) => return Ok(n),
                Err(Errno::AGAIN) | Err(Errno::INTR) => {
                    if !self.still_waiting() {
                        return Err(Error::from(ErrorKind::TimedOut));
                    }
                }
                Err(e) => return Err(Error::from(e)),
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A silent peer blocks exactly `within`, then the read refuses —
    /// `SO_RCVTIMEO`'s observable contract without `setsockopt`.
    #[test]
    fn read_times_out_past_deadline() {
        let (a, _b) = pair();
        let s = DeadlineStream::new(a, Duration::from_millis(60)).expect("nonblock");
        let mut buf = [0u8; 8];
        let start = Instant::now();
        let err = (&s).read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(
            start.elapsed() >= Duration::from_millis(60),
            "deadline must bound the wait"
        );
    }

    /// A peer that answers in time reads through — the deadline is an
    /// upper bound, not a forced wait.
    #[test]
    fn read_before_deadline_succeeds() {
        let (a, b) = pair();
        let s = DeadlineStream::new(a, Duration::from_secs(5)).expect("nonblock");
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let mut f = std::fs::File::from(b);
            f.write_all(b"hi").expect("peer write");
        });
        let mut buf = [0u8; 8];
        let n = (&s).read(&mut buf).expect("read");
        writer.join().expect("writer");
        assert_eq!(&buf[..n], b"hi");
    }

    /// Write side: a small payload flushes immediately — `O_NONBLOCK`
    /// plus a buffered socket answers without a wait.
    #[test]
    fn write_round_trip() {
        let (a, b) = pair();
        let s = DeadlineStream::new(a, Duration::from_secs(5)).expect("nonblock");
        assert_eq!((&s).write(b"ping").expect("write"), 4);
        let mut other = DeadlineStream::new(b, Duration::from_secs(5)).expect("nonblock");
        let mut buf = [0u8; 8];
        let n = other.read(&mut buf).expect("read back");
        assert_eq!(&buf[..n], b"ping");
    }
}
