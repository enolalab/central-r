//! The production CHL1 socket transport — the port of upstream
//! `internal/harnesslauncher/client_linux.go`. It dials the root
//! `central-harness-launcher` daemon over its fixed `AF_UNIX`/
//! `SOCK_SEQPACKET` socket, checks the peer with `SO_PEERCRED`, and
//! receives the launch's descriptors with `SCM_RIGHTS`.
//!
//! Upstream's `Client` becomes [`SocketLauncherClient`] (the
//! `LauncherClient` port), its `net.UnixConn` becomes [`SocketConn`]
//! (the `FrameConn` port), and its `Launch` state machine is the
//! already-ported [`WireSession`] this transport hands to it. Every
//! request uses a new connection; a started LAUNCH keeps its
//! connection as the lifeline. The request deadline bounds only the
//! dial + round-trip — the lifeline itself carries none, exactly as
//! upstream clears `conn.SetDeadline` after a successful launch.
//!
//! Two upstream probes have no safe rustix surface and are ported to
//! their equivalent checks:
//!
//! - `F_GETFD`/`FD_CLOEXEC` on every received descriptor: same
//!   `fcntl_getfd` call, same refusal.
//! - `pidfd_send_signal(fd, 0)` to prove the fourth descriptor is a
//!   pidfd: rustix's `pidfd_send_signal` takes only a real `Signal`
//!   (`Signal` is a `NonZeroI32`), so the port reads the descriptor's
//!   `/proc/self/fd` link target instead — a pidfd and only a pidfd
//!   links to `anon_inode:[pidfd]`. That check is stronger than
//!   upstream's EPERM/ESRCH passes and proves the descriptor kind
//!   even after the init has exited, exactly the race upstream's
//!   comment accepts.

use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::Duration;

use central_adapter_harness::launcher::client::{
    FrameConn, LauncherClient, LauncherSession, RecvReply, SOCKET_PATH, WireSession,
};
use central_adapter_harness::launcher::protocol::{
    self, LaunchRequest, Opcode, Response, Scope, codes, decode_response, encode_alive,
    encode_kill, encode_launch,
};
use central_foundation::failure::Failure;
use central_harness::port::PortFuture;
use rustix::io::Errno;
use rustix::net::{
    self, AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SocketAddrUnix, SocketFlags, SocketType,
};
use rustix::process::Uid;
use tokio::io::Interest;
use tokio::net::UnixStream;

/// The descriptor count a started LAUNCH carries — stdin, stdout and
/// stderr pipe ends plus the session init's pidfd (PROTOCOL.md §3.1.2).
const LAUNCH_DESCRIPTOR_COUNT: usize = 4;

/// The request deadline `roundTrip` took from upstream's ctx. The
/// launcher port's futures carry no deadline, so the client installs
/// this defensive bound over each dial + round-trip: above the
/// daemon's worst-case KILL ladder (~75 s) and far above a launch or
/// liveness probe, so only a genuinely wedged daemon hits it. The
/// lifeline never sees it.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

fn transport(msg: impl Into<String>) -> Failure {
    Failure::unavailable(
        codes::TRANSPORT,
        format!("harness launcher: {}", msg.into()),
    )
}

fn malformed_response(msg: impl Into<String>) -> Failure {
    Failure::internal(
        codes::MALFORMED_RESPONSE,
        format!("harness launcher: {}", msg.into()),
    )
}

fn bad_descriptors(msg: impl Into<String>) -> Failure {
    Failure::internal(
        codes::BAD_DESCRIPTORS,
        format!("harness launcher: {}", msg.into()),
    )
}

/// `Errno` → `std::io::Error` for `try_io`'s `WouldBlock` detection —
/// `EAGAIN`/`EWOULDBLOCK` must arrive as `io::ErrorKind::WouldBlock`.
fn errno_to_io(e: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.raw_os_error())
}

fn peer_denied() -> Failure {
    Failure::new(
        central_foundation::failure::FailureKind::Denied,
        codes::PEER_NOT_ROOT,
        "harness launcher: launcher peer is not root",
    )
}

/// `SocketLauncherClient` — upstream `harnesslauncher.Client`: every
/// request uses a new connection; a started LAUNCH keeps its
/// connection as the lifeline. [`SocketLauncherClient::new`] binds the
/// fixed socket path and admits only a root peer.
pub struct SocketLauncherClient {
    socket_path: PathBuf,
    peer_uid: Uid,
    /// `Some(d)` bounds each dial + round-trip (upstream's ctx
    /// deadline); `None` leaves a request unbounded — the caller's
    /// future drop is then the only cancellation.
    request_timeout: Option<Duration>,
}

impl Default for SocketLauncherClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketLauncherClient {
    /// `NewClient` — the fixed socket path admitting only a root peer.
    pub fn new() -> Self {
        Self {
            socket_path: PathBuf::from(SOCKET_PATH),
            peer_uid: Uid::ROOT,
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
        }
    }

    /// Test/configuration seam for a non-default socket path (the
    /// same knob upstream's `Client.socketPath` field is).
    #[must_use]
    pub fn with_socket_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.socket_path = path.into();
        self
    }

    /// Test seam for the admitted peer uid (upstream `peerUID`).
    /// Production never calls it — the default is [`Uid::ROOT`].
    #[must_use]
    pub fn with_peer_uid(mut self, uid: Uid) -> Self {
        self.peer_uid = uid;
        self
    }

    /// Installs a per-request deadline (`None` unbounds requests).
    /// A zero duration is kept — it makes every request expire
    /// immediately, which tests use for the timeout path.
    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// `dial` — one fresh `SOCK_SEQPACKET` connection whose peer has
    /// passed the `SO_PEERCRED` check. rustix's `Pid` is `NonZeroI32`,
    /// so upstream's `peer.Pid <= 0` arm cannot be constructed here —
    /// the uid check is the whole refusal.
    async fn dial(&self) -> Result<SocketConn, Failure> {
        let fd = net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|e| transport(format!("socket: {e}")))?;
        let addr = SocketAddrUnix::new(self.socket_path.as_path())
            .map_err(|e| transport(format!("socket address: {e}")))?;
        // `UnixStream::from_std` registers the fd on the reactor —
        // the safe registration path: no `unsafe` and no deprecated
        // `AsyncFd::new`. The stream type label is nominal; the
        // underlying `SOCK_SEQPACKET` fd keeps its datagram semantics,
        // and raw `send`/`recvmsg` run on its fd.
        let conn = match net::connect(&fd, &addr) {
            Ok(()) => UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
                .map_err(|e| transport(format!("register: {e}")))?,
            Err(Errno::INPROGRESS) | Err(Errno::AGAIN) => {
                let conn = UnixStream::from_std(std::os::unix::net::UnixStream::from(fd))
                    .map_err(|e| transport(format!("register: {e}")))?;
                conn.writable()
                    .await
                    .map_err(|e| transport(format!("connect: {e}")))?;
                match net::sockopt::socket_error(&conn) {
                    Ok(Ok(())) => conn,
                    Ok(Err(e)) | Err(e) => {
                        return Err(transport(format!("connect: {e}")));
                    }
                }
            }
            Err(e) => return Err(transport(format!("connect: {e}"))),
        };
        let peer = net::sockopt::socket_peercred(&conn)
            .map_err(|e| transport(format!("inspect peer: {e}")))?;
        if peer.uid != self.peer_uid {
            return Err(peer_denied());
        }
        Ok(SocketConn { conn: Some(conn) })
    }

    /// `roundTrip` — write one request frame, read one response
    /// datagram of `op` carrying at most `max_fds` descriptors.
    async fn round_trip(
        conn: &mut SocketConn,
        frame: &[u8],
        op: Opcode,
        max_fds: usize,
    ) -> Result<(Response, Vec<OwnedFd>), Failure> {
        conn.send(frame).await?;
        let Some((data, fds)) = conn.receive_inner().await? else {
            return Err(malformed_response("connection closed before a response"));
        };
        if fds.len() > max_fds {
            return Err(malformed_response("response carried descriptors"));
        }
        let resp = decode_response(&data, op)?;
        Ok((resp, fds))
    }

    /// The shared request path of upstream `request`: fresh
    /// connection, frame out, response in, connection closed — under
    /// the request deadline when installed.
    async fn request(&self, frame: &[u8], op: Opcode) -> Result<Response, Failure> {
        let mut conn = self.dial().await?;
        let (resp, _fds) = Self::round_trip(&mut conn, frame, op, 0).await?;
        if resp.status != protocol::Reason::Ok {
            return Err(refusal(&resp, "request"));
        }
        Ok(resp)
    }
}

impl LauncherClient for SocketLauncherClient {
    /// `Launch` — send LAUNCH on a new connection; on success the
    /// session owns the connection (the lifeline) plus the stdio and
    /// pidfd of PROTOCOL.md §3.1.2. The deadline bounds only the
    /// request: once this resolves, the lifeline is unbounded.
    fn launch<'a>(
        &'a self,
        req: LaunchRequest,
    ) -> PortFuture<'a, Result<Box<dyn LauncherSession>, Failure>> {
        Box::pin(async move {
            let frame = encode_launch(&req)?;
            let work = async {
                let mut conn = self.dial().await?;
                let (resp, fds) = Self::round_trip(&mut conn, &frame, Opcode::Launch, 4).await?;
                if resp.status != protocol::Reason::Ok {
                    if !fds.is_empty() {
                        return Err(malformed_response("refusal carried descriptors"));
                    }
                    return Err(refusal(&resp, "launch"));
                }
                check_launch_fds(&fds)?;
                // The lifeline carries no deadline: it lives as long
                // as the session — upstream `conn.SetDeadline(time.Time{})`.
                // `check_launch_fds` proved the count — the array
                // conversion cannot fail.
                let [stdin, stdout, stderr, pidfd] =
                    <[OwnedFd; LAUNCH_DESCRIPTOR_COUNT]>::try_from(fds).map_err(|v| {
                        bad_descriptors(format!(
                            "got {} descriptors, want {LAUNCH_DESCRIPTOR_COUNT}",
                            v.len()
                        ))
                    })?;
                let to_file = |fd: OwnedFd| tokio::fs::File::from_std(std::fs::File::from(fd));
                let stdin = to_file(stdin);
                let stdout = to_file(stdout);
                let stderr = to_file(stderr);
                let pidfd = Some(to_file(pidfd));
                let session: Box<dyn LauncherSession> = Box::new(WireSession::new(
                    req.scope,
                    Box::new(conn),
                    stdin,
                    stdout,
                    stderr,
                    pidfd,
                ));
                Ok(session)
            };
            match self.request_timeout {
                Some(limit) => match tokio::time::timeout(limit, work).await {
                    Ok(result) => result,
                    Err(_) => Err(transport("request deadline exceeded")),
                },
                None => work.await,
            }
        })
    }

    /// `Alive` — whether the scope's cgroup is populated.
    fn alive<'a>(&'a self, scope: Scope) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move {
            let frame = encode_alive(scope)?;
            let work = async { self.request(&frame, Opcode::Alive).await };
            let resp = match self.request_timeout {
                Some(limit) => match tokio::time::timeout(limit, work).await {
                    Ok(result) => result?,
                    Err(_) => return Err(transport("request deadline exceeded")),
                },
                None => work.await?,
            };
            Ok(resp.alive)
        })
    }

    /// `Kill` — SIGTERM through the session's init, up to `grace`,
    /// then `cgroup.kill`; returns once the scope is empty. It never
    /// touches a lifeline.
    fn kill<'a>(&'a self, scope: Scope, grace: Duration) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let frame = encode_kill(scope, grace)?;
            let work = async { self.request(&frame, Opcode::Kill).await.map(|_| ()) };
            match self.request_timeout {
                Some(limit) => match tokio::time::timeout(limit, work).await {
                    Ok(result) => result,
                    Err(_) => Err(transport("request deadline exceeded")),
                },
                None => work.await,
            }
        })
    }
}

/// The refusal failure — upstream's
/// `fmt.Errorf("harness launcher: <op> refused: %w", resp.Status.Err())`:
/// the status's own kind and code survive as the matching surface, the
/// message carries the operator's operation name.
fn refusal(resp: &Response, op: &str) -> Failure {
    match resp.status.err() {
        Some(cause) => Failure::new(
            cause.kind(),
            cause.code(),
            format!("harness launcher: {op} refused: {}", cause.message()),
        ),
        None => transport(format!("{op} refused: status {}", resp.status as u8)),
    }
}

/// `SocketConn` — one CHL1 datagram connection, upstream's
/// `*net.UnixConn` narrowed to send/receive/close. The socket is
/// nonblocking and registered on the tokio reactor, so a dropped
/// future cancels the in-flight `recvmsg` exactly the way upstream's
/// ctx deadline does.
pub struct SocketConn {
    conn: Option<UnixStream>,
}

impl SocketConn {
    /// `receivePacket` — one datagram of at most
    /// [`protocol::RESPONSE_SIZE`] bytes plus up to
    /// [`LAUNCH_DESCRIPTOR_COUNT`] descriptors (received
    /// close-on-exec). `Ok(None)` is the peer's orderly close — the
    /// lifeline's end.
    async fn receive_inner(&mut self) -> Result<Option<(Vec<u8>, Vec<OwnedFd>)>, Failure> {
        let Some(conn) = self.conn.as_ref() else {
            return Err(transport("receive on a closed connection"));
        };
        let fd = conn.as_fd();
        let mut data = [0u8; protocol::RESPONSE_SIZE + 1];
        let mut space =
            [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(LAUNCH_DESCRIPTOR_COUNT))];
        // `async_io` retries the closure while it reports WouldBlock.
        // The `RecvAncillaryBuffer` the kernel's `msg_controllen` is
        // written into lives outside the closure so its descriptors
        // can be drained after the successful receive.
        let mut cmsg = RecvAncillaryBuffer::new(&mut space[..]);
        let (n, flags) = conn
            .async_io(Interest::READABLE, || {
                let mut iov = [std::io::IoSliceMut::new(&mut data)];
                let ret = rustix::net::recvmsg(fd, &mut iov, &mut cmsg, RecvFlags::CMSG_CLOEXEC)
                    .map_err(errno_to_io)?;
                Ok::<_, std::io::Error>((ret.bytes, ret.flags))
            })
            .await
            .map_err(|e| transport(format!("receive: {e}")))?;
        let mut fds: Vec<OwnedFd> = Vec::new();
        for message in cmsg.drain() {
            // Upstream `ParseSocketControlMessage` also tolerates
            // non-rights ancillary data; only rights are carried.
            if let RecvAncillaryMessage::ScmRights(rights) = message {
                fds.extend(rights);
            }
        }
        if flags.intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            || n > protocol::RESPONSE_SIZE
            || fds.len() > LAUNCH_DESCRIPTOR_COUNT
        {
            return Err(malformed_response(
                "oversized response or too many descriptors",
            ));
        }
        if n == 0 {
            return Ok(None);
        }
        Ok(Some((data[..n].to_vec(), fds)))
    }
}

impl FrameConn for SocketConn {
    /// One request datagram — `SOCK_SEQPACKET` writes are atomic, so a
    /// short write is a protocol error, matching upstream's check.
    fn send<'a>(&'a mut self, frame: &'a [u8]) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let Some(conn) = self.conn.as_ref() else {
                return Err(transport("send on a closed connection"));
            };
            let fd = conn.as_fd();
            let n = conn
                .async_io(Interest::WRITABLE, || {
                    rustix::net::send(fd, frame, rustix::net::SendFlags::empty())
                        .map_err(errno_to_io)
                })
                .await
                .map_err(|e| transport(format!("write request: {e}")))?;
            if n != frame.len() {
                return Err(transport("short request write"));
            }
            Ok(())
        })
    }

    /// One datagram and its descriptors, mapped onto [`RecvReply`]'s
    /// `tokio::fs::File` surface — `Ok((vec![], _))` is the lifeline's
    /// end.
    fn receive<'a>(&'a mut self) -> PortFuture<'a, RecvReply> {
        Box::pin(async move {
            match self.receive_inner().await? {
                None => Ok((Vec::new(), Vec::new())),
                Some((data, fds)) => Ok((
                    data,
                    fds.into_iter()
                        .map(|fd| tokio::fs::File::from_std(std::fs::File::from(fd)))
                        .collect(),
                )),
            }
        })
    }

    /// `Close` — idempotent; dropping the stream closes the
    /// connection.
    fn close(&mut self) -> Result<(), Failure> {
        self.conn = None;
        Ok(())
    }
}

/// `checkLaunchFDs` — exactly four descriptors, every one
/// close-on-exec, the first three FIFOs, the fourth a pidfd.
fn check_launch_fds(fds: &[OwnedFd]) -> Result<(), Failure> {
    if fds.len() != LAUNCH_DESCRIPTOR_COUNT {
        return Err(bad_descriptors(format!(
            "got {} descriptors, want {LAUNCH_DESCRIPTOR_COUNT}",
            fds.len()
        )));
    }
    for (i, fd) in fds.iter().enumerate() {
        let flags = rustix::io::fcntl_getfd(fd)
            .map_err(|e| bad_descriptors(format!("descriptor {i}: inspect flags: {e}")))?;
        if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
            return Err(bad_descriptors(format!(
                "descriptor {i} is not close-on-exec"
            )));
        }
        if i < 3 {
            let st = rustix::fs::fstat(fd)
                .map_err(|e| bad_descriptors(format!("descriptor {i}: stat: {e}")))?;
            if !rustix::fs::FileType::from_raw_mode(st.st_mode).is_fifo() {
                return Err(bad_descriptors(format!("descriptor {i} is not a pipe")));
            }
        }
    }
    if !is_pidfd(&fds[3]) {
        return Err(bad_descriptors("descriptor 3 is not a pidfd"));
    }
    Ok(())
}

/// The pidfd proof upstream takes from `pidfd_send_signal(fd, 0)`:
/// rustix admits no signal-0 form, so the port identifies the
/// descriptor by its `/proc/self/fd` link target — `anon_inode:[pidfd]`
/// names a pidfd and nothing else. A vanished target keeps the same
/// link, covering the fast-exit race upstream's ESRCH arm accepts.
fn is_pidfd(fd: &OwnedFd) -> bool {
    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let Ok(target) = rustix::fs::readlinkat(rustix::fs::CWD, path.as_str(), Vec::with_capacity(64))
    else {
        return false;
    };
    target.to_bytes() == b"anon_inode:[pidfd]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::BorrowedFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use central_adapter_harness::launcher::protocol::{Exit, parse_scope};
    use rustix::net::SendAncillaryMessage;

    static UNIQUE: AtomicUsize = AtomicUsize::new(0);

    /// A scratch socket path beneath the system temp dir — the real
    /// socket lives only for the test's duration.
    fn socket_path() -> PathBuf {
        let n = UNIQUE.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("central-chl1-test-{}-{n}.sock", std::process::id()))
    }

    /// `bind` + `listen` on a blocking `SOCK_SEQPACKET` socket — the
    /// fake daemon's listener half (upstream's daemon accepts blocking
    /// connections; only the client is nonblocking).
    fn fake_listener(path: &std::path::Path) -> OwnedFd {
        let fd = net::socket(AddressFamily::UNIX, SocketType::SEQPACKET, None).unwrap();
        net::bind(&fd, &SocketAddrUnix::new(path).unwrap()).unwrap();
        net::listen(&fd, 4).unwrap();
        fd
    }

    /// `accept` one blocking connection.
    fn accept(listener: &OwnedFd) -> OwnedFd {
        net::accept(listener).unwrap()
    }

    /// `recv` one datagram from the daemon side.
    fn recv_frame(conn: &OwnedFd) -> Vec<u8> {
        let mut buf = vec![0u8; protocol::MAX_FRAME];
        let (n, _flags) = net::recv(conn, &mut buf, RecvFlags::empty()).unwrap();
        buf.truncate(n);
        buf
    }

    /// `sendmsg` one response, optionally carrying descriptors.
    fn send_frame(conn: &OwnedFd, frame: &[u8], fds: &[BorrowedFd<'_>]) {
        let iov = [std::io::IoSlice::new(frame)];
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut space[..]);
        if !fds.is_empty() {
            assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
        }
        let n = net::sendmsg(conn, &iov, &mut control, rustix::net::SendFlags::empty()).unwrap();
        assert_eq!(n, frame.len());
    }

    /// The client's own uid — the admitted peer for every happy-path
    /// test (the test daemon is this process).
    fn client(path: &std::path::Path) -> SocketLauncherClient {
        SocketLauncherClient::new()
            .with_socket_path(path.to_path_buf())
            .with_peer_uid(rustix::process::geteuid())
            .with_request_timeout(Some(Duration::from_secs(10)))
    }

    /// A valid LAUNCH request body — `encode_launch` validates it.
    fn launch_req() -> LaunchRequest {
        LaunchRequest {
            scope: parse_scope("01234567-89ab-cdef-0123-456789abcdef").unwrap(),
            harness: "claude".to_string(),
            work_dir: String::new(),
            argv: vec!["-p".to_string()],
            env: vec!["LANG=C.UTF-8".to_string()],
        }
    }

    /// A pidfd for the test process — `pidfd_open` on our own pid is
    /// always legal, and the descriptor keeps `anon_inode:[pidfd]` as
    /// its `/proc/self/fd` link target.
    fn own_pidfd() -> OwnedFd {
        rustix::process::pidfd_open(
            rustix::process::getpid(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap()
    }

    /// Three pipe ends + a pidfd, as the daemon's LAUNCH response set.
    fn launch_fds() -> Vec<OwnedFd> {
        let (sin_r, _sin_w) = std::io::pipe().unwrap();
        let (sout_r, _sout_w) = std::io::pipe().unwrap();
        let (serr_r, _serr_w) = std::io::pipe().unwrap();
        // Leak the writers' counterparts the daemon would hold; the
        // test needs only the three ends it sends.
        vec![
            OwnedFd::from(sin_r),
            OwnedFd::from(sout_r),
            OwnedFd::from(serr_r),
            own_pidfd(),
        ]
    }

    /// ALIVE reports the daemon's bit over a fresh connection.
    #[tokio::test(flavor = "current_thread")]
    async fn alive_round_trip_reports_daemon_bit() {
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            let req = recv_frame(&conn);
            assert_eq!(req.len(), protocol::ALIVE_REQUEST_SIZE);
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Alive,
                    status: protocol::Reason::Ok,
                    alive: true,
                    exit: Exit::default(),
                })
                .unwrap(),
                &[],
            );
        });
        let alive = client(&path)
            .alive(parse_scope("01234567-89ab-cdef-0123-456789abcdef").unwrap())
            .await
            .unwrap();
        assert!(alive);
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A refused KILL surfaces the daemon's reason code — upstream's
    /// `request refused: %w` wrap keeps the status's `errors.Is` value.
    #[tokio::test(flavor = "current_thread")]
    async fn kill_refusal_preserves_status_code() {
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            let req = recv_frame(&conn);
            assert_eq!(req.len(), protocol::KILL_REQUEST_SIZE);
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Kill,
                    status: protocol::Reason::ScopeBusy,
                    alive: false,
                    exit: Exit::default(),
                })
                .unwrap(),
                &[],
            );
        });
        let err = client(&path)
            .kill(
                parse_scope("01234567-89ab-cdef-0123-456789abcdef").unwrap(),
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::SCOPE_BUSY);
        assert!(err.message().contains("request refused"));
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// LAUNCH hands the session the lifeline + four descriptors; a
    /// later EXIT on the lifeline resolves `wait_exit`.
    #[tokio::test(flavor = "current_thread")]
    async fn launch_owns_lifeline_and_reports_exit() {
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            let _req = recv_frame(&conn);
            let fds = launch_fds();
            let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(|f| f.as_fd()).collect();
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Launch,
                    status: protocol::Reason::Ok,
                    alive: false,
                    exit: Exit::default(),
                })
                .unwrap(),
                &borrowed,
            );
            // The lifeline stays open; EXIT arrives on it later.
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Exit,
                    status: protocol::Reason::Ok,
                    alive: false,
                    exit: Exit {
                        code: 7,
                        signaled: false,
                    },
                })
                .unwrap(),
                &[],
            );
            // Keep the connection until the client drops its end.
            let _ = net::recv(&conn, &mut [0u8; 8], RecvFlags::empty());
        });
        let mut session = client(&path).launch(launch_req()).await.unwrap();
        assert!(session.take_stdin().is_some());
        assert!(session.take_stdout().is_some());
        assert!(session.take_stderr().is_some());
        let exit = session.wait_exit().await.unwrap();
        assert_eq!(exit.code, 7);
        assert!(!exit.signaled);
        // Cached: a second wait returns the same exit.
        assert_eq!(session.wait_exit().await.unwrap().code, 7);
        session.close();
        session.close(); // idempotent
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A refused LAUNCH surfaces the status's code.
    #[tokio::test(flavor = "current_thread")]
    async fn launch_refusal_surfaces_reason() {
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            let _req = recv_frame(&conn);
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Launch,
                    status: protocol::Reason::LaunchFailed,
                    alive: false,
                    exit: Exit::default(),
                })
                .unwrap(),
                &[],
            );
        });
        let err = client(&path).launch(launch_req()).await.err().unwrap();
        assert_eq!(err.code(), codes::LAUNCH_FAILED);
        assert!(err.message().contains("launch refused"));
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A refusal carrying descriptors is a malformed response.
    #[tokio::test(flavor = "current_thread")]
    async fn launch_refusal_with_descriptors_is_malformed() {
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            let _req = recv_frame(&conn);
            let one = own_pidfd();
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Launch,
                    status: protocol::Reason::LaunchFailed,
                    alive: false,
                    exit: Exit::default(),
                })
                .unwrap(),
                &[one.as_fd()],
            );
        });
        let err = client(&path).launch(launch_req()).await.err().unwrap();
        assert_eq!(err.code(), codes::MALFORMED_RESPONSE);
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Three descriptors instead of four is `ErrBadDescriptors`.
    #[tokio::test(flavor = "current_thread")]
    async fn launch_wrong_descriptor_count_fails() {
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            let _req = recv_frame(&conn);
            let mut fds = launch_fds();
            let _ = fds.pop();
            let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(|f| f.as_fd()).collect();
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Launch,
                    status: protocol::Reason::Ok,
                    alive: false,
                    exit: Exit::default(),
                })
                .unwrap(),
                &borrowed,
            );
        });
        let err = client(&path).launch(launch_req()).await.err().unwrap();
        assert_eq!(err.code(), codes::BAD_DESCRIPTORS);
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A non-pipe among the stdio descriptors is `ErrBadDescriptors`.
    #[tokio::test(flavor = "current_thread")]
    async fn launch_non_pipe_stdio_fails() {
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            let _req = recv_frame(&conn);
            // Second slot is a pidfd, not a FIFO.
            let (sin_r, _w) = std::io::pipe().unwrap();
            let (serr_r, _w2) = std::io::pipe().unwrap();
            let fds = [
                OwnedFd::from(sin_r),
                own_pidfd(),
                OwnedFd::from(serr_r),
                own_pidfd(),
            ];
            let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(|f| f.as_fd()).collect();
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Launch,
                    status: protocol::Reason::Ok,
                    alive: false,
                    exit: Exit::default(),
                })
                .unwrap(),
                &borrowed,
            );
        });
        let err = client(&path).launch(launch_req()).await.err().unwrap();
        assert_eq!(err.code(), codes::BAD_DESCRIPTORS);
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A peer that is not the admitted uid is denied — upstream's
    /// `ErrPeerNotRoot`. Skipped when the suite itself runs as root
    /// (the test daemon would then pass the check).
    #[tokio::test(flavor = "current_thread")]
    async fn non_root_peer_is_denied() {
        if rustix::process::geteuid() == Uid::ROOT {
            return;
        }
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            // The client must never speak to us — no response.
            let _ = net::recv(&conn, &mut [0u8; 8], RecvFlags::empty());
        });
        let client = SocketLauncherClient::new()
            .with_socket_path(path.to_path_buf())
            .with_request_timeout(Some(Duration::from_secs(10)));
        let err = client
            .alive(parse_scope("01234567-89ab-cdef-0123-456789abcdef").unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::PEER_NOT_ROOT);
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// A missing listener fails as a transport error, not a refusal.
    #[tokio::test(flavor = "current_thread")]
    async fn missing_socket_is_transport_error() {
        let path = std::env::temp_dir().join(format!(
            "central-chl1-absent-{}-{}.sock",
            std::process::id(),
            UNIQUE.fetch_add(1, Ordering::SeqCst)
        ));
        let err = client(&path)
            .alive(parse_scope("01234567-89ab-cdef-0123-456789abcdef").unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.code(), codes::TRANSPORT);
        assert!(err.message().contains("connect"));
    }

    /// The lifeline ending without EXIT is `ErrLifelineLost`, and the
    /// session caches it.
    #[tokio::test(flavor = "current_thread")]
    async fn lifeline_close_without_exit_is_lost() {
        let path = socket_path();
        let listener = fake_listener(&path);
        let daemon = thread::spawn(move || {
            let conn = accept(&listener);
            let _req = recv_frame(&conn);
            let fds = launch_fds();
            let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(|f| f.as_fd()).collect();
            send_frame(
                &conn,
                &protocol::encode_response(&protocol::Response {
                    op: Opcode::Launch,
                    status: protocol::Reason::Ok,
                    alive: false,
                    exit: Exit::default(),
                })
                .unwrap(),
                &borrowed,
            );
            // Drop: the lifeline ends with no EXIT.
        });
        let mut session = client(&path).launch(launch_req()).await.unwrap();
        let err = session.wait_exit().await.unwrap_err();
        assert_eq!(err.code(), codes::LIFELINE_LOST);
        assert_eq!(
            session.wait_exit().await.unwrap_err().code(),
            codes::LIFELINE_LOST
        );
        daemon.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
