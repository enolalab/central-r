//! `postgres_target_exclusion.go`'s `RetainForPostReap` OS half plus
//! `backuplauncher/worker_handoff_linux.go` — the honest Rust split
//! for the one primitive pgx gave upstream for free and sqlx does not:
//! handing the exact PostgreSQL session socket that owns the
//! accepted-point advisory locks to the per-launch native monitor.
//!
//! [`LocalPostgresSocketRetainer`] resolves the session descriptor by
//! `/proc/self/fd` scan — `getsockname`/`getpeername` must match the
//! lease's recorded `inet_client_port()` and the pinned loopback peer
//! port — duplicates it `F_DUPFD_CLOEXEC`, and invokes the composition
//! callback so a borrowed raw descriptor never outlives the dup. The
//! lease is marked `Retained` *before* the resolution, mirroring
//! upstream's `e.retained = true` inside `Hijack`: a failed handoff
//! can never leave a reusable worker-side lease.
//!
//! [`TargetLockHandoff`] is the CBW1 client over fixed descriptor 5 —
//! `workerHandoffFD`, `workerMagic`, `workerFrameSize`, the
//! type-1 request / type-2 acknowledgement, and the single-use channel
//! discipline all verbatim from `worker_handoff_linux.go`.

use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use central_backup::port::{BackupTargetExclusion, BackupTargetLockRetainer};
use central_foundation::failure::Failure;
use rustix::fs::{FileType, fstat};
use rustix::io::fcntl_dupfd_cloexec;
use rustix::net::sockopt::{Timeout, set_socket_timeout, socket_type};
use rustix::net::{
    SocketAddrUnix, SocketAddrV4, SocketAddrV6, SocketType, getpeername, getsockname,
};

use crate::sys::audited;
use crate::sys::scm_rights;

/// `workerHandoffFD` — the fixed monitor-channel descriptor.
const WORKER_HANDOFF_FD: RawFd = 5;
/// `workerMagic` / `workerFrameSize` / `workerProtocolVersion`.
const WORKER_MAGIC: [u8; 4] = *b"CBW1";
const WORKER_FRAME_SIZE: usize = 40;
const WORKER_PROTOCOL_VERSION: u8 = 1;
/// Request/acknowledgement type bytes (`frame[5]`).
const FRAME_TYPE_RETAIN: u8 = 1;
const FRAME_TYPE_ACK: u8 = 2;

/// The pinned peer port the session socket must speak — the fixed
/// `127.0.0.1:55432` target; never caller-selected.
const PINNED_PG_PEER_PORT: u16 = 55432;

fn retention_unavailable() -> Failure {
    Failure::unavailable(
        "backup_target_retention",
        "backup worker target retention is unavailable",
    )
}

fn handoff_unavailable() -> Failure {
    Failure::unavailable(
        "backup_target_handoff",
        "backup worker target retention is unavailable",
    )
}

fn handoff_denied() -> Failure {
    Failure::denied(
        "backup_target_handoff",
        "backup worker target retention failed",
    )
}

/// `hex.DecodeString(strings.TrimPrefix(proof, "sha256:"))` — the raw
/// 32-byte digest the CBW1 frame carries; the all-zero proof is
/// refused exactly like upstream's `proof == ([32]byte{})`.
fn decode_lock_proof(proof: &str) -> Result<[u8; 32], Failure> {
    let Some(hex_part) = proof.strip_prefix("sha256:") else {
        return Err(retention_unavailable());
    };
    let raw = hex_part.as_bytes();
    if raw.len() != 64 {
        return Err(retention_unavailable());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (raw[i * 2] as char).to_digit(16);
        let lo = (raw[i * 2 + 1] as char).to_digit(16);
        let (Some(hi), Some(lo)) = (hi, lo) else {
            return Err(retention_unavailable());
        };
        out[i] = u8::try_from((hi << 4) | lo).unwrap_or(0);
    }
    if out == [0u8; 32] {
        return Err(retention_unavailable());
    }
    Ok(out)
}

/// `LocalPostgresSocketRetainer` — the [`BackupTargetLockRetainer`]
/// bound to one already-acquired lease. The lease stays alive (its
/// `Arc` is shared with the environment) while this adapter resolves
/// and transfers the descriptor that backs it.
pub struct LocalPostgresSocketRetainer {
    lease: Arc<dyn BackupTargetExclusion>,
    /// The peer port the session must speak — fixed to
    /// [`PINNED_PG_PEER_PORT`] in production; tests bind a loopback
    /// listener elsewhere.
    peer_port: u16,
}

impl LocalPostgresSocketRetainer {
    /// `New…` — binds the exact lease whose session socket is to be
    /// handed off. The composition builds this after the coordinator's
    /// publication checks pass, exactly like upstream's late
    /// `lease.(RetainForPostReap)` type-assertion.
    #[must_use]
    pub fn new(lease: Arc<dyn BackupTargetExclusion>) -> Self {
        Self {
            lease,
            peer_port: PINNED_PG_PEER_PORT,
        }
    }

    /// The test-only constructor pinning a loopback peer port other
    /// than the production target's — the resolution logic itself is
    /// identical; only the pinned constant differs.
    #[cfg(test)]
    fn for_test(lease: Arc<dyn BackupTargetExclusion>, peer_port: u16) -> Self {
        Self { lease, peer_port }
    }

    /// The `/proc/self/fd` scan: every descriptor of this process is
    /// `getsockname`'d; the first INET socket whose local port is the
    /// lease's recorded `inet_client_port()` *and* whose peer is the
    /// pinned `127.0.0.1:55432` target is the session socket. A
    /// connected TCP local port is unique per live session, so no
    /// other descriptor can match — and a non-socket or wrong-peer
    /// descriptor can never be mistaken for it.
    fn resolve_session_socket(&self, client_port: u16) -> Result<OwnedFd, Failure> {
        let entries = std::fs::read_dir("/proc/self/fd").map_err(|_| retention_unavailable())?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(raw) = name.parse::<RawFd>() else {
                continue;
            };
            // `raw` names a descriptor of this process — the
            // `/proc/self/fd` listing just proved it open, so the
            // borrow is valid for the two metadata calls and the dup
            // below. It is never closed through the borrow.
            let borrowed = audited::borrow_process_fd(raw);
            let Ok(local) = getsockname(borrowed) else {
                continue;
            };
            let local_port = match SocketAddrV4::try_from(local.clone()) {
                Ok(v4) => v4.port(),
                Err(_) => match SocketAddrV6::try_from(local) {
                    Ok(v6) => v6.port(),
                    Err(_) => continue,
                },
            };
            if local_port != client_port {
                continue;
            }
            let Ok(Some(peer)) = getpeername(borrowed) else {
                continue;
            };
            let peer_port = match SocketAddrV4::try_from(peer.clone()) {
                Ok(v4) => v4.port(),
                Err(_) => match SocketAddrV6::try_from(peer) {
                    Ok(v6) => v6.port(),
                    Err(_) => continue,
                },
            };
            if peer_port != self.peer_port {
                continue;
            }
            return fcntl_dupfd_cloexec(borrowed, 0).map_err(|_| retention_unavailable());
        }
        Err(retention_unavailable())
    }
}

impl BackupTargetLockRetainer for LocalPostgresSocketRetainer {
    /// `RetainForPostReap` — assert the lease still owns both advisory
    /// keys (upstream's `assertHeldLocked` plus the `SyncConn`/`'I'`
    /// idle-transaction guards collapse into the lease's own re-proof),
    /// take the recorded session endpoint and proof, resolve and
    /// `F_DUPFD_CLOEXEC` the session socket — the honest `Hijack` +
    /// `tcp.File()` half — and only then mark the lease `Retained`:
    /// upstream's `e.retained = true` sits after a *successful*
    /// hijack and before the handoff callback, so a resolution failure
    /// leaves the lease releasable while a failed handoff still
    /// consumes it. The duplicate closes when this call returns; the
    /// monitor's SCM_RIGHTS copy is then the sole live session.
    fn retain_for_post_reap(
        &self,
        callback: &mut central_backup::port::TargetLockTransfer<'_>,
    ) -> Result<(), Failure> {
        self.lease
            .assert_held()
            .map_err(|_| retention_unavailable())?;
        let client_port = self.lease.client_port().ok_or_else(retention_unavailable)?;
        let proof = decode_lock_proof(&self.lease.proof())?;
        let duplicate = self.resolve_session_socket(client_port)?;
        self.lease
            .mark_retained()
            .map_err(|_| retention_unavailable())?;
        callback(duplicate.as_fd(), proof)
    }
}

/// `TargetLockHandoff` owns the worker's private monitor channel.
/// Construct it at worker startup so inherited FD 5 is immediately
/// duplicated CLOEXEC and closed before `pg_dump` or any other
/// subprocess can inherit the channel — upstream
/// `PrepareTargetLockHandoff`'s exact contract.
pub struct TargetLockHandoff {
    conn: OwnedFd,
    used: bool,
}

impl TargetLockHandoff {
    /// `PrepareTargetLockHandoff` — adopt fixed FD 5. No path,
    /// endpoint, credential, or descriptor number is caller
    /// controlled.
    ///
    /// # Errors
    /// `backup_target_handoff` on any shape violation.
    pub fn prepare() -> Result<Self, Failure> {
        Self::prepare_at(WORKER_HANDOFF_FD)
    }

    /// `prepareTargetLockHandoff(fd)` — `F_SETFD(FD_CLOEXEC)` (inside
    /// [`audited::adopt_inherited_fd`]), then a CLOEXEC duplicate
    /// (upstream's `net.FileConn`) after which the fixed slot itself
    /// is closed (`file.Close()`), and the `unixpacket` shape proof.
    fn prepare_at(fd: RawFd) -> Result<Self, Failure> {
        if fd < 0 {
            return Err(handoff_unavailable());
        }
        // `fd` names a live descriptor of this process — for
        // `prepare()` that is the fixed inherited slot; adoption takes
        // sole ownership, so nothing else may use the number after.
        let slot = audited::adopt_inherited_fd(fd).map_err(|_| handoff_unavailable())?;
        let conn = fcntl_dupfd_cloexec(&slot, 0).map_err(|_| handoff_unavailable())?;
        // `slot`'s drop closes the fixed descriptor number — upstream's
        // `file.Close()` after `net.FileConn`.
        drop(slot);
        let stat = fstat(&conn).map_err(|_| handoff_unavailable())?;
        if !FileType::from_raw_mode(stat.st_mode).is_socket()
            || socket_type(&conn).map_err(|_| handoff_unavailable())? != SocketType::SEQPACKET
        {
            return Err(handoff_unavailable());
        }
        let local = getsockname(&conn).map_err(|_| handoff_unavailable())?;
        if SocketAddrUnix::try_from(local).is_err() {
            return Err(handoff_unavailable());
        }
        Ok(Self { conn, used: false })
    }

    /// `RetainTargetLock` — exactly one connected target socket and
    /// its raw proof digest to the monitor, then a wait for the
    /// acknowledgement echoing that exact digest. The channel is
    /// single-use upstream-verbatim: `used` is set before the send,
    /// so a failed attempt still consumes it.
    ///
    /// `timeout` bounds the send/ack exchange like upstream's
    /// `conn.SetDeadline(ctx.Deadline())` — `None` mirrors the
    /// no-deadline context (the supervisor's own launch bound still
    /// applies), `Some` pins `SO_RCVTIMEO`/`SO_SNDTIMEO`.
    ///
    /// # Errors
    /// `backup_target_handoff` on any protocol or transport failure.
    pub fn retain_target_lock<Fd: AsFd>(
        &mut self,
        target: Fd,
        proof: [u8; 32],
        timeout: Option<Duration>,
    ) -> Result<(), Failure> {
        if self.used || proof == [0u8; 32] {
            return Err(handoff_unavailable());
        }
        self.used = true;
        if let Some(timeout) = timeout {
            set_socket_timeout(&self.conn, Timeout::Recv, Some(timeout))
                .map_err(|_| handoff_unavailable())?;
            set_socket_timeout(&self.conn, Timeout::Send, Some(timeout))
                .map_err(|_| handoff_unavailable())?;
        }
        let mut frame = [0u8; WORKER_FRAME_SIZE];
        frame[..4].copy_from_slice(&WORKER_MAGIC);
        frame[4] = WORKER_PROTOCOL_VERSION;
        frame[5] = FRAME_TYPE_RETAIN;
        frame[8..40].copy_from_slice(&proof);
        let sent = scm_rights::send(&self.conn, &frame, &[target.as_fd()])
            .map_err(|_| handoff_unavailable())?;
        if sent != WORKER_FRAME_SIZE {
            return Err(handoff_unavailable());
        }
        let mut buf = [0u8; WORKER_FRAME_SIZE];
        let recv = scm_rights::recv_raw(&self.conn, &mut buf).map_err(|_| handoff_unavailable())?;
        if !recv.fds.is_empty()
            || recv.bytes != WORKER_FRAME_SIZE
            || buf[..4] != WORKER_MAGIC
            || buf[4] != WORKER_PROTOCOL_VERSION
            || buf[5] != FRAME_TYPE_ACK
            || buf[7] != 0
        {
            return Err(handoff_unavailable());
        }
        if buf[6] != 0 {
            return Err(handoff_denied());
        }
        if buf[8..40] != proof {
            return Err(handoff_unavailable());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::sync::Mutex;

    struct FakeLease {
        port: Option<u16>,
        proof: String,
        state: Mutex<u8>, // 0 held, 1 released, 2 retained
    }
    impl BackupTargetExclusion for FakeLease {
        fn assert_held(&self) -> Result<(), Failure> {
            if *self.state.lock().unwrap() == 0 {
                Ok(())
            } else {
                Err(Failure::unavailable("test", "not held"))
            }
        }
        fn release(&self) -> Result<(), Failure> {
            let mut s = self.state.lock().unwrap();
            if *s != 0 {
                return Err(Failure::unavailable("test", "not held"));
            }
            *s = 1;
            Ok(())
        }
        fn proof(&self) -> String {
            self.proof.clone()
        }
        fn client_port(&self) -> Option<u16> {
            if *self.state.lock().unwrap() == 0 {
                self.port
            } else {
                None
            }
        }
        fn mark_retained(&self) -> Result<(), Failure> {
            let mut s = self.state.lock().unwrap();
            if *s != 0 {
                return Err(Failure::unavailable("test", "not held"));
            }
            *s = 2;
            Ok(())
        }
    }

    fn lease(port: Option<u16>) -> Arc<FakeLease> {
        Arc::new(FakeLease {
            port,
            proof: format!("sha256:{}", "ab".repeat(32)),
            state: Mutex::new(0),
        })
    }

    /// `RetainTargetLock`/`PrepareTargetLockHandoff`'s validation
    /// surface — exercised without a live monitor over the closed
    /// shapes only (the live CBW1 path is covered by the pair-socket
    /// test below).
    #[test]
    fn proof_decode_matches_upstream_shape() {
        assert!(decode_lock_proof("sha256:deadbeef").is_err());
        assert!(decode_lock_proof(&"ab".repeat(32)).is_err());
        assert!(
            decode_lock_proof(&format!("sha256:{}", "00".repeat(32))).is_err(),
            "all-zero proof refuses"
        );
        let ok = decode_lock_proof(&format!("sha256:{}", "ab".repeat(32))).unwrap();
        assert_eq!(ok[0], 0xab);
        assert_eq!(ok[31], 0xab);
        // Mixed/uppercase hex parses upstream identically (hex.DecodeString);
        // the canonical lease only ever emits lowercase.
        assert!(decode_lock_proof(&format!("sha256:{}", "AB".repeat(32))).is_ok());
    }

    /// A lease that cannot name its session endpoint is like upstream's
    /// failed `Hijack` — refused BEFORE the one-way transition, so the
    /// worker's deferred release path still works.
    #[test]
    fn retainer_refuses_unnamed_endpoint_without_consuming_lease() {
        let l = lease(None);
        let retainer = LocalPostgresSocketRetainer::new(l.clone());
        let mut cb = |_fd: BorrowedFd<'_>, _proof: [u8; 32]| Ok(());
        assert!(retainer.retain_for_post_reap(&mut cb).is_err());
        assert_eq!(*l.state.lock().unwrap(), 0, "lease must stay releasable");
        l.release().unwrap();
    }

    #[test]
    fn retainer_refuses_when_lease_released() {
        let l = lease(Some(4545));
        l.release().unwrap();
        let retainer = LocalPostgresSocketRetainer::new(l);
        let mut cb = |_fd: BorrowedFd<'_>, _proof: [u8; 32]| Ok(());
        assert!(retainer.retain_for_post_reap(&mut cb).is_err());
    }

    /// The live resolution: a real loopback TCP pair stands in for the
    /// PostgreSQL session — the lease records the client's
    /// `inet_client_port()`, the retainer pins the listener's port as
    /// the peer, and the callback receives a valid `F_DUPFD_CLOEXEC`
    /// duplicate of that exact socket before the lease turns retained.
    #[test]
    fn retainer_resolves_dup_marks_and_hands_off() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let client_port = client.local_addr().unwrap().port();
        let client_raw = client.as_raw_fd();

        let l = lease(Some(client_port));
        let retainer = LocalPostgresSocketRetainer::for_test(l.clone(), peer_port);
        let mut seen: Option<(RawFd, [u8; 32])> = None;
        let mut cb = |fd: BorrowedFd<'_>, proof: [u8; 32]| {
            // The duplicate is live only inside the callback — verify
            // it names the same session here, before the close.
            let local = getsockname(fd).unwrap();
            assert_eq!(SocketAddrV4::try_from(local).unwrap().port(), client_port);
            seen = Some((fd.as_raw_fd(), proof));
            Ok(())
        };
        retainer.retain_for_post_reap(&mut cb).unwrap();
        let (dup_fd, proof) = seen.unwrap();
        assert_ne!(dup_fd, client_raw, "callback sees the CLOEXEC duplicate");
        assert_eq!(proof[0], 0xab);
        assert_eq!(*l.state.lock().unwrap(), 2, "lease retained");
        assert!(l.assert_held().is_err());
        assert!(l.release().is_err());
        assert!(l.client_port().is_none());
        // A second retain refuses — `assert_held` already fails.
        let mut cb2 = |_fd: BorrowedFd<'_>, _proof: [u8; 32]| Ok(());
        assert!(retainer.retain_for_post_reap(&mut cb2).is_err());
        drop(client);
    }

    /// A failed handoff still consumes the lease — upstream's
    /// `e.retained = true` already ran before the callback.
    #[test]
    fn retainer_failed_callback_leaves_lease_retained() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let l = lease(Some(client.local_addr().unwrap().port()));
        let retainer = LocalPostgresSocketRetainer::for_test(l.clone(), peer_port);
        let mut cb = |_fd: BorrowedFd<'_>, _proof: [u8; 32]| {
            Err(Failure::unavailable("test", "monitor refused"))
        };
        assert!(retainer.retain_for_post_reap(&mut cb).is_err());
        assert_eq!(*l.state.lock().unwrap(), 2);
        assert!(l.release().is_err());
        drop(client);
    }

    /// The FD5-less shapes: a non-socket fd, a stream socket, and a
    /// non-Unix socket all refuse — upstream's `unixpacket` proof.
    #[test]
    fn prepare_refuses_wrong_socket_shapes() {
        // `prepare()` itself is intentionally not exercised here: in a
        // shared test process fd 5 could name anything, and adoption
        // closes the slot it is handed. `prepare_at` is the audited
        // seam.
        assert!(TargetLockHandoff::prepare_at(-1).is_err());
        use std::os::fd::IntoRawFd as _;
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(TargetLockHandoff::prepare_at(f.into_raw_fd()).is_err());
        // A SOCK_STREAM Unix socket is not `unixpacket`.
        let (stream_side, _peer) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::empty(),
            None,
        )
        .unwrap();
        assert!(TargetLockHandoff::prepare_at(stream_side.into_raw_fd()).is_err());
        // A connected TCP socket is a socket but not AF_UNIX.
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(TargetLockHandoff::prepare_at(tcp.into_raw_fd()).is_err());
    }

    /// The live CBW1 exchange over a real `SOCK_SEQPACKET` pair: the
    /// "monitor" receives the 40-byte frame plus exactly one descriptor
    /// and echoes the proof ack.
    #[test]
    fn handoff_exchanges_frame_descriptor_and_ack() {
        let (worker_side, monitor_side) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::empty(),
            None,
        )
        .unwrap();
        // `into_raw_fd` relinquishes the OwnedFd before adoption — a
        // second Rust owner of the same number is an IO-safety
        // violation, not a test shortcut.
        use std::os::fd::IntoRawFd as _;
        let mut handoff = TargetLockHandoff::prepare_at(worker_side.into_raw_fd()).unwrap();
        // The "target socket" is just another fd — the monitor only
        // needs a real descriptor to receive.
        let target = std::fs::File::open("/dev/null").unwrap();
        let proof = [7u8; 32];
        let monitor = std::thread::spawn(move || {
            let mut frame = [0u8; WORKER_FRAME_SIZE];
            let received = scm_rights::recv_raw(&monitor_side, &mut frame).unwrap();
            assert_eq!(received.bytes, WORKER_FRAME_SIZE);
            assert_eq!(received.fds.len(), 1);
            assert_eq!(&frame[..4], b"CBW1");
            assert_eq!(frame[4], WORKER_PROTOCOL_VERSION);
            assert_eq!(frame[5], FRAME_TYPE_RETAIN);
            assert_eq!(&frame[8..40], &[7u8; 32]);
            let mut ack = [0u8; WORKER_FRAME_SIZE];
            ack[..4].copy_from_slice(b"CBW1");
            ack[4] = WORKER_PROTOCOL_VERSION;
            ack[5] = FRAME_TYPE_ACK;
            ack[8..40].copy_from_slice(&proof);
            let sent = scm_rights::send(&monitor_side, &ack, &[]).unwrap();
            assert_eq!(sent, WORKER_FRAME_SIZE);
        });
        handoff
            .retain_target_lock(&target, [7u8; 32], Some(Duration::from_secs(5)))
            .unwrap();
        monitor.join().unwrap();
        // Single-use upstream-verbatim: a second retain refuses.
        assert!(
            handoff
                .retain_target_lock(&target, [7u8; 32], None)
                .is_err()
        );
    }

    /// The ack mismatch paths — denial byte and wrong proof echo.
    #[test]
    fn handoff_refuses_denied_and_mismatched_acks() {
        for (status, echo) in [(1u8, [9u8; 32]), (0u8, [7u8; 32])] {
            let (worker_side, monitor_side) = rustix::net::socketpair(
                rustix::net::AddressFamily::UNIX,
                rustix::net::SocketType::SEQPACKET,
                rustix::net::SocketFlags::empty(),
                None,
            )
            .unwrap();
            use std::os::fd::IntoRawFd as _;
            let mut handoff = TargetLockHandoff::prepare_at(worker_side.into_raw_fd()).unwrap();
            let target = std::fs::File::open("/dev/null").unwrap();
            let monitor = std::thread::spawn(move || {
                let mut frame = [0u8; WORKER_FRAME_SIZE];
                let _ = scm_rights::recv_raw(&monitor_side, &mut frame).unwrap();
                let mut ack = [0u8; WORKER_FRAME_SIZE];
                ack[..4].copy_from_slice(b"CBW1");
                ack[4] = WORKER_PROTOCOL_VERSION;
                ack[5] = FRAME_TYPE_ACK;
                ack[6] = status; // denial byte (0 = nominal)
                ack[8..40].copy_from_slice(&echo);
                let _ = scm_rights::send(&monitor_side, &ack, &[]);
            });
            assert!(
                handoff
                    .retain_target_lock(&target, [9u8; 32], Some(Duration::from_secs(5)))
                    .is_err()
            );
            monitor.join().unwrap();
        }
    }
}
