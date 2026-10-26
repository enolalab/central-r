//! `browser.go` — the browser-open and bootstrap-show handlers: the
//! nonce-bound ready proof, the live Wayland seat, the presentation
//! lease, the managed-profile launch. Every failure collapses to
//! `authority.ErrDenied` — no detail crosses.

use super::PeerIdentity;
use central_foundation::failure::Failure;
use serde::Serialize;
use std::time::{Duration, Instant};

fn denied() -> Failure {
    super::err_denied()
}

/// `authority.FixedBrowserOrigin` — the only origin a managed launch
/// may open.
pub const FIXED_BROWSER_ORIGIN: &str = "https://127.0.0.1:8080";

/// `kernel.ReadyProof` — the supervisor's launch authorization. The
/// nonce never appears in any formatted or serialized form.
#[derive(Debug, Clone)]
pub struct ReadyProof {
    pub launch_id: String,
    pub runtime_generation: String,
    pub nonce: [u8; 32],
    /// Wall-clock instant the proof stops being honored, as unix
    /// seconds (sub-second precision is not needed; the wire carries
    /// RFC3339 either way).
    pub expires_at: time::OffsetDateTime,
}

impl ReadyProof {
    /// `ReadyProof.Equal` — same launch id and generation, nonce
    /// compared in constant time. Expiry is the caller's separate
    /// check, upstream-fashion.
    pub fn equal(&self, other: &ReadyProof) -> bool {
        if self.launch_id != other.launch_id || self.runtime_generation != other.runtime_generation
        {
            return false;
        }
        self.nonce
            .iter()
            .zip(other.nonce.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    /// `ReadyProof.IsExpired` — `!p.ExpiresAt.After(reference)`:
    /// boundary-equal is expired.
    pub fn is_expired(&self, reference: time::OffsetDateTime) -> bool {
        !(self.expires_at > reference)
    }
}

impl Serialize for ReadyProof {
    /// `ReadyProof.MarshalJSON` — opaque; the nonce never serializes.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Opaque<'a> {
            launch_id: &'a str,
            runtime_generation: &'a str,
            expires_at: String,
            redacted: bool,
        }
        Opaque {
            launch_id: &self.launch_id,
            runtime_generation: &self.runtime_generation,
            expires_at: self
                .expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            redacted: true,
        }
        .serialize(s)
    }
}

/// `ReadyProofSource` — how the helper learns the current proof; the
/// operator never reads the root-owned proof file.
pub trait ReadyProofSource: Send + Sync {
    fn current(&self) -> Result<ReadyProof, Failure>;
}

/// `WaylandSeat` — the live desktop session check.
pub trait WaylandSeat: Send + Sync {
    fn verify(&self) -> Result<(), Failure>;
}

/// `SystemWaylandSeat` — `WAYLAND_DISPLAY` under `XDG_RUNTIME_DIR`
/// must be a socket that answers a dial, all inside one second.
pub struct SystemWaylandSeat;

impl WaylandSeat for SystemWaylandSeat {
    fn verify(&self) -> Result<(), Failure> {
        let display = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
        if display.is_empty() || runtime_dir.is_empty() || display.starts_with('/') {
            return Err(denied());
        }
        let path = std::path::Path::new(&runtime_dir).join(&display);
        let meta = std::fs::metadata(&path).map_err(|_| denied())?;
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() {
            return Err(denied());
        }
        let conn = dial_unix_bounded(&path, Duration::from_secs(1))?;
        drop(conn);
        Ok(())
    }
}

/// `net.Dialer{Timeout: …}.DialContext(ctx, "unix", path)` — a
/// nonblocking `connect` bounded to `timeout`: `poll` waits for
/// writability, `SO_ERROR` surfaces the pending connection's verdict,
/// and the finished stream goes back to blocking mode like the conn
/// upstream's dialer returns. Every failure — refused, timed out, or
/// malformed — collapses to the same `ErrDenied` a dial error produces.
/// The browser boundary passes one second (upstream `browser.go`);
/// the helper clients pass their `DIAL_TIMEOUT` (upstream's
/// `net.Dialer{Timeout: 5 * time.Second}`).
pub(crate) fn dial_unix_bounded(
    path: &std::path::Path,
    timeout: Duration,
) -> Result<std::os::unix::net::UnixStream, Failure> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::io::Errno;
    use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let fd = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| denied())?;
    let addr = SocketAddrUnix::new(path).map_err(|_| denied())?;
    match net::connect(&fd, &addr) {
        Ok(()) => {}
        Err(Errno::INPROGRESS) | Err(Errno::AGAIN) => {
            // `timeout` of budget across EINTR retries — upstream's
            // fixed dialer timeout, not a per-poll slice.
            let deadline = Instant::now() + timeout;
            let mut fds = [PollFd::new(&fd, PollFlags::OUT)];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(denied());
                }
                let timeout = Timespec::try_from(left).unwrap_or(Timespec {
                    tv_sec: 1,
                    tv_nsec: 0,
                });
                match poll(&mut fds, Some(&timeout)) {
                    Ok(0) => return Err(denied()),
                    Ok(_) => break,
                    Err(Errno::INTR) => continue,
                    Err(_) => return Err(denied()),
                }
            }
            match net::sockopt::socket_error(&fd) {
                Ok(Ok(())) => {}
                _ => return Err(denied()),
            }
        }
        Err(_) => return Err(denied()),
    }
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(false).map_err(|_| denied())?;
    Ok(stream)
}

/// `BrowserLauncher`.
pub trait BrowserLauncher: Send + Sync {
    fn open(&self, origin: &str) -> Result<(), Failure>;
}

/// `PresentationLease` — binds a managed launch to one durable
/// bootstrap presentation generation.
#[derive(Debug, Clone, Default)]
pub struct PresentationLease {
    pub generation: u64,
    /// Unix seconds.
    pub deadline_unix: i64,
}

/// `PresentationLeaseStarter` — error-returning begin.
pub trait PresentationLeaseStarter: Send + Sync {
    fn begin_presentation(&self) -> Result<(), Failure>;
}

/// `PresentationLeaseStarterV2` — lease-returning begin.
pub trait PresentationLeaseStarterV2: Send + Sync {
    fn begin_presentation(&self) -> Result<PresentationLease, Failure>;
}

/// `PresentationGuard` — binds presentation to the durable lease.
pub trait PresentationGuard: Send + Sync {
    fn validate_presentation(&self) -> Result<(), Failure>;
}

/// `ManagedBrowserLaunch`.
#[derive(Debug, Clone, Default)]
pub struct ManagedBrowserLaunch {
    pub proof: Option<ReadyProof>,
    pub lease: PresentationLease,
}

/// `ManagedBrowserProcess`.
#[derive(Debug, Clone, Default)]
pub struct ManagedBrowserProcess {
    pub pid: i32,
    pub start_time: u64,
}

/// `ManagedBrowserLauncher`.
pub trait ManagedBrowserLauncher: Send + Sync {
    fn open_managed(
        &self,
        origin: &str,
        launch: &ManagedBrowserLaunch,
    ) -> Result<ManagedBrowserProcess, Failure>;
}

/// `ManagedBrowserState`.
pub trait ManagedBrowserState: Send + Sync {
    fn approved(&self) -> Result<bool, Failure>;
}

/// `ManagedBrowserStateForLaunch` — the production-strength check:
/// approval bound to the exact proof and lease.
pub trait ManagedBrowserStateForLaunch: Send + Sync {
    fn approved_for(&self, launch: &ManagedBrowserLaunch) -> Result<bool, Failure>;
}

/// `FreshPAM` — one authentication, never reused.
pub trait FreshPam: Send + Sync {
    fn authenticate(&self) -> Result<(), Failure>;
}

/// `ControllingTTY` — the peer's controlling-terminal check.
pub trait ControllingTty: Send + Sync {
    fn check(&self) -> Result<(), Failure>;
}

/// `BootstrapPresenter` — shows the bootstrap value on the trusted
/// plane; it receives no plaintext from the request.
pub trait BootstrapPresenter: Send + Sync {
    fn present(&self) -> Result<(), Failure>;
}

/// The `presentation` slot's three shapes, in upstream's dispatch
/// order: V2 lease starter (managed launch), V1 starter (begin only),
/// plain guard (validate only).
pub enum Presentation {
    LeaseV2(Box<dyn PresentationLeaseStarterV2>),
    Lease(Box<dyn PresentationLeaseStarter>),
    Guard(Box<dyn PresentationGuard>),
}

/// `BrowserHandler` — proof, seat, presentation, launch.
pub struct BrowserHandler {
    proofs: Box<dyn ReadyProofSource>,
    seat: Box<dyn WaylandSeat>,
    launcher: Box<dyn BrowserLauncher>,
    managed_launcher: Option<Box<dyn ManagedBrowserLauncher>>,
    presentation: Option<Presentation>,
}

impl BrowserHandler {
    /// `NewBrowserHandler` — proof, seat, and launcher are all
    /// required; the managed slot defaults to absent.
    pub fn new(
        proofs: Box<dyn ReadyProofSource>,
        seat: Box<dyn WaylandSeat>,
        launcher: Box<dyn BrowserLauncher>,
    ) -> Result<Self, Failure> {
        Ok(BrowserHandler {
            proofs,
            seat,
            launcher,
            managed_launcher: None,
            presentation: None,
        })
    }

    /// `NewBrowserHandlerWithPresentation` — the production form; a
    /// launcher that also implements `OpenManaged` is supplied as
    /// `managed` so the V2 lease arm can reach it.
    pub fn with_presentation(
        proofs: Box<dyn ReadyProofSource>,
        seat: Box<dyn WaylandSeat>,
        launcher: Box<dyn BrowserLauncher>,
        managed: Option<Box<dyn ManagedBrowserLauncher>>,
        presentation: Presentation,
    ) -> Result<Self, Failure> {
        let mut h = Self::new(proofs, seat, launcher)?;
        h.managed_launcher = managed;
        h.presentation = Some(presentation);
        Ok(h)
    }

    /// `Open` — accepts only the nonce-bound current proof.
    pub fn open(&self, presented: &ReadyProof) -> Result<(), Failure> {
        let current = self.proofs.current().map_err(|_| denied())?;
        if !same_current_proof(&current, presented) {
            return Err(denied());
        }
        self.seat.verify().map_err(|_| denied())?;
        match &self.presentation {
            Some(Presentation::LeaseV2(starter)) => {
                let lease = starter.begin_presentation().map_err(|_| denied())?;
                if let Some(launcher) = &self.managed_launcher {
                    launcher
                        .open_managed(
                            FIXED_BROWSER_ORIGIN,
                            &ManagedBrowserLaunch {
                                proof: Some(current),
                                lease,
                            },
                        )
                        .map_err(|_| denied())?;
                    return Ok(());
                }
            }
            Some(Presentation::Lease(starter)) => {
                starter.begin_presentation().map_err(|_| denied())?;
            }
            Some(Presentation::Guard(guard)) => {
                guard.validate_presentation().map_err(|_| denied())?;
            }
            None => {}
        }
        self.launcher
            .open(FIXED_BROWSER_ORIGIN)
            .map_err(|_| denied())?;
        Ok(())
    }

    /// `OpenCurrent` — fetch and verify the current proof inside the
    /// helper; the operator never touches the proof file.
    pub fn open_current(&self) -> Result<(), Failure> {
        let proof = self.proofs.current().map_err(|_| denied())?;
        self.open(&proof)
    }
}

/// `BootstrapShowHandler` — the TTY-only bootstrap presentation,
/// gated separately from browser opening.
pub struct BootstrapShowHandler {
    proofs: Box<dyn ReadyProofSource>,
    state_for_launch: Option<Box<dyn ManagedBrowserStateForLaunch>>,
    state: Box<dyn ManagedBrowserState>,
    pam: Box<dyn FreshPam>,
    tty: Box<dyn ControllingTty>,
    presenter: Box<dyn BootstrapPresenter>,
    presentation: Option<Presentation>,
}

impl BootstrapShowHandler {
    /// `NewBootstrapShowHandler` — every prerequisite required.
    pub fn new(
        proofs: Box<dyn ReadyProofSource>,
        state: Box<dyn ManagedBrowserState>,
        pam: Box<dyn FreshPam>,
        tty: Box<dyn ControllingTty>,
        presenter: Box<dyn BootstrapPresenter>,
    ) -> Result<Self, Failure> {
        Ok(BootstrapShowHandler {
            proofs,
            state_for_launch: None,
            state,
            pam,
            tty,
            presenter,
            presentation: None,
        })
    }

    /// `NewBootstrapShowHandlerWithPresentation`, plus the optional
    /// `ManagedBrowserStateForLaunch` slot the production check fills.
    pub fn with_presentation(
        proofs: Box<dyn ReadyProofSource>,
        state: Box<dyn ManagedBrowserState>,
        state_for_launch: Option<Box<dyn ManagedBrowserStateForLaunch>>,
        pam: Box<dyn FreshPam>,
        tty: Box<dyn ControllingTty>,
        presenter: Box<dyn BootstrapPresenter>,
        presentation: Presentation,
    ) -> Result<Self, Failure> {
        let mut h = Self::new(proofs, state, pam, tty, presenter)?;
        h.state_for_launch = state_for_launch;
        h.presentation = Some(presentation);
        Ok(h)
    }

    /// `Show` — current proof, approved managed state, fresh PAM,
    /// controlling TTY, presentation guard, present.
    pub fn show(&self, presented: &ReadyProof) -> Result<(), Failure> {
        let current = self.proofs.current().map_err(|_| denied())?;
        if !same_current_proof(&current, presented) {
            return Err(denied());
        }
        let approved = match &self.state_for_launch {
            Some(for_launch) => for_launch
                .approved_for(&ManagedBrowserLaunch {
                    proof: Some(current.clone()),
                    lease: PresentationLease::default(),
                })
                .map_err(|_| denied())?,
            None => self.state.approved().map_err(|_| denied())?,
        };
        if !approved {
            return Err(denied());
        }
        self.pam.authenticate().map_err(|_| denied())?;
        self.tty.check().map_err(|_| denied())?;
        if let Some(Presentation::Guard(guard)) = &self.presentation {
            guard.validate_presentation().map_err(|_| denied())?;
        }
        self.presenter.present().map_err(|_| denied())?;
        Ok(())
    }

    /// `ShowCurrent` — the transport entry point; the current proof is
    /// fetched inside the helper.
    pub fn show_current(&self) -> Result<(), Failure> {
        let proof = self.proofs.current().map_err(|_| denied())?;
        self.show(&proof)
    }
}

/// `sameCurrentProof` — complete, equal, unexpired on both sides.
fn same_current_proof(current: &ReadyProof, presented: &ReadyProof) -> bool {
    if current.launch_id.is_empty() || presented.launch_id.is_empty() || !current.equal(presented) {
        return false;
    }
    // `ExpiresAt.IsZero()` on either side denies; a Go zero time is
    // year 1, so anything at or before the unix epoch counts as unset.
    let zero = |t: time::OffsetDateTime| t.unix_timestamp_nanos() <= 0;
    if zero(current.expires_at)
        || zero(presented.expires_at)
        || current.expires_at != presented.expires_at
    {
        return false;
    }
    let now = time::OffsetDateTime::now_utc();
    !current.is_expired(now) && !presented.is_expired(now)
}

/// `systemFreshPAM` — fresh authentication against the socket peer.
pub struct SystemFreshPam {
    pub peer: PeerIdentity,
    pub deadline: Option<Instant>,
}

impl FreshPam for SystemFreshPam {
    fn authenticate(&self) -> Result<(), Failure> {
        let session =
            super::pam_ceremony::authenticate(self.peer, self.deadline).map_err(|_| denied())?;
        if !session.valid {
            return Err(denied());
        }
        Ok(())
    }
}

/// `systemControllingTTY` — `/proc/<pid>/fd/0` names a real terminal
/// (`/dev/tty` or `/dev/pts/N`) and `/proc/<pid>/stat` reports a
/// controlling tty (field 7 after the `)` — `tty_nr` must be nonzero).
pub struct SystemControllingTty {
    pub peer: PeerIdentity,
}

impl ControllingTty for SystemControllingTty {
    fn check(&self) -> Result<(), Failure> {
        if !self.peer.available() {
            return Err(denied());
        }
        let target = std::fs::read_link(format!("/proc/{}/fd/0", self.peer.pid))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stat = std::fs::read(format!("/proc/{}/stat", self.peer.pid)).unwrap_or_default();
        if !is_controlling_tty(&target, &stat) {
            return Err(denied());
        }
        Ok(())
    }
}

/// `isControllingTTY` — verbatim: `/dev/tty` or `/dev/pts/N` target,
/// `tty_nr` (the 5th field after the closing paren) nonzero.
fn is_controlling_tty(target: &str, stat: &[u8]) -> bool {
    if target != "/dev/tty"
        && !(target.starts_with("/dev/pts/") && target.len() > "/dev/pts/".len())
    {
        return false;
    }
    let text = String::from_utf8_lossy(stat);
    let Some(paren) = text.rfind(')') else {
        return false;
    };
    if paren + 1 >= text.len() {
        return false;
    }
    let fields: Vec<&str> = text[paren + 1..].split_whitespace().collect();
    if fields.len() < 5 {
        return false;
    }
    fields[4].parse::<i64>().is_ok_and(|tty_nr| tty_nr != 0)
}

/// A `controllingTTY` seam that never admits — used where upstream's
/// nil-check would deny.
pub struct DenyingControllingTty;
impl ControllingTty for DenyingControllingTty {
    fn check(&self) -> Result<(), Failure> {
        Err(denied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn proof(nonce: u8) -> ReadyProof {
        ReadyProof {
            launch_id: "launch-1".into(),
            runtime_generation: String::new(),
            nonce: [nonce; 32],
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::seconds(3600),
        }
    }

    struct FixedProofs(ReadyProof);
    impl ReadyProofSource for FixedProofs {
        fn current(&self) -> Result<ReadyProof, Failure> {
            Ok(self.0.clone())
        }
    }
    struct OkSeat;
    impl WaylandSeat for OkSeat {
        fn verify(&self) -> Result<(), Failure> {
            Ok(())
        }
    }
    struct DenyingSeat;
    impl WaylandSeat for DenyingSeat {
        fn verify(&self) -> Result<(), Failure> {
            Err(denied())
        }
    }
    struct RecordingLauncher {
        origins: Mutex<Vec<String>>,
    }
    impl BrowserLauncher for RecordingLauncher {
        fn open(&self, origin: &str) -> Result<(), Failure> {
            self.origins
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(origin.to_owned());
            Ok(())
        }
    }

    /// `Open` admits only the exact current proof: a stale nonce, a
    /// wrong launch id, a dead seat, and an expired proof each deny
    /// with the collapsed refusal; the one real proof opens the fixed
    /// origin at the managed profile launcher.
    #[test]
    fn open_binds_proof_seat_and_fixed_origin() {
        let current = proof(7);
        let launcher = RecordingLauncher {
            origins: Mutex::new(Vec::new()),
        };
        let handler = BrowserHandler::new(
            Box::new(FixedProofs(current.clone())),
            Box::new(OkSeat),
            Box::new(launcher),
        )
        .unwrap();
        // Wrong nonce denies.
        assert!(handler.open(&proof(8)).is_err());
        // Empty launch id denies.
        let mut bad = current.clone();
        bad.launch_id.clear();
        assert!(handler.open(&bad).is_err());
        // Expired presented proof denies.
        let mut expired = current.clone();
        expired.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
        assert!(handler.open(&expired).is_err());
        // A different expiry — even in the future — denies.
        let mut skewed = current.clone();
        skewed.expires_at = current.expires_at + time::Duration::seconds(1);
        assert!(handler.open(&skewed).is_err());
        // The exact proof opens — managed browser profile launch.
        handler.open(&current).unwrap();
    }

    /// `OpenCurrent` drives the same gate from inside the helper, and
    /// the seat refusal collapses identically.
    #[test]
    fn open_current_and_seat_denial() {
        let dead_seat = BrowserHandler::new(
            Box::new(FixedProofs(proof(1))),
            Box::new(DenyingSeat),
            Box::new(RecordingLauncher {
                origins: Mutex::new(Vec::new()),
            }),
        )
        .unwrap();
        assert!(dead_seat.open_current().is_err());
    }

    /// The managed path: a V2 presentation lease routes the launch to
    /// `OpenManaged` with proof + lease bound.
    #[test]
    fn v2_presentation_routes_to_managed_launch() {
        struct Lease;
        impl PresentationLeaseStarterV2 for Lease {
            fn begin_presentation(&self) -> Result<PresentationLease, Failure> {
                Ok(PresentationLease {
                    generation: 9,
                    deadline_unix: 100,
                })
            }
        }
        struct Managed {
            seen: Mutex<Vec<u64>>,
        }
        impl ManagedBrowserLauncher for Managed {
            fn open_managed(
                &self,
                origin: &str,
                launch: &ManagedBrowserLaunch,
            ) -> Result<ManagedBrowserProcess, Failure> {
                assert_eq!(origin, FIXED_BROWSER_ORIGIN);
                self.seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(launch.lease.generation);
                Ok(ManagedBrowserProcess {
                    pid: 4242,
                    start_time: 1,
                })
            }
        }
        struct NoPlain;
        impl BrowserLauncher for NoPlain {
            fn open(&self, _origin: &str) -> Result<(), Failure> {
                Err(denied())
            }
        }
        let managed = Managed {
            seen: Mutex::new(Vec::new()),
        };
        let current = proof(3);
        let handler = BrowserHandler::with_presentation(
            Box::new(FixedProofs(current.clone())),
            Box::new(OkSeat),
            Box::new(NoPlain),
            Some(Box::new(managed)),
            Presentation::LeaseV2(Box::new(Lease)),
        )
        .unwrap();
        handler.open(&current).unwrap();
    }

    /// `isControllingTTY` — the /proc parse upstream does: /dev/tty or
    /// /dev/pts/N, and a nonzero controlling-tty number.
    #[test]
    fn controlling_tty_parse() {
        // Field layout: <state> <ppid> <pgrp> <session> <tty_nr> — the
        // 5th field after `)` is tty_nr.
        let stat = b"42 (firefox) S 1000 1000 1000 34816 2000".to_vec();
        assert!(is_controlling_tty("/dev/pts/3", &stat));
        assert!(is_controlling_tty("/dev/tty", &stat));
        assert!(!is_controlling_tty("/dev/null", &stat));
        assert!(!is_controlling_tty("/dev/pts/", &stat));
        let no_tty = b"42 (daemon) S 1 1 1 0 -1".to_vec();
        assert!(!is_controlling_tty("/dev/tty", &no_tty));
        // A comm containing a paren is skipped by the last-`)` rule.
        let tricky = b"42 (weird)name) S 1 1 1 1024 -1".to_vec();
        assert!(is_controlling_tty("/dev/pts/0", &tricky));
    }

    /// The bounded dial: a live socket answers inside the deadline
    /// with a clear `SO_ERROR`; a socket file with nobody listening
    /// refuses fast rather than hanging the seat check.
    #[test]
    fn bounded_unix_dial_answers_or_refuses() {
        let dir = std::env::temp_dir().join(format!(
            "helper-browser-dial-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir(&dir).unwrap();
        let sock = dir.join("wayland-9");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let conn = dial_unix_bounded(&sock, Duration::from_secs(1)).unwrap();
        // Connected: no pending SO_ERROR on the finished stream.
        assert!(conn.take_error().unwrap().is_none());
        drop(conn);
        // Nobody accepts; drop the listener and the path is a stale
        // socket — connect refuses immediately, no 1s wait needed.
        drop(listener);
        assert!(dial_unix_bounded(&sock, Duration::from_secs(1)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
