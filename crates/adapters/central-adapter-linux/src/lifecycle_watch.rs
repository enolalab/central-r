//! Lifecycle boundary watches — the port of upstream `serveFDWatch` /
//! `servePIDFDWatch` (`cmd/central/serve_monitors.go`).
//!
//! The installed runtime supervisor hands `central serve` a controller
//! descriptor (`CENTRAL_CONTROLLER_FD`) plus supervisor/parent process
//! ids (`CENTRAL_SUPERVISOR_PID`, `CENTRAL_PARENT_PID`; each defaults to
//! the parent pid). Each boundary is polled for its "trip" edge and the
//! kernel's lifecycle monitor reports the first.
//!
//! Unsafe-free boundary note: the workspace forbids `unsafe` here, so
//! the supervisor-inherited descriptor is re-opened through
//! `/proc/self/fd/{n}` — an `open` of the procfs link is a `dup` of the
//! same file description, so a supervisor-side close still surfaces as
//! `POLLHUP`, and the inherited descriptor itself is left untouched
//! (upstream `Close` releases it; the dup is released instead — the
//! supervisor's readiness semantics are unchanged). `rustix::event` is
//! not an enabled feature, so readiness is observed through Tokio's
//! reactor ([`AsyncFd`]) rather than a raw `poll(2)` loop. Upstream
//! distinguishes `POLLIN` from `POLLHUP|POLLERR|POLLNVAL` on the
//! controller descriptor; `AsyncFd` collapses them — acceptable because
//! the supervisor channel never carries data, so `POLLIN` only ever
//! co-occurs with a hangup/error edge.
//!
//! [`BoundaryWatch::wait`] resolves only on a trip; cancellation is
//! future drop, matching the kernel's supervisor model.

use std::os::unix::io::{OwnedFd, RawFd};
use std::os::unix::process::parent_id;

use central_foundation::failure::Failure;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use tokio::io::unix::AsyncFd;

/// `CENTRAL_CONTROLLER_FD` — the supervisor-inherited descriptor whose
/// disconnect means an intentional stop.
pub const ENV_CONTROLLER_FD: &str = "CENTRAL_CONTROLLER_FD";
/// `CENTRAL_SUPERVISOR_PID` — the supervisor process to watch.
pub const ENV_SUPERVISOR_PID: &str = "CENTRAL_SUPERVISOR_PID";
/// `CENTRAL_PARENT_PID` — the direct parent process to watch.
pub const ENV_PARENT_PID: &str = "CENTRAL_PARENT_PID";

fn invalid(msg: &'static str) -> Failure {
    Failure::invalid("lifecycle_watch_invalid", msg)
}

fn unavailable(msg: &'static str) -> Failure {
    Failure::unavailable("lifecycle_watch", msg)
}

/// `configuredFD` — parse a supervisor-inherited descriptor number.
///
/// # Errors
/// `Failure::invalid` when the variable is unset or not a non-negative
/// descriptor.
pub fn configured_fd(
    name: &str,
    getenv: impl Fn(&str) -> Option<String>,
) -> Result<RawFd, Failure> {
    let value = getenv(name).ok_or_else(|| invalid("boundary descriptor is not provisioned"))?;
    let fd: RawFd = value
        .trim()
        .parse()
        .map_err(|_| invalid("boundary descriptor is invalid"))?;
    if fd < 0 {
        return Err(invalid("boundary descriptor is invalid"));
    }
    Ok(fd)
}

/// `configuredPID` — parse a process id, defaulting to `fallback`
/// (upstream defaults to `os.Getppid()`); rejects `<= 1` and self.
///
/// # Errors
/// `Failure::invalid` when the value is not a usable pid.
pub fn configured_pid(
    _name: &str,
    fallback: u32,
    getenv: impl Fn(&str) -> Option<String>,
) -> Result<u32, Failure> {
    let value = getenv(_name)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(i64::from(fallback));
    if value <= 1 || value == i64::from(std::process::id()) {
        return Err(invalid("boundary process id is invalid"));
    }
    u32::try_from(value).map_err(|_| invalid("boundary process id is invalid"))
}

/// The fallback pid upstream uses (`os.Getppid`).
#[must_use]
pub fn default_parent_pid() -> u32 {
    parent_id()
}

/// One observed lifecycle boundary — readiness on its descriptor means
/// the boundary tripped.
pub struct BoundaryWatch {
    fd: AsyncFd<OwnedFd>,
    label: &'static str,
}

impl BoundaryWatch {
    /// `newServeFDWatch` — re-opens the supervisor-inherited descriptor
    /// through procfs (see the module note) and registers it with the
    /// reactor.
    ///
    /// # Errors
    /// `Failure::unavailable` when the descriptor cannot be polled.
    pub fn from_inherited_fd(fd: RawFd, label: &'static str) -> Result<Self, Failure> {
        if fd < 0 {
            return Err(invalid("boundary descriptor is invalid"));
        }
        let dup = std::fs::File::open(format!("/proc/self/fd/{fd}"))
            .map_err(|_| unavailable("boundary descriptor is unavailable"))?;
        let owned: OwnedFd = dup.into();
        Self::register(owned, label)
    }

    /// `newServePIDFDWatch` — opens a pidfd for `pid` and registers it
    /// with the reactor; the pidfd becomes readable when the process
    /// exits.
    ///
    /// # Errors
    /// `Failure::unavailable` when the kernel cannot open the pidfd.
    pub fn for_pid(pid: u32, label: &'static str) -> Result<Self, Failure> {
        let pid = Pid::from_raw(pid.cast_signed())
            .ok_or_else(|| invalid("boundary process id is invalid"))?;
        let fd = pidfd_open(pid, PidfdFlags::empty())
            .map_err(|_| unavailable("boundary pidfd is unavailable"))?;
        Self::register(fd, label)
    }

    fn register(fd: OwnedFd, label: &'static str) -> Result<Self, Failure> {
        Ok(Self {
            // `AsyncFd::new` is deprecated only because the generic
            // signature cannot prove the caller owns the descriptor —
            // `OwnedFd` is owned by construction (re-opened through
            // procfs or `pidfd_open` above), so registration cannot
            // alias a descriptor another owner polls. The `register`
            // replacement is `unsafe` and this crate forbids unsafe.
            #[allow(deprecated)]
            fd: AsyncFd::new(fd).map_err(|_| unavailable("boundary watch registration failed"))?,
            label,
        })
    }

    /// Resolves when the boundary trips. The controller descriptor
    /// trips on hangup/error/invalid (upstream revents filter); the
    /// pidfd on any readiness (the process exited).
    ///
    /// # Errors
    /// `Failure::unavailable` — the boundary tripped or the reactor
    /// wait itself failed.
    pub async fn wait(&self) -> Result<(), Failure> {
        let label = self.label;
        let _guard = self
            .fd
            .readable()
            .await
            .map_err(|_| unavailable("boundary poll failed"))?;
        Err(Failure::unavailable(
            "lifecycle_watch",
            match label {
                "controller" => "controller boundary disconnected",
                _ => "process boundary exited",
            },
        ))
    }
}
