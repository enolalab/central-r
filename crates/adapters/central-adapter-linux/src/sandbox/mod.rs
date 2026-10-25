//! `sandbox` — the sandbox launcher daemon and launch machinery
//! (R5 task 9 / A06), ported from upstream `internal/sandbox/`:
//!
//! - [`domain`] — `LaunchRequest`/`ResourceLimits`/`LaunchEvidence`
//!   (`domain.go`), descriptor-bound: the workspace root is the
//!   frame's one `SCM_RIGHTS` descriptor, never a JSON field;
//! - [`envelope`] — `DefaultLimits`/`HardLimits`, `ValidateLimits`,
//!   `ValidateBinary`, the `central-agent` identity, and the 600 s
//!   deadline cap (`envelope.go`, `app/launch_service.go`);
//! - [`launcher`] — `Launch` (`launcher_linux.go`): cgroup subtree,
//!   `clone3`-born namespaced child at the `central-agent` identity,
//!   `Pdeathsig = SIGKILL`, the deadline → SIGTERM → 10 s → SIGKILL
//!   ladder, pidfd signaling, cgroup cleanup;
//! - [`settle`] — `SettleOutcome` + `DefaultGracePeriod`
//!   (`settle.go`);
//! - [`daemon`] — `ServeLauncher` + `handleLaunchConn`
//!   (`daemon_linux.go`) hardened to the A06 contract: `SO_PEERCRED`
//!   admission, one-descriptor-bound request frames, and the denial
//!   matrix upstream never enforced (env injection, absolute-path
//!   escapes, extra descriptors, forged workspace fields);
//! - [`path_resolve`] — descriptor-relative resolution beneath the
//!   delegated workspace descriptor (`path_resolve.go`), the
//!   `sys::openat2` containment surface.

#[forbid(unsafe_code)]
pub mod daemon;
#[forbid(unsafe_code)]
pub mod domain;
#[forbid(unsafe_code)]
pub mod envelope;
#[forbid(unsafe_code)]
pub mod launcher;
#[forbid(unsafe_code)]
pub mod path_resolve;
#[forbid(unsafe_code)]
pub mod settle;
