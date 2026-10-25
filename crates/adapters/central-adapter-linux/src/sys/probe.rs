//! Re-exec probe harness — upstream `hardening_filter_test.go`'s
//! `TestMain`/`runProbe` shape. `SECCOMP_RET_KILL_PROCESS` cannot be
//! probed in-process (a violation kills the process — that *is* what is
//! being asserted), and `unshare`/hardening calls mutate the caller's
//! process state, so each probe re-execs this test binary with
//! `CENTRAL_SYS_PROBE` set to the probe mode and a `--exact` test-name
//! filter. The child test reads the mode, runs the boundary call, and
//! exits; the parent asserts the child's exit status (clean exit, exit
//! code, or death by `SIGSYS`).

use std::process::{ExitStatus, Stdio};

/// The environment variable a probe child inspects for its mode —
/// upstream's `CENTRAL_SECCOMP_FILTER_PROBE`.
pub(crate) const PROBE_ENV: &str = "CENTRAL_SYS_PROBE";

/// Re-exec this test binary on `test_name` (its full `module::path`)
/// with `CENTRAL_SYS_PROBE` set to `mode`. Returns the child's exit
/// status — `ExitStatus::signal()` (via `ExitStatusExt`) distinguishes
/// a `SIGSYS` kill from a clean exit or a panic.
pub(crate) fn run_on(test_name: &'static str, mode: &str) -> ExitStatus {
    run_on_with(test_name, mode, &[])
}

/// [`run_on`] plus extra `NAME=value` environment pairs.
pub(crate) fn run_on_with(test_name: &'static str, mode: &str, env: &[(&str, &str)]) -> ExitStatus {
    let exe = std::env::current_exe().expect("current test binary path");
    std::process::Command::new(exe)
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(PROBE_ENV, mode)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
        .expect("spawn probe child")
}

/// [`run_on`] for probes whose child takes its mode from the test
/// name's own fixed value — the common case, where one `#[test]` is
/// one probe.
pub(crate) fn run(test_name: &'static str) -> ExitStatus {
    run_on(test_name, "run")
}

/// Whether this process is running as a probe child for `mode` — the
/// first statement of every probe-child `#[test]`, so an ordinary
/// `cargo test` run returns early and the test trivially passes.
pub(crate) fn is(mode: &str) -> bool {
    std::env::var(PROBE_ENV).ok().as_deref() == Some(mode)
}
