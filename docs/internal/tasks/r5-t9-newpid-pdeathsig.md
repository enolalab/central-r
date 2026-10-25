# R5 T9 — `PR_SET_PDEATHSIG` liveness check condemns every `CLONE_NEWPID` child (P0-B), plus the R5 T9 spawn/timeout finding set

- **Type:** Defect fix record (review-verified findings from the R5 T9 review), recorded per the AGENTS.md "recorded under `docs/internal/tasks/`" rule for security-adjacent fixes.
- **Fixed:** 2026-10-26 on branch `r5-host-authority-broker-compose`.
- **Review findings:** P0-A (hardened broker `SIGSYS` — covered by [ADR 0044](../../adr/0044-keep-broker-seccomp-list-fixed-and-port-to-listed-syscalls.md)), P0-B (`getppid()` liveness check vs `CLONE_NEWPID`), P1 (missing `MS_PRIVATE` remount after `unshare(CLONE_NEWNS)`), P2 (inaccurate `TIOCNOTTY` comment; clean-shutdown exit code), P3 (dead `activated_listener`; `setgroups` skipped for same-uid launches).

## P0-B: the `getppid` compare is unobservable under `CLONE_NEWPID`

Upstream Go (`syscall/exec_linux.go`, `forkAndExecInChild1`) arms `PR_SET_PDEATHSIG` in the child, then closes the parent-died-between-clone-and-prctl race with a userspace check: `getppid() != the recorded parent pid → abort`.

The Rust port copied that compare unconditionally — but `NamespaceFlags::SANDBOX_CREATE` carries `CLONE_NEWPID`. A child created with `CLONE_NEWPID` is PID 1 of its new namespace; the kernel hides every ancestor outside the namespace and reports `getppid() == 0` for the namespace root. The recorded outer `parent_pid` is therefore *never* observable, and the compare condemned **every** sandboxed child to `child_fail(ESRCH)` before `execve`.

Go escapes this because its runtime `clone` path under `Cloneflags` reports the *outer* parent differently — and, materially, because Go's launcher never composes `CLONE_NEWPID` with a raw `forkExec` pdeathsig child the way the Rust launcher does.

### The fix

In `sys::audited::child_exec` the userspace compare now runs **only when `clone_flags` does not include `CLONE_NEWPID`**:

```text
if !new_pid_ns && getppid() != spec.parent_pid → child_fail(ESRCH)
```

`PR_SET_PDEATHSIG` itself stays installed unconditionally — the kernel still tracks the real outer-namespace parent and delivers the armed signal when it dies. What is skipped is only the *userspace* reparent probe, which is the part that is unanswerable inside a new PID namespace: `getppid() == 0` there is the correct, expected answer, not evidence of an orphan.

The non-`NEWPID` path is unchanged and still closes the race — `pdeathsig_compare_runs_without_newpid` pins that the compare still executes for plain spawns.

### Regression pin

`sys::spawn::tests::newpid_pdeathsig_child_reaches_exec` (root-gated — `CAP_SYS_ADMIN` or the reference host's delegated userns): spawns `/bin/true` under `SANDBOX_CREATE` + `SANDBOX_UNSHARE` with `pdeathsig = SIGKILL`. Pre-fix this returned `sys_spawn_child` errno `ESRCH` and the child never reached `exec`; post-fix it execs and exits 0.

## What a fix requires — the full R5 T9 set

1. **P0-A (SIGSYS):** every post-`harden()` emission must be an allow-listed syscall. Rust stdlib/`rustix` libc-backend emissions differ from Go's (`statx` not `newfstatat`, `fchmodat` not `fchmod`, `open` not `openat`, `clock_nanosleep` not `nanosleep`, `ioctl(FIONBIO)`/`setsockopt`/`socketpair`+`poll` for timeouts, nonblocking, and signals). Fixed by re-aiming the port at listed primitives — see ADR 0044 for the mapping table and the no-list-change decision. Pinned by `broker_surface_and_old_shape_probes` (real surface exits 0; `fchmodat`/`statx` die `SIGSYS`).
2. **P1 (mount propagation):** after `unshare` when `CLONE_NEWNS` is present, `mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)` — upstream pairs this with the unshare because systemd mounts `/` shared (debian bug 739593); without it, child mounts propagate back into the host mount table. Implemented in the child trampoline under `step!`, so a mount failure reports `errno` over the error pipe like every other setup step.
3. **P3 (`setgroups` gate):** supplementary-group dropping is now **privilege-based**, not target-uid-based: the child runs `setgroups(0, NULL)` + `setgid`/`setuid` whenever the target identity differs *or* the current `euid` is 0. A root parent must shed its supplementary set even on a same-uid launch; an unprivileged same-identity launch may skip the call — it has no privileged supplementary set to shed and would only take `EPERM`. Upstream's gate is `Credential`-presence; the Rust spec always carries an identity, so the privilege check is the equivalent load-bearing condition.
4. **P2 (TIOCNOTTY comment):** the comment now states the true divergence — upstream **fails** the child on `TIOCNOTTY` error (including `ENOTTY`), while this port deliberately ignores the result because the daemon launch shape is ctty-less (fd 0 is replaced by `/dev/null` immediately after).
5. **P2 (exit codes):** `serve` now returns `ctx.Err()`-equivalent `FailureKind::Cancelled` on shutdown — `run_broker_daemon_at` maps it to exit 3 (`runBrokerDaemon`'s `os.Exit(3)`), and `run_broker_serve_at` maps it back to operator-mode exit 0 (`broker_serve.go`'s `!errors.Is(err, context.Canceled)`).
6. **P3 (`activated_listener`):** the production daemon path now runs through `activated_listener_at` (full `LISTEN_PID`/`LISTEN_FDS` validation + audited fd claim) instead of a bare `socket_activation_fd(0)`; the code is no longer dead.

## Anchors

- Trampoline: `crates/adapters/central-adapter-linux/src/sys/audited.rs` (`child_exec` — `unshare` + `MS_REC|MS_PRIVATE`, privilege-gated `setgroups`, `NEWPID`-scoped `getppid` compare, `TIOCNOTTY` comment).
- Seccomp surface + probes: `crates/adapters/central-adapter-linux/src/sys/seccomp.rs` (module doc + `broker_surface`/`old_shape` probes), `broker/durable.rs`, `broker/deadline.rs`.
- Exit-code parity: `broker/server.rs` (`serve` returns `Cancelled`), `broker/daemon.rs` (`activated_listener_at`, exit 3 / 0 split).
- Upstream: `/usr/lib/go-1.26/src/syscall/exec_linux.go` (`forkAndExecInChild1`), `central/cmd/central/main.go` (`runBrokerDaemon`), `central/cmd/central/broker_serve.go`.
- Decision record: ADR 0044.
