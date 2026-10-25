# ADR 0044: Keep the broker seccomp allow-list fixed and port the Rust runtime surface to listed syscalls

- **Number:** 0044
- **Title:** Keep the broker seccomp allow-list fixed and port the Rust runtime surface to listed syscalls
- **Status:** Proposed
- **Created:** 2026-10-26
- **Owners:** Central maintainer
- **Decision due:** 2026-10-26
- **Decision due history:** None
- **Implementation blocked at:** Nothing — the R5 T9 P0-A fix ships with this ADR Proposed per the ADR 0028 D3 delegation (the fix changes no wire format and no Accepted ADR's decision; acceptance stays with the maintainer).
- **Decided by:** Not applicable while Proposed
- **Decision date:** Not applicable while Proposed
- **Decision record:** Not applicable while Proposed
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** [ADR 0008](0008-adopt-capability-owned-go-application-boundaries.md) (capability-owned adapter boundaries), ADR 0028/D3 (cross-repository security-adjacent fix delegation), ADR 0029 (upstream: getdents64 admitted for the daemon's own stores), upstream `docs/internal/tasks/sc-def-07-broker-seccomp-kills-itself-on-startup.md`, `docs/internal/tasks/r5-t9-newpid-pdeathsig.md`

## Context

Upstream `internal/adapter/authority/broker/hardening.go` installs a default-deny (`SECCOMP_RET_KILL_PROCESS`) seccomp-BPF filter on the broker daemon immediately before `Serve`. Its 64-entry `allowed` list was enumerated by strace of the Go runtime — every SC-DEF entry is a syscall *Go* was observed to emit on the serving path.

The Rust port kept the list verbatim and initially died with `SIGSYS` (the R5 T9 P0-A review finding): Rust's stdlib and this workspace's `rustix` (libc backend) reach *different* syscall numbers for the same logical operations. Enumerated post-`harden()` emissions that are absent from the list:

| Logical call | Rust emission | Listed equivalent |
| --- | --- | --- |
| `fs::metadata` / `fs::symlink_metadata` / `Path::exists` / `remove_dir_all`'s internal stat | `statx` (332) | `newfstatat` (262) via `rustix::fs::statat` |
| `fs::set_permissions` (any path) | `fchmodat` (268) | `fchmod` (91) on the open fd, or mode-at-`openat` |
| `File::open` / `fs::read` / modeless `OpenOptions`, `rustix::fs::open` (libc backend) | `open` (2) | `openat` (257), `openat2` (437) |
| `UnixStream`/`UnixListener` `set_*_timeout` | `setsockopt` (54) | `fcntl(O_NONBLOCK)` (72) + `read`/`write`/`recvmsg` `EAGAIN` retry under a `nanosleep` deadline |
| `UnixStream`/`UnixListener` `set_nonblocking` | `ioctl(FIONBIO)` (16) | `fcntl(F_SETFL, O_NONBLOCK)` (72) |
| `std::thread::sleep` | `clock_nanosleep` (230) | raw `nanosleep` (35) via `libc::syscall` |
| tokio `signal::unix::signal` (the original shutdown waiter) | `socketpair` (53) + `poll`/`epoll` | `rt_sigaction` (13) flag handler, polled flag |
| `fs::create_dir`/`create_dir_all` | `mkdir` (83) | `mkdirat` (258), mode at creation |
| `fs::rename` | `rename` (82) — unconditional on x86_64; `std::fs` never emits `renameat` | `renameat` (264) / `renameat2` (316) via `rustix::fs::renameat_with` — `durable::rename_replace`/`rename_noreplace` |
| `fs::remove_file` | `unlink` (87) on glibc ≥ 2.37, `unlinkat` below — toolchain-dependent | `unlinkat` (263) via `rustix::fs::unlinkat` — `durable::remove_file`/`remove_all` |
| `fs::hard_link` | `link` (86) or `linkat` (265) at the libc's discretion — toolchain-dependent | `linkat` (265) via `rustix::fs::linkat` — `durable::hard_link` |
| `rustix::fs::chown` (path form) | `fchownat` (260) | `fchown` (93) on the already-open fd |
| `fs::read_dir` | `openat` + `getdents64` — both listed, but per-entry `metadata`/`file_type` probes can emit `statx` | `getdents64` `d_type`-only via `durable::read_dir`; `lstat` by name when more is needed |

Two forces collide: (a) the filter's whole value is that it is a *closed* surface — every historic upstream widening (SC-DEF-02/07/10/24/36/40/45/48) added exactly one justified primitive; (b) the Rust port needs a syscall surface the list does not currently contain for *every* filesystem and timeout operation the broker performs.

## Decision

**The allow-list stays exactly the upstream 64 numbers, in upstream order — no additions, no removals.** The Rust broker is re-aimed at primitives the list already admits:

1. `broker::durable` owns the filter-safe filesystem primitives: `stat`/`lstat` (`statat`/`newfstatat`), `exists`, `mkdir_p` (`mkdirat`, mode at creation — no mkdir-then-chmod race), `write_file`/`open_read`/`open_write`/`open_exclusive` (`openat`, mode at creation), `read_file`, `read_dir` (`getdents64`, `d_type` only), `remove_file`/`remove_all` (`unlinkat` at 263), `hard_link` (`linkat` at 265), `sync_file`/`sync_dir` (`openat` + `fsync`), `open_lock`, `rename_noreplace`/`rename_replace` (`renameat2` at 316). All post-`harden()` broker stores (journal, lifecycle, signing, TLS, payload epoch, provisioning, bootstrap session, secret bootstrap, protected file, export token) route through them.
2. `broker::deadline::DeadlineStream` realizes upstream's `conn.SetDeadline` on `fcntl(O_NONBLOCK)` + `read`/`write`/`recvmsg` `EAGAIN`/`EINTR` retry under an `Instant` deadline with a bounded `nanosleep` cadence — the same cadence the accept loop already uses. `broker::server` sets the listener nonblocking via `fcntl`, never `ioctl(FIONBIO)`.
3. `audited::install_signal_handler` + a `static` flag replaces the tokio signal-waiter thread for `SIGINT`/`SIGTERM` shutdown (`rt_sigaction` is listed; `socketpair`/`poll` are not). `audited::nanosleep` is the raw `SYS_nanosleep` for every post-`harden()` sleep.
4. `fchmod`/`fchown` on an open fd (not `fchmodat`/`fchownat` on a path) carries the remaining "tighten a pre-existing file's mode or ownership" cases (`secret_bootstrap::write_private`, export identity mint).
5. Regression pins in `sys::seccomp::tests`: `probe_child_broker_surface` installs the real filter then walks the whole post-`harden()` surface (store ops including a tmp-write→fsync→`renameat2`→`unlinkat` persist path and a `linkat` publish, `fcntl` nonblock, `sendmsg`/`recvmsg`, `SO_PEERCRED`, `accept4`, `rt_sigaction`, `nanosleep`, `clock_gettime`, `getrandom`) to a clean exit; `probe_child_old_*_dies` pin every pre-fix emission — `fchmodat`, `statx`, `rename`, `unlink`, `link`, `fchownat` — to `SIGSYS` via raw `audited::*_raw` syscalls, so the pins hold regardless of which emission a future std/glibc picks. `allowlist_matches_upstream` keeps the 64-number list byte-verified.

## Consequences

- The filter's security posture is unchanged: the allow-list is the same closed surface upstream ships, still pinned verbatim by `allowlist_matches_upstream`. Every new emission is an *already-listed* syscall — nothing is newly admitted for Rust's convenience.
- The port's rule of thumb: **only `*at`/`f*`-family and the exact runtime calls on the list may be used post-`harden()`**; `std::fs` path APIs are unsafe-by-default there because their emissions differ per toolchain and glibc version.
- The deadline is ~1 ms-granular rather than timer-precise — observable semantics (`TimedOut` on an idle peer past the deadline) match upstream; the extra cost is at most a thousand cheap `nanosleep`s per worst-case connection.
- Non-broker processes (helper daemon, sandbox launcher, clients, `broker serve` operator mode) are untouched: they run no filter, so `serve_on_path`'s `fs::set_permissions(0666)` and client-side `create_dir_all` stay as-is.
- `broker::activated_listener` is now wired into `run_broker_daemon_at` (the previously dead socket-activation code path is the production one), with `activated_listener_at` as the test seam.
- If a future requirement genuinely needs a syscall absent from the list (e.g. `epoll_pwait2` for a timer-precise deadline), it must come back as its own ADR-backed list amendment — the same one-justified-primitive-at-a-time discipline upstream's SC-DEF series used.
