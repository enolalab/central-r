# Harness Phase 2b — `central-harness-launcher` Design

- **Date:** 2026-09-27
- **Status:** Draft. Brainstormed with the recommended option taken for each question, per the maintainer's workflow. Revised after the focused spec review (`docs/superpowers/reviews/2026-09-27-harness-phase-2b-spec-review.md`).
- **Governing decisions:**
  - [ADR 0036](../../../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md) (Accepted, governance route (b))
  - [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md)
- **Builds on:**
  - [Phase 2a design](2026-09-27-harness-phase-2a-claude-code-adapter-design.md), §10 in particular
  - [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md) §8–§9

## 1. Goal

Deliver the production `port.ProcessLauncher` in three parts:

1. **`central-harness-launcher`:** a root-owned, socket-activated daemon that launches a harness CLI as the configured operator. Each launch runs in private mount and PID namespaces and in a dedicated cgroup.
2. **Go code:**
   - `internal/harnesslauncher`, the protocol client;
   - `internal/adapter/harness/hostlauncher`, which implements `port.ProcessLauncher` on top of that client.
3. **Delivery:** systemd units, a build target, and tests that include a root-gated suite for the reference host.

When this phase is done, the phase 2a Claude Code adapter can run through the production launcher instead of `localexec`.

**Non-goals:** see §10.

## 2. Findings that shape the design

- **Existing root launchers are small C11 daemons.**
  - `central-backup-launcherd` is about 1,400 LOC; `central-migration-launcherd` is about 400 LOC.
  - Both use fixed binary frames over `SOCK_SEQPACKET`, `SO_PEERCRED`, pidfd handoff over `SCM_RIGHTS`, and `close_range`.
  - Both are hardened in their systemd units.
  - Both have a Python test driver that compiles test builds with injected UIDs.
  - Their Go clients are `internal/{backup,migration}launcher/protocol_linux.go`.
- **`internal/sandbox` is not reusable.** It is synchronous, hard-codes UID 502, has no stdio, no mounts and no tests, and never places the child in its cgroup.
- **No cgroup v2 precedent exists.** Nothing in the repo uses `cgroup.procs`, `cgroup.kill`, `CLONE_INTO_CGROUP` or `Delegate=`.
- **The socket client cannot live in the harness domain.** Archguard `harness-boundary` forbids `golang.org/x/sys` and `syscall` under `internal/harness/**`, so the client is a sibling package.
- **The claude binary lives under `HOME`.** `~/.local/bin/claude` is a symlink to `~/.local/share/claude/versions/2.1.283`.
- **Exit status needs the parent.** A pidfd lets a non-parent learn that a process exited, but not its exit status.
- **`~/.claude.json` is replaced by rename (verified 2026-09-27).** It has birth time equal to modify time, and `~/.claude.json.tmp.<pid>.<rand>` files exist. A bind mount of that single file would break the write.
- **Claude's login is independent of `~/.claude.json` (verified 2026-09-27).** With `HOME` set to a fresh directory containing only `.claude` (the operator's real `~/.claude`), `claude auth status` reports `loggedIn: true`, `authMethod: claude.ai`. Claude creates its own `.claude.json` there, printing a first-run notice on stderr. The OAuth tokens live in `~/.claude/.credentials.json`.
- **Host facts:** kernel 7.0, cgroup v2 at `/sys/fs/cgroup`. Unprivileged user namespaces are blocked on this host, so the mount view can only be exercised as root.

## 3. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Daemon language? | **C11**: `cmd/central-harness-launcherd/main.c` with its own Makefile, driven by the root `make`. | Matches both root launchers: direct `clone3`, `openat2`, mount and cgroup calls, no Go runtime in a root forker, and a reusable frame and test pattern. |
| 2 | Supervision and scope ownership? | **One owner per scope: its monitor.**<br>• For each LAUNCH the daemon forks a monitor (`PR_SET_CHILD_SUBREAPER`) and hands it the launch connection and a control `socketpair`.<br>• The monitor owns the scope from LAUNCH until release. The daemon keeps only `scope → control fd`.<br>• An ALIVE or KILL for an owned scope is forwarded: the daemon passes the client connection to the owning monitor over `SCM_RIGHTS`, and the monitor answers.<br>• For an unowned scope, the daemon answers from the cgroup directly: ALIVE reports `populated`. KILL runs `cgroup.kill` in a short-lived child, waits for `populated 0` and removes the directory. Unowned scopes are therefore never reported dead while alive.<br>• **If a monitor dies** (its control fd hits EOF), the daemon treats the scope as unowned and kills and cleans it up, because a harness without a monitor has no lifeline. At start, the daemon kills and removes any leftover `scopes/*`.<br>• The daemon's event loop never blocks on a KILL or on a forward. Its end of each control socket is non-blocking; if a forward would block, the daemon answers from the cgroup as for an unowned scope.<br>• At most one cleaner exists per scope, and cleaners close every inherited fd.<br>• The monitor's wait for the init has a deadline, after which it runs `cgroup.kill` and proceeds to release. | Removes the daemon/monitor ownership ambiguity, keeps request handling concurrent, and gives a real exit status. |
| 3 | Process tree and PID namespace? | The monitor calls `clone3` with `CLONE_NEWNS \| CLONE_NEWPID \| CLONE_NEWIPC \| CLONE_INTO_CGROUP \| CLONE_PIDFD`.<br>• The child becomes **PID 1** of the new namespace and acts as a tiny init.<br>• As root, it builds the mount view (decision 8), including a fresh `/proc` for the new PID namespace and a private devpts.<br>• It sets `NO_NEW_PRIVS` and enters its own Landlock domain (decision 7) **before** it forks the harness. The harness's domain therefore nests inside the init's, so the init's SIGTERM forwarding still reaches the whole tree, while nothing in the tree can signal the init.<br>• It then forks the harness process, which drops privilege (decision 7) and execs.<br>• The init also drops to the operator identity with all capabilities cleared. It forwards SIGTERM with `kill(-1, SIGTERM)` inside the namespace, reaps every process, and writes the harness's raw wait status to its status channel (a pipe to the monitor) before exiting.<br>The **pidfd returned to the client is the init's pidfd** (from `CLONE_PIDFD`). It marks the session's lifetime and is informational only. The exit status always comes from EXIT.<br>• When the init exits, the kernel kills the rest of the PID namespace. | A fresh `/proc` hides other operator processes, so `/proc/<pid>/root` cannot reach the real `HOME`. The init keeps signal semantics for SIGTERM → 143 and 137, and a namespace-scoped kill has no PID-reuse window (spec review S1, T-C1). |
| 4 | Lifeline and EXIT? | The **launch connection is the lifeline**, and the client keeps it open until EXIT.<br>• **EXIT source:** the harness's raw wait status from the init's status channel. If the channel closes without a status (the init was killed, for example on the `cgroup.kill` path), the source is the init's own wait status as the monitor reaps it (for example SIGKILL → `signaled`, code 137).<br>• The monitor sends **EXIT** (`code`, `signaled`) only after the scope is **drained and released**: the harness is reaped, the init has exited, `cgroup.kill` has run if anything was left, the scope reports unpopulated, the scope directory is removed and the daemon has dropped ownership.<br>• A LAUNCH for the same scope issued after EXIT therefore always succeeds.<br>• If the client closes the lifeline before EXIT, the monitor kills the scope and releases it. | Sequential launches under one scope (2a §10) never race the previous monitor. No harness outlives its client (spec review T-C1). |
| 5 | Operations and frames? | **Transport:** `SOCK_SEQPACKET`, magic `"CHL1"`, version 1. Each request is one datagram of at most **64 KiB total**, and the per-field caps also apply. Anything oversized or truncated is rejected.<br>**Operations:**<br>• **LAUNCH** opens its own connection. The response carries `stdin_w`, `stdout_r`, `stderr_r` and the harness `pidfd` over `SCM_RIGHTS`. EXIT follows later on the same connection.<br>• **ALIVE(scope)** reports whether the scope's cgroup is populated.<br>• **KILL(scope, grace_ms ≤ 30 000)** asks the init to SIGTERM the namespace, waits up to the grace, then `cgroup.kill`. The reply comes once the scope is empty. KILL does not touch the lifeline. | This is ADR 0036 decision 8. The kill ladder matches the port contract (2a T-I1). |
| 6 | LAUNCH request fields? | • `scope`: a 16-byte UUID.<br>• `harness`: 1–32 bytes of `[a-z0-9-]`.<br>• `workdir`: either a path relative to `worktree_root` of at most 4096 bytes, or **empty**. Empty is allowed only for a probe argv (decision 10), and it runs in the private `/tmp`.<br>• `argv`: at most 64 entries of at most 4096 bytes each.<br>• `env`: at most 64 `NAME=value` entries of at most 8192 bytes each.<br>No path, UID, mount or program is ever a request field. | A closed request shape. Probes have no worktree (spec review T-M1). |
| 6a | Configuration? | A single root-owned file, `/etc/central/harness-launcher.conf`, in a line-based `key value` format.<br>**Validation:** the daemon checks the file with `fstat` before every launch: owner 0:0, mode 0600 or 0644, a regular file, `st_nlink == 1`, and opened with `O_NOFOLLOW` (the offline-permit pattern).<br>**Keys:**<br>• `operator_user` and `runtime_user`, the only admitted peer;<br>• `worktree_root`, an absolute path that must **not** be beneath the operator's `HOME`. It and every one of its ancestors must be root-owned and not writable by group or others. It is opened with `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)` from `/` and its dev/ino recorded; the init re-opens it the same way and checks the dev/ino before hiding it or mounting from it, both by fd;<br>• `harness <id> <absolute program path>`, the program allowlist (ADR 0036 decision 1). The path must lie beneath the source of an `ro` `mount` entry of that harness, or outside `HOME`, so the executable is visible and read-only in the view;<br>• `home_dir <id> <HOME-relative path>` (decision 9);<br>• `mount <id> <HOME-relative source> <harness-home-relative target> <ro\|rw> <file\|dir>`;<br>• optional `pids_max`, `memory_max`, `cpu_max`.<br>Anything invalid, including a key used twice or an unknown key, fails `config_invalid`. | ADR 0036 decisions 1, 2 and 4 read identity and paths only from root-owned configuration. A line format keeps the C parser small (spec re-review N-T1). |
| 7 | Identity and privilege drop? | **Resolution:** `operator_user` is resolved with `getpwnam` at each launch. Its `HOME` must be canonical (`realpath(HOME) == HOME`), or the launch fails `operator_invalid`. The daemon refuses UID 0, UIDs below `UID_MIN` (from `/etc/login.defs`, default 1000), `central-runtime` and `central-agent`. An operator whose UID equals `runtime_user`'s is accepted **on purpose**: a single-operator host, such as the maintainer's reference-host recipe, runs both roles as one login (disclosed in §7).<br>**Drop sequence**, the same in the harness process and in the init. It runs while `CAP_SETPCAP` is still held:<br>1. close fds: the harness keeps only 0–2 (`close_range(3, ~0U, 0)`); the init keeps 0–2 plus its status channel, moved to fd 3 (`close_range(4, ~0U, 0)`). Every daemon fd is `O_CLOEXEC` from creation.<br>2. drop every capability from the bounding set (`PR_CAPBSET_DROP`) and clear the ambient set;<br>3. set and lock the securebits `NOROOT` and `NOROOT_LOCKED`, leaving `NO_SETUID_FIXUP` **unset**, so the next step clears the permitted and effective sets;<br>4. `setgroups(0)`, then `setresgid`, then `setresuid`;<br>5. `capset` everything to zero, then verify with `capget` that every set is empty (abort otherwise);<br>6. set `PR_SET_NO_NEW_PRIVS` and `PR_SET_DUMPABLE` = 0, then enter a **Landlock** domain with no filesystem or network rules and `scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET \| LANDLOCK_SCOPE_SIGNAL` (ABI ≥ 6). Neither process can then connect to an abstract Unix socket or signal a process created outside its domain. The init enters its domain before it forks the harness (decision 3), so its drop skips this part; the harness's domain nests inside it;<br>7. the harness process calls `chdir` and `execve`; the init continues as the reaper.<br>**Landlock at start:** the daemon probes the ABI (`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`) and fails closed below 6 (`landlock_unavailable`). A no-isolation test build probes only when `CHL_TEST_LANDLOCK_ABI` fakes the version, and scopes its sessions only where the kernel offers ABI 6.<br>**Env:** `HOME`, `USER` and `LOGNAME` always come from passwd, and a request value for any of them is ignored. `HOME` is the operator's real home path, which inside the view holds the harness home (decision 8). | Leaks nothing into the harness: no dirfds, no listen socket, no lifeline, no capabilities. The order is executable, and it also leaves the init with no capabilities (spec review S3, T-M2; re-review N-S1). |
| 8 | Filesystem view? | Built by the init, as root, inside the new mount namespace:<br>1. make `/` `MS_REC\|MS_SLAVE`;<br>2. open and clone every mount source first (see **Sources** below), because the next step hides them; then mount a fresh tmpfs over the directory that contains `HOME` (for example `/home`), and over `/root`, `/run/user`, `/tmp`, `/var/tmp` and `/dev/shm`;<br>3. mount a tmpfs over `worktree_root` if it is not already beneath a hidden tree, so no other worktree is visible;<br>4. mount a fresh `/proc` for the new PID namespace, and a **new devpts instance** on `/dev/pts` (`newinstance,ptmxmode=0666,mode=0620`, `gid=` the `tty` group when the host has one), with its `ptmx` bound over `/dev/ptmx` (a `pts/ptmx` symlink is left as it is). The host's ptys, the operator's terminals among them, are not in the view; ptys opened inside it work. The unit's `DevicePolicy=closed` (decision 16) leaves only the pseudo devices openable;<br>5. bind the per-harness **harness home** at `HOME`;<br>6. bind the configured `mount` entries inside it;<br>7. bind the attempt's worktree at its real path.<br>**Sources** are opened `O_PATH\|O_NOFOLLOW\|O_CLOEXEC` with `openat2(RESOLVE_BENEATH\|RESOLVE_NO_SYMLINKS\|RESOLVE_NO_MAGICLINKS)` from a dirfd of the real `HOME`, of the harness home, or of `worktree_root`. They are cloned with `open_tree(OPEN_TREE_CLONE)` **before** any tmpfs is mounted.<br>**Targets** are resolved only on the root-created tmpfs or on the harness home by dirfd, and attached with `move_mount`. The mount-point directories inside the harness home must already exist as real directories, or the launch fails `config_invalid`.<br>**ro** entries are remounted read-only.<br>Nothing else from the real `HOME` is visible, and the operator's own `~/.claude.json` is **not** mounted. | ADR 0036 decision 4: only the harness's own config and data directories. Fd-based attach closes the symlink-swap races (spec review S1, S5, T-I2). |
| 9 | What is the harness home? | Each harness has a dedicated, persistent, operator-owned directory beneath the real `HOME`, set by `home_dir <id> <HOME-relative path>`, for example `.local/state/central/harness-home/claude`. It is bound as `HOME` inside the view, so rename-based writes work.<br>For claude it holds claude's own `.claude.json`, separate from the operator's, plus two mount points:<br>• `.claude` ← the real `~/.claude` (rw), which carries the login, settings, hooks, plugins and projects;<br>• `.local/share/claude` ← the real one (ro), for the binary versions.<br>The harness home is created by installation (phase 3). The daemon never writes claude's files. | Solves the rename problem without binding the operator's real `HOME`: there is no denylist fallback (spec review S2, T-I2). The login stays in place (ADR 0035 §4).<br>**Disclosed:**<br>• The harness home is persistent state that the harness can write. Its `.claude.json` (MCP servers, project trust, and the settings stored there) carries over between sessions of that harness.<br>• **Behaviour change:** MCP servers the operator defined at user or local scope in `~/.claude.json` do not load for Central-launched sessions. The operator adds them to the harness home's `.claude.json` if wanted. Settings, hooks and plugins in `~/.claude/` still apply.<br>• **Behaviour change (M-2, re-review):** the unit's `SocketBindDeny=any` (decision 13) means a harness tool cannot bind any fixed port, loopback included, so dev servers and test fixtures that bind a fixed port fail; a port-0 bind still works. |
| 10 | Argv? | A **per-harness closed grammar compiled into the daemon**. For `claude`, argv is exactly one of three forms:<br>• the complete probe `--version`;<br>• the complete probe `auth status`;<br>• a session argv: `-p --verbose --output-format stream-json --input-format stream-json --setting-sources user`, then exactly one of `--session-id <uuid>` or `--resume <uuid>` (canonical lower-case), then one policy form, then optionally `--model <m>`, where `m` follows exactly the adapter's `safeModel` rule: 1–128 bytes, not starting with `-`, and only `[A-Za-z0-9]` plus `- . _ : / [ ] @` (see §11).<br>The three policy forms are:<br>• `--permission-mode dontAsk --permission-prompts none`;<br>• `--permission-mode manual --permission-prompts host --permission-prompt-tool stdio`;<br>• `--permission-mode bypassPermissions`.<br>`--flag=value` forms, duplicate flags, positional arguments and anything else are refused. | ADR 0036 decision 5 and phase 2a decision 8. The edges are closed (spec review S4). |
| 11 | Env? | The daemon re-validates the env with the same rules as `harness.ValidateLaunchEnv`, starting empty. Each harness's `EnvExtras` are compiled in; for claude they are none. `testdata/harness-launch-env-vectors.json` is asserted by the Go and Python tests, and `ci/test.sh` runs the Python suite. | ADR 0036 decision 3. The drift guard is actually run (spec review T-M2). |
| 12 | Cgroup? | **Setup:** `Delegate=yes`. At start the daemon moves itself into `<own>/supervisor` and creates `<own>/scopes/`. It fails closed at start unless cgroup v2 offers `cgroup.kill`, which needs kernel ≥ 5.14. Monitors live in `<own>/supervisor`.<br>**Per scope:** the harness tree is created in `scopes/<uuid>` with `CLONE_INTO_CGROUP`, with `pids.max`, `memory.max` and `cpu.max` from optional config (defaults: 512 pids, 2 GiB, no CPU cap).<br>**Liveness** comes from `cgroup.events` `populated`.<br>**Admission:** a scope that is owned or populated refuses a new launch with `scope_busy`.<br>**Permissions:** the scope directory and its files stay root-owned, so the harness cannot write `cgroup.procs` to leave. | ADR 0036 decision 7, without the process-group weaknesses. |
| 13 | Network? | Full egress in this iteration, with no network namespace. This is **disclosed**.<br>**No fixed-port inet listeners**: the unit's `SocketBindDeny=any` (decision 16) refuses `bind(2)` of `AF_INET`/`AF_INET6` sockets to any port from 1 to 65535. It is cgroup `bind4`/`bind6` BPF on the service cgroup, inherited by every scope, and egress `connect(2)` is unaffected. **Ephemeral-port listeners remain reachable inbound**: a bind to port 0 and `listen(2)` on an unbound socket still get a kernel-assigned ephemeral port, and so does UDP autobind; `SocketBindDeny=` does not cover port 0. This is a **deviation from Accepted ADR 0036 decision 6 ("Nothing inbound is allowed")**, not full compliance with it, until the egress-policy iteration introduces a network namespace with an egress path — see §12. **Abstract Unix sockets** on the host are no longer reachable: the Landlock scope of decision 7 refuses a connect to any abstract socket created outside the session. | ADR 0036 decision 6 allows full egress for the first iteration and asks for nothing inbound; this iteration gets close but not all the way there, and the gap is recorded rather than silently accepted. An abstract endpoint that admits the operator by `SO_PEERCRED` (X11, D-Bus) would be an unconfined escape, so it is closed rather than disclosed (final review). |
| 14 | Peer check? | The daemon admits only the UID of `runtime_user` through `SO_PEERCRED`. The client requires the peer to be UID 0. Test builds override both with compile-time macros. | ADR 0036 decision 8. |
| 15 | Go side? | **`internal/harnesslauncher`** (`//go:build linux`): the frame codec, and a `Client` with `Launch`, `Alive` and `Kill`, modelled on `internal/migrationlauncher`.<br>**`internal/adapter/harness/hostlauncher`:** implements `port.ProcessLauncher`.<br>• `Config{WorktreeRoot, ProbeWorkDir}` is supplied by composition and must match the daemon's `worktree_root`; the daemon stays authoritative and refuses a mismatch with `workdir_invalid`.<br>• `ProcessSpec.WorkDir == ProbeWorkDir` maps to an empty `workdir`. A path under `WorktreeRoot` maps to its relative form. Anything else is refused.<br>• `Process.Wait` reads EXIT, then closes the lifeline. If its ctx ends first, it returns `ctx.Err()` and leaves the lifeline open, so a later Wait still works.<br>• `Kill` issues KILL with a 5 s grace on a separate connection and leaves the lifeline open, so the following `Wait` still gets EXIT. After EXIT, `Kill` is a no-op returning nil.<br>• `Alive` issues ALIVE.<br>**Archguard:** a new rule, `harness-launcher-client-boundary`, lets only `hostlauncher` import `internal/harnesslauncher`. | Keeps `x/sys` out of the domain, and matches the adapter's Kill-then-Wait use (spec review T-C1, T-M1). |
| 16 | Packaging? | **Socket:** `central-harness-launcher.socket` with `ListenSequentialPacket=/run/central-harness-launcher/launcher.sock`, `SocketMode=0660` and `root:central-runtime`.<br>**Service:** `central-harness-launcher.service` with `User=root`, `Delegate=yes`, `KillMode=control-group` and `Restart=on-failure`. Its directives fall into three groups, because every directive is **inherited by harness processes**:<br>• *required:* `NoNewPrivileges=yes`, and a capability bounding set of exactly `CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_SYS_ADMIN CAP_KILL CAP_DAC_READ_SEARCH` with `AmbientCapabilities=` set to the same list (without it systemd leaves `CAP_SETUID` out of the daemon's effective set and every launch fails EPERM at the identity change — found by the maintainer's root gate, as in SC-DEF-73; the drop clears ambient before any harness exec) (`CAP_CHOWN` is not needed: the harness home is created by installation), plus `TasksMax=` and `MemoryMax=` bounding the daemon, its monitors and every harness, plus `DevicePolicy=closed` (only `/dev/null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx` and the ptys; no `DeviceAllow=`, since claude needs nothing more) and `SocketBindDeny=any` (nothing inbound, decision 13). Both are BPF programs on the service cgroup that the delegated scopes inherit;<br>• *allowed, since the harness tolerates them:* `ProtectSystem=full`, `ProtectKernelTunables`, `ProtectKernelModules`, `LockPersonality`, `SystemCallArchitectures=native`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`;<br>• *forbidden:* `ProtectHome` (the harness home is under `HOME`), `ProtectSystem=strict` (it would make rw binds read-only), `ProtectControlGroups` (it blocks the cgroup writes), `MemoryDenyWriteExecute` (it breaks the claude JIT), `PrivateTmp` (the daemon makes its own), and `DeviceAllow=` or `SocketBindAllow=` (they would reopen what the two required directives close).<br>**Stopping or restarting the service kills every running harness session** through the control-group kill. The client sees the lifeline close, and the session ends `failed`. This is disclosed.<br>A root Makefile target `native-harness-launcherd` builds the daemon, with grep assertions on the units. | Mirrors the existing launchers and sorts every directive by its effect on the harness (spec review T-I1). |

**Approaches considered:**

- **C daemon plus Go client (chosen, decision 1).**
- **Go daemon with a re-exec init stage.** Rejected: a multithreaded runtime in a root forker, plus a new build and test shape.
- **Extending `internal/sandbox`.** Rejected: route (b) requires a separate component, and the prototype has none of the needed behaviour.
- **For the rename problem, binding the real `HOME` and masking entries.** Rejected: it is a denylist, lets a writable `HOME` gain new login dotfiles, and deviates from ADR 0036 decision 4 (spec review S2).

## 4. Components

| Unit | Responsibility | Depends on |
|---|---|---|
| `cmd/central-harness-launcherd/main.c` | Everything the daemon does:<br>• socket loop and peer check;<br>• config validation;<br>• frame, grammar and env validation;<br>• cgroup handling;<br>• monitor and init;<br>• mount view and privilege drop;<br>• EXIT, ALIVE and KILL. | libc and Linux ≥ 5.14 (`clone3`/`CLONE_INTO_CGROUP`, `openat2`, `open_tree`/`move_mount`, `cgroup.kill`) |
| `cmd/central-harness-launcherd/test_launcher.py` | Python test suites: one non-root with injected UIDs, and one root-gated. | python3, cc |
| `internal/harnesslauncher` | Frame codec and socket client | `golang.org/x/sys/unix` |
| `internal/adapter/harness/hostlauncher` | `port.ProcessLauncher` implemented over the client | `internal/harness/port`, `internal/harnesslauncher` |
| `internal/archguard/rules.go` | The `harness-launcher-client-boundary` rule | — |
| `packaging/systemd/central-harness-launcher.{socket,service}` and the root `Makefile` target | Deployment | — |
| `testdata/harness-launch-env-vectors.json` | Shared env accept/reject vectors | — |
| `ci/test.sh` | Runs the non-root Python suite | — |

## 5. Data flow

1. **Client request.** `hostlauncher.Launch(spec)`:
   - maps `WorkDir` and validates the spec;
   - dials the socket and checks that the peer is UID 0;
   - sends LAUNCH on a new connection, the lifeline.
2. **Daemon checks.** The daemon:
   - checks the peer and re-validates the config;
   - validates the request (harness, workdir, argv form, env);
   - checks that the scope is neither owned nor populated.

   Any failure returns a fixed reason code and launches nothing.
3. **Handoff to a monitor.** The daemon records ownership, creates `scopes/<uuid>` and forks the monitor with the lifeline and the control `socketpair`.
4. **Namespace setup.** The monitor calls `clone3` into the scope with new mount and PID namespaces. The init (PID 1) builds the view, forks the harness and drops its own privileges. The harness drops privilege and execs.
5. **Response.** The monitor sends the LAUNCH response with the three pipe ends and the harness pidfd, then waits for three things: the init's wait-status pipe, the lifeline, and the control fd for forwarded ALIVE and KILL.
6. **Normal exit.** The harness exits, the init reports its raw status and exits, and the namespace dies.
7. **Drain and release.** The monitor then:
   - runs `cgroup.kill` if anything is left;
   - waits for `populated 0`;
   - removes the scope directory;
   - tells the daemon to drop ownership, and waits for the acknowledgement;
   - sends EXIT and exits.
8. **Lost client.** If the lifeline closes first, the monitor kills the namespace (SIGKILL to the init, then `cgroup.kill`), then drains and releases the same way. No EXIT is sent.

## 6. Errors and fixed reason codes

The reason codes are: `peer_denied`, `config_invalid`, `request_malformed`, `unknown_harness`, `workdir_invalid`, `argv_refused`, `env_refused`, `scope_busy`, `operator_invalid`, `launch_failed`.

- The Go client maps each reason to a wrapped sentinel error.
- No path, argv or env value is echoed in a response or a log line. Logs carry only the reason code and the scope id.

## 7. Security properties

- **Closed requests.** No UID, path, mount or program is chosen by the request.
- **Config re-check.** The config file is root-owned and is checked again before every launch.
- **Privilege drop.** The harness and the init run as the operator with `NO_NEW_PRIVS`, no capabilities and no supplementary groups. The harness keeps only fds 0–2, and the init adds only its status channel. IPC, `/dev/shm` and `/var/tmp` are private.
- **Landlock scope.** The harness and the init each run in a Landlock domain (ABI ≥ 6; the daemon fails closed without it) that refuses a connect to an abstract Unix socket created outside the session, and a signal to a process outside it. The harness's domain nests in the init's: the init can signal the tree, the tree cannot signal the init.
- **What the harness can see:**
  - the harness home, the configured entries and its own worktree;
  - a `/proc` that shows only its own PID namespace;
  - a devpts of its own: no host pty, so none of the operator's terminals;
  - under the unit, only the pseudo devices (`DevicePolicy=closed`), so none of the seat devices that logind `uaccess` ACLs open to the operator (sound, video, `hidraw`, `dri`);
  - no other home, no other worktree, and no `/run/user` (and so no user bus).
- **No fixed-port inbound.** Under the unit, `SocketBindDeny=any` refuses an inet `bind(2)` to any port from 1 to 65535. Egress `connect(2)` is not affected. Ephemeral-port listeners (a bind to port 0, `listen(2)` on an unbound socket, and UDP autobind) remain reachable inbound: this is a **deviation from Accepted ADR 0036 decision 6**, not an implementation of it — see §12.
- **Containment.** Kill and liveness go by cgroup and PID namespace, so `setsid` children cannot escape and there is no PID reuse. The scope's cgroup files are root-owned, so the harness cannot leave its scope.
- **Lifeline.** No harness outlives its client connection or a restart of the launcher service.
- **Residual risks (ADR 0036 costs, disclosed):**
  - full egress (no network namespace yet); pathname Unix sockets outside the hidden trees stay reachable by file permissions;
  - an inet socket bound to port 0, or put to `listen(2)` unbound, gets a kernel-assigned ephemeral port, which `SocketBindDeny=` does not cover and which a remote peer could reach once it learns the port; the same is true of UDP autobind. Closing it needs the network namespace of the egress-policy iteration (**inbound deviation from ADR 0036 decision 6** — see §12);
  - **(M-3, re-review)** Landlock (decision 7) scopes only outbound abstract connects: a session can still **bind** an abstract socket name, and an unsandboxed host client that connects to that name (for example an X11 display name not yet in use) is not stopped — an impersonation risk, not covered by the Landlock scope;
  - `/dev/mqueue` is still the host's instance, and the kernel user keyring is shared by UID, since there is no user namespace (final review Minor 8);
  - `/run/media/<user>` and `/media/<user>` are not hidden, and udisks mounts there carry operator ACLs (final review Minor 9);
  - **(M-6, re-review)** a host devpts bind-mounted into a tree that is still visible in the view (for example `schroot` under `/run/schroot` or `/srv`) would re-expose host ptys, since the private-devpts step (decision 8) only replaces `/dev/pts` and `/dev/ptmx`, not every bind mount of the host's instance elsewhere in the filesystem;
  - when `operator_user` and `runtime_user` are one login (decision 7, single-operator hosts), a harness passes the launcher's `SO_PEERCRED` check through the socket's group, and it can read what the runtime owns through DAC;
  - `~/.claude` is writable by the harness, including its hooks and settings, which later run unconfined in the operator's own claude sessions;
  - a compromised `central-runtime` can launch scopes that read the operator's claude credentials.

## 8. Testing

- **C, non-root.** The Python driver runs test builds with injected UIDs, config path and cgroup root. It also runs a `TEST_NO_ISOLATION` build in which namespace, mount and cgroup steps are explicit no-ops. It covers:
  - frame parsing, the per-field caps and the 64 KiB total cap;
  - peer denial;
  - config validation: owner, mode, nlink, symlink, missing mount points, duplicate or unknown keys, a program outside any `ro` entry, and a `worktree_root` beneath `HOME`;
  - the argv grammar: every allowed form, plus refusal of `--settings`, `--mcp-config`, `--add-dir`, `--dangerously-skip-permissions`, `--flag=value`, duplicate flags, positional arguments, `auth login`, `auth logout`, `--version` with extra arguments, and models starting with `-`;
  - the shared env vectors, including that `HOME`, `USER` and `LOGNAME` from the request are ignored;
  - a refused `workdir` (`..`, absolute, symlink), and an empty workdir without a probe argv;
  - `scope_busy`;
  - reason codes never echo request values;
  - the daemon failing closed at start without `cgroup.kill`, using a fake cgroup root;
  - the daemon failing closed at start below Landlock ABI 6 (a faked probe), in a no-isolation build and in the isolating build;
  - on a kernel with Landlock ABI ≥ 6, a no-isolation session that cannot connect to the runner's abstract socket or signal the runner, both of which its UID alone would allow, while its own abstract socket works.
- **C, root-gated** (`CENTRAL_TEST_HARNESS_LAUNCHER_ROOT=1` and euid 0; run by the maintainer). The suite creates and removes its own throwaway operator, and places its fixtures outside `/tmp` so the production hiding paths run.
  - It runs twice: once against a test build, and once (`CENTRAL_TEST_HARNESS_LAUNCHER_SYSTEMD=1`) against the production binary started the way the unit starts it (the unit's properties and socket activation).
  - Test knobs cannot reach a production build: a compile-time guard stops them, and the production target checks for them.
  - It checks:
  - `/proc/<pid>/status` of **both the harness and the init**: `Uid`, `Gid`, `Groups` empty, all `Cap*` zero, `NoNewPrivs` 1;
  - after a monitor is killed, the daemon kills and cleans the scope, and ALIVE never reports it dead while it is still populated;
  - EXIT when the init itself is SIGKILLed;
  - fds: only 0–2;
  - the view: other homes, `/root` and `/run/user` hidden; only the harness home, its entries and the worktree visible; ro entries read-only; `/proc` showing only the namespace;
  - that the harness cannot write the `cgroup.procs` of its scope, of the parent, or of the operator's `user@<uid>.service`;
  - that the host mount table is unchanged after a session, and that the harness cannot open `/proc/1/fd`;
  - cgroup placement, ALIVE, and KILL with a SIGTERM-ignoring tree;
  - a `setsid` escapee still killed;
  - a lifeline close that kills and releases the scope;
  - an immediate sequential relaunch of the same scope after EXIT;
  - EXIT codes 0, 1, 143 and 137;
  - `/dev`: while the runner holds a host pty, the view's `/dev/pts` lists only `ptmx` (from inside and through `/proc/<pid>/root`), no host pty path opens, and a pty opens inside. In systemd mode, no device but `/dev/null` opens, and `/dev/fuse` and `/dev/net/tun`, world-openable by mode, fail `EPERM` from the device policy. Sound, `hidraw`, `dri` and video nodes present on the host fail too;
  - Landlock: the harness cannot connect to the runner's abstract socket and cannot signal the init (PID 1, in the parent domain; nothing else outside is addressable in the PID namespace), each `EPERM`; its own abstract socket works;
  - inbound: in systemd mode an inet bind to a free port fails `EPERM` (IPv4, and IPv6 where available); the test build, without the unit, shows the same bind succeeding. A port-0 bind is recorded, not asserted.
- **Go:**
  - the `harnesslauncher` codec round-trip, plus client tests against an in-process fake server over `socketpair` (fd receipt, EXIT, and a peer check through a test hook);
  - `hostlauncher` with a fake client: `WorkDir` mapping and refusal, the probe mapping, and Kill-then-Wait still receiving EXIT;
  - `harness.ValidateLaunchEnv` checked against the shared vectors.
- **Reference host.** Build tag `//go:build referencehost`, gated by `CENTRAL_TEST_HARNESS_LAUNCHER=1` and `CENTRAL_TEST_CLAUDE=1`, with the daemon installed and running. It runs the phase 2a conformance and hostile-`.claude/` scenarios through `hostlauncher`, including the version probe. The maintainer runs it; it spends a few cents.
- **Archguard:** a test for `harness-launcher-client-boundary`.

## 9. Plan-stage live checks

Record each result in the plan, with evidence.

1. **Harness home.** Run a `claude -p --model haiku` session with `HOME` set to a fresh directory that holds only a `.claude` link to the real `~/.claude`, using the phase 2a argv. It must reach `result` as logged in. Also confirm that `.claude.json` is created there and that the real `~/.claude.json` is untouched (compare its inode and mtime).
2. **Other `HOME` entries.** Using the same session, find any other `HOME` path claude needs, for example `.cache` or `.config`, by listing what appears in the fresh `HOME`. Anything found becomes a `mount` entry or stays in the harness home.
3. **Kernel support.** Confirm `clone3` with `CLONE_INTO_CGROUP`, `open_tree`/`move_mount`, `openat2` and the `cgroup.kill` file on the reference host.

## 10. Out of scope

- **Phase 3:**
  - serve composition that wires `hostlauncher`;
  - installation of the units;
  - creating the harness home and its mount points;
  - the attempt-worktree layout: worktrees must live outside `HOME` and be self-contained (a clone, not a `git worktree` whose gitdir lies outside the view), or git inside the view fails;
  - one-click-installer integration.
- **Egress restriction** beyond full egress, which is disclosed.
- **Grammars for OpenCode and ACP** (phases 4–5).
- **Changes to `central-sandbox-launcher` and `internal/sandbox`** (ADR 0036, route (b)).

## 11. Plan-stage findings (live-verified, 2026-09-27)

These come from the verified draft behind the plan (`docs/superpowers/plans/2026-09-27-harness-phase-2b.md`).

- **§9.1, harness home:** a claude 2.1.283 session (haiku, deny policy) with `HOME` set to a fresh directory holding only a `.claude` link reached `result/success` while logged in.
  - Claude created its own `.claude.json` there, with no `projects` and no `mcpServers`.
  - The real `~/.claude.json` was untouched: the same inode and mtime before and after.
- **§9.2, other `HOME` entries:** only `.claude.json` and `.cache/claude-cli-nodejs/` appeared. Both stay inside the harness home. The mount entries stay `.claude` (rw) and `.local/share/claude` (ro).
- **§9.3, kernel 7.0:**
  - `cgroup.kill` is present;
  - `clone3` with `CLONE_INTO_CGROUP` exists (EINVAL/EBADF without privilege, not ENOSYS);
  - `open_tree`/`move_mount` exist (EPERM without privilege);
  - `openat2` works.
- **Accepted deviations from the text above:**
  - The env vectors live at `internal/harness/testdata/launch-env-vectors.json`. Archguard forbids `os` in `internal/harness/**`, and `go:embed` cannot reach a parent directory.
  - The harness process keeps fd 3 as an `O_CLOEXEC` exec-error pipe and runs `close_range(4, …)`, so exactly fds 0–2 remain after exec (asserted).
  - Internal ALIVE/KILL failures, and a KILL whose scope never empties, answer `launch_failed`.
  - A datagram without a usable header is dropped without a response.
  - The config and peer checks precede the frame-shape checks, because the peer UID comes from the config.
  - A request `HOME` is refused with `env_refused`, since it is on the Go denylist. A request `USER` or `LOGNAME` is accepted and replaced by passwd.
  - `--model` follows the adapter's `safeModel` rule (decision 10), so `opus[1m]` works through both launchers.
  - Additional fail-closed checks:
    - `HOME` needs a parent other than `/`;
    - the program must exist, be a regular executable, and be reached without symlinks;
    - a program outside `HOME` must not lie under a tree the view hides;
    - `file` mount entries need regular files at both ends.
  - `hostlauncher` requires canonical UUID scope ids; phase 3 composition passes attempt UUIDs.
  - The test builds read their paths from `CHL_TEST_*` env and macros. The production daemon requires socket activation.
- **Plan review fixes:**
  - The unit sets `TasksMax=4096` and `MemoryMax=8G`.
  - The monitor's wait for the init has a 30 s deadline.
  - A per-scope cleaner is bounded to 60 s.
  - If the owning monitor is wedged, KILL runs `cgroup.kill` at once, skipping the grace (`PROTOCOL.md` §3.3).
  - `worktree_root` must be root-owned, so phase 3 provisions a root-owned worktree layout.
- **Not verified without root:** the isolation paths (namespaces, the mount view, the root half of the privilege drop, real cgroups, systemd). The root-gated Python suite (now 8 tests per mode) and the reference-host Go suite are written. Plan Task 9 makes the root suite a maintainer gate before merge.
- **Final review fixes (2026-09-28).** The whole-branch review found two isolation claims untrue as written. Both are now enforced, not only disclosed:
  - *Host `/dev`:* the view mounts a private devpts, and the unit sets `DevicePolicy=closed` (decisions 8 and 16). Before this, a session could open the operator's live terminals and the seat devices that `uaccess` ACLs open to the operator.
  - *Inbound and abstract sockets:* the unit sets `SocketBindDeny=any` (decisions 13 and 16), and the harness and the init scope themselves with Landlock against abstract Unix sockets and signals (decision 7). The daemon fails closed below Landlock ABI 6; the reference host (kernel 7.0) reports ABI 8. The init enters its domain before it forks the harness, instead of in its own drop, so that its SIGTERM forwarding still reaches the harness's nested domain.
  - `hostlauncher`'s KILL budget is now 85 s. It covers the daemon's worst case, 75 s: a KILL forwarded during a launch's setup (30 s), then the grace (5 s), the init wait (30 s) and the drain (10 s). A cleaner is bounded at 60 s.
  - Recorded follow-ups, not fixed: the daemon's 500 ms receive wait per connection; ALIVE and KILL not serviced during a launch's setup; a failed RELEASE ack ending a session without EXIT; the root suite's cgroup probe not telling `EACCES` from `EBUSY`; no systemd-mode test that stopping the unit ends a live session; the rw-entry assertion checking only writability; the `/dev/mqueue`, keyring and `/media` residuals of §7; the plan's stale non-root test count; and stacked tmpfs mounts when `HOME`'s parent is itself a hidden tree. Refusing an operator whose UID equals `runtime_user`'s is **not** a follow-up: it is intentional for single-operator hosts (decision 7).

## 12. Known deviations and follow-ups (re-review, 2026-09-28)

- **Inbound deviation from ADR 0036 decision 6.** Decision 6 says nothing inbound is allowed. This iteration's `SocketBindDeny=any` (decisions 13, 16) closes every fixed-port inet bind, but an ephemeral-port listener — a bind to port 0, `listen(2)` on an unbound socket, or UDP autobind — still gets a kernel-assigned port and is reachable by a peer that learns it (§7). That is a deviation from the Accepted ADR text, not a reading of it, and it is recorded here rather than left implicit in a disclosure bullet.
  - **Owner:** maintainer.
  - **Close by:** the egress-policy iteration, either by putting sessions in a network namespace with a controlled egress path (closing the ephemeral-port gap as a side effect of no longer sharing the host's network stack), or, if that lands later than the gap needs closing, a cgroup `INET_INGRESS` BPF program or an `nftables` rule scoped to the delegated cgroup that drops inbound `SYN`/UDP to the ephemeral range.
  - **Decided 2026-09-28 (maintainer): no ADR amendment.** The planned closure, a network namespace with an egress path, meets ADR 0036 as written, so this is an implementation gap. It is tracked as [SC-DEF-105](../../../internal/tasks/sc-def-105-harness-launcher-inbound-2026-09-28.md). On the reference host the root gate (systemd mode) also refused a port-0 bind (`EPERM`). What remains open is `listen()` autobind and UDP autobind.
- **M-4, BPF directives fail open.** `DevicePolicy=` and `SocketBindDeny=` (decision 16) are cgroup BPF programs. On a systemd version or kernel without BPF-cgroup support, systemd skips them and logs a warning rather than failing the unit; the daemon does not probe or verify either directive, and neither does the client. Only the reference-host root-gated suite (§8) actually exercises the enforcement, by checking that a disallowed `fuse`/`tun` open and a disallowed bind both fail `EPERM` on the production unit. A host where the unit silently loses these directives gets no signal from the daemon itself.
  - **Owner:** maintainer, tracked as an installation/packaging gap rather than a code defect in this phase.
- **Plan-review follow-ups.** The recorded-but-not-fixed items from the plan review and the final review (§11) stand as written: they are not restated here.
