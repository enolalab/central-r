# ADR 0036: Add a separate harness launcher for operator harness sessions

- **Number:** 0036
- **Title:** Add a separate harness launcher for operator harness sessions
- **Status:** Accepted
- **Created:** 2026-09-27
- **Owners:** Central maintainer
- **Decision due:** 2026-10-11
- **Decision due history:** None
- **Implementation blocked at:** The `central-harness-launcher` daemon, its socket and service units, its Go client implementing `port.ProcessLauncher`, any production composition of that client, and any serve wiring that launches a harness. The harness adapters, the `port.ProcessLauncher` contract and the dev-only `localexec` launcher are not blocked.
- **Decided by:** Central maintainer
- **Decision date:** 2026-09-27
- **Decision record:** Git status-transition commit; exact hash resolved by this file's Git history
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0008 (effective local topology: adds one component; see "Governance note")
- **Amended by:** None
- **Related:** [ADR 0035](0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md), [Harness Adapter Boundary Design](../internal/superpowers/specs/2026-09-27-harness-adapter-boundary-design.md) §8–§9, [Phase 2a design](../internal/superpowers/specs/2026-09-27-harness-phase-2a-claude-code-adapter-design.md), [ADR 0010](0010-reassign-gate-9-executable-slices-to-phase-1.md), [ADR 0014](0014-authorize-postgresql-throughput-fixture-provisioner.md)

## Context

ADR 0035 moves agent execution into external harnesses (Claude Code, OpenCode). Each one runs as the **operator** and uses the operator's own login in `HOME`. The governing spec (§8) requires each harness attempt to run in its own launcher scope:

- namespaces and a cgroup;
- the worktree and the harness's config directory bind-mounted;
- an egress policy;
- a scope the control plane can kill as a whole.

It also requires that the serve process never `exec` a harness itself.

The effective local topology has no component that can do this. Its sandbox clause originated in ADR 0009, was carried forward by ADR 0010 (line 47), and is inherited through ADR 0011 → ADR 0014. It says:

> "A distinct root-owned, socket-activated `central-sandbox-launcher` with no Docker/network/secret authority launches untrusted execution as `central-agent` in a private PID/mount namespace with delegated Workspace descriptors only."

The supporting specs reject any request-chosen UID, mount, executable, path or network.

The code (`internal/sandbox`) is a prototype:

- it runs only `central-agent` (hard-coded UID 502);
- it has no stdio handoff, no cwd, no mounts and no network;
- it never places the child in its cgroup;
- it is synchronous;
- it has no socket unit and no client.

A harness also needs network access to its model provider, which the sandbox launcher's `CLONE_NEWNET` removes.

## Decision

Add a **new, separate, root-owned launcher component, `central-harness-launcher`**, used only for harness sessions.

A harness session is operator-delegated execution: the harness runs as the operator with the operator's own login. The existing `central-sandbox-launcher` and its `central-agent` class are **unchanged**. They keep governing Central-launched untrusted execution exactly as the effective topology states.

1. **Program.** The request names a symbolic harness (`claude`, `opencode`). The launcher resolves it from an instance-configured, root-owned allowlist of absolute paths. The request never carries a path.
2. **Identity.** The target UID is the instance's configured **operator** account, never a request field. It is read only from **root-owned** configuration.
   - The launcher refuses UID 0, any UID below the system's `UID_MIN`, `central-runtime` and `central-agent`.
   - `HOME`, `USER` and `LOGNAME` come from that account's passwd entry.
   - Supplementary groups are cleared, and `PR_SET_NO_NEW_PRIVS` is set, so setuid binaries and sudo cannot raise privilege.
3. **Environment.** It starts empty. Only names that pass `harness.ValidateLaunchEnv` for the harness class are accepted, and the launcher re-validates them.
4. **Filesystem.** A private mount namespace bind-mounts two things.
   - **The attempt's worktree** (read-write). It is accepted only beneath a worktree root set in root-owned configuration. It is opened with `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` or received as an fd, and it is mounted from that fd, which rules out swapping a symlink between check and mount.
   - **The harness's own config and data directories** under the operator's `HOME`, from a fixed per-harness list such as `~/.claude` and `~/.claude.json`.

   Nothing else from `HOME` is mounted. The request never carries mount source paths.
5. **Argv.** The launcher validates argv against the per-harness closed grammar of declared launch parameters (phase 2a decision 8). It rejects anything else, for example `--settings`, `--mcp-config`, `--add-dir` or `--dangerously-skip-permissions`, so a compromised caller cannot widen the harness's configuration.
6. **Network.** Egress to the harness's provider endpoints is allowed through a policy owned by the instance configuration. The first iteration may allow full egress, provided that fact is disclosed. Nothing inbound is allowed.
7. **Scope.** The caller supplies a scope id (a UUID).
   - The child is placed in a dedicated cgroup `central-harness/<scope>` (through `cgroup.procs` or `CLONE_INTO_CGROUP`), with resource limits sized for a Node-based CLI.
   - Killing the scope uses `cgroup.kill`, and liveness is judged by the cgroup, never by a process group.
   - A scope admits a new launch once its previous processes are gone, because adapters launch sequentially under one scope (phase 2a §10).
8. **Protocol.** The launch is asynchronous.
   - The launcher returns stdio pipes and a pidfd over `SCM_RIGHTS`, modelled on `central-backup-launcherd`.
   - Separate requests handle `alive(scope)` and `kill(scope)`.
   - `SO_PEERCRED` admits only the `central-runtime` UID.
9. **Deployment.** Units `central-harness-launcher.socket` and `.service` are added, root-owned, with the socket at mode `0660 root:central-runtime`. The component shares no socket, unit or request type with `central-sandbox-launcher`.

## Governance note

The Central maintainer chose governance route **(b)**, which treats the harness launcher as a new component of the effective local topology. The alternative, route (a), is recorded under "Alternatives considered".

This ADR does not change the `central-sandbox-launcher` clause (ADR 0009, carried by ADR 0010 → 0011 → 0014). That clause keeps governing untrusted execution as `central-agent`.

This ADR therefore amends ADR 0008 **only by adding** the harness launcher. It overlaps no active amendment, and ADR 0014 and ADR 0019 stay Accepted and unchanged.

## Consequences

### Benefits

- Harness processes run as the operator, with the operator's own login, in a scope Central can kill and inspect. Serve never execs a harness.
- The trust boundary stays closed: no request-chosen UID, path or mount.
- The decided `central-agent` sandbox class and its supersession chain stay untouched.

### Costs and limitations

- A second root-owned launcher daemon and protocol surface, with its own tests on a reference host.
- Egress policy is new ground. Full egress, if chosen first, weakens containment against a compromised harness.
- The harness config directory is writable by the harness. Central cannot protect it from the harness itself.
- A compromised `central-runtime` (the one peer `SO_PEERCRED` admits) can launch harness scopes. Any launched scope can read the operator's harness credentials (for example `~/.claude/.credentials.json`) and, under full egress, exfiltrate them. Argv validation limits what a scope runs; it does not prevent this.

## Alternatives considered

### Let serve exec harnesses directly as the operator

Rejected. Serve runs as `central-runtime`, so running as the operator would need privilege in serve. It would also lose the scope boundary.

### Widen the existing `central-agent` request with a UID, mounts and network

Rejected. It dissolves the closed request shape that the earlier specs deliberately fixed.

### Add a harness class inside `central-sandbox-launcher` (route (a))

Rejected. It overlaps the sandbox clause, so this ADR would have to supersede ADR 0014, restating it in full, and resolve ADR 0019 in the same transition. A separate component gives the same guarantees without reopening decided topology.

## Follow-ups

- Phase 2b plan: the `central-harness-launcher` daemon, reference-host tests, the systemd units, and the Go client implementing `port.ProcessLauncher`.

## References

- [Phase 2a design](../internal/superpowers/specs/2026-09-27-harness-phase-2a-claude-code-adapter-design.md) §2.1, §10
- `internal/sandbox/launcher_linux.go`, `internal/sandbox/envelope.go`, `cmd/central-backup-launcherd/main.c` (the SCM_RIGHTS/pidfd precedent)
- [ADR governance and index](README.md)
