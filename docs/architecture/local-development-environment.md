# Local Development Environment Topology

Design-only Gate 8 contract — commands are not currently available; Phase 1 slices return exit 5/UNSUPPORTED_IN_THIS_SLICE without mutation until implemented.

Ownership activation contract: At `OWNERSHIP_ALIGNMENT_TARGET`, ADR 0010 is Proposed and ADR 0009 remains ADR 0008's controlling active amendment. The documentation-only Gate 9 / executable Phase 1 allocation below becomes authoritative if and only if a descendant `ADR0010_ACCEPTANCE_TARGET` records ADR 0010 Accepted, ADR 0009 Superseded, and ADR 0010 as ADR 0008's Accepted non-superseded amendment. Current authority is resolved from ADR 0008, its Accepted non-superseded amendment, and `docs/adr/README.md`; this sentence is not a frozen status label.

## 1. Authority and phase boundary

This document is the canonical topology contract for the Gate 8 local development environment. It is normative: every table, value, identity, path, port, and constraint is binding on Phase 1 implementation. It creates no Go source, SQL migration, Dockerfile, Compose file, image, bucket, database, role, credential, runtime configuration, generated dependency lock, executable test, or implemented security control.

The sole technical source is the approved [Gate 8 governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md), historically adopted through [ADR 0009](../adr/0009-adopt-local-development-environment-topology.md), retained by ADR 0010, and amended by [ADR 0011](../adr/0011-amend-local-topology-for-dedicated-migration-operator.md). Where this document extracts a table or value from the governing design, the governing design is the canonical reference. This document adds enforcement-column annotations (Phase 1 enforcer, observation, safe failure, validation-scenario owner) and operator-journey indexing that the governing design delegates to the topology contract.

Gate 8 defines exact future filenames, JSON fields, commands, service names, ports, paths, image/source pins, permissions, capacity formulas, and validation scenarios as normative Markdown. Phase 1 owns the executable slices. Gate 10 owns the final Phase 0 closure audit.

## 2. Reference host and exact dependency identity

### 2.1 Reference host

The supported reference host is:

| Resource | Reference minimum | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | ---: | --- | --- | --- | --- |
| Operating system | Ubuntu Desktop 24.04.4 LTS, Linux/amd64 | `central local doctor --host-prerequisites` embedded manifest | `/etc/os-release`, `uname -m` | `HOST_PREREQUISITE_MISMATCH` exit 3 | Scenario 23: prerequisite evidence on clean hosts |
| Browser | Chromium-family at exact manifest identity | `central local doctor --host-prerequisites` | `dpkg-query`/binary hash | `HOST_PREREQUISITE_MISMATCH` exit 3 | Scenario 22: managed browser identity and profile |
| Logical CPUs | 4 | Configless doctor | `/proc/cpuinfo` | `outside_supported_profile` exit 0 diagnostic | Scenario 21: harness token calculation |
| RAM | 8 GiB | Configless doctor | `/proc/meminfo` | `outside_supported_profile` exit 0 diagnostic | Scenario 21: harness token calculation |
| Initially free local data storage | 40 GiB | `central local init` capacity check | `statfs` on data device | `CAPACITY_INSUFFICIENT` exit 4 | Scenario 13: capacity admission |
| Browser profile filesystem | local ext4 with `prjquota` enabled | Configless doctor + `central local init` | `/proc/mounts`, `statfs` | `HOST_PREREQUISITE_MISMATCH` exit 3 | Scenario 22: project quota enforcement |

CPU or RAM below the reference minimum produces an `outside_supported_profile` diagnostic. Workload-specific storage remains a hard precondition computed from exact backup/restore evidence; 40 GiB never substitutes for that calculation.

### 2.2 Locked system identities

| Identity | UID | Purpose | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- | --- |
| `central-runtime` | fixed numeric, no-login | Host process, all-in-one profile | Helper `runtime-start` launch | `/etc/passwd`, `/proc/<pid>/status` | `AUTHORITY_DENIED` exit 7 | Scenario 2: unauthorized root access |
| `central-migrate` | fixed numeric, no-login | One migration or version-zero reset invocation | Helper migration-mode launch and broker peer-UID check | `/etc/passwd`, `/proc/<pid>/status`, broker peer credentials | `AUTHORITY_DENIED` exit 7 | B05 migration credential and reset acceptance |
| `central-agent` | fixed numeric, no-login | Sandboxed execution | `central-sandbox-launcher` | `/proc/<pid>/status`, pidfd | `AUTHORITY_DENIED` exit 7 | Scenario 2: cross-agent ptrace |
| `central-browser` | fixed numeric, no-login | Managed browser profile | Helper `browser-open` scope | systemd scope, `/proc/<pid>/status` | `AUTHORITY_DENIED` exit 7 | Scenario 22: profile ownership enforcement |

All are no-login system identities. The runtime receives descriptor-only supervisor/sandbox boundaries with no repository, Workspace, or Docker/helper socket access. `central-migrate` can run only the fixed migration operator mode and receives no serving, Workspace, Docker, or direct protected-store authority. The browser is root-owned parent `0700` but profile belongs to `central-browser`.

### 2.3 Exact dependency identity table

| Dependency | Selection | Verification boundary | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- | --- |
| Go | 1.26.5 | Inherited from Gate 7 | Build manifest, `go version` | Binary build-info | `INCOMPATIBLE` exit 5 | Scenario 27: build reproducibility |
| Docker Engine and CLI | 29.6.1 | Host prerequisite | `central local doctor` | `docker version --format json` | `HOST_PREREQUISITE_MISMATCH` exit 3 | Scenario 23: package manifest verification |
| Docker Compose plugin | 5.3.1 | Host prerequisite; `docker compose` plugin shape | `central local doctor` | `docker compose version` | `HOST_PREREQUISITE_MISMATCH` exit 3 | Scenario 23: package manifest verification |
| PostgreSQL server image | 16.14, Debian Bookworm variant | OCI index `sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55`; linux/amd64 manifest `sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28`; config `sha256:67d1da22f4037b29cdd93e03d870a4a1c4d079358367d0cbc56459e52cde205e` | Helper `prepare` + embedded lock | Docker daemon inspection, `SELECT version()` | `PREPARATION_REQUIRED` or `DRIFTED` exit 5 | Scenario 3: image identity and no-pull |
| `pg_dump` / `pg_restore` | 16.14 | Absolute host paths and exact reported version | `central local doctor` | Hash + `--version` | `HOST_PREREQUISITE_MISMATCH` exit 3 | Scenario 12: tool adapter and sealed fd 3 |
| MinIO source | `RELEASE.2025-10-15T17-29-55Z` | Commit `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`; archive SHA-256 `be6d0bd3696c3a13a35f02d3a0280b64319c67918b4501c5c3d87f96d000085c` | Helper two-clean-builder `prepare` | OCI index/manifest/config/layer digests + normalized inventory | `INCOMPATIBLE` exit 5 | Scenario 2: two-build reproducibility |

The selected MinIO repository is archived and the selected security-fixed release has no accepted official container image. Phase 1 must build Central's image from the exact source commit with the hermetic two-clean-builder reproducibility contract. ADR 0009 records the archived-upstream maintenance risk, AGPL-3.0 distribution obligations, replacement trigger, and prohibition on falling back to the older pre-fix image.

## 3. Host `central-runtime`/supervisor/control topology

### 3.1 Process placement

One `central serve` process runs directly on the host under the locked `central-runtime` service UID and co-locates HTTP, execution, outbox, reconciliation, cleanup, and recovery components. The operator-facing `central serve` command is a controller that asks the installed service launcher to start that exact process and then follows its safe foreground status. Central is not an application container.

| Component | Location | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Application HTTPS listener | `central serve` process, `central-runtime` | Foreground supervisor | `ss -tlnp` | Exit via Gate 7 stable class | Scenario 1: all-in-one profile |
| Operational HTTP listener | `central serve` process, `central-runtime` | Foreground supervisor | `ss -tlnp` | Exit via Gate 7 stable class | Scenario 1: operational listener |
| Execution coordination | `central serve` process, `central-runtime` | Supervisor + pidfd | Component health | Terminal failure → cancel profile exit 6 | Scenario 15: component failure |
| Outbox delivery | `central serve` process, `central-runtime` | Supervisor + pidfd | Component health | Terminal failure → cancel profile exit 6 | Scenario 15: component failure |
| Artifact reconciliation and cleanup | `central serve` process, `central-runtime` | Supervisor + pidfd | Component health | Terminal failure → cancel profile exit 6 | Scenario 15: component failure |
| Task/runtime reconciliation | `central serve` process, `central-runtime` | Supervisor + pidfd | Component health | Terminal failure → cancel profile exit 6 | Scenario 15: component failure |

### 3.2 Supervisor/controller separation

The foreground `central-runtime` supervisor is the runtime's real parent and owns a root-created `SOCK_SEQPACKET` control/status pair plus pidfd. The operator controller receives only the peer carrying a one-use launch nonce and can send `interrupt` or `status`; it cannot inject config, signal number, command, or authority.

| Boundary | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- |
| Controller-to-supervisor control | Nonce-bound `SOCK_SEQPACKET` pair | Pipe/pidfd identity | Controller disconnect → graceful cancellation | Scenario 6: controller disconnect |
| SIGINT/SIGTERM relay | Supervisor relays as fixed graceful cancellation within 1 s | pidfd + signal | Exit 0 after settlement | Scenario 16: shutdown |
| Supervisor loss | Runtime parent-death cancellation | pidfd + `PR_SET_PDEATHSIG` | Exit 6 terminal | Scenario 6: supervisor crash |

## 4. Helper/broker/sandbox-launcher request and denial matrices

### 4.1 Infrastructure helper request matrix

The helper is an internal mode of the same Central release artifact, installed as a root-owned immutable copy at a fixed absolute path. The ordinary operator UID is not a member of the Docker group, has no Docker-socket ACL, and cannot open the local Docker socket. The helper permits only this closed operation matrix:

| Request | Permitted authority | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| `init` / `init-status` / `init-resume` / `init-abandon` | Configless journaled initialization; abandon limited to unaccepted empty reservation; no network/Docker | Root `sudoers` with `env_reset`, `timestamp_timeout=0`, fixed executable | Root intent audit journal | `AUTHORITY_DENIED` exit 7 | Scenario 1: init journal life cycle |
| `prepare` | Fetch, build, verify, load only embedded locked dependency artifacts | Root `sudoers` + embedded lock | Preparation receipts | `PREPARATION_REQUIRED` exit 3 | Scenario 2: two-clean-builder |
| `security-update` | Fetch only embedded advisory endpoint or consume fixed inherited offline descriptor | Root `sudoers` + Ed25519 key | Advisory bundle + admission receipt | `SECURITY_REVIEW_REQUIRED` exit 5 | Scenario 2: authority expiry |
| `dependency-upgrade-plan` / `dependency-upgrade-apply` / `dependency-upgrade-resume` | Ticket-bound old-to-new patch transition | Root `sudoers` + embedded compatibility evidence | Upgrade operation journal | `UPGRADE_NOT_SAFE` exit 5 | Scenario 23: ticketed upgrade |
| `trust-install` / `trust-remove` | Install/remove only exact validated instance CA public certificate | Root `sudoers` + CA constraint | Trust receipt | `TLS_TRUST_REQUIRED` exit 3 | Scenario 22: browser trust policy |
| `browser-open` / `browser-clear` / `browser-clear-resume` | Launch/exact journaled profile replacement as `central-browser` | Root `sudoers` + Wayland seat verification | Browser scope + profile receipt | `DEPENDENCY_UNAVAILABLE` exit 3 | Scenario 22: browser launch and clear |
| `runtime-stage` | Copy descriptor-opened binary + manifest into staging store | Root `sudoers` + manifest SHA-256 | Staging lease receipt | `AUTHORITY_DENIED` exit 7 | Scenario 27: development lease |
| `runtime-start` / `runtime-stop` / `operator-mode-start` | Launch only embedded/staged-authority modes as `central-runtime` | Root `sudoers` + descriptor-bound config | Runtime pidfd + supervisor | `AUTHORITY_DENIED` exit 7 | Scenario 6: supervisor launch |
| `migration-mode-start` / `migration-reset` | Launch one fixed migration mode as `central-migrate`; reset only the exact failed version-zero operation | Fresh PAM, broker peer-UID binding, exact target lock, TTY phrase for reset | Migration operation journal | `AUTHORITY_DENIED` exit 7 or `PROVISIONING_REPAIR_REQUIRED` exit 5 | B05 version-zero acceptance |
| `up` / `down` | Render embedded Compose model; start/stop exact instance resources | Root `sudoers` + embedded Compose policy | Up/down receipts | `DRIFTED` exit 5 | Scenario 3: restart: "no" enforcement |
| `status` / `doctor` | Bounded read-only inspection of exact instance resources | Root `sudoers` + doctor probes | Doctor findings | `CLEANUP_REQUIRED` exit 5 | Scenario 20: diagnostic redaction |
| `wipe` | Sequential one-root-at-a-time no-network `central-local-infra` wipe | Root `sudoers` + AppArmor profile + TTY confirmation | Wipe operation journal | `RESUME_REQUIRED` exit 6 | Scenario 17: AppArmor-locked wipe |
| `security-rescue-cleanup` | Stop/reap only exact rescue operation topology | Root `sudoers` + rescue binding | Rescue cleanup journal | `CLEANUP_REQUIRED` exit 5 | Scenario 2: rescue cleanup continuation |
| `bootstrap-show` | Broker rotate/write one presentation generation to helper-owned TTY | Root `sudoers` + ready-server proof | Bootstrap presentation receipt | `DEPENDENCY_UNAVAILABLE` exit 3 | Scenario 18: TTY-only reveal |

Every helper-backed command requires fresh PAM authentication (`timestamp_timeout=0`, no passwordless rules, no cached credentials). For destructive operations (wipe, restore apply, hard-expired rescue backup, backup/export deletion, trust removal, protected-generation maintenance, dependency-upgrade apply/resume), PAM success alone is insufficient: the helper additionally opens `/dev/tty`, displays the safe operation/target/plan IDs, reads the fixed confirmation phrase with echo disabled, and binds a one-use confirmation digest.

The B06 activation does not advertise `local trust install`; that command remains
deferred until its CA-install and protected-bootstrap staging authority is
implemented end to end.

### 4.2 Protected broker request matrix

The broker is a root-owned, socket-activated `central-protected-broker` mode. It has no network, Docker, shell, package, Workspace, arbitrary-path, or caller-executable authority and exits after the fixed idle deadline.

| Request | Permitted authority | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Secret resolution | Resolve exact purpose-bound generation to sealed memfd | Root-owned `0600` Unix socket + auth session | HMAC version token | `PROTECTED_STATE_INVALID` exit 5 | Scenario 19: protected value lifecycle |
| TLS signing | Leaf-only `crypto.Signer`; CA signs only fixed offline rotation | Root-owned socket + authenticated session | Certificate fingerprint | `PROTECTED_STATE_INVALID` exit 5 | Scenario 19: private key isolation |
| HMAC fingerprinting | Domain-separated HMAC-SHA-256 under versioned fingerprint key | Root-owned socket + auth session | Opaque version token | `PROTECTED_STATE_INVALID` exit 5 | Scenario 19: raw digests never leave broker |
| XDG view signing | Ed25519 signature over safe snapshot bytes | Root-owned socket | View signature + generation | `SNAPSHOT_INVALID` exit 5 | Scenario 20: signed snapshot integrity |
| Authority transition journaling | Prepared/issued/committed protocol with immutable sequence-specific payloads | Root-owned socket + `binding.lock` | Journal stream head | `PROTECTED_STATE_INVALID` exit 5 | Scenario 12: backup seal commit |
| Dependency handoff | Write exact purpose-bound value into helper's service-scoped tmpfs descriptor or pass a purpose-bound sealed SCM_RIGHTS descriptor to the verified `central-migrate` peer | Mutual auth + fixed policy + peer UID/GID | Generation version token | `HELPER_POLICY_DENIED` exit 7 | Scenario 7 and B05 credential handoff |
| Export signing | Ed25519 sign canonical export manifest for `bx1` token | Root-owned socket + export signing key | `bx1` token via exclusive TTY | `AUTHORITY_DENIED` exit 7 | Scenario 24: export integrity token |

### 4.3 Sandbox-launcher denial matrix

The `central-sandbox-launcher` is a distinct root-owned, socket-activated mode with no Docker, network, secret, config-mutation, arbitrary-path, or shell authority. Only an authenticated `central-runtime` launch session may call it.

| Attack | Expected denial | Phase 1 enforcer | Observation | Validation-scenario owner |
| --- | --- | --- | --- | --- |
| Arbitrary absolute path in request | Rejected – no path field accepted | Closed request schema | Launcher audit | Scenario 6: sandbox-launcher |
| Arbitrary UID in request | Rejected – only `central-agent` permitted | `setresuid`/`setresgid` | `/proc/<pid>/status` | Scenario 2: cross-UID |
| Arbitrary executable in request | Rejected – only fixed adapter/executable class | Exec validation | Binary hash | Scenario 6: sandbox-launcher |
| Arbitrary mount in request | Rejected – only delegated Workspace descriptors | `openat2` + binding | Kernel mount namespace | Scenario 6: sandbox-launcher |
| Cross-agent ptrace | Rejected – `PR_SET_DUMPABLE=0`, private PID ns | `ptrace` denial | `PTRACE_MODE_ATTACH` | Scenario 2 |
| Namespace escape | Rejected – private PID/mount ns | `unshare`/`setns` denial | Kernel ns isolation | Scenario 2 |
| Runtime/helper/broker access from agent | Rejected – no socket/descriptor inherited | Descriptor closure | `/proc/<pid>/fd` | Scenario 2 |

## 5. Six-service Compose topology

### 5.1 Compose project and services

The Compose project is `central-<full-instance-id>` and contains exactly one internal network named `infra` plus six services. Central itself is not a Compose service. Docker daemon restart, host reboot, dependency process exit, or an unhealthy probe never auto-starts or auto-restarts a service.

| Service | Lifetime | Network | Writable mount | Image | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `postgres-fs-init` | one-shot | none | PostgreSQL data directory only | `central-local-infra` (`fs-init` mode) | Helper `up` before daemon | Init receipt + container exit 0 | `RESUME_REQUIRED` if interrupted | Scenario 7: fs-init write audit |
| `minio-fs-init` | one-shot | none | MinIO data directory only | `central-local-infra` (`fs-init` mode) | Helper `up` before daemon | Init receipt + container exit 0 | `RESUME_REQUIRED` if interrupted | Scenario 7: fs-init write audit |
| `postgres` | long-running | `infra` | PostgreSQL data directory | `library/postgres:16.14-bookworm@sha256:c95fd...` | Embedded Compose policy | `pg_isready` probe | `STOPPED`; recovery probes on next `up` | Scenario 3: restart: "no" |
| `minio` | long-running | `infra` | MinIO data directory | Locally built MinIO at exact manifest digest | Embedded Compose policy | MinIO readiness endpoint | `STOPPED`; recovery probes on next `up` | Scenario 3: restart: "no" |
| `postgres-provision` | one-shot | `infra` | none | `library/postgres:16.14-bookworm@sha256:c95fd...` | Helper `up` after daemon healthy | Provision receipt | `RESUME_REQUIRED` if interrupted | Scenario 8: pre-baseline provisioning |
| `minio-provision` | one-shot | `infra` | none | Locally built MinIO at exact manifest digest | Helper `up` after daemon healthy | Provision receipt | `RESUME_REQUIRED` if interrupted | Scenario 9: bucket/policy provisioning |

### 5.2 Immutable image and restart contract

Every rendered service has exact digest-qualified images, `pull_policy: never`, `restart: "no"`, and no `build:` directive.

| Contract element | Value | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Pull policy | `pull_policy: never` on every service | Helper renders + `docker compose config` | Container inspect | `PREPARATION_REQUIRED` or `DRIFTED` | Scenario 3 |
| Restart policy | `restart: "no"` on every service | Helper renders + `docker compose config` | Container inspect | `DRIFTED` if auto-restart observed | Scenario 3 |
| Image reference format | Exact OCI manifest digest (`@sha256:...`), not tag-only | Helper renders + pre-up inspection | `docker image inspect` | `DRIFTED` if tag-only or mutable | Scenario 3 |
| Build directive | None – no `build:` on any service | Helper renders + policy check | Compose config | `INCOMPATIBLE` | Scenario 3 |

### 5.3 Networks and ports

| Endpoint | Bind | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Central application | `https://127.0.0.1:8080` | `central serve` listener + config validation | `ss -tlnp` | `PORT_IN_USE` exit 4 | Scenario 5: port collision |
| Central operations | `127.0.0.1:9090` | `central serve` listener + config validation | `ss -tlnp` | `PORT_IN_USE` exit 4 | Scenario 5: port collision |
| PostgreSQL host publication | `127.0.0.1:55432` | Docker Compose port mapping | `ss -tlnp` | `PORT_IN_USE` exit 4 | Scenario 5: port collision |
| MinIO S3 API host publication | `127.0.0.1:59000` | Docker Compose port mapping | `ss -tlnp` | `PORT_IN_USE` exit 4 | Scenario 5: port collision |
| MinIO console | not published | Helper Compose policy | Compose config | `INCOMPATIBLE` if published | Scenario 9: no console publication |

The `infra` bridge is project-scoped and internal. Services use Compose DNS aliases, never static IPs or a fixed subnet. Configuration and generated Compose output use numeric addresses, not `localhost`. Any non-loopback bind is a startup failure. No wildcard host, proxy, forwarded-address trust, wildcard CORS, or published MinIO console is valid in `central.config/v1`.

### 5.4 Listener and TLS boundary

| Constraint | Value | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| TLS version | 1.3 minimum | `central serve` TLS config | TLS handshake | `CONFIG_INVALID` exit 2 | Scenario 5: HTTPS origin |
| Certificate SAN | IP `127.0.0.1` only, no DNS SAN/wildcard | Broker leaf rotation | Certificate inspection | `CONFIG_INVALID` exit 2 | Scenario 5: correct SAN |
| CA/leaf key isolation | Root-owned protected broker generations | Broker socket auth | Protected generation journal | `PROTECTED_STATE_INVALID` exit 5 | Scenario 19: private key non-enumeration |
| Trust installation | Explicit `central local trust install` | Helper + system/NSS store | Trust receipt | `TLS_TRUST_REQUIRED` exit 3 | Scenario 22: CA anchor installation |
| Origin | `https://127.0.0.1:8080` | Cookie `Secure`, no CORS | Browser security headers | `CONFIG_INVALID` exit 2 | Scenario 5: correct Origin |

Application TLS requires TLS 1.3 with an instance-bound certificate having SAN IP `127.0.0.1` only. The CA and leaf private keys are root-owned protected broker generations. `central local trust install` is an explicit administrative trust transition.

## 6. Container capabilities, seccomp/AppArmor, rootfs, tmpfs/shm, UID/GID, writable-mount, memory/CPU/PID envelope

### 6.1 Container privilege baseline

| Service | Capabilities | no-new-privileges | Rootfs | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `postgres` (daemon) | none (all dropped) | yes | read-only | Container inspect | `/proc/1/status` NoNewPrivs + cap mask | `INCOMPATIBLE` exit 5 | Scenario 7: write audit |
| `minio` (daemon) | none (all dropped) | yes | read-only | Container inspect | `/proc/1/status` NoNewPrivs + cap mask | `INCOMPATIBLE` exit 5 | Scenario 7: write audit |
| `postgres-provision` | none (all dropped) | yes | read-only | Container inspect | `/proc/1/status` NoNewPrivs + cap mask | `INCOMPATIBLE` exit 5 | Scenario 7: write audit |
| `minio-provision` | none (all dropped) | yes | read-only | Container inspect | `/proc/1/status` NoNewPrivs + cap mask | `INCOMPATIBLE` exit 5 | Scenario 7: write audit |
| `postgres-fs-init` | `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER` only | yes | read-only | Container inspect | `/proc/1/status` cap mask | `INCOMPATIBLE` exit 5 | Scenario 7: fs-init caps |
| `minio-fs-init` | `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER` only | yes | read-only | Container inspect | `/proc/1/status` cap mask | `INCOMPATIBLE` exit 5 | Scenario 7: fs-init caps |
| Wipe mode | `CAP_DAC_OVERRIDE` only | yes | read-only | Container inspect + AppArmor profile | `/proc/1/status` cap mask | `HELPER_POLICY_DENIED` exit 7 | Scenario 17: wipe capability |

Both long-running daemons run as the numeric non-root UID/GID recorded in the dependency lock: PostgreSQL `999:999`, MinIO `1000:1000`.

### 6.2 Exact container writable-path contract

The dependency lock fixes PostgreSQL UID/GID `999:999` and MinIO UID/GID `1000:1000`. The image filesystem, working directory, binaries, libraries, `/etc`, and entrypoint configuration are read-only.

| Service/mode | Durable read-write mount | Ephemeral writable mounts | Fixed runtime contract | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `postgres-fs-init` | held PostgreSQL root at `/payload`; root directory itself is preserved | `/dev/shm` 8 MiB, mode `01777` | `HOME` unset; working directory `/` | Container inspect + in-container mountinfo | Mount table + `stat` | `INCOMPATIBLE` exit 5 | Scenario 7 |
| `minio-fs-init` | held MinIO root at `/payload`; root directory itself is preserved | `/dev/shm` 8 MiB, mode `01777` | `HOME` unset; working directory `/` | Container inspect + in-container mountinfo | Mount table + `stat` | `INCOMPATIBLE` exit 5 | Scenario 7 |
| `postgres` | PostgreSQL root at `/var/lib/postgresql/data` | `/tmp` 64 MiB `01770`; `/run/postgresql` 16 MiB `0750`; `/dev/shm` 768 MiB `01777` | UID/GID `999:999`; `PGDATA=/var/lib/postgresql/data` | Container inspect + in-container mountinfo | Full mount table + owner/mode | `INCOMPATIBLE` exit 5 | Scenario 7 |
| `minio` | MinIO root at `/data` | `/tmp` 256 MiB `01770`; `/home/minio` 16 MiB `0700`; `/run` 16 MiB `0750`; `/dev/shm` 64 MiB `01777` | UID/GID `1000:1000`; `HOME=/home/minio` | Container inspect + in-container mountinfo | Full mount table + owner/mode | `INCOMPATIBLE` exit 5 | Scenario 7 |
| `postgres-provision` | none | `/tmp` 16 MiB `0700`; `/dev/shm` 8 MiB `01777` | UID/GID `999:999`; `HOME=/tmp/home`; network only `infra` | Container inspect + in-container mountinfo | Full mount table + owner/mode | `INCOMPATIBLE` exit 5 | Scenario 7 |
| `minio-provision` | none | `/tmp` 16 MiB `0700`; `/home/minio` 8 MiB `0700`; `/run` 8 MiB `0750`; `/dev/shm` 8 MiB `01777` | UID/GID `1000:1000`; `HOME=/home/minio`; network only `infra` | Container inspect + in-container mountinfo | Full mount table + owner/mode | `INCOMPATIBLE` exit 5 | Scenario 7 |
| one-off `wipe` | one held payload root at `/payload`; root directory itself is preserved | `/tmp` 8 MiB `0700`; `/dev/shm` 8 MiB `01777` | UID/GID `0:0`; working directory `/`; no home/network/second payload | Container inspect + AppArmor profile | Full mount table + owner/mode | `HELPER_POLICY_DENIED` exit 7 | Scenario 17 |

Every listed tmpfs is private, size-capped, owned by the listed UID/GID, and mounted `rw,nosuid,nodev,noexec`. Docker IPC is private. No TTY, host PID/IPC namespace, device, cgroup namespace mutation, or additional anonymous/named volume is permitted.

### 6.3 Container resource envelope

| Service | CPU limit | Memory limit | PID limit | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | ---: | ---: | ---: | --- | --- | --- | --- |
| `postgres` | 1.5 | 2 GiB | 256 | Docker resource constraints | `docker stats` + cgroup | OOM → dependency failure exit 6 | Scenario 15: cgroup OOM |
| `minio` | 1.5 | 2 GiB | 256 | Docker resource constraints | `docker stats` + cgroup | OOM → dependency failure exit 6 | Scenario 15: cgroup OOM |
| each filesystem initializer | 0.25 | 256 MiB | 64 | Docker resource constraints | `docker stats` + cgroup | `DRIFTED` or `RESUME_REQUIRED` | Scenario 7: fs-init resource use |
| each logical provisioner | 0.5 | 512 MiB | 128 | Docker resource constraints | `docker stats` + cgroup | `DRIFTED` or `RESUME_REQUIRED` | Scenario 8/9: provisioner resource use |

### 6.4 PostgreSQL locked settings

PostgreSQL uses the following locked settings; config and `SHOW` drift are startup failures:

| PostgreSQL setting | Installed value | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | ---: | --- | --- | --- | --- |
| `shared_buffers` | 512 MiB | `postgres-provision` + `local doctor` | `SHOW shared_buffers` | `DRIFTED` exit 5 | Scenario 7: shm sizing |
| `work_mem` | 4 MiB | `postgres-provision` + `local doctor` | `SHOW work_mem` | `DRIFTED` exit 5 | Scenario 15: memory envelope |
| `maintenance_work_mem` | 128 MiB | `postgres-provision` + `local doctor` | `SHOW maintenance_work_mem` | `DRIFTED` exit 5 | Scenario 15: memory envelope |
| `autovacuum_work_mem` | 64 MiB | `postgres-provision` + `local doctor` | `SHOW autovacuum_work_mem` | `DRIFTED` exit 5 | Scenario 15: memory envelope |
| `temp_buffers` | 8 MiB | `postgres-provision` + `local doctor` | `SHOW temp_buffers` | `DRIFTED` exit 5 | Scenario 15: memory envelope |
| `wal_buffers` | 16 MiB | `postgres-provision` + `local doctor` | `SHOW wal_buffers` | `DRIFTED` exit 5 | Scenario 15: memory envelope |
| `max_connections` | 32 | `postgres-provision` + `local doctor` | `SHOW max_connections` | `DRIFTED` exit 5 | Scenario 11: connection cap |
| `superuser_reserved_connections` | 3 | `postgres-provision` + `local doctor` | `SHOW superuser_reserved_connections` | `DRIFTED` exit 5 | Scenario 11: connection cap |
| `autovacuum_max_workers` | 2 | `postgres-provision` + `local doctor` | `SHOW autovacuum_max_workers` | `DRIFTED` exit 5 | Scenario 15: memory envelope |
| `max_worker_processes` | 4 | `postgres-provision` + `local doctor` | `SHOW max_worker_processes` | `DRIFTED` exit 5 | Scenario 15: memory envelope |
| `max_parallel_workers` | 0 | `postgres-provision` + `local doctor` | `SHOW max_parallel_workers` | `DRIFTED` exit 5 | Scenario 15: parallel disabled |
| `max_parallel_workers_per_gather` | 0 | `postgres-provision` + `local doctor` | `SHOW max_parallel_workers_per_gather` | `DRIFTED` exit 5 | Scenario 15: parallel disabled |
| `max_parallel_maintenance_workers` | 0 | `postgres-provision` + `local doctor` | `SHOW max_parallel_maintenance_workers` | `DRIFTED` exit 5 | Scenario 15: parallel disabled |
| `temp_file_limit` | 256 MiB per backend | `postgres-provision` + `local doctor` | `SHOW temp_file_limit` | `DRIFTED` exit 5 | Scenario 15: temp file cap |
| `max_wal_size` | 1 GiB | `postgres-provision` + `local doctor` | `SHOW max_wal_size` | `DRIFTED` exit 5 | Scenario 13: WAL allowance |
| `min_wal_size` | 256 MiB | `postgres-provision` + `local doctor` | `SHOW min_wal_size` | `DRIFTED` exit 5 | Scenario 13: WAL allowance |
| `jit` | `off` | `postgres-provision` + `local doctor` | `SHOW jit` | `DRIFTED` exit 5 | Scenario 15: JIT disabled |
| `huge_pages` | `off` | `postgres-provision` + `local doctor` | `SHOW huge_pages` | `DRIFTED` exit 5 | Scenario 15: huge_pages disabled |

PostgreSQL `shm_size` is 768 MiB: 512 MiB shared buffers plus WAL/lock/extension fixed shared allocations and measured headroom.

### 6.5 Reference-host aggregate memory envelope

The 8-GiB reference profile does not rely on swap or optimistic overcommit:

| Profile | Bound calculation | Maximum | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | ---: | --- | --- | --- | --- |
| steady `serve` without browser | PostgreSQL 2 GiB + MinIO 2 GiB + Central 768 MiB + reserve 2 GiB | 6.75 GiB | Runtime memory check + cgroup | `GOMEMLIMIT`, RSS, cgroup stats | Exit 6 after 30 s above ceiling | Scenario 15: steady memory |
| browser launch/steady | + browser 512 MiB + controller/helper 256 MiB | 7.5 GiB | Runtime + browser scope `MemoryMax` | cgroup + RSS | OOM → scope killed | Scenario 22: browser memory |
| `local up`/provision | + one 512-MiB provisioner + controller 256 MiB | 6.75 GiB | Helper resource constraints | cgroup stats | `DEPENDENCY_UNAVAILABLE` | Scenario 15: provision memory |
| backup/restore | + controller 256 MiB + one tool 512 MiB | 6.75 GiB | Tool adapter RSS ceiling | `/proc/<pid>/status` VmRSS | Exit 6 terminal | Scenario 12: tool memory |
| clean `prepare` build | dependencies stopped + build 3 GiB + helper 256 MiB + BuildKit 1 GiB + reserve 2 GiB | 6.25 GiB | BuildKit resource constraints | cgroup stats | `INCOMPATIBLE` | Scenario 2: build memory |

The fixed 2-GiB host reserve covers kernel, Docker daemon outside build, filesystem cache, SSH/shell, and measurement error; at least 512 MiB remains additional headroom in every profile.

## 7. Descriptor-bound fs-init/provision/secret-handoff protocols

### 7.1 Filesystem initializer protocol

Filesystem initializers run as root with no network, one exact mount, `no-new-privileges`, a read-only root filesystem, and only `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER`.

| Step | Protocol | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Bind validation | Helper reopens from binding descriptor, compares `statx`/handle/mountinfo | Helper `openat2`/`statx` + held descriptor | Mount ID + device/inode/type | `DRIFTED` exit 5 | Scenario 4: descriptor validation |
| Container bind | Uses `/proc/<helper-pid>/fd/<fixed-fd>` as transient source | Helper procfs descriptor bind | Docker mount inspection | `CLEANUP_REQUIRED` if resolve fails | Scenario 4: descriptor bind |
| Container initialization | Entrypoint verifies `/payload` against expected device/inode/type; creates absent directory; sets ownership/mode | Entrypoint + host acknowledgement | Stdout acknowledgement | `RESUME_REQUIRED` exit 6 | Scenario 7: init write audit |
| Post-init verification | Helper compares acknowledgement to held descriptor evidence | Helper descriptor re-read | Device/inode/type/ownership | `DRIFTED` exit 5 | Scenario 7: post-init verification |

The helper rejects symlinks, changed device/mount identity, unexpected ownership, or nonempty unrecognized content.

### 7.2 Secret handoff protocol

Root-owned protected generations are never mounted directly into a container and secret values never appear in Compose YAML, image metadata, environment variables, command arguments, receipts, or Docker labels.

| Step | Protocol | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Tmpfs creation | Helper creates create-only destination beneath `/run/central-infra/<instance-id>/secrets/` | Helper creates in root-owned tmpfs | Tmpfs mount + directory | `CLEANUP_REQUIRED` | Scenario 7: secret handoff |
| Broker resolution | Broker resolves only exact active dependency-secret purpose/generation and writes bounded value to tmpfs descriptor | Broker auth session + fixed policy | Generation version token | `PROTECTED_STATE_INVALID` exit 5 | Scenario 7: broker write |
| File permission | Each file `0400`, owned by locked numeric UID/GID of exactly one consuming service | Helper `fchown`/`fchmod` | Container-side `stat` | `INCOMPATIBLE` exit 5 | Scenario 7: secret file ownership |
| Container mount | Bind-mounted read-only to one fixed in-container `_FILE` path | Docker Compose secrets/config mount | Container-side mount table | `INCOMPATIBLE` exit 5 | Scenario 7: `_FILE` interface |
| Cleanup (one-shot) | Helper removes file after stopped container releases its mount; correlates with generation version token | Helper rm + correlation | File absent + mount released | `CLEANUP_REQUIRED` | Scenario 7: one-shot cleanup |
| Cleanup (long-running) | MinIO server-scoped copy remains only while exact instance container exists; removed after `local down` | Helper rm after container stop | File absent + mount released | `CLEANUP_REQUIRED` | Scenario 7: server-scoped cleanup |

The mutually embedded helper/broker policy fixes the allowed mapping of secret purpose, service, target path, UID/GID, maximum size, and lifetime. Docker receives only the resulting file mount; it cannot request another protected binding.

### 7.3 PostgreSQL logical provisioning protocol

`postgres-provision` is idempotent and least-privileged. It owns only cluster/database prerequisites, not application schema.

| Constraint | Protocol | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Prerequisite scope | Fixed `central` database, three login roles with SCRAM, authentication posture, database-level grants | `postgres-provision` idempotent checks | `pg_roles`, `pg_database`, `pg_hba` | `DRIFTED` exit 5 | Scenario 8: pre-baseline provisioning |
| Schema boundary | Does not create or require `central` application schema | `postgres-provision` | `pg_namespace` | Absent schema is valid `MIGRATION_REQUIRED` | Scenario 8: absent-schema valid state |
| Migration ownership | Only version-zero migration creates schema/history/baseline | `migrate up` + `migrate verify` | Schema inspection | `DRIFTED` or `INCOMPATIBLE` | Scenario 8: migration baseline boundary |

### 7.4 MinIO logical provisioning protocol

| Constraint | Protocol | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Bucket | One private `central-artifacts-v1` bucket | `minio-provision` idempotent checks | `mc ls` | `DRIFTED` exit 5 | Scenario 9: bucket provisioning |
| Identities | Three non-root identities (runtime, backup, restore) with exact canonical policy digests | `minio-provision` policy attachment | Policy SHA-256 comparison | `DRIFTED` exit 5 | Scenario 9: identity provisioning |
| Policy digests | Runtime `b4613cce...`, Backup `aa5f63fd...`, Restore `79ec56ce...` | Policy canonicalization + SHA-256 | Runtime SHA-256 | `DRIFTED` exit 5 | Scenario 9: policy digest enforcement |
| Denials | No group membership, no console/admin credentials, no presigned browser delivery | `minio-provision` | IAM + bucket policy | `DRIFTED` exit 5 | Scenario 9: denial verification |

## 8. Browser Wayland/trust/profile/quota and loopback TLS boundary

### 8.1 Managed browser profile

| Constraint | Value | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Profile root | `/var/lib/central-browser/v1/<instance-id>/` beneath root-owned `0700` parent | Helper `browser-open` | `stat` parent mode + owner | `AUTHORITY_DENIED` exit 7 | Scenario 22: profile ownership |
| Profile owner | `central-browser` UID/GID | Helper `chown` + scope launch | `stat` instance directory | `AUTHORITY_DENIED` exit 7 | Scenario 22: profile access |
| Project quota | ext4 project hard quota 1 GiB / 50,000 inodes | Helper quota receipt + `local doctor` | Kernel quota record + receipt MAC | `DRIFTED` exit 5 | Scenario 22: quota enforcement |
| Disk cache ceiling | 256 MiB | Chromium cache policy | Profile cache directory size | Quota drift blocks open | Scenario 22: cache ceiling |
| Scope resources | 1 CPU, 512 MiB `MemoryMax`, PID limit 256 | systemd scope | cgroup stats | OOM → scope killed | Scenario 22: scope limits |
| Wayland launch | Helper opens exact compositor socket, passes `WAYLAND_SOCKET=<fixed-fd>` | Helper `browser-open` | `WAYLAND_SOCKET` descriptor | `AUTHORITY_DENIED` exit 7 | Scenario 22: Wayland descriptor |
| Disabled features | Downloads, extensions, developer tools/protocol, password storage, sync, external URL handlers, service workers, background mode, non-loopback navigation | Root-managed Chromium policy | Browser policy inspection | `DRIFTED` exit 5 | Scenario 22: browser policy enforcement |

### 8.2 Browser loopback and TLS trust

| Constraint | Value | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Origin | `https://127.0.0.1:8080` | Browser policy + `trust install` | CA/NSS trust store | `TLS_TRUST_REQUIRED` exit 3 | Scenario 22: correct origin |
| Trust anchors | Only root-managed system + NSS anchors | `trust install` receipt | `certutil` / `trust list` | Certificate warning → unsupported | Scenario 22: trust policy |
| Network | Numeric loopback only through namespace policy | Chromium network policy | Browser network inspection | `AUTHORITY_DENIED` exit 7 | Scenario 22: loopback-only |
| Browser clear | Journaled revocation/quarantine/recreate protocol; 5-minute deadline | `central local browser clear` | `central.browser-clear-operation/v1` journal | `RESUME_REQUIRED` exit 6 | Scenario 22: clear lifecycle |
| Window close | Closing last Central window terminates background processes | systemd scope | Scope state | Scope `inactive` | Scenario 22: scope termination |

## 9. Lifecycle/host/target locks, derived environment/serve states, health layers, retry, shutdown, and restart behavior

### 9.1 Lock ownership matrix

Each instance has fixed `lifecycle.lock` and `runtime.lock` files. Lock files are never removed during ordinary operation.

| Command/phase | `lifecycle.lock` | `runtime.lock` | PostgreSQL target lock | Phase 1 enforcer | Observation | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- | --- |
| `serve` | shared | exclusive | shared for profile lifetime | File locks + PostgreSQL advisory | `pg_locks` + `/proc/locks` | Scenario 11: dual-lock enforcement |
| Snapshot `local status`, `local security status` | none | none | none | Lockless; signed view only | Snapshot generation/age | Scenario 1: lockless snapshots |
| `bootstrap show` | shared | shared (ready serve required) | shared; exclusive bootstrap row | Bootstrap `binding.lock` + DB row lock | `pg_locks` | Scenario 18: bootstrap lock |
| `local browser clear` | exclusive | exclusive | exclusive through session revocation | File locks + DB session revocation | `pg_stat_activity` | Scenario 22: browser clear locks |
| `migrate verify`, `migrate status`, `restore verify` | shared | — | shared target-reading | File lock + DB lock | `pg_locks` | Scenario 11: read-only coexistence |
| `backup verify` (target-reading) | shared | — | shared | File lock + DB lock | `pg_locks` | Scenario 11: read-only coexistence |
| `backup status/list`, `restore status` | shared | — | none | Protected-state/repository read | Journal + receipt | Scenario 11: no-target reads |
| `backup export`, `backup export resume` | shared | — | none | Shared backup-repository lock | Repository lock | Scenario 24: export locks |
| `backup import`, `backup import resume` | shared | — | none | Exclusive destination backup-repository lock | Repository lock | Scenario 24: import locks |
| `backup delete/prune plan/apply` | exclusive | — | none | Exclusive backup-repository lock | Repository lock | Scenario 25: delete locks |
| `migrate up`, exact `migrate resume` | shared | — | exclusive then migration-specific | File lock + DB lock | `pg_locks` | Scenario 11: migration exclusivity |
| `backup create`, accepted-point `backup resume` | shared | — | exclusive through verified seal | File lock + DB lock | `pg_locks` | Scenario 12: backup exclusivity |
| hard-expired rescue backup | exclusive | — | exclusive through verified seal | File lock + DB lock + cold-copy evidence | Cold-copy inventory | Scenario 2: rescue exclusivity |
| `restore apply`, pre-ready `restore resume` | shared | — | exclusive through complete barrier | File lock + DB lock + restore barrier | `pg_locks` + restore epoch | Scenario 14: restore exclusivity |
| `local init`, `prepare`, `security update`, `up`, `down`, `wipe`, credential rotation | exclusive | exclusive where needed | none or target-exclusive per phase | File locks | `/proc/locks` | Scenario 3: lifecycle exclusivity |

Host shared lock asserts only that dependency topology/data roots remain stable; it grants no target coexistence beyond the Gate 7 matrix.

### 9.2 Derived environment state

| State | Condition | Phase 1 enforcer | Observation | Next action |
| --- | --- | --- | --- | --- |
| `ABSENT` | No instance binding exists | `local status` | XDG view, binding | `local init` |
| `INITIALIZED` | Config/bindings exist; no current-epoch dependency/schema receipt | `local status` / `local doctor` | Payload epoch, receipts | `local up` |
| `DATA_READY` | Dependency data directories prepared | `local status` / `local doctor` | fs-init receipts | `local up` continues to provision |
| `DEPENDENCIES_HEALTHY` | PostgreSQL and MinIO running and healthy | `local status` / `local doctor` | Compose health + provision receipts | `migrate up` if schema absent |
| `PROVISIONED` | Logical provisioning complete | `local status` / `local doctor` | Provision receipts | `migrate up` if schema absent |
| `MIGRATION_REQUIRED` | Dependencies healthy/provisioned with absent or behind schema | `local status` / `local doctor` | Schema version | `migrate up` |
| `ENVIRONMENT_READY` | Provisioned + compatible schema/ready external barrier | `local doctor` | Ready barrier | `central serve` |
| `STOPPED` | Exact durable bindings/receipts remain; dependencies intentionally stopped | `local status` | Boot ID + container start ID | `local up` |
| `DEGRADED` | Cleanup-required, released-reserve, terminal failure, or incomplete accepted operation | `local status` / `local doctor` | Failure evidence | `local doctor`, resume, or repair |
| `DRIFTED` | Unsafe/ambiguous binding, authority, policy, epoch, or mutation evidence | `local status` / `local doctor` | Mismatch evidence | `local doctor`, manual inspection |

Overlapping evidence uses this fixed first-match precedence: `DRIFTED` > `DEGRADED` > `STOPPED` > `MIGRATION_REQUIRED` > `ENVIRONMENT_READY` > `PROVISIONED` > `DEPENDENCIES_HEALTHY` > `DATA_READY` > `INITIALIZED` > `ABSENT`.

### 9.3 Three health layers

| Layer | Probe | Deadline | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | ---: | --- | --- | --- | --- |
| Container health | Credential-free: `pg_isready` for PostgreSQL; MinIO readiness endpoint | 2 min Compose health | Docker health check | Container health status | Health timeout → `STOPPED` | Scenario 3: container health |
| Provisioned-dependency readiness | Exact instance/config/image/epoch receipt; boot/start IDs; database/schema/role; bucket identity; policy digest; runtime credential metadata | Startup dependency 30 s | `local doctor` semantic checks | Receipt + semantic probe | `DEPENDENCY_UNAVAILABLE` exit 3 | Scenario 15: semantic dependency |
| Central readiness | No incomplete wipe; protected state; current schema; ready epochs; startup reconciliation; pools/adapters; target shared lock; every enabled component | Preflight 5 s | `central serve` startup | `/health/ready` | Readiness false; terminal failure exit 6 | Scenario 15: central readiness |

### 9.4 Retry and shutdown

| Behavior | Value | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Startup dependency connection deadline | 30 s installed | Runtime | Connection attempt + semantic probe | `DEPENDENCY_UNAVAILABLE` exit 3 | Scenario 15: startup dependency |
| Transient dependency backoff | Exponential 250 ms to 5 s with jitter | Runtime | Backoff state | Terminal after 60 s budget | Scenario 15: retry exhaustion exit 6 |
| Target-lock loss | Immediate terminal | Runtime | Connection health check | Exit 6, never retry | Scenario 15: target-lock loss |
| Settlement grace | 30 s | Runtime on shutdown | Durable effect checkpoint | Timeout → exit 6 | Scenario 16: shutdown settlement |
| Total shutdown | 45 s default, max 3 min | Runtime on shutdown | Shutdown progression | Timeout → exit 6 | Scenario 16: total-shutdown timeout |
| PostgreSQL stop grace | 60 s | Docker Compose | Container stop time | Forced termination → recovery probes | Scenario 3: postgres stop |
| MinIO stop grace | 30 s | Docker Compose | Container stop time | Forced termination → recovery probes | Scenario 3: minio stop |
| `local down` deadline | 90 s total | Helper | Container stop + mount release | `CLEANUP_REQUIRED` | Scenario 17: down preserves data |

### 9.5 Stable exit classes for `central serve`

| Exit | Meaning | Phase 1 enforcer | Observation | Validation-scenario owner |
| ---: | --- | --- | --- | --- |
| 0 | Intentional stop after durable settlement obligations | Supervisor waits for settlement | Settlement evidence | Scenario 16: graceful exit |
| 2 | Invalid invocation or configuration | Config parser / supervisor | `CONFIG_INVALID` | Scenario 1: config validation |
| 3 | Required dependency unavailable during startup | Startup preflight | `DEPENDENCY_UNAVAILABLE` | Scenario 15: startup dependency |
| 4 | Startup target-lock, pool, or bounded-preflight timeout | Startup preflight | Lock/pool timeout | Scenario 11: lock timeout |
| 5 | Dirty/incompatible schema or missing/corrupt/non-ready/mismatched restore barrier | Startup preflight | Schema/barrier check | Scenario 11: incompatible schema |
| 6 | Terminal runtime component failure, indeterminate process state, failed settlement, or total-shutdown timeout | Supervisor | Component failure | Scenario 15: terminal failure |
| 7 | Denied or insufficient authority, or preflight requires provisioning (`PROVISION_REQUIRED`) | Supervisor or startup preflight | Auth check or schema readiness | Scenario 2: authority denial; B06: run exact `central migrate up` |

A dependency lost after readiness that exhausts its finite retry budget exits `6`, never startup class `3`.

## 10. Aggregate memory/resource profile and test-suite concurrency

### 10.1 Resource pools and caps

The all-in-one profile installs the Gate 7 resource defaults:

| Resource | Installed value | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | ---: | --- | --- | --- | --- |
| Artifact active transfers | 2 | Config validation | Adapter state | `CONFIG_INVALID` | Scenario 15: adapter limits |
| Serving data pools (total) | 12 (6 general + 2 settlement + 3 outbox + 1 cleanup) | Config validation + `pg_stat_activity` | Pool state | `CONFIG_INVALID` above cap | Scenario 11: connection cap |
| Installation-wide target cap | 16 (12 serving + 2 coexisting read-only + 2 offline) | Config validation + `pg_stat_activity` | Active connections by `application_name` | `INCOMPATIBLE` exit 5 | Scenario 11: connection cap |
| Go memory limit | 640 MiB (`GOMEMLIMIT`) | Runtime `debug.SetMemoryLimit` | `runtime/metrics` | Exit 6 after 30 s above ceiling | Scenario 15: memory limit |
| Central RSS ceiling | 768 MiB | Runtime monitoring | `/proc/self/status` VmRSS | Exit 6 after 30 s above | Scenario 15: RSS ceiling |
| Host memory reserve | 2 GiB | System memory check | `/proc/meminfo` MemAvailable | Dependency failure | Scenario 15: host reserve |

### 10.2 Offline connection matrix

Exactly two offline permits are installation-wide:

| Offline phase | Lock/control permit | Data/tool permit | Exact maximum | Phase 1 enforcer | Observation | Validation-scenario owner |
| --- | ---: | ---: | ---: | --- | --- | --- |
| migration up/resume | one non-rebinding session owns locks | none | 1 | `pg_stat_activity` by `application_name` | Active sessions | Scenario 11: migration sessions |
| backup accepted point and dump | one lifetime target-exclusive | one `pg_dump` session | 2 | `pg_stat_activity` by `application_name` | Active sessions | Scenario 12: backup sessions |
| backup inventory/seal or target-reading verify | one lifetime/shared | one read-only session | 2 | `pg_stat_activity` by `application_name` | Active sessions | Scenario 12: inventory sessions |
| backup throughput probe | one lifetime target-exclusive | one provisioner then one `pg_dump` sequentially | 2 | `pg_stat_activity` by `application_name` | Active sessions | Scenario 12: probe sessions |
| restore verify/ticket | one shared target | one read-only verification | 2 | `pg_stat_activity` by `application_name` | Active sessions | Scenario 14: verify sessions |
| restore database replacement | one lifetime target-exclusive | one `pg_restore` session | 2 | `pg_stat_activity` by `application_name` | Active sessions | Scenario 14: restore sessions |
| restore full verification/quarantine/reset | one lifetime target-exclusive | one verification/reset session | 2 | `pg_stat_activity` by `application_name` | Active sessions | Scenario 14: quarantine sessions |

Dump and inventory are sequential. Tool subprocesses must connect exactly once; an observed second tool/backend session is terminal `INCOMPATIBLE`.

### 10.3 Test-suite concurrency

| Constraint | Value | Phase 1 enforcer | Observation | Validation-scenario owner |
| --- | --- | --- | --- | --- |
| Integration suite isolation | Fresh UUIDv7, temporary XDG roots, unique Compose project, dynamic loopback ports | Harness token + binding-protected `/tmp` root | Project/root/ports/trust isolation | Scenario 21: harness isolation |
| Reference host concurrency | 1 full suite (4 CPU + 8 GiB) | Harness token kernel lock | Token availability | Scenario 21: single-suite token |
| Expanded host concurrency | `max_full_suites = min(floor(logical_cpus/4), floor((host_ram_bytes - 2 GiB) / 6 GiB))` | Harness token formula | Token count | Scenario 21: dual-suite isolation |
| Suite cleanup | Remove only harness-created temporary roots with binding proof | Harness | Binding evidence | Scenario 21: crash leaves diagnostic path |

## 11. Slices A–E with unsupported-command behavior

Phase 1 delivers incrementally through five slices. Every not-yet-implemented command is present only as a schema-valid exit `5` `UNSUPPORTED_IN_THIS_SLICE` with no mutation.

| Slice | Required capability | Explicitly deferred while failing closed | Phase 1 enforcer | Observation | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| A — host authority foundation | Prerequisite manifest/config/result parser; locked UIDs; PAM/helper/broker/runtime launcher; configless doctor/init; root-owned protected/TLS journal; direct-open/ptrace/PTY denial tests | Docker/prepare, serving, backup/restore, wipe, upgrade, export/import, retention | Command registry → `UNSUPPORTED_IN_THIS_SLICE` | `central.local-result/v1` with exit 5 | Scenarios 1, 2, 23 |
| B — first safe runnable environment | Complete hermetic dependency lock/prepare; Compose fs-init/daemons/provisioners; broker handoff; `up/down/status/doctor`; migration zero; staged `central-runtime`; TLS/browser/bootstrap; one end-to-end durable Task | Wipe, portable recovery, upgrade, delete/prune, general protected/audit maintenance | Command registry → `UNSUPPORTED_IN_THIS_SLICE` | `central.local-result/v1` with exit 5 | Scenarios 2, 3, 7-12, 18, 22 |
| C — required recovery | Gate 7 backup/verify and restore barrier; representative throughput/capacity; failure/resume; fresh bootstrap authority reset | Export/import, dependency upgrade, retention maintenance | Command registry → `UNSUPPORTED_IN_THIS_SLICE` | `central.local-result/v1` with exit 5 | Scenarios 12-16, 26 |
| D — destructive and portable operations | AppArmor-locked wipe; export/import with independent integrity token; fresh-host recovery; backup delete/prune; protected/audit tombstone maintenance | Dependency patch upgrade where no supported pair exists | Command registry → `UNSUPPORTED_IN_THIS_SLICE` | `central.local-result/v1` with exit 5 | Scenarios 17, 24, 25 |
| E — supported dependency maintenance | Ticketed patch upgrade for selected compatibility matrix; rollback/out-of-place evidence; advisory operational runbooks | Every unlisted transition remains `UPGRADE_OUT_OF_PLACE_REQUIRED` or unsupported | Command registry → `UNSUPPORTED_IN_THIS_SLICE` | `central.local-result/v1` with exit 5 | Scenario 23 |

Deferred commands never perform a partial approximation, ask for manual Docker/file repair, or weaken authority.

## 12. Explicit non-goals and accepted trust limitations

### 12.1 Non-goals

| Non-goal | Rationale | Phase 1 enforcer | Validation-scenario owner |
| --- | --- | --- | --- |
| Central as application container | Slows Go edit/debug loop; complicates descriptor-brokered Workspace access | Host process execution only | Scenario 27: development loop |
| Docker named volumes | Host operator modes cannot prove device identity and free capacity without container execution | Instance-bound host directories | Scenario 13: capacity formulas |
| Operator Docker-group authority | Docker control is root-equivalent | Operator UID not in `docker` group; no socket ACL | Scenario 2: Docker denial |
| Writable container root filesystems | Undeclared writes evade durable-root bindings, capacity accounting, cleanup, restart evidence | Read-only rootfs + exact tmpfs contract | Scenario 7: write audit |
| `.env` / environment-variable config | Precedence, provenance, multiline credentials, process inheritance, diagnostic leakage, per-command drift | `central.config/v1` JSON only | Scenario 1: config validation |
| Auto-download/auto-build during `local up` | Ordinary startup becomes network-dependent; silent supply-chain changes | `pull_policy: never`; `prepare` is explicit | Scenario 3: no-pull enforcement |
| Docker automatic restart (`unless-stopped`) | Reopens writable payloads after host/Docker restart without revalidating bindings, images, advisory, secrets, ports, recovery barriers | `restart: "no"` on every service | Scenario 3: restart enforcement |
| LAN, shared browser profiles, production exposure | Local-only topology with instance-bound loopback CA | Numeric loopback only; no DNS SAN; no proxy | Scenario 5: loopback enforcement |
| Ubuntu Server, Linux/arm64, macOS (Phase 1) | Candidates until Phase 1 supplies equivalent end-to-end evidence | Reference platform check | Scenario 23: clean Ubuntu Desktop |
| Windows | Outside Phase 1 support | Platform check | Scenario 23: reference platform |

### 12.2 Accepted trust limitations

| Limitation | Scope | Phase 1 enforcer | Validation-scenario owner |
| --- | --- | --- | --- |
| Root, compromised kernel/helper/broker/Docker daemon | Central does not claim protection | Documented trust boundary | Scenario 2: authority model |
| Compromised `central-runtime` after authorized secret enters adapter memory | Post-authorization trust boundary | `protected_file_v1` minimizes plaintext lifetime | Scenario 2: authorized secret use |
| Archived MinIO dependency | Can accumulate unfixed vulnerabilities | Seven-day advisory authority + explicit replacement trigger | Scenario 2: authority expiry |
| Release-security offline key and advisory compiler | High-value supply-chain controls | Key separation, deterministic canonicalization, non-exemptible categories, emergency activation | Scenario 2: authority admission |
| Docker access is root-equivalent | Small audited helper trust boundary with immutable ancestry | Closed request/policy surface, sanitized environment, fixed local socket | Scenario 6: helper boundaries |
| Dependency-secret handoff | Bounded helper, root, kernel tmpfs, and Docker daemon inside trust boundary | Source/destination no-follow, service-specific ownership, `_FILE` support, crash-safe cleanup | Scenario 7: secret delivery |
| Protected filesystem backend | Cannot guarantee memory zeroization | Root-only durable storage, broker-mediated minimal lifetime, no intentional reveal path except fresh-PAM TTY | Scenario 19: protected value lifecycle |
| Bootstrap presentation boundary | High risk from future JSON/export/clipboard convenience | Fresh PAM + helper/broker-owned TTY, rotate before reveal, expire after 3 min | Scenario 18: TTY-only reveal |
| Capacity estimates | Conservative but cannot predict every WAL/index/object-store behavior | Continuous checks, cleanup-required evidence, no guarantee of completion | Scenario 13: capacity safeguards |
| Export confidentiality | Depends on LUKS2; authenticity on independently retained `bx1` token | Token never crosses controller JSON/log/audit; paper or root-protected recovery store | Scenario 24: export token |
| Host and PostgreSQL locks | Protect different failure domains | Lock acquisition order; no in-place shared-to-exclusive upgrade | Scenario 11: lock ordering |
| The helper does not protect from root or Docker daemon compromise | Accepted infrastructure boundary | Documented trust model | Scenario 2: authority boundary |

## Operator journeys

### Operator start here index

| Journey | Section | Contract owner |
| --- | --- | --- |
| First use (host setup → bootstrap) | `Verbatim future first-use journey` below | This document |
| Daily changed-code loop | `Verbatim changed-code daily journey` below | This document |
| Diagnosis and remediation | `Derived environment state`, `Diagnostic output planes` (§9.2, §9.3) | This document + [Rust application boundaries](../architecture/rust-application-boundaries.md) |
| Backup and verification | `Normative operator journeys` (§1486–1501) | [Governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) |
| Restore and interruption | `Normative operator journeys` (§1518–1548) | [Governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) |
| Fresh-host export/import | `Normative operator journeys` (§1552–1578) | [Governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) |
| Wipe and empty recovery | `One-off destructive wipe mode` (§320–344) | [Governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) |
| Dependency/security maintenance | `Continuing vulnerability authority` (§142–166), `Upgrade protocol` (§168–188) | [Governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) |
| Retention and escalation | `Backup and protected-state maintenance` (§1648–1658) | [Governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) |
| Rescue backup (hard-expired authority) | `Hard-expired offline rescue backup` (§1472–1478) | [Governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md) |

The owner documents are Gate 8 contracts; commands are not currently available. The build script `scripts/build-local-runtime.sh` is a future Phase 1 artifact and is not present in the repository as of this writing.

**Install B1 (2026-09-30):** the journey's first command, bare `central local init`, is implemented with the physical-console ceremony; see "Implemented subset" in `docs/security/local-configuration-and-protected-state.md` §2.1. The `prjquota` check and the `--status`, `--resume` and `--abandon` forms are not.

### Verbatim future first-use journey

This transcript requires the administrator prerequisite runbook (`docs/operations/local-prerequisites.md`) to be completed first. It uses two terminals. All commands produce `Design-only Gate 8 contract — commands are not currently available` until Phase 1 implementation.

```text
central local init
# => trusted TTY returns <absolute-config-path>

central --config <absolute-config-path> local trust install

central --config <absolute-config-path> local security update

central --config <absolute-config-path> local doctor

central --config <absolute-config-path> local prepare

central --config <absolute-config-path> local up

central --config <absolute-config-path> migrate up

# terminal 1: controller launches central-runtime; leave attached and wait for readiness
central --config <absolute-config-path> serve

# terminal 2: launch and verify the managed local browser page first
central --config <absolute-config-path> local browser open

# same terminal 2: only after the page is ready, reveal and immediately enter one generation
central --config <absolute-config-path> bootstrap show
```

The sequence is `init → trust install → security update → doctor → prepare → up → migrate up → attached serve → browser open → bootstrap show`. Bootstrap is never opened or revealed before TLS trust and `serve` readiness. If migration status requires exact resume, the operator runs the exact `--config`-selected `migrate resume --operation=<id>` rather than a new `up`.

The first-use authentication interaction budgets at most 9 fresh Central PAM conversations and 4 minutes active interaction after the administrator runbook. Complete first use after runbook targets at most 25 minutes.

### Verbatim changed-code daily journey

This transcript assumes `local down` has been run (dependencies intentionally stopped) or the instance is in `STOPPED` state. The build script is a future Phase 1 artifact.

```text
scripts/build-local-runtime.sh --output=<absolute-empty-build-directory>

central --config <absolute-config-path> local runtime stage \
  --binary=<absolute-empty-build-directory>/central \
  --manifest=<absolute-empty-build-directory>/central.local-runtime-build/v1.json

central --config <absolute-config-path> local up

# terminal 1: start the exact staged lease and remain attached
central --config <absolute-config-path> serve

# terminal 2, only when the managed profile is not already open
central --config <absolute-config-path> local browser open
```

The daily sequence is `scripts/build-local-runtime.sh → runtime stage → up → attached serve → conditional browser open`. The helper launches only copied lease-bound bytes as `central-runtime`. Bootstrap/session recovery uses terminal 2 only after that process and page are ready. If three minutes expire or terminal delivery is uncertain, the operator runs `bootstrap show` again and uses only the newly displayed token. Logout revokes the active session, clears session/CSRF cookies, issues fresh pre-auth CSRF, and requires a newly presented bootstrap token; revoked cookies and the previous token are never reused. Rebuilding or restarting the host process never restarts PostgreSQL or MinIO.

The daily loop budgets at most 4 fresh PAM conversations and 2 minutes active interaction (stage, up, serve launch, browser launch).

## Bounded observability contract

### Metric registry

The fixed local metric registry exposes only these bounded maintenance signals on the operational listener at `127.0.0.1:9090/metrics`:

| Metric name | Type | Labels | Values | Phase 1 enforcer | Observation | Advisory warning |
| --- | --- | --- | --- | --- | --- | --- |
| `central_security_authority_seconds_until_expiry` | Gauge | none | Seconds until current bundle expiry; negative when stale | Signed bundle expiry minus current time | Active bundle `expires_at` | 72 h, 24 h, 6 h before expiry |
| `central_security_authority_state` | Gauge | `state`: one of `current`, `stale_admitted`, `hard_expired`, `denied`, `missing` | Fixed state label only | Bundle evaluation + admission logic | Bundle identity + signature + policy result | `stale_admitted` = advisory warning; `hard_expired` = blocked |
| `central_backup_repository_ceiling_ratio` | Gauge | none | Current occupancy ÷ 256 GiB ceiling; ratio in [0, 1] | `stat` repository directory + content digests | Repository manifest + accounting | 75% and 90% |
| `central_operator_audit_ceiling_ratio` | Gauge | none | Current record count ÷ 100,000 ceiling; ratio in [0, 1] | Audit record count from bounded accounting | Audit directory bounded count | 75% and 90% |
| `central_capacity_survival_reserve_released` | Gauge | none | 0 (reserve intact) or 1 (reserve released) | Reserve file existence + allocated block count + MAC receipt | `stat` reserve file on each writable device | 1 = `DEGRADED` / `cleanup_required`; no mutation permitted |
| `central_cleanup_required` | Gauge | none | 0 (clean) or 1 (cleanup required) | Aggregate of known incomplete cleanup: stale tmpfs, unreleased mounts, orphaned operations, settlement reserve exhausted | Doctor probe evidence | 1 = `CLEANUP_REQUIRED` exit 5; blocks mutation |
| `central_dependency_retry_terminal_total` | Counter | `class`: fixed label `dependency` | Monotonically increasing count of terminal dependency failures after exhausted retry budget | Runtime retry exhaustion counter | Component health loop | Non-zero = readiness false; exit 6 |

### Metric design rules

- Metrics perform no dependency I/O, unbounded scan, or per-instance label emission. Values come from bounded current receipts/accounting.
- Only the two fixed labels exist: `state` (for security authority) and `class` (for dependency retry). No Workspace, Task, Run, Artifact, operation, or instance identity is ever a metric label.
- The trusted TTY `local status` / `local doctor` display additionally warns at the advisory thresholds above. The generic `/health/ready` endpoint uses only bounded reason classes (`STARTING`, `CONFIG_INVALID`, `PROTECTED_STATE_INVALID`, `POSTGRES_UNAVAILABLE`, `POSTGRES_INCOMPATIBLE`, `OBJECT_STORE_UNAVAILABLE`, `OBJECT_STORE_INCOMPATIBLE`, `MIGRATION_REQUIRED`, `LEASE_LOST`, `BACKGROUND_LOOP_FAILED`, `SHUTTING_DOWN`).
- No machine/generic observation contains plaintext secrets, bootstrap/session/CSRF tokens, credentials, command environment, raw paths, raw object keys, raw filenames, SQL text/parameters, backend locators, unrestricted request/response bodies, or unbounded labels.

### Security authority warning bands

| Threshold | Warning | Behavior | Phase 1 enforcer | Validation-scenario owner |
| ---: | --- | --- | --- | --- |
| 72 hours before expiry | TTY advisory warning | `local status` / metrics display warning | Bundle expiry check | Scenario 2: advisory expiry |
| 24 hours before expiry | TTY advisory warning | `local status` / metrics display warning | Bundle expiry check | Scenario 2: advisory expiry |
| 6 hours before expiry | TTY advisory warning | `local status` / metrics display warning | Bundle expiry check | Scenario 2: advisory expiry |
| Expired (0 to +30 days) | `SECURITY_AUTHORITY_STALE` | `prepare`, upgrade, new identity blocked; `up`/`serve` may continue with warnings | Bundle evaluation | Scenario 2: stale authority |
| Expired +30 days | `SECURITY_AUTHORITY_HARD_EXPIRED` | `up`, `serve`, agent execution, bootstrap/session, migration, backup create, restore apply blocked | Bundle evaluation + immutable root time evidence | Scenario 2: hard-expired |
| Denied (emergency/KEV/CVSS ≥7.0) | `DEPENDENCY_DENIED` exit 5 | Immediate block; no stale grace, no rescue creation that would reopen denied identities | Bundle evaluation + policy | Scenario 2: deny immediate |

### Repository and audit warning bands

| Metric | Threshold | Warning | Phase 1 enforcer | Validation-scenario owner |
| --- | ---: | --- | --- | --- |
| `central_backup_repository_ceiling_ratio` | 75% | TTY advisory: plan maintenance; `backup create` still permitted | Repository accounting | Scenario 25: ceiling warning |
| `central_backup_repository_ceiling_ratio` | 90% | TTY advisory: maintenance urgent; `backup create` fails `MAINTENANCE_REQUIRED` before accepted point | Repository accounting + capacity plan | Scenario 25: ceiling block |
| `central_operator_audit_ceiling_ratio` | 75% | TTY advisory: plan maintenance | Audit accounting | Scenario 25: audit warning |
| `central_operator_audit_ceiling_ratio` | 90% | TTY advisory: maintenance urgent | Audit accounting | Scenario 25: audit warning |

## Usability budget reference

| Journey/command | Acceptance target | Phase 1 enforcer | Validation-scenario owner |
| --- | ---: | --- | --- |
| Administrator prerequisite/helper/broker/browser runbook from clean OS | ≤15 min active; wall/reported separately | Timing measurement | Scenario 27 |
| Complete first use after runbook | ≤25 min | Timing measurement | Scenario 27 |
| First-use authentication interaction | ≤9 fresh PAM convs, ≤4 min | Conversation count + timing | Scenario 27 |
| Changed-code daily transcript | ≤4 fresh PAM convs, ≤2 min | Conversation count + timing | Scenario 27 |
| Clean `local prepare` (two builds) | ≤20 min | Timing measurement | Scenario 2 |
| `local init` | ≤3 s | Timing measurement | Scenario 27 |
| Cached `local up` from `STOPPED` | p95 ≤60 s; max ≤120 s | 20 iterations, p95 calc | Scenario 27 |
| Idempotent `local up` (already healthy) | p95 ≤5 s; max ≤10 s | 20 iterations, p95 calc | Scenario 27 |
| `local status` | p95 ≤1 s; max ≤3 s | 20 iterations, p95 calc | Scenario 27 |
| Read-only `local doctor` | p95 ≤5 s; max ≤15 s | 20 iterations, p95 calc | Scenario 27 |
| `doctor --write-probe` | ≤30 s including cleanup | Timing measurement | Scenario 27 |
| `doctor --backup-throughput-probe` | ≤5 min | Timing measurement | Scenario 12 |
| Warm-cache `serve` → ready | p95 ≤5 s; max ≤10 s | 20 iterations, p95 calc | Scenario 27 |
| `bootstrap show` after readiness | ≤3 s before TTY delivery | Timing measurement | Scenario 18 |
| Ordinary `local down` | p95 ≤30 s; max 90 s | 20 iterations, p95 calc | Scenario 27 |

P95 values use 20 independent iterations after one discarded warm-up, reporting all samples. Interactive commands exceeding 2 s print first bounded phase update within 1 s. SIGINT acknowledgement appears within 1 s.

## 13. B06 secure-serve-bootstrap reference host and acceptance inventory

This section records the implemented B06 secure-serve-bootstrap acceptance boundary. The governing design is `docs/internal/superpowers/specs/2026-07-22-phase-1-b06-secure-serve-bootstrap-design.md`; the acceptance evidence is `docs/internal/superpowers/reviews/2026-07-22-b06-secure-serve-bootstrap-acceptance.md`.

### 13.1 Reference-host launcher

The supported B06 reference-host launcher is `testdata/b06-reference-host/run.sh`. It must be invoked as root and is non-skipping: it either runs the full acceptance suite or exits nonzero. It reuses the B05 root-run cleanup/deadline/leak-detection pattern and pins every image with `pull_policy: never`.

| Resource | Reference | Phase 1 enforcer | Observation | Safe failure | Validation-scenario owner |
| --- | --- | --- | --- | --- | --- |
| Launcher | `testdata/b06-reference-host/run.sh` | UID 0 plus Docker access; 15-minute parent deadline including cleanup | 2m PostgreSQL health, 10m tagged suite, 3m bounded cleanup; Compose `up --abort-on-container-exit --exit-code-from test-runner` | Nonzero on non-root, test failure, Docker unavailability, timeout, or leak | B06 acceptance inventory |
| Compose | `testdata/b06-reference-host/compose.yaml` | `pull_policy: never`; `restart: "no"` on every service | `docker compose config` | `INCOMPATIBLE` if drift | Image identity contract |
| PostgreSQL image | `postgres:16.14-bookworm@sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28` | Embedded digest pin | `docker image inspect` | `PREPARATION_REQUIRED`/`DRIFTED` | §2.3 |
| Runner image | `golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651` | Embedded digest pin | `docker image inspect` | `INCOMPATIBLE` | Build reproducibility |
| Network | `b06-test` (internal bridge) | Compose policy | `docker network inspect` | `INCOMPATIBLE` if external | §5.3 |

### 13.2 Acceptance inventory

The B06 acceptance inventory is the exact 18-item contract from the brief. The portable kernel proof (`internal/kernel/reference_host_test.go`) runs on every host without Docker or PostgreSQL and maps each item to concrete executable tests. Transport, web, session, PostgreSQL, helper, and broker proofs run inside the Compose runner with the `authority_test` tag against the pinned PostgreSQL image. A passing package test is not evidence of an unavailable real browser or host-installed helper; those boundaries remain explicitly identified by their owning tests.

| # | Inventory item | Proof location | Owner |
| ---: | --- | --- | --- |
| 1 | dual listeners | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 2 | explicit browser proof gate | `internal/kernel/reference_host_test.go` + `internal/adapter/authority/helper` | kernel/helper boundary |
| 3 | migration failure | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 4 | TTY-only throttle/expiry | `internal/kernel/reference_host_test.go` + helper/browser + session/app | kernel/session/helper/transport |
| 5 | parallel exchange | `internal/kernel/reference_host_test.go` + broker RPC + `internal/adapter/postgres/session` | kernel/broker/session adapter |
| 6 | delivery failure | `internal/transport/http/gintransport/middleware` concrete buffered-write tests | transport |
| 7 | Host/Origin/CSRF/frame denial | middleware Host/Origin/CSRF tests + `web` frame-header test | transport |
| 8 | restart/epoch recovery | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 9 | lock loss | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 10 | controller disconnect | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 11 | signal relay | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 12 | supervisor loss | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 13 | teardown order | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 14 | port/config rejection | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 15 | health route isolation/transitions | `internal/kernel/reference_host_test.go` + `internal/transport/http/gintransport/health` | kernel/transport |
| 16 | pool/admission/buffer saturation and release | kernel tracker + middleware admission/response-cap tests | kernel/transport |
| 17 | shutdown deadline | `internal/kernel/reference_host_test.go` (portable) | kernel |
| 18 | diagnostic sentinel | `internal/kernel/reference_host_test.go` + session/web redaction tests | kernel/session/transport |

### 13.3 Operator order and health interpretation

Run the B06 ceremony in this order: (1) verify the fixed configuration and
dependency receipts; (2) run the explicit migration or exact recovery command
when preflight is not ready; (3) start `central serve`; (4) wait for both fixed
listeners and `/health/ready` 200; (5) open the managed browser through the
helper, which presents the one-use proof on its TTY; (6) perform bootstrap
exchange; and (7) on logout or shutdown, wait for settlement before restart.
Never auto-migrate from `serve`, expose the bootstrap proof through logs or a
non-TTY, or change the fixed listener addresses to work around a collision.

| Operator step | Command/observation | Health response | Reason | Next action |
| --- | --- | --- | --- | --- |
| Start serve | `central serve` foreground | `starting` (503 `/health/ready`) | `UNAVAILABLE` | Wait for readiness or bounded diagnostic |
| Ready | `/health/ready` → 200 | `ready` | (empty) | Explicit `central local browser open` only |
| Preflight PostgreSQL incompatible | exit 5 | `not_ready` (503) | `POSTGRES_INCOMPATIBLE` + remediation | Follow remediation copy; run exact repair action |
| Preflight requires provisioning | exit 7 | `not_ready` (503) | `PROVISION_REQUIRED` + remediation | Follow remediation copy; run exact `central migrate up` |
| Preflight requires resume | exit 6 | `not_ready` (503) | `RESUME_REQUIRED` + remediation | Follow remediation copy; run exact `central migrate resume` |
| Preflight requires repair | exit 6 | `not_ready` (503) | `REPAIR_REQUIRED` + remediation | Follow remediation copy; run exact repair action |
| Port collision | exit 4 | `not_ready` (503) | `PORT_IN_USE` | Stop the conflicting process; do not change the listener |
| Lock/config invalid | exit 4/2 | `not_ready` (503) | `LEASE_LOST`/`CONFIG_INVALID` | Recheck config binding; restart after clearing the condition |
| Controller disconnect | exit 0 | `shutting_down` | `SHUTTING_DOWN` | Intentional; restart via launcher |
| Epoch/parent/component loss | exit 6 | `failed` | `EPOCH_MISMATCH`/`BACKGROUND_LOOP_FAILED` | Diagnose; restart only after clearing the condition |
| Shutdown timeout | exit 6 | `failed`/`shutting_down` | deadline exceeded | Capture shutdown evidence; escalate |

### 13.4 No-auto-migrate rule

`central serve` never migrates the application schema. The serve profile holds a shared target lock and a read-only one-connection/no-retry preflight; it emits a typed diagnostic with exit 7 when the schema is absent, exit 6 when migration resume or repair is required, and exit 5 for incompatible state. Schema migration is the explicit `central migrate up` ceremony owned by the `central-migrate` identity. The serve boundary rejects any configuration that borrows a pool, enables retries, or uses the migration credential.

## Cross-reference index

| Governing design section | This document section | Notes |
| --- | --- | --- |
| Supported platform and dependency baseline (§60–105) | §2 Reference host and exact dependency identity | Tables augmented with enforcer/observation/failure/validation columns |
| Process and Compose topology (§189–387) | §3, §5, §6, §7 | Scoped to container privilege, writable paths, secret handoff |
| Listener, network, and local trust boundary (§402–434) | §5.3, §5.4, §8 | Listener ports, TLS, browser trust |
| Immutable startup configuration (§605–840) | Delegated to Task 3 config contract | Link only: [Configuration and protected state contract](../security/local-configuration-and-protected-state.md) |
| Protected local stores and credentials (§1098–1338) | §4.2, §7.2, §7.3, §7.4 | Broker matrix, secret handoff, provisioning |
| Local command workflow (§1340–1431) | §9, §11 | Derived state, locking, slices |
| Locking and command coexistence (§1433–1466) | §9.1 | Lock matrix |
| Concrete backup, restore, and capacity (§1468–1736) | Delegated to Task 4 backup/restore contract | Link only |
| Health, retry, restart, shutdown (§1755–1790) | §9.3, §9.4, §9.5 | Health layers, retry, exit classes |
| Observability and operator audit (§1791–1801) | Bounded observability contract | Complete metric table |
| Developer and test workflow (§1803–1904) | §10.3, Operator journeys | Test concurrency, operator transcripts |
| Slice structure (§1942–1958) | §11 Slices A–E | Exact slice table |
| Non-goals and risk (§1975–2101) | §12 Explicit non-goals and accepted trust limitations | Consolidated |
