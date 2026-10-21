# ADR 0009: Adopt the local development environment topology

- **Number:** 0009
- **Title:** Adopt the local development environment topology
- **Status:** Superseded
- **Created:** 2026-07-16
- **Owners:** Central maintainer
- **Decision due:** 2026-07-20
- **Decision due history:** None
- **Implementation blocked at:** Gate 9 host-authority foundation, local dependency topology, protected-state backend, browser bootstrap, and operator recovery implementation plans.
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-16
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** ADR 0010
- **Amends:** ADR 0008
- **Amended by:** None
- **Related:** [ADR 0001](0001-adopt-durable-task-domain-and-lifecycle.md), [ADR 0002](0002-authorize-accepted-to-superseded-status-transitions.md), [ADR 0003](0003-adopt-phase-1-security-policy-and-secret-reference-model.md), [ADR 0004](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md), [ADR 0005](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md), [ADR 0006](0006-adopt-local-v1-api-and-event-serialization.md), [ADR 0007](0007-adopt-postgresql-persistence-and-recovery-contracts.md), [ADR 0008](0008-adopt-capability-owned-go-application-boundaries.md), [approved Gate 8 local environment design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md), [approved Gate 8 implementation plan](../internal/superpowers/plans/2026-07-16-phase-0-local-development-environment.md), [Gate 8 plan-review report](../internal/superpowers/reviews/2026-07-16-phase-0-local-development-environment-plan-review.md), [ADR governance](README.md)

## Implementation notes

This ADR was proposed under EXECUTION_BASE commit `2c22c2656c53ce0b3abc4e9a5f0624f7f7ef3cd8`. That commit contains the approved Gate 8 implementation plan (`docs/internal/superpowers/plans/2026-07-16-phase-0-local-development-environment.md`, SHA-256 `88fcd67436289b36e3bd76729526a968e679da34d96140e4826160102ae5e28e`), the plan-review report (`docs/internal/superpowers/reviews/2026-07-16-phase-0-local-development-environment-plan-review.md`, SHA-256 `3b28c4f6dd1117e759a995a84f38ad57942ce4aadf1eeb0940d1951bbb7e9239`), and the governing design spec (`docs/internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md`, currently at SHA-256 `62333dff7fff318c63b1930e16d0e70442081a3a0e82652d236d0040c1c481c5`; the design brief records the pre-correction identity `62333dff7fff318c63b1930e16d0e70442081a3a0e82652d236d0040c1c2565`). These three artifacts constitute the sole execution authority range for Tasks 8, 10, and 13.

## Context

ADRs 0001–0008 established durable Task domain and lifecycle, ADR governance, security policy and SecretReference model, staged single-agent runtime and verified adapter handoffs, verified Artifact lifecycle and safe content delivery, local v1 API and Event serialization contracts, PostgreSQL persistence and recovery contracts, and capability-owned Go application boundaries. Those decisions define what Central builds, secures, persists, recovers, and how its Go packages are owned. They do not define the concrete local development topology: host-process and Docker Compose service placement, locked runtime/agent/browser identities, privileged helper and broker trust boundaries, PostgreSQL and MinIO identities and configuration, protected local stores, immutable startup configuration, component co-location, concrete backup/restore tools and capacity checks, or the failure boundaries that the executable Gate 9 slices must implement.

The approved Gate 8 design defines those topology decisions. Gate 8 is a design-only specification; this Proposed ADR adopts it.

This ADR also amends ADR 0008 to correct a material security issue in the restore-confirmation authorization. ADR 0008 and the canonical Go application boundaries document section 5.4 authorized noninteractive restore-apply confirmation through `--confirm-operation` and `--confirm-target`. Under the now-accepted same-operator-UID threat model, those public values are replayable by a compromised same-UID process and cannot replace fresh PAM plus helper-owned confirmation. This ADR removes those authorization forms and replaces them with a fresh PAM ceremony plus helper-owned physical-seat TTY confirmation, while preserving every Gate 7 durability semantic.

## Decision

Central adopts the following local development environment topology decisions from the approved Gate 8 design:

### Topology and process placement

- One `central serve` process runs directly on the host under the locked `central-runtime` service UID and co-locates HTTP, execution, outbox, reconciliation, cleanup, and recovery components. The operator-facing `central serve` command is a controller that asks the installed service launcher to start that exact process and then follows its safe foreground status. Central is not an application container.
- Docker Compose runs six services—`postgres-fs-init`, `minio-fs-init`, `postgres`, `minio`, `postgres-provision`, and `minio-provision`—on one internal `infra` network. Central itself is not a Compose service. Compose project is `central-<full-instance-id>`. All six services use exact digest-qualified images, `pull_policy: never`, `restart: "no"`, and no `build:` directive.
- PostgreSQL and MinIO data use instance-bound host directories mounted into containers, not Docker named volumes.
- The supported reference platform is Ubuntu Desktop 24.04.4 LTS on Linux/amd64 with the manifest-pinned Chromium-family browser and browser trust-store tooling. Ubuntu Server, Linux/arm64, and macOS remain candidates until Gate 9 supplies equivalent end-to-end evidence; Windows is outside Phase 1 support.

### Locked identities and privilege boundaries

- Locked runtime/agent/browser UIDs: `central-runtime`, `central-agent`, and `central-browser` are no-login system identities. The runtime receives only descriptor-only supervisor and sandbox boundaries with no repository, Workspace, or Docker/helper socket access.
- A root-owned, release-pinned infrastructure helper mediates all Docker authority through a closed request protocol with fresh PAM ceremony and physical-seat TTY confirmation. The operator UID is not a Docker group member and has no Docker socket access.
- A root-owned, socket-activated protected broker mediates all secret value access, TLS signing, HMAC fingerprinting, XDG view signing, and authority-transition journaling. It has no network, Docker, shell, or arbitrary-path authority and exits after a fixed idle deadline.
- The first SecretReference backend is `protected_file_v1`, a root-owned brokered local filesystem backend with create-only generations and atomic activation. The operator UID, `central-runtime`, and `central-agent` cannot enumerate or directly open its values or TLS private keys.
- A distinct root-owned, socket-activated `central-sandbox-launcher` with no Docker/network/secret authority launches untrusted execution as `central-agent` in a private PID/mount namespace with delegated Workspace descriptors only.

### Configuration and state

- General configuration is one strict versioned JSON document (`central.config/v1`) selected by absolute path or unambiguous XDG discovery. Environment variables and command-line flags do not override topology fields.
- Authoritative configuration/state, secret material, dependency data, audit, and backups live below root-owned parents outside the repository, XDG operator views, and every Workspace root.
- XDG contains only non-authoritative broker-signed views. Every authoritative transition is recorded as immutable sequence-specific payloads with `central.authority-transition/v1` HMAC envelopes under `authority-records/`. Post-commit materialized projections are never authority.
- `central.local-result/v1` and `central.local-remediation/v1` provide strict machine-output and local-remediation-catalog schemas. Every exit class has exact result/reason/resume semantics.

### Dependency selections

- PostgreSQL: server image `16.14` Debian Bookworm variant at exact OCI index, platform manifest, and config digests. Host `pg_dump`/`pg_restore` pinned to `16.14`.
- MinIO: source build from exact commit `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a` at tag `RELEASE.2025-10-15T17-29-55Z`, with archive SHA-256 `be6d0bd3696c3a13a35f02d3a0280b64319c67918b4501c5c3d87f96d000085c`.
- The selected MinIO repository is archived and the selected security-fixed release has no accepted official container image. Gate 9 must build Central's MinIO image from the exact source commit with the hermetic two-clean-builder reproducibility contract and digest-pinned Go/build/runtime bases. This ADR records the archived-upstream maintenance risk, AGPL-3.0 distribution obligations, replacement trigger, and prohibition on falling back to the older pre-fix image.
- Docker Engine/CLI `29.6.1`, Docker Compose plugin `5.3.1`, Go `1.26.5`.
- Dependency acquisition is explicit through `central local prepare`; daily startup never silently downloads or builds.

### Listener, network, and trust

- The browser application has one instance-bound HTTPS origin at `https://127.0.0.1:8080`. The operational HTTP listener at `127.0.0.1:9090`, PostgreSQL at `127.0.0.1:55432`, and MinIO S3 API at `127.0.0.1:59000` may remain plaintext on numeric loopback. Any non-loopback bind is a startup failure.
- Application TLS requires TLS 1.3 with an instance-bound certificate having SAN IP `127.0.0.1` only. The CA and leaf private keys are root-owned protected broker generations. `central local trust install` is an explicit administrative trust transition.
- The managed browser profile lives at `/var/lib/central-browser/v1/<instance-id>/` beneath a root-owned `0700` parent, runs as `central-browser` in a systemd scope with one CPU, 512 MiB `MemoryMax`, PID limit 256, an ext4 project hard quota of 1 GiB/50,000 inodes, and a 256 MiB disk-cache ceiling. Browser is launched in the active local Wayland session through a `WAYLAND_SOCKET` descriptor passed by the helper.

### Security authority

- A release-signed Ed25519 `central.security-advisory/v1` bundle provides continuing vulnerability and provenance authority. Accepted behavior: current (admit new dependencies), stale (admit unchanged identities only for 30 days), hard-expired (block serve and all mutations), deny (immediate block). A missing bundle or CVSS ≥ 7.0/CISA KEV/emergency-deny blocks admission.
- The release-security owner, not Gate 9 runtime code, owns the advisory compiler, offline signing ceremony, public-key custody and recovery, and emergency response.
- Normal `local up` revalidates advisory evidence. `local security update` is lifecycle-exclusive with online/offline closed-input forms. `prepare`, dependency upgrade, and new identity admission require current authority.

### PostgreSQL and MinIO identities

- One `central` database, one `central` application schema, exactly three application roles (`central_runtime`, `central_outbox`, `central_migration`) with separate protected password bindings and SCRAM-SHA-256.
- One `central-artifacts-v1` bucket with separate `central-runtime-v1`, `central-backup-v1`, and `central-restore-v1` policies at exact SHA-256 digests. Three non-root identities: runtime, backup, and restore, with no group membership or console/admin credentials.

### Concrete host configuration

- `central.config/v1` contains all required sections: identity, paths, HTTP, PostgreSQL, object store, protected store, bootstrap/session, Artifact, operator modes, tools, runtime, and observability. Every field is required with exact type constraints, installed defaults, and cross-field validation.
- `central.local-result/v1` provides the complete result schema with `schema_version`, `command`, `outcome`, `exit_class`, `reason_code`, `environment_state`, `mutation_phase`, `mutation_started`, `retryable`, `resume_required`, `operation_id`, timestamps, progress, `safe_next_action`, remediation fields, `details`, and `message`.

### Backup, restore, and recovery extensions

- Gate 8 extends the Gate 7 `backup/app` application port with `backup list`, `backup export`, `backup import`, `backup delete`, and `backup prune` commands. Their durable backup semantics remain Gate 7-owned; local repository/export/maintenance realization and public result variants are Gate 8-owned.
- Export uses a broker-signed Ed25519 `bx1:<export-key-id>:<public-key>:<manifest-digest>:<signature>` public integrity token. This is the sole exception to Gate 7's generic checksum-output rule. The token is revealed only through the fresh-PAM exclusive physical-seat TTY and never crosses controller JSON, logs, audit, HTTP, or any operator-writable token file.
- Hard-expired rescue backup (`backup create --security-rescue`) creates exactly one marked current-epoch seal from operation-owned cold copies. It uses the Gate 9 clean-host benchmark's conservative admission, never mounts authoritative payload roots writable, and remains unrestorable until current authority returns.
- `backup security-rescue cleanup --operation=<id>` provides settlement-only cleanup for any authenticated rescue operation with a bound scratch root.
- AppArmor-locked wipe using the exact `central-local-infra` image and an installed root-owned `central-local-infra-wipe-v1` profile processes one root at a time with no network, second mount, or caller-supplied path. After wipe, credential reseed produces fresh generations for all dependency and application identities while preserving CA/trust, preparation evidence, and signed advisory authority.

### Gate 9 slice structure

Gate 9 delivers incrementally through five slices with the rule that every deferred command is present only as a schema-valid exit `5` `UNSUPPORTED_IN_THIS_SLICE` with no mutation:

- **Slice A — host authority foundation:** prerequisite manifest, config/result parser, locked UIDs, PAM/helper/broker/runtime launcher, configless doctor/init, root-owned protected/TLS journal.
- **Slice B — first safe runnable environment:** complete hermetic dependency lock/prepare, Compose fs-init/daemons/provisioners, broker handoff, `up`/`down`/`status`/`doctor`, migration zero, staged `central-runtime`, TLS/browser/bootstrap, one end-to-end durable Task producing a verified Artifact.
- **Slice C — required recovery:** Gate 7 backup/verify and restore barrier, representative throughput/capacity, failure/resume, fresh bootstrap authority reset.
- **Slice D — destructive and portable operations:** AppArmor-locked wipe, export/import with independent integrity token, fresh-host recovery, backup delete/prune, protected/audit tombstone maintenance.
- **Slice E — supported dependency maintenance:** ticketed patch upgrade for the selected compatibility matrix, rollback/out-of-place evidence, advisory operational runbooks.

Deferred commands never perform a partial approximation, ask for manual Docker/file repair, or weaken authority.

### Operational rules

- General configuration is immutable for a process lifetime. Schema migration, credential rotation, restore, and destructive wipe remain explicit offline operator operations.
- Backup and restore run from the host through pinned PostgreSQL client tools and the S3 adapter. They never use Docker socket access or `docker exec`.
- Container secret handoff uses broker-written tmpfs files beneath root-owned `/run/central-infra/<instance-id>/secrets/`. Each file is `0400`, owned by the locked numeric UID/GID of exactly one consuming service, and bind-mounted read-only to one fixed in-container `_FILE` path. Secret values never appear in Compose YAML, image metadata, environment variables, command arguments, receipts, or Docker labels.
- Wipe is a distinct one-off destructive protocol, not a seventh Compose service. After fresh PAM, the helper displays and reads the trusted-TTY phrase `WIPE <full-instance-id> <full-target-id> POSTGRES+MINIO` and creates a one-use operation-bound confirmation. There is no `--yes`, force, partial-root selector, or caller confirmation digest.

### Amendment to ADR 0008

This ADR amends ADR 0008 and the canonical Go application boundaries document section 5.4 to remove noninteractive restore-apply authorization through `--confirm-operation` and `--confirm-target`. Under the same-operator-UID threat model, those public values are replayable and cannot replace fresh PAM plus helper-owned physical-seat TTY confirmation.

Restore verify, restore ticket, `--operation`, accepted point, target locks, result schema, status, resume, and every other Gate 7 durability semantic remain unchanged. Restore apply/resume never has a noninteractive production form. Fresh PAM and the helper-owned `/dev/tty` confirmation are mandatory; `--confirm-operation`, `--confirm-target`, `--yes`, redirected input, `--output=json` on apply, a backup ID as confirmation, an expired/replayed verify operation, or a target copied from another result is invalid.

### Authority boundary

This ADR authorizes documentary contract alignment only until Accepted. While Proposed, it creates no runtime authority, does not authorize implementation, and does not supersede any Accepted ADR's runtime semantics. After Acceptance in Task 11, it becomes the sole governing authority for the documentary contracts produced by Tasks 2–7.

## Consequences

### Benefits

- Concrete host-application-plus-Compose-dependency topology provides a single verifiable local-development deployment without containerizing Central or granting the operator Docker authority.
- Locked runtime/agent/browser UIDs with descriptor-only supervisor, broker, and sandbox boundaries prevent same-UID compromise from reaching protected state, Docker control, or cross-identity secrets.
- Root-owned helper and broker with fresh-PAM and physical-seat TTY confirmation make infrastructure authority, secret resolution, and destructive operations explicit and non-replayable under the same-operator-UID threat.
- Instance-bound HTTPS origin on numeric loopback with a broker-owned local CA provides server-origin authentication without external infrastructure.
- Signed seven-day advisory authority with current/stale/hard-expired/deny behavior, emergency denylist, and non-exemptible categories prevents known-vulnerable digest pins from becoming accepted runtime dependencies.
- `protected_file_v1` with immutable authority transition records and signed XDG projections provides tamper-evident configuration and state with non-enumerating secret resolution.
- Gate 8 backup command extensions (`list`, `export`, `import`, `delete`, `prune`) plus the `bx1` integrity-token exception, hard-expired rescue backup, and AppArmor-locked wipe provide a complete local recovery surface owned through the existing `backup/app` port without adding a new privileged namespace.
- Gate 9 slices A–E with deferred commands failing closed as `UNSUPPORTED_IN_THIS_SLICE` ensure partial implementations never pretend to offer missing capability.
- The amendment to ADR 0008 removes a concrete replayable-authorization vulnerability while preserving every Gate 7 durability semantic.

### Costs and limitations

- The host-level operator account is not a member of the Docker group and has no Docker-socket ACL. Every Docker or protected-value operation requires a fresh PAM conversation and an installed root-owned helper, adding an active-interaction budget of nine PAM conversations for first use and four for daily development.
- Exact dependency pins (PostgreSQL 16.14, MinIO source commit, Docker 29.6.1, Compose 5.3.1) require a new release manifest and two-host validation for every dependency update. Package drift becomes downtime.
- Disabling Docker auto-restart (`restart: "no"` on every service) trades unattended post-reboot availability for a single checked writable-start boundary. The operator must run `local up` after Docker/host restart.
- The archived MinIO dependency can accumulate unfixed vulnerabilities. The signed seven-day advisory authority, explicit replacement trigger, and named release-security owner bound that risk, but an exact stale-admitted installation may serve for at most 30 days without current evidence.
- Portable export confidentiality depends on separately managed LUKS2 encryption, and export authenticity depends on retaining the broker-signed `bx1` token on paper or in a separately administered root-protected recovery store. Loss of either can make recovery impossible.
- The local CA lifecycle adds an explicit administrative trust transition for the system and browser trust stores. This topology is not suitable for LAN, shared browser profiles, or production exposure.
- Locked runtime identities with descriptor-only boundaries, supervised component lifecycle, and mandatory fresh-PAM confirmation add ceremony and startup latency compared to a single-UID local process.

## Alternatives considered

### Containerize the Central application

Rejected for the Phase 1 development baseline because it slows the Go edit/debug loop, complicates descriptor-brokered access to developer Workspace roots and authoritative state, and tempts Docker authority or broad host mounts into the application container. Locked host execution preserves the accepted application boundaries while Compose isolates only dependencies.

### Run PostgreSQL and MinIO directly on the host

Rejected because dependency versions, identities, filesystem ownership, network exposure, and teardown become host-specific and difficult to reproduce. Compose provides a narrow dependency boundary without containerizing Central.

### Give the operator ambient Docker-group authority

Rejected because Docker control is root-equivalent and would let a compromised application, agent tool, repository hook, or same-UID process replace images, mount protected host paths, or bypass the intended application capability boundary. A root-owned release-pinned helper narrows that authority to an explicit operation and topology protocol.

### Docker named volumes

Rejected because host operator modes cannot prove device identity and free capacity without Docker-daemon inspection, container execution, or a privileged sidecar. Instance-bound host directories permit no-socket capacity and binding checks.

### One privileged provisioner or general long-running root daemon

Rejected because filesystem ownership and logical policy need different privileges and occur on opposite sides of dependency startup. Separate no-network root fs-init and non-root network provisioners keep each authority narrow.

### Writable container root filesystems

Rejected because undeclared config, cache, socket, or temporary writes would evade durable-root bindings, capacity accounting, cleanup, and restart evidence. Exact read-only images plus bounded service-specific tmpfs make every permitted write location inspectable and disposable.

### Host-side recursive wipe or dependency-image deletion

Rejected because a generic root helper recursion or shell inside PostgreSQL/MinIO would inherit a broad host/path/tool surface. The static release-built one-root maintenance mode has a separate digest, syscall/capability policy, held descriptor, acknowledgement, and no network/second mount.

### Environment-variable configuration and `.env`

Rejected because precedence, provenance, multiline credentials, process inheritance, diagnostic leakage, and per-command drift undermine immutable startup evidence and protected bindings.

### Auto-download or auto-build during `local up`

Rejected because ordinary startup would become network-dependent and could silently change its supply chain. Explicit preparation makes acquisition auditable and daily startup deterministic.

### Ambient Docker builder or reproducibility check alone

Rejected because host Buildx plugins, cached frontend/toolchain/module state, exporter defaults, and attestations can change the result without changing the Dockerfile. The fixed BuildKit archive, built-in frontend, offline inputs, two isolated content stores, explicit exporter, and no-build/no-pull Compose contract make undeclared input observable and terminal.

### Docker automatic dependency restart

Rejected because `unless-stopped` can reopen PostgreSQL or MinIO writable payloads after a daemon/host restart without rechecking descriptor bindings, image/advisory receipts, tmpfs secret generations, ports, or recovery barriers.

### Helper-managed host packages or version ranges

Rejected because making the helper an APT/key/service manager would greatly widen its root authority, while minimum-version ranges allow unvalidated package changes to enter the supported profile.

### In-place major dependency upgrade or assumed rollback

Rejected because a version label does not prove persistent-format compatibility in either direction. Only fixture-backed patch pairs may open existing roots; major, replacement, or unproven transitions use new roots plus verified restore.

### Auto-migrate during `serve` or `local up`

Rejected by Gate 7 because serving must not receive migration credentials and migration safety requires explicit target-exclusive operator control and exact-operation resume.

### Backup while serving

Rejected because Gate 7 requires target-exclusive ownership from accepted-point capture through verified manifest seal.

### In-place-only recovery or portable credential bundle

Rejected because in-place-only backup does not survive host loss, while exporting protected state would turn long-lived credentials into a portable secret archive.

### Automatic backup or audit pruning

Rejected because age, count, or disk pressure alone cannot prove that a sealed backup, incomplete operation, secret generation, or audit record is unreferenced.

### Plaintext browser application on loopback

Rejected because authentication above HTTP cannot prove to the browser that the process occupying the fixed loopback port is this Central instance. Instance-bound HTTPS makes server-origin authentication explicit while retaining the local-only topology.

### MinIO floating image or older official image

Rejected because the older image predates the selected security fix and the source repository is archived. Exact source-build evidence is safer than a convenient unsupported tag.

### Digest pinning without continuing advisory authority

Rejected because an immutable digest can remain reproducible after it becomes known-vulnerable. A short-lived release-signed advisory bundle, exact signed exceptions, and a non-exemptible emergency denylist keep identity and continuing security acceptance separate.

### Global active-instance pointer or destructive force flag

Rejected because implicit target switching and lock bypass make wipe, restore, migration, and credential rotation capable of acting on the wrong durable instance.

### Post-wipe receipt reuse or full instance deletion

Rejected because preserved receipts could falsely describe deleted payloads as initialized/provisioned, while deleting configuration, TLS, backups, and audit would turn payload wipe into an unrelated instance-destruction command.

### Raw paths in machine output or no actionable paths anywhere

Rejected because JSON/log paths propagate filesystem layout into CI and telemetry, while opaque-only local diagnostics make safe repair impractical. Descriptor-validated, escaped paths are confined to a proven operator TTY; the versioned catalog keeps machine output bounded and still supplies deterministic next actions.

### Low-level backup semantics without operator transcripts

Rejected because exact locks/tickets are insufficient if users cannot discover the right operation or distinguish new verify, apply, and resume. Normative safe-ID transcripts make the Gate 7 state machine executable without adding force aliases or hidden orchestration.

### Unmeasured local usability

Rejected because functional health alone permits silent multi-minute commands, slow cached loops, and undocumented manual repair. Reference-host elapsed/progress/cancellation budgets are release acceptance criteria.

## Follow-ups

- Tasks 2–7 produced canonical topology, security, backup, and alignment contracts. Those contracts are now governed by this Accepted ADR.
- Task 8 produced a validation report covering each Gate 8 required scenario. Validation passed.
- Task 10 performed an independent pre-acceptance review of the complete Gate 8 documentary evidence. Readiness audit passed with zero findings.
- Task 11 accepted this ADR on 2026-07-16 and updated ADR 0008's `Amended by` field to `0009` in the same atomic decision commit.
- Task 13 produces the final Gate 10 closure audit and determines Phase 0 completion.

## References

- [Approved Gate 8 Local Development Environment Design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md)
- [Approved Gate 8 Implementation Plan](../internal/superpowers/plans/2026-07-16-phase-0-local-development-environment.md)
- [Gate 8 Plan-Review Report](../internal/superpowers/reviews/2026-07-16-phase-0-local-development-environment-plan-review.md)
- [ADR governance and index](README.md)
- [ADR 0001 — Adopt the durable Task domain and lifecycle](0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0002 — Authorize Accepted-to-Superseded ADR Status transitions](0002-authorize-accepted-to-superseded-status-transitions.md)
- [ADR 0003 — Adopt the Phase 1 security policy and SecretReference model](0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [ADR 0004 — Adopt staged single-agent runtime and verified adapter handoffs](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [ADR 0005 — Adopt verified Artifact lifecycle and safe content delivery](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md)
- [ADR 0006 — Adopt the local v1 API and Event serialization contracts](0006-adopt-local-v1-api-and-event-serialization.md)
- [ADR 0007 — Adopt PostgreSQL persistence and recovery contracts](0007-adopt-postgresql-persistence-and-recovery-contracts.md)
- [ADR 0008 — Adopt capability-owned Go application boundaries](0008-adopt-capability-owned-go-application-boundaries.md)
