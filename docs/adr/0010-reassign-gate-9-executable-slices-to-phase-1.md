# ADR 0010: Reassign Gate 9 executable slices to Phase 1

- **Number:** 0010
- **Title:** Reassign Gate 9 executable slices to Phase 1
- **Status:** Superseded
- **Created:** 2026-07-16
- **Owners:** Central maintainer
- **Decision due:** 2026-07-20
- **Decision due history:** None
- **Implementation blocked at:** Gate 9 backlog execution and every Phase 1 Slice A–E executable implementation plan or artifact.
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-16
- **Decision record:** Git status-transition commit
- **Supersedes:** ADR 0009
- **Superseded by:** ADR 0011
- **Amends:** ADR 0008
- **Amended by:** None
- **Related:** [ADR 0008](0008-adopt-capability-owned-go-application-boundaries.md), [ADR 0009](0009-adopt-local-development-environment-topology.md), [Gate 9/10 design](../internal/superpowers/specs/2026-07-16-phase-0-implementation-backlog-and-closure-design.md), [Gate 9/10 plan](../internal/superpowers/plans/2026-07-16-phase-0-implementation-backlog-and-closure.md), [ADR governance](README.md)

## Implementation notes

This replacement amendment is proposed from `PRE_EXECUTION_BASE` `62edb3178637e4592530c3d027073a334d61ff40` and consumes ADR 0009 blob SHA-256 `a3f273d452bc1719ca2d785bdab11a1eb3fa51fafe46cc0898c1d87c3f09e599`. Its Decision section is the deterministic eight-fragment transformation specified by the governing Gate 9/10 design. The preservation matrix below binds all 62 non-empty Decision clauses.

## Context

ADR 0009 is an Accepted amendment of ADR 0008. It adopts the local development topology, corrects restore-confirmation authority, and assigns executable Slice A–E delivery to Gate 9. Phase 0 is design-only, so only that last ownership allocation conflicts with the Phase boundary.

Installed governance forbids amending an amendment. This ADR therefore targets ADR 0008, supersedes ADR 0009 as an overlapping replacement amendment, retains ADR 0009's complete technical Decision byte-for-byte except the eight ownership fragments listed by the governing design, and moves executable A–E delivery to Phase 1. Gate 9 becomes the documentation-only backlog and traceability gate; Gate 10 remains Phase 0 closure.

## Decision

Central adopts the following local development environment topology decisions from the approved Gate 8 design:

### Topology and process placement

- One `central serve` process runs directly on the host under the locked `central-runtime` service UID and co-locates HTTP, execution, outbox, reconciliation, cleanup, and recovery components. The operator-facing `central serve` command is a controller that asks the installed service launcher to start that exact process and then follows its safe foreground status. Central is not an application container.
- Docker Compose runs six services—`postgres-fs-init`, `minio-fs-init`, `postgres`, `minio`, `postgres-provision`, and `minio-provision`—on one internal `infra` network. Central itself is not a Compose service. Compose project is `central-<full-instance-id>`. All six services use exact digest-qualified images, `pull_policy: never`, `restart: "no"`, and no `build:` directive.
- PostgreSQL and MinIO data use instance-bound host directories mounted into containers, not Docker named volumes.
- The supported reference platform is Ubuntu Desktop 24.04.4 LTS on Linux/amd64 with the manifest-pinned Chromium-family browser and browser trust-store tooling. Ubuntu Server, Linux/arm64, and macOS remain candidates until Phase 1 supplies equivalent end-to-end evidence; Windows is outside Phase 1 support.

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
- The selected MinIO repository is archived and the selected security-fixed release has no accepted official container image. Phase 1 must build Central's MinIO image from the exact source commit with the hermetic two-clean-builder reproducibility contract and digest-pinned Go/build/runtime bases. This ADR records the archived-upstream maintenance risk, AGPL-3.0 distribution obligations, replacement trigger, and prohibition on falling back to the older pre-fix image.
- Docker Engine/CLI `29.6.1`, Docker Compose plugin `5.3.1`, Go `1.26.5`.
- Dependency acquisition is explicit through `central local prepare`; daily startup never silently downloads or builds.

### Listener, network, and trust

- The browser application has one instance-bound HTTPS origin at `https://127.0.0.1:8080`. The operational HTTP listener at `127.0.0.1:9090`, PostgreSQL at `127.0.0.1:55432`, and MinIO S3 API at `127.0.0.1:59000` may remain plaintext on numeric loopback. Any non-loopback bind is a startup failure.
- Application TLS requires TLS 1.3 with an instance-bound certificate having SAN IP `127.0.0.1` only. The CA and leaf private keys are root-owned protected broker generations. `central local trust install` is an explicit administrative trust transition.
- The managed browser profile lives at `/var/lib/central-browser/v1/<instance-id>/` beneath a root-owned `0700` parent, runs as `central-browser` in a systemd scope with one CPU, 512 MiB `MemoryMax`, PID limit 256, an ext4 project hard quota of 1 GiB/50,000 inodes, and a 256 MiB disk-cache ceiling. Browser is launched in the active local Wayland session through a `WAYLAND_SOCKET` descriptor passed by the helper.

### Security authority

- A release-signed Ed25519 `central.security-advisory/v1` bundle provides continuing vulnerability and provenance authority. Accepted behavior: current (admit new dependencies), stale (admit unchanged identities only for 30 days), hard-expired (block serve and all mutations), deny (immediate block). A missing bundle or CVSS ≥ 7.0/CISA KEV/emergency-deny blocks admission.
- The release-security owner, not Phase 1 runtime code, owns the advisory compiler, offline signing ceremony, public-key custody and recovery, and emergency response.
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
- Hard-expired rescue backup (`backup create --security-rescue`) creates exactly one marked current-epoch seal from operation-owned cold copies. It uses the Phase 1 clean-host benchmark's conservative admission, never mounts authoritative payload roots writable, and remains unrestorable until current authority returns.
- `backup security-rescue cleanup --operation=<id>` provides settlement-only cleanup for any authenticated rescue operation with a bound scratch root.
- AppArmor-locked wipe using the exact `central-local-infra` image and an installed root-owned `central-local-infra-wipe-v1` profile processes one root at a time with no network, second mount, or caller-supplied path. After wipe, credential reseed produces fresh generations for all dependency and application identities while preserving CA/trust, preparation evidence, and signed advisory authority.

### Phase 1 slice structure

Phase 1 delivers incrementally through five slices with the rule that every deferred command is present only as a schema-valid exit `5` `UNSUPPORTED_IN_THIS_SLICE` with no mutation:

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

This replacement amendment activates the validated ownership allocation only when Accepted. While Proposed, it creates no runtime authority, does not authorize implementation, and does not supersede any Accepted ADR's runtime semantics. After acceptance, it is ADR 0008's active amendment, retains the technical decisions above, assigns the documentation-only backlog to Gate 9, and assigns executable slices to Phase 1.

## Consequences

### Benefits

- Concrete host-application-plus-Compose-dependency topology provides a single verifiable local-development deployment without containerizing Central or granting the operator Docker authority.
- Locked runtime/agent/browser UIDs with descriptor-only supervisor, broker, and sandbox boundaries prevent same-UID compromise from reaching protected state, Docker control, or cross-identity secrets.
- Root-owned helper and broker with fresh-PAM and physical-seat TTY confirmation make infrastructure authority, secret resolution, and destructive operations explicit and non-replayable under the same-operator-UID threat.
- Instance-bound HTTPS origin on numeric loopback with a broker-owned local CA provides server-origin authentication without external infrastructure.
- Signed seven-day advisory authority with current/stale/hard-expired/deny behavior, emergency denylist, and non-exemptible categories prevents known-vulnerable digest pins from becoming accepted runtime dependencies.
- `protected_file_v1` with immutable authority transition records and signed XDG projections provides tamper-evident configuration and state with non-enumerating secret resolution.
- Gate 8 backup command extensions (`list`, `export`, `import`, `delete`, `prune`) plus the `bx1` integrity-token exception, hard-expired rescue backup, and AppArmor-locked wipe provide a complete local recovery surface owned through the existing `backup/app` port without adding a new privileged namespace.
- Phase 1 slices A–E with deferred commands failing closed as `UNSUPPORTED_IN_THIS_SLICE` ensure partial implementations never pretend to offer missing capability.
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

- Independently review the committed Proposed ADR and reconstruct the complete preservation matrix.
- Align and validate the six related Gate 8/status documents with the conditional activation contract before decision.
- If validation passes, atomically accept ADR 0010, supersede ADR 0009, preserve both historical amendment relationships on ADR 0008, and update the ADR index.
- Approve the combined Gate 9/10 design and plan only after that acceptance.

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
- [ADR 0009 — Adopt the local development environment topology](0009-adopt-local-development-environment-topology.md)

## ADR 0009 Decision preservation matrix

- Source ADR 0009 blob SHA-256: `a3f273d452bc1719ca2d785bdab11a1eb3fa51fafe46cc0898c1d87c3f09e599`
- Source Decision-range SHA-256: `55d4372070ad1c87ac8a11de5a6a122583decbc77936df77887f24c58c3b51f4`
- Resulting ADR 0010 Decision-range SHA-256: `0af2875a3884f866db258e30935baa23ac39dee5aac84079bd9a3ef8f8c8de99`
- Physical lines: 93; non-empty clauses: 62; ownership-replaced clauses: 7; retained-verbatim clauses: 55; fragment substitutions: 8.

Target clause identity is `ADR0010-CLAUSE-<same-six-digit-physical-line-ordinal>`. The complete byte transformation and eight-fragment allowlist are defined by the governing design.

| Ordinal | Source clause ID | Target clause ID | Disposition |
| --- | --- | --- | --- |
| `000001` | `ADR0009-CLAUSE-d6a017f43849ee0058b194036e21f434588889026f479df297833aff25416936` | `ADR0010-CLAUSE-000001` | `retained-verbatim` |
| `000003` | `ADR0009-CLAUSE-0b92b4a25fa935cefd22c1dfc267632456eff61ad6662ea0940ab393dfc5629c` | `ADR0010-CLAUSE-000003` | `retained-verbatim` |
| `000005` | `ADR0009-CLAUSE-29568a04bcc7474fcd70fcfab17ea1f555f0c2f5dc843dfd6cd24d46a69e5ce9` | `ADR0010-CLAUSE-000005` | `retained-verbatim` |
| `000007` | `ADR0009-CLAUSE-368dd3d3972b859a03cf8896911bc32ccc6ec477058b4d8865ef73ceec61d1d6` | `ADR0010-CLAUSE-000007` | `retained-verbatim` |
| `000008` | `ADR0009-CLAUSE-a11058ad64088526a4c6561af3d5b3b08ee7ba58b2bd51f96fa3c247e22d4f6a` | `ADR0010-CLAUSE-000008` | `retained-verbatim` |
| `000009` | `ADR0009-CLAUSE-86c10c5aee0d8dcc9abd85a717c1811f7a410b0d0c74ac59ba9c37d9c877b8ea` | `ADR0010-CLAUSE-000009` | `retained-verbatim` |
| `000010` | `ADR0009-CLAUSE-f9c1cf5bd2cb3cff86495a31fec14bf2312066c323cb6aff75acf53fb787d5bb` | `ADR0010-CLAUSE-000010` | `ownership-replaced` |
| `000012` | `ADR0009-CLAUSE-7c3fb7791aecc5a802b900ab87f65710707e84f24c12e3a87393d1cbf6ff9e57` | `ADR0010-CLAUSE-000012` | `retained-verbatim` |
| `000014` | `ADR0009-CLAUSE-b0bd37c219440d5c095cf4a9e5aeae746c912987e1fd1ef9dda75912bd876602` | `ADR0010-CLAUSE-000014` | `retained-verbatim` |
| `000015` | `ADR0009-CLAUSE-a8b76c28160faf10a535c13b0d2eedd9cab4a3db9759d0c47c7b74033b953b16` | `ADR0010-CLAUSE-000015` | `retained-verbatim` |
| `000016` | `ADR0009-CLAUSE-9f96cda33622a2ce4eb9e1ca2eee47b7f423b675502e5f9dd1c6615d8af38d18` | `ADR0010-CLAUSE-000016` | `retained-verbatim` |
| `000017` | `ADR0009-CLAUSE-f12811126ce3db32ccb8cffdcf3e28196da6ed72834cc7c7faea6d708e5e2005` | `ADR0010-CLAUSE-000017` | `retained-verbatim` |
| `000018` | `ADR0009-CLAUSE-6252f566c227d11fe56a88949be60c867e997ce0d4a6489a4cb6d68370f242d4` | `ADR0010-CLAUSE-000018` | `retained-verbatim` |
| `000020` | `ADR0009-CLAUSE-115a0eccf576423c11de9e5c9ade9e1495f84cff78d561b6806b4c2ab62a9629` | `ADR0010-CLAUSE-000020` | `retained-verbatim` |
| `000022` | `ADR0009-CLAUSE-38240c390759abf48bcdb0f8c16a9aed58a59de4c365d6ab2a8356afba66fcbd` | `ADR0010-CLAUSE-000022` | `retained-verbatim` |
| `000023` | `ADR0009-CLAUSE-d3dd0a6745f5cca67ce45c42f3e1161275d730486eff4bf23fa42a3c8822f93c` | `ADR0010-CLAUSE-000023` | `retained-verbatim` |
| `000024` | `ADR0009-CLAUSE-71d9982596ec2ab065a93154c3d277ffb1b91e8ba0e46f23104294c3fabfc51a` | `ADR0010-CLAUSE-000024` | `retained-verbatim` |
| `000025` | `ADR0009-CLAUSE-04631bb9ea5251fafb846229c2bd6b9ea6c02c3d3a1a1d0fe62f28c2c0633ce5` | `ADR0010-CLAUSE-000025` | `retained-verbatim` |
| `000027` | `ADR0009-CLAUSE-06a52388a4ef14313412c9b5311e31c5d6e8833682b86301374210a809a4194d` | `ADR0010-CLAUSE-000027` | `retained-verbatim` |
| `000029` | `ADR0009-CLAUSE-3533e41f42c21fdb97abd1cf27df1d00afda3b96290815c1010d1efda4d7666b` | `ADR0010-CLAUSE-000029` | `retained-verbatim` |
| `000030` | `ADR0009-CLAUSE-5e854cf4083372ad7b5ed3745c120726010848d6d02d0568a86b6d830773a7e5` | `ADR0010-CLAUSE-000030` | `retained-verbatim` |
| `000031` | `ADR0009-CLAUSE-6e4b110670a48993ee6374c42646a1af075a85461bae47abbc02a9fb1e399d36` | `ADR0010-CLAUSE-000031` | `ownership-replaced` |
| `000032` | `ADR0009-CLAUSE-9248c9a2262642b7182843826d6b4cd21ff477ad757776590535285bb81fb2fb` | `ADR0010-CLAUSE-000032` | `retained-verbatim` |
| `000033` | `ADR0009-CLAUSE-64b58f0e461f765fb9f3d23946654167e285e2624783684e91cb1fe10f340ce2` | `ADR0010-CLAUSE-000033` | `retained-verbatim` |
| `000035` | `ADR0009-CLAUSE-616bfdd3acdfee02dfb96c7365909fff495ae9dd8913577b8626726e43e48c89` | `ADR0010-CLAUSE-000035` | `retained-verbatim` |
| `000037` | `ADR0009-CLAUSE-8628aaa7eb638a479ce7f4f8ae557b1e36ad34902fcab3daecbba32bae1d63e0` | `ADR0010-CLAUSE-000037` | `retained-verbatim` |
| `000038` | `ADR0009-CLAUSE-4ccc96f0fca6fc6c97231287aeff64a9ebe270725c59ccd1155d49fb2e155079` | `ADR0010-CLAUSE-000038` | `retained-verbatim` |
| `000039` | `ADR0009-CLAUSE-b0cf2b3ca99df9b982f801512154cd35c74ba6b15265c54fc63a318500a47ca5` | `ADR0010-CLAUSE-000039` | `retained-verbatim` |
| `000041` | `ADR0009-CLAUSE-880ce0b51ae187e20283dfb7eb4d237ea796b87a80359da0a2127049b403446e` | `ADR0010-CLAUSE-000041` | `retained-verbatim` |
| `000043` | `ADR0009-CLAUSE-b24b00c1ea94d1cbdf7053d739c64d7534bf8c238eee59ec6126667ec102506e` | `ADR0010-CLAUSE-000043` | `retained-verbatim` |
| `000044` | `ADR0009-CLAUSE-bf9c7740ea2bdb80264234004320e1a41af8db264be597fbdf09985b9407537b` | `ADR0010-CLAUSE-000044` | `ownership-replaced` |
| `000045` | `ADR0009-CLAUSE-9cb3ddb253d7801c2285a0a0ddab0cbb22946baccc3cedd1045810eeafb14b3d` | `ADR0010-CLAUSE-000045` | `retained-verbatim` |
| `000047` | `ADR0009-CLAUSE-fc026e0405eb6face100f307cc882b168fa885ee21a5014d5ba13016c8b1df7c` | `ADR0010-CLAUSE-000047` | `retained-verbatim` |
| `000049` | `ADR0009-CLAUSE-1f75ecb6dc89ca64da1c4182dc9f0e5985c51857d76bafc3b569500a1bb26279` | `ADR0010-CLAUSE-000049` | `retained-verbatim` |
| `000050` | `ADR0009-CLAUSE-31431c1682b2187c6e40d910ed9224b597fec8af4be59914d37d7f576f405b4b` | `ADR0010-CLAUSE-000050` | `retained-verbatim` |
| `000052` | `ADR0009-CLAUSE-de0affb0e292c945a700523b48e0ff2c9c665592939871e956644235f24c9a28` | `ADR0010-CLAUSE-000052` | `retained-verbatim` |
| `000054` | `ADR0009-CLAUSE-0d51e4ec4e0a7801db1054bbb620496be255b7780cad5c7b1338dc0907b2823f` | `ADR0010-CLAUSE-000054` | `retained-verbatim` |
| `000055` | `ADR0009-CLAUSE-f924cec4b6759aaf47db115fe203c15a9ee28aca69ada5f648cbc2ec41db8747` | `ADR0010-CLAUSE-000055` | `retained-verbatim` |
| `000057` | `ADR0009-CLAUSE-ce56f556bbd44650264c3f89f009e3b60099ea8ee80fa4bf7f09447bcb2bebdf` | `ADR0010-CLAUSE-000057` | `retained-verbatim` |
| `000059` | `ADR0009-CLAUSE-704352d620c2affd915e460d0f6b791d30ceae0ba8a2f1b1d9dd83a63bf3cfbd` | `ADR0010-CLAUSE-000059` | `retained-verbatim` |
| `000060` | `ADR0009-CLAUSE-ba1ea01e5be1163b8f59efb905405df45b70683d2a3bc2995098d9f8ddf34a43` | `ADR0010-CLAUSE-000060` | `retained-verbatim` |
| `000061` | `ADR0009-CLAUSE-5090801812a7f65245c54852c118c4917ba65d65c09a06a6d56ba5e3671ce7de` | `ADR0010-CLAUSE-000061` | `ownership-replaced` |
| `000062` | `ADR0009-CLAUSE-f95b94c00fff6eccd043f702402f0470cb2c9de02c399038fdd7de105896620b` | `ADR0010-CLAUSE-000062` | `retained-verbatim` |
| `000063` | `ADR0009-CLAUSE-3a0d530a574f36064a4ca526e877fec99e907ec5ea1df4691924383266066001` | `ADR0010-CLAUSE-000063` | `retained-verbatim` |
| `000065` | `ADR0009-CLAUSE-59e42f1ff9526977fc7afac40d37f92f29716b33277d322f1da0a21eba73c2fc` | `ADR0010-CLAUSE-000065` | `ownership-replaced` |
| `000067` | `ADR0009-CLAUSE-00c7f37625a8cf5348d29a3d87f50d038bfd250f18fb5585fab0ddf50de4f991` | `ADR0010-CLAUSE-000067` | `ownership-replaced` |
| `000069` | `ADR0009-CLAUSE-3be2ef31fc800f267fe461bc782e7b61e4c89a0a085c57c04c09eb7158ba8243` | `ADR0010-CLAUSE-000069` | `retained-verbatim` |
| `000070` | `ADR0009-CLAUSE-e02c9e1556bc661a8e481da91ce1290e71082af3c17e94b87809adb6d7d11bae` | `ADR0010-CLAUSE-000070` | `retained-verbatim` |
| `000071` | `ADR0009-CLAUSE-66d1e1a197a548e2a7c8d28cc3af7827a3e25dea90ef881eeedf3d9649eb76f7` | `ADR0010-CLAUSE-000071` | `retained-verbatim` |
| `000072` | `ADR0009-CLAUSE-2448f28e05ab195d6022ac0f8813f318006b36dbb1814bbb0cbb2902dc25f5a3` | `ADR0010-CLAUSE-000072` | `retained-verbatim` |
| `000073` | `ADR0009-CLAUSE-27f507b9bb69c03cf8950932a5fe8d1cf48f6b6ce9d9fa65105c20d3086f5054` | `ADR0010-CLAUSE-000073` | `retained-verbatim` |
| `000075` | `ADR0009-CLAUSE-7dc7ab2c73317f5343bc9e5d019313fca3c08dddd6c8ca2fc8b3aa98d504206d` | `ADR0010-CLAUSE-000075` | `retained-verbatim` |
| `000077` | `ADR0009-CLAUSE-ac76b673983b20819c13c52bfbb56aaebd3dcad4ffbebee49a97e51e83ab0578` | `ADR0010-CLAUSE-000077` | `retained-verbatim` |
| `000079` | `ADR0009-CLAUSE-46502f814c4d3476eb3d8e940b896450dda1c21daf3f5430df79a0e1bd2467d7` | `ADR0010-CLAUSE-000079` | `retained-verbatim` |
| `000080` | `ADR0009-CLAUSE-c423cf4a525088677a9a574de248979a0bd26f614018b6e1bbf4f8613fd5e5b4` | `ADR0010-CLAUSE-000080` | `retained-verbatim` |
| `000081` | `ADR0009-CLAUSE-9e41dc3a501bf8a850137e5e544d926324fbc92e2c1d7f4af15dfeec1a66da57` | `ADR0010-CLAUSE-000081` | `retained-verbatim` |
| `000082` | `ADR0009-CLAUSE-4d1a0404fbea5531a1fbaa731103125fd402fbfd492dae6420a2833cc2441021` | `ADR0010-CLAUSE-000082` | `retained-verbatim` |
| `000084` | `ADR0009-CLAUSE-fe52c2cba2a5eb6faa6fc623452d4f4e7eb50b61024cd84e04a5943e8de84b28` | `ADR0010-CLAUSE-000084` | `retained-verbatim` |
| `000086` | `ADR0009-CLAUSE-f3b9cdf2d004531d102e70739013ba7f7d8b440b8ea2ce2c9f40023705f715b0` | `ADR0010-CLAUSE-000086` | `retained-verbatim` |
| `000088` | `ADR0009-CLAUSE-46fe00b9211092ebf656b316b1b4b1b497fc1833d248ba96bc2d0657d466b03e` | `ADR0010-CLAUSE-000088` | `retained-verbatim` |
| `000090` | `ADR0009-CLAUSE-67f45667da9327498527b673c758f8367ceb51c849f3c25445e0ffb7df621d76` | `ADR0010-CLAUSE-000090` | `retained-verbatim` |
| `000092` | `ADR0009-CLAUSE-ea7e053ba9d243db91cb2667ac1c1ad6f58ec1aa15b0177d83fde07013633796` | `ADR0010-CLAUSE-000092` | `ownership-replaced` |
