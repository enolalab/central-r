# Phase 0 Local Development Environment Design

- **Status:** Approved
- **Date:** 2026-07-16
- **Phase:** Phase 0 — Architecture and foundations
- **Program gate:** Gate 8 — Local development environment
- **Implementation target:** Phase 1 — Local Central MVP

Ownership activation contract: At `OWNERSHIP_ALIGNMENT_TARGET`, ADR 0010 is Proposed and ADR 0009 remains ADR 0008's controlling active amendment. The documentation-only Gate 9 / executable Phase 1 allocation below becomes authoritative if and only if a descendant `ADR0010_ACCEPTANCE_TARGET` records ADR 0010 Accepted, ADR 0009 Superseded, and ADR 0010 as ADR 0008's Accepted non-superseded amendment. Current authority is resolved from ADR 0008, its Accepted non-superseded amendment, and `docs/adr/README.md`; this sentence is not a frozen status label.

## Objective

Define the reproducible, least-privileged local environment that makes the accepted Gates 1–7 contracts executable in Phase 1 without moving application authority into Docker, configuration, or operator scripts.

Gate 8 fixes the supported host, dependency acquisition and verification, host-process and Docker Compose topology, listener and network placement, PostgreSQL and MinIO identities, protected local stores, immutable startup configuration, component co-location, local operator workflow, concrete backup/restore tools and capacity checks, and the failure boundaries that Phase 1 must implement.

The resulting design must let one developer initialize an isolated instance, prepare pinned dependencies, start PostgreSQL and MinIO, provision least-privileged identities, install the Central schema through the accepted migration protocol, run the all-in-one Central serving profile under a locked host service identity, preserve state across rebuilds and restarts, and perform verified backup and restore without giving the application Docker authority or giving repository-controlled same-UID processes direct access to protected values.

## Context and consumed authority

This design consumes and does not reopen:

- Gate 1, Accepted [ADR 0001](../../../adr/0001-adopt-durable-task-domain-and-lifecycle.md): durable Task ownership, lifecycle transitions, immutable Events, recovery, and the required-Artifact completion barrier;
- Gate 2, Accepted [ADR 0003](../../../adr/0003-adopt-phase-1-security-policy-and-secret-reference-model.md): the trusted local OS account, loopback authentication, fail-closed policy, SecretReference invariants, and protected-binding requirements;
- Gate 3, Accepted [ADR 0004](../../../adr/0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md): bounded execution, authorization-use fencing, just-in-time secret use, finite retry, Checkpoint recovery, and durable ambiguity;
- Gate 4, Accepted [ADR 0005](../../../adr/0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md): staged and ready Artifact generations, immutable bodies, safe delivery, quota, deletion, and reconciliation;
- Gate 5, Accepted [ADR 0006](../../../adr/0006-adopt-local-v1-api-and-event-serialization.md): loopback-only local v1 transport, bootstrap/session/CSRF flow, Host/Origin policy, fixed health routes, and safe serialization;
- Gate 6, Accepted [ADR 0007](../../../adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md): PostgreSQL 16, exact roles, transaction/locking rules, forward-only migration, target exclusion, backup/restore evidence, and database-time authority;
- Gate 7, Accepted [ADR 0008](../../../adr/0008-adopt-capability-owned-go-application-boundaries.md): one Go binary, capability-owned ports, manual composition, component lifecycle, concrete command contracts, stable exit classes, resource hard caps, serving shared locks, explicit migration, and the complete restore barrier;
- the canonical [Threat model](../../../security/threat-model.md), [SecretReference contract](../../../security/secret-reference.md), [Artifact lifecycle](../../../artifacts/lifecycle.md), [API v1](../../../api/v1.md), [PostgreSQL contract](../../../persistence/postgresql.md), [Migration and recovery contract](../../../persistence/migrations-and-recovery.md), [Go application boundaries](../../../architecture/go-application-boundaries.md), and [PostgreSQL adapter mapping](../../../persistence/postgresql-adapter-mapping.md).

When a Gate 8 convenience choice conflicts with an accepted contract, the accepted contract wins. Gate 8 preserves the Gate 7 health paths, target-lock matrix, command verbs, process exit classes, 30-second settlement grace, and 45-second total shutdown default.

One material security correction is explicit rather than hidden: ADR 0009 must amend ADR 0008 and canonical `Go application boundaries` section 5.4 to remove noninteractive restore apply and the `--confirm-operation`/`--confirm-target` authorization form. Under the now-accepted same-operator-UID threat, those public values are replayable and cannot replace fresh PAM plus helper-owned confirmation. Restore verify/ticket, `--operation`, accepted point, locks, result schema, status/resume, and every Gate 7 durability semantic remain unchanged. Gate 8 cannot become Accepted until ADR 0009 and the canonical Gate 7 document record that narrow supersession; until then the current conflict is deliberate proposed correction, not implementation authority.

## Phase boundary

This is a Phase 0 design contract. It creates no Go source, SQL migration, Dockerfile, Compose file, image, bucket, database, role, credential, runtime configuration, generated dependency lock, executable test, or implemented security control.

Gate 8 may define exact future filenames, JSON fields, commands, service names, ports, paths, image/source pins, permissions, capacity formulas, and validation scenarios as normative Markdown. Phase 1 owns the executable slices that create those artifacts and run the required build, integration, recovery, security, and reproducibility checks. Gate 10 owns the final Phase 0 closure audit.

Except for the explicit restore-confirmation amendment above, Gate 8 does not redefine domain behavior, serialized API or Event shape, PostgreSQL schema semantics, migration recovery, Artifact lifecycle, backup/restore accepted points, or Go package ownership. It supplies the concrete local realization those contracts explicitly delegated to Gate 8.

## Decisions

Central adopts a host application with Docker Compose dependencies:

1. One `central serve` process runs directly on the host under the locked `central-runtime` service UID and co-locates HTTP, execution, outbox, reconciliation, cleanup, and recovery components. The operator-facing `central serve` command is a controller that asks the installed service launcher to start that exact process and then follows its safe foreground status; Central is still not an application container.
2. Docker Compose runs PostgreSQL, MinIO, two filesystem initializers, and two logical provisioners. Central itself is not a Compose service.
3. PostgreSQL and MinIO data use instance-bound host directories mounted into containers, not Docker named volumes.
4. The supported reference platform is Ubuntu Desktop 24.04.4 LTS on Linux/amd64 with the manifest-pinned Chromium-family browser and browser trust-store tooling. Ubuntu Server, Linux/arm64, and macOS remain candidates until Phase 1 supplies equivalent end-to-end evidence; Windows is outside Phase 1 support.
5. General configuration is one strict versioned JSON document selected by absolute path or unambiguous XDG discovery. Environment variables and command-line flags do not override topology fields.
6. Authoritative configuration/state, secret material, dependency data, audit, and backups live below root-owned parents outside the repository, XDG operator views, and every Workspace root.
7. The first SecretReference backend is a root-owned brokered local filesystem backend, `protected_file_v1`, with create-only generations and atomic activation. The operator UID, `central-runtime`, and untrusted execution UID cannot enumerate or directly open its values or TLS private keys.
8. PostgreSQL has one `central` database, one `central` application schema, and exactly the three accepted application roles. MinIO has one instance bucket and separate runtime, backup, and restore identities.
9. Dependency acquisition is explicit through `central local prepare`; daily startup never silently downloads or builds.
10. The browser application has one instance-bound HTTPS origin on numeric IPv4 loopback. The operational HTTP listener and authenticated PostgreSQL and S3 traffic may remain plaintext only on numeric loopback. Any non-loopback bind is a startup failure.
11. Backup and restore run from the host through pinned PostgreSQL client tools and the S3 adapter. They never use Docker socket access or `docker exec`.
12. General configuration is immutable for a process lifetime. Schema migration, credential rotation, restore, and destructive wipe remain explicit offline operator operations.
13. The operator account that controls `central serve` has no Docker socket or protected-value authority. Docker acquisition and Compose mutation cross an explicit trust boundary through a root-owned, release-pinned local infrastructure helper. Secret resolution, TLS private-key use, and launch of the locked host identities cross a separate root-owned, release-pinned, socket-activated broker boundary; mutable repository or caller environment content is never Docker or secret authority.

## Supported platform and dependency baseline

### Reference host

The supported reference host is:

| Resource | Reference minimum |
| --- | ---: |
| Operating system | Ubuntu Desktop 24.04.4 LTS, Linux/amd64 |
| Browser | Chromium-family browser at the exact version and package identity in `central.local-prerequisites/v1` |
| Logical CPUs | 4 |
| RAM | 8 GiB |
| Initially free local data storage | 40 GiB |
| Browser profile filesystem | local ext4 with project quota enabled (`prjquota`) and verified kernel quota support |

CPU or RAM below the reference minimum produces an `outside_supported_profile` diagnostic. Workload-specific storage remains a hard precondition computed from exact backup/restore evidence; 40 GiB never substitutes for that calculation.

The operator account owns XDG selection/diagnostic views only. The root-owned broker owns protected values and TLS private keys. The locked `central-runtime` UID owns each instance's authoritative state/backup subtree below a root-only parent but owns no source repository or Workspace; untrusted execution uses `central-agent`, and the fixed browser uses `central-browser`. All are no-login system identities. The browser store must be on local ext4 mounted with project-quota support enabled at boot; runtime remount or quota enablement is forbidden. A network filesystem, shared home directory without reliable advisory locks, root-squashed mount, case-insensitive filesystem, or filesystem that cannot provide atomic same-directory rename, file/directory synchronization, stable identity, owner-only permissions, and the required browser project quota is unsupported for durable state.

### Dependency selections

The Gate 8 baseline is:

| Dependency | Selection | Verification boundary |
| --- | --- | --- |
| Go | 1.26.5 | Inherited from Gate 7 |
| Chromium-family browser and NSS trust tooling | Exact package/browser identity resolved by Phase 1 | Host prerequisite; local numeric-loopback TLS and browser trust validation |
| Docker Engine and CLI | 29.6.1 | Host prerequisite |
| Docker Compose plugin | 5.3.1 | Host prerequisite; `docker compose` plugin command shape |
| PostgreSQL server image | 16.14, Debian Bookworm variant | OCI index `sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55`; linux/amd64 manifest `sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28`; config `sha256:67d1da22f4037b29cdd93e03d870a4a1c4d079358367d0cbc56459e52cde205e` |
| `pg_dump` / `pg_restore` | 16.14 | Absolute host paths and exact reported version |
| MinIO source | `RELEASE.2025-10-15T17-29-55Z` | Commit `9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`; GitHub tag archive SHA-256 `be6d0bd3696c3a13a35f02d3a0280b64319c67918b4501c5c3d87f96d000085c` |

PostgreSQL major 16 is inherited from Gate 6. Host `pg_dump` and `pg_restore` must match server major 16 and are pinned to 16.14 for the first implementation. A version mismatch is `POSTGRES_INCOMPATIBLE`, not a warning.

The selected MinIO repository is archived and the selected security-fixed release has no accepted official container image. Phase 1 must build Central's image from the exact source commit with digest-pinned build and runtime bases. The ADR for this gate must record the archived-upstream maintenance risk, AGPL-3.0 distribution obligations, replacement trigger, and prohibition on falling back to the older pre-fix image.

### Supported-host installation authority

Phase 1 publishes a canonical `deploy/local/prerequisites.lock.json` with schema `central.local-prerequisites/v1` and embeds its RFC 8785 digest in the release artifact and installed helper authority. For Ubuntu 24.04/linux-amd64 it records the exact OS release, supported kernel range, package architecture, ext4/project-quota kernel and userspace identities, required persistent `prjquota` mount option, and, for every required host package, its package name, epoch/version/revision, repository origin/label/suite/component, repository URL, signing-key fingerprint, package-file SHA-256, installed-file inventory digest, required absolute executable paths, executable SHA-256 values, and exact version output. The closure includes Docker Engine/CLI 29.6.1 and containerd/runc, Docker Compose 5.3.1, PostgreSQL client 16.14, PAM/logind/Wayland, AppArmor/parser, quota tooling, CA/NSS/browser trust utilities, the selected Chromium-family browser, and Go 1.26.5. A non-APT tool archive additionally records its authoritative HTTPS URL, upstream signature/checksum authority, archive SHA-256, and extracted-file digests. No placeholder, version range, `latest`, unsigned repository, or mutable convenience script is valid.

The supported runbook is `docs/operations/local-prerequisites.md`. It instructs an administrator—not the Central operator account or helper—to install Ubuntu packages only from signed Noble/Docker sources with exact versions/hashes and root-owned key/source/preference files. It verifies the complete manifest; enables the exact persistent ext4 `prjquota` mount option and performs the one documented reboot before Central state exists; installs the selected Chromium/NSS/quota tooling; creates locked `central-runtime`, `central-agent`, and `central-browser` identities; creates root-parented `central-state`, `central-protected`, `central-runtime`, and `central-browser` stores; installs helper, broker and sandbox-launcher sockets/units, runtime/browser supervisors, PAM/AppArmor and browser policy; and proves the managed browser accepts only root-managed anchors with extensions/developer changes/service workers disabled in local Wayland. It never adds the operator to Docker group or socket ACL and never asks a Central command to remount a filesystem.

Installing or changing host prerequisites, APT sources/keys/preferences, the helper, or its `sudoers` policy is an explicit root administrative trust transition outside every `central local` command. The helper has no `apt`, `dpkg`, package-repository, key-installation, service-enable, or arbitrary download operation. `local init`, `prepare`, and `up` never remediate the host. Normal unattended/package upgrades may make the machine unsupported; they must fail closed rather than be adopted.

The configless `central local doctor --host-prerequisites` verifies only independently observable `/etc/os-release`, kernel/architecture, package origin/version/architecture, public executable hashes/version output, browser identity, ext4 filesystem type plus active/persistent project-quota support, and the embedded prerequisite-manifest digest; it never assumes an instance or invokes privileged inspection. After administrator installation and `local init`, ordinary `local doctor` authenticates through the helper and additionally verifies root ownership/non-writability, locked identities, broker/runtime units, PAM policy, AppArmor state, browser/system trust integration, collision-free instance project-ID binding, exact quota limits/usage/receipt, Docker local-socket/API identity, Compose identity, and installed authority digests. Human output names the exact mismatched manifest field and prints only fixed package/source/runbook commands generated from the embedded manifest; JSON emits `HOST_PREREQUISITE_MISMATCH` and a fixed safe next action without raw package-manager output.

Phase 1 resolves every concrete package/archive/key/file identity into the executable manifest on two clean reference hosts and retains signed repository metadata as validation evidence. A manifest cannot be approved until a clean Ubuntu 24.04.4 installation reaches `doctor` success using only the documented sources and commands.

### Dependency lock and preparation

Phase 1 will create `deploy/local/dependencies.lock.json` with schema `central.local-dependencies/v1`. It contains the supported platform, PostgreSQL OCI index/platform-manifest/config/layer digests, MinIO source URL/tag/commit/archive SHA-256, canonical source-context digest, complete Go module-mirror digest and module inventory, build-recipe digest, all build/runtime base-image digests, expected MinIO OCI index/manifest/config/layer/diff-ID identities, fixed numeric service UID/GIDs, the canonical writable-path/mount/capability/syscall-policy digest, PostgreSQL client versions, separate SPDX SBOM and signed-provenance digests, and license-report digest. It also records the release-built `central-local-infra` OCI index/manifest/config/layer/diff-ID identities and SBOM/provenance for the sole static `fs-init`/`wipe` entrypoint, plus BuildKit `v0.31.1`, the official `buildkit-v0.31.1.linux-amd64.tar.gz` SHA-256 `1fc78750d0c96bdc18799a3c0b551d6807bd4939e8cd79e357823e467451e16e`, the built-in `dockerfile.v0` frontend identity, buildkitd configuration digest, exporter parameters, and build-plan schema. The repository copy is a reviewed build input but is not runtime Docker authority. The approved lock digest, base Compose model, complete build plan, allowed service/image/mount/port/pull policy, and helper protocol version are embedded in the installed infrastructure-helper artifact. A lock with an absent or placeholder identity cannot be embedded or prepared.

### Hermetic MinIO build contract

The helper does not use Docker's ambient builder, `docker build`, Buildx, a host plugin, or an external frontend image. It downloads the exact BuildKit release archive only during `prepare`, verifies the archive before extraction, verifies the expected fixed `buildkitd` and `buildctl` file digests from the embedded lock, and runs those root-owned extracted binaries with a generated root-owned configuration whose digest is embedded. The built-in `dockerfile.v0` frontend shipped in that archive is the sole frontend; gateway/remote frontends, frontend image resolution, workers other than the configured linux/amd64 OCI worker, emulation, and host Dockerfile syntax directives are rejected.

Release preparation creates a content-addressed offline input set: the verified MinIO source archive; a canonical source tar sorted bytewise with numeric UID/GID zero, fixed modes, no xattrs/ACLs, and every mtime equal to the locked commit time; every Go module zip, `.mod`, and checksum required by the selected graph; and every base OCI descriptor/blob. The module mirror and graph must exactly satisfy the source `go.mod`/`go.sum`; missing, extra, replaced, local-path, workspace, VCS, proxy, or sum disagreement fails. The build uses the locked Go toolchain/base by digest with `GOPROXY=file://<mounted-mirror>`, `GOSUMDB=off`, `GONOSUMDB=`, `GOPRIVATE=`, `GOENV=off`, `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, `GOFLAGS=-mod=readonly -trimpath -buildvcs=false`, an empty home/cache, fixed locale/umask, and the locked linker flags. No secret, SSH agent, host source path, VCS metadata, host Go installation/cache, wall clock, or undeclared build argument is mounted or visible.

Both source and dependency inputs are read-only. Build execution uses `network=none` for every vertex after the helper has imported the verified base blobs; any requested network, device, security-insecure entitlement, bind outside the canonical context/mirror, cache import/export, or nondeterministic mount fails policy. `SOURCE_DATE_EPOCH` is the locked commit time and the recipe normalizes generated file mtimes and image creation/history timestamps to it.

The sole exporter is OCI with OCI media types, gzip compression level 9, forced compression, timestamp rewrite, and no inline cache, provenance, or SBOM attachment. Those exact exporter attributes and their ordering are embedded in the build plan. SPDX SBOM, license report, and SLSA provenance are generated as separate content-addressed artifacts after the OCI result is known, so their timestamps or signatures cannot alter the runtime image digest; provenance binds all input, plan, builder, OCI, SBOM, and license identities.

One `prepare` acceptance performs two complete builds. Build A and Build B run in separately created, initially empty buildkitd state roots and content stores with distinct sockets and no cache or state shared between them; each independently imports the same verified offline blobs. The helper stops each daemon and proves its state root identity before deletion. Acceptance requires byte-identical OCI layouts and equal index, linux/amd64 manifest, config, compressed-layer, and uncompressed diff-ID digests, plus equal normalized filesystem inventory. A mismatch is `INCOMPATIBLE`; neither result is loaded. Only after equality, SBOM/license/provenance verification, and signed advisory admission does the helper load the accepted OCI layout into the fixed local Docker daemon and record the distinct runtime-image and evidence identities.

`central local prepare` is the only normal local command permitted to request dependency acquisition or build. It requires a current active signed advisory bundle whose identities and policy admit every locked input and output. Its unprivileged controller validates safe user-facing input and sends a closed typed request to the installed helper; only the helper contacts Docker or the network. It:

1. validates the host and lock schema;
2. fetches only locked artifacts when absent;
3. verifies every source, module, base, builder, and build-plan digest before use;
4. executes the two-clean-builder hermetic MinIO build contract above;
5. verifies the complete OCI identity and normalized filesystem inventory;
6. emits and verifies separate SBOM, license, and signed provenance evidence; and
7. atomically writes correlated root/operator protected preparation receipts bound to instance, platform, embedded helper-authority digest, helper protocol, lock digest, image identities, and tool versions.

`local init` performs no network or Docker access; after fresh PAM it invokes only the helper/broker's closed create-instance operation needed to create root-owned protected bindings and TLS material. `local up` neither fetches nor builds; a missing or mismatched preparation receipt is `DRIFTED`. An offline OCI/input bundle is acceptable only when every source, module, base, builder, output, and evidence identity resolves to the same helper-embedded lock and still passes the two-clean-builder check; a prebuilt MinIO image alone is insufficient. No floating tag, branch, base, unverified URL, caller-supplied Compose file, caller-supplied build recipe, or ambient builder state is permitted.

Gate 8 records the deterministic recipe and expected evidence. Phase 1 slice B must implement the complete build plan before its first `prepare`, independently reproduce it from a second clean host fixture, and require all identities above to match before the image is accepted; slice A can complete authority/config/init work without Docker or pretending preparation exists.

The identities above were resolved on 2026-07-16. Resolution fetched Docker Hub's OCI index for `library/postgres:16.14-bookworm` by digest, selected the sole descriptor with `os=linux`, `architecture=amd64`, and no variant, fetched that manifest by digest, and recorded its config descriptor. It separately resolved the MinIO lightweight tag through Git `ls-remote`, streamed GitHub's canonical `archive/refs/tags/...tar.gz`, and hashed the received bytes before extraction. Validation must repeat the process from the authoritative Docker Registry/GitHub endpoints, require all values to match, verify the PostgreSQL config reports version `16.14-bookworm` and linux/amd64, and verify the archive builds from the recorded commit. Tag movement, another platform descriptor, redirect to another repository, digest mismatch, duplicate platform match, or archive/hash/commit disagreement fails before acquisition is accepted. Phase 1 copies these reviewed values into the executable lock and proves the locally built MinIO result; no placeholder digest can reach an approved canonical contract or executable lock.

### Continuing vulnerability and provenance authority

Digest pinning proves identity, not continuing acceptability. The installed helper embeds one Ed25519 release-security public key and key ID inside its root-owned authority digest. The corresponding private key is offline and absent from the repository, helper, build environment, and local instance. Normal key rotation requires a transition signed by the previously trusted key and a new helper release; loss or compromise of that key requires an explicit root trust transition to an independently reviewed release and cannot be performed by `security update`.

The helper is the sole writer of `/var/lib/central-infra/security/v1/`. It stores create-only, root-owned bundle and signature generations plus an atomically replaced `active.json` selector; directories are `0755` and the public bundle, signature, and selector are `0644` so the unprivileged server can verify them but cannot alter them. A canonical `central.security-advisory/v1` bundle contains:

- bundle/key identities, UTC issue/expiry instants, source-feed snapshots and digests, scanner names/versions/database digests, and the exact platform, prerequisite-manifest, dependency-lock, build-recipe, helper-authority, and policy digests;
- the PostgreSQL OCI index/platform/config/layer/package identities and SPDX SBOM digest;
- the MinIO source URL/tag/commit/archive, module graph, build/runtime base, built OCI identities, package inventory, and SPDX SBOM digest;
- the release-built `central-local-infra` OCI/config/layer identities, static-binary provenance, syscall-policy digest, and SPDX SBOM digest;
- Docker, Compose, Go, and PostgreSQL client identities used to resolve, build, scan, or operate the dependencies;
- for every finding, the advisory ID, affected component and exact digest, CVSS vector/score/severity, known-exploited status, fixed-version status, and signed evidence references; and
- signed exceptions plus an emergency denylist of advisory IDs and component/image/source digests.

Missing, ambiguous, unverifiable, or unknown evidence fails closed for new admission. A bundle is admissible only when its Ed25519 signature over RFC 8785 canonical JSON verifies under the embedded key, its issue time is not in the future, its expiry is no more than seven days after issue and is still in the future, every evidence digest resolves, and every identity matches the installed helper and preparation authority. Database time is used when safely available; otherwise kernel time must be no earlier than the root-owned last successful activation time, so local clock rollback cannot reactivate old evidence. Successful admission writes a root-owned immutable `central.security-admission/v1` receipt binding the exact already-installed prerequisite, helper, lock, images, policy, bundle, exception, and emergency-deny identities; expiry never admits a different identity.

`central local security update` is a lifecycle-exclusive explicit operation. The online form permits the helper to fetch only its embedded HTTPS advisory endpoint. The offline form has the controller open one operator-selected absolute file with no-follow regular-file checks and pass only a fixed inherited read-only descriptor; the pathname is not sent and the signed bytes receive no authority until validation completes. Neither form accepts a caller URL, public key, digest, scanner database, exception, denylist, policy, or expiry. The helper bounds input size, verifies the complete bundle, synchronizes a create-only generation, atomically activates it, and writes correlated safe audit evidence. Offline use applies the identical signature and freshness rules and cannot extend validity. Repository state, unsigned caches, caller environment, TLS alone, scanner exit status alone, or a locally edited vulnerability database is never advisory authority.

The fixed acceptance policy rejects any component with CVSS score at least 7.0, any CISA KEV or signed equivalent known-exploited finding, any emergency-denied advisory or digest, any finding with unknown severity/score, stale feed evidence, or any provenance/SBOM/identity mismatch. A signed exception may cover only one exact non-known-exploited High/Critical advisory and component digest. It must state scope, owner, compensating controls, issue time, and expiry; expiry is at most 30 days after issue and no later than bundle expiry. Unknown/unscored findings, known-exploited findings, emergency-denied identities, provenance mismatches, and expired evidence are non-exemptible.

The helper evaluates the active bundle before `prepare`, dependency upgrade, or admission of any new artifact identity. An emergency bundle update requires serving and dependencies to be stopped and never races an active runtime. `central serve` independently verifies the public signature, root ownership/modes, active-selector and evidence digests, policy, exact installed identities, and the immutable admission receipt before constructing adapters or listeners, and continues to monitor expiry while running. No privileged background updater exists. `central local security status` and `local doctor` report only safe bundle/key IDs, issue/expiry, policy result, advisory counts, stale-authority state, and exact next action—never raw package paths, scanner output, or suppressed finding detail.

A missing bundle or an expired bundle with no matching prior admission receipt returns exit `5`/`SECURITY_REVIEW_REQUIRED`. For at most 30 elapsed days after bundle expiry, an exact matching prior admission is `SECURITY_AUTHORITY_STALE`: `prepare`, dependency upgrade, helper/release transition, and changed identity remain blocked, while `up` and `serve` may continue only the receipt-bound set with prominent warnings/metrics. At expiry plus 30 days, immutable root time evidence enters `SECURITY_AUTHORITY_HARD_EXPIRED`; `up`, `serve`, agent execution, bootstrap/session creation, migration, ordinary backup create, restore apply, and every application mutation are blocked. Status/explain/read-only doctor without probes/security update, sealed-backup verify/export, the single offline rescue-backup mode and its settlement-only cleanup continuation below, browser-independent recovery documentation, and `down` remain. There is no renewable risk-acceptance override or clock rollback. A signed emergency deny already present, policy/exception/provenance violation, or identity mismatch returns exit `5`/`DEPENDENCY_DENIED` immediately and forbids rescue creation but never forbids cleanup of an already bound rescue scratch root. Phase 1 pins compiler/scanners/databases, implements current/stale/hard-expired/deny conformance, and requires review at least every seven days plus immediate emergency publication.

The release-security owner, not Phase 1 runtime code, owns the advisory compiler, offline signing ceremony, public-key custody and recovery, endpoint publication, feed ingestion, emergency response, and independently downloadable offline bundle channel. `docs/operations/local-security-authority.md` defines publication evidence, key-compromise recovery through a reviewed release, endpoint outage behavior, offline transfer, and warnings beginning 72 hours before expiry. Phase 1 owns only the closed consumer/conformance implementation. Central's local-first availability promise is therefore bounded: an already admitted unchanged installation can serve without a control plane for at most the 30-day stale grace and retains recovery/export access afterward, but cannot admit new dependency authority without current signed evidence.

### Host and persistent-dependency upgrade protocol

No package or dependency change occurs through `local up`. An upgrade begins under the currently accepted release by stopping `serve`, creating and verifying a complete Gate 7 backup after the last durable mutation, and recording its sealed manifest/security/config/dependency identities. The operator then runs `local down`. Only after every container and tmpfs handoff is proven stopped/released may an administrator install the new prerequisite manifest, release helper, and `sudoers` policy. `local doctor` must pass the new exact host manifest before `security update`, `prepare`, or an upgrade command can proceed.

Persistent dependency transition uses three explicit commands:

```text
central local dependency-upgrade plan
central local dependency-upgrade apply --ticket=<ticket-id>
central local dependency-upgrade resume --operation=<operation-id>
```

`plan` is lifecycle-exclusive, requires dependencies stopped, and creates a single-use protected ticket bound to the old and new helper/prerequisite/dependency/advisory/config identities, exact payload binding/mount/device evidence, current schema/security/restore barriers, the verified backup sealed after the last mutation, free-capacity evidence, upstream on-disk compatibility statement digest, Phase 1 compatibility-fixture result, rollback classification, issue time, and 30-minute expiry. It never changes payloads. Missing/stale backup is `BACKUP_REQUIRED`; absent exact compatibility evidence is `UPGRADE_NOT_SAFE`.

`apply` accepts only that exact unexpired ticket and takes lifecycle plus target-exclusive ownership. Its accepted point durably records the operation and old/new identities before any new binary opens a payload. A permitted in-place transition is limited to a PostgreSQL patch within major 16 or a MinIO patch/rebuild for which upstream documentation and Phase 1 fixtures prove the exact old-to-new on-disk format compatible. The helper starts only the new digest under the no-auto-restart topology, runs crash recovery and fixed read/write/inventory/schema/policy probes, writes new preparation/provision receipts only after success, and leaves dependencies `STOPPED`; the operator subsequently uses ordinary `local up`. Failure after acceptance is `RESUME_REQUIRED` or `MUTATION_INDETERMINATE`, never an automatic old-image start.

Rollback is permitted only when the ticket contains separately reviewed evidence that the old binary can safely reopen every format the new binary may have written, no application or operator write occurred under the new version, and the fixed rollback fixture passed. Otherwise the old image is barred after the accepted point; recovery is forward repair or verified restore into fresh roots. A package downgrade, image retag, old preparation receipt, or preserved container is not rollback evidence.

A PostgreSQL major transition, MinIO replacement with unproven in-place compatibility, storage-layout change, or cross-platform transition is never in-place. `plan` succeeds diagnostically with `UPGRADE_OUT_OF_PLACE_REQUIRED` and directs creation of a new isolated instance/payload roots followed by the accepted verified restore and cutover protocol. The old roots remain stopped and read-only-retained until the new target passes full verification; no command rewrites them in place or silently changes the configured target. Phase 1 need only implement the selected Phase 1 patch matrix; unsupported transitions fail safely with this exact out-of-place classification.

Upgrade durability uses create-only ticket generations plus `operations/dependency-upgrade/<operation-id>.json` with schema `central.dependency-upgrade-operation/v1`. Every atomic replacement contains operation/ticket/instance/target/config/payload-epoch/old-new authority IDs; phase `planned`, `accepted`, `old_stopped`, `new_opened`, `probed`, `receipts_committed`, `settled`, or `terminal`; accepted-at; current checkpoint; exact backup and compatibility-evidence IDs; rollback classification; safe failure class; and prior-record digest. `apply` first consumes the ticket and synchronizes phase `accepted` before a new binary can open payload state. Each later phase is synchronized before releasing its resource; preparation/provision receipt activation precedes `receipts_committed`, and terminal publication precedes ticket cleanup. Startup reconciles one monotonic chain only; a missing/duplicate predecessor, epoch change, or payload observation ahead of its record is `MUTATION_INDETERMINATE`, while an exact nonterminal chain permits only `dependency-upgrade resume --operation=<id>`.

## Process and Compose topology

### Host serving profile

One all-in-one host profile enables:

- the application HTTPS listener;
- the dedicated operational HTTP listener;
- execution coordination;
- outbox delivery;
- Artifact reconciliation and cleanup;
- Task/runtime reconciliation and lease recovery;
- session/bootstrap recovery; and
- bounded startup preflight and graceful shutdown.

These are supervised components inside one `central serve` process under the locked `central-runtime` UID, not additional command names or independently restartable application daemons. A terminal enabled-component failure cancels the entire profile as required by Gate 7. Migration, backup, and restore remain explicit operator modes and never become serving components or HTTP handlers. Generic tools, repository hooks, and agent child processes never run as `central-runtime`; they run as the locked `central-agent` identity inside the Gate 3 sandbox with no config/state/protected/broker mount, no broker socket access, a private PID/mount namespace, `PR_SET_DUMPABLE=0`, and only explicitly delegated Workspace descriptors.

### Privileged local infrastructure helper

The helper is an internal mode of the same Central release artifact, installed as a root-owned immutable copy at a fixed absolute path. Installing or replacing it and its root-owned `sudoers` policy is an explicit host trust transition from an approved package/release or operator-reviewed source build. `local init`, `local prepare`, and `local up` cannot install, replace, bless, or select a helper. The helper executable, every parent directory, its policy, embedded authority digest, absolute Docker/Compose executable paths, and audit-receipt directory are root-owned and not writable by the operator.

The ordinary operator UID is not a member of the Docker group, has no Docker-socket ACL, and cannot open the local Docker socket. The actual `central-runtime` serving process, migration/bootstrap/backup/restore adapters, broker, and `central-agent` executions cannot invoke the infrastructure helper and receive neither Docker socket access nor its `sudoers` grant. Operator commands are controllers: only they may invoke the closed helper entrypoint after PAM, and the helper launches the exact approved non-Docker application mode as `central-runtime` whenever protected use is required. Phase 1 must prove all denials. The helper permits only this closed operation matrix:

| Request | Permitted authority |
| --- | --- |
| `init` / `init-status` / `init-resume` / `init-abandon` | create, discover, resume, or abandon only caller-bound configless journaled initialization; abandon is limited to an unaccepted empty reservation; no network or Docker |
| `prepare` | fetch, build, verify, and load only embedded locked dependency artifacts |
| `security-update` | fetch only the embedded advisory endpoint or consume the fixed inherited offline descriptor; verify and atomically activate only a release-key-signed admissible bundle |
| `dependency-upgrade-plan` | bounded compatibility/backup/capacity inspection plus creation of one exact protected upgrade ticket; no payload or container mutation |
| `dependency-upgrade-apply` / `dependency-upgrade-resume` | execute or resume only the ticket-bound embedded old-to-new patch transition and its fixed verification probes |
| `trust-install` / `trust-remove` | install or remove only the exact validated instance CA public certificate in the Ubuntu system and selected browser trust stores; never read a CA or server private key |
| `browser-open` | launch the exact managed Central browser/profile as `central-browser` in the active local Wayland session at the fixed HTTPS origin; no caller URL, flags, extension, proxy, or alternate profile |
| `browser-clear` / `browser-clear-resume` | after durable application-session/bootstrap invalidation, start or resume only the exact journaled replacement of the descriptor-bound managed profile |
| `runtime-stage` | after fresh PAM, copy one descriptor-opened Go binary plus its descriptor-opened canonical build manifest into the root-owned instance-scoped runtime staging store, verify their binding, and activate the digest for a bounded development lease; never execute from the repository path |
| `runtime-start` / `runtime-stop` / `operator-mode-start` | launch or settle only the embedded/staged-authority `central serve`, migration, bootstrap, backup, restore, and registered adapter modes as `central-runtime` with descriptor-bound config and broker access; never execute caller code or an unlisted mode |
| `security-rescue-cleanup` | stop/reap only the exact rescue operation topology and continue only its authenticated descriptor-bound scratch deletion journal; no backup/data mutation or caller path |
| `bootstrap-show` | after fresh PAM and ready-server proof, let the broker rotate and write one presentation generation directly to the helper-owned TTY; helper/controller never receive plaintext |
| `up` | render and validate the embedded Compose model; materialize exact service-scoped secret handoffs; run filesystem initialization, start, health-check, provision, and inspect steps |
| `status` / `doctor` | bounded read-only inspection of the exact instance resources; the explicit write probe uses an ordinary application credential rather than Docker authority |
| `down` | stop only exact instance-bound resources while preserving payload data |
| `wipe` | after exact fixed confirmation/locks/accepted receipt, run or resume only the sequential one-root-at-a-time no-network `central-local-infra` wipe protocol |

The request protocol is versioned and closed: operation, invoking UID, instance/binding/config/lock identities, exact operation or confirmation identity where required, and safe correlation ID. It contains no plaintext secret, secret pathname, container UID/GID, Compose fragment, image, socket, or executable argument. The invoking UID is authenticated by a root-owned `sudoers` policy with `env_reset`, `timestamp_timeout=0`, a fixed executable, `secure_path`, and no shell or arbitrary arguments; passwordless rules and cached credentials are forbidden. Every helper request therefore requires a fresh PAM conversation. The helper verifies the active local logind/Wayland session and physical-seat TTY ancestry, takes an exclusive terminal lease, uses `vhangup`/reopen to invalidate prior same-UID terminal descriptors, applies `TIOCEXCL`, temporarily makes the reopened device root-only, and performs the PAM/confirmation conversation itself before restoring exact ownership/mode at final settlement. A caller-created PTY, remote/SSH session, missing physical seat, ownership transition failure, PAM failure, forwarding, or noninteractive invocation is `AUTHORITY_DENIED`; production has no automation bypass. The helper opens every selected config/state/data component with no-follow semantics, proves expected ownership, modes, path ancestry, mount/device identity, and lifecycle lock, then recomputes embedded authority. Unknown fields, operations, resources, or drift are denied before mutation.

For `wipe`, restore apply, hard-expired rescue backup, backup/export deletion or pruning, trust removal, audit/protected-generation maintenance, and dependency-upgrade apply/resume, PAM success alone is insufficient. After fresh authentication the helper itself opens `/dev/tty`, displays the safe operation/target/plan IDs it independently recomputed, reads the fixed confirmation phrase with echo disabled, and binds a one-use confirmation digest to the helper authority, PAM session, boot ID, caller UID, operation ID, target/payload epoch, exact action, and a 60-second deadline. Controller-created PTYs, controller confirmation digests, stdin, flags, environment, redirected input, and replay are rejected. The helper consumes the digest atomically at the accepted point. Phase 1 attacks this boundary using same-UID PTYs, sudo timestamp injection, process replay, `/proc`, and controller compromise.

Unprivileged `local status` and `local security status` read only broker-signed XDG safe views and loopback health, report `privileged_inspection=not_performed` plus snapshot generation/age, and never contact Docker, helper, or broker. A dedicated Ed25519 view-signing public key is installed read-only under `/usr/share/central/authority/v1/view-signing.pub`; its private key exists only in the broker. Missing/changed/invalid views are non-authoritative failure, not a fallback to raw state. These commands are lockless snapshots that may race topology and never claim lock-consistent/current inspection. Full `local doctor`, `prepare`, `up`, `down`, security/trust changes, runtime start/stop, upgrade, and destructive maintenance require fresh helper authentication. Usability measurements report authentication separately; no budget assumes cached sudo.

The helper executes locked absolute Docker and Compose paths against one fixed root-owned local socket. It starts from an allowlisted environment and discards `DOCKER_*`, `COMPOSE_*`, proxy, home, plugin, build, and credential variables; uses a root-owned empty Docker configuration; disables `.env` and implicit Compose discovery; and supplies explicit project/file arguments. Remote contexts/daemons, caller plugins, caller Compose/build files, Buildx/ambient builder selection, build during `up`, and registry pulls during `up` are forbidden.

The user-owned generated Compose override is diagnostic evidence only and is never executed. For every mutation the helper rerenders its embedded authority model with validated instance values into a root-owned `0600` ephemeral directory under `/run/central-infra/<instance-id>/`, runs `docker compose config`, and policy-checks the exact service/network set, immutable image references, pull policies, absence of build configuration, ports, mounts, secrets, resource limits, capabilities, health checks, and restart policies before contacting the daemon. It removes the ephemeral model after the operation. Root-owned helper audit and locked-runtime authoritative command audit share a safe correlation ID and record authority digest/result without secrets or raw protected paths; XDG receives only a broker-signed safe view.

Every rendered service has an `image` reference containing the exact accepted OCI manifest digest, has `pull_policy: never`, and has no `build`, tag-only reference, mutable alias, platform ambiguity, or credential-helper/registry dependency. Before the `up` accepted point, the helper performs bounded read-only local-daemon inspection and requires each exact manifest, config, and layer to exist, select linux/amd64, match the preparation receipt and signed advisory bundle, and contain the expected normalized image inventory. Absence or mismatch is `PREPARATION_REQUIRED` or `DRIFTED` with no container/network/secret-handoff mutation. The subsequent Compose invocation also uses the fixed no-build/no-pull operation form; an observed registry request, build session, image substitution, or daemon-side resolution aborts and is never accepted as startup.

Immediately before its first Docker mutation, `up` writes and synchronizes correlated root/operator prior-state receipts. They bind the exact project/network existence and identity; each service's absent/created/running/stopped state, container identity, image/config digest, and mount set; completed fs-init/provision receipts; active secret-handoff version tokens; and the command operation/config/authority identity. This is the `up` accepted point. The receipt contains no secret or raw protected path.

Successful `up` finalization additionally binds the Linux kernel boot ID, exact container IDs and Docker `StartedAt` values, stopped/completed identities for one-shot services, image/mount/secret-generation version tokens, and semantic provision receipts. Status and serving compare that evidence to current inspection. A later raw Docker start changes the observed start identity without a correlated helper operation and is `DRIFTED`; a host reboot changes boot ID and yields `STOPPED`. These opaque identities are retained only in protected/helper audit evidence and are not emitted by `central.local-result/v1`.

If Docker reports a publication conflict after that point, the helper stops forward progress and performs a 60-second reverse-order rollback. A previously running exact container remains running; a previously stopped exact container is returned to stopped; a container/network created by this operation is stopped and removed only after its labels/config/mount identity revalidate; and pre-existing resources are never replaced or removed. Exact secret handoffs created for a removed/stopped consumer are cleaned under their separate mount-release contract. Images, host payload roots, protected state, receipts, and backups are never deleted by rollback.

Filesystem initialization or another idempotent durable step may have completed before the authoritative bind failure. Rollback does not pretend to reverse it: its exact receipt remains, and a repeated identical `local up` resumes/skips only that proven step. Successful topology rollback with recognized durable-step evidence returns exit `6`/`PORT_BIND_RACE`, records the accepted mutation and operation ID, and permits `retry_same` only after the conflicting process is removed. Failure to prove or complete exact rollback returns exit `6`/`ROLLBACK_FAILED`, state `DRIFTED` or `cleanup_required`, and requires `local doctor`/manual inspection; no automatic retry starts. A crash during rollback resumes only from the correlated prior-state and helper audit evidence.

### Locked runtime identities and protected-value broker

Phase 1 installs a root-owned, socket-activated `central-protected-broker` mode of the approved Central release. It is not a general privileged daemon: systemd activates it only on a fixed `0600` Unix socket owned by root and accessible solely through one descriptor preopened for an authenticated `central-runtime` process; it has no network, Docker, shell, package, Workspace, arbitrary-path, or caller-executable authority and exits after the fixed idle deadline when no authenticated session or in-flight signing/use request exists. Root owns `/var/lib/central-protected/v1/` mode `0700`, every protected binding/value, TLS private key, HMAC fingerprint key, broker journal, and launcher evidence. The operator, `central-runtime`, and `central-agent` cannot traverse that root.

The root helper launches a tiny approved supervisor and the release/staged binary as locked UID/GID `central-runtime`, with `NoNewPrivileges`, `PR_SET_DUMPABLE=0`, private `/tmp` and `/proc`, no supplementary groups, no repository/Workspace pathname, and no Docker/helper socket. It preopens and passes only the exact mode-required authoritative config, instance directory, lifecycle/runtime lock inodes, operation/audit/repository directories, public TLS certificate, broker session, sandbox-launcher session, and control/status descriptors; descriptor tables are closed/embedded per command and unknown extras abort. The runtime uses `openat2` beneath those already-open central-state descriptors and never traverses `/var/lib` by pathname.

For foreground `serve`, the `central-runtime` supervisor is the runtime's real parent and owns a root-created `SOCK_SEQPACKET` control/status pair plus pidfd. The operator controller receives only the peer carrying a one-use launch nonce and can send `interrupt` or `status`; it cannot inject config, signal number, command, or authority. SIGINT/SIGTERM is relayed as the fixed graceful cancellation within one second. Controller disconnect/HUP triggers the same cancellation; it never daemonizes. The supervisor waits/reaps runtime, receives its durable settlement acknowledgement, closes broker/sandbox sessions, and relays the exact stable exit class only after child/descriptors are gone. Supervisor loss causes runtime parent-death cancellation. No second PAM is required to relay Ctrl-C or receive exit because the launch session already bound that fixed control plane.

A development stage opens both source binary and manifest by no-follow descriptor, requires the root-owned Go tool identity named by the manifest, verifies the manifest's binary SHA-256 against the held descriptor and embedded build info, copies both create-only into `/var/lib/central-runtime/v1/<instance-id>/builds/<digest>/`, synchronizes them, and records an instance/config/payload-epoch-bound lease expiring after eight hours or reboot. Fresh PAM and helper-displayed digest confirmation explicitly promote only those bytes; later source-tree changes are inert. Staging is permitted only for a `development` instance, and a new stage settles the old runtime. The broker authenticates the runtime by kernel credentials, launch/stage receipt, executable identity, boot ID, pidfd, and nonce; shutdown revokes sessions before settlement completes.

Phase 1 also installs a distinct root-owned, socket-activated `central-sandbox-launcher` with no Docker, network, secret, config-mutation, arbitrary-path, or shell authority. Only an authenticated `central-runtime` launch session may call it. A closed request names one persisted Gate 3 authorization-use ID, registered Workspace-root binding ID, fixed adapter/executable class, relative capability paths, resource envelope, and correlation ID. The launcher reopens the registered operator-owned Workspace root with `openat2`/binding/handle checks under the operator fsuid, verifies the broker-MAC authorization token and current database authorization epoch supplied through the runtime session, opens only allowed Workspace/artifact descriptors, then creates the private PID/mount namespace and drops permanently to `central-agent` before exec. It returns pidfd/control pipes to runtime and retains a minimal parent supervisor until it reaps the child. No request contains an absolute path, UID, mount, executable, environment, or namespace flag. Agent exit revokes descriptors/token; launcher crash kills the namespace. Phase 1 proves unauthorized root/path/executable substitution, cross-agent ptrace, namespace escape, and runtime/helper/broker access fail.

The managed browser profile lives at `/var/lib/central-browser/v1/<instance-id>/` beneath a root-owned `0700` parent; the exact instance directory/cache belongs to `central-browser` and is invisible to operator/runtime/agent UIDs. It contains only Chromium's bounded profile/session/cache state and the root-managed policy; no Workspace, Central config/state, broker/helper socket, or arbitrary download directory is mounted. Downloads, extensions, developer tools/protocol, password storage, sync, external URL handlers, service workers, background mode, and non-loopback navigation are disabled. The helper validates one active local logind Wayland seat, opens the exact compositor socket itself, passes only that connected descriptor as `WAYLAND_SOCKET=<fixed-fd>` plus fixed locale/runtime descriptors, and launches the browser in a systemd scope as `central-browser`; no X11, caller display/socket/environment, session bus, or alternate profile is used. The selected browser/sandbox must support this descriptor path on both clean fixtures.

At init, the helper holds the root-only browser-project registry lock, chooses the lowest unused project ID in `[100000,2147483646]`, binds it create-only to instance/profile device+inode evidence, applies it recursively before profile publication, installs the byte/inode hard limits, and commits a broker-HMAC quota receipt. It never derives a colliding truncated ID from the UUID. Open/clear/doctor compare the registry, kernel quota record, mount ID/options, and receipt; deletion does not free/reuse an ID during Phase 1.

The browser scope has one CPU, 512 MiB `MemoryMax`, PID limit 256, an ext4 project hard quota of 1 GiB/50,000 inodes for its complete profile, a 256 MiB disk-cache ceiling, disabled media cache, no network except numeric loopback through its namespace policy, and one profile lock. Quota or inventory drift blocks open and is reported by doctor; the browser cannot spill to another directory. Closing the last Central window terminates background processes; `browser open` reuses only the exact live scope or starts a new one.

`central local browser clear` is the sole profile reset. After fresh PAM it takes lifecycle and runtime locks exclusively, proves `serve` and the browser scope stopped, and requires the exact dependencies already healthy under a current correlated `local up` receipt; otherwise it returns preflight `DEPENDENCY_UNAVAILABLE` with the exact `local up` action and performs no revocation/profile mutation. It then launches the fixed runtime maintenance mode to revoke all application sessions and the bootstrap presentation generation under the target-exclusive/database-row locks. That durable revocation is the accepted point. The broker-bound `central.browser-clear-operation/v1` journal advances only through `planned`, `sessions_revoked`, `scope_stopped`, `old_profile_quarantined`, `new_profile_created`, and `complete`; each transition synchronizes before the next. The helper renames only the descriptor-bound instance profile to an operation-owned quarantine, creates the fixed root-policy/trust scaffold as `central-browser`, verifies it, and deletes the quarantine in at-most-1,000-entry/64-MiB quanta with durable counts. The five-minute parent deadline clips revocation, rename, quota setup, validation, deletion, and settlement; expiry synchronizes the checkpoint and requires exact resume without retaining locks. A crash resumes the exact operation; before the accepted point retry is safe, and afterward alternate/new clear is forbidden until exact settlement. Ordinary same-UID processes cannot read/delete cookies or trust state. Phase 1 validates Wayland launch, navigation/TLS/bootstrap, close/reopen, crash injection at every clear phase, profile/quota/cache ceilings, cgroup OOM safe failure, and direct filesystem/process-memory denial.

Secret use is purpose-specific and non-enumerating. For host adapters the broker revalidates the active protected pointer and authorization-use fence, copies only the named bounded generation to a sealed `memfd`, transfers it to the authenticated runtime adapter, and destroys its broker buffer; the adapter inherits no directory or broker-root descriptor and clears/closes the memfd after the one authorized use. TLS exposes the public chain plus a narrow `crypto.Signer` operation over the locked leaf key; the CA key signs only the fixed offline leaf-rotation object and never leaves the broker. Dependency handoff asks the broker to write the exact purpose-bound value directly into the helper's service-scoped root tmpfs descriptor after both authorities mutually authenticate the operation; neither helper nor operator can enumerate another binding.

Untrusted execution is launched as `central-agent` in a new PID/mount namespace with no broker/helper/config/state/protected path, no inherited runtime descriptor, a minimal read-only filesystem, and only capability-authorized Workspace/artifact descriptors. Each child is non-dumpable and cannot ptrace another agent or runtime process. The runtime does not execute repository hooks or generic tools in its own UID. Phase 1 proves direct open/enumeration, same-operator-UID access, `ptrace`, `/proc/<pid>/{mem,fd}`, inherited-descriptor, broker-socket replay, runtime-subprocess, and cross-agent attacks fail while an authorized adapter use still succeeds.

### Compose services

The Compose project is `central-<full-instance-id>` and contains exactly one internal network named `infra` plus six services:

| Service | Lifetime | Network | Writable mount |
| --- | --- | --- | --- |
| `postgres-fs-init` | one-shot | none | PostgreSQL data directory only |
| `minio-fs-init` | one-shot | none | MinIO data directory only |
| `postgres` | long-running | `infra` | PostgreSQL data directory |
| `minio` | long-running | `infra` | MinIO data directory |
| `postgres-provision` | one-shot | `infra` | none |
| `minio-provision` | one-shot | `infra` | none |

The order is filesystem initialization, dependency health, logical provisioning, and receipt verification. Both fs-init services use the exact `central-local-infra` image in their fixed `fs-init` mode; PostgreSQL daemon/provisioner use the locked PostgreSQL image, and MinIO daemon/provisioner use the locked MinIO image. All six services use exact digest-qualified images, `pull_policy: never`, and explicit `restart: "no"`; none contains `build:`. Central is never supervised by Compose. Docker daemon restart, host reboot, dependency process exit, or an unhealthy probe therefore never auto-starts or auto-restarts a service.

`central local up` through the installed helper is the sole supported dependency start path. Before any daemon can reopen writable payload state it revalidates lifecycle/target exclusion, descriptor-bound roots and mount identities, exact local images and preparation receipts, current advisory authority, active secret generations and tmpfs handoffs, configured ports, prior container state, crash-recovery probes, migration/restore security barriers, and the embedded Compose policy. Reboot clears tmpfs handoffs and leaves exact stopped containers plus durable payloads/receipts; the derived state is `STOPPED` until a fresh `local up` rematerializes secrets and completes the checks. The helper never implements a raw start/restart request, health-triggered restart, boot hook, or privileged background reconciler.

The `infra` bridge is project-scoped and internal. Services use Compose DNS aliases, never static IPs or a fixed subnet. No service mounts the Docker socket, repository, Workspace, backup repository, or complete operator-state root. Runtime services have no outbound Internet route; the installed helper mediates image acquisition through the fixed local Docker daemon during explicit preparation, before service startup.

### Container privilege and resource envelope

PostgreSQL, MinIO, and both logical provisioners drop all Linux capabilities, set `no-new-privileges`, use a read-only root filesystem, and receive only bounded tmpfs and exact writable mounts. PostgreSQL and MinIO daemons run as the numeric non-root UID/GID recorded in the dependency lock.

The two filesystem initializers run as root with no network, one exact mount, `no-new-privileges`, and a read-only root filesystem. They drop every capability except `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, and `CAP_FOWNER`, which are required only to traverse the bound owner-only root and establish the locked UID/GID and mode. They may validate the instance binding, create an absent payload directory, and perform that ownership/mode transition; the helper rejects any additional capability. They reject symlinks, changed device/mount identity, unexpected ownership, or nonempty unrecognized content. Logical provisioners are non-root, have network access only to `infra`, and never mount payload data.

### Exact container writable-path contract

The dependency lock fixes PostgreSQL UID/GID `999:999` and MinIO UID/GID `1000:1000`; both provisioners use the corresponding dependency identity, while fs-init and wipe enter as UID/GID `0:0` with only their separately listed capabilities. The image filesystem, working directory, binaries, libraries, `/etc`, and entrypoint configuration are read-only. The complete writable inventory is:

| Service/mode | Durable read-write mount | Ephemeral writable mounts | Fixed runtime contract |
| --- | --- | --- | --- |
| `postgres-fs-init` | held PostgreSQL root at `/payload`; root directory itself is preserved | `/dev/shm` 8 MiB, mode `01777` | `HOME` unset; working directory `/`; no socket/cache/temp path |
| `minio-fs-init` | held MinIO root at `/payload`; root directory itself is preserved | `/dev/shm` 8 MiB, mode `01777` | `HOME` unset; working directory `/`; no socket/cache/temp path |
| `postgres` | PostgreSQL root at `/var/lib/postgresql/data` | `/tmp` 64 MiB mode `01770`; `/run/postgresql` 16 MiB mode `0750`; `/dev/shm` 768 MiB mode `01777` | UID/GID `999:999`; `PGDATA=/var/lib/postgresql/data`; `HOME=/tmp/postgres-home`; Unix socket only `/run/postgresql/.s.PGSQL.5432` |
| `minio` | MinIO root at `/data` | `/tmp` 256 MiB mode `01770`; `/home/minio` 16 MiB mode `0700`; `/run` 16 MiB mode `0750`; `/dev/shm` 64 MiB mode `01777` | UID/GID `1000:1000`; `HOME=/home/minio`; fixed config/certs/cache descendants only below that ephemeral home |
| `postgres-provision` | none | `/tmp` 16 MiB mode `0700`; `/dev/shm` 8 MiB mode `01777` | UID/GID `999:999`; `HOME=/tmp/home`; no history file; network only `infra` |
| `minio-provision` | none | `/tmp` 16 MiB mode `0700`; `/home/minio` 8 MiB mode `0700`; `/run` 8 MiB mode `0750`; `/dev/shm` 8 MiB mode `01777` | UID/GID `1000:1000`; `HOME=/home/minio`; network only `infra` |
| one-off `wipe` | one held payload root at `/payload`; root directory itself is preserved | `/tmp` 8 MiB mode `0700`; `/dev/shm` 8 MiB mode `01777` | UID/GID `0:0`; working directory `/`; no home, network, socket, cache, or second payload |

Every listed tmpfs is private, size-capped, owned by the listed UID/GID, and mounted `rw,nosuid,nodev,noexec`; the helper rejects an executable tmpfs exception. Docker IPC is private. `/dev` contains only the fixed runtime device set, is not a durable/config/cache location, and is non-writable to non-root services; `/proc` and `/sys` use the embedded read-only/masked-path policy. No TTY, host PID/IPC namespace, device, cgroup namespace mutation, or additional anonymous/named volume is permitted. The helper compares effective mounts and options from container inspection plus in-container mountinfo before start acknowledgement.

Entrypoints create only the named descendants inside their tmpfs—for example `/tmp/postgres-home` mode `0700`—before exec and then drop any setup path. A write attempt elsewhere, unexpected runtime-created mount, undeclared volume from image metadata, writable image layer, tmpfs size/owner/mode/flag drift, or path escaping its named mount is `INCOMPATIBLE` and blocks the preparation receipt. Phase 1 runs each service through startup, health, provision, steady I/O, shutdown, failure, and restart probes with a write-auditing filesystem fixture and proves the inventory complete.

### One-off destructive wipe mode

`central-local-infra` is a release-built `scratch`-style image containing one statically linked entrypoint, no shell/package manager/network client/interpreter, and exactly two closed modes: `fs-init` and `wipe`. Its OCI/config/layer, binary, SBOM, provenance, seccomp-profile, and AppArmor-profile digests are embedded in the helper and admitted by the active advisory bundle. The two Compose fs-init services use only `fs-init`; `wipe` is never present in the Compose model and is not a seventh service.

The prerequisite manifest pins `apparmor`, `apparmor_parser`, kernel feature evidence, the root-owned profile name `central-local-infra-wipe-v1`, installed path `/etc/apparmor.d/central-local-infra-wipe-v1`, canonical source digest, compiled-cache digest where applicable, and exact loaded-policy feature/attachment identity. Administrator installation validates the source, loads/replaces it with the pinned parser, verifies the kernel-reported loaded identity, and records a root-owned trust receipt; removal or replacement is another explicit trust transition. Immediately before container creation the helper proves the installed file, parser/kernel feature set, loaded profile identity, and receipt all match its embedded authority, and passes only `apparmor=central-local-infra-wipe-v1`. Missing, ambient/default, complain-mode, stale, caller-selected, or unverifiable policy is `HELPER_POLICY_DENIED`; wipe never falls back to seccomp alone.

Wipe requires lifecycle-exclusive ownership, no runtime/target/backup/restore/upgrade operation, dependencies proven stopped, secret handoffs released, and an exact current data binding for both payload roots. After fresh PAM authentication the helper, not the controller, displays and reads the trusted-TTY phrase `WIPE <full-instance-id> <full-target-id> POSTGRES+MINIO` and creates the one-use operation-bound confirmation described above. There is no `--yes`, force, partial-root selector, caller confirmation digest, caller image, command, mount, UID/GID, capability, or path input.

The helper independently reopens and validates both roots with the held-descriptor/mount-handle protocol, rejects nested mounts, links, special files, immutable/append-only flags, active file handles it can detect, or unrecognized payload markers, and writes synchronized root/operator prior-state receipts. The wipe accepted point is publication of those receipts before the first destructive container. From that point, interruption returns exact `RESUME_REQUIRED`; a new wipe or ordinary `up` is forbidden.

The helper processes PostgreSQL then MinIO sequentially. For each root it uses direct fixed Docker API/CLI arguments—not Compose—to create one operation-labelled container from the already local exact `central-local-infra` manifest with `pull=never`, network `none`, read-only rootfs, private PID/IPC, PID limit 16, memory 64 MiB, one CPU, `no-new-privileges`, all capabilities dropped except `CAP_DAC_OVERRIDE`, and the exact wipe tmpfs/masked/read-only paths above. It bind-mounts only `/proc/<helper-pid>/fd/<fixed-fd>` to `/payload` read-write with `rprivate` propagation. No other host path, device, secret, environment value, or inherited descriptor is present.

The fixed entrypoint receives only bounded opaque operation/binding evidence and expected device/inode/type as fixed arguments. It verifies `/payload` against those values, enumerates descriptor-relative without following links, preserves `/payload` itself, removes only descendants in postorder with `openat2`/`unlinkat`, synchronizes the emptied root, reverifies identity/emptiness, and emits one canonical bounded acknowledgement on stdout. It cannot mount, unshare, set namespace, open a socket, ptrace, load BPF, change ownership/mode, execute another program, or address a second root under the locked seccomp/AppArmor policy.

The helper verifies the acknowledgement against its still-open source descriptor, inspects that no unexpected mount/write occurred, stops/removes only the exact operation-labelled container, and records a durable per-root completion checkpoint before advancing. A container/helper crash leaves the current root classified partial behind the wipe barrier. `central local wipe` repeated with the same operation ID resumes only the unfinished root after revalidation; a completed root is never reprocessed as evidence that the other completed. Success requires both roots empty, both containers absent, every Docker mount released, and final correlated receipts synchronized. It never deletes payload root directories, configuration, bindings, protected generations, operations, receipts, audit, backup repository, export media, or another instance resource.

After both empty-root checkpoints, the broker performs a wipe-bound credential reseed before releasing the barrier. It stages fresh independent generations for the PostgreSQL built-in bootstrap identity and all three application roles, plus the MinIO root/runtime/backup/restore identities. Those generations are future-only: the protected wipe operation registers them for the next exact provision step, activates each through the candidate journal, and retires the displaced generations; no absent dependency is claimed to have accepted them yet. Logical SecretReference binding IDs remain stable, while every secret value/version token changes. TLS CA/leaf generations, installed trust receipt, helper/prerequisite/preparation authority, and signed advisory bundle are preserved.

The same wipe commit revokes any bootstrap presentation generation, marks every pre-wipe target operation non-resumable, moves each fixed payload-dependent receipt into create-only `receipts/history/<prior-payload-epoch>/` with byte/digest verification and synchronized checkpoints, and creates a new payload-epoch generation bound to the wipe operation, both empty-root acknowledgements, all new credential candidate/active version tokens, and the prior epoch. Filesystem activation is crash-recovered through the protected phase journal: commands remain blocked by the incomplete wipe record until every active pointer and archived receipt matches the commit; only then does the controller atomically select the new payload epoch and publish `receipts/wipe.json`. Selection of that epoch is the post-wipe linearization point.

The new epoch makes every prior fs-init, provision, up/container-start, migration/schema, restore/security-barrier, backup-throughput, and dependency-upgrade receipt ineligible. Old records remain immutable historical/audit evidence and return `OPERATION_SUPERSEDED_BY_WIPE` if named; they are never deleted, rewritten, resumed, or adopted. Sealed backups/exports remain verifiable recovery sources, but restoring one requires a new ticket bound to the new epoch and the existing complete authority-reset barrier.

A completed wipe returns exit `0`, state `INITIALIZED`: configuration, instance/data/backup bindings, empty payload root directories, newly active protected credential generations not yet provisioned into a dependency, CA/trust, preparation evidence, backups, and audit remain, while no database, bucket, schema, role/policy receipt, session, bootstrap presentation, or ready barrier exists. `DATA_READY`, `PROVISIONED`, `MIGRATION_REQUIRED`, or `ENVIRONMENT_READY` cannot be reported from pre-wipe evidence.

The supported empty recovery journey is exact: `central local up` recreates/initializes the two payloads under the new epoch and provisions the new credentials, yielding `MIGRATION_REQUIRED`; `central migrate up` installs version zero and fresh security/bootstrap database state; `central serve` reaches readiness; then a separate trusted terminal runs `central bootstrap show`, which rotates and reveals a new three-minute generation. Alternatively, after `local up`, the operator may issue a new-epoch restore plan/apply for one preserved sealed backup instead of `migrate up`; restore verification and any required forward migration complete before `serve`. No step reuses a pre-wipe credential, receipt, operation, session, or presentation generation.

### Container secret handoff

Root-owned protected generations are never mounted directly into a container and secret values never appear in Compose YAML, image metadata, environment variables, command arguments, receipts, or Docker labels. During `local up`, the helper and broker mutually authenticate the exact operation and embedded service policy. The helper supplies a create-only destination descriptor beneath `/run/central-infra/<instance-id>/secrets/`; the broker resolves only the exact active dependency-secret purpose/generation and writes the bounded value directly to that descriptor without exposing its protected root or plaintext to the operator controller. The host must prove `/run` is tmpfs. Each file is `0400`, owned by the locked numeric UID/GID of exactly one consuming service, has a random non-secret filename, and is bind-mounted read-only to one fixed in-container `_FILE` path. A root-owned parent that is not searchable by those host UIDs prevents unrelated host accounts with a coincident numeric UID from reaching the source file.

The mutually embedded helper/broker policy fixes the allowed mapping of secret purpose, service, target path, UID/GID, maximum size, and lifetime. The helper opens the tmpfs destination with no-follow/create-exclusive semantics; the broker verifies the active pointer before and after writing, synchronizes safe HMAC-version evidence, and clears transient buffers best-effort. Docker receives only the resulting file mount; it cannot request another protected binding. Phase 1 must verify every selected image's `_FILE` behavior and fail the dependency lock if an image cannot consume the exact file interface without a root entrypoint.

PostgreSQL initialization and each logical provisioner receive separate service-scoped copies only for their one-shot lifetime; the helper removes each file after the stopped container releases its mount. The PostgreSQL long-running service receives no password after exact initialization proves it unnecessary. MinIO requires its root credential on every start, so its server-scoped copy remains in root-owned tmpfs only while the exact instance container exists and is removed after `local down`. Application runtime, backup, and restore credentials are not mounted into dependency daemons; authenticated host adapters receive only purpose-bound sealed memfds from the broker.

A helper or host crash may leave only root-protected tmpfs material. On the next lifecycle command, the helper correlates each file with its safe generation version token and exact container/mount identity: it reuses nothing, removes it only after proving no matching container uses it, then asks the broker to rematerialize from the still-active protected generation. Ambiguous evidence becomes `cleanup_required` and blocks mutation. Reboot clears tmpfs. Rotation requires dependencies stopped, activates the new protected generation through the offline rotation protocol, and no subsequent `up` may mount an old generation. Receipts contain only purpose class, opaque generation version token, service identity, mode/owner policy, mount identity, and cleanup state.

The installed resource envelope is:

| Service | CPU limit | Memory limit | PID limit |
| --- | ---: | ---: | ---: |
| `postgres` | 1.5 | 2 GiB | 256 |
| `minio` | 1.5 | 2 GiB | 256 |
| each filesystem initializer | 0.25 | 256 MiB | 64 |
| each logical provisioner | 0.5 | 512 MiB | 128 |

One-shot services run sequentially. PostgreSQL uses the following locked settings; config and `SHOW` drift are startup failures:

| PostgreSQL setting | Installed value |
| --- | ---: |
| `shared_buffers` | 512 MiB |
| `work_mem` | 4 MiB |
| `maintenance_work_mem` | 128 MiB |
| `autovacuum_work_mem` | 64 MiB |
| `temp_buffers` | 8 MiB |
| `wal_buffers` | 16 MiB |
| `max_connections` | 32 |
| `superuser_reserved_connections` | 3 |
| `autovacuum_max_workers` | 2 |
| `max_worker_processes` | 4 |
| `max_parallel_workers`, `max_parallel_workers_per_gather`, `max_parallel_maintenance_workers` | 0 |
| `temp_file_limit` | 256 MiB per backend |
| `max_wal_size` / `min_wal_size` | 1 GiB / 256 MiB |
| `jit` / `huge_pages` | `off` / `off` |

Only the fixed application SQL/query-plan inventory may use the target; no caller-supplied SQL exists. The installation permits at most 16 ordinary target sessions and two autovacuum workers in steady state even though 32 server slots leave recovery/admin headroom. Parallel query/maintenance and JIT are disabled, so one statement cannot multiply `work_mem` through parallel workers; multiple sort/hash nodes remain possible and are bounded by reviewed query shapes, row/page limits, statement deadlines, and the Phase 1 worst-plan benchmark. Maintenance/migration and restore are offline and do not overlap serving pools. Phase 1 holds every permitted application session on its maximum reviewed sort/hash query mix while both autovacuum workers and WAL activity run, and proves PostgreSQL remains below 2 GiB without cgroup or kernel OOM; exceeding the envelope blocks the slice rather than widening memory.

PostgreSQL `shm_size` is 768 MiB: 512 MiB shared buffers plus WAL/lock/extension fixed shared allocations and measured headroom. Its additional tmpfs mounts total exactly 80 MiB (`/tmp` 64 MiB and `/run/postgresql` 16 MiB). MinIO receives 64 MiB `/dev/shm`, `/tmp` 256 MiB, and `/home/minio` plus `/run` 16 MiB each. PostgreSQL provision receives 16 MiB application tmpfs plus 8 MiB `/dev/shm`; MinIO provision receives 32 MiB application tmpfs plus 8 MiB `/dev/shm`; each fs-init receives only 8 MiB `/dev/shm`; and one-off wipe receives 8 MiB `/tmp` plus 8 MiB `/dev/shm`. All use `nosuid,nodev,noexec`, and tmpfs usage is charged inside the service memory limit. Host secret-handoff tmpfs is capped at 1 MiB per instance. These container settings do not authorize Central to exceed the stricter installation-wide pool budgets below.

### Reference-host aggregate memory envelope

The 8-GiB reference profile does not rely on swap or optimistic overcommit. The installed Central process calls Go's runtime memory-limit API with 640 MiB and has a 768-MiB RSS acceptance ceiling including stacks, mapped buffers, and embedded assets. The managed browser is cgroup-capped at 512 MiB RSS. A local controller/helper is capped at 256 MiB RSS; one `pg_dump` or `pg_restore` at 512 MiB; and the clean MinIO build at 3 GiB. Exceeding a process ceiling, cgroup/kernel OOM, or sustained host available memory below 512 MiB fails Phase 1; runtime Central crossing 768 MiB for 30 seconds makes readiness false and exits `6` after settlement.

The profiles are mutually exclusive through lifecycle locks and command rules:

| Profile | Bound calculation | Maximum |
| --- | --- | ---: |
| steady `serve` without browser | PostgreSQL 2 GiB + MinIO 2 GiB + Central 768 MiB + kernel/Docker/host reserve 2 GiB | 6.75 GiB |
| browser launch/steady onboarding | PostgreSQL 2 GiB + MinIO 2 GiB + Central 768 MiB + browser 512 MiB + controller/helper 256 MiB + host reserve 2 GiB | 7.5 GiB |
| `local up`/provision | PostgreSQL 2 GiB + MinIO 2 GiB + one 512-MiB provisioner + controller/helper 256 MiB + host reserve 2 GiB | 6.75 GiB |
| backup/restore | PostgreSQL 2 GiB + MinIO 2 GiB + controller 256 MiB + one tool 512 MiB + host reserve 2 GiB | 6.75 GiB |
| clean `prepare` build | dependencies stopped + build 3 GiB + helper 256 MiB + BuildKit/Docker fixed allowance 1 GiB + host reserve 2 GiB | 6.25 GiB |

Filesystem initializers run before their daemon and never overlap a provisioner. `prepare` requires `local down` and no target operation; it never overlaps `serve`, dependency containers, backup, or restore. The fixed 2-GiB host reserve covers the kernel, Docker daemon outside build, filesystem cache, SSH/shell, and measurement error; at least 512 MiB remains additional headroom in every profile. Phase 1 runs each profile for a sustained interval at its admitted HTTP/pool/transfer workload, records cgroup/process RSS, tmpfs use, Docker/host memory, reclaim/pressure/OOM counters, and proves graceful rejection/exit rather than host or container OOM.

## Listener, network, and local trust boundary

The fixed default endpoints are:

| Endpoint | Bind |
| --- | --- |
| Central application | `https://127.0.0.1:8080` |
| Central operations | `127.0.0.1:9090` |
| PostgreSQL host publication | `127.0.0.1:55432` |
| MinIO S3 API host publication | `127.0.0.1:59000` |
| MinIO console | not published |

Configuration and generated Compose output use numeric addresses, not `localhost`. The application has no plaintext or IPv6 listener and performs no HTTP-to-HTTPS redirect. Central never silently chooses another port. Host port probes before the helper accepted point are best-effort diagnostics, not reservations; a detected existing conflict is exit `4`/`PORT_IN_USE` with no mutation. Docker's bind result is authoritative. A bind outside loopback, wildcard host, application origin other than the exact canonical HTTPS origin, trusted proxy, forwarded-address trust, wildcard CORS, or published MinIO console is invalid in `central.config/v1`.

The accepted Phase 1 boundary trusts the kernel and root-owned installed release authority, but possession of the ordinary operator UID alone is not secret or destructive authority. Infrastructure control separately trusts the installed root-owned helper, PAM ceremony, broker, their root-owned policy/executable chains, and the fixed local Docker daemon. Docker control is root-equivalent but is not granted to the ordinary operator account. The repository working tree, caller environment, Workspace content, agent-produced files, browser input, same-operator-UID generic processes, and unrelated local processes are untrusted for infrastructure, protected-value, TLS-signing, or destructive authority unless an explicit root trust transition promotes reviewed release content. Central does not claim protection from root, a compromised kernel/helper/broker/Docker daemon, or compromise of the locked `central-runtime` process after an authorized secret has entered its bounded adapter memory.

The application listener requires TLS 1.3 and an active instance-bound certificate before binding. Its certificate has server-auth EKU, the sole SAN IP `127.0.0.1`, no DNS SAN or wildcard, and a protected private key unavailable to Docker and the infrastructure helper. The exact Host is `127.0.0.1:8080`, the exact Origin is `https://127.0.0.1:8080`, cookies are `Secure`, and no CORS origin is accepted. Certificate, binding, trust receipt, expiry, and private-key permission drift fail startup before token or session handling.

`local init` asks the protected broker to create a per-instance local CA and leaf certificate from the operating-system cryptographic random source. The CA certificate is constrained to `127.0.0.1/32`; its signing key and the leaf private key are separate root-owned protected generations and are never resolved as plaintext by `central serve`. TLS handshakes use the broker's leaf-only signing operation. The CA public certificate includes the instance identity and public integrity token but no sensitive path. `central local trust install` is a distinct explicit administrative trust transition: the controller validates the instance/binding/token, and the helper independently validates the CA constraints before installing only that public certificate into both the Ubuntu system trust store and the manifest-selected browser NSS store and recording correlated receipts. Bypassing a certificate warning or using another browser profile is unsupported. `trust remove` requires fresh PAM plus the exact instance/token confirmation, removes no other anchor, and never deletes private state.

Leaf rotation is an offline lifecycle-exclusive operation: stage and sign a new leaf under the active CA, validate key/certificate/instance linkage and validity, atomically activate it, and retain exact repair evidence. CA rotation stages a new CA and leaf, installs the new public anchor before activation, verifies the trust receipt, atomically activates both, and only then allows explicit removal of the old anchor. No expired, not-yet-valid, revoked, mismatched, fallback, caller-supplied, or automatically regenerated certificate is served. The safe configuration/receipt digest binds certificate and CA fingerprints, never private-key bytes.

Plaintext PostgreSQL and S3 remain accepted only on numeric loopback and still require SCRAM-SHA-256 and signed S3 requests. The plaintext operational listener has no browser application, bootstrap, session, CSRF, administration, or secret-bearing route. Any future non-loopback listener requires a new reviewed TLS/proxy topology. Gate 8 defines no proxy.

The operational listener exposes only the inherited routes:

```text
GET /health/live
GET /health/ready
GET /metrics
```

`/health/live` is dependency-independent. `/health/ready` is generic and profile-aware. `/metrics` uses the custom registry and no Workspace, Task, Run, Artifact, operation, or instance identity as a label. There is no default debug, configuration-dump, profiling, tracing-exporter, or administration endpoint.

## Canonical instance filesystem

### Layout

For instance UUIDv7 `<instance-id>`, XDG contains only non-authoritative operator views while all mutable authority lives below root-owned parents:

```text
$XDG_CONFIG_HOME/central/instances/<instance-id>/
├── central.json                         # safe selection view, not authority
└── central.json.sig                     # broker Ed25519 signature binding view bytes to authority ID

$XDG_STATE_HOME/central/instances/<instance-id>/
├── generated/
│   ├── compose.override.yaml
│   └── compose.digest
└── views/<view-generation>.{json,sig}   # broker-signed sanitized snapshots only

/var/lib/central-state/v1/instances/<instance-id>/
├── config.json
├── binding.json
├── authority-records/<stream-id>/<sequence>-<transition-id>.{payload,auth}.json
├── lifecycle.lock
├── runtime.lock
├── init-bootstrap.json
├── operations/
│   ├── target.json
│   ├── migration/<operation-id>.json
│   ├── backup/<operation-id>.json
│   ├── restore/<operation-id>.json
│   ├── wipe/<operation-id>.json
│   ├── dependency-upgrade/<operation-id>.json
│   └── maintenance/<operation-id>.json
├── payload-epochs/{active.json,generations/<payload-epoch-id>.json}
├── receipts/{history/<payload-epoch-id>/,prepare.json,trust.json,wipe.json,postgres-fs-init.json,minio-fs-init.json,postgres-provision.json,minio-provision.json}
├── audit/<audit-sequence>.json
├── data/{binding.json,postgres/,minio/}
└── backups/
    ├── binding.json
    ├── backup-repository.lock
    ├── repository-manifest.json
    ├── imports/<operation-id>.json
    ├── exports/<operation-id>.json
    ├── maintenance/<plan-id>.json
    └── backups/<backup-id>/
        ├── binding.json
        ├── database/central.dump
        ├── inventory/<chunk-ordinal>.json
        ├── bodies/sha256/<first-two-hex>/<remaining-hex>
        ├── root-manifest.json
        └── root-manifest.auth.json

/var/lib/central-protected/v1/instances/<instance-id>/
├── binding.json
├── fingerprint-keys/<key-version>.key
├── authority/
│   ├── keys/<key-version>.key
│   ├── view-signing/<key-id>.{key,pub}
│   └── journals/<stream-id>/<sequence>/<transition-id>/{prepared,issued,committed}.json
├── secrets/<binding-id>/
│   ├── binding.json
│   ├── binding.lock
│   ├── active.json
│   ├── candidates/<candidate-id>/<phase>.json
│   └── generations/<opaque-generation>.{meta.json,value}
├── bootstrap/
│   ├── binding.json
│   ├── binding.lock
│   ├── active.json
│   ├── presentation.json
│   ├── candidates/<candidate-id>/<phase>.json
│   └── generations/<opaque-generation>.{meta.json,value}
└── tls/
    ├── binding.json
    ├── binding.lock
    ├── active.json
    ├── candidates/<candidate-id>/<phase>.json
    ├── ca/<opaque-generation>.{cert,key}
    └── leaf/<opaque-generation>.{cert,key}

/var/lib/central-rescue/v1/instances/<instance-id>/<rescue-operation-id>/
├── binding.json
├── cleanup.json
├── postgres/
└── minio/

$XDG_DATA_HOME/central/instances/<instance-id>/
└── views/<view-generation>.{json,sig}   # optional rebuildable safe inventory only
```

Every generic authoritative transition is stored under the immutable sequence-specific `authority-records` path shown above; the tree's fixed names such as `config.json`, `active.json`, receipt names, and operation names are replaceable materialized projections only. Each projection has an elided `<name>.projection-auth.json` containing the exact committed stream/sequence/payload/envelope digests. A projection is never read as authority unless both files equal the broker journal's current committed stream head, and it can always be reconstructed from that head; a crash between their replacements merely leaves a stale projection. The backup seal is the explicit exception because a backup ID has one final root manifest and exact companion. Lock files and immutable content bodies/chunks are not transition payloads; their identities are covered by the authoritative record that publishes or seals them.

When XDG variables are absent, the view fallbacks are `~/.config`, `~/.local/state`, and `~/.local/share`. Expansion happens once during selection. `central.json` remains the complete strict schema but is a readable copy; its adjacent `central.view-signature/v1` Ed25519 signature binds exact bytes, config binding ID, authoritative config digest, instance ID, view generation, signing-key ID, and creation time. Snapshot readers verify it with the root-installed public key and report its age without contacting privileged services. A mutating helper additionally resolves that binding to `/var/lib/central-state/v1/instances/<instance-id>/config.json`, asks the broker to verify the signed binding, and then requires byte equality with authoritative config before use. Changed/deleted/forged view or signature is `CONFIG_INVALID`; no command adopts view bytes as authority.

The authoritative backup repository is a sibling of `data/` beneath the non-operator-searchable root parent. `local down` and `local wipe` cannot reach it through recursive deletion of dependency data. No authoritative root may be beneath a Workspace, XDG view, another instance root, or export destination. `backup-repository.lock` is create-only and never removed; repository readers hold it shared and every mutation holds it exclusive for the complete operation.

`/var/lib/central-rescue/v1` and its instance parents are root-owned `0700`, outside XDG, Workspace, export, authoritative payload, backup, and protected roots. Each operation root is create-only, descriptor/binding/operation/mount/handle/capacity/audit-bound, non-searchable by operator/runtime/agent/browser UIDs, and reachable only by the helper. Its `postgres/` and `minio/` descendants preserve the exact locked service ownership/modes and are exposed to Docker only through helper-held descriptors; no service receives the parent or sibling descriptor. `binding.json` contains no raw source path or secret and is authenticated by the rescue operation authority. These roots are temporary recovery scratch, never backup/restore authority or a source adopted by ordinary startup.

### Bindings and permissions

Each root has a versioned binding containing purpose, instance ID, creation nonce, canonical device/inode evidence, and a digest of the safe immutable fields. The configuration, state, data, and backup bindings are distinct and cross-reference only opaque binding IDs. A binding never contains a credential, raw Workspace path in a safe digest, or backend secret locator.

`payload-epochs/active.json` selects one create-only UUIDv7 generation. Every fs-init, provision, successful-up, migration/schema, restore/security-barrier, backup-throughput, dependency-upgrade, and target-mutating operation/receipt binds that exact payload epoch. Trust, TLS, prerequisite, dependency preparation, signed advisory, sealed-backup content, export/import lineage, and operator audit do not become invalid merely because payload was wiped. An epoch mismatch is never repairable by copying or editing a receipt; it is historical evidence only.

The XDG view roots belong to the operator UID but contain no authoritative mutable evidence; view directories are `0700` and files `0600`. `/var/lib/central-state/v1` belongs to root and is `0700`; each instance directory and its configuration, operations, receipts, audit, and backup repository belong to locked `central-runtime` with directories `0700` and create-only files `0600`, but the operator and `central-agent` cannot traverse the root parent. The helper passes the authenticated runtime only the exact already-open instance/state/lock/repository descriptors required by its mode; no pathname or parent descriptor reaches the controller. PostgreSQL and MinIO payload subdirectories belong to their locked container UID/GID and are reachable by Docker only through helper-held bind descriptors. `/var/lib/central-protected/v1` and descendants belong to root with the modes above; neither operator, `central-runtime`, `central-agent`, nor `central-browser` receives search permission or a root descriptor. The broker alone mutates protected journals and performs MAC/signing/value use. Same-operator-UID direct unlink, rename, truncate, backup rewrite, audit deletion, or config replacement therefore either cannot reach authority or changes only a disposable view.

Ownership by `central-runtime` is not sufficient authority by itself. Every accepted configuration, operation, receipt, payload-epoch, repository-root-manifest, and audit transition is an immutable sequence-specific payload plus `central.authority-transition/v1` envelope under `authority-records/<stream-id>/`. The envelope contains transition/stream IDs, monotonic sequence, canonical payload digest and byte count, prior committed envelope digest, instance, authenticated launch ID, closed protocol phase, one-use nonce, broker key version, and domain-separated HMAC. The runtime may propose bytes through a bounded descriptor but cannot create a valid envelope.

Authority commit is one exact crash-safe protocol. Under the stream lock the runtime writes and synchronizes a transition-owned create-exclusive candidate and holds its immutable read-only descriptor. The broker rereads it, validates the previous committed journal record and command state machine, then create-exclusively writes and synchronizes `prepared.json` containing the exact canonical payload bytes as base64url (bounded by class below) and descriptor evidence. It next writes `issued.json` containing the exact envelope and synchronizes the transition directory. From those broker-stored bytes, payload and envelope are each written completely to create-exclusive staging files, synchronized, and atomically installed at the unique final names `<sequence>-<transition-id>.payload.json` and `<sequence>-<transition-id>.auth.json` with `renameat2(RENAME_NOREPLACE)`; each parent is synchronized before the next install. A final-name collision is accepted only when a no-follow complete reread exactly matches the issued digest/bytes, otherwise it is `PROTECTED_STATE_INVALID` and is never unlinked or replaced. Finally the broker reopens both immutable files through the authoritative root, verifies byte equality/HMAC, and writes `committed.json`; that append-only committed record is the stream head, so no fixed mutable filename is authority. Only after `committed.json` is synchronized may the semantic transition be observed as accepted.

Recovery scans only the next sequence after the last committed record. `prepared` without `issued` deterministically issues the stored bytes; `issued` removes/recreates only its own uninstalled staging files and atomically installs the identical broker-stored payload/envelope when its unique final name is absent; exact final publication without `committed` is reverified and committed. A truncated or different immutable collision is terminal invalid evidence, never “repaired.” Different bytes, another transition ID/nonce, an already consumed sequence, or a gap is `PROTECTED_STATE_INVALID`; reissue never creates a second envelope. After commit, a fixed materialized projection may be atomically replaced from the current committed payload and envelope; crash, mismatch, or same-UID rewrite makes only the projection stale and readers reconstruct or fail closed against the journal head. Genesis is bound to the synchronized root init intent and installed broker/view-signing identities. Key rotation is itself a committed transition authenticated by both old and new keys; the old key remains verification-only until every referenced stream has crossed the rotation record. Journal retention follows protected maintenance only after a compacted checkpoint preserves every live stream head and key reference.

Authority payload limits are 1 MiB for config, 256 KiB for operation/receipt, 64 KiB for payload-epoch/binding, 8 KiB for audit, and 16 MiB only for repository root/checkpoint manifests; envelopes and each phase record are at most 16 KiB excluding the prepared payload copy. A live stream tail is at most 64 committed transitions or 32 MiB, whichever comes first. At 48 transitions or 24 MiB the broker automatically creates a crash-safe `central.authority-checkpoint/v1` transition binding the prior checkpoint, ordered committed-envelope Merkle root, current stream head, retained key set, counts, and bytes. It follows the same prepared/issued/committed protocol; only after commit are older journal directories maintenance-eligible. Verification reads one checkpoint plus at most the bounded tail, never full history.

Across an instance, uncheckpointed journals are limited to 8,192 transitions/512 MiB and the complete broker authority store to 2 GiB, with a separately preallocated 64 MiB settlement reserve. At 75% of either hard ceiling, new non-settlement mutations return `MAINTENANCE_REQUIRED`; current transition settlement, checkpointing, verify/status, export, security update, and down remain possible from the reserve. Protected maintenance reclaims only checkpoint-covered, unreferenced old journal directories in bounded 8-MiB/1,000-entry quanta inside its existing two-hour deadline. Crash recovery either retains the old verified checkpoint/tail or commits the unique new checkpoint; it never advances a head by deletion. Exhausting the settlement reserve is `CLEANUP_REQUIRED` and blocks new accepted mutation without discarding the last committed head.

Backup sealing additionally requires the live accepted backup operation, target-exclusive lock proof, current payload epoch, completed database/object checkpoints, and the exact repository descriptor; an arbitrary runtime-created tree is never sealable. Its companion is exactly `root-manifest.auth.json`, schema `central.backup-seal/v1`, containing the authority-envelope identity, domain/key version, root-manifest digest, ordered file-tree digest, operation/target/config/payload-epoch IDs, and broker HMAC. The generic publication/commit ordering applies; a backup is neither sealed nor restorable before the broker journal's committed record. A missing, replayed, reordered, or runtime-only rewritten transition is `PROTECTED_STATE_INVALID`. This protects authority from an operator-UID process and limits a compromised runtime to the separately declared post-authorization trust boundary; it does not claim to make an already-authorized compromised Central runtime safe.

Every path component is opened with no-follow semantics and revalidated after open. Symlinks, unexpected hard links, ownership drift, mode drift, mount/device replacement, inode replacement of a held lock, or path escape fail closed. Protected and authoritative state requires atomic same-filesystem temp creation, file synchronization, rename, and parent-directory synchronization. Sanitized XDG receipt views use canonical JSON plus a broker Ed25519 signature; authoritative receipts use the chained broker-HMAC transition contract above. Protected-value fingerprints use the separate broker HMAC contract below and are never raw secret digests.

On the supported Linux profile, “no-follow” means `openat2(2)`, not a lexical clean followed by `stat`. Selection opens `/` as `O_PATH|O_DIRECTORY|O_CLOEXEC`, resolves each configured root component with `RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`, and records `statx` device, inode, mode, owner, link count, and `STATX_MNT_ID`. After a root descriptor is held, every descendant access uses `openat2` relative to it with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`; mutations use descriptor-relative `mkdirat`, create-exclusive open, `renameat2`, and `unlinkat`, never a reconstructed absolute path.

The helper parses a single held `/proc/self/mountinfo` snapshot, rejects any nested mount below a payload/destructive root, and rejects FUSE, overlay, network, idmapped, shared-propagation, or unrecognized mount types/options for protected/payload state. It compares mount IDs plus `name_to_handle_at` filesystem handles and descriptor-relative ancestor walks across every config/state/data/backup/Workspace root. Equal handles, ancestor/descendant handles, a bind alias, roots visible through different mount namespaces, or a filesystem that cannot supply stable handles is outside the supported profile. Phase 1 proves the reference ext4 profile; another filesystem requires equivalent evidence rather than a fallback to device/inode alone.

Before Docker mutation the helper reopens from the binding descriptor, compares the complete `statx`/handle/mountinfo evidence, and keeps every source `O_PATH` descriptor open until Docker has created the bind and the exact container-side initializer/daemon reports its root device/inode/type. The authoritative Compose model uses `/proc/<helper-pid>/fd/<fixed-fd>` as the transient bind source, not the user pathname, so replacement of a pathname after validation cannot redirect Docker. The fixed local root Docker daemon is the only reader allowed to resolve that proc descriptor; helper lifetime covers create/start/inspect and the descriptor is closed only after matching mount receipt. If Docker cannot bind through the descriptor on the locked engine, the operation fails before payload mutation; raw-path fallback is forbidden.

Filesystem initializers receive expected opaque binding identity and host device/inode/type as fixed arguments, revalidate the mounted root before their first write and after ownership/mode changes, and write one bounded acknowledgement that the helper compares to its held descriptor evidence. Wipe uses the same held-descriptor bind in the exact digest-locked no-network `central-local-infra` one-off mode and revalidates again immediately before deletion. A mount/path/namespace change at any host-open, Docker-resolve, container-check, or post-action boundary is `DRIFTED`; topology rollback may remove only exact newly created resources and never follows the changed path, while an accepted wipe uses only exact resume and never pretends deleted payload bytes were rolled back.

The generated Compose override contains exact absolute mount paths, so it is a broker-signed, operator-readable diagnostic view rather than protected or authoritative state. Its safe digest substitutes opaque binding IDs for raw paths and excludes all secret values. Re-generation is deterministic from the authoritative config, dependency lock, and binding evidence. Changed or missing diagnostic bytes invalidate only that view; the helper never executes or adopts it and independently renders the embedded authoritative model.

### Instance selection

Every instance-bound command accepts:

```text
central --config <absolute-path-to-central.json> ...
```

`--config` selects an existing document; it does not override any field and never names a prospective file. If omitted, Central discovers an instance only when exactly one valid config exists beneath the XDG config root. Zero matches is `CONFIG_NOT_FOUND`; two or more is `CONFIG_AMBIGUOUS`. There is no mutable global active-instance pointer.

Exactly two configless command families exist. `central local doctor --host-prerequisites` is read-only and instance-independent. The init family is limited to `central local init`, `central local init --status`, `central local init --resume=<init-operation-id>`, and `central local init --abandon=<init-operation-id>`; every form rejects `--config`, and every other configless invocation is invalid. Create generates the instance/config-binding/init-operation UUIDv7 values, create-exclusively reserves `$XDG_CONFIG_HOME/central/instances/<instance-id>/central.json`, and never adopts a pre-existing path. A collision or partial unrelated tree fails closed. Status discovers only bounded caller-bound incomplete intent; resume may complete only the exact journaled reservation; abandon may remove only the exact pre-accepted empty reservation under the protocol below.

Successful `local init` prints the absolute config path only on the trusted local TTY plane. Its `central.local-result/v1` machine `details` variant returns only `instance_id`, `config_binding_id`, and `init_operation_id`; automation derives or discovers the path locally and no generic plane emits it. Every subsequent normative command uses the exact TTY-returned `--config` path. Destructive commands still require exact operation/target confirmation even when config selection is explicit.

### Diagnostic output planes and remediation catalog

Central has exactly two diagnostic planes:

1. **Machine/generic:** JSON stdout, redirected stdout/stderr, structured logs, audit, HTTP health/metrics, test artifacts, and helper receipts. This plane contains no raw path/filename and follows the bounded schemas and redaction rules below.
2. **Trusted local TTY:** human output is enabled only when stdin, stdout, and stderr are terminals owned by the invoking operator UID, the command is not using JSON output, and selected config/root descriptors have been reopened and revalidated. It may show only the canonical config file, instance config/state/data root, backup repository, generated diagnostic Compose file, and an explicitly selected export/import path owned by that UID. Secret-generation/private-key paths, backend locators, object keys/body paths, database/MinIO payload descendants, root helper/audit internals, tmpfs secret paths, and arbitrary dependency error paths remain prohibited.

TTY paths are never interpolated from an error. Central derives them from held descriptors/bindings, rejects control/bidi/non-NFC bytes, renders a bounded JSON-escaped display value, and renders copyable commands with a fixed POSIX single-quote encoder. If descriptor ownership/identity cannot be proven or any terminal condition fails, output automatically uses the machine plane. A caller flag cannot promote output to trusted TTY.

Phase 1 creates and embeds a canonical catalog with schema/version `central.local-remediation/v1`. Every `central.local-result/v1` reason code has exactly one entry containing: stable entry ID and explanation; permitted command/environment/mutation phases; whether prior mutation occurred; retry/resume rules; required operation ID; exact allowlisted next-command template; TTY-only path classes needed to render it; consecutive-failure threshold and elapsed window for manual inspection; and the condition that resets its failure counter. Unknown/missing/duplicate entries or a result inconsistent with its entry fail conformance.

The installed thresholds are:

| Result class | Exact automated/operator guidance before manual inspection |
| --- | --- |
| exit `0` diagnostic state | one exact next command where applicable; no failure counter |
| exit `2` | correct the named invocation/config catalog field; after three consecutive results with the same safe failure fingerprint and unchanged config digest within 30 minutes, `inspect_manual` |
| exit `3` | perform the exact prerequisite command once; after three identical post-remediation failures or 30 minutes from the first, whichever occurs first, `inspect_manual` |
| exit `4` | at most three same-input retries with installed backoff inside 15 minutes; then `inspect_manual` |
| exit `5` or `7` | run the catalog's single non-mutating `local doctor`/status/explain command; if the same fingerprint remains, manual inspection is immediate and mutation retry is forbidden |
| exit `6`/`RESUME_REQUIRED` | only the exact operation resume command; after three failed resumes or the operation deadline, manual inspection; `MUTATION_INDETERMINATE` and `ROLLBACK_FAILED` are immediate manual inspection |

A failure fingerprint is a safe digest of reason code, instance/config/payload-epoch/authority identities, mutation phase, and bounded mismatch class—never raw detail. Counters come from protected operator audit, reset only after success or a catalog-declared relevant identity change, and never authorize a mutation. Crossing a threshold changes `safe_next_action.kind` to `inspect_manual`; it does not reveal additional detail or suggest force/permission weakening.

`central local explain --reason=<reason-code>` is read-only. Machine output returns only catalog version/entry ID, bounded explanation code, mutation/retry/resume semantics, threshold, and safe command template with `<absolute-config-path>` as a literal placeholder. Trusted TTY resolves that placeholder only from the validated selected config descriptor and may print the exact escaped command. `local status` and `local doctor` use the same catalog rather than inventing prose.

## Immutable startup configuration

### Source and parsing

The only general startup source is one UTF-8 JSON document with top-level `schema_version` equal to `central.config/v1`. Duplicate keys, unknown keys, invalid Unicode, comments, trailing content, noncanonical UUIDv7, unresolved or relative paths, out-of-range values, and cross-field budget violations fail before adapters or listeners are constructed.

There is no `.env` file, environment-variable interpolation, per-field environment lookup, CLI topology override, implicit secret fallback, hot reload, or mutable global configuration. Environment variables are consulted only for XDG discovery before a config is selected. Secret values live behind protected binding IDs and are resolved just in time by the owning adapter.

### Required field inventory

`central.config/v1` contains these required sections:

| Section | Required fields |
| --- | --- |
| identity | `schema_version`, `instance_id` |
| paths | `authoritative_state_root`, `instance_data_root`, `backup_repository_root`, `workspace_roots[] {root_id,path}` |
| HTTP | fixed application HTTPS/ops HTTP numeric binds and ports; TLS binding ID and exact CA/leaf fingerprints; admission, buffer, header, idle, route, and graceful-shutdown values |
| PostgreSQL | numeric host, port, database, schema, binding IDs for server admin/runtime/outbox/migration, pool maxima, acquisition/statement/lock deadlines |
| object store | `http` scheme, numeric host, port, bucket, region, path-style mode, root/runtime/backup/restore binding IDs |
| protected store | backend `protected_file_v1`, binding-root ID, maximum secret bytes, resolution deadline, candidate cleanup age |
| bootstrap/session | bootstrap binding ID, 256-bit token requirement, throttle values, one-minute first-use deadline, 30-minute idle and 12-hour absolute session expiry |
| Artifact | active/waiter counts, wait deadline, buffer, idle and total stream deadlines |
| operator modes | target/migration locks; prepare, backup, restore, export, import, maintenance, browser-clear, and security-rescue elapsed deadlines; browser profile/cache quotas; restore-ticket lifetime; inventory bounds and work-slice values |
| tools | absolute `pg_dump` and `pg_restore` paths plus expected version |
| runtime | preflight budget/page, dependency retry budget, total shutdown and settlement deadlines, enabled component set |
| observability | fixed JSON logging level and fixed custom metric registry selection |

The application origin is derived as exactly `https://127.0.0.1:8080` from the fixed numeric application listener and is not separately widened. Fixed TLS version/origin, database/schema/bucket/role/service names, and security invariants are not knobs.

### Installed Gate 7 resource values

The all-in-one profile installs the Gate 7 defaults:

| Resource | Installed value |
| --- | ---: |
| Artifact active transfers | 2 |
| Artifact waiters | 8 |
| Artifact admission wait | 5 s |
| Artifact copy buffer | 256 KiB |
| Artifact stream idle / total | 30 s / 30 min |
| Non-streaming HTTP active / waiters | 16 / 32 |
| Non-streaming admission wait | 2 s |
| JSON / HTML response buffer | 2 MiB / 1 MiB |
| Aggregate response buffers | 32 MiB |
| HTTP header bytes / one value | 32 KiB / 4 KiB |
| Header-read / idle timeout | 5 s / 60 s |
| Runtime-general pool | 6 |
| Runtime-settlement pool | 2, never borrowable |
| Outbox pool | 3 |
| Cleanup pool | 1 |
| Serving shared-lock control | 1 |
| Coexisting read-only operator connections | 2 |
| Offline mutation connections | 2 |
| Pool acquisition | 2 s |
| Ordinary preflight | 5 s, page 100 |
| Inventory workers / spool | 1 / 8 MiB |
| Inventory chunk / encoded record | 1,000 / 4 KiB |
| Inventory work slice | 100 pages or 5 min |
| Settlement grace / total shutdown | 30 s / 45 s |

The serving pools total 12 data connections plus one lifetime shared-lock control connection. With two permitted coexisting read-only operator connections, the topology remains within the default installation-wide target cap of 16. Mutation modes are offline and receive one shared allocation of exactly two connections; they do not coexist with serving data pools where Gate 7 requires target-exclusive ownership. Cross-field validation rejects any topology above Gate 7 defaults/hard caps or one that lets a non-settlement component acquire either settlement connection.

The two offline permits are installation-wide across the controller and every child process, not two pgx connections plus tool sessions. The coordinator acquires a permit before opening a pgx connection or spawning a PostgreSQL tool, passes one fixed safe `application_name`, and releases it only after the connection/process and inherited descriptors are closed. No phase overlaps two rows below, no `pg_dump`/`pg_restore` parallel job is permitted, and object-store work opens no PostgreSQL session.

| Offline phase | Lock/control permit | Data/tool permit | Exact maximum |
| --- | ---: | ---: | ---: |
| migration up/resume | one non-rebinding session owns target/migration locks and DDL | none | 1 |
| backup accepted point and dump | one lifetime target-exclusive control | one `pg_dump` session | 2 |
| backup inventory/seal or target-reading verify | one lifetime/shared target control | one read-only inventory/verification session | 2 |
| backup throughput probe create/load, dump, drop | one lifetime target-exclusive control | exactly one provisioner session or one `pg_dump` session, sequentially | 2 |
| restore verify/ticket | one shared target control | one read-only verification session | 2 |
| restore database replacement | one lifetime target-exclusive control | one `pg_restore` session | 2 |
| restore full verification/quarantine/reset | one lifetime target-exclusive control | one `central_runtime` verification/reset session | 2 |
| non-target backup/restore status | none | at most one protected-state reader, no PostgreSQL | 0 |

Dump and inventory are sequential. Throughput-probe create/load closes its provisioner session before `pg_dump`; dump is reaped before the provisioner reopens for drop; cleanup retains the shared allocation until the disposable database, tool, descriptors, and both sessions are proven gone. Restore tool and post-restore verification are sequential. Quarantine processing reuses the single verification session or closes it before another opens. Tool subprocesses must connect exactly once; an observed second tool/backend session is terminal `INCOMPATIBLE`. Phase 1 samples `pg_stat_activity` by safe application-name class during normal, timeout, cancellation, process-loss, probe cleanup, and resume paths and proves total target sessions never exceed the declared phase maximum or installation cap.

### Normative `central.config/v1` schema

The tables below are the complete Gate 8 schema, not an illustrative inventory. Every listed object and field is required; no other field, `null`, floating-point number, or omitted object is accepted. `uint` means a JSON integer in `[0, 2^53-1]`; durations use integer milliseconds and sizes use integer bytes. `uuid7` is canonical lowercase RFC 9562 UUIDv7; `binding` is an opaque canonical UUIDv7; `sha256` is 64 lowercase hexadecimal characters; `abspath` is an NFC-normalized absolute path with no `.`/`..`/symlink resolution ambiguity. Arrays preserve order only where stated and contain no duplicate identity. “Fixed” means any other value is invalid, including a value otherwise inside the scalar type.

| JSON path | Type | Installed value / exact constraint |
| --- | --- | --- |
| `schema_version` | string | fixed `central.config/v1` |
| `instance_id` | uuid7 | generated once; must match all bindings |
| `paths.authoritative_state_root` | abspath | fixed root-parented instance authority; root parent, locked-runtime instance owner |
| `paths.instance_data_root` | abspath | fixed `data/` descendant of authoritative state; descriptor-bound only |
| `paths.backup_repository_root` | abspath | fixed `backups/` sibling of data; descriptor-bound only |
| `paths.workspace_roots` | array | 0–32 entries, sorted by `root_id` |
| `paths.workspace_roots[].root_id` | uuid7 | unique opaque identity |
| `paths.workspace_roots[].path` | abspath | unique, non-overlapping governed Workspace root |

| JSON path | Type | Installed value | Hard constraint |
| --- | --- | ---: | --- |
| `http.application.host` | string | `127.0.0.1` | fixed |
| `http.application.port` | uint | `8080` | 1024–65535; tests may allocate another exact port |
| `http.operations.host` | string | `127.0.0.1` | fixed |
| `http.operations.port` | uint | `9090` | 1024–65535 and distinct from every other host port |
| `http.tls.binding_id` | binding | generated | purpose must be `application_tls_v1` |
| `http.tls.ca_fingerprint_sha256` | sha256 | generated | exact active CA generation |
| `http.tls.leaf_fingerprint_sha256` | sha256 | generated | exact active leaf generation |
| `http.non_streaming.active` | uint | `16` | 1–32 |
| `http.non_streaming.waiters` | uint | `32` | 0–64 |
| `http.non_streaming.admission_wait_ms` | uint | `2000` | 1–5000 and no later than route deadline |
| `http.non_streaming.api_buffer_bytes` | uint | `2097152` | fixed inherited maximum |
| `http.non_streaming.html_buffer_bytes` | uint | `1048576` | 1–2097152 |
| `http.non_streaming.body_read_ms` | uint | `30000` | 1000–120000 |
| `http.non_streaming.response_write_ms` | uint | `30000` | 1000–120000 |
| `http.non_streaming.route_total_ms` | uint | `65000` | 1000–120000 and at least admission + body-read + response-write |
| `http.max_header_bytes` | uint | `32768` | 4096–65536 |
| `http.max_header_value_bytes` | uint | `4096` | fixed inherited maximum; not above aggregate header bytes |
| `http.read_header_ms` | uint | `5000` | 1000–10000 |
| `http.idle_ms` | uint | `60000` | 1000–120000 |
| `http.graceful_shutdown_ms` | uint | `45000` | 30000–180000 and equals runtime total shutdown |

| JSON path | Type | Installed value / exact constraint |
| --- | --- | --- |
| `postgres.host` / `postgres.port` | string / uint | fixed `127.0.0.1` / installed `55432`, port 1024–65535 and globally distinct |
| `postgres.database` / `postgres.schema` | string | fixed `central` / `central` |
| `postgres.bindings.server_admin` | binding | purpose `postgres_server_admin_v1` |
| `postgres.bindings.runtime` | binding | purpose `postgres_runtime_v1` |
| `postgres.bindings.outbox` | binding | purpose `postgres_outbox_v1` |
| `postgres.bindings.migration` | binding | purpose `postgres_migration_v1` |
| `postgres.pools.runtime_general` | uint | installed `6`, range 1–8 |
| `postgres.pools.runtime_settlement` | uint | fixed `2` and never borrowable |
| `postgres.pools.outbox` | uint | installed `3`, range 1–4 |
| `postgres.pools.cleanup` | uint | installed `1`, range 1–2 |
| `postgres.pools.serve_lock_control` | uint | fixed `1` |
| `postgres.pools.coexisting_read_only` | uint | installed `2`, range 0–4 |
| `postgres.pools.offline_mutation` | uint | fixed `2`; every tool session consumes one permit |
| `postgres.timeouts.pool_acquire_ms` | uint | installed `2000`, range 1–5000 |
| `postgres.timeouts.statement_ms` | uint | installed `30000`, range 1000–120000 |
| `postgres.timeouts.lock_ms` | uint | installed `5000`, range 100–30000 and not above statement timeout |
| `postgres.timeouts.transaction_ms` | uint | installed `30000`, range 1000–120000 and not below statement timeout |
| `postgres.timeouts.idle_in_transaction_ms` | uint | installed `30000`, range 1000–60000 |
| `postgres.timeouts.connection_lifetime_ms` | uint | installed `1800000`, range 60000–3600000 |

| JSON path | Type | Installed value / exact constraint |
| --- | --- | --- |
| `object_store.scheme` / `object_store.host` / `object_store.port` | string/string/uint | fixed `http` / `127.0.0.1` / installed `59000`, port 1024–65535 and globally distinct |
| `object_store.bucket` / `object_store.region` / `object_store.path_style` | string/string/boolean | fixed `central-artifacts-v1` / `us-east-1` / `true` |
| `object_store.bindings.root` | binding | purpose `minio_root_v1` |
| `object_store.bindings.runtime` | binding | purpose `minio_runtime_v1` |
| `object_store.bindings.backup` | binding | purpose `minio_backup_v1` |
| `object_store.bindings.restore` | binding | purpose `minio_restore_v1` |
| `object_store.policy_digests.runtime` | sha256 | fixed `b4613cce4c0fe3e7b23cc7212d578919169cb1d64aab9c5b73fc544cf759d72f` |
| `object_store.policy_digests.backup` | sha256 | fixed `aa5f63fdf5b13e4bc2effd1a972a7c2ed6771faee3b56bc2fca7d822ad7d38b1` (SHA-256 of the generated canonical `minio_backup_v1` policy) |
| `object_store.policy_digests.restore` | sha256 | fixed `b742ea7085d0e80e88a1fb835ffa934e7ad7ac398f2d1426efe04d2ea48a0e48` |
| `protected_store.backend` | string | fixed `protected_file_v1` |
| `protected_store.binding_root_id` | binding | exact protected-state binding |
| `protected_store.max_secret_bytes` | uint | fixed `65536` |
| `protected_store.resolve_ms` | uint | installed `5000`, range 1–10000 |
| `protected_store.candidate_cleanup_age_ms` | uint | installed `86400000`, range 3600000–604800000 |
| `protected_store.retired_cleanup_age_ms` | uint | installed `604800000`, range 86400000–2592000000 and greater than candidate cleanup age |
| `bootstrap_session.binding_id` | binding | purpose `bootstrap_v1` |
| `bootstrap_session.token_bits` | uint | fixed `256` |
| `bootstrap_session.presentation_ms` | uint | installed `180000`, range 60000–300000; one reveal/exchange generation |
| `bootstrap_session.throttle_failures` | uint | installed `5`, range 3–10 |
| `bootstrap_session.throttle_window_ms` | uint | installed `60000`, range 10000–300000 |
| `bootstrap_session.first_use_ms` | uint | installed `60000`, range 1000–300000 |
| `bootstrap_session.idle_ms` | uint | installed `1800000`, range 60000–1800000 |
| `bootstrap_session.absolute_ms` | uint | installed `43200000`, range 1800000–43200000 and greater than idle |

| JSON path | Type | Installed value | Hard constraint |
| --- | --- | ---: | --- |
| `artifact.active_transfers` | uint | `2` | 1–8 |
| `artifact.waiters` | uint | `8` | 0–32 |
| `artifact.admission_wait_ms` | uint | `5000` | 1–30000 and not beyond operation deadline |
| `artifact.copy_buffer_bytes` | uint | `262144` | 65536–1048576 |
| `artifact.stream_idle_ms` | uint | `30000` | 1000–120000 |
| `artifact.stream_total_ms` | uint | `1800000` | 60000–7200000 and greater than idle |
| `operator_modes.backup_elapsed_ms` | uint | `7200000` | 60000–28800000 |
| `operator_modes.restore_ticket_ms` | uint | `900000` | 60000–3600000 |
| `operator_modes.restore_elapsed_ms` | uint | `14400000` | fixed 4-hour accepted-operation deadline |
| `operator_modes.prepare_elapsed_ms` | uint | `1200000` | fixed 20-minute complete prepare deadline |
| `operator_modes.export_elapsed_ms` | uint | `7200000` | fixed 2-hour export deadline |
| `operator_modes.import_elapsed_ms` | uint | `7200000` | fixed 2-hour import deadline |
| `operator_modes.maintenance_elapsed_ms` | uint | `7200000` | fixed 2-hour accepted apply deadline |
| `operator_modes.browser_clear_elapsed_ms` | uint | `300000` | fixed five-minute accepted clear deadline |
| `operator_modes.browser_profile_bytes` | uint | `1073741824` | fixed ext4 project hard quota |
| `operator_modes.browser_profile_inodes` | uint | `50000` | fixed ext4 project inode hard quota |
| `operator_modes.browser_disk_cache_bytes` | uint | `268435456` | fixed cache ceiling; media cache disabled |
| `operator_modes.security_rescue_elapsed_ms` | uint | `14400000` | fixed four-hour hard-expired rescue deadline |
| `operator_modes.inventory_workers` | uint | `1` | 1–2 |
| `operator_modes.inventory_spool_bytes_per_worker` | uint | `8388608` | fixed maximum per worker |
| `operator_modes.inventory_chunk_records` | uint | `1000` | 1–1000 |
| `operator_modes.inventory_record_bytes` | uint | `4096` | fixed maximum encoded record |
| `operator_modes.inventory_slice_pages` | uint | `100` | 1–1000 |
| `operator_modes.inventory_slice_ms` | uint | `300000` | 1000–1800000 |
| `operator_modes.target_lock_ms` | uint | `30000` | 1–300000 |
| `operator_modes.migration_lock_ms` | uint | `15000` | 1–60000 |
| `operator_modes.total_lock_ms` | uint | `45000` | 1–360000 and at least each component lock |
| `operator_modes.capacity_survival_reserve_bytes` | uint | `4294967296` | fixed per writable device |
| `operator_modes.capacity_free_floor_bytes` | uint | `1073741824` | fixed, excludes allocated reserve |
| `operator_modes.capacity_write_quantum_bytes` | uint | `8388608` | fixed maximum between checks |
| `operator_modes.capacity_poll_ms` | uint | `1000` | fixed maximum restore polling interval |
| `operator_modes.body_transfer_workers` | uint | `1` | fixed installation-wide backup/restore worker |
| `operator_modes.body_copy_buffer_bytes` | uint | `262144` | fixed reusable streaming/checksum buffer |
| `operator_modes.multipart_part_bytes` | uint | `16777216` | fixed part size; one resident part and upload |
| `operator_modes.body_attempts` | uint | `3` | fixed total attempts including first |
| `operator_modes.body_idle_ms` | uint | `30000` | 1000–120000 |
| `operator_modes.body_total_ms` | uint | `1800000` | 60000–7200000, above idle and within operation remainder |
| `operator_modes.backup_reference_database_bytes` | uint | `5368709120` | fixed 5-GiB supported-profile ceiling |
| `operator_modes.backup_reference_object_bytes` | uint | `10737418240` | fixed inherited 10-GiB ceiling |
| `operator_modes.backup_reference_records` | uint | `10000` | fixed supported-profile ceiling |
| `operator_modes.backup_min_throughput_bytes_per_second` | uint | `16777216` | fixed 16 MiB/s for both measured paths |
| `operator_modes.backup_probe_bytes` | uint | `536870912` | fixed 512 MiB per measured path |
| `operator_modes.backup_probe_elapsed_ms` | uint | `300000` | fixed five-minute complete fixture/probe/cleanup parent |
| `operator_modes.backup_probe_max_age_ms` | uint | `604800000` | fixed seven days |
| `operator_modes.backup_admission_deadline_fraction_per_mille` | uint | `750` | fixed 75% of operation deadline |

| JSON path | Type | Installed value / exact constraint |
| --- | --- | --- |
| `tools.pg_dump.path` / `tools.pg_restore.path` | abspath | root-owned executable, not writable by operator |
| `tools.pg_dump.version` / `tools.pg_restore.version` | string | fixed `16.14` |
| `runtime.preflight_ms` | uint | installed `5000`, range 1–10000 |
| `runtime.preflight_page` | uint | installed `100`, range 1–1000 |
| `runtime.startup_dependency_ms` | uint | installed `30000`, range 1000–60000 |
| `runtime.dependency_retry_ms` | uint | installed `60000`, range 0–300000 |
| `runtime.retry_initial_ms` / `runtime.retry_max_ms` | uint | fixed `250` / installed `5000` (range 250–10000), initial not above max |
| `runtime.health_interval_ms` / `runtime.health_timeout_ms` | uint | installed `5000` / `2000`; interval 1000–30000, timeout 100–5000 and below interval |
| `runtime.go_memory_limit_bytes` | uint | fixed `671088640` (640 MiB) |
| `runtime.central_rss_ceiling_bytes` | uint | fixed `805306368` (768 MiB) |
| `runtime.operator_tool_rss_ceiling_bytes` | uint | fixed `536870912` (512 MiB) |
| `runtime.host_memory_reserve_bytes` | uint | fixed `2147483648` (2 GiB) |
| `runtime.host_memory_headroom_bytes` | uint | fixed `536870912` (512 MiB) |
| `runtime.settlement_ms` | uint | installed `30000`, range 1000–120000 |
| `runtime.total_shutdown_ms` | uint | installed `45000`, range 30000–180000 and not below settlement |
| `runtime.enabled_components` | string array | fixed sorted set `artifact_reconciliation`, `cleanup`, `execution`, `http`, `outbox`, `session_recovery`, `task_reconciliation` |
| `observability.log_format` / `observability.log_level` | string | fixed `json` / `info` |
| `observability.metric_registry` | string | fixed `central_custom_v1` |

Cross-field validation computes all Gate 7 aggregate products and coexistence combinations. In particular: active non-streaming buffers must not exceed 32 or 64 MiB; Artifact active × copy buffer must not exceed 8 MiB; inventory workers × spool must not exceed 16 MiB; backup/restore body workers remain one with at most one 16-MiB multipart part plus one 256-KiB copy buffer; every permitted profile's aggregate memory ceiling plus host headroom must fit the detected 8-GiB-or-larger host; serving data pools total exactly 12; serving plus control plus coexisting readers must not exceed installed 16; no permitted combination may exceed hard 24; offline mutation is available only after serving pools drain; every port is distinct; roots and Workspace paths do not overlap by path or mount identity; every binding purpose is unique and matches its field; TLS fingerprints match one active generation; and every nested deadline fits within its parent operation/authority deadline. Failure is `CONFIG_INVALID` before adapter, listener, helper, Docker, database, or object-store mutation.

Parsing first rejects invalid UTF-8, duplicate/unknown keys, non-NFC strings, forbidden number forms, and trailing content. The normalized representation sorts every object key lexicographically, retains declared array order, emits integers in shortest decimal form, and otherwise uses RFC 8785 JSON Canonicalization Scheme. The safe digest is SHA-256 over that encoding after replacing every `abspath` with its bound opaque root ID and omitting secret values, backend locators, and hidden nonces. The complete config digest uses the unredacted canonical document only inside protected state and is never logged or exported.

This is a complete schema-valid example; its identities and fingerprints are synthetic and are never installation defaults:

```json
{
  "schema_version": "central.config/v1",
  "instance_id": "019b0000-0000-7000-8000-000000000001",
  "paths": {
    "authoritative_state_root": "/var/lib/central-state/v1/instances/019b0000-0000-7000-8000-000000000001",
    "instance_data_root": "/var/lib/central-state/v1/instances/019b0000-0000-7000-8000-000000000001/data",
    "backup_repository_root": "/var/lib/central-state/v1/instances/019b0000-0000-7000-8000-000000000001/backups",
    "workspace_roots": []
  },
  "http": {
    "application": {"host": "127.0.0.1", "port": 8080},
    "operations": {"host": "127.0.0.1", "port": 9090},
    "tls": {
      "binding_id": "019b0000-0000-7000-8000-000000000002",
      "ca_fingerprint_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "leaf_fingerprint_sha256": "2222222222222222222222222222222222222222222222222222222222222222"
    },
    "non_streaming": {
      "active": 16,
      "waiters": 32,
      "admission_wait_ms": 2000,
      "api_buffer_bytes": 2097152,
      "html_buffer_bytes": 1048576,
      "body_read_ms": 30000,
      "response_write_ms": 30000,
      "route_total_ms": 65000
    },
    "max_header_bytes": 32768,
    "max_header_value_bytes": 4096,
    "read_header_ms": 5000,
    "idle_ms": 60000,
    "graceful_shutdown_ms": 45000
  },
  "postgres": {
    "host": "127.0.0.1",
    "port": 55432,
    "database": "central",
    "schema": "central",
    "bindings": {
      "server_admin": "019b0000-0000-7000-8000-000000000003",
      "runtime": "019b0000-0000-7000-8000-000000000004",
      "outbox": "019b0000-0000-7000-8000-000000000005",
      "migration": "019b0000-0000-7000-8000-000000000006"
    },
    "pools": {
      "runtime_general": 6,
      "runtime_settlement": 2,
      "outbox": 3,
      "cleanup": 1,
      "serve_lock_control": 1,
      "coexisting_read_only": 2,
      "offline_mutation": 2
    },
    "timeouts": {
      "pool_acquire_ms": 2000,
      "statement_ms": 30000,
      "lock_ms": 5000,
      "transaction_ms": 30000,
      "idle_in_transaction_ms": 30000,
      "connection_lifetime_ms": 1800000
    }
  },
  "object_store": {
    "scheme": "http",
    "host": "127.0.0.1",
    "port": 59000,
    "bucket": "central-artifacts-v1",
    "region": "us-east-1",
    "path_style": true,
    "bindings": {
      "root": "019b0000-0000-7000-8000-000000000007",
      "runtime": "019b0000-0000-7000-8000-000000000008",
      "backup": "019b0000-0000-7000-8000-000000000009",
      "restore": "019b0000-0000-7000-8000-00000000000a"
    },
    "policy_digests": {
      "runtime": "b4613cce4c0fe3e7b23cc7212d578919169cb1d64aab9c5b73fc544cf759d72f",
      "backup": "aa5f63fdf5b13e4bc2effd1a972a7c2ed6771faee3b56bc2fca7d822ad7d38b1",
      "restore": "b742ea7085d0e80e88a1fb835ffa934e7ad7ac398f2d1426efe04d2ea48a0e48"
    }
  },
  "protected_store": {
    "backend": "protected_file_v1",
    "binding_root_id": "019b0000-0000-7000-8000-00000000000b",
    "max_secret_bytes": 65536,
    "resolve_ms": 5000,
    "candidate_cleanup_age_ms": 86400000,
    "retired_cleanup_age_ms": 604800000
  },
  "bootstrap_session": {
    "binding_id": "019b0000-0000-7000-8000-00000000000c",
    "token_bits": 256,
    "presentation_ms": 180000,
    "throttle_failures": 5,
    "throttle_window_ms": 60000,
    "first_use_ms": 60000,
    "idle_ms": 1800000,
    "absolute_ms": 43200000
  },
  "artifact": {
    "active_transfers": 2,
    "waiters": 8,
    "admission_wait_ms": 5000,
    "copy_buffer_bytes": 262144,
    "stream_idle_ms": 30000,
    "stream_total_ms": 1800000
  },
  "operator_modes": {
    "backup_elapsed_ms": 7200000,
    "restore_ticket_ms": 900000,
    "restore_elapsed_ms": 14400000,
    "prepare_elapsed_ms": 1200000,
    "export_elapsed_ms": 7200000,
    "import_elapsed_ms": 7200000,
    "maintenance_elapsed_ms": 7200000,
    "browser_clear_elapsed_ms": 300000,
    "browser_profile_bytes": 1073741824,
    "browser_profile_inodes": 50000,
    "browser_disk_cache_bytes": 268435456,
    "security_rescue_elapsed_ms": 14400000,
    "inventory_workers": 1,
    "inventory_spool_bytes_per_worker": 8388608,
    "inventory_chunk_records": 1000,
    "inventory_record_bytes": 4096,
    "inventory_slice_pages": 100,
    "inventory_slice_ms": 300000,
    "target_lock_ms": 30000,
    "migration_lock_ms": 15000,
    "total_lock_ms": 45000,
    "capacity_survival_reserve_bytes": 4294967296,
    "capacity_free_floor_bytes": 1073741824,
    "capacity_write_quantum_bytes": 8388608,
    "capacity_poll_ms": 1000,
    "body_transfer_workers": 1,
    "body_copy_buffer_bytes": 262144,
    "multipart_part_bytes": 16777216,
    "body_attempts": 3,
    "body_idle_ms": 30000,
    "body_total_ms": 1800000,
    "backup_reference_database_bytes": 5368709120,
    "backup_reference_object_bytes": 10737418240,
    "backup_reference_records": 10000,
    "backup_min_throughput_bytes_per_second": 16777216,
    "backup_probe_bytes": 536870912,
    "backup_probe_elapsed_ms": 300000,
    "backup_probe_max_age_ms": 604800000,
    "backup_admission_deadline_fraction_per_mille": 750
  },
  "tools": {
    "pg_dump": {"path": "/usr/lib/postgresql/16/bin/pg_dump", "version": "16.14"},
    "pg_restore": {"path": "/usr/lib/postgresql/16/bin/pg_restore", "version": "16.14"}
  },
  "runtime": {
    "preflight_ms": 5000,
    "preflight_page": 100,
    "startup_dependency_ms": 30000,
    "dependency_retry_ms": 60000,
    "retry_initial_ms": 250,
    "retry_max_ms": 5000,
    "health_interval_ms": 5000,
    "health_timeout_ms": 2000,
    "go_memory_limit_bytes": 671088640,
    "central_rss_ceiling_bytes": 805306368,
    "operator_tool_rss_ceiling_bytes": 536870912,
    "host_memory_reserve_bytes": 2147483648,
    "host_memory_headroom_bytes": 536870912,
    "settlement_ms": 30000,
    "total_shutdown_ms": 45000,
    "enabled_components": ["artifact_reconciliation", "cleanup", "execution", "http", "outbox", "session_recovery", "task_reconciliation"]
  },
  "observability": {
    "log_format": "json",
    "log_level": "info",
    "metric_registry": "central_custom_v1"
  }
}
```

### Normative `central.local-result/v1` schema

Every `central local ...` and `central local tls/trust ...` JSON outcome emits exactly one UTF-8 JSON object on stdout. Every field below is required; fields marked nullable use explicit `null`, never omission. Human output is not this schema and goes only to a TTY. Diagnostic detail remains on redacted stderr.

| Field | Type | Exact contract |
| --- | --- | --- |
| `schema_version` | string | fixed `central.local-result/v1` |
| `command` | enum | `init`, `init_status`, `init_abandon`, `prepare`, `security_status`, `security_update`, `dependency_upgrade_plan`, `dependency_upgrade_apply`, `dependency_upgrade_resume`, `maintenance_plan`, `maintenance_apply`, `runtime_stage`, `browser_open`, `browser_clear`, `trust_install`, `trust_remove`, `tls_rotate_leaf`, `tls_rotate_ca`, `up`, `status`, `doctor_host_prerequisites`, `doctor`, `doctor_write_probe`, `doctor_backup_throughput_probe`, `explain`, `down`, `wipe` |
| `outcome` | enum | `succeeded`, `failed`, `interrupted` |
| `exit_class` | uint | one of `0`, `2`, `3`, `4`, `5`, `6`, `7`; must equal process exit status |
| `reason_code` | enum | one value from the mapping below |
| `environment_state` | enum/null | one of the derived environment states or `null` when not safely derivable |
| `mutation_phase` | enum | `none`, `preflight`, `accepted`, `mutating`, `settling`, `complete` |
| `mutation_started` | boolean | true only after the command's documented accepted point |
| `retryable` | boolean | safe to repeat the same command/input without a resume operation |
| `resume_required` | boolean | only true when an exact operation continuation is mandatory |
| `operation_id` | uuid7/null | safe operation ID; required non-null when `resume_required` |
| `started_at` / `updated_at` | string | UTC RFC 3339 with microseconds; updated not before started |
| `progress.records` / `progress.bytes` / `progress.chunks` | uint/null | bounded committed progress only, never estimates or uncommitted work |
| `safe_next_action.kind` | enum | `none`, `retry_same`, `run_command`, `resume_exact`, `inspect_manual` |
| `safe_next_action.command` | string/null | one allowlisted command template, at most 256 ASCII bytes, containing only safe opaque IDs; non-null only for `run_command`/`resume_exact` |
| `remediation.catalog_version` | string | fixed `central.local-remediation/v1` |
| `remediation.entry_id` | string | fixed ASCII catalog ID corresponding exactly to `reason_code` |
| `remediation.failure_count` | uint | consecutive safe-fingerprint count including this result; zero only for exit `0` |
| `remediation.manual_after_count` | uint/null | exact catalog threshold, or null when not count-based |
| `remediation.manual_after_ms` | uint/null | exact catalog elapsed threshold, or null when not time-based |
| `details` | object | exactly one closed command-keyed variant below; never `null` and never presentation prose |
| `message` | string | fixed-code localized-safe English text, 1–512 NFC UTF-8 bytes; no raw dependency text or caller input |

`details.kind` equals `command`; every variant rejects fields not listed here. A field unavailable because the command failed is explicit `null`. IDs are UUIDv7 or fixed bounded ASCII authority IDs; counts/bytes are `uint`; times are UTC RFC 3339 with microseconds. `findings` contains at most 64 entries sorted by fixed catalog order, each exactly `{entry_id,reason_code,state,authority_field_id,next_action_kind}` with bounded enums/IDs and no raw value.

| `details.kind` | Complete additional fields |
| --- | --- |
| `init` | `instance_id`, `config_binding_id`, `init_operation_id` |
| `init_status` | `incomplete_operations`, `observation_limit`, `observation_truncated` |
| `init_abandon` | `init_operation_id`, `reservation_state`, `audit_tombstone_id` |
| `prepare` | `preparation_id`, `dependency_set_id`, `advisory_bundle_id`, `reused_verified_input_count`, `acquired_verified_input_count` |
| `security_status`, `security_update` | `bundle_id`, `key_id`, `issued_at`, `expires_at`, `authority_state` (`current`, `stale_admitted`, `hard_expired`, `denied`, `missing`), `advisory_count`, `exception_count`, `deny_count`, `snapshot_generation`, `snapshot_signed_at`, `snapshot_observed_age_ms`, `snapshot_signing_key_id`, `snapshot_signature_state`, `loopback_health` |
| `dependency_upgrade_plan` | `ticket_id`, `transition_id`, `expires_at`, `classification`, `backup_id` |
| `dependency_upgrade_apply`, `dependency_upgrade_resume` | `transition_id`, `old_dependency_set_id`, `new_dependency_set_id`, `checkpoint` |
| `maintenance_plan` | `plan_id`, `expires_at`, `candidate_count`, `candidate_bytes`, `retained_count`, `retained_bytes` |
| `maintenance_apply` | `plan_id`, `deleted_count`, `deleted_bytes`, `checkpoint` |
| `runtime_stage` | `runtime_build_id`, `lease_expires_at`, `development_instance` |
| `browser_open` | `browser_profile_id`, `public_ca_token`, `origin_id`, `browser_process_state` |
| `browser_clear` | `browser_profile_id`, `sessions_revoked`, `bootstrap_generation_revoked`, `checkpoint` |
| `trust_install`, `trust_remove`, `tls_rotate_leaf`, `tls_rotate_ca` | `public_ca_token`, `public_leaf_token`, `browser_profile_id`, `trust_state` |
| `up`, `down` | `dependency_set_id`, `postgres_state`, `object_store_state`, `completed_step_count` |
| `doctor_host_prerequisites` | `manifest_id`, `host_profile_state`, `findings` |
| `status`, `doctor`, `doctor_write_probe`, `doctor_backup_throughput_probe` | `privileged_inspection`, `serve_state`, `findings`, `capacity_class`, `probe_id`, `snapshot_generation`, `snapshot_signed_at`, `snapshot_observed_age_ms`, `snapshot_signing_key_id`, `snapshot_signature_state`, `loopback_health` |
| `explain` | `requested_reason_code`, `catalog_entry_id` |
| `wipe` | `prior_payload_epoch_id`, `current_payload_epoch_id`, `completed_root_count`, `checkpoint` |

`init_status.incomplete_operations` contains at most eight entries sorted by operation ID, each exactly `{init_operation_id,instance_id,phase,started_at,safe_next_action}`; every value is safe and caller-UID-bound, and truncation requires administrator inspection rather than guessing an ID.

Snapshot generation is uint64; age is a checked uint64 millisecond duration; key ID is bounded ASCII; `snapshot_signature_state` is exactly `valid_fresh`, `valid_stale`, `invalid`, or `missing`; and `loopback_health` is independently `reachable`, `unreachable`, or `not_checked`. A verified signature at most five minutes old is fresh. An older valid signature remains reportable as `valid_stale` with the fixed `SNAPSHOT_STALE` finding and no current-state claim. Missing, invalid, unknown-key, future-dated by more than 60 seconds, or overflowed evidence returns exit `5`/`SNAPSHOT_INVALID`; unavailable fields are null, live loopback remains separately labeled, and no authoritative fallback occurs.

Ticket/plan IDs in these variants are public opaque handles, not bearer authorization: apply still requires exact protected evidence plus fresh PAM/helper confirmation. They may appear only in their named details/command templates. Public CA tokens are domain-separated public-content values, not credential fingerprints. Export `bx1` authority tokens never enter this JSON schema.

| Exit | Allowed reason codes | Required semantics |
| ---: | --- | --- |
| `0` | `OK`, `MIGRATION_REQUIRED`, `OUTSIDE_SUPPORTED_PROFILE`, `UPGRADE_OUT_OF_PLACE_REQUIRED`, `SECURITY_AUTHORITY_STALE` | command completed its promised work; the latter four are successful diagnostic states with an exact next action or prominent warning |
| `2` | `INVALID_INVOCATION`, `CONFIG_NOT_FOUND`, `CONFIG_AMBIGUOUS`, `CONFIG_INVALID`, `CONFIRMATION_MISMATCH` | no accepted mutation; correct invocation/configuration first |
| `3` | `DEPENDENCY_UNAVAILABLE`, `HELPER_UNAVAILABLE`, `PREPARATION_REQUIRED`, `TLS_TRUST_REQUIRED`, `HOST_PREREQUISITE_MISMATCH`, `BACKUP_REQUIRED`, `THROUGHPUT_EVIDENCE_REQUIRED`, `MAINTENANCE_REQUIRED` | prerequisite unavailable before accepted mutation; retry only after stated prerequisite |
| `4` | `LOCK_TIMEOUT`, `RESOURCE_TIMEOUT`, `PORT_IN_USE`, `CAPACITY_INSUFFICIENT` | bounded pre-accepted-point contention/resource failure; no mutation remains active |
| `5` | `DRIFTED`, `INCOMPATIBLE`, `PROTECTED_STATE_INVALID`, `SNAPSHOT_INVALID`, `CLEANUP_REQUIRED`, `SECURITY_REVIEW_REQUIRED`, `SECURITY_AUTHORITY_HARD_EXPIRED`, `DEPENDENCY_DENIED`, `DEADLINE_NOT_PLAUSIBLE`, `UPGRADE_NOT_SAFE`, `UNSUPPORTED_IN_THIS_SLICE`, `OPERATION_SUPERSEDED_BY_WIPE` | unsafe mismatch, invalid diagnostic evidence, blocked/hard-expired authority, deferred capability, superseded operation, or unproven upgrade requiring exact diagnosis/governed repair; never blind retry |
| `6` | `RESUME_REQUIRED`, `PORT_BIND_RACE`, `MUTATION_FAILED`, `MUTATION_INDETERMINATE`, `ROLLBACK_FAILED` | accepted mutation failed/interrupted; operation evidence and exact next action required |
| `7` | `AUTHORITY_DENIED`, `HELPER_POLICY_DENIED`, `DOCKER_AUTHORITY_PRESENT` | authority or isolation policy denied; no privilege weakening is suggested |

`outcome=succeeded` iff exit `0`; `interrupted` is permitted only with exit `6`. Exit `2`, `3`, `4`, `5`, or `7` uses `failed`. `resume_required=true` requires exit `6`, reason `RESUME_REQUIRED`, non-null operation ID, `retryable=false`, and `safe_next_action.kind=resume_exact`. Ordinarily `retryable=true` is permitted only for exit `3` or `4` when no mutation started. The sole accepted-mutation exception is exit `6`/`PORT_BIND_RACE`: it requires a non-null operation ID, proven complete topology rollback, only exact idempotent durable-step receipts remaining, `resume_required=false`, and `safe_next_action.kind=retry_same`. `ROLLBACK_FAILED` and `MUTATION_INDETERMINATE` are never retryable. Exit `5` or `7` always selects `inspect_manual` or an exact non-mutating diagnostic command. `mutation_phase=complete` is required for exit `0`; `none` or `preflight` requires `mutation_started=false`; `accepted`, `mutating`, or `settling` requires it true. A failed mutation that was fully rolled back to the exact prior topology still records the accepted point and uses exit `6`; it is never recast as a preflight failure.

The local result canonicalization is the same strict RFC 8785/NFC/integer contract as configuration. Outside the exact public IDs/tokens in the closed `details` union it contains no path, secret, credential, nonce, Docker identifier, raw image/checksum, object key, SQL, dependency error, environment value, or unrestricted label; `<absolute-config-path>` may appear only as the literal catalog placeholder. Schema/catalog conformance and the exit/reason/cross-field/threshold matrix are Phase 1 golden tests for every command at every accepted-point failure boundary.

### Normalized safe configuration digest

Operator receipts, restore tickets, and generated topology bind a normalized safe configuration digest. It includes schema version, instance/target opaque identities, fixed logical names, numeric ports, resource values, tool/dependency versions, component set, and opaque root/credential binding IDs. It excludes secret values, raw paths, raw object keys, backend locators, hidden nonces, and unrestricted labels. Canonicalization is versioned; a future canonicalization requires a new config schema or digest version.

## Protected local stores and credentials

### `protected_file_v1`

`protected_file_v1` maps an opaque binding ID to exactly one local directory under the protected state root. Immutable `binding.json` records schema `central.protected-binding/v1`, binding ID, purpose, allowed adapter/target class, owning Workspace when applicable, creation time, and creation nonce. Mutable status and active generation never appear in that immutable binding. `binding.lock` is a never-deleted advisory-lock inode; every stage/register/activate/revoke/retire/cleanup path holds it exclusively from initial revalidation through its last directory synchronization. Resolution holds it shared only through opening and validating the exact value descriptor, then releases it before adapter I/O.

Generation values and phase records are create-only. Canonical JSON phase files use these complete schemas:

| Record | Required safe fields |
| --- | --- |
| `<generation>.meta.json` | schema `central.protected-generation/v1`; binding/candidate/generation IDs; purpose; created-at; byte count; opaque HMAC version token plus key version; value-format enum `opaque_bytes` |
| `staged.json` | schema `central.protected-candidate-phase/v1`; phase `staged`; binding/candidate ID; ordered `generation_refs[] {role,generation_id,version_token}`; expected prior candidate/generation or explicit `null`; owning protocol; safe operation ID or `null`; created-at |
| `registered.json` | same schema; phase `registered`; exact staged digest; registration class; opaque authoritative-reference fingerprint; registered-at |
| `activated.json` | same schema; phase `activated`; exact registered digest; activation sequence; activated-at |
| `retired.json` | same schema; phase `retired`; replacing candidate/generation; retired-at; not-before-cleanup-at |
| `abandoned.json` | same schema; phase `abandoned`; fixed safe reason enum; authoritative no-reference proof fingerprint; abandoned-at; not-before-cleanup-at |
| `active.json` | schema `central.protected-active/v1`; binding/purpose; status `active`, `revoked`, or `deleted`; candidate/generation refs and opaque version tokens, or an empty tuple only for `deleted`; monotonically increasing activation sequence; activated-at; revoked/deleted-at and fixed reason or explicit `null` |

Ordinary secret/bootstrap candidates contain exactly one generation ref with role `value`. A TLS candidate contains exactly two refs, roles `ca` and `leaf`, and activation treats the tuple atomically. IDs are UUIDv7. The broker computes each safe version token as HMAC-SHA-256 under a root-only versioned fingerprint key with domain separation over schema, purpose, binding ID, candidate ID, generation ID, role, byte count, and value bytes. Raw/unsalted secret digests never leave broker memory or appear in metadata, receipts, PostgreSQL, audit, configuration, or observations. Public certificate, OCI, file-integrity, and sealed-backup digests remain ordinary public-content SHA-256 values and are not secret fingerprints. Times are UTC RFC 3339 with microseconds. Unknown fields, duplicate roles, multiple phase files of the same name, a phase without all predecessors, conflicting terminal phases, token mismatch, nonmonotonic sequence, or purpose/binding/operation mismatch is `PROTECTED_STATE_INVALID`.

Staging has this exact durable order inside the broker while holding `binding.lock`: create the random candidate and generation identities; create a same-directory value temporary with `0600`; write bounded bytes while computing only the domain-separated HMAC token; synchronize; publish the value create-only; synchronize `generations/`; publish and synchronize generation metadata create-only; publish `staged.json` create-only; then synchronize the candidate and binding directories. A crash before durable `staged.json` creates no eligible candidate. TLS repeats value/key/certificate publication for both roles before one staged tuple is published.

The owning protocol next durably commits its authoritative registration under the global protected-state-before-database lock order. Only after that commit may it publish `registered.json`; if it crashes between those steps, reconciliation queries the exact authoritative operation/database reference and reconstructs only the matching registered phase. A phase file is evidence, never a substitute for that authoritative reference.

Activation revalidates candidate, every value/meta version token, authoritative registration, expected prior active tuple, and activation sequence while holding `binding.lock`. It writes a complete new `active.json` temporary, synchronizes it, atomically renames it over the pointer, synchronizes the binding directory, and only then publishes `activated.json`. The pointer rename is the activation linearization point. A crash afterward is reconciled by writing the uniquely implied activated phase; a crash beforehand leaves the old generation active. Concurrent candidates cannot both match the prior tuple/sequence.

After a later activation, the same locked protocol publishes `retired.json` for the displaced candidate with a seven-day installed retention. Revocation atomically replaces `active.json` with the same exact tuple/sequence and status `revoked`, synchronizes the binding directory, and immediately removes resolution eligibility; it never deletes bytes inline. Rotation preserves logical binding identity and may name a revoked tuple as its expected prior state.

Crash reconciliation follows durable evidence only:

| Evidence | Required action |
| --- | --- |
| value temporary, value without metadata, or metadata without `staged` | never resolve/register; after candidate cleanup age and exact no-reference proof, abandon and remove |
| durable `staged`, no authoritative registration | retain within candidate cleanup age; afterward recheck under lock, publish `abandoned`, then clean |
| exact authoritative registration, missing `registered` | reconstruct the one matching registered phase |
| durable `registered`, old active pointer | exact owning operation may activate; generic startup never chooses it |
| active pointer matches candidate, missing `activated` | verify all evidence and publish `activated` |
| displaced activated candidate missing `retired` | publish retirement derived from the newer active sequence |
| any conflict or unknowable external reference | fail closed; no generic cleanup or winner selection |

Cleanup is exact-reference collection, not age-only deletion. After the installed one-day candidate or seven-day retired not-before time, the broker acquires `binding.lock` and proves absence from `active.json`, every nonterminal candidate, protected operation/target records, PostgreSQL registration/security epochs, restore barriers, and helper/container handoff receipts. It then publishes `abandoned.json` where applicable, removes only the named value(s), synchronizes `generations/`, removes their metadata, synchronizes again, removes only that candidate journal, and synchronizes the binding directory. A crash resumes this order idempotently. It never deletes a registered, active, revoked-pointer, referenced, ambiguous, or concurrently selected generation. Terminal safe metadata is copied into the bounded operator-audit record before its candidate journal is removed; no plaintext or backend path enters audit.

Logical deletion is distinct from revocation. After fresh PAM authorization and external-provider revocation proof where applicable, the owning protocol commits a create-only `central.protected-tombstone/v1` bound to the binding, current tuple/sequence, operation, database/reference epoch, and deletion deadline. Under `binding.lock` the broker proves no database, operation, handoff, restore, or adapter reference remains, atomically replaces `active.json` with status `deleted`, an empty tuple, the next sequence, and the tombstone digest, and synchronizes the binding directory. Only then does the former revoked or active tuple become a retired cleanup candidate with a maximum seven-day terminal deadline. Cleanup repeats the reference proof, unlinks exact values and metadata with directory synchronization, and retains only the opaque tombstone/audit evidence. Revocation may retain repairable bytes temporarily; deletion cannot retain plaintext indefinitely. Unlink is not claimed to provide physical secure erasure on journaled or copy-on-write media.

Resolution occurs only inside a registered secret-aware adapter, defaults to a five-second deadline, and rejects a value above 64 KiB. The resolver returns no plaintext to domain, generic runtime, generic process, logs, metrics, Events, receipts, config, or error surfaces. Mutable buffers are minimized and cleared best-effort after use. Missing, ambiguous, multiply active, wrong-owner, wrong-purpose, revoked, unreadable, oversized, or permission-drifted bindings fail closed with no fallback.

Protected credential material is excluded from Central backup payloads. Restoring application state never restores or re-enables a credential binding. The post-restore Gate 7 reconciliation compares only opaque identity and safe HMAC version token and requires fresh operator authority before re-enabling a SecretReference.

The specialized `bootstrap/` namespace uses this same journal, generation metadata, exact registration, and atomic active-pointer protocol but is not a Workspace SecretReference and is never discoverable through the general resolver. The TLS namespace uses the same rules for its atomic CA/leaf tuple. `operations/target.json` is the Gate 7 external provisioning/restore/security barrier; per-operation records hold exact migration, backup, and restore progress. Receipt filenames are fixed desired-state records, while an operation record retains one immutable operation identity and advances only by atomic exact-phase replacement.

### Bootstrap token presentation

Bootstrap generations use 256 bits from the operating-system cryptographic random source. The protected store owns candidate plaintext; PostgreSQL owns only the accepted verifier, generation, database-time presentation expiry, consumption, throttle, and session linkage. A newly provisioned or post-exchange replacement generation is not browser-exchange eligible until an explicit presentation rotation.

The trusted operator obtains the current active bootstrap value only through:

```text
central bootstrap show
```

This is a separate local-operator mutation/presentation boundary, not the `session/port` used by serving code. It requires fresh PAM authentication plus the broker/helper-owned controlling-TTY ceremony, refuses redirected/stdout-JSON output, proves the exact `central serve` process holds `runtime.lock`, completes TLS authentication to the configured instance origin, and requires the profile to be ready before staging plaintext. The operator uses a second terminal; `show` never starts, supervises, or signals `serve`. A same-UID process, caller-created PTY, cached sudo credential, or operator controller alone cannot ask the broker to reveal bytes.

Every invocation creates a fresh candidate rather than rereading the current plaintext. Under shared host-lifecycle and target ownership plus exclusive bootstrap `binding.lock`, it stages a 256-bit generation. One PostgreSQL transaction locks and revalidates the current bootstrap/security epoch, invalidates any earlier unconsumed presentation generation, installs the new generation/verifier, marks it presentation-eligible until database time plus the installed three minutes, and registers the exact protected candidate/digest. That commit is the rotate-on-reveal linearization point. A concurrent bootstrap exchange or second `show` is serialized by the same row: exactly one wins against the old generation, and a loser never re-enables it.

The command activates only the registered protected candidate through the exact journal protocol, rechecks PostgreSQL generation/expiry and HTTPS server identity, then atomically replaces `bootstrap/presentation.json` with schema `central.bootstrap-presentation/v1`, generation/candidate/version token, revealed-at, database expiry, PAM-session identity, and a safe TTY class. It synchronizes that receipt before the broker opens the authenticated helper-supplied `/dev/tty` descriptor and writes the value exactly once, then clears its buffer best-effort. Plaintext never crosses the operator controller or runtime process. The presentation command refuses to resolve a generation already named by a durable presentation receipt. A TTY write failure leaves a bounded possibly-undelivered generation; running `show` again rotates and invalidates it rather than revealing it again.

The HTTP exchange accepts only the exact currently presented generation when database time is strictly earlier than its expiry; equality is expired. Expiry, replacement, or one successful exchange makes it permanently ineligible. The accepted exchange then follows the Gate 7 staged rotation/session protocol and leaves its replacement generation non-presented. Sessions retain the accepted 30-minute idle, 12-hour absolute, and one-minute first-use defaults. Throttling and presentation expiry use PostgreSQL database time. Crash recovery activates only an exactly registered candidate; it never reveals it. A crash before/after the database commit, protected activation, presentation receipt, or TTY write is recovered by another fresh `show`, never by replaying plaintext.

The command offers no list, export, URL, clipboard, environment, generic reveal, or warning-bypass mode. A server-not-ready, TLS/binding/epoch mismatch, stale generation, or protected-state conflict returns safe two-terminal repair guidance and no bytes.

### PostgreSQL identities

The fixed logical database is `central`; the application schema is `central`. Exactly these application roles exist:

- `central_runtime` for runtime-general, runtime-settlement, cleanup, read-only inspection, and bounded backup/restore verification operations;
- `central_outbox` for outbox delivery only; and
- `central_migration` for explicit migration and the database/schema replacement substep of confirmed restore apply.

Each role uses a separate protected password binding and SCRAM-SHA-256. Pool separation does not create new roles. `central serve` never receives migration, root/provisioner, backup-manifest, or restore credentials. Backup/restore never use `central_outbox`.

The PostgreSQL built-in administrative identity is available only through separate tmpfs handoff copies to the PostgreSQL server initialization path and `postgres-provision`; it is not an application role. After first cluster initialization, the authoritative runtime model and diagnostic override omit the bootstrap password mount when the exact init receipt proves it unnecessary. Logical provisioning is idempotent and least-privileged; an owned database, role, membership, attribute, database-level grant, or authentication-rule fact that differs from desired state is `DRIFTED`, never silently dropped or widened.

Before the version-zero baseline, `postgres-provision` owns only cluster/database prerequisites: the fixed `central` database, the three login roles and SCRAM verifiers, database `CONNECT`/temporary-object posture, role membership/attributes, `pg_hba` authentication posture, and denial of public/default privileges. It neither creates nor requires the `central` application schema, migration history, application tables/types/functions, schema ownership, or schema-dependent grants. An absent application schema and history on an otherwise exact fresh database is the valid `MIGRATION_REQUIRED` state, not drift.

Only the Gate 7 version-zero migration transaction creates the `central` schema/history/baseline and installs schema/object ownership, default privileges, and role grants from the embedded baseline manifest. On an initialized target, `postgres-provision` may compare only the prerequisite facts it owns; `migrate verify/status` inspects all schema-dependent facts under `central_runtime`. A present partial/unbound application schema before baseline, or any initialized schema/grant mismatch, remains the migration protocol's incompatible/dirty outcome and is never adopted or repaired by provisioning.

### MinIO bucket and identities

Each instance has one bucket named `central-artifacts-v1`. The fixed key namespaces are:

```text
v1/system/<opaque-namespace-generation>
v1/staging/<workspace-opaque-id>/<artifact-opaque-id>/<staging-generation>
v1/ready/<workspace-opaque-id>/<artifact-opaque-id>/<content-generation>
```

Only opaque Central-generated identifiers appear in application artifact keys.
The sole reserved exception is the reviewed non-application fixture key
`v1/system/backup-throughput-fixture-v1`. Original filenames, Task text, media
types, labels, paths, and secret material are prohibited.

Three non-root MinIO identities are provisioned:

- runtime identity: exact Artifact/system operations required by the serving adapters;
- backup identity: `GetObject` only for ready backup bodies and the one fixed throughput fixture; and
- restore identity: exact create/verify/reconciliation authority needed by confirmed offline restore.

The sole attached policies are the following canonical JSON documents under policy contract `central.minio-policy/v1`. No identity belongs to a group, inherits another policy, or receives console/admin credentials. The provisioner canonicalizes each document with RFC 8785, binds its SHA-256 to config/provision receipts, and fails `DRIFTED` on any statement, action, resource, condition, attachment, group, or digest difference. Implicit deny applies to every action not allowed; the final statement additionally makes security/lifecycle administration non-overridable if another policy is accidentally attached.

Runtime policy `central-runtime-v1`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListOnlyCentralNamespaces",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::central-artifacts-v1",
      "Condition": {"StringLike": {"s3:prefix": ["v1/ready/*", "v1/staging/*", "v1/system/*"]}}
    },
    {
      "Sid": "ListInstanceMultipartUploads",
      "Effect": "Allow",
      "Action": "s3:ListBucketMultipartUploads",
      "Resource": "arn:aws:s3:::central-artifacts-v1"
    },
    {
      "Sid": "ArtifactLifecycleObjects",
      "Effect": "Allow",
      "Action": ["s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject", "s3:ListMultipartUploadParts", "s3:PutObject"],
      "Resource": [
        "arn:aws:s3:::central-artifacts-v1/v1/ready/*",
        "arn:aws:s3:::central-artifacts-v1/v1/staging/*",
        "arn:aws:s3:::central-artifacts-v1/v1/system/*"
      ]
    },
    {
      "Sid": "DenyBucketAndPolicyAdministration",
      "Effect": "Deny",
      "Action": [
        "s3:BypassGovernanceRetention", "s3:CreateBucket", "s3:DeleteBucket", "s3:DeleteBucketCors",
        "s3:DeleteBucketPolicy", "s3:ForceDeleteBucket", "s3:PutBucketCors", "s3:PutBucketNotification",
        "s3:PutBucketObjectLockConfiguration", "s3:PutBucketPolicy", "s3:PutBucketQOS",
        "s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
        "s3:PutInventoryConfiguration", "s3:PutLifecycleConfiguration", "s3:PutObjectLegalHold",
        "s3:PutObjectRetention", "s3:PutReplicationConfiguration"
      ],
      "Resource": ["arn:aws:s3:::central-artifacts-v1", "arn:aws:s3:::central-artifacts-v1/*"]
    }
  ]
}
```

Backup policy `central-backup-v1`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": [
        "arn:aws:s3:::central-artifacts-v1/v1/ready/*",
        "arn:aws:s3:::central-artifacts-v1/v1/system/backup-throughput-fixture-v1"
      ]
    }
  ]
}
```

Restore policy `central-restore-v1`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListRestoredNamespaces",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::central-artifacts-v1",
      "Condition": {"StringLike": {"s3:prefix": ["v1/ready/*", "v1/staging/*", "v1/system/*"]}}
    },
    {
      "Sid": "ListRestoreMultipartUploads",
      "Effect": "Allow",
      "Action": "s3:ListBucketMultipartUploads",
      "Resource": "arn:aws:s3:::central-artifacts-v1"
    },
    {
      "Sid": "ApplyVerifyAndReconcileRestore",
      "Effect": "Allow",
      "Action": ["s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject", "s3:ListMultipartUploadParts", "s3:PutObject"],
      "Resource": [
        "arn:aws:s3:::central-artifacts-v1/v1/ready/*",
        "arn:aws:s3:::central-artifacts-v1/v1/staging/*",
        "arn:aws:s3:::central-artifacts-v1/v1/system/*"
      ]
    },
    {
      "Sid": "DenyBucketAndPolicyAdministration",
      "Effect": "Deny",
      "Action": [
        "s3:BypassGovernanceRetention", "s3:CreateBucket", "s3:DeleteBucket", "s3:DeleteBucketCors",
        "s3:DeleteBucketPolicy", "s3:ForceDeleteBucket", "s3:PutBucketCors", "s3:PutBucketNotification",
        "s3:PutBucketObjectLockConfiguration", "s3:PutBucketPolicy", "s3:PutBucketQOS",
        "s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
        "s3:PutInventoryConfiguration", "s3:PutLifecycleConfiguration", "s3:PutObjectLegalHold",
        "s3:PutObjectRetention", "s3:PutReplicationConfiguration"
      ],
      "Resource": ["arn:aws:s3:::central-artifacts-v1", "arn:aws:s3:::central-artifacts-v1/*"]
    }
  ]
}
```

Runtime and restore listing retain the Gate 8 fixed-prefix rules where their
policies permit it. The Slice C backup refinement never lists: authoritative
backup inventory supplies exact ready-body keys, and the C02 object probe reads
only `v1/system/backup-throughput-fixture-v1`. `GetObject` covers bounded
HEAD/read verification. Multipart create/complete is authorized by `PutObject`;
part enumeration and abort use their explicit actions. Runtime delete is valid
only after durable Artifact delete/cleanup intent. Restore delete is valid only
inside the accepted offline operation for an object created by that same
restore attempt or durably classified by reconciliation; IAM cannot express
those state predicates, so the typed adapter and persisted operation fence
remain mandatory. Backup has no list, write, delete, ACL, multipart, or
administration action. None of the three identities may create/delete the
bucket, alter policy/ACL/CORS/lifecycle/versioning/notification/encryption/replication/retention,
generate presigned browser delivery, or call MinIO administration APIs.

Separate tmpfs handoff copies of the MinIO root credential are mounted only into the MinIO server, which requires its copy for the container lifetime, and the one-shot `minio-provision` service. It is never available to the unprivileged Central application/controller or any other container; only the bounded helper handoff step may copy it. Policies are versioned and digest-bound; provisioning fails on unexpected policy or identity drift. Browser access, presigned-URL delivery, bucket-public policy, anonymous access, versioning/lifecycle mutation outside the accepted Artifact contract, and MinIO console publication are prohibited.

## Local command workflow and derived state

### Local lifecycle commands

Gate 8 adds these local-environment commands without changing the semantics of the Gate 7 migration/backup/restore verbs:

```text
central local init
central local init --status
central local init --resume=<init-operation-id>
central local init --abandon=<init-operation-id>
central local doctor --host-prerequisites
central local trust install
central local trust remove
central local tls rotate-leaf
central local tls rotate-ca
central local security status
central local security update
central local prepare
central local dependency-upgrade plan
central local dependency-upgrade apply --ticket=<ticket-id>
central local dependency-upgrade resume --operation=<operation-id>
central local maintenance plan
central local maintenance apply --plan=<plan-id>
central local runtime stage --binary=<absolute-go-binary> --manifest=<absolute-build-manifest>
central local browser open
central local browser clear
central local browser clear --operation=<browser-clear-operation-id>
central local up
central local status
central local doctor
central local doctor --write-probe
central local doctor --backup-throughput-probe
central local explain --reason=<reason-code>
central local down
central local wipe
central local wipe --operation=<operation-id>
central bootstrap show
```

Gate 8 also authorizes the `backup list`, `backup export`, `backup import`, `backup delete`, and `backup prune` extensions described below. ADR 0009 and the canonical Phase 1 command contract must record them as extensions owned by the existing Gate 7 `backup/app` application port; their durable backup semantics remain Gate 7-owned, while their local repository/export/maintenance realization and public result variants are Gate 8-owned. They are not silently inferred as pre-existing Gate 7 verbs and are not moved under an infrastructure-helper namespace.

Gate 8 additionally narrows the Gate 7 backup admission rule with `backup create --security-rescue` for hard-expired authority only and `backup security-rescue cleanup --operation=<rescue-operation-id>` for its settlement-only cleanup continuation. ADR 0009 must record these explicit recovery-only exceptions; neither is an ordinary backup permission or permission to continue application use.

ADR 0009 extends the Gate 7 backup result union with closed kind `security_rescue_cleanup`, fields `rescue_operation_id`, `checkpoint`, `containers_stopped`, `mounts_released`, `deleted_entries`, `deleted_bytes`, and `scratch_state`, plus the inherited mutation/retry/resume/action fields. After cleanup acceptance, `resume_exact` always renders the same cleanup command and never `backup resume`.

`local init` follows the configless create/resume grammar above. Its immutable operation ID is generated and displayed on the helper-owned TTY before mutation. The helper then writes and synchronizes a create-only intent in its installed root-owned `/var/lib/central-infra/init-audit/`, binding init operation, caller UID/PAM session, prospective instance/config/state/data/backup/protected-root identities, and authority digest. Only after that audit boundary may it create the XDG reservation, root-parented instance directory, `init-bootstrap.json`, bootstrap audit record, and protected broker instance root containing binding/key material plus the uncommitted genesis transition, in that order. These are the complete pre-accepted artifact allowlist; they contain no config authority, secret generation, TLS key, trust change, payload content, dependency evidence, or other operation. The exact init accepted point is the synchronized broker `committed.json` for `central.init-genesis/v1`, followed by the synchronized root intent phase `accepted`; the genesis binds the reserved roots, initial config/bindings, broker/view-signing identities, and init audit head. `mutation_started` becomes true at that point. A crash before the global intent leaves no instance; a crash after intent but before acceptance permits status plus exact resume/abandon; a crash at or after acceptance is `RESUME_REQUIRED` and only `local init --resume=<init-operation-id>` may advance the exact journal.

Configless fresh-PAM `local init --status` reads only root intent records bound to the invoking UID and returns at most eight incomplete safe IDs/phases with exact resume or abandon commands; it reveals no path, secret, other UID, or completed history. `local init --abandon=<id>` requires fresh PAM plus helper confirmation and is allowed only before the init accepted point when observed descendants equal the pre-accepted allowlist above. It removes exactly those descriptor-bound reservation/bootstrap/uncommitted-genesis artifacts in reverse synchronized order and leaves an immutable root-audit tombstone; any extra artifact, committed genesis, protected value, payload, or trust evidence forbids abandon. At or after the accepted point exact resume is mandatory. Only after acceptance may the helper/broker create protected values and TLS material. Success finalizes the instance audit and root intent, then writes the broker-signed XDG selection view; it never overwrites or adopts an arbitrary directory.

`local trust install` and `local trust remove` implement only the explicit system-plus-selected-browser public-anchor transitions defined above and require fresh PAM plus the helper-owned confirmation; they cannot select an arbitrary certificate, browser profile, or trust location. TLS rotation commands require serving to be stopped, lifecycle-exclusive ownership, exact active-generation evidence, and fresh helper authentication. `rotate-leaf` preserves the active CA; `rotate-ca` follows the staged install-before-activate protocol and does not remove the old anchor automatically. `local security status` is the unprivileged read-only view of the active signed advisory authority. `local security update` follows the online/offline closed-input activation protocol above and requires serving and dependencies to be stopped.

`local dependency-upgrade plan/apply/resume` implement only the ticketed patch and out-of-place classification protocol above. They never install host packages, replace the helper, infer compatibility from a version number, reuse a backup predating the last mutation, or widen a ticket. Apply/resume leaves dependencies stopped even on success so ordinary `local up` remains the sole start boundary.

`local maintenance plan/apply` implements only the bounded unsealed-operation, retired-secret, and audit retention policy below. Plan is a dry run; apply requires the exact unchanged plan and cannot accept a caller path, age, glob, policy, or candidate ID.

`local runtime stage` is the development-only explicit trust transition above. Phase 1 supplies `scripts/build-local-runtime.sh --output=<absolute-empty-directory>` as the sole supported development builder. Under the locked Go 1.26.5 tool it runs with `CGO_ENABLED=0`, `GOENV=off`, `GOFLAGS=-mod=readonly -trimpath -buildvcs=false`, empty caches, fixed locale/umask, and the reviewed `go build` package/ldflags; it emits create-only `central` plus RFC 8785 `central.local-runtime-build/v1.json`. The manifest contains binary digest/size, canonical source-tree and module-graph digests, Go/toolchain identity, target OS/architecture, embedded helper/broker protocol IDs, config/result/remediation/schema IDs, Git commit plus dirty-tree digest, and no timestamp/path. The binary's read-only build-info command emits the same fields except its own outer digest. The controller opens both paths by descriptor and the helper never follows or executes them in place. Staging requires fresh PAM and helper-displayed digest confirmation, produces no Docker authority, and rejects a shell, interpreter, directory, mutable file, cross-instance build, separate/changed manifest, or incompatible embedded identity.

`local browser open` is the sole supported application-browser launch. After fresh authentication the helper opens exactly `https://127.0.0.1:8080/app/bootstrap` in the root-policy-locked instance profile as `central-browser`, with no caller URL/flag/environment/profile. It refuses X11, remote sessions, an unlocked profile, user trust/extension policy, or another browser process using that profile. Ordinary operator-owned browser profiles are outside the supported Central origin.

`local browser clear` implements only the journaled stopped-browser/session-revocation protocol above. After an accepted interruption, `local browser clear --operation=<browser-clear-operation-id>` is the sole resume form and must match the one incomplete journal; an initial clear while any accepted clear exists, an unknown/terminal/cross-instance ID, or omission of the required operation ID is rejected. It accepts no profile, path, age, cookie selector, preservation flag, or force option and returns the `browser_clear` result variant with the common operation ID/checkpoint and exact `resume_exact` action when required.

`local up` validates config, bindings, dependency lock, helper authority, current signed advisory authority or an exact unchanged admission still inside the 30-day stale grace, absence of incomplete wipe, current epoch, receipts, and ports; then asks the helper to perform the fixed Compose workflow. Stale admission reuses only admitted local identities and returns prominent `SECURITY_AUTHORITY_STALE`; it cannot fetch/build/change anything. Hard-expired authority blocks `up`. Only current-epoch receipts may skip a step. The controller verifies correlated helper/rollback receipts and does not migrate schema. Healthy infrastructure with absent/behind schema is `MIGRATION_REQUIRED`; fresh targets use `migrate up`, initialized targets use status/safety evidence, and interruption uses exact resume.

Unprivileged `local status` verifies bounded broker-signed XDG snapshots and reports bindings, preparation/provision summary, loopback health, last correlated helper state, snapshot generation/age, and derived snapshot state with `privileged_inspection=not_performed`; it never reads authoritative directories or claims current Docker inspection. Fresh-PAM `local doctor` launches the exact runtime inspection mode with state descriptors and adds path/permission, Docker denial, helper/broker/PAM/AppArmor/browser policy, advisory, port, opaque credential, semantic dependency, capacity, backup/audit ceilings, and compatibility checks. The configless host variant remains narrower. `--write-probe` uses a broker-delivered scoped credential; failed cleanup is durably `cleanup_required`.

`local explain` reads only the embedded remediation catalog. It never inspects Docker, dependencies, protected secret values, or payload data; the optional exact TTY path rendering follows the trusted-plane rules and selected config descriptor above.

`local down` stops dependencies, verifies Docker has released every secret mount, removes the exact instance tmpfs handoff files, and preserves every durable data, state, protected-secret, and backup root. Failure to prove release or cleanup is `cleanup_required`, not success. `local wipe` is the distinct one-off destructive protocol above; initial invocation and resume both require fresh PAM, and the helper reads the fixed confirmation before accepting/resuming destructive work. It deletes only descendants of the two descriptor-bound payload roots through the locked `central-local-infra` image, never configuration, authoritative state, audit, backup, export media, or an unrelated tmpfs handoff. There is no `--yes`, root selector, or force-lock bypass.

### Derived environment state

Environment state is derived from bindings, receipts, dependency health, provisioning evidence, schema inspection, and restore/security barriers. It is not a mutable status flag:

```text
ABSENT
INITIALIZED
DATA_READY
DEPENDENCIES_HEALTHY
PROVISIONED
MIGRATION_REQUIRED
ENVIRONMENT_READY
STOPPED
DEGRADED
DRIFTED
```

`local up` reconciles forward only. An exact completed step is skipped; an exact idempotent partial step resumes; conflicting ownership, identity, policy, image, receipt, or binding evidence becomes `DRIFTED`. No reconcile path auto-drops a role/bucket, rewrites unrecognized data, loosens permissions, clears migration dirty state, adopts an unmatched baseline, or declares a non-ready restore barrier ready.

`INITIALIZED` includes the exact completed-wipe state: current configuration/bindings/payload epoch and protected future-provision credentials exist, both payload roots are proven empty, and no current-epoch dependency/schema readiness receipt exists. `ENVIRONMENT_READY` requires provisioned dependencies and a current compatible schema/ready external barrier; it does not mean the serving process is running. Human/JSON status always reports separate `environment_state` and `details.serve_state`. `STOPPED` is valid when durable bindings and receipts remain correct but dependency containers are intentionally stopped or remain stopped after Docker/host restart. A container found running without a correlated successful `local up` receipt for the current kernel boot ID and exact container start identity, bindings, images, advisory bundle, payload epoch, and secret generations is `DRIFTED`, never adopted. `DEGRADED` is transient dependency failure with readiness false. `DRIFTED` requires explicit diagnosis and governed corrective action.

Overlapping evidence uses this fixed first-match precedence: `DRIFTED` for unsafe/ambiguous binding, authority, policy, epoch, or mutation evidence; `DEGRADED` for exact cleanup-required, released-reserve, terminal dependency/runtime failure, or known incomplete accepted operation; `STOPPED` for otherwise exact intentionally stopped dependencies; `MIGRATION_REQUIRED` for healthy/provisioned dependencies with absent or behind schema; `ENVIRONMENT_READY` for a compatible ready external barrier; then `PROVISIONED`, `DEPENDENCIES_HEALTHY`, `DATA_READY`, `INITIALIZED`, and `ABSENT` in descending evidence order. An init bootstrap journal requiring resume is `DEGRADED`, not `ABSENT`; a conflicting journal is `DRIFTED`. Phase 1 uses one decision-table golden fixture for status, doctor, and JSON output.

## Locking and command coexistence

### Host locks

Each instance has fixed `lifecycle.lock` and `runtime.lock` files. Lock files are never removed during ordinary operation.

`central serve` holds `runtime.lock` exclusively and `lifecycle.lock` shared for its process lifetime. A second serve process therefore fails before listener or adapter construction. Every target-reading operation, including migration, backup, restore, bootstrap presentation rotation, and privileged doctor, takes lifecycle shared ownership so `local down` or wipe cannot change dependency storage beneath it. Snapshot-only unprivileged `local status` and `local security status` are explicit exceptions: they cannot traverse the lock root, take no lifecycle lock, report signed snapshot age, and make no atomic/current-state claim. `local init`, `local prepare`, `local security update`, `local browser clear`, every dependency-upgrade and local-maintenance phase, `local up`, `local down`, `local wipe`, dependency/TLS credential rotation, and other host-root/topology mutations take lifecycle exclusive ownership. Browser clear also takes runtime exclusive ownership and proves serving stopped. Upgrade apply/resume begins from a proven stopped target under lifecycle-exclusive ownership; once its bounded maintenance PostgreSQL becomes reachable, the controller acquires the common target-exclusive lock before any semantic probe or admitted client write and holds it through shutdown and the final receipt. Bootstrap presentation rotation is the sole credential mutation permitted alongside ready serving: it uses shared lifecycle/target ownership and the dedicated bootstrap binding/database-row locks defined above, and changes no dependency topology or adapter credential.

File locks are a host-side guard only. They do not replace the common PostgreSQL target-exclusion lock, migration-specific lock, exact operator-state ownership, or lock acquisition order accepted by Gate 7. A target operation acquires the host lifecycle mode first and then follows the Gate 7 order below; it never waits for a host lock while holding a PostgreSQL or object-store authority. A process crash releases the kernel lock; a PID file is never authority.

### Target lock matrix

Gate 8 preserves the Gate 7 matrix:

| Command/phase | PostgreSQL target lock | Host lifecycle relationship |
| --- | --- | --- |
| `serve` | shared for profile lifetime | shared lifecycle + exclusive runtime |
| snapshot `local status`, `local security status` | none; signed view only | none; explicitly lockless/non-current |
| `bootstrap show` | shared target; exclusive bootstrap row/generation rotation | shared lifecycle; ready serve required |
| `local browser clear` | exclusive through durable session/bootstrap revocation | exclusive lifecycle + exclusive runtime + stopped browser scope |
| `migrate verify`, `migrate status`, `restore verify` | shared for target-reading slice | shared lifecycle |
| `backup verify` | shared only when target-reading | shared lifecycle |
| `backup status/list`, `restore status` | none | shared lifecycle; protected-state/repository read |
| `backup export`, `backup export resume` | none | shared lifecycle + shared backup-repository lock |
| `backup import`, `backup import resume` | none | shared lifecycle + exclusive destination backup-repository lock |
| `backup delete/prune plan/apply` | none | lifecycle exclusive + exclusive backup-repository lock |
| `migrate up`, exact `migrate resume` | exclusive, then migration-specific | shared lifecycle |
| `backup create`, accepted-point `backup resume` | exclusive through verified seal | shared lifecycle |
| hard-expired rescue backup | exclusive through verified seal and dependency settlement | exclusive lifecycle; serving/browser/agents stopped |
| `restore apply`, pre-ready `restore resume` | exclusive through complete barrier | shared lifecycle |

Therefore backup creation does not run alongside `serve`; only the accepted read-only operations may coexist within the installation connection budget. The host shared lock asserts only that dependency topology/data roots remain stable; it grants no target coexistence. Backup create/resume takes the repository lock exclusively after common target exclusion; restore takes it shared after target exclusion and holds it through verification, so delete/prune cannot race either. Operations without a target lock acquire lifecycle, then protected operation ownership, then the repository lock. Local maintenance acquires lifecycle, affected secret binding locks in bytewise binding-ID order, then the repository lock, then audit ownership. No path waits for lifecycle/target ownership while holding a repository or binding lock, and no command upgrades a shared lock in place.

Offline credential rotation takes lifecycle exclusive ownership and requires serving to stop. It stages a new protected generation, applies the exact dependency-side change, verifies new access, atomically activates the generation, and revokes the old credential. Failure preserves exact resumable/repair evidence and never tries an alternate credential.

## Concrete backup, restore, and capacity realization

### Hard-expired offline rescue backup

When authority is hard-expired but the exact prior admission is otherwise valid and no signed deny applies, `central --config <absolute-config-path> backup create --security-rescue` may create exactly one rescue seal for the current payload epoch. It requires fresh PAM plus helper-owned confirmation, lifecycle and target exclusive ownership, stopped dependencies/serving/browser/agent execution, a proven clean prior dependency shutdown, and an existing current-epoch authoritative state chain. Before starting any daemon, the helper creates operation-owned cold-copy roots outside both authoritative payload roots, copies every PostgreSQL and MinIO file descriptor-relatively with no sparse/reflink/deduplication credit, synchronizes them, and completely rereads their ordered type/mode/size/SHA-256 inventories against the stopped source. Capacity admission charges source occupancy, three times every copied allocated byte (source read, copy write, copy verification read), the complete backup plan, reserve, and floor. A changed source, special/link entry, incomplete clean-shutdown evidence, mismatch, or insufficient capacity fails before the inherited backup accepted point.

The helper then starts only the already admitted digest-pinned PostgreSQL and MinIO identities with those verified disposable roots in a temporary no-egress maintenance topology; the authoritative payload descriptors are never mounted into a container or opened writable. Only the locked runtime backup coordinator may reach the copy endpoints. No migration, provision, repair, credential/image/policy change, application listener, bootstrap/session creation, or authoritative payload write is permitted. PostgreSQL client transactions are read-only for the dump and object storage grants only list/get/head; daemon-internal startup/WAL/statistics/metadata writes are confined to the cold copies. Dependency shutdown, copy cleanup in bounded quanta, and descriptor settlement are part of the same four-hour operation; cleanup failure is `CLEANUP_REQUIRED` and never invalidates an already committed rescue seal.

`backup security-rescue cleanup --operation=<id>` requires fresh PAM and accepts any authenticated rescue operation with a bound scratch root: pre-accepted/retryable, terminal, or seal-committed with `cleanup_pending`. Under lifecycle-exclusive ownership it first proves no rescue process/lock is active and commits the irreversible rescue transition `abandoned_for_cleanup` (or validates an existing terminal/seal state); that transition makes every backup retry/resume impossible. A signed deny or authority change may forbid rescue work but never this cleanup-only transition. The command cannot create/resume a dump, inspect application rows/objects, start a new dependency, alter a seal, or accept a root/path/force selector. The helper reopens the exact rescue binding, stops and reaps only operation-bound temporary containers if still recorded, proves their mounts released, then deletes `postgres/` and `minio/` descriptor-relatively in at-most-1,000-entry/64-MiB quanta. `central.security-rescue-cleanup/v1` advances through `accepted`, `abandoned_for_cleanup`, `stopping`, `mounts_released`, `deleting_postgres`, `deleting_minio`, `parents_synced`, and `complete`; each unlink/level synchronization and committed count/bytes precedes advancement. An interruption permits only the identical cleanup command and never re-enters backup work. Status/startup report the choice of exact rescue retry or cleanup before acceptance, and only `CLEANUP_REQUIRED`/cleanup after abandonment, terminal failure, or seal; ordinary init/up/serve/mutation remains blocked while scratch exists. Before removing `binding.json` and the synchronized empty operation directory, the helper commits the final binding digest/tombstone to the instance authority/audit stream outside the rescue root; that non-secret evidence survives scratch deletion.

The operation is rejected if another current-epoch rescue seal exists, identities drift, the copied database cannot prove read-only snapshot semantics, copied object evidence changes during inventory, or capacity/ordinary backup invariants fail. Ordinary seven-day throughput evidence is deliberately neither required nor refreshable: hard-expired policy forbids doctor write/throughput probes. Rescue planning instead uses the Phase 1 clean-host benchmark's fixed conservative 8 MiB/s lower bound over cold-copy plus backup work, requires the ordinary supported dataset/capacity ceilings and `predicted_elapsed <= 210 minutes`, and runs inside the fixed four-hour parent. Before the inherited Gate 7 accepted point, interruption is retryable without authoritative payload mutation and may clean/recreate only its exact cold-copy roots. At or after that point, rate failure, process/connection loss, cancellation, or deadline expiry is terminal and non-resumable under the unchanged Gate 7 rule; it leaves exact unsealed evidence, consumes no rescue seal, and a later new rescue operation is allowed only if no current-epoch rescue seal exists and all terminal/capacity evidence is exact. Its committed manifest and result are marked `security_authority_hard_expired` with the expired bundle/admission/time-evidence/cold-copy-inventory digests. It may be verified and exported under hard-expired policy, but import keeps the marker and restore verify/apply cannot issue/consume a ticket until a current signed authority explicitly admits the source and destination identities. Thus the mode preserves the newest durable bytes without turning stale authority into continued execution authority.

### Normative operator journeys

These transcripts are the supported product workflow. Angle-bracket values are safe opaque IDs or the trusted-TTY validated config path; commands never infer a target from another instance. `backup status` and `restore status` with no operation ID list at most the 20 most recently updated nonterminal operations for the selected instance, newest first, with operation ID, phase, resume/terminal classification, bounded progress, and exact catalog next command. Supplying `--operation` returns only that operation. `backup list` discovers sealed backup IDs. Status never creates, applies, resumes, or extends a ticket.

#### Complete local backup

```text
# stop central serve and wait for its exit 0 settlement
central --config <absolute-config-path> local status

# required only when doctor/status reports stale throughput evidence
central --config <absolute-config-path> local doctor --backup-throughput-probe

central --config <absolute-config-path> backup create --output=json
# => safe result identifies <backup-operation-id>, <backup-id>, sealed phase, and no resume

central --config <absolute-config-path> backup verify --backup=<backup-id> --output=json
central --config <absolute-config-path> backup list

# restart serving only after create released target-exclusive ownership
central --config <absolute-config-path> serve
```

Backup create itself seals only after complete verification; the explicit verify command is the portable/current-authority recheck used before migration, export, upgrade, or retention decisions. Neither command starts/stops `serve`. Attempting create while serving returns the bounded lock result and never signals or forces the process.

If backup create/verify exits `6`, the exact next journey is:

```text
central --config <absolute-config-path> backup status --operation=<backup-operation-id> --output=json

# only when status says resume_required=true
central --config <absolute-config-path> backup resume --operation=<backup-operation-id> --output=json
```

A pre-accepted acquisition or non-mutating verification phase may resume. Loss of the accepted-point exclusive connection makes create terminal/non-resumable as inherited from Gate 7; status then prescribes a new `backup create`, and the old unsealed subtree is eligible only for the explicit 24-hour maintenance flow. A new create never receives or reuses the old operation ID. If the original result was lost, ID discovery uses ID-less `backup status`; filesystem enumeration or guessed IDs is unsupported.

#### Verified in-place restore

```text
# stop central serve; keep exact dependencies healthy
central --config <absolute-config-path> backup list
central --config <absolute-config-path> restore verify --backup=<backup-id> --output=json
# => safe result identifies <restore-operation-id> and verified phase

# trusted interactive form; terminal displays safe backup/target/operation IDs
central --config <absolute-config-path> restore apply --operation=<restore-operation-id>
# type exactly: <restore-operation-id>

central --config <absolute-config-path> restore status --operation=<restore-operation-id> --output=json
# => safe result reports ready phase and no resume

central --config <absolute-config-path> serve
# terminal 2, only after readiness: open/verify page, then reveal
central --config <absolute-config-path> local browser open
central --config <absolute-config-path> bootstrap show
```

Restore verify/status remain automatable, but apply/resume never has a noninteractive production form. Fresh PAM and the helper-owned `/dev/tty` confirmation are mandatory; `--confirm-operation`, `--confirm-target`, `--yes`, redirected input, `--output=json` on apply, a backup ID as confirmation, an expired/replayed verify operation, or a target copied from another result is invalid. Verify is non-target-mutating but allocates the single-use 15-minute ticket; apply consumes that same operation at the accepted point. If the ticket expires before apply, the exact next command is a new `restore verify --backup=<backup-id>`, not apply/resume.

If apply exits `6`, the ticket has already been consumed and must never be verified/applied again. The only journey is:

```text
central --config <absolute-config-path> restore status --operation=<restore-operation-id> --output=json

# only when status says resume_required=true
central --config <absolute-config-path> restore resume --operation=<restore-operation-id> --output=json
```

Repeated resume is allowed only for that operation and its protected nonce/checkpoints. `verifying` or `quarantined` remains non-ready and status names the exact resume/review action; `MUTATION_INDETERMINATE`, terminal evidence, or the remediation threshold requires manual inspection, never a new apply or force-ready. After successful restore the security epoch has changed: all restored sessions/claims/leases are invalid, grants and SecretReferences remain suspended pending current-authority review, and the only login path is the fresh `bootstrap show` generation after `serve` is ready.

#### Fresh-host import and restore

```text
# after the prerequisite/helper administrative runbook
central local init
# => trusted TTY returns <new-absolute-config-path>
central --config <new-absolute-config-path> local trust install
central --config <new-absolute-config-path> local security update
central --config <new-absolute-config-path> local doctor
central --config <new-absolute-config-path> local prepare

central --config <new-absolute-config-path> backup import \
  --source=<absolute-export-directory> \
  --output=json
# after fresh PAM, enter the independently retained bx1 token at the helper prompt
# => safe result identifies <import-operation-id>, <backup-id>, and <new-instance-id>

central --config <new-absolute-config-path> local up
central --config <new-absolute-config-path> restore verify --backup=<backup-id> --output=json
central --config <new-absolute-config-path> restore apply --operation=<restore-operation-id>
# type exactly: <restore-operation-id>
central --config <new-absolute-config-path> restore status --operation=<restore-operation-id>
central --config <new-absolute-config-path> serve
# terminal 2 after readiness: launch/verify managed browser, then reveal
central --config <new-absolute-config-path> local browser open
central --config <new-absolute-config-path> bootstrap show
```

Import interruption uses only `backup import resume --operation=<import-operation-id>`. Restore interruption then follows the same status/resume transcript above. The destination remains the new instance with its new CA and dependency/application credentials; no transcript copies source config/protected state, runs `migrate up` before restore, bypasses the post-restore authority review, or starts serving before the ready barrier.

### Host tools and repository

Backup and restore execute on the host. PostgreSQL logical backup uses the absolute locked `pg_dump` 16.14 path with the fixed arguments `--format=custom --compress=zstd:3 --no-owner --no-privileges --no-tablespaces --dbname=central`; output is stdout through the coordinator rather than a caller-selected `--file`. The client installation must report zstd support. Restore uses one non-parallel `pg_restore` 16.14 process with `--format=custom --no-owner --no-privileges --no-tablespaces --exit-on-error --single-transaction --dbname=central`; the Gate 7 database replacement/verification protocol owns target creation and no `--clean`, `--create`, caller filter, or parallel job is allowed. Object bodies and inventories flow through the S3 adapter using the dedicated backup or restore identity. No operator mode calls `docker exec`, mounts the Docker socket, reads PostgreSQL physical files, or uses a MinIO container console.

### Secret-aware PostgreSQL tool adapter

`pg_dump` and `pg_restore` run only through registered adapter `pg_tool_memfd_v1`. Infrastructure-generated PostgreSQL passwords are 256 random bits encoded as unpadded base64url and therefore contain no colon, backslash, newline, NUL, or whitespace. The adapter still applies the libpq passfile encoder and rejects any encoded record containing more or less than one newline-terminated record. Dump resolves only the backup/read purpose under `central_runtime`; restore resolves only the migration/restore purpose under `central_migration`.

Inside the protected-use callback, the authenticated root broker resolves the exact purpose once, creates `memfd_create(MFD_ALLOW_SEALING|MFD_CLOEXEC)`, sets mode `0600`, writes exactly `127.0.0.1:55432:central:<fixed-role>:<encoded-password>\n`, seeks to zero, and applies `F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`. It transfers that one sealed descriptor over the authenticated runtime session with SCM_RIGHTS and clears broker buffers. No pipe/plaintext crosses operator UID and no broker-root descriptor is exposed.

The runtime coordinator remains the process parent. It forks one child, creates a new process group, duplicates only the sealed passfile to fixed descriptor 3 with close-on-exec cleared in the child, sets `PGPASSFILE=/proc/self/fd/3`, closes every other unauthorized descriptor, and execs the exact root-owned tool. The coordinator closes its copy immediately after successful fork and owns pidfd, wait/reap, cancellation, and final status. The tool can reopen only its own sealed descriptor; protected `/proc`, non-dumpable runtime, distinct UIDs, and no sibling runtime tools prevent another process from reading it. Phase 1 proves unrelated operator/agent/browser processes and a sibling child cannot open the descriptor. If procfs, memfd sealing, fixed-child inheritance, or permission behavior differs, the profile fails before spawn; there is no disk-passfile, URI, stdin-password, `PGPASSWORD`, or interactive fallback.

The tool receives a newly constructed environment containing only `LC_ALL=C`, `TZ=UTC`, the fixed passfile pseudo-path, a safe operation-bound `PGAPPNAME`, `PGCONNECT_TIMEOUT=5`, and one exact mode-specific `PGOPTIONS` value. Dump uses `-c statement_timeout=<remaining-dump-operation-ms> -c lock_timeout=30000 -c idle_in_transaction_session_timeout=60000`, where the generated integer is positive and clipped to the remaining two-hour parent. Restore uses `-c statement_timeout=1800000 -c lock_timeout=30000 -c idle_in_transaction_session_timeout=60000`; each statement is therefore bounded to 30 minutes inside the four-hour restore process. A remaining dump budget below the 30-second lock bound fails before spawn rather than setting zero/unbounded timeout. It receives explicit non-secret host/port/database/role/`sslmode=disable` arguments. `HOME`, `PATH`, `PGSERVICE`, `PGSERVICEFILE`, proxy variables, caller `PG*`, and every inherited descriptor other than required archive/stdout/stderr pipes are absent. `pg_dump` writes the archive only to its bounded stdout pipe; `pg_restore` reads it only from bounded stdin, so no backup path enters argv or environment.

The already-budgeted target-lock control connection polls `pg_stat_activity` without opening a third session and requires exactly one new backend matching operation-bound application name, fixed role/database, loopback source, and child start window. Observation must occur within the 30-second startup dependency deadline. On that proof—or authentication/tool failure—the broker session records use completion and no passfile descriptor remains outside the tool. The protected-use callback does not return until authenticated-session acceptance and broker completion, so broker plaintext state never outlives the SecretMaterial dynamic extent; the long dump/restore continues only on the authenticated connection while the runtime parent reaps it. Missing, duplicate, wrong-role, or disappearing-before-acceptance sessions cancel the process group and fail closed.

The coordinator owns a pidfd/process group, finite stdin/stdout pipes, cancellation, and the applicable dump/restore deadline. It closes pipes, sends graceful termination then bounded kill, waits/reaps every descendant, and does not release the offline permit until tool, broker, descriptors, and session are gone. Stderr passes through a source-specific bounded parser that maps allowlisted PostgreSQL diagnostics to safe codes and otherwise emits one redacted class; raw stderr/stdout, argv, environment, passfile record, process dump, or crash artifact is never logged. Broker/tool crash leaves no filesystem residue because the kernel destroys the pipe and memfd. Counting-transport conformance proves one secret resolution, broker handoff, tool exec, and database authentication across success, auth failure, timeout, cancellation, panic, and process loss.

The backup repository is an instance-bound authoritative, non-operator-searchable host directory. Every process touching it starts with umask `0077`; every backup/export/import/dump/body/inventory/temporary/quarantine/restore-spool file is create-only `0600` beneath a `0700` directory, and owner/mode are revalidated before reuse, sealing, or movement. Every backup is self-contained beneath one create-only opaque `backup-id`; no body is shared or deduplicated across backups. Immutable inventory chunks and root manifests use canonical encoding, create-only identities, SHA-256 verification, atomic authoritative checkpoints, and the broker transition/seal contract. The repository manifest binds opaque target/instance identity, safe configuration digest, tool/dependency versions, and repository format. Secret values and protected binding locators are never backup content.

Each inventory record binds the source object identity and immutable Artifact evidence to expected byte size, SHA-256, and its relative body path under that exact backup. Original object keys remain protected manifest data and never appear in a filesystem pathname or generic output. The body namespace is content-addressed only within one backup. Two inventory records with the same size and SHA-256 may reference the same body in that backup after the existing body is fully reverified; no reference can resolve outside its backup root.

Body copy is streaming and create-only. The coordinator writes one same-directory temporary file beneath the destination hash shard, enforces the expected byte count while computing SHA-256, synchronizes it, rejects any mismatch, and atomically renames it to the final hash path without replacing an existing entry. An existing final path is reusable only after no-follow open, regular-file/owner/mode validation, and complete size/checksum verification. The inventory chunk that references a body commits only after the final body exists and verifies. The database dump follows the same temporary, bounded-write, synchronization, and create-only publication discipline.

Object transfer uses one installation-wide backup/restore worker, one reusable 256 KiB copy/checksum buffer, and at most one open source body, destination body, temporary file, or multipart upload. Restore uses fixed 16 MiB multipart parts with upload concurrency one and at most one resident part; bodies below the SDK's locked multipart threshold use one streaming PUT with no whole-object buffer. The S3 adapter must prove these settings rather than accept SDK defaults. Backup has no additional spool beyond its one same-directory destination temporary; restore reads directly from the verified backup body and creates no host body spool.

Every body has a 30-second idle-I/O deadline and a 30-minute elapsed deadline bounded by the enclosing backup or restore operation's remaining two-hour or four-hour budget respectively. Reads and writes update SHA-256 and exact byte counts incrementally; declared size is enforced before one byte beyond it is accepted. An attempt retries at most twice (three total attempts), always from byte zero, and only after the prior GET/temporary file or multipart upload is closed and its exact cleanup/abort is proven. A timeout/cancellation/short read before durable publication may retry the same immutable identity. An ambiguous multipart completion performs one bounded HEAD verification: exact destination identity/size/checksum is success, absence permits a fresh attempt after abort proof, and any mismatch or unknowable outcome enters quarantine without retry. No retry reuses an upload ID, partial file, staging generation, mutable source observation, or already-consumed deadline.

`root-manifest.json` plus `root-manifest.auth.json` is the final seal. The manifest binds the ordered inventory-chunk identities and digests, database dump identity/size/digest, aggregate record/body bytes, backup/config/target/payload-epoch/tool versions, and Gate 7 accepted-point evidence. After every referenced file is reverified, the runtime passes read-only descriptors plus the canonical manifest candidate to the broker; the broker independently rereads the complete tree and executes the generic prepared/issued/published/committed authority protocol above. Only the exact committed `central.backup-seal/v1` companion is authenticity authority. Public SHA values detect transport error but are never authenticity authority. An absent, uncommitted, or mismatched broker seal is never restorable. A later wipe does not invalidate the sealed source; restore creates a new ticket that records source and destination payload epochs and applies the full authority reset.

A crash may leave a partial temporary file or a committed body not yet referenced by a sealed root. While the original create process continuously retains its accepted-point exclusive connection, internal slice continuation discards only its own partial temporary, revalidates the last committed checkpoint/body/chunk, and continues with the same backup ID. Process/connection loss after that accepted point is terminal and non-resumable as required by Gate 7; `backup resume` is limited to pre-accepted acquisition and non-mutating verification phases. No path adopts another operation's file or forks the manifest. Terminal incomplete-operation cleanup may unlink only files beneath that exact unsealed backup after repeated operation/binding/reference proof and parent-directory synchronization.

### Portable export and fresh-instance import

The v1 backup is portable application data, not a machine image. It contains the sealed logical database dump, complete backup-local Artifact bodies/inventories, source schema/dependency/config compatibility evidence, and public integrity metadata. It never contains PostgreSQL/MinIO passwords, SecretReference values or locators, TLS/CA private keys, bootstrap/session/CSRF material, helper authority, host bindings, operator audit, or raw payload directories. Copying an instance state/config/data tree is not a supported recovery method.

The exact portable flows are:

```text
central backup list [--cursor=<opaque-cursor>]
central backup export --backup=<backup-id> --destination=<absolute-empty-directory>
central backup export resume --operation=<operation-id>
central backup import --source=<absolute-export-directory>
central backup import resume --operation=<operation-id>
central backup delete plan --backup=<backup-id>
central backup delete apply --plan=<plan-id>
central backup prune plan
central backup prune apply --plan=<plan-id>
```

`backup list` holds the repository lock shared and returns at most 100 entries ordered by seal time then backup ID, with only opaque ID, sealed/incomplete state, UTC time, aggregate bytes/records, compatibility class, reference/export status, and opaque cursor. It emits no object key, path, filename, credential, binding locator, or unrestricted manifest field.

Export holds the repository lock shared, completely reverifies one sealed backup, and writes one create-only directory named `central-backup-v1-<backup-id>` below a no-follow-opened empty destination. The supported destination is an operator-owned `0700` ext4 filesystem on an already mounted LUKS2/dm-crypt device, distinct by mount/handle from every Central/Workspace root; Central verifies that boundary but never receives, stores, or manages the media recovery key. Files retain the backup-relative layout, `0600` modes, bounded names, and synchronized create-only publication. Export has one 256-KiB buffer, the same byte/deadline/capacity guards, no Docker/helper/network authority, and cannot follow links or overwrite any entry.

The final `central.backup-export/v1` manifest lists every allowed relative file, type, exact size and SHA-256, original broker backup-seal/key version, aggregate count/bytes, format/schema/tool compatibility fields, export ID, and UTC creation time. The broker owns a per-instance Ed25519 export-signing generation unavailable to operator/runtime files. It rereads every export descriptor and signs the domain-separated RFC 8785 manifest. ADR 0009 defines `bx1:<export-key-id>:<public-key>:<manifest-digest>:<signature>` as the sole public export-authority token exception to Gate 7's generic checksum-output rule. After fresh PAM the broker/helper writes it once through the exclusive physical-seat TTY; it never crosses controller JSON/log/audit/HTTP or any operator-writable token file. The supported operator retains it on non-digital paper or a separately administered root-protected recovery store; ordinary operator-owned media is not independent authority.

Fresh-host import accepts the expected `bx1` token only through the same fresh-PAM exclusive helper TTY, never a flag, environment, stdin redirection, file, export tree, or JSON input. It verifies token syntax, public-key/key-ID binding, Ed25519 signature, complete tree, and original backup MAC evidence before repository mutation. An absent/mismatched token, changed key/signature, extra/missing entry, link/special file, duplicate/case-colliding name, mode/owner/size/digest mismatch, unsealed root, unsupported format, or changed file fails. Export confidentiality still relies on encrypted media; authenticity against same-UID rewriting relies on the independently retained broker token.

Fresh-host recovery starts with the supported prerequisite/helper installation and a brand-new `central local init`; this generates a new instance ID, bindings, CA/leaf, infrastructure/application credentials, security epochs, and bootstrap state. After `trust install`, `security update`, and `prepare`, import targets only that explicitly selected fresh instance. The instance must have no completed application migration, Artifact, Task/Run, prior import, or non-bootstrap user data. Import never adopts the source instance ID or changes the destination config.

Import opens the export read-only with the same descriptor/mount rules, verifies the caller's independently retained public integrity token and complete tree twice, then copies it under the destination repository's exclusive lock into one create-only backup ID using bounded streaming and capacity guards. It publishes a `central.backup-import/v1` rebind receipt only after rereading the destination. The receipt preserves source instance/target/config identities as non-authoritative lineage and binds them to the new destination instance/target/bindings, new credential/security generations, current dependency/schema compatibility result, original export/root digests, and import operation. No source credential, trust anchor, receipt, or active pointer is copied or made current.

The imported backup remains non-restorable until the existing Gate 7 restore plan issues a fresh destination-bound ticket. Restore applies the inherited full barrier and, at its commit, rebinds application data to the destination target, rotates/resets external capability and security epochs, invalidates every imported bootstrap/session/CSRF/external-execution authority, preserves Artifact lineage IDs, and verifies every database/object invariant. Destination infrastructure/application credentials and TLS identity remain the newly generated ones. The operator then follows the exact `local up`/restore verification/migration-if-required/`serve`/`bootstrap show` journey; bootstrap is never automatically revealed or re-enabled. A source schema/dependency outside the supported restore/migration matrix is `INCOMPATIBLE` or `UPGRADE_OUT_OF_PLACE_REQUIRED`, not an identity relaxation.

Export/import crash state is bound to its exact operation, source/destination descriptors, public tree integrity token, byte checkpoints, and created entries. Resume accepts only the same evidence and never overwrites. Abandonment can remove only the operation-owned unsealed export/import subtree after exact proof; a sealed export or published imported backup uses the deletion policy below.

### Backup and protected-state maintenance

No backup or protected evidence is deleted automatically. The supported repository ceiling is 16 sealed backups and 256 GiB of sealed plus unsealed content per instance, while ordinary capacity floors still apply first. `backup create` fails before its accepted point with `MAINTENANCE_REQUIRED` when the new conservative plan could cross either ceiling. Repository manifest/accounting is recomputed from exact entries and cannot trust cached totals.

`backup delete plan` creates a 15-minute protected plan for exactly one sealed backup; `backup prune plan` selects only sealed backups older than 30 days while retaining at least the newest three. Both hold the repository lock exclusively while snapshotting candidates and include exact backup/root/export/import digests, bytes, reference graph, mount/binding evidence, plan time/expiry, and post-delete totals. A backup referenced by active/incomplete restore, upgrade, export/import, or another protected operation is ineligible. Plan commands are dry-run only and list bounded opaque IDs and totals.

Delete/prune apply requires lifecycle-exclusive ownership, repository-exclusive ownership, the exact unexpired unchanged plan, fresh PAM, and the helper-read confirmation of full plan ID plus aggregate candidate count and bytes. There is no `--yes`, force, glob, age override, path argument, or automatic high-water deletion. Apply renames each exact eligible backup to an operation-owned quarantine name in the same repository, synchronizes the parent, removes only descriptor-relative verified entries, synchronizes each level, and records each committed removal. After a crash, repeating the identical apply command requires fresh authentication and resumes the same plan from its protected checkpoint even if its wall-clock expiry has since passed; only a plan accepted before expiry is resumable. It never restores a partially deleted backup or selects a replacement candidate.

Terminal unsealed backups/exports/imports become maintenance-eligible after 24 hours only when no resumable operation, lock holder, checkpoint, restore/upgrade reference, or published seal exists. `central local maintenance plan` additionally selects retired/abandoned secret generations only under the existing one-day candidate/seven-day retired exact-reference rules, and completed operator-audit records only when older than 365 days and not among the newest 10,000 records. Audit records are bounded to 8 KiB each and the supported audit root is at most 100,000 records/1 GiB; incomplete, destructive wipe, trust/security, backup deletion, restore, or upgrade evidence is retained while referenced regardless of age.

`central local maintenance apply --plan=<plan-id>` requires lifecycle exclusive plus all affected binding/repository locks in canonical order, a 15-minute unchanged plan, fresh PAM plus helper-read confirmation of full plan ID/count/bytes, and create-before-delete audit evidence. It deletes only plan-enumerated unsealed operation subtrees, tombstoned/unreferenced secret generations/journals, and eligible audit records using descriptor-relative synchronized steps. Any new reference, changed identity, active process, ambiguous record, or lock timeout invalidates the complete plan before deletion. After its accepted point, an identical apply with fresh authentication resumes only its durable per-entry checkpoints without reselecting candidates. Maintenance never touches a sealed backup, active/revoked-pointer secret, current TLS anchor/key, incomplete audit, Event, database/object payload, or exported media.

Every accepted delete/prune/local-maintenance apply creates `operations/maintenance/<operation-id>.json` with schema `central.local-maintenance-operation/v1`. The monotonic record binds operation/plan/instance/config/payload-epoch/repository/broker-authority identities; phase `accepted`, `quarantining`, `deleting`, `protected_cleanup`, `audit_cleanup`, `settling`, or `terminal`; ordered candidate-set digest; current candidate ordinal and descriptor identity; committed count/bytes; per-entry rename/unlink/directory-sync checkpoint; PAM confirmation identity; safe failure class; and prior-record digest. The accepted record is synchronized before the first quarantine rename or protected tombstone cleanup. Each entry checkpoint is synchronized before advancing. Startup never replans: it resumes the exact chain or fails `MUTATION_INDETERMINATE` on changed reference, missing predecessor, or observed deletion ahead of evidence.

Restore reads only one sealed backup. For each inventory record it streams the referenced body, rechecks the backup file's size/SHA-256, materializes the exact destination object without overwrite, and then performs the inherited second destination verification before reconciliation may advance. An already-present destination is accepted only when its immutable identity, size, and checksum match; a conflict enters the inherited quarantine path. Missing, cross-backup, unsealed, changed, or extra unreferenced backup data never becomes restore authority.

The Gate 7 accepted-point, exact-operation IDs, status/resume semantics, ticket lifetime, confirmation, full inventory verification, quarantine, authority reset, and restore/security epoch barrier remain unchanged. The installed restore ticket lifetime is 15 minutes; backup exclusive elapsed deadline is two hours; hard-expired rescue is four hours; restore is four hours; prepare is 20 minutes; throughput probe and browser clear are five minutes each; export, import, and accepted maintenance apply are two hours each; inventory work yields after 100 pages or five minutes. Every fetch, build vertex, tool, body, file, delete quantum, verification, retry, cleanup, and settlement deadline is clipped to the remaining parent time. Parent expiry stops new work, synchronizes the last durable checkpoint, closes children/descriptors/locks, performs only bounded operation-owned cleanup, and returns exact resume or terminal evidence; it never retains a lifecycle/repository lock indefinitely or resets elapsed time on resume.

### Capacity evidence and formulas

Capacity is checked per `statx`/mount-identified filesystem device, not per configured directory. Requirements whose roots share one device are aggregated once with checked unsigned arithmetic. Every check records safe device identity, available bytes, committed/remaining bytes, evidence timestamp, reserve state, and formula version; it records no raw path in generic output. A capacity estimate is admission/planning evidence, never described as a logical-dump or restored-database upper bound.

Every device writable by backup or restore maintains one non-sparse 4 GiB survival-reserve file in the lexicographically first locked-runtime-owned authoritative root on that device. `local init/up` creates it with create-exclusive allocation, verifies allocated blocks/mount identity, mode `0600`, owner, size, broker-MAC receipt, and never counts those blocks as available capacity. A device also retains a 1 GiB ordinary free-space floor. Backup/restore cannot start while the reserve is absent, sparse, shared, changed, or previously released. On low-space or dependency-health failure, the coordinator first cancels its process group/transfers, synchronizes checkpoints, then atomically marks and releases only its bound reserve to make 4 GiB reclaimable for dependency settlement. A released reserve makes the environment `DEGRADED`/`cleanup_required`; no further mutation runs until dependencies are healthy and the reserve is re-created and reverified.

Backup accepted-point evidence records PostgreSQL heap, TOAST, index, total relation, and database physical bytes separately; total included Artifact bytes; inventory record count; and current device occupancy. These are planning signals only. Because v1 performs no cross-backup deduplication, the plan charges the full sum of every inventory object's bytes and credits neither another backup nor prospective within-backup deduplication.

The two-hour supported backup profile is the inherited Gate 7 fixture capped at 5 GiB PostgreSQL physical database bytes, 10 GiB included Artifact bodies, 10,000 inventory records, and the inherited 4-GiB per-object hard maximum. Exceeding any profile ceiling returns the successful diagnostic state `OUTSIDE_SUPPORTED_PROFILE` before the target accepted point; Phase 1 provides no override that weakens the deadline. A later larger profile requires benchmark and design review.

Ordinary admission requires a successful same-instance `central local doctor --backup-throughput-probe` receipt no older than seven days and bound to CPU/RAM profile, device/mount identities, PostgreSQL/MinIO/tool/image/config/policy digests, and transfer-envelope version. The explicit mutation-audited probe has a five-minute parent. Under the same target lock and tool adapter as backup, a scoped provisioner creates one operation-named disposable probe database outside the application database, loads deterministic seeded incompressible rows from the reviewed fixture, and runs the pinned `pg_dump --format=custom --compress=zstd:3`; the accepted archive is at least 512 MiB and at most 544 MiB or the fixture/tool identity is incompatible. It writes that archive into an operation-owned repository temporary, synchronizes and completely rereads/verifies it, then drops only that descriptor/operation-bound database. It separately creates one fixed 512 MiB reserved `v1/system/` incompressible probe object, measures S3 read → repository temporary write → synchronized reread/checksum, and removes the exact object/file. No application row or schema object is created or read. Fixture generation/load time is reported separately; the accepted rates cover the complete dump/publication/reread and object read/write/reread paths. Incomplete cleanup is `CLEANUP_REQUIRED`. The receipt records only bounded aggregate stage bytes/durations and measured end-to-end rates.

The accepted minimum is 16 MiB/s for both the representative custom-dump/publication/verification path and combined object/repository path on the reference host. Phase 1 includes a fixture where synthetic `COPY` exceeds 16 MiB/s but compressed `pg_dump` does not and requires admission to fail. Preflight computes conservative work rather than source size:

```text
backup_work_bytes =
  2 * database_dump_estimate       # archive write + complete verification read
  + 3 * artifact_object_bytes      # S3 source read + repository write + verification read
  + inventory_bound

predicted_elapsed = ceil(backup_work_bytes / min(probe_database_rate, probe_object_rate))
```

Acceptance requires `predicted_elapsed <= 90 minutes`, leaving 25% of the two-hour deadline for lock acquisition, inventory queries, checkpoints, fsync, retries, and variance. Missing/stale/mismatched probe evidence returns exit `3`/`THROUGHPUT_EVIDENCE_REQUIRED` with the exact doctor command; a measured rate below 16 MiB/s or prediction above 90 minutes returns exit `5`/`DEADLINE_NOT_PLAUSIBLE`. Neither allocates the backup accepted point. After acceptance, every checkpoint recomputes actual completed rate and remaining work from `verified_dump_bytes` and committed object bytes. If the remaining deadline is no longer plausible, the operation stops at the next safe durable boundary as class `6`; it never extends the deadline or accelerates by increasing concurrency.

The initial backup plan is:

```text
database_dump_estimate = max(database_physical_bytes, 1 GiB)  # planning only

inventory_bound =
  inventory_record_count * 4 KiB
  + ceil(inventory_record_count / 1,000) * 64 KiB
  + 1 MiB

initial_repository_plan =
  database_dump_estimate
  + artifact_object_bytes
  + inventory_bound
  + 1 GiB ordinary free-space floor
```

After the accepted point, `pg_dump` stdout is copied through one 256 KiB buffer into the create-only temporary archive while computing SHA-256. Before each at-most-8-MiB write quantum the coordinator revalidates mount identity and available blocks; it cancels before crossing the ordinary floor. The completed file is synchronized, published create-only, completely re-read/verified, and its actual byte count—not physical database size or the planning estimate—becomes `verified_dump_bytes`. Only then does backup recompute the exact remaining repository requirement as full remaining object bytes plus inventory bound plus the free floor. Each object receives the same pre-write/recheck guard. An unexpectedly large dump may therefore terminate the unsealed operation safely; no multiplier promises completion.

Restore admission uses only sealed evidence and separates every occupancy class:

```text
postgres_planning_bytes =
  backed_up_heap_bytes
  + backed_up_toast_bytes
  + backed_up_index_bytes
  + 2 GiB WAL allowance
  + 1 GiB temporary-file allowance
  + max(512 MiB, ceil(0.10 * backed_up_relation_bytes)) catalog/other allowance

object_planning_bytes =
  2 * exact_bytes_to_materialize
  + 16 MiB one-part memory/metadata allowance

shared_device_plan =
  sum(postgres_planning_bytes, object_planning_bytes)
  + 1 GiB ordinary free-space floor
```

Existing target occupancy is never credited as future free space before the destructive accepted point and is recorded separately as `old_target_bytes`; the approved fresh-instance/out-of-place protocol adds old and new occupancy on every shared device rather than reusing this formula. `exact_bytes_to_materialize` is the full sealed object sum unless the restore adapter completely verifies an existing immutable destination. `verified_dump_bytes` and all other sealed-backup files are recorded as existing read-only occupancy and retention evidence. Because `statfs` available bytes already excludes their allocated blocks and `pg_restore` streams the archive without another full copy, they are not incremental writable-byte demand. A future phase that materializes a second dump copy must add only that proven copy to the formula. Phase 1 includes a shared-device fixture whose exact free space passes this incremental formula but would fail the former double-counted formula and verifies actual peak allocation remains within admission evidence.

During the single-job restore, the coordinator polls device/mount/free-space and dependency health at least once per second and at every phase/checkpoint; PostgreSQL installs the separate WAL/temp limits defined by the resource envelope. Crossing the ordinary floor cancels the process group and releases the survival reserve as above. A partial database remains behind the Gate 7 non-ready restore barrier with exact failure/resume-or-replace evidence; it is never reported ready or blindly retried. Object materialization checks before each bounded part/write and cannot enter the survival reserve.

Missing/overflowed/stale evidence, changed mount/device/binding/reserve, insufficient planned bytes, or a failed recheck immediately before the restore accepted point is exit class `5` without mutation. Growth beyond the non-authoritative plan after acceptance is exit `6` with durable partial-operation evidence and released-reserve status where applicable. Central never deletes backup, Artifact, staging, database, or unrelated data to manufacture capacity.

### Deadline nesting and blocking-resource release

All installed deadlines are elapsed monotonic process bounds clipped by any earlier durable authority/database-time deadline. PostgreSQL 16 has no server `transaction_timeout`; adapters therefore start every transaction with a context deadline, set local `statement_timeout`, `lock_timeout`, and `idle_in_transaction_session_timeout`, cancel on expiry, and prove rollback/connection discard before releasing a pool permit. A connection whose cancellation/rollback outcome is unknown is destroyed, never returned to a pool. Maximum connection lifetime applies only when an idle connection returns to the pool and never terminates an in-use transaction.

| Work class | Admission/acquire | Lock | Statement or I/O idle | Transaction/phase | Parent total |
| --- | ---: | ---: | ---: | ---: | ---: |
| non-streaming HTTP | 2 s | 5 s DB maximum | 30 s body + 30 s response | 30 s DB transaction | 65 s route after admission begins |
| Artifact HTTP stream | 5 s | 5 s DB metadata | 30 s stream idle | bounded metadata transactions 30 s | 30 min Artifact operation |
| runtime/outbox/cleanup | 2 s pool | 5 s | 30 s | 30 s | earlier command/lease/settlement authority |
| terminal settlement | 2 s dedicated pool | 5 s | 25 s | 30 s | 30 s settlement grace; acquisition consumes it |
| read-only status/verify | 2 s pool | 5 s | 30 s | 30 s | command 60 s |
| migration lock acquisition | 2 s pool | target 30 s then migration 15 s | 5 min per approved batch | 5 min per batch | installed 45 s total acquisition (Gate 7 hard 6 min); durable operation owns later batches |
| backup dump/body | permit before spawn | target 30 s | body idle 30 s; dump statement/process clipped to remainder | no controller transaction across external I/O | 2 h accepted operation |
| restore apply | permit before spawn | target 30 s | body idle 30 s; each restore statement at most 30 min | one `pg_restore --single-transaction`, process-enforced 4 h | 4 h accepted operation |
| dependency health | none | none | 2 s probe | none | cadence every 5 s; no overlapping probe |
| startup dependency | 2 s connection attempt | 5 s | 5 s semantic probe | 30 s complete startup dependency phase | 30 s |

For HTTP, header read completes within five seconds before admission; the 65-second route total contains the two-second admission wait, a worst-case 30-second body read, and 30-second buffered response write with three seconds cancellation/closure margin. Artifact byte streaming never inherits the non-streaming write timeout and instead uses its idle/total pair. Database pool acquisition, lock wait, statement execution, and rollback all consume—not extend—the enclosing route/operation deadline.

The 30-minute pool connection lifetime uses deterministic per-instance jitter in `[0, 3 minutes]` derived from connection ordinal to prevent synchronized churn; idle/lifetime checks occur at most every minute. Health probes never queue: if the prior two-second probe has not returned, the next cadence records one timeout rather than opening another connection. Every timeout path closes request bodies, response writers, rows, transactions, object bodies, multipart handles, subprocess groups, and permits in reverse order, with leak/saturation tests proving the next waiter can progress.

## Health, retry, restart, and shutdown

### Three health layers

Container health uses credential-free probes: `pg_isready` for PostgreSQL and the MinIO readiness endpoint. The Compose health deadline is two minutes. Each logical provisioner has a two-minute deadline and emits a canonical receipt only after semantic verification.

Provisioned-dependency readiness additionally verifies the exact instance/config/image/current-payload-epoch receipt, current kernel boot ID and container start identities from the successful `up` receipt, database/schema/role identity, bucket identity, policy digest, and runtime credential metadata. Central readiness additionally requires no incomplete wipe, protected state, current schema, ready restore/security epochs, startup reconciliation, required pools/adapters, target shared lock, and every enabled component.

`local status` reports container health and receipt state. `local doctor` performs semantic read-only checks. `central serve` marks readiness false immediately when a required semantic dependency fails.

### Retry and process outcome

Startup dependency connection has a 30-second installed deadline. Classified transient dependency failures after readiness use exponential backoff from 250 ms to five seconds with jitter. Readiness remains false immediately; the installed transient budget is 60 seconds before the failure is classified terminal. The configurable retry budget has a five-minute hard ceiling; that ceiling is not an additional period in which a failed serving process remains nominally alive.

Loss of the lifetime PostgreSQL target-lock control connection, an incompatible schema/barrier, protected-state corruption, or a terminal component failure is not retried as an ordinary dependency outage. It cancels the profile and exits through the Gate 7 outcome.

`central serve` preserves these stable exit classes:

| Exit | Meaning |
| ---: | --- |
| 0 | intentional stop after durable settlement obligations |
| 2 | invalid invocation or configuration |
| 3 | required dependency unavailable during startup |
| 4 | startup target-lock, pool, or bounded-preflight timeout |
| 5 | dirty/incompatible schema or missing/corrupt/non-ready/mismatched restore barrier |
| 6 | terminal runtime component failure, indeterminate process state, failed settlement evidence, or total-shutdown timeout |
| 7 | denied or insufficient authority |

A dependency lost after readiness that exhausts its finite retry budget exits `6`, never startup class `3`. Local-environment commands use symbolic `central.local-result/v1` reason codes; they do not redefine the established migration or operator-mode result schemas/classes.

### Shutdown and container restart

At shutdown Central marks readiness false, stops HTTP intake, new claims, and new external invocation, then receives the Gate 7 30-second settlement grace to persist known or ambiguous effect outcomes. Background components checkpoint or hand off leases, then adapters, control connections, and pools close in reverse order. Total shutdown defaults to 45 seconds and cannot be shorter than settlement grace or exceed three minutes. An intentional signal exits `0` only when these obligations complete; otherwise the relevant failure exits `6`.

PostgreSQL has a 60-second Compose stop grace; MinIO has 30 seconds; `local down` has a 90-second total deadline. Dependency forced termination is treated as a crash and requires recovery probes on next `local up`. Every Compose service has `restart: "no"`; dependency exit, Docker restart, and host reboot leave it stopped until the explicit validated `local up` path. Central has no Compose restart policy; a future host supervisor may restart only according to the stable exit classes and cannot start dependencies.

## Observability and operator audit

`central serve` emits structured JSON to stderr and does not own file rotation. Local commands use the two diagnostic planes and embedded remediation catalog above; `--output=json` always selects the machine plane. Every generic observation uses a timestamp, severity, component, stable event/reason code, opaque instance binding, catalog version/entry where applicable, and correlation identity.

No machine/generic observation contains plaintext secrets, bootstrap/session/CSRF tokens, credentials, command environment, raw paths, raw object keys, raw filenames, SQL text/parameters, backend locators, unrestricted request/response bodies, or unbounded labels. The sole path exception is the validated bounded trusted-TTY diagnostic plane; all other prohibited classes remain prohibited there too. Source-boundary redaction occurs before generic logging/error handling.

The generic ready endpoint may use only bounded reason classes such as `STARTING`, `CONFIG_INVALID`, `PROTECTED_STATE_INVALID`, `POSTGRES_UNAVAILABLE`, `POSTGRES_INCOMPATIBLE`, `OBJECT_STORE_UNAVAILABLE`, `OBJECT_STORE_INCOMPATIBLE`, `MIGRATION_REQUIRED`, `LEASE_LOST`, `BACKGROUND_LOOP_FAILED`, and `SHUTTING_DOWN`. It exposes no dependency address, path, credential, schema detail, or operation evidence.

The fixed local metric registry additionally exposes only these bounded maintenance signals: `central_security_authority_seconds_until_expiry` (negative when stale), `central_security_authority_state` with one fixed state label, `central_backup_repository_ceiling_ratio`, `central_operator_audit_ceiling_ratio`, `central_capacity_survival_reserve_released` as 0/1, `central_cleanup_required` as 0/1, and `central_dependency_retry_terminal_total` with one fixed dependency-class label. Trusted TTY status warns at advisory 72/24/6-hour thresholds and at repository/audit 75%/90% thresholds. Metrics perform no dependency I/O, unbounded scan, or per-instance label emission; values come from bounded current receipts/accounting.

Every local mutation creates one atomic `0600` authoritative audit record before its first semantic/configuration/credential/payload mutation and finalizes it after outcome. `local init` uses the pre-existing root helper intent-audit boundary above; every other audit record lives in non-operator-writable `central-state`. Records include command, operator UID, PAM authorization class where applicable, start/update/end time, opaque instance/target/config identities, accepted-point state, safe result code, and receipt/operation references. Each record and prior-chain head receive a broker HMAC; changed, missing, reordered, or recomputed public JSON is invalid. A crash leaves `incomplete` evidence for later classification. Audit remains after `local wipe`, is not backup/export content or authoritative application Event history, and is reclaimed only through the fresh-PAM maintenance protocol.

## Developer and test workflow

The normative operator workflow index is:

| Journey | Authoritative command/contract section |
| --- | --- |
| Host setup and first instance | `Supported-host installation authority`, `Instance selection`, `Local lifecycle commands` |
| Daily build/start/browser/stop | `Locked runtime identities and protected-value broker`, this section, `Health, retry, restart, and shutdown` |
| Diagnosis and remediation | `Diagnostic output planes and remediation catalog`, `Derived environment state`, `Observability and operator audit` |
| Backup and verification | `Normative operator journeys`, `Host tools and repository`, `Capacity evidence and formulas` |
| Restore and interruption | `Verified in-place restore`, `Deadline nesting and blocking-resource release` |
| Fresh-host export/import | `Portable export and fresh-instance import` |
| Wipe and empty recovery | `One-off destructive wipe mode` |
| Dependency/security maintenance | `Continuing vulnerability and provenance authority`, `Host and persistent-dependency upgrade protocol` |
| Retention and escalation | `Backup and protected-state maintenance`, `Diagnostic output planes and remediation catalog` |

Before first use, the operator runs configless `central local doctor --host-prerequisites`; an administrator then follows the exact release-owned prerequisite runbook and installs/verifies the locked identities, root-owned helper/broker/runtime launcher, PAM/`sudoers`, AppArmor, browser/trust tooling, and host manifest as a separate explicit action. Rebuilding Central from a working tree changes only an untrusted candidate binary; it cannot replace or reauthorize host packages or installed authority. A development instance may explicitly promote one descriptor-copied build through `local runtime stage` after fresh PAM; every prerequisite, topology, dependency-lock, build-recipe, policy, broker, or helper-protocol source change remains inert until a reviewed release artifact is installed.

The supported first-use sequence is:

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

If migration status requires exact resume, the operator runs the exact `--config`-selected `migrate resume --operation=<id>` rather than a new `up`. The verbatim changed-code daily loop is:

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

The helper launches only copied lease-bound bytes as `central-runtime`. Bootstrap/session recovery uses terminal 2 only after that process and page are ready. If three minutes expire or terminal delivery is uncertain, the operator runs `bootstrap show` again and uses only the newly displayed token. Rebuilding or restarting the host process never restarts PostgreSQL or MinIO. Phase 1 runs this transcript after one source edit and proves source/manifest/binary drift, a later working-tree race, or an expired/rebooted lease cannot start.

No Node.js, browser bundler, hot-reload daemon, or source mount is required by the supported baseline. Templates and static assets remain embedded by the Gate 7 owning package. A debugger/reloader may attach only inside the disposable Phase 1 development VM/profile after its own fresh authorization; production-like instances keep runtime non-dumpable. Helper/broker/AppArmor/PAM development and rollback use disposable Ubuntu Desktop VM snapshots, never the normal developer instance or mutable installed authority.

### Measurable local usability budget

Phase 1 measures the supported Ubuntu Desktop 24.04.4, 4-logical-CPU/8-GiB/ext4 SSD host with no competing full suite. The validation report records the device's sequential read/write, random 4-KiB IOPS, fsync p95, and whether each sample starts with cold or warm page cache; Phase 1 fixes the accepted qualification floor before timing acceptance. Clean-network tests use a deterministic HTTPS fixture containing only locked artifacts, shaped to 100 Mbit/s throughput, 50 ms round-trip latency, and zero packet loss; DNS/TLS setup is included. External Internet performance is not promised, but artifact verification/build time and progress behavior remain bounded by the same command deadlines. Cached tests disable network and prove no registry/repository request occurs.

| Journey/command | Acceptance target |
| --- | ---: |
| administrator prerequisite/helper/broker/browser runbook from a clean installed OS | at most 15 minutes active operator time; wall time and one documented reboot reported separately |
| complete first use after runbook: `init → trust install → security update → doctor → prepare → up → migrate up → serve ready → browser open → bootstrap show` | at most 25 minutes |
| complete first use authentication interaction | at most 9 fresh Central PAM conversations and 4 minutes active interaction after the administrator runbook |
| changed-code daily transcript from stopped dependencies | at most 4 fresh PAM conversations and 2 minutes active interaction; exactly stage, up, serve launch, and browser launch |
| clean `local prepare`, including two isolated MinIO builds, SBOM/provenance, image load | at most 20 minutes |
| `local init` | at most 3 seconds |
| cached `local up` from exact `STOPPED` dependencies | p95 at most 60 seconds; every run at most 120 seconds |
| idempotent `local up` when exact dependencies are already healthy | p95 at most 5 seconds; every run at most 10 seconds |
| `local status` | p95 at most 1 second; every run at most 3 seconds |
| read-only `local doctor` without explicit probes | p95 at most 5 seconds; every run at most 15 seconds |
| `doctor --write-probe` | at most 30 seconds including cleanup |
| `doctor --backup-throughput-probe` | at most 5 minutes including fixture load, both bounded 512-MiB measurement stages, and cleanup |
| warm-cache `central serve` to ready after compatible provisioned dependencies | p95 at most 5 seconds; every run at most 10 seconds |
| `bootstrap show` after readiness | at most 3 seconds before TTY delivery |
| ordinary `local down` | p95 at most 30 seconds; every run remains inside the existing 90-second hard deadline |

P95 values use 20 independent iterations after one discarded warm-up, reporting all samples; clean setup/prepare uses three fresh VM/root/builder runs and every run must meet its maximum. Every helper-backed sample reports (a) active human PAM/confirmation time, (b) post-authentication command time used by the command table, and (c) end-to-end wall time; it performs exactly one fresh authentication and never uses a sudo timestamp. The nine/ four journey counts are intentional consequences of the same-UID threat decision; compatible commands are not silently coalesced into a wider helper grant, and destructive confirmations always remain separate. Timing starts before config/lock acquisition and ends only after promised durable receipts/readiness/cleanup. Reboot is outside active operator time but inside reported setup wall time. A test cannot exclude helper, broker, browser launch, Docker, fsync, health, or verification time, use a pre-existing dependency container in a clean run, or widen resource limits.

Any interactive command expected to exceed two seconds prints its accepted/non-accepted mutation state and first bounded phase update within one second, then an update at least every five seconds and at most once per second. Updates contain only phase, elapsed time, committed records/bytes/chunks, finite deadline, and catalog-safe next-action availability; an ETA is omitted unless derived from measured committed rate and is never authority. Multiple phase transitions inside one second are coalesced into the next update with the ordered transition count; transition records never exceed the one-hertz cap. TTY output remains under 120 columns and retains the last terminal result. With `--output=json`, stdout remains exactly one final result object; a second process may use bounded status by operation ID, and stderr never emits ad-hoc progress that breaks automation.

SIGINT acknowledgement appears within one second. The command stops new work immediately and reaches its documented safe checkpoint/cleanup or returns exact resume evidence within the enclosing operation deadline; cancellation is not reported complete while a child, lock, tmpfs handoff, multipart upload, or ambiguous mutation remains. No acceptance journey permits an undocumented shell command, Docker access, file edit, permission change, manual container cleanup, browser warning bypass, retry beyond the remediation catalog, or source-tree modification. Requiring any such intervention fails the usability scenario even if final health is green.

Automated integration suites never target the developer instance. Each suite receives a fresh UUIDv7, temporary XDG roots beneath `/tmp`, a unique Compose project, dynamically allocated numeric loopback ports, and an isolated browser trust profile containing only that suite's CA public certificate. Its exact HTTPS Origin derives from its allocated application port; the supported developer origin remains `https://127.0.0.1:8080`. It uses fixed logical database/bucket names inside its isolated dependency instance. Cleanup may remove only a temporary root whose binding proves the harness created it; a crash leaves a reported diagnostic path and never triggers a global Central-project sweep. Unit tests require no Docker.

The 4-CPU/8-GiB reference host runs exactly one full integration suite. Every full suite must first acquire one process-shared harness token representing 4 logical CPUs and 6 GiB RAM; token files/locks live under one binding-protected harness-control root in `/tmp`, are kernel-lock authority rather than PID text, and are released on process exit. Installed concurrency is:

```text
max_full_suites = min(
  floor(logical_cpus / 4),
  floor((host_ram_bytes - 2 GiB host reserve) / 6 GiB)
)
```

Below-reference hardware yields zero supported full-suite tokens. The harness caps the result at the number of free tokens and never treats swap as RAM. A suite waiting for a token starts no container, reserves no port, and times out with a diagnostic rather than oversubscribing. True two-suite parallel isolation is validated only on the documented larger profile of at least 8 logical CPUs and 16 GiB RAM; each suite still has a separate instance/project/root/ports/browser trust profile. The reference CI job defaults to serial full suites while unit/package tests may retain their own bounded Go parallelism.

There is no insecure development mode: tests and local development retain authentication, Host/Origin, CSRF, least-privileged roles, protected secrets, redaction, exact migration, and restore barriers.

## Required design-validation scenarios

Gate 8 validation is documentary design-contract evidence. Phase 1 implements and executes the corresponding tests. The validation report must map each scenario to its normative section, expected result, future test level, and owning Phase 1 slice.

1. A clean linux/amd64 host uses configless prerequisite doctor and init; all operator/root-owned roots, bootstrap audit journal, bindings, ownership, modes, and complete config are exact. Crash before/after each init-bootstrap phase is discoverable through caller-bound `local init --status` and permits only exact configless resume or pre-accepted empty-reservation abandon. Golden parsing rejects every invalid permutation, and every command/failure emits a schema-valid closed command-specific `details` variant whose exit, phase, mutation, retry, resume, and action fields satisfy the matrix.
2. The operator, runtime, agent, and browser UIDs cannot open unauthorized Docker/protected/state/profile/rescue-scratch roots or privileged descriptors. Helper/broker/PAM/sandbox authority matches installed identities; direct open/enumeration, same-UID PTY, cached sudo, ptrace, `/proc`, descriptor replay, audit/backup rewrite, runtime subprocess, and cross-agent attacks fail. Missing authority blocks admission; exact stale admission permits unchanged serving only through expiry plus 30 days, after which hard-expired mode permits only snapshot/status/security update/sealed verify-export/offline rescue/settlement-cleanup/down. With every ordinary seven-day throughput receipt stale, rescue uses only the fixed conservative benchmark admission, fully verifies operation-owned cold copies, never mounts/writes authoritative payload roots, confines daemon-internal writes to the copies, creates at most one marked current-epoch seal, and remains unrestorable until current authority; insufficient copy capacity, doctor write/throughput probes, and a signed deny forbid creation. Failure injection after every pre-accepted copy plus start/seal/stop/mount-release/delete/sync boundary leaves either the exact rescue retry or cleanup-only continuation. Operator abandonment and a signed deny arriving before acceptance still permit irreversible `abandoned_for_cleanup`; cleanup cannot restart work or delete outside its bound scratch root, and no raw copy remains after completion. Clock rollback, renewable override, changed identity, and deny tests fail closed. Two isolated builds and rendered Compose retain the locked no-build/no-pull contract.
3. A second configless `local init` creates a distinct instance; only `local init --resume=<id>` resumes an exact incomplete accepted init journal, while abandon removes only an unaccepted empty reservation and preserves its tombstone. Repeated exact `prepare` and `up` are idempotent; a partial fs-init/provision crash resumes only its exact step. All six rendered services have explicit `restart: "no"`. Dependency exit, Docker daemon restart, and host reboot leave every service stopped and state derived as `STOPPED`; no writable payload opens and cleared tmpfs secrets are not reused. Only a new `local up` revalidates every binding/image/advisory/secret/port/recovery barrier and starts dependencies. A manually running container without current correlated evidence becomes `DRIFTED`.
4. `openat2`/`statx`/mountinfo/handle tests reject symlink/magic-link escape, hard link, nested/bind/namespace alias, FUSE/network/overlay/idmapped/shared mount, root overlap, wrong owner/mode, ambiguous XDG discovery, or modified receipt. Races replace every path/mount after host validation and during Docker/wipe resolution; held descriptor binds either reach the original inode and pass container acknowledgement or fail without following the replacement.
5. A pre-existing port collision fails during best-effort preflight with no mutation. An injected bind race after the `up` accepted point returns `PORT_BIND_RACE`, restores every exact prior container/network state within the rollback deadline, preserves recognized fs-init/provision evidence, and permits only identical idempotent retry; injected rollback/crash failure leaves correlated durable evidence and blocks automatic retry. No command chooses a new/wildcard port, and the application exposes only its exact HTTPS IPv4 origin without plaintext/IPv6 fallback or redirect.
6. The helper ignores caller Docker/Compose/proxy/home/plugin variables and independently renders exactly six services. Runtime receives only its closed state/lock/repository/control descriptor table. Foreground supervisor tests relay SIGINT/status/settlement/exit, reap the child, cancel on controller/supervisor loss, and never daemonize. Sandbox-launcher tests verify broker-MAC authorization, descriptor-only Workspace delegation, central-agent namespaces, pidfd/reaping, and denial of arbitrary path/UID/executable/mount. Actual application modes cannot invoke infrastructure helper or Docker.
7. Filesystem initializers can prepare only their exact descriptor-bound empty/recognized directory and must match host/container device/inode/type acknowledgements before and after writing; logical provisioners cannot read payload data; daemons run as exact `999:999`/`1000:1000`. Mount/overlay write auditing across startup, health, provision, steady I/O, failure, shutdown, and restart proves every durable/tmpfs/shm/socket/home/cache write stays inside the complete table with exact size/mode/owner/`nosuid,nodev,noexec` options. Tests reject a writable image layer, undeclared image volume/runtime mount, unexpected device/namespace, wrong IPC/mount flag, or attempted write elsewhere. Each service reads only its exact `0400` tmpfs handoff through the verified `_FILE` interface; one-shot copies disappear after release, the MinIO server copy persists only for its container lifetime, and crash/stale cleanup cannot remove an active or unrelated mount.
8. Pre-baseline PostgreSQL provisioning creates or validates only the fixed database, exactly three application roles with SCRAM, authentication posture, and database-level prerequisites. An absent application schema is valid `MIGRATION_REQUIRED`; a partial schema is incompatible. Only version-zero migration creates schema/history and schema-dependent ownership/grants, and neither boundary widens, drops, adopts, or repairs the other's state.
9. MinIO provisioning creates or validates one private bucket and three ungrouped identities with the exact canonical policy digests. Positive tests cover each listed prefix/list/read/write/multipart/delete operation; negative tests cover cross-bucket/out-of-prefix access, backup write/delete, every explicit deny, unlisted administration APIs, extra group/policy attachment, anonymous/console access, and presigned browser delivery.
10. `local up` on an uninitialized database reports `MIGRATION_REQUIRED`; only `migrate up` enters the accepted version-zero provisioning/bootstrap protocol.
11. The host and PostgreSQL lock layers prevent a second serve and mutation-mode coexistence. Every offline phase, including `pg_dump`/`pg_restore`, stays within its fixed two-permit matrix; `pg_stat_activity` evidence across normal/failure/resume proves no hidden tool session. Permitted read-only coexistence keeps the complete installation within 16 connections.
12. Backup creation cannot coexist with serve, retains target-exclusive ownership, and publishes no restorable seal until the broker independently rereads descriptors and commits the complete tree. Failure injection at every generic authority prepared/staging/install/envelope/commit boundary deterministically reissues identical bytes, rejects truncated final collisions and alternate candidates, commits once, and covers genesis, bounded checkpoint/compaction/capacity limits, plus dual-key rotation; backup-specific injection verifies the exact `root-manifest.auth.json`. Same-operator-UID rewrite/delete/recomputed-SHA fixtures cannot reach authoritative repository and fail HMAC verification. The runtime coordinator forks/reaps exactly one tool using only inherited sealed fd 3; unrelated descriptor access and fallback fail. The bounded 512–544-MiB custom-dump plus 512-MiB object probe completes with cleanup inside five minutes, preserves the COPY-vs-pg_dump regression, and the 5-GiB/10-GiB/10,000-record fixture meets the stated rate/deadline with bounded transfer/failure/resume semantics.
13. Backup/restore capacity aggregates roots sharing a device, charges the full included body sum without deduplication credit, and rejects missing/overflowed/stale mount or reserve evidence. A shared-device fixture counts a sealed dump as existing occupancy but not new writable demand and proves actual peak allocation. Tests force a custom dump and restored database to exceed every planning estimate: bounded guards stop before the ordinary floor, release only the bound reserve, retain exact unsealed/non-ready evidence, and never delete unrelated data.
14. Restore apply rejects stale ticket, changed config/target/device/capacity, wrong confirmation, or active target owner before mutation; exact resume preserves the complete Gate 7 barrier and authority reset.
15. PostgreSQL or MinIO loss makes readiness false immediately; classified recovery within budget succeeds, exhausted runtime failure exits `6`, and target-lock loss is immediate terminal failure. Slow header/body/write, pool/lock/statement/transaction, mode-specific dump/restore `PGOPTIONS`, health, object I/O, subprocess, cancellation, and rollback tests prove every child nests inside backup/restore/prepare/export/import/maintenance parents and releases every scarce resource without resetting elapsed authority.
16. Shutdown gives effect settlement 30 seconds within a 45-second total default and returns `0` only after durable obligations; timeout/failure returns `6`.
17. `local down` preserves data. Wipe never appears as a seventh Compose service and accepts only the exact image plus installed/enforced AppArmor identity. Missing/complain/default policy, PAM/TTY replay, wrong confirmation or any wrong operation/root/container evidence deletes nothing. Failure injection across every accepted/delete/broker-reseed/epoch checkpoint resumes only the exact operation. Roots survive empty; configuration, CA/trust, preparation, audit, backups, exports, and siblings survive. Every database/object credential version token changes and completion/recovery follows the exact new-epoch journey.
18. `bootstrap show` fails until HTTPS is ready, requires fresh PAM and the helper/broker-owned TTY, rotates before revealing, emits one generation once directly from broker to TTY, and expires it after three database-time minutes. Same-UID PTY/replay and crash/concurrency injection never expose plaintext to the controller or logs and never replay it.
19. Failure injection after every broker-owned protected value/meta/phase/tombstone write, active-pointer rename, retirement, and cleanup unlink reconstructs only the uniquely implied state. Concurrent candidates produce at most one active generation; raw secret hashes never leave the broker; deletion reaches an empty tombstone and bounded plaintext cleanup; no registered/active/referenced winner is removed.
20. `/health/live`, `/health/ready`, `/metrics`, logs, redirected stderr/stdout, CLI JSON, receipts, config digests, and audit pass sentinel-secret/raw-path/object-key redaction tests and bounded-label checks. Trusted-TTY tests show only allowlisted descriptor-validated operator paths with exact escaping; redirected/mismatched-owner/non-TTY/control/bidi/symlink/replaced descriptors fall back to redaction. Every reason code has one `central.local-remediation/v1` entry, every result matches it, exact commands contain no raw path in machine output, and injected repeated failures cross the installed count/time threshold to `inspect_manual` without mutation or privilege advice.
21. Integration harnesses create isolated temporary instances and cannot clean a developer or sibling instance. The 4-CPU/8-GiB profile admits exactly one full suite; a waiting suite starts no resource. An 8-CPU/16-GiB profile admits exactly two and proves parallel port/project/trust/root isolation, kernel-lock release after crash, and refusal of a third suite.
22. Two clean Ubuntu Desktop hosts install the manifest browser/trust tooling, use collision-free root-registry project IDs and the helper-opened Wayland descriptor for root-parented `central-browser` profiles, stay within each 1-GiB/50,000-inode project quota, 256-MiB disk cache, 512-MiB/256-PID scope, and the 7.5-GiB aggregate profile, and open only the trusted numeric-loopback page. Direct profile/cookie/trust/process-memory access by operator/runtime/agent fails. Wrong quota/project/mount/display/profile/CA/SAN/origin, warning bypass, counterfeit process, expired presentation, or second exchange is rejected; close/reopen works, and crash injection at every `browser clear` revocation/quarantine/recreate/settlement phase permits only exact resume with no surviving session/bootstrap authority.
23. Two clean Ubuntu Desktop 24.04.4 hosts install only signed manifest sources and exact package/archive/browser/PAM/AppArmor/quota hashes, enable persistent ext4 `prjquota`, perform the documented reboot, and produce identical prerequisite evidence. Configless doctor verifies the mount/kernel prerequisite before helper installation; full doctor proves helper/broker/locked identities, enforced AppArmor, collision-free active project quota, physical-seat PAM, managed Wayland browser and trust policy afterward. A clean host without active/persistent project quota fails before init and no Central command remounts it. Upgrade tests exercise the exact durable operation schema and every accepted checkpoint; incompatible/major transitions remain out of place.
24. Export completely reverifies a broker-MAC-sealed backup, copies it only to encrypted media, broker-signs the canonical export, and reveals the `bx1` authority token only through the exclusive PAM TTY for retention on paper or an administered root-protected recovery store. Fresh-host tests enter that token only through the secure helper prompt and import/restore with new authorities. A token sourced from operator-writable/export media, changed key/signature/tree, wrong boundary, unsealed backup, source authority injection, non-fresh destination, incompatibility, or crash is rejected.
25. Backup list pagination is stable and bounded. Repository ceilings block a new backup before mutation. Delete/prune/maintenance require fresh PAM and helper confirmation; same-UID PTY/replay and reference races delete nothing. Failure injection after every accepted journal/quarantine/unlink/sync/tombstone checkpoint resumes only the same operation. Exact deleted protected bindings reach empty tombstones within the bound; active/referenced/sealed/current/incomplete evidence survives, and pressure never automatically deletes recovery media.
26. A naive operator follows the normative transcripts verbatim for complete backup, terminal/nonterminal backup interruption, verified fresh-PAM interactive restore, expired ticket, accepted interruption/resume, authority-reset bootstrap, and configless fresh-host import. No noninteractive restore apply exists. ID-less status discovers only bounded nonterminal safe IDs; every result's catalog action matches the transcript, and all invalid resume/new-operation/confirmation/serving/bootstrap/source-copy paths fail.
27. Three clean fixture-host runs and the defined 20-iteration cached samples meet every usability maximum/p95 without weakening resources or pre-seeding forbidden state. Long commands produce first/periodic/phase/final progress at the exact cadence and bounded fields; JSON stdout remains one object while concurrent status stays responsive. SIGINT acknowledges within one second and yields cleanup or exact resume evidence. The complete runbook and daily loop use only documented commands, confirmations, and browser origin; any manual Docker/file/permission repair, warning bypass, hidden retry, or source edit fails the scenario.

## Gate deliverables and governance

Gate 8 requires:

1. this governing design, approved after maintainer review;
2. proposed ADR 0009 recording host-application/Compose-dependency topology, locked runtime/agent identities, the root-owned protected broker and fresh-PAM destructive boundary, the privileged-helper/Docker trust boundary, the Ubuntu Desktop/browser HTTPS origin, stale-admitted advisory behavior, Gate 8 backup-command extensions/public export-integrity token, and MinIO source-build decision;
3. canonical local-environment, configuration/protected-state, and backup/restore-topology contracts aligned with Gates 1–7, plus the narrowly amended Gate 7 restore-confirmation paragraph authorized by ADR 0009;
4. a Gate 8 documentation implementation plan that orders ADR, canonical contracts, validation, reviews, and status updates without creating executable infrastructure;
5. a validation report covering every scenario above;
6. independent pre-acceptance and final-snapshot review evidence with no unresolved Critical, Important, or Minor finding; and
7. truthful roadmap/current-phase updates only after the governing design, ADR, canonical contracts, plan, and review evidence reach their required states.

Gate 8 completion does not create or validate a working local environment. Phase 1 delivers incrementally through this dependency map; a row may start only after the preceding row's listed acceptance, and every not-yet-implemented command is present only as a schema-valid exit `5` `UNSUPPORTED_IN_THIS_SLICE` with no mutation:

| Phase 1 slice | Required capability and acceptance | Explicitly deferred while failing closed |
| --- | --- | --- |
| A — host authority foundation | prerequisite manifest/config/result parser; locked UIDs; PAM/helper/broker/runtime launcher; configless doctor/init; root-owned protected/TLS journal; direct-open/ptrace/PTY denial tests | Docker/prepare, serving, backup/restore, wipe, upgrade, export/import, retention |
| B — first safe runnable environment | complete hermetic dependency lock/prepare; Compose fs-init/daemons/provisioners; broker handoff; `up/down/status/doctor`; migration zero; staged `central-runtime`; TLS/browser/bootstrap; one end-to-end durable Task producing a verified Artifact | wipe, portable recovery, upgrade, delete/prune, general protected/audit maintenance |
| C — required recovery | Gate 7 backup/verify and restore barrier; representative throughput/capacity; failure/resume; fresh bootstrap authority reset | export/import, dependency upgrade, retention maintenance |
| D — destructive and portable operations | AppArmor-locked wipe; export/import with independent integrity token; fresh-host recovery; backup delete/prune; protected/audit tombstone maintenance | dependency patch upgrade where no supported pair exists |
| E — supported dependency maintenance | ticketed patch upgrade for the selected compatibility matrix, rollback/out-of-place evidence, advisory operational runbooks | every unlisted transition remains `UPGRADE_OUT_OF_PLACE_REQUIRED` or unsupported |

This ordering preserves every accepted safety invariant but does not make upgrade, retention, export, or wipe a prerequisite for the first value-bearing local task. A deferred command never performs a partial approximation, asks for manual Docker/file repair, or weakens authority. Gate 10 decides Phase 0 closure.

## Cross-gate ownership

| Decision or artifact | Owner | Blocks |
| --- | --- | --- |
| Domain/runtime/Artifact/API/PostgreSQL/Go semantics consumed here | Gates 1–7 | Gate 8 may not redefine them |
| Concrete local topology, protected backend, config source/paths, dependencies, ports, credentials, bucket, process placement, host tools, capacity formulas | Gate 8 | Phase 1 local infrastructure and operator-mode slices |
| Advisory compilation/signing/publication, offline distribution, key custody/recovery, emergency response runbook | Release security owner | New dependency admission; not continued use of an exact stale-admitted installation |
| Gate 8 backup command extensions and export-integrity-token exception | ADR 0009 plus Gate 7 `backup/app` owner | Phase 1 portable/maintenance slices |
| Executable slice order, Dockerfiles/Compose/config code, dependency lock, integration/failure/reproducibility tests | Phase 1 | Phase 1 implementation and exit |
| Final completeness/traceability audit | Gate 10 | Phase 0 closure |

Any later non-loopback listener, proxy topology, alternate secret backend, different database/object-store, containerized application, multiple serving profile, MinIO replacement, platform expansion, or cloud deployment is a material change requiring threat-model and ADR review.

## Alternatives rejected

### Containerize the Central application

Rejected for the Phase 1 development baseline because it slows the Go edit/debug loop, complicates descriptor-brokered access to developer Workspace roots and authoritative state, and tempts Docker authority or broad host mounts into the application container. Locked host execution preserves the accepted application boundaries while Compose isolates only dependencies.

### Run PostgreSQL and MinIO directly on the host

Rejected because dependency versions, identities, filesystem ownership, network exposure, and teardown become host-specific and difficult to reproduce. Compose provides a narrow dependency boundary without containerizing Central.

### Give the operator ambient Docker-group authority

Rejected because Docker control is root-equivalent and would let a compromised application, agent tool, repository hook, or same-UID process replace images, mount protected host paths, or bypass the intended application capability boundary. A root-owned release-pinned helper narrows that authority to an explicit operation and topology protocol.

### Docker named volumes

Rejected because host operator modes cannot prove device identity and free capacity without Docker-daemon inspection, container execution, or a privileged sidecar. Instance-bound host directories permit no-socket capacity and binding checks.

### One privileged provisioner or general long-running root daemon

Rejected because filesystem ownership and logical policy need different privileges and occur on opposite sides of dependency startup. Separate no-network root fs-init and non-root network provisioners keep each authority narrow. The socket-activated protected broker is a reviewed exception with no Docker/network/Workspace/arbitrary-path authority, a fixed idle exit, and purpose-specific signing/use operations; it exists because filesystem modes cannot isolate secrets from same-operator-UID malware.

### Writable container root filesystems

Rejected because undeclared config, cache, socket, or temporary writes would evade durable-root bindings, capacity accounting, cleanup, and restart evidence. Exact read-only images plus bounded service-specific tmpfs make every permitted write location inspectable and disposable.

### Host-side recursive wipe or dependency-image deletion

Rejected because a generic root helper recursion or shell inside PostgreSQL/MinIO would inherit a broad host/path/tool surface. The static release-built one-root maintenance mode has a separate digest, syscall/capability policy, held descriptor, acknowledgement, and no network/second mount; it is never a persistent service.

### Environment-variable configuration and `.env`

Rejected because precedence, provenance, multiline credentials, process inheritance, diagnostic leakage, and per-command drift undermine immutable startup evidence and protected bindings.

### Auto-download or auto-build during `local up`

Rejected because ordinary startup would become network-dependent and could silently change its supply chain. Explicit preparation makes acquisition auditable and daily startup deterministic.

### Ambient Docker builder or reproducibility check alone

Rejected because host Buildx plugins, cached frontend/toolchain/module state, exporter defaults, and attestations can change the result without changing the Dockerfile. A reproducibility assertion is not self-enforcing if both runs share that state. The fixed BuildKit archive, built-in frontend, offline inputs, two isolated content stores, explicit exporter, and no-build/no-pull Compose contract make undeclared input observable and terminal.

### Docker automatic dependency restart

Rejected because `unless-stopped` can reopen PostgreSQL or MinIO writable payloads after a daemon/host restart without rechecking descriptor bindings, image/advisory receipts, tmpfs secret generations, ports, or recovery barriers. Explicit `restart: "no"` makes `local up` the single validation and start boundary; post-reboot availability requires an intentional command.

### Helper-managed host packages or version ranges

Rejected because making the helper an APT/key/service manager would greatly widen its root authority, while minimum-version ranges allow unvalidated package changes to enter the supported profile. A release-owned exact manifest plus an administrator-run signed-source installation keeps trust transitions explicit and lets `doctor` fail closed on drift.

### In-place major dependency upgrade or assumed rollback

Rejected because a version label does not prove persistent-format compatibility in either direction. Only fixture-backed patch pairs may open existing roots; major, replacement, or unproven transitions use new roots plus verified restore, and rollback requires its own old-reader compatibility evidence.

### Auto-migrate during `serve` or `local up`

Rejected by Gate 7 because serving must not receive migration credentials and migration safety requires explicit target-exclusive operator control and exact-operation resume.

### Backup while serving

Rejected because Gate 7 requires target-exclusive ownership from accepted-point capture through verified manifest seal. A filesystem shared lock cannot weaken that database authority.

### In-place-only recovery or portable credential bundle

Rejected because in-place-only backup does not survive host loss, while exporting protected state would turn long-lived database/object/TLS/bootstrap credentials into a portable secret archive. Fresh-instance import carries only logical data and integrity evidence, requires an independently retained fingerprint, and deliberately regenerates every host/security authority.

### Automatic backup or audit pruning

Rejected because age, count, or disk pressure alone cannot prove that a sealed backup, incomplete operation, secret generation, or audit record is unreferenced. Exact dry-run plans, reference locks, TTY confirmation, and resumable descriptor-relative deletion make reclamation explicit; capacity failure never becomes deletion authority.

### Plaintext browser application on loopback

Rejected because authentication above HTTP cannot prove to the browser that the process occupying the fixed loopback port is this Central instance. A different local process could present a counterfeit bootstrap page before session authentication. Instance-bound HTTPS makes server-origin authentication explicit while retaining the local-only topology.

### MinIO floating image or older official image

Rejected because the older image predates the selected security fix and the source repository is archived. Exact source-build evidence is safer than a convenient unsupported tag, while the ADR preserves the replacement trigger and maintenance risk.

### Digest pinning without continuing advisory authority

Rejected because an immutable digest can remain reproducible after it becomes known-vulnerable. A short-lived release-signed advisory bundle, exact signed exceptions, and a non-exemptible emergency denylist keep identity and continuing security acceptance separate without trusting a mutable repository file or caller-selected scanner result.

### Global active-instance pointer or destructive force flag

Rejected because implicit target switching and lock bypass make wipe, restore, migration, and credential rotation capable of acting on the wrong durable instance.

### Post-wipe receipt reuse or full instance deletion

Rejected because preserved receipts could falsely describe deleted payloads as initialized/provisioned, while deleting configuration, TLS, backups, and audit would turn payload wipe into an unrelated instance-destruction command. A new payload epoch and credential reseed preserve the instance boundary but make all payload-dependent evidence provably historical.

### Raw paths in machine output or no actionable paths anywhere

Rejected because JSON/log paths propagate filesystem layout into CI and telemetry, while opaque-only local diagnostics make safe repair impractical. Descriptor-validated, escaped paths are confined to a proven operator TTY; the versioned catalog keeps machine output bounded and still supplies deterministic next actions.

### Low-level backup semantics without operator transcripts

Rejected because exact locks/tickets are insufficient if users cannot discover the right operation or distinguish new verify, apply, and resume. Normative safe-ID transcripts make the Gate 7 state machine executable without adding force aliases or hidden orchestration.

### Unmeasured local usability

Rejected because functional health alone permits silent multi-minute commands, slow cached loops, and undocumented manual repair. Reference-host elapsed/progress/cancellation budgets are release acceptance criteria, while external Internet speed remains explicitly outside the promise.

## Risks and implementation cautions

- The archived MinIO dependency can accumulate unfixed vulnerabilities or become incompatible with future Go/toolchains. The signed seven-day advisory authority, immediate known-exploited/emergency denylist path, non-exemptible categories, explicit replacement trigger, and named release-security owner bound that risk. An exact stale-admitted installation may continue locally, but no changed dependency can be prepared or upgraded until current authority returns; an already obtained signed deny still stops use.
- The offline release-security key and advisory compiler become high-value supply-chain controls. Phase 1 must prove key separation, deterministic canonicalization, scanner/feed provenance, key transition, rollback resistance, exception expiry, emergency activation, and fail-closed behavior; TLS or a scanner exit code alone is not sufficient authority.
- Hermetic builds enlarge the release input set with BuildKit, canonical source/module/base bundles, and exporter semantics. Phase 1 must independently reproduce the full OCI and normalized filesystem identities on a second clean host; a shared cache or equal tag is not evidence, and any builder upgrade requires a new reviewed lock, advisory evidence, and preparation receipt.
- Disabling Docker auto-restart trades unattended post-reboot availability for a single checked writable-start boundary. The supported local-first profile requires the operator to run `local up` after Docker/host restart; future boot automation needs a new reviewed authority design and cannot silently restore `unless-stopped`.
- Exact prerequisite pins can lag Ubuntu/Docker security updates and deliberately turn ordinary package drift into downtime. The signed advisory expiry forces review; each accepted host-tool update needs a new release manifest and two-host validation rather than an in-place range widening.
- Patch compatibility and rollback evidence are directional. Phase 1 must inject crashes before/after first new-binary payload access and every receipt transition; when backward compatibility is absent, preserving old bytes is not permission to restart the old binary, and verified out-of-place restore remains the recovery path.
- Portable export confidentiality depends on the separately managed LUKS2 recovery key, and authenticity depends on retaining the broker-signed `bx1` token on paper or in a separately administered root-protected recovery store. Loss of either can make recovery impossible; an operator-writable token file is deliberately not accepted as independent authority.
- Explicit retention avoids surprising data loss but can block new backups at the 16-backup/256-GiB ceiling. Operators must list, export, and confirm exact delete/prune plans; the system never frees sealed recovery evidence merely to satisfy a capacity check.
- Exact tmpfs inventories depend on selected image behavior. Any new dependency write path, image-declared volume, UID/GID, or executable-tmpfs requirement invalidates the lock and must be reviewed; Phase 1 cannot make the rootfs writable to pass a startup test.
- Wipe deliberately gives one short-lived root container destructive access to one held payload descriptor. Its static image, capabilities, syscall policy, mount acknowledgement, sequential checkpoints, and no-second-root invariant are security-critical; ambiguous cleanup or container identity blocks all forward lifecycle work.
- Wipe credential reseed spans several protected bindings and cannot be one filesystem transaction. The wipe journal and final payload-epoch pointer are therefore the authority: every crash permutation must converge to the exact candidate set before the barrier clears, and no command may infer completion merely from empty directories.
- Trusted-TTY diagnostics intentionally reveal a bounded local filesystem layout to the operator account. Phase 1 must prove terminal ownership, descriptor derivation, escaping, output-plane fallback, and sentinel redaction; a caller flag, dependency error, or arbitrary path may never enter that plane.
- Operator transcripts are normative examples and can drift when a command/result schema changes. Phase 1 golden-tests every line and catalog next action against the parser/state machine; documentation mismatch fails the slice rather than teaching a workaround.
- Usability targets depend on the stated reference SSD and shaped artifact fixture. Phase 1 must publish raw samples and separate external transfer delay from local processing diagnostics, but cannot waive cached-loop or progress targets because a developer machine is faster or slower.
- Bind mounts make host paths and numeric container ownership operationally visible. No-follow traversal, exact bindings, init isolation, and wipe confirmation must be tested rather than assumed from Compose rendering.
- Docker access is root-equivalent. The helper must remain a small audited trust boundary with immutable executable ancestry, a closed request/policy surface, sanitized process environment, fixed local socket, exact render checks, and correlated receipts. These controls do not protect an instance from compromised root, the installed helper, or the Docker daemon.
- Dependency-secret handoff intentionally places the bounded helper, root, kernel tmpfs, and Docker daemon inside the secret-delivery trust boundary. Phase 1 must prove source/destination no-follow handling, service-specific ownership and `_FILE` support, absence from Docker metadata, rotation behavior, and crash-safe cleanup; ordinary host files or Compose environment substitution are not acceptable fallbacks.
- The local CA lifecycle adds an administrative trust transition. Exact instance constraints, private-key isolation, trust receipts, offline rotation, and explicit anchor removal must be tested across the supported Ubuntu system trust/browser profile. This topology is not suitable for LAN, shared browser profiles/runners, or production exposure.
- A protected filesystem backend cannot guarantee memory zeroization. Its enforceable properties are root-only durable storage, broker-mediated minimal lifetime/copies, exact adapter use, and no intentional reveal path except the fresh-PAM exclusive-TTY bootstrap presentation command.
- The bootstrap presentation boundary is high risk. Any future JSON/export/clipboard convenience would reopen the Gate 2/5 secret-exposure decision.
- Fixed pool and container limits may surface resource pressure earlier on large local datasets. Limits fail safely; operators do not widen them beyond Gate 7 caps without benchmark and design review.
- Capacity estimates are conservative but cannot predict every filesystem, WAL, index, or object-store behavior. Continuous/repeated checks and cleanup-required evidence remain necessary; a preflight is not a guarantee of success.
- Host and PostgreSQL locks protect different failure domains. Implementations must preserve acquisition order and avoid an in-place shared-to-exclusive upgrade.
- Generated overrides contain sensitive paths even without secret values. They are broker-signed diagnostic views, never authority, and must never be committed or printed by default.

## Gate 8 completion boundary

Gate 8 is complete only when:

- this governing design is Approved;
- the repository governance history records ADR 0009's acceptance and, after the ownership activation contract takes effect, ADR 0010 as ADR 0008's Accepted non-superseded amendment;
- canonical local topology, configuration/protected-state, and backup/restore realization contracts are complete and mutually consistent with Gates 1–7;
- the Gate 8 documentation plan and validation report cover every delegated decision and required scenario;
- exact dependency selections, source commit, future lock fields, security/license risk, config field inventory, paths, ports, identities, pools, tools, capacity formulas, lock coexistence, and failure outcomes have no unresolved implementation-blocking decision;
- independent reviews find no outstanding Critical, Important, or Minor issue in the final snapshot;
- roadmap and current-phase documents truthfully mark Gate 8 Complete and Gate 9 Ready without claiming a Compose file, image, database, bucket, credential, runtime, or executable test exists; and
- Phase 0 remains Incomplete until Gate 10.

This design is Approved by its final independent spec re-review. Until the remaining completion conditions hold, Gate 8 remains Ready or In progress according to the repository status ledger. Approval of this design authorizes only the remaining Gate 8 documentation/governance work, not Phase 1 implementation.

## References

- [Product vision](../../../product/vision.md)
- [Product roadmap](../../../product/roadmap.md)
- [Phase definitions](../../../product/phases.md)
- [Architecture overview](../../../architecture/overview.md)
- [Durable execution](../../../architecture/durable-execution.md)
- [Current phase](../../../implementation/current-phase.md)
- [Specification and implementation planning guide](../../../implementation/spec-and-plan-guide.md)
- [Go application boundaries design](2026-07-15-phase-0-go-application-boundaries-design.md)
- [Ubuntu 24.04.4 release images](https://releases.ubuntu.com/24.04.4/)
- [PostgreSQL 16.14 release notes](https://www.postgresql.org/docs/release/16.14/)
- [PostgreSQL official image](https://hub.docker.com/_/postgres/)
- [Docker Engine 29 release notes](https://docs.docker.com/engine/release-notes/29/)
- [Docker Compose 5.3.1 release](https://github.com/docker/compose/releases/tag/v5.3.1)
- [MinIO selected source release](https://github.com/minio/minio/releases/tag/RELEASE.2025-10-15T17-29-55Z)
