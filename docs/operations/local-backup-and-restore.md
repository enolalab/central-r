# Local Backup and Restore Topology

<!--
Design-only/unavailable/exit-5 banner
=====================================
All recovery commands described in this document are design-only.
Every operational verb (create, verify, apply, resume, export, import,
delete, prune, security-rescue, security-rescue cleanup, maintenance,
wipe) returns exit code 5 / UNSUPPORTED_IN_THIS_SLICE until Gate 9 Slice C
(database/restore barrier) and Slice D (wipe, export/import, delete/prune)
are implemented and accepted, and until ADR 0009 is Accepted.

The commands, schemas, lock protocols, capacity budgets, and operator
journeys below are normative documentary contracts. In the current
repository state they produce no mutation, no durable state, and no
recovery authority.
-->

## Authority and status

This is the canonical Gate 8 local backup and restore topology contract
for the Central project. It defines the concrete local realization of the
Gate 7 backup/restore persistence contract (ADR 0008) within the Gate 8
local development environment described in the [approved Gate 8
design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md).

**Design-only.** In the current Phase 0 repository, every command described
here returns exit `5`/`UNSUPPORTED_IN_THIS_SLICE`. No mutation, durable
state, or recovery authority exists.

**ADR 0009 dependency.** Every rule in this document that defines restore
authorization, rescue backup, export, import, deletion, pruning,
maintenance, and wipe behaviour is documentary and effective only when
[ADR 0009](../adr/0009-adopt-local-development-environment-topology.md)
is Accepted.

**Phase boundary.** This is a Phase 0 design contract. It creates no Go
source, SQL migration, Dockerfile, Compose file, image, bucket, database,
role, credential, runtime configuration, generated dependency lock,
executable test, or implemented security control.

## Ownership and compatibility boundary

### Gate 7-owned semantics (not redefined here)

Gate 7 (ADR 0008) owns every durable backup/restore semantic that this
document consumes:

- The `backup/app` application port and its seven verbs (`create`, `verify`,
  `status`, `restore-verify`, `restore-apply`, `restore-resume`,
  `restore-status`);
- Target-exclusive ownership from accepted-point capture through verified
  manifest seal;
- The consistent-offline-point contract (two-hour default, eight-hour hard
  maximum);
- The chunked canonical-key inventory with immutable 1,000-record chunks,
  ordered root manifest, and merge-compare verification;
- The restore procedure: ownership and ticket consumption, database
  replacement, chunked object verification, reconciliation and quarantine,
  operator resolution, authority reset, and ready transition;
- The external protected operator-state lifecycle (`ready → applying →
  verifying → quarantined → verifying → ready`);
- Protected manifest structure, diagnostics redaction, and backup access
  control;
- Quarantine of inconsistent Artifacts with structured operator resolution;
- Trust boundary: backup/restore runs on the host through pinned
  PostgreSQL client tools and the S3 adapter, never using Docker socket
  access or `docker exec`.

Gate 8 may not change any Gate 7 semantic listed above.

### Gate 8-owned local realization and extensions

This document defines the Gate 8 local realization of the following
operator commands. The underlying durable backup/restore semantics remain
Gate 7-owned; local repository layout, tool contracts, capacity formulas,
operator workflows, and public result variants are Gate 8-owned:

| Command | Ownership |
| --- | --- |
| `backup create` | Gate 7 semantics; Gate 8 local repository, tool, throughput, capacity realization |
| `backup verify` | Gate 7 semantics; Gate 8 local verification path |
| `backup status` | Gate 7 semantics; Gate 8 local status schema |
| `backup restore-verify` | Gate 7 semantics; Gate 8 local ticket/verification realization |
| `backup restore-apply` | Gate 7 semantics; Gate 8 local confirmation, lock, and apply realization |
| `backup restore-resume` | Gate 7 semantics; Gate 8 local resume path |
| `backup restore-status` | Gate 7 semantics; Gate 8 local status schema |
| `backup list` | Gate 8 extension (ADR 0009-controlled) |
| `backup export` | Gate 8 extension (ADR 0009-controlled) |
| `backup import` | Gate 8 extension (ADR 0009-controlled) |
| `backup delete` | Gate 8 extension (ADR 0009-controlled) |
| `backup prune` | Gate 8 extension (ADR 0009-controlled) |

### ADR 0009-controlled extensions

The following commands and behaviours are documentary extensions defined
by Gate 8 and are effective only when ADR 0009 is Accepted. While ADR
0009 is Proposed, they occupy only this contract and return exit
`5`/`UNSUPPORTED_IN_THIS_SLICE` with no mutation.

| Extension | Classification |
| --- | --- |
| `backup list` | ADR 0009-controlled; enumerates sealed backups in the local repository |
| `backup export` | ADR 0009-controlled; produces an independent export with `bx1` integrity token |
| `backup import` | ADR 0009-controlled; admits an external export into the local repository |
| `backup delete` | ADR 0009-controlled; removes one identified sealed backup and its bodies |
| `backup prune` | ADR 0009-controlled; removes eligible sealed backups by age and retention policy |
| `backup create --security-rescue` | ADR 0009-controlled; hard-expired rescue with cold-copy model |
| `backup security-rescue cleanup` | ADR 0009-controlled; settlement-only rescue scratch cleanup |
| Local maintenance (backup, protected, audit) | ADR 0009-controlled; bounded quanta, plan/apply/resume |
| Wipe | ADR 0009-controlled; AppArmor-locked destructive reset |

### Preserved semantics across the ADR 0009 boundary

Regardless of ADR 0009 status, the following Gate 7 invariants are
preserved in every command definition in this document:

- Target accepted points;
- Quarantine protocol;
- Authority reset (session/bootstrap/bootstrap-generation revocation,
  grant suspension, SecretReference disable, fresh bootstrap
  activation, epoch advance);
- Restore barrier (`ready → applying → verifying → quarantined →
  verifying → ready`);
- Post-accepted terminal behaviour (non-resumable after completion).

## Repository layout and lock protocols

### Canonical repository tree

The authoritative backup repository lives at:

```
/var/lib/central-state/v1/instances/<instance-id>/backups/
```

It is a sibling of `data/` beneath the root-owned, non-operator-searchable
parent. The layout is:

```text
backups/
├── binding.json                       # create-only immutable binding
├── backup-repository.lock             # create-only; never removed
├── repository-manifest.json           # ordered inventory of sealed backups
├── imports/<operation-id>.json        # import-operation journal
├── exports/<operation-id>.json        # export-operation journal
├── maintenance/<plan-id>.json         # maintenance operation journal
└── backups/<backup-id>/
    ├── binding.json                   # create-only per-backup binding
    ├── database/central.dump          # pg_dump custom-format output
    ├── inventory/<chunk-ordinal>.json # immutable ordered inventory chunks
    ├── bodies/sha256/<first-two-hex>/<remaining-hex>
    │                                  # content-addressed object bodies
    ├── root-manifest.json             # immutable sealed root manifest
    └── root-manifest.auth.json        # broker-HMAC seal companion
```

### Repository binding and permissions

- `binding.json` is create-only, schema `central.backup-repository-binding/v1`.
  It records the binding ID, instance ID, canonical device/inode/mount
  evidence, creation nonce, and an opaque digest of safe immutable fields.
  It contains no credential, secret, path, or backend locator.
- `backup-repository.lock` is a create-only lock file, never removed.
  Repository mutation holds it exclusive; readers hold it shared.
- The repository root and every descendant belong to locked `central-runtime`
  with directories `0700` and create-only files `0600`. Ownership does not
  grant the long-lived serving process repository authority: `central serve`
  receives neither a repository pathname nor a repository descriptor. Only a
  fresh-PAM, helper-launched backup/recovery worker running under the locked
  identity receives the exact already-bound descriptor for its invocation.
  The operator UID cannot traverse the root parent and `central-agent` cannot
  reach any path within it.
- All path components are opened with `openat2` no-follow semantics.
  Symlinks, unexpected hard links, ownership drift, mode drift, mount
  replacement, or inode replacement of a held lock fail closed.

The durable binding and index encodings are closed as follows. All three use
canonical JSON with unknown and duplicate fields rejected; every digest is a
lower-case SHA-256 over the canonical value with its own digest field omitted.

- Root `binding.json`, schema `central.backup-repository-binding/v1`, contains
  `binding_id`, `instance_id`, `owner_uid`, `owner_gid`, `device_major`,
  `device_minor`, `root_inode`, `mount_id`, `created_at`, `creation_nonce`, and
  `immutable_digest_sha256`. The helper derives the filesystem facts from the
  descriptor and the installed instance authority. Runtime input supplies none
  of them.
- Per-backup `binding.json`, schema `central.backup-binding/v1`, contains
  `repository_binding_id`, `backup_id`, `operation_id`,
  `target_fingerprint_sha256`, `config_fingerprint_sha256`, `payload_epoch`,
  `accepted_at`, and `immutable_digest_sha256`. It is written create-only
  before the dump and must match the protected operation exactly.
- Root `repository-manifest.json`, schema
  `central.backup-repository-manifest/v1`, contains the root binding ID, a
  monotonically increasing revision, and at most 16 entries ordered by
  `(accepted_at, backup_id)`. Each entry contains only `backup_id`,
  `accepted_at`, `root_manifest_digest_sha256`,
  `seal_companion_digest_sha256`, and `file_tree_digest_sha256`. The complete
  value carries `manifest_digest_sha256`. Under the exclusive repository lock,
  publication uses a create-only temporary inode, file and parent-directory
  synchronization, then one same-directory atomic rename. A backup enters this
  index only after the broker journal has committed the exact seal companion.
  This worker-written index revision is a publication proposal, not terminal
  seal authority: it becomes restorable only after the worker process tree is
  reaped and the helper independently attests the physical repository through
  its retained descriptor.

### Immutable inventories, bodies, and seals

Every backup is content-addressed and immutable after sealing:

- **Database dump.** `database/central.dump` is a `pg_dump --format=custom`
  output of the application database. Its SHA-256 is recorded in the root
  manifest.
- **Inventory chunks.** `inventory/<chunk-ordinal>.json` files are
  canonical-key sorted, each containing at most 1,000 bounded Artifact
  records. Each chunk has a canonical encoding, a SHA-256 checksum, and an
  operation/ordinal/content-hash identity. Chunks are created create-only
  and are never modified after the sealed root manifest references them.
- **Object bodies.** `bodies/sha256/<first-two-hex>/<remaining-hex>` stores
  each Artifact body content-addressed by its SHA-256. The first two hex
  characters form a fan-out directory. Bodies are identical to the MinIO
  source and are verified byte-for-byte against the database inventory
  checksum before the backup is sealed.
- **Root manifest.** `root-manifest.json` is the immutable sealed
  inventory. Schema `central.backup-seal-root/v1`. It binds the backup
  ID, operation ID, target identity, payload epoch, database dump
  reference and checksum, ordered chunk identities and checksums, tool
  and schema versions, accepted consistent-point evidence, and sealing
  outcome.
- **Seal companion.** `root-manifest.auth.json` is the broker-HMAC
  companion. Schema `central.backup-seal/v1`. It contains the authority
  envelope identity, domain/key version, root-manifest digest, ordered
  file-tree digest, operation/target/config/payload-epoch IDs, and broker
  HMAC. A backup is neither sealed nor restorable before the broker
  journal's committed record.

### Broker seal commit

Backup sealing requires:

1. The live accepted backup operation;
2. Target-exclusive lock proof (held continuously from accepted point
   through seal);
3. Current payload epoch matching the operation;
4. Completed database dump and object inventory checkpoints;
5. Exact repository descriptor (no arbitrary runtime-created tree).

The worker proposes the exact canonical root-manifest bytes through its
authority-bound request. The broker parses those bytes, recomputes their
digest, and validates every operation, accepted-point, repository-binding,
target, configuration, and payload-epoch field against protected state before
committing a companion. A digest without the exact canonical bytes is never a
sealable proposal.

Seal completion is a four-boundary idempotent protocol:

1. The broker commits the exact HMAC companion record in `committed` for the
   active, invocation-bound backup launch.
2. The descriptor-bound worker synchronizes `root-manifest.auth.json`,
   atomically appends the corresponding repository-index revision, and exits.
   The worker reports only a publication proposal and has no RPC or state
   transition that can terminalize the backup.
3. The native supervisor waits for and reaps the worker's complete process tree.
   The root helper then marks the launch `reaped` and, through an independently
   retained repository descriptor, recomputes the canonical root-manifest,
   database-dump, ordered inventory, complete file-tree, seal-companion, and
   repository-index evidence. It emits canonical
   `central.backup-repository-attestation/v1`, binding the launch-evidence ID,
   operation, backup, repository binding, root/companion/file-tree/index
   digests, index revision, and post-reap attestation time.
4. Only the root-authorized broker completion RPC accepts that exact
   attestation, matches it to the committed companion and protected launch
   record, and advances the operation to `sealed` and the launch to
   `completed`.

Generic operation CAS and worker-facing RPCs cannot enter `sealed`. C03
requires the root digest, companion digest, file-tree digest,
repository-manifest digest, and index revision to match the completed protected
attestation. A crash between boundaries remains non-restorable; exact retry
reconciles the same launch, proposal, attestation, and terminal record and
cannot create or replace another seal.

A missing, replayed, reordered, or runtime-only rewritten transition
returns `PROTECTED_STATE_INVALID`. This protects repository authority from
an operator-UID process and limits a compromised runtime to separately
declared post-authorization trust.

### Host tool contract

#### Pinned tool paths and versions

Backup and restore use host-installed PostgreSQL client tools at exact
pinned paths and versions:

| Tool | Absolute path | Required version |
| --- | --- | --- |
| `pg_dump` | `/usr/lib/postgresql/16/bin/pg_dump` | `16.14` |
| `pg_restore` | `/usr/lib/postgresql/16/bin/pg_restore` | `16.14` |

These paths are root-owned executables, not writable by the operator UID.
A version mismatch returns `POSTGRES_INCOMPATIBLE`, not a warning. The
tools are installed through the host prerequisite manifest and verified
by `central local doctor --host-prerequisites`.

#### Native supervisor and descriptor contract (worker fd 3/fd 4; tool fd 3)

The helper launches backup creation only through the installed native
supervisor and the fixed `/usr/lib/central/central-backup` executable. Caller
input cannot select an executable, UID/GID, environment, descriptor, repository
path, target, or mode. The broker persists an HMAC-protected launch record bound
to the exact runtime UID/GID, PID, process-start identity, executable, fixed
`backup-create` mode, deadline, operation, backup, and repository binding. Its
only legal lifecycle is `issued → active → reaped → completed`: exact worker
authentication moves `issued` to `active`, verified process-tree reaping moves
`active` to `reaped`, and exact post-reap attestation moves `reaped` to
`completed`.

The worker and PostgreSQL tool descriptor boundaries are distinct:

- **Worker fd 3 (launch evidence).** The native supervisor passes only the
  broker-issued opaque launch-evidence value at fd 3. The worker consumes it to
  authenticate its invocation-bound seal proposal; it is not a generic bearer
  credential and cannot complete the seal.
- **Worker fd 4 (repository).** The native supervisor passes the helper-selected
  bound repository descriptor at fd 4. The root helper keeps a separate
  descriptor open for post-reap attestation. The worker marks its fd 4 copy
  close-on-exec before spawning any tool, so neither `pg_dump` nor another
  descendant inherits repository authority.
- **Tool fd 3 (credential).** Within the child `pg_dump` or `pg_restore`
  invocation, fd 3 is a different descriptor table entry: a sealed
  `memfd_create` containing the single-line PostgreSQL password record and
  referenced only by `PGPASSFILE=/proc/self/fd/3`. No launch-evidence or
  repository descriptor crosses this nested exec boundary.

Backup and restore tool processes have explicit lifecycle control:

- **Parent.** The Central backup/restore process is the parent and holds a
  `pidfd` for each child. Child exit is observed through `pidfd` polling;
  no `waitpid(-1)` or signal-based reaping is used.
- **Supervisor.** The native supervisor owns the backup worker process group,
  installs itself as a Linux child subreaper before launch, and waits through
  direct-child and adopted-child reaping. The worker establishes a new session
  and isolated process group and installs parent-death cancellation. On
  completion, cancellation, or deadline the supervisor settles, terminates that
  group as necessary, and drains its adopted in-group descendants through
  `waitpid` until `ECHILD`. It returns success only after the fixed worker's
  launched process tree is gone. No post-reap attestation or terminal seal is
  attempted before that proof; the closed worker contract may not escape its
  session or process group.
- **Tool fd 3 (memfd).** The `PGPASSFILE` connection secret is delivered to the
  child through a sealed `memfd_create` file descriptor at fd 3. The
  parent creates a `MFD_CLOEXEC` memfd, writes the single-line
  `host:port:database:user:password` entry, seals it (`F_SEAL_SEAL |
  F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE`), then in the forked child
  duplicates it to fd 3 and explicitly clears `FD_CLOEXEC` only on that child
  fd before exec. `PGPASSFILE=/proc/self/fd/3` names the resulting descriptor.
  The child inherits no directory, socket, or broker-root descriptor beyond
  this bounded fd.

The parent clears the memfd buffer best-effort after the child execs. The
child receives no plaintext secret through an argument, environment
variable, or file path visible to other processes. The parent destroys the
memfd after the child process is reaped and its descriptors are gone.

#### Exact PGOPTIONS

Every `pg_dump` and `pg_restore` invocation uses:

```text
PGPASSFILE=/proc/self/fd/3
PGOPTIONS=-c statement_timeout=30000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=30000 -c application_name=central_backup_<operation-id>
```

The `application_name` is fixed and safe: it contains the operation kind
and an opaque operation identity prefix, never a secret, path, or caller
input. No other `PGOPTIONS`, environment variable, or `.pgpass` file is
permitted.

### Two-permit matrix

The installation-wide offline mutation permit budget is exactly two
permits. The coordinator acquires a permit before opening a `pgx`
connection or spawning a PostgreSQL tool process, passes one fixed safe
`application_name`, and releases the permit only after the
connection/process and inherited descriptors are closed.

The permit allocations for backup and restore phases are:

| Phase | Lock/control permit | Data/tool permit | Exact maximum |
| --- | ---: | ---: | ---: |
| backup accepted point and dump | one lifetime target-exclusive control | one `pg_dump` session | 2 |
| backup inventory/seal or target-reading verify | one lifetime/shared target control | one read-only inventory/verification session | 2 |
| backup throughput probe create/load, dump, drop | one lifetime target-exclusive control | exactly one provisioner session or one `pg_dump` session, sequentially | 2 |
| restore verify/ticket | one shared target control | one read-only verification session | 2 |
| restore database replacement | one lifetime target-exclusive control | one `pg_restore` session | 2 |
| restore full verification/quarantine/reset | one lifetime target-exclusive control | one `central_runtime` verification/reset session | 2 |
| non-target backup/restore status | none | at most one protected-state reader, no PostgreSQL | 0 |

No `pg_dump` or `pg_restore` parallel job is permitted. Object-store
work opens no PostgreSQL session. Dump and inventory are sequential.
Throughput-probe create/load closes its provisioner session before
`pg_dump`; dump is reaped before the provisioner reopens for drop; cleanup
retains the shared allocation until the disposable database, tool,
descriptors, and both sessions are proven gone.

### Host/target/repository lock order

The canonical lock order is:

1. Common target exclusion (advisory lock on the target database);
2. Protected operator state (exclusive over the external operator record);
3. Backup repository lock (exclusive for mutation, shared for reads);
4. Database transaction;
5. Object store.

No command upgrades in place. The lock order is never violated and no
cycle is possible. Every lock is bounded by its configured deadline and
cannot exceed the operation's total deadline.

### Subprocess deadlines, cancellation, and safe output

- Every `pg_dump`/`pg_restore` child has a fixed deadline derived from the
  operation's remaining budget. At deadline expiry the parent sends the
  child a graceful cancellation (SIGTERM), waits for the settlement grace,
  then escalates to SIGKILL.
- The parent monitors the child through `pidfd`. Child exit before the
  expected completion point is classified as `MUTATION_FAILED` (exit 6,
  resumable when the operation journal supports it) or `MUTATION_INDETERMINATE`
  (exit 6, non-resumable, manual inspection required).
- Safe output: the child's stdout and stderr are captured into bounded
  buffers (at most 256 KiB combined). The buffers are redacted before
  entering any log, manifest, or operator-facing output. No raw object
  key, path, credential, or sensitive timestamp is emitted.
- A `pg_dump` exit code other than 0 terminates the backup operation.
  The partial dump and inventory chunks are unreferenced and a new
  operation must establish a new point.

## Backup, restore, and capacity behaviour

### Streaming, checksum, retry, and multipart rules

#### Object-body streaming

Every object body is streamed from MinIO through the S3 adapter to the
repository using a fixed 256-KiB reusable copy buffer. The body is never
fully materialized in process memory. A streaming SHA-256 is accumulated
during transfer and compared to the database inventory checksum.
Mismatched bodies are re-fetched once; a second mismatch classifies the
backup as `CORRUPTED` and the operation is terminal.

#### Checksum verification

- **Database dump.** SHA-256 of the complete dump file, verified immediately
  after `pg_dump` exits and before inventory enumeration begins.
- **Inventory chunks.** Each chunk is checksummed independently. The root
  manifest commits an ordered list of chunk checksums. A chunk checksum
  mismatch quarantines the backup.
- **Object bodies.** Each body is checksummed during transfer and matched
  against the database record. A mismatch results in one retry, then
  terminal classification.
- **Root manifest.** The complete root manifest is SHA-256 checksummed.
  The seal companion binds this checksum.

#### Retry

- Body transfer uses at most 3 total attempts (first plus 2 retries) per
  body. A failure after 3 attempts classifies the body as
  `unrecoverable_body` and the backup as `CORRUPTED`.
- `CORRUPTED` is reserved for three complete size/SHA evidence mismatches.
  Transport, authority, capacity, and repository-I/O failures retain a
  non-corruption closed failure reason and are never relabeled as corruption. The
  protected `BackupOperation` persists that closed terminal reason, so
  `backup status` returns the same classification after a worker or broker
  restart.
- Body idle timeout is 30 seconds; total body transfer timeout is 30
  minutes.
- The operation admission deadline is 75% of the total operation
  deadline. An operation that has not passed its admission by that point
  fails closed.

#### Multipart

Object bodies in the repository are stored as single content-addressed
files. Multipart part size is 16 MiB for large objects but the phase-1
backup worker is single-threaded for body transfer (one worker, one
resident part, one upload at a time).

### Reference profile and capacity ceilings

#### Supported backup profile

| Dimension | Ceiling |
| --- | ---: |
| Database bytes (dump) | 5 GiB (5,368,709,120 bytes) |
| Object-store bytes (all bodies) | 10 GiB (10,737,418,240 bytes) |
| Database records (rows across all tables) | 10,000 |

These are the supported-profile ceilings, not general limits. A backup
that exceeds any ceiling returns `OUTSIDE_SUPPORTED_PROFILE` (exit 0
diagnostic, no mutation). The ceilings are derived from the reference
host's 40-GiB local storage with the fixed 4-GiB survival reserve and
1-GiB free floor.

#### Throughput probe

Before the first backup is accepted, the coordinator must perform a
throughput probe:

| Probe | Bytes | Time budget |
| --- | ---: | ---: |
| Dump probe (`pg_dump` to `/dev/null`) | 512 MiB | 5 minutes |
| Object probe (MinIO transfer to local storage) | 512 MiB | 5 minutes |

The probe creates and drops a disposable throughput-probe database on the
target instance under the same exclusive lock, generates probe data,
measures `pg_dump` throughput, and reads only the fixed MinIO object
`v1/system/backup-throughput-fixture-v1` into synchronized local storage for
the object measurement. The `minio_backup_v1` identity has `GetObject` on
`v1/ready/*` and that exact fixture object only: it has no list, put, delete,
staging, other `v1/system/`, or administrative authority. Seeding, replacing,
and deleting the fixed 512-MiB incompressible fixture therefore remain a
separate audited provision/cleanup mode and are not performed by backup.
Both measured paths must achieve at least
**16 MiB/s** (16,777,216 bytes/second). The probe result is valid for
at most 7 days. A throughput probe performing below the minimum returns
`THROUGHPUT_EVIDENCE_REQUIRED` (exit 3).

#### Rescue cold-copy model

The hard-expired rescue backup (`--security-rescue`) uses a conservative
cold-copy model:

| Dimension | Rescue value |
| --- | ---: |
| Minimum throughput | 8 MiB/s (8,388,608 bytes/second) |
| Operation deadline | 4 hours (14,400,000 ms) |
| Admission deadline | 75% of operation deadline |
| Capacity | Same 5-GiB/10-GiB/10,000-record profile |
| Scratch root | `/var/lib/central-rescue/v1/instances/<instance-id>/<rescue-operation-id>/` |

The rescue backup never mounts authoritative payload roots writable.
It copies bodies into a root-owned scratch root outside the backup
repository and is unrestorable until current security authority returns.

### Capacity guards

#### Reserve and free floor

| Resource | Value |
| --- | ---: |
| Survival reserve (per writable device) | 4 GiB (4,294,967,296 bytes) |
| Free floor (excludes allocated reserve) | 1 GiB (1,073,741,824 bytes) |
| Write quantum (maximum between checks) | 8 MiB (8,388,608 bytes) |

Before every write phase, the coordinator checks that free space minus the
survival reserve exceeds the free floor. A capacity check that fails
before the accepted point returns `CAPACITY_INSUFFICIENT` (exit 4). After
the accepted point, capacity exhaustion returns `MUTATION_FAILED` (exit 6,
operation journal required). Between checks, at most one write quantum
(8 MiB) is permitted.

#### Repository ceiling

| Resource | Ceiling |
| --- | ---: |
| Maximum sealed backups | 16 |
| Maximum repository total size | 256 GiB |

A backup create that would exceed either ceiling returns
`CAPACITY_INSUFFICIENT` (exit 4, before accepted point).
`backup prune` may create headroom by removing eligible backups.

#### Supported recovery-device filesystems

Recovery devices are narrowed to **ext4 and XFS only**. This is a
product-constraint narrowing owned by this contract and authorized by
[ADR 0018](../adr/0018-authorize-the-restore-capacity-reserve-authority.md).

Before it allocates anything, the restore capacity reserve authority
`statfs`-checks every capacity role root and fails closed on any filesystem
outside that allowlist, with the capacity refusal reason and no partial
effect. The narrowing exists because the reserve must be a *physical*
allocation: `fallocate` on ext4 and XFS reserves extents as a metadata
operation, and the same call on tmpfs would consume RAM rather than disk —
the exact opposite of reserving capacity. Btrfs, ZFS, overlayfs, network
filesystems, and tmpfs are all refused.

One consequence is worth stating rather than discovering: the kernel reports
a single `statfs` magic (`EXT4_SUPER_MAGIC`) for the whole ext2/ext3/ext4
family, so the allowlist is as narrow as the syscall permits and an ext2 or
ext3 role root is admitted by it. There is no finer distinction available
from `statfs` and this contract does not invent one.

A role root on an unsupported filesystem is a **host topology** condition,
not a media condition: the operator's remedy is to place the PostgreSQL and
object-store data directories on ext4 or XFS, not to re-verify the backup.

### Restore capacity reserve gate

The restore capacity reserve gate physically reserves disk before a
destructive `pg_restore` runs, so a recovery on a machine the operator has
already accepted as damaged cannot die of `ENOSPC` partway through replacing
the database. It is authorized by
[ADR 0018](../adr/0018-authorize-the-restore-capacity-reserve-authority.md)
and its design is
`docs/internal/superpowers/specs/2026-08-12-restore-capacity-reserve-authority-design.md` (upstream `central` record: `docs/internal/superpowers/specs/2026-08-12-restore-capacity-reserve-authority-design.md`).

The mechanism is: `restore verify` allocates a **reserve set** — one physical
reserve object per writable device the restore will touch — and the broker
daemon refuses to release the `pg_restore` credential at apply time unless
that reserve is still committed, unexpired, bound to the operation being
applied, and physically present when the daemon `fstat`s it for itself.

#### Verify mutates host free space

**`restore verify` is no longer free of physical effect.** It remains
non-mutating with respect to the target database and the object bodies —
that Gate 7 semantic is unchanged — but it now **consumes host free space**
for the duration of the reserve, up to 16 GiB, before it returns a ticket.

An operator watching `df` will see free space drop when a verify succeeds and
return when the reserve is released. That is the feature working, not a leak.
It is called out here because it contradicts the reasonable reading of
"non-mutating verification" everywhere else in this document, and because a
verify that is interrupted leaves those bytes held until a privileged
invocation reclaims them (see "Reclaiming a reserve" below).

On the reference topology this is one 4-GiB object, not four: all four
capacity roles resolve under
`/var/lib/central-state/v1/instances/<instance-id>/data/`, and roles sharing
one `st_dev` are backed by a single reserve object.

`restore verify` also now performs **one additional full media
verification**. The helper reads the sealed figures the reserve set records
(dump bytes, object bytes, artifact count) through the repository's own
`VerifyBackup`, which SHA-256s the database dump and every artifact body.
The verify path already performed three such walks inside the engine's
30-second window; this fourth one runs in the launcher *before* that window
opens, so a large repository cannot time the launch out before the engine
runs. The practical cost is roughly **+33%** on `restore verify` wall time,
proportional to repository size.

#### The four capacity role roots

The reserve covers four capacity roles, resolved from the instance
composition and never from a flag, environment variable, or helper request:

| Role | Host directory (reference topology) |
| --- | --- |
| `postgres_data` | `/var/lib/central-state/v1/instances/<instance-id>/data/postgres` |
| `postgres_wal` | same as `postgres_data` unless a dedicated WAL mount is defined |
| `postgres_temp` | same as `postgres_data` unless a dedicated temp mount is defined |
| `object_data` | `/var/lib/central-state/v1/instances/<instance-id>/data/minio` |

These directories are created by `central local up`, in its filesystem
initialization phase, before the PostgreSQL and MinIO containers start. They
are service data directories: their ownership belongs to the service that
runs on them (PostgreSQL's container chowns its own data directory), so the
reserve authority requires only that each is a directory reached without
following a symlink and reporting a non-zero device, never a fixed
`root:root 0700`.

**`restore apply` and `restore resume` now open all four role roots too**, to
keep the engine's inherited descriptor map identical across the three modes.
A role root that is missing, is not a directory, or cannot be opened is a
**new refusal on a path that previously proceeded**. An instance that has
never completed `central local up`, or whose data directories were removed
by hand, will now be refused at launch rather than partway through. The
remedy is `central local up`, not a re-verify.

#### Device-keyed reserve store layout

Each reserve object lives in a compile-time-fixed, device-keyed store
directory beneath the role root that anchors its device:

```text
<role-root>/
└── .central-restore-capacity-reserve/          # root:root, mode 0700
    └── fs-<32-hex-device-fingerprint>.reserve  # root:root, exactly 4 GiB
```

- The store directory name is a compile-time constant. No configuration
  value, environment variable, or argument can name it.
- The device fingerprint (`fs-` plus 32 hex characters) is a **naming key
  only**. Every identity decision in the gate turns on `st_dev`; a
  fingerprint match is never accepted as a substitute for an `st_dev` match.
- Every path component is resolved with
  `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH|RESOLVE_NO_XDEV)` from a held
  descriptor. The object is created `O_CREAT|O_EXCL|O_NOFOLLOW` and then
  `fstat`-checked for a regular file, `st_uid == 0`, `st_nlink == 1`, and a
  matching `st_dev`.
- Roles that share a device share one object. The store directory is keyed by
  **role root**, not by device, so two Central installations whose role roots
  sit on the same physical disk each admit their own four objects on it.

Because the store lives beneath the role root, a reserve object is visible to
`ls` and `stat` for anyone who can read those directories. That is what makes
the remediation playbook below executable without a privileged diagnostic
verb.

#### Reserve lifetimes and the two clocks

Three clocks bound a reserve, and they are not the same clock:

1. **The receipt window, 20 minutes.** How long a bearer value drawn for the
   engine stays usable. A set over which receipts were spent and whose spends
   have all lapsed is releasable.
2. **The reserve-retention clock, 15 minutes** — the restore ticket's own
   lifetime. A set that was bound to an operation by a *successful* verify,
   but whose apply never began, is retained only while that ticket is still
   `issued` and unexpired. Once the ticket lapses, the next sweep releases the
   reserve as helper abandonment.
3. **The absolute expiry, 8 hours.** The daemon stamps it at set creation; it
   is never read off the wire. It bounds every retention rule above, including
   the "cannot tell" ones, so nothing retains forever.

The retention clock is shorter than the receipt window, and that ordering is
deliberate: an operator who verifies and then walks away does not pin a
reserve for the receipt's 20 minutes, let alone the absolute 8 hours. **In
practice, a reserve from a verify whose apply never started is given back
roughly 15 minutes after the ticket was issued** — subject to a privileged
invocation actually running a sweep, which is the limitation below.

A set whose operation is in phase `applying`, whose operation record cannot
be read, or that is still covered by a live bound launch record is retained
whatever else is true of it, including past the absolute expiry. Freeing the
cushion out from under a live `pg_restore` is the failure this authority
exists to prevent.

#### Reclaiming a reserve: privileged invocation only

**Nothing runs on a schedule, and only root can free the bytes.** The
reconciliation sweep that releases reserves has exactly two call sites, both
inside `central --helper`, both named explicitly rather than left as "the
next root-owned invocation":

| Sweep call site | When it runs |
| --- | --- |
| `central-helper-startup` | once at helper daemon startup, after composition and before the helper begins serving |
| `central-helper-restore-launcher` | in the restore launcher, immediately before a `restore verify` allocates |

Both run under the helper's own root identity over a narrow reserve view —
the four record stores plus the role roots — never the broker daemon's whole
authority surface. Both report failures to stderr and continue: a
disaster-recovery tool that refuses a recovery because its housekeeping pass
failed is the failure mode this authority exists to avoid.

The consequence for an operator is direct. **On a host that only runs
`central serve`, reserved bytes stay reserved.** Neither call site is reached
by serving, by `local status`, or by any read-only verb. The bytes come back
when the helper is next started or when the next `restore verify` runs, and
not before. This repository ships systemd units for the backup and migration
launcher daemons only; how `central --helper` is started on a given host is a
deployment concern outside this contract.

#### Reserve inspection surface — built, not operator-reachable

A read-only reserve inspection surface exists and is **not reachable from an
operator's terminal in this build**. It is documented here so that a reader
who finds it in the source, or in the design, knows exactly what it is and
what it is not.

As built, it is broker frame `0xc5`. It admits **root peers only** and emits:

| Field | Value |
| --- | --- |
| `caller` | which of the two named sweep call sites produced the pass |
| `observed_at` | when that pass ran — the only way to tell a current view from a stale one |
| `records_intact` | whether the pass was able to read every record it needed |
| `live_sets` | `none` / `one` / `several` |
| `oldest_live_set` | `none` / `within_receipt_window` / `beyond_receipt_window` / `beyond_absolute_expiry` |
| `held_objects` | `none` / `one` / `several` |
| `devices[]` | per device fingerprint, the same three-value band |
| `findings[]` | the sweep's own outcome classes, each banded the same way |

Every figure is bucketed to `none`/`one`/`several`. There is no pathname, no
inode, no `st_dev`, no observed-free-bytes, and no exact byte count anywhere
in the shape — an exact figure over a 16-GiB range would be a device-headroom
oracle for any root peer, which is what the surface withholds by design.

**It has no operator invocation.** `checkPrivilegeForUID` admits UID 0 only
for the helper, broker, sandbox-launcher, and verify modes, and refuses it
for doctor, init, migrate, serve, and bootstrap — every verb an operator
types. The sudoers bridge that would carry a root-admitted operator verb is
still recorded as unimplemented in `internal/command/init.go`, and adding one
is a security-surface change that has not been authorized. Nothing in the
tree wires the frame's client. **Do not write remediation steps against this
surface, and do not read its existence as a diagnostic you can run.** The
sweep does publish its findings — the helper writes a signed, bucketed digest
that the hardened daemon reads back — so the data is fresh and waiting; only
the reader is missing.

#### Refusal vocabulary

| Reason | Where it is decided | What it means |
| --- | --- | --- |
| `RESTORE_CAPACITY_INSUFFICIENT` | the daemon's credential-release gate, the reserve allocator, and the pinned `pg_restore` adapter | a bounded resource is short: device headroom, or the remaining time budget |
| `RESTORE_STATE_INVALID` | protected operation, ticket, authorization, or credential-lease preconditions | wrong phase, wrong checkpoint, expired or unbound credential, substituted identity |
| `RESTORE_MEDIA_INVALID` | the sealed recovery evidence | manifest, seal, or dump could not be opened or verified |
| `RESTORE_ENGINE_UNAVAILABLE` | transport and composition | the credential transport was unreachable or the engine could not be run |

These four are the engine's closed, locator-free classification. The verify
command renders them to the operator as `RESTORE_VERIFY_CAPACITY_INSUFFICIENT`,
`RESTORE_VERIFY_STATE_INVALID`, `RESTORE_VERIFY_MEDIA_INVALID`, and
`RESTORE_VERIFY_ENGINE_UNAVAILABLE`; the first three exit `6`, the last
exits `3`.

**`RESTORE_RECEIPT_MODE_DENIED` is deliberately unreachable vocabulary.** The
receipt frame's mode gate admits all three restore launch modes, and the
launch record refuses any mode outside that same vocabulary, so no peer that
passes the launch-binding check can produce this reason. It is retained as a
fail-closed backstop for an allowlist a future mode could be added to without
being admitted here by default. An operator who somehow reads it out of a
denial has found a build whose launch record and receipt frame disagree about
what a mode is — a broker defect, not a capacity or admission condition. Do
not go looking for it.

### Stuck-reserve remediation playbook

**Trigger.** A `restore verify` refused with `RESTORE_CAPACITY_INSUFFICIENT`,
rendered to the operator as `RESTORE_VERIFY_CAPACITY_INSUFFICIENT` at exit
`6`:

```text
$ central restore verify

{"schema_version":"central.local-result/v1","command_id":"restore.verify","exit_code":6,"reason":"RESTORE_VERIFY_CAPACITY_INSUFFICIENT","details":{"safe_next_action":"CHECK_RECOVERY_MEDIA_AND_RETRY_VERIFY","elapsed_ms":8412},"timestamp":"2026-08-14T09:41:07Z"}
```

That reason is **structurally ambiguous**, and deliberately so: it is the same
value whether the device is genuinely too full to hold a survival reserve, or
whether a reserve from a previous crashed or abandoned attempt is still held
and the single-live-set rule is refusing the next one. The refusal carries no
pathname, no device name, and no byte count, because a capacity refusal that
reported exact headroom would be an oracle for anyone who could trigger one.
`safe_next_action` says `CHECK_RECOVERY_MEDIA_AND_RETRY_VERIFY`, which is the
generic verify next-action and is *not* the right instruction for this cause.

#### Step 1 — resolve the ambiguity, before doing anything irreversible

The two causes are distinguishable from the filesystem alone, with no
privileged verb, no state change, and nothing that can make the situation
worse. On the host, as a user who can read the instance data directories:

```bash
# The reserve objects, if any are held. One per device, exactly 4 GiB each.
ls -l /var/lib/central-state/v1/instances/<instance-id>/data/*/.central-restore-capacity-reserve/

# Real free space on the devices backing the four capacity role roots.
df -h /var/lib/central-state/v1/instances/<instance-id>/data/postgres \
      /var/lib/central-state/v1/instances/<instance-id>/data/minio
```

Read the result as follows.

- **A `fs-*.reserve` file is present.** A reserve is held. Its `mtime` tells
  you how long. Its 4 GiB is *counted as used* by `df`, so add 4 GiB per
  object back before judging whether the disk is genuinely full. Go to
  step 2.
- **No `fs-*.reserve` file, and `df` shows the device short of the
  demand plus a 4-GiB survival reserve plus the 1-GiB free floor.** The disk
  is genuinely too full. Free space or move the capacity role roots onto a
  device that has room. There is nothing stuck.
- **No `fs-*.reserve` file and ample free space.** The refusal came from
  something other than headroom — most likely a role root on an unsupported
  filesystem (see "Supported recovery-device filesystems"), or two role roots
  disagreeing about device identity. Check the filesystem types of the four
  role roots with `df -T` before anything else.

This step is the whole answer to why the playbook does not begin with an
irreversible action: the observation that distinguishes the two causes is a
directory listing.

#### Step 2 — let the sweep reclaim it

A held reserve is not stuck merely because it is held. Check the age first:

- **Held for less than about 15 minutes, and a `restore verify` recently
  succeeded.** This is the normal case and is not a fault. The reserve is
  being retained for the ticket that verify handed you. Either run
  `restore apply` with that ticket, or wait: once the ticket's 15 minutes
  lapse, the next sweep releases the reserve. **This is usually the whole
  answer, and the situation is usually not stuck at all.**
- **Held for longer, with no restore in flight.** The reserve is releasable
  and nothing has swept. Cause a sweep by restarting `central --helper` on
  the host — its startup sweep is one of the two call sites — or by running
  another `restore verify`, whose launcher sweeps before it allocates. Either
  reclaims every reserve whose retention rule no longer holds.
- **Held, and a `restore apply` or `restore resume` is in flight.** The sweep
  will refuse to release it, correctly. Let the apply finish or resume it.
- **Held past 8 hours with no live operation.** The absolute expiry has
  passed; the next sweep at either call site releases it unconditionally.

Re-run the `ls` from step 1 after the sweep. If the object is gone, retry the
verify.

#### Step 3 — when the sweep will not release it

If a sweep has run and the object is still there, exactly one class of cause
remains: something the sweep read told it to retain. In order of likelihood:

- **An operation is in phase `applying`.** The reserve is the cushion under a
  half-replaced database. The supported path forward is
  `central restore resume`, not release.
- **A record could not be parsed.** An unreadable or future-schema record is
  always retained and reported, never treated as absent — deleting an object
  because its record failed to parse is the exact `ENOSPC` this design
  exists to prevent. This is a defect condition: preserve the protected
  state and the helper's stderr output rather than clearing it by hand.

**Do not delete a `fs-*.reserve` file by hand while any restore operation is
non-terminal.** Doing so removes the guarantee the gate exists to provide and
will produce a refusal at the apply-time gate, because the daemon `fstat`s
the object for itself before releasing the credential.

#### What this playbook deliberately does not tell you to do

[ADR 0016](../adr/0016-adopt-a-terminal-outcome-for-an-interrupted-restore.md)
authorizes a terminal `abandoned` outcome for an interrupted restore, behind a
fresh PAM and physical-TTY ceremony, which releases the resources bound to
that operation. It is **irreversible**: an abandoned operation can never serve
and can never resume, and the target's data is given up.

Two things follow, and both are stated here rather than left to be discovered:

1. **This playbook never asks you to attempt it as a diagnostic.** Step 1
   distinguishes "genuinely full disk" from "held reserve" with a directory
   listing, so there is no branch on which an operator would reach for an
   irreversible transition to find out which cause they have. Abandonment is
   an answer to "this restore is dead and I accept the data loss", never to
   "why was my verify refused".
2. **The verb is reachable on a running host.** `central restore abandon` is
   in the command registry, the `restore-abandon` helper verb is in the
   operation matrix and on the helper's operator peer-admission arm, the
   production `helper.Server` carries a `RestoreAbandon` handler built on
   `broker.NewRestoreAbandonClient`, and `ModeDeferred` registers the CLI-side
   client. The ceremony is a third distinct typed phrase — `ABANDON RESTORE
   <instance> <target> <operation>` — read from the operator's physical TTY
   after a fresh PAM authentication, so a confirmation already given for
   `restore apply` cannot be replayed as consent to give that restore up.
   There is no `--force` on this path.

   **You name nothing.** `central restore abandon` takes no arguments. The
   root helper resolves the single live protected restore operation and acts
   on that. If there is none it answers `RESTORE_NO_LIVE_OPERATION`; if more
   than one matches it answers `RESTORE_LIVE_OPERATION_AMBIGUOUS` and
   **refuses rather than choosing** — it will not pick the newest, the first,
   or the most likely. There is deliberately no listing verb to help you
   choose: such a verb would run under root and reopen the security-surface
   question that kept the recovery inspection surface unshipped.

   Registration order was a precondition, not an accident: a host that could
   reach `restore apply` without being able to reach `restore abandon` is a
   host where an operation wedged in `applying` pins its reserve with no exit,
   so abandonment became reachable first and `verify`/`apply`/`resume` were
   registered only afterwards.

   Nothing has to be told to give the bytes back. The reserve sweep tests the
   operation's terminal outcome **before** its `Phase == applying` retention,
   so the phase change alone releases the set on the sweep's next pass. Do not
   go looking for a release command, and do not delete a reserve object by
   hand to hurry it. The reserve-return trigger on a serve-only host remains
   the ratified residual described below: both sweep call sites are inside
   `central --helper`.

### Ratified residuals

Two limits of the capacity gate are ADR-ratified tolerances rather than
defects, and both are recorded here — where an operator or a future
implementer will meet them — rather than only in the design.

**1. The object-bytes demand term is unverifiable at the gate.** When the
daemon re-derives the restore's planned write, it recomputes the dump size
and the artifact count from its own seal record and requires them to equal
what the helper recorded. It cannot do the same for **object bytes**: reading
them would require a daemon-side bounded inventory reader that does not
exist and was deliberately not added. The term is still carried into the
demand arithmetic from the helper's record — dropping it to zero because it
cannot be verified would turn a bounded tolerance into a permanent hole — but
a helper that under-reported it would obtain a smaller reserve than the
restore needs. What holds this closed is the launch-binding predicate on the
frame that carries the figure: only a live, root, launch-bound helper process
whose executable and process-start match the signed launch record can write
it. Any weakening of that predicate reopens this residual.

**2. The demand plan knowingly understates the true write on
shared-device topologies.** The plan reserves the archive independently for
PostgreSQL data and WAL, another archive plus the bounded inventory working
set for temp, and
every sealed body byte for object storage — then applies a 1.25 margin per
aggregated device. It does not model the staging and quarantine writes a
restore performs, nor the case where the backup repository shares a device
with a PostgreSQL role. The 4-GiB survival reserve is the cushion that
absorbs both. On a host where the repository, the database, and the object
store all share one disk, the reserve is doing more work than the arithmetic
shows. Giving the repository its own device reopens the decision; it is not
required, and this is a tolerance rather than an oversight.

### Quantitative bounds reference

| Rule | Value | Enforcement |
| --- | ---: | --- |
| `backup list` maximum entries | at most 100 sealed entries | Stable seal-time/backup-ID order, bounded cursor |
| Operation status maximum entries | at most 20 entries | Bounded scan of operation journals |
| Repository ceiling — sealed backups | at most 16 sealed backups | Rejected before accepted point |
| Repository ceiling — total size | 256 GiB | Rejected before accepted point |
| Prune — older than | older than 30 days | Date of each backup's accepted consistent point |
| Prune — retain newest | retain newest three | Never prunes below this count |
| Unsealed eligibility | 24 hours | A backup not sealed within 24 hours of its accepted point is eligible for automated cleanup |
| Audit — newest records | newest 10,000 records | Stream head bounded |
| Audit — time window | 365 days | Records older than this are maintenance-eligible |
| Audit — hard ceiling | 100,000 records / 1 GiB | Exceeding triggers `MAINTENANCE_REQUIRED` |
| Inventory — work slice | 100 pages or five minutes | Whichever is exhausted first |
| Parent deadline — ordinary backup | 2 hours (7,200,000 ms) | Default; 8-hour hard maximum |
| Parent deadline — rescue cold-copy | 4 hours (14,400,000 ms) | Fixed; not configurable |
| Dump probe | 512 MiB (536,870,912 bytes) | 5-minute budget |
| Object probe | 512 MiB (536,870,912 bytes) | 5-minute budget |
| Profile — database dump ceiling | 5 GiB (5,368,709,120 bytes) | Supported profile |
| Profile — object-store ceiling | 10 GiB (10,737,418,240 bytes) | Supported profile |
| Profile — record ceiling | 10,000 records | Supported profile |
| Ordinary minimum throughput | 16 MiB/s (16,777,216 bytes/s) | Both measured paths |
| Rescue minimum throughput | 8 MiB/s (8,388,608 bytes/s) | Conservative admission |
| Reserve — receipt expiry | 20 minutes | Bearer values drawn for the engine; a set whose spends have all lapsed is releasable |
| Reserve — retention clock | 15 minutes | The restore ticket's own lifetime; a bound set with no begun operation is retained only while that ticket is unexpired |
| Reserve — absolute expiry | 8 hours | Daemon-stamped at set creation, never read off the wire; bounds every retention rule |
| Reserve cap — objects per device | exactly one | Roles sharing one `st_dev` are backed by a single reserve object |
| Reserve cap — objects per device store | at most 4 | Objects already present plus the ones this call creates; refused before allocation |
| Reserve cap — bytes per device store | 16 GiB (17,179,869,184 bytes) | 4 objects x the 4-GiB survival reserve; refused before allocation |
| Reserve cap — live sets per instance | exactly one | In-process refusal plus the store's create-exclusive object open |
| Reserve — maximum supported resume count | N = 3 | `absoluteExpiry > ticketLifetime + N x apply deadline`; a fourth resume would cross the 8-hour expiry |

### Terminal and resume semantics

#### Ordinary backup

- `backup create` has a hard terminal classification. Once the accepted
  point is passed (target-exclusive lock acquired, dump started), lock
  loss, process crash, or total deadline expiry makes the operation
  terminal and non-resumable. Partial chunks remain unreferenced and a
  new operation must establish a new consistent point.
- The exception: non-mutating verification phases (before the accepted
  point's target-exclusive acquisition) are resumable across process
  boundaries.

#### Restore

- `restore apply` is always resumable through `restore resume
  --operation=<id>`. Each phase (`applying`, `verifying`, `quarantined`)
  checkpoints after every completed chunk and every operator resolution
  action. Resume revalidates the last immutable checkpoint and continues
  idempotently.
- `restore verify` is non-mutating with respect to the target database and
  object bodies. A restart requires a fresh `restore verify`.

#### Export and import

- `backup export` creates a sealed, independent export with an explicit
  `bx1` integrity token. The export operation is resumable before the
  export seal; after sealing, it is terminal.
- `backup import` is resumable through `backup import resume
  --operation=<id>` before the final seal verification.

#### Delete and prune

- `backup delete` is resumable through `backup delete resume
  --operation=<id>`. It removes one identified sealed backup in bounded
  quanta (at most 1,000 bodies per quantum, 64 MiB per quantum).
- `backup prune` is a maintenance operation with plan/idempotent-apply
  semantics. It is resumable through `backup maintenance resume
  --plan-id=<id>`.

### Continuous guards

These guards are evaluated at every phase boundary and every write
quantum (at most every 8 MiB):

1. **Capacity guard.** Free space minus survival reserve exceeds free
   floor.
2. **Repository ceiling guard.** At most 16 sealed backups and at most
   256 GiB total repository size.
3. **Lock guard.** The required lock is still held by this operation.
4. **Deadline guard.** The operation's remaining budget is positive.
5. **Authority guard.** The active security advisory bundle is not denied.

A guard failure before the accepted point returns a pre-mutation exit
code (2, 3, 4, or 5). After the accepted point, it returns exit 6 with
the operation journal updated.

## Operator journeys

Every transcript below is an **executable-future** transcript: normative
input/output contracts that Gate 9 must satisfy. They represent the
expected behaviour of a completed Gate 9 Slice C and Slice D
implementation. In the current Phase 0 repository, every command returns
exit `5`/`UNSUPPORTED_IN_THIS_SLICE`.

### Ordinary backup

```text
$ central --config ~/.config/central/instances/<id>/central.json backup create

--- PAM authentication required for backup-create ---
Password:

Target:           <target-id>
Repository:       /var/lib/central-state/v1/instances/<id>/backups
Consistent point: offline exclusive
Profile:          5 GiB database / 10 GiB objects / 10,000 records

Acquiring target-exclusive lock... acquired (30 s)
Throughput probe valid until 2026-07-23T12:00:00Z
Running pg_dump... 412 MiB in 18 s (23.8 MiB/s) ✓
Dump SHA-256: a1b2c3d4e5f6...
Enumerating objects... 847 objects, 1,204 MiB
Streaming bodies [847/847] ✓
Verifying inventory chunks [4/4] ✓
Sealing root manifest... sealed

Backup ID:  019c0000-0000-7000-8000-0000000000a1
Size:       1,616 MiB
Objects:    847
Duration:   94 s

Status: SEALED
```

### Interrupted backup (dump in progress, crash)

```text
$ central --config ~/.config/central/instances/<id>/central.json backup create

--- PAM authentication required for backup-create ---
Password:

Target:           <target-id>
Acquiring target-exclusive lock... acquired
Running pg_dump... 412 MiB in 18 s (23.8 MiB/s) ✓
Dump SHA-256: a1b2c3d4e5f6...
Enumerating objects...
--- PROCESS CRASH ---

$ central --config ~/.config/central/instances/<id>/central.json backup status

Active backup operation: none
Last terminal operation: <operation-id>
  State: MUTATION_FAILED
  Phase: inventory-enumeration
  Partial chunks: unreferenced
  Action: run 'central --config <path> backup create' for a new consistent point

$ central --config ~/.config/central/instances/<id>/central.json backup create

--- PAM authentication required for backup-create ---
Password:

A previous operation was terminal. Establishing a new consistent point...
Acquiring target-exclusive lock... acquired
Running pg_dump... 412 MiB in 18 s ✓
...
Backup ID:  019c0000-0000-7000-8000-0000000000a2
Status: SEALED
```

### Interactive restore

```text
$ central --config ~/.config/central/instances/<id>/central.json backup list

ID                                       Sealed at                   Size      Objects  Database
019c0000...00a1                          2026-07-16T14:22:00Z        1,616 MiB 847      412 MiB
019c0000...00a2                          2026-07-16T15:30:00Z        1,620 MiB 849      414 MiB

$ central --config ~/.config/central/instances/<id>/central.json backup restore-verify 019c0000...00a1

--- PAM authentication required for restore-verify ---
Password:

Target:        <target-id>
Backup ID:     019c0000-0000-7000-8000-0000000000a1
Manifest:      SHA-256 verified
Dump checksum: SHA-256 verified
Capacity:      5.2 GiB available (1,616 MiB required)
Reserve:       4 GiB physically reserved on 1 device
Security:      advisory bundle current
Ticket issued: <ticket-id>
Expires:       2026-07-16T15:45:00Z (15 minutes)

$ central --config ~/.config/central/instances/<id>/central.json backup restore-apply --operation=<ticket-id>

--- PAM authentication required for restore-apply ---
Password:

The restore operation will:

  Overwrite target: <target-id>
  From backup:      019c0000...00a1
  Objects:          847
  Database:         412 MiB dumped at 2026-07-16T14:22:00Z
  Expected size:    1,616 MiB

ALL EXISTING DATABASE STATE WILL BE REPLACED.
ALL SESSIONS AND GRANTS WILL BE REVOKED.
A FRESH BOOTSTRAP WILL BE REQUIRED.

Type the restore target identity to confirm: <target-id>

Target confirmed.

Acquiring target-exclusive lock... acquired
Ticket consumed
--- MUTATION ACCEPTED ---
Phase: applying
Restoring database... 412 MiB restored ✓
Phase: verifying
Verifying objects [847/847] ✓
No quarantined artifacts
Phase: authority-reset
Sessions revoked, grants suspended, bootstrap reset ✓
Phase: ready

Restore complete.
Fresh bootstrap: use 'central bootstrap show' in a separate trusted terminal.
```

**The `Reserve:` step, and how it differs from the rest of this transcript.**
Unlike every other line above, the reserve allocation it names is backed by
shipped code: `restore verify` physically allocates one 4-GiB reserve object
per writable device before it returns a ticket, and the apply-time gate
refuses the `pg_restore` credential without it. See
[Restore capacity reserve gate](#restore-capacity-reserve-gate) for the
mechanism, its bounds, and its limits. The shipped code emits **no such
human-readable line**: the helper performs the allocation silently, and the
operator's evidence is the `central.local-result/v1` JSON that the restore
verbs write to stdout. The as-built shapes of that JSON are below.

### Restore verify and apply — as-built results

Unlike the executable-future transcripts above, the results in this section
are the `central.local-result/v1` documents the shipped code writes. The
command grammar is `central restore verify` / `central restore apply` /
`central restore resume`.

All four verbs are registered in the binary's composition root and reach the
root helper over its Unix socket: `restore verify` through the `restore-verify`
helper verb, and `restore apply` / `restore resume` / `restore abandon`
through theirs. None of them answers `*_SERVICE_UNAVAILABLE` any more.

**None of them takes an argument, and none accepts an identity.** The helper
resolves the single candidate: verify resolves the one sealed backup in the
recovery repository's canonical index, and apply, resume and abandonment
resolve the one live protected restore operation. Two refusals follow from
that, and neither is a defect:

```text
# Nothing to work from.

$ central restore verify

{"schema_version":"central.local-result/v1","command_id":"restore.verify","exit_code":6,"reason":"RESTORE_NO_ADMISSIBLE_BACKUP","details":{"safe_next_action":"CHECK_RECOVERY_MEDIA_AND_RETRY_VERIFY","elapsed_ms":12},"timestamp":"2026-08-14T09:41:07Z"}

$ central restore apply

{"schema_version":"central.local-result/v1","command_id":"restore.apply","exit_code":6,"reason":"RESTORE_NO_LIVE_OPERATION","details":{"safe_next_action":"RUN_CENTRAL_RESTORE_RESUME","elapsed_ms":9},"timestamp":"2026-08-14T09:41:09Z"}

# More than one candidate matched. The verb refuses and does not choose: not
# the newest, not the first, not the most likely. There is no flag, no
# identity argument, and no listing verb that would let you pick -- a listing
# verb runs under root and reopens the security-surface question that kept the
# recovery inspection surface unshipped. Reduce the repository to one
# admissible backup, or resolve the extra live operation (see the abandonment
# verb above), and run the verb again.

$ central restore verify

{"schema_version":"central.local-result/v1","command_id":"restore.verify","exit_code":6,"reason":"RESTORE_BACKUP_CANDIDATE_AMBIGUOUS","details":{"safe_next_action":"CHECK_RECOVERY_MEDIA_AND_RETRY_VERIFY","elapsed_ms":14},"timestamp":"2026-08-14T09:41:07Z"}

$ central restore apply

{"schema_version":"central.local-result/v1","command_id":"restore.apply","exit_code":6,"reason":"RESTORE_LIVE_OPERATION_AMBIGUOUS","details":{"safe_next_action":"RUN_CENTRAL_RESTORE_RESUME","elapsed_ms":11},"timestamp":"2026-08-14T09:41:09Z"}
```

A successful verify and a capacity-authority refusal take these shapes:

```text
$ central restore verify

{"schema_version":"central.local-result/v1","command_id":"restore.verify","exit_code":0,"reason":"ok","details":{"ticket_id":"019c0000-0000-7000-8000-0000000000c1","backup_id":"019c0000-0000-7000-8000-0000000000a1","expires_at":"2026-08-14T09:56:07Z","safe_next_action":"RUN_CENTRAL_RESTORE_APPLY_BEFORE_TICKET_EXPIRY","elapsed_ms":11304},"timestamp":"2026-08-14T09:41:07Z"}

# The capacity-authority refusal. Structurally ambiguous between a genuinely
# full disk and a reserve still held from an earlier attempt — see the
# stuck-reserve remediation playbook.

$ central restore verify

{"schema_version":"central.local-result/v1","command_id":"restore.verify","exit_code":6,"reason":"RESTORE_VERIFY_CAPACITY_INSUFFICIENT","details":{"safe_next_action":"CHECK_RECOVERY_MEDIA_AND_RETRY_VERIFY","elapsed_ms":8412},"timestamp":"2026-08-14T09:41:07Z"}
```

The `expires_at` above is the ticket's 15-minute lifetime, which is also the
reserve-retention clock. `safe_next_action` on the refusal is the generic
verify next-action and is not the right instruction for a capacity cause; the
playbook is.

### Expired restore ticket

```text
$ central --config ~/.config/central/instances/<id>/central.json backup restore-apply --operation=<ticket-id>

--- PAM authentication required for restore-apply ---
Password:

Ticket expired at 2026-07-16T15:45:00Z (current time: 2026-07-16T15:50:00Z).
No mutation performed.

Action: run 'central --config <path> backup restore-verify <backup-id>' for a new ticket.
Exit: 4 / RESOURCE_TIMEOUT
```

### Fresh-host import

```text
# On the export host:
$ central --config ~/.config/central/instances/<id>/central.json backup export 019c0000...00a1 \
    --destination /media/secure-export/central-backup-2026-07-16

--- PAM authentication required for backup-export ---
Password:

Exporting backup 019c0000...00a1 to /media/secure-export/central-backup-2026-07-16
Verifying sealed backup... ✓
Copying database dump... 412 MiB ✓
Copying objects [847/847] ✓
Verifying destination integrity... ✓
Export sealed.

Export token:
  bx1:k1:abcdef0123456789:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:base64url-signature

COPY THE EXPORT TOKEN NOW. It is displayed only once and is not logged or stored.

$ central --config ~/.config/central/instances/<id>/central.json backup export token capture --destination /media/secure-export/central-backup-2026-07-16

--- PAM authentication required for export-token-capture ---
Password:

Export token:
  bx1:k1:abcdef0123456789:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:base64url-signature

# --- On the fresh import host ---
# Prerequisites: 'central local init', 'central local prepare', 'central local up'
# have completed. The instance is at MIGRATION_REQUIRED.

$ central --config ~/.config/central/instances/<new-id>/central.json backup import \
    --source /media/secure-export/central-backup-2026-07-16 \
    --token 'bx1:k1:abcdef0123456789:sha256:...'

--- PAM authentication required for backup-import ---
Password:

Import source:  /media/secure-export/central-backup-2026-07-16
Token:          verified (key k1, manifest sha256:...)
Backup ID:      019c0000...00a1
Size:           1,616 MiB
Objects:        847
Sealed at:      2026-07-16T14:22:00Z

Acquiring import lock... acquired
Verifying source integrity... ✓
Copying to repository... 1,616 MiB ✓
Verifying repository integrity... ✓
Import sealed.

Backup ID in this repository: 019c0000-0000-7000-8000-0000000000a1

Next: 'central --config <path> backup restore-verify 019c0000...00a1'
      then 'central --config <path> backup restore-apply --operation=<ticket-id>'
      then 'central --config <path> migrate up' (any required forward migrations)
      then 'central bootstrap show' in a separate trusted terminal
```

### Export token capture

```text
$ central --config ~/.config/central/instances/<id>/central.json backup export 019c0000...00a1 \
    --destination /media/secure-export/central-backup-2026-07-16

--- PAM authentication required for backup-export ---
Password:

Export token (displayed only once — copy now):
  bx1:k1:abcdef0123456789:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:base64url-signature

The export token format is:
  bx1:<export-key-id>:<public-key>:<manifest-digest>:<signature>

It is a broker-signed Ed25519 public integrity token. The token is
revealed only through the fresh-PAM exclusive physical-seat TTY and
never crosses controller JSON, logs, audit, HTTP, or any operator-writable
token file.

Copy it to paper or a separately administered root-protected recovery store.
Loss of the token can make recovery impossible.
```

### Rescue plus cleanup

```text
# Security authority is HARD_EXPIRED.
# Ordinary 'backup create' and 'serve' are blocked.

$ central --config ~/.config/central/instances/<id>/central.json backup create --security-rescue

--- PAM authentication required for backup-create (security-rescue) ---
Password:

SECURITY RESCUE BACKUP. This backup uses cold copies at reduced throughput
and will be unrestorable until security authority is restored.

Acquiring target-exclusive lock... acquired
Conservative admission: 8 MiB/s minimum
Creating cold copies... 412 MiB dump, 1,204 MiB objects
Dump SHA-256 verified ✓
Objects [847/847] verified ✓
Sealing rescue backup... sealed

Rescue backup ID: 019c0000-0000-7000-8000-0000000000b1
Status: SEALED (unrestorable until authority current)

$ central --config ~/.config/central/instances/<id>/central.json backup security-rescue cleanup --operation=<rescue-operation-id>

--- PAM authentication required for security-rescue-cleanup ---
Password:

Cleaning rescue scratch root... no Docker access, no mutation of backups or data
Scratch root: cleaned
Exit: 0
```

### Delete, prune, and maintenance

```text
$ central --config ~/.config/central/instances/<id>/central.json backup list

ID                                       Sealed at                   Size      Objects
019c0000...0090                          2026-06-10T10:00:00Z        1,100 MiB 610
019c0000...0095                          2026-06-15T10:00:00Z        1,200 MiB 720
019c0000...00a1                          2026-07-16T14:22:00Z        1,616 MiB 847

# Delete one identified backup:
$ central --config ~/.config/central/instances/<id>/central.json backup delete 019c0000...0090

--- PAM authentication required for backup-delete ---
Password:

WARNING: This will permanently delete backup 019c0000...0090
         and all its object bodies from the repository.
         The backup will no longer be restorable.

Type the backup ID to confirm: 019c0000-0000-7000-8000-000000000090

Backup ID confirmed.

Acquiring repository lock exclusively... acquired
Deleting backup 019c0000...0090:
  Bodies [610/610] ✓
  Manifest removed ✓
  Repository manifest updated ✓

Deleted: 1 backup, 610 bodies, 1,100 MiB recovered

$ central --config ~/.config/central/instances/<id>/central.json backup prune plan

--- PAM authentication required for backup-prune-plan ---
Password:

Prune plan: <plan-id>
Candidates (older than 30 days):
  019c0000...0095  2026-06-15T10:00:00Z  1,200 MiB  720 objects
Retained (newest 3):
  019c0000...00a1  2026-07-16T14:22:00Z  1,616 MiB  847 objects
Deleted:   1
Recovered: 1,200 MiB
Expires:   2026-07-16T16:00:00Z

$ central --config ~/.config/central/instances/<id>/central.json backup prune apply --plan=<plan-id>

--- PAM authentication required for backup-prune-apply ---
Password:

Type the plan ID to confirm: <plan-id>

Plan confirmed.

Acquiring repository lock exclusively... acquired
Pruning backup 019c0000...0095... ✓
Recovered: 1,200 MiB

$ central --config ~/.config/central/instances/<id>/central.json backup maintenance plan

--- PAM authentication required for backup-maintenance-plan ---
Password:

Maintenance plan: <plan-id>
Candidates:
  Unsealed backups: 1 (019c0000...00cc, 48 hours stale)
  Expired audit records: 2,340 (eligible, oldest 400 days)
  Protected stale candidates: 3

Retained: 3 sealed backups, 12,450 audit records, 5 protected candidates

Action: 'central --config <path> backup maintenance apply --plan=<plan-id>'
```

### Wipe

```text
$ central --config ~/.config/central/instances/<id>/central.json local wipe

--- PAM authentication required for wipe ---
Password:

WIPE WILL DESTROY ALL DATABASE AND OBJECT-STORE DATA.

Type the wipe confirmation phrase:
  WIPE <full-instance-id> <full-target-id> POSTGRES+MINIO

WIPE 019b0000-0000-7000-8000-000000000001 019b0000-0000-7000-8000-0000000000ff POSTGRES+MINIO

Confirmation accepted.

--- MUTATION ACCEPTED ---
Processing PostgreSQL root... empty ✓
Processing MinIO root... empty ✓
Reseeding credentials... 6 new generations staged ✓
Payload epoch advanced: 019c0000...00d0 → 019c0000...00d1

Wipe complete.
All database and object-store data destroyed.
Sealed backups preserved and remain verifiable.
New-epoch restore will require a fresh ticket.
Next: 'central --config <path> local up'
      then 'central --config <path> migrate up' or export restore.
```

### Bootstrap reset after restore

```text
# After a successful restore-apply:
$ central --config ~/.config/central/instances/<id>/central.json local up

Dependencies started ✓
Provision receipts current ✓
Dependencies healthy ✓
Migration status: MIGRATION_REQUIRED

$ central --config ~/.config/central/instances/<id>/central.json migrate up

--- PAM authentication required for migrate-up ---
Password:

Acquiring migration locks... acquired
Applying migrations [5/5] ✓
Migration status: READY

$ central serve

Serving on https://127.0.0.1:8080
Health: READY

# In a separate trusted terminal:
$ central --config ~/.config/central/instances/<id>/central.json bootstrap show

--- PAM authentication required for bootstrap-show ---
Password:

Bootstrap presentation (valid for 3 minutes):

  https://127.0.0.1:8080/bootstrap/complete?code=<single-use-code>

Open this URL in the managed browser.
```

### Restart

```text
$ central --config ~/.config/central/instances/<id>/central.json local down

Dependencies stopped ✓
Central stopped ✓

$ central --config ~/.config/central/instances/<id>/central.json local up

Dependencies started ✓
Provision receipts current ✓
Migration status: READY
Backup repository: 3 sealed backups, latest 2026-07-16T15:30:00Z

$ central serve

Serving on https://127.0.0.1:8080
Health: READY
```

## Destructive boundaries and restore authorization

### Restore confirmation — ADR 0009 amendment

**Historical context.** ADR 0008 and the canonical Gate 7 [application
boundaries](../architecture/rust-application-boundaries.md) contract section 5.4
originally defined restore-apply confirmation through `--confirm-operation`
and `--confirm-target` flags. Under the now-accepted same-operator-UID
threat model, those public values are replayable by a compromised
same-UID process and cannot replace fresh PAM plus helper-owned
confirmation.

**Explicit amendment/prohibition.** ADR 0009 amends ADR 0008 to remove
noninteractive restore-apply authorization. The following tokens are
explicitly prohibited in every restore apply/resume grammar and are
present in this document only as documentary evidence of the
amendment:

- `--confirm-operation` — prohibited; previously a Gate 7 noninteractive
  confirmation flag. Removed by ADR 0009 amendment to ADR 0008. The
  amendment record is authoritative; this documentary prohibition
  preserves the amendment trail.
- `--confirm-target` — prohibited; same amendment as above.
- `--yes` — prohibited; generic force/confirmation skip. Never accepted
  in any Central destructive command.
- `noninteractive` — prohibited; no restore apply/resume may accept
  noninteractive or redirected input as confirmation. The helper requires
  fresh PAM and physical-seat TTY interaction.

**Current confirmation protocol.** Restore apply and resume require:

1. Fresh PAM authentication through the installed helper;
2. The helper independently recomputes and displays the safe operation,
   target, and backup identities on the trusted TTY;
3. The operator types the verified target identity as the confirmation
   phrase (not a flag, not stdin piped content, not a JSON apply form);
4. The helper creates a one-use confirmation digest bound to the PAM
   session, boot ID, caller UID, operation ID, target/payload epoch, and
   a 60-second deadline;
5. The helper consumes the digest atomically at the accepted point.

**No JSON apply form.** Restore apply/resume emits only the standard
`central.local-result/v1` JSON on stdout. There is no JSON input form for
apply; the confirmation is exclusively a TTY conversation with the helper.

**Redirected input.** Piped or redirected stdin, `expect`-style
automation, and non-TTY invocations are rejected as `AUTHORITY_DENIED`
(exit 7).

### Wipe confirmation

Wipe uses the same fresh-PAM and physical-seat TTY protocol. The
confirmation phrase is:

```
WIPE <full-instance-id> <full-target-id> POSTGRES+MINIO
```

There is no `--yes`, force, partial-root selector, or caller confirmation
digest.

### Delete and prune confirmation

Delete requires typing the exact backup ID. Prune apply requires typing
the exact plan ID. Both require fresh PAM through the helper.

### Export token exclusivity

The `bx1` export token is revealed only through the fresh-PAM exclusive
physical-seat TTY. It never enters controller JSON, logs, audit, HTTP,
or any operator-writable token file. There is no `--output-token-file`
or `--token-format` flag.

## Validation

### Verification commands

```bash
rg -n 'pg_dump|pg_restore|PGPASSFILE=/proc/self/fd/3|worker fd 3|Worker fd 4|central.backup-repository-attestation/v1|issued → active → reaped → completed|target-exclusive|backup-repository.lock|root-manifest.auth.json' docs/operations/local-backup-and-restore.md
rg -n 'security-rescue|cold cop|abandoned_for_cleanup|bx1:|LUKS2|delete|prune|wipe' docs/operations/local-backup-and-restore.md
rg -n 'at most 100|seal-time|cursor|at most 20|16 sealed|256 GiB|older than 30 days|newest three|24 hours|10,000|365 days|100,000|1 GiB|100 pages|five minutes' docs/operations/local-backup-and-restore.md
rg -n 'Design-only.*commands are not currently available|effective only when ADR 0009 is Accepted|UNSUPPORTED_IN_THIS_SLICE' docs/operations/local-backup-and-restore.md
rg -n -- '--confirm-operation|--confirm-target|--yes|noninteractive' docs/operations/local-backup-and-restore.md
rg -n 'ext4 and XFS|EXT4_SUPER_MAGIC|\.central-restore-capacity-reserve|fs-<32-hex-device-fingerprint>\.reserve|RESTORE_CAPACITY_INSUFFICIENT|RESTORE_VERIFY_CAPACITY_INSUFFICIENT|RESTORE_RECEIPT_MODE_DENIED' docs/operations/local-backup-and-restore.md
rg -n 'central-helper-startup|central-helper-restore-launcher|consumes host free space|not reachable from an|Ratified residuals|object-bytes demand term|shared-device topologies' docs/operations/local-backup-and-restore.md
rg -n '20 minutes|15 minutes|8 hours|16 GiB|N = 3|exactly one|at most 4' docs/operations/local-backup-and-restore.md
git diff --check -- docs/operations/local-backup-and-restore.md
```

### Expected results

1. All positive recovery controls (`pg_dump`, `pg_restore`,
   `PGPASSFILE=/proc/self/fd/3`, worker fd 3/fd 4, post-reap repository
   attestation, the `issued → active → reaped → completed` launch lifecycle,
   `target-exclusive`, `backup-repository.lock`, and
   `root-manifest.auth.json`) appear in the document with exact contract
   definitions.
2. All ADR 0009-controlled extensions (`security-rescue`, `cold cop`,
   `bx1:`, `delete`, `prune`, `wipe`) appear in the document with
   explicit ADR 0009 dependency declarations.
3. Every quantitative bound from the normative inventory appears exactly
   once in the "Quantitative bounds reference" table.
4. The design-only banner and ADR 0009 dependency statement are present
   in the "Authority and status" section.
5. Every forbidden token (`--confirm-operation`, `--confirm-target`,
   `--yes`, `noninteractive`) appears only in the "Destructive boundaries
   and restore authorization" section, tagged as an explicit historical
   amendment/prohibition. No apply/resume grammar, transcript, or
   command definition accepts those tokens, a JSON apply form, redirected
   input, or a noninteractive form.
6. The restore capacity reserve controls appear with exact definitions: the
   ext4/XFS supported-filesystem narrowing (including the
   `EXT4_SUPER_MAGIC` family caveat), the device-keyed store layout and
   object name, and the closed refusal vocabulary — with
   `RESTORE_RECEIPT_MODE_DENIED` present only as the note explaining that it
   is unreachable and must not be hunted for.
7. Both sweep call sites are named literally (`central-helper-startup`,
   `central-helper-restore-launcher`), the statement that verify consumes
   host free space is present, the inspection surface is stated as not
   operator-reachable, and both ratified residuals are recorded.
8. Every reserve bound appears in the "Quantitative bounds reference" table:
   the 20-minute receipt expiry, the 15-minute retention clock, the 8-hour
   absolute expiry, the four cap values, and N = 3.
9. `git diff --check` prints nothing.
