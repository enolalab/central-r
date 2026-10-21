# ADR 0025: Settle the fs-init target-descriptor attestation across the container boundary

- **Number:** 0025
- **Title:** Settle the fs-init target-descriptor attestation across the
  container boundary
- **Status:** Accepted (Option B; mount_id dropped per-mode; ownership observed; host root created by Central)
- **Created:** 2026-08-20
- **Owners:** Central maintainer
- **Decision due:** None set — no calendar deadline is claimed here; the
  "Implementation blocked at" list below is the operative gate, and a
  clean-host B03 bring-up is blocked in fact until this is settled
- **Decision due history:** None
- **Implementation blocked at:**
  - Any change to `placeholderTargetDescriptor`
    (`internal/adapter/infralifecycle/lifecycle_linux.go:1137-1147`) or to the
    `Target` field it fills in `fsInitRequestPayload` (`:1189`).
  - Any change to `linuxValidator.Validate`'s comparison set
    (`central-local-infra/internal/target/linux.go:61-74`) or to how it obtains
    the descriptor it validates (`:46-56`).
  - Any change to the `target` rules in `request.Request.Validate`
    (`central-local-infra/internal/request/request.go:171-184`), which is a
    `central.local.infra.request/v1` schema-semantics change whether or not a
    JSON field moves.
  - Any widening of `validateBrokerSocketMount`
    (`internal/adapter/infralifecycle/compose_linux.go:1447-1467`) or of
    `addBrokerSocketMount` (`:811-817`) to admit a socket mount into a service
    other than `minio-provision` — required by Option A, and by Option C3b if
    its round trip is implemented over a socket rather than a second container
    run. No other option touches it.
  - Any change to `durableDataBindMounts` (`compose_linux.go:718-732`) made for
    attestation reasons — required by **Options B, C1a, C2, C3a and C3b**, i.e.
    by every shape in which `Validate` or `DescribeFD` reaches
    `validateMountBoundaries` against the bind-mount root. Only Option A (which
    fails earlier, on mount identity), Option C1b (which drops `Validate`
    altogether) and Option D leave it untouched. An earlier draft of this ADR
    attributed the cost to Option B alone; that was wrong, and the correction
    changes the cost ordering — see the option table.
  - Any creation of the host payload roots
    `/var/lib/central-state/v1/instances/<id>/data/{postgres,minio}`
    (`compose_linux.go:718-732` derives them; nothing creates them). There is no
    `MkdirAll` for that path anywhere in `internal/adapter/infralifecycle` — only
    journal, operation and secret roots are created — and `ValidateRoleRoot`'s
    own comment records that the role directories may not exist at composition
    time (`capacity_roles_linux.go:110-129`). Every option in which Central
    `stat`s the host path is blocked on settling who creates that directory,
    with what owner and mode. See the Context note on first-run ownership.
  - **Not blocked:** refreshing the fs-init mode inventories in
    `internal/dependencyprepare/assets/dependency-lock.json` from a future
    accepted delivery. That remains governed by ADR 0014 and ADR 0020 §1.
  - A clean-host B03 bring-up is blocked on this in fact, not only in policy —
    see Context.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-08-20)
- **Decision date:** 2026-08-20
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** ADR 0012 (`minio-provision` mode); ADR 0014 (fresh SB-G2
  delivery evidence as a precondition, Decision 8); ADR 0020 §1 (the dependency
  lock is updated only from accepted external deliveries); ADR 0024 (settled
  which image identity each mode carries, and refreshed the two fs-init mode
  digests — the adjacent half of the same clean-host bring-up);
  `docs/internal/superpowers/specs/2026-08-05-central-local-infra-design.md`;
  `docs/internal/superpowers/specs/2026-07-19-phase-1-b03-compose-lifecycle-design.md`;
  `docs/internal/superpowers/plans/2026-08-05-central-local-infra-implementation.md`;
  `docs/operations/central-local-infra-delivery-requirements.md`

## Context

**Provenance of the evidence below.** Every `file:line` citation in this
document was read directly from the two trees at Central `6a4e816` and
`central-local-infra` `5d5fbdd`, both with a clean working tree. **No build,
no test, and no container was run in preparing this ADR, and it asserts no gate
verdict.** Claims that are **not** directly readable from the source carry one
of two markers at the point of use, and there are no others:

- *[probe]* — resting on a container-boundary experiment run earlier in the same
  working session, on one host (Docker 29.1.3, no `userns-remap`), **not**
  re-executed here. Three claims carry it: the field-crossing table, the
  container-side `mount_id` result, and the `/payload` parent-boundary
  rejection.
- *[inference]* — reasoning from the code and the kernel's behaviour, never
  measured. One claim carries it: that an fd passed **into** the container by
  `SCM_RIGHTS` also fails mount identity. It is called out separately because it
  is the sole support for this document's strongest comparative statement.

Two further statements are marked **unverified** in place rather than inferred:
whether fs-init's capabilities are effective under `USER 65532`, and what owns
the host payload root on a first run. Both are cheap to check and both are
queued in Follow-ups **before** the ruling, not before the build.

### The immediate defect: two independent failures on the same call

`placeholderTargetDescriptor`
(`internal/adapter/infralifecycle/lifecycle_linux.go:1137-1147`) builds the
`target` object for every fs-init and minio-provision request:

```go
FDNumber:   3,
Device:     binary.BigEndian.Uint64(sum[0:8]) | 1,
Inode:      binary.BigEndian.Uint64(sum[8:16]) | 1,
MountID:    binary.BigEndian.Uint64(sum[16:24]) | 1,
Filesystem: "ext4",
RootID:     rootID,
```

`Device`, `Inode` and `MountID` are slices of a SHA-256 over the operation id
and root id. `UID` and `GID` exist on the struct (`:1092-1093`) and are never
assigned, so they ship as zero. The function's own doc comment
(`:1117-1136`) states the position plainly: it "is NOT a live FD/mount
attestation", "nothing in this repo's ComposeRunner -- nor `docker compose run`
itself -- passes a live host file descriptor into that container process", and
"solving the live attestation handshake is explicit follow-up work". That
comment is honest about the gap. This ADR exists because the gap is now on the
critical path.

The delivery side, `linuxValidator.Validate`
(`central-local-infra/internal/target/linux.go:42-76`), does the following in
order: reject a negative `FDNumber` (`:46-48`); `syscall.Fstat(expected.FDNumber)`
(`:50`); require a directory (`:53`); resolve the fd's own mount (`:56`); then
compare five digests — device, inode, mount, filesystem, and **ownership**
(`:61-74`, ownership at `:69` via `digestOwnership(expected.UID, expected.GID)`).

**There are two failures, and they are independent:**

1. **No descriptor is passed at all.** `RunWithInput` shells out to
   `docker compose --project-name … run --rm -T <service>`
   (`compose_linux.go:237`) through `executeCommandWithInput` (`:143-162`),
   which sets `cmd.Stdin`, `cmd.Stdout`, `cmd.Stderr` and **no `ExtraFiles`**.
   So fd 3 inside the container is whatever the container runtime left there,
   not a host directory. `syscall.Fstat(3)` fails and `Validate` returns
   `mismatch("descriptor-unavailable", …)` at `:51` — **before any of the five
   comparisons runs**.
2. **Even with a live descriptor, ownership would fail.** Central sends no
   `UID`/`GID`; the validator compares them at `:69` against the observed
   owner. On any idempotent repeat the target is 999:999 (postgres) or
   1000:1000 (minio), because that is what fs-init itself chowned it to
   (`fsinit/service.go:69`, `:136-140`) — so the sent 0:0 is wrong there by
   construction. What the owner is on a **first** run is **not established by
   anything in either tree**: no code in `internal/adapter/infralifecycle`
   creates `/var/lib/central-state/v1/instances/<id>/data/{postgres,minio}`
   (there is no `MkdirAll` for it), so the directory is presumably created by
   the Docker daemon as a side effect of the bind mount, with whatever owner
   and mode the daemon chooses. That presumption is **unverified in-repo** and
   is called out again in Sub-decision 2, which depends on it. Either way,
   fixing failure 1 alone leaves failure 2 standing.

**Consequence.** `Topology.Init` (`lifecycle_linux.go:1235-1258`) loops over
`fsInitCallSites` (`:1169-1176`) — `postgres-fs-init` first, then
`minio-fs-init` — and returns an error on the first non-zero exit code
(`:1253-1255`). So bring-up terminates at the very first call site, and every
phase after `Verified` is unreachable. This is the critical path for a
clean-host B03 bring-up, which SC-G1 needs. ADR 0024 removed one blocker on
that path (the fs-init mode digests now carry the accepted 2026-08-05 SB-G2
delivery `sha256:2f57e2c4…`,
`internal/dependencyprepare/assets/dependency-lock.json`); this is the next one.

### Scope: exactly two call sites, not four

The blast radius is narrower than the descriptor's reach suggests.

- **minio-provision never validates its target.** `dispatchMinioProvision`
  constructs `minioprovision.NewService(admin)` with no validator
  (`central-local-infra/cmd/central-local-infra/main.go:196`; the throughput
  fixture branch passes a literal `nil` validator at `:190`); contrast fs-init
  (`:98`, the `default:` branch at `:97-101`) and wipe (`:136`), which both
  build `target.NewLinuxValidator()`. The descriptor Central sends for
  minio-provision (`lifecycle_linux.go:1214`) is therefore only *syntax*-checked
  by `request.Request.Validate` (`request.go:176-184`) and is never `Fstat`'d.
  **That syntactic rule is the only check minio-provision's target receives**,
  which is why Sub-decision 1 cannot relax it blindly.
- **Central never invokes the central-local-infra `wipe` *mode*.** No
  `requestModeWipe` constant exists in `internal/adapter/infralifecycle` and
  nothing in Central builds a wipe request, so the delivery's wipe validator is
  never driven from here. This is **not** the same thing as Central's own
  `central local wipe` command (`internal/command/registry.go:54`,
  `Destructive: true`) or the `HelperWipe` verb
  (`internal/authority/domain.go:87`); those are unrelated host-side surfaces
  and neither dispatches the container mode.
- So this ADR governs `postgres-fs-init` and `minio-fs-init`, and nothing else.

Two related placeholders should be recorded even though they are out of scope
today: `backupMinioTargetDescriptor`
(`cmd/central/backup_minio_composition.go:289-296`) is a second, independent
copy of the same synthetic shape — `FDNumber: 3`, SHA-256-derived
device/inode/mount, `Filesystem: "ext4"`, `UID`/`GID` unset — and it is
likewise never `Fstat`'d today. It is not a second live instance of the defect;
it becomes one the moment minio-provision gains attestation.

### A correction to the record before the options are stated

`placeholderTargetDescriptor`'s comment asserts that "central-local-infra's own
tests construct exactly this kind of structurally-valid-but-unverified
TargetDescriptor for the same reason: nothing yet exercises the live
`syscall.Fstat` path outside a real container"
(`lifecycle_linux.go:1128-1131`). **That is not accurate in-process.**
`internal/target/descriptor_test.go` and `internal/fsinit/service_test.go` both
drive the real `NewLinuxValidator()` against real open directory fds derived by
`DescribeFD` (`target/linux.go:24-40`), and the existing suite already covers
device/inode/mount/filesystem/ownership mismatch and mount-point rejection.

The gap is narrower and more specific: **no container-boundary coverage reaches
`target.Validate`.** `scripts/clean-host-acceptance.sh` contains zero
occurrences of `fs-init`. The one script that does exercise the mode in a
container is `scripts/check-image-policy.sh`: it loops
`for mode in fs-init wipe minio-provision postgres-provision` (`:76`), and
inside that loop it both inspects a created container against the runtime policy
(`:87-101`), checks the embedded `/policy/entrypoint-allowlist.json` census
(`:103-112`), and actually runs
`docker run --rm --network none --read-only --security-opt no-new-privileges
--cap-drop ALL --ipc private "$IMAGE_REF" "$mode" </dev/null` (`:116-123`),
asserting exit status 1 and an `.outcome == "rejected"` /
`.reason == "request rejected"` receipt on stdout (`:126-131`). It is driven by
`make check-image-policy` (`Makefile:15-16`) and by
`testdata/imagepolicy/policy_test.go:130`.

So fs-init **is** already executed inside a container by an existing harness —
it simply never reaches `target.Validate`, because stdin is `/dev/null` and
`request.Decode` rejects the empty body first (`request.go:105` and the
zero-length guard above it). The unit tests and the delivery code therefore
agree with each other while both are silent about the descriptor path in the one
environment the code actually runs in. That is why this went unnoticed. It also
lowers the new-test estimate for the options below in two ways rather than one:
the unit-level validator harness already exists, **and** so does a per-mode
`docker run` + receipt-assert scaffold to extend. What every option must add is
a scenario that feeds a real request body in and asserts on the target outcome.

### What the attestation is for, and which fields can cross a container boundary

The governing documents state the property in two halves:

- **No caller-named path.** The design spec requires "a verified target
  descriptor, **never an arbitrary path**"
  (`docs/internal/superpowers/specs/2026-08-05-central-local-infra-design.md:67`), and
  the implementation plan is more explicit still: fs-init "Consumes:
  `request.TargetDescriptor` and **an inherited fixed file descriptor**"
  (`docs/internal/superpowers/plans/2026-08-05-central-local-infra-implementation.md:124`),
  "**Reopen only the inherited descriptor**" (`:133`).
- **Caller/callee agreement on object identity, re-checked around every
  mutation.** B03's design requires "one **held payload-root binding** each …
  Descriptor-relative access rejects symlinks, path traversal, mount
  replacement, unexpected device/inode, owner, mode, or mount options **before
  and after mutation**"
  (`docs/internal/superpowers/specs/2026-07-19-phase-1-b03-compose-lifecycle-design.md:51`).

Most of what `Validate` enforces is **self-referential** and consumes nothing
Central sends: the fd must `Fstat` and be a directory (`linux.go:50-54`); the
fd's own `mnt_id`, read from `/proc/self/fdinfo` (`:234-249`), must appear in
the reader's own `/proc/self/mountinfo` with a matching `st_dev`, or the call
fails closed with `"target: mount identity unavailable"` (`:191-225`); the
filesystem string is taken from that mountinfo line rather than from the caller;
and `validateMountBoundaries` (`:251-271`) requires the parent to be on the same
mount and then walks every descendant requiring the same. Only the five digest
comparisons at `:61-74` consume Central's declared values.

*[probe]* A container-boundary experiment run earlier in this session, using
the repository's own `internal/target` package against a Docker bind mount
(Docker 29.1.3, no `userns-remap`), reported the following. It was not
re-executed for this ADR.

| compared field | crosses the boundary? | note |
|---|---|---|
| `device` (`st_dev`) | **yes** | superblock property; identical host and container |
| `inode` (`st_ino`) | **yes** | identical host and container |
| `filesystem` | **yes** | identical; but see the `"ext4"` literal defect below |
| `uid` / `gid` | **yes, conditionally** | shifted by `userns-remap` or an idmapped mount, neither present on the probed host |
| `mount_id` | **no** | different mount object in the container's namespace |

The mount-id result is not a plumbing gap that better wiring closes. Docker's
`CLONE_NEWNS` gives the container a fresh `struct mount` for every entry in its
table, including the bind of the host directory, and the kernel allocates a new
id for each. Central never enters that namespace, so it cannot compute, look up,
or pre-agree the value. That much is what the probe measured.

*[inference — not measured]* The **reverse** direction is reasoning, not
observation, and it is flagged separately because it is the sole support for the
strongest comparative statement in this document (Option A "does not solve the
problem"). An fd handed **into** the container by `SCM_RIGHTS` names a `struct
mount` belonging to the *sender's* namespace; its `mnt_id`, as the receiver
reads it from `/proc/self/fdinfo`, is not enumerated in the receiver's
`/proc/self/mountinfo`, so `mountForDescriptor`'s lookup selects nothing and
fails closed at `:223-225` before any comparison. The probe described above
measured a container-side bind mount, **not a passed fd**, so this half was not
demonstrated. It is cheap to demonstrate and should be demonstrated before a
ruling that turns on it (see Follow-ups).

Taken together — one measured half, one inferred half — **`mount_id` looks
unsatisfiable in either direction**, which makes it a sub-decision in its own
right rather than something a live descriptor fixes along with everything else.

**If `mount_id` is dropped from the compared set, exactly one assertion is
lost:** "the mount through which the caller resolved the object is the mount
through which the callee resolved it." Every self-referential use of the value —
the mountinfo lookup, the `st_dev` cross-check, the filesystem derivation, and
the whole nested-mount boundary walk — is unaffected, because those read the
fd's *observed* `mnt_id`, never `expected.MountID`. `RevalidateAgainst`
(`:82-100`) likewise compares against `handle.snapshot`, which is
container-observed (`:75`), so pre-/post-mutation revalidation keeps working.

### A third failure the framing does not name: the parent-boundary check

*[probe]* The same experiment reported that `/payload` — the container path
`durableDataBindMounts` renders for both fs-init services
(`compose_linux.go:718-732`) — **is itself a mount point in the container's
namespace**, so `validateMountBoundaries`'s parent check rejects it: the parent
resolves to the container's `/`, whose `mnt_id` differs from the target's, and
`Validate` returns `mismatch("nested-mount", "none", "parent-boundary")`
(`linux.go:266-268`). The probe reported this firing for **all three**
descriptor variants it tried, including one in which every field was
container-observed and therefore matched by construction; and it reported that
a target *inside* the bind mount validates cleanly.

The probe half of this is the empirical confirmation; the structure is not in
doubt independently of it. `validateMountBoundaries` opens `..` relative to the
held fd (`openParent`, `linux.go:368-374`) and compares that parent's `mnt_id`
against the target's (`:266-268`). The parent of a **bind-mount root** is by
definition on the mount the root was grafted onto, i.e. a different `struct
mount` with a different id, so the check rejects a bind-mount root by
construction, not by accident of this host.

This matters because it lands **before** any field comparison, and because it
is the anti-mount-substitution check. **Relaxing it is off the table.**

**Which options this bills.** The check is reached from two places, and both are
self-referential — they consume nothing Central sends, so no schema choice
avoids them:

- `Validate` → `mountForFD` (`linux.go:56`), and `mountForFD` is
  `mountForDescriptor(fd, device, true)` (`:175-177`), i.e. boundaries always
  checked.
- `DescribeFD` → `mountForDescriptor(…, isDir)` (`:32`), i.e. boundaries checked
  for any directory a container self-describes.

So the cost lands on **every option in which the container ends up holding an fd
on `/payload` itself** and either validates it or describes it — Options B, C1a,
C2, C3a and C3b alike. It is **not** exclusive to Option B, and an earlier draft
of this document said it was; that error made Options C1 and C3 look cheaper
than they are. Only Option A escapes it, and only because it fails one step
earlier on mount identity (`:223-225`); Option C1b escapes it only by deleting
`Validate` from fs-init entirely; Option D escapes it by changing nothing.

What "have the container hold a usable fd on the payload root" costs, in every
one of those options, is that the fs-init target must become a subdirectory
beneath the bind mount rather than the bind-mount root — i.e. an edit to
`durableDataBindMounts`, which is documented there as the sole source of host
paths and is also read by `RoleRoots` for the capacity reserve
(`capacity_roles_linux.go:97`). The naive variant — mounting the parent
`…/data` — puts both roots inside each fs-init container, contradicting B03's
"one held payload-root binding each"; a variant preserving that isolation also
moves the daemons' mount sources (`postgres` → `/var/lib/postgresql/data`,
`minio` → `/data`, same lines). Whether that last part is a real migration cost
depends on whether any instance exists to migrate; see the qualifier under
Option B. Either way it must not be priced as an implementation detail.

### The cost floor every option shares

No option is free, and none can ship incrementally.

- **`Decode` uses `DisallowUnknownFields`**
  (`central-local-infra/internal/request/request.go:105`). Adding any JSON
  field is a hard reject on the currently delivered image. Removing or ignoring
  a field is tolerated. Either way **Central and the delivery must move in
  lockstep**, so the smallest schema delta is a real tiebreaker.
- **Every option changes the delivered Go binary**, so every option forces a
  new `central-local-infra` delivery build and a new independent review, and a
  new `dependency-lock.json` mode-inventory edit whose SHA-256 propagates to
  `dependency_lock_sha256` in `internal/recovery/evidence.go`,
  `scripts/verify-sc-g0-evidence.sh`, and every stored acceptance manifest.
  ADR 0020 §1 permits that lock edit only from an **accepted** external
  delivery; ADR 0014 Decision 8 requires the applicable independent SB-G2
  controls to be repeated for the new candidate.
- **Only Option A additionally changes the syscall policy.**
  `policy/seccomp/central-local-infra-v1.json` allows `sendmsg` (`:34`) and
  deliberately does **not** allow `recvmsg`, with the reason stated inline:
  "Only the send direction is used: this binary never reads a reply from the
  broker connection … so `recvmsg` is deliberately not added here" (`:36`).
  Receiving a descriptor is impossible under the shipped profile. Since the
  syscall-policy digest is a named immutable input of the delivery requirements,
  Option A invalidates a strictly larger slice of the SB-G2 evidence than any
  other option.
- **The freshly built four-mode delivery is unreviewed and will be
  superseded.** A build passing clean-host acceptance this session (manifest
  `sha256:67ebaf72…`, source `5d5fbdd`) is not in the lock and has not been
  reviewed. Whatever this ADR settles requires a new delivery commit, so
  reviewing `67ebaf72…` first would pay for two reviews rather than one.

### Collateral defects on the same critical path

Not decided by this ADR, recorded so they are not lost. Each blocks the same
clean-host bring-up independently.

- **The minio-provision broker rendezvous is never created on the bring-up
  path.** `ensureBackupMinioBrokerRendezvous` has exactly one call site —
  `cmd/central/backup_minio_composition.go:90`, reachable only from the backup
  and C02-throughput preparers. `Topology.ProvisionMinio`
  (`lifecycle_linux.go:1277-1311`) goes straight to `RunWithInput` with no
  rendezvous step, and nothing else in the tree creates
  `/run/central-infra/<instance>/broker/minio-provision.sock`. So even a
  perfectly fixed fs-init leaves B03 dead one phase later, when the provisioner
  dials a socket that was never made. This is separable and probably smaller
  than the attestation question.
- **The receipt carries no target or mount evidence at all.**
  `receipt.Receipt` (`central-local-infra/internal/receipt/receipt.go:59-68`)
  holds schema version, mode, ids, outcome, reason, timestamps and the two
  throughput sub-receipts — no target fields. But the design spec requires the
  receipt to contain "verified target identity and mount evidence"
  (`2026-08-05-central-local-infra-design.md:82`) and B03 step 6 requires
  Central to "verify their acknowledgements against held descriptor evidence"
  (`2026-07-19-phase-1-b03-compose-lifecycle-design.md:62`). Central cannot:
  `Init` reads only the exit code (`lifecycle_linux.go:1249-1255`). **Whatever
  is decided about the request side, a green fs-init remains
  indistinguishable from a validator that never ran.**
- **`Filesystem: "ext4"` is a hardcoded literal** (`lifecycle_linux.go:1144`,
  and again at `backup_minio_composition.go:294`). On any btrfs/xfs/zfs host it
  is wrong by construction, so it is a latent clean-host portability bug
  independent of everything else here.
- **fs-init's capabilities may not be effective.** The compose policy leaves
  `user: ""` for both fs-init services, and the renderer emits the `user:` key
  only when the value is non-empty (`compose_linux.go:1020-1021`), so the
  container runs as the image's `USER 65532:65532`
  (`central-local-infra/image/Dockerfile:25`) — a non-root uid — while being
  granted `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER` under
  `no_new_privileges: true`
  (`internal/adapter/infralifecycle/assets/compose-policy.json`). fs-init's
  whole job is `Fchown` to 999:999 / 1000:1000 plus opening a root-owned
  directory. Whether those capabilities are effective for a non-root uid in
  this configuration is **unverified here**. If they are not, fs-init fails
  *after* `Validate` for a reason no option below addresses — and it would force
  a second delivery immediately after the one this ADR triggers. **Checking
  this before a build is cheap; discovering it after a review is not.**

## Decision

**Decided 2026-08-20 by the maintainer: Option B, with `mount_id` dropped from
the compared set, ownership observed rather than declared, and the host payload
root created by Central.** The option texts below are unchanged from the
Proposed draft, so what was weighed stays readable beside what was chosen.

- **Option B is adopted.** `Validate` opens a compiled-in path with
  `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` instead of `Fstat(FDNumber)`, and Central
  replaces `placeholderTargetDescriptor` with a fresh `stat` of the host path
  `durableDataBindMounts` already derives. The probe recorded above is what
  makes this the evidenced choice: `device` and `inode` cross the container
  boundary byte-identical.
- **Option A is not adopted, on measurement rather than preference.** The probe
  showed a received fd carries the host's `mnt_id` and the container's
  `mountinfo` lists a disjoint range, and that dropping `mount_id` from the
  compared set does not rescue it, because `mountForDescriptor` fails in the
  lookup before any comparison. A would additionally have been the only option
  to change the seccomp policy, to widen the guard keeping host sockets out of
  capability-bearing containers, and to introduce an uncensused descriptor.
- **Sub-decision 1: drop `mount_id` from the compared set**, scoped per-mode.
  The scope warning in that sub-decision is binding: the `else` branch at
  `request.go:176-184` governs fs-init, wipe and minio-provision together, and
  minio-provision's descriptor is never `Fstat`'d, so that syntactic rule is
  the only check its target receives. Relaxing it repo-wide would silently
  weaken minio-provision. The relaxation must be written per-mode.
- **Sub-decision 2: ownership is observed, never declared.**
- **The host payload root is created by Central**, not left to the Docker
  daemon. The measurement above showed the daemon otherwise creates it, and
  every missing ancestor, as `root:root` mode `0755` — a permission nobody
  chose. Central creating it deliberately is what makes sub-decision 2
  tractable, since Central then knows the owner it established rather than
  inferring one; the ADR anticipated exactly this ("if the answer is instead
  'Central creates it', then Central chooses the owner and this sub-decision
  becomes trivial").

**What this ruling does not settle, and implementation must:** which owner and
mode Central creates the root with, and what that implies for fs-init's own
chown step — if Central pre-establishes the service ownership, fs-init's chown
becomes idempotent verification rather than mutation, which is a change in what
that mode does and must be stated rather than absorbed. The parent-boundary
problem recorded in Context is also unresolved by this ruling and remains
Option B's largest implementation cost.

**The question:** how should the fs-init target be identified to
`central-local-infra`, given that no live descriptor crosses `docker compose
run` and that `mount_id` appears unsatisfiable across a mount namespace in
either direction?

*(**Decided 2026-08-20 — Option B; see Decision above.** The note below is preserved from the Proposed draft as the analysis the ruling was made against, not as a verdict. In the style of
ADR 0024's option notes: on the evidence gathered here, Option A is not one
problem behind a seccomp edit but several unresolved sub-problems, one of which
— the mount-identity failure — is not fixed by passing a live fd at all, though
that half rests on the *[inference]* flagged in Context and should be
demonstrated before it is leaned on. Options B and C3b are the two shapes that
deliver a real host↔container object binding, from opposite ends: B by
attesting before the mutation, C3b by authorizing between the open and the
mutation. The Compose mount-layout re-parenting is **not** a differentiator
between them and the C-family — it is shared by B, C1a, C2, C3a and C3b alike,
which is a correction to an earlier draft of this note that treated it as
Option B's exclusive cost. Option C1's earlier billing as "smallest schema
delta with an exact in-repo precedent" does not survive the evidence either:
fs-init consumes `Target.RootID`, so the postgres-provision precedent cannot be
copied as-is. Which of these the project adopts, and in what order, is the
maintainer's call, and nothing in this note should be read as a ruling.)*

Two columns of this table are the same for every row but D and are stated once
here so the differentiating columns stay readable: **every** option A/B/C
changes the delivered Go binary, and therefore forces a new
`central-local-infra` delivery build, a new independent review under ADR 0014
Decision 8, and a `dependency-lock.json` mode-inventory edit whose SHA-256
propagates to every pinned `dependency_lock_sha256`. Every option A/B/C also
requires Central and the delivery to land in lockstep, because
`DisallowUnknownFields` (`request.go:105`) makes any added JSON field a hard
reject on the currently delivered image. That shared floor is carried as the
last column below so it is visible per row rather than only in prose.

| Option | Live host↔container object binding? | Compose mount-layout re-parenting | Seccomp change | Schema delta | New delivery + independent review |
|---|---|---|---|---|---|
| A — SCM_RIGHTS rendezvous into fs-init | **No** — fails on mount identity first | no (fails one step earlier) | **yes** (`recvmsg`; `dup2` is already allowed, `dup3` is not) | `fd_number` semantics | yes |
| B — container opens by path, Central states host-observed identity | **Yes** (pre-mutation attestation) | **yes** | no | relax `mount_id`-required | yes |
| C1a — target reduced to `root_id`; `Validate` keeps only its self-referential checks | No | **yes** (same reason as B) | no | relax the target syntax rules for fs-init; `root_id` must survive | yes |
| C1b — as C1a, but fs-init drops `Validate` entirely | No | no | no | same as C1a | yes |
| C2 — narrow the compared set only | Partial | **yes** (same reason as B) | no | relax `mount_id`-required, drop ownership | yes |
| C3a — post-hoc receipt audit record | No (admission control removed) | **yes** (`DescribeFD` walks boundaries too) | no | **two** contracts: request + receipt | yes |
| C3b — two-phase admission: describe, Central verifies, then authorize | **Yes** (post-open, pre-mutation) | **yes** (same reason) | no | two contracts **plus** a second round trip into a one-shot runner | yes |
| D — status quo | No | no | no | none | no |

### Option A — Deliver a live host descriptor via an `SCM_RIGHTS` rendezvous

Give fs-init a broker socket, have it receive a host directory fd over
`SCM_RIGHTS` before `fsinit.Run` reaches `Validate`, and move it to the fd
number the request names. The wire shape has a working in-repo precedent in the
minio-provision credential frame.

Note the syscall budget for that last step, since it is one line and easy to get
wrong in the estimate: the shipped allowlist permits `dup` and `dup2`
(`policy/seccomp/central-local-infra-v1.json:8`) and does **not** permit `dup3`.
So the renumbering must either use `dup2`, at no seccomp cost beyond `recvmsg`,
or budget a **second** allowlist entry. Today's delivery is `linux/amd64`-pinned
(`Makefile:10`, `image/Dockerfile:1`, `:8`), where `syscall.Dup2` exists, so
`dup2` is available at no extra policy cost. It is worth recording that this
does not survive a future multi-arch delivery: Go defines `Dup2` in every
`zsyscall_linux_*.go` **except** `arm64`, which offers only `Dup3` — the
`dup2(2)` syscall does not exist on that architecture.

**Central already has fd-sending code**, contrary to a claim made while
researching this: `WriteMsgUnix` + `unix.UnixRights` appear at
`internal/adapter/authority/broker/service.go:1551`,
`secret_bootstrap_transport_linux.go:143-144`,
`migration_client_linux.go:73`, `backup_worker_credential_linux.go:76`,
`restore_capacity_receipt_frame_linux.go:477` and
`restore_migration_credential_linux.go:156`. What does **not** exist is any
path that delivers an fd *into a container*: the one socket that crosses the
container boundary today runs the other way, container-as-sender.

Consequences and cost:

- **It does not solve the problem** — *no longer an inference. Measured
  2026-08-20; see "Probe: a live fd across the container boundary" below.* A
  received fd names the *host's* vfsmount. `mountForDescriptor` resolves the
  fd's `mnt_id` against the **container's** `/proc/self/mountinfo` and fails
  closed with `"target: mount identity unavailable"` (`linux.go:223-225`) when
  no entry matches. Option A therefore still requires a mount-identity redesign, or
  fs-init in the host mount namespace — which the compose policy's
  `propagation: rprivate`, `host_pid`/`host_ipc`/`host_network: false` posture
  forbids and which would be an isolation reduction. **This ADR does not propose
  that.** One consequence worth noting: because A fails at mount identity, it
  never reaches `validateMountBoundaries`, which is why A is the one non-D
  option that does **not** carry the Compose mount-layout cost.
- **It is the only option that changes the syscall policy**, adding `recvmsg`
  against an explicit inline rationale for its absence
  (`policy/seccomp/central-local-infra-v1.json:36`), and therefore invalidating
  the largest slice of SB-G2 evidence.
- **It widens the single guard that keeps host sockets out of containers.**
  `validateBrokerSocketMount` (`compose_linux.go:1447-1467`) today rejects any
  `.sock` mount for any service other than `minio-provision`, and
  `addBrokerSocketMount` (`:811-817`) early-returns for everything else. Both
  fs-init services carry `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER`.
  **Widening that rule for two capability-bearing services is the
  security-relevant part of this option**, not the `SCM_RIGHTS` plumbing, which
  is well-trodden. It is an authority expansion that must be argued on its own
  terms, not presented as a mechanical extension.
- **Nothing censuses the extra descriptor in fs-init.** The runtime policy
  census `policy.Census([]int{req.Target.FDNumber}, []uint64{req.Target.MountID})`
  is wired only into `dispatchWipe`
  (`central-local-infra/cmd/central-local-infra/main.go:126`); fs-init is the
  bare `default:` branch (`:97-101`) and runs no census at all. An fd received
  into fs-init would therefore be counted by nothing. Either the census is
  extended to fs-init or the option ships an uncensused inherited descriptor
  into a capability-bearing service; that belongs in the authority-expansion
  argument above, not in the plumbing estimate.
- It further needs: a new frame marker and `SO_PEERCRED` gate in the broker
  dispatch. Note the peer uid to admit is **65532**, not root: the compose
  policy leaves `user: ""` for both fs-init services and the renderer emits no
  `user:` key when it is empty (`compose_linux.go:1020-1021`), so the container
  runs as the image's `USER 65532:65532`
  (`central-local-infra/image/Dockerfile:25`). It also needs a per-service
  rendezvous step on the
  `Init` path mirroring `ensureBackupMinioBrokerRendezvous`; a compose-policy
  asset change, which re-keys `PolicyDigest` (`compose_linux.go:1538`) in every
  request body; and a new receive-side validator, since the existing
  `ReceiveDescriptor` demands an empty root-owned 0400 tmpfs memfd and an
  fs-init target is a populated directory.
- The `SB-G3` Task 14 lesson in the precedent must be carried over: folding the
  marker byte into the ancillary-bearing message, or reading any part of that
  message with a plain read, makes the kernel **silently discard the fd** while
  the sender still reports success.

### Probe: a live fd across the container boundary (measured 2026-08-20)

Option A's first consequence was flagged as an inference that "should be
demonstrated before this bullet is leaned on". It has now been demonstrated.

A host process opened a directory, sent the descriptor over `SCM_RIGHTS` to a
process in a container, and the container read `/proc/self/fdinfo/<fd>` and
`/proc/self/mountinfo`:

```
HOST:      sending fd for /var/tmp/fdp/payload  dev=66306 ino=23724065
HOST:      fd mnt_id = 44
CONTAINER: received fd 4
CONTAINER: fstat -> dev=66306 ino=23724065
CONTAINER: fd mnt_id = 44
CONTAINER: mountinfo ids = 7105 7107 7108 ... 7075
CONTAINER: VERDICT -> NOT FOUND — mount identity unavailable
```

Two results, and the second is the one that decides Option A:

1. **`device` and `inode` survive the boundary intact.** The container's
   `fstat` returned byte-identical values to the host's. Any design that
   compares only those two — plus a filesystem obtained some other way — is
   unaffected by the namespace boundary. This is a positive result for Option
   B and for the C family.
2. **`mnt_id` does not.** The fd carries the host's mount id (44); the
   container's `/proc/self/mountinfo` lists an entirely disjoint range. The
   lookup finds no entry.

**Dropping `mount_id` from the compared set does not rescue Option A.** The
failure is in the *lookup*, not the comparison: `mountForDescriptor` returns
`"target: mount identity unavailable"` when `selected.id == 0`
(`linux.go:223-225`), and `Validate` calls it before it builds `observed` and
before the comparison loop runs, because the `filesystem` value comes from the
same lookup. So Sub-decision 1's "drop it" branch leaves Option A failing at
exactly the same call. Only the "redesign mount identity" branch — the one this
ADR states it cannot supply and has no estimate for — makes Option A reach a
comparison at all.

### Option B — The container opens the target by path; Central states host-observed identity

`Validate` opens a compiled-in path with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`
instead of `Fstat(FDNumber)`; Central replaces `placeholderTargetDescriptor`
with a fresh `stat` of the host path `durableDataBindMounts` already derives,
sending real device, inode, filesystem, uid and gid; `mount_id` is dropped from
the compared set per the sub-decision below.

What it buys, stated precisely:

- A genuine **host↔container object binding** — the directory being chowned is
  the one Central attested to during its capacity, epoch and wipe-barrier
  checks — plus TOCTOU closure over a host-side rmdir-and-recreate or rename
  swap between render and run, plus detection of a crossed call site or a
  stale/misrendered project. That is meaningful, not syntactic, **provided
  Central really `stat`s the host directory per operation.**

What it does **not** buy, and this is a change to a claim in an accepted design
document rather than an implementation detail:

- **It does not deliver "never an arbitrary path"**
  (`2026-08-05-central-local-infra-design.md:67`) or "reopen only the inherited
  descriptor" (`…-implementation.md:133`). Inside the container the target is
  still reached by resolving a literal pathname. In the Compose topology that
  anti-arbitrary-path property is in fact delivered by the render-time mount
  policy — `durableDataBindMounts` is the sole source of host paths and the
  request body cannot influence it — plus the container's minimal mount table.
  **Option B re-sites that property onto the Compose render and demotes the
  descriptor to a binding/TOCTOU check.** If adopted, the design and plan
  language should be amended to say so rather than left to contradict the code.
  The path must stay compiled-in; a caller-supplied path would reintroduce
  exactly the "misleading caller-selected path/FD authority surface" the
  postgres-provision rationale already refuses (`request.go:70-73`).

Cost:

- **The Compose mount-layout change described in Context** — unavoidable,
  because the parent-boundary check rejects the bind-mount root and must not be
  relaxed. It is the item most likely to be under-priced, but it is **shared**
  with C1a, C2, C3a and C3b, so it is not a reason to prefer them over B.
  - *Qualifier on the migration half.* The isolation-preserving variant moves
    the daemons' mount sources too, which reads as a data-layout migration for
    existing instances. Whether any instance exists to migrate is **not
    established here**: the defining fact of this phase is that a clean-host B03
    bring-up has never succeeded past `postgres-fs-init`. If there are no live
    instances, that half of the cost is close to vacuous and only the renderer
    and `RoleRoots` derivation change. The maintainer should settle which world
    applies before weighing this against C1.
- **Who creates the host payload root, and with what owner.** B has Central
  `stat` `/var/lib/central-state/v1/instances/<id>/data/{postgres,minio}`. On the
  first clean-host run — the exact case this ADR exists to unblock — nothing in
  either tree creates that directory, so the `stat` is `ENOENT` unless something
  creates it first. Docker creating it as a bind-mount side effect is the
  presumption, not a verified fact. This interacts with fs-init's whole purpose
  (chown plus `0700`) and with `ValidateRoleRoot`'s existence check
  (`capacity_roles_linux.go:130-139`, deliberately uncalled today; its comment
  at `:126-129` expects `"local up"` to have created the role directories, which
  nothing in the tree does). It is unpriced and must be settled with the option,
  not after it. The same applies to C2, C3a and C3b.
- Ripple into wipe: `internal/wipe/service.go` is built end-to-end on
  `FDNumber`, so changing its semantics touches wipe even though Central never
  drives the wipe mode.
- `validateMountBoundaries` recursively enumerates the entire target tree
  (bounded at 100000 entries per directory). Nobody has ever paid that cost,
  because `Validate` has never run in a container. On a populated postgres data
  directory it runs on **every** fs-init call, including idempotent repeats.
- Seccomp is unchanged — `openat`, `fstat`, `fstatfs`, `newfstatat`, `statx`
  and `getdents64` are already allowed — so the syscall-policy half of the SB-G2
  evidence survives. This is a genuinely cheaper re-review than Option A.

### Option C1 — Stop declaring an identity fs-init cannot check

The shape here is "remove the fabricated attestation". The precedent usually
reached for is `postgres-provision`, which omits the target from the wire
(`Request.MarshalJSON`, `request.go:74-93`) and **forbids** a nonzero target on
arrival with the stated reason that "accepting even an unused target would leave
a misleading caller-selected path/FD authority surface" (`:171-174`, comment at
`:70-73`).

**That precedent cannot be copied as-is, and an earlier draft of this ADR said
it could.** `postgres-provision` forbids the *entire* struct — `if r.Target !=
(TargetDescriptor{})` (`request.go:172`) — and is deliberately excluded from the
`root_id` identity requirement (`:153-155`). fs-init needs `Target.RootID`:

- `request.Validate` requires `target.root_id` to be a safe identity for every
  mode **except** `postgres-provision` (`request.go:153-155`), so a wholly empty
  target is rejected at `Validate` with `invalid("root_id", …)` before any
  fs-init code runs.
- `fsinit.Run` rejects any root other than `postgres`/`minio`
  (`fsinit/service.go:37-39`) and derives the chown target from it —
  `fixedOwnership(req.Target.RootID)` (`:69`, `:136-140`). Without `root_id`,
  fs-init cannot choose 999:999 versus 1000:1000 at all.

So C1's real schema delta is "**`target` may carry `root_id` and nothing
else**" — a bespoke per-mode rule with **no** precedent in this repo — or else a
new **top-level** `root_id` field, which is an *added* JSON field and therefore
the hard-reject case under `DisallowUnknownFields`, the exact inverse of the
advantage C1 was previously credited with. Either way "smallest delta, exact
precedent to copy" was wrong. It is still plausibly the *smallest* delta of the
non-D options, but it is a **new rule**, not a copied one, and it must be stated
that way.

C1 then splits on what `Validate` does afterwards, and the two branches have
very different costs:

**C1a — `Validate` still runs, on a container-opened target.** `Validate` opens
the compiled-in payload path and runs only its self-referential checks —
directory, mount resolution, boundary walk — with no caller-declared values to
compare. This is the branch the earlier draft described. It requires the same
container-side "open by path" rework as Option B, and therefore **hits the same
`/payload` parent-boundary rejection and carries the same Compose mount-layout
cost**. Its table row previously read "Compose change: no"; that was wrong.

**C1b — fs-init drops `Validate` entirely.** No Compose change, no boundary
walk. But this deletes the directory check, the mount-identity fail-closed, the
parent-boundary check and the descendant walk from the one mode whose job is a
privileged recursive `chown`, and it removes the pre-/post-mutation
revalidation `mutate` depends on. **That is a materially larger assurance
reduction than "stop asserting something false"**, and it should be described as
such if it is chosen. This ADR does not propose it; it is listed because it is
the only reading under which C1's "no Compose change" claim holds.

Common to both branches:

- **The honest description is "stop asserting something false", not "attest
  more narrowly".** It removes a fabricated attestation; it does not add a real
  one. Relative to what the code *claims* to check, this is a reduction in
  stated assurance; relative to what it *actually* checks today — nothing, since
  `Validate` never gets past `Fstat` — C1a is an increase in honesty and no
  change in fact. C1b is a reduction in both. Say which is being adopted.
- Note that with a zeroed `FDNumber` the field defaults to `0`, which is
  **stdin** — the request channel itself (`main.go:50`). Under C1a the container
  must therefore open the payload path itself rather than trusting `FDNumber`;
  leaving `Validate` to `Fstat(0)` would reject on `special-file`
  (`target/linux.go:53-54`) against the request pipe. This is a real code change
  in the delivery, not a schema-only edit.
- **The wire delta must be spelled out before either branch is implementable.**
  `MarshalJSON` for `postgres-provision` omits the whole `target` object
  (`request.go:79-92`). C1 must say explicitly whether fs-init does the same and
  moves `root_id` elsewhere, or keeps `target` present with only `root_id`
  populated. That choice determines whether the delta is an added field (hard
  reject on the delivered image) or a relaxed rule (tolerated), and therefore
  whether Central and the delivery can be staged at all. It is the same
  schema-semantics question Sub-decision 1 raises for B and C2.
- Central deletes `placeholderTargetDescriptor` for the fs-init call sites and
  edits `fsInitRequestPayload`. No seccomp change under either branch.
- Gives up the host↔container object binding entirely, and with it the TOCTOU
  and crossed-call-site detection Options B and C3b would provide.

### Option C2 — Keep the descriptor, narrow only the compared set

Keep sending a descriptor but compare device, inode and filesystem plus the
boundary walk, dropping `mount_id` **and** ownership from `linux.go:61-74`.

- Needs Central to `stat` the host path exactly as Option B does, inherits the
  same unresolved question about who creates the host payload root, and hits the
  same parent-boundary problem and the same Compose mount-layout cost. It is
  Option B minus the ownership check, not a cheaper shape.
- Dropping ownership avoids making "no `userns-remap`, no idmapped mounts" a
  host prerequisite, at the price of not detecting a target whose owner is
  wrong before fs-init chowns it. Since fs-init's job *is* to set ownership,
  that is a defensible trade — but it should be a decision, not a side effect.

### Option C3 — Move the attestation to the receipt

Two shapes share the receipt as the carrier, and they are **not** equivalent:
one gives up admission control, the other keeps it. The earlier draft named only
the first, which made the receipt family look strictly weaker than it is.

**C3a — post-hoc audit record.** The container self-derives its descriptor,
reports it in the receipt, and Central compares after the fact.

- **This removes admission control rather than narrowing it.** The privileged
  mutation happens first and is judged afterwards.
- Self-deriving means `DescribeFD` (`target/linux.go:24-40`), which calls
  `mountForDescriptor(…, isDir)` at `:32` with boundary checking on for a
  directory. So C3a hits the **same** `/payload` parent-boundary rejection and
  carries the **same** Compose mount-layout cost as B. Its earlier "Compose
  change: no" cell was wrong.
- It touches a **second** wire contract (`central.local.infra.receipt/v1`,
  `receipt/receipt.go`).

**C3b — two-phase admission.** The container opens and describes its observed
descriptor; Central verifies that against a host `stat`; Central then authorizes
the mutation; only then does fs-init chown. This keeps admission control, needs
no live fd, and needs no seccomp change, and it closes the receipt-evidence gap
at the same time.

- It is a genuine host↔container object binding, taken at the last possible
  moment rather than the earliest, so it is stronger than B on TOCTOU and weaker
  than B on "refuse before the container is even started".
- **Its real cost is the round trip, and it is not small.** `RunWithInput` is
  one-shot: it delegates to `RunWithInputOutput` (`compose_linux.go:223-226`),
  which runs `docker compose … run --rm -T` (`:237`) and the container exits.
  Getting an answer back *into* the same process therefore needs either
  - a **second container run** — which means a new mode, and the mode census is
    closed at four in three places (`image/Dockerfile:14`,
    `image/entrypoint-allowlist.json`, and `scripts/check-image-policy.sh:106`
    asserting `.modes | length == 4`), plus cross-run TOCTOU between the
    describe run and the mutate run; or
  - a **broker socket into fs-init** — which inherits Option A's
    `validateBrokerSocketMount` widening and its authority-expansion argument
    wholesale, without inheriting A's seccomp cost (the container would send,
    not receive, and `sendmsg` is already allowed at
    `policy/seccomp/central-local-infra-v1.json:34`).
- Both routes are real work. Neither is free. C3b is listed because refusing the
  receipt family on C3a's "admission control removed" alone would be a false
  dichotomy, not because it is cheap.

Common to both:

- Central's side of the receipt work is **less** than the earlier draft implied.
  `Init` discards the body only because it calls the discarding wrapper
  `RunWithInput` (`lifecycle_linux.go:1249`); the receipt-bearing variant
  `RunWithInputOutput` already exists and is documented as "the receipt-bearing
  variant used by closed one-shot protocols" (`compose_linux.go:228-231`, `func`
  at `:232`). The seam is already there — what is missing is a receipt schema
  that carries target evidence and a Central-side comparison.
- The receipt work closes the receipt-evidence gap recorded in Context, and B03
  step 6 requires that gap closed **regardless** of which option wins. **The
  receipt work is better understood as complementary to A/B/C1/C2 than as an
  alternative to them** — as a substitute for admission control, C3a is weaker
  than any of them; as an addition, it is the only thing that gives Central
  proof the validator ran at all.

### Option D — Status quo: leave the placeholder in place

No change. `placeholderTargetDescriptor` keeps sending synthetic identity with
no ownership, and `Validate` keeps failing at `descriptor-unavailable`.

Consequences: zero implementation cost, no new delivery, no new review — and
**a clean-host B03 bring-up remains impossible**, since `Topology.Init` fails at
`postgres-fs-init` and nothing after `Verified` is reachable. SC-G1 stays
blocked on it. The doc comment at `lifecycle_linux.go:1117-1136` remains
accurate about the gap while being wrong about the delivery repo's tests, and
the two-repo contract keeps describing a handshake that neither side performs.
Recorded so the option space is complete and so the cost of *not* deciding is
visible next to the cost of deciding.

### Sub-decision 1 — `mount_id` (unavoidable under every option)

`mount_id` appears unsatisfiable across a mount namespace in either direction —
one half measured, one half inferred, see Context — so no option can "just send
it correctly". The choices are:

- **Drop it from the compared set.** The bounded loss is stated in Context: one
  assertion, no effect on any self-referential use.
- **Keep it and accept that fs-init cannot validate.** This is Option D by
  another name for fs-init specifically.
- **Redesign mount identity.** This is the only branch that preserves the full
  guarantee, and the only one under which Option A becomes viable, so it must
  not be offered without a price. It is **not sketched here and has no
  estimate**: it would need an identity for "the object's mount" that is stable
  across a `CLONE_NEWNS` boundary, which the kernel does not offer through
  `mnt_id`, and every in-repo consumer of the value
  (`mountForDescriptor`'s mountinfo lookup and `st_dev` cross-check, the
  filesystem derivation, `validateMountBoundaries`, `RevalidateAgainst`) reads
  the *observed* id rather than a declared one, so the redesign is about what
  Central can pre-agree, not about the checks. **A maintainer cannot rule on
  this branch as written; if it is live, it needs its own design pass before
  the ruling.**

**Scope warning: the relaxation is not fs-init-only unless it is written to
be.** "Relax `mount_id`-required" means editing `request.go:176-184`, and that
`else` branch governs **fs-init, wipe and minio-provision together** — it is
everything except `postgres-provision`. As established in Scope,
minio-provision's descriptor is never `Fstat`'d, so that syntactic rule is the
**only** check its target receives. Relaxing it repo-wide therefore weakens
minio-provision's sole target check as a side effect. **This ADR does not
propose that.** Either the relaxation is scoped per-mode, or the weakening is
stated plainly and argued; it must not happen silently. The same applies to
Sub-decision 2's ownership question and to Option C1's target-syntax change.

Whichever is chosen, `request.Validate`'s current rule that
`device, inode, and mount_id are required` (`request.go:180`) is a
schema-semantics change under Options B, C1 and C2 even though no JSON field
moves.

### Sub-decision 2 — ownership must be observed, never declared

If ownership stays in the compared set, Central must `stat` the host directory
**fresh at request-build time**. fs-init chowns its root to 999:999 (postgres)
or 1000:1000 (minio) (`fsinit/service.go:69`, `:136-140`), so the correct
expected ownership is the pre-state, and the pre-state differs between the two
paths: on any idempotent repeat it is 999:999 or 1000:1000, which is
established in-repo.

**What it is on a first run is not established, and this sub-decision rests on
it.** Nothing in `internal/adapter/infralifecycle` creates
`/var/lib/central-state/v1/instances/<id>/data/{postgres,minio}` — there is no
`MkdirAll` for that path — so on a clean host the directory is presumably
created by the Docker daemon as a side effect of the bind mount, with the owner
and mode the daemon chooses (conventionally root-owned, but that is convention,
not a citation). Until that is checked on a real host, "the correct expected
ownership on a first run" is an open question, not a fact this ADR supplies. If
the answer is instead "Central creates it", then Central chooses the owner and
this sub-decision becomes trivial — which is one more reason the host-root
creation question belongs with the ruling.

**Measured 2026-08-20, on a real host — this settles the first-run half.**
Running a container that bind-mounts a source path that does not exist, the way
bring-up does:

```
IN-CONTAINER /payload: uid=0 gid=0 mode=755 type=directory
HOST .../instances/inst-a/data/postgres: uid=0 gid=0 mode=755 type=directory
HOST .../instances/inst-a/data:          uid=0 gid=0 mode=755
HOST .../instances/inst-a:               uid=0 gid=0 mode=755
HOST .../instances:                      uid=0 gid=0 mode=755
```

So the Docker daemon creates the missing source **and every missing ancestor**
as `root:root` mode `0755`. "Conventionally root-owned" is now a citation
rather than an assumption. Two consequences follow:

- The first-run expected ownership is `0:0`, and the idempotent-repeat
  expectation is `999:999` or `1000:1000`. They genuinely differ, which is the
  concrete case behind the paragraph below.
- The payload root is world-readable (`0755`) and root-owned in the window
  before fs-init chowns it, and nothing in Central chose that — it is whatever
  the daemon defaults to. Whether Central should create these roots itself, and
  so choose owner and mode deliberately, is a live follow-up rather than a
  settled point; if it does, this sub-decision becomes trivial as noted above.

What *is* established either way: **any design in which Central declares a
static owner is wrong on at least one of the two paths**, and since retriable
operations must be idempotent, "send the owner we created it with" is not
viable. Keeping ownership compared also makes "no `userns-remap`, no idmapped
mounts" a host prerequisite, which should be routed to the existing `local
doctor --host-prerequisites` surface rather than left implicit.

One related constraint: `st_dev` must be observed fresh per operation and
**never persisted** into a durable binding for later comparison.
Anonymous-device filesystems (btrfs, zfs, overlayfs, tmpfs) receive a major-0
`dev_t` allocated at mount time, which changes across reboot or remount. Safe
for Options B, C2, C3a and C3b as described, since all four observe it per
operation rather than persisting it.

## Consequences

### Benefits

- **Any option (including D, if ruled deliberately):** the cross-repo contract
  stops silently describing a descriptor handshake that neither side performs.
  Today the request declares an attestation, the validator enforces one, and
  the two have never met — with no record that this was anyone's decision.
- **Options B, C2 and C3b specifically:** Central would, for the first time,
  state something true about the object it is asking a capability-bearing
  container to mutate, and the `Filesystem: "ext4"` literal retires as a side
  effect because the value becomes observed rather than declared.
- **Option C1 specifically:** removes a fabricated attestation, at the smallest
  schema delta of the non-D options and with no seccomp change. Note it is a
  *new* per-mode rule rather than a copy of the `postgres-provision` precedent
  (see the option), and only its C1b branch avoids the Compose change.
- **Option C3 (either branch) or its follow-up:** the only path by which Central
  ever obtains evidence that the validator ran, which B03 step 6 requires and
  which no request-side fix provides.
- **Deciding at all unblocks the sequencing question.** The UID/GID half is
  cheap and independent of the descriptor half, so a ruling lets the two
  failures be sequenced rather than treated as one atomic change.

### Costs and limitations

- **No option is free and none can ship incrementally.**
  `DisallowUnknownFields` (`request.go:105`) forces Central and the delivery to
  land together; every option changes the delivered binary, hence a new build,
  a new independent review under ADR 0014 Decision 8, and a
  `dependency-lock.json` edit permitted by ADR 0020 §1 only from an accepted
  delivery, whose new SHA-256 propagates into every pinned
  `dependency_lock_sha256`.
- **The unreviewed `67ebaf72…` delivery will be superseded** by whatever is
  decided. Reviewing it before this ADR lands pays for two reviews.
- **Option A's cost is concentrated in a security guard, and it does not fix
  the mount-identity failure.** `validateBrokerSocketMount` is today the single
  render-time rule that no container but `minio-provision` receives a host
  socket. Widening it for **two non-root (65532) capability-bearing services**
  — `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER` under `no_new_privileges: true`,
  with `user: ""` in the compose policy and `USER 65532:65532` in the image
  (`compose_linux.go:1020-1021`, `image/Dockerfile:25`) — is a deliberate
  authority expansion. It must not be adopted on the assumption that a live fd
  makes `Validate` pass; on the evidence here it does not. Note also that C3b's
  socket route inherits exactly this expansion.
- **The Compose mount-layout change is the item most likely to be under-priced,
  and it is shared, not Option B's alone.** It falls on B, C1a, C2, C3a and C3b.
  It edits the sole source of host paths, is read by `RoleRoots`, and in the
  isolation-preserving variant moves the daemons' mount sources too. Whether
  that last part is a real migration depends on whether any instance exists to
  migrate — undetermined here, on a phase whose defining fact is that clean-host
  bring-up has never got past `postgres-fs-init`.
- **Nobody creates the host payload roots, and four options depend on stat-ing
  them.** B, C2, C3a and C3b all have Central or the container inspect
  `/var/lib/central-state/v1/instances/<id>/data/{postgres,minio}`, which
  nothing in either tree creates. On the first clean-host run — the case this
  ADR exists to unblock — Central's `stat` is `ENOENT` unless something creates
  it first. Who creates it, with what owner and mode, is unpriced.
- **Every option demotes a claim in an accepted design document.** The "never an
  arbitrary path" / "reopen only the inherited descriptor" language
  (`2026-08-05-central-local-infra-design.md:67`,
  `…-implementation.md:124`, `:133`) survives under **none** of A/B/C1/C2/C3/D:
  B and C2 re-site the property onto the Compose render, C1 removes the
  descriptor's authority role, C3 moves it after the open, A fails to deliver
  it, and D never delivered it in the first place. The amendment is owed
  regardless of the ruling, not only under B or C2.
- **Option C1 reduces stated assurance, and its C1b branch reduces actual
  assurance.** C1a should be adopted, if at all, with "we stopped asserting
  something false" said plainly rather than described as a narrower attestation.
  C1b additionally deletes `Validate` from fs-init — the directory check, the
  mount-identity fail-closed, the boundary checks and the pre-/post-mutation
  revalidation — from the one mode that performs a privileged recursive chown.
- **`validateMountBoundaries`'s full recursive walk has never been executed in
  production.** Under any option that makes `Validate` reach it, it runs on
  every fs-init call over a populated data directory. Its cost is unmeasured.
- **Fixing the request side does not make a green fs-init trustworthy.** The
  receipt carries no target or mount evidence, so Central still cannot
  distinguish a validator that passed from one that never ran.
- **Three defects on this same critical path are untouched by every option:**
  the missing minio-provision rendezvous, the unverified effectiveness of
  fs-init's capabilities under `USER 65532` with `no_new_privileges`, and the
  receipt gap. Any of the three can keep a clean-host bring-up red after this
  ADR is implemented.

## Alternatives considered

### Inherit the descriptor through `docker compose run`

Not viable. `executeCommandWithInput` (`compose_linux.go:143-162`) sets only
`Stdin`/`Stdout`/`Stderr`, and adding `ExtraFiles` there would hand the fd to
the **docker client**, not to the container's process; Docker exposes no
fd-passing flag. Central's existing `ExtraFiles`-at-fd-3 pattern is used
elsewhere, but always for **host** children. A socket rendezvous is the only
in-band route into a container, which is why Option A exists at all.

### Run fs-init as a host child instead of a container

Recorded and refused, rather than left unnamed. Central already has the exact
mechanism: `ExtraFiles` at fd 3, used at
`internal/adapter/backup/pgdump_linux.go:113`,
`pgdump_throughput_linux.go:68`, `pgrestore_linux.go:152` and
`cmd/central/restore_engine_launcher.go:265`, `:496` — always for **host**
children, which is precisely why it works there. Running the fs-init helper as
a host child would be the **only** shape in this document that literally
implements the accepted plan language, "Consumes: `request.TargetDescriptor` and
an inherited fixed file descriptor" and "Reopen only the inherited descriptor"
(`…-implementation.md:124`, `:133`): `mount_id` would be coherent because sender
and receiver share a mount namespace, ownership would be coherent because there
is no `userns` shift, and the parent-boundary check would be evaluated against
the real host layout.

It is refused because the helper's entire security posture is the container
boundary. `network: none`, `readonly_rootfs: true`, `no_new_privileges: true`,
`propagation: rprivate`, the four-mode entrypoint census
(`image/Dockerfile:14`, `image/entrypoint-allowlist.json`) and the seccomp
profile are all properties of the shipped image, not of the Go code; moving the
mutation onto the host discards every one of them in exchange for a validation
detail. It is recorded here because a shape that satisfies the accepted design
language exactly should be **visibly refused**, not silently absent — and
because a maintainer who disagrees with that trade should be able to reopen it
by name.

### Relax the mount-boundary or parent-boundary checks

Rejected outright, and no option in this ADR requires it. The parent check
(`linux.go:266-268`) and the descendant walk are the anti-mount-substitution
controls; they are what stop a nested mount being swapped beneath a target
between attestation and mutation. The correct response to `/payload` failing
that check is to change the **mount layout** — a cost shared by B, C1a, C2, C3a
and C3b — never the check. Likewise `mountForDescriptor`'s fail-closed
`"target: mount identity unavailable"` (`:223-225`) must stay fail-closed.

### Put fs-init in the host mount namespace so a passed fd's `mnt_id` resolves

Rejected. It would make the container's mount table the host's, contradicting
the compose policy's `propagation: rprivate` and `host_pid`/`host_ipc`/
`host_network: false` posture, and it is an isolation reduction adopted to work
around a validation detail. Recorded because it is the only way Option A's
mount-identity failure resolves without a redesign, and it should be visibly
refused rather than silently unavailable.

### Fix only the UID/GID half

Not carried forward as a standalone option, though it is the cheapest single
step: Central already derives the host path and could `stat` it — subject to the
open question of whether that path exists on a first run. It closes failure 2
without any transport work — but failure 1 still returns
`descriptor-unavailable` at `linux.go:51` before ownership is ever compared, so
on its own it changes nothing observable. It is recorded here as a **sequencing**
note for whichever option is chosen, not as an alternative to choosing one.

### Extend the attestation to minio-provision in the same change

Not proposed. `dispatchMinioProvision` constructs no validator
(`cmd/central-local-infra/main.go:196`; `:190` is the fixture branch, which
passes a literal `nil`), so minio-provision's
descriptor is never `Fstat`'d and the two failures do not bite it. Scoping this
ADR to fs-init keeps the change surface materially smaller. The consequence to
accept knowingly is that `backupMinioTargetDescriptor`
(`cmd/central/backup_minio_composition.go:289-296`) stays synthetic, and would
become a live instance of this same defect the moment minio-provision gains
attestation.

## Follow-ups

- **Do BEFORE the ruling, not before the build:** re-execute the
  container-boundary probe and record the result in-repo. Three *[probe]*
  results carry three load-bearing conclusions — `mount_id` unsatisfiability
  (which is what kills Option A), the `/payload` parent-boundary rejection
  (which prices B, C1a, C2, C3a and C3b), and ownership crossing (which
  Sub-decision 2 turns on) — and they were measured once, on one host, Docker
  29.1.3, no `userns-remap`, no rootless, no podman, and were **not**
  re-executed for this document. The SCM_RIGHTS half is *[inference]* and was
  never measured at all. This repository's own precedent is that one-shot
  proofs get re-run before they are relied on. It is cheap; the ruling is not.
- **Do before the ruling, and it may make Sub-decision 2 moot:** establish who
  creates `/var/lib/central-state/v1/instances/<id>/data/{postgres,minio}` on a
  clean host, and with what owner and mode. Nothing in either tree does, so the
  answer today is presumably the Docker daemon. Four options depend on it.
- **Do before any build, independent of the ruling:** verify on a real host
  whether `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER` are effective for
  `USER 65532:65532` under `no_new_privileges: true`. If they are not, fs-init
  fails after `Validate` for a reason this ADR does not address, and a second
  delivery would be needed immediately.
- **Blocked on this ruling:** implement the selected option across both repos,
  then build a new `central-local-infra` delivery and obtain an independent
  review before the `dependency-lock.json` mode inventories are updated under
  ADR 0020 §1 and ADR 0014 Decision 8.
- **Do with the ruling, since every option needs it:** add a container-boundary
  fs-init scenario that feeds a real request body in and asserts on the target
  outcome. **Extend the existing harness rather than building one.**
  `scripts/check-image-policy.sh` already runs each mode in a container with the
  full policy posture and asserts on the emitted receipt (`:76`, `:116-131`); it
  only ever sends an empty stdin, so it never reaches `target.Validate`.
  `scripts/clean-host-acceptance.sh` has zero occurrences of `fs-init` today, so
  adding the scenario there instead changes the acceptance baseline itself
  (37/37 scenarios this session) — a review consequence to name deliberately,
  not to discover during the next delivery review.
- **Regardless of the ruling:** correct
  `placeholderTargetDescriptor`'s comment (`lifecycle_linux.go:1128-1131`),
  which states that central-local-infra's tests never exercise the live
  `syscall.Fstat` path. They do, in-process; the real gap is container-boundary
  coverage.
- **Regardless of the ruling:** retire the `Filesystem: "ext4"` literal
  (`lifecycle_linux.go:1144`, `backup_minio_composition.go:294`) in favour of an
  observed value, or state in code why a literal is acceptable. It is a
  clean-host portability bug on any non-ext4 host.
- **Separable, and probably smaller than this decision:** lift
  `ensureBackupMinioBrokerRendezvous`
  (`cmd/central/backup_minio_composition.go:298-340`) onto the
  `Topology.ProvisionMinio` path. Without it, B03 bring-up fails one phase
  after fs-init regardless of what this ADR settles. Could be decided and
  landed independently.
- **Still open and separate:** the receipt-evidence requirement
  (`2026-08-05-central-local-infra-design.md:82`; B03 design `:62`).
  `receipt.Receipt` carries no target or mount fields, and `Init` reads only an
  exit code. If neither C3 branch is adopted, this needs its own decision,
  because otherwise Central never learns whether the attestation ran. Note the
  Central-side seam already exists: `RunWithInputOutput`
  (`compose_linux.go:228-232`) is the receipt-bearing variant `Init` does not
  currently call.
- **Under every option, not only B or C2:** amend
  `2026-08-05-central-local-infra-design.md:67` and
  `…-implementation.md:124`, `:133`. The "never an arbitrary path" /
  "inherited fixed file descriptor" / "reopen only the inherited descriptor"
  language is satisfied by **no** option here — B and C2 re-site the property
  onto the Compose render, C1 removes the descriptor's authority role, C3 moves
  the check after the open, A is concluded not to deliver it, and D leaves the
  contradiction standing. Leaving accepted documents asserting an
  inherited-descriptor model the code does not implement is the one outcome
  ruled out under all of them.
- **If ownership stays compared:** route "no `userns-remap`, no idmapped
  mounts" to the existing `local doctor --host-prerequisites` surface
  (B03 design `:121`) rather than leaving it an implicit assumption.
- **Not updated by this ADR:** the index table in `docs/adr/README.md`, which
  currently has no row for 0023, 0024 or 0025.

## References

Central (`6a4e816`):

- `internal/adapter/infralifecycle/lifecycle_linux.go:1086-1095` —
  `requestTargetDescriptor`, including the `uid`/`gid` fields never assigned;
  `:1117-1136` — the doc comment stating this is not a live attestation;
  `:1137-1147` — `placeholderTargetDescriptor` (`FDNumber: 3` at `:1140`,
  `Filesystem: "ext4"` at `:1144`); `:1169-1176` — `fsInitCallSites`;
  `:1179-1195` — `fsInitRequestPayload` (`:1189` fills `Target`); `:1204-1233` —
  `minioProvisionRequestPayload` (`:1214` the second placeholder call);
  `:1235-1258` — `Init` (`:1249` `RunWithInput`, `:1253-1255` the exit-code
  gate); `:1277-1313` — `ProvisionMinio`, which creates no rendezvous.
- `internal/adapter/infralifecycle/compose_linux.go:78` — `RunWithInput`'s
  `stdin []byte` signature, with no fd seam; `:143-162` —
  `executeCommandWithInput`, no `ExtraFiles`; `:237` —
  `docker compose … run --rm -T`; `:718-732` — `durableDataBindMounts`, the
  documented sole source of host paths, mapping both fs-init roots to
  `/payload`; `:781` — `brokerSocketTarget`; `:811-817` —
  `addBrokerSocketMount`, `minio-provision` only; `:1447-1467` —
  `validateBrokerSocketMount`, the single render-time host-socket rule;
  `:1020-1021` — the `{{- if .User}}` guard, which omits the `user:` key
  entirely when the policy value is empty; `:1538` — `PolicyDigest`, carried in
  every request body.
- `internal/adapter/infralifecycle/assets/compose-policy.json` — both fs-init
  services with `user: ""`, `network: "none"`, `volumes: []` and
  `cap_add: ["CAP_DAC_OVERRIDE","CAP_CHOWN","CAP_FOWNER"]`; the shared security
  block with `no_new_privileges: true`, `readonly_rootfs: true`,
  `host_socket: false`, `propagation: "rprivate"`.
- `cmd/central/backup_minio_composition.go:90` — the only
  `ensureBackupMinioBrokerRendezvous` call site; `:289-296` —
  `backupMinioTargetDescriptor`, the second synthetic copy; `:298-340` — the
  rendezvous itself (comment from `:298`, `func` at `:301`).
- `internal/adapter/authority/broker/service.go:1551`,
  `secret_bootstrap_transport_linux.go:143-144`,
  `migration_client_linux.go:73`, `backup_worker_credential_linux.go:76`,
  `restore_capacity_receipt_frame_linux.go:477`,
  `restore_migration_credential_linux.go:156` — Central's existing fd-**send**
  sites; `server.go:526`, `secret_bootstrap_transport_linux.go:34`,
  `minio_runtime_client_linux.go:156` — its fd-**receive** sites. Neither
  direction crosses into a container.
- `internal/dependencyprepare/assets/dependency-lock.json` — the fs-init mode
  inventories, refreshed by ADR 0024's follow-up to the accepted 2026-08-05
  SB-G2 delivery `sha256:2f57e2c4…`; the unreviewed `sha256:67ebaf72…` build
  appears nowhere in it.

`central-local-infra` (`5d5fbdd`):

- `internal/target/linux.go:24-40` — `DescribeFD` (`:32` calls
  `mountForDescriptor` with boundary checking on for a directory); `:42-76` —
  `Validate` (`:46-48` negative fd, `:50-52` `Fstat` →
  `descriptor-unavailable`, `:53-54` directory / `special-file`, `:56` mount
  resolution, `:61-74` the five comparisons, `:69` ownership, `:75` the
  container-observed snapshot); `:78-80` — `Revalidate`; `:82-100` —
  `RevalidateAgainst`, which compares against that snapshot; `:175-177` —
  `mountForFD`, which is `mountForDescriptor(fd, device, true)`; `:179-232` —
  `mountForDescriptor` (`:223-225` fail-closed `"mount identity unavailable"`);
  `:234-249` — `mountIDForFD` reading `/proc/self/fdinfo`; `:251-271` —
  `validateMountBoundaries` (`:266-268` the
  `mismatch("nested-mount","none","parent-boundary")` result); `:279-…` — the
  bounded recursive descendant walk, capped at 100000 entries at `:303`;
  `:368-374` — `openParent`, which opens `..` relative to the held fd.
- `internal/request/request.go:45-54` — `TargetDescriptor` (`root_id` at `:53`,
  a field *of the descriptor*, not a sibling of it); `:70-93` — `MarshalJSON`
  omitting the target for `postgres-provision` (the omitting struct literal at
  `:79-92`), with the "misleading caller-selected path/FD authority surface"
  rationale at `:70-73`; `:105` — `DisallowUnknownFields`; `:128` —
  `Request.Validate`; `:153-155` — `target.root_id` required as a safe identity
  for every mode **except** `postgres-provision`; `:171-174` —
  `postgres-provision forbids target authority` (`:172` forbids the whole
  struct), the precedent Option C1 **cannot copy exactly**; `:176-184` — the
  syntactic target rules governing fs-init, wipe and minio-provision together,
  `:180` requiring nonzero `device`, `inode` and `mount_id`.
- `internal/fsinit/service.go:31` — `req.Validate()`; `:34-36` — the mode check;
  `:37-39` — the root check, which rejects any `Target.RootID` other than
  `postgres`/`minio`; `:40-42` — the deadline check; `:43` —
  `validator.Validate`, the first thing `Run` does *after* those four; `:48` —
  the container-observed snapshot; `:69`, `:136-140` — `fixedOwnership`,
  999:999 for postgres and 1000:1000 for minio.
- `cmd/central-local-infra/main.go:50` — stdin is the only input channel;
  `:97-101` — the `default:` branch, where fs-init builds
  `target.NewLinuxValidator()` at `:98` and no policy census runs; `:126` — the
  `policy.Census` call, wired only into `dispatchWipe`; `:136` — wipe's
  validator; `:196` — minio-provision builds **no** validator (`:190`, the
  throughput-fixture branch, passes a literal `nil`).
- `internal/receipt/receipt.go:59-68` — the receipt's complete field set, with
  no target or mount evidence.
- `policy/seccomp/central-local-infra-v1.json:8` — `dup` and `dup2` allowed,
  `dup3` absent; `:29`, `:34`, `:36` — `sendmsg` allowed, `recvmsg`
  deliberately excluded with the reason stated inline.
- `image/Dockerfile:1`, `:8` — the delivery is `linux/amd64`-pinned; `:14` — the
  closed mode census label; `:25` — `USER 65532:65532`.
  `image/entrypoint-allowlist.json` — the same four-mode census, embedded.
- `Makefile:10` — the `GOARCH=amd64` build; `:15-16` — `make check-image-policy`.
- `scripts/clean-host-acceptance.sh` — zero occurrences of `fs-init`.
  `scripts/check-image-policy.sh:76` — the per-mode loop including `fs-init`;
  `:87-101` — the created-container runtime-policy assertions; `:103-112` — the
  embedded allowlist census (`:106` asserts `.modes | length == 4`);
  `:116-123` — the actual `docker run` per mode with `</dev/null`; `:126-131` —
  the exit-status-1 plus `rejected` / `request rejected` receipt assertion. This
  is the existing container-boundary harness; it never reaches `target.Validate`
  only because the empty stdin is rejected by `request.Decode` first.

Governing documents:

- `docs/internal/superpowers/specs/2026-08-05-central-local-infra-design.md:67-68`
  ("a verified target descriptor, never an arbitrary path"; the five enumerated
  fields), `:82` (the receipt must carry verified target identity and mount
  evidence).
- `docs/internal/superpowers/plans/2026-08-05-central-local-infra-implementation.md:124`
  ("an inherited fixed file descriptor"), `:133` ("Reopen only the inherited
  descriptor").
- `docs/internal/superpowers/specs/2026-07-19-phase-1-b03-compose-lifecycle-design.md:51`
  (one held payload-root binding each; checks before and after mutation),
  `:62` (Central verifies acknowledgements against held descriptor evidence),
  `:121` (the `local doctor --host-prerequisites` surface).
- `docs/operations/central-local-infra-delivery-requirements.md` — the
  syscall-policy digest as a required immutable input, and the two-builder
  byte-identical rule.
- `docs/adr/0014-authorize-postgresql-throughput-fixture-provisioner.md`
  Decision 8 — fresh SB-G2 delivery evidence per candidate.
- `docs/adr/0020-populate-the-version-zero-dependency-receipt-at-provisioning.md`
  §1 — the lock is updated only from accepted external deliveries.
- `docs/adr/0024-settle-the-promoted-minio-identity-and-the-helper-release-digest.md`
  — the adjacent ruling, and the follow-up that refreshed the fs-init mode
  digests this ADR's critical path also depends on.
