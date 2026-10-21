# ADR 0024: Settle the promoted MinIO image identity and the helper release digest

- **Number:** 0024
- **Title:** Settle the promoted MinIO image identity and the helper release
  digest
- **Status:** Accepted (Decision 1 = Option 1B; Decision 2 = Option 2E)
- **Created:** 2026-08-20
- **Owners:** Central maintainer
- **Decision due:** None set
- **Decision due history:** None
- **Implementation blocked at:**
  - **Decision 1:** any change to the `MinioDaemon` branch of `ImageReference`
    (`internal/adapter/infralifecycle/compose_linux.go:596-597`); any change to
    how `preparedDependencySet`
    (`internal/dependencyprepare/app/service.go:576-605`) sources the `minio`
    mode's inventory; and any edit to the **`minio` entry** of the `modes` array
    in `internal/dependencyprepare/assets/dependency-lock.json`. Edits to the
    other six mode entries — notably the fs-init refresh in Follow-ups — are
    outside this block; they are governed by ADR 0014 and ADR 0020 §1, not by
    this ruling. A clean-host B03 bring-up is blocked on this in fact, not only
    in policy — see Context.
  - **Decision 2:** any code that writes a non-placeholder value into
    `lock.helper_release_digest`; any production caller of
    `Lock.VerifyReleaseDigest`; any assignment of
    `dependencyprepare.PreparedManifest.HelperRelease`
    (`internal/dependencyprepare/domain.go:880`), which the B02 design spec's
    cache-hit rule requires and which nothing sets today; and any change to the
    `central.local-dependency-lock/v1` key set
    (`internal/dependencyprepare/lock.go:328-338`).
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-08-20)
- **Decision date:** 2026-08-20
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** ADR 0012 (`minio-provision` mode); ADR 0014 (fresh SB-G2
  delivery evidence as a precondition); ADR 0020 (version-zero dependency
  receipt, and §1's rule that the lock asset holding these mode inventories is
  "updated only from accepted external deliveries");
  `docs/internal/superpowers/specs/2026-07-19-phase-1-b02-dependency-prepare-design.md`;
  `docs/internal/superpowers/specs/2026-08-05-central-local-infra-design.md`;
  `docs/operations/central-local-infra-delivery-requirements.md`

## Context

Commit `f767aa8` ("feat: complete the B02 dependency-prepare pipeline") landed
the B02 pipeline. Two questions it had to touch were deliberately left
unsettled, in both cases because settling them is an architecture decision and
not an implementation detail. This ADR states both precisely enough for the
maintainer to rule on them in one sitting. **Both were ruled on 2026-08-20 —
Decision 1 = Option 1B, Decision 2 = Option 2E; see Decision below.** The
Context and option texts are preserved as they stood when Proposed, so the
evidence the ruling was made against stays readable next to the ruling.

Everything below is documentary and code evidence gathered by reading the tree
at `f767aa8` and the external `central-local-infra` repository. **No build and
no test was run in preparing this ADR, and it asserts no gate verdict.**

### Decision 1 — What the promoted `minio` mode identity must be

B02 builds the MinIO **server** image from upstream source. The design spec is
explicit: `central local prepare` "produces a verified MinIO OCI image from the
selected source archive and commit using two hermetic, sequential, independent
clean builders"
(`docs/internal/superpowers/specs/2026-07-19-phase-1-b02-dependency-prepare-design.md:11`).
The acquisition surface is a closed two-selector set — `AcquisitionKindFor`
(`internal/dependencyprepare/domain.go:60-69`) maps `minio` to
`AcquiredByBuild`, `postgresql` to `AcquiredAsPublished`, and refuses anything
else. `ServiceModeForSelector` (`domain.go:71-84`) maps `minio` to
`MinioDaemon`, documented as "the B03 Compose mode **whose OCI identity that
selector's acquisition establishes**."

The promoted receipt's mode inventories, however, are copied out of the
embedded lock. `f767aa8` rewrote `preparedDependencySet` to take the build this
operation actually performed and to bind it: the built inventory must be
complete, and must be exactly the layout the two-build comparison proved equal
— which is also the attestation subject
(`internal/dependencyprepare/app/service.go:581-588`). The mode inventories
themselves stay lock-inherited (`service.go:590-597`).

**A correction to the record before the options are stated.** The rationale
comment `f767aa8` added (`service.go:552-562`) argues in the past tense against
a *different* binding — requiring the hermetically built OCI inventory to
**equal** `lock.Modes["minio"]` — as though that binding had been the previous
committed behaviour, and an earlier draft of this ADR repeated that framing.
It was not the previous behaviour. `preparedDependencySet` has had exactly two
committed signatures in this repository's entire history: the one-argument
`preparedDependencySet(lock dependencyprepare.Lock)` introduced in `ba45f5d`,
which copies `lock.Modes` and calls `ValidateB03()` with no built inventory in
scope at all (`git show f767aa8^:internal/dependencyprepare/app/service.go`,
line 333), and the current four-argument form. `git log --all -S` finds
`ErrPreparedIdentityDrift` only in `f767aa8`. The same holds for the test
comment at `service_test.go:49-54`, which says the stub builder "used to return
`lockedInventoryFor(req.Selector)`": `lockedInventoryFor` exists in no commit
before `f767aa8` (`git grep lockedInventoryFor f767aa8^` is empty), and
`f767aa8` is the commit that both introduced it (`service_test.go:71`, where it
remains in use) and wrote the "used to" comment about it. So the stub behaviour
that comment disowns is also `f767aa8`-internal, not a prior committed test.

The equality binding was therefore an approach tried and rejected *within*
`f767aa8`'s own development, not a check any released build ever enforced. This
ADR treats it as a design option on the table, never as history — and nothing
below should be read as saying a real `central local prepare` ever failed this
way.

**The argument against that option is sound on the facts regardless of its
history.** The two identities cannot be equal by construction. The recipe
builds upstream
`github.com/minio/minio@9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a` into a
`scratch` layout (`assets/minio-build-recipe.json`;
`assets/dependency-lock.json:33`, `buildkit.base_ref: "scratch"`), while the
lock's `minio` mode value is shaped as a `central-local-infra` Compose image
digest. Equality is unsatisfiable, so a build that required it would terminate
every real `central local prepare` at `PROMOTION_REJECTED`.

**But the justification is only half right, and the underlying defect is still
open.** The comment at `service.go:559-560` argues that substituting the built
identity "would have handed B03 an image reference that resolves to nothing."
That is true — *and it is equally true of the value that was kept*:

- `ImageReference` (`internal/adapter/infralifecycle/compose_linux.go:589-601`)
  renders `MinioDaemon` in the `central-local-infra@` branch
  (`compose_linux.go:596-597`), alongside the fs-init and provision modes.
- `DockerReceiptInspector.Inspect`
  (`internal/adapter/infralifecycle/lifecycle_linux.go:67-85`) runs
  `docker image inspect --format {{.Id}} <ref>` for **every** mode in the
  promoted set and fails the mode if the reference does not resolve.
- The lock's `minio` mode manifest digest is
  `sha256:5e4a6ac5f4fdb500…` (index `sha256:aa3b98d95e4d2940…`),
  `assets/dependency-lock.json:44`. A recursive grep of the entire
  `central-local-infra` repository for either digest returns **zero hits**.

So B03 fails at the same gate either way. The change converted an
unsatisfiable promotion check into a receipt that carries a known-fictitious
image identity for one mode.

Three further facts bound the option space:

1. **`central-local-infra` is not built by B02.** It is a separately delivered
   external artifact that Central pins by digest —
   `docs/operations/central-local-infra-delivery-requirements.md:3` ("an
   external delivery required before B10 can become Accepted");
   `docs/internal/superpowers/specs/2026-08-05-central-local-infra-design.md:6-15`
   ("its source, image, privilege boundary, release evidence, and acceptance
   remain independent from Central"). B02's acquisition surface has no path to
   build it: the selector set is closed at two, and the only build recipes in
   `internal/dependencyprepare/assets/` are `minio-build-recipe.json` and
   `postgresql-build-recipe.json` (the directory's third file is
   `dependency-lock.json`, which is not a recipe).
2. **The external image has no MinIO-server mode.** Its closed census is
   `["fs-init", "wipe", "minio-provision", "postgres-provision"]`
   (`central-local-infra/image/entrypoint-allowlist.json`, and the identical
   `com.central.local-infra.modes` LABEL at `image/Dockerfile:14`). Its design
   non-goals exclude "MinIO server logic"
   (`2026-08-05-central-local-infra-design.md:32`). `MinioDaemon` is therefore
   in the `central-local-infra@` branch of `ImageReference` in contradiction to
   what that image actually is.
3. **The value is a development placeholder, not a pin of anything accepted.**
   It entered the lock in `41a9338` ("feat: complete B03 compose lifecycle",
   2026-07-20) — the same commit that introduced `ImageReference` — sixteen
   days before the first `central-local-infra` delivery existed. Cross-checking
   every mode against the external repository's own acceptance evidence:

   | lock mode | manifest digest | corresponds to |
   |---|---|---|
   | `postgres`, `postgres-provision` | `c95fd534…` | the fetched upstream postgres image (identical to `fetches.postgresql.manifest_sha256`) |
   | `minio-provision` | `3fc5a004…` | the 2026-08-06 SB-G3 delivery (`evidence/2026-08-06-sb-g3/acceptance-8063ff8/acceptance-manifest.json:9`) |
   | `postgres-throughput-provision` | `642fd13d…` | the 2026-08-16 delivery (`evidence/2026-08-16-sb-g2-postgres-provision/acceptance-3e716a2/acceptance-manifest.json:9`) |
   | `postgres-fs-init` / `minio-fs-init` | `572f5a0c…` / `54e6ae58…` | **nothing.** The accepted 2026-08-05 SB-G2 fs-init delivery is `2f57e2c4…` (`evidence/2026-08-05-sb-g2/acceptance-981e30c/acceptance-manifest.json:9`), which appears nowhere in the lock |
   | `minio` | `5e4a6ac5…` | **nothing**, in either repository |

**Two collateral defects this survey exposed.** They are not decided by this
ADR, but they block the same clean-host bring-up and are recorded here so they
are not lost:

- The two fs-init mode digests are 2026-07-20 placeholders that were never
  refreshed from the accepted 2026-08-05 delivery. ADR 0020 §1 (`:69-70`) binds
  the lock asset — the container of these mode inventories — to being "updated
  only from accepted external deliveries per the existing supply-chain rules";
  that update has not happened. Any B03 bring-up on a clean host will also fail
  image inspection on these two modes.
- `f767aa8` changed `fetches.minio.archive_sha256` from `be6d0bd3…` to
  `45521908…` (`assets/dependency-lock.json:12`, mirrored in the compiled-in
  `expectedMinIO` at `internal/dependencyprepare/lock.go:95-98`), while the
  accepted B02 design spec still names `be6d0bd3696c3a13a35f02d3a0280b64319c67918b4501c5c3d87f96d000085c`
  as the MinIO source archive
  (`2026-07-19-phase-1-b02-dependency-prepare-design.md:23`, "Constraints and
  fixed decisions"). Spec and lock disagree on the accepted source identity.
  These are not symmetric candidates: `lock.go:89-94` records why the value
  changed — the old digest "was carried over from the tag-based era and hashed
  neither the tag archive nor the commit archive, so every real fetch died on
  ErrFetchDigest, which is deliberately non-transient." If that recorded
  rationale holds, the spec is the record that needs amending, not the lock.
  This ADR ran no fetch and verifies neither digest, so the reconciliation
  still has to be done against the archive itself; it records only that the
  lock states a reason and the spec does not.

### Decision 2 — What `helper_release_digest` should be, if anything

`lock.helper_release_digest` currently carries the all-zero placeholder
(`assets/dependency-lock.json:3`; `unsetDigest` at
`internal/dependencyprepare/lock.go:34`). The field's declaration already says
so: "nothing produces a helper release digest yet, and how one is derived is an
open architecture decision" (`lock.go:103-107`).

**The only semantics ever written down are unimplementable, not merely
unimplemented.** The one definition in the tree is the test fixture
`testHelperReleaseDigest` (`internal/dependencyprepare/lock_test.go:19-28`):
`sha256:` + SHA-256 of `os.Args[0]`, i.e. the digest of the running binary. But
the lock is a **build input** to that binary — `//go:embed
assets/dependency-lock.json` (`lock.go:20-21`). Writing value `D` into lock `L`
therefore requires `D = SHA256(binary(L, D))`: a SHA-256 fixed point,
equivalent to a chosen-prefix preimage. This is not awkward build sequencing;
it is computationally infeasible. Any option must be judged first on whether it
escapes that fixed point.

The current posture is inert and fails closed, which is correct as far as it
goes:

- `VerifyReleaseDigest` refuses the placeholder with `ErrLockHelperDigestUnset`
  **before** the equality check (`lock.go:424-432`), so a caller offering the
  same placeholder cannot self-match. Pinned by
  `TestVerifyReleaseDigestRefusesUnsetLockValue` (`lock_test.go:557-580`).
- `VerifyReleaseDigest` has **no non-test, non-preflight callers**. The
  complete tracked-file set is its definition (`lock.go:424`), two lock tests
  (`lock_test.go:552`, `:572`), and two preflight assertions
  (`preflight/harness.go:1532`,
  `preflight/reference_host_preflight_test.go:372`).
- Preflight already records this honestly: the axis
  `helper-release-digest-is-a-decided-value` is permanently skipped with the
  reason "lock.helper_release_digest is the all-zero placeholder; its
  definition is still undecided and no production caller verifies it"
  (`preflight/harness.go:1541`).
- The only read of the field outside preflight is
  `helper.HelperReleaseIdentity(lock.HelperReleaseDigest)`
  (`internal/adapter/dependencyprepare/factory_linux.go:460`), which refuses
  the placeholder and falls back to `helperInstanceID` — a per-process 32-byte
  CSPRNG value (`internal/adapter/authority/helper/prepare_confirmation.go:268-298`).
  Its own comment already names the circularity as the reason. Preflight reads
  it once more, to copy it into the evidence record (`harness.go:1242`), which
  is why Option 2D has to touch that path too.

Two adjacent facts change the shape of this decision:

1. **A second, parallel, equally unfinished release identity already exists.**
   `authority.InstanceBinding.ReleaseDigest` ("SHA-256 of the release
   artifact", `internal/authority/domain.go:29`) is populated nowhere in
   non-test code. `advisory.NewProductionVerifier`
   (`internal/advisory/release_key.go:24-34`) compares SHA-256 of
   `productionTrust.PublicKey` against it — and that public key is 32 **zero**
   bytes (`release_key.go:14-22`), which `lock.go:47-60` itself documents as a
   small-order ed25519 point that proves nothing, and which
   `AttestationTrustPolicy.Validate` (`lock.go:524-527`) rejects by policy.
   `NewProductionVerifier` has no production caller either. Whatever is decided
   here should unify with that, not create a third notion of release identity.
2. **The requirement the field was meant to serve is unimplemented
   independently of the digest question.** The design spec requires a cache hit
   to require "matching lock, configuration, **helper-release**, … identities"
   (spec `:49`, "Normal flow" step 2), and puts "helper release identity" in the
   record kept by the *prepared manifest*, `central.prepared-dependencies/v1`
   (spec `:62`, under "Durable state and recovery") — not in
   `central.dependency-preparation-receipt/v1`, which is described separately
   at `:68`. The field that clause lands on is therefore
   `PreparedManifest.HelperRelease` (`domain.go:880`), which exists and is **never
   assigned in non-test code**. So the cache-hit helper-release comparison does
   not exist at all today, and would not be created by filling in the digest.

**What attack a working version would actually prevent.** The helper is the
root-privileged component. An attacker who can replace the helper binary
already has write access to a root-owned path, and can equally replace the
embedded lock, the `VerifyReleaseDigest` code itself, or any digest the binary
carries — a binary self-checking a digest it also ships is worthless against
that attacker. Only three uses are non-vacuous:

1. **Receipt/cache lineage** (spec's cache-hit rule): a receipt produced under
   helper release X must not be honoured by helper release Y. Needs a value
   distinct per release and recorded in the receipt; does **not** need to be
   unforgeable. A correctness/staleness property, not a security one.
2. **Confirmation binding**: a ceremony token minted under one helper must not
   be consumable by another. `helperInstanceID` already serves this and is
   **strictly stronger** for the job — it changes on every restart and is
   unpredictable to a caller. Substituting a release digest here would be a
   downgrade.
3. **Install/acquisition-time verification**: an operator verifying the
   artifact they received is the release the project published. Real — but it
   requires a signature from a key held **outside** the artifact.

The honest summary is that a working `helper_release_digest`, in the sense the
field's name suggests, buys little that `Lock.CanonicalHash()`/`VerifyDigest`
(`lock.go:438-456`) and `RecipeDigest`/`VerifyRecipeDigest` (`lock.go:462-490`,
enforced from `LoadLock` at `lock.go:348`) do not already provide — unless a
real release-signing key exists, which this repository does not have.

## Decision

**Decision 1 is Option 1B. Decision 2 is Option 2E.** Both were ruled by the
maintainer on 2026-08-20. The option texts below are unchanged from the
Proposed draft, so what was weighed stays visible next to what was chosen; the
italic notes under each heading remain analysis of the evidence, not verdicts.

**Decision 1 — adopted: Option 1B.** `MinioDaemon` stops rendering as
`central-local-infra@…` and the B02-built MinIO server image gets its own local
repository name; `preparedDependencySet` writes the built, comparison-proven,
attestation-subject inventory into the `minio` mode in place of lock
inheritance, for that one mode only. The other six modes stay lock-pinned under
ADR 0020 §1. This authorizes the two changes named under Option 1B and nothing
wider: 1C's premise — that Central should build `central-local-infra` itself —
is **not** adopted, and the delivery model that keeps that image an independent
supplier's artifact is unchanged.

**Decision 2 — adopted: Option 2E.** `helper_release_digest` stays reserved and
fail-closed. `VerifyReleaseDigest` continues to refuse the unset placeholder
rather than admit anything against it, and no code may write a non-placeholder
value into the field. Nothing is implemented for Decision 2; the option is the
present state, deliberately retained. 2D (removing the field) and 2C (a
detached signed release manifest) both stay available and would each need their
own ADR — 2C in particular remains the only option that would buy a security
property, and remains unreachable until a real release-signing key, publish
pipeline, and custody policy exist.

**The remaining sub-decision Option 1B names is the local repository name**,
which becomes part of the Compose rendering contract and of every receipt that
records it. It is settled in Follow-ups rather than left open, because 1B
cannot be implemented without it.

### Decision 1 — the promoted `minio` mode identity

*(**Decided 2026-08-20: Option 1B.** The analysis note below is preserved from
the Proposed draft. Four options; pick one, or reject all and keep 1A. Analysis
note, not a verdict: an equality binding between the built inventory and
`lock.Modes["minio"]` is unsatisfiable as written under 1A, 1B and 1D, for the
construction reason given in Context. Option 1C is the only branch under which
it could become satisfiable, and then only once a recipe exists that can
produce a `central-local-infra` image. The evidence gathered here bears most
directly on 1B; weighing that against 1C's scope is the maintainer's call, not
this document's.)*

#### Option 1A — Status quo: leave the `minio` mode lock-inherited

No further change beyond `f767aa8`. The promotion check stays as it is (built
inventory complete and equal to the comparison-proven layout), and the receipt
keeps inheriting `lock.Modes["minio"]` for the `minio` mode.

Consequences: the receipt continues to name
`central-local-infra@sha256:5e4a6ac5…` for the MinIO daemon, which resolves to
no image in either repository, so `DockerReceiptInspector.Inspect` fails that
mode on any host that does not already have such an image — and none does. The
hermetically built identity remains durable but only as evidence, in the
candidate manifest's comparison and attestation facts
(`domain.go:220-226`, `:884-885`), never as the thing B03 pulls. Zero
implementation cost; B03 clean-host bring-up stays blocked; the comment at
`service.go:552-575` remains materially misleading about why the lock value was
kept.

#### Option 1B — Give the B02-built MinIO server image its own identity

Two changes, in order:

1. Fix `ImageReference` (`compose_linux.go:596-597`) so `MinioDaemon` no longer
   renders as `central-local-infra@…`. The external image has no MinIO-server
   mode, so the current branch is wrong on the facts. Give the B02-built
   server image its own local repository name.
2. Make `preparedDependencySet` write the built — comparison-proven,
   attestation-subject — inventory into the `minio` mode, replacing lock
   inheritance for that one mode only. This is exactly the "future acquisition
   path that produces a Compose-consumable image" the current comment
   (`service.go:571-575`) says it is holding the seam open for.

Consequences: the `minio` mode names something that actually exists on the
host, so B03's per-mode inspection can succeed for it; the receipt then states
what was built rather than what was guessed; the six remaining modes stay
lock-pinned under ADR 0020's rule. Requires a decision on the local repository
name (it becomes part of the Compose rendering contract and of every future
receipt), and touches both `internal/adapter/infralifecycle` and
`internal/dependencyprepare/app` — cross-package, and the mode-name choice is
effectively permanent once receipts record it. Does **not** by itself unblock
the two fs-init placeholder modes, which fail independently.

#### Option 1C — Make `central-local-infra` a B02 build output

The branch in which `f767aa8`'s binding is judged **wrong**: if B02 was always
meant to build the provisioner image, then an equality check between the built
inventory and the lock's `minio` mode becomes meaningful, and could be
introduced once a recipe that can satisfy it exists. It would be an addition,
not a restoration — no such check has ever been committed (see Context).

Consequences: contradicts the delivery model recorded across
`docs/operations/central-local-infra-delivery-requirements.md:3`,
`2026-08-05-central-local-infra-design.md:6-15`, the independent SB-G2/SB-G3
delivery reviews bound to foreign candidate commits, and ADR 0012 / ADR 0014's
requirement for fresh independent delivery evidence before production use. It
would make Central the producer of a root-privileged provisioner image whose
acceptance is presently an independent supplier cycle, collapsing that
separation. It requires a third selector, a build recipe, a recipe-digest
change, and a rebuild of the whole delivery-evidence story. For B03's compose
rendering it is the only option under which the `central-local-infra@` branch
of `ImageReference` is correct for `MinioDaemon` — because the daemon would
then genuinely be a mode of an image Central builds. Stated for completeness;
it is the largest-scope option here and should not be adopted merely because it
would make the existing `ImageReference` branch true.

#### Option 1D — Remove `minio` from the receipt's mode set

Treat the MinIO daemon as a service whose image the receipt does not pin,
leaving only the six externally delivered / upstream-fetched modes.

Consequences: gives up the property that an instance can prove which images it
runs, for exactly the one image Central builds itself. It also contradicts
`ServiceModeForSelector`'s stated purpose. Recorded so the option space is
complete; it trades away the guarantee rather than fixing the identity.

### Decision 2 — `helper_release_digest`

*(Proposed — not yet decided. These options are not mutually exclusive in time:
2E is the present state and continues without action. Analysis note, not a
verdict: on the evidence below, 2C is the only option that would buy a security
property, and it is unreachable until a real release-signing key exists; 2D is
the only one that removes the field rather than redefining it; 2A/2B/2B′ each
close or relocate the circularity without buying anything the lock does not
already cover. Which of these the project adopts, and in what order, is the
maintainer's call.)*

| Option | Escapes the fixed point? | Cost | Attack actually prevented |
|---|---|---|---|
| 2A1 — digest the lock minus this field | Yes | ~0 | none; duplicates `CanonicalHash` |
| 2A2 — digest the recipe set | Yes | 0 (exists) | none; already enforced |
| 2A3 — digest the source tree, this path masked | Yes, if masked | medium, brittle | none; identifies source, not artifact |
| 2B — two-stage build, `-ldflags -X` injection | **No** — relocates it | medium | none; yields an unverifiable claim |
| 2B′ — excise-and-hash a reserved region | Yes | high, fragile | non-adversarial corruption only |
| 2C — detached signed release manifest | **Yes** | high; needs a signing key and publish pipeline that do not exist | **yes** — install-time artifact substitution |
| 2D — drop the field | Yes, by deletion | v1 schema change + doc amendment | none, but removes a false control |
| 2E — reserved, fail closed (status quo) | No; quarantined | 0 | none |

**2A1 / 2A2 / 2A3 — digest some other build-time artifact.** All escape the
fixed point. 2A1 restates what `CanonicalHash`/`VerifyDigest` already compute
under a misleading name; 2A2 is fully redundant with
`RecipeDigest`/`VerifyRecipeDigest`, already enforced from `LoadLock`; 2A3
escapes only if this path is masked out of the tree hash, is brittle, and
identifies the *source* rather than the built artifact (different toolchains or
`GOFLAGS` give different binaries from one tree), so its honest name would be
`helper_source_digest`. Collectively: they close the circularity and buy
nothing the lock does not already cover.

**2B — inject the digest post-link with `-ldflags -X`.** This does **not**
close the circularity; it relocates it. `-X` sets a string at link time, so the
injected value becomes part of the linked output and `SHA256(output)` never
equals it. It works only by redefining the semantics as either "digest of the
stage-1 binary" — a claim no verifier can recompute from the artifact actually
shipped, which is worse than none — or "digest of some non-self input", which
is Option 2A with extra build machinery. It also interacts with the
`-trimpath` reproducibility posture (`Makefile:50`, `:58`, `:69`).

**2B′ — reserve a fixed-size region, hash the binary with that region zeroed,
then write the digest in.** This does close it mathematically, at the cost of
ELF surgery with no Go-native support, breakage under `strip`/`objcopy`/distro
repackaging, and a locate-the-region step that must stay deterministic across
`go:embed` layout changes. It detects non-adversarial corruption only: an
attacker who can rewrite the binary rewrites the region too, unless the region
is signed — at which point it is Option 2C and the region is unnecessary.

**2C — detached signed release manifest shipped alongside the binary.** Fully
escapes the fixed point (produced after link, signed with a key outside the
artifact, never fed back into the build) and is the only option that buys a
real security property: an operator or install ceremony can verify, against a
key trusted out of band, that the helper artifact is the published release.
Costs are large for this repository's current state: a release-signing key and
its custody, which does not exist today (`advisory.productionTrust.PublicKey`
is 32 zero bytes, `release_key.go:14-21`); a release/publish pipeline, which
does not exist (`Makefile` builds are plain `go build -trimpath`, `packaging/`
holds only `systemd`); an install-time verification path; and a
rotation/revocation policy. Honest limit: on the host, root can replace both
the binary and its manifest, so the check is meaningful at acquisition/install
time, not as a runtime self-check.

**2D — drop the field.** Escapes by deletion. Everything it was meant to carry
already exists or belongs elsewhere: lock identity in `CanonicalHash`/
`VerifyDigest`; recipe identity in `RecipeDigest`/`VerifyRecipeDigest`;
per-run helper identity for confirmations in `helperInstanceID`, which is
strictly stronger for that job; and publishable release identity in
`authority.InstanceBinding.ReleaseDigest`, which is the architecturally right
home because it is set at install, from outside the artifact — no circularity
by construction. Costs: a `central.local-dependency-lock/v1` schema change
(removing the key from `allowedLockKeys`, `lock.go:328-338`), which changes the
lock's canonical hash and every recorded lock digest; removal from
`preflight/evidence.go:263` and `preflight/harness.go:1242`; and amendment of
the design spec's cache-hit and receipt clauses to say where helper-release
identity actually lives. Buys no new attack prevention — but removes a field
that reads as a security control and is not one, which matches this
repository's established practice of withdrawing unsupported claims rather than
leaving them standing.

**2E — keep it unset and fail closed permanently, as a reserved field.** The
status quo, and presently correct: `VerifyReleaseDigest` refuses the
placeholder before comparing, preflight asserts that refusal and skips the axis
with a truthful reason. Zero cost, zero schema churn. Costs: the circularity is
quarantined, not closed; an inert field ships in a v1 schema and every future
reader must be told it is inert; the acceptance axis stays permanently skipped;
and — the real risk — the **only written definition of the field remains the
circular one** in `lock_test.go:19-28`, so the next implementer's most likely
move is to "just fill it in" with `SHA256(os.Args[0])`, which cannot work and
would produce a lock that fails on every host.

## Consequences

### Benefits

- **Decision 1 (any option):** the receipt stops carrying, or is knowingly
  ruled to keep carrying, an image identity that resolves nowhere. Today it
  carries one without that having been anyone's decision.
- **Option 1B specifically:** the one image B02 genuinely produces would be
  named by what was built and proven, making true for the first time the
  property `ServiceModeForSelector` already claims in its doc comment, and
  letting B03's per-mode inspection succeed for that mode.
- **Decision 2 (any option):** the impossible definition stops being the only
  guidance in the tree. That is the single most valuable output here,
  independent of which option wins.
- **Option 2D specifically:** removes a field that reads as a security control
  and is not one, and consolidates release identity into
  `authority.InstanceBinding.ReleaseDigest` instead of maintaining three
  half-built notions.
- **Option 2C specifically:** the only option that would buy a genuine
  security property (install-time artifact verification), if and when a
  release-signing key and publish pipeline exist.

### Costs and limitations

- **Decision 1 does not, by itself, unblock a clean-host B03 bring-up.** The
  two fs-init modes carry 2026-07-20 placeholder digests that match no accepted
  delivery, and will fail image inspection regardless of which option is
  chosen. Refreshing them is a lock edit, so it inherits ADR 0014's
  fresh-delivery-evidence precondition and ADR 0020 §1's rule that mode
  inventories come only from accepted external deliveries.
- **Option 1B fixes the naming permanently.** Once receipts record a local
  repository name for the built MinIO server image, changing it later is a
  receipt-compatibility problem, not a rename.
- **Option 1C would collapse a separation the project has been maintaining
  deliberately** — `central-local-infra`'s independent acceptance cycle — and
  should not be adopted merely because it would make the current
  `ImageReference` branch true.
- **Option 2E's cost is silent and deferred:** the acceptance axis stays
  skipped forever and the circular fixture keeps teaching the impossible
  semantics to the next reader.
- **Option 2D is a v1 schema change.** It changes the lock's canonical hash and
  therefore every recorded `dependency_lock_sha256`, including those already
  pinned in acceptance manifests. It should follow, not precede, this ADR's
  ruling.
- **Option 2C adopted prematurely would produce a third all-zero placeholder**
  alongside the two that already exist (`lock.helper_release_digest` and
  `advisory.productionTrust.PublicKey`), which is precisely the failure mode
  this repository has previously had to withdraw claims over.
- **The archive-digest divergence is unresolved either way.**
  `fetches.minio.archive_sha256` (`45521908…`, set 2026-08-20) and the accepted
  B02 design spec (`be6d0bd3…`, `spec:23`) disagree on the MinIO source
  archive. Until one is corrected, the compiled-in `expectedMinIO` constant and
  the accepted specification describe different artifacts. The lock records a
  reason for the change and the spec does not (`lock.go:89-94`), but this ADR
  ran no fetch and so verifies neither value.

## Alternatives considered

### Require the built inventory to equal the lock's `minio` mode, as written

Not carried forward as a standalone option — on the facts, not on preference.
The hermetic build produces an upstream-MinIO `scratch` layout; the lock value
is shaped as a `central-local-infra` Compose digest. No hermetic build can emit
the latter, so the equality is unsatisfiable and would terminate every real
`central local prepare` at `PROMOTION_REJECTED`.

Two qualifications the maintainer should have alongside that. First, this is
not a check being removed or reinstated: no committed state of this repository
ever enforced it, and both `f767aa8`'s rationale comment and
`service_test.go:49-54`'s "used to return `lockedInventoryFor`" describe that
commit's own in-development state rather than any released behaviour (see
Context for the history check). The related claim that "the only test that ever
agreed with the requirement used a stub builder that read its answer out of the
same lock" is `f767aa8`'s own account of a stub it changed inside that same
commit; this ADR reports the claim and its provenance, and does not
independently attest that such a test ever passed. Second, the option is not
foreclosed: under Option 1C an equality check becomes meaningful, against a
recipe that can actually produce that artifact — which does not exist today. It
is set aside here only in its as-written form against the current recipe set.

### Fill in `helper_release_digest` with the written semantics

Rejected as impossible, not merely undesirable. `D = SHA256(binary(L, D))` with
the lock embedded in the binary is a SHA-256 fixed point. Any implementation
attempt would either fail or silently redefine the semantics; a lock shipped
with such a value would fail on every host. This is called out explicitly
because the circular fixture (`lock_test.go:19-28`) is currently the only
written definition in the tree and is the obvious thing for the next
implementer to reach for.

### Weaken or remove `VerifyReleaseDigest`'s fail-closed guard

Rejected outright. The guard at `lock.go:424-432` is what stops the placeholder
being mistaken for a verified value, and the preflight assertions
(`harness.go:1532`, `reference_host_preflight_test.go:372`) are what prove it.
No option in this ADR requires weakening either, and none may.

### Substitute a release digest for `helperInstanceID` in confirmation binding

Rejected on the merits. `helperInstanceID` changes on every restart and is
unpredictable to a caller, so a token cannot survive a helper restart even
within one boot. A release digest is constant across restarts and predictable —
strictly weaker for this specific job. Whatever Decision 2 resolves, the
confirmation binding should keep the per-process identifier.

## Follow-ups

Both decisions were ruled on 2026-08-20, so the items below are authorized
rather than blocked, except where noted.

- **The local repository name, settled here because 1B cannot be implemented
  without it: `central-minio`.** `MinioDaemon` renders as
  `central-minio@<manifest digest>`. It is deliberately a sibling of
  `central-local-infra` in form, so the two read as what they are — one image
  Central builds, one an independent supplier delivers — and deliberately not
  a `central-local-infra` sub-name, since conflating them is the defect this
  decision exists to fix. This name enters the Compose rendering contract and
  every receipt that records it; changing it later invalidates receipts, so it
  should be treated as fixed once the first receipt carries it.
- **Decision 1 — authorized:** implement Option 1B: the `MinioDaemon` branch of
  `ImageReference`, plus the `minio` mode substitution in
  `preparedDependencySet`, using the name above.
- **Decision 1, regardless of ruling:** correct the rationale comment at
  `internal/dependencyprepare/app/service.go:552-575` on two counts: it argues
  that substituting the built identity would resolve to nothing without noting
  that the retained lock value resolves to nothing either, and it describes the
  equality binding in the past tense as though it had been prior committed
  behaviour, which it never was. The same past-tense framing should come out of
  `service_test.go:46-54`.
- **DONE (`ed7948c`, 2026-08-20), independent of Decision 1:** the
  `postgres-fs-init` and `minio-fs-init` mode inventories were refreshed from
  the accepted 2026-08-05 SB-G2 delivery (`central-local-infra@sha256:2f57e2c4…`,
  commit `981e30c`), derived from that delivery's own archived OCI layout
  rather than copied from prose. That delivery was chosen over the newer,
  cumulative `3e716a2` because `3e716a2` was accepted by maintainer decision
  rather than independent review.
- **Independent of Decision 1** (a `fetches` edit, outside both blocks):
  reconcile `fetches.minio.archive_sha256` with the B02 design spec's stated
  accepted archive (`spec:23`). The spec is the accepted record, but only the
  lock states a reason for the change (`lock.go:89-94`), so the reconciliation
  should start by fetching the commit archive and hashing it rather than by
  assuming either side. If the lock is right, the spec needs an amendment; if
  the spec is right, the lock and `expectedMinIO` need correcting.
- **Decision 2, on ruling:** implement the selected option. Under 2E this is
  documentation only; under 2D it is a `central.local-dependency-lock/v1`
  schema change plus spec amendment.
- **Decision 2, regardless of ruling:** retire `SHA256(os.Args[0])` as the
  fixture in `lock_test.go:19-28` in favour of an opaque non-zero constant. The
  fixture does not need to model any real derivation, and leaving it there
  keeps propagating semantics that cannot be implemented.
- **Decision 2, regardless of ruling:** state in the code comment, not only
  here, that helper-release identity for confirmation binding is
  `helperInstanceID` and that this is a deliberate, stronger choice for that
  job.
- **Still open and separate:** the receipt-lineage requirement (design spec's
  cache-hit rule and receipt contents; `PreparedManifest.HelperRelease`,
  `domain.go:880`) is unimplemented — nothing assigns that field. It needs a
  value distinct per release and recorded in the receipt; it does not need to
  be unforgeable, and filling in `helper_release_digest` would not create it.
- **Deferred to a future ADR:** a real release-identity story should decide
  `authority.InstanceBinding.ReleaseDigest` (`internal/authority/domain.go:29`),
  `advisory.productionTrust`'s placeholder key
  (`internal/advisory/release_key.go:14-21`), and Option 2C together, as one
  decision rather than three.

## References

- `internal/dependencyprepare/app/service.go:549-605` — `preparedDependencySet`
  and the 2026-08-20 rationale comment.
- `internal/dependencyprepare/domain.go:60-69`, `:71-84` — closed selector set;
  `ServiceModeForSelector` and its stated contract. `:220-226`, `:880`,
  `:884-885` — comparison/attestation facts and the unassigned
  `PreparedManifest.HelperRelease`.
- `internal/adapter/infralifecycle/compose_linux.go:589-601` —
  `ImageReference`; `:596-597` places `MinioDaemon` in the
  `central-local-infra@` branch.
- `internal/adapter/infralifecycle/lifecycle_linux.go:67-85` —
  `DockerReceiptInspector.Inspect` runs `docker image inspect` per receipt mode.
- `internal/dependencyprepare/assets/dependency-lock.json` — `:3`
  `helper_release_digest` placeholder; `:10-13` MinIO fetch identity; `:33`
  `base_ref: "scratch"`; `:41-47` mode inventories (`:44` the `minio` mode).
- `internal/dependencyprepare/assets/minio-build-recipe.json` — upstream MinIO
  source at commit `9e49d5e7…`.
- `internal/dependencyprepare/lock.go:20-21` (embedded lock), `:34`
  (`unsetDigest`), `:47-60` (all-zero ed25519 keys prove nothing), `:89-94`
  (recorded reason the MinIO archive digest changed), `:95-98`
  (`expectedMinIO`), `:103-107` (field doc), `:328-338` (`allowedLockKeys`),
  `:348` (recipe digest enforced), `:424-432` (`VerifyReleaseDigest` fail-closed),
  `:438-456` (`CanonicalHash`/`VerifyDigest`), `:462-490`
  (`RecipeDigest`/`VerifyRecipeDigest`), `:524-527` (trust-policy validation).
- `internal/dependencyprepare/lock_test.go:19-28` — the circular fixture, the
  only written definition of the field; `:557-580` — placeholder self-match is
  refused.
- `internal/dependencyprepare/preflight/harness.go:1525-1541`,
  `preflight/evidence.go:263`,
  `preflight/reference_host_preflight_test.go:367-375` — the honest skip and
  its assertions.
- `internal/adapter/authority/helper/prepare_confirmation.go:268-298` —
  `helperInstanceID`, `HelperReleaseIdentity`, and the in-code statement of the
  circularity; `internal/adapter/dependencyprepare/factory_linux.go:460` — the
  only read of `lock.HelperReleaseDigest` outside preflight.
- `internal/authority/domain.go:29` — `InstanceBinding.ReleaseDigest`;
  `internal/advisory/release_key.go:14-22` (all-zero production trust key),
  `:24-34` (`NewProductionVerifier`).
- `docs/internal/superpowers/specs/2026-07-19-phase-1-b02-dependency-prepare-design.md`
  — `:11` B02 builds MinIO from source; `:23` the accepted archive digest;
  `:49` the cache-hit helper-release requirement; `:62` helper-release
  identity as a field of the prepared manifest (`:68` is the receipt, which
  does not carry it).
- `docs/internal/superpowers/specs/2026-08-05-central-local-infra-design.md:6-15`, `:32`
  — separate repository, independent acceptance, no MinIO server logic.
- `docs/operations/central-local-infra-delivery-requirements.md:3-4` — external
  delivery, not a Central build step.
- `docs/adr/0012-...`, `docs/adr/0014-...` — `minio-provision` authorization and
  the fresh-delivery-evidence precondition.
- `docs/adr/0020-populate-the-version-zero-dependency-receipt-at-provisioning.md`
  — §1 (`:69-70`): the lock asset holding the mode inventories is updated only
  from accepted external deliveries.
- `central-local-infra/image/entrypoint-allowlist.json`,
  `image/Dockerfile:14` — the closed mode census, which contains no
  MinIO-server mode.
- `central-local-infra/docs/superpowers/reviews/evidence/2026-08-05-sb-g2/acceptance-981e30c/acceptance-manifest.json:9`
  (`2f57e2c4…`),
  `.../2026-08-06-sb-g3/acceptance-8063ff8/acceptance-manifest.json:9`
  (`3fc5a004…`),
  `.../2026-08-16-sb-g2-postgres-provision/acceptance-3e716a2/acceptance-manifest.json:9`
  (`642fd13d…`) — the accepted delivery digests the lock is compared against.
- Commit `41a9338` ("feat: complete B03 compose lifecycle", 2026-07-20) —
  seeded the `minio` and two fs-init mode digests. Commit `f767aa8` — the B02
  pipeline completion this ADR responds to.
