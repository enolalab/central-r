# Issue #124 — BP-4: serve must start the real-launcher scheduler path — design spec

Status: draft. Pipeline input for issue #124
("[Phase 2] BP-4: serve must start the real-launcher scheduler path (unblock #110)").
Split from #110. Implements the smallest runtime slice that unblocks
#110 Task 2 Step 2: a broker-capable `central serve` bring-up plus B10
`minio_runtime_v1` generation discovery for phase-2 real runs.

## Scope

Owns:

- a foreground, operator-managed broker bring-up (`central broker serve`)
  running the real `broker.Service` (same construction, same checks,
  same root privilege, same root-owned state) over an operator-chosen
  socket, so `central serve` reaches a real restore barrier through the
  existing `CENTRAL_BROKER_SOCKET` rendezvous;
- a sealed B10 binding-reference descriptor (0400 file) naming the one
  bound `minio_runtime_v1` generation serve must fetch, plus the serve-side
  `CredentialSource` that turns it into the existing frame-0xb1 request
  (no wire change, no weakened check);
- the campaign serve bring-up runbook (broker, mint, descriptor, serve env)
  and the #110 comment (acceptance criterion 5).

Does NOT own: any change to the restore-barrier check, to frame-0xb1/0xb2
wire formats, to peer authorization, to the one-shot consumption rule, or
to any Accepted ADR decision; any new reason code or event kind (every
asserted string must exist verbatim in specs S1–S8); any edit to historical
evidence files; the physical campaign execution itself (maintainer-owned,
per #110).

## Problem

The #110 physical campaign cleared Task 1 but stopped BLOCKED at Task 2
Step 2 on prerequisite BP-4: `central serve` cannot start the
real-launcher scheduler path in this tree. Two stacked gates, both runtime
work outside #110 scope (Slice 2F forbids runtime work in the campaign):

(a) Serve requires a broker with a protected restore journal before
anything else. Observed twice (with and without harness+scheduler env,
valid 0400 descriptor, migrated PG16): exit 6
`serve: [RESTORE_BARRIER_UNAVAILABLE]` (`openServeDeps` runs
`basePreflight.Run` first; `cmd/central/serve_composition.go`).

(b) Even past a broker, harness execution (required for the real scheduler
launcher) requires B10, which can never configure: no production mechanism
discovers which bound `minio_runtime_v1` generation to ask for
(`cmd/central/serve_artifact_composition.go`), so the credential request
stays unresolved and `MinioRuntimeCredential` always reports
"not delivered"; harness-enabled + nil artifacts refuses startup
(`CONFIG_INVALID`, `errHarnessArtifactsUnavailable` in
`cmd/central/harness_composition.go`).

Excluded alternatives (verified in #124): the stub dev gate is never a
real path; rehearsal-style direct stack composition is not `central serve`
(Task 2 Step 2 requires it; P1 injects by killing the serve process
group) and test composition is a forbidden test bypass; `central node` is
a one-shot primitive, not the dispatch loop.

## Brainstorm record (autonomous)

Context explored: issue #124, issue #110 + campaign spec
(`2026-10-08-issue-110-physical-exit-design.md`), serve composition
(`cmd/central/serve_composition.go` `openServeDeps`, `servePreflight.Run`),
artifact composition (`cmd/central/serve_artifact_composition.go`),
harness composition gate (`errHarnessArtifactsUnavailable`), scheduler
harness wiring (`composeSchedulerHarness`, `checkSchedulerLaunchGate`),
broker B10 binding store + 0xb1/0xb2 handlers
(`internal/adapter/authority/broker/`), `MinioRuntimeClient`, the SB-G3
B10 acceptance review (tracked rendezvous gap), SC-DEF-68 (restart churn),
the B10 live-test chain (`provisionMinioRuntimeChain`), the runbooks
(`harness-execution.md`, `phase-2-run-submit.md`), and the sibling
`central-local-infra` minio-provision receipt shape.

Questions asked and answers chosen:

1. *What exactly is undiscoverable for gate (b)?* Exactly one value: the
   broker-generated `OpaqueGeneration` UUID. Verified: `Bucket`
   (`central-artifacts-v1`) and `KeyPrefix` (`MinioRuntimeKeyScope()`) are
   closed constants enforced on both bind and use paths; `InstanceID` is
   known to the operator; `ReceiptID`/`OperationID` are caller-chosen
   (recorded, never matched); `FencingToken` is the token the minting
   orchestrator supplied at bind. The 0xb2 handler discards the bound
   generation id (`if _, err := s.BindMinioRuntimeSecret(...)`), and the
   provisioner receipt carries no generation id — so nobody outside the
   broker learns it today.
2. *Who enforces what after discovery?* The broker, unchanged: binding
   match, fence equality, one-shot O_EXCL consumption, peer UID. The
   reference is a pointer, not a credential; a stale/wrong reference fails
   closed to "not delivered" → existing `CONFIG_INVALID` (harness requires
   B10). No wire change, no check weakened.
3. *Broker-capable or broker-less for gate (a)?* Broker-capable. A fresh
   `broker.Service` self-initializes every store including the recovery
   journal; an empty journal reports the barrier inactive and preflight
   proceeds — gate (a) is purely a bring-up problem. Broker-less (skipping
   the barrier) would weaken an authority check (ADR 0028 D3 criterion 1)
   and violate #110's production-authority-chain requirement, invalidating
   the physical rows. Rejected as the unblock path.
4. *Which broker deployment for the campaign host?* A foreground,
   operator-managed broker verb running the same `broker.Service` as the
   systemd daemon (same root privilege, same root-owned 0700 state, same
   RPCs), rendezvousing with serve through the existing
   `CENTRAL_BROKER_SOCKET` override. Full-instance bring-up (systemd +
   instance ceremony) is heavier, unverifiable in-repo, and still blocked
   on the SB-G3 Compose rendezvous gap; docs-only systemd bring-up is
   fragile. The verb keeps every authority check and is machine-testable.
5. *What else does B10 composition need besides the credential?* The
   object-store endpoint: `brokerMinioRuntimeCredentialSource.endpoint` is
   unset at the serve call site, so `configured()` is false even if a
   fetch succeeded. The binding reference therefore also carries the
   endpoint (+TLS/region), validated at load, never trusted blindly.
6. *What about serve restarts (P1 kills serve)?* Each serve start consumes
   one generation (one-shot by construction; SC-DEF-68's keep-2 sweep
   already assumes restart churn). The runbook mints a fresh binding
   before every serve start. Stale reference → loud `CONFIG_INVALID`,
   never silent wrong-credentialed serving.

Approaches considered:

- **A. Campaign broker + binding-reference discovery (chosen).** New
  `central broker serve` foreground verb (real Service, root-only,
  root-owned state, operator socket) + sealed binding-reference descriptor
  + serve-side source populating the existing 0xb1 request. Weakens
  nothing, changes no wire format, keeps the production authority chain,
  and is machine-verifiable in-repo (unit + socket-level + docker-gated
  live chain). The unblock is real: after this slice, serve starts with
  harness+scheduler on the real launcher wherever the operator runs the
  documented bring-up.
- **B. Broker-less serve behind an explicit operator flag.** Rejected:
  weakens an authority check (needs a Proposed ADR whose acceptance is
  async and cannot complete this pipeline), and #110's campaign requires
  the production chain — physical rows under a skipped barrier would not
  count as production tier.
- **C. Full-instance bring-up only (docs + central-local-infra rendezvous
  fix, no Central change).** Rejected as the primary slice: it needs a
  cross-repo merge outside this pipeline, and the SB-G3 rendezvous gap +
  missing BindWaiter + generation discovery remain open regardless. The
  Compose rendezvous fix stays a follow-up, not the unblock.

## Design

### D1 — `central broker serve` (foreground campaign broker)

- New operator verb `central broker serve --state-root <abs-dir>
  --socket <abs-path>`, root-only (same privilege class as `--broker`;
  refuse non-root with the existing authority-denied shape).
- Constructs the production `broker.NewService(stateRoot,
  authority.CentralRuntimeUID)` — the identical constructor the systemd
  daemon uses (role roots stay daemon-only; the campaign broker carries
  none, and `RoleRoots` fails closed for it as for every plain
  `NewService` caller).
- State root MUST be root-owned `0700` (validate before constructing;
  refuse otherwise — the protected stores inherit this root). Self-
  initializes on first start (signing, journals, binding stores); an
  empty recovery journal reports the barrier inactive.
- Serves the real connection handler (`broker.HandleConn` per accepted
  unix connection) on a self-bound unix socket at `--socket` (both args
  absolute). Rendezvous filesystem policy (mirrors production): the socket
  parent must exist, be root-owned, and not be world-writable (refuse
  otherwise — a world-writable parent admits socket replacement); the
  socket path itself must not be a symlink (refuse); after binding, the
  verb chmods the socket to 0666, exactly like production's
  `central-broker.socket` (`SocketMode=0666`). Authorization stays
  per-RPC behind the socket (SO_PEERCRED gates), never filesystem-based.
  No LISTEN_FDS, no instance ceremony, no new RPC: every check behind
  the socket is the existing one.
- Shutdown: SIGINT/SIGTERM cancels the accept loop and closes the
  listener (idempotent; no durable mutation on stop). Logs one line at
  start (state root, socket, pid — no secret-adjacent material) and
  stays silent per connection.
- Serve rendezvous: `CENTRAL_BROKER_SOCKET=<same socket>` (the existing
  override in `brokerSocketPath()`); restore-barrier inspect and the
  bootstrap activator then run against the real broker.

### D2 — Sealed B10 binding-reference descriptor

- File format (JSON, schema-versioned, 0400, regular file, owned by the
  serve UID — the same ownership discipline as `loadCredentialDescriptor`;
  size-capped at 4096 bytes):

  ```json
  {"schema_version":"central.b10-binding-ref/v1",
   "instance_id":"<instance>",
   "opaque_generation":"<uuid>",
   "receipt_id":"<opaque>",
   "fencing_token":<uint64 nonzero>,
   "bucket":"central-artifacts-v1",
   "endpoint":"<host:port>",
   "use_tls":false,
   "region":"us-east-1"}
  ```

- Load rules (fail closed, `CONFIG_INVALID` naming the variable on any
  violation): strict JSON (unknown fields rejected); `schema_version`
  exact; `instance_id`/`opaque_generation`/`receipt_id` non-empty with
  `opaque_generation` a valid UUID; `fencing_token` nonzero;
  `bucket` exactly `central-artifacts-v1`; `endpoint` a non-empty
  `host:port` (no scheme, no credentials, no path); `region` non-empty.
  `key_prefix` is NOT a field: the source always sends
  `secretbootstrap.MinioRuntimeKeyScope()` (the closed scope; the broker
  enforces it anyway).
- Env: `CENTRAL_MINIO_RUNTIME_BINDING_REF=<abs path>`. Absent/empty =
  today's behavior exactly (unconfigured source, B10 inert, harness-off
  serve unaffected). Present but unreadable/invalid = `CONFIG_INVALID`
  (never silent fallback: an operator who points at a reference wants it
  honored).
- Campaign serve runs as the central-runtime OS user (501:501,
  `authority.CentralRuntimeUID/GID`) — the identity the foreground
  broker authorizes via `isMinioRuntimeOutboundPeer`. The descriptor is
  0400 owned by 501. The 1000:1000 admission branch is the pre-existing
  minio-provision identity, not a supported serve identity.
- Contents are a pointer, not a credential: generation id, receipt id,
  fence token, endpoint. They authenticate nothing by themselves — the
  broker's binding match + fence equality + one-shot + peer UID still
  decide. 0400 + self-UID ownership because the fence token is
  request-authenticating.

### D3 — Serve-side source wiring

- New `CredentialSource` implementation
  (`bindingRefMinioRuntimeCredentialSource`) built from the loaded
  descriptor + a `broker.MinioRuntimeClient{SocketPath:
  brokerSocketPath()}`: populates the FULL 0xb1 request —
  `InstanceID`, `OpaqueGeneration`, `ReceiptID`, `Bucket` (descriptor),
  `KeyPrefix` (`MinioRuntimeKeyScope()`), `FencingToken` (descriptor),
  `Deadline` (now + 60 s, set at fetch time so `Validate()`'s
  future-deadline rule always sees a fresh value) — and returns the
  descriptor's `endpoint` as the object-store endpoint.
- `openServeDeps` builds the artifact source as: binding-ref source when
  `CENTRAL_MINIO_RUNTIME_BINDING_REF` is set (load errors → the
  `CONFIG_INVALID` above), else today's unresolved source (B10 inert).
  `runtimeArtifactObjectStore`, `resolveArtifactComposition`, and every
  downstream seam are untouched: "not delivered" (stale/consumed/wrong
  reference, broker hiccup) still composes B10 unavailable, and
  harness-enabled serve still refuses with the existing message.
- Region/TLS: `artifactObjectStoreConfig` gains `Region` plumbed from the
  descriptor (TLS already exists as `UseTLS`). Defaults stay zero-value
  safe: the descriptor always carries both explicitly.

### D4 — Mint flow (operator bring-up, runbook)

1. Start the campaign broker (D1) as root; export
   `CENTRAL_BROKER_SOCKET` for serve and the mint step.
2. Ensure MinIO (campaign Compose) is up with bucket
   `central-artifacts-v1`.
3. Run the digest-pinned minio-provision image against the broker socket
   (same invocation shape as SB-G3 Task 14: `--user 1000:1000`, request
   JSON on stdin, `CENTRAL_LOCAL_INFRA_MINIO_ADMIN_ENDPOINT` set). The
   operator picks a stable-per-campaign InstanceID and a fresh nonzero
   fence token per mint (both go in the mint request; the broker binds
   exactly what the descriptor claims). It mints + seals + delivers; the
   broker binds and returns accept.
4. As root, read the broker's binding record for the new generation
   (`<state-root>/minio-runtime-bindings/*.json` — select the most
   recently created record; on a fresh campaign broker exactly one
   exists — non-secret fields only: generation, instance, bucket,
   fence) and transcribe them plus the endpoint into the 0400
   descriptor owned by 501. The descriptor `receipt_id` is a fresh
   operator-generated opaque id per descriptor (the broker records it,
   never matches it). The runbook gives the exact root commands. No
   credential material is ever displayed or copied.
5. Start serve with harness+scheduler env (existing runbook) +
   `CENTRAL_MINIO_RUNTIME_BINDING_REF`.
6. Before EVERY serve (re)start, repeat 3–4 (fresh generation per start;
   one-shot consumption). P1's kill → mint → restart sequence is
   explicit in the campaign note.

### D5 — Failure, retry, resume

- Broker down at serve start: today's `RESTORE_BARRIER_UNAVAILABLE`
  (unchanged).
- Stale/consumed/wrong reference: 0xb1 deny → "not delivered" → B10
  unavailable → harness-enabled serve refuses `CONFIG_INVALID`
  (unchanged message); harness-off serve starts as today.
- Broker hiccup mid-fetch: "not delivered" (existing collapse rule —
  never a startup hard failure beyond the harness gate).
- Mint-then-crash-before-serve-start: generation stays bound and
  unconsumed; next mint creates a new one; the orphan is inert (consumed
  never, delivered never). No resume needed: mint is idempotent-safe
  (each mint is a new generation; nothing reuses).
- Kill-confirmation split untouched: no change to attempt states,
  killer wiring, or `attempt_ambiguous` parking.
- Single-serve assumption: one descriptor feeds one serve start;
  concurrent serves sharing a descriptor race the one-shot and the loser
  fails closed (`CONFIG_INVALID` under harness). The campaign runs one
  serve; the runbook states the rule.

### D6 — Tests (machine tier)

- Unit: descriptor loader (every malformed shape → `CONFIG_INVALID`;
  strict JSON; ownership/permission/size rules); source request
  population (fields exact, scope pinned, deadline fresh,
  endpoint/bucket/TLS/region mapped); verb arg validation (non-root
  refuse, non-absolute refuse, non-0700-root-owned state refuse,
  symlink socket refuse).
- Socket-level (no docker): real `broker.Service` on a temp unix socket
  via the verb's serve loop — restore-barrier inspect returns inactive
  on fresh state (gate-a composition proven, no bypass); 0xb1 fetch
  against a directly-bound generation through the new source, asserting
  the precise split observable: the broker creates the consumption
  record (proves binding/fence/peer authorization passed) while the
  source reports not-delivered on the memfd-ownership check (the
  single-process root-ownership limit documented in
  `minio_runtime_client_linux_test.go` still holds — full delivery
  stays docker-gated).
- Live (docker-gated, same gate as `requireLiveB10Provisioning`): full
  `provisionMinioRuntimeChain` shape + descriptor + new source +
  `composeArtifactCapability` success against real MinIO. Proves gate
  (b) end to end.
- Regression: `TestPhase2RecoveryMatrix` 23/23 green, 0 inconclusive,
  vocabulary verbatim (acceptance criterion 4); PG-live `cmd/central`
  suite green; kill-confirmation tests green (criterion 3).
- Pre-existing skip preserved: nothing in this slice revives
  `TestMinioRuntimeClientFetchesDeliveredCredential`'s single-process
  impossibility.

### D7 — Docs and records

- `docs/operations/harness-execution.md` §1 prerequisite 6 updated: the
  production credential path now exists (link D4 runbook); the "cannot
  be enabled until that lands" caveat is lifted for hosts with a
  campaign broker.
- New `docs/operations/campaign-serve-bringup.md`: the exact D4
  transcript (commands, env, per-restart mint rule, P1 kill→mint→
  restart note, troubleshooting for the two `CONFIG_INVALID` shapes).
- `docs/internal/tasks/` record with the ADR 0028 D3 "What a fix
  requires" analysis (no weakened check, no wire change, test-covered,
  recorded) — SC-DEF-23 direction 1 is the model.
- No new ADR: no check weakened, no wire format changed, no Accepted
  decision altered. (A broker-less serve WOULD need one — explicitly
  not taken.)
- No migration. No historical evidence edits. `current-phase.md`
  untouched (the physical-exit update belongs to #110's verdict).

## Acceptance mapping

1. Serve starts with harness+scheduler on the real launcher: D1+D2+D3;
   machine-proven by D6 socket/live tests; physically proven by the
   campaign's Task 2 Step 2 setup (maintainer).
2. Pinned submit yields a live run: unchanged submit path
   (`phase-2-run-submit.md`); live run needs the campaign's launcher
   daemon + harness login (operator-owned, out of scope).
3. Kill-confirmation split preserved: D5 + regression tests.
4. Matrix 23/23 green, vocabulary verbatim: D6 regression gate.
5. #110 comment with unblock + serve start: pipeline step; content is
   the D4 transcript pointer + pinned serve env block.

## Constraints honored

Fail-closed literal reason-code vocabulary (no new codes); retriable
paths idempotent (mint-per-start; fetch collapse unchanged); production
authority chain (same Service, same root, same RPCs — no bypass);
historical evidence untouched; Central never handles harness credentials
(unchanged); no credential material in descriptors, logs, receipts, or
the repo.
