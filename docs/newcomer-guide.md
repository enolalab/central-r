# Newcomer guide

One page to orient yourself in Central: what the system is, how it is
secured, and the vocabulary the rest of the documentation uses. For
installation steps see the
[install guide](operations/user-install-guide.md); for exactly which
slice is being delivered see
[implementation/current-phase.md](implementation/current-phase.md).

## Architecture at a glance

Central is a local-first, durable AI workspace. One `central serve`
process runs on the host and co-locates HTTP, execution, reconciliation,
and recovery; PostgreSQL and MinIO run as digest-pinned containers beside
it. The full contract is
[architecture/overview.md](architecture/overview.md); what follows is the
short version. `central-rust` implements these contracts as a single
Cargo Workspace of capability crates per
[rust-application-boundaries.md](architecture/rust-application-boundaries.md).

### Kernel

The `central-kernel` crate owns process lifecycle, configuration,
dependency wiring, service startup, graceful shutdown, and runtime
health. Everything is composed manually in one workspace — there is no
plugin system or service locator.

### Task and orchestration domain

The task domain owns Task identity, lifecycle, transitions, retries,
cancellation, waiting, and completion rules. The Phase 1 execution chain
is `Workspace → Task → Run → Step → StepAttempt`, with ToolCalls,
Approvals, Checkpoints, Artifacts, and Events attached to it. Every
accepted transition updates current state and appends immutable Events in
one PostgreSQL transaction. Phase 1 has no persisted Workflow aggregate —
Workflow graphs and subagent relationships begin in Phase 2.

### Agent runtime

The runtime resolves an agent definition, trusted dispatch scope, tools,
permissions, context, and execution budget, then dispatches to a trusted
external agent adapter. The adapter owns provider selection, credentials,
provider request/response handling, and provider-side retries; Central
durably reconciles the opaque invocation outcome rather than intervening
in the provider loop. [ADR 0035](adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md)
repositions this boundary for external coding-agent harnesses (Claude
Code, …): Central is the control plane that owns the Task, Run, and
Artifact lifecycle around a harness attempt; the harness session itself
stays opaque, and Central never handles harness credentials. In
`central-rust` the frozen B09 loop coordinator is never ported —
`central-harness` and `central-execution` carry the sequential-coordinator
role (ADR 0043).

### Adapters and infrastructure

- **PostgreSQL** is authoritative for current execution state: Workspaces,
  Tasks, Runs, Steps, StepAttempts, ToolCalls, Approvals, Events,
  Checkpoints, execution ownership, Artifact metadata, and lineage.
  `central-adapter-postgres` implements every capability `port`/`query`
  trait with `sqlx` compile-time checked queries.
- **S3-compatible object storage** (MinIO locally) holds artifact bodies,
  large tool outputs, snapshots, and logs — never the database.
- **`central-local-infra`** is a sibling repository producing one
  digest-pinned OCI image with closed provisioner modes (`fs-init`,
  `minio-provision`, `postgres-provision`, `wipe`) that stand up the
  instance's containers. See [compatibility.md](compatibility.md).
- **Helper and broker** are the two root-owned authority boundaries
  described under [Security model](#security-model) below; their
  syscall-level machinery is isolated inside `central-adapter-linux`
  (`rustix` safe wrappers).

### Which ADR is authoritative

ADR governance uses amendments, so the top-level docs name the *active*
amendment, not the original. The upstream chain, per
[current-phase.md](implementation/current-phase.md): **ADR 0014**
([adr/0014](adr/0014-authorize-postgresql-throughput-fixture-provisioner.md))
is Accepted as ADR 0008's non-superseded upstream amendment — it
supersedes ADR 0011 (which superseded ADR 0010), keeps every ADR 0011
decision, and adds the `postgres-provision` infra mode plus a seventh,
probe-only Compose service for PostgreSQL throughput fixtures. In this
repository, [ADR 0043](adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md)
additionally amends ADR 0008: the capability-owned boundary decisions
stand, but their Go module/package formulation is replaced by the Rust
Cargo Workspace contract. If a document still names ADR 0011 as the
active amendment, it is stale; `docs/README.md` and `current-phase.md`
carry the authoritative chain.

## Security model

The short version of
[security/threat-model.md](security/threat-model.md), which is the
canonical Phase 1 threat register:

- **Physical-console ceremony.** `central local init` and helper-backed
  mutations go through the root helper, which demands fresh PAM
  authentication (`timestamp_timeout=0`) — and, for init, a typed
  confirmation phrase — on the machine's own console: a VT or VM console
  window, not SSH. The helper
  verifies physical-seat TTY ancestry so a forged PTY or remote session
  cannot stand in (threat T19). [ADR 0028](adr/0028-adopt-a-pre-authorized-grant-ceremony-and-context-independent-verdicts.md)
  adds the opt-in alternative: `central grant issue` produces a scoped,
  one-use, TTL-bound grant that admits one operation without the console.
- **Sealed broker-mediated credential handoff.** A root-owned broker
  reachable only over a `0600` Unix socket resolves secrets into sealed
  memfd descriptors delivered via `SCM_RIGHTS` — runtime components get a
  descriptor, never a bearer token to copy. The broker has no network,
  Docker, or arbitrary-path authority.
- **Digest-pinned infrastructure images.** The provisioner image Central
  runs is pinned by exact OCI digest in the dependency lock
  (`central.local-dependency-lock/v1`, maintained by the `central-infra`
  capability). Tags are never the contract; a
  rebuilt image whose digest does not match is refused.
- **Signed advisory bundles.** A `central.security-advisory/v1` bundle
  signed by the release authority `central-release-authority/v2`
  (Ed25519, at most seven days valid) gates production admission:
  missing, hard-expired, or emergency-deny bundles block operations.
  Verify a bundle offline with
  `central-advisory-sign verify --bundle <file>`.
- **Untrusted content has no authority.** Task text, repository contents,
  model output, and Artifact bodies are data; they can propose but never
  authorize an action. Every privileged request is evaluated as
  `resource × effect × scope` and persisted before invocation.

## Glossary

Terms as the codebase and docs use them:

- **Slice** — a named, independently accepted portion of the executable
  surface. Upstream Phase 1 was split into Slices A–E (packets like
  B01–B12) whose commands exited 5 with `UNSUPPORTED_IN_THIS_SLICE` until
  accepted; `central-rust` delivers the same surfaces as the `R0`–`R6`
  vertical slices in
  [rust-vertical-slice-roadmap.md](implementation/rust-vertical-slice-roadmap.md).
- **Gate** — a named review boundary in the delivery process. Phase 0
  had design gates G1–G10; acceptance gates are named per slice
  (SB-G1…SB-G5 for Slice B, SC-G0… for Slice C).
- **Acceptance** — the recorded verdict that a packet or slice works end
  to end against real infrastructure, with archived evidence. An
  acceptance claim without evidence in-tree is withdrawn, not assumed —
  this has happened (SC-G0's first record).
- **Advisory bundle** — the signed `central.security-advisory/v1`
  document the production admission evaluator consults before allowing
  operations; carries dependency verdicts and emergency denies.
- **Grant** — a scoped, single-use authorization issued by
  `central grant issue --kind <init|prepare|lifecycle> --ttl <dur>`;
  bound to the current boot, max TTL 15 minutes, one pending grant at a
  time. Admits one operation where no operator sits at the console.
- **Admission** — the evaluation deciding whether an install or
  lifecycle operation may proceed: the `physical_tty` console ceremony,
  grant mode, or the `--dev-admission` development evaluator (never
  acceptance evidence).
- **Provisioner** — one of the closed, fixed-argument modes inside the
  `central-local-infra` image (`fs-init`, `minio-provision`,
  `postgres-provision`, `wipe`). A provisioner is not a general shell or
  SQL client; each invocation takes exactly one fixed action and exits.
- **Helper** — the root-owned, immutable copy of the Central binary at a
  fixed path with a closed operation matrix (`init`, `prepare`,
  `up`/`down`, `security-update`, …). Every helper-backed command
  requires fresh PAM authentication.
- **Broker** — the root-owned `central-protected-broker` mode behind a
  `0600` Unix socket. It resolves secrets to sealed descriptors, signs
  TLS leafs and export tokens, and journals authority transitions; it
  holds no network or Docker authority.
- **Receipt** — an immutable record in the append-only, HMAC-chained
  operation journal (`central.operation/v1`) that receipt-producing
  commands (`local init`, `prepare`, `up`, `migrate`, `backup`, …) write.
  Also the `central.security-admission/v1` receipt binding the exact
  installed identities a bundle admitted.
- **Dependency lock** — the `central.local-dependency-lock/v1` document,
  the single source of truth
  pinning the exact OCI digests, source-archive hashes, and UID/GID
  assignments of the infra image modes. Editing it goes through the
  `pin-infra` workflow, not by hand.

## Where to go next

- Install: [operations/user-install-guide.md](operations/user-install-guide.md)
  ([Vietnamese](operations/user-install-guide.vi.md))
- What is being delivered: [implementation/current-phase.md](implementation/current-phase.md)
- Errors and limits: [known-limitations.md](known-limitations.md)
- Deep dive: [architecture/overview.md](architecture/overview.md)
