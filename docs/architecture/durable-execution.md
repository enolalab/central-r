# Durable Execution

*This document is ported from the upstream `central` repository. Gate reviews, audits, and acceptance evidence it references by name are archived upstream and are not copied here; only documents present in this repository are linked. In `central-rust`, the Go module/package formulations of these same contracts are replaced by the Rust Cargo Workspace contract under [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md).*

Durable execution is Central's primary technical capability. A Task, and a future Workflow graph in Phase 2, must recover from process crashes, executor loss, model failures, tool failures, and temporary network or storage outages without repeating completed side effects unnecessarily.

Detailed domain and transition rules are defined in the [approved Phase 0 domain and lifecycle design](../internal/superpowers/specs/2026-07-12-phase-0-domain-lifecycle-design.md).

## Persistence model

PostgreSQL normalized rows are authoritative current execution state. Append-only Events are audit and recovery evidence, not the sole state source.

Persist enough information to reconstruct execution without relying on process memory:

- normalized Task input, configuration, and policy references
- Run, Step, StepAttempt, ToolCall, and ToolCallAttempt state
- state-transition Events and aggregate versions
- retry policy and next eligible execution time
- execution owner, lease expiry, and heartbeat
- model and tool request metadata
- Checkpoint payload or reference
- produced Artifact metadata and checksums
- failure class, message, and recoverability
- Approval and external-input state

Workflow graphs and dependency edges are added in Phase 2; they are not Phase 1 persistence requirements.

## Privileged authorization and secret recovery

The canonical [capability and Approval policy](../security/capability-policy.md) and [SecretReference contract](../security/secret-reference.md) extend the durable ToolCall lifecycle without adding Task, Run, Step, ToolCall, or Approval statuses.

Central persists canonical capability request, policy decision, normalized input hash, operation key, and relevant Approval or effective-grant references before privileged adapter invocation. A prepared ToolCallAttempt still commits before the external call. Immediately before protected use, Central reevaluates expiry, revocation, policy version, Workspace, scope, adapter, destination, purpose, and SecretReference status.

Security waits reuse the approved lifecycle reasons:

- `approval` when exact local authorization or grant renewal is required;
- `external_input` when an operator can repair a missing, revoked, or unavailable SecretReference binding;
- `retry_delay` for a bounded known-safe retry of a transient resolver or infrastructure failure;
- `reconciliation` when an external effect may have occurred and blind retry is forbidden.

Approval remains immutable decision evidence. Effective Task authority is evaluated separately, expires no later than 24 hours after issuance, is unusable while a Task is failed, and may be revalidated for a new Run of the same failed Task only when stable Task intent, scope, and policy remain valid. A new Run never inherits a prior per-action operation approval, and a rerun of a cancelled Task inherits no grant.

Secret values are not recovery state. Durable recovery uses opaque SecretReference identity, safe version/fingerprint, authorization evidence, and sanitized outcome; the secret-aware adapter resolves the current value just in time after reevaluation.

## State transitions

The owning domain service must validate every state change. Normalized current-state updates and immutable transition Events commit in the same PostgreSQL transaction.

Each Event records entity, prior state, next state, aggregate version, related Run or attempt, actor, reason, correlation, causation, schema version, and timestamp.

No executor may mark a Task completed until required Artifact uploads are verified and their metadata, lineage, final state, and completion Events can commit atomically in PostgreSQL.

## Execution ownership and recovery

Executors claim work through persisted expiring ownership. Acquisition records executor identity, acquisition time, lease expiry, and heartbeat. A durable waiting transition releases ownership; requeued work requires a new claim.

Ownership expiry proves only that the owner is stale. It does not prove whether an external side effect succeeded.

At startup, Central scans stale non-terminal Runs and Steps, due retries, staging Artifacts, incomplete or ambiguous ToolCalls, cancellation requests, and requested Approvals.

Recovery evaluates persisted Checkpoints, operation outcomes, retry budgets, and Artifact state before choosing one durable action: resume the same Run, requeue safe work by creating a new StepAttempt, create an eligible new Run, reconcile an external side effect, finalize or clean a staging Artifact, settle cancellation, or fail according to policy.

Every recovery decision updates normalized state and appends a recovery Event in one transaction.

## Retry semantics

Retry policy must distinguish:

- transient infrastructure failures
- provider rate limits or temporary model failures
- deterministic user or validation errors
- permission and approval failures
- cancelled work
- unknown or ambiguous external side effects

Use bounded exponential backoff with jitter for transient failures. Preserve every attempt for audit and diagnosis.

A Step retry creates a new StepAttempt in the same Step and Run. Retrying a failed Task creates a new Run and preserves every prior Run and attempt. Rerunning a cancelled Task creates a new Task with explicit derived-from Task lineage; the cancelled Task never reopens.

An automatic whole-Run retry makes the old Run failed, places Task in waiting with retry_delay, and creates the next Run only when eligibility arrives.

## Idempotency and reconciliation

ToolCall is one logical side-effecting action. ToolCallAttempt is one physical adapter invocation.

Each ToolCall receives a stable operation key scoped to Workspace, Task, Run, Step, and logical action identity. The key excludes StepAttempt and ToolCallAttempt, remains stable across retries in one Run, and changes for a new Run.

Central stores a canonical input hash with the key and rejects reuse with different input. Adapters record or pass the key when supported.

When a ToolCallAttempt outcome is ambiguous, parent execution enters waiting with reconciliation. Central confirms success without reinvocation, confirms no side effect and permits policy-controlled retry, or remains waiting for explicit resolution. It never repeats the operation blindly.

## Checkpoints

A checkpoint represents a stable continuation boundary. It may contain compact serialized state or reference larger data in object storage.

A valid checkpoint records:

- schema and producer version
- task, run, and step identity
- completed logical work
- continuation cursor or next action
- relevant artifact references
- integrity checksum
- creation timestamp

Checkpoints must be backward-compatible within their supported version range or explicitly migrated.

## Event history and outbox

Normalized PostgreSQL rows are authoritative for scheduling, lifecycle, and UI state. Events are append-only audit and recovery evidence. Phase 1 does not reconstruct all current state by replaying Events.

Every accepted transition appends its Event in the same transaction as current-state updates.

When asynchronous publication is required, that transaction creates a separate outbox delivery record referencing the immutable Event. Delivery state never mutates the Event.

The [Event v1 contract](../events/v1.md) defines the serialized Event envelope, schema-versioned identity, and cursor-based feed contract for durable execution events (Accepted [ADR 0006](../adr/0006-adopt-local-v1-api-and-event-serialization.md)).

## Gate 3 runtime contracts

Gate 3 runtime contracts are adopted by Accepted [ADR 0004](../adr/0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md) and passed design-contract validation: the [Agent runtime contract](../runtime/agent-runtime.md), the [Tool invocation contract](../runtime/tool-invocation.md), and the [Checkpoint recovery contract](../runtime/checkpoints.md).

The [Agent runtime contract](../runtime/agent-runtime.md) maps external agent invocations to immutable StepAttempt evidence under a stable logical invocation identity. A known-safe retry keeps the operation identity and creates a new invocation-attempt identity; reusing an operation identity with a different context hash is rejected. Ambiguous delivery enters `reconciliation` waiting and is never automatically reinvoked. One local executor holds an expiring ownership lease with normative Phase 1 defaults: 30-second lease, 10-second heartbeat, 5-second recovery grace, one concurrent Run, one active StepAttempt, and one active external invocation.

The [Tool invocation contract](../runtime/tool-invocation.md) defines the authorization-use fence that linearizes revalidation, SecretReference resolution, and external delivery against grant revocation, policy tightening, SecretReference revocation, or Task termination. The fence handoff deadline is the earliest of the configured fence duration (5 seconds default, 10 seconds maximum), effective-grant expiry, a stricter reference or policy deadline, and the attempt deadline. Registered secret-aware adapters receive a non-transferable callback scope; the runtime never receives plaintext.

The [Checkpoint recovery contract](../runtime/checkpoints.md) verifies checksum, ownership, schema reader range, producer, AgentDefinition revision, policy fingerprint, Artifact readiness, and operation evidence before resume. Backward-compatible Checkpoints or supported migrations preserve the source; incompatible or corrupt Checkpoints fail safely without replay. Retry and budget tables distinguish default values from Phase 1 hard maxima — installed policy may choose a value at or below each hard maximum, and a value above one is rejected.

Runtime contracts were adopted by Accepted ADR 0004 and passed Gate 3 design-contract validation.

## Gate 4 Artifact contracts

Gate 4 Artifact contracts are adopted by Accepted [ADR 0005](../adr/0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md) and passed design-contract validation: the canonical [Artifact lifecycle contract](../artifacts/lifecycle.md) and [Artifact content policy](../artifacts/content-policy.md).

The [Artifact lifecycle contract](../artifacts/lifecycle.md) defines the durable-execution Artifact semantics: a reservation and unique staging generation admitted before any object-store delivery; staging bytes that are never reused or overwritten; finalization requiring full-body SHA-256 and size verification, ready-key promotion without overwriting an existing ready object, a second verification of the promoted body, and one durable finalization command that records ready metadata and any Task or Run completion guard it satisfies; content generation that is never reused, including after deletion; explicit Workspace-scoped two-phase deletion that records intent, prevents delivery, performs the object-store action outside the transaction, and retains a safe tombstone; staging expiry after 24 hours while ready Artifacts do not expire automatically in Phase 1; and orphan reconciliation that finalizes or cleans object-store bodies with no valid durable relationship. Quota admission atomically admits bounded declared and maximum capacity against per-Artifact, per-Run, and per-Workspace quotas, and finalization atomically rechecks usage and rejects quota conflicts without ready state.

The [Artifact content policy](../artifacts/content-policy.md) defines the untrusted-body trust boundary that durable recovery depends on: Artifact bytes are untrusted regardless of producer, delivery is attachment and download by default with an explicit media type and no MIME sniffing, inline preview requires allowlisted detected content plus format-specific sanitization and configured bounds, and Central mediates every body delivery after revalidating session authority, Workspace ownership, ready state, sensitivity, and absence of delete intent. Recovery uses opaque SecretReference identity and sanitized outcome, never plaintext or raw object URLs, and object-store failure never permits claiming an Artifact ready before bytes, checksum, and metadata are durably reconciled.

PostgreSQL is authoritative for Artifact lifecycle, ownership, metadata, and lineage; object-store listing is never a lifecycle source of truth. ADR 0005 is Accepted and Gate 4 design-contract validation passed.

## Gate 5 API and Event serialization

Gate 5 API and Event serialization contracts are defined by Accepted [ADR 0006](../adr/0006-adopt-local-v1-api-and-event-serialization.md): the canonical [API v1 contract](../api/v1.md) and [Event v1 contract](../events/v1.md). ADR 0006 is Accepted, pre-closure validation passed, and the corrective closure audit passed. Gate 5 remains design-only and does not authorize runtime implementation.

## Gate 6 PostgreSQL persistence

Gate 6 PostgreSQL persistence is defined by Accepted [ADR 0007](../adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md): the canonical [PostgreSQL persistence contract](../persistence/postgresql.md) and [Migrations and recovery contract](../persistence/migrations-and-recovery.md). The governing design is Approved, corrective validation and corrective pre-closure audit passed, and Gate 6 is complete. Gate 6 remains design-only and does not authorize runtime implementation.

Gate 7 — application boundaries — is Complete upstream and is realized for `central-rust` by Accepted [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md), which amends ADR 0008 for this repository. The canonical [Rust Application Boundaries contract](rust-application-boundaries.md), [PostgreSQL Adapter Mapping contract](../persistence/postgresql-adapter-mapping.md), and [Rust Engineering Workflow contract](../implementation/rust-engineering-workflow.md) carry the same decisions in Rust terms: four per-capability Clean Architecture roles, capability-owned ports, `sqlx`/`aws-sdk-s3`/`rustix` adapter isolation, and manual composition in a single Cargo Workspace.

## Local development environment — design contract

The local development environment is a completed design specification adopted upstream for documentary alignment by Accepted [ADR 0011](../adr/0011-amend-local-topology-for-dedicated-migration-operator.md), ADR 0008's non-superseded upstream amendment that supersedes ADR 0010. Upstream Phase 1 is complete at its recorded evidence tiers (Slice D Accepted under the Docker evidence profile, Slice E Accepted at machine tier); in `central-rust` the equivalent surfaces are delivered by R-slices R5/R6.

It connects the durable execution contract to an executable local topology. It defines:
- Host process placement for `central serve` under `central-runtime`, co-locating all durable components (execution, outbox, reconciliation, cleanup, recovery) — [Local Development Environment contract](local-development-environment.md) §3.
- Locked host identities (`central-runtime`, `central-agent`, `central-browser`) for the runtime, sandboxed execution, and browser — [Local Development Environment contract](local-development-environment.md) §2.2.
- A root-owned helper with a closed operation matrix and fresh-PAM authentication — [Local Development Environment contract](local-development-environment.md) §4.1.
- A root-owned broker that resolves secrets to sealed memfds, signs TLS leafs, and journals authority transitions — [Local Development Environment contract](local-development-environment.md) §4.2.
- A root-owned sandbox-launcher denial matrix preventing arbitrary-path, arbitrary-UID, and namespace-escape attacks — [Local Development Environment contract](local-development-environment.md) §4.3.
- PostgreSQL 16 locked settings (`shared_buffers` 512 MiB, `work_mem` 4 MiB, `max_connections` 32, `max_parallel_workers` 0, `jit off`) and resource envelope (1.5 CPU, 2 GiB memory, 256 PID limit) — [Local Development Environment contract](local-development-environment.md) §6.
- A 16-session serving-data-pool cap (12 serving + 2 coexisting read-only + 2 offline) enforced by `pg_stat_activity` census — [Local Development Environment contract](local-development-environment.md) §10.1.
- Sustained aggregate-memory profiles (steady serve 6.75 GiB, browser 7.5 GiB) with OOM-safe bounded ceilings and no swap/overcommit dependency — [Local Development Environment contract](local-development-environment.md) §6.5.
- Lifecycle/host/target lock ownership, derived environment states, three health layers, retry budgets, settlement grace (30 s), and total shutdown (45 s) — [Local Development Environment contract](local-development-environment.md) §9.
- Backup/restore topology: exclusive target capture, `pg_dump`/`pg_restore` 16.14 tool adapters, one-use restore tickets, authority reset, rescue backup lifecycle, and wipe with AppArmor profile — [Local Backup and Restore contract](../operations/local-backup-and-restore.md).
- Slice A–E phased implementation: Slice A delivers configless doctor through attached serve; deferred verbs fail closed with `exit 5` / `UNSUPPORTED_IN_THIS_SLICE` — [Local Development Environment contract](local-development-environment.md) §11.

All local-topology operator verbs (backup, restore, migrate, wipe, export, import, security update, browser clear, dependency upgrade) are design contracts here; the R-slices own their executable delivery.

## Required tests

Durable features require failure-path tests covering process restart, execution-ownership expiry, duplicated delivery, object-store failure, database transaction rollback, provider timeout, checkpoint resume, cancellation, and ambiguous tool outcomes.
