# Architecture Overview

*This document is ported from the upstream `central` repository. Gate reviews, audits, and acceptance evidence it references by name are archived upstream and are not copied here; only documents present in this repository are linked. In `central-rust`, the Go module/package formulations of these same contracts are replaced by the Rust Cargo Workspace contract under [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md).*

## System shape

Central begins as a local-first application and should preserve boundaries that later allow hybrid and hosted execution.

### Kernel

The `central-kernel` crate owns process lifecycle, configuration, dependency wiring, service startup, graceful shutdown, and runtime health.

### Task and orchestration domain

The task domain owns Task identity, lifecycle, transitions, retries, cancellation, waiting, and completion rules. Phase 1 has no persisted Workflow aggregate; Workflow graphs and subagent relationships begin in Phase 2.

### Agent runtime

The runtime resolves an agent definition, trusted dispatch scope, tools, permissions, context, and execution budget. An external agent adapter owns model-provider selection and execution; Central agent implementations depend on stable contracts rather than concrete providers.

Gate 2 authority and SecretReference contracts are adopted by Accepted [ADR 0003](../adr/0003-adopt-phase-1-security-policy-and-secret-reference-model.md) and passed design-contract validation. Gate 3 runtime contracts are adopted by Accepted [ADR 0004](../adr/0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md) and passed design-contract validation: the [Agent runtime contract](../runtime/agent-runtime.md), the [Tool invocation contract](../runtime/tool-invocation.md), and the [Checkpoint recovery contract](../runtime/checkpoints.md).

The [Agent runtime contract](../runtime/agent-runtime.md) defines one sequential coordinator that advances a single Agent Task through an agent-and-tool loop by requesting domain commands only; Phase 1 has no parallel coordinator, Worker scheduler, or Subagent. Agent invocations are immutable StepAttempt evidence under a stable logical invocation identity; a known-safe retry keeps the operation identity and creates a new invocation-attempt identity, while reusing an operation identity with a different context hash is rejected.

The approved B09 Agent Adapter Boundary Design (archived upstream) makes the Central boundary explicit: Central dispatches to a trusted external agent adapter and durably reconciles the opaque invocation outcome. The adapter owns provider selection, credentials, provider request/response handling, and provider-side retries. Central retains its helper, broker, sandbox, database, and generic Central-to-agent process boundaries; it does not require a provider-specific transport.

Upstream, B10 received its report source from the external agent adapter composition. If that source is absent, B10 fails closed before report materialization; Central does not construct a provider report retriever. In `central-rust` the B09 loop coordinator itself is frozen and never ported ([ADR 0035](../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md), [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md)); `central-harness` and `central-execution` carry the sequential-coordinator role.

The [Tool invocation contract](../runtime/tool-invocation.md) defines the authorization-use fence that linearizes revalidation, SecretReference resolution, and external delivery against grant revocation, policy tightening, SecretReference revocation, or Task termination. Registered secret-aware adapters receive a non-transferable callback scope, never a bearer token; tool results are sanitized and bounded before entering runtime context.

The [Checkpoint recovery contract](../runtime/checkpoints.md) defines immutable verified continuation evidence that resumes known completed work without replaying external effects. One local executor holds an expiring ownership lease with normative Phase 1 defaults — 30-second lease, 10-second heartbeat, 5-second recovery grace, one concurrent Run, one active StepAttempt, and one active external invocation. Default values and Phase 1 hard maxima are distinguished; installed policy may choose at or below a hard maximum and exceeding one is rejected.

Runtime contracts were adopted by Accepted ADR 0004 and passed Gate 3 design-contract validation. Phase 0 does not provide runtime enforcement.

### Durable state

PostgreSQL stores Workspaces, Tasks, Runs, Steps, StepAttempts, ToolCalls, ToolCallAttempts, Approvals, Events, Checkpoints, execution ownership, Artifact metadata, and lineage. Accepted transitions update normalized current state and append immutable Events in the same transaction.

### Artifact storage

S3-compatible object storage stores artifact bodies, large tool outputs, snapshots, logs, and generated files. MinIO is the default local development implementation. PostgreSQL stores searchable metadata, ownership, checksum, and lineage.

Gate 4 Artifact contracts are adopted by Accepted [ADR 0005](../adr/0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md) and passed design-contract validation: the canonical [Artifact lifecycle contract](../artifacts/lifecycle.md) and [Artifact content policy](../artifacts/content-policy.md). The [Artifact lifecycle contract](../artifacts/lifecycle.md) defines Artifact identity, ownership, metadata, integrity, staging reservation and generation, full-body SHA-256 and size verification, ready-key promotion without overwrite, atomic finalization, required-Artifact readiness as a Task and Run completion guard, content generation, lineage, two-phase Workspace-scoped deletion with tombstone, staging expiry, orphan reconciliation, and quota admission for Phase 1. The [Artifact content policy](../artifacts/content-policy.md) defines the untrusted-body trust boundary, detected classification, trusted sensitivity, Central-mediated delivery authorization, disposition, preview allowlist, and inspection and preview hard bounds. PostgreSQL is authoritative for Artifact lifecycle, ownership, metadata, and lineage; object-store listing is never a lifecycle source of truth.

ADR 0005 is Accepted and Gate 4 design-contract validation passed.

Gate 5 API and Event serialization contracts are defined by Accepted [ADR 0006](../adr/0006-adopt-local-v1-api-and-event-serialization.md): the canonical [API v1 contract](../api/v1.md) and [Event v1 contract](../events/v1.md). ADR 0006 is Accepted, pre-closure validation passed, and the corrective closure audit passed. Gate 5 remains design-only and does not authorize runtime implementation.

Gate 6 PostgreSQL persistence is defined by Accepted [ADR 0007](../adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md): the canonical [PostgreSQL persistence contract](../persistence/postgresql.md) and [Migrations and recovery contract](../persistence/migrations-and-recovery.md). The governing design is Approved, corrective validation and corrective pre-closure audit passed, and Gate 6 is complete. Gate 6 remains design-only and does not authorize runtime implementation.

Gate 7 — application boundaries — is Complete upstream and is realized for `central-rust` by Accepted [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md), which amends ADR 0008 for this repository. The canonical [Rust Application Boundaries contract](rust-application-boundaries.md), [PostgreSQL Adapter Mapping contract](../persistence/postgresql-adapter-mapping.md), and [Rust Engineering Workflow contract](../implementation/rust-engineering-workflow.md) carry the same decisions in Rust terms: four per-capability Clean Architecture roles — controller, service, usecase, and infrastructure as per-capability responsibilities rather than global horizontal layers — capability-owned ports, `sqlx`/`aws-sdk-s3`/`rustix` adapter isolation, and manual composition in a single Cargo Workspace.

## Local development environment — design contract

The local development environment is a completed design specification adopted upstream for documentary alignment by Accepted [ADR 0011](../adr/0011-amend-local-topology-for-dedicated-migration-operator.md), ADR 0008's non-superseded upstream amendment that supersedes ADR 0010. Upstream Phase 1 is complete at its recorded evidence tiers; in `central-rust` the equivalent surfaces are delivered by R-slices R5/R6 per [current-phase.md](../implementation/current-phase.md). Until an owning slice lands, its commands are unimplemented rather than reachable.

### Topology and process placement

One `central serve` process runs directly on the host under the locked `central-runtime` service UID and co-locates HTTP, execution, outbox, reconciliation, cleanup, and recovery in a single all-in-one profile. Docker Compose runs exactly six services — `postgres-fs-init`, `minio-fs-init`, `postgres`, `minio`, `postgres-provision`, and `minio-provision` — on one internal `infra` network under the `central-<instance-id>` project. All six services use exact OCI manifest digests, `pull_policy: never`, `restart: "no"`, and no `build:` directive. Central itself is not a Compose service.

The canonical topology contract is the [Local Development Environment contract](local-development-environment.md).

### Helper, broker, launcher, and browser identities

Three locked host identities own distinct trust boundaries:
- **`central-runtime`** (no-login): runs the `central serve` process. Receives descriptor-only supervisor/sandbox boundaries with no repository, Workspace, or Docker/helper-socket access.
- **`central-agent`** (no-login): sandboxed execution identity launched by the `central-sandbox-launcher`.
- **`central-browser`** (no-login): owns the managed browser profile at `/var/lib/central-browser/v1/<instance-id>/`.

The **helper** is a root-owned immutable copy of the Central release artifact with a closed operation matrix (`init`, `prepare`, `security-update`, `dependency-upgrade-*`, `trust-install`, `browser-open`, `runtime-stage/start/stop`, `up/down`, `status/doctor`, `wipe`, `security-rescue-cleanup`, `bootstrap-show`). Every helper-backed command requires fresh PAM authentication with `timestamp_timeout=0`.

The **broker** is a root-owned `central-protected-broker` mode accessed via a `0600` Unix socket. It resolves secrets to sealed memfds, signs TLS leafs, HMAC-fingerprints, and XDG views, journals authority transitions, hands off dependency secrets to tmpfs descriptors, and signs export integrity tokens. It has no network, Docker, Workspace, or arbitrary-path authority.

The **sandbox-launcher** is a root-owned, socket-activated mode with no Docker, network, secret, or config-mutation authority. Only authenticated `central-runtime` may call it.

The full request and denial matrices are in the [Local Development Environment contract](local-development-environment.md) §4 and the administrator prerequisites runbook at [Local Prerequisites](../operations/local-prerequisites.md).

### Configuration and protected state

The [Configuration and Protected State contract](../security/local-configuration-and-protected-state.md) defines strict JSON-schema-versioned configurations (`central.config/v1`), immutable authority transition records (`central.authority-transition/v1`), signed XDG projections (`central.projected-config/v1`, `central.projected-diagnostic/v1`), and the `central.secret-version/v1` envelope. Three protected-local stores separate per-instance data (`/var/lib/central-instances/<id>/`), instance-independent immutable policy (`/usr/local/lib/central/`), and ephemeral runtime state (`/run/central-infra/<id>/`).

### Local operation journals and backup/restore

Commands that produce authoritative receipts — `local init`, `prepare`, `up`/`down`, `migrate up`, `backup create`/`verify`/`apply`/`resume`, `bootstrap show`, `wipe`, and any helper-backed operation — write a single-shard append-only journal with HMAC-chained records under `central.operation/v1`. The journal is never truncated automatically and is writable only by root.

The [Local Backup and Restore contract](../operations/local-backup-and-restore.md) defines the concrete local backup/restore topology: exclusive target capture, `pg_dump`/`pg_restore` 16.14 tool adapters with sealed fd 3, chunked canonical-key inventory, verified manifest seal, one-use restore tickets with bound fingerprint/epoch/nonce, authority reset on restore, and the rescue-backup lifecycle. It is consumed through ADR 0009 and inherits all durable backup/restore semantics.

### Slice A–E structure

Upstream's Gate 9 decomposition divided the Gate 8 design into five sequential executable slices:

| Slice | Scope | Unsupported behavior |
| --- | --- | --- |
| **A** | Configless doctor, `local init`, `prepare`, `up`/`down`, `serve`, attached browser | Every deferred operator verb (migrate, backup, restore, security, wipe, export, import, maintenance, browser clear as operator command, dependency upgrade) returns `exit 5` |
| **B** | Migrate verify/up/status/resume for all migration classes (metadata, data-backfill, version-zero), exact version-zero `migrate reset`, and `backup create`/`verify` (target-reading only) | Restore, export, import, delete, prune, full-instance wipe, and all browser-operator commands return `exit 5` |
| **C** | Complete `restore verify`/`apply`/`resume`/`status`, restore barrier, authority reset + bootstrap clear | Wipe, export, import, delete, prune, maintenance, security-rescue return `exit 5` |
| **D** | Wipe, `backup export`/`import`/`resume`, `backup delete`/`prune plan`/`apply`, inline maintenance | Hard-expired rescue backup return `exit 5` |
| **E** | Hard-expired rescue backup, `central security-rescue cleanup`, `backup/maintenance prune` of rescue generations | All deferred Gate 8 verbs now implemented; full acceptance scenarios run |

The full slice structure with exact command surfaces, deferred-command tables, and validation-scenario assignments is in the [Local Development Environment contract](local-development-environment.md) §11. Upstream Phase 1 is complete at its recorded evidence tiers (Slice D Accepted under the Docker evidence profile, Slice E Accepted at machine tier); `central-rust` delivers the same surfaces as R-slices rather than packet-gated `exit 5` stubs.

### Web application

The initial UI is server-rendered HTML with minimal JavaScript — `axum` controllers rendering `askama` templates inside `central-transport-http`. It exposes task creation, status, logs, artifacts, approval requests, retry, cancel, and resume controls.

Gate 5 defines the [API v1 contract](../api/v1.md) and [Event v1 contract](../events/v1.md) (Accepted [ADR 0006](../adr/0006-adopt-local-v1-api-and-event-serialization.md)). The API v1 contract specifies the HTTP transport surface, and the Event v1 contract defines the serialized Event envelope and cursor feed for durable execution events.

### Security and authority

The [Phase 1 threat model](../security/threat-model.md), [capability and Approval policy](../security/capability-policy.md), and [SecretReference contract](../security/secret-reference.md) own the detailed Gate 2 security semantics. [ADR 0003](../adr/0003-adopt-phase-1-security-policy-and-secret-reference-model.md) records their adoption status.

Agent-visible content is untrusted and can propose but never authorize an action. Every privileged request is evaluated as `resource × effect × scope`, produces `allow`, `require_approval`, or `deny`, and persists its decision before adapter invocation. Workspace read does not imply hosted-model egress, and system-owned connections do not become agent authority.

SecretReference is an opaque Workspace-scoped identity. Secret values stay outside ordinary PostgreSQL and object-storage persistence, resolve just in time inside an authorized secret-aware adapter, and are never exposed through a generic process or raw-reveal capability.

ADR 0003 is Accepted and Gate 2 design-contract validation passed; these Phase 1 security contracts are adopted.

## Workspace crate boundaries

```text
Cargo.toml                            # workspace root: [workspace.dependencies], [workspace.lints]
rust-toolchain.toml                   # pinned stable toolchain (rustfmt + clippy)
deny.toml                             # cargo-deny license/advisory/source policy
migrations/                           # canonical ordered v0..b37 SQL + checksum manifest
.sqlx/                                # committed offline query-verification metadata
crates/
  central-foundation/                 # identity (UUIDv7 newtypes), failure taxonomy
  capabilities/central-*/             # one crate per capability, each owning
                                      # domain.rs / port.rs / query.rs / app.rs
  adapters/central-adapter-{postgres,s3,harness,linux}/
  transport/central-transport-http/   # axum API v1 + askama SSR + health/metrics
  central-kernel/                     # manual composition, supervised tasks, shutdown
bins/                                 # central (+ helper/broker/sandbox-launcher modes),
                                      # *-launcherd daemons, migrate/backup/restore,
                                      # advisory-sign
```

This is the summary form of the canonical [Rust Application Boundaries contract](rust-application-boundaries.md). Capability crates own domain rules; `app.rs` owns service implementations; `domain.rs`, `port.rs`, and `query.rs` form the inward usecase role. PostgreSQL query adapters implement `query.rs` read contracts, while command-persistence, object-store, tool, secret-resolver, and observation adapters implement capability-owned ports. External agent/harness adapters are composed at the boundary and are not Central-owned provider crates. Transport reaches every query through the service layer and never receives a query interface or concrete adapter. Phase 1 has no orchestration crate: persisted Workflow graphs and executable Subagents begin in Phase 2 (`central-workflow`, `central-eventjournal`, `central-scheduler`, `central-retry`, `central-runview`, `central-runsubmit`).

## Core domain model

The normative vocabulary, identifier rules, ownership, and aggregate boundaries are defined in the [approved Phase 0 domain and lifecycle design](../internal/superpowers/specs/2026-07-12-phase-0-domain-lifecycle-design.md#domain-vocabulary).

The Phase 1 execution chain is:

    Workspace -> Task -> Run -> Step -> StepAttempt

ToolCalls, ToolCallAttempts, Approvals, Checkpoints, Artifacts, and Events attach to that chain.

Project is not a Phase 0 or Phase 1 core entity. Workflow graphs and subagent relationships begin in Phase 2.

## Durable task lifecycle

The normative states, transition commands, actors, guards, and durable effects are defined in the [approved Phase 0 domain and lifecycle design](../internal/superpowers/specs/2026-07-12-phase-0-domain-lifecycle-design.md#task-lifecycle).

Phase 1 creates a valid Task directly in queued; there is no draft or pending Task status.

Task statuses are queued, running, waiting, cancelling, completed, failed, and cancelled. Waiting always has a typed reason. Explicit retry of a failed Task creates a new Run; rerunning a cancelled Task creates a new Task with lineage.

Run, Step, and ToolCall own persisted lifecycle state; StepAttempt and ToolCallAttempt preserve immutable attempt evidence; Approval is a separate durable aggregate, all within the Workspace and Task ownership boundaries defined by the approved design.

## Architectural invariants

- PostgreSQL normalized rows are authoritative current execution state.
- Every accepted transition updates current state and appends immutable Events in one PostgreSQL transaction.
- Artifact bodies are verified with size and SHA-256 before required Artifact metadata can participate in completion.
- A ToolCall operation key is stable across StepAttempts in one Run and changes for a new Run.
- Phase 1 persists expiring execution ownership for restart recovery; multi-worker scheduling begins in Phase 2.
- Ownership expiry never proves external side-effect failure.
- Recovery decisions are deterministic from persisted state, Checkpoints, operation outcomes, and retry policy.
- Untrusted content never grants capability or mutates policy.
- Privileged operations use the canonical capability policy and persist authorization evidence before adapter invocation.
