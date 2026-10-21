# ADR 0004: Adopt staged single-agent runtime and verified adapter handoffs

- **Number:** 0004
- **Title:** Adopt staged single-agent runtime and verified adapter handoffs
- **Status:** Accepted
- **Created:** 2026-07-14
- **Owners:** Central maintainer
- **Decision due:** 2026-07-20
- **Decision due history:** None
- **Implementation blocked at:** Phase 1 provider, tool, runtime, and resolver implementation plans plus dependent Gate 4–8 specifications that consume runtime semantics; none may cross that boundary until ADR 0004 is Accepted and Gate 3 validation passes
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-14
- **Decision record:** Git status-transition commit; exact hash resolved by this file's Git history
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** ADR 0022 (adopts a Task-level leader/worker decomposition
  direction that amends the single-agent commitment; the per-run single-lane
  guarantee is preserved, and 0022 authorizes no implementation pending a
  design gate); ADR 0035 (the agent boundary is one harness session attempt,
  not a provider turn; the B09 loop coordinator is frozen)
- **Related:** [approved Gate 3 runtime design](../internal/superpowers/specs/2026-07-14-phase-0-runtime-contracts-design.md), [Gate 3 implementation plan](../internal/superpowers/plans/2026-07-14-phase-0-runtime-contracts.md), [ADR 0001](0001-adopt-durable-task-domain-and-lifecycle.md), [ADR 0003](0003-adopt-phase-1-security-policy-and-secret-reference-model.md), [ADR governance](README.md)

## Context

ADR 0001 established the durable Task, Run, Step, StepAttempt, ToolCall, ToolCallAttempt, Approval, Checkpoint, Artifact, and Event domain model. ADR 0003 established the local trust boundary, capability policy, SecretReference contract, and single-use authorization-fence principle. Gate 3 must now define how a single local runtime advances that durable state through one sequential model-and-tool loop without inventing Phase 2 scheduling, exposing secret values, or letting infrastructure adapters own business rules.

Phase 1 executes one durable Agent Task through a sequential model-and-tool loop. It must survive restart, wait durably for Approval or external input, preserve every attempt, reconcile ambiguous effects, enforce finite budgets, and complete only after required Artifacts and final state are durable. The approved Gate 3 design defines the runtime roles, provider and tool semantic contracts, authorization and secret-aware handoffs, Checkpoint rules, local executor ownership, retry and resource budgets, failure taxonomy, and cross-gate ownership boundaries that this ADR proposes to adopt.

## Decision

Central proposes to adopt the following Phase 1 runtime decisions:

- one sequential runtime coordinator advances state only through domain commands;
- AgentDefinition is immutable versioned configuration and not an aggregate;
- Phase 1 has no executable Subagent, child graph, parallel invocation, or Worker scheduler;
- provider physical attempts are immutable StepAttempt evidence under a stable logical provider-operation identity;
- ToolCall operation-key rules remain those of ADR 0001;
- provider and tool calls use prepare, invoke outside transaction, and persist outcome;
- adapters acquire the single-use authorization fence before secret resolution and request handoff;
- Checkpoints are immutable verified safe-continuation evidence;
- one local expiring executor lease supports restart recovery;
- exact defaults/hard maxima and structured exhaustion are owned by the linked design;
- Gate 3 owns semantics, Gate 4 Artifact behavior, Gate 5 serialization, Gate 6 persistence, Gate 7 Go realization, and Gate 8 secret backend/topology.

The approved Gate 3 design owns the detailed runtime semantics, including the sequential execution flow, provider request envelopes and attempt outcomes, tool definition and invocation contracts, idempotency and reconciliation rules, authorization and secret-aware handoff sequencing, Checkpoint contract, local executor ownership, retry and resource budget tables, failure taxonomy, observability contract, and design-validation scenarios.

### Decision boundary

This ADR does not select:

- concrete Go types, interfaces, package paths, or dependency injection;
- JSON, HTTP, or other serialized API payloads;
- SQL tables, migration tooling, or repository mappings;
- provider SDKs or provider-specific wire formats;
- tool transports or external plugin discovery mechanisms;
- the first protected secret backend or exact binding format;
- Docker configuration, local service topology, or deployment manifests;
- executable sandboxing, process controls, or claims that Gate 2 security controls are implemented;
- persisted Workflow graphs, child Task edges, or executable Subagent relationships;
- multi-worker registration, scheduling, fairness, remote leases, or capability advertisement.

Those decisions must preserve these runtime semantics or use a later ADR to change them.

## Consequences

### Benefits

- Phase 1 implementations share one stable runtime coordination model with explicit roles for provider invocation, tool invocation, authorization, checkpointing, and local execution ownership.
- Provider and tool calls persist preparation before invocation outside PostgreSQL transactions, preserving durable evidence for every external effect.
- The single-use authorization fence linearizes revalidation, secret resolution, and external delivery against revocation and policy mutation, preventing confused-deputy and prompt-injection escalation.
- Checkpoints resume known completed work without replaying effects, enabling safe restart recovery from persisted evidence.
- Explicit prepare, invoke, and persist-outcome sequences at every external boundary provide test seams and independent verification of provider, tool, and recovery behavior.
- Finite resource budgets with structured exhaustion prevent unbounded Runs without silently truncating security-relevant content.
- Gate 3 semantic ownership does not preempt Gate 4–8 representation and infrastructure decisions.

### Costs and limitations

- Explicit semantic contracts at each external boundary add coordination, preparation-evidence, and reconciliation complexity compared to a thin loop.
- The single-use authorization fence and secret-aware adapter boundary make provider and tool adapters high-value trusted components requiring focused testing and response filtering.
- Checkpoint compatibility and safe-resume rules require strict producer/reader range tracking and migration discipline.
- Provider attempts are StepAttempt evidence rather than a first-class entity; a later material lifecycle change would require a new ADR.
- The local executor lease can expire during long pauses; recovery grace and the rule that expiry proves only staleness must be respected, not overridden.
- Paid hosted-provider requests fail closed when versioned price data is missing or stale; token and call ceilings still apply.

## Alternatives considered

### Monolithic runtime facade

Rejected because one facade owning the loop, policy, providers, tools, Checkpoints, and persistence conflates authority and execution, leaks infrastructure into business rules, and makes provider, tool, and recovery behavior difficult to test independently.

### Command and Event bus first

Rejected because durable commands delivered to independent provider and tool workers require acknowledgements, delivery ordering, remote Worker semantics, and asynchronous routing that belong to Gate 5 or Phase 2 and are unnecessary for one local Phase 1 runtime.

## Follow-ups

- Gate 4 specification owner defines Artifact staging, retention, orphan cleanup, preview allowlist ownership, and storage-size policy by `2026-07-20`.
- Gate 5 specification owner defines external API/config serialization, Event names/payloads, schema versions, outbox, and local session constants by `2026-07-20`.
- Gate 6 specification owner defines PostgreSQL major, migration tool, rollback policy, audit/tombstone retention, and lease-time query by `2026-07-20`.
- Gate 7 specification owner defines Go UUIDv7 library, interfaces, packages, dependency graph, and configuration types by `2026-07-20`.
- Gate 8 specification owner defines the first protected local secret backend, exact binding format, and local service topology by `2026-07-20`.
- Central maintainer explicitly accepts or rejects this ADR after proposal; Gate 3 design approval is not the ADR decision.
- Gate 3 validation owner records contract-walkthrough evidence after acceptance and before dependent implementation begins.

## References

- [Phase 0 Runtime Contracts Design](../internal/superpowers/specs/2026-07-14-phase-0-runtime-contracts-design.md)
- [Phase 0 Runtime Contracts Implementation Plan](../internal/superpowers/plans/2026-07-14-phase-0-runtime-contracts.md)
- [ADR governance and index](README.md)
- [ADR 0001 — Adopt the durable Task domain and lifecycle](0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0003 — Adopt the Phase 1 security policy and SecretReference model](0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [Durable execution](../architecture/durable-execution.md)
