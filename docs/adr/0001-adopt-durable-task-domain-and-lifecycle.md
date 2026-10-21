# ADR 0001: Adopt the durable Task domain and lifecycle

- **Number:** 0001
- **Title:** Adopt the durable Task domain and lifecycle
- **Status:** Accepted
- **Created:** 2026-07-13
- **Owners:** Central maintainer
- **Decision due:** 2026-07-13
- **Decision due history:** None
- **Implementation blocked at:** Gate 1 completion; this ADR must be Accepted before Gate 2 brainstorming or any code, schema, migration, API, or storage implementation based on its Task-domain decisions begins
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-13
- **Decision record:** Git status-transition commit; exact hash resolved by this file's Git history
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** [approved domain design](../internal/superpowers/specs/2026-07-12-phase-0-domain-lifecycle-design.md), [Gate 1 design](../internal/superpowers/specs/2026-07-12-phase-0-adr-governance-design.md), [domain validation](../internal/superpowers/reviews/2026-07-12-phase-0-domain-lifecycle-validation.md), [domain documentation plan](../internal/superpowers/plans/2026-07-12-phase-0-domain-lifecycle-documentation.md)

## Context

Central needs stable Phase 1 domain meaning before persistence, runtime, Artifact, Event, API, and package specifications can become implementation-ready. The approved domain design defines the Task-owned execution structure and durable lifecycle needed for local-first crash recovery.

The decision must preserve current state, immutable transition evidence, retry identity, ambiguous-side-effect reconciliation, and the completion barrier without introducing Phase 2 Workflow graphs or distributed scheduling.

## Decision

Central adopts the following durable Task-domain decisions:

- Workspace is the Phase 0 and Phase 1 top-level ownership boundary.
- Project is not a Phase 0 or Phase 1 core entity.
- Persisted Workflow graphs and executable subagent relationships begin in Phase 2.
- Task is stable user intent.
- A retry of a failed Task creates a new Run; rerunning a cancelled Task creates a new Task with lineage.
- A Step retry creates a new StepAttempt.
- ToolCall is one logical action and ToolCallAttempt is one physical adapter invocation.
- Approval is durable.
- PostgreSQL normalized rows are authoritative current state.
- Every accepted transition updates current state and appends an immutable Event in one PostgreSQL transaction.
- Phase 1 does not use pure event sourcing.
- External operations execute outside PostgreSQL transactions.
- An ambiguous side effect enters reconciliation and is never repeated blindly.
- Task completion requires verified required Artifacts plus durably persisted completion metadata, final state, and Events.
- Phase 1 persists execution ownership for restart recovery; multi-worker scheduling begins in Phase 2.

Detailed vocabulary, aggregate ownership, state machines, transition guards, identifiers, operation keys, Artifact finalization, and recovery behavior remain normative in the linked approved domain design.

### Decision boundary

ADR 0001 does not define:

- Agent or Subagent semantics;
- Worker or executor capability semantics beyond persisted execution ownership;
- SecretReference;
- concrete PostgreSQL schema;
- full Artifact retention and cleanup;
- Event payload and API compatibility;
- Go package layout;
- local deployment configuration;
- the Phase 1 vertical-slice backlog.

These remain later Phase 0 gates.

## Consequences

### Benefits

- Phase 1 implementations share stable domain identity and lifecycle meaning.
- Retry and restart recovery are deterministic from durable evidence.
- Immutable Events provide audit and recovery evidence without pure event-sourcing complexity.
- Ambiguous external effects cannot be retried blindly.
- Required Artifacts participate in an explicit durable completion barrier.

### Costs and limitations

- Central must persist normalized current state, Events, attempts, Approvals, ownership, and reconciliation evidence.
- State transitions require transaction, version, and idempotency discipline.
- PostgreSQL and object storage require explicit cross-store finalization behavior.
- Workflow graphs, distributed scheduling, and the remaining Phase 0 contracts are deferred.

## Alternatives considered

### Project as an early core entity

Rejected because Workspace directly owns Phase 1 Tasks and another aggregate would add policy and lifecycle questions without enabling the first vertical slice.

### Persisted Workflow graphs in Phase 1

Rejected because one durable Task is sufficient for the first local MVP; executable parent-child graphs begin in Phase 2.

### Pure event sourcing

Rejected because Phase 1 scheduling and UI reads need normalized authoritative current state without requiring replay of every Event.

### Current-state tables without immutable Events

Rejected because transition audit, recovery evidence, and causal history must survive crashes and retries.

### ToolCall identity tied to one StepAttempt

Rejected because a logical operation must retain its key across StepAttempts in one Run while each physical invocation remains separately auditable.

### Blind retry after an ambiguous side effect

Rejected because ownership expiry or timeout does not prove that an external mutation failed.

## Follow-ups

- Gate 2 defines the security threat model, capability classes, approval defaults, and SecretReference.
- Gate 3 defines Agent, Subagent, runtime, tool, checkpoint, and Worker or executor contracts.
- Gates 4–8 define Artifact, Event/API, PostgreSQL, Go-package, and local-development contracts.
- Gate 9 creates the Phase 1 vertical-slice backlog.
- Gate 10 performs the Phase 0 closure audit.

## References

- [Phase 0 domain model and durable lifecycle design](../internal/superpowers/specs/2026-07-12-phase-0-domain-lifecycle-design.md)
- [Architecture overview](../architecture/overview.md)
- [Durable execution](../architecture/durable-execution.md)
- [Domain and lifecycle validation](../internal/superpowers/reviews/2026-07-12-phase-0-domain-lifecycle-validation.md)
- [Domain documentation plan](../internal/superpowers/plans/2026-07-12-phase-0-domain-lifecycle-documentation.md)
