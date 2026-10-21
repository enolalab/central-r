# Specification and Implementation Planning Guide

Use this guide to turn a roadmap phase into implementable work. A phase definition describes outcomes and boundaries; it is not itself an implementation specification.

## Planning hierarchy

```text
Phase
  -> Capability
    -> Vertical slice
      -> Technical specification
        -> Implementation plan
          -> Tasks and pull requests
```

A vertical slice should produce observable user or operator value and cross all required layers: domain, persistence, runtime, API or UI, observability, and tests.

## Required documents for each phase

### 1. Phase brief

The phase brief should contain:

- problem statement
- target users and workflows
- measurable outcomes
- capabilities in scope
- explicit non-goals
- assumptions and dependencies
- risks and open decisions
- phase-level acceptance and exit criteria

### 2. Capability map

For every capability, record:

- capability ID and name
- user outcome
- owning domain
- inputs and outputs
- dependencies
- security classification
- durability requirements
- expected artifacts
- candidate vertical slices

### 3. Technical specification

Every non-trivial vertical slice should have a technical specification with the following sections.

#### Context and objective

- current behavior
- desired behavior
- why the slice is needed now
- links to phase, ADRs, and related specs

#### Scope

- in-scope behavior
- out-of-scope behavior
- compatibility expectations
- assumptions

#### User and system flows

- normal flow
- cancellation flow
- failure and retry flow
- restart and resume flow
- authorization or approval flow

#### Domain model

- entities, value objects, and aggregates
- invariants
- commands and results
- state transitions
- domain errors

#### Persistence

- tables, columns, constraints, and indexes
- transaction boundaries
- locking or concurrency behavior
- migration and rollback
- retention and cleanup

#### APIs and events

- HTTP, CLI, or internal interfaces
- request and response schemas
- event names and payloads
- ordering, acknowledgment, and idempotency
- versioning and compatibility

#### Runtime behavior

- execution ownership
- timeouts and resource limits
- retry policy
- cancellation semantics
- checkpoint boundaries
- startup reconciliation

#### Artifact behavior

- artifact types
- metadata
- object-key rules
- checksum and finalization
- lineage
- upload, download, retention, and deletion

#### Security

- trust boundary
- permissions
- secret access
- filesystem, network, shell, and database exposure
- abuse cases and mitigations

#### Observability

- structured logs
- metrics
- traces where useful
- audit events
- operational diagnostics

#### Test strategy

- unit tests
- integration tests
- migration tests
- failure-injection tests
- end-to-end acceptance scenarios
- performance or load tests where relevant

#### Rollout

- feature flags if required
- backward compatibility
- data migration
- rollback procedure
- documentation updates

#### Open questions

Every unresolved decision must include an owner and the point at which it blocks implementation.

## Implementation plan format

An implementation plan translates an approved technical specification into ordered, reviewable changes.

### Plan metadata

- plan ID
- linked phase and capability
- linked technical specification
- owner
- status
- dependencies

### Ordered steps

Each step should state:

- intended behavior
- files or packages likely affected
- schema or contract changes
- tests added or updated
- validation command
- dependencies on earlier steps
- rollback or recovery consideration

Prefer this order when possible:

1. domain types and invariants
2. persistence migration and repository contract
3. runtime or application service
4. API, CLI, or UI surface
5. observability and operational controls
6. failure-path and recovery tests
7. documentation and examples

### Pull request boundaries

A pull request should:

- implement one coherent slice or enabling change
- preserve buildability and migration correctness
- include its tests
- avoid unrelated refactors
- identify follow-up work explicitly

Avoid separating a schema change from all code and tests that prove its intended use unless the schema is an independently useful prerequisite.

## Definition of Ready

A slice is ready for implementation when:

- user outcome and acceptance scenarios are clear
- scope and non-goals are explicit
- state transitions and failure behavior are defined
- data ownership and transaction boundaries are known
- interfaces and compatibility impact are known
- security and permission implications are reviewed
- required tests can be described before implementation
- blocking decisions are resolved

## Definition of Done

A slice is done when:

- specified behavior is implemented
- migrations and rollback behavior are validated
- tests cover normal, failure, cancellation, and recovery behavior as applicable
- logs, metrics, and audit events are sufficient to diagnose failures
- documentation and ADRs reflect the final design
- acceptance scenarios pass
- known limitations and follow-up work are recorded

## Suggested file structure

```text
docs/
  specs/
    phase-0/
    phase-1/
      P1-C01-application-bootstrap.md
      P1-C02-task-management.md
      P1-C03-single-agent-runtime.md
  plans/
    phase-1/
      P1-C01-implementation-plan.md
  adr/
  architecture/
tasks/
  active/
  completed/
```

## Initial Phase 1 capability decomposition

Recommended capability IDs:

- `P1-C01` application bootstrap and configuration
- `P1-C02` PostgreSQL migration and persistence baseline
- `P1-C03` workspace, task, and run domain
- `P1-C04` single-agent execution loop
- `P1-C05` tool execution and safety boundaries
- `P1-C06` artifact storage and metadata
- `P1-C07` task web UI and progress visibility
- `P1-C08` cancellation, retry, and restart recovery
- `P1-C09` logging, metrics, and diagnostics
- `P1-C10` end-to-end workflow and release packaging

Each capability can have enabling tasks, but completion should be measured through vertical acceptance scenarios rather than package-level code completion.
