# ADR 0008: Adopt capability-owned Go application boundaries

- **Number:** 0008
- **Title:** Adopt capability-owned Go application boundaries
- **Status:** Accepted
- **Created:** 2026-07-15
- **Owners:** Central maintainer
- **Decision due:** 2026-07-20
- **Decision due history:** None
- **Implementation blocked at:** Go bootstrap, persistence-adapter, handler, operator-mode, worker, and Phase 1 vertical-slice implementation plans.
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-15
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** ADR 0009, ADR 0010, ADR 0011, ADR 0014, ADR 0036
- **Related:** [ADR 0001](0001-adopt-durable-task-domain-and-lifecycle.md), [ADR 0002](0002-authorize-accepted-to-superseded-status-transitions.md), [ADR 0003](0003-adopt-phase-1-security-policy-and-secret-reference-model.md), [ADR 0004](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md), [ADR 0005](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md), [ADR 0006](0006-adopt-local-v1-api-and-event-serialization.md), [ADR 0007](0007-adopt-postgresql-persistence-and-recovery-contracts.md), [approved Gate 7 Go application boundaries design](../internal/superpowers/specs/2026-07-15-phase-0-go-application-boundaries-design.md), [ADR governance](README.md)

## Context

ADRs 0001–0007 established durable Task domain and lifecycle, ADR governance, security policy and SecretReference model, staged single-agent runtime and verified adapter handoffs, verified Artifact lifecycle and safe content delivery, local v1 API and Event serialization contracts, and PostgreSQL persistence and recovery contracts. Those decisions define what Central builds, secures, persists, and recovers. They do not define the Go module identity, package ownership, dependency direction, transport/adapter boundaries, component lifecycle, typed failure taxonomy, change-set and conditional-port transaction patterns, read-contract separation, observability baseline, or the assignment of concrete topology and vertical-slice implementation to downstream gates.

The approved Gate 7 design defines those application-boundary decisions. Gate 7 is a design-only specification; this Accepted ADR adopts it.

## Decision

Central adopts the following Phase 1 Go application-boundary decisions from the approved Gate 7 design:

- one Go 1.26.5 module at `github.com/enolalabs/central`;
- capability-owned modular-monolith boundaries and manual composition;
- the four Clean Architecture roles as per-capability responsibilities, not global horizontal packages;
- controller-to-service-to-usecase dependency direction with infrastructure implementing Usecase-owned `port` and declaration-only `app/query` contracts; only parent Service invokes query interfaces after surface-appropriate authorization, and transport never receives a query interface or concrete adapter;
- domain-approved change-set commits plus named atomic conditional ports, with no public Unit of Work;
- Gin isolation, pgx/sqlc adapter isolation, typed safe failures, explicit external-effect prepare/invoke/settle protocols, and supervised component lifecycle;
- the selected dependency and observability baseline;
- Gate 8 ownership of concrete local topology/protected stores and Gate 9 ownership of executable vertical slices.

This ADR explicitly rejects global `controller/service/usecase/infrastructure` package trees, generic repository/service packages, framework-dependent core types, auto-migrate-on-serve, and adapter-owned business rules.

### Decision boundary

This ADR does not select:

- Go source, DDL, or Docker services;
- concrete config names, paths, or environment variables;
- executable tests, benchmarks, or smoke checks.

Gate 8 owns concrete local topology and protected stores. Gate 9 owns executable vertical slices, benchmarks, and integration tests.

## Consequences

### Benefits

- A single Go 1.26.5 module with capability-owned boundaries and manual composition avoids circular dependencies and keeps infrastructure from leaking into domain rules.
- Per-capability Clean Architecture roles prevent global horizontal packages from becoming unbounded catch-all dependency hubs.
- Declaration-only `app/query` read contracts owned by capabilities, with only the parent Service authorized to invoke them, prevent transport or adapters from bypassing Workspace ownership, surface-appropriate authorization, or read-contract boundaries.
- Domain-approved change-set commits and named atomic conditional ports provide two purpose-built transaction patterns without exposing a generic public Unit of Work that would let application code split invariants across commits.
- Gin confined to HTTP transport, pgx/sqlc confined to PostgreSQL adapters, and framework-dependent types never crossing the adapter boundary prevent framework lock-in of core types.
- Explicit prepare/invoke/settle external-effect protocols, supervised component lifecycle, and typed safe failures provide a deterministic execution model with known failure taxonomy rather than ad-hoc retry and error-string matching.
- Clear gate ownership splits design decisions (Gate 7) from topology/configuration (Gate 8) and executable implementation (Gate 9), preventing premature concrete commitments.

### Costs and limitations

- Capability-owned boundaries and manual composition require explicit constructor wiring in the kernel composition root; no framework-driven auto-wiring or service-locator pattern is available.
- `app/query` read contracts add an indirection layer between the Service and query adapters; every new read path requires a reviewed declaration-only interface, request, and projection type.
- Rejecting auto-migrate-on-serve means migration execution is an explicit operator or bootstrap concern; the process cannot silently alter the database schema at startup.
- Rejecting generic repository/service packages means each capability writes operation-oriented ports rather than reusing a CRUD base; this increases initial per-capability port surface but prevents generic abstractions from obscuring domain invariants.
- Confining Gin, pgx, sqlc, and Prometheus to adapters means core packages cannot use those libraries directly; infrastructure-specific testing and observable types must remain behind the adapter boundary.
- Typed safe failures and explicit conflict/outcome types require adapter-level classification and sanitization of every external error before it crosses the boundary.
- Supervised component lifecycle requires ordered startup and shutdown with explicit readiness and drain; a missed dependency order or circular wait fails fast at startup rather than silently degrading.

## Alternatives considered

### Global `controller/service/usecase/infrastructure` package trees

Rejected because a global horizontal package tree encourages cross-cutting imports, obscures capability ownership, and makes dependency direction unenforceable at the package level. Capability-owned boundaries with explicit directed acyclic imports make ownership and allowed dependencies visible to every reviewer and architecture check.

### Generic repository and service packages

Rejected because generic CRUD repositories expose building blocks that let application code accidentally split one invariant across commits, bypassing domain-approved change-set discipline. Operation-oriented command ports owned by each capability encode the exact durable intent and transaction boundaries required by the accepted domain rules.

### Framework-dependent core types

Rejected because allowing Gin handler types, pgx connection types, or sqlc-generated row types in domain or application packages would make core logic inseparable from the HTTP and database frameworks. Adapter isolation ensures core types depend only on standard Go and the reviewed dependency baseline exposed through capability-owned ports.

### Auto-migrate-on-serve

Rejected because automatic schema migration at server startup couples process startup to database privilege, removes operator control over migration timing, and risks concurrent migration runs from multiple processes. Explicit migration as a separate bootstrap or operator concern preserves the accepted forward-only, checksummed migration discipline and least-privilege role separation.

### Adapter-owned business rules

Rejected because placing business rules in infrastructure adapters would make domain invariants inseparable from specific database, object-storage, provider, or tool implementations. Capability-owned domain rules, ports, and read contracts ensure that adapter changes cannot silently alter accepted lifecycle, authorization, or persistence semantics.

## Follow-ups

- The Central maintainer accepted this ADR on 2026-07-15 after the required proposal, validation, and acceptance-readiness evidence; later corrective audits validate documentary realization without reopening the Accepted decision unless a material decision changes.
- Gate 8 specification owner defines concrete local topology and protected stores by the Gate 8 due date.
- Gate 9 specification owner defines the first executable vertical-slice backlog, preserving Gate 7's dependency direction, transaction patterns, adapter isolation, and typed failure contracts.

## References

- [Approved Gate 7 Go Application Boundaries Design](../internal/superpowers/specs/2026-07-15-phase-0-go-application-boundaries-design.md)
- [ADR governance and index](README.md)
- [ADR 0001 — Adopt the durable Task domain and lifecycle](0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0002 — Authorize Accepted-to-Superseded ADR Status transitions](0002-authorize-accepted-to-superseded-status-transitions.md)
- [ADR 0003 — Adopt the Phase 1 security policy and SecretReference model](0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [ADR 0004 — Adopt staged single-agent runtime and verified adapter handoffs](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [ADR 0005 — Adopt verified Artifact lifecycle and safe content delivery](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md)
- [ADR 0006 — Adopt the local v1 API and Event serialization contracts](0006-adopt-local-v1-api-and-event-serialization.md)
- [ADR 0007 — Adopt PostgreSQL persistence and recovery contracts](0007-adopt-postgresql-persistence-and-recovery-contracts.md)
