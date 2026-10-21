# ADR 0006: Adopt the local v1 API and Event serialization contracts

- **Number:** 0006
- **Title:** Adopt the local v1 API and Event serialization contracts
- **Status:** Accepted
- **Created:** 2026-07-14
- **Owners:** Central maintainer
- **Decision due:** 2026-07-20
- **Decision due history:** None
- **Implementation blocked at:** API/Event, UI, persistence, and handler implementation plans
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-14
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** [approved Gate 5 API and Event serialization design](../internal/superpowers/specs/2026-07-14-phase-0-api-event-serialization-design.md), [ADR 0001](0001-adopt-durable-task-domain-and-lifecycle.md), [ADR 0003](0003-adopt-phase-1-security-policy-and-secret-reference-model.md), [ADR 0004](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md), [ADR 0005](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md), [ADR governance](README.md)

## Context

ADR 0001 established Task, Run, Step, and Artifact as durable Workspace-scoped aggregates with authoritative PostgreSQL current-state records and immutable Event appends. ADR 0003 established the session-bootstrap security boundary, SecretReference, CSRF protection, and the prohibition on exposing tokens, secrets, raw filenames, object keys, and unbounded untrusted input in responses, Events, errors, and logs. ADR 0004 established the staged single-agent runtime and verified adapter-handoff semantics whose results must be queryable and downloadable. ADR 0005 established Central-mediated Artifact delivery with attachment-default disposition, no MIME sniffing, a bounded preview allowlist, and revalidation of authority, Workspace ownership, ready state, sensitivity, and delete intent before streaming.

These decisions define durable semantics but do not define how a local UI or automation client discovers, submits, reads, or streams them. The approved Gate 5 design defines the versioned HTTP and Event wire contracts that expose those semantics without changing ownership, lifecycle, authority, or security meaning. Gate 5 is a design-only contract; this ADR proposes to adopt it.

## Decision

Central proposes to adopt the following Phase 1 API and Event serialization decisions from the approved Gate 5 design:

- Phase 1 binds HTTP only to loopback and serves one trusted local OS account through the accepted bootstrap-token exchange, bounded session, CSRF protection, and Host/Origin validation;
- `/api/v1` is the single versioned JSON API namespace; every response has `schema_version: "v1"`, `request_id`, and either `data` or `error`; IDs are opaque strings and timestamps are RFC 3339 UTC strings;
- `POST /api/v1/session/bootstrap` exchanges a high-entropy single-use bootstrap token for an opaque server-side session with a 30-minute idle and 12-hour absolute expiry; sessions use an `HttpOnly; SameSite=Strict; Path=/` cookie and are revocable via `POST /api/v1/session/logout`;
- JSON commands require a session-issued `X-CSRF-Token`; cross-origin requests and unexpected JSON `Content-Type` values are rejected; CORS is disabled;
- every JSON command requires `Idempotency-Key` (opaque 16–128 bytes) and `If-Match` with the expected aggregate version; matching key, normalized input, and scope return the original durable result; a changed input or version returns `409` with safe `idempotency_conflict` or `version_conflict`;
- errors use `code`, safe `message`, optional `field`, and `retryable`; they never include secrets, bootstrap/session/CSRF tokens, raw Artifact bodies, raw filenames, object keys, internal database errors, or unbounded untrusted input; authorization failures are non-enumerating;
- response and request size, header, and nesting bounds are enforced; `429` and retryable `503` include `Retry-After`; Artifact byte streams are not JSON and return JSON errors only before bytes start;
- the v1 surface serializes only existing domain meanings — Workspace-scoped Task, Run, Step, StepAttempt, ToolCall, ToolCallAttempt, Approval, Checkpoint, Artifact, and Event summaries — supporting current-state reads, paginated/cursor lists, Task creation, cancel, retry, resume, Approval resolution, and Artifact download/allowlisted preview;
- Artifact delivery is Central-mediated: immediately before bytes stream, the delivery boundary revalidates session authority, Workspace ownership, `ready`, delete intent, sensitivity, disposition, and preview eligibility; it sets explicit content type and `X-Content-Type-Options: nosniff`, uses attachment by default, and exposes no presigned or raw object URL;
- an Event is immutable audit/recovery evidence with a v1 envelope containing `event_id`, `schema_version`, `type`, `occurred_at`, `workspace_id`, `aggregate_type`, `aggregate_id`, `aggregate_version`, `correlation_id`, `causation_id`, actor summary, and a minimal type-specific safe payload; payloads contain no secret material, token, raw body, raw filename, object key, or unbounded label;
- `GET /api/v1/workspaces/{workspace_id}/events` is a cursor-polling feed with stable ordering within one Workspace by immutable `event_sequence`, not a live subscription; a cursor is opaque, Workspace-bound, and invalid across retention or schema boundaries; clients deduplicate by `event_id`;
- the domain transaction that appends an Event may create an outbox delivery record referencing that immutable Event; outbox delivery state never mutates the Event and remains Gate 6 persistence work;
- `v1` is additive-only: adding optional fields or new Event types is compatible; changing a field meaning, requiredness, identifier, ordering, authorization rule, or Event payload meaning requires a new major version or material ADR; deprecated fields remain readable for the supported major version;
- `GET /api/v1/capabilities` returns supported API major, feed contract revision, and optional feature names; additive fields/types do not invalidate cursors, a major API or feed-order revision does.

The approved Gate 5 design owns the detailed route and representation matrix, common envelope structure, Event payload allowlist, cursor pagination semantics, validation scenarios, and the v1 compatibility/deprecation policy.

### Decision boundary

This ADR does not select:

- PostgreSQL schema, tables, transactions, indexes, outbox delivery queries, or migration tooling;
- Go types, interfaces, package paths, HTTP handler implementation, streaming adapters, or dependency injection;
- a broker, message queue, webhook delivery, SSE, WebSocket, or any asynchronous or live publication transport;
- public, remote, LAN, or Online Mode API surface;
- deployment topology, TLS configuration, process supervision, or infrastructure-as-code.

Those decisions belong to Gates 6–8 and must preserve these API and Event serialization semantics or use a later ADR to change them.

## Consequences

### Benefits

- The local API, common envelope, and cursor Event feed provide a single, versioned, loopback-only contract that every local client — browser UI, automation script, and internal adapter — can target without divergence.
- Bootstrap-token exchange, bounded sessions, CSRF protection, Host/Origin validation, and non-enumerating authorization rejections protect the local API without requiring a public-auth surface.
- Command idempotency keys and aggregate-version checks prevent duplicate side effects and blind overwrite, converging with the accepted domain transaction discipline.
- Event immutability, workspace-local sequence ordering, cursor polling, and `event_id` deduplication give every reader a stable replay boundary that survives crashes and lost responses without requiring a live subscription.
- Outbox delivery records reference immutable Events without mutating them, cleanly separating audit evidence from delivery state for later Gate 6 persistence decisions.
- Central-mediated Artifact delivery revalidates authority, Workspace ownership, ready state, sensitivity, and delete intent at the streaming boundary, enforcing ADR 0005's safety model without exposing object URLs.
- Additive-only v1 compatibility and capability discovery let clients negotiate formats and detect breaking changes before interpreting unknown payloads.
- Schema-level exclusions for SQL, Go, broker, SSE/WebSocket, public API, and topology keep Gate 5 a design-only contract, avoiding premature binding to persistence libraries, handler frameworks, or deployment choices.

### Costs and limitations

- Loopback-only HTTP with no SDK, bearer-token alternative, or public endpoint limits the Phase 1 API to a single local OS account; remote access, automation headless tokens, and multi-user scenarios require a later ADR.
- The 30-minute idle session expiry bounds convenience for long-running local debugging or unattended automation; clients must re-bootstrap, which rotates the single-use token and requires protected local configuration access.
- Cursor polling is not a live feed; clients that need near-real-time updates must poll at their own chosen interval, and every reader pays the latency of the poll cycle plus any intermediate current-state reconciliation after a cursor boundary.
- Immutable Events and outbox delivery records increase per-transaction write volume compared to populating only current-state tables; the trade is accepted durable execution evidence and clean delivery separation.
- Event retention and cursor-expiry behaviour are deferred to Gate 6, leaving Phase 1 Event storage unbounded until those decisions are made.

## Alternatives considered

### SSE or WebSocket live feed in Phase 1

Rejected because a live subscription transport requires connection lifecycle, reconnection, backpressure, and delivery-guarantee semantics that add protocol and infrastructure complexity before the first vertical slice is complete. The cursor polling feed provides the same logical Event sequence without a persistent bidirectional channel.

### Bearer-token or API-key alternative for local automation

Rejected because Phase 1 session management, CSRF, and token rotation are the same security mechanisms for both the browser UI and local automation; a separate bearer-token path would add a parallel auth surface, token storage requirements, and revocation complexity without a Phase 1 use case that the bootstrap-session flow cannot serve.

### Public or LAN-accessible API in Phase 1

Rejected because exposing the local API to a network interface requires threat-model, TLS, authentication, authorization, rate-limiting, and abuse-handling decisions that belong in a later Online Mode or multi-user phase, not in the first local-only vertical slice.

### Versionless or implicit schema

Rejected because an explicit `schema_version`, capabilities endpoint, and defined additive-only compatibility policy let every client detect format changes and negotiate their interpretation before parsing unknown fields or types.

### Raw bucket or presigned Artifact URLs

Rejected because it bypasses Central-mediated authority, Workspace-ownership, ready-state, sensitivity, and delete-intent revalidation at delivery time, and cannot enforce the attachment-default disposition, nosniff header, or preview allowlist uniformly.

## Follow-ups

- Central maintainer explicitly accepts or rejects this ADR after proposal; Gate 5 design approval is not the ADR decision.
- Gate 5 specification owner produces canonical API and Event serialization contracts and validation scenarios after acceptance and before dependent implementation begins.
- Gate 6 specification owner defines PostgreSQL Event table, outbox table, cursor seek index, retention policy, and migration by `2026-07-20`.
- Gate 7 specification owner defines Go handler ports, middleware, streaming interfaces, and package placement by `2026-07-20`.
- Gate 8 specification owner defines local topology, loopback binding, and TLS configuration by `2026-07-20`.

## References

- [Phase 0 API and Event Serialization Design](../internal/superpowers/specs/2026-07-14-phase-0-api-event-serialization-design.md)
- [ADR governance and index](README.md)
- [ADR 0001 — Adopt the durable Task domain and lifecycle](0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0003 — Adopt the Phase 1 security policy and SecretReference model](0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [ADR 0004 — Adopt staged single-agent runtime and verified adapter handoffs](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [ADR 0005 — Adopt verified Artifact lifecycle and safe content delivery](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md)
- [Durable execution](../architecture/durable-execution.md)
