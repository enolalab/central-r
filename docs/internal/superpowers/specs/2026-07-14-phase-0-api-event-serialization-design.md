# Phase 0 API and Event Serialization Design

- **Status:** Approved
- **Date:** 2026-07-14
- **Phase:** Phase 0 — Architecture and foundations
- **Program gate:** Gate 5 — External API and Event serialization
- **Implementation target:** Phase 1 — Local Central MVP

## Objective

Define the versioned local HTTP and Event wire contracts that expose the accepted Task, Runtime, Artifact, and security semantics without changing their ownership or lifecycle meanings.

## Phase boundary

This is a design-only contract. It defines HTTP paths, envelopes, serialization, schema compatibility, cursor polling, and outbox delivery meaning. It does not create Go handlers, database tables, migrations, templates, browser code, SSE/WebSocket transport, public or remote APIs, or a broker.

## Selected boundary

Phase 1 binds HTTP only to loopback and serves one trusted local OS account through the accepted bootstrap-token exchange, bounded session, CSRF protection, and Host/Origin validation. The server-rendered UI and any local automation use versioned JSON at `/api/v1`; no LAN, public, SDK, or Online Mode API exists.

Read endpoints use `GET`. A state-changing request uses its domain command name, is session- and CSRF-protected, and returns the resulting current representation plus correlation ID. HTTP never changes domain state directly: it validates transport input then submits a domain command.

`POST /api/v1/session/bootstrap` exchanges a high-entropy bootstrap token from protected local configuration for an opaque server-side session. The token is single-use, rotated on success, never appears in a URL, referrer, Event, error, or log, and failed exchanges are throttled. Sessions use an `HttpOnly; SameSite=Strict; Path=/` cookie (`Secure` whenever TLS is configured), have a 30-minute idle and 12-hour absolute expiry, and may be revoked by `POST /api/v1/session/logout`. JSON commands require an `X-CSRF-Token` issued with the session; cross-origin requests and unexpected JSON `Content-Type` values are rejected. CORS is disabled. Local automation uses this same protected bootstrap/session/CSRF flow; it has no bearer-token alternative in Phase 1.

## Common envelopes

Every JSON response has `schema_version: "v1"`, `request_id`, and either `data` or `error`; it never contains both. IDs are opaque strings. Timestamps are RFC 3339 UTC strings. Unknown response fields must be ignored; clients must reject an unknown major schema version.

```json
{"schema_version":"v1","request_id":"opaque","data":{}}
```

Errors use `code`, safe `message`, optional `field`, and `retryable`. They never include secrets, bootstrap/session/CSRF tokens, raw Artifact bodies, raw filenames, object keys, internal database errors, or unbounded untrusted input. Authorization failures are non-enumerating. `409` represents a command/version/idempotency conflict, `422` invalid input, `429` bounded retry delay, and `503` a known transient dependency failure; ambiguity remains the accepted durable `reconciliation` state rather than a transport retry instruction.

JSON command bodies are limited to 1 MiB, cursor/path/header values to 4 KiB, and JSON nesting to 32 levels; violations return safe `400` or `413`. `429` and retryable `503` include `Retry-After`. A JSON response is bounded to 2 MiB; Artifact byte streams are not JSON and return JSON errors only before bytes start.

## Resource and command surface

The v1 surface serializes only existing meanings: Workspace-scoped Task, Run, Step, StepAttempt, ToolCall, ToolCallAttempt, Approval, Checkpoint, Artifact, and Event summaries. It supports current-state reads, paginated/cursor lists, Task creation, cancel, retry, resume when the domain allows it, Approval resolution, and Artifact download/allowlisted preview. Gate 5 chooses JSON field names but does not add statuses, transitions, or authority.

Artifact delivery is Central-mediated. Immediately before bytes stream, the delivery boundary revalidates session authority, Workspace ownership, `ready`, delete intent, sensitivity, disposition, and preview eligibility. It sets explicit content type and `X-Content-Type-Options: nosniff`, uses attachment by default, exposes no presigned or raw object URL, and preserves Gate 4's preview allowlist and bounds.

### v1 route and representation matrix

| Route | Method | Contract |
| --- | --- | --- |
| `/api/v1/workspaces/{workspace_id}/tasks` | `GET`, `POST` | Cursor list; create Task command. |
| `/api/v1/workspaces/{workspace_id}/tasks/{task_id}` | `GET` | Current Task summary and linked current Run summary. |
| `/api/v1/workspaces/{workspace_id}/tasks/{task_id}:cancel` | `POST` | CancelTask command. |
| `/api/v1/workspaces/{workspace_id}/tasks/{task_id}:retry` | `POST` | RetryTask command; returns new Run. |
| `/api/v1/workspaces/{workspace_id}/approvals/{approval_id}:resolve` | `POST` | ResolveApproval command. |
| `/api/v1/workspaces/{workspace_id}/artifacts/{artifact_id}/content` | `GET` | Download-only bytes. |
| `/api/v1/workspaces/{workspace_id}/artifacts/{artifact_id}/preview` | `GET` | Allowlisted bounded preview only. |
| `/api/v1/workspaces/{workspace_id}/events` | `GET` | Cursor Event feed. |

Every resource summary has opaque `id`, `workspace_id`, `status` where the domain defines one, `created_at`, `updated_at` where applicable, and `version`; Task/Run/Step/attempt/Approval/Artifact summaries include only their accepted ownership IDs and safe state, reason, timestamps, and bounded display metadata. Optional fields are omitted, never `null`; lists return `items`, `next_cursor`, and `has_more`.

Every command requires `Idempotency-Key` (opaque 16–128 bytes) and `If-Match` with the expected aggregate version where a current aggregate is changed. Same key, same normalized command input, and same scope return the original durable result without another Event or transition. A changed input or expected version returns `409` with safe `idempotency_conflict` or `version_conflict`; clients must re-read current state rather than blind retry.

Downloads use a sanitized fallback filename, `Content-Disposition: attachment`, `Cache-Control: no-store`, and `Referrer-Policy: no-referrer`; byte ranges and conditional requests are unsupported in Phase 1. Preview uses the same no-store policy and an isolated, sandboxed response with a restrictive CSP; active content never executes.

## Events and cursor feed

An Event is immutable audit/recovery evidence, not a second current-state model. Its v1 envelope contains `event_id`, `schema_version`, `type`, `occurred_at`, `workspace_id`, `aggregate_type`, `aggregate_id`, `aggregate_version`, `correlation_id`, `causation_id`, actor summary, and a minimal type-specific safe payload. Event payloads contain no secret material, token, raw body, raw filename, object key, or unbounded label.

Every envelope also includes applicable `task_id`, `run_id`, `step_id`, `attempt_id`, `prior_state`, `next_state`, and safe `reason`. Actor is allowlisted to opaque actor ID and actor kind. Payload is a type-discriminated, versioned allowlist of opaque related IDs, state/reason, bounded counters, safe timestamps, and safe policy/version fingerprints; it never carries Task/tool input, backend locator, destination/path detail, raw operation input, or body content. Payload depth is at most 8 and serialized size at most 32 KiB; source redaction occurs before serialization.

`GET /api/v1/workspaces/{workspace_id}/events?after=<opaque-cursor>&limit=<n>` is a cursor-polling feed, not a live subscription. Ordering is stable within one Workspace by durable Event order; a response returns `events`, `next_cursor`, and `has_more`. A cursor is opaque, Workspace-bound, and invalid across retention or schema boundaries; invalid/expired cursors fail safely with a restart-from-current-state instruction. The feed may duplicate an Event after a lost response; clients deduplicate by `event_id` and reconcile from current-state reads. It never promises exactly-once delivery or cross-Workspace ordering.

The logical order is immutable Workspace-local `event_sequence`; a cursor encodes the last delivered `(workspace_id, event_sequence)` boundary. `limit` defaults to 100 and accepts 1–250 only. A page is seek-paginated, forward-only, and bounded by the common 2 MiB response limit; concurrent later Events appear only after the captured boundary and cannot cause skips before it. Phase 1 retains Events for the supported local MVP lifetime; pruning is deferred to Gate 6. A future retention watermark must invalidate cursors with `410 cursor_expired` and require current-state reload before a new feed. Gate 6 must provide a matching `(workspace_id, event_sequence)` seek index.

## Outbox and compatibility

The domain transaction that appends an Event may create an outbox delivery record referencing that immutable Event. Outbox delivery state never mutates the Event and remains Gate 6 persistence work. Phase 1 exposes the durable Event feed by polling; asynchronous publication, broker delivery, webhooks, SSE, and WebSockets are out of scope.

`v1` is additive-only: adding optional fields or new Event types is compatible; changing a field meaning, requiredness, identifier, ordering, authorization rule, or Event payload meaning requires a new major version or material ADR. Deprecated fields remain readable for the supported major version. Gate 5 owns this wire compatibility policy; Gates 6–8 own storage, Go realization, and topology.

`GET /api/v1/capabilities` returns supported API major, feed contract revision, and optional feature names. Additive fields/types do not invalidate cursors; a major API or feed-order revision does. A deprecated field is supported for the current major until the next major is introduced.

## Validation scenarios

1. A loopback session with valid CSRF invokes an allowed Task command and receives the durable result envelope.
2. Cross-Workspace, missing-session, invalid Host/Origin, and stale CSRF requests fail without state disclosure or mutation.
3. A lost event-feed response duplicates Events; `event_id` deduplication plus current-state read converges safely.
4. An invalid cursor, unknown schema major, and changed command idempotency input fail explicitly without blind retry.
5. Artifact delivery after delete intent, sensitivity change, or non-ready state never streams bytes.
6. Sentinel secrets and unsafe Artifact metadata are absent from responses, Events, errors, and cursors.

## Follow-ups

Gate 5 must propose the material API/Event decision in ADR 0006, produce canonical API/Event contracts and validation, then align summaries before acceptance. Gate 6 defines PostgreSQL/outbox representation; Gate 7 defines Go handlers and ports; Gate 8 defines local topology. No implementation begins from this Draft.
