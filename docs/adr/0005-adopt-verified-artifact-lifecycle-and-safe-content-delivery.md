# ADR 0005: Adopt verified Artifact lifecycle and safe content delivery

- **Number:** 0005
- **Title:** Adopt verified Artifact lifecycle and safe content delivery
- **Status:** Accepted
- **Created:** 2026-07-14
- **Owners:** Central maintainer
- **Decision due:** 2026-07-20
- **Decision due history:** None
- **Implementation blocked at:** Artifact lifecycle implementation plan plus dependent Gate 5–8 specifications that consume Artifact behavior; none may cross that boundary until ADR 0005 is Accepted and Gate 4 validation passes
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-14
- **Decision record:** Git status-transition commit; exact hash resolved by this file's Git history
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** [approved Gate 4 artifact storage and content policy design](../internal/superpowers/specs/2026-07-14-phase-0-artifact-storage-content-policy-design.md), [Gate 4 implementation plan](../internal/superpowers/plans/2026-07-14-phase-0-artifact-storage-content-policy.md), [ADR 0001](0001-adopt-durable-task-domain-and-lifecycle.md), [ADR 0003](0003-adopt-phase-1-security-policy-and-secret-reference-model.md), [ADR 0004](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md), [ADR governance](README.md)

## Context

ADR 0001 established Artifact as a Workspace-scoped durable aggregate whose body lives in S3-compatible storage while PostgreSQL owns lifecycle, metadata, checksum, and lineage, and made required-Artifact readiness a prerequisite for Task and Run completion. ADR 0003 established that Artifact bodies are untrusted, object keys contain only opaque IDs, MIME sniffing is disabled, and active content never renders directly. ADR 0004 reserved Gate 4 for Artifact behavior, including staging, retention, orphan cleanup, preview allowlist ownership, and storage-size policy, and blocked the Artifact lifecycle implementation plan until that behavior is decided.

The Phase 1 runtime produces generated files, logs, snapshots, large tool results, and Checkpoint payload references. It must survive a process or object-store failure without claiming an Artifact is ready before its bytes, checksum, and metadata are durably reconciled. The approved Gate 4 design defines the implementation-neutral Artifact lifecycle, integrity, object-key, content-delivery, retention, deletion, reconciliation, and quota semantics that this ADR proposes to adopt.

## Decision

Central proposes to adopt the following Phase 1 Artifact decisions from the approved Gate 4 design:

- Artifact is a separate immutable-output aggregate owned by one Workspace and linked to its producing Task, Run, Step, StepAttempt, ToolCallAttempt, or trusted system producer;
- PostgreSQL is authoritative for Artifact lifecycle, ownership, metadata, and lineage, and object-store listing is never a lifecycle source of truth;
- a ready Artifact body, ready key, byte size, and SHA-256 checksum are immutable; replacement or derivation creates a new Artifact and explicit lineage, and no ready body is ever overwritten;
- every upload begins with a durable reservation and a unique staging generation before any object-store delivery, and a staging generation is never reused or overwritten;
- finalization requires successful full-body SHA-256 and size verification, ready-key promotion without overwriting an existing ready object, a second verification of the promoted body, and one durable finalization command that records ready metadata and any completion guard it satisfies;
- required Artifact readiness remains a prerequisite for the existing Task and Run completion guard; upload success, staged bytes, or a pending finalization never satisfies that guard;
- object keys contain only version markers and opaque application-generated IDs; original filenames, Task text, labels, media types, secret values, and backend locators never appear in a key;
- Artifact bodies are untrusted; delivery is attachment and download by default with an explicit media type and no MIME sniffing; inline preview requires allowlisted detected content plus format-specific sanitization and configured bounds;
- Central mediates every body delivery; raw bucket access and presigned object URLs are never exposed to the browser, and the delivery boundary revalidates session authority, Workspace ownership, ready state, sensitivity, and absence of delete intent before streaming;
- reservation atomically admits bounded declared and maximum capacity against per-Artifact, per-Run, and per-Workspace quotas; stream-time enforcement aborts before the per-Artifact limit, and finalization atomically rechecks usage and rejects quota conflicts without ready state;
- ready Artifacts do not expire automatically in Phase 1; staging expires after 24 hours; deletion is an explicit Workspace-scoped two-phase operation that records intent, prevents delivery, performs the object-store action outside the transaction, and retains a safe tombstone preserving lineage;
- limit and integrity failures are structured failures that never silently truncate verified content, integrity metadata, authorization evidence, or completion decisions;
- reconciliation examines durable Artifact records rather than treating bucket listing as authoritative; staged-but-unfinalized state, ambiguous promotion, orphan candidates, and pending deletions resolve conservatively with durable evidence, no blind overwrite, and no resurrection.

The approved Gate 4 design owns the detailed Artifact lifecycle semantics, including the reserve, upload, verify, promote, finalize, reject, and delete commands; staging-generation and content-generation identity; idempotent command behavior; availability meanings exposed to Gate 5; the object-key namespace contract; content classification and the preview allowlist; limits, retention, and the cleanup table; recovery and reconciliation rules; the failure taxonomy; the observability contract; and the design-validation scenarios.

### Decision boundary

This ADR does not select:

- PostgreSQL schema, tables, transactions, indexes, locking queries, or migration tooling;
- concrete Go types, interfaces, package paths, streaming implementations, or dependency injection;
- S3 or MinIO bucket configuration, credentials, encryption configuration, or deployment topology;
- HTTP routes, serialized API or Event field names, schema versions, or wire payloads;
- the browser preview renderer, header implementation, UI layout, or sanitization library;
- object-store API selection, lifecycle policy configuration, or storage-class tiering;
- malware scanning, DLP, content extraction, OCR, full-text indexing, or remote sharing;
- changes to Task, Run, Step, ToolCall, Checkpoint, Event, Approval, SecretReference, or runtime semantics.

Those decisions belong to Gates 5–8 and must preserve these Artifact semantics or use a later ADR to change them.

## Consequences

### Benefits

- Artifact readiness is provable: a body becomes ready only after staged bytes, recomputed SHA-256 and size, ready-key promotion, promoted-body re-verification, and one durable finalization that records immutable evidence and updates the existing completion guard.
- A crash between object-store work and durable finalization is recoverable without overwrite or false completion, because staging generations, reservation evidence, and reconciliation rules make retry and cleanup deterministic.
- Immutable ready bodies, opaque keys, and conservative reconciliation prevent confused-deputy delivery, object-key collision, secret disclosure, and accidental resurrection of deleted or stale objects.
- Download-first delivery with an explicit media type, no MIME sniffing, and a bounded preview allowlist ensures active or unknown content never executes in the browser regardless of producer-declared filename or type.
- Central-mediated delivery with revalidation of authority, Workspace ownership, ready state, sensitivity, and delete intent prevents cross-Workspace access, post-delete delivery, and sensitivity downgrade by untrusted input.
- Quota reservation at admission and atomic recheck at finalization bound per-Artifact, per-Run, and per-Workspace storage without silent truncation or partial ready state.
- Explicit two-phase deletion with tombstones preserves safe lineage evidence while preventing body access after delete intent, satisfying audit and recovery needs without resurrection risk.
- Gate 4 semantic ownership does not preempt Gate 5–8 representation, API, persistence, Go, or infrastructure decisions.

### Costs and limitations

- The staged reservation, verify, promote, and finalize sequence adds object-store round-trips, a second verification pass, and reconciliation complexity compared to writing directly to a final key.
- Opaque application-generated keys and the prohibition on raw filenames in keys require producers and consumers to rely on durable metadata for display, debugging, and lineage.
- Conservative orphan cleanup that trusts durable state over bucket listing may retain stale staging or orphan objects longer than an aggressive listing-based sweep, trading storage cost for safety.
- The preview allowlist is deliberately narrow; expanding it to new active formats requires material review and a sanitization boundary, limiting preview convenience in Phase 1.
- Quota enforcement at reservation and finalization may reject otherwise-valid output when Workspace or Run capacity is exhausted; producers must delete retained Artifacts, reduce output, or wait for capacity release.
- Ready Artifact immutability means every correction or derivation creates a new Artifact with explicit lineage, increasing object count and metadata volume over in-place edits.
- Central-mediated delivery adds a streaming hop and per-request revalidation compared to direct presigned URLs; the safety gain is intentional and presigned exposure remains prohibited.

## Alternatives considered

### Write body directly to final key then infer readiness

Rejected because object storage cannot atomically coordinate with PostgreSQL. A crash would leave a final-looking body without authoritative metadata or completion evidence, making retry, cleanup, and completion decisions unsafe.

### Store Artifact bodies in PostgreSQL

Rejected because it conflicts with ADR 0001, duplicates object-storage responsibilities, and makes large bodies and object-store recovery unnecessarily expensive.

### Trust producer filename or declared media type

Rejected because untrusted producers can use misleading names and types to trigger active browser interpretation. Detected content classification and explicit delivery policy must control rendering and disposition.

### Automatic expiry of ready Artifacts in Phase 1

Rejected because local durable output should not disappear without explicit operator retention intent. Phase 1 auto-cleans only stale staging and proven orphans; ready bodies persist until explicit deletion.

### Presigned object URLs for browser delivery

Rejected because raw bucket exposure bypasses Central-mediated authority, Workspace-ownership, ready-state, sensitivity, and delete-intent revalidation, and cannot enforce the download-first disposition or nosniff header uniformly.

## Follow-ups

- Central maintainer explicitly accepts or rejects this ADR after proposal; Gate 4 design approval is not the ADR decision.
- Gate 4 validation owner records independent design-contract walkthrough evidence after acceptance and before the Artifact lifecycle implementation plan begins.
- Gate 5 specification owner defines API and Event field names, the delivery endpoint, response headers, the preview renderer boundary, and schema versions by `2026-07-20`.
- Gate 6 specification owner defines PostgreSQL representation, transactions, lease and reconciler queries, tombstone retention, and migration policy by `2026-07-20`.
- Gate 7 specification owner defines Go domain ports, streaming interfaces, and package placement by `2026-07-20`.
- Gate 8 specification owner defines bucket naming, MinIO topology, lifecycle configuration, and credentials by `2026-07-20`.

## References

- [Phase 0 Artifact Storage and Content Policy Design](../internal/superpowers/specs/2026-07-14-phase-0-artifact-storage-content-policy-design.md)
- [Phase 0 Artifact Storage and Content Policy Implementation Plan](../internal/superpowers/plans/2026-07-14-phase-0-artifact-storage-content-policy.md)
- [ADR governance and index](README.md)
- [ADR 0001 — Adopt the durable Task domain and lifecycle](0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0003 — Adopt the Phase 1 security policy and SecretReference model](0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [ADR 0004 — Adopt staged single-agent runtime and verified adapter handoffs](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [Durable execution](../architecture/durable-execution.md)
