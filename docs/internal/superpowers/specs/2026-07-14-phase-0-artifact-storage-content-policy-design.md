# Phase 0 Artifact Storage and Content Policy Design

- **Status:** Approved
- **Date:** 2026-07-14
- **Phase:** Phase 0 — Architecture and foundations
- **Program gate:** Gate 4 — Artifact storage and content policy
- **Implementation target:** Phase 1 — Local Central MVP

## Context

ADR 0001 defines Artifact as a Workspace-scoped durable aggregate whose body lives in S3-compatible storage while PostgreSQL owns lifecycle, metadata, checksum, and lineage. A Task may complete only after every required Artifact is verified and the final Artifact metadata, Task state, and Events commit atomically. ADR 0003 requires Artifact bodies to be treated as untrusted, object keys to contain opaque IDs only, MIME sniffing to be disabled, and active content never to render directly. ADR 0004 reserves Gate 4 for Artifact behavior, including staging, retention, orphan cleanup, preview allowlist ownership, and storage-size policy.

The Phase 1 runtime produces generated files, logs, snapshots, large tool results, and Checkpoint payload references. It must survive a process or object-store failure without claiming an Artifact is ready before the bytes, checksum, and metadata are durably reconciled.

Related decisions and contracts:

- [ADR 0001 — durable Task domain and lifecycle](../../../adr/0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0003 — security policy and SecretReference model](../../../adr/0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [ADR 0004 — staged runtime and verified adapter handoffs](../../../adr/0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [approved domain and lifecycle design](2026-07-12-phase-0-domain-lifecycle-design.md)
- [capability and Approval policy](../../../security/capability-policy.md)
- [durable execution overview](../../../architecture/durable-execution.md)

## Objective

Define implementation-neutral Artifact lifecycle, integrity, object-key, content-delivery, retention, deletion, reconciliation, and quota semantics so a Phase 1 implementation can persist and safely expose output without weakening the accepted completion barrier or security model.

The design succeeds when:

- PostgreSQL remains authoritative for Artifact state and ownership;
- an Artifact becomes ready only after its staged bytes, size, and SHA-256 checksum are verified;
- a crash between object-store work and durable finalization is recoverable without overwrite or false completion;
- required Artifacts participate in the existing Task/Run completion guard;
- object keys, metadata, logs, Events, and errors do not disclose secrets, raw filenames, or untrusted labels;
- browser delivery is download-first and cannot execute active content;
- retention, deletion, quotas, and orphan cleanup are finite, auditable, and Workspace-scoped.

## Phase boundary

This is a design-only Phase 0 contract. It does not create object-store buckets, Go interfaces, SQL tables, migrations, HTTP routes, Event payloads, browser handlers, Docker/MinIO configuration, background jobs, or executable tests.

### In scope

- Artifact identity, ownership, metadata, integrity, and lineage semantics;
- staging, verification, finalization, readiness, deletion, and tombstone behavior;
- object-key namespace and opaque-key rules;
- content classification, download disposition, preview allowlist, and sanitization boundary;
- Artifact size, Run, Workspace, staging-age, retention, and cleanup policy;
- restart reconciliation, failure classification, observability, and validation scenarios;
- ownership boundaries for Gates 5–8.

### Out of scope

- concrete S3/MinIO APIs, bucket provisioning, credentials, encryption configuration, or deployment topology;
- PostgreSQL schema, transactions, indexes, locking queries, or retention-job implementation;
- serialized API/Event fields, HTTP routes, browser header implementation, UI layout, or preview renderer;
- Go packages, interfaces, streaming implementation, worker scheduling, or background-job framework;
- malware scanning, DLP, content extraction, OCR, full-text indexing, or remote sharing;
- changing Task, Run, Step, ToolCall, Checkpoint, Event, Approval, SecretReference, or runtime semantics.

## Approaches considered

### Selected: durable reservation, verified staging, immutable ready body

An Artifact has a durable reservation before its body is written. Upload happens outside PostgreSQL to a unique staging key. Verification recomputes the full body size and SHA-256. A verified body is promoted to an immutable ready key, and a finalization command then atomically records ready metadata and any completion guard it satisfies.

This separates non-transactional object storage from authoritative lifecycle state, keeps recovery deterministic, and prevents a successful upload from being mistaken for a ready Artifact.

### Rejected: write body directly to final key then infer readiness

Object storage cannot atomically coordinate with PostgreSQL. A crash would leave a final-looking body without authoritative metadata or completion evidence, making retry and cleanup unsafe.

### Rejected: store Artifact bodies in PostgreSQL

This conflicts with ADR 0001, duplicates object-storage responsibilities, and makes large bodies and object-store recovery unnecessarily expensive.

### Rejected: trust producer filename or declared media type

Untrusted producers can use misleading names and types to trigger active browser interpretation. Detected content classification and explicit delivery policy must control rendering.

### Rejected: automatic expiry of ready Artifacts in Phase 1

Local durable output should not disappear without explicit operator retention intent. Phase 1 therefore only auto-cleans stale staging and proven orphans.

## Core decisions

1. Artifact is a separate immutable-output aggregate owned by one Workspace and linked to its producing Task, Run, Step, StepAttempt, ToolCallAttempt, or trusted system producer as applicable.
2. PostgreSQL is authoritative for Artifact lifecycle, ownership, metadata, and lineage; object-store listing is never a lifecycle source of truth.
3. A ready Artifact body and integrity metadata are immutable. Replacement or derivation creates a new Artifact and explicit lineage; no ready body is overwritten.
4. Every upload uses a durable reservation and a unique staging generation before object-store delivery.
5. Finalization requires successful full-body SHA-256 and size verification, a ready-key promotion result, and one durable command that records ready metadata.
6. Required Artifact readiness is a prerequisite for existing Task/Run completion. Upload success, staged bytes, or a pending finalization never satisfies that guard.
7. Object keys contain only version markers and opaque application-generated IDs. Original filenames, Task text, labels, media types, secret values, and backend locators never appear in a key.
8. Artifact bodies are untrusted. Delivery is attachment/download by default with an explicit type and no MIME sniffing. Inline preview requires allowlisted detected content plus format-specific sanitization and bounds.
9. Ready Artifacts do not expire automatically in Phase 1. Staging expires after 24 hours; deletion is an explicit Workspace-scoped, two-phase operation retaining safe tombstone and lineage evidence.
10. Limit failures are structured failures. They never silently truncate verified content, integrity metadata, authorization evidence, or completion decisions.

## Vocabulary and ownership

| Term | Meaning | Owner |
| --- | --- | --- |
| Artifact reservation | Durable authority to upload one body for one Artifact and staging generation. It is not readiness. | Artifact contract |
| Staging Artifact | Reserved Artifact whose body may exist only at its unique staging key and has not satisfied verification/finalization. | Artifact contract |
| Ready Artifact | Immutable Artifact with a verified body at its ready key and durable final metadata. | Artifact contract |
| Staging generation | Opaque one-time identity that prevents a retry or another producer from overwriting staged bytes. | Artifact contract |
| Content classification | Declared type, detected type/family, preview eligibility, and disposition determined from bounded verification. | Content policy |
| Artifact lineage | Immutable relation from an Artifact to producer evidence and optional parent/derived Artifact IDs. | Artifact contract |
| Orphan candidate | Object-store body with no valid durable reservation/finalization relationship or a stale staging body whose state is terminal. It is never treated as ready. | Reconciler |
| Tombstone | Durable non-body evidence that a delete intent and outcome occurred. It preserves safe lineage but grants no body access. | Artifact contract |

## Artifact metadata and invariants

Every Artifact records, at minimum:

- opaque Artifact ID and Workspace ID;
- Task, Run, Step, StepAttempt, ToolCallAttempt, and producer identity where applicable;
- required/optional completion role;
- immutable staging-generation identity while staging;
- ready object key only after finalization;
- sanitized display name, declared media type, detected media family/type, disposition, and preview eligibility;
- verified byte size and SHA-256 checksum;
- creation, verification, ready, retention/deletion-intent, and deletion-result timestamps as applicable;
- parent/derived Artifact lineage and safe provenance.

Invariants:

- every reference must belong to the same Workspace;
- an Artifact has at most one ready body and checksum;
- a ready body/key/checksum/size never changes;
- only a ready Artifact can satisfy a required output or Checkpoint reference;
- a tombstoned/deleted Artifact never becomes ready again;
- metadata, log, Event, metric, and error surfaces omit body content, secret material, raw filenames, unbounded labels, and unsafe path fragments.

## Lifecycle and finalization

The Artifact contract uses semantic states `reserved`, `staging`, `verifying`, `ready`, `rejected`, `delete_pending`, and `deleted`. These are Artifact-domain states, not Task/Run/Step states.

1. **ReserveArtifact** creates an Artifact ID, opaque staging generation/key, ownership links, limits snapshot, and reservation evidence. It occurs before any object-store call.
2. **Upload staging body** writes only to that unique staging key outside a PostgreSQL transaction. A producer may stream; it need not buffer the complete Artifact in process memory.
3. **VerifyArtifact** reads the staged body and recomputes byte size and SHA-256. It validates Workspace ownership, reservation, configured limits, and bounded content classification.
4. **PromoteArtifact** copies or otherwise materializes the verified bytes at the deterministic ready key without overwriting an existing ready object. A second verification confirms the promoted body still has the approved size and checksum.
5. **FinalizeArtifact** atomically records ready state, ready key, integrity metadata, classification, lineage, and immutable evidence. When required, the same transaction updates the existing Task/Run/Step completion guard and appends its Events.
6. **RejectArtifact** records a structured reason for checksum, size, classification, policy, or known upload failure. It cannot satisfy completion.
7. **RequestArtifactDeletion** records explicit Workspace-scoped delete intent. **SettleArtifactDeletion** records known object deletion or a recoverable failure after the external delete operation. The resulting tombstone preserves safe lineage only.

Object-store operations never occur inside an open PostgreSQL transaction. A known failed upload may retry only through a new staging generation; it never overwrites the prior staged body. Ambiguous object-store delivery or promotion enters reconciliation with durable evidence and no blind overwrite.

Every lifecycle command has a stable command identity. Repeating a command with the same Artifact, expected lifecycle version, staging generation, ready key, checksum, and size returns its already-durable result without another Event, quota settlement, promotion, or completion transition. A different generation, key, checksum, or size fails closed. Delete intent wins any uncommitted finalization: a transactional version/state check prevents transition to `ready` after `delete_pending`; reconciliation may only settle deletion or clean the body.

Gate 4 exposes these availability meanings to Gate 5: `reserved`, `staging`, and `verifying` are preparing and not downloadable; `ready` is the only downloadable state; `rejected` exposes a safe structured failure and retry eligibility; `delete_pending` is unavailable; `deleted` is an irreversible tombstone with no restore in Phase 1. Gate 5 may choose field names but not different meanings.

## Object-key contract

The semantic key layout is:

```text
v1/staging/<workspace-opaque-id>/<artifact-opaque-id>/<staging-generation>
v1/ready/<workspace-opaque-id>/<artifact-opaque-id>/<content-generation>
```

The exact bucket, encoding, delimiter, key prefix implementation, and object-store API belong to Gates 6–8. The semantic requirements are that keys are deterministic where readiness/recovery require it, scoped by Workspace, include no unsafe user-controlled segment, and cannot collide across Artifact IDs or staging generations.

## Content policy and delivery

Declared media type and filename are hints only. Verification classifies content from bounded bytes and format structure; unrecognized or contradictory content is download-only.

| Detected content | Default disposition | Preview rule |
| --- | --- | --- |
| Plain text, CSV, JSON | Download | May preview only as bounded escaped text; JSON is never executed or rendered as HTML. |
| PNG, JPEG, GIF | Download | May preview only after image parser verification and configured dimension/byte limits. |
| HTML, SVG, PDF, office documents, archives, scripts, executables, unknown/binary | Download | Never inline-preview in Phase 1. |
| Restricted/sensitive Artifact | Download | Never inline-preview, regardless of media type. |

The future Gate 5 delivery API/UI must set an explicit media type, attachment disposition unless preview is eligible, and `X-Content-Type-Options: nosniff`. It must not use the Artifact display name as a path, executable URL, or authorization input. Preview sanitization and rendering implementation are Gate 5 work, but must not widen this allowlist without a material review.

Central mediates every body delivery: raw bucket access and presigned object URLs are never exposed to the browser. Immediately before streaming, the delivery boundary revalidates authenticated session authority, Workspace ownership, `ready` state, sensitivity/disposition, and absence of delete intent. Sensitivity is derived from trusted producer context and policy; untrusted Task/tool/filename/type input cannot downgrade it, and uncertainty is restricted/download-only. Central-managed and secret-aware paths never write plaintext secrets or credential-bearing requests/responses into Artifact bodies; suspected disclosure blocks readiness/delivery and produces the existing sanitized revoke/rotate guidance. Classification and preview eligibility have hard installed-policy bounds for input/header bytes, parser work/time, decoded bytes, pixels, frames, text bytes/lines, and structured nesting; a limit breach is download-only or rejected.

## Limits, retention, and deletion

| Control | Default | Phase 1 hard maximum | Scope |
| --- | --- | --- | --- |
| Ready Artifact body | 256 MiB | 4 GiB | Per Artifact verified body |
| Artifact bytes per Run | 1 GiB | 16 GiB | Sum of ready Artifact bodies produced by one Run |
| Ready Artifact bytes per Workspace | 10 GiB | 100 GiB | Current retained ready bodies in one Workspace |
| Staging lifetime | 24 hours | 72 hours | Per reserved/staging generation |
| Ready Artifact automatic retention | No expiry | No expiry | Phase 1; explicit deletion only |

Installed policy may choose lower limits and shorter staging lifetime. A value above a hard maximum is rejected. Gate 4 limits do not relax any Gate 3 tool-result or Checkpoint limit; a producer that exceeds its own upstream bound must use an approved streaming Artifact path or fail structurally.

Reservation atomically admits bounded declared/maximum capacity for the Artifact plus Workspace staging bytes/count before upload. Staging and promoted-but-unfinalized bytes count against that reservation; stream-time enforcement aborts before the per-Artifact limit. Finalization atomically rechecks Run/Workspace usage, settles the reservation to verified size, and rejects quota conflicts without `ready`. Rejection, proven cleanup, and deletion release capacity exactly once. Capacity errors name safe remedies: delete retained Artifacts, reduce output, or retry after capacity is released.

Deletion requires explicit authorization for the Artifact and Workspace. It records intent before object-store deletion, prevents new delivery, performs the object-store action outside the transaction, and records either deletion completion or a recoverable failure. A deletion retry operates on the same Artifact/tombstone identity and is idempotent. Retention/tombstone duration after deletion is a Gate 6 persistence decision, but it must preserve enough safe lineage to prevent accidental resurrection or object-key reuse.

## Recovery and reconciliation

At startup and during bounded reconciliation, Central examines durable Artifact records rather than treating bucket listing as authoritative:

- a reserved/staging Artifact with a verified staged body may resume promotion/finalization only when reservation, owner, checksum, limits, and state are still valid;
- a staged body with a checksum/size mismatch is rejected and eventually cleaned;
- a crash after staging upload but before verification remains non-ready and cannot complete a Task;
- a crash during promotion/finalization creates durable reconciliation evidence; finalization is permitted only after ready-key integrity is proven;
- an object with no valid reservation is an orphan candidate and is removed only after conservative age and prefix/ownership checks;
- a stale ready object lacking durable ready metadata is never silently adopted as ready;
- a pending deletion is retried idempotently; no body is served after durable delete intent.

Expiry and cleanup eligibility use durable/database-derived comparison time; Gate 6 selects the query/representation. Reconciliation is resumable and cursor/batch/byte-budget bounded, allows normal command service between passes, and records staging bytes/age, backlog age, cleanup/delete failures, quota denials, actor/authority, and progress. It runs at startup and at an installed bounded interval; stalled entries have an operator-resolution path. Content-generation IDs are never reused, including after deletion.

Object-store unavailability before delivery may use the existing bounded `retry_delay` semantics when non-delivery is proven. Known uploaded-but-unfinalized state waits for reconciliation. Ambiguous delivery/promotion never causes a blind overwrite or completion claim.

## Failure behavior

| Condition | Durable behavior | Completion / retry rule |
| --- | --- | --- |
| Size/checksum mismatch | Reject Artifact with structured integrity reason | No ready state; producer may create a new staging generation if policy permits |
| Limit/quota exhausted | Structured limit failure | No partial finalization or silent truncation |
| Unsafe or unknown content | Download-only classification, or reject when policy forbids storage | Never active preview |
| Upload proven not delivered | Persist known non-delivery | Bounded retry with a new staging generation when policy permits |
| Upload/promotion outcome ambiguous | Persist reconciliation evidence | Never overwrite/re-upload blindly |
| Required Artifact not ready | Existing Task/Run completion guard rejects completion | Resume/fail through accepted runtime semantics |
| Cross-Workspace access or mutation | Structured authorization denial | No read, delivery, finalize, or delete |
| Cleanup/delete outcome ambiguous | Preserve delete-pending/reconciliation evidence | No resurrection or body delivery |

## Observability and validation

Safe observations include Artifact, Workspace, Task, Run, producer, staging generation, state transition, size bucket, checksum status, declared/detected content class, preview decision, limit result, retention action, cleanup reason, and correlation/causation IDs. They exclude body content, secret material, raw filenames, unsafe key fragments, and unbounded labels.

Representative Gate 4 validation scenarios will cover:

1. required verified Artifact finalizes once and permits the existing completion guard;
2. checksum/size mismatch never becomes ready;
3. crash after upload before finalization reconciles without Task completion or overwrite;
4. crash during promotion preserves immutable evidence and finalizes only after re-verification;
5. expired staging and proven orphan cleanup never delete a ready/finalizable Artifact;
6. cross-Workspace read, finalization, deletion, and key reuse fail closed;
7. keys, metadata, Events, logs, and errors contain no secret or raw filename;
8. active/unknown content is download-only with no sniffing; eligible preview stays bounded and sanitized;
9. quota exhaustion is structured and leaves no ready partial Artifact;
10. delete intent prevents delivery and tombstone lineage prevents resurrection.

## Cross-gate ownership and follow-ups

| Decision | Owner | Due | Blocks |
| --- | --- | --- | --- |
| Artifact lifecycle, key semantics, content policy, quotas, retention, cleanup | Gate 4 specification owner | 2026-07-20 | Artifact implementation plan |
| API/Event field names, delivery endpoint, headers, preview renderer | Gate 5 specification owner | 2026-07-20 | Artifact API/UI implementation plan |
| PostgreSQL representation, transactions, lease/reconciler queries, tombstone retention | Gate 6 specification owner | 2026-07-20 | Artifact persistence/migration plan |
| Go domain ports, streaming interfaces, package placement | Gate 7 specification owner | 2026-07-20 | Artifact adapter implementation plan |
| Bucket naming, MinIO topology, lifecycle configuration, credentials | Gate 8 specification owner | 2026-07-20 | Local object-storage implementation plan |

## ADR requirement

The selected Artifact lifecycle and safe content-delivery policy is material architecture. Gate 4 must propose ADR 0005 before canonical summaries claim adoption, accept it only through the established ADR governance flow, and record independent design-contract validation before Gate 4 becomes complete.

## Risks

- Cross-store finalization is easy to misread as an atomic distributed transaction; the implementation plan must preserve staged verification and reconciliation.
- Preview policy can expand unsafely through a convenient renderer; new active formats require material review.
- Orphan cleanup can destroy valid outputs if it trusts listing or local time alone; cleanup must use durable state and conservative expiry evidence.
- Unlimited retained local output can exhaust storage; quotas are enforced at reservation/finalization, and later retention policy must preserve lineage.
