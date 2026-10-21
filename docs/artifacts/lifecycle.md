# Artifact Lifecycle Contract

## Authority and status

This is the canonical Gate 4 Artifact contract for the Central project. It defines Artifact identity, ownership, metadata, integrity, staging, verification, finalization, readiness, lineage, deletion, recovery, cleanup, observability, and validation for Phase 1.

These contracts were adopted by Accepted ADR 0005 and passed Gate 4 design-contract validation. This document makes no runtime implementation claim. Phase 0 validated it through contract walkthroughs and repository checks. Phase 1 realizes it behind domain-owned interfaces without changing meaning.

This contract consumes ADR 0001 (durable Task domain and lifecycle), ADR 0003 (security policy and SecretReference model), and ADR 0004 (staged runtime and verified adapter handoffs). It is the implementation-neutral source for the Artifact lifecycle, object-key namespace, content-classification boundary, quota admission, retention, deletion, and reconciliation semantics. Gate 5 owns API/Event field names and the delivery endpoint; Gate 6 owns PostgreSQL representation and reconciler queries; Gate 7 owns Go domain ports and streaming interfaces; Gate 8 owns bucket and MinIO topology. None of those gates may change the meanings defined here without a later ADR.

PostgreSQL is authoritative for Artifact lifecycle, ownership, metadata, and lineage. Object-store listing is never a lifecycle source of truth.

## Vocabulary and ownership

| Term | Meaning | Owner |
| --- | --- | --- |
| Artifact reservation | Durable authority to upload one body for one Artifact and one staging generation. It is not readiness. | Artifact contract |
| Staging Artifact | Reserved Artifact whose body may exist only at its unique staging key and has not satisfied verification and finalization. | Artifact contract |
| Ready Artifact | Immutable Artifact with a verified body at its ready key and durable final metadata. | Artifact contract |
| Staging generation | Opaque one-time identity that prevents a retry or another producer from overwriting staged bytes. | Artifact contract |
| Content generation | Opaque one-time identity for a promoted ready body. It is never reused, including after deletion. | Artifact contract |
| Content classification | Declared type, detected type/family, preview eligibility, and disposition determined from bounded verification. | Content policy |
| Artifact lineage | Immutable relation from an Artifact to producer evidence and optional parent or derived Artifact IDs. | Artifact contract |
| Orphan candidate | Object-store body with no valid durable reservation or finalization relationship, or a stale staging body whose state is terminal. It is never treated as ready. | Reconciler |
| Tombstone | Durable non-body evidence that a delete intent and outcome occurred. It preserves safe lineage but grants no body access. | Artifact contract |
| Producer | Trusted system component, Task, Run, Step, StepAttempt, or ToolCallAttempt that owns a reservation. Untrusted Task, tool, filename, or media-type input cannot act as a producer authority. | Artifact contract |

Every Artifact is owned by exactly one Workspace. Every Task, Run, Step, StepAttempt, ToolCallAttempt, producer, lineage parent, derived Artifact, reservation, staging generation, content generation, and tombstone referenced by an Artifact must belong to the same Workspace. Cross-Workspace reference, delivery, finalization, or deletion is a structured authorization denial.

## Artifact metadata and invariants

Every Artifact durably records, at minimum:

- opaque Artifact ID and Workspace ID;
- Task, Run, Step, StepAttempt, ToolCallAttempt, and producer identity where applicable;
- required or optional completion role;
- immutable staging-generation identity while staging;
- ready object key only after finalization;
- sanitized display name, declared media type, detected media family/type, disposition, and preview eligibility;
- verified byte size and SHA-256 checksum;
- creation, verification, ready, retention/deletion-intent, and deletion-result timestamps as applicable;
- parent and derived Artifact lineage and safe provenance.

Invariants:

- every reference must belong to the same Workspace;
- an Artifact has at most one ready body, ready key, byte size, and SHA-256 checksum;
- a ready body, ready key, checksum, and size never change — replacement or derivation creates a new Artifact with explicit lineage, and the contract will never overwrite a ready body;
- only a ready Artifact can satisfy a required output or Checkpoint reference;
- a tombstoned or deleted Artifact never becomes ready again;
- metadata, log, Event, metric, and error surfaces omit body content, secret material, raw filenames, unbounded labels, and unsafe path fragments;
- object keys contain only version markers and opaque application-generated IDs.

## State and command transition matrix

Artifact-domain states are distinct from Task, Run, and Step states. The seven Artifact states are `reserved`, `staging`, `verifying`, `ready`, `rejected`, `delete_pending`, and `deleted`.

| Command | Pre-state(s) | Post-state | Notes |
| --- | --- | --- | --- |
| ReserveArtifact | (none) | `reserved` | Creates Artifact ID, opaque staging generation/key, ownership links, limits snapshot, reservation evidence. Occurs before any object-store call. |
| BeginStagedUpload | `reserved` | `staging` | Records that a producer is streaming to the unique staging key. Staged upload happens outside any PostgreSQL transaction. |
| VerifyArtifact | `staging` | `verifying` | Reads the staged body, recomputes byte size and SHA-256, validates Workspace ownership, reservation, configured limits, and bounded content classification. |
| PromoteArtifact | `verifying` | `verifying` | Copies or otherwise materializes verified bytes at the deterministic ready key without overwriting an existing ready object. A second verification confirms the promoted body still has the approved size and checksum. |
| FinalizeArtifact | `verifying` | `ready` | Atomically records ready state, ready key, integrity metadata, classification, lineage, and immutable evidence. When required, the same transaction updates the existing Task/Run/Step completion guard and appends its Events. |
| RejectArtifact | `staging`, `verifying` | `rejected` | Records a structured reason for checksum, size, classification, policy, or known upload failure. It cannot satisfy completion. |
| RequestArtifactDeletion | `reserved`, `staging`, `verifying`, `ready`, `rejected` | `delete_pending` | Records explicit Workspace-scoped delete intent before any object-store deletion. Prevents new delivery and new finalization. |
| SettleArtifactDeletion | `delete_pending` | `deleted` | Records known object deletion or a recoverable failure after the external delete operation. The resulting tombstone preserves safe lineage only. |

Transition guards:

- a transactional version and state check prevents any transition to `ready` after `delete_pending`;
- delete intent wins any uncommitted finalization: when `delete_pending` is durable, reconciliation may only settle deletion or clean the body, never finalize;
- `deleted` is terminal and irreversible in Phase 1 — there is no restore command and no path back to `ready`;
- `rejected` is terminal for that staging generation; a producer may create a new Artifact with a new staging generation if policy permits, but the rejected generation is never reused;
- object-store operations never occur inside an open PostgreSQL transaction.

Availability meanings exposed to Gate 5:

- `reserved`, `staging`, and `verifying` are preparing and not downloadable;
- `ready` is the only downloadable state;
- `rejected` exposes a safe structured failure and retry eligibility;
- `delete_pending` is unavailable;
- `deleted` is an irreversible tombstone with no restore in Phase 1.

Gate 5 may choose serialized field names but not different availability meanings.

## Command idempotency

Every lifecycle command has a stable command identity. The command identity is composed of the Artifact ID, expected lifecycle version, staging generation, ready key, content generation, SHA-256 checksum, and verified byte size.

Repeating a command with the same identity returns its already-durable result without another Event, quota settlement, promotion, completion transition, or object-store side effect. The replayed response carries the same immutable evidence and outcome as the original.

A command whose staging generation, ready key, content generation, checksum, or size differs from the durable record fails closed. It records a structured mismatch failure and performs no transition, no promotion, no quota settlement, and no completion update. Mismatched evidence never causes a blind overwrite or a duplicate Event.

A deletion retry operates on the same Artifact and tombstone identity and is idempotent: a repeated `SettleArtifactDeletion` returns the prior settlement result once object deletion is proven, without a second delete operation or a second tombstone.

## Reservation and quota admission

Reservation atomically admits bounded declared and maximum capacity against per-Artifact, per-Run, and per-Workspace quotas before any object-store delivery. The reservation records the limits snapshot in force so later policy changes cannot retroactively relax or reject an in-flight Artifact.

Reservation behavior:

- staging bytes and staging count are reserved before upload against the Workspace staging budget;
- a reservation is not readiness and does not satisfy any completion guard;
- stream-time enforcement aborts an upload before it exceeds the per-Artifact body limit, so a runaway producer cannot consume unbounded storage;
- a known failed upload may retry only through a new staging generation; the prior reservation is released exactly once and a new reservation is created.

Finalization atomically rechecks Run and Workspace usage, settles the reservation to verified size, and rejects quota conflicts without `ready`. Promoted-but-unfinalized bytes remain charged against the reservation until finalization commits or rejection releases them.

Capacity is released exactly once on:

- rejection of the staging generation;
- proven cleanup of a stale or orphaned staging body;
- deletion of a ready Artifact.

Capacity errors name safe remedies: delete retained Artifacts, reduce output, or retry after capacity is released. Limit failures are structured failures. They never silently truncate verified content, integrity metadata, authorization evidence, or completion decisions.

### Limits and capacity accounting

Installed policy may choose lower limits and a shorter staging lifetime. A value above a hard maximum is rejected. Changing a hard maximum is a material Gate 4 contract change and requires ADR review.

| Control | Default | Phase 1 hard maximum | Scope |
| --- | --- | --- | --- |
| Ready Artifact body | 256 MiB | 4 GiB | Per Artifact verified body |
| Artifact bytes per Run | 1 GiB | 16 GiB | Sum of ready Artifact bodies produced by one Run |
| Ready Artifact bytes per Workspace | 10 GiB | 100 GiB | Current retained ready bodies in one Workspace |
| Staging lifetime | 24 hours | 72 hours | Per reserved/staging generation |
| Ready Artifact automatic retention | No expiry | No expiry | Phase 1; explicit deletion only |

Gate 4 limits do not relax any Gate 3 tool-result or Checkpoint limit. A producer that exceeds its own upstream bound must use an approved streaming Artifact path or fail structurally.

## Staged upload, verification, promotion, and atomic finalization

The Artifact lifecycle separates non-transactional object storage from authoritative lifecycle state.

1. **ReserveArtifact** creates an Artifact ID, opaque staging generation and staging key, ownership links, limits snapshot, and reservation evidence. It occurs before any object-store call.
2. **Staged upload** writes only to that unique staging key outside any PostgreSQL transaction. A producer may stream; it need not buffer the complete Artifact in process memory. Stream-time enforcement aborts before the per-Artifact limit.
3. **VerifyArtifact** reads the staged body and recomputes byte size and SHA-256. It validates Workspace ownership, reservation, configured limits, and bounded content classification. The recomputed size and checksum are the only values trusted for promotion.
4. **PromoteArtifact** copies or otherwise materializes the verified bytes at the deterministic ready key without overwriting an existing ready object. A second verification confirms the promoted body still has the approved size and SHA-256 checksum.
5. **FinalizeArtifact** atomically records ready state, ready key, integrity metadata, classification, lineage, and immutable evidence in one PostgreSQL transaction. When the Artifact is required, the same transaction updates the existing Task/Run/Step completion guard and appends its Events.

A known failed upload retries only through a new staging generation; it never overwrites the prior staged body. Ambiguous object-store delivery or promotion enters reconciliation with durable evidence and no blind overwrite.

### Object-key contract

The semantic key layout is:

```text
v1/staging/<workspace-opaque-id>/<artifact-opaque-id>/<staging-generation>
v1/ready/<workspace-opaque-id>/<artifact-opaque-id>/<content-generation>
```

Keys are deterministic where readiness and recovery require it, scoped by Workspace, and include no unsafe user-controlled segment. The exact bucket, encoding, delimiter, key prefix implementation, and object-store API belong to Gates 6 through 8. Original filenames, Task text, labels, media types, secret values, and backend locators never appear in a key. Content-generation IDs are never reused, including after deletion.

### Content policy boundary

Declared media type and filename are hints only. Verification classifies content from bounded bytes and format structure. Unrecognized or contradictory content is download-only. Inline preview requires allowlisted detected content plus format-specific sanitization and configured bounds. Central mediates every body delivery; raw bucket access and presigned object URLs are never exposed to the browser. The delivery boundary revalidates authenticated session authority, Workspace ownership, `ready` state, sensitivity, disposition, and absence of delete intent before streaming.

## Completion barrier

A Task or Run completes only when every required Artifact is ready and the final Artifact metadata, Task state, and Events commit atomically in one PostgreSQL transaction.

The completion guard accepts only a verified ready Artifact:

- a `reserved`, `staging`, or `verifying` Artifact is preparing and never satisfies a required output;
- a staged body without verified SHA-256 and size never satisfies a required output;
- a pending finalization never satisfies a required output, even if the promoted body exists in object storage;
- a `rejected` Artifact never satisfies a required output;
- a `delete_pending` or `deleted` Artifact never satisfies a required output.

Upload success, staged bytes, or a pending finalization never satisfies the completion guard. This rule composes with the existing Task, Run, and Step completion semantics from ADR 0001 and the runtime contract; it adds no new Task or Run state.

## Lineage

Artifact lineage is an immutable relation from an Artifact to its producer evidence and optional parent or derived Artifact IDs. Replacement or derivation creates a new Artifact with explicit lineage; no ready body is ever overwritten.

Lineage records:

- producer identity — trusted system component, Task, Run, Step, StepAttempt, or ToolCallAttempt;
- parent Artifact ID when the new Artifact replaces or derives from a prior ready body;
- derived Artifact IDs when a later Artifact records this one as its parent;
- safe provenance — opaque IDs and classification only, never body content, secret material, or raw filenames.

Lineage is Workspace-scoped: a parent or derived Artifact must belong to the same Workspace. Cross-Workspace lineage is a structured authorization denial. A tombstoned or deleted Artifact retains its lineage evidence; the tombstone grants no body access but preserves the relation for audit and recovery.

## Delete intent and tombstone

Deletion is an explicit Workspace-scoped two-phase operation. It requires explicit authorization for the Artifact and Workspace.

1. **RequestArtifactDeletion** records delete intent before any object-store deletion. The Artifact enters `delete_pending`. New delivery is prevented and new finalization is blocked.
2. **SettleArtifactDeletion** performs the object-store action outside any PostgreSQL transaction and records either deletion completion or a recoverable failure. On completion, the Artifact enters `deleted` and a tombstone is durably recorded.

Delete intent precedence:

- delete intent wins any uncommitted finalization — a transactional version and state check prevents transition to `ready` after `delete_pending`;
- once `delete_pending` is durable, no body is served and reconciliation may only settle deletion or clean the body;
- a deletion retry operates on the same Artifact and tombstone identity and is idempotent.

The tombstone preserves safe lineage only:

- it records that a delete intent and outcome occurred, with safe actor, authority, timestamp, and reason evidence;
- it grants no body access — a tombstoned or deleted Artifact never becomes ready again;
- it prevents object-key and content-generation reuse, so a deleted body cannot be resurrected at the same key;
- retention and tombstone duration after deletion is a Gate 6 persistence decision, but it must preserve enough safe lineage to prevent accidental resurrection or object-key reuse.

## Recovery and reconciliation

At startup and during bounded reconciliation, Central examines durable Artifact records rather than treating bucket listing as authoritative. Object-store listing is never a lifecycle source of truth.

Reconciliation rules:

- a reserved or staging Artifact with a verified staged body may resume promotion and finalization only when reservation, owner, checksum, limits, and state are still valid;
- a staged body with a checksum or size mismatch is rejected and eventually cleaned;
- a crash after staging upload but before verification remains non-ready and cannot complete a Task;
- a crash during promotion or finalization creates durable reconciliation evidence; finalization is permitted only after ready-key integrity is proven by a second verification;
- an object with no valid reservation is an orphan candidate and is removed only after conservative age and prefix and ownership checks;
- a stale ready object lacking durable ready metadata is never silently adopted as ready;
- a pending deletion is retried idempotently; no body is served after durable delete intent;
- content-generation IDs are never reused, including after deletion.

Expiry and cleanup eligibility use durable, database-derived comparison time. Local wall-clock skew cannot make a reconciler prove expiry early or late. Gate 6 selects the query and representation.

Reconciliation is resumable and bounded:

- it runs at startup and at an installed bounded interval;
- each pass advances under cursor, batch, byte, and time budgets so normal command service continues between passes;
- a pass records its cursor so the next pass resumes without reprocessing;
- fairness to normal commands is preserved — reconciliation never starves reservation, upload, verification, finalization, or delivery;
- each pass records progress and backlog-age evidence: staging bytes, staging age, backlog age, cleanup failures, delete failures, quota denials, actor, and authority;
- stalled entries that exceed their budgets or age thresholds have an explicit operator-resolution path; reconciliation does not silently drop or force them.

Object-store unavailability before delivery may use the existing bounded `retry_delay` semantics when non-delivery is proven. Known uploaded-but-unfinalized state waits for reconciliation. Ambiguous delivery or promotion never causes a blind overwrite or a completion claim.

### Failure behavior

| Condition | Durable behavior | Completion or retry rule |
| --- | --- | --- |
| Size or checksum mismatch | Reject Artifact with structured integrity reason | No ready state; producer may create a new staging generation if policy permits |
| Limit or quota exhausted | Structured limit failure | No partial finalization or silent truncation |
| Unsafe or unknown content | Download-only classification, or reject when policy forbids storage | Never active preview |
| Upload proven not delivered | Persist known non-delivery | Bounded retry with a new staging generation when policy permits |
| Upload or promotion outcome ambiguous | Persist reconciliation evidence | Never overwrite or re-upload blindly |
| Required Artifact not ready | Existing Task or Run completion guard rejects completion | Resume or fail through accepted runtime semantics |
| Cross-Workspace access or mutation | Structured authorization denial | No read, delivery, finalize, or delete |
| Cleanup or delete outcome ambiguous | Preserve `delete_pending` and reconciliation evidence | No resurrection or body delivery |

## Cleanup

Cleanup removes only staging and orphan bodies. It never deletes a ready or finalizable Artifact.

Cleanup eligibility:

- a staging body whose reservation is older than the staging lifetime is eligible for cleanup;
- an orphan candidate — an object with no valid durable reservation or finalization relationship — is eligible only after conservative age and prefix and ownership checks;
- a `rejected` staging generation is eligible for cleanup after its structured failure is durably recorded;
- cleanup uses durable, database-derived comparison time so local clock skew cannot destroy a valid body.

Cleanup safety:

- cleanup never trusts object-store listing as authoritative;
- a stale ready object lacking durable ready metadata is never silently adopted as ready and never silently deleted as an orphan;
- cleanup releases the reservation exactly once and records the cleanup result with safe actor, authority, reason, and timestamp evidence;
- a cleanup or delete failure leaves the entry in `delete_pending` or reconciliation and preserves its evidence for retry;
- cleanup never reuses a staging generation or content generation.

## Observability

Safe observations include Artifact, Workspace, Task, Run, producer, staging generation, content generation, state transition, size bucket, checksum status, declared and detected content class, preview decision, limit result, retention action, cleanup reason, and correlation and causation IDs.

Required observations include:

- reservation admission, limits snapshot, and quota decision;
- staged upload start, stream-time cutoff, and known delivery or non-delivery;
- verification result, recomputed size, SHA-256 status, and classification decision;
- promotion result and second-verification result;
- finalization, completion guard update, and Event append;
- rejection reason and retry eligibility;
- delete intent, object deletion, tombstone creation, and delete failure;
- staging age, staging bytes, backlog age, cleanup result, quota denials, and operator-resolution events;
- reconciliation cursor, batch, byte and time budget, progress, and backlog-age evidence.

Source-boundary redaction occurs before data enters a generic error, Event, log, metric, or trace. Evidence excludes body content, secret material, raw filenames, unsafe key fragments, and unbounded labels. Logs, Events, metrics, and error surfaces repeat this prohibition: they record only opaque IDs, size buckets, classification decisions, and safe status, never plaintext bodies, secrets, original filenames, presigned URLs, or backend locators.

Suspected secret disclosure in a producer body blocks readiness and delivery and produces the existing sanitized revoke and rotate guidance; the contract does not continue merely after redaction.

## Validation scenarios

The following validation scenarios are owned by the Artifact lifecycle contract. They are validated in Phase 0 as contract walkthroughs and repository checks. Phase 1 implements them with fake object-store, clock, limits, and content-classification adapters plus failure injection.

| Scenario | Rule |
| --- | --- |
| A01 | A required verified Artifact finalizes once and permits the existing Task or Run completion guard. |
| A02 | A checksum or size mismatch never becomes ready; the staging generation is rejected with structured integrity reason. |
| A03 | A crash after upload before finalization reconciles without Task completion, completion claim, or overwrite. |
| A04 | A crash during promotion preserves immutable evidence and finalizes only after ready-key re-verification. |
| A05 | Expired staging and proven orphan cleanup never delete a ready or finalizable Artifact. |
| A06 | Cross-Workspace read, finalization, deletion, and key reuse fail closed with a structured authorization denial. |
| A07 | Object keys, metadata, Events, logs, metrics, and errors contain no secret material and no raw filename. |
| A08 | Active or unknown content is download-only with no MIME sniffing; eligible preview stays bounded and sanitized. |
| A09 | Quota exhaustion is structured and leaves no ready partial Artifact; capacity is released exactly once on rejection, cleanup, or deletion. |
| A10 | Delete intent prevents delivery and blocks uncommitted finalization; tombstone lineage prevents resurrection and content-generation reuse. |
| A11 | A replayed command with the same evidence returns its already-durable result with no duplicate Event, quota settlement, promotion, or completion transition. |
| A12 | A command with mismatched staging generation, ready key, content generation, checksum, or size fails closed with a structured mismatch failure and no transition. |
| A13 | Reservation admits staging bytes and count before upload, enforces stream-time cutoff, and settles atomically to verified size at finalization. |
| A14 | Reconciliation advances under cursor, batch, byte, and time budgets, records progress and backlog-age evidence, and preserves fairness to normal commands. |
| A15 | Stalled staging, orphan, cleanup, or delete entries have an operator-resolution path; reconciliation never silently drops or forces them. |
