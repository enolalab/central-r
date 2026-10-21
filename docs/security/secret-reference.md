# Phase 1 SecretReference Contract

## Authority and status

This document is the canonical Phase 1 SecretReference contract defined by the [approved Gate 2 security design](../internal/superpowers/specs/2026-07-13-phase-0-security-baseline-secret-reference-design.md), [local threat model](threat-model.md), and [capability policy](capability-policy.md). It becomes adopted architecture only after ADR 0003 is Accepted and Gate 2 validation passes. Phase 0 defines a backend-neutral contract and does not select or implement a secret backend.

The Gate 8 sections mapping `protected_file_v1` as the first concrete backend are documentary until and unless ADR 0009 is Accepted. They describe the security intent of the approved Gate 8 design — binding/generation lifecycle, broker callback, memfd use, dependency handoff, TLS signer, bootstrap presentation, rotation/revocation/deletion/tombstone, HMAC tokens, and no enumeration/raw reveal/backend locator — without claiming runtime enforcement or superseding ADR 0003's backend-neutral authority while ADR 0009 remains Proposed. Each Gate 8 subsection is marked **"effective only when ADR 0009 is Accepted."**

## Core invariants

- SecretReference is a stable, application-generated, opaque logical ID owned by exactly one Workspace.
- SecretReference is not a secret value, backend URI, environment-variable name, raw backend secret name, or human display label.
- Secret material remains outside PostgreSQL and S3-compatible Artifact storage.
- Protected configuration or another protected binding store maps the opaque ID to exactly one active backend and backend-native locator.
- Resolution occurs just in time inside a registered secret-aware adapter for one authorized operation.
- Plaintext is never returned to the model, agent, generic runtime, generic filesystem adapter, or generic process adapter.
- There is no raw reveal capability, name discovery, automatic backend discovery, or fallback value.
- Rotation preserves reference identity; revocation blocks every later resolution.
- Durable records contain only explicitly permitted metadata and safe audit evidence.

## Permitted durable metadata

| Field | Rule |
| --- | --- |
| SecretReference ID | Opaque application identity |
| Workspace ID | Required ownership and isolation scope |
| Display label | Mutable and non-sensitive; never authority or backend lookup input |
| Purpose | Non-secret declared use |
| Allowed adapter and target classes | Non-secret policy scope |
| Status | `active`, `revoked`, or operator-repairable `unavailable` |
| Opaque version or safe fingerprint | Backend-provided version preferred; never an unsalted hash of secret material |
| Timestamps | Created, rotated, revoked, and updated when applicable |

Permitted metadata may live in later normalized PostgreSQL state and append-only Events according to their owning specifications. It never includes the protected binding.

## Prohibited durable and agent-visible data

Central must not persist or expose:

- plaintext secret or a Central-managed recoverable ciphertext payload;
- backend URI, backend account, environment-variable name, or raw backend secret name;
- authentication header, provider token, private key, password, or credential fragment;
- unsalted or publicly guessable hash of secret material;
- secret value in Task input, prompt, model context, Event, checkpoint, log, metric, trace, URL, Approval, object key, Artifact body metadata, filename, error, or adapter result;
- a secret-bearing command argument, process environment, stdin stream, file, or inherited descriptor for a generic process.

If Central derives a fingerprint rather than receiving an opaque backend version, it uses a keyed construction with a protected audit key. The fingerprint must not support offline guessing of the secret.

## Protected backend binding

The binding from opaque SecretReference ID to backend and backend-native locator belongs to protected deployment configuration or another protected secret-binding store outside ordinary Task, Event, Approval, and Artifact persistence.

- Binding is explicit and selected by trusted configuration, never by agent content.
- One reference has one active binding at a time.
- Resolver selection is configuration, not request input.
- Label equality never selects or substitutes a reference.
- Missing binding fails closed and never triggers name discovery.
- The first protected local backend and exact binding format are decided by the security implementation specification owner before a resolver adapter implementation plan.
- The Gate 8 approved design selects `protected_file_v1` as the first concrete backend, with the root-owned socket-activated `central-protected-broker` as the sole resolver, mediated through sealed-memfd adapter callbacks and direct-tmpfs dependency handoffs. This selection is effective only when ADR 0009 is Accepted; the backend-neutral Gate 2 contract remains authoritative until then.

## Authorization context

A SecretReference resolver accepts only a complete authorization context containing:

- Workspace and Task IDs;
- current Run and operation identity where applicable;
- current policy version;
- SecretReference ID;
- registered secret-aware adapter identity;
- exact destination and purpose;
- effective grant or Approval evidence;
- normalized input or operation binding required by policy.

The resolver does not accept raw secret names from the model, agent, Task, tool input, or generic runtime.

## Resolve-and-use flow

1. Validate that the reference belongs to the operation's Workspace.
2. Validate reference identity, adapter, destination, purpose, and normalized operation binding.
3. Reevaluate grant expiry, revocation, Task state, current policy, and sensitivity.
4. Validate the reference is active and has exactly one configured protected binding.
5. Resolve the current backend version just in time inside the registered adapter boundary.
6. Use the value only for the authorized operation and destination.
7. Strip credential material from requests, responses, errors, traces, and adapter results before data leaves that boundary.
8. Minimize copies and lifetime, then clear mutable buffers best-effort after use.
9. Persist only opaque reference and safe version/fingerprint, result class, and sanitized reason.

Go and operating systems cannot guarantee perfect zeroization of every memory copy. The enforceable contract is minimized lifetime and copies, no durable plaintext, no generic-runtime return value, and no intentional exposure path.

## Secret-aware adapters

A secret-aware adapter owns protocol-specific credential use and never returns plaintext.

- Model-provider adapter may use only the provider reference selected for its exact provider destination and purpose.
- Database adapter may use only the registered database reference for its exact connection identity and purpose.
- A bounded HTTP integration may become secret-aware only after its destination and credential-use semantics are registered and reviewed.
- Generic filesystem and generic shell/process adapters are not secret-aware in Phase 1.
- Response reflection of a credential is stripped or becomes a security failure before reaching the runtime.
- `secret.use` authorizes credential use only; separately evaluated model, network, database, or data-egress authority is still required.

## Provider selection

Explicit authenticated provider selection establishes only:

- a bounded task-scoped `model_context × send` grant for that provider and declared Workspace resource scope;
- a bounded task-scoped `secret × use` grant for that provider adapter, provider destination, credential reference, and purpose.

Both grants expire no later than 24 hours after issuance and are reevaluated before use. Provider selection never creates generic network or generic secret authority.

Use of any other SecretReference requires explicit Approval bound to reference, adapter, destination, purpose, scope, policy version, and requested lifetime.

## Rotation

- Rotation changes the protected backend version while preserving the logical SecretReference ID.
- Existing grant remains eligible only when reference, adapter, destination, and purpose bindings are unchanged and current policy still allows use.
- Rotation does not require reapproval solely because opaque backend version changed.
- Every use records the current safe opaque version/fingerprint so audit can identify which rotation was used.
- Resolver never caches plaintext across an operation boundary merely to survive rotation.

## Revocation and deletion

- Revocation is checked at every later resolution and blocks use immediately.
- A Task already running cannot use a reference after revocation.
- Deletion removes the protected binding and retains only permitted opaque tombstone and audit lineage under the future retention policy.
- A revoked or deleted reference is never replaced by another reference with the same label.
- Historical Approval and audit evidence remain immutable but confer no effective authority after revocation.

## Failure behavior

| Condition | Durable behavior | Permitted continuation |
| --- | --- | --- |
| Reference missing, revoked, or binding unavailable and operator can repair intent or configuration | Existing `external_input` wait with sanitized condition | Resume only after explicit repair and full reevaluation |
| Approval missing or task grant expired | Existing `approval` wait | Resume only after new durable decision |
| Protected backend temporarily unavailable before use | Existing bounded `retry_delay` when resolution is known safe to retry | Retry the same reference and authorization context only |
| Policy, scope, Workspace, adapter, destination, or purpose mismatch | Structured denial | No retry without changed policy or explicit new action |
| Secret may have been disclosed | Structured security failure with revoke and rotate guidance | Do not continue merely because output was redacted |
| External operation outcome ambiguous after secret use | Existing `reconciliation` wait | Inspect or settle the same operation; never blind invoke |

No failure path uses an environment variable, Task field, similarly labeled reference, alternate backend, interactive plaintext reveal, or another credential.

## Durable audit evidence

Each resolution attempt records only applicable safe fields:

- Event or audit ID and timestamp;
- Workspace, Task, Run, ToolCall, and operation key references;
- actor and registered adapter;
- SecretReference ID and safe opaque version/fingerprint;
- destination class and declared purpose;
- policy version, effective grant or Approval reference;
- outcome and structured sanitized reason;
- retry or reconciliation correlation.

Required SecretReference event families include resolve success or failure, rotation, revocation, deletion, and secret-aware adapter invocation prepared, known success, known failure, ambiguous outcome, retry, and reconciliation.

Audit never stores secret value, backend locator, raw backend name, auth header, request body containing credential, reflected credential, or generic error text produced before source redaction.

## Validation contract

- Cross-Workspace reference use is rejected before backend resolution.
- Only the bound adapter, destination, and purpose resolve.
- Generic shell/process cannot consume or reveal a reference.
- Rotation preserves reference identity and records a new safe opaque version.
- Revocation blocks the next resolution during an active Task.
- Missing binding, transient backend failure, denial, and ambiguous effect map to the specified existing durable behavior.
- No failure attempts a fallback.
- Sentinel secret is absent from Task, prompt, model context, Event, checkpoint, log, metric, trace, Approval, URL, object key, Artifact metadata, and adapter-result fixtures.
- Resolution and use-time policy checks survive process restart from durable non-secret evidence.

## Concrete Backend: `protected_file_v1`

*This section is effective only when ADR 0009 is Accepted. It maps the abstract Gate 2 SecretReference contract to the Gate 8 concrete broker-mediated local filesystem backend.*

### Backend identity and ownership

`protected_file_v1` is a root-owned brokered local filesystem backend. The backend root is `/var/lib/central-protected/v1/instances/<instance-id>/` with mode `0700` owned by root. Neither the operator UID, `central-runtime`, `central-agent`, nor `central-browser` can traverse or enumerate this root.

The root-owned, socket-activated `central-protected-broker` process is the sole reader and writer of protected values. It is activated through a fixed `0600` Unix socket accessible only through one descriptor preopened for an authenticated `central-runtime` process. The broker has no network, Docker, shell, package, Workspace, arbitrary-path, or caller-executable authority and exits after a fixed idle deadline when no authenticated session or in-flight signing/use request exists.

### SecretReference logical-to-physical mapping

Each SecretReference logical identity maps to exactly one protected binding underneath the backend root at:

```text
/var/lib/central-protected/v1/instances/<instance-id>/secrets/<binding-id>/
```

The binding directory contains:

| Path | Purpose |
| --- | --- |
| `binding.json` | Opaque binding identity, purpose class, and safe metadata digest; no backend locator or secret value |
| `binding.lock` | Create-only lock file; present for the binding lifetime |
| `active.json` | Atomically replaced pointer to the current active generation |
| `candidates/<candidate-id>/<phase>.json` | Staged candidate generations with create-only phase journal |
| `generations/<opaque-generation>.{meta.json,value}` | Immutable generation metadata and the create-only secret value file (`0400`) |

The binding ID is an opaque UUIDv7. It is never derived from the SecretReference ID, display label, or backend URI. The operator, runtime, and agent receive only opaque binding IDs through the protected-broker protocol; they never receive backend paths.

### Generation lifecycle

Secret material enters the backend through a create-only, atomic-activation generation protocol:

1. **Candidate creation:** A new candidate generation is created as `candidates/<candidate-id>/prepared.json` with create-exclusive semantics. The candidate binds the SecretReference ID, binding ID, purpose class, creation nonce, and safe metadata digest. No secret value is present at this phase.

2. **Candidate staging:** The broker writes the secret value as `candidates/<candidate-id>/staged.json` containing the exact canonical secret bytes (base64url-encoded, bounded to `max_secret_bytes` from `central.config/v1`, default 65536). The file is `0400` root-only, create-exclusive, and synchronized before the phase advances.

3. **Candidate activation:** The broker atomically installs the generation as `generations/<opaque-generation>.meta.json` and `generations/<opaque-generation>.value` with `renameat2(RENAME_NOREPLACE)`. It then atomically replaces `active.json` to point to the new opaque generation. Activation is a committed broker authority transition; it never overwrites an existing generation.

4. **Candidate cleanup:** After `candidate_cleanup_age_ms` (default 24 hours) and proof of no active reference, the broker removes staged candidates that were never activated. Retired generations are eligible for removal after `retired_cleanup_age_ms` (default 7 days) and proof that no in-flight operation references them.

A generation whose candidate was created but never staged (prepared only) is an empty reservation; it is abandoned without a tombstone. A generation that was staged but never activated is cleaned after the candidate age expires. An activated generation is never modified; rotation or revocation creates a new generation and atomically updates `active.json`.

### Broker resolution callback and memfd use

When a secret-aware adapter (model-provider, database, or registered bounded HTTP integration adapter) requires a secret value, the runtime sends a closed typed resolution request through the authenticated broker session. The broker:

1. Revalidates the active protected pointer, binding lock, and authorization-use fence (Gate 3 fence deadline, effective-grant expiry, reference status, policy version).
2. Copies only the named bounded generation value to a sealed `memfd` with `MFD_CLOEXEC|MFD_ALLOW_SEALING` and applies `F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE`.
3. Transfers the sealed `memfd` descriptor to the authenticated runtime adapter through the broker session.
4. Destroys its own broker buffer best-effort.

The adapter inherits no directory descriptor or broker-root descriptor. It reads the value from the sealed `memfd`, uses it for exactly one authorized operation, then clears and closes the `memfd`. The runtime never receives plaintext; the callback scope is non-transferable.

### Dependency secret handoff

When a dependency container (PostgreSQL, MinIO, or their provisioners) requires a secret, the helper and broker mutually authenticate the exact operation and embedded service policy. The helper supplies a create-only destination descriptor beneath `/run/central-infra/<instance-id>/secrets/` (host tmpfs, root-owned). The broker validates the active protected pointer before and after writing, resolves only the exact active dependency-secret purpose/generation, writes the bounded value directly to that descriptor without exposing its protected root or plaintext to the operator controller, clears transient buffers best-effort, and records safe HMAC-version evidence.

Each resulting file is `0400`, owned by the locked numeric UID/GID of exactly one consuming service, and bind-mounted read-only to one fixed in-container `_FILE` path. The helper never receives the secret value, cannot enumerate another binding, and cannot request a secret for an unregistered purpose or service.

### TLS private-key signing (`crypto.Signer`)

The broker owns the instance CA private key and leaf private key as separate protected generations under `/var/lib/central-protected/v1/instances/<instance-id>/tls/`. These keys are never resolved as plaintext by `central serve`.

TLS handshakes use the broker's leaf-only `crypto.Signer` operation: the runtime passes the digest to be signed through the authenticated broker session; the broker signs with the locked leaf key and returns only the signature. The CA key signs only the fixed offline leaf-rotation object (a structured certificate signing request with exact instance/binding/fingerprint constraints) and never signs an arbitrary digest or leaves the broker.

Leaf rotation is a lifecycle-exclusive operation: stage and sign a new leaf under the active CA, validate key/certificate/instance linkage and validity, atomically activate the new leaf generation through the broker transition journal, and retain exact repair evidence. CA rotation stages a new CA and leaf, installs the new public anchor before activation, verifies the trust receipt, atomically activates both, and only then allows explicit removal of the old anchor.

### Bootstrap presentation

The bootstrap token is a protected generation under `/var/lib/central-protected/v1/instances/<instance-id>/bootstrap/`. After fresh PAM authentication and ready-server proof, the broker rotates and writes exactly one presentation generation directly to the helper-owned TTY through `bootstrap show`. The helper and controller never receive the plaintext token. The token has a three-minute presentation window. It never appears in URL, referrer, log, Event, controller JSON, audit, or any operator-writable file.

### Rotation

Rotation preserves the logical SecretReference binding ID while creating a new generation:

1. Broker creates a new candidate, stages the new secret value, and verifies the candidate against the binding lock.
2. Broker atomically activates the new generation and updates `active.json`.
3. The prior generation becomes a retired generation, eligible for cleanup after `retired_cleanup_age_ms`.
4. Every use records the current safe opaque generation version token so audit can identify which rotation was used.
5. Existing grants remain eligible when reference, adapter, destination, and purpose bindings are unchanged and current policy still allows use.
6. Rotation does not require reapproval solely because the opaque generation version changed.
7. Container secret handoff requires dependencies stopped; the next `local up` rematerializes only the new active generation.

### Revocation

Revocation creates a committed broker transition that marks the binding as revoked. The `active.json` pointer is replaced with a tombstone record. Every later resolution fails closed. A Task already running cannot use the reference after revocation. Revocation blocks every dependency handoff, memfd use, and TLS signing request for the binding.

### Deletion and tombstone

Deletion removes the protected binding directory after:

1. The binding is first revoked (above).
2. Every in-flight memfd handle for the binding is proven closed or expired.
3. No dependency container holds a secret-handoff mount for the binding.
4. Every historical audit reference to the binding is beyond the required retention window.

After deletion, only the permitted opaque tombstone remains in the audit lineage: binding ID, deletion timestamp, deletion operation ID, and safe prior-generation version tokens. The tombstone contains no secret value, backend locator, or raw backend name. A deleted binding ID is never reused.

### HMAC fingerprint and authority tokens

Protected-value fingerprints use the broker's separate HMAC key (stored at `/var/lib/central-protected/v1/instances/<instance-id>/fingerprint-keys/<key-version>.key`) rather than raw secret digests. The HMAC key is domain-separated from view-signing and authority-journal keys.

Every authoritative transition (secret generation, rotation, revocation, deletion, TLS leaf rotation, and bootstrap presentation) is a committed journal entry with a chained broker-HMAC envelope under `authority/journals/<stream-id>/<sequence>/<transition-id>/`. The envelope contains transition/stream IDs, monotonic sequence, canonical payload digest and byte count, prior committed envelope digest, instance, authenticated launch ID, closed protocol phase, one-use nonce, broker key version, and domain-separated HMAC.

### Prohibited operations

The broker rejects:

- **Enumeration:** No request can list secret bindings, generation IDs, or candidate IDs. The caller must name the exact binding ID known from a prior authorized operation.
- **Raw reveal:** No request returns a plaintext secret to the runtime, agent, model, helper, controller, or any caller. Plaintext is confined to sealed memfds (adapter use) or direct tmpfs descriptors (dependency handoff).
- **Backend locator:** No request returns a filesystem path, inode number, or backend-native name. The broker operates on held descriptors; the caller never receives a pathname or directory descriptor.
- **Cross-purpose use:** A binding registered for purpose `postgres_runtime_v1` cannot be resolved for purpose `minio_runtime_v1` or `application_tls_v1`.
- **Unregistered purpose:** A binding purpose not present in the helper/broker mutually embedded policy is denied before resolution.

### Workspace-scoped application secrets

Workspace-scoped application secrets (provider API keys, database credentials selected by an operator for a specific Workspace Task) use the same `protected_file_v1` backend and broker protocol but are registered with purpose classes distinct from instance/system credentials:

| Purpose class | Scope | Examples |
| --- | --- | --- |
| `postgres_server_admin_v1`, `postgres_runtime_v1`, `postgres_outbox_v1`, `postgres_migration_v1` | Instance | Central's own PostgreSQL roles |
| `minio_root_v1`, `minio_runtime_v1`, `minio_backup_v1`, `minio_restore_v1` | Instance | Central's own MinIO identities |
| `application_tls_v1` | Instance | CA and leaf private keys |
| `bootstrap_v1` | Instance | Bootstrap presentation token |
| `provider_api_key_v1` | Workspace | Operator-selected model-provider credential |
| `workspace_database_v1` | Workspace | Operator-selected database credential for a Workspace Task |

Instance/system credentials are created during `local init` and `local up` provisioning; they are never exposed through the SecretReference application API. Workspace-scoped secrets are created through the operator's authenticated browser session and follow the full Gate 2 resolve-and-use flow with per-operation authorization-use fencing. Both classes share the same broker resolution protocol, memfd/dependency-handoff delivery, and HMAC-journaled transition evidence, but their binding purposes and authorization contexts are distinct across every policy check.

### Concrete binding format

The protected binding stored in `binding.json` under each secret directory contains only:

| Field | Content |
| --- | --- |
| `binding_id` | Opaque UUIDv7 |
| `secret_reference_id` | The stable Gate 2 SecretReference logical identity |
| `purpose_class` | Exact enum from the table above |
| `instance_id` | Owning instance UUIDv7 |
| `workspace_id` | `null` for instance credentials; non-null UUIDv7 for Workspace-scoped secrets |
| `max_bytes` | Inherited from `central.config/v1 protected_store.max_secret_bytes` |
| `created_at` | UTC RFC 3339 with microseconds |
| `created_by_operation_id` | The init, provision, or secret-creation operation that created this binding |

It never contains a secret value, backend path, backend locator, environment-variable name, or raw backend secret name. The binding is readable by root only; the broker resolves it internally from its held root descriptor.

## Follow-up ownership

| Decision | Owner | Due | Blocks |
| --- | --- | --- | --- |
| First protected local secret backend and binding format | Security implementation specification owner | 2026-07-20 | Secret resolver adapter implementation plan |
| Resolver and secret-aware adapter Go/API protocol | Gate 3 runtime specification owner | 2026-07-20 | Provider and database adapter implementation plans |
| SecretReference tombstone and audit retention | Persistence and security specification owners | 2026-07-20 | Security schema and cleanup implementation plan |
| `protected_file_v1` broker protocol, sealed-memfd delivery, and dependency-handoff contract | Broker security specification owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice A host-authority foundation |
| TLS `crypto.Signer` leaf operation, CA offline rotation, and trust-install integration | TLS/broker security specification owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice B first safe runnable environment |
| Bootstrap presentation generation, TTY-only reveal, and three-minute window | Bootstrap/broker security specification owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice B first safe runnable environment |
| HMAC fingerprint-key domain separation, authority-journal chaining, and checkpoint compaction | Broker authority-journal owner | 2026-07-20 (documentary; effective only when ADR 0009 is Accepted) | Gate 9 Slice A host-authority foundation |
