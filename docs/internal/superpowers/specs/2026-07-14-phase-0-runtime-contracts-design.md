# Phase 0 Runtime Contracts Design

- **Status:** Approved
- **Approved:** 2026-07-14
- **Date:** 2026-07-14
- **Phase:** Phase 0 — Architecture and foundations
- **Program gate:** Gate 3 — Runtime contracts
- **Implementation target:** Phase 1 — Local Central MVP

## Context

Gate 1 established the durable Task, Run, Step, attempt, ToolCall, Approval, Checkpoint, Artifact, and Event model. Gate 2 established the local trust boundary, capability policy, and SecretReference contract. Gate 3 must now define how a single local runtime advances that durable state without inventing Phase 2 scheduling, exposing secret values, or letting infrastructure adapters own business rules.

Phase 1 executes one durable Agent Task through a sequential model-and-tool loop. It must survive restart, wait durably for Approval or external input, preserve every attempt, reconcile ambiguous effects, enforce finite budgets, and complete only after required Artifacts and final state are durable.

Related decisions and contracts:

- [ADR 0001 — durable Task domain and lifecycle](../../../adr/0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0003 — security policy and SecretReference model](../../../adr/0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [approved domain and lifecycle design](2026-07-12-phase-0-domain-lifecycle-design.md)
- [Phase 1 threat model](../../../security/threat-model.md)
- [capability and Approval policy](../../../security/capability-policy.md)
- [SecretReference contract](../../../security/secret-reference.md)
- [durable execution overview](../../../architecture/durable-execution.md)
- [Phase definitions](../../../product/phases.md)

## Objective

Define implementation-neutral runtime semantics so Phase 1 can implement one local Agent, one sequential execution loop, registered provider and tool adapters, safe Checkpoints, and restart recovery without changing the accepted domain or security meanings.

The design succeeds when:

- runtime coordination never bypasses a domain transition service;
- provider and tool invocations have persisted intent before external delivery;
- every privileged operation is authorized and revalidated at use time;
- plaintext secrets remain inside an exact secret-aware adapter operation;
- retries distinguish known-safe failures from ambiguous delivery;
- Checkpoints resume known completed work without replaying effects;
- local execution ownership supports restart recovery without becoming a Phase 2 Worker scheduler;
- every execution path has finite time, call, token, output, and spend bounds;
- Phase 1 cannot create a Subagent, child Task graph, or parallel invocation.

## Phase boundary

This is a design-only Phase 0 contract. It does not create Go packages, API payloads, SQL, migrations, Docker configuration, adapters, runtime enforcement, or executable tests.

### In scope

- AgentDefinition and Subagent meaning;
- runtime coordinator responsibilities;
- provider and tool semantic request, attempt, and outcome contracts;
- authorization, effective-grant, Approval, and SecretReference handoffs;
- Checkpoint creation, compatibility, and resume rules;
- one local executor's ownership, lease, heartbeat, cancellation, and recovery behavior;
- retry, timeout, concurrency, output, token, and spend defaults;
- failure taxonomy, observability requirements, and design validation scenarios;
- ownership boundaries for Gates 4–8.

### Out of scope

- persisted Workflow graphs, child Task edges, executable Subagents, fan-out, or parallel work;
- multi-worker registration, scheduling, fairness, remote leases, or capability advertisement;
- plugin discovery, arbitrary extensions, MCP transport, or public SDKs;
- concrete Go interfaces, package paths, database representation, JSON, HTTP, or Event schemas;
- provider-specific wire formats or the first protected secret backend;
- executable sandboxing or claims that Gate 2 controls are implemented;
- Central Server, Online Mode, LAN access, RBAC, or multi-user identity.

## Approaches considered

### Selected: staged semantic runtime contract

One sequential runtime coordinator advances accepted domain state through distinct semantic roles for provider invocation, tool invocation, authorization, checkpointing, and local execution ownership. Every external boundary has a prepare, invoke, and persist-outcome sequence.

This adds explicit contracts but provides test seams, preserves domain-owned interfaces, and lets Gates 5–7 define serialization, persistence, and Go realization without changing meaning.

### Rejected: monolithic runtime facade

One facade owning the loop, policy, providers, tools, Checkpoints, and persistence would have a smaller initial surface. It was rejected because it conflates authority and execution, leaks infrastructure into business rules, and makes provider, tool, and recovery behavior difficult to test independently.

### Rejected: command and Event bus first

Durable commands delivered to independent provider and tool workers would prepare for distributed execution. It was rejected because acknowledgements, delivery ordering, remote Worker semantics, and asynchronous routing belong to Gate 5 or Phase 2 and are unnecessary for one local Phase 1 runtime.

## Core decisions

1. Phase 1 has one sequential runtime coordinator and at most one active external invocation.
2. AgentDefinition is immutable versioned configuration, not a new durable aggregate.
3. Subagent is not a Phase 1 executable type. Child Tasks and Agent relationships begin in Phase 2.
4. Runtime requests domain commands; it never writes lifecycle state directly.
5. Provider-attempt evidence belongs to StepAttempt and does not create another aggregate or lifecycle family.
6. Ordered provider tool proposals execute one at a time.
7. A policy decision or caller Boolean is not authority. Registered adapters acquire a single-use authorization fence that linearizes exact revalidation, secret resolution, and external delivery against revocation and policy mutation.
8. SecretReference plaintext is resolved and consumed only inside the exact authorized secret-aware adapter operation.
9. Checkpoints are immutable, verified continuation evidence created only at known-safe boundaries.
10. Phase 1 execution ownership is one local expiring lease. It is not a Worker registry or scheduler.
11. Known-safe transient failures use bounded persisted retry. Ambiguous delivery enters reconciliation and is never automatically reinvoked.
12. Every Run has finite resource budgets and structured exhaustion; no security-relevant content is silently truncated.

## Vocabulary and ownership

| Term | Gate 3 meaning | Owner |
| --- | --- | --- |
| AgentDefinition | Immutable revision containing provider/model selection, instruction and context policy references, registered tool set, execution policy, budgets, and required output declarations. It contains no secret value. | Runtime semantic contract |
| AgentDefinition revision | Stable ID plus immutable revision. A Run records the exact revision and resolved configuration references it uses. | Runtime semantic contract |
| Subagent | A future AgentDefinition selected for a Phase 2 child Task. Phase 1 exposes no spawn command, child edge, dependency, or Subagent tool. | Reserved for Phase 2 |
| Runtime coordinator | Application-level coordinator that interprets untrusted provider results and invokes domain commands and registered ports. | Runtime semantic contract |
| Provider adapter | Registered secret-aware adapter for one configured provider destination and model family. | Provider boundary |
| Tool adapter | Registered adapter for one versioned tool identity and declared capability envelope. | Tool boundary |
| Executor | One process-local instance that holds persisted expiring ownership while advancing a Run or Step. | Local runtime boundary |
| Provider attempt | Immutable prepare/outcome evidence attached to one StepAttempt. It is not an aggregate. | StepAttempt evidence |
| Checkpoint | Immutable verified continuation evidence for completed logical work and the next safe action. | Checkpoint domain |

Agent instructions, provider output, tool proposals, tool results, repository content, and Artifact content remain untrusted data. They may propose actions but cannot select adapters, change policy, grant capability, or alter registered definitions.

## AgentDefinition contract

An AgentDefinition revision declares:

- opaque definition ID and immutable revision;
- provider profile and model identity;
- instruction and context-policy references;
- permitted versioned tool definitions;
- execution-policy and budget profile references;
- required output declarations and their completion role;
- compatibility range understood by the runtime;
- non-secret provenance and creation metadata.

A Run snapshots the selected revision and resolved version identities before execution. Changing instructions, provider, tool expansion, budgets, or output requirements creates another revision or Run policy snapshot; it never silently changes an active Run.

Definitions reference SecretReference IDs only through trusted provider or integration configuration. They never contain plaintext, backend locators, raw secret names, or environment-variable names.

## Sequential execution flow

1. A local executor atomically claims the queued Run and persists ownership.
2. Runtime selects or creates one logical Step and begins one StepAttempt through its owning domain service.
3. Runtime rebuilds context from normalized Task input, safe prior outputs, ready Artifacts, the exact AgentDefinition revision, and an optional valid Checkpoint.
4. Runtime constructs the complete provider egress and credential-use requests.
5. Policy evaluates them; required durable decisions and grants commit before delivery.
6. Runtime persists provider-attempt preparation evidence on the StepAttempt.
7. The provider adapter revalidates authority, resolves its SecretReference inside its boundary, and invokes the provider outside any PostgreSQL transaction.
8. Runtime validates the untrusted response and persists a sanitized outcome, usage, safe references, failure, cancellation, or ambiguity.
9. A final response advances required-output production and completion guards.
10. Ordered tool proposals become ToolCalls in provider order and execute one at a time through the ToolCall lifecycle.
11. Known tool results or safe Artifact references become subsequent context only after persistence.
12. The loop stops on final result, durable wait, cancellation, terminal failure, reconciliation, or exhausted budget.
13. Task completion still requires every required Artifact to be ready and verified and completion state plus Events to commit atomically in PostgreSQL.

A Step is a logical resumable unit, not necessarily one model turn. A StepAttempt may contain several sequential provider turns and ToolCalls, but never more than one active external invocation. Checkpoints mark safe progress inside that logical work.

## Provider semantic contract

### Request envelope

A provider request semantically contains:

- Workspace, Task, Run, Step, and StepAttempt identities;
- stable provider-operation identity, unique physical provider-attempt identity, and canonical context hash;
- AgentDefinition ID and revision;
- provider and model identities;
- a context manifest of references, hashes, Workspace scope, and sensitivity;
- model-context egress decision and provider `secret.use` evidence;
- remaining time, call-count, token, output, and spend budgets;
- timeout and cancellation signal;
- correlation and causation identities.

Gate 3 owns these meanings. Gate 5 owns any serialized field names and versioning; Gate 7 owns Go types and adapter interfaces.

### Attempt evidence and outcomes

Preparation evidence commits before network delivery and records safe request identity, authorization references, timeout, budget reservation, and correlation. It never stores unrestricted prompt bodies or secret material.

Provider-operation identity is stable for one logical provider turn within one Step and Run. It is scoped by Workspace, Task, Run, Step, logical turn, AgentDefinition revision, and canonical context hash. A known-safe physical retry keeps that operation identity and creates a new globally unique provider-attempt identity. Reusing an operation identity with another context hash is rejected, and a new Run always creates another operation identity.

Provider-attempt evidence has exactly one immutable terminal outcome after `prepared`: `succeeded`, `known_failed`, `cancelled`, or `ambiguous`. These are StepAttempt evidence values, not another aggregate or public lifecycle family.

The adapter returns exactly one semantic outcome:

- completed response;
- completed response with ordered tool proposals;
- known retryable failure with proven non-delivery or no external effect;
- known terminal failure;
- cancellation with known non-delivery;
- ambiguous delivery or outcome.

A known retryable provider failure records `known_failed`, ends the current StepAttempt with failed evidence, and may place Step/Run/Task in `retry_delay`; eligibility creates a new StepAttempt and provider-attempt identity under the same logical provider operation. A known terminal provider failure fails the Step and parent execution according to policy. Known cancellation records cancelled attempt evidence and follows the accepted cancellation settlement. A successful provider result remains durable evidence inside the active StepAttempt until its next safe Step boundary.

Provider response and proposed tools remain untrusted. Provider ambiguity maps to the accepted Step lifecycle as follows:

1. Mark the provider attempt `ambiguous` and end its current StepAttempt with immutable `ambiguous` evidence.
2. Move Step, Run, and Task to existing waiting reason `reconciliation`, referencing provider operation and attempt identities.
3. A confirmed response appends reconciliation evidence and a safe response reference, then requeues the same Step and Run. A new StepAttempt consumes that response without invoking the provider again.
4. Confirmed non-delivery appends no-effect evidence, requeues the same Step and Run, and permits a new StepAttempt to make a policy-controlled physical attempt under the same provider-operation identity and context hash.
5. A still-unknown outcome remains waiting by default and is never automatically resent.
6. To terminate instead of waiting indefinitely, explicit operator input or installed policy records `terminalize_unknown` reconciliation evidence. That evidence states that outcome remains unknown, forbids another external delivery, and permits `RequeueStep` only for terminalization. The newly claimed StepAttempt invokes no provider, ends `failed` with reason `unresolved_provider_outcome`, and then satisfies the existing `FailStep` guard so Run and Task can fail consistently.

Reconciliation never rewrites the ambiguous StepAttempt. `FailStep` is used only after a later no-delivery terminalization StepAttempt has itself ended `failed`.

## Tool definition and invocation contract

A versioned tool definition declares:

- stable tool and adapter identities;
- semantic input and result schemas;
- capability-derivation rules;
- support for operation-key delivery and outcome lookup;
- default timeout, input, output, and response limits;
- safe structured result fields and Artifact-producing behavior;
- reconciliation support and known failure classifications.

Invocation follows the accepted lifecycle:

1. Canonicalize tool identity and semantic input.
2. Compute normalized input hash and stable in-Run operation key.
3. Create ToolCall and derive every composed capability.
4. Persist the canonical authorization request and decision.
5. On `require_approval`, create Approval and durable `approval` wait atomically.
6. After Approval or grant resolution, perform preliminary eligibility revalidation for input, scope, policy, Task state, sensitivity, adapter, destination, purpose, and SecretReference state.
7. Persist a prepared ToolCallAttempt before external delivery.
8. Acquire the authorization-use fence and resolve any SecretReference inside the registered adapter boundary.
9. Invoke the registered adapter outside the transaction while the fence covers request handoff.
10. Persist known success, known failure, safe retry wait, cancellation evidence, or reconciliation.

A model or tool cannot provide an `allow` flag, authorization token, adapter identity, or fallback SecretReference. Unknown tools, versions, capability derivations, or failure classes fail closed.

## Idempotency and reconciliation

- ToolCall operation key is stable across StepAttempts in one Run and changes for another Run.
- Reusing the key with a different normalized input hash is a domain error.
- Every physical delivery receives another immutable ToolCallAttempt.
- A prepared attempt commits before delivery.
- Proven non-delivery permits a policy-controlled known-safe retry.
- Possible delivery with unknown outcome enters `reconciliation`; another invocation is forbidden.
- Reconciliation can record confirmed success, confirmed failure with no effect, or still unknown.
- Adapters pass the operation key to external systems that support idempotency and use it for outcome lookup when supported.
- Provider attempts use their own immutable invocation identity and StepAttempt evidence; they do not reuse ToolCall operation keys.
- Lease expiry, timeout, process loss, or cancellation signal alone never proves an external operation failed.

## Authorization and secret-aware handoff

1. Runtime proposes a complete canonical capability request; it grants nothing.
2. Policy persists a decision reference bound to Workspace, Task, Run, operation, normalized input, capability, scope, sensitivity, adapter, destination, purpose, policy version, and SecretReference IDs.
3. Approval remains immutable history; an effective grant is separate expiring authority.
4. After the external attempt is durably prepared, the adapter requests a single-use authorization-use fence for the exact operation.
5. Successful use-fence acquisition after durable revalidation is the use linearization point against grant revocation, policy tightening, SecretReference revocation, or Task termination.
6. The adapter receives a non-serializable, non-transferable callback scope, not an agent-visible bearer token or caller Boolean.
7. A secret-aware adapter resolves the SecretReference and hands the external request to its transport inside that callback scope while the fence remains held.
8. Mutation paths acquire the exclusive side of the same logical fence and hold it through their durable commit. Successful commit is the mutation linearization point. If mutation commits first, later use fails closed; if use linearizes first, that one already-prepared request may be handed off, and the mutation then blocks every later use. A failed mutation commit releases its fence without changing authority.
9. The fence is released immediately after transport proves non-delivery or accepts the request for delivery; it is not held while waiting for a response.
10. Only the adapter receives the transient value and only for the exact operation. Runtime receives safe opaque version/fingerprint, structured outcome, and sanitized reason.

The fence exists only inside the trusted local process. Its handoff deadline is the earliest of the configured authorization-use fence duration, the effective-grant expiry, a stricter reference/policy deadline, or the attempt deadline. If transport has not accepted the request by that point, the callback aborts with known non-delivery. A process crash releases the fence; recovery then treats the prepared attempt as ambiguous unless transport evidence proves non-delivery.

If revalidation, fence acquisition, or secret resolution fails after preparation but before delivery, the adapter records `delivery=not_started` and a known non-delivery outcome. A provider attempt becomes `known_failed`; a ToolCallAttempt becomes `failed`; the current StepAttempt ends with failed evidence. Expired authority creates the existing durable `approval` wait; an operator-repairable secret condition uses `external_input`; a known-safe resolver outage may use `retry_delay`; denial or binding mismatch fails according to policy. Any later resume creates a new StepAttempt and physical attempt after full revalidation.

Generic filesystem and shell/process adapters remain unable to resolve or receive a SecretReference. `secret.use` never implies network, database, model-context, or other data authority.

## Checkpoint contract

A Checkpoint records:

- immutable Checkpoint ID and schema version;
- producer identity/version and supported reader range;
- Workspace, Task, Run, Step, and producing StepAttempt identities;
- completed logical work and next safe action;
- ready Artifact references and relevant operation evidence;
- AgentDefinition revision and policy/configuration compatibility fingerprints;
- SHA-256 integrity checksum and creation time;
- compact payload up to 256 KiB or one Artifact reference for larger continuation state.

Rules:

- Checkpoints contain no plaintext secret, unrestricted provider/tool body, or ambient process state.
- A later boundary creates another Checkpoint; prior evidence is immutable.
- A Checkpoint commits only after all preceding effects have known durable outcomes.
- No Checkpoint crosses an unresolved ambiguous operation.
- Resume verifies ownership, checksum, reader/producer compatibility, AgentDefinition and policy compatibility, Artifact readiness, and operation evidence.
- A supported migration creates new verified continuation evidence and preserves the source Checkpoint.
- Corrupt or incompatible Checkpoints fail safely with an actionable structured reason. Runtime does not silently restart completed work.

## Local executor and ownership

- Process startup generates a fresh executor-instance UUID.
- Claiming Run/Step state and recording ownership are atomic.
- Only the current owner may advance actively running work.
- A durable wait releases ownership; requeued work needs another claim.
- Heartbeat renewal changes only lease freshness, never an external-effect outcome.
- Graceful shutdown stops new claims first, persists safe progress, and releases ownership only when no unrecorded invocation exists.
- Startup recovery scans stale ownership and uses persisted Checkpoints, attempts, retries, cancellation, and operation evidence.
- Phase 1 has no durable Worker registry, competing-worker fairness, remote heartbeat protocol, or capability advertisement.

Initial values are normative Phase 1 defaults:

| Control | Default |
| --- | --- |
| Ownership lease | 30 seconds |
| Heartbeat interval | 10 seconds |
| Expiry/recovery grace | 5 seconds |
| Concurrent Runs per local runtime | 1 |
| Active StepAttempts per Run | 1 |
| Active external invocations | 1 |

Gate 6 must use a database-derived comparison time for ownership decisions so local wall-clock skew cannot make a caller prove expiry.

## Retry and resource budgets

| Control | Default | Phase 1 hard maximum | Scope |
| --- | --- | --- | --- |
| Known-safe transient physical attempts | 3 total attempts | 5 total attempts | Per logical provider operation or ToolCall in one Run; StepAttempt retry does not reset it |
| Backoff | Exponential, 1-second base, 30-second cap, full jitter in `[0, bound]` | Base at most 5 seconds and cap at most 5 minutes | Per known-safe physical retry series |
| Automatic whole-Run retry | 0 | 0 | Phase 1 uses explicit retry to create a new Run |
| Authorization-use fence | 5 seconds | 10 seconds | Per secret resolution and external request handoff; never past authority expiry |
| Provider-call timeout | 5 minutes | 15 minutes | Per physical provider attempt and remaining Run time |
| Ordinary tool-call timeout | 2 minutes | 30 minutes | Per physical ToolCallAttempt and remaining Run time |
| Provider turns | 50 | 100 | Logical provider operations per Run; physical retries do not add turns |
| ToolCalls | 50 | 100 | Logical ToolCalls per Run; physical retries do not add ToolCalls |
| Run wall-clock budget | 60 minutes | 24 hours | Per Run, including waits only when policy declares them chargeable |
| Cumulative provider input tokens | 500,000 | 2,000,000 | Sum across every physical provider attempt in one Run |
| Cumulative provider output tokens | 50,000 | 200,000 | Sum across every physical provider attempt in one Run |
| Spend ceiling | USD 5 | USD 25 | Reserved and accounted per Run using versioned conservative price data |
| Provider response | 4 MiB | 8 MiB | Per physical provider response before sanitization |
| Tool request | 256 KiB | 1 MiB | Canonical semantic request; larger inputs use Artifact references |
| Inline sanitized tool result | 64 KiB | 256 KiB | Per ToolCallAttempt result returned to runtime context |
| Buffered tool-result body before Artifact handoff | 16 MiB | 64 MiB | Per ToolCallAttempt; larger bodies require Gate 4 streaming Artifact behavior |
| Inline Checkpoint payload | 256 KiB | 1 MiB | Per Checkpoint; larger state uses an Artifact reference |

Installed policy may choose a value at or below each hard maximum; adapters may impose stricter values. A value above a hard maximum is rejected. Changing a hard maximum is a material Gate 3 contract change and requires ADR review. Gate 4 may impose stricter Artifact object or staging limits.

The 16 MiB bound limits data buffered as a tool result; it is not a maximum ready-Artifact size. A registered Artifact-producing tool may stream a larger body through Gate 4's bounded upload contract while returning only safe metadata and an Artifact reference.

A paid hosted-provider request fails closed when its versioned price data is missing or stale; it never falls back to token-only monetary accounting. A local non-metered provider profile may explicitly declare zero external provider spend, while token and call ceilings still apply.

Retry occurs only for a classified known-safe failure. “Total attempts” includes the initial physical attempt. Ambiguous delivery consumes a physical attempt but never authorizes another one. Every counter, budget reservation, failure class, and next-eligible timestamp is durable. A new Run gets new logical identities and budgets; a StepAttempt retry inside one Run does not reset them. `Retry-After` may increase a delay only within the remaining Run and installed-policy bounds.

Token and spend reservations commit before provider delivery and settle from sanitized usage evidence. When an ambiguous provider attempt has no usage evidence, its conservative reservation remains charged until reconciliation proves non-delivery or supplies authoritative usage.

Budget exhaustion is a structured terminal Run failure. It does not add a lifecycle status or waiting reason. A user may explicitly retry the failed Task with a new Run and newly validated policy. Limit violations never silently truncate security-relevant decisions, authority context, errors, or audit evidence.

## Cancellation and restart

Cancellation is persisted before signaling active provider or tool work. After the durable request, runtime starts no new StepAttempt, provider attempt, or ToolCallAttempt.

- Proven non-delivery records cancellation.
- Known success or failure records the actual outcome before cancellation settles.
- Possible delivery records ambiguity and reconciles before terminal cancellation.
- Prior attempts and Checkpoints remain immutable.
- Restart rebuilds from PostgreSQL and verified Artifact or Checkpoint references, never process memory.
- Recovery revalidates policy, grant, Approval, sensitivity, AgentDefinition, adapter, and SecretReference state.
- Completion remains blocked until required Artifacts and final state satisfy ADR 0001.

## Failure taxonomy

| Class | Runtime behavior |
| --- | --- |
| Invalid definition, input, schema, or compatibility | Reject before side effect or fail deterministically |
| Permission denial | Record denial; invoke nothing |
| Approval or grant renewal required | Existing durable `approval` wait |
| Operator-repairable reference or configuration | Existing durable `external_input` wait |
| Known-safe transient infrastructure/provider/adapter failure | Bounded persisted `retry_delay` |
| Ambiguous delivery or effect | Existing durable `reconciliation` wait; no reinvocation |
| Budget or hard limit exhausted | Structured terminal failure |
| Cancellation | Persist, signal, settle known or ambiguous outcome, then cancel |
| Incompatible or corrupt Checkpoint | Structured failure or explicit new-Run action; never silent replay |
| Suspected secret disclosure | Structured security failure with revoke/rotate guidance; do not continue merely after redaction |

## Observability contract

Runtime evidence includes safe correlation, causation, Workspace, Task, Run, Step, attempt, ToolCall, operation, executor, provider, model, tool, and adapter identities where applicable.

Required observations include:

- lifecycle transition and waiting reason;
- provider/tool attempt preparation and outcome class;
- retry class, count, delay, and next eligibility;
- lease acquisition, heartbeat, expiry detection, and recovery decision;
- Checkpoint creation, compatibility, migration, and resume result;
- Approval/grant revalidation and sanitized authorization outcome;
- model calls, tokens, duration, and spend;
- tool calls, duration, request/result size, and Artifact handoff;
- cancellation latency, ambiguous operations, reconciliation age, and budget exhaustion.

Source-boundary redaction occurs before data enters a generic error, Event, log, metric, or trace. Evidence never includes plaintext secrets, bootstrap/session tokens, raw authorization material, unrestricted prompt/tool/Artifact bodies, command environments, or unbounded user-controlled labels. Gate 5 owns Event names, serialized payload fields, and outbox delivery.

## Cross-gate ownership

| Concern | Owning gate | Gate 3 handoff |
| --- | --- | --- |
| Runtime roles, operations, outcomes, limits, and recovery meaning | Gate 3 | Normative here |
| Artifact thresholds, staging, finalization, retention, and object recovery | Gate 4 | Consume Artifact handoff and completion barrier |
| External API/config serialization, Event names/payloads, schema versions, and outbox | Gate 5 | Serialize these semantic envelopes without changing meaning |
| Tables, constraints, transaction/locking, lease-time query, and repository mapping | Gate 6 | Persist required facts and compare ownership using database time |
| Go packages, interfaces, UUIDv7 library, dependency direction, and DI | Gate 7 | Realize the contracts behind domain-owned interfaces |
| First protected secret backend/binding, local topology, and service configuration | Gate 8 | Configure resolver and registered adapters without exposing values |

This allocation resolves the earlier phrase “Gate 3 Go/API serialization”: Gate 3 owns the complete logical envelope. Gate 5 owns external serialization and compatibility; Gate 7 owns Go representation and package placement.

## Closed decision and downstream ledger

Every Gate 3 blocking decision is resolved by this design. Remaining downstream decisions do not permit Gate 3 semantics to change silently.

| Decision | Owner | Due | Concrete blocking point |
| --- | --- | --- | --- |
| Artifact staging, retention, orphan cleanup, preview allowlist ownership, and storage-size policy | Gate 4 specification owner | 2026-07-20 | Artifact implementation plan |
| Runtime envelope/Event/API serialization and local session constants | Gate 5 specification owner | 2026-07-20 | Event/API and local UI implementation plans |
| PostgreSQL major, migration tool, rollback policy, audit/tombstone retention, and lease-time query | Gate 6 specification owner | 2026-07-20 | Persistence and migration implementation plan |
| Go UUIDv7 library, interfaces, packages, dependency graph, and configuration types | Gate 7 specification owner | 2026-07-20 | Go bootstrap implementation plan |
| First protected local secret backend, exact binding format, and local service topology | Gate 8 specification owner | 2026-07-20 | Resolver adapter and local-environment implementation plans |

## Required design-validation scenarios

1. Provider returns a final result; required Artifact verification precedes completion.
2. Provider proposes multiple tools; they execute in declared order with no overlap.
3. Allowed ToolCall persists one prepared attempt before known success.
4. Tool requires Approval; restart while waiting resumes the same Run after a durable decision.
5. Approval replay with changed input, scope, adapter, destination, or purpose fails closed.
6. Effective grant expires immediately before use; no adapter invocation occurs and Approval is required.
7. Provider credential rotates; the opaque reference resolves the current version after revalidation.
8. Secret is revoked or binding is unavailable; existing wait/failure semantics apply without fallback.
9. Crash after preparation with proven non-delivery permits known-safe retry.
10. Crash after possible tool delivery enters reconciliation and never blind retries.
11. Provider response is lost after possible delivery; request is not automatically resent.
12. Tool retry across StepAttempts retains operation key; a new Run changes it.
13. Same operation key with changed normalized input hash is rejected.
14. Valid Checkpoint resumes after completed work without replay.
15. Corrupt, incompatible, or policy-mismatched Checkpoint fails safely.
16. Executor lease expires during an external call; expiry does not classify the outcome.
17. Cancellation before delivery prevents invocation and settles durably.
18. Cancellation after possible delivery records ambiguity before terminal cancellation.
19. Retry, turn, call, time, token, output, or spend exhaustion is finite and structured.
20. Sentinel secret is absent from runtime, provider, tool, Checkpoint, Event, log, metric, and Artifact metadata surfaces.
21. Agent attempts to spawn a Subagent or create dependencies; Phase 1 rejects the unsupported operation without creating state.
22. Provider output invents an adapter or claims authorization; registration and policy reject it.
23. Output exceeds inline limit; it becomes a bounded Artifact handoff or explicit failure without silent truncation.
24. Restart after policy tightening revalidates and blocks stale authority.
25. Revocation races authorization-use fence acquisition; exactly one operation linearizes first, and no use starts after revocation becomes effective.
26. Authority or secret resolution fails after attempt preparation but before delivery; known non-delivery evidence and the correct existing wait or failure are persisted.
27. Provider outcome remains unknown; explicit terminalization creates a later failed no-delivery StepAttempt before `FailStep`, preserving the earlier ambiguous evidence.

Phase 0 validates these as contract walkthroughs and repository checks. Phase 1 implements them with fake provider, tool, policy, resolver, clock, and object-store adapters plus failure injection.

## Proposed ADR 0004 boundary

Gate 3 execution should propose **ADR 0004 — Adopt staged single-agent runtime and verified adapter handoffs**. It should adopt the Core decisions above and record that Gate 3 owns semantics while Gates 5 and 7 own serialization and Go realization.

The ADR must not select concrete packages, payloads, tables, provider SDKs, tool transports, secret backend, or Phase 2 scheduling. Its implementation blocking point is the Phase 1 provider/tool/runtime/resolver implementation plans and dependent Gate 4–8 specifications that consume these semantics.

## Acceptance criteria

- AgentDefinition, Subagent, runtime coordinator, provider adapter, tool adapter, executor, provider attempt, and Checkpoint each have one meaning and owner.
- Phase 1 remains sequential and cannot create executable Subagents or Workflow graphs.
- Provider and tool calls persist preparation before invocation outside PostgreSQL transactions.
- Tool operation-key and reconciliation rules match ADR 0001.
- Provider ambiguity is explicit without inventing a new aggregate.
- Authorization is revalidated at use and plaintext secrets never reach generic runtime.
- Checkpoint compatibility and safe-resume rules prevent silent replay.
- Lease, heartbeat, grace, concurrency, retry, timeout, call, token, output, and spend defaults and hard maxima are exact and finite.
- Cancellation and restart preserve every attempt and resolve ambiguous effects before terminal claims.
- Gate 3 semantic ownership does not preempt Gate 4–8 representation and infrastructure decisions.
- Every remaining decision has an owner, ISO due date, and concrete blocking point.
- All validation scenarios map to an explicit rule without claiming runtime enforcement.

## Risks

- Provider attempts may later justify a first-class entity. Phase 1 keeps them StepAttempt evidence; a material lifecycle change requires a new ADR.
- Thirty-second ownership leases can expire during local pauses. Recovery grace and the rule that expiry proves only staleness prevent it from classifying an external effect.
- Cost data can be unavailable or stale. Paid provider use then fails closed; a local non-metered profile must explicitly declare zero external spend, and token and call ceilings still apply.
- A registered process adapter may be unable to mediate ambient authority. Policy must disclose and evaluate the composite privilege or deny it; this design does not claim sandboxing.
- Artifact handoff limits can conflict with Gate 4 storage policy. The stricter bound wins until a later ADR changes the cross-gate contract.
