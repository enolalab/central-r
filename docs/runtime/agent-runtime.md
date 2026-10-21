# Agent Runtime Contract

## Authority and status

This is the canonical Gate 3 runtime contract for the Central project. It defines AgentDefinition, the runtime coordinator, provider-operation semantics, the local executor, retry and budget policy, cancellation, and observability for Phase 1.

These contracts were adopted by Accepted ADR 0004 and passed Gate 3 design-contract validation. This document makes no runtime implementation claim. Phase 0 validated it through contract walkthroughs and repository checks. Phase 1 realizes it behind domain-owned interfaces without changing meaning.

This contract consumes ADR 0004 (staged single-agent runtime and verified adapter handoffs), ADR 0001 (durable Task domain and lifecycle), and ADR 0003 (security policy and SecretReference model).

## AgentDefinition and Subagent

### AgentDefinition

An AgentDefinition is an immutable revision containing:

- opaque definition ID and immutable revision;
- provider profile and model identity;
- instruction and context-policy references;
- permitted versioned tool definitions;
- execution-policy and budget profile references;
- required output declarations and their completion role;
- compatibility range understood by the runtime;
- non-secret provenance and creation metadata.

It contains no secret value. Definitions reference SecretReference IDs only through trusted provider or integration configuration. They never contain plaintext, backend locators, raw secret names, or environment-variable names.

A Run snapshots the selected revision and resolved version identities before execution (the Run snapshot rule). Changing instructions, provider, tool expansion, budgets, or output requirements creates another revision or Run policy snapshot; it never silently changes an active Run.

### Subagent

A Subagent is a future AgentDefinition selected for a Phase 2 child Task. Phase 1 exposes no spawn command, child edge, dependency, or Subagent tool. An agent may attempt to spawn a Subagent or create dependencies; Phase 1 rejects the unsupported operation without creating state. Child Tasks and Agent relationships begin in Phase 2.

## Runtime coordinator

The runtime coordinator is an application-level coordinator that interprets untrusted provider results and invokes domain commands and registered ports. It requests domain commands; it never writes lifecycle state directly.

Phase 1 has one sequential runtime coordinator and at most one active external invocation. The coordinator never bypasses a domain transition service — all task transitions go through the task domain service.

## Sequential execution flow

The sequential execution loop advances one durable Agent Task through a model-and-tool loop:

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

## Provider request envelope

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

Preparation evidence excludes plaintext secrets and unrestricted bodies. It records safe request identity, authorization references, timeout, budget reservation, and correlation. It never stores unrestricted prompt bodies or secret material.

Gate 3 owns these meanings. Gate 5 owns any serialized field names and versioning. Gate 7 owns Go types and adapter interfaces.

## Provider operation and attempt evidence

Provider-operation identity is stable for one logical provider turn within one Step and Run. It is scoped by Workspace, Task, Run, Step, logical turn, AgentDefinition revision, and canonical context hash. A known-safe physical retry keeps that operation identity and creates a new globally unique provider-attempt identity. Reusing an operation identity with another context hash is rejected, and a new Run always creates another operation identity.

`prepared` is the durable pre-delivery state. Preparation evidence commits before network delivery and records safe request identity, authorization references, timeout, budget reservation, and correlation.

Provider-attempt evidence has exactly one immutable terminal outcome after `prepared`: `succeeded`, `known_failed`, `cancelled`, or `ambiguous`. These are StepAttempt evidence values, not another aggregate or public lifecycle family.

The adapter returns exactly one semantic outcome:

- completed response;
- completed response with ordered tool proposals;
- known retryable failure with proven non-delivery or no external effect;
- known terminal failure;
- cancellation with known non-delivery;
- ambiguous delivery or outcome.

A known retryable provider failure records `known_failed`, ends the current StepAttempt with failed evidence, and may place Step/Run/Task in `retry_delay`; eligibility creates a new StepAttempt and provider-attempt identity under the same logical provider operation. Known-safe retry keeps the logical identity but creates a physical identity without resetting its budget across StepAttempts. A known terminal provider failure fails the Step and parent execution according to policy.

## Provider failure and accounting

### Outcome classification

Each semantic outcome maps to evidence and domain behavior:

| Outcome | Evidence | Domain behavior |
| --- | --- | --- |
| Completed response | `succeeded` | Advances required-output production and completion guards |
| Completed response with ordered tool proposals | `succeeded` | Ordered tool proposals become ToolCalls in provider order |
| Known retryable failure with proven non-delivery/no effect | `known_failed` | Ends StepAttempt with failed evidence; may enter `retry_delay`; new StepAttempt under same logical operation |
| Known terminal failure | `known_failed` | Fails the Step and parent execution according to policy |
| Cancellation with known non-delivery | `cancelled` | Follows accepted cancellation settlement |
| Ambiguous delivery or outcome | `ambiguous` | Enters reconciliation; no automatic reinvocation |

Provider response and proposed tools remain untrusted. They may propose actions but cannot select adapters, change policy, grant capability, or alter registered definitions.

### Accounting rules

- Pre-delivery reservation: token and spend reservations commit before provider delivery.
- Sanitized usage settlement: budget reservations settle from sanitized usage evidence.
- Conservative charging while ambiguous: when an ambiguous provider attempt has no usage evidence, its conservative reservation remains charged until reconciliation proves non-delivery or supplies authoritative usage.
- Fail-closed paid-provider price data: a paid hosted-provider request fails closed when its versioned conservative price data is missing or stale; it never falls back to token-only monetary accounting. A local non-metered provider profile may explicitly declare zero external provider spend, while token and call ceilings still apply.

## Provider reconciliation

Provider ambiguity maps to the accepted Step lifecycle:

1. Mark the provider attempt `ambiguous` and end its current StepAttempt with immutable `ambiguous` evidence.
2. Move Step, Run, and Task to existing waiting reason `reconciliation`, referencing provider operation and attempt identities.
3. A confirmed response appends reconciliation evidence and a safe response reference, then requeues the same Step and Run. A new StepAttempt consumes that response without invoking the provider again.
4. Confirmed non-delivery appends no-effect evidence, requeues the same Step and Run, and permits a new StepAttempt to make a policy-controlled physical attempt under the same provider-operation identity and context hash.
5. A still-unknown outcome remains waiting by default and is never automatically resent.
6. To terminate instead of waiting indefinitely, explicit operator input or installed policy records `terminalize_unknown` reconciliation evidence. That evidence states that outcome remains unknown, forbids another external delivery, and permits `RequeueStep` only for terminalization. The newly claimed StepAttempt invokes no provider, ends `failed` with reason `unresolved_provider_outcome`, and then satisfies the existing `FailStep` guard so Run and Task can fail consistently.

Reconciliation never rewrites the ambiguous StepAttempt. `FailStep` is used only after a later no-delivery terminalization StepAttempt has itself ended `failed`.

## Local executor ownership

An Executor is one process-local instance that holds persisted expiring ownership while advancing a Run or Step.

- Process startup generates a fresh executor-instance UUID.
- Claiming Run/Step state and recording ownership are atomic; claim plus ownership record is atomic.
- Active work may advance only when the current owner holds ownership; only the current owner may advance actively running work.
- A durable wait releases ownership; durable waiting releases ownership and requeue requires a new claim.
- The heartbeat is a lease-freshness signal; heartbeat renewal changes only lease freshness, never an external-effect outcome.
- Graceful shutdown stops new claims first, persists safe progress, and releases ownership only when no unrecorded invocation exists.
- On restart, startup recovery scans stale ownership and uses persisted Checkpoints, attempts, retries, cancellation, and operation evidence.
- Expiry is not an outcome classification; expiry proves only staleness.
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

Gate 6 must use database-derived time for ownership comparisons so local wall-clock skew cannot make a caller prove expiry.

## Retry and budgets

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

Retry occurs only for a classified known-safe failure. "Total attempts" includes the initial physical attempt. Ambiguous delivery consumes a physical attempt but never authorizes another one. Every counter, budget reservation, failure class, and next-eligible timestamp is durable. A new Run gets new logical identities and budgets; a StepAttempt retry inside one Run does not reset them. `Retry-After` may increase a delay only within the remaining Run and installed-policy bounds.

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

Prepared, known, and ambiguous outcomes all follow their accepted paths. PostgreSQL reconstruction ensures every persisted attempt, reconciliation evidence, and safe reference survives restart.

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

## Observability

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

Source-boundary redaction occurs before data enters a generic error, Event, log, metric, or trace. Evidence never includes plaintext secrets, bootstrap/session tokens, raw authorization material, unrestricted prompt/tool/Artifact bodies, command environments, or unbounded user-controlled labels.

## Validation contract

The following validation scenarios are owned by the Agent/runtime contract. They are validated in Phase 0 as contract walkthroughs and repository checks. Phase 1 implements them with fake provider, tool, policy, resolver, clock, and object-store adapters plus failure injection.

| Scenario | Rule |
| --- | --- |
| R01 | Provider returns a final result; required Artifact verification precedes completion. |
| R02 | Provider proposes multiple tools; they execute in declared order with no overlap. |
| R11 | Provider response is lost after possible delivery; request is not automatically resent. |
| R16 | Executor lease expires during an external call; expiry does not classify the outcome. |
| R17 | Cancellation before delivery prevents invocation and settles durably. |
| R18 | Cancellation after possible delivery records ambiguity before terminal cancellation. |
| R19 | Retry, turn, call, time, token, output, or spend exhaustion is finite and structured. |
| R21 | Agent attempts to spawn a Subagent or create dependencies; Phase 1 rejects the unsupported operation without creating state. |
| R24 | Restart after policy tightening revalidates and blocks stale authority. |
| R27 | Provider outcome remains unknown; explicit terminalization creates a later failed no-delivery StepAttempt before `FailStep`, preserving the earlier ambiguous evidence. |

The remaining scenarios (R03 through R10, R12 through R15, R20, R22 through R23, R25 through R26) are owned by the ToolCall and Checkpoint contracts. See the ToolCall and Checkpoint documents for those scenarios; they are not renumbered here.
