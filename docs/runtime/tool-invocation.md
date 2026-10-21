# Tool Invocation Contract

## Authority and status

This is the canonical Gate 3 tool-invocation contract for the Central project. It defines registered tool definitions, the ToolCall lifecycle, the authorization-use fence, secret-aware adapter handoff, result and Artifact handoff, reconciliation, and validation scenarios for Phase 1.

These contracts were adopted by Accepted ADR 0004 and passed Gate 3 design-contract validation. This document makes no runtime implementation claim. Phase 0 validated it through contract walkthroughs and repository checks. Phase 1 realizes it behind domain-owned interfaces without changing meaning.

This contract consumes ADR 0004 (staged single-agent runtime and verified adapter handoffs), ADR 0001 (durable Task domain and lifecycle), and ADR 0003 (security policy and SecretReference model). The [Agent runtime contract](agent-runtime.md) owns AgentDefinition, provider-operation semantics, the local executor, and shared scenarios; this document owns tool-specific contracts and cross-references those scenarios rather than renumbering them.

## Registered tool definition

A versioned tool definition declares:

- stable tool identity and immutable version;
- registered adapter identity;
- semantic input and result schemas;
- capability-derivation rules derived from declared input and adapter properties;
- support for operation-key delivery and outcome lookup;
- default timeout, input, output, and response limits;
- safe structured result fields returned to runtime context;
- Artifact-producing behavior declarations;
- reconciliation support;
- known failure classifications.

Tool and adapter identities are registered before any invocation. A model or tool cannot provide an adapter identity, allow flag, authorization token, or fallback SecretReference. Unknown tools, versions, capability derivations, or failure classes fail closed.

Registered definitions contain no secret value. They reference SecretReference IDs only through trusted integration configuration. They never contain plaintext, backend locators, raw secret names, or environment-variable names.

A Run snapshots the exact tool definition versions it uses (the Run snapshot rule). Changing a tool definition, schema, capability derivation, or limit creates another version; it never silently changes an active Run.

## Invocation flow

Ordered tool proposals from the provider become ToolCalls in provider order and execute one at a time through the ToolCall lifecycle:

1. **Canonicalize** tool identity and semantic input.
2. **Compute** normalized input hash and stable in-Run operation key.
3. **Create ToolCall** and **derive every composed capability** from the registered tool definition and semantic input.
4. **Persist decision**: Runtime proposes the complete canonical capability request; policy persists a decision reference bound to Workspace, Task, Run, operation, normalized input, capability, scope, sensitivity, adapter, destination, purpose, policy version, and SecretReference IDs. Runtime grants nothing.
5. **Durable Approval wait**: On `require_approval`, create Approval and durable `approval` wait atomically.
6. **Preliminary revalidation**: After Approval or grant resolution, perform preliminary eligibility revalidation for input, scope, policy, Task state, sensitivity, adapter, destination, purpose, and SecretReference state.
7. **Prepare ToolCallAttempt**: Persist a prepared ToolCallAttempt before external delivery.
8. **Acquire fence and resolve**: Acquire the authorization-use fence and resolve any SecretReference inside the registered adapter boundary.
9. **Invoke outside transaction**: Invoke the registered adapter outside the transaction while the fence covers request handoff.
10. **Persist outcome**: Persist known success, known failure, safe retry wait, cancellation evidence, or reconciliation.

Steps 4 and 5 are atomic when Approval is required. The authorization decision commits before delivery. The ToolCallAttempt commits before the adapter invokes the external tool.

## Operation identity and retries

ToolCall operation key is stable across StepAttempts in one Run and changes for another Run. It is scoped by Workspace, Task, Run, logical ToolCall, AgentDefinition revision, and normalized input hash.

Reusing the operation key with a different normalized input hash is a domain error.

Every physical delivery receives another immutable ToolCallAttempt. A prepared attempt commits before delivery.

Total attempts include the initial physical attempt and do not reset across StepAttempts. A known-safe physical retry keeps the operation key and creates a new ToolCallAttempt under the same logical operation. Ambiguous delivery consumes a physical attempt but never authorizes another one.

Known-safe transient physical attempts are bounded at 3 total attempts (default) or 5 total attempts (hard maximum) per logical ToolCall in one Run. Backoff is exponential with 1-second base, 30-second cap, and full jitter in `[0, bound]`. Installed policy may choose a value at or below each hard maximum; adapters may impose stricter values. A value above a hard maximum is rejected.

Every counter, budget reservation, failure class, and next-eligible timestamp is durable. A new Run gets new logical identities and budgets; a StepAttempt retry inside one Run does not reset them. `Retry-After` may increase a delay only within the remaining Run and installed-policy bounds.

## Authorization-use fence

A policy decision or caller Boolean is not authority. Registered adapters acquire a single-use authorization-use fence that linearizes exact revalidation, secret resolution, and external delivery against grant revocation, policy tightening, SecretReference revocation, or Task termination.

Runtime proposes a complete canonical capability request; it grants nothing. Policy persists a decision reference bound to Workspace, Task, Run, operation, normalized input, capability, scope, sensitivity, adapter, destination, purpose, policy version, and SecretReference IDs. Approval remains immutable history; an effective grant is separate expiring authority.

After the external attempt is durably prepared, the adapter requests a single-use authorization-use fence for the exact operation. Successful use-fence acquisition after durable revalidation is the **use linearization point** against grant revocation, policy tightening, SecretReference revocation, or Task termination.

The exclusive mutation side of the same logical fence is held through durable commit. Successful commit is the **mutation linearization point**. If mutation commits first, later use fails closed; if use linearizes first, that one already-prepared request may be handed off, and the mutation then blocks every later use. A failed mutation commit releases its fence without changing authority.

The adapter receives a non-serializable, non-transferable callback scope, not an agent-visible bearer token or caller Boolean.

The fence handoff deadline is the earliest of:

- the configured authorization-use fence duration (5 seconds default, 10 seconds maximum);
- the effective-grant expiry;
- a stricter reference/policy deadline;
- the attempt deadline.

If transport has not accepted the request by that point, the callback aborts with known non-delivery. The adapter must release the fence immediately after proven non-delivery or transport acceptance; it is not held while waiting for a response. A process crash releases the fence; recovery then treats the prepared attempt as ambiguous unless transport evidence proves non-delivery.

The fence exists only inside the trusted local process.

## Post-preparation failure

If revalidation, fence acquisition, or secret resolution fails after preparation but before delivery, the adapter records `delivery=not_started` and a known non-delivery outcome. A ToolCallAttempt becomes `failed`; the current StepAttempt ends with failed evidence.

Each post-preparation failure class maps to an existing domain behavior:

| Failure class | Domain behavior |
| --- | --- |
| Provider or tool known non-delivery | `delivery=not_started`; attempt `failed`; may enter `retry_delay` for known-safe resolver or infrastructure outage |
| Expired authority | Existing durable `approval` wait |
| Operator-repairable secret condition | Existing durable `external_input` wait |
| Known-safe resolver outage | May use `retry_delay` |
| Denial or binding mismatch | Fails according to policy; invoke nothing |

Any later resume creates a new StepAttempt and physical attempt after full revalidation. The prepared ToolCallAttempt remains immutable evidence of the non-delivery.

## Secret-aware adapter

A secret-aware adapter resolves a SecretReference and hands the external request to its transport inside the authorization-use fence callback scope. Only the registered adapter for the exact operation receives the transient secret value.

Exact checks bind every secret-aware operation:

- Workspace identity;
- Task identity;
- Run identity;
- operation identity;
- adapter identity;
- destination identity;
- declared purpose.

The runtime never receives plaintext. There is no raw-secret reveal. The caller Boolean is not authority. Runtime receives only safe opaque version or fingerprint, structured outcome, and sanitized reason.

A generic filesystem adapter and any shell/process adapters cannot resolve or receive a SecretReference. They remain structurally incapable of secret access because they have no registered secret-aware binding.

`secret.use` grants no network, database, model-context, or other data authority. A `secret.use` capability authorizes only the resolution of the named SecretReference inside the exact authorized adapter operation for the exact destination and purpose.

Agent instructions, provider output, tool proposals, tool results, and Artifact content remain untrusted data. They may not select adapters, change policy, grant capability, alter registered definitions, or supply a fallback SecretReference.

## Result and Artifact handoff

Tool results are sanitized and bounded before entering runtime context.

| Control | Default | Phase 1 hard maximum | Scope |
| --- | --- | --- | --- |
| Inline sanitized tool result | 64 KiB | 256 KiB | Per ToolCallAttempt result returned to runtime context |
| Buffered tool-result body before Artifact handoff | 16 MiB | 64 MiB | Per ToolCallAttempt; larger bodies require Gate 4 streaming Artifact behavior |

A result at or below the inline limit is returned directly to runtime context. A result above the inline limit but at or below the buffered maximum becomes a safe structured result with an Artifact reference; the body is handed off through Gate 4's bounded upload contract while only safe metadata and the Artifact reference return to context.

A result above the buffered maximum requires Gate 4 streaming Artifact behavior. If streaming is unavailable, the result is a safe structured failure with no silent truncation.

Security-relevant decisions, authority context, errors, and audit evidence are never silently truncated. Limit violations produce explicit structured failure.

A registered Artifact-producing tool may stream a larger body through Gate 4's bounded upload contract while returning only safe metadata and an Artifact reference. The 16 MiB bound limits data buffered as a tool result; it is not a maximum ready-Artifact size.

## Reconciliation

Possible delivery with unknown outcome enters existing durable `reconciliation` waiting. There is no blind invocation after possible delivery.

Reconciliation can record three terminal outcomes:

1. **Confirmed success**: The external system confirms the operation completed with the expected effect. Reconciliation evidence and a safe result reference are appended. The Step and Run requeue; a new StepAttempt consumes the confirmed result without invoking the tool again.
2. **Confirmed no effect**: The external system confirms the operation was not delivered or had no side effect. No-effect evidence is appended. The Step and Run requeue; a new StepAttempt may make a policy-controlled physical attempt under the same operation key and normalized input hash.
3. **Still unknown**: The outcome remains unknown. The Run waits by default and is never automatically reinvoked. To terminate, explicit operator input or installed policy records `terminalize_unknown` reconciliation evidence that forbids another external delivery and permits terminalization only.

Reconciliation never rewrites the ambiguous ToolCallAttempt. Every attempt remains immutable evidence. Adapters pass the operation key to external systems that support idempotency and use it for outcome lookup when supported.

Lease expiry, timeout, process loss, or cancellation signal alone never proves an external tool operation failed.

## Validation contract

The following validation scenarios are owned by the ToolCall invocation contract. They are validated in Phase 0 as contract walkthroughs and repository checks. Phase 1 implements them with fake provider, tool, policy, resolver, clock, and object-store adapters plus failure injection.

| Scenario | Rule |
| --- | --- |
| R03 | Allowed ToolCall persists one prepared attempt before known success. |
| R04 | Tool requires Approval; restart while waiting resumes the same Run after a durable decision. |
| R05 | Approval replay with changed input, scope, adapter, destination, or purpose fails closed. |
| R06 | Effective grant expires immediately before use; no adapter invocation occurs and Approval is required. |
| R07 | Provider credential rotates; the opaque reference resolves the current version after revalidation. |
| R08 | Secret is revoked or binding is unavailable; existing wait or failure semantics apply without fallback. |
| R09 | Crash after preparation with proven non-delivery permits known-safe retry. |
| R10 | Crash after possible tool delivery enters reconciliation and never blind retries. |
| R12 | Tool retry across StepAttempts retains operation key; a new Run changes it. |
| R13 | Same operation key with changed normalized input hash is rejected. |
| R20 | Sentinel secret is absent from runtime, provider, tool, Checkpoint, Event, log, metric, and Artifact metadata surfaces. |
| R22 | Provider output invents an adapter or claims authorization; registration and policy reject it. |
| R23 | Output exceeds inline limit; it becomes a bounded Artifact handoff or explicit failure without silent truncation. |
| R25 | Revocation races authorization-use fence acquisition; exactly one operation linearizes first, and no use starts after revocation becomes effective. |
| R26 | Authority or secret resolution fails after attempt preparation but before delivery; known non-delivery evidence and the correct existing wait or failure are persisted. |

Scenarios R01, R02, R11, R14 through R19, R21, R24, and R27 are owned by the [Agent runtime contract](agent-runtime.md) and the Checkpoint contract. They are cross-referenced here, not renumbered.
