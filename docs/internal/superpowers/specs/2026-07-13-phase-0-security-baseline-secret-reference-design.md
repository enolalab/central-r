# Phase 0 Security Baseline and SecretReference Design

- **Status:** Approved
- **Approved:** 2026-07-13
- **Date:** 2026-07-13
- **Phase:** Phase 0 — Architecture and foundations
- **Implementation target:** Phase 1 — Local Central MVP

## Context

Central's approved domain model makes Workspace the Phase 1 isolation boundary, treats shell, filesystem, network, and database access as privileged, persists capability decisions before adapter invocation, and models Approval as durable state. It deliberately leaves the complete threat model, capability taxonomy, approval defaults, local authentication baseline, and SecretReference contract to Gate 2.

Phase 1 runs one local Central instance for one trusted operating-system account. Task input, repository and document content, model output, tool output, network responses, and Artifacts remain untrusted even when the local operator is trusted. A model or untrusted document may propose an action, but it cannot confer authority to perform that action.

This specification closes the Gate 2 design decisions without defining the Agent, Subagent, Worker, or concrete tool-execution protocols owned by Gate 3. It does not claim that the controls below are implemented during Phase 0.

Related documents:

- [Product vision](../../../product/vision.md)
- [Product phases](../../../product/phases.md)
- [Product roadmap](../../../product/roadmap.md)
- [Architecture overview](../../../architecture/overview.md)
- [Durable execution](../../../architecture/durable-execution.md)
- [Online Mode boundary](../../../architecture/online-mode.md)
- [Current phase](../../../implementation/current-phase.md)
- [Specification and planning guide](../../../implementation/spec-and-plan-guide.md)
- [Approved domain and lifecycle design](2026-07-12-phase-0-domain-lifecycle-design.md)
- [ADR governance](../../../adr/README.md)
- [ADR 0001 — Adopt the durable Task domain and lifecycle](../../../adr/0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0002 — Authorize Accepted-to-Superseded ADR Status transitions](../../../adr/0002-authorize-accepted-to-superseded-status-transitions.md)

## Objective

Define an implementation-ready security contract for the first local durable Task so that Phase 1 can:

- treat all agent-visible content as untrusted data rather than authority;
- evaluate every privileged operation through one fail-closed policy boundary;
- express least privilege as `resource × effect × scope`;
- persist authorization evidence before any external side effect;
- bind approvals to canonical intent and reject replay or substitution;
- keep model-context egress separate from local read access;
- refer to credentials without exposing plaintext to the runtime, model, durable state, or generic tools;
- revoke or expire grants without rewriting historical Approval evidence;
- preserve the durable waiting, retry, reconciliation, and completion invariants already approved.

The design is successful when later Phase 1 specifications can define APIs, storage, adapters, and UI without inventing another security model.

## Phase boundary

Phase 0 is a design-only gate. This document approves security semantics, not executable enforcement.

### In scope

- Phase 1 assets, actors, assumptions, trust boundaries, threats, controls, and residual risks
- canonical capability and scope model
- policy outcomes, precedence, and fail-closed behavior
- capability defaults for filesystem, process, network, database, model-context egress, and secret use
- durable approval binding, expiry, revocation, retry, and rerun behavior
- loopback UI authentication and request-forgery baseline
- SecretReference identity, metadata, resolver boundary, rotation, revocation, and failure behavior
- security-audit and redaction requirements
- security scenario validation and Gate 2 completion evidence

### Out of scope

- executable Go code, schema, migration, HTTP handler, template, or adapter implementation
- concrete Agent, Subagent, Worker, scheduler, tool protocol, or capability-token transport
- Workflow graphs, parallel subagents, and distributed execution
- third-party plugin trust and a general plugin sandbox
- Central Server, Online Mode, LAN access, remote control, or node identity
- multi-user authentication, RBAC, SSO, tenant isolation, or enterprise policy administration
- protection from a compromised operating-system account, root user, database administrator, or malicious Central binary
- selection of the first concrete secret-storage backend
- exact runtime resource limits, retry constants, and session durations

The policy boundary is not represented as a process sandbox. An approved arbitrary process remains highly privileged. Gate 3 must not claim that filesystem or network restrictions are enforced for a process unless the execution environment actually mediates those effects.

## Decisions

1. **Phase 1 binds its HTTP surface to loopback and assumes one trusted local operating-system account.**
2. **Loopback access still requires bootstrap-token exchange, a bounded session, CSRF defense, and Host/Origin validation.** This is local authentication, not RBAC.
3. **Model, Task, repository, document, tool, network, and Artifact content is untrusted and cannot grant authority.**
4. **The canonical authority model is `resource × effect × scope`.** Versioned profiles are UX bundles only.
5. **Policy has exactly three outcomes: `allow`, `require_approval`, or `deny`.** Unknown or malformed security state fails closed.
6. **The strictest decision controls an operation that composes multiple capabilities.** An allowed capability never implies another capability.
7. **Submitting a Task grants read-only access only within that Task's canonical Workspace roots.** Path escape, symlink escape, and cross-Workspace access are denied.
8. **Workspace read access does not grant model-context egress.** Hosted-provider selection must explicitly declare provider and resource scope.
9. **Filesystem creation or modification may use a bounded task-scoped grant.** Deletion, executable-bit changes, and protected paths require per-action approval.
10. **Arbitrary process execution requires per-action approval.** A task-scoped process grant requires an exact executable, working directory, argument envelope, and explicit auxiliary capabilities enforced by the execution environment.
11. **Agent-requested network access is denied by default.** A grant binds protocol, destination, port, purpose, and redirect behavior; system-owned connections use a separate authority plane.
12. **Database read may use a task-scoped grant; mutation requires per-action approval.** Administrative, DDL, or destructive operations are denied unless a protected maintainer override explicitly enables one action.
13. **Resource scopes have `local`, `dev`, `staging`, or `prod` sensitivity.** Unknown sensitivity is treated as the strictest level; every production mutation is per-action and cannot be bundle-opened.
14. **An Approval binds canonical intent and security context.** Meaningful changes invalidate the authorization and require reevaluation.
15. **Task-scoped grants have an `expires_at` no more than 24 hours after issuance.** Completion, cancellation, revocation, policy tightening, or scope change may invalidate them earlier; no grant is usable while a Task is failed.
16. **The unexpired authorization basis for a task-scoped grant may be revalidated when the same failed Task is explicitly retried with a new Run, but only when Task intent, grant subject, scope, and policy remain valid.** Per-action approvals do not survive a new operation key. A rerun of a cancelled Task creates a new Task and inherits no grants.
17. **SecretReference is a stable, opaque, Workspace-scoped logical identity.** It is not a secret value, backend locator, environment-variable name, or raw backend secret name.
18. **Secret material remains outside PostgreSQL and S3 behind an explicitly configured resolver backend.** Durable state contains only permitted reference metadata.
19. **Secret resolution occurs just in time inside an authorized secret-aware adapter.** Plaintext is never returned to the agent, model, generic runtime, or generic shell/process capability.
20. **There is no raw-secret reveal capability and no automatic fallback to another reference, environment variable, or backend.**
21. **Explicit model-provider selection creates only the bounded task-scoped model-egress and `secret.use` authority required by that provider adapter.** Other secret use requires an explicit bounded approval.
22. **Secret rotation preserves logical reference identity.** A binding-preserving rotation does not require reapproval; revocation blocks every later resolution.
23. **Capability decisions, approvals, overrides, secret-resolution uses, egress, adapter effects, and reconciliation produce durable append-only security evidence.**
24. **Secret failure uses the approved durable lifecycle reasons.** Operator-repairable absence uses `external_input`, transient backend outage uses bounded `retry_delay`, ambiguous external effects use `reconciliation`, and deterministic denial or unrecoverable failure is structured and fail closed.

## Approaches considered

### Selected: atomic capability policy kernel with versioned UX profiles

Every privileged request becomes a canonical authorization request. One policy kernel applies baseline policy, Task intent, durable grants, current policy version, sensitivity, and hard-deny rules. Profiles may expand into a visible set of atomic capabilities, but profiles never become independent authority or contain wildcards.

This provides the clearest audit chain, supports exact destination and SecretReference binding, and lets later phases add adapters without defining conflicting authorization semantics.

### Rejected: risk tiers as authority

Classifying actions as low, medium, high, or critical is easy to explain, but a single tier obscures material differences among path scope, network destination, data sensitivity, secret purpose, and destructive effects. Risk labels may remain UI hints; they are not the canonical policy input.

### Rejected: adapter-owned policy

Letting each filesystem, shell, network, database, or provider adapter define independent rules is initially convenient but creates inconsistent defaults and weak composition. It also makes cross-capability exfiltration and approval substitution harder to detect.

## Threat model

### Assumptions

- Central is operated by one trusted local user through one trusted OS account.
- The UI/API is reachable only through `127.0.0.1` and `::1` unless a later topology ADR changes this assumption.
- PostgreSQL and S3-compatible object storage are infrastructure dependencies, not authority sources.
- Hosted model use is permitted only after explicit provider selection and egress disclosure.
- Central runs with the minimum OS permissions practical for the selected Workspace and infrastructure.
- Compromise of the trusted OS account, root, a database administrator, or the Central binary itself is outside Phase 1's defensive claim.

### Assets

| Asset | Security objective |
| --- | --- |
| Workspace repositories, files, documents, and data | Confidentiality, integrity, and Workspace isolation |
| Task, Run, Step, ToolCall, Approval, and Checkpoint state | Durable integrity, attribution, and safe recovery |
| Artifact bodies and metadata | Integrity, lineage, confidentiality, and safe presentation |
| Policy, grants, Approval evidence, and audit records | Integrity, freshness, exact binding, and traceability |
| Provider credentials and other secrets | Non-disclosure, purpose limitation, rotation, and revocation |
| Model prompts and selected context | Explicit egress, minimization, and provider binding |
| PostgreSQL, MinIO, and local host | Least privilege, availability, and separation from agent authority |

### Actors and trust classification

| Actor or source | Classification | Authority |
| --- | --- | --- |
| Local operator through an authenticated loopback session | Trusted actor | May submit intent, decide Approval, revoke grants, and perform protected maintainer actions when configured |
| Central policy and domain services | Trusted computing base | Validate and persist authority; may not derive authority from content |
| Registered system adapter | Trusted, least-privileged component | May use only system identity and authorization context assigned to that adapter |
| Model or agent | Untrusted decision aid | May propose actions; cannot approve, broaden, or grant them |
| Task text, repository, document, tool output, network response, Artifact | Untrusted data | No authority |
| Hosted model provider or external service | External trust domain | Receives only explicitly authorized data and returns untrusted data |
| Other local process, web origin, or LAN client | Potential attacker | No Central authority |

### Trust boundaries

1. Local browser to loopback HTTP transport and session validation.
2. Untrusted Task/model/tool content to the policy kernel.
3. Workspace root to paths outside that Workspace and to another Workspace.
4. Runtime intent to privileged filesystem, process, network, database, model, and secret-aware adapters.
5. Approval UI decision to the canonical authorization request it permits.
6. SecretReference resolver and protected binding to the one authorized adapter operation.
7. Runtime to hosted model provider and every other external destination.
8. Agent-requested traffic to system-owned PostgreSQL, MinIO, provider, and control connections.
9. PostgreSQL durable metadata to S3-compatible Artifact bodies.
10. Untrusted Artifact body to browser download or preview.

### Threats, controls, and residual risk

| ID | Threat or abuse case | Required control | Residual risk and owner |
| --- | --- | --- | --- |
| T01 | Prompt injection asks the agent to run a tool, reveal data, or alter policy | Content has no authority; canonical policy evaluation and durable Approval precede invocation | Operator may approve a malicious but accurately disclosed action; approval UX owner must make consequences clear before Gate 3 UI implementation |
| T02 | Path traversal, symlink replacement, or cross-Workspace reference escapes isolation | Canonical Workspace roots, Workspace-scoped IDs, symlink-safe resolution, protected-path rules, and adapter revalidation | OS-level races remain unless the filesystem adapter uses descriptor-relative or equivalent safe operations; filesystem adapter owner before implementation |
| T03 | Approved input, destination, capability, or scope is substituted or replayed | Approval binds normalized input hash, operation key, scope, policy version, and security context; changed meaning requires a new decision | Canonicalization bugs can create collisions or semantic gaps; policy contract tests before adapter implementation |
| T04 | Secret leaks into prompt, Event, log, checkpoint, key, Artifact metadata, command, or generic process | Opaque references, just-in-time secret-aware resolution, no raw reveal, source redaction, safe metadata, and sentinel tests | An authorized external service may itself mishandle a secret; provider/adapter selection and destination binding remain required |
| T05 | Local data is silently sent to a hosted model | Separate `model_context × send` capability with provider, resource scope, and sensitivity disclosure | The provider can retain authorized data according to its own terms; operator chooses the provider and scope |
| T06 | Network plus secret use exfiltrates credentials or Workspace data | Separate capabilities, strictest composition, destination/purpose binding, redirect reevaluation, and agent-network default deny | Destination ownership can change; network adapter owner must define DNS pinning/rebinding controls before implementation |
| T07 | Agent reaches PostgreSQL, MinIO, loopback, private services, or metadata endpoints | Separate system authority plane; agent destinations resolving to loopback, private, link-local, multicast, unspecified, or metadata ranges fail closed | Explicitly registered local adapters remain trusted components and require least-privileged service identities |
| T08 | Database action mutates or destroys sensitive data | Read/write/admin classification, parameterization, per-action mutation approval, production rules, and protected override | Query classification may be ambiguous; database adapter must deny when it cannot classify safely |
| T09 | Crash or timeout causes a privileged external effect to repeat | Persist decision and prepared attempt before invocation; stable operation key inside one Run; ambiguous result enters reconciliation | External systems without idempotency or queryable outcome may require operator resolution |
| T10 | Another origin or local process submits or approves work | Loopback bind, bootstrap exchange, bounded cookie session, CSRF protection, and Host/Origin validation | Malware under the trusted OS account is out of scope; local-auth owner must still minimize token exposure |
| T11 | Malicious Artifact executes active content or spoofs content type | Treat Artifact as untrusted, sanitize display metadata, disable MIME sniffing, download safely by default, preview only allowlisted sanitized formats | Sanitizer vulnerabilities remain; artifact/UI owner before preview implementation |
| T12 | Tool, provider, output, or Artifact exhausts CPU, memory, disk, network, or spend | Per-adapter timeouts, size/output limits, concurrency and budget controls, and bounded retry | Exact limits depend on runtime and workload; Gate 3 runtime owner before execution implementation |
| T13 | Audit or log data becomes a secondary secret store | Minimal structured records, source redaction, safe fingerprints, bounded labels, and no unrestricted payloads | A database administrator can alter evidence and is outside Phase 1's claim; cryptographic tamper evidence is deferred |
| T14 | Grant remains effective after expiry, revocation, policy tightening, Task completion/cancellation, or while a Task is failed | Reevaluate immediately before use; separate historical Approval from effective grant; fail closed on stale policy | A check/use race must be closed by adapter authorization design; Gate 3 protocol owner before invocation implementation |

### Security goals

- Authority originates only from installed policy, explicit local-user intent, and durable unexpired grants.
- Policy is checked before privileged invocation and checked again at use when revocation or expiry can change the result.
- Every denial and wait is structured, attributable, durable where lifecycle-relevant, and free of sensitive values.
- Cross-Workspace references, unknown capability, unknown sensitivity, malformed scope, and hard-deny violations fail closed.
- The complete chain from proposal to durable effect can be reconstructed without storing plaintext credentials or unrestricted content.

### Security non-goals and honest limitations

- This baseline does not contain an arbitrary process by itself.
- Approval proves informed authorization of the displayed request; it does not prove that the requested operation is benign.
- Redaction reduces accidental disclosure but does not make an already exposed secret safe; exposed credentials must be rotated.
- Phase 1 application-layer append-only evidence is not cryptographically tamper-proof against a database administrator.
- Hosted-provider authorization does not control the provider after authorized data leaves Central.

## Capability model

### Canonical form

Every privileged request is represented conceptually as:

```text
resource × effect × scope
```

The canonical model contains these fields:

| Field | Meaning |
| --- | --- |
| Workspace | Ownership and isolation boundary |
| Task and current Run | Stable user intent and current execution context |
| Step, ToolCall, and operation key when applicable | Exact logical action and idempotency boundary |
| Actor and requester type | User, runtime, policy service, or registered adapter |
| Resource | Protected resource class |
| Effect | Requested observation, mutation, execution, connection, send, or use |
| Scope | Canonical resource selector and grant lifetime |
| Sensitivity | `local`, `dev`, `staging`, or `prod` |
| Adapter | Registered component permitted to carry out the operation |
| Destination and purpose when applicable | Exact external target and declared reason |
| Normalized input hash | Immutable semantic request identity |
| SecretReference IDs when applicable | Opaque references, never values |
| Policy version | Policy state against which the request is evaluated |

The concrete Go types and serialization belong to later specifications. They must preserve these semantics.

### Resource and effect classes

| Resource | Initial effects | Scope dimensions |
| --- | --- | --- |
| `filesystem` | `read`, `create`, `modify`, `delete`, `set_executable` | Workspace root, canonical path or path set, recursion, protected-path class |
| `process` | `execute` | Executable identity, working directory, argument envelope, environment policy, time and output bounds |
| `network` | `connect`, `listen` | Protocol, canonical host, resolved-address class, port, purpose, redirect policy, response bounds |
| `database` | `read`, `mutate`, `admin` | Connection identity, database, schema, relation, operation class, sensitivity |
| `model_context` | `send` | Provider, model class when material, selected resource scope, sensitivity, purpose |
| `secret` | `use` | SecretReference, adapter, destination, purpose |

`network.listen` is denied to agent-requested operations in Phase 1. Registered loopback HTTP service startup is a system-owned operation, not an agent grant.

Effects do not imply one another. In particular:

- `filesystem.read` does not imply `model_context.send`;
- `process.execute` does not imply filesystem, network, database, or secret authority;
- `network.connect` does not imply `secret.use`;
- `secret.use` does not imply raw reveal or arbitrary destination use;
- database read does not imply mutation or administration.

When an execution environment cannot actually prevent an executable from exercising undeclared ambient OS access, the request must declare that ambient access as composed capability and receive the strictest decision, or the operation is denied. Exact executable and arguments alone are not a sandbox.

### Policy outcomes and precedence

The policy kernel returns exactly one of:

- `allow`: current policy and effective grants authorize the exact request;
- `require_approval`: the request can be authorized by a local user through a new durable Approval;
- `deny`: a hard rule, missing authority, invalid request, or prohibited combination forbids invocation.

Evaluation applies these principles:

1. Canonicalization and validation happen before policy lookup.
2. Hard denies, Workspace isolation, and raw-secret prohibitions cannot be overridden by a profile.
3. Every composed capability is evaluated independently.
4. `deny` is stricter than `require_approval`, which is stricter than `allow`.
5. Missing rule, unknown resource/effect, unknown sensitivity, unsafe canonicalization, stale policy, or mismatched input fails closed.
6. A maintainer override is an explicit policy input with its own narrow rules; it is not an implicit bypass.
7. Policy decisions record reason codes and the effective policy version.

### Authorization flow

1. The runtime proposes an operation and its complete capability set.
2. Central canonicalizes selectors, normalized input, destination, purpose, sensitivity, and SecretReference IDs.
3. Central computes or verifies the normalized input hash and operation key.
4. The policy kernel evaluates baseline rules, Task intent, current grants, policy version, and hard denies.
5. Central durably records the requested capability and decision before adapter invocation.
6. On `require_approval`, Approval creation and the existing `approval` wait commit atomically.
7. On `allow`, or after an approved request is revalidated, the existing ToolCall becomes ready according to the approved domain lifecycle.
8. Central persists a prepared ToolCallAttempt before adapter invocation.
9. Immediately before protected use, expiry, revocation, policy version, scope, and reference status are rechecked.
10. The adapter receives only the authorization context needed for that exact operation.

Gate 3 decides the concrete call protocol. It may not let an adapter infer missing authority or accept a caller-provided `allow` flag without independently verifiable Central authorization context.

### Versioned profiles

A profile is a named, versioned UX bundle that expands to atomic capability requests. A Task policy snapshot records the profile version and expanded capabilities.

- Profiles contain no wildcard authority.
- UI displays the expanded capabilities before submission or approval.
- Updating a profile does not silently broaden an existing Task.
- A changed expansion creates new policy state and requires reevaluation.
- Production mutations and per-action-only effects cannot be converted into task grants by a profile.
- No `approve_all` or equivalent capability exists.

## Capability and approval defaults

| Operation | Phase 1 default | Maximum reusable scope |
| --- | --- | --- |
| Read inside canonical Workspace roots | Allow from the grant recorded at Task submission | Current Task, no more than 24 hours, exact Workspace roots |
| Read outside Workspace or cross Workspace | Deny | None |
| Create or modify an ordinary file in Workspace | Require approval | Current Task, no more than 24 hours, canonical path scope |
| Delete a file, change executable bit, or touch a protected path | Require approval | One operation key |
| Execute an arbitrary shell or process | Require approval | One operation key |
| Execute a bounded process in an enforcing environment | Require approval | Current Task, no more than 24 hours, exact executable/cwd/argument envelope and auxiliary capabilities |
| Agent-requested network connection | Deny without a specific exception | One operation by default; bounded Task grant only for exact protocol/destination/port/purpose |
| Agent-requested network listener | Deny | None |
| Database read | Require approval | Current Task, no more than 24 hours, exact connection/resource scope |
| Database mutation | Require approval | One operation key |
| DDL, administration, or destructive database action | Deny unless protected maintainer override permits the exact action | One operation key |
| Send selected context to a hosted model | Require explicit provider selection and egress disclosure | Current Task, no more than 24 hours, exact provider/resource scope |
| Use the selected provider credential | Derived from explicit provider selection | Current Task, no more than 24 hours, exact provider adapter/destination/purpose |
| Use another SecretReference | Require approval | Current Task, no more than 24 hours, exact reference/adapter/destination/purpose |
| Reveal a plaintext secret | Deny | None |
| Mutate a production-classified resource | Require approval | One operation key; never bundle-opened |
| Unknown sensitivity or unclassifiable operation | Deny or apply the production-strict rule when classification alone is unknown | No broader scope than the strictest applicable rule |

### Filesystem policy

- Workspace roots are canonical configuration, not user-controlled display paths.
- Every resource reference includes Workspace identity and is revalidated by the filesystem adapter.
- `..`, alternate path separators, device paths, symlink traversal, mount escape, case-folding ambiguity, and time-of-check/time-of-use behavior must be addressed for the target platform.
- Cross-Workspace object references and paths fail closed even for the same local user.
- Protected-path categories are policy configuration and require per-action approval.
- User-provided filenames never become object-storage keys and are sanitized before display.

### Process policy

- Direct executable invocation is distinct from an interpreter or shell command string.
- Shell interpreters, command strings, dynamic executable lookup, unbounded arguments, or uncontrolled environment make the request arbitrary and per-action.
- A bounded envelope names the exact executable identity, canonical working directory, permitted argument structure, environment policy, timeout, output bound, and all auxiliary capabilities.
- Secret values are never injected into a generic process through arguments, environment, stdin, files, or inherited descriptors in Phase 1.
- If filesystem or network access cannot be mediated, the approval UI must disclose the effective ambient authority and policy must evaluate it as composed privilege.

### Network policy

- Agent-requested network is denied unless a policy exception identifies protocol, destination, port, purpose, request bounds, and redirect behavior.
- Redirect to another origin, protocol, or port requires a new evaluation.
- DNS answers are checked against the approved destination class at connection time; rebinding must not turn a public approval into private access.
- Loopback, private, link-local, multicast, unspecified, and infrastructure-metadata destinations are denied to the agent plane.
- Registered system adapters use separate service identities and routes. Agent authority cannot reuse PostgreSQL, MinIO, provider, or control-plane connections.
- Selected model-provider traffic remains subject to `model_context.send` and `secret.use`; labeling it system traffic does not bypass egress consent.

### Database policy

- Database connections are registered resources with sensitivity and a secret-aware adapter.
- Queries use parameters for data values; credentials and sensitive parameters do not enter generic logs or Events.
- The adapter classifies operations as read, mutate, or admin before invocation and fails closed when safe classification is impossible.
- Reads require a bounded Task grant; writes require per-action approval.
- DDL, privilege changes, bulk destructive statements, and production administrative actions require an explicitly enabled maintainer override for one operation.
- No permission is weakened to make a test or Task succeed.

### Model-context egress policy

- Choosing a hosted provider is explicit user intent and creates a bounded Task grant for that provider only.
- The egress request declares which Workspace resource scope and sensitivity may be represented in context.
- Reading a resource locally never silently adds it to provider context.
- Context construction excludes plaintext secrets by design; scanning is defense in depth rather than the authority boundary.
- Provider responses are untrusted and cannot broaden the Task's capability set.
- A provider, destination, resource scope, or material sensitivity change requires reevaluation and, when needed, new approval.

## Approval and grant model

### Approval versus effective grant

The approved domain `Approval` remains an immutable historical decision with statuses `requested`, `approved`, `rejected`, or `cancelled`.

An approved decision may authorize an effective grant. Grant validity is evaluated separately and may end because of expiry, revocation, Task state, scope change, or policy tightening. Expiring or revoking authority does not rewrite the historical Approval status or decision Event.

Later persistence design must durably represent enough grant state to answer:

- which Approval or explicit Task-submission choice established it;
- subject Workspace and Task;
- atomic capabilities and canonical scopes;
- normalized intent or policy binding;
- issuance, expiry, revocation, and reason;
- whether it is task-scoped or per-action;
- the policy version last validated.

### Approval binding

Every Approval request displays and binds:

- Workspace, Task, current Run, ToolCall, and operation key when applicable;
- adapter, resource, effect, and canonical scope;
- normalized input hash;
- sensitivity and protected-resource classification;
- destination, protocol, port, redirect rule, and purpose when applicable;
- model provider and egress resource scope when applicable;
- non-sensitive SecretReference label and opaque ID when applicable;
- policy version and requested grant lifetime;
- composed auxiliary capabilities and the strictest resulting decision.

A changed input hash, operation key, capability, scope, destination, adapter, SecretReference, purpose, sensitivity, or materially changed policy cannot consume the old per-action authorization.

### Lifetime, retry, rerun, and revocation

- Every task-scoped grant has an explicit `expires_at` at most 24 hours after issuance.
- A task-scoped grant ends earlier when its Task completes or is cancelled, the grant is revoked, its scope or intent changes, or current policy is stricter.
- A failed Task cannot exercise a grant. If the local user explicitly retries that same Task before the authorization basis expires, Central may establish a revalidated grant for the new Run under the next rule.
- If an otherwise resumable Task reaches expiry, it enters the existing durable `approval` wait and requires a fresh decision.
- A retry inside the same Run retains the same operation key and may reuse the decision for that same logical ToolCall after revalidation.
- A new Run has new operation keys. Per-action approval does not transfer to them.
- An unexpired task-scoped authorization basis may be evaluated for a new Run of the same failed Task because its subject is the stable Task, but the new Run records a fresh effective grant and authorization decision linked to the original Approval or explicit Task choice.
- Running a cancelled Task creates a derived new Task and inherits no grant.
- Revocation and policy tightening affect the next protected use, including a Task already in progress.
- Reconciliation of one ambiguous operation may use its persisted authorization evidence to inspect or settle that same operation; it does not authorize a new side effect.

### Maintainer override

A maintainer override:

- is disabled unless protected local configuration enables the specific override class;
- requires an authenticated local maintainer action, exact operation binding, reason, and short expiry;
- is always per-action and produces dedicated audit evidence;
- cannot enable raw-secret reveal, cross-Workspace reference acceptance, unsafe canonicalization, or silent policy mutation;
- does not turn production mutation into a reusable profile or Task grant.

## SecretReference contract

### Identity and permitted metadata

SecretReference is a stable application-generated opaque ID owned by one Workspace. Human labels are mutable display metadata and never authority or backend lookup input by themselves.

Durable Central metadata may contain only:

- opaque SecretReference ID;
- owning Workspace ID;
- non-sensitive display label;
- declared purpose;
- allowed adapter and target classes;
- status such as `active`, `revoked`, or operator-repairable `unavailable`;
- opaque current version or safe fingerprint;
- created, rotated, revoked, and updated timestamps where applicable.

Durable Central metadata must not contain:

- secret value or recoverable ciphertext managed as a Central database secret;
- backend URI, backend account, environment-variable name, or raw backend secret name;
- authentication header, provider token, private key, password, or credential fragment;
- unsalted hash of secret material;
- sensitive value in a Task, prompt, Event, checkpoint, log, URL, Approval, object key, or Artifact metadata.

An opaque version should be supplied by the backend. If Central must derive a fingerprint, it uses a keyed construction with a protected audit key and never hashes the raw secret into a public or guessable identifier.

### Backend binding

The mapping from opaque SecretReference ID to backend and backend-native locator belongs to protected deployment configuration or another protected secret-binding store outside ordinary Task/Event/Artifact persistence.

- Bindings are explicit; there is no name-based discovery.
- Each reference has one active binding at a time.
- Resolver selection is configured, not agent-controlled.
- PostgreSQL and S3 do not store plaintext or Central-managed recoverable secret payloads under this design.
- The first local backend and its binding format are a follow-up implementation decision behind this contract.

### Resolve-and-use contract

Conceptually, a resolver accepts an authorization context containing:

- Workspace, Task, current operation, and policy version;
- SecretReference ID;
- registered secret-aware adapter identity;
- destination and purpose;
- current grant or Approval evidence.

The resolve-and-use flow is:

1. Validate Workspace ownership and exact reference identity.
2. Reevaluate grant expiry, revocation, current policy, adapter, destination, and purpose.
3. Validate the reference is active and has one configured protected binding.
4. Resolve the current backend version just in time inside the registered adapter boundary.
5. Use the value only for the authorized operation.
6. Remove credentials from requests, responses, errors, traces, and adapter results exposed outside that boundary.
7. Minimize copies and lifetime, then clear mutable buffers best-effort after use.
8. Persist only the opaque reference/version fingerprint, outcome, and sanitized reason.

Go and operating systems cannot guarantee perfect zeroization of every copy. The enforceable contract is minimized lifetime and copies, no durable plaintext, no generic-runtime return value, and no intentional exposure path.

### Secret-aware adapters

- A secret-aware adapter owns the protocol-specific use of a credential and never returns it.
- Model provider, database, and bounded HTTP integrations may become secret-aware only after registering their target and purpose semantics.
- Generic filesystem and generic shell/process adapters are not secret-aware in Phase 1.
- A response that reflects credentials must be stripped or treated as a security failure before it reaches the runtime.
- `secret.use` authorizes use only; it does not authorize data egress beyond the separately evaluated operation.

### Rotation, revocation, and deletion

- Rotation changes the backend version while preserving the logical SecretReference ID.
- An existing grant remains eligible after rotation only when reference, adapter, destination, and purpose bindings are unchanged and current policy still allows it.
- Every use records the current safe opaque version/fingerprint, so audit can identify which rotation was used without revealing it.
- Revocation is checked on every later resolution and fails closed immediately.
- Deletion removes the protected binding and retains only the permitted opaque tombstone and audit lineage according to retention policy.
- A revoked or deleted reference is never silently replaced by a similarly labeled reference.

### Failure behavior

| Condition | Durable behavior | Retry or repair |
| --- | --- | --- |
| Reference missing, revoked, or binding unavailable and operator can repair intent/configuration | Existing `external_input` wait with a sanitized condition | Resume only after explicit repair and full reevaluation |
| Approval missing or task grant expired | Existing `approval` wait | Resume only after a new durable decision |
| Protected backend temporarily unavailable before use | Existing bounded `retry_delay` when safe | Retry resolution only; do not substitute another secret |
| Policy, scope, adapter, destination, or purpose mismatch | Structured denial | No retry without changed policy or explicit new action |
| Secret may have been disclosed | Structured security failure and revocation/rotation guidance | Never continue by redaction alone |
| External operation outcome ambiguous after secret use | Existing `reconciliation` wait | Inspect the same operation; never invoke blindly |

No failure path falls back to an environment variable, raw Task input, another reference, another backend, or interactive secret reveal.

## Local UI and API baseline

Phase 1 local authentication establishes that a request comes through the intended local operator session. It does not introduce users, roles, organizations, or remote identity.

- The service binds only to loopback addresses by default and rejects wildcard or LAN binding under the Phase 1 topology.
- Startup creates or reads a high-entropy bootstrap token through protected configuration or a permission-restricted local file.
- The bootstrap token is exchanged in a request body or protected header for a bounded session; it never appears in a URL, referrer, log, Event, or HTML artifact.
- The session cookie is `HttpOnly`, `SameSite=Strict`, path-scoped, bounded in time, and `Secure` when TLS is used.
- Every state-changing request uses CSRF protection and validates the expected Host and Origin policy.
- Approval and override endpoints require the authenticated local session and bind the submitted decision to the displayed Approval and operation.
- Session and bootstrap failures do not downgrade to anonymous access.
- Exact entropy, storage path, rotation, idle timeout, and absolute session lifetime are resolved before the local UI implementation plan.

## Separate system and agent authority planes

Central's own infrastructure connections do not become capabilities that an agent can borrow.

System-owned operations include registered service startup, PostgreSQL repositories, MinIO artifact storage, and the configured provider transport. Each uses a least-privileged identity and a fixed adapter purpose.

Agent-requested operations always enter through the capability model. The agent cannot:

- obtain a repository or object-storage connection handle;
- reuse a provider credential for arbitrary HTTP;
- reach internal services merely because Central can reach them;
- convert `model_context.send` into generic network authority;
- convert `secret.use` into provider-independent credential use.

## Durable security flows

### Privileged ToolCall

1. The agent proposes an action; proposal content remains untrusted.
2. Central creates the canonical ToolCall identity, normalized input hash, operation key, and complete capability request.
3. The policy service records its versioned decision before adapter invocation.
4. On `deny`, Central records a structured denied outcome and never invokes the adapter.
5. On `require_approval`, Central creates Approval and waiting state with reason `approval` in one transaction.
6. A local authenticated actor approves or rejects the exact request.
7. On approval, Central reevaluates policy and effective grant state, then makes the ToolCall ready according to the approved lifecycle.
8. Central persists the prepared ToolCallAttempt before leaving PostgreSQL transaction scope.
9. The adapter reevaluates use-time constraints and performs only the authorized operation.
10. Central persists known outcome, retry state, reconciliation state, and append-only Events.

No external call occurs inside an open PostgreSQL transaction.

### Hosted model call

1. Task submission or later local action selects the hosted provider.
2. Central records bounded provider egress and provider-credential grants.
3. Context construction records the authorized Workspace resource scope and sensitivity, excluding plaintext secrets.
4. Policy reevaluates `model_context.send` and `secret.use` for the provider adapter.
5. The adapter resolves the provider credential and sends context to the exact configured destination.
6. The adapter strips credential material from response and errors.
7. Central treats provider output as untrusted and records sanitized egress evidence.

### Grant expiry while waiting or running

1. Before the next protected use, Central observes that the grant is expired or invalid.
2. It does not invoke the adapter.
3. If a new user decision can authorize the same request, affected execution enters waiting with reason `approval`.
4. A new Approval captures current policy, scope, and expiry.
5. The same safe Run resumes only after durable resolution evidence and a new claim.

### Secret backend outage

1. Authorization succeeds but the protected backend reports a known transient availability failure before use.
2. Central records a sanitized retryable failure and bounded retry policy.
3. Affected execution uses `retry_delay` and releases execution ownership.
4. Retry resolves the same reference and authorization context; it does not substitute a value.
5. If delivery may have occurred, the operation uses `reconciliation` rather than retry.

### Ambiguous privileged effect

The approved ToolCall idempotency and reconciliation rules remain authoritative. Authorization evidence permits only investigation and settlement of the same operation. It never justifies blind reinvocation or a new operation key.

## Security audit and redaction

### Durable evidence model

Security-relevant accepted facts are append-only Events or immutable security-audit records linked to those Events. Normalized rows remain authoritative for current policy, grant, Approval, reference, and lifecycle state; audit evidence is not a second current-state model and does not introduce pure event sourcing.

An audit record contains only the fields applicable to its event:

- audit/Event ID and timestamp;
- Workspace, Task, Run, Step, ToolCall, and operation key references;
- actor type and safe actor identity;
- registered adapter and event type;
- capability, effect, canonical or safely redacted scope, and sensitivity;
- decision, structured reason code, and policy version;
- Approval ID, grant class, expiry, revocation, or override reason;
- destination class and safe canonical target;
- SecretReference ID and safe opaque version/fingerprint;
- correlation, causation, retry, and reconciliation references;
- known execution outcome.

Required event families include:

- authorization requested, allowed, approval-required, and denied;
- Approval requested, approved, rejected, cancelled, expired-effective-grant, and revoked-effective-grant;
- maintainer override requested and used;
- model-context egress;
- SecretReference resolve success or failure, rotation, revocation, and deletion;
- adapter invocation prepared, known success, known failure, ambiguous outcome, retry, and reconciliation.

An effective grant expiry does not invent an `expired` Approval status. Audit describes grant invalidation while preserving the historical Approval decision.

### Prohibited audit and telemetry content

Logs, Events, metrics, traces, Approval payloads, checkpoints, and audit records must not contain:

- plaintext secret, session token, bootstrap token, authentication header, or private key;
- environment value, database credential, or backend-native secret locator;
- unrestricted prompt, tool body, database parameters, command environment, network response, or Artifact body;
- raw URL query, unsafe filename, or unsanitized object key;
- unbounded user-controlled values as metric labels.

Sensitive resource selectors may be represented by safe display text and stable keyed fingerprints when full paths or destinations are unnecessary for durable audit.

### Redaction controls

- Redaction occurs at the source boundary before values enter generic error, Event, or logging types.
- Structured safe fields are preferred to free-form messages.
- Error wrapping must not reintroduce adapter request bodies or credentials.
- Secret-pattern scanning and sentinel tests are defense in depth, not the primary isolation mechanism.
- Debug mode cannot disable secret redaction or emit raw credentials.
- Suspected disclosure produces a security failure and rotation guidance rather than silently continuing.

## Artifact and resource-safety baseline

- Artifact bodies are untrusted regardless of producer.
- Object keys contain opaque IDs only; original filenames are sanitized display metadata.
- Browser delivery uses explicit content type, disables MIME sniffing, and defaults to safe download disposition.
- Inline preview is restricted to allowlisted formats after format-specific sanitization; executable or active content is not rendered directly.
- Adapters apply configured timeouts, maximum input/output or response sizes, concurrency bounds, and budget limits.
- Limit violations produce structured failures and do not silently truncate security-relevant decisions.
- Exact limits and quotas are Gate 3 or adapter implementation decisions and must be fixed before those implementation plans begin.

## Validation strategy

Phase 0 validates design completeness and consistency. Phase 1 must add executable unit, integration, failure-injection, and UI security tests.

### Policy contract tests

- canonical equivalent requests produce the same security identity;
- a changed semantic input cannot reuse an operation key or Approval;
- missing capability, malformed scope, cross-Workspace identity, and unknown sensitivity fail closed;
- strictest composition controls a multi-capability operation;
- profiles expand to visible atomic capabilities and cannot override per-action rules;
- grant expiry, revocation, Task completion/cancellation, failed-state suspension, and policy tightening block the next use;
- task-scoped and per-action authorization survive only the retry boundaries defined here.

### Adapter security tests

- filesystem traversal, absolute-path escape, symlink escape, and replacement races are rejected;
- process envelopes reject executable, cwd, argument, environment, and auxiliary-capability drift;
- network redirect, new origin, DNS rebinding, loopback/private/link-local/metadata targets, and oversized responses fail closed;
- database adapter distinguishes read, mutation, and admin operations and denies unknown classification;
- provider context cannot be sent under filesystem read authority alone;
- an agent cannot obtain or reuse system adapter credentials or handles.

### SecretReference tests

- cross-Workspace reference use is rejected;
- only the bound adapter, destination, and purpose can resolve;
- generic shell/process cannot consume a secret;
- rotation preserves identity and records the new opaque version;
- revocation blocks the next resolution even during a running Task;
- missing binding, transient backend failure, denial, and ambiguous effect map to the specified durable behavior;
- no fallback path is attempted;
- sentinel secret values are absent from Task, prompt, Event, checkpoint, log, trace, Approval, URL, object key, and Artifact metadata fixtures.

### Local UI tests

- non-loopback and unexpected Host/Origin requests are rejected;
- bootstrap token never appears in URL, HTML, redirect, referrer, or log fixtures;
- unauthenticated, expired-session, and missing/invalid-CSRF state changes fail closed;
- Approval mutation cannot alter the canonical request displayed to the operator;
- Artifact active content is downloaded safely or sanitized before an allowlisted preview.

### Durable failure tests

- crash before adapter invocation resumes without claiming an effect occurred;
- crash after possible delivery enters reconciliation and never blind retries;
- Approval and wait state survive restart;
- grant expiry during waiting or before use returns to durable approval;
- secret backend outage uses bounded retry without substitution;
- a new Run cannot reuse a prior per-action approval;
- a derived Task from a cancelled Task inherits no grant.

## Representative abuse-case validation

| Scenario | Expected result |
| --- | --- |
| Repository text instructs the model to upload files | Content has no authority; model egress/network capability is denied or waits for exact approval |
| Agent reads an allowed file then adds it to hosted-provider context | Separate egress evaluation discloses provider, scope, and sensitivity before send |
| Approved write path is replaced by a symlink | Adapter revalidation detects escape and denies without writing outside Workspace |
| Approval request is replayed with another destination or input | Canonical binding mismatch denies and requires a new Approval |
| Public URL redirects to a private address | Redirect or resolved-address change triggers reevaluation and private target denial |
| Agent asks shell to print a provider credential | Generic process cannot resolve SecretReference and raw reveal is a hard deny |
| Secret rotates during a long Task | Same logical reference resolves current version after revalidation; audit records the new safe fingerprint |
| Secret is revoked before the next provider call | Use-time check fails closed and enters repairable external input or structured failure according to policy |
| Production database update appears in a profile | Profile cannot bundle it; exact operation requires per-action approval |
| Provider call times out after uncertain delivery | Operation enters reconciliation rather than blind retry |
| Malicious HTML Artifact is opened | Safe download or sanitized allowlisted preview prevents direct active-content execution |

## Documentation and ADR work implied by this design

Gate 2 implementation planning must create and align:

1. `docs/security/threat-model.md` as the canonical threat/control/residual-risk register;
2. `docs/security/capability-policy.md` as the canonical capability, scope, default, Approval, and grant contract;
3. `docs/security/secret-reference.md` as the canonical reference and resolver contract;
4. a new Proposed ADR for the policy kernel, security trust boundary, privileged-capability model, and secret-access model;
5. the ADR index entry, followed by a separate explicit maintainer acceptance or rejection commit;
6. architecture and current-phase summaries that link to canonical details without duplicating them;
7. a Gate 2 validation report distinguishing approved contracts from unimplemented runtime controls;
8. roadmap/prototype status only after Gate 2 validation actually passes.

ADR governance requires a new ADR because this design selects security and trust boundaries plus privileged-capability and secret-access models. Dependent Gate 3 security protocol design and all runtime/schema/API implementation based on these decisions remain blocked until that ADR is Accepted and Gate 2 validation passes.

## Follow-up decisions

| Decision | Owner | Decision due | Must be resolved before |
| --- | --- | --- | --- |
| First protected local secret backend and binding format | Security implementation specification owner | 2026-07-20 | Secret resolver adapter implementation plan |
| Capability request, decision, and grant Go/API serialization | Gate 3 runtime specification owner | 2026-07-20 | Agent/tool runtime implementation plan |
| Filesystem descriptor-relative or equivalent target-platform enforcement | Filesystem adapter specification owner | 2026-07-20 | Filesystem adapter implementation plan |
| DNS pinning/rebinding enforcement and canonical destination algorithm | Network adapter specification owner | 2026-07-20 | Network adapter implementation plan |
| Bootstrap entropy, protected path, exchange lifetime, idle timeout, and absolute session duration | Local UI/API specification owner | 2026-07-20 | Local UI implementation plan |
| Adapter-specific time, size, concurrency, and spend defaults | Gate 3 runtime specification owner | 2026-07-20 | Execution-loop implementation plan |
| Security audit retention and SecretReference tombstone retention | Persistence and security specification owners | 2026-07-20 | Security schema and cleanup implementation plan |

These decisions may select implementation details behind this contract. A choice that changes a trust boundary, authority model, raw-secret prohibition, or approval semantics requires ADR review rather than silent implementation.

## Acceptance criteria for this specification

- Assets, actors, assumptions, trust boundaries, threats, controls, residual risks, and phase owners are explicit.
- Untrusted content cannot grant capability or alter policy.
- The canonical authority model is `resource × effect × scope` with deterministic fail-closed outcomes.
- Capability composition applies the strictest result and profiles remain non-authoritative UX bundles.
- Filesystem, process, network, database, model egress, and secret-use defaults are complete.
- Production mutations are per-action and unknown sensitivity fails closed or receives the strictest rule.
- Approval binding prevents input, destination, scope, SecretReference, and policy substitution.
- Approval history remains immutable while effective grants can expire or be revoked.
- Retry, new Run, cancelled-Task rerun, and reconciliation behavior matches the approved domain model.
- SecretReference is opaque and Workspace-scoped, with no durable plaintext, backend locator, raw reveal, generic-process injection, or fallback path.
- Rotation, revocation, deletion, missing binding, backend outage, denial, and ambiguous outcomes have deterministic behavior.
- Model context egress is independent from local read access.
- Local UI baseline covers loopback binding, bootstrap exchange, bounded session, CSRF, and Host/Origin validation without introducing RBAC.
- System-owned and agent-requested authority planes are separate.
- Audit and redaction requirements provide traceability without creating a secondary secret store.
- Artifact active-content and resource-exhaustion threats have explicit baseline controls and owners.
- Validation scenarios cover prompt injection, path escape, approval substitution, egress, redirects, secrets, grant lifecycle, production mutation, durable retry, and local UI controls.
- Gate 3 interfaces and Phase 1 implementation remain explicitly out of scope and blocked on the required Accepted ADR and Gate 2 validation.

## Risks

- A detailed capability model can create approval fatigue. Profiles and task-scoped grants may reduce friction only within the hard maximums and visible atomic expansion defined here.
- Treating unknown sensitivity as strictest may initially block legitimate work. Resource classification must be simple and explicit rather than weakening the fallback.
- Generic process execution can bypass conceptual auxiliary capabilities if Phase 1 lacks actual mediation. Gate 3 must either enforce the declared envelope and access controls or disclose and authorize the ambient composite privilege.
- Secret-aware adapters reduce exposure but become high-value trusted components. Their interfaces, response filtering, and failure paths require focused review and tests.
- A 24-hour maximum grant may interrupt long-running Tasks. Durable approval waiting is the intentional safe fallback.
- Loopback binding narrows exposure but does not defend against malware running as the trusted OS account. Documentation must not overstate the local-auth guarantee.
- Application-layer append-only audit is useful evidence but not tamper-proof against a database administrator. Stronger audit integrity belongs to a later explicit requirement and ADR if adopted.

## Gate 2 completion boundary

Approval of this design authorizes writing the implementation plan for Gate 2 documentation and ADR work. It does not itself mark Gate 2 or Phase 0 complete.

Gate 2 completes only after:

- the canonical security documents are written and cross-linked;
- the required ADR is Proposed and then explicitly Accepted in its own status-transition commit;
- documentation and focused repository checks pass;
- the validation report records scenario evidence and remaining risks;
- summaries mark runtime controls as planned rather than implemented;
- the roadmap/current-phase status is updated from Gate 2 ready to Gate 2 complete only after the evidence passes.

Only then may Gate 3 consume these security contracts as accepted architecture.
