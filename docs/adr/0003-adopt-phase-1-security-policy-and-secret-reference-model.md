# ADR 0003: Adopt the Phase 1 security policy and SecretReference model

- **Number:** 0003
- **Title:** Adopt the Phase 1 security policy and SecretReference model
- **Status:** Accepted
- **Created:** 2026-07-13
- **Owners:** Central maintainer
- **Decision due:** 2026-07-20
- **Decision due history:** None
- **Implementation blocked at:** Gate 3 capability, authorization, SecretReference-resolver, and privileged-adapter protocol design; dependent runtime, schema, API, adapter, and UI implementation remains blocked until ADR 0003 is Accepted and Gate 2 validation passes
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-14
- **Decision record:** Git status-transition commit; exact hash resolved by this file's Git history
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** [approved Gate 2 security design](../internal/superpowers/specs/2026-07-13-phase-0-security-baseline-secret-reference-design.md), [Gate 2 implementation plan](../internal/superpowers/plans/2026-07-13-phase-0-security-baseline-secret-reference.md), [ADR governance](README.md), [ADR 0001](0001-adopt-durable-task-domain-and-lifecycle.md)

## Context

ADR 0001 makes Workspace the Phase 1 isolation boundary, persists capability decisions before adapter invocation, and models Approval as durable. Gate 2 must decide the trust boundary, capability authority, local authentication assumptions, model-context egress, Approval defaults, and secret-access model required before Gate 3 can define runtime and privileged-adapter protocols.

Phase 1 runs one local Central instance for one trusted operating-system account. The local operator is trusted, but Task text, repository and document content, model output, tool output, network responses, and Artifacts are not authority. Without one fail-closed policy boundary, prompt injection or a confused deputy could compose filesystem, process, network, database, model, and credential access into unintended effects.

Credentials require a stable identity that durable Task state can reference without putting plaintext, backend locators, or raw secret names into PostgreSQL, S3-compatible storage, prompts, Events, logs, checkpoints, Approval payloads, or generic tools.

## Decision

Central adopts the following Phase 1 local security model:

- HTTP binds to loopback for one trusted local OS account and still uses bootstrap-token exchange, bounded session, CSRF protection, and Host/Origin validation.
- Model, agent, Task, repository, document, tool, network, and Artifact content is untrusted data that can propose but never grant authority.
- The canonical capability model is `resource × effect × scope`.
- Policy returns exactly `allow`, `require_approval`, or `deny`; the strictest result controls composed capability and unknown security state fails closed.
- Workspace read is granted only inside canonical Workspace roots and never implies hosted-model context egress.
- Filesystem mutation, process execution, network access, database access, model egress, and secret use receive the bounded defaults and sensitivity rules in the linked Gate 2 design and canonical security documents.
- Approval remains durable historical evidence. Effective grants are separate authority that can expire or be revoked without rewriting Approval state.
- Task-scoped grants expire no later than 24 hours after issuance. Production mutations and other per-action effects remain bound to one operation key.
- Agent-requested traffic and system-owned PostgreSQL, MinIO, provider, and control connections use separate authority planes.
- SecretReference is a stable opaque Workspace-scoped logical identity, not a secret value, backend locator, environment-variable name, or raw backend secret name.
- Secret material remains outside PostgreSQL and S3 behind an explicitly configured protected resolver backend.
- Secret resolution occurs just in time inside an authorized secret-aware adapter for the exact reference, adapter, destination, and purpose.
- There is no raw-secret reveal capability, generic-process secret injection, name discovery, or fallback reference/backend.
- Rotation preserves logical identity when bindings remain unchanged; revocation blocks every later use.
- Capability, Approval, override, secret-use, egress, adapter-effect, retry, and reconciliation evidence is durable and append-only at the application layer without persisting plaintext secrets or unrestricted content.

The approved Gate 2 design owns the detailed security semantics. The canonical threat, capability, and SecretReference documents created under this plan organize those semantics by responsibility.

### Decision boundary

This ADR does not select:

- concrete Go types, API payloads, database tables, or Event schemas;
- Agent, Subagent, Worker, scheduler, tool transport, or authorization-token protocol;
- first protected local secret backend or binding format;
- process sandbox, descriptor-relative filesystem implementation, DNS rebinding algorithm, or database classifier;
- exact resource, session, retry, output, concurrency, or spend limits;
- LAN, remote, multi-user, Online Mode, or enterprise security architecture.

Those decisions must preserve this authority and secret-access model or use a later ADR to change it.

## Consequences

### Benefits

- Untrusted content cannot silently acquire tool or data authority.
- One composable model covers filesystem, process, network, database, model egress, and credential use.
- Approval is exact, durable, restart-safe, expiring, and auditable without changing ADR 0001 lifecycle meaning.
- Workspace read and hosted-provider egress remain independently visible choices.
- Credentials can rotate and revoke without embedding values or backend identities into durable Task state.
- Gate 3 receives one security contract instead of adapter-specific policy models.

### Costs and limitations

- Fine-grained capability and sensitivity classification adds policy and Approval UX work.
- A 24-hour task-grant maximum can interrupt long-running Tasks and require durable reapproval.
- Secret-aware adapters become high-value trusted components requiring focused tests and response filtering.
- Policy gating alone does not sandbox an arbitrary process; Gate 3 must enforce or accurately disclose ambient authority.
- Loopback authentication does not defend against malware running under the trusted OS account.
- Phase 1 audit evidence is not cryptographically tamper-proof against a database administrator.

## Alternatives considered

### Risk tiers as canonical authority

Rejected because a low, medium, high, or critical label hides material differences among resource scope, destination, effect, sensitivity, egress, and SecretReference purpose. Risk labels may remain UX hints.

### Adapter-owned authorization

Rejected because independent filesystem, shell, network, database, and provider policy creates inconsistent defaults and unsafe cross-capability composition.

### Store encrypted secret values in PostgreSQL

Rejected because Central would become a secret store, expand key-management and recovery scope, and create a durable plaintext-recovery path contrary to the local SecretReference boundary.

### Pass secrets to generic processes

Rejected because argument, environment, stdin, file, and inherited-descriptor injection lets agent-controlled processes reveal or repurpose credentials.

## Follow-ups

- Security specification owner creates the canonical threat model, capability policy, and SecretReference contract before ADR acceptance review.
- Architecture owners align overview, durable-execution, current-phase, and documentation-index summaries before ADR acceptance review.
- Central maintainer explicitly accepts or rejects this ADR after proposal and alignment checks; prior design approval is not the ADR decision.
- Security implementation specification owner selects the first protected local secret backend and binding format by `2026-07-20`, before its adapter implementation plan.
- Gate 3 runtime specification owner defines capability request, grant, resolver, and privileged-adapter protocols by `2026-07-20`, before runtime implementation planning.
- Gate 2 validation owner records contract-walkthrough evidence after acceptance and before Gate 3 begins.

## References

- [Phase 0 Security Baseline and SecretReference Design](../internal/superpowers/specs/2026-07-13-phase-0-security-baseline-secret-reference-design.md)
- [Phase 0 Security Baseline and SecretReference Implementation Plan](../internal/superpowers/plans/2026-07-13-phase-0-security-baseline-secret-reference.md)
- [ADR governance and index](README.md)
- [ADR 0001 — Adopt the durable Task domain and lifecycle](0001-adopt-durable-task-domain-and-lifecycle.md)
- [Durable execution](../architecture/durable-execution.md)
