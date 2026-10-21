# Checkpoint Recovery Contract

## Authority and status

This is the canonical Gate 3 checkpoint recovery contract for the Central project. It defines the Checkpoint envelope, creation boundary, size policy, compatibility verification, migration, resume flow, failure behavior, and validation scenarios for Phase 1.

These contracts were adopted by Accepted ADR 0004 and passed Gate 3 design-contract validation. This document makes no runtime implementation claim. Phase 0 validated it through contract walkthroughs and repository checks. Phase 1 realizes it behind domain-owned interfaces without changing meaning.

This contract consumes ADR 0004 (staged single-agent runtime and verified adapter handoffs), ADR 0001 (durable Task domain and lifecycle), and ADR 0003 (security policy and SecretReference model). The [Agent runtime contract](agent-runtime.md) owns AgentDefinition, provider-operation semantics, the local executor, retry and budget policy, and shared scenarios. The [Tool invocation contract](tool-invocation.md) owns the ToolCall lifecycle, authorization-use fence, secret-aware adapter handoff, and reconciliation. This document owns Checkpoint creation, compatibility, migration, and resume and cross-references shared scenarios rather than renumbering them.

## Envelope

A Checkpoint is immutable verified continuation evidence for completed logical work and the next safe action. The envelope records:

- immutable Checkpoint ID and schema version;
- producer identity, producer version, and supported reader range;
- Workspace, Task, Run, Step, and producing StepAttempt identities;
- completed logical work and next safe action;
- ready Artifact references and relevant operation evidence;
- AgentDefinition revision and policy/configuration compatibility fingerprints;
- SHA-256 integrity checksum and creation timestamp;
- inline continuation payload or Artifact reference for larger state.

The envelope contains no plaintext secret, no unrestricted provider/tool body, and no ambient process state. Agent instructions, provider output, tool proposals, tool results, and Artifact content are untrusted data; none enter the envelope except as safe references or fingerprints. The envelope records what was completed and what comes next; it never carries authority, capability, or a grant.

## Creation boundary

A Checkpoint commits only after all preceding effects have known durable outcomes.

- Every prior provider attempt and ToolCallAttempt has a known terminal outcome (`succeeded`, `known_failed`, `cancelled`) or has been reconciled to a terminal state.
- No Checkpoint crosses an unresolved ambiguous operation. If any preceding operation is in `reconciliation` with an unknown outcome, no Checkpoint is created until that ambiguity resolves.
- A later safe boundary creates a new Checkpoint; prior evidence is immutable and is never rewritten, extended, or merged.
- A Checkpoint records the state of durable work at its creation instant; nothing about it changes after commit.

## Size policy

| Control | Default | Phase 1 hard maximum | Scope |
| --- | --- | --- | --- |
| Inline Checkpoint payload | 256 KiB | 1 MiB | Per Checkpoint; larger state uses an Artifact reference |

Continuation state at or below 256 KiB is stored inline in the envelope. State above 256 KiB but at or below 1 MiB is permitted as an inline payload when installed policy allows the higher value. State above 1 MiB requires an Artifact reference; the envelope then carries the Artifact identity and checksum instead of the payload body.

Installed policy may choose a value at or below the hard maximum. A value above the hard maximum is rejected. Changing the hard maximum is a material Gate 3 contract change and requires ADR review. Gate 4 may impose stricter Artifact object or staging limits on the referenced body.

## Compatibility

On resume, the runtime verifies the Checkpoint before using any continuation data. Compatibility checks, in order:

1. **Checksum**: Recompute the SHA-256 over the envelope and confirm it matches the recorded checksum.
2. **Ownership**: Confirm the claiming executor holds the persisted ownership lease for the Run.
3. **Schema and reader range**: Confirm the current runtime reader version falls within the Checkpoint's supported reader range and the schema version is recognized.
4. **Producer**: Confirm the producer identity and version are known and accepted.
5. **AgentDefinition**: Confirm the AgentDefinition revision recorded in the Checkpoint matches the Run's snapshot exactly.
6. **Policy**: Confirm the policy and configuration fingerprints recorded in the Checkpoint match the current effective policy, or that only a supported migration path applies.
7. **Artifact readiness**: Confirm every Artifact referenced by the Checkpoint is present, ready, and verified.
8. **Operation evidence**: Confirm the recorded completed work and operation evidence are consistent with the durable state in PostgreSQL.

Every check must pass. The first failing check produces a structured incompatibility reason and stops the resume.

## Migration

A supported migration transforms one Checkpoint's continuation state to a new envelope under a different schema version, AgentDefinition revision, or policy fingerprint while preserving the source.

- Migration produces a new verified Checkpoint with its own immutable ID, updated schema version, updated fingerprints, and a fresh SHA-256 checksum.
- The source Checkpoint is preserved unchanged; it is never rewritten or deleted.
- Migration is performed only by a registered migration path declared by the producer. An unrecognized schema or revision combination has no migration and fails as incompatible.
- A migrated Checkpoint must pass the full compatibility verification before it is usable for resume.
- Migration never introduces plaintext secrets, unrestricted bodies, or ambient process state into the new envelope.
- A migrated Checkpoint records its source Checkpoint ID in its lineage for auditability.

## Resume flow

When a Run requeues after a restart, durable wait, or recovery, the resume flow reconstructs continuation state from a verified Checkpoint:

1. **Claim**: A local executor atomically claims the Run and persists ownership (see [Agent runtime contract — Local executor ownership](agent-runtime.md)).
2. **Validate**: The runtime performs the full compatibility verification (see [Compatibility](#compatibility) above).
3. **Reconstruct without replay**: The runtime rebuilds context from the Checkpoint's completed work, next safe action, ready Artifact references, and operation evidence. Resume reconstructs known completed work without replay of any external effect. No provider, tool, or adapter is re-invoked for work the Checkpoint records as complete.
4. **Revalidate authority**: Before any new external invocation, the runtime revalidates policy, grant, Approval, sensitivity, AgentDefinition, adapter, and SecretReference state in full (see [Agent runtime contract — Cancellation and restart](agent-runtime.md)). A Checkpoint does not carry authority; every authorization decision is re-derived from current durable state.

A valid resume continues from the recorded next safe action. The Run's logical identities, budgets, and counters are not reset by resume.

## Failure behavior

| Failure class | Runtime behavior |
| --- | --- |
| Corrupt Checkpoint (checksum mismatch, unreadable) | Structured failure; the Run fails or enters `external_input` for operator repair. No silent replay. |
| Incompatible Checkpoint (schema, reader range, producer unknown) | Structured incompatibility failure; no resume. Operator may create a new Run or apply a supported migration. |
| Missing Artifact referenced by Checkpoint | Structured failure; the Checkpoint cannot resume without its referenced ready Artifacts. No continuation. |
| Policy mismatch (AgentDefinition or policy fingerprint changed) | Structured failure; stale authority is blocked. Operator may create a new Run with current policy or apply a supported migration. |
| Ambiguous predecessor operation | No Checkpoint exists across an ambiguous boundary. If recovery discovers an unresolved ambiguous operation preceding a recorded Checkpoint, the Checkpoint is treated as invalid and the runtime follows reconciliation rules. |

In every failure class the runtime must never silently restart completed work. A structured reason names the specific incompatibility, corruption, missing reference, or mismatch. The operator or installed policy decides whether to create a new Run, repair the reference, or apply a migration. No failure path re-invokes a provider, tool, or adapter for work already recorded as complete.

## Validation contract

The following validation scenarios are owned by the Checkpoint recovery contract. They are validated in Phase 0 as contract walkthroughs and repository checks. Phase 1 implements them with fake provider, tool, policy, resolver, clock, and object-store adapters plus failure injection.

| Scenario | Rule |
| --- | --- |
| R14 | Valid Checkpoint resumes after completed work without replay. |
| R15 | Corrupt, incompatible, or policy-mismatched Checkpoint fails safely. |

Cross-referenced scenarios with Checkpoint aspects:

| Scenario | Checkpoint aspect | Owner |
| --- | --- | --- |
| R20 | Sentinel secret is absent from Checkpoint surfaces; the envelope carries no plaintext secret. | [Tool invocation contract](tool-invocation.md) |
| R24 | Restart after policy tightening revalidates the Checkpoint policy fingerprint and blocks stale authority. | [Agent runtime contract](agent-runtime.md) |

Additional contract rule:

| Rule | Description |
| --- | --- |
| CM-1 | Supported migration produces a new verified Checkpoint while preserving the source; an unsupported migration path fails as incompatible without silent data loss. |

Scenarios R01 through R13, R16 through R19, R21 through R23, and R25 through R27 are owned by the [Agent runtime contract](agent-runtime.md) and the [Tool invocation contract](tool-invocation.md). They are cross-referenced here, not renumbered.
