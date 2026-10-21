# ADR 0011: Amend local topology for dedicated migration operator

- **Number:** 0011
- **Title:** Amend local topology for dedicated migration operator
- **Status:** Superseded
- **Created:** 2026-07-21
- **Owners:** Central maintainer
- **Decision due:** 2026-07-28
- **Decision due history:** None
- **Implementation blocked at:** B05 implementation planning and code that creates the `central-migrate` identity, delivers `central_migration` credentials, or exposes `central migrate reset`.
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-21
- **Decision record:** Git status-transition commit
- **Supersedes:** ADR 0010
- **Superseded by:** ADR 0014
- **Amends:** ADR 0008
- **Amended by:** None
- **Related:** [ADR 0010](0010-reassign-gate-9-executable-slices-to-phase-1.md), [PostgreSQL persistence contract](../persistence/postgresql.md), [Local development environment](../architecture/local-development-environment.md), [B05 design](../internal/superpowers/specs/2026-07-21-phase-1-b05-version-zero-provisioning-design.md), [ADR governance](README.md)

## Context

The accepted local topology has three locked host identities and permits the Central host binary to receive the `central_migration` credential only for migration and restore-apply invocations. B05 needs a narrower, separately auditable consumer identity for the version-zero migration credential and an explicit recovery path when an exact version-zero baseline cannot be verified.

Both changes affect locked trust boundaries and command authority. ADR governance therefore requires an ADR; because ADR 0010 is the active amendment of ADR 0008, acceptance must replace that amendment rather than modify it in place.

## Decision

This ADR supersedes ADR 0010 as an overlapping replacement amendment of ADR 0008. It retains every ADR 0010 decision except these explicit changes:

- Add `central-migrate` as a fixed numeric, no-login host identity. It can run only the Central migration operator mode and cannot run `central serve`, access Workspace roots, Docker, the protected-store path, or broker authority beyond its bound handoff session.
- The broker delivers `central_migration` only to a verified `central-migrate` peer for the invocation lifetime through the existing framed SCM_RIGHTS handoff. The receiving process reads from the descriptor and never opens a credential path by name. The descriptor is closed on command completion, failure, or cancellation.
- Add `central migrate reset` as a version-zero-only destructive recovery command. It requires fresh PAM and helper-owned TTY confirmation of `RESET VERSION-ZERO <full-instance-id> <full-target-id> <operation-id>`. It is denied unless the external record is the exact failed B05 provisioning operation and PostgreSQL contains no capability table or user data. It reacquires B05's exclusive lock order, removes only the B05 baseline and exact protected provisioning/candidate state, records the destructive operation in the authority journal, and requires a subsequent `central migrate up`. No generic yes flag, force option, path selector, or initialized-target reset is permitted.

The retained ADR 0010 decision clauses remain in force by reference. This acceptance updates reciprocal ADR/index metadata atomically, as required by ADR governance.

## Consequences

### Benefits

- Separates migration authority from the serving runtime identity.
- Makes version-zero destructive recovery explicit, confirmation-bound, and unavailable once user data could exist.
- Reuses B04's verified descriptor handoff rather than introducing plaintext credential delivery.

### Costs and limitations

- Replacing the active amendment requires a complete governance review and atomic status transition.
- `migrate reset` is intentionally not a general database repair or wipe mechanism.

## Alternatives considered

### Reuse `central-runtime`

Rejected. It broadens the serving process identity's credential reach and weakens separation of duties.

### Use the existing full-instance wipe flow

Rejected. It is deferred to Slice D and destroys more state than a failed, data-free version-zero provisioning attempt requires.

### Root-owned migration credential path

Rejected. It conflicts with least-privilege credential ownership and the B04 descriptor-handoff model.

## Follow-ups

- The B05 owner must maintain the retained ADR 0010 semantics while implementing this narrowly scoped amendment.
- The B05 acceptance review must confirm the chosen migration identity and reset command do not broaden any other topology authority.
- B05 owner: implement the selected broker, Compose fixture, and recovery semantics only after acceptance.

## References

- [B05 Version-Zero Provisioning Design](../internal/superpowers/specs/2026-07-21-phase-1-b05-version-zero-provisioning-design.md)
- [B05 Spec Review](../internal/superpowers/reviews/2026-07-21-phase-1-b05-version-zero-provisioning-spec-review.md)
- [B04 Materialization Addendum](../internal/superpowers/reviews/2026-07-21-phase-1-b04-postgres-migration-materialization-addendum.md)
