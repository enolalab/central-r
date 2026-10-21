# ADR 0002: Authorize Accepted-to-Superseded ADR Status transitions

- **Number:** 0002
- **Title:** Authorize Accepted-to-Superseded ADR Status transitions
- **Status:** Accepted
- **Created:** 2026-07-13
- **Owners:** Central maintainer
- **Decision due:** 2026-07-13
- **Decision due history:** None
- **Implementation blocked at:** Gate 1 corrective closure; Gate 2 brainstorming and governance-dependent implementation remain blocked until ADR 0002 is Accepted and correction validation passes
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-13
- **Decision record:** Git status-transition commit; exact hash resolved by this file's Git history
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** [corrective design](../internal/superpowers/specs/2026-07-13-phase-0-adr-governance-correction-design.md), [Gate 1 design](../internal/superpowers/specs/2026-07-12-phase-0-adr-governance-design.md), [ADR governance](README.md), [Gate 1 validation evidence](../internal/superpowers/reviews/2026-07-13-phase-0-adr-governance-validation.md)

## Context

Gate 1 installed ADR governance and accepted ADR 0001. A post-implementation review found that the lifecycle permits `Accepted -> Superseded`, but decided-record immutability does not explicitly authorize the corresponding Status mutation on a replaced ADR.

Correcting that contradiction is a material governance change and therefore requires a new ADR. ADR 0001 owns the durable Task-domain decision and is neither amended nor otherwise changed by this governance correction.

The same corrective cycle aligns two existing non-semantic requirements: technical specifications own testing detail, and Rejected ADRs state their rejection reason in both Decision and Consequences.

## Decision

When a later ADR is Accepted as a full replacement, its dedicated acceptance commit may make exactly these changes to each replaced Accepted ADR:

- change `Status` from `Accepted` to `Superseded`;
- set `Superseded by` to the new Accepted ADR;
- apply the matching Status and `Superseded by` changes to the ADR index.

These are authorized lifecycle and relationship metadata transitions, not semantic rewrites.

For each replaced ADR, the acceptance commit preserves:

- Number, Title, Created, Owners, Decision due, Decision due history, and Implementation blocked at;
- original Decided by, Decision date, and Decision record;
- Supersedes, Amends, Amended by, and Related metadata;
- Context, original Decision text, Consequences, and Alternatives considered;
- historical Follow-ups and References except a non-semantic broken-link repair.

If the replaced base ADR has Accepted, non-superseded amendments, the superseding ADR enumerates and resolves every active amendment. The base and every active amendment become Superseded, record the same `Superseded by` relationship, and receive matching index changes in the same acceptance commit. Retained amendment semantics must be absorbed into the replacement decision.

This exception does not reopen Rejected or Superseded ADRs, return an Accepted ADR to Proposed, authorize semantic editing, change partial-amendment rules, permit one-sided or cyclic relationships, or allow a supersession transition to be split across commits.

## Consequences

### Benefits

- The documented lifecycle and decided-record immutability rules become internally consistent.
- Historical decision text and original acceptance metadata remain durable evidence.
- Full replacement cannot orphan an active amendment.
- A supersession transition remains reviewable as one atomic Git change.

### Costs and limitations

- Full replacement requires coordinated updates to every affected ADR and index row.
- Maintainers must distinguish the two authorized historical metadata mutations from prohibited semantic edits.
- Gate 1 continues to rely on manual validation for these rules.

## Alternatives considered

### Amend ADR 0001

Rejected because ADR 0001 owns Task-domain decisions rather than ADR-process governance. Treating this correction as an amendment would incorrectly imply a change to its domain meaning.

### Edit governance directly

Rejected because changing decided-record immutability without a new ADR would violate the installed governance change-control rule.

## Follow-ups

- Align the approved Gate 1 design, installed ADR governance, and ADR template before accepting this ADR.
- Obtain explicit Central-maintainer acceptance in a dedicated status-transition commit.
- Append corrective commit identities and validation results to the existing Gate 1 evidence.
- Keep Gate 2 brainstorming blocked until this ADR is Accepted and correction validation passes.

## References

- [Phase 0 ADR Governance Correction Design](../internal/superpowers/specs/2026-07-13-phase-0-adr-governance-correction-design.md)
- [Phase 0 ADR Governance and Domain Decision Recording Design](../internal/superpowers/specs/2026-07-12-phase-0-adr-governance-design.md)
- [ADR governance and index](README.md)
- [Gate 1 validation evidence](../internal/superpowers/reviews/2026-07-13-phase-0-adr-governance-validation.md)
