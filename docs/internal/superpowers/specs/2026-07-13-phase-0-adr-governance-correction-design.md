# Phase 0 ADR Governance Correction Design

- **Status:** Approved
- **Approved:** 2026-07-13
- **Date:** 2026-07-13
- **Phase:** Phase 0 — Architecture and foundations
- **Program gate:** Gate 1 corrective cycle
- **Owners:** Central maintainer

## Context

Gate 1 installed ADR governance, proposed and accepted ADR 0001, aligned canonical Task-domain documentation, and recorded validation evidence. A post-implementation review found one material governance contradiction and two alignment defects:

1. the lifecycle permits `Accepted -> Superseded`, while decided-record immutability does not explicitly permit the required Status update;
2. the governance source hierarchy omits testing from technical-specification ownership even though the approved Gate 1 design includes it;
3. the ADR template tells Rejected ADR authors to put the rejection reason in Decision but does not repeat the governance requirement to include it in Consequences.

The material contradiction is inherited from the approved Gate 1 design and was copied faithfully into the installed governance. Correcting it now is a semantic governance change, so the installed change-control rule requires a new ADR.

Related documents:

- [ADR governance and index](../../../adr/README.md)
- [ADR template](../../../adr/template.md)
- [ADR 0001](../../../adr/0001-adopt-durable-task-domain-and-lifecycle.md)
- [Gate 1 design](2026-07-12-phase-0-adr-governance-design.md)
- [Gate 1 implementation plan](../plans/2026-07-13-phase-0-adr-governance.md)
- [Gate 1 validation evidence](../reviews/2026-07-13-phase-0-adr-governance-validation.md)

## Objective

Remove the lifecycle and immutability contradiction through a standalone ADR 0002, align the two non-semantic documentation omissions, and revalidate Gate 1 without changing ADR 0001 or claiming that Phase 0 is complete.

## Scope

### In scope

- standalone ADR 0002 for the authorized supersession Status update;
- exact fields that may change on an Accepted ADR during full replacement;
- preservation of original decision text and decision metadata;
- treatment of active amendments during full replacement;
- alignment of the approved Gate 1 design and installed governance;
- restoration of testing ownership in the source hierarchy;
- explicit rejection-reason guidance in the template Consequences section;
- corrective commit ledger and rerun of Gate 1 validation;
- deadline-extension behavior if ADR 0002 becomes overdue;
- proof that ADR 0001 is unchanged.

### Out of scope

- changing any Task-domain or durable-lifecycle decision in ADR 0001;
- introducing a new ADR status;
- reopening Rejected or Superseded ADRs;
- redefining partial amendment precedence;
- automating ADR validation;
- starting Gate 2 security design;
- declaring Phase 0 complete;
- runtime code, schema, migration, Docker, or infrastructure changes.

## Approaches considered

### Selected: standalone corrective ADR 0002

Create an independent governance decision related to the Gate 1 design. ADR 0002 does not amend ADR 0001 because ADR 0001 owns Task-domain decisions, not ADR-process governance.

This preserves decision ownership, follows installed change control, and creates an explicit durable record for the semantic correction.

### Rejected: ADR 0002 Amends ADR 0001

This would attach governance semantics to the Task-domain decision and make ADR 0001 appear partially changed even though its domain meaning remains untouched.

### Rejected: direct governance edit

Editing the immutability rule without a new ADR would violate the installed requirement that material governance changes first receive their own decision record.

## Corrective architecture

The correction has four distinct units:

1. **Decision record:** ADR 0002 owns the new governance decision and rationale.
2. **Governance alignment:** the Gate 1 design and `docs/adr/README.md` state the authorized transition consistently.
3. **Editorial alignment:** the README restores testing ownership and the template repeats the existing rejection-reason rule.
4. **Validation evidence:** the existing Gate 1 validation retains its original ledger and appends the corrective ledger and results.

ADR 0001 is a protected non-participant. No corrective commit may modify it.

## ADR 0002

### Identity

- **Number:** 0002
- **Title:** Authorize Accepted-to-Superseded ADR Status transitions
- **Filename:** `0002-authorize-accepted-to-superseded-status-transitions.md`
- **Owners:** Central maintainer
- **Status:** Proposed
- **Created:** actual proposal-commit date in Asia/Bangkok
- **Decision due:** the proposal-commit date because the corrective design has already been approved
- **Decision due history:** None
- **Implementation blocked at:** Gate 1 corrective closure; Gate 2 brainstorming and governance-dependent implementation remain blocked until ADR 0002 is Accepted and correction validation passes
- **Decided by:** Not applicable while Proposed
- **Decision date:** Not applicable while Proposed
- **Decision record:** Not applicable while Proposed
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** corrective design, Gate 1 design, ADR governance, and Gate 1 validation evidence

The Context records the implementation-review findings that triggered the correction. ADR 0002 does not amend ADR 0001.

### Decision

When a new ADR is Accepted as a full replacement, its dedicated acceptance commit may update each replaced Accepted ADR as follows:

- `Status` changes from `Accepted` to `Superseded`;
- `Superseded by` records the new Accepted ADR;
- the ADR index receives the matching Status and `Superseded by` updates.

These changes are authorized lifecycle and relationship metadata transitions. They are not semantic rewrites of the historical decision.

### Preserved fields and content

The replacement commit must not change the replaced ADR's:

- Number, Title, Created, Owners, Decision due, Decision due history, or Implementation blocked at;
- original Decided by, Decision date, or Decision record;
- Supersedes, Amends, Amended by, or Related metadata;
- Context;
- original Decision text;
- Consequences;
- Alternatives considered;
- historical Follow-ups or References except non-semantic broken-link repair.

The new superseding ADR and Git history are the durable authority and record for the supersession. The old ADR does not overwrite its original acceptance authority or date.

### Active amendments

If a replaced base ADR has Accepted, non-superseded amendments:

1. the superseding ADR enumerates and resolves each active amendment;
2. retained amendment semantics are absorbed into the replacement decision;
3. the base and every active amendment change to Superseded in the same acceptance commit;
4. each records the same `Superseded by` relationship;
5. the index records every matching transition;
6. no active amendment remains attached to a Superseded base.

### Non-applicable cases

The exception does not:

- permit Rejected or Superseded ADRs to reopen;
- permit Accepted ADRs to return to Proposed;
- authorize semantic editing outside a new ADR decision;
- change partial amendment rules;
- permit one-sided or cyclic relationships;
- allow supersession across separate commits.

## Source-of-truth alignment

### Gate 1 design

The decided-ADR immutability section is corrected to list one additional permitted in-place change:

- the authorized `Accepted -> Superseded` Status transition and `Superseded by` update performed through a later ADR's dedicated acceptance commit.

The design continues to prohibit semantic rewrites of Accepted, Rejected, and Superseded records.

### ADR governance

The installed governance receives the same explicit exception. The lifecycle, immutability, and supersession sections must read as one rule:

- lifecycle authorizes the transition;
- immutability authorizes only the exact metadata mutations needed to perform it;
- supersession requires all affected records and the index to change atomically in the new ADR's acceptance commit.

The aligned README marks the exception as effective only when ADR 0002 is Accepted. While ADR 0002 remains Proposed, the text is staged for maintainer review and cannot authorize a supersession.

An incomplete transition, extra historical edit, or split commit remains a decision blocker.

### Technical-specification ownership

The source hierarchy sentence changes from ownership of:

    detailed semantics, state machines, interfaces, data flows, failure behavior, and acceptance detail

to ownership of:

    detailed semantics, state machines, interfaces, data flows, failure behavior, testing, and acceptance detail

This is alignment with the already approved Gate 1 design, not a new architectural decision.

### ADR template

The Consequences section gains explicit Rejected-state guidance:

    If Rejected, state the rejection reason here as well as in Decision, including the consequences of not adopting the proposal.

This is alignment with the existing governance rule that a Rejected ADR states its reason in both Decision and Consequences.

## Change-control sequencing

Installed change control requires a new ADR to exist before governance adopts a material change; it does not require that ADR to be Accepted before related documentation can be staged. The decision workflow separately requires related documentation to be aligned before acceptance.

The approved corrective design therefore permits the governance text to be staged after ADR 0002 exists as Proposed. The text contains its own effectiveness condition, so the new rule remains unavailable for dependent use until ADR 0002 is Accepted. Acceptance activates the already-reviewed rule without requiring a third file in the dedicated status-transition commit.

Required sequence:

1. commit this approved corrective design and its implementation plan;
2. record the correction baseline;
3. create ADR 0002 as Proposed and add its Proposed index row;
4. align the Gate 1 design, governance README, and template;
5. validate the aligned Proposed state;
6. present the written ADR 0002 and checks to the Central maintainer;
7. obtain explicit acceptance;
8. change only ADR 0002 and the index to Accepted in a dedicated commit;
9. update Gate 1 validation evidence with the correction ledger and results;
10. run the post-commit closure audit without amending the evidence commit.

## Commit boundaries

### Proposal commit

Changes only:

- `docs/adr/0002-authorize-accepted-to-superseded-status-transitions.md`;
- `docs/adr/README.md` for the Proposed index row.

### Alignment commit

Changes only:

- `docs/superpowers/specs/2026-07-12-phase-0-adr-governance-design.md`;
- `docs/adr/README.md` governance text, while preserving ADR 0002 as Proposed;
- `docs/adr/template.md`.

### Acceptance commit

Changes only:

- `docs/adr/0002-authorize-accepted-to-superseded-status-transitions.md`;
- `docs/adr/README.md` for the Accepted index row.

It must not contain the alignment changes or validation evidence.

### Validation commit

Changes only:

- `docs/superpowers/reviews/2026-07-13-phase-0-adr-governance-validation.md`.

## Deadline and failure handling

ADR 0002 uses the installed proposal deadline rules.

If the current Asia/Bangkok date passes Decision due before acceptance:

1. acceptance stops;
2. the owner requests an extension with a reason;
3. the Central maintainer explicitly approves it;
4. ADR 0002 and the index update together in a separate extension commit;
5. decision-due history remains one append-only metadata field with entries separated by `<br>`;
6. the acceptance gate reruns on the new due date.

The correction also stops for:

- missing or mismatched ADR number, status, due date, or relationship fields;
- ADR 0002 incorrectly declaring Amends ADR 0001;
- ADR 0001 appearing in any corrective diff;
- governance alignment before the ADR 0002 proposal exists;
- use of the new exception before ADR 0002 is Accepted;
- unapproved or overdue acceptance;
- an acceptance commit containing a third file;
- disagreement among lifecycle, immutability, and supersession wording;
- broken relative references;
- non-Markdown files in the corrective range;
- tracked `.superpowers/` content.

## Validation evidence

The existing Gate 1 validation file remains the single Gate 1 evidence ledger. Its original baseline and five implementation commits remain intact.

After the correction, it changes:

- **Status:** `Passed after correction`;
- adds a **Post-review correction** section;
- records the exact correction baseline;
- records the exact ADR 0002 proposal, alignment, optional deadline-extension, and acceptance commits;
- records the post-correction validation results;
- continues to state that Phase 0 is not complete.

The validation commit does not record its own hash. Git history resolves it.

## Validation strategy

### ADR identity and lifecycle

- exactly two numbered ADRs exist;
- numbers 0001 and 0002 are unique and indexed once;
- ADR 0002 is Proposed in the proposal commit;
- ADR 0002 is Accepted in the dedicated acceptance commit;
- ADR 0002 has no Supersedes or Amends relationships;
- ADR 0001 remains byte-for-byte unchanged across the correction range;
- ADR 0002 and index due dates agree;
- in the proposal snapshot, ADR 0002 Created and Decision due both equal the Asia/Bangkok calendar date of the proposal commit;
- an optional extension has explicit authority, preserves the original due date in append-only history, and makes the current ADR and index due dates equal the approved extension date.

### Governance consistency

- the lifecycle still contains `Accepted -> Superseded`;
- immutability explicitly permits that authorized Status transition;
- the permission is limited to the later ADR's acceptance commit;
- the staged governance text is explicitly ineffective while ADR 0002 is Proposed;
- original decision text and decision metadata remain protected;
- full replacement still resolves every active amendment;
- Rejected and Superseded remain terminal;
- the source hierarchy assigns testing to technical specifications;
- the template requires rejection reason in both Decision and Consequences.

### Commit integrity

- the proposal commit changes only ADR 0002 and the index;
- the alignment commit changes only the Gate 1 design, governance README, and template;
- the acceptance commit changes only ADR 0002 and the index;
- the validation commit changes only the Gate 1 validation evidence;
- every corrective path is Markdown under `docs/`;
- `git diff --check` passes across the full correction range;
- `.superpowers/` has no tracked files.

### Reference integrity

- every relative link in ADR 0002 resolves;
- ADR 0002 links to the corrective design, Gate 1 design, governance, and validation evidence;
- the Gate 1 validation evidence links to the corrective design and ADR 0002;
- no reference implies that ADR 0002 modifies ADR 0001.

## Acceptance criteria

The corrective cycle is complete when:

- ADR 0002 is Accepted through a separate proposal and acceptance history;
- ADR 0002 is standalone and does not amend ADR 0001;
- supersession Status updates are explicitly authorized without permitting semantic rewrites;
- original decision authority, date, record, and content remain immutable;
- active amendments cannot be orphaned by full replacement;
- testing ownership is restored in installed governance;
- the ADR template repeats rejection-reason guidance in Consequences;
- ADR 0001 is unchanged;
- Gate 1 validation evidence is `Passed after correction` with exact corrective commit identities;
- all identity, lifecycle, relationship, link, regression, scope, and whitespace checks pass;
- only documentation files change;
- Phase 0 remains explicitly incomplete.

## Risks and mitigations

### Immutability exception becomes too broad

The exception names exact fields, exact transition, exact authority, and exact commit boundary. All original decision content and metadata remain protected.

### Governance change appears before ADR acceptance

Alignment occurs only after the Proposed ADR exists and after this corrective design is approved. The new behavior remains blocked from use until ADR 0002 becomes Accepted.

### ADR 0001 is accidentally treated as amended

ADR 0002 has all four relationship fields set to None, and validation requires ADR 0001 to remain unchanged across the correction range.

### Historical validation is obscured

The original Gate 1 ledger remains in place. A new Post-review correction section appends the correction history rather than replacing the original commit evidence.

## Next gate

Gate 2 brainstorming may begin only after ADR 0002 is Accepted and the Gate 1 validation evidence passes after correction.
