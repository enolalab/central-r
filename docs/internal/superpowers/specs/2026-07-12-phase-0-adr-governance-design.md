# Phase 0 ADR Governance and Domain Decision Recording Design

- **Status:** Approved
- **Approved:** 2026-07-13
- **Date:** 2026-07-12
- **Phase:** Phase 0 — Architecture and foundations
- **Program gate:** 1 of 10
- **Owner:** Central maintainer

## Context

Central has an approved domain and durable-lifecycle design, a documentation-alignment plan, and four-workflow validation evidence. The repository does not have an ADR directory, ADR index, template, lifecycle, acceptance authority, or supersession rules.

Phase 0 exit criteria require approved foundational ADRs. The approved domain design also requires its decisions to be recorded in the ADR index once governance exists.

This gate establishes that governance, records the approved domain decision as ADR 0001, and repairs documentation inconsistencies found during review before ADR 0001 becomes Accepted.

Related documents:

- [Phase definitions](../../../product/phases.md)
- [Current phase](../../../implementation/current-phase.md)
- [Architecture overview](../../../architecture/overview.md)
- [Durable execution](../../../architecture/durable-execution.md)
- [Approved domain and lifecycle design](2026-07-12-phase-0-domain-lifecycle-design.md)
- [Domain and lifecycle validation](../reviews/2026-07-12-phase-0-domain-lifecycle-validation.md)
- [Domain documentation plan](../plans/2026-07-12-phase-0-domain-lifecycle-documentation.md)

## Objective

Create a minimal, durable, Markdown-and-Git ADR process that:

- states when an ADR is required;
- gives each ADR stable identity and lifecycle;
- records owner, decision deadline, implementation blocking point, authority, rationale, alternatives, and consequences;
- preserves rejected and superseded decisions;
- supports full replacement and partial amendment;
- distinguishes ADR, technical-specification, and overview responsibilities;
- prevents implementation from proceeding through a known documentation conflict;
- records the approved Task-domain and lifecycle decision without claiming that all Phase 0 contracts are complete.

## Phase 0 completion-program boundary

The broader Phase 0 completion effort is one continuous program with independently approved specifications and plans. This document covers Gate 1 only.

Later gates cover security and secrets, agent/runtime/tool/checkpoint contracts, artifact storage, Event and API conventions, PostgreSQL persistence, Go package architecture, local development, the Phase 1 vertical-slice backlog, and the final Phase 0 closure audit.

Phase 0 is not complete when this gate finishes.

## Scope

### In scope

- ADR directory, governance document, index, and template
- ADR number allocation and filename rules
- ADR lifecycle and acceptance authority
- immutable decided-ADR history
- Rejected-ADR retention
- full supersession and partial amendment
- source-of-truth hierarchy and conflict handling
- ADR trigger and non-trigger rules
- umbrella ADR 0001 for the approved Task-domain and durable lifecycle
- two-commit proposal and acceptance flow
- repair of the reviewed documentation inconsistencies
- manual validation sufficient for the current repository size

### Out of scope

- CODEOWNERS
- ADR generator, schema validator, linter, or CI job
- runtime code, database schema, Docker configuration, or migrations
- security, Agent, Worker, SecretReference, Artifact-retention, Event-schema, API, or package-architecture decisions
- declaring the entire Phase 0 complete
- changing the approved detailed Task-domain semantics

## Approaches considered

### Selected: minimal governed ADRs

Use Markdown files, a human-maintained index, explicit maintainer acceptance, Git history, and focused validation commands.

This is sufficient for the current repository, creates durable decision history immediately, and avoids an automation subsystem before enough ADR volume exists to justify it.

### Rejected: strict automated governance

Introduce CODEOWNERS, ADR generation, metadata schema validation, link checking, and CI enforcement now.

This gives stronger automation but expands Gate 1 into repository-governance tooling and creates maintenance cost before Central has more than one ADR.

### Rejected: single decision log

Keep all decisions in one append-only Markdown file.

This is compact but lacks stable identity, per-decision lifecycle, ownership, supersession, amendment, and clear review boundaries.

## Repository structure

Gate 1 creates:

    docs/
      adr/
        README.md
        template.md
        0001-adopt-durable-task-domain-and-lifecycle.md

### docs/adr/README.md

Owns:

- ADR governance rules;
- trigger and non-trigger criteria;
- lifecycle and transition rules;
- acceptance authority;
- immutability and relationship rules;
- number allocation;
- source-of-truth hierarchy;
- ADR index.

### docs/adr/template.md

Owns the required metadata and section structure for new ADRs. It is not assigned an ADR number and does not appear as a decision in the index.

### ADR files

Each numbered file is a self-contained decision record. It contains enough context, decision, consequence, and alternative information to understand why the decision exists, while linking to a technical specification for detailed semantics.

### Documentation index

`docs/README.md` links to `docs/adr/README.md`. It does not duplicate the ADR index.

The ADR index contains one row per numbered ADR with:

- linked number and title;
- current status;
- owners;
- current decision due date;
- implementation blocking point;
- Supersedes, Superseded by, Amends, and Amended by relationships.

The index preserves decided and historical ADR rows; it never lists only active decisions.

## Source-of-truth hierarchy

### ADR

Owns:

- decision identity;
- rationale;
- status;
- decision authority;
- alternatives;
- consequences;
- supersession and amendment relationships.

### Technical specification

Owns:

- detailed semantics;
- state machines;
- interfaces;
- data flows;
- failure behavior;
- testing and acceptance detail.

### Architecture overview

Owns concise summaries and links. It is not a second detailed specification.

### Conflict rule

A material conflict between ADR, linked technical specification, or overview blocks implementation.

The conflict must be resolved by:

1. identifying which decision or detail changed;
2. creating or updating the appropriate Proposed ADR when the decision changed;
3. updating the technical specification when semantics changed within the accepted decision;
4. aligning overview summaries;
5. validating links and terminology before implementation resumes.

No agent or maintainer may silently select the most convenient document.

### Governance change control

The approved Gate 1 specification bootstraps the first version of ADR governance. After that version is installed, a material change to ADR triggers, lifecycle, authority, immutability, relationships, source hierarchy, or conflict handling requires a new ADR before `docs/adr/README.md` or the template adopts the change.

Editorial corrections and clarifications that do not change governance semantics may be made directly. When it is unclear whether a change is semantic, the Central maintainer treats it as material.

## ADR identity

### Filename

ADR files use:

    NNNN-kebab-title.md

Examples:

- `0001-adopt-durable-task-domain-and-lifecycle.md`
- `0002-example-future-decision.md`

### Number allocation

- Allocate the next integer after the highest number ever used.
- Format the integer as four digits.
- Never reuse a number, including numbers held by Rejected or Superseded ADRs.
- Renaming a title does not change the number.
- The index is the allocation record.
- A duplicate number blocks review and acceptance.

## Required metadata

Every ADR records:

| Field | Requirement |
| --- | --- |
| Number | Always required; matches filename and index. |
| Title | Always required; concise decision phrase. |
| Status | Always required. |
| Created | Always required; ISO `YYYY-MM-DD`. |
| Owners | Always required; one or more accountable roles or people. |
| Decision due | Required while Proposed; ISO `YYYY-MM-DD` and preserved after decision. |
| Decision due history | Required after any deadline extension; append-only list of prior date, new date, reason, approving maintainer, and approval record. |
| Implementation blocked at | Always required; names the first concrete implementation activity that cannot proceed without the decision. |
| Decided by | Required for Accepted or Rejected. |
| Decision date | Required for Accepted or Rejected. |
| Decision record | Required for Accepted or Rejected; PR reference or the Git status-transition commit. |
| Supersedes | Required when replacing an ADR; otherwise explicitly none. |
| Superseded by | Required on an ADR that has been replaced; otherwise explicitly none. |
| Amends | Required for partial change; otherwise explicitly none. |
| Amended by | Required on an ADR that has accepted amendments; otherwise explicitly none. |
| Related | Required list of relevant specifications, plans, reviews, issues, or explicitly none. |

For a direct Git acceptance without a PR, the commit that changes Status and index is the decision record. The ADR records the maintainer and decision date; Git history resolves the exact commit.

### Proposal deadline and blocking behavior

- A Proposed ADR may coexist with discovery, prototyping, and other work that does not depend on its unresolved decision.
- Work at or beyond `Implementation blocked at` cannot begin until the ADR is Accepted. Rejection requires the dependent work to select an accepted alternative before proceeding.
- Passing `Decision due` does not change status automatically. It makes the proposal overdue and blocks dependent implementation even when its declared blocking point has not otherwise been reached.
- An owner may propose a new due date with a reason. A Central maintainer must explicitly approve the extension; the ADR and index are updated together, and the append-only decision-due history preserves the old date, new date, reason, authority, and approval record.
- A proposal that is already overdue remains blocked until the extension commit is durable; requesting an extension does not unblock it.
- An overdue proposal must be Accepted, Rejected, or explicitly extended before dependent work resumes.

## Required sections

Every ADR contains:

1. **Context**
2. **Decision**
3. **Consequences**
   - benefits
   - costs and limitations
4. **Alternatives considered**
5. **Follow-ups**
6. **References**

Rejected ADRs state the rejection reason in Decision and Consequences.

## ADR lifecycle

Statuses are:

- `Proposed`
- `Accepted`
- `Rejected`
- `Superseded`

Allowed transitions:

| From | To | Authority | Required durable changes |
| --- | --- | --- | --- |
| none | Proposed | ADR owner | Create numbered file and index row with owner, due date, and implementation blocking point. |
| Proposed | Accepted | Central maintainer | Record decision authority and date; update index in the same commit. |
| Proposed | Rejected | Central maintainer | Record rejection reason, authority, and date; update index in the same commit. |
| Accepted | Superseded | Central maintainer through a new Accepted ADR | Record reciprocal Supersedes relationships and update index in the same commit. |

Rejected and Superseded are terminal.

An abandoned proposal becomes Rejected with an explicit withdrawal reason. It is not deleted.

## Acceptance authority

- Only explicit Central-maintainer approval can move an ADR from Proposed to Accepted or Rejected.
- Merge alone does not imply acceptance.
- Acceptance or rejection is recorded in a dedicated status-transition commit or a PR that explicitly states the decision.
- The status-transition commit changes only the ADR, reciprocal relationship files when applicable, and the index. Related documentation alignment must already be complete.
- An implementation commit cannot silently accept an ADR.

## Decided-ADR immutability

After an ADR becomes Accepted, Rejected, or Superseded, permitted in-place edits are:

- spelling or grammar corrections that do not change meaning;
- broken-link repair;
- formatting correction;
- reciprocal relationship metadata required by a later ADR.
- after [ADR 0002](../../../adr/0002-authorize-accepted-to-superseded-status-transitions.md) is Accepted, an authorized `Accepted -> Superseded` Status transition and corresponding `Superseded by` update performed on every replaced ADR and active amendment through the later ADR's dedicated full-replacement acceptance commit.

During full replacement, this exception authorizes only those two fields and the matching index values on each replaced record. It does not authorize changes to Number, Title, Created, Owners, Decision due, Decision due history, Implementation blocked at, original Decided by, Decision date, Decision record, Supersedes, Amends, Amended by, Related, or any semantic section. While ADR 0002 remains Proposed, the exception is staged for review and has no effect.

A semantic change to an Accepted ADR requires a new ADR. A Rejected or Superseded ADR is historical evidence and cannot be semantically rewritten; a new proposal records any renewed or replacement decision.

## Supersession and amendment

### Full replacement

A new ADR uses `Supersedes`. When accepted:

- the old ADR becomes Superseded;
- the old ADR records `Superseded by`;
- the new ADR records `Supersedes`;
- the index records both sides;
- all changes occur in the acceptance commit.

If the replaced ADR has Accepted, non-superseded amendments, the replacement ADR must enumerate and resolve every one. The replacement absorbs any amendment semantics that remain valid and Supersedes the base ADR plus all of its active amendments in the same acceptance commit. An amendment that should remain effective must therefore be represented in the replacement decision; it cannot keep pointing to a Superseded base.

Acceptance is blocked if a full replacement would leave an active amendment attached to a Superseded base.

### Partial change

A new ADR uses `Amends`. When accepted:

- the original ADR remains Accepted;
- the original records `Amended by`;
- the new records `Amends`;
- the index records both sides;
- all changes occur in the acceptance commit.

Amendment semantics are:

- an amendment may target only an Accepted base ADR, not another amendment;
- the amendment must identify the exact decision clauses it changes;
- the Accepted amendment controls those clauses, while the original ADR remains effective everywhere else;
- non-overlapping Accepted amendments may coexist;
- a later amendment that overlaps an earlier amendment must Supersede that earlier amendment and state the resulting effective rule;
- Supersedes and Amends relationships must not form a cycle;
- the effective decision is the Accepted, non-superseded base ADR plus its Accepted, non-superseded amendments.

These target-status rules apply when an amendment is Proposed or active. A Superseded amendment retains its historical `Amends` link even when the base is Superseded in the same replacement commit.

Ambiguous scope, an invalid target status, an overlap without supersession, or a relationship cycle blocks acceptance.

## ADR triggers

An ADR is required for:

- cross-domain ownership or aggregate boundaries;
- package and dependency direction;
- durable-state source of truth;
- database, object-storage, or cross-store consistency model;
- Task, Run, Step, retry, cancellation, reconciliation, or completion lifecycle;
- public API, command, Event, or compatibility contract;
- security or trust boundary;
- privileged-capability and secret-access model;
- major technology choice;
- deployment topology or operating mode;
- reversing, replacing, or materially amending an Accepted ADR.

An ADR is not required for:

- local implementation detail behind an accepted interface;
- reversible refactor that preserves behavior and boundaries;
- test-only organization;
- formatting, spelling, or link repair;
- dependency patch updates that do not change compatibility or architecture;
- task-specific operational choice with no durable cross-task effect.

When uncertain, the maintainer decides whether the choice is material before implementation.

## ADR workflow

### Proposal

1. Read the index and allocate the next number.
2. Copy the template.
3. Fill every required Proposed field, including owner, decision due date, and implementation blocking point.
4. State context, decision, consequences, alternatives, and follow-ups.
5. Link related specifications and evidence.
6. Add the Proposed row to the index.
7. Commit proposal and index together.

### Decision

1. Central maintainer reviews scope, trigger, alternatives, source conflicts, and consequences.
2. Related specifications and summaries are aligned before acceptance.
3. Confirm that dependent implementation has not crossed the declared blocking point.
4. Maintainer selects Accepted or Rejected explicitly.
5. Update decision metadata, status, reason, and index.
6. Commit the status transition separately.

### Later change

1. Create a new Proposed ADR with Supersedes or Amends.
2. Complete normal review.
3. On acceptance, update reciprocal metadata and index together.
4. Leave historical decision text intact.

## Failure handling

The following block an ADR decision:

- duplicate or reused number;
- filename, metadata, and index number mismatch;
- missing required metadata;
- missing owner or decision due date;
- missing or vague implementation blocking point;
- overdue proposal without an explicitly approved extension;
- invalid status transition;
- non-maintainer acceptance;
- missing rejection reason;
- one-sided Supersedes or Amends relationship;
- amendment of a non-Accepted ADR;
- amendment targeting another amendment;
- overlapping amendment without explicit supersession;
- full replacement that does not resolve every active amendment of the replaced ADR;
- relationship cycle;
- broken relative reference;
- material conflict with a linked Accepted ADR, approved specification, or architecture summary;
- semantic edit to an Accepted, Rejected, or Superseded ADR outside the permitted historical metadata updates.

Resolution is manual in Gate 1. Automation may be proposed through a later ADR when recurring failures justify it.

## ADR 0001

### Identity

- **Filename:** `0001-adopt-durable-task-domain-and-lifecycle.md`
- **Title:** Adopt the durable Task domain and lifecycle
- **Owner:** Central maintainer
- **Created:** the ADR proposal-commit date in ISO `YYYY-MM-DD`
- **Decision due:** the same ISO date as the proposal commit because the underlying design has already been approved
- **Implementation blocked at:** Gate 1 completion; ADR 0001 must be Accepted before Gate 2 brainstorming or any code, schema, migration, API, or storage implementation based on its Task-domain decisions begins
- **Initial status:** Proposed

### Decision summary

ADR 0001 records:

- Workspace is the Phase 0 and Phase 1 top-level ownership boundary.
- Project is not a Phase 0 or Phase 1 core entity.
- Persisted Workflow graphs and executable subagent relationships begin in Phase 2.
- Task is stable user intent.
- whole-Task retry creates a new Run;
- Step retry creates a new StepAttempt;
- ToolCall is a logical action and ToolCallAttempt is a physical invocation;
- Approval is durable;
- PostgreSQL normalized rows are authoritative current state;
- accepted transitions update current state and append immutable Events in one PostgreSQL transaction;
- Phase 1 does not use pure event sourcing;
- external operations occur outside PostgreSQL transactions;
- ambiguous side effects enter reconciliation and are not repeated blindly;
- Task completion requires verified required Artifacts and durable completion metadata and Events;
- Phase 1 persists execution ownership for restart recovery; multi-worker scheduling begins in Phase 2.

### Explicit boundary

ADR 0001 does not define:

- Agent or Subagent semantics;
- Worker or executor capability model beyond basic execution ownership;
- SecretReference;
- concrete PostgreSQL schema;
- full Artifact retention and cleanup;
- Event payload and API compatibility;
- Go package layout;
- local deployment configuration;
- Phase 1 vertical-slice backlog.

These remain later Phase 0 gates.

### Consequences summary

ADR 0001 records these benefits and costs:

- stable domain meaning for Phase 1 implementation;
- deterministic retry and recovery from persisted evidence;
- durable audit history without pure event-sourcing complexity;
- explicit cross-store completion barrier;
- additional normalized state, Event, attempt, Approval, and reconciliation records;
- mandatory transaction and idempotency discipline;
- deferred Workflow graphs, distributed scheduling, and the remaining Phase 0 contracts.

### Alternatives recorded

ADR 0001 records why Central rejected:

- Project as a Phase 0 or Phase 1 core entity;
- persisted Workflow graphs in Phase 1;
- pure event sourcing;
- current-state tables without immutable Events;
- attaching logical ToolCall identity to one physical StepAttempt;
- blindly retrying ambiguous external side effects.

### References

ADR 0001 links to the approved domain design, architecture overview, durable-execution summary, validation review, and documentation plan. It summarizes decisions without copying detailed state tables.

### Acceptance flow

1. Governance, template, index, and ADR 0001 are committed with ADR 0001 Proposed.
2. Documentation consistency repairs are completed and validated.
3. Central maintainer reviews the written ADR.
4. A separate commit changes ADR 0001 and index to Accepted.
5. That status-transition commit is the decision record.

## Documentation consistency repairs

ADR 0001 cannot become Accepted until these changes are complete:

1. Align Phase 0 exit criteria to require owner, ISO decision due date, and implementation blocking point.
2. Scope the existing validation result to the Task-domain and lifecycle walkthrough.
3. Explicitly defer Agent, Subagent, Worker or executor, and SecretReference definitions.
4. Record all remaining Phase 0 gates in validation follow-ups.
5. Replace `independent durable state` with wording that preserves approved ownership while acknowledging persisted lifecycle state.
6. Make the retry failure taxonomy mandatory rather than advisory.
7. State locally that retrying a failed Task creates a Run while rerunning a cancelled Task creates a new Task with lineage.
8. Replace language that could imply reusing an immutable StepAttempt with requeueing safe work and creating a new attempt.
9. Use execution-ownership expiry rather than Phase 2 Worker terminology in Phase 1 test summaries.

## Validation strategy

### Validation baseline

Immediately before the first Gate 1 implementation commit, record the current commit as `GATE1_BASE` in the Gate 1 validation evidence. All scope and whitespace checks use the inclusive implementation range after that base through the final Gate 1 commit, rather than relying on an empty working-tree diff.

The validation evidence records:

- the exact `GATE1_BASE` commit;
- the proposal commit for governance, index, template, and Proposed ADR 0001;
- any intervening documentation-repair commits;
- the distinct ADR 0001 acceptance commit.

### File and index integrity

- required files exist;
- ADR 0001 is indexed;
- every numbered ADR file has exactly one index row;
- every index row resolves to one file;
- numbers are unique;
- filename, metadata, and index number agree.

### Metadata and lifecycle

- all required Proposed fields are present before proposal commit;
- all required decision fields are present before acceptance or rejection;
- only allowed status transitions occur;
- Accepted, Rejected, and Superseded histories remain present;
- owner and ISO decision due date are present;
- implementation blocking point is present and concrete;
- every deadline extension has append-only history and explicit maintainer approval;
- overdue proposals have an explicit extension, acceptance, or rejection record;
- decision authority is a Central maintainer.

### Relationship integrity

- Supersedes and Superseded by are reciprocal;
- Amends and Amended by are reciprocal;
- every active amendment targets an Accepted base ADR;
- amendment targets are base ADRs rather than other amendments;
- overlapping amendments explicitly supersede the earlier amendment;
- full replacement supersedes or absorbs every active amendment of the replaced base;
- relationship graphs contain no cycles;
- index relationships match ADR metadata.

### Reference integrity

- every relative link resolves;
- ADR 0001 links to the approved specification and validation;
- `docs/README.md` links to the ADR index;
- the ADR, specification, overview, and durable-execution summary do not conflict.

### Documentation regression checks

- Phase 0 exit-criteria wording is consistent;
- validation does not claim all Phase 0 vocabulary is complete;
- aggregate ownership wording is preserved;
- retry taxonomy uses mandatory language;
- failed retry and cancelled rerun remain distinct;
- no language implies reusing an immutable attempt.

### Repository scope

- `git diff --check "$GATE1_BASE"..HEAD` passes;
- `git diff --name-only "$GATE1_BASE"..HEAD` contains only documentation files;
- `git log "$GATE1_BASE"..HEAD` shows distinct proposal and acceptance commits;
- the recorded acceptance commit changes only ADR 0001 and the ADR index;
- `.superpowers/brainstorm/` is not committed;
- no Go, SQL, migration, Docker, or runtime file is created.

## Acceptance criteria

Gate 1 is complete when:

- ADR governance and trigger rules are documented;
- the ADR index and template exist;
- numbering and filename rules are explicit;
- lifecycle, authority, immutability, rejection, supersession, and amendment rules are explicit;
- Proposed ADRs require owner, ISO decision due date, and a concrete implementation blocking point;
- overdue and deadline-extension behavior is explicit;
- source-of-truth hierarchy and conflict blocking are explicit;
- material changes to the installed governance require a new ADR;
- decided ADRs preserve immutable semantic history;
- amendment precedence, target status, overlap, and cycle rules are explicit;
- ADR 0001 accurately summarizes the approved Task-domain decision and its exclusions;
- ADR 0001 is proposed and then accepted through separate commits;
- documentation consistency findings are resolved;
- index, metadata, relationship, link, and regression checks pass;
- `docs/README.md` links to the ADR index;
- no implementation code is introduced.

## Risks and mitigations

### Umbrella ADR breadth

ADR 0001 covers several linked Task-domain decisions. Partial future changes use Amends so the complete ADR need not be superseded for a narrow change.

### Manual index drift

The current ADR volume does not justify automation. Focused validation and same-commit index updates mitigate drift. Repeated failures can justify a later automation ADR.

### Approval ambiguity

Merge alone does not accept an ADR. A dedicated maintainer status-transition commit or explicit PR decision is required.

### Deadline drift

An overdue proposal cannot silently remain non-blocking. Dependent work pauses until the proposal is decided or a maintainer explicitly approves and records an extension.

### Documentation duplication

ADR records decision and rationale, the specification records detailed semantics, and overview documents summarize. Conflict blocks implementation.

### Phase 0 overclaim

ADR 0001 and its validation explicitly state their Task-domain scope and list later gates.

## Next gate

After Gate 1 is implemented and reviewed, Gate 2 defines the security threat model, capability classes, approval defaults, and SecretReference contract needed by runtime, Artifact, API, storage, and local-development specifications.
