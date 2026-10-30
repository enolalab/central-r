# Architecture Decision Records

This directory contains Central's durable architectural decisions and the governance for proposing, accepting, rejecting, superseding, and amending them.

The [approved Gate 1 design](../internal/superpowers/specs/2026-07-12-phase-0-adr-governance-design.md) bootstraps this governance. A material change to the rules below requires a new ADR before this file or the template adopts that change. Editorial corrections that do not change meaning may be made directly; uncertainty is treated as material.

## Source-of-truth hierarchy

An ADR owns decision identity, rationale, status, authority, alternatives, consequences, and decision relationships.

A linked technical specification owns detailed semantics, state machines, interfaces, data flows, failure behavior, testing, and acceptance detail.

Architecture overviews own concise summaries and links. They do not duplicate detailed specifications.

A material conflict between an ADR, linked specification, or overview blocks dependent implementation. Resolve it by identifying whether the decision or its detailed semantics changed, proposing a new ADR when the decision changed, aligning the specification and summaries, and validating terminology and links before work resumes. No contributor may silently choose the most convenient document.

## When an ADR is required

Create an ADR for:

- cross-domain ownership or aggregate boundaries;
- package and dependency direction;
- durable-state source of truth;
- database, object-storage, or cross-store consistency models;
- Task, Run, Step, retry, cancellation, reconciliation, or completion lifecycles;
- public API, command, Event, or compatibility contracts;
- security or trust boundaries;
- privileged-capability and secret-access models;
- major technology choices;
- deployment topology or operating mode;
- reversing, replacing, or materially amending an Accepted ADR;
- a material change to this installed ADR governance.

An ADR is not required for:

- a local implementation detail behind an accepted interface;
- a reversible refactor that preserves behavior and boundaries;
- test-only organization;
- formatting, spelling, or link repair;
- a dependency patch update that does not change compatibility or architecture;
- a task-specific operational choice with no durable cross-task effect.

When materiality is unclear, the Central maintainer decides before implementation.

## Identity and allocation

Numbered ADR filenames use `NNNN-kebab-title.md`.

- Allocate the next integer after the highest number ever used.
- Format the number as four digits.
- Never reuse a number held by an Accepted, Rejected, or Superseded ADR.
- Renaming a title does not change its number.
- This index is the allocation record.
- Duplicate or mismatched numbers block review and acceptance.

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
| Decision due history | Required after an extension; append-only old date, new date, reason, approving maintainer, and approval record. |
| Implementation blocked at | Always required; first concrete activity that cannot proceed without the decision. |
| Decided by | Required for Accepted or Rejected. |
| Decision date | Required for Accepted or Rejected. |
| Decision record | Required for Accepted or Rejected; explicit PR or Git status-transition commit. |
| Supersedes | Replaced ADRs, or `None`. |
| Superseded by | Replacing ADR, or `None`. |
| Amends | Partially changed base ADR, or `None`. |
| Amended by | Accepted amendments, or `None`. |
| Related | Relevant specifications, plans, reviews, issues, or `None`. |

Every ADR contains Context, Decision, Consequences with benefits and costs, Alternatives considered, Follow-ups, and References. A Rejected ADR states its rejection reason in Decision and Consequences.

## Lifecycle

Statuses and transitions are:

| From | To | Authority | Durable changes |
| --- | --- | --- | --- |
| none | Proposed | ADR owner | Create numbered file and index row with owner, due date, and blocking point. |
| Proposed | Accepted | Central maintainer | Record authority and date; update ADR and index in one dedicated commit. |
| Proposed | Rejected | Central maintainer | Record reason, authority, and date; update ADR and index in one dedicated commit. |
| Accepted | Superseded | Central maintainer through a new Accepted ADR | In the new ADR's dedicated acceptance commit, change every replaced Accepted ADR to Superseded, record reciprocal relationships, and update every affected ADR plus the index together. |

Rejected and Superseded are terminal. An abandoned proposal becomes Rejected with an explicit withdrawal reason; it is never deleted.

## Deadline and blocking behavior

- Discovery, prototyping, and unrelated work may continue while an ADR is Proposed.
- Work at or beyond `Implementation blocked at` cannot begin until the ADR is Accepted.
- Rejection requires dependent work to select an accepted alternative.
- Passing `Decision due` does not change status automatically; it makes the proposal overdue and blocks dependent implementation.
- An owner may request a new due date with a reason.
- A Central maintainer must explicitly approve an extension in a commit that updates the ADR and index together.
- The append-only decision-due history preserves both dates, reason, authority, and approval record.
- An overdue proposal remains blocked until its extension, acceptance, or rejection is durable.

## Decision authority and workflow

Only explicit Central-maintainer approval moves Proposed to Accepted or Rejected. Merge alone is not approval, and an implementation commit cannot silently decide an ADR.

Proposal workflow:

1. Read the index and allocate the next number.
2. Copy `template.md`.
3. Complete every Proposed field, including owner, due date, and implementation blocking point.
4. Record context, decision, consequences, alternatives, follow-ups, and references.
5. Add the Proposed index row.
6. Commit ADR and index together.

Decision workflow:

1. The Central maintainer reviews scope, alternatives, conflicts, and consequences.
2. Related specifications and summaries are aligned before acceptance.
3. Confirm dependent implementation has not crossed the blocking point.
4. Explicitly choose Accepted or Rejected.
5. Record decision metadata and update the index.
6. Commit the status transition separately.

A direct Git decision records `Git status-transition commit`; Git history resolves the exact commit hash.

## Decided-record immutability

After an ADR becomes Accepted, Rejected, or Superseded, permitted in-place edits are limited to non-semantic spelling, grammar, broken-link, and formatting repairs plus reciprocal relationship metadata required by a later ADR.

The following exception takes effect only when [ADR 0002](0002-authorize-accepted-to-superseded-status-transitions.md) has Status `Accepted`; while it is Proposed, the exception is staged for maintainer review and cannot authorize supersession. In a later ADR's dedicated full-replacement acceptance commit, the only newly authorized changes to each replaced Accepted ADR are `Status` from `Accepted` to `Superseded` and `Superseded by` to the new ADR, together with matching index changes.

That exception does not permit changes to the replaced ADR's Number, Title, Created, Owners, Decision due, Decision due history, Implementation blocked at, original Decided by, Decision date, Decision record, Supersedes, Amends, Amended by, Related, or any semantic section.

A semantic change to an Accepted ADR requires a new ADR. Rejected and Superseded records are historical evidence and cannot be semantically rewritten.

## Supersession and amendment

Full replacement uses `Supersedes`. On acceptance, the old ADR becomes Superseded, both ADRs record reciprocal relationships, and the index changes in the same commit.

The full-replacement acceptance commit is atomic: every affected Accepted base or active amendment changes to Superseded, records the same `Superseded by` relationship, preserves all other original decision content and metadata, and receives matching index updates. An incomplete transition, an extra historical edit, or a transition split across commits blocks acceptance.

If the base has active amendments, the replacement must enumerate and resolve every one. It absorbs retained semantics and Supersedes the base plus all active amendments together. Acceptance is blocked if an active amendment would point to a Superseded base.

Partial change uses `Amends`. On acceptance, the base remains Accepted, both ADRs record reciprocal relationships, and the index changes in the same commit.

- An amendment targets only an Accepted base ADR, never another amendment.
- It identifies the exact clauses changed and controls only those clauses.
- Non-overlapping active amendments may coexist.
- An overlapping later amendment must Supersede the earlier amendment and state the resulting rule.
- Supersedes and Amends relationships cannot form cycles.
- The effective decision is an Accepted, non-superseded base plus its Accepted, non-superseded amendments.
- A Superseded amendment retains its historical `Amends` link when its base is Superseded in the same replacement commit.

## Decision blockers

Review or acceptance is blocked by:

- duplicate, reused, or mismatched numbers;
- missing metadata, owner, due date, or concrete implementation blocking point;
- an overdue proposal without a durable extension;
- an invalid transition or non-maintainer decision;
- a missing rejection reason;
- a one-sided relationship, invalid amendment target, unhandled overlap, orphaned active amendment, or relationship cycle;
- a broken relative reference;
- a material conflict with an Accepted ADR, approved specification, or architecture summary;
- an incomplete or split full-replacement transition, or an edit beyond the authorized `Status` and `Superseded by` fields on a replaced ADR;
- a semantic edit to decided historical evidence outside permitted metadata updates.

Gate 1 uses manual review and focused repository commands. Recurring failures may justify a later automation ADR.

## ADR index

The index preserves Proposed, Accepted, Rejected, and Superseded records. It never lists only active decisions.

| ADR | Status | Owners | Decision due | Implementation blocked at | Supersedes | Superseded by | Amends | Amended by |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [0001 — Adopt the durable Task domain and lifecycle](0001-adopt-durable-task-domain-and-lifecycle.md) | Accepted | Central maintainer | 2026-07-13 | Gate 1 completion; must be Accepted before Gate 2 brainstorming or dependent code, schema, migration, API, or storage implementation begins. | None | None | None | None |
| [0002 — Authorize Accepted-to-Superseded ADR Status transitions](0002-authorize-accepted-to-superseded-status-transitions.md) | Accepted | Central maintainer | 2026-07-13 | Gate 1 corrective closure; Gate 2 brainstorming and governance-dependent implementation remain blocked until ADR 0002 is Accepted and correction validation passes. | None | None | None | None |
| [0003 — Adopt the Phase 1 security policy and SecretReference model](0003-adopt-phase-1-security-policy-and-secret-reference-model.md) | Accepted | Central maintainer | 2026-07-20 | Gate 3 capability, authorization, SecretReference-resolver, and privileged-adapter protocol design; dependent runtime, schema, API, adapter, and UI implementation remains blocked until ADR 0003 is Accepted and Gate 2 validation passes. | None | None | None | None |
| [0004 — Adopt staged single-agent runtime and verified adapter handoffs](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md) | Accepted | Central maintainer | 2026-07-20 | Phase 1 provider, tool, runtime, and resolver implementation plans plus dependent Gate 4–8 specifications that consume runtime semantics; none may cross that boundary until ADR 0004 is Accepted and Gate 3 validation passes | None | None | None | 0022, 0035 |
| [0005 — Adopt verified Artifact lifecycle and safe content delivery](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md) | Accepted | Central maintainer | 2026-07-20 | Artifact lifecycle implementation plan plus dependent Gate 5–8 specifications that consume Artifact behavior; none may cross that boundary until ADR 0005 is Accepted and Gate 4 validation passes | None | None | None | None |
| [0006 — Adopt the local v1 API and Event serialization contracts](0006-adopt-local-v1-api-and-event-serialization.md) | Accepted | Central maintainer | 2026-07-20 | API/Event, UI, persistence, and handler implementation plans | None | None | None | None |
| [0007 — Adopt PostgreSQL persistence and recovery contracts](0007-adopt-postgresql-persistence-and-recovery-contracts.md) | Accepted | Central maintainer | 2026-07-20 | persistence, migration, repository, and recovery implementation plans | None | None | None | None |
| [0008 — Adopt capability-owned Go application boundaries](0008-adopt-capability-owned-go-application-boundaries.md) | Accepted | Central maintainer | 2026-07-20 | Go bootstrap, persistence-adapter, handler, operator-mode, worker, and Phase 1 vertical-slice implementation plans. | None | None | None | 0009, 0010, 0014, 0036, 0043 |
| [0009 — Adopt the local development environment topology](0009-adopt-local-development-environment-topology.md) | Superseded | Central maintainer | 2026-07-20 | Gate 9 host-authority foundation, local dependency topology, protected-state backend, browser bootstrap, and operator recovery implementation plans. | None | 0010 | 0008 | None |
| [0010 — Reassign Gate 9 executable slices to Phase 1](0010-reassign-gate-9-executable-slices-to-phase-1.md) | Superseded | Central maintainer | 2026-07-20 | Gate 9 backlog execution and every Phase 1 Slice A–E executable implementation plan or artifact. | 0009 | 0011 | 0008 | None |
| [0011 — Amend local topology for dedicated migration operator](0011-amend-local-topology-for-dedicated-migration-operator.md) | Superseded | Central maintainer | 2026-07-28 | B05 implementation planning and code that creates the `central-migrate` identity, delivers `central_migration` credentials, or exposes `central migrate reset`. | 0010 | 0014 | 0008 | None |
| [0012 — Extend root credential mount and add minio-provision mode](0012-extend-root-credential-mount-and-add-minio-provision-mode.md) | Accepted | Central maintainer | 2026-08-13 | SB-G3 plan Task 9 (credential-mount extension) and Task 13 (minio-provision mode registration), both blocked on this ADR per their own plan headers and the plan's Global Constraints. | None | None | None | 0014 |
| [0013 — Widen frame 0xb1 peer authorization to admit Central's runtime UID](0013-widen-frame-0xb1-peer-authorization-to-admit-runtime-uid.md) | Accepted | Central maintainer | 2026-08-14 | SB-G3 plan Task 11a (widening the frame `0xb1` `SO_PEERCRED` gate in `server.go` and the matching `ValidateDependency` check in `domain.go`), blocked on this ADR per its own plan header. | None | None | None | None |
| [0014 — Authorize PostgreSQL throughput fixture provisioner mode](0014-authorize-postgresql-throughput-fixture-provisioner.md) | Accepted | Central maintainer | 2026-08-17 | C02 production Compose/image-inventory/admin-passfile wiring, `postgres_server_admin_v1` materialization, and any production acceptance claim for `postgres-throughput-provision`; external prototypes and coordinator interfaces may continue while Proposed. | 0011 | None | 0008, 0012 | 0019 |
| [0015 — Bind restore engine process identity outside the authorized process](0015-bind-restore-engine-process-identity-outside-the-authorized-process.md) | Accepted | Central maintainer | 2026-08-20 | Prerequisite-plan Task 3, and any capacity-reserve precondition that relies on a launch record to distinguish the restore engine from another root peer. | None | None | None | None |
| [0016 — Adopt a terminal outcome for an interrupted restore](0016-adopt-a-terminal-outcome-for-an-interrupted-restore.md) | Accepted | Central maintainer | 2026-08-20 | Prerequisite-plan Task 4; the capacity-reserve sweep's refusal to release a set bound to a non-terminal applying operation; and the capacity design's stuck-apply operator instruction, which currently names a transition that does not exist. | None | None | None | 0028 |
| [0017 — Narrow the object-store restore credential's precondition](0017-narrow-the-object-store-restore-credential-precondition.md) | Accepted | Central maintainer | 2026-08-20 | The fix for `docs/internal/tasks/sc-def-01-object-store-write-credential-gate.md`; no code may narrow or widen frame `0xc2` kind 3's precondition until this is decided. | None | None | None | None |
| [0018 — Authorize the restore capacity reserve authority](0018-authorize-the-restore-capacity-reserve-authority.md) | Accepted | Central maintainer | 2026-08-20 | Any code implementing the reserve gate — helper-side physical allocation, frame `0xc3` and its record store, the new preconditions on frame `0xc2` kind 1's release, the launch-record field its predicate needs, and the reserve inspection surface. |  None | None | None | None |
| [0019 — Bootstrap the production PostgreSQL role topology and admin credential chain](0019-bootstrap-the-production-postgresql-role-topology.md) | Accepted | Central maintainer | 2026-08-24 | Postgres daemon/provision service environment changes in `compose-policy.json`, the credential-mount table extension, the rendered first-boot init script, and the helper rotate-then-sync protocol. | None | None | 0014 | None |
| [0020 — Populate the version-zero dependency receipt at instance provisioning](0020-populate-the-version-zero-dependency-receipt-at-provisioning.md) | Accepted | Central maintainer | 2026-08-24 | Production composition of `internal/dependencyprepare/app.Service` and any writer of a live instance's `active` dependency selector; the Slice E operator upgrade surface stays blocked. | None | None | None | 0030, 0038 |
| [0021 — Expose B09 provider-turn activity to the operator read model](0021-expose-b09-provider-turn-activity-to-the-operator-read-model.md) | Accepted | Central maintainer | 2026-08-25 | Any code reading B09 provider-turn records (`central.b09_provider_turns` / `central.provider_execution_evidence`) for operator display, or surfacing provider/tool activity through the web read model. | None | None | None | None |
| [0022 — Adopt a task-decomposition (leader/worker) model](0022-adopt-a-task-decomposition-leader-worker-model.md) | Accepted | Central maintainer | 2026-09-30 | Any code letting one Task spawn child Tasks as a decomposition edge, deriving a child's authority/budget from a parent, or aggregating child outcomes; and any UI presenting a leader→worker hierarchy as real — all remain blocked pending the design gate. | None | None | ADR 0004 | None |
| [0023 — Reconsider the physical-console ceremony's development path](0023-reconsider-the-physical-console-ceremony-development-path.md) | Accepted | Central maintainer | None set | Option D only: any change to `openPhysicalTTY`, to what counts as a qualifying console, or to the `privilege_profile` / `ceremony_records` manifest fields requires its own follow-up ADR; Options B and C carry no block. | None | None | None | 0028, 0031 |
| [0024 — Settle the promoted MinIO image identity and the helper release digest](0024-settle-the-promoted-minio-identity-and-the-helper-release-digest.md) | Accepted | Central maintainer | None set | Decision 1: any change to the `MinioDaemon` image reference, the `minio` mode inventory source, or the `minio` dependency-lock entry. Decision 2: any non-placeholder `lock.helper_release_digest`, production caller of `Lock.VerifyReleaseDigest`, assignment of `PreparedManifest.HelperRelease`, or lock key-set change. | None | None | None | None |
| [0025 — Settle the fs-init target-descriptor attestation across the container boundary](0025-settle-the-fs-init-target-descriptor-attestation.md) | Accepted | Central maintainer | None set | Any change to `placeholderTargetDescriptor`, `linuxValidator.Validate`, the request `target` rules, the broker-socket mount validation, attestation-driven `durableDataBindMounts` changes, or creation of the host payload roots; fs-init inventory refresh is not blocked. | None | None | None | None |
| [0026 — Remove `postgres-provision` from the B03 service census](0026-remove-postgres-provision-from-the-b03-service-census.md) | Accepted | Central maintainer | None set | Nothing further; authorizes only the census removal, not removing the `PostgresProvisioned` phase, changing `provisionReceipt`, or touching `postgres-throughput-provision`. | None | None | B03 six-service census | None |
| [0027 — Acquire Go modules in the dependency-prepare fetch phase](0027-acquire-go-modules-in-the-dependency-prepare-fetch-phase.md) | Accepted | Central maintainer | None set | Nothing further; authorizes only the recipe correction, fetch-phase module acquisition, and the two named lock edits — not build-step network, new allowlist hosts, or attestation/settlement changes. | None | None | B02 hermetic build contract | None |
| [0028 — Adopt a pre-authorized grant ceremony and context-independent verdicts](0028-adopt-a-pre-authorized-grant-ceremony-and-context-independent-verdicts.md) | Accepted | Central maintainer | 2026-09-13 | None; implementation authorized. Before acceptance: any change to `openPhysicalTTY` or the `Perform*TTYCeremony` functions, governance fields 16/21/24 and §5, SC-DEF-20 Task 4, and unattended SC-G1–SC-G3 runs. | None | None | 0023, 0016 | 0032 |
| [0029 — Admit directory enumeration (getdents64) in the hardened broker](0029-admit-directory-enumeration-in-the-hardened-broker.md) | Accepted | Central maintainer | 2026-09-13 | None; implemented under ADR 0028 D3. | None | None | Restore capacity reserve seccomp decision; SC-DEF-07 `hardening.go` note | None |
| [0030 — Rotate the dependency-attestation trust anchor](0030-rotate-the-dependency-attestation-trust-anchor.md) | Accepted | Central maintainer | 2026-09-13 | None; implementation authorized. | None | None | 0020 §1 (narrowly); `console-bringup-probe.md` lock-edit sentence | 0038 |
| [0031 — Admit a Docker evidence profile for SC-G3](0031-admit-a-docker-evidence-profile-for-sc-g3.md) | Accepted | Central maintainer | 2026-09-30 | None; implementation authorized. Before acceptance: any Docker-profile C06 evidence run claimed toward SC-G3. | None | None | 0023; Slice C acceptance governance fields 16 and 21 | 0033 |
| [0032 — Extend the pre-authorized grant ceremony to Slice D verbs](0032-extend-grant-ceremony-to-slice-d-verbs.md) | Accepted | Central maintainer | 2026-09-26 | Grant-mode Slice D evidence runs and any D07 verdict; `physical_tty` Slice D implementation was never blocked. | None | None | 0028 | 0037 |
| [0033 — Admit a Docker evidence profile for Slice D acceptance](0033-admit-a-docker-evidence-profile-for-slice-d.md) | Accepted | Central maintainer | 2026-09-26 | Any Slice D (D07) verdict; Slice D implementation and rehearsal runs were never blocked. | None | None | 0031 | None |
| [0034 — Restore imported data to the data plane](0034-restore-imported-data-to-the-data-plane.md) | Proposed | Central maintainer | 2026-10-10 | Any pg_restore or MinIO upload of imported data; the D03 staging verb and all other Slice D packets were never blocked. | None | None | 0017 | None |
| [0035 — Freeze the B09 loop coordinator and adopt a harness-session adapter boundary](0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md) | Accepted | Central maintainer | 2026-10-04 | Any production code implementing the `HarnessAdapter` port or a concrete harness adapter, wiring harness execution into `central serve`, adding a harness-session migration, or deleting frozen B09 code. | None | None | 0004 | None |
| [0036 — Add a separate harness launcher for operator harness sessions](0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md) | Accepted | Central maintainer | 2026-10-11 | The `central-harness-launcher` daemon, its socket and service units, its Go client implementing `port.ProcessLauncher`, any production composition of that client, and any serve wiring that launches a harness; adapters, the launcher port and dev-only `localexec` are not blocked | None | None | 0008 | None |
| [0037 — Allow one pre-instance `init` grant for unattended genesis](0037-pre-instance-init-grant.md) | Accepted | Central maintainer | 2026-10-01 | `central grant issue --kind init`, the host-scoped genesis grant store, a grant-mode `ConfirmInit`, and genesis writing the new instance's ceremony-mode file as `grant` (install B2); implementation authorized | None | None | 0028, 0032 | None |
| [0038 — Import attested dependency images from a release](0038-import-attested-dependency-images-from-a-release.md) | Accepted | Central maintainer | 2026-10-01 | `central local prepare --from-release` and any writer of a dependency receipt from artifacts it did not build; the installer end-user path after genesis (install A1); implementation authorized. | None | None | 0020, 0030 D2 | None |
| [0039 — Rotate the release authority key and record its custody](0039-rotate-the-release-authority-key-and-record-its-custody.md) | Accepted | Central maintainer | 2026-10-01 | The pinned release authority key, the sign tool's default key id, and shipping a signed advisory bundle (install A2); implementation authorized. | None | None | None | None |
| [0040 — Adopt Apache-2.0 licenses for central and central-local-infra, DCO contributor terms](0040-adopt-apache-2-0-licenses-and-dco-contributor-terms.md) | Accepted | Central maintainer | 2026-10-11 | None; implementation authorized (`central-rust` amended to dual `MIT OR Apache-2.0`, 2026-10-30). | None | None | None | None |
| [0041 — Adopt enolalab as the canonical GitHub org and module path](0041-adopt-enolalab-as-canonical-org-and-module-path.md) | Accepted | Central maintainer | 2026-10-11 | None; implementation authorized (`central-rust` public repo `enolalab/central-workspace`, 2026-10-30). | None | None | None | None |
| [0042 — Rewrite git history with `git filter-repo` once, before the visibility flip](0042-rewrite-git-history-with-filter-repo-before-going-public.md) | Accepted | Central maintainer | 2026-10-11 | The rewrite-day force-push and the #56 visibility flip — both still require the maintainer's explicit go-ahead at execution time. | None | None | None | None |
| [0043 — Adopt Rust workspace and harness-first porting strategy](0043-adopt-rust-workspace-and-harness-first-porting-strategy.md) | Accepted | Central maintainer | 2026-10-21 | Phase R1 Cargo workspace scaffold, canonical SQL extraction (`v0`..`b37`), `central-adapter-postgres` migration-runner implementation, and every later `central-rust` R-slice; the upstream Go `central` repository is not blocked. | None | None | 0008 — in `central-rust` only: adapts Gate 7 application boundaries to the Rust Cargo Workspace while retaining all upstream ADR 0001–0042 domain, security, persistence, and topology decisions | None |
| [0044 — Keep the broker seccomp allow-list fixed and port the Rust runtime surface to listed syscalls](0044-keep-broker-seccomp-list-fixed-and-port-to-listed-syscalls.md) | Accepted | Central maintainer | 2026-10-26 | None; implementation shipped under ADR 0028 D3 and accepted 2026-10-30. | None | None | None | None |
