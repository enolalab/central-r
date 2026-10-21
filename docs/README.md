# Central Documentation

This directory is the source of truth for Central's product direction, architecture, roadmap, and implementation scope.

`central-rust` is the full-parity Rust reimplementation of the upstream Go `central` codebase, delivered as the `R0`–`R6` vertical-slice sequence under Accepted [ADR 0043](adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md), which amends ADR 0008 for this repository (Cargo Workspace crates replace Go module/package boundaries; every other upstream decision stands). The upstream ledger — Phase 0 gates G1–G10 complete, Phase 1 Slices A–E accepted at their recorded evidence tiers, the Harness Control Plane (ADR 0035/0036) delivered, and Phase 2 orchestration exit-complete at machine tier — is authoritative in the upstream repository; its gate reviews and evidence archives live there and are not copied here. Current delivery scope is defined in [implementation/current-phase.md](implementation/current-phase.md) and [implementation/rust-vertical-slice-roadmap.md](implementation/rust-vertical-slice-roadmap.md).

## Public vs internal

`docs/` is the public documentation set — product, architecture, operations,
security, ADRs, and the current implementation boundary. `docs/internal/`
holds process records: working plans, specs, reviews, gate evidence, and
task reports. They stay public for transparency, not as onboarding
material — start with the sections below and consult `docs/internal/` for
the provenance behind a decision.

## Start here

- [`newcomer-guide.md`](newcomer-guide.md): one-page orientation — architecture at a glance, the security model, and the glossary the rest of these docs use
- [`operations/user-install-guide.md`](operations/user-install-guide.md): the user install walkthrough (English canonical; Vietnamese translation alongside)
- [`known-limitations.md`](known-limitations.md): what does not work yet — limitations, FAQ, and troubleshooting

## Product

- [`product/vision.md`](product/vision.md): product definition and positioning
- [`product/use-cases.md`](product/use-cases.md): supported local-first workflows
- [`product/roadmap.md`](product/roadmap.md): concise phased delivery plan
- [`product/phases.md`](product/phases.md): detailed phase outcomes, workstreams, required specifications, acceptance scenarios, and exit criteria
- [`product/web-ui-feature-spec.md`](product/web-ui-feature-spec.md): server-rendered Web UI feature contract
- [`product/agent-orchestration-view-design.md`](product/agent-orchestration-view-design.md): Phase 2 multi-agent run views design

## Architecture

- [`architecture/overview.md`](architecture/overview.md): system boundaries and major components
- [`architecture/durable-execution.md`](architecture/durable-execution.md): persisted execution, retries, checkpoints, and recovery
- [`architecture/online-mode.md`](architecture/online-mode.md): future connection between Local Central and Central Server
- [`runtime/agent-runtime.md`](runtime/agent-runtime.md): Agent runtime contract — coordinator, provider evidence, executor, and budgets (Gate 3)
- [`runtime/tool-invocation.md`](runtime/tool-invocation.md): Tool invocation contract — authorization-use fence, secret-aware adapter, and reconciliation (Gate 3)
- [`runtime/checkpoints.md`](runtime/checkpoints.md): Checkpoint recovery contract — envelope, compatibility, migration, and resume (Gate 3)
- [`artifacts/lifecycle.md`](artifacts/lifecycle.md): Artifact lifecycle contract — identity, staging, verification, finalization, readiness, lineage, deletion, recovery, cleanup, and quota admission (Gate 4)
- [`artifacts/content-policy.md`](artifacts/content-policy.md): Artifact content policy — untrusted-body trust boundary, detected classification, Central-mediated delivery, disposition, preview allowlist, and inspection hard bounds (Gate 4)
- [`api/v1.md`](api/v1.md): API v1 contract — HTTP transport surface, request/response schema, and versioning (Gate 5)
- [`events/v1.md`](events/v1.md): Event v1 contract — serialized Event envelope, schema-versioned identity, and cursor-based feed (Gate 5)
- [`persistence/postgresql.md`](persistence/postgresql.md): PostgreSQL persistence contract — authoritative records, transaction and concurrency rules, session persistence, capacity accounting, Event sequence and outbox semantics, query and index requirements, role separation, and validation scenarios (Gate 6)
- [`persistence/migrations-and-recovery.md`](persistence/migrations-and-recovery.md): Migrations and recovery contract — forward-only migration lifecycle, metadata/data-backfill classification, backup/restore manifest rules, retention windows, and cleanup contract (Gate 6)
- [`architecture/rust-application-boundaries.md`](architecture/rust-application-boundaries.md): Rust Application Boundaries contract — Cargo Workspace and dependency baseline, four per-capability Clean Architecture roles, capability-owned ports, `sqlx`/`aws-sdk-s3`/`rustix` adapter isolation, manual composition in `central-kernel`, crate and binary topology, controller and rendering contracts, and resource matrix (ADR 0043)
- [`persistence/postgresql-adapter-mapping.md`](persistence/postgresql-adapter-mapping.md): PostgreSQL Adapter Mapping contract — `sqlx` compile-time checked query mapping with `.sqlx/` offline verification, Rust type mapping, SQL-construction policy, index matrix, role grants, and the native `central.schema_migrations` ledger across `v0..b37` (ADR 0043)
- [`architecture/local-development-environment.md`](architecture/local-development-environment.md): Local Development Environment topology contract — host and Compose topology, helper/broker/launcher/browser identities, config/protected state, local operation journals, backup/restore, Phase 1 slices, and observability contract (Gate 8, design-only)

## Operations

User-facing and maintainer documents:

- [`operations/user-install-guide.md`](operations/user-install-guide.md): install/upgrade/uninstall walkthrough for users — verified release flow, offline bundle import, `--from-source` development variant (Vietnamese: [`operations/user-install-guide.vi.md`](operations/user-install-guide.vi.md))
- [`operations/install-acceptance.md`](operations/install-acceptance.md): maintainer install-acceptance rehearsal — clean-VM release install → init → verify → console screenshot → upgrade → uninstall
- [`operations/release-authority-custody.md`](operations/release-authority-custody.md): advisory-key and tarball-signer custody, fingerprints, offline signing, and rotation
- [`operations/harness-execution.md`](operations/harness-execution.md): harness execution operational runbook — launcher, permission policies, budgets, capture, and ambiguous-attempt recovery
- [`operations/phase-2-run-submit.md`](operations/phase-2-run-submit.md): Phase 2 run submission operations contract
- [`compatibility.md`](compatibility.md): central ↔ central-local-infra version matrix, digest pinning, and release-coordination protocol

The documents below are **design-only Gate 8 contracts**: upstream, commands in them returned `exit 5` / `UNSUPPORTED_IN_THIS_SLICE` without mutation until implemented and accepted. In `central-rust` they are the contracts R5/R6 implement against; nothing is executable until its owning R-slice lands.

- **[Operator start here](architecture/local-development-environment.md#operator-start-here-index):** The canonical first-use journey index documents the operator workflow from fresh host to running Central (`init → trust install → security update → doctor → prepare → up → migrate up → attached serve → browser open → bootstrap show`). See also the [changed-code daily journey](architecture/local-development-environment.md#verbatim-changed-code-daily-journey) for the development workflow.
- [`operations/local-prerequisites.md`](operations/local-prerequisites.md): administrator signed-source and package-authority runbook — exact APT sources, Docker, Compose, helper/broker/sandbox-launcher installation, PAM, AppArmor, two-clean-host evidence (Gate 8, design-only)
- [`operations/local-security-authority.md`](operations/local-security-authority.md): release-security operational runbook — advisory bundle lifecycle, Ed25519 signing ceremony, current/stale/hard-expired/deny behavior, emergency response, key custody, offline distribution (Gate 8, design-only)
- [`operations/local-backup-and-restore.md`](operations/local-backup-and-restore.md): local backup and restore topology — exclusive target capture, `pg_dump`/`pg_restore` tool adapters, one-use restore tickets, authority reset, rescue lifecycle, wipe with AppArmor, export/import/delete/prune (Gate 8, design-only)

## Security

- [`security/threat-model.md`](security/threat-model.md): Phase 1 local assets, actors, trust boundaries, threats, controls, and residual risks
- [`security/capability-policy.md`](security/capability-policy.md): capability taxonomy, policy outcomes, Approval defaults, grant semantics, local authentication, and audit rules
- [`security/secret-reference.md`](security/secret-reference.md): opaque secret identity, protected binding, resolver boundary, lifecycle, failure, and validation contract
- [`security/local-configuration-and-protected-state.md`](security/local-configuration-and-protected-state.md): configuration and protected-state contract — `central.config/v1` schema, immutable authority transition records, signed XDG projections, protected stores, and secret-version envelope (Gate 8, design-only)

## Architecture decisions

- [`adr/README.md`](adr/README.md): ADR governance, lifecycle, and decision index (`0001`–`0043`)
- [ADR 0004](adr/0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md): Accepted staged single-agent runtime and verified adapter handoffs (Gate 3)
- [ADR 0005](adr/0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md): Accepted verified Artifact lifecycle and safe content delivery (Gate 4)
- [ADR 0006](adr/0006-adopt-local-v1-api-and-event-serialization.md): Accepted local-first API v1 and Event serialization (Gate 5)
- [ADR 0007](adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md): Accepted PostgreSQL persistence and recovery contracts (Gate 6)
- [ADR 0008](adr/0008-adopt-capability-owned-go-application-boundaries.md): Accepted capability-owned application boundaries (Gate 7; formulated for Go, adapted to Rust by ADR 0043)
- [ADR 0009](adr/0009-adopt-local-development-environment-topology.md): local development environment topology; historical/status authority resolves from the ADR index (Gate 8)
- [ADR 0010](adr/0010-reassign-gate-9-executable-slices-to-phase-1.md): replacement allocation for documentation-only Gate 9 and executable Phase 1; status authority resolves from the ADR index
- [ADR 0011](adr/0011-amend-local-topology-for-dedicated-migration-operator.md): dedicated migration-operator amendment to the local topology; superseded by ADR 0014
- [ADR 0012](adr/0012-extend-root-credential-mount-and-add-minio-provision-mode.md): Accepted extension of the root-credential mount and the `minio-provision` mode (SB-G3)
- [ADR 0013](adr/0013-widen-frame-0xb1-peer-authorization-to-admit-runtime-uid.md): Accepted widening of frame `0xb1` peer authorization to admit Central's runtime UID (SB-G3)
- [ADR 0014](adr/0014-authorize-postgresql-throughput-fixture-provisioner.md): Accepted PostgreSQL throughput fixture-provisioner mode; ADR 0008's upstream non-superseded amendment
- [ADR 0035](adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md): Accepted freeze of the B09 loop coordinator and adoption of the harness session boundary
- [ADR 0036](adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md): Accepted separate root-owned harness launcher for operator harness sessions
- [ADR 0043](adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md): Accepted Rust Cargo Workspace adoption and harness-first `R0`–`R6` porting strategy; amends ADR 0008 for this repository

## Implementation

- [`implementation/current-phase.md`](implementation/current-phase.md): current delivery boundary — the active R-slice
- [`implementation/rust-vertical-slice-roadmap.md`](implementation/rust-vertical-slice-roadmap.md): the complete `R0`–`R6` vertical-slice plan — owning capability crates, `v0..b37` migration authority, upstream references, and acceptance criteria
- [Phase 1 entry reconciliation register](implementation/phase-1-entry-reconciliation.md) — the six-item documentary gate required before Slice A code-level planning
- [`implementation/phase-1-vertical-slice-backlog.md`](implementation/phase-1-vertical-slice-backlog.md): Phase 1 master backlog — packet index, source census, traceability, and closure projection
- [`implementation/phase-1-slices/slice-a-host-authority-foundation.md`](implementation/phase-1-slices/slice-a-host-authority-foundation.md): Slice A dossier — host authority foundation (A01–A07)
- [`implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md`](implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md): Slice B dossier — first safe runnable environment (B01–B12)
- [`implementation/phase-1-slices/slice-c-required-recovery.md`](implementation/phase-1-slices/slice-c-required-recovery.md): Slice C dossier — required recovery (C01–C06)
- [`implementation/phase-1-slices/slice-d-destructive-portable-operations.md`](implementation/phase-1-slices/slice-d-destructive-portable-operations.md): Slice D dossier — destructive portable operations (D01–D07)
- [`implementation/phase-1-slices/slice-e-dependency-maintenance.md`](implementation/phase-1-slices/slice-e-dependency-maintenance.md): Slice E dossier — dependency maintenance (E01–E06)
- [`implementation/phase-2-slices/README.md`](implementation/phase-2-slices/README.md): Phase 2 dossier index — workflow graph/lineage (2A), scheduler/workers (2B), checkpoint/resume (2C), retry/idempotency (2D), graph UI (2E), acceptance (2F)
- [`implementation/spec-and-plan-guide.md`](implementation/spec-and-plan-guide.md): process for converting phases into technical specifications and implementation plans
- [`implementation/rust-engineering-workflow.md`](implementation/rust-engineering-workflow.md): Rust Engineering Workflow contract — toolchain pinning, workspace dependency and lint policy, `sqlx` compile-time verification and `.sqlx/` hygiene, `cargo fmt`/`clippy`/`deny`/`test` fail-fast pipeline, and the four-tier test taxonomy (ADR 0043)

## Approved designs and validation

The governing design specs for the ported contracts live under `internal/superpowers/specs/`; the upstream gate reviews, audits, and acceptance evidence that validated them are archived in the upstream `central` repository and are authoritative there.

- [`superpowers/specs/2026-07-12-phase-0-domain-lifecycle-design.md`](internal/superpowers/specs/2026-07-12-phase-0-domain-lifecycle-design.md): approved Phase 0 domain and durable-lifecycle design
- [`superpowers/specs/2026-07-13-phase-0-security-baseline-secret-reference-design.md`](internal/superpowers/specs/2026-07-13-phase-0-security-baseline-secret-reference-design.md): approved Gate 2 security baseline and SecretReference design
- [`superpowers/specs/2026-07-14-phase-0-runtime-contracts-design.md`](internal/superpowers/specs/2026-07-14-phase-0-runtime-contracts-design.md): approved Gate 3 runtime contracts design
- [`superpowers/specs/2026-07-14-phase-0-artifact-storage-content-policy-design.md`](internal/superpowers/specs/2026-07-14-phase-0-artifact-storage-content-policy-design.md): approved Gate 4 artifact storage and content policy design
- [`superpowers/specs/2026-07-14-phase-0-api-event-serialization-design.md`](internal/superpowers/specs/2026-07-14-phase-0-api-event-serialization-design.md): approved Gate 5 API and Event serialization design
- [`superpowers/specs/2026-07-14-phase-0-postgresql-persistence-design.md`](internal/superpowers/specs/2026-07-14-phase-0-postgresql-persistence-design.md): approved Gate 6 PostgreSQL persistence design
- [`superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md`](internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md): **Approved** Gate 8 local development environment governing design
- [`superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md`](internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md): **Approved** governing design for this repository — documentation porting strategy, Rust application boundaries, `sqlx` adapter mapping, engineering workflow, and the `R0`–`R6` roadmap
- [`superpowers/plans/2026-10-21-phase-r0-documentation-baseline.md`](internal/superpowers/plans/2026-10-21-phase-r0-documentation-baseline.md): Phase R0 implementation plan
- [`superpowers/reviews/2026-10-21-central-rust-documentation-and-architecture-spec-review.md`](internal/superpowers/reviews/2026-10-21-central-rust-documentation-and-architecture-spec-review.md): review record for the governing spec

Significant architectural decisions should be recorded as ADRs under `docs/adr/` before implementation diverges from the documented design.
