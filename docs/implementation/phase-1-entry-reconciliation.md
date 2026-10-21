# Phase 1 Entry Reconciliation Register

- **Governing design:** Phase 1 Local Central MVP Strategy Design (upstream `central` record: `docs/internal/superpowers/specs/2026-07-17-phase-1-local-central-mvp-strategy-design.md`)
- **Owner:** Central maintainer
- **Gate status:** Complete
- **Scope:** Documentary reconciliation only; no executable implementation is authorized

## Resolution rule

Accepted ADRs and canonical contracts control. The master backlog owns global packet order, dependencies, readiness, command deferral, milestones, and cross-slice acceptance. Slice dossiers own packet-local behavior and evidence. A material decision change returns through ADR governance.

## Contradiction register

| ID | Finding | Governing authority | Disposition | Verification |
| --- | --- | --- | --- | --- |
| P1-ER-01 | Slice B claims operator-driven backup/restore although master acceptance assigns it to Slice C. | Strategy milestones; ADR 0010 Slice C allocation; local-environment contract §11 | B12 owns only the documented, unscheduled manual `pg_dump` + `mc mirror` Preview bridge. C01–C06 own Central-managed backup/verify/status/resume and restore verify/apply/status/resume, quarantine, and authority reset. | Slice B introduction and acceptance name only the bridge; Slice C owns automated recovery commands and acceptance. |
| P1-ER-02 | B02 describes online tag-like image pulls, service startup, and health ownership. | ADR 0010 dependency selection; local-environment contract §§2.3, 5, 11 | B02 owns explicit offline `central local prepare`, exact OCI/source identities, hermetic two-clean-builder MinIO reproducibility, digest verification, and no service start. B03 owns six-service `up/down/status`, ordered lifecycle, and health gating. | Searches reject `pull exact pinned` and service-start claims in B02; B02 and B03 dependency/acceptance text agree with the master. |
| P1-ER-03 | B04 derives credentials from instance identity and writes values to files. | ADR 0003; ADR 0010 protected broker and `protected_file_v1`; SecretReference contract | The broker generates non-derivable create-only credential generations, retains values in protected memory/backend custody, persists only protected backend material inaccessible to operator/runtime/agent, and hands values to registered adapters through operation-bound descriptors after authorization-fence revalidation. No plaintext value is written to configuration, Workspace, XDG, command arguments, environment variables, or logs. | Security-critical searches find no deterministic credential derivation, base64 secret values, or plaintext credential-file contract. |
| P1-ER-04 | Helper, broker, TLS, topology, migration, Run/Step/Event, and Artifact ownership differ between master and dossiers. | ADRs 0004–0008 and 0010; Go application boundaries; local-environment contract §11 | A03 owns helper/locked identities; A04 owns broker/protected state/TLS authority; A05 owns strict configuration and signed projections; B02 owns dependency preparation; B03 owns Compose lifecycle; B04 owns descriptor secret handoff; B05 owns migration zero; B08 owns Run/StepAttempt/Event evidence; B10 owns Artifact lifecycle; C owns managed backup/restore; D owns deletion/retention/portable operations; E owns maintenance. | Master packet index, implementation-sequence mapping, capability mapping, scenario mapping, and all dossier scope-control sections use this single ownership matrix. |
| P1-ER-05 | B11 overlaps Loading/Progress, invents restart reconciliation as a Task state, and exposes Delete before Slice D. | ADR 0001 lifecycle; Go application boundaries §4.7; strategy operator projections | B11 exposes exactly Empty, Queued, Running, Waiting, Settling, Unsuccessful, and Completed projections. Restart reconciliation is an instance-level banner and interaction barrier over affected canonical states. Delete/prune are absent until D04. | B11 table has exactly seven named projections, no invented lifecycle state, and no Delete/Prune action. |
| P1-ER-06 | The earlier register required a Central-owned execution-selection gate before B09 planning. | ADR 0004 provider-agnostic `agent/port`; approved B09 Agent Adapter Boundary Design (upstream `central` record: `docs/internal/superpowers/specs/2026-08-03-b09-agent-adapter-boundary-design.md`) | **Superseded.** Central does not own provider selection or provider execution. B09 production acceptance instead requires generic external agent-adapter delivery and composition, trusted Central-to-agent dispatch, live PostgreSQL evidence, serving composition, restart/recovery, and applicable Docker/external infrastructure evidence. | Current-phase, roadmap, backlog, Slice B dossier, and the Slice B acceptance program must use these generic blockers and must not claim B09 accepted before their immutable evidence and independent verdict pass. |

## Gate completion checklist

- [x] Every register row has a disposition, authority, owner where applicable, and deterministic verification.
- [x] Every packet has one canonical owner, dependency set, behavior, and acceptance contribution.
- [x] Master-to-dossier and requirement-to-packet links resolve both ways.
- [x] Deferred commands return `exit 5` / `UNSUPPORTED_IN_THIS_SLICE` without mutation until their owning slice is accepted.
- [x] Contradiction searches, structural checks, `git diff --check`, and the canonical local-link resolver pass.
- [x] An independent review records zero unresolved Critical, Important, or Minor findings, or routes a material decision through ADR governance.

**Maintainer validation:** 2026-07-17 validation report (upstream `central` record: `docs/internal/superpowers/reviews/2026-07-17-phase-1-entry-reconciliation-validation.md`) — all deterministic checks passed.

**Independent review:** 2026-07-17 independent review (upstream `central` record: `docs/internal/superpowers/reviews/2026-07-17-phase-1-entry-reconciliation-review.md`) — zero unresolved findings; gate complete.

P1-ER-06's execution-selection blocker is superseded by the approved agent-adapter boundary. The completed entry gate is unchanged; the remaining B09 production blockers are generic agent-adapter delivery/composition, live PostgreSQL, serving composition, restart/recovery, and applicable external infrastructure evidence.

## B09 production acceptance blockers

- **Generic agent adapter:** delivery and composition of an externally supplied adapter contract; no OpenCode transport is invented here.
- **Central-to-agent evidence:** trusted dispatch scope, opaque provider handling, durable invocation outcome, restart reconciliation, and no blind duplicate agent invocation.
- **Runtime evidence:** live PostgreSQL, serving composition, restart/recovery, and Docker-backed recovery evidence.
- **External infrastructure:** applicable `central-local-infra` or other external delivery evidence required by B10 or serving composition.
