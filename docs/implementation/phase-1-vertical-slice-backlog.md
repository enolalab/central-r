# Phase 1 Vertical-Slice Implementation Backlog

- **Plan ID:** P0-G9-G10-BACKLOG-CLOSURE
- **Execution base:** `5ccaa551feaf26cffb7e01991fdbcce3b6210ef9` (VALIDATOR_ACCEPTANCE_TARGET)
- **Governing design:** Approved Phase 0 Implementation Backlog and Closure Design
- **Governing authority:** ADR 0014 is Accepted as ADR 0008's non-superseded amendment, superseding ADR 0011 (which superseded ADR 0010). B05 has a narrow packet-level activation exception for `migrate up`, exact `migrate resume`, `migrate status`, `migrate verify`, and exact failed-version-zero `migrate reset`; all other deferred commands remain fail-closed until their owning packet is accepted. The unaccepted Slice C candidate branch routes `backup` and `restore verify`/`apply`/`resume` ahead of acceptance; that routing carries no packet-level activation authority until C01–C05 are Accepted.
- **Current Slice B status:** Accepted (2026-08-08). B01–B09 Accepted; SB-G2 Accepted (2026-08-06, `central-local-infra`'s immutable-candidate delivery and Central's root-credential-boundary evidence both closed); SB-G3 Accepted and B10 Accepted (2026-08-07, real broker-scoped MinIO runtime credential chain); SB-G4 Accepted and B11 Accepted (2026-08-08, real Chromium/Firefox operator-flow acceptance); SB-G5 Accepted and B12 Accepted (2026-08-08, real B09/B10/B11 clean-host acceptance) — see [current phase](current-phase.md) for full evidence links.
- **Acceptance program:** Slice B acceptance program (upstream `central` record: `docs/internal/superpowers/plans/2026-08-03-slice-b-acceptance-program.md`) governed SB-G0 through SB-G5; all six gates are now Accepted, closing Slice B. Slice C is governed by the Slice C required-recovery plan (upstream `central` record: `docs/internal/superpowers/plans/2026-08-09-slice-c-required-recovery.md`), where every gate requires a `central.slice-c-acceptance/v1` manifest and an independent verdict. That manifest is specified in Slice C acceptance governance (upstream `central` record: `docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md`) (ratified 2026-08-15), which defines required fields, prohibitions, per-gate requirements, independence, and the immutable-candidate rule, and which accepts no packet and changes no status.
- **Current Slice C status:** SC-G0's 2026-08-09 acceptance record was withdrawn 2026-08-17 — no supporting manifest or independent verdict existed in this repository or `central-local-infra` (withdrawal decision (upstream `central` record: `docs/internal/superpowers/reviews/2026-08-17-sc-g0-record-withdrawal.md`)); SC-G0 was re-run for real the same day: a conforming manifest and complete evidence are archived in-tree (`docs/internal/superpowers/reviews/evidence/2026-08-17-sc-g0/`, manifest SHA-256 `2a00163a…`), and its independent verdict was issued 2026-08-18 — **SC-G0 is Accepted** (verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-08-17-sc-g0-acceptance.md`)), the first Slice C gate to pass, authorizing no packet. C01–C06 candidate implementation is present on the branch and unaccepted; C06's acceptance suite has run once against a self-provisioned reference host (2026-08-16), found and fixed five product defects outside its own scope (P-1–P-5), and produced no acceptance evidence. A 2026-09-09 dev-admission rehearsal (`ceremony_mode: grant`, not a physical-console run) subsequently completed `restore verify → apply` end to end for the first time, reaching `ready`/`authority_reset` and fixing eight further, never-previously-reachable defects (`docs/internal/tasks/sc-def-59-*.md` through `docs/internal/tasks/sc-def-65-*.md`). A follow-up session then closed B01's own production-wiring gap and, on 2026-09-10, the maintainer (`hieuntg81`) — now the sole contributor to this repository and `central-local-infra` — amended Slice C governance §5 (upstream `central` record: `docs/internal/superpowers/specs/2026-08-14-slice-c-acceptance-governance.md`) and the parallel Slice B governance (upstream `central` record: `docs/internal/superpowers/specs/2026-08-02-slice-b-acceptance-governance.md`) to drop the provenance-independence requirement, introducing the **Accepted (self-issued)** label. Under that amendment, a fresh `central-local-infra` delivery (SC-DEF-44) was published PASS self-issued, a real `capacity_reserve` measurement was captured, the SC-G1 manifest was bound, and a self-issued verdict was recorded: SC-G1 was claimed Accepted (self-issued) — but **withdrawn the same day** (withdrawal decision (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g1-record-withdrawal.md`)): candidate commit `d767568` does not build `go build ./...` from a clean checkout (it silently depended on files never committed, closing a gap dating to 2026-09-08), so the cited `local up`/`backup create` evidence was a dirty-worktree result, not immutable-candidate evidence. The build gap was fixed the same day (`a0baf21`, `467b9cc`, verified clean via `go build ./...`/`go vet ./...`/tests, plus an unrelated co-discovered dependency-lock staleness fix, `f6d2f9e`), and SC-G1 was re-run for real against the resulting verified-buildable candidate `d4bbbfc`: **SC-G1 is Accepted (self-issued)** (verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g1-redo-acceptance.md`)) — **C01 and C02 are Accepted**. The same session then gathered SC-G2 evidence against the same candidate — two full restore verify→apply→ready/authority_reset cycles plus seven real negative/restart scenarios — and issued **SC-G2 is Accepted (self-issued)** (verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g2-acceptance.md`)) — **C03, C04, and C05 are Accepted**, with disclosed limitations (five negative scenarios not completed, `capacity_reserve` reported as a measurement not a certified allocation, restart-injection coverage partial). SC-G3 clean-host evidence remains required for C06; C02's production throughput gate is wired as of 2026-08-17 (no longer hardcoded fail-closed) with both former blockers implemented under ADR 0019/ADR 0020 (2026-08-17: version-zero receipt population at provisioning; first-boot superuser environment, role script, and helper-owned rotate-then-sync) — see [current phase](current-phase.md) for the candidate notes.
- **B10 report rule:** report materialization receives a source injected by an external agent adapter and fails closed when that source is absent; see the B09 Agent Adapter Boundary Design (upstream `central` record: `docs/internal/superpowers/specs/2026-08-03-b09-agent-adapter-boundary-design.md`).

## Phase outcome

Phase 1 delivers the first value-bearing Local Central: one user, one durable agent Task, verified artifacts, a server-rendered UI, restart recovery, and operator-driven backup and restore. It intentionally precedes the complete hardening and maintenance slices so Phase 1 does not become a big-bang delivery.

## Users

Single local operator with physical-seat access to a Linux host. No multi-user, remote, or enterprise identity required in Phase 1.

## Supported host

Ubuntu 24.04 LTS amd64 with Docker 29.6.1, Compose 5.3.1, PostgreSQL 16.14, and MinIO running under Compose. Exact runtime constraints are defined in the approved [Local Development Environment topology contract](../architecture/local-development-environment.md).

## Non-goals

- Central Server or Online Mode
- Multi-tenant organizations, projects, or workspaces
- Marketplace or public plugin distribution
- Distributed or Kubernetes scheduling
- Complex frontend frameworks
- Automatic production remediation
- Unrestricted shell or filesystem access
- Executable product code, database migrations, or infrastructure deployment before Phase 1

## Slice dependency graph

```
Slice A: Host authority foundation (A01–A07)
  ↓
Slice B: First safe runnable environment (B01–B12)
  ↓
Slice C: Required recovery (C01–C06)
  ↓
Slice D: Destructive portable operations (D01–D07)
  ↓
Slice E: Dependency maintenance (E01–E06)
```

## First-value and full-exit definitions

**First value (Slice B complete):** One agent Task executes end-to-end, durably persists its state, saves verified artifacts, exposes progress in the server-rendered UI, and recovers safely after an application restart.

**Full exit (all slices complete):** Operator-driven verified local backup/restore, interruption-safe external restore barrier and quarantine, post-restore security epoch plus fresh bootstrap/authority reevaluation, destructive portable operations, dependency maintenance, and the complete compatibility, recovery, security-sentinel, and minimum-profile performance/resource suite.

## Packet readiness

A packet is **Ready** when its dossier defines every mandatory section with zero open decisions or unresolved placeholders, all dependencies are listed, and its Definition of Done is testable.

## Slice readiness

A slice is **Ready** when all its packets are Ready, the master backlog records complete traceability, and the slice's acceptance scenario is testable.

## Phase readiness

Phase 1 is **Ready** when all five slices are Ready, the master backlog maps every Accepted requirement to a packet and evidence owner, the critical path and permitted parallelism are defined, and the independent readiness audit passes.

## Change control

The master backlog is the sole global authority for packet ordering, dependencies, status, and cross-slice acceptance. Dossiers own packet contract detail only. Changing a packet contract requires a dependency-impact review of affected slices. Adding a new packet requires a fresh source-census increment and reassignment of existing requirement coverage.

---

## Packet index

**Reading the Status column:** Status records governance state. A packet becomes Accepted only through its gate's immutable evidence manifest and independent verdict; candidate implementation present on a branch is recorded here as context and never changes a packet's status by itself.

| ID | Dossier anchor | Outcome | Status | Dependencies | Capability IDs | Authority IDs | Future plan anchor | Future test owner | Evidence owner | Evidence visibility | Phase 1 contribution |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A01 | [slice-a-host-authority-foundation.md#a01](../implementation/phase-1-slices/slice-a-host-authority-foundation.md#a01) | Single Go module, pinned toolchain, reproducible build substrate and architecture-import checks | Complete | None | P1-C01 | REQ-SRC-0001 | slice-a-plan.md#a01 | slice-a-test-suite | Slice A dossier | Operator CLI | Bootstrap Phase 1 foundation |
| A02 | [slice-a-host-authority-foundation.md#a02](../implementation/phase-1-slices/slice-a-host-authority-foundation.md#a02) | Complete A–E command census, closed grammar, deferred dispatcher, exit-5 matrix, and activation rule | Complete | A01 | P1-C01 | REQ-SRC-0002 | slice-a-plan.md#a02 | slice-a-test-suite | Slice A dossier | Operator CLI | Command registry for all slices |
| A03 | [slice-a-host-authority-foundation.md#a03](../implementation/phase-1-slices/slice-a-host-authority-foundation.md#a03) | Instance genesis, locked identity derivation, and helper/PAM agent binding | Complete | A01, A02 | P1-C01 | REQ-SRC-0003 | slice-a-plan.md#a03 | slice-a-test-suite | Slice A dossier | Operator CLI | Instance identity and authorization |
| A04 | [slice-a-host-authority-foundation.md#a04](../implementation/phase-1-slices/slice-a-host-authority-foundation.md#a04) | Protected broker, `protected_file_v1`, local TLS authority, signed authority transitions, and protected-state custody | Complete | A03 | P1-C01 | REQ-SRC-0004 | slice-a-plan.md#a04 | slice-a-test-suite | Slice A dossier | Operator CLI | Secure service communication |
| A05 | [slice-a-host-authority-foundation.md#a05](../implementation/phase-1-slices/slice-a-host-authority-foundation.md#a05) | Strict `central.config/v1`, signed XDG projections, runtime instance configuration, and no secret values | Complete | A03, A04 | P1-C01 | REQ-SRC-0005 | slice-a-plan.md#a05 | slice-a-test-suite | Slice A dossier | Operator CLI | Runtime configuration authority |
| A06 | [slice-a-host-authority-foundation.md#a06](../implementation/phase-1-slices/slice-a-host-authority-foundation.md#a06) | Sandbox launcher with CPU, memory, process, fd, namespace, deadline, and cleanup bounds | Complete | A03, A04, A05 | P1-C05 | REQ-SRC-0006 | slice-a-plan.md#a06 | slice-a-test-suite | Slice A dossier | Operator CLI | Sandbox resource governance |
| A07 | [slice-a-host-authority-foundation.md#a07](../implementation/phase-1-slices/slice-a-host-authority-foundation.md#a07) | Same-UID, descriptor, TTY, path-race, broker-crash, and authority denial proof | Complete; Slice A accepted 2026-07-18 | A03, A04, A05, A06 | P1-C05 | REQ-SRC-0007 | slice-a-plan.md#a07 | slice-a-test-suite | Slice A dossier | Operator CLI | Host authority verification |
| B01 | [slice-b-first-safe-runnable-environment.md#b01](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b01) | Local advisory consumer, signed bundle verification, and release-security evaluation | Accepted 2026-07-18 | A07 | P1-C01 | REQ-SRC-0008 | slice-b-plan.md#b01 | slice-b-test-suite | Slice B dossier | Operator CLI | Release security foundation |
| B02 | [slice-b-first-safe-runnable-environment.md#b02](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b02) | Offline hermetic dependency preparation, exact digest/source admission, and reproducible MinIO build evidence; starts no service | Accepted 2026-07-19 | B01 | P1-C01, P1-C02 | REQ-SRC-0009 | slice-b-plan.md#b02 | slice-b-test-suite | Slice B dossier | Operator CLI | Service admission and health |
| B03 | [slice-b-first-safe-runnable-environment.md#b03](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b03) | Six-service Compose `up/down/status`, ordered lifecycle, crash detection, and health-ready gating | Accepted 2026-07-20 on the portable semantic gate; decision committed 2026-08-12 (upstream `central` record: `docs/internal/superpowers/reviews/2026-08-12-b03-compose-lifecycle-acceptance-decision.md`), maintainer decision with no independent reviewer verdict, and the real Compose runner path remains unexercised | B02 | P1-C01, P1-C02 | REQ-SRC-0010 | slice-b-plan.md#b03 | slice-b-test-suite | Slice B dossier | Operator CLI | Service topology management |
| B04 | [slice-b-first-safe-runnable-environment.md#b04](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b04) | Broker-generated protected credential generations and authorization-fenced descriptor handoff; no derivation or plaintext files | Accepted 2026-07-21 | A04, B03 | P1-C01 | REQ-SRC-0011 | slice-b-plan.md#b04 | slice-b-test-suite | Slice B dossier | Internal | Secret and protected-state bootstrap |
| B05 | [slice-b-first-safe-runnable-environment.md#b05](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b05) | Version-zero inspection/provisioning and exact-operation migration resume using broker-held migration credentials | Accepted 2026-07-22 | A01, B03, B04 | P1-C02 | REQ-SRC-0012 | slice-b-plan.md#b05 | slice-b-test-suite | Slice B dossier | Internal | Database schema foundation |
| B06 | [slice-b-first-safe-runnable-environment.md#b06](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b06) | Host serve, browser open, and bootstrap session with anti-framing and security-epoch checks | Accepted 2026-07-23 | B04, B05 | P1-C01, P1-C07 | REQ-SRC-0013 | slice-b-plan.md#b06 | slice-b-test-suite | Slice B dossier | Operator UI | First operator-visible UI |
| B07 | [slice-b-first-safe-runnable-environment.md#b07](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b07) | Durable Task identity, lifecycle, and PostgreSQL persistence with index/query/connection/cursor and bounded-feed duties | Accepted 2026-07-26 | B05, B06 | P1-C03 | REQ-SRC-0014 | slice-b-plan.md#b07 | slice-b-test-suite | Slice B dossier | Operator UI | Task domain implementation |
| B08 | [slice-b-first-safe-runnable-environment.md#b08](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b08) | Run execution evidence, Step, immutable StepAttempt, ToolCallAttempt, Approval, Event/outbox, lease, checkpoint, and reconciliation | Accepted 2026-07-28 | B07 | P1-C04 | REQ-SRC-0015 | slice-b-plan.md#b08 | slice-b-test-suite | Slice B dossier | Operator UI | Execution recording |
| B09 | [slice-b-first-safe-runnable-environment.md#b09](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b09) | Generic Central-to-agent dispatch with ordered read-only filesystem Tool operations, opaque provider handling, durable invocation outcomes, and restart reconciliation | Accepted 2026-08-04; SB-G1 independent acceptance (upstream `central` record: `docs/internal/superpowers/reviews/2026-08-03-sb-g1-b09-acceptance.md`) | B08; generic external agent adapter delivery and composition; context builder, execution-driver binding, ToolCall persistence, serving composition, and recovery evidence | P1-C04, P1-C05 | REQ-SRC-0016 | slice-b-plan.md#b09 | slice-b-test-suite | Slice B dossier | Operator UI | Agent execution engine |
| B10 | [slice-b-first-safe-runnable-environment.md#b10](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b10) | Verified Artifact reserve/stage/verify/promote/finalize lifecycle, opaque keys, required completion guard, metadata, and lineage | Accepted 2026-08-07; SB-G3 independent acceptance (upstream `central` record: `docs/internal/superpowers/reviews/2026-08-03-sb-g3-b10-acceptance.md`) | B08; verified `central-local-infra` source, build recipe, pinned manifest, and broker-scoped MinIO runtime capability | P1-C06 | REQ-SRC-0017 | slice-b-plan.md#b10 | slice-b-test-suite | Slice B dossier | Operator UI | Artifact storage implementation |
| B11 | [slice-b-first-safe-runnable-environment.md#b11](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b11) | Server-rendered UI with seven canonical projections, instance restart banner, adaptive polling, accessible announcements, and sanitized Markdown preview | Accepted 2026-08-08; SB-G4 independent acceptance (upstream `central` record: `docs/internal/superpowers/reviews/2026-08-08-sb-g4-b11-acceptance.md`) | B06, B07, B08, B10 | P1-C07 | REQ-SRC-0018 | slice-b-plan.md#b11 | slice-b-test-suite | Slice B dossier | Operator UI | Complete operator interface |
| B12 | [slice-b-first-safe-runnable-environment.md#b12](../implementation/phase-1-slices/slice-b-first-safe-runnable-environment.md#b12) | Local MVP Preview acceptance plus documented unscheduled `pg_dump`/`mc mirror` manual backup bridge | Accepted 2026-08-08; SB-G5 independent acceptance (upstream `central` record: `docs/internal/superpowers/reviews/2026-08-08-sb-g5-b12-acceptance.md`) | B01–B11 | P1-C08, P1-C10 | REQ-SRC-0019 | slice-b-plan.md#b12 | slice-b-test-suite | Slice B dossier | Operator UI | Slice B first-value exit |
| C01 | [slice-c-required-recovery.md#c01](../implementation/phase-1-slices/slice-c-required-recovery.md#c01) | Sealed backup creation with timestamped identity, pg_dump 16.14 tool adapter, and immutable repository evidence | **Accepted** — a same-day self-issued SC-G1 verdict (bound to Central candidate `d767568`) was **withdrawn 2026-09-10** (decision (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g1-record-withdrawal.md`)): `d767568` did not build from a clean checkout, so the cited evidence was a dirty-worktree result, not an immutable candidate. Build gap fixed (`a0baf21`, `467b9cc`, `f6d2f9e`); SC-G1 was redone against verified-buildable candidate `d4bbbfc` and **SC-G1 is Accepted (self-issued)** (verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g1-redo-acceptance.md`)) | B12, SC-G0, SC-G1 | P1-C10 | REQ-SRC-0020 | Slice C plan Task 1 (upstream `central` record: `docs/internal/superpowers/plans/2026-08-09-slice-c-required-recovery.md`) | slice-c-test-suite | Slice C dossier | Operator CLI | Backup creation |
| C02 | [slice-c-required-recovery.md#c02](../implementation/phase-1-slices/slice-c-required-recovery.md#c02) | Backup throughput and capacity admission with representative probes, reserve/floor formulas, device aggregation, continuous guards, deadlines, permit/session census, and outside-profile results | **Accepted** — coupled to C01; its self-issued SC-G1 verdict was **withdrawn 2026-09-10** for the same reason (decision (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g1-record-withdrawal.md`)); SC-G1 was redone the same day and **SC-G1 is Accepted (self-issued)** (verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g1-redo-acceptance.md`)) | SC-G0, SC-G1, C01 (acceptance) | P1-C10 | REQ-SRC-0021 | Slice C plan Task 2 (upstream `central` record: `docs/internal/superpowers/plans/2026-08-09-slice-c-required-recovery.md`) | slice-c-test-suite | Slice C dossier | Operator CLI | Backup capacity governance |
| C03 | [slice-c-required-recovery.md#c03](../implementation/phase-1-slices/slice-c-required-recovery.md#c03) | Restore verification, one-use restore ticket, and PAM authorization | **Accepted** — C01/C02 are now Accepted (SC-G1 redo, verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g1-redo-acceptance.md`)). Candidate implemented 2026-08-10 and extended 2026-08-14 with the restore capacity reserve gate ([ADR 0018](../adr/0018-authorize-the-restore-capacity-reserve-authority.md)), which supplies the production `RestoreCapacityReserveVerifier` the earlier candidate lacked; the restore CLI is registered and the chain is reachable; `restore verify`/`apply`/`resume`/`abandon` reach the production handler. SC-G2 evidence — two real `verify → apply → ready/authority_reset` cycles plus negative scenarios (ticket replay, wrong ticket, ticket expiry, target-admission-stale) — was gathered 2026-09-10 and **SC-G2 is Accepted (self-issued)** (verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g2-acceptance.md`)) | C01, C02 | P1-C10 | REQ-SRC-0022 | Slice C plan Task 3 (upstream `central` record: `docs/internal/superpowers/plans/2026-08-09-slice-c-required-recovery.md`) | slice-c-test-suite | Slice C dossier | Operator CLI | Restore admission |
| C04 | [slice-c-required-recovery.md#c04](../implementation/phase-1-slices/slice-c-required-recovery.md#c04) | Restore apply via pg_restore, quarantine barrier, fresh bootstrap, and no partially-served restore | **Accepted** — candidate implemented 2026-08-10 (routed verify/apply/resume, resumable quarantine barrier, root `central-restore` engine, broker frame `0xc2` kind-separated credentials); a 2026-09-09 dev-admission rehearsal completed a real `pg_restore` and the resumable barrier through inventory verification/quarantine for the first time, fixing several defects along the way (`docs/internal/tasks/sc-def-59-*.md` onward). SC-G2 evidence — two real `apply` completions (one surviving a mid-operation broker/helper restart) plus crash-injection and restart scenarios — was gathered 2026-09-10 and **SC-G2 is Accepted (self-issued)** (verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g2-acceptance.md`)) | C03 | P1-C02, P1-C10 | REQ-SRC-0023 | Slice C plan Task 4 (upstream `central` record: `docs/internal/superpowers/plans/2026-08-09-slice-c-required-recovery.md`) | slice-c-test-suite | Slice C dossier | Internal | Restore execution |
| C05 | [slice-c-required-recovery.md#c05](../implementation/phase-1-slices/slice-c-required-recovery.md#c05) | Post-restore authority reset: security epoch increment, fresh helper/PAM binding, broker TLS re-key, and bootstrap session re-authentication | **Accepted** — candidate implemented 2026-08-10 (v25 recovery-audit projection, v26 recovery-bootstrap registration, restore/security epoch advance, exactly one fresh operation-bound bootstrap generation); a 2026-09-09 dev-admission rehearsal completed the full authority-reset transaction (broker TLS rekey, bootstrap draft/activation, database reset/register/finalize) for the first time, reaching `ready`/`authority_reset`. SC-G2 evidence — real epoch-before/after and bootstrap-generation figures read directly from the live instance, twice — was gathered 2026-09-10 and **SC-G2 is Accepted (self-issued)** (verdict (upstream `central` record: `docs/internal/superpowers/reviews/2026-09-10-sc-g2-acceptance.md`)) | C04 | P1-C01, P1-C10 | REQ-SRC-0024 | Slice C plan Task 4 (upstream `central` record: `docs/internal/superpowers/plans/2026-08-09-slice-c-required-recovery.md`) | slice-c-test-suite | Slice C dossier | Internal | Restore authority recovery |
| C06 | [slice-c-required-recovery.md#c06](../implementation/phase-1-slices/slice-c-required-recovery.md#c06) | Full recovery acceptance with minimum-profile capacity/throughput failure assertions and end-to-end evidence | Unaccepted and blocked by C01–C05 acceptance; no candidate implementation | C01–C05 | P1-C08, P1-C10 | REQ-SRC-0025 | Slice C plan Task 5 (upstream `central` record: `docs/internal/superpowers/plans/2026-08-09-slice-c-required-recovery.md`) | slice-c-test-suite | Slice C dossier | Operator CLI | Slice C exit |
| D01 | [slice-d-destructive-portable-operations.md#d01](../implementation/phase-1-slices/slice-d-destructive-portable-operations.md#d01) | AppArmor wipe and protected-state reseed with fresh PAM, physical-seat confirmation, and safe denial under signed deny | Blocked by C06 acceptance | C06 | P1-C10 | REQ-SRC-0026 | slice-d-plan.md#d01 | slice-d-test-suite | Slice D dossier | Operator CLI | Protected reset |
| D02 | [slice-d-destructive-portable-operations.md#d02](../implementation/phase-1-slices/slice-d-destructive-portable-operations.md#d02) | Export and independent bx1 token for trusted fresh-host bootstrap | Blocked by C06/D01 acceptance | C06, D01 | P1-C10 | REQ-SRC-0027 | slice-d-plan.md#d02 | slice-d-test-suite | Slice D dossier | Operator CLI | Portable export |
| D03 | [slice-d-destructive-portable-operations.md#d03](../implementation/phase-1-slices/slice-d-destructive-portable-operations.md#d03) | Fresh-host import and bootstrap from exported data with descriptor-bound selection | Blocked by D02 acceptance | D02 | P1-C10 | REQ-SRC-0028 | slice-d-plan.md#d03 | slice-d-test-suite | Slice D dossier | Operator CLI | Portable import |
| D04 | [slice-d-destructive-portable-operations.md#d04](../implementation/phase-1-slices/slice-d-destructive-portable-operations.md#d04) | Delete and prune operations with checkpoints, retention/reference proof, and crash behavior | Blocked by C06 acceptance | C06 | P1-C10 | REQ-SRC-0029 | slice-d-plan.md#d04 | slice-d-test-suite | Slice D dossier | Operator CLI | Destructive cleanup |
| D05 | [slice-d-destructive-portable-operations.md#d05](../implementation/phase-1-slices/slice-d-destructive-portable-operations.md#d05) | Protected-state maintenance and audit with signed denials and prohibited force/manual repair | Blocked by C06 acceptance | C06 | P1-C10 | REQ-SRC-0030 | slice-d-plan.md#d05 | slice-d-test-suite | Slice D dossier | Internal | State integrity |
| D06 | [slice-d-destructive-portable-operations.md#d06](../implementation/phase-1-slices/slice-d-destructive-portable-operations.md#d06) | Hard-expired advisory rescue with deny-safe cleanup and fresh authority evaluation per B01 | Blocked by C06/D05/B01 acceptance | C06, D05, B01 | P1-C10 | REQ-SRC-0031 | slice-d-plan.md#d06 | slice-d-test-suite | Slice D dossier | Operator CLI | Security expiry rescue |
| D07 | [slice-d-destructive-portable-operations.md#d07](../implementation/phase-1-slices/slice-d-destructive-portable-operations.md#d07) | Slice D acceptance with destructive, portable, and authority evaluation evidence | Blocked by D01–D06 acceptance | D01–D06 | P1-C10 | REQ-SRC-0032 | slice-d-plan.md#d07 | slice-d-test-suite | Slice D dossier | Operator CLI | Slice D exit |
| E01 | [slice-e-dependency-maintenance.md#e01](../implementation/phase-1-slices/slice-e-dependency-maintenance.md#e01) | Compatibility planning with directional transition matrix and rejection of unlisted transitions | Blocked by D07 acceptance | D07 | P1-C01 | REQ-SRC-0033 | slice-e-plan.md#e01 | slice-e-test-suite | Slice E dossier | Operator CLI | Compatibility governance |
| E02 | [slice-e-dependency-maintenance.md#e02](../implementation/phase-1-slices/slice-e-dependency-maintenance.md#e02) | Patch apply with resume capability and post-patch verification | Blocked by E01 acceptance | E01 | P1-C01 | REQ-SRC-0034 | slice-e-plan.md#e02 | slice-e-test-suite | Slice E dossier | Operator CLI | Dependency updates |
| E03 | [slice-e-dependency-maintenance.md#e03](../implementation/phase-1-slices/slice-e-dependency-maintenance.md#e03) | Rollback with out-of-place fallback, exact evidence, and safe state preservation | Blocked by E02 acceptance | E02 | P1-C01 | REQ-SRC-0035 | slice-e-plan.md#e03 | slice-e-test-suite | Slice E dossier | Operator CLI | Safe rollback |
| E04 | [slice-e-dependency-maintenance.md#e04](../implementation/phase-1-slices/slice-e-dependency-maintenance.md#e04) | Advisory lifecycle conformance using externally produced fixtures; excludes compiler, signing ceremony, private-key custody, publication, and emergency response from runtime code | Blocked by E01/E02/E03 acceptance | E01, E02, E03 | P1-C01 | REQ-SRC-0036 | slice-e-plan.md#e04 | slice-e-test-suite | Slice E dossier | Operator CLI | Advisory lifecycle |
| E05 | [slice-e-dependency-maintenance.md#e05](../implementation/phase-1-slices/slice-e-dependency-maintenance.md#e05) | Operator runbooks for patch, rollback, and compatibility procedures | Blocked by E01/E02/E03/E04 acceptance | E01, E02, E03, E04 | P1-C01 | REQ-SRC-0037 | slice-e-plan.md#e05 | slice-e-test-suite | Slice E dossier | Operator CLI | Operator documentation |
| E06 | [slice-e-dependency-maintenance.md#e06](../implementation/phase-1-slices/slice-e-dependency-maintenance.md#e06) | Full Phase 1 suite ownership, final acceptance with complete maintenance evidence | Blocked by E01–E05 acceptance | E01–E05 | P1-C10 | REQ-SRC-0038 | slice-e-plan.md#e06 | slice-e-test-suite | Slice E dossier | Operator CLI | Phase 1 full exit |

**Total: 38 packets.** Slice A: 7, Slice B: 12, Slice C: 6, Slice D: 7, Slice E: 6. All IDs are unique across the complete A–E range.

---

## Source census

### Source-path/blob denominator

The exact Gates 1–8 source-path/blob denominator is frozen in `VALIDATOR_CONTRACT_TARGET` (`1860abddaa114ef8a8faa3bb5bff329103979389`) at `docs/internal/superpowers/reviews/2026-07-16-phase-0-implementation-backlog-validator-contract.md`. The following 36 source files constitute the complete accepted Gates 1–8 evidence corpus consumed by the source census:

| Path | Blob SHA-256 |
| --- | --- |
| `docs/product/vision.md` | `1566e2f48c03956de992fec92c4339bc3485fd82a6a988992f4873e17fb4f021` |
| `docs/product/use-cases.md` | `6891bf1bbb0412aa25f3ee8dea3331d0e4e63507b4e431294a673e39d67c18d4` |
| `docs/product/roadmap.md` | `b31ace2e0ee24dfc8011dfdf34c860cf17cd791ac2fe1ead06c07f2d9e6f7db2` |
| `docs/product/phases.md` | `d9d42a0f6dc8d286bfd5bb2824179312da901cebaf428bb9d278b3241fcfde2f` |
| `docs/architecture/overview.md` | `eb5d515e38b006ec9c891bfbe036ee28de8d101b6f1ab6bc39c1f71e6d22042e` |
| `docs/architecture/durable-execution.md` | `10070f6302fd52c074d4496d7ed468b89e9f459dd69018bab20e6d045a9c7d92` |
| `docs/runtime/agent-runtime.md` | `1caa3f9ce23918f8797fa8d77c502afad3097c589bdb755459f1b49c28d3915f` |
| `docs/runtime/tool-invocation.md` | `2f727b9731055a54397f0012b3a22f8281092f36f4ad43d96366d969c69a7e60` |
| `docs/runtime/checkpoints.md` | `fce168f49abe1a87db452c7db55ca1997272dfea9dd6060debd18e31baf0b4cb` |
| `docs/artifacts/lifecycle.md` | `6ca6bc03da5052566c320cd0e61c1e0e864798917e8ad13d349cb4726730398f` |
| `docs/artifacts/content-policy.md` | `1d80da4f3763c73eac6f9aea862c139f896ee728b7853d9b975a8325603eb94d` |
| `docs/api/v1.md` | `940a540ac0797bdca96c8317bfaf9e3037a0920cec14d8f9cc8de5356c11a9ad` |
| `docs/events/v1.md` | `75b1c59603bb0cba9a90ea88288d36845894ae10190bd934c12cf7a4654b83b0` |
| `docs/persistence/postgresql.md` | `919690fec89efd5753d6f5646eca654a6bbabfcd1f93e0542e68fcde3a89f8f0` |
| `docs/persistence/migrations-and-recovery.md` | `f793ead897ac63f90355a6b7b392e189b98c339417a9c70c9ca728ecfc0c343e` |
| `docs/architecture/go-application-boundaries.md` | `52865c14e654bf5ee379411793fcb53bec24ef3e077938794ad1abc447f1beff` |
| `docs/persistence/postgresql-adapter-mapping.md` | `ea9b6b01519c94c87488017afc3a59135120f3ec1938f8560b1b0551bde65697` |
| `docs/architecture/local-development-environment.md` | `98185d4c1ff75f768ca2570357d234f0c332804bcaced1a9ae4c9c259a33e27f` |
| `docs/operations/local-prerequisites.md` | `9fdf43eb419038f5f1a9ab13b91f59b6a7844a9d5bf8d8dbcf4fee0a529f7ba2` |
| `docs/operations/local-security-authority.md` | `f50094700251ea82cea98b474bdfa7a5526f5b544f0e7ba74bd76cc277d193b2` |
| `docs/operations/local-backup-and-restore.md` | `36efb243f835549f776d597f83decfb9ed8d7c7980c6fa78818d1c289cadb212` |
| `docs/security/threat-model.md` | `8aefbe5e63c5a2f14637ad7e47adc6f9769c0ff1509deda431f0dca1d0b36b3b` |
| `docs/security/capability-policy.md` | `6867ac6e35bf1680393b7cc858e7528084e8d74a9e1c11cc34886ee997dfa4a9` |
| `docs/security/secret-reference.md` | `5dc5ded36ce7cfea2eb7a90f24a5421741443ef324ff078d705093abf58749ee` |
| `docs/security/local-configuration-and-protected-state.md` | `e5a8a6b800ade630ddc6139d8e51ef0eb03c355f72e3b4d1445383c4a92492fe` |
| `docs/implementation/spec-and-plan-guide.md` | `fc3a8db539281ef76c6c4769941f5367c5ed188785f316b8e3a2299b9ede6f44` |
| `docs/implementation/go-engineering-workflow.md` | `5cf1af7168587aee0497fff8d3224ae264d4f05a8b71871e61f2735b8a63c763` |
| `docs/adr/0001-adopt-durable-task-domain-and-lifecycle.md` | `f40fe152aaafaa210614996a8221ffbe15a7ad70cfa27cd7397144ccdea470e1` |
| `docs/adr/0002-authorize-accepted-to-superseded-status-transitions.md` | `fc5280a694345675d83acd77f6c15aa97185183fbea027d4342ebb6b7189bb05` |
| `docs/adr/0003-adopt-phase-1-security-policy-and-secret-reference-model.md` | `f4f7774d32f45b4a531ba4fe93a690f1535fd02043ecdacc377f13a488d1dd42` |
| `docs/adr/0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md` | `c0b5341db9b768fdc467bcc175f4beb5e89d2138b4799a88663264ef83d70f92` |
| `docs/adr/0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md` | `c6ee3a920503d24d8190e6aa6d8addde024f52063be5b6322bea1abba9d16ef7` |
| `docs/adr/0006-adopt-local-v1-api-and-event-serialization.md` | `62f6d5b26c41909fea89bc3245e43cbb21c6672f28a2f905f415e3377a11e2b0` |
| `docs/adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md` | `92363c5676c5716eaf08497d028dd61c982ba0a117c8e7a263408a110cee0720` |
| `docs/adr/0008-adopt-capability-owned-go-application-boundaries.md` | `fd52410c50b66c3974f426a5a6a5c8523ffeb91cf9b0c63abb3a9770bdb04ad5` |
| `docs/adr/0010-reassign-gate-9-executable-slices-to-phase-1.md` | `30a8b27ea8bcd894c7fb87bc3f4cb3ffbfe88335116dc4ce0759141425e89424` |

The ADR 0009 blob is excluded from the executable denominator by ADR 0010's supersession. Every path resolves to an in-repository regular Git blob at EXECUTION_BASE with the accepted mode, never a symlink, gitlink, binary, or NUL-containing blob. Changing any source blob creates an explicit `supersedes` edge.

### Source manifest methodology

Source documents are tokenized using the accepted CommonMark block/link grammar defined in the validator contract. The parser handles inline and reference-style links, angle destinations, escapes, encoded destinations, and balanced parentheses. Local-link-like constructs outside the accepted grammar fail closed. Candidates are resolved relative to `docs/README.md` and repository traversal is rejected.

Blocks are ordered by byte-order path and one-based document order. Every block is normalized to LF line endings with all other bytes preserved. The source-unit identity is deterministic:

`SOURCE_UNIT_ID = SRC-<SHA256(path NUL blob_sha256 NUL block_kind NUL six_digit_order NUL normalized_block_bytes)>`

Full 64-hex digests never shorten or renumber. A changed blob creates an explicit `supersedes` edge.

### Semantic census

Every source unit is classified as one of:

- `normative`: A gateway requirement or invariant that Phase 1 implementation must satisfy
- `non_goal`: An explicit exclusion or deferral with accepted source rationale
- `evidence_only`: A validation, audit, or historical record that does not impose requirements
- `explanatory`: Background, context, or non-normative exposition

Every normative source unit contributes zero or more normalized requirements in document order. Each requirement receives:

`REQUIREMENT_ID = REQ-<SHA256(source_unit_id NUL six_digit_within_unit_ordinal NUL normalized_requirement_bytes)>`

Split, merged, or changed requirements create explicit `supersedes`/`derived_from` lineage and never silently reuse an ID.

Source-unit columns: `source_unit_id`, `path`, `blob_sha256`, `block_kind`, `document_order`, `classification`, `performance_resource`, `command_bearing`, `supersedes`.

Requirement columns: `requirement_id`, `source_unit_id`, `within_unit_ordinal`, `normalized_text`, `phase1_scope`, `evidence_class`, `supersedes`, `derived_from`.

Relation columns: `requirement_id`, `packet_id`, `future_test_owner`, `evidence_owner`.

The full census enumeration is deferred to the semantic audit in Task 12. The structural validator at Task 10 verifies schema, citation, ID set equality, and closed row relations but does not supply or approve semantic classifications.

---

## Two-way traceability schema

### Authority-to-packet

Every Accepted Phase 1 requirement maps to exactly one packet and one evidence owner. Every packet maps its authority IDs to source requirements. The relation table establishes the complete two-way projection.

### Packet-to-authority

Each packet declares `authority_ids` referencing the requirements it fulfills. The master backlog verifies set equality across both projections at Task 8.

### Coverage rule

A requirement not mapped to any packet is a gap. A packet not mapped to any requirement is an orphan. Neither is permitted at Phase 1 exit.

---

## Critical path and permitted parallelism

**Cross-slice critical path:** entry reconciliation → A07 acceptance → B12 acceptance → C06 acceptance → D07 acceptance → E06 acceptance.

**Within-slice scheduling:** only packets whose declared dependencies are complete and whose changes do not compete for the same invariant or acceptance fixture may proceed concurrently. B09 has an approved generic agent boundary, but external adapter delivery/composition and production acceptance evidence remain required. Packet completion never implies slice acceptance; only the slice acceptance barrier does.

**Slice B first value:** B01–B12 must complete and pass B12 acceptance before claiming Phase 1 first value. Slices C, D, and E are not prerequisites to first value.

---

## Entry reconciliation

Entry reconciliation is Complete. Slice A was accepted on 2026-07-18 after the root-run reference-host suite recorded 8/8 passing scenarios; B01 is now actionable. This gate changed documentary readiness only and did not add a sixth slice or change A–E.

## Milestones

- **Slice A accepted:** host authority foundation and adversarial acceptance; no product-value claim.
- **Local MVP Preview — B12:** browser-to-verified-required-Artifact repository analysis, restart recovery, durable cancel/retry, and the documented manual backup bridge.
- **Recovery-ready — C06:** managed backup/restore, interruption handling, quarantine, capacity admission, and post-restore authority reset.
- **Operationally complete — D07:** wipe isolation, export/import, retention, rescue, and crash-resume acceptance.
- **P1 Complete — E06:** dependency maintenance, compatibility/fallback, advisory conformance, and the complete Phase 1 suite.

---

## Documentary coherence walkthrough

| Scenario | Operator-facing visibility | Internal audit evidence |
| --- | --- | --- |
| Clean-host first run | B02 → B03 → B06 (browser bootstrap) | B04, B05 (protected state, migration) |
| Unsupported host | B01 advisory fails with explicit reason | B01 release-security evaluation |
| First Task success | B06 → B07 → B08 → B09 → B10 → B11 (UI progress) | B12 (end-to-end evidence) |
| Restart recovery | B11 (reconciliation status) → B12 (authoritative UI) | B12 (restart-safe acceptance) |
| Failed Artifact | B10 (upload failure in UI) → B11 (error state) | B10 (checksum/metadata evidence) |
| Interrupted backup | C01 (backup status) → C02 (capacity guard failure) | C06 (recovery evidence) |
| Interrupted restore | C03 (ticket status) → C04 (quarantine) → C05 (reset) | C06 (post-restore evidence) |
| Destructive cancellation | D01/D04/D05 (confirmation, progress, denial) | D07 (destructive acceptance) |
| Fresh-host import | D02 → D03 (descriptor, import progress) | D07 (portable evidence) |
| Rejected upgrade | E01 (compatibility rejection) → E04 (advisory status) | E06 (maintenance evidence) |

---

## Concern-to-packet ownership

This is the canonical ownership matrix that the implementation-sequence, capability, scenario, and documentary-walkthrough tables must agree with:

| Concern | Owner |
| --- | --- |
| helper and locked host identities | A03 |
| protected broker, protected backend, TLS authority | A04 |
| strict configuration and signed projections | A05 |
| dependency preparation and image/source identity | B02 |
| Compose service lifecycle and health | B03 |
| credential generation/custody and descriptor handoff | B04 |
| version-zero migration | B05 |
| Task lifecycle | B07 |
| Run/StepAttempt/ToolCallAttempt/Event/checkpoint evidence | B08 |
| generic agent dispatch and read-only Tool loop | B09 |
| Artifact lifecycle and completion guard | B10 |
| seven UI projections and restart banner | B11 |
| Preview acceptance and manual backup bridge | B12 |
| managed backup/restore and recovery | C01–C06 |
| delete/prune/retention/export/import/wipe | D01–D07 |
| dependency maintenance and full Phase 1 exit | E01–E06 |

### Deferred command behavior

A02 owns the complete A–E command census, closed grammar, deferred dispatcher, and exit-5 matrix. Every deferred command points to its owning slice and returns `exit 5` with `UNSUPPORTED_IN_THIS_SLICE`, performing no mutation before the owning slice is accepted. Activation of a previously deferred command requires the owning slice's acceptance barrier and a fresh source-census increment; deferred commands never execute partially.

---

## Implementation sequence mapping

The 12 current sequence items from Gate 8 map to packet ownership:

| Seq | Label | Owning packet |
| --- | --- | --- |
| 1 | Go service/config/health/shutdown | A01, A02, A03, A04, A05 |
| 2 | PostgreSQL and MinIO Compose | B02, B03 |
| 3 | Migration inspection and runner | B05 |
| 4 | Protected bootstrap exchange | B04, B06 |
| 5 | Task identity, lifecycle, persistence | B07 |
| 6 | Run and step attempts with events | B08 |
| 7 | Object-storage artifact management | B10 |
| 8 | Execute single agent task | B09 |
| 9 | Retry and process-restart recovery | B12 |
| 10 | Minimal web UI for task operations | B11 |
| 11 | Local MVP hardening with backup/restore | C01, C02, C03, C04, C05, C06 |
| 12 | Compatibility, recovery, security, performance suite | D07, E06 |

## Capability mapping

The ten P1-C01–P1-C10 capabilities from the accepted `docs/implementation/spec-and-plan-guide.md` map to packets:

| Capability ID | Label | Owning packets |
| --- | --- | --- |
| P1-C01 | Application bootstrap and configuration | A01, A02, A03, A04, A05, B01, B02, B03, B04, B06, C05, E01, E02, E03, E04, E05 |
| P1-C02 | PostgreSQL migration and persistence baseline | B02, B03, B05, C04 |
| P1-C03 | Workspace, task, and run domain | B07 |
| P1-C04 | Single-agent execution loop | B08, B09 |
| P1-C05 | Tool execution and safety boundaries | A06, A07, B09 |
| P1-C06 | Artifact storage and metadata | B10 |
| P1-C07 | Task web UI and progress visibility | B06, B11 |
| P1-C08 | Cancellation, retry, and restart recovery | B12, C06 |
| P1-C09 | Logging, metrics, and diagnostics | A01, B08 |
| P1-C10 | End-to-end workflow and release packaging | B12, C01, C02, C03, C04, C05, C06, D01, D02, D03, D04, D05, D06, D07, E06 |

## Gate 8 scenario mapping

Every Gate 8 scenario maps to packet, deferred matrix, future suite, and evidence owner:

| Scenario | Description | Owning packet | Future suite | Evidence owner |
| --- | --- | --- | --- | --- |
| 1 | Fresh host first run | B02 | `slice-b-test-suite` | Slice B dossier |
| 2 | Protected bootstrap with anti-framing | B04, B06 | `slice-b-test-suite` | Slice B dossier |
| 3 | Task create and inspect | B07 | `slice-b-test-suite` | Slice B dossier |
| 4 | Single agent execution | B09 | `slice-b-test-suite` | Slice B dossier |
| 5 | Artifact upload and verification | B10 | `slice-b-test-suite` | Slice B dossier |
| 6 | Server-rendered UI with seven states | B11 | `slice-b-test-suite` | Slice B dossier |
| 7 | Restart recovery | B12 | `slice-b-test-suite` | Slice B dossier |
| 8 | Backup creation | C01 | `slice-c-test-suite` | Slice C dossier |
| 9 | Restore with quarantine | C03, C04 | `slice-c-test-suite` | Slice C dossier |
| 10 | Post-restore authority reset | C05 | `slice-c-test-suite` | Slice C dossier |
| 11 | Destructive wipe with PAM | D01 | `slice-d-test-suite` | Slice D dossier |
| 12 | Portable export and import | D02, D03 | `slice-d-test-suite` | Slice D dossier |
| 13 | Advisory lifecycle and rescue | B01, E04, D06 | `slice-d-test-suite` | Slice D dossier |
| 14 | Compatibility planning and patch | E01, E02 | `slice-e-test-suite` | Slice E dossier |
| 15 | Rollback with out-of-place fallback | E03 | `slice-e-test-suite` | Slice E dossier |
| 16 | Delete and prune | D04 | `slice-d-test-suite` | Slice D dossier |
| 17 | State integrity audit | D05 | `slice-d-test-suite` | Slice D dossier |
| 18 | Full Phase 1 acceptance | E06 | `slice-e-test-suite` | Slice E dossier |

## Performance and resource projection

Every performance/resource-bearing accepted source requirement is projected to its owning packet and evidence:

| Requirement | Metric | Accepted bound | Minimum-profile fixture | Owning packet | Future suite | Evidence artifact | Evidence owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Go build time | Wall clock | < 60s on 4-core | Single `go build ./...` | A01 | `slice-a-test-suite` | `slice-a-build-time.json` | Slice A dossier |
| Service startup | Wall clock | < 30s all healthy | Compose up cycle | B02 | `slice-b-test-suite` | `slice-b-compose-startup.json` | Slice B dossier |
| Task list query | Response time | < 10ms for 100 tasks | Indexed query with LIMIT 100 | B07 | `slice-b-test-suite` | `slice-b-task-query.json` | Slice B dossier |
| Agent execution | Wall clock | < 300s per run | Single prompt with 2 tool calls | B09 | `slice-b-test-suite` | `slice-b-agent-runtime.json` | Slice B dossier |
| Artifact upload | Throughput | > 10 MB/s local | 100 MB multipart upload | B10 | `slice-b-test-suite` | `slice-b-artifact-throughput.json` | Slice B dossier |
| UI page render | Response time | < 500ms initial, < 200ms subsequent | Seven pages rendered | B11 | `slice-b-test-suite` | `slice-b-ui-render.json` | Slice B dossier |
| UI polling | Interval | 2s–30s with backoff | Poll 100 iterations | B11 | `slice-b-test-suite` | `slice-b-ui-polling.json` | Slice B dossier |
| Sandbox CPU | Limit | 0.5 cores enforced | `stress-ng` 1 worker | A06 | `slice-a-test-suite` | `slice-a-sandbox-cpu.json` | Slice A dossier |
| Sandbox memory | Limit | 256 MiB enforced | 300 MB allocation attempt | A06 | `slice-a-test-suite` | `slice-a-sandbox-memory.json` | Slice A dossier |
| Sandbox deadline | Limit | 300s enforced | `sleep 301` | A06 | `slice-a-test-suite` | `slice-a-sandbox-deadline.json` | Slice A dossier |
| Sandbox processes | Limit | 32 max | Fork bomb containment | A06 | `slice-a-test-suite` | `slice-a-sandbox-processes.json` | Slice A dossier |
| Sandbox file descriptors | Limit | 64 max | `ulimit -n` check | A06 | `slice-a-test-suite` | `slice-a-sandbox-fds.json` | Slice A dossier |
| Backup creation time | Wall clock | < 3600s | 1 GB database dump | C01 | `slice-c-test-suite` | `slice-c-backup-time.json` | Slice C dossier |
| Backup disk reserve | Capacity | 70% free floor | 80% full device | C02 | `slice-c-test-suite` | `slice-c-capacity-reject.json` | Slice C dossier |
| Restore apply time | Wall clock | < 3600s | 1 GB database restore | C04 | `slice-c-test-suite` | `slice-c-restore-time.json` | Slice C dossier |
| Database connections | Pool | Min 2, max 10 | Connection pool test | B07 | `slice-b-test-suite` | `slice-b-db-connections.json` | Slice B dossier |
| Query timeout | Deadline | 5s per operation | Query timeout test | B07 | `slice-b-test-suite` | `slice-b-query-timeout.json` | Slice B dossier |
| Event page size | Bound | Max 50 per page | Event feed pagination | B11 | `slice-b-test-suite` | `slice-b-event-page.json` | Slice B dossier |
| List page size | Bound | Max 25 per page | Task list pagination | B11 | `slice-b-test-suite` | `slice-b-list-page.json` | Slice B dossier |

## Strategy-to-packet traceability

Every requirement family in the Approved Phase 1 Local Central MVP Strategy maps to owning packets and an acceptance barrier. The Approved strategy has no unmapped section:

| Strategy requirement family | Owning packet(s) | Acceptance barrier |
| --- | --- | --- |
| Entry reconciliation and conditional readiness | Documentary gate; no packet | Independent entry-gate review |
| Bootstrap prerequisites, init, protected authority, TLS, managed browser | A01–A07, B01–B06 | A07 then B12 |
| Workspace creation and HTTP-boundary input validation | B06, B07, B11 | B12 |
| Local MVP Preview milestone and representative repository analysis | B07–B12 | B12 |
| Single execution lane, budgets, sandbox, ordered read-only filesystem access | A06, A07, B08, B09 | B12 and E06 minimum-profile suite |
| PostgreSQL durability, indexes, transactions, migration zero | B05, B07, B08, B10 | B12 |
| Generic agent boundary, SecretReference handoff, and one external adapter | B04, B09 | B09 packet evidence and B12; adapter delivery/composition and production acceptance evidence remain required |
| Required report and produced execution-log Artifact | B08, B10, B12 | B12 |
| Retry, cancellation, ambiguous effects, restart reconciliation | B07, B08, B10, B12 | B12 |
| Seven UI projections, polling, accessibility, browser compatibility, sanitized Markdown | B06, B11, B12 | B12 |
| Structured logs, health/readiness, configuration, deployment identity | A01, A05, B02, B03, B06, B08 | A07 and B12 |
| Manual Preview backup bridge | B12 | B12 documentary/acceptance evidence |
| Managed backup/restore, quarantine, capacity, post-restore reset | C01–C06 | C06 |
| Destructive, portable, retention, rescue operations | D01–D07 | D07 |
| Compatibility, dependency maintenance, advisory conformance, complete suite | E01–E06 | E06 |
| Deferred application-layer encryption at rest gap | B12 documentation evidence; no runtime encryption packet | B12 verifies prerequisite warning and non-overclaim; later remote/multi-user ADR owns implementation |

## Definition of Ready

A packet is Ready when:
1. Its dossier defines all eight mandatory sections with non-empty content
2. Zero unresolved placeholders or open decisions exist
3. All dependencies are listed and satisfied
4. Its Definition of Done is testable with concrete verification steps
5. Future test suite, test owner, evidence artifact, and evidence owner are identified

## Definition of Done

A packet is Done when:
1. All verification steps in its Definition of Done pass with recorded evidence
2. Durable data is correctly persisted
3. Negative security tests pass
4. Crash/recovery behavior is verified
5. The evidence artifact is durably recorded and verifiable

A slice is Done when all its packets are Done and its slice acceptance criteria pass.

Phase 1 is Done when all five slices are Done and the full Phase 1 acceptance suite (E06) passes.
