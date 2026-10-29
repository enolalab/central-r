# Current Phase

## Active slice: lifecycle composition — post-R6 slice on `lifecycle-composition`

`central-rust` is delivered as the `R0`–`R6` vertical-slice sequence defined in [rust-vertical-slice-roadmap.md](rust-vertical-slice-roadmap.md) under Accepted [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md). **All seven slices are complete** (see below) — R6 closed out the backup/restore/wipe/maintenance operator surface: the migrate CLI and launcher daemons, the Slice C recovery plane, Slice D destructive portable operations, and the Slice E dependency-maintenance and release-advisory lifecycle.

The `lifecycle-composition` slice closes R6's largest recorded deferral — the `bind_postgres_service_role` writer half and the broker-backed `local up|down|status` lifecycle in the helper daemon — per the [lifecycle-composition plan](../internal/superpowers/plans/2026-10-28-lifecycle-composition.md): the broker writer arm, the production service-role credential store with rotate-then-sync, the compose/bootstrap decorations and broker rendezvous, and the full B03 chain wired into `Server::lifecycle` (rescue cleanup delegating `down` as upstream's second ceremony, one shared confirmer across handler slots).

The `prepare-promotion` slice closes the `PREPARE_PROMOTION_UNAVAILABLE` boundary, per the [prepare-promotion plan](../internal/superpowers/plans/2026-10-28-prepare-promotion.md): the durable `FileJournal`, the journal-driven `PrepareState` machine (capacity → acquire → verify → two independent builds → compare → attest → load → stage → fresh promotion admission → switch, with exact resume and `CandidateStore::recover`), the ed25519/DSSE attestation signer, verifier and key loader, the docker image loader, release verify/import/re-verify and the self-checking release export, and the real advisory-currency admission verifier. A host without an attestation key stays import-only (`PREPARE_UNAVAILABLE` for fresh prepares). Key generation (upstream operator tool) is not ported; the host-level BuildKit/docker end-to-end run remains a Tier-3 evidence item.

Verification for changes continues to follow the fail-fast pipeline in [rust-engineering-workflow.md](rust-engineering-workflow.md) §7 (`cargo sqlx prepare --check` → `cargo fmt --check` → `cargo clippy -D warnings` → `cargo deny check` → `cargo test --workspace`).

## Completed: Phase R6 — Backup, Restore, Wipe & Maintenance

Phase R6 delivered, per roadmap §9 and the [R6 plan](../internal/superpowers/plans/2026-10-23-phase-r6-backup-restore-wipe-maintenance.md):

- `bins/central-migrate` + `bins/central-migration-launcherd`: the CLI migration-ops surface — `migrate verify|up|status|resume` over the helper transport plus the exact version-zero `migrate reset` semantics — and the launcher daemon driving them.
- `central-backup` capability + `bins/central-backup`/`bins/central-restore`/`bins/central-backup-launcherd`: exclusive target capture, the `pg_dump`/`pg_restore` fd-3 tool adapters, chunked canonical-key inventory, the verified manifest seal, one-use restore tickets, the restore capacity reserve gate (ADR 0018), quarantine resolution, authority reset on restore, incremental runtime-grant reapplication after `pg_restore`, and the rescue-backup lifecycle.
- Broker R6 stores and RPCs: the `b25`–`b29` recovery evidence stores (`central-adapter-postgres`), the recovery and throughput journals + launch store, `0xc1`/`0xc2` credential transports, the authority RPC dispatch with Go digest wire parity, restore-capacity admission, `RestoreTicketIssuer`/`BrokerAuthorityReset`, and the `advisory_evaluation` append RPC behind the peer gate.
- `central-adapter-linux`: the `pg_dump`/`pg_restore` process boundary, the restore engine, the production backup/restore MinIO credential provisioner, and the C02 throughput gate.
- Slice C recovery acceptance (`tests/c06_acceptance/`): the ceremony driver plus the slice-C acceptance core — corruption injection and detection, the verify-resolver battery, the ticket one-use lifecycle, and the continuous run.
- Slice D destructive portable operations: the `central-infra::destructive` vocabulary, helper wipe/delete/prune handlers behind the grant ceremony, and the `local wipe`/`backup delete`/`backup prune` CLI verbs with evidence.
- Portable backup exchange: the `central-infra::portable` `bx1` vocabulary and chunked AES-256-GCM token crypto, the Go-byte-parity tar/gzip codec (committed goldens), and `backup export`/`backup import` with the production import-MinIO preparer.
- Slice D acceptance (`tests/d07_acceptance/`): the fixture-tier grant-ceremony suite — wipe/reseed, signed denial, export→import staging, fail-closed delete/prune, tamper-detecting audit repair, and the rescue cycle; the production tier stays an explicit opt-in honest skip.
- Audit/rescue/security-update: the deny-safe rescue vocabulary plus the `local audit`, `local security update`, and `local security rescue` helper handlers, clients, and dispatch.
- Slice E dependency maintenance: the `central-infra::maintenance` compatibility-matrix domain (HMAC-chained transition journal, sealed matrix file), the helper plan/apply handlers, and `central maintenance plan|apply` with their evidence artifacts.
- Release-advisory lifecycle: `bins/central-advisory-sign` (`genkey`/`bundle`/`verify`), the shared B01 evaluator wired into every destructive helper path, and the `tests/e04_advisory` conformance suite over a real broker Journal.
- Slice E verification and acceptance: `tests/e05_runbook` (runbook grammar/token parity) and `tests/e06_acceptance` (the E-slice authority cycle end-to-end on the real store, apply handler, and Journal; physical-tier criteria recorded `deferred-physical`).
- Committed `.sqlx/` offline query metadata for the `b25`–`b29` stores and every new checked statement; the §7 fail-fast pipeline is green — the `CENTRAL_TEST_DSN`/`CENTRAL_TEST_HELPER_SOCKET`-gated e2e suites and the root/Tier-3 platform legs skip cleanly as designed.

Documented boundaries deferred past the `R0`–`R6` sequence: `security-rescue-cleanup` (also unimplemented upstream) and the physical/Tier-3 evidence tiers requiring a root-capable reference host. The `bind_postgres_service_role` writer half and broker-backed lifecycle composition landed on `lifecycle-composition` — the R6 deferral record at `docs/internal/tasks/r6-t16-postgres-service-role-bind-deferral.md` is now resolved — the `local browser open` client verb plus the sibling `central bootstrap show` landed on `local-browser-open` (B06 helper-client half; the helper-side `browser-open`/`bootstrap-show` verbs were already composed), and prepare promotion/attestation landed on `prepare-promotion` (see below).

## Completed: Phase R5 — Host Authority, Broker & Compose Topology

Phase R5 delivered, per roadmap §8 and the [R5 plan](../internal/superpowers/plans/2026-10-23-phase-r5-host-authority-broker-compose.md):

- `bins/central`: the upstream command census — every verb/mode registered with Go-compatible flag parsing and the protected-mode skeleton; `central protected-*` entries refuse `UNSUPPORTED_IN_THIS_SLICE` fail-closed outside their composed paths.
- `central-foundation`: RFC 8785 JCS canonicalization (sorted UTF-16 keys, ECMAScript numbers, minimal escaping) verified against upstream fixtures; `central-infra::config`: strict `central.config/v1` parsing.
- `central-infra`: the host-authority domain — authority state, ports, wire contracts (`central.*` envelope digests byte-exact via `RawValue` payloads), and the app skeleton shared by broker/helper/lifecycle.
- `central-adapter-linux` audited OS boundary (`sys::`): sealed `memfd`, `SCM_RIGHTS` descriptor transport with peer-credential checks, `openat2` confinement (`BENEATH|NO_SYMLINKS|NO_MAGICLINKS|NO_XDEV`), `pidfd`, cgroup/namespace primitives, the upstream 64-syscall seccomp allowlist with `SECCOMP_RET_KILL_PROCESS` default, and the hardening sequence — all `unsafe` confined to `sys/audited.rs` with `// SAFETY:` proofs.
- PAM + TTY physical-console boundary: hand-written `libpam` FFI (`pam_start` → `pam_authenticate` → `pam_end`), echo-off-only conversation, physical-console TTY checks (`/dev/tty*` predicate, `TIOCEXCL`, `TCIFLUSH`, echo suppression, fixed confirmation phrase, zeroized buffers).
- The protected broker: `0xB1`/`0xC1` protocol frames, `SO_PEERCRED` admission gates, the append-only authority journal with HMAC fingerprinting over exact raw bytes, `protected_file_v1`, provisioning, payload epochs, durable state, and Ed25519 signing.
- Broker custody: the TLS authority (rcgen CA + leaf issuance/persistence), sealed-memfd secret bootstrap over `SCM_RIGHTS`, bootstrap sessions, handoff, and export-token signing/verification.
- The root helper: closed denial matrix (out-of-slice ops refuse with exact upstream codes), init/prepare/up/down/status/doctor/grant ceremonies, flock'd grant store with TTL + consume-once, and PAM/TTY confirmation.
- The sandbox launcher and protected-mode entrypoints on the hardened syscall surface; `bins/central-harness-launcherd` moved onto shared `sys::` primitives (only clone3/mount/landlock remain daemon-local).
- The release-advisory consumer: Ed25519-over-JCS verification, admission gating, and audit records.
- `central local prepare`: the verified dependency lock (JCS + digest pinning), archive fetch/staging with symlink/traversal refusal, OCI/BuildKit identity checks, and bounded subprocesses — originally stopping at `PREPARE_PROMOTION_UNAVAILABLE`; promotion landed post-R6 on `prepare-promotion`.
- `central local up|down|status`: the six-service Compose lifecycle — digest-pinned rendering, phase machine, durable lock/journal/barrier, capacity admission, receipt inspection, and the B04 durable credential handoff to `/run/central-infra/<instance>/secrets`.
- `central local init`: instance genesis — absent/present/broken classification, capacity checks, descriptor-relative installation ordering, owner/mode enforcement, locked identities, version-zero receipt, atomic `RENAME_NOREPLACE` config commit, idempotent `ALREADY_INITIALIZED`, and `grant issue --kind init` issuance.
- `central serve` hardening (B06): bind fixed `127.0.0.1:8080`, TLS 1.3-only with the instance certificate from the broker/file authority, `validate_tls` reproducing every upstream check (including the unhandled-critical-extension gate), lazy `tls.NewListener`-parity handshake, broker `ProtectedBootstrap` session bootstrap (`CENTRAL_LOCALEXEC=1` dev gate), and `WorkspaceSealer` port injection keeping `central-adapter-harness` free of `central-adapter-linux`.
- `tests/a07_*`: the host-authority denial suite — same-UID peer denial, descriptor smuggling, TTY spoofing, `openat2` path races, broker crash mid-transition, and the full denial ladder; portable tier green locally, Tier 3 legs gated (`CENTRAL_TIER3=1` + root + pinned reference host).
- Committed `.sqlx/` offline query metadata for every new checked statement; the §7 fail-fast pipeline is green (`phase2_recovery_matrix` remains `CENTRAL_TEST_DSN`-gated by design).

Documented slice boundaries deferred to R6: broker-backed restore-barrier RPC for `central serve` production preflight (fail-closed `RESTORE_BARRIER_UNAVAILABLE` until composed), `local browser open` client verb, promotion/attestation for `local prepare`, and backup/restore/wipe/maintenance operations. (Broker-backed lifecycle composition in the helper daemon — listed here at R5 close — landed on `lifecycle-composition`.)

## Completed: Phase R4 — Multi-Agent Workflow Orchestration

Phase R4 delivered, per roadmap §7 and the [R4 plan](../internal/superpowers/plans/2026-10-23-phase-r4-multi-agent-workflow-orchestration.md):

- `central-retry`: the Phase 2 retry taxonomy — retry classes, `retry_after`/`not_before` scheduling, budget accounting (`attempt_counts`), terminal-failure reason codes, and `on_terminal_failure` compensation hooks (managed vs unmanaged).
- `central-workflow`: the `b33` workflow graph domain — emit/recompute readiness, cancel cascade, ambiguity parking, resume/rerun decisions, and `SPEC_VALIDATION_FAILED` cycle/depth refusals naming offending keys.
- `central-eventjournal`: the `b33` event journal — ordered append, per-run sequence integrity (`EVENT_SEQUENCE_GAP`), redelivery dedupe, undeclared-kind tolerance (`UNKNOWN_EVENT_KIND`), and the outbox publisher (`OUTBOX_PUBLISH_STALLED` health).
- `central-adapter-postgres`: the `b33`/`b35`/`b37` stores — workflow/journal/scheduler/outcome rows, worker registrations, lease fencing (`LEASE_FENCE_STALE`/`LEASE_RENEWAL_STALE`), admission deferral, `sweep_timeouts` (session wall-clock + node/run deadlines with ambiguity skips), and `runview` read-only projections.
- `central-scheduler`: admission, claim loops, dispatch, heartbeat ladder (suspect→lost), starvation bounds, and the `Provisioner` port for dispatch workspaces.
- `central-runsubmit`: the run-submission service shared by `central run submit` and the `/app/runs` PRG form — keyed idempotent resubmission, run-fingerprint adoption, workspace-scoped authorization, and Phase 1 dispatch invisibility.
- `central-runview`: `/app/runs` list/DAG/node detail, run controls (cancel/decide/resume/checkpoint ops) calling `central-retry`/`central-workflow` services only, fleet census, and lineage views — keyset `SeekCursor` polling, state-matrix semantics, PRG + CSRF.
- `central-checkpoint` (Phase 2C): subtree-anchored checkpoint write/resolve/preflight, `RESUME_TOKEN_STALE`/`CHECKPOINT_INCOMPATIBLE`/`BOUNDARY_ILLEGAL` refusals, `resume_subtree` execution with seq-2 reclaim and `RESUME_REQUIRES_OPERATOR_DECISION` parking.
- `central-kernel`: Phase 2 composition — scheduler worker/claim-loop/sweeper components, retry sweeper, checkpoint janitor, outbox publisher, and the scheduler→harness launcher/killer/brief wiring (gated on `CENTRAL_PHASE2_SCHEDULER`); `bins/central` lifts `run submit`, `node decide`, `checkpoint *`, and `artifact read` to env-composed backends.
- `bins/central/tests/phase2_acceptance`: the 23-record recovery test matrix (`phase-2-recovery-matrix/v1` evidence under `docs/internal/evidence/`) — 20 machine scenarios across graph, leasing, policy, and checkpoint/journal legs plus 3 deferred-physical runbook rows.
- Committed `.sqlx/` offline query metadata for every new checked statement; the §7 fail-fast pipeline and the `CENTRAL_TEST_DSN`-gated integration suites are green.

## Completed: Phase R3 — Harness Control Plane & `central serve`

Phase R3 delivered, per roadmap §6 and ADRs [0035](../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md)/[0036](../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md):

- `central-harness`: the harness control-plane domain — adapter identity/capabilities vocabulary, the session boundary, capture, permission bridging, budget metering, and the cancel/resume/rerun + ambiguity-resolution state machines.
- `central-adapter-harness`: the Claude Code, OpenCode, Codex, and Antigravity adapters (protocol codecs, argv grammars, probe pins), `gitclone` provision/capture, the CHL1 launcher client, and the `CENTRAL_LOCALEXEC` dev executor.
- `central-session`: bootstrap-generation exchange, session cookies, and CSRF token issuance/verification.
- `central-transport-http`: the API v1 JSON controllers and the `askama` SSR Web UI (bootstrap exchange, task list/detail, harness resolve and permission PRG flows, artifact preview/download), plus health/metrics with loopback-peer admission.
- `central-adapter-postgres`: the fenced execution/recovery stores — recovery epochs with bounded claim batches and degraded-epoch quarantine, step-attempt reconciliation, command receipts, and the outbox.
- `central-kernel`: the `central serve` composition — supervised listeners, the R2 artifact reconciler behind the recovery-coordinator fence, bootstrap reconciliation, bounded startup recovery, and graceful drain.
- `bins/central`: the `serve` verb plus harness/session/node CLI surfaces; `bins/central-harness-launcherd` ports the ADR 0036 socket-activated launcher.
- `scripts/r3-acceptance.sh` + `tests/acceptance/`: the Tier 4 Playwright SSR acceptance suite and its bounded end-to-end runner (provision → migrate → serve → seed → Playwright → teardown).
- Committed `.sqlx/` offline query metadata for every new checked statement; the §7 fail-fast pipeline and the `CENTRAL_TEST_DSN`/`CENTRAL_TEST_MINIO_ENDPOINT`-gated integration suites are green.

## Completed: Phase R2 — Verified Artifact Lifecycle & Object Storage

Phase R2 delivered, per roadmap §5 and the [R2 plan](../internal/superpowers/plans/2026-10-22-phase-r2-verified-artifact-lifecycle.md):

- `central-foundation`: UUIDv4 generation/edge identities (`content_generation`, lineage edge IDs) alongside the R1 UUIDv7 newtypes.
- `central-artifact`: the pure lifecycle domain (reserve → staging → verifying → promotion → finalize, plus `reserved`/`rejected`/`delete_pending`/`deleted` with tombstones), the bounded content classifier, the orchestrating `Service` (materialize, resume-verifying, deliver, two-phase delete), the fenced bounded `Reconciler` (large-claim pass, rejected-staging sweep, staging-lifetime expiry), and the `b34` lineage model plus produce/read-edge port/query contracts.
- `central-adapter-s3`: the S3/MinIO `ObjectStore` (staging upload, bounded reads, atomic create-only promotion, staging/ready removal) with the bounded `TransferLimiter` and per-transfer idle/total deadlines.
- `central-adapter-postgres::artifact`: the artifact `Store`, two-phase delete + `CompletionContributor`, `ReconciliationStore`, and `b34` lineage stores — including the SB-G4 `central_runtime` UPDATE-demotion fix on `artifact_reconciliation_claims` recorded in `docs/internal/tasks/`.
- `central-kernel`: `artifact_reconcile::ArtifactReconcilerComponent` — the supervised periodic fenced pass (claim → renew → reconcile on a bounded `tokio::time::Interval`, idle-until-shutdown without an epoch) with `ArtifactPass`/`ArtifactFenceSource` composition seams.
- Committed `.sqlx/` offline query metadata for every new checked statement; the §7 fail-fast pipeline and the `CENTRAL_TEST_DSN` PostgreSQL integration suites are green (the `CENTRAL_TEST_MINIO_ENDPOINT`-gated S3 test skips cleanly when no MinIO is provisioned).

## Completed: Phase R1 — Workspace Scaffold, Canonical SQL Extraction (`v0..b37`) & Durable Task/Execution Core

Phase R1 delivered, per roadmap §4 and the [R1 plan](../internal/superpowers/plans/2026-10-21-phase-r1-workspace-and-durable-core.md):

- Cargo Workspace scaffold — root `Cargo.toml` (`[workspace.dependencies]`, `[workspace.lints]`), `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml` — per [rust-application-boundaries.md](../architecture/rust-application-boundaries.md); `cargo deny check` clean.
- `central-foundation`: UUIDv7 identity newtypes, the Failure taxonomy and exit classes, and the `central.local-result/v1` result envelope.
- `migrations/`: the complete `v0..b37` ordered SQL corpus extracted statement-for-statement from the upstream Go-embedded DDL, plus the immutable SHA-256 checksum `manifest.json` ([postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md)).
- `central-adapter-postgres`: the native migration runner — `central.schema_migrations` checksum ledger, single-session `pg_advisory_lock`, version-zero `VerifiedEmptyTarget` atomic baseline installer, dirty data-backfill resume without generic `Force`, and `reapply_incremental_runtime_grants` after `pg_restore`; `_sqlx_migrations` absent — plus the durable stores for workspace, authorization, event, checkpoint, task, and execution.
- Core Phase 1 durable domains: `central-workspace`, `central-task`, `central-execution`, `central-event`, `central-checkpoint`, `central-authorization`.
- `central-kernel` composition root: manual dependency composition, supervised component lifecycle (`CancellationToken` + bounded settlement), profile-aware readiness, and the ready-proof lifecycle (publish, revoke, generation fencing).
- `bins/central` skeleton: `--version` and fail-closed `exit 5` (`UNSUPPORTED_IN_THIS_SLICE`) `central.local-result/v1` JSON for R2–R6 verbs; it depends only on `central-kernel` and `central-foundation`.
- Committed `.sqlx/` offline query metadata; the §7 fail-fast pipeline and the `CENTRAL_TEST_DSN` PostgreSQL integration suites are green (lease fencing, recovery epochs, retry, and the outbox covered).

## Completed: Phase R0 — Documentation & Contract Baseline

Phase R0 is **Complete upon R0 acceptance** per the [governing spec](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md) §7. It ported every language-agnostic contract (product, API/Event v1, artifact, runtime, persistence, security, operations, Phase 1/2 slice dossiers), the immutable ADR ledger `0001`–`0042`, and the authoritative Phase 0/1/2 design specs, and it authored the Rust-specific contracts this repository runs on: `AGENTS.md`, `CLAUDE.md`, [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md), [rust-application-boundaries.md](../architecture/rust-application-boundaries.md), [postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md), [rust-engineering-workflow.md](rust-engineering-workflow.md), this file, and the [R-slice roadmap](rust-vertical-slice-roadmap.md).

## Upstream reference baseline (Phase 0–2)

`central-rust` reimplements the upstream Go `central` repository at full parity. The upstream baseline the ported contracts encode:

- **Phase 0 (Complete):** design-only gates G1–G10 produced the product, security, runtime, artifact, API/Event, persistence, application-boundary, local-topology, and slice-decomposition contracts now canonically ported here; ADRs `0001`–`0042` are retained unchanged as the immutable decision ledger.
- **Phase 1 (Complete at recorded evidence tiers):** Slices A–E delivered host authority, the first safe runnable environment (B01–B12), required recovery, destructive portable operations, and dependency maintenance; the Harness Control Plane (ADR 0035/ADR 0036) delivered Claude Code, OpenCode, Codex, and Antigravity adapters, capture, permission bridging, budgets, and cancel/resume/rerun (upstream phases 1a–3m). Upstream gate evidence — including the SC/SD/SE verdicts and their recorded evidence tiers — is archived in the upstream repository and is authoritative there, not copied here.
- **Phase 2 (Exit-complete at machine tier):** multi-agent workflow orchestration — workflow graph and event journal (`b33`), scheduler/workers (`b35`), subtree checkpoints (`b36`), retry/idempotency (`b37`), run submission, DAG run views, and the recovery test matrix — is specified by the Phase 2 spec series and slice dossiers ported under `docs/implementation/phase-2-slices/`.

Two upstream decisions shape everything below: [ADR 0035](../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md) froze the B09 loop coordinator (never ported — `central-harness` + `central-execution` carry the sequential-coordinator role instead), and [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md) replaces Go module/package boundaries with the Rust Cargo Workspace contract for this repository while preserving every other upstream decision.

## Remaining sequence

| Slice | Scope | Status |
| --- | --- | --- |
| R1 | Workspace scaffold, `v0..b37` extraction, native migration runner, durable Task/Execution core | **Complete** |
| R2 | Verified artifact lifecycle, `central-adapter-s3` | **Complete** |
| R3 | Harness control plane, `central-session`, `central-transport-http`, `central-harness-launcherd` | **Complete** |
| R4 | Phase 2 orchestration (`workflow`, `eventjournal`, `scheduler`, `retry`, `runview`, `runsubmit`), recovery matrix | **Complete** |
| R5 | Host authority, protected broker, `central-adapter-linux`, Compose topology | **Complete** |
| R6 | Backup, restore, wipe, maintenance, launcher daemons | **Complete** |
