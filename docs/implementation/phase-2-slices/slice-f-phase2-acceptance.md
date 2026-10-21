# Slice 2F — Phase 2 Acceptance Suite

- **Slice ID:** 2F
- **Dossier:** `slice-f-phase2-acceptance.md`
- **Issue:** #97 — acceptance suite (injected-failure recovery matrix + verdict)
- **Packets:** P2F01–P2F05
- **Dependency:** P2E06 (Slice 2E complete)
- **Outcome:** The injected-failure recovery matrix executed against a live Central, an end-to-end multi-agent orchestration proof, and a machine-checkable Phase 2 verdict with a complete divergence report on failure

## Governing specs

- `docs/internal/superpowers/specs/2026-10-07-phase-2-spec-gate-design.md` — deliverable 9 defines this suite's contract: injected-failure catalog, per-scenario expectations, evidence schema
- Recovery test matrix spec (spec 9, per the spec-gate table) — owns the scenario catalog this suite executes; the matrix spec is drafted under #91 and consumed here, not redefined
- Every prior spec's `## Failure semantics` section — the reason-code vocabulary the matrix asserts: specs 1–8 each name codes the suite must be able to trigger and observe

## Slice 2F ownership

P2F01–P2F05 collectively own:

- the failure-injection harness — deterministic triggers for process kill, launcher/adapter error, provider/network fault, worker loss, checkpoint corruption, clock control, and PostgreSQL/MinIO faults;
- the recovery-matrix scenario execution against every spec's documented expectations (each scenario maps to the reason codes its owning spec declares);
- the end-to-end orchestration proof: leader session → validated child-spec batches → depth-3 tree → dynamic expansion → sibling `central artifact read` → final artifacts with `run_lineage` audit;
- the evidence schema and verdict artifact; on failure a complete divergence report, not a partial pass.

Slice 2F must not implement new runtime components — it composes and attacks what Slices 2A–2E built. It uses the production authority chain; no test-only bypass.

## Packets

- **P2F01** — Failure-injection harness: deterministic fault triggers and fixtures for every injectable failure class
- **P2F02** — Crash and leasing matrix: mid-dispatch/mid-attempt kills, lease expiry split, worker loss, startup reconciliation scenarios
- **P2F03** — Policy matrix: taxonomy/backoff/budget, timeout ladder, cancel cascade, checkpoint preflight failures, idempotent replay, outbox stall, admission deferral
- **P2F04** — End-to-end orchestration proof: multi-level run with expansion, sibling reads, ambiguous-resolution path, and full lineage audit
- **P2F05** — Evidence schema and verdict: scenario census, divergence report, `phase-2-slice-f-acceptance.json`

## P2F01

### Identity and outcome

Implement the failure-injection harness: deterministic, journaled triggers for each fault class the matrix enumerates — so every scenario is reproducible and attributable.

### Implementation boundary

Injection points: process kill at defined windows (post-claim pre-`attempt_started`, mid-invoke, post-outcome pre-commit); harness-adapter error and launcher refusal fixtures; provider `RATE_LIMITED`/`retry_after` responses; worker heartbeat stop (suspect→lost) and unclean worker death; workspace mutation to trip `WORKSPACE_DIGEST_MISMATCH`; checkpoint tampering/expiry; clock control for timeout and lease sweeps; MinIO and PostgreSQL fault windows. Injections are test-surface only (build tag / test harness), never reachable from production commands — the B12 injected-failure precedent applied to orchestration.

### Durable data and migration

None — the harness manipulates the environment, not schema. Every injection journals a test-marker event so runs are attributable.

### Security and authority

Injection code compiles only under the test build tag (precedent: `authority_test`); the production binary carries no injection path.

### Failure, retry, cancellation, and recovery

A failed injection (fault didn't land) invalidates the scenario — recorded as `inconclusive`, never counted as pass or fail.

### Verification and evidence

- Each fault class demonstrably triggers under test builds
- Injection markers journal so scenario evidence is attributable
- No injection surface exists in production builds
- Evidence artifact: `phase-2-slice-f-injection-harness.json`

### Scope control

P2F01 owns injection mechanics only — scenario expectations belong to P2F02/P2F03.

### Definition of Done

Every failure class in the matrix has a deterministic, journaled, test-only trigger.

## P2F02

### Identity and outcome

Execute the crash and leasing recovery matrix: process kills at each dispatch/attempt window, lease expiry split by attempt state, worker loss ladder, and startup reconcile-before-reinvoke.

### Implementation boundary

Scenarios and expected outcomes per specs 1–2: kill post-claim pre-start → `LEASE_EXPIRED_NOT_STARTED`-class closure, node returns `ready`; kill mid-attempt → `attempt_ambiguous` (`ATTEMPT_AMBIGUOUS_LEASE_EXPIRED`/`ATTEMPT_AMBIGUOUS_WORKER_LOST`), operator decision required, no auto-rerun; heartbeat stop → `worker_suspect` at 2 missed, `worker_lost` at 5, all leases expired atomically; Central restart with live leases → reconciler runs before any dispatch, orphan-worker leases treated lost; stale-lease durable write → `LEASE_FENCE_STALE`; clean shutdown → `WORKER_SHUTDOWN_LEASE_RELEASED` requeue. Each scenario asserts the journaled event + reason code + terminal/parked state.

### Durable data and migration

Asserts on durable state only — the matrix reads what the specs wrote.

### Security and authority

Runs under the production authority chain; the injected faults exercise real code paths, not mocks of the domain service.

### Failure, retry, cancellation, and recovery

This packet IS the crash/recovery assertion surface: every expected outcome is the spec's documented path; deviation = divergence entry.

### Verification and evidence

- Every kill window produces its spec'd closure or ambiguity — never a silent loss or double-dispatch
- Missed-beat ladder fires on schedule; worker loss expires all its leases in one transaction
- Reconciler completes before post-restart dispatch in every restart scenario
- Stale-lease writes are fenced in every attempted path
- Evidence artifact: `phase-2-slice-f-crash-matrix.json`

### Scope control

P2F02 owns crash/lease scenarios only — policy-level failures belong to P2F03.

### Definition of Done

The crash/leasing matrix passes: every injected loss resolves to its documented state with journaled evidence, and ambiguity always waits on the operator.

## P2F03

### Identity and outcome

Execute the policy matrix: taxonomy classification, backoff/budget exhaustion, the timeout ladder, cancel cascade, checkpoint preflight failures, idempotent replay, outbox stall, admission deferral, and lineage edge cases.

### Implementation boundary

Scenarios per specs 3–8: each retryable class retries within budget then `RETRY_BUDGET_EXHAUSTED` → `failed_terminal`; terminal classes skip retry entirely; session/node/workflow timeouts each fire their code (`SESSION_TIMEOUT`, `NODE_TIMEOUT`, `WORKFLOW_TIMEOUT`) with unconfirmed-kill ambiguity honored; cancel cascades to the full non-terminal subtree; checkpoint refuse (`CHECKPOINT_BOUNDARY_ILLEGAL`), stale token, incompatible version, digest mismatch, missing artifact each fail safely; command replay across every idempotency key produces no duplicate rows; `ARTIFACT_ALREADY_FINALIZED`/`ARTIFACT_CHECKSUM_MISMATCH` hold; `OUTBOX_PUBLISH_STALLED` surfaces while state stays correct; fifth session defers `CAPACITY_ADMISSION_DEFERRED` and re-evaluates on freeing; undeclared read journals `LINEAGE_READ_UNDECLARED`; out-of-scope read refuses `ARTIFACT_SCOPE_DENIED`; `child_spec_rejected` covers cycle/depth/budget violations.

### Durable data and migration

Asserts on durable state and journaled events; no new state.

### Security and authority

Every asserted reason code must be the spec's literal string — vocabulary drift is a gate failure, not a tolerance.

### Failure, retry, cancellation, and recovery

Each scenario's expectation IS the failure semantics; unexpected codes or states record as divergences with the observed-versus-declared pair.

### Verification and evidence

- Every reason code in specs 1–8's failure tables is exercised at least once
- Retry/timeout/cancel composition fires inner-first with correct terminal states
- Idempotent replays verified for every key-table row
- Deferral re-evaluation, lineage flags, and checkpoint failures all journal correctly
- Evidence artifact: `phase-2-slice-f-policy-matrix.json`

### Scope control

P2F03 owns policy-failure scenarios only — no new runtime code, no UI assertions (those are 2E's own evidence).

### Definition of Done

Every documented failure path in the Phase 2 specs is triggered, observed, and verified against its named reason code and terminal state.

## P2F04

### Identity and outcome

Execute the end-to-end orchestration proof: a leader harness session emits validated `central.child-spec/v1` batches, the graph expands dynamically to depth 3, siblings exchange data via `central artifact read`, an ambiguous attempt is resolved by operator decision, and `run_lineage` explains every final artifact.

### Implementation boundary

The proof runs a real multi-level run: leader node → child batch → at least one grandchild (depth 3 enforced — a depth-4 spec must reject `MAX_DEPTH_EXCEEDED`); a second emission batch proves dynamic expansion; a child reads a sibling's finalized artifact via the CLI (declared read edge journaled); one injected ambiguity resolved through the operator control; run completes with final artifacts whose `run_lineage` closure accounts for every byte of provenance. UI evidence (2E) is re-verified against this run's journal.

### Durable data and migration

The proof is itself durable evidence — its run, events, edges, and artifacts persist for audit.

### Security and authority

Runs under the production authority chain and real harness adapter — no stubbed leader; the leader's emitted specs pass the same validation as any emission.

### Failure, retry, cancellation, and recovery

Any unmet expectation (missing edge, unexplained artifact, auto-resolved ambiguity) is a divergence; the proof does not partially pass.

### Verification and evidence

- Depth-3 tree executes; depth-4 emission rejects with `MAX_DEPTH_EXCEEDED`
- Second emission batch appends without mutating existing nodes
- Sibling read journals a declared read edge with the finalized checksum
- Injected ambiguity parks until the operator chooses; both outcomes verified across runs
- `run_lineage` explains every final artifact; undeclared reads render flagged
- Evidence artifact: `phase-2-slice-f-e2e-orchestration.json`

### Scope control

P2F04 owns the orchestration proof only — faults beyond the one ambiguity belong to P2F02/P2F03 scenarios.

### Definition of Done

One recorded run demonstrates the complete Phase 2 loop end-to-end with auditable provenance for every final artifact.

## P2F05

### Identity and outcome

Implement the evidence schema and verdict: a machine-checkable manifest recording every scenario, its result, its log digests, the skip census, and the host profile — emitting `phase-2-slice-f-acceptance.json` with a complete divergence report on any failure.

### Implementation boundary

Evidence follows the Slice C governance shape (SC manifest precedent): per-scenario `id`, `result` (`pass`/`fail` — `skip` requires census entry with reason class), log digests, commands executed, image/toolchain census, `host_profile`, and `prerequisite_verdicts` naming S2A–S2E gate evidence. The verdict is binary; any divergence produces the complete observed-versus-declared report. The manifest itself is a finalized artifact of the acceptance run.

### Durable data and migration

The verdict artifact persists through the normal artifact path — metadata in PostgreSQL, body in object storage.

### Security and authority

Evidence uses production authority; a manifest claiming a scenario that no log corroborates is rejected at review — the SC-gate lesson carried forward.

### Failure, retry, cancellation, and recovery

Suite failure is a gate failure with the divergence report; re-runs produce a new manifest — history is append-only like everything else.

### Verification and evidence

- Manifest schema validates; every declared scenario appears exactly once
- Skip census is complete — a skip absent from the census invalidates the manifest
- Prerequisite evidence artifacts exist and recompute against their digests
- Divergence report lists every observed-vs-declared mismatch
- Evidence artifact: `phase-2-slice-f-acceptance.json`

### Scope control

P2F05 owns evidence and verdict only — no scenario execution, no runtime code.

### Definition of Done

The Phase 2 verdict is recorded as a machine-checkable manifest whose every claim is backed by digested, committed evidence.

## Slice acceptance

**Gate:** `S2F-G1` — **Evidence:** `phase-2-slice-f-acceptance.json`

Slice 2F — and Phase 2 — is complete when:

1. P2F01–P2F05 contracts are verified with passing tests
2. Every injectable failure class fires deterministically under test builds and is absent from production builds (P2F01)
3. The crash/leasing matrix passes: no lost work, no double dispatch, ambiguity always operator-gated (P2F02)
4. The policy matrix passes: every spec-declared reason code exercised and verified (P2F03)
5. The end-to-end proof passes: depth-3 expansion, sibling reads, operator-resolved ambiguity, complete `run_lineage` provenance (P2F04)
6. The verdict manifest validates with a complete skip census and prerequisite chain (P2F05)
7. `S2A-G1`, `S2B-G1`, `S2C-G1`, `S2D-G1`, `S2E-G1` verdicts are recorded and their evidence recomputes
8. The complete Phase 2 acceptance evidence is durably recorded at `phase-2-slice-f-acceptance.json`

Slice 2F must not implement runtime capabilities — it proves them. Phase 2 exit requires all six slices accepted with verifiable evidence.
