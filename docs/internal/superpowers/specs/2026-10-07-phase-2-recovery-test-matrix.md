# Phase 2 — recovery test matrix — spec

Status: draft. Design-gate input under issue #91 — spec 9 of the
spec-gate table (`2026-10-07-phase-2-spec-gate-design.md`), drafted
last per the declared dependency order because it consumes every other
spec's failure semantics. This spec defines the injected-failure
scenario catalog the issue-#97 acceptance suite executes and the
evidence schema that suite emits. It implements no runtime code and
authorizes none.

## Scope

Owns:

- the injected-failure catalog — each scenario's setup, injection, and
  expected behavior, cited to the spec that owns that behavior;
- the evidence schema `phase-2-recovery-matrix/v1`, its machine|
  physical tiering (E06 precedent), and its archive location;
- starvation detection (assigned here by spec 8 decision 5) and the
  deferral-escalation question (spec 8 OQ-4).

Does NOT own: the acceptance suite's implementation (issue #97); the
review/verdict ceremony; any new failure semantics — every reason code
asserted below is defined by specs 1–8, cited never introduced.

## Design

Shorthand: **S1** workflow-graph/scheduling, **S2** leasing/worker
protocol, **S3** checkpoint/resume, **S4** retry/timeout taxonomy,
**S5** idempotency/consistency, **S6** event schema, **S7** artifact
lineage, **S8** concurrency/resource limits — all
`docs/internal/superpowers/specs/2026-10-07-phase-2-*`.

### D1 — Scenario catalog

Each row names its injection, minimal setup, expected behavior, owning
spec(s), asserted reason codes/events, and tier. `machine` = in-process
acceptance driver on real components with stub harness seams (E06
precedent); `physical` = real host/process/network, recorded
`deferred-physical` with a pointer to its acceptance track.

| scenario_id | injection | setup | expected behavior | owning spec + codes asserted | tier |
| --- | --- | --- | --- | --- | --- |
| RTM-01 golden-path graph | none | run: 2 parallel + 1 dependent child | all `succeeded`; ordering edge gates dependent; read/produce edges journaled; final artifact explains itself | S1 state machine; S7 lineage (no failure codes — asserts event order) | machine |
| RTM-02 harness session crash | harness process exits nonzero mid-attempt | running attempt | `attempt_failed` `PROCESS_EXIT_NONZERO` (transient) → `attempt_retry_scheduled` → node `ready` | S4 taxonomy + backoff; S1 retry path | machine |
| RTM-03 process kill mid-attempt | kill daemon/worker mid-run, restart | running + completed siblings | reconcile-before-reinvoke; completed nodes/`finalized` artifacts survive; started attempts → `attempt_ambiguous`; no output lost | S2 d9/d6; S6 fold verifies state; phases.md kill scenario | machine; physical companion RTM-P1 |
| RTM-04 provider network partition | adapter sees provider unreachable / `RATE_LIMITED` | running attempt | `attempt_failed` `ADAPTER_ERROR`\|`RATE_LIMITED` (transient); `retry_after` honored, bounded by cap | S4 backoff + retry_after | machine; physical companion RTM-P2 |
| RTM-05 heartbeat-loss ladder | worker stops heartbeating | worker holding lease | `worker_suspect` at 2 missed beats (observable only); `worker_lost` `WORKER_LOST_GRACE_EXPIRED` at 5 → all leases expire per S2 d6 | S2 d5; suspect→lost ladder | machine |
| RTM-06 lease expiry, never-started | lease lapses pre-`attempt_started` | claimed, not started | `attempt_failed` `LEASE_EXPIRED_NOT_STARTED`; node → `ready`; safe reassignment under new lease — no duplicate durable effects | S2 d6; S1 claim; phases.md lease scenario | machine |
| RTM-07 lease expiry mid-flight | lease lapses on started attempt; stale write attempted | running attempt | `attempt_ambiguous` `ATTEMPT_AMBIGUOUS_LEASE_EXPIRED`; node NOT auto-requeued; stale durable write → `LEASE_FENCE_STALE` | S2 d6/d7 fence | machine |
| RTM-08 duplicate idempotency key | same key + same payload; same key + different fingerprint; late duplicate outcome report | submitted command | replay returns existing record (`command_deduped`); different fingerprint → `DUPLICATE_IDEMPOTENCY_KEY`; no second row/transition/event | S5 replay table; phases.md dedup scenario | machine |
| RTM-09 incompatible checkpoint | resume token against bumped `format_version`; stale token; edited workspace; GC'd artifact | checkpoint exists | preflight fails all-or-nothing: `CHECKPOINT_INCOMPATIBLE`, `RESUME_TOKEN_STALE`, `WORKSPACE_DIGEST_MISMATCH`, `CHECKPOINT_ARTIFACT_MISSING`; `resume_failed` journaled; run state unchanged | S3 D3; phases.md checkpoint scenario | machine |
| RTM-10 resume happy path + ambiguous halt | resume after kill; one subtree node `attempt_ambiguous` | valid checkpoint | unfinished nodes dispatch as new `attempt_seq`; ambiguous node parks `RESUME_REQUIRES_OPERATOR_DECISION`; readable artifact set re-exposed, payloads never restored | S3 D4 | machine |
| RTM-11 parent cancel cascade | cancel parent node | mixed subtree (running/ready/declared) | running descendants get harness cancel control; non-terminal → `cancelled`; `declared`/`ready` transition with no session; `node_cancelled` journaled | S1 cancel propagation; phases.md cancel scenario | machine |
| RTM-12 child-spec cycle rejection | emit batch A→B→A | leader emission | atomic `child_spec_rejected` naming offending keys; no nodes created; leader may re-emit corrected batch. Asserted code `SPEC_VALIDATION_FAILED` (S4) — see OQ-4 | S1 validation; S4 code | machine |
| RTM-13 budget exhaustion | repeated transient failures past class/`max_attempts_total`; terminal-class failure | node with failing attempts | `node_failed_terminal` `RETRY_BUDGET_EXHAUSTED` (or class code, e.g. `BUDGET_EXHAUSTED`); dependents stay blocked; leader observes | S4 d3/d7 | machine |
| RTM-14 sibling artifact read ordering | dependent with `artifact` edge; premature read attempt | producer mid-flight | node not `ready` until `artifact_finalized`; premature `central artifact read` → `ARTIFACT_NOT_FINALIZED`; after finalize → `ready` → dispatch; read edge carries checksum | S7 d3; S1 readiness | machine |
| RTM-15 admission deferral under capacity | saturate `max_parallel_sessions`; shrink free disk below floor | `ready` nodes queued | no attempt row; node stays `ready`; `admission_deferred` `CAPACITY_ADMISSION_DEFERRED`; re-evaluation event-driven; FIFO position kept | S8 d2/d5/d6 | machine |
| RTM-16 ambiguous attempt → operator gate | attempt `attempt_ambiguous` (via RTM-03/05/07) | unresolved ambiguous | no auto-resume/auto-rerun; node/workflow timers do not fire; operator decision idempotent — replay returns recorded choice; rerun → new `attempt_seq` | S2 locked 1; S4 locked 2/3; S5 decision key | machine |
| RTM-17 starvation detection | sustained saturation across runs | deferred node | keeps FIFO position; dispatches after capacity frees; matrix flags non-dispatch past threshold (OQ-3) | S8 d5 + OQ-4 hand-off | machine |
| RTM-18 event-stream integrity | inject `seq` gap; re-deliver event; emit undeclared kind | journaled run | `EVENT_SEQUENCE_GAP`, `DUPLICATE_EVENT_ID`, `UNKNOWN_EVENT_KIND`; across all scenarios: zero undeclared kinds vs S6 catalog | S6 d2/d6 | machine |
| RTM-19 timeout hierarchy | session ceiling breach (confirmed kill); unconfirmed kill; node/workflow expiry | attempts under ceilings | `SESSION_TIMEOUT` retryable on confirmed kill; unconfirmed → `attempt_ambiguous`; `NODE_TIMEOUT`, `WORKFLOW_TIMEOUT` terminal; workflow expiry cancels per cascade | S4 d5 | machine |
| RTM-P1 real daemon kill | `kill -9` central + worker on host | live run | RTM-03 expectations at production tier | S2 d9; physical pointer: operator runbook | physical |
| RTM-P2 real provider partition | real network drop / provider 429 | live run | RTM-04 expectations with real adapter | S4; physical pointer: maintainer run | physical |
| RTM-P3 clean-host end-to-end | full multi-agent run on fresh host | install → run | exit-criteria walkthrough: survives process/network/provider/worker faults; lineage explains every artifact | all; physical pointer: phases.md exit track | physical |

### D2 — phases.md acceptance-scenario mapping

Every `docs/product/phases.md` §Phase 2 acceptance scenario maps onto
catalog rows — explicit, no orphan coverage:

| phases.md scenario | rows |
| --- | --- |
| parallel + dependent children → correct final result | RTM-01 (+ RTM-14 ordering evidence) |
| kill application/worker loses no completed child outputs | RTM-03, RTM-05, RTM-P1 |
| expired lease → safe reassignment, no duplicate durable effects | RTM-06 (auto path), RTM-07 + RTM-16 (started path: reassignment only via operator rerun, fence prevents dup effects) |
| repeated idempotency key → no duplicates | RTM-08 |
| incompatible checkpoint fails safe + actionable reason | RTM-09 |
| parent cancel propagates per documented policy | RTM-11 |

Note on row 3: S2 splits reassignment by attempt state — automatic only
when nothing ran; a started attempt requires the operator gate. The
catalog asserts both branches.

### D3 — Evidence schema `phase-2-recovery-matrix/v1`

The suite emits one JSON artifact:

```json
{
  "schema": "phase-2-recovery-matrix/v1",
  "generated_at": "…", "central_revision": "…",
  "scenarios": [{
    "scenario_id": "RTM-06", "tier": "machine",
    "status": "passed|failed|deferred-physical",
    "owning_specs": ["S2", "S1"],
    "reason_codes_asserted": ["LEASE_EXPIRED_NOT_STARTED"],
    "event_kinds_asserted": ["lease_expired", "node_ready"],
    "expected": "…", "observed": "…",
    "journal_receipt_ids": ["…"],
    "physical_pointer": null
  }],
  "coverage": {
    "phases_md_scenarios": { "…": ["RTM-…"] },
    "specs_consumed": ["S1"…"S8"],
    "asserted_codes_all_cataloged": true
  }
}
```

Archived under `docs/internal/superpowers/reviews/evidence/<date>-phase-2-recovery-matrix/`,
emitted via an env dir like E06's `CENTRAL_E06_EVIDENCE_DIR`. Machine
tier runs in-process on real components; physical rows are recorded
`deferred-physical` — never silently skipped — with pointer to the
owning acceptance track. A `failed` row fails the suite.

## Failure semantics

This spec introduces **no** new reason codes. Rules:

- Every catalog row asserts only codes defined in S1–S8; the
  `reason_codes_asserted` field is the traceability mechanism.
- A scenario whose expected behavior needs a code that exists nowhere
  is a defect in the owning spec — route: amend that spec, never mint
  one here.
- The suite itself reports `passed`/`failed`/`deferred-physical`;
  scenario *injections* are not journaled reason codes — asserted
  codes are the system's responses.
- Cross-check: all `event_kinds_asserted` and all events observed in
  machine-tier runs must resolve against the S6 catalog
  (`UNKNOWN_EVENT_KIND` on undeclared kinds is itself asserted by
  RTM-18).

## Open questions

- **OQ-1 — repetitions.** Default: 1 repetition per gate run; a nightly
  flake-detection pass runs N=10. Reviewer may raise the gate count.
- **OQ-2 — cadence.** Default: matrix gates issue-#97 acceptance and
  Phase 2 exit, not every commit; machine tier is CI-eligible, physical
  tier on maintainer demand.
- **OQ-3 — deferral staleness signal (spec 8 OQ-4 hand-off).** Default:
  RTM-17 asserts eventual dispatch only. A `admission_stale`
  operator-visible signal is proposed but would be a spec-8 amendment,
  not this spec's to mint.
- **OQ-4 — cycle-rejection code.** S1's `child_spec_rejected` names
  offending keys but assigns no reason code for cycles (S8 assigns
  codes only for cap rejections). Default: assert S4's
  `SPEC_VALIDATION_FAILED`; a dedicated code would be an S1 amendment.
- **OQ-5 — catalog mutability.** Default: scenario ids are append-only
  and stable; retired rows are marked `superseded`, never renumbered.

## Acceptance criteria

- Every catalog row is traceable: `owning_specs` cites file + decision;
  `reason_codes_asserted` exist verbatim in S1–S8 vocabularies.
- All six phases.md acceptance scenarios map to rows in D2; the mapping
  names rows, not prose.
- Evidence schema names every field the suite must emit, per scenario
  and per coverage block; physical rows carry pointers.
- No new reason code or event kind is introduced; contradiction /
  missing-code findings route back to owning specs.
- Spec review records a verdict under
  `docs/internal/superpowers/reviews/`; issue #97 can implement the
  suite from this catalog alone.
