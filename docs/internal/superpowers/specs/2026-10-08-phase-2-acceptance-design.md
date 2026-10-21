# Phase 2 acceptance — Slice 2F execution design (issue #97)

Status: draft. Design-gate input under issue #97. Governing inputs:
the Slice 2F dossier (`docs/implementation/phase-2-slices/slice-f-phase2-acceptance.md`,
packets P2F01–P2F05, gate S2F-G1), the recovery test matrix spec
(`docs/internal/superpowers/specs/2026-10-07-phase-2-recovery-test-matrix.md`,
spec 9 of the #91 gate, scenarios RTM-01–RTM-19 + RTM-P1–P3), and the
verdict precedents SE (`docs/internal/superpowers/reviews/2026-10-07-se-acceptance.md`)
and E06 (`cmd/central/e06_acceptance_test.go`). This spec defines HOW
Slice 2F is executed: driver shape, injection harness, scenario
binding, evidence manifest, and verdict procedure. It implements no
runtime code and authorizes none.

## Scope

Owns:

- the acceptance driver: one linux-tagged Go test in `cmd/central`
  executing the RTM catalog machine tier against real components;
- the failure-injection harness: deterministic, journaled, test-only
  triggers for every injectable fault class (dossier P2F01);
- the scenario-to-packet binding: which driver steps execute RTM-01–19,
  the P2F04 end-to-end proof, and the 2E projection re-verification;
- the evidence manifest: RTM schema `phase-2-recovery-matrix/v1`
  extended with the dossier's census/prerequisite/divergence blocks,
  its archive location, and the SHA256SUMS discipline;
- the verdict procedure: clean-worktree run, self-issued machine-tier
  record per the §5 amendment, and the #96-closure check.

Does NOT own: the RTM catalog itself (spec 9 — cited, never
redefined); any failure semantics or reason code (specs 1–8 — every
asserted code must exist verbatim there); the physical-tier runs
(RTM-P1–P3 — recorded `deferred-physical` with owning-track
pointers); any runtime, migration, or UI behavior change.

## Brainstorm decisions

Brainstorming (`dotagent-superpowers-brainstorming`) ran with
recommended-option choice per the maintainer's autonomous pipeline.
Questions, options, and chosen answers:

| # | Question | Options | Chosen + why |
| --- | --- | --- | --- |
| 1 | Driver shape | (a) Go test in `cmd/central`, linux tag, env-dir evidence; (b) new binary; (c) shell orchestrator | (a) — E06/SE precedent, clean-worktree runnable, single-command gate |
| 2 | Injection mechanics | (a) test-only fault package (build tag) + journaled markers on real components; (b) real kills in machine tier; (c) domain mocks | (a) — dossier P2F01 + B12 precedent; (b) is flaky/slow; (c) violates "real code paths" |
| 3 | Harness seam | (a) deterministic fake behind `scheduler/port.Launcher`, real dispatch/validation/reconcile; (b) real harness agent | (a) — ADR 0035: Central never handles harness credentials; real runs are the physical tier |
| 4 | Evidence manifest | (a) RTM v1 + dossier census/prerequisite/divergence blocks; (b) RTM v1 verbatim; (c) dossier shape only | (a) — satisfies both owners; every extra block is additive, no field redefined |
| 5 | Verdict identity | (a) self-issued machine tier per §5; (b) wait for independent review | (a) — issue #97 names it; SE precedent; physical tier upgrades later |
| 6 | Repetitions/cadence | (a) RTM OQ-1/OQ-2 defaults (1 rep, gates #97 + Phase 2 exit); (b) higher | (a) — spec default; reviewer may raise |
| 7 | #96 (merged as #103, issue still open) | (a) index 2E evidence as prerequisite, close #96 with evidence comment; (b) leave open | (a) — #97's dependency reads "#92–#96 complete"; the code is merged and its evidence is in-tree, so the closure is verifiable, not assumed |

Approaches considered: (A) single composed acceptance test per this
spec — recommended, see Q1; (B) per-packet binaries + shell
orchestrator — rejected: weaker atomicity, harder clean-worktree
story, no composition proof; (C) extend each slice's own suite instead
of a composed matrix — rejected: loses the composition proof, which
is the point of #97 (the B12 lesson: composition finds defects
slices miss).

## Design

### D1 — Driver shape

One test, `TestPhase2RecoveryMatrix`, in
`cmd/central/phase2_acceptance_test.go` (`//go:build linux &&
phase2inject`, package `main`; the E06 shape plus the D2 injection
tag, since the driver imports the tag-gated injection package). It:

- builds the real component graph the slices' own tests compose
  (PostgreSQL via `CENTRAL_TEST_PG_URL` test container, the
  `workflow`/`scheduler`/`checkpoint`/`retry`/`eventjournal` domain
  services over their postgres adapters, the dispatch/reconcile/sweep
  app loops);
- executes RTM-01–RTM-19 in catalog order, one subtest per scenario,
  each asserting the journaled events + reason codes + terminal or
  parked state its owning spec declares;
- executes the P2F04 end-to-end proof (D4) after the matrix;
- indexes prerequisites (D6) without re-running other suites;
- emits the manifest (D5) to `$CENTRAL_PHASE2_EVIDENCE_DIR` when set;
  without the env var it still runs every assertion but writes no
  manifest (CI-safe default, E06 behavior).

A `failed` scenario fails the test. A fault that does not land is
`inconclusive` (dossier P2F01 rule) and fails the test — never
counted as pass. Package-level test helpers live in the test file;
reusable fault triggers live in the injection package (D2).

### D2 — Injection harness (P2F01)

New package `internal/phase2accept` (test-only surface: every trigger
file carries a dedicated build tag, e.g. `phase2inject`, so the
production binary cannot link an injection path — the dossier's
`authority_test` precedent generalized). Triggers, one per fault
class:

- kill windows: post-claim pre-`attempt_started`, mid-invoke,
  post-outcome pre-commit — implemented as controlled restarts of the
  in-process driver graph (drop + rebuild component handles without
  touching durable state), followed by the real
  `scheduler/port.Store.Reconcile` pass;
- launcher/adapter faults: scripted `port.Launcher` fakes —
  definite refusal (`LAUNCHER_REFUSED`), unconfirmed outcome
  (`confirmed=false`), provider `RATE_LIMITED` with `retry_after`;
- worker loss: heartbeat suppression (suspect→lost ladder via the
  real `SweepSuspects`), unclean death (lease rows orphaned, worker
  row left registered);
- checkpoint faults: tampered token bytes, bumped `format_version`,
  edited workspace digest, GC'd artifact reference;
- clock control: injected `port.Clock` advancing past lease TTL,
  session/node/workflow ceilings, and backoff `not_before`;
- MinIO/PostgreSQL faults: narrow windows (connection refuse,
  object-missing) scoped to the scenario that needs them.

Every injection records a marker (scenario id + fault class) in the
test log and the manifest's `observed` block so the run is
attributable. Markers are never journal events: a synthetic event
kind would trip RTM-18's zero-undeclared-kinds rule, and minting one
in the S6 catalog would be a spec-6 amendment for test attribution
alone. A link assertion (a tag-less test asserting no production
package depends on the injection package via `go list -deps`)
proves the production binary carries no injection path.

### D3 — Scenario binding (P2F02/P2F03)

Crash/leasing rows (RTM-02/03/05/06/07/16 + kill/timeout halves of
RTM-19) execute through the real dispatch path: `ClaimReady` →
provision (test provisioner) → scripted launcher → outcome persist
under the lease fence — asserting `attempt_started`/`attempt_failed`
(`PROCESS_EXIT_NONZERO`)/`attempt_ambiguous`
(`ATTEMPT_AMBIGUOUS_LEASE_EXPIRED` /
`ATTEMPT_AMBIGUOUS_WORKER_LOST`)/`lease_expired`
(`LEASE_EXPIRED_NOT_STARTED`)/`worker_suspect`/`worker_lost`
(`WORKER_LOST_GRACE_EXPIRED`) and the parked-or-requeued node state
spec 2 declares. Startup reconciliation (RTM-03) runs the real
`Reconcile` before any post-restart dispatch and asserts completed
nodes + `finalized` artifacts survive byte-identical.

Policy rows execute through the owning domain entry points under the
production authority chain: `Classify`/`ComputeDelay`/`BudgetRemaining`
(RTM-13/19, `RETRY_BUDGET_EXHAUSTED`, `SESSION_TIMEOUT`,
`NODE_TIMEOUT`, `WORKFLOW_TIMEOUT`); provider partition (RTM-04) drives
the D2 scripted launcher returning `RATE_LIMITED` with `retry_after`,
asserting `attempt_failed` `RATE_LIMITED` (transient) and node requeue
with `not_before` = min(`retry_after`, cap) via `ComputeDelay`;
`CancelNode` cascade (RTM-11,
`node_cancelled` partition per spec 1); `BoundaryLegal`/`Compatible`/
`EncodeToken`/`DecodeToken` preflight (RTM-09, the four S3 codes);
resume (RTM-10) drives the checkpoint resume entry point after a D2
kill, asserting unfinished nodes dispatch as new `attempt_seq`, the
ambiguous node parks `RESUME_REQUIRES_OPERATOR_DECISION`, and the
readable artifact set is re-exposed without payload restore (exact
resume symbol bound by the plan);
idempotency replay across every spec-5 key table (RTM-08,
`command_deduped` / `DUPLICATE_IDEMPOTENCY_KEY`); outbox stall and
admission deferral (RTM-15/17, `CAPACITY_ADMISSION_DEFERRED`,
`admission_deferred`, FIFO kept); lineage edges (RTM-01/14,
`artifact_finalized` gating, `ARTIFACT_NOT_FINALIZED`,
`ARTIFACT_SCOPE_DENIED`, `LINEAGE_READ_UNDECLARED`); event integrity
(RTM-18, `EVENT_SEQUENCE_GAP`, `DUPLICATE_EVENT_ID`,
`UNKNOWN_EVENT_KIND`, plus the global zero-undeclared-kinds
cross-check over every machine-tier run); cycle rejection (RTM-12,
`child_spec_rejected` + `SPEC_VALIDATION_FAILED` per RTM OQ-4).

No new UI behavior is asserted (dossier P2F03 scope control).

### D4 — End-to-end proof (P2F04)

One recorded run after the matrix: a leader session emits validated
`central.child-spec/v1` batches through the real `EmitBatch`
(spec-1 validation, no bypass); the graph expands to depth 3 with a
second dynamic batch; a depth-4 emission rejects `MAX_DEPTH_EXCEEDED`;
a child reads a sibling's finalized artifact through the attempt
scope (declared read edge + checksum journaled); one injected
ambiguity parks until the operator resolves it via `ResolveAmbiguous`
(rerun branch; the resume branch stays parked for harness-native
resume per the port contract); the run completes and `run_lineage`
closure accounts for every final artifact.

2E re-verification (resolving the dossier's P2F03/P2F04 tension):
read-only — the proof projects its own journal through the 2E
projection path and asserts every proof node/edge/decision renders
(no new UI behavior, no browser). Both ambiguity outcomes are
verified across runs (rerun resolves here; resume stays parked and
its parked rendering is asserted).

### D5 — Evidence manifest (P2F05)

One JSON manifest, `phase-2-recovery-matrix.json`, schema
`phase-2-recovery-matrix/v1` (RTM D3) extended with additive blocks
the dossier requires. The per-scenario blocks subsume the dossier's
per-packet files
(`phase-2-slice-f-{injection-harness,crash-matrix,policy-matrix,e2e-orchestration}.json`)
in this single source to prevent inter-file drift; the dossier's
packet names survive as `packet` tags on scenario blocks:

- per scenario the RTM fields (`scenario_id`, `tier`, `status`,
  `owning_specs`, `reason_codes_asserted`, `event_kinds_asserted`,
  `expected`, `observed`, `journal_receipt_ids`,
  `physical_pointer`) plus a `packet` tag (P2F02/P2F03/P2F04)
  tracing the dossier packet;
- `coverage` exactly per RTM D3;
- additive: `prerequisites` (S2A-G1–S2E-G1 evidence files, each with
  path + SHA-256 + parse status), `host_profile` (toolchain, PG
  version, build tags), `commands` (exact commands executed, incl.
  the matrix invocation), `divergences` (observed-vs-declared pairs;
  empty on pass), `skip_census` (empty — every row is
  passed/failed/deferred-physical; a silent skip invalidates the
  manifest). Per-scenario `journal_receipt_ids` are the log anchors
  the dossier's "log digests" require.

`status` vocabulary is RTM's (`passed`/`failed`/
`deferred-physical`); the dossier's `pass`/`fail` wording is the same
binary verdict under RTM names. Emission dir:
`docs/internal/superpowers/reviews/evidence/<date>-phase-2-recovery-matrix/`
containing the manifest + `SHA256SUMS`, committed on the branch. The
manifest records `candidate_commit` + per-artifact digests (SE
discipline). The driver reads `central_revision`/`candidate_commit`
from `GITHUB_SHA` (E06 precedent) and fails closed when it is absent
during an evidence run. Physical rows RTM-P1–P3 record `deferred-physical` with
pointers (operator runbook / maintainer run / phases.md exit track)
— never passed, never silently skipped.

### D6 — Prerequisites + #96 closure

The driver asserts each `phase-2-slice-[a-e]-acceptance.json` exists
in-tree, parses as valid JSON, and carries substantive attestation —
a non-empty `packets` map (slices a–d) or a non-empty `criteria` map
(slice e; its `criteria` is the attestation, it has no `packets`
key) — and records the
SHA-256 of the exact bytes indexed in `prerequisites` for audit — the
SE `prior-acceptance-evidence-indexed` rule: index, don't re-run,
don't re-issue. `schema`/`gate` keys are recorded as-is with a `notes`
field naming absences: several slice files predate the gate-key
convention (b/c lack `gate`, d lacks both) and historical evidence is
never edited post-hoc to satisfy a new check. (Execution-time
amendment 2026-10-08: the as-approved `schema`+`gate` requirement did
not match the in-tree files; the Task 2 implementer caught it before
writing code.) Whole-branch reviews for
issues #92–#96, where present, are cited in the verdict record, not
re-litigated.

#96 closure check (decision 7): the plan verifies slice 2E's merge
(#103) + its in-tree evidence (acceptance, conformance, graph-view,
lineage-ui, operator-controls, projections, observability) parse and
cover the dossier's P2E packets; on success issue #96 is closed with
an evidence comment during execution. If the check fails, #96 stays
open and the verdict records the gap — the matrix itself still runs.

### D7 — Verdict procedure

1. Green branch: full `go test` for touched packages + `go vet` +
  `gofmt` clean.
2. Clean-worktree run (the SC-G1-withdrawal check): fresh detached
  `git worktree` at the candidate commit, `go build ./...` + the
  matrix command
  `GITHUB_SHA=<candidate> CENTRAL_PHASE2_EVIDENCE_DIR=<dir> go test
  -tags phase2inject -run 'TestPhase2RecoveryMatrix' ./cmd/central/
  -count=1` — all 19
  machine rows must pass, zero inconclusive, zero undeclared event
  kinds.
3. Evidence commit on the branch (manifest + SHA256SUMS under the
  D5 path).
4. Verdict record `docs/internal/superpowers/reviews/<date>-phase-2-acceptance.md`
  in the SE shape: verdict line, gate, governing schema, candidate +
  evidence commits, manifest + SHA-256, reviewer identity
  (self-issued per §5), evidence table, criterion coverage, disclosed
  limitations (machine tier only; fake-harness fidelity boundary —
  no real agent ran; prior evidence indexed not re-run; self-issued),
  and what the verdict does/does-not do (accepts Slice 2F at machine
  tier; does not claim physical exit, independent review, or anything
  about the physical tracks).
5. S2F-G1 recorded; issue #97 closed by the merge. Epic #90 closes
  only with #96 also closed (D6).

## Failure semantics

- No new reason code or event kind is introduced. A scenario needing
  a code that exists nowhere is a defect in the owning spec — amend
  that spec, never mint one here (RTM rule, repeated as a gate).
- Every `reason_codes_asserted` string must match its owning spec's
  literal vocabulary — drift is a gate failure, not a tolerance
  (dossier P2F03 rule).
- A fault that does not land invalidates its scenario as
  `inconclusive` and fails the suite — never pass, never silent.
- Any observed-vs-declared mismatch is a divergence entry with the
  full pair; the suite does not partially pass.
- Scenario ids are append-only and stable (RTM OQ-5); retired rows
  are marked `superseded`, never renumbered.

## Open questions

- **OQ-1 — fake-harness fidelity boundary.** The machine tier proves
  dispatch/validation/reconcile/evidence paths with a deterministic
  launcher fake; no real agent executes. Default: disclose as a
  verdict limitation (D7.4), real runs owned by RTM-P1–P3. A reviewer
  wanting a live-agent machine row must say which failure class it
  would cover that the fake cannot.
- **OQ-2 — repetitions/cadence.** RTM OQ-1/OQ-2 defaults adopted
  (decision 6): 1 repetition per gate run, nightly N=10 flake pass
  optional; gates #97 + Phase 2 exit, machine tier CI-eligible.
  Reviewer may raise the gate count.
- **OQ-3 — 2E projection binding.** D4 names the 2E projection path
  without pinning symbols; the plan binds exact query entry points.
  If 2E exposes no journal-to-view projector callable outside HTTP,
  the re-verification degrades to asserting the proof journal
  contains every node/edge/decision the 2E evidence shapes require —
  recorded honestly either way.

## Acceptance criteria

- The driver executes RTM-01–RTM-19 + the D4 proof + D6 prerequisite
  index from this spec + spec 9 alone; every asserted code traces to
  specs 1–8 verbatim.
- All six phases.md acceptance scenarios map to passing machine rows
  per RTM D2; RTM-P1–P3 record `deferred-physical` with pointers.
- The manifest validates against D5 (RTM v1 fields + additive
  blocks); every declared scenario appears exactly once; the skip
  census rule holds; digests recompute.
- Injection triggers are deterministic and journaled; the production
  binary links no injection symbol (compile assertion).
- The verdict record follows D7.4 with all four disclosed
  limitations; S2F-G1 is recorded; #97 closes on merge.
- Spec review records a verdict under
  `docs/internal/superpowers/reviews/` before the plan is written.
