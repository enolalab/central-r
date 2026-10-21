# Run-Submission Entrypoint — Design (issue #122)

- **Date:** 2026-10-09
- **Issue:** #122 — [Phase 2] Add run-submission entrypoint (unblock #110 Task 2)
- **Parent:** #110 (physical-tier exit RTM-P1–P3); split because the campaign
  stopped BLOCKED at Task 2 Step 2 (submit-command pinning rule).
- **Prior verdicts (read-only, never edited):** S2A-G1 … S2F-G1, SE, SD —
  all Accepted (machine tier / Docker profile) (self-issued).

## 1. Goal

Add a production submit surface that creates workflow runs + nodes — a CLI
verb and an HTTP route over one shared domain path — so the #110 Task 2
Step 2 pin rule can name an exact command and a live multi-agent run with
real sessions becomes producible under the production authority chain.

Done means: an exact, documented `central run submit` command exists;
submitting through it yields a live leader→children run (workflow nodes,
scheduler attempts, real harness sessions — no SQL fixtures, no test
bypass); the kill-confirmation split is untouched; the machine matrix
stays 23/23 green with the S1–S8 vocabulary verbatim; #110 gets the
pinned command as a comment.

## 2. Findings that shape the design

All inspected on origin/main at `33698a81`.

1. **Run shell already exists; only the workflow half is missing.**
   `task.SubmitTask` (`internal/task/domain.go`) creates a queued task +
   first queued run in one change-set through the task domain service;
   `central.runs` rows are the run-row lock anchor every workflow-graph
   write takes (`internal/adapter/postgres/workflow/store.go`). No new
   run table is needed — the submit path reuses the task domain and then
   emits nodes against the fresh run id.
2. **Phase-1 dispatch would steal a queued submit.** `queryListDispatchableRuns`
   (`internal/adapter/postgres/execution/queries.go`, case `queued`) takes
   any queued task whose queued current run has no steps. A Phase-2 submit
   left queued would ALSO launch a Phase-1 harness attempt on the same run.
   `task.ClaimCurrentRun` (queued→running, needs an owner token) removes
   the run from case (a); case (b) needs a prepared successor attempt that
   never exists on a Phase-2 run. So submit claims its own run (owner
   `phase2`) through the task domain service.
3. **The scheduler claim needs no run-status change.**
   `Store.ClaimReady` (`internal/adapter/postgres/scheduler/store.go`)
   scans `workflow_nodes WHERE state='ready'` filtered by worker
   workspace + capabilities; it never reads `central.runs.status`. Ready
   nodes dispatch whether the run row reads queued or running.
4. **Serve's worker is sentinel-scoped with a fixed capability set.**
   `composeScheduler` (`cmd/central/scheduler_composition.go`) registers
   one in-process worker on `pgsession.SentinelWorkspaceID`
   (`019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a`), harness `["claude-code"]`,
   workspace kinds `[directory]` (`+ worktree` only with SourceRepo).
   Submitted nodes must name harness `claude-code` and workspace kind
   `directory` to be claimable on every deployment; the pinned #110
   command targets the sentinel workspace.
5. **`EmitBatch` is the only node-write path and it dedupes.**
   `port.GraphStore.EmitBatch` validates one `central.child-spec/v1`
   batch atomically; re-emission on `(run_id, node_key)` with the same
   spec fingerprint dedupes to the committed node (`command_deduped`),
   a colliding key with a different fingerprint rejects the batch as
   `DUPLICATE_IDEMPOTENCY_KEY`. `RecomputeReady` converges (declared→ready
   with no prerequisites). Both are replay-safe — the submit saga needs no
   new dedup rows.
6. **Task receipt replay does NOT cover submit retries.** `replayByReceipt`
   (`internal/adapter/postgres/task/store.go`) compares a fingerprint over
   the change-set, which embeds fresh UUIDs minted inside
   `task.SubmitTask` — a retried submit with a deterministic receipt key
   would always mismatch. The run_key path instead fails closed with
   `DUPLICATE_IDEMPOTENCY_KEY` on the partial UNIQUE
   `(workspace_id, run_key)`; the submit service resumes by reading the
   existing run back by `(workspace_id, run_key)` and comparing
   `request_fingerprint` (deterministic over the canonical request).
7. **Children must be flat, not ordering-blocked.** #111 shipped the real
   launcher but deferred outcome collection (F2): real sessions start but
   nothing yet records node success. Children with `depends_on: [leader]`
   would park `declared` forever. Leader + workers emitted with NO
   `depends_on` all flip ready in one `RecomputeReady`, while the batch-2
   `parentID = leader` preserves leader→children lineage. Multi-agent live
   proof needs no completion event — nodes + attempts + real sessions.
8. **The machine matrix uses scripted fakes, not serve composition.**
   Per #111 §Finding 8, `phase2accept` drives the 23-scenario matrix
   directly. New submit code cannot break it; criterion 4 is proved by
   re-running the matrix.
9. **CLI precedent: `central node decide`.** `internal/command/node.go` shows
   the envelope (`cli.WriteResultTo`), exit mapping (usage 2, terminal 6),
   command-level `NODE_*` tokens, key-or-id resolution, and env-composed
   backend failing closed (`NODE_UNAVAILABLE`). `run submit` mirrors it.
   No `run` verb exists yet (`internal/command/registry.go`), so the
   grammar is free.
10. **HTTP precedent: `ServeTaskSubmit` + run controls.** POST-only, Origin
    required, single CSRF field, `activeSessionWithCSRF`, generic failure
    body, redirect-on-success (`handler.go`, `run_controls.go`). The runs
    surface today is read + cancel/decide controls — no submit route.

## 3. Decisions

### D1. One app service, two surfaces

New package `internal/runsubmit` (app service, not domain — it orchestrates
the task, workflow and scheduler-adjacent stores without new business
rules) exposing:

```go
type SubmitRequest struct {
    WorkspaceID uuid.UUID // required; sentinel for serve-claimed runs
    Title       string    // task title; required, bounded
    Workers     int       // 1..8 child workers; leader always emitted
    RunKey      string    // optional; empty disables replay lookup
}
type SubmitResult struct {
    TaskID  uuid.UUID
    RunID   uuid.UUID
    Nodes   []SubmittedNode // leader first, then workers
    Deduped bool            // true when run_key replay resumed
}
func (s *Service) Submit(ctx, req) (SubmitResult, error)
```

Flow per call: pre-validate (D8) → task submit → task claim (owner
`phase2`) → emit batch 1 `[leader]` (parent nil) → emit batch 2
`[worker-1..N]` (parent = leader id) → `RecomputeReady` → result.
Steps 2–6 each commit independently (the stores share no transaction);
step order plus native dedup/convergence makes the saga resumable (D4).
The service performs no workspace-existence pre-check (spec-review F3):
an unknown workspace fails at the first commit, and the plan records the
exact refusal in a test.

### D2. Run shell reuse + self-claim

- Task input is a fixed marker JSON (`{"schema_version":
  "central.phase2-run-submit/v1", ...}`) recording the submit shape
  (workers, run key presence) — provenance for the operator, never
  executed by Phase-1 (frozen B09 + no steps: nothing reads it).
- Permission policy `deny`, no budgets at submit (node ceilings stay
  Central-enforced per spec-8; worker brief unchanged).
- Immediately after submit, `ClaimCurrentRun` moves task+run to running
  with owner `phase2`, excluding the run from Phase-1 dispatch (F2) while
  leaving the scheduler path untouched (F3). All task transitions go
  through `task/app.Service` (AGENTS.md rule).
- B08 safety: a running run with zero `central.steps` rows is invisible to
  both dispatch cases and to step-row recovery; the startup reconciler
  only expires leases of lost workers. No recovery path can quarantine or
  adopt the run.
- Task-cancel of a phase2-owned run is out of scope for this issue
  (spec-review SR1): the plan pins the CURRENT cancel-path behavior over a
  step-less running run in a test and documents the outcome; if the path
  wedges instead of settling, the plan files a follow-up defect rather
  than redesigning cancel here.

### D3. Node shape (leader + flat workers)

- Batch 1: `leader` — harness `claude-code`, workspace `directory`,
  no `depends_on`, no artifact refs, no budget override (inherits
  unbounded root), default retry/timeout posture.
- Batch 2: `worker-1 … worker-N` — same fields; `parentID` = leader node
  id (lineage only, no scheduling edge).
- `Workers` range 1..8 (caps allow 64 nodes/run; 9 nodes max keeps a live
  proof well under `max_parallel_sessions: 4` FIFO + deferral behavior).
- Harness/registry seam: emit-time `HarnessLaunchable` names exactly
  `claude-code` (serve parity, F4); `ArtifactFinalized` seam unused (no
  input refs) but wired fail-closed, never nil-pass.

### D4. Idempotency and replay (no new dedup state)

- With `run_key` (1..128 chars; `runs.run_key` is unbounded text, so the
  service enforces the bound on both surfaces): submit plants it on the
  run row. On `DUPLICATE_IDEMPOTENCY_KEY` the service reads the run back
  by `(workspace_id, run_key)` (new narrow read on the task store port +
  one pg query) and compares the row's `request_fingerprint` against the
  task domain's OWN fingerprint bytes for the incoming request
  (spec-review SR3: the plan exposes an accessor on the domain function;
  no second implementation of the canonical JSON). Mismatch is a
  `DUPLICATE_IDEMPOTENCY_KEY` conflict and the recorded row stands; match
  adopts the existing run id and continues: claim only if still
  queued-and-unowned (already-`phase2`-owned skips), emits dedupe natively
  (F5), `RecomputeReady` converges. Returns `Deduped: true`.
- A version conflict on the claim step re-reads the run (spec-review
  SR2): owner `phase2` + fingerprint match adopts and continues
  (`Deduped: true`); anything else returns the conflict. Concurrent
  same-key submits therefore converge on one run, never two.
- Without `run_key`: every call mints a fresh task+run (Phase-1 parity);
  retries of a half-finished keyless submit are NOT deduped (documented;
  the pinned command always sets a key).
- `RecomputeReady` is safe to repeat at every resume; it never un-readies.

### D5. CLI: `central run submit`

Grammar (registered in `internal/command/registry.go`):

```text
central run submit --workspace <uuid> --title <text> --workers <n> [--run-key <k>]
```

- `--workers` required, integer 1..8; `--title` required, 1..200 chars;
  `--workspace` required UUID (no default — the operator pins the exact
  workspace; the #110 pin names the sentinel id verbatim); `--run-key`
  optional, 1..128 chars when present (D4 bound).
- Envelope: `cli.WriteResultTo` with details
  `{run_id, task_id, nodes: [{node_id, node_key}], deduped}`; reason `ok`.
- Exits mirror `node decide`: grammar 2 `RUN_USAGE`; nil backend 5
  `RUN_UNAVAILABLE` (`cli.ExitUnsupported`, same as `node`);
  store `workflow.Failure` keeps its reason (INVALID→2, DENIED/CONFLICT→6);
  `DUPLICATE_IDEMPOTENCY_KEY` mismatch → 6; adapter errors → 6
  `RUN_FAILED`. No new journaled codes — `RUN_*` are envelope tokens only.
- Pinned #110 command shape (exact key/title pinned at execution time):

```text
CENTRAL_NODE_DSN=<dsn> central run submit --workspace 019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a --title <t> --workers 2 --run-key <k>
```

### D6. HTTP: POST /app/runs/submit

- `ServeRunSubmit` on the web handler: `runControlPrelude`-equivalent
  security sequence (POST-only with `Allow`, Origin required, single CSRF
  field, `activeSessionWithCSRF`, session-workspace scoping), form fields
  `title`, `workers`, `run_key` (optional), `idempotency_key` (fresh per
  render, minted where the form is rendered — same pattern as task submit;
  carried as the task-scope receipt key, NOT the run_key).
- Success: `303 SeeOther` to `/app/runs/detail?run=<id>` (task-submit
  redirect precedent). Refusal: the run-control generic failure shape —
  status + `RUN_CONTROL_FAILED`, never the domain reason pre-scope-check;
  post-scope validation failures (bad workers/title) are `400` with the
  same generic body (non-disclosure precedent).
- Route registered in the admission table with the full
  `OriginRequired|CSRFRequired|SessionCSRFRequired|StateChanging|BodyLimit|
  HTMLResponseCap` tuple (run-controls precedent).
- A minimal submit form is rendered above the runs list on GET `/app/runs`
  (`ServeRunList`; budget-submit precedent: "the submit form is now always
  shown above the task list"), carrying the fresh `idempotency_key` + CSRF
  fields. `run_key` on the form keeps the D4 1..128 bound.

### D7. Backend composition (one DSN, fail closed)

- CLI deferred mode reuses `CENTRAL_NODE_DSN` (same database the operator
  already provisions for `node decide`): both the task change-set store and
  the workflow graph store compose over it; absent/unreachable DSN leaves
  the seam nil → `RUN_UNAVAILABLE`. No credential files are read.
- Serve composition wires the HTTP handler's submit port over the shared
  runtime pool (same pool as `newRunControlPorts`).
- Required grants are exactly the union of the web task-submit writes and
  the `node decide` writes (tasks, runs, command_receipts, workflow_nodes,
  workflow_edges, run_events, attempt tables are untouched at submit).
  The plan verifies `central_runtime` holds them; no grant migration is
  expected — if a grant is missing the plan says so before code lands.

### D8. Pre-validation before the first commit

Before touching the task store, the service runs `workflow.ValidateBatch`
twice (batch 1 against empty state, batch 2 against batch-1 keys) with
`DefaultCaps()`, unbounded parent budget, and the D3 seams. A rejection
fails the submit with `SPEC_VALIDATION_FAILED` + offending keys and
commits NOTHING — a claimed-but-empty run is unreachable by construction
(the only post-commit failures left are infra errors, which resume via
D4). Emit-time validation still runs (defense in depth; identical input
cannot diverge on a fresh run id).

## 4. Data flow (happy path)

```text
operator → central run submit (D5) ─┐
                                    ├→ runsubmit.Service.Submit (D1)
browser → POST /app/runs/submit (D6)┘        │
        ┌────────────────────────────────────┘
        ▼
  pre-validate batches (D8) → task submit (queued) → task claim (owner
  phase2, running) → EmitBatch[leader] → EmitBatch[workers|parent=leader]
  → RecomputeReady (all ready) → {task, run, nodes}
        │
        ▼ (existing machinery, unchanged)
  serve claim loop → ClaimReady (sentinel worker) → provision →
  real Launcher.Start (scope = attempt id) → MarkStarted(real session) →
  heartbeats; wall-clock breach → real Killer → confirmed SESSION_* or
  parked ATTEMPT_AMBIGUOUS_* (split untouched).
```

## 5. Errors

Journaled vocabulary is UNCHANGED (fail-closed literal rule):

- `SPEC_VALIDATION_FAILED` (pre-validation or emit rejection — same code,
  same detail rule codes), `DUPLICATE_IDEMPOTENCY_KEY` (run_key collision
  with differing payload, or node-key collision — same token, same
  standing-row rule), `command_deduped` (replay convergence).
- No new `reason_code` values anywhere; any new error text is `fmt.Errorf`
  context on existing sentinels.
- Envelope-only tokens (never journaled, never in S1–S8): `RUN_USAGE`,
  `RUN_UNAVAILABLE`, `RUN_FAILED` (CLI); `RUN_CONTROL_FAILED` (HTTP,
  existing token).

## 6. Security

- ADR 0035/0036 unchanged: no harness credentials touched; the worker brief
  (D4 of #111) still builds from durable node facts only; no submit string
  reaches launch argv (title/input land in task rows + journal payloads,
  never in `StartSpec` — the brief renderer takes ids + refs only).
- Title is operator input persisted to the DB and rendered in HTML: bounded
  (200 chars), rendered through the existing escaping renderer (no new
  template helpers with raw HTML).
- Permission checks are not weakened: new tests use real stores over the
  test PG fixture with the production grants, never a relaxed allowlist,
  gate, or assert helper.
- CLI takes no workspace-root path, no SQL, no file input — the grammar is
  closed (workspace uuid, title text, workers int, run-key token).

## 7. Testing

- Unit (no PG): request validation table (workers/title/workspace/run-key
  bounds); two-batch pre-validation shape (leader + N workers validate
  clean under `DefaultCaps`); fingerprint determinism for the run_key
  resume-compare; CLI grammar table (mirror `node_test.go`).
- Live (test PG fixture, no harness exec): submit→nodes-ready end to end
  over real task + workflow stores; run_key replay returns same run with
  `Deduped`, no second nodes/events; mismatched-payload replay conflicts
  with `DUPLICATE_IDEMPOTENCY_KEY` and the recorded row stands; keyless
  double submit yields two runs; Phase-1 dispatch exclusion (submitted run
  is never listed by `queryListDispatchableRuns` — queued case gone via
  claim, prepared-successor case absent); HTTP route prelude + redirect +
  failure-shape tests behind the existing web harness.
- Live dispatch proof (criterion 2, local PG + serve stack): with scheduler
  gate on and the real launcher composed, submit (keyless or keyed) then
  assert leader + workers reach `dispatched`/`running` with
  `session_attempts` rows and real `harness_session_id`s — claude absent
  fails closed `LAUNCHER_REFUSED` per the #111 live-test precedent (that
  refusal IS the no-bypass proof: nothing is scripted); with claude
  present the sessions are real. This test does not run in CI-gated form —
  it is the witnessed #110-setup rehearsal the plan records.
- Regression: full `make test` + S2F matrix re-run 23/23 green,
  0 inconclusive; reason-code grep over S1–S8 verbatim. Historical evidence
  files are never edited.

## 8. Acceptance (issue #122 done)

1. Exact documented submit command exists and is pinnable — D5 grammar +
   the pinned invocation recorded verbatim (criterion 1).
2. Live multi-agent run via the production authority chain — §7 live
   dispatch proof (criterion 2).
3. Kill-confirmation split preserved — no code on the kill path changes;
   unit + matrix RTM-19-session (criterion 3).
4. Matrix 23/23 green, vocabulary verbatim — §7 regression (criterion 4).
5. #110 comment with the pinned submit command; #110 Task 2 setup becomes
   executable (criterion 5 — posted from the merged result, not from a
   branch).

## 9. Out of scope (recorded follow-ups, not this issue)

- F1. Instruction carriage (`prompt_ref`-as-artifact) and outcome
  collection into `RecordOutcome` (#111 F1/F2) — submit creates live
  sessions; completion still needs those tracks.
- F2. Submit-time budgets / node timeouts / artifact refs / custom DAG
  shape — the fixed leader+flat-workers shape is the whole surface.
- F3. Task-detail/run-detail UI polish for claimed-by-phase2 runs.
- F4. Any new verdict or any edit to historical evidence files.

## 10. Open points for plan stage

- O1. Task-store constructor shape for CLI deferred mode: `*pgx.Conn`
  (node precedent) vs single-connection pool — plan inspects
  `pgtask.NewStore` and picks; one DSN either way (D7).
- O2. `RunByKey` read: confirm no existing port covers
  `(workspace_id, run_key)` lookup; else add the narrow read + query (D4).
- O3. Grant audit: prove `central_runtime` holds every D7 write (task +
  workflow + journal) or report the missing grant before code lands.
- O4. Claim-aggregate read path for the service (versions for
  `ClaimCurrentRun`): reuse the service's `detailRead` vs a store read —
  plan picks the narrowest existing seam.
- O5. Runs-list template wiring point for the D6 form (which template
  renders the list; CSRF + idempotency mint call sites).
