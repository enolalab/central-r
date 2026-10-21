# Harness Phase 3e — Cancel, Recovery and Report Design

- **Date:** 2026-09-29
- **Status:** Draft. Brainstormed with the recommended option taken for each question, per the maintainer's workflow. Revised after the focused spec review (`docs/superpowers/reviews/2026-09-29-harness-phase-3e-spec-review.md`).
- **Governing decisions:** [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md); [ADR 0036](../../../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md); ADR 0004 (prepare → invoke → persist); the B08 recovery design (the recovery gate, epochs and quarantine).
- **Governing spec:** [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md), §7 (attempt lifecycle, `ambiguous` never transitions automatically) and §8 (supervision and reconciliation).
- **Builds on:** phase 3a (which disclosed: "a Task cancelled while `queued` stays `cancelling`, and a serve stop mid-cancel falls to existing B08 behaviour"), 3b (the report Artifact, follow-up M7) and 3d (the wall clock, follow-up "wall clock during a cancel").
- **Investigation:** the facts below come from a read-only investigation of the code at `dc50fe1`.

## 1. Goal and decomposition

3a listed "cancel while queued, serve stop mid-cancel, an ambiguous-resolution UI and retries" for 3c. The investigation shows the first two are **data-integrity gaps**, not polish, and that the resolution UI needs an execution-domain answer for a cancelling Task. So the rest of 3c's list is split:

| Sub-phase | Delivers |
|---|---|
| **3e (this spec)** | Operator actions on the Task lifecycle stop leaving Tasks stuck or breaking recovery:<br>• cancelling a Task that was never claimed ends it `cancelled` at once, and a Task already stuck in `cancelling` can be finished;<br>• a serve stop (or lease expiry) in the middle of a cancel no longer quarantines the Workspace at every restart;<br>• "Mark cancelled (operator resolved)" is the operator's exit for a cancelling Task whose attempt is ambiguous;<br>• the report is taken from the `result` frame (3b follow-up);<br>• the wall clock never relabels a cancelled attempt;<br>• Retry and Rerun of harness Tasks get an end-to-end test and a runbook description. |
| 3f | Resume by a new attempt (it needs an execution disposition and Claude Code `--resume` semantics), the resume-chain cost rule, an attempt-count ceiling and token ceilings. |

### Non-goals

- **A resume button.** There is no execution disposition for "resume by a new attempt". Its product equivalent today is "Mark failed", then Retry.
- **`ConfirmSucceeded` on an ambiguous attempt.** It would complete a harness Task without its report Artifact, which the hard rule forbids (3b decision 2). It is never offered.
- **Automatic cancel at restart of an invoked attempt.** An invoked effect is ambiguous unless the lease-holding executor attests that it stopped; the operator's cancel intent is not that attestation.
- **Changing the policy or budget on Retry or Rerun,** a cumulative spend cap across retries, or cleaning retained clones.

## 2. Findings that shape the design

1. **One transition leaves `cancelling`.** Only `task.SettleCancellation` does (`internal/task/domain.go`), and it is reached through the execution facade by three evaluators. Two need a StepAttempt; none is called for a Task without one. `task/app.Service.SettleCancellation` needs no attempt, but has no production caller. B09's driver is not wired into serve.
2. **Cancel while `queued` is stuck for ever.** `RequestCancellation` makes Task and Run `cancelling`; no Step or attempt exists; `ListDispatchableRuns` no longer lists it; recovery finds no unsettled attempt. The page shows "Settling" with no buttons. This also happens with harness execution disabled, where every submitted Task sits `queued`. The race with `StartHarnessRun` is safe today: both commits check the Task version.
3. **A serve stop mid-cancel quarantines the Workspace.**
   - State: Task `cancelling`, StepAttempt `invoked`, the orchestrator never settled.
   - At the next start, B08 recovery moves the attempt to `reconciliation` and asks the task domain to put the Task in `waiting`. `Wait` refuses a `cancelling` Task, and the refusal becomes `TASK_TRANSITION_REJECTED`.
   - That error rolls back the whole recovery batch, quarantines the Workspace's recovery work (`scan_error`) and marks the epoch `degraded`. It repeats at **every** start.
   - Every older Run of the Workspace is then undispatchable, and its web actions return 409.
   - The operator has no control on the page. Only manual SQL helps.
4. **The most reachable variant:** the operator presses **Cancel on an ambiguous `waiting(reconciliation)` Task**, which the page offers next to "Mark failed", and then restarts.
5. **A cancel with a `prepared` attempt** (stop before `MarkInvoked`) is not quarantined but stays `cancelling` for ever: recovery makes a prepared successor, and the dispatcher only re-dispatches `running` Tasks.
6. **Retry and Rerun are wired correctly** for harness Tasks (a new Run gets a fresh clone and keeps the Task's policy and budget), but nothing tests them end to end.
7. **The report can come from a subagent.** The adapter emits every text block, and the orchestrator keeps the last one. Every successful `result` frame in the fixtures carries a `result` field equal to the final top-level assistant text.
8. **The wall clock has no guard during a cancel.** The cost backstop already has one.

## 3. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Split? | 3e as in §1; 3f takes resume, the chain cost rule, attempt count and tokens. | Resume needs new execution semantics and a live check; the rest of this list is a repair of stuck states. |
| 2 | Cancel of a Task that was never claimed? | A new task-domain transition, `CancelUnclaimedTask`, takes a Task `queued` whose current Run is `queued` and **never claimed** (`Run.OwnershipToken == ""`; only `ClaimCurrentRun` sets it) straight to Task and Run `cancelled`, in **one commit**, with the events `task.cancel_requested` and `task.cancelled`. `task/app.Service` exposes it under its own command scope. `ServeTaskCancel` chooses it when the loaded Task qualifies, and `RequestCancellation` otherwise. `RequestCancellation` itself is unchanged. | One click, one commit, no executor needed. A two-commit "request, then settle" would leave the bug behind if the process died between them. The race with the dispatcher stays safe: both commits need the same Task version, so exactly one wins. |
| 3 | Tasks already stuck in `cancelling`? | `CancelUnclaimedTask` also accepts a Task `cancelling` whose current Run is `cancelling` and never claimed. The detail page shows a **"Finish cancelling"** button for such a Task, posting to the same cancel route. | Stuck rows exist wherever an operator cancelled a queued Task before this phase (including with harness execution disabled). It needs no change to recovery. |
| 4 | Recovery and a `cancelling` Task with an invoked or reconciling attempt? | **B08 never asks the task domain to `Wait` a `cancelling` Task.** For a `cancelling` Task it keeps Task and Run as they are, still moves the Step and StepAttempt to `reconciliation` and expires the lease, and records the decision `reconciliation_required_cancelling`. That decision emits the same `execution.reconciliation.required` outbox row as `reconciliation_required` (recovery evidence keys on an explicit set of decisions, so the new string must be added to it); the next-start branch keeps recording `reconciliation_preserved`. No error, no quarantine. The harness reconciler then sees the linked attempt in reconciliation and marks the attempt row `ambiguous`, and the dispatcher's first-start sweep kills any surviving scope, as today. | It removes the quarantine for findings 3 and 4 with the smallest change, and it keeps the domain rule that an invoked effect is ambiguous without the executor's attestation. |
| 5 | Recovery and a `cancelling` Task with a `prepared` attempt? | B08 settles it **whether or not the prepared attempt is a successor** (a predecessor id is set): it cancels the prepared StepAttempt and Step and applies `task.ExecutionSettleCancellationRequest` (Task and Run `cancelled`) with a no-active-lease assertion, in the same recovery transaction, **instead of** creating a prepared successor or preserving one. The `cancelling` check comes first in the prepared branch, before the existing "prepared successor preserved" rule. This needs a **new pure recovery evaluator** (in the style of `EvaluateRecoveryCompletion`): `evaluateSettleCancellation` cannot be reused as is, because it requires the executor capability and command metadata. Nothing was invoked, so no attestation is needed. The harness reconciler already maps a prepared attempt row with a cancelled StepAttempt to `failed(harness_not_launched)`. | A cancel that beat `MarkInvoked` needs nobody's attestation, so it finishes by itself at the restart. Rows already stuck with a successor (created by the old recovery) finish the same way. |
| 6 | The operator's exit for a cancelling, ambiguous Task? | A new action **"Mark cancelled (operator resolved)"**, a sibling of "Mark failed". For a Task `cancelling` whose StepAttempt is in `reconciliation`, it calls the existing `ResolveReconciliation` with the disposition `ReconciliationCancel`, the same operator-attestation evidence and `AssertNoActiveLease`, and **its own idempotency key** (`harness:resolve-cancel:<attempt-id>`; "Mark failed" keeps `harness:resolve:<attempt-id>`). Then the harness attempt row becomes `resolved(abandon)`. The Task and Run end `cancelled`, so Rerun appears. | The execution domain already supports this disposition for a cancelling Task; the 3a resolve action only used `ConfirmFailed`. |
| 7 | How does the page choose? | The resolve form is shown for a Task `waiting(reconciliation)` (button "Mark failed") **and** for a Task `cancelling` whose linked StepAttempt is in `reconciliation` and whose harness attempt row is `ambiguous` **or already terminal** (the orchestrator may have persisted `interrupted` before the settle failed). `ServeTaskHarnessResolve` derives the disposition from the **durable Task `Status` alone**, never from a form field and never from `WaitingReason` (which a cancel from `waiting` leaves set to `reconciliation`); the same prelude, Origin, session CSRF and claimability gate apply; the operator identity comes from the session principal. See decision 12 for Cancel on `waiting(reconciliation)`. | The operator cannot ask for a disposition the state does not allow, and no new route is needed. |
| 8 | The report source? | The Claude Code adapter decodes the `result` frame's `result` string and, on the **last** non-error result whose `result` is non-empty, emits it as the last assistant `Message` (after the `UsageReport`, before stdin closes). The orchestrator's existing "last assistant Message wins" rule then picks it, so **the orchestrator and the domain do not change**. A missing or empty `result` falls back to today's behaviour (the last text block; blank still fails `harness_report_missing`). Size and UTF-8 rules of 3b are unchanged. | The result frame carries the final answer of the top-level agent, so a subagent's text can no longer become the report. |
| 9 | Wall clock versus cancel? | Cancel wins: the wall clock's `stopForBudget` is skipped once `cancelHit` is set, mirroring the cost backstop. | The attempt row then never reads `budget_exhausted` for a Task that ended `cancelled` (3d follow-up). |
| 10 | The `reconcile` milestone status (3b follow-up M9)? | `reconcile` records the terminal state the attempt was about to take when the terminal write failed, not the stale `running`. | Cosmetic, and in the same code. |
| 11 | Retry and Rerun? | Behaviour is unchanged and now documented and tested end to end: a Retry creates a new Run with a **fresh clone** from the source HEAD (the earlier Run's work is not continued); the per-Run budget applies again with **no cumulative cap**; Retry is offered for every failure reason; a retried Task keeps its original `created_at`, so one created before `CENTRAL_HARNESS_ELIGIBLE_AFTER` is queued but never dispatched. A Rerun of a cancelled Task copies the policy and budget. | These are real product behaviours the operator should know, and no harness e2e pinned them. |
| 12 | Cancel on an ambiguous Task? | On a Task `waiting(reconciliation)` whose attempt is resolvable, the page **hides Cancel** and shows **"Mark failed" and "Mark cancelled" side by side**. "Mark cancelled" does the request and the resolve in **one operator action** (`RequestCancellation`, then `ResolveReconciliation(ReconciliationCancel)`: two durable commits). If the first commits and the second fails, the Task is `cancelling` with an ambiguous attempt, and the same panel offers "Mark cancelled" again (decisions 4 and 6). Both buttons carry the text: "By marking, you confirm that the harness is no longer running." A `cancelling` Task with an ambiguous attempt shows: "Settling: the harness stopped when serve stopped. Confirm it is not running, then Mark cancelled." | The operator never lands on an unexplained "Settling" page, and the attestation that makes Rerun safe is explicit. |
| 13 | What does a losing click show? | A Cancel that loses the claim race shows "The Task started. Press Cancel again." A "Finish cancelling" or "Mark cancelled" on a Task that is already `cancelled` shows "Already cancelled." A second "Mark cancelled" replays under its idempotency key. | A stuck-state operator is never left guessing at a bare 409. |


## 4. Data flow

**Cancel while queued:**
1. The operator presses Cancel on a `queued` Task. The handler loads the aggregate and sees the current Run `queued` and never claimed.
2. `CancelUnclaimedTask` commits Task and Run `cancelled` in one transaction.
3. The Task is never listed for dispatch. If the dispatcher's claim committed first, the cancel gets a version conflict and shows the usual 409; pressing Cancel again then follows the normal running path.

**Serve stop while a Task is `cancelling` with an invoked attempt:**
1. The stop closes the lifeline, so the launcher kills the scope. Nothing more is written.
2. At the next start, B08 recovery moves the StepAttempt to `reconciliation` and expires the lease, and leaves the Task and Run `cancelling` (decision 4). The recovery epoch completes.
3. The harness reconciler marks the attempt row `ambiguous`.
4. The Task page offers "Mark cancelled (operator resolved)". The operator presses it: `ResolveReconciliation(ReconciliationCancel)` ends the Task and Run `cancelled`, and the attempt row becomes `resolved(abandon)`.

**Serve stop with a prepared attempt:** at the next start recovery cancels the prepared attempt and settles the cancellation (decision 5). The Task is `cancelled`, and the attempt row is `failed(harness_not_launched)`.

## 5. Errors

| Situation | Behaviour |
|---|---|
| Cancel commits after the dispatcher's claim | Version conflict, 409. The Task is now `running`; a second Cancel follows the normal path. |
| `CancelUnclaimedTask` on a claimed Run | Refused (`ClassDenied`); the route falls back to `RequestCancellation`. |
| "Mark cancelled" with the lease still live | Refused by the `AssertNoActiveLease` evidence check, as "Mark failed" is. |
| "Mark cancelled" twice | The second call replays under the same idempotency key. |
| A recovery batch that meets a `cancelling` Task | No longer an error (decision 4). Other contradictions still quarantine, unchanged. |
| The `result` frame has no `result`, or it is an error result | Today's behaviour: the last text block, or `harness_report_missing`. |
| Recovery finds a completion receipt for an attempt of a `cancelling` Task (the orchestrator staged a success receipt and the report Artifact while the Task was `running`, the lease was lost, then the operator cancelled) | **A receipt never settles a `cancelling` Task: cancel wins.** The task domain refuses `CompleteTask` and `FailTask` from `cancelling`, and recovery already treats that refusal as contradictory and falls back to reconciliation. Decision 4's path runs, the staged Artifact stays unpromoted, and "Mark cancelled" is the exit. `ConfirmSucceeded` is never offered. |

## 6. Security

- Every state change goes through the task and execution domain services. No SQL shortcut.
- The two resolve actions differ only in the disposition, which comes from durable Task state. They share the prelude of the 3a resolve action (Origin, session CSRF, active session, claimability gate), and the operator is the session principal. `ConfirmSucceeded` is never reachable.
- Recovery never invents an attestation: the invoked case ends only through the operator's explicit action, and the prepared case needs none (nothing was invoked).
- The report text comes from a frame the harness produced. It is still treated as untrusted and still passes the B10 classifier and size limits.

## 7. Testing

- **Task domain:** `CancelUnclaimedTask` table test: queued+unclaimed → cancelled; cancelling+unclaimed → cancelled; a claimed Run, a running Task, and a waiting Task are refused; both events; version checks; `RequestCancellation` unchanged.
- **Task app / postgres task store (live):** one commit persists both rows and both events; a stale version conflicts.
- **Web:** Cancel on a queued unclaimed Task calls the new method; on a claimed one it falls back; "Finish cancelling" appears for a cancelling unclaimed Task only; the resolve form appears for `cancelling` with an ambiguous attempt and posts "Mark cancelled"; a forged disposition field is ignored; the same CSRF/Origin/session/claimability tests as the 3a resolve route; Cancel is hidden on a resolvable `waiting(reconciliation)` Task and both buttons and the attestation text render; the settling copy renders for `cancelling` + ambiguous; the resolve form also renders when the harness row is already terminal; the disposition follows `Status`, not `WaitingReason`; the losing-click notices of decision 13.
- **B08 recovery (live PostgreSQL, Architecture mode):**
  - invoked + cancelling: no error, no quarantine, the epoch completes, the StepAttempt is in reconciliation, Task and Run stay cancelling;
  - reconciling + cancelling (the ambiguous-then-cancel case): the same;
  - prepared + cancelling: Task and Run `cancelled`, the StepAttempt and Step `cancelled`, no successor;
  - prepared **successor** + cancelling: the same (decision 5);
  - invoked + a completion receipt + cancelling: the attempt goes to reconciliation, the Task stays `cancelling`, the Artifact stays unpromoted;
  - a Workspace whose previous epoch is `degraded` with a failed `scan_error` row and an old `cancelling` + invoked Task: the quarantine persists across a plain restart, and after the fenced resume the fixed scan completes, clears the `scan_error` row, and the older queued Task is dispatchable;
  - the recovery evidence: `reconciliation_required_cancelling` emits the reconciliation-required outbox row;
  - a `waiting`/`running` Task's recovery is unchanged (the existing tests still pass);
  - a Workspace with an older queued Task stays dispatchable after the restart.
- **Execution/lifecycle:** `ResolveReconciliation(ReconciliationCancel)` through `harnessOperator`: evidence, idempotency key, refusal on a live lease, and the attempt row `resolved(abandon)`.
- **Adapter:** the result frame's text becomes the last Message; a subagent text block before it does not win; an error result and a result without `result` add no Message; the kind sequence test is updated.
- **Orchestrator:** the wall clock during a cancel leaves the cancel's terminal un-relabelled; the reconcile milestone records the intended state.
- **e2e (`cmd/central`, fake claude):**
  - cancel while queued, then a dispatcher never starts it;
  - cancel racing the claim, both orders;
  - serve stop mid-cancel (invoked), restart, "Mark cancelled", Rerun; a second pre-restart Task still dispatches;
  - serve stop with a prepared attempt;
  - Cancel on an ambiguous Task, restart, no quarantine;
  - Retry after a failed Run completes with a fresh clone and the same policy and budget; Rerun after a cancel completes.
- **Live claude (optional, `CENTRAL_TEST_CLAUDE=1`):** confirm on the pinned version that `result` equals the final top-level text. The maintainer runs this at the reference host.

## 7a. Upgrade and runbook

- **No new quarantine; an existing one needs an operator resume.** B08 makes a degraded epoch **sticky**: `StartRecoveryEpoch` takes over the latest incomplete epoch (including a `degraded` one) and the next claim returns `RECOVERY_EPOCH_QUARANTINED`; only the fenced, operator-acknowledged `ResumeRecoveryEpoch` reopens it, and no production code calls it (verified by the draft, §10.1). 3e does not change that accepted B08 rule. So the fixed binary stops **creating** quarantines, but a Workspace that the old behaviour already degraded stays quarantined until that epoch is resumed; the resume surface is a follow-up. In practice such a Workspace can exist only where a Task was cancelled with an invoked harness attempt, which needs harness execution to have run. The runbook's "Upgrading to phase 3e" says so. After a resume, the fixed scan completes, clears the `scan_error` row, and the old `cancelling` Tasks land as described below.
- **After a resume, or where no quarantine exists:** an old `cancelling` Task with an invoked attempt waits as `cancelling` with an ambiguous attempt and shows "Mark cancelled"; one with a prepared attempt, or a prepared successor, settles by itself; one with no Run claimed shows "Finish cancelling".
- **Runbook edits (scoped):** the cancel semantics in §1 (the "Settling" text); §8 becomes "Ambiguous attempts" with "Mark failed" and "Mark cancelled (operator resolved)" and the cancelling-ambiguous case; a Retry and Rerun subsection (fresh clone from the source HEAD, per-Run budget with no cumulative cap, Retry offered for every failure reason, a retried Task keeps its `created_at` so one older than `CENTRAL_HARNESS_ELIGIBLE_AFTER` is queued but never dispatched); and the reference-host checks of §10.
- **Reference-host checks (maintainer, part of the gate, not automated):** with the pinned real claude:
  - the `result` frame equals the final top-level text (the live check of decision 8);
  - serve stopped in the middle of a cancel, then a restart: the Workspace is not quarantined, "Mark cancelled" ends the Task, a Task queued before the restart is still dispatched, and Rerun works;
  - cancel while queued.

## 8. Plan-stage checks

1. **B08 recovery code and its design.** Read the recovery design (ADR or spec) and `persistRecoveryRunDecision`, `persistRecoveryWaitingState` and the prepared branch, before changing them. This is Architecture mode: the full suite, including the live B08 recovery tests, must pass.
2. **How recovery applies a task transition** for the prepared branch: reuse the pattern of `persistRecoveryCompletion` (a pure execution evaluation), and confirm the no-active-lease assertion and the epoch fencing.
3. **How the detail page learns that a Run was never claimed** (for the cancel button and "Finish cancelling"): the aggregate's Run `OwnershipToken`.
4. **The 3a resolve form and route** (`harnessResolvable`, `ServeTaskHarnessResolve`): how the Task status reaches them.
5. **The recovery evidence keys** (the set of decisions that emit the reconciliation-required outbox row) and the prepared-successor branch (`PredecessorID`) in `case AttemptPrepared`.
6. **The B11/B12 acceptance tests** that pin "cancelling stays cancelling" for B09: they must keep passing, since `RequestCancellation` is unchanged.

## 9. Acceptance

1. Cancelling a queued Task ends it `cancelled` at once. It is never dispatched, and a cancel that races the claim is safe in both orders.
2. A Task already stuck in `cancelling` without a claimed Run can be finished from its page.
3. After a serve stop in the middle of a cancel with an invoked attempt, the restart completes the recovery epoch: the epoch is `completed`, `recovery_epoch_workspaces` has no `failure_class = 'scan_error'` row for it, and `/health` shows no `pre_watermark_quarantine`. The Task waits as `cancelling` with an ambiguous attempt, "Mark cancelled" ends it `cancelled`, and Rerun works. A queued Task from before the restart is still dispatched.
4. After a serve stop in the middle of a cancel with a prepared attempt (or a prepared successor), the restart ends the Task `cancelled` by itself.
5. Cancel on an ambiguous Task (through "Mark cancelled", or the two-step path after a crash between its commits) followed by a restart no longer quarantines the Workspace, by the same observables as 3.
5a. A Workspace whose recovery epoch the old behaviour had degraded stays quarantined across a plain restart (B08's sticky rule is unchanged); after the fenced `ResumeRecoveryEpoch` the fixed scan completes, clears the `scan_error` row, and the Workspace's older queued Task is dispatchable again. The runbook states that this needs an operator resume.
6. The report Artifact holds the `result` frame's text, and a subagent's text never becomes the report.
7. A wall clock that fires during a cancel leaves the attempt's terminal as the cancel's.
8. Retry and Rerun of a harness Task are covered end to end and described in the runbook.
9. The full portable suite passes (apart from the known `internal/recovery` `TestNoC06SuiteSourceOutsideTheRunnerCallsTestingSkipDirectly` failure), and the touched packages pass against live PostgreSQL, including the B08 recovery tests.

## 10. Plan-stage findings (verified draft, 2026-09-29)

These take precedence over the decisions above where they differ.

1. **A degraded epoch is sticky (corrects §7a and acceptance 5a).** See §7a. `StartRecoveryEpoch` takes over a `degraded` epoch, `ClaimRecoveryWorkspaces` returns `RECOVERY_EPOCH_QUARANTINED`, and only the fenced `ResumeRecoveryEpoch` reopens it; there is no production caller. The draft did not change this B08 rule. **Follow-up:** an operator resume surface, or an ADR that allows an automatic resume.
2. **Cancel on an already-cancelled Task** answers 303 with "Already cancelled." instead of 409, because the route cannot tell "Finish cancelling" from Cancel (decision 13).
3. **`ResolveFailed` refuses** any Task that is not `waiting(reconciliation)` (`ErrHarnessNotResolvable`); before, a cancelling Task reached the execution command and was refused there.
4. **The resolve route accepts a missing `action` field** (pages rendered before 3e): "Mark failed" on a waiting Task, "Mark cancelled" on a cancelling Task. Form values are `fail` and `cancel`; a value the status does not offer is refused, and an unknown or repeated value is 400.
5. **"A second Mark cancelled replays"** holds for concurrent duplicates (same key and fingerprint). A click after the first succeeded is refused up front and shows "Already cancelled.".
6. **The runtime `EnterReconciliation` path is unchanged.** It can still ask the task domain to `Wait` a Task that became `cancelling` meanwhile; the orchestrator already maps that refusal to the cancel path, so decision 4 applies to B08 recovery only.
7. **Names in code:** `task.CancelUnclaimedTask` with `TaskAggregate.Unclaimed()` and command scope `task.cancel_unclaimed`; `execution.EvaluateRecoveryCancellation` and the recovery decision `cancellation_settled`; `web.HarnessOperator.ResolveCancelled`; idempotency keys `harness:resolve-cancel:<attempt-id>` and `harness:request-cancel:<attempt-id>` (the combined action's first commit); notices `cancel_started` and `already_cancelled`.
8. **A wall clock that fires before the cancel** still lets the cancel's terminal be relabelled `budget_exhausted` (plan review P-T2): decision 9's guard applies only once `cancelHit` is set. The Task still ends `cancelled`; only the attempt row reads `budget_exhausted`/`budget_wall_clock` in that order. The wording of decision 9 is narrowed accordingly: cancel wins **when the cancel is seen first**.
9. **A refusal inside the new recovery cancellation** (an `execution.Failure` from `EvaluateRecoveryCancellation`) fails the recovery batch, like every other contradiction in B08's fail-closed design, instead of falling back (plan review P-T3). No reachable state triggers it. **Follow-up:** fall back to reconciliation with a distinct decision instead of quarantining.
10. **Isolated database for live tests** (plan review P-T1, P-O4). The recovery and e2e tests reset the whole database, so the plan runs them only on the isolated container `central-3e-draft-pg` (port 55434), with its creation command documented. The shared `central-1b-pg` (port 55433) cannot start because its `init.sql` bind mount source was replaced by a root-owned directory.
11. **B11 and B12 acceptance suites** are added to the verification (Task 10 Step 2b): they pin cancel behaviour, are opt-in (`referencehost` tag), and need Docker and a browser, so they are the maintainer's step if they cannot run on the agent's host.
