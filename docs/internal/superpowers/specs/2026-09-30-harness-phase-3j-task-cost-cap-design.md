# ADR 0035 harness phase 3j: a cumulative cost cap per Task across Retries

Date: 2026-09-30. Follows phase 3i (PR #18, `dbab086`). No migration.

## 1. Problem

Cost budgets are per Run (phase 3d) and, inside a Run, per resume chain (phase 3g). A Retry (`task.RetryFailedTask`) keeps the Task id and creates a new Run with the Task's per-Run budget again, so a Task that keeps failing can spend the per-Run limit once per Retry without bound. Runbook §4b says so explicitly ("there is no cumulative cap across retries").

Goal: the recorded harness cost of all Runs of one Task is bounded by one serve-wide cap. A Retry that would start above the cap is not offered and not committed; a Run that is started is clamped so it cannot run past the cap.

## 2. Decisions

| # | Topic | Decision | Why |
|---|---|---|---|
| 1 | Shape | One serve-wide cap, `CENTRAL_HARNESS_TASK_COST_CAP_USD` (same two-decimal USD grammar as `CENTRAL_HARNESS_MAX_COST_USD`, range US$0.01 to US$100000.00). Unset: the default is five times the serve per-Run default (US$25.00 with the default US$5.00 per Run), capped at the range maximum. An explicit value below the serve per-Run default (`CENTRAL_HARNESS_MAX_COST_USD`) is refused at startup with the existing config error shape, so the cap can never shrink the first Run of a Task that uses the serve default. Harness execution on: always in force. No per-Task cap field and no schema change. | A per-Task field needs a migration and a submit-form change; the gap is an unbounded total, which a global cap closes. Harness execution is still off by default, and deriving the default from the per-Run default means the cap never changes a Run that uses the serve default. A Task that requests its own cost budget above the cap is clamped (decision 4). |
| 2 | Used cost | The cap counts the recorded `usage_cost_micro_usd` of every `harness_attempts` row of every Run of the Task (join `runs.(workspace_id, id)` to get `task_id`), via a new read `CostForTask(ctx, workspace, task)` on the harness attempt store (port, postgres adapter, fake). The sum saturates at `MaxInt64`. Rows are immutable once terminal, so the sum only grows. A Rerun is a new Task (`ParentTaskID`) and starts with its own cap: lineage is not followed (out of scope). | Reuses the recorded figure the chain rule already trusts. |
| 3 | Retry gate | The web Retry action asks the harness operator first (new `HarnessOperator.RetryState` and the Retry POST). Blocked when `cap - used < MinRetryCostMicroUSD` (US$0.01, the same floor as the resume chain and the per-Run minimum). Blocked Retry: the Task page shows `<p id="harness-retry-unavailable">Retry is unavailable: this Task has used its cost cap</p>` in place of the Retry button, and a forged POST is refused as 409 with the existing task-action failure body, committing nothing and never calling the task service. Harness execution off (no operator): no gate. A Task that never ran under the harness has used 0. | Same pattern as Resume's unavailable reasons. The operator owns the cap, so the task domain does not learn it. |
| 4 | Claim clamp | The effective cost budget of every fresh-prepared claim (`harnessBudget`, called from `claimStart` and from `claimSuccessor`) becomes `min(per-Run budget, max(cap - used, floor))`, so a Run that was offered can never outspend the remaining cap by more than the floor. This covers the queued start and also a sequence-1 prepared successor that is prepared fresh after a crash (it uses `ClaimedRun.Budget`). The resume path is unchanged: it pins the chain root's budget (`prepareResume` uses `from.Budget`), which was clamped when the root was claimed. `CostForTask` is read BEFORE the claim command runs (the claim commits the lease, so a read error after it would strand a leased Run): a read error returns before any command and leaves the Run exactly as it was. `CostDefaulted` still describes where the per-Run bound came from and is not changed by the clamp; a clamped limit is shown as the explicit effective value, and the Task-level line (decision 6) carries the cap so the operator can see why. | The gate decides at Retry time; the clamp covers the window until the claim (for example the cap lowered and serve restarted) and bounds the first Run too when the cap is below the per-Run default. Overshoot is at most the floor, by design, as for the resume chain. |
| 5 | Limit of the count | Cost is recorded only from the `result` frame, so an attempt that ended without one (serve stopped, killed) contributes 0 and the cap under-counts (runbook §4b already documents this for the chain). The cap does not change that. | Token and cost accounting per message is a separate item (phase 3l). |
| 6 | Display | The Task detail page adds one line when the harness is on: `Task cost used: US$<used> of US$<cap>` using the same micro-USD formatter as the attempt cost. | The operator sees why Retry is blocked before clicking. |
| 7 | Scope | Only Retry and the claim clamp. Resume (chain rule), Rerun, Mark failed/cancelled and the ordinary submit are unchanged. | Only Retry creates a new Run under an existing Task. |
| 8 | Docs | Runbook §4b and the Retry paragraph of §8 drop "no cumulative cap" and describe the cap, the env var, the under-count, the Rerun exclusion and the clamp overshoot; `docs/implementation/current-phase.md` gets one line; §10 (maintainer gate) gets no entry. | Operator-facing behaviour. |

## 3. Data flow

`harnessConfig` parses the env var into `TaskCostCapMicroUSD` and passes it to `composeHarness`, which hands it to the operator and to `harnessLifecycle`. Page: `RetryState` reads `CostForTask` and returns `{Used, Cap, Blocked}`; the Retry POST calls the same function before `RetryFailedTask`. Claim: `claimStart` and `claimSuccessor` read `CostForTask` before their command and clamp the resolved budget; a read error returns before any command, so the Run is untouched and the dispatcher handles it as any other claim error. `CostForTask` lives on the composition's `harnessAttemptStore` next to `AttemptsForRun` (not on `port.AttemptStore`, which `WithLease` also returns), and is injected into `harnessLifecycle` and the operator.

## 4. Errors

- Used + floor above the cap: page line, no button; POST 409; nothing committed.
- `CostForTask` read error on the page: button hidden, no unavailable line; on the POST: an infrastructure failure (500, nothing committed); at the claim: returned before any command (the Run is untouched).
- Invalid env value (not two-decimal USD, out of range): serve refuses to start with the existing config error shape.

## 5. Acceptance

1. Config: valid; default (five times the per-Run default, US$25.00 with the default per-Run, and scaling when `CENTRAL_HARNESS_MAX_COST_USD` is changed); explicit value below the per-Run default refused; out-of-range and malformed values; harness off ignores the variable.
2. Store: `CostForTask` sums across two Runs of one Task, ignores another Task's attempts and another Workspace's, is 0 for none, saturates; live PostgreSQL test plus a fake that matches.
3. Operator unit: `RetryState` blocked exactly when `cap - used < 10_000` (boundary at 10_000 and 9_999), allowed below; harness off: no gate.
4. Web: detail page shows the unavailable line and no Retry form for the blocked state, the "used of cap" line, and keeps the existing Retry button otherwise; a forged POST is 409 with no task-service call.
5. Clamp: `harnessBudget` returns `min(per-Run, max(cap - used, floor))` for used 0, used near the cap, and used above the cap (floor); both `claimStart` and `claimSuccessor` apply it; a `CostForTask` error returns before the claim command is sent (a counting fake proves zero commands).
6. Live e2e (`CENTRAL_TEST_PG_URL` and runtime URL, `-p=1`; the e2e harness has no HTTP driver, so it drives the operator directly and acceptance 4 covers the page): a Task whose first Run fails after recording cost C; with a cap that leaves more than the floor, `RetryState` allows it and the second Run's recorded effective budget is the remaining amount (below the per-Run default); with a cap that leaves less than the floor, `RetryState` is blocked.
7. `gofmt`, `go vet ./...` (also `-tags referencehost`), `go build ./...` clean; runbook and `current-phase.md` updated.

## 6. Out of scope

Token ceilings, the `rerun` kind, following Rerun lineage, making the overview attention list cap-aware (it keeps saying "Retry available" for a failed Task; the Task page explains), a marker for a clamped limit on the attempt row (a new flag would need a migration), a per-Task configurable cap, accounting for cost of an attempt that has no `result` frame, and the 3d to 3f Minors.
