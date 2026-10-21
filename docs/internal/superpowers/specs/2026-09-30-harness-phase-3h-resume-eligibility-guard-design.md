# ADR 0035 harness phase 3h: Resume honours CENTRAL_HARNESS_ELIGIBLE_AFTER

Date: 2026-09-30. Follows phase 3g (PR #15, `f710462`). No migration.

## 1. Problem

The dispatcher lists a Run only when its Task was created at or after `CENTRAL_HARNESS_ELIGIBLE_AFTER` (`queryListDispatchableRuns`, `task.created_at >= $1`, for both the `queued` and the `prepared_successor` case). Resume (3g) does not check this: for a Task created before that time, in `waiting(reconciliation)` with an ambiguous harness row, the page offers **Resume**, the command commits a new prepared successor and moves the Task and Run to `running`, and then the dispatcher never claims the successor. The Task sits `running` with no lease and no harness. The only exit is Cancel then Finish cancelling (runbook §8, known limitation).

Goal: Resume is never offered, and never committed, for a Task the dispatcher would not pick up.

## 2. Decisions

| # | Topic | Decision | Why |
|---|---|---|---|
| 1 | Where | The guard lives in the harness operator (`cmd/central`), the composition that owns the `EligibleAfter` config. No domain, store or dispatcher change. | Eligibility is harness deployment config, not a Task or execution rule. The execution domain never sees it. |
| 2 | Predicate | A Task is eligible when `Task.CreatedAt` is not before `EligibleAfter`, both taken in UTC and truncated to the microsecond (Postgres `timestamptz` precision), the complement of the SQL filter `task.created_at >= $1` (equal is eligible). A zero `EligibleAfter` switches the guard off: serve's config requires a non-zero value while harness execution is on, so zero occurs only in tests that build the operator directly. | Same boundary as the dispatcher, without the Go side rejecting a Task the SQL would accept (`time.Parse` keeps nanoseconds). |
| 3 | Single check point | The check sits in `readResumeTarget`'s caller path shared by `ResumeState` and `Resume`, as a new obstacle in `resumeTarget.blocked`, judged before the ceiling and the budget (decision 4). It needs the Task's `CreatedAt`, read from the same `ReadExecution` state (`state.Task.Task.CreatedAt`). | The page and the command cannot disagree; the command re-checks durable state as it does for the ceiling. |
| 4 | Order of obstacles | not-eligible first, then the ceiling, then the budget. | A Task the dispatcher will never pick up makes the other two moot; the operator can fix it by lowering `CENTRAL_HARNESS_ELIGIBLE_AFTER` and restarting. The existing two keep their text. |
| 5 | Page | New `web.HarnessResumeBlock` value `not_eligible`. The panel shows `<p id="harness-resume-unavailable">Resume is unavailable: this Task was created before harness execution was enabled</p>` in place of the button. Mark failed and Mark cancelled stay available. | Same panel element as the other two reasons. |
| 6 | Command refusal | `Resume` returns `web.ErrHarnessNotResolvable` (the existing refusal for a blocked Resume) without committing anything. | Consistent with ceiling and budget. |
| 7 | Scope | Only Resume. Retry, Mark failed/cancelled and the ordinary start are unchanged. | Only Resume creates a dispatchable row the filter then ignores. |
| 8 | Docs | Runbook §8 limitation is **narrowed**, not removed: Resume is no longer offered for a Task older than the floor, but moving `CENTRAL_HARNESS_ELIGIBLE_AFTER` later after a Resume has committed and before its successor is claimed still leaves that Task `running` and unclaimed (exit: Cancel, then Finish cancelling). §10 (the maintainer's real-host checklist) gets no entry, the e2e proves the guard; `docs/implementation/current-phase.md` gets one line. | The guard covers the page and the command at decision time only; a later config change is an operator action and is documented. |

## 3. Data flow

`ResumeState` / `Resume` → `readResumeTarget` (unchanged reads) → `target.blocked(maxAttempts, eligibleAfter)` → `attempt_limit` | `budget` | `not_eligible` | `""`. `ResumeState` maps a non-empty obstacle to `HarnessResumeState{Blocked}`; `Resume` refuses. The operator gets an `eligibleAfter time.Time` field, set in `composeHarness` from `Config.EligibleAfter` next to `maxAttempts`.

## 4. Errors

- Task created before the floor: page shows the new line, no button; a forged POST gets `ErrHarnessNotResolvable` (HTTP as the other not-resolvable cases), no state changes.
- `ReadExecution` error: unchanged (button hidden on the page, error on the command).

## 5. Acceptance

1. Unit: `blocked` returns `not_eligible` when `CreatedAt` is before `EligibleAfter`; eligible when equal or after; eligible when `EligibleAfter` is zero; the ceiling and budget still win when they also apply.
2. Unit: `ResumeState` returns `Blocked: not_eligible` for such a Task, and `Resume` returns `ErrHarnessNotResolvable` and calls no command.
3. Web: the detail page renders the new line and no Resume form for `not_eligible`; existing two lines unchanged (strings pinned).
4. Live e2e (`cmd/central`): dispatch a Task under floor F1 until it is `waiting(reconciliation)` with an ambiguous row, then restart serve with a floor F2 later than the Task's `created_at`: the page shows the new line and no Resume, a POST is refused, and the Task stays `waiting(reconciliation)`; with F1 the same Task still resumes (the existing 3g scenarios keep passing). The web tests also add the new case to `resumeUnavailableText`, since an unknown block renders nothing.
5. Runbook and `current-phase.md` updated; `gofmt`, `go vet ./...`, `go build ./...` clean.

## 6. Out of scope

Token ceilings, `rerun`, a cumulative cap across Retries, and the 3g Minors listed in PR #15.
