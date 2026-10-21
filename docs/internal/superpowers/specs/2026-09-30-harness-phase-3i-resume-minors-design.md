# ADR 0035 harness phase 3i: close the 3g Resume Minors

Date: 2026-09-30. Follows phase 3h (PR #17, `ce488f8`). No migration.

## 1. Problem

The whole-branch and per-task reviews of phase 3g (PR #15) left eight Minor items. Three are behaviour gaps (one store validation, one refusal code, one HTTP status) and five are missing test evidence. None blocks a release, but the two store items sit on the most invariant-sensitive path (`execution.resume_reconciled_attempt`), and the status item makes an internal failure look like an operator error.

Goal: each item is either fixed in code with a test, or pinned by a test that fails if the behaviour regresses. No behaviour change beyond items 1, 2 and 8.

## 2. Decisions

| # | 3g Minor | Decision | Why |
|---|---|---|---|
| 1 | Store does not validate the shape of the Step the resume scope inserts | Add a Step-shape check to `validateChangeSetOwnership`, before `BuildExecutionChangeSet` runs, for the resume scope only. Operands: the binding Step is the change-set row whose id is `ReceiptBinding.StepID`; the inserted Step is the one other Step row; the inserted Step's logical operation is taken from the new attempt (`execution.Step` has no logical id field of its own). Required: exactly one inserted Step; its `Sequence` equals the binding Step row's `Sequence` + 1; `Version` 1; state `running`; the new attempt's `LogicalOperationID` differs from `ReceiptBinding.LogicalOperation`; same workspace, task and run as the binding Step. Any other shape is refused as `FailureDenied` with code `SCOPE_MISMATCH`. The Sequence check is relative to the change set (the store does not re-read the stored Sequence for the binding Step); the domain revalidation and the existing ownership checks stay as they are. | The attempt side is checked row by row; the Step side trusts the domain evaluator. Running the check inside `validateChangeSetOwnership` makes it fire before any SQL and before the domain revalidation, so the refusal code is the one the scope already uses. Residual: a caller able to hand-craft a whole change set is trusted at this layer (it already is for every other scope); recorded, not addressed. |
| 2 | A second resume row in the old Step is refused with a different code than the rest of the scope | Today a second attempt row in the old Step is already refused, as a typed failure (`INVALID_LOGICAL_OPERATION_REUSE` through the insert rule or `ACTIVE_ATTEMPT_CONFLICT`), after the Step insert has run. Normalize it: in the same `validateChangeSetOwnership` pass, the old Step may hold exactly one attempt row in the change set, the binding attempt; any additional row whose `StepID` is the old Step is refused as `FailureDenied` / `SCOPE_MISMATCH` before any SQL. `SCOPE_MISMATCH` is an existing string literal, not a named constant; do not add a constant in this phase. The test first records the current outcome against the real store, then pins the new one. | One refusal family for every scope-shape violation, raised before any write. |
| 3 | The heal branch returning `ErrResumeNotAllowed` and reloading is untested | Add a table case to `TestHarnessResumeSourceKeysOnTheClaimedAttempt`: the fake resolver returns `ErrResumeNotAllowed` and the reloaded row is already `resolved(resume)`; expect success with no error. Also add the same case with a reloaded row that is NOT resolved: expect the existing fail-safe error. Add a case for `CompleteResume` reloading on `ErrVersionConflict` in `internal/harness/app/reconciler_test.go`. | Pins both reload branches of a lost-write heal. |
| 4 | Ceiling not tested at Sequence = max - 1 | Add rows Sequence 2, max 3 (eligible) to `TestHarnessResumeStateOffersResumeOnlyWhenEligible` and `TestHarnessResumeMapsRefusals`. | The boundary between eligible and `attempt_limit`. |
| 5 | The chain-budget e2e cannot tell root wall clock from config wall clock | In `TestHarnessE2EChainBudgetShrinksAcrossResumes` make the root Task's wall clock differ from the serve default (root 30 minutes, default 1 hour) and assert the resumed attempt row keeps 30 minutes. The e2e also asserts the `WallClockDefaulted` flag of the resumed row equals the root's. | Proves the chain pins the root's wall clock, not the current config. |
| 6 | Exactly 10_000 micro-USD remaining is not exercised end to end | Add a second Task in the same e2e family: budget US$1.00, first attempt records US$0.99 spent, `Resume` commits and the resumed attempt's effective cost budget is exactly 10_000 micro-USD. One micro-USD less is refused as `budget`. | Floor boundary through the real `Resume`, not only `ResumeState`. |
| 7 | The admission composition test compares status codes only | Extend `TestServeCompositionAdmitsHarnessResumeWithTheResolvePolicy` to compare the response body and the `Content-Type` and `Cache-Control` headers for the resume route against the resolve route in every case where the two must match. | A status-only comparison would accept a different body or a missing security header. |
| 8 | An infrastructure error from web Resume gives 409 | Classify in the operator, not the handler: `resumeRefusal` (`cmd/central/harness_resume.go`) keeps mapping the existing typed refusals and additionally maps every other typed `execution.Failure` (for example `STATE_SCOPE_MISMATCH`, `TASK_TRANSITION_REJECTED`, `IDEMPOTENCY_CONFLICT`, `RESUME_TOOL_CALLS_PRESENT`, the new `SCOPE_MISMATCH`) to `ErrHarnessNotResolvable`, so those stay 409 as today (they are concurrent-change or refused-state outcomes the operator can retry or re-check). Only the database failure type (`databaseFailure`) and an error that is not an `execution.Failure` are returned as-is. In `ServeTaskHarnessResume`: `ErrHarnessStarting` unchanged; `ErrHarnessNotResolvable` 409 with the existing body; any other error becomes HTTP 500 through the existing task-action failure renderer, same body shape and no error text. The "other" case of `TestServeTaskHarnessResumeRefusalIs409` moves to the 500 group; the live-lease 409 stays. Resolve is out of scope and unchanged. | An operator reading 409 retries or re-checks state; 500 says "Central failed", which is true only for infrastructure failure. A blanket default-to-500 in the handler would have reported a racing cancel as a Central failure. |

## 3. Data flow

Items 1 and 2 change only `validateChangeSetOwnership`, which runs before `BuildExecutionChangeSet` and before any SQL, so `persistSteps` sees a change set whose shape was already checked. Item 8 changes the operator's error classification and the web handler's error switch. Items 3 to 7 add tests only.

## 4. Errors

- A change set under `execution.resume_reconciled_attempt` whose inserted Step has a wrong Sequence, Version, state, logical id or owner, or whose old Step holds a second attempt row: refused as `FailureDenied` / `SCOPE_MISMATCH`, nothing written.
- A well-formed resume (what the domain evaluator produces) commits exactly as before.
- Web Resume with a database failure or an untyped error: HTTP 500. Any typed `execution.Failure` the operator does not map to a named refusal is still a 409.

## 5. Acceptance

1. Store unit tests (no DB), at the level of `validateChangeSetOwnership` (the level where the check runs): the resume shape builder in `resume_scope_test.go` gains one failing row per Step field (Sequence not old+1, Version not 1, state not running, logical id equal to the binding Step's, owner mismatch, a second inserted Step) and one row for a second attempt in the old Step; all are refused as `FailureDenied` / `SCOPE_MISMATCH`; the good shape still passes.
2. Live store test (`CENTRAL_TEST_PG_URL`): the second-attempt-in-old-Step case against the real store returns `SCOPE_MISMATCH` and leaves no extra row.
3. `cmd/central` unit tests: the heal cases of item 3 and the Sequence = max - 1 rows of item 4.
4. `internal/harness/app`: `CompleteResume` reload on `ErrVersionConflict`.
5. Live e2e (`CENTRAL_TEST_PG_URL` and `CENTRAL_TEST_PG_RUNTIME_URL`, `-p=1`): the wall-clock pin (item 5) and the exact-floor commit (item 6). The effective budget is written when the resumed attempt is claimed, so both tests dispatch the resumed attempt before asserting its budget. The one-micro-USD-less case (9_999 remaining) is refused by the operator pre-check as the `budget` obstacle, and the test pins that refusal (not the command's `RESUME_BUDGET_EXHAUSTED`).
6. Operator and web tests: a database failure gives 500 with no error text in the body; a typed `execution.Failure` outside the named refusals (for example `TASK_TRANSITION_REJECTED`) stays 409; not-resolvable and live lease stay 409.
7. The composition test compares body and headers.
8. `gofmt`, `go vet ./...` (also with `-tags referencehost`), `go build ./...` clean; the runbook refusal list says web Resume returns 500 for an unexpected error; `docs/implementation/current-phase.md` gets one line.

## 6. Out of scope

Token ceilings, the `rerun` kind, a cumulative cap across Retries, and the 3d to 3f Minors. Resolve keeps returning 409 for unexpected errors.
