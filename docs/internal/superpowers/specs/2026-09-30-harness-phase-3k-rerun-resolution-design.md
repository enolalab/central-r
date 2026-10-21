# ADR 0035 harness phase 3k: produce the `rerun` resolution kind

Date: 2026-09-30. Follows phase 3j (PR #19, `639cb48`). No migration.

## 1. Problem

`ResolutionRerun` exists in the harness domain (phase 1a), the store CHECK (migration v30) and `Attempt.Resolve`, but no production code writes it. Every operator resolution of an ambiguous attempt is recorded as `abandon`, including the case where the operator then runs the work again. The original documents disagree on what `rerun` means: the adapter-boundary spec says "rerun (new Run)"; ADR 0035 and `durable-execution.md` call the Task-level Rerun of a cancelled Task a new Task. Phase 3g left it explicitly unproduced.

Goal: fix one meaning, make exactly one operator action produce it, and keep every existing path unchanged.

## 2. Decisions

| # | Topic | Decision | Why |
|---|---|---|---|
| 1 | Meaning | `rerun` on a harness attempt means: the operator resolved the ambiguous attempt by running the same Task again as a NEW Run (Retry: fresh clone, no session continuity). It is the counterpart of `resume` (same Run, same session) and of `abandon` (closed, nothing follows). It is not the Task-level Rerun of a cancelled Task, which creates a new Task and keeps following Mark cancelled, recorded as `abandon`. | The attempt belongs to a Run, so the kind describes what happens to the Run's work; it matches the adapter-boundary spec ("rerun (new Run)") and `PrepareResume` already refuses it. |
| 2 | The one producer | A new operator action on the harness panel of a `waiting(reconciliation)` Task whose harness row is `ambiguous` (a terminal row is not eligible), while harness execution is enabled: **Mark failed and rerun (operator resolved)**. One operator attestation, three steps in this order: (a) the same commit as Mark failed (Task and Run `failed`, reason `operator_resolved`, `ResolveReconciliation(ConfirmFailed)`, under its own idempotency key `harness:rerun:<attempt id>`); (b) `RetryFailedTask` (new Run of the same Task, the Task's budget and policy kept), fed by a re-read of the aggregate after (a) (accepted only if it is (a)'s commit: Task `failed`, versions taken from that read) under its own idempotency key `harness:rerun-retry:<attempt id>`, so a replay of the same action finds (b) done and continues; (c) the harness attempt row `ambiguous -> resolved(rerun)` decided by `operator-session:<principal>`. Each step's failure returns an error and stops; nothing is undone. After (a) alone the Task is `failed` and the ordinary Retry button applies; after (b) without (c) the row stays `ambiguous` and the startup reconciler later records it as `abandon` (its existing healing), so the label can be `abandon` if a crash separates (b) and (c); this is documented, not healed. | The kind is honest only if the new Run exists when the row is labelled, so the row write is last. |
| 3 | Gates | The action is offered and accepted only when Retry would work and be dispatched: harness execution is enabled (with it off there is no dispatcher, so the new Run would never be claimed; the operator method refuses as Resume does), the Task is not older than `CENTRAL_HARNESS_ELIGIBLE_AFTER` (same predicate as phase 3h, else the new Run is never claimed) and the Task cost cap of phase 3j leaves at least US$0.01 (`RetryState` not blocked). Otherwise the button is not shown and a forged POST is refused with the existing 409 (`ErrHarnessNotResolvable`) BEFORE any commit, so the operator never ends with a failed Task they did not choose. A live lease, and any other refusal, is the resolve route's plain 409 (that route answers 409 for every error). A cancelled Task is not resolvable for this action: the route's "already cancelled" shortcut must not answer a `rerun` request as a success. | Reuses the two guards of the new Run; a refusal after step (a) would leave a failed Task. |
| 4 | Authority | The recovery authority (`recoveryTarget` and `RecoverAttempt` in the postgres harness adapter) accepts `resolved(rerun)` only for an ambiguous row whose linked StepAttempt is `failed`, whose Run is no longer the current Run of its Task (a Retry has created a newer Run, so the label is true when it is written), with no live lease; it refuses it for a StepAttempt in reconciliation, cancelled or succeeded, and for one that has a successor (`LinkedResumed`). If the startup reconciler already recorded `abandon` in the window between steps (b) and (c), `ResolveRerun` finds the row terminal and writes nothing (the existing behaviour for a resolved row). `Resolver` gets `ResolveRerun` (same shape as `ResolveAbandon`, kind `rerun`). The domain and the DB CHECK are unchanged. | One-line widening of an existing rule; `resume` stays the only kind bound to `LinkedResumed`. |
| 5 | Web | `parseResolveAction` accepts a third action `rerun` on the existing resolve route, with the same prelude as Mark failed (origin, session, barrier, attestation). A new `HarnessOperator` method performs steps (a) to (c); the Retry of step (b) goes through the task service like the page's Retry button (the operator needs a narrow retry port in the composition). Success redirects to the Task detail. The harness panel shows the button next to Mark failed only when the Task is resolvable and the gates of decision 3 pass. | Same route and policy as resolve, so the admission policy is not widened. |
| 6 | Other paths | Mark failed, Mark cancelled, Resume, the plain Retry and the Task-level Rerun are unchanged. Mark failed still records `abandon`. | The kind is produced only where the operator's intent is stated in the action itself. |
| 7 | Docs | Runbook: what `resolved(rerun)` means, the new button and its gates, the `abandon`-label caveat of decision 2, and the clarification that the adapter-boundary spec's "rerun (new Run)" is this meaning while the Task-level Rerun stays a separate action; `docs/implementation/current-phase.md` one line; §10 gets no entry (an e2e proves it). | Operator-facing behaviour. |

## 3. Data flow

Page: `HarnessOperator.ResumeState`-style read decides the button (resolvable Task, eligible, `RetryState` not blocked). POST: prelude, then the operator re-reads durable state, re-checks the gates, runs (a) through the existing resolve command with the new key, (b) through the retry port, (c) through `Resolver.ResolveRerun`. The row write in (c) logs and does not fail the request when it fails after (b), as `CompleteResume` does.

## 4. Errors

- Gate fails or the Task is no longer resolvable: 409, nothing committed.
- (a) fails: the existing Mark failed error mapping; nothing changed.
- (b) fails after (a): error to the operator; the Task is `failed` and the plain Retry button applies; the row stays `ambiguous` and is later labelled `abandon` by the startup reconciler.
- (c) fails after (b): logged; the new Run proceeds; the row is labelled by the reconciler at the next start.

## 5. Acceptance

1. Authority: `RecoverAttempt` writes `resolved(rerun)` only for a `failed` StepAttempt whose Run is no longer the Task's current Run, and refuses it while that Run is still current, for a StepAttempt in reconciliation, cancelled or succeeded, for `LinkedResumed`, and with a live lease (live PostgreSQL store test plus a fake that matches); `Resolver.ResolveRerun` unit test; the domain test that `rerun` is not resumable stays.
2. Operator unit tests: the three steps in order (a call recorder), gates refusing before any commit (floor, cap, live lease, harness execution disabled, a terminal harness row, a cancelled Task), step failures stopping as in decision 2, the replay of a completed (b), and the row write after (b).
3. Web: the button appears only when offered; a forged POST is 409 before any command; the admission composition admits the `rerun` action exactly as `fail` and `cancel`; existing buttons and their texts unchanged (pinned).
4. Live e2e (with an enabled operator, as the resume e2e tests build one): a Task with an ambiguous attempt after a restart; `Mark failed and rerun` leaves the old attempt `resolved(rerun)` decided by the operator session, the Task `running` or `queued` on a NEW Run (Run index 2, same Task id), and the new Run completes under a succeeding script; Mark failed still gives `abandon` (existing e2e stays green).
5. `gofmt`, `go vet ./...` (also `-tags referencehost`), `go build ./...` clean; runbook and `current-phase.md` updated.

## 6. Out of scope

Relabelling after the fact, healing a crash between (b) and (c), showing a resolved attempt's kind on the page, a rerun action for a cancelled Task, token ceilings, and the 3d to 3f Minors.
