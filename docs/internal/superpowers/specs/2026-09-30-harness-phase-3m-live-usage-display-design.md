# ADR 0035 harness phase 3m: do not show placeholder cost while usage is live

Date: 2026-09-30. Follows phase 3l (PR #21, `cd4fb99`). No migration.

## 1. Problem

Since phase 3l the Claude Code adapter reports tokens while a Run is live. Task detail decides "usage was reported" from any non-zero usage row (`UsageReported` in `harnessOperator.RunBudget`), so the first live report switches the page from "No usage reported yet." to the full usage list, which then shows `Cache read 0` and `Cost US$0.00 (estimated)` as if they were real. They are placeholders: Claude Code reports cost and cache reads only with its final result. An attempt that ends without a result (Central killed it after the grace, a `budget_tokens` stop included, or it was left ambiguous) keeps showing US$0.00 for good although it may have spent money. Found by the phase 3l final review and documented there as a known limit.

Goal: the page never presents a placeholder as spend.

## 2. Decisions

| # | Topic | Decision | Why |
|---|---|---|---|
| 1 | When cost is "reported" | `RunBudget` computes `CostReported`: true when any attempt of the Run's chain has `CostMicroUSD > 0` or `CacheRead > 0`, or the latest attempt is `succeeded` (a succeeded attempt always received its result, so a real zero stays a real zero). | A live report carries cost 0 and cache read 0; a result carries them. Non-zero cost or cache read therefore proves a result arrived, and success proves it too. |
| 2 | Also expose `Ended` | `RunBudget` also reports `Ended`: the latest attempt (the one the existing `latest` logic picks) is in a terminal state (`State.IsTerminal()`: succeeded, failed, interrupted, killed, budget_exhausted, resolved) or is `ambiguous` (which `IsTerminal` excludes). `Ended` looks at the latest attempt only, `CostReported` at every attempt of the chain: an earlier attempt's result is real spend and keeps the cost shown. | Tells "still running" from "ended without a result". |
| 3 | Page | Tokens in, tokens out and cache write stay as they are. When `CostReported` is true the page is unchanged (Cache read and Cost lines as today). When it is false the Cache read line is not shown and the Cost line reads `not reported yet (Claude Code reports cost and cache reads with each result)` while the Run is not `Ended`, and `not reported (Claude Code sent no cost or cache reads before the attempt ended)` once it is. The second wording is deliberately about what was received, not about why the attempt ended: an error result is also a result and can legitimately carry cost 0 and cache read 0. No cost figure, no "(across N attempts)", no "(estimated)" and no "over the limit" marker appears in the not-reported case. | The placeholder disappears and the cause is named; the limit and wall clock lines above are untouched. |
| 4 | Data unchanged | Nothing is recorded or computed differently: the chain rule, the Task cost cap, the resume budget and the stored usage are unchanged. `UsageReported` keeps its meaning (some usage exists) and the empty-usage text stays. | Display only. |
| 5 | Docs | Runbook §4b (`docs/operations/harness-execution.md` around lines 175 and 471) and the phase 3l upgrade note: replace the "placeholders" caveat by the new behaviour (the page says "not reported"); the under-count of the chain rule and the Task cap for an attempt without a result stays documented. `docs/implementation/current-phase.md` one line. | Operator-facing behaviour. |

## 3. Data flow

`harnessOperator.RunBudget` (cmd/central) folds the chain's attempts as today and sets the two new fields on `web.HarnessRunBudget`; `buildRunBudget` (web/budget_view.go) carries them into the view; the `tasks_detail.html` usage block branches on them.

## 4. Errors

None new: a read error keeps today's behaviour (the Budget section is omitted).

## 5. Acceptance

1. Operator unit tests (the fake harness store): tokens-only usage on a running attempt gives `CostReported` false and `Ended` false; a result-shaped usage (cost above 0, or cache read above 0) gives `CostReported` true; a `succeeded` attempt with cost 0 and cache read 0 gives `CostReported` true; a `failed`, `interrupted`, `killed`, `budget_exhausted` or `ambiguous` attempt with tokens only gives `CostReported` false and `Ended` true; a chain where an earlier attempt has a result and the latest has tokens only gives `CostReported` true.
2. Web tests: the four page outcomes (no usage: "No usage reported yet."; tokens only while live: the two texts as specified, no `Cache read`, no `Cost US$`, no "estimated"; ended without a result; full usage: unchanged lines) the strings are pinned. The existing tests that build `web.HarnessRunBudget` literals or compare `RunBudget` results as structs are updated for the new fields (`CostReported: true`, and `Ended` where compared): `internal/transport/http/gintransport/web/handler_budget_test.go` (five literals), `cmd/central/harness_budget_test.go` and `cmd/central/harness_resume_test.go` (struct equality); every other assertion stays as it is.
3. Live e2e is not needed: no SQL or dispatch change; the operator tests cover the fold.
4. `gofmt`, `go vet ./...` (also `-tags referencehost`), `go build ./...` clean; runbook and `current-phase.md` updated.

## 6. Out of scope

Showing a cost estimate from tokens, recording cost per message, changing how the chain rule or the Task cap count an attempt without a result, and the overview list.
