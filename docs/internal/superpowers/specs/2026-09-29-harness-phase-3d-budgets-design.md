# Harness Phase 3d — Budgets Design

- **Date:** 2026-09-29
- **Status:** Draft. Brainstormed with the recommended option taken for each question, per the maintainer's workflow. Revised after the focused spec review (`docs/superpowers/reviews/2026-09-29-harness-phase-3d-spec-review.md`).
- **Governing decisions:** [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md); ADR 0004.
- **Governing spec:** [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md), §5 (`LaunchLimits`, capabilities), §6 (usage normalized by scope) and §13 (budgets).
- **Builds on:**
  - phase 3a: the global wall clock `CENTRAL_HARNESS_WALL_CLOCK` and the terminal `budget_exhausted`;
  - phase 3b: non-success terminals capture artifacts best-effort;
  - phase 3c: a per-Task policy recorded on the Task (migration v31).

## 1. Goal

The operator can bound what one harness Run may spend, per Task. When a Run reaches its bound, it stops through the kill ladder and ends `budget_exhausted` with a reason that names the bound. The task detail page shows the Run's usage against its limits.

| Bound | How it is chosen | Who enforces it |
|---|---|---|
| **Cost** (USD, as the harness reports it) | Per Task at submission. Empty means the serve default. | The harness itself, when the adapter declares support (Claude Code: `--max-budget-usd`). Central adds a backstop for adapters that report usage while the session is still live. |
| **Wall clock** | Per Task at submission. Empty means the serve default. | Central, using the existing 3a timer, now set per Run. |

For a subscription login, the "cost" is Claude Code's own estimate. It works as a proxy for quota use; it is not a charge.

### Non-goals (deferred)

- **Token ceilings.** Claude Code reports tokens only on `result` frames, and in a `-p` Run that is the end of the session, so Central cannot stop a Run midway on tokens. That would need per-message usage parsing with de-duplication by message id, which is a protocol change. Operators reason about cost, and the harness enforces cost mid-run. Tokens are shown, not capped.
- **Attempt-count ceilings and resume-chain arithmetic.** Until 3e adds resume and retries, a Run has exactly one attempt, so a Run's usage is that attempt's usage. How cost adds up across attempts depends on whether a resumed Claude Code process's `total_cost_usd` includes the earlier processes. 3e verifies that live and defines the chain rule then (review T3).
- **Max turns.** Central never counts turns (governing §13), and a native `--max-turns` is not needed for the goal.
- **Workspace-wide or daily spend limits.** These are a different control and need their own spec.

## 2. Findings that shape the design

1. **The Claude Code CLI has a native cost cap.** `claude --help` (2.1.284) lists `--max-budget-usd <amount>` with the note "only works with --print". The adapter already maps the result subtype `error_max_budget_usd` to `Terminal{budget, harness_budget}` (phase 2a).
2. **Usage reaches Central only with the final result.**
   - `onResult` emits `UsageReport` (scope `session_cumulative`, `Estimated: true`) just before the adapter reports the terminal.
   - Central sends one prompt per Run.
   - So for Claude Code, a Central-side cost check can never stop a session midway. It matters only for adapters that report usage while the session is live (review T1).
3. **The wall clock is global.**
   - `OrchestratorConfig.WallClock` defaults to 30m and is set by `CENTRAL_HARNESS_WALL_CLOCK`, which already has a range.
   - At expiry the orchestrator sets `budgetHit`, interrupts, and settles `harness_budget` (`FailureBudget`).
   - That is the same reason the native cost stop produces, so the operator cannot tell which bound fired.
4. **Limits have no native support yet.** `port.LaunchLimits` holds only `MaxTurns`, and no capability declares limit support. Governing §13 says harness-native limits are passed only when the adapter declares them.
5. **The submit form is unreachable after the first Task.** It renders only while the task list is empty (`tasks_list.html`, `{{if .Empty}}`), so after the first Task no Task can be submitted from the UI. This predates 3c, and it blocks every budget field (review P1).
6. **3c set the pattern for per-Task settings:**
   - the value lives in the task domain;
   - it is stored in a Task column (with a migration);
   - Rerun copies it explicitly;
   - `ClaimedRun` carries it.

## 3. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Which bounds? | Cost and wall clock per Task (§1). Tokens and attempts are deferred, with reasons (§1 non-goals). | These are the bounds that can be enforced mid-run today. |
| 2 | Where are the limits recorded? | Migration v32 records the **requested** limits on the Task and the **effective** limits on the attempt.<br>**Task:**<br>• nullable columns `budget_cost_micro_usd bigint` (10,000 to 1,000,000,000, i.e. US$0.01 to US$1,000) and `budget_wall_clock_seconds integer` (60 to 86,400). NULL means "use the serve default";<br>• `task.SubmitTaskRequest` gains `Budget{CostMicroUSD, WallClockSeconds}`, whose zero value means NULL;<br>• the task domain validates the ranges;<br>• the values never change: a Retry keeps them, and a Rerun copies them explicitly.<br>**Attempt:**<br>• `harness_attempts` gains `budget_cost_micro_usd bigint NOT NULL`, `budget_wall_clock_seconds integer NOT NULL`, and the flags `budget_cost_defaulted` and `budget_wall_clock_defaulted` (`boolean NOT NULL`), written at `prepared` with the resolved values;<br>• the migration backfills existing rows with the pre-3d defaults: cost = the new default, wall clock = 1800 s, both flagged as defaulted;<br>• `harness.Attempt` gains `Budget{CostMicroUSD, WallClock, CostDefaulted, WallClockDefaulted}`, which cannot change after prepare. | The Task records what the operator asked for. The attempt records what the Run actually ran under, so a later change to the serve defaults never rewrites history (review T2). |
| 3 | Serve defaults? | • New `CENTRAL_HARNESS_MAX_COST_USD`: a decimal with at most 2 places, default **5.00**, range 0.01–1000.<br>• Out of range while harness execution is enabled: serve refuses to start. While execution is disabled, the variable is ignored, like every harness variable.<br>• `CENTRAL_HARNESS_WALL_CLOCK` keeps its default (30m) and its existing range. | There is always a cost bound, so no Run is unbounded. The default is conservative. |
| 4 | Effective limits? | 1. At claim, the lifecycle resolves the Task's requested values against the serve defaults into `ClaimedRun.Budget`.<br>2. At `prepared`, the orchestrator writes that budget on the attempt (decision 2).<br>3. From then on it uses only the attempt's recorded budget: the wall clock arms the timer (replacing `cfg.WallClock`), and the cost goes to the adapter when the adapter declares support. | One tested resolution point, recorded before launch. |
| 5 | Native cost cap? | **Port:** `Capabilities` gains `NativeCostLimit bool`, and `LaunchLimits` gains `MaxCostMicroUSD int64`. `StartSpec.Validate` refuses a negative value, as it does for `MaxTurns`.<br>**Orchestrator:** passes a positive value only when `adapter.Capabilities().NativeCostLimit` is true. An adapter that does not declare the capability refuses a positive value in `Start`.<br>**claudecode:** declares the capability and appends `--max-budget-usd <amount>` to its closed argv. The amount is micro-USD formatted as a plain decimal with 2 places, and the argv builder validates it. | Governing §13: limits are "passed only when the adapter declares them". The harness stops itself between API calls, which is the cheapest stop. |
| 6 | Central backstop, and how outcomes are labelled? | **Backstop:** on every applied `UsageReport` whose cumulative `CostMicroUSD` is at or above the limit, **while no terminal has been reported yet**, the orchestrator records the first budget cause and takes the existing stop path. The cause is `budgetCause`, an enum (`none`, `wall_clock`, `cost`) that replaces the `budgetHit` bool.<br>**Outcome rules,** applied by `budgeted()`:<br>1. A terminal the adapter reported as `budget` keeps its own reason (`harness_budget`).<br>2. A `succeeded` terminal stays succeeded. The usage above the limit is recorded, and task detail marks it "over the limit".<br>3. Any other terminal is relabelled `budget_cost` or `budget_wall_clock` **only when Central's stop caused it**, meaning it is `interrupted` or `killed`, or `failed` after Central sent its interrupt. A harness failure that happened on its own keeps its reason.<br>**Interrupt:** `interrupt()` treats `ErrSessionEnded` (the session has already seen its result) as a no-op, never as a kill, so a process that is exiting cleanly is not killed. | Defence in depth for adapters that report usage while live. It never mislabels a harness's own stop or failure, and never turns a success into a failure (review T1). For Claude Code, the native cap does the stopping. |
| 7 | Reasons? | Three bounded reasons, so the operator can tell which bound fired. Each is a new `harnessapp` failure code and a new execution `FailureReason`:<br>• `budget_wall_clock`: Central's timer. It replaces the 3a use of `harness_budget` for the wall clock;<br>• `budget_cost`: Central's backstop;<br>• `harness_budget`: the harness stopped itself (`error_max_budget_usd`). Its meaning is unchanged, and it stays the fallback of `settlementFor` for a budget state without a reason.<br>In all three cases the attempt's terminal status is `budget`, and `Terminal.Reason` holds the code. | The reason names the bound. The vocabulary is fixed, with no free text. |
| 8 | Run usage? | A Run's usage is the scope-normalized `Usage` of its single attempt, since 3d has one attempt per Run. The chain rule is deferred to 3e (§1 non-goals). | No rule is frozen before the behaviour it depends on is verified (review T3). |
| 9 | What does the operator see? | **Submit form** (while harness execution is enabled):<br>• "Cost limit (USD)" and "Wall clock (minutes)", both optional, with the serve defaults as placeholders;<br>• the note "For a subscription login the cost is Claude Code's own estimate, a proxy for quota use, not a charge.";<br>• a malformed or out-of-range value gives 400.<br>**Task detail** (for a harness Run):<br>• the attempt's recorded limits, marked "(default)" when inherited;<br>• the usage: tokens in, tokens out, cache read, cache write and cost. It shows "estimated" when the harness says so, and "over the limit" when a successful Run exceeded its limit. Usage updates when the harness reports it, which for Claude Code is at the end of the Run;<br>• on a budget stop, the reason in words:<br>&nbsp;&nbsp;– `harness_budget`: "The harness stopped at its budget limit" (neutral, because before 3d this reason also covered the wall clock);<br>&nbsp;&nbsp;– `budget_cost`: "Central stopped the Run: the reported cost reached the limit";<br>&nbsp;&nbsp;– `budget_wall_clock`: "Central stopped the Run: the wall clock limit was reached". | The operator sees the spend and exactly which bound stopped a Run. The estimate caveat appears where the choice is made (review P2 and the product Minor). |
| 10 | Artifacts on a budget stop? | Unchanged from 3b: a non-success terminal captures patch and commits best-effort, and the Run fails with the budget reason. | The partial work stays inspectable. |
| 11 | The submit form bug? | Fixed in 3d: the task list always renders the submit form, above the list, not only while the list is empty. | Without this fix, no second Task can be submitted, so after first use no budget field (and no 3c policy field) is reachable (review P1). |

## 4. Data flow

1. **Submit:** the Task stores the requested budget (or NULL).
2. **Claim:** the lifecycle resolves the effective budget into `ClaimedRun.Budget`.
3. **Prepare:** the attempt records the effective budget.
4. **Launch:**
   - `StartSpec.Limits.MaxCostMicroUSD` is set, because `claudecode` declares `NativeCostLimit`, so `--max-budget-usd` is in the argv;
   - the wall-clock timer is armed from the attempt's budget.
5. **Native stop** (the Claude Code path):
   - the harness ends with `result error_max_budget_usd`;
   - the adapter reports `UsageReport`, then `Terminal{budget, harness_budget}`;
   - rule 1 keeps that reason, and the Run settles `harness_budget`.
6. **Backstop** (adapters that report usage while live):
   - a usage report at or over the limit arrives before any terminal;
   - the orchestrator takes the stop path, and the session ends interrupted or killed;
   - rule 3 applies, and the Run settles `budget_cost`.
7. **Wall clock:** expiry triggers the stop path, and the Run settles `budget_wall_clock` (rule 3).
8. **Success over the limit:** a successful result whose reported cost exceeds the limit stays a success (rule 2). Task detail marks it "over the limit".

## 5. Errors

| Situation | Behaviour |
|---|---|
| The adapter does not declare `NativeCostLimit` | No native limit is passed. Only the backstop applies. |
| The harness overshoots its own cap (it checks between API calls) | The native terminal stands (rule 1). The runbook states that a Run can exceed its limit by about one API call, and that a successful Run can finish above it (rule 2). |
| A harness failure reports a cost over the limit, e.g. an API error on the last call | It keeps its own reason, because Central did not stop it (rule 3). |
| Usage is never reported (the harness dies early) | Only the wall clock bounds the Run, as in 3a. |
| A config value is malformed or out of range | Serve refuses to start while the harness is enabled. |
| The budget is hit while a permission request is pending (3c) | The existing D13 path: stop answering, and supersede through the terminal write. |

## 6. Security

- The budget values are numbers, validated in the domain and in the form. They reach the argv only through the closed builder (a fixed flag and a formatted decimal), so no value can inject a flag.
- There are no new routes. The submit form keeps its CSRF, Origin and session checks.
- The credentials rule is unchanged: Central never reads the harness's billing or login. It only reads the cost the harness reports.

## 7. Testing

- **Domain:**
  - budget range validation;
  - Rerun copies the budget and Retry keeps it;
  - the attempt's budget is set once at prepare and cannot change after;
  - the `budgeted()` outcome rules 1–3 as a table test: a native budget stop is kept, a success is kept, an interrupted or killed terminal is relabelled, and a harness's own failure is kept.
- **Migration v32:**
  - apply, re-apply, the inspector and the check constraints;
  - the Task columns allow NULL;
  - the attempt columns are backfilled for existing rows.
- **Stores (live PostgreSQL):**
  - the Task budget round-trips on write and on every task read;
  - the execution store's `readTask` carries it;
  - the attempt budget round-trips and cannot change after prepare.
- **Adapter:**
  - the argv contains `--max-budget-usd 2.50` for 2,500,000 micro-USD;
  - formatting is exact at the boundaries (0.01 and 1000.00);
  - without a limit the flag is absent;
  - an adapter without the capability refuses a limit.
- **Orchestrator** (fake adapter, fake clock):
  - the attempt's wall clock is used instead of the config one;
  - a live usage report at the limit stops the session and yields `budget_cost`;
  - a usage report followed by a native budget terminal yields `harness_budget`;
  - a success over the limit stays succeeded;
  - the wall clock yields `budget_wall_clock`;
  - `interrupt()` does not kill on `ErrSessionEnded`;
  - a limit is passed only with the capability.
- **cmd/central:**
  - config bounds and defaults;
  - resolution (Task value first, then the default), recorded on the attempt;
  - the failure-reason mapping;
  - e2e with fake claude:
    - a live usage report over the limit, then a wait, ends the Task failed `budget_cost`, with patch and commits captured best-effort;
    - a native budget terminal ends it failed `harness_budget`.
- **Web:**
  - the submit form renders when the task list is not empty;
  - the form fields and their validation (400s), and the subscription note;
  - task detail shows the attempt's limits with "(default)", usage with "estimated" and "over the limit", and the three budget reason texts.
- **Live claude** (optional, `CENTRAL_TEST_CLAUDE=1`): run with `--max-budget-usd 0.01` and a prompt that needs two tool calls. The result must be `error_max_budget_usd`. It costs about US$0.02.

## 8. Plan-stage checks

1. **The native cap on the pinned version.** Verify on the pinned 2.1.283 (and on the installed 2.1.284) that:
   - `--max-budget-usd` is accepted with the adapter's argv;
   - it works under a subscription login;
   - exhausting it yields `result` `error_max_budget_usd`.

   One live run at a 0.01 limit is enough.
2. **The amount format** that `--max-budget-usd` accepts, e.g. the decimal string `2.50`.
3. **Every place that uses `cfg.WallClock`, or `FailureBudget` for the wall clock,** moves to the attempt's value or to `budget_wall_clock`. That covers the timer and `budgeted` in `orchestrator.go`, `harness_composition.go`, the runbook, and the 3a/3c tests that expect `harness_budget` for the wall clock.
4. **The migration v32 gate** follows the v31 pattern: the b08 record count, and the inspector chain.

## 9. Acceptance

1. A Task submitted with a cost limit of US$0.50 runs Claude Code with `--max-budget-usd 0.50`. When Claude Code stops at the limit, the Task fails `harness_budget`, and task detail says "The harness stopped at its budget limit". `budget_cost` is reachable only for adapters that report usage while live; it is verified with the fake adapter.
2. A Task with a 2-minute wall clock is stopped at 2 minutes and fails `budget_wall_clock`.
3. A Task submitted without limits uses the serve defaults, recorded on the attempt. Task detail marks them "(default)", and changing the serve default later does not change what that page shows.
4. The submit form is still shown when the list holds at least one Task.
5. Task detail shows the Run's reported tokens and cost. It marks them "estimated" when the harness says so, and "over the limit" when a successful Run exceeded its limit.
6. The full portable suite passes, apart from the known `internal/recovery` failure, and the touched packages pass against live PostgreSQL.

## 10. Plan-stage findings (verified draft, 2026-09-29)

These take precedence over the decisions above where they differ.

1. **Checks 1 and 2 (live, claude 2.1.284).** A run with a cost cap below the price of one API call ended with `result` `error_max_budget_usd` after one turn, with a reported `total_cost_usd` of about US$0.36, well above the cap: the harness stops between API calls, so a Run can exceed its limit by one call. `--max-budget-usd 0.01` (a two-place decimal) is accepted.
2. **Cost formatting (decision 5).** `formatCostUSD` renders micro-USD as `<dollars>.<cents>` and rounds **down** to the cent, so the limit the harness enforces is never above the recorded one (2,509,999 micro-USD becomes `2.50`).
3. **Names in code.**
   - The spec's `LaunchLimits` is `port.Limits`, and it gains `MaxCostMicroUSD`.
   - The attempt's budget is `harness.Budget` on `harness.Attempt` and on `harness.PrepareInput`.
   - The port gains the sentinel `port.ErrSessionEnded`, wrapped by the claudecode and fake adapters.
   - The web reads are `harnessOperator.RunBudget` and `BudgetDefaults`, backed by `Store.LatestAttemptForRun`.
4. **Resolution (decisions 3 and 4).** `harnessLifecycle.harnessBudget` resolves the Task's requested values against the serve defaults (`harnessBudgetDefaults`). `Orchestrator.effectiveBudget` is a second fallback for constructors and tests that claim a Run without a budget: it fills an unset bound with `DefaultMaxCostMicroUSD` (US$5) or `cfg.WallClock`, flagged as defaulted, so the attempt always records a complete budget.
5. **Outcome rule 3 and the ended session (decision 6).** A `failed` terminal is relabelled only when Central's interrupt reached a live session (`interruptSent`) or Central killed it. `interrupt()` on `ErrSessionEnded` sends no interrupt and kills nothing at once, **but it still arms the grace timer**: a process that hangs after its result (a child holding stdout open) must be reaped, or the Run would keep its lease and slot for ever (plan review P-T2). That late kill sets `stopAfterEnd` and does not count as Central's stop for rule 3 when the terminal is a harness result (failed); a `killed` terminal, which is Central's own, is still relabelled. This replaces "never a kill" in decision 6.
6. **The backstop** (`costReached`) considers only an applied `UsageReport`, only while no terminal has been reported and no budget cause is recorded yet.
7. **Verification.** T2–T8 were each verified in isolation with live PostgreSQL. RED signatures are compile failures, except Task 4, whose RED is the assertion `Save with a changed wall clock defaulted: err = <nil>, want ErrInvalidAttempt`.
8. **The launcher grammar (plan review P-T1, Critical).** The launcher daemon (`cmd/central-harness-launcherd/policy.c`, `claude_argv_kind`) refuses any argv outside its closed grammar, so it would have refused `--max-budget-usd` and failed every Run at launch. The grammar now accepts an optional `--max-budget-usd <amount>` pair after the optional `--model` pair: exactly `<1-4 digits>.<2 digits>`, from 0.01 to 1000.00, once, with nothing after it. `test_launcher.py` covers accepted and refused forms. The launcher and serve must be installed together; the runbook says so.
9. **Wording and upgrade notes (plan review P-O1, P-O3, P-O5).** `harness_budget` is described neutrally on task detail and in the runbook. A budget stop shows the words with the code as a hint instead of a bare "Failure:" line. Runbook §4b has an "Upgrading to phase 3d" list: the default cap, the reason rename, the one-way migration with its backfill (limits that were not enforced on earlier Runs), and the installation order.
