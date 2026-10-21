# Harness Phase 3f — Recovery Epoch Resume and Prepared-Successor Cancel Design

- **Date:** 2026-09-29
- **Status:** Draft. Brainstormed with the recommended option taken for each question, per the maintainer's workflow. Revised after the focused spec review (`docs/superpowers/reviews/2026-09-29-harness-phase-3f-spec-review.md`).
- **Governing decisions:** [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md); [ADR 0036](../../../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md); the B08 recovery design (recovery epochs, the fenced coordinator lease, quarantine).
- **Governing spec:** [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md), §7 and §8.
- **Builds on:** phase 3e (its follow-ups: "no operator resume for a degraded epoch" and "a cancel on a prepared successor shows a bare Settling until the next start").
- **Investigation:** facts below come from a read-only investigation of the code at `8b4f63a`.

## 1. Goal and decomposition

3e's non-goals and follow-ups name four items for 3f. They are two different kinds of work:

| Sub-phase | Delivers |
|---|---|
| **3f (this spec)** | Two repairs of stuck states, with one named execution-domain change (decision 8):<br>• an operator can resume a **degraded recovery epoch**, so a Workspace that an older release quarantined is dispatchable again;<br>• an operator can finish a **cancel on a prepared successor** (a Task `cancelling` whose current attempt was never invoked) without waiting for the next serve start. |
| 3g | **Resume of an ambiguous attempt** with Claude Code `--resume`, the attempt-count ceiling and the resume-chain cost rule. It needs new execution-domain commands, a live check of `--resume` on the pinned claude, and a rule for `total_cost_usd` across a chain. |

### Non-goals

- **Resuming an ambiguous attempt.** The investigation found no execution path that creates a second StepAttempt for a Run after an operator resolves an ambiguous one (`ResolveReconciliation` has only `confirm_succeeded`, `confirm_failed` and `cancel`; `StartHarnessRun` refuses an existing Step). That is 3g.
- **An attempt-count ceiling and the chain cost rule.** They have no home until 3g creates a second attempt for a Run.
- **A web button for the epoch resume.** A resume reopens every quarantined Workspace of the epoch, so it is not a Workspace operator's authority.
- **Changing B08's sticky rule.** A degraded epoch still stays degraded until the fenced, operator-acknowledged resume.
- **A new CLI verb.** No existing verb opens PostgreSQL, and a CLI cannot hold the coordinator lease while a live serve renews it.

## 2. Findings that shape the design

1. **The resume command exists and is complete.** `execution.ResumeRecoveryEpochCommand` → `RecoveryCoordinator.ResumeEpoch` → `Store.ResumeRecoveryEpoch` (`internal/adapter/postgres/execution/store.go`) requeues every `failed` Workspace row of the epoch (`retry_attempt+1`), sets the epoch `running`, writes one `execution.recovery.resumed` event, an outbox row and an idempotency receipt, in one transaction. It needs `CapabilityWorkspaceOperator` and `CapabilityRecoveryCoordinator`, the epoch's current fence, and the expected state, cursor and retry attempt. No production code calls it; only tests do.
2. **The coordinator lease is the obstacle for a CLI.** `ResumeEpoch` acquires the lease for its own instance id and requires the command's fence to equal the lease's. Serve uses a random per-process instance id and renews the lease, so an outside process gets `STALE_RECOVERY_FENCE` while serve runs.
3. **Serve already holds the lease at exactly the right moment.** `serveRecoveryPreflight.RunForServe` calls `runServingRecoveryEpoch` (which returns the taken-over epoch, `degraded` for a quarantined Workspace) and then `runGateSteps`, whose first step is `runRecoveryToCompletion`. A resume between the two runs under serve's own fence, and the same start then drains the requeued Workspaces.
4. **`/health` does not expose the recovery epoch** (`kernel.MarshalHealth` emits only status, reason, remediation and failure class; the recovery generation and retry count live only in the in-process snapshot of `cmd/central/serve_monitors.go`). The operator finds what to acknowledge in serve's log hint line (decision 7) and in `SELECT epoch_generation, state, retry_attempt FROM central.recovery_epochs ORDER BY epoch_generation DESC LIMIT 1;` (`degraded` or `failed` means quarantined).
5. **A prepared successor of a `cancelling` Task never reaches the dispatcher** (`queryListDispatchableRuns` lists prepared successors only for `running` Tasks), so the only settler is the next start's B08 scan (3e decision 5).
6. **`execution.Cancel` cannot serve an operator as it stands.** `Service.Cancel` (`CapabilityWorkspaceOperator`) settles a **prepared** attempt of a `cancelling` Task in one commit (attempt and Step `cancelled`, then `task.ExecutionSettleCancellationRequest`), and an invoked or settling attempt gets `RECONCILIATION_REQUIRED`. But `evaluateCancel` (`internal/execution/domain.go` ~3749) takes the fenced-release branch whenever an ownership row exists, expired or not, and the store always loads that row (lease release expires the row, it never deletes it). The operator holds no lease credential, so every operator cancel of a once-leased Run returns `STALE_LEASE_FENCE`. `evaluateResolveReconciliation` already has the right rule (~4043: only an **unexpired** lease takes the fenced branch, otherwise the no-active-lease assertion). `execution.Cancel` has no production caller.
7. **The harness row of a prepared successor may not exist.** The orchestrator creates the harness attempt row only after a claim, so a successor cancelled before any re-claim has none. Where a row exists, the mapping "prepared row plus cancelled StepAttempt to `failed(harness_not_launched)`" (`FailUnlaunched`) runs today only inside the full startup reconciler pass; `Resolver.ResolveAbandon` (`internal/harness/app/reconciler.go`) is the single-attempt precedent for the ambiguous case.

## 3. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Split? | 3f as in §1; resume of an ambiguous attempt, the attempt ceiling and the chain cost rule move to 3g. | The two repairs need no new execution semantics and no live claude check; resume is a different risk class. |
| 2 | Where does the epoch resume run? | **Inside serve's startup gate**, driven by an operator acknowledgment in the environment. Not a CLI, not a web action. | Serve holds the lease and the fence, so there is no contention and no new database credential path. A resume is a deployment-level act, like `CENTRAL_HARNESS_ENABLED`; it is not a Workspace operator's authority. |
| 3 | What is the acknowledgment? | Two variables, set together: `CENTRAL_RECOVERY_RESUME=<generation>:<retry_attempt>` (the values in the serve log hint line, or the `epoch_generation` and `retry_attempt` columns of `central.recovery_epochs`, for the degraded epoch) and `CENTRAL_RECOVERY_RESUME_REASON=<text>` (1–500 characters, no control characters). One without the other, a malformed value, or a blank reason makes serve refuse to start with a configuration error. | The value names the exact state the operator looked at. After a successful resume the epoch's `retry_attempt` is higher, so a variable left in place is stale and does nothing; it can never resume a later, different degradation without a new operator decision. |
| 4 | When does serve act on it? | Between `runServingRecoveryEpoch` and `runGateSteps`. If the epoch is `degraded` or `failed` **and** its generation and retry attempt equal the acknowledged pair, serve builds `ResumeRecoveryEpochCommand` and calls `ResumeEpoch`. Otherwise it does nothing except log why (`recovery resume not applied: epoch is <state> at <gen>:<retry>`). The start then continues as today, so a resumed epoch is drained by `runRecoveryToCompletion` in the same start. | It reuses the audited command and the existing drain, and a wrong acknowledgment is harmless. |
| 5 | Command details | Scope principal `serve:recovery-resume-ack` (unless the plan finds an established convention for serve-internal principals) with `CapabilityWorkspaceOperator` and `CapabilityRecoveryCoordinator` and **no** Executor or Approver capability; the command's own `Capability` is `CapabilityRecoveryCoordinator` (`ResumeRecoveryEpochCommand.Validate` requires all three). `ExpectedState`, `ExpectedCursor` and `ExpectedRetryAttempt` come from the epoch serve just took over; idempotency key `recovery-resume:<generation>:<retry_attempt>`; fingerprint by `RecoveryResumeFingerprint`. The audit event is written under the **lowest `workspace_id` among the epoch's `failed` rows** (a new read-only store method, `ListFailedRecoveryWorkspaces(ctx, epochGeneration, limit)`). The requeue clears each row's `failure_class` and `failure_reason`, so the durable trail carries the set: the stored `AcknowledgementReason` is the operator's text followed by `[workspaces: <id>,<id>,... (+N more)]` with at most 50 ids, built deterministically (ascending order) so the fingerprint is stable, and serve logs the same list. | The resume is epoch-wide, but the command carries one Workspace scope for its event and receipt. Putting the affected set in the acknowledgment keeps the act reviewable after the failure fields are cleared. |
| 6 | Failure handling | After a successful resume the gate continues with the epoch that `ResumeEpoch` returns (not the one taken over before it), so the recovery monitor shows the new state. `RECOVERY_RESUME_EXPECTATION_CONFLICT` and `RECOVERY_EPOCH_NOT_RESUMABLE`: log, continue as a degraded start with the taken-over epoch. Any other error, including a stale fence: fail the start with `RECOVERY_FAILED`, as every other recovery error does. | A refused acknowledgment must not stop a serve that can run degraded; an unexpected error is fail-closed. |
| 7 | Discoverability | When serve starts with a `degraded`/`failed` epoch and no applicable acknowledgment, it logs one line with the exact value to set: `recovery epoch <gen> is degraded; to resume set CENTRAL_RECOVERY_RESUME=<gen>:<retry> and CENTRAL_RECOVERY_RESUME_REASON=...`. The runbook's upgrade section replaces "ask the maintainer" with the procedure. | The operator does not have to derive the pair. |
| 8 | Settling a cancel on a prepared successor | A new operator method `harnessOperator.SettlePrepared` calls `execution.Service.Cancel` for a Task `cancelling` whose linked StepAttempt is `prepared`. **Named execution-domain change:** `evaluateCancel` takes the fenced-release branch only for an **unexpired** lease (the rule `evaluateResolveReconciliation` already uses) and otherwise the no-active-lease assertion; an unexpired lease still needs the executor's credential, so an executor's cancel is unchanged and an operator cannot cancel under a live lease. The detail page shows the existing **"Finish cancelling"** button for it, posting to the cancel route; the handler picks `CancelUnclaimedTask` for an unclaimed Run (unchanged), `SettlePrepared` for any `cancelling` Task whose Run was claimed (`RequestCancellation` refuses every `cancelling` Task, so nothing else can apply; a refusal of `SettlePrepared` keeps today's 409), and `RequestCancellation` for the other statuses. Nothing was invoked, so no attestation is needed. | It reuses the tested domain command instead of waiting for a restart, one click, one commit; the lease rule is the one already proven for the resolve action. |
| 9 | What if a lease is live on the prepared attempt? | Only an **unexpired** lease refuses the settle (`STALE_LEASE_FENCE` from the fenced branch); the route maps that refusal (`STALE_LEASE_FENCE`, and the store's `ACTIVE_LEASE_CONFLICT` for the same state, and a pre-read that sees a live lease) to 409 "The harness is still starting. Try again in a moment." An expired or absent ownership row settles. | The dispatcher may be claiming it; a released lease is the normal state of a successor and must not look busy. |
| 10 | The harness attempt row | The page predicate and `SettlePrepared` key on **execution state only** (Task `cancelling`, StepAttempt `prepared`, no unexpired lease), never on a harness row. After the execution commit, a new single-attempt method on the harness `Resolver` (modelled on `ResolveAbandon`) runs `FailUnlaunched` for the attempt **if a harness row exists** and does nothing otherwise. If that write fails after the commit, the Task is already `cancelled`; the next start's reconciler applies the same mapping. | A successor cancelled before any re-claim has no row; a row that exists would otherwise stay `prepared`, which the one-live-attempt-per-Run index counts as live. |
| 11 | The acknowledgment text | The reason must be 1 to 500 characters of printable Unicode: any character in category Cc or Cf, and U+2028 and U+2029, is refused. It is logged with `%q`. The runbook says it is stored in the event and outbox (retained like any event), so it must not contain secrets. | It is operator prose that ends in logs and durable rows. |

## 4. Data flow

**Epoch resume:**
1. An older release degraded the epoch. `central.recovery_epochs` shows `epoch_generation=7`, `state=degraded`, `retry_attempt=2`. Serve's log line names the two variables.
2. The operator sets `CENTRAL_RECOVERY_RESUME=7:2` and a reason, and restarts serve.
3. At the gate, serve takes the epoch over (still `degraded`), matches `7:2`, and calls `ResumeEpoch` under its own fence. The failed Workspace rows become `pending` with `retry_attempt=3`; the epoch is `running`.
4. `runRecoveryToCompletion` drains it. The fixed scan clears the `scan_error` rows, the epoch completes, and the Workspace's older Runs are claimable again.
5. The operator removes the two variables at leisure. If serve restarts first, `7:2` no longer matches and nothing happens.

**Cancel on a prepared successor:** the operator opens the Task page (`cancelling`, StepAttempt `prepared`), presses "Finish cancelling", and `execution.Cancel` commits attempt, Step, Task and Run `cancelled`; the harness row becomes `failed(harness_not_launched)`; Rerun appears.

## 5. Errors

| Situation | Behaviour |
|---|---|
| Only one of the two variables, malformed pair, blank or too-long reason | Serve refuses to start (configuration error naming the variable). |
| Epoch is not `degraded`/`failed`, or the pair differs | No resume; a log line says why; the start continues. |
| `ResumeEpoch` raises `RECOVERY_RESUME_EXPECTATION_CONFLICT` or `RECOVERY_EPOCH_NOT_RESUMABLE` | Log, continue degraded. |
| `ResumeEpoch` raises anything else | The start fails with `RECOVERY_FAILED`. |
| The resumed scan fails again for a Workspace | The epoch degrades again with a higher `retry_attempt`; the old acknowledgment is stale, and serve logs the new value to set. |
| Two "Finish cancelling" clicks on a prepared successor | The second replays or shows "Already cancelled.", as in 3e. |
| The prepared attempt's ownership row is expired (the normal state of a successor) | The settle proceeds (decision 8). |
| The harness-row write fails after the execution commit | The Task is `cancelled`; the next start's reconciler finishes the row. |
| The prepared attempt is invoked meanwhile | `execution.Cancel` returns `RECONCILIATION_REQUIRED`; the route answers the generic 409 and the page shows "Settling". The resolve panel (3e) appears only once the attempt is in `reconciliation`, that is after the next restart. The runbook says so. |

## 6. Security

- The resume is an operator-configured act of the deployment, not reachable from the web or from any harness principal. It uses the existing capability check, fence, idempotency receipt and fingerprint.
- The acknowledgment binds to a generation and retry attempt, so a stale variable cannot approve a later degradation. It is not bound to the database: the runbook says to remove both variables after the resumed start, and that a restore or a changed DSN makes a leftover pair applicable again if the numbers match. A downgrade to 3e ignores the variables.
- The safety of the resume rests on the B08 invariant, not on the acknowledgment: a Run becomes claimable only after the rescan of its Workspace succeeds and the harness reconcile has run, both before serve accepts traffic. A rescan that fails again re-degrades the epoch.
- `SettlePrepared` uses only `CapabilityWorkspaceOperator` through the existing service, requires the same prelude as the 3a resolve action (Origin, session CSRF, active session, claimability gate), and can act only on an attempt that was never invoked.
- Nothing in 3f weakens a quarantine: a start without a matching acknowledgment behaves exactly as before.
- The reason text is logged and stored as the acknowledgment; it must not contain secrets, and the runbook says so.

## 7. Testing

- **Config:** table test for the two variables (both, one, malformed, blank reason, 501 characters, control character, valid).
- **Serve gate (unit, fake coordinator):** matching pair calls `ResumeEpoch` once with the built command (principal, capabilities, expected values, key, the reason with the workspace list and its 50-id cap); wrong generation, wrong retry attempt and a `running`/`completed` epoch do not; the two conflict failures continue with the taken-over epoch; another failure returns `RECOVERY_FAILED`; after a success the gate uses the returned epoch; the discoverability log line.
- **Postgres store (live, isolated DB):** `ListFailedRecoveryWorkspaces` returns the failed rows in ascending order and respects the limit; the audit event lands under the lowest failed Workspace.
- **B08 (live, Architecture mode):** the 3e scenario end to end through the serve gate rather than by hand: a Workspace degraded by an old-behaviour Task, a plain restart stays quarantined, a restart with the matching acknowledgment completes the epoch, clears `scan_error`, and makes the older queued Run dispatchable; a second restart with the variables still set is a no-op; a rescan that fails again re-degrades the epoch at a higher `retry_attempt`, the stale pair does nothing, and the Run stays quarantined.
- **Execution domain (`evaluateCancel`):** an unexpired lease with no credential is refused (`STALE_LEASE_FENCE`); an expired row and an absent row settle through the no-active-lease assertion; an executor with a valid credential still releases the lease as before; the existing `Cancel` tests pass.
- **Prepared cancel (live):** `SettlePrepared` refuses an invoked, settling, reconciling or `running` Task and a mismatched aggregate; succeeds for a prepared successor whose ownership row was expired by recovery and for a plain prepared attempt; an unexpired lease gives the retryable refusal; with a harness row the row ends `failed(harness_not_launched)`, without one nothing is written; both events exist; a stale version conflicts.
- **Web:** the button appears only for that state; the handler picks the right method for unclaimed, prepared and other Tasks; CSRF, Origin, session and claimability tests as the 3a resolve route; the 409 notice.
- **e2e (`cmd/central`, fake claude):** serve stopped with a prepared successor and a cancel on it, "Finish cancelling", Rerun completes; the epoch acknowledgment scenario above.
- **Docs:** runbook §1 ("Settling"), §8 and "Upgrading to phase 3e" (replace "ask the maintainer" with the procedure), a new "Recovery epoch resume" subsection, and `docs/implementation/current-phase.md`.

## 8. Plan-stage checks

1. **B08 recovery design.** Architecture mode: read the recovery design and `queryAcquireRecoveryCoordinator` before touching the gate. The review verified that `ResumeEpoch` re-acquiring for the same instance keeps the fence that `RunEpoch` returned; pin it with a test rather than assume it.
2. **The `AcknowledgementReason` length limit,** if any, and the principal-id convention for serve-internal principals (decisions 5 and 11).
3. **The single-attempt harness method** (decision 10): shape it on `Resolver.ResolveAbandon`, and confirm `FailUnlaunched` accepts the fence of a prepared row. `central_runtime` already has `SELECT` on `recovery_epoch_workspaces` (verified by the review), so no migration is needed.
4. **The web route and `harnessResolvable`:** how to add the prepared-attempt predicate (`Resolvable` looks for `reconciliation`); reuse the `LoadAggregate` in the cancel handler.
5. **Where serve validates its environment** (`cmd/central/harness_config.go` pattern) so the two variables get the same fail-at-start treatment, including when harness execution is disabled (a degraded epoch exists independently of it).
6. **B11/B12 and existing recovery tests** that expect serve to start degraded with `RECOVERY_EPOCH_QUARANTINED`; they must keep passing with no variables set.

## 9. Acceptance

1. With `CENTRAL_RECOVERY_RESUME=<gen>:<retry>` and a reason matching a degraded epoch, one serve start resumes it, drains it, and leaves the epoch `completed` with no `scan_error` row; the Workspace's older queued Run is dispatched.
2. With no variables, a wrong pair, or a stale pair, serve resumes nothing and its durable state is today's (degraded start, the epoch stays `degraded` or `failed` in `central.recovery_epochs`); only log lines differ.
3. Invalid configuration of the two variables refuses to start with a message naming the variable.
4. The resume writes exactly one `execution.recovery.resumed` event, one outbox row and one receipt; a repeated start with the variables set writes none.
5. A Task `cancelling` with a prepared attempt (including a successor whose ownership row recovery expired) can be finished from its page; Task, Run, Step and StepAttempt end `cancelled`, the harness row, if one exists, ends `failed(harness_not_launched)`, and Rerun works.
6. An unexpired lease on the prepared attempt gives a retryable 409, never a partial commit.
7. The full portable suite passes (apart from the known `internal/recovery` `TestNoC06SuiteSourceOutsideTheRunnerCallsTestingSkipDirectly` failure), and the touched packages pass against live PostgreSQL, including the B08 recovery tests.
