# Harness Phase 3a — Serve Wiring Design

- **Date:** 2026-09-28
- **Status:** Draft. Brainstormed with the recommended option taken for each question, per the maintainer's workflow. Revised after the focused spec review (`docs/superpowers/reviews/2026-09-28-harness-phase-3a-spec-review.md`).
- **Governing decisions:**
  - [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md);
  - [ADR 0036](../../../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md) (Accepted);
  - ADR 0004 (prepare → invoke → persist).
- **Governing spec:** [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md), §7, §8, §10, §11, §13 and §14 (phase 3).
- **Builds on:**
  - phase [1b](2026-09-27-harness-phase-1b-persistence-design.md): `AttemptStore` and migration v30;
  - phase [2a](2026-09-27-harness-phase-2a-claude-code-adapter-design.md): the Claude Code adapter;
  - phase [2b](2026-09-27-harness-phase-2b-harness-launcher-design.md): `central-harness-launcher` and `hostlauncher`.

## 1. Goal and decomposition

Governing phase 3 ("a submitted Task runs an attempt end to end, with artifacts captured and restart reconciliation") is split into three sub-phases:

| Sub-phase | Delivers |
|---|---|
| **3a (this spec)** | serve runs a submitted Task as one Claude Code attempt through `hostlauncher`:<br>• in a Central-owned per-Run clone;<br>• every event persisted;<br>• the Run and Task ended through the execution and task domain services;<br>• milestones projected into the task event log;<br>• interrupted attempts reconciled at startup.<br>The only permission policy is `Deny`. 3a also ships a minimal operator exit for `ambiguous` Tasks. |
| 3b | Artifact capture at terminal (governing §10), shown on task detail. |
| 3c | `Bridge` approvals with UI, per-Task `AutoAllow`, cost and token budgets, an ambiguous-resolution UI, and retries. |

3a declares no required artifacts. The rule that a Run completes only after its required artifacts are durable is therefore met by the terminal state alone; 3b adds the artifacts. **3a needs no schema migration.**

## 2. Findings that shape the design

- **Submit stops at `queued`.** `POST /app/tasks/submit` persists a `queued` Task and Run and does nothing more. `Task.Input` carries the submission text.
- **Execution already has an ordered lifecycle.** A non-B09 worker must follow it:
  1. `task.ClaimCurrentRun` (queued → running), which has no production caller today;
  2. `execution.Prepare`, which creates the Step and StepAttempt;
  3. `Claim` (lease plus generation);
  4. `MarkInvoked`;
  5. `Heartbeat`;
  6. `RecordCompletionReceipt`;
  7. `Settle` or `EnterReconciliation`.

  Gaps today:
  - `Settle` hard-codes the failure reason `execution_failed`.
  - A `prepared` attempt can only leave via `ScheduleRetry`, `cancelled` or `reconciliation`.
  - No read lists dispatchable Runs.
- **B08 startup recovery** (`runRecoveryToCompletion` in the serve recovery gate) runs before readiness. It already owns the Run, Step and Task reconciliation:
  - an `invoked`/`settling` attempt with no completion receipt → the Step/StepAttempt to `reconciliation`, the Task to `waiting(reconciliation)`, and the lease expired;
  - with a receipt → settled automatically;
  - a `prepared` attempt → a prepared successor, which makes the Run re-dispatchable.

  The exit from reconciliation is `ResolveReconciliation`, which requires `CapabilityWorkspaceOperator`. No operator surface exposes it today.
- **The task event log accepts new producers without a schema change.** Execution commands already write to it, so heartbeats appear there too.
- **2b constraints:**
  - `worktree_root` and every one of its ancestors must be root-owned and not group- or other-writable, and it must lie outside `HOME`.
  - The harness process has **no supplementary groups** (`setgroups(0)`), only the operator's UID and primary GID.
  - The view shows `/etc` (read-only under `ProtectSystem=full`).
  - No harness outlives its client connection (the lifeline).
- **Git ownership checks.** git 2.53 refuses a repository owned by another UID unless `safe.directory` is set in protected (system or global) config. The operator's own `~/.gitconfig` is not visible in the view, because only the harness home is.
- **serve config** is environment variables only.

## 3. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | How does a queued Run start? | A **harness dispatcher** in serve reads dispatchable Runs through a new execution query, `ListDispatchableRuns(limit)`.<br>• A Run is dispatchable in two cases, both requiring that the Task was created at or after `CENTRAL_HARNESS_ELIGIBLE_AFTER` (decision 12), oldest first:<br>  (a) its Task is `queued` with a `queued` current Run;<br>  (b) its Task is `running` and its current StepAttempt is `prepared` with no live lease. This is the successor B08 creates when a crash or stop happened before `MarkInvoked`.<br>• For (b) the orchestrator skips `StartHarnessRun` and calls the existing `Claim` on the prepared attempt.<br>• It runs each through the orchestrator, up to `CENTRAL_HARNESS_CONCURRENCY` (default 1, maximum 4).<br>• Submit itself does not block. | This reuses the domain lifecycle and keeps the old backlog out (review P-I3). |
| 2 | Execution mapping for one attempt? | One harness attempt = one execution StepAttempt. A new fused execution command, **`StartHarnessRun`**, performs `ClaimCurrentRun` + `Prepare` + `Claim` in **one transaction**, returning the lease credential and generation. This removes the stranded-`running` window.<br>Then, in order, **heartbeating the lease from `StartHarnessRun` onward**, every lease/3 (10 s at the 30 s lease):<br>1. provision the workspace;<br>2. `AttemptStore.Create` (`prepared`);<br>3. **`MarkInvoked`**;<br>4. `Adapter.Start`;<br>5. the event loop;<br>6. at harness terminal: persist the terminal, then `RecordCompletionReceipt`, then `Settle` (decision 8).<br>A failure before step 3 uses the new command **`AbandonPrepared(reason)`**: prepared → `cancelled`, Run and Task → `failed` with a bounded reason, and no retry.<br>A serve stop before step 3 does **not** abandon. The dispatcher stops heartbeating, B08 creates a prepared successor at the next start, and the Run is re-dispatched through case (b) of decision 1. | `MarkInvoked` before `Start` means B08 treats a launched attempt as needing reconciliation, never as a retryable prepared one. The receipt lets B08 finalize "terminal persisted, settle lost" automatically (review C1, C2). |
| 3 | Fence? | The attempt's `harness.Fence` is the execution lease generation from `StartHarnessRun`. The harness store validates each fenced write against the live execution lease in the **same transaction** (the 1b follow-up, `NewStore(pgx.Tx)` with a savepoint): generation equal, not expired, token hash matching. | A stale orchestrator can never write an attempt row (review M2). |
| 4 | Reason on failure? | `Settle`, `AbandonPrepared` and the execution **`CompletionReceipt`** carry a **bounded reason code**. B08's receipt-based recovery completion uses the receipt's code (review N3). The codes are: the 2a harness vocabulary, plus `workspace_unavailable`, `harness_launch_failed`, `harness_lease_lost` and `operator_resolved`. This code becomes `Task.FailureReason` in place of the hard-coded `execution_failed`, which stays the default for callers that give no code. | The operator sees why a Task failed, with no free text. |
| 5 | Workspace source? | Each Workspace has a **source repository**: a bare repo at `/var/lib/central-harness/sources/<workspace-id>.git`, owned `central-runtime:central-harness`, mode `2770` for `sources/`, created by `central-runtime` with `git init --bare --shared=0664` (`core.sharedRepository=0664`). With `group`, the "other" bits of pushed objects would follow the pusher's umask, and the runtime, which is not a group member, could not read objects pushed under umask 027 or 077; `0664` makes them readable whatever the umask, while `sources/` (`2770`) still keeps other users out.<br>• `setup.sh --workspace <id>` creates it.<br>• The operator (a member of `central-harness` in their normal session) adds it as a remote and pushes.<br>• The base is the source's default-branch HEAD, whose SHA is recorded at `prepared`.<br>• A missing source → `AbandonPrepared(workspace_unavailable)` with a runbook hint. | serve never reads the operator's `HOME`, and the operator controls what Central sees. |
| 6 | Per-Run workspace and access? | `data_root` = `/var/lib/central-harness` (root, `0755`). `worktree_root` = `/var/lib/central-harness/worktrees` (root, `0755`), matching the launcher config.<br>Installation creates `worktrees/runs` (`central-runtime`, `0750`) with an ACL `u:<operator>:--x`. Per Run, the runtime:<br>• creates `runs/<run-id>` and clones the source into `runs/<run-id>/repo` with `git clone --no-hardlinks`;<br>• sets **POSIX ACLs** on the tree: access and default entries `u:<operator>:rwX` and `u:central-runtime:rwX`, with mask `rwx`.<br>ACLs are UID-based, so they survive the launcher dropping groups. The default entries let the runtime read what the harness writes (3b). | The operator's harness gets write access, the runtime keeps read access, and the 2b root-owned-ancestor rule is met (review P-C1, P-I1). |
| 7 | git inside the view? | `safe.directory = /var/lib/central-harness/worktrees/runs/*` goes **only** in the harness home's `.gitconfig`. **Prerequisite:** a `safe.directory` entry ending in `/*` (leading-path matching) needs git ≥ 2.46.0 (backported to 2.45.3); `setup.sh` checks `git --version` and refuses an older git. The entry goes there together with `user.name` and `user.email` taken from the operator's global git config or from `setup.sh` flags and confirmed by the operator.<br>**Nothing is written to `/etc/gitconfig`**, so the operator's own sessions never trust a harness-written `.git/config` (plan review S1).<br>For pushing, the operator adds a `safe.directory` entry for their Workspace's exact source path to their own `~/.gitconfig`, as documented in the runbook; `git -c safe.directory` has no effect for a local push on git 2.53.<br>The runbook inspects clones only by fetching them into the operator's own checkout, never with `cd` or `git -C` into a clone.<br>Acceptance requires a harness commit in the clone and an operator push to the source. | Without these, the harness's commit and the operator's push fail on the ownership check. A system-wide trust of Run clones would let a harness-set `core.fsmonitor` run outside the sandbox (review I1, P-C1, plan review S1). |
| 8 | Terminal mapping to the Run and Task? | • `succeeded` → `Settle` succeeded.<br>• `failed`, `killed`, `interrupted` or `budget_exhausted` → `Settle` failed with the bounded reason (decision 4). There is no automatic retry.<br>• Pre-launch failures → `AbandonPrepared` (decision 2).<br>• The harness-row `ambiguous` state comes from reconciliation (decision 9). The Task is then `waiting(reconciliation)`, set by B08.<br>Every Run and Task transition goes through the execution and task domain services. | Hard constraint. |
| 9 | Startup reconciliation? | **B08 owns the Run, Step and Task side** and runs first, as today. A new **harness reconciliation step** runs right after `runRecoveryToCompletion` in the recovery gate:<br>• It **always runs**, even when harness execution is disabled.<br>• It is **DB-only**: no launcher calls in the gate.<br>• For each non-terminal harness attempt it reads the linked StepAttempt. Settled (B08 used the receipt) → the attempt row takes the matching terminal.<br>• A harness attempt row still `prepared` (never launched), whose StepAttempt B08 cancelled into a prepared successor → the row takes the terminal the harness domain allows for a never-launched attempt (plan check 4). The Run is re-dispatched through decision 1 (b).<br>• Otherwise → `ambiguous`.<br>• The write authority is the recovery epoch: a store method that checks in one transaction that the linked StepAttempt is no longer lease-live (`reconciliation`, settled or cancelled). It does not use a fence.<br>No kill is needed. The lifeline guarantees that a harness died with the previous serve. On its first start, the dispatcher also asks the launcher `ALIVE` for each `ambiguous` attempt's scope and kills any survivor, logging a warning. It does this through a new port method, `ProcessLauncher.KillScope(ctx, scopeID)`: `hostlauncher` maps it to the launcher's KILL, `localexec` to its process-group kill, and a KILL on a missing scope is a no-op. | This matches B08, keeps readiness independent of the launcher, and leaves nothing stranded when the feature is disabled (review C2, P-I2). |
| 10 | Lease lost mid-attempt (serve still running)? | The orchestrator closes the lifeline, so the launcher kills the scope. It then **stops writing** and marks the Run *lost* in the dispatcher's memory (shown on the health detail).<br>The Task stays `running` until the next restart, when B08 plus decision 9 turn it into `waiting(reconciliation)` with the attempt `ambiguous`. The dispatcher never re-dispatches a lost Run. | With no lease there is no authority to write. The restart path is already correct (review C2). |
| 11 | Probe and not-logged-in? | The dispatcher runs `Adapter.Probe` before each claim.<br>• Not logged in, or the launcher unreachable → the dispatcher **pauses**. It claims nothing, fails nothing, and retries the probe every 30 s.<br>• The state (`running`, `paused: not logged in`, `paused: launcher unreachable`) appears at `/health/harness` and as a banner on `/app` pages. | Nothing fails silently, and one logout does not burn the queue (review P-I3). |
| 12 | Config and enablement? | Off by default. It is enabled by environment variables (the existing serve config mechanism): `CENTRAL_HARNESS_ENABLED=1`, `CENTRAL_HARNESS_ELIGIBLE_AFTER` (RFC 3339; required when enabled), `CENTRAL_HARNESS_DATA_ROOT` (default `/var/lib/central-harness`), `CENTRAL_HARNESS_PATH` (absolute directories only), `CENTRAL_HARNESS_WALL_CLOCK` (default 30 m), `CENTRAL_HARNESS_CONCURRENCY` (1–4), `CENTRAL_HARNESS_MIN_FREE` (default 2 GiB) and the pinned claude version.<br>Invalid values → serve refuses to start. Disabling → the dispatcher does not start; reconciliation still runs (decision 9). | Existing installations are unchanged, and toggling it is safe. |
| 13 | Shutdown? | On stop, the dispatcher stops claiming. Each orchestrator **closes its lifeline**, so the launcher kills the scope, and it stops writing. Shutdown is therefore bounded by a single socket close, not by the 85 s Kill budget. The Tasks become `waiting(reconciliation)` on the next start. | Bounded, predictable stop (review P-I2). |
| 14 | Wall clock and disk? | Wall clock → Interrupt, then Kill → `budget_exhausted`.<br>Before provisioning, the orchestrator checks free space at `data_root`. Below `CENTRAL_HARNESS_MIN_FREE` → the dispatcher pauses (`paused: low disk`). Run clones are never cleaned in 3a. The runbook documents a root cleanup command for Runs in a terminal state. | Disk exhaustion is visible and recoverable (review P-M1). |
| 15 | Operator exit for `ambiguous`? | The authenticated web UI gets one action: on a task in `waiting(reconciliation)` whose attempt is `ambiguous`, the task detail page shows a **"Mark failed (operator resolved)"** POST form, with CSRF and origin checks like submit, and the operator session's `CapabilityWorkspaceOperator`.<br>It calls `ResolveReconciliation`, which 3a fixes in two ways:<br>• it takes the fenced branch only for an **active, unexpired** lease, so B08's expired lease row is not a `STALE_LEASE_FENCE`;<br>• `ConfirmFailed` passes the bounded reason `operator_resolved` instead of the hard-coded `execution_failed`.<br>The harness attempt row becomes `resolved(abandon)`, the harness domain's existing outcome.<br>There is no CLI: an operator-run CLI cannot read the runtime DB credential. | The minimal exit until the 3c UI, on the existing operator authority (review N2). |
| 16 | Task event log? | The orchestrator projects these milestones: attempt launched, session started, permission denied, retry, terminal status and reason, dispatcher paused and resumed.<br>The task detail and activity views **hide execution heartbeat events**, a read-side filter by kind. | Keeps the log readable (review M1). |
| 17 | Package placement? | • **`internal/harness/app`:** the orchestrator, dispatcher and reconciler. It depends only on ports: the harness ports, a `RunLifecycle` port implemented over execution and task, `WorkspaceProvisioner`, `TaskEventSink` and `Clock`. Archguard confines it to those.<br>• **`internal/adapter/workspace/gitclone`:** clone, ACLs, free space.<br>• **Execution:** the new commands `StartHarnessRun` and `AbandonPrepared`, the bounded reason on `Settle`, the query `ListDispatchableRuns`, and the recovery-authorized harness write.<br>• **`cmd/central`:** composition, env config, the recovery-gate step, `/health/harness`, the banner, and the resolve action. | Domain packages own their interfaces, and adapters do not leak. |
| 18 | Installation? | `docs/operations/harness-execution.md` and `packaging/harness/setup.sh`, which is idempotent and run with sudo:<br>• group `central-harness`, with the operator added (takes effect at next login; the script says so). `central-runtime` owns the source repos and needs no group membership;<br>• `/var/lib/central-harness/{sources,worktrees/runs}` with the modes and ACLs above;<br>• the harness home and its `.gitconfig`, written as the operator (`sudo -u`), never by root inside `HOME` (plan review S3);<br>• the launcher units.<br>`/etc/central/harness-launcher.conf` is created if it is absent; if it exists and differs from the expected content, the script prints the diff and exits non-zero without overwriting it.<br>Serve environment snippet; `--workspace <id>` creates a source repo. | Reviewable, rerunnable, never clobbers operator edits (review P-I1). |

**Approaches considered:**

- **Chosen:** a dispatcher over the domain lifecycle (the fused claim command).
- **Rejected:**
  - synchronous launch in the submit handler: it binds process lifetime to an HTTP request;
  - reviving B09: ADR 0035 forbids it;
  - a `git worktree` of the operator's repo: the gitdir lies outside the view, and serve would need `HOME`;
  - group-only access to Run clones: the launcher drops supplementary groups.

## 4. Data flow (happy path)

1. The operator pushes to the source repo and submits a Task (`queued`).
2. The dispatcher probes, then calls `StartHarnessRun`: Task and Run → `running`, StepAttempt `prepared` with a live lease. The generation becomes the fence.
3. The orchestrator:
   1. checks free space and provisions `runs/<run-id>/repo` (clone plus ACLs), recording BaseSHA;
   2. `AttemptStore.Create` (`prepared`);
   3. `MarkInvoked`;
   4. `Adapter.Start` through `hostlauncher` (scope = attempt id, workdir = the clone, policy `Deny`, env from config);
   5. drains the events: `AppendEvent`, projection, heartbeat every 10 s, wall clock;
   6. at terminal: persists the harness terminal, then `RecordCompletionReceipt`, then `Settle` with the mapped status and reason.
4. The task detail page shows the milestones and the final status. The clone holds the harness's commits.

## 5. Errors

| Condition | Result |
|---|---|
| Probe says not logged in, or the launcher is unreachable | The dispatcher pauses. Nothing fails. |
| Free space low | The dispatcher pauses. |
| Source missing or clone fails | `AbandonPrepared(workspace_unavailable)` |
| Launcher error at `Start` (after `MarkInvoked`) | `Settle` failed, `harness_launch_failed` |
| Lease lost | Lifeline closed, writing stops, Run marked lost. Next start: `waiting(reconciliation)` + `ambiguous`. |
| Fence conflict on a store write | Same as a lost lease. |
| serve stop | Lifelines closed. Next start: `waiting(reconciliation)` + `ambiguous`. |

Reasons and errors never carry harness free text or prompt content.

## 6. Security

- serve never execs a harness. It runs git only on data it owns, under `/var/lib/central-harness`.
- serve never touches the operator's `HOME`, apart from what `setup.sh` does with explicit operator confirmation (`.gitconfig` identity).
- The harness sees only its clone and harness home (2b).
- `Deny` is the only policy.
- Credentials: governing §9 holds unchanged.
- ACLs grant exactly two UIDs, the operator and `central-runtime`.

## 7. Testing

- **Unit (`internal/harness/app`, fake ports and the fake adapter):**
  - every terminal mapping and reason;
  - `AbandonPrepared` for pre-launch failures;
  - the `MarkInvoked`-before-`Start` ordering;
  - receipt before `Settle`;
  - wall clock;
  - lease loss (lifeline closed, no writes);
  - pause and resume on probe and disk;
  - the projection set;
  - bounded shutdown;
  - reconciler branches.
- **Execution:**
  - `StartHarnessRun` atomicity (no stranded `running` on failure);
  - `AbandonPrepared`;
  - the bounded reason in `Settle` (`FailureReason`);
  - `ListDispatchableRuns` eligibility (`ELIGIBLE_AFTER`, order);
  - the recovery-authorized harness write.

  These run as live PostgreSQL tests against `central-1b-pg`.
- **`gitclone`:** temp bare repos; clone; BaseSHA; ACL entries (via `getfacl`, or xattr reads); missing source; the free-space check.
- **Postgres live:** the fence validated against the lease in one transaction (stale, expired or wrong token refused). Harness reconciliation after B08 for each B08 outcome.
- **Composition:** serve with harness disabled is unchanged, and reconciliation still runs. Enabled with invalid env → refuses to start. `/health/harness` states.
- **End to end without root:** real stores, the fake adapter, and a local bare repo run:
  - submit → `succeeded`;
  - a failure path;
  - a restart mid-attempt → `waiting(reconciliation)` plus `ambiguous`, then the resolve action;
  - a stop before `MarkInvoked` → re-dispatched after restart;
  - a slow clone → the lease is kept alive.
- **Reference host** (maintainer, `referencehost` tag, gated by `CENTRAL_TEST_HARNESS_E2E=1` and `CENTRAL_TEST_CLAUDE=1`):
  - after `setup.sh`, a fixture repo with the prompt "create hello.txt containing hi and commit it" → Task `succeeded`, the clone has a new commit by the configured identity, and the operator can push to the source;
  - a killed serve then a restart → `waiting(reconciliation)`, the attempt `ambiguous`, the scope dead;
  - `setup.sh` rerun is a no-op;
  - serve starting with the launcher stopped → ready, dispatcher paused.

## 8. Plan-stage checks

1. The exact transaction shape for `StartHarnessRun`: whether a single execution change-set can carry the Task transition, as `persistRecoveryWaitingState` does.
2. Setting ACLs from Go (the `system.posix_acl_access`/`default` xattr encoding) versus shelling out to `setfacl`. Pick one and record the dependency.
3. Wiring the resolve form: the web handler's operator authorization, and the task facade's `ExecutionClaimRequest` path for `StartHarnessRun`, which must keep the recovery-claim admission check.
4. Which terminal the harness state machine allows for a `prepared` attempt that was never launched. If there is none, add the smallest transition (for example prepared → failed with `harness_not_launched`) with its tests.

## 9. Acceptance

- On the reference host, the fixture Task from §7 ends `succeeded` with a harness commit in its clone. The detail page shows its milestones and no heartbeat noise.
- Killing serve mid-attempt, then restarting, gives `waiting(reconciliation)`, an `ambiguous` attempt and a dead scope. The "Mark failed (operator resolved)" action then settles the Task as `failed(operator_resolved)` and the attempt as `resolved(abandon)`.
- With harness disabled, serve behaves as before, apart from reconciliation, which is a no-op when there are no attempts.

## 10. Out of scope

- **3b:** artifacts. **Constraint carried to 3b:** the Run clone's `.git` is writable by the harness, so any git the runtime runs there (diff, log) must treat it as untrusted: hooks disabled (`core.hooksPath=/dev/null`), no fsmonitor, no repo-local config honored beyond what capture needs. Otherwise a harness could get code execution as `central-runtime`. 3a runs no git in a clone after launch (review M2).
- **3c:**
  - `Bridge`/`AutoAllow`;
  - approvals UI;
  - cost and token budgets;
  - ambiguous-resolution UI;
  - retries.
- **Elsewhere:**
  - automatic cleanup and retention of Run clones (governing §15 Q4);
  - one-click-installer integration;
  - OpenCode and ACP (phases 4–5).

## 11. Plan-stage findings (verified draft, 2026-09-28)

These come from the draft behind `docs/superpowers/plans/2026-09-28-harness-phase-3a.md`.

- **Check 1:** one execution commit can carry `ClaimCurrentRun` + `Prepare` + `Claim`. `commitNew` applies the Task transition in the same transaction. A forced mid-commit failure leaves the Task `queued` with nothing written (live test). `StartHarnessRun` keeps the recovery-claim admission check.
- **Check 2:** ACLs are written from Go as `system.posix_acl_*` extended attributes through the vendored `x/sys/unix`. There is no `setfacl` runtime dependency and symlinks are never followed; the byte layout is pinned by a test.
- **Check 3:** the resolve action reuses the web handler's aggregate loading, with a new operator trusted scope built from the validated web session, and `AssertNoActiveLease`. **Disclosed:** every validated web session acts as Workspace operator for this one action. That matches Central's single-operator model.
- **Check 4:** prepared → failed already existed in the harness domain. A named `FailUnlaunched` helper with reason `harness_not_launched` was added.
- **A pre-existing bug was fixed:** no command could act on a B08 prepared successor (`INVALID_LOGICAL_OPERATION_REUSE`), which made decision 1 case (b) impossible. The rule was relaxed so the successor is claimable, while a change set still cannot create a lone successor.
- **Attempt ↔ StepAttempt link, with no migration:** the harness attempt id is derived from the StepAttempt id (`harness.AttemptIDForStepAttempt`).
- **Config:** `CENTRAL_HARNESS_OPERATOR_UID` was added, because the clone ACLs need it.
- **Low disk:** found only at clone time, low disk abandons the Run as `workspace_unavailable` and pauses the dispatcher.
- **Resolve action scope:** the resolve action also shows for a harness row that is already terminal, which covers a lease lost between persisting the terminal and recording the receipt.
- **Plan review fixes:**
  - **Cancel:** the orchestrator observes `cancelling` and settles through the new `ExecutorStopped` (reconciliation, in one change set, only with a live lease). A cancel arriving before `MarkInvoked` cancels the prepared attempt.
  - **Quarantine:** `ListDispatchableRuns` excludes recovery-quarantined Runs, and the dispatcher keeps a backoff set for Runs refused at start.
  - **Clone:** it uses `--no-local`, and ACLs are set post-order without following symlinks.
  - **Prepared successors:** they are refenced onto the old harness row, and a lone successor is refused.
  - **Pre-existing, disclosed:** a Task cancelled while `queued` stays `cancelling` (no executor ever settled it), and a serve stop mid-cancel falls to existing B08 behaviour. Both are 3c follow-ups.
- **Deny policy and the operator's allow rules:** under `Deny`, claude edits files or runs `git commit` only when the operator's own user-level settings (`~/.claude/settings.json`) allow those tools. This follows 2a decision 7: user-level allow rules are the operator's trust decision. The runbook recommends the minimal allow rules, and the reference-host acceptance depends on them.
- **Final review fixes:**
  - **`.git` in the allow rules (I1):** `runs/**` also covers each clone's `.git/`, so a harness could plant hooks or `.git/config` and have the allowed `git commit` run them, inside a sandbox that mounts the operator's `~/.claude` read-write. The runbook and the reference-host fixture add `Edit`/`Write` deny rules for `runs/**/.git` and `runs/**/.git/**`; in Claude Code deny rules take precedence over allow rules. A reference-host case checks the harness cannot write the clone's `.git/config`. The maintainer verifies the `.git` denial and symlink resolution on the pinned 2.1.283 before enabling.
  - **The clone's `.git` is untrusted:** after launch, 3a runs no git in a clone (the runtime's `Settle` path included), and the §10 constraint stands: 3b capture must treat `.git` as untrusted (hooks and fsmonitor off, no repo-local config beyond what capture needs).
  - **Store errors on event writes (I2):** only a harness-domain refusal (`ErrInvalidEvent`, `ErrEventConflict`, `ErrInvalidTransition`, `ErrInvalidAttempt`) settles `harness_protocol_error`. A store error is retried with capped backoff while the heartbeat keeps the lease (no successful heartbeat for three intervals, or a lease-lost heartbeat, takes the lost path); past 2 minutes the session is killed and the Run fails `execution_failed`.
  - **Unknown-outcome start:** a claim command that fails without a domain refusal may have committed, so the Run is held lost (`NeedsRestart`, banner) instead of cooling down.
  - **N1 fix:** the harness-home `.gitconfig` also sets `safe.bareRepository = explicit` (refusing an embedded bare repository git would otherwise discover under `runs/**`), and the allow rules use only `Edit` (not the inert `Write`), with `.git` denied.
- **Release gate (maintainer decision, 2026-09-28):** phase 3a merges with harness execution off by default. The reference-host acceptance in §9 (a real `setup.sh` run plus a real claude session) is **required before `CENTRAL_HARNESS_ENABLED=1` is first set** on any host. It is not a merge gate.
