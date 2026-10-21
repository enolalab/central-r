# Harness Phase 3c — Permission Approvals Design

- **Date:** 2026-09-29
- **Status:** Draft. Brainstormed with the recommended option taken for each question, per the maintainer's workflow. Revised after the focused spec review (`docs/superpowers/reviews/2026-09-29-harness-phase-3c-spec-review.md`).
- **Governing decisions:**
  - [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md);
  - [ADR 0036](../../../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md) (Accepted);
  - ADR 0001 (the Approval entity);
  - ADR 0004 (prepare → invoke → persist).
- **Governing spec:** [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md), §11 (permission bridging) and §15 open question 3.
- **Builds on:**
  - [phase 3a](2026-09-28-harness-phase-3a-serve-wiring-design.md): serve runs a Task as one Claude Code attempt, with `Deny` as the only policy;
  - [phase 3b](2026-09-28-harness-phase-3b-artifact-capture-design.md): artifact capture;
  - [phase 2a](2026-09-27-harness-phase-2a-claude-code-adapter-design.md): the Claude Code adapter already implements all three policies, including `Bridge` over the stream-json `can_use_tool` control request.

## 1. Goal and decomposition

3a's table assigned five things to 3c. They are three independent subsystems, so 3c is split:

| Sub-phase | Delivers |
|---|---|
| **3c (this spec)** | Permission policies end to end:<br>• the operator picks `Deny`, `Bridge` or `AutoAllow` per Task at submission;<br>• `Bridge` turns every harness permission request into a durable Approval that the operator answers on the task detail page, with a timeout that answers deny;<br>• `AutoAllow` is recorded on the Task and shown in the UI;<br>• `PermissionRequested` carries the tool call id and the tool input, and the input is treated as sensitive. |
| 3d | Budgets (governing §13): wall clock per session, attempt count, and reported cost and tokens (scope-normalized: tokens summed across a resume chain, the latest cumulative cost). A breach ends the attempt `budget_exhausted`. |
| 3e | Operator actions: the ambiguous-resolution UI (resume by new attempt, rerun, abandon), retries, cancel while `queued`, a serve stop in the middle of a cancel, and taking the report from the result frame (3b follow-up). |

3d and 3e get their own spec → plan → implementation cycle.

### Non-goals

- "Always allow this tool" rules, or any remembered decision. Each request is answered on its own.
- Notifications outside the web UI (email, push, desktop).
- Several operators, or delegating approvals. Central runs for one operator (governing §9).
- Persisting the tool input. It stays in serve memory only (decision 5).
- Reattaching to a pending request after a serve restart. Claude Code has no `Reattach`, so the attempt becomes `ambiguous` and its approval is `superseded` (governing §11).
- Changing the B09 executor. The policy applies to harness Runs only.

## 2. Findings that shape the design

1. **The adapter is ready.** `claudecode` maps `Bridge` to `--permission-mode manual --permission-prompts host --permission-prompt-tool stdio` and verifies that `system/init` reports `default`. It emits `PermissionRequested` for each `can_use_tool` request and answers it through `RespondPermission`. Under `Deny` and `AutoAllow` it answers any request itself with a denial. It keeps the request's `tool_use_id` and `input` in memory but does not expose them.
2. **The orchestrator hard-codes `Deny`.** Both `StartSpec.Permission` and the attempt record are set to `PermissionDeny`, and every `PermissionRequested` is answered with `policy:deny`.
3. **The attempt domain supports one pending request.** `Attempt.AwaitPermission` / `ResolvePermission` hold a single `PendingPermission`, and `harness_attempts.pending_permission` stores it.
4. **The event row has room for the ids.** `harness_events` already has `tool_call_id`, `tool_name`, `permission_request_id` and `permission_outcome`. Raw frames are stored only as size and SHA-256, so no payload is in the database.
5. **`central.approvals` does not fit.** Its B08 `execution` kind is a gate before a step: it binds an operation digest and an expected step version, one pending approval per logical operation, and the Task waits with `approval`. A harness permission happens in the middle of a running step, can repeat many times per step, and ends with the attempt.
6. **The Task Input is a strict three-field document.** `ParseRepositoryAnalysisInput` rejects any fourth field, and B09 re-parses the stored Input verbatim. The policy therefore cannot ride in the Input without changing the B09 contract.
7. **A single serve process** runs both the web handlers and the harness dispatcher, so the operator's decision can reach the live session in memory.

## 3. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| 1 | Split 3c? | Yes, into 3c (permissions), 3d (budgets) and 3e (operator actions), per §1. | Each is an independent subsystem with its own tests and review. Permissions come first because the adapter support already exists and `Deny` makes most real tasks fail. |
| 2 | The default policy for a new Task (governing open question 3)? | **`Deny`.** | Fail-safe, and it matches governing §11. The operator opts in to more. |
| 3 | Where is the policy recorded? | A new Task column `permission_policy text NOT NULL DEFAULT 'deny'`, with a check for `deny`, `bridge` and `auto_allow` (migration v31). `task.SubmitTaskRequest` gains `PermissionPolicy`. The task domain owns its own enum and validates it; it does not import `internal/harness`. The value never changes after submission. A Retry reuses the Task, so it keeps the policy. A Rerun creates a new Task by copying fields one by one, so it copies `PermissionPolicy` explicitly; the database default must never apply to a Rerun. | "Recorded on the Task" (governing §11), and atomic with the submission. A side table would race the dispatcher. The Input cannot carry it (finding 6). |
| 4 | How is the policy chosen and shown? | The submit form has a policy select, rendered only while harness execution is enabled, with `Deny` selected by default.<br>• `auto_allow` also requires the checkbox `auto_allow_ack=1`; without it the submission fails with 400.<br>• A policy other than `deny` while harness execution is disabled fails with 400.<br>• Task detail shows the policy. `AutoAllow` is shown as a warning: "Auto-allow: the harness runs every tool without asking, and can change your own Claude Code settings." | An explicit, visible choice (governing §11). The acknowledgement keeps a mis-click from granting everything. |
| 5 | The tool input the operator must see? | `PermissionRequested` gains `ToolCallID` and `Input` (the raw bytes of the request's `input` JSON, exactly as the adapter will echo them as `updatedInput`).<br>• The **input is never persisted and never logged.** It lives in serve memory, in the orchestrator's pending-approval registry, for as long as the request is pending.<br>• The database stores only `input_mac` and `input_size`. `input_mac` is HMAC-SHA256 over the raw input bytes, keyed by a random 32-byte key generated once per serve process and never stored. A plain hash would let anyone who reads the database or the page confirm a guessed low-entropy secret. The key dying with the process costs nothing, because a request never outlives its process.<br>• The event's `String`/`GoString` redact it, and `RecordOf` never copies it.<br>• `ToolCallID` goes into the existing `harness_events.tool_call_id`.<br>• **Bounds on harness-controlled fields.** A request whose `request_id` or `tool_call_id` exceeds 512 bytes, whose tool name exceeds 256 bytes or is not printable ASCII, or that has more than 16 resources or a resource over 1 KiB, is a protocol error. The adapter fails the attempt closed and never answers it. | The hard rule is no payloads in the database, and the input can hold secrets (a shell command with a token). Nothing is lost by keeping it in memory: a request cannot outlive its serve process (§1 non-goals). |
| 6 | Where is the durable Approval? | A new harness-owned table `central.harness_permission_approvals` (migration v31). Its columns:<br>• `workspace_id`, `id` (uuid), `attempt_id`, `task_id`, `run_id`;<br>• `request_id`, `tool_call_id`, `tool_name`, `input_mac`, `input_size`;<br>• `state` (`pending`, `allowed`, `denied`, `expired`, `superseded`);<br>• `requested_at`, `expires_at`, `decided_at`, `decided_by`, `version`.<br>`(attempt_id, request_id)` is unique, and at most one row per attempt is `pending`. `central_runtime` gets SELECT, INSERT and UPDATE, and no DELETE. A domain type `harness.PermissionApproval` owns the transitions; every terminal state is final. | It is an ADR 0001 Approval in shape (durable, a timeout, a recorded decider, survives restarts) without bending the B08 execution kind (finding 5). |
| 7 | Concurrent requests? | **One pending approval per attempt.** A request that arrives while another is pending waits in an in-memory FIFO queue in the orchestrator. Its event is recorded when it arrives. Its approval row is created, and its timeout starts, only when it reaches the head of the queue. The queue holds at most 16 requests; a 17th fails the attempt closed (decision 10). A `request_id` that is already pending in the adapter is a protocol error: the adapter fails the attempt closed and never answers by that id, so an approval can never be answered with another request's input. | This matches the domain's single `PendingPermission` (finding 3), and the operator answers one thing at a time. Plan-stage check 1 verifies whether Claude Code sends concurrent requests. |
| 8 | How does a decision reach the session? | Through the durable row first, then an in-memory signal.<br>1. The operator's decision is a compare-and-set: `pending` → `allowed` or `denied`, with `decided_by = operator-session:<principal>`. It holds only if all of these are true in the same statement:<br>&nbsp;&nbsp;– `expires_at > now()`;<br>&nbsp;&nbsp;– the attempt is `awaiting_permission` on that `request_id`;<br>&nbsp;&nbsp;– the posted `input_mac` matches;<br>&nbsp;&nbsp;– an unexpired execution lease still claims the Run (the ownership join of `queryLockLiveLease`, without the bearer).<br>Both allow and deny are refused unless the orchestrator's registry holds the input for that approval (decision 13, §10.13).<br>2. The orchestrator's registry is then signalled.<br>3. The orchestrator's drive loop also re-reads the pending row every 2 s, so a lost signal only delays the answer.<br>4. On a decided row the orchestrator calls `RespondPermission` with the row's decision, its `DecidedBy` and the `InputMAC` it approved. The adapter recomputes the MAC over the exact bytes it will echo as `updatedInput` and refuses on a mismatch (decision 10). The orchestrator then records `PermissionResolved` and `ResolvePermission` in one transaction. | The durable row is the source of truth, and the compare-and-set picks one winner between the operator and the timeout. The MAC check binds the decision to the input the operator saw. |
| 9 | Timeout? | `CENTRAL_HARNESS_APPROVAL_TIMEOUT`, default **10 minutes**, accepted range 30 s to 24 h (an out-of-range value fails serve startup). On expiry the orchestrator compare-and-sets `pending` → `expired` with `decided_by = policy:timeout` and answers deny. The attempt's wall clock (`CENTRAL_HARNESS_WALL_CLOCK`) keeps running while it waits. | Governing §11: "the timeout answers deny". The Claude process is idle while it waits, so no work is lost. |
| 10 | What if the bridge cannot work? | Fail closed (governing §11). The request is never allowed. Exactly these map to the new terminal reason `permission_bridge_unavailable`; for each, the orchestrator interrupts the session (kill ladder) and the attempt ends `failed`:<br>• the approval row cannot be written. The insert runs inside the event or attempt write, so it shares the existing event-write budget, and a failure past that budget takes this reason instead of `execution_failed`;<br>• `RespondPermission` fails with anything other than `ErrNoPendingPermission`, including a MAC mismatch (decision 8);<br>• the queue overflows, or the adapter reports a protocol error on a permission request (decisions 5 and 7).<br>**Benign cases:**<br>• `ErrNoPendingPermission` after the session has ended, been stopped or seen its last result is not a failure. The orchestrator keeps draining, and the terminal event already queued settles the attempt with its own status (for example `interrupted` or `budget_exhausted`).<br>• A failed expiry compare-and-set is retried at the next 2 s tick while the lease holds. | "No silent fallback. If the bridge channel is unavailable, the attempt fails closed." |
| 11 | When does a pending approval close without a decision? | It becomes `superseded` (`decided_by = system:superseded`) **in the same transaction** as every write that moves the attempt to a terminal state or to `ambiguous`. That covers `Save` (finish), `AppendEvent` (a terminal event), `RecoverAttempt` (startup reconciliation, both its ambiguous and its terminate paths; it is not fenced, by design) and the resolver. This is a store invariant, not a caller duty (decision 16).<br>**Lease loss and stop write nothing** (3a: `OutcomeLost` and `OutcomeStopped`). The approval stays `pending` until startup reconciliation supersedes it. Meanwhile:<br>• the operator's compare-and-set is refused, because no live lease claims the Run (decision 8);<br>• the banner and the panel show it as "waiting for restart reconciliation", with no buttons (decision 13);<br>• the orchestrator drops its registry entries for that attempt. | Every approval ends in a terminal state, and no dead session can be approved. |
| 12 | The operator's decision route? | `POST /app/tasks/harness/permission` with `csrf`, `task_id`, `approval_id`, `input_mac` and `decision` (`allow` or `deny`). It uses the same prelude as the 3a resolve action: a non-empty Origin, the session-bound CSRF token, an active session, and the recovery-claimability gate. The decider comes from the session's principal, never from a form field. A decision that no longer applies re-renders the task detail page with "This request is no longer pending." Every query is scoped to the session's workspace. | It reuses a reviewed prelude, and a stale page is handled without leaking state. |
| 13 | UI? | **Task detail**, for a harness Run:<br>• the policy (decision 4);<br>• a **pending request** panel: tool name, tool call id, resources, time left, the input size, the input, and Allow / Deny buttons. **The operator can only allow what they were fully shown:**<br>&nbsp;&nbsp;– the input is rendered in full, never truncated. Top-level string values are shown decoded (the Bash `command` with its real newlines), in a wrapping, HTML-escaped `<pre>`;<br>&nbsp;&nbsp;– every non-printing or direction-changing code point is replaced by a visible marker such as `⟦U+202E⟧`. That covers C0/C1 controls other than newline and tab, U+200B–200F, U+202A–202E, U+2060–2064, U+2066–2069 and U+FEFF;<br>&nbsp;&nbsp;– an input over **256 KiB** is never bridged. The adapter denies it at once with `DecidedBy = policy:input_too_large`, and no approval row is created. This also bounds the queue's memory at 16 × 256 KiB;<br>&nbsp;&nbsp;– Allow is offered only while the registry holds the input. Otherwise the panel says "waiting for restart reconciliation" (decision 11);<br>• a **history** of the Run's approvals, newest first, at most 20: tool, outcome, decider, time.<br>**Every `/app` page** shows a banner while any approval in the session's workspace is pending: "N harness permission request(s) waiting", linking to the oldest one's Task. `HarnessOperator.Banner() string` therefore becomes `Banner(ctx, workspaceID)`.<br>Task detail already polls through `tasks_poll.js`. A new `permission_requested` milestone makes it reload, so a request appears within one poll interval. It never reloads over a shown pending panel. | The operator must see a new request without hunting for it, and the input must be visible to make the decision meaningful. |
| 14 | Milestones in the task event log? | `permission_requested` (the tool name) when an approval row is created, and `permission_allowed` / `permission_denied` (with `operator`, `timeout` or `input_too_large`) when a bridged request is answered. Under `Deny` and `AutoAllow` the adapter answers requests itself and emits a `Warning`, not `PermissionRequested`. The existing `permission_denied` milestone from `ToolResult{denied}` stays as it is. `superseded` gets no milestone; the Run's end already explains it. | The task timeline shows each question and its answer. |
| 15 | `AutoAllow` behaviour? | The adapter's existing mapping (`--permission-mode bypassPermissions`, verified mode `bypassPermissions`). Nothing else changes: the sandbox, egress policy and event recording apply as for any Run. The acknowledgement text says that the harness can also change the operator's own Claude Code settings (decision 17). | Governing §11 wants only an explicit, recorded, visible choice. |
| 16 | The store's shape? | Approval handling is a store invariant tied to attempt transitions:<br>• `AttemptStore.Save` and `AppendEvent` take an optional `ApprovalOpen{ID, RequestID, ToolCallID, Tool, InputMAC, InputSize, ExpiresAt}`. It is inserted in the same transaction when `next` enters `awaiting_permission` with a new `PendingPermission`, and refused otherwise;<br>• every write that moves the attempt to a terminal state or to `ambiguous` supersedes its pending row in the same transaction (decision 11);<br>• new methods: `DecidePermission` (the operator's compare-and-set, decision 8), `ExpirePermission` (fenced, the timeout's compare-and-set), `PendingPermission(attempt)` (the 2 s re-read), and workspace-scoped reads for the banner, the panel and the history.<br>The approval id is fixed before `appendEvent`'s retry loop, so a replayed append that skips its writes stays consistent.<br>**Promoting a queued request** is a `Save` with `ApprovalOpen`. It is made right after the previous request's `PermissionResolved` append, and before the next event is read. | One transaction per transition keeps "one pending row per awaiting attempt" true under crashes and retries. |
| 17 | The operator's user-level Claude Code settings? | **Honoured, and documented as a residual risk.** Claude runs with `--setting-sources user` (2a), and governing §9 forbids relocating or rewriting harness config. So `permissions.allow` rules, hooks and `defaultMode` in `~/.claude/settings.json` apply to every policy. A tool the operator pre-allowed there never reaches the bridge, and runs even under `Deny`.<br>• The runbook states this. The submit form shows it next to the policy select: "Your own ~/.claude permission rules and hooks also apply."<br>• Plan-stage check 6 verifies live on 2.1.283 which settings bypass `can_use_tool` under `manual` and `dontAsk`.<br>• **Integrity of those files is not solved in 3c.** An allowed Write, Edit or Bash, or any `AutoAllow` Run, can change them for later Tasks and for the operator's interactive use. A read-only bind of the settings files needs a launcher change under ADR 0036, and is a follow-up. | The operator's own harness config is theirs, and Central is indifferent to it (governing §9). The risk is stated where the choice is made, instead of being hidden. |

## 4. Data flow (Bridge)

1. The operator submits a Task with `bridge`. The Task row stores `permission_policy = 'bridge'`.
2. The dispatcher claims the Run. `ClaimedRun` carries the policy; the attempt is prepared with it, and `StartSpec.Permission` is `Bridge`.
3. Claude asks `can_use_tool`. The adapter emits `PermissionRequested{RequestID, ToolCallID, Tool, Resources, Input}`.
4. The orchestrator records the event. If no approval is pending, it writes, in one transaction (`AppendEvent` with `ApprovalOpen`, decision 16):
   - the approval row (`pending`, with `expires_at`);
   - the attempt's `AwaitPermission`;
   - the event.

   It then keeps the input in its registry and projects `permission_requested`. Otherwise the request joins the queue.
5. The web page shows the banner and the panel. The operator presses Allow. The handler calls the decision service, which compare-and-sets the row to `allowed` and signals the registry.
6. The drive loop sees the decision and calls `RespondPermission(allow)`. The adapter emits `PermissionResolved`. The orchestrator records it together with `ResolvePermission`, projects `permission_allowed`, and takes the next request from the queue.
7. The Run continues and ends through the 3b path.

## 5. Errors

| Situation | Behaviour |
|---|---|
| The operator decides after the timeout, after supersession, on a different input MAC, or while no live lease claims the Run | The compare-and-set matches no row. The page says "This request is no longer pending." Nothing is sent to the harness. |
| The lease is lost, or serve stops, while a request is pending | Nothing is written. The approval stays `pending`, shown as "waiting for restart reconciliation" and not decidable, until startup reconciliation supersedes it (decision 11). |
| An input over 256 KiB | Denied at once by the adapter (`policy:input_too_large`), with no approval row. |
| The operator and the timeout race | One compare-and-set wins. The orchestrator always answers with the row's final state. |
| The approval row cannot be written | Fail closed: interrupt, then `failed` / `permission_bridge_unavailable` (decision 10). |
| `RespondPermission` fails | The same as above, unless it is `ErrNoPendingPermission` after the session ended, which is benign (decision 10). The durable row keeps the operator's decision for audit. |
| The Task is cancelled while a request is pending | The heartbeat sees the cancel. The attempt goes through the kill ladder, and the terminal write supersedes the approval. |
| Serve restarts while a request is pending | Startup reconciliation moves the attempt to `ambiguous` and supersedes the approval in the same write. The Task waits for the 3a resolve action. |
| A permission request under `Deny` or `AutoAllow` | The adapter denies it itself and emits a `Warning`, not `PermissionRequested` (finding 1). No approval is created. |
| The adapter reports a mode that does not match the policy | This is already handled by the 2a mode check, which fails the launch. |

## 6. Security

- **Authorization.** Only an authenticated operator session, with CSRF and Origin checks, can decide, and only for its own workspace. The decider is derived from the session.
- **Decision binding.** The posted `input_mac` must equal the stored MAC, and the adapter checks the same MAC against the exact bytes it echoes, so an allow applies to the input that was shown and nothing else. A duplicate pending `request_id` fails closed. Approval ids are random UUIDs.
- **Only allow what was shown.** The input is rendered in full, with invisible and direction-changing code points made visible. Inputs over 256 KiB are never bridged (decision 13).
- **Bounded harness-controlled fields and queue** (decisions 5 and 7).
- **User-level Claude settings** are a stated residual risk (decision 17).
- **No payload persistence.** The tool input is held only in memory, never logged, and redacted from `String`/`GoString`. The database holds a keyed MAC and a size. `Raw` frames stay size-and-hash only.
- **Rendering.** The input is rendered through `html/template` escaping, inside a wrapping `<pre>`.
- **Fail closed** everywhere (decision 10). No path turns a failure into an allow.
- **`AutoAllow`** needs an explicit acknowledgement and is shown as a warning. It is only available while harness execution is enabled.
- The permission checks are never weakened for tests. Tests use the fake adapter and fake clocks.

## 7. Testing

- **Domain** (`internal/harness`): every `PermissionApproval` transition, including that a terminal state is final and that a MAC mismatch is refused. `PermissionRequested.String` redacts the input. `RecordOf` never copies it.
- **Task domain:** the policy enum, the `deny` default, and that the policy cannot change after submission.
- **Migration v31:** apply, re-apply, the shape inspector, the checks, the unique indexes (one `pending` per attempt), and the runtime grants (no DELETE).
- **Store (live PostgreSQL):**
  - the compare-and-set wins exactly once under an operator/timeout race;
  - supersession happens in the same transaction as every terminal and ambiguous write (`Save`, `AppendEvent`, `RecoverAttempt`, the resolver);
  - the operator's compare-and-set is refused without a live lease;
  - `ApprovalOpen` is refused unless the attempt enters `awaiting_permission`;
  - every query is scoped to the workspace;
  - a fence mismatch is refused.
- **Orchestrator** (fake adapter, fake clock):
  - allow and deny both reach `RespondPermission` with the right `DecidedBy`;
  - the timeout answers deny;
  - two concurrent requests are queued and answered in order;
  - a lost signal is recovered by the 2 s re-read;
  - a failed row write, a failed `RespondPermission`, a MAC mismatch and a queue overflow all fail closed with `permission_bridge_unavailable`;
  - `ErrNoPendingPermission` after the session ended lets the queued terminal settle with its own status;
  - cancel and the wall clock while pending supersede the approval through the terminal write;
  - stop and lease loss write nothing and drop the registry entries;
  - under `Deny` and `AutoAllow` no approval is created.
- **Adapter:** a duplicate pending `request_id` and out-of-bounds fields fail closed; an input over 256 KiB is denied with `policy:input_too_large`; `RespondPermission` refuses a MAC mismatch; `ToolCallID` and `Input` are emitted.
- **Reconciler:** an ambiguous attempt, and a terminated one, supersedes its pending approval.
- **Web handlers:** CSRF, Origin and session are required; a MAC mismatch or a non-pending approval gives the "no longer pending" page; an allow without a registry entry is refused; invisible code points are rendered as markers; Rerun copies the policy; another workspace's approval is refused; `auto_allow` without the acknowledgement gives 400; a non-`deny` policy with harness execution disabled gives 400; the input is HTML-escaped; the banner count is correct.
- **e2e (`cmd/central`, fake claude):**
  - a `bridge` Task whose request is allowed through the HTTP route completes with the three 3b artifacts;
  - a denied request is recorded, and the Run continues;
  - a request left unanswered expires to a denial.
- **Live claude (optional, `CENTRAL_TEST_CLAUDE=1`):** extend the existing live test with one bridged request, allowed through `RespondPermission`. It costs about $0.17. Run it only if plan-stage check 1 changes the adapter.

## 8. Plan-stage checks

1. **Concurrent `can_use_tool` requests.** Verify live against claude 2.1.283 whether one assistant turn with parallel tool calls sends several requests before any answer. Decision 7 is safe either way. The answer only decides whether the queue path needs a live test.
2. **Adding a Task column.** Confirm that the migration shape inspector and the baseline checks accept a new `tasks` column, and that no query reads tasks with `SELECT *` into a fixed struct.
3. **`ClaimedRun` source.** Confirm where `harness_lifecycle` reads the Task so the policy can be added next to `Prompt`.
4. **Task detail polling.** Confirm how `tasks_poll.js` decides to reload, and that a shown pending panel suppresses it (decision 13).
5. **The adapter's pending entry.** `pendingPermission` already holds `toolUseID` and `input`. Confirm that emitting them on the event needs no protocol change, and that `input` is kept as the raw bytes that are echoed.
6. **User-level settings.** Verify live on 2.1.283 which `~/.claude/settings.json` entries (`permissions.allow`, hooks, `defaultMode`) bypass `can_use_tool` under `manual` and `dontAsk`, and record the result in the runbook (decision 17).

## 9. Acceptance

1. A Task submitted with `bridge` stops at its first tool permission. The request appears on the Task's detail page within one `tasks_poll.js` interval, and in the banner of every `/app` page loaded after that. Allowing it lets the Run continue, and denying it records a denial.
2. An unanswered request is denied when `CENTRAL_HARNESS_APPROVAL_TIMEOUT` elapses.
3. A Task submitted with `auto_allow` (acknowledged) runs with `bypassPermissions`, and its detail page shows the warning.
4. A Task submitted without a choice runs with `Deny`, as in 3a.
5. No tool input reaches PostgreSQL, the logs, or the task event log.
6. An approval whose Run lost its lease cannot be allowed, and the operator can only allow an input that was shown in full.
7. After a serve restart, every approval that was pending is `superseded`, and its Task waits for the resolve action.
8. The full portable suite passes (apart from the known `internal/recovery` failure), and the touched packages pass against live PostgreSQL.

## 10. Plan-stage findings (verified draft, 2026-09-29)

These take precedence over the decisions above where they differ.

1. **Check 1.** On claude 2.1.284, one turn with two parallel tool calls sent its `can_use_tool` requests one at a time: the second arrived only after the first was answered. The queue (decision 7) stays as a safety net, covered by fake-based tests.
2. **Allow binding (decision 8).** `port.PermissionDecision.InputSHA256` carries the in-memory SHA-256 of the held input. The adapter compares it with the SHA-256 of the exact bytes it echoes, and refuses a mismatch with `port.ErrPermissionBinding`. Before answering, the orchestrator also re-checks the stored HMAC against the held input. Only the keyed MAC is ever persisted. The adapter compacts the input at intake, and emits and echoes exactly those bytes.
3. **Oversize input (decision 13).** An input over 256 KiB emits no `PermissionRequested`, only `PermissionResolved{deny, policy:input_too_large}`. No approval row is written, and the tool name of that request is not recorded.
4. **Store names (decision 16):**
   - the 2 s re-read uses `LoadApproval(ws, id)`;
   - the web reads are `PendingApprovals`, `PendingApprovalForRun` and `ApprovalHistory`;
   - `ExpirePermission` returns the row as it stands, which may be still pending or already decided;
   - the store refuses an `ApprovalOpen` that does not match the awaiting transition, but does not require one on it.
5. **A stale decision (decision 12)** redirects with 303 to `detail?id=…&permission=stale`, and the detail page renders "This request is no longer pending.".
6. **Approval ids** are UUIDv7: the identity package requires v7.
7. **Milestone `permission_requested`** carries Status `pending` and Reason = the tool name.
8. **Protocol violations on a permission request** (bounds, a duplicate pending id, a request that fails domain validation) end the attempt with `permission_bridge_unavailable`.
9. **Extra strictness:**
   - Rerun refuses a source Task without a known policy;
   - the decision service refuses an approval of another Task than the posted one;
   - the schema bounds `input_size ≤ 262144`, `decided_by` to 1..256 bytes, and requires `expires_at > requested_at`.
10. **Once the wall clock or a cancel has fired,** the orchestrator stops answering pending approvals. The terminal write supersedes them.
11. **Check 6** was answered from Claude Code documentation, not a live run: `permissions.allow` rules and `PreToolUse` hooks decide before `can_use_tool` under `manual` and `dontAsk`, and the CLI `--permission-mode` overrides `defaultMode`. The runbook marks this as documentation-based.
12. **Raw-frame digest (plan review P-S2).** `harness_events.raw_sha256` now holds HMAC-SHA256 of the raw frame under the per-process key, for every event: `harness.RecordOf(e, digestKey)`. A plain SHA-256 of a `can_use_tool` frame would have been a guess oracle for the input. The column keeps its name. Its only reader is the in-process replay comparison inside `appendEvent`'s retry loop.
13. **No undeliverable decision (plan review P-T2).**
    - The orchestrator drops an attempt's registry entries as soon as a cancel or the wall clock fires, and it never registers an approval opened after that.
    - The decision service requires a registry entry for deny as well as allow, so a decision is only recorded when a live session can receive it.
    - The panel says "Waiting for restart reconciliation, or the run is stopping".
    - A row found `superseded` is treated as answered, and is never a bridge failure.
14. **Unforgeable panel (plan review P-T1/P-S1).**
    - Each top-level field is rendered in its own `<dt>`/`<dd><pre>`, with its line and byte counts.
    - The adapter rejects an input with a repeated member name at any depth as a protocol error. It checks this before the 256 KiB size check.
    - The view offers only Deny for a repeated top-level name.
    - Markers cover every Default_Ignorable code point plus U+061C and U+2028/2029, and the input is shown with `unicode-bidi: bidi-override`.
15. **Evidence.** `TestHarnessE2EBridgeAllowThroughTheHTTPRouteCompletes` drives the allow through the composed serve handler with a real session, CSRF and Origin.
