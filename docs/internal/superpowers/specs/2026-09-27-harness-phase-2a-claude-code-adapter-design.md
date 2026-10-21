# Harness Phase 2a: Claude Code Adapter — Design

Date: 2026-09-27
Status: Reviewed — [spec review](../reviews/2026-09-27-harness-phase-2a-spec-review.md) findings applied
Governing decision: [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md) (Accepted); launcher prerequisite [ADR 0036](../../../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md)
Governing spec: [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md), phase 2
Inputs: phase-2 follow-ups in the [1a final review](../reviews/2026-09-27-harness-phase-1a-final-review.md) and the phase 1b follow-ups (PR #5 description, M1–M6; [1b plan review](../reviews/2026-09-27-harness-phase-1b-plan-review.md)); protocol facts captured live from Claude Code 2.1.283 (§2.2)

## 1. Goal

Deliver a Claude Code adapter that implements `port.Adapter`. It drives the unmodified `claude` binary headlessly, never alters its loop, and never touches its credentials.

It launches the process through a new, domain-owned **`port.ProcessLauncher`**, so that the adapter never calls `exec` itself. A development/test launcher (`localexec`) is included. The production sandbox launcher is phase 2b, gated by ADR 0036.

**Success criteria:**

- With a scripted in-memory `port.Process`, the adapter test suite drives every path:
  - start;
  - resume;
  - the permission bridge, allow and deny;
  - interrupt and kill;
  - not authenticated;
  - stream ended without a result;
  - usage/cost mapping;
  - event mapping for every protocol message kind.

  The fixtures are sanitized excerpts of real 2.1.283 transcripts.
- Launched through `localexec`, the adapter drives the phase-1a fake-free flow end to end: a fixture-replaying stub process started through the real launcher reaches `succeeded`, and domain transitions apply cleanly.
- A **live conformance test** runs against the real installed `claude`, gated by `CENTRAL_TEST_CLAUDE=1` and skipped by default. It uses `--model haiku` and a scratch git repo. It completes `start → permission request → allow → succeeded` and a `resume` that keeps the session id.
- Archguard stays clean. A new rule forbids every package except `localexec` itself (and its `_test` package) from importing `localexec`.
- The declared launch parameters make the recorded Task policy the one the harness enforces. The adapter fails closed when `system/init.permissionMode` differs from the policy's expected mode.
- `go test -race`, `go vet` and `go build` pass. Phase 1 tests stay green.

## 2. Findings that shape the design

### 2.1 The sandbox launcher cannot host a harness today

`internal/sandbox` is a prototype:

- it runs only `central-agent`, as a hard-coded UID 502;
- it has no stdio handoff, no cwd, no bind mounts and no network;
- it never places the child in its cgroup (no `cgroup.procs`);
- it is synchronous, run-to-completion;
- it has no systemd unit and no client.

The superseded ADR 0009 clause, still carried into the effective topology through ADR 0010 → 0011 → 0014, forbids request-chosen UIDs, mounts and executables. The governing spec (§8/§9) needs operator-UID scopes, bind-mounted worktree and harness config, egress, and stdio. ADR 0035 called the launcher reusable "as-is", which does not hold.

**Consequence:** production launching needs a governed launcher change (ADR 0036, phase 2b). Phase 2a proceeds on every path that decision does not gate (AGENTS.md delegation rule).

### 2.2 Claude Code 2.1.283 headless protocol (captured live)

- **Invocation:** `claude -p --verbose --output-format stream-json --input-format stream-json`.
  - The host first sends `{"type":"control_request","request_id":…,"request":{"subtype":"initialize"}}`.
  - It then sends `{"type":"user","message":{"role":"user","content":"<prompt>"}}`.
  - Closing stdin after the `result` message ends the process with exit 0.
- **Output order:**
  - `system/hook_*` (the operator's own hooks run);
  - `system/init`, carrying `session_id`, `cwd`, `tools`, `mcp_servers`, `model`, `permissionMode`, `apiKeySource`, `claude_code_version` and `capabilities`;
  - `assistant` and `user` messages (content blocks `text`, `thinking`, `tool_use`, `tool_result`);
  - `rate_limit_event`;
  - `result`, carrying `subtype`, `is_error`, `terminal_reason`, `total_cost_usd`, `usage`, `num_turns` and `session_id`.
- **Session id:** `--session-id <uuid>` preassigns it. `--resume <id>` keeps the **same** id and appends to `~/.claude/projects/<cwd>/<id>.jsonl`.
- **Permissions:**
  - `--permission-prompts host` plus `--permission-prompt-tool stdio` emits `control_request` `{"subtype":"can_use_tool","tool_name","input","permission_suggestions","blocked_path","tool_use_id"}`.
  - Allow: `{"type":"control_response","response":{"subtype":"success","request_id":…,"response":{"behavior":"allow","updatedInput":<input>}}}`.
  - Deny: `…{"behavior":"deny","message":"…","interrupt":false}`, which yields a `tool_result` with `is_error:true`.
  - `--permission-prompts none` auto-denies anything that would prompt.
  - `--permission-mode bypassPermissions` never prompts.
  - `--permission-prompt-tool` is hidden from `--help` in 2.1.283 but works. This is a version risk.
- **Interrupt:** `control_request` `{"subtype":"interrupt"}` → `result` with `subtype:"error_during_execution"`, `is_error:true`, `terminal_reason:"aborted_tools"`, exit 1.
- **SIGTERM:** exit 143 with **no** `result` line.
- **Not authenticated:**
  - exit 1, empty stderr;
  - `result` with `subtype:"success"` but `is_error:true` and `terminal_reason:"api_error"`;
  - an assistant message with `error:"authentication_failed"`.
- **Auth probe:** `claude auth status` prints JSON `{"loggedIn":bool,"authMethod",…}` without spending tokens.
- **No `--max-turns` flag** exists in 2.1.283.

## 3. Decisions (brainstorming; recommended option taken per the maintainer's workflow)

| # | Question | Decision | Reason |
| --- | --- | --- | --- |
| 1 | Scope of phase 2? | **Split.** **2a** (this spec): adapter, `ProcessLauncher` port, `localexec` dev launcher, the phase-2 domain follow-ups, and ADR 0036 as Proposed. **2b**: the sandbox launcher's harness launch class, after ADR 0036 is accepted. | The sandbox change is a governed trust-boundary decision (§2.1). The adapter does not depend on it once launching sits behind a port. |
| 2 | Where does process launching live? | **`internal/harness/port/launcher.go`** defines `ProcessLauncher`, `ProcessSpec` and `Process` (context and io only; no `os`). Adapters depend on the port. Implementations are `internal/adapter/harness/localexec` (dev/test) and, later, the sandbox client. | This honours "no direct exec from serve" (governing spec §4), keeps the adapter testable with in-memory pipes, and lets 2b swap the implementation. |
| 3 | Who picks the scope id? | **Central.** `ProcessSpec.ScopeID` is taken from `StartSpec.Env.SandboxScopeID`, and the launcher uses it as the scope name. | The attempt can record the scope id before the process exists, which matches the 1b rule that `StartSpec` requires it. |
| 4 | Harness session id? | **Preassigned:** `--session-id <attempt id>` on start. `--resume <ResumeSessionID>` on resume keeps that id. The adapter checks that `system/init.session_id` matches the expected id; a mismatch ends with `failed` / `harness_session_mismatch`. Capability `PreassignSessionID` is added (default false). | The id is known before launch, which removes the launching→ambiguous gap for Claude. It also closes the 1a follow-up I4 for Claude. |
| 5 | Resume that yields a new id (1a I4)? | **Domain rule:** `RevealSession` on an attempt with a non-empty `ResumeSessionID` must reveal that same id, else `ErrSessionMismatch`. A future harness that legitimately forks ids would need a capability and a spec change. | Verified: Claude keeps the id. A silent fresh session stays impossible. |
| 6 | Permission policy mapping? | Every policy passes an **explicit** `--permission-mode`, so settings cannot choose it:<br>• `deny` → `--permission-mode dontAsk --permission-prompts none`.<br>• `bridge` → `--permission-mode <default mode> --permission-prompts host --permission-prompt-tool stdio`, with `can_use_tool` → `PermissionRequested` and `RespondPermission` → `control_response`.<br>• `auto_allow` → `--permission-mode bypassPermissions`, an explicit operator choice recorded on the Task.<br>The default mode's CLI token (`manual` per `--help`; `system/init` reports it as `default`) is confirmed live at plan stage. The adapter checks `system/init.permissionMode` against the policy's expected value; a mismatch → kill, then `failed` / `harness_policy_mismatch`. A `can_use_tool` arriving under `deny` or `auto_allow` is answered with deny and emits a `Warning`. | These are the harness's own seams; nothing is scraped. Under `-p`, `--permission-prompts none` explicitly leaves "everything else" to the permission mode, so an unset mode would let a settings file decide. There is never a silent fallback to bypass. |
| 7 | Operator config and hooks? | The **operator's user-level** config applies unchanged: hooks, plugins, skills, MCP servers and allow rules from `~/.claude`. **Repo-level settings do not load:** the adapter passes `--setting-sources user`, so a worktree's `.claude/settings*.json` cannot add hooks, allow rules or a default mode. No `--bare`, `--safe-mode`, `--strict-mcp-config` or `--settings`. Project `.mcp.json`: the plan stage verifies live whether `-p --setting-sources user` still starts project MCP servers. If it does, the adapter refuses to launch when the worktree root contains `.mcp.json` → `failed` / `harness_untrusted_project_config`. | `-p` skips the workspace trust dialog, so settings from an untrusted branch would otherwise run hooks and allow tools as the operator, contradicting the Task's policy. User-level config is the operator's own trust decision. Excluding untrusted repo config is a declared launch parameter, not a change to the operator's config (ADR 0035 §4). |
| 8 | Declared launch parameters (the only flags Central passes)? | `-p --verbose --output-format stream-json --input-format stream-json --setting-sources user`, `--session-id` or `--resume`, the policy flags of decision 6, and `--model <m>` when `StartSpec.Model` is set. The prompt goes over stdin, never argv. | This is a closed list. Anything else is intervention. Keeping the prompt out of argv keeps it out of `ps`. |
| 9 | `Terminal.Reason` normalization (1b M4)? | The adapter sets `Reason` only from a **fixed vocabulary**: `harness_not_authenticated`, `harness_api_error`, `harness_aborted`, `harness_exited_without_result`, `harness_session_mismatch`, `harness_protocol_error`, `harness_max_turns`, `harness_budget`, `harness_policy_mismatch`, `harness_untrusted_project_config`. Harness free text never reaches `Reason`. The vocabulary is exported by the adapter and pinned by a test. | This closes M4: no harness-echoed text is persisted in `terminal_reason`. |
| 10 | Env hardening (1a follow-up)? | `harness.ValidateLaunchEnv`'s denylist adds the prefixes `LD_` and `DYLD_` and the suffix `_PROXY`, and matches denylist rules **case-insensitively** (the name is uppercased before the prefix, suffix and exact checks). The allowlist stays case-sensitive. | This closes loader injection, other proxy names, and lower-case credential names (e.g. `github_token`) passed as extras. |
| 11 | Launch env from empty (1a follow-up)? | The adapter builds `ProcessSpec.Env` only from the validated `StartSpec.Env.Vars`, with no inheritance. Each launcher derives `HOME` and `USER`/`LOGNAME` from the target user's passwd entry. `localexec` takes an **explicitly configured operator UID** and refuses to run if `os.Getuid()` differs from it or is 0. Its program map accepts only absolute paths: an unknown name is an error, with no `LookPath`. The adapter requires `PATH` in `Vars` and refuses `Start` and `Probe` otherwise. | This implements governing spec §9. `localexec` can never run as root, as a different user, or an unlisted program. |
| 12 | Probe? | `claude --version` (parsed strictly) and `claude auth status`, both through the launcher, spending no tokens. They run in `Config.ProbeWorkDir` (default `os.TempDir()`) under `LaunchEnv.SandboxScopeID`. The auth JSON is decoded into a struct holding only `loggedIn` and `authMethod`, mapped to an enum. Each output read is capped at 64 KiB. Stdout and stderr are **never** copied into `ProbeResult.Detail`, errors or logs, because they may carry account identifiers. The version is compared with the pinned version (`2.1.283`). A mismatch → `Detail` says so, and `Start` refuses unless the adapter was built with `AllowUnpinned`. | Covers governing spec §12 version pinning and the "not logged in → fail fast" rule without reading credential files. |
| 13 | Kill ladder? | `Interrupt` → `control_request interrupt`. `Kill` → `Process.Kill`: the launcher sends SIGTERM to the process group or scope, waits a 5 s grace, then SIGKILL. A stream EOF without `result` → `killed` if a kill was requested, else `failed` / `harness_exited_without_result`. | Matches the protocol facts. SIGTERM yields no `result` line. |
| 14 | Usage mapping? | From `result`: `usage.input_tokens`, `output_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens`, plus `total_cost_usd` × 1e6 rounded to micro-USD. `Scope = session_cumulative`, `Estimated = true` (client-side estimate per the docs). | Consistent with the 1b cumulative `ApplyUsage` rules. |
| 15 | Keeping `localexec` out of production? | New archguard rule `harness-launcher-boundary`: **no package** may import `internal/adapter/harness/localexec` except `localexec` itself. The adapter+`localexec` integration test and the live conformance test live in `internal/adapter/harness/localexec` as `package localexec_test`, which archguard sees as the `localexec` package path. | The analyzer checks direct imports only. With no importer other than itself, nothing in `serve` can reach `localexec`, directly or transitively. |

**Approaches considered:**

- **(A, chosen)** The adapter sits on a launcher port, with a dev launcher now and the sandbox launcher in 2b.
- **(B)** Extend the sandbox launcher first, then build the adapter. Rejected: this blocks all harness progress on a governed trust-boundary decision the adapter does not need.
- **(C)** The adapter calls `os/exec` directly. Rejected: this violates governing spec §4 and would need a rewrite for 2b.

## 4. Components

- **`internal/harness/port/launcher.go`:**
  - `ProcessSpec{Program string; Args []string; Env map[string]string; WorkDir string; ScopeID string}`. `Program` is a symbolic name such as `"claude"`; each launcher resolves it through its own allowlist and configuration.
  - `ExitStatus{Code int; Signaled bool}`.
  - `Process` interface: `ScopeID() string`, `Stdin() io.WriteCloser`, `Stdout() io.Reader`, `Stderr() io.Reader`, `Wait(ctx) (ExitStatus, error)`, `Kill(ctx) error`.
  - `ProcessLauncher` interface: `Launch(ctx, ProcessSpec) (Process, error)`, `Alive(ctx, scopeID string) (bool, error)`.
  - `ProcessSpec.Validate()` requires a program, a scope id and a workdir, and runs `harness.ValidateLaunchEnv(Env, nil)`.
  - Printing `ProcessSpec` never shows `Args`, which may contain `--resume` ids but never the prompt, or env values.
- **`internal/adapter/harness/localexec`:**
  - Resolves `Program` from a configured map (for example `{"claude": "/home/op/.local/bin/claude"}`).
  - Runs as the current user, with `HOME`/`USER`/`LOGNAME` derived from passwd, `Setpgid`, and stdio pipes.
  - `Kill` sends SIGTERM to the pgid, waits 5 s, then SIGKILL.
  - `Alive` keeps an in-memory scope→pgid map (dev only) and sends signal 0.
- **`internal/adapter/harness/claudecode`:**
  - `Adapter` is built with `New(Config{Launcher port.ProcessLauncher; PinnedVersion string; AllowUnpinned bool})`.
  - It implements `port.Adapter` with the capabilities of decision 16.
  - It holds a session reader goroutine that parses NDJSON and maps it to normalized events (§5), writes control messages, correlates permission requests, and computes the terminal state.
- **Domain (`internal/harness`):**
  - `Capabilities.PreassignSessionID`.
  - The `RevealSession` resume-id rule.
  - The env denylist hardening.
  - Updated `env_internal_test` pins.
- **Archguard:** the `harness-launcher-boundary` rule.
- **Tests:**
  - scripted `Process` fakes;
  - sanitized fixtures in `internal/adapter/harness/claudecode/testdata/` (ids replaced, the tool, plugin and slash-command lists trimmed, no user paths);
  - `localexec` tests with a `/bin/sh` stub;
  - the gated live conformance test.

**Decision 16 — capabilities:**

| Capability | Value |
| --- | --- |
| `StreamingInput` | ✓ |
| `Interrupt` | ✓ |
| `ResumeByID` | ✓ |
| `PreassignSessionID` | ✓ |
| `PermissionBridge` | ✓ |
| `UsageTokens` | ✓ |
| `CostUSD` | ✓ |
| `UsageScope` | `session_cumulative` |
| `Fork` | ✗ |
| `PartialDeltas` | ✗ (no `--include-partial-messages`) |
| `Reattach` | ✗ |
| `AutoResumeOnRestart` | ✗ |

## 5. Event mapping

| Claude message | Normalized event(s) |
| --- | --- |
| `system/init` | `SessionStarted{HarnessSessionID, HarnessVersion: claude_code_version, Model, Tools, ReportedCapabilities: capabilities}`, after checking the id against the expected one |
| `assistant` block `text` | `Message{assistant}` |
| `assistant` block `thinking` | `Reasoning` |
| `assistant` block `tool_use` | `ToolCall{ID, Name, Input}` |
| `user` block `tool_result` | `ToolResult{ID, Status: ok / error (is_error)}`. If the `tool_use_id` was denied, either by the host (`PermissionResolved{deny}`) or by the harness policy (`system/permission_denied` with that `tool_use_id`), the status is `denied`. |
| `control_request can_use_tool` | `PermissionRequested{RequestID: request_id, Tool: tool_name, Resources: [blocked_path] if set}` |
| host `RespondPermission` | `PermissionResolved{…, Decision, DecidedBy}`, emitted by the adapter when it queues the `control_response` for stdin (before the write completes; a later ctx or write error does not retract it) |
| `system/api_retry` | `Retry{Reason: "api_retry"}` (no harness text) |
| `result` | `UsageReport` (decision 14) for every result; the last one (`queued_turn_count` 0 or absent) is then followed by `TerminalReported` (§6) |
| `system/permission_denied` | not emitted by itself; it records the `tool_use_id` so that its `ToolResult` becomes `denied` |
| `system/hook_*`, `rate_limit_event`, `stream_event`, `control_response` acks | not emitted; they stay in the raw stream |
| an unknown `type` | `Warning{Message: "unrecognized harness message"}`; the raw frame is kept |
| a malformed JSON line | `Warning{Message: "malformed harness frame"}`; the session continues |

Every emitted event carries the untouched source line as `Raw`. Sequence numbers are adapter-assigned and monotonic.

## 6. Terminal mapping

| Condition | Terminal |
| --- | --- |
| `result` with `is_error:false` | `succeeded` |
| `result` with `terminal_reason:"api_error"` and an earlier `authentication_failed` assistant error | `failed` / `harness_not_authenticated` |
| `result` with `terminal_reason:"api_error"` otherwise | `failed` / `harness_api_error` |
| `result` with `terminal_reason:"aborted_tools"`, or `subtype:"error_during_execution"` after a host interrupt | `interrupted` / `harness_aborted` |
| `result` with `subtype:"error_max_turns"` | `max_turns` / `harness_max_turns` |
| `result` with `subtype:"error_max_budget_usd"` | `budget` / `harness_budget` |
| any other `result` with `is_error:true` | `failed` / `harness_api_error` |
| EOF without `result` after `Kill` | `killed` |
| EOF without `result` otherwise | `failed` / `harness_exited_without_result` |
| session id mismatch at `system/init` | the adapter kills the process → `failed` / `harness_session_mismatch` |

`Terminal.ExitCode` is set from `Process.Wait` when it is available.

**`Reconcile`** (`Reattach` is false): it returns `ReconcileResult{ScopeAlive: Launcher.Alive(in.SandboxScopeID), Reattached: nil, Terminal: nil}`. The caller decides ambiguity (governing spec §8).

## 7. Error handling and security

- The adapter never reads files under `HOME`, never sets credential env, and never passes `--settings`, `--bare` or `--safe-mode`.
- **Residual risk (disclosed):** under every policy, the operator's own user-level allow rules and hooks run unchecked by Central. They are the operator's trust decisions (decision 7).
- Error text never includes prompts, tool input, or harness free text.
- `RespondPermission` on an unknown or already-answered request id → an error (no silent write).
- Stdin has a single writer goroutine fed by a FIFO queue; no lock is held across a `Write`, so a harness that stops reading stdin blocks only that writer (and callers waiting on their own line, within their ctx), never `Kill` or the reader. The reader is one goroutine. Channels are closed after the terminal event. `Wait` returns after both the reader and the process are done.
- A cancelled `ctx` passed to `Start` stops only the launch. The session lives until `Kill` or `Interrupt`.

## 8. Testing

- **Unit tests (no binary):** a scripted `port.Process` built on `io.Pipe`, replaying sanitized fixtures and asserting on the control messages the adapter writes. It covers every row of §5 and §6, the three permission policies' argv, `--session-id` vs `--resume` argv, id-mismatch handling, and usage rounding.
- **`localexec`:** it launches `/bin/sh -c` stubs. It checks env-from-empty (the child prints its env), HOME derivation, the pgid kill ladder, `Alive` before and after kill, and refusal on a UID mismatch (a simulated resolver).
- **Adapter with `localexec` and a stub:** a `/bin/sh` script `cat`s a fixture while reading stdin, driving the full port through a real process.
- **Live conformance** (`CENTRAL_TEST_CLAUDE=1`, skipped by default; lives in `package localexec_test`):
  - It uses a scratch git repo under `t.TempDir()`, asserted to contain no `.claude/` and no `.mcp.json`, with `--model haiku`.
  - A `bridge` policy prompt runs `echo probe > probe.txt`.
  - The test allows **only** `tool_name=="Bash"` with `input.command=="echo probe > probe.txt"`. It denies anything else and fails. It also fails if no `PermissionRequested` arrives, because that would mean an operator default mode bypassed the bridge.
  - It asserts the file exists and that the run reaches `succeeded`.
  - It then resumes with a follow-up under the same rule and asserts the same session id.
  - It spends a few cents from the operator's own account, and writes `~/.claude/projects/<tmp>/…` plus likely an entry in `~/.claude.json`. The doc comment discloses both.
- **Domain:** the resume-id rule, and env hardening (`LD_PRELOAD`, `ftp_proxy`/`FTP_PROXY`, and a lower-case `github_token` extra are all rejected).
- **Adapter:**
  - policy→argv (`--permission-mode`, `--setting-sources user`) for each policy;
  - a `permissionMode` mismatch → `harness_policy_mismatch`;
  - `can_use_tool` under `deny` → deny answer plus a `Warning`;
  - a `system/permission_denied` → `ToolResult{denied}`;
  - `Reconcile` → `Alive`;
  - a missing `PATH` → error;
  - Probe output capping and non-copying (a fixture with an email field in `auth status` never appears in `ProbeResult` or errors).
- **`localexec`:** refuses UID 0 and a UID mismatch; refuses relative program paths; unknown program → error.
- **Archguard:** a test for `harness-launcher-boundary`.

## 9. Out of scope

- **Phase 2b:** the separate `central-harness-launcher`, per ADR 0036 (governance route (b)).
- **Phase 3:** the app service, serve wiring, artifact capture, the approval UI, and binding the fence to the lease.
- **Phase 4–5:** OpenCode v2 and ACP.
- **Isolating the operator's Claude config:** decision 7 rules it out.

## 10. Plan-stage findings (live-verified, 2026-09-27)

These amend decisions 6, 7, 12 and 14 with results from the verified draft (claude 2.1.283, `--model haiku`).

- **Decision 6, default-mode token:**
  - `bridge` passes `--permission-mode manual`, which `system/init` reports as `default`.
  - `deny` (`dontAsk`) and `auto_allow` (`bypassPermissions`) report their own tokens.
  - `system/init` appears only after the first user message, so the mode check happens then.
- **Decision 7, project `.mcp.json`:**
  - With `-p --setting-sources user`, a project `.mcp.json` server did **not** start: no marker file appeared, and it was absent from `init.mcp_servers`.
  - The adapter therefore does **not** refuse launch. `harness_untrusted_project_config` stays in the pinned vocabulary as a reserved value.
  - **Residual risk (disclosed):** an operator's user-level `enableAllProjectMcpServers: true` was not tested and may start project servers. It is the operator's own setting (decision 7).
- **Decision 7, repo `.claude/` (plan review S1):**
  - Verified live with a hostile repo `.claude/`: `settings.json` and `settings.local.json` with SessionStart/PreToolUse marker hooks, `defaultMode: bypassPermissions` and `allow: ["Bash(*)"]`, plus an agent with `permissionMode: bypassPermissions`, a skill with `allowed-tools: Bash`, and a command.
  - Under `-p --setting-sources user` none of it loaded: no marker file appeared, the Bash call still raised `PermissionRequested`, and init reported mode `default` with no project agents, skills or commands.
  - Gated test: `TestLiveClaudeCodeIgnoresHostileProjectConfig`.
- **Fail-closed ordering (plan review T-I3, S4):**
  - A `can_use_tool`, `result`, assistant or user frame before `system/init` → kill, then `failed` / `harness_protocol_error`.
  - At init, `claude_code_version` must equal the pin unless `AllowUnpinned` → else kill, then `failed` / `harness_protocol_error`.
- **`PATH` (plan review S2):** every `PATH` entry must be a non-empty absolute directory, else `Start`, `Resume` and `Probe` refuse.
- **Decision 12, version enforcement:** `Start` and `Resume` run `claude --version` through the launcher under the attempt's scope before the session launch. They refuse a mismatch unless `AllowUnpinned` is set.
- **Decision 14, usage within an attempt and across resume (final re-review N1):**
  - Under `--input-format stream-json`, each `result`'s `usage` tokens are that turn's own, while `total_cost_usd` is cumulative across the process's turns ("read the latest result rather than summing").
  - The adapter therefore sums the tokens of every `result` in the process and reports the running sums. Cost is taken from the latest `result`, but never lower than a cost already reported (a crash result or `/clear` can zero or reset it). The report stays `session_cumulative`, `Estimated`, so `ApplyUsage` never sees a counter decrease.
  - Across a resume chain, tokens restart per process, while `total_cost_usd` is cumulative for the whole session.
  - **Phase 3 budget rule (unchanged):** sum tokens across a chain's attempts, but take cost from the latest attempt only. Never sum cost.
- **Launch-value safety:** in addition to decision 8, the session and resume ids must be canonical lower-case UUIDs, and `--model` must be a plain identifier that does not start with `-`. Anything else is refused, never altered. `Limits.MaxTurns > 0` returns `port.ErrUnsupported`, because Claude has no such flag.
- **§5 additions:**
  - Adapter-originated events carry the line the adapter wrote, or a synthetic `central_stream_ended` line, as `Raw`.
  - A `control_request` subtype other than `can_use_tool` is answered with an error `control_response` plus a `Warning`, so the harness never hangs.
  - Prompt-replay user frames and `system` subtypes other than `init`, `permission_denied` and `api_retry` are not emitted.
- **Queued turns (final review I1):**
  - A user message sent mid-turn (`Send`) is queued by 2.1.283 and run as a further turn in the same process. Each turn ends with its own `result`, which carries `queued_turn_count` (turns still queued) and `result_index`.
  - Every `result` emits a `session_cumulative` `UsageReport` with the running sums (decision 14 above). A `result` with `queued_turn_count > 0` ends only its turn: stdin stays open and pending permissions stay answerable.
  - An interrupt aborts only the running turn; queued turns survive it (2.1.283 answers it with `still_queued`, and the adapter never sends `cancel_queued`). The harness acknowledges an interrupt before the aborted turn's `result`, so an interrupt acknowledged by a non-final `result` is spent on that turn, and a later turn's unrelated `error_during_execution` maps by §6 without it. One not yet acknowledged applies to the next turn.
  - Only the last `result` (`queued_turn_count` 0 or absent) ends the session: the terminal is mapped from it (§6), stdin is closed, and a later `can_use_tool` is not bridged.
  - If the process exits after a non-final `result` and before the last one, the terminal is `failed` / `harness_exited_without_result` (fail closed).
  - The session ends on the last `result` barring cancellation: a queued turn that is cancelled without a `result` carrying `queued_turn_count` 0 leaves the session idle, with stdin open, until `Kill`.
  - A `Send` that races the last `result` is best-effort: the harness may run another turn whose frames and cost are not reported, or the line may be dropped when stdin closes (documented on `port.Session.Send`).
- **Scope reuse (final review I2):** `Start` and `Resume` launch the `--version` probe and then the session under the same `SandboxScopeID`, and `Probe` runs two commands under one scope. `port.ProcessLauncher` documents that a launcher must admit a new launch under a scope once the previous tree is gone, and that `Alive` may briefly report the probe. The 2b launcher (systemd/cgroup scopes) must honour this, or the adapter must move probes to a derived scope.
- **Hidden flag:** `--permission-prompt-tool stdio` is hidden in 2.1.283. Any change to the pinned version must re-run the live conformance test and the checks above.
