# Issue #128 — Codex session adapter (third harness backend) — design spec

Status: draft. Pipeline input for issue #128
("[Harness] Add Codex session adapter (third harness backend)").
Implements a production Codex backend behind the ADR 0035
harness-session boundary, following the OpenCode adapter (#126,
PR #127) as the model implementation, against the only verifiable
Codex surface: `codex exec --json` over stdio, pinned at 0.162.1.

## Scope

Owns:

- a production `port.Adapter` for Codex (`internal/adapter/harness/codex`):
  launch, JSONL event streaming, cancel/kill, wall-clock/token
  backstops through reported usage, artifact capture through the
  unchanged 3b path, and Deny-only permission semantics;
- serve wiring: the Codex backend on the existing selector (default
  stays Claude Code), per-backend version pins, and the shared
  adapter factory used by both the phase-3a path (`composeHarness`)
  and the phase-2 path (`composeSchedulerHarness`);
- fail-closed refusal of explicit cost controls under the Codex
  backend (the harness reports no cost): serve refuses startup when
  `CENTRAL_HARNESS_MAX_COST_USD` or
  `CENTRAL_HARNESS_TASK_COST_CAP_USD` is explicitly set, and submit
  refuses an explicit `budget_cost_usd`;
- the launcher-daemon argv grammar for codex plus its
  `test_launcher.py` cases (wire format unchanged), and the
  `CODEX_HOME` relocation guard in `internal/harness/env.go` with its
  daemon mirror;
- `packaging/harness/setup.sh` support for the codex program,
  harness home and mounts;
- the runbook extension (`docs/operations/harness-execution.md`):
  install, login, enable, version-pin update flow;
- a maintainer-run rehearsal: one submitted Task end to end through
  the codex backend with captured artifacts, with exact commands
  documented (no harness credentials exist in this environment, so
  the pipeline itself cannot run it; criterion 5 allows a
  maintainer run).

Does NOT own: any change to #110 (the physical campaign stays pinned
on Claude Code sessions); any weakening of permission,
peer-authorization or ceremony checks; any wire-format change; any new
reason code or event kind (every adapter reason reuses an
`execution.FailureReason` string verbatim); any edit to historical
evidence files; Bridge/Auto-allow mapping for Codex (refused
fail-closed); app-server/exec-server/SSE, MCP bridging, reasoning
passthrough, fork, reattach, multi-backend serve, per-Task backend
selection.

## Problem

Real harness execution is Claude-Code/OpenCode-only:
`internal/adapter/harness/` holds two production adapters
(`claudecode`, `opencode`) plus fake/test scaffolding, and both serve
composition sites select between them through `newHarnessAdapter`.
Codex (OpenAI's CLI harness) is not behind the boundary. Its headless
surface differs from both siblings in three load-bearing ways: `exec`
forces approval Never and leans on the OS sandbox for protection
(so Deny must be constructed from sandbox + auto-reject, not from a
permission flag); `resume` has no `-s` flag (so the sandbox must be
carried by a pinned `-c` literal or a resume silently downgrades to
read-only); and `turn.completed` reports tokens but no cost and as a
thread-cumulative total (so cost backstops are unenforceable and
usage needs the session_cumulative scope). This spec grounds the
third backend on the verified 0.162.1 surface with a per-item parity
table and fail-closed behavior for every gap.

## Brainstorm record (autonomous)

Context explored: issue #128; ADR 0035/0036; the #126 spec, plan and
reviews; the `claudecode` and `opencode` adapters
(adapter/argv/protocol/session/probe); `internal/harness`
(domain/events/usage/capability/env); the orchestrator, dispatcher
and bridge (`internal/harness/app`); both composition sites
(`cmd/central/harness_composition.go`, `scheduler_harness_wiring.go`,
`harness_backend.go`, `harness_config.go`); the launcher daemon
grammar (`cmd/central-harness-launcherd/policy.c`);
`packaging/harness/setup.sh`; the harness runbook; the web permission
and budget views; the installed `codex` 0.162.1 (npm
`@openai/codex@0.162.1`, live probes) and its `rust-v0.162.1` source
(exec JSONL schema and processor, approval/sandbox/config layers);
upstream release state (latest stable 0.162.1, 2026-10-09).

Questions asked and answers chosen:

1. *Which Codex, which surface?* 0.162.1, `codex exec --json` over
   stdio. The app-server/exec-server path would buy only reattach
   and bridging, both out of scope, at the price of a supervised
   server, port management and a second protocol client; the TUI is
   not headless; human-format scraping breaks on UI text.
2. *What does Deny mean for `exec`?* `exec` forces approval Never
   (S3) and auto-rejects every approval request (command, file
   change, user input, dynamic tools). Under Never, dangerous
   commands are Forbidden, sandbox denials fail the tool and are
   never retried unsandboxed (S4). Deny is therefore the default
   invocation plus `-s workspace-write`: in-scope work proceeds
   inside the sandbox, escalations fail closed.
3. *Why not the default sandbox?* The default is read-only (S12):
   the harness could not write the worktree, so 3b patch artifacts
   could never exist. `workspace-write` is the minimum that lets
   Central's capture path work; the boundary stays enforced (S4).
4. *How is the prompt delivered?* Over stdin with the `-` sentinel
   (Forced, silent, S3). Never positional, so prompt bytes never
   appear in `ps` output.
5. *How does resume keep the sandbox?* `exec resume` has no `-s`
   flag and the server applies the current config's sandbox as an
   override (S5/S6), so a bare resume would downgrade a
   workspace-write thread to read-only. Resume argv carries one
   pinned `-c` literal, `sandbox_mode="workspace-write"`, matched
   exactly by the Go builder and the daemon grammar. `--last` is
   never used (operator-global, not Central's recorded id).
6. *What is the interrupt seam?* The binary maps SIGINT to
   `turn/interrupt` (S3), but `port.Process` exposes no Signal and
   stdin closes after the prompt, so the seam is unreachable through
   the port. `Interrupt` returns an error like opencode, the
   orchestrator kills the scope at once, and the terminal is
   `killed`, never `interrupted`, on a Central stop.
7. *What is the auth signal?* `codex login status` (S9): exit 0
   means logged in, exit 1 means not (or an error). Probe runs it
   and reports `Authenticated` from the exit code only — its output
   is never logged (the API-key variant prints a masked key). The
   dispatcher pauses on false. Runtime auth/model failures surface
   as untyped `turn.failed` and map to `harness_api_error`; the
   adapter never inspects harness message text.
8. *How is project config handled?* Project layers load from the
   worktree's `.codex/` directory with full config power (providers,
   MCP, hooks, sandbox options, rules) when the project is trusted
   (S10). Trust records live in the operator's CODEX_HOME, so an
   operator-trusted worktree plus a hostile repo could widen
   capabilities. The adapter refuses a worktree containing `.codex`
   (any file type; stat failure also refuses), mirroring opencode's
   D6. `AGENTS.md` stays allowed: instructions only, like any repo
   content. No `--ignore-rules`/`--ignore-user-config`: user layers
   are the operator's own config and stay in force.
9. *Which reason strings may the adapter emit?* The same four
   verbatim `execution.FailureReason` strings as opencode:
   `harness_api_error` (a recorded `turn.failed`),
   `harness_exited_without_result` (empty or unmarked non-zero exit,
   covering resume-unknown and non-git),
   `harness_session_mismatch` (thread-id guard),
   `harness_protocol_error` (oversize line/scanner error). No
   `harness_not_authenticated` at runtime (no typed signal; the
   probe carries auth), no `harness_max_turns`/`harness_budget` (no
   native limit surface), no `harness_policy_mismatch` (Deny holds
   by construction of the closed argv).
10. *What about cost?* `turn.completed` usage carries tokens only
    (S1) as a thread-cumulative total (S11). Capabilities report
    `CostUSD: false`, `UsageScope: session_cumulative`. The Central
    cost backstop can never fire, so explicit cost controls refuse
    fail-closed instead of running silently unenforced: serve
    refuses startup when a cost var is explicitly set under codex,
    and submit refuses an explicit `budget_cost_usd` (D8/D9). The
    token ceiling and wall clock still bound every attempt. A
    resumed attempt over-attributes the thread total to itself
    (conservative for ceilings; documented, D7-3l/3m).
11. *Serve-wide or per-Task backend?* Serve-wide single backend.
    Mixed per-Task backends are not expressible; an unknown
    `CENTRAL_HARNESS_BACKEND` value refuses startup
    (`CONFIG_INVALID` naming the variable).
12. *What does the daemon need?* A closed argv grammar mirroring the
    Go builder (config lines for a harness id without a grammar are
    refused by `chl_harness_has_grammar`), the `login status` probe
    form, the codex program path, harness home and data-dir mounts
    via the existing config keys, and the `CODEX_HOME` exact-deny
    mirror. No wire change.

Approaches considered:

- **A. `exec --json` stdio adapter (chosen).** Mirrors the
  `opencode` package shape, reuses the orchestrator/dispatcher/
  capture paths unchanged, and every mapping below is verified
  against the pinned binary (E) or its pinned source (S).
- **B. app-server/exec-server + event stream.** Rejected: buys only
  reattach and bridging (both out of scope), needs server
  supervision, port management and a second protocol client.
- **C. TUI automation.** Rejected: not headless, no contract.
- **D. Human-format scraping.** Rejected: breaks on UI text
  changes (governing-design finding 6, reused from #126).

## Evidence

Live probes against the installed 0.162.1 (`E` = live run,
`S` = `rust-v0.162.1` source read). No harness credentials exist in
this environment, so model-backed runs are unverifiable here; every
wire shape the adapter parses is fixed by the serde schema (S1) and
the processor (S2) instead, and fixtures derived from them are
marked hand-built.

- E1: `exec --json` emits newline-delimited `{"type",...}`; observed
  types `thread.started` (with `thread_id`), `turn.started`,
  `error` (transient retry notices, non-terminal), `item.completed`
  (error item on transport fallback), `turn.failed{error}`. Exit 1
  on auth failure with `turn.failed` recorded.
- E2: `login status` exits 1 with `Not logged in` on stderr when no
  credentials are stored.
- E3: outside a git checkout, `exec` exits 1 with empty stdout
  (`Not inside a trusted directory...` on stderr, drained).
- E4: `exec resume` of an unknown UUID exits 1 with empty stdout
  (`Error: thread/resume ... no rollout found ...` on stderr).
- E5: `--version` prints exactly `codex-cli 0.162.1\n`.
- E6: a worktree `.codex/config.toml` with invalid TOML is ignored
  for a fresh (untrusted) project: the run proceeds to network and
  fails 401. Trust-gating confirmed; loading itself is per S10.
- E7: upstream latest stable is 0.162.1 (npm + `rust-v0.162.1`,
  2026-10-09); only newer tags are `0.163.0-alpha.*`.
- S1 (`exec/exec_events.rs`): the full JSONL schema — 8 event
  types, 9 item types, `Usage{input,cached_input,cache_write_input
  (defaulted),output,reasoning_output}` (no cost),
  `CommandExecutionStatus::{InProgress,Completed,Failed,Declined}`,
  `PatchApplyStatus` without Declined.
- S2 (`exec/event_processor_with_jsonl_output.rs`): agent_message/
  reasoning items emit only as `item.completed`; file_change
  Declined collapses to Failed; `TurnStatus::Interrupted` shuts
  down with NO event; `Error` notifications emit non-terminal
  `error` events; `turn.completed` usage is the last thread-total;
  warnings/config/deprecation/reroute become non-fatal error items.
- S3 (`exec/lib.rs`): exec builds config with approval Never
  (harness override, beats `-c`); every approval request is
  rejected in exec mode; ctrl_c sends `turn/interrupt`; `-`
   reads the prompt from stdin silently (Forced); the git check is
   `get_git_repo_root(cwd)`; a failed/interrupted turn exits 1.
- S4 (`core/exec_policy.rs`, `core/tools/sandboxing.rs`,
  `core/tools/orchestrator.rs`): under Never, dangerous commands
  are Forbidden and other commands run relying on the sandbox;
  `wants_no_sandbox_approval(Never)` is false, so sandbox denials
  fail the tool and are never retried unsandboxed.
- S5 (`core/config/mod.rs`, `exec/cli.rs`): `resume` has no `-s`;
   the resumed thread's sandbox derives from the current config
   (default read-only), so a bare resume downgrades the thread.
- S6 (`app-server/.../thread_processor.rs`): resume forwards
  sandbox/approval as thread config overrides (confirms S5).
- S7 (`protocol/thread_id.rs`): thread ids are UUIDv7, rendered
  hyphenated lowercase.
- S8 (`utils/home-dir`): home is `CODEX_HOME` or `~/.codex`
  (derived from the launcher-set HOME; Central never sets it).
- S9 (`cli/login.rs`): status exits 0 (`Logged in using ...`, mode
  words) or 1 (`Not logged in` / error); the API-key form prints a
  masked key, so probe output stays unread beyond the exit code.
- S10 (`config/loader`, `config/state.rs`, `core/agents_md.rs`):
  project layers come from `.codex/` directories (cwd up to the
  project root) carrying `config.toml` plus `rules/*.rules`,
  gated by per-dir trust; `AGENTS.md` is instructions only;
  skills arrive via operator plugins, not cwd scans.
- S11 (`core/tasks/mod.rs`): `total_token_usage` is cumulative and
  turn usage is derived as a delta, so the exec-visible total is
  thread-cumulative.
- S12 (`protocol/config_types.rs`): the default `SandboxMode` is
  read-only.

## Design

### D1 — Package shape

New package `internal/adapter/harness/codex`, mirroring
`opencode`:

- `codex.go`: `Kind = "codex"`, `DefaultPinnedVersion =
  "0.162.1"`, `program = "codex"`, `Config`, reason constants,
  `Reasons()`, `Capabilities()`.
- `argv.go`: the closed argv builder (D2).
- `protocol.go`: strict frame decode (D3).
- `session.go`: the event loop and terminal computation (D4).
- `probe.go`: the version + login-status probe (D5).
- `adapter.go`: `New`/`Start`/`Resume`/`Reconcile`, PATH
  requirement, `.codex` refusal (D6).

Capabilities: `ResumeByID`, `UsageTokens` true,
`UsageScope: session_cumulative`, `CostUSD` false; everything else
false (`StreamingInput`, `Interrupt`, `PreassignSessionID`, `Fork`,
`PermissionBridge`, `PartialDeltas`, `Reattach`,
`AutoResumeOnRestart`, `NativeCostLimit`).

### D2 — Closed argv

Fresh: `exec --json -s workspace-write [--model M] -`.
Resume: `exec resume --json -c sandbox_mode="workspace-write"
[--model M] <uuid> -`.
The prompt travels over stdin addressed by the `-` sentinel; no
message positionals, ever. The `-c` value is one exact literal
(constant in Go, exact match in C): the only `-c` the grammar
admits, required on resume (S5/S6) and never passed fresh (`-s`
covers fresh). No `--last` (operator-global, not Central's id), no
`-C`/`--cd` (the worktree comes from the launcher's `WorkDir`), no
`--add-dir`, `--worktree`, `--profile`, `--oss`,
`--local-provider`, `-i`, `-o`, `--output-schema`, `--enable`,
`--disable`, `--strict-config`, `--thread-source`,
`--cyber-access-program`, `--skip-git-repo-check`, `--ephemeral`,
`--ignore-user-config`, `--ignore-rules`, `--approve-for-me`,
`--dangerously-bypass-approvals-and-sandbox`,
`--dangerously-bypass-hook-trust`, `--color`: each would widen
writable roots, attach foreign state, change loop behavior, skip a
fail-closed check, or (ephemeral) drop the rollout resume needs.
`--model` accepts the `safeModel` charset (same rule as opencode:
non-empty, ≤128 bytes, not starting with `-`, alnum plus
`-._:/[]@`); codex validates the model server-side and an unknown
model fails the turn (→ `harness_api_error`, fail-closed). The
resume id accepts strict UUID shape only (S7):
`8-4-4-4-12` lowercase hex, hyphenated. The daemon grammar mirrors
this exactly (D11).

### D3 — Protocol mapping

One JSON object per stdout line, decoded strictly; the raw line is
kept as each emitted event's `Raw`:

| exec type | normalized events | notes |
| --- | --- | --- |
| `thread.started` | none (binds `thread_id`) | first id emits `SessionStarted{id, probedVersion, model}` + resolves `Ref()`; a differing id vs the resumed/first id stops the session (`harness_session_mismatch`); a same-id repeat is ignored |
| `turn.started` | none | no content |
| `turn.completed` | `UsageReport` | `TokensIn=input_tokens`, `TokensOut=output_tokens+reasoning_output_tokens` (saturating; both billed as output), `CacheRead=cached_input_tokens`, `CacheWrite=cache_write_input_tokens` (absent → 0, its serde default), `CostMicroUSD=0`, `Scope:session_cumulative`, `Estimated:false`; `total_tokens` ignored; the first `turn.completed` wins and a later one warns (fixed literal) + skips |
| `turn.failed` | recorded; terminal at stream end | never copied into `Reason` (D4) |
| `item.started` tool item | `ToolCall{id,name,input}` | tool items are `command_execution`, `file_change`, `mcp_tool_call`, `web_search`, `collab_tool_call`; `name` is the item type; `input` is the compact JSON of the discriminating field (per-type table pinned at plan stage), nil when absent |
| `item.completed` tool item | `ToolResult{id,status,output}` (+ a synthesized `ToolCall` when no start was seen) | `completed`→`ok`, `failed`→`error`, `declined`→`denied`; `in_progress` in a completed event warns (fixed literal) and maps to `error`; `output` is the compact JSON of the result field (plan-stage table), nil when absent; `file_change` normally arrives completed-only (S2) |
| `item.started`/`item.completed` `agent_message` | `Message{assistant, text, Partial:false}` on completed | started never carries it (S2) — a started agent_message/reasoning, should one appear, warns (fixed literal) + skips; empty text emits nothing |
| `item.*` `reasoning` | none | skipped silently (no passthrough) |
| `item.*` `todo_list` | none | skipped silently (no `Plan` mapping; Central owns planning) |
| `item.completed` `error` | `Warning` + skip | non-fatal by construction (S2); fixed literal, Raw kept |
| top-level `error` | `Warning` + skip | retry/transport notices (E1); never terminal by itself |
| `item.updated` | none | only todo lists update (S2); skipped (`PartialDeltas` false) |
| unknown type | `Warning` + skip | forward tolerance, like opencode |

Frame-error posture mirrors `opencode` (tolerant with warnings, not
strict stops). A malformed JSON line, an unknown `type`, a frame
with a missing `thread_id` where the schema requires correlation
(`thread.started`), or a per-frame field problem (undecodable text,
a tool part without id/shape, an unusable usage report) emits a
fixed-literal `Warning` carrying Raw and the frame is skipped; the
stream continues. Warning texts are fixed literals (same pattern as
opencode `warnMalformed`/`warnUnrecognized`), never harness text.
Only two classes stop the session: a `thread_id` that differs from
the resumed id or changes mid-stream (`harness_session_mismatch`),
and a stdout line over the frame bound (16 MiB, mirrored) or a
scanner error (`harness_protocol_error`, stream drained). An empty
stream closes `Ref()` unresolved at finish.

Usage numerics mirror `opencode`: token fields must be integral,
≥0 and int64-ranged JSON numbers — a fractional, negative or
out-of-range field, or a missing required field (`input_tokens`,
`cached_input_tokens`, `output_tokens`,
`reasoning_output_tokens`), makes the report unusable (Warning +
skip, never a stop); the output+reasoning sum saturates at MaxInt64.

### D4 — Session lifecycle and terminal

`Start` writes the prompt to stdin and closes it (like opencode's
`begin`); stdout is decoded per D3; stderr is drained and discarded
(it carries messages such as `no rollout found`, trust warnings and
PATH-alias notes, never mapped to `Reason`). Sequence numbers are
adapter-assigned, monotonic per attempt.

Terminal computation at stream end (mirror of opencode `finish`):

1. adapter-initiated stop (protocol/session mismatch) →
   `failed` + stop reason;
2. else `turn.failed` recorded → `failed` + `harness_api_error`;
3. else `Kill` requested → `killed` (empty reason, Central's own);
4. else exit 0 → `succeeded` (empty reason);
5. else → `failed` + `harness_exited_without_result` (covers the
   empty-stream resume refusal, the non-git refusal, the
   no-terminal-event interrupt shutdown, and any silent non-zero
   exit).

`Interrupt` returns an error (no seam through the port, Q6): the
orchestrator kills the scope at once, so a Central stop always
settles `killed`. Once the terminal is recorded, `Interrupt`
returns `ErrSessionEnded` instead (mirror of opencode), so a
post-result stop path never kills at once. `Send` returns
`ErrUnsupported` (no production caller exists).
`RespondPermission` returns `ErrNoPendingPermission` (no request is
ever emitted). `Wait`/`Kill` follow the `port.Process` contract;
`Events` closes after the terminal event.

### D5 — Probe

`codex --version` through the launcher in the probe workdir, parsed
strictly (`codex-cli 0.162.1`, E5; exact bytes pinned at plan
stage), plus `codex login status` whose exit code alone sets
`Authenticated` (0 true, else false; S9). Both commands run under
one scope (the claudecode two-command precedent). `login status`
output is drained and discarded, never parsed, logged or recorded:
the API-key form prints a masked key. A version mismatch fails each
attempt at `Start` (like opencode), not at probe: the dispatcher
does not gate on version. It pauses on `Authenticated: false`.

### D6 — Start/Resume/Reconcile

`Start`/`Resume` validate the spec, require the absolute-dir `PATH`,
refuse `Permission != deny` with `ErrUnsupported`, refuse positive
`Limits.MaxTurns`/`MaxCostMicroUSD` (no native surface; the
orchestrator already withholds the cost limit when `NativeCostLimit`
is false), refuse a worktree containing `.codex` (any file type;
stat failure also refuses, → `ErrInvalidLaunch` naming `.codex`),
check the pinned version, then launch. Resume requires a
strict-UUID `ref.HarnessSessionID`, else `ErrInvalidLaunch`, and
passes the pinned `-c` sandbox literal (D2); the id guard in D3
makes a silent fresh session impossible. `Reconcile` reports scope
aliveness only (no reattach): a live scope is killed and the
attempt goes `ambiguous`, exactly like opencode.

### D7 — Parity surface (3a–3m)

| Phase | Codex backend | Fail-closed gap behavior |
| --- | --- | --- |
| 3a serve wiring | supported via the backend selector (D9) | unknown backend refuses startup |
| 3b artifacts (report/patch/commits) | supported unchanged (report = final `agent_message` text; patch/commits from the worktree) | empty final text follows the existing report-missing path |
| 3c approvals | Deny supported (S3/S4 + closed argv) | Bridge/Auto-allow refused at Start (D8) |
| 3d budgets | wall clock + token ceiling supported | no cost backstop (no cost signal); explicit cost controls refused (D8/D9) |
| 3e cancel/recovery | cancel via scope kill; recovery via kill + `ambiguous` | terminal is `killed`, never `interrupted` |
| 3f prepared cancel/epoch resume | supported (adapter-independent + `Resume`) | — |
| 3g resume ambiguous | supported via `resume` + id guard | unknown id fails the attempt, never a silent fresh session |
| 3h eligibility guard | supported (adapter-independent) | — |
| 3i resume minors | supported (adapter-independent) | — |
| 3j task cost cap | UNSUPPORTED (no cost signal) | explicit caps refused at config (D9) and submit (D8); serve defaults stay inert and documented |
| 3k rerun | supported (adapter-independent) | — |
| 3l token ceiling | supported (usage-driven; billed = in+out+cache-write, reasoning folded into out) | usage is reported only when the turn completes, so failed or killed attempts record no usage (attempts stay bounded by MaxAttempts + wall clock); resumed attempts over-attribute the thread total (conservative for ceilings) |
| 3m live usage display | partial (usage-driven, one end-of-turn report) | no streaming usage; display updates once per attempt, only on success |

### D8 — Non-Deny and explicit-cost refusal

Backstop (required): the adapter refuses `bridge`/`auto_allow` at
Start/Resume (D6) → the Run settles `harness_launch_failed` with the
cause in the error (never a silent downgrade to deny).
Submit-time (required): under the codex backend the submit form
offers deny only, with a note naming the backend; a submit carrying
bridge/auto_allow is refused server-side; a submit carrying an
explicit `budget_cost_usd` is refused server-side (400), because a
cost limit Central cannot enforce must not be silently accepted.
The wall-clock field stays. Exact handler and plumbing
(`HarnessOperator` backend surfacing already exists from #126) are
pinned at plan stage.

### D9 — Serve wiring

- `CENTRAL_HARNESS_BACKEND=claude-code|opencode|codex`, default
  `claude-code`, validated only when harness execution is enabled. An
  unknown value refuses startup with `errHarnessConfig` naming
  `CENTRAL_HARNESS_BACKEND` (reported as `CONFIG_INVALID`).
- `CENTRAL_HARNESS_CODEX_VERSION`, default `0.162.1`, shape
  `1.2.3`, same validation as the sibling pins. The non-selected
  backends' version vars are ignored (documented).
- Under `codex`, an explicitly set `CENTRAL_HARNESS_MAX_COST_USD`
  or `CENTRAL_HARNESS_TASK_COST_CAP_USD` refuses startup with
  `errHarnessConfig` naming that variable: an operator who asks for
  cost enforcement must not get silent non-enforcement. Unset vars
  keep their defaults, which stay inert on this backend
  (documented in the runbook).
- Shared factory `newHarnessAdapter(hc, launcher)` gains the codex
  arm returning the recorded adapter version (`codex/issue-128`),
  used by both `composeHarness` and `composeSchedulerHarness`. The
  backend is serve-wide; per-Task mixing is not expressible.
- #110 is untouched: the campaign stays on the default backend via
  its specs/plans; no gate changes.

### D10 — Deployment: program, home, mounts

`setup.sh` gains `--codex-program PATH` (same `path_shape` charset
rule as the siblings; no default resolution — absent means codex
stays unconfigured with a note, NOT a die, so existing installs
keep working) and writes a third harness home (`harness-home/codex`)
with a mount point for the codex data dir `.codex` (auth, config,
sessions, trust), read-write (the harness's own state), plus the
read-only program mount when the program lives under HOME. The
visibility rule mirrors claude (exact paths pinned at plan stage);
the runbook tells the operator to install the pinned release binary
outside `~/.codex` (verified checksum) or pass `--codex-program`.
Daemon config lines use the existing keys (`harness codex <path>`,
`home_dir`, `mount`).

### D11 — Daemon grammar

`policy.c` gains `codex_argv_kind`: probes `["--version"]` and
`["login", "status"]` → `ARGV_PROBE`; else the D2 fresh/resume
forms with `--model`/`-c`-literal/`-`/uuid in fixed order, each at
most once → `ARGV_SESSION`; anything else → `ARGV_REFUSED`. Reuse
`valid_model` as-is; add `valid_uuid` (strict
`8-4-4-4-12` lowercase hex); match the `-c` value by exact literal
(`sandbox_mode="workspace-write"`). `argc == 0` → `ARGV_REFUSED`
without dereferencing argv. Extend `chl_harness_has_grammar` and
the `chl_argv_kind` dispatch. The env policy gains the exact
`CODEX_HOME` deny (mirror of `env.go`). `test_launcher.py` gains
accept/refuse cases for every production. No `PROTOCOL.md` change
(wire untouched).

### D12 — Product surfaces

Web permission view: the deny-only note generalizes to the codex
backend (wording names the backend + a pointer to the runbook's
permission section). Budget view: the cost note is backend-aware
(codex: no cost reported, cost limits unenforced, token ceiling is
the spend bound; explicit cost input refused at submit). Wording is
pinned at plan stage; no new page or route.

### D13 — Docs and records

`docs/operations/harness-execution.md` gains the codex backend
section: install the pinned version (release binary + checksum, or
pinned npm; `--codex-program` override); login (`codex login`,
`login status`; no single free tier — per-model/auth failures
surface as `harness_api_error`); enable
(`CENTRAL_HARNESS_BACKEND=codex` + the standard harness env);
permission semantics (Never + workspace-write, auto-reject, the
`.codex` refusal, sandbox prerequisite); cost/token notes (no cost
signal, token ceiling + wall clock bound spend, cumulative usage,
resume over-attribution); troubleshooting (stale resume `no
rollout`, version mismatch, non-git worktree, sandbox/bwrap
warnings, explicit-cost refusals, and the note that
enterprise-managed (MDM/managed) codex config wins over CLI flags
by design, so an org profile can widen the sandbox as the
operator-org's responsibility); and the version-pin update flow
(verify new version → bump default +
`CENTRAL_HARNESS_CODEX_VERSION` → rerun setup → re-run conformance).
`docs/internal/tasks/` records the fix-requirement analysis per the
SC-DEF convention, including the maintainer-run rehearsal commands.

### D14 — Tests (machine tier)

- Unit: argv builder (accept/refuse matrix incl. prompt-never-in-argv,
  `-c`-literal exactness, `--last` refusal), frame decode (every D3
  row + malformed/unknown), session terminal table (D4), probe
  parsing (version + login-status exit codes), capabilities
  validation, config (selector + pin + explicit-cost refusals,
  invalid names the variable), composition (both sites select the
  backend; default unchanged), daemon grammar cases, `CODEX_HOME`
  env vectors.
- Fixtures: real captures where obtainable without credentials
  (auth-failure `turn.failed` stream E1, resume-unknown empty
  stream E4, `--version` bytes E5), sanitized before check-in
  (cf-ray/request-id/credential-adjacent tokens redacted, live ids
  replaced with fixed test UUIDs, worktree paths canonicalized to
  `/work`) plus the #126 testdata hygiene test (each file < 100 KB,
  text-only, marker-free); hand-built fixtures from the
  serde schema (S1/S2), marked hand-built: success text, command
  execution started/completed, file change completed-only, denied
  command, mcp call, web search, collab call, reasoning/todo skip,
  error-item warning, top-level error tolerance, turn.completed
  usage, unknown-type tolerance, resume same-id.
- Integration: scripted launcher runs (launch/stream/cancel/capture/
  policy-refusal/cost-agnosticism) through `localexec`.
- Live (gated, same convention as the sibling live tests): probe
  version + login-gated tiny run (skips without login; one model
  call when logged in). No live deny-check: Deny rests on S3/S4
  plus closed-argv/grammar tests.
- Regression: full `make test` (and the repo's static gates) plus
  `TestPhase2RecoveryMatrix` 23/23 green, 0 inconclusive, S1–S8
  vocabulary verbatim.
- Rehearsal (criterion 5): a PG-gated rehearsal test (mirror of
  the opencode one) plus documented maintainer-run commands; the
  pipeline records the run or the pending state honestly in the
  task record.

## Acceptance mapping

1. Parity surface: D7 table (3a–3m per item, gaps fail closed).
2. Selector + pins: D9 (default claude-code; invalid refuses startup
   naming the variable; serve-wide, no mixing; explicit cost
   controls refused under codex).
3. Machine-tier proof: D14 (unit + integration + gated live;
   23/23 regression).
4. Runbook: D13.
5. Live rehearsal: D14 (PG-gated test + maintainer-run commands;
   no credentials in this environment).

## Constraints honored

ADR 0035/0036: no harness credential handling (no credential env set
or read — `CODEX_HOME` is denied, not set; operator login precedes
use; probe output discarded); serve never execs (all launches via
`port.ProcessLauncher`); closed launch parameters;
prepare/invoke-outside/persist-outcome unchanged in the orchestrator.
Fail-closed literal vocabulary: D3/D4 reasons reuse
`execution.FailureReason` strings verbatim; no harness text in
`Reason`, errors or logs. Idempotent retriable paths: probe,
version check and kill are idempotent; Start/Resume are single
launches under the orchestrator's existing claim protocol (no new
retry loop). No weakened check, no wire change, no historical-evidence
edit. The `env.go`/`policy.c` `CODEX_HOME` deny is additive
(strengthens, per the D3 delegation rule).

## Out of scope (recorded follow-ups, not this issue)

App-server/exec-server/SSE tracking; generic ACP (phase 5);
Bridge/Auto-allow mapping; reattach; reasoning passthrough; fork;
native cost limits; per-Task backend selection; Central-side cost
estimation from tokens (no rate table; would fabricate a bound);
refusing the inert serve cost defaults under codex (only explicit
cost controls refuse).

## Open points for plan stage

1. ToolCall input / ToolResult output per-type field table (D3
   compact-JSON rule → exact fields per item type).
2. `login status` behavior under the daemon/localexec launchers
   (stderr warnings discarded; no network; exit-code-only
   contract) and exact `--version` bytes for the strict parser.
3. Same-`thread_id` repeat handling (adopted: ignore) and
   `in_progress`-in-completed mapping (adopted: warn + `error`).
4. Submit handler + `HarnessOperator` plumbing for deny-only and
   explicit-cost refusal (D8); web wording (D12).
5. `setup.sh` exact paths/rule for `--codex-program` (D10) after a
   full read of the script.
6. Orphan `item.started` at stream end (adopted: drop; terminal
   carries the outcome) and completed-without-started synthesis
   (adopted: emit the pair).
7. Rehearsal composition and exact maintainer-run commands.
8. `env_vectors` test additions for `CODEX_HOME` (check the file).
9. Negative/fractional usage posture (adopted: whole report
   unusable → Warning + skip, mirroring opencode).

## Spec self-review

Placeholders: none (open points are plan-stage pins with adopted
resolutions, not TBDs). Consistency: Never+workspace-write (S3/S4)
matches D2/D3-declined/D6/D8; `-c`-on-resume (S5/S6) matches D2/D6;
no-cost (S1) matches capabilities + D7-3d/3j + D8/D9 refusals +
D12/D13 notes; cumulative usage (S11) matches
session_cumulative + D7-3l/3m; login-status probe (S9) matches D5 +
dispatcher-pause analysis; no-interrupt-through-port (Q6) matches
D4/D7-3e; `.codex` full-power-when-trusted (S10) matches D6; reason
subset matches the `failureReason` fallback rule; capabilities match
the orchestrator reads (`ResumeByID`, `NativeCostLimit`) plus
behavior-driven errors elsewhere. Scope: one adapter + wiring +
deployment + docs; servers/ACP/bridging explicitly excluded.
Ambiguity: "mixed config" is defined (D9: serve-wide, no per-Task
mixing, unknown value refuses); "model/auth decided by operator
config + login" holds (D2 passes `--model` only when the serve
config sets one; credentials never touched); "explicit cost
control" is defined (var set / field filled vs serve default).
