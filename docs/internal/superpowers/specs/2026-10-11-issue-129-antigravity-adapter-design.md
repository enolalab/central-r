# Issue #129 — Antigravity session adapter (fourth harness backend) — design spec

Status: draft. Pipeline input for issue #129
("[Harness] Add Antigravity session adapter (fourth harness backend)").
Implements a fourth production harness adapter behind the ADR 0035
boundary, following the OpenCode adapter (#126) as the model, against
the only verifiable Antigravity surface: the `agy` CLI's
`--input-format stream-json --output-format stream-json` stdio
protocol, pinned at 1.3.3.

## Scope

Owns:

- a production `port.Adapter` for Antigravity
  (`internal/adapter/harness/antigravity`): launch, NDJSON event
  streaming with stdin follow-up, cancel/kill, wall-clock/token
  backstops through reported usage, artifact capture through the
  unchanged 3b path, and Deny-only permission semantics;
- serve wiring: the backend selector gains `antigravity` (default
  stays Claude Code), a per-backend version pin, and the shared
  adapter factory;
- the launcher-daemon argv grammar for agy plus its
  `test_launcher.py` cases (wire format unchanged);
- `packaging/harness/setup.sh` support for the agy program,
  harness home and mounts;
- the runbook extension (`docs/operations/harness-execution.md`):
  install, login, enable, version-pin update flow;
- a documented dev-run rehearsal: one submitted Task end to end
  through the antigravity backend with captured artifacts.

Does NOT own: any change to #110 (the physical campaign stays pinned
on Claude Code sessions); any weakening of permission,
peer-authorization or ceremony checks; any wire-format change; any new
reason code or event kind (every adapter reason reuses an
`execution.FailureReason` string verbatim); any edit to historical
evidence files; Bridge/Auto-allow mapping for Antigravity (refused
fail-closed); ACP, fork, reattach, multi-backend serve.

## Problem

Real harness execution is Claude-Code/OpenCode/Codex-only: three
production adapters exist and the serve factory selects among them.
Antigravity (Google's agentic platform, driven locally by the `agy`
CLI) is the next harness the maintainer decided to admit, with the
same decided scope as #126/#128: Deny-first policy mapping only,
exactly one pinned backend version, model/auth by operator config +
login. The spec phase had to establish a feasible programmatic
session interface first; it exists (Evidence, E1–E16) and this spec
grounds the adapter on it with a per-item parity table and
fail-closed behavior for every gap.

## Brainstorm record (autonomous)

Context explored: issue #129; ADR 0035/0036; the harness adapter
boundary design; the `claudecode`, `opencode` and `codex` adapters
(`adapter/argv/protocol/session/probe`); `internal/harness`
(domain/events/usage/capability/env); the orchestrator, dispatcher
and bridge (`internal/harness/app`); both composition sites
(`cmd/central/harness_composition.go`, `scheduler_harness_wiring.go`);
the launcher daemon grammar (`cmd/central-harness-launcherd/policy.c`);
`packaging/harness/setup.sh`; the harness runbook; the installed
`agy` binary (1.3.2 at probe start, silently self-updated to 1.3.3
mid-probe, E9) via live probes; its binary strings (env surface,
config names); and a syscall trace of its worktree reads.

Questions asked and answers chosen:

1. *Is there a feasible programmatic session interface?* Yes: `agy
   --input-format stream-json --output-format stream-json` runs a
   resident process exchanging NDJSON over stdio (E1, E5). Without
   `-p` it reads one `{"event":"user","message":{"role":"user",
   "content":...}}` object per stdin line and runs one turn per
   line; each turn streams `init` (first turn only),
   `step_update` and exactly one `result` event. The process exits
   0 on stdin EOF. Stopping criterion from the issue is met: no
   stop-with-findings.
2. *What does Deny mean for agy?* The default headless behavior
   with no approval flags: tools headless mode cannot prompt for
   are auto-denied (E4: `rm` in the worktree denied, file
   untouched, `denied_actions:[{action:command,...}]` on the
   `result`, exit 0). Proven live. Benign tools (workspace file
   write, `echo`) auto-proceed; risky ones deny. There is no prompt
   channel to bridge and no scoped allow: only the default deny
   behavior is expressible.
3. *How are Bridge/Auto-allow expressed?* They are not: headless
   mode states it "cannot prompt for" permissions (E4 stderr), the
   only recognized stdin event is `user` (E5: any other event is
   ignored with a stderr warning, so no in-band permission
   channel exists), and auto-approval exists only as the blanket
   `--dangerously-skip-permissions` flag or operator-owned
   `permissions.allow` rules in `settings.json` (E4 stderr, E15),
   both forbidden to Central. Per the maintainer scope,
   Start/Resume refuse non-Deny policies fail-closed
   (`ErrUnsupported` → `harness_launch_failed`); the submit form
   goes deny-only under the antigravity backend (D8).
4. *How is the prompt delivered?* Over stdin as the first NDJSON
   `user` event (E5, two-turn session verified). `-p` takes the
   prompt as argv (hits OS length limits on large prompts and
   exposes bytes in `ps`), so `-p` is never used; the argv stays a
   closed grammar with no prompt bytes.
5. *What is the interrupt seam?* None usable: SIGTERM ends the
   process (~2s) after it emits an `ERROR`/`interrupted` result
   (E7). There is no in-band interrupt event (E5). `Interrupt`
   returns an error and the orchestrator kills the scope at once;
   the terminal is `killed`, never `interrupted`, on a Central
   stop (D4 precedence puts Central's own kill ahead of the
   harness's self-reported `interrupted` error).
6. *What is the auth signal?* Operator login precedes use
   (`settings.json`, subscription state under
   `~/.gemini/antigravity-cli`, E15/E16); Central never reads it.
   Every auth/model failure surfaces as a generic `result`
   `ERROR` (E8: bad model → `ERROR` + exit 1). Probe is
   version-only and reports `Authenticated: true` (the dispatcher
   pauses on false); auth failures map to `harness_api_error`. No
   credential file is ever read.
7. *How is project config handled?* A syscall trace (E11) shows
   agy reading `.agent/`, `_agent/`, `.agents/`, `_agents/`,
   `codeium.yaml`, `.codeium.yaml`, `codeium.yml`, `.codeium.yml`
   and `.citc/workspace_id` from the worktree; binary strings tie
   `.agents` to custom-agent discovery and `codeium.yaml` to
   rules/customizations (E12). No ignore flag exists, so the
   adapter refuses a worktree containing any of these fail-closed
   (→ `harness_launch_failed`, error names the file). `AGENTS.md`
   / `GEMINI.md` / `rules.json` / `hooks.json` /
   `mcp_config.json` are not read from the worktree in print mode
   (E11: only home-dir `settings.json` is read).
8. *How is the silent self-update handled?* The binary replaced
   itself (1.3.2 → 1.3.3) during probing (E9: `.old` binary,
   `updater/update_status.json`). The binary exposes
   `AGY_CLI_DISABLE_AUTO_UPDATE` (E9 strings). The adapter sets it
   to `1` on every launch and probe (declared in `EnvExtras`) so
   the pin stays meaningful; the daemon env policy admits that
   one variable (D11). Pin updates stay an operator runbook flow
   (D13).
9. *Which reason strings may the adapter emit?* Only strings
   already in the `execution.FailureReason` vocabulary (anything
   else falls back to `execution_failed` in `failureReason`):
   `harness_api_error`, `harness_exited_without_result`,
   `harness_session_mismatch`, `harness_protocol_error`. No
   `harness_not_authenticated` (no signal, E8), no
   `harness_max_turns`/`harness_budget` (no native limit surface),
   no `harness_policy_mismatch` (`init.permission_mode` reports
   operator settings, not launch state; Deny holds by
   construction of the closed argv).
10. *Serve-wide or per-Task backend?* Serve-wide single backend,
    like the three existing ones. An unknown
    `CENTRAL_HARNESS_BACKEND` value refuses startup
    (`CONFIG_INVALID` naming the variable).
11. *What does the daemon need?* A closed agy argv grammar
    mirroring the Go builder, plus the agy program path, harness
    home and data-dir mounts via the existing config keys. No
    wire change.

Approaches considered:

- **A. stream-json stdio resident adapter (chosen).** Mirrors the
  `opencode`/`claudecode` package shape, reuses the
  orchestrator/dispatcher/capture paths unchanged, supports
  follow-up `Send` over stdin (like claudecode), and every
  mapping below is live-verified against the pinned binary.
- **B. `-p` one-shot (prompt as argv).** Rejected: prompt bytes in
  `ps` output, OS argv length limits on large prompts, no
  follow-up channel; gains nothing over A.
- **C. Third-party ACP bridge (`google-antigravity-acp`).**
  Rejected: out-of-boundary third-party process, unpinned
  upstream, needs a full ACP client; the native stdio protocol
  already covers the parity surface.
- **D. Antigravity SDK (`pip install google-antigravity`).**
  Rejected: an embeddable Python library, not a harness process
  Central can launch/fence/kill; credential handling unclear;
  contradicts the harness-session boundary.

## Evidence

All probes ran against the installed agy (1.3.2 at probe start,
1.3.3 after the silent self-update; the 1.3.3 changelog shows no
print/stream-json change, and E1/E10 shapes were re-verified on
1.3.3):

- E1: stream-json emits newline-delimited `{"event",...}` objects;
  observed `event` values `init`, `step_update`, `result`.
  `init` carries top-level `conversation_id` plus
  `init{model,cwd,tools[60],permission_mode:"request-review"}`.
  `step_update` carries
  `step_update{conversation_id,step_index,state,step_type,...}`
  with `state` in `ACTIVE/DONE/ERROR` and `step_type` in
  `user_input/agent_response/tool/system_message`. `result`
  carries `result{conversation_id,status,response,error?,
  denied_actions?,duration_seconds,num_turns,usage}` with
  `status` in `SUCCESS/ERROR`.
- E2: `tool` steps arrive ACTIVE then DONE/ERROR with
  `tool_name` and `tool_info{name,parameters,output?,
  error?{type,message}}`. Observed: `run_command` with `output`
  on success; `view_file` ERROR with `TOOL_ERROR`/`invalid_args`
  message; denied `run_command` DONE with neither output nor
  error.
- E3: `agent_response` DONE steps and `result` both carry
  `usage{input_tokens,output_tokens,thinking_tokens,
  cache_read_tokens,total_tokens}` (no cost field). Verified
  identical values on step and result of the same turn
  (11750/5/0/0/11755): the two overlap, so only step reports
  are folded (D3).
- E4: default headless invocation auto-denies the unpromptable:
  `rm doomed2.txt` denied, file untouched, `result` holds
  `denied_actions:[{"action":"command","display_name":
  "RunCommand"}]`, exit 0, `status:"SUCCESS"`, empty response;
  stderr: `jetski: no output produced — a tool required the
  "command" permission that headless mode cannot prompt for, so
  it was auto-denied...`. Benign `echo` and workspace file
  write auto-proceeded.
- E5: stdin `{"event":"user","message":{"role":"user",
  "content":"..."}}` runs one turn per line in a single resident
  process (two-turn session verified, each turn ending in its
  own `result`); stdin EOF exits the process 0. A missing
  `event` field, a string (non-object) `message`, or an
  `event` other than `user` is refused/ignored with a stderr
  warning or an `ERROR` result: no in-band interrupt,
  permission, or model-switch channel exists.
- E6: `--conversation <known id>` continues the same
  conversation id (verified for both `-p` and stream-json
  stdin). `--conversation <unknown id>` starts a FRESH
  conversation with a new id, exit 0, with only a stderr
  `warning: conversation ... not found`: stdout never signals
  the switch, so the resume-id guard (D3) is the only
  fail-closed mechanism.
- E7: SIGTERM mid-turn emits `result{status:"ERROR",
  error:"interrupted",...}` on stdout plus `error: interrupted`
  on stderr, and the process exits (~2s). No soft seam.
- E8: harness errors are `result` `ERROR` + exit 1 with stderr
  mirroring: bad `--model` (empty conversation id, zero usage),
  undecodable stream input. Stderr is drained and discarded (it
  mirrors harness diagnostics); the `result` is the signal.
- E9: `agy --version` prints the bare version (`1.3.3`).
  Mid-probe silent self-update 1.3.2 → 1.3.3 observed
  (timestamped `.old` binary beside `~/.local/bin/agy`,
  `updater/update_status.json` reading `Update successful`).
  Binary strings expose `AGY_CLI_DISABLE_AUTO_UPDATE`.
- E10: a `/help` prompt WITHOUT `--disable-slash-commands`
  expanded to the slash-command list instead of reaching the
  model; WITH the flag the same prompt reached the model
  (conversational answer). The flag is required for literal
  prompt delivery.
- E11: `strace -f -e trace=openat` of a print run shows
  worktree-root reads of exactly `_agent`, `.agent`,
  `_agents`, `.agents`, `.citc/workspace_id`,
  `.codeium.yaml`, `codeium.yaml`, `.codeium.yml`,
  `codeium.yml` (all ENOENT here). No worktree reads of
  `AGENTS.md`, `GEMINI.md`, `rules.json`, `hooks.json`,
  `mcp_config.json`; only home-dir `settings.json`.
- E12: binary strings tie `.agents` to custom-agent discovery
  (`agentsCustomization ... discoverInDir`) and `codeium.yaml`
  to rules/customizations (`unsupported codeium.yaml version`,
  adjacent to customization strings): worktree entries that
  change harness behavior beyond launch parameters.
- E13: `init.tools` lists 60 tools including `ask_permission`,
  `ask_question`, `run_command`, `write_to_file`;
  `permission_mode` is `"request-review"`. Headless mode
  cannot surface prompts (E4), so no bridge binds to them.
- E14: exit 0 on success (including auto-denied turns, E4) and
  on immediate stdin EOF (init only, no `result`); exit 1 on
  harness errors (E8).
- E15: home `settings.json` top keys are `model`,
  `permissions{allow}`, `allowNonWorkspaceAccess`,
  `trustedWorkspaces`: operator-owned, Central never reads or
  writes them (ADR 0035).
- E16: state dirs `~/.gemini/antigravity-cli` (settings,
  conversations, updater) and `~/.cache/antigravity`;
  program `~/.local/bin/agy` (single 214 MB Go binary,
  self-replacing updater).

## Design

### D1 — Package shape

New package `internal/adapter/harness/antigravity`, mirroring
`opencode` (frame decode, terminal table) and `claudecode`
(queued stdin writer, `Send` until the result):

- `antigravity.go`: `Kind = "antigravity"`,
  `DefaultPinnedVersion = "1.3.3"`, `program = "agy"`,
  `Config`, reason constants, `Reasons()`, `Capabilities()`.
- `argv.go`: the closed argv builder (D2).
- `protocol.go`: strict frame decode (D3).
- `session.go`: the event loop and terminal computation (D4).
- `probe.go`: the version-only probe (D5).
- `adapter.go`: `New`/`Start`/`Resume`/`Reconcile`, PATH
  requirement, project-config refusal, auto-update disable
  (D6).

Capabilities: `StreamingInput`, `ResumeByID`, `UsageTokens`,
`UsageScope: step` true; everything else false (`Interrupt`,
`PreassignSessionID`, `Fork`, `PermissionBridge`,
`PartialDeltas`, `CostUSD`, `Reattach`, `AutoResumeOnRestart`,
`NativeCostLimit`). No `CostUSD`: usage carries tokens only
(E3), so the antigravity backend refuses a configured cost
limit at startup exactly like the codex backend (D9).

### D2 — Closed argv

Fresh: `--input-format stream-json --output-format stream-json
--disable-slash-commands [--model <id>]`.
Resume: the same plus `--conversation <id>`.
The prompt travels over stdin as the first NDJSON `user` event
(E5); no `-p`, no message positionals, ever: `-p` takes the
prompt as argv (length limits, `ps` exposure). `--continue` is
never used (it follows the operator-global last conversation,
not Central's recorded id). No
`--dangerously-skip-permissions` (Deny by construction), no
`--sandbox`, `--mode`, `--agent`, `--effort`, `--project`,
`--add-dir`, `--print-timeout`, `--remote-control`: each would
widen configuration, change loop behavior, or bind foreign
state beyond the declared launch parameters. The worktree comes
from the launcher's `WorkDir` (`init.cwd` confirms it, E1),
never from argv. The daemon grammar mirrors this exactly (D11).

`--model` accepts the `safeModel` charset (same rule as
claudecode/opencode: non-empty, ≤128 bytes, not starting with
`-`, alnum plus `-._:/[]@`), covering ids such as
`gemini-3.8-flash-low`. `--conversation` accepts a strict lowercase UUID
(`8-4-4-4-12` hex with hyphens at fixed positions; every
observed conversation id has that shape, E1/E6; codex precedent, mirrored by the daemon's `canonical_uuid`).

### D3 — Protocol mapping

One JSON object per stdout line, decoded strictly; the raw line
is kept as each emitted event's `Raw`:

| agy frame | normalized events | notes |
| --- | --- | --- |
| `init` | binds `conversation_id`; first frame emits `SessionStarted{id, version, model}` + resolves `Ref()` | `init.tools`/`cwd`/`permission_mode` recorded in Raw only (nil Tools like opencode; no policy-mismatch reason, brainstorm Q9) |
| `user_input` step | none (binds id) | no content; id binding only |
| `agent_response` ACTIVE | buffered per `step_index` (`text_delta` appended) | never emitted directly (`PartialDeltas` false) |
| `agent_response` DONE | `Message{assistant, text, Partial:false}` (skipped when blank) + `UsageReport` | usage: `TokensIn=input_tokens`, `TokensOut=output_tokens+thinking_tokens` (both billed as output, mirror of opencode's reasoning fold), `CacheRead=cache_read_tokens`, `CacheWrite=0`, `CostMicroUSD=0`, `Scope:step`, `Estimated:false`; `total_tokens` ignored (sum of parts) |
| `tool` ACTIVE | `ToolCall{id:"step-<index>",name:tool_name,input}` | `input` is the whitespace-compacted `tool_info.parameters` (mirror of opencode); `step_index` is unique per process (E6 resume resets per process), hence per attempt |
| `tool` DONE | `ToolResult{id,ok,output}` | `output` is `tool_info.output` or empty; a DONE with no pending ACTIVE for its index warns and skips |
| `tool` ERROR | `ToolResult{id,error,output}` | `output` is `tool_info.error.message`, else the compacted error object, else empty |
| `result` | turn/session accounting (D4) + final `Message` + denial warning | `response` on success (non-blank) is emitted as the last assistant `Message` (claude 3e-8 last-Message-wins rule for the 3b report); non-empty `denied_actions` emits a fixed-literal `Warning` (presence is the signal; entries never decoded); `result.usage` is ignored (overlaps step reports, E3) |
| `system_message` / unknown step type / unknown event | `Warning` + skip | forward tolerance, like opencode unknown types (`system_message` observed once with uncaptured shape; mapping it would be unverified) |
| malformed line | `Warning` + skip | fixed literals, never harness text |

Frame-error posture mirrors `opencode`/`claudecode`
(tolerant with warnings, not strict stops). A malformed JSON
line, an unknown `event`, a frame with a missing
`conversation_id` (other than the `result` rule below), or a
per-frame field problem (undecodable text, a tool step
without name/shape, an unusable usage field, an orphan tool
DONE/ERROR) emits a fixed-literal `Warning` carrying Raw and
the frame is skipped; the stream continues.
Only two classes stop the session: a `conversation_id` that
differs from the resumed id or changes mid-stream
(`harness_session_mismatch` — this is what makes the silent
fresh-conversation switch of E6 fail closed), and a stdout
line over the frame bound (16 MiB, mirrored) or a scanner
error (`harness_protocol_error`, stream drained). A `result`
with an empty `conversation_id` is processed for terminal
accounting only while no session id is bound yet (the
pre-init harness failure of E8, e.g. bad model → recorded
`ERROR` → `harness_api_error`); after binding, an empty id is
a stream-integrity violation → `harness_session_mismatch`
stop. An empty stream closes `Ref()` unresolved at finish.

Usage numerics mirror `opencode` exactly: token counters must
be integral int64 JSON numbers (fractional/out-of-range/missing
makes that report warned-and-skipped); values ≤0 ignored in
folds; saturation at MaxInt64.

Tool-call text buffering: deltas accumulate per step in memory;
the bound is the harness's own output, already persisted as the
3b report. A second ACTIVE for an already-pending index
overwrites the pending call (tolerant, last-wins).

### D4 — Session lifecycle and terminal

`Start`/`Resume` launch the resident process and queue the
prompt as the first stdin `user` event (claudecode-style queued
writer; stdin stays open). `Send` queues further NDJSON `user`
events until the session ends; a `Send` racing the final result
is best-effort per the port contract (the line may be dropped
when stdin closes). Stdout is decoded per D3; stderr is drained
and discarded (it carries account-adjacent diagnostics and the
E4/E6/E8 mirrors, never mapped to `Reason`). Sequence numbers
are adapter-assigned, monotonic per attempt.

Result accounting (mirror of claude `onResult` via queue
state): a `result` arriving while `Send` lines are still queued
ends only its turn (final `Message` + denial warning emitted,
input stays open, the harness runs the queued turns — E5). The
`result` with nothing queued ends the session: its terminal is
mapped, stdin closes, and the process exits 0 on EOF (E5). An
`ERROR` result is recorded; the session still ends at the
first unqueued result (the harness exits after an `ERROR`
result, E8).

Terminal computation at stream end:

1. adapter-initiated stop (protocol/session mismatch) →
   `failed` + stop reason;
2. else `Kill` requested → `killed` (empty reason, Central's
   own). This precedes the harness error (unlike opencode's
   order) because agy reports Central's own SIGTERM back as an
   `ERROR`/`interrupted` result (E7): a Central stop must
   settle `killed`, never `failed`, per 3e;
3. else recorded `ERROR` result → `failed` +
   `harness_api_error` (the `error` text is never copied);
4. else exit 0 → `succeeded` (empty reason; covers the no-turn
   empty stream of E14, whose missing report follows the
   existing 3b report-missing path);
5. else → `failed` + `harness_exited_without_result`.

`Interrupt` returns an error (no seam, E5/E7): the orchestrator
kills the scope at once, so a Central stop always settles
`killed`. Once the terminal is recorded, `Interrupt` returns
`ErrSessionEnded` (mirror of claude/opencode), so a
post-result stop path never kills at once. `Send` after the end
returns `ErrSessionEnded`. `RespondPermission` returns
`ErrNoPendingPermission` (no request is ever emitted). `Wait`/
`Kill` follow the `port.Process` contract; `Events` closes
after the terminal event. Frames arriving after the
session-ending result, before EOF, are drained and dropped:
nothing past the terminal may reach the attempt.

Denials surface as a `Warning`, never as `ToolDenied`: the
denied tool step itself is indistinguishable from success at
step level (DONE, no output, no error — E2/E4) and only the
turn-level `denied_actions` array reports it. The Warning text
is a fixed literal (exact text pinned at plan stage); the
result frame stays in Raw as evidence.

### D5 — Probe

`agy --version` through the launcher in the probe workdir with
`AGY_CLI_DISABLE_AUTO_UPDATE=1` in the probe env, parsed
strictly (exact bytes verified at plan stage; observed bare
`1.3.3`). No auth probe exists (E8): `Authenticated` is always
true and `Detail` says `antigravity has no probeable login;
model/auth failures surface as harness_api_error`, plus the
pin verdict when the version differs (same shape as
claude/opencode). A version mismatch fails each attempt at
`Start` (like the other adapters), not at probe: the
dispatcher does not gate on version.

### D6 — Start/Resume/Reconcile

`Start`/`Resume` validate the spec, require the absolute-dir
`PATH`, set `AGY_CLI_DISABLE_AUTO_UPDATE=1` on the launched
env (E9; declared in `EnvExtras`; the value is force-set, never
taken from operator env), refuse `Permission != deny` with
`ErrUnsupported`, refuse positive `Limits.MaxTurns`/
`MaxCostMicroUSD` (no native surface; the orchestrator already
withholds the cost limit when `NativeCostLimit` is false),
refuse a worktree containing `.agent`, `_agent`, `.agents`,
`_agents`, `codeium.yaml`, `.codeium.yaml`, `codeium.yml`,
`.codeium.yml` or `.citc` (any file type; stat failure also
refuses — E11/E12), check the pinned version, then launch.
Resume passes `--conversation` with the recorded id; the id
guard in D3 makes the silent fresh conversation of E6
impossible. `Reconcile` reports scope aliveness only (no
reattach): a live scope is killed and the attempt goes
`ambiguous`, exactly like the other adapters.

(`AGY_CLI_DISABLE_AUTO_UPDATE` passes the `env.go` denylist:
no `AGY_` rule denies it and it matches no credential suffix.
No denylist change is needed: Central passes only allowlisted
vars, so no other `AGY_*` operator var can reach the harness.)

### D7 — Parity surface (3a–3m)

| Phase | Antigravity backend | Fail-closed gap behavior |
| --- | --- | --- |
| 3a serve wiring | supported via the backend selector (D9) | unknown backend refuses startup |
| 3b artifacts (report/patch/commits) | supported unchanged (report = final `Message` text incl. the result `response`; patch/commits from the worktree) | empty final text follows the existing report-missing path |
| 3c approvals | Deny supported (E4) | Bridge/Auto-allow refused at Start (D8) |
| 3d budgets | wall clock + Central token backstop supported (step-scope fold exists; tokens only, no USD) | no native limit passed or accepted; a configured cost limit refuses startup (D9, codex rule) |
| 3e cancel/recovery | cancel via scope kill; recovery via kill + `ambiguous` | terminal is `killed`, never `interrupted` (D4 precedence) |
| 3f prepared cancel/epoch resume | supported (adapter-independent + `Resume`) | — |
| 3g resume ambiguous | supported via `--conversation` + id guard | unknown id fails the attempt via `harness_session_mismatch`, never a silent fresh session (E6) |
| 3h eligibility guard | supported (adapter-independent) | — |
| 3i resume minors | supported (adapter-independent) | — |
| 3j task cost cap | refused at startup (no cost signal; codex rule) | cost-cap var must be unset (D9) |
| 3k rerun | supported (adapter-independent) | — |
| 3l token ceiling | supported (usage-driven; billed = in+out+thinking folded into out) | usage is step-streamed, so failed or killed attempts may record partial usage from completed steps; never assumed zero |
| 3m live usage display | supported (usage-driven, tokens only) | partial usage as in 3l |

### D8 — Non-Deny refusal

Backstop (required): the adapter refuses `bridge`/`auto_allow`
at Start/Resume (D6) → the Run settles `harness_launch_failed`
with the cause in the error (never a silent downgrade to
deny). Submit-time (required): under the antigravity backend
the submit form offers deny only, with a note naming the
backend; a submit carrying bridge/auto_allow is refused
server-side. Exact handler and plumbing follow the
opencode/codex sites (pinned at plan stage).

### D9 — Serve wiring

- `CENTRAL_HARNESS_BACKEND=claude-code|opencode|codex|
  antigravity`, default `claude-code`, validated only when
  harness execution is enabled. An unknown value refuses
  startup with `errHarnessConfig` naming
  `CENTRAL_HARNESS_BACKEND` (reported as `CONFIG_INVALID`).
- `CENTRAL_HARNESS_ANTIGRAVITY_VERSION`, default `1.3.3`,
  shape `1.2.3`, same validation as the other pins. A
  non-selected backend's version var is ignored (documented).
- The cost-limit var must be unset when the backend is
  antigravity (same rule and error shape as the codex backend:
  tokens-only reporting cannot enforce a USD cap).
- Shared factory `newHarnessAdapter(hc, launcher)` gains the
  antigravity case, returning the recorded adapter version
  (`antigravity/issue-129`). The backend is serve-wide;
  per-Task mixing is not expressible.
- #110 is untouched: the campaign stays on the default backend
  via its specs/plans; no gate changes.

### D10 — Deployment: program, home, mounts

`setup.sh` gains `--antigravity-program` (default the
operator's `~/.local/bin/agy`, resolved; the binary must lie
beneath a read-only mount or outside HOME, same rule as the
other backends — read-only additionally pins the binary
against the self-updater, E9/E16) and writes a fourth harness
home (`harness-home/antigravity`) with a mount point for the
agy data dir `.gemini/antigravity-cli` (settings,
conversations, updater state), read-write (the harness's own
state), plus the read-only program mount when the program
lives under HOME. `.cache/antigravity` is installer staging
only (zero references in the E11 runtime trace) and is not
mounted. Daemon config
lines use the existing keys (`harness antigravity <path>`,
`home_dir`, `mount`). Exact mount list is verified against the
pinned binary at plan stage.

### D11 — Daemon grammar

`policy.c` gains `antigravity_argv_kind`: probe `["--version"]`,
else `--input-format stream-json --output-format stream-json
--disable-slash-commands [--model <safeModel>] [--conversation
<uuid>]` with flags in that order and no further args (the resume id
reuses the daemon's `canonical_uuid`, strict hyphenated lowercase);
`chl_harness_has_grammar` admits `antigravity`; the env policy
admits `AGY_CLI_DISABLE_AUTO_UPDATE` (and only that `AGY_*`
name). `test_launcher.py` gains accept/refuse cases for every
production. No `PROTOCOL.md` change (wire untouched).

### D12 — Product surfaces

Web permission view: the deny-only note is backend-aware
(antigravity: deny-only note + a pointer to the runbook's
permission section, following the opencode/codex wording).
Budget view: the cost note is backend-aware (antigravity
reports tokens only, 0 USD always; the cost limit is refused
at startup). Wording is pinned at plan stage; no new page or
route.

### D13 — Docs and records

`docs/operations/harness-execution.md` gains the antigravity
backend section: install the pinned version (including how the
self-updater is held back and how to re-pin), operator login
(interactive `agy` auth flow precedes use), enable
(`CENTRAL_HARNESS_BACKEND=antigravity`), permission semantics
(defaults + headless auto-deny + the worktree-config refusal),
token-only cost notes, troubleshooting (model/auth errors →
`harness_api_error`; unknown conversation → session-mismatch
failure, never silent; version mismatch), and the version-pin
update flow (verify new version → bump default +
`CENTRAL_HARNESS_ANTIGRAVITY_VERSION` → rerun setup → re-run
conformance). The runbook states that operator-owned
`settings.json` (`permissions.allow` rules, default model,
trusted workspaces) applies by design: an allow-rule can widen
headless behavior past the E4 default, which is the operator's
responsibility, not Central's (E4's denial assumes no
allow-rule). `docs/internal/tasks/` records the
fix-requirement analysis per the SC-DEF convention.

### D14 — Tests (machine tier)

- Unit: argv builder (accept/refuse matrix incl.
  prompt-never-in-argv, flag order, UUID rule), frame decode
  (every D3 row + malformed/unknown), session terminal table
  (D4 incl. kill-beats-interrupted and queued-turn results),
  probe parsing, capabilities validation, config (selector +
  pin + cost-limit refusal; invalid names the variable),
  composition (both sites select the backend; default
  unchanged), daemon grammar cases.
- Scripted fixtures captured from 1.3.3 (checked in as NDJSON):
  success, tool use, tool error, denied turn
  (`denied_actions`, E4), API error (bad model, E8),
  interrupted (E7), resume, unknown-conversation mismatch
  (E6), slash-command literal prompt (E10), unknown-type
  tolerance, multi-turn Send. Captures are sanitized before
  check-in (live ids replaced with fixed test UUIDs, worktree
  paths canonicalized, credential-adjacent markers redacted)
  and covered by the #126 testdata hygiene test (size,
  text-only, marker-free).
- Integration: scripted launcher runs (launch/stream/Send/
  cancel/capture/policy-refusal) through `localexec`.
- Live (gated, same convention as `claudecode_live_test.go`):
  probe + one tiny run against the pinned binary; skipped by
  default.
- Regression: full `make test` (and the repo's static gates)
  plus `TestPhase2RecoveryMatrix` 23/23 green, 0 inconclusive,
  S1–S8 vocabulary verbatim.
- Rehearsal (criterion 5): a documented dev run — one
  submitted Task end to end through the antigravity backend
  with report/patch/commits artifacts captured; exact commands
  pinned at plan stage.

## Acceptance mapping

1. Parity surface: D7 table (3a–3m per item, gaps fail
   closed). Feasible interface established (E1–E16); no stop.
2. Selector + pins: D9 (default claude-code; invalid refuses
   startup naming the variable; serve-wide, no mixing).
3. Machine-tier proof: D14 (unit + integration + gated live;
   23/23 regression).
4. Runbook: D13.
5. Live rehearsal: D14 (documented dev run).

## Constraints honored

ADR 0035/0036: no harness credential handling (no credential
env set or read, no config relocation; operator login precedes
use); serve never execs (all launches via
`port.ProcessLauncher`); closed launch parameters;
prepare/invoke-outside/persist-outcome unchanged in the
orchestrator. Fail-closed literal vocabulary: D3/D4 reasons
reuse `execution.FailureReason` strings verbatim; no harness
text in `Reason`, errors or logs. Idempotent retriable paths:
probe, version check and kill are idempotent; Start/Resume are
single launches under the orchestrator's existing claim
protocol (no new retry loop). No weakened check, no wire
change, no historical-evidence edit.

## Out of scope (recorded follow-ups, not this issue)

ACP (phase 5); Bridge/Auto-allow mapping; reattach; fork;
native cost limits; per-Task backend selection; `system_message`
content mapping (shape uncaptured — Warning+skip stands until
verified); `init.tools` surfacing (nil like opencode);
`--sandbox`/`--mode` pass-through.

## Open points for plan stage

1. Exact `--version` bytes (newline form) for the strict
   parser.
2. `system_message` step shape (observed once, uncaptured):
   confirm Warning+skip stands; map only if a live shape is
   captured.
3. Denial Warning literal text.
4. Tool I/O byte mapping edge cases (`parameters` non-object,
   `output` non-string, `error` shape variants) mirroring
   claude/opencode conventions.
5. Submit handler + `HarnessOperator` plumbing for deny-only
   submit-time refusal (D8); web wording (D12).
6. Cost-limit var name + codex-rule error shape for the
   antigravity startup refusal (D9); budget-view wording.
7. `~/.local/bin` install-layout check for the ro program
   mount (D10); `.cache/antigravity` necessity; daemon env
   allow vs deny shape for `AGY_CLI_DISABLE_AUTO_UPDATE`.
8. Rehearsal composition (existing e2e harness vs full serve)
   and exact commands.
9. Cancel path audit: orchestrator cancel calls
   `session.Kill` (sets `killRequested`) before/while killing
   the scope, so D4 precedence yields `killed` on every
   Central stop; external-SIGTERM-without-Kill edge
   documented.

## Spec self-review

Placeholders: none (open points are plan-stage pins with
owners, not TBDs). Consistency: Deny-by-default (E4) matches
D3/D6/D8; no-auth-signal (E8) matches D5 + dispatcher-pause
analysis; no-interrupt (E5/E7) matches D4/D7-3e with the
kill-precedence justification; project-config reads (E11/E12)
match D6; auto-update (E9) matches D6/D10/D11/D13; slash
expansion (E10) matches D2; usage overlap (E3) matches the
steps-only fold; silent resume switch (E6) matches the id
guard; reason subset matches the `failureReason` fallback
rule; capabilities match the orchestrator's capability reads
plus behavior-driven errors elsewhere. Scope: one adapter +
wiring + deployment + docs; ACP/bridge explicitly excluded.
Ambiguity: "mixed config" is defined (D9: serve-wide, no
per-Task mixing, unknown value refuses); "model/auth decided
by operator config + login" holds (D2 passes `--model` only
when the serve config sets one; credentials never touched).
