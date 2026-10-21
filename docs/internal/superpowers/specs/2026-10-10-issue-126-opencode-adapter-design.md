# Issue #126 — OpenCode session adapter (second harness backend) — design spec

Status: draft. Pipeline input for issue #126
("[Harness] Add OpenCode session adapter (second harness backend)").
Implements governing-design phase 4 (OpenCode adapter) against the only
verifiable OpenCode surface: the v1 `opencode run --format json` stdio
protocol, pinned at 1.18.32.

## Scope

Owns:

- a production `port.Adapter` for OpenCode (`internal/adapter/harness/opencode`):
  launch, NDJSON event streaming, cancel/kill, wall-clock/cost/token
  backstops through reported usage, artifact capture through the
  unchanged 3b path, and Deny-only permission semantics;
- serve wiring: an explicit backend selector (default stays Claude
  Code), per-backend version pins, and a shared adapter factory used by
  both the phase-3a path (`composeHarness`) and the phase-2 path
  (`composeSchedulerHarness`);
- the launcher-daemon argv grammar for opencode plus its
  `test_launcher.py` cases (wire format unchanged);
- `packaging/harness/setup.sh` support for the opencode program,
  harness home and mounts;
- the runbook extension (`docs/operations/harness-execution.md`):
  install, login, enable, version-pin update flow;
- a documented dev-run rehearsal: one submitted Task end to end
  through the opencode backend with captured artifacts.

Does NOT own: any change to #110 (the physical campaign stays pinned
on Claude Code sessions); any weakening of permission,
peer-authorization or ceremony checks; any wire-format change; any new
reason code or event kind (every adapter reason reuses a
`execution.FailureReason` string verbatim); any edit to historical
evidence files; Bridge/Auto-allow mapping for OpenCode (refused
fail-closed); serve+SSE, ACP, reasoning passthrough, fork, reattach,
multi-backend serve.

## Problem

Real harness execution is Claude-Code-only: `internal/adapter/harness/`
holds one production adapter (`claudecode`) plus fake/test scaffolding,
and both serve composition sites hardcode `claudecode.New`. The
governing boundary design phases OpenCode as adapter #2, but its phase-4
premise ("v2.0.x shipped, serve + SSE") is stale: upstream latest is
v1.18.x (checked 2026-10-10) and only v1 is installed (1.18.32) and
verifiable here. This spec re-grounds phase 4 on the v1 surface with a
per-item parity table and fail-closed behavior for every gap.

## Brainstorm record (autonomous)

Context explored: issue #126; ADR 0035/0036; the harness adapter
boundary design; the phase-1a domain design; the `claudecode` adapter
(`adapter/argv/protocol/session/probe`); `internal/harness`
(domain/events/usage/capability/env); the orchestrator, dispatcher and
bridge (`internal/harness/app`); both composition sites
(`cmd/central/harness_composition.go`, `scheduler_harness_wiring.go`);
the launcher daemon grammar (`cmd/central-harness-launcherd/policy.c`);
`packaging/harness/setup.sh`; the harness runbook; the web permission
and budget views; the installed `opencode` 1.18.32 binary (live probes)
and its v1.18.32 source (run command, permission evaluation, default
agent rules); upstream release state (latest v1.18.35, no v2).

Questions asked and answers chosen:

1. *Which OpenCode, which surface?* v1.18.32, `opencode run --format
   json` over stdio. v2 does not exist upstream, so the spec's
   serve+SSE target is unverifiable; v1 `serve`+SSE would buy only
   Reattach and bridging, both out of scope, at 3-5x the complexity;
   ACP is the separate phase-5 generic adapter. `run` streams typed
   JSON events, resumes by id, denies by default (proven below), and
   reports per-step usage.
2. *What does Deny mean for `run`?* The default invocation (no `--auto`
   or permission flags): `run` auto-rejects every permission ask
   (`run.ts` permission.asked branch) and records the rejection as a
   tool error. Proven live: a `*.env` read (default rule `ask`) came
   back `status:error` with `The user rejected permission to use this
   specific tool call.` and exit 0.
3. *How are Bridge/Auto-allow expressed?* They are not: `run` exposes
   no bridge channel, and `--auto`/`--dangerously-skip-permissions`
   are blanket allow, not Central-bridged approval. Per the maintainer
   scope, Start/Resume refuse non-Deny policies fail-closed
   (`ErrUnsupported` → `harness_launch_failed`); the submit form goes
   deny-only under the opencode backend (D8).
4. *How is the prompt delivered?* Over stdin, like claude: `run` with
   no message args reads a piped prompt (proven live: `piped-ok`), so
   the argv stays a closed grammar with no prompt bytes in `ps` output.
5. *What is the interrupt seam?* None: SIGINT kills the process
   (proven live, exit by signal, no further events). `Interrupt`
   returns an error, and the orchestrator's existing rule ("an
   interrupt that fails kills it at once") ends the scope; the
   terminal is `killed`, never `interrupted`, on a Central stop.
6. *What is the auth signal?* There is no global login state: free
   models answer with an empty HOME, and every auth/model failure
   surfaces as a generic `error` event (`APIError`/`UnknownError`,
   exit 1). Probe is version-only and reports `Authenticated: true`
   (the dispatcher pauses on false); auth failures map to
   `harness_api_error`. No credential file is ever read.
7. *How is project config handled?* `opencode.json` in the worktree is
   loaded (proven live: a bad project model fails the run), and it can
   declare permissions, MCP servers and config-driven plugins with
   hooks. There is no `--setting-sources`-style ignore flag, so the
   adapter refuses a worktree containing `opencode.json`,
   `opencode.jsonc` or `.opencode/` fail-closed (→
   `harness_launch_failed`, error names the file).
8. *Which reason strings may the adapter emit?* Only strings already in
   the `execution.FailureReason` vocabulary (anything else falls back
   to `execution_failed` in `failureReason`): `harness_api_error`,
   `harness_exited_without_result`, `harness_session_mismatch`,
   `harness_protocol_error`. No `harness_not_authenticated` (no
   signal), no `harness_max_turns`/`harness_budget` (no native limit
   surface), no `harness_policy_mismatch` (no mode report; Deny holds
   by construction of the closed argv).
9. *Serve-wide or per-Task backend?* Serve-wide single backend. Mixed
   per-Task backends are not expressible (no such knob); an unknown
   `CENTRAL_HARNESS_BACKEND` value refuses startup (`CONFIG_INVALID`
   naming the variable).
10. *What does the daemon need?* A closed `run` argv grammar mirroring
    the Go builder (config lines for a harness id without a grammar
    are refused by `chl_harness_has_grammar`), plus the opencode
    program path, harness home and data-dir mounts via the existing
    config keys. No wire change.

Approaches considered:

- **A. `run --format json` stdio adapter (chosen).** Mirrors the
  `claudecode` package shape, reuses the orchestrator/dispatcher/
  capture paths unchanged, and every mapping below is live-verified
  against the pinned binary.
- **B. v1 `serve` + SSE.** Rejected: buys only Reattach and bridging
  (both out of scope), needs an HTTP client plus server supervision
  and port management, and the v1 endpoint shapes differ from the
  v2 table the governing spec assumed.
- **C. ACP via `opencode acp`.** Rejected: that is the phase-5 generic
  adapter, explicitly separate work, and needs a full ACP client.
- **D. Default-format scraping.** Rejected: human format that breaks on
  UI text changes (governing-design finding 6).

## Evidence

All probes ran against the installed 1.18.32 (`E` = live run, `S` =
v1.18.32 source read):

- E1: `run --format json` emits newline-delimited
  `{"type","timestamp","sessionID",...}`; observed types `step_start`,
  `text`, `tool_use`, `step_finish`, `error`. Exit 0 on idle success,
  exit 1 with an `error` event on API/model failures.
- E2: `step_finish` carries per-step
  `tokens{total,input,output,reasoning,cache{read,write}}` plus float
  `cost` in USD (currency confirmed via `opencode stats`, `$`).
- E3: `tool_use` carries `tool`, `callID`, `state{status,input,output?,
  error?,metadata?,title,time}`; `status` is `completed` or `error`.
- E4: default `run` auto-rejects asks (S: `run.ts` permission.asked
  branch replies `reject`; E: `*.env` read → `status:error`,
  `The user rejected permission to use this specific tool call.`).
- E5: resume with `-s <id>` continues the same session id (E); an
  unknown id exits 1 with empty stdout and `Error: Session not found`
  on stderr (E).
- E6: SIGINT kills mid-run with no further events (E, exit by signal).
- E7: stdin prompt delivery works with no message args (E,
  `piped-ok`).
- E8: project `opencode.json` is loaded from the worktree (E: bad
  project model fails the run).
- E9: no global auth state (E: free model answers under an empty HOME;
  bad-provider and no-credential runs fail as generic `UnknownError`
  exit 1).
- E10: upstream latest is v1.18.35; no v2 tag exists (checked
  2026-10-10). Default build-agent rules are `*: allow` with `ask` for
  `doom_loop`, `external_directory` (minus whitelisted dirs) and
  `read` of `*.env*` (S: `agent.ts`).

## Design

### D1 — Package shape

New package `internal/adapter/harness/opencode`, mirroring
`claudecode`:

- `opencode.go`: `Kind = "opencode"`, `DefaultPinnedVersion =
  "1.18.32"`, `program = "opencode"`, `Config`, reason constants,
  `Reasons()`, `Capabilities()`.
- `argv.go`: the closed argv builder (D2).
- `protocol.go`: strict frame decode (D3).
- `session.go`: the event loop and terminal computation (D4).
- `probe.go`: the version-only probe (D5).
- `adapter.go`: `New`/`Start`/`Resume`/`Reconcile`, PATH requirement,
  project-config refusal (D6).

Capabilities: `ResumeByID`, `UsageTokens`, `CostUSD`,
`UsageScope: step` true; everything else false
(`StreamingInput`, `Interrupt`, `PreassignSessionID`, `Fork`,
`PermissionBridge`, `PartialDeltas`, `Reattach`,
`AutoResumeOnRestart`, `NativeCostLimit`).

### D2 — Closed argv

Fresh: `run --format json [--model provider/model]`.
Resume: `run --format json [--model ...] --session <id>`.
The prompt travels over stdin; no message positionals, ever.
`--continue` is never used (it follows the operator-global last
session, not Central's recorded id). No `--auto`, `--agent`,
`--command`, `--attach`, `--dir`, `--port`, `--file`, `--share`,
`--thinking`, `--variant`: each would widen configuration, attach to
foreign servers, or change loop behavior beyond the declared launch
parameters.

`--model` accepts the `safeModel` charset (same rule as claudecode:
non-empty, ≤128 bytes, not starting with `-`, alnum plus
`-._:/[]@`), covering `provider/model` ids. `--session` accepts
`ses_` plus 1-64 `[A-Za-z0-9]` (observed ids are `ses_` + 22 alnum).
`--dir` is refused: the worktree comes from the launcher's `WorkDir`,
never from argv. The daemon grammar mirrors this exactly (D11).

### D3 — Protocol mapping

One JSON object per stdout line, decoded strictly; the raw line is
kept as each emitted event's `Raw`:

| run type | normalized events | notes |
| --- | --- | --- |
| `step_start` | none (binds `sessionID`) | no content; id binding only |
| `text` | `Message{assistant, text, Partial:false}` | final text (`time.end` set); empty or undecodable text emits nothing |
| `tool_use` | `ToolCall{id:callID,name:tool,input}` + `ToolResult{id,status,output}` | `completed`→`ok` (output `state.output`); `error`→`denied` iff `state.error` equals the pinned rejection string (E4), else `error` (output `state.error`) |
| `step_finish` | `UsageReport` | `TokensIn=input`, `TokensOut=output+reasoning` (both billed as output), `CacheRead/CacheWrite`, `CostMicroUSD` via the mirrored `costMicroUSD` rule below, `Scope:step`, `Estimated:false`; `total` ignored; `reason` recorded in Raw only |
| `reasoning` | none | `--thinking` is never passed; skipped silently if the harness emits it |
| `error` | recorded; terminal at stream end | never copied into `Reason` (D4); an undecodable `error` event is warned and not recorded — the exit code decides |
| unknown type | `Warning` + skip | forward tolerance, like claude misc frames |

Frame-error posture mirrors `claudecode` (tolerant with warnings, not
strict stops). A malformed JSON line, an unknown `type`, a frame with
a missing `sessionID`, or a per-frame field problem (undecodable text,
a tool part without id/shape, an unusable usage field) emits a
fixed-literal `Warning` carrying Raw and the frame is skipped; the
stream continues. Warning texts are fixed literals (same pattern as
claude `warnMalformed`/`warnUnrecognized`), never harness text. Only
two classes stop the session: a `sessionID` that differs from the
resumed id or changes mid-stream (`harness_session_mismatch`), and a
stdout line over the frame bound (16 MiB, mirrored) or a scanner error
(`harness_protocol_error`, stream drained). The first observed
`sessionID` emits `SessionStarted{id, version, model}` and resolves
`Ref()`; an empty stream closes `Ref()` unresolved at finish.

Usage numerics mirror `claudecode` exactly: cost converts by
`costMicroUSD` (round half away from zero; ≤0/NaN/Inf map to 0;
saturate at MaxInt64); token counters ignore values ≤0 and saturate
on overflow; a fractional or out-of-int64-range token field makes
that usage report ignored with a Warning, never a stop.

### D4 — Session lifecycle and terminal

`Start` writes the prompt to stdin and closes it (like claude's
`begin`); stdout is decoded per D3; stderr is drained and discarded
(it carries messages such as `Error: Session not found`, never mapped
to `Reason`). Sequence numbers are adapter-assigned, monotonic per
attempt.

Terminal computation at stream end (mirror of claude `finish`):

1. adapter-initiated stop (protocol/session mismatch) →
   `failed` + stop reason;
2. else error event recorded → `failed` + `harness_api_error`;
3. else `Kill` requested → `killed` (empty reason, Central's own);
4. else exit 0 → `succeeded` (empty reason);
5. else → `failed` + `harness_exited_without_result` (covers the
   empty-stream resume refusal and any silent non-zero exit).

`Interrupt` returns an error (no seam, E6): the orchestrator kills the
scope at once, so a Central stop always settles `killed`. Once the
terminal is recorded, `Interrupt` returns `ErrSessionEnded` instead
(mirror of claude), so a post-result stop path never kills at once.
`Send` returns `ErrUnsupported` (no production caller exists).
`RespondPermission` returns `ErrNoPendingPermission` (no request is
ever emitted). `Wait`/`Kill` follow the `port.Process` contract;
`Events` closes after the terminal event.

### D5 — Probe

`opencode --version` through the launcher in the probe workdir,
parsed strictly (`1.18.32` plus newline; exact bytes verified at plan
stage). No auth probe exists (E9): `Authenticated` is always true and
`Detail` says `opencode has no single login; per-model auth failures
surface as harness_api_error`, plus the pin verdict when the version
differs (same shape as claude). A version mismatch fails each attempt
at `Start` (like claude), not at probe: the dispatcher does not gate
on version.

### D6 — Start/Resume/Reconcile

`Start`/`Resume` validate the spec, require the absolute-dir `PATH`,
refuse `Permission != deny` with `ErrUnsupported`, refuse positive
`Limits.MaxTurns`/`MaxCostMicroUSD` (no native surface; the
orchestrator already withholds the cost limit when `NativeCostLimit`
is false), refuse a worktree containing `opencode.json`,
`opencode.jsonc` or `.opencode` (any file type; stat failure also
refuses), check the pinned version, then launch. Refusal (rather than
a harness ignore flag) is the only mechanism: the harness's
`OPENCODE_DISABLE_PROJECT_CONFIG` switch is env-only and unsettable
under the `OPENCODE_` launch-env denylist. Resume passes
`--session` with the recorded id; the id guard in D3 makes a silent
fresh session impossible (the Canvas defect). `Reconcile` reports
scope aliveness only (no reattach): a live scope is killed and the
attempt goes `ambiguous`, exactly like claude.

### D7 — Parity surface (3a–3m)

| Phase | OpenCode backend | Fail-closed gap behavior |
| --- | --- | --- |
| 3a serve wiring | supported via the backend selector (D9) | unknown backend refuses startup |
| 3b artifacts (report/patch/commits) | supported unchanged (report = final `Message` text; patch/commits from the worktree) | empty final text follows the existing report-missing path |
| 3c approvals | Deny supported (E4) | Bridge/Auto-allow refused at Start (D8) |
| 3d budgets | wall clock + Central cost backstop supported (step-scope fold exists) | no native limit passed or accepted |
| 3e cancel/recovery | cancel via scope kill; recovery via kill + `ambiguous` | terminal is `killed`, never `interrupted` |
| 3f prepared cancel/epoch resume | supported (adapter-independent + `Resume`) | — |
| 3g resume ambiguous | supported via `--session` + id guard | unknown id fails the attempt, never a silent fresh session |
| 3h eligibility guard | supported (adapter-independent) | — |
| 3i resume minors | supported (adapter-independent) | — |
| 3j task cost cap | supported (usage-driven) | — |
| 3k rerun | supported (adapter-independent) | — |
| 3l token ceiling | supported (usage-driven; billed = in+out+cache-write, reasoning folded into out) | — |
| 3m live usage display | supported (usage-driven) | — |

### D8 — Non-Deny refusal

Backstop (required): the adapter refuses `bridge`/`auto_allow` at
Start/Resume (D6) → the Run settles `harness_launch_failed` with the
cause in the error (never a silent downgrade to deny).
Submit-time (required): under the opencode backend the submit form
offers deny only, with a note naming the backend; a submit carrying
bridge/auto_allow is refused server-side. Exact handler and plumbing
(`HarnessOperator` backend surfacing) are pinned at plan stage.

### D9 — Serve wiring

- `CENTRAL_HARNESS_BACKEND=claude-code|opencode`, default
  `claude-code`, validated only when harness execution is enabled. An
  unknown value refuses startup with `errHarnessConfig` naming
  `CENTRAL_HARNESS_BACKEND` (reported as `CONFIG_INVALID`).
- `CENTRAL_HARNESS_OPENCODE_VERSION`, default `1.18.32`, shape
  `1.2.3`, same validation as the claude pin. The non-selected
  backend's version var is ignored (documented).
- Shared factory `newHarnessAdapter(hc, launcher)` returning the
  `port.Adapter` plus the recorded adapter version
  (`claudecode/phase-3a` or `opencode/issue-126`), used by both
  `composeHarness` and `composeSchedulerHarness`. The backend is
  serve-wide; per-Task mixing is not expressible.
- #110 is untouched: the campaign stays on the default backend via
  its specs/plans; no gate changes.

### D10 — Deployment: program, home, mounts

`setup.sh` gains `--opencode-program` (default the operator's
`~/.opencode/bin/opencode`, resolved; the binary must lie beneath a
read-only mount or outside HOME, same rule as claude) and writes a
second harness home (`harness-home/opencode`) with mount points for
the opencode data dirs: `.config/opencode`, `.local/share/opencode`
(auth, DB, sessions) and `.cache/opencode`, all read-write (the
harness's own state), plus the read-only program mount when the
program lives under HOME. Daemon config lines use the existing keys
(`harness opencode <path>`, `home_dir`, `mount`). Exact mount list is
verified against the pinned binary at plan stage (ro-vs-rw for the
program dir depends on the install layout).

### D11 — Daemon grammar

`policy.c` gains `opencode_argv_kind`: probe `["--version"]`, else
`run --format json [--model <safeModel>] [--session <ses-id>]` with
no further args; `chl_harness_has_grammar` admits `opencode`; the env
policy already mirrors `env.go` (opencode relocation/credential names
are denied). `test_launcher.py` gains accept/refuse cases for every
production. No `PROTOCOL.md` change (wire untouched).

### D12 — Product surfaces

Web permission view: the `~/.claude` note and auto-allow warning are
backend-aware (opencode: deny-only note + a pointer to the runbook's
permission section). Budget view: the subscription-estimate note is
backend-aware (opencode costs are per-step computed USD, 0 on free
models). Wording is pinned at plan stage; no new page or route.

### D13 — Docs and records

`docs/operations/harness-execution.md` gains the opencode backend
section: install the pinned version, provider login (`opencode
providers login`), enable (`CENTRAL_HARNESS_BACKEND=opencode`),
permission semantics (defaults + auto-reject + the project-config
refusal), cost/token notes, troubleshooting (model/auth errors →
`harness_api_error`; `Session not found`; version mismatch), and the
version-pin update flow (verify new version → bump default +
`CENTRAL_HARNESS_OPENCODE_VERSION` → rerun setup → re-run
conformance). `docs/internal/tasks/` records the fix-requirement
analysis per the SC-DEF convention. The governing boundary design's
v2 premise (§1 table, §14.4) is stale (E10); updating it is a
maintainer follow-up, not this issue.

### D14 — Tests (machine tier)

- Unit: argv builder (accept/refuse matrix incl. prompt-never-in-argv),
  frame decode (every D3 row + malformed/unknown), session terminal
  table (D4), probe parsing, capabilities validation, config
  (selector + pin, invalid names the variable), composition (both
  sites select the backend; default unchanged), daemon grammar cases.
- Scripted fixtures captured from 1.18.32 (checked in as NDJSON):
  success, tool use, tool error, denied tool (E4), API error, bad
  model, resume, unknown-session empty stream, unknown-type tolerance.
- Integration: scripted launcher runs (launch/stream/cancel/capture/
  policy-refusal) through `localexec`.
- Live (gated, same convention as `claudecode_live_test.go`): probe +
  one tiny `run` against the pinned binary; skipped by default.
- Regression: full `make test` (and the repo's static gates) plus
  `TestPhase2RecoveryMatrix` 23/23 green, 0 inconclusive, S1–S8
  vocabulary verbatim.
- Rehearsal (criterion 5): a documented dev run — one submitted Task
  end to end through the opencode backend with report/patch/commits
  artifacts captured; exact commands pinned at plan stage.

## Acceptance mapping

1. Parity surface: D7 table (3a–3m per item, gaps fail closed).
2. Selector + pins: D9 (default claude-code; invalid refuses startup
   naming the variable; serve-wide, no mixing).
3. Machine-tier proof: D14 (unit + integration + gated live;
   23/23 regression).
4. Runbook: D13.
5. Live rehearsal: D14 (documented dev run).

## Constraints honored

ADR 0035/0036: no harness credential handling (no credential env set
or read, no config relocation — the denylist already covers
`OPENCODE_*`; operator login precedes use); serve never execs (all
launches via `port.ProcessLauncher`); closed launch parameters;
prepare/invoke-outside/persist-outcome unchanged in the orchestrator.
Fail-closed literal vocabulary: D3/D4 reasons reuse
`execution.FailureReason` strings verbatim; no harness text in
`Reason`, errors or logs. Idempotent retriable paths: probe, version
check and kill are idempotent; Start/Resume are single launches under
the orchestrator's existing claim protocol (no new retry loop). No
weakened check, no wire change, no historical-evidence edit.

## Out of scope (recorded follow-ups, not this issue)

Serve+SSE or v2 tracking; generic ACP (phase 5); Bridge/Auto-allow
mapping; reattach; reasoning passthrough (`--thinking`); fork;
native cost limits; per-Task backend selection; boundary-design v2
premise update (maintainer follow-up, D13).

## Open points for plan stage

1. Exact `--version` bytes (newline form) for the strict parser.
2. `step_finish` `reason` enum from source (informational only per
   D3; confirm no abort/max-steps signal the terminal needs).
3. claude misc-frame/unknown-frame handling to mirror (skip-vs-error
   boundaries) and `SessionStarted.HarnessVersion` value (probed vs
   pinned).
4. Tool I/O byte mapping (`Input`/`Output` encoding of `state.input`
   / `state.output`) mirroring claude's conventions.
5. Submit handler + `HarnessOperator` plumbing for deny-only
   submit-time refusal (D8); web wording (D12).
6. `~/.opencode` install-layout check for the ro program mount (D10);
   cache-dir necessity. (HOME-based dir resolution is already
   verified: the empty-HOME probe created `.cache/.config/.local`
   under the overridden HOME.)
7. Rehearsal composition (existing e2e harness vs full serve) and
   exact commands.

## Spec self-review

Placeholders: none (open points are plan-stage pins with owners, not
TBDs). Consistency: Deny-by-default (E4/S) matches D3/D6/D8; no-auth
(E9) matches D5 + dispatcher-pause analysis; no-interrupt (E6) matches
D4/D7-3e; project-config load (E8) matches D6; reason subset matches
the `failureReason` fallback rule; capabilities match the two
capability reads in the orchestrator (`ResumeByID`, `NativeCostLimit`)
plus behavior-driven errors elsewhere. Scope: one adapter + wiring +
deployment + docs; serves+ACP explicitly excluded. Ambiguity: "mixed
config" is defined (D9: serve-wide, no per-Task mixing, unknown value
refuses); "model/auth decided by operator config + login" holds (D2
passes `--model` only when the serve config sets one; credentials
never touched).
