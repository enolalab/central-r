# Production Launcher + Killer Wiring — Design (issue #111)

- **Date:** 2026-10-08
- **Issue:** #111 — [Phase 2] Production launcher + killer wiring (remove 2B/2D stubs)
- **Slices:** 2B (issue #93) launcher stub, 2D (issue #95) Killer stub
- **Prior verdicts (read-only, never edited):** S2B-G1, S2D-G1, S2F-G1
  Accepted (machine tier) (self-issued); S2F-G1 L2 is the fake-harness
  fidelity boundary this issue narrows.

## 1. Goal

Remove the two production-code stubs that bound the machine-tier proof:

1. `schedapp.StubLauncher` behind `scheduler/port.Launcher` (Slice 2B
   dispatch confirms `attempt_started` for a session nothing runs).
2. `unconfirmedKiller` behind `retry/port.Killer` (Slice 2D session/node
   timeouts always evaluate UNCONFIRMED and park ambiguous).

Order per the issue: launcher first (B09 session wiring), then Killer on
the cancel path. Real harness execution stays owned by the
harness-adapter track (ADR 0035/0036 — Central never handles harness
credentials).

Done means: with the scheduler gate on and harness execution enabled,
dispatch starts a real harness session through the shipped adapter and
records its real session id; session-timeout sweep kills go through the
real cancel control with the kill-confirmation split preserved; the
machine matrix stays 23/23 green with the S1–S8 reason-code vocabulary
verbatim.

## 2. Findings that shape the design

1. **The claim carries no agent instruction.** `scheduler.ClaimedAttempt`
   is attempt row + lease + harness name; `workflow.ChildSpecNode`
   (`central.child-spec/v1`) has no prompt field; Phase 2 has no run
   instruction input. `harness/port.StartSpec.Validate` requires a
   non-empty prompt, so the launcher must resolve one from durable node
   facts. Instruction carriage (prompt-as-artifact `prompt_ref`, per the
   Slice A dossier) is a follow-up; this issue ships a deterministic
   interim worker brief and records the follow-up.
2. **Scope ids must be canonical UUIDs.** `hostlauncher` refuses any
   scope id that is not a canonical non-nil UUID, so the attempt scope
   is exactly `attempt.ID.String()` — no prefix. Attempt ids are uuidv7
   (non-nil); one scope per attempt, so a kill can never touch a
   successor attempt (reruns take a new `attempt_seq` and id).
3. **`CENTRAL_ATTEMPT_SCOPE` is not launchable today.**
   `harness.ValidateLaunchEnv` allows only the base list + `LC_*` +
   adapter extras. The name is valid and not denied (no `CENTRAL_`
   prefix ban, no suffix hit), so adding it to the base allowlist is
   the minimal change. It carries IDs only — non-secret, Central-
   injected, exactly what the base list is for.
4. **The session id is known at launch.** The claudecode adapter starts
   with `--session-id <attempt>` where attempt is
   `identity.HarnessAttemptID`; `ParseHarnessAttemptID` converts the
   Phase-2 attempt uuid losslessly. Confirmed launch = `Adapter.Start`
   returned nil: argv validated, version pinned, process launched under
   the recorded scope. The recorded id feeds harness-native resume
   (Slice C: resume uses only the recorded session id).
5. **The store interprets Killer outcomes fail-closed already.**
   `sweepSessionBreachTx`: `(true, nil)` → definite
   `SESSION_WALL_CLOCK_REACHED` through the retry decision;
   `(false, nil)` → park `ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED`; `err` →
   the pass aborts and the sweeper retries next tick (errors are
   ignored per pass by design). So: infrastructure failures propagate,
   a verified-dead scope confirms, a still-live scope reports
   unconfirmed.
6. **Post-restart kills CAN hit the sweep path.** `Store.Reconcile`
   pass 2 expires only leases of workers already in `lost` /
   `deregistered` state — a crashed worker's row keeps its last state,
   so its pre-restart `started` attempts park via the suspect/lost
   ladder (5 missed beats) or lease TTL expiry, up to ~a minute after
   restart. In that window a session-breach sweep can call `Kill` on a
   pre-restart attempt whose scope this process never launched. With
   `localexec` (in-memory scope table, forgotten on restart) that
   kill would mis-confirm, so the Killer must know launch provenance
   (D3.0): only scopes this process launched can confirm. The
   remaining orphan (crash between invoke and `MarkStarted`) is a
   recorded follow-up (F3), not this issue.
7. **Sessions must be drained.** The `port.Session` contract requires
   draining `Events` until close even after `Kill`. A launcher that
   starts sessions must own a drainer per session, or every launch
   leaks a goroutine holding process pipes.
8. **The machine matrix uses scripted fakes, not serve composition.**
   `phase2accept` (`ScriptedLauncher`/`ScriptedKiller`, `phase2inject`
   tag) drives the 23-scenario recovery matrix directly. Serve-
   composition changes cannot break it; criterion 3 is proved by
   re-running the matrix, not by keeping the stubs.

## 3. Decisions

### D1. New adapter package `internal/adapter/schedulerharness`

One package owns both production seams so the scope-naming rule and the
confirmation rule live in exactly one place:

- `Launcher` implements `schedport.Launcher` over a
  `harness/port.Adapter` plus the `harness/port.ProcessLauncher` behind
  it (the launcher needs scope liveness for the D2.4 orphan guard and
  the D2.7 post-error fail-closed check; the adapter alone cannot
  answer those). No concrete adapter or launcher type crosses into the
  scheduler/retry domains — both seams depend on harness ports only
  (AGENTS.md adapter rule).
- `Killer` implements `retryport.Killer` over a
  `harness/port.ProcessLauncher` (`KillScope` + `Alive`).

### D2. Launch flow (B09 session wiring)

`Launch(ctx, spec)`:

0. Harness check: if `spec.Attempt.Harness != "claude-code"`, return
   `("", true, errHarnessUnsupported)` — a definite refusal. This
   launcher ships one adapter; an adapter registry is future work
   (unreachable in practice: registration intersects worker claims
   with the launchable set, which names only `claude-code`).
1. Resolve the prompt via `PromptSource.PromptFor(spec)` (D4).
2. Convert env: `spec.Env` (`K=V` strings) → map; malformed entries
   (no `=`, empty name) are a definite refusal — nothing ran.
3. `attemptID = ParseHarnessAttemptID(spec.Attempt.Attempt.ID.String())`
   (infallible for uuidv7; a parse failure is a definite refusal).
4. Pre-launch orphan guard: `Alive(ctx, scope)` on the attempt scope;
   alive → `KillScope`, re-check; still alive → `(“”, false, err)`
   (unconfirmed — never launch a duplicate agent for one attempt).
   The scope is fresh per attempt so this fires only after a crashed
   prior invoke.
5. `Adapter.Start` with `StartSpec{Attempt, Fence{Generation: 1},
   Workspace{Path}, Prompt, Permission: Deny, Env{Vars, SandboxScopeID:
   scope}}`. Only `Path` is set on the workspace — `StartSpec.Validate`
   requires `Path` alone (spec-review SR4; `BaseSHA` belongs to the
   Phase-1 clone path and is not invented here). Permission is `Deny`
   (fail-safe default; Phase 2 has no
   permission policy carriage yet — same follow-up as instruction
   carriage). Model empty (adapter default); no native limits (Central
   ceilings stay the enforcement point per spec-8).
6. On success: spawn the session drainer (D5) and return
   `(attemptID.String(), true, nil)`.
7. Outcome mapping onto the `port.Launcher` contract:
   - `Start` nil error → confirmed success (D2.6).
   - `Start` error with `ctx.Err() == nil` → `(“”, true, err)`:
     definite refusal → dispatch journals `LAUNCHER_REFUSED`. The
     adapter validates argv, env and pin before exec, so a refusal
     means nothing ran — UNLESS the scope was observed alive at any
     point during this call (spec-review SR2). The call tracks
     `sawLive` across the D2.4 guard observation and a post-error
     best-effort `KillScope` + `Alive` re-check: `sawLive` →
     unconfirmed (a killed-but-possibly-acted session parks
     ambiguous, never silently retries), even if the final re-check
     reads dead. Fail closed, always.
   - `Start` error with cancelled ctx, or empty session id → `(“”,
     false, err/nil)`: unconfirmed → dispatch parks
     `ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN`, never auto-relaunched.

### D3. Kill flow (cancel path)

`Kill(ctx, attemptID)` with `scope = attemptID.String()`:

0. Launch provenance (spec-review SR1): the composition shares one
   in-memory scope registry between `Launcher` (records each
   confirmed `Start` scope) and `Killer`. A kill for a scope this
   process never launched runs best-effort `KillScope` (reaps the
   orphan under hostlauncher; no-op under localexec) and returns
   `(false, nil)` — unconfirmed — without consulting `Alive`. A
   scope unobservable to this process can never confirm.
1. `KillScope(ctx, scope)`; any error other than ctx-cancellation
   propagates (the sweep pass aborts and retries next tick — a
   transient daemon outage must not park attempts ambiguous).
2. `Alive(ctx, scope)`; error propagates the same way.
3. `alive == false` → `(true, nil)`: confirmed → definite
   `SESSION_WALL_CLOCK_REACHED` (retryable `session_timeout` class).
   `alive == true` → `(false, nil)`: unconfirmed → park
   `ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED`.
4. A cancelled ctx returns `(false, ctx.Err())`: the ladder may still
   be running (the `Kill` contract runs it to completion), so the
   outcome is unknowable; the sweep aborts and retries.

No other code changes: the store's confirmed/unconfirmed split, the
`ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED` / `ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN`
vocabulary, and the never-auto-rerun rule are untouched (criterion 2).

### D4. Interim worker brief (prompt resolution)

`PromptSource` is a constructor-injected function
`func(schedport.LaunchSpec) (string, error)` owned by the adapter
package (not a domain port — prompt content is an adapter concern until
instruction carriage exists). The shipped source renders a fixed brief
from durable node facts only: run/node/attempt ids, input artifact
refs, workspace path, and the `central artifact read` direction. (No
node key — `ClaimedAttempt` carries none and ids suffice; see O1.) It directs the agent to
resolve its real instructions from its declared input artifacts in its
workspace and to do nothing outside them. Empty brief is impossible by
construction (fixed template + ids); an error → definite refusal.

Non-intervention (ADR 0035) holds: the brief is Central-originated
worker scaffolding, not operator input; no harness credentials are
touched; no child-spec string reaches argv (closed grammar unchanged).

### D5. Session drainer

Each confirmed launch spawns one supervised goroutine: drain `Events`
to close, then `Wait`, then log the bounded terminal (reason code only,
never content). It never writes durable state — outcome collection
into `RecordOutcome` is the recorded follow-up (needs the
harness-terminal → retry-taxonomy mapping). The drainer exists so
confirmed launches never leak adapter goroutines or process pipes.

### D6. Serve composition gating

- `composeScheduler` gains an explicit real-launcher path: when the
  scheduler gate is on AND harness execution is enabled AND the
  harness launcher factory + adapter build succeeds, serve passes the
  real `Launcher`; otherwise the request's launcher (or stub default
  with the existing loud log line) stands. Default serve is byte-
  identical in behavior.
- `newSchedulerStore` keeps building the store; the Killer seam moves
  to a composition decision: real `Killer` under the same gate,
  `unconfirmedKiller` otherwise. No store change.
- The scheduler path builds its own launcher + adapter pair via the
  same factory + config `composeHarness` uses (pinned version, probe
  dir) — no instance sharing, no lifecycle coupling (O2/O3 resolved:
  `hostlauncher.Launcher` is stateless, and separate clients make
  the question moot).
- Path containment: the real launcher engages only when the scheduler
  scratch root lies beneath the harness worktree root
  (`<data-root>/worktrees`), because `hostlauncher` refuses any
  workdir outside it. Scheduler gate on + harness on + scratch
  outside the worktree root refuses startup with `CONFIG_INVALID`
  (fail-closed, per the `loadSchedulerConfig` /
  `probeHarnessCaptureHost` precedent) — serve must never silently
  run stub dispatch while claiming production wiring. Scheduler on +
  harness off keeps the stub (dev); gate off is untouched.

### D7. Base allowlist addition

Add `"CENTRAL_ATTEMPT_SCOPE": true` to `baseAllowedEnv` in
`internal/harness/env.go` with a comment naming it the Phase-2
attempt-scope carrier (IDs only, non-secret). No denylist change.

## 4. Data flow (happy path)

Dispatch (unchanged shape): provision → `MarkProvisioning` →
`Launch` (real session starts under scope = attempt id; drainer
spawned) → `MarkStarted(attempt, sessionID)` records the real harness
session id → worker heartbeats the lease. On wall-clock breach:
`SweepTimeouts` → `Kill` (scope ladder runs to verified dead) →
`SESSION_WALL_CLOCK_REACHED` → retry decision → node `ready` under
backoff while budget remains. On unconfirmed kill at any level: park
`attempt_ambiguous` for `central node decide`; timers block across it.

## 5. Errors

All vocabulary stays literal (fail-closed; criterion 3):

- Dispatch: `WORKSPACE_PROVISION_FAILED`, `LAUNCHER_REFUSED`,
  `ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN` — same split, new producer.
- Sweep: `SESSION_WALL_CLOCK_REACHED` (confirmed kill),
  `ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED` (unconfirmed kill).
- No new reason codes. Any new error text is `fmt.Errorf` context on
  existing sentinels, never a new code.

## 6. Security

- ADR 0035/0036 unchanged: symbolic program resolution, operator
  identity, empty-start env re-validated by the launcher, closed
  launch-argv grammar, no credential handling. The new code passes no
  new env var except the allowlisted scope carrier, and no child-spec
  string reaches argv unvalidated (D2.5 builds `StartSpec` from typed
  fields only).
- Permission `Deny` default: the agent cannot approve its own tool use
  beyond the harness default-deny posture.
- Permission checks are not weakened to make tests pass: new tests use
  fake adapters/launchers behind the harness ports, never a relaxed
  allowlist or gate.

## 7. Testing

- Unit (no PG, no exec): launcher mapping table over a scripted
  `port.Adapter` — confirmed success returns the attempt-id session;
  pre-launch refusal → `(true, err)`; ctx-cancel → unconfirmed; empty
  session → unconfirmed; malformed env → definite refusal; orphan
  scope alive-then-dead → launches; orphan stuck alive → unconfirmed;
  post-error scope alive → unconfirmed (fail-closed). Killer table
  over a scripted `port.ProcessLauncher` — dead → confirmed; alive →
  unconfirmed; infra error → error. Brief renderer determinism test.
  Drainer: session with scripted events drains to close and `Wait`s
  (no leak under `-race`).
- Composition: scheduler gate on + harness on wires real seams;
  gate on + harness off keeps stub/unconfirmedKiller; gate off
  unchanged (existing tests keep passing).
- Live (local PG + real `localexec`, no network model needed — launch
  is expected to fail closed when claude is absent): dispatch against
  the real launcher with claude missing journals `LAUNCHER_REFUSED`
  (definite, retryable) — proves the refusal path end to end without
  credentials. Kill path live test over `localexec` with a stub
  process scope: kill → verified dead → confirmed.
- Regression: full `make test` + the S2F recovery matrix
  (`phase2accept`, 23 scenarios) green, 0 inconclusive; reason-code
  grep over S1–S8 verbatim. Historical evidence files are never
  edited; the run is a fresh manifest only if the plan requires one
  (criterion 3 needs a witnessed run, not a new verdict).

## 8. Acceptance (issue #111 done)

1. Real launcher wired into dispatch; real kill path wired into
   session-timeout handling (D2/D3/D6,proved by the live tests in §7).
2. Kill-confirmation split preserved: unconfirmed kills still park
   `attempt_ambiguous` (`ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED`,
   `ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN` as listed in S2); no auto-rerun
   of ambiguous attempts at any level (D3.3, §5; covered by unit +
   matrix RTM-19-session).
3. Machine matrix still 23/23 green, 0 inconclusive, reason-code
   vocabulary verbatim in S1–S8 (§7 regression).

## 9. Out of scope (recorded follow-ups, not this issue)

- F1. Instruction carriage: `prompt_ref`-as-artifact (Slice A
  direction) or child-spec prompt field; permission-policy and
  model/limits carriage per node.
- F2. Outcome collection: harness terminal → `RecordOutcome` mapping
  (retry taxonomy classes for adapter reasons) so real sessions
  complete nodes, not just start them.
- F3. Orphan reaping: crash between invoke and `MarkStarted` leaves a
  live scope whose attempt expires never-started; a best-effort
  scope kill on that path or a reconciler orphan pass.
- F4. `harness_attempt`-row binding (the stub comment's "B09 lineage"
  aspiration): deliberately not done — the Phase-2-native binding is
  `session_attempts.harness_session_id` + scope = attempt id, which
  covers kill, resume and operator inspection without mapping Phase-2
  uuids into Phase-1 identity rows.
- F5. Any new verdict or any edit to historical evidence files.

## 10. Open points for plan stage

- O1. Node key for the brief: `ClaimedAttempt` carries no node key.
  Options: (a) omit it (ids suffice); (b) extend the claim read.
  Recommendation: (a) — the brief keys on ids; the key is cosmetic.
  Plan confirms.
- O2. RESOLVED (plan stage): build a second launcher + adapter pair
  for the scheduler via the same factory + config. See D6.
- O3. RESOLVED (plan stage): moot — no instance is shared (O2).
  (`hostlauncher.Launcher` inspected: stateless struct, safe anyway.)
