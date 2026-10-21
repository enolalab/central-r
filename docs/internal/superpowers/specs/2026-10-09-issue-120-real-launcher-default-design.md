# Real launcher as the serve default (BP-1) — Design (issue #120)

- **Date:** 2026-10-09
- **Issue:** #120 — [Phase 2] Wire real launcher (BP-1: unblock #110 physical exit)
- **Parent:** #110 — [Phase 2] Physical-tier exit: RTM-P1–P3 (this issue is blocking prerequisite BP-1)
- **Prior work:** #111 (closed) landed the production `schedulerharness`
  launcher + killer and composes them in serve when the scheduler gate
  AND harness execution are on.
- **Prior verdicts (read-only, never edited):** S2B-G1, S2D-G1, S2F-G1
  Accepted (machine tier); regen #112 evidence.

## 1. Goal

Remove the stub launcher as the default on the serve path. Today
(`serve_composition.go`, scheduler gate on + harness execution off)
serve silently stands up stub dispatch — `attempt_started` journals for
a session nothing runs — as the "dev default". After this issue, the
serve path runs dispatch behind the real launcher by default; the stub
survives only behind an explicit dev-gate flag, loudly flagged, for
machine-tier/dev use.

Done means: scheduler gate on + harness on → real launcher + real
killer (unchanged #111 behavior); scheduler gate on + harness off +
explicit stub gate → stub launcher + unconfirmed kill boundary with a
loud log line; scheduler gate on + harness off without the stub gate →
serve refuses startup (`CONFIG_INVALID`, fail-closed). The machine
matrix stays 23/23 green with the S1–S8 reason-code vocabulary
verbatim, and #110 gets a comment recording the new BP-1 state.

## 2. Findings that shape the design

1. **The real seams already exist and are composed.** #111 added
   `internal/adapter/schedulerharness` (`Launcher` over the claudecode
   adapter + hostlauncher `ProcessLauncher`, `Killer` over
   `KillScope`/`Alive`, shared scope registry, interim brief, session
   drainer) and `composeSchedulerHarness` in serve. This issue is
   gating-only: no new launch, kill, store, or adapter behavior.
2. **The stub default lives in exactly one serve-path branch.**
   `openServeDeps` wires the real pair only `if harnessCfg.Enabled`;
   otherwise `schedulerReq.Launcher` stays nil and `composeScheduler`
   installs `schedapp.NewStubLauncher()` with the warn line
   "scheduler launch seam is the stub launcher -- no harness process
   runs". The nil-default inside `composeScheduler` also serves
   direct composition callers (unit tests); only the serve path
   changes.
3. **The machine matrix cannot break from serve changes.**
   `phase2accept` drives the 23-scenario recovery matrix with
   `ScriptedLauncher`/`ScriptedKiller` directly, never through serve
   composition (#111 design finding 8). Criterion 3 is proved by
   re-running the matrix.
4. **The kill-confirmation split lives in the store, untouched.**
   `sweepSessionBreachTx` maps `(true, nil)` → definite
   `SESSION_WALL_CLOCK_REACHED`, `(false, nil)` → park
   `ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED`, error → abort the pass and
   retry next tick. This issue changes which Killer serve installs in
   the harness-off case (still `unconfirmedKiller`, now only behind
   the explicit stub gate) and never touches the mapping, so
   criterion 2 holds by construction plus regression tests.
5. **Fail-closed refusal is the established composition precedent.**
   `composeSchedulerHarness` containment failure, bad scheduler env,
   and bad harness env all refuse startup with exit 2
   `CONFIG_INVALID`. `loadSchedulerConfig` refuses non-`0`/`1` gate
   values the same way. The new gate follows the same shape.

## 3. Decisions

### D1. New explicit stub dev-gate flag

- Env var `CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB`, read only while the
  scheduler gate is on: `1` allows stub dispatch, `0`/unset forbids
  it; any other value refuses startup (`errSchedulerConfig`,
  consistent with the gate itself).
- `schedulerConfig` gains `AllowStub bool`. `loadSchedulerConfig`
  parses it after the scratch-root validation (order irrelevant; one
  function owns all scheduler env).
- Naming: the `CENTRAL_PHASE2_SCHEDULER_` prefix keeps it in the
  scheduler family; `ALLOW_STUB` states exactly what it permits.

### D2. Serve-path decision table (scheduler gate on)

| harness execution | stub gate | result |
| --- | --- | --- |
| on | * | real launcher + real killer via `composeSchedulerHarness` (unchanged #111 path, containment refusal unchanged) |
| off | `1` | stub launcher + `unconfirmedKiller`, with the loud warn line extended to name the dev gate (D3) |
| off | `0`/unset | refuse startup: exit 2 `CONFIG_INVALID`, "scheduler requires harness execution (CENTRAL_HARNESS_ENABLED=1) or the explicit stub dev gate (CENTRAL_PHASE2_SCHEDULER_ALLOW_STUB=1)" |

Gate off is untouched: empty capability, no store, no launcher, no
refusal — default serve stays byte-identical in behavior.

### D3. Stub stays loudly flagged

- The `composeScheduler` warn line stays for direct (non-serve)
  composition callers.
- On the serve stub-gated path, `openServeDeps` logs an additional
  loud warn naming the dev gate and its consequence: stub dispatch
  journals `attempt_started` for sessions nothing runs; never a real
  run path.
- `StubLauncher`'s doc comment gains one line pointing at the serve
  rule: serve installs it only behind the explicit stub dev gate.

### D4. What does NOT change

- `composeScheduler`'s nil-launcher → stub default (unit-test and
  machine-tier composition use; `scheduler_composition_test.go`
  keeps asserting it).
- `composeSchedulerHarness`, the `schedulerharness` package, the
  store, the Killer mapping, reason-code vocabulary (no new codes;
  the refusal is a startup `CONFIG_INVALID`, not a journaled code).
- `newSchedulerStore(pool, nil)` still selects `unconfirmedKiller`
  as the explicit harness-off default; serve overwrites with the
  real killer on the harness-on path only (existing behavior).
- No migration, no ADR change (ADR 0035/0036 untouched: no new
  credential handling, no argv/env change, closed grammar unchanged).
- Historical evidence files are never edited.

## 4. Data flow

Unchanged shape. The only new edge is startup refusal before any
component starts: scheduler on + harness off + stub gate off fails
in `openServeDeps` with `CONFIG_INVALID`, so no worker, claim loop,
or dispatcher ever exists in that configuration. All three
post-startup dispatch outcomes (`MarkStarted` /
`FailDispatch(LAUNCHER_REFUSED)` /
`AmbiguateDispatch(ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN)`) keep their
producers and vocabulary.

## 5. Errors

- New startup refusal text (English, `CONFIG_INVALID`, exit 2); not
  a journaled reason code, so the S1–S8 vocabulary is untouched.
- Invalid stub-gate value: `errSchedulerConfig` ("must be 1 or 0"),
  same as the scheduler gate.

## 6. Security

- The change strictly narrows execution: configurations that
  previously ran fake dispatch now refuse unless the operator opts
  in explicitly. No permission, peer-authorization, or ceremony
  check is weakened.
- No new env vars reach any harness process; the flag is
  serve-composition-only and never enters `LaunchSpec`/`ProcessSpec`.
- Tests use fake env maps through `loadSchedulerConfig(getenv)` and
  composition-level assertions; no relaxed allowlist or gate.

## 7. Testing

- Unit (no PG, no exec): `loadSchedulerConfig` table — stub gate
  `1`/`0`/unset/invalid × scheduler on/off (off ignores the flag).
- Composition: serve-path decision table test at the
  `openServeDeps`-helper level if it is factorable without
  refactoring production code for tests; otherwise a
  `composeScheduler`-level test plus a startup test asserting the
  refusal string. Existing `composeScheduler` stub-default and
  `composeSchedulerHarness` containment tests keep passing
  unmodified.
- Regression: full `make test` (and `make test-integration` if the
  plan finds it runnable locally) + the S2F recovery matrix
  (`phase2accept`, 23 scenarios) green, 0 inconclusive; reason-code
  grep over S1–S8 verbatim. Fresh run only — no new verdict, no
  edits to historical evidence.
- Probe for criterion 4: with scheduler on + harness off and no stub
  gate, `central serve` exits 2 with `CONFIG_INVALID`; with
  `CENTRAL_HARNESS_ENABLED=1` (valid harness env) the serve path
  composes the real launcher (startup-composition assertion, not a
  live harness run — no credentials on this host).

## 8. Acceptance (issue #120 done)

1. Real launcher is the serve-path default for dispatch; the stub is
   reachable only via the explicit stub dev gate, loudly flagged
   (D1–D3).
2. Kill-confirmation split preserved: unconfirmed kills still park
   `attempt_ambiguous`; no auto-rerun of ambiguous attempts at any
   level (D4 + matrix RTM-19-session regression).
3. Machine matrix 23/23 green, 0 inconclusive, reason-code
   vocabulary verbatim in S1–S8 (§7 regression).
4. The #110 Task 1 Step 1 probe flips to CLEAR: record the wiring
   commit; post a comment to #110 with the new BP-1 state.

## 9. Out of scope (recorded follow-ups, not this issue)

- F1–F5 of the #111 design (instruction carriage, outcome
  collection, orphan reaping, `harness_attempt`-row binding,
  verdicts) — unchanged, still open.
- Live harness runs on this host (no operator harness login, no
  launcher daemon here); physical-tier execution belongs to #110
  RTM-P1–P3 on a prepared host.
- Any new verdict or any edit to historical evidence files.

## 10. Open points for plan stage

- O1. Exact refusal-test seam: factor a pure
  `decideSchedulerLauncher`-style helper vs. asserting through a
  serve-composition test harness. Plan picks the smaller diff that
  does not refactor production code for tests.
- O2. `docs/implementation/current-phase.md` wording update for the
  new default (plan confirms the narrowest truthful edit).
- O3 (spec-review SR-F1). Enumerate every in-repo caller that starts
  serve (or `openServeDeps`) with `CENTRAL_PHASE2_SCHEDULER=1`;
  each either sets the stub flag or asserts the refusal.
