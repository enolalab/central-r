# Phase-2 run submission (issue #122)

Production entrypoint for workflow runs: `central run submit` (CLI) and
`POST /app/runs/submit` (runs-list form), sharing `internal/runsubmit`.

## Pinned command

```text
CENTRAL_NODE_DSN=<runtime-dsn> central run submit --workspace 019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a --title <title> --workers 2 --run-key <fresh-key-per-run>
```

- `--workspace` pins the exact workspace; the value above is the sentinel
  workspace (`pgsession.SentinelWorkspaceID`) that serve's scheduler
  worker claims for. Other workspaces submit fine but no serve worker
  will claim their nodes.
- `--workers 1..8`; `--title 1..200` runes; `--run-key 1..128` bytes.
- `--run-key` must be fresh per intended-new-run. Re-issuing with the
  same key adopts the recorded run when the payload matches
  (`deduped:true`) and conflicts with `DUPLICATE_IDEMPOTENCY_KEY`
  otherwise; without a key every call mints a fresh run.

## Prerequisites

- Migrated PostgreSQL with the sentinel workspace row present
  (instance provisioning owns workspaces; submit performs no pre-check
  and fails at the first commit for unknown workspaces).
- Serve running with `CENTRAL_PHASE2_SCHEDULER=1` for dispatch
  (+ `CENTRAL_HARNESS_ENABLED=1` for real sessions; without it serve
  refuses startup unless the stub dev gate is set — never a real path).
  Serve env per `docs/operations/harness-execution.md` plus the harness
  launcher daemon for the real launch path.
- `CENTRAL_NODE_DSN` carries a DSN with the task + workflow + journal
  writes (the `central_runtime` grant set; node-decide parity).

## Verify

```sql
-- nodes of the run (expect leader + workers, all ready right after submit)
SELECT node_key, state FROM central.workflow_nodes
 WHERE run_id = '<run>' ORDER BY node_key;
-- attempts once the scheduler claims (expect one row per node)
SELECT n.node_key, a.attempt_seq, a.state, a.harness_session_id
  FROM central.session_attempts a
  JOIN central.workflow_nodes n ON n.id = a.node_id
 WHERE a.run_id = '<run>' ORDER BY 1, 2;
-- journaled outcome (expect node_ready/node_dispatched per node, then
-- either attempt_started with real sessions or a fail-closed refusal)
SELECT kind, reason_code, count(*)
  FROM central.run_events WHERE run_id = '<run>' GROUP BY 1, 2;
```

## HTTP

`POST /app/runs/submit` from the form on `GET /app/runs` (same service,
session workspace); success answers `303` to `/app/runs/detail?run=<id>`.

## Replay

Same `--run-key` + same payload (`--title`, `--workers`) → recorded run
adopted, no second nodes (`deduped:true`). Same key + different payload
→ `DUPLICATE_IDEMPOTENCY_KEY`, recorded row stands, nothing emitted.

## Appendix: rehearsal transcript (2026-10-09)

Environment: container PG `postgres:16` (scratch database), production
`central` binary built from this branch, `CENTRAL_NODE_DSN` on the
`central_runtime` role (production grants), scheduler stack composed via
the production `composeSchedulerHarness` + `composeScheduler` + preflight
functions (serve's own composition; the serve binary wrapper needs a full
instance with broker/helper and was not runnable here). No launcher
daemon in the container; `claude` binary present but no harness session
was attempted past the daemon dial.

Submit (verbatim envelope, ids real):

```text
$ CENTRAL_NODE_DSN=<runtime-dsn> central run submit --workspace 019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a --title "122-rehearsal" --workers 2 --run-key "r122-rehearsal-1"
{"schema_version":"central.local-result/v1","command_id":"run.submit","exit_code":0,"reason":"ok",
 "details":{"run_id":"01a11f1d-8428-762a-aaa4-bc70476d32c8",
 "task_id":"01a11f1d-8428-7629-b736-f65504dbe2c0",
 "nodes":[{"node_id":"...","node_key":"leader","state":"ready"},
          {"node_id":"...","node_key":"worker-1","state":"ready"},
          {"node_id":"...","node_key":"worker-2","state":"ready"}],
 "deduped":false,"elapsed_ms":144}}
$ # replay, same key:
$ CENTRAL_NODE_DSN=<runtime-dsn> central run submit --workspace ... --title "122-rehearsal" --workers 2 --run-key "r122-rehearsal-1"
0 ok True 01a11f1d-8428-762a-aaa4-bc70476d32c8   # exit, reason, deduped, run
```

DB after submit: 3 nodes `ready` (`claude-code`/`directory`); run row
`running`, owner `phase2`, key recorded.

Scheduler window (90 s, production worker + claim loop + dispatcher +
real launcher): all 3 nodes claimed (`node_dispatched` ×3), workspace
provisioning ran, the real launcher's scope guard dialed the absent
daemon and fail-closed per #111 D2 (`ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN`
×3, sessions empty). Final states: all `attempt_ambiguous`, exactly one
`ambiguous` attempt per node, `node_ready`/`node_dispatched` exactly once
each (no auto-rerun across the whole window — kill-confirmation-adjacent
split holds), worker deregistered and leases released on shutdown, no
stray processes.

Not proven here (environmental): real harness sessions — needs the
launcher daemon + authenticated harness on a real host. That half is the
#110 physical-tier run, which this entrypoint unblocks.
