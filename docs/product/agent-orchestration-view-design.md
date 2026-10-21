# Agent orchestration view — data-source design

Status: design proposal (2026-08-18). This documents what a "watch the agents
work" view can honestly show given Central's actual model, and what each richer
version would require. It deliberately proposes no schema change and writes no
new domain command — the load-bearing parts need an ADR, called out below.

## Why this exists

The office view (`/app/office`) visualises tasks as workers in status rooms
from the live projection. The next ambition — a "leader coordinating workers,
each worker's live thoughts" (the virtual-office mockup) — needs a data source.
Before building UI, this pins down which of those concepts Central actually
has, so we ship a view backed by real data rather than a convincing fiction.

## What Central actually models today

- **One coordinator per run, single lane.** Agent execution is the B09
  provider/tool coordinator (`internal/agent/app/coordinator.go`) — "the
  single-lane B09 provider/tool coordinator". A run advances in **provider
  turns** (`agent.ProviderTurnID`, one per provider POST). There is **no
  leader delegating to many worker subagents**: no fan-out, no parallel worker
  lanes.
- **No task decomposition tree.** `Task.ParentTaskID` exists but is **only
  rerun lineage** (the cancelled task a rerun descends from — see
  `internal/task/domain.go`), not a leader→subtask hierarchy.
- **The read model exposes Tasks and Runs only.** `internal/task/app/query`
  projects `TaskSummary`/`TaskDetail` and `RunSummary`. That is everything the
  overview, detail, and office views consume.
- **Lifecycle events are persisted but not queryable.** Every transition
  writes a durable event to `central.events` (kinds: `task.submitted`,
  `task.claimed`, `task.wait`, `task.resumed`, `task.retry_scheduled`,
  `task.retry_activated`, `task.completed`, `task.failed`,
  `task.cancel_requested`, `task.cancelled`, `task.run_transition`), counted by
  `central.workspace_event_counters` (the `EventRevision` the detail poller
  already compares). **There is no read API over this log** — `query` exposes
  no `ListEvents`.
- **Provider turns / tool calls are B09-internal.** They are not projected into
  any read model.

## Mapping the mockup to reality (the honest gaps)

| Mockup concept | Central reality |
| --- | --- |
| A **leader** chatting with the operator and delegating | The per-run coordinator is a single lane; there is no delegator-over-workers entity to surface. |
| Many **workers**, one per subtask, running in parallel | Not modelled. One coordinator advances one run. |
| Each worker's **live "thoughts"** | The closest real signal is provider turns + tool calls — B09-internal, not persisted in a queryable form. |
| A **live activity feed** | Real and already persisted: the `central.events` lifecycle log — but not yet exposed by a read API. |

The takeaway: the leader/worker/thoughts framing does not correspond to
anything Central models today. Shipping it as if it were live would mislead the
operator. What *is* real and underused is the durable event log.

## Recommended data source and sequencing

### Step 1 — Live activity stream from the existing event log *(done)*

> **Status (2026-08-18):** complete. A new `query.TaskEventLogRead` port over
> `central.events` (no migration; bounded, non-sensitive columns only) powers
> all three surfaces: the instance feed (`GET /app/activity`), a per-task
> timeline on the detail page (task-scoped filter), and the office activity
> ticker (recent events embedded in the office page; the canvas flashes a
> worker when its task emits a newer event).


The one genuinely-available, already-durable source is `central.events`. Add a
**bounded, workspace-scoped read projection** over it and nothing else:

```go
// in internal/task/app/query
type TaskEvent struct {
    Sequence  int64            // from workspace_event_counters ordering
    TaskID    identity.TaskID
    RunID     identity.RunID   // zero when not run-scoped
    Kind      task.EventKind   // the persisted lifecycle kind
    Reason    string           // bounded, non-sensitive (e.g. waiting reason)
    Detail    string           // bounded, non-sensitive summary
    At        time.Time
}

type TaskEventLogRequest struct {
    WorkspaceID identity.WorkspaceID
    TaskID      identity.TaskID   // optional: scope to one task
    Cursor      *EventCursor      // keyset by sequence
    PageSize    int               // bounded, like the task list
}

type TaskEventLogProjection struct {
    Events     []TaskEvent
    NextCursor *EventCursor
}
```

This powers three real surfaces with no fiction:

- **Per-task activity timeline** on `/app/tasks/detail` (interleaved with the
  run history already shown).
- **Instance-wide live feed** — a new `/app/activity` page, or a panel on the
  overview.
- **Office activity ticker** — replace the office's poll-and-redraw with a real
  event feed, and animate a worker when its task emits an event.

**Scope & cost.** The table exists, so **no migration**. It adds a query
contract + a Postgres adapter read + handler/route — a cross-package read-model
addition. Because it extends the domain read surface, it warrants a **short
design/ADR sign-off**, not just a routine change. Safety mirrors the existing
reads exactly: workspace-scoped, keyset-bounded, fail-closed, and only the
bounded non-sensitive columns (kind/reason/detail/timestamps) are projected —
never raw inputs or provider payloads.

### Step 2 — Per-run agent activity (provider turns / tool calls)

To show what a run is *doing* turn-by-turn (the closest honest version of
"thoughts"), expose the B09 provider-turn records. **Correction to the earlier
assumption:** these turns are **not** ephemeral — they are already persisted
for crash reconciliation (`central.b09_provider_turns` /
`central.provider_execution_evidence`), and `execution/port.B09ProviderTurnEvidence`
is already a *safe* read model (bodies, raw arguments, credentials, and host
paths intentionally absent). So Step 2 needs **no new hot-path write and no
migration** — it is a bounded, read-only projection over existing durable data,
restricted to the already-safe fields. Because it crosses B09 execution
internals into the operator read surface, it is decided by
**[ADR 0021](../adr/0021-expose-b09-provider-turn-activity-to-the-operator-read-model.md)**
(Accepted 2026-08-18).

> **Status (2026-08-18):** implemented. A `RunTurnActivityRead` port
> (`internal/execution/app/query`) + a Postgres adapter over
> `central.b09_provider_turns` (safe fields only: turn state + lifecycle
> timestamps, oldest first, bounded) power a **Provider turns** timeline on the
> task detail page for the current run. The reader is an optional web
> capability — a composition that does not wire it simply omits the section.

### Step 3 — True leader↔worker orchestration

Only meaningful if Central grows a genuine **task-decomposition model**: a
leader task spawning child tasks as a tree, distinct from rerun lineage. That
is a core domain change (new relationships, lifecycle, authority) — well beyond
a UI feature, and it **amends ADR 0004's single-agent runtime**. It is captured
in **[ADR 0022](../adr/0022-adopt-a-task-decomposition-leader-worker-model.md)**
(**Accepted 2026-08-18 as a direction**, amending ADR 0004), which scopes
decomposition to the Task level (children each keep their own single-lane run,
preserving ADR 0004's per-run guarantee) and names the seven invariants that
are now binding constraints. Acceptance authorizes **no implementation**: the
required next step is a dedicated design gate that resolves the seven
invariants — now drafted in
task-decomposition design (upstream `central` record: `docs/internal/superpowers/specs/2026-08-18-task-decomposition-design.md`),
which fixes the `task_edges` model, the idempotent bounded spawn command,
roll-up/cancellation, partial-tree recovery, and flags the child authority +
tree-budget derivation as needing its own follow-on ADR. Until that design and
its authority/budget ADR are Accepted, no decomposition code or UI ships, and
the office's leader/worker visual keeps waiting for the real model. A lighter
UI-only correlation-grouping alternative remains available as a separate,
smaller ADR if some grouping is wanted before then.

## Recommendation

Build **Step 1** next: a `TaskEventLog` read projection over `central.events`,
surfaced as a per-task timeline and an instance activity feed, and used to give
the office a real activity signal. It is the honest, low-risk version of "watch
the agents work," reuses already-persisted data, needs no migration, and does
not pretend Central has an orchestration model it lacks. Gate it behind a short
design/ADR sign-off because it extends the domain read model. Steps 2–3 are
real features but each is an ADR-level decision, not a client-side flourish.
