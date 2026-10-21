# Local Web UI — feature specification

Status: draft (2026-08-18). Scope: the operator-facing local web console that
Central already serves on loopback. This spec catalogues the console's current
surface, then defines a prioritised feature backlog (MVP → v2 → v3) with the
safety boundaries each feature must honour.

## What already ships

The console is server-rendered `html/template` over stdlib `net/http` with
`go:embed` assets (no client framework, no external hosts — a strict
`default-src 'none'` CSP), single-operator, loopback-only. Owning packets:
**B06** (Slice A shells) and **B11/B11b** (task console). Package:
`internal/transport/http/gintransport/web` (the `gintransport` directory name
is historical; gin is **not** used).

Routes today:

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | State-resolving entry: bootstrap shell, or ready shell when a session is active |
| `/app/bootstrap`, `/api/v1/session/bootstrap`, `/app/logout` | GET/POST | Session bootstrap exchange and logout (CSRF + Origin enforced) |
| `/app/overview` | GET | Operator overview: instance health, per-status task counts, needs-attention list |
| `/app/activity` | GET | Bounded, newest-first feed of instance task-lifecycle events |
| `/app/office` | GET | Canvas office view of the live task projection (same-origin `/static/office.js`) |
| `/app/tasks` | GET | Bounded task list (seven canonical B11 labels) |
| `/app/tasks/detail` | GET | Task detail: lineage, restart barrier, artifact links, run/turn timelines, harness pending-permission panel, adaptive polling |
| `/app/tasks/submit` `/cancel` `/retry` `/rerun` | POST | B11b task mutations (CSRF + Origin + recovery-claimability enforced) |
| `/app/tasks/harness/resolve` `/resume` `/permission` | POST | Harness operator actions: resolve an ambiguous attempt (mark failed/cancelled), resume it, or answer a bridged permission request |
| `/app/tasks/artifact/preview` `/download` | GET | Artifact body preview (bounded) and attachment download |

The seven task labels are **Empty, Queued, Running, Waiting, Settling,
Unsuccessful, Completed**, mapped from the domain status in `task_view.go`.
Status is always rendered as text, never colour alone.

## Design invariants (every feature inherits these)

1. **The domain owns state.** Reads go through `task/app/query`; mutations go
   through the task domain service. The UI is a mirror, never a shortcut.
2. **The safety boundary is inviolable.** Irreversible recovery operations
   (`restore apply`, `resume`, `abandon`) require **physical-console consent**
   (ADR 0015/0016). The web UI may *initiate* and *observe* such a flow and
   display the exact `CONFIRM <opID>` prompt, but it must never approve one.
   A pty is refused by design.
3. **Artifact bodies never touch Postgres.** Metadata is projected from
   Postgres; bodies stream from object storage, bounded.
4. **Fail closed, disclose nothing across workspaces.** Every new route
   mirrors the existing generic-404 / bootstrap-fallback precedents; no route
   reveals whether a resource exists in another workspace.
5. **Bounded everything.** Reads are page-bounded; responses are capped by the
   admission `ResponseCap`; a truncated view says so rather than implying it
   is complete.
6. **Self-contained + strict CSP.** No external fonts/scripts/styles; assets
   are embedded and served same-origin.

## Backlog

### MVP

- **Operator overview** *(implemented — see below)*. A single landing view
  that answers "is the instance healthy, and what needs me?": instance
  readiness + per-status task counts + a "needs attention" list (Waiting →
  approve, Unsuccessful → retry/rerun). Read-only; reuses existing ports.
- **Act on Waiting tasks** *(partially present)*. The detail page exposes
  cancel/retry/rerun; the overview routes the operator to the tasks needing
  action and, for Waiting tasks, distinguishes the ones that genuinely need a
  human (approval/external input) from the ones the engine resolves on its own
  (retry-delay/dependency/reconciliation). See the constraint below on a
  dedicated **Approve** affordance.
- **Task detail diagnostics** *(implemented)*. The detail page now surfaces
  **why** a task is blocked (`WaitingReason`) or failed (`FailureReason`), a
  **run-history timeline** (per-attempt status + reason + start time), the
  diagnostic record (created/updated as absolute UTC, retry count when
  non-zero), and **what the task was asked to do** (the instruction + target
  repository root parsed from the stored Input, display-only via the same
  canonical parser the submit route validates against) — all from existing
  projection fields, no new domain surface. The detail page also carries
  back-navigation to Tasks and Overview.
- **Instance health panel.** Surface `kernel.HealthSnapshot`
  (state/reason/remediation) prominently — folded into the overview for MVP.

> **Constraint on a web "Approve" button (recorded 2026-08-18).** The only
> transition out of `Waiting` is `task.ResumeSameRun`, an **execution-facade**
> transition (`internal/task/execution_facade.go`) driven by the execution
> engine, not an operator command exposed by `task/app.Service`. Adding an
> operator-facing "Approve" (resume) action from the web would introduce a new
> domain command (who may resume, idempotency, the facade contract) — an
> ADR-level decision, deliberately **not** taken here. Until then the overview
> only *routes* the operator to approval-waiting tasks; it does not resume them.

### v2 — coordination & observability

- **Office view** *(implemented)*. `GET /app/office` visualises the **live**
  task projection as a top-down office: each task is a worker standing in its
  status room, hover shows title/reason, click opens the detail page. It is
  served **same-origin from Central**, so it renders real data from this
  instance (127.0.0.1) under the strict self-only CSP — the key difference
  from a static mockup, which cannot fetch a loopback host. The data is
  server-rendered into `data-*` attributes (no executable data island) and
  drawn by an external same-origin script (`/static/office.js`), respecting
  `script-src 'self'` and `prefers-reduced-motion`. It **live-refreshes** by
  polling this same-origin page (like `tasks_poll.js`), rebuilding in place and
  pausing while the tab is hidden, so it tracks real task-state changes without
  a reload. It is a visualisation over the same projection `/app/overview`
  counts — never a second source of truth.
- **Activity feed** *(implemented)*. `GET /app/activity` — a bounded,
  newest-first feed of the instance's task lifecycle events, projected
  read-only from the durable `central.events` log via a new
  `query.TaskEventLogRead` port (no migration; only bounded, non-sensitive
  columns — never the event payload). Each event links to its task. The same
  reader also powers a **per-task activity timeline** on the detail page
  (task-scoped filter) and the **office activity ticker** (recent events are
  embedded in the office page; the canvas flashes a worker when its task emits
  a newer event). This completes Step 1 of the orchestration-view design.
- **Provider-turn timeline** *(implemented)*. The task detail page shows the
  current run's B09 provider-turn timeline (state + timestamps, oldest first),
  read-only over the durable `central.b09_provider_turns` records via
  `execution/app/query.RunTurnActivityRead` — the safe fields authorized by
  [ADR 0021](../adr/0021-expose-b09-provider-turn-activity-to-the-operator-read-model.md).
  This is Step 2 of the orchestration-view design.
- **Agent orchestration view.** Extend the office and the feed with richer
  coordination detail. This needs more than the lifecycle log; see
  [agent-orchestration-view-design.md](agent-orchestration-view-design.md),
  which finds that Central models a single-lane coordinator (no leader/worker
  tree), that lifecycle events persist in `central.events` but are not yet
  queryable, and recommends a bounded `TaskEventLog` read projection as the
  honest first step (per-task timeline + instance feed + office ticker). The
  leader↔worker framing and per-turn "thoughts" require ADR-level domain work
  and must not be faked in the client.
- **Live event stream.** A unified feed of task/run transitions for the
  session, backed by the same projections the detail poller uses.

### v3 — durability, recovery, administration (highest caution)

- **Backup centre.** List backups (size, checksum, seal state); *initiate*
  `backup create`; the destructive step still goes through the helper +
  console.
- **Recovery board (verify → apply → resume).** The web *prepares and
  observes*; it renders the console `CONFIRM <opID>` prompt but never issues
  it (invariant 2).
- **Authority / identity.** View roles; rotate credentials (rotate-then-sync,
  ADR 0019) with explicit warnings.
- **Dependency / receipt browser.** Inspect the version-zero receipt (ADR
  0020) and dependency-preparation state.

### Cross-cutting quality

Command palette; audited operator-action log; graceful empty/error states
that state cause and remedy; full keyboard operability; colour-blind-safe
status (text labels, already in force); a read-only/demo mode.

### Deliberately excluded

Approving destructive recovery from the web; any path that writes artifact
bodies into the DB; multi-tenant RBAC (Central is single-operator local);
self-issuing governance-gate verdicts.

## First implementation: Operator overview

Route: `GET /app/overview`. Authenticated (unauthenticated → bootstrap shell,
mirroring `/app/tasks`). Read-only, no new domain ports — it composes the
handler's existing `ReadinessProbe.Health()` and `TaskService.ListTasks`.

It renders:

- **Instance health**: the readiness state as a text label plus any bounded
  reason/remediation from `HealthSnapshot`.
- **Task counts** by the six live canonical labels (Queued, Running, Waiting,
  Settling, Unsuccessful, Completed), in a fixed order; the empty case says so.
- **Needs attention**: the operator-actionable tasks only — Waiting (awaiting
  approval), Failed (retry available), Cancelled (rerun available) — each
  linking to its detail page where the existing, fully-guarded mutation lives.
- A **bounded** notice: the counts are taken from one bounded projection page;
  when more tasks exist the view marks the counts as a lower bound rather than
  implying completeness.

Every count and attention row is derived by pure functions
(`overview_view.go`) that are unit-tested independently of HTTP, and the route
is covered by handler tests mirroring the existing `/app/tasks` suite
(authenticated render + unauthenticated non-disclosure).
