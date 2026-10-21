# ADR 0021: Expose B09 provider-turn activity to the operator read model

- **Number:** 0021
- **Title:** Expose B09 provider-turn activity to the operator read model
- **Status:** Accepted
- **Created:** 2026-08-18
- **Owners:** Central maintainer
- **Decision due:** 2026-08-25
- **Decision due history:** None
- **Implementation blocked at:** Any code path that reads B09 provider-turn
  records (`central.b09_provider_turns` / `central.provider_execution_evidence`)
  for operator display, or that surfaces provider/tool activity through the web
  read model (`internal/task/app/query` + `internal/transport/http/gintransport`).
  The web activity feed shipped for Slice-1 of the orchestration-view design
  (`docs/product/agent-orchestration-view-design.md`) deliberately stops at the
  `central.events` lifecycle log and does **not** read any B09 turn record;
  that boundary holds until this decision.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-08-18)
- **Decision date:** 2026-08-18
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** `docs/product/agent-orchestration-view-design.md` (Step 2 is the
  scope this ADR decides); the shipped activity feed over `central.events`
  (Step 1); the B09 single-lane provider/tool coordinator
  (`internal/agent/app/coordinator.go`); the existing safe turn read model
  `execution/port.B09ProviderTurnEvidence` (`internal/execution/port/b09.go`)
  and its evidence reader (`internal/adapter/postgres/execution/b09_evidence_reader.go`);
  ADR 0005 (verified artifact lifecycle and safe content delivery), whose
  "never surface raw bodies" discipline this decision extends to turn activity.

## Context

The operator web console can now watch **task lifecycle** activity: the
`/app/activity` feed, the per-task timeline, and the office ticker all project
the durable `central.events` log (submitted / claimed / wait / resumed /
retry / completed / failed / cancelled / run_transition). That answers "what
happened to this task," but not "what is this run *doing* right now" — the
turn-by-turn provider and tool activity the virtual-office mockup called
"worker thoughts."

That finer signal is real and **already durable**. The B09 coordinator
(`internal/agent/app/coordinator.go`) advances a run in **provider turns**
(one provider POST each), and every turn's progress is persisted across a
crash for reconciliation: `central.b09_provider_turns` holds the turn records
(turn id, parent turn, binding), and `central.provider_execution_evidence`
holds each turn's state through a closed machine — `prepared → invoked →
responded → tool_prepared → tool_invoked → tool_settled → continued →
reconciled` — alongside request/response **hashes**, token counts, and
per-function-call evidence rows. Sibling tables carry the authorization
decision and price reservation for each turn.

Two facts make this the right foundation:

1. **A safe read model already exists.** `execution/port.B09ProviderTurnEvidence`
   is documented as "a safe read model. Bodies, raw arguments, credentials, and
   host paths are intentionally absent," and the tool-call mapping projection
   likewise "contains only opaque identifiers and hashes; paths, arguments,
   provider bodies, and secrets are intentionally absent." The redaction line
   Central needs for display has already been drawn and is enforced in the
   execution port.
2. **But it is read one turn at a time, for reconciliation only.** The evidence
   reader loads "only the durable evidence bound to one exact provider turn"
   (`B09EvidenceReadRequest`), keyed by the precise turn identity the
   coordinator is resuming. Nothing reads a run's turns as a **sequence**, and
   nothing exposes turn activity to the operator read model or the web layer.

So the data to show "the run is on turn 3, responded, ran two tool calls" is
already committed and already redacted — there is simply no queryable,
operator-facing projection of it, and adding one crosses B09 execution's
durable internals into the web read surface. That crossing, and the exact
fields it may expose, is a decision the read side must not make on its own.

## Decision

**Authorize a bounded, workspace-scoped, read-only projection of B09
provider-turn activity for a single run, restricted to the already-safe fields,
and expose it through the operator read model and web console. Do not add any
new durable write, table, or migration.**

Concretely:

1. **Source.** The projection reads the existing `central.b09_provider_turns`
   and `central.provider_execution_evidence` records (and, where needed, the
   sibling `b09_authorization_decisions` / `b09_price_reservations` rows for a
   turn), scoped to a workspace and one run, ordered by turn sequence. No new
   table is created and no migration ships; the projection reads what B09
   already persists for reconciliation.

2. **No new hot-path write.** The B09 coordinator's write path is unchanged.
   This decision adds only reads; it must not add a durable write, a heartbeat
   row, or any coupling that could slow or fail a provider turn.

3. **Redaction is the existing line, not a new one.** The projection exposes
   only the fields `execution/port.B09ProviderTurnEvidence` and
   `B09ToolCallMapping` already permit — turn sequence/id and parent, turn
   **state**, function-**call count** and opaque call identifiers, token
   counts, reservation state, and timestamps. It **must never** expose provider
   request/response **bodies**, raw tool **arguments**, function/tool **names**
   or **paths**, credentials, or any host path — the same content ADR 0005 bars
   from artifact delivery. Request/response hashes may be shown only as opaque
   correlation values, never decoded. If a field's safety is uncertain, it is
   excluded until the execution owners confirm it.

4. **Bounded and fail-closed like every other read.** The projection is
   keyset-paginated with a bounded page size, workspace-scoped, discloses
   nothing across workspaces, and fails closed — matching the `TaskEventLog`
   read shipped for Step 1. It is consumed through a narrow query port
   (`internal/task/app/query` or an execution-owned query package) and a
   Postgres adapter, then surfaced on the task detail page (a per-run turn
   timeline) and, optionally, as office enrichment.

5. **Scope is observation only.** This decision authorizes *reading and
   displaying* turn activity. It does not authorize any operator action on a
   turn, does not change B09 execution semantics, and does not model a
   leader→worker hierarchy (Central remains single-lane; that hierarchy is a
   separate, larger decision — Step 3 of the design).

## Consequences

### Benefits

- Turns the honest version of "watch the agent think" on — a real, per-turn
  progress timeline — grounded entirely in already-durable data, with no new
  write on the provider hot path and no migration.
- Reuses the redaction discipline execution already enforces
  (`B09ProviderTurnEvidence`), so the risk of leaking provider content, tool
  arguments, or secrets is bounded by an existing, reviewed line rather than a
  new one invented at the read layer.
- Completes the observability arc (lifecycle events → run history → turn
  activity) without pretending Central has an orchestration model it lacks.

### Costs and limitations

- **Couples the operator read model to B09 execution internals.** The turn
  tables and state vocabulary exist for reconciliation; exposing them makes
  their shape a read-surface dependency. As B09 evolves, the projection and any
  displayed state labels must be kept in step, and the state names
  (`tool_prepared`, `continued`, …) may read as implementation detail unless
  mapped to operator-friendly phrases.
- **Single-lane only.** It shows one coordinator's turns per run; it is not a
  leader/worker view and must not be presented as one.
- **Adds read load** to the execution turn tables from the web layer; the
  bounded, paginated, indexed read must be verified not to contend with the
  coordinator's own reconciliation reads.
- The safe-field set may prove too thin to be interesting (counts/states/hashes
  only); enriching it later is itself a follow-up decision, not a default.

## Alternatives considered

### Add a new append-only activity log written by the coordinator

Have B09 write a dedicated, display-oriented activity row per turn/tool call.
Rejected: it adds a durable write on the provider hot path, a new table, and a
migration, and it **duplicates** data the turn records already hold — buying
nothing over reading the existing, already-safe records, at real cost to the
execution path this project is trying not to perturb.

### Do nothing — keep only the `central.events` lifecycle feed

Rejected: lifecycle events do not show intra-run turn progress, which is
exactly the "what is it doing now" signal Step 2 exists to provide. The gap
would remain, and the mockup's "thoughts" would stay unbacked.

### Expose richer turn content (bodies, arguments, tool names/paths)

Rejected: it violates the existing safe-model discipline and ADR 0005, and
risks leaking provider content, user data, secrets, or host paths into the
operator UI. Any future widening beyond the safe set is a separate decision.

## Follow-ups

- If accepted: add a narrow read port + Postgres adapter over
  `central.b09_provider_turns` / `central.provider_execution_evidence` (safe
  fields only), then a per-run turn timeline on the task detail page and
  optional office enrichment — mirroring the Step-1 `TaskEventLog` slice.
- Confirm with the execution/B09 owners that the chosen field set is stable and
  safe to display, and agree operator-friendly labels for the turn states.
- Decide separately whether function/tool **names** (not arguments) are safe to
  surface; excluded by default under this decision.
- Verify the projection's read pattern does not contend with the coordinator's
  reconciliation reads on the same tables.

## References

- `docs/product/agent-orchestration-view-design.md` — Steps 1–3; this ADR
  decides Step 2.
- `internal/agent/app/coordinator.go` — the single-lane B09 provider/tool
  coordinator and its turn loop.
- `internal/execution/port/b09.go` — `B09ProviderTurnEvidence` and
  `B09ToolCallMapping`, the existing safe read models this decision reuses.
- `internal/adapter/postgres/execution/b09_evidence_reader.go` — the current
  one-turn reconciliation reader over `central.b09_provider_turns` /
  `central.provider_execution_evidence`.
- ADR 0005 — verified artifact lifecycle and safe content delivery (the
  "never surface raw bodies" discipline extended here).
