# ADR 0035: Freeze the B09 loop coordinator and adopt a harness-session adapter boundary

- **Number:** 0035
- **Title:** Freeze the B09 loop coordinator and adopt a harness-session adapter boundary
- **Status:** Accepted
- **Created:** 2026-09-27
- **Owners:** Central maintainer
- **Decision due:** 2026-10-04
- **Decision due history:** None
- **Implementation blocked at:** Any production code that implements the `HarnessAdapter` port or a concrete harness adapter, wires harness execution into `central serve`, adds a schema migration for harness sessions, or deletes frozen B09 code. Writing the linked specification, prototypes outside production composition, and competitor research are not blocked.
- **Decided by:** Central maintainer
- **Decision date:** 2026-09-27
- **Decision record:** Git status-transition commit; exact hash resolved by this file's Git history
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0004
- **Amended by:** None
- **Related:** [Harness Adapter Boundary Design](../internal/superpowers/specs/2026-09-27-harness-adapter-boundary-design.md), [B09 Agent Adapter Boundary Design](../internal/superpowers/specs/2026-08-03-b09-agent-adapter-boundary-design.md), [ADR 0004](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md), [ADR 0021](0021-expose-b09-provider-turn-activity-to-the-operator-read-model.md), [ADR 0022](0022-adopt-a-task-decomposition-leader-worker-model.md), [current phase](../implementation/current-phase.md)

## Context

ADR 0004 commits Phase 1 to "one durable Agent Task through a sequential model-and-tool loop" owned by a Central runtime coordinator. B09 realized that commitment as a provider-turn coordinator: `internal/agent/app/b09_turn_planner.go` and `b09_context_builder.go` plan each model turn, `agent.ProviderRequest` carries `Model` and `ContextHash`, `agent.ProviderOutcome` returns `Calls []FunctionCall`, and `internal/agent/domain.go` enforces `MaxProviderTurns`, `MaxToolCallsPerStep`, and per-run token ceilings.

The 2026-08-03 B09 Agent Adapter Boundary Design already moved provider selection, credentials, and provider HTTP out of Central ("Central runtime -> agent adapter (OpenCode or another agent) -> provider"). The code did not follow through: `agentport.Provider` is still a per-turn interface, and its only implementations are test doubles (`cmd/central/b09_dispatcher_test.go`, `cmd/central/b12_slice_b_acceptance_test.go`, `internal/agent/app/coordinator_test.go`). `composeB09` is called only from a test, and `serveComposition.B09Dispatcher` is nil in production (`cmd/central/serve_composition.go:153-157`). The shipped binary therefore executes no agent work.

On 2026-09-27 the Central maintainer positioned Central as a product that centrally manages agents and their artifacts **without intervening in the harness or agent loop** of the agents it manages (Claude Code, Muse Code, OpenCode, OpenCode v2). A source-level comparison the same day found that loop-level orchestration is where mature ecosystems (LangGraph, OpenHands, OpenWorker) already lead. It also found that Central's differentiated assets sit at the session, state, credential, and artifact layers: Postgres-fenced leases, reconcile-before-reinvoke recovery, an object-storage artifact lifecycle, a root credential broker, backup/restore. A per-turn coordinator contradicts the new positioning and cannot drive a harness that owns its own loop.

## Decision

Central adopts the following, amending ADR 0004 only in the clauses named below.

### 1. Freeze B09 loop-level code

The following are **frozen**: `internal/agent/app` (coordinator, `b09_turn_planner`, `b09_context_builder`, `b09_execution_driver`, report materializer), the per-turn `agentport.Provider` and `FilesystemTool` ports, `cmd/central/b09_dispatcher.go`, the B09 PostgreSQL binding, and the ADR 0021 provider-turn read-model surfaces.

Frozen means:

- no new behavior;
- code keeps compiling and its existing tests keep passing;
- fixes only when they are needed to keep the build or tests green;
- never wired into `central serve`;
- no deletion until a later decision records what is removed and how existing B09 tables are migrated or retired.

The unaccepted B09 v24 restart-resume candidate is not pursued.

### 2. The agent boundary is a harness session, not a provider turn

A **harness** is an external agent program that owns its own loop: provider and model selection, prompts and context, tool execution, subagents, and provider retries. Claude Code and OpenCode are harnesses.

The unit of external effect Central models is one **harness session attempt**: one launch or resume of a harness process against one workspace for one Run. Central does not model, plan, count, or retry individual model turns or tool calls inside a harness.

### 3. Central's responsibilities at this boundary

- Task/Run lifecycle, leases, and fencing for harness session attempts, through the task domain service.
- Workspace provisioning and isolation for the harness process.
- No harness credential handling. Harnesses authenticate with the operator's own pre-existing login, whether subscription or API key. Central never stores, injects, reads, copies, or proxies harness credentials, and it does not relocate a harness's config directory. The operator must log in to each harness before use. Central runs harnesses only as the operator, on the operator's host.
- Launch, cancellation, and wall-clock/cost ceilings at session granularity, using whatever usage the harness reports.
- Ingesting harness events as read-only evidence for the operator read model.
- Bridging harness-initiated permission requests to operator approval and returning the operator's answer.
- Forwarding operator-authored follow-up input.
- Capturing outputs (workspace diff, declared files, final report) into the Artifact lifecycle of ADR 0005.
- Restart reconciliation: a session attempt interrupted after launch is **ambiguous**. Central never re-launches it automatically. The operator chooses harness-native resume (by the recorded harness session identifier, where the harness supports it) or a fresh Rerun.

### 4. Non-intervention rule

Central must not:

- rewrite or inject prompts or context mid-session;
- fabricate or alter tool results;
- change harness configuration beyond launch parameters declared in the adapter contract;
- make loop decisions from parsed harness output.

Permission answers, cancellation, and operator follow-up input are the only inbound signals. Each is originated or explicitly configured by the operator, and each is delivered through a control the harness itself exposes.

### Amended ADR 0004 clauses

| ADR 0004 clause | Effective rule after this ADR |
| --- | --- |
| Context: Phase 1 executes one Agent Task "through a sequential model-and-tool loop" | Phase 1 executes one Agent Task through one sequential series of harness session attempts; the model-and-tool loop belongs to the harness. |
| "provider physical attempts are immutable StepAttempt evidence under a stable logical provider-operation identity" | Harness session attempts are the immutable attempt evidence; Central records no per-provider-turn attempts. |
| "provider and tool calls use prepare, invoke outside transaction, and persist outcome" | Harness launch, resume, and cancel use prepare, invoke outside transaction, and persist outcome. Provider and tool calls inside the harness are outside Central's model. |
| "Checkpoints are immutable verified safe-continuation evidence" | A Central Checkpoint for a harness Run records the harness session identifier and a workspace-state digest; it never serializes loop state. |
| "exact defaults/hard maxima … owned by the linked design" | Session-level ceilings (wall clock, reported cost/tokens, attempt count) are owned by the harness-adapter specification. Per-turn and per-tool-call maxima no longer apply. |

These ADR 0004 clauses are unchanged:

- one sequential coordinator that uses domain commands;
- the single-use authorization fence before secret handoff (for Central's own infrastructure secrets; a harness launch carries no secret);
- one local expiring executor lease;
- the no-executable-Subagent rule for Central itself.

ADR 0022 is not amended. Whether a leader/worker decomposition maps onto multiple harness sessions is left to the ADR 0022 design gate.

The detailed port shape, event normalization, capability flags, and per-harness adapter contracts are owned by the [Harness Adapter Boundary Design](../internal/superpowers/specs/2026-09-27-harness-adapter-boundary-design.md).

## Consequences

### Benefits

- Central's scope matches its positioning, and it stops competing with harness ecosystems on loop features.
- Existing durable assets are reused as-is: Task/Run lifecycle, leases and fencing, reconcile-before-reinvoke, Artifact lifecycle, credential broker, sandbox launcher, backup/restore.
- A shipped `central serve` can execute real agent work as soon as one adapter exists, closing the gap recorded in `current-phase.md`.
- New harnesses are added as adapters, not as Central loop changes.

### Costs and limitations

- Frozen B09 code, about 5.7k production lines in `internal/agent` plus its PostgreSQL binding and tests, remains as maintenance weight until a removal decision.
- Central loses fine-grained evidence: per-turn provider records and per-tool-call attempts inside a harness are visible only as harness-reported events, which Central cannot verify.
- Central inherits harness churn: CLI flags, event formats, and session-storage layouts change outside Central's control and need versioned adapter contracts.
- Harness-native resume is only as reliable as each harness's own session persistence, and side effects already made in the workspace cannot be rolled back by Central.
- Harness credentials are entirely outside Central's control. Central cannot scope, rotate, or revoke them, and the sandbox must expose the operator's harness config directory (for example `~/.claude`) to the harness process. ADR 0003's secret model covers Central's own secrets only.

## Alternatives considered

### Continue B09 as a Central-owned loop

Rejected. It contradicts the maintainer's positioning, duplicates what harnesses already do better, and still has no real provider implementation after the 2026-08-03 boundary design removed the OpenAI adapter.

### Delete B09 code now

Rejected for now. Deletion is destructive and interacts with existing B09 tables and migrations. Parts of the execution-evidence and reconciliation code may be reusable for session attempts. The maintainer chose to freeze, not delete.

### Supersede ADR 0004 entirely

Not selected. The coordinator-through-domain-commands, authorization-fence, and executor-lease decisions remain valid; only the loop-ownership clauses change. A full replacement would also have to absorb the active ADR 0022 amendment.

### Mandate one wire protocol (for example ACP) for all harnesses

Deferred to the specification. Harness control surfaces differ (headless CLI streams, local HTTP servers, ACP), and the choice needs the per-harness capability evidence being gathered.

## Follow-ups

- Central maintainer: review the [Harness Adapter Boundary Design](../internal/superpowers/specs/2026-09-27-harness-adapter-boundary-design.md) and resolve its remaining §15 open questions before phase 2 of its delivery plan.
- Central maintainer: update `docs/implementation/current-phase.md` and the B09 boundary design's status on acceptance.
- Central maintainer: a later decision on removing frozen B09 code and retiring its tables.
- ADR index: add this row (done with this proposal).

## References

- [B09 Agent Adapter Boundary Design](../internal/superpowers/specs/2026-08-03-b09-agent-adapter-boundary-design.md)
- [ADR 0004 — Adopt staged single-agent runtime and verified adapter handoffs](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [ADR 0005 — Adopt verified Artifact lifecycle and safe content delivery](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md)
- [ADR 0021 — Expose B09 provider-turn activity to the operator read model](0021-expose-b09-provider-turn-activity-to-the-operator-read-model.md)
- [ADR 0022 — Adopt a task-decomposition (leader/worker) model](0022-adopt-a-task-decomposition-leader-worker-model.md)
- [ADR governance and index](README.md)
