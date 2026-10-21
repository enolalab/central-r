# Phase 2 — retry, timeout, and error taxonomy — spec

Status: draft. Design-gate input under issue #91 (deliverable 4 of the
spec-gate table): specifies how Phase 2 classifies attempt outcomes,
when a failed node returns to `ready`, how backoff and attempt limits
are computed, how the three-level timeout hierarchy composes, and what
happens when a node's retry budget is spent. No production code is
authorized by this document.

## Scope

Owns: retryable-vs-terminal error classification; exponential backoff
parameters and per-class attempt limits; the timeout hierarchy
(session → node → workflow); compensation/cleanup hook surface where
required.

Does not own: ambiguous-attempt handling — `attempt_ambiguous` is an
operator decision at every graph level (locked, below); idempotency
key mechanics for commands and steps (spec 5); queue claim mechanics
(spec 1); event canonical fields (spec 6 — this spec only names the
events and reason codes it introduces).

## Locked inputs — maintainer decisions 2026-10-07

1. **Policy retry applies only to definite failures.** A definite
   failure is one whose outcome is known: observed process exit,
   an enforced (kill-confirmed) timeout, a structured adapter error,
   or a dispatch refusal. Nothing else enters the retry path.
2. **Ambiguous session attempts are operator decisions** — launch
   persisted, outcome unknown (ADR 0035 reconciliation, kept for
   children). The retry policy never sees them: no automatic
   re-launch, no automatic rerun, no backoff entry.
3. **Ambiguous parents never auto-anything.** A node or run with an
   `attempt_ambiguous` descendant is blocked on operator resolution;
   timeouts and retry timers do not fire across an unresolved
   ambiguous attempt.

## Design

1. **Error taxonomy.** Every `attempt_failed` and every dispatch
   refusal carries exactly one class and one reason code; the class,
   not the code, decides retryability.

   | class | retryable? | reason codes (this spec's vocabulary) |
   | --- | --- | --- |
   | `transient` | retryable | `PROCESS_EXIT_NONZERO`, `ADAPTER_ERROR`, `RATE_LIMITED` |
   | `dispatch_infra` | retryable | `WORKSPACE_PROVISION_FAILED`, `LAUNCHER_REFUSED` |
   | `session_timeout` | retryable | `SESSION_WALL_CLOCK_REACHED`, `SESSION_COST_CEILING_REACHED` (codes owned by spec 8; emitted on `attempt_failed`) |
   | `terminal` | terminal | `SPEC_VALIDATION_FAILED`, `BUDGET_EXHAUSTED`, `WORKSPACE_UNAVAILABLE`, `CAPABILITY_MISSING` |
   | `node_timeout` | terminal | `NODE_TIMEOUT` |
   | `workflow_timeout` | terminal | `WORKFLOW_TIMEOUT` |

   Unknown or unclassified outcomes are `terminal` by default — the
   taxonomy fails closed; a new retryable class requires a spec
   amendment, not a heuristic.

   Capacity admission is not a failure class: deferral happens before
   any attempt row exists — the node stays `ready` and spec 8's
   `admission_deferred` event with `CAPACITY_ADMISSION_DEFERRED` is
   journaled. No `attempt_failed` is emitted.

2. **Backoff.** For retryable classes the retry delay is
   `delay_n = min(cap, base × multiplier^(n−1))` with full jitter
   applied to the result (`uniform(0, delay_n)`). Proposed defaults
   (OQ-1): `base=30s`, `multiplier=2`, `cap=10m`. A provider-supplied
   `retry_after` hint on `RATE_LIMITED` replaces `delay_n`, still
   bounded by `cap` (OQ-4). The computed instant is journaled on the
   retry event — restarting Central never recomputes or loses it.

3. **Attempt limits.** Each node carries `max_attempts` per retryable
   class (OQ-2 defaults: `transient=3`, `dispatch_infra=5`,
   `session_timeout=2`) plus an absolute ceiling `max_attempts_total`
   (default 5) so mixed failure modes cannot multiply attempts. An
   attempt counts against the class that produced it and against the
   total. The counting attempts are the node's journaled
   `session_attempt` rows — the node, not the attempt, holds durable
   progress (spec 1).

4. **Retry scheduling.** On a definite failure the policy evaluates
   the class: if budget remains it emits `attempt_retry_scheduled`
   `(run_id, node_id, attempt_id, reason_code, retry_at, attempt_seq+1)`
   and returns the node to `ready` with `not_before = retry_at`; the
   scheduler claim requires `not_before ≤ now()` — readiness stays
   event-driven, the delay is a property of the node, not a timer
   Central must keep alive. If budget is spent, the node goes
   `failed_terminal` (decision 7).

5. **Timeout hierarchy.** Three wall-clock bounds, innermost first:
   - **Session timeout** — ceiling on one harness session attempt,
     enforced by the launcher/adapter (the per-attempt wall clock of
     the harness workstream). Expiry kills the attempt; once the kill
     is confirmed the failure is definite (`SESSION_WALL_CLOCK_REACHED`)
     and retryable. An unconfirmed kill is `attempt_ambiguous` — locked
     input 2 applies.
   - **Node timeout** — aggregate bound on a node's elapsed time
     across all its attempts and backoff waits, measured from first
     dispatch. Expiry is `failed_terminal` with `NODE_TIMEOUT`; it is
     a bound, not a retryable class.
   - **Workflow timeout** — bound on the run's graph. Expiry cancels
     running attempts (harness cancel control), transitions
     non-terminal nodes `cancelled` per the spec-1 cascade, and ends
     the run `failed_terminal` with `WORKFLOW_TIMEOUT`.
   The effective session ceiling at dispatch is
   `min(spec_hint, node_remaining, workflow_remaining)` so inner
   bounds fire first; a child spec's budget hints may tighten, never
   loosen, parent bounds.

6. **Compensation hooks.** A child spec may declare
   `on_terminal_failure` naming a cleanup action. Phase 2 executes
   only Central-managed values — `cleanup_workspace` (remove the
   worktree/private dir) and `retain_artifacts` (mark declared
   artifacts kept for inspection). Any other value is journaled as
   `compensation_requested` for the leader/operator to act on;
   agent-authored cleanup code is not auto-executed in Phase 2
   (OQ-3). Hooks run at most once, keyed on the node, and their
   outcome is journaled.

7. **Budget exhaustion.** When any limit in decision 3 is reached,
   or a terminal-class failure arrives, the node transitions
   `failed_terminal` in one task-service transaction with
   `node_failed_terminal` journaled carrying the terminal
   `reason_code` (`RETRY_BUDGET_EXHAUSTED` or the class's code) and
   the failing `attempt_id`. Readiness recomputation then lets
   dependents stay blocked (they never dispatch) and the leader
   observes the event; because the graph is append-only, the leader's
   remedy is emitting replacement or compensation nodes — never
   mutating the dead node.

## Failure semantics

Reason codes introduced here (uppercase, journaled on events):
`RETRY_BUDGET_EXHAUSTED`, `NODE_TIMEOUT`, `WORKFLOW_TIMEOUT`,
`PROCESS_EXIT_NONZERO`, `ADAPTER_ERROR`,
`RATE_LIMITED`, `WORKSPACE_PROVISION_FAILED`, `LAUNCHER_REFUSED`,
`SPEC_VALIDATION_FAILED`, `BUDGET_EXHAUSTED`,
`WORKSPACE_UNAVAILABLE`, `CAPABILITY_MISSING`.
Codes owned by spec 8 but classed here: `SESSION_WALL_CLOCK_REACHED`,
`SESSION_COST_CEILING_REACHED` (`session_timeout`),
`CAPACITY_ADMISSION_DEFERRED` (pre-attempt deferral — not a failure
class, see decision 1's note).
Events introduced: `attempt_retry_scheduled`, `compensation_requested`
— both carrying `(run_id, node_id, attempt_id?, recorded_at,
reason_code?)` per the spec-1 event contract.

## Open questions

- **OQ-1 — backoff defaults.** `base=30s`, `×2`, full jitter,
  `cap=10m` proposed.
- **OQ-2 — attempt limits.** Per-class `3/5/2` plus absolute ceiling
  5 proposed; reviewer decides whether a single flat budget suffices.
- **OQ-3 — compensation execution.** Default: only Central-managed
  actions run; whether any leader-declared cleanup node type is
  worth auto-dispatching in Phase 2.
- **OQ-4 — `retry_after` hints.** Default: honored, bounded by cap;
  alternative is ignore-and-backoff.
- **OQ-5 — default node/workflow timeout values.** Default: unset
  (unbounded) unless the run or child spec sets them; whether Phase 2
  ships a system default (e.g., 4h node, 24h workflow).

## Acceptance criteria

- Spec review records a verdict under `docs/internal/superpowers/reviews/`.
- Every definite-failure path reachable in spec 1's state machine maps
  to exactly one class and reason code here.
- Locked inputs are encoded as rules (decisions 1, 4, 5, 7); nothing
  ambiguous reaches the retry path.
- Reason-code and event vocabulary this spec introduces is named in
  full for the event-schema spec.
- A slice dossier `docs/implementation/phase-2-slices/slice-*.md`
  covers retry/idempotency per the Phase 1 precedent.
