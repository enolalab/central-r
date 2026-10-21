# Harness Adapter Boundary Design

Date: 2026-09-27
Status: Approved design, governed by [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md)

## 1. Purpose and scope

Central manages external coding-agent harnesses and their artifacts. It never owns or alters a harness's agent loop (ADR 0035 §4). This specification defines:

- the `HarnessAdapter` port;
- the normalized event model;
- the durable harness-session-attempt lifecycle;
- process supervision and crash reconciliation;
- permission bridging;
- credential and config isolation;
- artifact capture;
- the per-harness adapter contracts for the first delivery.

**Non-goals:**

- prompt construction;
- context management;
- tool execution;
- model or provider selection logic;
- subagent orchestration inside a harness;
- multi-host placement;
- replacing a harness's own session storage.

**Harnesses in scope:**

| Harness | Priority | Integration surface | Notes |
| --- | --- | --- | --- |
| Claude Code | 1 | `claude -p --output-format stream-json --verbose`, stdin `--input-format stream-json` | Closed source; contract from official docs (code.claude.com, fetched 2026-09-27). |
| OpenCode v2 | 2 | `opencode serve` HTTP API (`/api/session…`) + SSE `/api/event` | Rewrite shipped as `v2.0.x`; API not backward-compatible with v1. |
| OpenCode v1 | 3 | ACP via `opencode acp` (generic ACP adapter) | v1 (`1.18.x`) still released in parallel; no dedicated v1 HTTP adapter. |
| Muse Code (Meta) | 4 | `muse exec --json`, `--session-id` (per public docs) | **Unverified:** no source read, `muse serve` protocol and license/ToS undocumented. Blocked until verified. |

## 2. Evidence base

A read-only source audit on 2026-09-27 covered six projects: OpenHands Agent Canvas + software-agent-sdk, Vibe Kanban, Claude Squad, Crystal, Sculptor, and Dagger container-use. It also mapped the harness control surfaces of Claude Code, OpenCode v1/v2 and ACP.

**Findings that shape this design:**

1. **Every project resumes through the harness's own session id and relaunch; none survives a control-plane crash with the run intact.**
   - Vibe Kanban marks orphans `Failed` while the processes keep running, and persists no PID.
   - Crystal marks sessions `stopped`.
   - Canvas marks runs `ERROR`.
   - Canvas also silently starts a fresh ACP session when `session/load` fails.
2. **No project isolates the harness process itself.**
   - Sculptor runs on the host with every permission auto-approved.
   - container-use confines the harness only by prompt rules.
   - Canvas's local mode has no sandbox, and its Docker mode has no egress restriction.
3. **No project bridges permissions durably.**
   - Canvas's ACP path auto-selects "allow once".
   - Crystal defaults to skip-permissions and silently falls back to it.
   - Vibe Kanban holds approvals in memory, so they are lost on restart.
4. **No project scopes credentials per harness.** Canvas passes all of `os.environ` plus every stored secret to every harness. The others inherit the user's environment.
5. **No project has an artifact store.** Outputs are live worktree reads, local JSON/SQLite, or git notes, and they vanish with `/tmp` worktrees.
6. **Structured protocols work; screen-scraping does not.** Crystal and Vibe Kanban use stream-json/SSE/ACP reliably. Claude Squad's tmux capture-pane hashing and keystroke auto-yes break on UI text changes.
7. **Harness surfaces drift.** Canvas and Vibe Kanban both pin exact harness versions, and Canvas runs live conformance probes against real binaries.

Central's differentiation follows directly from these findings:

- Postgres-fenced attempts with explicit ambiguity;
- sandboxed harness processes;
- durable, audited permission bridging;
- zero harness-credential handling: Central never touches harness credentials, unlike Canvas, which pushes every stored secret into every harness;
- first-class artifacts.

## 3. Terminology

- **Harness:** an external agent program that owns its loop (Claude Code, OpenCode, …).
- **Harness kind:** an adapter identifier plus a pinned harness version range, e.g. `claude-code@2.1.x`.
- **Harness session id:** the harness-owned conversation identifier (Claude Code `session_id` from `system/init`; OpenCode session id; ACP `sessionId`). Opaque to Central; it is the resume key.
- **Harness session attempt ("attempt"):** Central-owned. One launch or resume of one harness process tree, for one Run, in one workspace. It is the unit of external effect under ADR 0035 §2.
- **Adapter:** Central code that translates between the port and one harness's control surface. Adapters must not make loop decisions.

## 4. Package placement

- `internal/harness`: domain. Attempt aggregate, state machine, normalized event types, capability model, and port interfaces. It must not import adapters, pgx, S3, or `os/exec`.
- `internal/adapter/harness/{claudecode,opencode,acp}`: adapters. Process launch goes through the sandbox launcher; there is no direct `exec` from the serve process.
- `internal/adapter/postgres/harness`: the attempt repository.
- The archguard rules gain `internal/harness` as a domain package with the same purity rules as `internal/task`.

Concrete Go names below are a sketch. The implementation plan owns the final types.

## 5. Port

```go
// Capabilities is declared explicitly by every adapter; the zero value of a
// field means unsupported, and Capabilities.Validate() checks consistency at
// registration.
type Capabilities struct {
    StreamingInput      bool // follow-up input into a live process
    Interrupt           bool // soft cancel that ends the turn cleanly
    ResumeByID          bool // relaunch against a prior harness session id
    Fork                bool
    PermissionBridge    bool // harness asks, Central answers
    PartialDeltas       bool
    UsageTokens         bool
    CostUSD             bool
    UsageScope          UsageScope // Step | Run | SessionCumulative
    Reattach            bool // control plane can reconnect to a live process after restart
    AutoResumeOnRestart bool // harness may restart an interrupted turn by itself
}

type HarnessAdapter interface {
    Kind() Kind
    Capabilities() Capabilities
    // Probe reports the installed harness version and auth readiness without
    // starting a session. Used for pinning checks and availability display.
    Probe(ctx context.Context, env LaunchEnv) (ProbeResult, error)
    Start(ctx context.Context, spec StartSpec) (Session, error)
    Resume(ctx context.Context, ref SessionRef, spec StartSpec) (Session, error)
    // Reconcile inspects a possibly-live or dead attempt after a control-plane
    // restart and reports what is knowable. It never relaunches.
    Reconcile(ctx context.Context, rec AttemptRecord) (ReconcileResult, error)
}

type Session interface {
    Ref() <-chan SessionRef // resolves once the harness reveals its session id
    Events() <-chan Event   // closed after Terminal
    Send(ctx context.Context, in OperatorInput) error // ErrUnsupported if !StreamingInput
    Interrupt(ctx context.Context) error
    RespondPermission(ctx context.Context, id PermissionRequestID, d PermissionDecision) error
    Wait(ctx context.Context) (Terminal, error)
    Kill(ctx context.Context) error // kills the whole sandbox scope
}

type StartSpec struct {
    Attempt    AttemptID
    Fence      FenceToken
    Workspace  WorkspaceMount // worktree path inside the sandbox
    Prompt     string         // operator-authored; passed verbatim
    Model      string         // optional launch parameter, passed verbatim
    Permission PermissionPolicy
    Limits     LaunchLimits   // harness-native limits, only if the adapter declares them
    Env        LaunchEnv      // built by Central from an allowlist; see §9
}
```

**Rules:**

- `Prompt` and `Model` are passed through unchanged. Adapters must not append system prompts, commit reminders, secret lists or worktree guidance. Canvas, Crystal and Vibe Kanban all do this; Central does not.
- `Send` carries only operator-authored input.
- `RespondPermission` carries only a decision made by an operator or by an operator-configured policy.
- An adapter that cannot provide a core method fails at registration. The core methods are `Start`, `Events`, `Interrupt` or `Kill`, `Wait`, and a `SessionRef`.

## 6. Normalized events

Every event carries `Attempt`, `Seq` (adapter-assigned, monotonic per attempt), `At`, `HarnessSessionID` (once known), and `Raw` (the untouched source frame).

| Event | Key fields |
| --- | --- |
| `SessionStarted` | harness session id, harness version, model, tools, harness-reported capabilities |
| `Message` / `TextDelta` | role, text |
| `Reasoning` | text |
| `ToolCall` | tool call id, parent id (subagent linkage), name, input |
| `ToolResult` | tool call id, status (ok, error, denied, cut_off), output |
| `PermissionRequested` / `PermissionResolved` | request id, tool, resources, options / decision, decider |
| `Plan` | entries (persisted, not dropped) |
| `Usage` | tokens in/out/cache, cost USD, `Scope`, `Estimated` |
| `Retry`, `Warning` | harness-reported, informational |
| `Terminal` | status (`succeeded`, `failed`, `interrupted`, `max_turns`, `budget`, `killed`), reason, exit code |

**Storage:**

- The raw stream is the ground truth. It is written as chunked NDJSON Artifact bodies in object storage.
- Normalized events are derivable from raw and are stored in PostgreSQL as bounded metadata rows (type, ids, status, timestamps, sizes) for the read model. Payload text stays in object storage, per the hard rule "no payloads in the DB".
- Usage must be normalized by `Scope` before any budget arithmetic. Claude Code reports session-cumulative estimates; OpenCode reports per step.

## 7. Attempt lifecycle

```text
prepared ──launch──▶ launching ──ref known──▶ running ◀──▶ awaiting_permission
    │                    │                        │
    │                    └──────────┬─────────────┘
    │                               ▼
    │     terminal: succeeded | failed | interrupted | killed | budget_exhausted
    │                               ▲
    └────────────────────▶ ambiguous (control plane lost the process)
                                    │ operator resolution only
                                    ▼
                   resumed-by-new-attempt | rerun (new Run) | abandoned
```

**Durable record per attempt:**

- attempt id, run id, harness kind, adapter version, probed harness version;
- harness session id (nullable until `SessionStarted`);
- workspace ref, base commit SHA;
- sandbox scope id;
- lease and fencing generation;
- state, terminal status, reason, exit code;
- last event seq, usage snapshot;
- timestamps.

**Invariants:**

- **Prepare, invoke outside transaction, persist outcome** (ADR 0004 as amended). `prepared` is committed before the process starts.
- **The harness session id is persisted as soon as it is revealed.** A failure between launch and id capture leaves `launching`, which reconciles to `ambiguous`.
- **At most one live attempt per Run.** This is enforced by the existing execution lease and fencing generation; every write carries the fence.
- **`ambiguous` never transitions automatically.** Side effects may already have happened (file edits, shell, `git push`), and Central cannot roll them back.
- **A failed `Resume` is a visible terminal failure of the new attempt.** It is never a silent fresh session (the Canvas defect).
- **A Run completes only after required Artifacts (§10) and the terminal state are durable.**

## 8. Supervision and reconciliation

- **Scope.** Each attempt's harness process tree runs in its own sandbox-launcher scope (namespaces + cgroup) under the operator's UID. The worktree and the harness's own config directory (§9) are bind-mounted, and an egress policy is applied. The scope id is persisted.
- **Kill ladder.** `Interrupt` (harness-native: stdin control / `POST …/interrupt` / ACP `session/cancel`) → wait up to the drain timeout → SIGTERM to the scope → wait → cgroup kill.
- **Central restart:**
  1. Recovery claims each non-terminal attempt under a new fence.
  2. It calls `Reconcile`.
     - If the scope is dead, the attempt becomes `ambiguous`, unless the last persisted event was `Terminal`.
     - If the scope is alive and the adapter has `Reattach`, Central reattaches. OpenCode serve reattaches by re-subscribing to SSE and then reconciling through REST (`/api/session/active`, messages), because SSE has no replay.
     - If the scope is alive without `Reattach` (Claude Code CLI: the stdout pipe is lost), Central kills the scope and marks the attempt `ambiguous`.
- **OpenCode v2 auto-resume.** A restarted OpenCode server may auto-resume an interrupted turn: at-least-once, up to 10 times, per the v2 source. Central launches one server per attempt inside the attempt scope and kills it with the attempt, so auto-resume can only occur during a Central-initiated `Resume`. Any `execution.started` not caused by a Central `Start`/`Resume`/`Send` is recorded as a `Warning` and surfaced to the operator.

## 9. Credentials: harness-owned, never touched by Central

**Rule.** Central does not store, inject, copy, read, move, refresh or proxy any harness credential. Each harness authenticates exactly as the operator already configured it on the host: subscription login, API key in the harness's own settings, or anything else. Central is indifferent to which. The operator must log in to each harness before using it through Central.

**Consequences for adapters:**

- **Run as the operator.**
  - The harness process runs under the operator's UID with the operator's `HOME`, so it finds its own login (Claude Code `~/.claude/`, OpenCode's default data dir and DB).
  - The sandbox scope bind-mounts that harness config directory read-write. It is the harness's own state, not Central's.
- **Never relocate harness config.**
  - Adapters must not set `CLAUDE_CONFIG_DIR`, `OPENCODE_CONFIG_DIR`, `OPENCODE_DB`, or equivalents. Relocating them hides the operator's login and would force Central to handle credentials.
  - Harness transcripts therefore live in the harness's default location, not under a Central-owned path.
- **Never inject provider credential variables.**
  - Adapters must not set `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `META_API_KEY`, or similar. For Claude Code, an injected API key would also override the operator's subscription login through its auth precedence.
  - The launch env is built from a per-harness allowlist of non-secret variables (`PATH`, locale, terminal settings). `HOME` and `XDG_*` are never taken from the launch request; the launcher derives them from the operator's passwd entry. The exact policy is in the [phase 1a design](2026-09-27-harness-phase-1a-domain-design.md) §6.
  - Provider credential variables present in the serve process environment are not passed through.
- **No `--bare` for Claude Code.** `--bare` skips OAuth login, so it would break subscription users.
  - Claude Code docs (2026-09-27) state that `--bare` "will become the default for `-p`". The adapter must pin a version and the conformance suite must detect that change.
- **Not logged in → fail fast with a clear message.**
  - `Probe` and `Start` detect "not authenticated" from the harness's own output or exit status, never by reading credential files.
  - The attempt fails with `harness_not_authenticated`, and the UI tells the operator which login command to run, for example `claude` then `/login`.
- **Backup and artifacts exclude credentials.** Transcript snapshots (§10) copy only session transcript files. They explicitly exclude harness credential files (`~/.claude/.credentials.json`, OpenCode's credential store) and never copy whole config directories.
- **The authority broker is not used for harness auth.** It keeps serving Central's own infrastructure credentials (PostgreSQL, MinIO).

**Operating boundary.** Central runs harnesses only as the operator, on the operator's own host, for the operator's own work. This matches the case Anthropic's published terms permit: an end user signing in to the unmodified Claude Code binary with their own subscription (code.claude.com legal-and-compliance, fetched 2026-09-27). Running harnesses for other people on one operator's login is out of scope for Central.

**Residual risk (ADR 0035 cost).** The harness holds whatever credential the operator configured, with the operator's full privileges over it. Central cannot scope, rotate or revoke it. The sandbox's egress policy limits where a compromised harness can send data, but not what the credential can do.

## 10. Workspace and artifacts

- **Workspace.** One git worktree per Run under a Central-owned path, not `/tmp`. The base SHA is recorded at `prepared`.
- **Captured at attempt terminal**, through the ADR 0005 lifecycle, with workspace/task/run/producer ids, checksum and lineage:
  - raw event stream (NDJSON);
  - diff against the base SHA (patch);
  - commit list with before/after HEAD;
  - final assistant message as the report;
  - an opaque snapshot of the harness transcript (Claude Code session JSONL, OpenCode session export), excluding every credential file (§9). This is stored for backup and audit only and never parsed for control, because the formats are internal.
- **Commits.** Central does not auto-commit inside the harness session. That would be loop intervention, as Vibe Kanban's Stop-hook does. Capture reads the worktree state after the process ends.

## 11. Permission bridging

| Policy | Behavior |
| --- | --- |
| `Deny` (default) | The harness runs with its own non-interactive deny behavior; denials are recorded. |
| `Bridge` | `PermissionRequested` creates a durable Approval (ADR 0001 entity) with a timeout; the operator answers in the web UI; the timeout answers deny. |
| `AutoAllow` | Explicit per-Task operator choice, recorded on the Task and shown in the UI. |

**Rules:**

- No silent fallback. If the bridge channel is unavailable, the attempt fails closed.
- Adapters use the harness's own seam:
  - Claude Code: the stream-json control protocol's permission request, or `--permission-prompt-tool` with an adapter-owned MCP shim. The choice is verified against the pinned version at implementation.
  - OpenCode v2: `permission.asked` → `POST /api/session/:id/permission/:rid/reply`.
  - ACP: `session/request_permission`.
- Approvals survive Central restarts. After a restart, a pending approval whose attempt became `ambiguous` is closed as `superseded`.

## 12. Version pinning and conformance

- A catalog pins each harness kind to an exact version and install source. `Probe` refuses unpinned versions unless the operator overrides it explicitly.
- Adapters declare the version range they were verified against. Harness-reported capabilities (e.g. Claude Code `system/init.capabilities`) are recorded and checked against adapter `Capabilities`.
- Live conformance tests run against real pinned binaries with fake or limited credentials. They are gated behind a build tag and an env var, and skip by default like the existing live suites.

## 13. Budgets

- Session-level ceilings: wall clock, attempt count, and reported cost/tokens (scope-normalized).
- Harness-native limits (e.g. max turns) are passed only when the adapter declares them.
- On a breach, Central performs `Interrupt` → kill ladder → terminal `budget_exhausted`.
- Central never counts or caps model turns itself.

## 14. Delivery phases

Each phase is gated by ADR 0035 acceptance.

1. **Port and domain:** `internal/harness` domain + state machine + a fake adapter + the attempt migration + archguard rule.
2. **Claude Code adapter:** operator's pre-existing login (§9), `Deny`/`Bridge` policies, sandbox scope.
3. **Serve wiring:** a submitted Task runs an attempt end to end, with artifacts captured and restart reconciliation. This closes the "serve executes nothing" gap.
4. **OpenCode v2 adapter:** serve + SSE, with `Reattach`.
5. **Generic ACP adapter:** covers OpenCode v1 via `opencode acp` and other ACP harnesses.
6. **Muse Code:** only after its protocol, session storage, license and ToS are verified.

## 15. Open questions for the maintainer

1. **Resolved 2026-09-27 (maintainer):** Central never handles harness credentials; the operator logs in beforehand (§9).
2. Is OpenCode v1 support via ACP sufficient, or is a dedicated v1 HTTP adapter required?
3. The default permission policy for new Tasks: `Deny` or `Bridge`?
4. How long to retain raw event streams and transcript snapshots.
5. Can several concurrent OpenCode v2 servers (one per attempt) share the operator's default OpenCode DB safely? This is unverified. If they cannot, use one long-lived OpenCode server per operator, supervised by Central, instead of one server per attempt (§8).
