# Harness Phase 1a: Domain, Port, Fake Adapter — Design

Date: 2026-09-27
Status: Reviewed — [spec review](../reviews/2026-09-27-harness-phase-1a-spec-review.md) findings applied
Governing decision: [ADR 0035](../../../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md) (Accepted)
Governing spec: [Harness Adapter Boundary Design](2026-09-27-harness-adapter-boundary-design.md), phase 1

## 1. Goal

Deliver the pure, schema-free foundation of the harness boundary:

- the `internal/harness` domain: attempt aggregate, state machine, normalized events, capabilities, launch-environment policy;
- the `internal/harness/port` adapter contract;
- a scripted fake adapter;
- a new identity type;
- archguard enforcement.

Nothing in this phase touches PostgreSQL, the sandbox launcher, `central serve`, or a real harness.

**Success criteria:**

- `go build ./...`, `go vet ./...` and gofmt are clean.
- The tests of every touched package pass: `internal/harness/...`, `internal/adapter/harness/...`, `internal/identity/...`, `internal/archguard/...`.
- The full-repository archguard analysis reports no violations.
- A test drives the fake adapter through the port and applies every resulting transition to the domain aggregate, reaching `succeeded`, `failed`, `interrupted` and `killed`.
- The same test then exercises `MarkAmbiguous → Resolve(resume) → PrepareResume` through direct domain mutator calls. Ambiguity is a caller decision (governing spec §8), not something the port or fake emits.

## 2. Decisions made during brainstorming

Each question was answered with its recommended option, per the maintainer's workflow instruction.

| # | Question | Decision | Reason |
| --- | --- | --- | --- |
| 1 | Deliver all of governing-spec phase 1 in one cycle, or split it? | **Split.** 1a = this document; 1b = v30 migration + PostgreSQL repository, in its own spec→plan→PR cycle. | The migration chain is intricate: each version classifies its predecessor chain, verifies catalog shape and grants, and is registered in runner, inspector and reset paths. Isolating it keeps both reviews small. |
| 2 | Reuse `internal/execution` attempt states, or give harness its own? | **Own vocabulary in `internal/harness`.** | archguard `domain-purity` forbids a domain root from importing another domain. The semantics also differ: session attempts, not provider/tool attempts. |
| 3 | Model ambiguity resolutions as three states, or as one state plus a field? | **One terminal `resolved` state plus a `Resolution` field** (`resume`, `rerun`, `abandon`). | This keeps the transition table small. The resolution is data, not lifecycle. |
| 4 | Mutation style? | **Value-receiver methods that return a new `Attempt` and an error**, as in `internal/task` `SubmitTask`/`ClaimCurrentRun`. | This matches the existing domain idiom and keeps the domain pure and easy to test. |
| 5 | Where is the fence enforced? | **In the domain, as well as in the repository.** Every mutator takes the caller's `Fence` and rejects one that differs from the loaded attempt. `Attempt.Fence.Generation` mirrors the Run's execution-lease fencing generation. Recovery calls `Refence` with the newly claimed lease generation. | The domain check catches reload-then-mutate with an old lease fence. It **cannot** detect a stale in-memory copy, which carries its own matching fence. Phase 1b must therefore write every change as a compare-and-swap on the stored generation (`WHERE fence_generation = $callerFence`), and persist `Refence` under `WHERE fence_generation = current`. |
| 6 | The governing spec says a missing capability field is a compile error. Go cannot enforce that. | **Keep an explicit struct.** The zero value means "unsupported". `Capabilities.Validate()` checks consistency, and the governing spec's wording is corrected in this cycle. | This states the rule honestly and enforces what Go can enforce. |
| 7 | Enforce the "no harness credentials" rule in code? | **Yes, allowlist-first** (§6). Only a fixed non-secret base set, plus adapter-declared extras, may appear in `Vars`. Extras must also pass an expanded denylist. `HOME`, `XDG_*`, proxy and CA variables are never accepted. `port.StartSpec.Validate` calls it. | A name-only denylist can be bypassed by relocation (`HOME`, `XDG_*`) and by redirection (`*_BASE_URL`, custom headers, proxies, `NODE_OPTIONS`). An allowlist turns ADR 0035 §3 into a failing check. |
| 8 | Event payload representation? | **A sealed interface** (`EventPayload` with an unexported marker method) inside an `Event` envelope. | Adapters cannot invent payload types, and a type switch is exhaustive by convention. |
| 9 | Cost representation? | **`int64` micro-USD.** | No float rounding in budget arithmetic. |
| 10 | Fake adapter location? | **`internal/adapter/harness/fake`**, a real package with no build tag. | Later phases (app service, serve wiring) need it in their tests. |
| 11 | Archguard scope? | **Add `internal/harness` to the domain roots, plus a new `harness-boundary` rule appended at index 9.** The rule has two parts. First, `internal/harness/**` may not import effect packages, including the process-start packages `os/exec`, `syscall` and `golang.org/x/sys/`. Second, `internal/adapter/harness/**` may not import the authority, secret-bootstrap or full-config packages. | This follows the `execution-boundary`/`artifact-boundary` pattern. The second part enforces governing spec §9: the broker is not used for harness auth, so harness adapters never reach broker-held secrets. |
| 12 | Is `PrepareResume` general, or only for resolving ambiguity? | **General.** Any terminal attempt with a `HarnessSessionID` can be resumed. This includes `succeeded` (an operator follow-up), `failed`, `interrupted`, `killed` and `budget_exhausted`. A `resolved` attempt can be resumed only if `Resolution.Kind == resume`. | ADR 0035 §3 names resume as one answer to ambiguity; it does not restrict resume to that case. Follow-up prompts on a finished harness session are a core control-plane flow in every audited competitor. The operator-facing policy (when the UI offers Resume) belongs to phase 3. |

**Approaches considered for the package shape:**

- **(A, chosen)** A standalone `internal/harness` domain with its own port package.
- **(B)** Extend `internal/execution`'s attempt model with a harness kind. Rejected: execution's attempts are per provider or tool effect, which is exactly the granularity ADR 0035 removes, and the 4.5k-line domain would grow a second meaning.
- **(C)** Reuse `internal/agent`. Rejected: that package is frozen by ADR 0035.

## 3. Package layout

| Path | Contents |
| --- | --- |
| `internal/identity/identity.go` | `HarnessAttemptID` (UUIDv7, same pattern as `StepAttemptID`) |
| `internal/harness/domain.go` | Package doc; `Kind`, `State`, transitions, `Attempt`, `Fence`, `Workspace`, `Terminal`, `Resolution`, errors, mutators, `Validate` |
| `internal/harness/capability.go` | `Capabilities`, `UsageScope`, `Validate` |
| `internal/harness/event.go` | `Event`, `EventPayload` and payload types, `Usage`, `Validate` |
| `internal/harness/env.go` | `ValidateLaunchEnv` and its deny rules |
| `internal/harness/port/port.go` | `Adapter`, `Session`, `StartSpec`, `LaunchEnv`, `SessionRef`, `ProbeResult`, `ReconcileInput`, `ReconcileResult`, `OperatorInput`, `PermissionDecision`, `ErrUnsupported` |
| `internal/adapter/harness/fake/fake.go` | Scripted `Adapter` and `Session` |
| `internal/archguard/rules.go` | Domain root entry and the `harness-boundary` rule |

Imports:

- `internal/harness` imports only the standard library and `internal/identity`.
- `internal/harness/port` imports `internal/harness`, `internal/identity` and the standard library.
- The fake adapter imports both of them and the standard library.

## 4. Attempt aggregate and state machine

**States:**

- Non-terminal: `prepared`, `launching`, `running`, `awaiting_permission`, `ambiguous`.
- Terminal: `succeeded`, `failed`, `interrupted`, `killed`, `budget_exhausted`, `resolved`.

| From | To |
| --- | --- |
| `prepared` | `launching`, `failed`, `ambiguous` |
| `launching` | `running`, `failed`, `interrupted`, `killed`, `ambiguous` |
| `running` | `awaiting_permission`, `succeeded`, `failed`, `interrupted`, `killed`, `budget_exhausted`, `ambiguous` |
| `awaiting_permission` | `running`, `failed`, `interrupted`, `killed`, `budget_exhausted`, `ambiguous` |
| `ambiguous` | `resolved` |

Terminal states have no outgoing transitions. `succeeded` is reachable only from `running`, because a successful attempt must have revealed its harness session id.

**`Attempt` fields:**

- `ID`, `RunID`, `Kind`, `AdapterVersion` (fixed at `Prepare`), `HarnessVersion` (set at `Launch`);
- `HarnessSessionID` (opaque; set on reveal);
- `ResumeOf` (optional prior attempt id) and `ResumeSessionID` (the harness session id being resumed);
- `Workspace{Path, BaseSHA}`, `Permission` (`deny`, `bridge`, `auto_allow`), `SandboxScopeID` (set at launch);
- `Fence{Generation int64}`, `State`, `PendingPermission` (request id while awaiting);
- `Terminal{Status, Reason, ExitCode *int}` (set on terminate);
- `Resolution{Kind, DecidedBy}` (set on resolve), `AmbiguityReason`;
- `LastEventSeq uint64`, `Usage` (latest snapshot);
- `PreparedAt`, `UpdatedAt`, `EndedAt`.

**Constructors and mutators.** All are pure. Each mutator takes `(fence Fence, …, at time.Time)` and returns `(Attempt, error)`.

- `Prepare(PrepareInput) (Attempt, error)` creates a fresh attempt in `prepared`.
- `PrepareResume(prev Attempt, PrepareInput) (Attempt, error)` implements decision 12. It requires all of:
  - `prev` is terminal;
  - `prev.HarnessSessionID` is non-empty;
  - `prev.State != resolved`, or `prev.Resolution.Kind == resume`.

  It sets `ResumeOf` and `ResumeSessionID`. The `RunID`, `Kind` and `Workspace` must match `prev`.
- `Launch(fence, scopeID, harnessVersion, at)`: `prepared → launching`.
- `RevealSession(fence, sessionID, at)`: `launching → running`.
  - It is idempotent when the attempt is already `running` with the same id.
  - A different id returns `ErrSessionMismatch`.
- `AwaitPermission(fence, requestID, at)`: `running → awaiting_permission`.
- `ResolvePermission(fence, requestID, at)`: `awaiting_permission → running`. The request id must match `PendingPermission`.
- `RecordProgress(fence, seq, usage, at)`: allowed in `launching`, `running` and `awaiting_permission`. `seq` must be greater than `LastEventSeq`. An equal `seq` is an idempotent no-op. A lower `seq` returns `ErrInvalidEvent`: adapters assign `Seq` monotonically per attempt, so a lower value is an adapter bug.
- `Terminate(fence, Terminal, at)` maps the terminal status to a state and sets `EndedAt`:

  | Terminal status | State |
  | --- | --- |
  | `succeeded` | `succeeded` |
  | `failed` | `failed` |
  | `max_turns` | `failed`, with reason `max_turns` |
  | `interrupted` | `interrupted` |
  | `killed` | `killed` |
  | `budget` | `budget_exhausted` |

- `MarkAmbiguous(fence, reason, at)`: any non-terminal state except `ambiguous` → `ambiguous`.
- `Resolve(fence, Resolution, at)`: `ambiguous → resolved`. `DecidedBy` is required.
- `Refence(current Fence, next Fence, at)`: non-terminal only; `next.Generation` must exceed the current generation.

**`Validate()` invariants:**

- The ids, `RunID`, `Kind` and `Workspace.Path`/`BaseSHA` are non-zero. `Permission` is known. `Fence.Generation` is at least 1.
- `running`, `awaiting_permission` and `succeeded` require a `HarnessSessionID`.
- `awaiting_permission` requires a `PendingPermission`; every other state requires it to be empty.
- Terminal states require an `EndedAt`; non-terminal states require it to be zero.
- `resolved` requires a `Resolution`, and an `AmbiguityReason` carried over from `ambiguous`.
- `ResumeOf` and `ResumeSessionID` are either both set or both empty.

**Errors** (sentinels, wrapped with `fmt.Errorf("%w: …")`, style of `internal/task/contract.go`):

- `ErrInvalidTransition`
- `ErrFenceMismatch`
- `ErrInvalidAttempt`
- `ErrSessionMismatch`
- `ErrPermissionMismatch`
- `ErrResumeNotAllowed`
- `ErrForbiddenLaunchEnv`
- `ErrInvalidEvent`
- `ErrInvalidCapabilities`

## 5. Capabilities

`Capabilities` has these fields: `StreamingInput`, `Interrupt`, `ResumeByID`, `Fork`, `PermissionBridge`, `PartialDeltas`, `UsageTokens`, `CostUSD`, `UsageScope`, `Reattach`, and `AutoResumeOnRestart`. The zero value of each field means unsupported.

`Validate()` checks consistency:

- `UsageScope` must be set exactly when `UsageTokens` or `CostUSD` is true.
- `UsageScope` must be one of `step`, `run`, or `session_cumulative`.

## 6. Launch-environment policy

The signature is `ValidateLaunchEnv(vars map[string]string, extras []string) error`. `extras` is the adapter-declared list of additional allowed names. Names are compared case-sensitively, as on Linux, except where lower-case variants are listed explicitly.

A variable is accepted only if it passes three gates, in this order.

**0. Name syntax.** The name must match `[A-Za-z_][A-Za-z0-9_]*`. A name containing `=` could smuggle an assignment such as `HOME=/x`. Invalid names are rejected. They are counted in the error but never printed, because they may embed a value.

**1. Allowlist gate.** The name is in the base set, or in `extras`.

- Base set: `PATH`, `LANG`, `LANGUAGE`, `TERM`, `COLORTERM`, `NO_COLOR`, `TZ`, `TMPDIR`, `USER`, `LOGNAME`, `SHELL`, `CENTRAL_ATTEMPT_SCOPE` (amended 2026-10-08 by issue #111: the Phase-2 attempt-scope carrier, IDs only, non-secret), plus every name with the prefix `LC_`.

**2. Denylist gate.** This applies to every name, including base names and extras. The name must match none of the following.

- **Identity/config relocation (exact):**
  - `HOME`, `CLAUDE_CONFIG_DIR`;
  - `OPENCODE_CONFIG_DIR`, `OPENCODE_CONFIG`, `OPENCODE_CONFIG_CONTENT`, `OPENCODE_DB`.
- **Redirection and interception (exact):**
  - `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` and their lower-case forms;
  - `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`;
  - `GOOGLE_APPLICATION_CREDENTIALS`.
- **Prefixes:**
  - `XDG_`, `NODE_`;
  - `ANTHROPIC_`, `CLAUDE_CODE_`, `OPENAI_`, `OPENCODE_`;
  - `AWS_`, `GOOGLE_`, `GEMINI_`, `META_`, `AZURE_`.
- **Suffixes:**
  - `_TOKEN`, `_API_KEY`, `_KEY`, `_SECRET`;
  - `_SECRET_ACCESS_KEY`, `_ACCESS_KEY_ID`;
  - `_PASSWORD`, `_CREDENTIALS`, `_BASE_URL`, `_CUSTOM_HEADERS`.

**Consequences:**

- `HOME` and `XDG_*` never come from `Vars`. The phase-2 launcher derives them from the operator's passwd entry, so the harness always sees the operator's own home and login (governing spec §9).
- Proxy and CA variables are never accepted. Egress control belongs to the sandbox's network policy, not to harness env.
- An adapter needing a variable that the denylist blocks (for example a non-secret `CLAUDE_CODE_*` toggle) requires a spec change. The denylist is deliberately not overridable by `extras`.
- `extras` itself is validated. An extra that matches the denylist is rejected. The check does not silently drop it.

The error is `ErrForbiddenLaunchEnv`. It lists offending valid **names only**, sorted for determinism, plus a count of invalid names. It never includes values.

## 7. Normalized events

`Event` has these fields: `Attempt`, `Seq` (≥ 1), `At`, `HarnessSessionID` (may be empty before `SessionStarted`), `Raw []byte` (non-empty), and `Payload EventPayload`.

`Raw`, `Message.Text`, `Reasoning.Text`, `ToolCall.Input`, `ToolResult.Output`, `PermissionRequested.Resources`/`Options`, `Warning.Message`, `Retry.Reason` and `Plan.Entries` are **sensitive**: a harness may echo credentials into them. No validation error and no `String()`/`GoString()` output may include their content, or the content of `StartSpec.Prompt`.

| Payload | Fields |
| --- | --- |
| `SessionStarted` | `HarnessSessionID` (required), `HarnessVersion`, `Model`, `Tools []string`, `ReportedCapabilities []string` |
| `Message` | `Role` (`assistant`, `user`, `system`), `Text`, `Partial bool` (true for streaming deltas) |
| `Reasoning` | `Text` |
| `ToolCall` | `ID` (required), `ParentID`, `Name` (required), `Input []byte` |
| `ToolResult` | `ID` (required), `Status` (`ok`, `error`, `denied`, `cut_off`), `Output []byte` |
| `PermissionRequested` | `RequestID` (required), `Tool`, `Resources []string`, `Options []string` |
| `PermissionResolved` | `RequestID` (required), `Decision` (`allow`, `deny`, `timeout`), `DecidedBy` |
| `Plan` | `Entries []string` |
| `UsageReport` | `Usage{TokensIn, TokensOut, CacheRead, CacheWrite int64; CostMicroUSD int64; Scope UsageScope; Estimated bool}` |
| `Retry` | `Reason` |
| `Warning` | `Message` |
| `TerminalReported` | `Terminal` |

`Event.Validate()` requires:

- a non-zero attempt;
- `Seq ≥ 1`;
- a non-empty `Raw` and a non-nil payload;
- valid payload fields;
- for `SessionStarted`, the envelope `HarnessSessionID` must equal the payload's.

## 8. Port

```go
type Adapter interface {
    Kind() harness.Kind
    Capabilities() harness.Capabilities
    Probe(ctx context.Context, env LaunchEnv) (ProbeResult, error)
    Start(ctx context.Context, spec StartSpec) (Session, error)
    Resume(ctx context.Context, ref SessionRef, spec StartSpec) (Session, error)
    Reconcile(ctx context.Context, in ReconcileInput) (ReconcileResult, error)
}

type Session interface {
    Ref() <-chan SessionRef
    Events() <-chan harness.Event
    Send(ctx context.Context, in OperatorInput) error
    Interrupt(ctx context.Context) error
    RespondPermission(ctx context.Context, d PermissionDecision) error
    Wait(ctx context.Context) (harness.Terminal, error)
    Kill(ctx context.Context) error
}
```

**Port types:**

- **`StartSpec`:** `Attempt`, `Fence`, `Workspace`, `Prompt`, `Model`, `Permission`, `Limits{MaxTurns int}`, `Env LaunchEnv`.
- **`LaunchEnv`:** `Vars map[string]string`, `SandboxScopeID string`.
- **`SessionRef`:** `HarnessSessionID string`.
- **`ProbeResult`:** `HarnessVersion`, `Authenticated bool`, `Detail string`.
- **`ReconcileInput`:** `Attempt`, `SandboxScopeID`, `HarnessSessionID`, `LastEventSeq`.
- **`ReconcileResult`:** `ScopeAlive bool`, `Reattached Session` (nil unless reattached), `Terminal *harness.Terminal`.
- **`OperatorInput`:** `Text string`.
- **`PermissionDecision`:** `RequestID`, `Allow bool`, `OptionID`, `DecidedBy`.

**Rules:**

- `StartSpec.Validate()` requires:
  - a non-zero attempt, a fence with generation ≥ 1, a workspace path, and a known permission policy;
  - a non-empty `Prompt` (a resume always carries its operator prompt);
  - `harness.ValidateLaunchEnv(Env.Vars, adapterExtras)` to pass, where `adapterExtras` is supplied by the adapter. The fake declares none.
- `ErrUnsupported` is returned by `Send`, `RespondPermission`, `Resume` or `Reconcile`-reattach when the adapter does not declare the matching capability.
- `LaunchEnv` and `OperatorInput` are printable only in redacted form. `LaunchEnv.String`/`GoString` print the sorted variable names and the scope, never values. `OperatorInput.String`/`GoString` never print `Text`.
- The port's doc comment carries the ADR 0035 non-intervention rule: `Prompt` and `Model` are passed verbatim, and `Send`/`RespondPermission` carry only operator-originated input.

## 9. Fake adapter

`fake.Adapter` is built with `fake.New(kind, caps, scripts ...Script)`. Each `Start` or `Resume` consumes the next `Script`:

- `SessionID`
- `Payloads []harness.EventPayload`: emitted with `Seq` 1..n and a synthetic `Raw` (the JSON of the payload)
- `Terminal harness.Terminal`
- `StartErr error`
- `WaitForPermission bool`: pause after a `PermissionRequested` until `RespondPermission` is called

**Behavior:**

- `Start`/`Resume` validate the `StartSpec` and record it in `Adapter.Calls()`.
- `Ref()` delivers the session id when the `SessionStarted` payload is emitted.
- `Interrupt` stops the script and ends with `interrupted`; `Kill` ends with `killed`.
- `Send` returns `ErrUnsupported` unless `caps.StreamingInput`; otherwise it records the input.
- `Probe` returns a configured `ProbeResult`.
- `Reconcile` returns a configured `ReconcileResult`.

The fake is deterministic: no goroutine leaks, and every channel is closed after the terminal event. It is not concurrency-hardened beyond what a single-consumer test needs.

## 10. Archguard

- Add `internal/harness` to `isDomainRoot` for consistency. Enforcement comes from rule (a) below, because `domain-purity` does not see the module-qualified imports that the analyzer passes. That pre-existing gap is tracked as a follow-up and is not fixed here.
- Append the `harness-boundary` rule at index 9. It has two parts.
  - **(a)** It applies to `internal/harness` and `internal/harness/*`.
    - It allows only these internal imports: `internal/identity`, `internal/failure`, `internal/harness` and `internal/harness/*`. This check applies after module-qualified normalization. The allowlist is needed because the existing `domain-purity` rule only sees repository-relative imports.
    - It blocks `os` by exact match: `Getenv`, `LookupEnv` and `StartProcess` live there.
    - It also blocks these import prefixes:
    - `internal/adapter/`, `internal/transport/`;
    - `net/http`, `os/exec`, `syscall`, `golang.org/x/sys/`;
    - `github.com/jackc/pgx`, `github.com/minio/`, `github.com/aws/aws-sdk`;
    - `github.com/openai/`, `github.com/anthropics/`.
  - **(b)** It applies to `internal/adapter/harness/**`, and blocks `internal/authority`, `internal/authority/`, `internal/adapter/authority/`, `internal/secretbootstrap`, `internal/config` and `internal/config/`.

  Module-qualified imports are normalized, as the existing rules do.
- Tests follow the existing `TestExecutionBoundaryRejectsConcreteEffectImports` pattern: they assert the rule index and name, cover rejected and allowed imports, and check that the composition root (`cmd/central`) is not constrained.

## 11. Error handling

- Domain and port validation return wrapped sentinels. Callers use `errors.Is`. Error text never includes sensitive content (§7) or env values (§6).
- Mutators never partially apply: on error they return the zero `Attempt` and leave the receiver unchanged (value semantics).
- The fake returns `ErrUnsupported` rather than panicking. Script exhaustion is a test error: `Start` returns an error saying so.

## 12. Testing

- **Domain:**
  - a full transition matrix over `State × State`;
  - a positive and a negative case for every mutator;
  - fence mismatch and `Refence` monotonicity;
  - `RecordProgress` idempotence and ordering;
  - `PrepareResume` preconditions;
  - `Validate` invariants on hand-built invalid attempts;
  - the `Terminate` mapping table.
- **Capabilities and env:**
  - the capability consistency rules;
  - every allowlist base name accepted, and `LC_ALL` accepted through the prefix;
  - an unknown name rejected;
  - an extra accepted only when declared;
  - an extra that matches the denylist rejected;
  - every denylist category rejected, including `HOME`, `XDG_CONFIG_HOME`, `ANTHROPIC_BASE_URL`, `https_proxy`, `NODE_OPTIONS`, `AWS_SESSION_TOKEN` and `GITHUB_TOKEN`;
  - offending names sorted;
  - no value appearing in the error text.
- **Events:** each payload's required fields, the envelope checks, and the `SessionStarted` id agreement.
- **Port:** `StartSpec.Validate`, including the env policy.
- **Fake adapter:**
  - scripted runs reach `succeeded`, `failed`, `interrupted` and `killed`;
  - the permission pause and resume;
  - `Send` both unsupported and supported;
  - recorded calls.
  - An end-to-end in-memory test applies each emitted event to an `Attempt` through the domain mutators. It then calls `MarkAmbiguous → Resolve(resume) → PrepareResume` directly on the domain (§1).
- **Archguard (additions):** rule (b) rejects each authority, secret-bootstrap and config import from `internal/adapter/harness/fake`. Rule (a) rejects `syscall` and `golang.org/x/sys/unix`.
- **Identity:** `HarnessAttemptID` round-trip in the existing table test.
- **Archguard:** the rule-index test and the full-repository `Analyze` staying clean.

## 13. Out of scope (later cycles)

- **1b:** the v30 migration, the attempt and event-metadata tables, and the PostgreSQL repository with compare-and-swap fence and version checks (decision 5).
- **Phase 2 open item:** raw event streams and transcript snapshots may contain credentials that a harness echoed. Backup and restore replicate them, which counts as a "copy" under ADR 0035 §3. Decide their retention and access scope together with artifact capture.
- **Phase 2 onward:** real adapters, the app service, the sandbox launcher integration, serve wiring, artifact capture, the approval bridge, the conformance suite.
- Any change to frozen B09 code.

## 14. Governing-spec correction

The governing spec (§5) says a missing capability field is a compile error in the adapter's constructor. Go cannot enforce that. It is replaced by: "declared explicitly; zero value means unsupported; consistency validated by `Capabilities.Validate()` at registration."
