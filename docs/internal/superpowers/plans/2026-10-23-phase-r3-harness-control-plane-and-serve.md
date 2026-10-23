# Phase R3 — Harness Control Plane & `central serve` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete Phase R3 vertical slice in `$CENTRAL_RUST_SRC` per [rust-vertical-slice-roadmap.md](../../../implementation/rust-vertical-slice-roadmap.md) §6: implement `central-harness` (ADR 0035 control plane: attempts, events, permission approvals, budgets, cancel/resume/rerun — upstream phases 1a–3m), `central-adapter-harness` (Claude Code, OpenCode, Codex, Antigravity adapters, `gitclone` shadow repo + per-Run clone + capture, launcher client, dev-gated `localexec`), `central-adapter-postgres::{harness,session}` over `b30`–`b32` + `v0`, `central-session` (bootstrap exchange, session lifecycle, CSRF bindings), `central-transport-http` (API v1 JSON, `askama` SSR Web UI for Tasks/Harness surfaces, health/metrics) under the exact resource-cap and security-header contract, the `central-kernel` serve composition (including the R2 `ArtifactReconcilerComponent` behind the recovery-coordinator fence), the `bins/central serve` + harness verbs, and `bins/central-harness-launcherd` (ADR 0036); wire Tier 3 launcher suites and the Tier 4 Playwright SSR suite; pass the §7 fail-fast pipeline.

**Architecture:**
- **Crate DAG ([rust-application-boundaries.md](../../../architecture/rust-application-boundaries.md) §1–§3):**
  - `central-harness` depends only on `central-foundation`, `serde`, `serde_json`, `sha2`, `time`, `trait-variant` (boundaries §2 Harness row: "Own `domain`/`port`/`query`, `central-foundation`"; the service DAG has no `central-harness → *` edge). **No `central-task`, `central-execution`, `central-artifact`, `tokio`, `uuid`, or `sqlx`.** `domain.rs` is pure sync; `port.rs` owns `Adapter`, `Session`, `ProcessLauncher`, `AttemptStore`, `ApprovalStore`, `LeaseBinder`, `RecoveryStore`; `query.rs` owns seek-paginated attempt/event/approval projections; `app/` owns `Orchestrator`, `Dispatcher`, permission `Bridge`, `Reconciler`, `Resolver`.
  - Collaboration with execution, task, and artifact goes through **harness-owned consumer-side ports** in `app/ports.rs`, mirroring upstream `internal/harness/app/ports.go`: `RunLifecycle`, `ArtifactSink`, `WorkspaceProvisioner`, `WorkspaceCapture`, `WorkspaceSealer`, `ResumeSource`, `TaskEventSink`, `ResolveStore`, `Clock`. Their value types (`DispatchableRun`, `ClaimedRun`, `Settlement`, `ArtifactOutcome`, `Capture`, `ResumeFrom`, `Milestone`) are defined in `central-harness`. `central-kernel` implements them by adapting `central-execution`, `central-task`, and `central-artifact` services.
  - Concurrency inside `central-harness::app` (heartbeat, event pump, cancel) is expressed through capability-owned traits (`Clock`, `Ticker`, `CancelSignal`) implemented in `central-kernel`, mirroring how R2 kept `tokio` out of `central-artifact`.
  - `central-adapter-harness` implements `central-harness::port` (and the `WorkspaceProvisioner`/`WorkspaceCapture` app ports) only; `tokio::process` is allowed here; `unsafe_code = "forbid"`; it never imports `rustix` or another adapter crate (boundaries §2.4 and §3: "other adapters" prohibited). Linux seal/ACL work goes through the `WorkspaceSealer` port (see Open Decision D2).
  - `central-session` depends only on `central-foundation`, `hmac`, `sha2`, `rand`, `zeroize`, `time`, `trait-variant`. Protected bootstrap token authority is a `port::ProtectedBootstrap` trait; R3 ships a file-backed dev implementation, the broker-backed one lands in R5 (see Open Decision D1).
  - `central-transport-http` maps wire → typed `app` commands / `query` value types only; never imports adapters, `sqlx`, or `query` traits. Admission is acquired before body read or PostgreSQL access.
  - `central-kernel` is the only place where concrete adapters meet services (manual composition, supervised components).
  - Phase 2 surfaces (`/app/runs*`, run controls, fleet, lineage, run submit, `scheduler_harness_wiring`) are **out of scope** — they land in R4 with `central-runview`/`central-runsubmit`.

**Tech Stack:** already pinned in `[workspace.dependencies]` — `axum =0.8.9`, `tower =0.5.3`, `tower-http =0.7.1`, `rustls =0.23.46`, `askama =0.16.1`, `hmac =0.13.0`, `rand =0.10.3`, `zeroize =1.9.1`, `prometheus-client =0.25.1`, `sqlx =0.8.6`, `tokio =1.54.1`, `tokio-util =0.7.20`, `trait-variant =0.1.3`, `rustix =1.1.5` (launcherd only), `tracing`. **No new dependency is planned.** If a task discovers it needs one (e.g. Playwright runner tooling, a TOML parser for harness config), stop and ask the maintainer before adding it (CLAUDE.md).

## Global Constraints

- **Source of truth:** `$CENTRAL_SRC` (read-only) — exact domain transitions, wire formats, SQL, fixtures, and test scenarios. No new DDL: `b30`–`b32` are already on disk (`migrations/0030_b30_harness_attempts.sql`, `0031_b31_harness_permission_approvals.sql`, `0032_b32_task_attempt_budgets.sql`).
- **Zero `unsafe`** everywhere except `bins/central-harness-launcherd` (audited `[lints]` override, `rustix` safe wrappers only).
- **No unwraps in production targets** (`unwrap_used`, `expect_used`, `panic`, `todo`, `dbg_macro` = deny).
- **Compile-time SQL only:** `sqlx::query!`/`query_as!`; regenerate `.sqlx/` in every task that adds a statement.
- **No secret/locator leakage:** adapter errors expose only closed `FailureClass`/reason tokens; harness CLI stderr, prompts, bootstrap tokens, cookies, and CSRF values never appear in `Display`, logs, or HTML.
- **Wire parity:** API v1 JSON, event v1 envelopes, launcher protocol frames, and HTML form/redirect behavior must match upstream byte-for-byte where upstream has golden fixtures.
- **Every task ends green:** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p <touched crates>` (+ `cargo test --workspace` when a `port`/`query` trait or `central-foundation` type changes), then commit.

---

## Open Decisions (resolve before the gated task starts; all other tasks proceed)

| ID | Question | Gates | Default if no ruling |
| --- | --- | --- | --- |
| D1 | Bootstrap token authority lives in the R5 protected broker. R3 ships `ProtectedBootstrap` as a port + a file-backed dev implementation behind the same dev gate as `localexec`? | Task 10 | Yes; the dev implementation lives in `central-adapter-linux::dev_bootstrap` (the crate that later hosts the broker implementation), never in `central-adapter-postgres`; broker impl replaces it in R5; record in `docs/internal/tasks/` |
| D2 | `gitclone` upstream uses Linux ACL/seal syscalls (`acl_linux.go`, `seal_linux.go`). Boundaries forbid `rustix` outside `central-adapter-linux` and forbid adapter→adapter imports. | Task 9 | `central-harness::app::ports::WorkspaceSealer` port; implementation `central-adapter-linux::workspace_seal` pulled forward into R3; `central-kernel` injects it into the gitclone provisioner. `central-adapter-harness` never imports `central-adapter-linux` (no ADR needed: no check weakened) |
| D3 | Upstream `central-harness-launcherd` is C (`cmd/central-harness-launcherd/*.c`). Port to Rust (`rustix`), keeping `PROTOCOL.md` frames identical? | Task 14 | Port to Rust; protocol bytes identical; C `test_launcher.py` scenarios become Rust Tier 3 tests |
| D4 | Tier 4 Playwright runner location and toolchain (Node not in workspace). | Task 15 | `tests/acceptance/playwright/` driven by `scripts/`; ask before adding any Node lockfile |

---

## File Structure

```text
central-rust/
├── .sqlx/                                         # + harness/session queries
├── crates/
│   ├── capabilities/
│   │   ├── central-harness/src/
│   │   │   ├── lib.rs
│   │   │   ├── domain.rs        # Fence, Workspace, Terminal, Resolution, closed reason codes
│   │   │   ├── attempt.rs       # Attempt state machine: prepare / prepare_resume / settle
│   │   │   ├── event.rs         # Event + EventPayload variants (SessionStarted … TerminalReported), Usage
│   │   │   ├── record.rs        # EventRecord persistence shape + sequence rules
│   │   │   ├── approval.rs      # PermissionApproval, OpenApprovalInput, ApprovalDecision (b31)
│   │   │   ├── budget.rs        # Budget, ChainCost, cost/wall-clock/token ceilings (b32, 3d/3j/3l)
│   │   │   ├── capability.rs    # adapter Capabilities matrix
│   │   │   ├── env.rs           # launch env allowlist + vectors
│   │   │   ├── recovery.rs      # recovery classification (3e–3h)
│   │   │   ├── port.rs          # Adapter, Session, ProcessLauncher, stores, LeaseBinder
│   │   │   ├── query.rs         # attempt/event/approval/budget projections (seek pagination)
│   │   │   └── app/{mod,ports,orchestrator,dispatcher,bridge,reconciler}.rs
│   │   └── central-session/src/
│   │       ├── lib.rs, domain.rs, contract.rs, port.rs, query.rs, app.rs
│   ├── adapters/
│   │   ├── central-adapter-harness/src/
│   │   │   ├── lib.rs
│   │   │   ├── process.rs       # shared stream/line framing, bounded stderr, kill ladder
│   │   │   ├── fake.rs          # scripted adapter + launcher for tests
│   │   │   ├── localexec.rs     # dev-gated direct launcher (issue #120)
│   │   │   ├── launcher/{mod,protocol,client}.rs   # ADR 0036 wire protocol + client
│   │   │   ├── claudecode/{mod,argv,probe,protocol,session}.rs
│   │   │   ├── opencode/{mod,argv,probe,protocol,session}.rs
│   │   │   ├── codex/{mod,argv,probe,protocol,session}.rs
│   │   │   ├── antigravity/{mod,argv,probe,protocol,session}.rs
│   │   │   └── gitclone/{mod,capture,provision}.rs   # seal via injected WorkspaceSealer
│   │   ├── central-adapter-linux/src/{lib,workspace_seal,dev_bootstrap}.rs   # D1/D2 pull-forward
│   │   └── central-adapter-postgres/src/
│   │       ├── harness/{mod,queries,store,approval,recovery}.rs
│   │       └── session/{mod,store}.rs
│   ├── transport/central-transport-http/
│   │   ├── src/{lib,router,error}.rs
│   │   ├── src/middleware/{admission,buffer,headers,origin,session,context}.rs
│   │   ├── src/health.rs, src/metrics.rs
│   │   ├── src/api/{mod,tasks,harness,approvals,session}.rs
│   │   ├── src/web/{mod,task_view,harness,permission_view,budget_view,activity_view,overview_view,office_view}.rs
│   │   ├── templates/*.html     # askama
│   │   └── assets/{bootstrap.js,app.css}
│   └── central-kernel/src/{serve,harness_compose,session_compose}.rs
├── bins/
│   ├── central/src/{main,serve,harness_cli}.rs
│   └── central-harness-launcherd/src/{main,protocol,policy,session,cgroup}.rs
└── tests/acceptance/playwright/                   # Tier 4 (D4)
```

---

## Milestone A — Harness domain & persistence

### Task 1: `central-harness` pure domain (phases 1a, 3c, 3d, 3j, 3l)

**Files:** Create `crates/capabilities/central-harness/src/{domain,attempt,event,record,approval,budget,capability,env,recovery}.rs`; modify `lib.rs`, `Cargo.toml`; possibly `crates/central-foundation/src/identity.rs` (new `HarnessAttemptId`, `ApprovalId` v7 newtypes).

**Reference (read-only):** `internal/harness/{domain,attempt,event,record,approval,budget,capability,env,recovery}.go` + their `_test.go` and `env_vectors_internal_test.go`; specs `2026-09-27-harness-phase-1a-domain-design.md`, `…-3c-permission-approvals…`, `…-3d-budgets…`, `…-3j-task-cost-cap…`, `…-3l-token-ceiling…`.

- [ ] **Step 1:** Add `HarnessAttemptId`/`PermissionApprovalId` to `central-foundation::identity` via the existing `define_v7_id!` macro; unit-test strict parsing.
- [ ] **Step 2:** Write failing tests ported 1:1 from `attempt_test.go`, `event_test.go`, `approval_test.go`, `budget_test.go`, `env_vectors_internal_test.go` into `#[cfg(test)]` modules.
- [ ] **Step 3:** Run `cargo test -p central-harness` → FAIL (types missing).
- [ ] **Step 4:** Implement the pure types/transitions: `Attempt::prepare(PrepareInput)`, `Attempt::prepare_resume(&Attempt, PrepareInput)`, settle → `Terminal`; closed `EventPayload` enum with serde tags identical to upstream JSON; `PermissionApproval` open/decide/expire; `Budget::evaluate(&ChainCost) -> BudgetVerdict`; env allowlist filtering.
- [ ] **Step 5:** `cargo test -p central-harness` → PASS; `cargo clippy -p central-harness --all-targets -- -D warnings`.
- [ ] **Step 6:** Commit `feat(harness): port pure harness domain (attempts, events, approvals, budgets)`.

### Task 2: `central-harness` ports & queries

**Files:** Create `port.rs`, `query.rs`.

**Reference:** `internal/harness/port/{port,store,launcher}.go` + tests; spec `2026-09-27-harness-adapter-boundary-design.md`.

- [ ] **Step 1:** Port `port_test.go`/`launcher_test.go` contract tests as in-memory fake tests (`memStore`, `scriptedLauncher`).
- [ ] **Step 2:** Define `#[trait_variant::make(Send)]` traits: `Adapter { probe, start, reconcile }`, `Session { events, send_operator_input, decide_permission, cancel, wait }`, `ProcessLauncher { launch, is_alive, kill }`, `AttemptStore`, `ApprovalStore`, `LeaseBinder`, `RecoveryStore` with value types `StartSpec`, `LaunchEnv`, `Limits`, `ProcessSpec`, `ExitStatus`, `ProbeResult`, `ReconcileInput/Result`, `OperatorInput`, `PermissionDecision`, `ExecutionLease`, `RecoveryCandidate`, `RecoveryCursor`.
- [ ] **Step 3:** Define `query.rs`: `AttemptSummaryRead`, `HarnessEventRead` (seek cursor on `(attempt_id, seq)`), `PendingApprovalRead`, `BudgetUsageRead` — no `OFFSET`.
- [ ] **Step 4:** `cargo test -p central-harness` → PASS; then `cargo test --workspace` (new trait surface).
- [ ] **Step 5:** Commit `feat(harness): define harness port and query contracts`.

### Task 3: `central-adapter-postgres::harness` (b30–b32)

**Files:** Create `crates/adapters/central-adapter-postgres/src/harness/{mod,queries,store,approval,recovery}.rs`; modify `lib.rs`, `Cargo.toml`; regenerate `.sqlx/`.

**Reference:** `internal/adapter/postgres/harness/{store,approval,recovery,queries}.go` + tests; spec `2026-09-27-harness-phase-1b-persistence-design.md`; `docs/persistence/postgresql-adapter-mapping.md`.

- [ ] **Step 1:** Port upstream store tests as `CENTRAL_TEST_DSN`-gated integration tests (skip cleanly when unset, same helper R2 uses).
- [ ] **Step 2:** Implement `PgHarnessStore`: attempt insert/transition with expected-version fencing, `harness_events` append with monotonic `seq`, `LeaseBinder` reusing `execution` transaction/event/outbox helpers, approval open/decide/expire with `tasks.permission_policy`, budget column reads/updates, `RecoveryStore` seek scan.
- [ ] **Step 3:** Implement `query.rs` traits on the same struct.
- [ ] **Step 4:** `cargo sqlx prepare --workspace -- --all-targets`; `cargo test -p central-adapter-postgres` with DSN set → PASS.
- [ ] **Step 5:** Verify `central_runtime` grants cover every statement (no SQLSTATE `42501`); if a grant gap exists, record it in `docs/internal/tasks/` per AGENTS.md D3 rules — do not widen grants silently.
- [ ] **Step 6:** Commit `feat(adapter-postgres): implement harness attempt, approval, and recovery stores`.

## Milestone B — Harness application layer

### Task 4: `Orchestrator` + permission `Bridge` + budgets (phases 3a–3d, 3j, 3l, 3m)

**Files:** Create `central-harness/src/app/{mod,ports,orchestrator,bridge}.rs`.

**Reference:** `internal/harness/app/{orchestrator,bridge,ports}.go`, `fakes_test.go`, `orchestrator_test.go`; specs `…-3a-serve-wiring…`, `…-3b-artifact-capture…`, `…-3m-live-usage-display…`.

- [ ] **Step 1:** Port `fakes_test.go` world (`lifecycle`, `store`, `adapter`, `session`, `capturer`, `artifacts`, `sink`) as Rust test fakes.
- [ ] **Step 2:** Port `orchestrator_test.go` scenarios (happy path, flaky lifecycle, permanent error, zero lease, blocked heartbeat, tracing sink) → FAIL.
- [ ] **Step 3:** Implement `Orchestrator::run(ClaimedRun) -> Result<HarnessResult, Failure>`: prepare durably → bind lease → provision workspace → start adapter session **outside** any transaction → pump events (append, usage, budget checks, approvals via `Bridge`) → capture (`harness.report`/`harness.patch`/`harness.commits`) through `ArtifactSink` → settle via `RunLifecycle`. Concurrency via capability traits `Clock`/`Ticker`/`CancelSignal` (no `tokio`).
- [ ] **Step 4:** `cargo test -p central-harness` → PASS.
- [ ] **Step 5:** Commit `feat(harness): port orchestrator, permission bridge, and budget enforcement`.

### Task 5: `Dispatcher`, `Reconciler`, `Resolver`, cancel/resume/rerun (phases 3e–3i, 3k)

**Files:** Create `app/{dispatcher,reconciler}.rs`; extend `app/orchestrator.rs` for resume.

**Reference:** `internal/harness/app/{dispatcher,reconciler}.go` + `dispatcher_test.go`, `reconciler_test.go`, `resume_test.go`; specs `…-3e-cancel-and-recovery…` through `…-3k-rerun-resolution…`.

- [ ] **Step 1:** Port dispatcher/reconciler/resume tests (relisting, refusing, hanging launcher, conflict-once, ambiguous attempt, eligibility guard, prepared cancel) → FAIL.
- [ ] **Step 2:** Implement `Dispatcher` (bounded concurrency, claim → orchestrate, refuse on shutdown), `Reconciler::pass(cursor) -> ReconcileSummary` (fenced, idempotent), `Resolver` (operator resolve/cancel/rerun decisions), `ResumeSource` resume path with eligibility guard.
- [ ] **Step 3:** `cargo test -p central-harness` → PASS.
- [ ] **Step 4:** Commit `feat(harness): port dispatcher, reconciler, resolver, and resume/rerun`.

## Milestone C — Harness adapters

### Task 6: Adapter runtime core — process framing, fake, `localexec`, launcher protocol + client

**Files:** Create `central-adapter-harness/src/{process,fake,localexec}.rs`, `launcher/{mod,protocol,client}.rs`; `Cargo.toml` (`central-harness`, `tokio`, `serde_json`, `tracing`).

**Reference:** `internal/adapter/harness/{fake,localexec,hostlauncher}/*.go`, `internal/harnesslauncher/{protocol,client_linux}.go`, `cmd/central-harness-launcherd/PROTOCOL.md`; specs `…-2b-harness-launcher…`, `issue-111`, `issue-120`.

- [ ] **Step 1:** Port protocol golden-frame tests from `protocol_test.go` (encode/decode, size caps, unknown-frame rejection) → FAIL.
- [ ] **Step 2:** Implement `launcher::protocol` as pure codec (shared with `central-harness-launcherd`), `launcher::client::HostLauncher: ProcessLauncher` over the Unix socket, `localexec::LocalExec` refusing construction unless the explicit dev gate is set (issue #120), `fake::{FakeAdapter, FakeLauncher}`.
- [ ] **Step 3:** `cargo test -p central-adapter-harness` → PASS.
- [ ] **Step 4:** Commit `feat(adapter-harness): add process core, launcher protocol/client, localexec dev gate, fakes`.

### Task 7: Claude Code adapter (phase 2a)

**Files:** Create `claudecode/{mod,argv,probe,protocol,session}.rs`; fixtures under `crates/adapters/central-adapter-harness/tests/fixtures/claudecode/` copied from upstream testdata.

**Reference:** `internal/adapter/harness/claudecode/*.go` + tests; spec `2026-09-27-harness-phase-2a-claude-code-adapter-design.md`.

- [ ] **Step 1:** Port argv, probe, protocol (stream-JSON → `EventPayload`) and session tests using recorded fixtures → FAIL.
- [ ] **Step 2:** Implement `ClaudeCode: Adapter` (argv builder, version probe, stream parser, permission-prompt bridge, cancel/kill ladder, resume via session ref).
- [ ] **Step 3:** `cargo test -p central-adapter-harness claudecode` → PASS.
- [ ] **Step 4:** Commit `feat(adapter-harness): port Claude Code adapter`.

### Task 8: OpenCode, Codex, Antigravity adapters (issues #126, #128, #129)

**Files:** Create `opencode/*`, `codex/*`, `antigravity/*` (same 5-file shape as Task 7) + fixtures.

**Reference:** `internal/adapter/harness/{opencode,codex,antigravity}/*.go` + tests; specs `issue-126`, `issue-128`, `issue-129`.

- [ ] **Step 1:** OpenCode: port tests → FAIL → implement → PASS → commit `feat(adapter-harness): port OpenCode adapter`.
- [ ] **Step 2:** Codex: port tests → FAIL → implement → PASS → commit `feat(adapter-harness): port Codex adapter`.
- [ ] **Step 3:** Antigravity: port tests → FAIL → implement → PASS → commit `feat(adapter-harness): port Antigravity adapter`.

### Task 9: `gitclone` — shadow repo, per-Run clone, capture (phase 3b) — **gated by D2**

**Files:** Create `crates/adapters/central-adapter-harness/src/gitclone/{mod,provision,capture}.rs`; create `crates/adapters/central-adapter-linux/src/{lib,workspace_seal}.rs` implementing `central_harness::app::ports::WorkspaceSealer` (per D2; `central-adapter-linux` gets its audited `[lints]` override here).

**Reference:** `internal/adapter/workspace/gitclone/*.go`, `internal/adapter/workspace/provision/provisioner.go`, `cmd/central/harness_artifacts.go`; spec `…-3b-artifact-capture…`.

- [ ] **Step 1:** Port gitclone tests (temp-dir `git` fixtures: provision, reopen, seal, capture report/patch/commits, path-escape rejection) → FAIL.
- [ ] **Step 2:** Implement `GitClone: WorkspaceProvisioner + WorkspaceCapture` invoking `git` via `tokio::process` with a sanitized env and taking a `WorkspaceSealer` by constructor injection (tests use an in-memory sealer; the Linux sealer is tested in `central-adapter-linux`); produce bounded `harness.report`, `harness.patch`, `harness.commits` bodies handed to `ArtifactSink` (bodies go to object storage via R2 `Service`, never PostgreSQL).
- [ ] **Step 3:** `cargo test -p central-adapter-harness gitclone` → PASS.
- [ ] **Step 4:** Commit `feat(adapter-harness): port gitclone shadow repo, per-run clone, and capture`.

## Milestone D — Session, HTTP, serve

### Task 10: `central-session` + `central-adapter-postgres::session` — **gated by D1**

**Files:** Create `central-session/src/{domain,contract,port,query,app}.rs`; `central-adapter-postgres/src/session/{mod,store}.rs`; `central-adapter-linux/src/dev_bootstrap.rs` (D1); `.sqlx/`.

**Reference:** `internal/session/{domain,contract}.go`, `port/session_port.go`, `app/service.go` + tests; `internal/adapter/postgres/session/*`; `docs/security/` session contract; boundaries §5 normal/loading rows.

- [ ] **Step 1:** Port domain/contract/service tests (verifier versions, candidate binding, pre-auth CSRF, throttle via database time, exchange → activate → deliver, reconcile, leak-proof `Failure` Display) → FAIL.
- [ ] **Step 2:** Implement the two-phase bootstrap exchange (candidate staging → PostgreSQL commit → activation → delivery), `ValidateSession`, refresh, logout, revoke; HMAC-SHA256 CSRF binding; `zeroize` secrets.
- [ ] **Step 3:** Implement `PgSessionStore` in `central-adapter-postgres::session` and `DevFileProtectedBootstrap` in `central-adapter-linux::dev_bootstrap` (construction refused unless the dev gate is set, per D1).
- [ ] **Step 4:** `cargo sqlx prepare …`; `cargo test -p central-session -p central-adapter-postgres` → PASS.
- [ ] **Step 5:** Commit `feat(session): port bootstrap exchange, session lifecycle, and CSRF bindings`.

### Task 11: `central-transport-http` middleware, health, metrics, rendering

**Files:** Create `src/{lib,router,error,health,metrics}.rs`, `src/middleware/*.rs`, base `templates/layout.html`, `assets/`.

**Reference:** `internal/transport/http/gintransport/{middleware,health,rendering,assets}/*.go` + tests; boundaries §4 resource-cap table.

- [ ] **Step 1:** Write failing tests with `tower::ServiceExt::oneshot`: 33rd active request queues, 65th waiter → `503`, 5 s admission timeout, 2 MiB body/response cap, 64 MiB aggregate, 4 KiB header cap; every response carries CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store`; mutating route rejects bad `Origin`/CSRF; restart barrier returns the upstream status; missing session → `303`.
- [ ] **Step 2:** Implement admission (acquired before body read), buffering, headers, origin, session/CSRF extractors calling `central-session::app`, `/healthz` live + profile-aware `/readyz`, loopback metrics listener with kernel-owned `prometheus-client` registry, askama renderer with `nonce`-free strict CSP (no inline script/style).
- [ ] **Step 3:** `cargo test -p central-transport-http` → PASS.
- [ ] **Step 4:** Commit `feat(transport-http): add admission, security headers, session/CSRF, health and metrics`.

### Task 12: API v1 JSON + SSR Web UI (Tasks/Harness surfaces)

**Files:** Create `src/api/*.rs`, `src/web/{task_view,harness,permission_view,permission_form,budget_view,activity_view,overview_view,office_view}.rs`, matching `templates/*.html`.

**Reference:** `internal/transport/http/gintransport/web/{handler,harness,task_view,permission_view,permission_form,budget_view,activity_view,overview_view,office_view}.go` + `handler_*_test.go` (excluding runs/fleet/lineage/run_controls/run_submit → R4); `docs/api/v1.md`, `docs/events/v1.md`, `docs/product/web-ui-feature-spec.md`.

- [ ] **Step 1:** Port handler tests for in-scope routes (overview, tasks, harness detail, permission approve/deny PRG, budget display, cancel, prepared cancel, resolve, resume, rerun, retry cap, activity, office) → FAIL.
- [ ] **Step 2:** Implement API v1 controllers (canonical error envelope) and askama views; auto-escape only (no `|safe` on untrusted values); mutations via PRG `303`.
- [ ] **Step 3:** `cargo test -p central-transport-http` → PASS.
- [ ] **Step 4:** Commit `feat(transport-http): add API v1 and SSR task/harness views`.

### Task 13: `central-kernel` serve composition + `bins/central` serve & harness verbs

**Files:** Create `crates/central-kernel/src/{serve,harness_compose,session_compose}.rs`; modify `lib.rs`, `Cargo.toml`; create `bins/central/src/{serve,harness_cli}.rs`; modify `main.rs` (replace `UNSUPPORTED_IN_THIS_SLICE` for `serve`, `harness resume|rerun|cancel` only).

**Reference:** `internal/kernel/serve.go`; `cmd/central/{serve_composition,serve_monitors,serve_artifact_composition,harness_composition,harness_config,harness_lifecycle,harness_resume,harness_rerun,harness_task_cost,harness_retry_gate,harness_backend,harness_launcher_linux}.go`; specs `…-3a-serve-wiring…`, `issue-124`.

- [ ] **Step 1:** Failing kernel tests: serve profile starts HTTP + harness dispatcher + harness reconciler + `ArtifactReconcilerComponent` (only while holding the recovery-coordinator fence) and settles within `DEFAULT_SETTLEMENT`; real launcher is the default, `localexec` only behind the dev gate (issue #120/#124).
- [ ] **Step 2:** Implement composition: concrete stores/adapters → services → transport router; kernel implements `Clock`/`Ticker`/`CancelSignal` with `tokio`, and implements the harness consumer-side ports (`RunLifecycle`, `ArtifactSink`, `ResumeSource`, `TaskEventSink`, `ResolveStore`) by adapting `central-execution`, `central-artifact`, and `central-task` services; injects `central-adapter-linux::workspace_seal` into gitclone.
- [ ] **Step 3:** Implement `central serve` and harness CLI verbs emitting `central.local-result/v1`; other R4–R6 verbs stay fail-closed `exit 5`.
- [ ] **Step 4:** `cargo test -p central-kernel -p central`; `cargo build --workspace` → PASS.
- [ ] **Step 5:** Commit `feat(kernel): compose central serve with harness, session, and artifact reconciler`.

## Milestone E — Launcher & acceptance

### Task 14: `bins/central-harness-launcherd` (ADR 0036) — **gated by D3**

**Files:** Create `bins/central-harness-launcherd/src/{main,protocol,policy,session,cgroup}.rs`; `Cargo.toml` with audited `[lints]` override; `packaging/systemd/central-harness-launcherd.{socket,service}` if upstream ships them.

**Reference:** `cmd/central-harness-launcherd/{main,protocol,policy,session,cgroup}.c`, `PROTOCOL.md`, `test_launcher.py`; ADRs 0036, 0013; spec `issue-111`.

- [ ] **Step 1:** Port `test_launcher.py` scenarios as Rust tests: frame decode reuse from `central-adapter-harness::launcher::protocol`, peer-cred authorization (ADR 0013 runtime UID), policy denial matrix, cgroup kill on client disconnect (issue #111). Root-only tests skip as non-root / off reference host.
- [ ] **Step 2:** Implement socket-activated daemon (`LISTEN_FDS`), `SO_PEERCRED` check, policy, per-session cgroup, kill ladder — `rustix` safe wrappers only.
- [ ] **Step 3:** `cargo test -p central-harness-launcherd` → PASS (root tests skipped locally); run Tier 3 on the reference host.
- [ ] **Step 4:** Commit `feat(harness-launcherd): port ADR 0036 socket-activated harness launcher`.

### Task 15: Tier 4 Playwright SSR suite, docs, R3 closeout — **gated by D4**

**Files:** Create `tests/acceptance/playwright/*` + `scripts/r3-acceptance.sh`; modify `docs/implementation/current-phase.md`, `docs/implementation/rust-engineering-workflow.md` §8.4, `docs/operations/harness-execution.md` if behavior differs.

- [ ] **Step 1:** Playwright flows: bootstrap exchange → session delivery → task list → harness attempt detail → permission approve/deny → artifact download → accessibility smoke.
- [ ] **Step 2:** Run the §7 pipeline:
  `cargo sqlx prepare --check --workspace -- --all-targets && cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo deny check && cargo test --workspace`
  with `CENTRAL_TEST_DSN` and `CENTRAL_TEST_MINIO_ENDPOINT` set.
- [ ] **Step 3:** Mark R3 Complete, R4 Active in `current-phase.md`; summarize delivered crates.
- [ ] **Step 4:** Commit `docs(phase-r3): mark Phase R3 complete and advance active slice to Phase R4`.

---

## Self-review notes

- **Roadmap §6 coverage:** four adapters (T7–T8), gitclone + capture (T9), approvals `v31` (T1/T3/T4), budgets `v32` (T1/T3/T4), cancel/resume/rerun 3a–3m (T4–T5), session + CSRF (T10), resource caps + headers + PRG/CSRF/Origin/restart barrier (T11–T12), launcherd + `localexec` dev gate (T6/T14), Tier 3 + Tier 4 (T14–T15), kernel serve with R2 reconciler behind fence (T13).
- **Cross-slice risks:** D1 (broker, R5), D2 (`central-adapter-linux`, R5), D3 (C → Rust rewrite). Each is isolated to one task; every other task proceeds without them.
- **Explicitly deferred to R4:** `/app/runs*`, run controls, fleet, lineage views, run submit, `scheduler_harness_wiring`.
