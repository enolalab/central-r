# Phase R0 — Central-Rust Documentation & Architecture Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the complete, authoritative Phase R0 documentation and design-contract baseline inside `$CENTRAL_RUST_SRC` per the approved spec (`docs/internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md`), porting all language-agnostic contracts (`§2.1`), authoring the Rust-specific Gate 7 replacement contracts and root guidelines (`§2.2`), rewriting broken cross-links (`§2.3`), and passing all Phase R0 acceptance checks (`§7`).

**Architecture:** Two-tier "Canonical Mirror + Rust Gate 7 Replacement" structure:
1. Copy verbatim all language-independent product, API/Event v1, Artifact, Runtime, Persistence, Security, Operations, Slice Dossiers (Phase 1 & Phase 2), ADRs `0001`–`0042`, and authoritative Phase 0/1/2 design specs from `$CENTRAL_SRC`.
2. Author the Rust-specific architectural and engineering contracts (`AGENTS.md`, `CLAUDE.md`, `ADR 0043`, `docs/architecture/rust-application-boundaries.md`, `docs/persistence/postgresql-adapter-mapping.md`, `docs/implementation/rust-engineering-workflow.md`, `docs/implementation/current-phase.md`, `docs/implementation/rust-vertical-slice-roadmap.md`) and adapt top-level orientation files (`docs/README.md`, `docs/newcomer-guide.md`, `docs/architecture/overview.md`, `docs/architecture/durable-execution.md`, `docs/adr/README.md`).

**Tech Stack:** Markdown (GitHub-Flavored Markdown), Bash verification scripts, Git.

## Global Constraints

- **Source Repository:** `$CENTRAL_SRC` (read-only; never modify files in `$CENTRAL_SRC`).
- **Target Repository:** `$CENTRAL_RUST_SRC`.
- **Immutable Historical Ledger:** ADRs `0001` through `0042` and copied historical specs under `docs/internal/superpowers/specs/` are historical provenance records and must not have their substantive decisions altered.
- **No Go Gate 7 Artifacts in Target:** `docs/architecture/go-application-boundaries.md` and `docs/implementation/go-engineering-workflow.md` must never exist in `central-rust`; all active documentation must link to `rust-application-boundaries.md` and `rust-engineering-workflow.md`.
- **Every Task Ends With Verification and Commit:** Each task below ends with a deterministic shell check and a dedicated git commit in `$CENTRAL_RUST_SRC`.

---

## File Structure

- **Copied Verbatim (`§2.1`, Task 1):**
  - `docs/product/{vision,roadmap,phases,use-cases,web-ui-feature-spec,agent-orchestration-view-design}.md`
  - `docs/api/v1.md`, `docs/events/v1.md`
  - `docs/artifacts/{lifecycle,content-policy}.md`
  - `docs/runtime/{agent-runtime,checkpoints,tool-invocation}.md`
  - `docs/persistence/{postgresql,migrations-and-recovery}.md`
  - `docs/security/{threat-model,capability-policy,secret-reference,local-configuration-and-protected-state,gitleaks-triage,vuln-scan-2026-10}.md`
  - `docs/architecture/{local-development-environment,online-mode}.md`
  - `docs/operations/*.md` (all 16 files in `central/docs/operations/`)
  - `docs/compatibility.md`, `docs/known-limitations.md`
  - `docs/implementation/{phase-1-entry-reconciliation,phase-1-vertical-slice-backlog,spec-and-plan-guide}.md`
  - `docs/implementation/phase-1-slices/*.md` (5 files)
  - `docs/implementation/phase-2-slices/*.md` (7 files including `README.md`)
  - `docs/adr/template.md`, `docs/adr/0001-*.md` .. `docs/adr/0042-*.md` (42 ADRs)
  - `docs/internal/superpowers/specs/*.md` (Phase 0 foundational specs, Phase 1 Harness/Adapter specs, Phase 2 Workflow Orchestration specs per `§2.1`)
- **Authored / Adapted for Rust (`§2.2`, Tasks 2–6):**
  - Create: `docs/adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md` (Task 2)
  - Create/Adapt: `docs/adr/README.md` (Task 2)
  - Create: `docs/architecture/rust-application-boundaries.md` (Task 3)
  - Create: `docs/persistence/postgresql-adapter-mapping.md` (Task 4)
  - Create: `docs/implementation/rust-engineering-workflow.md` (Task 4)
  - Create: `AGENTS.md`, `CLAUDE.md` (Task 5)
  - Create/Adapt: `docs/README.md`, `docs/newcomer-guide.md`, `docs/architecture/overview.md`, `docs/architecture/durable-execution.md`, `docs/implementation/current-phase.md`, `docs/implementation/rust-vertical-slice-roadmap.md` (Task 5)
- **Verification & Acceptance (`§7`, Task 6):**
  - Run link-integrity, inventory completeness, and Gate 7 parity checks across `central-rust`.

---

### Task 1: Copy Verbatim Language-Agnostic Contracts, ADRs 0001–0042, and Authoritative Specs

**Files:**
- Copy from `$CENTRAL_SRC/docs/` to `$CENTRAL_RUST_SRC/docs/` all files specified in Spec `§2.1`.

- [x] **Step 1: Create directory structure in `$CENTRAL_RUST_SRC/docs/`**
  Create directories: `product`, `api`, `events`, `artifacts`, `runtime`, `persistence`, `security`, `architecture`, `operations`, `implementation/phase-1-slices`, `implementation/phase-2-slices`, `adr`, `internal/superpowers/specs`, `internal/superpowers/plans`, `internal/superpowers/reviews`, `internal/tasks`.

- [x] **Step 2: Copy Product, API, Events, Artifacts, Runtime, Persistence, Security, Operations, and Implementation Dossiers**
  Copy all files listed in Spec `§2.1` from `$CENTRAL_SRC/docs/` into `$CENTRAL_RUST_SRC/docs/`, explicitly excluding `docs/architecture/go-application-boundaries.md`, `docs/implementation/go-engineering-workflow.md`, and `docs/prototypes/`.

- [x] **Step 3: Copy ADRs `0001`–`0042` and `template.md`**
  Copy `$CENTRAL_SRC/docs/adr/00*.md` and `template.md` into `$CENTRAL_RUST_SRC/docs/adr/`.

- [x] **Step 4: Copy Authoritative Phase 0, Phase 1 (Harness & Adapters), and Phase 2 Specs**
  Copy the selected specs from `$CENTRAL_SRC/docs/internal/superpowers/specs/` into `$CENTRAL_RUST_SRC/docs/internal/superpowers/specs/` (preserving `2026-10-21-central-rust-documentation-and-architecture-design.md`).

- [x] **Step 5: Verify copied file counts and exclusions**
   verify that `go-application-boundaries.md` and `go-engineering-workflow.md` do not exist in `central-rust/docs/`, and all 42 historical ADRs (`0001`–`0042`) are present.

- [x] **Step 6: Commit Task 1**
  Commit with message `docs(r0): import language-agnostic contracts, ADRs 0001-0042, and reference specs`.

---

### Task 2: Author `ADR 0043` and Update `docs/adr/README.md`

**Files:**
- Create: `$CENTRAL_RUST_SRC/docs/adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md`
- Create: `$CENTRAL_RUST_SRC/docs/adr/README.md`

- [x] **Step 1: Author `docs/adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md`**
  Follow `docs/adr/template.md` and ADR governance rules:
  - **Number:** 0043
  - **Status:** Accepted
  - **Context:** Porting `central` (Go) to `central-rust` (Rust) while preserving 100% of durable execution, security/authority, artifact, harness (ADR 0035 / ADR 0036), and Phase 2 multi-agent workflow orchestration contracts.
  - **Decision:**
    1. Adopt a multi-crate Cargo Workspace enforcing Gate 7's four-layer capability boundaries (`domain`, `port`, `query`, `app`) at compile time.
    2. Pin the Rust dependency baseline (`tokio`, `trait-variant`, `axum`, `askama`, `sqlx` v0.8 with `runtime-tokio` + `tls-rustls-ring`, `aws-sdk-s3`, `rustix`, `uuid` v7, `time`, `serde`, `ed25519-dalek`, `tracing`, `prometheus-client`).
    3. Extract embedded SQL migrations (`baseline.go`, `b08`..`b37`) into canonical `.sql` files while preserving Central's native `central.schema_migrations` checksum ledger, single-session advisory locking, version-zero `VerifiedEmptyTarget` proof, and `reapply_incremental_runtime_grants`.
    4. Execute the `R0`–`R6` delivery sequence prioritizing the active Harness Control Plane (`R3`) and Phase 2 Multi-Agent Workflow Orchestration (`R4`) rather than re-implementing the frozen B09 agent loop coordinator.
  - **Amends:** ADR 0008 (for the `central-rust` repository, replacing Go module/package boundaries with the Rust Cargo Workspace contract).

- [x] **Step 2: Copy and update `docs/adr/README.md`**
  Copy `$CENTRAL_SRC/docs/adr/README.md` and add `ADR 0043` to the index table as `Accepted`, noting that in `central-rust` it adapts Gate 7 application boundaries to Rust while retaining all upstream ADR `0001`–`0042` domain, security, persistence, and topology decisions.

- [x] **Step 3: Verify ADR links and Commit Task 2**
  Verify `0043` is linked in `docs/adr/README.md` and commit with message `docs(adr): add ADR 0043 for Rust workspace and harness-first porting strategy`.

---

### Task 3: Author `docs/architecture/rust-application-boundaries.md` (Gate 7 for Rust)

**Files:**
- Create: `$CENTRAL_RUST_SRC/docs/architecture/rust-application-boundaries.md`

- [x] **Step 1: Author `docs/architecture/rust-application-boundaries.md`**
  Using `$CENTRAL_SRC/docs/architecture/go-application-boundaries.md` and Spec `§3` as the structural reference, write the comprehensive canonical contract covering:
  1. **Workspace & Dependency Baseline (`§1`):** Rust toolchain, workspace structure, pinned crate selection (`tokio`, `trait-variant`, `axum`, `askama`, `sqlx` v0.8 features, `aws-sdk-s3`, `rustix`, `uuid`, `time`, `tracing`, `prometheus-client`), license policy (MIT / Apache-2.0 / BSD-3).
  2. **Four-Layer Role Matrix (`§2`):**
     - **Controller (`central-transport-http`, `bins/*`, `central-kernel` supervised tasks):** HTTP API v1 (`axum`), SSR HTML (`askama`), Health/Metrics, CLI migration/backup/restore/workflow/harness commands, and supervised runtime components.
     - **Service (`crates/capabilities/central-*/src/app.rs`):** All Phase 1 and Phase 2 capabilities (`workspace`, `task`, `execution`, `authorization`, `session`, `checkpoint`, `event`, `artifact`, `harness`, `workflow`, `eventjournal`, `scheduler`, `retry`, `runview`, `runsubmit`, `backup`, `infra`), coordination rules (no open DB tx across external I/O), and acyclic crate dependency DAG.
     - **Usecase (`domain.rs`, `port.rs`, `query.rs`):** Pure synchronous domain root (`no async`, no I/O), `#[trait_variant::make(Send)]` async ports (`Send + Sync + 'static`), operation-oriented `ChangeSet` commit vs atomic conditional ports, and `query.rs` rules (mandatory `SeekCursor` pagination, no offset, no N+1, safe projections).
     - **Infrastructure Adapters (`crates/adapters/central-adapter-{postgres,s3,harness,linux}`):** Adapter isolation rules and prohibited upward imports.
  3. **Binary vs Execution-Mode Topology (`§3`):** Map `bins/central` (including `serve`, `helper`, `central-protected-broker`, `central-sandbox-launcher` modes) and standalone root/operator daemons (`central-harness-launcherd`, `central-migration-launcherd`, `central-migrate`, `central-backup-launcherd`, `central-backup`, `central-restore`, `central-advisory-sign`).
  4. **HTTP, SSR HTML, Security Header & Resource Contract (`§4`):** Carry over Gate 7's exact resource limits (32 active non-streaming requests, 64 waiters, 5s wait timeout, 2 MiB max buffer, 64 MiB aggregate buffered memory), mandatory headers (`CSP: frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` per SB-G4, `Cache-Control: no-store`), PRG pattern, CSRF + `Origin` checks, restart-barrier enforcement, and WCAG keyboard accessibility baseline.

- [x] **Step 2: Verify completeness and Commit Task 3**
  Commit with message `docs(arch): add rust-application-boundaries canonical contract`.

---

### Task 4: Author `docs/persistence/postgresql-adapter-mapping.md` and `docs/implementation/rust-engineering-workflow.md`

**Files:**
- Create: `$CENTRAL_RUST_SRC/docs/persistence/postgresql-adapter-mapping.md`
- Create: `$CENTRAL_RUST_SRC/docs/implementation/rust-engineering-workflow.md`

- [x] **Step 1: Adapt `docs/persistence/postgresql-adapter-mapping.md` for Rust & `sqlx`**
  Start from `$CENTRAL_SRC/docs/persistence/postgresql-adapter-mapping.md` (preserving the complete table, column, constraint, index, role-grant, and SQLSTATE matrices) and update §1–§2 for Rust (`Spec §4`):
  - Replace `pgx/v5` + `sqlc` references with `sqlx` (`v0.8+`, `postgres`, `runtime-tokio`, `tls-rustls-ring`, `macros`, `uuid`, `time`, `json`) and `.sqlx/` offline compile-time verification (`SQLX_OFFLINE=true`).
  - Document the Rust type mapping table (`central_foundation::identity::*Id` wrapping `uuid::Uuid`, `time::OffsetDateTime`, `i64` / `Version(u64)`, `[u8; 32]`, `sqlx::types::Json<T>`).
  - Document the Migration Extraction & Native Ledger contract (`SR-02`): canonical `.sql` extraction from `baseline.go` (`v0`) and `b08`..`b37` into `migrations/`, governed by `central.schema_migrations` checksum verification, single-session `pg_advisory_lock`, version-zero `VerifiedEmptyTarget` proof, and `reapply_incremental_runtime_grants` after `pg_restore` (explicitly prohibiting `_sqlx_migrations`).
  - Update links from `go-application-boundaries.md` to `rust-application-boundaries.md`.

- [x] **Step 2: Author `docs/implementation/rust-engineering-workflow.md`**
  Define the canonical Rust engineering workflow (`Spec §5`):
  - **Toolchain & Workspace Manifest:** `rust-toolchain.toml` (pinned stable Rust, `rustfmt`, `clippy`), workspace `Cargo.toml` dependency pinning rules (no floating git branches, no unapproved `patch` directives).
  - **Workspace Lints:** `unsafe_code = "forbid"` in all capability, transport, postgres, s3, and harness crates (isolated audited syscall boundary in `central-adapter-linux` and launcher daemons only); `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"`, `clippy::panic = "deny"`, `clippy::todo = "deny"`, `clippy::dbg_macro = "deny"` in production targets.
  - **Compile-Time SQL Verification (`sqlx`):** How `migrations/` provisions the local verification schema (`v0..b37`), running `cargo sqlx prepare --workspace -- --all-targets`, committing `.sqlx/`, and gating CI with `cargo sqlx prepare --check --workspace -- --all-targets`.
  - **Supply-Chain, License & Vulnerability Gate (`cargo-deny`):** `deny.toml` configuration enforcing MIT / Apache-2.0 / BSD-3 allowlist, banning wildcards/git sources, and scanning RustSec advisories (`cargo deny check`).
  - **Test Taxonomy & Fail-Fast CI Pipeline:** Pure synchronous domain unit tests, deterministic PostgreSQL/MinIO integration suites, reference-host Linux security/launcher suites, and Playwright SSR browser acceptance suites.

- [x] **Step 3: Commit Task 4**
  Commit with message `docs(gate7): add postgresql-adapter-mapping for sqlx and rust-engineering-workflow`.

---

### Task 5: Author Root Guidelines (`AGENTS.md`, `CLAUDE.md`), Roadmaps (`current-phase.md`, `rust-vertical-slice-roadmap.md`), and Adapt Core Orientation Docs

**Files:**
- Create: `$CENTRAL_RUST_SRC/AGENTS.md`
- Create: `$CENTRAL_RUST_SRC/CLAUDE.md`
- Create: `$CENTRAL_RUST_SRC/docs/implementation/rust-vertical-slice-roadmap.md`
- Create: `$CENTRAL_RUST_SRC/docs/implementation/current-phase.md`
- Adapt: `$CENTRAL_RUST_SRC/docs/README.md`, `docs/newcomer-guide.md`, `docs/architecture/overview.md`, `docs/architecture/durable-execution.md`

- [x] **Step 1: Author `AGENTS.md` and `CLAUDE.md`**
  Adapt `$CENTRAL_SRC/AGENTS.md` and `CLAUDE.md` for `central-rust`:
  - Update technology constraints: Main language **Rust** (Cargo Workspace), Database **PostgreSQL 16** (`sqlx` compile-time checked), Artifact storage **S3-compatible / MinIO** (`aws-sdk-s3`), Web UI **Server-rendered HTML (`axum` + `askama`)**, Linux security boundaries (`rustix`).
  - Point required reading to `docs/product/vision.md`, `docs/product/roadmap.md`, `docs/architecture/overview.md`, `docs/architecture/durable-execution.md`, `docs/architecture/rust-application-boundaries.md`, `docs/implementation/rust-engineering-workflow.md`, and `docs/implementation/current-phase.md`.
  - Preserve all architectural, database/artifact, security, and ADR 0028 D3 delegation rules verbatim.

- [x] **Step 2: Author `docs/implementation/rust-vertical-slice-roadmap.md` and `docs/implementation/current-phase.md`**
  - In `rust-vertical-slice-roadmap.md`, detail the complete `R0` through `R6` vertical-slice plan (`Spec §6`), mapping each R-Slice to its owning capability crates, SQL migrations (`v0..b37`), upstream reference specs/dossiers, and acceptance criteria.
  - In `current-phase.md`, record **Phase R0 — Documentation & Contract Baseline** as Complete upon R0 acceptance and **Phase R1 — Workspace Scaffold, Canonical SQL Extraction (`v0..b37`) & Durable Task/Execution Core** as the next active implementation slice, while summarizing the upstream Phase 0–2 reference baseline.

- [x] **Step 3: Copy and adapt `docs/README.md`, `docs/newcomer-guide.md`, `docs/architecture/overview.md`, and `docs/architecture/durable-execution.md`**
  - Copy from `$CENTRAL_SRC/docs/` and update references from `go-application-boundaries.md` $\rightarrow$ `rust-application-boundaries.md`, `go-engineering-workflow.md` $\rightarrow$ `rust-engineering-workflow.md`, and Go kernel/packages $\rightarrow$ Rust Cargo Workspace crates (`central-kernel`, `crates/capabilities/*`, `crates/adapters/*`), while adding `rust-vertical-slice-roadmap.md` and `ADR 0043` to `docs/README.md`.

- [x] **Step 4: Commit Task 5**
  Commit with message `docs(r0): add AGENTS.md, CLAUDE.md, R-slice roadmap, and adapt core orientation docs`.

---

### Task 6: Link-Integrity Sweep and Phase R0 Acceptance Verification (`§7`)

**Files:**
- Inspect/Modify if needed: active docs under `$CENTRAL_RUST_SRC/docs/`, `AGENTS.md`, `CLAUDE.md`

- [x] **Step 1: Check and fix any residual references to `go-application-boundaries.md` or `go-engineering-workflow.md` in active docs**
  Run:
  ```bash
  git -C $CENTRAL_RUST_SRC grep -nE 'go-application-boundaries\.md|go-engineering-workflow\.md' -- \
    AGENTS.md CLAUDE.md docs/README.md docs/newcomer-guide.md \
    docs/architecture/ docs/persistence/ docs/implementation/current-phase.md \
    docs/implementation/rust-vertical-slice-roadmap.md
  ```
  Rewrite any remaining occurrences in active docs (including `docs/persistence/postgresql.md`, `docs/persistence/migrations-and-recovery.md`, `docs/architecture/local-development-environment.md`) to `rust-application-boundaries.md` and `rust-engineering-workflow.md`.

- [x] **Step 2: Run the Phase R0 Acceptance Criteria Verification Suite (`Spec §7`)**
  Execute verification checks confirming:
  1. **Criterion 1 (Completeness & Exclusions):** All `§2.1` and `§2.2` files exist; `go-application-boundaries.md`, `go-engineering-workflow.md`, and `docs/prototypes/` are absent.
  2. **Criterion 2 (ADR Ledger Integrity):** `docs/adr/0001-*.md` through `docs/adr/0043-*.md` exist and are indexed in `docs/adr/README.md`.
  3. **Criterion 3 (Zero Broken Active Links to Replaced Go Contracts):** Active docs contain zero references to `go-application-boundaries.md` or `go-engineering-workflow.md`, and all markdown links inside the newly authored Rust docs (`AGENTS.md`, `CLAUDE.md`, `docs/README.md`, `docs/architecture/rust-application-boundaries.md`, `docs/persistence/postgresql-adapter-mapping.md`, `docs/implementation/rust-engineering-workflow.md`, `docs/implementation/current-phase.md`, `docs/implementation/rust-vertical-slice-roadmap.md`, `docs/adr/0043-*.md`) resolve to existing files in `central-rust`.
  4. **Criterion 4 (Gate 7 Parity):** Verify all required sections exist in `rust-application-boundaries.md`, `postgresql-adapter-mapping.md`, and `rust-engineering-workflow.md`.

- [x] **Step 3: Commit any link adjustments and finalize Phase R0**
  Commit with message `docs(r0): complete link-integrity sweep and verify Phase R0 acceptance criteria`.
