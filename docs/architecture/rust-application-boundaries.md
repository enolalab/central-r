# Rust Application Boundaries — Canonical Contract

- **Status:** Adopted
- **Replaces:** Gate 7 application boundaries for the Rust codebase. The upstream Go contract (`central/docs/architecture/go-application-boundaries.md`) is historical provenance only and is intentionally absent from this repository.
- **Governing design:** [Central-Rust Documentation Baseline & Architecture Design](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md), §3
- **ADR:** [ADR 0043 — Adopt Rust workspace and harness-first porting strategy](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md) (amends ADR 0008 for this repository)
- **Historical ADR basis:** [ADR 0008 — Adopt capability-owned Go application boundaries](../adr/0008-adopt-capability-owned-go-application-boundaries.md) and its upstream amendments (ADR 0009, 0010, 0011, 0014, 0036), retained as the immutable decision ledger this contract translates into Rust terms
- **Implementation target:** R1–R6 per [rust-vertical-slice-roadmap.md](../implementation/rust-vertical-slice-roadmap.md)

## 1. Workspace and dependency baseline

```text
Workspace root:  central-rust/Cargo.toml    (shared [workspace.dependencies] and [workspace.lints])
Toolchain:       rust-toolchain.toml        (pinned stable Rust; rustfmt + clippy components)
Supply chain:    deny.toml                  (cargo-deny license, advisory, and source policy)
```

`central-rust` is a single Cargo Workspace. Every application boundary is enforced by the crate dependency graph at compile time, not by review convention. There is no public SDK crate and no published crate surface; workspace members are `central-foundation`, the capability crates, the adapter crates, `central-transport-http`, `central-kernel`, and the binary targets under `bins/`.

| Concern | Crate selection | Boundary | License |
| --- | --- | --- | --- |
| Async runtime | `tokio` (v1, `rt-multi-thread`, `macros`, `net`, `process`, `signal`, `sync`, `time`, `fs`) + `tokio-util` | `central-kernel`, adapters, transport, binaries only (prohibited in domain root) | MIT |
| Async trait bounds | `trait-variant` (v0.1) | Capability `port` and `query` traits to enforce `: Send` futures across `tokio` multi-threaded executors | MIT / Apache-2.0 |
| HTTP transport | `axum` (v0.8) + `tower` + `tower-http` + `rustls` | `central-transport-http` only | MIT / Apache-2.0 |
| Server-rendered HTML | `askama` (compile-time typed templates with auto-escaping) | `central-transport-http` (`web` module) only | MIT / Apache-2.0 |
| PostgreSQL | `sqlx` (v0.8, features: `postgres`, `runtime-tokio`, `tls-rustls-ring`, `macros`, `uuid`, `time`, `json`; `migrate` feature disabled in favor of Central's native migration ledger) | `central-adapter-postgres` only | MIT / Apache-2.0 |
| Object storage (S3/MinIO) | `aws-sdk-s3` + `aws-config` + `sha2` | `central-adapter-s3` only | Apache-2.0 |
| Linux syscalls & IPC | `rustix` (`fs`, `net`, `process`, `shm`/`mm` for `memfd_create`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`) | `central-adapter-linux` and the launcher and protected-execution-mode binaries only | Apache-2.0 / MIT |
| Identity (UUIDv7) | `uuid` (v1, `v7`, `serde`) | Wrapped privately inside `central-foundation::identity` | Apache-2.0 / MIT |
| Time | `time` (v0.3, `serde`, `formatting`, `parsing`, `macros`) | `central-foundation` and across workspace | MIT / Apache-2.0 |
| Serialization | `serde` + `serde_json` | Wire envelopes, event payloads, config schemas, adapters | MIT / Apache-2.0 |
| Cryptography | `ed25519-dalek`, `hmac`, `sha2`, `rand`, `zeroize` | Broker, advisory verification, CSRF/session/approval binding | BSD-3 / MIT / Apache-2.0 |
| Observability | `tracing` + `tracing-subscriber` (JSON) + `prometheus-client` | Kernel, observability rendering, operational HTTP endpoints | MIT / Apache-2.0 |

Production dependencies use tagged registry versions pinned in shared `[workspace.dependencies]`. No floating branches, no unapproved `[patch]` directives, no path dependencies outside the workspace. Licenses are restricted to MIT / Apache-2.0 / BSD-3 and enforced by `cargo deny check` per [rust-engineering-workflow.md](../implementation/rust-engineering-workflow.md).

**Boundary enforcement notes:**

- `sqlx`'s `migrate` feature is disabled workspace-wide. Central's native `central.schema_migrations` checksum ledger — not `_sqlx_migrations` — governs schema state; see §8.5 and [postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md).
- `uuid::Uuid` never escapes `central-foundation::identity`; every capability sees only opaque newtype IDs.
- `tokio`/`tokio-util` are absent from every capability crate's `[dependencies]`. Rust future-drop replaces `context.Context` cancellation inside capability boundaries: `app.rs`, `port.rs`, and `query.rs` signatures carry no context parameter; callers cancel by dropping the returned future. Explicit deadlines (`time::OffsetDateTime`), authority, and operation identity remain ordinary parameters. `tokio_util::sync::CancellationToken` lives only in `central-kernel`, adapters, transport, and binaries.
- `unsafe_code` is `forbid` in every capability, transport, `central-adapter-postgres`, `central-adapter-s3`, and `central-adapter-harness` crate. Only `central-adapter-linux` and the launcher and protected-execution-mode binaries may encapsulate audited OS syscall boundaries through `rustix` safe wrappers.

## 2. Four-layer role matrix

Central adopts per-capability Clean Architecture roles. There are no global horizontal `controller`, `service`, `usecase`, or `infrastructure` trees. Each capability owns its four roles as the module set `domain.rs` / `port.rs` / `query.rs` / `app.rs` inside its own crate, and the Cargo dependency DAG — not convention — makes boundary violations compile errors.

### 2.1 Controller (transport / CLI / supervised components)

| Role | Owning target | Accepts | Allowed imports | Prohibited imports | External-effect boundary | Failure mapping |
| --- | --- | --- | --- | --- | --- | --- |
| HTTP API handler | `crates/transport/central-transport-http` (API v1 module) | `axum` extractors, typed application command/query request types, `query` projection value types | `central-foundation` (`identity`, `failure`), service-layer `app` command/result types, `query` request/projection types | `query` traits, command-persistence ports, concrete adapters, `sqlx`, S3 SDKs, harness/tool SDKs, `axum`/`tower` outside own crate | Transport maps wire input to typed commands; provisions admission slot before body read | Canonical HTTP status codes per API v1 error envelope |
| HTML server-rendered UI | `central-transport-http` (`web` module) | `axum` extractors, typed application command/query request types, `query` projection value types (mapped to view models) | Same as API plus `askama` | Same as API; no unescaped Askama markup (`\|safe`, `Safe`, `MarkupDisplay::Unsafe`) on untrusted values, no inline script/style | Transport maps projections to view models; HTML uses PRG for mutations | Canonical HTML rendering with safe anti-framing headers; `303` redirect for missing session |
| Health endpoints | `central-transport-http` (`health` module) | `axum` extractors | `central-foundation` | Application commands, queries, ports, adapters | Dependency-independent live check; generic profile-aware ready report | Fixed operational responses; no dependency details |
| Metrics endpoint | `central-transport-http` operational listener | `axum` extractors | Kernel-owned `prometheus-client` registry | Application packages | Dedicated loopback operational listener or authenticated session required | Fixed operational response |
| CLI migration ops | `bins/central` (`migrate *`) and `bins/central-migrate` | Typed operator args, operation identity | `central-backup` migration coordinator, `port` inspector traits | Application services not required for the operation; no serve-pool dependencies | No HTTP intake; read-only modes use `central_runtime` pool; mutating modes use one `central_migration` session | Stable exit classes 0/2/3/4/5/6/7 |
| CLI backup/restore ops | `bins/central` (`backup *`, `restore *`) and `bins/central-backup`, `bins/central-restore` | Typed operator args, operation identity, confirmation | `central-backup` `app`/`port`, backup adapter contracts | Application services not required for the operation | Shared/exclusive advisory lock matrix; exclusive mode blocks all serve profiles | Stable exit classes 0/2/3/4/5/6/7 |
| CLI local-operator ops | `bins/central` (`local *`) | Typed operator args | `central-infra` service, helper-protocol contracts | Direct Docker/Compose/`pg_dump`/`pg_restore`/S3 calls | All infrastructure authority mediated through the root-owned helper protocol | Stable exit classes 0/2/3/4/5/6/7 |
| CLI workflow/harness ops | `bins/central` (`run submit`, `node decide`, `checkpoint *`, `artifact read`) | Typed operator args, workspace/run identity | `central-runsubmit`, `central-retry`, `central-checkpoint`, `central-artifact` services | Adapters, ports, transport internals | Operator commands map to the same services as HTTP surfaces | Stable exit classes + `central.local-result/v1` |
| Protected execution modes | `bins/central` (`helper`, `central-protected-broker`, `central-sandbox-launcher` modes) | Locked socket/systemd boundary invocations | `central-adapter-linux`, `rustix` | HTTP transport, capability `app` services | Root-owned privilege operations only; invoked under locked boundaries, never user-facing | Sanitized broker-protocol outcomes |
| Standalone launcher daemons | `bins/central-harness-launcherd`, `bins/central-migration-launcherd`, `bins/central-backup-launcherd` | Socket-activated launch requests | `central-adapter-linux`, `rustix`, adapter-specific runtime contracts | HTTP transport, capability `app` services | Root-owned daemon lifecycle; see §3.2 (SR-F1) | Sanitized launcher-protocol outcomes |
| Offline tools | `bins/central-advisory-sign` | Operator args, signing material path | `central-foundation`, `ed25519-dalek` | Network, database, transport | Offline Ed25519 advisory signing only | Stable exit classes |
| Supervised components (scheduler, journal publisher, retry sweeper, checkpoint janitor, outbox, reconciliation, cleanup) | `central-kernel` composition | Typed startup configuration; immutable adapter trait objects | Component-owned domain/port contracts; kernel lifecycle registry | Each other's internal state; transport crates | Component types expose `async fn run(&mut self) -> Result<(), Failure>`; kernel supervises and cancels by future drop; no assumption of co-location | Component retry with finite budget; terminal failure cancels profile |

**Slice test ownership:** Every controller role maps to at least one R-slice executable test target. Test ownership fields trace `controller role → R-slice capability → exact test file or declared future owner`. Roles marked `N/A` must state the explicit reason and the owning future scenario.

### 2.2 Service (`crates/capabilities/central-<cap>/src/app.rs`)

| Capability | Owning crate | Primary input | Primary output | Allowed imports | Prohibited imports | Transaction boundary | Authority source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Workspace | `central-workspace` | Typed commands, authority, deadline, operation identity | Typed results or application-classified failures | Own `domain`/`port`/`query`, `central-foundation` | Any transport, adapter, or framework crate; `axum`; `sqlx`; other capability `app` implementations (except approved DAG edges) | Loads domain snapshots; invokes domain decision; produces change-set or invokes conditional port | Workspace owner per ADR 0001 |
| Task | `central-task` | Typed Task lifecycle commands, authority, deadline | Typed results; approved change sets; Event intents | Own `domain`/`port`/`query`, `central-foundation` | Same prohibitions; may not import `central-execution`, `central-artifact`, `central-harness` | Task domain evaluates command, produces change-set with expected versions; adapter commits atomically | Workspace owner; Task execution chain per ADR 0001 |
| Execution | `central-execution` | Typed execution commands (claim, cancel, resume, harness-run, recovery epochs, retry, outbox) | Typed results; settled outcomes; Event intents | Own `domain`/`port`/`query`, `central-task` domain types (approved edge), `central-foundation` | Transport, adapter, framework crates; capability `app` implementations | Prepares attempt durably; invokes adapter outside transaction; persists outcome; atomic conditional lease/fencing ports | Run execution chain per ADR 0004 |
| Harness | `central-harness` | Typed harness commands (attempts, budgets, permissions, capture) per ADR 0035 | Classified attempts; settled outcomes; captured artifacts | Own `domain`/`port`/`query`, `central-foundation` | Transport, adapter, framework crates; capability `app` implementations; concrete harness SDKs | Prepare durably → invoke registered adapter outside transaction → settle outcome | Sequential coordinator per ADR 0004/0035 |
| Authorization | `central-authorization` | Typed authorization commands, capability policy queries | Approval decisions; effective grant results | Own `domain`/`port`/`query`, `central-foundation` | Provider/tool/harness concrete adapters; `central-harness`/`central-execution` `app` | Capability evaluation; durable Approval recording | Capability policy per ADR 0003 |
| Checkpoint | `central-checkpoint` | Typed checkpoint commands | Verified continuation evidence | Own `domain`/`port`/`query`, `central-foundation` | Transport, adapter, framework crates | Immutable checkpoint recording; subtree-anchored resume preflight (b36) | Run execution chain per ADR 0004 |
| Artifact | `central-artifact` | Typed Artifact lifecycle commands | Staged/ready/finalized outcomes; one-shot delivery capabilities | Own `domain`/`port`/`query`, `central-execution` completion-guard types (approved edge), `central-foundation` | Transport, adapter, framework crates | Reserve, stage, verify, promote, finalize sequence; composite finalization change-set | Artifact lifecycle per ADR 0005 |
| Event | `central-event` | Typed Event projection/feed queries | Bounded seek-paginated Event projections | Own `domain`/`port`/`query`, `central-foundation` | Transport, adapter, framework crates | Read-only event projections; writes occur only through other capability change-set commits | Workspace scoping; Event immutability per ADR 0001 |
| Session | `central-session` | Typed bootstrap/exchange, session management, validation, refresh, logout, revocation commands | Session state; cookie/CSRF result bindings | Own `domain`/`port`/`query`, `central-foundation` | Transport, adapter, framework crates; `axum` request state | Bootstrap exchange two-phase protocol: candidate staging, PostgreSQL commit, candidate activation, session delivery | Bootstrap token authority per protected store; database-time throttle |
| Workflow | `central-workflow` | Typed graph commands (node/edge validation, dynamic DAG expansion) | Graph change sets; validated node specs | Own `domain`/`port`/`query`, `central-retry` domain types (approved edge), `central-foundation` | Transport, adapter, framework crates; `app` implementations | Change-set commits with graph constraints; run-row lock anchor | Workflow graph per Phase 2 specs (b33) |
| Eventjournal | `central-eventjournal` | Typed journal append/fold queries | Canonical `run_events` envelopes; reconstructed state | Own `domain`/`port`/`query`, `central-foundation` | Transport, adapter, framework crates | Append via change-set commit; fold/reconstruction is read-only | Canonical journal per Phase 2 specs (b33) |
| Scheduler | `central-scheduler` | Typed scheduling commands (ready queue, worker registration, node leases) | Claim outcomes; missed-beat ladder state | Own `domain`/`port`/`query`, `central-foundation` | Transport, adapter, framework crates; capability `app` implementations | Atomic conditional claim ports (`SKIP LOCKED`); lease fencing | Worker protocol per Phase 2 specs (b35) |
| Retry | `central-retry` | Typed retry/decision commands | Classified retry outcomes; compensation intents | Own `domain`/`port`/`query`, `central-foundation` | Transport, adapter, framework crates; capability `app` implementations | Atomic conditional eligibility ports; timeout hierarchy; transactional `event_outbox` (b37) | Retry taxonomy per Phase 2 specs (b37) |
| Runview | `central-runview` | Typed projection queries | DAG projections; run lineage views; fleet probes | Own `domain`/`port`/`query`, `central-eventjournal` fold types (approved edge), `central-foundation` | Transport, adapter, framework crates; mutation ports | Read-only projection queries | Run lineage per Phase 2 specs (b33/b35) |
| Runsubmit | `central-runsubmit` | Typed run-submission commands | Run receipt; first-page node outcomes | Own `domain`/`port`/`query`, `central-task` domain/`app`/`port` types, `central-workflow` domain types, `central-foundation` | Transport, adapter, framework crates; other capability `app` implementations | Orchestrates task + workflow change-sets; every task transition passes through `central-task` domain service; store access via narrow consumer-side traits in its own `port.rs` (issue-122; see §6.4) | Run submission per Phase 2 specs |
| Backup | `central-backup` | Typed backup/restore operator commands | Backup manifests; restore reports; operation outcomes | Own `domain`/`port`/`query`, `central-foundation` | Transport, adapter, framework crates; does not own Task/Artifact/migration/authorization rules | Exclusive advisory lock scope; consistent-point snapshot; inventory chunking | Local operator authority plus verified backup/restore evidence |
| Infra | `central-infra` | Typed local-operator commands (init, prepare, up/down, doctor, maintenance, advisory) | Operation outcomes; status reports | Own `domain`/`port`/`query`, `central-foundation` | Transport, capability `app` implementations; direct Docker/Compose calls | Helper-protocol prepare → invoke → settle; exclusive lifecycle operations | Local operator authority per ADR 0009/0011 topology |

**Coordination rules (all services):**

- Methods accept typed commands/queries and explicit authority, deadline, and operation identity. No `context.Context` equivalent crosses the signature: cancellation is delivered by future drop, so every service future must be cancellation-safe at every `.await` (no mutation without durable receipt, no partial external effect without recorded ambiguity).
- Cross-capability workflows use an acyclic higher coordinator. `central-harness` + `central-execution` jointly carry the sequential-coordinator role ADR 0004 assigned to `agent/app`; the frozen B09 loop coordinator is never ported (ADR 0035/0036, ADR 0043).
- No external effect occurs while a PostgreSQL transaction is open.
- Prepare, invoke, settle, ambiguity, cancellation, retry, and recovery state remain explicit.
- Service code does not open transactions, pass a generic Unit of Work, inspect `axum` request/`Extension` state, or select concrete adapters.
- Supervised components return classified failures and use kernel-owned fail-fast lifecycle/shutdown behavior.

**Service-to-service crate DAG:**

```text
central-execution  → central-task                       (task root domain types: cancel/resume/harness-run coordination)
central-artifact   → central-execution                  (ExecutionChangeSet completion-guard types only; one-way, no reverse import)
central-runsubmit  → central-task, central-workflow                     (Phase 2 submission orchestration)
central-workflow   → central-retry                      (retry-policy domain types in node-spec validation)
central-runview    → central-eventjournal               (journal fold and lineage projection types)
```

Service-to-service edges never cycle. Lower capabilities (`task`, `authorization`, `checkpoint`, `artifact`, `event`, `workspace`, `session`, `workflow`, `eventjournal`, `scheduler`, `retry`, `backup`, `infra`) never import `central-harness`, `central-execution`, `central-runsubmit`, transport, or `central-kernel`.

**Cyclic-edge rule (Cargo constraint):** The upstream Go graph contains an intra-capability edge `task/app/query → execution` (the claimability decorator) alongside `execution → task`. Cargo forbids cyclic crates, so the Rust boundary inverts it: `central-execution::query` owns the claimability-decoration read contract that augments `central-task` projections with `Claimability`/`TrustedScope`, and `central-task` never imports `central-execution`. Any future requirement shaped like a capability↔capability cycle is resolved the same way — the higher (coordinator-side) capability owns the composed read/write contract; never merge crates or weaken the DAG to accommodate it.

**Kernel-edge rule (Cargo constraint):** The upstream Go components implement `kernel.Component`/`kernel.Preflight`, importing `internal/kernel`. In Rust, `central-kernel` is the composition root that imports every capability crate, so capability crates must not depend on `central-kernel`. Each capability's supervised component type instead exposes the structural signature `async fn run(&mut self) -> Result<(), Failure>` plus `async fn settle(&mut self) -> Result<(), Failure>` and `fn preflight(&self) -> Result<PreflightReport, Failure>` where applicable; `central-kernel` wraps those signatures in its owned `Component`/`Preflight` trait objects. Cancellation and settlement are delivered by kernel-held `CancellationToken` + future drop + a bounded `tokio::time::timeout` settlement call — never by a capability-imported kernel type.

### 2.3 Usecase (`domain.rs`, `port.rs`, `query.rs`)

| Role | Owning module | Primary content | Allowed imports | Prohibited imports |
| --- | --- | --- | --- | --- |
| Domain rules | `crates/capabilities/central-<cap>/src/domain.rs` (crate root re-export) | Domain decisions, invariants, change-set construction, rejections, Event intents, version expectations, domain snapshots, completion guards, safe domain failures | `central-foundation` (`identity`, `failure`), `time`, `serde` for payload value types | `async fn`, `tokio`, I/O traits, service implementations, `axum`, `sqlx`, `aws-sdk-s3`, `rustix`, `prometheus-client` |
| Command-persistence, external-effect, and observation ports | `src/port.rs` | Capability-owned operation-oriented traits for change-set commits, atomic conditional operations, external-effect invocations, and observations | `central-foundation`, its capability domain root types, `trait-variant` | `app.rs` internals, `query.rs`, transport, kernel, adapters |
| Read contracts | `src/query.rs` | Declaration-only consumer-side read traits, bounded request types, safe projection types, typed `SeekCursor` structs | `central-foundation`, its capability domain root types (reviewed allowlist only), `trait-variant` | `app.rs` internals, `port.rs`, transport, kernel, adapters |

**Key architectural rule:** "Usecase" is the inward capability `domain.rs` + `port.rs` + `query.rs` role called by `app.rs`. It is not a global crate name and does not contain transport DTOs. Only the parent capability `app.rs` Service consumes `query.rs` traits, and only after the surface-appropriate authorization decision. `central-adapter-postgres` implements `query.rs` read traits; command-persistence, external-effect, and observation adapters implement `port.rs` traits.

**Async-bound rules:**

- Every async trait in `port.rs` and `query.rs` is annotated `#[trait_variant::make(Send)]` (or carries explicit `+ Send` future bounds) and the trait itself requires `Send + Sync + 'static`, so trait objects compose with multi-threaded `tokio`/`axum` handlers without per-call-site `Send` debugging.
- `domain.rs` declares no `async fn`, no I/O traits, and no `tokio` import; it is pure synchronous Rust. Its unit tests are synchronous and deterministic.
- Future-drop cancellation must be safe at every `.await` point in `app.rs`: dropping a service future mid-operation leaves either a durable receipt, a durable prepared attempt, or no mutation — never a partial effect.

**`query.rs` contract rules:**

- Every `query.rs` contract records: parent Service caller, surface-appropriate authority decision, bounded request/projection types, Workspace/target/operation scoping, typed `SeekCursor`, maximum page, maximum SQL round trips and rows examined/returned, stable continuation, safe failure, and future test owner.
- Typed seek pagination is required. Offset pagination and unbounded queries are prohibited.
- N+1 behavior, readiness exact counts/full scans, authority-bearing exports, domain/recovery snapshots, persistence/object references, and direct transport injection of a query trait are prohibited.
- Query projections must not embed, alias, or expose domain aggregates, decision or recovery snapshots, change sets, application commands, `port.rs` traits, grants, `ProtectedUse`, `AuthorizedDownload`, fencing tokens, session/bootstrap/CSRF material, or restore tickets/nonces.

**`port.rs` contract rules:**

- Command ports are operation-oriented; they do not mirror tables and do not expose CRUD building blocks or database transactions (`sqlx::Transaction`, `&mut PgConnection`, `Executor` never appear in signatures).
- Domain-approved change-set commits follow: load typed durable snapshot → domain evaluates command → produce approved change set → adapter commits with expected versions and constraints → adapter returns committed database facts or typed conflict/failure.
- Atomic conditional ports are used for database-time and fencing operations (lease acquire/renew/settle, outbox claim/settle, `SKIP LOCKED` ready-queue claims, time-driven session expiry, retry eligibility, cleanup eligibility) where load/decide/commit is unsafe.
- Pattern selection is semantic: change-set commit for versioned domain snapshots; atomic conditional port when database time or fencing must be evaluated at mutation linearization point.

### 2.4 Infrastructure (`crates/adapters/`)

| Adapter | Owning crate | Implements | Allowed imports | Prohibited imports |
| --- | --- | --- | --- | --- |
| PostgreSQL persistence | `central-adapter-postgres` | Capability-owned `port.rs` and `query.rs` traits; native migration runner | `central-foundation`, capability domain/port/query contracts, `sqlx`, `time`, `serde`, `uuid` (mapping only), adapter-internal modules | Service implementations, `axum`, other adapters, capability `app.rs` |
| Object store | `central-adapter-s3` | `central-artifact` body-store port traits | `central-foundation`, `central-artifact` port/domain types, `aws-sdk-s3`, `aws-config`, `sha2` | Service implementations, `axum`, `sqlx`, other capabilities' domain crates |
| Harness adapters | `central-adapter-harness` | `central-harness` port traits (Claude Code, OpenCode, Codex, Antigravity invocation + `gitclone` + launcher client) | `central-foundation`, `central-harness` port/domain types, harness CLIs/transports, `tokio` process facilities | Service implementations, `axum`, `sqlx`, other capabilities' domain crates |
| Linux platform | `central-adapter-linux` | Protected-broker protocol, `memfd`, `SCM_RIGHTS`, `SO_PEERCRED`, `openat2`, `pidfd`, PAM/TTY, namespaces, cgroups; `central-authorization`/`central-infra`/`central-backup` platform port traits | `central-foundation`, capability port traits, `rustix` (`fs`, `net`, `process`, `shm`/`mm`), audited `unsafe` boundaries | Service implementations, `axum`, `sqlx`, `aws-sdk-s3`, other adapters |

**Infrastructure rules:**

- Adapters implement `port.rs` or `query.rs` traits but never define traits that core crates must import.
- Generated and database-specific types (`sqlx` row/query types, `PgPool`, AWS SDK shapes, `rustix` fd types) never cross the adapter boundary. Domain snapshots, change sets, conditional outcomes, and projections are mapped inside the adapter.
- Adapters classify and sanitize `sqlx`, object-store, harness, platform, and resolver errors before returning. Raw SQLSTATE detail, query text, object location, provider body, secret locator, or unbounded external message never crosses the adapter boundary.
- Adapters may enforce stronger resource/privilege safety but cannot decide business lifecycle or create authority.
- Repository abstractions, DI frameworks, service locators, and generic `Invoke(kind, payload)` adapters are prohibited.
- Adapters may not be imported upward by `app.rs`, `domain.rs`, `port.rs`, or `query.rs`: no capability crate ever depends on an adapter crate. Concrete-adapter wiring exists only in `central-kernel` composition, invoked from `bins/*` binaries (§3.3). This rule has no exceptions.

**Artifact delivery rules (infrastructure contract):**

- `central-artifact::app` owns the exact Service entry point `async fn prepare_authorized_download(&self, req: AuthorizedDownloadRequest) -> Result<AuthorizedDownload, Failure>`; the request carries only authenticated Workspace/Artifact identity and transport-independent authority evidence. The Service performs the initial durable authorization/open sequence and returns the opaque one-shot capability.
- One-shot `AuthorizedDownload`: `start` consumes the value once (`self` by value; the type is `!Clone`); performs final synchronous revalidation immediately before transport commits headers and copies first byte.
- Failed or repeated start closes/refuses the stream. Zero-byte failure on any denial/error.
- Safe media type and disposition are set explicitly. No presigned URLs. No framework file helpers (`NamedFile`, `ServeFile` on untrusted paths).
- No mid-stream revocation claim; after first byte, error uses API v1 transport-level termination.

**Streaming/inventory infrastructure rules:**

- Whole-body or materialized inventory is prohibited.
- Counting readers (`tokio::io::AsyncRead` wrappers) with fixed reusable buffers. FIFO cancellation without stranded successors.
- Admission occurs before body/object/multipart open. Sequential verification.
- Sorted bounded inventory merge using at most one database page and one object page per worker with 1,000 × 4 KiB chunks, 1–2 workers, 8 MiB spool per worker.
- Durable bounded slice/checkpoint ownership.

## 3. Crate tree, binary topology, and dependency contract

### 3.1 Cargo workspace tree

```text
central-rust/
├── Cargo.toml                        # Workspace root, shared [workspace.dependencies] & [workspace.lints]
├── rust-toolchain.toml               # Pinned stable toolchain
├── deny.toml                         # cargo-deny license, advisory, and source policy
├── migrations/                       # Canonical forward-only SQL & migration definitions (v0..b37)
├── .sqlx/                            # Offline compile-time verification metadata for sqlx
├── crates/
│   ├── central-foundation/           # identity (UUIDv7 newtypes), failure (error taxonomy & exit classes)
│   ├── capabilities/
│   │   ├── central-workspace/        # domain.rs, port.rs, query.rs, app.rs
│   │   ├── central-task/             # domain.rs, port.rs, query.rs, app.rs
│   │   ├── central-execution/        # Phase 1 lease fencing, recovery epochs, retry, outbox
│   │   ├── central-authorization/    # capability policy, grants, approvals
│   │   ├── central-session/          # bootstrap exchange, session lifecycle, CSRF bindings
│   │   ├── central-checkpoint/       # Phase 1 & Phase 2 (b36) subtree-anchored checkpoints & resume preflight
│   │   ├── central-event/            # Phase 1 immutable event envelopes & seek-paginated feeds
│   │   ├── central-artifact/         # staging, SHA-256 verification, promotion, content policy, b34 lineage
│   │   ├── central-harness/          # ADR 0035 harness control plane (attempts, budgets, permissions, capture)
│   │   ├── central-workflow/         # Phase 2A (b33) workflow_nodes, workflow_edges, dynamic DAG expansion
│   │   ├── central-eventjournal/     # Phase 2A (b33) canonical run_events envelope, fold & reconstruction
│   │   ├── central-scheduler/        # Phase 2B (b35) ready queue, worker registration, node leases, missed-beat ladder
│   │   ├── central-retry/            # Phase 2D (b37) error taxonomy, budgets, timeout hierarchy, compensation, outbox
│   │   ├── central-runview/          # Phase 2E DAG projection, run lineage view, fleet probes
│   │   ├── central-runsubmit/        # Phase 2 run submission orchestration
│   │   ├── central-backup/           # backup/restore manifests, tickets, chunked inventory, quarantine
│   │   └── central-infra/            # local init, prepare, compose lifecycle, doctor, maintenance, advisory
│   ├── adapters/
│   │   ├── central-adapter-postgres/ # sqlx implementations of capability port.rs & query.rs traits + migration runner
│   │   ├── central-adapter-s3/       # S3/MinIO object storage adapter for central-artifact
│   │   ├── central-adapter-harness/  # Claude Code, OpenCode, Codex, and Antigravity adapters + gitclone + launcher client
│   │   └── central-adapter-linux/    # Protected broker protocol, memfd, SCM_RIGHTS, PAM/TTY, namespaces, cgroups
│   ├── transport/
│   │   └── central-transport-http/   # Axum controllers: API v1 JSON, Askama SSR Web UI (Tasks + Phase 2 Runs), Health & Metrics
│   └── central-kernel/               # Manual dependency composition, supervised task runner, graceful shutdown
└── bins/
    ├── central/                      # Main CLI (serve, run submit, node decide, checkpoint *, artifact read, local *, migrate *, backup *, restore *, helper/broker/sandbox-launcher modes)
    ├── central-harness-launcherd/    # Root socket-activated daemon launching isolated operator harness sessions (ADR 0036)
    ├── central-migration-launcherd/  # Dedicated migration launcher
    ├── central-migrate/              # Migration operator binary (central-migrate UID)
    ├── central-backup-launcherd/     # Backup/restore launcher daemon
    ├── central-backup/               # Backup operator binary
    ├── central-restore/              # Restore engine binary
    └── central-advisory-sign/        # Offline Ed25519 advisory signing tool
```

### 3.2 Binary vs execution-mode topology (SR-F1)

Matching the upstream Go architecture, the process topology splits **standalone root-owned launcher daemons** from **execution modes of the main `central` binary**. The distinction is an authority boundary, not a code-organization convenience: standalone daemons own root privileges under their own unit/socket identity, while execution modes of `central` run under locked socket/systemd boundaries invoked by the operator-facing CLI.

| Binary / mode | Process identity | Role | Privilege boundary |
| --- | --- | --- | --- |
| `central serve` | `central-runtime` operator UID | Serving profile: HTTP transport + supervised components | Application pools only; never loads `central_migration` credentials |
| `central run submit`, `central node decide`, `central checkpoint *`, `central artifact read`, `central local *`, `central migrate *`, `central backup *`, `central restore *` | Local operator | CLI controller verbs (§5) | Verb-specific authority per §5.3; mutating infrastructure verbs require fresh PAM + helper-owned TTY per the ADR 0009–0019 topology |
| `central helper` (execution mode) | Root (via locked socket boundary) | Root infrastructure helper | Root-owned operations only through the helper protocol; never user-facing HTTP |
| `central central-protected-broker` (execution mode) | Root broker identity | Protected broker: `memfd` secret material, `SCM_RIGHTS` fd passing, TLS leaf signing, XDG projections | Broker protocol only; no direct DB/object-store access |
| `central central-sandbox-launcher` (execution mode) | Sandbox launcher identity | Sandboxed launcher for harness child processes | Namespace/cgroup confinement only |
| `bins/central-harness-launcherd` | Root daemon (socket-activated) | Launches isolated operator harness sessions per ADR 0036 | Standalone daemon; independent of `central` process lifecycle |
| `bins/central-migration-launcherd` | Root daemon | Dedicated migration launcher | Mediates `central_migration` privilege per ADR 0011 |
| `bins/central-migrate` | `central-migrate` UID | Migration operator binary | Single `central_migration` session for mutating migration ops |
| `bins/central-backup-launcherd` | Root daemon | Backup/restore launcher daemon | Mediates backup/restore privileged steps (fd-3 `pg_dump`/`pg_restore`) |
| `bins/central-backup` | `central-backup` UID | Backup operator binary | Shared/exclusive advisory lock matrix |
| `bins/central-restore` | `central-restore` UID | Restore engine binary | Verified-ticket authority; capacity reserve per ADR 0018 |
| `bins/central-advisory-sign` | Offline operator | Ed25519 advisory signing | No network, no database |

SR-F1 rule: adding a new privileged operation is a **binary-or-mode decision**, not a flag on an existing process. A capability that needs root authority must justify either a dedicated daemon (long-lived, socket-activated, independently supervised) or an execution mode of `central` (short-lived, invoked under a locked boundary). Root authority never flows through `central serve`.

### 3.3 Dependency-allowlist matrix

| Importing crate | May import | Must not import |
| --- | --- | --- |
| Controller (`central-transport-http`, `bins/*`) | `central-foundation`, service-layer `app` command/result types, `query` request/projection **value types** for mapping | `query` traits, command-persistence ports, concrete adapters (except `central-adapter-linux` inside the §3.2 launcher and protected-execution-mode binaries), `sqlx`, `aws-sdk-s3`, `rustix` (outside `central-adapter-linux` + launcher and protected-execution-mode bins), harness SDKs |
| Service (`central-<cap>::app`) | Its own capability `domain`/`port`/`query`; approved cross-capability types per the §2.2/§6.4 DAG | Any transport, adapter, or framework crate; `axum`; `sqlx`; cross-capability `app` implementations not on the approved DAG |
| Usecase (`domain.rs`) | `central-foundation`, `time`, `serde` value-type derives | `async`, `tokio`, I/O traits, service implementations, `axum`, `sqlx`, `aws-sdk-s3`, `rustix`, `prometheus-client` |
| Usecase (`port.rs`) | `central-foundation`, its capability `domain.rs`, `trait-variant` | `app.rs` internals, `query.rs`, transport, kernel, adapters |
| Usecase (`query.rs`) | `central-foundation`, its capability `domain.rs` (reviewed allowlist), `trait-variant` | `app.rs` internals, `port.rs`, transport, kernel, adapters |
| Infrastructure (adapter crate) | `central-foundation`, the domain/port/query contracts it implements, its SDK crates, adapter-internal modules | Service implementations; other adapters; capability `app.rs`; `axum`/`askama` |
| Kernel (composition root) | All inward contracts AND concrete adapter crates | None (it is the single composition point that knows both) |

**Explicit prohibitions:**

- Crates or modules named `common`, `models`, `utils`, `services`, or `repositories` are prohibited as catch-all ownership substitutes.
- Global layer roots (top-level `domain/`/`service/`/`infrastructure/` crates or a single shared `ports` crate) are prohibited.
- DI framework, service-locator, and global-registry crates (`once_cell`/`lazy_static` global containers consulted by capability code) are prohibited.
- Capability-to-capability dependency cycles are compile-time impossible and must stay so; see the §2.2 cyclic-edge rule.

### 3.4 Representative Rust signatures

```rust
// Identity — opaque newtype IDs; UUIDv7 under the hood; uuid::Uuid never escapes
// central_foundation::identity.
pub struct WorkspaceId(uuid::Uuid);   // field is private
pub struct TaskId(uuid::Uuid);
pub struct RunId(uuid::Uuid);
pub struct ArtifactId(uuid::Uuid);
pub struct EventId(uuid::Uuid);
// FromStr accepts only canonical lowercase 8-4-4-4-12 text, RFC 9562 variant, version 7,
// non-zero — plus the explicitly admitted sentinel workspace ID (b20).

// Failure taxonomy
#[non_exhaustive]
pub enum FailureKind {
    Invalid,      // 400
    NotFound,     // 404
    Conflict,     // 409
    Denied,       // 403
    Unavailable,  // 503
    Ambiguous,    // indeterminate external effect
    Cancelled,    // explicit cancellation
    Internal,     // 500
}

// Domain change set (central-task::domain)
pub struct TaskChangeSet {
    pub task_id: TaskId,
    pub expected_version: Version,
    pub next_state: TaskStatus,
    pub bounded_reasons: Vec<SafeReason>,
    pub event_intents: Vec<EventIntent>,
    pub correlation_id: CorrelationId,
    pub causation_id: CausationId,
}

// Event intent — owned by domain/application decision; PostgreSQL supplies sequence and timestamps.
pub struct EventIntent {
    pub event_type: EventType,
    pub aggregate_id: AggregateId,
    pub aggregate_version: Version,
    pub payload: SafePayload,
    pub correlation_id: CorrelationId,
    pub causation_id: CausationId,
}

// Atomic conditional port (example: lease acquire) — central-execution::port
#[trait_variant::make(Send)]
pub trait LeasePort: Send + Sync + 'static {
    async fn acquire(&self, req: LeaseAcquireRequest) -> Result<LeaseAcquireOutcome, Failure>;
    async fn renew(&self, req: LeaseRenewRequest) -> Result<LeaseRenewOutcome, Failure>;
    async fn settle(&self, req: LeaseSettleRequest) -> Result<LeaseSettleOutcome, Failure>;
}

// Declaration-only query contract (example: Task list projection) — central-task::query
pub struct TaskListRequest {
    pub workspace_id: WorkspaceId,
    pub cursor: Option<TaskListCursor>,  // typed seek cursor; no offset, no generic filter map
    pub page_size: u16,                  // bounded, default 100, max 250
}

pub struct TaskListProjection {
    pub tasks: Vec<TaskSummary>,
    pub next_cursor: Option<TaskListCursor>,
}

#[trait_variant::make(Send)]
pub trait TaskReadContract: Send + Sync + 'static {
    async fn list_tasks(&self, req: TaskListRequest) -> Result<TaskListProjection, Failure>;
}

// Protected use — non-transferable, one-shot; !Clone, !Serialize, consumed by value.
pub struct ProtectedUse { /* sealed fields */ }
impl ProtectedUse {
    pub async fn use_once<F, Fut>(self, invoke: F) -> Result<ProtectedUseResult, Failure>
    where
        F: FnOnce(SecretMaterial) -> Fut + Send,
        Fut: Future<Output = Result<TransportAcceptance, Failure>> + Send;
}

// One-shot Artifact delivery — opaque capability value type.
pub struct AuthorizedDownload { /* sealed fields */ }
impl AuthorizedDownload {
    pub async fn start(
        self,
    ) -> Result<(Box<dyn AsyncRead + Send + Unpin>, MediaType, u64, SafeDisposition), Failure>;
}

// Component lifecycle — structural signature, never a kernel import.
// central-<cap>::app exposes:
//     pub async fn run(&mut self) -> Result<(), Failure>;
//     pub async fn settle(&mut self) -> Result<(), Failure>;
//     pub fn preflight(&self) -> Result<PreflightReport, Failure>;
// central-kernel wraps them into its owned Component/Preflight trait objects; cancellation
// arrives via kernel-held CancellationToken + future drop; settlement via bounded timeout.
```

## 4. Controller contract

### 4.1 Axum construction and configured router

- Build a `tower::ServiceBuilder`-layered `axum::Router` served by `axum::serve` on an explicit `tokio::net::TcpListener`. Convenience defaults that hide server configuration are prohibited.
- No automatic trailing-slash/fixed-path redirect behavior is enabled.
- Explicit method gating: every route declares its allowed methods via `MethodRouter`; unmatched methods produce a fixed `405` + `Allow` outcome (see §4.1.1).
- CORS is disabled (no `tower_http::cors::CorsLayer`); forwarded addresses are not trusted unless the local-topology documentation defines a proxy topology.
- Default framework logging/recovery are replaced by Central-owned `tower` layers.
- `Router::fallback` and `Router::method_not_allowed_fallback` produce the fixed safe outcomes below.

#### 4.1.1 Fallback and method-not-allowed outcomes

Unmatched routes and methods produce fixed safe outcomes. No route inventory is revealed. The access observer receives the fixed `unmatched` sentinel for both paths.

**Unmatched path (any method):**

| Attribute | Specification |
| --- | --- |
| HTTP status | 404 |
| Content-Type | `application/json` for paths beginning with `/api/` or unclassified paths; `text/html; charset=utf-8` for paths beginning with `/app/` |
| JSON body shape | `{"error":{"code":"NOT_FOUND"}}` — API v1 canonical error envelope with no additional fields |
| HTML body shape | Safe static HTML page with generic "Page not found" message; no route suggestion, no path echo, no header reflection |
| Security headers (JSON) | `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` |
| Security headers (HTML) | Full §4.4 response-security profile: CSP `default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` |

**Method not allowed (matched route, method not in route's allowlist):**

| Attribute | Specification |
| --- | --- |
| HTTP status | 405 |
| `Allow` header | Comma-separated uppercase methods permitted on the matched route |
| Content-Type | Same content-type and body-shape rules as unmatched path |
| Security headers | Same security-header rules as unmatched path |
| Prohibitions | No route inventory enumeration beyond the matched route's `Allow` header |

Configured-router tests must verify: unmatched-path 404 JSON and HTML bodies, unmatched-method 405 with correct `Allow`, absence of route enumeration, presence of full CSP and anti-framing on HTML responses, and absence of reflected path/header content in both JSON and HTML bodies.

### 4.2 Layer order

The canonical `tower` layer stack from outermost to innermost:

1. Safe panic recovery (with private final-outcome recorder)
2. Request-metadata bounds plus strict request/correlation identity validation or replacement
3. Exact response-security profile
4. Safe access observation using sanitized facts only
5. Universal loopback-source/exact-Host validation plus method-sensitive Origin validation
6. Body/content-type bounds not already enforced by the HTTP server (`DefaultBodyLimit`/`RequestBodyLimitLayer` configured at or below §4.6 caps)
7. Explicit route-policy dispatch
8. Session authentication (when route policy requires it)
9. Header or form CSRF validation (when route policy requires it)
10. Route-specific parsing and Workspace authorization
11. Handler invocation

### 4.3 Route matrix

| Route class | Methods | Session | CSRF | Additional policy |
| --- | --- | --- | --- | --- |
| `/api/v1/session/bootstrap` | POST only | No | No | Loopback/exact Host + required exact Origin; single-use token; database-time throttle. Only state-changing session/CSRF exception |
| `/api/v1/capabilities` | GET only | No | No | Loopback/exact Host + safe-method optional-Origin; fixed API/version feature discovery |
| `/app/bootstrap` | GET only | No | No | Fixed first-run/session-recovery HTML + embedded same-origin helper; authenticated session redirects to `/app/tasks`; no token accepted in URL/query/form |
| `/api/v1/session/logout` | POST only | Required | Required (`X-CSRF-Token`) | Revokes session; clears cookie safely |
| Other `/api/v1/...` queries | GET only | Required | No | Workspace authority + bounded query policy |
| Other `/api/v1/...` commands | POST only | Required | Required (`X-CSRF-Token`) | JSON content/bounds; idempotency; expected-version; Workspace authority |
| Other `/app/...` pages | GET only | Required | No | HTML view models; missing/expired session → `303` to `/app/bootstrap`; `no-store` |
| `/app/...` mutations | POST only | Required | Required (session-bound hidden form value) | Token never from URL; success uses Post/Redirect/Get |
| `/app/runs`, `/app/runs/submit` | GET/POST per Phase 2 specs | Required | Required on POST | `central-runview`/`central-runsubmit` services; same mutation policy as `/app/...` |
| `/assets/...` | GET or HEAD only | No | No | Embedded static allowlist; no filesystem fallback or dynamic content |
| `/` | GET only | No | No | Fixed redirect to `/app/tasks` |
| `/health/live`, `/health/ready` | GET only | No | No | Generic operational response; loopback listener policy applies |
| `/metrics` | GET only | Topology policy | No | Dedicated loopback operational listener or authenticated application session required |

**Restart-barrier enforcement:** every Cancel/Retry/Rerun/Resume mutation re-evaluates eligibility from fresh durable state inside the commit transaction. A mutation admitted before a serve restart is never assumed still-eligible after it; post-restart actions act only on reconciled durable state. This applies uniformly to `/app/tasks/:task_id/{cancel,retry,rerun,resume}`, `/app/runs/...` mutations, and their `/api/v1/...` counterparts.

### 4.4 Response-security profile

Normative on every `/app/...` (and `/app/runs...`) success, redirect, validation/authentication/authorization failure, and recovered `500`:

```text
Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cache-Control: no-store
```

Templates contain no inline script or style; JavaScript assets are allowlisted embedded same-origin. Redirect and error responses retain anti-framing headers. API responses retain `nosniff`, same-origin referrer, and canonical cache policy. Artifact responses retain stricter Artifact-lifecycle delivery headers.

> **SB-G4 note (carried forward unchanged):** `Referrer-Policy` is `same-origin`, not `no-referrer`. Per the Fetch spec's "append a request Origin header" algorithm, `no-referrer` causes a browser to send a literal `Origin: null` header on a same-origin, non-GET/HEAD native `<form>` POST navigation, which the Origin-enforcement layer correctly rejects with `403 NULL_ORIGIN` — breaking every plain native form post (task-console mutations, logout). `same-origin` is safe under this CSP (every `*-src` directive is `'self'` or `'none'`, so no cross-origin request can be made; `same-origin` sends no `Referer` cross-origin), and it restores `Origin` correctly for same-origin native form posts. The profile may be tightened further but must not be re-broadened to `no-referrer` without re-confirming this Origin-header interaction has been addressed by other means.

### 4.5 Rendering contract

- `askama` templates are compile-time checked and load-tested before readiness; escaping is automatic (`escape = "html"` default).
- No unescaped markup on untrusted values: `|safe`, `askama::filters::Safe`, and `MarkupDisplay::Unsafe` are prohibited outside a reviewed allowlist of constant markup.
- No inline script or style. Embedded same-origin allowlisted assets only (`include_bytes!`/`rust-embed`-style embedded registry; no filesystem fallback).
- Transport-owned DTO/view-model mapping, not domain serialization.
- Hostile-string renderer fixtures required (Askama escaping proofs).
- DTOs and view models are separate handler/representation sets per `/api/v1/...` and `/app/...`.
- Post/Redirect/Get (PRG) is mandatory for all HTML mutations: every `/app/...` POST resolves to a `303` redirect (or a `200` re-render only when no mutation committed, per the §4.7 state rows); no mutation response renders a direct page body.
- CSRF token (session-bound `X-CSRF-Token` header or hidden form value) plus `Origin` validation is mandatory on every state-changing route; tokens never travel in URL/query.

### 4.6 Resource matrix (SR-F2)

All values are defaults with hard caps. Installed configuration must land at or below caps. Exceeding a hard cap fails startup or the individual operation safely. `central-transport-http` enforces: **max 32 active non-streaming requests, 64 queued waiters, 5-second admission wait timeout, 2 MiB maximum request/response buffer, and 64 MiB aggregate buffered-response memory cap. Admission is acquired before reading request bodies or touching PostgreSQL.**

#### Artifact streaming

| Resource | Default | Hard cap | Configuration owner | Enforcer |
| --- | --- | --- | --- | --- |
| Active transfers per process | 2 | 8 | Topology config | `central-artifact` port adapter admission gate |
| Admission waiters | 8 | 32 | Topology config | `central-artifact` port adapter admission gate |
| Admission wait deadline | 5 s | 30 s (never past request deadline) | Topology config | `central-artifact` port adapter |
| Streaming copy buffer | 256 KiB | 1 MiB per active transfer | Topology config | `central-artifact` port adapter |
| Stream idle I/O timeout | 30 s | 2 min | Topology config | `central-artifact` port adapter |
| Stream total operation timeout | 30 min | 2 h (never past durable authority deadline) | Topology config | `central-artifact` port adapter |
| Ready Artifact body (inherited) | 256 MiB | 4 GiB | ADR 0005 | `central-artifact` port adapter |

Cross-field validation: Artifact copy buffer × active concurrency must not exceed 8 MiB. Full queue fails immediately before body/object/multipart open.

#### Non-streaming HTTP

| Resource | Default | Hard cap | Configuration owner | Enforcer |
| --- | --- | --- | --- | --- |
| In-flight requests | 16 | 32 | Topology config | `central-transport-http` admission gate (`tower` concurrency limit) |
| Admission waiters | 32 | 64 | Topology config | `central-transport-http` admission gate (bounded queue) |
| Admission wait deadline | 2 s | 5 s (never past request deadline) | Topology config | `central-transport-http` admission gate |
| Buffered response per route | JSON 2 MiB; HTML 1 MiB | 2 MiB per route | Topology config | `central-transport-http` rendering |
| Aggregate response buffers | 32 MiB | 64 MiB (enforced as active × 2 MiB) | Topology config | `central-transport-http` admission |
| Request header bytes | 32 KiB | 64 KiB | Topology config | HTTP server bound |
| Single header value | 4 KiB | 4 KiB | Topology config | `central-transport-http` |
| Header-read timeout | 5 s | 10 s | Topology config | HTTP server bound |
| Idle timeout | 60 s | 2 min | Topology config | HTTP server bound |

Cross-field validation: at most 32 active buffers × 2 MiB = 64 MiB aggregate capacity.

#### PostgreSQL pools

| Pool | Default | Hard cap | Notes |
| --- | --- | --- | --- |
| Installation-wide total | 16 | 24 | Sum of all profiles/modes |
| Serving data pool | 12 | 16 | Partitioned across all profiles |
| Shared-lock control | 1 | 4 | One per configured serve profile |
| Coexisting read-only operator | 2 | 4 | Shared readers during serve runtime |
| Mutually exclusive mutation operator | 4 | 8 | Only when serving pools are absent |
| Runtime-general | 6 | 8 | Execution, reconciliation, outbox dispatch |
| Runtime-settlement | 2 | 2 | Dedicated; cannot borrow from runtime-general, cleanup, or outbox |
| Outbox | 3 | 4 | |
| Cleanup | 1 | 2 | Authenticates as `central_runtime` |
| Pool acquisition timeout | 2 s | 5 s | `sqlx` `acquire_timeout` at or below cap |

Cross-field validation: 16 default / 24 hard total; settlement must be exactly 2; no non-settlement route may use the settlement pool.

#### Lock and operator deadlines

| Resource | Default | Hard cap |
| --- | --- | --- |
| Common target-exclusive lock acquisition | 30 s | 5 min |
| Migration-specific advisory-lock acquisition | 15 s | 60 s |
| Total `migrate up`/`migrate resume` lock acquisition | 45 s | 6 min (sequential) |
| Backup exclusive operation elapsed | 2 h | 8 h (terminal for that point) |
| Restore verification ticket lifetime | 15 min | 1 h |
| Unreferenced provisioning-candidate cleanup age | 5 min | 1 h |

#### Inventory

| Resource | Default | Hard cap |
| --- | --- | --- |
| Records per immutable chunk | 1,000 | 1,000 |
| Verification workers | 1 | 2 |
| Encoded record size | 4 KiB | 4 KiB |
| Local spool per worker | 8 MiB | 8 MiB |
| Work slice | 100 pages or 5 min | 1,000 pages or 30 min |

Cross-field validation: inventory worker × spool product must not exceed 16 MiB.

#### Runtime deadlines

| Resource | Default | Hard cap |
| --- | --- | --- |
| Ordinary preflight elapsed budget | 5 s | 10 s |
| Preflight/reconciliation discovery page | 100 | 1,000 |
| Serve settlement shutdown grace | 30 s | 2 min |
| Serve total shutdown elapsed | 45 s | 3 min (not shorter than settlement grace) |

### 4.7 HTML surface families

Phase 1 defines seven HTML surface families. The tables below map every state for each family, carried over from the upstream Gate 7 contract with capability names remapped to Rust crates. Every non-applicable state uses `N/A` with an explicit reason; no contract behavior is left as a placeholder. Column meanings:

- **Parent Service:** capability `app` method invoked (command or query).
- **query.rs:** bounded request and projection types consumed via the parent Service. `N/A` for mutation-only surfaces.
- **Rendering:** safe result or error rendering approach for this state.
- **PRG:** Post/Redirect/Get code or `N/A` for non-mutation displays.
- **Action:** user or system action available in this state.
- **Polling/backoff:** cursor-polling or retry-backoff behavior.
- **Durable source:** authoritative PostgreSQL/object-store state producing the display.
- **Owning capability:** capability whose slice owns the executable coverage. HTML surfaces ship with `central-transport-http` (R3) or `central-runview` (R4); domain/query contracts ship with their capability slice per [rust-vertical-slice-roadmap.md](../implementation/rust-vertical-slice-roadmap.md).

Common defaults applying to every row unless overridden: anti-framing = full §4.4 profile; rendering = `askama` automatic escaping with transport-owned view models; PRG = `N/A` for GET displays.

Phase 2 adds the `/app/runs` surface family (run DAG projection, run lineage view, fleet probes) owned by `central-runview` per the Phase 2 design specs (slice 2E). It follows this identical state-matrix contract — normal/loading/empty/pending/terminal/conflict/denied/unavailable/restart/validation rows with typed `SeekCursor` polling — and is authored in detail by its owning R4 slice.

---

#### 4.7.1 Bootstrap (`GET /app/bootstrap`, `POST /api/v1/session/bootstrap` via JS)

| State | Parent Service | query.rs | Rendering | PRG | Action | Polling/backoff | Durable source | Owning capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| normal | `central-session::app` → `ValidateSession` (query) | `SessionStatusRequest` → `SessionStatusProjection` | Session-required/expired form with labelled password input, `autocomplete="off"`; already-authenticated session → redirect | `303` → `/app/tasks` (authenticated) | Submit via embedded same-origin `/assets/bootstrap.js` | N/A | Session cookie, CSRF verifier (PostgreSQL) | `central-session` |
| loading | `central-session::app` → `ExchangeBootstrap` (command) | `N/A` (mutation) | Disabled input with progress indicator; `Retry-After` rendered from header when present | N/A (JS navigation after hook success) | JS POST to `/api/v1/session/bootstrap` with `credentials: same-origin` | N/A | Bootstrap exchange two-phase protocol | `central-session` |
| empty | N/A — bootstrap has no collection | N/A — no read projection | N/A — render the `normal` bootstrap state when no prior context exists | N/A — no mutation | N/A — no action | N/A — no polling | N/A — no durable collection | `central-session` |
| pending | `central-session::app` → `ExchangeBootstrap` (command) | `N/A` | Throttle feedback with `Retry-After` countdown; non-enumerating message | N/A | Retry exchange after `Retry-After` | Bounded retry per `Retry-After` | Database-time throttle counters (PostgreSQL) | `central-session` |
| terminal | `central-session::app` → `ExchangeBootstrap` (command) | `N/A` | Fixed non-enumerating failure message (invalid/consumed token) | `303` → `/app/bootstrap` (fresh form) | New bootstrap attempt | N/A | Consumed generation record (PostgreSQL) | `central-session` |
| conflict | `central-session::app` → `ExchangeBootstrap` (command) | N/A — command path | Concurrent identical exchange renders the `pending` state from the idempotent receipt; changed input renders bounded conflict without enumeration | `303` to the fixed bootstrap/session destination when the receipt completed; otherwise `200` pending | Retry only the same exchange identity | Honor bounded `Retry-After`; default 1 s, cap 10 s with jitter | Idempotent command receipt (PostgreSQL) | `central-session` |
| denied | `central-session::app` → `ExchangeBootstrap` (command) | `N/A` | Fixed denied display; no token, authority, or internal state leak | N/A | N/A (requires new exchange) | N/A | Throttle/authority evidence (PostgreSQL) | `central-session` |
| unavailable | `central-session::app` → `ExchangeBootstrap` (command) | `N/A` | Safe `503` with bounded integer `Retry-After`; no dependency detail | N/A | Retry after backoff | Retry with backoff per `Retry-After` (1 s default, 10 s cap + jitter) | Dependency health (adapter observation) | `central-session` |
| restart/reconciliation | `central-session::app` → `ReconcileBootstrap` (recovery) | `BootstrapStatusRequest` → `BootstrapStatusProjection` | Server-side recovery; user sees fresh `normal` bootstrap page or safe operator-repair outcome | N/A (`GET /app/bootstrap` renders reconciled state) | Server activates registered candidate/generation/digest or fails closed | N/A | PostgreSQL generation/candidate records + protected store | `central-session` |
| validation | N/A (client-side) | `N/A` | Field-associated error with accessible `role="alert"` summary; empty/invalid token feedback | N/A | Corrected resubmission | N/A | N/A (pre-submission) | `central-session` |

---

#### 4.7.2 Task list/create (`GET /app/tasks`, `POST /app/tasks`)

| State | Parent Service | query.rs | Rendering | PRG | Action | Polling/backoff | Durable source | Owning capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| normal | `central-task::app` → `ListTasks` (query) | `TaskListRequest` → `TaskListProjection` | List with Task summaries (status, title, metadata); create button | N/A (GET) | Create task (link to `POST /app/tasks`) | Optional polling via cursor for live updates | `central-task` query projection via PostgreSQL adapter | `central-task` |
| loading | `central-task::app` → `ListTasks` (query) | `TaskListRequest` → `TaskListProjection` | Skeleton/spinner state; `aria-live="polite"` | N/A — read-only GET | N/A — initial navigation | N/A — initial server render is synchronous; no polling before the response | `central-task` query projection | `central-task` |
| empty | `central-task::app` → `ListTasks` (query) | `TaskListRequest` → `TaskListProjection` | Empty-state message with create-CTA; no empty-table visual | N/A | Create first task | N/A | `central-task` query projection with zero results | `central-task` |
| pending | `central-task::app` → `ListTasks` (query) | `TaskListRequest` → `TaskListProjection` | Queued/running/waiting summaries with status badges/indicators; polling active | N/A | Poll for updates | Cursor poll: 1 s default, 10 s cap + jitter; stop on terminal | `central-task` query projection + Event seek cursor | `central-task` |
| terminal | `central-task::app` → `ListTasks` (query) | `TaskListRequest` → `TaskListProjection` | Completed/failed task summaries; polling stops | N/A | View detail | N/A (polling stops) | `central-task` query projection | `central-task` |
| conflict | `central-task::app` → `CreateTask` (command) | `N/A` | Stale-version or duplicate-command conflict with refreshed state; bounded reason rendered | `303` → `GET /app/tasks` (refreshed list) | N/A | N/A | Command receipt + version CAS (PostgreSQL) | `central-task` |
| denied | `central-task::app` → `ListTasks` / `CreateTask` | `TaskListRequest` | Denied-authority display; no Workspace or cross-scope leak | N/A | N/A | N/A | Authorization capability decision | `central-task` |
| unavailable | `central-task::app` → `ListTasks` (query) | `TaskListRequest` → `TaskListProjection` | Safe `503` with bounded `Retry-After`; resource-exhausted feedback | N/A | Retry after backoff | Retry per `Retry-After` | `central-task` query adapter observation | `central-task` |
| restart/reconciliation | `central-task::app` → `ListTasks` (query) | `TaskListRequest` → `TaskListProjection` | Post-restart recovered list; background reconciliation active; cursor-polling resumes from durable checkpoint | N/A | Poll for updates if reconciliation is active | Cursor poll resumed from last durable checkpoint | Durable task state + reconciliation cursors (PostgreSQL) | `central-task` |
| validation | `central-task::app` → `CreateTask` (command) | `N/A` | Field-associated errors with accessible summary; invalid input feedback rendered on form | `200` (re-render form with errors) | Corrected resubmission | N/A | N/A (domain validation rejection) | `central-task` |

---

#### 4.7.3 Task detail (`GET /app/tasks/:task_id`)

The task-detail controller is the transport-owned composition coordinator. It calls `central-task::app.get_task_detail`, `central-artifact::app.list_artifact_summaries`, and `central-authorization::app.list_approvals` independently with the same authenticated Workspace context, then maps their safe projections into one transport-owned view model. Each Service performs its own authority decision before invoking its capability-owned query trait; the controller fails closed and does not let one projection's success authorize another. Event-region reads remain a separate `central-event::app.seek_events` call governed by §4.7.6. No capability Service or query adapter imports or directly reads another capability's contract or tables.

| State | Parent Service | query.rs | Rendering | PRG | Action | Polling/backoff | Durable source | Owning capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| normal | `central-task::app` → `GetTaskDetail`; `central-artifact::app` → `ListArtifactSummaries`; `central-authorization::app` → `ListApprovals` (independent queries) | `TaskDetailRequest` → `TaskDetailProjection`; `ArtifactSummaryRequest` → `ArtifactSummaryProjection`; `ApprovalSummaryRequest` → `ApprovalSummaryProjection` | Current durable state, Run/step summary, bounded Artifact/Approval summaries | N/A | Cancel/retry/rerun/resume actions (available per lifecycle rules) | N/A | Three capability-owned query projections composed only by the controller | `central-task` |
| loading | `central-task::app` → `GetTaskDetail` (query) | `TaskDetailRequest` → `TaskDetailProjection` | Skeleton/spinner state; `aria-live="polite"` | N/A — read-only GET | N/A — initial navigation | N/A — initial server render is synchronous; later Event polling uses the Event-region schedule | `central-task` query projection | `central-task` |
| empty | N/A — detail resolves to a Task or safe 404 | N/A — no empty projection | N/A — no empty-state rendering | N/A — read-only GET | N/A — no action | N/A — no polling | N/A — no durable empty state | `central-task` |
| pending | `central-task::app` → `GetTaskDetail`; `central-authorization::app` → `ListApprovals` (independent queries) | `TaskDetailRequest` → `TaskDetailProjection`; `ApprovalSummaryRequest` → `ApprovalSummaryProjection` | Retry-delay countdown, approval/external-input wait, reconciliation progress; Event region polls independently | N/A | Approve/deny (when applicable); retry (when eligible) | Event-region `SeekEvents` cursor poll: 1 s default, 10 s cap + jitter | Capability-owned Task/Run and Approval projections; Event state via §4.7.6 | `central-task` |
| terminal | `central-task::app` → `GetTaskDetail` (query) | `TaskDetailRequest` → `TaskDetailProjection` | Completed/failed/cancelled display; no further mutation actions | N/A | N/A (no mutations) | N/A (polling stops) | Terminal Task/Run/Step durable state | `central-task` |
| conflict | `central-task::app` → `CancelTask` / `RetryTask` / `ResumeTask` / `RerunTask` (commands) | N/A (mutation result redirects to detail) | Stale-version conflict; detail re-renders with refreshed state and bounded reason | `303` → `GET /app/tasks/:task_id` (refreshed) | N/A (detail shows fresh state) | N/A | Command receipt + version CAS (PostgreSQL) | `central-task` |
| denied | `central-task::app` → `GetTaskDetail` (query) | `TaskDetailRequest` → `TaskDetailProjection` | Denied-authority display; cross-Workspace request returns safe not-found | N/A | N/A | N/A | Authorization capability decision | `central-task` |
| unavailable | `central-task::app` → `GetTaskDetail` (query) | `TaskDetailRequest` → `TaskDetailProjection` | Safe not-found or `503` with bounded `Retry-After`; no internal state leak | N/A | Retry after backoff (503 cases) | Retry per `Retry-After` | `central-task` query adapter observation | `central-task` |
| restart/reconciliation | `central-task::app` → `GetTaskDetail` (query) | `TaskDetailRequest` → `TaskDetailProjection` | Post-restart recovered detail; reconciliation-banner when applicable | N/A | Resume/retry when eligible per reconciled state | Cursor poll from last durable checkpoint | Durable Task/Run/Step/Checkpoint state + reconciliation cursors | `central-task` |
| validation | N/A — detail GET has no user mutation input | N/A — no validation projection | N/A — mutation validation belongs to cancel/retry/rerun/resume and is rendered inline after redirect | N/A — read-only GET | N/A — no action | N/A — no polling | N/A — no durable validation state | `central-task` |

---

#### 4.7.4 Cancel/retry/rerun/resume (`POST /app/tasks/:task_id/{cancel,retry,rerun,resume}`)

| State | Parent Service | query.rs | Rendering | PRG | Action | Polling/backoff | Durable source | Owning capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| normal | `central-task::app` → `CancelTask` / `RetryTask` / `RerunTask` / `ResumeTask` (commands) | N/A | Accepted outcome; redirects to refreshed detail | `303` → `GET /app/tasks/:task_id` | N/A (redirect) | N/A | Durable command receipt + committed state transition | `central-task` |
| loading | N/A — form submit is synchronous | N/A — command path | N/A — disable the submitted control and render loading only on the parent detail surface | N/A — response not yet committed | N/A — await the same submission | N/A — no background poll before response | N/A — no durable loading state | `central-task` |
| empty | N/A — mutation-only route | N/A — command path | N/A — no empty-state rendering | N/A — mutation route | N/A — no action | N/A — no polling | N/A — no durable empty state | `central-task` |
| pending | `central-task::app` → `GetTaskDetail` (query after redirect) | `TaskDetailRequest` → `TaskDetailProjection` | Pending transition renders on the parent detail page | `303` → `GET /app/tasks/:task_id` | Refresh or permitted follow-up action | Event-region polling schedule | Durable Task state + command receipt | `central-task` |
| terminal | `central-task::app` → `GetTaskDetail` (query after redirect) | `TaskDetailRequest` → `TaskDetailProjection` | Terminal result renders on the parent detail page | `303` → `GET /app/tasks/:task_id` | Only actions permitted by terminal state | N/A — terminal state stops transition polling | Durable terminal Task state | `central-task` |
| conflict | `central-task::app` → `CancelTask` / `RetryTask` / `RerunTask` / `ResumeTask` (commands) | N/A | Stale-version conflict; bounded reason rendered; redirects to refreshed detail showing new state | `303` → `GET /app/tasks/:task_id` | N/A (detail shows fresh state) | N/A | Command receipt duplicate or version CAS mismatch (PostgreSQL) | `central-task` |
| denied | `central-task::app` → `CancelTask` / `RetryTask` / `RerunTask` / `ResumeTask` (commands) | N/A | Denied-authority display; no authority leak | `303` → `GET /app/tasks/:task_id` (with denied reason code) | N/A | N/A | Authorization capability decision | `central-task` |
| unavailable | `central-task::app` → `CancelTask` / `RetryTask` / `RerunTask` / `ResumeTask` (commands) | N/A | Retryable dependency failure re-renders the parent detail action region with a safe bounded message and `Retry-After` | `200` re-render; no redirect because no mutation committed | Retry the same action after backoff | Retry per `Retry-After` | Adapter observation; no mutation committed | `central-task` |
| restart/reconciliation | `central-task::app` → `CancelTask` / `RetryTask` / `RerunTask` / `ResumeTask` (commands) | N/A | Post-restart: action re-evaluated from fresh durable state per §4.3 restart barrier; redirects to detail | `303` → `GET /app/tasks/:task_id` | N/A (fresh evaluation) | N/A | Durable Task state + receipt idempotency (PostgreSQL) | `central-task` |
| validation | `central-task::app` → `CancelTask` / `RetryTask` / `RerunTask` / `ResumeTask` (commands) | N/A | Domain rejection (invalid lifecycle action); bounded reason rendered on detail; no mutation | `303` → `GET /app/tasks/:task_id` (with reason code) | N/A | N/A | Domain rejection (no mutation) | `central-task` |

---

#### 4.7.5 Approval resolution (`POST /app/approvals/:approval_id/resolve`)

| State | Parent Service | query.rs | Rendering | PRG | Action | Polling/backoff | Durable source | Owning capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| normal | `central-authorization::app` → `ResolveApproval` (command) | N/A | Accepted outcome (allow/deny); redirects to parent Task detail or safe confirmation page | `303` → `GET /app/tasks/:task_id` (or confirmation page) | N/A (redirect) | N/A | Durable Approval recording + committed decision | `central-authorization` |
| loading | N/A — form submit is synchronous | N/A — command path | Disable the submitted control and render loading on the parent Task detail surface | N/A — response not yet committed | Await the same submission | N/A — no background poll before response | N/A — no durable loading state | `central-authorization` |
| empty | N/A — mutation-only route | N/A — command path | N/A — no empty-state rendering | N/A — mutation route | N/A — no action | N/A — no polling | N/A — no durable empty state | `central-authorization` |
| pending | `central-authorization::app` → `ListApprovals` (query after redirect) | `ApprovalSummaryRequest` → `ApprovalSummaryProjection` | Pending Approval remains on the parent detail surface until resolved | `303` → `GET /app/tasks/:task_id` when a prior identical receipt is still settling | Refresh or wait | Event-region polling schedule | Durable Approval state + command receipt | `central-authorization` |
| terminal | `central-authorization::app` → `ResolveApproval` (command) | N/A | Allow/deny decision confirmed; safe result displayed with bounded reason | `303` → `GET /app/tasks/:task_id` | N/A (no further action) | N/A | Terminal Approval/effective-grant state | `central-authorization` |
| conflict | `central-authorization::app` → `ResolveApproval` (command) | N/A | Expired/superseded request or binding conflict; bounded reason; redirect to refreshed detail | `303` → `GET /app/tasks/:task_id` | N/A | N/A | Versioned Approval request + receipt (PostgreSQL) | `central-authorization` |
| denied | `central-authorization::app` → `ResolveApproval` (command) | N/A | Denied-authority display; capability disclosure safe | `303` → `GET /app/tasks/:task_id` (with denied reason code) | N/A | N/A | Authorization capability decision | `central-authorization` |
| unavailable | `central-authorization::app` → `ResolveApproval` (command) | N/A | Approval action region re-renders with a safe bounded `503` message and `Retry-After`; no capability detail leaks | `200` re-render; no redirect because no decision committed | Retry the same resolution after backoff | Retry per `Retry-After` | Adapter observation; no decision committed | `central-authorization` |
| restart/reconciliation | `central-authorization::app` → `ResolveApproval` (command) | N/A | Post-restart: re-evaluated from fresh durable state; redirect to detail | `303` → `GET /app/tasks/:task_id` | N/A (fresh evaluation) | N/A | Durable Approval state + receipt idempotency (PostgreSQL) | `central-authorization` |
| validation | `central-authorization::app` → `ResolveApproval` (command) | N/A | Domain rejection (invalid decision); bounded reason rendered; no mutation | `303` → `GET /app/tasks/:task_id` (with reason code) | N/A | N/A | Domain rejection (no mutation) | `central-authorization` |

---

#### 4.7.6 Event/log polling

| State | Parent Service | query.rs | Rendering | PRG | Action | Polling/backoff | Durable source | Owning capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| normal | `central-event::app` → `SeekEvents` (query) | `EventSeekRequest` → `EventSeekProjection` | Bounded first page of Events within Task display projection; typed seek cursor for next page | N/A | Poll for new Events | Cursor poll: 1 s default, 10 s cap + jitter | Workspace Event feed via `(workspace_id, event_sequence)` index | `central-event` |
| loading | `central-event::app` → `SeekEvents` (query) | `EventSeekRequest` → `EventSeekProjection` | Initial-load indicator within event region | N/A — read-only region | N/A — initial load | N/A — first request is synchronous; after response use the normal cursor schedule | `central-event` query projection | `central-event` |
| empty | `central-event::app` → `SeekEvents` (query) | `EventSeekRequest` → `EventSeekProjection` | Empty-state message; polling continues awaiting first Event | N/A | Poll for first Event | Cursor poll (same schedule) | Event feed (zero results from cursor) | `central-event` |
| pending | `central-event::app` → `SeekEvents` (query) | `EventSeekRequest` → `EventSeekProjection` | New Events rendered since last cursor; polling continues | N/A | Continue polling | Cursor poll; `NextCursor` advances | Event feed with `event_sequence > cursor` | `central-event` |
| terminal | `central-event::app` → `SeekEvents` (query) | `EventSeekRequest` → `EventSeekProjection` | Terminal stop message; polling stops (e.g., Task completed); no further Events expected | N/A | N/A (polling stops) | N/A (stop when parent Task is terminal) | Terminal Task state + final Event cursor | `central-event` |
| conflict | N/A — seek read has no versioned mutation | N/A — no conflict projection | N/A — malformed/stale cursors map to validation or safe restart/reconciliation, never conflict | N/A — read-only region | N/A — no conflict action | N/A — no conflict retry schedule | N/A — no durable conflict state | `central-event` |
| denied | `central-event::app` → `SeekEvents` (query) | `EventSeekRequest` → `EventSeekProjection` | Denied-authority or cross-Workspace display; no Event or Workspace leak | N/A | N/A | N/A | Authorization capability decision | `central-event` |
| unavailable | `central-event::app` → `SeekEvents` (query) | `EventSeekRequest` → `EventSeekProjection` | Temporary failure with backoff hint; `Retry-After` rendered | N/A | Retry poll after backoff | Retry per `Retry-After` | `central-event` query adapter observation | `central-event` |
| restart/reconciliation | `central-event::app` → `SeekEvents` (query) | `EventSeekRequest` → `EventSeekProjection` | Cursor recovery from last durable cursor; poll resumes from that point | N/A | Resume polling from recovered cursor | Cursor poll resumed from durable checkpoint cursor | Last committed poll cursor (client-side durable storage) or Event feed from Task restart cursor | `central-event` |
| validation | `central-event::app` → `SeekEvents` | `EventSeekRequest` | Invalid cursor/page size returns a bounded validation result and resets only through a fresh authorized initial read | N/A — read-only region | Start a fresh authorized Event read | Normal cursor schedule after successful reset | Durable Event feed; rejected input is not persisted | `central-event` |

---

#### 4.7.7 Artifact region/download

| State | Parent Service | query.rs | Rendering | PRG | Action | Polling/backoff | Durable source | Owning capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| normal | `central-artifact::app` → `ListArtifactSummaries` (query) | `ArtifactSummaryRequest` → `ArtifactSummaryProjection` | Ready Artifact summary with safe download action; Artifact identity, media type, size displayed | N/A | Download (one-shot `AuthorizedDownload` via `/api/v1/artifacts/:id/content`) | N/A | `central-artifact` query projection (PostgreSQL) + ready body (object store) | `central-artifact` |
| loading | `central-artifact::app` → `ListArtifactSummaries` (query) | `ArtifactSummaryRequest` → `ArtifactSummaryProjection` | Loading indicator within artifact region | N/A — read-only region | N/A — initial load | N/A — first request is synchronous; pending Artifacts use the normal cursor schedule | `central-artifact` query projection | `central-artifact` |
| empty | `central-artifact::app` → `ListArtifactSummaries` (query) | `ArtifactSummaryRequest` → `ArtifactSummaryProjection` | No-Artifact message; no empty-table visual | N/A | N/A | N/A | `central-artifact` query projection (zero results) | `central-artifact` |
| pending | `central-artifact::app` → `ListArtifactSummaries` (query) | `ArtifactSummaryRequest` → `ArtifactSummaryProjection` | Staging/verifying progress indicators; download disabled | N/A | Poll for readiness | Cursor poll: 1 s default, 10 s cap + jitter | `central-artifact` query projection + Artifact lifecycle state | `central-artifact` |
| terminal | `central-artifact::app` → `ListArtifactSummaries` (query) | `ArtifactSummaryRequest` → `ArtifactSummaryProjection` | Quarantined/delete-pending indicators; download unavailable, safe reason displayed | N/A | N/A (no download) | N/A (terminal Artifact state) | Terminal Artifact lifecycle + quarantine/delete-intent state | `central-artifact` |
| conflict | `central-artifact::app` → `PrepareAuthorizedDownload` (command returning `AuthorizedDownload`); then one-shot `AuthorizedDownload::start` | N/A — command/capability path | Final revalidation conflict disables download and refreshes the Artifact region from a new authorized summary read | N/A — content headers were not committed | Refresh Artifact summaries | Normal pending-Artifact schedule after refresh | Current durable Artifact lifecycle and content generation | `central-artifact` |
| denied | `central-artifact::app` → `ListArtifactSummaries` (query) | `ArtifactSummaryRequest` → `ArtifactSummaryProjection` | Download unavailable/denied display; safe reason (sensitivity, cross-Workspace) | N/A | N/A | N/A | Authorization capability + Artifact sensitivity/Workspace ownership | `central-artifact` |
| unavailable | `central-artifact::app` → `ListArtifactSummaries` (query) | `ArtifactSummaryRequest` → `ArtifactSummaryProjection` | Safe `503` with bounded `Retry-After` (admission full or store unavailable) | N/A | Retry after backoff | Retry per `Retry-After` | Artifact admission gate saturation or store health (adapter observation) | `central-artifact` |
| restart/reconciliation | `central-artifact::app` → `ListArtifactSummaries` (query) | `ArtifactSummaryRequest` → `ArtifactSummaryProjection` | Post-restart reconciled Artifact summaries; quarantine/download status updated from durable state | N/A | Download when ready | Cursor poll from durable checkpoint | Durable Artifact lifecycle + reconciliation cursors | `central-artifact` |
| validation | `central-artifact::app` → `ListArtifactSummaries` (query) or `PrepareAuthorizedDownload` (command) | Summary path: `ArtifactSummaryRequest` → `ArtifactSummaryProjection`; download path: N/A — command | Invalid Artifact identity/cursor returns bounded validation without existence disclosure | N/A — read-only or pre-header rejection | Return to the authorized parent Task detail | N/A until a valid authorized request succeeds | Rejected input is not persisted | `central-artifact` |

---

### 4.8 Accessibility baseline

Server-rendered HTML meets the Phase 1 accessibility baseline (WCAG keyboard accessibility, semantic landmarks, visible focus), carried forward unchanged:

- Declared language and unique title.
- Semantic header/nav/main/footer landmarks and ordered headings.
- Skip link.
- Programmatically labelled controls. Keyboard-operable actions with visible focus.
- Field-associated errors plus a focused error summary.
- Table headers/captions where tabular data is used.
- Status and sensitivity communicated by text/icon as well as color.
- `aria-live="polite"`/`role="status"` only for bounded polling or submission updates without stealing focus.
- Reduced-motion preference is respected.
- Essential behavior never depends on hover, drag, color, animation, or JavaScript timing.

## 5. CLI controller/operator contract

### 5.1 Command matrix

```text
central serve

central migrate verify
central migrate status
central migrate up
central migrate resume --operation=<id>

central backup create
central backup verify
central backup status
central backup resume --operation=<id>

central restore verify
central restore apply --operation=<verified-id>
central restore status
central restore resume --operation=<id>
```

**Accepted ADR 0011.** The following local operator and backup-extension verbs are active under the accepted local topology:

```text
central local init
central local status
central local prepare
central local up
central local down
central local doctor
central local trust install
central local security update
central local browser status
central local browser restart
central local runtime status
central local runtime restart
central local maintenance wipe
central local maintenance status

central backup list
central backup export --operation=<id>
central backup import --manifest=<path>
central backup delete --operation=<id>
central backup prune
central backup create --security-rescue
central backup security-rescue cleanup --operation=<id>
```

**Phase 2 / harness verbs (ADR 0035/0036 + Phase 2 specs):**

```text
central run submit --workspace <id> --title <title> --workers <n> --run-key <fresh-key-per-run>
central node decide
central checkpoint <subcommands>
central artifact read
```

Mutating migration/backup/restore verbs dispatch through the dedicated operator binaries (`central-migrate`, `central-backup`, `central-restore`) and their launcher daemons under the dedicated OS identities of §3.2; the `central` binary exposes the shared operator surface for read-only/status verbs and defers privileged mutations to the locked helper/launcher boundaries. These verbs are governed by the ADR 0009–0019 topology, locked-identity, PAM/helper, and advisory-authority rules. Deferred commands return safe exit `5` `UNSUPPORTED_IN_THIS_SLICE` with no mutation until their owning R-slice is implemented.

### 5.2 Exit classes

| Class | Meaning |
| --- | --- |
| 0 | Success (serve: intentional stop after durable settlement evidence) |
| 2 | Invalid invocation, configuration, or operation selection |
| 3 | Required dependency unavailable during startup |
| 4 | Startup shared-lock, pool, or bounded-preflight timeout |
| 5 | Dirty/incompatible schema; checksum mismatch; missing/corrupt restore barrier; unsafe precondition; unsupported-in-this-slice |
| 6 | Interrupted/failed/indeterminate mutation requiring exact-operation resume |
| 7 | Denied or insufficient authority |

### 5.3 Authority and behavior per verb

| Verb | Authority | Mutating | Shared/exclusive lock | Resume identity | Output schema |
| --- | --- | --- | --- | --- | --- |
| `migrate verify` | Local operator | Non-mutating | Shared (target read) | N/A | `central.migration-result/v1` |
| `migrate status` | Local operator | Non-mutating | Shared (target read) | N/A | `central.migration-result/v1` |
| `migrate up` | Local operator + migration-safety input | Mutating | Exclusive (common + migration-specific) | New operation ID allocated on first run | `central.migration-result/v1` |
| `migrate resume` | Local operator + exact operation ID | Mutating | Exclusive (common + migration-specific) | `--operation=<id>` must match extant resumable operation | `central.migration-result/v1` |
| `backup create` | Local operator | Mutating (creates manifest) | Exclusive (common target) | New operation ID; becomes terminal on exclusive-lock loss | `central.operator-result/v1` |
| `backup verify` | Local operator | Non-mutating (wrt target) | Shared (target read) | N/A (may allocate operator evidence) | `central.operator-result/v1` |
| `backup status` | Local operator | Non-mutating | None | `--operation=<id>` | `central.operator-result/v1` |
| `backup resume` | Local operator + exact operation ID | Pre-point: mutating; post-point: terminal | Depends on phase | `--operation=<id>` | `central.operator-result/v1` |
| `restore verify` | Local operator | Non-mutating (wrt target) | Shared (target read) | Issues expiring ticket bound to operation nonce | `central.operator-result/v1` |
| `restore apply` | Local operator + verified ticket + confirmation | Mutating (destructive) | Exclusive (common target + operator-state) | `--operation=<verified-id>` from verify | `central.operator-result/v1` |
| `restore status` | Local operator | Non-mutating | None | `--operation=<id>` | `central.operator-result/v1` |
| `restore resume` | Local operator + exact operation nonce + exclusive ownership | Mutating (continues extant phase) | Exclusive | `--operation=<id>` from extant operation | `central.operator-result/v1` |

**Accepted ADR 0011.** The following authority rows apply under the accepted local topology:

| Verb | Authority | Mutating | Shared/exclusive lock | Resume identity | Output schema |
| --- | --- | --- | --- | --- | --- |
| `local init` | Local operator (fresh PAM + helper) | Mutating (creates instance identity, directories, initial protected state) | N/A (no PostgreSQL dependency) | N/A | `central.local-result/v1` |
| `local status` | Local operator | Non-mutating | None | N/A | `central.local-result/v1` |
| `local prepare` | Local operator (fresh PAM + helper) | Mutating (acquires dependency images, builds MinIO, creates root-owned infrastructure) | N/A (no PostgreSQL dependency) | N/A | `central.local-result/v1` |
| `local up` | Local operator (fresh PAM + helper for infrastructure; helper-owned TTY confirmation) | Mutating (starts dependencies, provisions if uninitialized, starts serve) | Exclusive (common target during provision/startup) | N/A (fresh PAM per invocation) | `central.local-result/v1` |
| `local down` | Local operator (helper-owned TTY confirmation) | Mutating (stops serve, stops dependencies) | N/A | N/A | `central.local-result/v1` |
| `local doctor` | Local operator | Non-mutating | Shared (target read, when applicable) | N/A | `central.local-result/v1` |
| `local trust install` | Local operator (fresh PAM + helper + physical-seat TTY) | Mutating (installs CA certificate into system and browser trust stores) | N/A (no PostgreSQL dependency) | N/A | `central.local-result/v1` |
| `local security update` | Local operator (fresh PAM + helper + physical-seat TTY) | Mutating (fetches and validates signed advisory bundle) | Lifecycle-exclusive | N/A | `central.local-result/v1` |
| `local browser status` | Local operator | Non-mutating | N/A | N/A | `central.local-result/v1` |
| `local browser restart` | Local operator (helper-owned TTY confirmation) | Mutating (restarts managed browser profile) | N/A | N/A | `central.local-result/v1` |
| `local runtime status` | Local operator | Non-mutating | N/A | N/A | `central.local-result/v1` |
| `local runtime restart` | Local operator (helper-owned TTY confirmation) | Mutating (restarts central-runtime) | N/A | N/A | `central.local-result/v1` |
| `local maintenance wipe` | Local operator (fresh PAM + helper + physical-seat TTY confirmation of `WIPE <full-instance-id> <full-target-id> POSTGRES+MINIO`) | Mutating (destructive: AppArmor-locked root wiping of PostgreSQL and MinIO data; credential reseed after wipe) | Exclusive (helper-enforced one-root-at-a-time) | One-use operation-bound confirmation | `central.local-result/v1` |
| `local maintenance status` | Local operator | Non-mutating | None | N/A | `central.local-result/v1` |
| `backup list` | Local operator | Non-mutating | None | N/A | `central.operator-result/v1` |
| `backup export` | Local operator (fresh PAM + helper-owned physical-seat TTY) | Non-mutating (wrt target; produces broker-signed `bx1` integrity token on TTY only) | None (reads sealed manifests) | `--operation=<id>` | `central.operator-result/v1` |
| `backup import` | Local operator (fresh PAM + helper-owned physical-seat TTY) | Non-mutating (wrt target; places manifest in local repository) | None | `--manifest=<path>` | `central.operator-result/v1` |
| `backup delete` | Local operator (fresh PAM + helper-owned physical-seat TTY) | Mutating (removes sealed manifest and associated inventory chunks) | None (target-independent) | `--operation=<id>` | `central.operator-result/v1` |
| `backup prune` | Local operator (fresh PAM + helper-owned physical-seat TTY) | Mutating (removes unreferenced manifests, chunks, and candidates per retention policy) | Exclusive (operator-state) | N/A | `central.operator-result/v1` |
| `backup create --security-rescue` | Local operator (fresh PAM + helper + physical-seat TTY) | Mutating (creates one marked current-epoch seal from cold copies only; conservative admission) | Exclusive (common target) | New operation ID; terminal on exclusive-lock loss | `central.operator-result/v1` |
| `backup security-rescue cleanup` | Local operator + exact operation ID | Mutating (settlement-only cleanup of authenticated rescue operation with bound scratch root) | Exclusive (operator-state) | `--operation=<id>` | `central.operator-result/v1` |

Every local verb and backup-extension verb that mutates infrastructure, dependencies, protected state, or trust stores requires fresh PAM and helper-owned physical-seat TTY confirmation; redirected input, `--yes`, a prior-operation ID as confirmation, or a target copied from another result is invalid.

### 5.4 Output contracts

- `--output=json` emits schema `central.migration-result/v1`, `central.operator-result/v1`, or `central.local-result/v1` with command, safe operation ID, phase, outcome class, retryability, `resume_required`, bounded progress, and safe reason.
- Never emit: credentials, connection strings, SQL text/parameters, paths, backend locators, object keys, raw checksums, ticket/nonce material, hidden nonces.
- Human output is bounded and redacted.
- `resume_required` is set when safe continuation exists after an interrupted/indeterminate outcome (class 6).
- Generic `Force` and `Drop` are rejected.

**Restore-confirmation rule (upstream Proposed ADR 0009 amendment, retained):** Noninteractive restore-apply confirmation through `--confirm-operation`, `--confirm-target`, `--yes`, or `--output=json` on apply is prohibited. Under the same-operator-UID threat model those public values are replayable and cannot replace fresh PAM plus helper-owned physical-seat TTY confirmation. Restore apply and restore resume require: fresh PAM ceremony, helper-owned `/dev/tty` confirmation, exact operation identity from `restore verify`, the verified target identity, and the consumed single-use ticket nonce. `--confirm-operation`, `--confirm-target`, `--yes`, redirected input, a backup ID as confirmation, an expired/replayed verify operation, or a target copied from another result is invalid. Every durability semantic (verify, ticket, `--operation`, accepted point, target locks, result schema, status, resume, epoch markers) remains unchanged.

### 5.5 CLI-to-Service mapping

Every CLI controller maps to its parent Service and inward port/query contracts:

- Migration commands → `central-backup` migration coordinator → `MigrationInspector` port / `MigrationRunner` (in `central-adapter-postgres`)
- Backup commands → `central-backup` backup coordinator → `central-backup` port traits
- Restore commands → `central-backup` restore coordinator → `central-backup` port traits
- `run submit` → `central-runsubmit` submission service → `central-task`/`central-workflow` contracts
- `node decide` → `central-retry` decision service
- `checkpoint *` → `central-checkpoint` service
- `artifact read` → `central-artifact` read service
- Local init/status/prepare/up/down/doctor/trust/security/browser/runtime/maintenance verbs → `central-infra` service → `central-adapter-linux` helper protocol. The local controller mediates all infrastructure authority through the root-owned helper protocol and never calls Docker, Compose, `pg_dump`/`pg_restore`, or the S3 adapter directly.
- Backup list/export/import/delete/prune → `central-backup` backup coordinator → operator-state port traits extended with local repository/manifest management.
- Backup create --security-rescue → `central-backup` backup coordinator with cold-copy admission and scratch-root isolation.
- Backup security-rescue cleanup → `central-backup` backup coordinator with settlement-only cleanup.
- No CLI verb fabricates Workspace/session authority for target/operator modes; no local or backup-extension verb invokes `central serve` directly, constructs migration credentials, or bypasses the PAM/helper protocol for any mutating infrastructure operation.

## 6. Service contract

### 6.1 Coordinator rules

1. Methods accept typed commands/queries and explicit authority, deadline, and operation identity; cancellation arrives via future drop.
2. Cross-capability workflows use an acyclic higher coordinator. `central-harness` (harness session boundary, ADR 0035) layered on `central-execution` (lease fencing, recovery epochs, retry, outbox) is the approved Phase 1 sequential coordinator pair; `central-runsubmit` orchestrates Phase 2 run submission.
3. No external effect occurs in a PostgreSQL transaction.
4. Prepare, invoke, settle, ambiguity, cancellation, retry, and recovery state remain explicit.
5. Service code does not open transactions, pass a generic Unit of Work, inspect `axum` request/extension state, or select concrete adapters.
6. Supervised components return classified failures and use kernel-owned fail-fast lifecycle/shutdown behavior.

### 6.2 Transaction ownership

- **Domain-approved change-set commits:** load typed durable snapshot → domain evaluates command → produce approved change set → adapter commits atomically with expected versions and constraints → adapter returns committed facts or typed conflict.
- **Atomic conditional ports:** used for database-time and fencing operations (lease, outbox claim, `SKIP LOCKED` ready-queue claims, time-driven session expiry, retry eligibility, cleanup eligibility). The capability owns predicate and outcomes; the adapter realizes them in one statement/bounded transaction.
- No public Unit of Work. Transaction plumbing (`sqlx::Transaction`, `PgConnection`, `PgPool` acquisition) is private to `central-adapter-postgres` and is never held open across an external network, process, or object-storage call.
- Safe retry of proven-rolled-back commit is internal to `central-adapter-postgres` and retries the same approved change set or conditional request only.

### 6.3 External-effect protocol (sequential coordinator)

```text
prepare attempt durably
→ construct immutable prepared invocation
→ invoke registered adapter outside transaction
→ sanitize and classify outcome
→ persist known success, known retryable failure, known terminal failure, cancellation, or ambiguity
```

- A prepared invocation contains attempt identity, exact registered adapter identity and revision, stable logical operation key, normalized invocation/manifest hash, bounded budgets, database-authoritative deadline, and safe correlation facts.
- Secret-aware adapters receive a sealed, non-serializable, non-transferable, one-shot `ProtectedUse` capability bound to Workspace, Task, Run, physical attempt, stable operation key, normalized input fingerprint, capability/scope/sensitivity, effective grant and policy version, exact adapter/revision, destination, purpose, SecretReference and safe version, and earliest durable-authority/fence deadline. In Rust this is a `!Clone`, `!Serialize` value consumed by `use_once(self, …)` — the type system, not runtime checks alone, enforces single consumption and non-transferability.
- `ProtectedUse::use_once` atomically rejects second/concurrent consumption; performs exact just-in-time revalidation; acquires authorization-use fence; resolves secret; invokes exact registered adapter callback once.
- Successful fence acquisition is the use linearization point against revocation, policy tightening, SecretReference revocation, or Task termination.
- Handoff deadline: earliest of 5 s default/10 s hard maximum, authority/grant expiry, prepared-attempt deadline, and stricter local deadline.
- The fence is released immediately after proven non-delivery or transport acceptance.
- After possible external delivery, cancellation cannot discard settlement. A kernel-owned bounded settlement (`settle` call under `tokio::time::timeout`) persists known or ambiguous outcome but cannot authorize a new external invocation.

### 6.4 Cross-capability crate DAG

```text
central-execution  → central-task          (task root domain types: cancel/resume/harness-run)
central-artifact   → central-execution     (ExecutionChangeSet completion-guard types only)
central-runsubmit  → central-task          (domain, app, port)
central-runsubmit  → central-workflow      (domain types)
central-workflow   → central-retry         (retry-policy domain types in node-spec validation)
central-runview    → central-eventjournal  (journal fold and lineage projection types)
```

- **`central-runsubmit` store access (upstream issue-122):** `central-runsubmit` is an orchestration-only submission service; it owns no new business rules and every task transition still passes through the `central-task` domain service. It declares narrow consumer-side store traits in its own `port.rs` — task commands (`TaskCommands`), a run-by-key reader (`RunByKeyReader`), and a workflow graph store (`GraphStore`) — and additionally consumes `central-task`'s aggregate-loader `port.rs` trait. `central-adapter-postgres` store types implement the store-facing traits (`RunByKeyReader`, `GraphStore`, task aggregate loader); `central-task::app` satisfies `TaskCommands`; `central-kernel` wires the implementations at composition over the serve pool or the operator-supplied DSN (issue-122 D7); `bins/central` invokes that composition function rather than wiring adapters itself (§3.3); the sole bin-side adapter import remains `central-adapter-linux` in launcher and protected-execution-mode binaries (§3.2). `central-runsubmit` never names `central-adapter-postgres`: no service crate imports an adapter crate, and that rule admits no exceptions.
- **`central-harness` coordinator isolation:** the sequential coordinator drives `central-execution`, `central-authorization`, `central-checkpoint`, `central-artifact`, and `central-event` exclusively through its own `port.rs` traits; it holds no capability-import edge. Coordination is port-mediated, not import-mediated.
- **Claimability surface:** `central-execution::query` owns the claimability-decoration read contract (upstream `task/app/query` claimability decorator) so that `central-task` never imports `central-execution`. See §2.2 cyclic-edge rule.
- Service-to-service edges never cycle. Lower capabilities (`task`, `authorization`, `checkpoint`, `artifact`, `event`, `workspace`, `session`, `workflow`, `eventjournal`, `scheduler`, `retry`, `backup`, `infra`) never import `central-harness`, `central-execution`, `central-runsubmit`, transport, or `central-kernel`.

## 7. Usecase contract

### 7.1 Domain decision ownership (`domain.rs`)

Every capability `domain.rs` owns:

- Invariants and rejected-command no-op rules.
- Change-set construction from approved command evaluation.
- Event intent ownership (type, schema/payload meaning, actor, aggregate identity/version, correlation, causation).
- Version expectations for conditional updates.
- Domain snapshots (decision snapshots for commands; recovery snapshots for resume/retry/reconciliation).
- Completion guards (e.g., required-Artifact readiness as a Task/Run completion guard).
- Safe domain failures as typed rejections.
- Pure synchronous Rust only: no `async fn`, no I/O traits, no `tokio`/`tokio-util`/`std::net`/`std::fs` calls; `unsafe_code` forbidden.

### 7.2 Change-set construction

```text
load typed durable snapshot (adapter-provided)
→ domain evaluates command
→ domain produces either:
   - an approved change set (aggregate identities, expected versions, approved next state,
     bounded reasons, allowlisted Event intents, correlation/causation, command-receipt binding)
   - a typed domain rejection
→ adapter commits change set atomically (CAS, constraints, locks, database timestamps,
   Event sequence allocation, outbox references, receipt persistence)
→ adapter returns committed database facts or typed conflict/failure
```

A changed snapshot returns conflict; application code does not blind-retry a business decision against newly changed state.

### 7.3 Atomic conditional ports

Used for database-time and fencing operations where load/decide/commit is unsafe. Capability owns predicate and outcomes; adapter realizes with database-time/fencing conditions in one statement or bounded transaction.

Examples: lease acquire/renew/settle, outbox claim/settle, `SKIP LOCKED` ready-queue claims, time-driven session expiry, retry eligibility, cleanup eligibility.

Pattern selection: change-set commit for versioned domain snapshots; atomic conditional port when database time, fencing token, or claim exclusivity must be evaluated at the same linearization point as mutation. Explicit session revocation is a change-set command; time-driven session expiry is an atomic conditional operation.

### 7.4 `query.rs` read contracts

Every capability's declaration-only `query.rs` module owns:

- Consumer-side read traits (only the parent Service invokes them after authorization).
- Bounded typed request structs.
- Safe immutable projection types.
- Typed `SeekCursor` structs (no offset, no generic filter maps).

`query.rs` exports are dedicated immutable bounded read-model declarations. They may contain only: explicitly reviewed opaque non-authority IDs, safe display enums/value objects, bounded scalar metadata, typed seek cursors, and sanitized result facts.

They must not embed, alias, or expose: domain aggregates, decision or recovery snapshots, change sets, application commands, `port.rs` traits, persistence/object references, raw failures, grants, `ProtectedUse`, `AuthorizedDownload`, fencing tokens, session/bootstrap/CSRF material, or restore tickets/nonces.

### 7.5 Representative `query.rs` contracts

The table below records the representative Phase 1 `query.rs` contracts covering the seven HTML surface families and CLI operator operations, carried over from the upstream Gate 7 contract with module names remapped. Remaining contracts (Phase 2 run/DAG/fleet projections) will be authored as their owning capabilities are implemented, citing the owning R-slice.

| # | Contract | Capability | Parent Service caller | Authority decision | Request type | Projection type | Scoping | Seek cursor | Max page | SQL round trips | Rows examined/returned | Stable continuation | Safe failure | Owning capability |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `BootstrapStatusRead` | `central-session::query` | `central-session::app` → `ValidateSession` | None (no authenticated session; fixed bootstrap route) | `BootstrapStatusRequest{ workspace_id: Option<WorkspaceId> }` | `BootstrapStatusProjection{ has_active_session, throttle_remaining, retry_after }` | Workspace (when bound; None for pre-Workspace bootstrap page) | N/A (singleton status) | N/A | 1 | ≤ 5 rows examined; ≤ 1 row returned | N/A (singleton) | Fixed non-enumerating response; no session/Workspace enum | `central-session` |
| 2 | `TaskListRead` | `central-task::query` | `central-task::app` → `ListTasks` | Authenticated session + Workspace owner (capability eval by Service before query invocation) | `TaskListRequest{ workspace_id, cursor: Option<TaskListCursor>, page_size }` | `TaskListProjection{ tasks, next_cursor }` | Workspace only | `TaskListCursor{ task_id, status, updated_at }` — typed; no offset | Default 100; hard 250 | ≤ 2 | ≤ 250 rows examined; ≤ 250 rows returned (per page) | `next_cursor` forward-only; empty cursor = end | `NotFound` for missing Workspace; `Denied` for cross-Workspace; `Unavailable` for pool saturation | `central-task` |
| 3 | `TaskDetailRead` | `central-task::query` | `central-task::app` → `GetTaskDetail` | Authenticated session + Workspace owner | `TaskDetailRequest{ workspace_id, task_id, run_cursor, run_page_size }` | `TaskDetailProjection{ task, runs, next_run_cursor }` | Workspace + Task | `RunSeekCursor{ created_at, run_id }` for additional Runs | Runs default 10, hard 25 | ≤ 2 | ≤ 26 rows examined; ≤ 26 rows returned | `None` run_cursor loads the first Run page; `next_run_cursor` uses stable `(created_at, run_id)` descending seek and `None` means no additional Runs | `NotFound` (Task or Workspace); `Denied` (cross-Workspace) | `central-task` |
| 4 | `EventSeekRead` | `central-event::query` | `central-event::app` → `SeekEvents` | Authenticated session + Workspace owner | `EventSeekRequest{ workspace_id, cursor: Option<EventSeekCursor>, page_size }` | `EventSeekProjection{ events, next_cursor }` | Workspace only; optional Task filter | `EventSeekCursor{ event_sequence: i64 }` — typed; uses `(workspace_id, event_sequence)` index | Default 100; hard 250 | 1 | ≤ 250 rows examined; ≤ 250 rows returned | `next_cursor`; `None` = live head (continue polling); empty page with same cursor = no new Events | `Denied` for cross-Workspace; `Unavailable` for pool saturation | `central-event` |
| 5 | `ArtifactSummaryRead` | `central-artifact::query` | `central-artifact::app` → `ListArtifactSummaries` | Authenticated session + Workspace owner | `ArtifactSummaryRequest{ workspace_id, task_id, cursor, page_size }` | `ArtifactSummaryProjection{ artifacts, next_cursor }` | Workspace + Task | `ArtifactSummaryCursor{ artifact_id, updated_at }` — typed | Default 100; hard 250 | ≤ 2 | ≤ 250 rows examined; ≤ 250 rows returned | `next_cursor`; `None` = end of list | `NotFound` for missing Task; `Denied` for cross-Workspace; sensitive Artifacts omitted from summary | `central-artifact` |
| 6 | `ApprovalSummaryRead` | `central-authorization::query` | `central-authorization::app` → `ListApprovals` | Authenticated session + Workspace + capability disclosure | `ApprovalSummaryRequest{ workspace_id, task_id, approver }` | `ApprovalSummaryProjection{ approvals }` | Workspace + Task + Approver | N/A (bounded by Task; typically ≤ 10 pending approvals) | N/A (Task-scoped; no pagination required) | ≤ 2 | ≤ 20 rows examined; ≤ 10 rows returned | N/A | `Denied` for unauthorized approver; expired/superseded marked in projection | `central-authorization` |
| 7 | `MigrationStatusRead` | `central-backup::query` | `central-backup::app` → `InspectMigrationStatus` | Local operator (no Workspace/session authority) | `MigrationStatusRequest{ target_identity: OpaqueTargetId }` | `MigrationStatusProjection{ initialized, version, dirty, checksum_ok, resumable_operation }` | Target only (operator scope) | N/A (singleton status) | N/A | 1 | ≤ 20 rows examined; ≤ 5 rows returned | N/A | `Unavailable` when target unreachable; `Denied` when operator lacks authority; operator-result class 0/2/3/7 | `central-backup` |
| 8 | `BackupStatusRead` | `central-backup::query` | `central-backup::app` → `InspectBackupStatus` | Local operator (no Workspace/session authority) | `BackupStatusRequest{ operation_id: SafeOperationId }` | `BackupStatusProjection{ phase, progress, complete, resume_required }` | Operation only (operator scope) | N/A (singleton per operation) | N/A | 1 | ≤ 10 rows examined; ≤ 3 rows returned | N/A | `NotFound` for unknown operation; `Unavailable` when operator state unreachable; operator-result class 0/2/3/6/7 | `central-backup` |
| 9 | `RestoreStatusRead` | `central-backup::query` | `central-backup::app` → `InspectRestoreStatus` | Local operator (no Workspace/session authority) | `RestoreStatusRequest{ operation_id: SafeOperationId }` | `RestoreStatusProjection{ phase, epoch, progress, ready, resume_required }` | Operation only (operator scope) | N/A (singleton per operation) | N/A | 1 | ≤ 15 rows examined; ≤ 5 rows returned | N/A | `NotFound` for unknown operation; `Unavailable` when operator state unreachable; `Denied` when status-incompatible epoch; operator-result class 0/2/3/5/6/7 | `central-backup` |
| 10 | `SessionStatusRead` | `central-session::query` | `central-session::app` → `ValidateSession` | Authenticated session cookie (per-request validation) | `SessionStatusRequest{ session_id: SessionId }` | `SessionStatusProjection{ valid, workspace_id, expires_at, requires_bootstrap }` | Session only (read own session) | N/A (singleton) | N/A | 1 | ≤ 3 rows examined; ≤ 1 row returned | N/A | Fixed non-enumerating expired/invalid response; no Workspace enumeration | `central-session` |

All `query.rs` contracts use typed seek cursors. Offset and generic filter maps are prohibited. Every request type includes bounded `page_size` where pagination applies. The default is 100 and hard cap is 250 unless that contract's table row declares a smaller operation-specific default and hard cap; the row-level values are normative for that request. `TaskDetailRead.run_page_size`, for example, uses its declared 10/default and 25/hard bounds. Every Workspace-scoped adapter query repeats the Workspace ownership predicate on every relation, join, subquery, and cursor as defense in depth. N+1 behavior, readiness exact counts/full scans, authority-bearing exports, and direct transport injection of a query trait are prohibited.

Remaining `query.rs` contracts (e.g., run/DAG/fleet projections for `central-runview`, workflow graph reads, detailed capability-inventory queries, diagnostic projections) will be authored as their owning capabilities reach implementation, citing the owning R-slice.

### 7.6 Port ownership (`port.rs`)

Capability-owned `port.rs` modules own:

- Command-persistence traits (operation-oriented; not CRUD; not table mirrors; no `sqlx` types).
- Atomic conditional operation traits.
- External-effect invocation traits.
- Observation traits.
- Narrow cross-capability traits per approved DAG.

`port.rs` never imports `app.rs` internals, `query.rs`, transport, kernel, or adapters.

## 8. Infrastructure contract

### 8.1 `central-adapter-postgres`

- `sqlx` v0.8 (`postgres`, `runtime-tokio`, `tls-rustls-ring`, `macros`, `uuid`, `time`, `json`; `migrate` feature disabled). Every leaf query uses `sqlx::query!`/`sqlx::query_as!` checked against the canonical `central.*` schema and recorded in `.sqlx/` for offline builds (`SQLX_OFFLINE=true`); see [postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md).
- Adapter-internal row/parameter types remain beneath the adapter boundary and are mapped to capability-owned snapshots, change sets, conditional outcomes, and projections.
- Compound transaction orchestration is handwritten and explicit; `sqlx::Transaction` never escapes the adapter.
- Application objects live in a dedicated `central` schema. SQL is fully schema-qualified.
- Three database roles: `central_runtime`, `central_outbox`, `central_migration`. No fourth role.
- `central_runtime` includes cleanup operations. `central_runtime` and `central_outbox` cannot update/delete Events, tombstones, or immutable decision history.
- Migration execution and the database/schema replacement substep of confirmed offline restore apply may load `central_migration`; post-restore verification and quarantine use `central_runtime`.
- `central serve` profiles never load migration credentials.
- `READ COMMITTED` baseline. Expected-version conditional updates. Explicit row locks/atomic predicates only for linearization cases defined by the persistence contract.
- Global row-lock order defined for cross-aggregate transactions.
- Deadlock/serialization failure retry only when PostgreSQL proves rollback, no external effect occurred, and command identity/input unchanged.
- Connection loss during `COMMIT` returns indeterminate-commit outcome; resolved through durable receipt/reconciliation.
- Dynamic SQL string concatenation (`format!`) is strictly prohibited; configurable ordering uses explicit Rust `enum` variants mapped to dedicated static queries.

#### Transaction pipeline

1. Load typed durable snapshot (domain-decision facts only).
2. Domain evaluates command, produces change set or rejection.
3. Adapter commits: expected-version CAS, constraint enforcement, bounded locks, database timestamps, Event sequence allocation from `workspace_event_counters`, outbox references, receipt persistence, atomic commit.
4. Rejected command or rolled-back transaction consumes no Event sequence.

#### Command receipts

- Unique by `(workspace_id, command_scope, idempotency_key)`.
- Bind versioned normalized-input fingerprint, expected aggregate-version vector, result kind/reference, correlation, creation, and expiry.
- `command_scope` is a versioned allowlisted identity.
- Insert, mutation, Events, outbox, and final durable result commit together.
- Identical request returns original immutable Event/outcome correlation. Changed input or version vector fails without mutation.
- Receipts never store raw HTTP responses, cookies, secrets, or unrestricted bodies.

#### Adapter error classification

- Adapters classify and sanitize `sqlx`, object-store, harness, platform, and resolver errors before returning.
- Raw SQLSTATE detail, query text, object location, provider body, secret locator, or unbounded external message never crosses the adapter boundary.
- Expected conflicts carry typed bounded facts rather than formatted error strings.
- SQLSTATE to `FailureKind` mapping defined per capability port.

#### PostgreSQL representation

- IDs: native `uuid` columns ↔ `central_foundation::identity::*Id` newtypes wrapping `uuid::Uuid`.
- Instants/deadlines: `timestamptz` ↔ `time::OffsetDateTime`; database time (`now()`/`transaction_timestamp()`) is authoritative; caller timestamps are never authoritative.
- Versions/sequences/sizes/counters: bounded `bigint` ↔ `i64` validated non-negative into domain `Version(u64)`/`ByteCount(u64)`.
- Checksums/fingerprints: bounded `bytea` with algorithm/version ↔ `[u8; 32]` or bounded `Vec<u8>`.
- Statuses/kinds: `text` with explicit `CHECK`.
- `jsonb` ↔ `sqlx::types::Json<T>` only for bounded (32 KiB, depth ≤ 8), allowlisted, versioned immutable envelopes (e.g., type-specific Event payloads, compatible Checkpoint metadata). Ownership, lifecycle, versions, leases, fencing, quota ledgers, and queried guards are never hidden in generic JSON documents.
- Nullable columns represent real absent state, not empty-string convention.

### 8.2 `central-adapter-s3`

- Implements `central-artifact` S3-neutral body-store port traits using `aws-sdk-s3` + `aws-config` + `sha2`.
- Operations: unique staging upload, bounded inspection, no-overwrite promotion, open, delete.
- Object references are opaque internal types. AWS/S3/MinIO SDK types, bucket names, raw keys, and presigned URLs never cross the adapter boundary.
- Store-reported size/checksum are observations, not readiness authority.

### 8.3 `central-adapter-harness`

- Implements `central-harness` typed invocation port traits for Claude Code, OpenCode, Codex, and Antigravity, plus `gitclone` and launcher-client ports. No generic `Invoke(kind, payload)` adapter.
- Registries are static, immutable, exact-match. Duplicate identity fails startup.
- Missing, disabled, or revision-incompatible adapters fail explicitly; recovery never silently substitutes another adapter or revision.
- Secret-aware harness adapters receive non-transferable `ProtectedUse` scope; never receive bearer tokens.

### 8.4 `central-adapter-linux` (protected broker / platform boundary)

- Implements the protected-broker protocol, `memfd_create`, `SCM_RIGHTS` fd passing, `SO_PEERCRED` peer authorization, `openat2`, `pidfd`, PAM/TTY ceremonies, namespaces, and cgroups — through `rustix` safe wrappers inside audited `unsafe` boundaries. This crate is the only place (with the launcher and protected-execution-mode binaries) where `unsafe`/`rustix` is permitted.
- Implements `central-authorization` protected-use/resolution port traits (the upstream secret-resolver role), `central-infra` platform port traits, and `central-backup` fd-3 helper adapters (`pg_dump`/`pg_restore` fd protocol under `central-backup-launcherd`).
- The root-owned helper protocol mediates every privileged operation; no capability or CLI calls Docker, Compose, or storage tools directly.

### 8.5 Migration runner (inside `central-adapter-postgres`)

- `migrations/` at the workspace root contains canonical, ordered, version-controlled `.sql` files (`v0`..`b37`) extracted from the upstream Go-embedded DDL, plus an immutable checksum manifest; see [postgresql-adapter-mapping.md](../persistence/postgresql-adapter-mapping.md) for the extraction and ledger contract.
- A Central-owned `MigrationRunner` (single non-rebinding session, `pg_advisory_lock`, `central.schema_migrations` SHA-256 checksum ledger, version-zero `VerifiedEmptyTarget` broker proof, dirty data-backfill resume without generic `Force`, `reapply_incremental_runtime_grants` after `pg_restore`) is used only by `migrate up` and `migrate resume`. The `sqlx` `migrate` feature and `_sqlx_migrations` table are prohibited.
- `MigrationInspector` port is used for `migrate verify`, `migrate status`, and serving schema preflight. It uses `central_runtime`, read-only transactions, and allowlisted PostgreSQL catalogs plus Central's checksum/history/progress relations only.
- Version-zero provisioning: first persists external `initializing` state, then commits baseline schema/history/epoch/bootstrap registration in one Central-owned transaction. Only after `candidate_staged` is externally durable may the inspector mint `VerifiedEmptyTarget`.
- Initialized migration: `metadata` or `data_backfill` classification. Data backfill records dirty state with exact operation ID, version, checksum, progress version, and start cursor for crash-resume. `migrate resume` invokes the exact embedded backfill coordinator directly; resumes after last committed cursor.
- Generic `Force`, `Drop`, or auto-migrate are prohibited. Only the recognized data-backfill resume path may complete a dirty version.
- Runner close marks only library lifecycle; it closes the single non-rebinding session, releasing both advisory locks. No hidden connection acquisition.

### 8.6 Backup/restore plumbing

- `central-adapter-postgres` implements snapshot/dump-facing and inventory port traits; `central-adapter-linux` implements protected-manifest and fd-3 helper port traits.
- Inventory: sorted, chunked, resource-bounded. Database enumeration seeks by canonical object key plus stable Artifact identity; object enumeration uses canonical key `start-after`.
- Chunks: immutable, create-only, at most 1,000 records, each at most 4 KiB, under operation/ordinal/content-hash identity with own checksum.
- Verification merge-compares at most one database page and one object page per worker.
- Operator state: atomic replace, data flush, parent-directory synchronization with local operator-only write authority.
- All backup/restore verbs support `--output=json` → `central.operator-result/v1`.

### 8.7 Observability rendering

- `tracing` + `tracing-subscriber` JSON layer at the composition root; domain code does not log directly.
- `prometheus-client` registry constructed at composition root and injected as a value; global default collectors are prohibited. `/metrics` encodes that registry's text exposition.
- Metric labels are allowlisted low-cardinality enums: operation, component, outcome, route template, method class, status class. Workspace/Task/Run/Artifact/operation IDs, raw paths, model names from untrusted input, and error strings are prohibited labels.
- Safe IDs may appear in bounded structured logs for correlation.

## 9. Configuration, lifecycle, and validation

### 9.1 Configuration authority

Three distinct authorities:

1. **Immutable startup/bootstrap configuration:** loaded and validated before adapters are constructed. This contract defines typed fields and cross-field validation; the local-topology documentation owns concrete sources, names, protected paths, and precedence.
2. **Durable application policy and SecretReference metadata:** read from PostgreSQL/protected binding authority.
3. **Persisted per-operation input:** authority, budget, retry, and recovery state.

No hot-reload of general configuration. Secret rotation is just-in-time resolver behavior; policy change is durable versioned state.

### 9.2 Constructor rules

- Manual constructor injection. `central-kernel` is the single composition root (it imports every capability, adapter, and transport crate; `bins/central` invokes its wiring).
- Constructors receive minimal trait objects and immutable typed configuration.
- Constructors do not start work, `tokio::spawn`, or perform I/O; `#[tokio::main]` appears only in `bins/*` entry points.
- No DI framework, global container, logger singleton, pool singleton, or environment lookup from capability crates.

### 9.3 Component supervision

Every component enabled by a serving profile is required for that profile. There is no silently degraded serving mode.

| Failure class | Component behavior | Profile behavior |
| --- | --- | --- |
| Individual request/work-item rejection/failure | Return safe outcome or durably settle/classify item; continue component loop when contract permits | Remains ready if component is healthy |
| Transient component/dependency failure | Retry internally with typed finite attempt/elapsed budgets, cancellation-aware bounded exponential backoff with jitter; no new external effect without accepted prepare/authority fence | Unready during startup; after readiness, marks readiness false if component cannot safely serve/claim during retry |
| Exhausted transient budget or terminal failure | `run` returns one sanitized classified error | Readiness becomes false, profile context cancelled, all enabled components shut down |
| Parent cancellation during normal shutdown | Stop intake/claims, perform only authorized bounded settlement, release resources, return canonical cancellation outcome | External supervisor observes intentional stop, not crash loop |

### 9.4 Readiness and preflight

- Ordinary preflight: index-backed compatibility/health checks, one index-backed `EXISTS` query per readiness-blocking fact class, and seek-paginated discovery with `LIMIT N+1`.
- Never executes exact aggregate count or scans history to prove absence.
- Discovery page: default 100, hard 1,000. Each query receives only remaining portion of 5 s default/10 s hard elapsed budget.
- Blocking `EXISTS` result fails readiness with safe class. `LIMIT N+1` records stable continuation cursor, moves classified non-blocking work to background reconciliation.
- Every blocking and discovery predicate must have a matching composite index and representative `EXPLAIN` evidence showing index-backed bounded plan at reference dataset.
- N+1 behavior, exact-count queries on readiness path, and full-table scans at reference dataset are acceptance failures.
- Post-restore start obeys the complete restore-readiness barrier (full manifest inventory verification, quarantine resolution, authority-reset, fresh bootstrap activation); may not classify unfinished work as background.

### 9.5 Shutdown

Two-phase bounded shutdown:

1. **Time zero:** readiness becomes false. Stop HTTP intake and new claims. Prevent every new external invocation.
2. **Settlement grace:** kernel-owned settlement (each component's `settle` under a `tokio::time::timeout`) with 30 s default/2 min hard maximum to persist known or ambiguous outcome for every effect that may have occurred. Expiry cannot authorize retry or discard evidence.
3. **Reverse-order closure:** background components stop after durable checkpoint/lease handoff; adapters, control connections, and pools close in reverse dependency order.
4. **Total deadline:** 45 s default/3 min hard maximum (cannot be configured shorter than settlement grace).

Exit `0` only after durable obligations complete. Failed settlement persistence, terminal component failure, or total-deadline expiry triggers best-effort reverse closure and exit `6`. In-memory queues and wake-up signals are never durable work authority.

### 9.6 Cross-field validation

Topology validation must reject any concurrent combination where:

- Target-wide connections exceed 16 default/24 hard.
- More than 4 serve profiles/control connections.
- Serving pools exceed their single installation-wide allocation.
- Runtime-settlement maximum is other than 2.
- Any non-settlement route accesses the settlement pool.
- Artifact active/waiter/deadline exceeds its cap.
- Artifact copy buffer × concurrency exceeds 8 MiB.
- Non-streaming active/waiter/deadline exceeds its cap.
- Non-streaming active × buffer exceeds 64 MiB.
- Inventory worker × spool exceeds 16 MiB.
- Any installed value exceeds its inherited/contract maximum.

Every topology combination must fail closed when invalid.

## 10. Observability boundary

### 10.1 Domain isolation

`domain.rs` modules return decisions, rejections, and change sets. They do not log or emit metrics (and cannot: `tracing`/`prometheus-client` are absent from capability domain dependencies).

### 10.2 Observation path

Application services emit typed observations through capability-specific narrow `port.rs` traits. Adapters render those observations.

### 10.3 Logging

- `tracing-subscriber` JSON layer at the composition root.
- Structured logs for correlation only; never use for recovery decisions.
- Plaintext secrets, bootstrap/session/CSRF tokens, authorization material, database credentials, backend locators, raw object keys, raw filenames, unrestricted prompt/tool/Artifact bodies, raw URLs/query strings, and unbounded labels are excluded from all observations.

### 10.4 Metrics

- `prometheus-client` registry constructed at composition root.
- Global default collectors are prohibited.
- Allowlisted low-cardinality labels: operation, component, outcome, route template, method class, status class.
- Prohibited labels: Workspace, Task, Run, Artifact, operation IDs, raw paths, model names from untrusted input, error strings.
- `/metrics` serves the registry's text exposition from the operational listener.

### 10.5 Trace propagation

- `tracing` span context may travel alongside calls. Correlation and causation identities remain explicit typed command, invocation, observation, and durable-record fields.
- No distributed tracing exporter is configured in the current phase.

## 11. Security and safe-data boundary

### 11.1 Trust boundaries

- `axum`, `sqlx`, `aws-sdk-s3`, harness CLIs/SDKs, and `rustix` are trusted implementation dependencies but not authority sources.
- Untrusted Task/model/harness/tool/network/Artifact content is parsed and bounded at its source boundary before entering generic failure, Event, receipt, log, metric, trace, key, query request, or query projection.
- System-owned connections use fixed registered adapters with least-privileged identities. Harness authority cannot borrow those clients.

### 11.2 Safe-data exclusions

Excluded from application failure, query request/projection, and observation types:

- Plaintext secrets, bootstrap/session/CSRF tokens, authorization material.
- Database credentials, backend locators, raw object keys, raw filenames.
- Unrestricted prompt/tool/Artifact bodies, raw URLs/query strings, command environments.
- Unbounded labels.

### 11.3 Adapter trust

The in-process boundary does not claim sandboxing against hostile adapter code. Adapter registration and review remain part of the trusted computing base. Every registered secret-aware adapter must pass counting-transport conformance tests proving:

- At most one transport call across success, rejection, timeout, cancellation, panic, and retry paths.
- Exact immutable request binding.
- Rejection of fence reuse/concurrency (`use_once` consumes by value; the test proves no second consumption path exists).
- Byte clearing/release (`zeroize` on drop).
- Zero plaintext in results or observations.

## 12. Validation scenarios

This contract is documentary design-contract evidence. The governing design and upstream Gate 7 validation inventory define the scenario coverage; each Rust R-slice re-proves its inherited scenarios with executable tests:

- Accepted Task transitions and change-set commits.
- Invalid transition rejection before persistence mutation.
- Version-conflict detection and non-retry.
- Idempotent concurrent command receipt convergence.
- Multi-Event sequence range allocation and rollback correctness.
- Deadlock/proven-rollback safe retry and indeterminate commit resolution.
- Stale fencing-token rejection.
- Database-time vs. process-time authority.
- Harness/tool invocation outside PostgreSQL transactions.
- Cancellation-after-delivery ambiguity persistence.
- Secret-aware adapter fence semantics and counting-transport conformance (including `use_once` single-consumption proofs).
- Exact adapter revision recovery.
- Artifact upload, verify, promote, finalize, and completion-guard sequences.
- HTTP admission, layer order, route-policy, and safe-observation enforcement (32/64/5 s/2 MiB/64 MiB).
- Prohibited-type absence from `domain.rs`, `port.rs`, and `query.rs` exports (no `tokio`, no `sqlx`, no `axum`, no adapter types).
- API/HTML handler convergence on same Service behavior.
- Migration verify/status/preflight and serve compatibility preflight against the canonical `v0`..`b37` `.sql` schema.
- Serve profile migration-credential exclusion and role privilege enforcement.
- Event/tombstone immutability under application roles.
- Intentional shutdown with bounded settlement and reverse-order closure.
- Metric label allowlist and sentinel secret/data absence.
- Representative workflow traces through crates, ports, and adapters.
- Advisory lock matrix for serve/backup coexistence and terminal lock-loss.
- Restore verify→apply ticket freshness, reacquisition, and crash-resume.
- Restore external/database epoch matching and authority reset.
- Component retry budget exhaustion and profile-wide fail-fast.
- Reference dataset performance budgets including SQL round trips and query plans.
- Artifact streaming byte, buffer, concurrency, admission, and idle/total timeout contracts.
- Topology-wide connection-partition validation across all pools/profiles/modes.
- Bootstrap exchange two-phase protocol with concurrent candidate IDs.
- Session credential lifecycle, buffer precommit hook, and first-use deadline.
- Cookie attributes, anti-framing headers, and CSP on all HTML surfaces (§4.4 profile verbatim).
- Inventory chunking, worker/page/spool budgets, and immutable-chunk resume.
- Non-streaming HTTP saturation, buffer capacity, and safe rejection.
- HTML surface/state-to-Service mapping, accessibility baseline, and automated checker.
- Phase 2 additions: `SKIP LOCKED` scheduler claim exclusivity, `run_events` fold/reconstruction equivalence, subtree-checkpoint resume preflight, retry/compensation/idempotency matrix, and run-submission receipt convergence.

Every scenario identifies normative contract, expected result, future executable test level, and owning capability crate. R-slices assign concrete slices and order per [rust-vertical-slice-roadmap.md](../implementation/rust-vertical-slice-roadmap.md); acceptance reviews trace slices back to this evidence.

## 13. R-slice ownership

Per ADR 0043, upstream Gate 8 (concrete local topology/protected stores) and Gate 9 (executable vertical slices) ownership is replaced by the `R0`–`R6` delivery sequence:

| Concern | Owner |
| --- | --- |
| Cargo Workspace DAG, crate matrix, lint gates, toolchain pinning, canonical `v0`..`b37` SQL extraction, native migration runner, durable Task/Execution core | R1 |
| Verified Artifact lifecycle and `central-adapter-s3` | R2 |
| Harness control plane (`central-harness`, `central-adapter-harness`), `central-session`, `central-transport-http`, `central-harness-launcherd` | R3 |
| Phase 2 orchestration (`central-workflow`, `central-eventjournal`, `central-scheduler`, `central-retry`, `central-runview`, `central-runsubmit`) and recovery matrix | R4 |
| Host authority, protected broker, `central-adapter-linux`, PAM/TTY ceremonies, Compose topology | R5 |
| `central-backup`, `central-restore`, `central-backup-launcherd`, wipe/prune/security-rescue, maintenance | R6 |

This document (R0 output) is the contract those slices implement against; nothing in R1–R6 may weaken it without a new ADR.

## 14. References

- [ADR 0001](../adr/0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0002](../adr/0002-authorize-accepted-to-superseded-status-transitions.md) — ADR governance meta-rules; listed for cross-reference completeness
- [ADR 0003](../adr/0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [ADR 0004](../adr/0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [ADR 0005](../adr/0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md)
- [ADR 0006](../adr/0006-adopt-local-v1-api-and-event-serialization.md)
- [ADR 0007](../adr/0007-adopt-postgresql-persistence-and-recovery-contracts.md)
- [ADR 0008](../adr/0008-adopt-capability-owned-go-application-boundaries.md) — upstream capability-boundary decision this contract translates; immutable historical record
- [ADR 0011](../adr/0011-amend-local-topology-for-dedicated-migration-operator.md) — dedicated migration/operator topology carried into §3.2 and §5
- [ADR 0018](../adr/0018-authorize-the-restore-capacity-reserve-authority.md) — restore capacity reserve referenced by `central-restore`
- [ADR 0035](../adr/0035-freeze-b09-loop-coordinator-and-adopt-harness-session-boundary.md) — harness session boundary replacing the B09 coordinator role
- [ADR 0036](../adr/0036-add-a-separate-harness-launcher-for-operator-harness-sessions.md) — `central-harness-launcherd` provenance
- [ADR 0043](../adr/0043-adopt-rust-workspace-and-harness-first-porting-strategy.md) — the amendment adopting this contract for `central-rust`
- [Central-Rust documentation and architecture design](../internal/superpowers/specs/2026-10-21-central-rust-documentation-and-architecture-design.md) — governing spec (§3)
- [PostgreSQL adapter mapping (sqlx)](../persistence/postgresql-adapter-mapping.md) — type mapping, `.sqlx/` verification, native migration ledger
- [Rust engineering workflow](../implementation/rust-engineering-workflow.md) — toolchain, lint gates, `cargo sqlx prepare`, `cargo deny`, test taxonomy
- [Current phase](../implementation/current-phase.md) and [Rust vertical-slice roadmap](../implementation/rust-vertical-slice-roadmap.md) — R-slice sequencing
- [Architecture overview](./overview.md) · [Durable execution](./durable-execution.md)
- [PostgreSQL persistence contract](../persistence/postgresql.md) · [Migrations and recovery contract](../persistence/migrations-and-recovery.md)
- [Artifact lifecycle contract](../artifacts/lifecycle.md) · [Artifact content policy](../artifacts/content-policy.md)
- [API v1 contract](../api/v1.md) · [Event v1 contract](../events/v1.md) · [Agent runtime contract](../runtime/agent-runtime.md)
- Historical provenance: upstream `central/docs/architecture/go-application-boundaries.md` (Go contract; not present in this repository by design)
