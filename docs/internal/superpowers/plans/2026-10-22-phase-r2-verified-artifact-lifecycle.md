# Phase R2 — Verified Artifact Lifecycle & Object Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete, verified Phase R2 vertical slice in `$CENTRAL_RUST_SRC` per [rust-vertical-slice-roadmap.md](../../implementation/rust-vertical-slice-roadmap.md) §5: extend `central-foundation::identity` with RFC 9562 UUIDv4 generation/edge newtypes, implement `central-artifact` (`domain.rs`, `lineage.rs`, `port.rs`, `query.rs`, `app.rs`, `classifier.rs`, `reconciler.rs`), `central-adapter-s3` (S3/MinIO `ObjectStore` and process-wide `TransferLimiter`), and `central-adapter-postgres::artifact` (`Store`, `CompletionContributor`, `ReconciliationStore`, two-phase deletion/tombstones, `ArtifactSummaryRead`, and `b34` lineage stores), wire `central-kernel` supervision for artifact reconciliation, regenerate `.sqlx/` offline metadata, and pass all 5 stages of the verification pipeline plus deterministic PostgreSQL and MinIO integration suites.

**Architecture:**
- **Compiler-enforced Cargo Workspace DAG ([rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §1–§3):**
  - `central-foundation::identity` Remains the sole crate outside `central-adapter-postgres` that imports `uuid::Uuid` ([rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §1 line 40). It exposes opaque RFC 9562 UUIDv4 newtypes `StagingGeneration`, `ContentGeneration`, `ProduceEdgeId`, and `ReadEdgeId` alongside deterministic digest constructors (`ArtifactId::from_v7_digest_bytes`, `StagingGeneration::from_v4_digest_bytes`) so `central-artifact` never imports `uuid::Uuid`.
  - `crates/capabilities/central-artifact` depends **only** on `central-foundation`, `central-execution` (one-way, for `ExecutionChangeSet` completion-guard types; `central-execution` never imports `central-artifact`), `serde`, `serde_json`, `sha2`, `time`, and `trait-variant`. Per [rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §1 line 41, `tokio` and `tokio-util` are **absent** from `central-artifact/Cargo.toml`: cancellation is delivered by Rust future drop, elapsed pass budgets use `std::time::{Duration, Instant}`, and byte streams cross `port.rs` via a capability-owned `#[trait_variant::make(Send)] pub trait ByteStream` / `std::io::Read`.
  - `central-artifact::domain` and `central-artifact::lineage` are 100% synchronous Rust (`no async fn`, no I/O traits). They own the B10 lifecycle transitions (`Reserve`, `BeginUpload`, `Verified`, `Reject`, `Promotion`, `Finalize`), workspace-scoped two-phase deletion transitions (`MarkDeletePending`, `CompleteDeletion` + `ArtifactTombstone`), content-policy delivery/preview disposition rules ([content-policy.md](../../artifacts/content-policy.md)), and `b34` lineage models (`ProduceEdge`, `ReadEdge`, `ReadScope`, `ReadAuthorization`).
  - `central-artifact::port` defines `#[trait_variant::make(Send)]` async traits (`TransferLimiter`, `ObjectStore`, `Store`, `TwoPhaseDeleteStore`, `Classifier`, `CompletionContributor`, `ReconciliationStore`, `ProduceEdgeStore`, `ReadEdgeStore`, `LineageReader`, `ReadStore`) and `central-artifact::query` defines seek-paginated read contracts (`ArtifactSummaryRead` using `ArtifactSeekCursor`, no `OFFSET`).
  - `central-artifact::app` coordinates `MaterializeRequiredReport`, `ResumeVerifying`, `DeliverReadyArtifact`, the one-shot `!Clone` `AuthorizedDownload` capability (`prepare_authorized_download` + `AuthorizedDownload::start(self)` per [rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §2.4/§3.4), untrusted-body content classification (`ReportClassifier`), B08-fenced orphan/expiry reconciliation (`Reconciler`), and `b34` lineage operations.
  - `crates/adapters/central-adapter-s3` is the sole workspace consumer of `aws-sdk-s3` and `aws-config` (using `aws_sdk_s3::primitives::ByteStream` and `aws_sdk_s3::error::ProvideErrorMetadata` re-exports without adding undeclared `aws-smithy-*` crates). It enforces `MaxConcurrentTransfers = 2`, a 5 MiB S3 multipart part-size floor (`StagingPartSizeBytes`) on streaming staging uploads, a single conditional `PUT` with `If-None-Match: "*"` on ready promotion (`PromoteCreateOnly` and `RestoreBodyCreateOnly`), 60s idle / 10m total transfer watchdogs, and locator-free `ObjectFailureClass` error sanitization.
  - `crates/adapters/central-adapter-postgres/src/artifact/` implements `Store` (workspace quota admission under `FOR NO KEY UPDATE` reserving `2 * MaxBytes` peak capacity, stage transitions, and 7-day `artifact_command_receipts`), `CompletionContributor` (`CommitArtifact` atomic ready transition + quota settlement + B08 lease-fenced `ExecutionChangeSet` settlement reusing `central-adapter-postgres::execution`'s transaction/event/outbox helpers), `ReconciliationStore` (demoting resolved/released large claims via `UPDATE ... SET claim_kind = 'normal'` so `central_runtime` never hits SQLSTATE `42501` on `DELETE`), `TwoPhaseDeleteStore` + `ArtifactSummaryRead`, and `b34` lineage stores (`artifact_produce_edges`, `artifact_read_edges`).
  - **Phase R2 vs. Phase R4 Boundary ([rust-vertical-slice-roadmap.md](../../implementation/rust-vertical-slice-roadmap.md) §2, §5, §7):** R2 delivers the complete `b10` artifact lifecycle and the `b34` lineage domain + PostgreSQL stores (`ProduceEdgeStore`, `ReadEdgeStore`, `LineageReader`, `ReadStore`). Attempt-scoped `FinalizeAttemptArtifact` (which journals `artifact_finalized` into `b33` `central.run_events` and keys `b37` `central.artifact_finalizations`) and the `central artifact read` CLI verb land in Phase R4 alongside `central-eventjournal` and `central-workflow`.

**Tech Stack:** Rust stable (`rust-toolchain.toml`), `trait-variant` (`=0.1.3`), `aws-sdk-s3` (`=1.154.0`) + `aws-config` (`=1.13.0`) (confined to `central-adapter-s3`), `sqlx` (`=0.8.6`, `postgres`, `macros`, `uuid`, `time`, `json`), `uuid` (`=1.28.0`, `v4`, `v7`, `serde` — confined to `central-foundation` and `central-adapter-postgres`), `sha2` (`=0.11.1`), `serde` + `serde_json`, `time` (`=0.3.55`), `tokio` (`=1.54.1`) + `tokio-util` (`=0.7.20`, confined to adapters and `central-kernel`), `tracing`.

## Global Constraints

- **Source of Truth:** `$CENTRAL_SRC` (read-only reference for exact domain transitions, canonical receipt fingerprint JSON layouts, SQL queries, S3 precondition semantics, classifier rules, and test scenarios).
- **Zero `unsafe`:** Every crate touched in R2 (`central-foundation`, `central-artifact`, `central-adapter-s3`, `central-adapter-postgres`, `central-kernel`) enforces `unsafe_code = "forbid"` via workspace lints.
- **Strict Capability Dependency Hygiene:** `central-artifact` must **not** depend on `tokio`, `tokio-util`, or `uuid`. All UUID construction/parsing lives in `central-foundation::identity`.
- **No Unwraps in Production Targets:** `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::todo`, and `clippy::dbg_macro` are `deny` across all non-test targets.
- **No Secret, Body, or Locator Leakage:** Neither `central-adapter-s3` nor `central-adapter-postgres::artifact` may include object keys, bucket names, S3 endpoints, raw body bytes, SQL text, or driver error strings in `Display` / `Error` outputs. Only closed `FailureClass` and `Reason` / `FailureCode` tokens cross adapter boundaries.
- **Every Task Ends Green:** Each task below runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, and commits before advancing.

---

## File Structure

```text
central-rust/
├── Cargo.toml                                          # Add "v4" feature to workspace `uuid = "=1.28.0"` dependency
├── .sqlx/                                              # Updated offline sqlx query metadata including central-adapter-postgres::artifact queries
├── crates/
│   ├── central-foundation/
│   │   └── src/
│   │       └── identity.rs                             # Add RFC 9562 UUIDv4 newtypes (StagingGeneration, ContentGeneration, ProduceEdgeId, ReadEdgeId, ArtifactTombstoneId) + deterministic digest constructors
│   ├── capabilities/
│   │   └── central-artifact/
│   │       ├── Cargo.toml                              # Depends ONLY on central-foundation, central-execution, serde, serde_json, sha2, time, trait-variant (NO tokio, NO uuid)
│   │       └── src/
│   │           ├── lib.rs                              # Re-exports domain, lineage, port, query, classifier, reconciler, app
│   │           ├── domain.rs                           # Pure B10 state machine, DeriveReservationIdentity, Limits, Reserve/BeginUpload/Verified/Reject/Promotion/Finalize, two-phase delete (MarkDeletePending/CompleteDeletion + ArtifactTombstone), content-policy delivery/preview disposition rules, CommandIdentity & fingerprints
│   │           ├── lineage.rs                          # Pure b34 ProduceEdge, ReadEdge, ReadScope, ParseAttemptScope, LineageArtifact, ReadAuthorization, closed reason codes
│   │           ├── port.rs                             # #[trait_variant::make(Send)] traits: ByteStream, TransferLimiter, ObjectStore, Store, TwoPhaseDeleteStore, Classifier, CompletionContributor, ReconciliationStore, ProduceEdgeStore, ReadEdgeStore, LineageReader, ReadStore + transfer/reconcile constants
│   │           ├── query.rs                            # Seek-paginated ArtifactSummaryRead contract (ArtifactListRequest, ArtifactSeekCursor, ArtifactSummaryView, no OFFSET)
│   │           ├── classifier.rs                       # ReportClassifier: 1 MiB prefix inspection, secret-disclosure detector (PEM, env assignments, token prefixes, credentialed URLs), UTF-8/NUL/Markdown sniffing
│   │           ├── reconciler.rs                       # Reconciler: B08 Fence validation, DefaultBudget / LargeClaimBudget, sweep_rejected_staging, normal & dedicated large-claim passes, 8 MiB/s throughput floor deferral
│   │           └── app.rs                              # Service: MaterializeRequiredReport, ResumeVerifying, DeliverReadyArtifact, prepare_authorized_download + one-shot !Clone AuthorizedDownload, TwoPhaseDelete orchestration, plus async lineage helpers (record_produce, record_read, authorize_read, ancestors, descendants, run_lineage_for_run)
│   ├── adapters/
│   │   ├── central-adapter-s3/
│   │   │   ├── Cargo.toml                              # central-foundation, central-artifact, aws-config, aws-sdk-s3, sha2, tokio, tokio-util, trait-variant, tracing
│   │   │   └── src/
│   │   │       ├── lib.rs                              # Public Config, S3ObjectStore, TransferLimiter, Failure, FailureClass, Reason
│   │   │       ├── error.rs                            # Closed FailureClass + Reason taxonomy and SDK error sanitizer (never wraps raw SDK error)
│   │   │       ├── limiter.rs                          # Process-wide counting semaphore TransferLimiter (MaxConcurrentTransfers = 2) with idempotent permit guard
│   │   │       ├── stream.rs                           # ProgressReader (+1 byte ceiling sentinel) and PermitStream (60s idle & 10m total deadline watchdogs) implementing port::ByteStream
│   │   │       └── store.rs                            # S3ObjectStore implementing ObjectStore (upload multipart 5 MiB parts, read, promote_create_only single PUT If-None-Match: *, restore_body_create_only, remove_staging, remove_ready_for_delete, open_backup_throughput_fixture)
│   │   └── central-adapter-postgres/
│   │       ├── Cargo.toml                              # Add central-artifact dependency
│   │       └── src/
│   │           ├── lib.rs                              # Export `pub mod artifact;`
│   │           └── artifact/
│   │               ├── mod.rs                          # PgArtifactStore wiring Store, CompletionContributor, ReconciliationStore, TwoPhaseDeleteStore, ArtifactSummaryRead, ProduceEdgeStore, ReadEdgeStore, LineageReader, ReadStore
│   │               ├── queries.rs                      # SQL constants and canonical receipt fingerprint helpers matching internal/adapter/postgres/artifact/{queries.go,store.go}
│   │               ├── store.rs                        # ReserveArtifact (FOR NO KEY UPDATE quota + 2x peak reservation), RecordBeginUpload, RecordVerification, RecordPromotion, RecordRejection, LoadArtifact, two-phase delete & tombstone, ArtifactSummaryRead
│   │               ├── commit.rs                       # CompletionContributor::commit_artifact (atomic finalize + quota settlement + B08 lease-fenced ExecutionChangeSet commit reusing execution store helpers)
│   │               ├── reconcile.rs                    # ReconciliationStore (ClaimIncomplete round-robin workspace seek, ClaimLarge with UPDATE claim_kind = 'normal' demotion for central_runtime compatibility, RecordLargeClaim, ExpireStaging against DB clock_timestamp(), ReleaseLargeClaim, ClaimRejectedStaging, ClearStagingKey, RecordProgress)
│   │               └── lineage_store.rs                # b34 ProduceEdgeStore, ReadEdgeStore, LineageReader, ReadStore over artifact_produce_edges & artifact_read_edges
│   └── central-kernel/
│       ├── Cargo.toml                                  # Add central-artifact and central-adapter-s3 dependencies
│       └── src/
│           └── lib.rs                                  # Register supervised artifact reconciliation component adapter in kernel composition root
```

---

### Task 1: `central-foundation` UUIDv4 Generation Newtypes & `central-artifact` Pure Domain Root (`domain.rs`)

**Files:**
- Modify: `$CENTRAL_RUST_SRC/Cargo.toml`
- Modify: `$CENTRAL_RUST_SRC/crates/central-foundation/src/identity.rs`
- Modify: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/Cargo.toml`
- Create: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/domain.rs`
- Modify: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/lib.rs`

**Reference files (read-only):**
- `$CENTRAL_SRC/internal/artifact/domain.go`
- `$CENTRAL_SRC/internal/artifact/domain_test.go`
- `$CENTRAL_SRC/internal/artifact/fingerprint_coverage_test.go`
- `$CENTRAL_RUST_SRC/docs/artifacts/lifecycle.md`
- `$CENTRAL_RUST_SRC/docs/artifacts/content-policy.md`
- `$CENTRAL_RUST_SRC/docs/persistence/postgresql-adapter-mapping.md` (§3.9, §3.10)

- [ ] **Step 1: Add `"v4"` feature to workspace `uuid = "=1.28.0"` and extend `central-foundation::identity`**
  - In root `Cargo.toml`, update `uuid` under `[workspace.dependencies]` to `uuid = { version = "=1.28.0", features = ["v4", "v7", "serde"] }`.
  - In `crates/central-foundation/src/identity.rs`:
    - Add a `define_v4_id!` macro enforcing strict canonical lowercase 8-4-4-4-12 text, non-nil, version 4, and RFC 9562 variant (`IdParseErrorKind::WrongVersion` when version != 4), with `new()` (`Uuid::new_v4()`), `parse(&str)`, `as_bytes()`, `from_trusted_db_bytes([u8; 16])`, and `is_nil()`.
    - Define `StagingGeneration`, `ContentGeneration`, `ProduceEdgeId`, `ReadEdgeId`, and `ArtifactTombstoneId`.
    - Add deterministic digest constructors `ArtifactId::from_v7_digest_bytes(raw: [u8; 16]) -> Self` (setting `(raw[6] & 0x0f) | 0x70` and `(raw[8] & 0x3f) | 0x80`) and `StagingGeneration::from_v4_digest_bytes(raw: [u8; 16]) -> Self` (setting `(raw[6] & 0x0f) | 0x40` and `(raw[8] & 0x3f) | 0x80`) so `central-artifact` never imports `uuid::Uuid`.
  - In `crates/capabilities/central-artifact/Cargo.toml`, declare **only** `central-foundation`, `central-execution`, `serde`, `serde_json`, `sha2`, `time`, and `trait-variant` (no `tokio`, no `uuid`).

- [ ] **Step 2: Implement `crates/capabilities/central-artifact/src/domain.rs` (pure synchronous Rust)**
  - Port `FailureClass` (`Invalid`, `Conflict`, `Denied`) and `Failure` (`class`, `reason`) with `Display` formatting `"artifact: {} ({})"` and conversion into `central_foundation::failure::Failure`.
  - Port `Limits` (`DEFAULT_REQUIRED_REPORT_MAX_BYTES = 1 << 20`, `HARD_REQUIRED_REPORT_MAX_BYTES = 10 << 20`, `ARTIFACT_PREVIEW_MAX_BYTES = 128 * 1024`, `validate()`).
  - Port `derive_reservation_identity(operation_id: &str) -> Result<(ArtifactId, StagingGeneration), Failure>` using the exact domain-separated SHA-256 seeds `"central.b10.reservation-artifact-id/v1\x00"` and `"central.b10.reservation-staging-generation/v1\x00"`.
  - Port `State` (`Reserved`, `Staging`, `Verifying`, `Ready`, `Rejected`, `DeletePending`, `Deleted`, `Quarantined`), `Sensitivity` (`Unrestricted`, `Restricted`, `Sensitive`), `Disposition` (`Inline`, `Attachment`), `Artifact` snapshot struct, and key derivation helpers `staging_key("v1/staging/{ws}/{art}/{gen}")` and `ready_key_for("v1/ready/{ws}/{art}/{gen}")`.
  - Port `CommandStage` (`Reserve`, `BeginUpload`, `Verify`, `Promote`, `Finalize`, `Reject`), `CommandIdentity`, `reserve_fingerprint(in: &ReserveInput) -> [u8; 32]` (matching the exact field order and `skip_serializing_if` semantics of upstream's `reserveFingerprint` JSON struct), `OutcomeKind` (`Ready`, `Retryable`, `Terminal`, `Reconciliation`), `Outcome`, closed `FAILURE_CODE_*` constants, `classifier_rejection_admitted`, and `rejection_outcome`.
  - Port pure B10 lifecycle transition functions:
    - `reserve(ReserveInput) -> Result<ReserveResult, Failure>`
    - `begin_upload(BeginUploadInput) -> Result<BeginUploadResult, Failure>`
    - `verified(VerifiedInput) -> Result<VerifiedResult, Failure>`
    - `reject(RejectInput) -> Result<RejectResult, Failure>`
    - `promotion(PromotionInput) -> Result<PromotionResult, Failure>`
    - `finalize(FinalizeInput) -> Result<FinalizeResult, Failure>` and `new_finalize_identity`
  - Implement pure workspace-scoped two-phase deletion & tombstone transitions (`docs/artifacts/lifecycle.md`, `postgresql-adapter-mapping.md` §3.9–§3.10):
    - `mark_delete_pending(MarkDeletePendingInput) -> Result<Artifact, Failure>` (validates workspace/artifact chain and version, requires `State::Ready`, transitions to `State::DeletePending` and sets `delete_intent_at`).
    - `complete_deletion(CompleteDeletionInput) -> Result<(Artifact, ArtifactTombstone), Failure>` (requires `State::DeletePending` or `State::Ready` with non-empty deletion reason, transitions to `State::Deleted`, and constructs immutable `ArtifactTombstone { id, workspace_id, artifact_id, object_key, staging_generation, checksum_algorithm, checksum_value, size_at_deletion, deletion_reason }`).
  - Implement content-policy delivery and preview disposition evaluator (`docs/artifacts/content-policy.md`):
    - `evaluate_delivery_policy(detected_media_type: Option<&str>, sensitivity: Sensitivity, requested_disposition: Disposition, verified_size: i64) -> DeliveryPolicyDecision` enforcing the preview allowlist (`text/plain`, `text/markdown`, `application/json`), `ARTIFACT_PREVIEW_MAX_BYTES` (`128 KiB`) raw preview bound with truncation flag, and forced `Disposition::Attachment` + `application/octet-stream` fallback for unallowlisted or `Sensitive` content.

- [ ] **Step 3: Port all unit tests from `domain_test.go` and `fingerprint_coverage_test.go` plus two-phase deletion and content-policy unit tests**
  - Verify UUIDv4 newtype strict parsing in `central-foundation`, state machine transitions, workspace chain mismatch denials, version conflicts, `derive_reservation_identity` byte-for-byte determinism, `reserve_fingerprint` sensitivity to every field, `verified` rejection precedence, `finalize` identity verification, `mark_delete_pending` -> `complete_deletion` tombstone construction, and `evaluate_delivery_policy` allowlist/disposition rules.

- [ ] **Step 4: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-foundation -p central-artifact --all-targets -- -D warnings && cargo test -p central-foundation -p central-artifact`
  - Commit: `feat(artifact): implement B10 pure artifact lifecycle domain and UUIDv4 identities`

---

### Task 2: `central-artifact` Pure Lineage Domain (`lineage.rs`) and Ports/Queries (`port.rs`, `query.rs`)

**Files:**
- Create: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/lineage.rs`
- Create: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/port.rs`
- Create: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/query.rs`
- Modify: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/lib.rs`

**Reference files (read-only):**
- `$CENTRAL_SRC/internal/artifact/lineage.go`
- `$CENTRAL_SRC/internal/artifact/lineage_test.go`
- `$CENTRAL_SRC/internal/artifact/port/port.go`
- `$CENTRAL_RUST_SRC/docs/internal/superpowers/specs/2026-10-07-phase-2-artifact-lineage.md`
- `$CENTRAL_RUST_SRC/docs/architecture/rust-application-boundaries.md` (§2.3, §3.4)

- [ ] **Step 1: Implement `crates/capabilities/central-artifact/src/lineage.rs` (pure synchronous domain types & validators)**
  - Port closed reason codes (`REASON_ARTIFACT_NOT_FINALIZED`, `REASON_ARTIFACT_SCOPE_DENIED`, `REASON_ARTIFACT_READ_UNRESOLVED`, `REASON_LINEAGE_READ_UNDECLARED`, `REASON_ARTIFACT_BODY_INTEGRITY`, `REASON_ARTIFACT_READ_AMBIGUOUS`).
  - Port `ProduceEdge` (`id: ProduceEdgeId`, `run_id: RunId`, `node_id: WorkflowNodeId`, `attempt_id: SessionAttemptId`, `artifact_id: ArtifactId`, `created_at: OffsetDateTime`) and its validation rules.
  - Port `ReadEdge` (`id: ReadEdgeId`, `run_id: RunId`, `reader_node_id: Option<WorkflowNodeId>`, `attempt_id: Option<SessionAttemptId>`, `artifact_id: ArtifactId`, `declared: bool`, `checksum: String`, `created_at: OffsetDateTime`) enforcing the all-or-nothing `(reader_node_id, attempt_id)` pair check (`LINEAGE_READ_EDGE_READER_PAIR_MISMATCH`) and 64-char lowercase hex SHA-256 checksum validation (`LINEAGE_READ_EDGE_CHECKSUM_REQUIRED`).
  - Port `ReadScope` (`Attempt { run_id, node_id, attempt_id }` / `Operator`), `parse_attempt_scope(value: &str) -> Result<ReadScope, Failure>` (`"<run_id>:<node_id>:<attempt_id>"` or empty for operator), `LineageArtifact`, `ReadSelector` (`ByArtifactId(ArtifactId)` | `ByProduced { from_node_key: String, name: String }`), `ReadRequest`, `ReadAuthorization` (`edge()`), and `RunLineage`.

- [ ] **Step 2: Implement `crates/capabilities/central-artifact/src/port.rs` and `query.rs`**
  - Define process-wide transfer and ceiling constants from `internal/artifact/port/port.go`:
    - `MAX_CONCURRENT_TRANSFERS: usize = 2`
    - `TRANSFER_COPY_BUFFER_BYTES: usize = 256 * 1024`
    - `TRANSFER_IDLE_TIMEOUT: Duration = Duration::from_secs(60)`
    - `TRANSFER_TOTAL_DEADLINE: Duration = Duration::from_secs(10 * 60)`
    - `MAX_ARTIFACT_BODY_BYTES: i64 = 4 * 1024 * 1024 * 1024`
  - Define a runtime-agnostic `#[trait_variant::make(Send)] pub trait ByteStream: Send` (`async fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, Failure>`, `async fn close(&mut self) -> Result<(), Failure>`) so `central-artifact` streams object bodies without importing `tokio::io::AsyncRead`.
  - Define `ObjectRef`, `ObjectInfo`, `UploadRequest`, `UploadResult`, `ClassifyRequest`, `ClassifyResult`, `ArtifactCommandReceipt`, `ArtifactChangeSet`, `CommitResult`, `TwoPhaseDeleteResult`, and reconciliation DTOs (`ReconciliationCursor`, `IncompleteClaim`, `ClaimIncompleteRequest`, `ClaimIncompleteResult`, `ClaimLargeRequest`, `LargeClaim`, `RecordLargeClaimRequest`, `ExpireStagingRequest`, `ExpireStagingResult`, `ReleaseLargeClaimRequest`, `RejectedStagingClaim`, `ClaimRejectedStagingRequest`, `ClaimRejectedStagingResult`, `ClearStagingKeyRequest`, `ReconciliationProgress`).
  - Define `#[trait_variant::make(Send)]` traits (each requiring `Send + Sync + 'static`):
    - `TransferLimiter`
    - `ObjectStore` (`upload`, `read`, `promote_create_only`, `remove_staging`, `remove_ready_for_delete`)
    - `Store` (`reserve_artifact`, `record_begin_upload`, `record_verification`, `record_promotion`, `record_rejection`, `load_artifact`)
    - `TwoPhaseDeleteStore` (`mark_delete_pending`, `complete_deletion_with_tombstone`, `has_tombstone`)
    - `Classifier` (`classify`)
    - `CompletionContributor` (`commit_artifact`)
    - `ReconciliationStore` (`claim_incomplete`, `claim_large`, `record_progress`, `record_large_claim`, `expire_staging`, `release_large_claim`, `claim_rejected_staging`, `clear_staging_key`)
    - `ProduceEdgeStore` (`insert_produce_edge`)
    - `ReadEdgeStore` (`insert_read_edge`)
    - `LineageReader` (`produce_edge_for_artifact`, `read_edges_for_artifact`, `read_edges_for_node`, `produce_edges_for_node`, `produce_edges_for_run`, `read_edges_for_run`)
    - `ReadStore` (`find_artifact`, `resolve_produced`, `declared_scope`, `run_produced_artifacts`)
  - In `query.rs`, define `ArtifactSummaryRead` (`#[trait_variant::make(Send)]`), `ArtifactListRequest` (`workspace_id`, `task_id`, `cursor: Option<ArtifactSeekCursor>`, bounded `page_size` default 100 / max 250), `ArtifactSeekCursor { updated_at: OffsetDateTime, artifact_id: ArtifactId }`, and `ArtifactSummaryView` (exposing no object keys, staging generations, or authority tokens) per `rust-application-boundaries.md` §2.3 & §3.4.

- [ ] **Step 3: Port unit tests from `lineage_test.go` for pure lineage validation, `parse_attempt_scope`, and `query.rs` bounds**
  - Verify `ReadEdge` reader-pair mismatch rejection, checksum hex validation, `parse_attempt_scope` parsing for operator (`""`) and `<run>:<node>:<attempt>` triples, `ReadAuthorization::edge()` construction, and `ArtifactListRequest` page-size clamping/validation.

- [ ] **Step 4: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-artifact --all-targets -- -D warnings && cargo test -p central-artifact`
  - Commit: `feat(artifact): add b34 lineage model and capability port/query contracts`

---

### Task 3: `central-artifact` Application Services (`classifier.rs`, `reconciler.rs`, `app.rs`)

**Files:**
- Create: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/classifier.rs`
- Create: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/reconciler.rs`
- Create: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/app.rs`
- Modify: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/lib.rs`

**Reference files (read-only):**
- `$CENTRAL_SRC/internal/artifact/app/classifier.go`
- `$CENTRAL_SRC/internal/artifact/app/classifier_test.go`
- `$CENTRAL_SRC/internal/artifact/app/service.go`
- `$CENTRAL_SRC/internal/artifact/app/service_test.go`
- `$CENTRAL_SRC/internal/artifact/app/reconciler.go`
- `$CENTRAL_SRC/internal/artifact/app/reconciler_test.go`
- `$CENTRAL_SRC/internal/artifact/app/reconciler_resume_test.go`
- `$CENTRAL_RUST_SRC/docs/architecture/rust-application-boundaries.md` (§2.4 lines 162–169, §3.4 lines 350–355)

- [ ] **Step 1: Implement `crates/capabilities/central-artifact/src/classifier.rs`**
  - Port `ReportClassifier` (`CLASSIFY_PREFIX_BYTES = 1 << 20`, `MEDIA_TYPE_MARKDOWN = "text/markdown"`, `MEDIA_TYPE_PLAIN = "text/plain"`, `MEDIA_TYPE_OCTET_STREAM = "application/octet-stream"`).
  - Port `contains_secret_disclosure(sample: &[u8]) -> bool` covering all four upstream heuristic families:
    1. PEM private key headers (`-----BEGIN PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN OPENSSH PRIVATE KEY-----`, `-----BEGIN PGP PRIVATE KEY BLOCK-----`).
    2. Credential environment assignments (`AWS_SECRET_ACCESS_KEY=`, `MINIO_ROOT_PASSWORD=`, `POSTGRES_PASSWORD=`, `OPENAI_API_KEY=`, `ANTHROPIC_API_KEY=`) with non-placeholder values.
    3. Provider/platform token prefixes (`sk-ant-`, `sk-`, `AKIA`, `ASIA`, `xoxb-`, `xoxp-`, `ghp_`, `gho_`, `github_pat_`, `glpat-`) at word boundaries followed by $\ge 16$ unbroken token characters.
    4. Credentialed URLs (`scheme://user:secret@host`) with non-placeholder secrets.
  - Port UTF-8, NUL-byte, and Markdown block/link sniffing (`looks_like_markdown`) and `normalize_media_type`.

- [ ] **Step 2: Implement `crates/capabilities/central-artifact/src/app.rs`**
  - Port `ObjectFailureClass` (`Invalid`, `NotFound`, `Conflict`, `Denied`, `LimitExceeded`, `Unavailable`, `Ambiguous`) and `ObjectFailureClassifier` trait.
  - Port `Service`:
    - `materialize_required_report(&self, req: MaterializeRequest) -> Result<Outcome, Failure>`:
      1. `Reserve` → `store.reserve_artifact`
      2. `BeginUpload` → `store.record_begin_upload` → `objects.upload` (known non-delivery immediately calls `reject_staged` with `FAILURE_CODE_UPLOAD_NON_DELIVERY` to release quota reservation)
      3. `verify_staged_body` (reads staged object bounded to `max_bytes + 1`, rejects durably with `FAILURE_CODE_SIZE_LIMIT_EXCEEDED` on stream-cap breach, runs `classifier.classify`) → `Verified` → `store.record_verification`
      4. `Promotion` → `store.record_promotion` → `objects.promote_create_only` (treating `ObjectFailureClass::Conflict` as idempotent fallthrough to second verification)
      5. `verify_ready_object` (re-reads ready object, verifies exact size, SHA-256 checksum, and object version/ETag when exposed)
      6. `Finalize` → `completion.commit_artifact` (mapping `FailureKind::Ambiguous` or `FailureKind::Cancelled` to `Outcome { kind: OutcomeKind::Reconciliation, failure_code: FAILURE_CODE_OBJECT_AMBIGUOUS }`)
    - `resume_verifying(&self, current: Artifact) -> Result<ResumeResult, Failure>` (non-interactive crash recovery for `verifying` records, using deterministic `resume_receipt_key` with `"central.b10.reconcile-finalize/v1"` and empty `ExecutionChangeSet`).
    - `deliver_ready_artifact(&self, req: DeliverReadyArtifactRequest) -> Result<DeliverArtifactOutcome, Failure>` (enforcing workspace ownership match, `State::Ready`, `delete_intent_at.is_none()`, and `verified_size <= limits.max_bytes` before touching `objects.read`).
    - `prepare_authorized_download(&self, req: AuthorizedDownloadRequest) -> Result<AuthorizedDownload, Failure>` and one-shot `!Clone` `AuthorizedDownload::start(self) -> Result<StartedDownload, Failure>` ([rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §2.4/§3.4): validates initial durable snapshot, and on `start(self)` (consuming `self` by value so a second call is impossible at compile time) performs final revalidation via `deliver_ready_artifact` and returns `(Box<dyn ByteStream>, SafeMediaType, u64, Disposition)`.
    - `delete_artifact_two_phase(&self, req: TwoPhaseDeleteRequest) -> Result<ArtifactTombstone, Failure>`: marks artifact `delete_pending` durably (`mark_delete_pending`), removes the object body (`remove_ready_for_delete`), and records `deleted` + `ArtifactTombstone` (`complete_deletion_with_tombstone`).
  - Port async lineage application operations from `lineage.go`: `record_produce`, `record_read`, `produced`, `read_by`, `ancestors` (BFS with cycle guard), `descendants` (BFS skipping operator reads), `run_lineage_for_run`, and `authorize_read` (declared scope union + in-run undeclared flag + operator scope).

- [ ] **Step 3: Implement `crates/capabilities/central-artifact/src/reconciler.rs`**
  - Port `Fence` (`generation`, `epoch_generation`, `claim_token`, `validate()`), `Budget` (`default_budget()`, `large_claim_budget()`, `normalize()`), `DEFAULT_STAGING_LIFETIME` (24h) / `HARD_STAGING_LIFETIME` (72h), `RECONCILE_THROUGHPUT_FLOOR_BYTES_PER_SECOND` (8 MiB/s), and `PassReport` using `std::time::{Duration, Instant}`.
  - Port `Reconciler::reconcile(&self, fence: &Fence) -> Result<PassReport, Failure>`:
    - Dedicated large-claim check (`claim_large` → `reconcile_claim` under `large_claim_budget()` → `release_large_claim`; if already resolved, continue to normal pass).
    - Normal pass: `sweep_rejected_staging` (sharing pass count and duration budgets, verifying `owns_staging_key` before `remove_staging` + `clear_staging_key`), followed by batch loop (`claim_incomplete` → per-item hard/soft budget check → `reconcile_claim` → `record_progress`).
    - `reconcile_claim`: load artifact, skip terminal/moved rows, defer to `record_large_claim` if `declared > remaining_bytes || declared > budget.max_bytes || declared > affordable_bytes(remaining_time)`, call `resume_verifying` for `State::Verifying`, or `expire_staging` + `remove_staging` + `clear_staging_key` for `State::Reserved` / `State::Staging`.

- [ ] **Step 4: Port unit tests from `classifier_test.go`, `service_test.go`, `reconciler_test.go`, `reconciler_resume_test.go`, and `lineage_test.go`**
  - Use in-memory fake implementations of `Store`, `TwoPhaseDeleteStore`, `ObjectStore`, `CompletionContributor`, `ReconciliationStore`, and `LineageReader` / `ReadStore` in `#[cfg(test)]` modules.
  - Cover all classifier secret-disclosure cases, full materialization happy path, upload non-delivery immediate rejection, size-cap rejection, secret-disclosure rejection, create-only conflict recovery, ready-object version mismatch, `resume_verifying` across both crash windows, `deliver_ready_artifact` and one-shot `AuthorizedDownload::start(self)` revalidation/denials, two-phase deletion with tombstone, reconciler budget enforcement, large-claim deferral, rejected-staging sweep, and lineage BFS graph walks.

- [ ] **Step 5: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-artifact --all-targets -- -D warnings && cargo test -p central-artifact`
  - Commit: `feat(artifact): implement classifier, lifecycle service, reconciler, and lineage operations`

---

### Task 4: `central-adapter-s3` S3/MinIO Object Store Adapter

**Files:**
- Modify: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/Cargo.toml`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/error.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/limiter.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/stream.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/store.rs`
- Modify: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/lib.rs`

**Reference files (read-only):**
- `$CENTRAL_SRC/internal/adapter/objectstore/minio.go`
- `$CENTRAL_SRC/internal/adapter/objectstore/minio_test.go`

- [ ] **Step 1: Configure `crates/adapters/central-adapter-s3/Cargo.toml`**
  - Add **only** workspace dependencies declared in root `Cargo.toml`: `central-foundation`, `central-artifact`, `aws-config`, `aws-sdk-s3`, `sha2`, `tokio`, `tokio-util`, `trait-variant`, `tracing`. Use `aws_sdk_s3::primitives::ByteStream` and `aws_sdk_s3::error::ProvideErrorMetadata` re-exports directly from `aws-sdk-s3`.

- [ ] **Step 2: Implement `error.rs` and `limiter.rs`**
  - In `error.rs`, implement `FailureClass` (`Invalid`, `NotFound`, `Conflict`, `Denied`, `LimitExceeded`, `Unavailable`, `Ambiguous`), `Reason` (`KeyRoleInvalid`, `LimitInvalid`, `ConfigInvalid`, `BodyMissing`, `ObjectMissing`, `PreconditionConflict`, `AccessDenied`, `LimitExceeded`, `IdleTimeout`, `TotalDeadline`, `Canceled`, `UpstreamRejected`, `TransferIncomplete`), and `Failure { op, class, reason }`.
  - Implement `ObjectFailureClassifier` for `S3FailureClassifier` so `central-artifact::app::Service` maps `Failure` to `ObjectFailureClass` without inspecting strings.
  - Ensure `Failure` **never** wraps or echoes raw `aws_sdk_s3` error messages, bucket names, object keys, or endpoints (`"objectstore: {op} {class} ({reason})"`).
  - In `limiter.rs`, implement `TransferLimiter` backed by `Arc<tokio::sync::Semaphore>` initialized with `MAX_CONCURRENT_TRANSFERS` (`2`), returning an idempotent `TransferPermit` guard (`OwnedSemaphorePermit`) that releases on drop or explicit `release()`.

- [ ] **Step 3: Implement `stream.rs` and `store.rs`**
  - Validate key roles before any network call: `is_staging_key` (`"v1/staging/"`), `is_ready_key` (`"v1/ready/"`), rejecting empty keys, leading `/`, or `".."`.
  - Implement `STAGING_PART_SIZE_BYTES = 5 * 1024 * 1024` (5 MiB S3 multipart floor).
  - Implement bounded streaming helpers:
    - Upload reader wrapper tracking byte progress, enforcing `max_bytes + 1` ceiling sentinel (`Reason::LimitExceeded`), 60s idle watchdog (`Reason::IdleTimeout`), and 10m total deadline (`Reason::TotalDeadline`).
    - For streaming staging `upload`: stream in 5 MiB chunks (single `put_object` with `if_none_match("*")` when total body fits in a single part $\le 5\text{ MiB}$, or multipart upload `create_multipart_upload` + `upload_part` 5 MiB parts + `complete_multipart_upload`, calling `abort_multipart_upload` on over-limit/failure so an over-limit body is never committed).
    - `read`: acquire transfer permit, issue `get_object`, wrap returned `ByteStream` in a `PermitStream` implementing `central_artifact::port::ByteStream` that holds the semaphore permit until closed or terminated by idle/total timeout.
    - `promote_create_only`: acquire permit, read staging object via `get_object`, validate `0 <= size <= MAX_ARTIFACT_BODY_BYTES`, execute a single-request `put_object` to the `v1/ready/...` key with `.if_none_match("*")` (never `copy_object` and never `head_object` + write), then `head_object` (`stat`) the created ready object to return authoritative `ObjectInfo { size, etag, version }`.
    - `restore_body_create_only`: single-PUT create-only upload to a `v1/ready/...` key with exact known size and `.if_none_match("*")` + read-back `head_object` evidence (for ADR 0034 restore parity).
    - `remove_staging`: refuse any non-staging key (`Reason::KeyRoleInvalid`), then call `delete_object`.
    - `remove_ready_for_delete`: refuse any non-ready key (`Reason::KeyRoleInvalid`), used exclusively by two-phase deletion / prune after `delete_pending` or tombstone metadata commits.
    - `open_backup_throughput_fixture`: read `v1/system/backup-throughput-fixture-v1` and require exact size `512 * 1024 * 1024`.

- [ ] **Step 4: Port unit and mock/local-HTTP S3 tests from `minio_test.go`, plus gated live MinIO integration test**
  - Test key-role validation (`v1/staging/` vs `v1/ready/`, path traversal `".."` rejection), `TransferLimiter` concurrency cap at 2, over-limit stream cutoff at `max_bytes + 1` without committing, idle stall timeout classification into `AMBIGUOUS (idle_timeout)`, HTTP status code classification (`404` -> `NOT_FOUND`, `412`/`409` -> `CONFLICT`, `401`/`403` -> `DENIED`, `400`/`405`/`411`/`413` -> `UNAVAILABLE`, `500` -> `AMBIGUOUS`), and locator-free error strings.
  - Add a MinIO integration test gated on `CENTRAL_TEST_MINIO_ENDPOINT` (following `rust-engineering-workflow.md` §4 Tier 2 rules) exercising `upload` → `read` → `promote_create_only` (including second-call `CONFLICT` precondition proof) → `remove_staging`.

- [ ] **Step 5: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-adapter-s3 --all-targets -- -D warnings && cargo test -p central-adapter-s3`
  - Commit: `feat(adapter-s3): implement S3/MinIO ObjectStore and bounded TransferLimiter`

---

### Task 5: `central-adapter-postgres::artifact` Core Lifecycle Store, Two-Phase Deletion, `ArtifactSummaryRead` & Atomic `CompletionContributor`

**Files:**
- Modify: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/Cargo.toml`
- Modify: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/lib.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/artifact/mod.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/artifact/queries.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/artifact/store.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/artifact/commit.rs`

**Reference files (read-only):**
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/queries.go`
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/store.go`
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/store_test.go`
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/identity_fingerprint_test.go`
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/reserve_replay_test.go`
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/quota_lock_test.go`
- `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/execution/store.rs`

- [ ] **Step 1: Wire `central-artifact` into `central-adapter-postgres` and implement canonical receipt fingerprinting (`queries.rs`)**
  - Add `central-artifact = { path = "../../capabilities/central-artifact", version = "0.1.0" }` to `crates/adapters/central-adapter-postgres/Cargo.toml` and `pub mod artifact;` to `src/lib.rs`.
  - Port `command_receipt_key` and `canonical_identity_hash(id: &CommandIdentity) -> [u8; 32]` in `artifact/queries.rs` with the exact JSON field layout (`stage`, `workspace_id`, `artifact_id`, `expected_version`, `staging_generation`, `content_generation`, `ready_key`, `verified_size`, `verified_checksum`, `idempotency_key`, `failure_code` with `skip_serializing_if = "String::is_empty"`, `reserve_fingerprint` with `skip_serializing_if = "String::is_empty"`).
  - Port `RECEIPT_TTL = 7 * 24 * 3600s` and `lookup_artifact_receipt` / `insert_artifact_receipt` against `central.artifact_command_receipts`.

- [ ] **Step 2: Implement `Store`, `TwoPhaseDeleteStore`, and `ArtifactSummaryRead` in `artifact/store.rs` using `sqlx::query!` / `sqlx::query_as!`**
  - `reserve_artifact`:
    - Check `artifact_command_receipts` for `"reserve"`; on exact fingerprint match, reload and return the stored `Artifact`; on mismatch, return `FailureKind::Conflict ("IDEMPOTENCY_FINGERPRINT_MISMATCH")`.
    - Lock workspace quota row with `SELECT quota_ready_bytes, quota_max_bytes FROM central.workspaces WHERE id = $1 FOR NO KEY UPDATE` (using `FOR NO KEY UPDATE` to prevent FK key-share deadlocks against concurrent execution commits).
    - Sum active reservations (`SELECT COALESCE(SUM(reserved_bytes), 0)::bigint FROM central.capacity_reservations WHERE workspace_id = $1 AND state = 'reserved'`).
    - Enforce `ready_bytes + reserved_sum + (limits.max_bytes * 2) <= max_bytes`, returning `FailureKind::Denied ("QUOTA_EXCEEDED")` if exceeded.
    - Insert into `central.artifacts`, `central.capacity_reservations` (`reserved_bytes = limits.max_bytes * 2`), and `central.artifact_command_receipts` in one transaction.
  - `record_begin_upload`: receipt check/replay, `FOR UPDATE` row lock, version + `reserved` state guard, update to `staging`, insert receipt.
  - `record_verification`: receipt check/replay (reconstructing `Outcome` from `rejection` JSONB on replay), `FOR UPDATE` row lock, version + `staging` state guard, update `size`, `checksum_value`, `checksum_algorithm = 'sha256'`, `rejection`, and when `State::Rejected`, release capacity reservation (`state = 'released'`, `released_at = clock_timestamp()`), insert receipt.
  - `record_promotion`: receipt check/replay, `FOR UPDATE` row lock, version + `verifying` state + empty `ready_key` guard, update `content_generation` and `ready_key`, insert receipt.
  - `record_rejection`: receipt check/replay, `FOR UPDATE` row lock, version + `reserved`/`staging` state guard, update to `rejected` + release capacity reservation in one transaction, insert receipt.
  - `load_artifact`: read snapshot and map to `central_artifact::domain::Artifact`.
  - `TwoPhaseDeleteStore`:
    - `mark_delete_pending`: lock `central.artifacts` row `FOR UPDATE`, verify `state = 'ready'` and expected version, update `state = 'delete_pending', delete_intent_at = COALESCE(delete_intent_at, clock_timestamp()), version = version + 1, updated_at = clock_timestamp()` (executable under `central_runtime`).
    - `complete_deletion_with_tombstone`: lock workspace quota row `FOR NO KEY UPDATE` and artifact row `FOR UPDATE`, insert into `central.artifact_tombstones ... ON CONFLICT (workspace_id, artifact_id) DO NOTHING`, transition `central.artifacts` to `state = 'deleted', deleted_at = clock_timestamp(), version = version + 1`, and decrement `central.workspaces` (`quota_ready_bytes = GREATEST(0, quota_ready_bytes - $2), quota_ready_count = GREATEST(0, quota_ready_count - 1)`) when the artifact was not already `'deleted'` (executed under migration/owner authority in tests and R6 prune).
    - `has_tombstone`: `SELECT EXISTS(SELECT 1 FROM central.artifact_tombstones WHERE workspace_id = $1 AND artifact_id = $2)` (executable under `central_runtime`).
  - `ArtifactSummaryRead`: seek-paginated query on `central.artifacts` using `artifacts_task_id_idx` (`WHERE workspace_id = $1 AND task_id = $2 AND ($3::timestamptz IS NULL OR (updated_at, id) < ($3, $4)) ORDER BY updated_at DESC, id DESC LIMIT $5`).

- [ ] **Step 3: Implement `CompletionContributor::commit_artifact` in `artifact/commit.rs`**
  - Port `b10_supported_execution_change` validation (rejecting tool calls/approvals/checkpoints/leases/assertions/reconciliations, requiring `settlements.len() == 1` and `lease_releases.len() == 1` with matching `(workspace_id, run_id)` when settling an attempt, or empty execution change set for reconciler resume).
  - Reuse `central-adapter-postgres::execution`'s transaction opener (`execution::begin` with `synchronous_commit = on`) and encoding helpers (`uuid_for_invocation`, `invocation_generation`, `go_json_escapes`, `go_rfc3339_local`, `reserve_event_sequence`, `upsert_outbox_workspace_work`).
  - Enforce the exact lock ordering inside the single PostgreSQL transaction:
    0. `central.workspace_event_counters` (`FOR UPDATE`, when task or execution events are present)
    1. `central.workspaces` (`FOR NO KEY UPDATE` quota lock)
    2. `central.tasks` (`FOR UPDATE` + expected version check)
    3. `central.runs` (`FOR UPDATE` + expected version check)
    4. `central.execution_ownership` lease fence (`fence_completion_lease`: verify `lease_token_hash`, `fencing_generation`, and `lease_expires_at > clock_timestamp()`, releasing the lease or failing with `STALE_LEASE_FENCE`)
    5. `central.steps` and `central.step_attempts` (`FOR UPDATE` + version checks)
    6. `central.artifacts` (`FOR UPDATE` + version, `verifying` state, `ready_key`/`content_generation` match, and producer chain match against Task/Run/Step/Attempt)
    7. `central.capacity_reservations` (`FOR UPDATE`, must be `'reserved'`, plus defensive `ready_bytes + verified_size <= max_bytes` check)
  - Apply mutations atomically: transition artifact to `'ready'` (binding `ready_object_version`), settle capacity reservation (`'settled'`), charge workspace quota (`quota_ready_bytes + verified_size`, `quota_ready_count + 1`), apply task/run/step/attempt updates, append task events (formatting absent `run_id` as `""` in `"task:{task_id}:{task_version}:{kind}:{run_id}"` outbox deduplication keys, matching upstream `zeroRun`) and execution events + `central.outbox` rows, and insert the `"finalize"` command receipt.

- [ ] **Step 4: Port unit and `CENTRAL_TEST_DSN` PostgreSQL integration tests**
  - Port fingerprint canonicalization tests (`identity_fingerprint_test.go`) and PostgreSQL integration tests (`store_test.go`, `reserve_replay_test.go`, `quota_lock_test.go`) covering reserve quota enforcement, `2 * MaxBytes` peak accounting, capacity release on verify/explicit reject, idempotent command replays and fingerprint conflicts, two-phase deletion + tombstone idempotency + quota release, `ArtifactSummaryRead` seek pagination, atomic finalize + task completion under a live B08 lease, and `STALE_LEASE_FENCE` refusal when a lease is superseded.

- [ ] **Step 5: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-adapter-postgres --all-targets -- -D warnings && cargo test -p central-adapter-postgres`
  - Commit: `feat(adapter-postgres): implement B10 artifact Store, two-phase delete, and CompletionContributor`

---

### Task 6: `central-adapter-postgres::artifact` Reconciliation Store & `b34` Lineage Store

**Files:**
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/artifact/reconcile.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/artifact/lineage_store.rs`
- Modify: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-postgres/src/artifact/mod.rs`
- Modify: `$CENTRAL_RUST_SRC/.sqlx/` (via `cargo sqlx prepare`)

**Reference files (read-only):**
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/store.go` (lines 1450–2089)
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/reconcile_store_test.go`
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/lineage_store.go`
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/lineage_store_test.go`
- `$CENTRAL_SRC/internal/adapter/postgres/artifact/explain_test.go`

- [ ] **Step 1: Implement `ReconciliationStore` in `artifact/reconcile.rs`**
  - `claim_incomplete`: round-robin workspace seek (`queryNextIncompleteWorkspace`, `queryWorkspaceHasIncompleteAfterCursor`, and per-state index scan `queryScanIncompleteByWorkspaceAndState` over `('reserved', 'staging', 'verifying')` with `MAX_SKIPPED_WORKSPACES_PER_CALL = 64`), acquiring per-artifact claims in `central.artifact_reconciliation_claims` with `claim_token_hash = sha256(claim_token)` and database-derived `clock_timestamp()` lease expiry.
  - `claim_large` and `release_large_claim` (**SB-G4 `central_runtime` privilege fix**):
    - Because `0014_b10_artifact_lifecycle.sql` grants `SELECT, INSERT, UPDATE` (and not `DELETE`) on `central.artifact_reconciliation_claims` to `central_runtime`, demote resolved large claims in `claim_large` via:
      ```sql
      UPDATE central.artifact_reconciliation_claims c
      SET claim_kind = 'normal', lease_expires_at = clock_timestamp(), updated_at = clock_timestamp()
      WHERE c.claim_kind = 'large'
        AND NOT EXISTS (
          SELECT 1 FROM central.artifacts a
          WHERE a.workspace_id = c.workspace_id AND a.id = c.artifact_id
            AND a.state NOT IN ('ready', 'rejected')
        )
      ```
      and demote released claims in `release_large_claim` via:
      ```sql
      UPDATE central.artifact_reconciliation_claims
      SET claim_kind = 'normal', lease_expires_at = clock_timestamp(), updated_at = clock_timestamp()
      WHERE workspace_id = $1 AND artifact_id = $2 AND claim_kind = 'large'
      ```
      This requires only `UPDATE` privilege (admitted for `central_runtime` under ADR 0028 D3 without altering any migration checksum or wire format), prevents `queryLockOldestLargeClaim` (`WHERE c.claim_kind = 'large'`) from ever re-selecting a resolved or released claim, and allows the normal cursor (`ClaimIncomplete`) to re-observe and re-defer any still-incomplete artifact on the next cycle.
  - `record_large_claim`: verify active claim via constant-time `claim_token_hash` comparison and `lease_expires_at > clock_timestamp()`, verify artifact version, and upsert `claim_kind = 'large'` with `lease_expires_at = clock_timestamp()`.
  - `expire_staging`: verify active claim, lock artifact row, compare age in SQL via `SELECT created_at < clock_timestamp() - make_interval(secs => $3::double precision) FROM central.artifacts WHERE workspace_id = $1 AND id = $2` (never using caller wall clock), evaluate domain `reject`, apply rejection + capacity release + `"reject"` receipt idempotently.
  - `claim_rejected_staging` (`WHERE staging_key IS NOT NULL AND state = 'rejected' ORDER BY workspace_id, staging_key LIMIT $1`), `clear_staging_key` (`UPDATE central.artifacts SET staging_key = NULL ... WHERE state = 'rejected'`), and `record_progress` (`central.artifact_reconciliation_progress`).

- [ ] **Step 2: Implement `b34` Lineage Stores in `artifact/lineage_store.rs`**
  - Implement `ProduceEdgeStore::insert_produce_edge` (`INSERT INTO central.artifact_produce_edges ... ON CONFLICT (artifact_id) DO NOTHING`, falling back to `SELECT` on conflict for idempotent replay).
  - Implement `ReadEdgeStore::insert_read_edge` (`INSERT INTO central.artifact_read_edges ... ON CONFLICT (run_id, reader_node_id, attempt_id, artifact_id) DO NOTHING`, falling back to `SELECT` when `reader_node_id IS NOT NULL` so attempt-scoped reads dedupe while operator `NULL` reads append distinct rows).
  - Implement `LineageReader` (`produce_edge_for_artifact`, `read_edges_for_artifact`, `read_edges_for_node`, `produce_edges_for_node`, `produce_edges_for_run`, `read_edges_for_run`).
  - Implement `ReadStore` (`find_artifact`, `resolve_produced` joining `artifact_produce_edges`, `workflow_nodes`, and `artifacts`, `declared_scope` unioning `workflow_edges` of `kind = 'artifact'` with `workflow_nodes.input_artifact_refs` JSONB UUIDs, and `run_produced_artifacts`).

- [ ] **Step 3: Port PostgreSQL integration tests from `reconcile_store_test.go`, `lineage_store_test.go`, and `explain_test.go`**
  - Verify round-robin workspace cursor progression, skip-budget bounding (`64` workspaces), DB-clock staging expiry, large-claim promotion/demotion under `central_runtime` privileges (proving `claim_large` and `release_large_claim` succeed without `DELETE` privilege), rejected-staging key clearing, idempotent `artifact_produce_edges` and `artifact_read_edges` inserts, operator vs. attempt-scoped read edge uniqueness, `declared_scope` JSONB parsing, and `EXPLAIN` index-scan plan assertions on `artifacts_state_expiry_idx` and `artifacts_workspace_staging_key_unique_idx`.

- [ ] **Step 4: Regenerate `.sqlx/` offline metadata and commit**
  - Run `cargo sqlx prepare --workspace -- --all-targets` against the live test database so all new `central-adapter-postgres::artifact` queries are recorded in `.sqlx/`.
  - Run: `cargo sqlx prepare --workspace --check -- --all-targets && cargo fmt --all -- --check && cargo clippy -p central-adapter-postgres --all-targets -- -D warnings && cargo test -p central-adapter-postgres`
  - Commit: `feat(adapter-postgres): implement artifact ReconciliationStore, b34 lineage stores, and sqlx metadata`

---

### Task 7: `central-kernel` Supervision Wiring, Full 5-Stage Verification Gate & Phase R2 Closeout

**Files:**
- Modify: `$CENTRAL_RUST_SRC/crates/central-kernel/Cargo.toml`
- Modify: `$CENTRAL_RUST_SRC/crates/central-kernel/src/lib.rs`
- Modify: `$CENTRAL_RUST_SRC/docs/implementation/current-phase.md`

**Reference files (read-only):**
- `$CENTRAL_RUST_SRC/crates/central-kernel/src/lifecycle.rs`
- `$CENTRAL_RUST_SRC/docs/architecture/rust-application-boundaries.md` (§2.2 line 112)
- `$CENTRAL_RUST_SRC/docs/implementation/rust-engineering-workflow.md`

- [ ] **Step 1: Wire `central-artifact` and `central-adapter-s3` into `central-kernel`**
  - Add `central-artifact` and `central-adapter-s3` to `crates/central-kernel/Cargo.toml`.
  - Following the Kernel-edge rule ([rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §2.2 line 112), implement a kernel-owned `ArtifactReconcilerComponent` wrapper in `central-kernel` implementing `lifecycle::Component` that drives `central_artifact::reconciler::Reconciler::reconcile` on a bounded `tokio::time::Interval` ticker until future drop / `CancellationToken` cancellation and settles cleanly within `DEFAULT_SETTLEMENT`.
  - Add a deterministic unit test in `central-kernel` proving `ArtifactReconcilerComponent` starts under `Profile`, executes reconciliation passes, and settles cleanly on profile shutdown.

- [ ] **Step 2: Update `docs/implementation/current-phase.md` to record R2 completion and advance active slice to R3**
  - Move Phase R2 to the **Completed** section with a summary of delivered crates (`central-foundation` UUIDv4 generation/edge IDs, `central-artifact`, `central-adapter-s3`, `central-adapter-postgres::artifact`, `central-kernel` reconciler supervision, `.sqlx/` metadata) and mark **Phase R3 — Harness Control Plane & `central serve`** as the active slice in the status table.

- [ ] **Step 3: Execute the mandatory 5-stage verification pipeline (`rust-engineering-workflow.md` §7)**
  - Stage 1 (SQLx offline metadata check):
    `cargo sqlx prepare --workspace --check -- --all-targets`
  - Stage 2 (Formatting gate):
    `cargo fmt --all -- --check`
  - Stage 3 (Static analysis & lint gate):
    `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - Stage 4 (Supply-chain, license & ban gate):
    `cargo deny check`
  - Stage 5 (Workspace unit & integration test suite):
    `cargo test --workspace --all-targets` (including `CENTRAL_TEST_DSN` PostgreSQL integration tests and `CENTRAL_TEST_MINIO_ENDPOINT` S3/MinIO integration tests when local infra is running)

- [ ] **Step 4: Commit Phase R2 closeout**
  - Commit: `docs(phase-r2): mark Phase R2 complete and advance active slice to Phase R3`
