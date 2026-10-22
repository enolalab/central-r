# Phase R2 — Verified Artifact Lifecycle & Object Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete, verified Phase R2 vertical slice in `$CENTRAL_RUST_SRC` per [rust-vertical-slice-roadmap.md](../../implementation/rust-vertical-slice-roadmap.md) §5: implement `central-artifact` (`domain.rs`, `lineage.rs`, `port.rs`, `query.rs`, `app.rs`, `classifier.rs`, `reconciler.rs`), `central-adapter-s3` (S3/MinIO `ObjectStore` and process-wide `TransferLimiter`), and `central-adapter-postgres::artifact` (`Store`, `CompletionContributor`, `ReconciliationStore`, and `b34` lineage stores), wire `central-kernel` supervision for artifact reconciliation, regenerate `.sqlx/` offline metadata, and pass all 5 stages of the verification pipeline plus deterministic PostgreSQL and MinIO integration suites.

**Architecture:**
- **Compiler-enforced Cargo Workspace DAG ([rust-application-boundaries.md](../../architecture/rust-application-boundaries.md) §2):**
  - `crates/capabilities/central-artifact` depends only on `central-foundation` and `central-execution` (one-way, for `ExecutionChangeSet` completion-guard types; `central-execution` never imports `central-artifact`).
  - `central-artifact::domain` and `central-artifact::lineage` (pure domain transition/validation logic) are 100% synchronous Rust with zero `tokio`, `sqlx`, or `aws-sdk-s3` dependencies.
  - `central-artifact::port` defines `#[trait_variant::make(Send)]` async traits (`ObjectStore`, `TransferLimiter`, `Store`, `Classifier`, `CompletionContributor`, `ReconciliationStore`, `ProduceEdgeStore`, `ReadEdgeStore`, `LineageReader`, `ReadStore`) and read-projection types (`central-artifact::query`).
  - `central-artifact::app` coordinates the B10 verified lifecycle (`MaterializeRequiredReport`, `ResumeVerifying`, `DeliverReadyArtifact`), untrusted-body content classification (`ReportClassifier`), and B08-fenced orphan/expiry reconciliation (`Reconciler`).
  - `crates/adapters/central-adapter-s3` is the sole workspace consumer of `aws-sdk-s3` and `aws-config`. It enforces `MaxConcurrentTransfers = 2`, a 5 MiB S3 multipart part-size floor (`StagingPartSizeBytes`) on streaming staging uploads, a single conditional `PUT` with `If-None-Match: "*"` on ready promotion (`PromoteCreateOnly` and `RestoreBodyCreateOnly`), 60s idle / 10m total transfer watchdogs, and locator-free `ObjectFailureClass` error sanitization.
  - `crates/adapters/central-adapter-postgres/src/artifact/` implements `Store` (workspace quota admission under `FOR NO KEY UPDATE` reserving `2 * MaxBytes` peak capacity, stage transitions, and 7-day `artifact_command_receipts`), `CompletionContributor` (`CommitArtifact` atomic ready transition + quota settlement + B08 lease-fenced `ExecutionChangeSet` settlement following the canonical `EventCounter -> Quota -> Task -> Run -> execution_ownership -> Step -> Attempt -> Artifact -> capacity_reservations` lock ladder), `ReconciliationStore` (`artifact_reconciliation_claims`, `artifact_reconciliation_progress`, DB-clock staging expiry, rejected-staging cleanup), and `b34` lineage stores (`artifact_produce_edges`, `artifact_read_edges`).
  - **Phase R2 vs. Phase R4 Boundary ([rust-vertical-slice-roadmap.md](../../implementation/rust-vertical-slice-roadmap.md) §2, §5, §7):** R2 delivers the complete `b10` artifact lifecycle and the `b34` lineage domain + PostgreSQL stores (`ProduceEdgeStore`, `ReadEdgeStore`, `LineageReader`, `ReadStore`). Attempt-scoped `FinalizeAttemptArtifact` (which journals `artifact_finalized` into `b33` `central.run_events` and keys `b37` `central.artifact_finalizations`) and the `central artifact read` CLI verb land in Phase R4 alongside `central-eventjournal` and `central-workflow`.

**Tech Stack:** Rust stable (`rust-toolchain.toml`), `tokio` v1 (`sync`, `time`, `io-util`), `trait-variant` v0.1, `aws-sdk-s3` v1 + `aws-config` v1 + `aws-smithy-types` / `aws-smithy-runtime-api` (confined to `central-adapter-s3`), `sqlx` v0.8 (`postgres`, `macros`, `uuid`, `time`, `json`), `uuid` v1 (`v4`, `v7`, `serde`), `sha2` v0.11, `subtle` / constant-time digest comparison, `serde` + `serde_json`, `time` v0.3, `tracing`.

## Global Constraints

- **Source of Truth:** `$CENTRAL_SRC` (read-only reference for exact domain transitions, canonical receipt fingerprint JSON layouts, SQL queries, S3 precondition semantics, classifier rules, and test scenarios).
- **Zero `unsafe`:** Every crate touched in R2 (`central-artifact`, `central-adapter-s3`, `central-adapter-postgres`, `central-kernel`, `bins/central`) enforces `unsafe_code = "forbid"` via workspace lints.
- **No Unwraps in Production Targets:** `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::todo`, and `clippy::dbg_macro` are `deny` across all non-test targets.
- **No Secret, Body, or Locator Leakage:** Neither `central-adapter-s3` nor `central-adapter-postgres::artifact` may include object keys, bucket names, S3 endpoints, raw body bytes, SQL text, or driver error strings in `Display` / `Error` outputs. Only closed `FailureClass` and `Reason` / `FailureCode` tokens cross adapter boundaries.
- **Every Task Ends Green:** Each task below runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, and commits before advancing.

---

## File Structure

```text
central-rust/
├── Cargo.toml                                          # Add "v4" feature to workspace `uuid` dependency for StagingGeneration/ContentGeneration/Edge IDs
├── .sqlx/                                              # Updated offline sqlx query metadata including central-adapter-postgres::artifact queries
├── crates/
│   ├── capabilities/
│   │   └── central-artifact/
│   │       ├── Cargo.toml
│   │       └── src/
│   │           ├── lib.rs                              # Re-exports domain, lineage, port, query, app
│   │           ├── domain.rs                           # Pure B10 state machine, StagingGeneration, ContentGeneration, DeriveReservationIdentity, Limits, Reserve/BeginUpload/Verified/Reject/Promotion/Finalize, CommandIdentity & fingerprints, two-phase delete/tombstone & delivery disposition rules
│   │           ├── lineage.rs                          # Pure b34 ProduceEdge, ReadEdge, ReadScope, ParseAttemptScope, LineageArtifact, ReadAuthorization, closed reason codes
│   │           ├── port.rs                             # #[trait_variant::make(Send)] traits: TransferLimiter, ObjectStore, Store, Classifier, CompletionContributor, ReconciliationStore, ProduceEdgeStore, ReadEdgeStore, LineageReader, ReadStore + transfer/reconcile constants
│   │           ├── query.rs                            # Seek-paginated artifact metadata & lineage read projections (SeekCursor, no OFFSET)
│   │           ├── classifier.rs                       # ReportClassifier: 1 MiB prefix inspection, secret-disclosure detector (PEM, env assignments, token prefixes, credentialed URLs), UTF-8/NUL/Markdown sniffing
│   │           ├── reconciler.rs                       # Reconciler: B08 Fence validation, DefaultBudget / LargeClaimBudget, sweep_rejected_staging, normal & dedicated large-claim passes, 8 MiB/s throughput floor deferral
│   │           └── app.rs                              # Service: MaterializeRequiredReport, ResumeVerifying, DeliverReadyArtifact, ObjectFailureClassifier, plus async lineage helpers (record_produce, record_read, authorize_read, ancestors, descendants, run_lineage_for_run)
│   ├── adapters/
│   │   ├── central-adapter-s3/
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── lib.rs                              # Public Config, S3ObjectStore, TransferLimiter, Failure, FailureClass, Reason
│   │   │       ├── error.rs                            # Closed FailureClass + Reason taxonomy and SDK error sanitizer (never wraps raw SDK error)
│   │   │       ├── limiter.rs                          # Process-wide counting semaphore TransferLimiter (MaxConcurrentTransfers = 2) with idempotent permit guard
│   │   │       ├── stream.rs                           # ProgressReader (+1 byte ceiling sentinel) and PermitStream (60s idle & 10m total deadline watchdogs)
│   │   │       └── store.rs                            # S3ObjectStore implementing ObjectStore (upload multipart 5 MiB parts, read, promote_create_only single PUT If-None-Match: *, restore_body_create_only, remove_staging, open_backup_throughput_fixture)
│   │   └── central-adapter-postgres/
│   │       ├── Cargo.toml                              # Add central-artifact dependency
│   │       └── src/
│   │           ├── lib.rs                              # Export `pub mod artifact;`
│   │           └── artifact/
│   │               ├── mod.rs                          # PgArtifactStore wiring Store, CompletionContributor, ReconciliationStore, ProduceEdgeStore, ReadEdgeStore, LineageReader, ReadStore
│   │               ├── queries.rs                      # SQL constants and canonical receipt fingerprint helpers matching internal/adapter/postgres/artifact/{queries.go,store.go}
│   │               ├── store.rs                        # ReserveArtifact (FOR NO KEY UPDATE quota + 2x peak reservation), RecordBeginUpload, RecordVerification, RecordPromotion, RecordRejection, LoadArtifact
│   │               ├── commit.rs                       # CompletionContributor::commit_artifact (atomic finalize + quota settlement + B08 lease-fenced ExecutionChangeSet commit)
│   │               ├── reconcile.rs                    # ReconciliationStore (ClaimIncomplete round-robin workspace seek, ClaimLarge, RecordLargeClaim, ExpireStaging against DB clock_timestamp(), ReleaseLargeClaim, ClaimRejectedStaging, ClearStagingKey, RecordProgress)
│   │               └── lineage_store.rs                # b34 ProduceEdgeStore, ReadEdgeStore, LineageReader, ReadStore over artifact_produce_edges & artifact_read_edges
│   └── central-kernel/
│       ├── Cargo.toml                                  # Add central-artifact and central-adapter-s3 dependencies
│       └── src/
│           └── lib.rs                                  # Register supervised artifact reconciliation component hook in kernel composition root
```

---

### Task 1: `central-artifact` Pure Domain Root (`domain.rs`)

**Files:**
- Modify: `$CENTRAL_RUST_SRC/Cargo.toml`
- Modify: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/Cargo.toml`
- Create: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/domain.rs`
- Modify: `$CENTRAL_RUST_SRC/crates/capabilities/central-artifact/src/lib.rs`

**Reference files (read-only):**
- `$CENTRAL_SRC/internal/artifact/domain.go`
- `$CENTRAL_SRC/internal/artifact/domain_test.go`
- `$CENTRAL_SRC/internal/artifact/fingerprint_coverage_test.go`
- `$CENTRAL_RUST_SRC/docs/artifacts/lifecycle.md`
- `$CENTRAL_RUST_SRC/docs/artifacts/content-policy.md`

- [ ] **Step 1: Add `"v4"` feature to workspace `uuid` dependency and configure `central-artifact/Cargo.toml`**
  - In root `Cargo.toml`, update `uuid` under `[workspace.dependencies]` to `uuid = { version = "=1.23.1", features = ["v4", "v7", "serde"] }` (keeping the exact pinned version already in `Cargo.toml`).
  - In `crates/capabilities/central-artifact/Cargo.toml`, declare dependencies on `central-foundation`, `central-execution`, `serde`, `serde_json`, `sha2`, `time`, `tokio` (`io-util`, `sync`, `time`), `trait-variant`, and `uuid`.

- [ ] **Step 2: Implement `crates/capabilities/central-artifact/src/domain.rs` (pure synchronous Rust, zero `tokio` imports)**
  - Port `FailureClass` (`Invalid`, `Conflict`, `Denied`) and `Failure` (`class`, `reason: &'static str` / `String`) with `Display` formatting `"artifact: {} ({})"`.
  - Port `Limits` (`DEFAULT_REQUIRED_REPORT_MAX_BYTES = 1 << 20`, `HARD_REQUIRED_REPORT_MAX_BYTES = 10 << 20`, `validate()`).
  - Port RFC 9562 UUIDv4 generation newtypes `StagingGeneration` and `ContentGeneration` with strict lowercase 8-4-4-4-12 version-4 RFC 9562 validation (`new()`, `parse()`, `is_zero()`, `as_bytes()`, `from_trusted_db_bytes()`).
  - Port `derive_reservation_identity(operation_id: &str) -> Result<(ArtifactId, StagingGeneration), Failure>` using the exact domain-separated SHA-256 seeds `"central.b10.reservation-artifact-id/v1\x00"` (setting UUIDv7 version `0x70` and RFC 9562 variant `0x80` bits) and `"central.b10.reservation-staging-generation/v1\x00"` (setting UUIDv4 version `0x40` and RFC 9562 variant `0x80` bits) so deterministic reservation IDs match upstream byte-for-byte.
  - Port `State` (`Reserved`, `Staging`, `Verifying`, `Ready`, `Rejected`), `Sensitivity` (`Unrestricted`, `Restricted`, `Sensitive`), `Disposition` (`Inline`, `Attachment`), `Artifact` snapshot struct, and key derivation helpers `staging_key("v1/staging/{ws}/{art}/{gen}")` and `ready_key_for("v1/ready/{ws}/{art}/{gen}")`.
  - Port `CommandStage` (`Reserve`, `BeginUpload`, `Verify`, `Promote`, `Finalize`, `Reject`), `CommandIdentity`, `reserve_fingerprint(in: &ReserveInput) -> [u8; 32]` (matching the exact field order and `omitempty` semantics of upstream's `reserveFingerprint` JSON struct), `OutcomeKind` (`Ready`, `Retryable`, `Terminal`, `Reconciliation`), `Outcome`, closed `FAILURE_CODE_*` constants, `classifier_rejection_admitted`, and `rejection_outcome`.
  - Port pure lifecycle transition functions:
    - `reserve(ReserveInput) -> Result<ReserveResult, Failure>`
    - `begin_upload(BeginUploadInput) -> Result<BeginUploadResult, Failure>`
    - `verified(VerifiedInput) -> Result<VerifiedResult, Failure>`
    - `reject(RejectInput) -> Result<RejectResult, Failure>`
    - `promotion(PromotionInput) -> Result<PromotionResult, Failure>`
    - `finalize(FinalizeInput) -> Result<FinalizeResult, Failure>` and `new_finalize_identity`

- [ ] **Step 3: Port all unit tests from `domain_test.go` and `fingerprint_coverage_test.go`**
  - Verify state machine transitions, workspace chain mismatch denials, version conflicts, `derive_reservation_identity` determinism and collision separation, `reserve_fingerprint` sensitivity to every field (including `tool_call_attempt_id` and `required_role`), `verified` size/checksum/secret-disclosure/content-policy rejection precedence, and `finalize` identity verification.

- [ ] **Step 4: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-artifact --all-targets -- -D warnings && cargo test -p central-artifact`
  - Commit: `feat(artifact): implement B10 pure artifact lifecycle domain`

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

- [ ] **Step 1: Implement `crates/capabilities/central-artifact/src/lineage.rs` (pure synchronous domain types & validators)**
  - Port closed reason codes (`REASON_ARTIFACT_NOT_FINALIZED`, `REASON_ARTIFACT_SCOPE_DENIED`, `REASON_ARTIFACT_READ_UNRESOLVED`, `REASON_LINEAGE_READ_UNDECLARED`, `REASON_ARTIFACT_BODY_INTEGRITY`, `REASON_ARTIFACT_READ_AMBIGUOUS`).
  - Port `ProduceEdge` (`id`, `run_id: RunId`, `node_id: WorkflowNodeId`, `attempt_id: SessionAttemptId`, `artifact_id: ArtifactId`, `created_at: OffsetDateTime`) and its validation rules.
  - Port `ReadEdge` (`id`, `run_id: RunId`, `reader_node_id: Option<WorkflowNodeId>`, `attempt_id: Option<SessionAttemptId>`, `artifact_id: ArtifactId`, `declared: bool`, `checksum: String`, `created_at: OffsetDateTime`) enforcing the all-or-nothing `(reader_node_id, attempt_id)` pair check (`LINEAGE_READ_EDGE_READER_PAIR_MISMATCH`) and 64-char lowercase hex SHA-256 checksum validation (`LINEAGE_READ_EDGE_CHECKSUM_REQUIRED`).
  - Port `ReadScope` (`Attempt { run_id, node_id, attempt_id }` / `Operator`), `parse_attempt_scope(value: &str) -> Result<ReadScope, Failure>` (`"<run_id>:<node_id>:<attempt_id>"` or empty for operator), `LineageArtifact`, `ReadSelector` (`ByArtifactId(ArtifactId)` | `ByProduced { from_node_key: String, name: String }`), `ReadRequest`, `ReadAuthorization` (`edge()`), and `RunLineage`.

- [ ] **Step 2: Implement `crates/capabilities/central-artifact/src/port.rs` and `query.rs`**
  - Define process-wide transfer and ceiling constants from `internal/artifact/port/port.go`:
    - `MAX_CONCURRENT_TRANSFERS: usize = 2`
    - `TRANSFER_COPY_BUFFER_BYTES: usize = 256 * 1024`
    - `TRANSFER_IDLE_TIMEOUT: Duration = Duration::from_secs(60)`
    - `TRANSFER_TOTAL_DEADLINE: Duration = Duration::from_secs(10 * 60)`
    - `MAX_ARTIFACT_BODY_BYTES: i64 = 4 * 1024 * 1024 * 1024`
  - Define `ObjectRef`, `ObjectInfo`, `UploadRequest`, `UploadResult`, `ClassifyRequest`, `ClassifyResult`, `ArtifactCommandReceipt`, `ArtifactChangeSet`, `CommitResult`, and reconciliation DTOs (`ReconciliationCursor`, `IncompleteClaim`, `ClaimIncompleteRequest`, `ClaimIncompleteResult`, `ClaimLargeRequest`, `LargeClaim`, `RecordLargeClaimRequest`, `ExpireStagingRequest`, `ExpireStagingResult`, `ReleaseLargeClaimRequest`, `RejectedStagingClaim`, `ClaimRejectedStagingRequest`, `ClaimRejectedStagingResult`, `ClearStagingKeyRequest`, `ReconciliationProgress`).
  - Define `#[trait_variant::make(Send)]` traits:
    - `TransferLimiter`
    - `ObjectStore` (`upload`, `read`, `promote_create_only`, `remove_staging`)
    - `Store` (`reserve_artifact`, `record_begin_upload`, `record_verification`, `record_promotion`, `record_rejection`, `load_artifact`)
    - `Classifier` (`classify`)
    - `CompletionContributor` (`commit_artifact`)
    - `ReconciliationStore` (`claim_incomplete`, `claim_large`, `record_progress`, `record_large_claim`, `expire_staging`, `release_large_claim`, `claim_rejected_staging`, `clear_staging_key`)
    - `ProduceEdgeStore` (`insert_produce_edge`)
    - `ReadEdgeStore` (`insert_read_edge`)
    - `LineageReader` (`produce_edge_for_artifact`, `read_edges_for_artifact`, `read_edges_for_node`, `produce_edges_for_node`, `produce_edges_for_run`, `read_edges_for_run`)
    - `ReadStore` (`find_artifact`, `resolve_produced`, `declared_scope`, `run_produced_artifacts`)
  - In `query.rs`, define seek-paginated query projections (`ArtifactSummaryView`, `ArtifactSeekQuery` using `SeekCursor`, no `OFFSET`) per `rust-application-boundaries.md` §3.3.

- [ ] **Step 3: Port unit tests from `lineage_test.go` for pure lineage validation and `parse_attempt_scope`**
  - Verify `ReadEdge` reader-pair mismatch rejection, checksum hex validation, `parse_attempt_scope` parsing for operator (`""`) and `<run>:<node>:<attempt>` triples, and `ReadAuthorization::edge()` construction.

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
      6. `Finalize` → `completion.commit_artifact` (mapping context timeout/cancellation to `OutcomeReconciliation`)
    - `resume_verifying(&self, current: Artifact) -> Result<ResumeResult, Failure>` (non-interactive crash recovery for `verifying` records, using deterministic `resume_receipt_key` with `"central.b10.reconcile-finalize/v1"` and empty `ExecutionChangeSet`).
    - `deliver_ready_artifact(&self, req: DeliverReadyArtifactRequest) -> Result<DeliverArtifactOutcome, Failure>` (enforcing workspace ownership match, `State::Ready`, `delete_intent_at.is_none()`, and `verified_size <= limits.max_bytes` before touching `objects.read`).
  - Port async lineage application operations from `lineage.go`: `record_produce`, `record_read`, `produced`, `read_by`, `ancestors` (BFS with cycle guard), `descendants` (BFS skipping operator reads), `run_lineage_for_run`, and `authorize_read` (declared scope union + in-run undeclared flag + operator scope).

- [ ] **Step 3: Implement `crates/capabilities/central-artifact/src/reconciler.rs`**
  - Port `Fence` (`generation`, `epoch_generation`, `claim_token`, `validate()`), `Budget` (`default_budget()`, `large_claim_budget()`, `normalize()`), `DEFAULT_STAGING_LIFETIME` (24h) / `HARD_STAGING_LIFETIME` (72h), `RECONCILE_THROUGHPUT_FLOOR_BYTES_PER_SECOND` (8 MiB/s), and `PassReport`.
  - Port `Reconciler::reconcile(&self, fence: &Fence) -> Result<PassReport, Failure>`:
    - Dedicated large-claim check (`claim_large` → `reconcile_claim` under `large_claim_budget()` → `release_large_claim`; if already resolved, continue to normal pass).
    - Normal pass: `sweep_rejected_staging` (sharing pass count and duration budgets, verifying `owns_staging_key` before `remove_staging` + `clear_staging_key`), followed by batch loop (`claim_incomplete` → per-item hard/soft budget check → `reconcile_claim` → `record_progress`).
    - `reconcile_claim`: load artifact, skip terminal/moved rows, defer to `record_large_claim` if `declared > remaining_bytes || declared > budget.max_bytes || declared > affordable_bytes(remaining_time)`, call `resume_verifying` for `State::Verifying`, or `expire_staging` + `remove_staging` + `clear_staging_key` for `State::Reserved` / `State::Staging`.

- [ ] **Step 4: Port unit tests from `classifier_test.go`, `service_test.go`, `reconciler_test.go`, `reconciler_resume_test.go`, and `lineage_test.go`**
  - Use in-memory fake implementations of `Store`, `ObjectStore`, `CompletionContributor`, `ReconciliationStore`, and `LineageReader` / `ReadStore` in `#[cfg(test)]` modules.
  - Cover all classifier secret-disclosure cases, full materialization happy path, upload non-delivery immediate rejection, size-cap rejection, secret-disclosure rejection, create-only conflict recovery, ready-object version mismatch, `resume_verifying` across both crash windows (before and after `RecordPromotion`), `deliver_ready_artifact` guard denials, reconciler budget enforcement, large-claim deferral, rejected-staging sweep, and lineage BFS graph walks.

- [ ] **Step 5: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-artifact --all-targets -- -D warnings && cargo test -p central-artifact`
  - Commit: `feat(artifact): implement classifier, lifecycle service, reconciler, and lineage operations`

---

### Task 4: `central-adapter-s3` S3/MinIO Object Store Adapter

**Files:**
- Modify: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/Cargo.toml`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/error.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/limiter.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-artifact/src/...` (if any trait hooks needed)
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/stream.rs`
- Create: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/store.rs`
- Modify: `$CENTRAL_RUST_SRC/crates/adapters/central-adapter-s3/src/lib.rs`

**Reference files (read-only):**
- `$CENTRAL_SRC/internal/adapter/objectstore/minio.go`
- `$CENTRAL_SRC/internal/adapter/objectstore/minio_test.go`

- [ ] **Step 1: Configure `crates/adapters/central-adapter-s3/Cargo.toml`**
  - Add workspace dependencies: `central-artifact`, `aws-config`, `aws-sdk-s3`, `tokio` (`sync`, `time`, `io-util`, `rt`, `macros`), `trait-variant`, `tracing`.

- [ ] **Step 2: Implement `error.rs` and `limiter.rs`**
  - In `error.rs`, implement `FailureClass` (`Invalid`, `NotFound`, `Conflict`, `Denied`, `LimitExceeded`, `Unavailable`, `Ambiguous`), `Reason` (`KeyRoleInvalid`, `LimitInvalid`, `ConfigInvalid`, `BodyMissing`, `ObjectMissing`, `PreconditionConflict`, `AccessDenied`, `LimitExceeded`, `IdleTimeout`, `TotalDeadline`, `Canceled`, `UpstreamRejected`, `TransferIncomplete`), and `Failure { op, class, reason }`.
  - Implement `ObjectFailureClassifier` for `S3FailureClassifier` so `central-artifact::app::Service` maps `Failure` to `ObjectFailureClass` without inspecting strings.
  - Ensure `Failure` **never** wraps or echoes raw `aws_sdk_s3` error messages, bucket names, object keys, or endpoints (`"objectstore: {op} {class} ({reason})"`).
  - In `limiter.rs`, implement `TransferLimiter` backed by `Arc<tokio::sync::Semaphore>` initialized with `MAX_CONCURRENT_TRANSFERS` (`2`), returning an idempotent `TransferPermit` guard that releases on drop or explicit `release()`.

- [ ] **Step 3: Implement `stream.rs` and `store.rs`**
  - Validate key roles before any network call: `is_staging_key` (`"v1/staging/"`), `is_ready_key` (`"v1/ready/"`), rejecting empty keys, leading `/`, or `".."`.
  - Implement `STAGING_PART_SIZE_BYTES = 5 * 1024 * 1024` (5 MiB S3 multipart floor).
  - Implement bounded streaming helpers:
    - Upload reader wrapper tracking byte progress, enforcing `max_bytes + 1` ceiling sentinel (`Reason::LimitExceeded`), 60s idle watchdog (`Reason::IdleTimeout`), and 10m total deadline (`Reason::TotalDeadline`).
    - For streaming staging `upload`: stream in 5 MiB chunks (single `put_object` with `if_none_match("*")` when total body fits in a single part $\le 5\text{ MiB}$, or multipart upload `create_multipart_upload` + `upload_part` 5 MiB parts + `complete_multipart_upload`, calling `abort_multipart_upload` on over-limit/failure so an over-limit body is never committed).
    - `read`: acquire transfer permit, issue `get_object`, wrap returned `ByteStream` in a `PermitStream` that holds the semaphore permit until closed or terminated by idle/total timeout.
    - `promote_create_only`: acquire permit, read staging object via `get_object`, validate `0 <= size <= MAX_ARTIFACT_BODY_BYTES`, execute a single-request `put_object` to the `v1/ready/...` key with `.if_none_match("*")` (never `copy_object` and never `head_object` + write), then `head_object` (`stat`) the created ready object to return authoritative `ObjectInfo { size, etag, version }`.
    - `restore_body_create_only`: single-PUT create-only upload to a `v1/ready/...` key with exact known size and `.if_none_match("*")` + read-back `head_object` evidence (for ADR 0034 restore parity).
    - `remove_staging`: refuse any non-staging key (`Reason::KeyRoleInvalid`), then call `delete_object`.
    - `open_backup_throughput_fixture`: read `v1/system/backup-throughput-fixture-v1` and require exact size `512 * 1024 * 1024`.

- [ ] **Step 4: Port unit and mock/local-HTTP S3 tests from `minio_test.go`, plus gated live MinIO integration test**
  - Test key-role validation (`v1/staging/` vs `v1/ready/`, path traversal `".."` rejection), `TransferLimiter` concurrency cap at 2, over-limit stream cutoff at `max_bytes + 1` without committing, idle stall timeout classification into `AMBIGUOUS (idle_timeout)`, HTTP status code classification (`404` -> `NOT_FOUND`, `412`/`409` -> `CONFLICT`, `401`/`403` -> `DENIED`, `400`/`405`/`411`/`413` -> `UNAVAILABLE`, `500` -> `AMBIGUOUS`), and locator-free error strings.
  - Add a MinIO integration test gated on `CENTRAL_TEST_MINIO_ENDPOINT` (following `rust-engineering-workflow.md` §4 Tier 2 rules) exercising `upload` → `read` → `promote_create_only` (including second-call `CONFLICT` precondition proof) → `remove_staging`.

- [ ] **Step 5: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-adapter-s3 --all-targets -- -D warnings && cargo test -p central-adapter-s3`
  - Commit: `feat(adapter-s3): implement S3/MinIO ObjectStore and bounded TransferLimiter`

---

### Task 5: `central-adapter-postgres::artifact` Core Lifecycle Store & Atomic `CompletionContributor`

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

- [ ] **Step 1: Wire `central-artifact` into `central-adapter-postgres` and implement canonical receipt fingerprinting (`queries.rs`)**
  - Add `central-artifact.workspace = true` to `crates/adapters/central-adapter-postgres/Cargo.toml` and `pub mod artifact;` to `src/lib.rs`.
  - Port `command_receipt_key` and `canonical_identity_hash(id: &CommandIdentity) -> [u8; 32]` in `artifact/queries.rs` with the exact JSON field layout (`stage`, `workspace_id`, `artifact_id`, `expected_version`, `staging_generation`, `content_generation`, `ready_key`, `verified_size`, `verified_checksum`, `idempotency_key`, `failure_code` with `skip_serializing_if = "String::is_empty"`, `reserve_fingerprint` with `skip_serializing_if = "String::is_empty"`).
  - Port `RECEIPT_TTL = 7 * 24 * 3600s` and `lookup_artifact_receipt` / `insert_artifact_receipt` against `central.artifact_command_receipts`.

- [ ] **Step 2: Implement `Store` methods in `artifact/store.rs` using `sqlx::query!` / `sqlx::query_as!`**
  - `reserve_artifact`:
    - Check `artifact_command_receipts` for `"reserve"`; on exact fingerprint match, reload and return the stored `Artifact`; on mismatch, return `FailureClass::Conflict ("IDEMPOTENCY_FINGERPRINT_MISMATCH")`.
    - Lock workspace quota row with `SELECT quota_ready_bytes, quota_max_bytes FROM central.workspaces WHERE id = $1 FOR NO KEY UPDATE` (using `FOR NO KEY UPDATE` to prevent FK key-share deadlocks against concurrent execution commits).
    - Sum active reservations (`SELECT COALESCE(SUM(reserved_bytes), 0) FROM central.capacity_reservations WHERE workspace_id = $1 AND state = 'reserved'`).
    - Enforce `ready_bytes + reserved_sum + (limits.max_bytes * 2) <= max_bytes`, returning `FailureClass::Denied ("QUOTA_EXCEEDED")` if exceeded.
    - Insert into `central.artifacts`, `central.capacity_reservations` (`reserved_bytes = limits.max_bytes * 2`), and `central.artifact_command_receipts` in one transaction.
  - `record_begin_upload`: receipt check/replay, `FOR UPDATE` row lock, version + `reserved` state guard, update to `staging`, insert receipt.
  - `record_verification`: receipt check/replay (reconstructing `Outcome` from `rejection` JSONB on replay), `FOR UPDATE` row lock, version + `staging` state guard, update `size`, `checksum_value`, `checksum_algorithm = 'sha256'`, `rejection`, and when `State::Rejected`, release capacity reservation (`state = 'released'`, `released_at = clock_timestamp()`), insert receipt.
  - `record_promotion`: receipt check/replay, `FOR UPDATE` row lock, version + `verifying` state + empty `ready_key` guard, update `content_generation` and `ready_key`, insert receipt.
  - `record_rejection`: receipt check/replay, `FOR UPDATE` row lock, version + `reserved`/`staging` state guard, update to `rejected` + release capacity reservation in one transaction, insert receipt.
  - `load_artifact`: read snapshot and map to `central_artifact::domain::Artifact`.

- [ ] **Step 3: Implement `CompletionContributor::commit_artifact` in `artifact/commit.rs`**
  - Port `b10_supported_execution_change` validation (rejecting tool calls/approvals/checkpoints/leases/assertions/reconciliations, requiring `settlements.len() == 1` and `lease_releases.len() == 1` with matching `(workspace_id, run_id)` when settling an attempt, or empty execution change set for reconciler resume).
  - Enforce the exact lock ordering inside the single PostgreSQL transaction:
    0. `central.workspace_event_counters` (`FOR UPDATE`, when task or execution events are present)
    1. `central.workspaces` (`FOR NO KEY UPDATE` quota lock)
    2. `central.tasks` (`FOR UPDATE` + expected version check)
    3. `central.runs` (`FOR UPDATE` + expected version check)
    4. `central.execution_ownership` lease fence (`fence_completion_lease`: verify `lease_token_hash`, `fencing_generation`, and `lease_expires_at > clock_timestamp()`, releasing the lease or failing with `STALE_LEASE_FENCE`)
    5. `central.steps` and `central.step_attempts` (`FOR UPDATE` + version checks)
    6. `central.artifacts` (`FOR UPDATE` + version, `verifying` state, `ready_key`/`content_generation` match, and producer chain match against Task/Run/Step/Attempt)
    7. `central.capacity_reservations` (`FOR UPDATE`, must be `'reserved'`, plus defensive `ready_bytes + verified_size <= max_bytes` check)
  - Apply mutations atomically: transition artifact to `'ready'` (binding `ready_object_version`), settle capacity reservation (`'settled'`), charge workspace quota (`quota_ready_bytes + verified_size`, `quota_ready_count + 1`), apply task/run/step/attempt updates, append task and execution events + `central.outbox` rows, and insert the `"finalize"` command receipt.

- [ ] **Step 4: Port unit and `CENTRAL_TEST_DSN` PostgreSQL integration tests**
  - Port fingerprint canonicalization tests (`identity_fingerprint_test.go`) and PostgreSQL integration tests (`store_test.go`, `reserve_replay_test.go`, `quota_lock_test.go`) covering reserve quota enforcement, `2 * MaxBytes` peak accounting, capacity release on verify/explicit reject, idempotent command replays and fingerprint conflicts, atomic finalize + task completion under a live B08 lease, and `STALE_LEASE_FENCE` refusal when a lease is superseded.

- [ ] **Step 5: Run verification and commit**
  - Run: `cargo fmt --all -- --check && cargo clippy -p central-adapter-postgres --all-targets -- -D warnings && cargo test -p central-adapter-postgres`
  - Commit: `feat(adapter-postgres): implement B10 artifact Store and atomic CompletionContributor`

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
  - `claim_large`: clean resolved large claims (`queryDeleteResolvedLargeClaims` — handling `central_runtime` role privilege semantics cleanly if `DELETE` is restricted, while `queryLockOldestLargeClaim` independently filters `a.state NOT IN ('ready', 'rejected') FOR UPDATE OF c SKIP LOCKED`), lock oldest eligible large claim, and extend its lease.
  - `record_large_claim`: verify active claim via constant-time `claim_token_hash` comparison and `lease_expires_at > clock_timestamp()`, verify artifact version, and upsert `claim_kind = 'large'` with `lease_expires_at = clock_timestamp()`.
  - `expire_staging`: verify active claim, lock artifact row, compare age in SQL via `SELECT created_at < clock_timestamp() - make_interval(secs => $3::double precision) FROM central.artifacts WHERE workspace_id = $1 AND id = $2` (never using caller wall clock), evaluate domain `reject`, apply rejection + capacity release + `"reject"` receipt idempotently.
  - `release_large_claim`, `claim_rejected_staging` (`WHERE staging_key IS NOT NULL AND state = 'rejected' ORDER BY workspace_id, staging_key LIMIT $1`), `clear_staging_key` (`UPDATE central.artifacts SET staging_key = NULL ... WHERE state = 'rejected'`), and `record_progress` (`central.artifact_reconciliation_progress`).

- [ ] **Step 2: Implement `b34` Lineage Stores in `artifact/lineage_store.rs`**
  - Implement `ProduceEdgeStore::insert_produce_edge` (`INSERT INTO central.artifact_produce_edges ... ON CONFLICT (artifact_id) DO NOTHING`, falling back to `SELECT` on conflict for idempotent replay).
  - Implement `ReadEdgeStore::insert_read_edge` (`INSERT INTO central.artifact_read_edges ... ON CONFLICT (run_id, reader_node_id, attempt_id, artifact_id) DO NOTHING`, falling back to `SELECT` when `reader_node_id IS NOT NULL` so attempt-scoped reads dedupe while operator `NULL` reads append distinct rows).
  - Implement `LineageReader` (`produce_edge_for_artifact`, `read_edges_for_artifact`, `read_edges_for_node`, `produce_edges_for_node`, `produce_edges_for_run`, `read_edges_for_run`).
  - Implement `ReadStore` (`find_artifact`, `resolve_produced` joining `artifact_produce_edges`, `workflow_nodes`, and `artifacts`, `declared_scope` unioning `workflow_edges` of `kind = 'artifact'` with `workflow_nodes.input_artifact_refs` JSONB UUIDs, and `run_produced_artifacts`).

- [ ] **Step 3: Port PostgreSQL integration tests from `reconcile_store_test.go`, `lineage_store_test.go`, and `explain_test.go`**
  - Verify round-robin workspace cursor progression, skip-budget bounding (`64` workspaces), DB-clock staging expiry, large-claim promotion and lease takeovers, rejected-staging key clearing, idempotent `artifact_produce_edges` and `artifact_read_edges` inserts, operator vs. attempt-scoped read edge uniqueness, `declared_scope` JSONB parsing, and `EXPLAIN` index-scan plan assertions on `artifacts_state_expiry_idx` and `artifacts_workspace_staging_key_unique_idx`.

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
- `$CENTRAL_RUST_SRC/docs/implementation/rust-engineering-workflow.md`
- `$CENTRAL_RUST_SRC/docs/implementation/rust-vertical-slice-roadmap.md`

- [ ] **Step 1: Wire `central-artifact` and `central-adapter-s3` into `central-kernel`**
  - Add `central-artifact` and `central-adapter-s3` to `crates/central-kernel/Cargo.toml`.
  - Expose a supervised background reconciliation loop builder in `central-kernel` that drives `central_artifact::reconciler::Reconciler::reconcile` on a bounded ticker under the kernel's `CancellationToken` and B08 coordinator `Fence`, settling cleanly within the kernel shutdown deadline.
  - Add a deterministic unit test in `central-kernel` proving the supervised artifact reconciler component starts, executes a pass, and halts cleanly when the kernel `CancellationToken` is cancelled.

- [ ] **Step 2: Update `docs/implementation/current-phase.md` to record R2 completion and advance active slice to R3**
  - Move Phase R2 to the **Completed** section with a summary of delivered crates (`central-artifact`, `central-adapter-s3`, `central-adapter-postgres::artifact`, `central-kernel` reconciler supervision, `.sqlx/` metadata) and mark **Phase R3 — Harness Control Plane & `central serve`** as the active slice in the status table.

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
