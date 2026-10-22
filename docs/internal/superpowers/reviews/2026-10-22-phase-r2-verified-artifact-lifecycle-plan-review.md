# Plan Review: Phase R2 — Verified Artifact Lifecycle (`R2`)

- **Target:** `docs/internal/superpowers/plans/2026-10-22-phase-r2-verified-artifact-lifecycle.md`
- **Base Commit:** `5ee1259`
- **Mode:** Full (`Technical`, `Security`, `Performance`, `Process`, `Product`)
- **Recommendation:** Ready (sau khi đã cập nhật trực tiếp 5 điểm `PR-01`..`PR-05` vào bản kế hoạch)

## Blocking Findings (Resolved in Plan)

### [PR-01] `Critical` — Vi phạm ranh giới phụ thuộc của capability crate `central-artifact` (`tokio`, `uuid`) và lệch pin phiên bản `uuid` trong `Cargo.toml`
- **Dimension:** Technical / Architecture Boundary
- **Location:** `Tech Stack`, `Task 1: Step 1–2`, `Task 2: Step 2`, `Task 3: Step 1`
- **Evidence:**
  - `docs/architecture/rust-application-boundaries.md` §1 (dòng 40–41) quy định: *"uuid::Uuid never escapes `central-foundation::identity`. `tokio`, `tokio-util`, `futures` channel primitives ... are absent from every capability crate's `[dependencies]`."*
  - `crates/capabilities/central-execution/Cargo.toml` tuân thủ nghiêm ngặt quy tắc này (chỉ phụ thuộc `central-foundation`, `serde`, `serde_json`, `thiserror`, `trait-variant`).
  - `Cargo.toml` gốc của workspace (dòng 63) đang pin `uuid = { version = "=1.28.0", features = ["v7", "serde"] }`, nhưng bản plan ban đầu ghi `"=1.23.1"` và thêm `tokio`, `uuid` trực tiếp vào `crates/capabilities/central-artifact/Cargo.toml`.
- **Resolution Applied:**
  - Giữ nguyên pin `uuid = { version = "=1.28.0", features = ["v4", "v7", "serde"] }` tại `[workspace.dependencies]` trong `Cargo.toml`.
  - Đưa các newtype định danh UUIDv4 (`StagingGeneration`, `ContentGeneration`, `ProduceEdgeId`, `ReadEdgeId`, `ArtifactTombstoneId`) và các hàm dựng tất định từ SHA-256 (`ArtifactId::from_v7_digest_bytes`, `StagingGeneration::from_v4_digest_bytes`) về `central-foundation::identity`.
  - Loại bỏ hoàn toàn `tokio` và `uuid` khỏi `crates/capabilities/central-artifact/Cargo.toml`; thay `tokio::io::AsyncRead` trong `port.rs` bằng trait độc lập runtime `#[trait_variant::make(Send)] pub trait ByteStream: Send` và dùng `std::time::{Duration, Instant}` trong `reconciler.rs`.

### [PR-02] `Critical` — Thiếu one-shot `AuthorizedDownload`, `ArtifactSummaryRead`, và quy trình xóa hai pha kèm tombstone (`TwoPhaseDeleteStore`)
- **Dimension:** Product / Security / Infrastructure Contract
- **Location:** `File Structure`, `Task 1`, `Task 2`, `Task 3`, `Task 4`, `Task 5`
- **Evidence:**
  - `docs/architecture/rust-application-boundaries.md` §2.4 (dòng 164–168) và §3.4 (dòng 350–355) bắt buộc `central-artifact::app::ArtifactService` phải cung cấp `prepare_authorized_download` trả về capability token dùng một lần (`!Clone` `AuthorizedDownload::start(self)`) cùng `evaluate_delivery_policy` (`128 KiB` inline preview cap, allowlist `text/plain`, `text/markdown`, `application/json`, ép `Disposition::Attachment` cho mọi trường hợp khác).
  - `docs/implementation/rust-vertical-slice-roadmap.md` §5 (dòng 94–96) và `docs/persistence/postgresql-adapter-mapping.md` §3.9–§3.10 yêu cầu R2 phải hoàn thiện `ArtifactSummaryRead` (seek pagination `(created_at, id)`) và xóa hai pha phạm vi workspace (`mark_delete_pending` → xóa đối tượng S3 ready-for-delete → `complete_deletion_with_tombstone` ghi vào `central.artifact_tombstones` và giảm `retained_bytes` / `artifact_count` trên `central.workspace_artifact_quotas`).
- **Resolution Applied:**
  - Bổ sung `mark_delete_pending`, `complete_deletion`, `Disposition`, `DeliveryDecision`, và `evaluate_delivery_policy` vào `Task 1` (`domain.rs`).
  - Bổ sung `TwoPhaseDeleteStore` vào `port.rs` và `ArtifactSummaryRead` (`get_artifact_summary`, `list_task_artifacts`, `list_run_artifacts`, `get_tombstone`) vào `query.rs` trong `Task 2`.
  - Bổ sung `prepare_authorized_download` + `!Clone` `AuthorizedDownload::start(self)` và `delete_artifact_two_phase` vào `Task 3` (`app.rs`).
  - Bổ sung `remove_ready_for_delete` vào `Task 4` (`central-adapter-s3`) và các truy vấn PostgreSQL tương ứng cùng integration tests vào `Task 5` (`store.rs`).

## Important & Minor Findings (Resolved in Plan)

### [PR-03] `Important` — Cơ chế giải phóng large claim (`SB-G4`) trên `central.artifact_reconciliation_claims` dưới quyền `central_runtime`
- **Dimension:** Security / Database Role Privileges
- **Location:** `Task 6: Step 1` (`crates/adapters/central-adapter-postgres/src/artifact/reconciler.rs`)
- **Evidence:**
  - `migrations/0014_b10_artifact_lifecycle.sql` (dòng 176–180) và `migrations/reapply_incremental_runtime_grants.sql` (dòng 275–279) chỉ cấp `SELECT, INSERT, UPDATE` (không có `DELETE`) trên bảng `central.artifact_reconciliation_claims` cho role `central_runtime`.
  - Upstream Go gọi `DELETE FROM central.artifact_reconciliation_claims` trong `ClaimLarge` và `ReleaseLargeClaim`, dẫn đến lỗi `42501 insufficient_privilege` khi chạy bằng `central_runtime`.
- **Resolution Applied:**
  - Chỉ định rõ câu lệnh SQL trong `Task 6: Step 1`: hạ cấp (demote) claim đã giải quyết/nhả bằng `UPDATE central.artifact_reconciliation_claims SET claim_kind = 'normal', lease_expires_at = clock_timestamp(), updated_at = clock_timestamp() WHERE ...` (chỉ cần quyền `UPDATE` của `central_runtime` và đảm bảo `queryLockOldestLargeClaim` vốn lọc `WHERE c.claim_kind = 'large'` không bao giờ quét lại claim đã xử lý).

### [PR-04] `Important` — Đồng bộ `CommitArtifact` với các helper giao dịch của R1 (`central-adapter-postgres::execution`) và dọn phụ thuộc `aws-smithy-*`
- **Dimension:** Technical / Cross-Crate Consistency
- **Location:** `Tech Stack`, `Task 4: Step 1`, `Task 5: Step 3`
- **Evidence:**
  - `Cargo.toml` chỉ khai báo `aws-sdk-s3` và `aws-config`, không khai báo trực tiếp `aws-smithy-Runtime-api` hay `aws-smithy-types`.
  - Trong R1, `crates/adapters/central-adapter-postgres/src/execution/store.rs` đã xây dựng sẵn `execution::begin`, `uuid_for_invocation`, `invocation_generation`, `go_json_escapes`, `go_rfc3339_local`, `reserve_event_sequence`, và `upsert_outbox_workspace_work`. Ngoài ra, khóa chống trùng lặp outbox cho sự kiện task khi `run_id` rỗng (`nil`) phải định dạng `run_id` thành chuỗi rỗng `""` (`"task:{task_id}:{task_version}:{kind}:"`), khớp với hàm `zeroRun` của upstream.
- **Resolution Applied:**
  - Dùng các kiểu re-export trực tiếp từ `aws_sdk_s3` (`aws_sdk_s3::primitives::ByteStream`, `aws_sdk_s3::error::ProvideErrorMetadata`) trong `Task 4`.
  - Cập nhật `Task 5: Step 3` để tái sử dụng các helper giao dịch/mã hóa từ `crate::execution` và quy định rõ quy tắc định dạng `deduplication_key` khi `run_id` là `None`.

### [PR-05] `Minor` — Tách `ArtifactReconcilerComponent` về `central-kernel` để giữ quy tắc Kernel-Edge
- **Dimension:** Process / Architecture Hygiene
- **Location:** `Task 7: Step 1`
- **Evidence:**
  - `docs/architecture/rust-application-boundaries.md` §1 quy định `central-kernel` là nơi duy nhất sở hữu `lifecycle::Component` và `CancellationToken`; các capability crate không phụ thuộc ngược vào `central-kernel`.
- **Resolution Applied:**
  - Cập nhật `Task 7: Step 1` để đặt struct `ArtifactReconcilerComponent` (triển khai `crate::lifecycle::Component`) bên trong `crates/central-kernel`, bọc quanh `ArtifactReconciler` của `central-artifact`.

## Risk Summary

| Dimension | Status | Notes |
| --- | --- | --- |
| Technical | Pass | Đã loại bỏ `tokio`/`uuid` khỏi `central-artifact`, đồng bộ pin `uuid = "=1.28.0"` và tái sử dụng helper giao dịch từ R1. |
| Security | Pass | Đã bổ sung one-shot `AuthorizedDownload`, `evaluate_delivery_policy` (chống inline XSS/preview quá khổ), và xử lý `SB-G4` dưới đúng quyền của `central_runtime`. |
| Performance | Pass | Giữ nguyên streaming có giới hạn (`max_artifact_bytes + 1`), không đệm toàn bộ payload vào RAM, và seek pagination `(created_at, id)` có chỉ mục. |
| Process | Pass | 7 task tuân thủ TDD, cập nhật `.sqlx/` offline metadata và kiểm chứng qua `cargo nextest`, `cargo clippy -- -D warnings`, cùng `check-rust-boundaries.sh`. |
| Product | Pass | Đầy đủ vòng đời artifact của R2 theo `rust-vertical-slice-roadmap.md` §5: stage → verify → commit → lineage → read/summary → two-phase delete → reconcile. |
