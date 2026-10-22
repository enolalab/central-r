//! The S3/MinIO object-store adapter (port of upstream `minio.Store`).
//!
//! The `aws-sdk-s3` client is confined to this file: no SDK type, bucket
//! name, object key, or endpoint escapes through results or errors. Every
//! operation is bounded — at most `MAX_CONCURRENT_TRANSFERS` byte transfers
//! run at once, each stream stops one byte past its declared ceiling,
//! transfers without byte progress are cut at the idle deadline, and the
//! whole transfer is capped by a total deadline.
//!
//! Readiness is never inferred from object existence: a ready object is
//! only ever created through an atomic create-only precondition
//! (`If-None-Match: *`), never through a HEAD probe followed by a write and
//! never through a server-side `CopyObject`.
//!
//! # Streaming-body deviations from upstream
//!
//! `aws-sdk-s3` exposes no public constructor that turns a caller-supplied
//! `std::io::Read` into an SDK request body (the `http-body`/`http-body-util`
//! crates that would enable one are intentionally outside the workspace
//! dependency policy). Two deliberate consequences:
//!
//! - [`S3ObjectStore::upload`] drives the multipart protocol itself: a
//!   blocking pump thread fills 5 MiB part buffers and the transfer task
//!   issues `upload_part` calls — which is also what bounds memory and what
//!   lets an over-limit body abort before any commit.
//! - [`S3ObjectStore::restore_body_create_only`] buffers its exact-size
//!   body before the single conditional PUT. The buffer is still capped by
//!   `size + 1` and `size <= MAX_ARTIFACT_BODY_BYTES`; it trades upstream's
//!   constant-memory PUT for bounded-but-large allocation because the
//!   single-PUT create-only precondition cannot gate a multipart commit.
//!
//! For [`S3ObjectStore::promote_create_only`] the GET response body is the
//! SDK's own `ByteStream`, so it streams straight into the conditional
//! PUT — but per-byte progress is not observable inside the SDK, so that
//! path is bounded by the total deadline and connection-level behavior
//! rather than the per-byte idle watchdog. Both stalls still classify as
//! `AMBIGUOUS`; the `Reason` differs (`total_deadline`, not `idle_timeout`).
//! The SDK's own stalled-stream protection is disabled so this adapter's
//! watchdog remains the single authority on the upload/read paths.

use std::future::Future;
use std::io::{self, Read as _};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region, SharedCredentialsProvider};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::{ByteStream, SdkBody};
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use central_artifact::port::{
    ByteStream as PortByteStream, MAX_ARTIFACT_BODY_BYTES, MAX_CONCURRENT_TRANSFERS, ObjectInfo,
    ObjectRef, ObjectStore, TRANSFER_IDLE_TIMEOUT, TRANSFER_TOTAL_DEADLINE, UploadRequest,
    UploadResult,
};
use central_foundation::failure::Failure as PortFailure;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::error::{Failure, FailureClass, Reason, classify_sdk, fail};
use crate::limiter::TransferLimiter;
use crate::stream::{PermitStream, Progress, PumpError, spawn_pump};

// ---------------------------------------------------------------------------
// Key roles
// ---------------------------------------------------------------------------

/// The only two key roles this adapter will act on. The role is checked
/// before any request leaves the process, so a mis-derived key can never
/// reach the object store at all.
const STAGING_PREFIX: &str = "v1/staging/";
const READY_PREFIX: &str = "v1/ready/";

/// The S3 multipart part size for a streamed staging upload, and therefore
/// the adapter's per-transfer memory bound (upstream `StagingPartSizeBytes`).
///
/// It is the S3 protocol's absolute minimum part size — a hard floor of the
/// multipart protocol, not a tunable. It bounds a transfer to ~5 MiB in
/// flight, so the whole adapter holds ~10 MiB at `MAX_CONCURRENT_TRANSFERS`
/// `= 2`.
pub const STAGING_PART_SIZE_BYTES: usize = 5 * 1024 * 1024;

fn is_staging_key(key: &str) -> bool {
    valid_key(key) && key.starts_with(STAGING_PREFIX)
}

fn is_ready_key(key: &str) -> bool {
    valid_key(key) && key.starts_with(READY_PREFIX)
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && !key.contains("..") && !key.starts_with('/')
}

// ---------------------------------------------------------------------------
// Configuration and construction
// ---------------------------------------------------------------------------

/// The adapter's connection input (upstream `Config`). Credentials arrive
/// here already materialized from the sealed `minio_runtime_v1` descriptor;
/// they are never read from the environment by this crate.
#[derive(Debug, Clone)]
pub struct Config {
    /// Host (`host[:port]`), without a URL scheme — as upstream's
    /// `minio.New` endpoint. The scheme comes from [`Self::use_tls`].
    pub endpoint: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Set only when the credential is a temporary one. A long-lived
    /// scoped principal leaves it empty.
    pub session_token: String,
    pub bucket: String,
    /// The signing region. Empty resolves to `us-east-1` so the signer
    /// never issues a bucket-location lookup (upstream `Region` pin).
    pub region: String,
    pub use_tls: bool,
}

/// Implements [`ObjectStore`] against one bucket (upstream `Store`).
/// Construct through [`S3ObjectStore::new`].
pub struct S3ObjectStore {
    client: Client,
    bucket: String,
    limiter: TransferLimiter,
    pub(crate) idle_timeout: Duration,
    pub(crate) total_deadline: Duration,
}

impl S3ObjectStore {
    /// Builds a store bound to exactly one bucket. Region is set
    /// explicitly so the SDK never issues a bucket-location lookup, and
    /// path-style addressing is pinned because the local MinIO deployment
    /// is not virtual-host capable.
    pub fn new(config: Config) -> Result<Self, Failure> {
        const OP: &str = "new";
        if config.endpoint.is_empty()
            || config.bucket.is_empty()
            || config.access_key_id.is_empty()
            || config.secret_access_key.is_empty()
        {
            return Err(fail(OP, FailureClass::Invalid, Reason::ConfigInvalid));
        }
        let scheme = if config.use_tls { "https" } else { "http" };
        let region = if config.region.is_empty() {
            "us-east-1".to_owned()
        } else {
            config.region.clone()
        };
        let credentials = Credentials::new(
            config.access_key_id,
            config.secret_access_key,
            if config.session_token.is_empty() {
                None
            } else {
                Some(config.session_token)
            },
            None,
            "central-minio-static",
        );
        let sdk_config = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region))
            .credentials_provider(SharedCredentialsProvider::new(credentials))
            .endpoint_url(format!("{scheme}://{}", config.endpoint))
            .force_path_style(true)
            // The adapter's own watchdogs are the single stall authority;
            // the SDK's protection would produce duplicate, differently
            // reasoned ambiguity.
            .stalled_stream_protection(
                aws_config::stalled_stream_protection::StalledStreamProtectionConfig::disabled(),
            )
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::standard())
            .build();
        Ok(Self {
            client: Client::from_conf(sdk_config),
            bucket: config.bucket,
            limiter: TransferLimiter::new(MAX_CONCURRENT_TRANSFERS),
            idle_timeout: TRANSFER_IDLE_TIMEOUT,
            total_deadline: TRANSFER_TOTAL_DEADLINE,
        })
    }

    /// The store's limiter — exposed to in-crate tests (upstream tests
    /// reach `s.limiter` directly because they share the package).
    #[cfg(test)]
    pub(crate) fn limiter(&self) -> &TransferLimiter {
        &self.limiter
    }

    /// The instant the current operation's total deadline lands on.
    fn deadline(&self) -> Instant {
        Instant::now() + self.total_deadline
    }

    /// One bounded SDK call: `send`-style operations wrapped in the
    /// operation's remaining total deadline (upstream `context.WithTimeout`
    /// around the call site). Elapsed maps to `AMBIGUOUS/total_deadline`;
    /// the SDK error is classified and dropped.
    async fn bounded<F, T, E>(
        &self,
        op: &'static str,
        deadline: Instant,
        call: F,
    ) -> Result<T, Failure>
    where
        F: Future<Output = Result<T, SdkError<E>>>,
        E: ProvideErrorMetadata,
    {
        match tokio::time::timeout_at(deadline.into(), call).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(classify_sdk(op, &err)),
            Err(_) => Err(fail(op, FailureClass::Ambiguous, Reason::TotalDeadline)),
        }
    }

    // -------------------------------------------------------------------
    // Bounded transfer supervision
    // -------------------------------------------------------------------

    /// Drives a spawned transfer task under the idle watchdog and the total
    /// deadline — upstream `runBounded`.
    ///
    /// The task is `tokio::spawn`ed rather than awaited inline: a reader
    /// parked inside a blocking `read` cannot be interrupted, so when a
    /// bound fires we cancel the task's work, detach, and return — the task
    /// unwinds once its source finally yields, and its permit stays held
    /// until then. Releasing the permit only at task settlement is what
    /// keeps "at most `MAX_CONCURRENT_TRANSFERS` byte transfers run at
    /// once" true: an abandoned transfer still holds its buffer and still
    /// reads its source.
    async fn supervise<T>(
        &self,
        op: &'static str,
        mut join: JoinHandle<Result<T, Failure>>,
        progress: &Progress,
        cancel: CancellationToken,
    ) -> Result<T, Failure> {
        // Fires the task's cancellation on *every* exit path — including a
        // dropped `supervise` future (caller cancellation).
        struct CancelOnDrop(CancellationToken);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }
        let _guard = CancelOnDrop(cancel);

        // Upstream polls the watchdog at idle/4 clamped to [1ms, 1s].
        let mut tick = tokio::time::interval(
            self.idle_timeout
                .checked_div(4)
                .unwrap_or(self.idle_timeout)
                .clamp(Duration::from_millis(1), Duration::from_secs(1)),
        );
        let deadline = tokio::time::Instant::from_std(Instant::now() + self.total_deadline);
        loop {
            tokio::select! {
                res = &mut join => {
                    return match res {
                        Ok(result) => match result {
                            Err(err) => Err(over_limit_upgrade(op, progress, err)),
                            ok => ok,
                        },
                        // A panicked or aborted task never delivered a
                        // verdict — its fate is unknown by definition.
                        Err(_) => Err(over_limit_upgrade(
                            op,
                            progress,
                            fail(op, FailureClass::Ambiguous, Reason::TransferIncomplete),
                        )),
                    };
                }
                _ = tick.tick() => {
                    if progress.idle_for() > self.idle_timeout {
                        return Err(over_limit_upgrade(
                            op,
                            progress,
                            fail(op, FailureClass::Ambiguous, Reason::IdleTimeout),
                        ));
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(over_limit_upgrade(
                        op,
                        progress,
                        fail(op, FailureClass::Ambiguous, Reason::TotalDeadline),
                    ));
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Upload
    // -------------------------------------------------------------------

    /// Upstream `Upload`: streams a body to a staging key under a
    /// create-only precondition, refuses any non-staging key, stops exactly
    /// one byte past `max_bytes` without ever committing an over-limit
    /// body, and holds one transfer permit for the duration.
    ///
    /// Reader ownership matches upstream: `request.body` is caller-owned
    /// but the pump thread that consumes it can outlive this call. On a
    /// stall-classified failure (`AMBIGUOUS` with `idle_timeout`,
    /// `total_deadline`, or `canceled`) the transfer is abandoned rather
    /// than stopped — the caller must not reuse the reader on those
    /// outcomes.
    pub(crate) async fn upload_inner(
        &self,
        request: UploadRequest,
    ) -> Result<UploadResult, Failure> {
        const OP: &str = "upload";
        let key = request.reference.key;
        if !is_staging_key(&key) {
            return Err(fail(OP, FailureClass::Invalid, Reason::KeyRoleInvalid));
        }
        if request.max_bytes <= 0 || request.max_bytes > MAX_ARTIFACT_BODY_BYTES {
            return Err(fail(OP, FailureClass::Invalid, Reason::LimitInvalid));
        }

        // The permit's ownership passes to the spawned task, which
        // releases it when the transfer — including the pump thread — has
        // actually settled.
        let permit = self.limiter.acquire_owned().await?;

        let progress = Arc::new(Progress::new());
        let (rx, pump) = spawn_pump(
            request.body,
            request.max_bytes,
            STAGING_PART_SIZE_BYTES,
            Arc::clone(&progress),
        )?;
        let cancel = CancellationToken::new();
        let task = {
            let client = self.client.clone();
            let bucket = self.bucket.clone();
            let progress = Arc::clone(&progress);
            let cancel = cancel.clone();
            let mut rx = rx;
            tokio::spawn(async move {
                let _permit = permit;
                let result = run_upload(&client, &bucket, &key, &mut rx, &progress, &cancel).await;
                // Settle path: dropping rx unblocks a send-parked pump; a
                // read-parked pump unwinds once the caller's reader yields.
                // The permit is released by `_permit` only after the pump
                // thread has exited — an abandoned transfer is still an
                // active transfer until then.
                drop(rx);
                let _ = tokio::task::spawn_blocking(move || pump.join()).await;
                result
            })
        };
        self.supervise(OP, task, &progress, cancel).await
    }

    // -------------------------------------------------------------------
    // Read
    // -------------------------------------------------------------------

    /// Upstream `Read`: opens a verification or post-promotion read. The
    /// returned stream holds one transfer permit until it is closed, so an
    /// abandoned reader can never silently starve the process of permits —
    /// the caller must close it.
    pub(crate) async fn read_inner(
        &self,
        reference: ObjectRef,
    ) -> Result<(PermitStream, ObjectInfo), Failure> {
        const OP: &str = "read";
        let key = reference.key;
        if !is_staging_key(&key) && !is_ready_key(&key) {
            return Err(fail(OP, FailureClass::Invalid, Reason::KeyRoleInvalid));
        }

        let permit = self.limiter.acquire_owned().await?;
        let deadline = self.deadline();

        // The GET carries the object's evidence in its own response, so a
        // missing object is a typed NOT_FOUND without an extra HEAD round
        // trip. The permit returns via RAII on every early return.
        let output = self
            .bounded(
                OP,
                deadline,
                self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(&key)
                    .send(),
            )
            .await?;

        let info = ObjectInfo {
            size: output.content_length().unwrap_or_default(),
            etag: output.e_tag().unwrap_or_default().to_owned(),
            version: output.version_id().unwrap_or_default().to_owned(),
        };
        let stream = PermitStream::new(OP, output.body, permit, self.idle_timeout, deadline);
        Ok((stream, info))
    }

    // -------------------------------------------------------------------
    // Promotion
    // -------------------------------------------------------------------

    /// Upstream `PromoteCreateOnly`: creates the ready object from the
    /// staged body under an atomic create-only precondition.
    ///
    /// It is deliberately a read-then-create, never a HEAD-then-copy and
    /// never a server-side `copy_object`: only the precondition decides the
    /// winner, so two concurrent promotions cannot both believe they
    /// created the ready object. The losing caller gets a typed `CONFLICT`
    /// and the existing object stays untouched. The create is a single PUT
    /// — the only request shape on which `If-None-Match` gates the commit —
    /// with `content_length` pinned so the SDK cannot split the body.
    pub(crate) async fn promote_inner(
        &self,
        source: ObjectRef,
        destination: ObjectRef,
    ) -> Result<ObjectInfo, Failure> {
        const OP: &str = "promote";
        if !is_staging_key(&source.key) || !is_ready_key(&destination.key) {
            return Err(fail(OP, FailureClass::Invalid, Reason::KeyRoleInvalid));
        }

        // Held for the whole GET → conditional PUT → stat sequence; the
        // RAII guard returns it on every exit.
        let _permit = self.limiter.acquire_owned().await?;
        let deadline = self.deadline();

        // The GET carries the staged object's size in its own response, so
        // the source is never probed with a separate HEAD before the
        // create.
        let staged = self
            .bounded(
                OP,
                deadline,
                self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(&source.key)
                    .send(),
            )
            .await?;

        let size = staged.content_length().unwrap_or(-1);
        if !(0..=MAX_ARTIFACT_BODY_BYTES).contains(&size) {
            return Err(fail(OP, FailureClass::Invalid, Reason::LimitInvalid));
        }

        // A single conditional PUT: `If-None-Match` rides the one request
        // that actually creates the object. `size <= 4 GiB` is below the
        // 5 GiB single-PUT ceiling, so every legal body fits; the pinned
        // `content_length` also keeps the SDK from ever choosing a
        // chunked/multipart encoding for this request. The GET body — the
        // SDK's own `ByteStream` — streams straight through without an
        // intermediate buffer.
        self.bounded(
            OP,
            deadline,
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&destination.key)
                .content_type("application/octet-stream")
                .content_length(size)
                .if_none_match("*")
                .body(staged.body)
                .send(),
        )
        .await?;

        // Evidence is read back from the created object rather than trusted
        // from the write response (upstream `StatObject`), so the recorded
        // ETag/version is what the store actually holds.
        let ready = self
            .bounded(
                OP,
                deadline,
                self.client
                    .head_object()
                    .bucket(&self.bucket)
                    .key(&destination.key)
                    .send(),
            )
            .await?;
        Ok(ObjectInfo {
            size: ready.content_length().unwrap_or_default(),
            etag: ready.e_tag().unwrap_or_default().to_owned(),
            version: ready.version_id().unwrap_or_default().to_owned(),
        })
    }

    // -------------------------------------------------------------------
    // Staging cleanup
    // -------------------------------------------------------------------

    /// Upstream `RemoveStaging`: deletes a staging object during
    /// reconciliation. It refuses every non-staging key, so reconciliation
    /// can never delete a ready object.
    pub(crate) async fn remove_staging_inner(&self, reference: ObjectRef) -> Result<(), Failure> {
        const OP: &str = "remove_staging";
        if !is_staging_key(&reference.key) {
            return Err(fail(OP, FailureClass::Invalid, Reason::KeyRoleInvalid));
        }
        self.bounded(
            OP,
            self.deadline(),
            self.client
                .delete_object()
                .bucket(&self.bucket)
                .key(&reference.key)
                .send(),
        )
        .await?;
        Ok(())
    }

    /// The Rust slice's two-phase-deletion counterpart of
    /// `remove_staging`: removes a *ready* object whose durable record is
    /// `delete_pending`. It refuses every non-ready key, so two-phase
    /// deletion can never remove a staging object through this path. Called
    /// only after the delete-intent commit is durable.
    pub(crate) async fn remove_ready_for_delete_inner(
        &self,
        reference: ObjectRef,
    ) -> Result<(), Failure> {
        const OP: &str = "remove_ready_for_delete";
        if !is_ready_key(&reference.key) {
            return Err(fail(OP, FailureClass::Invalid, Reason::KeyRoleInvalid));
        }
        self.bounded(
            OP,
            self.deadline(),
            self.client
                .delete_object()
                .bucket(&self.bucket)
                .key(&reference.key)
                .send(),
        )
        .await?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Restore import (ADR 0034) — inherent, not on the ObjectStore trait
    // -------------------------------------------------------------------

    /// Upstream `RestoreBodyCreateOnly`: creates one ready object from a
    /// caller-supplied body stream under the same atomic create-only
    /// precondition as `promote_create_only`. It exists for ADR 0034's
    /// import path, whose bodies stream from a staged restore-plan tree on
    /// disk rather than from a staged object.
    ///
    /// Only ready keys are admitted, and only under `If-None-Match`: the
    /// fresh target's store must be empty at these keys, so an existing
    /// object is a typed `CONFLICT` the import refuses rather than
    /// overwrites. The size is exact, which keeps the upload a single PUT —
    /// the precondition would not gate a multipart commit. Evidence is read
    /// back from the created object, never trusted from the write response.
    ///
    /// Deviation: the body is buffered (at most `size + 1` bytes) rather
    /// than streamed, because `aws-sdk-s3` accepts only its own
    /// `ByteStream` for a PUT body. The buffer is bounded by
    /// `size <= MAX_ARTIFACT_BODY_BYTES`; see the module docs.
    pub async fn restore_body_create_only(
        &self,
        key: String,
        body: Box<dyn io::Read + Send>,
        size: i64,
    ) -> Result<ObjectInfo, Failure> {
        const OP: &str = "restore_body";
        if !is_ready_key(&key) {
            return Err(fail(OP, FailureClass::Invalid, Reason::KeyRoleInvalid));
        }
        if !(0..=MAX_ARTIFACT_BODY_BYTES).contains(&size) {
            return Err(fail(OP, FailureClass::Invalid, Reason::LimitInvalid));
        }

        let permit = self.limiter.acquire_owned().await?;
        let deadline = self.deadline();
        let cancel = CancellationToken::new();

        // The buffered read runs on the blocking pool inside a spawned
        // task that owns the permit: if the supervisor gives up on a
        // stalled read, the permit stays held until the read settles —
        // the same "abandoned transfer" contract as `upload`.
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let key2 = key.clone();
        let task = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let read = tokio::task::spawn_blocking(move || {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut limited = io::Read::take(body, size.saturating_add(1) as u64);
                    let result = limited.read_to_end(&mut buf);
                    result.map(|_| buf)
                });
                let bytes: Vec<u8> = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        Err(fail(OP, FailureClass::Ambiguous, Reason::Canceled))
                    }
                    joined = read => match joined {
                        Ok(Ok(bytes)) => Ok(bytes),
                        Ok(Err(_)) | Err(_) => {
                            Err(fail(OP, FailureClass::Ambiguous, Reason::TransferIncomplete))
                        }
                    },
                }?;
                if bytes.len() as i64 > size {
                    return Err(fail(OP, FailureClass::LimitExceeded, Reason::LimitExceeded));
                }
                if bytes.len() as i64 != size {
                    // The reader ended before its declared size — upstream
                    // classifies the short body as an unexpected EOF.
                    return Err(fail(
                        OP,
                        FailureClass::Ambiguous,
                        Reason::TransferIncomplete,
                    ));
                }
                if let Err(err) = client
                    .put_object()
                    .bucket(&bucket)
                    .key(&key2)
                    .content_type("application/octet-stream")
                    .content_length(size)
                    .if_none_match("*")
                    .body(ByteStream::new(SdkBody::from(bytes)))
                    .send()
                    .await
                {
                    return Err(classify_sdk(OP, &err));
                }
                match client.head_object().bucket(&bucket).key(&key2).send().await {
                    Ok(ready) => Ok(ObjectInfo {
                        size: ready.content_length().unwrap_or_default(),
                        etag: ready.e_tag().unwrap_or_default().to_owned(),
                        version: ready.version_id().unwrap_or_default().to_owned(),
                    }),
                    Err(err) => Err(classify_sdk(OP, &err)),
                }
            })
        };
        // A buffered single-read transfer has no intermediate progress
        // signal, so the idle watchdog has nothing to observe; the real
        // bound is the total deadline. Cancel still propagates.
        self.supervise_restore(OP, task, deadline, cancel).await
    }

    /// Total-deadline-only supervision for the buffered restore transfer —
    /// the idle watchdog has no per-byte signal to observe (see module
    /// docs), so only the deadline and caller cancellation apply.
    async fn supervise_restore(
        &self,
        op: &'static str,
        mut join: JoinHandle<Result<ObjectInfo, Failure>>,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<ObjectInfo, Failure> {
        struct CancelOnDrop(CancellationToken);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                self.0.cancel();
            }
        }
        let _guard = CancelOnDrop(cancel);
        tokio::select! {
            res = &mut join => match res {
                Ok(result) => result,
                Err(_) => Err(fail(op, FailureClass::Ambiguous, Reason::TransferIncomplete)),
            },
            _ = tokio::time::sleep_until(deadline.into()) => {
                Err(fail(op, FailureClass::Ambiguous, Reason::TotalDeadline))
            }
        }
    }

    // -------------------------------------------------------------------
    // Backup throughput fixture — inherent, not on the ObjectStore trait
    // -------------------------------------------------------------------

    /// Upstream `OpenBackupThroughputFixture`: the only system-object read
    /// this adapter exposes. Its key and expected length are compile-time
    /// fixed; callers receive only a stream and cannot select or observe an
    /// object-store locator.
    pub async fn open_backup_throughput_fixture(&self) -> Result<PermitStream, Failure> {
        const OP: &str = "read_backup_throughput_fixture";
        let permit = self.limiter.acquire_owned().await?;
        let deadline = self.deadline();
        let output = self
            .bounded(
                OP,
                deadline,
                self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(BACKUP_THROUGHPUT_FIXTURE_KEY)
                    .send(),
            )
            .await?;
        if output.content_length() != Some(BACKUP_THROUGHPUT_FIXTURE_BYTES) {
            return Err(fail(OP, FailureClass::Invalid, Reason::UpstreamRejected));
        }
        Ok(PermitStream::new(
            OP,
            output.body,
            permit,
            self.idle_timeout,
            deadline,
        ))
    }
}

const BACKUP_THROUGHPUT_FIXTURE_KEY: &str = "v1/system/backup-throughput-fixture-v1";
const BACKUP_THROUGHPUT_FIXTURE_BYTES: i64 = 512 * 1024 * 1024;

/// Upstream `classify`'s `pr.over` check: a pump that consumed the
/// `max_bytes + 1` sentinel overrides whatever raced it — the stream
/// *observed* over-limit, so the outcome is known non-delivery.
fn over_limit_upgrade(op: &'static str, progress: &Progress, failure: Failure) -> Failure {
    if progress.is_over() {
        fail(op, FailureClass::LimitExceeded, Reason::LimitExceeded)
    } else {
        failure
    }
}

// ---------------------------------------------------------------------------
// Multipart / single-PUT upload execution
// ---------------------------------------------------------------------------

/// Receives the next pumped chunk under cancellation — the one await that
/// keeps a cancel responsive while the task waits on the pump thread.
async fn recv_chunk(
    op: &'static str,
    rx: &mut mpsc::Receiver<Result<Vec<u8>, PumpError>>,
    progress: &Progress,
    cancel: &CancellationToken,
) -> Result<Option<Vec<u8>>, Failure> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(fail(op, FailureClass::Ambiguous, Reason::Canceled)),
        msg = rx.recv() => match msg {
            None => Ok(None),
            Some(Ok(chunk)) => {
                progress.record(chunk.len() as i64);
                Ok(Some(chunk))
            }
            Some(Err(PumpError::OverLimit)) => {
                Err(fail(op, FailureClass::LimitExceeded, Reason::LimitExceeded))
            }
            Some(Err(PumpError::Io)) => {
                Err(fail(op, FailureClass::Ambiguous, Reason::TransferIncomplete))
            }
        },
    }
}

/// One SDK call inside a transfer task, cancel-responsive.
async fn transfer_call<F, T, E>(
    op: &'static str,
    cancel: &CancellationToken,
    call: F,
) -> Result<T, Failure>
where
    F: Future<Output = Result<T, SdkError<E>>>,
    E: ProvideErrorMetadata,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(fail(op, FailureClass::Ambiguous, Reason::Canceled)),
        result = call => result.map_err(|err| classify_sdk(op, &err)),
    }
}

/// The spawned upload transfer (the body of upstream `runBounded`'s `fn`).
///
/// A body that fits a single part takes a single conditional `put_object`;
/// anything larger becomes a multipart upload of 5 MiB parts whose commit
/// is preceded by an abort on every failure — an over-limit or failed body
/// is never committed (upstream `PutObject` with `PartSize` pinning).
async fn run_upload(
    client: &Client,
    bucket: &str,
    key: &str,
    rx: &mut mpsc::Receiver<Result<Vec<u8>, PumpError>>,
    progress: &Progress,
    cancel: &CancellationToken,
) -> Result<UploadResult, Failure> {
    const OP: &str = "upload";

    // An empty body still uploads as a single PUT.
    let first: Vec<u8> = recv_chunk(OP, rx, progress, cancel)
        .await?
        .unwrap_or_default();
    let second = recv_chunk(OP, rx, progress, cancel).await?;
    match second {
        None => {
            // Fits in one part: a single conditional PUT — the only
            // request shape whose If-None-Match gates the commit.
            let out = transfer_call(
                OP,
                cancel,
                client
                    .put_object()
                    .bucket(bucket)
                    .key(key)
                    .content_type("application/octet-stream")
                    .content_length(first.len() as i64)
                    .if_none_match("*")
                    .body(ByteStream::new(SdkBody::from(first)))
                    .send(),
            )
            .await?;
            Ok(UploadResult {
                info: ObjectInfo {
                    size: progress.count(),
                    etag: out.e_tag().unwrap_or_default().to_owned(),
                    version: out.version_id().unwrap_or_default().to_owned(),
                },
            })
        }
        Some(second) => {
            let mut ctx = TransferCtx {
                client,
                bucket,
                key,
                rx,
                progress,
                cancel,
            };
            multipart_upload(&mut ctx, first, second).await
        }
    }
}

/// The multipart branch — `create_multipart_upload`, 5 MiB `upload_part`s,
/// `complete_multipart_upload` — with `abort_multipart_upload` on every
/// failure path so an over-limit body is never committed.
///
/// The `If-None-Match` precondition cannot gate a multipart commit (the
/// API attaches it to the initiate, which does not decide the winner), so
/// staging safety rests on the key itself: every staging key carries a
/// per-upload generation id, and the precondition that must hold under
/// contention — never overwriting a ready object — is enforced in
/// `promote_inner` as a single conditional PUT.
/// Everything one transfer task needs — bundled so the multipart helpers
/// stay under the argument-count lint.
struct TransferCtx<'a> {
    client: &'a Client,
    bucket: &'a str,
    key: &'a str,
    rx: &'a mut mpsc::Receiver<Result<Vec<u8>, PumpError>>,
    progress: &'a Progress,
    cancel: &'a CancellationToken,
}

async fn multipart_upload(
    ctx: &mut TransferCtx<'_>,
    first: Vec<u8>,
    second: Vec<u8>,
) -> Result<UploadResult, Failure> {
    const OP: &str = "upload";

    let created = transfer_call(
        OP,
        ctx.cancel,
        ctx.client
            .create_multipart_upload()
            .bucket(ctx.bucket)
            .key(ctx.key)
            .content_type("application/octet-stream")
            .send(),
    )
    .await?;
    let Some(upload_id) = created.upload_id().map(str::to_owned) else {
        // A response the service signed off on but cannot be interpreted:
        // the upload may exist — ambiguous by construction.
        return Err(fail(
            OP,
            FailureClass::Ambiguous,
            Reason::TransferIncomplete,
        ));
    };

    let result = upload_parts(ctx, &upload_id, first, second).await;
    if let Err(failure) = result {
        abort_upload(ctx.client, ctx.bucket, ctx.key, &upload_id).await;
        return Err(failure);
    }
    let parts = result?;
    let completed = CompletedMultipartUpload::builder()
        .set_parts(Some(parts))
        .build();
    match transfer_call(
        OP,
        ctx.cancel,
        ctx.client
            .complete_multipart_upload()
            .bucket(ctx.bucket)
            .key(ctx.key)
            .upload_id(&upload_id)
            .multipart_upload(completed)
            .send(),
    )
    .await
    {
        Ok(out) => Ok(UploadResult {
            info: ObjectInfo {
                size: ctx.progress.count(),
                etag: out.e_tag().unwrap_or_default().to_owned(),
                version: out.version_id().unwrap_or_default().to_owned(),
            },
        }),
        Err(failure) => {
            abort_upload(ctx.client, ctx.bucket, ctx.key, &upload_id).await;
            Err(failure)
        }
    }
}

/// Uploads every pumped chunk as one part, in order.
async fn upload_parts(
    ctx: &mut TransferCtx<'_>,
    upload_id: &str,
    first: Vec<u8>,
    second: Vec<u8>,
) -> Result<Vec<CompletedPart>, Failure> {
    const OP: &str = "upload";
    let mut parts = Vec::new();
    let mut part_number = 0i32;
    let mut buffered = [first, second].into_iter();
    loop {
        let chunk = match buffered.next() {
            Some(chunk) => chunk,
            None => match recv_chunk(OP, ctx.rx, ctx.progress, ctx.cancel).await? {
                Some(chunk) => chunk,
                None => break,
            },
        };
        part_number += 1;
        let out = transfer_call(
            OP,
            ctx.cancel,
            ctx.client
                .upload_part()
                .bucket(ctx.bucket)
                .key(ctx.key)
                .upload_id(upload_id)
                .part_number(part_number)
                .content_length(chunk.len() as i64)
                .body(ByteStream::new(SdkBody::from(chunk)))
                .send(),
        )
        .await?;
        parts.push(
            CompletedPart::builder()
                .e_tag(out.e_tag().unwrap_or_default())
                .part_number(part_number)
                .build(),
        );
    }
    Ok(parts)
}

/// Best-effort abort: the result is deliberately discarded (upstream
/// relies on MinIO's stale-upload reclamation plus the reconcile sweep —
/// the abort accelerates it but is not load-bearing for correctness).
async fn abort_upload(client: &Client, bucket: &str, key: &str, upload_id: &str) {
    let send = client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .send();
    match tokio::time::timeout(Duration::from_secs(10), send).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "multipart abort was rejected; upload expires upstream")
        }
        Err(_) => tracing::debug!("multipart abort timed out; upload expires upstream"),
    }
}

// ---------------------------------------------------------------------------
// The ObjectStore port — thin boundary converting the adapter `Failure`
// ---------------------------------------------------------------------------

impl ObjectStore for S3ObjectStore {
    async fn upload(&self, request: UploadRequest) -> Result<UploadResult, PortFailure> {
        self.upload_inner(request).await.map_err(Into::into)
    }

    async fn read(
        &self,
        reference: ObjectRef,
    ) -> Result<(Box<dyn PortByteStream>, ObjectInfo), PortFailure> {
        match self.read_inner(reference).await {
            Ok((stream, info)) => Ok((Box::new(stream), info)),
            Err(err) => Err(err.into()),
        }
    }

    async fn promote_create_only(
        &self,
        source: ObjectRef,
        destination: ObjectRef,
    ) -> Result<ObjectInfo, PortFailure> {
        self.promote_inner(source, destination)
            .await
            .map_err(Into::into)
    }

    async fn remove_staging(&self, reference: ObjectRef) -> Result<(), PortFailure> {
        self.remove_staging_inner(reference)
            .await
            .map_err(Into::into)
    }

    async fn remove_ready_for_delete(&self, reference: ObjectRef) -> Result<(), PortFailure> {
        self.remove_ready_for_delete_inner(reference)
            .await
            .map_err(Into::into)
    }
}
