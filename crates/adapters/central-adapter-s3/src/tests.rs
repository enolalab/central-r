//! Ported unit/mock tests — upstream `minio_test.go` against `fakes3`.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use central_artifact::port::{
    ByteStream as _, MAX_ARTIFACT_BODY_BYTES, MAX_CONCURRENT_TRANSFERS, ObjectRef, ObjectStore,
    UploadRequest,
};

use crate::error::{FailureClass, Reason};
use crate::fakes3::{FakeS3, TEST_BUCKET};
use crate::store::{Config, S3ObjectStore, STAGING_PART_SIZE_BYTES};

const TEST_WORKSPACE: &str = "0194aaaa0000700080000000000000aa";
const TEST_ARTIFACT: &str = "0194bbbb0000700080000000000000bb";
const STAGING_KEY: &str = "v1/staging/0194aaaa0000700080000000000000aa/0194bbbb0000700080000000000000bb/0194cccc0000700080000000000000cc";
const READY_KEY: &str = "v1/ready/0194aaaa0000700080000000000000aa/0194bbbb0000700080000000000000bb/0194dddd0000700080000000000000dd";
const FIXTURE_KEY: &str = "v1/system/backup-throughput-fixture-v1";
const FIXTURE_BYTES: i64 = 512 * 1024 * 1024;

fn staging() -> ObjectRef {
    ObjectRef {
        key: STAGING_KEY.to_owned(),
    }
}

fn ready() -> ObjectRef {
    ObjectRef {
        key: READY_KEY.to_owned(),
    }
}

fn new_test_store(fake: &FakeS3) -> S3ObjectStore {
    S3ObjectStore::new(Config {
        endpoint: fake.endpoint().to_owned(),
        access_key_id: "test-access".to_owned(),
        secret_access_key: "test-secret-value".to_owned(),
        session_token: String::new(),
        bucket: TEST_BUCKET.to_owned(),
        region: "us-east-1".to_owned(),
        use_tls: false,
    })
    .expect("New store")
}

fn upload_request(body: &'static [u8], max_bytes: i64) -> UploadRequest {
    UploadRequest {
        reference: staging(),
        body: Box::new(io::Cursor::new(body.to_vec())),
        max_bytes,
    }
}

// ---------------------------------------------------------------------------
// Required test 1: atomic create-only promotion
// ---------------------------------------------------------------------------

/// Upstream `TestPromoteUsesCreateOnlyCondition`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promote_uses_create_only_condition() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    f.put_object(STAGING_KEY, b"staged body".to_vec());
    f.put_object(READY_KEY, b"pre-existing ready body".to_vec());

    let err = s
        .promote_inner(staging(), ready())
        .await
        .expect_err("want conflict");
    assert_eq!(err.class, FailureClass::Conflict, "class");
    assert_eq!(err.reason, Reason::PreconditionConflict, "reason");

    let obj = f.object(READY_KEY).expect("ready object");
    assert_eq!(
        obj.body, b"pre-existing ready body",
        "ready object was overwritten"
    );

    let mut saw_precondition = false;
    for req in f.recorded() {
        if req.header("if-none-match") == Some("*") {
            saw_precondition = true;
        }
        assert!(
            req.header("x-amz-copy-source").is_none(),
            "promotion used a server-side copy: {} {}",
            req.method,
            req.path
        );
        assert_ne!(
            req.method, "HEAD",
            "promotion used a HEAD probe before creating"
        );
    }
    assert!(saw_precondition, "no request carried If-None-Match: *");
}

/// Upstream `TestPromoteNeverInitiatesMultipartUpload`: a promotion must
/// never become a multipart upload — `If-None-Match` does not gate a
/// multipart commit on real S3/MinIO.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promote_never_initiates_multipart_upload() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    let body = vec![b'm'; 17 << 20];
    f.put_object(STAGING_KEY, body.clone());

    s.promote_inner(staging(), ready())
        .await
        .expect("PromoteCreateOnly");

    assert_eq!(
        f.count_requests(|r| r.method == "POST" && r.query_has("uploads")),
        0,
        "promotion initiated a multipart upload"
    );
    assert!(
        f.part_sizes().is_empty(),
        "promotion uploaded multipart parts"
    );
    assert!(
        f.recorded()
            .iter()
            .any(|r| r.method == "PUT" && r.header("if-none-match") == Some("*")),
        "no single PUT carried If-None-Match: *"
    );
    assert_eq!(f.object(READY_KEY).expect("ready").body, body);
}

/// Upstream `TestPromoteLargeBodyStillLosesToExistingReadyObject`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promote_large_body_still_loses_to_existing_ready_object() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    f.put_object(STAGING_KEY, vec![b'm'; 17 << 20]);
    f.put_object(READY_KEY, b"pre-existing ready body".to_vec());

    let err = s
        .promote_inner(staging(), ready())
        .await
        .expect_err("want conflict");
    assert_eq!(err.class, FailureClass::Conflict);
    assert_eq!(err.reason, Reason::PreconditionConflict);
    assert_eq!(
        f.object(READY_KEY).expect("ready").body,
        b"pre-existing ready body"
    );
}

// ---------------------------------------------------------------------------
// Required test 2: limit-plus-one streaming cutoff
// ---------------------------------------------------------------------------

/// Upstream `countingReader`: an endless body that records consumption.
struct CountingReader {
    read: Arc<AtomicI64>,
}

impl io::Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(b'a');
        self.read.fetch_add(buf.len() as i64, Ordering::Relaxed);
        Ok(buf.len())
    }
}

/// Upstream `TestUploadStopsAtLimitPlusOne`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_stops_at_limit_plus_one() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    const MAX: i64 = 10 << 20;
    let read = Arc::new(AtomicI64::new(0));
    let src = CountingReader {
        read: Arc::clone(&read),
    };

    let err = s
        .upload_inner(UploadRequest {
            reference: staging(),
            body: Box::new(src),
            max_bytes: MAX,
        })
        .await
        .expect_err("want limit failure");
    assert_eq!(err.class, FailureClass::LimitExceeded, "class");

    // Limit-plus-one: never more than one byte past the ceiling.
    assert_eq!(
        read.load(Ordering::Relaxed),
        MAX + 1,
        "consumed bytes (limit plus one)"
    );

    // The body is never committed: no CompleteMultipartUpload, no object;
    // and the initiated multipart upload was aborted.
    assert_eq!(
        f.count_requests(|r| r.method == "POST" && r.query_get("uploadId").is_some()),
        0,
        "body was committed despite exceeding the limit"
    );
    assert!(
        f.object(STAGING_KEY).is_none(),
        "over-limit object was created"
    );
    assert!(
        f.count_requests(|r| r.method == "DELETE" && r.query_get("uploadId").is_some()) >= 1,
        "over-limit multipart upload was never aborted"
    );
}

// ---------------------------------------------------------------------------
// Idle watchdog
// ---------------------------------------------------------------------------

/// Upstream `stalledReader`: one byte then never again.
struct StalledReader {
    once: AtomicBool,
    done: mpsc::Receiver<()>,
}

impl io::Read for StalledReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.once.swap(true, Ordering::SeqCst) {
            buf[0] = b'x';
            return Ok(1);
        }
        match self.done.recv() {
            Ok(()) | Err(_) => Ok(0),
        }
    }
}

/// Upstream `TestUploadIdleWatchdogCancelsStalledStream`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_idle_watchdog_cancels_stalled_stream() {
    let f = FakeS3::new();
    let mut s = new_test_store(&f);
    s.idle_timeout = Duration::from_millis(75);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let src = StalledReader {
        once: AtomicBool::new(false),
        done: done_rx,
    };
    let _guard = scopeguard(done_tx); // release the parked pump on test exit

    let started = std::time::Instant::now();
    let err = s
        .upload_inner(UploadRequest {
            reference: staging(),
            body: Box::new(src),
            max_bytes: MAX_ARTIFACT_BODY_BYTES,
        })
        .await
        .expect_err("want idle failure");
    let elapsed = started.elapsed();

    assert_eq!(err.reason, Reason::IdleTimeout, "reason");
    assert_eq!(
        err.class,
        FailureClass::Ambiguous,
        "a timeout is never a blind-retry signal"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "idle watchdog took {elapsed:?}"
    );
}

fn scopeguard<T>(value: T) -> impl Drop {
    struct Guard<T>(Option<T>);
    impl<T> Drop for Guard<T> {
        fn drop(&mut self) {
            drop(self.0.take());
        }
    }
    Guard(Some(value))
}

/// Upstream `TestUploadHoldsPermitUntilAbandonedTransferSettles`: an
/// abandoned transfer still holds its permit until the reader yields.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_holds_permit_until_abandoned_transfer_settles() {
    let f = FakeS3::new();
    let mut s = new_test_store(&f);
    s.idle_timeout = Duration::from_millis(50);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let src = StalledReader {
        once: AtomicBool::new(false),
        done: done_rx,
    };

    s.upload_inner(UploadRequest {
        reference: staging(),
        body: Box::new(src),
        max_bytes: MAX_ARTIFACT_BODY_BYTES,
    })
    .await
    .expect_err("want idle-timeout failure");

    // Every other permit is free...
    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_TRANSFERS - 1 {
        let permit = tokio::time::timeout(Duration::from_secs(1), s.limiter().acquire_owned())
            .await
            .expect("permit should be free")
            .expect("acquire");
        held.push(permit);
    }

    // ...but the abandoned transfer's own permit is not, because that
    // transfer is still running.
    let blocked =
        tokio::time::timeout(Duration::from_millis(250), s.limiter().acquire_owned()).await;
    assert!(
        blocked.is_err(),
        "permit was released while the abandoned transfer was still running"
    );

    // Letting the stalled reader yield settles the transfer, which is what
    // returns the permit.
    drop(done_tx);
    let settled = tokio::time::timeout(Duration::from_secs(10), s.limiter().acquire_owned()).await;
    assert!(
        settled.is_ok(),
        "permit was never released after the abandoned transfer settled"
    );
    drop(settled);
    drop(held);
}

// ---------------------------------------------------------------------------
// Bounded multipart part size
// ---------------------------------------------------------------------------

/// Upstream `TestUploadUsesBoundedMultipartPartSize`: part size pinned to
/// the S3 5 MiB minimum.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_uses_bounded_multipart_part_size() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    let body = vec![b'c'; 6 << 20];

    s.upload_inner(UploadRequest {
        reference: staging(),
        body: Box::new(io::Cursor::new(body)),
        max_bytes: MAX_ARTIFACT_BODY_BYTES,
    })
    .await
    .expect("Upload");

    let parts = f.part_sizes();
    assert_eq!(
        parts.len(),
        2,
        "6 MiB body should produce 2 parts at the 5 MiB minimum"
    );
    assert_eq!(parts[0], STAGING_PART_SIZE_BYTES, "first part size");
    for size in &parts {
        assert!(*size <= STAGING_PART_SIZE_BYTES, "part exceeds ceiling");
    }
}

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

/// Upstream `TestFailureNeverLeaksObjectLocator`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_never_leaks_object_locator() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    f.force_complete(403, "AccessDenied");

    let err = s
        .upload_inner(upload_request(b"body", 1024))
        .await
        .expect_err("want denied failure");
    assert_eq!(err.class, FailureClass::Denied, "class");

    let msg = err.to_string();
    for needle in [
        TEST_BUCKET,
        STAGING_KEY,
        TEST_WORKSPACE,
        TEST_ARTIFACT,
        f.endpoint(),
        "http",
        "Resource",
        "AccessDenied",
        "denied for",
        "req-1",
        "host-1",
    ] {
        assert!(!msg.contains(needle), "error {msg:?} leaked {needle:?}");
    }
    // The port-boundary failure is equally clean.
    let port: central_foundation::failure::Failure = err.into();
    let rendered = port.message().to_string();
    for needle in [TEST_BUCKET, STAGING_KEY, f.endpoint(), "denied for"] {
        assert!(!rendered.contains(needle), "port failure leaked {needle:?}");
    }
}

/// Upstream `TestReadMissingObjectIsTypedNotFound`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_missing_object_is_typed_not_found() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    let err = s.read_inner(staging()).await.err().expect("want not found");
    assert_eq!(err.class, FailureClass::NotFound, "class");
}

/// Upstream `TestReadIdleWatchdogClosesStalledBodyAndReturnsPermit`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_idle_watchdog_closes_stalled_body_and_returns_permit() {
    let f = FakeS3::new();
    let mut s = new_test_store(&f);
    s.idle_timeout = Duration::from_millis(75);
    f.put_object(READY_KEY, b"xy".to_vec());
    f.block_get(true);

    let (mut stream, _info) = s.read_inner(ready()).await.expect("Read");
    let mut first = [0u8; 1];
    let n = stream.read_chunk(&mut first).await.expect("first read");
    assert_eq!((n, first[0]), (1, b'x'), "one progress byte");

    let started = std::time::Instant::now();
    let mut buf = [0u8; 1];
    let err = stream.read_chunk(&mut buf).await.expect_err("stalled read");
    assert_eq!(
        err.kind(),
        central_foundation::failure::FailureKind::Ambiguous
    );
    assert_eq!(err.code(), "idle_timeout");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "read idle watchdog took too long"
    );

    // The watchdog owns terminal cleanup: both permits must be back even
    // though the caller has not closed the stream yet.
    for _ in 0..MAX_CONCURRENT_TRANSFERS {
        let permit = tokio::time::timeout(Duration::from_secs(2), s.limiter().acquire_owned())
            .await
            .expect("permit was not returned after stalled GET")
            .expect("acquire");
        drop(permit);
    }
    stream.close().await.expect("Close after watchdog");
}

// ---------------------------------------------------------------------------
// Backup throughput fixture
// ---------------------------------------------------------------------------

/// Upstream `TestBackupThroughputFixtureReadUsesOnlyFixedSystemKey`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixture_read_uses_only_fixed_system_key() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    f.put_fixture_object(FIXTURE_KEY, b"short test transport".to_vec(), FIXTURE_BYTES);

    let mut stream = s
        .open_backup_throughput_fixture()
        .await
        .expect("fixture open");
    stream.close().await.expect("close");

    let requests = f.recorded();
    assert_eq!(requests.len(), 1, "fixture requests");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].path,
        format!("/{TEST_BUCKET}/{FIXTURE_KEY}"),
        "fixture path"
    );

    // The generic object API must reject the fixed system key.
    let err = s
        .read_inner(ObjectRef {
            key: FIXTURE_KEY.to_owned(),
        })
        .await
        .err()
        .expect("system key must not be readable");
    assert_eq!(err.class, FailureClass::Invalid);
    assert_eq!(err.reason, Reason::KeyRoleInvalid);
}

/// Upstream `TestBackupThroughputFixtureReadRejectsWrongLength`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixture_read_rejects_wrong_length() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    f.put_object(FIXTURE_KEY, b"wrong length".to_vec());
    let err = s
        .open_backup_throughput_fixture()
        .await
        .err()
        .expect("want wrong-length failure");
    assert_eq!(err.class, FailureClass::Invalid);
    assert_eq!(err.reason, Reason::UpstreamRejected);
}

// ---------------------------------------------------------------------------
// Happy path and evidence
// ---------------------------------------------------------------------------

/// Upstream `TestUploadReadPromoteRoundTrip`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_read_promote_round_trip() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    let body = b"central".repeat(1024);

    let up = s
        .upload_inner(UploadRequest {
            reference: staging(),
            body: Box::new(io::Cursor::new(body.clone())),
            max_bytes: MAX_ARTIFACT_BODY_BYTES,
        })
        .await
        .expect("Upload");
    assert_eq!(up.info.size, body.len() as i64, "uploaded size");
    assert!(!up.info.etag.is_empty(), "upload returned no ETag");

    let (mut rc, info) = s.read_inner(staging()).await.expect("Read");
    assert_eq!(info.size, body.len() as i64, "read size");
    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = rc.read_chunk(&mut buf).await.expect("read body");
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    rc.close().await.expect("close");
    assert_eq!(got, body, "round-tripped body differs");

    let ready_info = s
        .promote_inner(staging(), ready())
        .await
        .expect("PromoteCreateOnly");
    assert_eq!(ready_info.size, body.len() as i64, "ready size");
    assert!(
        !ready_info.etag.is_empty() && !ready_info.version.is_empty(),
        "promotion returned no ETag/version evidence"
    );
    assert_eq!(f.object(READY_KEY).expect("ready").body, body);
}

/// Upstream `TestReadReleasesPermitOnClose`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_releases_permit_on_close() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    f.put_object(STAGING_KEY, b"staged".to_vec());

    let (mut rc, _info) = s.read_inner(staging()).await.expect("Read");

    // One permit is held while the stream is open.
    let second = tokio::time::timeout(Duration::from_millis(150), s.limiter().acquire_owned())
        .await
        .expect("second permit should still be available")
        .expect("acquire");
    let blocked =
        tokio::time::timeout(Duration::from_millis(100), s.limiter().acquire_owned()).await;
    assert!(blocked.is_err(), "an open read did not hold its permit");
    drop(second);

    rc.close().await.expect("Close");
    let regained = tokio::time::timeout(Duration::from_secs(1), s.limiter().acquire_owned()).await;
    assert!(
        regained.is_ok(),
        "Close did not release the transfer permit"
    );
}

// ---------------------------------------------------------------------------
// Key-role guards
// ---------------------------------------------------------------------------

/// Upstream `TestUploadRefusesNonStagingKey` plus the traversal matrix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_refuses_non_staging_key() {
    let f = FakeS3::new();
    let s = new_test_store(&f);

    for (name, key) in [
        ("ready key", READY_KEY),
        ("relative key", "../escape"),
        ("absolute key", "/v1/staging/x"),
        ("traversal key", "v1/staging/../x"),
        ("empty key", ""),
    ] {
        let err = s
            .upload_inner(UploadRequest {
                reference: ObjectRef {
                    key: key.to_owned(),
                },
                body: Box::new(io::Cursor::new(b"body".to_vec())),
                max_bytes: 1024,
            })
            .await
            .unwrap_err();
        assert_eq!(
            (err.class, err.reason),
            (FailureClass::Invalid, Reason::KeyRoleInvalid),
            "{name}"
        );
    }
    assert!(
        f.recorded().is_empty(),
        "a refused-key upload reached the object store"
    );
}

/// Upstream `TestPromoteRefusesNonReadyDestination`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn promote_refuses_non_ready_destination() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    f.put_object(STAGING_KEY, b"staged".to_vec());
    let other =
        format!("v1/staging/{TEST_WORKSPACE}/{TEST_ARTIFACT}/0194eeee0000700080000000000000ee");

    let err = s
        .promote_inner(staging(), ObjectRef { key: other })
        .await
        .unwrap_err();
    assert_eq!(
        (err.class, err.reason),
        (FailureClass::Invalid, Reason::KeyRoleInvalid)
    );
}

/// Upstream `TestRemoveStagingRefusesReadyKey` and
/// `TestRemoveStagingDeletesStagingKey`, plus the ready-side two-phase
/// delete path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removes_enforce_key_roles() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    f.put_object(READY_KEY, b"ready".to_vec());
    f.put_object(STAGING_KEY, b"staged".to_vec());

    let err = s.remove_staging_inner(ready()).await.unwrap_err();
    assert_eq!(
        (err.class, err.reason),
        (FailureClass::Invalid, Reason::KeyRoleInvalid)
    );
    assert!(
        f.object(READY_KEY).is_some(),
        "ready object was deleted by staging cleanup"
    );

    let err = s
        .remove_ready_for_delete_inner(staging())
        .await
        .unwrap_err();
    assert_eq!(
        (err.class, err.reason),
        (FailureClass::Invalid, Reason::KeyRoleInvalid)
    );
    assert!(
        f.object(STAGING_KEY).is_some(),
        "staging object was deleted by the ready-key path"
    );

    s.remove_staging_inner(staging())
        .await
        .expect("RemoveStaging");
    assert!(
        f.object(STAGING_KEY).is_none(),
        "staging object not removed"
    );

    s.remove_ready_for_delete_inner(ready())
        .await
        .expect("RemoveReadyForDelete");
    assert!(f.object(READY_KEY).is_none(), "ready object not removed");
}

/// Upstream `TestUploadRejectsOverCeilingMaxBytes` plus the zero/negative
/// bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_rejects_invalid_max_bytes() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    for (name, max_bytes) in [
        ("over ceiling", MAX_ARTIFACT_BODY_BYTES + 1),
        ("zero", 0),
        ("negative", -5),
    ] {
        let err = s
            .upload_inner(upload_request(b"body", max_bytes))
            .await
            .unwrap_err();
        assert_eq!(
            (err.class, err.reason),
            (FailureClass::Invalid, Reason::LimitInvalid),
            "{name}"
        );
    }
    assert!(
        f.recorded().is_empty(),
        "a refused upload reached the store"
    );
}

// ---------------------------------------------------------------------------
// Restore import (ADR 0034)
// ---------------------------------------------------------------------------

/// Upstream `TestRestoreBodyCreateOnlyWritesReadyKeysOnce`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_body_create_only_writes_ready_keys_once() {
    let f = FakeS3::new();
    let s = new_test_store(&f);

    let info = s
        .restore_body_create_only(
            READY_KEY.to_owned(),
            Box::new(io::Cursor::new(b"body-bytes".to_vec())),
            "body-bytes".len() as i64,
        )
        .await
        .expect("RestoreBodyCreateOnly");
    assert_eq!(info.size, "body-bytes".len() as i64);
    assert_eq!(
        f.object(READY_KEY).expect("stored").body,
        b"body-bytes".to_vec()
    );

    // The create rode a single conditional PUT with read-back evidence.
    assert!(
        f.recorded()
            .iter()
            .any(|r| r.method == "PUT" && r.header("if-none-match") == Some("*")),
        "no conditional PUT"
    );

    let err = s
        .restore_body_create_only(
            READY_KEY.to_owned(),
            Box::new(io::Cursor::new(b"other-bytes".to_vec())),
            "other-bytes".len() as i64,
        )
        .await
        .unwrap_err();
    assert_eq!(err.class, FailureClass::Conflict, "second create");
    assert_eq!(
        f.object(READY_KEY).expect("stored").body,
        b"body-bytes".to_vec(),
        "conflicting create overwrote the ready object"
    );
}

/// Upstream `TestRestoreBodyCreateOnlyRefusesBeforeAnyRequest`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_body_create_only_refuses_before_any_request() {
    let f = FakeS3::new();
    let s = new_test_store(&f);

    for (name, key) in [
        ("staging key", STAGING_KEY),
        ("relative key", "../escape"),
        ("absolute key", "/v1/ready/x"),
        ("traversal key", "v1/ready/../x"),
    ] {
        let err = s
            .restore_body_create_only(key.to_owned(), Box::new(io::Cursor::new(b"x".to_vec())), 1)
            .await
            .unwrap_err();
        assert_eq!(
            (err.class, err.reason),
            (FailureClass::Invalid, Reason::KeyRoleInvalid),
            "{name}"
        );
    }
    let err = s
        .restore_body_create_only(
            READY_KEY.to_owned(),
            Box::new(io::Cursor::new(b"x".to_vec())),
            -1,
        )
        .await
        .unwrap_err();
    assert_eq!(
        (err.class, err.reason),
        (FailureClass::Invalid, Reason::LimitInvalid),
        "negative size"
    );
    assert!(
        f.recorded().is_empty(),
        "a refused restore-body reached the object store"
    );
}

// ---------------------------------------------------------------------------
// HTTP classification matrix (upstream `classify` table)
// ---------------------------------------------------------------------------

/// Each forced HTTP status drives the documented failure class through the
/// single-PUT path — upstream's classification table, observed end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_classification_matrix() {
    let f = FakeS3::new();
    let s = new_test_store(&f);
    for (status, code, class, reason) in [
        (
            400u16,
            "BadRequest",
            FailureClass::Unavailable,
            Reason::UpstreamRejected,
        ),
        (
            401,
            "Unauthorized",
            FailureClass::Denied,
            Reason::AccessDenied,
        ),
        (
            403,
            "AccessDenied",
            FailureClass::Denied,
            Reason::AccessDenied,
        ),
        (
            405,
            "MethodNotAllowed",
            FailureClass::Unavailable,
            Reason::UpstreamRejected,
        ),
        (
            409,
            "Conflict",
            FailureClass::Conflict,
            Reason::PreconditionConflict,
        ),
        (
            411,
            "LengthRequired",
            FailureClass::Unavailable,
            Reason::UpstreamRejected,
        ),
        (
            413,
            "EntityTooLarge",
            FailureClass::Unavailable,
            Reason::UpstreamRejected,
        ),
        (
            500,
            "InternalError",
            FailureClass::Ambiguous,
            Reason::TransferIncomplete,
        ),
    ] {
        f.force_complete(status, code);
        let err = s
            .upload_inner(upload_request(b"body", 1024))
            .await
            .unwrap_err();
        assert_eq!(
            (err.class, err.reason),
            (class, reason),
            "status {status}/{code}"
        );
    }
    // Reset; a missing GET maps to NOT_FOUND.
    f.force_complete(0, "");
    let err = s.read_inner(staging()).await.err().expect("want not found");
    assert_eq!(
        (err.class, err.reason),
        (FailureClass::NotFound, Reason::ObjectMissing)
    );
}

// ---------------------------------------------------------------------------
// Trait-object conformance (upstream TestStoreSatisfiesObjectStorePort)
// ---------------------------------------------------------------------------

#[test]
fn store_satisfies_object_store_port() {
    fn assert_store<T: ObjectStore>() {}
    assert_store::<S3ObjectStore>();
    fn assert_limiter<T: central_artifact::port::TransferLimiter>() {}
    assert_limiter::<crate::TransferLimiter>();
}
