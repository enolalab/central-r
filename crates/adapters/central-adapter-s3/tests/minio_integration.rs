//! Tier-2 live MinIO integration test (port of upstream
//! `minio_integration_test.go`), gated on `CENTRAL_TEST_MINIO_ENDPOINT` —
//! it skips cleanly when the environment is absent, so the default
//! `cargo test` run never depends on it.
//!
//! Environment contract (all TEST credentials for a local Compose MinIO;
//! nothing in non-test code reads an object-store credential from the
//! environment):
//!
//! - `CENTRAL_TEST_MINIO_ENDPOINT`   — `host[:port]` (required to run)
//! - `CENTRAL_TEST_MINIO_ACCESS_KEY` — root access key (required)
//! - `CENTRAL_TEST_MINIO_SECRET_KEY` — root secret key (required)
//! - `CENTRAL_TEST_MINIO_BUCKET`     — default `central-artifacts`
//! - `CENTRAL_TEST_MINIO_TLS`        — `1` enables TLS

use std::io;

use central_adapter_s3::{Config, S3ObjectStore};
use central_artifact::port::{MAX_ARTIFACT_BODY_BYTES, ObjectRef, ObjectStore as _, UploadRequest};

const STAGING_KEY: &str = "v1/staging/0194aaaa0000700080000000000000aa/0194bbbb0000700080000000000000bb/0194cccc0000700080000000000000cc";
const READY_KEY: &str = "v1/ready/0194aaaa0000700080000000000000aa/0194bbbb0000700080000000000000bb/0194dddd0000700080000000000000dd";

struct Env {
    endpoint: String,
    access_key: String,
    secret_key: String,
    bucket: String,
    use_tls: bool,
}

fn require_minio() -> Option<Env> {
    let endpoint = std::env::var("CENTRAL_TEST_MINIO_ENDPOINT").ok()?;
    let access_key = std::env::var("CENTRAL_TEST_MINIO_ACCESS_KEY").ok()?;
    let secret_key = std::env::var("CENTRAL_TEST_MINIO_SECRET_KEY").ok()?;
    if endpoint.is_empty() || access_key.is_empty() || secret_key.is_empty() {
        return None;
    }
    Some(Env {
        endpoint,
        access_key,
        secret_key,
        bucket: std::env::var("CENTRAL_TEST_MINIO_BUCKET")
            .ok()
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| "central-artifacts".to_owned()),
        use_tls: std::env::var("CENTRAL_TEST_MINIO_TLS").ok().as_deref() == Some("1"),
    })
}

fn config(env: &Env) -> Config {
    Config {
        endpoint: env.endpoint.clone(),
        access_key_id: env.access_key.clone(),
        secret_access_key: env.secret_key.clone(),
        session_token: String::new(),
        bucket: env.bucket.clone(),
        region: "us-east-1".to_owned(),
        use_tls: env.use_tls,
    }
}

/// A raw admin client used only to create the bucket — never the client
/// under test.
async fn ensure_bucket(env: &Env) {
    let credentials = aws_sdk_s3::config::Credentials::new(
        env.access_key.clone(),
        env.secret_key.clone(),
        None,
        None,
        "central-minio-test-admin",
    );
    let conf = aws_sdk_s3::config::Builder::new()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_s3::config::SharedCredentialsProvider::new(
            credentials,
        ))
        .endpoint_url(format!(
            "{}://{}",
            if env.use_tls { "https" } else { "http" },
            env.endpoint
        ))
        .force_path_style(true)
        .build();
    let admin = aws_sdk_s3::Client::from_conf(conf);
    let _ = admin.create_bucket().bucket(&env.bucket).send().await; // exists → fine
}

/// The upstream happy-path lifecycle: upload → read → promote → second
/// promote conflicts without overwrite → remove_staging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn minio_upload_read_promote_conflict_remove() {
    let Some(env) = require_minio() else {
        eprintln!("CENTRAL_TEST_MINIO_* unset; MinIO integration case skipped");
        return;
    };
    ensure_bucket(&env).await;
    let s = S3ObjectStore::new(config(&env)).expect("S3ObjectStore::new");

    let staging_ref = ObjectRef {
        key: STAGING_KEY.to_owned(),
    };
    let ready_ref = ObjectRef {
        key: READY_KEY.to_owned(),
    };

    // Clean slate in case a previous run left residue.
    let _ = s.remove_staging(staging_ref.clone()).await;
    let _ = s.remove_ready_for_delete(ready_ref.clone()).await;

    let body = b"central-minio-body".repeat(4096);
    let up = s
        .upload(UploadRequest {
            reference: staging_ref.clone(),
            body: Box::new(io::Cursor::new(body.clone())),
            max_bytes: MAX_ARTIFACT_BODY_BYTES,
        })
        .await
        .expect("Upload");
    assert_eq!(up.info.size, body.len() as i64, "uploaded size");

    let (mut rc, info) = s.read(staging_ref.clone()).await.expect("Read");
    assert_eq!(info.size, body.len() as i64);
    let mut got = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = rc.read_chunk(&mut buf).await.expect("read chunk");
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    rc.close().await.expect("close");
    assert_eq!(got, body, "read body differs");

    let ready_info = s
        .promote_create_only(staging_ref.clone(), ready_ref.clone())
        .await
        .expect("PromoteCreateOnly");
    assert_eq!(ready_info.size, body.len() as i64);

    let second = s
        .promote_create_only(staging_ref.clone(), ready_ref.clone())
        .await
        .expect_err("second promote must conflict");
    assert_eq!(second.code(), "precondition_conflict");
    assert_eq!(
        second.kind(),
        central_foundation::failure::FailureKind::Conflict
    );

    // And the losing promote cannot have overwritten the winner.
    let (mut rc2, _) = s.read(ready_ref.clone()).await.expect("read ready");
    let mut got2 = Vec::new();
    loop {
        let n = rc2.read_chunk(&mut buf).await.expect("read chunk");
        if n == 0 {
            break;
        }
        got2.extend_from_slice(&buf[..n]);
    }
    rc2.close().await.expect("close");
    assert_eq!(got2, body, "ready object was overwritten");

    s.remove_staging(staging_ref.clone())
        .await
        .expect("RemoveStaging");
    let gone = s.read(staging_ref).await.err().expect("want not found");
    assert_eq!(gone.code(), "object_missing");
    s.remove_ready_for_delete(ready_ref)
        .await
        .expect("RemoveReadyForDelete");
}
