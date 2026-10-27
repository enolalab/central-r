//! `cmd/central/c06_scenario2_corruption_test.go` — C06 scenario 2: intentional
//! database AND object corruption, detected by the application's own
//! [`RestoredInventoryVerifier`], each of the domain's five quarantine reasons
//! produced by a distinct injection plus the packet's own row deletion.
//!
//! WHAT IS PORTED VERBATIM. The six-case injection plan (names, reasons,
//! surfaces, truncation/drift constants, per-case evidence-shape assertions),
//! the clean control before and after every injection, the combined
//! six-finding census, the schema-bound row-deletion probe, the inventory
//! snapshot predicate (`state = 'ready' AND delete_intent_at IS NULL`), the
//! expected-inventory stand-in, the operation built through the production
//! domain transitions only, both state-fingerprint captures (the strict
//! pre-corruption `validate` and the corrupted-instance
//! `validate_as_corrupted`), and the scope disclosure attached to every
//! expectation.
//!
//! THE TWO ADAPTATIONS, BOTH DISCLOSED.
//!
//! 1. THE EXPECTED INVENTORY IS READ OFF THE LIVE INSTANCE, EXACTLY AS
//!    UPSTREAM — the sealed-manifest anchor does not exist in the Rust port
//!    for the same reason it does not exist upstream (no sealable backup
//!    while the production composition supplies no throughput gate). The
//!    disclosure below says what a pass does and does not establish.
//!
//! 2. THE OBJECT INJECTION SURFACE IS THE PRODUCTION S3 ADAPTER, NOT A RAW
//!    CLIENT. Upstream tampers through a raw `minio.Client` and detects
//!    through the production `objectstore.Store`. The Rust port composes ONE
//!    object-store type, so this file runs TWO `S3ObjectStore` instances on
//!    distinct connections: one for injection, one (behind the
//!    `S3BackupObjectSource` -> `ReadyArtifactObjectReader` bridge, the same
//!    seam the kernel composes) for detection. The detector still observes
//!    what a bystander wrote rather than its own writes. Every body write —
//!    seed, injury and repair alike — goes through the production
//!    staging-upload + create-only-promote path the artifact flow itself
//!    uses, so the 1.5 GiB streamed body is never held whole (SC-DEF-92);
//!    the checksum injury prepares its replacement on a spooled temp file,
//!    exactly as upstream's `SpoolBodyToTemp` does.
//!
//! 3. THE CORPUS IS SEEDED BY THIS SCENARIO, OUTSIDE THE RECORDED CHECKS —
//!    the position upstream's removed per-scenario wrapper occupied before
//!    Task 12 folded seeding into scenario 1. Rust's s1 body is the
//!    `central backup create` verb, which seeds nothing; leaving seeding out
//!    would make the inventory-empty refusal an environmental fact rather
//!    than an assertion. Seeding is idempotent: it runs only when the ready
//!    inventory is empty, so the continuous run does not stack corpora.

use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use central_adapter_linux::backup::S3BackupObjectSource;
use central_adapter_postgres::backup::ReadyArtifactObjectReader;
use central_adapter_postgres::recovery::RestoredInventoryVerifier;
use central_adapter_postgres::store_support::BlockingConn;
use central_adapter_s3::{Config as S3Config, S3ObjectStore};
use central_artifact::port::{ObjectInfo, ObjectRef, ObjectStore, UploadRequest};
use central_backup::backup::capacity::RecoveryProfile;
use central_backup::backup::inventory::InventoryEntry;
use central_backup::backup::operation::{BACKUP_DATABASE_SCHEMA_VERSION, BACKUP_DUMP_TOOL_VERSION};
use central_backup::domain::TargetIdentity;
use central_backup::port::{ReadClose, RecoveryInventorySource};
use central_backup::recovery::operation::{RestoreOperation, RestoreTicket, new_restore_operation};
use central_backup::recovery::quarantine::{QuarantineFinding, QuarantineReason};
use central_foundation::failure::Failure;

/// Pump a body through SHA-256 without buffering it — the streamed subject
/// is digested in bounded chunks exactly as the detector reads it.
fn digest_stream(reader: &mut impl std::io::Read) -> std::io::Result<(u64, [u8; 32])> {
    let mut hash = Sha256::new();
    let mut chunk = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        hash.update(&chunk[..n]);
        size += n as u64;
    }
    Ok((size, hash.finalize().into()))
}

use crate::catalogue::ReasonClass;
use crate::evidence::transcript_digest;
use crate::fingerprint::{
    ArtifactFingerprint, STREAMED_BODY_FLOOR_BYTES, SchemaObject, SchemaObjectFingerprint,
    SchemaRelation, StateFingerprint, TableFingerprint, refuse_uncovered_relation_kinds,
    refuse_uncovered_schema_object_kinds,
};
use crate::fixture;
use crate::runner::runner;

// ---------------------------------------------------------------------------
// The scope disclosure — ported from upstream's c06Scenario2ScopeDisclosure,
// attached to every expectation and written at the transcript head.
// ---------------------------------------------------------------------------

pub(crate) const SCENARIO2_SCOPE_DISCLOSURE: &str = "SCOPE, CARRIED ON EVERY DIVERGENCE THIS SCENARIO EMITS: the expected inventory compared against here is read from the live instance before this scenario corrupts it, NOT from a sealed backup manifest -- no backup can be sealed on any host while the production composition supplies no throughput gate, and an acceptance suite must not supply one. A pass therefore establishes that the application detects THE INSTANCE HAVING CHANGED and names each corruption correctly; it does NOT establish detection against the sealed manifest, which is the authority a restore is judged by and which never entered this comparison. NOT SATISFIED, and not satisfiable until the gate exists: manifest-anchored detection. A pass here is also NOT end-to-end C04 evidence -- scenario 1 fails on that same missing gate, so this scenario can pass while the operator path that would have produced the backup it should be judged against does not work. The corruption is applied through a second production S3ObjectStore rather than a raw SDK client, because the Rust port composes one object-store type; the two stores are distinct connections over the same adapter, so the detector still observes what a bystander wrote rather than its own writes.";

/// `c06Expect` — every expectation this scenario states, with the scope
/// disclosure attached, as upstream requires (`s.Expect` is never called
/// bare).
pub(crate) fn expect(id: &str, what: impl AsRef<str>) {
    runner().attach_divergence(
        id,
        &format!("{}. {}", what.as_ref(), SCENARIO2_SCOPE_DISCLOSURE),
    );
}

// ---------------------------------------------------------------------------
// The scenario transcript (governance field 10's log_sha256).
// ---------------------------------------------------------------------------

/// `c06ScenarioLog` — one scenario's transcript. The digest is attached on
/// every record, so a body that fails still carries the digest of the
/// transcript up to the failure — upstream's cleanup ordering, reproduced by
/// attaching eagerly on each write rather than at teardown. The BYTES
/// persist on drop (`c06PersistTranscript`), beside where the emit step
/// writes the artifact, so every `log_sha256` the document commits to is
/// dereferenceable there — a digest naming a file nothing wrote is a
/// transcript that exists only inside the dropped allocation.
pub(crate) struct ScenarioLog {
    id: String,
    transcript: Vec<u8>,
    /// Whether this log belongs to an armed catalogue entry: armed logs
    /// attach their digest to the runner and persist their bytes on drop.
    /// Portable batteries run unarmed on any workstation and record no
    /// catalogue outcome, so their logs attach nothing and persist nothing
    /// — an attach from one would still write the shared digest slot of a
    /// catalogue entry, which is exactly the shared-record race the armed
    /// body is protected from.
    armed: bool,
}

impl ScenarioLog {
    /// The armed constructor, for a declared catalogue entry's body.
    pub(crate) fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            transcript: Vec::new(),
            armed: true,
        }
    }

    /// The portable constructor — `recordf` still accumulates the
    /// transcript so a battery's narration is exercisable, but nothing is
    /// attached and nothing is persisted: a portable check records no
    /// catalogue outcome, so its transcript has no artifact to be named by.
    pub(crate) fn portable(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            transcript: Vec::new(),
            armed: false,
        }
    }

    pub(crate) fn recordf(&mut self, args: std::fmt::Arguments<'_>) {
        use std::io::Write as _;
        let _ = self.transcript.write_fmt(args);
        let _ = self.transcript.write_all(b"\n");
        if self.armed {
            runner().attach_log(&self.id, &transcript_digest(&self.transcript));
        }
    }
}

impl Drop for ScenarioLog {
    /// `c06PersistTranscript` — writes the transcript into the evidence
    /// directory at mode 0600 through the same helper the emit step
    /// verifies against. This runs at body end AND during an unwind, so a
    /// failed entry still leaves the bytes its recorded `log_sha256`
    /// committed to — upstream's cleanup ordering, kept.
    ///
    /// A persist failure on the normal path is the scenario's own failure.
    /// A persist failure during unwind cannot panic a second time; it is
    /// recorded through [`crate::fixture::record_transcript_failure`] and
    /// the emit step refuses instead — an artifact must not be written
    /// over transcripts that do not exist.
    fn drop(&mut self) {
        if !self.armed || self.transcript.is_empty() {
            return;
        }
        let outcome = (|| -> Result<(), String> {
            let dir = crate::fixture::evidence_directory()?;
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("create the evidence directory: {e}"))?;
            let record = crate::evidence::write_transcript(
                dir.to_str()
                    .ok_or_else(|| "the evidence directory is not UTF-8".to_owned())?,
                &self.id,
                &self.transcript,
            )?;
            // The checksum the write returned is recomputed from the bytes
            // written; it must be the digest the last recordf attached,
            // or the file and the committed value disagree.
            let attached = transcript_digest(&self.transcript);
            if record.checksum_sha256 != attached {
                return Err(format!(
                    "the persisted transcript recomputes to {} and the attached log digest is {attached}",
                    record.checksum_sha256
                ));
            }
            Ok(())
        })();
        if let Err(e) = outcome {
            let message = format!("{}: {e}", self.id);
            if std::thread::panicking() {
                crate::fixture::record_transcript_failure(message);
            } else {
                panic!("persisting this entry's transcript failed: {message}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Environment gates — the live half of this scenario needs a real PostgreSQL
// and a real MinIO. Every gate names its env var in the skip detail.
// ---------------------------------------------------------------------------

pub(crate) const S3_BUCKET_ENV: &str = "CENTRAL_C06_S3_BUCKET";
pub(crate) const S3_ACCESS_KEY_ENV: &str = "CENTRAL_C06_S3_ACCESS_KEY";
pub(crate) const S3_SECRET_KEY_ENV: &str = "CENTRAL_C06_S3_SECRET_KEY";
pub(crate) const S3_TLS_ENV: &str = "CENTRAL_C06_S3_TLS";

/// One env var, required; `None` when unset-or-empty so the caller can skip
/// naming it.
pub(crate) fn require_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// The S3 adapter config from the env gates — never fabricated: every field
/// is read from the environment the reference host provides. The gate already
/// ran, so the required vars are present here.
pub(crate) fn s3_config() -> Result<S3Config, String> {
    let endpoint = require_env(fixture::S3_ENDPOINT_ENV).ok_or_else(|| {
        format!(
            "{} names no object-store endpoint",
            fixture::S3_ENDPOINT_ENV
        )
    })?;
    let bucket = require_env(S3_BUCKET_ENV)
        .ok_or_else(|| format!("{S3_BUCKET_ENV} names no object-store bucket"))?;
    let access_key_id = require_env(S3_ACCESS_KEY_ENV)
        .ok_or_else(|| format!("{S3_ACCESS_KEY_ENV} names no access key"))?;
    let secret_access_key = require_env(S3_SECRET_KEY_ENV)
        .ok_or_else(|| format!("{S3_SECRET_KEY_ENV} names no secret key"))?;
    let use_tls = std::env::var(S3_TLS_ENV).is_ok_and(|v| v.trim() == "1");
    Ok(S3Config {
        endpoint,
        access_key_id,
        secret_access_key,
        session_token: String::new(),
        bucket,
        region: "us-east-1".to_owned(),
        use_tls,
    })
}

/// The missing-gate precondition read: the live legs need real PostgreSQL
/// and MinIO. Runs in the precondition closure — a skip decides whether the
/// scenario runs at all and belongs before `run`, which is the only place it
/// can produce one outcome rather than two.
pub(crate) fn missing_live_env() -> Option<(ReasonClass, String)> {
    let missing: Vec<&str> = [
        fixture::PG_DSN_ENV,
        fixture::S3_ENDPOINT_ENV,
        S3_BUCKET_ENV,
        S3_ACCESS_KEY_ENV,
        S3_SECRET_KEY_ENV,
    ]
    .into_iter()
    .filter(|name| require_env(name).is_none())
    .collect();
    if missing.is_empty() {
        return None;
    }
    Some((
        ReasonClass::PreconditionFailed,
        format!(
            "the live corruption leg needs real PostgreSQL and MinIO; {} unset — fabricating the instance or the object store is exactly the failure this scenario exists to prevent",
            missing.join(", ")
        ),
    ))
}

/// `connectBlocking` — a dedicated session through the port's own sync/async
/// bridge. `BlockingConn::run` must be called off-runtime; scenario bodies
/// run on libtest's plain threads, so that holds.
pub(crate) fn connect_pg(dsn: &str) -> Result<BlockingConn, String> {
    let dsn_owned = dsn.to_owned();
    BlockingConn::new_connecting(move || {
        let dsn = dsn_owned.clone();
        async move {
            <sqlx::PgConnection as sqlx::Connection>::connect(&dsn)
                .await
                .map_err(|e| {
                    Failure::internal("c06", format!("connect the migrated database: {e}"))
                })
        }
    })
    .map_err(|e| format!("open the blocking bridge to the migrated database: {e}"))
}

// ---------------------------------------------------------------------------
// The corpus — `c06SeedCorpus`, through the production object path.
// ---------------------------------------------------------------------------

/// `c06DeriveReadyKey` — the ready key the production reader recomputes, in
/// the one place this suite composes it.
pub(crate) fn derive_ready_key(workspace_id: &str, artifact_id: &str, generation: &str) -> String {
    format!("v1/ready/{workspace_id}/{artifact_id}/{generation}")
}

fn derive_staging_key(workspace_id: &str, artifact_id: &str, generation: &str) -> String {
    format!("v1/staging/{workspace_id}/{artifact_id}/{generation}")
}

/// `c06SeedCorpus` — a known, bounded corpus in the live database and the
/// object store, written through the production staging -> ready path.
///
/// Every body is seeded through a reader, never a buffer (SC-DEF-92): the
/// digest pass and the upload pass read the same bytes; only the
/// (size, digest) pair is retained. `upload` pumps the stream through 5 MiB
/// parts and `promote_create_only` turns it into the ready object under the
/// adapter's atomic create-only precondition — the same two calls the
/// production artifact flow makes.
pub(crate) fn seed_corpus(
    conn: &BlockingConn,
    store: &S3ObjectStore,
    runtime: &tokio::runtime::Runtime,
) -> Result<(), String> {
    let owner = format!("c06-synthetic-owner-{}", std::process::id());
    let workspace_id: Uuid = conn
        .run(|c| {
            let owner = owner.clone();
            Box::pin(async move {
                sqlx::query_scalar(
                    "INSERT INTO central.workspaces (id, state, owner_principal_id)
                     VALUES (gen_random_uuid(), 'active', $1) RETURNING id",
                )
                .bind(&owner)
                .fetch_one(&mut *c)
                .await
                .map_err(|e| Failure::internal("c06", format!("seed the corpus workspace: {e}")))
            })
        })
        .map_err(|e| e.to_string())?;
    let task_id: Uuid = conn
        .run(|c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "INSERT INTO central.tasks (id, workspace_id, version, status, last_run_index, title, input_spec)
                     VALUES (gen_random_uuid(), $1::uuid, 1, 'running', 1, 'c06-synthetic-task', '{}'::jsonb)
                     RETURNING id",
                )
                .bind(workspace_id)
                .fetch_one(&mut *c)
                .await
                .map_err(|e| Failure::internal("c06", format!("seed the corpus task: {e}")))
            })
        })
        .map_err(|e| e.to_string())?;
    let run_id: Uuid = conn
        .run(|c| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "INSERT INTO central.runs (id, workspace_id, task_id, version, status, run_index)
                     VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 1, 'running', 1) RETURNING id",
                )
                .bind(workspace_id)
                .bind(task_id)
                .fetch_one(&mut *c)
                .await
                .map_err(|e| Failure::internal("c06", format!("seed the corpus run: {e}")))
            })
        })
        .map_err(|e| e.to_string())?;

    let workspace = workspace_id.to_string();
    for index in 0..=fixture::ORDINARY_ARTIFACT_COUNT {
        let (size, streamed) = if index == fixture::ORDINARY_ARTIFACT_COUNT {
            (fixture::STREAMED_BODY_SIZE, true)
        } else {
            (fixture::ORDINARY_BODY_SIZE as u64, false)
        };
        let label = format!("body-{index:02}");
        let digest: [u8; 32] = {
            let mut stream = fixture::SyntheticBodyReader::new(&label, size);
            digest_stream(&mut stream)
                .map_err(|e| format!("digest corpus body {label}: {e}"))?
                .1
        };
        // The identity and the content generation are minted here so the
        // ready key can be derived exactly as the production readers
        // recompute it.
        let minted = Uuid::now_v7();
        let generation = Uuid::now_v7();
        let ready_key = derive_ready_key(&workspace, &minted.to_string(), &generation.to_string());
        let staging_key =
            derive_staging_key(&workspace, &minted.to_string(), &Uuid::now_v7().to_string());

        let (artifact_id, held_key): (String, String) = conn
            .run(|c| {
                let (ready_key, label) = (ready_key.clone(), label.clone());
                Box::pin(async move {
                    let row: (String, String) = sqlx::query_as(
                        "INSERT INTO central.artifacts (
                            id, workspace_id, task_id, run_id, state, staging_generation, object_key,
                            sensitivity, disposition, size, media_type,
                            checksum_algorithm, checksum_value, content_generation, ready_key, ready_at
                         ) VALUES (
                            $4::uuid, $1::uuid, $2::uuid, $3::uuid, 'ready', gen_random_uuid(),
                            $7, 'unrestricted', 'attachment', $5, 'application/octet-stream',
                            'sha256', $6, $8::uuid, $7, now()
                         ) RETURNING id::text, ready_key",
                    )
                    .bind(workspace_id)
                    .bind(task_id)
                    .bind(run_id)
                    .bind(minted)
                    .bind(size as i64)
                    .bind(digest.to_vec())
                    .bind(&ready_key)
                    .bind(generation)
                    .fetch_one(&mut *c)
                    .await
                    .map_err(|e| Failure::internal("c06", format!("seed corpus artifact {label}: {e}")))?;
                    Ok(row)
                })
            })
            .map_err(|e| e.to_string())?;
        // Read back rather than assumed: the key the row actually carries is
        // what both readers derive against.
        if held_key != ready_key || artifact_id != minted.to_string() {
            return Err(format!(
                "corpus artifact {label} was seeded with identity {minted} and ready key {ready_key:?}; the row holds {artifact_id} and {held_key:?}, so the key the production readers derive would not match the row"
            ));
        }

        let body: Box<dyn std::io::Read + Send> =
            Box::new(fixture::SyntheticBodyReader::new(&label, size));
        runtime
            .block_on(store.upload(UploadRequest {
                reference: ObjectRef {
                    key: staging_key.clone(),
                },
                body,
                max_bytes: size as i64,
            }))
            .map_err(|e| format!("stage corpus body {label} into the object store: {e}"))?;
        runtime
            .block_on(
                store.promote_create_only(
                    ObjectRef { key: staging_key },
                    ObjectRef { key: ready_key },
                ),
            )
            .map_err(|e| format!("promote corpus body {label} to ready: {e}"))?;
        let _ = streamed;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The inventory snapshot + expected-inventory stand-in.
// ---------------------------------------------------------------------------

type InventoryRowTuple = (Uuid, Uuid, Uuid, Uuid, String, i64, Vec<u8>);
type ArtifactRowTuple = (
    Uuid,
    i64,
    Vec<u8>,
    Uuid,
    String,
    String,
    String,
    String,
    String,
);

/// `c06InventoryRow` — one ready artifact as the live instance holds it.
/// The ready key is carried here and never leaves this file (the injections
/// act on the object store directly).
#[derive(Clone)]
pub(crate) struct InventoryRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub task_id: Uuid,
    pub run_id: Uuid,
    pub ready_key: String,
    pub size: i64,
    pub checksum: [u8; 32],
}

impl InventoryRow {
    fn entry(&self) -> InventoryEntry {
        InventoryEntry {
            artifact_id: self.id,
            checksum: self.checksum,
            size: self.size,
        }
    }
}

/// `c06ReadInventorySnapshot` — the production predicate, character for
/// character: `state = 'ready' AND delete_intent_at IS NULL`, in identity
/// order.
pub(crate) fn read_inventory_snapshot(conn: &BlockingConn) -> Result<Vec<InventoryRow>, String> {
    conn.run(|c| {
        Box::pin(async move {
            let rows: Vec<InventoryRowTuple> = sqlx::query_as(
                "SELECT id, workspace_id, task_id, run_id, ready_key, size, checksum_value
                 FROM central.artifacts
                 WHERE state = 'ready' AND delete_intent_at IS NULL
                 ORDER BY id ASC",
            )
            .fetch_all(&mut *c)
            .await
            .map_err(|e| {
                Failure::internal("c06", format!("read the pre-corruption ready inventory: {e}"))
            })?;
            let mut snapshot = Vec::with_capacity(rows.len());
            for (id, workspace_id, task_id, run_id, ready_key, size, checksum) in rows {
                if checksum.len() != 32 {
                    return Err(Failure::internal(
                        "c06",
                        format!(
                            "artifact {id} records a {}-byte checksum; the inventory comparison is over sha-256",
                            checksum.len()
                        ),
                    ));
                }
                let mut sum = [0u8; 32];
                sum.copy_from_slice(&checksum);
                snapshot.push(InventoryRow {
                    id,
                    workspace_id,
                    task_id,
                    run_id,
                    ready_key,
                    size,
                    checksum: sum,
                });
            }
            Ok(snapshot)
        })
    })
    .map_err(|e| e.to_string())
}

/// `c06ExpectedInventory` — the snapshot as the application's inventory type,
/// ascending identity order (strictly — `canonical_inventory_entries`
/// requires it).
fn expected_inventory(snapshot: &[InventoryRow]) -> Vec<InventoryEntry> {
    let mut entries: Vec<InventoryEntry> = snapshot.iter().map(InventoryRow::entry).collect();
    entries.sort_by_key(|e| e.artifact_id.to_string());
    entries
}

/// `c06PreCorruptionInventory` — the stand-in `RecoveryInventorySource`:
/// returns the inventory this run read off the live instance before it
/// corrupted anything, in place of the sealed media walk that cannot run
/// until a backup can be sealed.
struct PreCorruptionInventory {
    entries: Vec<InventoryEntry>,
}

impl RecoveryInventorySource for PreCorruptionInventory {
    fn read_verified_inventory(
        &self,
        backup_id: Uuid,
        profile: &RecoveryProfile,
    ) -> Result<Vec<InventoryEntry>, Failure> {
        if backup_id.is_nil() || profile.validate().is_err() {
            return Err(Failure::internal(
                "c06",
                "the inventory stand-in was called with an input the real source would refuse",
            ));
        }
        Ok(self.entries.clone())
    }
}

// ---------------------------------------------------------------------------
// The operation the findings are stamped with.
// ---------------------------------------------------------------------------

/// `c06InventoryVerificationOperation` — a `RestoreOperation` in the one
/// state `verify_inventory` admits, through the production domain
/// transitions and nothing else, with a synthetic ticket proven not to
/// verify under any key.
fn inventory_verification_operation() -> Result<RestoreOperation, String> {
    let now = time::OffsetDateTime::now_utc();
    let opaque = |label: &str| {
        format!(
            "sha256:{}",
            crate::hex_lower(Sha256::digest(label.as_bytes()))
        )
    };
    let ticket = RestoreTicket {
        ticket_id: Uuid::now_v7(),
        operation_id: Uuid::now_v7(),
        backup_id: Uuid::now_v7(),
        target: TargetIdentity {
            system_id: "c06-synthetic-system".to_owned(),
            database_oid: "1".to_owned(),
            database: "central".to_owned(),
            config_hash: opaque("target-config"),
            epoch: 1,
        },
        target_fingerprint: opaque("target"),
        manifest_digest: opaque("manifest"),
        config_fingerprint: opaque("config"),
        security_epoch: 1,
        restore_epoch: 1,
        payload_epoch_id: Uuid::now_v7(),
        database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.to_owned(),
        capacity_evidence_digest: opaque("capacity"),
        tool_version: BACKUP_DUMP_TOOL_VERSION.to_owned(),
        hidden_nonce: b"c06-synthetic-nonce".to_vec(),
        issued_at: now - time::Duration::minutes(1),
        expires_at: now + time::Duration::hours(1),
        hmac: String::new(),
    };
    if ticket.verify_hmac(b"any key at all") {
        return Err(
            "the synthetic restore ticket verified against an arbitrary key; a ticket this file constructed must never satisfy the broker's own HMAC check"
                .to_owned(),
        );
    }
    let operation = new_restore_operation(&ticket, now).map_err(|e| {
        format!("the production domain constructor refused the scenario's restore record ({e}); nothing below this line would be a statement about corruption detection")
    })?;
    let operation = operation
        .record_database_replaced(now + time::Duration::seconds(1))
        .map_err(|e| format!("the database-replaced checkpoint was refused: {e}"))?;
    let operation = operation
        .begin_verification(now + time::Duration::seconds(2))
        .map_err(|e| format!("the verification transition was refused: {e}"))?;
    if operation.validate().is_err() {
        return Err(
            "the operation the findings would be stamped with does not validate".to_owned(),
        );
    }
    if !operation.admits_inventory_verification() {
        return Err(format!(
            "the operation reached phase {} at checkpoint {}, which does not admit inventory verification; verify_inventory would refuse it before reading anything",
            operation.phase.as_str(),
            operation.last_checkpoint.as_str()
        ));
    }
    Ok(operation)
}

// ---------------------------------------------------------------------------
// The detector — the application's own detection path, composed over the live
// stores through a SECOND S3 store (the injection store is distinct).
// ---------------------------------------------------------------------------

struct Detector {
    verifier: RestoredInventoryVerifier,
    operation: RestoreOperation,
}

impl Detector {
    /// `Detect` — one inventory verification pass; an error is NEVER
    /// "nothing was found" (upstream: an error reports no finding, names no
    /// artifact and names no corruption — it is fatal, not clean).
    fn detect(&self, occasion: &str) -> Result<Vec<QuarantineFinding>, String> {
        let mut findings = self.verifier.verify_inventory(&self.operation).map_err(|e| {
            format!("the application's inventory verification refused to complete over {occasion} ({e}). This is a refusal and NOT a detection: it reports no finding, names no artifact and names no corruption")
        })?;
        findings.sort_by_key(|f| f.artifact_id.to_string());
        Ok(findings)
    }

    /// `DetectClean` — the control every injection is measured against.
    fn detect_clean(&self, occasion: &str) -> Result<(), String> {
        let findings = self.detect(occasion)?;
        if !findings.is_empty() {
            return Err(format!(
                "the application reported {} finding(s) over {occasion}, where it must report none: {}. Every assertion compares against a clean control, and a control that is not clean makes each of them meaningless",
                findings.len(),
                describe_findings(&findings)
            ));
        }
        Ok(())
    }
}

/// `c06DescribeFindings` — opaque identity and reason only, the only fields
/// a `QuarantineFinding` may carry.
fn describe_findings(findings: &[QuarantineFinding]) -> String {
    findings
        .iter()
        .map(|f| format!("{}={}", f.artifact_id, f.reason.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `c06QuarantineReasons` — the domain's whole enumeration, in declaration
/// order.
fn quarantine_reasons() -> [QuarantineReason; 5] {
    [
        QuarantineReason::MissingBody,
        QuarantineReason::ChecksumMismatch,
        QuarantineReason::SizeMismatch,
        QuarantineReason::UnexpectedArtifact,
        QuarantineReason::MetadataMismatch,
    ]
}

fn reason_index(reason: QuarantineReason) -> usize {
    quarantine_reasons()
        .iter()
        .position(|r| *r == reason)
        .unwrap_or(usize::MAX)
}

// ---------------------------------------------------------------------------
// The corruption kit — the live database plus the injection-side object
// store. Every body write goes through staging + create-only promote; the
// streamed subject is spooled through a temp file, never held (SC-DEF-92).
// ---------------------------------------------------------------------------

pub(crate) struct CorruptionKit {
    pub(crate) conn: Arc<BlockingConn>,
    pub(crate) store: Arc<S3ObjectStore>,
    pub(crate) runtime: Arc<tokio::runtime::Runtime>,
}

impl CorruptionKit {
    /// Read a body whole through the injection store — ordinary bodies only;
    /// the streamed subject goes through [`Self::spool_body_to_temp`].
    pub(crate) fn read_body(&self, key: &str) -> Result<Vec<u8>, String> {
        let (mut stream, _info) = self
            .runtime
            .block_on(self.store.read(ObjectRef {
                key: key.to_owned(),
            }))
            .map_err(|e| format!("open a body to injure it: {e}"))?;
        let mut body = Vec::new();
        let mut chunk = vec![0u8; 256 * 1024];
        loop {
            let n = self
                .runtime
                .block_on(stream.read_chunk(&mut chunk))
                .map_err(|e| format!("read a body to injure it: {e}"))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        self.runtime
            .block_on(stream.close())
            .map_err(|e| format!("close a body after reading it: {e}"))?;
        Ok(body)
    }

    /// `SpoolBodyToTemp` — streams a body into a temp file (SC-DEF-92):
    /// injuries on the 1.5 GiB body must not hold it in RAM. The caller
    /// removes the file when the injection is repaired.
    pub(crate) fn spool_body_to_temp(&self, key: &str) -> Result<(PathBuf, i64), String> {
        use std::io::Write as _;
        let (mut stream, _info) = self
            .runtime
            .block_on(self.store.read(ObjectRef {
                key: key.to_owned(),
            }))
            .map_err(|e| format!("open a body to spool it: {e}"))?;
        let path = std::env::temp_dir().join(format!("c06-spooled-body-{}", Uuid::now_v7()));
        let mut spooled =
            std::fs::File::create(&path).map_err(|e| format!("spool a body to temp: {e}"))?;
        let mut size = 0i64;
        let mut chunk = vec![0u8; 1024 * 1024];
        let spool_result = (|| -> Result<(), String> {
            loop {
                let n = self
                    .runtime
                    .block_on(stream.read_chunk(&mut chunk))
                    .map_err(|e| format!("read a body to spool it: {e}"))?;
                if n == 0 {
                    break;
                }
                spooled
                    .write_all(&chunk[..n])
                    .map_err(|e| format!("write a spooled body: {e}"))?;
                size += n as i64;
            }
            Ok(())
        })();
        let close = self.runtime.block_on(stream.close());
        if let Err(e) = spool_result.and(close.map_err(|e| e.to_string())) {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        Ok((path, size))
    }

    /// Delete the ready object at `key`; a missing object is not an error —
    /// a write that follows it still lands under create-only.
    pub(crate) fn remove_body(&self, key: &str) -> Result<(), String> {
        self.runtime
            .block_on(self.store.remove_ready_for_delete(ObjectRef {
                key: key.to_owned(),
            }))
            .map_err(|e| format!("delete a body from the object store: {e}"))
    }

    /// Write `body` at `key` through staging + create-only promote — the
    /// production object-creation path, so the injury lands exactly where
    /// the application reads.
    pub(crate) fn put_body(&self, key: &str, body: Vec<u8>) -> Result<(), String> {
        let size = body.len() as i64;
        self.put_body_streaming(key, Box::new(std::io::Cursor::new(body)), size)
    }

    /// Write a body at `key` from a reader — the streamed subjects' path.
    pub(crate) fn put_body_streaming(
        &self,
        key: &str,
        body: Box<dyn std::io::Read + Send>,
        size: i64,
    ) -> Result<(), String> {
        // The ready slot must be empty for the create-only precondition —
        // the injury is a delete+create, never an overwrite the store would
        // not let the bystander perform anyway.
        let _ = self
            .runtime
            .block_on(self.store.remove_ready_for_delete(ObjectRef {
                key: key.to_owned(),
            }));
        let staging = format!("v1/staging/c06-tamper/{}", Uuid::now_v7());
        self.runtime
            .block_on(self.store.upload(UploadRequest {
                reference: ObjectRef {
                    key: staging.clone(),
                },
                body,
                max_bytes: size,
            }))
            .map_err(|e| format!("stage a body: {e}"))?;
        self.runtime
            .block_on(self.store.promote_create_only(
                ObjectRef { key: staging },
                ObjectRef {
                    key: key.to_owned(),
                },
            ))
            .map_err(|e| format!("promote a body to ready: {e}"))?;
        Ok(())
    }

    /// `PutBodyFromFile` — write exactly the spooled file's bytes at `key`.
    pub(crate) fn put_body_from_file(
        &self,
        key: &str,
        path: &std::path::Path,
        size: i64,
    ) -> Result<(), String> {
        let file = std::fs::File::open(path)
            .map_err(|e| format!("open a spooled body to write it: {e}"))?;
        self.put_body_streaming(key, Box::new(file), size)
    }

    pub(crate) fn exec(&self, what: &str, statement: &str, binds: &[Bind]) -> Result<(), String> {
        let what = what.to_owned();
        let statement = statement.to_owned();
        let binds = binds.to_vec();
        self.conn
            .run(|c| {
                Box::pin(async move {
                    let mut query = sqlx::query(&statement);
                    for bind in binds {
                        query = match bind {
                            Bind::Uuid(v) => query.bind(v),
                            Bind::I64(v) => query.bind(v),
                            Bind::Text(v) => query.bind(v),
                            Bind::Bytes(v) => query.bind(v),
                        };
                    }
                    query
                        .execute(&mut *c)
                        .await
                        .map_err(|e| Failure::internal("c06", format!("{what}: {e}")))?;
                    Ok(())
                })
            })
            .map_err(|e| e.to_string())
    }

    pub(crate) fn query_scalar_i64(
        &self,
        what: &str,
        statement: &str,
        binds: &[Bind],
    ) -> Result<i64, String> {
        let what = what.to_owned();
        let statement = statement.to_owned();
        let binds = binds.to_vec();
        self.conn
            .run(|c| {
                Box::pin(async move {
                    let mut query = sqlx::query_scalar(&statement);
                    for bind in binds {
                        query = match bind {
                            Bind::Uuid(v) => query.bind(v),
                            Bind::I64(v) => query.bind(v),
                            Bind::Text(v) => query.bind(v),
                            Bind::Bytes(v) => query.bind(v),
                        };
                    }
                    let value: i64 = query
                        .fetch_one(&mut *c)
                        .await
                        .map_err(|e| Failure::internal("c06", format!("{what}: {e}")))?;
                    Ok(value)
                })
            })
            .map_err(|e| e.to_string())
    }

    pub(crate) fn query_scalar_bool(
        &self,
        what: &str,
        statement: &str,
        binds: &[Bind],
    ) -> Result<bool, String> {
        let what = what.to_owned();
        let statement = statement.to_owned();
        let binds = binds.to_vec();
        self.conn
            .run(|c| {
                Box::pin(async move {
                    let mut query = sqlx::query_scalar(&statement);
                    for bind in binds {
                        query = match bind {
                            Bind::Uuid(v) => query.bind(v),
                            Bind::I64(v) => query.bind(v),
                            Bind::Text(v) => query.bind(v),
                            Bind::Bytes(v) => query.bind(v),
                        };
                    }
                    let value: bool = query
                        .fetch_one(&mut *c)
                        .await
                        .map_err(|e| Failure::internal("c06", format!("{what}: {e}")))?;
                    Ok(value)
                })
            })
            .map_err(|e| e.to_string())
    }
}

#[derive(Clone)]
pub(crate) enum Bind {
    Uuid(Uuid),
    I64(i64),
    Text(String),
    Bytes(Vec<u8>),
}

// ---------------------------------------------------------------------------
// The corruption plan — six cases, one per quarantine reason plus the
// packet's own row deletion, ported case-for-case.
// ---------------------------------------------------------------------------

const CORRUPTION_SURFACE_OBJECTS: &str = "object store";
const CORRUPTION_SURFACE_DATABASE: &str = "database";
/// `c06SizeMismatchTruncation` — 101 bytes, not one: a single-byte
/// truncation would also change the digest, and a finding that could be
/// explained by either damage is not a finding that names this one.
const SIZE_MISMATCH_TRUNCATION: i64 = 101;
/// `c06MetadataSizeDrift` — positive, so the recorded size cannot collide
/// with a truncation, and small enough that the row still satisfies
/// `artifacts_size_check`.
const METADATA_SIZE_DRIFT: i64 = 7;

enum CorruptionCase {
    BodyDeleted,
    ChecksumMismatch,
    BodyTruncated,
    SizeAltered,
    UnexpectedArtifact,
    RowDeleted,
}

impl CorruptionCase {
    fn plan() -> [CorruptionCase; 6] {
        [
            Self::BodyDeleted,
            Self::ChecksumMismatch,
            Self::BodyTruncated,
            Self::SizeAltered,
            Self::UnexpectedArtifact,
            Self::RowDeleted,
        ]
    }

    fn name(&self) -> &'static str {
        match self {
            Self::BodyDeleted => "the artifact's body was deleted from the object store",
            Self::ChecksumMismatch => {
                "the artifact's body was replaced with different bytes of the same length"
            }
            Self::BodyTruncated => "the artifact's body was truncated in the object store",
            Self::SizeAltered => "the artifact row's recorded size was altered in the database",
            Self::UnexpectedArtifact => {
                "a ready artifact row the inventory never carried was added to the database"
            }
            Self::RowDeleted => {
                "the artifact's row was deleted from the database (the C06 packet's own injection)"
            }
        }
    }

    fn reason(&self) -> QuarantineReason {
        match self {
            Self::BodyDeleted => QuarantineReason::MissingBody,
            Self::ChecksumMismatch => QuarantineReason::ChecksumMismatch,
            Self::BodyTruncated => QuarantineReason::SizeMismatch,
            Self::SizeAltered => QuarantineReason::MetadataMismatch,
            Self::UnexpectedArtifact => QuarantineReason::UnexpectedArtifact,
            Self::RowDeleted => QuarantineReason::MetadataMismatch,
        }
    }

    fn surface(&self) -> &'static str {
        match self {
            Self::BodyDeleted | Self::ChecksumMismatch | Self::BodyTruncated => {
                CORRUPTION_SURFACE_OBJECTS
            }
            Self::SizeAltered | Self::UnexpectedArtifact | Self::RowDeleted => {
                CORRUPTION_SURFACE_DATABASE
            }
        }
    }
}

/// A repair closure: puts the instance back the way the injection found it.
type Repair = Box<dyn FnOnce(&CorruptionKit) -> Result<(), String> + Send>;

fn inject(
    case: &CorruptionCase,
    kit: &CorruptionKit,
    target: &InventoryRow,
) -> Result<(Uuid, Repair), String> {
    match case {
        CorruptionCase::BodyDeleted => {
            let body = kit.read_body(&target.ready_key)?;
            kit.remove_body(&target.ready_key)?;
            let key = target.ready_key.clone();
            Ok((target.id, Box::new(move |kit| kit.put_body(&key, body))))
        }
        CorruptionCase::ChecksumMismatch => {
            // SC-DEF-92: this case runs on the streamed body, so the injury
            // is prepared on spooled files, never in RAM. The LAST byte is
            // flipped — a corruption at the head is found by a reader that
            // gives up early; the class this case is about is one only a
            // complete read can see, and on the streamed subject that means
            // every part of a multipart object.
            let (original, size) = kit.spool_body_to_temp(&target.ready_key)?;
            if size == 0 {
                let _ = std::fs::remove_file(&original);
                return Err(format!(
                    "artifact {} has an empty body; flipping a bit in it would change nothing",
                    target.id
                ));
            }
            let injured_path =
                std::env::temp_dir().join(format!("c06-injured-body-{}", Uuid::now_v7()));
            let copy_result = (|| -> Result<(), String> {
                let mut source = std::fs::File::open(&original)
                    .map_err(|e| format!("open the spooled original: {e}"))?;
                let mut injured = std::fs::File::create(&injured_path)
                    .map_err(|e| format!("spool the injured copy: {e}"))?;
                std::io::copy(&mut source, &mut injured)
                    .map_err(|e| format!("spool the injured copy: {e}"))?;
                use std::io::{Read as _, Seek as _, Write as _};
                injured
                    .seek(std::io::SeekFrom::Start((size - 1) as u64))
                    .map_err(|e| format!("seek the spooled last byte: {e}"))?;
                let mut last = [0u8; 1];
                injured
                    .read_exact(&mut last)
                    .map_err(|e| format!("read the spooled last byte: {e}"))?;
                last[0] ^= 0xFF;
                injured
                    .seek(std::io::SeekFrom::Start((size - 1) as u64))
                    .map_err(|e| format!("seek back to the spooled last byte: {e}"))?;
                injured
                    .write_all(&last)
                    .map_err(|e| format!("flip the spooled last byte: {e}"))?;
                Ok(())
            })();
            if let Err(e) = copy_result {
                let _ = std::fs::remove_file(&original);
                let _ = std::fs::remove_file(&injured_path);
                return Err(e);
            }
            kit.put_body_from_file(&target.ready_key, &injured_path, size)?;
            let _ = std::fs::remove_file(&injured_path);
            let key = target.ready_key.clone();
            Ok((
                target.id,
                Box::new(move |kit| {
                    let result = kit.put_body_from_file(&key, &original, size);
                    let _ = std::fs::remove_file(&original);
                    result
                }),
            ))
        }
        CorruptionCase::BodyTruncated => {
            let body = kit.read_body(&target.ready_key)?;
            if body.len() as i64 <= SIZE_MISMATCH_TRUNCATION {
                return Err(format!(
                    "artifact {} is {} bytes, which is not long enough to lose {SIZE_MISMATCH_TRUNCATION} and still be a body",
                    target.id,
                    body.len()
                ));
            }
            let truncated = body[..body.len() - SIZE_MISMATCH_TRUNCATION as usize].to_vec();
            kit.put_body(&target.ready_key, truncated)?;
            let key = target.ready_key.clone();
            Ok((target.id, Box::new(move |kit| kit.put_body(&key, body))))
        }
        CorruptionCase::SizeAltered => {
            kit.exec(
                "alter an artifact row's recorded size",
                "UPDATE central.artifacts SET size = size + $2 WHERE id = $1::uuid",
                &[Bind::Uuid(target.id), Bind::I64(METADATA_SIZE_DRIFT)],
            )?;
            let id = target.id;
            Ok((
                id,
                Box::new(move |kit| {
                    kit.exec(
                        "restore an artifact row's recorded size",
                        "UPDATE central.artifacts SET size = size - $2 WHERE id = $1::uuid",
                        &[Bind::Uuid(id), Bind::I64(METADATA_SIZE_DRIFT)],
                    )
                }),
            ))
        }
        CorruptionCase::UnexpectedArtifact => {
            // Seeded in the same shape the corpus is, off the same
            // workspace, task and run, so the only thing that distinguishes
            // it is that the inventory does not carry it. A row the reader
            // would refuse for any other reason would be an
            // ErrRestoredInventory rather than a finding, and this case
            // would then pass for a refusal.
            let intruder = Uuid::now_v7();
            let generation = Uuid::now_v7();
            let key = derive_ready_key(
                &target.workspace_id.to_string(),
                &intruder.to_string(),
                &generation.to_string(),
            );
            let body = fixture::synthetic_body("intruder", fixture::ORDINARY_BODY_SIZE);
            let digest: [u8; 32] = Sha256::digest(&body).into();
            kit.put_body(&key, body)?;
            kit.exec(
                "insert a ready artifact row the inventory never carried",
                "INSERT INTO central.artifacts (
                    id, workspace_id, task_id, run_id, state, staging_generation, object_key,
                    sensitivity, disposition, size, media_type,
                    checksum_algorithm, checksum_value, content_generation, ready_key, ready_at
                 ) VALUES (
                    $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'ready', gen_random_uuid(),
                    $5, 'unrestricted', 'attachment', $6, 'application/octet-stream',
                    'sha256', $7, $8::uuid, $5, now()
                 )",
                &[
                    Bind::Uuid(intruder),
                    Bind::Uuid(target.workspace_id),
                    Bind::Uuid(target.task_id),
                    Bind::Uuid(target.run_id),
                    Bind::Text(key.clone()),
                    Bind::I64(fixture::ORDINARY_BODY_SIZE as i64),
                    Bind::Bytes(digest.to_vec()),
                    Bind::Uuid(generation),
                ],
            )?;
            let key_for_repair = key.clone();
            Ok((
                intruder,
                Box::new(move |kit| {
                    kit.exec(
                        "remove the row the inventory never carried",
                        "DELETE FROM central.artifacts WHERE id = $1::uuid",
                        &[Bind::Uuid(intruder)],
                    )?;
                    kit.remove_body(&key_for_repair)
                }),
            ))
        }
        CorruptionCase::RowDeleted => {
            // The row is set aside whole — every column, including the ones
            // this file does not name — and put back from that copy. A
            // repair that re-inserted a row this file composed would restore
            // the columns it thought of and silently change the rest, and
            // the clean control that follows would then be passing over a
            // different row.
            kit.exec(
                "clear any previous set-aside row",
                "DROP TABLE IF EXISTS c06_deleted_artifact",
                &[],
            )?;
            kit.exec(
                "set the artifact row aside before deleting it",
                "CREATE TEMP TABLE c06_deleted_artifact AS SELECT * FROM central.artifacts WHERE id = $1::uuid",
                &[Bind::Uuid(target.id)],
            )?;
            let set_aside = kit.query_scalar_i64(
                "count the set-aside row",
                "SELECT count(*) FROM c06_deleted_artifact",
                &[],
            )?;
            if set_aside != 1 {
                return Err(format!(
                    "setting artifact {} aside copied {set_aside} rows, want exactly 1; the deletion below would be unrecoverable",
                    target.id
                ));
            }
            kit.exec(
                "delete the artifact row",
                "DELETE FROM central.artifacts WHERE id = $1::uuid",
                &[Bind::Uuid(target.id)],
            )?;
            Ok((
                target.id,
                Box::new(move |kit| {
                    kit.exec(
                        "put the deleted artifact row back",
                        "INSERT INTO central.artifacts SELECT * FROM c06_deleted_artifact",
                        &[],
                    )?;
                    kit.exec(
                        "clear the set-aside row",
                        "DROP TABLE c06_deleted_artifact",
                        &[],
                    )
                }),
            ))
        }
    }
}

/// The per-case evidence-shape assertions — what separates "the application
/// said metadata_mismatch" from "the application described THIS corruption":
/// two of the six cases share a reason and are told apart by nothing else.
fn assert_shape(
    case: &CorruptionCase,
    finding: &QuarantineFinding,
    target: &InventoryRow,
) -> Result<(), String> {
    match case {
        CorruptionCase::BodyDeleted | CorruptionCase::RowDeleted => {
            require_expected(finding, target)?;
            require_no_observed_side(
                finding,
                if matches!(case, CorruptionCase::BodyDeleted) {
                    "a body that is not there has no observed size and no observed checksum"
                } else {
                    // THIS is what separates the deleted row from the
                    // altered row: both answer metadata_mismatch; only the
                    // deleted row has nothing on the observed side.
                    "a row that is not there has no observed size and no observed checksum"
                },
            )
        }
        CorruptionCase::ChecksumMismatch => {
            let (Some(expected), Some(observed)) =
                (finding.expected_checksum, finding.observed_checksum)
            else {
                return Err(format!(
                    "the checksum-mismatch finding for {} carries expected={} observed={}; a checksum mismatch that cannot say what it expected or what it saw names no corruption",
                    target.id,
                    finding.expected_checksum.is_some(),
                    finding.observed_checksum.is_some()
                ));
            };
            if expected != target.checksum {
                return Err(format!(
                    "the checksum-mismatch finding for {} expected a checksum this run did not record for it",
                    target.id
                ));
            }
            if expected == observed {
                return Err(format!(
                    "the checksum-mismatch finding for {} reports the same value on both sides, so it is a mismatch of nothing",
                    target.id
                ));
            }
            Ok(())
        }
        CorruptionCase::BodyTruncated => require_sizes(
            finding,
            target,
            target.size,
            target.size - SIZE_MISMATCH_TRUNCATION,
        ),
        CorruptionCase::SizeAltered => require_sizes(
            finding,
            target,
            target.size,
            target.size + METADATA_SIZE_DRIFT,
        ),
        CorruptionCase::UnexpectedArtifact => {
            if finding.expected_checksum.is_some() || finding.expected_size.is_some() {
                return Err(
                    "the unexpected-artifact finding carries an expected side; the inventory carried nothing for this identity, so there is nothing it could have expected"
                        .to_owned(),
                );
            }
            if finding.observed_checksum.is_none() && finding.observed_size.is_none() {
                return Err(
                    "the unexpected-artifact finding carries no observed side at all, so it does not say what it found"
                        .to_owned(),
                );
            }
            if let Some(observed) = finding.observed_size
                && observed != fixture::ORDINARY_BODY_SIZE as i64
            {
                return Err(format!(
                    "the unexpected-artifact finding observed {observed} bytes; this run added a {}-byte row",
                    fixture::ORDINARY_BODY_SIZE
                ));
            }
            Ok(())
        }
    }
}

fn require_expected(finding: &QuarantineFinding, target: &InventoryRow) -> Result<(), String> {
    let (Some(expected_sum), Some(expected_size)) =
        (finding.expected_checksum, finding.expected_size)
    else {
        return Err(format!(
            "the finding for {} carries expected checksum={} size={}; it must say what the inventory held",
            target.id,
            finding.expected_checksum.is_some(),
            finding.expected_size.is_some()
        ));
    };
    if expected_sum != target.checksum || expected_size != target.size {
        return Err(format!(
            "the finding for {} expected {expected_size} bytes at a checksum this run did not record for it (recorded {} bytes)",
            target.id, target.size
        ));
    }
    Ok(())
}

fn require_no_observed_side(finding: &QuarantineFinding, why: &str) -> Result<(), String> {
    if finding.observed_checksum.is_some() || finding.observed_size.is_some() {
        return Err(format!(
            "the finding for {} carries an observed side (checksum={} size={}); {why}, so a finding that reports one is describing a different corruption from the one that was injected",
            finding.artifact_id,
            finding.observed_checksum.is_some(),
            finding.observed_size.is_some()
        ));
    }
    Ok(())
}

fn require_sizes(
    finding: &QuarantineFinding,
    target: &InventoryRow,
    expected: i64,
    observed: i64,
) -> Result<(), String> {
    let (Some(expected_size), Some(observed_size)) = (finding.expected_size, finding.observed_size)
    else {
        return Err(format!(
            "the finding for {} carries expected size={} observed size={}; a size finding that cannot say both is not a comparison",
            target.id,
            finding.expected_size.is_some(),
            finding.observed_size.is_some()
        ));
    };
    if expected_size != expected || observed_size != observed {
        return Err(format!(
            "the finding for {} reports expected {expected_size} observed {observed_size}; this run injected expected {expected} observed {observed}, and a finding with different numbers is describing a different corruption",
            target.id
        ));
    }
    // A size finding that also carried checksums would be reporting a
    // second difference this injection did not make.
    if finding.expected_checksum.is_some() || finding.observed_checksum.is_some() {
        return Err(format!(
            "the size finding for {} also carries a checksum; this injection changed a length and nothing else",
            target.id
        ));
    }
    Ok(())
}

/// `c06ChooseCorruptionTargets` — one distinct artifact per case, the
/// streamed body spent on the checksum case (a corruption only a complete
/// read can see, on the multipart subject).
fn choose_targets(snapshot: &[InventoryRow]) -> Result<Vec<InventoryRow>, String> {
    let streamed_index = snapshot
        .iter()
        .position(|row| row.size >= STREAMED_BODY_FLOOR_BYTES)
        .ok_or_else(|| {
            format!(
                "the instance carries no body at or above the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor, so the checksum-mismatch case would be injected on a body nothing streams"
            )
        })?;
    let ordinary: Vec<InventoryRow> = snapshot
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != streamed_index)
        .map(|(_, row)| row.clone())
        .collect();
    let plan = CorruptionCase::plan();
    let needed = plan.len() - 1;
    if ordinary.len() < needed {
        return Err(format!(
            "the instance carries {} ordinary ready artifacts and this scenario injures {needed} distinct ones; two injections would land on the same artifact and the combined pass would report fewer findings than injections",
            ordinary.len()
        ));
    }
    let mut targets = Vec::with_capacity(plan.len());
    let mut next = 0usize;
    for case in &plan {
        if matches!(case, CorruptionCase::ChecksumMismatch) {
            targets.push(snapshot[streamed_index].clone());
        } else {
            targets.push(ordinary[next].clone());
            next += 1;
        }
    }
    Ok(targets)
}

/// `c06RecordWhichRowsCanBeDeleted` — establishes, against the live schema,
/// where referential integrity bounds the packet's "random rows". One
/// transaction PER attempt — PostgreSQL aborts a transaction on the first
/// failed statement, so a second DELETE inside the same transaction would
/// fail for a reason that has nothing to do with referential integrity.
fn record_which_rows_can_be_deleted(
    kit: &CorruptionKit,
    log: &mut ScenarioLog,
) -> Result<(), String> {
    for relation in ["runs", "tasks"] {
        let relation = relation.to_owned();
        let outcome = kit
            .conn
            .run(|c| {
                use sqlx::Connection as _;
                let relation = relation.clone();
                Box::pin(async move {
                    let mut tx = c.begin().await.map_err(|e| {
                        Failure::internal(
                            "c06",
                            format!(
                                "open the transaction the central.{relation} deletion probe is made in: {e}"
                            ),
                        )
                    })?;
                    let outcome =
                        sqlx::query(&format!("DELETE FROM central.{relation}"))
                            .execute(&mut *tx)
                            .await;
                    let _ = tx.rollback().await;
                    match outcome {
                        Ok(_) => Ok("succeeded".to_owned()),
                        Err(e) => Ok(format!("{e}")),
                    }
                })
            })
            .map_err(|e| e.to_string())?;
        if outcome == "succeeded" {
            return Err(format!(
                "DELETE FROM central.{relation} succeeded while ready artifacts reference it; the referential integrity this scenario relies on to bound its injection is not there, and the row deletion it does inject is therefore not the whole of what the packet asks for"
            ));
        }
        if !outcome.contains("foreign key constraint") {
            return Err(format!(
                "DELETE FROM central.{relation} failed for something other than referential integrity ({outcome}); this step cannot say what bounds the packet's row deletion"
            ));
        }
        log.recordf(format_args!(
            "row deletion bound: DELETE FROM central.{relation} is refused by a foreign key constraint while ready artifacts reference it, so this scenario's row deletion is injected on the artifact row itself"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The state fingerprints — the SAME capture at both ends, plus the corrupted
// instance's artifact arm that tolerates what it is describing.
// ---------------------------------------------------------------------------

/// `c06TableSchemaDigestSQL` — one relation's schema-object digest (columns,
/// constraints, indexes, triggers, policies, relation flags, owner, ACLs).
const TABLE_SCHEMA_DIGEST_SQL: &str = r#"SELECT encode(sha256(convert_to(coalesce(string_agg(item, E'\n' ORDER BY item COLLATE "C"), ''), 'UTF8')), 'hex')
	FROM (
		SELECT 'column' || E'\t' || a.attname
			|| E'\t' || format_type(a.atttypid, a.atttypmod)
			|| E'\t' || (NOT a.attnotnull)::text
			|| E'\t' || coalesce(pg_get_expr(d.adbin, d.adrelid), '')
			|| E'\t' || a.attidentity::text
			|| E'\t' || a.attgenerated::text
			|| E'\t' || coalesce(col.collname, '')
			|| E'\t' || coalesce(array_to_string(ARRAY(SELECT entry::text FROM unnest(a.attacl) AS entry ORDER BY entry::text COLLATE "C"), ','), '')
			|| E'\t' || (row_number() OVER (ORDER BY a.attnum))::text AS item
		  FROM pg_attribute a
		  LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		  LEFT JOIN pg_collation col ON col.oid = a.attcollation
		 WHERE a.attrelid = $1::regclass AND a.attnum > 0 AND NOT a.attisdropped
		UNION ALL
		SELECT 'constraint' || E'\t' || c.conname || E'\t' || c.contype::text
			|| E'\t' || pg_get_constraintdef(c.oid)
		  FROM pg_constraint c WHERE c.conrelid = $1::regclass
		UNION ALL
		SELECT 'index' || E'\t' || i.indexname || E'\t' || i.indexdef
		  FROM pg_indexes i WHERE i.schemaname = $2 AND i.tablename = $3
		UNION ALL
		SELECT 'trigger' || E'\t' || tg.tgname || E'\t' || pg_get_triggerdef(tg.oid)
		  FROM pg_trigger tg WHERE tg.tgrelid = $1::regclass AND NOT tg.tgisinternal
		UNION ALL
		SELECT 'policy' || E'\t' || p.policyname || E'\t' || p.permissive
			|| E'\t' || coalesce(array_to_string(p.roles, ','), '')
			|| E'\t' || p.cmd || E'\t' || coalesce(p.qual, '') || E'\t' || coalesce(p.with_check, '')
		  FROM pg_policies p WHERE p.schemaname = $2 AND p.tablename = $3
		UNION ALL
		SELECT 'relation' || E'\t' || rel.relkind::text || E'\t' || rel.relpersistence::text
			|| E'\t' || rel.relreplident::text || E'\t' || rel.relrowsecurity::text
			|| E'\t' || rel.relforcerowsecurity::text
			|| E'\t' || coalesce(array_to_string(rel.reloptions, ','), '')
			|| E'\t' || rel.relowner::regrole::text
			|| E'\t' || coalesce(array_to_string(ARRAY(SELECT entry::text FROM unnest(rel.relacl) AS entry ORDER BY entry::text COLLATE "C"), ','), '')
		  FROM pg_class rel WHERE rel.oid = $1::regclass
	) AS schema_items"#;

/// `c06SchemaObjectDigestSQL` — every non-relation object in the schema:
/// functions/procedures/enums/domains/composites digested; every other kind
/// returned with an empty definition so the coverage refusal can name it.
const SCHEMA_OBJECT_DIGEST_SQL: &str = r#"SELECT kind, name, encode(sha256(convert_to(definition, 'UTF8')), 'hex')
	FROM (
		SELECT CASE p.prokind WHEN 'f' THEN 'function' ELSE 'procedure' END AS kind,
			p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS name,
			pg_get_functiondef(p.oid)
				|| E'\t' || p.proowner::regrole::text
				|| E'\t' || coalesce(array_to_string(ARRAY(SELECT entry::text FROM unnest(p.proacl) AS entry ORDER BY entry::text COLLATE "C"), ','), '') AS definition
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = $1 AND p.prokind IN ('f', 'p')
		UNION ALL
		SELECT CASE p.prokind WHEN 'a' THEN 'aggregate' WHEN 'w' THEN 'window function'
				ELSE 'routine of prokind ' || p.prokind::text END,
			p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', ''
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = $1 AND p.prokind NOT IN ('f', 'p')
		UNION ALL
		SELECT CASE t.typtype WHEN 'e' THEN 'enum type' WHEN 'd' THEN 'domain' ELSE 'composite type' END,
			t.typname::text,
			t.typtype::text
				|| E'\t' || coalesce(format_type(t.typbasetype, t.typtypmod), '')
				|| E'\t' || t.typnotnull::text
				|| E'\t' || coalesce(t.typdefault, '')
				|| E'\t' || t.typowner::regrole::text
				|| E'\t' || coalesce(array_to_string(ARRAY(SELECT entry::text FROM unnest(t.typacl) AS entry ORDER BY entry::text COLLATE "C"), ','), '')
				|| E'\t' || coalesce((SELECT string_agg(e.enumsortorder::text || ':' || e.enumlabel, ',' ORDER BY e.enumsortorder)
					FROM pg_enum e WHERE e.enumtypid = t.oid), '')
				|| E'\t' || coalesce((SELECT string_agg(pg_get_constraintdef(dc.oid), E'\n' ORDER BY pg_get_constraintdef(dc.oid) COLLATE "C")
					FROM pg_constraint dc WHERE dc.contypid = t.oid), '')
				|| E'\t' || coalesce((SELECT string_agg(a.attname || ' ' || format_type(a.atttypid, a.atttypmod), E'\n' ORDER BY a.attname COLLATE "C")
					FROM pg_attribute a WHERE a.attrelid = t.typrelid AND a.attnum > 0 AND NOT a.attisdropped), '')
		  FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		 WHERE n.nspname = $1 AND t.typtype IN ('e', 'd', 'c')
		   AND (t.typrelid = 0 OR (SELECT c.relkind FROM pg_class c WHERE c.oid = t.typrelid) = 'c')
		   AND NOT EXISTS (SELECT 1 FROM pg_type el WHERE el.oid = t.typelem AND el.typarray = t.oid)
		UNION ALL
		SELECT CASE t.typtype WHEN 'b' THEN 'base type' WHEN 'r' THEN 'range type'
				WHEN 'm' THEN 'multirange type' WHEN 'p' THEN 'pseudo type'
				ELSE 'type of typtype ' || t.typtype::text END,
			t.typname::text, ''
		  FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		 WHERE n.nspname = $1 AND t.typtype NOT IN ('e', 'd', 'c')
		   AND NOT EXISTS (SELECT 1 FROM pg_type el WHERE el.oid = t.typelem AND el.typarray = t.oid)
		UNION ALL
		SELECT 'operator', o.oprname::text, ''
		  FROM pg_operator o JOIN pg_namespace n ON n.oid = o.oprnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'operator class', opc.opcname::text, ''
		  FROM pg_opclass opc JOIN pg_namespace n ON n.oid = opc.opcnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'operator family', opf.opfname::text, ''
		  FROM pg_opfamily opf JOIN pg_namespace n ON n.oid = opf.opfnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'collation', co.collname::text, ''
		  FROM pg_collation co JOIN pg_namespace n ON n.oid = co.collnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'conversion', cv.conname::text, ''
		  FROM pg_conversion cv JOIN pg_namespace n ON n.oid = cv.connamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'extended statistics', stx.stxname::text, ''
		  FROM pg_statistic_ext stx JOIN pg_namespace n ON n.oid = stx.stxnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'text search configuration', tsc.cfgname::text, ''
		  FROM pg_ts_config tsc JOIN pg_namespace n ON n.oid = tsc.cfgnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'text search dictionary', tsd.dictname::text, ''
		  FROM pg_ts_dict tsd JOIN pg_namespace n ON n.oid = tsd.dictnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'text search parser', tsp.prsname::text, ''
		  FROM pg_ts_parser tsp JOIN pg_namespace n ON n.oid = tsp.prsnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'text search template', tst.tmplname::text, ''
		  FROM pg_ts_template tst JOIN pg_namespace n ON n.oid = tst.tmplnamespace WHERE n.nspname = $1
		UNION ALL
		SELECT 'extension', ext.extname::text, ''
		  FROM pg_extension ext JOIN pg_namespace n ON n.oid = ext.extnamespace WHERE n.nspname = $1
	) AS schema_objects
	ORDER BY kind, name"#;

pub(crate) fn pin_fingerprint_session(conn: &BlockingConn) -> Result<(), String> {
    conn.run(|c| {
        Box::pin(async move {
            for statement in [
                "SET TimeZone = 'UTC'",
                "SET DateStyle = 'ISO, MDY'",
                "SET IntervalStyle = 'postgres'",
                "SET bytea_output = 'hex'",
                "SET extra_float_digits = 3",
            ] {
                sqlx::query(statement).execute(&mut *c).await.map_err(|e| {
                    Failure::internal(
                        "c06",
                        format!(
                            "pin the session settings the fingerprint's renderings depend on: {e}"
                        ),
                    )
                })?;
            }
            Ok(())
        })
    })
    .map_err(|e| e.to_string())
}

pub(crate) fn fingerprint_tables(conn: &BlockingConn) -> Result<Vec<TableFingerprint>, String> {
    let relations: Vec<(String, String)> = conn
        .run(|c| {
            Box::pin(async move {
                let rows: Vec<(String, String)> = sqlx::query_as(
                    "SELECT c.relname, c.relkind::text
                     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE n.nspname = 'central' ORDER BY c.relname",
                )
                .fetch_all(&mut *c)
                .await
                .map_err(|e| {
                    Failure::internal("c06", format!("list the application's relations: {e}"))
                })?;
                Ok(rows)
            })
        })
        .map_err(|e| e.to_string())?;
    let schema_relations: Vec<SchemaRelation> = relations
        .iter()
        .map(|(name, kind)| SchemaRelation {
            name: format!("central.{name}"),
            kind: kind.clone(),
        })
        .collect();
    refuse_uncovered_relation_kinds(&schema_relations)?;
    let names: Vec<String> = relations
        .iter()
        .filter(|(_, kind)| kind == "r" || kind == "p")
        .map(|(name, _)| name.clone())
        .collect();
    if names.is_empty() {
        return Err(
            "the application's schema holds no base table; the migration this run performed installed nothing, and a fingerprint over no table would compare equal to an empty instance"
                .to_owned(),
        );
    }
    let mut fingerprints = Vec::with_capacity(names.len());
    for name in names {
        let relation = format!("central.\"{name}\"");
        let (row_count, content_sha256): (i64, String) = conn
            .run(|c| {
                let relation = relation.clone();
                Box::pin(async move {
                    let row: (i64, String) = sqlx::query_as(&format!(
                        "SELECT count(*)::bigint,
                            encode(sha256(convert_to(coalesce(string_agg(rendered, E'\\n' ORDER BY rendered COLLATE \"C\"), ''), 'UTF8')), 'hex')
                            FROM (SELECT source::text AS rendered FROM {relation} AS source) AS rendered_rows"
                    ))
                    .fetch_one(&mut *c)
                    .await
                    .map_err(|e| {
                        Failure::internal("c06", format!("fingerprint {relation}: {e}"))
                    })?;
                    Ok(row)
                })
            })
            .map_err(|e| e.to_string())?;
        let schema_sha256: String = conn
            .run(|c| {
                let (relation, name) = (relation.clone(), name.clone());
                Box::pin(async move {
                    let digest: String = sqlx::query_scalar(TABLE_SCHEMA_DIGEST_SQL)
                        .bind(&relation)
                        .bind("central")
                        .bind(&name)
                        .fetch_one(&mut *c)
                        .await
                        .map_err(|e| {
                            Failure::internal(
                                "c06",
                                format!("fingerprint the schema objects of {relation}: {e}"),
                            )
                        })?;
                    Ok(digest)
                })
            })
            .map_err(|e| e.to_string())?;
        fingerprints.push(TableFingerprint {
            name: format!("central.{name}"),
            row_count,
            content_sha256,
            schema_sha256,
        });
    }
    Ok(fingerprints)
}

fn fingerprint_schema_objects(conn: &BlockingConn) -> Result<Vec<SchemaObjectFingerprint>, String> {
    conn.run(|c| {
        Box::pin(async move {
            let rows: Vec<(String, String, String)> = sqlx::query_as(SCHEMA_OBJECT_DIGEST_SQL)
                .bind("central")
                .fetch_all(&mut *c)
                .await
                .map_err(|e| {
                    Failure::internal(
                        "c06",
                        format!("list the application's non-relation schema objects: {e}"),
                    )
                })?;
            let mut objects = Vec::with_capacity(rows.len());
            let mut fingerprints = Vec::with_capacity(rows.len());
            for (kind, name, digest) in rows {
                let qualified = format!("central.{name}");
                objects.push(SchemaObject {
                    name: qualified.clone(),
                    kind: kind.clone(),
                });
                fingerprints.push(SchemaObjectFingerprint {
                    name: qualified,
                    kind,
                    definition_sha256: digest,
                });
            }
            refuse_uncovered_schema_object_kinds(&objects)
                .map_err(|e| Failure::internal("c06", e))?;
            Ok(fingerprints)
        })
    })
    .map_err(|e| e.to_string())
}

/// `c06ArtifactMetadata` — the exact field set, in the exact order, BOTH
/// captures digest into `ArtifactFingerprint.metadata_sha256`. One type
/// rather than two copies of a join, so the two captures cannot drift apart.
struct ArtifactMetadata<'a> {
    id: &'a str,
    size: i64,
    checksum: &'a str,
    generation: &'a str,
    ready_key: &'a str,
    state: &'a str,
    media_type: &'a str,
    sensitivity: &'a str,
    disposition: &'a str,
}

impl ArtifactMetadata<'_> {
    fn digest(&self) -> String {
        let joined = [
            self.id.to_owned(),
            self.size.to_string(),
            self.checksum.to_owned(),
            self.generation.to_owned(),
            self.ready_key.to_owned(),
            self.state.to_owned(),
            self.media_type.to_owned(),
            self.sensitivity.to_owned(),
            self.disposition.to_owned(),
        ]
        .join("\x1f");
        crate::hex_lower(Sha256::digest(joined.as_bytes()))
    }
}

pub(crate) struct ArtifactRow {
    pub(crate) id: String,
    pub(crate) size: i64,
    pub(crate) checksum: String,
    pub(crate) generation: String,
    pub(crate) ready_key: String,
    pub(crate) state: String,
    pub(crate) media_type: String,
    pub(crate) sensitivity: String,
    pub(crate) disposition: String,
}

pub(crate) fn ready_artifact_rows(conn: &BlockingConn) -> Result<Vec<ArtifactRow>, String> {
    conn.run(|c| {
        Box::pin(async move {
            let rows: Vec<ArtifactRowTuple> = sqlx::query_as(
                "SELECT id, size, checksum_value, content_generation,
                        ready_key, state, coalesce(media_type,''), sensitivity, disposition
                     FROM central.artifacts
                     WHERE state = 'ready' AND delete_intent_at IS NULL
                     ORDER BY id ASC",
            )
            .fetch_all(&mut *c)
            .await
            .map_err(|e| {
                Failure::internal("c06", format!("read the artifacts to fingerprint: {e}"))
            })?;
            Ok(rows
                .into_iter()
                .map(
                    |(
                        id,
                        size,
                        checksum,
                        generation,
                        ready_key,
                        state,
                        media_type,
                        sensitivity,
                        disposition,
                    )| ArtifactRow {
                        id: id.to_string(),
                        size,
                        checksum: crate::hex_lower(checksum),
                        generation: generation.to_string(),
                        ready_key,
                        state,
                        media_type,
                        sensitivity,
                        disposition,
                    },
                )
                .collect::<Vec<_>>())
        })
    })
    .map_err(|e| e.to_string())
}

/// `c06FingerprintArtifacts` — every ready artifact: metadata digest plus
/// the body read back whole through the object store (never the recorded
/// checksum).
fn fingerprint_artifacts(
    conn: &BlockingConn,
    objects: &S3BackupObjectSource,
) -> Result<Vec<ArtifactFingerprint>, String> {
    let records = ready_artifact_rows(conn)?;
    let mut fingerprints = Vec::with_capacity(records.len());
    for record in &records {
        let (mut body, _info) = objects
            .read_ready_object(&ObjectRef {
                key: record.ready_key.clone(),
            })
            .map_err(|e| format!("open the body of artifact {}: {e}", record.id))?;
        let (size, digest) = digest_stream(&mut body)
            .map_err(|e| format!("stream the body of artifact {}: {e}", record.id))?;
        body.close()
            .map_err(|e| format!("close the body of artifact {}: {e}", record.id))?;
        // The recorded size and the size actually returned must agree:
        // they are two different facts — one is metadata, one is the
        // store's answer.
        if size as i64 != record.size {
            return Err(format!(
                "artifact {} records {} bytes and the object store returned {size}; the corpus is inconsistent before anything has corrupted it",
                record.id, record.size
            ));
        }
        fingerprints.push(ArtifactFingerprint {
            id: record.id.clone(),
            size_bytes: record.size,
            body_sha256: crate::hex_lower(digest),
            streamed: record.size >= STREAMED_BODY_FLOOR_BYTES,
            metadata_sha256: ArtifactMetadata {
                id: &record.id,
                size: record.size,
                checksum: &record.checksum,
                generation: &record.generation,
                ready_key: &record.ready_key,
                state: &record.state,
                media_type: &record.media_type,
                sensitivity: &record.sensitivity,
                disposition: &record.disposition,
            }
            .digest(),
        });
    }
    Ok(fingerprints)
}

/// `c06FingerprintArtifactsAsTheStoreAnswers` — the corrupted-instance arm:
/// a body the store cannot return is OMITTED and counted, never replaced by
/// a placeholder (a zero-length body has the same digest whatever the store
/// returns, so it would be a fingerprint of nothing wearing an identity).
pub(crate) fn fingerprint_artifacts_as_the_store_answers(
    conn: &BlockingConn,
    objects: &S3BackupObjectSource,
    occasion: &str,
    log: &mut ScenarioLog,
) -> Result<Vec<ArtifactFingerprint>, String> {
    let records = ready_artifact_rows(conn)?;
    let mut fingerprints = Vec::with_capacity(records.len());
    let mut unreadable = 0usize;
    for record in &records {
        let (mut body, _info) = match objects.read_ready_object(&ObjectRef {
            key: record.ready_key.clone(),
        }) {
            Ok(opened) => opened,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let (size, digest) = match digest_stream(&mut body) {
            Ok(done) => done,
            Err(_) => {
                unreadable += 1;
                let _ = body.close();
                continue;
            }
        };
        let _ = body.close();
        fingerprints.push(ArtifactFingerprint {
            id: record.id.clone(),
            size_bytes: size as i64,
            body_sha256: crate::hex_lower(digest),
            streamed: (size as i64) >= STREAMED_BODY_FLOOR_BYTES,
            metadata_sha256: ArtifactMetadata {
                id: &record.id,
                size: record.size,
                checksum: &record.checksum,
                generation: &record.generation,
                ready_key: &record.ready_key,
                state: &record.state,
                media_type: &record.media_type,
                sensitivity: &record.sensitivity,
                disposition: &record.disposition,
            }
            .digest(),
        });
    }
    log.recordf(format_args!(
        "corrupted-instance artifact capture {occasion}: {} bodies read, {unreadable} omitted as unreadable",
        fingerprints.len()
    ));
    Ok(fingerprints)
}

/// `c06CaptureStateFingerprint` — the pre-corruption capture: every table,
/// every artifact body, every schema object.
pub(crate) fn capture_state_fingerprint(
    conn: &BlockingConn,
    objects: &S3BackupObjectSource,
) -> Result<StateFingerprint, String> {
    pin_fingerprint_session(conn)?;
    Ok(StateFingerprint {
        tables: fingerprint_tables(conn)?,
        artifacts: fingerprint_artifacts(conn, objects)?,
        schema_objects: fingerprint_schema_objects(conn)?,
    })
}

/// `c06CaptureStateFingerprintOfACorruptedInstance` — the second capture,
/// tolerating exactly the damage the first refuses.
fn capture_fingerprint_of_corrupted_instance(
    conn: &BlockingConn,
    objects: &S3BackupObjectSource,
    occasion: &str,
    log: &mut ScenarioLog,
) -> Result<StateFingerprint, String> {
    pin_fingerprint_session(conn)?;
    Ok(StateFingerprint {
        tables: fingerprint_tables(conn)?,
        artifacts: fingerprint_artifacts_as_the_store_answers(conn, objects, occasion, log)?,
        schema_objects: fingerprint_schema_objects(conn)?,
    })
}

// ---------------------------------------------------------------------------
// The scenario entry.
// ---------------------------------------------------------------------------

/// `c06.s2.corruption_detected` — inject database row deletion and each
/// object-corruption shape; the application detects the inconsistency
/// through its own path.
pub(crate) fn c06_s2_corruption_detected() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s2.corruption_detected";
    crate::slice_c::scenario(
        id,
        |profile| crate::slice_c::unmet_precondition(id, profile).or_else(missing_live_env),
        |_s| {
            let mut log = ScenarioLog::new(id);
            // THE DISCLOSURE GOES INTO THE LOG FIRST — a passing run emits
            // no divergence by design, so the transcript head is the
            // strongest place the ratified shape gives this text (upstream's
            // own reasoning, kept).
            log.recordf(format_args!("{SCENARIO2_SCOPE_DISCLOSURE}"));
            crate::continuous_run::gate_the_sequence("c06.s1.backup_create", &mut log)?;

            expect(
                id,
                "the live instance carries a ready inventory big enough to injure in six distinct places, one of them a streamed body",
            );
            let dsn = require_env(fixture::PG_DSN_ENV)
                .expect("the environment gate passed before this body ran");
            let s3 = s3_config()?;
            let conn = Arc::new(connect_pg(&dsn)?);
            let runtime = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .map_err(|e| format!("build the object-store runtime: {e}"))?,
            );
            // Seeding is idempotent and sits OUTSIDE the recorded checks —
            // the position upstream's standalone entry point occupied.
            if read_inventory_snapshot(&conn)?.is_empty() {
                let seed_store = S3ObjectStore::new(s3.clone())
                    .map_err(|e| format!("compose the seeding object store: {e}"))?;
                seed_corpus(&conn, &seed_store, &runtime)?;
            }

            // --- 1. The instance as it stands, before anything touches it.
            let snapshot = read_inventory_snapshot(&conn)?;
            let targets = choose_targets(&snapshot)?;
            let expected = expected_inventory(&snapshot);
            let streamed = snapshot
                .iter()
                .filter(|r| r.size >= STREAMED_BODY_FLOOR_BYTES)
                .count();
            log.recordf(format_args!(
                "pre-corruption inventory: {} ready artifacts, {streamed} of them at or above the {STREAMED_BODY_FLOOR_BYTES}-byte multipart floor",
                snapshot.len()
            ));

            // Two S3ObjectStore instances on distinct connections: the
            // detector reads through the production reader bridge the
            // kernel composes; the injection store is a second client —
            // nothing the injector wrote is the detector's own write.
            let detection_store = Arc::new(
                S3ObjectStore::new(s3.clone())
                    .map_err(|e| format!("compose the detection object store: {e}"))?,
            );
            let detection_objects =
                S3BackupObjectSource::new(detection_store.clone(), runtime.handle().clone())
                    .map_err(|e| format!("compose the detection object reader: {e}"))?;
            let injection_store = Arc::new(
                S3ObjectStore::new(s3.clone())
                    .map_err(|e| format!("compose the injection object store: {e}"))?,
            );
            let kit = CorruptionKit {
                conn: conn.clone(),
                store: injection_store,
                runtime: runtime.clone(),
            };

            // The instance as this scenario found it, by the SAME capture —
            // this scenario's own control for the last step (upstream's
            // "beforeAnything" capture, recorded nowhere).
            let before_anything = capture_fingerprint_of_corrupted_instance(
                &conn,
                &detection_objects,
                "the instance before this scenario injected anything",
                &mut log,
            )?;
            if let Err(e) = before_anything.validate() {
                return Err(format!(
                    "the instance this scenario was handed cannot be fingerprinted well enough to be compared against later ({e}); every difference the last step reports would then be a fact about the capture rather than about the corruption"
                ));
            }
            // Upstream's `beforeAnything` is this scenario's own control and
            // is never recorded; the baseline scenario 7 compares against is
            // scenario 1's capture. THIS PORT records this capture as that
            // baseline instead: scenario 1 here dispatches the operator
            // command only and takes no fingerprint, and under this port's
            // unordered armed schedule there is no earlier point the
            // baseline could be taken at — the idempotent seed above and
            // this capture precede every injection by construction order
            // inside this body, so the state recorded is the state before
            // the corruption, which is what the baseline names.
            fixture::records().record_pre_corruption(before_anything.clone())?;

            // The detector: the production restored-inventory verifier over
            // a REAL connection and the real object-store adapter, against
            // the pre-corruption stand-in.
            let reader: Arc<dyn ReadyArtifactObjectReader> = Arc::new(ReaderBridge {
                source: S3BackupObjectSource::new(
                    detection_store.clone(),
                    runtime.handle().clone(),
                )
                .map_err(|e| format!("compose the verifier object reader: {e}"))?,
            });
            let inventory: Arc<dyn RecoveryInventorySource> =
                Arc::new(PreCorruptionInventory { entries: expected });
            let detection_dsn = dsn.clone();
            let verifier = RestoredInventoryVerifier::new_connecting(
                move || async move {
                    <sqlx::PgConnection as sqlx::Connection>::connect(&detection_dsn)
                        .await
                        .map_err(|e| {
                            Failure::internal("c06", format!("connect the detection database: {e}"))
                        })
                },
                inventory,
                reader,
                central_backup::backup::capacity::default_recovery_profile(),
            )
            .map_err(|e| format!("compose the production restored-inventory verifier: {e}"))?;
            let detector = Detector {
                verifier,
                operation: inventory_verification_operation()?,
            };

            // --- 2. The clean control, before any injection.
            //
            // This is the assertion that makes every one below it mean
            // something: "the application detected an inconsistency" is
            // worth nothing if it would have said the same about an
            // untouched instance.
            expect(
                id,
                "the application's own inventory verification reports NO finding over the untouched instance, so every finding below is attributable to an injection and not to the instance",
            );
            detector.detect_clean("the untouched instance")?;
            log.recordf(format_args!(
                "clean control: the application reported no finding over {} artifacts before any corruption was injected",
                snapshot.len()
            ));

            // --- 3. The packet's row deletion, at the edge the schema draws.
            expect(
                id,
                "the schema's referential integrity is what bounds which rows can be deleted, and this run records where that bound is rather than assuming the packet's \"random rows\" reaches everywhere",
            );
            record_which_rows_can_be_deleted(&kit, &mut log)?;

            // --- 4. Each corruption class, injected alone and repaired.
            //
            // One at a time, each with the clean control re-established
            // after it. A combined injection alone could not tell which
            // damage produced which finding.
            let plan = CorruptionCase::plan();
            for (index, case) in plan.iter().enumerate() {
                let target = &targets[index];
                expect(
                    id,
                    format!(
                        "injecting {} (on the {}) makes the application report exactly one finding, on that artifact, with reason {} and the evidence that reason carries",
                        case.name(),
                        case.surface(),
                        case.reason().as_str()
                    ),
                );
                let (named, repair) = inject(case, &kit, target)?;
                let findings = detector.detect(&format!("the instance with {}", case.name()))?;
                if findings.len() != 1 {
                    return Err(format!(
                        "injecting {} produced {} findings, want exactly 1: {}. More than one means the injection damaged something else as well and this case cannot say which finding is its own; none means the application did not detect it at all",
                        case.name(),
                        findings.len(),
                        describe_findings(&findings)
                    ));
                }
                let finding = &findings[0];
                if finding.artifact_id != named {
                    return Err(format!(
                        "injecting {} produced a finding against artifact {}; the corruption was injected on {named}, so the application detected something other than what this case injected",
                        case.name(),
                        finding.artifact_id
                    ));
                }
                if finding.reason != case.reason() {
                    return Err(format!(
                        "injecting {} made the application answer {}, want {}; a detection that names the wrong corruption is a detection nobody can act on",
                        case.name(),
                        finding.reason.as_str(),
                        case.reason().as_str()
                    ));
                }
                if let Err(e) = finding.validate_for(&detector.operation) {
                    return Err(format!(
                        "the finding for {} does not validate against the operation it was stamped with: {e}",
                        case.name()
                    ));
                }
                assert_shape(case, finding, target)?;
                log.recordf(format_args!(
                    "injection {}/{} on the {}: {} -> the application answered {} against the injected artifact, carrying the evidence that reason requires",
                    index + 1,
                    plan.len(),
                    case.surface(),
                    case.name(),
                    finding.reason.as_str()
                ));

                repair(&kit)?;
                // The control in the other direction: the finding goes
                // away when the damage does.
                expect(
                    id,
                    format!(
                        "repairing {} makes the finding go away, so the finding was attributable to that damage and not to a standing property of the instance",
                        case.name()
                    ),
                );
                detector
                    .detect_clean(&format!("the instance after {} was repaired", case.name()))?;
                log.recordf(format_args!(
                    "injection {}/{} repaired: the application reported no finding again",
                    index + 1,
                    plan.len()
                ));
            }

            // --- 5. All six at once, and left in place.
            //
            // THE REPAIR CLOSURE IS DELIBERATELY DISCARDED HERE, AND ONLY
            // HERE. Step 4 calls every repair it takes; this step is the
            // opposite act: the corrupted instance IS this scenario's
            // product. Scenario 5 restores it and scenario 7 asks whether
            // the restore put it back.
            expect(
                id,
                format!(
                    "with all {} injections in place the application reports exactly {} findings covering every one of the {} quarantine reasons the domain enumerates",
                    plan.len(),
                    plan.len(),
                    quarantine_reasons().len()
                ),
            );
            let mut injured: std::collections::HashMap<Uuid, &'static str> =
                std::collections::HashMap::new();
            for (index, case) in plan.iter().enumerate() {
                let (named, _repair) = inject(case, &kit, &targets[index])?;
                if let Some(previous) = injured.insert(named, case.name()) {
                    return Err(format!(
                        "two injections landed on artifact {named} ({previous} and {}); the combined pass would then report fewer findings than injections and the shortfall would look like a detection failure",
                        case.name()
                    ));
                }
            }
            let findings = detector.detect("the instance with every injection in place")?;
            if findings.len() != plan.len() {
                return Err(format!(
                    "the application reported {} findings over {} injections: {}",
                    findings.len(),
                    plan.len(),
                    describe_findings(&findings)
                ));
            }
            for finding in &findings {
                if !injured.contains_key(&finding.artifact_id) {
                    return Err(format!(
                        "the application reported a finding against artifact {}, which this scenario did not injure; the instance carries an inconsistency this run did not inject",
                        finding.artifact_id
                    ));
                }
                // Asserted here as well as per-injection, because these
                // are the findings scenario 5's census is resolved from.
                if let Err(e) = finding.validate_for(&detector.operation) {
                    return Err(format!(
                        "the combined pass produced a finding against {} that does not validate against the operation it was stamped with: {e}",
                        finding.artifact_id
                    ));
                }
            }
            let mut census = [0usize; 5];
            for finding in &findings {
                census[reason_index(finding.reason)] += 1;
            }
            for reason in quarantine_reasons() {
                if census[reason_index(reason)] == 0 {
                    return Err(format!(
                        "the combined injection produced no {} finding; scenario 5's quarantine census needs one of each of the {} reasons to resolve",
                        reason.as_str(),
                        quarantine_reasons().len()
                    ));
                }
            }
            log.recordf(format_args!(
                "combined injection: {} findings, census {}",
                findings.len(),
                quarantine_reasons()
                    .iter()
                    .map(|r| format!("{}={}", r.as_str(), census[reason_index(*r)]))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));

            // --- 6. The post-corruption fingerprint.
            expect(
                id,
                "the corrupted instance fingerprints to a state that differs from the instance this scenario started from, and that difference is what scenario 7 must show the restore undoing",
            );
            let post = capture_fingerprint_of_corrupted_instance(
                &conn,
                &detection_objects,
                "the corrupted instance",
                &mut log,
            )?;
            // The control in both directions, asserted BEFORE the record.
            if before_anything.equal(&post) {
                return Err(format!(
                    "the corrupted instance fingerprints identically ({}) to the instance this scenario was handed; {} injections changed nothing the fingerprint covers, so scenario 7 could not tell a restored instance from a corrupted one",
                    post.digest(),
                    plan.len()
                ));
            }
            {
                let mut records = fixture::records();
                records.record_corrupted(post.clone())?;
                if let Some(pre) = records.pre_corruption.as_ref()
                    && pre.equal(&post)
                {
                    return Err(
                        "the corrupted instance fingerprints identically to the pre-corruption capture, which is the state scenario 7 must show the restore returning to"
                            .to_owned(),
                    );
                }
            }
            log.recordf(format_args!(
                "post-corruption fingerprint: {} tables, {} rows, {} readable artifact bodies, {} streamed, digest {}",
                post.tables.len(),
                post.total_rows(),
                post.artifacts.len(),
                post.streamed_bodies(),
                post.digest()
            ));
            Ok(())
        },
    );
}

/// The `ReadyArtifactObjectReader` impl the verifier needs — delegates to
/// the `S3BackupObjectSource` seam the kernel composes, exactly as
/// `RestoreObjectReader` does in `restore_compose.rs`.
struct ReaderBridge {
    source: S3BackupObjectSource,
}

impl ReadyArtifactObjectReader for ReaderBridge {
    fn read(&self, reference: &ObjectRef) -> Result<(Box<dyn ReadClose>, ObjectInfo), Failure> {
        self.source.read_ready_object(reference)
    }
}

// ---------------------------------------------------------------------------
// Portable guards — the plan's completeness against the domain, checked by
// reading the domain's own enumeration.
// ---------------------------------------------------------------------------

#[test]
fn the_corruption_plan_covers_every_quarantine_reason_and_injures_both_surfaces() {
    let plan = CorruptionCase::plan();
    let mut covered = [false; 5];
    let mut surfaces = std::collections::HashMap::new();
    for case in &plan {
        assert!(!case.name().is_empty());
        covered[reason_index(case.reason())] = true;
        *surfaces.entry(case.surface()).or_insert(0usize) += 1;
    }
    for reason in quarantine_reasons() {
        assert!(
            covered[reason_index(reason)],
            "no corruption case produces {}; scenario 5's quarantine census can never carry one",
            reason.as_str()
        );
    }
    for surface in [CORRUPTION_SURFACE_OBJECTS, CORRUPTION_SURFACE_DATABASE] {
        assert!(
            surfaces.get(surface).copied().unwrap_or(0) > 0,
            "no corruption case injures the {surface}; SC-G3 requires intentional database AND object corruption"
        );
    }
    assert_eq!(
        surfaces.values().sum::<usize>(),
        plan.len(),
        "a corruption case names a surface outside the two SC-G3 requires"
    );
    let deletions = plan
        .iter()
        .filter(|c| c.name().contains("row was deleted"))
        .count();
    assert_eq!(
        deletions, 1,
        "the packet's own row deletion must appear in the plan exactly once"
    );
}

/// `TestC06TheSeededReadyKeyIsTheKeyTheProductionReaderDerives` — the
/// suite composes the ready key in exactly one place, and that place must
/// produce keys the adapter's own `READY_PREFIX`/`STAGING_PREFIX`
/// constants admit. The constants are private, so the pin reads them out
/// of the adapter source; a prefix that drifted would make every seeded
/// object unreachable by the very reads the scenario performs.
#[test]
fn the_seeded_ready_key_is_the_key_the_production_reader_derives() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let store_path = std::path::Path::new(manifest)
        .join("../../crates/adapters/central-adapter-s3/src/store.rs");
    let source = std::fs::read_to_string(&store_path)
        .unwrap_or_else(|e| panic!("read the adapter store {}: {e}", store_path.display()));
    let declared = |name: &str| -> String {
        let needle = format!("{name}: &str = \"");
        let at = source
            .find(&needle)
            .unwrap_or_else(|| panic!("{name} is not declared in the adapter source; this pin would hold the key shape to nothing"));
        source[at + needle.len()..]
            .split('"')
            .next()
            .expect("a quoted prefix")
            .to_owned()
    };
    let ready = declared("READY_PREFIX");
    let staging = declared("STAGING_PREFIX");
    let ready_key = derive_ready_key("w", "a", "0");
    let staging_key = derive_staging_key("w", "a", "0");
    assert!(
        ready_key.starts_with(&ready),
        "the suite composes {ready_key:?} and the adapter's READY_PREFIX is {ready:?}; the seeded corpus would seed under a key no production read can find"
    );
    assert!(
        staging_key.starts_with(&staging),
        "the suite composes {staging_key:?} and the adapter's STAGING_PREFIX is {staging:?}"
    );
    assert_ne!(ready, staging, "the two prefixes must differ");

    // Prefix agreement alone cannot catch a segment-order or separator
    // drift — `v1/ready/{gen}/{a}/{w}` still starts with the prefix. The
    // domain's own derivation functions are the symbolic source: read
    // each `format!` literal out of `ready_key_for`/`staging_key_for`,
    // substitute the same inputs the suite composes with, and require
    // the production template to produce exactly the suite's key.
    let domain_path = std::path::Path::new(manifest)
        .join("../../crates/capabilities/central-artifact/src/domain.rs");
    let domain_src = std::fs::read_to_string(&domain_path)
        .unwrap_or_else(|e| panic!("read the artifact domain {}: {e}", domain_path.display()));
    let derivation = |function: &str| -> String {
        let fn_at = domain_src
            .find(&format!("fn {function}("))
            .unwrap_or_else(|| panic!("the domain source no longer declares {function}; this pin would hold the key shape to nothing"));
        let lit_at = domain_src[fn_at..]
            .find("format!(\"")
            .unwrap_or_else(|| panic!("{function} no longer derives through a format literal"));
        domain_src[fn_at + lit_at + "format!(\"".len()..]
            .split('"')
            .next()
            .expect("a quoted derivation")
            .to_owned()
    };
    for (function, suite_key) in [("ready_key_for", &ready_key), ("staging_key", &staging_key)] {
        let production = derivation(function)
            .replace("{workspace_id}", "w")
            .replace("{artifact_id}", "a")
            .replace("{generation}", "0");
        assert_eq!(
            *suite_key, production,
            "the suite composes {suite_key:?} but the domain's {function} derives {production:?} for the same inputs; the seeded corpus would seed under a key no production read can find"
        );
    }
}

/// `TestC06TheCorruptionPlanIsAnchoredToTheDomainSource` — the enumeration
/// the plan is written against is checked by reading the domain source, so
/// a reason added to the domain without a case here goes red rather than
/// silently shrinking what the combined injection must cover.
#[test]
fn the_corruption_plan_is_anchored_to_the_domain_source() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let domain_source = std::fs::read_to_string(
        PathBuf::from(manifest)
            .join("../../crates/capabilities/central-backup/src/recovery/quarantine.rs"),
    )
    .expect("the quarantine domain source must be readable");
    for reason in quarantine_reasons() {
        let variant = format!("Self::{} => \"{}\"", variant_name(reason), reason.as_str());
        assert!(
            domain_source.contains(&variant),
            "the domain source does not declare {} as a QuarantineReason; the combined injection would require a class the application cannot produce",
            reason.as_str()
        );
    }
    // Count the enum's own variant arms — a reason added to the domain and
    // not to this suite is one the plan cannot cover. A variant arm is an
    // identifier followed by a comma at the top level of the enum body.
    let declared = domain_source
        .split("pub enum QuarantineReason")
        .nth(1)
        .and_then(|tail| tail.split('}').next())
        .map(|body| {
            body.lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    trimmed.strip_suffix(',').is_some_and(|v| {
                        !v.is_empty()
                            && v.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                            && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    })
                })
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        declared,
        quarantine_reasons().len(),
        "the domain declares {declared} quarantine reasons and this suite knows {}; a sixth reason must produce a sixth injection",
        quarantine_reasons().len()
    );
}

fn variant_name(reason: QuarantineReason) -> &'static str {
    match reason {
        QuarantineReason::MissingBody => "MissingBody",
        QuarantineReason::ChecksumMismatch => "ChecksumMismatch",
        QuarantineReason::SizeMismatch => "SizeMismatch",
        QuarantineReason::UnexpectedArtifact => "UnexpectedArtifact",
        QuarantineReason::MetadataMismatch => "MetadataMismatch",
    }
}
