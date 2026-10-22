//! `central.artifacts` / `central.artifact_command_receipts` /
//! `central.capacity_reservations` / `central.workspaces` leaf queries
//! and the canonical command-identity fingerprint — the port of
//! `internal/adapter/postgres/artifact/{queries.go,store.go}`'s
//! shared query surface.
//!
//! Every leaf here is a compile-time checked `sqlx::query!`; the
//! transaction-scoped statements take `&mut Transaction` and the
//! plain reads take a generic `Executor` so they serve both the
//! replay paths inside a transaction and the unlocked `load_artifact`
//! snapshot read.

use central_artifact::domain::{
    Artifact, ArtifactTombstone, CommandIdentity, CommandStage, Disposition, Limits, Outcome,
    OutcomeKind, Sensitivity, State, rejection_outcome,
};
use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{
    ArtifactId, ArtifactTombstoneId, ContentGeneration, StagingGeneration, StepAttemptId, StepId,
    ToolCallAttemptId, WorkspaceId,
};
use sha2::{Digest, Sha256};
use sqlx::{Executor, Postgres, Transaction};
use time::OffsetDateTime;

use super::{conflict, corrupt};
use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::uuid_of;

// ---------------------------------------------------------------------------
// Command identity canonicalization: idempotency key + fingerprint
// (upstream commandReceiptKey / canonicalIdentityHash).
// ---------------------------------------------------------------------------

/// `commandReceiptKey` — derives the durable receipt lookup key and the
/// 32-byte fingerprint for one command identity. Reserve carries a
/// caller-supplied idempotency key (the only stage that does); every
/// other stage's identity is fully self-describing, so its own
/// canonical encoding serves as both the lookup key and the fingerprint.
pub(crate) fn command_receipt_key(id: &CommandIdentity) -> (String, [u8; 32]) {
    let fingerprint = canonical_identity_hash(id);
    if id.stage == CommandStage::Reserve && !id.idempotency_key.is_empty() {
        return (id.idempotency_key.clone(), fingerprint);
    }
    (hex_encode(&fingerprint), fingerprint)
}

/// `canonicalIdentityHash` — SHA-256 over the Go `encoding/json` form of
/// the canonical identity struct, byte for byte: fixed field order,
/// compact separators, `omitempty` on `failure_code` and
/// `reserve_fingerprint` only, and Go's HTML-escaping string encoder.
/// The golden digests in this module's tests are taken verbatim from
/// upstream `identity_fingerprint_test.go`.
pub(crate) fn canonical_identity_hash(id: &CommandIdentity) -> [u8; 32] {
    let mut canonical = Vec::with_capacity(512);
    canonical.push(b'{');
    let mut first = true;
    push_json_field(&mut canonical, &mut first, "stage", id.stage.as_str());
    let workspace = id.workspace_id.to_string();
    push_json_field(&mut canonical, &mut first, "workspace_id", &workspace);
    let artifact = id.artifact_id.to_string();
    push_json_field(&mut canonical, &mut first, "artifact_id", &artifact);
    push_json_i64_field(
        &mut canonical,
        &mut first,
        "expected_version",
        id.expected_version,
    );
    // A missing generation is the Go nil UUID — its String() renders the
    // all-zero form, never the empty string.
    let staging = id.staging_generation.map_or_else(
        || "00000000-0000-0000-0000-000000000000".to_owned(),
        |generation| generation.to_string(),
    );
    push_json_field(&mut canonical, &mut first, "staging_generation", &staging);
    let content = id.content_generation.map_or_else(
        || "00000000-0000-0000-0000-000000000000".to_owned(),
        |generation| generation.to_string(),
    );
    push_json_field(&mut canonical, &mut first, "content_generation", &content);
    push_json_field(&mut canonical, &mut first, "ready_key", &id.ready_key);
    push_json_i64_field(
        &mut canonical,
        &mut first,
        "verified_size",
        id.verified_size,
    );
    let checksum = hex_encode(&id.verified_checksum);
    push_json_field(&mut canonical, &mut first, "verified_checksum", &checksum);
    push_json_field(
        &mut canonical,
        &mut first,
        "idempotency_key",
        &id.idempotency_key,
    );
    // `failure_code` is populated only by Verify/Reject; omitting it keeps
    // every other stage's canonical encoding byte-identical to what it was
    // before rejection identities existed, so no retained receipt
    // fingerprint changes.
    if !id.failure_code.is_empty() {
        push_json_field(&mut canonical, &mut first, "failure_code", &id.failure_code);
    }
    // `reserve_fingerprint` folds in the domain's own reserve-request
    // fingerprint (upstream's `,omitempty` drop on the all-zero array):
    // it covers the byte limit, required-output role, and the whole
    // ownership chain the remaining fields do not.
    if id.fingerprint != [0; 32] {
        let reserve = hex_encode(&id.fingerprint);
        push_json_field(&mut canonical, &mut first, "reserve_fingerprint", &reserve);
    }
    canonical.push(b'}');
    Sha256::digest(&canonical).into()
}

/// Lowercase hex (Go `hex.EncodeToString`) — no `hex` dependency.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Writes one `"name":"value"` pair, honoring the running `first` flag.
fn push_json_field(buf: &mut Vec<u8>, first: &mut bool, name: &str, value: &str) {
    if !*first {
        buf.push(b',');
    }
    *first = false;
    push_json_string(buf, name);
    buf.push(b':');
    push_json_string(buf, value);
}

/// Writes one `"name":<int>` pair, honoring the running `first` flag.
fn push_json_i64_field(buf: &mut Vec<u8>, first: &mut bool, name: &str, value: i64) {
    if !*first {
        buf.push(b',');
    }
    *first = false;
    push_json_string(buf, name);
    buf.push(b':');
    buf.extend_from_slice(value.to_string().as_bytes());
}

/// Writes `value` as a Go `encoding/json` string literal — the same
/// escaping `central-artifact::domain`'s canonical encoders use:
/// `\"`, `\\`, `\n`, `\r`, `\t`, `\u00xx` for other control characters
/// (never `\b`/`\f`), and Go's always-on HTML escapes `<` `>` `&`
/// U+2028 U+2029.
pub(crate) fn push_json_string(buf: &mut Vec<u8>, value: &str) {
    buf.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => buf.extend_from_slice(b"\\\""),
            '\\' => buf.extend_from_slice(b"\\\\"),
            '\n' => buf.extend_from_slice(b"\\n"),
            '\r' => buf.extend_from_slice(b"\\r"),
            '\t' => buf.extend_from_slice(b"\\t"),
            '<' => buf.extend_from_slice(b"\\u003c"),
            '>' => buf.extend_from_slice(b"\\u003e"),
            '&' => buf.extend_from_slice(b"\\u0026"),
            '\u{2028}' => buf.extend_from_slice(b"\\u2028"),
            '\u{2029}' => buf.extend_from_slice(b"\\u2029"),
            c if (c as u32) < 0x20 => {
                buf.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut encoded = [0u8; 4];
                buf.extend_from_slice(c.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    buf.push(b'"');
}

// ---------------------------------------------------------------------------
// artifact_command_receipts — durable idempotency journal.
// ---------------------------------------------------------------------------

/// `receiptTTL` — seven days.
pub(crate) const RECEIPT_TTL: time::Duration = time::Duration::days(7);

pub(crate) struct ReceiptRow {
    pub(crate) found: bool,
    pub(crate) fingerprint: [u8; 32],
}

/// `queryLookupArtifactReceipt`.
pub(crate) async fn lookup_artifact_receipt(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    kind: &str,
    idempotency_key: &str,
) -> Result<ReceiptRow, Failure> {
    let row = sqlx::query!(
        "SELECT request_fingerprint FROM central.artifact_command_receipts \
         WHERE workspace_id = $1 AND command_kind = $2 AND idempotency_key = $3",
        uuid_of(workspace_id.as_bytes()),
        kind,
        idempotency_key,
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: lookup command receipt")?;
    match row {
        None => Ok(ReceiptRow {
            found: false,
            fingerprint: [0; 32],
        }),
        Some(row) => {
            let fingerprint: [u8; 32] =
                row.request_fingerprint.as_slice().try_into().map_err(|_| {
                    corrupt("an artifact_command_receipts fingerprint is not 32 bytes")
                })?;
            Ok(ReceiptRow {
                found: true,
                fingerprint,
            })
        }
    }
}

/// `queryInsertArtifactReceipt` — `ON CONFLICT ... DO NOTHING`; zero rows
/// affected means another writer committed the identity first, a hard
/// idempotency conflict (never a silent replay).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_artifact_receipt(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
    kind: &str,
    idempotency_key: &str,
    fingerprint: [u8; 32],
    payload: serde_json::Value,
) -> Result<(), Failure> {
    let expires = OffsetDateTime::now_utc() + RECEIPT_TTL;
    let done = sqlx::query!(
        "INSERT INTO central.artifact_command_receipts (\
         id, workspace_id, artifact_id, command_kind, idempotency_key, \
         request_fingerprint, result_payload, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8) \
         ON CONFLICT (workspace_id, command_kind, idempotency_key) DO NOTHING",
        uuid::Uuid::now_v7(),
        uuid_of(workspace_id.as_bytes()),
        uuid_of(artifact_id.as_bytes()),
        kind,
        idempotency_key,
        &fingerprint[..],
        payload,
        expires,
    )
    .execute(&mut **tx)
    .await
    .ctx("artifact: insert command receipt")?
    .rows_affected();
    if done != 1 {
        return Err(conflict("IDEMPOTENCY_CONFLICT"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// artifacts row model (upstream artifactRow / scanArtifactRow /
// toDomainArtifact / outcomeFromRow).
// ---------------------------------------------------------------------------

/// The persisted artifact row with domain-typed fields already mapped.
/// `rejection_code` and `max_bytes` come from the JSONB side-channels
/// exactly as upstream parses them.
pub(crate) struct ArtifactRow {
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) artifact_id: ArtifactId,
    pub(crate) version: i64,
    pub(crate) state: State,
    pub(crate) staging_generation: StagingGeneration,
    pub(crate) staging_key: String,
    pub(crate) content_generation: Option<ContentGeneration>,
    pub(crate) ready_key: String,
    pub(crate) limits: Limits,
    pub(crate) verified_size: i64,
    pub(crate) verified_checksum: [u8; 32],
    pub(crate) rejection_code: String,
    pub(crate) ready_object_version: String,
    pub(crate) task_id: central_foundation::identity::TaskId,
    pub(crate) run_id: central_foundation::identity::RunId,
    pub(crate) step_id: StepId,
    pub(crate) step_attempt_id: StepAttemptId,
    pub(crate) tool_call_attempt_id: Option<ToolCallAttemptId>,
    pub(crate) producer_id: String,
    pub(crate) required_role: String,
    pub(crate) sensitivity: Sensitivity,
    pub(crate) disposition: Disposition,
    pub(crate) delete_intent_at: Option<OffsetDateTime>,
    pub(crate) deleted_at: Option<OffsetDateTime>,
}

/// The shared row → [`ArtifactRow`] mapping; fails closed on anything
/// the domain cannot represent (`PG_DATA_CORRUPT`, never a caller
/// conflict) — the same discipline `execution`'s row readers follow.
struct RawArtifactRow {
    workspace_id: uuid::Uuid,
    id: uuid::Uuid,
    version: i64,
    state: String,
    staging_generation: uuid::Uuid,
    staging_key: String,
    content_generation: Option<uuid::Uuid>,
    ready_key: String,
    limits_snapshot: Option<serde_json::Value>,
    size: i64,
    checksum_value: Option<Vec<u8>>,
    rejection: Option<serde_json::Value>,
    ready_object_version: String,
    task_id: uuid::Uuid,
    run_id: uuid::Uuid,
    step_id: Option<uuid::Uuid>,
    step_attempt_id: Option<uuid::Uuid>,
    tool_call_attempt_id: Option<uuid::Uuid>,
    producer_id: String,
    required_role: String,
    sensitivity: String,
    disposition: String,
    delete_intent_at: Option<OffsetDateTime>,
    deleted_at: Option<OffsetDateTime>,
}

fn artifact_from_raw(row: RawArtifactRow) -> Result<ArtifactRow, Failure> {
    let state = State::parse(&row.state)
        .ok_or_else(|| corrupt("an artifacts.state is outside the closed vocabulary"))?;
    let sensitivity = Sensitivity::parse(&row.sensitivity)
        .ok_or_else(|| corrupt("an artifacts.sensitivity is outside the closed set"))?;
    let disposition = Disposition::parse(&row.disposition)
        .ok_or_else(|| corrupt("an artifacts.disposition is outside the closed set"))?;
    let max_bytes = row
        .limits_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.get("max_bytes"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let rejection_code = row
        .rejection
        .as_ref()
        .and_then(|rejection| rejection.get("code"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let mut verified_checksum = [0u8; 32];
    if let Some(checksum) = row.checksum_value.as_deref()
        && checksum.len() == 32
    {
        verified_checksum.copy_from_slice(checksum);
    }
    Ok(ArtifactRow {
        workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
        artifact_id: ArtifactId::from_trusted_db_bytes(*row.id.as_bytes()),
        version: row.version,
        state,
        staging_generation: StagingGeneration::from_trusted_db_bytes(
            *row.staging_generation.as_bytes(),
        ),
        staging_key: row.staging_key,
        content_generation: row
            .content_generation
            .map(|id| ContentGeneration::from_trusted_db_bytes(*id.as_bytes())),
        ready_key: row.ready_key,
        limits: Limits { max_bytes },
        verified_size: row.size,
        verified_checksum,
        rejection_code,
        ready_object_version: row.ready_object_version,
        task_id: central_foundation::identity::TaskId::from_trusted_db_bytes(
            *row.task_id.as_bytes(),
        ),
        run_id: central_foundation::identity::RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
        step_id: row.step_id.map_or_else(
            || StepId::from_trusted_db_bytes([0; 16]),
            |id| StepId::from_trusted_db_bytes(*id.as_bytes()),
        ),
        step_attempt_id: row.step_attempt_id.map_or_else(
            || StepAttemptId::from_trusted_db_bytes([0; 16]),
            |id| StepAttemptId::from_trusted_db_bytes(*id.as_bytes()),
        ),
        tool_call_attempt_id: row
            .tool_call_attempt_id
            .map(|id| ToolCallAttemptId::from_trusted_db_bytes(*id.as_bytes())),
        producer_id: row.producer_id,
        required_role: row.required_role,
        sensitivity,
        disposition,
        delete_intent_at: row.delete_intent_at,
        deleted_at: row.deleted_at,
    })
}

/// `readArtifact` — the plain snapshot read (no lock).
pub(crate) async fn read_artifact<'e, E>(
    executor: E,
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
) -> Result<ArtifactRow, Failure>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query_as!(
        RawArtifactRow,
        "SELECT workspace_id, id, version, state, \
         staging_generation, COALESCE(staging_key, '') AS \"staging_key!\", \
         content_generation, COALESCE(ready_key, '') AS \"ready_key!\", \
         limits_snapshot, size, checksum_value, rejection, \
         COALESCE(ready_object_version, '') AS \"ready_object_version!\", \
         task_id, run_id, step_id, step_attempt_id, tool_call_attempt_id, \
         COALESCE(producer_id, '') AS \"producer_id!\", \
         COALESCE(required_role, '') AS \"required_role!\", \
         sensitivity, disposition, delete_intent_at, deleted_at \
         FROM central.artifacts \
         WHERE workspace_id = $1 AND id = $2",
        uuid_of(workspace_id.as_bytes()),
        uuid_of(artifact_id.as_bytes()),
    )
    .fetch_optional(executor)
    .await
    .map_err(|e| classify_sqlx(&e))?;
    row.map(artifact_from_raw)
        .transpose()?
        .ok_or_else(|| conflict("ARTIFACT_NOT_FOUND"))
}

/// `readArtifactForUpdate` — the same projection under a row lock.
pub(crate) async fn read_artifact_for_update(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
) -> Result<ArtifactRow, Failure> {
    let row = sqlx::query_as!(
        RawArtifactRow,
        "SELECT workspace_id, id, version, state, \
         staging_generation, COALESCE(staging_key, '') AS \"staging_key!\", \
         content_generation, COALESCE(ready_key, '') AS \"ready_key!\", \
         limits_snapshot, size, checksum_value, rejection, \
         COALESCE(ready_object_version, '') AS \"ready_object_version!\", \
         task_id, run_id, step_id, step_attempt_id, tool_call_attempt_id, \
         COALESCE(producer_id, '') AS \"producer_id!\", \
         COALESCE(required_role, '') AS \"required_role!\", \
         sensitivity, disposition, delete_intent_at, deleted_at \
         FROM central.artifacts \
         WHERE workspace_id = $1 AND id = $2 FOR UPDATE",
        uuid_of(workspace_id.as_bytes()),
        uuid_of(artifact_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: lock artifact row")?;
    row.map(artifact_from_raw)
        .transpose()?
        .ok_or_else(|| conflict("ARTIFACT_NOT_FOUND"))
}

/// `toDomainArtifact` — every domain field comes from the row; nothing
/// is re-derived.
pub(crate) fn to_domain_artifact(row: &ArtifactRow) -> Artifact {
    Artifact {
        workspace_id: row.workspace_id,
        artifact_id: row.artifact_id,
        state: row.state,
        version: row.version,
        staging_generation: row.staging_generation,
        staging_key: row.staging_key.clone(),
        content_generation: row.content_generation,
        ready_key: row.ready_key.clone(),
        limits: row.limits,
        verified_size: row.verified_size,
        verified_checksum: row.verified_checksum,
        ready_object_version: row.ready_object_version.clone(),
        task_id: row.task_id,
        run_id: row.run_id,
        step_id: row.step_id,
        step_attempt_id: row.step_attempt_id,
        tool_call_attempt_id: row.tool_call_attempt_id,
        producer_id: row.producer_id.clone(),
        required_role: row.required_role.clone(),
        sensitivity: row.sensitivity,
        disposition: row.disposition,
        delete_intent_at: row.delete_intent_at,
        deleted_at: row.deleted_at,
    }
}

/// `outcomeFromRow` — reconstructs the `Outcome` a rejected row
/// originally carried. `None` for a non-rejected row; an unrecognized
/// durable rejection code stays terminal, the conservative reading.
pub(crate) fn outcome_from_row(row: &ArtifactRow) -> Option<Outcome> {
    if row.state != State::Rejected {
        return None;
    }
    Some(
        rejection_outcome(&row.rejection_code).unwrap_or_else(|_| Outcome {
            kind: OutcomeKind::Terminal,
            failure_code: row.rejection_code.clone(),
        }),
    )
}

// ---------------------------------------------------------------------------
// workspaces quota ledger + capacity reservations.
// ---------------------------------------------------------------------------

/// `queryLockWorkspaceQuota` — `FOR NO KEY UPDATE`, not `FOR UPDATE`: it
/// serializes quota writers just the same, but does not conflict with
/// the `FOR KEY SHARE` lock a foreign-key check takes. `None` means the
/// workspace row is absent.
pub(crate) async fn lock_workspace_quota(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
) -> Result<Option<(i64, i64)>, Failure> {
    let row = sqlx::query!(
        "SELECT quota_ready_bytes, quota_max_bytes FROM central.workspaces \
         WHERE id = $1 FOR NO KEY UPDATE",
        uuid_of(workspace_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: lock workspace quota")?;
    Ok(row.map(|row| (row.quota_ready_bytes, row.quota_max_bytes)))
}

/// `queryActiveCapacityReservationSum`.
pub(crate) async fn active_capacity_sum(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
) -> Result<i64, Failure> {
    let row = sqlx::query!(
        "SELECT COALESCE(SUM(reserved_bytes), 0)::bigint AS \"sum!\" \
         FROM central.capacity_reservations \
         WHERE workspace_id = $1 AND state = 'reserved'",
        uuid_of(workspace_id.as_bytes()),
    )
    .fetch_one(&mut **tx)
    .await
    .ctx("artifact: sum active capacity reservations")?;
    Ok(row.sum)
}

/// `queryLockCapacityReservation` — `None` means no reservation exists.
pub(crate) async fn lock_capacity_reservation(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
) -> Result<Option<String>, Failure> {
    let row = sqlx::query!(
        "SELECT state FROM central.capacity_reservations \
         WHERE workspace_id = $1 AND artifact_id = $2 FOR UPDATE",
        uuid_of(workspace_id.as_bytes()),
        uuid_of(artifact_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: lock capacity reservation")?;
    Ok(row.map(|row| row.state))
}

/// `queryReleaseCapacityReservation` — the state predicate makes a
/// second call a safe no-op rather than a double release (exactly-once).
pub(crate) async fn release_capacity_reservation(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
) -> Result<(), Failure> {
    sqlx::query!(
        "UPDATE central.capacity_reservations \
         SET state = 'released', released_at = clock_timestamp() \
         WHERE workspace_id = $1 AND artifact_id = $2 AND state = 'reserved'",
        uuid_of(workspace_id.as_bytes()),
        uuid_of(artifact_id.as_bytes()),
    )
    .execute(&mut **tx)
    .await
    .ctx("artifact: release capacity reservation")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// artifact_tombstones — the immutable deletion journal.
// ---------------------------------------------------------------------------

struct RawTombstoneRow {
    id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    artifact_id: uuid::Uuid,
    object_key: String,
    staging_generation: uuid::Uuid,
    checksum_algorithm: Option<String>,
    checksum_value: Option<Vec<u8>>,
    size_at_deletion: i64,
    deletion_reason: String,
}

fn tombstone_from_raw(row: RawTombstoneRow) -> Result<ArtifactTombstone, Failure> {
    let checksum_value = match row.checksum_value {
        None => None,
        Some(value) => Some(
            <[u8; 32]>::try_from(value.as_slice())
                .map_err(|_| corrupt("an artifact_tombstones checksum is not 32 bytes"))?,
        ),
    };
    Ok(ArtifactTombstone {
        id: ArtifactTombstoneId::from_trusted_db_bytes(*row.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
        artifact_id: ArtifactId::from_trusted_db_bytes(*row.artifact_id.as_bytes()),
        object_key: row.object_key,
        staging_generation: StagingGeneration::from_trusted_db_bytes(
            *row.staging_generation.as_bytes(),
        ),
        checksum_algorithm: row.checksum_algorithm,
        checksum_value,
        size_at_deletion: row.size_at_deletion,
        deletion_reason: row.deletion_reason,
    })
}

/// Reads the journaled tombstone for `(workspace_id, artifact_id)` —
/// `None` when none exists.
pub(crate) async fn read_tombstone(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
) -> Result<Option<ArtifactTombstone>, Failure> {
    let row = sqlx::query_as!(
        RawTombstoneRow,
        "SELECT id, workspace_id, artifact_id, object_key, staging_generation, \
         checksum_algorithm, checksum_value, size_at_deletion, deletion_reason \
         FROM central.artifact_tombstones \
         WHERE workspace_id = $1 AND artifact_id = $2",
        uuid_of(workspace_id.as_bytes()),
        uuid_of(artifact_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: read tombstone")?;
    row.map(tombstone_from_raw).transpose()
}

/// `FailureKind::Conflict` helper for the shared fingerprint-mismatch
/// arm every command stage repeats.
pub(crate) fn fingerprint_mismatch() -> Failure {
    Failure::new(
        FailureKind::Conflict,
        "IDEMPOTENCY_FINGERPRINT_MISMATCH",
        "artifact store refused",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_foundation::identity::{
        ArtifactId, ContentGeneration, StagingGeneration, WorkspaceId,
    };

    /// Upstream `fingerprintFixture` — every field is populated for every
    /// stage (the fixture varies only `stage` and `failure_code`), so the
    /// golden digests pin the whole canonical encoding at once.
    fn fingerprint_fixture(stage: CommandStage, failure_code: &str) -> CommandIdentity {
        let mut checksum = [0u8; 32];
        for (i, byte) in checksum.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap_or_default();
        }
        CommandIdentity {
            stage,
            workspace_id: WorkspaceId::parse("018f0000-0000-7000-8000-000000000001")
                .expect("workspace"),
            artifact_id: ArtifactId::parse("018f0000-0000-7000-8000-000000000002")
                .expect("artifact"),
            expected_version: 5,
            staging_generation: Some(
                StagingGeneration::parse("33333333-3333-4333-8333-333333333333").expect("staging"),
            ),
            content_generation: Some(
                ContentGeneration::parse("44444444-4444-4444-8444-444444444444").expect("content"),
            ),
            ready_key: "v1/ready/k".to_owned(),
            verified_size: 99,
            verified_checksum: checksum,
            idempotency_key: "op-1".to_owned(),
            fingerprint: [0; 32],
            failure_code: failure_code.to_owned(),
        }
    }

    /// Upstream `TestExistingCommandStageFingerprintsAreUnchanged` — the
    /// golden digests for every persisted command stage. A byte-level
    /// divergence in the canonical encoding silently turns every
    /// retained receipt replay into `IDEMPOTENCY_FINGERPRINT_MISMATCH`.
    #[test]
    fn existing_command_stage_fingerprints_are_unchanged() {
        let cases: [(CommandStage, &str); 5] = [
            (
                CommandStage::Reserve,
                "c0edfdb318e749deccaeb1d2969bfd2bbefc7d312ebb9bfe8b1edb8facb4f541",
            ),
            (
                CommandStage::BeginUpload,
                "79841b4b9299133aac41a53890025d9f8dacb5e7a543be3438a981e3bce2ad2f",
            ),
            (
                CommandStage::Verify,
                "58d330f4350835c06060e3e30d795541423eeae6dc79b6eb4c57e74240636df9",
            ),
            (
                CommandStage::Promote,
                "035861336b9f27000d4423cc15ab05037dc4dc68c071b34f1e09b81ea1803e47",
            ),
            (
                CommandStage::Finalize,
                "404faf80a68a32dd4c3befac701e7e3f50014af48089d8c0a322bff8364189c1",
            ),
        ];
        for (stage, expected) in cases {
            let id = fingerprint_fixture(stage, "");
            assert_eq!(
                hex_encode(&canonical_identity_hash(&id)),
                expected,
                "stage {stage}"
            );
        }
    }

    /// Upstream `TestRejectionFingerprintBindsTheFailureCode` — two
    /// rejections differing only in their closed reason are different
    /// commands, so neither replays the other.
    #[test]
    fn rejection_fingerprint_binds_the_failure_code() {
        let expired = canonical_identity_hash(&fingerprint_fixture(
            CommandStage::Reject,
            "STAGING_LIFETIME_EXPIRED",
        ));
        let non_delivery = canonical_identity_hash(&fingerprint_fixture(
            CommandStage::Reject,
            "UPLOAD_NON_DELIVERY",
        ));
        assert_ne!(expired, non_delivery);

        let (expired_key, _) = command_receipt_key(&fingerprint_fixture(
            CommandStage::Reject,
            "STAGING_LIFETIME_EXPIRED",
        ));
        let (non_delivery_key, _) = command_receipt_key(&fingerprint_fixture(
            CommandStage::Reject,
            "UPLOAD_NON_DELIVERY",
        ));
        assert_ne!(expired_key, non_delivery_key);
    }

    /// `commandReceiptKey`: reserve with a caller key replays under the
    /// caller key; every other stage derives its lookup key from the
    /// fingerprint itself.
    #[test]
    fn command_receipt_key_selects_key_source() {
        let reserve = fingerprint_fixture(CommandStage::Reserve, "");
        let (key, fingerprint) = command_receipt_key(&reserve);
        assert_eq!(key, "op-1");
        assert_eq!(fingerprint, canonical_identity_hash(&reserve));

        let begin = fingerprint_fixture(CommandStage::BeginUpload, "");
        let (begin_key, begin_fingerprint) = command_receipt_key(&begin);
        assert_eq!(begin_key, hex_encode(&begin_fingerprint));
        assert_eq!(begin_fingerprint, canonical_identity_hash(&begin));
    }

    /// Upstream `TestCanonicalHashFoldsInTheReserveFingerprint` — the
    /// domain's reserve-request fingerprint covers the byte limit,
    /// required-output role, and ownership chain the remaining fields do
    /// not, so it must be folded in: a reused reserve idempotency key
    /// bound to different reserved content is a fingerprint mismatch.
    #[test]
    fn reserve_fingerprint_folds_into_canonical_identity() {
        let base = fingerprint_fixture(CommandStage::Reserve, "");
        let mut with_fingerprint = base.clone();
        for (i, byte) in with_fingerprint.fingerprint.iter_mut().enumerate() {
            *byte = 0xa0 + u8::try_from(i % 16).unwrap_or_default();
        }
        assert_ne!(
            canonical_identity_hash(&base),
            canonical_identity_hash(&with_fingerprint)
        );

        let mut other = with_fingerprint.clone();
        other.fingerprint[0] ^= 0xff;
        assert_ne!(
            canonical_identity_hash(&other),
            canonical_identity_hash(&with_fingerprint)
        );

        // The receipt key for Reserve is the caller's idempotency key
        // either way; it is the fingerprint half that must now differ.
        let (base_key, base_fingerprint) = command_receipt_key(&with_fingerprint);
        let (other_key, other_fingerprint) = command_receipt_key(&other);
        assert_eq!(base_key, other_key);
        assert_ne!(base_fingerprint, other_fingerprint);
    }
}
