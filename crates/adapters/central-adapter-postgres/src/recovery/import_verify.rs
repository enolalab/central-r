//! `import_verify.go` — [`ImportTargetInspector`] answers ADR 0034's
//! post-restore questions against the fresh target: which ready
//! artifacts must receive staged bodies, and does the restored shape
//! match the dump's own table of contents. It holds only a runtime
//! SELECT connection: verification reads, it never writes.

use central_foundation::failure::Failure;
use sha2::Digest as _;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::SqlxContext as _;
use crate::store_support::BlockingConn;

/// `ErrImportTargetShape` is deliberately locator-free: table names are
/// source data (the bundle's bytes) and must never cross this recovery
/// boundary into an error the operator reads.
fn import_target_shape_unavailable() -> Failure {
    Failure::unavailable(
        "recovery_import_target_shape",
        "import target shape is unavailable",
    )
}

/// `backupapp.ImportTableRef` — names one TABLE entry from the staged
/// dump's own table of contents. Schema and name are source data (the
/// bundle's bytes), so every consumer quotes them as identifiers and
/// never interpolates them. (Adapter-owned: the C04 import engine that
/// owns this type in `backup/app` is not yet ported.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportTableRef {
    /// Schema name.
    pub schema: String,
    /// Table name.
    pub name: String,
}

/// `backupapp.ImportReadyArtifact` — one restored row the post-import
/// body upload must satisfy. `ready_key` is re-derived from the row's
/// own identity by the reader (mirroring `ReadyArtifactSource`) and
/// never trusted as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReadyArtifact {
    /// Artifact identity.
    pub artifact_id: Uuid,
    /// Sealed body checksum.
    pub checksum: [u8; 32],
    /// Sealed body size.
    pub size: i64,
    /// The re-derived ready object key.
    pub ready_key: String,
}

/// `pgx.Identifier{...}.Sanitize()` — strict PostgreSQL identifier
/// quoting: each part is `"`-wrapped with `"` doubled inside. A hostile
/// table name can fail the import but never escape the query.
fn sanitize_identifier(schema: &str, name: &str) -> String {
    let quote = |part: &str| format!("\"{}\"", part.replace('"', "\"\""));
    format!("{}.{}", quote(schema), quote(name))
}

/// `ImportTargetInspector` — see module docs.
pub struct ImportTargetInspector {
    conn: BlockingConn,
}

impl ImportTargetInspector {
    /// `NewImportTargetInspector` — over an already-opened runtime
    /// connection to the import target.
    ///
    /// # Errors
    /// `recovery_import_target_shape` when the bridge runtime cannot
    /// be built.
    pub fn new(conn: PgConnection) -> Result<Self, Failure> {
        Ok(Self {
            conn: BlockingConn::new(conn)?,
        })
    }

    /// `ListReadyArtifacts` returns every restored artifact row the body
    /// upload must satisfy, in artifact-ID order. The predicate mirrors
    /// `ReadyArtifactSource::list_ready_artifacts` exactly (ready, no
    /// delete intent): the backup inventoried exactly this set, so the
    /// import uploads exactly this set — staging-state artifacts have
    /// no staged bodies and do not survive the import.
    ///
    /// # Errors
    /// `recovery_import_target_shape` on any failure.
    pub fn list_ready_artifacts(&self) -> Result<Vec<ImportReadyArtifact>, Failure> {
        struct RawImportRow {
            id: uuid::Uuid,
            size: i64,
            checksum_value: Option<Vec<u8>>,
            ready_key: Option<String>,
            workspace_id: uuid::Uuid,
            content_generation: Option<uuid::Uuid>,
        }
        self.conn.run(|conn| {
            Box::pin(async move {
                let rows = sqlx::query_as!(
                    RawImportRow,
                    "SELECT id, size, checksum_value, ready_key,
                        workspace_id, content_generation
                    FROM central.artifacts
                    WHERE state='ready' AND delete_intent_at IS NULL
                    ORDER BY id ASC",
                )
                .fetch_all(&mut *conn)
                .await
                .ctx("recovery: list import ready artifacts")?;
                let mut out = Vec::with_capacity(rows.len());
                for row in &rows {
                    let checksum: [u8; 32] = row
                        .checksum_value
                        .as_deref()
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(import_target_shape_unavailable)?;
                    let (Some(ready_key), Some(generation)) =
                        (row.ready_key.as_deref(), row.content_generation)
                    else {
                        return Err(import_target_shape_unavailable());
                    };
                    if row.id.is_nil()
                        || row.workspace_id.is_nil()
                        || generation.is_nil()
                        || row.size < 0
                    {
                        return Err(import_target_shape_unavailable());
                    }
                    // The key is re-derived, never trusted as stored —
                    // the same check ReadyArtifactSource applies at
                    // backup time.
                    let derived =
                        format!("v1/ready/{}/{}/{}", row.workspace_id, row.id, generation);
                    if ready_key != derived {
                        return Err(import_target_shape_unavailable());
                    }
                    out.push(ImportReadyArtifact {
                        artifact_id: row.id,
                        checksum,
                        size: row.size,
                        ready_key: derived,
                    });
                }
                Ok::<Vec<ImportReadyArtifact>, Failure>(out)
            })
        })
    }

    /// `VerifyTargetShape` proves every TABLE entry from the dump's own
    /// table of contents exists in the target and records the shape
    /// checksum: the hex SHA-256 over the sorted
    /// `(schema.table, exact row count)` listing. An empty table list is
    /// refused, never vacuously accepted — a dump with no tables
    /// restoring "successfully" onto a fresh database is not an import.
    ///
    /// Presence is probed with a parameterized `to_regclass($1)` call;
    /// the count uses the sanitized identifier — the one controlled
    /// dynamic-SQL exception in this adapter, mirroring upstream's
    /// `pgx.Identifier.Sanitize` design. Compile-checked macros cannot
    /// bind an identifier, and a runtime `format!` over a sanitized
    /// `identifier` is the verbatim port.
    ///
    /// # Errors
    /// `recovery_import_target_shape` on any failure; returns
    /// `(shape_checksum_hex, table_count)` on success.
    pub fn verify_target_shape(
        &self,
        tables: &[ImportTableRef],
    ) -> Result<(String, usize), Failure> {
        if tables.is_empty() {
            return Err(import_target_shape_unavailable());
        }
        for table in tables {
            if table.schema.is_empty() || table.name.is_empty() {
                return Err(import_target_shape_unavailable());
            }
        }
        let tables = tables.to_vec();
        self.conn.run(|conn| {
            Box::pin(async move {
                let mut lines = Vec::with_capacity(tables.len());
                for table in &tables {
                    let qualified = format!("{}.{}", table.schema, table.name);
                    let regclass = sqlx::query_scalar!(
                        "SELECT to_regclass($1)::text AS \"regclass\"",
                        qualified,
                    )
                    .fetch_one(&mut *conn)
                    .await
                    .ctx("recovery: probe import table")?;
                    if regclass.is_none() {
                        return Err(import_target_shape_unavailable());
                    }
                    let identifier = sanitize_identifier(&table.schema, &table.name);
                    let count =
                        sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {identifier}"))
                            .fetch_one(&mut *conn)
                            .await
                            .map_err(|_| import_target_shape_unavailable())?;
                    if count < 0 {
                        return Err(import_target_shape_unavailable());
                    }
                    lines.push(format!("{}.{}:{}", table.schema, table.name, count));
                }
                lines.sort();
                let digest = sha2::Sha256::digest(format!("{}\n", lines.join("\n")).as_bytes());
                let table_count = lines.len();
                Ok::<(String, usize), Failure>((crate::backup::hex_encode(&digest), table_count))
            })
        })
    }
}
