//! `central-artifact` b34 lineage stores — the port of
//! `internal/adapter/postgres/artifact/lineage_store.go`:
//! `ProduceEdgeStore`, `ReadEdgeStore`, `LineageReader`, and
//! `ReadStore` over `central.artifact_produce_edges` and
//! `central.artifact_read_edges`.
//!
//! Everything follows this adapter's invariants: `sqlx` stays inside
//! the adapter, every statement runs inside one bounded
//! `store_support::begin_tx` transaction, no artifact body ever
//! touches PostgreSQL, and errors surface only through the
//! `classify_sqlx`/`ctx` sanitized classification. Both tables are
//! append-only for `central_runtime` (`SELECT, INSERT` only); the
//! only writes are idempotent inserts whose `ON CONFLICT` dedupe
//! makes journaled edge replay an exact-replay success rather than a
//! failure.
//!
//! Identity mapping note: upstream scans every uuid column through
//! `::text` + version-agnostic `uuid.FromString`. The Rust port binds
//! and scans `Uuid` directly and wraps identity newtypes through
//! `from_trusted_db_bytes` — the trusted-DB-boundary conversion —
//! which is upstream's version-agnostic acceptance exactly (the b34
//! columns carry no version constraint of their own).

use std::collections::HashSet;

use central_artifact::domain::State;
use central_artifact::lineage::{LineageArtifact, ProduceEdge, ReadEdge};
use central_artifact::port::{LineageReader, ProduceEdgeStore, ReadEdgeStore, ReadStore};
use central_foundation::failure::Failure;
use central_foundation::identity::{
    ArtifactId, ProduceEdgeId, ReadEdgeId, RunId, SessionAttemptId, WorkflowNodeId, WorkspaceId,
};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

use super::{conflict, corrupt};
use crate::error::{SqlxContext, classify_sqlx};
use crate::store_support::{begin_tx, opt_uuid_of, uuid_of};

use super::Store;

// ---------------------------------------------------------------------------
// Row shapes + trusted-boundary identity mapping.
// ---------------------------------------------------------------------------

struct RawProduceEdge {
    id: uuid::Uuid,
    run_id: uuid::Uuid,
    node_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    artifact_id: uuid::Uuid,
    created_at: OffsetDateTime,
}

fn produce_edge_from_raw(row: RawProduceEdge) -> ProduceEdge {
    ProduceEdge {
        id: ProduceEdgeId::from_trusted_db_bytes(*row.id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
        node_id: WorkflowNodeId::from_trusted_db_bytes(*row.node_id.as_bytes()),
        attempt_id: SessionAttemptId::from_trusted_db_bytes(*row.attempt_id.as_bytes()),
        artifact_id: ArtifactId::from_trusted_db_bytes(*row.artifact_id.as_bytes()),
        created_at: row.created_at,
    }
}

struct RawReadEdge {
    id: uuid::Uuid,
    run_id: uuid::Uuid,
    reader_node_id: Option<uuid::Uuid>,
    attempt_id: Option<uuid::Uuid>,
    artifact_id: uuid::Uuid,
    declared: bool,
    checksum: String,
    created_at: OffsetDateTime,
}

fn read_edge_from_raw(row: RawReadEdge) -> ReadEdge {
    ReadEdge {
        id: ReadEdgeId::from_trusted_db_bytes(*row.id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
        reader_node_id: row
            .reader_node_id
            .map(|id| WorkflowNodeId::from_trusted_db_bytes(*id.as_bytes())),
        attempt_id: row
            .attempt_id
            .map(|id| SessionAttemptId::from_trusted_db_bytes(*id.as_bytes())),
        artifact_id: ArtifactId::from_trusted_db_bytes(*row.artifact_id.as_bytes()),
        declared: row.declared,
        checksum: row.checksum,
        created_at: row.created_at,
    }
}

struct RawLineageArtifact {
    id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    run_id: uuid::Uuid,
    state: String,
    ready_key: String,
    checksum: String,
}

fn lineage_artifact_from_raw(row: RawLineageArtifact) -> Result<LineageArtifact, Failure> {
    let state = State::parse(&row.state)
        .ok_or_else(|| corrupt("an artifacts.state is outside the closed vocabulary"))?;
    Ok(LineageArtifact {
        id: ArtifactId::from_trusted_db_bytes(*row.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
        run_id: RunId::from_trusted_db_bytes(*row.run_id.as_bytes()),
        state,
        ready_key: row.ready_key,
        checksum: row.checksum,
    })
}

/// `querySelectProduceEdgeForArtifact` — the journaled edge for one
/// artifact, when present.
async fn produce_edge_for_artifact_tx(
    tx: &mut Transaction<'_, Postgres>,
    artifact_id: ArtifactId,
) -> Result<Option<ProduceEdge>, Failure> {
    let row = sqlx::query_as!(
        RawProduceEdge,
        "SELECT id, run_id, node_id, attempt_id, artifact_id, created_at \
         FROM central.artifact_produce_edges \
         WHERE artifact_id = $1",
        uuid_of(artifact_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: read produce edge")?;
    Ok(row.map(produce_edge_from_raw))
}

// ---------------------------------------------------------------------------
// Inserts (append-only, idempotent)
// ---------------------------------------------------------------------------

impl ProduceEdgeStore for Store {
    /// `InsertProduceEdge` — journals the produce edge.
    /// `ON CONFLICT (artifact_id) DO NOTHING` is the
    /// `unique(artifact_id)` dedupe: a replayed finalization returns
    /// the originally journaled edge.
    async fn insert_produce_edge(&self, edge: ProduceEdge) -> Result<ProduceEdge, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let inserted = sqlx::query_as!(
            RawProduceEdge,
            "INSERT INTO central.artifact_produce_edges \
             (id, run_id, node_id, attempt_id, artifact_id) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (artifact_id) DO NOTHING \
             RETURNING id, run_id, node_id, attempt_id, artifact_id, created_at",
            uuid_of(edge.id.as_bytes()),
            uuid_of(edge.run_id.as_bytes()),
            uuid_of(edge.node_id.as_bytes()),
            uuid_of(edge.attempt_id.as_bytes()),
            uuid_of(edge.artifact_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("artifact: insert produce edge")?;
        let out = match inserted {
            Some(row) => produce_edge_from_raw(row),
            // Conflict: the artifact's edge already exists; return it.
            None => produce_edge_for_artifact_tx(&mut tx, edge.artifact_id)
                .await?
                .ok_or_else(|| conflict("LINEAGE_PRODUCE_EDGE_INCONSISTENT"))?,
        };
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }
}

impl ReadEdgeStore for Store {
    /// `InsertReadEdge` — journals one released read. The
    /// `(run, reader, attempt, artifact)` dedupe returns the
    /// journaled edge on a retried ambiguous read; the operator NULL
    /// pair never conflicts, so every operator read journals a
    /// distinct edge — matching the b34 UNIQUE semantics (NULLs are
    /// distinct). The `reader_pair_check` makes the NULL pair
    /// all-or-nothing at the schema level.
    async fn insert_read_edge(&self, edge: ReadEdge) -> Result<ReadEdge, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let inserted = sqlx::query_as!(
            RawReadEdge,
            "INSERT INTO central.artifact_read_edges \
             (id, run_id, reader_node_id, attempt_id, artifact_id, declared, checksum) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (run_id, reader_node_id, attempt_id, artifact_id) DO NOTHING \
             RETURNING id, run_id, reader_node_id, attempt_id, artifact_id, \
             declared, checksum, created_at",
            uuid_of(edge.id.as_bytes()),
            uuid_of(edge.run_id.as_bytes()),
            opt_uuid_of(edge.reader_node_id, |id| id.as_bytes()),
            opt_uuid_of(edge.attempt_id, |id| id.as_bytes()),
            uuid_of(edge.artifact_id.as_bytes()),
            edge.declared,
            edge.checksum.as_str(),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("artifact: insert read edge")?;
        let out = match inserted {
            Some(row) => read_edge_from_raw(row),
            None => {
                // Attempt-scoped dedupe replayed: return the journaled
                // edge. The operator NULL pair never reaches here —
                // its insert always lands a distinct row.
                if let Some(node_id) = edge.reader_node_id {
                    let row = sqlx::query_as!(
                        RawReadEdge,
                        "SELECT id, run_id, reader_node_id, attempt_id, artifact_id, \
                         declared, checksum, created_at \
                         FROM central.artifact_read_edges \
                         WHERE run_id = $1 AND reader_node_id = $2 \
                         AND attempt_id = $3 AND artifact_id = $4",
                        uuid_of(edge.run_id.as_bytes()),
                        uuid_of(node_id.as_bytes()),
                        opt_uuid_of(edge.attempt_id, |id| id.as_bytes()),
                        uuid_of(edge.artifact_id.as_bytes()),
                    )
                    .fetch_optional(&mut *tx)
                    .await
                    .ctx("artifact: read read-edge dedupe")?;
                    row.map(read_edge_from_raw)
                        .ok_or_else(|| conflict("LINEAGE_READ_EDGE_INCONSISTENT"))?
                } else {
                    return Err(conflict("LINEAGE_READ_EDGE_INCONSISTENT"));
                }
            }
        };
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// LineageReader projections
// ---------------------------------------------------------------------------

impl LineageReader for Store {
    /// `ProduceEdgeForArtifact` — the single produce edge for one
    /// artifact, when journaled.
    async fn produce_edge_for_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<ProduceEdge>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let out = produce_edge_for_artifact_tx(&mut tx, artifact_id).await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }

    /// `ReadEdgesForArtifact` — every read edge journaling a read of
    /// one artifact.
    async fn read_edges_for_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Vec<ReadEdge>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query_as!(
            RawReadEdge,
            "SELECT id, run_id, reader_node_id, attempt_id, artifact_id, \
             declared, checksum, created_at \
             FROM central.artifact_read_edges \
             WHERE artifact_id = $1 \
             ORDER BY created_at, id",
            uuid_of(artifact_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: read edges for artifact")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(rows.into_iter().map(read_edge_from_raw).collect())
    }

    /// `ReadEdgesForNode` — every read edge one node journaled,
    /// unioned across its attempts.
    async fn read_edges_for_node(&self, node_id: WorkflowNodeId) -> Result<Vec<ReadEdge>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query_as!(
            RawReadEdge,
            "SELECT id, run_id, reader_node_id, attempt_id, artifact_id, \
             declared, checksum, created_at \
             FROM central.artifact_read_edges \
             WHERE reader_node_id = $1 \
             ORDER BY created_at, id",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: read edges for node")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(rows.into_iter().map(read_edge_from_raw).collect())
    }

    /// `ProduceEdgesForNode` — every produce edge one node journaled,
    /// attributed per attempt.
    async fn produce_edges_for_node(
        &self,
        node_id: WorkflowNodeId,
    ) -> Result<Vec<ProduceEdge>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query_as!(
            RawProduceEdge,
            "SELECT id, run_id, node_id, attempt_id, artifact_id, created_at \
             FROM central.artifact_produce_edges \
             WHERE node_id = $1 \
             ORDER BY created_at, id",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: produce edges for node")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(rows.into_iter().map(produce_edge_from_raw).collect())
    }

    /// `ProduceEdgesForRun` — every produce edge journaled inside one
    /// run.
    async fn produce_edges_for_run(&self, run_id: RunId) -> Result<Vec<ProduceEdge>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query_as!(
            RawProduceEdge,
            "SELECT id, run_id, node_id, attempt_id, artifact_id, created_at \
             FROM central.artifact_produce_edges \
             WHERE run_id = $1 \
             ORDER BY created_at, id",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: produce edges for run")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(rows.into_iter().map(produce_edge_from_raw).collect())
    }

    /// `ReadEdgesForRun` — every read edge journaled inside one run.
    async fn read_edges_for_run(&self, run_id: RunId) -> Result<Vec<ReadEdge>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query_as!(
            RawReadEdge,
            "SELECT id, run_id, reader_node_id, attempt_id, artifact_id, \
             declared, checksum, created_at \
             FROM central.artifact_read_edges \
             WHERE run_id = $1 \
             ORDER BY created_at, id",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: read edges for run")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(rows.into_iter().map(read_edge_from_raw).collect())
    }
}

// ---------------------------------------------------------------------------
// ReadStore — the `central artifact read` authorization inputs.
// ---------------------------------------------------------------------------

impl ReadStore for Store {
    /// `FindArtifact` — resolves one artifact identity to its
    /// read-authorization projection: identity, lifecycle state, the
    /// opaque ready key, and the finalized checksum rendered as hex
    /// (`checksum_value` is `bytea` in the B10 schema; encoding here
    /// keeps the domain's checksum a plain string).
    async fn find_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<LineageArtifact>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let row = sqlx::query_as!(
            RawLineageArtifact,
            "SELECT id, workspace_id, run_id, state, \
             COALESCE(ready_key, '') AS \"ready_key!\", \
             COALESCE(encode(checksum_value, 'hex'), '') AS \"checksum!\" \
             FROM central.artifacts \
             WHERE id = $1",
            uuid_of(artifact_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("artifact: find lineage artifact")?;
        let out = row.map(lineage_artifact_from_raw).transpose()?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }

    /// `ResolveProduced` — the `--from`/`--name` selector resolves
    /// through the journaled produce edge plus the producing node's
    /// key and the artifact's required role: the produce edge is the
    /// durable "produced by" claim, `node_key` names the producer,
    /// `required_role` names the output.
    async fn resolve_produced(
        &self,
        run_id: Option<RunId>,
        node_key: &str,
        name: &str,
    ) -> Result<Vec<LineageArtifact>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query_as!(
            RawLineageArtifact,
            "SELECT a.id, a.workspace_id, a.run_id, a.state, \
             COALESCE(a.ready_key, '') AS \"ready_key!\", \
             COALESCE(encode(a.checksum_value, 'hex'), '') AS \"checksum!\" \
             FROM central.artifact_produce_edges pe \
             JOIN central.workflow_nodes n ON n.id = pe.node_id \
             JOIN central.artifacts a ON a.id = pe.artifact_id \
             WHERE n.node_key = $2 AND a.required_role = $3 \
             AND ($1::uuid IS NULL OR pe.run_id = $1::uuid) \
             ORDER BY pe.created_at, pe.id",
            opt_uuid_of(run_id, |id| id.as_bytes()),
            node_key,
            name,
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: resolve produced artifact")?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(lineage_artifact_from_raw(row)?);
        }
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }

    /// `DeclaredScope` — the node's declared read set: its
    /// `artifact`-kind in-edges unioned with its spec's
    /// `input_artifact_refs`. Each ref element is an object whose
    /// `artifact_id` member is a uuid, or a bare uuid string.
    async fn declared_scope(&self, node_id: WorkflowNodeId) -> Result<Vec<ArtifactId>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let mut seen: HashSet<ArtifactId> = HashSet::new();
        let mut out: Vec<ArtifactId> = Vec::new();

        let rows = sqlx::query_scalar!(
            "SELECT artifact_id FROM central.workflow_edges \
             WHERE dependent_node_id = $1 AND kind = 'artifact' \
             AND artifact_id IS NOT NULL",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: declared scope edges")?;
        for artifact_id in rows.into_iter().flatten() {
            let id = ArtifactId::from_trusted_db_bytes(*artifact_id.as_bytes());
            if seen.insert(id) {
                out.push(id);
            }
        }

        let refs = sqlx::query_scalar!(
            "SELECT input_artifact_refs FROM central.workflow_nodes \
             WHERE id = $1",
            uuid_of(node_id.as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("artifact: declared scope input refs")?;
        if let Some(serde_json::Value::Array(elements)) = refs {
            for element in elements {
                let Some(id) = parse_artifact_ref(&element) else {
                    continue;
                };
                if seen.insert(id) {
                    out.push(id);
                }
            }
        }
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(out)
    }

    /// `RunProducedArtifacts` — the set of artifacts produced inside
    /// the run (the journaled produce edges), used to bound
    /// undeclared-but-authorized reads to in-run artifacts.
    async fn run_produced_artifacts(&self, run_id: RunId) -> Result<Vec<ArtifactId>, Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query_scalar!(
            "SELECT artifact_id FROM central.artifact_produce_edges \
             WHERE run_id = $1",
            uuid_of(run_id.as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: run produced artifacts")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(rows
            .into_iter()
            .map(|id| ArtifactId::from_trusted_db_bytes(*id.as_bytes()))
            .collect())
    }
}

/// `parseArtifactRef` — extracts one artifact uuid from an
/// `input_artifact_refs` element. The declared element shape is an
/// object carrying `artifact_id` (with `artifactId`/`artifactID`/`id`
/// tolerated for spec evolution); a bare uuid string element is also
/// accepted. Anything else is skipped — a malformed ref narrows the
/// declared set, which can only ever produce a stricter denial,
/// never a wider one. Upstream's `uuid.FromString` is version-
/// agnostic; `Uuid::parse_str` matches it exactly.
fn parse_artifact_ref(element: &serde_json::Value) -> Option<ArtifactId> {
    let raw = if let Some(text) = element.as_str() {
        uuid::Uuid::parse_str(text).ok()?
    } else {
        let object = element.as_object()?;
        let mut found = None;
        for key in ["artifact_id", "artifactId", "artifactID", "id"] {
            let Some(value) = object.get(key).and_then(serde_json::Value::as_str) else {
                continue;
            };
            if let Ok(id) = uuid::Uuid::parse_str(value) {
                found = Some(id);
                break;
            }
        }
        found?
    };
    Some(ArtifactId::from_trusted_db_bytes(*raw.as_bytes()))
}
