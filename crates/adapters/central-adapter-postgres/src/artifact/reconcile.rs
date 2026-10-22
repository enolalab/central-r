//! `central-artifact::port::ReconciliationStore` — the port of
//! `internal/adapter/postgres/artifact/store.go`'s fenced
//! reconciliation claim surface (`ClaimIncomplete`, `ClaimLarge`,
//! `RecordLargeClaim`, `ExpireStaging`, `ReleaseLargeClaim`,
//! `ClaimRejectedStaging`, `ClearStagingKey`, `RecordProgress`).
//!
//! Every method opens one bounded transaction through
//! `store_support::begin_tx`. Claims are fenced by
//! `claim_token_hash = sha256(claim_token)` — the raw token never
//! crosses the boundary — and every lease/age comparison is made
//! against database-derived `clock_timestamp()` inside the
//! statement; no caller wall clock participates.
//!
//! SB-G4 `central_runtime` privilege fix (ADR 0028 D3): the b10
//! migration grants `SELECT, INSERT, UPDATE` — not `DELETE` — on
//! `central.artifact_reconciliation_claims` to `central_runtime`, so
//! where upstream `DELETE`s a resolved or released large claim this
//! port *demotes* it: `claim_kind = 'normal'` plus an immediately
//! elapsed lease. `queryLockOldestLargeClaim` (`WHERE claim_kind =
//! 'large'`) can never re-select it, and the normal cursor
//! re-observes and re-defers any still-incomplete artifact on the
//! next cycle — the same liveness the DELETE provided, under the
//! smaller grant.

use std::time::Duration;

use central_artifact::domain::{
    self, FAILURE_CODE_RESERVATION_EXPIRED, FAILURE_CODE_STAGING_EXPIRED, Outcome, OutcomeKind,
    State,
};
use central_artifact::port::{
    ClaimIncompleteRequest, ClaimIncompleteResult, ClaimLargeRequest, ClaimRejectedStagingRequest,
    ClaimRejectedStagingResult, ClearStagingKeyRequest, ExpireStagingRequest, ExpireStagingResult,
    IncompleteClaim, LargeClaim, ReconciliationCursor, ReconciliationProgress, ReconciliationStore,
    RecordLargeClaimRequest, RejectedStagingClaim, ReleaseLargeClaimRequest,
};
use central_foundation::failure::Failure;
use central_foundation::identity::{ArtifactId, WorkspaceId};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

use super::queries::{
    command_receipt_key, fingerprint_mismatch, insert_artifact_receipt, lookup_artifact_receipt,
    read_artifact_for_update, release_capacity_reservation, to_domain_artifact,
};
use super::store::outcome_payload;
use super::{conflict, corrupt, invalid};
use crate::error::{SqlxContext, classify_sqlx};
use crate::execution::{ct_eq, sha256};
use crate::store_support::{begin_tx, usize_as_i64, uuid_of};

use super::Store;

/// `b10IncompleteStates` — every non-terminal B10 lifecycle state in
/// the exact literal form that matches `artifacts_state_expiry_idx`'s
/// partial predicate. Each is scanned separately (one ordered Index
/// Scan per state) so the keyset seek never needs a Sort node.
const B10_INCOMPLETE_STATES: [&str; 3] = ["reserved", "staging", "verifying"];

/// `maxUnparsableWorkspaceSkips` — bounds how many unparseable
/// (non-UUIDv7) workspaces one `claim_incomplete` call walks past
/// before giving up for this cycle (port constant name
/// `MAX_SKIPPED_WORKSPACES_PER_CALL`).
const MAX_SKIPPED_WORKSPACES_PER_CALL: usize = 64;

/// The zero-instant sentinel the reconciler's `zero_cursor()` uses
/// where Go's `time.Time{}` stood: `OffsetDateTime::UNIX_EPOCH`
/// binds SQL NULL, exactly like upstream's `nullTimeValue`.
fn null_time(t: OffsetDateTime) -> Option<OffsetDateTime> {
    (t != OffsetDateTime::UNIX_EPOCH).then_some(t)
}

/// A `std::time::Duration` → `time::Duration` for the
/// `OffsetDateTime` lease arithmetic; an unrepresentable duration is
/// a caller-level invalid request, never a panic.
fn lease_duration(value: Duration, code: &'static str) -> Result<time::Duration, Failure> {
    time::Duration::try_from(value).map_err(|_| invalid(code))
}

/// `queryDBNow` — the database's own clock. Every claim lease and
/// backlog age is measured against this instant, never a process
/// clock.
async fn db_now(tx: &mut Transaction<'_, Postgres>) -> Result<OffsetDateTime, Failure> {
    let row = sqlx::query!("SELECT clock_timestamp() AS \"now!\"")
        .fetch_one(&mut **tx)
        .await
        .ctx("artifact: read database time")?;
    Ok(row.now)
}

/// `commitNonMutating` — closes a transaction that deliberately
/// changed nothing: a stale claim, moved version, or moved state is
/// a non-mutating conflict, indistinguishable from a clean no-op.
async fn commit_non_mutating(
    tx: Transaction<'_, Postgres>,
    operation: &'static str,
) -> Result<(), Failure> {
    tx.commit().await.map_err(|e| {
        let failure = classify_sqlx(&e);
        Failure::new(
            failure.kind(),
            failure.code(),
            format!("{operation}: {}", failure.message()),
        )
    })
}

/// One pass's skip-walk outcome, so "nothing to reconcile" is
/// distinguishable from "gave up before reaching anything
/// reconcilable".
struct WorkspaceSkips {
    count: usize,
    budget_exhausted: bool,
}

/// `resolveReconciliationWorkspace` — the round-robin target
/// workspace for one `claim_incomplete` call: the cursor's own
/// workspace when it still has an incomplete artifact at or after
/// the cursor, else the next workspace (ascending `uuid` order) that
/// has any incomplete artifact at all. `None` means no incomplete
/// artifact exists at or after the cursor — or the bounded skip walk
/// gave up before reaching a parseable one.
async fn resolve_reconciliation_workspace(
    tx: &mut Transaction<'_, Postgres>,
    cursor: ReconciliationCursor,
) -> Result<(Option<WorkspaceId>, WorkspaceSkips), Failure> {
    if !cursor.workspace_id.is_nil() {
        let exists = sqlx::query_scalar!(
            "SELECT EXISTS (\
             SELECT 1 FROM central.artifacts \
             WHERE workspace_id = $1 AND state IN ('reserved', 'staging', 'verifying') \
             AND ($2::timestamptz IS NULL OR created_at > $2::timestamptz)\
             ) AS \"exists!\"",
            uuid_of(cursor.workspace_id.as_bytes()),
            null_time(cursor.created_at),
        )
        .fetch_one(&mut **tx)
        .await
        .ctx("artifact: check workspace incomplete backlog")?;
        if exists {
            return Ok((
                Some(cursor.workspace_id),
                WorkspaceSkips {
                    count: 0,
                    budget_exhausted: false,
                },
            ));
        }
    }

    // Walk forward past workspaces whose durable ID is not a
    // parseable `WorkspaceId` (a non-UUIDv7 uuid). This is a guard,
    // not a fix for an observed defect: no known production path
    // writes such a row, but one could never be reconciled and
    // failing here would starve every workspace sorting behind it.
    // The walk is bounded so a large such population costs one
    // bounded probe per pass instead of an unbounded scan.
    let mut probe: Option<uuid::Uuid> =
        (!cursor.workspace_id.is_nil()).then(|| uuid_of(cursor.workspace_id.as_bytes()));
    let mut skipped = 0usize;
    while skipped < MAX_SKIPPED_WORKSPACES_PER_CALL {
        let row = sqlx::query!(
            "SELECT DISTINCT workspace_id FROM central.artifacts \
             WHERE state IN ('reserved', 'staging', 'verifying') \
             AND ($1::uuid IS NULL OR workspace_id > $1::uuid) \
             ORDER BY workspace_id \
             LIMIT 1",
            probe,
        )
        .fetch_optional(&mut **tx)
        .await
        .ctx("artifact: resolve next incomplete workspace")?;
        let Some(row) = row else {
            return Ok((
                None,
                WorkspaceSkips {
                    count: skipped,
                    budget_exhausted: false,
                },
            ));
        };
        // The raw value is a well-formed uuid (the column type
        // guarantees it), just possibly not a UUIDv7 — safe as a seek
        // position and never surfaced to a caller, event, or log.
        if let Ok(workspace) = WorkspaceId::parse(&row.workspace_id.to_string()) {
            return Ok((
                Some(workspace),
                WorkspaceSkips {
                    count: skipped,
                    budget_exhausted: false,
                },
            ));
        }
        probe = Some(row.workspace_id);
        skipped += 1;
    }
    // Skip budget exhausted: report no target rather than an error —
    // nothing durable is poisoned — but flag the give-up so it is
    // never mistaken for an empty backlog.
    Ok((
        None,
        WorkspaceSkips {
            count: skipped,
            budget_exhausted: true,
        },
    ))
}

/// `holdsActiveReconciliationClaim` — rereads the artifact's claim
/// row under a row lock and reports whether the caller's own token
/// is still the active claim. An absent row, a different token, or
/// an expired lease all mean the caller no longer holds the claim —
/// a non-mutating conflict, never an error. The hash comparison is
/// constant-time; the raw token is never bound to a statement.
async fn holds_active_reconciliation_claim(
    tx: &mut Transaction<'_, Postgres>,
    workspace_id: WorkspaceId,
    artifact_id: ArtifactId,
    claim_token: &[u8],
) -> Result<bool, Failure> {
    let row = sqlx::query!(
        "SELECT claim_token_hash, lease_expires_at > clock_timestamp() AS \"live!\" \
         FROM central.artifact_reconciliation_claims \
         WHERE workspace_id = $1 AND artifact_id = $2 \
         FOR UPDATE",
        uuid_of(workspace_id.as_bytes()),
        uuid_of(artifact_id.as_bytes()),
    )
    .fetch_optional(&mut **tx)
    .await
    .ctx("artifact: lock active reconciliation claim")?;
    let Some(row) = row else {
        return Ok(false);
    };
    if !row.live {
        return Ok(false);
    }
    let token_hash = sha256(claim_token);
    Ok(ct_eq(&row.claim_token_hash, &token_hash))
}

/// The `ExpireStagingResult` zero value for every non-mutating
/// conflict path — upstream's `port.ExpireStagingResult{}` (`Expired:
/// false`, empty `Outcome`).
fn expire_noop() -> ExpireStagingResult {
    ExpireStagingResult {
        expired: false,
        outcome: Outcome {
            kind: OutcomeKind::Retryable,
            failure_code: String::new(),
        },
    }
}

impl ReconciliationStore for Store {
    /// `ClaimIncomplete` — one bounded claim sweep over incomplete
    /// artifacts. The pass round-robins workspaces: exactly one
    /// target workspace is resolved per call so each per-state scan
    /// below is a pure equality-plus-range Index Scan on
    /// `artifacts_state_expiry_idx` (workspace_id, state, created_at)
    /// with no Sort.
    async fn claim_incomplete(
        &self,
        request: ClaimIncompleteRequest,
    ) -> Result<ClaimIncompleteResult, Failure> {
        if request.batch_size == 0
            || request.claim_token.is_empty()
            || request.lease_duration.is_zero()
            || request.coordinator_generation <= 0
        {
            return Err(invalid("INVALID_CLAIM_REQUEST"));
        }
        let mut tx = begin_tx(&self.pool).await?;
        let token_hash = sha256(&request.claim_token);
        let now = db_now(&mut tx).await?;

        let (target, skips) = resolve_reconciliation_workspace(&mut tx, request.cursor).await?;
        let mut next = request.cursor;
        let Some(target_workspace) = target else {
            // No incomplete artifact anywhere at or after the cursor.
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(ClaimIncompleteResult {
                claims: Vec::new(),
                next_cursor: next,
                observed_at: now,
                skipped_workspaces: skips.count,
                skip_budget_exhausted: skips.budget_exhausted,
            });
        };

        let cursor_created_at = (target_workspace == request.cursor.workspace_id)
            .then(|| null_time(request.cursor.created_at))
            .flatten();

        struct Candidate {
            artifact: uuid::Uuid,
            state: State,
            created_at: OffsetDateTime,
        }

        // Scan once per literal incomplete state (never a
        // parameterized IN-list) so the WHERE clause exactly matches
        // the partial index predicate. Upstream binds the remaining
        // budget per state but never decrements it inside the loop —
        // the post-merge sort + truncate bounds the batch — so each
        // state's scan is `LIMIT batch_size`.
        let mut candidates: Vec<Candidate> = Vec::new();
        let remaining = request.batch_size;
        for state in B10_INCOMPLETE_STATES {
            if remaining == 0 {
                break;
            }
            let rows = sqlx::query!(
                "SELECT id, created_at FROM central.artifacts \
                 WHERE workspace_id = $1 AND state = $2 \
                 AND ($3::timestamptz IS NULL OR created_at > $3::timestamptz) \
                 ORDER BY created_at \
                 LIMIT $4",
                uuid_of(target_workspace.as_bytes()),
                state,
                cursor_created_at,
                usize_as_i64(remaining),
            )
            .fetch_all(&mut *tx)
            .await
            .ctx("artifact: scan incomplete artifacts")?;
            let state = State::parse(state)
                .ok_or_else(|| corrupt("an artifacts.state literal was mistyped"))?;
            candidates.extend(rows.into_iter().map(|row| Candidate {
                artifact: row.id,
                state,
                created_at: row.created_at,
            }));
        }

        // Merge the (at most three, one per state) already-ordered
        // candidate streams into one created_at order within this
        // workspace. Upstream's `artifactID.String()` tiebreak is
        // uuid byte order — identical to `Uuid`'s own `Ord`.
        candidates.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.artifact.cmp(&b.artifact))
        });
        candidates.truncate(request.batch_size);

        let lease = lease_duration(request.lease_duration, "INVALID_CLAIM_REQUEST")?;
        let lease_expires_at = now
            .checked_add(lease)
            .ok_or_else(|| invalid("INVALID_CLAIM_REQUEST"))?;

        let mut claims = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let current_lease = sqlx::query_scalar!(
                "SELECT lease_expires_at FROM central.artifact_reconciliation_claims \
                 WHERE workspace_id = $1 AND artifact_id = $2 FOR UPDATE",
                uuid_of(target_workspace.as_bytes()),
                candidate.artifact,
            )
            .fetch_optional(&mut *tx)
            .await
            .ctx("artifact: lock reconciliation claim")?;
            let artifact_id = ArtifactId::parse(&candidate.artifact.to_string())
                .map_err(|_| corrupt("an artifacts.id is not a UUIDv7"))?;
            if let Some(current_lease) = current_lease
                && current_lease > now
            {
                // An active claim fences out a second claimant; skip
                // without mutating the existing lease, but still
                // advance the cursor past the scanned row.
                next = ReconciliationCursor {
                    workspace_id: target_workspace,
                    created_at: candidate.created_at,
                    artifact_id,
                };
                continue;
            }
            sqlx::query!(
                "INSERT INTO central.artifact_reconciliation_claims (\
                 artifact_id, workspace_id, claim_kind, coordinator_generation, \
                 claim_token_hash, lease_expires_at, attempt_count, created_at, updated_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, 1, clock_timestamp(), clock_timestamp()) \
                 ON CONFLICT (artifact_id) DO UPDATE SET \
                 claim_kind = EXCLUDED.claim_kind, \
                 coordinator_generation = EXCLUDED.coordinator_generation, \
                 claim_token_hash = EXCLUDED.claim_token_hash, \
                 lease_expires_at = EXCLUDED.lease_expires_at, \
                 attempt_count = central.artifact_reconciliation_claims.attempt_count + 1, \
                 updated_at = clock_timestamp()",
                candidate.artifact,
                uuid_of(target_workspace.as_bytes()),
                "normal",
                request.coordinator_generation,
                &token_hash[..],
                lease_expires_at,
            )
            .execute(&mut *tx)
            .await
            .ctx("artifact: upsert reconciliation claim")?;
            claims.push(IncompleteClaim {
                artifact_id,
                workspace_id: target_workspace,
                state: Some(candidate.state),
                lease_expires_at,
                created_at: candidate.created_at,
            });
            next = ReconciliationCursor {
                workspace_id: target_workspace,
                created_at: candidate.created_at,
                artifact_id,
            };
        }

        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        // `observed_at` is database-derived, so every backlog age the
        // caller computes from these claims is measured against the
        // database clock, never a process one.
        Ok(ClaimIncompleteResult {
            claims,
            next_cursor: next,
            observed_at: now,
            skipped_workspaces: skips.count,
            skip_budget_exhausted: skips.budget_exhausted,
        })
    }

    /// `ClaimLarge` — claims the one durable dedicated large-artifact
    /// claim currently eligible, if any. Resolved claims are demoted
    /// (not deleted — SB-G4) before looking for work so a stale row
    /// can never starve the pass.
    async fn claim_large(&self, request: ClaimLargeRequest) -> Result<Option<LargeClaim>, Failure> {
        if request.claim_token.is_empty() || request.lease_duration.is_zero() {
            return Err(invalid("INVALID_CLAIM_REQUEST"));
        }
        let mut tx = begin_tx(&self.pool).await?;
        let now = db_now(&mut tx).await?;

        // SB-G4 `central_runtime` privilege fix — upstream's
        // `queryDeleteResolvedLargeClaims` DELETE requires a grant
        // `central_runtime` does not hold. This UPDATE demotion needs
        // only the granted UPDATE privilege and leaves the row
        // immediately re-eligible for the normal cursor to
        // re-observe and re-defer a still-incomplete artifact.
        sqlx::query!(
            "UPDATE central.artifact_reconciliation_claims c \
             SET claim_kind = 'normal', lease_expires_at = clock_timestamp(), \
             updated_at = clock_timestamp() \
             WHERE c.claim_kind = 'large' \
             AND NOT EXISTS (\
             SELECT 1 FROM central.artifacts a \
             WHERE a.workspace_id = c.workspace_id AND a.id = c.artifact_id \
             AND a.state NOT IN ('ready', 'rejected')\
             )",
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: demote resolved large claims")?;

        // Only ever returns a claim whose artifact is still
        // genuinely incomplete: a resolved record can never be
        // re-claimed even if the demotion above has not run yet.
        let row = sqlx::query!(
            "SELECT c.workspace_id, c.artifact_id, c.lease_expires_at \
             FROM central.artifact_reconciliation_claims c \
             JOIN central.artifacts a \
             ON a.workspace_id = c.workspace_id AND a.id = c.artifact_id \
             WHERE c.claim_kind = 'large' AND c.lease_expires_at <= $1 \
             AND (c.next_eligible_at IS NULL OR c.next_eligible_at <= $1) \
             AND a.state NOT IN ('ready', 'rejected') \
             ORDER BY c.updated_at \
             LIMIT 1 \
             FOR UPDATE OF c SKIP LOCKED",
            now,
        )
        .fetch_optional(&mut *tx)
        .await
        .ctx("artifact: lock oldest large claim")?;
        let Some(row) = row else {
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(None);
        };
        let workspace_id = WorkspaceId::parse(&row.workspace_id.to_string()).map_err(|_| {
            corrupt("an artifact_reconciliation_claims.workspace_id is not a UUIDv7")
        })?;
        let artifact_id = ArtifactId::parse(&row.artifact_id.to_string()).map_err(|_| {
            corrupt("an artifact_reconciliation_claims.artifact_id is not a UUIDv7")
        })?;

        let token_hash = sha256(&request.claim_token);
        let lease = lease_duration(request.lease_duration, "INVALID_CLAIM_REQUEST")?;
        let new_lease = now
            .checked_add(lease)
            .ok_or_else(|| invalid("INVALID_CLAIM_REQUEST"))?;
        sqlx::query!(
            "UPDATE central.artifact_reconciliation_claims \
             SET claim_token_hash = $3, lease_expires_at = $4, \
             attempt_count = attempt_count + 1, updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND artifact_id = $2",
            row.workspace_id,
            row.artifact_id,
            &token_hash[..],
            new_lease,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: update large claim lease")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(Some(LargeClaim {
            artifact_id,
            workspace_id,
            lease_expires_at: new_lease,
        }))
    }

    /// `RecordProgress` — journals the pass's scan position.
    /// `central.artifact_reconciliation_progress` (v14) has no
    /// processed-count column: `processed_count` is accepted for
    /// port conformance but has no durable slot to persist into.
    async fn record_progress(&self, progress: ReconciliationProgress) -> Result<(), Failure> {
        let mut tx = begin_tx(&self.pool).await?;
        // The progress cursor_check constraint requires the three
        // cursor columns all-NULL or all-present; a nil workspace
        // means "no cursor".
        let (cursor_workspace, cursor_created_at, cursor_artifact) =
            if progress.cursor.workspace_id.is_nil() {
                (None, None, None)
            } else {
                (
                    Some(uuid_of(progress.cursor.workspace_id.as_bytes())),
                    Some(progress.cursor.created_at),
                    Some(uuid_of(progress.cursor.artifact_id.as_bytes())),
                )
            };
        sqlx::query!(
            "UPDATE central.artifact_reconciliation_progress \
             SET cursor_workspace_id = $1, cursor_created_at = $2, cursor_artifact_id = $3, \
             last_progress_at = clock_timestamp(), version = version + 1, cycle = $4 \
             WHERE singleton = true",
            cursor_workspace,
            cursor_created_at,
            cursor_artifact,
            progress.cycle,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: update reconciliation progress")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(())
    }

    /// `RecordLargeClaim` — records the durable dedicated
    /// large-artifact claim for one candidate the deferring pass
    /// could not afford. The claim table is keyed by `artifact_id`,
    /// so the upsert re-declares the same deferral rather than
    /// creating a second row — safe to call repeatedly. A record
    /// that moved under the claim, or a claim the caller no longer
    /// holds, is a non-mutating conflict.
    async fn record_large_claim(&self, request: RecordLargeClaimRequest) -> Result<(), Failure> {
        if request.workspace_id.is_nil()
            || request.artifact_id.is_nil()
            || request.claim_token.is_empty()
            || request.coordinator_generation <= 0
        {
            return Err(invalid("INVALID_CLAIM_REQUEST"));
        }
        let mut tx = begin_tx(&self.pool).await?;
        if !holds_active_reconciliation_claim(
            &mut tx,
            request.workspace_id,
            request.artifact_id,
            &request.claim_token,
        )
        .await?
        {
            return commit_non_mutating(tx, "commit record large claim (stale claim)").await;
        }
        let row =
            read_artifact_for_update(&mut tx, request.workspace_id, request.artifact_id).await?;
        if request.expected_version > 0 && row.version != request.expected_version {
            return commit_non_mutating(tx, "commit record large claim (version moved)").await;
        }

        // lease_expires_at is set to database-derived now rather
        // than a future lease: the deferring pass is explicitly not
        // doing this work, so the claim must be immediately eligible
        // for `claim_large` on a later pass. `attempt_count` is
        // deliberately not bumped — deferring is a declaration, not
        // a reconciliation attempt.
        let token_hash = sha256(&request.claim_token);
        sqlx::query!(
            "INSERT INTO central.artifact_reconciliation_claims (\
             artifact_id, workspace_id, claim_kind, coordinator_generation, \
             claim_token_hash, lease_expires_at, attempt_count, created_at, updated_at\
             ) VALUES ($1, $2, 'large', $3, $4, clock_timestamp(), 1, clock_timestamp(), \
             clock_timestamp()) \
             ON CONFLICT (artifact_id) DO UPDATE SET \
             claim_kind = 'large', \
             coordinator_generation = EXCLUDED.coordinator_generation, \
             claim_token_hash = EXCLUDED.claim_token_hash, \
             lease_expires_at = clock_timestamp(), \
             updated_at = clock_timestamp()",
            uuid_of(request.artifact_id.as_bytes()),
            uuid_of(request.workspace_id.as_bytes()),
            request.coordinator_generation,
            &token_hash[..],
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: record large claim")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(())
    }

    /// `ExpireStaging` — the staging-lifetime expiry transition. The
    /// age comparison is made by PostgreSQL against database-derived
    /// time inside the statement; no caller clock participates. Every
    /// failed guard — claim, version, state, age — is a non-mutating
    /// conflict reported as `expired: false` with an `Ok` result, so
    /// a single unlucky item never aborts a bounded pass.
    async fn expire_staging(
        &self,
        request: ExpireStagingRequest,
    ) -> Result<ExpireStagingResult, Failure> {
        if request.workspace_id.is_nil()
            || request.artifact_id.is_nil()
            || request.claim_token.is_empty()
            || request.lifetime.is_zero()
        {
            return Err(invalid("INVALID_EXPIRE_REQUEST"));
        }
        let mut tx = begin_tx(&self.pool).await?;
        if !holds_active_reconciliation_claim(
            &mut tx,
            request.workspace_id,
            request.artifact_id,
            &request.claim_token,
        )
        .await?
        {
            commit_non_mutating(tx, "commit expire staging (stale claim)").await?;
            return Ok(expire_noop());
        }
        let row =
            read_artifact_for_update(&mut tx, request.workspace_id, request.artifact_id).await?;
        if row.version != request.expected_version {
            commit_non_mutating(tx, "commit expire staging (version moved)").await?;
            return Ok(expire_noop());
        }
        // Only a reserved record with no begun upload and a staging
        // record with no active claim expire. A verifying record is
        // finalizable and a ready/rejected one is terminal: none of
        // them are touched here.
        if row.state != State::Reserved && row.state != State::Staging {
            commit_non_mutating(tx, "commit expire staging (state moved)").await?;
            return Ok(expire_noop());
        }

        // The age comparison is made inside PostgreSQL against
        // database-derived time; no caller clock participates in the
        // decision.
        let outlived = sqlx::query_scalar!(
            "SELECT created_at < clock_timestamp() - make_interval(secs => $3::double precision) \
             FROM central.artifacts \
             WHERE workspace_id = $1 AND id = $2",
            uuid_of(request.workspace_id.as_bytes()),
            uuid_of(request.artifact_id.as_bytes()),
            request.lifetime.as_secs_f64(),
        )
        .fetch_one(&mut *tx)
        .await
        .ctx("artifact: compare artifact staging lifetime")?
        .unwrap_or(false);
        if !outlived {
            commit_non_mutating(tx, "commit expire staging (within lifetime)").await?;
            return Ok(expire_noop());
        }

        let current = to_domain_artifact(&row);
        let reason = if current.state == State::Reserved {
            FAILURE_CODE_RESERVATION_EXPIRED
        } else {
            FAILURE_CODE_STAGING_EXPIRED
        };
        let rejected = domain::reject(&domain::RejectInput {
            workspace_id: current.workspace_id,
            artifact_id: current.artifact_id,
            current,
            expected: row.version,
            reason,
        })?;

        let (key, fingerprint) = command_receipt_key(&rejected.identity);
        let existing =
            lookup_artifact_receipt(&mut tx, request.workspace_id, "reject", &key).await?;
        if existing.found {
            if existing.fingerprint != fingerprint {
                return Err(fingerprint_mismatch());
            }
            // The transition already committed under this exact
            // identity. Report it as expired so the caller's own
            // idempotent staging cleanup still runs, but apply
            // nothing again.
            tx.commit().await.map_err(|e| classify_sqlx(&e))?;
            return Ok(ExpireStagingResult {
                expired: true,
                outcome: rejected.outcome,
            });
        }

        // `applyRejection` — the version guard makes the rejection,
        // and therefore the single capacity release paired with it,
        // exactly-once; the state predicate is defence in depth.
        let rejection = serde_json::json!({"code": reason});
        let done = sqlx::query!(
            "UPDATE central.artifacts \
             SET version = $3, state = 'rejected', rejection = $4::jsonb, \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND version = $5 \
             AND state IN ('reserved', 'staging')",
            uuid_of(request.workspace_id.as_bytes()),
            uuid_of(request.artifact_id.as_bytes()),
            rejected.artifact.version,
            rejection,
            row.version,
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: reject artifact")?
        .rows_affected();
        if done != 1 {
            return Err(conflict("VERSION_CONFLICT"));
        }
        release_capacity_reservation(&mut tx, request.workspace_id, request.artifact_id).await?;
        insert_artifact_receipt(
            &mut tx,
            request.workspace_id,
            request.artifact_id,
            "reject",
            &key,
            fingerprint,
            outcome_payload(&rejected.outcome),
        )
        .await?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(ExpireStagingResult {
            expired: true,
            outcome: rejected.outcome,
        })
    }

    /// `ReleaseLargeClaim` — demotes (SB-G4, never deletes) the
    /// dedicated large-artifact claim the calling pass just
    /// processed. Deliberately unconditional on the artifact's
    /// resulting state: the dedicated worker has had its turn either
    /// way, and an artifact that still needs work is re-observed by
    /// the normal cursor and re-deferred. Idempotent — an
    /// already-demoted or absent row is a success.
    async fn release_large_claim(&self, request: ReleaseLargeClaimRequest) -> Result<(), Failure> {
        if request.workspace_id.is_nil()
            || request.artifact_id.is_nil()
            || request.claim_token.is_empty()
        {
            return Err(invalid("INVALID_CLAIM_REQUEST"));
        }
        let mut tx = begin_tx(&self.pool).await?;
        // SB-G4 `central_runtime` privilege fix — upstream's
        // `queryDeleteLargeClaim` DELETE requires a grant
        // `central_runtime` does not hold. Demoting to `claim_kind =
        // 'normal'` with an elapsed lease removes the row from
        // `queryLockOldestLargeClaim`'s predicate permanently while
        // leaving the normal claim lifecycle intact.
        sqlx::query!(
            "UPDATE central.artifact_reconciliation_claims \
             SET claim_kind = 'normal', lease_expires_at = clock_timestamp(), \
             updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND artifact_id = $2 AND claim_kind = 'large'",
            uuid_of(request.workspace_id.as_bytes()),
            uuid_of(request.artifact_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: release large claim")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(())
    }

    /// `ClaimRejectedStaging` — rejected artifacts that still carry
    /// an unremoved staging object. Applies no transition and takes
    /// no lock: the only mutation this cleanup performs is
    /// `clear_staging_key`, which revalidates the record's state
    /// itself. The WHERE clause matches
    /// `artifacts_workspace_staging_key_unique_idx`'s partial
    /// predicate and its ORDER BY the index's own column order, so
    /// the bounded scan needs no Sort node; cleared records leave
    /// the predicate permanently, so successive passes drain rather
    /// than rescan.
    async fn claim_rejected_staging(
        &self,
        request: ClaimRejectedStagingRequest,
    ) -> Result<ClaimRejectedStagingResult, Failure> {
        if request.batch_size == 0 || request.claim_token.is_empty() {
            return Err(invalid("INVALID_CLAIM_REQUEST"));
        }
        let mut tx = begin_tx(&self.pool).await?;
        let rows = sqlx::query!(
            "SELECT workspace_id, id, staging_key FROM central.artifacts \
             WHERE staging_key IS NOT NULL AND state = 'rejected' \
             ORDER BY workspace_id, staging_key \
             LIMIT $1",
            usize_as_i64(request.batch_size),
        )
        .fetch_all(&mut *tx)
        .await
        .ctx("artifact: scan rejected staging")?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let workspace_id = WorkspaceId::parse(&row.workspace_id.to_string())
                .map_err(|_| corrupt("an artifacts.workspace_id is not a UUIDv7"))?;
            let artifact_id = ArtifactId::parse(&row.id.to_string())
                .map_err(|_| corrupt("an artifacts.id is not a UUIDv7"))?;
            let staging_key = row
                .staging_key
                .ok_or_else(|| corrupt("a rejected staging claim carried no staging_key"))?;
            claims.push(RejectedStagingClaim {
                workspace_id,
                artifact_id,
                staging_key,
            });
        }
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(ClaimRejectedStagingResult { claims })
    }

    /// `ClearStagingKey` — records that a rejected artifact's staging
    /// object has been removed. The statement's own state predicate
    /// is the safety boundary: only a rejected record's staging-role
    /// key is ever cleared, and no ready-key column is touched by any
    /// code path here. A non-rejected record, or one whose key is
    /// already cleared, is a non-mutating conflict rather than an
    /// error.
    async fn clear_staging_key(&self, request: ClearStagingKeyRequest) -> Result<(), Failure> {
        if request.workspace_id.is_nil()
            || request.artifact_id.is_nil()
            || request.claim_token.is_empty()
        {
            return Err(invalid("INVALID_CLAIM_REQUEST"));
        }
        let mut tx = begin_tx(&self.pool).await?;
        sqlx::query!(
            "UPDATE central.artifacts \
             SET staging_key = NULL, updated_at = clock_timestamp() \
             WHERE workspace_id = $1 AND id = $2 AND state = 'rejected' \
             AND staging_key IS NOT NULL",
            uuid_of(request.workspace_id.as_bytes()),
            uuid_of(request.artifact_id.as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .ctx("artifact: clear staging key")?;
        tx.commit().await.map_err(|e| classify_sqlx(&e))?;
        Ok(())
    }
}
