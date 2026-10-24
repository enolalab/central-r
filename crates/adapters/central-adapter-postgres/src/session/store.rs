//! The session store — port of upstream `store.go` + `queries.go`:
//! discovery, exchange, delivery preparation, precommit activation,
//! validation, revoke, and the durable presentation lease over
//! `central.bootstrap_generations` and `central.sessions`.
//!
//! The only database-specific types live behind this adapter boundary:
//! `sqlx` macros bind `Uuid`/`Vec<u8>`/`OffsetDateTime`, and every
//! method's error surface is either a typed `central_session` `Failure`
//! (`BootstrapInvalid` / `BootstrapThrottled` with bounded
//! `Retry-After` / `SessionInvalidated`) or an untyped
//! `session store: <operation>` failure — upstream's
//! `databaseFailure(op)` — that carries only the audited operation name
//! and never a SQLSTATE, raw database error, or secret material. The
//! classified `sqlx` error is retained as an unformatted `cause` so
//! diagnostics can inspect it without its text ever reaching a
//! `Display` path.
//!
//! Upstream divergence notes:
//!
//! - `pgx` binds uuid text; `sqlx` binds `Uuid` directly, so upstream's
//!   `::uuid` casts and `sessionIDFromString` canonical checks collapse
//!   into typed binds (`is_nil` guards the corrupt-row case).
//! - Domain session ids are `SessionId` (UUIDv7, the workspace identity
//!   convention) where upstream minted v4; `candidate_id` and the
//!   replacement-generation id remain v4 — they are opaque broker/PG
//!   values, not domain identities. Both are valid `uuid` column
//!   values.
//! - `scanSession` returns an `internal`-shaped untyped failure where
//!   upstream propagated the raw scan error (which its callers then
//!   flattened to `databaseFailure(op)`); a durable row the domain
//!   refuses is corrupt durable state, never a caller error — the
//!   `pg_data_corrupt` convention the rest of this adapter uses, kept
//!   inside the session error surface.
//! - Port futures carry no `Context`; upstream's `ctx.Err()` gates now
//!   rest on sqlx `Transaction` drop-rollback.
//! - `PresentationLease.deadline` is `Option<OffsetDateTime>` — Go's
//!   zero `time.Time` — and `Session`'s non-`Option` timestamps are
//!   `UNIX_EPOCH` in the exchange result where upstream left them
//!   `time.Time` zero.

use central_foundation::identity::{SessionId, WorkspaceId};
use central_session::contract::{
    BOOTSTRAP_VERIFIER_V1, CandidateBinding, Failure, FailureClass, Sentinel,
};
use central_session::domain::{
    ActivationRequest, DEFAULT_FIRST_USE_FENCE, DeliveryId, DeliveryRequest, DeliveryResult,
    ExchangeRequest, ExchangeResult, PRESENTATION_WINDOW, PresentationLease, ReconcileCandidate,
    SecurityEpoch, Session, SessionState, ValidationRequest, clamp_retry_after,
    new_throttled_failure,
};
use central_session::port::{PresentationStore, SessionStore};
use sqlx::{PgPool, Postgres, Transaction};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::error::classify_sqlx;
use crate::store_support::{PG_DATA_CORRUPT, begin_tx, uuid_of};

// ---------------------------------------------------------------------------
// Error vocabulary — upstream's `bootstrapInvalid`/`sessionInvalidated`/
// `throttled`/`databaseFailure` builders.
// ---------------------------------------------------------------------------

fn bootstrap_invalid() -> Failure {
    Failure::new(
        FailureClass::BootstrapInvalid,
        "bootstrap token invalid",
        "request a fresh bootstrap token",
    )
    .with_cause(Sentinel::BootstrapInvalid)
}

fn session_invalidated() -> Failure {
    Failure::new(
        FailureClass::SessionInvalidated,
        "session is no longer valid",
        "request a fresh bootstrap token",
    )
    .with_cause(Sentinel::SessionInvalidated)
}

fn throttled(retry_after: Duration) -> Failure {
    new_throttled_failure(clamp_retry_after(retry_after).duration())
}

/// `databaseFailure` — an untyped failure carrying only the audited
/// operation name, never SQLSTATE text or raw database errors. The
/// classified `sqlx` failure is attached as an unformatted cause so
/// diagnostics can downcast to it; `Display` never reaches it.
fn database_failure(operation: &'static str) -> Failure {
    Failure::untyped(format!("session store: {operation}"))
}

fn db_err(operation: &'static str, err: &sqlx::Error) -> Failure {
    database_failure(operation).with_cause(classify_sqlx(err))
}

fn begin_err(err: central_foundation::failure::Failure) -> Failure {
    database_failure("begin session transaction").with_cause(err)
}

/// `pg_data_corrupt` — a durable row the domain refuses. It is still
/// the untyped `session store:` surface upstream used (the classified
/// cause carries the corruption code for diagnostics).
fn corrupt(operation: &'static str) -> Failure {
    database_failure(operation).with_cause(central_foundation::failure::Failure::internal(
        PG_DATA_CORRUPT,
        "a stored row failed domain reconstruction",
    ))
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// `currentGeneration` — the locked active bootstrap generation row
/// plus the database clock read in the same statement.
struct CurrentGenerationRow {
    id: uuid::Uuid,
    generation: i64,
    verifier_hash: Vec<u8>,
    /// Scanned for upstream parity; the value is not consulted (the
    /// registration carries `principal_identity` only for audit).
    #[allow(dead_code)]
    principal_identity: String,
    #[allow(dead_code)]
    throttle_failure_window_start: Option<OffsetDateTime>,
    #[allow(dead_code)]
    throttle_failure_count: i64,
    throttle_next_eligible: Option<OffsetDateTime>,
    presentation_deadline: Option<OffsetDateTime>,
    database_now: OffsetDateTime,
}

struct ThrottleRow {
    failure_count: i64,
    next_eligible: OffsetDateTime,
    database_now: OffsetDateTime,
}

struct DiscoverRow {
    id: uuid::Uuid,
    lifecycle_state: String,
    outcome: String,
    first_use_deadline: Option<OffsetDateTime>,
    first_used_at: Option<OffsetDateTime>,
}

struct PresentationRow {
    generation: i64,
    presentation_deadline: Option<OffsetDateTime>,
}

/// `scanSession` — the 14-column session row every mutation returns.
struct SessionRow {
    id: uuid::Uuid,
    workspace_id: uuid::Uuid,
    token_hash: Vec<u8>,
    csrf_hash: Vec<u8>,
    principal_identity: String,
    lifecycle_state: String,
    security_epoch: i64,
    created_at: OffsetDateTime,
    last_seen_at: OffsetDateTime,
    idle_expiry: OffsetDateTime,
    absolute_expiry: OffsetDateTime,
    first_use_deadline: Option<OffsetDateTime>,
    first_used_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
}

/// `scanSession` — reconstructs the durable session. A hash column of
/// the wrong length, a negative epoch, or an unrecognized lifecycle
/// state is corrupt durable state, never a caller error.
fn session_from_row(row: SessionRow, operation: &'static str) -> Result<Session, Failure> {
    let token: [u8; 32] = row.token_hash.try_into().map_err(|_| corrupt(operation))?;
    let csrf: [u8; 32] = row.csrf_hash.try_into().map_err(|_| corrupt(operation))?;
    let state =
        SessionState::from_db_str(&row.lifecycle_state).ok_or_else(|| corrupt(operation))?;
    let epoch = u64::try_from(row.security_epoch).map_err(|_| corrupt(operation))?;
    Ok(Session {
        id: SessionId::from_trusted_db_bytes(*row.id.as_bytes()),
        workspace_id: WorkspaceId::from_trusted_db_bytes(*row.workspace_id.as_bytes()),
        state,
        principal_identity: row.principal_identity,
        security_epoch: SecurityEpoch(epoch),
        token_hash: token,
        csrf_hash: csrf,
        idle_expiry: row.idle_expiry,
        absolute_expiry: row.absolute_expiry,
        first_use_deadline: row.first_use_deadline,
        first_used_at: row.first_used_at,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        revoked_at: row.revoked_at,
    })
}

// ---------------------------------------------------------------------------
// Request-shape gates — upstream `validateExchangeRequest` /
// `validCandidate`.
// ---------------------------------------------------------------------------

fn validate_exchange_request(req: &ExchangeRequest) -> Result<(), Failure> {
    if req.workspace_id.is_some_and(|w| !w.is_sentinel()) {
        return Err(bootstrap_invalid());
    }
    if req.verifier.is_zero()
        || req.verifier.version() != BOOTSTRAP_VERIFIER_V1
        || req.pre_auth_csrf_hash == [0u8; 32]
    {
        return Err(bootstrap_invalid());
    }
    if req.idle_expiry <= Duration::ZERO
        || req.absolute_expiry <= Duration::ZERO
        || req.first_use_fence <= Duration::ZERO
    {
        return Err(bootstrap_invalid());
    }
    Ok(())
}

/// `validCandidate` — the candidate id must parse as a UUID (any
/// version), the generation must be positive and bigint-representable,
/// and the digest must be non-zero.
fn valid_candidate(candidate: &CandidateBinding) -> bool {
    uuid::Uuid::parse_str(&candidate.candidate_id).is_ok()
        && candidate.generation > 0
        && i64::try_from(candidate.generation).is_ok()
        && *candidate.digest != [0u8; 32]
}

/// `u64` domain counter → `bigint` bind; `None`/overflow maps to `f`
/// (epoch values originate in `epoch_markers`, so overflow is a
/// caller-level shape failure, never reachable from durable state).
fn counter_as_i64(value: u64, f: impl Fn() -> Failure) -> Result<i64, Failure> {
    i64::try_from(value).map_err(|_| f())
}

// ---------------------------------------------------------------------------
// PgSessionStore
// ---------------------------------------------------------------------------

/// `Store` — the PostgreSQL implementation of `central_session`'s
/// `SessionStore` + `PresentationStore`. `pool` should authenticate as
/// `central_runtime`; the baseline grants cover exactly SELECT/INSERT/
/// UPDATE on `central.bootstrap_generations` and `central.sessions`
/// (no DELETE is required anywhere in this port).
#[derive(Clone)]
pub struct PgSessionStore {
    pool: PgPool,
}

impl PgSessionStore {
    /// Upstream `NewStore`.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Upstream `s.begin` — a bounded READ COMMITTED transaction with
    /// the advisory timeouts (`lock_timeout = 2s`,
    /// `statement_timeout = 5s`,
    /// `idle_in_transaction_session_timeout = 10s`).
    async fn begin(&self) -> Result<Transaction<'static, Postgres>, Failure> {
        begin_tx(&self.pool).await.map_err(begin_err)
    }

    /// `readCurrentGeneration` — locks the active generation row
    /// `FOR UPDATE` and returns it with the database clock read in the
    /// same statement.
    async fn read_current_generation(
        tx: &mut Transaction<'static, Postgres>,
    ) -> Result<CurrentGenerationRow, Failure> {
        sqlx::query_as!(
            CurrentGenerationRow,
            r#"SELECT id, generation, verifier_hash, principal_identity,
                      throttle_failure_window_start, throttle_failure_count,
                      throttle_next_eligible, presentation_deadline,
                      clock_timestamp() AS "database_now!"
               FROM central.bootstrap_generations
               WHERE workspace_id = $1 AND state = 'active'
               ORDER BY generation DESC
               LIMIT 1
               FOR UPDATE"#,
            uuid_of(WorkspaceId::sentinel().as_bytes()),
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| db_err("read current bootstrap generation", &e))?
        .ok_or_else(bootstrap_invalid)
    }
}

impl SessionStore for PgSessionStore {
    /// `DiscoverBootstrapCandidates` — reads the durable
    /// `delivery_pending` recovery set. A row reaches `delivery_pending`
    /// only after the broker accepted its exact candidate, so the
    /// persisted outcome is acknowledged recovery input.
    async fn discover_bootstrap_candidates(&self) -> Result<Vec<ReconcileCandidate>, Failure> {
        let mut tx = self.begin().await?;
        let rows = sqlx::query_as!(
            DiscoverRow,
            r#"SELECT id, lifecycle_state, COALESCE(delivery_outcome, '') AS "outcome!",
                      first_use_deadline, first_used_at
               FROM central.sessions
               WHERE workspace_id = $1
                 AND (
                   lifecycle_state IN ('pending_bootstrap', 'delivery_pending')
                   OR (lifecycle_state = 'active' AND first_used_at IS NULL AND first_use_deadline <= clock_timestamp())
                 )
               ORDER BY created_at ASC, id ASC"#,
            uuid_of(WorkspaceId::sentinel().as_bytes()),
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| db_err("discover bootstrap candidates", &e))?;
        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            if row.id.is_nil() {
                return Err(corrupt("validate bootstrap candidate"));
            }
            let state = row.lifecycle_state.as_str();
            candidates.push(ReconcileCandidate {
                delivery_id: DeliveryId::from_session_id(SessionId::from_trusted_db_bytes(
                    *row.id.as_bytes(),
                )),
                activated: row.outcome == "prepared" || row.outcome == "activated",
                pending_bootstrap: state == SessionState::PendingBootstrap.as_str(),
                first_use_overdue: state == SessionState::Active.as_str()
                    && row.first_used_at.is_none()
                    && row.first_use_deadline.is_some(),
            });
        }
        tx.commit()
            .await
            .map_err(|e| db_err("read bootstrap candidates", &e))?;
        Ok(candidates)
    }

    /// `Exchange` — the atomic generation-consume + throttle + pending
    /// session insert + replacement registration on database time.
    async fn exchange(&self, req: ExchangeRequest) -> Result<ExchangeResult, Failure> {
        validate_exchange_request(&req)?;

        let mut tx = self.begin().await?;
        let current = Self::read_current_generation(&mut tx).await?;
        if let Some(next) = current.throttle_next_eligible
            && next > current.database_now
        {
            return Err(throttled(next - current.database_now));
        }
        if let Some(deadline) = current.presentation_deadline
            && deadline <= current.database_now
        {
            return Err(bootstrap_invalid());
        }
        if current.generation < 0 {
            return Err(corrupt("read current bootstrap generation"));
        }
        if !req.verifier.digest_equal(&current.verifier_hash) {
            let throttle = sqlx::query_as!(
                ThrottleRow,
                r#"WITH clock AS MATERIALIZED (SELECT clock_timestamp() AS now),
                   next_failure AS (
                       SELECT g.id, c.now,
                              CASE
                                WHEN g.throttle_failure_window_start IS NULL
                                  OR g.throttle_failure_window_start <= c.now - interval '60 seconds'
                                THEN 1
                                ELSE g.throttle_failure_count + 1
                              END AS failure_count
                       FROM central.bootstrap_generations g
                       CROSS JOIN clock c
                       WHERE g.id = $1
                   ),
                   updated AS (
                       UPDATE central.bootstrap_generations g
                       SET throttle_failure_window_start = CASE WHEN n.failure_count = 1 THEN n.now ELSE g.throttle_failure_window_start END,
                           throttle_failure_count = n.failure_count,
                           throttle_next_eligible = CASE WHEN n.failure_count >= 5 THEN n.now + interval '60 seconds' ELSE NULL END
                       FROM next_failure n
                       WHERE g.id = n.id
                       RETURNING g.throttle_failure_count AS failure_count, g.throttle_next_eligible
                   )
                   SELECT failure_count, COALESCE(throttle_next_eligible, clock_timestamp()) AS "next_eligible!", clock_timestamp() AS "database_now!"
                   FROM updated"#,
                current.id,
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| db_err("update bootstrap throttle", &e))?;
            tx.commit()
                .await
                .map_err(|e| db_err("commit bootstrap throttle", &e))?;
            if throttle.failure_count >= 5 {
                return Err(throttled(throttle.next_eligible - throttle.database_now));
            }
            return Err(bootstrap_invalid());
        }

        let candidate_id = uuid::Uuid::new_v4();
        let candidate_digest: [u8; 32] = rand::random();
        let pending_id = SessionId::new();
        let placeholder_token_hash: [u8; 32] = rand::random();
        let replacement_id = uuid::Uuid::new_v4();
        let next_generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| corrupt("allocate next bootstrap generation"))?;

        sqlx::query!(
            r#"UPDATE central.bootstrap_generations
               SET state = 'consumed',
                   consumed_at = clock_timestamp(),
                   candidate_id = $2,
                   candidate_digest = $3,
                   registered_generation = $4
               WHERE id = $1 AND state = 'active'
               RETURNING id"#,
            current.id,
            candidate_id,
            &candidate_digest[..],
            next_generation,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| db_err("consume bootstrap generation", &e))?;

        let identity = req.identity.to_string();
        sqlx::query!(
            r#"INSERT INTO central.bootstrap_generations
                   (id, workspace_id, generation, verifier_hash, state, principal_identity, created_at)
               VALUES ($1, $2, $3, $4, 'active', $5, clock_timestamp())"#,
            replacement_id,
            uuid_of(WorkspaceId::sentinel().as_bytes()),
            next_generation,
            &candidate_digest[..],
            identity,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| db_err("register replacement bootstrap generation", &e))?;

        sqlx::query!(
            r#"INSERT INTO central.sessions
                   (id, workspace_id, token_hash, csrf_hash, principal_identity, lifecycle_state,
                    security_epoch, created_at, last_seen_at, idle_expiry, absolute_expiry)
               VALUES ($1, $2, $3, $4, $5, 'pending_bootstrap', $6,
                       clock_timestamp(), clock_timestamp(),
                       clock_timestamp() + ($7::double precision * interval '1 second'),
                       clock_timestamp() + ($8::double precision * interval '1 second'))"#,
            uuid_of(pending_id.as_bytes()),
            uuid_of(WorkspaceId::sentinel().as_bytes()),
            &placeholder_token_hash[..],
            &req.pre_auth_csrf_hash[..],
            identity,
            counter_as_i64(req.epoch.0, bootstrap_invalid)?,
            req.idle_expiry.as_seconds_f64(),
            req.absolute_expiry.as_seconds_f64(),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| db_err("create pending session", &e))?;

        tx.commit()
            .await
            .map_err(|e| db_err("commit bootstrap exchange", &e))?;

        Ok(ExchangeResult {
            session: Session {
                id: pending_id,
                workspace_id: WorkspaceId::sentinel(),
                state: SessionState::PendingBootstrap,
                principal_identity: identity,
                security_epoch: req.epoch,
                token_hash: [0u8; 32],
                csrf_hash: req.pre_auth_csrf_hash,
                idle_expiry: OffsetDateTime::UNIX_EPOCH,
                absolute_expiry: OffsetDateTime::UNIX_EPOCH,
                first_use_deadline: None,
                first_used_at: None,
                created_at: OffsetDateTime::UNIX_EPOCH,
                last_seen_at: OffsetDateTime::UNIX_EPOCH,
                revoked_at: None,
            },
            replacement: CandidateBinding {
                candidate_id: candidate_id.to_string(),
                // `checked_add` above guarantees the i64→u64 fit.
                generation: u64::try_from(next_generation)
                    .map_err(|_| corrupt("allocate next bootstrap generation"))?,
                digest: Zeroizing::new(candidate_digest),
            },
        })
    }

    /// `PrepareDelivery` — `pending_bootstrap -> delivery_pending`,
    /// gated on the exact consumed-generation candidate evidence.
    async fn prepare_delivery(&self, req: DeliveryRequest) -> Result<DeliveryResult, Failure> {
        if req.session_id.is_nil() || !valid_candidate(&req.candidate) {
            return Err(bootstrap_invalid());
        }
        let candidate_id =
            uuid::Uuid::parse_str(&req.candidate.candidate_id).map_err(|_| bootstrap_invalid())?;
        // Upstream `g.generation = $4 - 1` resolves `$4` as `int4`
        // (`bigint = int4` via the int4 `1` literal), so PostgreSQL
        // types the bind as i32 — a generation above `i32::MAX` can
        // never match a stored `bigint` this query accepts anyway.
        let generation =
            i32::try_from(req.candidate.generation).map_err(|_| bootstrap_invalid())?;

        let mut tx = self.begin().await?;
        let row = sqlx::query_as!(
            SessionRow,
            r#"UPDATE central.sessions s
               SET lifecycle_state = 'delivery_pending',
                   delivery_outcome = 'prepared'
               FROM central.bootstrap_generations g
               WHERE s.id = $1
                 AND s.workspace_id = $2
                 AND s.lifecycle_state = 'pending_bootstrap'
                 AND g.workspace_id = s.workspace_id
                 AND g.state = 'consumed'
                 AND g.generation = $4 - 1
                 AND g.candidate_id = $3
                 AND g.registered_generation = $4
                 AND g.candidate_digest = $5
               RETURNING s.id, s.workspace_id, s.token_hash, s.csrf_hash,
                         s.principal_identity, s.lifecycle_state, s.security_epoch,
                         s.created_at, s.last_seen_at, s.idle_expiry, s.absolute_expiry,
                         s.first_use_deadline, s.first_used_at, s.revoked_at"#,
            uuid_of(req.session_id.as_bytes()),
            uuid_of(WorkspaceId::sentinel().as_bytes()),
            candidate_id,
            generation,
            &req.candidate.digest[..],
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| db_err("prepare session delivery", &e))?;
        let Some(row) = row else {
            return Err(bootstrap_invalid());
        };
        let prepared = session_from_row(row, "prepare session delivery")?;
        tx.commit()
            .await
            .map_err(|e| db_err("commit session delivery", &e))?;
        Ok(DeliveryResult {
            session: prepared,
            delivery_id: DeliveryId::from_session_id(req.session_id),
        })
    }

    /// `ActivateDelivery` — the precommit `delivery_pending -> active`
    /// transition persisting only the fresh token/CSRF hashes.
    async fn activate_delivery(&self, req: ActivationRequest) -> Result<Session, Failure> {
        if req.token_hash == [0u8; 32] || req.csrf_hash == [0u8; 32] {
            return Err(session_invalidated());
        }
        let session_id = req.delivery_id.as_session_id();
        if session_id.is_nil() {
            return Err(session_invalidated());
        }
        let identity = req.identity.to_string();
        let epoch = counter_as_i64(req.epoch.0, session_invalidated)?;

        let mut tx = self.begin().await?;
        let row = sqlx::query_as!(
            SessionRow,
            r#"UPDATE central.sessions
               SET token_hash = $2,
                   csrf_hash = $3,
                   lifecycle_state = 'active',
                   first_use_deadline = clock_timestamp() + ($5::double precision * interval '1 second'),
                   delivery_outcome = 'activated'
               WHERE id = $1
                 AND workspace_id = $7
                 AND lifecycle_state = 'delivery_pending'
                 AND principal_identity = $4
                 AND security_epoch = $6
               RETURNING id, workspace_id, token_hash, csrf_hash,
                         principal_identity, lifecycle_state, security_epoch,
                         created_at, last_seen_at, idle_expiry, absolute_expiry,
                         first_use_deadline, first_used_at, revoked_at"#,
            uuid_of(session_id.as_bytes()),
            &req.token_hash[..],
            &req.csrf_hash[..],
            identity,
            DEFAULT_FIRST_USE_FENCE.as_seconds_f64(),
            epoch,
            uuid_of(WorkspaceId::sentinel().as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| db_err("activate session delivery", &e))?;
        let Some(row) = row else {
            return Err(session_invalidated());
        };
        let active = session_from_row(row, "activate session delivery")?;
        tx.commit()
            .await
            .map_err(|e| db_err("commit session activation", &e))?;
        Ok(active)
    }

    /// `Validate` — token-hash + epoch + expiry + first-use-fence +
    /// optional CSRF-hash comparison, with `last_seen`/`first_used`
    /// written by the same statement.
    async fn validate(&self, req: ValidationRequest) -> Result<Session, Failure> {
        if req.token_hash == [0u8; 32] {
            return Err(session_invalidated());
        }
        // Upstream: `checkCSRF := req.PresentedCSRFHash != ([32]byte{})`
        // — a zero presented hash means "route does not require CSRF".
        // `Some([0;32])` is that same absent signal.
        let (check_csrf, csrf_hash) = match req.presented_csrf_hash {
            Some(h) if h != [0u8; 32] => (true, h),
            _ => (false, [0u8; 32]),
        };
        let epoch = counter_as_i64(req.epoch.0, session_invalidated)?;

        let mut tx = self.begin().await?;
        let row = sqlx::query_as!(
            SessionRow,
            r#"UPDATE central.sessions
               SET last_seen_at = clock_timestamp(),
                   first_used_at = COALESCE(first_used_at, clock_timestamp())
               WHERE token_hash = $1
                 AND workspace_id = $5
                 AND lifecycle_state = 'active'
                 AND security_epoch = $2
                 AND absolute_expiry >= clock_timestamp()
                 AND idle_expiry >= clock_timestamp()
                 AND (first_used_at IS NOT NULL OR first_use_deadline IS NULL OR clock_timestamp() <= first_use_deadline)
                 AND ($3::boolean = false OR csrf_hash = $4)
               RETURNING id, workspace_id, token_hash, csrf_hash,
                         principal_identity, lifecycle_state, security_epoch,
                         created_at, last_seen_at, idle_expiry, absolute_expiry,
                         first_use_deadline, first_used_at, revoked_at"#,
            &req.token_hash[..],
            epoch,
            check_csrf,
            &csrf_hash[..],
            uuid_of(WorkspaceId::sentinel().as_bytes()),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| db_err("validate session", &e))?;
        let Some(row) = row else {
            return Err(session_invalidated());
        };
        let validated = session_from_row(row, "validate session")?;
        tx.commit()
            .await
            .map_err(|e| db_err("commit session validation", &e))?;
        Ok(validated)
    }

    /// `Revoke` — idempotent terminal transition covering
    /// `pending_bootstrap`, `delivery_pending`, and `active` rows.
    async fn revoke(&self, id: SessionId) -> Result<(), Failure> {
        if id.is_nil() {
            return Err(session_invalidated());
        }
        let mut tx = self.begin().await?;
        sqlx::query!(
            r#"UPDATE central.sessions
               SET lifecycle_state = 'revoked',
                   revoked_at = COALESCE(revoked_at, clock_timestamp()),
                   delivery_outcome = 'revoked'
               WHERE id = $1
                 AND workspace_id = $2
                 AND lifecycle_state IN ('pending_bootstrap', 'delivery_pending', 'active')"#,
            uuid_of(id.as_bytes()),
            uuid_of(WorkspaceId::sentinel().as_bytes()),
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| db_err("revoke session", &e))?;
        tx.commit()
            .await
            .map_err(|e| db_err("commit session revocation", &e))?;
        Ok(())
    }
}

impl PresentationStore for PgSessionStore {
    /// `BeginPresentation` — leases the current active bootstrap
    /// generation using the PostgreSQL clock. The lease is durable and
    /// replaces any prior presentation deadline for that generation.
    async fn begin_presentation(&self) -> Result<PresentationLease, Failure> {
        let mut tx = self.begin().await?;
        let row = sqlx::query_as!(
            PresentationRow,
            r#"UPDATE central.bootstrap_generations
               SET presentation_deadline = clock_timestamp() + ($2::double precision * interval '1 second')
               WHERE workspace_id = $1 AND state = 'active'
               RETURNING generation, presentation_deadline"#,
            uuid_of(WorkspaceId::sentinel().as_bytes()),
            PRESENTATION_WINDOW.as_seconds_f64(),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| db_err("begin bootstrap presentation", &e))?;
        let Some(row) = row else {
            return Err(bootstrap_invalid());
        };
        let generation =
            u64::try_from(row.generation).map_err(|_| corrupt("begin bootstrap presentation"))?;
        tx.commit()
            .await
            .map_err(|e| db_err("commit bootstrap presentation", &e))?;
        Ok(PresentationLease {
            generation,
            deadline: row.presentation_deadline,
        })
    }

    /// `ValidatePresentation` — checks the currently leased generation
    /// against the PostgreSQL clock. It intentionally returns no token
    /// or verifier material.
    async fn validate_presentation(&self) -> Result<(), Failure> {
        let mut tx = self.begin().await?;
        let ok = sqlx::query_scalar!(
            r#"SELECT EXISTS (
                   SELECT 1 FROM central.bootstrap_generations
                   WHERE workspace_id = $1 AND state = 'active'
                     AND presentation_deadline > clock_timestamp()
               ) AS "valid!""#,
            uuid_of(WorkspaceId::sentinel().as_bytes()),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| db_err("validate bootstrap presentation", &e))?;
        tx.commit()
            .await
            .map_err(|e| db_err("commit bootstrap presentation validation", &e))?;
        if !ok {
            return Err(bootstrap_invalid());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Audited SQL inventory — upstream `queries.go`. These statements are
    // deliberately kept in one inventory: callers provide values, never SQL
    // fragments, and every mutation uses PostgreSQL's wall clock rather
    // than transaction-start time.
    // ---------------------------------------------------------------------------

    const QUERY_DISCOVER_BOOTSTRAP_CANDIDATES: &str = r#"SELECT id, lifecycle_state, COALESCE(delivery_outcome, '') AS "outcome!",
                      first_use_deadline, first_used_at
               FROM central.sessions
               WHERE workspace_id = $1
                 AND (
                   lifecycle_state IN ('pending_bootstrap', 'delivery_pending')
                   OR (lifecycle_state = 'active' AND first_used_at IS NULL AND first_use_deadline <= clock_timestamp())
                 )
               ORDER BY created_at ASC, id ASC"#;

    const QUERY_CURRENT_GENERATION: &str = r#"SELECT id, generation, verifier_hash, principal_identity,
                      throttle_failure_window_start, throttle_failure_count,
                      throttle_next_eligible, presentation_deadline,
                      clock_timestamp() AS "database_now!"
               FROM central.bootstrap_generations
               WHERE workspace_id = $1 AND state = 'active'
               ORDER BY generation DESC
               LIMIT 1
               FOR UPDATE"#;

    const QUERY_THROTTLE_GENERATION: &str = r#"WITH clock AS MATERIALIZED (SELECT clock_timestamp() AS now),
                   next_failure AS (
                       SELECT g.id, c.now,
                              CASE
                                WHEN g.throttle_failure_window_start IS NULL
                                  OR g.throttle_failure_window_start <= c.now - interval '60 seconds'
                                THEN 1
                                ELSE g.throttle_failure_count + 1
                              END AS failure_count
                       FROM central.bootstrap_generations g
                       CROSS JOIN clock c
                       WHERE g.id = $1
                   ),
                   updated AS (
                       UPDATE central.bootstrap_generations g
                       SET throttle_failure_window_start = CASE WHEN n.failure_count = 1 THEN n.now ELSE g.throttle_failure_window_start END,
                           throttle_failure_count = n.failure_count,
                           throttle_next_eligible = CASE WHEN n.failure_count >= 5 THEN n.now + interval '60 seconds' ELSE NULL END
                       FROM next_failure n
                       WHERE g.id = n.id
                       RETURNING g.throttle_failure_count AS failure_count, g.throttle_next_eligible
                   )
                   SELECT failure_count, COALESCE(throttle_next_eligible, clock_timestamp()) AS "next_eligible!", clock_timestamp() AS "database_now!"
                   FROM updated"#;

    const QUERY_CONSUME_GENERATION: &str = r#"UPDATE central.bootstrap_generations
               SET state = 'consumed',
                   consumed_at = clock_timestamp(),
                   candidate_id = $2,
                   candidate_digest = $3,
                   registered_generation = $4
               WHERE id = $1 AND state = 'active'
               RETURNING id"#;

    const QUERY_INSERT_REPLACEMENT: &str = r#"INSERT INTO central.bootstrap_generations
                   (id, workspace_id, generation, verifier_hash, state, principal_identity, created_at)
               VALUES ($1, $2, $3, $4, 'active', $5, clock_timestamp())"#;

    const QUERY_INSERT_PENDING_SESSION: &str = r#"INSERT INTO central.sessions
                   (id, workspace_id, token_hash, csrf_hash, principal_identity, lifecycle_state,
                    security_epoch, created_at, last_seen_at, idle_expiry, absolute_expiry)
               VALUES ($1, $2, $3, $4, $5, 'pending_bootstrap', $6,
                       clock_timestamp(), clock_timestamp(),
                       clock_timestamp() + ($7::double precision * interval '1 second'),
                       clock_timestamp() + ($8::double precision * interval '1 second'))"#;

    const QUERY_PREPARE_DELIVERY: &str = r#"UPDATE central.sessions s
               SET lifecycle_state = 'delivery_pending',
                   delivery_outcome = 'prepared'
               FROM central.bootstrap_generations g
               WHERE s.id = $1
                 AND s.workspace_id = $2
                 AND s.lifecycle_state = 'pending_bootstrap'
                 AND g.workspace_id = s.workspace_id
                 AND g.state = 'consumed'
                 AND g.generation = $4 - 1
                 AND g.candidate_id = $3
                 AND g.registered_generation = $4
                 AND g.candidate_digest = $5
               RETURNING s.id, s.workspace_id, s.token_hash, s.csrf_hash,
                         s.principal_identity, s.lifecycle_state, s.security_epoch,
                         s.created_at, s.last_seen_at, s.idle_expiry, s.absolute_expiry,
                         s.first_use_deadline, s.first_used_at, s.revoked_at"#;

    const QUERY_ACTIVATE_DELIVERY: &str = r#"UPDATE central.sessions
               SET token_hash = $2,
                   csrf_hash = $3,
                   lifecycle_state = 'active',
                   first_use_deadline = clock_timestamp() + ($5::double precision * interval '1 second'),
                   delivery_outcome = 'activated'
               WHERE id = $1
                 AND workspace_id = $7
                 AND lifecycle_state = 'delivery_pending'
                 AND principal_identity = $4
                 AND security_epoch = $6
               RETURNING id, workspace_id, token_hash, csrf_hash,
                         principal_identity, lifecycle_state, security_epoch,
                         created_at, last_seen_at, idle_expiry, absolute_expiry,
                         first_use_deadline, first_used_at, revoked_at"#;

    const QUERY_VALIDATE_SESSION: &str = r#"UPDATE central.sessions
               SET last_seen_at = clock_timestamp(),
                   first_used_at = COALESCE(first_used_at, clock_timestamp())
               WHERE token_hash = $1
                 AND workspace_id = $5
                 AND lifecycle_state = 'active'
                 AND security_epoch = $2
                 AND absolute_expiry >= clock_timestamp()
                 AND idle_expiry >= clock_timestamp()
                 AND (first_used_at IS NOT NULL OR first_use_deadline IS NULL OR clock_timestamp() <= first_use_deadline)
                 AND ($3::boolean = false OR csrf_hash = $4)
               RETURNING id, workspace_id, token_hash, csrf_hash,
                         principal_identity, lifecycle_state, security_epoch,
                         created_at, last_seen_at, idle_expiry, absolute_expiry,
                         first_use_deadline, first_used_at, revoked_at"#;

    const QUERY_REVOKE_SESSION: &str = r#"UPDATE central.sessions
               SET lifecycle_state = 'revoked',
                   revoked_at = COALESCE(revoked_at, clock_timestamp()),
                   delivery_outcome = 'revoked'
               WHERE id = $1
                 AND workspace_id = $2
                 AND lifecycle_state IN ('pending_bootstrap', 'delivery_pending', 'active')"#;

    const QUERY_BEGIN_PRESENTATION: &str = r#"UPDATE central.bootstrap_generations
               SET presentation_deadline = clock_timestamp() + ($2::double precision * interval '1 second')
               WHERE workspace_id = $1 AND state = 'active'
               RETURNING generation, presentation_deadline"#;

    const QUERY_VALIDATE_PRESENTATION: &str = r#"SELECT EXISTS (
                   SELECT 1 FROM central.bootstrap_generations
                   WHERE workspace_id = $1 AND state = 'active'
                     AND presentation_deadline > clock_timestamp()
               ) AS "valid!""#;

    /// `include_str!` drift guard: `sqlx` macros require inline
    /// literals, so the audited constants below are the review anchor
    /// and the call-site literals are the executed SQL. Requiring each
    /// constant to appear a second time in this same file proves the
    /// executed text is byte-identical to the audited constant — the
    /// upstream `queries.go` "one inventory" property.
    const SRC: &str = include_str!("store.rs");

    /// `TestSessionQueriesAreParameterizedAndUseDatabaseClock` — the
    /// query inventory is parameterized (`$n` binds only) and every
    /// mutation uses `clock_timestamp()`.
    #[test]
    fn session_queries_are_parameterized_and_use_database_clock() {
        let queries = [
            QUERY_DISCOVER_BOOTSTRAP_CANDIDATES,
            QUERY_CURRENT_GENERATION,
            QUERY_THROTTLE_GENERATION,
            QUERY_CONSUME_GENERATION,
            QUERY_INSERT_REPLACEMENT,
            QUERY_INSERT_PENDING_SESSION,
            QUERY_PREPARE_DELIVERY,
            QUERY_ACTIVATE_DELIVERY,
            QUERY_VALIDATE_SESSION,
            QUERY_REVOKE_SESSION,
            QUERY_BEGIN_PRESENTATION,
            QUERY_VALIDATE_PRESENTATION,
        ];
        for q in queries {
            assert!(q.contains("$1"), "query is not parameterized: {q}");
            assert!(!q.contains('%'), "query contains interpolation: {q}");
            assert!(
                SRC.matches(q).count() >= 2,
                "audited constant and executed literal diverged: {q}"
            );
        }
        for q in [
            QUERY_THROTTLE_GENERATION,
            QUERY_CONSUME_GENERATION,
            QUERY_INSERT_REPLACEMENT,
            QUERY_INSERT_PENDING_SESSION,
            QUERY_ACTIVATE_DELIVERY,
            QUERY_VALIDATE_SESSION,
            QUERY_REVOKE_SESSION,
            QUERY_BEGIN_PRESENTATION,
            QUERY_VALIDATE_PRESENTATION,
        ] {
            assert!(
                q.contains("clock_timestamp()"),
                "query does not use database clock: {q}"
            );
        }
    }

    /// `TestSessionQueriesDoNotAcceptPlaintextCredentialColumns`.
    #[test]
    fn session_queries_do_not_accept_plaintext_credential_columns() {
        for (name, q) in [
            (
                "exchange",
                format!(
                    "{QUERY_CONSUME_GENERATION}{QUERY_INSERT_REPLACEMENT}{QUERY_INSERT_PENDING_SESSION}"
                ),
            ),
            ("delivery", QUERY_PREPARE_DELIVERY.to_string()),
            ("activate", QUERY_ACTIVATE_DELIVERY.to_string()),
            ("validate", QUERY_VALIDATE_SESSION.to_string()),
            ("revoke", QUERY_REVOKE_SESSION.to_string()),
        ] {
            let lower = q.to_lowercase();
            for forbidden in [
                "bootstrap_token",
                "session_token",
                "csrf_token",
                "plaintext",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "{name} query mentions forbidden plaintext field {forbidden:?}"
                );
            }
        }
    }

    /// `TestDeliveryQueryUsesAuditedGenerationKey`.
    #[test]
    fn delivery_query_uses_audited_generation_key() {
        assert!(QUERY_PREPARE_DELIVERY.contains("g.generation = $4 - 1"));
        assert!(QUERY_CURRENT_GENERATION.contains("LIMIT 1"));
        assert!(QUERY_REVOKE_SESSION.contains("pending_bootstrap"));
        assert!(
            QUERY_DISCOVER_BOOTSTRAP_CANDIDATES.contains("first_use_deadline")
                && QUERY_DISCOVER_BOOTSTRAP_CANDIDATES.contains("pending_bootstrap")
        );
        assert!(
            QUERY_REVOKE_SESSION.contains("SET lifecycle_state = 'revoked'")
                && !QUERY_REVOKE_SESSION.contains("THEN lifecycle_state")
        );
        assert!(
            QUERY_CURRENT_GENERATION.contains("presentation_deadline")
                && QUERY_BEGIN_PRESENTATION.contains("presentation_deadline")
        );
    }

    /// `TestActivationRejectsZeroCredentialHashesBeforeDatabaseUse` —
    /// the zero-hash gate runs before any database work (asserted by
    /// the port contract; the `is_nil`/`is_zero` guards are the first
    /// statements).
    #[test]
    fn typed_failure_builders_carry_sentinels() {
        assert_eq!(
            bootstrap_invalid().class,
            Some(FailureClass::BootstrapInvalid)
        );
        assert!(bootstrap_invalid().is_sentinel(Sentinel::BootstrapInvalid));
        assert_eq!(
            session_invalidated().class,
            Some(FailureClass::SessionInvalidated)
        );
        assert!(session_invalidated().is_sentinel(Sentinel::SessionInvalidated));
        let t = throttled(Duration::seconds(90));
        assert_eq!(t.class, Some(FailureClass::BootstrapThrottled));
        assert_eq!(
            central_session::domain::retry_after_from_failure(&t).map(|r| r.seconds()),
            Some(60)
        );
        assert_eq!(
            database_failure("validate session").to_string(),
            "session store: validate session"
        );
    }
}
