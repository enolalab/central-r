//! The bounded, fenced Artifact reconciliation pass — the port of
//! `central/internal/artifact/app/reconciler.go`.
//!
//! [`Reconciler`] runs under B08's existing `recovery_coordinator` lease:
//! B10 introduces no second scheduler and no second coordinator lease.
//! The pass never treats object listing as authoritative, never blindly
//! re-uploads, never overwrites a ready key, never adopts a ready object
//! lacking durable metadata, and never completes a Task from an
//! incomplete Artifact.
//!
//! Cancellation is delivered by future drop (the Rust runtime has no
//! `context.Context`): dropping the [`Reconciler::reconcile`] future
//! stops the pass at the next port call, and a port that reports
//! [`FailureKind::Cancelled`] ends the pass the same way upstream's
//! `ctx.Err()` check does.

use std::time::{Duration, Instant};

use central_foundation::failure::{Failure, FailureKind};
use central_foundation::identity::{ArtifactId, WorkspaceId};
use time::OffsetDateTime;

use crate::app::ResumeLifecycle;
use crate::domain::State;
use crate::port::{
    ClaimIncompleteRequest, ClaimLargeRequest, ClaimRejectedStagingRequest, ClearStagingKeyRequest,
    ExpireStagingRequest, IncompleteClaim, MAX_ARTIFACT_BODY_BYTES, ObjectRef, ObjectStore,
    ReconciliationCursor, ReconciliationProgress, ReconciliationStore, RecordLargeClaimRequest,
    ReleaseLargeClaimRequest, Store, TRANSFER_TOTAL_DEADLINE,
};

// ---------------------------------------------------------------------------
// Fence
// ---------------------------------------------------------------------------

/// The caller's proof that this reconciliation pass runs under B08's
/// existing `recovery_coordinator` lease (upstream `Fence`):
/// `generation` is that lease's fencing generation and `claim_token` its
/// raw 256-bit bearer, both passed through unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct Fence {
    /// The coordinator lease's fencing generation — must be positive.
    pub generation: i64,
    /// The coordinator epoch's generation, carried for observability.
    pub epoch_generation: i64,
    /// The lease's raw 256-bit claim token.
    pub claim_token: Vec<u8>,
}

impl Fence {
    /// Fails closed (upstream `Fence.Validate`). An unfenced or
    /// short-token pass must never reach the store, because only the
    /// fence distinguishes this coordinator from a superseded one that
    /// must not mutate durable state.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.generation <= 0 {
            return Err(Failure::invalid(
                "ARTIFACT_RECONCILE_UNFENCED",
                "reconciliation requires a coordinator fencing generation",
            ));
        }
        if self.claim_token.len() != 32 {
            return Err(Failure::invalid(
                "ARTIFACT_RECONCILE_MISSING_CLAIM_TOKEN",
                "reconciliation requires the 256-bit coordinator claim token",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

/// Bounds one reconciliation pass (upstream `Budget`). Each dimension has
/// an installed default and a hard ceiling, and the two have distinct,
/// enforced meanings:
///
/// - `max_*` is the soft target the pass aims to stay within under
///   normal conditions. Reaching it ends the pass cleanly; work already
///   started is always allowed to finish.
/// - `hard_*` is the absolute ceiling the pass may never cross,
///   including under degraded conditions. It is checked before every
///   single item, not merely between batches, so no batch can run past
///   it.
///
/// [`Reconciler::new`] normalizes each `max_*` down to its own `hard_*`
/// and fills a missing `hard_*` from `max_*`, so "hard" is a real
/// ceiling rather than a documented intention: after construction
/// `max_* <= hard_*` always holds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Budget {
    /// Soft per-pass artifact count.
    pub max_artifacts: usize,
    /// Hard per-pass artifact ceiling.
    pub hard_artifacts: usize,
    /// Soft per-pass moved-bytes budget.
    pub max_bytes: i64,
    /// Hard per-pass moved-bytes ceiling.
    pub hard_bytes: i64,
    /// Soft per-pass wall-clock budget.
    pub max_duration: Duration,
    /// Hard per-pass wall-clock ceiling.
    pub hard_duration: Duration,
}

/// The normal periodic pass (upstream `DefaultBudget`): at most 100
/// Artifacts (250 hard), 256 MiB (1 GiB hard), or 30 seconds (120 seconds
/// hard).
#[must_use]
pub const fn default_budget() -> Budget {
    Budget {
        max_artifacts: 100,
        hard_artifacts: 250,
        max_bytes: 256 << 20,
        hard_bytes: 1 << 30,
        max_duration: Duration::from_secs(30),
        hard_duration: Duration::from_secs(120),
    }
}

/// The dedicated single-Artifact pass (upstream `LargeClaimBudget`). It
/// is deliberately exempt from the normal 120-second cap — a 4 GiB body
/// cannot transfer inside it — but it still retains the port's transfer
/// limits and total deadline, and it processes exactly one Artifact
/// under its own fence.
#[must_use]
pub const fn large_claim_budget() -> Budget {
    Budget {
        max_artifacts: 1,
        hard_artifacts: 1,
        max_bytes: MAX_ARTIFACT_BODY_BYTES,
        hard_bytes: MAX_ARTIFACT_BODY_BYTES,
        max_duration: TRANSFER_TOTAL_DEADLINE,
        hard_duration: TRANSFER_TOTAL_DEADLINE,
    }
}

impl Budget {
    /// Makes the hard ceilings enforceable (upstream `Budget.normalize`):
    /// a missing hard value adopts its soft value, and a soft value
    /// above its hard ceiling is clamped down to it. A pass therefore
    /// cannot be configured to legally cross a hard ceiling.
    #[must_use]
    pub fn normalize(mut self) -> Self {
        if self.hard_artifacts == 0 {
            self.hard_artifacts = self.max_artifacts;
        }
        if self.max_artifacts > self.hard_artifacts {
            self.max_artifacts = self.hard_artifacts;
        }
        if self.hard_bytes <= 0 {
            self.hard_bytes = self.max_bytes;
        }
        if self.max_bytes > self.hard_bytes {
            self.max_bytes = self.hard_bytes;
        }
        if self.hard_duration.is_zero() {
            self.hard_duration = self.max_duration;
        }
        if self.max_duration > self.hard_duration {
            self.max_duration = self.hard_duration;
        }
        self
    }
}

/// Staging lifetime bounds (upstream `DefaultStagingLifetime`/
/// `HardStagingLifetime`). A reserved record with no begun upload, and a
/// staging record with no active claim, expire at the installed
/// lifetime.
pub const DEFAULT_STAGING_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
/// The absolute ceiling an installed staging lifetime may be configured
/// to.
pub const HARD_STAGING_LIFETIME: Duration = Duration::from_secs(72 * 60 * 60);

const NORMAL_CLAIM_LEASE: Duration = Duration::from_secs(5 * 60);
const LARGE_CLAIM_LEASE: Duration = Duration::from_secs(15 * 60);

const STAGING_KEY_PREFIX: &str = "v1/staging/";

/// Bounds the rejected-staging cleanup sweep that opens a normal pass
/// (upstream `rejectedStagingSweepBatch`). Cleaned records leave the
/// scan permanently, so a small per-pass batch drains any backlog across
/// successive passes without letting cleanup crowd out lifecycle
/// reconciliation.
const REJECTED_STAGING_SWEEP_BATCH: usize = 25;

/// The deliberately pessimistic transfer rate the pass assumes when
/// converting its remaining *time* budget into bytes it can still afford
/// to move (upstream `reconcileThroughputFloorBytesPerSecond` = 8 MiB/s).
/// It exists so the design's "exceeds the remaining byte or time budget"
/// deferral criterion has a deterministic time half: a candidate that
/// could not plausibly transfer inside the pass's remaining time becomes
/// a dedicated large claim instead of being started and then abandoned
/// mid-transfer.
pub const RECONCILE_THROUGHPUT_FLOOR_BYTES_PER_SECOND: u64 = 8 << 20;

// ---------------------------------------------------------------------------
// PassReport
// ---------------------------------------------------------------------------

/// The safe, aggregate result of one reconciliation pass (upstream
/// `PassReport`). It carries no Workspace, Artifact, key, or body
/// evidence: only counts and durations the health monitor may publish.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PassReport {
    /// Counts claims the pass acted on or deliberately skipped.
    pub processed: usize,
    /// Counts candidates promoted to a dedicated large claim.
    pub deferred: usize,
    /// The byte budget the pass consumed. It counts object bytes the
    /// pass actually moved, never the declared ceilings of the
    /// candidates it looked at: a candidate that resolved without a
    /// transfer costs the pass nothing, so a record that can never
    /// resolve cannot consume the whole budget pass after pass and
    /// starve real work.
    pub bytes_charged: i64,
    /// The pass's own wall-clock duration.
    pub elapsed: Duration,
    /// Counts single items whose transient failure was contained without
    /// aborting the pass.
    pub item_failures: usize,
    /// Counts rejected records whose staging object this pass cleaned
    /// up.
    pub staging_objects_removed: usize,
    /// Counts Workspaces the claim resolver stepped over because their
    /// durable ID is not a parseable `WorkspaceId`.
    pub skipped_workspaces: usize,
    /// `true` when at least one claim call in this pass gave up walking
    /// before it reached a valid workspace. Together with
    /// `skipped_workspaces` it lets an operator tell a stalled pass —
    /// one wedged behind unreconcilable rows — apart from a pass that
    /// simply found nothing to do: both report zero `processed`.
    pub resolver_budget_exhausted: bool,
    /// The database-derived age of the oldest incomplete Artifact this
    /// pass observed. Zero when the pass observed no such Artifact — an
    /// empty backlog is not a stale one.
    pub oldest_backlog_age: Duration,
    /// The database-derived age of the oldest incomplete Artifact
    /// carrying a required role.
    pub required_output_blocked_for: Duration,
}

// ---------------------------------------------------------------------------
// Reconciler
// ---------------------------------------------------------------------------

/// Runs the bounded, fenced Artifact reconciliation pass (upstream
/// `Reconciler`).
///
/// `C` is the [`ReconciliationStore`] (claims and fenced transitions),
/// `R` the durable [`Store`] (records), `O` the [`ObjectStore`], and `L`
/// the [`ResumeLifecycle`] — normally the same [`crate::app::Service`]
/// that drives a live materialization, so the pass resumes a `verifying`
/// Artifact by re-entering that command sequence non-interactively
/// rather than reimplementing it: there is exactly one definition of
/// what promoting, re-verifying, and finalizing mean.
pub struct Reconciler<C, R, O, L> {
    claims: C,
    records: R,
    objects: O,
    lifecycle: L,
    budget: Budget,
    staging_lifetime: Duration,
}

impl<C, R, O, L> Reconciler<C, R, O, L>
where
    C: ReconciliationStore,
    R: Store,
    O: ObjectStore,
    L: ResumeLifecycle,
{
    /// Constructs the reconciler over its four ports (upstream
    /// `NewReconciler`); the nil-check upstream performs is a
    /// compile-time property here. Installs [`default_budget`] and
    /// [`DEFAULT_STAGING_LIFETIME`].
    pub fn new(claims: C, records: R, objects: O, lifecycle: L) -> Self {
        Self {
            claims,
            records,
            objects,
            lifecycle,
            budget: default_budget().normalize(),
            staging_lifetime: DEFAULT_STAGING_LIFETIME,
        }
    }

    /// Installs a custom pass budget, normalized so the hard ceilings
    /// are real (upstream `ReconcilerConfig.Budget`).
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget.normalize();
        self
    }

    /// Installs a custom staging lifetime, clamped to
    /// [`HARD_STAGING_LIFETIME`] exactly like upstream's constructor.
    /// A zero value keeps the installed default.
    #[must_use]
    pub fn with_staging_lifetime(mut self, lifetime: Duration) -> Self {
        self.staging_lifetime = if lifetime.is_zero() {
            DEFAULT_STAGING_LIFETIME
        } else {
            lifetime.min(HARD_STAGING_LIFETIME)
        };
        self
    }

    /// Runs exactly one pass under the supplied coordinator fence
    /// (upstream `Reconcile`).
    ///
    /// A pending dedicated large-Artifact claim takes the whole pass —
    /// but only when it is real work. A claim whose Artifact has already
    /// resolved is released and the pass continues to normal
    /// reconciliation, so a stale claim row can never consume tick after
    /// tick.
    ///
    /// Deviation from upstream's signature `(PassReport, error)`: the
    /// `Err` arm carries no partial report — a fatal failure returns the
    /// error alone, matching the brief's `Result<PassReport, Failure>`
    /// contract. `elapsed` is measured on every success path.
    pub async fn reconcile(&self, fence: &Fence) -> Result<PassReport, Failure> {
        let mut report = PassReport::default();
        fence.validate()?;

        let large = self
            .claims
            .claim_large(ClaimLargeRequest {
                claim_token: fence.claim_token.clone(),
                lease_duration: LARGE_CLAIM_LEASE,
            })
            .await?;
        if let Some(large) = large {
            let budget = large_claim_budget().normalize();
            let claim = IncompleteClaim {
                artifact_id: large.artifact_id,
                workspace_id: large.workspace_id,
                // A dedicated large claim carries no recorded state
                // (upstream's empty-string `State`): the staleness check
                // is skipped for it by construction.
                state: None,
                lease_expires_at: large.lease_expires_at,
                created_at: OffsetDateTime::UNIX_EPOCH,
            };
            let result = self
                .reconcile_claim(
                    fence,
                    &claim,
                    &budget,
                    budget.max_bytes,
                    budget.max_duration,
                    true,
                )
                .await;
            let mut resolved = false;
            match result {
                Ok(outcome) => {
                    report.processed += 1;
                    report.bytes_charged += outcome.spent;
                    resolved = outcome.resolved;
                }
                Err(failure) => {
                    if fatal_pass_error(&failure) {
                        return Err(failure);
                    }
                    report.item_failures += 1;
                    report.processed += 1;
                }
            }

            // The claim is consumed either way: the dedicated worker has
            // had its turn. An Artifact still needing work is re-observed
            // by the normal cursor and re-deferred if it still cannot
            // fit a normal pass, so no claim row outlives the work it
            // describes.
            if let Err(failure) = self
                .claims
                .release_large_claim(ReleaseLargeClaimRequest {
                    workspace_id: large.workspace_id,
                    artifact_id: large.artifact_id,
                    claim_token: fence.claim_token.clone(),
                })
                .await
            {
                if fatal_pass_error(&failure) {
                    return Err(failure);
                }
                report.item_failures += 1;
            }
            if !resolved {
                // A pending large claim on a record that still needs
                // reconciliation takes the whole pass, exactly as
                // designed: it runs alone, under its own fence.
                return Ok(report);
            }
            // The claim described an already-resolved record: stale
            // work. It must not cost this pass its normal
            // reconciliation.
        }

        self.run_normal_pass(fence, report).await
    }

    /// The normal reconciliation pass: the rejected-staging sweep, then
    /// the bounded claim loop. `elapsed` is measured from here and
    /// stamped onto every successful return — the named-return `defer`
    /// upstream uses.
    async fn run_normal_pass(
        &self,
        fence: &Fence,
        carried: PassReport,
    ) -> Result<PassReport, Failure> {
        let started = Instant::now();
        let result = self.run_normal_pass_inner(fence, carried, started).await;
        match result {
            Ok(mut report) => {
                report.elapsed = started.elapsed();
                Ok(report)
            }
            Err(failure) => Err(failure),
        }
    }

    async fn run_normal_pass_inner(
        &self,
        fence: &Fence,
        mut report: PassReport,
        started: Instant,
    ) -> Result<PassReport, Failure> {
        let budget = self.budget;
        let mut cycle: i64 = 1;
        let mut cursor = zero_cursor();

        self.sweep_rejected_staging(fence, &mut report, &budget, started)
            .await?;

        loop {
            let elapsed = started.elapsed();
            if report.processed >= budget.max_artifacts
                || report.bytes_charged >= budget.max_bytes
                || elapsed >= budget.max_duration
            {
                return Ok(report);
            }
            let batch = budget.max_artifacts - report.processed;
            let result = self
                .claims
                .claim_incomplete(ClaimIncompleteRequest {
                    cursor,
                    batch_size: batch,
                    claim_token: fence.claim_token.clone(),
                    lease_duration: NORMAL_CLAIM_LEASE,
                    coordinator_generation: fence.generation,
                })
                .await?;
            // Recorded before the empty-batch return: a call that
            // claimed nothing because the resolver ran out of skip
            // budget is exactly the case that must stay observable, and
            // it always returns an empty batch.
            report.skipped_workspaces += result.skipped_workspaces;
            report.resolver_budget_exhausted =
                report.resolver_budget_exhausted || result.skip_budget_exhausted;
            if result.claims.is_empty() {
                return Ok(report);
            }
            for claim in &result.claims {
                // Hard ceilings are checked per item, never only per
                // batch: one batch of up to max_artifacts items must not
                // be able to run past them under any condition.
                let elapsed = started.elapsed();
                if report.processed >= budget.hard_artifacts
                    || report.bytes_charged >= budget.hard_bytes
                    || elapsed >= budget.hard_duration
                {
                    return Ok(report);
                }
                // The soft time target is likewise enforced per item
                // rather than only between batches.
                if elapsed >= budget.max_duration {
                    return Ok(report);
                }

                observe_backlog(&mut report, result.observed_at, claim);

                let remaining_bytes = budget.max_bytes - report.bytes_charged;
                let remaining_time = budget.max_duration.saturating_sub(elapsed);
                match self
                    .reconcile_claim(
                        fence,
                        claim,
                        &budget,
                        remaining_bytes,
                        remaining_time,
                        false,
                    )
                    .await
                {
                    Err(failure) => {
                        if fatal_pass_error(&failure) {
                            return Err(failure);
                        }
                        // One unlucky item never aborts the pass: record
                        // it and move on, exactly as a non-mutating
                        // conflict already does.
                        report.item_failures += 1;
                        report.processed += 1;
                        continue;
                    }
                    Ok(outcome) => {
                        report.processed += 1;
                        observe_blocked_required_output(
                            &mut report,
                            result.observed_at,
                            claim,
                            &outcome.required_role,
                        );
                        if outcome.deferred {
                            report.deferred += 1;
                            continue;
                        }
                        report.bytes_charged += outcome.spent;
                        report.staging_objects_removed += outcome.staging_removed;
                    }
                }
            }
            cursor = result.next_cursor;
            self.claims
                .record_progress(ReconciliationProgress {
                    cursor,
                    processed_count: report.processed as i64,
                    cycle,
                })
                .await?;
            cycle += 1;
        }
    }

    /// Removes the staging objects of already-rejected records (upstream
    /// `sweepRejectedStaging`). The design restricts staging cleanup to
    /// "rejected, expired, or proven orphan staging objects"; expiry
    /// cleans itself up inline, so without this sweep the rejected case
    /// — including a body rejected for suspected secret disclosure —
    /// would never be cleaned at all.
    ///
    /// Only the staging-role key of a rejected record is ever a
    /// candidate, and it is proven to belong to exactly that Workspace
    /// and Artifact before any delete. A ready key is never reachable
    /// from here.
    ///
    /// The sweep spends the *same* pass budget the main claim loop
    /// spends, measured from the same start instant: it is not a
    /// privileged phase that runs before the ceilings apply. Exhausting
    /// the sweep's share stops only the sweep — the pass falls through
    /// to the main loop with whatever budget remains. The byte ceilings
    /// are deliberately not consulted: a delete moves no body bytes, so
    /// charging the sweep against them would let one large transfer
    /// suppress cleanup entirely.
    async fn sweep_rejected_staging(
        &self,
        fence: &Fence,
        report: &mut PassReport,
        budget: &Budget,
        started: Instant,
    ) -> Result<(), Failure> {
        // The count ceiling is shared too: the sweep never asks for more
        // records than the pass's remaining artifact allowance can cover.
        let batch = REJECTED_STAGING_SWEEP_BATCH
            .min(budget.hard_artifacts.saturating_sub(report.processed));
        if batch == 0 {
            return Ok(());
        }
        if started.elapsed() >= budget.max_duration {
            return Ok(());
        }
        let claimed = match self
            .claims
            .claim_rejected_staging(ClaimRejectedStagingRequest {
                batch_size: batch,
                claim_token: fence.claim_token.clone(),
            })
            .await
        {
            Ok(claimed) => claimed,
            Err(failure) => {
                if fatal_pass_error(&failure) {
                    return Err(failure);
                }
                report.item_failures += 1;
                return Ok(());
            }
        };
        for (swept, claim) in claimed.claims.iter().enumerate() {
            // Ceilings are checked before every single item, never only
            // per batch, and a store that returns more records than the
            // sweep asked for cannot widen the sweep past its own share
            // of the count budget.
            let elapsed = started.elapsed();
            if swept >= batch || elapsed >= budget.hard_duration || elapsed >= budget.max_duration {
                return Ok(());
            }
            if !owns_staging_key(
                &claim.workspace_id.to_string(),
                &claim.artifact_id.to_string(),
                &claim.staging_key,
            ) {
                // Not a proven staging-role key for this record: never
                // delete it, and never clear the durable evidence of it
                // either.
                continue;
            }
            if let Err(failure) = self
                .objects
                .remove_staging(ObjectRef {
                    key: claim.staging_key.clone(),
                })
                .await
            {
                if fatal_pass_error(&failure) {
                    return Err(failure);
                }
                // A transient object-store failure is retried by a later
                // pass: the record keeps its staging key and stays in
                // the sweep.
                report.item_failures += 1;
                continue;
            }
            if let Err(failure) = self
                .claims
                .clear_staging_key(ClearStagingKeyRequest {
                    workspace_id: claim.workspace_id,
                    artifact_id: claim.artifact_id,
                    claim_token: fence.claim_token.clone(),
                })
                .await
            {
                if fatal_pass_error(&failure) {
                    return Err(failure);
                }
                report.item_failures += 1;
                continue;
            }
            report.staging_objects_removed += 1;
        }
        Ok(())
    }

    /// Revalidates one claimed Artifact against durable state and acts
    /// on it (upstream `reconcileClaim`).
    ///
    /// Every early return is a deliberate non-mutating skip: an
    /// ownership mismatch, a state that moved under the claim, or a
    /// terminal state must never produce an object-store call or a
    /// durable transition. Claim staleness itself is revalidated by the
    /// adapter inside the same transaction as each durable transition —
    /// strictly stronger than an unlocked pre-check here — and surfaces
    /// as a transition that reports having applied nothing.
    async fn reconcile_claim(
        &self,
        fence: &Fence,
        claim: &IncompleteClaim,
        budget: &Budget,
        remaining_bytes: i64,
        remaining_time: Duration,
        dedicated: bool,
    ) -> Result<ClaimOutcome, Failure> {
        let snap = self
            .records
            .load_artifact(claim.workspace_id, claim.artifact_id)
            .await?;
        if snap.workspace_id != claim.workspace_id || snap.artifact_id != claim.artifact_id {
            return Ok(ClaimOutcome {
                resolved: true,
                ..ClaimOutcome::default()
            });
        }
        // The claim recorded a state; if durable state has moved on, this
        // pass no longer knows what it is looking at and must re-observe
        // next cycle. A dedicated large claim carries no recorded state
        // (upstream's empty string) and skips this check.
        if claim.state.is_some_and(|claimed| claimed != snap.state) {
            return Ok(ClaimOutcome {
                resolved: true,
                ..ClaimOutcome::default()
            });
        }
        // Ready is terminal and untouchable. A rejected record is
        // terminal for lifecycle purposes too, but its staging object is
        // still cleanup work, which `sweep_rejected_staging` owns.
        if snap.state == State::Ready || snap.state == State::Rejected {
            return Ok(ClaimOutcome {
                resolved: true,
                ..ClaimOutcome::default()
            });
        }

        // A candidate that would exceed the remaining byte budget — or
        // that could not plausibly transfer inside the remaining time
        // budget — becomes a durable large-Artifact claim, and the normal
        // cursor advances past it. A dedicated pass never defers again:
        // it already is the large claim.
        let declared = snap.limits.max_bytes;
        if !dedicated
            && (declared > remaining_bytes
                || declared > budget.max_bytes
                || declared > affordable_bytes(remaining_time))
        {
            self.claims
                .record_large_claim(RecordLargeClaimRequest {
                    workspace_id: snap.workspace_id,
                    artifact_id: snap.artifact_id,
                    expected_version: snap.version,
                    coordinator_generation: fence.generation,
                    claim_token: fence.claim_token.clone(),
                })
                .await?;
            return Ok(ClaimOutcome {
                deferred: true,
                acted: true,
                ..ClaimOutcome::default()
            });
        }

        // `spent` starts at zero and accumulates only what this item
        // actually moved. Charging the *declared* ceiling regardless of
        // outcome was how a single record that never resolves consumed
        // the whole 256 MiB pass budget every pass: the declaration is
        // the right basis for the prospective deferral decision above,
        // but never for the retrospective charge below.
        let mut out = ClaimOutcome {
            required_role: snap.required_role.clone(),
            ..ClaimOutcome::default()
        };

        // A verifying record has already had its body durably verified;
        // what it is missing is the promotion and/or the finalize
        // commit. It is finalizable, so it is never expired or cleaned
        // up — but "finalizable" has to mean something actually
        // finalizes it, which is what this resume does.
        if snap.state == State::Verifying {
            let resumed = self.lifecycle.resume_verifying(snap).await?;
            out.acted = true;
            out.spent = resumed.bytes_moved;
            out.resolved = resumed.resolved;
            return Ok(out);
        }

        // Expiry applies only to a reserved record with no begun upload
        // and a staging record with no active claim. Whether the record
        // has actually outlived the installed lifetime is decided by the
        // store against database-derived time, never by this process's
        // clock.
        if snap.state == State::Reserved || snap.state == State::Staging {
            let expiry = self
                .claims
                .expire_staging(ExpireStagingRequest {
                    workspace_id: snap.workspace_id,
                    artifact_id: snap.artifact_id,
                    expected_version: snap.version,
                    claim_token: fence.claim_token.clone(),
                    lifetime: self.staging_lifetime,
                })
                .await?;
            // Only after the durable record is rejected may its staging
            // object be removed, and only when the key is a proven
            // staging key owned by this Artifact.
            if expiry.expired
                && owns_staging_key(
                    &snap.workspace_id.to_string(),
                    &snap.artifact_id.to_string(),
                    &snap.staging_key,
                )
            {
                out.acted = true;
                self.objects
                    .remove_staging(ObjectRef {
                        key: snap.staging_key.clone(),
                    })
                    .await?;
                out.staging_removed += 1;
                // Record the removal so the rejected-staging sweep never
                // revisits this record.
                self.claims
                    .clear_staging_key(ClearStagingKeyRequest {
                        workspace_id: snap.workspace_id,
                        artifact_id: snap.artifact_id,
                        claim_token: fence.claim_token.clone(),
                    })
                    .await?;
            }
            if expiry.expired {
                out.acted = true;
            }
        }
        Ok(out)
    }
}

/// One claimed Artifact's contribution to the pass budget (upstream
/// `claimResult`).
#[derive(Debug, Default)]
struct ClaimOutcome {
    /// The byte budget the item consumed.
    spent: i64,
    /// The candidate was promoted to a dedicated large-Artifact claim.
    deferred: bool,
    /// A durable transition or object-store operation was actually
    /// attempted, as opposed to a non-mutating skip.
    acted: bool,
    /// The claim referred to a record that no longer needs
    /// reconciliation at all: already terminal, absent, or moved out
    /// from under the claim. A dedicated large claim in this state is
    /// stale work and must not cost the pass its normal reconciliation.
    resolved: bool,
    /// Staging objects this item cleaned up.
    staging_removed: usize,
    /// The durable required-output role the record carries, or empty
    /// when the Artifact is not a required output.
    required_role: String,
}

/// The zero keyset cursor — upstream's `port.ReconciliationCursor{}`
/// zero value: nil IDs and a zero instant, which the adapter treats as
/// the first page.
fn zero_cursor() -> ReconciliationCursor {
    ReconciliationCursor {
        workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
        created_at: OffsetDateTime::UNIX_EPOCH,
        artifact_id: ArtifactId::from_trusted_db_bytes([0; 16]),
    }
}

/// Whether one item's failure must stop the whole pass (upstream
/// `fatalPassError`). Only shutdown-class errors qualify — in Rust that
/// is [`FailureKind::Cancelled`], delivered either by an adapter
/// observing its own cancellation or by the caller dropping work it can
/// no longer wait on. A single unlucky item — a row briefly unreadable,
/// a transient object-store error — must never discard a bounded pass's
/// cursor progress, which is exactly the liveness risk when the object
/// store is flaky and reconciliation matters most.
fn fatal_pass_error(failure: &Failure) -> bool {
    matches!(failure.kind(), FailureKind::Cancelled)
}

/// Records the database-derived age of the oldest incomplete Artifact
/// the pass has seen (upstream `observeBacklog`). The age comes from the
/// store's own observation instant, so no process clock participates.
/// `OffsetDateTime::UNIX_EPOCH` is the zero-sentinel, matching upstream's
/// `time.Time` zero check.
fn observe_backlog(report: &mut PassReport, observed_at: OffsetDateTime, claim: &IncompleteClaim) {
    if observed_at == OffsetDateTime::UNIX_EPOCH || claim.created_at == OffsetDateTime::UNIX_EPOCH {
        return;
    }
    let age = observed_at - claim.created_at;
    let Ok(age) = Duration::try_from(age) else {
        return;
    };
    if age.is_zero() {
        return;
    }
    if age > report.oldest_backlog_age {
        report.oldest_backlog_age = age;
    }
}

/// Records how long a required output has been non-ready (upstream
/// `observeBlockedRequiredOutput`). It is separate from
/// [`observe_backlog`] because the required role is only known once the
/// durable snapshot has been read.
fn observe_blocked_required_output(
    report: &mut PassReport,
    observed_at: OffsetDateTime,
    claim: &IncompleteClaim,
    required_role: &str,
) {
    if required_role.is_empty()
        || observed_at == OffsetDateTime::UNIX_EPOCH
        || claim.created_at == OffsetDateTime::UNIX_EPOCH
    {
        return;
    }
    let age = observed_at - claim.created_at;
    let Ok(age) = Duration::try_from(age) else {
        return;
    };
    if age > report.required_output_blocked_for {
        report.required_output_blocked_for = age;
    }
}

/// Converts the pass's remaining time budget into the number of bytes it
/// could still move at the documented pessimistic throughput floor
/// (upstream `affordableBytes`) — what gives the deferral rule its time
/// half.
fn affordable_bytes(remaining: Duration) -> i64 {
    if remaining.is_zero() {
        return 0;
    }
    (remaining.as_secs_f64() * RECONCILE_THROUGHPUT_FLOOR_BYTES_PER_SECOND as f64) as i64
}

/// Proves the key is a staging-role key belonging to exactly this
/// Workspace and Artifact before any delete is attempted (upstream
/// `ownsStagingKey`). Listing is never authoritative and a ready key is
/// never a candidate.
fn owns_staging_key(workspace_id: &str, artifact_id: &str, key: &str) -> bool {
    if key.is_empty() || !key.starts_with(STAGING_KEY_PREFIX) {
        return false;
    }
    key.starts_with(&format!(
        "{STAGING_KEY_PREFIX}{workspace_id}/{artifact_id}/"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::ResumeResult;
    use crate::domain::{Artifact, Disposition, Limits, Outcome, OutcomeKind, Sensitivity};
    use crate::port::{ClaimIncompleteResult, LargeClaim, RejectedStagingClaim};
    use crate::testkit::{
        FakeLifecycle, FakeObjects, FakeReconciliationStore, FakeRecords, Journal, block_on,
    };
    use central_foundation::identity::{RunId, StagingGeneration, StepAttemptId, StepId, TaskId};

    fn fence() -> Fence {
        Fence {
            generation: 7,
            epoch_generation: 3,
            claim_token: vec![0xAB; 32],
        }
    }

    /// The shared reconciliation fixture.
    struct Fixture {
        journal: Journal,
        claims: FakeReconciliationStore,
        records: FakeRecords,
        objects: FakeObjects,
        lifecycle: FakeLifecycle,
        reconciler: Reconciler<FakeReconciliationStore, FakeRecords, FakeObjects, FakeLifecycle>,
    }

    fn fixture() -> Fixture {
        let journal = Journal::default();
        let claims = FakeReconciliationStore::new(journal.clone(), OffsetDateTime::now_utc());
        let records = FakeRecords::new(journal.clone());
        let objects = FakeObjects::new(journal.clone());
        let lifecycle = FakeLifecycle::new(journal.clone());
        let reconciler = Reconciler::new(
            claims.clone(),
            records.clone(),
            objects.clone(),
            lifecycle.clone(),
        );
        Fixture {
            journal,
            claims,
            records,
            objects,
            lifecycle,
            reconciler,
        }
    }

    /// A durable snapshot at an arbitrary lifecycle state.
    fn artifact_at(state: State) -> Artifact {
        let workspace_id = WorkspaceId::new();
        let artifact_id = ArtifactId::new();
        Artifact {
            workspace_id,
            artifact_id,
            state,
            version: 1,
            staging_generation: StagingGeneration::new(),
            staging_key: format!("v1/staging/{workspace_id}/{artifact_id}/gen"),
            content_generation: None,
            ready_key: String::new(),
            limits: Limits::default(),
            verified_size: 0,
            verified_checksum: [0; 32],
            ready_object_version: String::new(),
            task_id: TaskId::new(),
            run_id: RunId::new(),
            step_id: StepId::new(),
            step_attempt_id: StepAttemptId::new(),
            tool_call_attempt_id: None,
            producer_id: "producer".to_owned(),
            required_role: String::new(),
            sensitivity: Sensitivity::Unrestricted,
            disposition: Disposition::Inline,
            delete_intent_at: None,
            deleted_at: None,
        }
    }

    /// Registers `artifact` with the record store and returns the claim
    /// shape the claim sweep would emit for it.
    fn claim_for(f: &Fixture, artifact: &Artifact, state: State) -> IncompleteClaim {
        f.records
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());
        IncompleteClaim {
            artifact_id: artifact.artifact_id,
            workspace_id: artifact.workspace_id,
            state: Some(state),
            lease_expires_at: OffsetDateTime::now_utc(),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    fn push_batch(f: &Fixture, claims: Vec<IncompleteClaim>) {
        f.claims
            .incomplete
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(ClaimIncompleteResult {
                claims,
                next_cursor: ReconciliationCursor {
                    workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                    artifact_id: ArtifactId::from_trusted_db_bytes([0; 16]),
                },
                observed_at: f.claims.observed_at,
                skipped_workspaces: 0,
                skip_budget_exhausted: false,
            });
    }

    // ------------------------------------------------------------------
    // Fence and budget invariants
    // ------------------------------------------------------------------

    #[test]
    fn reconcile_requires_fencing() {
        let f = fixture();
        // No fencing generation.
        let mut bad = fence();
        bad.generation = 0;
        assert!(block_on(f.reconciler.reconcile(&bad)).is_err());
        // No claim token.
        let mut bad = fence();
        bad.claim_token = Vec::new();
        assert!(block_on(f.reconciler.reconcile(&bad)).is_err());
        // A short token is equally unfenced.
        let mut bad = fence();
        bad.claim_token = vec![0; 16];
        assert!(block_on(f.reconciler.reconcile(&bad)).is_err());
        // None of them may have reached the store.
        assert_eq!(
            0,
            *f.claims
                .large_calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
        );
    }

    #[test]
    fn budget_normalize_clamps_soft_under_hard() {
        let budget = Budget {
            max_artifacts: 500,
            hard_artifacts: 100,
            max_bytes: 1 << 30,
            hard_bytes: 1 << 20,
            max_duration: Duration::from_secs(300),
            hard_duration: Duration::from_secs(60),
        }
        .normalize();
        assert_eq!(100, budget.max_artifacts);
        assert_eq!(1 << 20, budget.max_bytes);
        assert_eq!(Duration::from_secs(60), budget.max_duration);

        // A missing hard ceiling adopts the soft value.
        let filled = Budget {
            max_artifacts: 10,
            hard_artifacts: 0,
            max_bytes: 100,
            hard_bytes: 0,
            max_duration: Duration::from_secs(5),
            hard_duration: Duration::ZERO,
        }
        .normalize();
        assert_eq!(10, filled.hard_artifacts);
        assert_eq!(100, filled.hard_bytes);
        assert_eq!(Duration::from_secs(5), filled.hard_duration);
    }

    #[test]
    fn claim_request_carries_generation_token_and_batch() {
        let f = fixture();
        push_batch(&f, Vec::new());
        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        let reqs = f
            .claims
            .claim_reqs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(1, reqs.len());
        assert_eq!(7, reqs[0].coordinator_generation);
        assert_eq!(vec![0xAB; 32], reqs[0].claim_token);
        assert!(reqs[0].batch_size <= default_budget().max_artifacts);
        drop(reqs);
        // An empty backlog is not a stalled one.
        assert!(report.elapsed >= Duration::ZERO);
        assert_eq!(Duration::ZERO, report.oldest_backlog_age);
    }

    // ------------------------------------------------------------------
    // Large claims
    // ------------------------------------------------------------------

    /// Upstream `TestProcessedLargeClaimIsReleasedAfterOwningThePass`:
    /// a genuine large claim — real work the pass does not resolve —
    /// runs alone, and its claim row does not outlive it.
    #[test]
    fn processed_large_claim_releases_after_owning_the_pass() {
        let f = fixture();
        let artifact = artifact_at(State::Staging);
        f.records
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());
        f.objects.put(&artifact.staging_key, b"staged", "v-staging");
        // The store's database-derived clock says the record outlived
        // the installed lifetime, so the dedicated pass performs real
        // expiry work that stays unresolved.
        f.claims
            .age
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, Duration::from_secs(48 * 60 * 60));
        *f.claims.large.lock().unwrap_or_else(|e| e.into_inner()) = Some(LargeClaim {
            artifact_id: artifact.artifact_id,
            workspace_id: artifact.workspace_id,
            lease_expires_at: OffsetDateTime::now_utc(),
        });
        // A queued normal claim proves the pass returned early rather
        // than merely finding the backlog empty.
        let ordinary = artifact_at(State::Staging);
        push_batch(&f, vec![claim_for(&f, &ordinary, State::Staging)]);

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(1, report.processed);
        // The claim did real work — the staging record expired.
        assert_eq!(
            vec![artifact.artifact_id],
            f.claims
                .expired
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
        // Unresolved work owns the whole pass: the normal cursor never
        // ran — no claim_incomplete request was ever issued.
        assert!(!f.journal.has("claim.Incomplete"));
        assert!(
            f.claims
                .claim_reqs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
        assert_eq!(
            1,
            *f.claims
                .large_calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
        );
        // The consumed claim row is released either way.
        assert_eq!(
            vec![artifact.artifact_id],
            f.claims
                .released_large
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
    }

    /// The resume half of the ownership rule: a dedicated claim whose
    /// `resume_verifying` leaves the record unresolved still owns the
    /// whole pass — the `!resolved` early return is exercised directly.
    #[test]
    fn unresolved_large_claim_resume_owns_the_pass() {
        let f = fixture();
        let artifact = artifact_at(State::Verifying);
        f.records
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());
        *f.claims.large.lock().unwrap_or_else(|e| e.into_inner()) = Some(LargeClaim {
            artifact_id: artifact.artifact_id,
            workspace_id: artifact.workspace_id,
            lease_expires_at: OffsetDateTime::now_utc(),
        });
        // The resume re-observes the record but cannot prove it
        // resolved — genuinely ambiguous work, not a stale claim row.
        *f.lifecycle.result.lock().unwrap_or_else(|e| e.into_inner()) = ResumeResult {
            outcome: Outcome {
                kind: OutcomeKind::Reconciliation,
                failure_code: String::new(),
            },
            resolved: false,
            bytes_moved: 0,
        };

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(1, report.processed);
        assert_eq!(
            1,
            f.lifecycle
                .calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len()
        );
        // The unresolved claim owns the pass: claim_incomplete was
        // never called and the pass returned early.
        assert!(!f.journal.has("claim.Incomplete"));
        assert!(
            f.claims
                .claim_reqs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
        // The claim is still released: it is re-observed by the normal
        // cursor next pass, so no claim row outlives the work.
        assert_eq!(
            vec![artifact.artifact_id],
            f.claims
                .released_large
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
    }

    #[test]
    fn stale_large_claim_releases_and_falls_through() {
        let f = fixture();
        // The claim row describes a record that already resolved — a
        // ready artifact is terminal.
        let artifact = artifact_at(State::Ready);
        f.records
            .artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, artifact.clone());
        *f.claims.large.lock().unwrap_or_else(|e| e.into_inner()) = Some(LargeClaim {
            artifact_id: artifact.artifact_id,
            workspace_id: artifact.workspace_id,
            lease_expires_at: OffsetDateTime::now_utc(),
        });
        push_batch(&f, Vec::new());

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(1, report.processed);
        // The stale claim was consumed AND normal reconciliation ran.
        assert_eq!(
            vec![artifact.artifact_id],
            f.claims
                .released_large
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
        assert_eq!(
            1,
            f.claims
                .claim_reqs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len()
        );
        // No resume: a terminal record is skipped before the lifecycle.
        assert!(
            f.lifecycle
                .calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn oversized_candidate_defers_to_large_claim() {
        let f = fixture();
        let mut artifact = artifact_at(State::Staging);
        // The declared body ceiling exceeds the whole pass byte budget.
        artifact.limits = Limits {
            max_bytes: MAX_ARTIFACT_BODY_BYTES,
        };
        let claim = claim_for(&f, &artifact, State::Staging);
        push_batch(&f, vec![claim]);

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(1, report.processed);
        assert_eq!(1, report.deferred);
        assert_eq!(
            vec![artifact.artifact_id],
            f.claims
                .large_recorded
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
        let reqs = f
            .claims
            .large_claim_reqs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(7, reqs[0].coordinator_generation);
    }

    // ------------------------------------------------------------------
    // Expiry, cleanup, and the rejected-staging sweep
    // ------------------------------------------------------------------

    #[test]
    fn expired_staging_rejects_and_removes_object() {
        let f = fixture();
        let artifact = artifact_at(State::Staging);
        f.objects.put(&artifact.staging_key, b"staged", "v-staging");
        let claim = claim_for(&f, &artifact, State::Staging);
        // The store's database-derived clock says the record outlived
        // the installed lifetime.
        f.claims
            .age
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, Duration::from_secs(25 * 60 * 60));
        push_batch(&f, vec![claim]);

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(1, report.processed);
        assert_eq!(1, report.staging_objects_removed);
        assert_eq!(
            vec![artifact.artifact_id],
            f.claims
                .expired
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
        // Object removal is ordered after the durable rejection and
        // recorded so the sweep never revisits it.
        let expire = f.journal.index("claim.ExpireStaging").unwrap_or(usize::MAX);
        let remove = f
            .journal
            .index("object.RemoveStaging")
            .unwrap_or(usize::MAX);
        let clear = f
            .journal
            .index("claim.ClearStagingKey")
            .unwrap_or(usize::MAX);
        assert!(expire < remove && remove < clear, "cleanup out of order");
        assert_eq!(
            vec![artifact.staging_key.clone()],
            f.objects
                .removed_staging
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
    }

    #[test]
    fn young_record_is_not_expired() {
        let f = fixture();
        let artifact = artifact_at(State::Staging);
        let claim = claim_for(&f, &artifact, State::Staging);
        f.claims
            .age
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, Duration::from_secs(60));
        push_batch(&f, vec![claim]);

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(1, report.processed);
        assert_eq!(0, report.staging_objects_removed);
        assert!(
            f.claims
                .expired
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
        assert!(
            f.objects
                .removed_staging
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn verifying_record_resumes_never_expires() {
        let f = fixture();
        let mut artifact = artifact_at(State::Verifying);
        artifact.verified_size = 4;
        artifact.verified_checksum = [1; 32];
        let claim = claim_for(&f, &artifact, State::Verifying);
        // Even an ancient record: verifying is finalizable, never
        // expiry or cleanup work.
        f.claims
            .age
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, Duration::from_secs(72 * 60 * 60));
        push_batch(&f, vec![claim]);

        block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(
            1,
            f.lifecycle
                .calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len()
        );
        assert!(
            f.claims
                .expire_reqs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
        assert!(
            f.objects
                .removed_staging
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn resume_consumes_only_moved_bytes() {
        let f = fixture();
        let mut artifact = artifact_at(State::Verifying);
        artifact.verified_size = 4;
        artifact.verified_checksum = [1; 32];
        let claim = claim_for(&f, &artifact, State::Verifying);
        f.lifecycle
            .result
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bytes_moved = 123;
        push_batch(&f, vec![claim]);

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        // The byte budget is charged for the bytes the resume actually
        // moved, never the declared ceiling.
        assert_eq!(123, report.bytes_charged);
    }

    #[test]
    fn rejected_staging_sweep_removes_only_proven_keys() {
        let f = fixture();
        let artifact = artifact_at(State::Rejected);
        let staging_key = artifact.staging_key.clone();
        f.objects.put(&staging_key, b"reject", "v-staging");
        f.claims
            .rejected_staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(RejectedStagingClaim {
                workspace_id: artifact.workspace_id,
                artifact_id: artifact.artifact_id,
                staging_key: staging_key.clone(),
            });
        // A foreign key that is not a proven staging key for this
        // record is never removed and never cleared.
        f.claims
            .rejected_staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(RejectedStagingClaim {
                workspace_id: artifact.workspace_id,
                artifact_id: ArtifactId::new(),
                staging_key: "v1/ready/foreign/key".to_owned(),
            });
        push_batch(&f, Vec::new());

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(1, report.staging_objects_removed);
        assert_eq!(
            vec![staging_key],
            f.objects
                .removed_staging
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
        assert_eq!(
            vec![artifact.artifact_id],
            f.claims
                .cleared_staging
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        );
    }

    // ------------------------------------------------------------------
    // Movement under a claim, containment, and reporting
    // ------------------------------------------------------------------

    #[test]
    fn state_moved_under_claim_skips_mutation() {
        let f = fixture();
        // The claim recorded `staging`, but the durable record has
        // moved on to ready: a terminal state the pass must not touch.
        let artifact = artifact_at(State::Ready);
        let claim = claim_for(&f, &artifact, State::Staging);
        f.claims
            .age
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, Duration::from_secs(72 * 60 * 60));
        push_batch(&f, vec![claim]);

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(1, report.processed);
        // No expire attempt: the moved state skips the whole action.
        assert!(
            f.claims
                .expire_reqs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn one_items_failure_is_contained() {
        let f = fixture();
        let good = artifact_at(State::Staging);
        let bad = artifact_at(State::Staging);
        let good_claim = claim_for(&f, &good, State::Staging);
        let bad_claim = claim_for(&f, &bad, State::Staging);
        // The one unlucky row is briefly unreadable.
        f.claims
            .age
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(good.artifact_id, Duration::from_secs(60));
        f.records
            .load_err_for
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                bad.artifact_id,
                Failure::internal("TRANSIENT", "row briefly unreadable"),
            );
        push_batch(&f, vec![bad_claim, good_claim]);

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(2, report.processed);
        assert_eq!(1, report.item_failures);
        // Progress is still journaled past the failed item.
        assert!(
            !f.claims
                .progress
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn shutdown_class_failure_stops_the_pass() {
        let f = fixture();
        *f.claims
            .incomplete_err
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Failure::cancelled(
            "PASS_CANCELLED",
            "the coordinator lease was lost",
        ));
        let result = block_on(f.reconciler.reconcile(&fence()));
        assert!(result.is_err());
    }

    #[test]
    fn resolver_budget_and_skipped_workspaces_are_reported() {
        let f = fixture();
        f.claims
            .incomplete
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(ClaimIncompleteResult {
                claims: Vec::new(),
                next_cursor: ReconciliationCursor {
                    workspace_id: WorkspaceId::from_trusted_db_bytes([0; 16]),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                    artifact_id: ArtifactId::from_trusted_db_bytes([0; 16]),
                },
                observed_at: OffsetDateTime::now_utc(),
                skipped_workspaces: 3,
                skip_budget_exhausted: true,
            });
        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(3, report.skipped_workspaces);
        assert!(report.resolver_budget_exhausted);
        assert_eq!(0, report.processed);
    }

    #[test]
    fn backlog_age_comes_from_database_time() {
        let f = fixture();
        let artifact = artifact_at(State::Staging);
        let mut claim = claim_for(&f, &artifact, State::Staging);
        // claimed two hours ago by the database's own clock.
        claim.created_at = f.claims.observed_at - time::Duration::hours(2);
        f.claims
            .age
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(artifact.artifact_id, Duration::from_secs(60));
        push_batch(&f, vec![claim]);

        let report = block_on(f.reconciler.reconcile(&fence()))
            .unwrap_or_else(|e| unreachable!("reconcile failed: {e:?}"));
        assert_eq!(Duration::from_secs(2 * 60 * 60), report.oldest_backlog_age);
    }
}
