//! The startup reconciler and the operator's `Resolver` — the port of
//! `internal/harness/app/reconciler.go` (decision 9; harness phase 3e
//! decision 6, phase 3f decision 10, phase 3g decision 6, phase 3k
//! decisions 2 and 4).
//!
//! [`Reconciler`] is the harness step of the serve recovery gate: it
//! runs right after the scheduler's recovery pass, always (even with
//! harness execution disabled), and touches the database only: each
//! non-terminal harness attempt takes the state its linked
//! StepAttempt implies, written under the recovery authority
//! ([`RecoveryStore`]), never under a fence. The `slog.Warn` line
//! upstream logs for each ambiguous row has no Rust form — this crate
//! has no logging port.
//!
//! [`Resolver`] is the harness side of the operator's single-attempt
//! actions, written under the same recovery authority once the
//! execution side has settled the linked StepAttempt.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_foundation::identity::{StepAttemptId, WorkspaceId};
use time::OffsetDateTime;

use crate::attempt::Attempt;
use crate::domain::{self, Resolution, ResolutionKind, State, Terminal, TerminalStatus, codes};
use crate::port::{LinkedStepAttemptState, MAX_RECOVERY_CANDIDATES, RecoveryCursor, RecoveryStore};
use crate::recovery::attempt_id_for_step_attempt;

use super::ports::{Clock, ResolveStore};

/// `AmbiguityRestart` — the `ambiguity_reason` of an attempt whose
/// serve stopped (or lost its lease) after `MarkInvoked`: whether the
/// harness ran to the end is unknown.
pub const AMBIGUITY_RESTART: &str = "control_plane_restart";
/// `ReasonRecoveredSettlement` — the `Terminal::reason` of an attempt
/// whose linked StepAttempt's settlement the reconciler adopted.
pub const REASON_RECOVERED_SETTLEMENT: &str = "recovered_settlement";
/// `DecidedByRecovery` — the `Resolution::decided_by` when the
/// reconciler completes an operator resolution whose harness write was
/// lost: the linked StepAttempt is already settled.
pub const DECIDED_BY_RECOVERY: &str = "recovery:settled_step_attempt";
/// `DecidedByOperatorResume` — the `Resolution::decided_by` when the
/// reconciler completes a resume whose harness write was lost.
pub const DECIDED_BY_OPERATOR_RESUME: &str = "recovery:operator_resume";

/// `ReconcileSummary` counts one reconciliation pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Candidates visited.
    pub scanned: usize,
    /// Took the terminal of a settled StepAttempt.
    pub settled: usize,
    /// Prepared rows whose StepAttempt was cancelled before launch.
    pub unlaunched: usize,
    /// Rows marked ambiguous (restart after launch may have happened).
    pub ambiguous: usize,
    /// Ambiguous rows whose operator resolution the reconciler
    /// completed.
    pub resolved: usize,
    /// Lease-live, unrecovered or refused rows — left alone.
    pub skipped: usize,
}

/// `app.Reconciler` — the startup reconciliation pass.
pub struct Reconciler {
    store: Arc<dyn RecoveryStore>,
    clock: Arc<dyn Clock>,
}

/// Where one candidate's count goes.
enum Counter {
    Settled,
    Unlaunched,
    Ambiguous,
    Resolved,
}

impl Reconciler {
    /// `NewReconciler`. The Rust form takes no `logger`: upstream logs
    /// one warning per ambiguous row; the rows themselves carry the
    /// fact.
    pub fn new(store: Arc<dyn RecoveryStore>, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }

    /// `Run` — reconciles every non-terminal harness attempt once. A
    /// candidate the recovery authority refuses (its StepAttempt is
    /// still lease-live, or not yet recovered) is skipped and counted;
    /// any other store failure ends the pass with an error, which
    /// fails the recovery gate.
    pub async fn run(&self) -> Result<ReconcileSummary, Failure> {
        let mut sum = ReconcileSummary::default();
        let mut cursor = RecoveryCursor::default();
        loop {
            let page = self
                .store
                .list_recovery_candidates(cursor, MAX_RECOVERY_CANDIDATES)
                .await?;
            for c in &page {
                sum.scanned += 1;
                self.reconcile(c, &mut sum).await?;
            }
            if page.len() < MAX_RECOVERY_CANDIDATES {
                return Ok(sum);
            }
            let last = page[page.len() - 1].attempt.clone();
            cursor = RecoveryCursor {
                prepared_at: last.prepared_at,
                id: last.id,
            };
        }
    }

    async fn reconcile(
        &self,
        c: &crate::port::RecoveryCandidate,
        sum: &mut ReconcileSummary,
    ) -> Result<(), Failure> {
        let a = &c.attempt;
        if c.lease_live {
            sum.skipped += 1;
            return Ok(());
        }
        let at = std::cmp::max(self.clock.now(), a.updated_at);
        // A non-ambiguous row whose failed StepAttempt has a successor
        // takes the plain failed path.
        let mut step = c.step_state;
        if step == LinkedStepAttemptState::Resumed && a.state != State::Ambiguous {
            step = LinkedStepAttemptState::Failed;
        }
        let counter;
        let next: Attempt;
        if a.state == State::Ambiguous {
            match c.step_state {
                LinkedStepAttemptState::Succeeded
                | LinkedStepAttemptState::Failed
                | LinkedStepAttemptState::Cancelled => {
                    // The operator's resolution settled the
                    // StepAttempt but its harness write was lost:
                    // finish it.
                    next = a.resolve(
                        a.fence,
                        Resolution {
                            kind: ResolutionKind::Abandon,
                            decided_by: DECIDED_BY_RECOVERY.to_string(),
                        },
                        at,
                    )?;
                    counter = Counter::Resolved;
                }
                LinkedStepAttemptState::Resumed => {
                    // The operator's resume created the successor
                    // StepAttempt but its harness write was lost
                    // (harness phase 3g decision 6). A row with no
                    // session id cannot be resumed: it falls back to
                    // abandon, never an error.
                    next = a.resolve(
                        a.fence,
                        Resolution {
                            kind: if a.harness_session_id.is_empty() {
                                ResolutionKind::Abandon
                            } else {
                                ResolutionKind::Resume
                            },
                            decided_by: if a.harness_session_id.is_empty() {
                                DECIDED_BY_RECOVERY
                            } else {
                                DECIDED_BY_OPERATOR_RESUME
                            }
                            .to_string(),
                        },
                        at,
                    )?;
                    counter = Counter::Resolved;
                }
                _ => {
                    sum.skipped += 1;
                    return Ok(());
                }
            }
        } else if step == LinkedStepAttemptState::Succeeded
            || step == LinkedStepAttemptState::Failed
        {
            match Self::settled(a, step, at) {
                Ok(n) => {
                    next = n;
                    counter = Counter::Settled;
                }
                Err(e)
                    if e.code() == codes::INVALID_TRANSITION
                        || e.code() == codes::INVALID_ATTEMPT =>
                {
                    next = a.mark_ambiguous(a.fence, AMBIGUITY_RESTART, at)?;
                    counter = Counter::Ambiguous;
                }
                Err(e) => return Err(e),
            }
        } else if step == LinkedStepAttemptState::Cancelled && a.state == State::Prepared {
            // The scheduler cancelled a never-invoked attempt into a
            // prepared successor, or an abandon lost its harness
            // write: the harness never ran.
            next = a.fail_unlaunched(a.fence, at)?;
            counter = Counter::Unlaunched;
        } else if step == LinkedStepAttemptState::Cancelled
            || step == LinkedStepAttemptState::Reconciliation
        {
            next = a.mark_ambiguous(a.fence, AMBIGUITY_RESTART, at)?;
            counter = Counter::Ambiguous;
        } else {
            // prepared, invoked or settling without a live lease, or
            // no linked StepAttempt: the scheduler has not recovered
            // it (for example a degraded epoch). The recovery
            // authority would refuse; leave it.
            sum.skipped += 1;
            return Ok(());
        }
        if let Err(e) = self.store.recover_attempt(a, &next).await {
            if e.code() == codes::RECOVERY_NOT_AUTHORIZED
                || e.code() == domain::codes::VERSION_CONFLICT
            {
                sum.skipped += 1;
                return Ok(());
            }
            return Err(e);
        }
        match counter {
            Counter::Settled => sum.settled += 1,
            Counter::Unlaunched => sum.unlaunched += 1,
            Counter::Ambiguous => sum.ambiguous += 1,
            Counter::Resolved => sum.resolved += 1,
        }
        Ok(())
    }

    /// `settled` gives `a` the terminal matching its settled
    /// StepAttempt.
    fn settled(
        a: &Attempt,
        step: LinkedStepAttemptState,
        at: OffsetDateTime,
    ) -> Result<Attempt, Failure> {
        if step == LinkedStepAttemptState::Failed && a.state == State::Prepared {
            return a.fail_unlaunched(a.fence, at);
        }
        let status = if step == LinkedStepAttemptState::Succeeded {
            TerminalStatus::Succeeded
        } else {
            TerminalStatus::Failed
        };
        a.terminate(
            a.fence,
            Terminal {
                status,
                reason: REASON_RECOVERED_SETTLEMENT.to_string(),
                exit_code: None,
            },
            at,
        )
    }
}

/// `app.Resolver` — the harness side of the operator's single-attempt
/// actions.
pub struct Resolver {
    store: Arc<dyn ResolveStore>,
    clock: Arc<dyn Clock>,
}

impl Resolver {
    /// `NewResolver`.
    pub fn new(store: Arc<dyn ResolveStore>, clock: Arc<dyn Clock>) -> Self {
        Self { store, clock }
    }

    /// `ResolveAbandon` records `resolved(abandon)` by `decided_by` on
    /// the harness attempt linked to `step_attempt`. It is idempotent:
    /// an attempt already terminal, or none at all, needs nothing. A
    /// live attempt is first marked ambiguous, since only an
    /// ambiguous attempt can be resolved.
    pub async fn resolve_abandon(
        &self,
        ws: WorkspaceId,
        step_attempt: StepAttemptId,
        decided_by: &str,
    ) -> Result<(), Failure> {
        self.resolve_as(ws, step_attempt, ResolutionKind::Abandon, decided_by)
            .await
    }

    /// `ResolveRerun` records `resolved(rerun)` by `decided_by` on the
    /// harness attempt linked to `step_attempt` (harness phase 3k
    /// decisions 2 and 4), in `resolve_abandon`'s shape: an attempt
    /// already terminal (resolved(abandon) by the startup reconciler
    /// in the window between the Retry and this write included), or
    /// none at all, needs nothing; a live attempt is first marked
    /// ambiguous. The recovery authority accepts `resolved(rerun)`
    /// only once the Retry has replaced the attempt's Run; its
    /// refusal is returned.
    pub async fn resolve_rerun(
        &self,
        ws: WorkspaceId,
        step_attempt: StepAttemptId,
        decided_by: &str,
    ) -> Result<(), Failure> {
        self.resolve_as(ws, step_attempt, ResolutionKind::Rerun, decided_by)
            .await
    }

    /// `resolveAs` is `resolve_abandon` and `resolve_rerun`:
    /// `resolved(kind)` by `decided_by`.
    async fn resolve_as(
        &self,
        ws: WorkspaceId,
        step_attempt: StepAttemptId,
        kind: ResolutionKind,
        decided_by: &str,
    ) -> Result<(), Failure> {
        let id = attempt_id_for_step_attempt(step_attempt)?;
        let mut a = match self.store.load(ws, id).await {
            Err(e) if e.code() == codes::ATTEMPT_NOT_FOUND => return Ok(()),
            r => r?,
        };
        if a.state.is_terminal() {
            return Ok(());
        }
        let at = std::cmp::max(self.clock.now(), a.updated_at);
        if a.state != State::Ambiguous {
            let next = a.mark_ambiguous(a.fence, AMBIGUITY_RESTART, at)?;
            a = self.store.recover_attempt(&a, &next).await?;
        }
        let next = a.resolve(
            a.fence,
            Resolution {
                kind,
                decided_by: decided_by.to_string(),
            },
            at,
        )?;
        self.store.recover_attempt(&a, &next).await?;
        Ok(())
    }

    /// `FailUnlaunched` records `failed(harness_not_launched)` on the
    /// harness attempt linked to `step_attempt`, once execution
    /// `Cancel` settled that never-invoked StepAttempt (harness phase
    /// 3f decision 10): the reconciler's prepared-and-cancelled
    /// mapping for one attempt, with the row's own fence. No row (a
    /// prepared successor never re-claimed) or a terminal one needs
    /// nothing. A row that is not prepared is left to the next
    /// start's reconciler (the `INVALID_TRANSITION` failure returns).
    pub async fn fail_unlaunched(
        &self,
        ws: WorkspaceId,
        step_attempt: StepAttemptId,
    ) -> Result<(), Failure> {
        let id = attempt_id_for_step_attempt(step_attempt)?;
        let a = match self.store.load(ws, id).await {
            Err(e) if e.code() == codes::ATTEMPT_NOT_FOUND => return Ok(()),
            r => r?,
        };
        if a.state.is_terminal() || a.state != State::Prepared {
            // A row that launched is the reconciler's, not this
            // resolver's (upstream: "leaves a launched row to the
            // reconciler").
            return Ok(());
        }
        let at = std::cmp::max(self.clock.now(), a.updated_at);
        let next = a.fail_unlaunched(a.fence, at)?;
        self.store.recover_attempt(&a, &next).await?;
        Ok(())
    }

    /// `CompleteResume` records `resolved(resume)` by `decided_by` on
    /// the harness attempt linked to `step_attempt` (harness phase 3g
    /// decision 6). Idempotent: `resolved(resume)` already returns
    /// `Ok`. An ambiguous attempt gets `resolve(resume)` and
    /// `recover_attempt`; on `VERSION_CONFLICT` it reloads once and
    /// re-checks. No row returns `ATTEMPT_NOT_FOUND`; any other state
    /// (resolved(abandon), terminal, live) returns
    /// `RESUME_NOT_ALLOWED`.
    pub async fn complete_resume(
        &self,
        ws: WorkspaceId,
        step_attempt: StepAttemptId,
        decided_by: &str,
    ) -> Result<(), Failure> {
        let id = attempt_id_for_step_attempt(step_attempt)?;
        let mut reload = false;
        loop {
            let a = match self.store.load(ws, id).await {
                Err(e) if e.code() == codes::ATTEMPT_NOT_FOUND => {
                    return Err(Failure::not_found(
                        codes::ATTEMPT_NOT_FOUND,
                        format!("no harness attempt for step attempt {step_attempt}"),
                    ));
                }
                r => r?,
            };
            if a.state == State::Resolved && a.resolution.kind == ResolutionKind::Resume {
                return Ok(());
            }
            if a.state != State::Ambiguous {
                return Err(Failure::conflict(
                    codes::RESUME_NOT_ALLOWED,
                    format!("harness attempt is {}, not ambiguous", a.state.as_str()),
                ));
            }
            let at = std::cmp::max(self.clock.now(), a.updated_at);
            let next = a.resolve(
                a.fence,
                Resolution {
                    kind: ResolutionKind::Resume,
                    decided_by: decided_by.to_string(),
                },
                at,
            )?;
            match self.store.recover_attempt(&a, &next).await {
                Err(e) if e.code() == domain::codes::VERSION_CONFLICT && !reload => {
                    reload = true;
                }
                r => {
                    r?;
                    return Ok(());
                }
            }
        }
    }
}
