//! The execution facade — sealed execution-originated Task-domain
//! commands (ports `internal/task/execution_facade.go`).
//!
//! [`ExecutionTransition`] commands evaluate lifecycle changes without
//! a store, context, or persistence side effect so `central-execution`
//! can commit its own evidence atomically with the Task-domain change
//! set inside one composite transaction (harness phases 3a/3g).
//!
//! Each command carries explicit expected versions:
//! [`evaluate_execution_transition`] rejects omitted or sentinel
//! versions *before* touching the domain, so an execution caller can
//! never evaluate against a stale or create-semantics guard.
//!
//! Divergence from upstream: upstream leaves `MutationInput.Now` zero
//! on the Wait/Complete/Fail/SettleCancellation requests and lets the
//! domain fall back to wall-clock time. This port requires a
//! caller-supplied `now` on every request — the domain never reads a
//! clock (rust-application-boundaries.md §2.3 purity rule).

use central_foundation::failure::Failure;
use time::OffsetDateTime;

use crate::domain::{self, MutationInput, TaskAggregate, TaskChangeSet, WaitingReason, codes};

/// Claims a queued Task and its queued current Run (queued → running)
/// inside an execution-owned composite commit, so the claim and the
/// first StepAttempt and lease commit atomically (harness phase 3a
/// `StartHarnessRun`). `owner` is recorded as the Run's ownership
/// token.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionClaimRequest {
    /// The loaded aggregate.
    pub aggregate: TaskAggregate,
    /// The executor's claim token — non-blank.
    pub owner: String,
    /// The evaluation instant.
    pub now: OffsetDateTime,
    /// The caller's optimistic guards.
    pub expected_task_version: i64,
    /// The caller's optimistic guards.
    pub expected_run_version: i64,
}

/// Moves a running Task and Run into a typed wait state.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionWaitRequest {
    /// The loaded aggregate.
    pub aggregate: TaskAggregate,
    /// The wait classification.
    pub reason: Option<WaitingReason>,
    /// Bounded safe detail.
    pub detail: String,
    /// The evaluation instant.
    pub now: OffsetDateTime,
    /// The caller's optimistic guards.
    pub expected_task_version: i64,
    /// The caller's optimistic guards.
    pub expected_run_version: i64,
}

/// Moves the current Task/Run into its durable retry-delay state. The
/// execution aggregate closes the current StepAttempt before this Task
/// transition is committed.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionScheduleRetryRequest {
    /// The loaded aggregate.
    pub aggregate: TaskAggregate,
    /// The wait classification recorded on the retry event.
    pub reason: Option<WaitingReason>,
    /// When the retry becomes eligible; `None` means `now`.
    pub retry_at: Option<OffsetDateTime>,
    /// The evaluation instant.
    pub now: OffsetDateTime,
    /// The failed run's recorded failure.
    pub failure_note: String,
    /// The caller's optimistic guards.
    pub expected_task_version: i64,
    /// The caller's optimistic guards.
    pub expected_run_version: i64,
}

/// Completes a running Task and Run.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionCompleteRequest {
    /// The loaded aggregate.
    pub aggregate: TaskAggregate,
    /// The evaluation instant.
    pub now: OffsetDateTime,
    /// The caller's optimistic guards.
    pub expected_task_version: i64,
    /// The caller's optimistic guards.
    pub expected_run_version: i64,
}

/// Fails a running or waiting Task and Run.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionFailRequest {
    /// The loaded aggregate.
    pub aggregate: TaskAggregate,
    /// The terminal failure summary.
    pub reason: String,
    /// The evaluation instant.
    pub now: OffsetDateTime,
    /// The caller's optimistic guards.
    pub expected_task_version: i64,
    /// The caller's optimistic guards.
    pub expected_run_version: i64,
}

/// Settles cancellation for a cancelling Task and its current Run.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionSettleCancellationRequest {
    /// The loaded aggregate.
    pub aggregate: TaskAggregate,
    /// The evaluation instant.
    pub now: OffsetDateTime,
    /// The caller's optimistic guards.
    pub expected_task_version: i64,
    /// The caller's optimistic guards.
    pub expected_run_version: i64,
}

/// Re-queues the waiting Task and its same Run.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionResumeSameRunRequest {
    /// The loaded aggregate.
    pub aggregate: TaskAggregate,
    /// The evaluation instant.
    pub now: OffsetDateTime,
    /// The caller's optimistic guards.
    pub expected_task_version: i64,
    /// The caller's optimistic guards.
    pub expected_run_version: i64,
}

/// The sealed execution facade of [`domain::resume_reconciled_run`]:
/// it moves the reconciliation-waiting Task and its claimed Run back
/// to running, keeping the Run and its `ownership_token`.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionResumeReconciledRequest {
    /// The loaded aggregate.
    pub aggregate: TaskAggregate,
    /// The evaluation instant.
    pub now: OffsetDateTime,
    /// The caller's optimistic guards.
    pub expected_task_version: i64,
    /// The caller's optimistic guards.
    pub expected_run_version: i64,
}

/// A sealed execution-originated Task-domain command — the closed
/// Rust port of upstream's `ExecutionTransition` interface. The set is
/// exhaustive by construction: unsupported or nil transitions are
/// unrepresentable, so upstream's rejection of them needs no runtime
/// path.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionTransition {
    /// Queued → running claim (see [`ExecutionClaimRequest`]).
    Claim(ExecutionClaimRequest),
    /// Running → waiting (see [`ExecutionWaitRequest`]).
    Wait(ExecutionWaitRequest),
    /// Running/waiting → retry-delay waiting (see
    /// [`ExecutionScheduleRetryRequest`]).
    ScheduleRetry(ExecutionScheduleRetryRequest),
    /// Running → completed (see [`ExecutionCompleteRequest`]).
    Complete(ExecutionCompleteRequest),
    /// Running/waiting → failed (see [`ExecutionFailRequest`]).
    Fail(ExecutionFailRequest),
    /// Cancelling → cancelled (see
    /// [`ExecutionSettleCancellationRequest`]).
    SettleCancellation(ExecutionSettleCancellationRequest),
    /// Waiting → queued same-run resume (see
    /// [`ExecutionResumeSameRunRequest`]).
    ResumeSameRun(ExecutionResumeSameRunRequest),
    /// Reconciliation-waiting → running resume (see
    /// [`ExecutionResumeReconciledRequest`]).
    ResumeReconciled(ExecutionResumeReconciledRequest),
}

/// The non-committing Task-domain result to be included in an
/// execution-owned composite persistence transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionTransitionResult {
    /// The evaluated change set — committed by the caller, never by
    /// this facade.
    pub change_set: TaskChangeSet,
}

fn mutation_input(
    aggregate: TaskAggregate,
    now: OffsetDateTime,
    task_version: i64,
    run_version: i64,
) -> Result<MutationInput, Failure> {
    if task_version <= 0 {
        return Err(Failure::invalid(
            codes::INVALID,
            "explicit current task version required",
        ));
    }
    if aggregate.current_run.is_some() && run_version <= 0 {
        return Err(Failure::invalid(
            codes::INVALID,
            "explicit current run version required",
        ));
    }
    Ok(MutationInput {
        aggregate,
        expected_task_version: task_version,
        expected_run_version: run_version,
        now,
    })
}

/// Routes a sealed execution command only to the existing Task-domain
/// transition evaluators. It intentionally has no store or context and
/// therefore cannot commit independently.
pub fn evaluate_execution_transition(
    req: ExecutionTransition,
) -> Result<ExecutionTransitionResult, Failure> {
    let change_set = match req {
        ExecutionTransition::Claim(r) => {
            let input = mutation_input(
                r.aggregate,
                r.now,
                r.expected_task_version,
                r.expected_run_version,
            )?;
            domain::claim_current_run(domain::ClaimCurrentRunRequest {
                input,
                owner: r.owner,
            })?
        }
        ExecutionTransition::Wait(r) => {
            let input = mutation_input(
                r.aggregate,
                r.now,
                r.expected_task_version,
                r.expected_run_version,
            )?;
            domain::wait_task(domain::WaitTaskRequest {
                input,
                reason: r.reason,
                detail: r.detail,
            })?
        }
        ExecutionTransition::ScheduleRetry(r) => {
            let input = mutation_input(
                r.aggregate,
                r.now,
                r.expected_task_version,
                r.expected_run_version,
            )?;
            domain::schedule_run_retry(domain::ScheduleRunRetryRequest {
                input,
                reason: r.reason,
                retry_at: r.retry_at,
                failure_note: r.failure_note,
            })?
        }
        ExecutionTransition::Complete(r) => {
            let input = mutation_input(
                r.aggregate,
                r.now,
                r.expected_task_version,
                r.expected_run_version,
            )?;
            domain::complete_task(domain::CompleteTaskRequest { input })?
        }
        ExecutionTransition::Fail(r) => {
            let input = mutation_input(
                r.aggregate,
                r.now,
                r.expected_task_version,
                r.expected_run_version,
            )?;
            domain::fail_task(domain::FailTaskRequest {
                input,
                reason: r.reason,
            })?
        }
        ExecutionTransition::SettleCancellation(r) => {
            let input = mutation_input(
                r.aggregate,
                r.now,
                r.expected_task_version,
                r.expected_run_version,
            )?;
            domain::settle_cancellation(domain::SettleCancellationRequest { input })?
        }
        ExecutionTransition::ResumeSameRun(r) => {
            let input = mutation_input(
                r.aggregate,
                r.now,
                r.expected_task_version,
                r.expected_run_version,
            )?;
            domain::resume_same_run(domain::ResumeSameRunRequest { input })?
        }
        ExecutionTransition::ResumeReconciled(r) => {
            let input = mutation_input(
                r.aggregate,
                r.now,
                r.expected_task_version,
                r.expected_run_version,
            )?;
            domain::resume_reconciled_run(domain::ResumeReconciledRunRequest { input })?
        }
    };
    Ok(ExecutionTransitionResult { change_set })
}

// ---------------------------------------------------------------------------
// Tests — port of internal/task/{execution_facade_test,
// execution_facade_claim_test}.go and the facade-routing case of
// resume_reconciled_test.go.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{self, RunStatus, SubmitTaskRequest, TaskStatus, WaitTaskRequest};
    use central_foundation::failure::FailureKind;
    use central_foundation::identity::WorkspaceId;
    use time::macros::datetime;

    const T0: OffsetDateTime = datetime!(2026-07-27 12:00 UTC);
    const CLAIM_NOW: OffsetDateTime = datetime!(2026-09-28 12:00 UTC);

    fn apply(cs: &domain::TaskChangeSet) -> domain::TaskAggregate {
        domain::TaskAggregate {
            task: cs.task.clone(),
            current_run: cs.runs.first().cloned(),
        }
    }

    fn queued_aggregate() -> domain::TaskAggregate {
        let cs = domain::submit_task(SubmitTaskRequest {
            workspace_id: WorkspaceId::new(),
            title: "execution facade claim".to_string(),
            input: "input".to_string(),
            permission_policy: None,
            budget: domain::Budget::default(),
            run_key: None,
            now: CLAIM_NOW - time::Duration::hours(1),
        })
        .unwrap();
        apply(&cs)
    }

    fn running_aggregate() -> domain::TaskAggregate {
        let cs = domain::submit_task(SubmitTaskRequest {
            workspace_id: WorkspaceId::new(),
            title: "execution facade task".to_string(),
            input: "input".to_string(),
            permission_policy: None,
            budget: domain::Budget::default(),
            run_key: None,
            now: T0,
        })
        .unwrap();
        let claimed = domain::claim_current_run(domain::ClaimCurrentRunRequest {
            input: domain::MutationInput {
                aggregate: apply(&cs),
                expected_task_version: cs.task.version,
                expected_run_version: cs.runs[0].version,
                now: T0 + time::Duration::seconds(1),
            },
            owner: "executor".to_string(),
        })
        .unwrap();
        apply(&claimed)
    }

    fn cancelling_aggregate() -> domain::TaskAggregate {
        let running = running_aggregate();
        let cs = domain::request_cancellation(domain::RequestCancellationRequest {
            input: domain::MutationInput {
                aggregate: running.clone(),
                expected_task_version: running.task.version,
                expected_run_version: running.current_run.as_ref().unwrap().version,
                now: T0 + time::Duration::seconds(2),
            },
        })
        .unwrap();
        apply(&cs)
    }

    fn versions(agg: &domain::TaskAggregate) -> (i64, i64) {
        (
            agg.task.version,
            agg.current_run.as_ref().map_or(0, |r| r.version),
        )
    }

    // -- execution_facade_claim_test.go --------------------------------------

    /// Harness phase 3a facade case: the dispatcher claims the queued
    /// task and run through the task domain's own `claim_current_run`,
    /// inside the execution change set — without committing.
    #[test]
    fn facade_claims_queued_run_without_committing() {
        let aggregate = queued_aggregate();
        let (tv, rv) = versions(&aggregate);
        let change =
            evaluate_execution_transition(ExecutionTransition::Claim(ExecutionClaimRequest {
                aggregate: aggregate.clone(),
                owner: "harness-dispatcher".to_string(),
                now: CLAIM_NOW,
                expected_task_version: tv,
                expected_run_version: rv,
            }))
            .unwrap()
            .change_set;
        assert_eq!(change.task.status, TaskStatus::Running);
        assert_eq!(change.runs.len(), 1);
        assert_eq!(change.runs[0].status, RunStatus::Running);
        assert_eq!(change.runs[0].ownership_token, "harness-dispatcher");
        assert_eq!(change.expected_task_version, tv);
        assert_eq!(
            change
                .run_expected_versions
                .get(&aggregate.current_run.unwrap().id),
            Some(&rv)
        );
        assert_eq!(change.events.len(), 2);
        assert_eq!(change.events[0].kind, domain::EventKind::TaskClaimed);
        assert_eq!(change.events[0].occurred_at, CLAIM_NOW);
    }

    #[test]
    fn facade_claim_rejects_non_queued_and_missing_versions() {
        let queued = queued_aggregate();
        let (qtv, qrv) = versions(&queued);
        let running = running_aggregate();
        for (name, req) in [
            (
                "running task",
                ExecutionClaimRequest {
                    aggregate: running,
                    owner: "w".to_string(),
                    now: CLAIM_NOW,
                    expected_task_version: 2,
                    expected_run_version: 2,
                },
            ),
            (
                "omitted task version",
                ExecutionClaimRequest {
                    aggregate: queued.clone(),
                    owner: "w".to_string(),
                    now: CLAIM_NOW,
                    expected_task_version: 0,
                    expected_run_version: qrv,
                },
            ),
            (
                "omitted run version",
                ExecutionClaimRequest {
                    aggregate: queued,
                    owner: "w".to_string(),
                    now: CLAIM_NOW,
                    expected_task_version: qtv,
                    expected_run_version: 0,
                },
            ),
        ] {
            let err = evaluate_execution_transition(ExecutionTransition::Claim(req)).unwrap_err();
            assert!(
                matches!(
                    err.kind(),
                    FailureKind::Invalid | FailureKind::Denied | FailureKind::Conflict
                ),
                "{name}: {err:?}"
            );
        }
    }

    // -- execution_facade_test.go --------------------------------------------

    #[test]
    fn facade_waits_without_committing() {
        let aggregate = running_aggregate();
        let (tv, rv) = versions(&aggregate);
        let change =
            evaluate_execution_transition(ExecutionTransition::Wait(ExecutionWaitRequest {
                aggregate: aggregate.clone(),
                reason: Some(WaitingReason::Reconciliation),
                detail: String::new(),
                now: T0 + time::Duration::seconds(3),
                expected_task_version: tv,
                expected_run_version: rv,
            }))
            .unwrap()
            .change_set;
        assert_eq!(change.task.status, TaskStatus::Waiting);
        assert_eq!(change.expected_task_version, tv);
        assert_eq!(
            change
                .run_expected_versions
                .get(&aggregate.current_run.unwrap().id),
            Some(&rv)
        );
    }

    #[test]
    fn facade_rejects_omitted_and_sentinel_versions() {
        let aggregate = running_aggregate();
        let (tv, rv) = versions(&aggregate);
        let valid = ExecutionWaitRequest {
            aggregate,
            reason: Some(WaitingReason::Reconciliation),
            detail: String::new(),
            now: T0 + time::Duration::seconds(3),
            expected_task_version: tv,
            expected_run_version: rv,
        };
        for (name, task_v, run_v) in [
            ("omitted task version", 0, rv),
            ("omitted run version", tv, 0),
            ("task sentinel", domain::NO_EXISTING_VERSION, rv),
            ("run sentinel", tv, domain::NO_EXISTING_VERSION),
        ] {
            let mut req = valid.clone();
            req.expected_task_version = task_v;
            req.expected_run_version = run_v;
            let err = evaluate_execution_transition(ExecutionTransition::Wait(req)).unwrap_err();
            assert_eq!(err.kind(), FailureKind::Invalid, "{name}");
        }
    }

    #[test]
    fn facade_rejects_stale_version_guards() {
        let aggregate = running_aggregate();
        let (tv, rv) = versions(&aggregate);
        let valid = ExecutionWaitRequest {
            aggregate,
            reason: Some(WaitingReason::Reconciliation),
            detail: String::new(),
            now: T0 + time::Duration::seconds(3),
            expected_task_version: tv,
            expected_run_version: rv,
        };
        for (name, task_v, run_v) in [("task", tv - 1, rv), ("run", tv, rv - 1)] {
            let mut req = valid.clone();
            req.expected_task_version = task_v;
            req.expected_run_version = run_v;
            let err = evaluate_execution_transition(ExecutionTransition::Wait(req)).unwrap_err();
            assert_eq!(err.kind(), FailureKind::Conflict, "{name}");
        }
    }

    #[test]
    fn facade_completes_fails_and_settles_cancellation() {
        let aggregate = running_aggregate();
        let (tv, rv) = versions(&aggregate);
        let change = evaluate_execution_transition(ExecutionTransition::Complete(
            ExecutionCompleteRequest {
                aggregate,
                now: T0 + time::Duration::seconds(3),
                expected_task_version: tv,
                expected_run_version: rv,
            },
        ))
        .unwrap()
        .change_set;
        assert_eq!(change.task.status, TaskStatus::Completed);

        let aggregate = running_aggregate();
        let (tv, rv) = versions(&aggregate);
        let change =
            evaluate_execution_transition(ExecutionTransition::Fail(ExecutionFailRequest {
                aggregate,
                reason: "execution failure".to_string(),
                now: T0 + time::Duration::seconds(3),
                expected_task_version: tv,
                expected_run_version: rv,
            }))
            .unwrap()
            .change_set;
        assert_eq!(change.task.status, TaskStatus::Failed);

        let aggregate = cancelling_aggregate();
        let (tv, rv) = versions(&aggregate);
        let change = evaluate_execution_transition(ExecutionTransition::SettleCancellation(
            ExecutionSettleCancellationRequest {
                aggregate,
                now: T0 + time::Duration::seconds(4),
                expected_task_version: tv,
                expected_run_version: rv,
            },
        ))
        .unwrap()
        .change_set;
        assert_eq!(change.task.status, TaskStatus::Cancelled);
    }

    #[test]
    fn facade_resumes_same_run_without_committing() {
        let running = running_aggregate();
        let (tv, rv) = versions(&running);
        let waited = domain::wait_task(WaitTaskRequest {
            input: domain::MutationInput {
                aggregate: running,
                expected_task_version: tv,
                expected_run_version: rv,
                now: T0 + time::Duration::seconds(2),
            },
            reason: Some(WaitingReason::Approval),
            detail: "approval required".to_string(),
        })
        .unwrap();
        let waiting = apply(&waited);
        let now = datetime!(2026-07-27 12:30 UTC);
        let (tv, rv) = versions(&waiting);
        let change = evaluate_execution_transition(ExecutionTransition::ResumeSameRun(
            ExecutionResumeSameRunRequest {
                aggregate: waiting,
                now,
                expected_task_version: tv,
                expected_run_version: rv,
            },
        ))
        .unwrap()
        .change_set;
        assert_eq!(change.task.status, TaskStatus::Queued);
        assert_eq!(change.runs.len(), 1);
        assert_eq!(change.runs[0].status, RunStatus::Queued);
        assert_eq!(change.task.updated_at, now);
    }

    /// Upstream rejects nil and unknown `ExecutionTransition`
    /// implementations; the sealed Rust enum makes both
    /// unrepresentable at compile time. This test pins the remaining
    /// runtime guard — a request whose versions are omitted — so the
    /// facade's total-rejection surface stays exercised.
    #[test]
    fn facade_rejects_unsupported_and_nil_transitions() {
        // `ExecutionTransition` is a closed enum: `nil` and unknown
        // implementations are unconstructable (upstream's two rejected
        // cases). A zero-versioned request is the nearest expressible
        // "empty" command.
        let err = evaluate_execution_transition(ExecutionTransition::Complete(
            ExecutionCompleteRequest {
                aggregate: running_aggregate(),
                now: T0,
                expected_task_version: 0,
                expected_run_version: 0,
            },
        ))
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Invalid);
    }

    // -- resume_reconciled_test.go: facade routing ----------------------------

    /// `ExecutionResumeReconciledRequest` must route to
    /// `domain::resume_reconciled_run` — the routed change set is
    /// field-for-field the direct evaluation's (the two transitions
    /// differ: same-run resume goes waiting → queued; reconciled
    /// resume goes reconciliation-waiting → running under the same
    /// claim).
    #[test]
    fn facade_resume_reconciled_routes_to_the_transition() {
        let running = running_aggregate();
        let (tv, rv) = versions(&running);
        let waited = domain::wait_task(WaitTaskRequest {
            input: domain::MutationInput {
                aggregate: running,
                expected_task_version: tv,
                expected_run_version: rv,
                now: T0 + time::Duration::seconds(2),
            },
            reason: Some(WaitingReason::Reconciliation),
            detail: "reconciled".to_string(),
        })
        .unwrap();
        let agg = apply(&waited);
        let now = datetime!(2026-07-27 13:00 UTC);
        let (tv, rv) = versions(&agg);

        let direct = domain::resume_reconciled_run(domain::ResumeReconciledRunRequest {
            input: domain::MutationInput {
                aggregate: agg.clone(),
                expected_task_version: tv,
                expected_run_version: rv,
                now,
            },
        })
        .unwrap();
        let got = evaluate_execution_transition(ExecutionTransition::ResumeReconciled(
            ExecutionResumeReconciledRequest {
                aggregate: agg.clone(),
                now,
                expected_task_version: tv,
                expected_run_version: rv,
            },
        ))
        .unwrap()
        .change_set;
        assert_eq!(got.task.status, direct.task.status);
        assert_eq!(got.task.version, direct.task.version);
        assert_eq!(got.runs.len(), 1);
        assert_eq!(got.runs[0].id, direct.runs[0].id);
        assert_eq!(got.runs[0].status, direct.runs[0].status);
        assert_eq!(got.runs[0].version, direct.runs[0].version);
        assert_eq!(got.runs[0].ownership_token, direct.runs[0].ownership_token);
        assert_eq!(got.expected_task_version, direct.expected_task_version);
        assert_eq!(got.events.len(), direct.events.len());
        assert_eq!(got.events[0].kind, direct.events[0].kind);
        assert_eq!(got.events[1].detail, direct.events[1].detail);

        // An omitted task-version guard is rejected before routing.
        let err = evaluate_execution_transition(ExecutionTransition::ResumeReconciled(
            ExecutionResumeReconciledRequest {
                aggregate: agg,
                now,
                expected_task_version: 0,
                expected_run_version: rv,
            },
        ))
        .unwrap_err();
        assert_eq!(err.kind(), FailureKind::Invalid);
    }
}
