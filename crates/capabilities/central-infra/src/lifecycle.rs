//! `lifecycle` — the B03 infrastructure lifecycle application service
//! (upstream `internal/infralifecycle/app/service.go`). It composes the
//! domain journal/topology ports with the inward admission, bootstrap,
//! capacity, barrier, locker, and clock ports into crash-safe `up`,
//! `down`, and `status` operations.
//!
//! Cancellation is future-drop: upstream's `ctx.Done()` arm maps to
//! dropping the returned future; the durable journal records every
//! settled outcome so a dropped operation stays resumable.

use std::time::Duration;

use time::OffsetDateTime;

use crate::domain::{
    DependencyReceipt, LifecycleBinding, LifecycleOperation, LifecyclePhase, LifecycleRequest,
    LifecycleResult, LifecycleStatusRequest, Observation, PreparedDependencySet, SemanticReceipt,
};
use crate::port::{
    AdmissionRequest, BootstrapPurpose, LifecycleAdmission, LifecycleBarrier, LifecycleBootstrap,
    LifecycleCapacity, LifecycleClock, LifecycleLock, LifecycleLocker, LifecyclePort, TopologyPort,
};
use central_foundation::failure::Failure;

/// `provisionDeadline` — the B03 overall `up` budget.
pub const PROVISION_DEADLINE: Duration = Duration::from_secs(400);
/// `fsInitBudget`.
pub const FS_INIT_BUDGET: Duration = Duration::from_secs(30);
/// `daemonBudget`.
pub const DAEMON_BUDGET: Duration = Duration::from_secs(120);
/// `provisionBudget`.
pub const PROVISION_BUDGET: Duration = Duration::from_secs(120);
/// `semanticBudget`.
pub const SEMANTIC_BUDGET: Duration = Duration::from_secs(20);
/// `selectorBudget`.
pub const SELECTOR_BUDGET: Duration = Duration::from_secs(5);
/// `daemonHealthBudget`.
pub const DAEMON_HEALTH_BUDGET: Duration = Duration::from_secs(120);
/// `cleanupBudget`.
pub const CLEANUP_BUDGET: Duration = Duration::from_secs(5);
/// `downBudget`.
pub const DOWN_BUDGET: Duration = Duration::from_secs(90);
/// `statusBudget`.
pub const STATUS_BUDGET: Duration = Duration::from_secs(3);

/// `Service` — the infrastructure lifecycle application service. The
/// ports are the exact seams upstream injects; `capacity` and `barrier`
/// are optional (`nil`-equivalent) as upstream permits. Generics follow
/// the house pattern: `Arc<T>` satisfies each port via the blanket
/// forwarding impls.
pub struct LifecycleService<A, B, J, T, C, R, L, K>
where
    A: LifecycleAdmission,
    B: LifecycleBootstrap,
    J: LifecyclePort,
    T: TopologyPort,
    C: LifecycleCapacity,
    R: LifecycleBarrier,
    L: LifecycleLocker,
    K: LifecycleClock,
{
    /// B01/B02 receipt admission verification.
    pub admission: A,
    /// Host bootstrap artifact authority.
    pub bootstrap: B,
    /// The durable lifecycle journal.
    pub journal: J,
    /// The orchestration boundary.
    pub topology: T,
    /// Optional capacity admission.
    pub capacity: Option<C>,
    /// Optional writable-start barrier.
    pub barrier: Option<R>,
    /// The lifecycle lock.
    pub locker: L,
    /// The deadline clock.
    pub clock: K,
}

impl<A, B, J, T, C, R, L, K> LifecycleService<A, B, J, T, C, R, L, K>
where
    A: LifecycleAdmission,
    B: LifecycleBootstrap,
    J: LifecyclePort,
    T: TopologyPort,
    C: LifecycleCapacity,
    R: LifecycleBarrier,
    L: LifecycleLocker,
    K: LifecycleClock,
{
    // ---------------------------------------------------------------------
    // Up
    // ---------------------------------------------------------------------

    /// `Up` — starts or resumes an infrastructure lifecycle. Follows
    /// upstream's phase machine exactly, recovering the most recent
    /// unsettled operation for the binding on resume.
    pub async fn up(&self, req: LifecycleRequest) -> LifecycleResult {
        self.up_with_deadline(req, None).await
    }

    /// `Up(ctx, req)` — `cancel_at` is upstream's caller context
    /// deadline: the helper computes it from the verb budget before
    /// driving the state machine, and the loop arm checks it each
    /// iteration exactly where upstream's `select ctx.Done()` sits.
    /// `None` is upstream's `context.Background()`.
    pub async fn up_with_deadline(
        &self,
        req: LifecycleRequest,
        cancel_at: Option<OffsetDateTime>,
    ) -> LifecycleResult {
        let binding = binding_from_request(&req);

        let lock = match self.locker.acquire(&binding).await {
            Ok(l) => l,
            Err(e) => {
                return result_error(
                    "",
                    "",
                    &format!("LOCK_FAILED: {e}"),
                    LifecyclePhase::Failed,
                    1,
                );
            }
        };
        let mut result = self.up_locked(&binding, &lock, cancel_at).await;
        if let Err(e) = self.locker.release(&binding, lock).await {
            if result.exit_code == 0 {
                result = result_error(
                    "",
                    "",
                    &format!("LOCK_RELEASE_FAILED: {e}"),
                    LifecyclePhase::Failed,
                    1,
                );
            } else {
                result.reason = format!("{}; LOCK_RELEASE_FAILED: {e}", result.reason);
            }
        }
        result
    }

    async fn up_locked(
        &self,
        binding: &LifecycleBinding,
        lock: &LifecycleLock,
        cancel_at: Option<OffsetDateTime>,
    ) -> LifecycleResult {
        match self.journal.unsettled(binding).await {
            Err(e) => result_error(
                "",
                "",
                &format!("UNSETTLED_CHECK_FAILED: {e}"),
                LifecyclePhase::Failed,
                1,
            ),
            Ok(Some(existing)) => {
                let bound = with_b04_evidence(binding, &existing, lock);
                self.up_execute(existing, bound, cancel_at).await
            }
            Ok(None) => match self
                .journal
                .begin(binding.clone(), Observation::default())
                .await
            {
                Err(e) => result_error(
                    "",
                    "",
                    &format!("BEGIN_FAILED: {e}"),
                    LifecyclePhase::Failed,
                    1,
                ),
                Ok(op) => {
                    let bound = with_b04_evidence(binding, &op, lock);
                    self.up_execute(op, bound, cancel_at).await
                }
            },
        }
    }

    async fn up_execute(
        &self,
        mut op: LifecycleOperation,
        binding: LifecycleBinding,
        cancel_at: Option<OffsetDateTime>,
    ) -> LifecycleResult {
        let deadline = op.created_at + PROVISION_DEADLINE;
        if self.clock.now() > deadline {
            return self.settle_fail(&op, "DEADLINE_EXCEEDED".to_owned()).await;
        }

        let mut phase = op.phase;
        let mut admitted: Option<PreparedDependencySet>;
        if phase.is_terminal() {
            // Terminal: start from the beginning. (Upstream's empty-phase
            // case is unreachable — the enum has no empty variant.)
            phase = LifecyclePhase::Started;
        }

        loop {
            // Upstream's `select ctx.Done()` arm: the caller's deadline —
            // the helper verb budget — cancels the operation into a
            // settled `cancelled` before the phase work begins.
            if let Some(cancel_at) = cancel_at
                && self.clock.now() >= cancel_at
            {
                return self
                    .settle_cancel(&op, "CANCELLED: context deadline exceeded".to_owned())
                    .await;
            }
            if self.clock.now() > deadline {
                return self.settle_fail(&op, "DEADLINE_EXCEEDED".to_owned()).await;
            }

            // Upstream's `phaseDeadline` context: the phase's own budget
            // bounds every I/O call inside this iteration. The only
            // in-service loop the budget can interrupt is
            // `wait_for_healthy`; the synchronous port calls inherit the
            // operation deadline at the loop head above.
            let phase_deadline_at = cancel_at
                .map(|d| d.min(self.clock.now() + phase_deadline(phase)))
                .unwrap_or_else(|| self.clock.now() + phase_deadline(phase));

            let next = match phase {
                LifecyclePhase::Started => {
                    let admitted = match self.verify_admission(&binding).await {
                        Ok(set) => set,
                        Err(reason) => return self.settle_fail(&op, reason).await,
                    };
                    if let Some(capacity) = &self.capacity
                        && let Err(e) = capacity.admit(&binding, &admitted).await
                    {
                        return self.settle_fail(&op, format!("CAPACITY_DENIED: {e}")).await;
                    }
                    if let Some(barrier) = &self.barrier
                        && let Err(e) = barrier.validate_writable_start(&binding).await
                    {
                        return self.settle_fail(&op, format!("BARRIER_DENIED: {e}")).await;
                    }
                    if let Err(e) = self
                        .bootstrap
                        .ensure(&binding, BootstrapPurpose::FirstSetup)
                        .await
                    {
                        return self
                            .settle_fail(&op, format!("BOOTSTRAP_ENSURE_FAILED: {e}"))
                            .await;
                    }
                    LifecyclePhase::Verified
                }
                LifecyclePhase::Verified => {
                    if let Err(e) = self.topology.validate(&binding).await {
                        return self.settle_fail(&op, format!("VALIDATE_FAILED: {e}")).await;
                    }
                    if let Err(e) = self.topology.init(&op).await {
                        return self.settle_fail(&op, format!("INIT_FAILED: {e}")).await;
                    }
                    LifecyclePhase::FsInitialized
                }
                LifecyclePhase::FsInitialized => {
                    if let Err(e) = self.topology.start_daemons(&op).await {
                        return self
                            .settle_fail(&op, format!("START_DAEMONS_FAILED: {e}"))
                            .await;
                    }
                    LifecyclePhase::DaemonsStarted
                }
                LifecyclePhase::DaemonsStarted => {
                    if let Err(e) = self.wait_for_healthy(&binding, phase_deadline_at).await {
                        return self
                            .settle_fail(&op, format!("CONTAINER_HEALTH_FAILED: {e}"))
                            .await;
                    }
                    LifecyclePhase::ContainersHealthy
                }
                LifecyclePhase::ContainersHealthy => {
                    // ADR 0019/0026: no postgres-provision step; the
                    // daemon's verified healthy first boot established
                    // the role topology. See upstream's comment.
                    LifecyclePhase::PostgresProvisioned
                }
                LifecyclePhase::PostgresProvisioned => {
                    // SC-DEF-28: thread the B04-attached binding into the
                    // provisioning operation so the fence token is real.
                    let mut provisioning_op = op.clone();
                    provisioning_op.binding = binding.clone();
                    match self.topology.provision_minio(&provisioning_op).await {
                        Err(e) => {
                            return self
                                .settle_fail(&op, format!("PROVISION_MINIO_FAILED: {e}"))
                                .await;
                        }
                        Ok(sr) => {
                            if let Err(e) = verify_semantic_receipt(&sr, "minio") {
                                return self
                                    .settle_fail(
                                        &op,
                                        format!("MINIO_SEMANTIC_VERIFICATION_FAILED: {e}"),
                                    )
                                    .await;
                            }
                        }
                    }
                    LifecyclePhase::MinioProvisioned
                }
                LifecyclePhase::MinioProvisioned => LifecyclePhase::SemanticVerified,
                LifecyclePhase::SemanticVerified => {
                    // Reinspect B01/B02 immediately before preparing the
                    // selector-visible receipt.
                    match self.verify_admission(&binding).await {
                        Ok(set) => admitted = Some(set),
                        Err(reason) => {
                            let reason = reason.replacen(
                                "ADMISSION_FAILED",
                                "ADMISSION_REINSPECTION_FAILED",
                                1,
                            );
                            return self.settle_fail(&op, reason).await;
                        }
                    }
                    let receipt = DependencyReceipt {
                        id: binding.receipt_id.clone(),
                        dependency_set: admitted.clone().unwrap_or_default(),
                        ..DependencyReceipt::default()
                    };
                    if let Err(e) = self.journal.prepare_receipt(&op, &receipt).await {
                        return self
                            .settle_fail(&op, format!("PREPARE_RECEIPT_FAILED: {e}"))
                            .await;
                    }
                    LifecyclePhase::ReceiptPrepared
                }
                LifecyclePhase::ReceiptPrepared => {
                    if let Err(e) = self.topology.inspect(&binding).await {
                        return self
                            .settle_fail(&op, format!("REINSPECT_FAILED: {e}"))
                            .await;
                    }
                    if let Err(e) = self.journal.switch_receipt(&op).await {
                        // Switch failed — the selector was NOT published.
                        return self
                            .settle_at(
                                &op,
                                LifecyclePhase::ReceiptPrepared,
                                format!("SWITCH_RECEIPT_FAILED: {e}"),
                                1,
                            )
                            .await;
                    }
                    LifecyclePhase::ReceiptSelectorSwitched
                }
                LifecyclePhase::ReceiptSelectorSwitched => {
                    // The MinIO server-scoped handoff stays mounted for
                    // the daemon's lifetime; Down owns cleanup.
                    if let Err(e) = self.journal.settle(&op, LifecyclePhase::Completed).await {
                        return self.settle_fail(&op, format!("SETTLE_FAILED: {e}")).await;
                    }
                    LifecyclePhase::Completed
                }
                LifecyclePhase::Completed => {
                    return result_with_state(
                        &op,
                        LifecyclePhase::Completed,
                        "MIGRATION_REQUIRED",
                        "completed",
                        0,
                    );
                }
                other => {
                    return self
                        .settle_fail(&op, format!("UNKNOWN_PHASE: {}", other.as_str()))
                        .await;
                }
            };

            if let Err(e) = self.journal.record(&op, next).await {
                if phase == LifecyclePhase::ReceiptPrepared {
                    return self
                        .settle_at(
                            &op,
                            LifecyclePhase::ReceiptPrepared,
                            format!("RECORD_FAILED_AFTER_SWITCH: {e}"),
                            1,
                        )
                        .await;
                }
                return self.settle_fail(&op, format!("RECORD_FAILED: {e}")).await;
            }
            op.phase = next;
            phase = next;
        }
    }

    async fn verify_admission(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<PreparedDependencySet, String> {
        let adm = self
            .admission
            .verify(AdmissionRequest {
                instance_id: binding.instance_id.clone(),
                config_binding: binding.config_binding.clone(),
                receipt_id: binding.receipt_id.clone(),
                model_digest: binding.model_digest.clone(),
                payload_epoch: binding.payload_epoch.clone(),
            })
            .await
            .map_err(|e| format!("ADMISSION_FAILED: {e}"))?;
        if adm.receipt_id != binding.receipt_id {
            return Err("ADMISSION_FAILED: receipt binding mismatch".to_owned());
        }
        adm.prepared
            .validate_b03()
            .map_err(|e| format!("ADMISSION_FAILED: invalid prepared dependency set: {e}"))?;
        Ok(adm.prepared)
    }

    /// `waitForHealthy` — polls topology health every 250 ms until the
    /// phase deadline (`min(daemonHealthBudget, caller deadline)`,
    /// upstream's `select ctx.Done() / time.After(250ms)`).
    async fn wait_for_healthy(
        &self,
        binding: &LifecycleBinding,
        deadline: OffsetDateTime,
    ) -> Result<(), Failure> {
        loop {
            let snapshot = self.topology.inspect(binding).await?;
            if snapshot.healthy {
                return Ok(());
            }
            if self.clock.now() >= deadline {
                // Upstream surfaces `context.DeadlineExceeded` here; the
                // Cancelled kind is the failure taxonomy's deadline class.
                return Err(Failure::cancelled(
                    "deadline_exceeded",
                    "container health wait: deadline exceeded",
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    // ---------------------------------------------------------------------
    // Down
    // ---------------------------------------------------------------------

    /// `Down` — tears down the infrastructure: linked stop-settlement,
    /// verified teardown, then credential cleanup, then settle.
    pub async fn down(&self, req: LifecycleRequest) -> LifecycleResult {
        self.down_with_deadline(req, None).await
    }

    /// `Down(ctx, req)` — `cancel_at` is the caller's deadline; the
    /// teardown work is further bounded by `DOWN_BUDGET` exactly as
    /// upstream's `context.WithDeadline(ctx, now+downBudget)`.
    pub async fn down_with_deadline(
        &self,
        req: LifecycleRequest,
        cancel_at: Option<OffsetDateTime>,
    ) -> LifecycleResult {
        let binding = binding_from_request(&req);

        let lock = match self.locker.acquire(&binding).await {
            Ok(l) => l,
            Err(e) => {
                return result_error(
                    "",
                    "",
                    &format!("DOWN_LOCK_FAILED: {e}"),
                    LifecyclePhase::Failed,
                    1,
                );
            }
        };
        let mut result = self.down_locked(&binding, cancel_at).await;
        if let Err(e) = self.locker.release(&binding, lock).await {
            if result.exit_code == 0 {
                result = result_error(
                    "",
                    "",
                    &format!("DOWN_LOCK_RELEASE_FAILED: {e}"),
                    LifecyclePhase::Failed,
                    1,
                );
            } else {
                result.reason = format!("{}; DOWN_LOCK_RELEASE_FAILED: {e}", result.reason);
            }
        }
        result
    }

    async fn down_locked(
        &self,
        binding: &LifecycleBinding,
        cancel_at: Option<OffsetDateTime>,
    ) -> LifecycleResult {
        let linked_op = match self.journal.unsettled(binding).await {
            Err(e) => {
                return result_error(
                    "",
                    "",
                    &format!("DOWN_UNSETTLED_FAILED: {e}"),
                    LifecyclePhase::Failed,
                    1,
                );
            }
            Ok(existing) => existing,
        };

        let op = match &linked_op {
            Some(linked) => {
                self.journal
                    .begin_linked_down(binding.clone(), Observation::default(), linked)
                    .await
            }
            None => {
                self.journal
                    .begin(binding.clone(), Observation::default())
                    .await
            }
        };
        let op = match op {
            Ok(o) => o,
            Err(e) => {
                return result_error(
                    "",
                    "",
                    &format!("DOWN_BEGIN_FAILED: {e}"),
                    LifecyclePhase::Failed,
                    1,
                );
            }
        };

        if let Err(e) = self.journal.record(&op, LifecyclePhase::Started).await {
            return self
                .settle_fail(&op, format!("DOWN_RECORD_FAILED: {e}"))
                .await;
        }

        // Upstream: `teardownCtx = context.WithDeadline(ctx,
        // now+downBudget)` — the teardown window is bounded by the
        // earlier of the caller's deadline and the down budget.
        let deadline = cancel_at
            .map(|d| d.min(self.clock.now() + DOWN_BUDGET))
            .unwrap_or_else(|| self.clock.now() + DOWN_BUDGET);
        if self.clock.now() >= deadline {
            return self
                .settle_fail(
                    &op,
                    "DOWN_TEARDOWN_VERIFICATION_FAILED: deadline exceeded".to_owned(),
                )
                .await;
        }

        if let Err(e) = self.topology.teardown_verified(&op).await {
            // Keep the MinIO handoff when stopped proof is unavailable.
            return self
                .settle_fail(&op, format!("DOWN_TEARDOWN_VERIFICATION_FAILED: {e}"))
                .await;
        }
        if let Err(e) = self.cleanup_bootstrap(&op).await {
            return self
                .settle_fail(&op, format!("BOOTSTRAP_CLEANUP_FAILED: {e}"))
                .await;
        }

        if let Some(linked) = linked_op
            && let Err(e) = self.journal.settle(&linked, LifecyclePhase::Failed).await
        {
            return self
                .settle_fail(&op, format!("LINKED_SETTLE_FAILED: {e}"))
                .await;
        }

        if let Err(e) = self.journal.settle(&op, LifecyclePhase::Completed).await {
            return self
                .settle_fail(&op, format!("DOWN_SETTLE_FAILED: {e}"))
                .await;
        }

        result_from_op(
            &op,
            LifecyclePhase::Completed,
            "down_completed".to_owned(),
            0,
        )
    }

    // ---------------------------------------------------------------------
    // Status
    // ---------------------------------------------------------------------

    /// `Status` — strictly read-only topology inspection.
    pub async fn status(&self, req: LifecycleStatusRequest) -> LifecycleResult {
        self.status_with_deadline(req, None).await
    }

    /// `Status(ctx, req)` — upstream wraps the inspect in
    /// `context.WithDeadline(ctx, now+statusBudget)`; the port's
    /// synchronous inspect cannot be interrupted mid-call, so the
    /// budget check runs before the call begins.
    pub async fn status_with_deadline(
        &self,
        req: LifecycleStatusRequest,
        cancel_at: Option<OffsetDateTime>,
    ) -> LifecycleResult {
        let binding = LifecycleBinding {
            instance_id: req.instance_id,
            config_binding: req.config_binding,
            admission_id: String::new(),
            receipt_id: String::new(),
            model_digest: String::new(),
            payload_epoch: String::new(),
            bootstrap_fingerprints: Vec::new(),
            b04: crate::domain::B04LifecycleEvidence::default(),
        };

        let deadline = cancel_at
            .map(|d| d.min(self.clock.now() + STATUS_BUDGET))
            .unwrap_or_else(|| self.clock.now() + STATUS_BUDGET);
        if self.clock.now() >= deadline {
            return result_error(
                "",
                "",
                "INSPECT_FAILED: deadline exceeded",
                LifecyclePhase::Failed,
                1,
            );
        }

        match self.topology.inspect(&binding).await {
            Err(e) => result_error(
                "",
                "",
                &format!("INSPECT_FAILED: {e}"),
                LifecyclePhase::Failed,
                1,
            ),
            Ok(snap) => LifecycleResult {
                operation_id: String::new(),
                receipt_id: String::new(),
                instance_fingerprint: snap.description,
                phase: LifecyclePhase::Completed,
                state: if snap.healthy {
                    "PROVISIONED"
                } else {
                    "STOPPED"
                }
                .to_owned(),
                reason: String::new(),
                safe_next_action: String::new(),
                exit_code: 0,
                model_digest: String::new(),
            },
        }
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    async fn settle_fail(&self, op: &LifecycleOperation, reason: String) -> LifecycleResult {
        self.settle_at(op, LifecyclePhase::Failed, reason, 1).await
    }

    /// `settleCancel` — upstream's terminal `Cancelled` settlement on
    /// caller-context cancellation (exit code 1).
    async fn settle_cancel(&self, op: &LifecycleOperation, reason: String) -> LifecycleResult {
        self.settle_at(op, LifecyclePhase::Cancelled, reason, 1)
            .await
    }

    /// `settleAt` — records the settled terminal state; runs verified
    /// teardown before credential cleanup when the settling phase may
    /// have daemons running.
    async fn settle_at(
        &self,
        op: &LifecycleOperation,
        phase: LifecyclePhase,
        reason: String,
        exit_code: i32,
    ) -> LifecycleResult {
        let mut r = result_from_op(op, phase, reason.clone(), exit_code);
        if requires_verified_teardown(op.phase) {
            if let Err(e) = self.topology.teardown_verified(op).await {
                r.reason = format!("{}; TEARDOWN_VERIFICATION_FAILED: {e}", r.reason);
            } else if let Err(e) = self.cleanup_bootstrap(op).await {
                r.reason = format!("{}; BOOTSTRAP_CLEANUP_FAILED: {e}", r.reason);
            }
        } else if let Err(e) = self.cleanup_bootstrap(op).await {
            r.reason = format!("{}; BOOTSTRAP_CLEANUP_FAILED: {e}", r.reason);
        }
        if let Err(e) = self.journal.settle(op, phase).await {
            r.reason = format!("{reason}; SETTLE_FAILED: {e}");
            r.exit_code = exit_code;
        }
        r
    }

    /// `cleanupBootstrap` — upstream's optional `bootstrapCleaner`
    /// type-assertion; the trait default answers `Ok(())`.
    async fn cleanup_bootstrap(&self, op: &LifecycleOperation) -> Result<(), Failure> {
        self.topology.cleanup_secrets(op).await
    }
}

/// `withB04Evidence` — attaches the operation's real B04 evidence to a
/// copy of the binding (never written back into `op.binding`).
#[must_use]
pub fn with_b04_evidence(
    binding: &LifecycleBinding,
    op: &LifecycleOperation,
    lock: &LifecycleLock,
) -> LifecycleBinding {
    let mut bound = binding.clone();
    bound.b04.instance_id = binding.instance_id.clone();
    bound.b04.operation_id = op.id.clone();
    bound.b04.fencing_token = lock.fencing_token;
    bound.b04.expires_at = Some(lock.expires_at);
    bound
}

/// The per-phase budget (upstream `phaseDeadline`). The helper seam
/// owns real enforcement; the domain keeps the policy table.
#[must_use]
pub fn phase_deadline(phase: LifecyclePhase) -> Duration {
    match phase {
        LifecyclePhase::Started => PROVISION_DEADLINE,
        LifecyclePhase::Verified => FS_INIT_BUDGET,
        LifecyclePhase::FsInitialized | LifecyclePhase::DaemonsStarted => DAEMON_BUDGET,
        LifecyclePhase::ContainersHealthy => DAEMON_HEALTH_BUDGET,
        LifecyclePhase::PostgresProvisioned | LifecyclePhase::MinioProvisioned => PROVISION_BUDGET,
        LifecyclePhase::SemanticVerified => SEMANTIC_BUDGET,
        LifecyclePhase::ReceiptPrepared | LifecyclePhase::ReceiptSelectorSwitched => {
            SELECTOR_BUDGET
        }
        _ => PROVISION_DEADLINE,
    }
}

/// `requiresVerifiedTeardown` — FSInitialized included per SC-DEF-25:
/// a failed `compose up` can leave partial daemons, and teardown of
/// nothing is a no-op.
#[must_use]
pub const fn requires_verified_teardown(phase: LifecyclePhase) -> bool {
    matches!(
        phase,
        LifecyclePhase::FsInitialized
            | LifecyclePhase::DaemonsStarted
            | LifecyclePhase::ContainersHealthy
            | LifecyclePhase::PostgresProvisioned
            | LifecyclePhase::MinioProvisioned
            | LifecyclePhase::SemanticVerified
            | LifecyclePhase::ReceiptPrepared
            | LifecyclePhase::ReceiptSelectorSwitched
    )
}

/// `verifySemanticReceipt`.
fn verify_semantic_receipt(receipt: &SemanticReceipt, service: &str) -> Result<(), String> {
    if !receipt.verified || receipt.receipt_id.is_empty() || receipt.digest.is_empty() {
        return Err(format!("{service} receipt is unverified"));
    }
    Ok(())
}

fn binding_from_request(req: &LifecycleRequest) -> LifecycleBinding {
    LifecycleBinding {
        instance_id: req.instance_id.clone(),
        config_binding: req.config_binding.clone(),
        admission_id: req.admission_id.clone(),
        receipt_id: req.receipt_id.clone(),
        model_digest: req.model_digest.clone(),
        payload_epoch: req.payload_epoch.clone(),
        bootstrap_fingerprints: req.bootstrap_fingerprints.clone(),
        ..LifecycleBinding::default()
    }
}

fn result_from_op(
    op: &LifecycleOperation,
    phase: LifecyclePhase,
    reason: String,
    exit_code: i32,
) -> LifecycleResult {
    result_with_state(op, phase, phase.as_str(), &reason, exit_code)
}

fn result_with_state(
    op: &LifecycleOperation,
    phase: LifecyclePhase,
    state: &str,
    reason: &str,
    exit_code: i32,
) -> LifecycleResult {
    LifecycleResult {
        operation_id: op.id.clone(),
        receipt_id: op.binding.receipt_id.clone(),
        instance_fingerprint: op.binding.instance_id.clone(),
        phase,
        state: state.to_owned(),
        reason: reason.to_owned(),
        safe_next_action: String::new(),
        exit_code,
        model_digest: op.binding.model_digest.clone(),
    }
}

fn result_error(
    op_id: &str,
    receipt_id: &str,
    reason: &str,
    phase: LifecyclePhase,
    exit_code: i32,
) -> LifecycleResult {
    LifecycleResult {
        operation_id: op_id.to_owned(),
        receipt_id: receipt_id.to_owned(),
        instance_fingerprint: String::new(),
        phase,
        state: phase.as_str().to_owned(),
        reason: reason.to_owned(),
        safe_next_action: String::new(),
        exit_code,
        model_digest: String::new(),
    }
}

// ---------------------------------------------------------------------------
// The portable semantic lifecycle suite — upstream
// `internal/infralifecycle/preflight` + `app/service_test.go`. Fakes
// record the call order the state machine must produce; scenario
// assertions pin result vocabulary, ordering, denial paths, recovery,
// and the teardown-before-credential-cleanup contract.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{B03_REQUIRED_SERVICE_MODES, OciInventory, PreparedMode, TopologySnapshot};
    use crate::port::{
        AdmissionResult, BootstrapGeneration, BootstrapHandoff, LifecycleReservation, MountProof,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};
    use time::OffsetDateTime;

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut f = Box::pin(f);
        loop {
            if let Poll::Ready(v) = Pin::new(&mut f).poll(&mut cx) {
                return v;
            }
        }
    }

    // -- fakes --------------------------------------------------------------

    struct FakeClock(Mutex<OffsetDateTime>);
    impl LifecycleClock for FakeClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    struct FakeAdmission {
        set: PreparedDependencySet,
        err: Mutex<Option<Failure>>,
        verify_count: Mutex<u32>,
    }
    impl LifecycleAdmission for FakeAdmission {
        async fn verify(&self, _request: AdmissionRequest) -> Result<AdmissionResult, Failure> {
            *self.verify_count.lock().unwrap() += 1;
            if let Some(e) = self.err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(AdmissionResult {
                receipt_id: "receipt-1".to_owned(),
                prepared: self.set.clone(),
                ..AdmissionResult::default()
            })
        }
    }

    struct FakeBootstrap {
        err: Mutex<Option<Failure>>,
        calls: Mutex<Vec<String>>,
    }
    impl LifecycleBootstrap for FakeBootstrap {
        async fn ensure(
            &self,
            _b: &LifecycleBinding,
            _p: BootstrapPurpose,
        ) -> Result<BootstrapGeneration, Failure> {
            self.calls.lock().unwrap().push("ensure".to_owned());
            if let Some(e) = self.err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(BootstrapGeneration::default())
        }
        async fn materialize(&self, _h: BootstrapHandoff) -> Result<MountProof, Failure> {
            Ok(MountProof::default())
        }
        async fn cleanup(&self, _p: MountProof) -> Result<(), Failure> {
            Ok(())
        }
        async fn record_handoff(
            &self,
            _b: &LifecycleBinding,
            _p: &MountProof,
        ) -> Result<(), Failure> {
            Ok(())
        }
        async fn cleanup_binding(&self, _b: &LifecycleBinding) -> Result<(), Failure> {
            Ok(())
        }
    }

    struct FakeCapacity {
        err: Mutex<Option<Failure>>,
    }
    impl LifecycleCapacity for FakeCapacity {
        async fn admit(
            &self,
            _b: &LifecycleBinding,
            _s: &PreparedDependencySet,
        ) -> Result<LifecycleReservation, Failure> {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(LifecycleReservation::default())
        }
    }

    struct FakeBarrier {
        err: Mutex<Option<Failure>>,
    }
    impl LifecycleBarrier for FakeBarrier {
        async fn validate_writable_start(&self, _b: &LifecycleBinding) -> Result<(), Failure> {
            if let Some(e) = self.err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(())
        }
    }

    struct FakeLocker {
        acquire_err: Mutex<Option<Failure>>,
        release_err: Mutex<Option<Failure>>,
    }
    impl LifecycleLocker for FakeLocker {
        async fn acquire(&self, _b: &LifecycleBinding) -> Result<LifecycleLock, Failure> {
            if let Some(e) = self.acquire_err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(LifecycleLock {
                id: "lock-1".to_owned(),
                acquired: true,
                expires_at: OffsetDateTime::UNIX_EPOCH + Duration::from_secs(60),
                fencing_token: 42,
            })
        }
        async fn release(&self, _b: &LifecycleBinding, _l: LifecycleLock) -> Result<(), Failure> {
            if let Some(e) = self.release_err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(())
        }
    }

    /// Scriptable journal: per-method failure injection keyed on the
    /// call sequence, plus a record of every settle/record/begin.
    struct FakeJournal {
        ops: Mutex<Vec<LifecycleOperation>>,
        recorded: Mutex<Vec<LifecyclePhase>>,
        settled: Mutex<Vec<(String, LifecyclePhase)>>,
        prepared: Mutex<u32>,
        switched: Mutex<u32>,
        linked_begun: Mutex<u32>,
        unsettled_err: Mutex<Option<Failure>>,
        begin_err: Mutex<Option<Failure>>,
        record_err_at: Mutex<Option<usize>>, // record call index (1-based) to fail
        record_calls: Mutex<usize>,
        prepare_receipt_err: Mutex<Option<Failure>>,
        switch_receipt_err: Mutex<Option<Failure>>,
        settle_err_at: Mutex<Option<usize>>,
        settle_calls: Mutex<usize>,
        next_id: Mutex<u64>,
    }
    impl FakeJournal {
        fn new() -> Self {
            Self {
                ops: Mutex::new(Vec::new()),
                recorded: Mutex::new(Vec::new()),
                settled: Mutex::new(Vec::new()),
                prepared: Mutex::new(0),
                switched: Mutex::new(0),
                linked_begun: Mutex::new(0),
                unsettled_err: Mutex::new(None),
                begin_err: Mutex::new(None),
                record_err_at: Mutex::new(None),
                record_calls: Mutex::new(0),
                prepare_receipt_err: Mutex::new(None),
                switch_receipt_err: Mutex::new(None),
                settle_err_at: Mutex::new(None),
                settle_calls: Mutex::new(0),
                next_id: Mutex::new(0),
            }
        }
        fn make_op(&self, binding: LifecycleBinding) -> LifecycleOperation {
            let mut id = self.next_id.lock().unwrap();
            *id += 1;
            LifecycleOperation {
                id: format!("op-{id}"),
                linked_operation_id: String::new(),
                phase: LifecyclePhase::Started,
                binding,
                observation: Observation::default(),
                created_at: OffsetDateTime::UNIX_EPOCH,
            }
        }
    }
    impl LifecyclePort for FakeJournal {
        async fn begin(
            &self,
            binding: LifecycleBinding,
            observation: Observation,
        ) -> Result<LifecycleOperation, Failure> {
            if let Some(e) = self.begin_err.lock().unwrap().take() {
                return Err(e);
            }
            let mut op = self.make_op(binding);
            op.observation = observation;
            self.ops.lock().unwrap().push(op.clone());
            Ok(op)
        }
        async fn begin_linked_down(
            &self,
            binding: LifecycleBinding,
            observation: Observation,
            linked: &LifecycleOperation,
        ) -> Result<LifecycleOperation, Failure> {
            *self.linked_begun.lock().unwrap() += 1;
            let mut op = self.make_op(binding);
            op.observation = observation;
            op.linked_operation_id = linked.id.clone();
            self.ops.lock().unwrap().push(op.clone());
            Ok(op)
        }
        async fn record(
            &self,
            operation: &LifecycleOperation,
            phase: LifecyclePhase,
        ) -> Result<(), Failure> {
            let mut calls = self.record_calls.lock().unwrap();
            *calls += 1;
            if *self.record_err_at.lock().unwrap() == Some(*calls) {
                return Err(Failure::internal("JOURNAL", "record failed"));
            }
            self.recorded.lock().unwrap().push(phase);
            let mut ops = self.ops.lock().unwrap();
            if let Some(o) = ops.iter_mut().find(|o| o.id == operation.id) {
                o.phase = phase;
            }
            Ok(())
        }
        async fn prepare_receipt(
            &self,
            _operation: &LifecycleOperation,
            _receipt: &DependencyReceipt,
        ) -> Result<(), Failure> {
            *self.prepared.lock().unwrap() += 1;
            if let Some(e) = self.prepare_receipt_err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(())
        }
        async fn switch_receipt(&self, _operation: &LifecycleOperation) -> Result<(), Failure> {
            *self.switched.lock().unwrap() += 1;
            if let Some(e) = self.switch_receipt_err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(())
        }
        async fn settle(
            &self,
            operation: &LifecycleOperation,
            phase: LifecyclePhase,
        ) -> Result<(), Failure> {
            let mut calls = self.settle_calls.lock().unwrap();
            *calls += 1;
            if *self.settle_err_at.lock().unwrap() == Some(*calls) {
                return Err(Failure::internal("JOURNAL", "settle failed"));
            }
            self.settled
                .lock()
                .unwrap()
                .push((operation.id.clone(), phase));
            let mut ops = self.ops.lock().unwrap();
            if let Some(o) = ops.iter_mut().find(|o| o.id == operation.id) {
                o.phase = phase;
            }
            Ok(())
        }
        async fn unsettled(
            &self,
            _binding: &LifecycleBinding,
        ) -> Result<Option<LifecycleOperation>, Failure> {
            if let Some(e) = self.unsettled_err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(self
                .ops
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|o| !o.phase.is_terminal())
                .cloned())
        }
    }

    /// Scriptable topology: records call order, fails a named call once,
    /// reports scripted health, and records teardown/cleanup order.
    /// `clock`/`advance_per_inspect` let the health-wait deadline tests
    /// move the fake clock forward on each poll without a real sleep.
    struct FakeTopology {
        calls: Mutex<Vec<String>>,
        fail_at: Mutex<Option<(String, u32)>>, // (call name, nth occurrence) to fail once
        call_counts: Mutex<std::collections::BTreeMap<String, u32>>,
        healthy: Mutex<bool>,
        inspect_calls: Mutex<u32>,
        clock: Mutex<Option<Arc<FakeClock>>>,
        advance_per_inspect: Mutex<Duration>,
    }
    impl FakeTopology {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_at: Mutex::new(None),
                call_counts: Mutex::new(std::collections::BTreeMap::new()),
                healthy: Mutex::new(true),
                inspect_calls: Mutex::new(0),
                clock: Mutex::new(None),
                advance_per_inspect: Mutex::new(Duration::ZERO),
            }
        }
        fn called(&self, name: &str) -> Result<(), Failure> {
            self.calls.lock().unwrap().push(name.to_owned());
            let mut counts = self.call_counts.lock().unwrap();
            let n = counts.entry(name.to_owned()).or_insert(0);
            *n += 1;
            if self.fail_at.lock().unwrap().as_ref() == Some(&(name.to_owned(), *n)) {
                return Err(Failure::internal("TOPOLOGY", format!("{name} failed")));
            }
            Ok(())
        }
    }
    impl TopologyPort for FakeTopology {
        async fn validate(&self, _b: &LifecycleBinding) -> Result<(), Failure> {
            self.called("validate")
        }
        async fn init(&self, _op: &LifecycleOperation) -> Result<(), Failure> {
            self.called("init")
        }
        async fn start_daemons(&self, _op: &LifecycleOperation) -> Result<Observation, Failure> {
            self.called("start_daemons")?;
            Ok(Observation::default())
        }
        async fn provision_minio(
            &self,
            op: &LifecycleOperation,
        ) -> Result<SemanticReceipt, Failure> {
            self.called("provision_minio")?;
            // SC-DEF-28 pin: the fence token must be the lock's, not zero.
            if op.binding.b04.fencing_token == 0 {
                return Err(Failure::invalid("TOPOLOGY", "fence token must be nonzero"));
            }
            Ok(SemanticReceipt {
                receipt_id: "sr-1".to_owned(),
                digest: "sha256:sr".to_owned(),
                verified: true,
            })
        }
        async fn inspect(&self, _b: &LifecycleBinding) -> Result<TopologySnapshot, Failure> {
            *self.inspect_calls.lock().unwrap() += 1;
            self.called("inspect")?;
            let advance = *self.advance_per_inspect.lock().unwrap();
            if advance > Duration::ZERO
                && let Some(clock) = self.clock.lock().unwrap().as_ref()
            {
                *clock.0.lock().unwrap() += advance;
            }
            Ok(TopologySnapshot {
                healthy: *self.healthy.lock().unwrap(),
                description: "fake-topology".to_owned(),
                ..TopologySnapshot::default()
            })
        }
        async fn down(&self, _op: &LifecycleOperation) -> Result<(), Failure> {
            self.called("down")
        }
        async fn teardown_verified(&self, _op: &LifecycleOperation) -> Result<(), Failure> {
            self.called("teardown_verified")
        }
        async fn cleanup_secrets(&self, _op: &LifecycleOperation) -> Result<(), Failure> {
            self.called("cleanup_secrets")
        }
    }

    #[allow(clippy::type_complexity)]
    type Service = LifecycleService<
        Arc<FakeAdmission>,
        Arc<FakeBootstrap>,
        Arc<FakeJournal>,
        Arc<FakeTopology>,
        Arc<FakeCapacity>,
        Arc<FakeBarrier>,
        Arc<FakeLocker>,
        Arc<FakeClock>,
    >;

    struct Harness {
        service: Service,
        journal: Arc<FakeJournal>,
        topology: Arc<FakeTopology>,
        admission: Arc<FakeAdmission>,
        bootstrap: Arc<FakeBootstrap>,
        capacity: Arc<FakeCapacity>,
        barrier: Arc<FakeBarrier>,
        locker: Arc<FakeLocker>,
        clock: Arc<FakeClock>,
    }

    fn prepared_set() -> PreparedDependencySet {
        let inv = OciInventory {
            index_digest: "sha256:92620daddcd947f8d5ab5ba66e848702fe443d87fed30c4cea8e389fd78dfc55"
                .to_owned(),
            manifest_digest:
                "sha256:c95fd5346040eba2de3c435e14874af18f5d681fb5848d4f081dbead0878af28".to_owned(),
            config_digest:
                "sha256:67d1da22f4037b29cdd93e03d870a4a1c4d079358367d0cbc56459e52cde205e".to_owned(),
            layers: Vec::new(),
        };
        PreparedDependencySet {
            modes: B03_REQUIRED_SERVICE_MODES
                .iter()
                .map(|mode| PreparedMode {
                    mode: *mode,
                    inventory: inv.clone(),
                })
                .collect(),
        }
    }

    fn harness() -> Harness {
        let journal = Arc::new(FakeJournal::new());
        let clock = Arc::new(FakeClock(Mutex::new(OffsetDateTime::UNIX_EPOCH)));
        let topology = Arc::new(FakeTopology::new());
        *topology.clock.lock().unwrap() = Some(clock.clone());
        let admission = Arc::new(FakeAdmission {
            set: prepared_set(),
            err: Mutex::new(None),
            verify_count: Mutex::new(0),
        });
        let bootstrap = Arc::new(FakeBootstrap {
            err: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
        });
        let capacity = Arc::new(FakeCapacity {
            err: Mutex::new(None),
        });
        let barrier = Arc::new(FakeBarrier {
            err: Mutex::new(None),
        });
        let locker = Arc::new(FakeLocker {
            acquire_err: Mutex::new(None),
            release_err: Mutex::new(None),
        });
        let service = LifecycleService {
            admission: admission.clone(),
            bootstrap: bootstrap.clone(),
            journal: journal.clone(),
            topology: topology.clone(),
            capacity: Some(capacity.clone()),
            barrier: Some(barrier.clone()),
            locker: locker.clone(),
            clock: clock.clone(),
        };
        Harness {
            service,
            journal,
            topology,
            admission,
            bootstrap,
            capacity,
            barrier,
            locker,
            clock,
        }
    }

    fn request() -> LifecycleRequest {
        LifecycleRequest {
            instance_id: "inst-1".to_owned(),
            config_binding: "cfg-1".to_owned(),
            admission_id: "adm-1".to_owned(),
            receipt_id: "receipt-1".to_owned(),
            model_digest: "sha256:model".to_owned(),
            payload_epoch: "epoch-1".to_owned(),
            ..LifecycleRequest::default()
        }
    }

    fn calls(h: &Harness) -> Vec<String> {
        h.topology.calls.lock().unwrap().clone()
    }

    // -- up: ordering and completion ----------------------------------------

    #[test]
    fn up_runs_phases_in_order_and_settles_completed() {
        let h = harness();
        let r = block_on(h.service.up(request()));
        assert_eq!(r.state, "MIGRATION_REQUIRED");
        assert_eq!(r.reason, "completed");
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.phase, LifecyclePhase::Completed);
        assert_eq!(r.receipt_id, "receipt-1");
        // The durable record order: fs-init path, daemons, health,
        // provisioning, semantic, receipt, selector, settle — with the
        // inspect-based health wait between start_daemons and
        // provision_minio.
        // The Completed path returns before settleAt: the MinIO handoff
        // stays mounted for the daemon's lifetime — Down owns cleanup.
        assert_eq!(
            calls(&h),
            vec![
                "validate",
                "init",
                "start_daemons",
                "inspect", // waitForHealthy
                "provision_minio",
                "inspect", // reinspect before selector switch
            ]
        );
        // settle(Failed) on a completed path would be a bug — assert the
        // exact terminal settle.
        assert_eq!(
            *h.journal.settled.lock().unwrap(),
            vec![("op-1".to_owned(), LifecyclePhase::Completed)]
        );
        // Admission is verified twice: at Started and at SemanticVerified.
        assert_eq!(*h.admission.verify_count.lock().unwrap(), 2);
        assert_eq!(*h.journal.prepared.lock().unwrap(), 1);
        assert_eq!(*h.journal.switched.lock().unwrap(), 1);
    }

    #[test]
    fn up_attaches_b04_evidence_with_lock_fencing_token() {
        let h = harness();
        let r = block_on(h.service.up(request()));
        assert_eq!(r.exit_code, 0, "{}", r.reason);
        // FakeTopology::provision_minio rejects a zero fencing token, so
        // success proves with_b04_evidence threaded the lock token.
    }

    #[test]
    fn up_resumes_unsettled_operation_from_last_phase() {
        let h = harness();
        let mut op = h.journal.make_op(binding_from_request(&request()));
        op.id = "op-resume".to_owned();
        op.phase = LifecyclePhase::DaemonsStarted;
        h.journal.ops.lock().unwrap().push(op);
        let r = block_on(h.service.up(request()));
        assert_eq!(r.state, "MIGRATION_REQUIRED");
        // Resumed at DaemonsStarted: no admission/init/start_daemons.
        assert_eq!(calls(&h), vec!["inspect", "provision_minio", "inspect"]);
    }

    // -- up: denial paths ----------------------------------------------------

    #[test]
    fn up_denies_when_lock_acquire_fails() {
        let h = harness();
        *h.locker.acquire_err.lock().unwrap() = Some(Failure::denied("LOCK", "held"));
        let r = block_on(h.service.up(request()));
        assert_eq!(r.exit_code, 1);
        assert!(r.reason.starts_with("LOCK_FAILED:"), "{}", r.reason);
        assert!(h.journal.settled.lock().unwrap().is_empty());
    }

    #[test]
    fn up_denies_when_admission_fails() {
        let h = harness();
        *h.admission.err.lock().unwrap() = Some(Failure::denied("ADM", "denied"));
        let r = block_on(h.service.up(request()));
        assert_eq!(r.phase, LifecyclePhase::Failed);
        assert!(r.reason.starts_with("ADMISSION_FAILED:"), "{}", r.reason);
    }

    #[test]
    fn up_denies_on_receipt_binding_mismatch() {
        let h = harness();
        let mut req = request();
        req.receipt_id = "different".to_owned();
        let r = block_on(h.service.up(req));
        assert!(
            r.reason.contains("receipt binding mismatch"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn up_denies_when_capacity_rejects() {
        let h = harness();
        *h.capacity.err.lock().unwrap() = Some(Failure::denied("CAP", "full"));
        let r = block_on(h.service.up(request()));
        assert!(r.reason.starts_with("CAPACITY_DENIED:"), "{}", r.reason);
    }

    #[test]
    fn up_denies_when_barrier_rejects() {
        let h = harness();
        *h.barrier.err.lock().unwrap() = Some(Failure::denied("BAR", "conflict"));
        let r = block_on(h.service.up(request()));
        assert!(r.reason.starts_with("BARRIER_DENIED:"), "{}", r.reason);
    }

    #[test]
    fn up_denies_when_bootstrap_ensure_fails() {
        let h = harness();
        *h.bootstrap.err.lock().unwrap() = Some(Failure::internal("BOOT", "unavailable"));
        let r = block_on(h.service.up(request()));
        assert!(
            r.reason.starts_with("BOOTSTRAP_ENSURE_FAILED:"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn up_denies_when_validate_fails() {
        let h = harness();
        *h.topology.fail_at.lock().unwrap() = Some(("validate".to_owned(), 1));
        let r = block_on(h.service.up(request()));
        assert!(r.reason.starts_with("VALIDATE_FAILED:"), "{}", r.reason);
    }

    #[test]
    fn up_denies_when_init_fails() {
        let h = harness();
        *h.topology.fail_at.lock().unwrap() = Some(("init".to_owned(), 1));
        let r = block_on(h.service.up(request()));
        assert!(r.reason.starts_with("INIT_FAILED:"), "{}", r.reason);
    }

    #[test]
    fn up_denies_when_start_daemons_fails() {
        let h = harness();
        *h.topology.fail_at.lock().unwrap() = Some(("start_daemons".to_owned(), 1));
        let r = block_on(h.service.up(request()));
        assert!(
            r.reason.starts_with("START_DAEMONS_FAILED:"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn up_denies_when_provision_minio_fails() {
        let h = harness();
        *h.topology.fail_at.lock().unwrap() = Some(("provision_minio".to_owned(), 1));
        let r = block_on(h.service.up(request()));
        assert!(
            r.reason.starts_with("PROVISION_MINIO_FAILED:"),
            "{}",
            r.reason
        );
    }

    #[test]
    fn up_fails_fast_when_deadline_exceeded() {
        let h = harness();
        *h.clock.0.lock().unwrap() =
            OffsetDateTime::UNIX_EPOCH + PROVISION_DEADLINE + Duration::from_secs(1);
        let r = block_on(h.service.up(request()));
        assert_eq!(r.reason, "DEADLINE_EXCEEDED");
        assert_eq!(r.phase, LifecyclePhase::Failed);
        // Only settle-path cleanup may run; no init/daemon/provision
        // work executes past the deadline.
        assert_eq!(calls(&h), vec!["cleanup_secrets"]);
    }

    /// Upstream's `select ctx.Done()` arm: a caller deadline in the
    /// past settles the operation `Cancelled` — never a silent drop.
    #[test]
    fn up_caller_cancellation_settles_cancelled() {
        let h = harness();
        let r = block_on(h.service.up_with_deadline(
            request(),
            Some(OffsetDateTime::UNIX_EPOCH - Duration::from_secs(1)),
        ));
        assert_eq!(r.exit_code, 1);
        assert_eq!(r.phase, LifecyclePhase::Cancelled);
        assert!(r.reason.starts_with("CANCELLED:"), "reason: {}", r.reason);
        // The terminal settle is durably recorded, and only
        // settle-path cleanup ran.
        assert_eq!(
            *h.journal.settled.lock().unwrap(),
            vec![("op-1".to_owned(), LifecyclePhase::Cancelled)]
        );
        assert_eq!(calls(&h), vec!["cleanup_secrets"]);
    }

    /// The health poll honours `min(caller, daemonHealthBudget)`: an
    /// inspect that pushes the clock past the deadline settles
    /// `CONTAINER_HEALTH_FAILED` instead of polling forever.
    #[test]
    fn up_health_wait_deadline_settles_container_health_failed() {
        let h = harness();
        *h.topology.healthy.lock().unwrap() = false;
        *h.topology.advance_per_inspect.lock().unwrap() = Duration::from_secs(200);
        let r = block_on(h.service.up(request()));
        assert_eq!(r.phase, LifecyclePhase::Failed);
        assert!(
            r.reason.starts_with("CONTAINER_HEALTH_FAILED:"),
            "reason: {}",
            r.reason
        );
        assert!(r.reason.contains("deadline"), "reason: {}", r.reason);
        // One poll proved the deadline; no busy loop ran.
        assert_eq!(*h.topology.inspect_calls.lock().unwrap(), 1);
    }

    /// `down` with an already-elapsed caller deadline fails fast —
    /// `DOWN_BUDGET` is further bounded by `ctx`, exactly as
    /// upstream's `context.WithDeadline(ctx, now+downBudget)`.
    #[test]
    fn down_deadline_fails_before_teardown() {
        let h = harness();
        let r = block_on(h.service.down_with_deadline(
            request(),
            Some(OffsetDateTime::UNIX_EPOCH - Duration::from_secs(1)),
        ));
        assert_eq!(r.exit_code, 1);
        assert!(
            r.reason
                .starts_with("DOWN_TEARDOWN_VERIFICATION_FAILED: deadline exceeded"),
            "reason: {}",
            r.reason
        );
        // No teardown was attempted; settle-path cleanup ran.
        assert_eq!(calls(&h), vec!["cleanup_secrets"]);
    }

    /// `status` with an elapsed caller deadline refuses before the
    /// read-only inspect runs (upstream `context.WithDeadline(ctx,
    /// now+statusBudget)`).
    #[test]
    fn status_deadline_expired_refuses_before_inspect() {
        let h = harness();
        let r = block_on(h.service.status_with_deadline(
            LifecycleStatusRequest {
                instance_id: "inst-1".to_owned(),
                config_binding: "cfg-1".to_owned(),
            },
            Some(OffsetDateTime::UNIX_EPOCH - Duration::from_secs(1)),
        ));
        assert_eq!(r.exit_code, 1);
        assert_eq!(r.reason, "INSPECT_FAILED: deadline exceeded");
        assert_eq!(calls(&h), Vec::<String>::new());
    }

    // -- teardown/cleanup ordering (SC-DEF-25 contract) ----------------------

    #[test]
    fn settle_from_started_skips_verified_teardown() {
        let h = harness();
        *h.admission.err.lock().unwrap() = Some(Failure::denied("ADM", "denied"));
        let r = block_on(h.service.up(request()));
        assert_eq!(r.phase, LifecyclePhase::Failed);
        assert_eq!(calls(&h), vec!["cleanup_secrets"]);
    }

    #[test]
    fn settle_from_fs_initialized_verifies_teardown_before_cleanup() {
        let h = harness();
        *h.topology.fail_at.lock().unwrap() = Some(("start_daemons".to_owned(), 1));
        let r = block_on(h.service.up(request()));
        assert!(r.reason.starts_with("START_DAEMONS_FAILED:"));
        // Settling from FsInitialized runs verified teardown first.
        assert_eq!(
            calls(&h),
            vec![
                "validate",
                "init",
                "start_daemons",
                "teardown_verified",
                "cleanup_secrets"
            ]
        );
    }

    #[test]
    fn settle_failure_after_switch_stays_at_receipt_prepared() {
        let h = harness();
        *h.journal.switch_receipt_err.lock().unwrap() =
            Some(Failure::internal("J", "switch failed"));
        let r = block_on(h.service.up(request()));
        assert_eq!(r.phase, LifecyclePhase::ReceiptPrepared);
        assert!(
            r.reason.starts_with("SWITCH_RECEIPT_FAILED:"),
            "{}",
            r.reason
        );
        // Never reports MIGRATION_REQUIRED for a switch that failed.
        assert_ne!(r.state, "MIGRATION_REQUIRED");
    }

    #[test]
    fn record_failure_after_switch_stays_at_receipt_prepared() {
        let h = harness();
        // record calls: verified(1) fs(2) daemons(3) healthy(4)
        // pg_prov(5) minio_prov(6) semantic(7) receipt_prepared(8)
        // then the failing record for selector_switched is call 9.
        *h.journal.record_err_at.lock().unwrap() = Some(9);
        let r = block_on(h.service.up(request()));
        assert_eq!(r.phase, LifecyclePhase::ReceiptPrepared);
        assert!(
            r.reason.starts_with("RECORD_FAILED_AFTER_SWITCH:"),
            "{}",
            r.reason
        );
    }

    // -- down ----------------------------------------------------------------

    #[test]
    fn down_tears_down_and_settles_completed() {
        let h = harness();
        let r = block_on(h.service.down(request()));
        assert_eq!(r.exit_code, 0, "{}", r.reason);
        assert_eq!(r.reason, "down_completed");
        assert_eq!(r.phase, LifecyclePhase::Completed);
        assert_eq!(calls(&h), vec!["teardown_verified", "cleanup_secrets"]);
        assert_eq!(
            *h.journal.settled.lock().unwrap(),
            vec![("op-1".to_owned(), LifecyclePhase::Completed)]
        );
    }

    #[test]
    fn down_creates_linked_down_and_terminalizes_unsettled_up() {
        let h = harness();
        let mut up_op = h.journal.make_op(binding_from_request(&request()));
        up_op.id = "up-1".to_owned();
        up_op.phase = LifecyclePhase::DaemonsStarted;
        h.journal.ops.lock().unwrap().push(up_op);
        let r = block_on(h.service.down(request()));
        assert_eq!(r.exit_code, 0, "{}", r.reason);
        assert_eq!(*h.journal.linked_begun.lock().unwrap(), 1);
        // The linked up settles Failed before the down settles Completed.
        let settled = h.journal.settled.lock().unwrap().clone();
        assert_eq!(
            settled,
            vec![
                ("up-1".to_owned(), LifecyclePhase::Failed),
                ("op-2".to_owned(), LifecyclePhase::Completed),
            ]
        );
    }

    #[test]
    fn down_reports_teardown_verification_failure_and_delegates_cleanup_refusal() {
        let h = harness();
        *h.topology.fail_at.lock().unwrap() = Some(("teardown_verified".to_owned(), 1));
        let r = block_on(h.service.down(request()));
        assert!(
            r.reason.starts_with("DOWN_TEARDOWN_VERIFICATION_FAILED:"),
            "{}",
            r.reason
        );
        // The domain still invokes cleanup_secrets; the production
        // adapter's CleanupSecrets itself refuses without a verified
        // teardown (upstream's "teardown must be verified before
        // credential cleanup" check lives in the adapter).
        assert_eq!(calls(&h), vec!["teardown_verified", "cleanup_secrets"]);
    }

    // -- status ----------------------------------------------------------------

    #[test]
    fn status_reports_provisioned_when_healthy() {
        let h = harness();
        let r = block_on(h.service.status(LifecycleStatusRequest {
            instance_id: "inst-1".to_owned(),
            config_binding: "cfg-1".to_owned(),
        }));
        assert_eq!(r.state, "PROVISIONED");
        assert_eq!(r.instance_fingerprint, "fake-topology");
        assert_eq!(calls(&h), vec!["inspect"]);
    }

    #[test]
    fn status_reports_stopped_when_unhealthy() {
        let h = harness();
        *h.topology.healthy.lock().unwrap() = false;
        let r = block_on(h.service.status(LifecycleStatusRequest {
            instance_id: "inst-1".to_owned(),
            config_binding: "cfg-1".to_owned(),
        }));
        assert_eq!(r.state, "STOPPED");
    }

    #[test]
    fn status_is_strictly_read_only() {
        let h = harness();
        let _ = block_on(h.service.status(LifecycleStatusRequest {
            instance_id: "inst-1".to_owned(),
            config_binding: "cfg-1".to_owned(),
        }));
        // Inspect only — no mutation calls ever reach the topology.
        assert_eq!(calls(&h), vec!["inspect"]);
    }

    #[test]
    fn phase_deadline_table_matches_upstream() {
        assert_eq!(phase_deadline(LifecyclePhase::Started), PROVISION_DEADLINE);
        assert_eq!(phase_deadline(LifecyclePhase::Verified), FS_INIT_BUDGET);
        assert_eq!(
            phase_deadline(LifecyclePhase::DaemonsStarted),
            DAEMON_BUDGET
        );
        assert_eq!(
            phase_deadline(LifecyclePhase::ContainersHealthy),
            DAEMON_HEALTH_BUDGET
        );
        assert_eq!(
            phase_deadline(LifecyclePhase::PostgresProvisioned),
            PROVISION_BUDGET
        );
        assert_eq!(
            phase_deadline(LifecyclePhase::SemanticVerified),
            SEMANTIC_BUDGET
        );
        assert_eq!(
            phase_deadline(LifecyclePhase::ReceiptPrepared),
            SELECTOR_BUDGET
        );
    }
}
