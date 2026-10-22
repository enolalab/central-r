//! Supervised profile lifecycle — ports the component-supervision half
//! of `internal/kernel/{lifecycle.go,serve.go}`.
//!
//! The kernel-edge rule (rust-application-boundaries.md §2.2): capability
//! crates expose structural `async fn run(&mut self) -> Result<(),
//! Failure>` / `async fn settle(&mut self) -> Result<(), Failure>`
//! signatures and never import this crate. [`Profile`] wraps them in the
//! kernel-owned [`Component`]/[`Preflight`] trait objects. Cancellation
//! is delivered by a kernel-held [`CancellationToken`] plus future drop;
//! settlement is delivered by a bounded `tokio::time::timeout` call —
//! never by a capability-imported kernel type.
//!
//! A terminal component failure cancels the whole profile and surfaces
//! [`ExitClass::Terminal`] (process exit `6`); an intentional stop
//! revokes the ready proof, marks the profile `shutting_down`, settles
//! components in reverse registration order under the shutdown budget,
//! and returns `Ok` — the upstream `stop()`/`fail()` sequence
//! (`revokeProof` → `markShuttingDown`/`markFailed` → `cancel` →
//! `shutdown`).

use std::future::Future;
use std::task::{Context, Poll};
use std::time::Duration;

use central_foundation::failure::{ExitClass, Failure};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::BoxFuture;
use crate::readiness::{Readiness, safe_reason, safe_remediation};
use crate::readyproof::{ReadyProofPublisher, new_ready_proof, new_runtime_launch_id};

/// Upstream `defaultProofTTL` (5 minutes).
pub const DEFAULT_PROOF_TTL: Duration = Duration::from_secs(300);
/// Upstream `defaultSettlement` (30 seconds): bounds the drain window in
/// which in-flight component work may finish before the kernel drops the
/// outstanding run futures.
pub const DEFAULT_SETTLEMENT: Duration = Duration::from_secs(30);
/// Upstream `defaultShutdown` (45 seconds): bounds the whole settle
/// sequence including every per-component `settle` call.
pub const DEFAULT_SHUTDOWN: Duration = Duration::from_secs(45);
/// Upstream `maxSettlement` (2 minutes).
pub const MAX_SETTLEMENT: Duration = Duration::from_secs(120);
/// Upstream `maxShutdown` (3 minutes).
pub const MAX_SHUTDOWN: Duration = Duration::from_secs(180);
/// Upstream `StartupLimit` default (5 seconds): bounds the proof-guard,
/// preflight, and proof-publication stages.
pub const DEFAULT_STARTUP_LIMIT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Exit classification
// ---------------------------------------------------------------------------

/// Preserves the stable serve exit class without exposing dependency or
/// certificate details through the error string — the port of upstream
/// `kernel.ExitError`.
#[derive(Debug)]
pub struct ExitError {
    class: ExitClass,
    reason: String,
    remediation: String,
    diagnostic: bool,
    source: Option<Failure>,
}

impl ExitError {
    /// Builds an exit error. `reason` is a stable safe reason code (it is
    /// later filtered through [`safe_reason`] when copied into health
    /// state); `cause` is the classified failure that produced it.
    pub fn new(class: ExitClass, reason: impl Into<String>, cause: Failure) -> Self {
        Self {
            class,
            reason: reason.into(),
            remediation: String::new(),
            diagnostic: false,
            source: Some(cause),
        }
    }

    /// The exit class — its `code()` is the process exit status.
    #[must_use]
    pub const fn class(&self) -> ExitClass {
        self.class
    }

    /// The safe reason code.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Bounded remediation copy (may be empty).
    #[must_use]
    pub fn remediation(&self) -> &str {
        &self.remediation
    }

    /// Whether this error carries classified diagnostic detail (upstream
    /// `diagnostic` flag): diagnostic errors copy `class`, `reason`, and
    /// `remediation` into the not-ready health snapshot verbatim.
    #[must_use]
    pub const fn is_diagnostic(&self) -> bool {
        self.diagnostic
    }
}

impl std::fmt::Display for ExitError {
    /// `central serve: {reason}` optionally with `({remediation})`; never
    /// renders the cause or any dependency detail.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.reason.is_empty() {
            return write!(f, "central serve exited with code {}", self.class.code());
        }
        if self.remediation.is_empty() {
            return write!(f, "central serve: {}", self.reason);
        }
        write!(f, "central serve: {} ({})", self.reason, self.remediation)
    }
}

impl std::error::Error for ExitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|f| f as &(dyn std::error::Error + 'static))
    }
}

/// The process exit status for `err`: the carried [`ExitClass`] when the
/// error is an [`ExitError`], `0` for `None`, and `6`
/// ([`ExitClass::Terminal`]) for anything else — the port of upstream
/// `kernel.ExitCode`.
#[must_use]
pub fn exit_code(err: Option<&(dyn std::error::Error + 'static)>) -> u8 {
    match err {
        None => 0,
        Some(e) => e
            .downcast_ref::<ExitError>()
            .map_or(ExitClass::Terminal.code(), |exit| exit.class().code()),
    }
}

/// Maps a startup [`Failure`] to a classified [`ExitError`], the port of
/// upstream `startupFailure` + `diagnosticExitError`: the failure's kind
/// selects the exit class, an unrecognized reason collapses to
/// `fallback_reason`, and remediation comes from the redacted message
/// bounded by [`safe_remediation`].
fn startup_failure(cause: Failure, fallback_reason: &'static str) -> ExitError {
    let reason = match safe_reason(cause.code()) {
        "UNAVAILABLE" => fallback_reason,
        allowlisted => allowlisted,
    };
    ExitError {
        class: cause.exit_class(),
        reason: reason.to_string(),
        remediation: safe_remediation(cause.message()).to_string(),
        diagnostic: true,
        source: Some(cause),
    }
}

/// Copies an [`ExitError`] into the profile readiness, the port of
/// upstream `markStartupFailure`.
fn mark_startup_failure(readiness: &Readiness, err: &ExitError) {
    if err.diagnostic {
        readiness.mark_not_ready_diagnostic(err.class().code(), &err.reason, &err.remediation);
        return;
    }
    readiness.mark_not_ready(&err.reason);
}

// ---------------------------------------------------------------------------
// Kernel-owned trait objects
// ---------------------------------------------------------------------------

/// Kernel-owned supervised-component contract. Implementations are
/// capability component shims: each wraps one capability's structural
/// `async fn run(&mut self) -> Result<(), Failure>` /
/// `async fn settle(&mut self) -> Result<(), Failure>` pair.
///
/// `run` must be cancellation-safe at every `.await`: the supervisor
/// drops the future to cancel it. `settle` is invoked exactly once per
/// registered component during profile shutdown, in reverse registration
/// order, under the shared shutdown deadline.
pub trait Component: Send + 'static {
    /// The component's main loop. Completing — successfully or not — is
    /// a terminal event: any completion cancels the entire profile.
    fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>>;
    /// Bounded post-cancellation settlement (persist receipts, release
    /// claims, close resources). Called once on the stop and terminal
    /// paths, never while `run` is still being polled.
    fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>>;
}

/// The result of a startup admission check. `security_epoch` carries the
/// authoritative epoch observed by the preflight; the profile records it
/// on readiness so every startup consumer sees the same value without it
/// appearing in health responses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PreflightReport {
    /// The authoritative security epoch, when the preflight is the
    /// serving-inspection kind that produces one.
    pub security_epoch: Option<u64>,
}

/// Kernel-owned startup preflight contract (port of upstream
/// `kernel.Preflight`). Preflights run sequentially inside the startup
/// budget before the ready proof is issued; any failure refuses the
/// profile with a classified exit.
pub trait Preflight: Send + 'static {
    /// Runs the admission check.
    fn run(&mut self) -> BoxFuture<'_, Result<PreflightReport, Failure>>;
}

// ---------------------------------------------------------------------------
// Profile configuration
// ---------------------------------------------------------------------------

/// Bounded lifecycle budgets. Zero values select the upstream defaults;
/// [`Profile::run`] validates the installed bounds exactly like upstream
/// `validateConfig` (settlement ≤ 2 min, shutdown ≤ 3 min, shutdown ≥
/// settlement).
#[derive(Debug, Clone, Copy)]
pub struct ProfileConfig {
    /// Startup budget for the proof guard, preflights, and publication.
    pub startup_limit: Duration,
    /// Drain window for in-flight component work after cancellation.
    pub settlement: Duration,
    /// Total shutdown budget covering every `settle` call.
    pub shutdown: Duration,
    /// Ready-proof TTL.
    pub proof_ttl: Duration,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            startup_limit: DEFAULT_STARTUP_LIMIT,
            settlement: DEFAULT_SETTLEMENT,
            shutdown: DEFAULT_SHUTDOWN,
            proof_ttl: DEFAULT_PROOF_TTL,
        }
    }
}

impl ProfileConfig {
    fn effective(self) -> Self {
        Self {
            startup_limit: if self.startup_limit.is_zero() {
                DEFAULT_STARTUP_LIMIT
            } else {
                self.startup_limit
            },
            settlement: if self.settlement.is_zero() {
                DEFAULT_SETTLEMENT
            } else {
                self.settlement
            },
            shutdown: if self.shutdown.is_zero() {
                DEFAULT_SHUTDOWN
            } else {
                self.shutdown
            },
            proof_ttl: if self.proof_ttl.is_zero() {
                DEFAULT_PROOF_TTL
            } else {
                self.proof_ttl
            },
        }
    }

    fn validate(self) -> Result<(), ExitError> {
        if self.settlement > MAX_SETTLEMENT
            || self.shutdown > MAX_SHUTDOWN
            || self.shutdown < self.settlement
        {
            return Err(ExitError::new(
                ExitClass::Usage,
                "CONFIG_INVALID",
                Failure::invalid(
                    "kernel_shutdown_budget_out_of_bounds",
                    "shutdown budget is outside the installed bounds",
                ),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Proof session
// ---------------------------------------------------------------------------

/// The per-run proof-lifecycle guard: tracks whether `begin_startup` is
/// held and which runtime generation this profile owns so cleanup can
/// release the guard without touching a successor's proof (upstream's
/// `proofSessionOpen`/`ownedProofGeneration` pair).
struct ProofSession<'a> {
    publisher: Option<&'a mut dyn ReadyProofPublisher>,
    open: bool,
    owned_generation: String,
}

impl ProofSession<'_> {
    /// `abortStartup`: release the guard without deleting a proof.
    async fn abort(&mut self) -> Result<(), Failure> {
        if !self.open {
            return Ok(());
        }
        self.open = false;
        match self.publisher.as_mut() {
            Some(publisher) => publisher.abort_startup().await,
            None => Ok(()),
        }
    }

    /// `revokeProof`: `RevokeIfGeneration` for the owned generation plus
    /// `AbortStartup` to release the guard; clears ownership only when
    /// both succeed (upstream cleanup ordering).
    async fn revoke(&mut self) -> Result<(), Failure> {
        if self.owned_generation.is_empty() {
            return Ok(());
        }
        let Some(publisher) = self.publisher.as_mut() else {
            return Ok(());
        };
        let revoke = publisher
            .revoke_if_generation(self.owned_generation.clone())
            .await;
        // `revoke_if_generation` owns guard release by contract; abort is
        // idempotent and protects cleanup if the adapter returns midway.
        let abort = publisher.abort_startup().await;
        self.open = false;
        if revoke.is_ok() && abort.is_ok() {
            self.owned_generation.clear();
        }
        revoke.and(abort)
    }
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// How the supervised phase ended.
enum Cause {
    /// `stop` completed or the profile token was cancelled.
    Stop,
    /// A component's `run` completed — always terminal, even when it
    /// returned `Ok` (upstream treats nil error as "terminated
    /// unexpectedly").
    Terminal(Failure),
}

/// The supervised serve profile: manual dependency composition +
/// component lifecycle. Construct through [`Self::new`], register
/// [`Preflight`]s, [`Component`]s, and an optional
/// [`ReadyProofPublisher`], then [`run`](Self::run) until an intentional
/// stop or a terminal failure.
pub struct Profile {
    readiness: Readiness,
    config: ProfileConfig,
    cancel: CancellationToken,
    components: Vec<Box<dyn Component>>,
    preflights: Vec<Box<dyn Preflight>>,
    publisher: Option<Box<dyn ReadyProofPublisher>>,
    launch_id: Option<String>,
}

impl Profile {
    /// Manual composition entry point: `config` carries the bounded
    /// budgets, `readiness` is the profile's externally observed state.
    /// There is intentionally no builder of last resort — the
    /// composition root passes each collaborator explicitly.
    #[must_use]
    pub fn new(config: ProfileConfig, readiness: Readiness) -> Self {
        Self {
            readiness,
            config: config.effective(),
            cancel: CancellationToken::new(),
            components: Vec::new(),
            preflights: Vec::new(),
            publisher: None,
            launch_id: None,
        }
    }

    /// Registers a supervised component. Startup order is registration
    /// order; settlement is the reverse.
    pub fn add_component(&mut self, component: impl Component) {
        self.components.push(Box::new(component));
    }

    /// Registers a startup preflight (runs before the ready proof is
    /// issued, inside the startup budget).
    pub fn add_preflight(&mut self, preflight: impl Preflight) {
        self.preflights.push(Box::new(preflight));
    }

    /// Installs the proof publisher that transfers the ready proof to
    /// the privileged helper boundary.
    pub fn set_proof_publisher(&mut self, publisher: impl ReadyProofPublisher) {
        self.publisher = Some(Box::new(publisher));
    }

    /// Pins the launch ID; unset means a fresh `central-runtime-*`
    /// identifier is generated at proof issuance.
    pub fn set_launch_id(&mut self, launch_id: impl Into<String>) {
        self.launch_id = Some(launch_id.into());
    }

    /// The profile's shared readiness handle.
    #[must_use]
    pub fn readiness(&self) -> Readiness {
        self.readiness.clone()
    }

    /// The profile cancellation token. Cancelling it is an intentional
    /// stop: the profile settles and [`run`](Self::run) returns `Ok`.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Runs the profile until `stop` completes, the cancellation token
    /// fires, or a runtime component terminates. `stop` is the outer
    /// stop signal (signal relay, controller disconnect, parent death —
    /// whichever the host wires).
    ///
    /// # Errors
    /// [`ExitError`] classified [`ExitClass::Usage`] (config), `Timeout`
    /// (startup deadline), the preflight failure's own class (startup
    /// refusal), or `Terminal` (publication failure, terminal component
    /// failure, failed settlement).
    pub async fn run(&mut self, stop: impl Future<Output = ()>) -> Result<(), ExitError> {
        let readiness = self.readiness.clone();
        if let Err(err) = self.config.validate() {
            readiness.mark_not_ready("CONFIG_INVALID");
            return Err(err);
        }

        let mut publisher = self.publisher.take();
        let mut session = ProofSession {
            publisher: publisher.as_deref_mut(),
            open: false,
            owned_generation: String::new(),
        };
        let result = self.drive(stop, &mut session, &readiness).await;
        self.publisher = publisher;
        result
    }

    async fn drive(
        &mut self,
        stop: impl Future<Output = ()>,
        session: &mut ProofSession<'_>,
        readiness: &Readiness,
    ) -> Result<(), ExitError> {
        let startup_deadline = Instant::now() + self.config.startup_limit;

        // The persistent proof guard is the outer singleton; taking it
        // before admission closes the acquire->revoke race.
        if let Some(publisher) = session.publisher.as_mut() {
            match timeout_at(startup_deadline, publisher.begin_startup()).await {
                Ok(Ok(())) => session.open = true,
                Ok(Err(cause)) => {
                    readiness.mark_failed("BACKGROUND_LOOP_FAILED");
                    return Err(ExitError::new(
                        ExitClass::Terminal,
                        "BACKGROUND_LOOP_FAILED",
                        cause,
                    ));
                }
                Err(_) => {
                    readiness.mark_not_ready("LEASE_LOST");
                    return Err(ExitError::new(
                        ExitClass::Timeout,
                        "LEASE_LOST",
                        Failure::internal(
                            "kernel_proof_guard_held",
                            "ready proof startup guard is held",
                        ),
                    ));
                }
            }
        }

        // Only the admitted singleton may invalidate an older generation,
        // and it does so while retaining the outer proof guard. The call
        // runs under the startup deadline exactly like upstream's
        // `Revoke(startupCtx)` — upstream maps any failure on this path,
        // deadline expiry included, to `BACKGROUND_LOOP_FAILED`.
        if let Some(publisher) = session.publisher.as_mut() {
            let revoked = timeout_at(startup_deadline, publisher.revoke()).await;
            let cause = match revoked {
                Ok(Ok(())) => None,
                Ok(Err(cause)) => Some(cause),
                Err(_) => Some(Failure::internal(
                    "kernel_startup_deadline",
                    "stale ready proof revoke exceeded the startup budget",
                )),
            };
            if let Some(cause) = cause {
                let _ = session.abort().await;
                readiness.mark_failed("BACKGROUND_LOOP_FAILED");
                tracing::warn!(
                    code = cause.code(),
                    "kernel: stale ready proof revoke failed"
                );
                return Err(ExitError::new(
                    ExitClass::Terminal,
                    "BACKGROUND_LOOP_FAILED",
                    Failure::internal(
                        "kernel_stale_proof_revoke_failed",
                        "stale ready proof could not be revoked",
                    ),
                ));
            }
        }

        // Startup admission: preflights run sequentially inside the
        // startup budget.
        for preflight in &mut self.preflights {
            match timeout_at(startup_deadline, preflight.run()).await {
                Ok(Ok(report)) => {
                    if let Some(epoch) = report.security_epoch {
                        readiness.set_security_epoch(epoch);
                    }
                }
                Ok(Err(cause)) => {
                    let _ = session.abort().await;
                    let err = startup_failure(cause, "POSTGRES_INCOMPATIBLE");
                    mark_startup_failure(readiness, &err);
                    return Err(err);
                }
                Err(_) => {
                    let _ = session.abort().await;
                    readiness.mark_not_ready("LEASE_LOST");
                    return Err(ExitError::new(
                        ExitClass::Timeout,
                        "LEASE_LOST",
                        Failure::internal(
                            "kernel_startup_deadline",
                            "startup admission exceeded its budget",
                        ),
                    ));
                }
            }
        }

        // Issue and publish the ready proof. Ownership is recorded before
        // publish so a publisher that fails after a partial write is
        // still cleaned up without touching a successor generation.
        let launch_id = match self.launch_id.clone() {
            Some(id) => id,
            None => new_runtime_launch_id(time::OffsetDateTime::now_utc()),
        };
        let proof = match new_ready_proof(
            &launch_id,
            time::OffsetDateTime::now_utc(),
            self.config.proof_ttl,
        ) {
            Ok(proof) => proof,
            Err(cause) => {
                let _ = session.abort().await;
                readiness.mark_not_ready("CONFIG_INVALID");
                return Err(ExitError::new(ExitClass::Usage, "CONFIG_INVALID", cause));
            }
        };
        session.owned_generation = proof.runtime_generation.clone();
        readiness.mark_ready(proof.clone());
        // Publication is likewise bounded by the startup deadline
        // (upstream `Publish(startupCtx, proof)`); a failure — deadline
        // expiry included — exits `BACKGROUND_LOOP_FAILED`.
        if let Some(publisher) = session.publisher.as_mut() {
            let published = timeout_at(startup_deadline, publisher.publish(proof)).await;
            let cause = match published {
                Ok(Ok(())) => None,
                Ok(Err(cause)) => Some(cause),
                Err(_) => Some(Failure::internal(
                    "kernel_startup_deadline",
                    "ready proof publication exceeded the startup budget",
                )),
            };
            if let Some(cause) = cause {
                let _ = session.revoke().await;
                readiness.mark_failed("BACKGROUND_LOOP_FAILED");
                tracing::warn!(code = cause.code(), "kernel: ready proof publish failed");
                return Err(ExitError::new(
                    ExitClass::Terminal,
                    "BACKGROUND_LOOP_FAILED",
                    Failure::internal(
                        "kernel_proof_publish_failed",
                        "ready proof publication failed",
                    ),
                ));
            }
        }

        // Supervised phase. Every component's run future is borrowed and
        // polled by the supervisor: cancellation is future drop — there
        // is no detach and no hidden task.
        let mut running: Vec<Option<BoxFuture<'_, Result<(), Failure>>>> = self
            .components
            .iter_mut()
            .map(|component| Some(component.run()))
            .collect();

        let mut stop = std::pin::pin!(stop);
        let cancel = self.cancel.clone();
        let cause = tokio::select! {
            () = stop.as_mut() => Cause::Stop,
            () = cancel.cancelled() => Cause::Stop,
            result = next_completion(&mut running) => {
                // A component that returns `Ok` still terminated
                // unexpectedly (upstream treats nil error the same).
                Cause::Terminal(match result {
                    Ok(()) => Failure::internal(
                        "kernel_component_exit",
                        "runtime component terminated unexpectedly",
                    ),
                    Err(cause) => cause,
                })
            }
        };

        // Upstream `stop()`/`fail()` ordering: the proof revoke and the
        // readiness transition land BEFORE cancellation and settlement —
        // leaving them after `settle_components` would keep the
        // stale-proof window open for the whole settle budget.
        let mut shutdown_cause: Option<Failure> = None;
        match &cause {
            Cause::Stop => {
                if session.revoke().await.is_err() {
                    shutdown_cause = Some(Failure::internal(
                        "kernel_proof_revoke_failed",
                        "ready proof revocation failed",
                    ));
                }
                readiness.mark_shutting_down();
            }
            Cause::Terminal(_) => {
                if session.revoke().await.is_err() {
                    shutdown_cause = Some(Failure::internal(
                        "kernel_proof_revoke_failed",
                        "ready proof revocation failed",
                    ));
                }
                readiness.mark_failed("BACKGROUND_LOOP_FAILED");
            }
        }

        // Cancellation phase: signal the profile token, then give
        // in-flight component work up to `settlement` to finish — the
        // bounded settlement window. Survivors are cancelled by dropping
        // their futures, which also releases the component borrows.
        self.cancel.cancel();
        let _ = timeout(self.config.settlement, drain_running(&mut running)).await;
        drop(running);

        // Settlement: reverse registration order, shared shutdown
        // deadline (upstream `shutdown`).
        let settle = self.settle_components().await;
        match cause {
            Cause::Stop => {
                if let Err(failure) = settle {
                    shutdown_cause = Some(match shutdown_cause {
                        Some(joined) => join_failure(joined, failure),
                        None => failure,
                    });
                }
                // Upstream maps a failed revoke or a failed settlement
                // on the stop path to `exitError(6, "SHUTDOWN_FAILED")`.
                match shutdown_cause {
                    Some(failure) => Err(ExitError::new(
                        ExitClass::Terminal,
                        "SHUTDOWN_FAILED",
                        failure,
                    )),
                    None => Ok(()),
                }
            }
            Cause::Terminal(result) => {
                // Upstream `errors.Join`: the component failure stays the
                // reported cause; the revoke and settlement failures are
                // attached, not substituted.
                let mut cause = result;
                if let Some(revoke_failure) = shutdown_cause {
                    cause = join_failure(cause, revoke_failure);
                }
                if let Err(failure) = settle {
                    tracing::warn!(
                        code = failure.code(),
                        "kernel: settlement failed on terminal path"
                    );
                    cause = join_failure(cause, failure);
                }
                Err(ExitError::new(
                    ExitClass::Terminal,
                    "BACKGROUND_LOOP_FAILED",
                    cause,
                ))
            }
        }
    }

    /// Reverse-registration-order bounded settlement: each `settle` call
    /// is bounded by the shared `shutdown` deadline. The first failure
    /// wins, matching `errors.Join`'s reported cause.
    async fn settle_components(&mut self) -> Result<(), Failure> {
        let deadline = Instant::now() + self.config.shutdown;
        let mut failure: Option<Failure> = None;
        for component in self.components.iter_mut().rev() {
            let result = match timeout_at(deadline, component.settle()).await {
                Ok(result) => result,
                Err(_) => Err(Failure::internal(
                    "kernel_shutdown_deadline",
                    "component settlement exceeded the shutdown budget",
                )),
            };
            if let Err(cause) = result {
                tracing::warn!(code = cause.code(), "kernel: component settlement failed");
                if failure.is_none() {
                    failure = Some(cause);
                }
            }
        }
        match failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

/// The [`Failure`] port of `errors.Join` for the shutdown-path cause:
/// the first failure's kind and code stay the reported classification
/// while the second failure's `[code] message` is appended the way a Go
/// joined error renders — one error per line.
fn join_failure(first: Failure, second: Failure) -> Failure {
    Failure::new(
        first.kind(),
        first.code(),
        format!("{}\n{}", first.message(), second),
    )
}

/// Polls every outstanding run future once per wakeup and yields the
/// first completion. With no outstanding futures it pends forever, which
/// is exactly the supervised steady state: only `stop` or cancellation
/// ends the profile.
async fn next_completion<'a>(
    running: &mut [Option<BoxFuture<'a, Result<(), Failure>>>],
) -> Result<(), Failure> {
    std::future::poll_fn(|cx: &mut Context<'_>| {
        for slot in running.iter_mut() {
            let Some(fut) = slot else { continue };
            if let Poll::Ready(result) = fut.as_mut().poll(cx) {
                *slot = None;
                return Poll::Ready(result);
            }
        }
        Poll::Pending
    })
    .await
}

/// Polls the outstanding run futures until all complete. Used inside the
/// bounded settlement window after cancellation.
async fn drain_running<'a>(running: &mut [Option<BoxFuture<'a, Result<(), Failure>>>]) {
    std::future::poll_fn(|cx: &mut Context<'_>| {
        let mut pending = false;
        for slot in running.iter_mut() {
            let Some(fut) = slot else { continue };
            if fut.as_mut().poll(cx).is_ready() {
                *slot = None;
            } else {
                pending = true;
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness::State;
    use crate::readyproof::ReadyProof;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    fn failure(code: &'static str) -> Failure {
        Failure::internal(code, "test failure")
    }

    /// A component whose `run` records the start and then pends (the
    /// usual supervised shape — cancellation arrives by future drop),
    /// and whose `settle` records invocation.
    struct RecordingComponent {
        name: &'static str,
        started: Arc<AtomicUsize>,
        settled: Arc<StdMutex<Vec<&'static str>>>,
        settle_error: Option<Failure>,
        run_fails: bool,
    }

    impl RecordingComponent {
        fn new(
            name: &'static str,
            started: Arc<AtomicUsize>,
            settled: Arc<StdMutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                name,
                started,
                settled,
                settle_error: None,
                run_fails: false,
            }
        }
    }

    impl Component for RecordingComponent {
        fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let fails = self.run_fails;
            Box::pin(async move {
                if fails {
                    return Err(failure("component_failed"));
                }
                std::future::pending::<()>().await;
                Ok(())
            })
        }

        fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            let name = self.name;
            let error = self.settle_error.take();
            let settled = self.settled.clone();
            Box::pin(async move {
                settled.lock().unwrap().push(name);
                match error {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            })
        }
    }

    struct StubPreflight {
        epoch: Option<u64>,
        result: Option<Failure>,
    }

    impl Preflight for StubPreflight {
        fn run(&mut self) -> BoxFuture<'_, Result<PreflightReport, Failure>> {
            let epoch = self.epoch;
            let result = self.result.take();
            Box::pin(async move {
                match result {
                    Some(cause) => Err(cause),
                    None => Ok(PreflightReport {
                        security_epoch: epoch,
                    }),
                }
            })
        }
    }

    /// Records the publisher call sequence so tests can assert the
    /// upstream lifecycle order.
    struct LoggedPublisher {
        log: Arc<StdMutex<Vec<&'static str>>>,
    }

    impl ReadyProofPublisher for LoggedPublisher {
        fn begin_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("begin_startup");
            Box::pin(async { Ok(()) })
        }
        fn publish(&mut self, _proof: ReadyProof) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("publish");
            Box::pin(async { Ok(()) })
        }
        fn revoke(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("revoke");
            Box::pin(async { Ok(()) })
        }
        fn revoke_if_generation(
            &mut self,
            _generation: String,
        ) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("revoke_if_generation");
            Box::pin(async { Ok(()) })
        }
        fn abort_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("abort_startup");
            Box::pin(async { Ok(()) })
        }
    }

    /// A publisher that records into a shared ordering log so tests can
    /// pin the upstream revoke-before-settle sequence; `fail_revoke`
    /// makes `revoke_if_generation` fail the way an unreachable proof
    /// store would.
    struct OrderingPublisher {
        log: Arc<StdMutex<Vec<String>>>,
        fail_revoke: bool,
    }

    impl ReadyProofPublisher for OrderingPublisher {
        fn begin_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("begin_startup".to_string());
            Box::pin(async { Ok(()) })
        }
        fn publish(&mut self, _proof: ReadyProof) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("publish".to_string());
            Box::pin(async { Ok(()) })
        }
        fn revoke(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("revoke".to_string());
            Box::pin(async { Ok(()) })
        }
        fn revoke_if_generation(
            &mut self,
            _generation: String,
        ) -> BoxFuture<'_, Result<(), Failure>> {
            self.log
                .lock()
                .unwrap()
                .push("revoke_if_generation".to_string());
            let fail = self.fail_revoke;
            Box::pin(async move {
                if fail {
                    Err(Failure::unavailable(
                        "proof_store_down",
                        "proof store unreachable",
                    ))
                } else {
                    Ok(())
                }
            })
        }
        fn abort_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            self.log.lock().unwrap().push("abort_startup".to_string());
            Box::pin(async { Ok(()) })
        }
    }

    /// A component that pends in `run` and, inside `settle`, records the
    /// readiness state it observes into the shared ordering log — the
    /// probe that pins mark-before-settle ordering.
    struct StateProbingComponent {
        log: Arc<StdMutex<Vec<String>>>,
        readiness: Readiness,
    }

    impl Component for StateProbingComponent {
        fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            Box::pin(std::future::pending())
        }
        fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            let log = self.log.clone();
            let readiness = self.readiness.clone();
            Box::pin(async move {
                log.lock()
                    .unwrap()
                    .push(format!("settle:{}", readiness.state().as_str()));
                Ok(())
            })
        }
    }

    /// A publisher whose selected call never completes — the startup
    /// deadline must bound it.
    struct HungPublisher {
        hang_on: &'static str,
    }

    impl ReadyProofPublisher for HungPublisher {
        fn begin_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }
        fn publish(&mut self, _proof: ReadyProof) -> BoxFuture<'_, Result<(), Failure>> {
            let hang = self.hang_on == "publish";
            Box::pin(async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                Ok(())
            })
        }
        fn revoke(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            let hang = self.hang_on == "revoke";
            Box::pin(async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                Ok(())
            })
        }
        fn revoke_if_generation(
            &mut self,
            _generation: String,
        ) -> BoxFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }
        fn abort_startup(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn pending_stop() -> impl Future<Output = ()> {
        std::future::pending()
    }

    /// Small budgets so the bounded settlement window and shutdown
    /// deadline do not slow the suite; never-completing fake components
    /// burn the whole drain window (they only observe future-drop
    /// cancellation).
    fn test_config() -> ProfileConfig {
        ProfileConfig {
            startup_limit: Duration::from_secs(5),
            settlement: Duration::from_millis(20),
            shutdown: Duration::from_millis(100),
            proof_ttl: Duration::from_secs(300),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn components_start_and_settle_on_token_stop() {
        let started = Arc::new(AtomicUsize::new(0));
        let settled = Arc::new(StdMutex::new(Vec::new()));
        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.add_component(RecordingComponent::new(
            "a",
            started.clone(),
            settled.clone(),
        ));
        profile.add_component(RecordingComponent::new(
            "b",
            started.clone(),
            settled.clone(),
        ));
        let token = profile.cancellation_token();
        let readiness = profile.readiness();

        let driver = tokio::spawn(async move { profile.run(pending_stop()).await });
        while started.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(readiness.state(), State::Ready);
        token.cancel();
        let result = driver.await.unwrap();
        assert!(result.is_ok(), "intentional stop must succeed");
        assert_eq!(readiness.state(), State::ShuttingDown);
        // Settlement runs in reverse registration order.
        assert_eq!(*settled.lock().unwrap(), vec!["b", "a"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_future_ends_profile_gracefully() {
        let settled = Arc::new(StdMutex::new(Vec::new()));
        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.add_component(RecordingComponent::new(
            "only",
            Arc::new(AtomicUsize::new(0)),
            settled.clone(),
        ));
        let readiness = profile.readiness();
        let result = profile.run(std::future::ready(())).await;
        assert!(result.is_ok());
        assert_eq!(readiness.state(), State::ShuttingDown);
        assert_eq!(*settled.lock().unwrap(), vec!["only"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_component_failure_cancels_profile_with_exit_6() {
        let started = Arc::new(AtomicUsize::new(0));
        let settled = Arc::new(StdMutex::new(Vec::new()));
        let mut profile = Profile::new(test_config(), Readiness::new());
        let mut failing = RecordingComponent::new("failing", started.clone(), settled.clone());
        failing.run_fails = true;
        profile.add_component(failing);
        profile.add_component(RecordingComponent::new("peer", started, settled.clone()));
        let token = profile.cancellation_token();
        let readiness = profile.readiness();

        let err = profile.run(pending_stop()).await.unwrap_err();
        assert_eq!(err.class(), ExitClass::Terminal);
        assert_eq!(err.class().code(), 6);
        assert_eq!(err.reason(), "BACKGROUND_LOOP_FAILED");
        assert_eq!(readiness.state(), State::Failed);
        assert!(token.is_cancelled(), "terminal failure cancels the profile");
        // Both components still settle.
        assert!(settled.lock().unwrap().contains(&"peer"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn component_completing_ok_is_still_terminal() {
        struct Completing;
        impl Component for Completing {
            fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
                Box::pin(async { Ok(()) })
            }
            fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
                Box::pin(async { Ok(()) })
            }
        }
        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.add_component(Completing);
        let err = profile.run(pending_stop()).await.unwrap_err();
        assert_eq!(err.class(), ExitClass::Terminal);
        assert_eq!(err.reason(), "BACKGROUND_LOOP_FAILED");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn settlement_is_bounded_by_shutdown_budget() {
        struct SlowSettle;
        impl Component for SlowSettle {
            fn run(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
                Box::pin(std::future::pending())
            }
            fn settle(&mut self) -> BoxFuture<'_, Result<(), Failure>> {
                // Never completes; the shutdown deadline must bound it.
                Box::pin(std::future::pending())
            }
        }
        let config = ProfileConfig {
            settlement: Duration::from_millis(20),
            shutdown: Duration::from_millis(40),
            ..test_config()
        };
        let mut profile = Profile::new(config, Readiness::new());
        profile.add_component(SlowSettle);
        let token = profile.cancellation_token();

        let started = Instant::now();
        let handle = tokio::spawn(async move { profile.run(pending_stop()).await });
        tokio::task::yield_now().await;
        token.cancel();
        let err = handle.await.unwrap().unwrap_err();
        assert_eq!(err.class(), ExitClass::Terminal);
        assert_eq!(err.reason(), "SHUTDOWN_FAILED");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "settlement must be bounded by the shutdown budget"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn settle_error_fails_the_stop() {
        let settled = Arc::new(StdMutex::new(Vec::new()));
        let mut profile = Profile::new(test_config(), Readiness::new());
        let mut bad = RecordingComponent::new("bad", Arc::new(AtomicUsize::new(0)), settled);
        bad.settle_error = Some(failure("settle_failed"));
        profile.add_component(bad);
        let err = profile.run(std::future::ready(())).await.unwrap_err();
        assert_eq!(err.class(), ExitClass::Terminal);
        assert_eq!(err.reason(), "SHUTDOWN_FAILED");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn preflight_epoch_reaches_readiness_and_failure_refuses() {
        let readiness = Readiness::new();
        let mut profile = Profile::new(test_config(), readiness.clone());
        profile.add_preflight(StubPreflight {
            epoch: Some(77),
            result: None,
        });
        let result = profile.run(std::future::ready(())).await;
        assert!(result.is_ok());
        assert_eq!(readiness.security_epoch(), 77);

        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.add_preflight(StubPreflight {
            epoch: None,
            result: Some(Failure::unavailable("pg_down", "postgres down")),
        });
        let readiness = profile.readiness();
        let err = profile.run(pending_stop()).await.unwrap_err();
        assert_eq!(err.class(), ExitClass::Unavailable);
        assert_eq!(err.class().code(), 3);
        assert_eq!(readiness.state(), State::NotReady);
        // Diagnostic startup failures carry the classified class.
        assert_eq!(readiness.health().reason, "POSTGRES_INCOMPATIBLE");
        assert_eq!(readiness.health().failure_class, 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_budget_refuses_with_exit_2() {
        let config = ProfileConfig {
            settlement: Duration::from_secs(90),
            shutdown: Duration::from_secs(30), // < settlement
            ..test_config()
        };
        let mut profile = Profile::new(config, Readiness::new());
        let err = profile.run(pending_stop()).await.unwrap_err();
        assert_eq!(err.class(), ExitClass::Usage);
        assert_eq!(err.class().code(), 2);
        assert_eq!(err.reason(), "CONFIG_INVALID");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proof_lifecycle_orders_begin_publish_revoke_by_generation() {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.set_launch_id("launch-fixed");
        profile.set_proof_publisher(LoggedPublisher { log: log.clone() });
        let readiness = profile.readiness();

        let result = profile.run(std::future::ready(())).await;
        assert!(result.is_ok());
        assert_eq!(readiness.state(), State::ShuttingDown);
        let calls = log.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                "begin_startup",
                "revoke",
                "publish",
                "revoke_if_generation",
                "abort_startup"
            ],
            "proof lifecycle must serialize begin -> revoke-stale -> publish -> revoke-by-generation"
        );
    }

    #[test]
    fn exit_code_mapping() {
        assert_eq!(exit_code(None), 0);
        let plain = Failure::internal("x", "x");
        assert_eq!(exit_code(Some(&plain)), 6);
        let exit = ExitError::new(ExitClass::Incompatible, "MIGRATION_REQUIRED", plain);
        assert_eq!(exit_code(Some(&exit)), 5);
        assert_eq!(exit.to_string(), "central serve: MIGRATION_REQUIRED");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_revokes_proof_and_marks_readiness_before_settlement() {
        // Upstream stop() order: revokeProof -> markShuttingDown ->
        // cancel -> shutdown. The revoke must precede settlement so the
        // stale-proof window is not open for the whole settle budget.
        let log = Arc::new(StdMutex::new(Vec::new()));
        let readiness = Readiness::new();
        let mut profile = Profile::new(test_config(), readiness.clone());
        profile.set_launch_id("launch-order");
        profile.set_proof_publisher(OrderingPublisher {
            log: log.clone(),
            fail_revoke: false,
        });
        profile.add_component(StateProbingComponent {
            log: log.clone(),
            readiness: readiness.clone(),
        });
        let result = profile.run(std::future::ready(())).await;
        assert!(result.is_ok());
        let calls = log.lock().unwrap().clone();
        let revoke = calls
            .iter()
            .position(|c| c == "revoke_if_generation")
            .expect("proof must be revoked on the stop path");
        let settle = calls
            .iter()
            .position(|c| c.starts_with("settle:"))
            .expect("component must settle on the stop path");
        assert!(
            revoke < settle,
            "proof revocation must precede component settlement: {calls:?}"
        );
        assert_eq!(
            calls[settle], "settle:shutting_down",
            "readiness transition must land before settlement: {calls:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_failure_revokes_proof_before_settlement_and_joins_causes() {
        // Upstream fail() order: revokeProof -> markFailed -> cancel ->
        // shutdown, with `errors.Join` keeping the component failure as
        // the reported cause when the revoke also fails.
        let log = Arc::new(StdMutex::new(Vec::new()));
        let readiness = Readiness::new();
        let mut profile = Profile::new(test_config(), readiness.clone());
        profile.set_launch_id("launch-order");
        profile.set_proof_publisher(OrderingPublisher {
            log: log.clone(),
            fail_revoke: true,
        });
        let mut failing = RecordingComponent::new(
            "failing",
            Arc::new(AtomicUsize::new(0)),
            Arc::new(StdMutex::new(Vec::new())),
        );
        failing.run_fails = true;
        profile.add_component(failing);
        profile.add_component(StateProbingComponent {
            log: log.clone(),
            readiness,
        });

        let err = profile.run(pending_stop()).await.unwrap_err();
        assert_eq!(err.class(), ExitClass::Terminal);
        assert_eq!(err.reason(), "BACKGROUND_LOOP_FAILED");
        let calls = log.lock().unwrap().clone();
        let revoke = calls
            .iter()
            .position(|c| c == "revoke_if_generation")
            .expect("proof revoke must be attempted on the terminal path");
        let settle = calls
            .iter()
            .position(|c| c.starts_with("settle:"))
            .expect("component must settle on the terminal path");
        assert!(
            revoke < settle,
            "proof revocation must precede component settlement: {calls:?}"
        );
        assert_eq!(
            calls[settle], "settle:failed",
            "readiness transition must land before settlement: {calls:?}"
        );
        // `errors.Join` parity: the component failure stays the cause and
        // the revoke failure is attached, not substituted.
        let cause = std::error::Error::source(&err)
            .and_then(|e| e.downcast_ref::<Failure>())
            .expect("ExitError must carry the component failure");
        assert_eq!(cause.code(), "component_failed");
        assert!(
            cause.message().contains("ready proof revocation failed"),
            "revoke failure must join the component failure: {}",
            cause.message()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stop_with_failing_proof_revoke_exits_shutdown_failed() {
        // Upstream stop() returns `exitError(6, "SHUTDOWN_FAILED")` when
        // the proof revoke fails — never a warn-and-Ok.
        let mut profile = Profile::new(test_config(), Readiness::new());
        profile.set_launch_id("launch-revoke-fail");
        profile.set_proof_publisher(OrderingPublisher {
            log: Arc::new(StdMutex::new(Vec::new())),
            fail_revoke: true,
        });
        let err = profile.run(std::future::ready(())).await.unwrap_err();
        assert_eq!(err.class(), ExitClass::Terminal);
        assert_eq!(err.class().code(), 6);
        assert_eq!(err.reason(), "SHUTDOWN_FAILED");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hung_publish_is_bounded_by_the_startup_deadline() {
        let config = ProfileConfig {
            startup_limit: Duration::from_millis(30),
            ..test_config()
        };
        let mut profile = Profile::new(config, Readiness::new());
        profile.set_launch_id("launch-hung-publish");
        profile.set_proof_publisher(HungPublisher { hang_on: "publish" });
        let started = Instant::now();
        let err = profile.run(pending_stop()).await.unwrap_err();
        // Upstream maps a `Publish(startupCtx, …)` failure — deadline
        // expiry included — to exit 6 BACKGROUND_LOOP_FAILED.
        assert_eq!(err.class(), ExitClass::Terminal);
        assert_eq!(err.reason(), "BACKGROUND_LOOP_FAILED");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "publish must be bounded by the startup deadline"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hung_stale_revoke_is_bounded_by_the_startup_deadline() {
        let config = ProfileConfig {
            startup_limit: Duration::from_millis(30),
            ..test_config()
        };
        let mut profile = Profile::new(config, Readiness::new());
        profile.set_proof_publisher(HungPublisher { hang_on: "revoke" });
        let started = Instant::now();
        let err = profile.run(pending_stop()).await.unwrap_err();
        assert_eq!(err.class(), ExitClass::Terminal);
        assert_eq!(err.reason(), "BACKGROUND_LOOP_FAILED");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stale-proof revoke must be bounded by the startup deadline"
        );
    }
}
