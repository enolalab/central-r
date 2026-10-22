//! `central-kernel` — the single composition root (manual constructor
//! injection), supervised-component lifecycle, and graceful shutdown.
//! It is the only crate that may import both inward capability contracts
//! and concrete adapters (rust-application-boundaries.md §3.3).
//!
//! Kernel-edge rule (§2.2): capability crates expose structural
//! `async fn run(&mut self) -> Result<(), Failure>` /
//! `async fn settle(&mut self) -> Result<(), Failure>` signatures and
//! never import this crate. [`lifecycle::Profile`] wraps them in its
//! owned [`lifecycle::Component`]/[`lifecycle::Preflight`] trait objects;
//! cancellation arrives via a kernel-held `CancellationToken` plus future
//! drop, and settlement via a bounded `tokio::time::timeout` call. This
//! crate is the async host layer — `tokio`/`tokio-util` are permitted
//! here and prohibited inside capability domain code.
//!
//! Ports `internal/kernel` (upstream Go): [`lifecycle`] carries the
//! supervised profile runner and exit-class contract, [`readiness`] the
//! profile-aware health state, and [`readyproof`] the nonce-bound launch
//! proof with its publisher port, and [`artifact_reconcile`] the
//! kernel-owned supervised wrapper for the periodic fenced Artifact
//! reconciliation pass (upstream `cmd/central`'s
//! `serveArtifactReconcilePass`). The listener/TLS/control-lock stages
//! of the upstream `Run` land with the R3 serve composition.

pub mod artifact_reconcile;
pub mod lifecycle;
pub mod readiness;
pub mod readyproof;

/// Object-safe boxed future shared by the kernel-owned trait objects —
/// the same erase shape `DynProofService` uses in the postgres adapter.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
