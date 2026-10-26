//! Session composition — the kernel's port of the session-service
//! wiring block of upstream `cmd/central/serve_composition.go`
//! (`openServeDeps`).
//!
//! Upstream constructs `pgsession.New(pool)` plus the broker-backed
//! `ProtectedBootstrap` activator and injects both into
//! `sessionapp.New(store, activator)`. This module is where the
//! bootstrap selection meets the concrete store: the broker
//! [`BootstrapActivator`][central_adapter_linux::broker::bootstrap_session::BootstrapActivator]
//! is the production default (upstream's only
//! form — candidate evidence crosses the protected socket, the
//! verifier never leaves the broker), and the R3 file-backed
//! [`DevFileProtectedBootstrap`][central_adapter_linux::dev_bootstrap::DevFileProtectedBootstrap]
//! is reachable only under the explicit
//! `CENTRAL_LOCALEXEC=1` development gate. The selection policy
//! itself stays in [`crate::harness_compose::select_bootstrap`], the
//! one place that already owns the gate rule.
//!
//! The returned [`SessionComposition`] hands the composed
//! `Service<PgSessionStore, ServeBootstrap>` to serve: the same value
//! satisfies the transport's `SessionService`, `SessionValidator`,
//! `PreAuthCsrf`, and `DeliveryPrecommit` ports (upstream's single
//! `sessionSvc` injected into every middleware seam). The service
//! owns the single bootstrap instance — upstream's broker activator
//! is a per-call socket client, and under the dev gate the in-memory
//! registry mirror is the authoritative cache of the registry file,
//! so a second instance over the same root would diverge.

use std::path::Path;
use std::sync::Arc;

use central_adapter_postgres::session::PgSessionStore;
use central_foundation::failure::Failure;
use central_session::app::Service;

use crate::harness_compose::ServeBootstrap;

/// The composed session capability — upstream `sessionSvc`.
pub struct SessionComposition {
    /// The service every transport seam shares (upstream
    /// `sessionSvc` injected into session validation, pre-auth CSRF,
    /// delivery precommit, and the web handler's session surface).
    pub service: Arc<Service<PgSessionStore, ServeBootstrap>>,
    /// The store's `DiscoverBootstrapCandidates` half — the
    /// `bootstrapCandidateSource` the startup reconciler consumes
    /// (upstream `candidates: store`).
    pub candidates: PgSessionStore,
}

/// `pgsession.New(pool)` + `broker.NewBootstrapActivator` +
/// `sessionapp.New` — the session block of `openServeDeps`.
///
/// `bootstrap_root` is used only when the dev gate selects the
/// file-backed bootstrap (upstream's broker-managed protected state
/// has no file; the file layout is the dev bootstrap's own). The
/// broker path resolves through `CENTRAL_BROKER_SOCKET` /
/// [`central_adapter_linux::broker::PRODUCTION_SOCKET_PATH`].
///
/// # Errors
/// Propagates [`crate::harness_compose::select_bootstrap`]'s
/// failures — the dev bootstrap's construction refusal under the
/// gate, or the broker activator's socket-path refusal.
pub fn compose_session(
    pool: sqlx::PgPool,
    bootstrap_root: &Path,
) -> Result<SessionComposition, Failure> {
    let bootstrap =
        crate::harness_compose::select_bootstrap(|name| std::env::var_os(name), bootstrap_root)?;
    Ok(SessionComposition {
        service: Arc::new(Service::new(PgSessionStore::new(pool.clone()), bootstrap)),
        candidates: PgSessionStore::new(pool),
    })
}
