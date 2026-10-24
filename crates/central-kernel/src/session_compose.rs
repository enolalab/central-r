//! Session composition — the kernel's port of the session-service
//! wiring block of upstream `cmd/central/serve_composition.go`
//! (`openServeDeps`).
//!
//! Upstream constructs `pgsession.New(pool)` plus the broker-backed
//! `ProtectedBootstrap` activator and injects both into
//! `sessionapp.New(store, activator)`. The R3 slice has no broker
//! activator: [`crate::harness_compose::select_bootstrap`] already
//! owns the selection rule — the file-backed
//! [`DevFileProtectedBootstrap`] is reachable only under the explicit
//! `CENTRAL_LOCALEXEC=1` development gate, and anything else fails
//! closed (the broker-backed bootstrap is deferred to R5). This
//! module is where that selection meets the concrete store: it is
//! deliberately tiny so the bootstrap selection policy stays in the
//! one place that already owns it.
//!
//! The returned [`SessionComposition`] hands the composed
//! `Service<PgSessionStore, DevFileProtectedBootstrap>` to serve: the
//! same value satisfies the transport's `SessionService`,
//! `SessionValidator`, `PreAuthCsrf`, and `DeliveryPrecommit` ports
//! (upstream's single `sessionSvc` injected into every middleware
//! seam). The service owns the single bootstrap instance — its
//! in-memory registry mirror is the authoritative cache of the
//! registry file, so a second instance over the same root would
//! diverge.

use std::path::Path;
use std::sync::Arc;

use central_adapter_linux::dev_bootstrap::DevFileProtectedBootstrap;
use central_adapter_postgres::session::PgSessionStore;
use central_foundation::failure::Failure;
use central_session::app::Service;

/// The composed session capability — upstream `sessionSvc`.
pub struct SessionComposition {
    /// The service every transport seam shares (upstream
    /// `sessionSvc` injected into session validation, pre-auth CSRF,
    /// delivery precommit, and the web handler's session surface).
    pub service: Arc<Service<PgSessionStore, DevFileProtectedBootstrap>>,
}

/// `pgsession.New(pool)` + broker-activator selection +
/// `sessionapp.New` — the session block of `openServeDeps`.
///
/// `bootstrap_root` is where the dev-gated bootstrap keeps its
/// candidate registry (upstream's broker-managed protected state has
/// no file; the file layout is the dev bootstrap's own).
///
/// # Errors
/// Propagates [`crate::harness_compose::select_bootstrap`]'s
/// fail-closed refusal when the dev gate is unset.
pub fn compose_session(
    pool: sqlx::PgPool,
    bootstrap_root: &Path,
) -> Result<SessionComposition, Failure> {
    let bootstrap =
        crate::harness_compose::select_bootstrap(|name| std::env::var_os(name), bootstrap_root)?;
    Ok(SessionComposition {
        service: Arc::new(Service::new(PgSessionStore::new(pool), bootstrap)),
    })
}
