//! Read projections for `central-session` — the query-side value types
//! the transport consumes when rendering `/app/bootstrap`
//! (rust-application-boundaries.md §5 "Session bootstrap" rows).
//!
//! Projections never embed domain aggregates, port traits, or
//! session/bootstrap/CSRF material — only the redirect/repair decisions
//! the server-rendered page needs.

/// `SessionStatusRequest` — input to the `ValidateSession` query
/// driving the bootstrap page's `normal` row (boundaries §5.4.7.1).
/// The transport already extracted and validated the request context;
/// only the presence of a session credential crosses this boundary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SessionStatusRequest {
    /// Whether the request presented a session credential at all (a
    /// cookie was attached; validity is decided by the store).
    pub presented: bool,
}

/// `SessionStatusProjection` — the bootstrap page's redirect decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatusProjection {
    /// A valid, active session was presented: `/app/bootstrap`
    /// redirects an authenticated session to `/app/tasks`.
    Authenticated,
    /// No, invalid, or expired session: render the bootstrap form
    /// (`303` stays a redirect only for the authenticated case).
    Unauthenticated,
}

/// `BootstrapStatusRequest` — input to the `ReconcileBootstrap` status
/// read driving the `restart/reconciliation` row: whether startup
/// reconciliation has already run against the durable session census.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapStatusRequest {
    /// Whether the kernel ran `ReconcileBootstrap` before readiness.
    pub reconciliation_ran: bool,
}

/// `BootstrapStatusProjection` — the reconciliation outcome rendered to
/// the operator: either the fresh `normal` bootstrap page or the safe
/// operator-repair outcome. It carries counts, never session material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapStatusProjection {
    /// All discovered candidates reached a terminal outcome; the page
    /// renders the fresh `normal` bootstrap form.
    pub ready: bool,
    /// Sessions reconciliation completed to `active` (report only).
    pub activated: usize,
    /// Sessions reconciliation revoked (report only).
    pub revoked: usize,
    /// `true` when an acknowledged delivery could not be recovered
    /// safely — the page must render the operator-repair outcome and
    /// require a fresh bootstrap token.
    pub operator_repair_required: bool,
}
