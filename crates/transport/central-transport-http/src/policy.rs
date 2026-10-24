//! Route policy data — the §4.3 route matrix expressed as data.
//!
//! [`RouteSpec`] pairs one HTTP method and one path template with the
//! [`RoutePolicy`] the inner layers enforce. The admission layer matches
//! requests against the [`RouteTable`] built from the same specs the
//! axum router is built from, so the policy table and the handler table
//! can never diverge.
//!
//! Path templates support literal segments and whole-segment
//! `{param}` placeholders (e.g. `/app/tasks/{task_id}/cancel`), matching
//! the §4.3/api-v1 route shapes. A `{param}` matches exactly one
//! non-empty segment. Literal-vs-parameter ambiguity across different
//! templates is resolved by preferring the template with more literal
//! segments (most specific), mirroring `matchit`'s static-over-param
//! precedence.

use axum::http::Method;
use central_foundation::failure::{Failure, FailureKind};

// ---------------------------------------------------------------------------
// Bounds (§4.6 + upstream admission.go constants)
// ---------------------------------------------------------------------------

/// `HTMLResponseCap` — the 1 MiB cap applied to HTML responses.
pub const HTML_RESPONSE_CAP: usize = 1 << 20;

/// `APIResponseCap` — the 2 MiB cap applied to JSON API responses.
pub const API_RESPONSE_CAP: usize = 2 << 20;

/// `MaxResponseBuffer` — the §4.6 hard cap on a per-route buffered
/// response (2 MiB). A larger configured cap is a build-time error.
pub const MAX_RESPONSE_BUFFER: usize = 2 << 20;

/// `DefaultBootstrapBodyLimit` — the 1 MiB bootstrap-body cap (upstream
/// `DefaultBootstrapBodyLimit`, the API v1 §4.2 JSON body bound).
pub const DEFAULT_BOOTSTRAP_BODY_LIMIT: usize = 1 << 20;

/// `MaxBodyBuffer` — the §4.6 hard cap on a buffered request body
/// (2 MiB). `body_limit == 0` on a route means "no route-specific cap";
/// the effective cap then falls back to this hard bound.
pub const MAX_BODY_BUFFER: usize = 2 << 20;

/// `ActiveLimit` — §4.6 installed in-flight cap (32). The architecture
/// contract installs its hard cap as the serving value: the 33rd
/// concurrent request queues rather than rejecting.
pub const DEFAULT_ACTIVE_LIMIT: usize = 32;
/// `MaxActiveLimit` — §4.6 hard cap on in-flight non-streaming requests.
pub const MAX_ACTIVE_LIMIT: usize = 32;
/// `WaiterLimit` — §4.6 installed admission-queue cap (64): the 65th
/// waiter is rejected with `503`.
pub const DEFAULT_WAITER_LIMIT: usize = 64;
/// `MaxWaiterLimit` — §4.6 hard cap on queued waiters.
pub const MAX_WAITER_LIMIT: usize = 64;
/// `WaitTimeout` — §4.6 installed admission wait budget (5 s).
pub const DEFAULT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// `MaxWaitTimeout` — §4.6 hard cap on the admission wait budget.
pub const MAX_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// `DefaultRouteDeadline` — upstream default per-route budget from
/// admission through response flush.
pub const DEFAULT_ROUTE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);
/// `DefaultMaxHeaderBytes` — the 32 KiB total-header budget re-checked
/// by admission as defense in depth behind the HTTP server's bound.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 32 * 1024;
/// `MaxHeaderBytes` — §4.6 hard cap on total header bytes (64 KiB).
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// `MaxPerHeaderBytes` — the per-header 4 KiB budget (cap == default).
pub const MAX_PER_HEADER_BYTES: usize = 4 * 1024;

/// `MaxAggregateBuffer` — §4.6 aggregate buffered-response memory cap
/// (64 MiB = 32 active × 2 MiB).
pub const MAX_AGGREGATE_BUFFER: u64 = 64 << 20;

// ---------------------------------------------------------------------------
// RouteClass — response-family classification
// ---------------------------------------------------------------------------

/// The response family a route belongs to. It decides the fixed-outcome
/// body shape (HTML vs JSON envelope), the unauthenticated-session
/// outcome (`303` vs `401`), and which session-CSRF channel applies
/// (hidden form field vs `X-CSRF-Token` header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteClass {
    /// `/app/...` server-rendered pages and mutations — HTML outcomes,
    /// `303` on missing session, form-field session CSRF.
    App,
    /// `/api/v1/...` JSON endpoints — envelope outcomes, `401` on
    /// missing session, `X-CSRF-Token` session CSRF.
    Api,
    /// `/assets/...` embedded static allowlist — no session, no CSRF,
    /// GET or HEAD only.
    Asset,
    /// `/health/...` operational endpoints — generic JSON outcome.
    Health,
    /// `/metrics` scrape endpoint — operational listener.
    Metrics,
    /// `/` — fixed redirect to `/app/tasks`.
    Root,
}

// ---------------------------------------------------------------------------
// RoutePolicy — the per-(method, path) admission contract
// ---------------------------------------------------------------------------

/// The per-route policy the admission layer matches and stashes in the
/// request extensions for the inner Origin, pre-auth CSRF, session, and
/// buffered layers to read. Mirrors upstream `middleware.Route` /
/// `RoutePolicy` plus the §4.3 session and restart-barrier columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutePolicy {
    /// Response family (HTML vs JSON envelope, session outcome).
    pub class: RouteClass,
    /// Per-route buffered-response cap. `0` defaults to
    /// [`HTML_RESPONSE_CAP`]; values above [`MAX_RESPONSE_BUFFER`] are
    /// clamped at the table build.
    pub response_cap: usize,
    /// Per-route body cap applied before the body is read. `0` means no
    /// route-specific cap; the effective bound is [`MAX_BODY_BUFFER`].
    pub body_limit: usize,
    /// Reject a state-changing request whose `Origin` header is missing.
    pub origin_required: bool,
    /// The route mutates server state (implies Origin discipline).
    pub state_changing: bool,
    /// Require the validated pre-auth double-submit CSRF pair
    /// (bootstrap-exchange routes only).
    pub csrf_required: bool,
    /// Require the session-bound CSRF value — `X-CSRF-Token` header on
    /// `Api` routes, hidden `csrf` form field on `App` routes.
    pub session_csrf_required: bool,
    /// Mint a fresh pre-auth CSRF cookie on this safe route.
    pub issue_pre_auth_csrf: bool,
    /// Require a valid active session (§4.3 session column).
    pub session_required: bool,
    /// The mutation re-evaluates eligibility from fresh durable state
    /// inside its commit transaction — the §4.3 restart barrier. The
    /// transport records the flag; the handler/domain enforce it. The
    /// canonical barred outcome is [`crate::error::task_action_failure`]
    /// (upstream's `http.StatusConflict` — 409).
    pub restart_barrier: bool,
}

impl RoutePolicy {
    /// A permissive safe-GET baseline (assets/health/metrics).
    #[must_use]
    pub const fn safe_get(class: RouteClass) -> Self {
        Self {
            class,
            response_cap: 0,
            body_limit: 0,
            origin_required: false,
            state_changing: false,
            csrf_required: false,
            session_csrf_required: false,
            issue_pre_auth_csrf: false,
            session_required: false,
            restart_barrier: false,
        }
    }

    /// The effective response cap — `0` maps to [`HTML_RESPONSE_CAP`]
    /// (upstream's default), anything larger than the §4.6 hard cap is
    /// clamped so an over-configured route can never exceed it.
    #[must_use]
    pub const fn effective_response_cap(&self) -> usize {
        if self.response_cap == 0 {
            HTML_RESPONSE_CAP
        } else if self.response_cap > MAX_RESPONSE_BUFFER {
            MAX_RESPONSE_BUFFER
        } else {
            self.response_cap
        }
    }

    /// The effective request-body cap — `0` maps to the §4.6 hard bound.
    #[must_use]
    pub const fn effective_body_limit(&self) -> usize {
        if self.body_limit == 0 || self.body_limit > MAX_BODY_BUFFER {
            MAX_BODY_BUFFER
        } else {
            self.body_limit
        }
    }
}

// ---------------------------------------------------------------------------
// RouteSpec + RouteTable
// ---------------------------------------------------------------------------

/// One `(method, path)` admission rule — upstream `middleware.Route`.
/// The same spec drives the axum `MethodRouter` registration and the
/// admission policy lookup, so the two tables cannot diverge.
#[derive(Debug, Clone)]
pub struct RouteSpec {
    /// The exact HTTP method.
    pub method: Method,
    /// The path template: literal segments and whole-segment `{param}`
    /// placeholders only.
    pub path: &'static str,
    /// The per-route policy the matched request carries.
    pub policy: RoutePolicy,
}

/// What the admission lookup decided about a request's `(method, path)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMatch {
    /// Path and method are registered; the policy applies.
    Matched {
        /// The matched policy.
        policy: RoutePolicy,
        /// The matched path template (e.g. `/app/tasks/{task_id}`) — the
        /// sanitized label for the access observer.
        template: &'static str,
    },
    /// Path registered but not for this method — fixed `405` + `Allow`.
    MethodNotAllowed,
    /// No template matched — fixed `404` that leaks no route existence.
    NotFound,
}

/// The policy stashed into request extensions by the admission layer.
/// `MatchedRoute` also records the matched path template so the access
/// observer can label the outcome with the fixed template (never the
/// raw request path) — or the `unmatched` sentinel when absent.
#[derive(Debug, Clone)]
pub struct MatchedRoute {
    /// The matched policy.
    pub policy: RoutePolicy,
    /// The matched path template (e.g. `/app/tasks/{task_id}/cancel`).
    pub path_template: &'static str,
}

/// The `Allow` header for a path's registered methods, formatted exactly
/// like axum's own `allow_header` (`GET` implies `HEAD`; methods joined
/// by `,` in registration order, deduplicated).
#[must_use]
pub fn allow_header(methods: &[Method]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for m in methods {
        let expanded: &[&str] = if *m == Method::GET {
            &["GET", "HEAD"]
        } else {
            &[m.as_str()]
        };
        for part in expanded {
            if !parts.iter().any(|p| p == part) {
                parts.push((*part).to_string());
            }
        }
    }
    parts.join(",")
}

/// One compiled path template — segments plus the method→policy map of
/// every spec sharing the template.
#[derive(Debug)]
struct CompiledPath {
    segments: Vec<Segment>,
    methods: Vec<(Method, RoutePolicy)>,
    literal_count: usize,
    path: &'static str,
}

#[derive(Debug, PartialEq)]
enum Segment {
    Literal(&'static str),
    Param,
}

impl CompiledPath {
    fn matches(&self, path: &str) -> bool {
        // Exact segmentation: only the single leading slash is
        // structural. A trailing slash (`/app/tasks/`) yields a real
        // empty segment and cannot match — no implicit normalization
        // or redirect (§4.5). `"/"` is zero segments; a doubled or
        // empty interior segment can never match (literal compares
        // fail, `Param` requires non-empty).
        let segs: Vec<&str> = if path == "/" {
            Vec::new()
        } else {
            path.strip_prefix('/').unwrap_or(path).split('/').collect()
        };
        if segs.len() != self.segments.len() {
            return false;
        }
        segs.iter()
            .zip(&self.segments)
            .all(|(got, want)| match want {
                Segment::Literal(lit) => lit == got,
                Segment::Param => !got.is_empty(),
            })
    }
}

/// The admission route allowlist — built from the same [`RouteSpec`]s
/// that register the axum handlers.
#[derive(Debug)]
pub struct RouteTable {
    paths: Vec<CompiledPath>,
}

impl RouteTable {
    /// Compiles the route specs. Errors (`FailureKind::Invalid`) on a
    /// malformed template, a duplicate `(method, path)` pair, or a
    /// wildcard segment other than a whole `{param}`.
    pub fn build(specs: &[RouteSpec]) -> Result<Self, Failure> {
        let mut paths: Vec<CompiledPath> = Vec::new();
        for spec in specs {
            let segments = compile_path(spec.path)?;
            let literal_count = segments
                .iter()
                .filter(|s| matches!(s, Segment::Literal(_)))
                .count();
            match paths.iter_mut().find(|p| p.path == spec.path) {
                Some(existing) => {
                    if existing.methods.iter().any(|(m, _)| *m == spec.method) {
                        return Err(Failure::new(
                            FailureKind::Invalid,
                            "transport_route",
                            format!("duplicate route {} {}", spec.method, spec.path),
                        ));
                    }
                    existing.methods.push((spec.method.clone(), spec.policy));
                }
                None => paths.push(CompiledPath {
                    segments,
                    methods: vec![(spec.method.clone(), spec.policy)],
                    literal_count,
                    path: spec.path,
                }),
            }
        }
        // Most-literal-segments first so `/app/tasks/new` outranks
        // `/app/tasks/{task_id}` on a concrete request path.
        paths.sort_by_key(|a| std::cmp::Reverse(a.literal_count));
        Ok(Self { paths })
    }

    /// The admission lookup. `HEAD` falls back to a `GET` registration
    /// (axum `get()` answers HEAD too).
    #[must_use]
    pub fn match_route(&self, method: &Method, path: &str) -> RouteMatch {
        let mut method_allowed = false;
        for entry in &self.paths {
            if !entry.matches(path) {
                continue;
            }
            let effective = if method == Method::HEAD {
                Method::GET
            } else {
                method.clone()
            };
            if let Some((_, policy)) = entry.methods.iter().find(|(m, _)| *m == effective) {
                return RouteMatch::Matched {
                    policy: *policy,
                    template: entry.path,
                };
            }
            method_allowed = true;
        }
        if method_allowed {
            RouteMatch::MethodNotAllowed
        } else {
            RouteMatch::NotFound
        }
    }

    /// The `Allow` header for a concrete path (used by the fixed `405`
    /// outcome; mirrors axum's comma-joined order).
    #[must_use]
    pub fn allow_for(&self, path: &str) -> Option<String> {
        for entry in &self.paths {
            if entry.matches(path) {
                let methods: Vec<Method> = entry.methods.iter().map(|(m, _)| m.clone()).collect();
                return Some(allow_header(&methods));
            }
        }
        None
    }
}

fn compile_path(path: &'static str) -> Result<Vec<Segment>, Failure> {
    if !path.starts_with('/') {
        return Err(Failure::new(
            FailureKind::Invalid,
            "transport_route",
            format!("route path must start with /: {path}"),
        ));
    }
    let mut segments = Vec::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg.starts_with('{') || seg.ends_with('}') {
            // Only whole-segment `{name}` placeholders are supported.
            let valid = seg.starts_with('{')
                && seg.ends_with('}')
                && seg.len() > 2
                && seg[1..seg.len() - 1]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid {
                return Err(Failure::new(
                    FailureKind::Invalid,
                    "transport_route",
                    format!("unsupported path parameter segment in {path}"),
                ));
            }
            segments.push(Segment::Param);
        } else if seg.contains('*') {
            return Err(Failure::new(
                FailureKind::Invalid,
                "transport_route",
                format!("wildcards are not admitted in {path}"),
            ));
        } else {
            segments.push(Segment::Literal(seg));
        }
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(method: Method, path: &'static str) -> RouteSpec {
        RouteSpec {
            method,
            path,
            policy: RoutePolicy::safe_get(RouteClass::App),
        }
    }

    #[test]
    fn exact_and_template_matching() {
        let table = RouteTable::build(&[
            spec(Method::GET, "/app/tasks"),
            spec(Method::GET, "/app/tasks/{task_id}"),
            spec(Method::POST, "/app/tasks/{task_id}/cancel"),
            spec(Method::GET, "/app/tasks/new"),
        ])
        .unwrap();
        assert!(matches!(
            table.match_route(&Method::GET, "/app/tasks"),
            RouteMatch::Matched { .. }
        ));
        assert!(matches!(
            table.match_route(&Method::GET, "/app/tasks/abc"),
            RouteMatch::Matched { .. }
        ));
        // literal `new` outranks the `{task_id}` template
        assert!(matches!(
            table.match_route(&Method::GET, "/app/tasks/new"),
            RouteMatch::Matched { .. }
        ));
        assert!(matches!(
            table.match_route(&Method::POST, "/app/tasks/abc/cancel"),
            RouteMatch::Matched { .. }
        ));
        assert_eq!(
            table.match_route(&Method::GET, "/app/tasks/abc/cancel"),
            RouteMatch::MethodNotAllowed
        );
        assert_eq!(
            table.match_route(&Method::GET, "/nope"),
            RouteMatch::NotFound
        );
        // HEAD falls back to GET
        assert!(matches!(
            table.match_route(&Method::HEAD, "/app/tasks"),
            RouteMatch::Matched { .. }
        ));
        // trailing slash does not match (no fixed-path redirect behavior)
        assert_eq!(
            table.match_route(&Method::GET, "/app/tasks/"),
            RouteMatch::NotFound
        );
    }

    #[test]
    fn allow_header_shape() {
        let table = RouteTable::build(&[
            spec(Method::GET, "/x"),
            spec(Method::POST, "/x"),
            spec(Method::GET, "/only-get"),
        ])
        .unwrap();
        assert_eq!(table.allow_for("/x").unwrap(), "GET,HEAD,POST");
        assert_eq!(table.allow_for("/only-get").unwrap(), "GET,HEAD");
    }

    #[test]
    fn build_rejects_duplicates_and_bad_templates() {
        assert!(RouteTable::build(&[spec(Method::GET, "/x"), spec(Method::GET, "/x")]).is_err());
        assert!(RouteTable::build(&[spec(Method::GET, "/x/*rest")]).is_err());
        assert!(RouteTable::build(&[spec(Method::GET, "/x/{bad-seg}")]).is_err());
        assert!(RouteTable::build(&[spec(Method::GET, "no-slash")]).is_err());
    }

    #[test]
    fn effective_caps_clamp() {
        let mut p = RoutePolicy::safe_get(RouteClass::Api);
        assert_eq!(p.effective_response_cap(), HTML_RESPONSE_CAP);
        assert_eq!(p.effective_body_limit(), MAX_BODY_BUFFER);
        p.response_cap = usize::MAX;
        assert_eq!(p.effective_response_cap(), MAX_RESPONSE_BUFFER);
        p.body_limit = usize::MAX;
        assert_eq!(p.effective_body_limit(), MAX_BODY_BUFFER);
    }
}
