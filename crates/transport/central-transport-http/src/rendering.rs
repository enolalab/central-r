//! Rendering — the Askama port of upstream `rendering/renderer.go`.
//!
//! Templates are compile-time checked at build (`askama::Template`),
//! escaping is automatic (`escape = "html"` default), and no template
//! emits inline script or style — §4.5's nonce-free strict-CSP
//! contract. `|safe`/`MarkupDisplay::Unsafe` are prohibited outside a
//! reviewed allowlist of constant markup; none exists today.
//!
//! Task 12 adds the real surface templates; this module ships the base
//! [`layout`](templates/layout.html) plus the generic error page the
//! fixed `404`/`405` HTML outcomes use.

use askama::Template;

/// `Page not found` / `Method not allowed` — the generic error page
/// rendered for fixed HTML outcomes. It echoes no request data: the
/// title and message are call-site constants.
#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage<'a> {
    title: &'a str,
    message: &'a str,
}

/// Renders the generic error page. Rendering cannot fail on this
/// fixed-shape template; a failure would still yield a complete (if
/// minimal) safe HTML document rather than an empty body.
#[must_use]
pub fn render_error_page(title: &str, message: &str) -> String {
    ErrorPage { title, message }.render().unwrap_or_else(|_| {
        // Compile-time-checked template rendering a plain &str cannot
        // realistically fail; fall back to a static shell that still
        // satisfies the "safe static HTML" contract.
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error</title></head><body><p>Something went wrong.</p></body></html>"
            .to_string()
    })
}
