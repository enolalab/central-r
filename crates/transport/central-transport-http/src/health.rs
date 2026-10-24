//! Health endpoints — port of upstream `health/handler.go` and the
//! kernel's `healthHandlerWith`.
//!
//! `/health/live` always returns `200` with the bounded JSON; the
//! profile-aware `/health/ready` returns `200` only while the probe
//! reports `Ready`, else `503`. Both carry the redacted
//! `{"status":..,"reason":..}` shape — remediation text, failure
//! detail, and proof material never reach the wire. The probe is the
//! narrow port the kernel's `Readiness` satisfies via an adapter (the
//! transport must not import `central-kernel`).

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// The lifecycle states the probe may report — mirrors
/// `central_kernel::readiness::State`'s wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeState {
    /// Startup admission in progress.
    Starting,
    /// Admitted and serving.
    Ready,
    /// Alive but not admitted.
    NotReady,
    /// Intentional stop settling.
    ShuttingDown,
    /// Terminal failure.
    Failed,
}

/// A bounded, non-sensitive readiness snapshot — what the kernel's
/// `HealthSnapshot` carries after `safe_reason`/`safe_remediation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSnapshot {
    /// Current lifecycle state.
    pub state: ProbeState,
    /// Already-bounded reason token (re-bounded here defensively).
    pub reason: String,
}

/// `ReadinessProbe` — the narrow kernel-readiness port (upstream's
/// `health.ReadinessProbe`). The kernel adapts `Readiness::health()`
/// into it at composition time.
pub trait ReadinessProbe: Send + Sync + 'static {
    /// The current bounded snapshot.
    fn health(&self) -> ProbeSnapshot;
}

#[derive(Serialize)]
struct BoundedHealth<'a> {
    status: &'a str,
    // Upstream serializes `reason` unconditionally — `""` on ready.
    reason: &'a str,
}

fn render(snapshot: &ProbeSnapshot) -> BoundedHealth<'_> {
    if snapshot.state == ProbeState::Ready {
        BoundedHealth {
            status: "ready",
            reason: "",
        }
    } else {
        BoundedHealth {
            status: "not_ready",
            reason: bound_reason(&snapshot.reason),
        }
    }
}

/// `GET /health/live` — always `200`; the process is alive.
pub async fn live(State(probe): State<Arc<dyn ReadinessProbe>>) -> Response {
    (StatusCode::OK, Json(render(&probe.health()))).into_response()
}

/// `GET /health/ready` — `200` only while admitted; `503` otherwise.
pub async fn ready(State(probe): State<Arc<dyn ReadinessProbe>>) -> Response {
    let snapshot = probe.health();
    let status = if snapshot.state == ProbeState::Ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(render(&snapshot))).into_response()
}

/// `boundReason` — collapses any reason to the kernel's safe bounded
/// set (mirrors `kernel.safeReason`; an unknown reason never reaches
/// the wire even if a future adapter sets one).
#[must_use]
pub fn bound_reason(reason: &str) -> &'static str {
    match reason {
        "CONFIG_INVALID" => "CONFIG_INVALID",
        "POSTGRES_UNAVAILABLE" => "POSTGRES_UNAVAILABLE",
        "POSTGRES_INCOMPATIBLE" => "POSTGRES_INCOMPATIBLE",
        "MIGRATION_REQUIRED" => "MIGRATION_REQUIRED",
        "LEASE_LOST" => "LEASE_LOST",
        "BACKGROUND_LOOP_FAILED" => "BACKGROUND_LOOP_FAILED",
        "SHUTTING_DOWN" => "SHUTTING_DOWN",
        "PORT_IN_USE" => "PORT_IN_USE",
        "TLS_INVALID" => "TLS_INVALID",
        "BOOTSTRAP_RECONCILIATION_FAILED" => "BOOTSTRAP_RECONCILIATION_FAILED",
        "EPOCH_MISMATCH" => "EPOCH_MISMATCH",
        "READY_EXPIRED" => "READY_EXPIRED",
        "PROVISION_REQUIRED" => "PROVISION_REQUIRED",
        "RESUME_REQUIRED" => "RESUME_REQUIRED",
        "REPAIR_REQUIRED" => "REPAIR_REQUIRED",
        _ => "UNAVAILABLE",
    }
}
