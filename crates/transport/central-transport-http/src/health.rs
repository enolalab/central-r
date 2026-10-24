//! Health endpoints — port of upstream `health/handler.go` and the
//! kernel's `healthHandlerWith`.
//!
//! `/health/live` always returns `200` with the bounded JSON; the
//! profile-aware `/health/ready` returns `200` only while the probe
//! reports `Ready`, else `503`. The wire shape is upstream
//! `kernel.MarshalHealth` — `status` always, `reason` always (the
//! bounded allowlist maps `""` to `UNAVAILABLE`), `remediation` and
//! `failure_class` only when present (`omitempty`). Proof material
//! and unbounded text never reach the wire. The probe is the narrow
//! port the kernel's `Readiness` satisfies via an adapter (the
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
    /// Bounded remediation copy (re-bounded via [`safe_remediation`]);
    /// serialized only when non-empty (`omitempty`).
    pub remediation: String,
    /// Exit class associated with the failure; serialized only when
    /// non-zero (`omitempty`).
    pub failure_class: u8,
}

/// `ReadinessProbe` — the narrow kernel-readiness port (upstream's
/// `health.ReadinessProbe`). The kernel adapts `Readiness::health()`
/// into it at composition time.
pub trait ReadinessProbe: Send + Sync + 'static {
    /// The current bounded snapshot.
    fn health(&self) -> ProbeSnapshot;
}

/// The `MarshalHealth` wire shape: `status` and `reason` always
/// (`bound_reason` never returns empty — `""` maps to `UNAVAILABLE`,
/// so `omitempty` would never fire anyway); `remediation` and
/// `failure_class` only when present, matching the upstream
/// `omitempty` fields.
#[derive(Serialize)]
struct BoundedHealth<'a> {
    status: &'a str,
    reason: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    remediation: &'a str,
    #[serde(skip_serializing_if = "is_zero")]
    failure_class: u8,
}

fn is_zero(v: &u8) -> bool {
    *v == 0
}

fn render(snapshot: &ProbeSnapshot) -> BoundedHealth<'_> {
    BoundedHealth {
        status: if snapshot.state == ProbeState::Ready {
            "ready"
        } else {
            "not_ready"
        },
        // `safeReason` runs unconditionally upstream — on a ready
        // snapshot the empty reason collapses to `UNAVAILABLE`.
        reason: bound_reason(&snapshot.reason),
        remediation: safe_remediation(&snapshot.remediation),
        failure_class: snapshot.failure_class,
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

/// `safeRemediation` — bounded remediation copy: over 256 bytes or
/// containing control characters collapses to empty (which the
/// serializer then omits). Ported here because the transport cannot
/// import `central-kernel`.
#[must_use]
pub fn safe_remediation(remediation: &str) -> &str {
    if remediation.len() > 256 {
        return "";
    }
    if remediation
        .chars()
        .any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f)
    {
        return "";
    }
    remediation
}
