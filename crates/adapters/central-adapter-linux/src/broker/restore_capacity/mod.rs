//! Restore-capacity reserve + receipt authority — the broker-side port
//! of upstream `internal/adapter/authority/broker/restore_capacity_*.go`.
//!
//! The design: the restore helper physically reserves disk (`0xc3`
//! frames), the broker records signed reserve/receipt records, and the
//! restore engine draws bearer receipts (`0xc4` frames) that the
//! destructive-restore credential (`0xc2` kind 1) is gated on. `0xc5` is
//! the root-only inspection surface. Nothing in this module is reachable
//! until the stores it needs exist; unsupported configurations keep the
//! fail-closed denial upstream specifies.
//!
//! Submodules:
//!
//! - [`receipt`] — receipt records, bearer proofs, draw/spend ledgers.
//! - [`frame`] — the `0xc4` receipt frame handler + engine client.
//! - [`reserve_frame`] — the `0xc3` reserve frame handler + helper client.
//! - [`object`] — the daemon's read-only reserve-object presence check.
//! - [`store`] — the protected, HMAC-signed set/member/operation record
//!   store.
//! - [`store_path`] — the single resolver naming device-keyed reserve
//!   objects; every physical-object lookup in this package routes
//!   through it.

pub mod allocation;
pub mod frame;
pub(crate) mod gate;
pub mod helper;
pub mod inspection;
pub(crate) mod object;
/// `broker.RestoreCapacityReceipt` — upstream exports the wire type;
/// the root restore engine's composition maps it onto the frozen
/// capacity source's receipt shape.
pub mod receipt;
pub mod reserve_frame;
pub(crate) mod store;
pub(crate) mod store_path;
pub mod sweep;

use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};

/// `restoreCapacityReserveAbsoluteLifetime` — the set's absolute expiry
/// (`RestoreOperationAbsoluteLifetime` upstream, 8h). Distinct from the
/// 20-minute receipt window: provisional marks lapse on the receipt's
/// clock while the reserve object is held on this one.
pub(crate) const RESERVE_ABSOLUTE_LIFETIME: time::Duration = time::Duration::hours(8);

/// `restoreCapacityReserveRoles` — the four physical demand roles in
/// upstream order; a reserve set is complete when every one has a
/// durable member record.
pub(crate) const RESERVE_ROLES: [ReserveRole; 4] = [
    ReserveRole::PostgresData,
    ReserveRole::PostgresWal,
    ReserveRole::PostgresTemp,
    ReserveRole::ObjectData,
];

/// `RestoreCapacityReserveRole` — the JSON shape is the Go string type
/// verbatim (`"postgres_data"`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveRole {
    PostgresData,
    PostgresWal,
    PostgresTemp,
    ObjectData,
}

impl ReserveRole {
    /// The wire/record string — `string(role)` in Go.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PostgresData => "postgres_data",
            Self::PostgresWal => "postgres_wal",
            Self::PostgresTemp => "postgres_temp",
            Self::ObjectData => "object_data",
        }
    }

    /// `restoreCapacityReserveRoleRootPath` — pick this role's root path
    /// out of `RoleRoots`.
    pub(crate) fn root(self, roots: &central_backup::backup::capacity::RoleRoots) -> &str {
        match self {
            Self::PostgresData => roots.postgres_data.as_str(),
            Self::PostgresWal => roots.postgres_wal.as_str(),
            Self::PostgresTemp => roots.postgres_temp.as_str(),
            Self::ObjectData => roots.object_data.as_str(),
        }
    }
}

/// `RestoreCapacityReserveState` — `intent → allocated →
/// provisionally_consumed → verified`, plus `released`. Transitions
/// only ever move forward except release, which may fire from any
/// non-released state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveState {
    Intent,
    Allocated,
    ProvisionallyConsumed,
    Verified,
    Released,
}

// --- Sentinel refusals --------------------------------------------------
// Upstream discriminates with `errors.Is` sentinels; the Rust port keeps
// the same three-way split (absent / ambiguous / unavailable) on the
// `Failure` code, because sweep semantics turn on which one fired.

pub(crate) const RESERVE_UNAVAILABLE: &str = "broker_restore_reserve_unavailable";
pub(crate) const RESERVE_NOT_FOUND: &str = "broker_restore_reserve_not_found";
pub(crate) const RESERVE_AMBIGUOUS: &str = "broker_restore_reserve_ambiguous";

/// `errRestoreCapacityReserveUnavailable` — the record exists (or might)
/// but cannot be trusted: IO failure, wrong shape, bad signature.
pub(crate) fn reserve_unavailable(detail: impl Into<String>) -> Failure {
    Failure::internal(RESERVE_UNAVAILABLE, detail.into())
}

/// `errRestoreCapacityReserveNotFound` — the record is genuinely absent.
pub(crate) fn reserve_not_found(detail: impl Into<String>) -> Failure {
    Failure::denied(RESERVE_NOT_FOUND, detail.into())
}

/// `ErrRestoreCapacityReserveRecordAmbiguous` — bytes are present but do
/// not decode under the strict schema. Upstream retains these; callers
/// must never treat them as absent.
pub(crate) fn reserve_ambiguous(detail: impl Into<String>) -> Failure {
    Failure::invalid(RESERVE_AMBIGUOUS, detail.into())
}

pub(crate) fn is_reserve_not_found(f: &Failure) -> bool {
    f.code() == RESERVE_NOT_FOUND
}

pub(crate) fn is_reserve_ambiguous(f: &Failure) -> bool {
    f.code() == RESERVE_AMBIGUOUS
}
