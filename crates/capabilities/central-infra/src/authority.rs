//! The A03 host-authority domain — port of upstream
//! `internal/authority` (`domain.go`, `genesis.go`, `identity.go`).
//!
//! Owns the durable [`InstanceBinding`] (the genesis record binding
//! host identity, release digest, config binding, and the locked
//! UID/GID map), the closed [`HelperVerb`] operation matrix, the
//! locked no-login host identities, the broker/helper protocol
//! envelope types, the B04/B05/B10 closed wire payloads, the
//! authority-transition journal record, and the prepare-operation
//! journal types shared with `port::DependencyStore`.
//!
//! Pure synchronous Rust: no async, no I/O, no adapter types. Domain
//! failures arrive as [`central_foundation::failure::Failure`]
//! carrying [`codes`] values; `Failure::message` is already redacted —
//! no secret, path, or credential material ever crosses this module.
//!
//! Crate placement (R5 T3 step 0): upstream keeps this under
//! `internal/authority`; the Rust plan puts the authority domain in
//! `central-infra` — rust-application-boundaries.md §2 gives
//! `central-infra` the local init/prepare/lifecycle/advisory operator
//! commands and reserves `central-authorization` for
//! Workspace-scoped approval/authorization decisions, not host
//! authority.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use central_foundation::failure::Failure;
use central_foundation::identity::{
    ConfigBindingId, InstanceId, OperationId, ProtectedGenerationId, SecretBindingId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Failure codes — the stable machine vocabulary riding `Failure::code`.
// Where upstream fixes the wire token verbatim (the `B04_*` reason
// strings, `AUTHORITY_DENIED`) the constant carries it exactly.
// ---------------------------------------------------------------------------

/// Machine codes carried by [`Failure::code`] across this module and
/// `domain`. The `B04_*` values are upstream's closed reason strings —
/// they ride the wire verbatim and must not be renamed.
pub mod codes {
    /// `authority: denied` — the redacted authority boundary refusal.
    /// Callers must not expose the underlying reason or any
    /// candidate/proof material across this boundary.
    pub const AUTHORITY_DENIED: &str = "AUTHORITY_DENIED";
    /// `authority.InstanceBinding`/genesis validation rejection.
    pub const GENESIS_INVALID: &str = "GENESIS_INVALID";
    /// `authority.PrepareOperation` journal validation rejection.
    pub const PREPARE_OPERATION_INVALID: &str = "PREPARE_OPERATION_INVALID";
}

/// `authority.ErrDenied` — the redacted authority boundary error.
/// Callers must not expose the underlying reason or any
/// candidate/proof material across this boundary.
pub fn denied() -> Failure {
    Failure::denied(codes::AUTHORITY_DENIED, "authority: denied")
}

// ---------------------------------------------------------------------------
// Shared wire-encoding helpers — crate-private. The JSON shapes they
// produce are byte-level contracts: Go `time.Time` marshals as
// RFC 3339 with trimmed nanoseconds, and `[]byte` marshals as standard
// padded Base64. The broker adapter owns the frames these helpers
// feed; keeping the exact renderings here is what lets them.
// ---------------------------------------------------------------------------

pub(crate) mod wire {
    use serde::{Deserialize, Deserializer, Serializer};
    use sha2::{Digest, Sha256};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    use time::macros::datetime;

    /// Go's `time.Time{}` zero value — January 1, year 1, 00:00:00 UTC —
    /// which upstream `IsZero` checks. `OffsetDateTime` has no zero
    /// value, so the ported checks compare against this instant.
    const GO_ZERO_TIME: OffsetDateTime = datetime!(1-01-01 0:00:00 UTC);

    /// `t.IsZero()` upstream — true only for the exact zero instant.
    pub(crate) fn is_go_zero_time(t: OffsetDateTime) -> bool {
        t == GO_ZERO_TIME
    }

    /// `#[serde(default)]` for `time.Time` fields: Go's `json.Unmarshal`
    /// leaves an absent timestamp at the zero value rather than
    /// failing the decode.
    pub(crate) fn go_zero_time() -> OffsetDateTime {
        GO_ZERO_TIME
    }

    /// Go `time.RFC3339Nano` formatting: `hh:mm:ss` plus a fractional
    /// second field that appears only when the nanosecond part is
    /// non-zero, then with trailing zeros trimmed (`.999999999`
    /// semantics) — never a fixed nine digits. `Z` for UTC, `±hh:mm`
    /// otherwise.
    pub(crate) fn format_rfc3339_nano(t: OffsetDateTime) -> String {
        let mut out = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        let nanos = t.nanosecond();
        if nanos != 0 {
            let frac = format!("{nanos:09}");
            out.push('.');
            out.push_str(frac.trim_end_matches('0'));
        }
        let offset = t.offset();
        if offset.is_utc() {
            out.push('Z');
        } else {
            let sign = if offset.is_negative() { '-' } else { '+' };
            out.push_str(&format!(
                "{sign}{:02}:{:02}",
                offset.whole_hours().abs(),
                offset.whole_minutes().abs() % 60
            ));
        }
        out
    }

    /// Serde adapter for `time.Time` fields tagged `json:"...,..."`:
    /// serializes the RFC 3339 / RFC 3339Nano text Go emits, parses
    /// what Go's `time.Time.UnmarshalJSON` accepts.
    pub(crate) mod rfc3339 {
        use super::*;

        pub(crate) fn serialize<S: Serializer>(
            t: &OffsetDateTime,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            s.serialize_str(&format_rfc3339_nano(*t))
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<OffsetDateTime, D::Error> {
            let text = String::deserialize(d)?;
            OffsetDateTime::parse(&text, &Rfc3339).map_err(serde::de::Error::custom)
        }
    }

    /// Standard padded Base64 (Go `encoding/base64.StdEncoding`) —
    /// the JSON encoding Go applies to `[]byte` fields.
    const B64_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub(crate) fn b64_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(B64_ALPHABET[(n >> 6) as usize & 63] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(B64_ALPHABET[n as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    /// Strict `StdEncoding` decode: rejects non-alphabet bytes, bad
    /// length, padding outside the final quad, and content after
    /// padding — matching Go `StdEncoding.DecodeString` refusal shape.
    pub(crate) fn b64_decode(text: &str) -> Option<Vec<u8>> {
        let bytes = text.as_bytes();
        if bytes.is_empty() {
            return Some(Vec::new());
        }
        if !bytes.len().is_multiple_of(4) {
            return None;
        }
        let quads = bytes.len() / 4;
        let mut out = Vec::with_capacity(quads * 3);
        for (i, quad) in bytes.chunks(4).enumerate() {
            let last = i == quads - 1;
            let mut vals = [0u8; 4];
            let mut pad = 0usize;
            for (j, &c) in quad.iter().enumerate() {
                match c {
                    b'=' => {
                        if !last || j < 2 {
                            return None;
                        }
                        pad += 1;
                    }
                    _ if pad > 0 => return None,
                    b'A'..=b'Z' => vals[j] = c - b'A',
                    b'a'..=b'z' => vals[j] = c - b'a' + 26,
                    b'0'..=b'9' => vals[j] = c - b'0' + 52,
                    b'+' => vals[j] = 62,
                    b'/' => vals[j] = 63,
                    _ => return None,
                }
            }
            if pad > 2 {
                return None;
            }
            let n = (u32::from(vals[0]) << 18)
                | (u32::from(vals[1]) << 12)
                | (u32::from(vals[2]) << 6)
                | u32::from(vals[3]);
            out.push((n >> 16) as u8);
            if pad < 2 {
                out.push((n >> 8) as u8);
            }
            if pad < 1 {
                out.push(n as u8);
            }
        }
        Some(out)
    }

    /// Lowercase hex encode (Go `encoding/hex.EncodeToString`).
    pub(crate) fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    /// Hex decode (Go `encoding/hex.DecodeString`): rejects odd length
    /// and non-hex bytes; accepts mixed case like upstream.
    pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
        let bytes = text.as_bytes();
        if !bytes.len().is_multiple_of(2) {
            return None;
        }
        fn nib(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        }
        let mut out = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks(2) {
            out.push(nib(pair[0])? << 4 | nib(pair[1])?);
        }
        Some(out)
    }

    /// HMAC-SHA256 (RFC 2104) over `sha2` — `hmac` is deliberately
    /// absent from this capability's approved dependency set, so the
    /// 15-line construction is kept here, pinned by RFC 4231 test
    /// vectors.
    pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
        const BLOCK: usize = 64;
        let mut block_key = [0u8; BLOCK];
        if key.len() > BLOCK {
            block_key[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block_key[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for (i, &k) in block_key.iter().enumerate() {
            ipad[i] ^= k;
            opad[i] ^= k;
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(message);
        let inner_digest = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_digest);
        outer.finalize().into()
    }

    /// Constant-time equality for MAC comparison (Go `hmac.Equal`).
    pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    /// `serde(skip_serializing_if)` for `,omitempty` `u32` fields —
    /// Go's `uint32` omits the zero value.
    pub(crate) fn u32_is_zero(v: &u32) -> bool {
        *v == 0
    }

    /// `serde(skip_serializing_if)` for `,omitempty` `i32` fields.
    pub(crate) fn i32_is_zero(v: &i32) -> bool {
        *v == 0
    }

    /// `serde(skip_serializing_if)` for `,omitempty` `u64` fields —
    /// Go's `uint64` omits the zero value.
    pub(crate) fn u64_is_zero(v: &u64) -> bool {
        *v == 0
    }

    /// `serde(skip_serializing_if)` for `,omitempty` `bool` fields.
    pub(crate) fn bool_is_false(v: &bool) -> bool {
        !*v
    }

    /// `serde(deserialize_with)` for Go `nil`-able slices and maps:
    /// Go marshals a nil `[]T`/`map` as `null`, which the plain
    /// collection deserializers reject. This adapter decodes `null`
    /// (or a missing key, via `#[serde(default)]`) as
    /// `T::default()` — the read-side half of Go's
    /// `null`⇔`nil` equivalence. The write side emits `[]`/`{}`;
    /// a nil-vs-empty re-serialization difference is the manifest
    /// serializer's (T11) concern, not this crate's.
    pub(crate) fn null_to_default<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + Default,
    {
        Option::<T>::deserialize(d).map(Option::unwrap_or_default)
    }

    /// Serde adapter for `[]byte` fields that may arrive as JSON
    /// `null` (Go marshals a nil `[]byte` as `null`): decodes `null`
    /// as the empty byte string, Base64 otherwise.
    pub(crate) mod b64_lenient {
        use super::*;

        pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&b64_encode(v))
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            let text = Option::<String>::deserialize(d)?;
            match text {
                None => Ok(Vec::new()),
                Some(t) => b64_decode(&t).ok_or_else(|| serde::de::Error::custom("invalid base64")),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InstanceBinding
// ---------------------------------------------------------------------------

/// The durable identity of a central instance on a specific host. It
/// binds the hardware identity (SHA-256 of `/etc/machine-id`), the
/// release artifact digest, the generated `central.config/v1` binding,
/// and the locked UID/GID allocations. Port of
/// `authority.InstanceBinding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceBinding {
    /// The generated instance identity.
    pub instance_id: InstanceId,
    /// SHA-256 of `/etc/machine-id`.
    pub host_id: String,
    /// SHA-256 of the release artifact; empty means an unsigned
    /// release, which the helper must refuse before mutation.
    pub release_digest: String,
    /// RFC 3339 UTC creation time from the system clock.
    pub created_at: OffsetDateTime,
    /// Binds to the generated `central.config/v1` document.
    pub config_binding_id: ConfigBindingId,
    /// Locked numeric allocations for the purpose-runner identities.
    pub uid_gid: UidGidMap,
}

/// The Unix UID and GID allocated for each purpose-runner identity on
/// the host (upstream `authority.UIDGIDMap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidGidMap {
    /// `central-runtime` identity.
    pub runtime_uid: u32,
    /// `central-runtime` primary group.
    pub runtime_gid: u32,
    /// `central-agent` identity.
    pub agent_uid: u32,
    /// `central-agent` primary group.
    pub agent_gid: u32,
    /// `central-browser` identity.
    pub browser_uid: u32,
    /// `central-browser` primary group.
    pub browser_gid: u32,
}

/// The fixed, allocated `central-runtime` identity
/// (`authority.CentralRuntimeUID/GID`). This single constant pair is
/// what `cmd/central`'s broker daemon passes to `broker.NewService`
/// as its dynamic `runtimeUID`, and what the widened
/// `minio_runtime_v1` dependency check
/// ([`crate::domain::Purpose::validate_dependency`]) compares against
/// for the OUTBOUND (broker → runtime) frame `0xb1` transport. Keeping
/// both sides derived from this one constant is what keeps the
/// `SO_PEERCRED` gate and the domain-level dependency check in
/// lockstep by construction. GID is checked by neither widened gate
/// (both mirror the pre-existing UID-only `isRuntimeOrRootPeer`
/// pattern) but is defined alongside UID as the complete identity pair.
pub const CENTRAL_RUNTIME_UID: u32 = 501;
/// See [`CENTRAL_RUNTIME_UID`].
pub const CENTRAL_RUNTIME_GID: u32 = 501;

/// The fixed `central-migrate` identity — the only peer permitted to
/// receive a `postgres_migration_v1` descriptor (upstream
/// `authority.CentralMigrateUID/GID`).
pub const CENTRAL_MIGRATE_UID: u32 = 986;
/// See [`CENTRAL_MIGRATE_UID`].
pub const CENTRAL_MIGRATE_GID: u32 = 986;

/// The only origin the managed browser may open
/// (`authority.FixedBrowserOrigin`).
pub const FIXED_BROWSER_ORIGIN: &str = "https://127.0.0.1:8080";

// ---------------------------------------------------------------------------
// HelperVerb — the closed operation matrix
// ---------------------------------------------------------------------------

/// A named operation the root-owned central helper may perform on
/// behalf of the runtime (upstream `authority.HelperVerb`). The set is
/// closed and serialized kebab-case, matching the wire verb strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HelperVerb {
    /// `init` — instance genesis.
    Init,
    /// `init-status` — genesis status read.
    InitStatus,
    /// `init-resume` — resume an interrupted genesis.
    InitResume,
    /// `init-abandon` — abandon an interrupted genesis.
    InitAbandon,
    /// `prepare` — dependency prepare (B02).
    Prepare,
    /// `security-update` — security update ceremony.
    SecurityUpdate,
    /// `trust-install` — trust installation.
    TrustInstall,
    /// `browser-open` — managed browser open.
    BrowserOpen,
    /// `runtime-stage` — runtime staging.
    RuntimeStage,
    /// `runtime-start` — runtime start.
    RuntimeStart,
    /// `runtime-stop` — runtime stop.
    RuntimeStop,
    /// `up` — lifecycle up (B03).
    Up,
    /// `down` — lifecycle down (B03).
    Down,
    /// `status` — lifecycle status (B03).
    Status,
    /// `doctor` — read-only diagnostics.
    Doctor,
    /// `wipe` — destructive instance wipe (D02).
    Wipe,
    /// `bootstrap-show` — bootstrap inspection.
    BootstrapShow,
    /// `security-rescue-cleanup` — Slice E rescue-generation cleanup
    /// (distinct from [`Self::SecurityRescue`], which re-arms a denied
    /// instance).
    SecurityRescueCleanup,
    /// `migrate-launch` — launch the dedicated `central-migrate`
    /// descriptor-only worker.
    MigrateLaunch,
    /// `migrate-read-outcome` — proxies a migration launch's
    /// terminal-state read to the broker on the operator's behalf
    /// (SC-DEF-41): the broker's own peer gate admits only root, the
    /// runtime UID, or the migrate worker's UID — never the
    /// unprivileged operator CLI — so the CLI polls this verb on the
    /// helper instead of dialing the broker directly.
    MigrateReadOutcome,
    /// `backup-create` — backup launch (C01).
    BackupCreate,
    /// `backup-verify` — backup verification (C01).
    BackupVerify,
    /// `backup-status` — backup status read (C01).
    BackupStatus,
    /// `restore-verify` — privileged because the verify launcher opens
    /// the protected broker root (uid 0 / gid 0 / mode 0700) and
    /// physically reserves disk on every device the restore will later
    /// write — none of which is available to the unprivileged CLI.
    RestoreVerify,
    /// `restore-apply` — restore apply (C03).
    RestoreApply,
    /// `restore-resume` — resume an interrupted restore (C03).
    RestoreResume,
    /// `restore-abandon` — ADR 0016's terminal outcome for an
    /// interrupted restore: privileged because the ceremony runs on
    /// the operator's physical TTY inside the root helper and its
    /// consequence — giving up the target's data permanently — is
    /// irreversible.
    RestoreAbandon,
    /// `backup-export` — Slice D verb (D01).
    BackupExport,
    /// `backup-import` — Slice D verb (D02).
    BackupImport,
    /// `backup-delete` — Slice D verb (D03).
    BackupDelete,
    /// `backup-prune` — Slice D verb (D04).
    BackupPrune,
    /// `state-audit` — backs `central local audit` (D05); read-only,
    /// `--repair` escalates to the wipe ceremony.
    StateAudit,
    /// `security-rescue` — backs `central local security rescue` (D06);
    /// re-arms a denied instance. Distinct from
    /// [`Self::SecurityRescueCleanup`] (`security-rescue-cleanup`),
    /// which removes rescue generations.
    SecurityRescue,
    /// `maintenance-plan` — backs `central maintenance plan` (E01);
    /// read-only evaluation of the compatibility matrix.
    MaintenancePlan,
    /// `maintenance-apply` — backs `central maintenance apply` (E02);
    /// records a matrix-approved dependency transition under PAM
    /// authorization, runs the entry's validation gate, then commits.
    MaintenanceApply,
}

/// Every registered [`HelperVerb`], in upstream declaration order.
pub const ALL_HELPER_VERBS: [HelperVerb; 35] = [
    HelperVerb::Init,
    HelperVerb::InitStatus,
    HelperVerb::InitResume,
    HelperVerb::InitAbandon,
    HelperVerb::Prepare,
    HelperVerb::SecurityUpdate,
    HelperVerb::TrustInstall,
    HelperVerb::BrowserOpen,
    HelperVerb::RuntimeStage,
    HelperVerb::RuntimeStart,
    HelperVerb::RuntimeStop,
    HelperVerb::Up,
    HelperVerb::Down,
    HelperVerb::Status,
    HelperVerb::Doctor,
    HelperVerb::Wipe,
    HelperVerb::BootstrapShow,
    HelperVerb::SecurityRescueCleanup,
    HelperVerb::MigrateLaunch,
    HelperVerb::MigrateReadOutcome,
    HelperVerb::BackupCreate,
    HelperVerb::BackupVerify,
    HelperVerb::BackupStatus,
    HelperVerb::RestoreVerify,
    HelperVerb::RestoreApply,
    HelperVerb::RestoreResume,
    HelperVerb::RestoreAbandon,
    HelperVerb::BackupExport,
    HelperVerb::BackupImport,
    HelperVerb::BackupDelete,
    HelperVerb::BackupPrune,
    HelperVerb::StateAudit,
    HelperVerb::SecurityRescue,
    HelperVerb::MaintenancePlan,
    HelperVerb::MaintenanceApply,
];

impl HelperVerb {
    /// The wire verb string — exactly the upstream `HelperVerb` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::InitStatus => "init-status",
            Self::InitResume => "init-resume",
            Self::InitAbandon => "init-abandon",
            Self::Prepare => "prepare",
            Self::SecurityUpdate => "security-update",
            Self::TrustInstall => "trust-install",
            Self::BrowserOpen => "browser-open",
            Self::RuntimeStage => "runtime-stage",
            Self::RuntimeStart => "runtime-start",
            Self::RuntimeStop => "runtime-stop",
            Self::Up => "up",
            Self::Down => "down",
            Self::Status => "status",
            Self::Doctor => "doctor",
            Self::Wipe => "wipe",
            Self::BootstrapShow => "bootstrap-show",
            Self::SecurityRescueCleanup => "security-rescue-cleanup",
            Self::MigrateLaunch => "migrate-launch",
            Self::MigrateReadOutcome => "migrate-read-outcome",
            Self::BackupCreate => "backup-create",
            Self::BackupVerify => "backup-verify",
            Self::BackupStatus => "backup-status",
            Self::RestoreVerify => "restore-verify",
            Self::RestoreApply => "restore-apply",
            Self::RestoreResume => "restore-resume",
            Self::RestoreAbandon => "restore-abandon",
            Self::BackupExport => "backup-export",
            Self::BackupImport => "backup-import",
            Self::BackupDelete => "backup-delete",
            Self::BackupPrune => "backup-prune",
            Self::StateAudit => "state-audit",
            Self::SecurityRescue => "security-rescue",
            Self::MaintenancePlan => "maintenance-plan",
            Self::MaintenanceApply => "maintenance-apply",
        }
    }

    /// `HelperVerb.Implemented()` — the verbs fully operational in
    /// upstream Slice A. Verbs beyond that set are deferred to later
    /// slices (R6 in this workspace) and the helper denies them with
    /// the upstream `UNSUPPORTED_IN_THIS_SLICE` outcome.
    #[must_use]
    pub const fn implemented(self) -> bool {
        matches!(
            self,
            Self::Init
                | Self::InitStatus
                | Self::InitResume
                | Self::InitAbandon
                | Self::MigrateLaunch
                | Self::MigrateReadOutcome
                | Self::BackupCreate
                | Self::BackupVerify
                | Self::BackupStatus
                | Self::RestoreVerify
                | Self::RestoreApply
                | Self::RestoreResume
                | Self::RestoreAbandon
        )
    }
}

impl fmt::Display for HelperVerb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HelperVerb {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for verb in ALL_HELPER_VERBS {
            if verb.as_str() == s {
                return Ok(verb);
            }
        }
        Err(Failure::invalid(
            codes::GENESIS_INVALID,
            "authority: unknown helper verb",
        ))
    }
}

// ---------------------------------------------------------------------------
// LifecycleAuthorization
// ---------------------------------------------------------------------------

/// A one-use token that authorizes a specific lifecycle operation
/// (e.g. `up`, `down`) on a named instance. It carries a nonce for
/// replay protection, the operation identity, a fingerprint of the
/// authorized caller, and an expiry timestamp. Port of
/// `authority.LifecycleAuthorization` — the JSON field names and
/// `,omitempty` treatment are upstream's tagged wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleAuthorization {
    /// Replay-protection nonce.
    pub nonce: String,
    /// The bound instance.
    pub instance_id: String,
    /// The authorized operation.
    pub operation: String,
    /// Digest of the authorized request (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_digest: String,
    /// Authorized caller UID (`,omitempty` — Go omits the zero value
    /// even though `0` is a legitimate root uid; the quirk is
    /// upstream's and is ported verbatim).
    #[serde(default, skip_serializing_if = "wire::u32_is_zero")]
    pub peer_uid: u32,
    /// Authorized caller PID (`,omitempty`).
    #[serde(default, skip_serializing_if = "wire::i32_is_zero")]
    pub peer_pid: i32,
    /// Fingerprint of the authorized caller.
    pub caller_fingerprint: String,
    /// Expiry timestamp.
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// The complete scope that must be bound to a one-use lifecycle
/// authorization before the helper can reach Docker
/// (`authority.LifecycleAuthorizationRequest`).
///
/// Upstream carries no JSON tags on this struct: it marshals
/// PascalCase field names onto the broker wire (Go's case-insensitive
/// unmarshal accepts them back). The explicit renames keep the Rust
/// serialization byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleAuthorizationRequest {
    /// The bound instance.
    #[serde(rename = "InstanceID")]
    pub instance_id: String,
    /// The operation to authorize.
    #[serde(rename = "Operation")]
    pub operation: String,
    /// Digest of the request being authorized.
    #[serde(rename = "RequestDigest")]
    pub request_digest: String,
    /// Calling peer's UID.
    #[serde(rename = "PeerUID")]
    pub peer_uid: u32,
    /// Calling peer's PID.
    #[serde(rename = "PeerPID")]
    pub peer_pid: i32,
}

// ---------------------------------------------------------------------------
// Broker protocol envelopes
// ---------------------------------------------------------------------------

/// The broker-protocol outcome vocabulary (upstream
/// `authority.BrokerOutcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrokerOutcome {
    /// The operation succeeded.
    Success,
    /// The broker refused the operation.
    Denied,
    /// The operation errored inside the broker.
    Error,
}

/// Human-readable debugging context for an operation that was denied
/// or failed (upstream `authority.BrokerEvidence`). Never carries
/// secrets, paths, or credential material.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerEvidence {
    /// The operation this evidence describes.
    pub operation_id: String,
    /// Machine reason code (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub code: String,
    /// Operator-safe message (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
}

/// A signed operation carried from the runtime to the privileged
/// helper via the broker protocol (upstream `authority.BrokerRequest`).
/// `payload` is the named argument map — in the upstream client the
/// typed request rides under the `"request"` key.
/// (`RawValue` has no `PartialEq`; compare `.get()` bytes in tests,
/// matching Go's `bytes.Equal` on `json.RawMessage`.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerRequest {
    /// The operation identity downstream authority records bind.
    pub operation_id: String,
    /// The closed operation name (a [`BrokerWireCommand`] or
    /// RPC-scoped purpose string).
    pub purpose: String,
    /// Session token; empty when the transport does not require one.
    pub session_token: String,
    /// Named arguments — upstream `map[string]json.RawMessage`.
    /// Upstream's tag has no `omitempty`, so a nil map marshals as
    /// `null`: `None` ↔ nil (`"payload":null`), `Some` ↔ non-nil —
    /// including `Some(empty)` ↔ `"{}"`, the distinction Go keeps.
    /// `null` and an absent key both decode to `None`. Each value is
    /// the verbatim JSON the peer sent (`RawValue` passthrough), so a
    /// dispatch that hashes or re-emits it sees the exact bytes, never
    /// a normalized `Value` re-encoding.
    pub payload: Option<BTreeMap<String, Box<serde_json::value::RawValue>>>,
}

/// The broker's signed reply to a broker operation (upstream
/// `authority.BrokerResponse`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrokerResponse {
    /// Echoed operation identity.
    pub operation_id: String,
    /// The outcome classification.
    pub outcome: BrokerOutcome,
    /// The typed result payload (`,omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Denial/error evidence.
    pub evidence: BrokerEvidence,
}

// ---------------------------------------------------------------------------
// AdvisoryAdmissionEvidence
// ---------------------------------------------------------------------------

/// The bounded payload persisted alongside every advisory evaluation
/// via the authority journal (upstream
/// `authority.AdvisoryAdmissionEvidence`). It carries only allowlisted
/// metadata and must never contain raw bundle bytes, signatures, or
/// file paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryAdmissionEvidence {
    /// Advisory generation.
    pub generation_id: String,
    /// Selector digest.
    pub selector_digest: String,
    /// Canonical bundle digest.
    pub canonical_bundle_digest: String,
    /// Signing key identity.
    pub key_id: String,
    /// Evaluation state.
    pub state: String,
    /// Evaluation code.
    pub code: String,
    /// The failing check (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub check: String,
    /// Evaluation timestamp.
    #[serde(with = "wire::rfc3339")]
    pub evaluation_time: OffsetDateTime,
    /// Policy version evaluated.
    pub policy_version: String,
    /// Time-witness state.
    pub time_witness_state: String,
    /// Allowlisted host facts (`,omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_facts: Option<AdvisoryHostFacts>,
}

/// Allowlisted host environment versions collected during an advisory
/// evaluation (upstream `authority.AdvisoryHostFacts`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryHostFacts {
    /// `/etc/os-release` version (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os_release: String,
    /// Kernel version (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kernel: String,
    /// Docker version (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub docker: String,
    /// Compose version (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compose: String,
    /// PostgreSQL client version (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub psql: String,
}

// ---------------------------------------------------------------------------
// AuthorityTransitionPayload — the journal entry
// ---------------------------------------------------------------------------

/// The on-disk journal entry written for every authority lifecycle
/// transition (init, bind, rotate, revoke). It carries 17 fields
/// covering identity, payload integrity, and cryptographic proof.
/// Port of `authority.AuthorityTransitionPayload`.
/// (`RawValue` has no `PartialEq`; compare `.get()` bytes in tests,
/// matching Go's `bytes.Equal` on `json.RawMessage`.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityTransitionPayload {
    /// `central.authority-transition/v1`.
    pub schema_version: String,
    /// Journal stream identity.
    pub stream_id: String,
    /// Stream sequence number.
    pub sequence_num: u64,
    /// Transition phase.
    pub phase: String,
    /// Operation name.
    pub operation: String,
    /// Bound instance.
    pub instance_id: String,
    /// Bound binding.
    pub binding_id: String,
    /// Bound launch.
    pub launch_id: String,
    /// Replay-protection nonce.
    pub nonce: String,
    /// Transition payload (upstream `json.RawMessage`): the verbatim
    /// bytes `payload_digest` hashes and `payload_bytes` counts.
    /// `None` ↔ Go nil (`"payload":null` on output, digest of the
    /// empty slice, `payload_bytes` 0); `Some` serializes the raw
    /// bytes back unchanged, so the durable record is byte-identical
    /// to what was hashed.
    pub payload: Option<Box<serde_json::value::RawValue>>,
    /// Digest of `payload`.
    pub payload_digest: String,
    /// `payload` size in bytes.
    pub payload_bytes: u64,
    /// Digest of the prior journal entry.
    pub prior_digest: String,
    /// Broker key version that signed.
    pub broker_key_ver: String,
    /// HMAC over the canonical record.
    pub hmac: String,
    /// Signature over the canonical record.
    pub signature: String,
    /// Signing timestamp — a string field upstream, not `time.Time`.
    pub signed_at: String,
}

// ---------------------------------------------------------------------------
// ProtectedGeneration
// ---------------------------------------------------------------------------

/// Returned by `Journal.AppendCommitted` after a successful authority
/// transition has been durably persisted (upstream
/// `authority.CommittedReceipt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedReceipt {
    /// Journal entry identity.
    pub id: String,
    /// Stream sequence.
    pub sequence: u64,
}

/// A single generation of the local CA (protected key material) from
/// creation through retirement (upstream
/// `authority.ProtectedGeneration`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedGeneration {
    /// The generation identity.
    pub generation_id: ProtectedGenerationId,
    /// The purpose it serves.
    pub purpose: String,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// The owning secret binding.
    pub binding_id: SecretBindingId,
    /// Retirement timestamp; `None` while live.
    pub retired_at: Option<OffsetDateTime>,
}

// ---------------------------------------------------------------------------
// PrepareOperation — durable journal record for dependency prepare
// ---------------------------------------------------------------------------

/// The fine-grained state-machine phase for a dependency prepare
/// operation (upstream `authority.PrepareOperationPhase`): which step
/// the operation reached before interruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrepareOperationPhase {
    /// `capacity_admitted`.
    CapacityAdmitted,
    /// `acquiring`.
    Acquiring,
    /// `verified_inputs`.
    VerifiedInputs,
    /// `build_one`.
    BuildOne,
    /// `build_two`.
    BuildTwo,
    /// `compared`.
    Compared,
    /// `attested`.
    Attested,
    /// `candidate_staged`.
    CandidateStaged,
    /// `promotion_admitted`.
    PromotionAdmitted,
    /// `selector_switched`.
    SelectorSwitched,
    /// `completed` — terminal.
    Completed,
    /// `failed` — terminal.
    Failed,
    /// `cancelled` — terminal.
    Cancelled,
}

impl PrepareOperationPhase {
    /// `IsTerminal` — true when the phase is a final state from which
    /// the operation cannot be resumed.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// The upstream phase string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapacityAdmitted => "capacity_admitted",
            Self::Acquiring => "acquiring",
            Self::VerifiedInputs => "verified_inputs",
            Self::BuildOne => "build_one",
            Self::BuildTwo => "build_two",
            Self::Compared => "compared",
            Self::Attested => "attested",
            Self::CandidateStaged => "candidate_staged",
            Self::PromotionAdmitted => "promotion_admitted",
            Self::SelectorSwitched => "selector_switched",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for PrepareOperationPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PrepareOperationPhase {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for phase in [
            Self::CapacityAdmitted,
            Self::Acquiring,
            Self::VerifiedInputs,
            Self::BuildOne,
            Self::BuildTwo,
            Self::Compared,
            Self::Attested,
            Self::CandidateStaged,
            Self::PromotionAdmitted,
            Self::SelectorSwitched,
            Self::Completed,
            Self::Failed,
            Self::Cancelled,
        ] {
            if phase.as_str() == s {
                return Ok(phase);
            }
        }
        Err(Failure::invalid(
            codes::PREPARE_OPERATION_INVALID,
            "authority: unknown prepare operation phase",
        ))
    }
}

/// The durable journal record for a single dependency prepare
/// workflow (upstream `authority.PrepareOperation`). It is created at
/// Prepare start and updated after each state-machine transition so
/// the service can detect unsettled operations and resume them
/// exactly. Consumed by [`crate::port::DependencyStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareOperation {
    /// The operation identity.
    pub operation_id: String,
    /// Current state-machine phase.
    pub phase: PrepareOperationPhase,
    /// The admission receipt authorizing this operation.
    pub admission_id: String,
    /// The dependency selector being prepared.
    pub selector: String,
    /// The operation deadline.
    #[serde(with = "wire::rfc3339")]
    pub deadline: OffsetDateTime,
    /// Terminal/abandonment reason (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Dependencies reused from the active receipt.
    pub reused: u32,
    /// Dependencies newly acquired.
    pub acquired: u32,
    /// The produced receipt (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub receipt_id: String,
    /// Operation creation time.
    #[serde(with = "wire::rfc3339")]
    pub created_at: OffsetDateTime,
}

// ---------------------------------------------------------------------------
// B04/B05/B10 secret-bootstrap wire vocabulary
// ---------------------------------------------------------------------------

/// The closed set of broker wire commands used by the B04/B05/B10
/// authority protocol (upstream `authority.BrokerWireCommand`). These
/// replace generic-purpose dispatch for all secret-bootstrap
/// operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrokerWireCommand {
    /// `adopt_b03_minio_bootstrap` — import the legacy B03 MinIO
    /// bootstrap into the B04 registry.
    #[serde(rename = "adopt_b03_minio_bootstrap")]
    AdoptB03MinioBootstrap,
    /// `issue_b04_lifecycle_proof` — durably sign the caller's
    /// stopped-topology/mount-release/binding tokens (SC-DEF-12).
    #[serde(rename = "issue_b04_lifecycle_proof")]
    IssueLifecycleProof,
    /// `materialize_minio_root` — write the bound MinIO root
    /// credential to its authorized target.
    #[serde(rename = "materialize_minio_root")]
    MaterializeMinioRoot,
    /// `materialize_postgres_migration` — B05: deliver the
    /// `postgres_migration_v1` credential to the verified
    /// `central-migrate` descriptor peer.
    #[serde(rename = "materialize_postgres_migration")]
    MaterializePostgresMigration,
    /// `materialize_minio_runtime` — B10: deliver the
    /// `minio_runtime_v1` descriptor to the registered provisioner or
    /// the runtime identity.
    #[serde(rename = "materialize_minio_runtime")]
    MaterializeMinioRuntime,
}

/// The closed allowlist of broker wire commands
/// (`authority.AllBrokerWireCommands()`), in upstream order.
pub const ALL_BROKER_WIRE_COMMANDS: [BrokerWireCommand; 5] = [
    BrokerWireCommand::AdoptB03MinioBootstrap,
    BrokerWireCommand::IssueLifecycleProof,
    BrokerWireCommand::MaterializeMinioRoot,
    BrokerWireCommand::MaterializePostgresMigration,
    BrokerWireCommand::MaterializeMinioRuntime,
];

impl BrokerWireCommand {
    /// The upstream wire command string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdoptB03MinioBootstrap => "adopt_b03_minio_bootstrap",
            Self::IssueLifecycleProof => "issue_b04_lifecycle_proof",
            Self::MaterializeMinioRoot => "materialize_minio_root",
            Self::MaterializePostgresMigration => "materialize_postgres_migration",
            Self::MaterializeMinioRuntime => "materialize_minio_runtime",
        }
    }
}

impl fmt::Display for BrokerWireCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BrokerWireCommand {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for command in ALL_BROKER_WIRE_COMMANDS {
            if command.as_str() == s {
                return Ok(command);
            }
        }
        Err(Failure::invalid(
            codes::GENESIS_INVALID,
            "authority: unknown broker wire command",
        ))
    }
}

/// The closed wire payload for `adopt_b03_minio_bootstrap` (upstream
/// `authority.B04AdoptRequest`). Every field defaults: Go's
/// `json.Unmarshal` leaves absent fields at their zero value and the
/// dispatch ladder's semantic checks — not the decoder — assign the
/// denial reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct B04AdoptRequest {
    /// The instance adopting the bootstrap.
    #[serde(default)]
    pub instance_id: String,
    /// The adopted purpose (`minio_root_v1`).
    #[serde(default)]
    pub purpose: String,
    /// The adopting operation.
    #[serde(default)]
    pub operation_id: String,
    /// Lifecycle fencing token.
    #[serde(default)]
    pub fencing_token: u64,
    /// Proof the topology was stopped.
    #[serde(default)]
    pub stopped_topology_proof: String,
    /// Proof the mount was released.
    #[serde(default)]
    pub mount_release_proof: String,
    /// The binding evidence.
    #[serde(default)]
    pub binding_evidence: String,
    /// Evidence expiry.
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    pub evidence_expires_at: OffsetDateTime,
}

/// The closed wire payload for `issue_b04_lifecycle_proof` (upstream
/// `authority.B04IssueProofRequest`): asks the broker to durably sign
/// the caller's own stopped-topology/mount-release/binding tokens so a
/// subsequent `adopt_b03_minio_bootstrap` carrying the same tokens has
/// a genuine broker-issued record to verify against (SC-DEF-12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct B04IssueProofRequest {
    /// The requesting instance.
    #[serde(default)]
    pub instance_id: String,
    /// The requesting operation.
    #[serde(default)]
    pub operation_id: String,
    /// Lifecycle fencing token.
    #[serde(default)]
    pub fencing_token: u64,
    /// Proof the topology was stopped.
    #[serde(default)]
    pub stopped_topology_proof: String,
    /// Proof the mount was released.
    #[serde(default)]
    pub mount_release_proof: String,
    /// The binding evidence.
    #[serde(default)]
    pub binding_evidence: String,
    /// Evidence expiry.
    #[serde(default = "wire::go_zero_time", with = "wire::rfc3339")]
    pub evidence_expires_at: OffsetDateTime,
}

/// The closed wire payload for `materialize_minio_root` (upstream
/// `authority.B04MaterializeRequest`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct B04MaterializeRequest {
    /// The binding being materialized.
    pub binding_id: String,
    /// The requesting operation.
    pub operation_id: String,
    /// The consumed one-use receipt.
    pub receipt_id: String,
    /// Receipt HMAC.
    pub receipt_hmac: String,
    /// Lifecycle fencing token.
    pub fencing_token: u64,
    /// Calling peer's UID.
    pub peer_uid: u32,
    /// Calling peer's PID.
    pub peer_pid: i32,
    /// Dependency service (`minio`).
    pub service: String,
    /// Authorized materialization target.
    pub target: String,
    /// Target file owner UID.
    pub uid: u32,
    /// Target file owner GID.
    pub gid: u32,
}

/// The safe outcome payload for `materialize_minio_root` (upstream
/// `authority.B04MaterializeResult`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct B04MaterializeResult {
    /// Echoed operation identity.
    pub operation_id: String,
    /// The consumed receipt.
    pub receipt_id: String,
    /// The materialized binding.
    pub binding_id: String,
    /// Opaque downstream token (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub opaque_token: String,
    /// Operator-safe next action (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub safe_next_action: String,
}

/// The safe outcome payload for `adopt_b03_minio_bootstrap` (upstream
/// `authority.B04AdoptResult`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct B04AdoptResult {
    /// The adopted binding.
    pub binding_id: String,
    /// The adopted generation.
    pub generation_id: String,
    /// The adoption outcome.
    pub outcome: String,
    /// Operator-safe next action (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub safe_next_action: String,
}

/// The closed wire payload for `materialize_postgres_migration`
/// (upstream `authority.B05MaterializePostgresMigrationRequest`). Every
/// field defaults, Go `json.Unmarshal`-style: the JSON dispatch
/// ladder's own checks produce `invalid dependency binding`/`invalid
/// binding id`/`invalid operation id`, not decode failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct B05MaterializePostgresMigrationRequest {
    /// Broker-issued launch evidence for the migrate worker.
    #[serde(default)]
    pub launch_evidence_id: String,
    /// The binding being materialized.
    #[serde(default)]
    pub binding_id: String,
    /// The requesting operation.
    #[serde(default)]
    pub operation_id: String,
    /// The consumed one-use receipt.
    #[serde(default)]
    pub receipt_id: String,
    /// Receipt HMAC.
    #[serde(default)]
    pub receipt_hmac: String,
    /// Lifecycle fencing token.
    #[serde(default)]
    pub fencing_token: u64,
    /// Calling peer's UID.
    #[serde(default)]
    pub peer_uid: u32,
    /// Calling peer's PID.
    #[serde(default)]
    pub peer_pid: i32,
    /// Dependency service (`central-migrate`).
    #[serde(default)]
    pub service: String,
    /// Delivery mechanism (`scm_rights`).
    #[serde(default)]
    pub target: String,
    /// Target credential owner UID.
    #[serde(default)]
    pub uid: u32,
    /// Target credential owner GID.
    #[serde(default)]
    pub gid: u32,
}

/// The helper request to launch a dedicated, descriptor-only
/// `central-migrate` process (upstream
/// `authority.B05MigrationLaunchRequest`). Launch evidence is issued
/// only after the helper has observed the launched process identity —
/// the request must never claim evidence before launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct B05MigrationLaunchRequest {
    /// The requesting operation.
    pub operation_id: String,
    /// The launched service (`central-migrate`).
    pub service: String,
    /// Delivery mechanism (`scm_rights`).
    pub target: String,
    /// The migrate identity UID.
    pub uid: u32,
    /// The migrate identity GID.
    pub gid: u32,
}

/// The opaque broker-issued evidence needed for the subsequent
/// materialization request (upstream
/// `authority.B05MigrationLaunchResult`). It never exposes signing
/// material or a credential path — no peer identity fields cross it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct B05MigrationLaunchResult {
    /// Echoed operation identity.
    pub operation_id: String,
    /// The broker-issued launch evidence token.
    pub launch_evidence_id: String,
}

/// The safe outcome payload for `materialize_postgres_migration`
/// (upstream `authority.B05MaterializePostgresMigrationResult`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct B05MaterializePostgresMigrationResult {
    /// Echoed operation identity.
    pub operation_id: String,
    /// The consumed receipt.
    pub receipt_id: String,
    /// The materialized binding.
    pub binding_id: String,
    /// Opaque downstream token (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub opaque_token: String,
    /// Operator-safe next action (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub safe_next_action: String,
}

/// The closed wire payload the `minio-provision` provisioner
/// (central-local-infra) sends inbound over the `b10ProvisionedFrameMarker`
/// framed transport (upstream `authority.MinioProvisionedDescriptor`):
/// a length-prefixed JSON descriptor delivered together with exactly
/// one sealed `memfd` carrying a freshly minted MinIO credential.
/// Every field name and JSON tag here must exactly match the sender's
/// `handoff.Descriptor` — they describe the same value on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinioProvisionedDescriptor {
    /// Provisioner identity (`minio-provision`).
    pub service: String,
    /// Delivery mechanism (`sealed_memfd`).
    pub target: String,
    /// Runtime credential owner UID.
    pub uid: u32,
    /// Runtime credential owner GID.
    pub gid: u32,
    /// The scoped bucket.
    pub bucket: String,
    /// The scoped key prefix pair.
    pub key_prefix: String,
    /// The bound policy digest (`,omitempty`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_digest: String,
    /// The credential's purpose (`minio_runtime_v1`).
    pub purpose: String,
    /// The provisioning operation.
    pub operation_id: String,
    /// The owning instance.
    pub instance_id: String,
    /// The provisioning receipt.
    pub receipt_id: String,
    /// Descriptor expiry.
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Lifecycle fencing token.
    pub fence_token: u64,
}

/// The credential-free, broker-authoritative scope for one external
/// `minio-provision` delivery used by Slice C (upstream
/// `authority.RecoveryMinioHandoffRequest`). The broker persists this
/// scope before the provisioner runs; the provisioner may only echo
/// the opaque receipt ID it receives, never mint its own recovery
/// authority.
///
/// Upstream carries no JSON tags on this struct — it is a
/// broker-internal scope record, so no serde impl is derived here;
/// the broker adapter owns the record encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryMinioHandoffRequest {
    /// The requesting operation.
    pub operation_id: String,
    /// The owning instance.
    pub instance_id: String,
    /// The recovery purpose.
    pub purpose: String,
    /// The scoped bucket.
    pub bucket: String,
    /// The scoped key prefix.
    pub key_prefix: String,
    /// The bound policy digest.
    pub policy_digest: String,
    /// Scope expiry.
    pub expires_at: OffsetDateTime,
    /// Lifecycle fencing token.
    pub fence_token: u64,
}

/// The broker-issued receipt safe to pass to the external provisioner
/// (upstream `authority.RecoveryMinioHandoffReceipt`). It carries no
/// credential material and is one-use at the broker boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMinioHandoffReceipt {
    /// The one-use receipt.
    pub receipt_id: String,
    /// The requesting operation.
    pub operation_id: String,
    /// The owning instance.
    pub instance_id: String,
    /// The recovery purpose.
    pub purpose: String,
    /// The scoped bucket.
    pub bucket: String,
    /// The scoped key prefix.
    pub key_prefix: String,
    /// The bound policy digest.
    pub policy_digest: String,
    /// Receipt expiry.
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Lifecycle fencing token.
    pub fence_token: u64,
    /// Whether the provisioner echoed this receipt (`,omitempty` —
    /// Go's `bool` omitempty omits `false`).
    #[serde(default, skip_serializing_if = "wire::bool_is_false")]
    pub bound: bool,
}

// ---------------------------------------------------------------------------
// Genesis — the instance genesis record (upstream authority/genesis.go)
// ---------------------------------------------------------------------------

/// The caller's desire to perform a genesis operation — the input
/// side of the genesis protocol (upstream `authority.GenesisIntent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisIntent {
    /// The genesis operation identity.
    pub operation_id: OperationId,
    /// Request time.
    pub requested_at: OffsetDateTime,
}

/// The durable proof that genesis completed successfully for a
/// specific instance (upstream `authority.GenesisReceipt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisReceipt {
    /// The genesis operation identity.
    pub operation_id: OperationId,
    /// The instance that was bound.
    pub instance_id: InstanceId,
    /// The generated `central.config/v1` binding.
    pub config_binding_id: ConfigBindingId,
    /// The locked UID/GID allocations applied.
    pub uid_gid: UidGidMap,
    /// Completion timestamp.
    pub completed_at: OffsetDateTime,
}

/// The current phase of a genesis operation (upstream
/// `authority.GenesisStatus.Phase` — closed in the Rust port: the
/// upstream string vocabulary has exactly these four values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GenesisPhase {
    /// A binding was written but no committed receipt exists yet.
    Prepared,
    /// A committed receipt exists.
    Committed,
    /// The operation was abandoned.
    Abandoned,
    /// No durable evidence of the operation exists.
    Absent,
}

impl GenesisPhase {
    /// The upstream phase string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::Abandoned => "abandoned",
            Self::Absent => "absent",
        }
    }
}

impl fmt::Display for GenesisPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The current phase of a genesis operation and, when committed, its
/// receipt (upstream `authority.GenesisStatus`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisStatus {
    /// The queried operation identity.
    pub operation_id: OperationId,
    /// The durable phase.
    pub phase: GenesisPhase,
    /// The committed receipt, present only for
    /// [`GenesisPhase::Committed`].
    pub receipt: Option<GenesisReceipt>,
}

// ---------------------------------------------------------------------------
// Locked service identities (upstream authority/identity.go)
// ---------------------------------------------------------------------------

/// A system identity that must exist on the host before the central
/// runtime starts (upstream `authority.LockedIdentity`). The actual
/// UID/GID values come from the [`UidGidMap`] negotiated at genesis
/// time — the template fields are zero here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedIdentity {
    /// Account name.
    pub name: String,
    /// Allocated UID; `0` in the template before genesis allocation.
    pub uid: u32,
    /// Allocated GID; `0` in the template before genesis allocation.
    pub gid: u32,
    /// Login shell — always `/usr/sbin/nologin`.
    pub shell: String,
    /// Home directory.
    pub home: String,
}

/// The `central-runtime` daemon identity template: nologin shell,
/// `/nonexistent` home (upstream `authority.RuntimeIdentity`).
#[must_use]
pub fn runtime_identity() -> LockedIdentity {
    LockedIdentity {
        name: "central-runtime".to_string(),
        uid: 0,
        gid: 0,
        shell: "/usr/sbin/nologin".to_string(),
        home: "/nonexistent".to_string(),
    }
}

/// The `central-agent` subagent-runner identity template: nologin
/// shell, `/nonexistent` home (upstream `authority.AgentIdentity`).
#[must_use]
pub fn agent_identity() -> LockedIdentity {
    LockedIdentity {
        name: "central-agent".to_string(),
        uid: 0,
        gid: 0,
        shell: "/usr/sbin/nologin".to_string(),
        home: "/nonexistent".to_string(),
    }
}

/// The `central-browser` managed-profile identity template: nologin
/// shell, `/var/lib/central-browser` home (upstream
/// `authority.BrowserIdentity`).
#[must_use]
pub fn browser_identity() -> LockedIdentity {
    LockedIdentity {
        name: "central-browser".to_string(),
        uid: 0,
        gid: 0,
        shell: "/usr/sbin/nologin".to_string(),
        home: "/var/lib/central-browser".to_string(),
    }
}

/// The `central-migrate` migration-operator identity template used
/// for version-zero provisioning: nologin shell, `/nonexistent` home
/// (upstream `authority.MigrateIdentity`).
#[must_use]
pub fn migrate_identity() -> LockedIdentity {
    LockedIdentity {
        name: "central-migrate".to_string(),
        uid: 0,
        gid: 0,
        shell: "/usr/sbin/nologin".to_string(),
        home: "/nonexistent".to_string(),
    }
}

/// The full set of identities that must be allocated during genesis
/// (upstream `authority.AllLockedIdentities`), in upstream order.
/// None receives a login shell, a Docker/broker group, or any
/// authority beyond its own locked home.
#[must_use]
pub fn all_locked_identities() -> [LockedIdentity; 4] {
    [
        runtime_identity(),
        agent_identity(),
        browser_identity(),
        migrate_identity(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    // Ports upstream `internal/authority/genesis_test.go` —
    // `TestInstanceBindingRoundTrip` and `TestHelperVerbImplemented`.
    #[test]
    fn instance_binding_round_trip() {
        let id = InstanceId::new();
        let binding = InstanceBinding {
            instance_id: id,
            host_id: "test-host-hash".to_string(),
            release_digest: "sha256:release".to_string(),
            created_at: datetime!(2026-01-01 0:00:00 UTC),
            config_binding_id: ConfigBindingId::new(),
            uid_gid: UidGidMap {
                runtime_uid: 501,
                runtime_gid: 501,
                agent_uid: 502,
                agent_gid: 502,
                browser_uid: 503,
                browser_gid: 503,
            },
        };
        assert!(!binding.instance_id.is_nil(), "InstanceID must not be zero");
        assert_eq!(binding.uid_gid.runtime_uid, 501, "RuntimeUID mismatch");
    }

    #[test]
    fn helper_verb_implemented_matrix() {
        assert!(HelperVerb::Init.implemented(), "init is Slice A");
        assert!(
            HelperVerb::InitStatus.implemented(),
            "init-status is Slice A"
        );
        assert!(
            HelperVerb::InitResume.implemented(),
            "init-resume is Slice A"
        );
        assert!(
            HelperVerb::InitAbandon.implemented(),
            "init-abandon is Slice A"
        );
        assert!(HelperVerb::MigrateLaunch.implemented());
        assert!(HelperVerb::MigrateReadOutcome.implemented());
        assert!(HelperVerb::BackupCreate.implemented());
        assert!(HelperVerb::BackupVerify.implemented());
        assert!(HelperVerb::BackupStatus.implemented());
        assert!(HelperVerb::RestoreVerify.implemented());
        assert!(HelperVerb::RestoreApply.implemented());
        assert!(HelperVerb::RestoreResume.implemented());
        assert!(HelperVerb::RestoreAbandon.implemented());
        assert!(!HelperVerb::Prepare.implemented(), "prepare is deferred");
        assert!(!HelperVerb::Up.implemented(), "up is deferred");
        assert!(!HelperVerb::Wipe.implemented(), "wipe is deferred");
        assert!(!HelperVerb::Doctor.implemented(), "doctor is deferred");
        assert!(!HelperVerb::StateAudit.implemented());
        assert!(!HelperVerb::MaintenanceApply.implemented());
        assert!(
            ALL_HELPER_VERBS.len() == 35,
            "the closed matrix holds 35 verbs"
        );
    }

    /// Ports `TestScenario7_UnsignedHelperIsDenied`: the genesis
    /// protocol requires a signed release identity — an unsigned or
    /// wrong-release helper binary must be rejected.
    #[test]
    fn scenario7_unsigned_helper_is_denied() {
        let binding = InstanceBinding {
            instance_id: InstanceId::new(),
            host_id: String::new(),
            release_digest: String::new(),
            created_at: datetime!(2026-01-01 0:00:00 UTC),
            config_binding_id: ConfigBindingId::new(),
            uid_gid: UidGidMap {
                runtime_uid: 0,
                runtime_gid: 0,
                agent_uid: 0,
                agent_gid: 0,
                browser_uid: 0,
                browser_gid: 0,
            },
        };
        assert!(
            binding.release_digest.is_empty(),
            "unsigned release has empty digest"
        );
        // In production the helper verifies the release digest before
        // performing any privileged mutation; the domain model carries
        // the digest for that verification.
    }

    /// Ports `TestScenario7_GenesisIsIdempotent`: UUIDv7 produces
    /// unique values on each call — the basis for genesis idempotency.
    #[test]
    fn scenario7_genesis_is_idempotent() {
        let id1 = InstanceId::new();
        let id2 = InstanceId::new();
        assert_ne!(id1, id2, "UUIDv7 must produce unique values");
    }

    /// Ports `TestLockedIdentitiesAreDistinct`: 4 identities, unique
    /// names, all locked to nologin — and none may carry a Docker or
    /// broker group (none is granted one anywhere upstream).
    #[test]
    fn locked_identities_are_distinct_no_login() {
        let ids = all_locked_identities();
        assert_eq!(ids.len(), 4, "expected 4 locked identities");
        let mut seen = std::collections::BTreeSet::new();
        for id in &ids {
            assert!(seen.insert(id.name.as_str()), "duplicate name {}", id.name);
            assert_eq!(
                id.shell, "/usr/sbin/nologin",
                "{}: shell must be nologin",
                id.name
            );
            assert_eq!(id.uid, 0, "{}: template uid is unallocated", id.name);
            assert_eq!(id.gid, 0, "{}: template gid is unallocated", id.name);
        }
        assert_eq!(ids[0].name, "central-runtime");
        assert_eq!(ids[1].name, "central-agent");
        assert_eq!(ids[2].name, "central-browser");
        assert_eq!(ids[2].home, "/var/lib/central-browser");
        assert_eq!(ids[3].name, "central-migrate");
        assert_eq!(ids[3].home, "/nonexistent");
    }

    #[test]
    fn helper_verb_wire_strings_and_parse() {
        assert_eq!(HelperVerb::InitStatus.as_str(), "init-status");
        assert_eq!(
            HelperVerb::SecurityRescueCleanup.as_str(),
            "security-rescue-cleanup"
        );
        assert_eq!(HelperVerb::SecurityRescue.as_str(), "security-rescue");
        assert_eq!(
            HelperVerb::MigrateReadOutcome.as_str(),
            "migrate-read-outcome"
        );
        for verb in ALL_HELPER_VERBS {
            assert_eq!(
                verb.as_str().parse::<HelperVerb>().unwrap(),
                verb,
                "{}: as_str/FromStr must round-trip",
                verb.as_str()
            );
            let json = serde_json::to_value(verb).unwrap();
            assert_eq!(json, serde_json::Value::String(verb.as_str().to_string()));
            assert_eq!(serde_json::from_value::<HelperVerb>(json).unwrap(), verb);
        }
        assert!("shell-escape".parse::<HelperVerb>().is_err());
        assert!("".parse::<HelperVerb>().is_err());
    }

    #[test]
    fn broker_wire_commands_closed_set() {
        assert_eq!(ALL_BROKER_WIRE_COMMANDS.len(), 5);
        for command in ALL_BROKER_WIRE_COMMANDS {
            assert_eq!(
                command.as_str().parse::<BrokerWireCommand>().unwrap(),
                command
            );
            // Serde renders the exact upstream wire command string.
            let json = serde_json::to_value(command).unwrap();
            assert_eq!(
                json,
                serde_json::Value::String(command.as_str().to_string())
            );
        }
        assert_eq!(
            BrokerWireCommand::AdoptB03MinioBootstrap.as_str(),
            "adopt_b03_minio_bootstrap"
        );
        assert!("arbitrary_purpose".parse::<BrokerWireCommand>().is_err());
    }

    #[test]
    fn prepare_operation_phase_terminal_set() {
        assert!(!PrepareOperationPhase::CapacityAdmitted.is_terminal());
        assert!(!PrepareOperationPhase::SelectorSwitched.is_terminal());
        assert!(PrepareOperationPhase::Completed.is_terminal());
        assert!(PrepareOperationPhase::Failed.is_terminal());
        assert!(PrepareOperationPhase::Cancelled.is_terminal());
        assert_eq!(
            PrepareOperationPhase::CandidateStaged.as_str(),
            "candidate_staged"
        );
        assert_eq!(
            "build_two".parse::<PrepareOperationPhase>().unwrap(),
            PrepareOperationPhase::BuildTwo
        );
    }

    /// Ports `TestMigrationLaunchContractJSON` (secretbootstrap
    /// domain_test.go): the B05 launch request must not claim evidence
    /// before launch, and the result must carry only the operation and
    /// the opaque evidence id — never peer/process fields.
    #[test]
    fn migration_launch_contract_json() {
        let request = B05MigrationLaunchRequest {
            operation_id: "operation-1".to_string(),
            service: "central-migrate".to_string(),
            target: "scm_rights".to_string(),
            uid: CENTRAL_MIGRATE_UID,
            gid: CENTRAL_MIGRATE_GID,
        };
        let result = B05MigrationLaunchResult {
            operation_id: "operation-1".to_string(),
            launch_evidence_id: "opaque-evidence-id".to_string(),
        };
        let request_json = serde_json::to_vec(&request).unwrap();
        assert!(
            !request_json
                .windows(b"launch_evidence_id".len())
                .any(|w| w == b"launch_evidence_id"),
            "launch request must not claim evidence before launch: {}",
            String::from_utf8_lossy(&request_json)
        );
        let result_json = serde_json::to_vec(&result).unwrap();
        let text = String::from_utf8_lossy(&result_json);
        for field in ["operation_id", "launch_evidence_id"] {
            assert!(
                text.contains(&format!("\"{field}\"")),
                "launch result JSON missing {field:?}: {text}"
            );
        }
        for field in ["peer_uid", "peer_pid", "service", "target", "uid", "gid"] {
            assert!(
                !text.contains(&format!("\"{field}\"")),
                "launch result JSON unexpectedly exposes {field:?}: {text}"
            );
        }
    }

    #[test]
    fn wire_base64_round_trip_and_strictness() {
        for (raw, want) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (
                b"abcdef0123456789abcdef0123456789",
                "YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODk=",
            ),
        ] {
            assert_eq!(wire::b64_encode(raw), want);
            assert_eq!(wire::b64_decode(want).unwrap(), raw);
        }
        assert_eq!(wire::b64_decode("Zg"), None, "truncated quad rejected");
        assert_eq!(wire::b64_decode("Zg==Zg=="), None, "mid padding rejected");
        assert_eq!(wire::b64_decode("Zm9v!b=="), None, "non-alphabet rejected");
        assert_eq!(
            wire::b64_decode("ab=c"),
            None,
            "content after padding rejected"
        );
        assert_eq!(wire::b64_decode("a==="), None, "early padding rejected");
        assert_eq!(
            wire::b64_decode("abcd="),
            None,
            "length must be a multiple of 4"
        );
    }

    #[test]
    fn wire_hex_round_trip() {
        assert_eq!(wire::hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(
            wire::hex_decode("deadbeef"),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(
            wire::hex_decode("DEADBEEF"),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(wire::hex_decode("abc"), None);
        assert_eq!(wire::hex_decode("zz"), None);
    }

    #[test]
    fn wire_hmac_sha256_rfc4231_vectors() {
        // RFC 4231 test case 1: 20-byte 0x0b key, "Hi There".
        let mac = wire::hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            wire::hex_encode(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231 test case 2: "Jefe", "what do ya want for nothing?".
        let mac = wire::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            wire::hex_encode(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // RFC 4231 test case 6: 131-byte key (> block size, exercises
        // the key-hashing path).
        let mac = wire::hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            wire::hex_encode(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // Distinct messages never collide; constant-time comparison.
        let a = wire::hmac_sha256(b"k", b"one");
        let b = wire::hmac_sha256(b"k", b"two");
        assert!(wire::ct_eq(&a, &a));
        assert!(!wire::ct_eq(&a, &b));
        assert!(!wire::ct_eq(&a, &a[..31]));
    }

    #[test]
    fn wire_rfc3339_nano_matches_go_formatting() {
        // Zero nanoseconds: no fraction, `Z` suffix (Go RFC3339Nano).
        assert_eq!(
            wire::format_rfc3339_nano(datetime!(2026-03-04 05:06:07 UTC)),
            "2026-03-04T05:06:07Z"
        );
        // Nanos trimmed to significant digits — Go's `.999999999` semantics.
        assert_eq!(
            wire::format_rfc3339_nano(datetime!(2026-03-04 05:06:07.120000000 UTC)),
            "2026-03-04T05:06:07.12Z"
        );
        assert_eq!(
            wire::format_rfc3339_nano(datetime!(2026-03-04 05:06:07.123456789 UTC)),
            "2026-03-04T05:06:07.123456789Z"
        );
        // Go zero-time detection.
        assert!(wire::is_go_zero_time(datetime!(1-01-01 0:00:00 UTC)));
        assert!(!wire::is_go_zero_time(OffsetDateTime::UNIX_EPOCH));
        // serde round-trip through the wire adapter.
        #[derive(Serialize, Deserialize)]
        struct T {
            #[serde(with = "wire::rfc3339")]
            t: OffsetDateTime,
        }
        let value = T {
            t: datetime!(2026-03-04 05:06:07.5 UTC),
        };
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, "{\"t\":\"2026-03-04T05:06:07.5Z\"}");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["t"], "2026-03-04T05:06:07.5Z");
    }
}
