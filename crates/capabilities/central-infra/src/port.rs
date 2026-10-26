//! The `central-infra` port surface — every async boundary between
//! this capability and the host-privileged or durable infrastructure
//! behind it.
//!
//! House rules (rust-application-boundaries.md):
//!
//! - Every async trait is `#[trait_variant::make(Send)]` with
//!   `Send + Sync + 'static`, so `Arc<dyn Trait>` composition works
//!   on multi-threaded executors; each trait has a blanket
//!   `impl for Arc<T>` forwarding block.
//! - Errors are [`central_foundation::failure::Failure`] — never
//!   adapter error types.
//! - No `context.Context`: Rust cancellation is future-drop. Methods
//!   are `&self` calls that complete or are dropped.
//! - No adapter types: no socket, fd, Docker, Compose, `sqlx`, or
//!   `tokio` types cross these signatures — only domain values.
//! - The envelope types on [`HelperClient`]/[`BrokerClient`] are the
//!   upstream newline-delimited JSON frames re-exported from
//!   `crate::authority`; the socket adapters in Tasks 4–8 own the
//!   transport.

use std::sync::Arc;

use central_foundation::failure::Failure;
use central_foundation::identity::{OperationId, SecretBindingId};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::authority::{
    BrokerRequest, BrokerResponse, GenesisReceipt, HelperVerb, InstanceBinding, PrepareOperation,
};
use crate::domain::{
    AdmissionBinding, B04LifecycleEvidence, BootstrapOutcome, Candidate, DependencyReceipt,
    HandoffReceipt, HandoffRequest, LifecycleBinding, LifecycleOperation, LifecyclePhase,
    Observation, PreparedDependencySet, Purpose, SecretBinding, SemanticReceipt, ServiceMode,
    TopologySnapshot,
};

// ---------------------------------------------------------------------------
// HelperClient — the root-owned helper socket boundary (A02/A03)
// ---------------------------------------------------------------------------

/// A single newline-delimited JSON request to the helper Unix socket
/// (upstream `helper/protocol.go Request`). `verb` is the closed
/// [`HelperVerb`] matrix — the helper denies anything it does not
/// implement with `UNSUPPORTED_IN_THIS_SLICE`.
///
/// Upstream `Request.Verb` is a raw `string`, so the Go server can
/// *decode* an unknown verb and still answer `denied` through its
/// matrix lookup. This typed field cannot represent an unknown verb —
/// envelope decode fails before any deny decision. The T4–T8
/// socket-server task needs a raw-string decode view (e.g. a
/// transport-side `verb: String` twin resolved to [`HelperVerb`]
/// only after the deny-unknown check) to preserve upstream's
/// deny-not-reject behavior for out-of-matrix verbs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelperRequest {
    /// The operation identity echoed in the response.
    pub operation_id: String,
    /// The requested operation.
    pub verb: HelperVerb,
    /// The typed verb payload (`,omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

/// The helper's newline-delimited JSON reply (upstream
/// `helper/protocol.go Response`). `outcome` is the closed
/// `success`/`denied`/`error`/`deferred` vocabulary the server
/// writes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelperResponse {
    /// Echoed operation identity.
    pub operation_id: String,
    /// The outcome classification.
    pub outcome: HelperOutcome,
    /// The process exit code the CLI should surface.
    pub exit_code: i32,
    /// Machine reason (`,omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The typed result payload (`,omitempty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

/// The closed outcome set the helper writes (upstream's literal
/// `"success"`, `"denied"`, `"error"`, and `"deferred"` strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HelperOutcome {
    /// The operation succeeded.
    Success,
    /// The helper refused the operation (the authority boundary
    /// denied it).
    Denied,
    /// The operation errored inside the helper.
    Error,
    /// The verb is registered in the matrix but not implemented in
    /// this slice — upstream answers `deferred` with
    /// `UNSUPPORTED_IN_THIS_SLICE` (or a verb-specific
    /// `*_UNAVAILABLE` reason) for every `!Implemented` verb and
    /// for dispatch arms whose handler is not wired.
    Deferred,
}

/// The client side of the helper Unix socket: one
/// request → one response. `HelperClient` is the
/// capability-side name for upstream `helper.Client` generalized to
/// the full verb matrix (upstream's concrete client is per-verb; the
/// transport envelope it serializes is exactly [`HelperRequest`] /
/// [`HelperResponse`]).
#[trait_variant::make(Send)]
pub trait HelperClient: Send + Sync + 'static {
    /// Sends one request and returns the helper's response. A denied
    /// operation arrives as [`HelperResponse.outcome`], not as a
    /// transport error — `Err` means the boundary itself failed.
    async fn invoke(&self, request: HelperRequest) -> Result<HelperResponse, Failure>;
}

impl<H: HelperClient + ?Sized> HelperClient for Arc<H> {
    async fn invoke(&self, request: HelperRequest) -> Result<HelperResponse, Failure> {
        (**self).invoke(request).await
    }
}

// ---------------------------------------------------------------------------
// BrokerClient — the protected-broker socket boundary (A04)
// ---------------------------------------------------------------------------

/// The client side of the protected broker's Unix socket: one
/// [`BrokerRequest`] → one [`BrokerResponse`]. Upstream's
/// `callWithOperationID(ctx, operationID, purpose, payload, result)`
/// generalizes here: the caller builds the request (with the typed
/// payload under `"request"` inside `payload`, as upstream does) and
/// decodes `response.result` itself — the port carries the envelope,
/// not each RPC's typed shape.
#[trait_variant::make(Send)]
pub trait BrokerClient: Send + Sync + 'static {
    /// Sends one broker request and returns the broker's response.
    /// A `denied`/`error` outcome arrives in
    /// [`BrokerResponse::outcome`], not as `Err` — `Err` means the
    /// boundary itself failed.
    async fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Failure>;
}

impl<B: BrokerClient + ?Sized> BrokerClient for Arc<B> {
    async fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Failure> {
        (**self).call(request).await
    }
}

// Tracking note — upstream `authority/port/protected_port.go`'s
// `ProtectedDescriptorUse` is intentionally not ported in T3. It is
// an fd-carrying boundary: `Use(ctx, fn(ctx, fd int) error)` hands a
// borrowed SCM_RIGHTS descriptor to an in-process callback, so its
// natural Rust shape belongs to the socket adapter (fds plus
// `rustix`/`OwnedFd`), not to this capability's domain-value port
// surface. It lands with the T4+ adapter task.

// ---------------------------------------------------------------------------
// TlsAuthority — the local CA (upstream authority/port/tls_port.go)
// ---------------------------------------------------------------------------

/// The public key material and validity window the caller wants the
/// local CA to sign (upstream `port.LeafSignRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafSignRequest {
    /// Subject public key bytes.
    pub public_key: Vec<u8>,
    /// `NotAfter` as Unix seconds.
    pub not_after: i64,
}

/// A signed X.509 leaf certificate returned by the local CA
/// (upstream `port.LeafCertificate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafCertificate {
    /// The DER-encoded certificate.
    pub raw: Vec<u8>,
    /// Its fingerprint.
    pub fingerprint: String,
}

/// The local TLS certificate-authority boundary: leaf signing plus
/// fingerprint introspection (upstream `port.TLSAuthority`).
#[trait_variant::make(Send)]
pub trait TlsAuthority: Send + Sync + 'static {
    /// Signs a leaf certificate over `request`'s public key.
    async fn sign_leaf(&self, request: LeafSignRequest) -> Result<LeafCertificate, Failure>;
    /// The CA's own fingerprint.
    async fn ca_fingerprint(&self) -> Result<String, Failure>;
    /// The current leaf's fingerprint.
    async fn leaf_fingerprint(&self) -> Result<String, Failure>;
}

impl<T: TlsAuthority + ?Sized> TlsAuthority for Arc<T> {
    async fn sign_leaf(&self, request: LeafSignRequest) -> Result<LeafCertificate, Failure> {
        (**self).sign_leaf(request).await
    }
    async fn ca_fingerprint(&self) -> Result<String, Failure> {
        (**self).ca_fingerprint().await
    }
    async fn leaf_fingerprint(&self) -> Result<String, Failure> {
        (**self).leaf_fingerprint().await
    }
}

// ---------------------------------------------------------------------------
// GenesisPort — durable genesis persistence (A03)
// ---------------------------------------------------------------------------

/// The persistence port for genesis operations — the primary
/// interface through which [`crate::app::GenesisService`] reads and
/// writes durable binding and receipt data (upstream
/// `authority/port.GenesisPort`). `None` means no durable record —
/// upstream's `*T` nil return.
#[trait_variant::make(Send)]
pub trait GenesisPort: Send + Sync + 'static {
    /// Reads the instance binding recorded for `host_id` (SHA-256 of
    /// `/etc/machine-id`), or `None` when this host has never
    /// completed genesis.
    async fn read_binding(&self, host_id: &str) -> Result<Option<InstanceBinding>, Failure>;

    /// Writes the genesis binding. A re-run with an identical binding
    /// is idempotent; a conflicting binding for the same host is the
    /// adapter's conflict, not a silent overwrite.
    async fn write_binding(&self, binding: &InstanceBinding) -> Result<(), Failure>;

    /// Reads the committed genesis receipt for `operation_id`, or
    /// `None` when none exists.
    async fn read_genesis_receipt(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<GenesisReceipt>, Failure>;

    /// Writes the committed genesis receipt — the durable proof a
    /// genesis completed.
    async fn write_genesis_receipt(&self, receipt: &GenesisReceipt) -> Result<(), Failure>;
}

impl<G: GenesisPort + ?Sized> GenesisPort for Arc<G> {
    async fn read_binding(&self, host_id: &str) -> Result<Option<InstanceBinding>, Failure> {
        (**self).read_binding(host_id).await
    }
    async fn write_binding(&self, binding: &InstanceBinding) -> Result<(), Failure> {
        (**self).write_binding(binding).await
    }
    async fn read_genesis_receipt(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<GenesisReceipt>, Failure> {
        (**self).read_genesis_receipt(operation_id).await
    }
    async fn write_genesis_receipt(&self, receipt: &GenesisReceipt) -> Result<(), Failure> {
        (**self).write_genesis_receipt(receipt).await
    }
}

// ---------------------------------------------------------------------------
// Lifecycle inward ports (upstream infralifecycle/port)
// ---------------------------------------------------------------------------

/// An admission request for a lifecycle operation (upstream
/// `port.Request`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmissionRequest {
    /// The bound instance.
    pub instance_id: String,
    /// The `central.config/v1` binding.
    pub config_binding: String,
    /// The promoted dependency receipt.
    pub receipt_id: String,
    /// The compose model digest.
    pub model_digest: String,
    /// The payload epoch.
    pub payload_epoch: String,
}

/// The outcome of verifying an admission request (upstream
/// `port.AdmissionResult`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmissionResult {
    /// The admission state.
    pub state: String,
    /// Operator warning, when any.
    pub warning: String,
    /// The admitted receipt.
    pub receipt_id: String,
    /// The prepared dependency set the admission covers.
    pub prepared: PreparedDependencySet,
}

/// The receipt-admission verification boundary: validates that a
/// lifecycle operation is admissible given the current receipt state
/// and binding constraints (upstream `port.Admission`).
#[trait_variant::make(Send)]
pub trait LifecycleAdmission: Send + Sync + 'static {
    /// Verifies `request` and returns the admission result.
    async fn verify(&self, request: AdmissionRequest) -> Result<AdmissionResult, Failure>;
}

impl<A: LifecycleAdmission + ?Sized> LifecycleAdmission for Arc<A> {
    async fn verify(&self, request: AdmissionRequest) -> Result<AdmissionResult, Failure> {
        (**self).verify(request).await
    }
}

/// A capacity reservation for a lifecycle operation (upstream
/// `port.Reservation`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleReservation {
    /// The reservation identity.
    pub id: String,
    /// Bytes allocated.
    pub allocated: i64,
    /// Whether the reservation was bound.
    pub bound: bool,
}

/// The capacity-admission boundary: reserves host resources (disk,
/// memory) required to execute the lifecycle for the given binding
/// and dependency set (upstream `port.Capacity`).
#[trait_variant::make(Send)]
pub trait LifecycleCapacity: Send + Sync + 'static {
    /// Reserves capacity for `binding` + `set`.
    async fn admit(
        &self,
        binding: &LifecycleBinding,
        set: &PreparedDependencySet,
    ) -> Result<LifecycleReservation, Failure>;
}

impl<C: LifecycleCapacity + ?Sized> LifecycleCapacity for Arc<C> {
    async fn admit(
        &self,
        binding: &LifecycleBinding,
        set: &PreparedDependencySet,
    ) -> Result<LifecycleReservation, Failure> {
        (**self).admit(binding, set).await
    }
}

/// The writable-state barrier: ensures no conflicting lifecycle
/// operation is in progress before starting a new writable operation
/// (upstream `port.Barrier`).
#[trait_variant::make(Send)]
pub trait LifecycleBarrier: Send + Sync + 'static {
    /// Fails unless `binding` may start a writable operation.
    async fn validate_writable_start(&self, binding: &LifecycleBinding) -> Result<(), Failure>;
}

impl<B: LifecycleBarrier + ?Sized> LifecycleBarrier for Arc<B> {
    async fn validate_writable_start(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        (**self).validate_writable_start(binding).await
    }
}

/// A lifecycle lock that serializes operations for a binding
/// (upstream `port.Lock`). The fencing token is what stale-lock
/// takeover is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleLock {
    /// The lock identity.
    pub id: String,
    /// Whether the lock was acquired.
    pub acquired: bool,
    /// Lease expiry.
    pub expires_at: OffsetDateTime,
    /// The fencing token.
    pub fencing_token: u64,
}

/// The lifecycle-lock boundary: exclusive access to the lifecycle
/// state for a binding (upstream `port.Locker`).
#[trait_variant::make(Send)]
pub trait LifecycleLocker: Send + Sync + 'static {
    /// Acquires the lock for `binding`.
    async fn acquire(&self, binding: &LifecycleBinding) -> Result<LifecycleLock, Failure>;
    /// Relinquishes an acquired lock for the exact binding. Callers
    /// must release every successfully acquired lock, including on
    /// operation failure.
    async fn release(&self, binding: &LifecycleBinding, lock: LifecycleLock)
    -> Result<(), Failure>;
}

impl<L: LifecycleLocker + ?Sized> LifecycleLocker for Arc<L> {
    async fn acquire(&self, binding: &LifecycleBinding) -> Result<LifecycleLock, Failure> {
        (**self).acquire(binding).await
    }
    async fn release(
        &self,
        binding: &LifecycleBinding,
        lock: LifecycleLock,
    ) -> Result<(), Failure> {
        (**self).release(binding, lock).await
    }
}

/// An authoritative broker result for an expired lock owner (upstream
/// `port.DeadOwnerProof`). Lease expiry alone never authorizes
/// takeover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadOwnerProof {
    /// The expired lock.
    pub lock_id: String,
    /// The owner PID checked.
    pub owner_pid: i32,
    /// Whether the broker verified the owner is dead.
    pub dead: bool,
    /// When the broker verified.
    pub verified_at: OffsetDateTime,
}

/// Verifies an expired lock owner through the protected broker
/// before a replacement lock may be created (upstream
/// `port.DeadOwnerVerifier`).
#[trait_variant::make(Send)]
pub trait DeadOwnerVerifier: Send + Sync + 'static {
    /// Returns the broker's proof for `lock_id`'s `owner_pid`.
    async fn verify_dead_owner(
        &self,
        lock_id: &str,
        owner_pid: i32,
    ) -> Result<DeadOwnerProof, Failure>;
}

impl<V: DeadOwnerVerifier + ?Sized> DeadOwnerVerifier for Arc<V> {
    async fn verify_dead_owner(
        &self,
        lock_id: &str,
        owner_pid: i32,
    ) -> Result<DeadOwnerProof, Failure> {
        (**self).verify_dead_owner(lock_id, owner_pid).await
    }
}

/// A cryptographically signed topology snapshot (upstream
/// `port.SignedSnapshot`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedSnapshot {
    /// The observed snapshot.
    pub snapshot: TopologySnapshot,
    /// The broker signature over it.
    pub signature: String,
}

/// The signed-snapshot read boundary: a point-in-time view of the
/// infrastructure that is cryptographically verifiable (upstream
/// `port.SnapshotReader`).
#[trait_variant::make(Send)]
pub trait SnapshotReader: Send + Sync + 'static {
    /// Reads the signed snapshot for `binding`.
    async fn read(&self, binding: &LifecycleBinding) -> Result<SignedSnapshot, Failure>;
}

impl<R: SnapshotReader + ?Sized> SnapshotReader for Arc<R> {
    async fn read(&self, binding: &LifecycleBinding) -> Result<SignedSnapshot, Failure> {
        (**self).read(binding).await
    }
}

/// Why a bootstrap operation is being performed (upstream
/// `port.BootstrapPurpose`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootstrapPurpose {
    /// `first-setup`.
    FirstSetup,
    /// `reconcile`.
    Reconcile,
    /// `recovery`.
    Recovery,
}

/// A specific bootstrap generation (upstream
/// `port.BootstrapGeneration`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootstrapGeneration {
    /// The generation number.
    pub generation: u32,
    /// Its digest.
    pub digest: String,
}

/// The validity window for a bootstrap handoff (upstream
/// `port.HandoffLifetime`). Serde renders upstream's untagged Go
/// output: `Duration` as int64 nanoseconds, `Expires` as RFC 3339.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffLifetime {
    /// Window length.
    pub duration: Duration,
    /// Expiry instant.
    pub expires: OffsetDateTime,
}

impl Default for HandoffLifetime {
    fn default() -> Self {
        Self {
            duration: Duration::ZERO,
            expires: OffsetDateTime::UNIX_EPOCH,
        }
    }
}

impl Serialize for HandoffLifetime {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("HandoffLifetime", 2)?;
        #[allow(clippy::cast_possible_truncation)]
        st.serialize_field("Duration", &(self.duration.whole_nanoseconds() as i64))?;
        st.serialize_field(
            "Expires",
            &crate::authority::wire::format_rfc3339_nano(self.expires),
        )?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for HandoffLifetime {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Repr {
            /// `Duration` — int64 nanoseconds (Go `time.Duration`).
            #[serde(rename = "Duration")]
            duration: i64,
            /// `Expires` — RFC 3339 (Go `time.Time`).
            #[serde(rename = "Expires")]
            expires: String,
        }
        let repr = Repr::deserialize(d)?;
        let expires = OffsetDateTime::parse(
            &repr.expires,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(serde::de::Error::custom)?;
        Ok(Self {
            duration: Duration::nanoseconds(repr.duration),
            expires,
        })
    }
}

/// The information needed to materialize a bootstrap artifact on the
/// host filesystem (upstream `port.BootstrapHandoff`). It does not
/// serialize `mount_path` or secret values. B04 adoption extends it
/// with opaque operation, binding, receipt, and fencing evidence —
/// the `b04_*` fields are upstream's tagged wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapHandoff {
    /// The bound instance.
    #[serde(rename = "InstanceID")]
    pub instance_id: String,
    /// Why the bootstrap runs.
    #[serde(rename = "Purpose")]
    pub purpose: BootstrapPurpose,
    /// The dependency service.
    #[serde(rename = "Service")]
    pub service: ServiceMode,
    /// Authorized materialization target.
    #[serde(rename = "Target")]
    pub target: String,
    /// Target owner UID.
    #[serde(rename = "UID")]
    pub uid: u32,
    /// Target owner GID.
    #[serde(rename = "GID")]
    pub gid: u32,
    /// The validity window the materialization must complete inside.
    /// Declared before `container_id` so serde emits upstream's Go
    /// declaration order (`Lifetime` then `ContainerID`) —
    /// [`MountProof::handoff_digest`] covers these exact bytes.
    #[serde(rename = "Lifetime")]
    pub lifetime: HandoffLifetime,
    /// The container performing materialization.
    #[serde(rename = "ContainerID")]
    pub container_id: String,
    /// B04 opaque evidence (never plaintext or raw paths).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub b04_operation_id: String,
    /// See [`Self::b04_operation_id`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub b04_binding_id: String,
    /// See [`Self::b04_operation_id`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub b04_receipt_id: String,
    /// See [`Self::b04_operation_id`].
    #[serde(default, skip_serializing_if = "crate::authority::wire::u64_is_zero")]
    pub b04_fencing_token: u64,
    /// See [`Self::b04_operation_id`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub b04_stopped_topology_proof: String,
    /// See [`Self::b04_operation_id`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub b04_mount_release_proof: String,
    /// See [`Self::b04_operation_id`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub b04_binding_evidence: String,
}

/// Proof that a bootstrap artifact was successfully mounted
/// (upstream `port.MountProof`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountProof {
    /// The handoff digest.
    pub handoff_digest: String,
    /// The mount path — adapter-internal; never crosses an authority
    /// boundary.
    pub mount_path: String,
    /// Whether the mount was confirmed.
    pub confirmed: bool,
}

/// The host-bootstrap boundary: ensures the required bootstrap
/// artifact exists, materializes it, and cleans up afterwards
/// (upstream `port.Bootstrap`).
#[trait_variant::make(Send)]
pub trait LifecycleBootstrap: Send + Sync + 'static {
    /// Ensures the bootstrap generation for `binding`/`purpose`.
    async fn ensure(
        &self,
        binding: &LifecycleBinding,
        purpose: BootstrapPurpose,
    ) -> Result<BootstrapGeneration, Failure>;
    /// Materializes one handoff and returns its mount proof.
    async fn materialize(&self, handoff: BootstrapHandoff) -> Result<MountProof, Failure>;
    /// Cleans up a mount proof's artifacts.
    async fn cleanup(&self, proof: MountProof) -> Result<(), Failure>;
    /// `RecordHandoff` — upstream's optional interface assertion on the
    /// concrete `FileBootstrap`: persists the nonsecret mount path for
    /// `binding` so a restarted helper can finish cleanup after a
    /// verified teardown. Implementations with no durable handoff
    /// record answer `Ok(())`, which is upstream's
    /// "interface not implemented" branch — the caller skips the record
    /// rather than fabricating one.
    async fn record_handoff(
        &self,
        binding: &LifecycleBinding,
        proof: &MountProof,
    ) -> Result<(), Failure>;
    /// `CleanupBinding` — upstream's optional interface assertion:
    /// resumes credential cleanup from the durable handoff record for
    /// `binding` after a helper restart. Same default rule as
    /// [`Self::record_handoff`].
    async fn cleanup_binding(&self, binding: &LifecycleBinding) -> Result<(), Failure>;
}

impl<B: LifecycleBootstrap + ?Sized> LifecycleBootstrap for Arc<B> {
    async fn ensure(
        &self,
        binding: &LifecycleBinding,
        purpose: BootstrapPurpose,
    ) -> Result<BootstrapGeneration, Failure> {
        (**self).ensure(binding, purpose).await
    }
    async fn materialize(&self, handoff: BootstrapHandoff) -> Result<MountProof, Failure> {
        (**self).materialize(handoff).await
    }
    async fn cleanup(&self, proof: MountProof) -> Result<(), Failure> {
        (**self).cleanup(proof).await
    }
    async fn record_handoff(
        &self,
        binding: &LifecycleBinding,
        proof: &MountProof,
    ) -> Result<(), Failure> {
        (**self).record_handoff(binding, proof).await
    }
    async fn cleanup_binding(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        (**self).cleanup_binding(binding).await
    }
}

/// The mandatory typed authority client for production bootstrap
/// adoption (upstream `port.B04Bootstrap`). It receives opaque
/// lifecycle evidence only — never paths or secret material.
#[trait_variant::make(Send)]
pub trait B04Bootstrap: Send + Sync + 'static {
    /// Imports the legacy B03 MinIO bootstrap into the B04 registry.
    async fn adopt_b03_minio(&self, evidence: B04LifecycleEvidence) -> Result<(), Failure>;
    /// Materializes the MinIO root credential under `handoff`.
    async fn materialize_minio_root(
        &self,
        handoff: BootstrapHandoff,
    ) -> Result<MountProof, Failure>;
    /// Asks the broker to durably sign the caller's own
    /// stopped-topology/mount-release/binding tokens before
    /// `adopt_b03_minio` is called with the same evidence (SC-DEF-12:
    /// without it, adoption has no broker-issued record to verify
    /// against and denies unconditionally).
    async fn issue_lifecycle_proof(&self, evidence: B04LifecycleEvidence) -> Result<(), Failure>;
}

impl<B: B04Bootstrap + ?Sized> B04Bootstrap for Arc<B> {
    async fn adopt_b03_minio(&self, evidence: B04LifecycleEvidence) -> Result<(), Failure> {
        (**self).adopt_b03_minio(evidence).await
    }
    async fn materialize_minio_root(
        &self,
        handoff: BootstrapHandoff,
    ) -> Result<MountProof, Failure> {
        (**self).materialize_minio_root(handoff).await
    }
    async fn issue_lifecycle_proof(&self, evidence: B04LifecycleEvidence) -> Result<(), Failure> {
        (**self).issue_lifecycle_proof(evidence).await
    }
}

/// The caller credentials for lifecycle authorization (upstream
/// `port.AuthRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleAuthRequest {
    /// Fingerprint of the authorized caller.
    pub caller_fingerprint: String,
    /// The bound instance.
    pub instance_id: String,
    /// The config binding.
    pub config_binding: String,
    /// The authorized verb.
    pub verb: String,
    /// Digest of the authorized request.
    pub request_digest: String,
    /// Digest of the helper binary.
    pub helper_digest: String,
    /// Authorization expiry.
    pub expires_at: OffsetDateTime,
}

/// An opaque authorization token for lifecycle operations (upstream
/// `port.OpaqueAuthorization`). The token format and validation are
/// adapter-specific.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueAuthorization {
    /// The opaque token.
    pub token: String,
    /// Its expiry.
    pub expires_at: OffsetDateTime,
}

/// The lifecycle-authorization boundary: issues and consumes opaque
/// authorization tokens that gate privileged lifecycle transitions
/// (upstream `port.LifecycleAuthorization`).
#[trait_variant::make(Send)]
pub trait LifecycleAuthority: Send + Sync + 'static {
    /// Issues an authorization for `request`.
    async fn authorize(
        &self,
        request: LifecycleAuthRequest,
    ) -> Result<OpaqueAuthorization, Failure>;
    /// Consumes an issued authorization — one use.
    async fn consume(&self, authorization: OpaqueAuthorization) -> Result<(), Failure>;
}

impl<A: LifecycleAuthority + ?Sized> LifecycleAuthority for Arc<A> {
    async fn authorize(
        &self,
        request: LifecycleAuthRequest,
    ) -> Result<OpaqueAuthorization, Failure> {
        (**self).authorize(request).await
    }
    async fn consume(&self, authorization: OpaqueAuthorization) -> Result<(), Failure> {
        (**self).consume(authorization).await
    }
}

/// The orchestration boundary for infrastructure topology operations
/// — filesystem initialization, daemon lifecycle, service
/// provisioning (upstream `infralifecycle.Topology`, re-exported as
/// `port.Topology`).
#[trait_variant::make(Send)]
pub trait TopologyPort: Send + Sync + 'static {
    /// Checks that `binding`'s topology constraints are satisfied.
    async fn validate(&self, binding: &LifecycleBinding) -> Result<(), Failure>;
    /// Initializes the filesystem for `operation`.
    async fn init(&self, operation: &LifecycleOperation) -> Result<(), Failure>;
    /// Starts the long-running daemon containers and returns the
    /// runtime observation.
    async fn start_daemons(&self, operation: &LifecycleOperation) -> Result<Observation, Failure>;
    /// Provisions MinIO and returns a semantically verified receipt.
    async fn provision_minio(
        &self,
        operation: &LifecycleOperation,
    ) -> Result<SemanticReceipt, Failure>;
    /// Returns a point-in-time snapshot of the topology for
    /// `binding`.
    async fn inspect(&self, binding: &LifecycleBinding) -> Result<TopologySnapshot, Failure>;
    /// Tears down the infrastructure for `operation`.
    async fn down(&self, operation: &LifecycleOperation) -> Result<(), Failure>;
    /// `TeardownVerified` — upstream's optional `verifiedTeardown`
    /// interface assertion. Implementations must prove every daemon
    /// stopped before the domain releases credential cleanup; an
    /// implementation that cannot verify answers the same
    /// "verified teardown is unavailable" failure upstream's
    /// type-assertion produces.
    async fn teardown_verified(&self, operation: &LifecycleOperation) -> Result<(), Failure>;
    /// `CleanupSecrets` — upstream's optional `bootstrapCleaner`
    /// interface assertion: removes the materialized bootstrap secrets
    /// for `operation`. Implementations with no secrets answer `Ok(())`,
    /// matching a topology that does not implement the interface.
    async fn cleanup_secrets(&self, operation: &LifecycleOperation) -> Result<(), Failure>;
}

impl<T: TopologyPort + ?Sized> TopologyPort for Arc<T> {
    async fn validate(&self, binding: &LifecycleBinding) -> Result<(), Failure> {
        (**self).validate(binding).await
    }
    async fn init(&self, operation: &LifecycleOperation) -> Result<(), Failure> {
        (**self).init(operation).await
    }
    async fn start_daemons(&self, operation: &LifecycleOperation) -> Result<Observation, Failure> {
        (**self).start_daemons(operation).await
    }
    async fn provision_minio(
        &self,
        operation: &LifecycleOperation,
    ) -> Result<SemanticReceipt, Failure> {
        (**self).provision_minio(operation).await
    }
    async fn inspect(&self, binding: &LifecycleBinding) -> Result<TopologySnapshot, Failure> {
        (**self).inspect(binding).await
    }
    async fn down(&self, operation: &LifecycleOperation) -> Result<(), Failure> {
        (**self).down(operation).await
    }
    async fn teardown_verified(&self, operation: &LifecycleOperation) -> Result<(), Failure> {
        (**self).teardown_verified(operation).await
    }
    async fn cleanup_secrets(&self, operation: &LifecycleOperation) -> Result<(), Failure> {
        (**self).cleanup_secrets(operation).await
    }
}

/// The durable lifecycle journal — records every state-machine
/// transition and supports resuming an unsettled operation after a
/// crash or restart (upstream `infralifecycle.Journal`, re-exported as
/// `port.Journal`; named `LifecyclePort` here per the R5 plan).
///
/// `begin`/`record`/`settle` are the write path; `unsettled` is the
/// resume path. `begin_linked_down` opens a `down` operation even
/// when its linked `up` is unsettled — the durable link lets `down`
/// terminalize that exact `up` only after teardown.
#[trait_variant::make(Send)]
pub trait LifecyclePort: Send + Sync + 'static {
    /// Opens a new lifecycle operation for `binding` with the initial
    /// `observation`.
    async fn begin(
        &self,
        binding: LifecycleBinding,
        observation: Observation,
    ) -> Result<LifecycleOperation, Failure>;

    /// Opens a `down` operation linked to the unsettled `up`
    /// operation `linked`.
    async fn begin_linked_down(
        &self,
        binding: LifecycleBinding,
        observation: Observation,
        linked: &LifecycleOperation,
    ) -> Result<LifecycleOperation, Failure>;

    /// Persists a phase transition for `operation`.
    async fn record(
        &self,
        operation: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure>;

    /// Associates a dependency-prepare receipt with `operation`.
    async fn prepare_receipt(
        &self,
        operation: &LifecycleOperation,
        receipt: &DependencyReceipt,
    ) -> Result<(), Failure>;

    /// Commits a receipt selector switch for `operation`.
    async fn switch_receipt(&self, operation: &LifecycleOperation) -> Result<(), Failure>;

    /// Records the terminal phase of `operation`.
    async fn settle(
        &self,
        operation: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure>;

    /// Returns the most recent unsettled (non-terminal) operation for
    /// `binding`, if any.
    async fn unsettled(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<Option<LifecycleOperation>, Failure>;
}

impl<J: LifecyclePort + ?Sized> LifecyclePort for Arc<J> {
    async fn begin(
        &self,
        binding: LifecycleBinding,
        observation: Observation,
    ) -> Result<LifecycleOperation, Failure> {
        (**self).begin(binding, observation).await
    }
    async fn begin_linked_down(
        &self,
        binding: LifecycleBinding,
        observation: Observation,
        linked: &LifecycleOperation,
    ) -> Result<LifecycleOperation, Failure> {
        (**self)
            .begin_linked_down(binding, observation, linked)
            .await
    }
    async fn record(
        &self,
        operation: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure> {
        (**self).record(operation, phase).await
    }
    async fn prepare_receipt(
        &self,
        operation: &LifecycleOperation,
        receipt: &DependencyReceipt,
    ) -> Result<(), Failure> {
        (**self).prepare_receipt(operation, receipt).await
    }
    async fn switch_receipt(&self, operation: &LifecycleOperation) -> Result<(), Failure> {
        (**self).switch_receipt(operation).await
    }
    async fn settle(
        &self,
        operation: &LifecycleOperation,
        phase: LifecyclePhase,
    ) -> Result<(), Failure> {
        (**self).settle(operation, phase).await
    }
    async fn unsettled(
        &self,
        binding: &LifecycleBinding,
    ) -> Result<Option<LifecycleOperation>, Failure> {
        (**self).unsettled(binding).await
    }
}

/// The clock deadline enforcement in lifecycle operations reads
/// (upstream `port.Clock`). Synchronous — time is a value, not a
/// boundary round-trip.
pub trait LifecycleClock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> OffsetDateTime;
}

impl<C: LifecycleClock + ?Sized> LifecycleClock for Arc<C> {
    fn now(&self) -> OffsetDateTime {
        (**self).now()
    }
}

// ---------------------------------------------------------------------------
// BootstrapAuthority — the broker-facing B04 mutation boundary
// (upstream secretbootstrap/port.BootstrapAuthority)
// ---------------------------------------------------------------------------

/// The typed broker-facing authority interface for B04 secret
/// bootstrap operations. It is the only mutation/use boundary; there
/// is no arbitrary secret read or write method.
#[trait_variant::make(Send)]
pub trait BootstrapAuthority: Send + Sync + 'static {
    /// Imports a legacy B03 protected generation into the B04
    /// registry without replacing the existing generation value.
    /// Returns the canonical [`SecretBinding`] and its
    /// [`BootstrapOutcome`].
    async fn adopt_b03(
        &self,
        request: crate::domain::AdoptRequest,
    ) -> Result<(SecretBinding, BootstrapOutcome), Failure>;

    /// Resolves a one-use [`HandoffReceipt`] and writes the bound
    /// dependency credential to the authorized target. The receipt
    /// is consumed atomically.
    async fn materialize_dependency(
        &self,
        request: HandoffRequest,
    ) -> Result<HandoffReceipt, Failure>;

    /// Creates a new protected generation for a system purpose.
    /// Non-operator-facing; used by the broker internally.
    async fn prepare_system_generation(
        &self,
        purpose: Purpose,
        instance_id: &str,
    ) -> Result<SecretBinding, Failure>;

    /// Invalidates every unacknowledged receipt for a binding. It
    /// does not revoke bytes a running dependency already read.
    async fn revoke_binding(
        &self,
        binding_id: SecretBindingId,
    ) -> Result<BootstrapOutcome, Failure>;

    /// Removes a binding and all associated generation data. The
    /// caller must prove the binding has no live lease holder.
    async fn delete_binding(
        &self,
        binding_id: SecretBindingId,
        fencing_token: u64,
    ) -> Result<BootstrapOutcome, Failure>;
}

impl<A: BootstrapAuthority + ?Sized> BootstrapAuthority for Arc<A> {
    async fn adopt_b03(
        &self,
        request: crate::domain::AdoptRequest,
    ) -> Result<(SecretBinding, BootstrapOutcome), Failure> {
        (**self).adopt_b03(request).await
    }
    async fn materialize_dependency(
        &self,
        request: HandoffRequest,
    ) -> Result<HandoffReceipt, Failure> {
        (**self).materialize_dependency(request).await
    }
    async fn prepare_system_generation(
        &self,
        purpose: Purpose,
        instance_id: &str,
    ) -> Result<SecretBinding, Failure> {
        (**self)
            .prepare_system_generation(purpose, instance_id)
            .await
    }
    async fn revoke_binding(
        &self,
        binding_id: SecretBindingId,
    ) -> Result<BootstrapOutcome, Failure> {
        (**self).revoke_binding(binding_id).await
    }
    async fn delete_binding(
        &self,
        binding_id: SecretBindingId,
        fencing_token: u64,
    ) -> Result<BootstrapOutcome, Failure> {
        (**self).delete_binding(binding_id, fencing_token).await
    }
}

// ---------------------------------------------------------------------------
// AdvisoryFetch — the active advisory bundle boundary (B01)
// ---------------------------------------------------------------------------

/// The currently active advisory bundle (upstream
/// `advisory.Snapshot`): the generation identity, the selector digest
/// it pins, and the raw bundle + signature bytes the evaluator
/// verifies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvisorySnapshot {
    /// The advisory generation.
    pub generation_id: String,
    /// The dependency-selector digest the bundle pins.
    pub selector_digest: String,
    /// The canonical bundle bytes.
    pub bundle: Vec<u8>,
    /// The bundle signature.
    pub signature: Vec<u8>,
}

/// Loads the active advisory snapshot (upstream
/// `advisory/port.ActiveBundleSource`). `load_active` returning a
/// `Failure::not_found` means no bundle has ever been durably
/// accepted — a legitimate absence, not a corrupted one.
#[trait_variant::make(Send)]
pub trait AdvisoryFetch: Send + Sync + 'static {
    /// Loads the active advisory bundle.
    async fn load_active(&self) -> Result<AdvisorySnapshot, Failure>;
}

impl<A: AdvisoryFetch + ?Sized> AdvisoryFetch for Arc<A> {
    async fn load_active(&self) -> Result<AdvisorySnapshot, Failure> {
        (**self).load_active().await
    }
}

// ---------------------------------------------------------------------------
// DependencyStore — the prepared-dependency settlement store (B02)
// ---------------------------------------------------------------------------

/// The prepared-dependency settlement store — upstream
/// `dependencyprepare/port.CandidateStore` plus its `Journal` (one
/// adapter implements both).
///
/// `stage_candidate`/`switch_selector`/`recover` are the write path
/// a prepare operation uses; `active` is what a lifecycle admission
/// reads; `record_operation`/`unsettled_operation`/`exact_operation`
/// are the durable checkpoint records that make an interrupted
/// prepare resumable.
///
/// `recover` repeats exactly the switch a previously staged candidate
/// was prepared for, or quarantines it with
/// `ERR_CANDIDATE_QUARANTINED`. It takes only the staged candidate's
/// ID: the selector and dependency set must come from the staged
/// evidence, never from a resumed caller.
#[trait_variant::make(Send)]
pub trait DependencyStore: Send + Sync + 'static {
    /// Stages a candidate and returns its persisted form.
    async fn stage_candidate(&self, candidate: Candidate) -> Result<Candidate, Failure>;

    /// Switches the active selector to `candidate` under `binding`
    /// and returns the settled receipt.
    async fn switch_selector(
        &self,
        candidate: &Candidate,
        binding: &AdmissionBinding,
    ) -> Result<DependencyReceipt, Failure>;

    /// Repeats exactly the switch `candidate_id` was staged for, or
    /// quarantines it. Selector and dependency set come from the
    /// staged evidence, never from the resumed caller.
    async fn recover(
        &self,
        candidate_id: &str,
        binding: &AdmissionBinding,
    ) -> Result<DependencyReceipt, Failure>;

    /// Returns the currently active receipt, or `None` when none has
    /// settled.
    async fn active(&self) -> Result<Option<DependencyReceipt>, Failure>;

    /// Persists a checkpoint of `operation`. What is written and what
    /// `exact_operation` reads back are the same value.
    async fn record_operation(&self, operation: &PrepareOperation) -> Result<(), Failure>;

    /// The unsettled (non-terminal) operation record, if any.
    async fn unsettled_operation(&self) -> Result<Option<PrepareOperation>, Failure>;

    /// The exact operation record for `id` — `Failure::not_found`
    /// when none exists.
    async fn exact_operation(&self, id: &str) -> Result<PrepareOperation, Failure>;
}

impl<D: DependencyStore + ?Sized> DependencyStore for Arc<D> {
    async fn stage_candidate(&self, candidate: Candidate) -> Result<Candidate, Failure> {
        (**self).stage_candidate(candidate).await
    }
    async fn switch_selector(
        &self,
        candidate: &Candidate,
        binding: &AdmissionBinding,
    ) -> Result<DependencyReceipt, Failure> {
        (**self).switch_selector(candidate, binding).await
    }
    async fn recover(
        &self,
        candidate_id: &str,
        binding: &AdmissionBinding,
    ) -> Result<DependencyReceipt, Failure> {
        (**self).recover(candidate_id, binding).await
    }
    async fn active(&self) -> Result<Option<DependencyReceipt>, Failure> {
        (**self).active().await
    }
    async fn record_operation(&self, operation: &PrepareOperation) -> Result<(), Failure> {
        (**self).record_operation(operation).await
    }
    async fn unsettled_operation(&self) -> Result<Option<PrepareOperation>, Failure> {
        (**self).unsettled_operation().await
    }
    async fn exact_operation(&self, id: &str) -> Result<PrepareOperation, Failure> {
        (**self).exact_operation(id).await
    }
}

// ---------------------------------------------------------------------------
// Advisory consumer ports — upstream `internal/advisory/port/advisory_port.go`
// ---------------------------------------------------------------------------

/// `port.ActiveBundleSource` — loads the installed active advisory
/// snapshot (`advisories/active.json` → `generations/<id>/envelope.json`).
/// `Err` means the source could not produce a snapshot; the evaluation
/// service maps it to `Denied`/`SourceUnavailable`.
#[trait_variant::make(Send)]
pub trait ActiveBundleSource: Send + Sync + 'static {
    /// `LoadActive`.
    async fn load_active(&self) -> Result<crate::advisory::Snapshot, Failure>;
}

impl<S: ActiveBundleSource + ?Sized> ActiveBundleSource for Arc<S> {
    async fn load_active(&self) -> Result<crate::advisory::Snapshot, Failure> {
        (**self).load_active().await
    }
}

/// `port.HostFactsCollector` — collects the host environment versions
/// the compatibility matrix compares against. `Err` means collection
/// failed; the service substitutes the zero facts.
#[trait_variant::make(Send)]
pub trait HostFactsCollector: Send + Sync + 'static {
    /// `Collect`.
    async fn collect(&self) -> Result<crate::advisory::HostFacts, Failure>;
}

impl<C: HostFactsCollector + ?Sized> HostFactsCollector for Arc<C> {
    async fn collect(&self) -> Result<crate::advisory::HostFacts, Failure> {
        (**self).collect().await
    }
}

/// `port.Clock` — the evaluation-time wall clock. Upstream's interface
/// is synchronous, so this port is too (it is not a suspension point).
pub trait AdvisoryClock: Send + Sync + 'static {
    /// `Now`.
    fn now(&self) -> OffsetDateTime;
}

impl<C: AdvisoryClock + ?Sized> AdvisoryClock for Arc<C> {
    fn now(&self) -> OffsetDateTime {
        (**self).now()
    }
}

/// `port.TimeWitnessStore` — reads and durably advances the root-owned
/// anti-rollback witness.
///
/// `load` returns [`crate::advisory::WITNESS_NOT_FOUND_CODE`] (a
/// `NotFound` failure) for a legitimately absent witness — no bundle has
/// ever been durably accepted, so there is nothing to protect a rollback
/// to. Every other error means a witness that exists but cannot be
/// trusted (corrupt, wrong owner, unparseable); the service treats it as
/// a denial, never as a zero witness.
///
/// `advance` is called only after an evaluation accepts a bundle as
/// `current`, with the accepted bundle's own `issued_at` — never the
/// wall clock — so re-evaluating an unchanged bundle stays stable.
#[trait_variant::make(Send)]
pub trait TimeWitnessStore: Send + Sync + 'static {
    /// `Load`.
    async fn load(&self) -> Result<crate::advisory::TimeWitness, Failure>;
    /// `Advance` — durably replace the witness.
    async fn advance(&self, witness: &crate::advisory::TimeWitness) -> Result<(), Failure>;
}

impl<W: TimeWitnessStore + ?Sized> TimeWitnessStore for Arc<W> {
    async fn load(&self) -> Result<crate::advisory::TimeWitness, Failure> {
        (**self).load().await
    }
    async fn advance(&self, witness: &crate::advisory::TimeWitness) -> Result<(), Failure> {
        (**self).advance(witness).await
    }
}

/// `port.TransitionRecorder` — atomically appends the outcome of one
/// advisory evaluation to the authority-transition journal. `bundle` is
/// `None` when evaluation stopped before a bundle verified (source
/// unavailable, signature/schema failure); `facts` is the zero value
/// when host facts were never collected. Implementations persist only
/// allowlisted evidence (`authority::AdvisoryAdmissionEvidence`) and
/// must never persist raw bundle bytes or signature material.
#[trait_variant::make(Send)]
pub trait TransitionRecorder: Send + Sync + 'static {
    /// `Record` — returns the journaled receipt the admission binds.
    async fn record(
        &self,
        outcome: &crate::advisory::Outcome,
        bundle: Option<&crate::advisory::VerifiedBundle>,
        facts: &crate::advisory::HostFacts,
    ) -> Result<crate::advisory::Receipt, Failure>;
}

impl<R: TransitionRecorder + ?Sized> TransitionRecorder for Arc<R> {
    async fn record(
        &self,
        outcome: &crate::advisory::Outcome,
        bundle: Option<&crate::advisory::VerifiedBundle>,
        facts: &crate::advisory::HostFacts,
    ) -> Result<crate::advisory::Receipt, Failure> {
        (**self).record(outcome, bundle, facts).await
    }
}

/// The deny-safe write seam upstream's `Service.DenySafeDir` +
/// `advisory.EnterDenySafe` provide. The domain cannot touch the
/// filesystem, so the adapter's file store carries the directory and
/// uid/gid. The service calls `enter` best-effort on `hard_expired`
/// outcomes only — the refusal itself is the primary protection and a
/// state-file failure must never turn an evaluation error into an
/// admission.
#[trait_variant::make(Send)]
pub trait DenySafeStore: Send + Sync + 'static {
    /// `EnterDenySafe` — record mode entry; an already-active record is
    /// returned untouched (entry keeps the original trigger and time).
    async fn enter(&self, trigger_code: &str, now: OffsetDateTime) -> Result<(), Failure>;
}

impl<S: DenySafeStore + ?Sized> DenySafeStore for Arc<S> {
    async fn enter(&self, trigger_code: &str, now: OffsetDateTime) -> Result<(), Failure> {
        (**self).enter(trigger_code, now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{
        BrokerOutcome, GenesisPhase, GenesisStatus, InstanceBinding, UidGidMap,
    };
    use crate::domain::{LifecycleOperation, Observation};
    use std::sync::Mutex;
    use time::macros::datetime;

    /// `Waker::noop` keeps this unsafe-free (house pattern from
    /// central-event/central-scheduler).
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        let mut fut = core::pin::pin!(fut);
        let waker = core::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(waker);
        loop {
            match fut.as_mut().poll(&mut cx) {
                core::task::Poll::Ready(v) => return v,
                core::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    // ---------------------------------------------------------------
    // Envelope wire shapes (upstream helper/protocol.go + authority)
    // ---------------------------------------------------------------

    /// Ports the upstream helper protocol framing: request is
    /// `{operation_id, verb, payload?}`, response is
    /// `{operation_id, outcome, exit_code, reason?, result?}` — both
    /// newline-delimited (the delimiter is the transport's, not the
    /// struct's).
    #[test]
    fn helper_envelope_wire_shape() {
        let request = HelperRequest {
            operation_id: "op-1".to_string(),
            verb: HelperVerb::Init,
            payload: Some(serde_json::json!({"key": "value"})),
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            "{\"operation_id\":\"op-1\",\"verb\":\"init\",\"payload\":{\"key\":\"value\"}}"
        );
        let bare = HelperRequest {
            operation_id: "op-2".to_string(),
            verb: HelperVerb::Status,
            payload: None,
        };
        assert_eq!(
            serde_json::to_string(&bare).unwrap(),
            "{\"operation_id\":\"op-2\",\"verb\":\"status\"}"
        );

        let response = HelperResponse {
            operation_id: "op-1".to_string(),
            outcome: HelperOutcome::Denied,
            exit_code: 5,
            reason: Some("UNSUPPORTED_IN_THIS_SLICE".to_string()),
            result: None,
        };
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            "{\"operation_id\":\"op-1\",\"outcome\":\"denied\",\"exit_code\":5,\"reason\":\"UNSUPPORTED_IN_THIS_SLICE\"}"
        );
        let ok = HelperResponse {
            operation_id: "op-3".to_string(),
            outcome: HelperOutcome::Success,
            exit_code: 0,
            reason: None,
            result: Some(serde_json::json!({"ready": true})),
        };
        assert_eq!(
            serde_json::to_string(&ok).unwrap(),
            "{\"operation_id\":\"op-3\",\"outcome\":\"success\",\"exit_code\":0,\"result\":{\"ready\":true}}"
        );
        assert_eq!(
            serde_json::from_str::<HelperOutcome>("\"error\"").unwrap(),
            HelperOutcome::Error
        );

        // The fourth outcome word: upstream answers `deferred` for
        // registered-but-`!Implemented` verbs
        // (helper/server.go — `UNSUPPORTED_IN_THIS_SLICE` and the
        // verb-specific `*_UNAVAILABLE` arms).
        let deferred: HelperResponse = serde_json::from_str(
            "{\"operation_id\":\"op-4\",\"outcome\":\"deferred\",\"exit_code\":5,\"reason\":\"UNSUPPORTED_IN_THIS_SLICE\"}",
        )
        .unwrap();
        assert_eq!(deferred.outcome, HelperOutcome::Deferred);
        assert_eq!(
            serde_json::to_string(&deferred).unwrap(),
            "{\"operation_id\":\"op-4\",\"outcome\":\"deferred\",\"exit_code\":5,\"reason\":\"UNSUPPORTED_IN_THIS_SLICE\"}"
        );
    }

    /// Pins `BootstrapHandoff`'s serialized bytes to upstream's Go
    /// declaration order — `InstanceID … GID, Lifetime, ContainerID,
    /// b04_*` — because [`MountProof::handoff_digest`] digests this
    /// exact encoding. `b04_fencing_token` is `,omitempty` upstream:
    /// zero is not emitted.
    #[test]
    fn bootstrap_handoff_wire_shape_matches_upstream() {
        let handoff = BootstrapHandoff {
            instance_id: "i-1".to_string(),
            purpose: BootstrapPurpose::FirstSetup,
            service: ServiceMode::Minio,
            target: "/run/central/bootstrap".to_string(),
            uid: 501,
            gid: 502,
            lifetime: HandoffLifetime {
                duration: Duration::seconds(90),
                expires: datetime!(2026-03-04 06:30:00 UTC),
            },
            container_id: "container-9".to_string(),
            b04_operation_id: String::new(),
            b04_binding_id: String::new(),
            b04_receipt_id: String::new(),
            b04_fencing_token: 0,
            b04_stopped_topology_proof: String::new(),
            b04_mount_release_proof: String::new(),
            b04_binding_evidence: String::new(),
        };
        assert_eq!(
            serde_json::to_string(&handoff).unwrap(),
            "{\"InstanceID\":\"i-1\",\"Purpose\":\"first-setup\",\"Service\":\"minio\",\"Target\":\"/run/central/bootstrap\",\"UID\":501,\"GID\":502,\"Lifetime\":{\"Duration\":90000000000,\"Expires\":\"2026-03-04T06:30:00Z\"},\"ContainerID\":\"container-9\"}"
        );

        // B04 evidence emits in tag order; a non-zero fencing token
        // appears where upstream's `,omitempty` places it.
        let adopted = BootstrapHandoff {
            b04_operation_id: "op-7".to_string(),
            b04_binding_id: "bind-3".to_string(),
            b04_receipt_id: "rcpt-2".to_string(),
            b04_fencing_token: 42,
            b04_stopped_topology_proof: "stop".to_string(),
            b04_mount_release_proof: "rel".to_string(),
            b04_binding_evidence: "ev".to_string(),
            ..handoff.clone()
        };
        assert_eq!(
            serde_json::to_string(&adopted).unwrap(),
            "{\"InstanceID\":\"i-1\",\"Purpose\":\"first-setup\",\"Service\":\"minio\",\"Target\":\"/run/central/bootstrap\",\"UID\":501,\"GID\":502,\"Lifetime\":{\"Duration\":90000000000,\"Expires\":\"2026-03-04T06:30:00Z\"},\"ContainerID\":\"container-9\",\"b04_operation_id\":\"op-7\",\"b04_binding_id\":\"bind-3\",\"b04_receipt_id\":\"rcpt-2\",\"b04_fencing_token\":42,\"b04_stopped_topology_proof\":\"stop\",\"b04_mount_release_proof\":\"rel\",\"b04_binding_evidence\":\"ev\"}"
        );
        // The zero token round-trips through `default`.
        let decoded: BootstrapHandoff =
            serde_json::from_str(&serde_json::to_string(&handoff).unwrap()).unwrap();
        assert_eq!(decoded, handoff);
    }

    // ---------------------------------------------------------------
    // Stub implementations — compile + smoke coverage that every
    // trait is object-safe and Arc-forwarding works.
    // ---------------------------------------------------------------

    struct StubHelper {
        seen: Mutex<Vec<HelperRequest>>,
    }

    impl HelperClient for StubHelper {
        async fn invoke(&self, request: HelperRequest) -> Result<HelperResponse, Failure> {
            let operation_id = request.operation_id.clone();
            self.seen.lock().unwrap().push(request);
            Ok(HelperResponse {
                operation_id,
                outcome: HelperOutcome::Success,
                exit_code: 0,
                reason: None,
                result: None,
            })
        }
    }

    struct StubBroker;

    impl BrokerClient for StubBroker {
        async fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Failure> {
            Ok(BrokerResponse {
                operation_id: request.operation_id.clone(),
                outcome: BrokerOutcome::Success,
                result: None,
                evidence: crate::authority::BrokerEvidence {
                    operation_id: request.operation_id,
                    ..Default::default()
                },
            })
        }
    }

    struct StubGenesis {
        binding: Mutex<Option<InstanceBinding>>,
        receipt: Mutex<Option<GenesisReceipt>>,
    }

    impl GenesisPort for StubGenesis {
        async fn read_binding(&self, _host_id: &str) -> Result<Option<InstanceBinding>, Failure> {
            Ok(self.binding.lock().unwrap().clone())
        }
        async fn write_binding(&self, binding: &InstanceBinding) -> Result<(), Failure> {
            *self.binding.lock().unwrap() = Some(binding.clone());
            Ok(())
        }
        async fn read_genesis_receipt(
            &self,
            _operation_id: OperationId,
        ) -> Result<Option<GenesisReceipt>, Failure> {
            Ok(self.receipt.lock().unwrap().clone())
        }
        async fn write_genesis_receipt(&self, receipt: &GenesisReceipt) -> Result<(), Failure> {
            *self.receipt.lock().unwrap() = Some(receipt.clone());
            Ok(())
        }
    }

    struct StubLifecycle {
        operations: Mutex<Vec<LifecycleOperation>>,
    }

    impl LifecyclePort for StubLifecycle {
        async fn begin(
            &self,
            binding: LifecycleBinding,
            observation: Observation,
        ) -> Result<LifecycleOperation, Failure> {
            let operation = LifecycleOperation {
                id: "op-1".to_string(),
                linked_operation_id: String::new(),
                phase: LifecyclePhase::Started,
                binding,
                observation,
                created_at: datetime!(2026-03-04 05:00:00 UTC),
            };
            self.operations.lock().unwrap().push(operation.clone());
            Ok(operation)
        }
        async fn begin_linked_down(
            &self,
            binding: LifecycleBinding,
            observation: Observation,
            linked: &LifecycleOperation,
        ) -> Result<LifecycleOperation, Failure> {
            let mut op = self.begin(binding, observation).await?;
            op.linked_operation_id = linked.id.clone();
            Ok(op)
        }
        async fn record(
            &self,
            _operation: &LifecycleOperation,
            _phase: LifecyclePhase,
        ) -> Result<(), Failure> {
            Ok(())
        }
        async fn prepare_receipt(
            &self,
            _operation: &LifecycleOperation,
            _receipt: &DependencyReceipt,
        ) -> Result<(), Failure> {
            Ok(())
        }
        async fn switch_receipt(&self, _operation: &LifecycleOperation) -> Result<(), Failure> {
            Ok(())
        }
        async fn settle(
            &self,
            _operation: &LifecycleOperation,
            _phase: LifecyclePhase,
        ) -> Result<(), Failure> {
            Ok(())
        }
        async fn unsettled(
            &self,
            _binding: &LifecycleBinding,
        ) -> Result<Option<LifecycleOperation>, Failure> {
            Ok(self.operations.lock().unwrap().first().cloned())
        }
    }

    /// Every port is usable through a generic `T: Port` bound and the
    /// blanket `Arc<S>` impl forwards — the composition style the
    /// kernel uses (`Arc<Adapter>` passed where `T: Port` is
    /// required). `trait_variant` futures are RPITIT, so ports
    /// compose generically rather than behind `dyn`.
    #[test]
    fn ports_compose_and_arc_forwarding() {
        async fn invoke_on<C: HelperClient>(client: C) -> Result<HelperResponse, Failure> {
            client
                .invoke(HelperRequest {
                    operation_id: "op-1".to_string(),
                    verb: HelperVerb::Init,
                    payload: None,
                })
                .await
        }
        let helper = Arc::new(StubHelper {
            seen: Mutex::new(Vec::new()),
        });
        let response = block_on(invoke_on(helper)).unwrap();
        assert_eq!(response.outcome, HelperOutcome::Success);
        assert_eq!(response.operation_id, "op-1");

        async fn call_on<B: BrokerClient>(broker: B) -> Result<BrokerResponse, Failure> {
            broker
                .call(BrokerRequest {
                    operation_id: "op-2".to_string(),
                    purpose: "issue_b04_lifecycle_proof".to_string(),
                    session_token: String::new(),
                    payload: Default::default(),
                })
                .await
        }
        let response = block_on(call_on(Arc::new(StubBroker))).unwrap();
        assert_eq!(response.outcome, BrokerOutcome::Success);
        assert_eq!(response.operation_id, "op-2");

        let genesis = Arc::new(StubGenesis {
            binding: Mutex::new(None),
            receipt: Mutex::new(None),
        });
        async fn round_trip<G: GenesisPort>(g: G, binding: &InstanceBinding) -> bool {
            assert!(g.read_binding("host-1").await.unwrap().is_none());
            g.write_binding(binding).await.unwrap();
            g.read_binding("host-1").await.unwrap() == Some(binding.clone())
        }
        let binding = InstanceBinding {
            instance_id: central_foundation::identity::InstanceId::new(),
            host_id: "host-1".to_string(),
            release_digest: "sha256:rel".to_string(),
            created_at: datetime!(2026-03-04 05:00:00 UTC),
            config_binding_id: central_foundation::identity::ConfigBindingId::new(),
            uid_gid: UidGidMap {
                runtime_uid: 501,
                runtime_gid: 501,
                agent_uid: 502,
                agent_gid: 502,
                browser_uid: 503,
                browser_gid: 503,
            },
        };
        assert!(block_on(round_trip(genesis, &binding)));

        let lifecycle = Arc::new(StubLifecycle {
            operations: Mutex::new(Vec::new()),
        });
        let binding = LifecycleBinding {
            instance_id: "i".to_string(),
            config_binding: "c".to_string(),
            receipt_id: "r".to_string(),
            payload_epoch: "e".to_string(),
            ..Default::default()
        };
        let op = block_on(lifecycle.begin(binding.clone(), Observation::default())).unwrap();
        assert_eq!(op.phase, LifecyclePhase::Started);
        assert!(block_on(lifecycle.unsettled(&binding)).unwrap().is_some());
    }

    /// The remaining inward ports satisfy the same contract: the
    /// stub proves the trait compiles and `Arc<S>` satisfies the
    /// generic bound via the forwarding impl.
    #[test]
    fn remaining_ports_compose_via_arc_forwarding() {
        struct StubAdmission;
        impl LifecycleAdmission for StubAdmission {
            async fn verify(&self, _request: AdmissionRequest) -> Result<AdmissionResult, Failure> {
                Ok(AdmissionResult::default())
            }
        }
        struct StubCapacity;
        impl LifecycleCapacity for StubCapacity {
            async fn admit(
                &self,
                _binding: &LifecycleBinding,
                _set: &PreparedDependencySet,
            ) -> Result<LifecycleReservation, Failure> {
                Ok(LifecycleReservation::default())
            }
        }
        struct StubBarrier;
        impl LifecycleBarrier for StubBarrier {
            async fn validate_writable_start(
                &self,
                _binding: &LifecycleBinding,
            ) -> Result<(), Failure> {
                Ok(())
            }
        }
        struct StubLocker;
        impl LifecycleLocker for StubLocker {
            async fn acquire(&self, _binding: &LifecycleBinding) -> Result<LifecycleLock, Failure> {
                Ok(LifecycleLock {
                    id: "lock-1".to_string(),
                    acquired: true,
                    expires_at: datetime!(2026-03-04 06:00:00 UTC),
                    fencing_token: 1,
                })
            }
            async fn release(
                &self,
                _binding: &LifecycleBinding,
                _lock: LifecycleLock,
            ) -> Result<(), Failure> {
                Ok(())
            }
        }
        struct StubVerifier;
        impl DeadOwnerVerifier for StubVerifier {
            async fn verify_dead_owner(
                &self,
                _lock_id: &str,
                _owner_pid: i32,
            ) -> Result<DeadOwnerProof, Failure> {
                Ok(DeadOwnerProof {
                    lock_id: "lock-1".to_string(),
                    owner_pid: 1,
                    dead: true,
                    verified_at: datetime!(2026-03-04 05:00:00 UTC),
                })
            }
        }
        struct StubSnapshots;
        impl SnapshotReader for StubSnapshots {
            async fn read(&self, _binding: &LifecycleBinding) -> Result<SignedSnapshot, Failure> {
                Ok(SignedSnapshot::default())
            }
        }
        struct StubBootstrap;
        impl LifecycleBootstrap for StubBootstrap {
            async fn ensure(
                &self,
                _binding: &LifecycleBinding,
                _purpose: BootstrapPurpose,
            ) -> Result<BootstrapGeneration, Failure> {
                Ok(BootstrapGeneration::default())
            }
            async fn materialize(&self, _handoff: BootstrapHandoff) -> Result<MountProof, Failure> {
                Ok(MountProof::default())
            }
            async fn cleanup(&self, _proof: MountProof) -> Result<(), Failure> {
                Ok(())
            }
            async fn record_handoff(
                &self,
                _binding: &LifecycleBinding,
                _proof: &MountProof,
            ) -> Result<(), Failure> {
                Ok(())
            }
            async fn cleanup_binding(&self, _binding: &LifecycleBinding) -> Result<(), Failure> {
                Ok(())
            }
        }
        struct StubB04;
        impl B04Bootstrap for StubB04 {
            async fn adopt_b03_minio(
                &self,
                _evidence: B04LifecycleEvidence,
            ) -> Result<(), Failure> {
                Ok(())
            }
            async fn materialize_minio_root(
                &self,
                _handoff: BootstrapHandoff,
            ) -> Result<MountProof, Failure> {
                Ok(MountProof::default())
            }
            async fn issue_lifecycle_proof(
                &self,
                _evidence: B04LifecycleEvidence,
            ) -> Result<(), Failure> {
                Ok(())
            }
        }
        struct StubAuthority;
        impl LifecycleAuthority for StubAuthority {
            async fn authorize(
                &self,
                _request: LifecycleAuthRequest,
            ) -> Result<OpaqueAuthorization, Failure> {
                Ok(OpaqueAuthorization {
                    token: "tok".to_string(),
                    expires_at: datetime!(2026-03-04 06:00:00 UTC),
                })
            }
            async fn consume(&self, _authorization: OpaqueAuthorization) -> Result<(), Failure> {
                Ok(())
            }
        }
        struct StubTopology;
        impl TopologyPort for StubTopology {
            async fn validate(&self, _binding: &LifecycleBinding) -> Result<(), Failure> {
                Ok(())
            }
            async fn init(&self, _operation: &LifecycleOperation) -> Result<(), Failure> {
                Ok(())
            }
            async fn start_daemons(
                &self,
                _operation: &LifecycleOperation,
            ) -> Result<Observation, Failure> {
                Ok(Observation::default())
            }
            async fn provision_minio(
                &self,
                _operation: &LifecycleOperation,
            ) -> Result<SemanticReceipt, Failure> {
                Ok(SemanticReceipt::default())
            }
            async fn inspect(
                &self,
                _binding: &LifecycleBinding,
            ) -> Result<TopologySnapshot, Failure> {
                Ok(TopologySnapshot::default())
            }
            async fn down(&self, _operation: &LifecycleOperation) -> Result<(), Failure> {
                Ok(())
            }
            async fn teardown_verified(
                &self,
                _operation: &LifecycleOperation,
            ) -> Result<(), Failure> {
                Err(Failure::unavailable(
                    "TOPOLOGY_VERIFIED_TEARDOWN_UNAVAILABLE",
                    "verified teardown is unavailable",
                ))
            }
            async fn cleanup_secrets(
                &self,
                _operation: &LifecycleOperation,
            ) -> Result<(), Failure> {
                Ok(())
            }
        }
        struct StubClock;
        impl LifecycleClock for StubClock {
            fn now(&self) -> OffsetDateTime {
                datetime!(2026-03-04 05:00:00 UTC)
            }
        }
        struct StubBootstrapAuthority;
        impl BootstrapAuthority for StubBootstrapAuthority {
            async fn adopt_b03(
                &self,
                _request: crate::domain::AdoptRequest,
            ) -> Result<(SecretBinding, BootstrapOutcome), Failure> {
                Err(Failure::internal("test", "not exercised"))
            }
            async fn materialize_dependency(
                &self,
                _request: HandoffRequest,
            ) -> Result<HandoffReceipt, Failure> {
                Err(Failure::internal("test", "not exercised"))
            }
            async fn prepare_system_generation(
                &self,
                _purpose: Purpose,
                _instance_id: &str,
            ) -> Result<SecretBinding, Failure> {
                Err(Failure::internal("test", "not exercised"))
            }
            async fn revoke_binding(
                &self,
                _binding_id: SecretBindingId,
            ) -> Result<BootstrapOutcome, Failure> {
                Ok(BootstrapOutcome::Revoked)
            }
            async fn delete_binding(
                &self,
                _binding_id: SecretBindingId,
                _fencing_token: u64,
            ) -> Result<BootstrapOutcome, Failure> {
                Ok(BootstrapOutcome::Deleted)
            }
        }
        struct StubAdvisory;
        impl AdvisoryFetch for StubAdvisory {
            async fn load_active(&self) -> Result<AdvisorySnapshot, Failure> {
                Ok(AdvisorySnapshot::default())
            }
        }
        struct StubDependencyStore;
        impl DependencyStore for StubDependencyStore {
            async fn stage_candidate(&self, candidate: Candidate) -> Result<Candidate, Failure> {
                Ok(candidate)
            }
            async fn switch_selector(
                &self,
                _candidate: &Candidate,
                _binding: &AdmissionBinding,
            ) -> Result<DependencyReceipt, Failure> {
                Ok(DependencyReceipt::default())
            }
            async fn recover(
                &self,
                _candidate_id: &str,
                _binding: &AdmissionBinding,
            ) -> Result<DependencyReceipt, Failure> {
                Ok(DependencyReceipt::default())
            }
            async fn active(&self) -> Result<Option<DependencyReceipt>, Failure> {
                Ok(None)
            }
            async fn record_operation(&self, _operation: &PrepareOperation) -> Result<(), Failure> {
                Ok(())
            }
            async fn unsettled_operation(&self) -> Result<Option<PrepareOperation>, Failure> {
                Ok(None)
            }
            async fn exact_operation(&self, _id: &str) -> Result<PrepareOperation, Failure> {
                Err(Failure::not_found("test", "none"))
            }
        }

        // `Arc<S>` satisfies every port bound via the forwarding
        // impls — the handle the kernel hands to `T: Port` generics.
        macro_rules! arc_satisfies {
            ($trait:ident, $ty:ty) => {{
                fn check<T: $trait>() {}
                check::<$ty>();
            }};
        }
        arc_satisfies!(LifecycleAdmission, Arc<StubAdmission>);
        arc_satisfies!(LifecycleCapacity, Arc<StubCapacity>);
        arc_satisfies!(LifecycleBarrier, Arc<StubBarrier>);
        arc_satisfies!(LifecycleLocker, Arc<StubLocker>);
        arc_satisfies!(DeadOwnerVerifier, Arc<StubVerifier>);
        arc_satisfies!(SnapshotReader, Arc<StubSnapshots>);
        arc_satisfies!(LifecycleBootstrap, Arc<StubBootstrap>);
        arc_satisfies!(B04Bootstrap, Arc<StubB04>);
        arc_satisfies!(LifecycleAuthority, Arc<StubAuthority>);
        arc_satisfies!(TopologyPort, Arc<StubTopology>);
        arc_satisfies!(LifecycleClock, Arc<StubClock>);
        arc_satisfies!(BootstrapAuthority, Arc<StubBootstrapAuthority>);
        arc_satisfies!(AdvisoryFetch, Arc<StubAdvisory>);
        arc_satisfies!(DependencyStore, Arc<StubDependencyStore>);

        // Exercise a few so the Arc forwarding blocks are covered.
        let verifier = Arc::new(StubVerifier);
        let proof = block_on(verifier.verify_dead_owner("lock-1", 7)).unwrap();
        assert!(proof.dead);
        let clock = Arc::new(StubClock);
        assert_eq!(clock.now(), datetime!(2026-03-04 05:00:00 UTC));
        let store = Arc::new(StubDependencyStore);
        assert!(block_on(store.active()).unwrap().is_none());
        assert!(block_on(store.exact_operation("op-9")).is_err());
    }

    /// `GenesisStatus`/`GenesisPhase` and `PrepareOperation` are the
    /// domain records the ports move — serde on `PrepareOperation`
    /// matches the upstream journal record's tagged fields.
    #[test]
    fn prepare_operation_serde_matches_upstream_record() {
        let op = PrepareOperation {
            operation_id: "op-1".to_string(),
            phase: crate::authority::PrepareOperationPhase::SelectorSwitched,
            admission_id: "adm-1".to_string(),
            selector: "minio".to_string(),
            deadline: datetime!(2026-03-04 05:20:00 UTC),
            reason: String::new(),
            reused: 2,
            acquired: 1,
            receipt_id: "rcpt-1".to_string(),
            created_at: datetime!(2026-03-04 05:00:00 UTC),
        };
        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["phase"], serde_json::json!("selector_switched"));
        assert_eq!(json["deadline"], serde_json::json!("2026-03-04T05:20:00Z"));
        assert_eq!(json["reused"], serde_json::json!(2));
        // `reason` is omitempty upstream — empty is not emitted.
        assert!(json.get("reason").is_none());
        let decoded: PrepareOperation = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, op);

        let status = GenesisStatus {
            operation_id: OperationId::new(),
            phase: GenesisPhase::Committed,
            receipt: None,
        };
        assert_eq!(status.phase, GenesisPhase::Committed);
        assert_eq!(GenesisPhase::Absent.as_str(), "absent");
    }
}
