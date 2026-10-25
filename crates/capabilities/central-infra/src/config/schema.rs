//! `central.config/v1` typed schema and semantic validation — port of
//! upstream `internal/config/schema.go`.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::is_nfc;

use central_foundation::identity::InstanceId;

use super::strict_json::{CONFIG_DOCUMENT_LIMITS, canonical_json, validate_strict_json};
use super::{Error, ErrorKind};

/// `2^53 - 1` — the maximum integer safely representable as f64.
const MAX_SAFE_INTEGER: u64 = 9007199254740991;

/// Marker returned by the safe-number gate; the public error maps it to
/// [`ErrorKind::Semantic`], matching upstream's
/// `errors.Join(errUnsafeInteger, ErrSemantic)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnsafeInteger;

/// Errors from provider quote arithmetic — returned raw (not wrapped in
/// the redacted [`Error`]), matching upstream's package-level sentinels.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteError {
    /// Unrepresentable provider quote (`config: provider quote overflow`).
    Overflow,
    /// A quote or selected spend that cannot be reserved under the
    /// signed hard provider spend limit
    /// (`config: provider quote exceeds budget`).
    ExceedsBudget,
    /// Absent authoritative quote input (`config: provider reservation
    /// input missing`).
    ReservationInputMissing,
}

impl std::fmt::Display for QuoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Overflow => "config: provider quote overflow",
            Self::ExceedsBudget => "config: provider quote exceeds budget",
            Self::ReservationInputMissing => "config: provider reservation input missing",
        })
    }
}

impl std::error::Error for QuoteError {}

/// The complete, typed `central.config/v1` document.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: String,
    pub instance_id: InstanceId,
    pub paths: PathsConfig,
    pub http: HttpConfig,
    pub postgres: PostgresConfig,
    pub object_store: ObjectStoreConfig,
    pub protected_store: ProtectedStoreConfig,
    pub bootstrap_session: BootstrapSessionConfig,
    pub artifact: ArtifactConfig,
    pub operator_modes: OperatorModesConfig,
    pub tools: ToolsConfig,
    pub runtime: RuntimeConfig,
    pub observability: ObservabilityConfig,
    pub provider: ProviderProfile,
}

/// The signed, compatibility-shaped policy projection used by the
/// current configuration schema. B09 does not use its route, provider,
/// model, or `secret_ref` fields as active Central-to-agent authority;
/// those decisions belong to the externally composed agent adapter.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProfile {
    pub provider: String,
    pub model: String,
    pub destination: String,
    pub method: String,
    pub path: String,
    pub policy_revision: String,
    pub tool_revision: String,
    pub price_data_revision: String,
    pub secret_ref: String,
    pub purpose: String,
    pub protected_paths: Vec<String>,
    pub default_budget: ProviderBudget,
    pub hard_budget: ProviderBudget,
    pub input_token_price_micros: u64,
    pub output_token_price_micros: u64,
    pub local_grant_ttl_seconds: u64,
    pub signature: String,
}

/// The bounded provider admission budget recorded in policy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBudget {
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub tool_calls_per_step: u64,
    pub tool_calls_per_run: u64,
    pub wall_time_seconds: u64,
    pub spend_micros: u64,
}

/// `providerProfileUnsigned` — the fields covered by the canonical
/// digest (signature excluded).
#[derive(Serialize)]
struct ProviderProfileUnsigned {
    provider: String,
    model: String,
    destination: String,
    method: String,
    path: String,
    policy_revision: String,
    tool_revision: String,
    price_data_revision: String,
    secret_ref: String,
    purpose: String,
    protected_paths: Vec<String>,
    default_budget: ProviderBudget,
    hard_budget: ProviderBudget,
    input_token_price_micros: u64,
    output_token_price_micros: u64,
    local_grant_ttl_seconds: u64,
}

impl ProviderProfile {
    /// Verifies the compatibility-shaped signed policy, including its
    /// canonical digest, bounded budgets, rate card, and grant lifetime.
    /// Upstream `ValidateSigned` — returns the raw [`ErrorKind`]
    /// sentinel (`config: invalid semantics`), not the redacted
    /// [`Error`] wrapper.
    pub fn validate_signed(&self) -> Result<(), ErrorKind> {
        validate_provider(self).map_err(|_| ErrorKind::Semantic)
    }

    /// Returns the checked input and output token quote for a provider
    /// profile. It does not apply spend policy; callers compare the
    /// result with a selected signed budget before reserving it.
    pub fn quote_micros(&self, input_tokens: u64, output_tokens: u64) -> Result<u64, QuoteError> {
        let input = input_tokens
            .checked_mul(self.input_token_price_micros)
            .ok_or(QuoteError::Overflow)?;
        let output = output_tokens
            .checked_mul(self.output_token_price_micros)
            .ok_or(QuoteError::Overflow)?;
        input.checked_add(output).ok_or(QuoteError::Overflow)
    }

    /// Returns the amount a turn must reserve: the higher of the checked
    /// worst-case token quote and `selected_spend`. Both are constrained
    /// by the signed hard spend budget.
    pub fn reserve_micros(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        selected_spend: u64,
    ) -> Result<u64, QuoteError> {
        let quote = self.quote_micros(input_tokens, output_tokens)?;
        if selected_spend > self.hard_budget.spend_micros || quote > self.hard_budget.spend_micros {
            return Err(QuoteError::ExceedsBudget);
        }
        Ok(selected_spend.max(quote))
    }

    /// The stable domain-separated provider-policy digest. The signature
    /// field is excluded from the unsigned JCS object. Returns an empty
    /// string only if the value cannot be encoded/canonicalized —
    /// unreachable for struct fields, kept for upstream parity.
    #[must_use]
    pub fn canonical_digest(&self) -> String {
        let unsigned = ProviderProfileUnsigned {
            provider: self.provider.clone(),
            model: self.model.clone(),
            destination: self.destination.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            policy_revision: self.policy_revision.clone(),
            tool_revision: self.tool_revision.clone(),
            price_data_revision: self.price_data_revision.clone(),
            secret_ref: self.secret_ref.clone(),
            purpose: self.purpose.clone(),
            protected_paths: self.protected_paths.clone(),
            default_budget: self.default_budget,
            hard_budget: self.hard_budget,
            input_token_price_micros: self.input_token_price_micros,
            output_token_price_micros: self.output_token_price_micros,
            local_grant_ttl_seconds: self.local_grant_ttl_seconds,
        };
        let Ok(value) = serde_json::to_value(&unsigned) else {
            return String::new();
        };
        let Ok(canonical) = central_foundation::jcs::canonicalize(&value) else {
            return String::new();
        };
        let mut hasher = Sha256::new();
        hasher.update(b"central.provider-profile/v1\x00");
        hasher.update(&canonical);
        hex_encode(&hasher.finalize())
    }
}

/// Canonical protected-binding purposes (upstream `BindingPurpose`
/// constants). The `protected_store.binding_root_id` requirement carries
/// the empty purpose — the inventory treats it as an exact
/// protected-state binding with no public token.
pub mod binding_purposes {
    pub const APPLICATION_TLS: &str = "application_tls_v1";
    pub const POSTGRES_SERVER_ADMIN: &str = "postgres_server_admin_v1";
    pub const POSTGRES_RUNTIME: &str = "postgres_runtime_v1";
    pub const POSTGRES_OUTBOX: &str = "postgres_outbox_v1";
    pub const POSTGRES_MIGRATION: &str = "postgres_migration_v1";
    pub const MINIO_ROOT: &str = "minio_root_v1";
    pub const MINIO_RUNTIME: &str = "minio_runtime_v1";
    pub const MINIO_BACKUP: &str = "minio_backup_v1";
    pub const MINIO_RESTORE: &str = "minio_restore_v1";
    pub const BOOTSTRAP: &str = "bootstrap_v1";
    /// No public purpose token (upstream `BindingPurpose("")`).
    pub const UNSPECIFIED: &str = "";
}

/// Immutable association supplied by the protected binding authority for
/// one opaque configuration binding ID. The config JSON intentionally
/// contains only `binding_id`; purpose and instance ownership are
/// authoritative metadata, not caller-controlled policy fields.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingMetadata {
    pub binding_id: String,
    pub purpose: String,
    pub instance_id: InstanceId,
}

/// An immutable lookup of protected binding metadata.
#[derive(Debug, Clone, Default)]
pub struct BindingCatalog {
    by_id: HashMap<String, BindingMetadata>,
}

impl BindingCatalog {
    /// Validates and copies authoritative binding metadata — upstream
    /// `NewBindingCatalog`.
    pub fn new(metadata: Vec<BindingMetadata>) -> Result<Self, Error> {
        let mut by_id = HashMap::with_capacity(metadata.len());
        for item in &metadata {
            if validate_binding(&item.binding_id).is_err() || item.instance_id.is_nil() {
                return Err(Error::redacted(ErrorKind::Semantic));
            }
            if by_id.contains_key(&item.binding_id) {
                return Err(Error::redacted(ErrorKind::Semantic));
            }
            by_id.insert(item.binding_id.clone(), item.clone());
        }
        Ok(Self { by_id })
    }
}

/// Validates static configuration semantics and verifies every binding
/// field against its canonical purpose and instance owner. Callers must
/// obtain the catalog from the protected binding authority.
pub fn validate_with_binding_catalog(cfg: &Config, catalog: &BindingCatalog) -> Result<(), Error> {
    if validate_config(cfg).is_err() {
        return Err(Error::redacted(ErrorKind::Semantic));
    }
    if validate_binding_catalog(cfg, catalog).is_err() {
        return Err(Error::redacted(ErrorKind::Semantic));
    }
    Ok(())
}

/// Directory layout for a central instance.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsConfig {
    pub authoritative_state_root: String,
    pub instance_data_root: String,
    pub backup_repository_root: String,
    pub workspace_roots: Vec<WorkspaceRoot>,
}

/// Associates a stable workspace root ID with a filesystem path.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRoot {
    pub root_id: String,
    pub path: String,
}

/// HTTP server configuration.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    pub application: HttpEndpointConfig,
    pub operations: HttpEndpointConfig,
    pub tls: TlsConfig,
    pub non_streaming: NonStreamingConfig,
    pub max_header_bytes: u64,
    pub max_header_value_bytes: u64,
    pub read_header_ms: u64,
    pub idle_ms: u64,
    pub graceful_shutdown_ms: u64,
}

/// A host:port pair for one HTTP endpoint.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpEndpointConfig {
    pub host: String,
    pub port: u64,
}

/// Binding and active certificate fingerprints.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub binding_id: String,
    pub ca_fingerprint_sha256: String,
    pub leaf_fingerprint_sha256: String,
}

/// Non-streaming HTTP concurrency and buffer bounds.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonStreamingConfig {
    pub active: u64,
    pub waiters: u64,
    pub admission_wait_ms: u64,
    pub api_buffer_bytes: u64,
    pub html_buffer_bytes: u64,
    pub body_read_ms: u64,
    pub response_write_ms: u64,
    pub route_total_ms: u64,
}

/// PostgreSQL connectivity, bindings, pools, and timeouts.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    pub host: String,
    pub port: u64,
    pub database: String,
    pub schema: String,
    pub bindings: PostgresBindings,
    pub pools: PostgresPools,
    pub timeouts: PostgresTimeouts,
}

/// Each protected PostgreSQL purpose binding.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresBindings {
    pub server_admin: String,
    pub runtime: String,
    pub outbox: String,
    pub migration: String,
}

/// The bounded PostgreSQL pool allocation.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresPools {
    pub runtime_general: u64,
    pub runtime_settlement: u64,
    pub outbox: u64,
    pub cleanup: u64,
    pub serve_lock_control: u64,
    pub coexisting_read_only: u64,
    pub offline_mutation: u64,
}

/// PostgreSQL operation deadlines.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresTimeouts {
    pub pool_acquire_ms: u64,
    pub statement_ms: u64,
    pub lock_ms: u64,
    pub transaction_ms: u64,
    pub idle_in_transaction_ms: u64,
    pub connection_lifetime_ms: u64,
}

/// The S3-compatible object store.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStoreConfig {
    pub scheme: String,
    pub host: String,
    pub port: u64,
    pub bucket: String,
    pub region: String,
    pub path_style: bool,
    pub bindings: ObjectStoreBindings,
    pub policy_digests: ObjectStorePolicyDigests,
}

/// Each protected object-store purpose binding.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStoreBindings {
    pub root: String,
    pub runtime: String,
    pub backup: String,
    pub restore: String,
}

/// Installed object-store policies.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStorePolicyDigests {
    pub runtime: String,
    pub backup: String,
    pub restore: String,
    #[serde(default)]
    pub import: String,
}

/// Protected key material storage selection and bounds.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedStoreConfig {
    pub backend: String,
    pub binding_root_id: String,
    pub max_secret_bytes: u64,
    pub resolve_ms: u64,
    pub candidate_cleanup_age_ms: u64,
    pub retired_cleanup_age_ms: u64,
}

/// The one-use bootstrap exchange bounds.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSessionConfig {
    pub binding_id: String,
    pub token_bits: u64,
    pub presentation_ms: u64,
    pub throttle_failures: u64,
    pub throttle_window_ms: u64,
    pub first_use_ms: u64,
    pub idle_ms: u64,
    pub absolute_ms: u64,
}

/// Bounded artifact transfers.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConfig {
    pub active_transfers: u64,
    pub waiters: u64,
    pub admission_wait_ms: u64,
    pub copy_buffer_bytes: u64,
    pub stream_idle_ms: u64,
    pub stream_total_ms: u64,
}

/// Bounded operator and backup policy values.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorModesConfig {
    pub backup_elapsed_ms: u64,
    pub restore_ticket_ms: u64,
    pub restore_elapsed_ms: u64,
    pub prepare_elapsed_ms: u64,
    pub export_elapsed_ms: u64,
    pub import_elapsed_ms: u64,
    pub maintenance_elapsed_ms: u64,
    pub browser_clear_elapsed_ms: u64,
    pub browser_profile_bytes: u64,
    pub browser_profile_inodes: u64,
    pub browser_disk_cache_bytes: u64,
    pub security_rescue_elapsed_ms: u64,
    pub inventory_workers: u64,
    pub inventory_spool_bytes_per_worker: u64,
    pub inventory_chunk_records: u64,
    pub inventory_record_bytes: u64,
    pub inventory_slice_pages: u64,
    pub inventory_slice_ms: u64,
    pub target_lock_ms: u64,
    pub migration_lock_ms: u64,
    pub total_lock_ms: u64,
    pub capacity_survival_reserve_bytes: u64,
    pub capacity_free_floor_bytes: u64,
    pub capacity_write_quantum_bytes: u64,
    pub capacity_poll_ms: u64,
    pub body_transfer_workers: u64,
    pub body_copy_buffer_bytes: u64,
    pub multipart_part_bytes: u64,
    pub body_attempts: u64,
    pub body_idle_ms: u64,
    pub body_total_ms: u64,
    pub backup_reference_database_bytes: u64,
    pub backup_reference_object_bytes: u64,
    pub backup_reference_records: u64,
    pub backup_min_throughput_bytes_per_second: u64,
    pub backup_probe_bytes: u64,
    pub backup_probe_elapsed_ms: u64,
    pub backup_probe_max_age_ms: u64,
    pub backup_admission_deadline_fraction_per_mille: u64,
}

/// One root-owned PostgreSQL utility.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolConfig {
    pub path: String,
    pub version: String,
}

/// The root-owned PostgreSQL utility set.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolsConfig {
    pub pg_dump: ToolConfig,
    pub pg_restore: ToolConfig,
}

/// Process limits and enabled-component policy.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub preflight_ms: u64,
    pub preflight_page: u64,
    pub startup_dependency_ms: u64,
    pub dependency_retry_ms: u64,
    pub retry_initial_ms: u64,
    pub retry_max_ms: u64,
    pub health_interval_ms: u64,
    pub health_timeout_ms: u64,
    pub go_memory_limit_bytes: u64,
    pub central_rss_ceiling_bytes: u64,
    pub operator_tool_rss_ceiling_bytes: u64,
    pub host_memory_reserve_bytes: u64,
    pub host_memory_headroom_bytes: u64,
    pub settlement_ms: u64,
    pub total_shutdown_ms: u64,
    pub enabled_components: Vec<String>,
}

/// The fixed safe observation policy.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    pub log_format: String,
    pub log_level: String,
    pub metric_registry: String,
}

/// Required-field table — upstream `requiredConfigFields`. `""` is the
/// document root; `paths.workspace_roots[]` applies to each array
/// element.
const REQUIRED_CONFIG_FIELDS: &[(&str, &[&str])] = &[
    (
        "",
        &[
            "schema_version",
            "instance_id",
            "paths",
            "http",
            "postgres",
            "object_store",
            "protected_store",
            "bootstrap_session",
            "artifact",
            "operator_modes",
            "tools",
            "runtime",
            "observability",
            "provider",
        ],
    ),
    (
        "paths",
        &[
            "authoritative_state_root",
            "instance_data_root",
            "backup_repository_root",
            "workspace_roots",
        ],
    ),
    ("paths.workspace_roots[]", &["root_id", "path"]),
    (
        "http",
        &[
            "application",
            "operations",
            "tls",
            "non_streaming",
            "max_header_bytes",
            "max_header_value_bytes",
            "read_header_ms",
            "idle_ms",
            "graceful_shutdown_ms",
        ],
    ),
    ("http.application", &["host", "port"]),
    ("http.operations", &["host", "port"]),
    (
        "http.tls",
        &[
            "binding_id",
            "ca_fingerprint_sha256",
            "leaf_fingerprint_sha256",
        ],
    ),
    (
        "http.non_streaming",
        &[
            "active",
            "waiters",
            "admission_wait_ms",
            "api_buffer_bytes",
            "html_buffer_bytes",
            "body_read_ms",
            "response_write_ms",
            "route_total_ms",
        ],
    ),
    (
        "postgres",
        &[
            "host", "port", "database", "schema", "bindings", "pools", "timeouts",
        ],
    ),
    (
        "postgres.bindings",
        &["server_admin", "runtime", "outbox", "migration"],
    ),
    (
        "postgres.pools",
        &[
            "runtime_general",
            "runtime_settlement",
            "outbox",
            "cleanup",
            "serve_lock_control",
            "coexisting_read_only",
            "offline_mutation",
        ],
    ),
    (
        "postgres.timeouts",
        &[
            "pool_acquire_ms",
            "statement_ms",
            "lock_ms",
            "transaction_ms",
            "idle_in_transaction_ms",
            "connection_lifetime_ms",
        ],
    ),
    (
        "object_store",
        &[
            "scheme",
            "host",
            "port",
            "bucket",
            "region",
            "path_style",
            "bindings",
            "policy_digests",
        ],
    ),
    (
        "object_store.bindings",
        &["root", "runtime", "backup", "restore"],
    ),
    (
        "object_store.policy_digests",
        &["runtime", "backup", "restore"],
    ),
    (
        "protected_store",
        &[
            "backend",
            "binding_root_id",
            "max_secret_bytes",
            "resolve_ms",
            "candidate_cleanup_age_ms",
            "retired_cleanup_age_ms",
        ],
    ),
    (
        "bootstrap_session",
        &[
            "binding_id",
            "token_bits",
            "presentation_ms",
            "throttle_failures",
            "throttle_window_ms",
            "first_use_ms",
            "idle_ms",
            "absolute_ms",
        ],
    ),
    (
        "artifact",
        &[
            "active_transfers",
            "waiters",
            "admission_wait_ms",
            "copy_buffer_bytes",
            "stream_idle_ms",
            "stream_total_ms",
        ],
    ),
    (
        "operator_modes",
        &[
            "backup_elapsed_ms",
            "restore_ticket_ms",
            "restore_elapsed_ms",
            "prepare_elapsed_ms",
            "export_elapsed_ms",
            "import_elapsed_ms",
            "maintenance_elapsed_ms",
            "browser_clear_elapsed_ms",
            "browser_profile_bytes",
            "browser_profile_inodes",
            "browser_disk_cache_bytes",
            "security_rescue_elapsed_ms",
            "inventory_workers",
            "inventory_spool_bytes_per_worker",
            "inventory_chunk_records",
            "inventory_record_bytes",
            "inventory_slice_pages",
            "inventory_slice_ms",
            "target_lock_ms",
            "migration_lock_ms",
            "total_lock_ms",
            "capacity_survival_reserve_bytes",
            "capacity_free_floor_bytes",
            "capacity_write_quantum_bytes",
            "capacity_poll_ms",
            "body_transfer_workers",
            "body_copy_buffer_bytes",
            "multipart_part_bytes",
            "body_attempts",
            "body_idle_ms",
            "body_total_ms",
            "backup_reference_database_bytes",
            "backup_reference_object_bytes",
            "backup_reference_records",
            "backup_min_throughput_bytes_per_second",
            "backup_probe_bytes",
            "backup_probe_elapsed_ms",
            "backup_probe_max_age_ms",
            "backup_admission_deadline_fraction_per_mille",
        ],
    ),
    ("tools", &["pg_dump", "pg_restore"]),
    ("tools.pg_dump", &["path", "version"]),
    ("tools.pg_restore", &["path", "version"]),
    (
        "runtime",
        &[
            "preflight_ms",
            "preflight_page",
            "startup_dependency_ms",
            "dependency_retry_ms",
            "retry_initial_ms",
            "retry_max_ms",
            "health_interval_ms",
            "health_timeout_ms",
            "go_memory_limit_bytes",
            "central_rss_ceiling_bytes",
            "operator_tool_rss_ceiling_bytes",
            "host_memory_reserve_bytes",
            "host_memory_headroom_bytes",
            "settlement_ms",
            "total_shutdown_ms",
            "enabled_components",
        ],
    ),
    (
        "observability",
        &["log_format", "log_level", "metric_registry"],
    ),
    (
        "provider",
        &[
            "provider",
            "model",
            "destination",
            "method",
            "path",
            "policy_revision",
            "tool_revision",
            "price_data_revision",
            "secret_ref",
            "purpose",
            "protected_paths",
            "default_budget",
            "hard_budget",
            "input_token_price_micros",
            "output_token_price_micros",
            "local_grant_ttl_seconds",
            "signature",
        ],
    ),
    (
        "provider.default_budget",
        &[
            "request_bytes",
            "response_bytes",
            "input_tokens",
            "output_tokens",
            "tool_calls_per_step",
            "tool_calls_per_run",
            "wall_time_seconds",
            "spend_micros",
        ],
    ),
    (
        "provider.hard_budget",
        &[
            "request_bytes",
            "response_bytes",
            "input_tokens",
            "output_tokens",
            "tool_calls_per_step",
            "tool_calls_per_run",
            "wall_time_seconds",
            "spend_micros",
        ],
    ),
];

/// Upstream `Parse`: strict-JSON gate, canonical-form gate, then the
/// presence/semantic/typed pipeline. Returns the redacted [`Error`].
pub fn parse(data: &[u8]) -> Result<Config, Error> {
    if let Err(kind) = validate_strict_json(data, CONFIG_DOCUMENT_LIMITS) {
        return Err(Error::redacted(kind));
    }
    if let Err(kind) = canonical_json(data) {
        return Err(Error::redacted(kind));
    }
    parse_validated_canonical(data)
}

/// Parses a canonical configuration and verifies its opaque binding
/// references against authoritative purpose and instance metadata before
/// returning it — upstream `ParseWithBindingCatalog`.
pub fn parse_with_binding_catalog(data: &[u8], catalog: &BindingCatalog) -> Result<Config, Error> {
    let cfg = parse(data)?;
    validate_with_binding_catalog(&cfg, catalog)?;
    Ok(cfg)
}

/// Semantic validation of a parsed [`Config`]. Always returns the
/// redacted public [`Error`] for invalid input.
pub fn validate(cfg: &Config) -> Result<(), Error> {
    validate_config(cfg).map_err(|_| Error::redacted(ErrorKind::Semantic))
}

/// Upstream `parseValidatedCanonical`.
pub(crate) fn parse_validated_canonical(raw: &[u8]) -> Result<Config, Error> {
    let document: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| Error::redacted(ErrorKind::Schema))?;
    if require_config_presence(&document).is_err() {
        return Err(Error::redacted(ErrorKind::Schema));
    }
    if require_canonical_instance_id(&document).is_err() {
        return Err(Error::redacted(ErrorKind::Semantic));
    }
    if validate_safe_numbers(&document).is_err() {
        return Err(Error::redacted(ErrorKind::Semantic));
    }
    let cfg: Config =
        serde_json::from_value(document).map_err(|_| Error::redacted(ErrorKind::Schema))?;
    if validate_config(&cfg).is_err() {
        return Err(Error::redacted(ErrorKind::Semantic));
    }
    Ok(cfg)
}

/// Upstream `requireConfigPresence`: every required field present and
/// non-null at every level, including each workspace-roots element.
fn require_config_presence(document: &serde_json::Value) -> Result<(), ()> {
    let Some(root) = document.as_object() else {
        return Err(());
    };
    for &(path, fields) in REQUIRED_CONFIG_FIELDS {
        if path == "paths.workspace_roots[]" {
            continue;
        }
        if path.is_empty() {
            for &field in fields {
                match root.get(field) {
                    Some(value) if !value.is_null() => {}
                    _ => return Err(()),
                }
            }
            continue;
        }
        let Some(object) = lookup_object_field(document, path).and_then(|v| v.as_object()) else {
            return Err(());
        };
        for &field in fields {
            match object.get(field) {
                Some(value) if !value.is_null() => {}
                _ => return Err(()),
            }
        }
    }
    let Some(roots) =
        lookup_object_field(document, "paths.workspace_roots").and_then(|v| v.as_array())
    else {
        return Err(());
    };
    let element_fields = REQUIRED_CONFIG_FIELDS
        .iter()
        .find(|(path, _)| *path == "paths.workspace_roots[]")
        .map(|(_, fields)| *fields)
        .unwrap_or(&[]);
    for root_element in roots {
        let Some(object) = root_element.as_object() else {
            return Err(());
        };
        for &field in element_fields {
            match object.get(field) {
                Some(value) if !value.is_null() => {}
                _ => return Err(()),
            }
        }
    }
    Ok(())
}

/// Upstream `requireCanonicalInstanceID`: present, a string, and a
/// canonical UUIDv7.
fn require_canonical_instance_id(document: &serde_json::Value) -> Result<(), ()> {
    let Some(object) = document.as_object() else {
        return Err(());
    };
    let Some(value) = object.get("instance_id") else {
        return Err(());
    };
    if value.is_null() {
        return Err(());
    }
    match value.as_str() {
        Some(text) if InstanceId::parse(text).is_ok() => Ok(()),
        _ => Err(()),
    }
}

/// Upstream `lookupObjectField`: navigate a dotted path through JSON
/// objects; every intermediate must be an object.
fn lookup_object_field<'a>(
    document: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = document;
    for part in path.split('.') {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

/// Upstream `validateSafeNumbers`: every JSON number must parse as a
/// `u64` no larger than `2^53 - 1`.
pub(crate) fn validate_safe_numbers(document: &serde_json::Value) -> Result<(), UnsafeInteger> {
    match document {
        serde_json::Value::Number(n) => match n.as_u64() {
            Some(v) if v <= MAX_SAFE_INTEGER => Ok(()),
            _ => Err(UnsafeInteger),
        },
        serde_json::Value::Array(items) => {
            for item in items {
                validate_safe_numbers(item)?;
            }
            Ok(())
        }
        serde_json::Value::Object(members) => {
            for item in members.values() {
                validate_safe_numbers(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Upstream `validateConfig`.
fn validate_config(cfg: &Config) -> Result<(), ()> {
    if cfg.schema_version != "central.config/v1" || cfg.instance_id.is_nil() {
        return Err(());
    }
    validate_paths(cfg)?;
    validate_http(cfg)?;
    validate_postgres(cfg)?;
    validate_object_store(cfg)?;
    validate_protected_and_bootstrap(cfg)?;
    validate_artifact_and_operator(cfg)?;
    validate_tools_runtime_observability(cfg)?;
    validate_binding_uniqueness(cfg)?;
    validate_provider(&cfg.provider)?;
    Ok(())
}

fn validate_paths(cfg: &Config) -> Result<(), ()> {
    let paths = [
        cfg.paths.authoritative_state_root.as_str(),
        cfg.paths.instance_data_root.as_str(),
        cfg.paths.backup_repository_root.as_str(),
    ];
    for path in paths {
        validate_absolute_path(path)?;
    }
    if cfg.paths.instance_data_root != format!("{}/data", cfg.paths.authoritative_state_root)
        || cfg.paths.backup_repository_root
            != format!("{}/backups", cfg.paths.authoritative_state_root)
    {
        return Err(());
    }
    if cfg.paths.workspace_roots.len() > 32 {
        return Err(());
    }
    let mut previous_id = "";
    for (i, root) in cfg.paths.workspace_roots.iter().enumerate() {
        validate_uuid7(&root.root_id)?;
        if i > 0 && root.root_id.as_str() <= previous_id {
            return Err(());
        }
        previous_id = &root.root_id;
        validate_absolute_path(&root.path)?;
        for reserved in paths {
            if paths_overlap(&root.path, reserved) {
                return Err(());
            }
        }
        for prior in &cfg.paths.workspace_roots[..i] {
            if paths_overlap(&root.path, &prior.path) {
                return Err(());
            }
        }
    }
    Ok(())
}

fn validate_http(cfg: &Config) -> Result<(), ()> {
    validate_loopback_endpoint(&cfg.http.application, 1024, 65535)?;
    validate_loopback_endpoint(&cfg.http.operations, 1024, 65535)?;
    if cfg.http.application.port == cfg.http.operations.port
        || cfg.http.application.port == cfg.postgres.port
        || cfg.http.application.port == cfg.object_store.port
        || cfg.http.operations.port == cfg.postgres.port
        || cfg.http.operations.port == cfg.object_store.port
        || cfg.postgres.port == cfg.object_store.port
    {
        return Err(());
    }
    validate_binding(&cfg.http.tls.binding_id)?;
    validate_fingerprint(&cfg.http.tls.ca_fingerprint_sha256)?;
    validate_fingerprint(&cfg.http.tls.leaf_fingerprint_sha256)?;
    let n = &cfg.http.non_streaming;
    if n.active < 1
        || n.active > 32
        || n.waiters > 64
        || n.admission_wait_ms < 1
        || n.admission_wait_ms > 5000
        || n.api_buffer_bytes != 2097152
        || n.html_buffer_bytes < 1
        || n.html_buffer_bytes > 2097152
        || n.body_read_ms < 1000
        || n.body_read_ms > 120000
        || n.response_write_ms < 1000
        || n.response_write_ms > 120000
        || n.route_total_ms < 1000
        || n.route_total_ms > 120000
        || n.route_total_ms < n.admission_wait_ms + n.body_read_ms + n.response_write_ms
        || n.active * n.api_buffer_bytes > 32 * 1024 * 1024
        || n.active * (n.api_buffer_bytes + n.html_buffer_bytes) > 64 * 1024 * 1024
    {
        return Err(());
    }
    if cfg.http.max_header_bytes < 4096
        || cfg.http.max_header_bytes > 65536
        || cfg.http.max_header_value_bytes != 4096
        || cfg.http.max_header_value_bytes > cfg.http.max_header_bytes
        || cfg.http.read_header_ms < 1000
        || cfg.http.read_header_ms > 10000
        || cfg.http.idle_ms < 1000
        || cfg.http.idle_ms > 120000
        || cfg.http.graceful_shutdown_ms < 30000
        || cfg.http.graceful_shutdown_ms > 180000
    {
        return Err(());
    }
    Ok(())
}

fn validate_loopback_endpoint(endpoint: &HttpEndpointConfig, min: u64, max: u64) -> Result<(), ()> {
    if endpoint.host != "127.0.0.1" || endpoint.port < min || endpoint.port > max {
        return Err(());
    }
    Ok(())
}

fn validate_postgres(cfg: &Config) -> Result<(), ()> {
    let p = &cfg.postgres;
    if p.host != "127.0.0.1"
        || p.port < 1024
        || p.port > 65535
        || p.database != "central"
        || p.schema != "central"
    {
        return Err(());
    }
    for binding in [
        &p.bindings.server_admin,
        &p.bindings.runtime,
        &p.bindings.outbox,
        &p.bindings.migration,
    ] {
        validate_binding(binding)?;
    }
    let pool = &p.pools;
    if pool.runtime_general < 1
        || pool.runtime_general > 8
        || pool.runtime_settlement != 2
        || pool.outbox < 1
        || pool.outbox > 4
        || pool.cleanup < 1
        || pool.cleanup > 2
        || pool.serve_lock_control != 1
        || pool.coexisting_read_only > 4
        || pool.offline_mutation != 2
        || pool.runtime_general + pool.runtime_settlement + pool.outbox + pool.cleanup != 12
        || pool.runtime_general
            + pool.runtime_settlement
            + pool.outbox
            + pool.cleanup
            + pool.serve_lock_control
            + pool.coexisting_read_only
            > 16
    {
        return Err(());
    }
    let t = &p.timeouts;
    if t.pool_acquire_ms < 1
        || t.pool_acquire_ms > 5000
        || t.statement_ms < 1000
        || t.statement_ms > 120000
        || t.lock_ms < 100
        || t.lock_ms > 30000
        || t.lock_ms > t.statement_ms
        || t.transaction_ms < 1000
        || t.transaction_ms > 120000
        || t.transaction_ms < t.statement_ms
        || t.idle_in_transaction_ms < 1000
        || t.idle_in_transaction_ms > 60000
        || t.connection_lifetime_ms < 60000
        || t.connection_lifetime_ms > 3600000
    {
        return Err(());
    }
    Ok(())
}

fn validate_object_store(cfg: &Config) -> Result<(), ()> {
    let o = &cfg.object_store;
    if o.scheme != "http"
        || o.host != "127.0.0.1"
        || o.port < 1024
        || o.port > 65535
        || o.bucket != "central-artifacts-v1"
        || o.region != "us-east-1"
        || !o.path_style
    {
        return Err(());
    }
    for binding in [
        &o.bindings.root,
        &o.bindings.runtime,
        &o.bindings.backup,
        &o.bindings.restore,
    ] {
        validate_binding(binding)?;
    }
    for digest in [
        &o.policy_digests.runtime,
        &o.policy_digests.backup,
        &o.policy_digests.restore,
        &o.policy_digests.import,
    ] {
        validate_fingerprint(digest)?;
    }
    if o.policy_digests.runtime
        != "b4613cce4c0fe3e7b23cc7212d578919169cb1d64aab9c5b73fc544cf759d72f"
        || o.policy_digests.backup
            != "aa5f63fdf5b13e4bc2effd1a972a7c2ed6771faee3b56bc2fca7d822ad7d38b1"
        || o.policy_digests.restore
            != "79ec56cee096807d98ca968500e2b5bd16ac948c008a2c83ab5cbfc5e338e6dc"
    {
        return Err(());
    }
    Ok(())
}

fn validate_protected_and_bootstrap(cfg: &Config) -> Result<(), ()> {
    let p = &cfg.protected_store;
    if p.backend != "protected_file_v1"
        || validate_binding(&p.binding_root_id).is_err()
        || p.max_secret_bytes != 65536
        || p.resolve_ms < 1
        || p.resolve_ms > 10000
        || p.candidate_cleanup_age_ms < 3600000
        || p.candidate_cleanup_age_ms > 604800000
        || p.retired_cleanup_age_ms < 86400000
        || p.retired_cleanup_age_ms > 2592000000
        || p.retired_cleanup_age_ms <= p.candidate_cleanup_age_ms
    {
        return Err(());
    }
    let b = &cfg.bootstrap_session;
    if validate_binding(&b.binding_id).is_err()
        || b.token_bits != 256
        || b.presentation_ms < 60000
        || b.presentation_ms > 300000
        || b.throttle_failures < 3
        || b.throttle_failures > 10
        || b.throttle_window_ms < 10000
        || b.throttle_window_ms > 300000
        || b.first_use_ms < 1000
        || b.first_use_ms > 300000
        || b.idle_ms < 60000
        || b.idle_ms > 1800000
        || b.absolute_ms < 1800000
        || b.absolute_ms > 43200000
        || b.absolute_ms <= b.idle_ms
        || b.throttle_window_ms > b.first_use_ms
    {
        return Err(());
    }
    Ok(())
}

fn validate_artifact_and_operator(cfg: &Config) -> Result<(), ()> {
    let a = &cfg.artifact;
    if a.active_transfers < 1
        || a.active_transfers > 8
        || a.waiters > 32
        || a.admission_wait_ms < 1
        || a.admission_wait_ms > 30000
        || a.copy_buffer_bytes < 65536
        || a.copy_buffer_bytes > 1048576
        || a.stream_idle_ms < 1000
        || a.stream_idle_ms > 120000
        || a.stream_total_ms < 60000
        || a.stream_total_ms > 7200000
        || a.stream_total_ms <= a.stream_idle_ms
        || a.admission_wait_ms > a.stream_total_ms
        || a.active_transfers > 8388608 / a.copy_buffer_bytes
    {
        return Err(());
    }
    let o = &cfg.operator_modes;
    if o.backup_elapsed_ms < 60000
        || o.backup_elapsed_ms > 28800000
        || o.restore_ticket_ms < 60000
        || o.restore_ticket_ms > 3600000
        || o.restore_elapsed_ms != 14400000
        || o.prepare_elapsed_ms != 1200000
        || o.export_elapsed_ms != 7200000
        || o.import_elapsed_ms != 7200000
        || o.maintenance_elapsed_ms != 7200000
        || o.browser_clear_elapsed_ms != 300000
        || o.browser_profile_bytes != 1073741824
        || o.browser_profile_inodes != 50000
        || o.browser_disk_cache_bytes != 268435456
        || o.security_rescue_elapsed_ms != 14400000
        || o.inventory_workers < 1
        || o.inventory_workers > 2
        || o.inventory_spool_bytes_per_worker != 8388608
        || o.inventory_chunk_records < 1
        || o.inventory_chunk_records > 1000
        || o.inventory_record_bytes != 4096
        || o.inventory_slice_pages < 1
        || o.inventory_slice_pages > 1000
        || o.inventory_slice_ms < 1000
        || o.inventory_slice_ms > 1800000
        || o.target_lock_ms < 1
        || o.target_lock_ms > 300000
        || o.migration_lock_ms < 1
        || o.migration_lock_ms > 60000
        || o.total_lock_ms < 1
        || o.total_lock_ms > 360000
        || o.total_lock_ms < o.target_lock_ms
        || o.total_lock_ms < o.migration_lock_ms
        || o.capacity_survival_reserve_bytes != 4294967296
        || o.capacity_free_floor_bytes != 1073741824
        || o.capacity_write_quantum_bytes != 8388608
        || o.capacity_poll_ms != 1000
        || o.body_transfer_workers != 1
        || o.body_copy_buffer_bytes != 262144
        || o.multipart_part_bytes != 16777216
        || o.body_attempts != 3
        || o.body_idle_ms < 1000
        || o.body_idle_ms > 120000
        || o.body_total_ms < 60000
        || o.body_total_ms > 7200000
        || o.body_total_ms <= o.body_idle_ms
        || o.backup_reference_database_bytes != 5368709120
        || o.backup_reference_object_bytes != 10737418240
        || o.backup_reference_records != 10000
        || o.backup_min_throughput_bytes_per_second != 16777216
        || o.backup_probe_bytes != 536870912
        || o.backup_probe_elapsed_ms != 300000
        || o.backup_probe_max_age_ms != 604800000
        || o.backup_admission_deadline_fraction_per_mille != 750
        || o.inventory_workers > 16777216 / o.inventory_spool_bytes_per_worker
        || o.body_total_ms > o.backup_elapsed_ms
    {
        return Err(());
    }
    if o.backup_probe_elapsed_ms > o.backup_elapsed_ms
        || o.backup_probe_elapsed_ms * 1000
            > o.backup_elapsed_ms * o.backup_admission_deadline_fraction_per_mille
    {
        return Err(());
    }
    if cfg.paths.workspace_roots.len() > 32 {
        return Err(());
    }
    Ok(())
}

fn validate_tools_runtime_observability(cfg: &Config) -> Result<(), ()> {
    validate_tool(&cfg.tools.pg_dump)?;
    validate_tool(&cfg.tools.pg_restore)?;
    let r = &cfg.runtime;
    if r.preflight_ms < 1
        || r.preflight_ms > 10000
        || r.preflight_page < 1
        || r.preflight_page > 1000
        || r.startup_dependency_ms < 1000
        || r.startup_dependency_ms > 60000
        || r.dependency_retry_ms > 300000
        || r.retry_initial_ms != 250
        || r.retry_max_ms < 250
        || r.retry_max_ms > 10000
        || r.retry_initial_ms > r.retry_max_ms
        || r.health_interval_ms < 1000
        || r.health_interval_ms > 30000
        || r.health_timeout_ms < 100
        || r.health_timeout_ms > 5000
        || r.health_timeout_ms >= r.health_interval_ms
        || r.go_memory_limit_bytes != 671088640
        || r.central_rss_ceiling_bytes != 805306368
        || r.operator_tool_rss_ceiling_bytes != 536870912
        || r.host_memory_reserve_bytes != 2147483648
        || r.host_memory_headroom_bytes != 536870912
        || r.settlement_ms < 1000
        || r.settlement_ms > 120000
        || r.total_shutdown_ms < 30000
        || r.total_shutdown_ms > 180000
        || r.total_shutdown_ms < r.settlement_ms
        || r.total_shutdown_ms != cfg.http.graceful_shutdown_ms
    {
        return Err(());
    }
    const WANT_COMPONENTS: &[&str] = &[
        "artifact_reconciliation",
        "cleanup",
        "execution",
        "http",
        "outbox",
        "session_recovery",
        "task_reconciliation",
    ];
    if !equal_strings(&r.enabled_components, WANT_COMPONENTS)
        || r.go_memory_limit_bytes
            + r.central_rss_ceiling_bytes
            + r.operator_tool_rss_ceiling_bytes
            + r.host_memory_reserve_bytes
            + r.host_memory_headroom_bytes
            > 8 * 1024 * 1024 * 1024
    {
        return Err(());
    }
    if cfg.observability.log_format != "json"
        || cfg.observability.log_level != "info"
        || cfg.observability.metric_registry != "central_custom_v1"
    {
        return Err(());
    }
    Ok(())
}

fn validate_tool(tool: &ToolConfig) -> Result<(), ()> {
    validate_absolute_path(&tool.path)?;
    if tool.version != "16.14" {
        return Err(());
    }
    Ok(())
}

fn validate_provider(p: &ProviderProfile) -> Result<(), ()> {
    if p.provider.trim().is_empty()
        || p.model.trim().is_empty()
        || p.destination.trim().is_empty()
        || p.method.trim().is_empty()
        || p.path.trim().is_empty()
        || p.policy_revision.is_empty()
        || p.tool_revision.is_empty()
        || p.price_data_revision.is_empty()
        || p.signature.is_empty()
        || p.signature != p.signature.to_lowercase()
        || p.signature != p.canonical_digest()
    {
        return Err(());
    }
    validate_protected_paths(&p.protected_paths)?;
    validate_provider_budget(&p.default_budget)?;
    validate_provider_budget(&p.hard_budget)?;
    if p.hard_budget.request_bytes < p.default_budget.request_bytes
        || p.hard_budget.response_bytes < p.default_budget.response_bytes
        || p.hard_budget.input_tokens < p.default_budget.input_tokens
        || p.hard_budget.output_tokens < p.default_budget.output_tokens
        || p.hard_budget.tool_calls_per_step < p.default_budget.tool_calls_per_step
        || p.hard_budget.tool_calls_per_run < p.default_budget.tool_calls_per_run
        || p.hard_budget.wall_time_seconds < p.default_budget.wall_time_seconds
        || p.hard_budget.spend_micros < p.default_budget.spend_micros
        || p.input_token_price_micros == 0
        || p.input_token_price_micros > 1_000_000
        || p.output_token_price_micros == 0
        || p.output_token_price_micros > 1_000_000
        || p.local_grant_ttl_seconds == 0
        || p.local_grant_ttl_seconds > 86_400
    {
        return Err(());
    }
    match p.quote_micros(p.hard_budget.input_tokens, p.hard_budget.output_tokens) {
        Ok(quote) if quote <= p.hard_budget.spend_micros => Ok(()),
        _ => Err(()),
    }
}

fn validate_provider_budget(b: &ProviderBudget) -> Result<(), ()> {
    if b.request_bytes == 0
        || b.request_bytes > 4 << 20
        || b.response_bytes == 0
        || b.response_bytes > 8 << 20
        || b.input_tokens == 0
        || b.input_tokens > 2_000_000
        || b.output_tokens == 0
        || b.output_tokens > 200_000
        || b.tool_calls_per_step == 0
        || b.tool_calls_per_step > 20
        || b.tool_calls_per_run == 0
        || b.tool_calls_per_run > 100
        || b.tool_calls_per_run < b.tool_calls_per_step
        || b.wall_time_seconds == 0
        || b.wall_time_seconds > 86_400
        || b.spend_micros == 0
        || b.spend_micros > 25_000_000
    {
        return Err(());
    }
    Ok(())
}

fn validate_binding_uniqueness(cfg: &Config) -> Result<(), ()> {
    let bindings = [
        &cfg.http.tls.binding_id,
        &cfg.postgres.bindings.server_admin,
        &cfg.postgres.bindings.runtime,
        &cfg.postgres.bindings.outbox,
        &cfg.postgres.bindings.migration,
        &cfg.object_store.bindings.root,
        &cfg.object_store.bindings.runtime,
        &cfg.object_store.bindings.backup,
        &cfg.object_store.bindings.restore,
        &cfg.protected_store.binding_root_id,
        &cfg.bootstrap_session.binding_id,
    ];
    let mut seen: HashSet<&str> = HashSet::with_capacity(bindings.len());
    let instance_id = cfg.instance_id.to_string();
    for binding in bindings {
        if *binding == instance_id {
            return Err(());
        }
        if !seen.insert(binding.as_str()) {
            return Err(());
        }
    }
    Ok(())
}

struct BindingRequirement {
    #[allow(dead_code)]
    field: &'static str,
    id: String,
    purpose: &'static str,
}

fn binding_requirements(cfg: &Config) -> Vec<BindingRequirement> {
    use binding_purposes::*;
    vec![
        BindingRequirement {
            field: "http.tls.binding_id",
            id: cfg.http.tls.binding_id.clone(),
            purpose: APPLICATION_TLS,
        },
        BindingRequirement {
            field: "postgres.bindings.server_admin",
            id: cfg.postgres.bindings.server_admin.clone(),
            purpose: POSTGRES_SERVER_ADMIN,
        },
        BindingRequirement {
            field: "postgres.bindings.runtime",
            id: cfg.postgres.bindings.runtime.clone(),
            purpose: POSTGRES_RUNTIME,
        },
        BindingRequirement {
            field: "postgres.bindings.outbox",
            id: cfg.postgres.bindings.outbox.clone(),
            purpose: POSTGRES_OUTBOX,
        },
        BindingRequirement {
            field: "postgres.bindings.migration",
            id: cfg.postgres.bindings.migration.clone(),
            purpose: POSTGRES_MIGRATION,
        },
        BindingRequirement {
            field: "object_store.bindings.root",
            id: cfg.object_store.bindings.root.clone(),
            purpose: MINIO_ROOT,
        },
        BindingRequirement {
            field: "object_store.bindings.runtime",
            id: cfg.object_store.bindings.runtime.clone(),
            purpose: MINIO_RUNTIME,
        },
        BindingRequirement {
            field: "object_store.bindings.backup",
            id: cfg.object_store.bindings.backup.clone(),
            purpose: MINIO_BACKUP,
        },
        BindingRequirement {
            field: "object_store.bindings.restore",
            id: cfg.object_store.bindings.restore.clone(),
            purpose: MINIO_RESTORE,
        },
        // The canonical inventory calls this an exact protected-state
        // binding but assigns no public purpose token; its association is
        // still checked by field identity and instance owner.
        BindingRequirement {
            field: "protected_store.binding_root_id",
            id: cfg.protected_store.binding_root_id.clone(),
            purpose: UNSPECIFIED,
        },
        BindingRequirement {
            field: "bootstrap_session.binding_id",
            id: cfg.bootstrap_session.binding_id.clone(),
            purpose: BOOTSTRAP,
        },
    ]
}

fn validate_binding_catalog(cfg: &Config, catalog: &BindingCatalog) -> Result<(), ()> {
    let requirements = binding_requirements(cfg);
    if catalog.by_id.len() != requirements.len() {
        return Err(());
    }
    for requirement in requirements {
        let metadata = catalog.by_id.get(&requirement.id).ok_or(())?;
        if metadata.binding_id != requirement.id
            || metadata.instance_id != cfg.instance_id
            || metadata.purpose != requirement.purpose
        {
            return Err(());
        }
    }
    Ok(())
}

fn validate_protected_paths(paths: &[String]) -> Result<(), ()> {
    if !paths.windows(2).all(|w| w[0] <= w[1]) {
        return Err(());
    }
    for (i, path) in paths.iter().enumerate() {
        validate_protected_path(path)?;
        if i > 0 && paths[i - 1] == *path {
            return Err(());
        }
        for prior in &paths[..i] {
            if protected_paths_overlap(path, prior) {
                return Err(());
            }
        }
    }
    Ok(())
}

/// Validates one provider policy entry. Absolute entries name host
/// paths; relative entries are either one segment matched at every
/// Workspace depth or a rooted Workspace-relative path. The value is
/// required to already be in canonical form because the provider digest
/// covers the exact string and the Workspace adapter must not
/// reinterpret aliases.
fn validate_protected_path(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.contains('\0')
        || value.contains('\n')
        || !is_nfc(value)
        || value != value.trim()
    {
        return Err(());
    }
    if value.starts_with('/') {
        return validate_absolute_path(value);
    }
    if value.len() > 4096
        || value == "."
        || value == ".."
        || value.ends_with('/')
        || path_clean(value) != value
        || value.to_lowercase() != value
    {
        return Err(());
    }
    for component in value.split('/') {
        if component.is_empty() || component == "." || component == ".." || component.len() > 255 {
            return Err(());
        }
    }
    Ok(())
}

fn protected_paths_overlap(a: &str, b: &str) -> bool {
    let a_absolute = a.starts_with('/');
    let b_absolute = b.starts_with('/');
    if a_absolute || b_absolute {
        return a_absolute && b_absolute && paths_overlap(a, b);
    }
    let a_components: Vec<&str> = a.split('/').collect();
    let b_components: Vec<&str> = b.split('/').collect();
    if a_components.len() == 1 || b_components.len() == 1 {
        let (segment, other) = if a_components.len() == 1 {
            (a_components[0], &b_components)
        } else {
            (b_components[0], &a_components)
        };
        return other.contains(&segment);
    }
    let (a_components, b_components) = if a_components.len() > b_components.len() {
        (b_components, a_components)
    } else {
        (a_components, b_components)
    };
    a_components
        .iter()
        .zip(b_components.iter())
        .all(|(x, y)| x == y)
}

fn validate_absolute_path(path: &str) -> Result<(), ()> {
    if path.is_empty()
        || !is_nfc(path)
        || !path.starts_with('/')
        || path.contains("//")
        || (path != "/" && path.ends_with('/'))
    {
        return Err(());
    }
    if path == "/" {
        return Ok(());
    }
    for component in path[1..].split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(());
        }
    }
    Ok(())
}

fn paths_overlap(a: &str, b: &str) -> bool {
    a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/"))
}

fn validate_binding(value: &str) -> Result<(), ()> {
    validate_uuid7(value)
}

fn validate_uuid7(value: &str) -> Result<(), ()> {
    // `InstanceId::parse` enforces canonical lowercase text, version 7,
    // RFC 9562 variant, and non-nil — upstream `validateUUID7` including
    // the `u.String() == value` canonicality check.
    InstanceId::parse(value).map(|_| ()).map_err(|_| ())
}

pub(crate) fn validate_fingerprint(value: &str) -> Result<(), ()> {
    if value.len() != 64 || value != value.to_lowercase() {
        return Err(());
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    Ok(())
}

fn equal_strings(got: &[String], want: &[&str]) -> bool {
    got.len() == want.len()
        && got.windows(2).all(|w| w[0] <= w[1])
        && got
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\0")
            == want.join("\0")
}

/// Go `path.Clean` (POSIX semantics) — used by the relative protected
/// path canonicality check and by `defaults` state-root validation.
pub(crate) fn path_clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let rooted = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if stack.last().is_some_and(|&top| top != "..") {
                    stack.pop();
                } else if !rooted {
                    stack.push("..");
                }
            }
            c => stack.push(c),
        }
    }
    let mut out = String::new();
    if rooted {
        out.push('/');
    }
    out.push_str(&stack.join("/"));
    if out.is_empty() {
        out.push('.');
    }
    out
}

/// Lowercase hex encoding of a digest — shared by the provider-profile
/// digest and view key IDs.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    //! Port of upstream `safe_number_gate_test.go` — the internal gate
    //! coverage over `validateSafeNumbers`.

    use super::*;
    use crate::config::testutil::{
        COMPLETE_CONFIG_FIXTURE, canonical, numeric_field_paths_for_gate,
    };

    /// Upstream `replaceNumberFieldForGate` — sets one numeric leaf to a
    /// raw literal and re-marshals (no canonicalization; the gate runs
    /// before that check anyway).
    fn replace_number_field(raw: &[u8], path: &str, value: &str) -> Vec<u8> {
        let mut document: serde_json::Value = serde_json::from_slice(raw).expect("decode fixture");
        let parts: Vec<&str> = path.split('.').collect();
        set_number(&mut document, &parts, value);
        serde_json::to_vec(&document).expect("marshal document")
    }

    fn set_number(node: &mut serde_json::Value, parts: &[&str], value: &str) {
        if parts.len() == 1 {
            let object = node.as_object_mut().expect("number parent object");
            object.insert(
                parts[0].to_owned(),
                serde_json::json!(value.parse::<u64>().expect("u64 literal")),
            );
            return;
        }
        let child = node.get_mut(parts[0]).expect("missing nested object");
        set_number(child, &parts[1..], value);
    }

    #[test]
    fn safe_number_gate_covers_every_numeric_field() {
        let raw = canonical(COMPLETE_CONFIG_FIXTURE);
        for path in numeric_field_paths_for_gate() {
            let maximum = replace_number_field(&raw, &path, "9007199254740991");
            let document: serde_json::Value =
                serde_json::from_slice(&maximum).expect("decode maximum");
            assert!(
                validate_safe_numbers(&document).is_ok(),
                "maximum safe integer rejected by gate at {path}"
            );

            let too_large = replace_number_field(&raw, &path, "9007199254740992");
            let document: serde_json::Value =
                serde_json::from_slice(&too_large).expect("decode tooLarge");
            assert!(
                matches!(validate_safe_numbers(&document), Err(UnsafeInteger)),
                "2^53 gate accepted {path}"
            );
        }
    }
}
