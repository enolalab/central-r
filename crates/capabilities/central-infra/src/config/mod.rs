//! `central.config/v1` — strict, canonical, locally declared
//! configuration authority.
//!
//! This module ports upstream `internal/config`: a hand-rolled strict
//! JSON gate (bounded size/depth/tokens/strings, no duplicate keys, no
//! `null`, strict integers only), an RFC 8785 canonical-form gate, a
//! required-field presence gate, the typed `central.config/v1` schema
//! with full cross-field validation, the signed provider profile, the
//! protected-binding catalog, and the signed view envelope that binds a
//! canonical configuration to an Ed25519 verification.
//!
//! Authority fields are never overridden by flags or environment
//! variables; every digest and signed payload is produced with
//! [`central_foundation::jcs::canonicalize`]. The public [`Error`]
//! redacts caller-controlled values — its message is the stable
//! `"config: invalid input"` and [`Error::kind`] exposes the stable
//! [`ErrorKind`] category.

pub mod defaults;
mod schema;
mod strict_json;
#[cfg(test)]
pub(crate) mod testutil;
mod view;

pub use schema::{
    ArtifactConfig, BindingCatalog, BindingMetadata, BootstrapSessionConfig, Config, HttpConfig,
    HttpEndpointConfig, NonStreamingConfig, ObjectStoreBindings, ObjectStoreConfig,
    ObjectStorePolicyDigests, ObservabilityConfig, OperatorModesConfig, PathsConfig,
    PostgresBindings, PostgresConfig, PostgresPools, PostgresTimeouts, ProtectedStoreConfig,
    ProviderBudget, ProviderProfile, QuoteError, RuntimeConfig, TlsConfig, ToolConfig, ToolsConfig,
    WorkspaceRoot, binding_purposes, parse, parse_with_binding_catalog, validate,
    validate_with_binding_catalog,
};
pub use view::{
    B09ProviderAuthority, RuntimeProviderPolicy, VerificationKey, VerificationKeyring,
    VerifiedView, VerifiedViewMetadata, ViewSignature, derive_signing_key_id, parse_view_signature,
    verify_view,
};

/// The stable error categories a caller may branch on — the Rust port
/// of upstream's `ErrInvalidSyntax`, `ErrDuplicateKey`, `ErrLimit`,
/// `ErrSchema`, `ErrSemantic`, `ErrEnvelope`, `ErrKeyring`,
/// `ErrDigest`, `ErrSignature`, and `ErrTimestamp` sentinels.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// `config: invalid syntax`
    InvalidSyntax,
    /// `config: duplicate key`
    DuplicateKey,
    /// `config: limit exceeded`
    Limit,
    /// `config: invalid schema`
    Schema,
    /// `config: invalid semantics`
    Semantic,
    /// `config: invalid envelope`
    Envelope,
    /// `config: invalid keyring`
    Keyring,
    /// `config: digest mismatch`
    Digest,
    /// `config: signature mismatch`
    Signature,
    /// `config: invalid timestamp`
    Timestamp,
}

impl std::fmt::Display for ErrorKind {
    /// The upstream sentinel texts — these are stable, content-free
    /// strings safe to surface where a category message is wanted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidSyntax => "config: invalid syntax",
            Self::DuplicateKey => "config: duplicate key",
            Self::Limit => "config: limit exceeded",
            Self::Schema => "config: invalid schema",
            Self::Semantic => "config: invalid semantics",
            Self::Envelope => "config: invalid envelope",
            Self::Keyring => "config: invalid keyring",
            Self::Digest => "config: digest mismatch",
            Self::Signature => "config: signature mismatch",
            Self::Timestamp => "config: invalid timestamp",
        })
    }
}

impl std::error::Error for ErrorKind {}

/// The redacted public error returned by configuration parsing —
/// upstream `config.Error`.
///
/// Its text is deliberately independent of the input document. Callers
/// can use [`Error::kind`] to inspect the stable category without
/// receiving paths, IDs, or document contents in logs or API responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    /// The stable error category — the `errors.Is` surface.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Wraps a kind into the redacted public error.
    pub(crate) fn redacted(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

impl std::fmt::Display for Error {
    /// Always `"config: invalid input"` — never caller-controlled data.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("config: invalid input")
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    //! Ports of the upstream `config_test` package suites:
    //! `config_test.go`, `schema_test.go`, `public_error_test.go`,
    //! `b09_provider_contract_test.go`, `view_test.go`, and the
    //! config-side half of `workspace_projection_test.go` (the
    //! workspace-policy enumeration half needs the workspace adapter,
    //! out of Task 2 scope).

    use serde_json::Value;
    use sha2::Digest;
    use time::macros::datetime;

    use super::defaults;
    use super::schema;
    use super::testutil::*;
    use super::view;
    use super::*;

    /// A named mutation applied to a [`ProviderProfile`] in the
    /// digest-binding tables — upstream's `func(p *ProviderProfile)`
    /// case lists.
    type ProfileMutation = (&'static str, Box<dyn Fn(&mut ProviderProfile)>);

    // ---------- config_test.go ----------

    #[test]
    fn valid_config_parses() {
        let cfg = parse(&valid_config()).expect("parse");
        assert_eq!(cfg.schema_version, "central.config/v1");
    }

    #[test]
    fn valid_config_parse_from_bytes() {
        let cfg = parse(&valid_config()).expect("parse");
        assert!(!cfg.instance_id.is_nil());
        assert_eq!(cfg.http.application.port, 8080);
        assert_eq!(cfg.http.operations.port, 9090);
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let bad = replace_object_field(&valid_config(), "schema_version", Some(Value::from("v99")));
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn rejects_non_loopback_hosts() {
        for path in ["http.application.host", "http.operations.host"] {
            let bad = replace_object_field(&valid_config(), path, Some(Value::from("0.0.0.0")));
            assert!(parse(&bad).is_err(), "{path}");
        }
    }

    #[test]
    fn rejects_identical_application_and_operations_ports() {
        let bad = replace_object_field(
            &valid_config(),
            "http.operations.port",
            Some(Value::from(8080)),
        );
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(parse(b"not json").is_err());
    }

    #[test]
    fn rejects_noncanonical_config() {
        let pretty = b"{\n  \"schema_version\": \"central.config/v1\",\n  \"instance_id\": \"018f4e2c-0000-7000-8000-000000000001\",\n  \"http\": {\"application\": {\"host\": \"127.0.0.1\", \"port\": 8080}, \"operations\": {\"host\": \"127.0.0.1\", \"port\": 9090}}\n}";
        expect_kind(parse(pretty), ErrorKind::Semantic, "parse pretty");
    }

    #[test]
    fn config_round_trip() {
        let cfg = parse(&valid_config()).expect("parse");
        assert_eq!(
            cfg.instance_id.to_string(),
            "019b0000-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn provider_profile_rejects_unsigned_and_unknown_fields() {
        let unsigned = remove_object_field(&valid_config(), "provider.signature");
        assert!(
            parse(&unsigned).is_err(),
            "unsigned provider profile accepted"
        );
        let unknown = add_object_field(&valid_config(), "provider.proxy", Some(Value::from(1)));
        assert!(parse(&unknown).is_err(), "unknown provider field accepted");
    }

    #[test]
    fn provider_profile_rejects_altered_signed_destination() {
        parse(&valid_config()).expect("signed profile rejected");
        let altered = replace_object_field(
            &valid_config(),
            "provider.destination",
            Some(Value::from("https://evil.example.net:443/v1/responses")),
        );
        assert!(
            parse(&altered).is_err(),
            "altered signed destination accepted"
        );
    }

    #[test]
    fn verified_view_accessors_remain_defensive_copies() {
        let raw =
            replace_workspace_root_field(&valid_config(), "path", Some(Value::from("/workspace")));
        let mut cfg = parse(&raw).expect("parse");
        cfg.provider.protected_paths = vec!["/secrets".to_owned()];
        cfg.provider.signature = cfg.provider.canonical_digest();
        let raw = canonical(&serde_json::to_vec(&cfg).expect("marshal"));
        let verified = verify_view(&raw, &signed_benchmark_envelope(&raw), &vector_keyring())
            .expect("verify_view");

        let mut roots = verified.root_ids();
        assert!(!roots.is_empty(), "expected at least one workspace root");
        let want_root = roots[0].clone();
        roots[0] = "mutated-root-id".to_owned();
        assert_eq!(
            verified.root_ids()[0],
            want_root,
            "root_ids exposed mutable state"
        );

        let mut policy = verified.provider_policy();
        assert!(!policy.protected_paths.is_empty());
        let want_path = policy.protected_paths[0].clone();
        policy.protected_paths[0] = "/mutated".to_owned();
        assert_eq!(
            verified.provider_policy().protected_paths[0],
            want_path,
            "provider_policy exposed mutable state"
        );

        // Upstream: the serialized policy must not leak secret fields
        // or values — catches a future `RuntimeProviderPolicy` field
        // addition. ("ProfileSignature" is PascalCase and does not
        // match "signature", same as upstream's byte search.)
        let policy_json = serde_json::to_string(&policy).expect("marshal policy");
        for forbidden in ["secret_ref", "purpose", "signature", "openai_api_key"] {
            assert!(
                !policy_json.contains(forbidden),
                "ProviderPolicy serialization contains forbidden field/value {forbidden:?}: {policy_json}"
            );
        }
    }

    // ---------- schema_test.go ----------

    #[test]
    fn complete_config_fixture_parses() {
        let raw = valid_config();
        let cfg = parse(&raw).expect("parse complete fixture");
        assert_eq!(cfg.provider.provider, "openai-responses");
    }

    #[test]
    fn provider_profile_accepts_generic_agent_identity_without_provider_secret() {
        let mut cfg = parse(&valid_config()).expect("parse");
        cfg.provider.provider = "agent-runtime".to_owned();
        cfg.provider.model = "agent-model".to_owned();
        cfg.provider.destination = "opaque-agent-dispatch".to_owned();
        cfg.provider.method = "dispatch".to_owned();
        cfg.provider.path = "/invoke".to_owned();
        cfg.provider.secret_ref = String::new();
        cfg.provider.purpose = String::new();
        cfg.provider.signature = cfg.provider.canonical_digest();
        validate(&cfg).expect("generic agent profile rejected");
    }

    #[test]
    fn parse_requires_every_canonical_section() {
        for path in [
            "artifact",
            "operator_modes",
            "tools",
            "runtime",
            "observability",
            "provider",
        ] {
            let mutated = remove_object_field(&valid_config(), path);
            assert!(parse(&mutated).is_err(), "parse accepted missing {path}");
        }
    }

    #[test]
    fn parse_rejects_missing_required_nested_leaf() {
        for path in [
            "http.tls.binding_id",
            "postgres.bindings.runtime",
            "postgres.pools.runtime_general",
            "object_store.policy_digests.runtime",
            "bootstrap_session.absolute_ms",
            "artifact.copy_buffer_bytes",
            "operator_modes.total_lock_ms",
            "tools.pg_dump.version",
            "runtime.enabled_components",
            "provider.default_budget.request_bytes",
            "provider.hard_budget.spend_micros",
        ] {
            let mutated = remove_object_field(&valid_config(), path);
            assert!(parse(&mutated).is_err(), "parse accepted missing {path}");
        }
    }

    #[test]
    fn parse_rejects_unknown_and_null_fields() {
        let raw = valid_config();
        let unknown = add_object_field(&raw, "runtime.unknown", Some(Value::from(1)));
        expect_kind(parse(&unknown), ErrorKind::Schema, "unknown field");
        let null = replace_object_field(&raw, "runtime.preflight_ms", Some(Value::Null));
        assert!(parse(&null).is_err(), "parse accepted null");
    }

    #[test]
    fn parse_rejects_null_at_every_required_boundary() {
        let raw = valid_config();
        let mut paths: Vec<String> = [
            "schema_version",
            "instance_id",
            "paths",
            "paths.authoritative_state_root",
            "paths.instance_data_root",
            "paths.backup_repository_root",
            "paths.workspace_roots",
            "http",
            "http.application",
            "http.application.host",
            "http.application.port",
            "http.operations",
            "http.operations.host",
            "http.operations.port",
            "http.tls",
            "http.tls.binding_id",
            "http.tls.ca_fingerprint_sha256",
            "http.tls.leaf_fingerprint_sha256",
            "http.non_streaming",
            "http.non_streaming.active",
            "http.non_streaming.waiters",
            "http.non_streaming.admission_wait_ms",
            "http.non_streaming.api_buffer_bytes",
            "http.non_streaming.html_buffer_bytes",
            "http.non_streaming.body_read_ms",
            "http.non_streaming.response_write_ms",
            "http.non_streaming.route_total_ms",
            "http.max_header_bytes",
            "http.max_header_value_bytes",
            "http.read_header_ms",
            "http.idle_ms",
            "http.graceful_shutdown_ms",
            "postgres",
            "postgres.host",
            "postgres.port",
            "postgres.database",
            "postgres.schema",
            "postgres.bindings",
            "postgres.bindings.server_admin",
            "postgres.bindings.runtime",
            "postgres.bindings.outbox",
            "postgres.bindings.migration",
            "postgres.pools",
            "postgres.pools.runtime_general",
            "postgres.pools.runtime_settlement",
            "postgres.pools.outbox",
            "postgres.pools.cleanup",
            "postgres.pools.serve_lock_control",
            "postgres.pools.coexisting_read_only",
            "postgres.pools.offline_mutation",
            "postgres.timeouts",
            "postgres.timeouts.pool_acquire_ms",
            "postgres.timeouts.statement_ms",
            "postgres.timeouts.lock_ms",
            "postgres.timeouts.transaction_ms",
            "postgres.timeouts.idle_in_transaction_ms",
            "postgres.timeouts.connection_lifetime_ms",
            "object_store",
            "object_store.scheme",
            "object_store.host",
            "object_store.port",
            "object_store.bucket",
            "object_store.region",
            "object_store.path_style",
            "object_store.bindings",
            "object_store.bindings.root",
            "object_store.bindings.runtime",
            "object_store.bindings.backup",
            "object_store.bindings.restore",
            "object_store.policy_digests",
            "object_store.policy_digests.runtime",
            "object_store.policy_digests.backup",
            "object_store.policy_digests.restore",
            "protected_store",
            "protected_store.backend",
            "protected_store.binding_root_id",
            "protected_store.max_secret_bytes",
            "protected_store.resolve_ms",
            "protected_store.candidate_cleanup_age_ms",
            "protected_store.retired_cleanup_age_ms",
            "bootstrap_session",
            "bootstrap_session.binding_id",
            "bootstrap_session.token_bits",
            "bootstrap_session.presentation_ms",
            "bootstrap_session.throttle_failures",
            "bootstrap_session.throttle_window_ms",
            "bootstrap_session.first_use_ms",
            "bootstrap_session.idle_ms",
            "bootstrap_session.absolute_ms",
            "artifact",
            "artifact.active_transfers",
            "artifact.waiters",
            "artifact.admission_wait_ms",
            "artifact.copy_buffer_bytes",
            "artifact.stream_idle_ms",
            "artifact.stream_total_ms",
            "operator_modes",
            "tools",
            "tools.pg_dump",
            "tools.pg_dump.path",
            "tools.pg_dump.version",
            "tools.pg_restore",
            "tools.pg_restore.path",
            "tools.pg_restore.version",
            "runtime",
            "runtime.preflight_ms",
            "runtime.preflight_page",
            "runtime.startup_dependency_ms",
            "runtime.dependency_retry_ms",
            "runtime.retry_initial_ms",
            "runtime.retry_max_ms",
            "runtime.health_interval_ms",
            "runtime.health_timeout_ms",
            "runtime.go_memory_limit_bytes",
            "runtime.central_rss_ceiling_bytes",
            "runtime.operator_tool_rss_ceiling_bytes",
            "runtime.host_memory_reserve_bytes",
            "runtime.host_memory_headroom_bytes",
            "runtime.settlement_ms",
            "runtime.total_shutdown_ms",
            "runtime.enabled_components",
            "observability",
            "observability.log_format",
            "observability.log_level",
            "observability.metric_registry",
            "provider",
            "provider.provider",
            "provider.model",
            "provider.destination",
            "provider.method",
            "provider.path",
            "provider.policy_revision",
            "provider.tool_revision",
            "provider.price_data_revision",
            "provider.secret_ref",
            "provider.purpose",
            "provider.protected_paths",
            "provider.default_budget",
            "provider.default_budget.request_bytes",
            "provider.default_budget.response_bytes",
            "provider.default_budget.spend_micros",
            "provider.hard_budget",
            "provider.hard_budget.request_bytes",
            "provider.hard_budget.response_bytes",
            "provider.hard_budget.spend_micros",
            "provider.signature",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        paths.extend(prefixed_paths("operator_modes", OPERATOR_MODE_FIELDS));
        for path in &paths {
            let mutated = replace_object_field(&raw, path, Some(Value::Null));
            assert!(parse(&mutated).is_err(), "parse accepted null at {path}");
        }
        for field in ["root_id", "path"] {
            let mutated = replace_workspace_root_field(&raw, field, Some(Value::Null));
            assert!(
                parse(&mutated).is_err(),
                "parse accepted null at workspace root {field}"
            );
        }
    }

    #[test]
    fn parse_rejects_every_required_field_deletion() {
        let raw = valid_config();
        let mut paths: Vec<String> = [
            "schema_version",
            "instance_id",
            "paths.authoritative_state_root",
            "paths.instance_data_root",
            "paths.backup_repository_root",
            "paths.workspace_roots",
            "http.application.host",
            "http.application.port",
            "http.operations.host",
            "http.operations.port",
            "http.tls.binding_id",
            "http.tls.ca_fingerprint_sha256",
            "http.tls.leaf_fingerprint_sha256",
            "http.non_streaming.active",
            "http.non_streaming.waiters",
            "http.non_streaming.admission_wait_ms",
            "http.non_streaming.api_buffer_bytes",
            "http.non_streaming.html_buffer_bytes",
            "http.non_streaming.body_read_ms",
            "http.non_streaming.response_write_ms",
            "http.non_streaming.route_total_ms",
            "http.max_header_bytes",
            "http.max_header_value_bytes",
            "http.read_header_ms",
            "http.idle_ms",
            "http.graceful_shutdown_ms",
            "postgres.host",
            "postgres.port",
            "postgres.database",
            "postgres.schema",
            "postgres.bindings.server_admin",
            "postgres.bindings.runtime",
            "postgres.bindings.outbox",
            "postgres.bindings.migration",
            "postgres.pools.runtime_general",
            "postgres.pools.runtime_settlement",
            "postgres.pools.outbox",
            "postgres.pools.cleanup",
            "postgres.pools.serve_lock_control",
            "postgres.pools.coexisting_read_only",
            "postgres.pools.offline_mutation",
            "postgres.timeouts.pool_acquire_ms",
            "postgres.timeouts.statement_ms",
            "postgres.timeouts.lock_ms",
            "postgres.timeouts.transaction_ms",
            "postgres.timeouts.idle_in_transaction_ms",
            "postgres.timeouts.connection_lifetime_ms",
            "object_store.scheme",
            "object_store.host",
            "object_store.port",
            "object_store.bucket",
            "object_store.region",
            "object_store.path_style",
            "object_store.bindings.root",
            "object_store.bindings.runtime",
            "object_store.bindings.backup",
            "object_store.bindings.restore",
            "object_store.policy_digests.runtime",
            "object_store.policy_digests.backup",
            "object_store.policy_digests.restore",
            "protected_store.backend",
            "protected_store.binding_root_id",
            "protected_store.max_secret_bytes",
            "protected_store.resolve_ms",
            "protected_store.candidate_cleanup_age_ms",
            "protected_store.retired_cleanup_age_ms",
            "bootstrap_session.binding_id",
            "bootstrap_session.token_bits",
            "bootstrap_session.presentation_ms",
            "bootstrap_session.throttle_failures",
            "bootstrap_session.throttle_window_ms",
            "bootstrap_session.first_use_ms",
            "bootstrap_session.idle_ms",
            "bootstrap_session.absolute_ms",
            "artifact.active_transfers",
            "artifact.waiters",
            "artifact.admission_wait_ms",
            "artifact.copy_buffer_bytes",
            "artifact.stream_idle_ms",
            "artifact.stream_total_ms",
            "operator_modes.backup_elapsed_ms",
            "tools.pg_dump.path",
            "tools.pg_dump.version",
            "tools.pg_restore.path",
            "tools.pg_restore.version",
            "runtime.preflight_ms",
            "runtime.preflight_page",
            "runtime.startup_dependency_ms",
            "runtime.dependency_retry_ms",
            "runtime.retry_initial_ms",
            "runtime.retry_max_ms",
            "runtime.health_interval_ms",
            "runtime.health_timeout_ms",
            "runtime.go_memory_limit_bytes",
            "runtime.central_rss_ceiling_bytes",
            "runtime.operator_tool_rss_ceiling_bytes",
            "runtime.host_memory_reserve_bytes",
            "runtime.host_memory_headroom_bytes",
            "runtime.settlement_ms",
            "runtime.total_shutdown_ms",
            "runtime.enabled_components",
            "observability.log_format",
            "observability.log_level",
            "observability.metric_registry",
            "provider.provider",
            "provider.model",
            "provider.destination",
            "provider.method",
            "provider.path",
            "provider.policy_revision",
            "provider.tool_revision",
            "provider.price_data_revision",
            "provider.secret_ref",
            "provider.purpose",
            "provider.protected_paths",
            "provider.default_budget.request_bytes",
            "provider.default_budget.response_bytes",
            "provider.default_budget.spend_micros",
            "provider.hard_budget.request_bytes",
            "provider.hard_budget.response_bytes",
            "provider.hard_budget.spend_micros",
            "provider.signature",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        paths.extend(prefixed_paths("operator_modes", OPERATOR_MODE_FIELDS));
        for path in &paths {
            let mutated = remove_object_field(&raw, path);
            assert!(parse(&mutated).is_err(), "parse accepted missing {path}");
        }
        for field in ["root_id", "path"] {
            let mutated = replace_workspace_root_field(&raw, field, None);
            assert!(
                parse(&mutated).is_err(),
                "parse accepted missing paths.workspace_roots[].{field}"
            );
        }
    }

    #[test]
    fn parse_rejects_noncanonical_instance_id_text() {
        let raw = valid_config();
        let document: Value = serde_json::from_slice(&raw).expect("decode");
        let instance_id = document["instance_id"]
            .as_str()
            .expect("instance_id string");
        for (name, value) in [
            ("uppercase", instance_id.to_uppercase()),
            ("leading plus", format!("+{instance_id}")),
            ("braced", format!("{{{instance_id}}}")),
        ] {
            let mutated = replace_object_field(&raw, "instance_id", Some(Value::from(value)));
            assert!(
                parse(&mutated).is_err(),
                "{name}: noncanonical instance_id accepted"
            );
        }
    }

    #[test]
    fn parse_enforces_binding_identity_rules() {
        let raw = valid_config();
        for (name, value) in [
            (
                "duplicate purpose binding",
                "019b0000-0000-7000-8000-000000000003",
            ),
            (
                "instance id used as binding",
                "019b0000-0000-7000-8000-000000000001",
            ),
            ("malformed binding", "not-a-uuid"),
            ("uppercase binding", "019B0000-0000-7000-8000-000000000003"),
        ] {
            let mutated =
                replace_object_field(&raw, "postgres.bindings.runtime", Some(Value::from(value)));
            assert!(
                parse(&mutated).is_err(),
                "{name}: invalid binding association accepted"
            );
        }
        parse(&raw).expect("valid binding vector rejected");
    }

    #[test]
    fn binding_catalog_enforces_field_purpose_and_instance() {
        let raw = valid_config();
        let cfg = parse(&raw).expect("parse");
        let metadata = binding_metadata(&cfg);

        let valid = BindingCatalog::new(metadata.clone()).expect("new catalog");
        validate_with_binding_catalog(&cfg, &valid).expect("valid binding catalog rejected");
        parse_with_binding_catalog(&raw, &valid).expect("parse with catalog");

        let mut swapped = metadata.clone();
        let purpose = swapped[0].purpose.clone();
        swapped[0].purpose = swapped[1].purpose.clone();
        swapped[1].purpose = purpose;
        if let Ok(catalog) = BindingCatalog::new(swapped) {
            assert!(
                validate_with_binding_catalog(&cfg, &catalog).is_err(),
                "purpose swap accepted"
            );
        }

        let mut wrong = metadata.clone();
        wrong[0].instance_id =
            central_foundation::identity::InstanceId::parse("019b0000-0000-7000-8000-0000000000ff")
                .expect("wrong instance id");
        if let Ok(catalog) = BindingCatalog::new(wrong) {
            assert!(
                validate_with_binding_catalog(&cfg, &catalog).is_err(),
                "wrong instance accepted"
            );
        }

        let mut duplicate = metadata.clone();
        duplicate[1].binding_id = duplicate[0].binding_id.clone();
        if let Ok(catalog) = BindingCatalog::new(duplicate) {
            assert!(
                validate_with_binding_catalog(&cfg, &catalog).is_err(),
                "duplicate metadata accepted"
            );
        }

        let instance_reuse = replace_object_field(
            &raw,
            "postgres.bindings.runtime",
            Some(must_json(&cfg.instance_id.to_string())),
        );
        assert!(
            parse(&instance_reuse).is_err(),
            "binding ID reused instance ID"
        );

        let duplicate_id = replace_object_field(
            &raw,
            "postgres.bindings.runtime",
            Some(must_json(&cfg.postgres.bindings.server_admin)),
        );
        assert!(
            parse(&duplicate_id).is_err(),
            "duplicate binding ID accepted"
        );
    }

    #[test]
    fn parse_rejects_invalid_workspace_root_collections() {
        let raw = valid_config();
        let root = |id: &str, path: &str| serde_json::json!({"root_id": id, "path": path});
        let valid_roots = serde_json::json!([
            root("019b0000-0000-7000-8000-000000000010", "/workspace/a"),
            root("019b0000-0000-7000-8000-000000000011", "/workspace/b"),
        ]);
        let cases: Vec<(&str, Value)> = vec![
            (
                "duplicate root IDs",
                serde_json::json!([
                    root("019b0000-0000-7000-8000-000000000010", "/workspace/a"),
                    root("019b0000-0000-7000-8000-000000000010", "/workspace/b"),
                ]),
            ),
            (
                "unsorted roots",
                serde_json::json!([valid_roots[1], valid_roots[0]]),
            ),
            (
                "overlapping roots",
                serde_json::json!([
                    root("019b0000-0000-7000-8000-000000000010", "/workspace/a"),
                    root("019b0000-0000-7000-8000-000000000011", "/workspace/a/b"),
                ]),
            ),
        ];
        for (name, roots) in cases {
            let mutated = replace_object_field(&raw, "paths.workspace_roots", Some(roots));
            assert!(
                parse(&mutated).is_err(),
                "{name}: invalid workspace roots accepted"
            );
        }
        let mutated = replace_object_field(&raw, "paths.workspace_roots", Some(valid_roots));
        parse(&mutated).expect("parse rejected valid workspace roots");

        let too_many: Vec<Value> = (0..33)
            .map(|i| {
                serde_json::json!({
                    "root_id": format!("019b0000-0000-7000-8000-{:012}", i + 10),
                    "path": format!("/workspace/{i:04}"),
                })
            })
            .collect();
        let mutated =
            replace_object_field(&raw, "paths.workspace_roots", Some(Value::Array(too_many)));
        assert!(
            parse(&mutated).is_err(),
            "parse accepted >32 workspace roots"
        );
    }

    #[test]
    fn parse_rejects_every_global_port_collision() {
        let raw = valid_config();
        let values = [
            ("http.application.port", "8080"),
            ("http.operations.port", "9090"),
            ("postgres.port", "55432"),
            ("object_store.port", "59000"),
        ];
        for (source, source_value) in values {
            for (target, _) in values.iter().filter(|(t, _)| *t != source) {
                let mutated = replace_object_field(
                    &raw,
                    target,
                    Some(Value::from(source_value.parse::<u64>().expect("port"))),
                );
                assert!(
                    parse(&mutated).is_err(),
                    "parse accepted collision {source}={target}"
                );
            }
        }
    }

    #[test]
    fn parse_rejects_invalid_fingerprints_and_budgets() {
        let raw = valid_config();
        let mutated = replace_object_field(
            &raw,
            "http.tls.ca_fingerprint_sha256",
            Some(Value::from("A".repeat(64))),
        );
        assert!(parse(&mutated).is_err(), "uppercase fingerprint accepted");

        let mutated = replace_object_field(
            &raw,
            "object_store.policy_digests.runtime",
            Some(Value::from("deadbeef")),
        );
        assert!(parse(&mutated).is_err(), "short fingerprint accepted");

        let mut profile = must_provider(&raw);
        profile.default_budget.request_bytes = 0;
        profile.signature = profile.canonical_digest();
        let mutated = replace_object_field(&raw, "provider", Some(must_json(&profile)));
        assert!(parse(&mutated).is_err(), "zero default budget accepted");

        let mut profile = must_provider(&raw);
        profile.hard_budget.request_bytes = profile.default_budget.request_bytes - 1;
        profile.signature = profile.canonical_digest();
        let mutated = replace_object_field(&raw, "provider", Some(must_json(&profile)));
        assert!(
            parse(&mutated).is_err(),
            "hard budget below default accepted"
        );
    }

    #[test]
    fn parse_accepts_generic_purpose_and_validates_protected_path_overlap() {
        let raw = valid_config();
        let mut provider = must_provider(&raw);
        provider.purpose = "postgres_runtime_v1".to_owned();
        provider.signature = provider.canonical_digest();
        let mutated = replace_object_field(&raw, "provider", Some(must_json(&provider)));
        parse(&mutated).expect("generic compatibility purpose rejected");

        let cases: &[(&str, &str, bool)] = &[
            ("equal absolute", r#"["/a","/a"]"#, false),
            ("parent absolute", r#"["/a","/a/b"]"#, false),
            ("child absolute", r#"["/a/b","/a"]"#, false),
            ("component absolute", r#"["/a","/ab"]"#, true),
            (
                "single relative segments",
                r#"["secrets","terraform.tfstate"]"#,
                true,
            ),
            ("rooted relative", r#"["infra/private","secrets"]"#, true),
            (
                "relative component prefix distinct",
                r#"["infra/private","infra/privates"]"#,
                true,
            ),
            (
                "relative segment overlap",
                r#"["infra/private","private"]"#,
                false,
            ),
            (
                "relative rooted overlap",
                r#"["infra","infra/private"]"#,
                false,
            ),
            ("relative unsorted", r#"["secrets","infra/private"]"#, false),
            ("relative trailing slash", r#"["secrets/"]"#, false),
            ("relative wrong case", r#"["Secrets"]"#, false),
            ("relative unclean", r#"["infra/./private"]"#, false),
            ("relative decomposed NFC", "[\"secrets/e\\u0301\"]", false),
        ];
        for (name, paths_json, valid) in cases {
            let mut profile = must_provider(&raw);
            profile.protected_paths =
                serde_json::from_str(paths_json).expect("protected paths JSON");
            profile.signature = profile.canonical_digest();
            let candidate = replace_object_field(&raw, "provider", Some(must_json(&profile)));
            assert_eq!(parse(&candidate).is_ok(), *valid, "{name}");
        }
    }

    #[test]
    fn parse_rejects_provider_protected_path_control_characters() {
        let raw = valid_config();
        for (form, value) in [
            ("absolute", "/safe\u{0}/path"),
            ("relative", "sec\u{0}rets"),
            ("rooted relative", "infra\u{0}/private"),
        ] {
            for (name, control) in [("nul", '\0'), ("newline", '\n')] {
                let mut profile = must_provider(&raw);
                profile.protected_paths = vec![value.replacen('\u{0}', &control.to_string(), 1)];
                profile.signature = profile.canonical_digest();
                let candidate = replace_object_field(&raw, "provider", Some(must_json(&profile)));
                assert!(
                    parse(&candidate).is_err(),
                    "parse accepted protected path {form}/{name} control character"
                );
            }
        }
    }

    #[test]
    fn parse_rejects_provider_signature_only_mutation() {
        let raw = valid_config();
        let mutated = replace_object_field(
            &raw,
            "provider.signature",
            Some(Value::from("0".repeat(64))),
        );
        expect_kind(
            parse(&mutated),
            ErrorKind::Semantic,
            "provider.signature-only mutation",
        );
    }

    #[test]
    fn parse_enforces_backup_parent_deadlines() {
        let raw = valid_config();
        let cases: &[(&str, &[(&str, &str)])] = &[
            (
                "probe exceeds operation",
                &[
                    ("operator_modes.backup_elapsed_ms", "299999"),
                    ("operator_modes.body_total_ms", "60000"),
                    ("operator_modes.body_idle_ms", "1000"),
                ],
            ),
            (
                "probe exceeds admission deadline",
                &[
                    ("operator_modes.backup_elapsed_ms", "399999"),
                    ("operator_modes.body_total_ms", "60000"),
                    ("operator_modes.body_idle_ms", "1000"),
                ],
            ),
            (
                "body exceeds backup operation",
                &[("operator_modes.backup_elapsed_ms", "1799999")],
            ),
            (
                "http route misses children",
                &[("http.non_streaming.route_total_ms", "61999")],
            ),
            (
                "artifact admission exceeds stream",
                &[("artifact.stream_total_ms", "4999")],
            ),
        ];
        for (name, mutations) in cases {
            let mut candidate = raw.clone();
            for (path, value) in *mutations {
                candidate = replace_object_field(
                    &candidate,
                    path,
                    Some(Value::from(value.parse::<u64>().expect("number"))),
                );
            }
            assert!(
                parse(&candidate).is_err(),
                "{name}: deadline violation accepted"
            );
        }
    }

    #[test]
    fn safe_number_gate_accepts_maximum_and_rejects_next_value() {
        let raw = valid_config();
        for path in numeric_field_paths() {
            let maximum = replace_object_field(&raw, &path, Some(Value::from(9007199254740991u64)));
            let err =
                parse(&maximum).expect_err("maximum safe integer parsed without semantic error");
            assert_eq!(
                err.kind(),
                ErrorKind::Semantic,
                "maximum safe integer error at {path}, want semantic validation after acceptance"
            );
            let too_large =
                replace_object_field(&raw, &path, Some(Value::from(9007199254740992u64)));
            let err = parse(&too_large).expect_err("2^53 parsed");
            assert_eq!(
                err.kind(),
                ErrorKind::Semantic,
                "2^53 error at {path}, want semantic rejection"
            );
        }
    }

    #[test]
    fn provider_canonical_digest_vectors() {
        let raw = valid_config();
        let cfg = parse(&raw).expect("parse");
        assert_eq!(
            cfg.provider.canonical_digest(),
            "1dfba9dbc2dae200b8dd3b8256ff4440fe40195294179f171d94264d14da79ef",
            "fixture digest"
        );
        let baseline = cfg.provider.canonical_digest();
        let mutations: Vec<ProfileMutation> = vec![
            ("provider", Box::new(|p| p.provider = "other".into())),
            ("model", Box::new(|p| p.model = "other".into())),
            (
                "destination",
                Box::new(|p| p.destination = "https://other.example/v1/responses".into()),
            ),
            ("method", Box::new(|p| p.method = "PUT".into())),
            ("path", Box::new(|p| p.path = "/other".into())),
            (
                "policy revision",
                Box::new(|p| p.policy_revision = "policy-2".into()),
            ),
            (
                "tool revision",
                Box::new(|p| p.tool_revision = "tool-2".into()),
            ),
            (
                "price revision",
                Box::new(|p| p.price_data_revision = "prices-2".into()),
            ),
            (
                "secret ref",
                Box::new(|p| p.secret_ref = "other_secret".into()),
            ),
            ("purpose", Box::new(|p| p.purpose = "other_purpose".into())),
            (
                "protected path content",
                Box::new(|p| p.protected_paths = vec!["/protected".into()]),
            ),
            (
                "protected path order",
                Box::new(|p| p.protected_paths = vec!["/b".into(), "/a".into()]),
            ),
            (
                "default request budget",
                Box::new(|p| p.default_budget.request_bytes += 1),
            ),
            (
                "default response budget",
                Box::new(|p| p.default_budget.response_bytes += 1),
            ),
            (
                "default spend budget",
                Box::new(|p| p.default_budget.spend_micros += 1),
            ),
            (
                "hard request budget",
                Box::new(|p| p.hard_budget.request_bytes += 1),
            ),
            (
                "hard response budget",
                Box::new(|p| p.hard_budget.response_bytes += 1),
            ),
            (
                "hard spend budget",
                Box::new(|p| p.hard_budget.spend_micros += 1),
            ),
            (
                "control character",
                Box::new(|p| p.policy_revision = "policy-\u{1}".into()),
            ),
            (
                "escaping-sensitive string",
                Box::new(|p| p.tool_revision = "tool-\\\"".into()),
            ),
            (
                "signature excluded",
                Box::new(|p| p.signature = "different".into()),
            ),
        ];
        for (name, mutate) in &mutations {
            let mut profile = cfg.provider.clone();
            mutate(&mut profile);
            let got = profile.canonical_digest();
            if *name == "signature excluded" {
                assert_eq!(got, baseline, "signature changed digest");
            } else {
                assert_ne!(got, baseline, "{name} did not change digest");
            }
        }
    }

    #[test]
    fn validate_rejects_lexical_path_aliases_and_overlaps() {
        let raw = valid_config();
        let root = |id: &str, path: &str| serde_json::json!({"root_id": id, "path": path});
        let cases: Vec<(&str, Value, bool)> = vec![
            (
                "empty",
                serde_json::json!([root("019b0000-0000-7000-8000-000000000010", "")]),
                false,
            ),
            (
                "relative",
                serde_json::json!([root("019b0000-0000-7000-8000-000000000010", "relative")]),
                false,
            ),
            (
                "dot component",
                serde_json::json!([root("019b0000-0000-7000-8000-000000000010", "/a/./b")]),
                false,
            ),
            (
                "dot dot component",
                serde_json::json!([root("019b0000-0000-7000-8000-000000000010", "/a/../b")]),
                false,
            ),
            (
                "repeated separator",
                serde_json::json!([root("019b0000-0000-7000-8000-000000000010", "/a//b")]),
                false,
            ),
            (
                "trailing separator",
                serde_json::json!([root("019b0000-0000-7000-8000-000000000010", "/a/")]),
                false,
            ),
            (
                "decomposed NFC alias",
                serde_json::json!([root(
                    "019b0000-0000-7000-8000-000000000010",
                    "/workspace/e\u{301}"
                )]),
                false,
            ),
            (
                "component overlap",
                serde_json::json!([
                    root("019b0000-0000-7000-8000-000000000010", "/a"),
                    root("019b0000-0000-7000-8000-000000000011", "/a/b"),
                ]),
                false,
            ),
            (
                "prefix is not component overlap",
                serde_json::json!([
                    root("019b0000-0000-7000-8000-000000000010", "/a"),
                    root("019b0000-0000-7000-8000-000000000011", "/ab"),
                ]),
                true,
            ),
        ];
        for (name, roots, valid) in cases {
            let mutated = replace_object_field(&raw, "paths.workspace_roots", Some(roots));
            assert_eq!(parse(&mutated).is_ok(), valid, "{name}");
        }
    }

    #[test]
    fn validate_returns_redacted_public_error() {
        let mut cfg = parse(&valid_config()).expect("parse");
        let marker = "host-with-secret";
        cfg.http.application.host = marker.to_owned();
        let err = validate(&cfg).expect_err("validate");
        assert_eq!(err.kind(), ErrorKind::Semantic);
        assert_eq!(err.to_string(), "config: invalid input");
        assert!(!err.to_string().contains(marker));
    }

    #[test]
    fn new_binding_catalog_returns_redacted_semantic_errors() {
        let instance =
            central_foundation::identity::InstanceId::parse("019b0000-0000-7000-8000-000000000001")
                .expect("instance");
        let valid_binding = "019b0000-0000-7000-8000-000000000002";
        let cases: Vec<(&str, Vec<BindingMetadata>)> = vec![
            (
                "malformed binding ID",
                vec![BindingMetadata {
                    binding_id: "not-a-binding".to_owned(),
                    purpose: binding_purposes::APPLICATION_TLS.to_owned(),
                    instance_id: instance,
                }],
            ),
            (
                "zero instance",
                vec![BindingMetadata {
                    binding_id: valid_binding.to_owned(),
                    purpose: binding_purposes::APPLICATION_TLS.to_owned(),
                    instance_id: central_foundation::identity::InstanceId::from_trusted_db_bytes(
                        [0u8; 16],
                    ),
                }],
            ),
            (
                "duplicate binding ID",
                vec![
                    BindingMetadata {
                        binding_id: valid_binding.to_owned(),
                        purpose: binding_purposes::APPLICATION_TLS.to_owned(),
                        instance_id: instance,
                    },
                    BindingMetadata {
                        binding_id: valid_binding.to_owned(),
                        purpose: binding_purposes::APPLICATION_TLS.to_owned(),
                        instance_id: instance,
                    },
                ],
            ),
        ];
        for (name, metadata) in cases {
            let err = BindingCatalog::new(metadata).expect_err(name);
            assert_eq!(err.kind(), ErrorKind::Semantic, "{name}");
            assert_eq!(err.to_string(), "config: invalid input", "{name}");
        }
    }

    #[test]
    fn validate_redacts_caller_controlled_values() {
        struct Case {
            marker: &'static str,
            mutate: fn(&mut Config),
        }
        let cases = [
            Case {
                marker: "malicious-application-host",
                mutate: |cfg| cfg.http.application.host = "malicious-application-host".to_owned(),
            },
            Case {
                marker: "malicious-operations-host",
                mutate: |cfg| cfg.http.operations.host = "malicious-operations-host".to_owned(),
            },
            Case {
                marker: "malicious-protected-backend",
                mutate: |cfg| {
                    cfg.protected_store.backend = "malicious-protected-backend".to_owned()
                },
            },
        ];
        for case in cases {
            let mut cfg = parse(&valid_config()).expect("parse");
            (case.mutate)(&mut cfg);
            let err = validate(&cfg).expect_err("validate");
            assert_eq!(err.kind(), ErrorKind::Semantic);
            assert!(
                !err.to_string().contains(case.marker),
                "validate error contains caller data"
            );
        }
    }

    // ---------- public_error_test.go ----------

    #[test]
    fn parse_redacts_separate_caller_input_classes() {
        let cases: Vec<(&str, &str, Vec<u8>)> = {
            let mut docs = Vec::new();
            let mut doc = base_config_document();
            doc.insert("paths".to_owned(), serde_json::json!({
                "workspace_roots": [{"root_id": "root-1", "path": "malicious/path/with-secret"}],
                "unknown": 1,
            }));
            docs.push((
                "path",
                "malicious/path/with-secret",
                canonical_document(&doc),
            ));

            let mut doc = base_config_document();
            doc.insert(
                "instance_id".to_owned(),
                Value::from("malicious-instance-id"),
            );
            docs.push((
                "instance ID",
                "malicious-instance-id",
                canonical_document(&doc),
            ));

            docs.push((
                "raw JSON",
                "malicious-raw-json",
                b"not-json-malicious-raw-json".to_vec(),
            ));

            let mut doc = base_config_document();
            doc.insert("digest".to_owned(), Value::from("malicious-digest"));
            docs.push(("digest", "malicious-digest", canonical_document(&doc)));

            let mut doc = base_config_document();
            doc.insert("key_id".to_owned(), Value::from("malicious-key-id"));
            docs.push(("key ID", "malicious-key-id", canonical_document(&doc)));

            let mut doc = base_config_document();
            doc.insert(
                "provider".to_owned(),
                provider_document("malicious-signature"),
            );
            docs.push(("signature", "malicious-signature", canonical_document(&doc)));
            docs
        };
        for (name, marker, raw) in cases {
            let err = parse(&raw).expect_err(name);
            assert_eq!(err.to_string(), "config: invalid input", "{name}");
            assert!(!err.to_string().contains(marker), "{name} leaked marker");
        }
    }

    #[test]
    fn error_unwraps_kind_without_exposing_it() {
        let err = Error::redacted(ErrorKind::Digest);
        assert_eq!(err.to_string(), "config: invalid input");
        assert_eq!(err.kind(), ErrorKind::Digest);
    }

    // ---------- b09_provider_contract_test.go ----------

    #[test]
    fn provider_profile_signs_complete_b09_authority() {
        let budget = |n: u64| ProviderBudget {
            request_bytes: n,
            response_bytes: n,
            input_tokens: n,
            output_tokens: n,
            tool_calls_per_step: n,
            tool_calls_per_run: n,
            wall_time_seconds: n,
            spend_micros: n,
        };
        let profile = ProviderProfile {
            provider: String::new(),
            model: String::new(),
            destination: String::new(),
            method: String::new(),
            path: String::new(),
            policy_revision: String::new(),
            tool_revision: String::new(),
            price_data_revision: String::new(),
            secret_ref: String::new(),
            purpose: String::new(),
            protected_paths: vec![],
            default_budget: budget(1),
            hard_budget: budget(2),
            input_token_price_micros: 1,
            output_token_price_micros: 2,
            local_grant_ttl_seconds: 3,
            signature: String::new(),
        };
        let baseline = profile.canonical_digest();
        assert!(!baseline.is_empty(), "canonical_digest returned empty");
        let mutations: Vec<ProfileMutation> = vec![
            (
                "default input tokens",
                Box::new(|p| p.default_budget.input_tokens += 1),
            ),
            (
                "default output tokens",
                Box::new(|p| p.default_budget.output_tokens += 1),
            ),
            (
                "default step tool calls",
                Box::new(|p| p.default_budget.tool_calls_per_step += 1),
            ),
            (
                "default run tool calls",
                Box::new(|p| p.default_budget.tool_calls_per_run += 1),
            ),
            (
                "default wall time",
                Box::new(|p| p.default_budget.wall_time_seconds += 1),
            ),
            (
                "hard input tokens",
                Box::new(|p| p.hard_budget.input_tokens += 1),
            ),
            (
                "hard output tokens",
                Box::new(|p| p.hard_budget.output_tokens += 1),
            ),
            (
                "hard step tool calls",
                Box::new(|p| p.hard_budget.tool_calls_per_step += 1),
            ),
            (
                "hard run tool calls",
                Box::new(|p| p.hard_budget.tool_calls_per_run += 1),
            ),
            (
                "hard wall time",
                Box::new(|p| p.hard_budget.wall_time_seconds += 1),
            ),
            ("input price", Box::new(|p| p.input_token_price_micros += 1)),
            (
                "output price",
                Box::new(|p| p.output_token_price_micros += 1),
            ),
            ("grant ttl", Box::new(|p| p.local_grant_ttl_seconds += 1)),
        ];
        for (name, mutate) in &mutations {
            let mut candidate = profile.clone();
            mutate(&mut candidate);
            assert_ne!(
                candidate.canonical_digest(),
                baseline,
                "{name}: canonical_digest did not bind changed authority"
            );
        }
    }

    #[test]
    fn provider_profile_quote_micros_uses_checked_arithmetic() {
        let mut profile = empty_profile_for_contract();
        profile.input_token_price_micros = 3;
        profile.output_token_price_micros = 7;
        assert_eq!(profile.quote_micros(11, 13).expect("quote"), 124);
        assert_eq!(
            profile.quote_micros(u64::MAX, 1),
            Err(QuoteError::Overflow),
            "QuoteMicros overflow"
        );
    }

    #[test]
    fn provider_profile_reserve_micros_uses_higher_signed_spend_and_rejects_hard_limit() {
        let mut profile = empty_profile_for_contract();
        profile.hard_budget.spend_micros = 200;
        profile.input_token_price_micros = 3;
        profile.output_token_price_micros = 7;
        assert_eq!(profile.reserve_micros(11, 13, 90).expect("reserve"), 124);
        assert_eq!(profile.reserve_micros(1, 1, 200).expect("reserve"), 200);
        assert_eq!(
            profile.reserve_micros(1, 1, 201),
            Err(QuoteError::ExceedsBudget),
            "selected budget exceeded"
        );
        assert_eq!(
            profile.reserve_micros(60, 3, 1),
            Err(QuoteError::ExceedsBudget),
            "quote exceeded"
        );
    }

    #[test]
    fn provider_profile_requires_complete_bounded_authority_fields() {
        let raw = valid_config();
        let edits: Vec<(&str, Vec<u8>)> = vec![
            (
                "missing input tokens",
                remove_object_field(&raw, "provider.default_budget.input_tokens"),
            ),
            (
                "missing price",
                remove_object_field(&raw, "provider.input_token_price_micros"),
            ),
            (
                "missing grant ttl",
                remove_object_field(&raw, "provider.local_grant_ttl_seconds"),
            ),
            (
                "default exceeds hard",
                replace_object_field(
                    &raw,
                    "provider.default_budget.output_tokens",
                    Some(Value::from(200001)),
                ),
            ),
            (
                "zero grant ttl",
                replace_object_field(
                    &raw,
                    "provider.local_grant_ttl_seconds",
                    Some(Value::from(0)),
                ),
            ),
            (
                "unquotable hard budget",
                replace_object_field(
                    &raw,
                    "provider.input_token_price_micros",
                    Some(Value::from(1000000)),
                ),
            ),
        ];
        for (name, mutated) in edits {
            match parse(&mutated) {
                Err(err) => assert!(
                    matches!(err.kind(), ErrorKind::Semantic | ErrorKind::Schema),
                    "{name}: error kind = {:?}, want strict provider authority rejection",
                    err.kind()
                ),
                Ok(_) => {
                    unreachable!("{name}: parse accepted");
                }
            }
        }
    }

    fn empty_profile_for_contract() -> ProviderProfile {
        ProviderProfile {
            provider: String::new(),
            model: String::new(),
            destination: String::new(),
            method: String::new(),
            path: String::new(),
            policy_revision: String::new(),
            tool_revision: String::new(),
            price_data_revision: String::new(),
            secret_ref: String::new(),
            purpose: String::new(),
            protected_paths: vec![],
            default_budget: ProviderBudget {
                request_bytes: 0,
                response_bytes: 0,
                input_tokens: 0,
                output_tokens: 0,
                tool_calls_per_step: 0,
                tool_calls_per_run: 0,
                wall_time_seconds: 0,
                spend_micros: 0,
            },
            hard_budget: ProviderBudget {
                request_bytes: 0,
                response_bytes: 0,
                input_tokens: 0,
                output_tokens: 0,
                tool_calls_per_step: 0,
                tool_calls_per_run: 0,
                wall_time_seconds: 0,
                spend_micros: 0,
            },
            input_token_price_micros: 0,
            output_token_price_micros: 0,
            local_grant_ttl_seconds: 0,
            signature: String::new(),
        }
    }

    // ---------- workspace_projection_test.go (config half) ----------

    /// The config-side half of `TestParsedProviderProjectionPreservesRelativeProtectedPaths`:
    /// relative entries survive the signed-profile round trip through
    /// `parse` unchanged. The workspace-policy enumeration half needs
    /// the workspace adapter, out of Task 2 scope.
    #[test]
    fn parsed_provider_projection_preserves_relative_protected_paths() {
        let mut cfg = parse(&valid_config()).expect("parse fixture");
        cfg.provider.policy_revision = "policy-1".to_owned();
        cfg.provider.protected_paths = vec![
            "infra/private".to_owned(),
            "secrets".to_owned(),
            "terraform.tfstate".to_owned(),
        ];
        cfg.provider.signature = cfg.provider.canonical_digest();
        let raw = canonical(&serde_json::to_vec(&cfg).expect("marshal"));
        let parsed = parse(&raw).expect("parse relative provider fixture");
        assert_eq!(
            parsed.provider.protected_paths,
            vec![
                "infra/private".to_owned(),
                "secrets".to_owned(),
                "terraform.tfstate".to_owned()
            ]
        );
    }

    // ---------- view_test.go ----------

    #[test]
    fn parse_view_signature_accepts_fixed_canonical_vector() {
        let got = parse_view_signature(VIEW_VECTOR_ENVELOPE.as_bytes()).expect("parse");
        assert_eq!(got.schema_version, "central.view-signature/v1");
        assert_eq!(got.authoritative_config_digest, VIEW_VECTOR_DIGEST);
        assert_eq!(got.signing_key_id, VIEW_VECTOR_KEY_ID);
        assert_eq!(got.view_generation, 7);
        assert_eq!(got.signature, VIEW_VECTOR_SIG);
    }

    #[test]
    fn fixed_interoperability_vector_is_literal_and_reproducible() {
        let raw = valid_config();
        assert_ne!(
            raw, COMPLETE_CONFIG_FIXTURE,
            "B09 fixture lacks the required signed authority fields"
        );
        assert_eq!(canonical(&raw), raw, "B09 fixture is not JCS canonical");
        verify_view(&raw, &signed_benchmark_envelope(&raw), &vector_keyring())
            .expect("verify_view B09 fixture");
    }

    #[test]
    fn verify_view_rejects_signed_but_noncanonical_config_before_authentication() {
        let raw = [b" ".as_ref(), valid_config().as_slice()].concat();
        let envelope = signed_benchmark_envelope(&raw);
        parse_view_signature(&envelope).expect("canonical noncanonical-config envelope rejected");
        expect_kind(
            verify_view(&raw, &envelope, &vector_keyring()),
            ErrorKind::Semantic,
            "verify_view noncanonical",
        );
    }

    #[test]
    fn parse_view_signature_rejects_invalid_and_noncanonical_vectors() {
        let cases: Vec<(&str, String)> = vec![
            (
                "noncanonical whitespace",
                format!("{{ {}", &VIEW_VECTOR_ENVELOPE[1..]),
            ),
            (
                "missing field",
                VIEW_VECTOR_ENVELOPE.replacen(
                    &format!(",\"signature\":\"{VIEW_VECTOR_SIG}\""),
                    "",
                    1,
                ),
            ),
            (
                "extra field",
                VIEW_VECTOR_ENVELOPE.replacen(
                    ",\"view_generation\":7}",
                    ",\"view_generation\":7,\"extra\":1}",
                    1,
                ),
            ),
            (
                "schema version",
                VIEW_VECTOR_ENVELOPE.replacen(
                    "central.view-signature/v1",
                    "central.view-signature/v2",
                    1,
                ),
            ),
            (
                "instance ID",
                VIEW_VECTOR_ENVELOPE.replacen(
                    "019b0000-0000-7000-8000-000000000001",
                    "019B0000-0000-7000-8000-000000000001",
                    1,
                ),
            ),
            (
                "binding ID",
                VIEW_VECTOR_ENVELOPE.replacen(
                    "019b0000-0000-7000-8000-000000000101",
                    "not-a-uuid",
                    1,
                ),
            ),
            (
                "digest alphabet",
                VIEW_VECTOR_ENVELOPE.replacen(
                    VIEW_VECTOR_DIGEST,
                    &VIEW_VECTOR_DIGEST.to_uppercase(),
                    1,
                ),
            ),
            (
                "zero generation",
                VIEW_VECTOR_ENVELOPE.replacen(
                    ",\"view_generation\":7}",
                    ",\"view_generation\":0}",
                    1,
                ),
            ),
            (
                "empty key ID",
                VIEW_VECTOR_ENVELOPE.replacen(VIEW_VECTOR_KEY_ID, "", 1),
            ),
            (
                "long key ID",
                VIEW_VECTOR_ENVELOPE.replacen(VIEW_VECTOR_KEY_ID, &"k".repeat(129), 1),
            ),
            (
                "timestamp precision",
                VIEW_VECTOR_ENVELOPE.replacen("123456Z", "12345Z", 1),
            ),
            (
                "URL base64 alphabet",
                VIEW_VECTOR_ENVELOPE.replacen(
                    VIEW_VECTOR_SIG,
                    &VIEW_VECTOR_SIG.replacen('/', "_", 1),
                    1,
                ),
            ),
            (
                "padded base64",
                VIEW_VECTOR_ENVELOPE.replacen(
                    &format!("\"{VIEW_VECTOR_SIG}\""),
                    &format!("\"{VIEW_VECTOR_SIG}=\""),
                    1,
                ),
            ),
            (
                "short signature",
                VIEW_VECTOR_ENVELOPE.replacen(
                    VIEW_VECTOR_SIG,
                    &VIEW_VECTOR_SIG[..VIEW_VECTOR_SIG.len() - 1],
                    1,
                ),
            ),
        ];
        for (name, raw) in cases {
            assert!(
                parse_view_signature(raw.as_bytes()).is_err(),
                "{name}: parse_view_signature unexpectedly succeeded"
            );
        }
    }

    #[test]
    fn verify_view_authenticates_exact_bytes_and_projects_minimum_view() {
        let raw = valid_config();
        let verified = verify_view(&raw, &signed_benchmark_envelope(&raw), &vector_keyring())
            .expect("verify_view");
        assert_eq!(verified.generation(), 7);
        assert_eq!(
            verified.signed_at(),
            datetime!(2026-08-01 12:34:56.123456 UTC),
            "signed_at"
        );
        let metadata = verified.selector_metadata();
        assert_eq!(
            metadata.instance_id.to_string(),
            "019b0000-0000-7000-8000-000000000001"
        );
        assert_eq!(
            metadata.config_binding_id.to_string(),
            "019b0000-0000-7000-8000-000000000101"
        );
        assert_eq!(metadata.signing_key_id, VIEW_VECTOR_KEY_ID);
        let policy = verified.provider_policy();
        assert_eq!(policy.provider, "openai-responses");
        assert_eq!(policy.model, "gpt-5.6");
        assert_eq!(
            policy.destination,
            "https://api.openai.com:443/v1/responses"
        );
        assert_eq!(policy.method, "POST");
        assert_eq!(policy.path, "/v1/responses");
        assert!(!policy.policy_revision.is_empty());
        assert!(!policy.tool_revision.is_empty());
        assert!(!policy.price_data_revision.is_empty());
        assert_ne!(policy.default_budget.request_bytes, 0);
        assert_ne!(policy.default_budget.input_tokens, 0);
        assert_ne!(policy.hard_budget.spend_micros, 0);
        assert_ne!(policy.input_token_price_micros, 0);
        assert_ne!(policy.output_token_price_micros, 0);
        assert_ne!(policy.local_grant_ttl_seconds, 0);
        let serialized = serde_json::to_string(&verified).expect("marshal verified");
        assert_eq!(serialized, "{}", "VerifiedView JSON");
    }

    #[test]
    fn verify_view_rejects_before_key_lookup_for_bad_config_bytes() {
        let cases: Vec<(&str, Vec<u8>, ErrorKind)> = vec![
            (
                "invalid JSON",
                b"not json".to_vec(),
                ErrorKind::InvalidSyntax,
            ),
            (
                "oversized",
                [valid_config(), vec![b' '; 1 << 20]].concat(),
                ErrorKind::Limit,
            ),
            (
                "noncanonical",
                [b" ".as_ref(), valid_config().as_slice()].concat(),
                ErrorKind::Semantic,
            ),
        ];
        for (name, raw, want) in cases {
            let result = verify_view(
                &raw,
                VIEW_VECTOR_ENVELOPE.as_bytes(),
                &VerificationKeyring::default(),
            );
            assert!(result.is_err(), "{name}");
            assert_eq!(result.err().map(|e| e.kind()), Some(want), "{name}");
        }
    }

    #[test]
    fn verify_view_rejects_exact_byte_and_authentication_mutations() {
        let raw = valid_config();
        let mutated_config = [b" ".as_ref(), raw.as_slice()].concat();
        let envelope_bytes = signed_benchmark_envelope(&raw);
        let envelope = String::from_utf8(envelope_bytes).expect("envelope utf8");
        let digest_text = super::schema::hex_encode(&sha2::Sha256::digest(&raw));
        let cases: Vec<(&str, Vec<u8>, String, ErrorKind)> = vec![
            (
                "noncanonical config",
                mutated_config,
                envelope.clone(),
                ErrorKind::Semantic,
            ),
            (
                "digest mismatch",
                raw.clone(),
                envelope.replacen(&digest_text, &"0".repeat(64), 1),
                ErrorKind::Digest,
            ),
            (
                "unknown key",
                raw.clone(),
                envelope.clone(),
                ErrorKind::Keyring,
            ),
            (
                "signature mismatch",
                raw.clone(),
                envelope.replacen("\"view_generation\":7", "\"view_generation\":8", 1),
                ErrorKind::Signature,
            ),
        ];
        for (name, config_raw, envelope, want) in cases {
            let keys = if name == "unknown key" {
                VerificationKeyring::new(vec![]).expect("empty keyring")
            } else {
                vector_keyring()
            };
            let result = verify_view(&config_raw, envelope.as_bytes(), &keys);
            assert!(result.is_err(), "{name}");
            assert_eq!(result.err().map(|e| e.kind()), Some(want), "{name}");
        }
    }

    #[test]
    fn verification_keyring_validates_and_copies_keys() {
        let key = VerificationKey {
            id: VIEW_VECTOR_KEY_ID.to_owned(),
            public: VIEW_VECTOR_PUBLIC,
        };
        for (name, keys) in [
            ("duplicate", vec![key.clone(), key.clone()]),
            (
                "derived ID mismatch",
                vec![VerificationKey {
                    id: "wrong".to_owned(),
                    public: VIEW_VECTOR_PUBLIC,
                }],
            ),
            (
                "zero public key",
                vec![VerificationKey {
                    id: VIEW_VECTOR_KEY_ID.to_owned(),
                    public: [0u8; 32],
                }],
            ),
        ] {
            assert!(
                VerificationKeyring::new(keys).is_err(),
                "{name}: keyring accepted invalid input"
            );
        }
        // Upstream also mutates the input slice and the looked-up key —
        // stored copies must be unaffected. `new` consumes the vector
        // in Rust, so the "input slice" is a clone the caller keeps and
        // mutates after construction.
        let mut input = vec![key.clone()];
        let ring = VerificationKeyring::new(input.clone()).expect("keyring");
        input[0].id = "changed".to_owned();
        input[0].public[0] ^= 0xff;
        let got = ring.lookup(VIEW_VECTOR_KEY_ID).expect("lookup");
        assert_eq!(got, key, "ring did not copy input key");
        let mut got = got;
        got.public[0] ^= 0xff;
        let again = ring.lookup(VIEW_VECTOR_KEY_ID).expect("lookup");
        assert_eq!(again, key, "Lookup exposed mutable key state");
    }

    #[test]
    fn verify_view_binds_envelope_instance_to_typed_config() {
        let mutated = replace_object_field(
            &valid_config(),
            "instance_id",
            Some(Value::from("019b0000-0000-7000-8000-0000000000ff")),
        );
        let envelope = signed_benchmark_envelope(&mutated);
        expect_kind(
            verify_view(&mutated, &envelope, &vector_keyring()),
            ErrorKind::Semantic,
            "instance binding",
        );
    }

    #[test]
    fn verify_view_does_not_claim_binding_catalog_authority() {
        let raw = valid_config();
        let verified = verify_view(&raw, &signed_benchmark_envelope(&raw), &vector_keyring())
            .expect("verify_view");
        assert_eq!(verified.generation(), 7);
        let cfg = parse(&raw).expect("parse");
        let empty = BindingCatalog::default();
        expect_kind(
            validate_with_binding_catalog(&cfg, &empty),
            ErrorKind::Semantic,
            "ValidateWithBindingCatalog(empty)",
        );
    }

    /// The functional half of `TestViewBenchmarkMetricCeilings` — the
    /// limit-adjacent document parses and verifies. Go's
    /// `testing.Benchmark` allocation ceilings are not portable and are
    /// not ported.
    #[test]
    fn verify_limit_adjacent_config_functional() {
        let raw = make_limit_adjacent_config();
        assert!(raw.len() <= 1 << 20, "limit-adjacent config oversize");
        let envelope = signed_benchmark_envelope(&raw);
        verify_view(&raw, &envelope, &vector_keyring()).expect("verify limit adjacent");
        parse(&raw).expect("parse limit adjacent");
    }

    // Compile-time surface anchors so imports that only tests use are
    // not flagged dead when tests are not built.
    #[allow(dead_code)]
    fn surface_anchors() {
        let _ = schema::validate;
        let _ = view::parse_view_signature;
        let _ = defaults::config;
    }
}
