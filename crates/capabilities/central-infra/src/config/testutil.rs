//! Shared test helpers — ports of the upstream `*_test.go` support
//! functions. Only compiled for `cargo test`.

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::Error;
use super::schema::{BindingMetadata, Config, ProviderProfile, binding_purposes, parse};
use super::view::{VerificationKey, VerificationKeyring, base64_raw_std_encode};

/// The on-disk upstream fixture — incomplete B09 authority fields on
/// purpose; `complete_config_fixture` fills and re-signs it.
pub(crate) const COMPLETE_CONFIG_FIXTURE: &[u8] = include_bytes!("testdata/complete-config.json");

/// RFC 8785 canonical form of `raw` — upstream `canonical`/`mustCanonical`.
pub(crate) fn canonical(raw: &[u8]) -> Vec<u8> {
    let value: Value = serde_json::from_slice(raw).expect("canonicalize: parse");
    central_foundation::jcs::canonicalize(&value).expect("canonicalize: JCS")
}

/// Upstream `validConfig` — the fixture completed with B09 authority
/// values and a re-signed provider profile.
pub(crate) fn valid_config() -> Vec<u8> {
    complete_config_fixture(COMPLETE_CONFIG_FIXTURE)
}

/// Upstream `completeConfigFixture` — produces the canonical
/// B09-authority test snapshot. Production parsing never supplies these
/// values: an on-disk profile must contain every signed authority field
/// itself.
pub(crate) fn complete_config_fixture(raw: &[u8]) -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(raw).expect("fixture decodes");
    let provider = document
        .get_mut("provider")
        .and_then(Value::as_object_mut)
        .expect("provider object");
    let set_budget = |budget: &mut serde_json::Map<String, Value>, inputs: &[(&str, u64)]| {
        for (field, value) in inputs {
            budget.insert((*field).to_owned(), Value::from(*value));
        }
    };
    let default_budget = provider
        .get_mut("default_budget")
        .and_then(Value::as_object_mut)
        .expect("default_budget object");
    set_budget(
        default_budget,
        &[
            ("input_tokens", 10_000),
            ("output_tokens", 1_000),
            ("tool_calls_per_step", 5),
            ("tool_calls_per_run", 20),
            ("wall_time_seconds", 900),
        ],
    );
    let hard_budget = provider
        .get_mut("hard_budget")
        .and_then(Value::as_object_mut)
        .expect("hard_budget object");
    set_budget(
        hard_budget,
        &[
            ("input_tokens", 2_000_000),
            ("output_tokens", 200_000),
            ("tool_calls_per_step", 20),
            ("tool_calls_per_run", 100),
            ("wall_time_seconds", 86_400),
        ],
    );
    provider.insert("input_token_price_micros".to_owned(), Value::from(1));
    provider.insert("output_token_price_micros".to_owned(), Value::from(4));
    provider.insert("local_grant_ttl_seconds".to_owned(), Value::from(900));
    let profile: ProviderProfile =
        serde_json::from_value(Value::Object(provider.clone())).expect("provider decodes");
    provider.insert(
        "signature".to_owned(),
        Value::String(profile.canonical_digest()),
    );
    canonical(&serde_json::to_vec(&document).expect("encode fixture"))
}

/// Upstream `mutateObject` — `value` is the JSON fragment to assign; a
/// `None` value deletes the key unless `add` is set, in which case the
/// key is set to `null`.
pub(crate) fn mutate_object(raw: &[u8], path: &str, value: Option<Value>, add: bool) -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(raw).expect("decode fixture");
    let parts: Vec<&str> = path.split('.').collect();
    set_at(&mut document, &parts, value, add);
    canonical(&serde_json::to_vec(&document).expect("encode fixture mutation"))
}

fn set_at(node: &mut Value, parts: &[&str], value: Option<Value>, add: bool) {
    if parts.len() == 1 {
        let object = node.as_object_mut().expect("mutation parent is object");
        if add {
            object.insert(parts[0].to_owned(), value.unwrap_or(Value::Null));
        } else if let Some(v) = value {
            object.insert(parts[0].to_owned(), v);
        } else {
            object.remove(parts[0]);
        }
        return;
    }
    let child = node
        .get_mut(parts[0])
        .expect("mutation parent path must exist in fixture");
    set_at(child, &parts[1..], value, add);
}

/// Upstream `replaceObjectField`.
pub(crate) fn replace_object_field(raw: &[u8], path: &str, value: Option<Value>) -> Vec<u8> {
    mutate_object(raw, path, value, false)
}

/// Upstream `removeObjectField`.
pub(crate) fn remove_object_field(raw: &[u8], path: &str) -> Vec<u8> {
    mutate_object(raw, path, None, false)
}

/// Upstream `addObjectField`.
pub(crate) fn add_object_field(raw: &[u8], path: &str, value: Option<Value>) -> Vec<u8> {
    mutate_object(raw, path, value, true)
}

/// Upstream `replaceWorkspaceRootField` — sets or deletes (`None`) one
/// field on the first workspace root, inserting a default root when the
/// array is empty.
pub(crate) fn replace_workspace_root_field(
    raw: &[u8],
    field: &str,
    value: Option<Value>,
) -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(raw).expect("decode fixture");
    let roots = document
        .get_mut("paths")
        .and_then(|p| p.get_mut("workspace_roots"))
        .and_then(Value::as_array_mut)
        .expect("paths.workspace_roots array");
    if roots.is_empty() {
        roots.push(serde_json::json!({
            "root_id": "019b0000-0000-7000-8000-000000000010",
            "path": "/workspace"
        }));
    }
    let object = roots[0].as_object_mut().expect("workspace root object");
    match value {
        Some(v) => {
            object.insert(field.to_owned(), v);
        }
        None => {
            object.remove(field);
        }
    }
    canonical(&serde_json::to_vec(&document).expect("encode workspace root mutation"))
}

/// Upstream `mustJSON`.
pub(crate) fn must_json<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("must_json marshal")
}

/// Upstream `mustProvider`.
pub(crate) fn must_provider(raw: &[u8]) -> ProviderProfile {
    parse(raw).expect("must_provider parse").provider
}

/// The eleven protected-binding metadata entries, in the order
/// `validateBindingUniqueness` names them — upstream `bindingMetadata`.
pub(crate) fn binding_metadata(cfg: &Config) -> Vec<BindingMetadata> {
    use binding_purposes::*;
    let instance_id = cfg.instance_id;
    vec![
        BindingMetadata {
            binding_id: cfg.http.tls.binding_id.clone(),
            purpose: APPLICATION_TLS.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.postgres.bindings.server_admin.clone(),
            purpose: POSTGRES_SERVER_ADMIN.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.postgres.bindings.runtime.clone(),
            purpose: POSTGRES_RUNTIME.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.postgres.bindings.outbox.clone(),
            purpose: POSTGRES_OUTBOX.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.postgres.bindings.migration.clone(),
            purpose: POSTGRES_MIGRATION.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.object_store.bindings.root.clone(),
            purpose: MINIO_ROOT.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.object_store.bindings.runtime.clone(),
            purpose: MINIO_RUNTIME.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.object_store.bindings.backup.clone(),
            purpose: MINIO_BACKUP.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.object_store.bindings.restore.clone(),
            purpose: MINIO_RESTORE.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.protected_store.binding_root_id.clone(),
            purpose: UNSPECIFIED.to_owned(),
            instance_id,
        },
        BindingMetadata {
            binding_id: cfg.bootstrap_session.binding_id.clone(),
            purpose: BOOTSTRAP.to_owned(),
            instance_id,
        },
    ]
}

/// `operatorModeFields` upstream — every `operator_modes` numeric leaf.
pub(crate) const OPERATOR_MODE_FIELDS: &[&str] = &[
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
];

/// Upstream `prefixedPaths`.
pub(crate) fn prefixed_paths(prefix: &str, fields: &[&str]) -> Vec<String> {
    fields.iter().map(|f| format!("{prefix}.{f}")).collect()
}

/// Upstream `numericFieldPaths` (public-test list — all numeric leaves
/// incl. full provider budget and price fields).
pub(crate) fn numeric_field_paths() -> Vec<String> {
    let mut paths: Vec<String> = vec![
        "http.application.port".into(),
        "http.operations.port".into(),
        "http.non_streaming.active".into(),
        "http.non_streaming.waiters".into(),
        "http.non_streaming.admission_wait_ms".into(),
        "http.non_streaming.api_buffer_bytes".into(),
        "http.non_streaming.html_buffer_bytes".into(),
        "http.non_streaming.body_read_ms".into(),
        "http.non_streaming.response_write_ms".into(),
        "http.non_streaming.route_total_ms".into(),
        "http.max_header_bytes".into(),
        "http.max_header_value_bytes".into(),
        "http.read_header_ms".into(),
        "http.idle_ms".into(),
        "http.graceful_shutdown_ms".into(),
        "postgres.port".into(),
        "postgres.pools.runtime_general".into(),
        "postgres.pools.runtime_settlement".into(),
        "postgres.pools.outbox".into(),
        "postgres.pools.cleanup".into(),
        "postgres.pools.serve_lock_control".into(),
        "postgres.pools.coexisting_read_only".into(),
        "postgres.pools.offline_mutation".into(),
        "postgres.timeouts.pool_acquire_ms".into(),
        "postgres.timeouts.statement_ms".into(),
        "postgres.timeouts.lock_ms".into(),
        "postgres.timeouts.transaction_ms".into(),
        "postgres.timeouts.idle_in_transaction_ms".into(),
        "postgres.timeouts.connection_lifetime_ms".into(),
        "object_store.port".into(),
        "protected_store.max_secret_bytes".into(),
        "protected_store.resolve_ms".into(),
        "protected_store.candidate_cleanup_age_ms".into(),
        "protected_store.retired_cleanup_age_ms".into(),
        "bootstrap_session.token_bits".into(),
        "bootstrap_session.presentation_ms".into(),
        "bootstrap_session.throttle_failures".into(),
        "bootstrap_session.throttle_window_ms".into(),
        "bootstrap_session.first_use_ms".into(),
        "bootstrap_session.idle_ms".into(),
        "bootstrap_session.absolute_ms".into(),
        "artifact.active_transfers".into(),
        "artifact.waiters".into(),
        "artifact.admission_wait_ms".into(),
        "artifact.copy_buffer_bytes".into(),
        "artifact.stream_idle_ms".into(),
        "artifact.stream_total_ms".into(),
    ];
    paths.extend(prefixed_paths("operator_modes", OPERATOR_MODE_FIELDS));
    for tail in [
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
        "provider.default_budget.request_bytes",
        "provider.default_budget.response_bytes",
        "provider.default_budget.input_tokens",
        "provider.default_budget.output_tokens",
        "provider.default_budget.tool_calls_per_step",
        "provider.default_budget.tool_calls_per_run",
        "provider.default_budget.wall_time_seconds",
        "provider.default_budget.spend_micros",
        "provider.hard_budget.request_bytes",
        "provider.hard_budget.response_bytes",
        "provider.hard_budget.input_tokens",
        "provider.hard_budget.output_tokens",
        "provider.hard_budget.tool_calls_per_step",
        "provider.hard_budget.tool_calls_per_run",
        "provider.hard_budget.wall_time_seconds",
        "provider.hard_budget.spend_micros",
        "provider.input_token_price_micros",
        "provider.output_token_price_micros",
        "provider.local_grant_ttl_seconds",
    ] {
        paths.push(tail.into());
    }
    paths
}

/// Upstream `numericFieldPathsForGate` — the internal gate-test list
/// (provider budget subset, no price fields).
pub(crate) fn numeric_field_paths_for_gate() -> Vec<String> {
    let mut paths: Vec<String> = vec![
        "http.application.port".into(),
        "http.operations.port".into(),
        "http.non_streaming.active".into(),
        "http.non_streaming.waiters".into(),
        "http.non_streaming.admission_wait_ms".into(),
        "http.non_streaming.api_buffer_bytes".into(),
        "http.non_streaming.html_buffer_bytes".into(),
        "http.non_streaming.body_read_ms".into(),
        "http.non_streaming.response_write_ms".into(),
        "http.non_streaming.route_total_ms".into(),
        "http.max_header_bytes".into(),
        "http.max_header_value_bytes".into(),
        "http.read_header_ms".into(),
        "http.idle_ms".into(),
        "http.graceful_shutdown_ms".into(),
        "postgres.port".into(),
        "postgres.pools.runtime_general".into(),
        "postgres.pools.runtime_settlement".into(),
        "postgres.pools.outbox".into(),
        "postgres.pools.cleanup".into(),
        "postgres.pools.serve_lock_control".into(),
        "postgres.pools.coexisting_read_only".into(),
        "postgres.pools.offline_mutation".into(),
        "postgres.timeouts.pool_acquire_ms".into(),
        "postgres.timeouts.statement_ms".into(),
        "postgres.timeouts.lock_ms".into(),
        "postgres.timeouts.transaction_ms".into(),
        "postgres.timeouts.idle_in_transaction_ms".into(),
        "postgres.timeouts.connection_lifetime_ms".into(),
        "object_store.port".into(),
        "protected_store.max_secret_bytes".into(),
        "protected_store.resolve_ms".into(),
        "protected_store.candidate_cleanup_age_ms".into(),
        "protected_store.retired_cleanup_age_ms".into(),
        "bootstrap_session.token_bits".into(),
        "bootstrap_session.presentation_ms".into(),
        "bootstrap_session.throttle_failures".into(),
        "bootstrap_session.throttle_window_ms".into(),
        "bootstrap_session.first_use_ms".into(),
        "bootstrap_session.idle_ms".into(),
        "bootstrap_session.absolute_ms".into(),
        "artifact.active_transfers".into(),
        "artifact.waiters".into(),
        "artifact.admission_wait_ms".into(),
        "artifact.copy_buffer_bytes".into(),
        "artifact.stream_idle_ms".into(),
        "artifact.stream_total_ms".into(),
    ];
    paths.extend(prefixed_paths("operator_modes", OPERATOR_MODE_FIELDS));
    for tail in [
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
        "provider.default_budget.request_bytes",
        "provider.default_budget.response_bytes",
        "provider.default_budget.spend_micros",
        "provider.hard_budget.request_bytes",
        "provider.hard_budget.response_bytes",
        "provider.hard_budget.spend_micros",
    ] {
        paths.push(tail.into());
    }
    paths
}

// ---- Signed-view vectors (upstream `view_test.go` constants) ----

pub(crate) const VIEW_VECTOR_DIGEST: &str =
    "04f1267e277e02b4c348197e980ce26c95da475ac3dc3a17cea94a975d4ce607";
pub(crate) const VIEW_VECTOR_KEY_ID: &str =
    "central.view-signing/v1:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
pub(crate) const VIEW_VECTOR_SIG: &str =
    "kD5W1HpX8O0oeYIF9y4yTvncYc3X++/duN5EqyWHRs5P1EQL90iymmOgtStMyHjsmXTAJJDEBJzWznH+beAHDA";
pub(crate) const VIEW_VECTOR_ENVELOPE: &str = "{\"authoritative_config_digest\":\"04f1267e277e02b4c348197e980ce26c95da475ac3dc3a17cea94a975d4ce607\",\"config_binding_id\":\"019b0000-0000-7000-8000-000000000101\",\"instance_id\":\"019b0000-0000-7000-8000-000000000001\",\"schema_version\":\"central.view-signature/v1\",\"signature\":\"kD5W1HpX8O0oeYIF9y4yTvncYc3X++/duN5EqyWHRs5P1EQL90iymmOgtStMyHjsmXTAJJDEBJzWznH+beAHDA\",\"signed_at\":\"2026-08-01T12:34:56.123456Z\",\"signing_key_id\":\"central.view-signing/v1:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9\",\"view_generation\":7}";

/// The instrumentation envelope — signed over the raw on-disk fixture
/// (`c0fb8120...` is its SHA-256), so verification reaches Ed25519.
pub(crate) const INSTRUMENTATION_ENVELOPE: &str = "{\"authoritative_config_digest\":\"c0fb8120f74c08e83d2240914b48ad799da01095d341efcd98e21a5057335b1c\",\"config_binding_id\":\"019b0000-0000-7000-8000-000000000101\",\"instance_id\":\"019b0000-0000-7000-8000-000000000001\",\"schema_version\":\"central.view-signature/v1\",\"signature\":\"YpTK3L/ESoNKE3i4V23fb2gHNidlXYygQAQxzOU05xWJ1yeDfQjB3OMcjYThecs4Hze03mWORS6Q1hMIX7n8Ag\",\"signed_at\":\"2026-08-01T12:34:56.123456Z\",\"signing_key_id\":\"central.view-signing/v1:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9\",\"view_generation\":7}";

/// Signed over `b" " + fixture` — a valid envelope for a non-canonical
/// payload.
pub(crate) const SIGNED_NONCANONICAL_ENVELOPE: &str = "{\"authoritative_config_digest\":\"6ff11175ea691616b136ed3906c8014eb6834a2b4393d30ee830ea8a31af8172\",\"config_binding_id\":\"019b0000-0000-7000-8000-000000000101\",\"instance_id\":\"019b0000-0000-7000-8000-000000000001\",\"schema_version\":\"central.view-signature/v1\",\"signature\":\"xytLh6X61z4b3zuZxwXFvfMoVdKxXXSyG7aQWw8F/pwp8nN+7SUpQCef4I0HwHSq/hTMY8YvmcWcV/vmeQe2DA\",\"signed_at\":\"2026-08-01T12:34:56.123456Z\",\"signing_key_id\":\"central.view-signing/v1:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9\",\"view_generation\":7}";

pub(crate) const VIEW_VECTOR_PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

const VIEW_VECTOR_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Upstream `vectorKeyring`.
pub(crate) fn vector_keyring() -> VerificationKeyring {
    VerificationKeyring::new(vec![VerificationKey {
        id: VIEW_VECTOR_KEY_ID.to_owned(),
        public: VIEW_VECTOR_PUBLIC,
    }])
    .expect("vector keyring")
}

/// Upstream `signedBenchmarkEnvelope` — builds the unsigned envelope,
/// canonicalizes, signs `unsigned ++ 0x00 ++ config_raw` with the
/// vector seed, and re-canonicalizes.
pub(crate) fn signed_benchmark_envelope(config_raw: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::digest(config_raw).into();
    let mut unsigned = serde_json::json!({
        "authoritative_config_digest": super::schema::hex_encode(&digest),
        "config_binding_id": "019b0000-0000-7000-8000-000000000101",
        "instance_id": "019b0000-0000-7000-8000-000000000001",
        "schema_version": "central.view-signature/v1",
        "signed_at": "2026-08-01T12:34:56.123456Z",
        "signing_key_id": VIEW_VECTOR_KEY_ID,
        "view_generation": 7u64,
    });
    let canonical_unsigned =
        central_foundation::jcs::canonicalize(&unsigned).expect("canonicalize unsigned envelope");
    let private = SigningKey::from_bytes(&VIEW_VECTOR_SEED);
    let mut message = canonical_unsigned;
    message.push(0);
    message.extend_from_slice(config_raw);
    let signature = private.sign(&message);
    unsigned["signature"] = Value::String(base64_raw_std_encode(&signature.to_bytes()));
    central_foundation::jcs::canonicalize(&unsigned).expect("canonicalize signed envelope")
}

/// Upstream `makeLimitAdjacentConfig` — binary-searches a protected-path
/// padding size so the re-signed config lands just under the 1 MiB cap.
pub(crate) fn make_limit_adjacent_config() -> Vec<u8> {
    let cfg = parse(&valid_config()).expect("parse fixture");
    let make_candidate = |size: usize| -> Vec<u8> {
        let paths: Vec<String> = (0..32)
            .map(|i| format!("/protected/{i:02}{}", "a".repeat(size)))
            .collect();
        let mut candidate = cfg.clone();
        candidate.provider.protected_paths = paths;
        candidate.provider.signature = candidate.provider.canonical_digest();
        canonical(&serde_json::to_vec(&candidate).expect("marshal candidate"))
    };
    const TARGET: usize = (1 << 20) - 2048;
    let mut best: Vec<u8> = Vec::new();
    let (mut low, mut high) = (1000usize, 40000usize);
    while low <= high {
        let middle = low + (high - low) / 2;
        let candidate = make_candidate(middle);
        if candidate.len() < TARGET {
            best = candidate;
            low = middle + 1;
        } else {
            best = candidate;
            high = middle - 1;
        }
    }
    best
}

/// Port of upstream `baseConfigDocument` — a minimal valid-shaped
/// document for redaction tests.
pub(crate) fn base_config_document() -> serde_json::Map<String, Value> {
    serde_json::json!({
        "http": {
            "application": {"host": "127.0.0.1", "port": 8080},
            "operations": {"host": "127.0.0.1", "port": 9090}
        },
        "instance_id": "018f4e2c-0000-7000-8000-000000000001",
        "schema_version": "central.config/v1"
    })
    .as_object()
    .expect("base document object")
    .clone()
}

/// Port of upstream `providerDocument`.
pub(crate) fn provider_document(signature: &str) -> Value {
    serde_json::json!({
        "provider": "openai-responses",
        "model": "gpt-5.6",
        "destination": "https://api.openai.com:443/v1/responses",
        "method": "POST",
        "path": "/v1/responses",
        "policy_revision": "p1",
        "tool_revision": "t1",
        "price_data_revision": "prices-1",
        "secret_ref": "openai_api_key",
        "purpose": "provider_api_key_v1",
        "protected_paths": [],
        "default_budget": {"request_bytes": 1, "response_bytes": 1, "spend_micros": 1},
        "hard_budget": {"request_bytes": 1, "response_bytes": 1, "spend_micros": 1},
        "signature": signature
    })
}

/// Upstream `canonicalDocument` — marshal a map and canonicalize.
pub(crate) fn canonical_document(doc: &serde_json::Map<String, Value>) -> Vec<u8> {
    canonical(&serde_json::to_vec(doc).expect("marshal document"))
}

/// Assertion helper for the `errors.Is(err, kind)` pattern.
pub(crate) fn expect_kind<T>(result: Result<T, Error>, want: super::ErrorKind, what: &str) {
    assert!(result.is_err(), "{what}: expected an error, got success");
    let err = result.err().expect("checked is_err");
    assert_eq!(err.kind(), want, "{what}: error kind");
}
