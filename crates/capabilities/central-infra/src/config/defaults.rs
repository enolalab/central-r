//! Genesis config rendering — port of upstream
//! `internal/config/defaults`.
//!
//! Holds what a new instance's authoritative configuration is built
//! from: a template embedded in the binary, the default provider
//! profile, and a versioned price table. Genesis (`central local init`,
//! and the reference-host harness that calls the same core) is its only
//! production caller. Nothing here reads the filesystem: every input
//! ships in the binary — the one exception is `/dev/urandom`, which is
//! the platform CSPRNG backing `crypto/rand` upstream.

use std::collections::HashMap;
use std::io::Read as _;

use serde::Deserialize;
use serde_json::Value;

use central_foundation::identity::InstanceId;

use super::schema::{ProviderProfile, parse, path_clean};

/// Names the embedded price table. It is recorded in the provider
/// profile's `price_data_revision`, so a configuration says which table
/// priced it.
pub const PRICE_TABLE_REVISION: &str = "default-prices-v1";

/// Marks every template value genesis must replace. A value that still
/// carries it after rendering is a defect, and [`config`] refuses it.
pub const PLACEHOLDER_PREFIX: &str = "@genesis:";

const CONFIG_TEMPLATE: &[u8] = include_bytes!("assets/config.template.json");
const PROVIDER_PROFILE: &[u8] = include_bytes!("assets/provider-profile.json");
const PRICE_TABLE: &[u8] = include_bytes!("assets/default-prices-v1.json");

/// The identity genesis renders a configuration for.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Instance {
    /// The new instance's canonical UUIDv7.
    pub instance_id: String,
    /// The instance's authoritative state root: the clean, absolute
    /// instance directory whose base name is `instance_id`.
    pub state_root: String,
}

/// The versioned per-token price table the default provider profile is
/// priced from.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceTable {
    pub revision: String,
    pub provider: String,
    pub model: String,
    pub input_token_price_micros: u64,
    pub output_token_price_micros: u64,
}

/// Genesis-rendering failures — the Rust port of upstream's `fmt.Errorf`
/// strings. Details never embed caller input beyond the placeholder
/// kind and the (already validated) parse error class.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultsError {
    /// `defaults: the instance id must be a canonical UUIDv7`
    InstanceId,
    /// `defaults: the state root must be the clean absolute instance directory`
    StateRoot,
    /// `defaults: price table ...`
    PriceTable(&'static str),
    /// `defaults: provider profile ...`
    ProviderProfile(&'static str),
    /// `defaults: config template ...`
    Template(&'static str),
    /// `defaults: placeholder "@genesis:<kind>" has no value here`
    Placeholder(String),
    /// `defaults: binding id: ...`
    BindingId(&'static str),
    /// `defaults: fingerprint: ...`
    Fingerprint(&'static str),
    /// `defaults: encode config: ...`
    Encode,
    /// `defaults: canonicalize config: ...`
    Canonicalize,
    /// `defaults: rendered config does not validate: config: invalid input`
    RenderedInvalid,
    /// `defaults: rendered config names another instance`
    InstanceMismatch,
}

impl std::fmt::Display for DefaultsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InstanceId => f.write_str("defaults: the instance id must be a canonical UUIDv7"),
            Self::StateRoot => f.write_str(
                "defaults: the state root must be the clean absolute instance directory",
            ),
            Self::PriceTable(detail) => write!(f, "defaults: price table: {detail}"),
            Self::ProviderProfile(detail) => write!(f, "defaults: provider profile: {detail}"),
            Self::Template(detail) => write!(f, "defaults: config template: {detail}"),
            Self::Placeholder(kind) => {
                write!(
                    f,
                    "defaults: placeholder \"{PLACEHOLDER_PREFIX}{kind}\" has no value here"
                )
            }
            Self::BindingId(detail) => write!(f, "defaults: binding id: {detail}"),
            Self::Fingerprint(detail) => write!(f, "defaults: fingerprint: {detail}"),
            Self::Encode => f.write_str("defaults: encode config: serialization failed"),
            Self::Canonicalize => f.write_str("defaults: canonicalize config: JCS failed"),
            Self::RenderedInvalid => {
                f.write_str("defaults: rendered config does not validate: config: invalid input")
            }
            Self::InstanceMismatch => {
                f.write_str("defaults: rendered config names another instance")
            }
        }
    }
}

impl std::error::Error for DefaultsError {}

/// Decodes the embedded price table and refuses one that is not the
/// revision this binary names or that prices a token at zero —
/// upstream `Prices`.
pub fn prices() -> Result<PriceTable, DefaultsError> {
    let table: PriceTable = serde_json::from_slice(PRICE_TABLE)
        .map_err(|_| DefaultsError::PriceTable("invalid JSON or unexpected fields"))?;
    if table.revision != PRICE_TABLE_REVISION
        || table.provider.is_empty()
        || table.model.is_empty()
        || table.input_token_price_micros == 0
        || table.output_token_price_micros == 0
    {
        return Err(DefaultsError::PriceTable(
            "is not the embedded default revision",
        ));
    }
    Ok(table)
}

/// Renders the canonical (JCS) authoritative configuration of a new
/// instance — upstream `defaults.Config`. The embedded template is
/// bound to the instance's identity and paths, fresh UUIDv7 binding
/// IDs, fresh random TLS fingerprints (the configuration only validates
/// their format; the broker mints and serves its own TLS material), and
/// the default provider profile priced from the embedded table and
/// signed with its canonical digest. The result has passed
/// [`super::parse`].
pub fn config(instance: &Instance) -> Result<Vec<u8>, DefaultsError> {
    if InstanceId::parse(&instance.instance_id).is_err() {
        return Err(DefaultsError::InstanceId);
    }
    if !instance.state_root.starts_with('/')
        || path_clean(&instance.state_root) != instance.state_root
        || instance.state_root.rsplit('/').next() != Some(instance.instance_id.as_str())
    {
        return Err(DefaultsError::StateRoot);
    }
    let prices = prices()?;
    let provider = signed_provider(&prices)?;
    let mut document = decode_object(CONFIG_TEMPLATE).map_err(DefaultsError::Template)?;
    if document.get("provider") != Some(&Value::String(format!("{PLACEHOLDER_PREFIX}provider"))) {
        return Err(DefaultsError::Template(
            "does not delegate the provider profile",
        ));
    }
    if let Some(root) = document.as_object_mut() {
        root.insert("provider".to_owned(), provider);
    }
    let state_root = instance.state_root.clone();
    let producers: HashMap<&'static str, Producer> = HashMap::from([
        (
            "instance_id",
            constant(Value::String(instance.instance_id.clone())),
        ),
        (
            "state_root",
            constant(Value::String(instance.state_root.clone())),
        ),
        (
            "data_root",
            constant(Value::String(format!("{state_root}/data"))),
        ),
        (
            "backup_root",
            constant(Value::String(format!("{state_root}/backups"))),
        ),
        ("binding", Box::new(new_binding_id) as Producer),
        ("fingerprint", Box::new(new_fingerprint) as Producer),
    ]);
    let rendered = substitute(document, &producers)?;
    let marshaled = serde_json::to_vec(&rendered).map_err(|_| DefaultsError::Encode)?;
    let raw = central_foundation::jcs::canonicalize(
        &serde_json::from_slice(&marshaled).map_err(|_| DefaultsError::Encode)?,
    )
    .map_err(|_| DefaultsError::Canonicalize)?;
    let cfg = parse(&raw).map_err(|_| DefaultsError::RenderedInvalid)?;
    if cfg.instance_id.to_string() != instance.instance_id
        || cfg.paths.authoritative_state_root != instance.state_root
    {
        return Err(DefaultsError::InstanceMismatch);
    }
    Ok(raw)
}

/// A placeholder producer — `func() (any, error)` upstream.
type Producer = Box<dyn Fn() -> Result<Value, DefaultsError>>;

/// Returns a producer that yields the same value every time.
fn constant(value: Value) -> Producer {
    Box::new(move || Ok(value.clone()))
}

/// Upstream `signedProvider` — fills the default provider profile from
/// the price table and signs it with its canonical digest, the same
/// value [`super::parse`] verifies.
fn signed_provider(prices: &PriceTable) -> Result<Value, DefaultsError> {
    let mut provider = decode_object(PROVIDER_PROFILE).map_err(DefaultsError::ProviderProfile)?;
    let object = provider
        .as_object_mut()
        .ok_or(DefaultsError::ProviderProfile("not a JSON object"))?;
    if object.get("provider") != Some(&Value::String(prices.provider.clone()))
        || object.get("model") != Some(&Value::String(prices.model.clone()))
    {
        return Err(DefaultsError::ProviderProfile(
            "the price table prices another provider or model",
        ));
    }
    if object.get("signature") != Some(&Value::String(format!("{PLACEHOLDER_PREFIX}signature"))) {
        return Err(DefaultsError::ProviderProfile(
            "provider profile carries a fixed signature",
        ));
    }
    object.remove("signature");
    let producers: HashMap<&'static str, Producer> = HashMap::from([
        (
            "price_data_revision",
            constant(Value::String(prices.revision.clone())),
        ),
        (
            "input_token_price_micros",
            constant(Value::from(prices.input_token_price_micros)),
        ),
        (
            "output_token_price_micros",
            constant(Value::from(prices.output_token_price_micros)),
        ),
    ]);
    let priced = substitute(provider, &producers)?;
    let raw =
        serde_json::to_vec(&priced).map_err(|_| DefaultsError::ProviderProfile("encode failed"))?;
    // Go `json.Unmarshal` leaves the absent signature at its zero value;
    // serde requires every struct field, so decode with the same
    // explicit empty signature. `canonical_digest` excludes it.
    let mut for_decode: Value = serde_json::from_slice(&raw)
        .map_err(|_| DefaultsError::ProviderProfile("decode failed"))?;
    if let Some(object) = for_decode.as_object_mut() {
        object.insert("signature".to_owned(), Value::String(String::new()));
    }
    let profile: ProviderProfile = serde_json::from_value(for_decode)
        .map_err(|_| DefaultsError::ProviderProfile("decode failed"))?;
    let digest = profile.canonical_digest();
    if digest.is_empty() {
        return Err(DefaultsError::ProviderProfile(
            "provider profile has no canonical digest",
        ));
    }
    let mut provider = priced;
    if let Some(object) = provider.as_object_mut() {
        object.insert("signature".to_owned(), Value::String(digest));
    }
    Ok(provider)
}

/// Upstream `substitute` — replaces every `"@genesis:<kind>"` string in
/// `node` with a value produced for that kind, and refuses a kind the
/// caller did not supply.
fn substitute(
    node: Value,
    producers: &HashMap<&'static str, Producer>,
) -> Result<Value, DefaultsError> {
    match node {
        Value::Object(map) => {
            let mut replaced = serde_json::Map::with_capacity(map.len());
            for (key, child) in map {
                replaced.insert(key, substitute(child, producers)?);
            }
            Ok(Value::Object(replaced))
        }
        Value::Array(items) => {
            let mut replaced = Vec::with_capacity(items.len());
            for child in items {
                replaced.push(substitute(child, producers)?);
            }
            Ok(Value::Array(replaced))
        }
        Value::String(text) => {
            let Some(kind) = text.strip_prefix(PLACEHOLDER_PREFIX) else {
                return Ok(Value::String(text));
            };
            let produce = producers
                .get(kind)
                .ok_or_else(|| DefaultsError::Placeholder(kind.to_owned()))?;
            produce()
        }
        other => Ok(other),
    }
}

/// Upstream `decodeObject` — one complete JSON object, no trailing data.
fn decode_object(raw: &[u8]) -> Result<Value, &'static str> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| "invalid JSON")?;
    if !value.is_object() {
        return Err("not a JSON object");
    }
    Ok(value)
}

/// Upstream `newBindingID` — a fresh canonical UUIDv7.
fn new_binding_id() -> Result<Value, DefaultsError> {
    Ok(Value::String(InstanceId::new().to_string()))
}

/// Upstream `newFingerprint` — 32 CSPRNG bytes as lowercase hex. The
/// platform CSPRNG is `/dev/urandom`, the same source `crypto/rand`
/// reads on Linux.
fn new_fingerprint() -> Result<Value, DefaultsError> {
    let mut raw = [0u8; 32];
    let mut file = std::fs::File::open("/dev/urandom")
        .map_err(|_| DefaultsError::Fingerprint("open /dev/urandom"))?;
    file.read_exact(&mut raw)
        .map_err(|_| DefaultsError::Fingerprint("read /dev/urandom"))?;
    Ok(Value::String(super::schema::hex_encode(&raw)))
}

#[cfg(test)]
mod tests {
    //! Port of upstream `defaults/defaults_test.go`.

    use super::*;
    use crate::config::Config;
    use crate::config::testutil::canonical;

    fn test_instance() -> Instance {
        let id = InstanceId::new().to_string();
        Instance {
            state_root: format!("/var/lib/central-state/v1/instances/{id}"),
            instance_id: id,
        }
    }

    /// The eleven protected-binding references a configuration carries,
    /// in the order `validateBindingUniqueness` names them.
    fn binding_ids(cfg: &Config) -> [&str; 11] {
        [
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
        ]
    }

    #[test]
    fn config_renders_a_canonical_config_bound_to_the_instance() {
        let instance = test_instance();
        let raw = config(&instance).expect("config render");
        assert_eq!(canonical(&raw), raw, "rendered config is not JCS canonical");
        assert!(
            !String::from_utf8_lossy(&raw).contains(PLACEHOLDER_PREFIX),
            "rendered config still carries a genesis placeholder"
        );
        let cfg = parse(&raw).expect("rendered config does not parse");
        assert_eq!(cfg.instance_id.to_string(), instance.instance_id);
        assert_eq!(cfg.paths.authoritative_state_root, instance.state_root);
        assert_eq!(
            cfg.paths.instance_data_root,
            format!("{}/data", instance.state_root)
        );
        assert_eq!(
            cfg.paths.backup_repository_root,
            format!("{}/backups", instance.state_root)
        );
        for binding in binding_ids(&cfg) {
            assert!(
                InstanceId::parse(binding).is_ok(),
                "binding {binding} is not a UUIDv7"
            );
        }
        assert_ne!(
            cfg.http.tls.ca_fingerprint_sha256, cfg.http.tls.leaf_fingerprint_sha256,
            "the CA and leaf fingerprints are the same value"
        );
        let provider = &cfg.provider;
        assert_eq!(provider.signature, provider.canonical_digest());
        assert_eq!(provider.secret_ref, "openai_api_key");
        assert_eq!(provider.price_data_revision, PRICE_TABLE_REVISION);
        assert_eq!(provider.input_token_price_micros, 1);
        assert_eq!(provider.output_token_price_micros, 3);
        for (name, tool) in [
            ("pg_dump", &cfg.tools.pg_dump),
            ("pg_restore", &cfg.tools.pg_restore),
        ] {
            assert_eq!(tool.version, "16.14", "tools.{name}.version");
            assert_eq!(
                tool.path,
                format!("/usr/lib/postgresql/16/bin/{name}"),
                "tools.{name}.path"
            );
        }
    }

    #[test]
    fn config_mints_fresh_bindings_and_fingerprints_on_every_render() {
        let instance = test_instance();
        let first = parse(&config(&instance).expect("first render")).expect("first parse");
        let second = parse(&config(&instance).expect("second render")).expect("second parse");
        let first_ids = binding_ids(&first);
        let second_ids = binding_ids(&second);
        for (i, (a, b)) in first_ids.iter().zip(second_ids.iter()).enumerate() {
            assert_ne!(a, b, "binding {i} was reused across renders: {a}");
        }
        assert_ne!(
            first.http.tls.ca_fingerprint_sha256, second.http.tls.ca_fingerprint_sha256,
            "a TLS CA fingerprint was reused across renders"
        );
        assert_ne!(
            first.http.tls.leaf_fingerprint_sha256, second.http.tls.leaf_fingerprint_sha256,
            "a TLS leaf fingerprint was reused across renders"
        );
    }

    #[test]
    fn config_refuses_an_identity_it_cannot_bind() {
        let valid = test_instance();
        let cases: Vec<(&str, Instance)> = vec![
            (
                "not a uuid",
                Instance {
                    instance_id: "instance".to_owned(),
                    state_root: "/var/lib/central-state/v1/instances/instance".to_owned(),
                },
            ),
            (
                "uuid v4",
                Instance {
                    instance_id: "5b2c1f7e-8d1a-4c3b-9e2f-1a2b3c4d5e6f".to_owned(),
                    state_root:
                        "/var/lib/central-state/v1/instances/5b2c1f7e-8d1a-4c3b-9e2f-1a2b3c4d5e6f"
                            .to_owned(),
                },
            ),
            (
                "relative state root",
                Instance {
                    instance_id: valid.instance_id.clone(),
                    state_root: format!("instances/{}", valid.instance_id),
                },
            ),
            (
                "unclean state root",
                Instance {
                    instance_id: valid.instance_id.clone(),
                    state_root: format!(
                        "/var/lib/central-state/v1/instances/{}/",
                        valid.instance_id
                    ),
                },
            ),
            (
                "another instance root",
                Instance {
                    instance_id: valid.instance_id.clone(),
                    state_root: "/var/lib/central-state/v1/instances/other".to_owned(),
                },
            ),
        ];
        for (name, instance) in cases {
            assert!(
                config(&instance).is_err(),
                "{name}: config accepted {instance:?}"
            );
        }
    }

    #[test]
    fn prices_are_the_embedded_default_table() {
        let table = prices().expect("prices");
        assert_eq!(
            table,
            PriceTable {
                revision: "default-prices-v1".to_owned(),
                provider: "openai-responses".to_owned(),
                model: "gpt-5.6".to_owned(),
                input_token_price_micros: 1,
                output_token_price_micros: 3,
            }
        );
    }

    /// Pins the template's placeholder census, so a value genesis must
    /// mint cannot be committed as a fixed literal (every host would
    /// share it) and a new placeholder cannot be added without a
    /// producer — upstream
    /// `TestTheTemplateMarksExactlyTheValuesGenesisReplaces`.
    #[test]
    fn template_marks_exactly_the_values_genesis_replaces() {
        let template = String::from_utf8_lossy(CONFIG_TEMPLATE);
        let profile = String::from_utf8_lossy(PROVIDER_PROFILE);
        let want: &[(&str, usize)] = &[
            ("instance_id", 1),
            ("state_root", 1),
            ("data_root", 1),
            ("backup_root", 1),
            ("binding", 11),
            ("fingerprint", 2),
            ("provider", 1),
        ];
        let mut total = 0usize;
        for (kind, count) in want {
            let needle = format!("\"{PLACEHOLDER_PREFIX}{kind}\"");
            assert_eq!(
                template.matches(&needle).count(),
                *count,
                "template placeholder count for {kind}"
            );
            total += count;
        }
        assert_eq!(
            template.matches(PLACEHOLDER_PREFIX).count(),
            total,
            "template total placeholder count"
        );
        for (kind, count) in [
            ("price_data_revision", 1),
            ("input_token_price_micros", 1),
            ("output_token_price_micros", 1),
            ("signature", 1),
        ] {
            let needle = format!("\"{PLACEHOLDER_PREFIX}{kind}\"");
            assert_eq!(
                profile.matches(&needle).count(),
                count,
                "provider profile placeholder count for {kind}"
            );
        }
        assert_eq!(
            profile.matches(PLACEHOLDER_PREFIX).count(),
            4,
            "provider profile total placeholder count"
        );
    }
}
