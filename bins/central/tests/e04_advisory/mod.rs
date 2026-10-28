//! `e04_advisory_lifecycle_test.go` — the E04 conformance suite:
//! advisory lifecycle stages against externally produced signed
//! fixtures (spec:
//! docs/internal/superpowers/specs/2026-10-05-slice-e-e04-advisory-lifecycle.md).
//! Each fixture envelope is minted at suite start with an ephemeral
//! test keypair, written to a designated fixtures directory, then
//! consumed only through `VerifySnapshot` + `EvaluateVerified` +
//! `TransitionRecorder` against a real broker `Journal` — the same
//! wire path a production admission takes. Set
//! `CENTRAL_E04_EVIDENCE_DIR` to also emit
//! `slice-e-advisory-lifecycle.json` and copy the fixtures for
//! offline re-verification.

// Test-target relaxation, same as the other acceptance targets: a
// refused evaluation IS the assertion — unwrap/expect/panic are how a
// libtest body reports FailNow.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use central_adapter_linux::broker::journal::Journal;
use central_adapter_linux::broker::signing::{Ed25519Signer, SigningService};
use central_adapter_linux::infra::advisory_fetch::{
    AdvisoryJournalWriter, AdvisoryTransitionRecorder,
};
use central_adapter_linux::infra::lifecycle::block_on;
use central_foundation::failure::Failure;
use central_infra::advisory::{
    CompatibilityMatrix, DenyPolicy, HostFacts, Outcome, ReleaseTrust, Snapshot, State,
    TimeWitness, VerifiedBundle, Verifier,
};
use central_infra::authority::{AuthorityTransitionPayload, CommittedReceipt};
use central_infra::port::TransitionRecorder;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;

const E04_EVIDENCE_ENV: &str = "CENTRAL_E04_EVIDENCE_DIR";
const E04_KEY_ID: &str = "central-release-authority/e04-test";

/// `signedBundle` — the same shape `central-advisory-sign` marshals
/// (upstream keeps three copies — the tool, the dev bootstrap, and
/// this suite — that must never independently drift; all three share
/// the domain's `CompatibilityMatrix`/`DenyPolicy` field spellings).
#[derive(Serialize)]
struct SignedBundle {
    schema_version: i64,
    key_id: String,
    issued_at: String,
    expires_at: String,
    compatibility: CompatibilityMatrix,
    emergency_deny: DenyPolicy,
}

struct FixtureFields {
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    emergency: bool,
    deny_reason: String,
    compat: CompatibilityMatrix,
    /// Defaults to the suite key when `None`.
    signing_key: Option<SigningKey>,
    /// Defaults to [`E04_KEY_ID`] when empty.
    key_id: String,
    /// Sign, then corrupt — the `SIGNATURE_INVALID` path.
    mutate_sig: bool,
}

impl Default for FixtureFields {
    /// `OffsetDateTime` has no `Default`; scenarios always stamp both
    /// times through `valid(..)` — the epoch zeroes are unreachable.
    fn default() -> Self {
        Self {
            issued_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH,
            emergency: false,
            deny_reason: String::new(),
            compat: CompatibilityMatrix::default(),
            signing_key: None,
            key_id: String::new(),
            mutate_sig: false,
        }
    }
}

/// `e04MintFixture` replicates central-advisory-sign's bundle path
/// verbatim: canonical JCS bundle → sha256 →
/// `central.security-advisory/v1|bundle|SHA-256:<hex>` message →
/// `ed25519.Sign` → base64. A fixture that drifts from the tool's
/// wire format fails `verify_snapshot` loudly.
fn mint_fixture(f: &FixtureFields, suite_key: &SigningKey) -> Vec<u8> {
    let bundle = SignedBundle {
        schema_version: 1,
        key_id: if f.key_id.is_empty() {
            E04_KEY_ID.to_owned()
        } else {
            f.key_id.clone()
        },
        issued_at: f
            .issued_at
            .to_offset(time::UtcOffset::UTC)
            .replace_nanosecond(0)
            .expect("issued_at nanos")
            .format(&Rfc3339)
            .expect("issued_at"),
        expires_at: f
            .expires_at
            .to_offset(time::UtcOffset::UTC)
            .replace_nanosecond(0)
            .expect("expires_at nanos")
            .format(&Rfc3339)
            .expect("expires_at"),
        compatibility: f.compat.clone(),
        emergency_deny: DenyPolicy {
            emergency: f.emergency,
            reason: f.deny_reason.clone(),
        },
    };
    let raw = serde_json::to_vec(&bundle).expect("marshal bundle");
    let value: serde_json::Value = serde_json::from_slice(&raw).expect("bundle value");
    let canonical = central_foundation::jcs::canonicalize(&value).expect("canonicalize");
    let sum = Sha256::digest(&canonical);
    let message = format!(
        "central.security-advisory/v1|bundle|SHA-256:{}",
        hex_encode(&sum)
    );
    let signing = f.signing_key.as_ref().unwrap_or(suite_key);
    let mut sig = signing.sign(message.as_bytes()).to_bytes();
    if f.mutate_sig {
        sig[0] ^= 0xff;
    }
    #[derive(Serialize)]
    struct Envelope<'a> {
        bundle: &'a serde_json::value::RawValue,
        signature: String,
    }
    let bundle_raw =
        serde_json::value::RawValue::from_string(String::from_utf8(raw).expect("bundle utf8"))
            .expect("bundle raw");
    serde_json::to_vec(&Envelope {
        bundle: &bundle_raw,
        signature: b64_encode(&sig),
    })
    .expect("marshal envelope")
}

// Go `base64.StdEncoding` helpers — the suite's fixture path must not
// reach through a production codec (upstream uses the std library at
// both ends; here the codec is private to the suite).
fn b64_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let quad = [
            b[0] >> 2,
            ((b[0] & 0x03) << 4) | (b[1] >> 4),
            ((b[1] & 0x0f) << 2) | (b[2] >> 6),
            b[2] & 0x3f,
        ];
        for (i, idx) in quad.iter().enumerate() {
            out.push(if i > n { '=' } else { A[*idx as usize] as char });
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The in-process `broker.Journal` behind the `AdvisoryJournalWriter`
/// port — upstream `advisory.NewTransitionRecorder(journal)` takes the
/// real journal directly; the RPC client is the production *socket*
/// path, which this suite deliberately does not need.
struct DirectJournalWriter(Journal);

impl AdvisoryJournalWriter for DirectJournalWriter {
    /// `JournalWriter.AppendCommitted` — the writer stamps the record
    /// into the journal's own stream; sequence allocation and all
    /// provenance fields stay journal-owned exactly as over the wire.
    fn append_committed(
        &self,
        stream_id: &str,
        payload: &AuthorityTransitionPayload,
    ) -> Result<CommittedReceipt, Failure> {
        self.0.append_committed(stream_id, &mut payload.clone())
    }
}

struct Scenario {
    name: &'static str,
    fixture: FixtureFields,
    now: OffsetDateTime,
    facts: HostFacts,
    witness: TimeWitness,
    expected_state: State,
    expected_code: &'static str,
    expected_check: &'static str,
}

#[derive(Serialize)]
struct ScenarioEvidence {
    fixture: String,
    fixture_sha256: String,
    key_id: String,
    expected_state: String,
    expected_code: String,
    observed_state: String,
    observed_code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    observed_check: String,
    receipt_id: String,
    receipt_sequence: u64,
}

#[test]
fn e04_advisory_lifecycle_conformance() {
    let mut seed = [0u8; 32];
    rustix::rand::getrandom(&mut seed, rustix::rand::GetRandomFlags::empty())
        .expect("suite key entropy");
    let suite_key = SigningKey::from_bytes(&seed);
    let mut wrong_seed = [0u8; 32];
    rustix::rand::getrandom(&mut wrong_seed, rustix::rand::GetRandomFlags::empty())
        .expect("wrong key entropy");
    let wrong_key = SigningKey::from_bytes(&wrong_seed);
    let verifier = Verifier::for_testing(ReleaseTrust {
        key_id: E04_KEY_ID.to_owned(),
        protocol: "central.security-advisory/v1".to_owned(),
        public_key: suite_key.verifying_key().to_bytes(),
        release_authority_digest: String::new(),
    });

    let now = datetime!(2026-10-05 12:00:00 UTC);
    let compat = CompatibilityMatrix {
        os_release: "ubuntu-22.04".to_owned(),
        kernel: String::new(),
        docker: "27.x".to_owned(),
        compose: String::new(),
        psql: "16.x".to_owned(),
    };
    let matching = HostFacts {
        os_release: "ubuntu-22.04".to_owned(),
        kernel: String::new(),
        docker: "27.x".to_owned(),
        compose: String::new(),
        psql: "16.x".to_owned(),
    };

    let evidence_dir = std::env::var(E04_EVIDENCE_ENV).unwrap_or_default();
    let fixture_dir = if evidence_dir.is_empty() {
        std::env::temp_dir().join(format!("e04-fixtures-{}", std::process::id()))
    } else {
        Path::new(&evidence_dir).join("fixtures")
    };
    std::fs::create_dir_all(&fixture_dir).expect("fixture dir");

    let valid =
        |issued_hours: i64, expires_hours: i64, compat: CompatibilityMatrix| FixtureFields {
            issued_at: now + time::Duration::hours(issued_hours),
            expires_at: now + time::Duration::hours(expires_hours),
            compat,
            ..FixtureFields::default()
        };

    let scenarios = [
        Scenario {
            name: "current",
            fixture: valid(-24, 30 * 24, compat.clone()),
            now,
            facts: matching.clone(),
            witness: TimeWitness::default(),
            expected_state: State::Current,
            expected_code: "",
            expected_check: "",
        },
        Scenario {
            name: "stale-grace",
            fixture: valid(-40 * 24, -24, CompatibilityMatrix::default()),
            now,
            facts: HostFacts::default(),
            witness: TimeWitness::default(),
            expected_state: State::Stale,
            expected_code: "ADVISORY_EXPIRED",
            expected_check: "",
        },
        Scenario {
            name: "host-mismatch",
            fixture: valid(-24, 30 * 24, compat.clone()),
            now,
            facts: HostFacts {
                os_release: "debian-13".to_owned(),
                ..HostFacts::default()
            },
            witness: TimeWitness::default(),
            expected_state: State::Stale,
            expected_code: "ADVISORY_HOST_MISMATCH",
            expected_check: "os_release",
        },
        Scenario {
            name: "hard-expired",
            fixture: valid(-60 * 24, -30 * 24, CompatibilityMatrix::default()),
            now,
            facts: HostFacts::default(),
            witness: TimeWitness::default(),
            expected_state: State::HardExpired,
            expected_code: "ADVISORY_HARD_EXPIRED",
            expected_check: "",
        },
        Scenario {
            name: "emergency-deny",
            fixture: FixtureFields {
                emergency: true,
                deny_reason: "CVE-9999-0001".to_owned(),
                ..valid(-24, 30 * 24, CompatibilityMatrix::default())
            },
            now,
            facts: HostFacts::default(),
            witness: TimeWitness::default(),
            expected_state: State::Denied,
            expected_code: "EMERGENCY_DENY",
            expected_check: "",
        },
        Scenario {
            name: "bad-signature",
            fixture: FixtureFields {
                mutate_sig: true,
                ..valid(-24, 30 * 24, CompatibilityMatrix::default())
            },
            now,
            facts: HostFacts::default(),
            witness: TimeWitness::default(),
            expected_state: State::Denied,
            expected_code: "SIGNATURE_INVALID",
            expected_check: "",
        },
        Scenario {
            name: "wrong-key",
            fixture: FixtureFields {
                signing_key: Some(wrong_key),
                ..valid(-24, 30 * 24, CompatibilityMatrix::default())
            },
            now,
            facts: HostFacts::default(),
            witness: TimeWitness::default(),
            expected_state: State::Denied,
            expected_code: "SIGNATURE_INVALID",
            expected_check: "",
        },
        Scenario {
            name: "future-issued",
            fixture: valid(24, 60 * 24, CompatibilityMatrix::default()),
            now,
            facts: HostFacts::default(),
            witness: TimeWitness::default(),
            expected_state: State::Denied,
            expected_code: "INVALID_ADVISORY",
            expected_check: "",
        },
        Scenario {
            name: "witness-rollback",
            fixture: valid(-48, 30 * 24, CompatibilityMatrix::default()),
            now,
            facts: HostFacts::default(),
            witness: TimeWitness {
                last_accepted_at: Some(now),
                last_issued_at: Some(now),
            },
            expected_state: State::Denied,
            expected_code: "INVALID_ADVISORY",
            expected_check: "",
        },
    ];

    let journal = Journal::new(
        std::env::temp_dir().join(format!("e04-journal-{}", std::process::id())),
        Arc::new(SigningService::new()),
        Some(Arc::new(Ed25519Signer::new().expect("journal signer"))),
    );
    let recorder = AdvisoryTransitionRecorder::new(DirectJournalWriter(journal));

    let mut rows: Vec<ScenarioEvidence> = Vec::new();
    for sc in &scenarios {
        let env_bytes = mint_fixture(&sc.fixture, &suite_key);
        let path = fixture_dir.join(format!("{}.json", sc.name));
        std::fs::write(&path, &env_bytes).expect("write fixture");

        // Consume only through the file path — the fixture is external
        // to the verification path by construction.
        let consumed = std::fs::read(&path).expect("read fixture");
        #[derive(serde::Deserialize)]
        struct EnvelopeSig {
            #[serde(default)]
            signature: String,
        }
        let env: EnvelopeSig = serde_json::from_slice(&consumed)
            .unwrap_or_else(|e| panic!("{}: envelope does not parse: {e}", sc.name));
        let (vb, vres) = verifier.verify_snapshot(&Snapshot {
            generation_id: format!("e04-{}", sc.name),
            selector_digest: "e04".to_owned(),
            bundle: consumed.clone(),
            signature: env.signature.into_bytes(),
        });

        let mut recorded: Option<&VerifiedBundle> = None;
        let result: Outcome = if vres.state == State::Current {
            let bundle = vb.as_ref().expect("verified bundle on current");
            recorded = Some(bundle);
            verifier.evaluate_verified(bundle, &sc.facts, &sc.witness, sc.now)
        } else {
            vres
        };
        assert_eq!(
            (result.state, result.code.as_str()),
            (sc.expected_state, sc.expected_code),
            "{}: got state={} code={}",
            sc.name,
            result.state.as_str(),
            result.code.as_str()
        );
        if !sc.expected_check.is_empty() {
            assert_eq!(result.check, sc.expected_check, "{}: check", sc.name);
        }

        let receipt = block_on(recorder.record(&result, recorded, &sc.facts))
            .unwrap_or_else(|e| panic!("{}: journal record: {}", sc.name, e.message()));
        assert!(
            !receipt.id.is_empty() && receipt.sequence != 0,
            "{}: empty receipt {receipt:?}",
            sc.name
        );
        rows.push(ScenarioEvidence {
            fixture: format!("{}.json", sc.name),
            fixture_sha256: format!("sha256:{}", hex_encode(&Sha256::digest(&consumed))),
            key_id: E04_KEY_ID.to_owned(),
            expected_state: sc.expected_state.as_str().to_owned(),
            expected_code: sc.expected_code.to_owned(),
            observed_state: result.state.as_str().to_owned(),
            observed_code: result.code.as_str().to_owned(),
            observed_check: result.check.clone(),
            receipt_id: receipt.id,
            receipt_sequence: receipt.sequence,
        });
    }

    // Receipts must be strictly increasing — every scenario journaled
    // its own signed authority transition.
    for pair in rows.windows(2) {
        assert!(
            pair[1].receipt_sequence > pair[0].receipt_sequence,
            "receipt sequence not increasing: {:?} after {:?}",
            pair[1].receipt_sequence,
            pair[0].receipt_sequence
        );
    }

    if !evidence_dir.is_empty() {
        std::fs::create_dir_all(&evidence_dir).expect("evidence dir");
        #[derive(Serialize)]
        struct Evidence {
            schema_version: &'static str,
            suite_key_id: &'static str,
            suite_pubkey_base64: String,
            scenarios: Vec<ScenarioEvidence>,
        }
        let raw = serde_json::to_string_pretty(&Evidence {
            schema_version: "slice-e-advisory-lifecycle/v1",
            suite_key_id: E04_KEY_ID,
            suite_pubkey_base64: b64_encode(&suite_key.verifying_key().to_bytes()),
            scenarios: rows,
        })
        .expect("evidence marshal");
        std::fs::write(
            Path::new(&evidence_dir).join("slice-e-advisory-lifecycle.json"),
            format!("{raw}\n"),
        )
        .expect("evidence write");
    }
}

/// `TestE04ExclusionScan` fails if advisory runtime code grows the
/// signing ceremony E04 excludes: key minting or signing in the
/// advisory path. Other production signing (broker journal, TLS CA,
/// B02 attestation, portable bundles) is out of scope and untouched.
///
/// The Rust production seams map to upstream's `internal/advisory` and
/// `internal/adapter/advisory` trees as:
///
///   - `central_infra::advisory` (verify.go/evaluate.go/domain)
///   - `central_adapter_linux::infra::advisory_fetch` (source/facts/
///     witness/install/recorder — upstream's adapter dir)
///
/// Inline `#[cfg(test)]` modules are the `_test.go` exclusion — the
/// scan covers only the production region before them, exactly as
/// upstream's file filter does.
#[test]
fn e04_exclusion_scan() {
    let forbidden = ["SigningKey", "ed25519_dalek::Signer", ".sign("];
    let files = [
        "../../crates/capabilities/central-infra/src/advisory.rs",
        "../../crates/adapters/central-adapter-linux/src/infra/advisory_fetch.rs",
    ];
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in files {
        let path = manifest.join(rel);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("exclusion scan: read {}: {e}", path.display()));
        // `#[cfg(test)]` items are the `_test.go` exclusion — dropped
        // wherever they appear, including mid-file test-only helpers,
        // so the production tail after them stays scanned.
        let production = production_region(&raw);
        for token in forbidden {
            assert!(
                !production.contains(token),
                "{} contains forbidden advisory-ceremony token {token:?}",
                path.display()
            );
        }
    }
}

/// `production_region` — the source with every `#[cfg(test)]`-gated
/// item removed, wherever it appears. One lexical pass honors line
/// and block comments, `"…"`/`b"…"`/`r#"…"#` strings, char literals,
/// and lifetimes in both the scanned region and the dropped item, so
/// a `{`/`;`/`"` inside a literal can never desync the walk — and a
/// `#[cfg(test)]` inside a comment or string is never a marker.
fn production_region(raw: &str) -> String {
    const MARK: &str = "#[cfg(test)]";
    let bytes = raw.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < len {
        if let Some(end) = skip_lexeme(bytes, len, i) {
            out.push_str(&raw[i..end]);
            i = end;
            continue;
        }
        if bytes[i..].starts_with(MARK.as_bytes()) {
            i = skip_item(bytes, len, i + MARK.len());
            continue;
        }
        let c = raw[i..].chars().next().unwrap();
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// The lexical atoms the scanner never looks inside: comments,
/// string/byte-string/raw-string literals, and char literals
/// (lifetimes return `None`). Returns the index just past the token.
fn skip_lexeme(bytes: &[u8], len: usize, i: usize) -> Option<usize> {
    match bytes[i] {
        b'/' if bytes.get(i + 1) == Some(&b'/') => Some(
            bytes[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(len, |p| i + p),
        ),
        b'/' if bytes.get(i + 1) == Some(&b'*') => {
            // Rust block comments nest.
            let mut depth = 1usize;
            let mut j = i + 2;
            while depth > 0 && j + 1 < len {
                match (bytes[j], bytes[j + 1]) {
                    (b'/', b'*') => {
                        depth += 1;
                        j += 2;
                    }
                    (b'*', b'/') => {
                        depth -= 1;
                        j += 2;
                    }
                    _ => j += 1,
                }
            }
            Some(if depth == 0 { j } else { len })
        }
        b'"' => Some(skip_quoted(bytes, len, i + 1, b'"')),
        b'b' if bytes.get(i + 1) == Some(&b'"') => Some(skip_quoted(bytes, len, i + 2, b'"')),
        b'r' | b'b' => {
            // Raw strings `r"…"`, `r#"…"#`, `br#"…"#`: `r`/`br` +
            // `#`* + `"`, closed by `"` + the same `#` count.
            let mut k = i;
            if bytes[k] == b'b' && bytes.get(k + 1) == Some(&b'r') {
                k += 1;
            }
            if bytes.get(k) != Some(&b'r') {
                return None;
            }
            let mut h = k + 1;
            while bytes.get(h) == Some(&b'#') {
                h += 1;
            }
            if bytes.get(h) != Some(&b'"') {
                return None;
            }
            let hashes = h - (k + 1);
            let mut j = h + 1;
            while j < len {
                if bytes[j] == b'"'
                    && j + 1 + hashes <= len
                    && bytes[j + 1..j + 1 + hashes].iter().all(|&c| c == b'#')
                {
                    return Some(j + 1 + hashes);
                }
                j += 1;
            }
            Some(len)
        }
        b'\'' => {
            // Char literal `'x'`/`'\n'` vs lifetime `'a`: only a
            // closing quote one char (or escape) ahead counts.
            let mut j = i + 1;
            if bytes.get(j) == Some(&b'\\') {
                j += 1;
            }
            if bytes.get(j + 1) == Some(&b'\'') {
                Some(j + 2)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `"`/`'` body with `\` escaping; `start` sits just past the opener.
fn skip_quoted(bytes: &[u8], len: usize, start: usize, quote: u8) -> usize {
    let mut j = start;
    while j < len {
        match bytes[j] {
            b'\\' => j += 2,
            b if b == quote => return j + 1,
            _ => j += 1,
        }
    }
    len
}

/// The item following a `#[cfg(test)]` marker: trivia + signature
/// tokens until the first `{` (balanced body) or `;` (statement) at
/// bracket depth zero — a `;` inside `[u8; N]` or a generic bound
/// can never cut the head short.
fn skip_item(bytes: &[u8], len: usize, mut i: usize) -> usize {
    let mut depth = 0i64;
    loop {
        if let Some(end) = skip_lexeme(bytes, len, i) {
            i = end;
            continue;
        }
        match bytes.get(i) {
            None => return len,
            Some(b'(' | b'[' | b'<') => {
                depth += 1;
                i += 1;
            }
            Some(b')' | b']' | b'>') => {
                depth -= 1;
                i += 1;
            }
            Some(b';') if depth <= 0 => return i + 1,
            Some(b'{') if depth <= 0 => {
                i += 1;
                break;
            }
            Some(_) => i += 1,
        }
    }
    // Balanced body, literals and comments transparent.
    let mut braces = 1usize;
    while i < len && braces > 0 {
        if let Some(end) = skip_lexeme(bytes, len, i) {
            i = end;
            continue;
        }
        match bytes[i] {
            b'{' => {
                braces += 1;
                i += 1;
            }
            b'}' => {
                braces -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    i
}

#[test]
fn production_region_drops_test_items_but_keeps_the_tail() {
    let raw = "fn live_a() {}\n    #[cfg(test)]\n    fn helper() -> &'static str { \"x;y\" }\nfn live_b() {}\n#[cfg(test)]\nmod tests {\n    fn t() { {}\n    }\n}\n";
    let production = production_region(raw);
    assert!(production.contains("fn live_a()"));
    assert!(production.contains("fn live_b()"));
    assert!(!production.contains("helper"));
    assert!(!production.contains("mod tests"));
}

#[test]
fn production_region_survives_comment_before_head_and_literals() {
    // A doc comment between the marker and the head — the `;` inside
    // it must not end the item, and the item tail must still drop.
    let raw = "fn live() {}\n#[cfg(test)]\n    /// uses x;\n    fn t(a: [u8; 4]) {\n        let s = \"};\"\n    }\nfn tail() {}\n";
    let production = production_region(raw);
    assert!(production.contains("fn live()"));
    assert!(production.contains("fn tail()"));
    assert!(!production.contains("fn t("));
    // A `#[cfg(test)]` string inside production code is not a marker.
    let raw2 = "fn live() { let _ = \"#[cfg(test)]\"; }\nfn tail2() {}\n";
    let production2 = production_region(raw2);
    assert!(production2.contains("fn tail2()"));
}
