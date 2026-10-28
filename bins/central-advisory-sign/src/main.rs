//! `central-advisory-sign` is an offline tool for producing B01
//! release-security advisory material: a release signing keypair, and
//! bundles signed with it — the port of upstream
//! `cmd/central-advisory-sign/main.go`.
//!
//! It never runs as part of a Central instance and never touches
//! protected state — it only ever reads and writes plain files the
//! operator names on the command line. Key custody (where the private
//! key this tool prints is stored, and who may use it) is the
//! maintainer's decision; this tool only performs the cryptographic
//! operations B01's design
//! (docs/internal/superpowers/specs/2026-07-18-phase-1-b01-advisory-admission-design.md)
//! requires, in the exact wire shape `infra::advisory_fetch`'s
//! production `ActiveBundleSource` and `Verifier::verify_snapshot`
//! already agree on. No network, no database.

use std::io::Read;
use std::io::Write;

use central_infra::advisory::{
    CompatibilityMatrix, DenyPolicy, PRODUCTION_KEY_ID, Snapshot, State, Verifier,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// `bundleSchemaVersion`.
const BUNDLE_SCHEMA_VERSION: i64 = 1;

/// `signedBundle` mirrors `infra::advisory_fetch`'s installed-bundle
/// shape and `central_infra::advisory`'s `ParsedBundle` field-for-field:
/// this tool, the dev bootstrap, and the verifier must never
/// independently drift on what a bundle's JSON shape is.
#[derive(Serialize)]
struct SignedBundle {
    schema_version: i64,
    key_id: String,
    issued_at: String,
    expires_at: String,
    compatibility: CompatibilityMatrix,
    emergency_deny: DenyPolicy,
}

/// `envelope` — the `{bundle, signature}` wrapper
/// `ActiveBundleSource` consumes and `verify_snapshot` unwraps.
#[derive(Serialize)]
struct Envelope<'a> {
    bundle: &'a serde_json::value::RawValue,
    signature: &'a str,
}

/// `genkeyOutput`.
#[derive(Serialize)]
struct GenkeyOutput {
    key_id: &'static str,
    public_key_base64: String,
    private_key_base64: String,
    release_authority_digest_sha256: String,
}

// ---------------------------------------------------------------------------
// flag — the Go `flag` package's grammar for this tool's two kinds
// (string and bool), plus the FlagSet's own stderr diagnostics.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum FlagKind {
    Str,
    Bool,
}

struct FlagSpec {
    name: &'static str,
    kind: FlagKind,
    default: &'static str,
    usage: &'static str,
}

/// `fs.Parse` — accepts `-name`/`--name`, `-name=value`/`--name=value`;
/// string flags also take `-name value`. The first non-flag argument
/// (or `--`, or a lone `-`) stops parsing exactly as Go's flag package
/// does; trailing positionals are ignored like upstream's unchecked
/// `fs.Args()`. The returned set is the flagset's defaults with each
/// occurrence applied in order — last occurrence wins.
fn parse_flags(
    set_name: &str,
    args: &[String],
    specs: &[FlagSpec],
) -> Result<Vec<(String, String)>, String> {
    let mut values: Vec<(String, String)> = specs
        .iter()
        .map(|s| (s.name.to_owned(), s.default.to_owned()))
        .collect();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        let stripped = arg.trim_start_matches('-');
        if stripped.is_empty() {
            // `--` terminator.
            break;
        }
        let (name, inline) = match stripped.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (stripped, None),
        };
        if matches!(name, "h" | "help") {
            print_flag_usage(set_name, specs);
            return Err("flag: help requested".to_owned());
        }
        let Some(spec) = specs.iter().find(|s| s.name == name) else {
            let msg = format!("flag provided but not defined: -{name}");
            print_flag_error(set_name, specs, &msg);
            return Err(msg);
        };
        let value = match (spec.kind, inline) {
            (FlagKind::Bool, None) => "true".to_owned(),
            (FlagKind::Bool, Some(v)) => {
                if !matches!(
                    v.as_str(),
                    "1" | "t"
                        | "T"
                        | "TRUE"
                        | "true"
                        | "True"
                        | "0"
                        | "f"
                        | "F"
                        | "FALSE"
                        | "false"
                        | "False"
                ) {
                    let msg = format!("invalid boolean value {v:?} for -{name}: parse error");
                    print_flag_error(set_name, specs, &msg);
                    return Err(msg);
                }
                v
            }
            (FlagKind::Str, Some(v)) => v,
            (FlagKind::Str, None) => {
                i += 1;
                let Some(v) = args.get(i) else {
                    let msg = format!("flag needs an argument: -{name}");
                    print_flag_error(set_name, specs, &msg);
                    return Err(msg);
                };
                v.clone()
            }
        };
        if let Some(entry) = values.iter_mut().find(|(n, _)| n == name) {
            entry.1 = value;
        }
        i += 1;
    }
    Ok(values)
}

/// `FlagSet.failf` + `Usage` — the parse failure prints the error and
/// the flagset's `Usage of <name>:` + `PrintDefaults` table to stderr
/// before `run*` returns the error to `main`.
fn print_flag_error(set_name: &str, specs: &[FlagSpec], msg: &str) {
    eprintln!("{msg}");
    print_flag_usage(set_name, specs);
}

fn print_flag_usage(set_name: &str, specs: &[FlagSpec]) {
    eprintln!("Usage of {set_name}:");
    print_defaults(specs);
}

/// `PrintDefaults` — one `  -name [type]` line per flag, then the
/// tab-indented usage with a non-zero default appended as
/// ` (default "x")`. Flags are declared in upstream's order; Go sorts
/// alphabetically — the specs here are already alphabetical.
fn print_defaults(specs: &[FlagSpec]) {
    for spec in specs {
        let ty = match spec.kind {
            FlagKind::Str => " string",
            FlagKind::Bool => "",
        };
        eprintln!("  -{}{}", spec.name, ty);
        if spec.default.is_empty() {
            eprintln!("    \t{}", spec.usage);
        } else {
            eprintln!("    \t{} (default {:?})", spec.usage, spec.default);
        }
    }
}

fn flag_value<'a>(values: &'a [(String, String)], name: &str) -> &'a str {
    values
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

// ---------------------------------------------------------------------------
// base64 — Go `base64.StdEncoding` (standard alphabet, padded).
// ---------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
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
            if i > n {
                out.push('=');
            } else {
                out.push(B64_ALPHABET[*idx as usize] as char);
            }
        }
    }
    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    // Go's `DecodeString` ignores new-line characters and accepts the
    // empty input — mirror before the quad grammar runs.
    let filtered: Vec<u8> = text
        .bytes()
        .filter(|b| *b != b'\r' && *b != b'\n')
        .collect();
    let bytes = filtered.as_slice();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut table = [0xFFu8; 256];
    for (i, &c) in B64_ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut padding = 0usize;
    for quad in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        for (i, &c) in quad.iter().enumerate() {
            if c == b'=' {
                padding += 1;
                vals[i] = 0;
            } else {
                if padding != 0 {
                    return None;
                }
                vals[i] = table[c as usize];
                if vals[i] == 0xFF {
                    return None;
                }
            }
        }
        let b0 = (vals[0] << 2) | (vals[1] >> 4);
        let b1 = (vals[1] << 4) | (vals[2] >> 2);
        let b2 = (vals[2] << 6) | vals[3];
        out.push(b0);
        if quad[2] != b'=' {
            out.push(b1);
        }
        if quad[3] != b'=' {
            out.push(b2);
        }
    }
    if padding > 2 {
        return None;
    }
    Some(out)
}

/// `t.Format(time.RFC3339)` — second precision, offset preserved.
fn format_rfc3339_seconds(t: &OffsetDateTime) -> Result<String, String> {
    t.replace_nanosecond(0)
        .map_err(|e| format!("--issued: {e}"))?
        .format(&Rfc3339)
        .map_err(|e| format!("--issued: {e}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Subcommands — upstream's `runGenkey` / `runBundle` / `runVerify`.
// ---------------------------------------------------------------------------

fn run_genkey(args: &[String]) -> Result<(), String> {
    parse_flags("genkey", args, &[])?;
    let mut seed = [0u8; 32];
    rustix::rand::getrandom(&mut seed, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| format!("generate key: {e}"))?;
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();
    let private = signing.to_keypair_bytes();
    let digest = Sha256::digest(public);
    let out = GenkeyOutput {
        key_id: PRODUCTION_KEY_ID,
        public_key_base64: b64_encode(&public),
        private_key_base64: b64_encode(&private),
        release_authority_digest_sha256: hex_encode(&digest),
    };
    // `json.NewEncoder(os.Stdout)` + `SetIndent("", "  ")` — Encode
    // appends its own newline.
    let mut raw =
        serde_json::to_string_pretty(&out).map_err(|e| format!("encode genkey output: {e}"))?;
    raw.push('\n');
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(raw.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| format!("write genkey output: {e}"))?;
    Ok(())
}

/// The `bundle` flagset — upstream's `flag.NewFlagSet("bundle", ...)`
/// declarations, kept alphabetical as `PrintDefaults` expects.
const BUNDLE_FLAGS: &[FlagSpec] = &[
    FlagSpec {
        name: "compose",
        kind: FlagKind::Str,
        default: "",
        usage: "compatibility pin (empty admits any)",
    },
    FlagSpec {
        name: "deny-reason",
        kind: FlagKind::Str,
        default: "",
        usage: "required if --emergency-deny is set",
    },
    FlagSpec {
        name: "docker",
        kind: FlagKind::Str,
        default: "",
        usage: "compatibility pin (empty admits any)",
    },
    FlagSpec {
        name: "emergency-deny",
        kind: FlagKind::Bool,
        default: "false",
        usage: "set the bundle's emergency deny bit",
    },
    FlagSpec {
        name: "expires",
        kind: FlagKind::Str,
        default: "",
        usage: "RFC3339 expires_at (default: now + 90 days)",
    },
    FlagSpec {
        name: "issued",
        kind: FlagKind::Str,
        default: "",
        usage: "RFC3339 issued_at (default: now)",
    },
    FlagSpec {
        name: "kernel",
        kind: FlagKind::Str,
        default: "",
        usage: "compatibility pin (empty admits any)",
    },
    FlagSpec {
        name: "key-id",
        kind: FlagKind::Str,
        default: PRODUCTION_KEY_ID,
        usage: "bundle key_id; must match the verifier's trust root",
    },
    FlagSpec {
        name: "os-release",
        kind: FlagKind::Str,
        default: "",
        usage: "compatibility pin (empty admits any)",
    },
    FlagSpec {
        name: "out",
        kind: FlagKind::Str,
        default: "",
        usage: "path to write the signed envelope JSON to",
    },
    FlagSpec {
        name: "private-key-file",
        kind: FlagKind::Str,
        default: "",
        usage: "path to a file containing exactly the base64 private key",
    },
    FlagSpec {
        name: "psql",
        kind: FlagKind::Str,
        default: "",
        usage: "compatibility pin (empty admits any)",
    },
];

fn run_bundle(args: &[String]) -> Result<(), String> {
    let values = parse_flags("bundle", args, BUNDLE_FLAGS)?;
    let private_key_file = flag_value(&values, "private-key-file").to_owned();
    let out = flag_value(&values, "out").to_owned();
    let key_id = flag_value(&values, "key-id").to_owned();
    let issued_flag = flag_value(&values, "issued").to_owned();
    let expires_flag = flag_value(&values, "expires").to_owned();
    let emergency_deny = flag_value(&values, "emergency-deny");
    let emergency_deny = !matches!(
        emergency_deny,
        "" | "0" | "f" | "F" | "FALSE" | "false" | "False"
    );
    let deny_reason = flag_value(&values, "deny-reason").to_owned();
    if private_key_file.is_empty() || out.is_empty() {
        return Err("--private-key-file and --out are required".to_owned());
    }
    if emergency_deny && deny_reason.is_empty() {
        return Err("--deny-reason is required when --emergency-deny is set".to_owned());
    }

    let signing = read_private_key(&private_key_file)?;

    let now = OffsetDateTime::now_utc();
    let issued = if issued_flag.is_empty() {
        now
    } else {
        OffsetDateTime::parse(&issued_flag, &Rfc3339).map_err(|e| format!("--issued: {e}"))?
    };
    let mut expires = issued + time::Duration::days(90);
    if !expires_flag.is_empty() {
        expires = OffsetDateTime::parse(&expires_flag, &Rfc3339)
            .map_err(|e| format!("--expires: {e}"))?;
    }
    if expires <= issued {
        return Err("--expires must be after --issued".to_owned());
    }

    let bundle = SignedBundle {
        schema_version: BUNDLE_SCHEMA_VERSION,
        key_id,
        // Go's `t.Format(time.RFC3339)` truncates sub-second precision —
        // the layout carries no fractional digits. Match at format time
        // (the instant comparisons above still see full precision).
        issued_at: format_rfc3339_seconds(&issued)?,
        expires_at: format_rfc3339_seconds(&expires)?,
        compatibility: CompatibilityMatrix {
            os_release: flag_value(&values, "os-release").to_owned(),
            kernel: flag_value(&values, "kernel").to_owned(),
            docker: flag_value(&values, "docker").to_owned(),
            compose: flag_value(&values, "compose").to_owned(),
            psql: flag_value(&values, "psql").to_owned(),
        },
        emergency_deny: DenyPolicy {
            emergency: emergency_deny,
            reason: deny_reason,
        },
    };
    let raw = serde_json::to_vec(&bundle).map_err(|e| format!("marshal bundle: {e}"))?;
    // Canonicalization and the signed message format are copied verbatim
    // from `Verifier::verify_snapshot` and the dev bootstrap's own signer:
    // all three must agree byte-for-byte on both, or a bundle signed by
    // this tool would fail verification even with a correctly matching
    // key.
    let value: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("canonicalize bundle: {e}"))?;
    let canonical = central_foundation::jcs::canonicalize(&value)
        .map_err(|e| format!("canonicalize bundle: {e}"))?;
    let sum = Sha256::digest(&canonical);
    let message = format!(
        "central.security-advisory/v1|bundle|SHA-256:{}",
        hex_encode(&sum)
    );
    let signature = b64_encode(&signing.sign(message.as_bytes()).to_bytes());

    let bundle_raw = serde_json::value::RawValue::from_string(
        String::from_utf8(raw).map_err(|e| format!("marshal bundle: {e}"))?,
    )
    .map_err(|e| format!("marshal envelope: {e}"))?;
    let env = serde_json::to_vec(&Envelope {
        bundle: &bundle_raw,
        signature: &signature,
    })
    .map_err(|e| format!("marshal envelope: {e}"))?;

    // `os.WriteFile(*out, env, 0600)` — mode applies on creation.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&out).map_err(|e| format!("write {out}: {e}"))?;
    file.write_all(&env)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write {out}: {e}"))?;
    drop(file);
    eprintln!(
        "central-advisory-sign: wrote {out} (bundle SHA-256 {}, key_id {}, issued {}, expires {})",
        hex_encode(&sum),
        bundle.key_id,
        bundle.issued_at,
        bundle.expires_at
    );
    Ok(())
}

/// `readPrivateKey` — a bare base64 file (or stdin for `-`), trimmed,
/// decoded, and required to be exactly 64 bytes: Go's
/// `ed25519.PrivateKeySize` keypair form (seed ‖ public).
fn read_private_key(path: &str) -> Result<SigningKey, String> {
    let mut raw = Vec::new();
    if path == "-" {
        std::io::stdin()
            .lock()
            .read_to_end(&mut raw)
            .map_err(|e| format!("read private key: {e}"))?;
    } else {
        raw = std::fs::read(path).map_err(|e| format!("read private key: {e}"))?;
    }
    let trimmed = String::from_utf8_lossy(&raw).trim().to_owned();
    let decoded = b64_decode(&trimmed)
        .ok_or_else(|| "decode private key: illegal base64 data at input byte 0".to_owned())?;
    let keypair: &[u8; 64] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("private key is {} bytes, want 64", decoded.len()))?;
    SigningKey::from_keypair_bytes(keypair).map_err(|e| format!("decode private key: {e}"))
}

const VERIFY_FLAGS: &[FlagSpec] = &[FlagSpec {
    name: "bundle",
    kind: FlagKind::Str,
    default: "",
    usage: "path to a signed bundle envelope JSON",
}];

/// `runVerify` validates one bundle envelope file against the
/// compiled-in production trust root. The verifier unwraps the envelope
/// itself, so `Snapshot::bundle` receives the whole file bytes and
/// `Snapshot::signature` the base64 signature field copied out of it.
fn run_verify(args: &[String]) -> Result<(), String> {
    let values = parse_flags("verify", args, VERIFY_FLAGS)?;
    let bundle_path = flag_value(&values, "bundle").to_owned();
    if bundle_path.is_empty() {
        return Err("--bundle is required".to_owned());
    }
    let raw = std::fs::read(&bundle_path).map_err(|e| format!("read bundle: {e}"))?;
    #[derive(serde::Deserialize)]
    struct EnvelopeSig {
        #[serde(default)]
        signature: String,
    }
    let env: EnvelopeSig =
        serde_json::from_slice(&raw).map_err(|e| format!("parse envelope: {e}"))?;
    let (vb, res) = Verifier::production().verify_snapshot(&Snapshot {
        generation_id: String::new(),
        selector_digest: String::new(),
        bundle: raw,
        signature: env.signature.into_bytes(),
    });
    if res.state != State::Current {
        return Err(format!(
            "INVALID: state={} code={}",
            res.state.as_str(),
            res.code.as_str()
        ));
    }
    let Some(vb) = vb else {
        return Err("INVALID: state=denied code=INVALID_ADVISORY".to_owned());
    };
    let now = OffsetDateTime::now_utc();
    if vb.expires_at <= now {
        return Err(format!(
            "INVALID: bundle expired at {}",
            format_rfc3339_seconds(&vb.expires_at).unwrap_or_default()
        ));
    }
    if vb.issued_at > now {
        return Err(format!(
            "INVALID: bundle not yet valid (issued {})",
            format_rfc3339_seconds(&vb.issued_at).unwrap_or_default()
        ));
    }
    println!(
        "VALID key_id={} issued={} expires={} digest={}",
        vb.key_id,
        format_rfc3339_seconds(&vb.issued_at).unwrap_or_default(),
        format_rfc3339_seconds(&vb.expires_at).unwrap_or_default(),
        vb.digest
    );
    Ok(())
}

const USAGE: &str = r#"usage:
  central-advisory-sign genkey
      Generates one Ed25519 release-signing keypair and prints it, and the
      release authority digest, as JSON on stdout. Store the private key
      offline, under whatever custody the maintainer has decided on -- this
      tool never persists it anywhere itself. Embed public_key_base64 (decoded)
      into internal/advisory/release_key.go's productionTrust as the final,
      separate step that makes a signed bundle verify in production; this tool
      does not do that step for you. (release_authority_digest_sha256 is a
      documentation cross-check only -- the compiled trust path does not use it.)

  central-advisory-sign bundle --private-key-file <path> --out <path> [flags]
      Builds, canonicalizes, and signs one advisory bundle envelope, and
      writes it to --out in the exact shape
      internal/adapter/advisory.InstallActiveBundle expects as its envelope
      argument. --private-key-file must contain exactly the base64
      private_key_base64 genkey printed (a bare file, no JSON wrapper).

      Flags:
        --key-id string       default "central-release-authority/v2" -- see genkey's note; do not change this for a production release key.
        --issued string       RFC3339 (default: now)
        --expires string      RFC3339 (default: now + 90 days)
        --emergency-deny      set the bundle's emergency deny bit
        --deny-reason string  required if --emergency-deny is set
        --os-release string   compatibility pin (default: empty, meaning "admit any")
        --kernel string       compatibility pin (default: empty, meaning "admit any")
        --docker string       compatibility pin (default: empty, meaning "admit any")
        --compose string      compatibility pin (default: empty, meaning "admit any")
        --psql string         compatibility pin (default: empty, meaning "admit any")

  central-advisory-sign verify --bundle <path>
      Verifies one signed bundle envelope against the compiled-in production
      trust root (internal/advisory/release_key.go). Prints the verdict;
      exits non-zero if the signature is invalid, the key_id mismatches, or
      the bundle is expired. Offline; no daemon or grant needed.
"#;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprint!("{USAGE}");
        return std::process::ExitCode::from(2);
    }
    let result = match args[1].as_str() {
        "genkey" => run_genkey(&args[2..]),
        "bundle" => run_bundle(&args[2..]),
        "verify" => run_verify(&args[2..]),
        "-h" | "--help" | "help" => {
            eprint!("{USAGE}");
            return std::process::ExitCode::SUCCESS;
        }
        _ => {
            eprint!("{USAGE}");
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("central-advisory-sign: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trip_std() {
        assert_eq!(b64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_decode("aGVsbG8="), Some(b"hello".to_vec()));
        assert_eq!(b64_decode("Zm9v!g=="), None);
        assert_eq!(b64_decode("Zg"), None);
        assert_eq!(b64_decode("Zg==Zg=="), None);
        // Padded-only grammar: a two-byte output ends in one '='.
        assert_eq!(b64_decode("Zm8="), Some(b"fo".to_vec()));
        assert_eq!(b64_decode("Zm9v"), Some(b"foo".to_vec()));
    }

    #[test]
    fn flag_grammar_matches_go() {
        // `--name=v`, `-name v`, `--bool`, `--bool=false`.
        let specs = BUNDLE_FLAGS;
        let args = vec![
            "--out=/tmp/x".to_owned(),
            "-issued".to_owned(),
            "2026-01-02T00:00:00Z".to_owned(),
            "--emergency-deny".to_owned(),
            "--docker=27.x".to_owned(),
        ];
        let v = parse_flags("bundle", &args, specs).expect("parse");
        assert_eq!(flag_value(&v, "out"), "/tmp/x");
        assert_eq!(flag_value(&v, "issued"), "2026-01-02T00:00:00Z");
        assert_eq!(flag_value(&v, "docker"), "27.x");
        // First positional stops parsing — `--out` after it is unseen.
        let args2 = vec!["positional".to_owned(), "--out=/tmp/y".to_owned()];
        let v2 = parse_flags("bundle", &args2, specs).expect("parse");
        assert_eq!(flag_value(&v2, "out"), "");
        // Unknown flag is an error.
        assert!(parse_flags("bundle", &["--nope".to_owned()], specs).is_err());
        // Missing string argument is an error.
        assert!(parse_flags("bundle", &["--out".to_owned()], specs).is_err());
        // Bad bool value is an error.
        assert!(parse_flags("bundle", &["--emergency-deny=maybe".to_owned()], specs).is_err());
    }

    /// `runBundle`'s wire path end-to-end: sign a bundle with an
    /// ephemeral key and verify the envelope with
    /// `Verifier::for_testing` — the same `verify_snapshot` a production
    /// admission runs.
    #[test]
    fn signed_bundle_verifies_under_matching_trust() {
        let seed = [0x42u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let dir =
            std::env::temp_dir().join(format!("central-advisory-sign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let key_file = dir.join("key.b64");
        std::fs::write(&key_file, b64_encode(&signing.to_keypair_bytes())).expect("key");
        let out = dir.join("env.json");
        let args = vec![
            "--private-key-file".to_owned(),
            key_file.to_string_lossy().into_owned(),
            "--out".to_owned(),
            out.to_string_lossy().into_owned(),
            "--key-id".to_owned(),
            "central-release-authority/test".to_owned(),
            "--issued".to_owned(),
            "2026-10-04T12:00:00Z".to_owned(),
            "--expires".to_owned(),
            "2027-01-02T12:00:00Z".to_owned(),
        ];
        run_bundle(&args).expect("bundle");
        let raw = std::fs::read(&out).expect("env");
        let env: serde_json::Value = serde_json::from_slice(&raw).expect("parse");
        let sig = env["signature"].as_str().expect("sig");
        let verifier = Verifier::for_testing(central_infra::advisory::ReleaseTrust {
            key_id: "central-release-authority/test".to_owned(),
            protocol: central_infra::advisory::PRODUCTION_PROTOCOL.to_owned(),
            public_key: signing.verifying_key().to_bytes(),
            release_authority_digest: String::new(),
        });
        let (vb, outcome) = verifier.verify_snapshot(&Snapshot {
            generation_id: "g".to_owned(),
            selector_digest: "s".to_owned(),
            bundle: raw,
            signature: sig.as_bytes().to_vec(),
        });
        assert_eq!(outcome.state, State::Current, "verify_snapshot denied");
        let vb = vb.expect("verified bundle");
        assert_eq!(vb.key_id, "central-release-authority/test");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_private_key_rejects_wrong_length() {
        let dir =
            std::env::temp_dir().join(format!("central-advisory-sign-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let key = dir.join("short.b64");
        std::fs::write(&key, b64_encode(&[7u8; 32])).expect("key");
        let err = read_private_key(key.to_str().expect("utf8")).expect_err("must refuse");
        assert_eq!(err, "private key is 32 bytes, want 64");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn run_bundle_requires_both_paths_and_reason() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let dir =
            std::env::temp_dir().join(format!("central-advisory-sign-req-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let key = dir.join("k");
        std::fs::write(&key, b64_encode(&signing.to_keypair_bytes())).expect("key");
        let err = run_bundle(&[
            "--private-key-file".to_owned(),
            key.to_string_lossy().into_owned(),
        ])
        .expect_err("out required");
        assert_eq!(err, "--private-key-file and --out are required");
        let err = run_bundle(&[
            "--private-key-file".to_owned(),
            key.to_string_lossy().into_owned(),
            "--out".to_owned(),
            dir.join("o").to_string_lossy().into_owned(),
            "--emergency-deny".to_owned(),
        ])
        .expect_err("reason required");
        assert_eq!(
            err,
            "--deny-reason is required when --emergency-deny is set"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
