//! `agent.ParseRepositoryAnalysisInput` — the one Task input the web
//! surface accepts, parses, and validates (upstream
//! `internal/agent/repository_analysis_input.go`). The same function
//! validates a submission and re-parses a stored Task input for display,
//! so a rendered instruction can never be one the system would refuse.
//!
//! `CanonicalHash` is deliberately not computed here: upstream's caller
//! discards it (`if _, err := Parse…; err != nil` — validation only),
//! and computing the JCS canonicalization without the workspace's
//! canonicalization crate would add a dependency for a value nobody
//! reads.

use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use unicode_normalization::is_nfc;

/// The only accepted schema version.
pub const SCHEMA_VERSION: &str = "repository_analysis/v1";
/// Upstream `maxRepositoryAnalysisInputBytes`.
pub const MAX_INPUT_BYTES: usize = 64 << 10;
/// Upstream `maxRepositoryInstructionBytes`.
pub const MAX_INSTRUCTION_BYTES: usize = 32 << 10;

/// `ErrInvalidRepositoryAnalysisInput` — a malformed, unsupported, or
/// unauthorized input. Its text never exposes input content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidInput {
    /// `ErrB09InputDenied` — the root id is not in the verified
    /// allowlist; still an invalid-input error, distinguished only
    /// internally.
    pub denied: bool,
}

impl fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid repository analysis input")
    }
}

impl std::error::Error for InvalidInput {}

const fn invalid() -> InvalidInput {
    InvalidInput { denied: false }
}

const fn denied() -> InvalidInput {
    InvalidInput { denied: true }
}

/// `RepositoryAnalysisInput` — the parsed and validated Task input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryAnalysisInput {
    /// The operator's instruction (NFC-verified, non-blank).
    pub instruction: String,
    /// The verified `workspace_root_id`.
    pub workspace_root_id: String,
}

/// `ParseRepositoryAnalysisInput` — parses exactly
/// `repository_analysis/v1` and binds its root id to `verified_root_ids`:
/// precisely the three string fields, no duplicates, no trailing data,
/// NFC-normalized instruction and root id, root in the allowlist.
pub fn parse_repository_analysis_input(
    raw: &[u8],
    verified_root_ids: &[String],
) -> Result<RepositoryAnalysisInput, InvalidInput> {
    if raw.is_empty() || raw.len() > MAX_INPUT_BYTES || std::str::from_utf8(raw).is_err() {
        return Err(invalid());
    }
    // `repositoryAnalysisFields`: exactly the three known string
    // members, no unknown member, no duplicate member, one JSON value.
    // serde's `deny_unknown_fields` plus the trailing-data check covers
    // the shape; duplicate members need a first pass of their own
    // (serde maps silently keep the last).
    reject_duplicate_members(raw)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fields<'a> {
        schema_version: &'a str,
        instruction: &'a str,
        workspace_root_id: &'a str,
    }
    let fields: Fields<'_> = serde_json::from_slice(raw).map_err(|_| invalid())?;
    if fields.schema_version != SCHEMA_VERSION
        || fields.instruction.is_empty()
        || fields.instruction.len() > MAX_INSTRUCTION_BYTES
        || fields.instruction.trim().is_empty()
        || fields.instruction.contains('\0')
        || !is_nfc(fields.instruction)
    {
        return Err(invalid());
    }
    if !verified_root_id(fields.workspace_root_id, verified_root_ids) {
        return Err(denied());
    }
    Ok(RepositoryAnalysisInput {
        instruction: fields.instruction.to_string(),
        workspace_root_id: fields.workspace_root_id.to_string(),
    })
}

/// The first pass `repositoryAnalysisFields` performs: the input is one
/// JSON object whose every member name is known, NFC-normalized and
/// unique, and whose values are strings (never `null`). serde's
/// whole-input `IgnoredAny` pass additionally guarantees the trailing-
/// data and well-formedness checks.
fn reject_duplicate_members(raw: &[u8]) -> Result<(), InvalidInput> {
    // A non-object (or malformed) input fails in the typed parse as
    // well; this pass only needs the member names when it is an object.
    let text = std::str::from_utf8(raw).map_err(|_| invalid())?;
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        return Err(invalid());
    }
    // serde_json::Value's Map keeps insertion order only under the
    // `preserve_order` feature; walk member names manually instead —
    // the input is bounded to 64 KiB so a second token pass is cheap.
    let mut seen: HashSet<&str> = HashSet::new();

    let mut i = 0usize;
    let bytes = raw;
    // Walk just past the opening brace reading `"name" :` pairs at
    // depth 1; anything unexpected defers to the typed parse.
    while i < bytes.len() && bytes[i] != b'{' {
        i += 1;
    }
    if i == bytes.len() {
        return Err(invalid());
    }
    i += 1;
    let depth: usize = 1;
    loop {
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n' | b',') {
            i += 1;
        }
        match bytes.get(i) {
            Some(b'}') => return Ok(()),
            Some(b'"') => {
                let start = i;
                i = skip_json_string(bytes, i).ok_or_else(invalid)?;
                if depth != 1 {
                    return Err(invalid());
                }
                let name: &str = serde_json::from_slice(&bytes[start..i]).map_err(|_| invalid())?;
                if !matches!(name, "schema_version" | "instruction" | "workspace_root_id")
                    || !seen.insert(name)
                    || !is_nfc(name)
                {
                    return Err(invalid());
                }
                while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
                    i += 1;
                }
                if bytes.get(i) != Some(&b':') {
                    return Err(invalid());
                }
                i += 1;
                while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
                    i += 1;
                }
                // Member value must be a JSON string; skip it whole.
                if bytes.get(i) != Some(&b'"') {
                    return Err(invalid());
                }
                i = skip_json_string(bytes, i).ok_or_else(invalid)?;
            }
            _ => return Err(invalid()),
        }
    }
}

/// Scans a JSON string literal starting at `b[p] == '"'`, returning the
/// offset just past the closing quote.
fn skip_json_string(b: &[u8], mut p: usize) -> Option<usize> {
    p += 1;
    while p < b.len() {
        match b[p] {
            b'\\' => p += 2,
            b'"' => return Some(p + 1),
            _ => p += 1,
        }
    }
    None
}

/// `verifiedRootID` — non-empty, NFC-normalized, and in the allowlist.
#[must_use]
fn verified_root_id(root_id: &str, roots: &[String]) -> bool {
    !root_id.is_empty() && is_nfc(root_id) && roots.iter().any(|r| r == root_id)
}

/// `repositoryAnalysisRequest` — the exact `repository_analysis/v1`
/// wire shape: precisely the three fields, `schema_version` always the
/// fixed literal, never taken from the form.
#[derive(serde::Serialize)]
struct RepositoryAnalysisRequest<'a> {
    schema_version: &'a str,
    instruction: &'a str,
    workspace_root_id: &'a str,
}

/// `repositoryAnalysisJSON` — builds the canonical JSON document from
/// submitted form fields. `serde_json` cannot fail for a struct of
/// string slices.
#[must_use]
pub fn repository_analysis_json(instruction: &str, workspace_root_id: &str) -> Vec<u8> {
    serde_json::to_vec(&RepositoryAnalysisRequest {
        schema_version: SCHEMA_VERSION,
        instruction,
        workspace_root_id,
    })
    .unwrap_or_default()
}
