//! `protocol.go` — the newline-delimited JSON envelope and the closed
//! typed payloads. Parsers reject unknown fields and trailing JSON,
//! upstream-fashion: `DisallowUnknownFields` is `deny_unknown_fields`,
//! and the second `Decode` == EOF check is `serde_json`'s whole-input
//! requirement.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::io::{BufRead, BufReader, Read, Write};

/// `ReadRequest`'s scanner bound — one request line, at most 64 KiB.
pub const MAX_REQUEST_LINE: usize = 65_536;

/// `Request` — one envelope line. `payload` is verbatim bytes so the
/// prepare request digest covers what the wire carried.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub operation_id: String,
    pub verb: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Box<RawValue>>,
}

impl Request {
    pub fn payload_bytes(&self) -> &[u8] {
        self.payload.as_deref().map_or(b"", |p| p.get().as_bytes())
    }
}

/// `Response` — the answer line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub operation_id: String,
    pub outcome: String,
    pub exit_code: i64,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<RawValue>>,
}

impl Response {
    pub fn new(
        operation_id: impl Into<String>,
        outcome: &str,
        exit_code: i64,
        reason: &str,
    ) -> Self {
        Response {
            operation_id: operation_id.into(),
            outcome: outcome.to_owned(),
            exit_code,
            reason: reason.to_owned(),
            result: None,
        }
    }

    /// `denied` outcome; the closed refusal builder.
    pub fn denied(operation_id: impl Into<String>, exit_code: i64, reason: &str) -> Self {
        Self::new(operation_id, "denied", exit_code, reason)
    }

    /// `deferred` outcome; the closed not-in-this-slice answer.
    pub fn deferred(operation_id: impl Into<String>, reason: &str) -> Self {
        Self::new(operation_id, "deferred", 5, reason)
    }

    /// Attach a typed result (marshal failure keeps the response
    /// result-less, as upstream's `Result, _ = json.Marshal` sites do).
    pub fn with_result<T: Serialize>(mut self, value: &T) -> Self {
        if let Ok(raw) = serde_json::to_string(value) {
            self.result = RawValue::from_string(raw).ok();
        }
        self
    }
}

/// `ReadRequest` — one bounded line; missing `operation_id`/`verb` is
/// the caller-visible "missing required fields" error.
pub fn read_request(reader: &mut impl Read) -> Result<Request, String> {
    let mut limited = BufReader::new(reader.take(MAX_REQUEST_LINE as u64 + 1));
    let mut line = Vec::new();
    match limited.read_until(b'\n', &mut line) {
        Ok(0) => return Err("helper: failed to read request".to_owned()),
        Ok(_) => {}
        Err(e) => return Err(format!("helper: failed to read request: {e}")),
    }
    if line.len() > MAX_REQUEST_LINE {
        return Err("helper: failed to read request: line too long".to_owned());
    }
    let req: Request =
        serde_json::from_slice(&line).map_err(|e| format!("helper: invalid request: {e}"))?;
    if req.operation_id.is_empty() || req.verb.is_empty() {
        return Err("helper: missing required fields".to_owned());
    }
    Ok(req)
}

/// `WriteResponse` — marshal + `\n`.
pub fn write_response(writer: &mut impl Write, resp: &Response) -> Result<(), String> {
    let mut b = serde_json::to_vec(resp).map_err(|e| e.to_string())?;
    b.push(b'\n');
    writer.write_all(&b).map_err(|e| e.to_string())
}

/// `WriteRequest` — an absent payload goes on the wire as `{}`.
pub fn write_request(writer: &mut impl Write, req: &Request) -> Result<(), String> {
    let mut req = req.clone();
    if req.payload.is_none() {
        req.payload = RawValue::from_string("{}".to_owned()).ok();
    }
    let mut b = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    b.push(b'\n');
    writer.write_all(&b).map_err(|e| e.to_string())
}

/// `ReadResponse` — decode the one response object.
pub fn read_response(reader: &mut impl Read) -> Result<Response, String> {
    let mut line = Vec::new();
    BufReader::new(reader)
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&line).map_err(|e| e.to_string())
}

/// The Go `DisallowUnknownFields + second-Decode-is-EOF` pair: decode
/// `payload` as `T`, refusing unknown fields (declared on the struct)
/// and any trailing token (serde consumes the whole input).
pub fn strict_decode<T: for<'de> Deserialize<'de>>(payload: &[u8]) -> Result<T, String> {
    serde_json::from_slice(payload).map_err(|e| format!("{e}"))
}

/// The `empty-or-{}` payload check several parsers share
/// (`ParseBackupCreateRequest`/`ParseInitRequest`/`ParseWipeRequest`
/// family): absent, empty, or exactly `{}` is empty; anything else is
/// decoded as an empty object so stray fields fail.
pub fn payload_is_empty_object(payload: &[u8]) -> Result<bool, String> {
    let trimmed = trim_ascii(payload);
    if trimmed.is_empty() || trimmed == b"{}" {
        return Ok(true);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    strict_decode::<Empty>(trimmed)?;
    Ok(false)
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let s = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let e = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(s, |i| i + 1);
    &b[s..e.max(s)]
}

// ---------------------------------------------------------------------------
// Typed payloads
// ---------------------------------------------------------------------------

/// `PrepareRequest` — the closed `prepare` payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub resume_operation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub from_release_dir: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub export_release_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_claim: Option<PrepareConfirmationClaim>,
}

/// `PrepareConfirmationClaim` — the client-supplied cross-check; it can
/// only ever deny, never admit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareConfirmationClaim {
    pub request_digest: String,
    pub resume_operation_id: String,
    pub config_binding: String,
    pub boot_id: String,
    pub helper_release: String,
    pub issued_at: String,
    pub expires_at: String,
    pub nonce: String,
}

/// `ParsePrepareRequest`.
pub fn parse_prepare_request(req: &Request) -> Result<PrepareRequest, String> {
    let payload = trim_ascii(req.payload_bytes());
    if payload.is_empty() {
        return Ok(PrepareRequest::default());
    }
    strict_decode(payload).map_err(|e| format!("helper: invalid prepare request payload: {e}"))
}

/// `LifecycleRequest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_binding: String,
}

/// `ParseLifecycleRequest` — upstream's plain `json.Unmarshal`: unknown
/// fields are tolerated on this one parser only; keep that quirk.
#[derive(Deserialize)]
struct LifecycleLoose {
    #[serde(default)]
    config_binding: String,
}

pub fn parse_lifecycle_request(req: &Request) -> Result<LifecycleRequest, String> {
    let payload = trim_ascii(req.payload_bytes());
    if payload.is_empty() {
        return Ok(LifecycleRequest::default());
    }
    let decoded: LifecycleLoose = strict_decode(payload)
        .map_err(|e| format!("helper: invalid lifecycle request payload: {e}"))?;
    Ok(LifecycleRequest {
        config_binding: decoded.config_binding,
    })
}

/// `BrowserOpenRequest` — the proof the caller presents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserOpenRequest {
    #[serde(default)]
    pub launch_id: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub expires_at: String,
}

/// `ParseBrowserOpenRequest`.
pub fn parse_browser_open_request(req: &Request) -> Result<BrowserOpenRequest, String> {
    let payload = trim_ascii(req.payload_bytes());
    if payload.is_empty() {
        return Ok(BrowserOpenRequest::default());
    }
    strict_decode(payload).map_err(|e| format!("helper: invalid browser-open request payload: {e}"))
}

impl BrowserOpenRequest {
    /// `readyProof` — every field must be present and well formed
    /// before the proof is compared: the nonce is `base64.RawStd` of
    /// exactly 32 bytes, the expiry a strict RFC3339 timestamp.
    pub fn ready_proof(&self) -> Result<super::browser::ReadyProof, String> {
        if self.launch_id.is_empty() || self.nonce.is_empty() || self.expires_at.is_empty() {
            return Err("helper: browser-open proof is incomplete".to_owned());
        }
        let nonce = crate::broker::wire::b64_raw_decode(&self.nonce)
            .filter(|n| n.len() == 32)
            .ok_or_else(|| "helper: browser-open proof nonce is invalid".to_owned())?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&nonce);
        let expires_at = time::OffsetDateTime::parse(
            &self.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| "helper: browser-open proof is incomplete".to_owned())?;
        Ok(super::browser::ReadyProof {
            launch_id: self.launch_id.clone(),
            runtime_generation: String::new(),
            nonce: arr,
            expires_at,
        })
    }
}

/// `TrustInstallRequest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustInstallRequest {
    #[serde(default)]
    pub release_digest: String,
}

/// `SecurityUpdateRequest` — `envelope` is verbatim bytes.
#[derive(Debug, Clone)]
pub struct SecurityUpdateRequest {
    pub operation_id: String,
    pub envelope: Vec<u8>,
}

/// `ParseSecurityUpdateRequest`.
pub fn parse_security_update_request(req: &Request) -> Result<SecurityUpdateRequest, String> {
    let payload = trim_ascii(req.payload_bytes());
    if req.operation_id.is_empty() || payload.is_empty() {
        return Err("helper: missing security update request".to_owned());
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        envelope: Box<RawValue>,
    }
    let wire: Wire = strict_decode(payload)
        .map_err(|e| format!("helper: invalid security update request: {e}"))?;
    if trim_ascii(wire.envelope.get().as_bytes()).is_empty() {
        return Err("helper: invalid security update request".to_owned());
    }
    Ok(SecurityUpdateRequest {
        operation_id: req.operation_id.clone(),
        envelope: wire.envelope.get().as_bytes().to_vec(),
    })
}

/// `BootstrapShowRequest` — closed empty object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapShowRequest {}

/// `ParseBootstrapShowRequest`.
pub fn parse_bootstrap_show_request(req: &Request) -> Result<BootstrapShowRequest, String> {
    let payload = trim_ascii(req.payload_bytes());
    if payload.is_empty() {
        return Ok(BootstrapShowRequest {});
    }
    strict_decode::<BootstrapShowRequest>(payload)
        .map_err(|e| format!("helper: invalid bootstrap-show request payload: {e}"))
}

/// `LifecycleResultDetails` — the typed lifecycle `result`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LifecycleResultDetails {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub phase: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub safe_next_action: String,
}

/// `StageTiming` — `dependencyprepare.StageTiming`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageTiming {
    pub phase: String,
    pub duration_ms: f64,
}

/// `ResourceCounters` — `dependencyprepare.ResourceCounters`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCounters {
    #[serde(default)]
    pub fetched: i64,
    #[serde(default)]
    pub built: i64,
    #[serde(default)]
    pub compared: i64,
    #[serde(default)]
    pub staged: i64,
    #[serde(default)]
    pub bytes_read: i64,
}

/// `PrepareResultDetails` — the whole of what a prepare tells the
/// operator: identifiers, phase names, counts, durations. No path,
/// URL, command line, or build output may ever be added here —
/// upstream's wire-redaction rule, and the reason this struct is
/// closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrepareResultDetails {
    #[serde(default)]
    pub authority_state: String,
    #[serde(default)]
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remediation: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub phase: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selector: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resume_required: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub reused: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub acquired: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub advisory_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub safe_next_action: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub operation_elapsed_ms: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stage_timings: Vec<StageTiming>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_counters: Option<ResourceCounters>,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(payload: &str) -> Request {
        Request {
            operation_id: "op-1".to_owned(),
            verb: "v".to_owned(),
            payload: RawValue::from_string(payload.to_owned()).ok(),
        }
    }

    #[test]
    fn envelope_roundtrip_and_limits() {
        let r = Request {
            operation_id: "o".into(),
            verb: "up".into(),
            payload: None,
        };
        let mut buf = Vec::new();
        write_request(&mut buf, &r).unwrap();
        assert!(
            buf.ends_with(b"\"payload\":{}}\n"),
            "{}",
            String::from_utf8_lossy(&buf)
        );
        let back = read_request(&mut buf.as_slice()).unwrap();
        assert_eq!(back.verb, "up");
        let mut resp = Vec::new();
        write_response(
            &mut resp,
            &Response::denied("o", 5, "UNSUPPORTED_IN_THIS_SLICE"),
        )
        .unwrap();
        let r2 = read_response(&mut resp.as_slice()).unwrap();
        assert_eq!(r2.exit_code, 5);
    }

    #[test]
    fn strict_parsers_reject_unknown_and_trailing() {
        assert!(parse_prepare_request(&req("{\"resume_operation_id\":\"x\"}")).is_ok());
        assert!(parse_prepare_request(&req("{\"bogus\":1}")).is_err());
        // Two JSON values cannot even be a `json.RawMessage` — upstream's
        // second-Decode-EOF check maps to `from_slice`'s trailing rule.
        assert!(strict_decode::<PrepareRequest>(b"{\"resume_operation_id\":\"x\"} {}").is_err());
        assert!(
            parse_browser_open_request(&req(
                "{\"launch_id\":\"l\",\"nonce\":\"n\",\"expires_at\":\"e\",\"extra\":1}"
            ))
            .is_err()
        );
        // `{"envelope":{}}` is accepted — TrimSpace of `{}` is non-empty,
        // upstream's exact rule; a *missing* envelope is what refuses.
        assert!(parse_security_update_request(&req("{\"envelope\":{}}")).is_ok());
        assert!(parse_security_update_request(&req("{\"other\":1}")).is_err());
        assert!(payload_is_empty_object(b"{}").unwrap());
        assert!(payload_is_empty_object(b"{\"x\":1}").is_err());
    }
}
