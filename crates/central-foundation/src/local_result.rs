//! The `central.local-result/v1` JSON envelope — ports
//! `internal/cli/result.go`.
//!
//! Every `central` operator command emits exactly one UTF-8 JSON object
//! on stdout (or stderr when the command payload owns stdout). The
//! envelope's `exit_code` is the process exit status — the same contract
//! upstream enforces through `cli.ResultExitCode`, where a command that
//! ends without a result fails closed at exit `6`.

use std::io::Write;

use serde::Serialize;
use time::OffsetDateTime;

use crate::failure::ExitClass;

/// Fixed schema identifier for the operator-result envelope.
pub const LOCAL_RESULT_SCHEMA: &str = "central.local-result/v1";

/// The canonical reason code for a capability owned by a not-yet-landed
/// R-slice (upstream `cli.ExitUnsupportedCmd`).
pub const REASON_UNSUPPORTED_IN_THIS_SLICE: &str = "UNSUPPORTED_IN_THIS_SLICE";

/// One operator-result envelope.
///
/// Field names and optionality match upstream `cli.LocalResult`:
/// `reason` and `details` are omitted when absent, never serialized as
/// `null`, and `timestamp` is UTC RFC 3339.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LocalResult {
    /// Fixed `central.local-result/v1`.
    pub schema_version: &'static str,
    /// The command grammar identifier, e.g. `run.submit`, `local.init`,
    /// `migrate-up`, or `unknown`.
    pub command_id: String,
    /// The process exit status; must equal [`crate::failure::ExitClass`]'s
    /// code.
    pub exit_code: u8,
    /// Safe machine reason code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Command-keyed detail payload; omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// UTC RFC 3339 emission timestamp.
    pub timestamp: String,
}

impl LocalResult {
    /// Records a result at `now`.
    #[must_use]
    pub fn at(
        command_id: impl Into<String>,
        exit_class: ExitClass,
        reason: Option<String>,
        details: Option<serde_json::Value>,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            schema_version: LOCAL_RESULT_SCHEMA,
            command_id: command_id.into(),
            exit_code: exit_class.code(),
            reason,
            details,
            timestamp: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }

    /// Records a result stamped at the current UTC time.
    #[must_use]
    pub fn now(
        command_id: impl Into<String>,
        exit_class: ExitClass,
        reason: Option<String>,
        details: Option<serde_json::Value>,
    ) -> Self {
        Self::at(
            command_id,
            exit_class,
            reason,
            details,
            OffsetDateTime::now_utc(),
        )
    }

    /// The canonical `UNSUPPORTED_IN_THIS_SLICE` result for a deferred
    /// command (exit `5`).
    #[must_use]
    pub fn unsupported(command_id: impl Into<String>) -> Self {
        Self::now(
            command_id,
            ExitClass::Incompatible,
            Some(REASON_UNSUPPORTED_IN_THIS_SLICE.to_string()),
            None,
        )
    }

    /// Writes the envelope as one JSON line — the upstream
    /// `WriteResultTo` seam. Callers route it to stdout, or to stderr
    /// when the command payload owns stdout (e.g. `artifact read
    /// --stdout` in a later slice).
    ///
    /// # Errors
    /// Propagates writer failures; a result that cannot be written means
    /// the process must fail closed at exit `6`.
    pub fn write_json_line<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        serde_json::to_writer(&mut *writer, self).map_err(std::io::Error::other)?;
        writer.write_all(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn envelope_matches_upstream_shape() {
        let result = LocalResult::at(
            "run.submit",
            ExitClass::Success,
            Some("ok".to_string()),
            Some(serde_json::json!({"run_id": "019c"})),
            datetime!(2026-08-14 09:41:07 UTC),
        );
        let mut out = Vec::new();
        result.write_json_line(&mut out).unwrap();
        let line = String::from_utf8(out).unwrap();
        assert_eq!(
            line,
            "{\"schema_version\":\"central.local-result/v1\",\"command_id\":\"run.submit\",\"exit_code\":0,\"reason\":\"ok\",\"details\":{\"run_id\":\"019c\"},\"timestamp\":\"2026-08-14T09:41:07Z\"}\n"
        );
    }

    #[test]
    fn optional_fields_are_omitted_not_null() {
        let result = LocalResult::unsupported("local.wipe");
        let mut out = Vec::new();
        result.write_json_line(&mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["schema_version"], "central.local-result/v1");
        assert_eq!(parsed["command_id"], "local.wipe");
        assert_eq!(parsed["exit_code"], 5);
        assert_eq!(parsed["reason"], "UNSUPPORTED_IN_THIS_SLICE");
        assert!(parsed.get("details").is_none());
        assert!(parsed["timestamp"].as_str().unwrap().ends_with('Z'));
    }
}
