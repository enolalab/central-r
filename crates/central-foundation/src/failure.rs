//! The failure taxonomy — ports `central/internal/failure/failure.go`.
//!
//! [`FailureKind`] classifies how the system reacts to a failure: HTTP
//! status mapping, retry eligibility, exit-class selection, and error
//! propagation. [`Failure`] is the structured carrier handed across
//! boundaries: a stable machine `code` plus a redacted, operator-safe
//! `message` that never carries secrets, raw query text, locators, or
//! untrusted payloads.

use core::fmt;

/// How the system should react to a failure.
///
/// The variant set is intentionally small; new variants change transport
/// and CLI semantics workspace-wide.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// `400` — caller input is malformed.
    Invalid,
    /// `404` — requested resource does not exist.
    NotFound,
    /// `409` — request conflicts with current state.
    Conflict,
    /// `403` — caller lacks permission.
    Denied,
    /// `503` — dependency or service is down.
    Unavailable,
    /// Indeterminate external effect — the outcome of an attempted
    /// mutation is unknown (`409`/`502`).
    Ambiguous,
    /// `409` — explicit cancellation.
    Cancelled,
    /// `500` — unrecoverable internal error.
    Internal,
}

impl FailureKind {
    /// Stable lowercase machine name (matches upstream `Kind.String()`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::Ambiguous => "ambiguous",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal",
        }
    }

    /// Canonical API v1 HTTP status for this kind.
    ///
    /// `Ambiguous` maps to `502` (the effect on a dependency is
    /// indeterminate); a transport may answer `409` instead when the
    /// ambiguity is strictly request-local.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Invalid => 400,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::Denied => 403,
            Self::Unavailable => 503,
            Self::Ambiguous => 502,
            Self::Cancelled => 409,
            Self::Internal => 500,
        }
    }

    /// Default CLI exit class for an unclassified failure of this kind.
    /// Controllers may override with a more specific class where the
    /// contract assigns one (e.g. startup timeouts exit `4`).
    #[must_use]
    pub const fn exit_class(self) -> ExitClass {
        match self {
            Self::Invalid | Self::NotFound => ExitClass::Usage,
            Self::Conflict => ExitClass::Incompatible,
            Self::Denied => ExitClass::Denied,
            Self::Unavailable => ExitClass::Unavailable,
            Self::Ambiguous | Self::Cancelled | Self::Internal => ExitClass::Terminal,
        }
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable CLI exit classes — the value *is* the process exit status.
///
/// Only `0`, `2`, `3`, `4`, `5`, `6`, `7` exist; `1` is never a Central
/// exit class. Semantics follow the `central serve` contract:
///
/// | Exit | Meaning |
/// | ---: | --- |
/// | 0 | intentional stop after durable settlement obligations |
/// | 2 | invalid invocation or configuration |
/// | 3 | required dependency unavailable during startup |
/// | 4 | startup target-lock, pool, or bounded-preflight timeout |
/// | 5 | dirty/incompatible schema or missing/corrupt/non-ready/mismatched restore barrier |
/// | 6 | terminal runtime component failure, indeterminate process state, failed settlement evidence, or total-shutdown timeout |
/// | 7 | denied or insufficient authority |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ExitClass {
    /// `0` — intentional stop after durable settlement obligations.
    Success = 0,
    /// `2` — invalid invocation or configuration.
    Usage = 2,
    /// `3` — required dependency unavailable during startup.
    Unavailable = 3,
    /// `4` — startup target-lock, pool, or bounded-preflight timeout.
    Timeout = 4,
    /// `5` — dirty/incompatible schema or missing/corrupt/non-ready/
    /// mismatched restore barrier.
    Incompatible = 5,
    /// `6` — terminal runtime component failure, indeterminate process
    /// state, failed settlement evidence, or total-shutdown timeout.
    Terminal = 6,
    /// `7` — denied or insufficient authority.
    Denied = 7,
}

impl ExitClass {
    /// The process exit status value.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for ExitClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl From<ExitClass> for std::process::ExitCode {
    fn from(class: ExitClass) -> Self {
        Self::from(class.code())
    }
}

/// A structured failure: classified kind, stable machine `code`, and a
/// redacted `message` safe for operators, logs, and wire envelopes.
///
/// `message` is built at the call site and must already be sanitized —
/// never secrets, tokens, raw SQL/object locators, internal error text,
/// or unbounded untrusted input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    kind: FailureKind,
    code: &'static str,
    message: String,
}

impl Failure {
    /// Builds a failure. `code` is part of the stable machine vocabulary;
    /// `message` must already be redacted.
    pub fn new(kind: FailureKind, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            code,
            message: message.into(),
        }
    }

    /// [`FailureKind::Invalid`] shorthand.
    pub fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(FailureKind::Invalid, code, message)
    }

    /// [`FailureKind::NotFound`] shorthand.
    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(FailureKind::NotFound, code, message)
    }

    /// [`FailureKind::Conflict`] shorthand.
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(FailureKind::Conflict, code, message)
    }

    /// [`FailureKind::Denied`] shorthand.
    pub fn denied(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(FailureKind::Denied, code, message)
    }

    /// [`FailureKind::Unavailable`] shorthand.
    pub fn unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(FailureKind::Unavailable, code, message)
    }

    /// [`FailureKind::Ambiguous`] shorthand.
    pub fn ambiguous(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(FailureKind::Ambiguous, code, message)
    }

    /// [`FailureKind::Cancelled`] shorthand.
    pub fn cancelled(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(FailureKind::Cancelled, code, message)
    }

    /// [`FailureKind::Internal`] shorthand.
    pub fn internal(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(FailureKind::Internal, code, message)
    }

    /// The failure classification.
    #[must_use]
    pub const fn kind(&self) -> FailureKind {
        self.kind
    }

    /// The stable machine code (safe for wire envelopes).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The redacted, operator-safe message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// [`FailureKind::http_status`] for this failure's kind.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        self.kind.http_status()
    }

    /// [`FailureKind::exit_class`] for this failure's kind.
    #[must_use]
    pub const fn exit_class(&self) -> ExitClass {
        self.kind.exit_class()
    }
}

impl fmt::Display for Failure {
    /// `[code] message` — matches the upstream `Failure.Error()` shape.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for Failure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_kind_names_match_upstream() {
        assert_eq!(FailureKind::Invalid.as_str(), "invalid");
        assert_eq!(FailureKind::NotFound.as_str(), "not_found");
        assert_eq!(FailureKind::Conflict.as_str(), "conflict");
        assert_eq!(FailureKind::Denied.as_str(), "denied");
        assert_eq!(FailureKind::Unavailable.as_str(), "unavailable");
        assert_eq!(FailureKind::Ambiguous.as_str(), "ambiguous");
        assert_eq!(FailureKind::Cancelled.as_str(), "cancelled");
        assert_eq!(FailureKind::Internal.as_str(), "internal");
        assert_eq!(FailureKind::NotFound.to_string(), "not_found");
    }

    #[test]
    fn failure_kind_http_status_mapping() {
        assert_eq!(FailureKind::Invalid.http_status(), 400);
        assert_eq!(FailureKind::NotFound.http_status(), 404);
        assert_eq!(FailureKind::Conflict.http_status(), 409);
        assert_eq!(FailureKind::Denied.http_status(), 403);
        assert_eq!(FailureKind::Unavailable.http_status(), 503);
        assert_eq!(FailureKind::Ambiguous.http_status(), 502);
        assert_eq!(FailureKind::Cancelled.http_status(), 409);
        assert_eq!(FailureKind::Internal.http_status(), 500);
    }

    #[test]
    fn failure_kind_exit_class_mapping() {
        assert_eq!(FailureKind::Invalid.exit_class(), ExitClass::Usage);
        assert_eq!(FailureKind::NotFound.exit_class(), ExitClass::Usage);
        assert_eq!(FailureKind::Conflict.exit_class(), ExitClass::Incompatible);
        assert_eq!(FailureKind::Denied.exit_class(), ExitClass::Denied);
        assert_eq!(
            FailureKind::Unavailable.exit_class(),
            ExitClass::Unavailable
        );
        assert_eq!(FailureKind::Ambiguous.exit_class(), ExitClass::Terminal);
        assert_eq!(FailureKind::Cancelled.exit_class(), ExitClass::Terminal);
        assert_eq!(FailureKind::Internal.exit_class(), ExitClass::Terminal);
    }

    #[test]
    fn exit_class_codes_are_the_process_exit_status() {
        assert_eq!(ExitClass::Success.code(), 0);
        assert_eq!(ExitClass::Usage.code(), 2);
        assert_eq!(ExitClass::Unavailable.code(), 3);
        assert_eq!(ExitClass::Timeout.code(), 4);
        assert_eq!(ExitClass::Incompatible.code(), 5);
        assert_eq!(ExitClass::Terminal.code(), 6);
        assert_eq!(ExitClass::Denied.code(), 7);
        let codes = [
            ExitClass::Success,
            ExitClass::Usage,
            ExitClass::Unavailable,
            ExitClass::Timeout,
            ExitClass::Incompatible,
            ExitClass::Terminal,
            ExitClass::Denied,
        ]
        .map(ExitClass::code);
        assert!(!codes.contains(&1), "exit status 1 is never a class");
        let _process_code: std::process::ExitCode = ExitClass::Terminal.into();
    }

    #[test]
    fn failure_carries_kind_code_and_redacted_message() {
        let failure = Failure::new(
            FailureKind::NotFound,
            "workspace_not_found",
            "the workspace is not visible to this session",
        );
        assert_eq!(failure.kind(), FailureKind::NotFound);
        assert_eq!(failure.code(), "workspace_not_found");
        assert_eq!(
            failure.message(),
            "the workspace is not visible to this session"
        );
        assert_eq!(failure.http_status(), 404);
        assert_eq!(failure.exit_class(), ExitClass::Usage);
        assert_eq!(
            failure.to_string(),
            "[workspace_not_found] the workspace is not visible to this session"
        );
        let standard: &dyn std::error::Error = &failure;
        assert!(standard.source().is_none());
    }

    #[test]
    fn failure_kind_shorthand_constructors() {
        assert_eq!(Failure::invalid("c", "m").kind(), FailureKind::Invalid);
        assert_eq!(Failure::not_found("c", "m").kind(), FailureKind::NotFound);
        assert_eq!(Failure::conflict("c", "m").kind(), FailureKind::Conflict);
        assert_eq!(Failure::denied("c", "m").kind(), FailureKind::Denied);
        assert_eq!(
            Failure::unavailable("c", "m").kind(),
            FailureKind::Unavailable
        );
        assert_eq!(Failure::ambiguous("c", "m").kind(), FailureKind::Ambiguous);
        assert_eq!(Failure::cancelled("c", "m").kind(), FailureKind::Cancelled);
        assert_eq!(Failure::internal("c", "m").kind(), FailureKind::Internal);
    }
}
