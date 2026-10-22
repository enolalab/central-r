//! Typed, sanitized failures — the only error type this adapter produces
//! (port of upstream `objectstore.Failure`).
//!
//! The `aws_sdk_s3` error surface is confined to this file: no SDK type, no
//! bucket name, no object key, and no endpoint ever escapes through a
//! returned [`Failure`] or through the port-level
//! `central_foundation::failure::Failure` it converts into at the boundary.
//! `Failure` deliberately does not wrap its SDK cause: a wrapped cause would
//! let a bucket, key, or endpoint reach a log line through `source()` or
//! `Display` on the chain.
//!
//! Classification separates known non-delivery (the write certainly did not
//! land) from ambiguity (the write may or may not have landed), because only
//! the former is safe to retry blindly.

use std::fmt;

use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use central_artifact::app::{ObjectFailureClass, ObjectFailureClassifier};
use central_foundation::failure::{Failure as PortFailure, FailureKind};

/// The closed set of outcomes the Artifact app service distinguishes
/// (upstream `FailureClass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// A caller-side contract violation detected before any request reaches
    /// the object store (upstream `FailureInvalid`).
    Invalid,
    /// Known non-delivery: the object is absent.
    NotFound,
    /// Known non-delivery: a create-only precondition lost to an existing
    /// object. The existing object is authoritative.
    Conflict,
    /// Known non-delivery: the runtime principal is not permitted to
    /// perform this operation.
    Denied,
    /// Known non-delivery: the body exceeded its declared ceiling and was
    /// never committed.
    LimitExceeded,
    /// Known non-delivery: the object store rejected the request before
    /// accepting a body.
    Unavailable,
    /// The conservative default. The transfer's fate is unknown, so the
    /// caller must reconcile rather than blindly retry.
    Ambiguous,
}

impl FailureClass {
    /// The upstream wire token (`INVALID`, `NOT_FOUND`, …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "INVALID",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::Denied => "DENIED",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::Unavailable => "UNAVAILABLE",
            Self::Ambiguous => "AMBIGUOUS",
        }
    }

    /// The workspace taxonomy kind this class converts to.
    ///
    /// `LimitExceeded` has no dedicated [`FailureKind`]; it maps to
    /// [`FailureKind::Invalid`] — a caller-side contract violation — and is
    /// recovered downstream through the `code` token, which is
    /// [`Reason::LimitExceeded`] for this class and this class only.
    const fn kind(self) -> FailureKind {
        match self {
            Self::Invalid | Self::LimitExceeded => FailureKind::Invalid,
            Self::NotFound => FailureKind::NotFound,
            Self::Conflict => FailureKind::Conflict,
            Self::Denied => FailureKind::Denied,
            Self::Unavailable => FailureKind::Unavailable,
            Self::Ambiguous => FailureKind::Ambiguous,
        }
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A closed, locator-free reason code (upstream `Reason`). Reason values are
/// safe to log: none of them can carry a bucket, key, endpoint, or upstream
/// message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The key is not valid for the role this operation requires
    /// (staging-only, ready-only).
    KeyRoleInvalid,
    /// The declared byte ceiling is out of contract range.
    LimitInvalid,
    /// The adapter configuration is incomplete or malformed.
    ConfigInvalid,
    /// A required body was absent.
    BodyMissing,
    /// The addressed object is absent.
    ObjectMissing,
    /// The create-only precondition lost to an existing object.
    PreconditionConflict,
    /// The runtime principal lacks permission.
    AccessDenied,
    /// The body exceeded its declared ceiling; it was never committed.
    LimitExceeded,
    /// The transfer made no byte progress within the idle deadline.
    IdleTimeout,
    /// The transfer exceeded its total deadline.
    TotalDeadline,
    /// The caller's cancellation resolved the wait or the transfer.
    Canceled,
    /// The store (or a non-response upstream edge) rejected the request.
    UpstreamRejected,
    /// The transfer's fate is unknown; reconcile rather than retry.
    TransferIncomplete,
}

impl Reason {
    /// The upstream wire token (`key_role_invalid`, …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyRoleInvalid => "key_role_invalid",
            Self::LimitInvalid => "limit_invalid",
            Self::ConfigInvalid => "config_invalid",
            Self::BodyMissing => "body_missing",
            Self::ObjectMissing => "object_missing",
            Self::PreconditionConflict => "precondition_conflict",
            Self::AccessDenied => "access_denied",
            Self::LimitExceeded => "limit_exceeded",
            Self::IdleTimeout => "idle_timeout",
            Self::TotalDeadline => "total_deadline",
            Self::Canceled => "canceled",
            Self::UpstreamRejected => "upstream_rejected",
            Self::TransferIncomplete => "transfer_incomplete",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The only error type this adapter returns (upstream `Failure`). It
/// deliberately does not wrap its SDK cause: an unwrappable cause would let
/// a bucket, key, or endpoint reach a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The closed operation token (`upload`, `read`, `promote`, …).
    pub op: &'static str,
    /// The closed outcome class.
    pub class: FailureClass,
    /// The closed reason code.
    pub reason: Reason,
}

impl Failure {
    /// Upstream `FailureClass()`/`FailureReason()` exposed as methods so a
    /// caller holding only the error can recover the classification without
    /// parsing the rendered text.
    #[must_use]
    pub const fn failure_class(&self) -> FailureClass {
        self.class
    }

    /// The closed reason code.
    #[must_use]
    pub const fn failure_reason(&self) -> Reason {
        self.reason
    }
}

impl fmt::Display for Failure {
    /// `"objectstore: {op} {class} ({reason})"` — only the closed operation,
    /// class, and reason codes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "objectstore: {} {} ({})",
            self.op, self.class, self.reason
        )
    }
}

impl std::error::Error for Failure {}

/// The boundary conversion into the workspace failure taxonomy (port.rs
/// §2.4): the class maps onto [`FailureKind`] and the reason is carried as
/// the stable machine `code`, so the composition-root
/// [`ObjectFailureClassifier`] recovers the class without parsing text.
/// The rendered message stays the locator-free `"objectstore: …"` form.
impl From<Failure> for PortFailure {
    fn from(f: Failure) -> Self {
        PortFailure::new(f.class.kind(), f.reason.as_str(), f.to_string())
    }
}

/// Builds one typed failure (upstream `fail`).
pub(crate) fn fail(op: &'static str, class: FailureClass, reason: Reason) -> Failure {
    Failure { op, class, reason }
}

/// Converts an SDK error into a typed, locator-free [`Failure`] (upstream
/// `Store.classify` for the `minio.ErrorResponse` branch). The upstream
/// error is inspected here and then dropped: nothing from it — message,
/// resource, request id, host id — is carried forward.
///
/// Anything not positively identified as known non-delivery is `AMBIGUOUS`,
/// because a caller that cannot prove the write did not land must reconcile
/// rather than retry.
pub(crate) fn classify_sdk<E>(op: &'static str, err: &SdkError<E>) -> Failure
where
    E: ProvideErrorMetadata,
{
    let status = err.raw_response().map(|r| r.status().as_u16());
    let code = err.as_service_error().and_then(|e| e.code());

    if let Some(status) = status {
        match status {
            404 => return fail(op, FailureClass::NotFound, Reason::ObjectMissing),
            412 | 409 => {
                return fail(op, FailureClass::Conflict, Reason::PreconditionConflict);
            }
            401 | 403 => return fail(op, FailureClass::Denied, Reason::AccessDenied),
            400 | 405 | 411 | 413 => {
                return fail(op, FailureClass::Unavailable, Reason::UpstreamRejected);
            }
            _ => {}
        }
    }
    match code {
        Some("NoSuchKey") | Some("NoSuchBucket") => {
            return fail(op, FailureClass::NotFound, Reason::ObjectMissing);
        }
        Some("PreconditionFailed") => {
            return fail(op, FailureClass::Conflict, Reason::PreconditionConflict);
        }
        _ => {}
    }
    // The SDK's own operation timeout is a deadline trip: the request may
    // already have been applied, so it is ambiguous rather than retryable.
    if matches!(err, SdkError::TimeoutError(_)) {
        return fail(op, FailureClass::Ambiguous, Reason::TotalDeadline);
    }
    // 5xx, transport resets, unparseable responses, and unknown SDK errors
    // are all ambiguous by construction.
    fail(op, FailureClass::Ambiguous, Reason::TransferIncomplete)
}

/// The composition-root classifier installed beside `central-artifact`'s
/// [`ObjectStore`] implementation (upstream: the `ObjectFailures` wiring in
/// the service config). It recovers the [`ObjectFailureClass`] from the
/// port-boundary [`PortFailure`]'s closed `kind`/`code` tokens — never from
/// message text.
#[derive(Debug, Default, Clone, Copy)]
pub struct S3FailureClassifier;

impl ObjectFailureClassifier for S3FailureClassifier {
    fn classify_object_failure(&self, failure: &PortFailure) -> ObjectFailureClass {
        // `limit_exceeded` is the one class the `FailureKind` taxonomy
        // cannot express (`FailureClass::LimitExceeded` maps to
        // `FailureKind::Invalid`); the closed reason token distinguishes
        // it. Every other class round-trips through `kind`.
        if failure.code() == Reason::LimitExceeded.as_str() {
            return ObjectFailureClass::LimitExceeded;
        }
        match failure.kind() {
            FailureKind::Invalid => ObjectFailureClass::Invalid,
            FailureKind::NotFound => ObjectFailureClass::NotFound,
            FailureKind::Conflict => ObjectFailureClass::Conflict,
            FailureKind::Denied => ObjectFailureClass::Denied,
            FailureKind::Unavailable => ObjectFailureClass::Unavailable,
            FailureKind::Ambiguous | FailureKind::Cancelled => ObjectFailureClass::Ambiguous,
            _ => ObjectFailureClass::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_renders_only_closed_tokens() {
        let f = fail("upload", FailureClass::Denied, Reason::AccessDenied);
        assert_eq!(f.to_string(), "objectstore: upload DENIED (access_denied)");
        assert_eq!(f.failure_class(), FailureClass::Denied);
        assert_eq!(f.failure_reason(), Reason::AccessDenied);
        let e: &dyn std::error::Error = &f;
        assert!(e.source().is_none());
    }

    #[test]
    fn port_conversion_carries_kind_and_reason_code() {
        let port: PortFailure = fail(
            "promote",
            FailureClass::Conflict,
            Reason::PreconditionConflict,
        )
        .into();
        assert_eq!(port.kind(), FailureKind::Conflict);
        assert_eq!(port.code(), "precondition_conflict");
        assert_eq!(
            port.message(),
            "objectstore: promote CONFLICT (precondition_conflict)"
        );
    }

    #[test]
    fn classifier_recovers_every_class_without_parsing() {
        let classifier = S3FailureClassifier;
        for (class, reason, want) in [
            (
                FailureClass::Invalid,
                Reason::KeyRoleInvalid,
                ObjectFailureClass::Invalid,
            ),
            (
                FailureClass::NotFound,
                Reason::ObjectMissing,
                ObjectFailureClass::NotFound,
            ),
            (
                FailureClass::Conflict,
                Reason::PreconditionConflict,
                ObjectFailureClass::Conflict,
            ),
            (
                FailureClass::Denied,
                Reason::AccessDenied,
                ObjectFailureClass::Denied,
            ),
            (
                FailureClass::LimitExceeded,
                Reason::LimitExceeded,
                ObjectFailureClass::LimitExceeded,
            ),
            (
                FailureClass::Unavailable,
                Reason::UpstreamRejected,
                ObjectFailureClass::Unavailable,
            ),
            (
                FailureClass::Ambiguous,
                Reason::IdleTimeout,
                ObjectFailureClass::Ambiguous,
            ),
        ] {
            let port: PortFailure = fail("op", class, reason).into();
            assert_eq!(
                classifier.classify_object_failure(&port),
                want,
                "{class:?}/{reason:?}"
            );
        }
        // A failure this adapter never mints fails safe to Unknown — which
        // the service treats as ambiguity.
        let foreign = PortFailure::internal("other", "unrelated");
        assert_eq!(
            classifier.classify_object_failure(&foreign),
            ObjectFailureClass::Unknown
        );
    }
}
