//! `central-foundation` — the crate every other workspace member may depend
//! on.
//!
//! Two surfaces only:
//!
//! - [`identity`]: opaque RFC 9562 UUIDv7 identity newtypes. `uuid::Uuid`
//!   never escapes this crate; capabilities see only the newtypes
//!   (rust-application-boundaries.md §1).
//! - [`failure`]: the failure taxonomy — `FailureKind`, HTTP status and
//!   stable CLI exit-class mappings, and the structured `Failure` carrier.
//! - [`local_result`]: the `central.local-result/v1` operator-result
//!   envelope every `central` command emits exactly once on stdout.

pub mod failure;
pub mod identity;
pub mod local_result;
