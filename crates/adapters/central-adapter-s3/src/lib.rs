//! `central-adapter-s3` — S3/MinIO object storage adapter implementing
//! `central-artifact` body-store port traits (upstream
//! `internal/adapter/objectstore`).
//!
//! Sole consumer of `aws-sdk-s3`/`aws-config`/`sha2` for artifact bodies.
//! The adapter never exposes an object-store locator: keys are validated
//! role tokens (`v1/staging/…`, `v1/ready/…`) checked before any request
//! leaves the process, and [`error::Failure`] renders only closed
//! operation/class/reason tokens.
//!
//! Bounded-transfer contract (upstream `objectstore` package docs): at most
//! `central_artifact::port::MAX_CONCURRENT_TRANSFERS` transfers run at once,
//! every body stops one byte past its declared ceiling without committing,
//! stalls are cut at the idle deadline, and every transfer is capped by the
//! total deadline.

pub mod error;
mod limiter;
mod store;
mod stream;

pub use error::{Failure, FailureClass, Reason, S3FailureClassifier};
pub use limiter::TransferLimiter;
pub use store::{Config, S3ObjectStore, STAGING_PART_SIZE_BYTES};
pub use stream::PermitStream;

#[cfg(test)]
pub(crate) mod fakes3;

#[cfg(test)]
mod tests;
