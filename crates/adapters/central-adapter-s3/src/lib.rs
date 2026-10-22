//! `central-adapter-s3` — S3/MinIO object storage adapter implementing
//! `central-artifact` body-store port traits. Sole consumer of
//! `aws-sdk-s3`/`aws-config`/`sha2` for artifact bodies.
//!
//! Stub crate: implementations land in this adapter's R-slice
//! (rust-application-boundaries.md §2.4).
