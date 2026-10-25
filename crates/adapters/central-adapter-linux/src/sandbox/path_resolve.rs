//! `path_resolve.go` — descriptor-relative path resolution for the
//! sandbox boundary: open beneath a delegated directory descriptor
//! with no symlink following, no `..` escape, no mount-point or
//! magic-link traversal. The whole upstream contract is already the
//! [`crate::sys::openat2`] primitive (RESOLVE_BENEATH | NO_SYMLINKS |
//! NO_MAGICLINKS | NO_XDEV); this module names it for the sandbox
//! surface so call sites read with the upstream file's vocabulary.
//!
//! Upstream resolves paths inside the workspace root the caller
//! handed over; A06 makes that delegation a received descriptor, so
//! every resolution is descriptor-relative by construction.

pub use crate::sys::openat2::{resolve, resolve_directory, resolve_regular_file};
