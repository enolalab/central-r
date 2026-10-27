//! C06 Slice C full-recovery acceptance suite — the Rust port of upstream's
//! `internal/recovery` portable machine plus `cmd/central`'s
//! `c06_slice_c_acceptance_test.go` and `c06_ceremony_driver_test.go`
//! (R6 Task 10 slice A).
//!
//! Layout mirrors upstream: the catalogue, the runner, the skip census, the
//! reconciliation, the evidence emitter and the fingerprint comparison are
//! the portable half (`catalogue`, `runner`, `fingerprint`, `evidence`,
//! `profile`); the reference-host driver is `fixture` + `slice_c`; the
//! ceremony driver is `ceremony`. Later slices land the remaining scenario
//! bodies (`c06_scenario{2,34,5,6,78}` and the continuous run) against these
//! shared modules without touching the machine.

// Test-target relaxation, same as `phase2_acceptance`: a refused run IS the
// assertion — panic/unwrap/expect are how a libtest body reports FailNow.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
// The driver and the record/fixture surface carry the shared machinery Task
// 10b's scenario files plug into — upstream keeps the same helpers in the
// ceremony-driver test file where the later scenarios consume them. Parts
// are deliberately unexercised until those bodies land; they are the port's
// structure, not dead weight.
#![allow(dead_code)]

/// Lowercase hex — the Go `hex.EncodeToString` shape the upstream machine
/// emits for every digest. Local to the suite; the workspace does not carry
/// a hex crate.
pub(crate) fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

mod catalogue;
mod ceremony;
mod evidence;
mod fingerprint;
mod fixture;
mod profile;
mod runner;
mod scenario2;
mod slice_c;
