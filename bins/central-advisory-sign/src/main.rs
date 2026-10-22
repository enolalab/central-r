//! `central-advisory-sign` — offline Ed25519 advisory signing tool; no
//! network, no database (rust-application-boundaries.md §2.1/§3.2).
//! Stub binary.

fn main() -> std::process::ExitCode {
    eprintln!("central-advisory-sign: unsupported in this slice");
    std::process::ExitCode::from(5)
}
