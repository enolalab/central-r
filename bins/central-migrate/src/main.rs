//! `central-migrate` — migration operator binary; mutating migration
//! ops run in a single `central_migration` session
//! (rust-application-boundaries.md §3.2). Stub binary.

fn main() -> std::process::ExitCode {
    eprintln!("central-migrate: unsupported in this slice");
    std::process::ExitCode::from(5)
}
