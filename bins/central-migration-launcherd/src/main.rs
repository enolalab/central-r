//! `central-migration-launcherd` — root daemon mediating the
//! `central_migration` privilege per ADR 0011
//! (rust-application-boundaries.md §3.2). Stub binary.

fn main() -> std::process::ExitCode {
    eprintln!("central-migration-launcherd: unsupported in this slice");
    std::process::ExitCode::from(5)
}
