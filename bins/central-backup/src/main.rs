//! `central-backup` — backup operator binary under the shared/exclusive
//! advisory lock matrix (rust-application-boundaries.md §3.2). Stub
//! binary.

fn main() -> std::process::ExitCode {
    eprintln!("central-backup: unsupported in this slice");
    std::process::ExitCode::from(5)
}
