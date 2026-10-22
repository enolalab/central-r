//! `central-harness-launcherd` — root daemon (socket-activated) that
//! launches isolated operator harness sessions per ADR 0036
//! (rust-application-boundaries.md §3.2). Stub binary.

fn main() -> std::process::ExitCode {
    eprintln!("central-harness-launcherd: unsupported in this slice");
    std::process::ExitCode::from(5)
}
