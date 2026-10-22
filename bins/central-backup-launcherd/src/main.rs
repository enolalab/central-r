//! `central-backup-launcherd` — root daemon mediating backup/restore
//! privileged steps (fd-3 `pg_dump`/`pg_restore`)
//! (rust-application-boundaries.md §3.2). Stub binary.

fn main() -> std::process::ExitCode {
    eprintln!("central-backup-launcherd: unsupported in this slice");
    std::process::ExitCode::from(5)
}
