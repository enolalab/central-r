# Findings from the `central-ref` VirtualBox bring-up (2026-10-29)

A Ubuntu 24.04.4 reference-profile VM (`~/VMs/central-ref`, SSH
`central@127.0.0.1:2222`) was provisioned per
`docs/operations/local-prerequisites.md`: pinned Docker 29.6.1 + Compose
plugin 5.3.1 with the containerd image store, `pg_dump` 16.14, quota,
apparmor, libnss3-tools, Go 1.26.6, buildctl, `central-runtime` (501) and
`central_migrate` (986), `/var/lib/central-browser` on a dedicated ext4 with
`prjquota` enabled via fstab, upstream helper/broker socket units, PAM
`central-helper`, and a `--dev-admission`-equivalent `helper.env`.

What works: `central local init` (via `grant issue --kind init`, grant
consumed correctly), `local status` -> `STOPPED`, `local init` idempotent
`ALREADY_INITIALIZED`, helper logs the designed keyless import-only note.

## Task V1 — production grant environment is unimplemented

`bins/central/src/grant_cli.rs` `production_grant_environment()` is a
hard-coded `Err("production instance authority unavailable")`, so every
`grant issue --kind <lifecycle|prepare|...>` after init exits 6. Only
`--kind init` dispatches on the pre-instance env. This blocks every
grant-admitted verb on a real host (the port has no non-console admission
path at all).

## Task V2 — physical-console ceremony denies instantly on `local up`

`central local up` run by the operator on tty1 (real VT, stdin =
`/dev/tty1`) returns `LIFECYCLE_EXECUTION_FAILED` / `AUTHORITY_DENIED`
within ~1s, with no PAM or CONFIRM prompt ever reaching the console. The
helper's lifecycle path calls `pam.confirm(peer)` first; the confirmer
fails before `open_physical_tty` writes anything (no journal output
either). Needs helper-side tracing on the VM to identify whether the
peer-console open, PAM conversation, or confirmer composition fails.

## Notes

- Host-side correctness of `central local doctor --host-prerequisites` is
  questionable: it reports `ok` on a 26.04 host (observation-only today).
- `central local doctor` inside the VM reports only OS-release facts.
- V1+V2 together mean lifecycle verbs currently have no admission path on
  the Rust port; Tier-3 evidence for `local up` is gated on both.
