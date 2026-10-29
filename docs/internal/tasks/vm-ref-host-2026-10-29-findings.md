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

## Task V1 — production grant environment is unimplemented — RESOLVED (grant-ceremony-fix)

`bins/central/src/grant_cli.rs` `production_grant_environment()` was a
hard-coded `Err("production instance authority unavailable")`. Fixed on
`grant-ceremony-fix`: the env now resolves
`resolve_production_instance_composition()` + the ceremony owner, and
`issue`/`mode`/`list` are wired through `read_ceremony_mode`,
`write_ceremony_mode`, and the instance grant store (upstream
`grantIssue`/`grantMode`/`grantList` ports). Verified live on the VM:
`grant mode grant` -> `ceremony mode: grant`, `grant issue --kind
lifecycle|prepare` mints grants, `grant list` shows consumed records, and
`local up` then runs past `AUTHORITY_DENIED` to the honest
`ADMISSION_FAILED`/`RUN_CENTRAL_LOCAL_PREPARE` refusal (no staged
dependency). With grant mode the host has a working admission path; V2
below no longer gates it.

## Task V2 — physical-console ceremony denies instantly on `local up` — DIAGNOSED (not a code bug)

Diagnosis (grant-ceremony-fix): the physical_tty ceremony is CORRECT.
Reproduced live on the VM by running the client with a real VT stdin
(`setsid … </dev/tty5`): `Central PAM password:` prompt appeared on
tty5, the password was accepted, the `CONFIRM <code>` phrase printed,
and `local up` then proceeded to the honest
`ADMISSION_FAILED`/`RUN_CENTRAL_LOCAL_PREPARE` refusal.

The earlier instant denials came from clients that did NOT own a
usable physical console: SSH sessions (fd/0 = `/dev/pts/*`, refused by
`open_physical_tty` by design) and tty1 after `ubuntu-desktop-minimal`
installed gdm (the GNOME greeter owns tty1 — keystrokes went to the
greeter, not a getty). Correct runbook: use a real text VT
(Ctrl+Alt+F2+ on a desktop host) and run the `central` client there
with stdin on `/dev/ttyN`.

Small helper-side diagnostics were added (eprintln the confirm Failure
code on the AUTHORITY_DENIED branches) so future refusals are
identifiable from `journalctl -u central-helper` without strace.

## Notes

- Host-side correctness of `central local doctor --host-prerequisites` is
  questionable: it reports `ok` on a 26.04 host (observation-only today).
- `central local doctor` inside the VM reports only OS-release facts.
- V1 is resolved (see above); V2 remains — the physical-TTY ceremony
  still denies instantly. Grant mode is now the usable admission path on
  this host; V2 only matters for `physical_tty` instances and Tier-3
  console-ceremony evidence.
