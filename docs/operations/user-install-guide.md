# Central install guide (for users)

> Host: Ubuntu 24.04 amd64 with Docker installed. About 30 minutes total for
> the release path (roughly 15 of them unattended package work).
>
> The install path is real and exercised end to end: a release's `install.sh`
> takes a bare host to a running instance, and the accepted `central local …`
> verbs work on it. Verbs whose slice is not yet accepted return exit `5` /
> `UNSUPPORTED_IN_THIS_SLICE` without mutating anything — see
> [`../implementation/current-phase.md`](../implementation/current-phase.md).
>
> The installer is safe to rerun: a step that is already done reports
> `OK ... (already present)`. It never overwrites a configuration or unit
> file that differs from what it would write — it prints the diff and stops.

## 0. Prepare the host (once, about 10 minutes)

1. Install Docker Engine and the compose plugin, then enable the containerd
   image store: add `"features": {"containerd-snapshotter": true}` to
   `/etc/docker/daemon.json` and run `sudo systemctl restart docker`.
2. Your user must **not** be in the `docker` group (that group is
   root-equivalent): `sudo gpasswd -d "$USER" docker`, then log out and back
   in.
3. Install `curl` (release downloads) and `gnupg` (the installer checks the
   PostgreSQL apt key's fingerprint with `gpg` before trusting it):
   `sudo apt-get install curl gnupg`. The build tools `gcc make libpam0g-dev`
   and Go 1.26.6 (the version in `go.mod`, from [go.dev](https://go.dev/dl/))
   are only needed for `--from-source` (section 3) — a release install builds
   nothing.
4. At least 40 GiB free on the filesystem that holds `/var/lib`
   (`df -h /var/lib`); 8 GiB RAM recommended.

## 1. Install from a release (production)

Every release ships a stamped `install.sh` (version + release public key
embedded) as a standalone asset. Download it and `SHA256SUMS`, verify the
checksum, check the embedded key's fingerprint out of band, then run it —
never `curl | bash` blind:

```bash
TAG=v0.x.y   # pick a tag from https://github.com/enolalab/central/releases
curl -fSLO "https://github.com/enolalab/central/releases/download/$TAG/install.sh"
curl -fSLO "https://github.com/enolalab/central/releases/download/$TAG/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing                        # expect: install.sh: OK
bash install.sh --show-release-key                            # fingerprint must match docs/operations/release-authority-custody.md
sudo bash install.sh                                          # 1. host steps (about 15 minutes)
central local init                                            # 2. at the machine's console, not SSH
sudo /usr/lib/central/install/install.sh                      # 3. enables the broker, reports what is left
sudo /usr/lib/central/install/install.sh --verify             # check; --uninstall removes it (data is kept)
```

`--ignore-missing` is needed because `SHA256SUMS` also lists the tarball you
did not download; the script itself fetches and verifies that tarball
(signature + checksum) before changing anything. The `SHA256:...` fingerprint
from `--show-release-key` must match
[`release-authority-custody.md`](release-authority-custody.md) — continue only
if the two match.

Step 1 pins `postgresql-client-16` at 16.14, creates the `central_runtime`
(501) and `central_migrate` (986) users, copies the binaries and a root-owned
installer copy into `/usr/lib/central`, writes the PAM service and systemd
units, and records each item in `/var/lib/central-install/manifest.json` as
it goes. Log: `/var/log/central-install.log` (mode 0600, root).

Step 2, `central local init`, must run **at the machine's own console** — a
text console (Ctrl+Alt+F3) or the VM's console window, not SSH. Turn off any
input method first. The command asks for your password, then a confirmation
phrase typed exactly as shown (no quotes) within the stated seconds. A first
mismatch prints `That did not match. Turn off any input method and type it
again.` and allows one retry; a second exits 7 having created nothing —
disable the input method and rerun.

Step 3 reruns the now root-owned installed copy with the same flags as the
first run (none, for a release install): it enables the broker and prints
the **after genesis** items — what the host still needs for `local prepare`,
`local up`, and `migrate up`.

Step 4, `--verify`, is read-only: each line is `OK` or `FAIL` with a fix,
`SKIP` for `migrate status` while the instance is not running. Exit 0 means
every check passed.

### Admission modes

`central local init` and later lifecycle operations are admitted one of
three ways:

- **Physical-console ceremony** (production default, `physical_tty`): the
  console prompt above. A release install needs no flags.
- **Grant mode**: root pre-authorizes one operation with
  `sudo central grant issue --kind init --ttl 10m`, after which
  `sudo -u <operator> central local init` runs over SSH with no ceremony.
  One usable grant at a time (a second issue is refused with
  `GRANT_PENDING` unless `--replace`); TTL max 15 minutes; each grant is
  single-use and bound to the current boot. An instance created this way is
  already in grant mode (`--kind lifecycle` grants work immediately).
- **`--dev-admission`** (development hosts only): swaps in the B01
  development evaluator and requires `--yes`. **Never acceptance evidence.**

## 2. Offline bundle import (maintainer exports, user imports)

An end user's machine holds no private key, so it cannot build and sign a
release itself: a maintainer exports a release directory once, the user
imports it. Both flags need `=` (`--export-release=<dir>`,
`--from-release=<dir>`); written with a space (`--from-release /tmp/...`)
the flag is silently ignored and the command runs like plain `prepare`.

1. Maintainer, on the machine holding the key (must have run `up` at least
   once so the infra image exists):
   `central local prepare --export-release=/tmp/central-release-a1` → exit 0,
   a 7-file directory: `release.json`, `minio/` (image, comparison, 3
   attestations), `infra/image.tar`.
2. Maintainer packs and ships it:
   `tar czf central-release-a1.tar.gz -C /tmp central-release-a1`, reads the
   `sha256sum`, and sends the file plus its hash over a trusted channel.
3. User, on the receiving machine: verifies the hash (byte-exact
   `sha256sum`) and extracts `tar xzf central-release-a1.tar.gz -C /tmp`.
4. User imports — this needs a grant and runs as the operator user like
   every `local` command: root runs
   `sudo central grant issue --kind prepare --ttl 1h`, then
   `sudo -u <operator> central local prepare --from-release=/tmp/central-release-a1`
   → exit 0. An imported release downloads and builds nothing, so no network
   is needed.
5. User continues normally: `local up`, `migrate up`, `local up` (each
   `migrate` command costs a separate `--kind lifecycle` grant).

Rules: a keyless machine running plain `prepare` fails with
`PREPARE_UNAVAILABLE` immediately and writes no log; a release altered by
even one byte fails with `RELEASE_UNTRUSTED` and nothing is written to the
store.

### Building the infra image yourself (no GHCR token)

The dependency lock pins `ghcr.io/enolalab/central-local-infra` by digest.
While that image is private, plain `local prepare` fails at the fetch with
`denied`. To build it locally instead:

1. Clone and build the infra image from
   [`central-local-infra`](https://github.com/enolalab/central-local-infra):
   `docker build -t ghcr.io/enolalab/central-local-infra .` (or the repo's
   build recipe), then read its digest:
   `docker inspect --format='{{index .RepoDigests 0}}'
   ghcr.io/enolalab/central-local-infra` (or
   `docker images --digests` for a local-only image).
2. In the `central-workspace` checkout, repoint the lock: in
   `crates/capabilities/central-infra/src/prepare/assets/dependency-lock.json`
   set every mode's `index_digest`, `manifest_digest`, and
   `config_digest` that references the infra image to your local digests,
   then recompute `recipe_digest`/the lock digest per
   `prepare::Lock::verify_*`. This repoint is **host-local state — do not
   commit it** (VM finding V7; the repository keeps the upstream pin).
3. Rebuild `central` (`cargo build --workspace`) so the embedded lock is
   refreshed, then continue with `local prepare` normally.

This path was validated on the `central-ref` reference host (2026-10-29):
a repointed lock plus a locally built image completes `local up` →
`PROVISIONED`. A public GHCR image — removing this step entirely — is a
tracked follow-up in
[`docs/internal/tasks/open-source-readiness.md`](../internal/tasks/open-source-readiness.md).

## 3. From a checkout (development)

`--from-source` builds the binaries from a checkout **as your own user** (not
root) and replaces the Central binaries in `/usr/lib/central`, printing each
one it replaces. The checkout's own script runs the first install and every
upgrade; every other run uses the root-owned installed copy:

```bash
packaging/install/install.sh --dry-run --operator-user "$USER" --from-source "$PWD" --dev-admission --yes   # preview, no changes
sudo packaging/install/install.sh --from-source "$PWD" --dev-admission --yes   # 1. host steps (about 15 minutes)
central local init                                                             # 2. at the machine's console, not SSH
sudo /usr/lib/central/install/install.sh --dev-admission --yes                 # 3. enables the broker
sudo /usr/lib/central/install/install.sh --verify                              # check
```

`--from-source` treats the checkout as **root-equivalent input**: use it on
a development host only (the installer also refuses to run while the harness
launcher is active). Keep the **same flags on every run** — changing flags
between runs makes `/etc/central/helper.env` differ, and the installer prints
the diff and stops rather than overwriting it. A dev build has no signed
attestation chain, hence `--dev-admission --yes` each run.

## 4. Upgrade and uninstall

**Upgrade (release):** run the new version's stamped `install.sh` — the same
flow as section 1. Deliberately downgrading works the same way with an older
version's script; a same-version rerun is a no-op.

**Upgrade (checkout):** always run the *new* checkout's script, not the
installed copy: `sudo <checkout>/packaging/install/install.sh --from-source
<checkout> --yes` (harness launcher stopped). The installed copy holds its
own script and units and refuses (exit 3) a `--from-source` checkout whose
script or units differ, printing the correct command.

**Uninstall:** `sudo /usr/lib/central/install/install.sh --uninstall` removes
only what the manifest lists (units, binaries, config files, created users).
Data (`/var/lib/central-state`, `/var/lib/central-protected`) is **kept**;
add `--purge-data` to delete it (type the instance id exactly, or `--yes
--purge-data`). With `--purge-data` the installer stops the instance's
containers first — if `docker compose down` fails or the Docker daemon does
not answer, data is **not** deleted: it prints `NOT REMOVED`, lists the
remaining containers, and exits 1. If anything survives the uninstall the
command lists the leftovers, keeps the manifest, and exits 1 — fix them and
rerun the same command. A missing or unparseable manifest is refused (exit
3) with nothing changed.

## Troubleshooting

Every preflight failure prints one cause line, one `fix:` line, and
`nothing was changed`. Exit 3 is a failed precondition, exit 4 insufficient
disk, exit 2 bad arguments, exit 7 a mistyped console phrase.

The full error table — every installer refusal and `central local` error
with its fix — lives in [`../known-limitations.md`](../known-limitations.md);
the Vietnamese guide's fix table at
[`user-install-guide.vi.md`](user-install-guide.vi.md#gặp-lỗi-thường-gặp)
covers the same ground.
