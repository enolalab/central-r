# Install acceptance rehearsal

Maintainer-executed runbook: prove a tagged release installs end to end on a
clean **Ubuntu 24.04 amd64** VM before that release is called good. The first
real release gates on a completed record of this run (see the record template
at the bottom).

Spec: `docs/internal/superpowers/specs/2026-10-04-install-flow-design.md`
(decision 5). This rehearsal covers install → init → finish → verify →
console screenshot → upgrade → uninstall; it does not replace the slice
acceptance programs.

## Preconditions

- A clean Ubuntu 24.04 amd64 VM with a hypervisor console (virt-manager,
  VMware console, …). "Physical console" below means that VM console —
  **not an SSH session**.
- The VM has network access for the install itself (apt, image pulls,
  release downloads).
- The release under test is **published** (not a draft): its `install.sh`,
  `SHA256SUMS`, and `SHA256SUMS.sig` are uploaded assets.
- The tarball-signer fingerprint in
  [`release-authority-custody.md`](release-authority-custody.md)
  ("Tarball signer (central-release/v1)") is filled in — that is the
  out-of-band value the installer's printed fingerprint is checked against.
- `curl` or `gh` on the VM for the download step.

## Checklist

Record wall-clock times as you go; the installer also logs every action to
`/var/log/central-install.log`.

### 1. Download the bootstrap assets

```bash
mkdir central-install && cd central-install
TAG=v0.x.y   # the release under test
gh release download "$TAG" -R enolalab/central -p install.sh -p SHA256SUMS
# or: curl -fSLO "https://github.com/enolalab/central/releases/download/$TAG/install.sh"
#     curl -fSLO "https://github.com/enolalab/central/releases/download/$TAG/SHA256SUMS"
```

### 2. Checksum-verify the script

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Expected: `install.sh: OK`. `--ignore-missing` is required — `SHA256SUMS`
also lists the release tarball, which was not downloaded. A `FAILED` line
for `install.sh` itself stops the rehearsal here.

Optional but recommended: verify `SHA256SUMS.sig` too
(`ssh-keygen -Y verify -f allowed_signers -I central-release -n central-release -s SHA256SUMS.sig <SHA256SUMS`)
when an `allowed_signers` file for `central-release` is at hand.

### 3. Check the embedded release key

```bash
bash install.sh --show-release-key
```

Expected: prints the `ssh-ed25519` pubkey and its `ssh-keygen -l`
fingerprint. Compare the fingerprint **digit by digit** against the
`central-release/v1` value in
[`release-authority-custody.md`](release-authority-custody.md). Any mismatch
— or "no release key embedded" — stops the rehearsal. Never `curl | bash`
without this step.

### 4. Timed install

```bash
time sudo bash install.sh
```

Expected: preflight passes, `fetch_release` downloads and verifies the
tarball (signature + sha256), host steps run.
Record the wall time — this is the "how long does a cold install take"
data point. Review `/var/log/central-install.log` afterwards.

### 5. `central local init` — at the physical console

```bash
central local init
```

Run this in the VM's hypervisor console as the operator user, **not over
SSH**: the production admission ceremony requires a physical-console PAM
prompt (password + confirmation phrase; turn off any input method). A run
over SSH must refuse.

### 6. Finish the install

```bash
sudo /usr/lib/central/install/install.sh
```

The installed, root-owned copy completes the post-init steps and reports
what is left. (Every later run — `--verify`, `--uninstall`, upgrades — uses
this installed copy or a stamped download, never the bootstrap file.)

### 7. Verify

```bash
sudo /usr/lib/central/install/install.sh --verify
```

Expected: every check `OK`, exit 0.

### 8. Web console screenshot

**Pending** — no capture exists yet; the first rehearsal produces it.

After `--verify` passes, start `central serve` on the VM, bootstrap a
browser session at `https://127.0.0.1:8080`, submit one task so the
console has content, and capture the task-console route
(`/app/overview` or `/app/tasks`). Save the shot as
`docs/images/web-console.png` in this repository, optimize it to
**under 1 MiB** (`pngquant docs/images/web-console.png` or
`convert docs/images/web-console.png -resize 1280x` —
`ci/check-no-binaries.sh` rejects larger committed binaries), commit it,
and reference it from `README.md` and `docs/newcomer-guide.md`.

### 9. Upgrade rehearsal (next version)

When a newer release exists, download its stamped `install.sh` the same way
(steps 1–3) and run it:

```bash
time sudo bash install.sh   # the NEWER stamped script
```

Expected: `UPGRADE_MODE` — it fetches and verifies the new tarball, prints
each file it replaces (binaries, installed script copy, units), exit 0.
Then `--verify` again. The same path applies to a deliberate downgrade
(older stamped script): version difference in either direction triggers
the replace path, with the same signature verification.

A rerun of the *same* version's script must instead report the files kept
(idempotent, nothing replaced).

### 10. Uninstall — data kept

```bash
sudo /usr/lib/central/install/install.sh --uninstall
```

Expected: removes what the manifest lists (units, binaries, configuration);
`/var/lib/central-state` and `/var/lib/central-protected` are **kept**.
`--purge-data` additionally removes those data roots after a typed
instance-id confirmation — it is an explicit opt-in, not part of the
default uninstall and not part of this rehearsal unless specifically run.

## Record template

Copy into the rehearsal notes (a maintainer-private file or a
`docs/internal/tasks/` record, as decided per release):

```markdown
# Install acceptance — v0.x.y

- Date:
- VM: (hypervisor, vCPU/RAM/disk, Ubuntu 24.04 amd64 image date)
- Release: v0.x.y  (commit: )
- SHA256SUMS check: install.sh OK / FAILED
- Release-key fingerprint match: yes / no (compared against custody doc)
- Install wall time (`sudo bash install.sh`):
- `central local init` at physical console: pass / fail
- Finish-install run: pass / fail
- `--verify`: pass / fail
- Web console screenshot committed at docs/images/web-console.png: yes / no
- Upgrade to v0.x.z: wall time, files replaced, `--verify` result
- Same-version rerun idempotent: yes / no
- `--uninstall`: pass / fail; data roots kept: yes / no
- Deviations from this runbook:
- Verdict: pass / fail
```
