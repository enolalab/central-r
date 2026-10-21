# Known limitations, FAQ, and troubleshooting

## Known limitations

- **Ubuntu 24.04 LTS amd64 only.** The installer's preflight enforces
  this; arm64, macOS, and other distributions are not install targets.
  Source checkouts build anywhere Go ≥ 1.26 runs — only the installed
  runtime is Ubuntu-bound (see [compatibility.md](compatibility.md)).
- **Single operator.** Phase 1 runs one local instance for one trusted
  OS account (the operator). There is no multi-user or team mode.
- **No online mode.** Central is local-first; the Central Server and
  hybrid execution described in
  [architecture/online-mode.md](architecture/online-mode.md) are future
  work.
- **Partial command surface.** Commands whose owning slice is not yet
  accepted exit `5` with `UNSUPPORTED_IN_THIS_SLICE` and mutate nothing.
  The authoritative list of what works is
  [implementation/current-phase.md](implementation/current-phase.md).
- **Loopback-only web console.** `central serve` binds
  `https://127.0.0.1:8080` only; sessions come from a local bootstrap
  exchange. There is no remote access model — do not expose the port.
- **English-first docs.** The English files are canonical; the
  Vietnamese install guide
  ([user-install-guide.vi.md](operations/user-install-guide.vi.md)) is a
  translation that may lag.

## FAQ

**Why does `central local init` demand the physical console?**
The init ceremony proves a person is sitting at the machine: the helper
requires an active local seat and physical-console TTY ancestry, takes an
exclusive terminal lease, and asks for the account password plus a typed
confirmation phrase (threat T19 in the
[threat model](security/threat-model.md)). A process that merely
controls a terminal cannot reproduce that.

**Why not over SSH?**
An SSH session is indistinguishable from a forged PTY at the trust level
the ceremony needs, so it is refused by design. When nobody is at the
console, root pre-authorizes one operation instead:
`sudo central grant issue --kind init --ttl 10m`, then `central local
init` runs without the ceremony (ADR 0028 grant mode).

**Where does my state live?**
Split by design: PostgreSQL holds authoritative metadata (Tasks, Runs,
Events, Artifact metadata, sessions); S3-compatible object storage
(MinIO locally) holds artifact bodies. On the host, the installed state
trees are `/var/lib/central-state/v1/instances/<id>/` (per-instance data)
and `/var/lib/central-protected/v1/instances/<id>/` (protected state);
`--uninstall` keeps them, `--purge-data` removes them. Nothing
authoritative lives only in a container.

**How do I upgrade or downgrade?**
Same flow, different version: run the target version's stamped
`install.sh` (it fetches and verifies that version's tarball itself). A
same-version rerun is a no-op. A dev-installed copy upgrades only from
its own checkout:
`sudo <checkout>/packaging/install/install.sh --from-source <checkout>`.

**Is Central production-ready?**
Honestly: Phase 1, pre-1.0. The install path is real and the accepted
slices work end to end, but the command surface is still delivered
incrementally, some gates carry self-issued verdicts, and there is no
online mode. Treat it as early-access software; read
[current-phase.md](implementation/current-phase.md) before relying on a
specific verb.

**Can I run it in a VM or a container?**
A VM, yes — the installer needs Ubuntu 24.04 amd64, systemd as init, and
Docker; a VM's console window satisfies the physical-console ceremony.
A container, no: preflight refuses when systemd is not PID 1, and the
install creates host users, PAM services, and systemd units.

## Troubleshooting

Every install preflight refusal prints one cause line, one `fix:` line,
and `nothing was changed` — exit 3 is a missing prerequisite, exit 4 is
capacity, exit 2 is usage. `central` results carry a machine-readable
`reason` and the process exit status equals the envelope's `exit_code`.

| Symptom (exact string) | Cause | Fix |
| --- | --- | --- |
| `install.sh must run as root` | Ran without sudo | `sudo bash install.sh` (first install) or `sudo /usr/lib/central/install/install.sh` (installed copy) |
| `this host is ... ; Central installs on Ubuntu 24.04 amd64 only` | Unsupported OS or architecture | Install on Ubuntu 24.04 LTS amd64 |
| `this install.sh has no release key embedded` | An unstamped/dev script tried to fetch a release | Download `install.sh` from the release page, or use `--from-source <checkout>` |
| `bad release signature: SHA256SUMS.sig does not verify for ...` | Downloaded release failed signature verification | Re-download `install.sh` from the release page; verify `--show-release-key`'s fingerprint first |
| `checksum mismatch: ....tar.gz does not match SHA256SUMS` | Corrupt or substituted tarball | Re-download; if it persists the release is corrupt |
| `installed copy is a dev build; upgrade it with --from-source from its own checkout` | A release script ran over a dev install | Upgrade with the checkout's own script: `sudo <checkout>/packaging/install/install.sh --from-source <checkout>` |
| `operator ... is in the docker group, which is root-equivalent and breaks Central's uid separation` | Operator is a docker-group member | `sudo gpasswd -d "$USER" docker`, then log out and back in |
| `Docker does not use the containerd image store` | `daemon.json` lacks the feature flag | Add `"features": {"containerd-snapshotter": true}` to `/etc/docker/daemon.json`, then `sudo systemctl restart docker` |
| `Docker is installed but its daemon does not answer (docker info failed or timed out)` | Daemon stopped or hung | `sudo systemctl enable --now docker`; check `sudo docker info` |
| `... GiB free on the /var/lib filesystem; genesis needs 40 GiB` (exit 4) | Insufficient disk | Free space on the `/var/lib` filesystem (`df -h /var/lib`) |
| `UNSUPPORTED_IN_THIS_SLICE` (exit 5) | The verb's owning slice is not yet accepted | Expected, nothing mutated; check [current-phase.md](implementation/current-phase.md) for the accepted surface |
| `central local init` → `AUTHORITY_DENIED`, hint `run it as the operator at this machine's physical console ... on a host with no console, root can authorize one run over SSH first: sudo central grant issue --kind init --ttl 10m` | Init attempted over SSH | Run at the machine's console, or `sudo central grant issue --kind init --ttl 10m` first |
| `central local init: the typed phrase did not match the one shown, twice; nothing was created. ...` (exit 7) | An input method altered the typed phrase | Turn off the input method, run `central local init` again, type the phrase exactly |
| `central local init: the helper is not reachable; start it with: sudo systemctl start central-helper.socket` | Helper socket not running | `sudo systemctl start central-helper.socket` |

More installer rows — uid/gid collisions, differing-file refusals,
manifest problems, uninstall leftovers — are tabled in the Vietnamese
guide's fix section
([user-install-guide.vi.md](operations/user-install-guide.vi.md))
pending translation.
