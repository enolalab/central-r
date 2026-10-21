# Local Development Environment Prerequisites

Design-only Gate 8 contract — commands are not currently available; Gate 9 slices return exit 5/UNSUPPORTED_IN_THIS_SLICE without mutation until implemented.

Design-only future Gate 9 runbook — commands are not currently available.

## 1. Authority

This document defines the administrator prerequisite runbook for the Central local development environment. It is a Gate 8 design contract only; no command listed here is currently executable. The document establishes the normative administrator workflow that Gate 9 must implement and validate on two independent clean Ubuntu Desktop 24.04.4 hosts.

Installing or changing host prerequisites, APT sources/keys/preferences, the helper, or its `sudoers` policy is an explicit root administrative trust transition outside every `central local` command. The helper has no `apt`, `dpkg`, package-repository, key-installation, service-enable, or arbitrary download operation.

The supported operator account that controls `central serve` has no Docker socket or protected-value authority. The operator UID is never added to the Docker group and never receives Docker-socket ACL. The operator account owns XDG selection/diagnostic views only.

## 2. Signed Noble/Docker source and package authority

### 2.1 Operating system

| Resource | Exact identity | Verification |
| --- | --- | --- |
| Operating system | Ubuntu Desktop 24.04.4 LTS, Linux/amd64 | `/etc/os-release`; `VERSION_ID="24.04"`; `VERSION="24.04.4 LTS (Noble Numbat)"`; `ID=ubuntu` |
| Kernel | Canonical signed Noble kernel within locked range | `uname -r`; Gate 9 resolves exact range in prerequisite manifest |
| Architecture | `x86_64` | `uname -m` |

Install Ubuntu Desktop 24.04.4 from an [official signed release image](https://releases.ubuntu.com/24.04.4/). Verify the ISO against the published SHA-256 checksum and GPG signature before installation. Third-party images, minimal/server variants, daily builds, and pre-configured cloud images without the mandatory desktop/Wayland/logind/PAM/AppArmor stack are not supported for the Phase 1 reference hosting profile.

### 2.2 Docker Engine and CLI

| Dependency | Version | Source | Verification |
| --- | --- | --- | --- |
| Docker Engine | 29.6.1 | Official Docker APT repository for Ubuntu Noble (`https://download.docker.com/linux/ubuntu`) | Signed Docker GPG key; exact version pin; package-file SHA-256; `docker version --format '{{.Server.Version}}'` |
| Docker CLI | 29.6.1 | Official Docker APT repository for Ubuntu Noble | Signed Docker GPG key; exact version pin; package-file SHA-256; `docker version --format '{{.Client.Version}}'` |
| containerd / runc | Exact pinned version | Official Docker APT repository | Signed Docker GPG key; package-file SHA-256 |
| Docker Compose plugin | 5.3.1 | Official Docker APT repository (`docker-compose-plugin`) | Signed Docker GPG key; exact version pin; `docker compose version` |

**Installation authority:**

1. Add only the official Docker APT repository signing key to `/etc/apt/keyrings/docker.asc` (root-owned, `0644`). Never add third-party or convenience-script keys.
2. Create `/etc/apt/sources.list.d/docker.sources` with `Signed-By` pointing to the keyring file, exact suite `noble`, and component `stable`. Never use `latest`, version ranges, or unsigned repositories.
3. Create `/etc/apt/preferences.d/docker` pinning `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin` to exact versions. Never use wildcards or floating pins.
4. Install the exact pinned packages only: `apt-get install docker-ce=5:29.6.1-1~ubuntu.24.04~noble docker-ce-cli=5:29.6.1-1~ubuntu.24.04~noble containerd.io=<exact-version> docker-buildx-plugin=<exact-version> docker-compose-plugin=5.3.1-1~ubuntu.24.04~noble`.

Gate 9 publishes a canonical `deploy/local/prerequisites.lock.json` with schema `central.local-prerequisites/v1` containing the exact package identities, repository origin/label/suite/component, signing-key fingerprint, package-file SHA-256, installed-file inventory digest, required absolute executable paths, executable SHA-256 values, and exact version output for every required host package. The administrator follows the signed manifest, not convenience scripts or version ranges.

**Prohibited:**
- Docker's `get.docker.com` convenience script
- `docker.io` Ubuntu package
- Snap-installed Docker
- Adding the operator to the `docker` group
- Docker-socket ACL for the operator UID
- `DOCKER_HOST`, `DOCKER_CONTEXT`, or remote daemon configuration
- Docker Buildx ambient builders, plugins, or credential helpers
- Docker Compose standalone binary (must use the plugin)
- Any Docker version outside the exact pinned range

### 2.3 PostgreSQL client tools

| Dependency | Version | Source | Verification |
| --- | --- | --- | --- |
| `pg_dump` | 16.14 | Official PostgreSQL APT repository for Ubuntu Noble (`https://apt.postgresql.org/pub/repos/apt`) | Signed PostgreSQL GPG key; exact version pin; package-file SHA-256; `/usr/lib/postgresql/16/bin/pg_dump --version` |
| `pg_restore` | 16.14 | Official PostgreSQL APT repository for Ubuntu Noble | Signed PostgreSQL GPG key; exact version pin; package-file SHA-256; `/usr/lib/postgresql/16/bin/pg_restore --version` |

The installed `pg_dump` must report `zstd` compression support. The executable paths must be root-owned and not writable by the operator UID.

**Installation authority:**

1. Add only the official PostgreSQL APT repository signing key to `/etc/apt/keyrings/postgresql.asc` (root-owned, `0644`).
2. Create `/etc/apt/sources.list.d/postgresql.sources` with `Signed-By`, exact suite, and component.
3. Pin `postgresql-client-16` to `16.14` in `/etc/apt/preferences.d/postgresql`.
4. Install: `apt-get install postgresql-client-16=16.14-1.pgdg24.04+1`.

Never install the PostgreSQL server package on the host. The server runs exclusively in a pinned Compose container.

**Prohibited:**
- `pg_dump` / `pg_restore` from a different major version
- `pg_dump` / `pg_restore` from a non-APT source without upstream signature verification
- Using the versions bundled in the Docker image instead of host tools
- Adding the operator to the `postgres` group
- Any `PG*` environment variable, `.pgpass`, or `PGSERVICE` file

### 2.4 Chromium-family browser and NSS trust tooling

| Dependency | Version | Source | Verification |
| --- | --- | --- | --- |
| Chromium-family browser | Exact package name and version resolved by Gate 9 in prerequisite manifest | Official Ubuntu Noble APT repository (`noble`/`universe`) | Signed Ubuntu APT key; package-file SHA-256; binary SHA-256 |
| NSS trust utilities (`certutil`, `modutil`) | Exact pinned version | Official Ubuntu Noble APT repository (`noble`/`main`) | Signed Ubuntu APT key; package-file SHA-256; binary SHA-256 |
| CA certificates | Exact pinned version | Official Ubuntu Noble APT repository (`noble`/`main`) | Signed Ubuntu APT key; package-file SHA-256 |

Gate 9 resolves the exact Chromium-family browser package identity for Ubuntu 24.04/x86_64. The browser must support:
- Launch via `WAYLAND_SOCKET` descriptor (not X11 or `--display`)
- Root-managed policy disabling extensions, developer tools, password storage, sync, service workers, background mode, and external URL handlers
- Numeric-loopback-only network policy
- Root-managed NSS trust store (not user-profile trust anchors)
- Systemd scope with `MemoryMax`, PID limit, and CPU quota

**Prohibited:**
- Snap-installed browser
- Flatpak-installed browser
- Non-Chromium-family browser
- User-managed profile without root policy
- X11 or XWayland fallback
- Browser with extensions, developer tools, or service workers enabled

### 2.5 Additional host packages

| Dependency | Source | Verification |
| --- | --- | --- |
| `apparmor` + `apparmor-utils` | Official Ubuntu Noble APT (`noble`/`main`) | Signed Ubuntu APT key; package-file SHA-256; `aa-status` |
| `quota` tooling | Official Ubuntu Noble APT (`noble`/`main`) | Signed Ubuntu APT key; package-file SHA-256; `quota --version` |
| PAM + `libpam-modules` | Official Ubuntu Noble APT (`noble`/`main`) | Signed Ubuntu APT key; package-file SHA-256 |
| `logind` / Wayland compositor | Official Ubuntu Noble APT (`noble`/`main`) | Signed Ubuntu APT key; package-file SHA-256 |
| Go 1.26.6 | Official Go download archive (`https://go.dev/dl/`) | Archive SHA-256 + upstream checksum; `go version` |

Go 1.26.6 is installed from the official signed archive (not APT) to `/usr/local/go` or a root-owned alternate path, with `/usr/local/go/bin` in the operator's `PATH`.

**Prohibited:**
- Installing any package from an unsigned or unlisted repository
- Using `apt version range` or `latest` pin
- Mutable convenience scripts for any dependency
- Operator-owned Go installation
- Go from `snap` or a third-party PPA

## 3. Manifest verification

Gate 9 publishes a canonical `deploy/local/prerequisites.lock.json` with schema `central.local-prerequisites/v1`. The administrator must verify:

| Evidence | Verification method | Safe failure |
| --- | --- | --- |
| Manifest signature | Ed25519 signature over RFC 8785 canonical JSON, verified with release public key | Reject; do not proceed |
| Package origins | Every package must trace to the exact signed repository/label/suite/component listed | `HOST_PREREQUISITE_MISMATCH` |
| Package versions | Every package epoch/version/revision must match exactly | `HOST_PREREQUISITE_MISMATCH` |
| Package-file SHA-256 | Every `.deb` must match its declared SHA-256 | `HOST_PREREQUISITE_MISMATCH` |
| Installed executable SHA-256 | Every binary at its declared absolute path must match | `HOST_PREREQUISITE_MISMATCH` |
| Exact version output | Every tool's `--version` output must match declared string | `HOST_PREREQUISITE_MISMATCH` |
| Repository signing keys | Only the declared fingerprints must be trusted in `/etc/apt/keyrings/` | `HOST_PREREQUISITE_MISMATCH` |
| Embedded prerequisite-manifest digest | The running `central local doctor --host-prerequisites` must embed the exact same manifest digest | `HOST_PREREQUISITE_MISMATCH` |

The manifest also records kernel range, architecture, ext4/project-quota identities, AppArmor parser path and feature set, and PAM module versions. Every field is exact; no placeholder, `latest`, unsigned repository, or mutable convenience script is valid.

## 4. Kernel range and ext4 `prjquota`

### 4.1 Kernel

The supported kernel is within the range recorded in the prerequisite manifest. The manifest locks the exact Canonical-signed kernel package identity (`linux-image-*`) for Ubuntu 24.04/x86_64.

Verify:
```text
# Future Gate 9 acceptance-contract commands — not currently available
uname -r
dpkg-query -W linux-image-$(uname -r)
```

The manifest records the exact kernel version range and required features (ext4, project quota, AppArmor LSM, cgroup v2, pidfd, `openat2`, `memfd_create` with sealing, `renameat2`).

### 4.2 ext4 `prjquota` mount option

The browser profile filesystem must be local ext4 with the `prjquota` mount option **enabled persistently at boot**. Runtime remount or quota enablement is forbidden — no Central command remounts a filesystem.

**Required administrator procedure:**

1. Identify the ext4 filesystem holding `/var/lib/central-browser/` (typically the root filesystem).
2. Edit `/etc/fstab` to add `prjquota` to the mount options for that filesystem. For example, change `defaults` to `defaults,prjquota`.
3. **Reboot the host** and verify the option is active:
   ```text
   # Future Gate 9 acceptance-contract commands — not currently available
   findmnt --mountpoint / --output OPTIONS | grep prjquota
   ```
   Or equivalently:
   ```text
   grep 'prjquota' /proc/mounts
   ```
4. Verify kernel quota support:
   ```text
   # Future Gate 9 acceptance-contract commands — not currently available
   quota --version
   ```

The documented reboot must be performed **before any Central state exists** (before `central local init`). An active `prjquota` mount option with verified kernel quota support is a hard prerequisite; configless `central local doctor --host-prerequisites` fails `HOST_PREREQUISITE_MISMATCH` if absent.

**Prohibited:**
- Network filesystem, FUSE, overlay, NFS, or case-insensitive filesystem for browser profile or any authoritative state
- Shared home directory without reliable advisory locks
- Root-squashed mount for `/var/lib/central-state/` or `/var/lib/central-protected/`
- Runtime `mount -o remount,prjquota` (must be in `/etc/fstab` and survive reboot)
- Enabling quotas on a live filesystem without the documented reboot
- A Central command requesting or performing a remount

## 5. Locked identities

The administrator creates these no-login system identities before `central local init`:

| Identity | Type | Purpose | Verification |
| --- | --- | --- | --- |
| `central-runtime` | System UID/GID, no-login (`/usr/sbin/nologin` or `/bin/false`) | `central serve` host process and all-in-one profile | `id central-runtime`; `/etc/passwd` shell is nologin |
| `central-agent` | System UID/GID, no-login | Sandboxed untrusted execution | `id central-agent` |
| `central-browser` | System UID/GID, no-login | Managed browser profile and Wayland scope | `id central-browser` |

Creation commands (future Gate 9 acceptance-contract — not currently available):

```text
# Create locked identities (exact commands from prerequisite manifest)
useradd --system --no-create-home --shell /usr/sbin/nologin central-runtime
useradd --system --no-create-home --shell /usr/sbin/nologin central-agent
useradd --system --no-create-home --shell /usr/sbin/nologin central-browser
```

The exact numeric UID/GID values are fixed in the dependency lock and prerequisite manifest. The administrator installs them; `central local init` validates but never creates or modifies system identities.

**Prohibition:** No identity may have a valid login shell, password, SSH key, home directory with write permission, or supplementary group membership.

## 6. Store/unit/PAM/AppArmor/browser-policy installation ownership

### 6.1 Root-owned stores

The administrator creates these root-owned directories before `central local init`:

| Directory | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/var/lib/central-state/v1/` | root | `0700` | Authoritative instance configuration, operations, receipts, audit |
| `/var/lib/central-protected/v1/` | root | `0700` | Protected secret bindings, TLS keys, bootstrap, broker journal |
| `/var/lib/central-browser/v1/` | root | `0700` | Parent of per-instance managed browser profiles |
| `/var/lib/central-infra/` | root | `0700` | Helper state, init audit, advisory, lock receipts |
| `/var/lib/central-rescue/v1/` | root | `0700` | Temporary rescue-backup scratch roots |
| `/var/lib/central-runtime/v1/` | root | `0700` | Runtime staging builds (development instances only) |
| `/run/central-infra/` | root (tmpfs) | `0700` | Ephemeral Compose secrets, project directories |

Creation (future Gate 9 acceptance-contract — not currently available):

```text
mkdir -p /var/lib/central-state/v1/instances
mkdir -p /var/lib/central-protected/v1/instances
mkdir -p /var/lib/central-browser/v1
mkdir -p /var/lib/central-infra/security/v1
mkdir -p /var/lib/central-rescue/v1/instances
mkdir -p /var/lib/central-runtime/v1
chown root:root /var/lib/central-{state,protected,browser,infra,rescue,runtime}
chmod 0700 /var/lib/central-{state,protected,browser,infra,rescue,runtime}
```

The operator UID, `central-runtime`, `central-agent`, and `central-browser` cannot traverse or list the root-owned `/var/lib/central-protected/v1/` parent. Descendants beneath `central-state` instance directories belong to `central-runtime` after `local init` creates them, but the root parent remains operator-non-searchable.

### 6.2 Installed authority files

| File | Owner | Mode | Purpose |
| --- | --- | --- | --- |
| `/usr/share/central/authority/v1/view-signing.pub` | root | `0444` | Ed25519 public key for XDG view signature verification |
| `/etc/apparmor.d/central-local-infra-wipe-v1` | root | `0644` | AppArmor profile for wipe container |

### 6.3 Helper, broker, sandbox-launcher, and runtime supervisor installation

These artifacts are installed by the Gate 9 release artifact, not manually:

| Artifact | Type | Installed by | Gate 9 enforcer |
| --- | --- | --- | --- |
| Helper | Root-owned immutable binary at fixed absolute path; `sudoers` policy with `env_reset`, `timestamp_timeout=0`, `secure_path`, no shell/arguments | Gate 9 release installer | `sudoers` policy verification |
| Protected broker | Root-owned systemd socket unit (`central-protected-broker.socket`) + service unit | Gate 9 release installer | systemd unit verification |
| Runtime supervisor | Root-owned systemd service unit (`central-runtime@.service`) | Gate 9 release installer | systemd unit verification |
| Sandbox launcher | Root-owned systemd socket unit (`central-sandbox-launcher.socket`) + service unit | Gate 9 release installer | systemd unit verification |
| PAM policy | Root-owned `/etc/pam.d/central-helper` (the PAM service the helper authenticates with) | Gate 9 release installer | PAM configuration verification |
| AppArmor profile | Root-owned `/etc/apparmor.d/central-local-infra-wipe-v1` | Gate 9 release installer; `apparmor_parser` load | `aa-status`; kernel-loaded identity verification |
| Browser policy | Root-owned Chromium policy JSON (path resolved by Gate 9) | Gate 9 release installer | Browser policy verification |

The administrator runs the Gate 9 installer as root. The installer validates the signed release artifact, copies immutable binaries, installs systemd units, loads AppArmor profiles, and records root-owned trust receipts. The operator UID never installs, replaces, or selects these artifacts.

**Prohibited:**
- Manual helper/broker/sandbox-launcher installation from a repository working tree
- Editing `sudoers` outside the installed release artifact
- Enabling passwordless `sudo` rules for any central command
- Enabling `sudo` timestamp caching for central commands
- Operator-owned copies of helper/broker binaries
- `systemctl edit` or drop-in overrides for Central units
- Loading AppArmor profiles in complain mode

## 7. Helper/broker/sandbox-launcher immutable ancestry

Every installed Central infrastructure artifact has a fixed ancestry chain:

| Ancestry property | Requirement | Verification |
| --- | --- | --- |
| Executable source | Exact release artifact with embedded Ed25519 signature | Release signature verification |
| Parent directories | Root-owned, non-writable by operator | `stat` parent chain to `/` |
| Executable file | Immutable (`chattr +i`), root-owned, mode `0755` | `lsattr`, `stat` |
| `sudoers` policy | Root-owned, mode `0440`, `visudo -c` valid | `visudo -cf` |
| Authority digest | Embedded in helper; matches installed release | `central local doctor` |
| systemd unit files | Root-owned, mode `0644`, no drop-in overrides | `systemctl cat` |
| AppArmor profile source | Digest matches embedded in helper + signed release | `sha256sum` vs embedded |

The helper, broker, sandbox-launcher, and runtime supervisor have no mutable configuration, no environment-variable overrides, no plugin directories, and no caller-supplied paths or arguments outside their closed request protocol.

## 8. Configless prerequisite doctor and privileged doctor

### 8.1 Configless prerequisite doctor

Before helper installation, the operator runs:

```text
# Future Gate 9 acceptance-contract command — not currently available
central local doctor --host-prerequisites
```

This is instance-independent and read-only. It verifies only independently observable evidence:

| Check | Method | Safe failure |
| --- | --- | --- |
| OS release | `/etc/os-release` | `HOST_PREREQUISITE_MISMATCH` |
| Kernel version / architecture | `uname -r`, `uname -m` | `HOST_PREREQUISITE_MISMATCH` |
| Package identities | `dpkg-query` for exact package/version/architecture | `HOST_PREREQUISITE_MISMATCH` |
| Public executable SHA-256 | Hash of each declared absolute path | `HOST_PREREQUISITE_MISMATCH` |
| Exact version output | `--version` stdout for each tool | `HOST_PREREQUISITE_MISMATCH` |
| Browser identity | Browser binary hash + `--version` | `HOST_PREREQUISITE_MISMATCH` |
| ext4 filesystem type + `prjquota` | `findmnt` / `/proc/mounts` | `HOST_PREREQUISITE_MISMATCH` |
| Kernel project-quota support | `quota` tool + kernel config or feature test | `HOST_PREREQUISITE_MISMATCH` |
| Embedded prerequisite-manifest digest | Comparison with installed manifest | `HOST_PREREQUISITE_MISMATCH` |

It never assumes an instance or invokes privileged inspection. Human output names the exact mismatched manifest field and prints only fixed package/source/runbook commands generated from the embedded manifest. JSON emits `HOST_PREREQUISITE_MISMATCH`.

### 8.2 Privileged doctor

After administrator installation of helper, broker, identities, and `central local init`:

```text
# Future Gate 9 acceptance-contract command — not currently available
central --config <absolute-config-path> local doctor
```

This authenticates through the helper and additionally verifies:

| Check | Method | Safe failure |
| --- | --- | --- |
| Root ownership/non-writability of every authoritative root | `stat` parent chains | `DRIFTED` or `AUTHORITY_DENIED` |
| Locked identity existence + no-login | `/etc/passwd`, `/etc/shadow` | `HOST_PREREQUISITE_MISMATCH` |
| Helper/broker/runtime/sandbox-launcher unit state | systemd | `HELPER_UNAVAILABLE` exit 3 |
| PAM policy | `/etc/pam.d/central-helper` | `AUTHORITY_DENIED` exit 7 |
| AppArmor state + loaded profile | `aa-status` | `HELPER_POLICY_DENIED` exit 7 |
| Browser/system trust integration | CA trust store, NSS store | `TLS_TRUST_REQUIRED` exit 3 |
| Collision-free instance project-ID binding | Browser-project registry + kernel quota | `DRIFTED` exit 5 |
| Exact quota limits/usage/receipt | Kernel quota records + broker-HMAC receipt | `DRIFTED` exit 5 |
| Docker local-socket/API identity | `docker version`, `docker info` | `HELPER_UNAVAILABLE` exit 3 |
| Compose plugin identity | `docker compose version` | `HELPER_UNAVAILABLE` exit 3 |
| Installed authority digests | Helper/broker/sandbox-launcher manifest comparison | `DRIFTED` exit 5 |
| Host prerequisite manifest identity | Comparison with embedded | `HOST_PREREQUISITE_MISMATCH` exit 3 |

Human output names the exact mismatched field; JSON emits the appropriate reason code.

### 8.3 Write probe and throughput probe

```text
# Future Gate 9 acceptance-contract commands — not currently available
central --config <absolute-config-path> local doctor --write-probe
central --config <absolute-config-path> local doctor --backup-throughput-probe
```

The write probe uses a broker-delivered scoped credential to perform a bounded read/write semantic check; failed cleanup is durably `cleanup_required`. The throughput probe runs the 512-MiB `pg_dump` and 512-MiB object transfer measurements (5-minute parent) and requires dependencies healthy.

## 9. Two-clean-host evidence and active/wall-time measurement

### 9.1 Validation requirements

Gate 9 must prove the complete prerequisite runbook on two independent clean Ubuntu Desktop 24.04.4 hosts. Each host:

1. Starts from a clean ISO installation with only default packages.
2. Installs only the manifest-listed packages from exact signed sources with pinned versions.
3. Enables persistent ext4 `prjquota` and performs the documented reboot.
4. Creates locked identities, stores, and installed authority files as specified.
5. Runs configless `central local doctor --host-prerequisites` successfully.
6. Runs privileged `central local doctor` successfully.

Both hosts must produce identical prerequisite evidence (same package identities, binary SHA-256 values, version output, manifest digest). A difference in any field fails Gate 9.

### 9.2 Timing budgets

| Phase | Measurement | Target |
| --- | --- | --- |
| Administrator active time | Cumulative time the administrator is actively entering commands | ≤15 min |
| Wall time | Total elapsed including the documented reboot | Reported separately |
| Reboot | One documented reboot after `prjquota` fstab change | Outside active time budget |

The administrator runbook is measured from a clean installed OS to successful `central local init` exit 0. Active time is cumulative command-entry and confirmation time across the complete runbook. Wall time starts at first APT source configuration and ends at `central local init` success.

## 10. Prohibited operator actions

The following operator actions are prohibited at all times during the lifecycle of a Central instance:

### 10.1 Docker authority prohibitions

| Prohibition | Reason |
| --- | --- |
| Adding operator UID to `docker` group | Docker control is root-equivalent |
| Adding operator UID to Docker-socket ACL | Circumvents helper trust boundary |
| Setting `DOCKER_HOST` or `DOCKER_CONTEXT` | Redirects Docker authority |
| Running `docker` or `docker compose` directly for Central resources | Bypasses helper validation |
| Running `docker exec` in Central containers | Speculative repair with undefined durable state |
| Using Docker convenience scripts (`get.docker.com`) | Unsigned, mutable acquisition |
| Installing Docker from Ubuntu `docker.io` package | Wrong version, unsigned channel |
| Installing Docker via Snap | Wrong version, sandboxed daemon |
| Enabling Buildx plugins, credential helpers, remote builders | Ambient Docker authority |
| Using Docker Compose standalone binary instead of plugin | Wrong command shape |

### 10.2 Manual repair prohibitions

| Prohibition | Reason |
| --- | --- |
| Manually starting/stopping Central dependency containers | Bypasses `local up` validation |
| Editing PostgreSQL/MinIO configuration inside containers | Undetectable drift |
| Editing `pg_hba.conf` or PostgreSQL settings | Drift from locked settings |
| Manually creating/dropping databases, roles, schemas | Drift from provisioning |
| Manually creating/deleting MinIO buckets, policies, identities | Drift from provisioning |
| Editing or deleting Central instance state files | Corrupts authority journals |
| Editing or deleting backup/repository files | Corrupts sealed evidence |
| Editing or deleting protected state files | Corrupts secret bindings |
| Copying, moving, or renaming receiver files between instances | Cross-instance identity violation |
| Manually resetting browser profile or trust store | Incomplete session revocation |
| Editing `central.json` configuration by hand | Corrupts config binding/signature |

### 10.3 Package and version prohibitions

| Prohibition | Reason |
| --- | --- |
| Using version ranges or `latest` in APT pins | Unvalidated package changes enter supported profile |
| Installing packages from unsigned/unlisted repositories | Supply-chain compromise |
| Upgrading Docker/PostgreSQL client/Go/browser outside a reviewed release manifest | Drift becomes downtime |
| Using `snap` for any Central dependency | Wrong version, sandboxed, mutable |
| Using `flatpak` for any Central dependency | Wrong version, sandboxed |
| Using a convenience script to install any dependency | Unsigned, mutable acquisition |
| Installing Central-managed packages (helper, broker, etc.) from a working tree | Unreviewed code as root authority |
| Unattended/automatic package upgrades for Central dependencies | May make machine unsupported; must fail closed |

### 10.4 General prohibitions

| Prohibition | Reason |
| --- | --- |
| Running Central commands as root | Operator account must be an unprivileged UID |
| Setting `DOCKER_*`, `COMPOSE_*`, `PG*`, proxy variables in Central command environment | May override locked config fields |
| Editing/replacing installed helper, broker, or `sudoers` policy manually | Breaks immutable ancestry |
| Running Central outside the locked `central-runtime` UID | Violates privilege boundary |
| Running Central on a non-ext4 filesystem for authoritative state | Required atomicity/project-quota |
| Running Central on a non-loopback listener | Invalid `central.config/v1` |
| Using a non-Chromium-family browser | Unsupported browser policy/trust integration |
| Bypassing browser certificate warnings | Unsupported; TLS origin authentication is mandatory |
| Running Central on Ubuntu Server, Linux/arm64, or macOS with Phase 1 claims | Candidates only until Gate 9 supplies equivalent evidence |

## 11. Future command shapes (acceptance contract)

The following are the exact command shapes that Gate 9 must implement. They are normative acceptance-contract references, not executable instructions in the current repository state. All commands produce exit `5` `UNSUPPORTED_IN_THIS_SLICE` until implemented.

### 11.1 Prerequisite verification

```text
# Configless: verify host prerequisites independently (no instance, no privileged access)
central local doctor --host-prerequisites

# With config: full privileged doctor after helper installation and init
central --config <absolute-config-path> local doctor

# Write probe (requires dependencies healthy)
central --config <absolute-config-path> local doctor --write-probe

# Throughput probe (requires dependencies healthy; 5-minute parent)
central --config <absolute-config-path> local doctor --backup-throughput-probe
```

### 11.2 Instance initialization

```text
# Create new instance (configless; generates config path on trusted TTY)
central local init

# Status of incomplete init journals (configless; caller-UID-bound only)
central local init --status

# Resume exact incomplete accepted init journal
central local init --resume=<init-operation-id>

# Abandon unaccepted empty reservation (configless; requires exact ID and no committed state)
central local init --abandon=<init-operation-id>
```

### 11.3 Trust, security, and preparation

```text
# Install instance CA in system and browser trust stores
central --config <absolute-config-path> local trust install

# Remove instance CA from trust stores
central --config <absolute-config-path> local trust remove

# Unprivileged read-only advisory authority status
central --config <absolute-config-path> local security status

# Update signed advisory bundle (online: fetch from embedded endpoint; offline: open absolute file descriptor)
central --config <absolute-config-path> local security update

# Prepare dependencies (fetch, build, verify — requires current advisory)
central --config <absolute-config-path> local prepare
```

### 11.4 Dependency lifecycle

```text
# Start dependencies through helper (validate everything before Docker mutation)
central --config <absolute-config-path> local up

# Stop dependencies (preserve data)
central --config <absolute-config-path> local down

# Unprivileged snapshot status (signed XDG views only; no Docker/helper contact)
central --config <absolute-config-path> local status

# Wipe payload data (one-off destructive protocol with AppArmor; requires fresh PAM + TTY confirmation)
central --config <absolute-config-path> local wipe

# Resume interrupted wipe
central --config <absolute-config-path> local wipe --operation=<operation-id>
```

### 11.5 Browser launch and maintenance

```text
# Launch managed browser
central --config <absolute-config-path> local browser open

# Clear browser profile (journaled session/bootstrap revocation)
central --config <absolute-config-path> local browser clear

# Resume interrupted browser clear
central --config <absolute-config-path> local browser clear --operation=<browser-clear-operation-id>
```

### 11.6 Runtime staging (development only)

```text
# Stage a developer-built binary for a development instance
central --config <absolute-config-path> local runtime stage \
  --binary=<absolute-path-to-built-binary> \
  --manifest=<absolute-path-to-build-manifest>
```

### 11.7 Diagnostic commands

```text
# Explain a reason code from the embedded remediation catalog
central --config <absolute-config-path> local explain --reason=<reason-code>
```

### 11.8 Upgrade and maintenance

```text
# Plan dependency upgrade (lifecycle-exclusive; creates protected ticket)
central --config <absolute-config-path> local dependency-upgrade plan

# Apply exact unexpired upgrade ticket
central --config <absolute-config-path> local dependency-upgrade apply --ticket=<ticket-id>

# Resume interrupted upgrade
central --config <absolute-config-path> local dependency-upgrade resume --operation=<operation-id>

# Plan protected-state/maintenance cleanup (dry run only)
central --config <absolute-config-path> local maintenance plan

# Apply exact unchanged maintenance plan
central --config <absolute-config-path> local maintenance apply --plan=<plan-id>
```

### 11.9 TLS rotation

```text
# Rotate leaf certificate (preserve CA; requires serving stopped)
central --config <absolute-config-path> local tls rotate-leaf

# Rotate CA (staged install-before-activate; requires serving stopped)
central --config <absolute-config-path> local tls rotate-ca
```

## 12. Post-installation validation checklist

Before `central local init` can succeed, every item on this checklist must pass:

- [ ] Ubuntu Desktop 24.04.4 LTS, Linux/amd64, clean ISO installation
- [ ] Kernel within manifest-locked range; ext4, AppArmor, cgroup v2, pidfd, `openat2`, `memfd_create`, `renameat2` features present
- [ ] ext4 `prjquota` in `/etc/fstab`; one documented reboot performed; `prjquota` confirmed in `/proc/mounts`
- [ ] `quota` tooling installed and `quota --version` succeeds
- [ ] Docker Engine 29.6.1 installed from signed `download.docker.com` APT repository; `docker version` reports exact version
- [ ] Docker Compose plugin 5.3.1 installed; `docker compose version` reports exact version
- [ ] Operator UID **not** in `docker` group; `groups` output confirms; Docker-socket ACL absent
- [ ] PostgreSQL client 16.14 installed from signed `apt.postgresql.org` APT repository; `pg_dump --version` and `pg_restore --version` report 16.14 with zstd
- [ ] `pg_dump` and `pg_restore` absolute paths are root-owned and not operator-writable
- [ ] Chromium-family browser installed from official Ubuntu APT; binary hash matches manifest
- [ ] NSS trust utilities (`certutil`, `modutil`) installed; `certutil --version` succeeds
- [ ] `apparmor` and `apparmor-utils` installed; `aa-status` reports loaded profiles
- [ ] `central-runtime`, `central-agent`, `central-browser` system identities exist with no-login shells
- [ ] Root-owned stores created: `/var/lib/central-state/v1/`, `/var/lib/central-protected/v1/`, `/var/lib/central-browser/v1/`, `/var/lib/central-infra/`, `/var/lib/central-rescue/v1/`, `/var/lib/central-runtime/v1/`
- [ ] Helper, broker, sandbox-launcher, runtime supervisor installed by Gate 9 release artifact (not manually)
- [ ] `sudoers` policy active with `env_reset`, `timestamp_timeout=0`, fixed executable, `secure_path`
- [ ] PAM policy (`/etc/pam.d/central-helper`) present and validated
- [ ] AppArmor wipe profile loaded and enforced (not complain mode)
- [ ] Browser policy installed enforcing extensions-off, devtools-off, password-storage-off, sync-off, service-workers-off, background-off, loopback-only
- [ ] Go 1.26.6 installed from official signed archive to root-owned path
- [ ] No Central dependency package uses version range, `latest`, unsigned repository, Snap, or Flatpak
- [ ] Unattended upgrades disabled or pinned to not update Central dependencies
- [ ] `central local doctor --host-prerequisites` succeeds (configless, read-only)
- [ ] Two clean hosts produce identical prerequisite-manifest evidence
- [ ] Wall time and active time recorded; runbook target ≤15 min active

## 13. B06 secure-serve-bootstrap operator runbook

This section is the implemented B06 operator runbook for the secure-serve-bootstrap acceptance boundary. It complements the design-only Gate 8/9 commands above with the executable reference-host launcher and exact remediation guidance. The governing contract is `docs/internal/superpowers/specs/2026-07-22-phase-1-b06-secure-serve-bootstrap-design.md`; evidence is recorded in `docs/internal/superpowers/reviews/2026-07-22-b06-secure-serve-bootstrap-acceptance.md`.

### 13.1 Acceptance launcher

The supported launcher is non-skipping and requires UID 0 plus Docker root access:

```text
testdata/b06-reference-host/run.sh
```

It pins every image with `pull_policy: never`, uses a 15-minute parent deadline including cleanup (2m PostgreSQL health, 10m suite, 3m bounded cleanup), and runs the suite with `-tags authority_test` across the kernel, runtime, transport, session, helper, broker, and PostgreSQL packages. The runner uses `docker compose up --abort-on-container-exit --exit-code-from test-runner`; the outer deadline wrapper and bounded cleanup trap prevent a blocked Docker cleanup from extending the deadline. It fails nonzero if any fixture resource leaks after completion. Non-root execution and Docker unavailability are hard nonzero results; portable CI does not skip.

The operator order is fixed: verify receipts and configuration, complete the
explicit migration or exact recovery action if preflight is not ready, start
`central serve`, wait for both listeners and `/health/ready` 200, invoke the
managed browser through the helper for its explicit TTY proof presentation,
complete bootstrap exchange, then logout or shut down and wait for settlement.
The proof is never copied from logs, health responses, or shell output.

### 13.2 Health response and reason interpretation

| `/health/ready` | `/health/live` | Reason | Exit class | Operator action |
| --- | --- | --- | ---: | --- |
| 200 ready | 200 | (empty) | 0 | Proceed to explicit browser open |
| 503 starting | 200 | `UNAVAILABLE` | — | Wait; bounded diagnostic follows |
| 503 not_ready | 200 | `POSTGRES_INCOMPATIBLE` | 5 | Follow remediation copy; run exact repair action |
| 503 not_ready | 200 | `PROVISION_REQUIRED` | 7 | Follow remediation copy; run exact `central migrate up` |
| 503 not_ready | 200 | `RESUME_REQUIRED` | 6 | Follow remediation copy; run exact `central migrate resume` |
| 503 not_ready | 200 | `REPAIR_REQUIRED` | 6 | Follow remediation copy; run exact repair action |
| 503 not_ready | 200 | `PORT_IN_USE` | 4 | Stop conflicting process; keep fixed listener |
| 503 not_ready | 200 | `LEASE_LOST` | 4 | Recheck lock/config; restart after clearing |
| 503 not_ready | 200 | `CONFIG_INVALID` | 2 | Recheck config binding/signature |
| 503 shutting_down | 200 | `SHUTTING_DOWN` | 0 | Intentional; restart via launcher |
| 503 failed | 200 | `EPOCH_MISMATCH`/`BACKGROUND_LOOP_FAILED` | 6 | Diagnose root cause; clear before restart |

Health bodies are redacted JSON (`status`, `reason`, `remediation`, `failure_class`) and never carry proof material, nonces, credentials, DSNs, or raw internal error text.

### 13.3 Safe remediation and recovery decision table

| Symptom | First check | Safe action | Prohibited action |
| --- | --- | --- | --- |
| Serve exits 7 `PROVISION_REQUIRED` | Schema version via `migrate status` | Run exact `central migrate up` | Auto-migrate from serve; manual SQL |
| Serve exits 6 `RESUME_REQUIRED` | Migration journal | Run exact `central migrate resume` | Manual table edit |
| Serve exits 6 `REPAIR_REQUIRED` | Checksum drift evidence | Follow repair advisory | Manual schema patch |
| Serve exits 4 `PORT_IN_USE` | `ss -tlnp` on 8080/9090 | Stop conflicting process | Change listener address |
| Serve exits 4 `LEASE_LOST` | Lock/config binding | Recheck and restart | Force-remove lock file |
| Serve exits 6 after readiness | Component/epoch/parent evidence | Diagnose; clear root cause; restart | Repeated blind restart |
| Browser open denied | Ready proof validity + Wayland seat | Re-run `serve`; verify proof | Bypass certificate warning |
| Operations port request is not a health route | Route and method policy | Use `/health/live` or `/health/ready` only | Expose bootstrap, admin, or session routes on port 9090 |
| Logout/session recovery | Revoke active session; render recovery form | Clear session/CSRF cookies, issue fresh pre-auth CSRF, and submit a newly presented bootstrap token | Reuse revoked cookies or resume with the previous token |

### 13.4 Restart recovery

1. A clean intentional stop (controller disconnect, SIGTERM relay, parent `central down`) exits 0 and leaves durable bindings intact.
2. A terminal runtime failure (lock loss, epoch mismatch, parent/component loss, shutdown timeout) exits 6. The operator must diagnose and clear the root cause before restarting.
3. Restart always re-runs the full startup reconciliation: read-only one-connection/no-retry preflight, bootstrap reconciliation, dual-listener bind, dedicated non-borrowable control lock, then proof publication.
4. A stale proof is never honored: expiry, revocation, and mismatch all deny browser open and bootstrap reveal until a fresh launch re-mints the proof.

### 13.5 No-auto-migrate rule

`central serve` never migrates application schema. The serve profile rejects any configuration that borrows a pool, enables retries, or constructs the migration credential. Schema migration is the explicit `central migrate up` ceremony owned by `central-migrate`. Violating this rule from the serve path is a startup failure, not a fallback.

## References

- [Gate 8 governing design](../internal/superpowers/specs/2026-07-16-phase-0-local-development-environment-design.md)
- [ADR 0009 — Local development environment topology](../adr/0009-adopt-local-development-environment-topology.md)
- [Local development environment topology](../architecture/local-development-environment.md)
- [Ubuntu 24.04.4 release images](https://releases.ubuntu.com/24.04.4/)
- [Docker Engine 29 release notes](https://docs.docker.com/engine/release-notes/29/)
- [Docker Compose 5.3.1 release](https://github.com/docker/compose/releases/tag/v5.3.1)
- [PostgreSQL 16.14 release notes](https://www.postgresql.org/docs/release/16.14/)
- [PostgreSQL APT repository](https://wiki.postgresql.org/wiki/Apt)
- [Docker APT repository](https://docs.docker.com/engine/install/ubuntu/)
- [Go downloads](https://go.dev/dl/)
