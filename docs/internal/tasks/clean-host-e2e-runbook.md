# Clean-host end-to-end runbook (open-source gate)

The last hard blocker before the visibility flip: one complete lifecycle
on a real host, from a fresh clone, recorded as evidence. Prerequisites
per `docs/operations/local-prerequisites.md` (Ubuntu Desktop 24.04.x /
amd64, Docker + BuildKit, physical console or `ceremony_mode: grant`).

Record each step's output under this file's "Run log" section and commit
it — that is the evidence.

## 0. Build

```bash
git clone https://github.com/enolalab/central-workspace.git && cd central-workspace
cargo build --workspace
```

NOTE: `packaging/install/install.sh` does not exist in this repository yet —
it ships with the deferred Phase-3 release workflow. Provision the host
manually like the `central-ref` bring-up (see step 0b).

### 0b. Manual host provisioning (replaces the installer)

```bash
# Identities (fixed UIDs per prerequisite manifest)
sudo useradd --system -u 501 --no-create-home --shell /usr/sbin/nologin central-runtime
sudo useradd --system -u 986 --no-create-home --shell /usr/sbin/nologin central_migrate
sudo useradd --system --no-create-home --shell /usr/sbin/nologin central-agent
sudo useradd --system --no-create-home --shell /usr/sbin/nologin central-browser

# Root-owned stores
sudo mkdir -p /var/lib/central-state/v1/instances /var/lib/central-protected/v1/instances \
  /var/lib/central-browser/v1 /var/lib/central-infra/security/v1 \
  /var/lib/central-rescue/v1/instances /var/lib/central-runtime/v1 /run/central-infra
sudo chmod 0700 /var/lib/central-{state,protected,browser,infra,rescue,runtime}

# Binaries → /usr/lib/central (root-owned)
sudo mkdir -p /usr/lib/central
sudo install -m 0755 -o root -g root target/debug/central target/debug/central-migrate \
  target/debug/central-backup target/debug/central-restore \
  target/debug/central-advisory-sign target/debug/central-harness-launcherd \
  target/debug/central-migration-launcherd target/debug/central-backup-launcherd \
  /usr/lib/central/
sudo ln -sf /usr/lib/central/central /usr/local/bin/central

# PAM service the helper authenticates through (pam_unix in all groups)
printf 'auth required pam_unix.so\naccount required pam_unix.so\npassword required pam_unix.so\nsession required pam_unix.so\n' \
  | sudo tee /etc/pam.d/central-helper

# Helper socket activation — LISTEN_FDS admission, /run/central-operator/helper.sock
printf '[Socket]\nListenStream=/run/central-operator/helper.sock\nDirectoryMode=0755\nSocketMode=0660\nSocketUser=root\nSocketGroup=root\n\n[Install]\nWantedBy=sockets.target\n' \
  | sudo tee /etc/systemd/system/central-helper.socket
printf '[Unit]\nDescription=Central helper\nRequires=central-helper.socket\n\n[Service]\nType=simple\nExecStart=/usr/lib/central/central --helper\nEnvironmentFile=/etc/central/helper.env\nUser=root\nRestart=on-failure\n' \
  | sudo tee /etc/systemd/system/central-helper.service

# Dev-admission helper env (grant mode admission path — matches central-ref)
sudo mkdir -p /etc/central
printf 'CENTRAL_HELPER_SOCKET=/run/central-operator/helper.sock\nCENTRAL_INSTANCE_ADMISSION=dev\n' \
  | sudo tee /etc/central/helper.env
sudo chmod 0600 /etc/central/helper.env

sudo systemctl daemon-reload
sudo systemctl enable --now central-helper.socket
journalctl -u central-helper --no-pager | tail   # helper starts on first connect
```

If any unit name or env key differs from the code's expectations, the first
`local init`/`local status` reports it — iterate from there, exactly as the
central-ref bring-up did.

## 1. Self-build infra image + devkey (per user-install-guide §2)

```bash
git clone https://github.com/enolalab/central-local-infra.git ~/central-local-infra
docker build -t ghcr.io/enolalab/central-local-infra ~/central-local-infra
# repoint dependency-lock.json digests → local image (host-local, do NOT commit)
cargo build --workspace   # refresh embedded lock
central-advisory-sign devkey --out ~/.local/state/central/dev-trust/dependency-attestation-key.json
```

## 2. Lifecycle

```bash
central local init                 # at the physical console or grant mode
sudo central grant issue --kind prepare --ttl 1h
central local prepare              # → PROVISIONED
central local up
central migrate up                 # needs its own lifecycle grant
central local up                   # settles past MIGRATION_REQUIRED
central local status               # expect all services healthy
central local doctor               # expect ok (this host is Ubuntu 24.04)
```

## 3. Serve + workflow

```bash
central serve &                    # or the systemd unit
# API/Web UI: submit a workflow run, read its artifact back
central run submit ...
central artifact read <artifact-id> ...
```

## 4. Recovery

```bash
central backup create ... && central restore verify/apply ...
central local down && central local up   # restart after restore
central local down
```

## 5. Evidence + gates

- [ ] Every command above recorded with its exit code/reason line.
- [ ] `bash scripts/check-repo-hygiene.sh` clean.
- [ ] `gitleaks git --config .gitleaks.toml` zero findings on the clone.
- [ ] `cargo test --workspace` green on the same commit.

## Run log

_(fill in during the run)_
