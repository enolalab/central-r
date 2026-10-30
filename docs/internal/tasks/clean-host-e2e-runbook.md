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
sudo packaging/install/install.sh --from-source "$PWD" --dev-admission --yes
```

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
