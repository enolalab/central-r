# Campaign serve bring-up (issue #124, BP-4)

Starts `central serve` with harness + scheduler enabled on the real
launcher. Unblocks #110 Task 2 Step 2. No step here bypasses an authority
check: the broker is the production `broker.Service`, every fetch crosses
the real frame-0xb1 authorization, and every failure below fails closed.

## Prerequisites

- Root on the campaign host, and the `central-runtime` OS user (501:501).
- This repo's `central` binary built from the merged BP-4 commit.
- Migrated PostgreSQL 16 + the 0400 `central_runtime` descriptor serve
  already needs (unchanged).
- MinIO up with bucket `central-artifacts-v1` (campaign Compose; plain
  HTTP `127.0.0.1:9000` in this transcript — replace with yours).
- The digest-pinned `central-local-infra` image providing
  `minio-provision` (SB-G3 Task 14 shape).
- Harness host requirements per `harness-execution.md` §1 (launcher
  daemon, `fs.protected_hardlinks=1`, capture dir, operator harness
  login). Serve refuses harness execution without them — that is
  unchanged behavior, not this bring-up failing.

## 1. Start the campaign broker (as root)

```bash
mkdir -p /var/lib/campaign-broker/state /var/lib/campaign-broker/sock
chown 0:0 /var/lib/campaign-broker/state /var/lib/campaign-broker/sock
chmod 0700 /var/lib/campaign-broker/state
chmod 0755 /var/lib/campaign-broker/sock
central broker serve \
  --state-root /var/lib/campaign-broker/state \
  --socket /var/lib/campaign-broker/sock/broker.sock
# stderr: broker serve: listening on .../broker.sock (state .../state)
```

Rules the verb enforces (all fail closed, exit 6): root-only; state
root an existing root-owned 0700 directory; socket path fresh (a stale
socket is refused, never unlinked — remove it by hand); socket parent
root-owned and not world-writable. The socket is chmodded 0666 exactly
like production's `central-broker.socket`; authorization stays per-RPC.

Export for serve and the mint step (same shell or unit env):

```bash
export CENTRAL_BROKER_SOCKET=/var/lib/campaign-broker/sock/broker.sock
```

## 2. Mint a binding (as root; fresh per serve start)

Pick a stable-per-campaign instance id and a fresh nonzero fence token
per mint. Request JSON on stdin (Task-14 shape):

```bash
export BP4_INSTANCE=bp4-campaign BP4_FENCE=4242
cat > /tmp/bp4-mint.json <<EOF
{"schema_version":"central.local.infra.request/v1","mode":"minio-provision",
 "operation_id":"bp4-mint-1","instance_id":"$BP4_INSTANCE",
 "target":{"fd_number":3,"device":1,"inode":1,"mount_id":1,
           "filesystem":"ext4","root_id":"minio-provision"},
 "policy_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "image_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
 "deadline":"2030-01-01T00:00:00Z",
 "minio_provision":{"root_credential_path":"/run/secrets/minio-root-password",
  "broker_socket_path":"/run/broker/sock/broker.sock",
  "bucket":"central-artifacts-v1",
  "key_prefix":"v1/staging/ v1/ready/",
  "credential_purpose":"minio_runtime_v1","fence_token":$BP4_FENCE}}
EOF
docker run --rm -i --user 1000:1000 \
  -v /run/secrets/minio-root-password:/run/secrets/minio-root-password:ro \
  -v /var/lib/campaign-broker/sock/broker.sock:/run/broker/sock/broker.sock:ro \
  -e CENTRAL_LOCAL_INFRA_MINIO_ADMIN_ENDPOINT=<minio-host>:9000 \
  <digest-pinned-image> minio-provision < /tmp/bp4-mint.json
# expect: {"outcome":"completed",...}
```

Use a fresh `operation_id` and fence token per mint. The provisioner
mints, seals, and delivers; the broker binds and returns accept.

## 3. Transcribe the binding record (as root)

```bash
cat /var/lib/campaign-broker/state/minio-runtime-bindings/*.json
# exactly one record on a fresh broker; after several mints take the
# most recently created file (ls -t | head -1). Non-secret fields only.
```

Write the descriptor (replace values from the record):

```json
{"schema_version":"central.b10-binding-ref/v1",
 "instance_id":"bp4-campaign",
 "opaque_generation":"<generation_id from the record>",
 "receipt_id":"<fresh opaque id, e.g. bp4-mint-1-ref>",
 "fencing_token":<fence_generation from the record>,
 "bucket":"central-artifacts-v1",
 "endpoint":"127.0.0.1:9000",
 "use_tls":false,
 "region":"us-east-1"}
```

Install it 0400 owned by the serve user:

```bash
install -o 501 -g 501 -m 0400 /tmp/bp4-binding.json /var/lib/campaign-broker/binding-ref.json
```

`receipt_id` is operator-generated (the broker records it, never matches
it). `endpoint` is `host:port`, no scheme, no credentials, no path. No
credential material is ever displayed or copied in this step.

## 4. Start serve (as 501)

```bash
export CENTRAL_BROKER_SOCKET=/var/lib/campaign-broker/sock/broker.sock
export CENTRAL_MINIO_RUNTIME_BINDING_REF=/var/lib/campaign-broker/binding-ref.json
export CENTRAL_HARNESS_ENABLED=1
export CENTRAL_PHASE2_SCHEDULER=1
# ... plus the harness-execution.md §4 env (operator UID, eligible-after,
# PATH, budgets) and the scheduler scratch root under the worktree root
setpriv --reuid=501 --regid=501 --clear-groups central serve
```

Serve fetches the bound generation over frame 0xb1, composes B10, and
starts the scheduler on the real launcher + real killer.

## 5. Submit (pinned command)

```text
CENTRAL_NODE_DSN=<runtime-dsn> central run submit --workspace 019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a --title <title> --workers 2 --run-key <fresh-key-per-run>
```

(Copied verbatim from `phase-2-run-submit.md`; fresh `--run-key` per
intended-new-run.) Verify per that doc's queries: nodes ready →
claimed/dispatched → real sessions under the started serve.

## Per-restart mint rule

Each serve start consumes one generation (one-shot by construction).
Before EVERY serve (re)start, repeat steps 2–3. P1's sequence is
kill → mint → transcribe → restart. Concurrent serves must never share
one descriptor: they race the one-shot and the loser fails closed.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `serve: [RESTORE_BARRIER_UNAVAILABLE]` exit 6 | broker down or wrong `CENTRAL_BROKER_SOCKET` | start step 1; check the socket path |
| `CONFIG_INVALID: harness execution requires the artifact object store` | stale/consumed/wrong reference (or broker hiccup at fetch) | re-mint + re-transcribe (steps 2–3), restart serve |
| `CONFIG_INVALID: invalid B10 binding reference descriptor` | descriptor unreadable/invalid (perms, owner, JSON, endpoint) | fix file: 0400, owned by 501, strict schema |
| `broker serve: socket path already exists` | stale socket from a killed broker | remove the socket file, restart the verb |
| `authority denied: mode requires root` | verb run as non-root | run step 1 as root |
| `CONFIG_INVALID` naming a harness variable | harness env (unchanged behavior) | see `harness-execution.md` §4 |

No step in this doc handles harness credentials (operator-owned,
unchanged) or edits historical evidence.
