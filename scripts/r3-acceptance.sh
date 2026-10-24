#!/usr/bin/env bash
# r3-acceptance.sh — Phase R3 Tier-4 acceptance runner.
#
# Provisions a scratch database through the native migration runner,
# boots `central serve` on the CENTRAL_LOCALEXEC=1 dev path, seeds the
# durable fixtures in tests/acceptance/seed.sql, then runs the
# Playwright suite in tests/acceptance/playwright/.
#
# Environment:
#   CENTRAL_TEST_DSN              superuser DSN on the scratch cluster
#                                 (default postgresql://postgres:central@localhost:55432/postgres)
#   CENTRAL_TEST_MINIO_ENDPOINT   reachable S3 endpoint for the artifact
#                                 leg; when unset, an `adobe/s3mock`
#                                 docker image is started if available.
#                                 CENTRAL_ACCEPTANCE_S3MOCK=off disables
#                                 that fallback.
#   CENTRAL_TEST_MINIO_ACCESS_KEY / _SECRET_KEY / _BUCKET / _TLS
#   CENTRAL_ACCEPTANCE_APP_LISTEN / _OPS_LISTEN   listener addresses
#   CENTRAL_ACCEPTANCE_KEEP_DB=1  keep the acceptance database on exit
#   CENTRAL_ACCEPTANCE_SKIP_PLAYWRIGHT=1          skip the browser leg
#
# Exit codes: 0 pass (or explicit skip), 2 prerequisite/config, 3 serve
# readiness timeout, 4 Playwright failure, 5 provision/seed failure.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

CENTRAL_TEST_DSN="${CENTRAL_TEST_DSN:-postgresql://postgres:central@localhost:55432/postgres}"
ACCEPT_DB="${CENTRAL_ACCEPTANCE_DB:-central_r3_acceptance}"
APP_LISTEN="${CENTRAL_ACCEPTANCE_APP_LISTEN:-127.0.0.1:18080}"
OPS_LISTEN="${CENTRAL_ACCEPTANCE_OPS_LISTEN:-127.0.0.1:19090}"
BOOTSTRAP_TOKEN="${CENTRAL_ACCEPTANCE_BOOTSTRAP_TOKEN:-r3-acceptance-bootstrap-token}"
WORK_DIR="${CENTRAL_ACCEPTANCE_WORK_DIR:-$REPO_ROOT/target/r3-acceptance}"
READY_TIMEOUT_S="${CENTRAL_ACCEPTANCE_READY_TIMEOUT_S:-120}"
SERVE_BIN="${CENTRAL_SERVE_BIN:-$REPO_ROOT/target/debug/central}"
S3MOCK_IMAGE="${CENTRAL_ACCEPTANCE_S3MOCK_IMAGE:-adobe/s3mock:latest}"
S3MOCK_MODE="${CENTRAL_ACCEPTANCE_S3MOCK:-auto}"

# ACCEPT_DB interpolates into DROP/CREATE DDL — hold it to a plain
# PostgreSQL identifier before anything runs.
[[ "$ACCEPT_DB" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] \
    || die "CENTRAL_ACCEPTANCE_DB is not a plain identifier ([A-Za-z_][A-Za-z0-9_]*, max 63 bytes)" 2

SERVE_PID=""
S3MOCK_CONTAINER=""
ARTIFACT_ENABLED=false
PW_RESULT="not-run"

note() { printf 'r3-acceptance: %s\n' "$*" >&2; }
die() { note "$*"; exit "${2:-2}"; }

cleanup() {
    local rc=$?
    if [ -n "$SERVE_PID" ] && kill -0 "$SERVE_PID" 2>/dev/null; then
        kill -TERM "$SERVE_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$SERVE_PID" 2>/dev/null || break
            sleep 0.3
        done
        kill -KILL "$SERVE_PID" 2>/dev/null || true
    fi
    if [ -n "$S3MOCK_CONTAINER" ]; then
        docker rm -f "$S3MOCK_CONTAINER" >/dev/null 2>&1 || true
    fi
    if [ "${CENTRAL_ACCEPTANCE_KEEP_DB:-0}" != "1" ] && [ -n "${MIGRATION_DSN:-}" ]; then
        psql "$CENTRAL_TEST_DSN" -v ON_ERROR_STOP=0 \
            -c "DROP DATABASE IF EXISTS $ACCEPT_DB WITH (FORCE)" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# --- 1. prerequisites -------------------------------------------------------
command -v cargo >/dev/null || die "cargo not found" 2
command -v psql >/dev/null || die "psql not found (required to seed fixtures)" 2
command -v sha256sum >/dev/null || die "sha256sum not found" 2
command -v curl >/dev/null || die "curl not found" 2
command -v node >/dev/null || die "node not found (required for the seed-object and Playwright legs)" 2

mkdir -p "$WORK_DIR" "$WORK_DIR/dev-bootstrap" "$WORK_DIR/allowed-root"
chmod 700 "$WORK_DIR/dev-bootstrap"

# --- 2. provision the acceptance database ----------------------------------
note "provisioning $ACCEPT_DB via the native migration runner"
PROVISION_OUT=$(CENTRAL_TEST_DSN="$CENTRAL_TEST_DSN" CENTRAL_ACCEPTANCE_DB="$ACCEPT_DB" \
    cargo run -q -p central-adapter-postgres --example r3_acceptance_provision) \
    || die "database provision failed" 5
MIGRATION_DSN=$(grep '^CENTRAL_MIGRATION_DSN=' <<<"$PROVISION_OUT" | cut -d= -f2-)
RUNTIME_DSN=$(grep '^CENTRAL_RUNTIME_DSN=' <<<"$PROVISION_OUT" | cut -d= -f2-)
[ -n "$MIGRATION_DSN" ] && [ -n "$RUNTIME_DSN" ] || die "provision output malformed" 5

# --- 3. object store leg (artifact preview/download) ------------------------
S3_ENDPOINT="${CENTRAL_TEST_MINIO_ENDPOINT:-}"
if [ -n "$S3_ENDPOINT" ]; then
    if ! curl -sf -o /dev/null -m 3 "$S3_ENDPOINT/minio/health/live" \
        && ! curl -sf -o /dev/null -m 3 "$S3_ENDPOINT"; then
        note "CENTRAL_TEST_MINIO_ENDPOINT=$S3_ENDPOINT unreachable — artifact leg disabled"
        S3_ENDPOINT=""
    fi
fi
if [ -z "$S3_ENDPOINT" ] && [ "$S3MOCK_MODE" != "off" ] && command -v docker >/dev/null \
    && docker image inspect "$S3MOCK_IMAGE" >/dev/null 2>&1; then
    S3MOCK_CONTAINER=$(docker run -d --rm -p 127.0.0.1:19093:9090 \
        -e "initialBuckets=${CENTRAL_TEST_MINIO_BUCKET:-central-artifacts}" \
        "$S3MOCK_IMAGE" 2>/dev/null) || S3MOCK_CONTAINER=""
    if [ -n "$S3MOCK_CONTAINER" ]; then
        S3_ENDPOINT="http://127.0.0.1:19093"
        for _ in $(seq 1 30); do
            curl -sf -o /dev/null -m 2 "$S3_ENDPOINT" && break
            sleep 1
        done
        note "s3mock started ($S3_ENDPOINT)"
    fi
fi

# --- 4. playwright toolchain ------------------------------------------------
PLAYWRIGHT_DIR="$REPO_ROOT/tests/acceptance/playwright"
PW_OK=false
if [ "${CENTRAL_ACCEPTANCE_SKIP_PLAYWRIGHT:-0}" = "1" ]; then
    note "CENTRAL_ACCEPTANCE_SKIP_PLAYWRIGHT=1 — browser leg skipped"
elif ! (cd "$PLAYWRIGHT_DIR" && npm install --no-audit --no-fund >/dev/null 2>&1); then
    note "npm install failed — browser leg skipped"
elif ! (cd "$PLAYWRIGHT_DIR" && npx playwright install chromium >/dev/null 2>&1); then
    note "playwright chromium install failed — browser leg skipped"
else
    PW_OK=true
fi

# --- 5. serve ---------------------------------------------------------------
if [ ! -x "$SERVE_BIN" ]; then
    note "building central (cargo build -p central)"
    cargo build -q -p central --bin central || die "central build failed" 5
fi

SERVE_ENV=(
    "CENTRAL_DSN=$RUNTIME_DSN"
    "CENTRAL_WORKSPACE_ID=019fdc8d-e33a-76ed-9ef0-a0d9fe92e54a"
    "CENTRAL_APP_LISTEN=$APP_LISTEN"
    "CENTRAL_OPS_LISTEN=$OPS_LISTEN"
    "CENTRAL_LOCALEXEC=1"
    "CENTRAL_DEV_BOOTSTRAP_ROOT=$WORK_DIR/dev-bootstrap"
    "CENTRAL_B11_ALLOWED_WORKSPACE_ROOTS=$WORK_DIR/allowed-root"
)
if [ -n "$S3_ENDPOINT" ]; then
    # `CENTRAL_ARTIFACT_OBJECT_ENDPOINT` is a bare host:port — the S3
    # adapter prepends the scheme from CENTRAL_ARTIFACT_OBJECT_USE_TLS.
    S3_HOSTPORT="${S3_ENDPOINT#http://}"
    S3_HOSTPORT="${S3_HOSTPORT#https://}"
    S3_HOSTPORT="${S3_HOSTPORT%/}"
    SERVE_ENV+=(
        "CENTRAL_ARTIFACT_OBJECT_ENDPOINT=$S3_HOSTPORT"
        "CENTRAL_ARTIFACT_OBJECT_BUCKET=${CENTRAL_TEST_MINIO_BUCKET:-central-artifacts}"
        "CENTRAL_ARTIFACT_OBJECT_ACCESS_KEY=${CENTRAL_TEST_MINIO_ACCESS_KEY:-minioadmin}"
        "CENTRAL_ARTIFACT_OBJECT_SECRET_KEY=${CENTRAL_TEST_MINIO_SECRET_KEY:-minioadmin}"
        "CENTRAL_ARTIFACT_OBJECT_USE_TLS=${CENTRAL_TEST_MINIO_TLS:-0}"
        "CENTRAL_ARTIFACT_OBJECT_REGION=${CENTRAL_TEST_MINIO_REGION:-us-east-1}"
    )
fi

note "starting central serve on $APP_LISTEN (ops $OPS_LISTEN)"
env "${SERVE_ENV[@]}" "$SERVE_BIN" serve >"$WORK_DIR/serve.log" 2>&1 &
SERVE_PID=$!

deadline=$((SECONDS + READY_TIMEOUT_S))
ready=false
while [ "$SECONDS" -lt "$deadline" ]; do
    if ! kill -0 "$SERVE_PID" 2>/dev/null; then
        note "central serve exited during startup — tail of serve.log:"
        tail -30 "$WORK_DIR/serve.log" >&2 || true
        die "serve exited" 3
    fi
    if curl -sf -o /dev/null -m 2 "http://$OPS_LISTEN/health/ready"; then
        ready=true
        break
    fi
    sleep 1
done
if [ "$ready" != "true" ]; then
    note "readiness timeout (${READY_TIMEOUT_S}s) — tail of serve.log:"
    tail -30 "$WORK_DIR/serve.log" >&2 || true
    die "serve never became ready" 3
fi
note "serve ready"

# --- 6. durable fixtures ----------------------------------------------------
TOKEN_HASH=$(printf '%s' "$BOOTSTRAP_TOKEN" | sha256sum | cut -d' ' -f1)
REPORT_SHA256=$(sha256sum "$REPO_ROOT/tests/acceptance/report.md" | cut -d' ' -f1)
REPORT_SIZE=$(wc -c < "$REPO_ROOT/tests/acceptance/report.md")

if [ -n "$S3_ENDPOINT" ] && [ "$PW_OK" = "true" ]; then
    # seed-object.mjs reads the CENTRAL_TEST_MINIO_* env — export it even
    # when the endpoint came from the auto-provisioned s3mock container.
    if (cd "$PLAYWRIGHT_DIR" && \
        CENTRAL_TEST_MINIO_ENDPOINT="$S3_ENDPOINT" \
        CENTRAL_TEST_MINIO_BUCKET="${CENTRAL_TEST_MINIO_BUCKET:-central-artifacts}" \
        CENTRAL_TEST_MINIO_ACCESS_KEY="${CENTRAL_TEST_MINIO_ACCESS_KEY:-minioadmin}" \
        CENTRAL_TEST_MINIO_SECRET_KEY="${CENTRAL_TEST_MINIO_SECRET_KEY:-minioadmin}" \
        CENTRAL_TEST_MINIO_TLS="${CENTRAL_TEST_MINIO_TLS:-0}" \
        CENTRAL_TEST_MINIO_REGION="${CENTRAL_TEST_MINIO_REGION:-us-east-1}" \
        node seed-object.mjs); then
        ARTIFACT_ENABLED=true
    else
        note "object seed failed — artifact leg disabled"
    fi
fi

psql "$MIGRATION_DSN" -v ON_ERROR_STOP=1 -q \
    -v token_hash="$TOKEN_HASH" \
    -v artifact_enabled="$ARTIFACT_ENABLED" \
    -v report_sha256="$REPORT_SHA256" \
    -v report_size="$REPORT_SIZE" \
    -f "$REPO_ROOT/tests/acceptance/seed.sql" \
    || die "fixture seed failed" 5
note "fixtures seeded (artifact_enabled=$ARTIFACT_ENABLED)"

# Cheap SSR liveness independent of the browser leg.
curl -sf -o /dev/null "http://$APP_LISTEN/app/bootstrap" \
    || die "/app/bootstrap did not render" 4

# --- 7. playwright ----------------------------------------------------------
if [ "$PW_OK" = "true" ]; then
    note "running playwright suite"
    if (cd "$PLAYWRIGHT_DIR" && \
        CENTRAL_ACCEPTANCE_BASE_URL="http://$APP_LISTEN" \
        CENTRAL_ACCEPTANCE_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
        CENTRAL_ACCEPTANCE_ARTIFACT="$([ "$ARTIFACT_ENABLED" = "true" ] && echo 1 || echo 0)" \
        npx playwright test); then
        PW_RESULT=pass
    else
        PW_RESULT=fail
    fi
else
    PW_RESULT="skipped (no playwright/chromium toolchain)"
fi

note "playwright: $PW_RESULT"
[ "$PW_RESULT" = "fail" ] && exit 4
exit 0
