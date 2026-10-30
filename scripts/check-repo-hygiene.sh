#!/usr/bin/env bash
# Repo hygiene gate: fail if personal identifiers appear in tracked files.
# Mirrors upstream ci/check-repo-hygiene.sh (ADR 0042 amendment).
#
# Deliberate exemptions:
#   - SECURITY.md, CODE_OF_CONDUCT.md  — maintainer's contact email is
#     published intentionally (ADR 0042 central-rust amendment).
#   - docs/adr/0042-*.md               — quotes the strip-list literals.
#   - docs/internal/tasks/open-source-readiness.md — documents the audit.
#   - THIRD_PARTY_LICENSES.md, this script.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# /home/<user> personal home paths. System/upstream homes
# (/home/minio, /home/op, /home/operator, /home/plugin, /home/cache,
# /home/central) are legitimate and allowed.
PERSONAL_HOME='~'
PERSONAL_EMAIL='hieuntg81@gmail\.com'

hits() {
    git grep -n -E "$1" -- . \
        ':!target' \
        ':!SECURITY.md' \
        ':!CODE_OF_CONDUCT.md' \
        ':!THIRD_PARTY_LICENSES.md' \
        ':!docs/adr/0042-*' \
        ':!docs/internal/tasks/open-source-readiness.md' \
        ':!scripts/check-repo-hygiene.sh' || true
}

fail=0

if out=$(hits "$PERSONAL_HOME") && [ -n "$out" ]; then
    echo "personal home path found:"
    echo "$out"
    fail=1
fi

if out=$(hits "$PERSONAL_EMAIL") && [ -n "$out" ]; then
    echo "personal email found:"
    echo "$out"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "repo hygiene: clean"
