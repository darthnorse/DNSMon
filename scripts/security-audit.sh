#!/usr/bin/env bash
# Audit shipped dependencies for known vulnerabilities: the production Python
# packages (pip-audit, inside the dev container) and the frontend runtime
# bundle (npm audit). Needs network access to the advisory databases, which is
# why it runs beside pytest rather than inside it.
set -uo pipefail

cd "$(dirname "$0")/.."
status=0

echo "== Python (pip-audit, production packages) =="
# appuser has no writable home, so the cache goes to /tmp.
docker exec dnsmon-app pip-audit -r /app/production-packages.txt --no-deps --disable-pip \
  --cache-dir /tmp/pip-audit-cache --progress-spinner off || status=1

echo
echo "== Frontend (npm audit, shipped bundle) =="
(cd frontend && npm audit --omit=dev) || status=1

exit "$status"
