#!/usr/bin/env bash
# hiveCyber E2E against the local vulnerable apps.
#
# Prereqs:
#   docker compose -f e2e/docker-compose.yml up -d
#   a configured LLM provider — either `hivecyber provider set …` or an env key
#   (e.g. HIVEAGENTS_API_KEY / ANTHROPIC_API_KEY).
#
# This drives hiveCyber with the mandatory PolicyGate (--require-policy) against
# 127.0.0.1 only, then verifies the audit chain. Read-only web recon by default
# (no --unsafe-mode) so it is safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${HIVECYBER_BIN:-$ROOT/target/release/hivecyber}"
POLICY="$ROOT/e2e/engagement-policy.json"

[ -x "$BIN" ] || { echo "build first: cargo build --release (or set HIVECYBER_BIN)"; exit 1; }

wait_for() { # url name
  echo -n "waiting for $2 ($1) "
  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "$1"; then echo "ok"; return 0; fi
    echo -n "."; sleep 2
  done
  echo "TIMEOUT"; return 1
}

wait_for "http://127.0.0.1:3000/" "juice-shop" || true
wait_for "http://127.0.0.1:8080/WebGoat" "webgoat" || true
wait_for "http://127.0.0.1:8081/" "dvwa" || true

echo "=== hiveCyber E2E (PolicyGate obligatorio, solo 127.0.0.1) ==="
"$BIN" run \
  "Haz recon web autorizado de http://127.0.0.1:3000 (OWASP Juice Shop): identifica el servidor, rutas visibles y posibles puntos de inyección. Solo GET/POST, sin explotación destructiva. Resume hallazgos con evidencia." \
  --engagement-policy "$POLICY" \
  --require-policy

echo "=== verificación de la cadena de auditoría ==="
"$BIN" audit verify
echo "=== runs ==="
"$BIN" runs
