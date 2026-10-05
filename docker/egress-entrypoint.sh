#!/usr/bin/env bash
# Opt-in egress-firewalled entrypoint for hiveCyber.
#
# Applies a default-deny nftables egress firewall derived from the
# EngagementPolicy BEFORE running the agent, then drops to the unprivileged
# `hive` user. Kernel-level, protocol-agnostic egress control (covers nmap /
# hydra / dig / HTTP alike) — the container can only reach the authorized
# targets, the DNS resolver, and whatever infra you allow (LLM provider, MCP).
#
# Run as root with NET_ADMIN and point it at your policy:
#   docker run --rm -it \
#     --user 0 --cap-add=NET_ADMIN \
#     -e HIVECYBER_EGRESS_POLICY=/policy.json \
#     -e HIVECYBER_EGRESS_ALLOW="104.18.0.0/16" \   # e.g. LLM provider CIDR (REQUIRED so the agent reaches the model)
#     -e HIVECYBER_EGRESS_RESOLVER="1.1.1.1" \       # DNS resolver (optional)
#     -e HIVEAGENTS_API_KEY=... \
#     -v "$PWD/policy.json:/policy.json:ro" \
#     --entrypoint /usr/local/bin/egress-entrypoint.sh \
#     hivecyber run "recon autorizado de …" --engagement-policy /policy.json --require-policy
set -euo pipefail

if [ "$(id -u)" != "0" ]; then
  echo "[egress] este entrypoint debe correr como root (--user 0 --cap-add=NET_ADMIN)" >&2
  exit 1
fi

if [ -n "${HIVECYBER_EGRESS_POLICY:-}" ]; then
  args=(egress-rules --engagement-policy "$HIVECYBER_EGRESS_POLICY" --resolve-hosts)
  for a in ${HIVECYBER_EGRESS_ALLOW:-}; do args+=(--allow "$a"); done
  for r in ${HIVECYBER_EGRESS_RESOLVER:-}; do args+=(--resolver "$r"); done

  # Generate rules while DNS is still open, then lock down egress.
  hivecyber "${args[@]}" 2>/dev/null > /tmp/hivecyber-egress.nft
  echo "[egress] aplicando firewall nftables desde ${HIVECYBER_EGRESS_POLICY}" >&2
  nft -f /tmp/hivecyber-egress.nft
  echo "[egress] tabla activa:" >&2
  nft list table inet hivecyber_egress >&2 || true
else
  echo "[egress] AVISO: HIVECYBER_EGRESS_POLICY no definido — el contenedor corre SIN firewall de egreso (inseguro para bug bounty)." >&2
fi

# Register the Obscura MCP server (browser automation) as the `hive` user,
# idempotently, before the real process boots — `agent/mcp_integration.rs`'s
# `load_and_connect` connects every registered MCP server eagerly at `chat`/
# `run`/`daemon` startup, so this just needs to exist in HiveDB beforehand.
# Safe to run every container start: `hivecyber mcp add` overwrites the same
# key, and the `mcp list` check below skips it if already present.
if [ -x /usr/local/bin/obscura-mcp ]; then
  if ! runuser -u hive -- hivecyber mcp list 2>/dev/null | grep -q '^  obscura '; then
    echo "[mcp] registrando servidor obscura (stdio, /usr/local/bin/obscura-mcp)" >&2
    runuser -u hive -- hivecyber mcp add obscura --transport stdio --command /usr/local/bin/obscura-mcp
  fi
else
  echo "[mcp] AVISO: /usr/local/bin/obscura-mcp no presente en esta imagen — sin tool de browser." >&2
fi

# Drop to the unprivileged app user for the actual work.
exec runuser -u hive -- hivecyber "$@"
