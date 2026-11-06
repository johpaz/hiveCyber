#!/usr/bin/env bash
# Guarda la clave de un proveedor en el gateway SIN pasar por el chat ni imprimirla.
# Copia la clave al portapapeles y ejecuta:   scripts/set-provider-key.sh [proveedor]   (def.: hiveagents)
# La clave se envía por loopback al gateway, que la cifra en su almacén de secretos.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ID="${1:-hiveagents}"
TOKEN="$("$ROOT/scripts/gateway.sh" token)"
PORT="${HIVECYBER_PORT:-18798}"
KEY="$(wl-paste -n 2>/dev/null || xclip -o -selection clipboard 2>/dev/null)"
case "$KEY" in *[[:space:]]*|"") echo "RECHAZADO: el portapapeles no parece una clave (vacío o con espacios/saltos de línea)" >&2; exit 1;; esac
[ "${#KEY}" -ge 16 ] || { echo "RECHAZADO: clave demasiado corta (${#KEY} caracteres)" >&2; exit 1; }
python3 - "$ID" "$PORT" "$TOKEN" "$KEY" <<'PY'
import sys, json, urllib.request
pid, port, token, key = sys.argv[1:5]
req = urllib.request.Request(f"http://127.0.0.1:{port}/api/providers/{pid}", method="PUT",
    data=json.dumps({"api_key": key}).encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
print("OK" if json.load(urllib.request.urlopen(req)).get("ok") else "falló", "- clave guardada para", pid, "(longitud", len(key), ")")
PY
