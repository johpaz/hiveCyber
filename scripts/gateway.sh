#!/usr/bin/env bash
# Operación local del gateway + panel de hiveCyber.
#
#   scripts/gateway.sh start             arranca el gateway (sirve el panel de panel/dist)
#   scripts/gateway.sh stop              lo para y limpia navegadores huérfanos del scoped-browser
#   scripts/gateway.sh restart
#   scripts/gateway.sh status            puerto, política activa, ventana, auditoría
#   scripts/gateway.sh token             imprime el token de acceso al panel
#   scripts/gateway.sh panel             instala dependencias y compila el panel
#   scripts/gateway.sh register-browser  registra el MCP scoped-browser (con el gateway parado)
#   scripts/gateway.sh logs
#
# Variables: HIVECYBER_GATEWAY_HOME (def. <repo>/.hivecyber/gateway; ignora HIVECYBER_HOME), HIVECYBER_PORT (def. 18798),
#            HIVECYBER_CONTEXT_BUDGET (def. 40000), BUN_CHROME_PATH (Chrome/Chromium para scoped-browser).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Variable propia: NO hereda un HIVECYBER_HOME ya exportado en tu shell (es el de la CLI).
export HIVECYBER_HOME="${HIVECYBER_GATEWAY_HOME:-$ROOT/.hivecyber/gateway}"
PORT="${HIVECYBER_PORT:-18798}"
export HIVECYBER_CONTEXT_BUDGET="${HIVECYBER_CONTEXT_BUDGET:-40000}"
PIDFILE="$HIVECYBER_HOME/gateway.pid"
LOG="$HIVECYBER_HOME/gateway.log"
PANEL="$ROOT/panel/dist"

bin() { # nombre -> ruta (release > debug)
  for p in "$ROOT/target/release/$1" "$ROOT/target/debug/$1"; do [ -x "$p" ] && { echo "$p"; return; }; done
  echo "falta $1: ejecuta  cargo build --release -p hivecyber-gateway -p hivecyber-worker -p hivecyber-cli" >&2; exit 1
}
chrome() {
  [ -n "${BUN_CHROME_PATH:-}" ] && { echo "$BUN_CHROME_PATH"; return; }
  find "$HOME/.cache/ms-playwright" -maxdepth 4 -type f \( -name chrome -o -name chrome-headless-shell \) 2>/dev/null | head -1
}
token() { cat "$HIVECYBER_HOME/gateway.token" 2>/dev/null || { echo "aún no hay token: arranca el gateway una vez" >&2; exit 1; }; }
running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }
api() { curl -fsS -m 10 -H "Authorization: Bearer $(token)" "http://127.0.0.1:$PORT/api/$1"; }

cmd="${1:-status}"
case "$cmd" in
  start)
    running && { echo "ya está corriendo (pid $(cat "$PIDFILE"))"; exit 0; }
    if ss -ltn 2>/dev/null | grep -q ":$PORT "; then echo "el puerto $PORT está ocupado" >&2; exit 1; fi
    [ -d "$PANEL" ] || { echo "panel sin compilar: ejecuta  scripts/gateway.sh panel" >&2; exit 1; }
    mkdir -p "$HIVECYBER_HOME"; chmod 700 "$HIVECYBER_HOME"
    HIVECYBER_WORKER_BIN="$(bin hivecyber-worker)" nohup "$(bin hivecyber-gateway)" --port "$PORT" --panel-dir "$PANEL" \
      >"$LOG" 2>&1 &
    echo $! >"$PIDFILE"
    for _ in $(seq 1 20); do sleep 0.5; curl -fsS -m 2 -o /dev/null "http://127.0.0.1:$PORT/" && break; done
    running || { echo "no arrancó; revisa $LOG" >&2; exit 1; }
    echo "gateway en http://127.0.0.1:$PORT   (home: $HIVECYBER_HOME)"
    echo "token: $(token)"
    ;;
  stop)
    if running; then kill "$(cat "$PIDFILE")"; sleep 1; fi
    rm -f "$PIDFILE"
    # el servidor MCP scoped-browser y su Chrome sobreviven al gateway: se cierran aquí
    for p in $(pgrep -f "tools/scoped-browser/server.ts" || true); do [ "$p" != "$$" ] && kill "$p" 2>/dev/null || true; done
    echo "detenido"
    ;;
  restart) "$0" stop; "$0" start ;;
  status)
    if running; then echo "gateway: corriendo (pid $(cat "$PIDFILE")) en http://127.0.0.1:$PORT"; else echo "gateway: detenido"; exit 0; fi
    api security/status | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("política activa: v%s  %s" % (d.get("active_policy_version"), d.get("program")))
w = d.get("window")
print("ventana: " + ("sin ventana" if not w else ("ABIERTA" if w["open_now"] else "CERRADA") + " " + str(w.get("allowed_hours_utc"))))
print("cabeceras obligatorias:", d.get("required_headers") or "—")
print("aprobación humana:", d.get("require_human_approval"))
print("unsafe_mode:", d.get("unsafe_mode"), "| cli_exec:", d.get("allow_cli_exec"))'
    echo -n "auditoría: "; api audit/verify; echo
    ;;
  token) token ;;
  logs) tail -n 60 -f "$LOG" ;;
  panel) (cd "$ROOT/panel" && npm install && npm run build) ;;
  register-browser)
    running && { echo "para el gateway primero (scripts/gateway.sh stop): la CLI no debe abrir el mismo HIVECYBER_HOME" >&2; exit 1; }
    CH="$(chrome)"; [ -n "$CH" ] || { echo "no encuentro Chrome/Chromium; define BUN_CHROME_PATH" >&2; exit 1; }
    CLI="$(bin hivecyber)"
    "$CLI" mcp remove scoped-browser >/dev/null 2>&1 || true
    "$CLI" mcp add scoped-browser --transport stdio --command bun \
      --arg "$ROOT/tools/scoped-browser/server.ts" \
      --env "HIVECYBER_HOME=$HIVECYBER_HOME" --env "BUN_CHROME_PATH=$CH" \
      --env "HIVECYBER_GATEWAY=http://127.0.0.1:$PORT" --env "SCOPED_BROWSER_MAX_REQUESTS=${SCOPED_BROWSER_MAX_REQUESTS:-150}"
    ;;
  *) sed -n 2,14p "$0"; exit 1 ;;
esac
