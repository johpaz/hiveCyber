# Manual de uso de hiveCyber

Guía práctica de extremo a extremo: del cero a operar agentes autónomos de ciberseguridad
contra objetivos **autorizados** (bug bounty, pentest con alcance, labs, CTF).

> ⚠️ **Solo objetivos autorizados.** Las tools de red exigen allowlist/EngagementPolicy; las
> de explotación exigen además `--unsafe-mode`. Toda ejecución queda auditada (hash-chain
> tamper-evident). Nunca lo uses sobre sistemas sin autorización explícita.

Índice:
1. [Qué es](#1-qué-es)
2. [Instalación](#2-instalación)
3. [Configuración inicial (provider + modelo)](#3-configuración-inicial-provider--modelo)
4. [Verificar el entorno (`doctor`)](#4-verificar-el-entorno)
5. [Definir el alcance (EngagementPolicy)](#5-definir-el-alcance-engagementpolicy)
6. [Ejecutar una operación (`run` / `chat`)](#6-ejecutar-una-operación)
7. [Cómo funciona por dentro](#7-cómo-funciona-por-dentro)
8. [Operaciones de larga duración (`runs` / `resume`)](#8-operaciones-de-larga-duración)
9. [Endurecimiento de red (firewall de egreso)](#9-endurecimiento-de-red)
10. [Extender con MCP](#10-extender-con-mcp)
11. [Auditoría](#11-auditoría)
12. [Flujo completo de bug bounty (paso a paso)](#12-flujo-completo-de-bug-bounty)
13. [Troubleshooting](#13-troubleshooting)
14. [Referencia rápida de comandos](#14-referencia-rápida-de-comandos)

---

## 1. Qué es

hiveCyber es un harness en Rust donde un **coordinador (Caelum)** delega tareas en **8 workers
especializados** (recon, vulns, exploit, forense, web, threat-intel, reportes, archivos), con
selección dinámica de tools (BM25), acceptance por evidencias, memoria persistente, sandbox
seccomp para las tools ofensivas y auditoría tamper-evident. Los agentes son de **larga
duración**: los runs son durables y reanudables.

## 2. Instalación

**Desde fuente** (Linux/macOS/Windows):
```bash
git clone <repo> && cd hiveCyber
cargo build --release
# binarios: target/release/hivecyber  y  target/release/hivecyber-worker
sudo install target/release/hivecyber* /usr/local/bin/   # opcional
```

**Docker** (recomendado para el toolchain cybersec + el firewall de egreso — ver §9):
```bash
docker build -t hivecyber .
docker run --rm -it hivecyber doctor
```

**Binarios precompilados**: en GitHub Releases (linux x86_64/aarch64, macOS Intel/ARM, Windows).
Detalle multi-SO en [distribution.md](distribution.md).

## 3. Configuración inicial (provider + modelo)

Las API keys se guardan **cifradas** (AES-256-GCM; master key en `<home>/.master.key`, 0600).
Una vez configurado, corres **sin exportar env vars**.

```bash
# Ver el catálogo de modelos (provider, context window, costo USD/1M)
hivecyber models
hivecyber models --provider anthropic

# Guardar la key (cifrada) y fijar el provider/modelo por defecto
hivecyber provider set anthropic --api-key sk-ant-...
hivecyber provider default anthropic --model claude-sonnet-5

hivecyber provider list      # muestra qué providers tienen key y cuál es default
hivecyber provider show anthropic
```

Alternativa por variable de entorno (prevalece sobre lo guardado): `export ANTHROPIC_API_KEY=…`.

**Caso hiveagents (backend GGUF local/propio)** requiere cargar el modelo antes de usarlo:
```bash
hivecyber provider set hiveagents --api-key <KEY> --model Qwen3.6-35B-A3B-UD-Q4_K_M.gguf
hivecyber provider default hiveagents
# cargar el modelo en el backend (POST /api/load) y esperar a que quede "loaded":
curl -sS -X POST https://llm.hiveagents.io/api/load \
  -H "Authorization: Bearer <KEY>" -H "Content-Type: application/json" \
  -d '{"model":"Qwen3.6-35B-A3B-UD-Q4_K_M.gguf","config":{"ctx":50000}}'
curl -sS https://llm.hiveagents.io/api/status -H "Authorization: Bearer <KEY>"   # {"loaded":true,...}
```

El **context window** del modelo (del catálogo) determina el presupuesto de compaction del
loop; el costo alimenta reportes de gasto. Ver [providers.md](providers.md).

## 4. Verificar el entorno

```bash
hivecyber doctor
```
Reporta plataforma/arch, **disponibilidad del sandbox** (seccomp es Linux-only; fuera de Linux
las tools de explotación se **rechazan por defecto** — usa Docker o `HIVECYBER_ALLOW_UNSANDBOXED=1`),
estado de `agent-browser`, y qué binarios cybersec (nmap/nuclei/…) están instalados, con el
comando de instalación para tu SO.

## 5. Definir el alcance (EngagementPolicy)

El control central. Un JSON declara los targets, límites y prohibiciones del programa:

```json
{
  "program": "acme-bugbounty-2026",
  "targets": [
    { "host": "app.example.com", "paths": ["/api/**"], "methods": ["GET","POST"],
      "rate_limit_rps": 3, "only_own_accounts": true },
    { "host": "10.0.0.0/24", "paths": ["/**"], "methods": ["GET","POST"], "rate_limit_rps": 5 }
  ],
  "excluded": ["admin.example.com", "10.0.0.1"],
  "prohibited": ["denial_of_service", "destructive_test", "social_engineering"],
  "require_human_approval": ["exploit", "credential_use"],
  "time_windows": { "allowed_days": ["Mon","Tue","Wed","Thu","Fri"], "allowed_hours_utc": [22, 6] }
}
```

Se aplica por cada llamada a una tool de red (`validate_target`): host exacto/subdominio/CIDR,
exclusiones, **ventanas horarias**, y **rate limiting fail-closed** por `programa::host`.

```bash
# Gate OBLIGATORIO (recomendado para bug bounty): rechaza operar sin política válida
hivecyber run "..." --engagement-policy acme.json --require-policy
```

Alternativa mínima (host/CIDR por línea, sin rate/ventanas): `--allowlist-hosts targets.txt`.
Detalle en [security.md](security.md).

## 6. Ejecutar una operación

**No interactivo** (una misión):
```bash
# Recon web autorizado (solo GET, sin explotación)
hivecyber run "Recon de https://app.example.com: enumera rutas y tecnología, prioriza superficie" \
  --engagement-policy acme.json --require-policy

# Explotación autorizada (requiere --unsafe-mode)
hivecyber run "Reproduce la inyección SQL del login de https://app.example.com y captura PoC" \
  --engagement-policy acme.json --require-policy --unsafe-mode
```

**Interactivo** (REPL con el coordinador):
```bash
hivecyber chat --engagement-policy acme.json --require-policy
> Enumera subdominios de example.com y prioriza los que expongan API
```

Flags de seguridad: `--unsafe-mode` (habilita exploit), `--allow-cli-exec` (habilita `cli_exec`),
`--approve-human <categoria>` (aprueba una categoría que la política marca como que requiere
aprobación humana), `--require-policy` (gate obligatorio).

## 7. Cómo funciona por dentro

- **Delegación**: Caelum descompone la misión y delega en workers con `task_delegate`; sigue el
  avance con `task_status`/`task_list` y re-delega con `task_revise`. Ver [delegation.md](delegation.md).
- **Selección de tools (BM25)**: cada turno se envía al modelo solo las tools relevantes a la tarea
  (máx 12), no el catálogo completo. Igual para rutear workers y sugerir skills.
- **Acceptance**: cada entrega se valida con **evidencias estructuradas** tipadas (host,
  vulnerability con CVE/severidad, shell_session, artifact con hash+timestamp, report_file…);
  Failed → auto-pause@3 / auto-disable@5.
- **Memoria**: los agentes guardan notas persistentes (`memory_write/read/list/search`) para
  recordar hallazgos entre turnos.
- **Sandbox**: las tools `Isolation::Sandbox` (metasploit_rpc, hydra, crackmapexec, mimikatz)
  corren en un subproceso worker con seccomp + rlimits + namespaces (Linux).

## 8. Operaciones de larga duración

Cada hilo de conversación tiene un **run durable** (se checkpointea cada turno: iteraciones,
tokens, lease). Si el proceso o el LLM se cae, el run queda `interrupted` y **reanudable**:

```bash
hivecyber runs                 # lista runs: RUN_ID, STATUS, AGENT, iteraciones, tokens
hivecyber resume <RUN_ID>      # rehidrata el historial desde COL_MESSAGES y continúa
```

El loop compacta el contexto en memoria según el **context window real del modelo** (sin tocar
el registro durable). Ver [agent-loop.md](agent-loop.md).

## 9. Endurecimiento de red

Además del gate in-process, aplica un **firewall de egreso a nivel de kernel** (nftables
default-deny) generado desde la política — el contenedor solo alcanza los targets + DNS + la
infra que permitas (proveedor LLM):

```bash
# Generar el ruleset
hivecyber egress-rules --engagement-policy acme.json --resolve-hosts \
  --allow <CIDR-del-proveedor-LLM> --resolver 1.1.1.1

# Aplicarlo vía la imagen Docker endurecida (root aplica nft, baja a 'hive')
docker run --rm -it --user 0 --cap-add=NET_ADMIN \
  -e HIVECYBER_EGRESS_POLICY=/policy.json -e HIVECYBER_EGRESS_ALLOW="<CIDR-LLM>" \
  -e ANTHROPIC_API_KEY=... -v "$PWD/acme.json:/policy.json:ro" \
  --entrypoint /usr/local/bin/egress-entrypoint.sh \
  hivecyber run "recon de app.example.com" --engagement-policy /policy.json --require-policy
```
Detalle en [egress.md](egress.md). **Incluye el CIDR del proveedor LLM en `--allow`** o el agente
no podrá llamar al modelo.

## 10. Extender con MCP

Conecta tools externas (filesystem, GitHub, KBs, APIs) por Model Context Protocol; sus tools
quedan disponibles para los agentes.

```bash
hivecyber mcp add fs --transport stdio --command npx \
  --arg -y --arg @modelcontextprotocol/server-filesystem --arg /casos
hivecyber mcp add remote --transport wss --url wss://api.example.com/mcp --header "Authorization=Bearer …"
hivecyber mcp list           # servers + estado
hivecyber mcp tools fs       # tools que expone
```
Transportes: stdio, SSE/streamable-HTTP, WebSocket (con reconnect). Ver [mcp.md](mcp.md).

## 11. Auditoría

Toda ejecución de tool se sella en una cadena hash SHA-256 **tamper-evident** (append atómico):

```bash
hivecyber audit show      # [timestamp] id tool target=… worker=…
hivecyber audit verify    # "Audit log chain: VERIFIED (all hashes valid)"
hivecyber logs            # tail de traces (tool, OK/FAIL, duración)
```

## 12. Flujo completo de bug bounty

```bash
# 1) Configura provider + modelo (una vez)
hivecyber provider set anthropic --api-key sk-ant-... && hivecyber provider default anthropic --model claude-sonnet-5

# 2) Escribe el alcance del programa (targets, rate, ventanas, prohibidas)
$EDITOR acme.json

# 3) (opcional, recomendado) genera y aplica el firewall de egreso — ver §9

# 4) Verifica el entorno
hivecyber doctor

# 5) Recon con gate obligatorio (solo GET)
hivecyber run "Recon de https://app.example.com: superficie, rutas, tecnología, prioriza hallazgos" \
  --engagement-policy acme.json --require-policy

# 6) Profundiza / explota lo autorizado
hivecyber run "Valida y reproduce las vulnerabilidades priorizadas con PoC reproducible" \
  --engagement-policy acme.json --require-policy --unsafe-mode

# 7) Informe
hivecyber run "Compila un informe ejecutivo (docx) + tabla de riesgos (xlsx) con los hallazgos" \
  --engagement-policy acme.json --require-policy

# 8) Verifica la integridad de la operación
hivecyber audit verify
hivecyber runs
```

Para practicar sin un programa real: [e2e.md](e2e.md) levanta OWASP Juice Shop/WebGoat/DVWA
locales y corre el flujo contra ellos.

## 13. Troubleshooting

- **`--require-policy: se requiere una EngagementPolicy`** → pasa `--engagement-policy <file>`.
- **`target … not in engagement policy allowlist`** → el host no está en `targets` (o está en
  `excluded`); revisa el JSON.
- **`rate limit excedido`** → es fail-closed por diseño; sube `rate_limit_rps` del target si el
  programa lo permite.
- **`fuera de la ventana horaria`** → tu `time_windows` no cubre la hora UTC actual.
- **`provider not configured`** → falta la key (`provider set` o env var) o el `default_provider`.
- **hiveagents `No hay modelo cargado` / `524`** → carga el modelo (`/api/load`) y espera `loaded`;
  el 524 es timeout de Cloudflare en modelos grandes — reintenta o usa un modelo más rápido; el run
  queda `interrupted` y se reanuda con `resume`.
- **`[MISSING] nmap/nuclei/…`** → instala el toolchain (`doctor` da el comando) o usa la imagen Docker.
- **`agent-browser no disponible`** → instala `agent-browser` o setea `AGENT_BROWSER_BIN`; los
  `browser_*` degradan con error claro.
- **Sandbox no disponible (macOS/Windows)** → las tools de exploit se rechazan; usa Docker (Linux).

## 14. Referencia rápida de comandos

| Comando | Para qué |
|---|---|
| `hivecyber chat` / `run "<misión>"` | Operar (interactivo / una vez) |
| `hivecyber provider set/list/show/default` | Providers, API keys (cifradas), modelos |
| `hivecyber models [--provider p]` | Catálogo de modelos (ctx, costo) |
| `hivecyber agent list/show/enable/disable/set-model/set-provider` | Gestión de agentes |
| `hivecyber skills list/show/add/reload` | Skills (playbooks) |
| `hivecyber mcp add/list/connect/tools/call/disconnect/remove` | Servers MCP |
| `hivecyber runs` / `resume <id>` | Runs durables / reanudar |
| `hivecyber egress-rules --engagement-policy <f>` | Firewall de egreso nftables |
| `hivecyber audit show/verify` · `logs` | Auditoría tamper-evident / traces |
| `hivecyber doctor` | Entorno, sandbox, deps cybersec |
| `hivecyber config show` | Config efectiva |

Flags globales: `--engagement-policy <f>` · `--require-policy` · `--allowlist-hosts <f>` ·
`--unsafe-mode` · `--allow-cli-exec` · `--approve-human <cat>`.

Docs por tema: [cli.md](cli.md) · [security.md](security.md) · [egress.md](egress.md) ·
[delegation.md](delegation.md) · [agent-loop.md](agent-loop.md) · [mcp.md](mcp.md) ·
[providers.md](providers.md) · [tools.md](tools.md) · [skills.md](skills.md) ·
[use-cases.md](use-cases.md) · [e2e.md](e2e.md) · [distribution.md](distribution.md) ·
[architecture.md](architecture.md).
