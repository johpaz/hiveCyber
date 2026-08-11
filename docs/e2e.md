# E2E contra apps vulnerables locales

Flujo de extremo a extremo que corre hiveCyber (con **PolicyGate obligatorio**) contra
aplicaciones deliberadamente vulnerables levantadas en tu propia máquina — objetivos
**autorizados** por construcción. Útil para validar el harness completo: delegación,
tools de red, acceptance por evidencias, y la cadena de auditoría.

## Apps incluidas (`e2e/docker-compose.yml`)

| App | Imagen | URL local |
|-----|--------|-----------|
| OWASP Juice Shop | `bkimminich/juice-shop` | http://127.0.0.1:3000 |
| WebGoat | `webgoat/webgoat` | http://127.0.0.1:8080/WebGoat |
| DVWA | `vulnerables/web-dvwa` | http://127.0.0.1:8081 |

Todas se atan a `127.0.0.1` — **nunca** las expongas a una red.

## Pasos

```bash
# 1) Levanta los objetivos
docker compose -f e2e/docker-compose.yml up -d

# 2) Configura un provider LLM (una vez): key cifrada o env var
hivecyber provider set hiveagents --api-key <KEY> --model Qwen3.6-35B-A3B-UD-Q4_K_M.gguf
hivecyber provider default hiveagents
# (o export ANTHROPIC_API_KEY=… / HIVEAGENTS_API_KEY=…)

# 3) Corre el E2E (recon web autorizado, solo 127.0.0.1, con gate obligatorio)
cargo build --release
./e2e/run-e2e.sh

# 4) Baja los objetivos
docker compose -f e2e/docker-compose.yml down
```

`run-e2e.sh` espera a que las apps respondan, ejecuta `hivecyber run … --engagement-policy
e2e/engagement-policy.json --require-policy`, y al final corre `hivecyber audit verify` y
`hivecyber runs`.

## EngagementPolicy del E2E (`e2e/engagement-policy.json`)

Apunta solo a `127.0.0.1`/`localhost`, con `rate_limit_rps: 5` por host (fail-closed) y
actividades destructivas/DoS prohibidas. El flag `--require-policy` **rechaza** operar sin
esta política — el gate obligatorio recomendado para programas reales.

Para explotación (no solo recon) añade `--unsafe-mode`; el `web_pentester` usará
`sqlmap`/`nuclei`/`browser_*`. Mantén `rate_limit_rps` conservador.

## Nota: credential helper de Docker

Si `docker compose up` falla con `error getting credentials` (helper gpg del sistema
bloqueado), las imágenes son públicas y no requieren login — usa un config vacío:

```bash
export DOCKER_CONFIG="$(mktemp -d)"; echo '{}' > "$DOCKER_CONFIG/config.json"
docker compose -f e2e/docker-compose.yml up -d
```

## Estado

Scaffolding validado: el compose es válido, Juice Shop arranca y responde (`200`,
`/rest/products/search`), y el path del harness carga la política + pasa el gate
`--require-policy` + siembra agentes. El paso final (Caelum ejecutando recon real) requiere
un provider LLM configurado.
