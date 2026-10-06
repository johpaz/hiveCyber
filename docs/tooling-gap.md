# Análisis de gaps de tooling

hiveCyber ya integra 38 tools base. Para un foco moderno de **bug bounty web/API/IA**, estas
son las que más faltan, mapeadas al worker que las usaría y a cómo encajan en el `ToolRegistry`
(categoría + `Isolation`). Todas son OSS conocidas y no destructivas (recon/descubrimiento),
salvo donde se indica.

## Recon de activos y superficie web
El `recon_operator` hoy tiene nmap/dig/whois/theHarvester/shodan/recon-ng. nmap no cubre bien
el descubrimiento de **activos web**:

| Tool | Para qué | Worker | Isolation |
|---|---|---|---|
| `subfinder` | enumeración de subdominios | recon_operator | none |
| `amass` | enumeración pasiva/activa (ya puede estar) | recon_operator | none |
| `dnsx` | resolución masiva + permutaciones | recon_operator | none |
| `httpx` | probing HTTP, títulos, tech, status | recon_operator | none |
| `katana` | crawling y extracción de endpoints | recon_operator / web_pentester | none |
| `gau` / `waybackurls` | URLs históricas (wayback, commoncrawl) | recon_operator | none |

## Descubrimiento de contenido y parámetros
| Tool | Para qué | Worker | Isolation |
|---|---|---|---|
| `ffuf` | fuzzing de rutas/params/vhosts | web_pentester | none |
| `feroxbuster` | content discovery recursivo | web_pentester | none |
| `arjun` | descubrimiento de parámetros ocultos | web_pentester | none |

## Análisis de JS y secretos
| Tool | Para qué | Worker | Isolation |
|---|---|---|---|
| `jsluice` | extraer endpoints/URLs/secretos de JS | web_pentester | none |
| `trufflehog` | secretos verificados en código/respuestas | threat_intel_analyst / vuln_scanner | none |
| `gitleaks` | secretos en repos/históricos git | threat_intel_analyst | none |

## Handoff a pruebas manuales (humano en el bucle)
El valor no es automatizar el disparo, sino **preparar** para el operador:

| Tool | Para qué | Worker | Isolation |
|---|---|---|---|
| Caido (REST API) | enviar requests interesantes al proxy del humano | web_pentester | none |
| `mitmproxy` | captura/replay programable de tráfico API | web_pentester | none |

## Superficie de IA (targets de productos LLM)
| Tool | Para qué | Worker | Isolation |
|---|---|---|---|
| `garak` | escáner de vulnerabilidades de LLMs | vuln_scanner | none |
| `promptfoo` | evaluación/red-team reproducible de prompts | vuln_scanner | none |

## Cloud (si el scope incluye infra)
| Tool | Para qué | Worker | Isolation |
|---|---|---|---|
| `prowler` | postura de seguridad cloud (lectura) | forensics_analyst / vuln_scanner | none |
| `cloudfox` | enumeración de superficie en cuentas cloud | recon_operator | none |

## Prioridad sugerida
1. **httpx + subfinder + katana + gau** — sin esto, el recon web es ciego. Máximo impacto.
2. **ffuf + jsluice + trufflehog** — descubrimiento y secretos, donde salen muchos findings.
3. **garak + promptfoo** — diferenciador para programas de IA, alineado con tu foco en agentes.
4. Caido/mitmproxy — el puente limpio hacia el testing manual.
5. Cloud — solo si entra en el scope del engagement.

> Todas entran como integraciones del `ToolRegistry` (igual que las 38 actuales): wrapper que
> normaliza salida a estructura + `EvidenceItem`, categoría declarada, y `Isolation::None` para
> las de recon/descubrimiento. Ninguna requiere el sandbox seccomp (ese queda para la categoría
> exploit).
