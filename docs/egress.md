# Control de egreso de red (firewall nftables desde la política)

Control de egreso **a nivel de kernel**, protocolo-agnóstico, para agentes autónomos:
el contenedor donde corre hiveCyber solo puede alcanzar los **targets autorizados** de la
`EngagementPolicy`, el resolver DNS, y la infraestructura que permitas explícitamente
(proveedor LLM, MCP). Todo lo demás se **descarta** (default-deny).

## Por qué a nivel de kernel (y no un proxy)

Todas las tools de shell-out pasan por `CliExec → bash → binario`, y las ofensivas abren
**sockets crudos** (nmap SYN, hydra TCP, dig DNS) que un proxy HTTP/SOCKS **no ve**. Un
firewall nftables en el borde del contenedor los cubre a todos por igual, y lo aplica el
kernel **fuera del proceso** del agente — lo que una validación in-process no puede
garantizar. Las tools ofensivas además ya llaman `validate_target` in-process; el firewall
es el backstop de kernel.

## Generar las reglas desde la política

```bash
hivecyber egress-rules --engagement-policy programa.json \
  --resolve-hosts \                 # resuelve hostnames de la política a IPs (DNS aún abierto)
  --allow 104.18.0.0/16 \           # infra a permitir: CIDR del proveedor LLM (REQUERIDO)
  --resolver 1.1.1.1                # resolver DNS permitido (si se omite, DNS queda abierto)
```

Produce un script `nft -f` **default-deny** que permite loopback, established/related, DNS
(al resolver), y los `targets` de la política (IPv4/IPv6, IPs y CIDRs). Los hostnames sin
`--resolve-hosts` se listan como aviso para resolverlos y re-generar.

> **Importante:** incluye el CIDR/IP del **proveedor LLM** en `--allow`, o el agente no podrá
> llamar al modelo (el firewall bloquea todo lo no permitido). Igual para servidores MCP
> remotos y endpoints de research que necesites.

## Aplicarlo (imagen Docker)

La imagen trae `nftables` y un entrypoint opt-in que aplica las reglas como root y luego baja
al usuario no privilegiado `hive`:

```bash
docker run --rm -it \
  --user 0 --cap-add=NET_ADMIN \
  -e HIVECYBER_EGRESS_POLICY=/policy.json \
  -e HIVECYBER_EGRESS_ALLOW="104.18.0.0/16" \
  -e HIVECYBER_EGRESS_RESOLVER="1.1.1.1" \
  -e HIVEAGENTS_API_KEY=... \
  -v "$PWD/programa.json:/policy.json:ro" \
  --entrypoint /usr/local/bin/egress-entrypoint.sh \
  hivecyber run "recon autorizado de app.target.com" \
    --engagement-policy /policy.json --require-policy
```

El entrypoint (`docker/egress-entrypoint.sh`): genera las reglas mientras el DNS está abierto,
aplica `nft -f`, imprime la tabla activa, y hace `exec runuser -u hive -- hivecyber "$@"`. Sin
`--cap-add=NET_ADMIN` no puede aplicar el firewall.

## Capas de defensa

1. **Gate in-process** (`--require-policy`): rechaza operar sin política; `validate_target`
   aplica allowlist/exclusiones/rutas/métodos/ventanas/rate por cada llamada.
2. **Firewall de egreso (kernel)**: default-deny; solo targets + DNS + infra permitida.
   Cubre tools de socket crudo y el subproceso worker sandboxeado.

## Limitaciones / Roadmap

- **Separación agente vs tools**: hoy el allowlist es a nivel de contenedor — el agente y las
  tools comparten la misma allowlist (targets + infra). Un refinamiento (roadmap) es separar
  por `uid`/`cgroup` en nftables para que solo el agente alcance el LLM y las tools solo los
  targets.
- **Hostnames que rotan IP**: las reglas fijan las IPs al momento de generar. Para targets con
  DNS dinámico, re-genera/aplica periódicamente o usa CIDRs.
- **Fuera de Docker**: puedes aplicar el mismo ruleset en un network namespace dedicado; el
  patrón (root aplica nft → baja privilegios) es el mismo.
