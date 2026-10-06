# Reto inicial: CFR / Think Global Health

Programa publico: https://bugcrowd.com/engagements/cfr

Seleccionado como primer ejercicio porque el brief vigente lo marca abierto, incluye
`https://thinkglobalhealth.org` expresamente y permite herramientas automatizadas hasta
2 solicitudes por segundo. Esta configuracion es mas conservadora: un solo host, 1 rps,
solo GET/HEAD y scanners automaticos bloqueados.

## Ejecucion segura

```bash
export HIVECYBER_HOME=/data/hiveCyber/.hivecyber
/data/hiveCyber/target/release/hivecyber run "$(cat mission.txt)" \
  --engagement-policy engagement-policy.json \
  --require-policy
```

No uses `--unsafe-mode`. Revisa nuevamente el brief antes de cada sesion. Si cambia el
estado, el alcance o las exclusiones, actualiza primero la politica.
