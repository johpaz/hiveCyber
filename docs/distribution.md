# Distribución por sistema operativo

hiveCyber se compone de dos binarios Rust (`hivecyber` — CLI/coordinador, y
`hivecyber-worker` — ejecutor sandboxeado) más una cadena de herramientas cybersec
externas que se invocan por *shell-out*.

## ⚠️ Caveat de seguridad por SO (importante)

El **sandbox del worker** (seccomp BPF + rlimits + user/mount namespaces + Landlock)
es una característica del kernel de **Linux**. Las tools marcadas `Isolation::Sandbox`
(`metasploit_rpc`, `hydra`, `crackmapexec`, `mimikatz`) se confinan **solo en Linux**.

| SO | Compila | Sandbox del worker | Tools `Isolation::Sandbox` | Recomendación |
|----|---------|--------------------|----------------------------|---------------|
| **Linux** | ✅ | ✅ Enforced (seccomp+ns) | Se ejecutan confinadas | Nativo o Docker |
| **macOS** | ✅ | ❌ No disponible | **Rechazadas (fail-closed)** | Explotación → Docker |
| **Windows** | ✅ | ❌ No disponible | **Rechazadas (fail-closed)** | WSL2 o Docker |

En macOS/Windows los binarios funcionan (CLI, MCP, providers, memoria, delegación,
recon/OSINT), pero las tools `Isolation::Sandbox` (`metasploit_rpc`, `hydra`,
`crackmapexec`, `mimikatz`) se **rechazan por defecto** en vez de correr sin confinar —
tanto en el middleware (antes de spawnear el worker) como en el propio worker (defensa en
profundidad). Para ejecutarlas:

- **Recomendado**: la imagen Docker (Linux), donde el sandbox seccomp sí aplica.
- **Override explícito (inseguro)**: `HIVECYBER_ALLOW_UNSANDBOXED=1` las fuerza sin
  confinar, con warning. La ejecución queda auditada. Úsalo solo en un lab aislado.

`hivecyber doctor` reporta en tiempo real la disponibilidad del sandbox y si el override
está activo.

## Compilación desde fuente (cualquier SO)

Requiere Rust estable (edición 2021+).

```bash
git clone <repo> && cd hiveCyber
cargo build --release
# target/release/hivecyber  +  target/release/hivecyber-worker
```

Los deps unix-only (`nix`, `caps`, `libc`) están *target-gated* a `cfg(target_os = "linux")`,
por lo que macOS y Windows compilan sin ellos (el sandbox degrada a no-op).

## Binarios precompilados (GitHub Releases)

El workflow `.github/workflows/release.yml` publica, al hacer push de un tag `v*`,
artefactos por plataforma:

| Artefacto | Target |
|-----------|--------|
| `hivecyber-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` | Linux x86_64 |
| `hivecyber-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` | Linux ARM64 |
| `hivecyber-vX.Y.Z-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon |
| `hivecyber-vX.Y.Z-x86_64-apple-darwin.tar.gz` | macOS Intel |
| `hivecyber-vX.Y.Z-x86_64-pc-windows-msvc.zip` | Windows x64 |

```bash
# Linux/macOS
tar xzf hivecyber-*.tar.gz && sudo install hivecyber-*/hivecyber* /usr/local/bin/
# Windows: descomprime el .zip y agrega la carpeta al PATH
```

## Docker (recomendado para el toolchain completo)

La imagen `Dockerfile` es *batteries-included*: trae ambos binarios y el subset de
herramientas cybersec disponible en Debian (nmap, nikto, hydra, yara, whois, dig,
sqlmap). Es la forma recomendada de correr explotación **en cualquier host** porque el
sandbox seccomp se aplica dentro del contenedor Linux.

```bash
docker build -t hivecyber .
docker run --rm -it hivecyber doctor
docker run --rm -it \
  -e HIVEAGENTS_API_KEY=... \
  -v "$PWD/work:/home/hive/.hivecyber" \
  hivecyber run "Escanea 10.0.0.0/24 y reporta servicios"
```

Herramientas **no** empaquetadas en Debian (instálalas en una imagen derivada si las
necesitas): `nuclei`, `trivy`, `semgrep` (instaladores propios / go / pipx),
`metasploit`, `crackmapexec`, `theHarvester`, `volatility3`, `zeek`, `osquery`.

## Dependencias externas por SO

`hivecyber doctor` verifica las 16 tools y te imprime el comando de instalación según
tu SO. Resumen:

- **Debian/Ubuntu**: `sudo apt install -y nmap nikto hydra yara whois dnsutils zeek osquery`
  (el resto: instaladores propios de cada proyecto).
- **macOS (Homebrew)**: `brew install nmap nikto hydra yara nuclei trivy semgrep zeek`.
- **Windows**: `choco install nmap` (cobertura parcial); se recomienda WSL2 o Docker.

`agent-browser` (para los tools `browser_*`) es un binario aparte; define `AGENT_BROWSER_BIN`
si no está en el PATH.

## Configuración persistente (portátil entre SO)

- `HIVECYBER_HOME` fija el directorio de datos; por defecto usa el data dir del SO
  (`~/.local/share/hivecyber` en Linux, `~/Library/Application Support/…` en macOS,
  `%APPDATA%\…` en Windows) vía la crate `directories`.
- API keys cifradas con `provider set` (master key en `<home>/.master.key`, 0600 en
  unix). En Windows el archivo no recibe permisos 0600 (limitación de NTFS ACL); usa
  `HIVECYBER_MASTER_KEY` si necesitas control fino.
