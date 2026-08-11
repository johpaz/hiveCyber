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

## Paquetes Linux (.deb / .rpm)

El release también publica **`.deb`** (familia Debian: Debian, Ubuntu, Mint, Kali…) y
**`.rpm`** (familia RPM: Fedora, RHEL/Rocky/Alma, openSUSE…), para **amd64 y arm64**,
generados con [`nfpm`](https://nfpm.goreleaser.com/) desde `packaging/nfpm.yaml`. Instalan
`hivecyber` y `hivecyber-worker` en `/usr/bin`.

```bash
# Debian/Ubuntu/Kali/…
sudo dpkg -i hivecyber_<ver>_amd64.deb        # o arm64
# Fedora/RHEL/openSUSE/…
sudo rpm -i hivecyber-<ver>-1.x86_64.rpm      # o aarch64
```

**Notas de portabilidad (importante):**
- Un `.deb`/`.rpm` **no es "solo Ubuntu"** — es por *familia de empaquetado*, no por distro.
- Los binarios se compilan con **glibc** en `ubuntu-latest`, así que corren en distros glibc
  cuyo glibc sea **≥** el del build. Distros con glibc muy viejo pueden no ejecutarlos.
- Los `.deb`/`.rpm` son glibc → **no corren en Alpine** (musl). Para eso usa el binario
  **musl-static** (abajo) o la **imagen Docker**.

## Binario musl-static (corre en CUALQUIER distro, incl. Alpine)

El release también publica binarios **estáticos musl** (`x86_64-unknown-linux-musl` y
`aarch64-unknown-linux-musl`) como `.tar.gz`. Al estar enlazados estáticamente **no dependen
de glibc**, así que corren en cualquier distribución — Alpine, distros viejas, contenedores
`scratch`/`distroless`, etc. Es la opción "un solo binario, cualquier Linux".

```bash
tar xzf hivecyber-*-x86_64-unknown-linux-musl.tar.gz
sudo install hivecyber-*/hivecyber* /usr/local/bin/
```

Se compilan con [`cross`](https://github.com/cross-rs/cross) (Docker, trae el toolchain musl
completo que necesita `ring`/rustls). El sandbox seccomp del worker sigue siendo Linux-only,
pero funciona igual en un binario musl.

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

### Imagen publicada en Docker Hub

Cada release publica `johpaz/hivecyber` en Docker Hub, **multi-arch** (`linux/amd64` +
`linux/arm64` — construida con `docker buildx` + QEMU, sin necesitar runners nativos
por arquitectura; el Dockerfile no requiere cambios, cada plataforma compila nativamente
dentro de su propio contexto de build):

```bash
docker pull johpaz/hivecyber:latest      # o :vX.Y.Z para una versión fija
docker run --rm -it johpaz/hivecyber doctor
```

Publicado por el job `docker` de `release.yml` (`docker/build-push-action`), que requiere
el secret de repo `DOCKERHUB_TOKEN` (access token de Docker Hub con permiso Read & Write;
Docker Hub → Account Settings → Security → New Access Token). El usuario (`johpaz`) está
fijo en el workflow, no es secreto.

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
