# hiveCyber — batteries-included Linux image.
#
# Ships both binaries plus the apt-available subset of the cybersec toolchain.
# Linux is the only platform where the worker seccomp sandbox is enforced, so
# the container is the recommended way to run exploitation workloads regardless
# of the operator's host OS.
#
# Build:  docker build -t hivecyber .
# Run:    docker run --rm -it hivecyber run "Escanea 10.0.0.0/24"
#
# Tools NOT in Debian repos (install separately if needed): nuclei, trivy,
# semgrep, metasploit, crackmapexec, theHarvester, volatility3, zeek, osquery,
# subfinder, dnsx, httpx, katana, gau, feroxbuster, arjun (ver recon-builder).

# ---- builder ----
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin hivecyber --bin hivecyber-worker

# ---- obscura-builder (disabled until pinned — see below) ----
# Obscura (browser-automation MCP server, replaces the old agent-browser/
# Bun.WebView daemon). Commented out on purpose: it must be pinned to an
# exact, already-vetted commit/tag/checksum before this image ships browser
# automation — never a moving branch. To enable: uncomment this stage AND
# the matching `COPY --from=obscura-builder` line in the runtime stage below.
#
# FROM rust:1-bookworm AS obscura-builder
# WORKDIR /obscura
# RUN git clone --depth 1 --branch <VETTED_TAG_OR_COMMIT> <VETTED_REPO_URL> . \
#     && echo "<EXPECTED_SHA256>  Cargo.lock" | sha256sum -c - \
#     && cargo build --release --bin obscura-mcp

# ---- runtime ----
FROM debian:bookworm-slim AS runtime

# Core tools guaranteed in Debian bookworm main; the optional ones are installed
# best-effort so the image still builds if a package is absent in the repo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ca-certificates \
         nmap \
         hydra \
         whois \
         dnsutils \
         python3 \
         nftables \
    && for p in yara sqlmap ffuf; do \
         apt-get install -y --no-install-recommends "$p" || echo "skip optional: $p"; \
       done \
    && rm -rf /var/lib/apt/lists/*

# Recon moderno (ProjectDiscovery subfinder/dnsx/httpx/katana, gau). Son
# binarios de Go que no están en Debian. Etapa opcional y vetada, igual que
# obscura-builder: descomenta ambos bloques para incluirlos. Los wrappers de
# `recon/mod.rs` validan el scope y rechazan metacaracteres antes de ejecutarlos.
#   feroxbuster: binario propio (releases de GitHub); arjun: `pipx install arjun`.
# FROM golang:1-bookworm AS recon-builder
# RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@<TAG> \
#  && go install github.com/projectdiscovery/dnsx/cmd/dnsx@<TAG> \
#  && go install github.com/projectdiscovery/httpx/cmd/httpx@<TAG> \
#  && go install github.com/projectdiscovery/katana/cmd/katana@<TAG> \
#  && go install github.com/lc/gau/v2/cmd/gau@<TAG>
# (en runtime) COPY --from=recon-builder /go/bin/ /usr/local/bin/

COPY --from=builder /build/target/release/hivecyber /usr/local/bin/hivecyber
COPY --from=builder /build/target/release/hivecyber-worker /usr/local/bin/hivecyber-worker
# Uncomment once the obscura-builder stage above is enabled:
# COPY --from=obscura-builder /obscura/target/release/obscura-mcp /usr/local/bin/obscura-mcp
# Opt-in egress-firewalled entrypoint (run as root + --cap-add=NET_ADMIN). Ver docs/egress.md.
# Also registers the Obscura MCP server (if /usr/local/bin/obscura-mcp is
# present) before dropping to the unprivileged `hive` user — see the [mcp]
# step added to this script.
COPY docker/egress-entrypoint.sh /usr/local/bin/egress-entrypoint.sh
RUN chmod +x /usr/local/bin/egress-entrypoint.sh

# Run unprivileged; the worker sandbox drops privileges further per exploit tool.
RUN useradd --create-home --uid 1000 hive
USER hive
WORKDIR /home/hive
ENV HIVECYBER_HOME=/home/hive/.hivecyber

ENTRYPOINT ["hivecyber"]
CMD ["doctor"]
