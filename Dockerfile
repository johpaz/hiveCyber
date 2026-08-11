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
# semgrep, metasploit, crackmapexec, theHarvester, volatility3, zeek, osquery.

# ---- builder ----
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin hivecyber --bin hivecyber-worker

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
    && for p in yara sqlmap; do \
         apt-get install -y --no-install-recommends "$p" || echo "skip optional: $p"; \
       done \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/hivecyber /usr/local/bin/hivecyber
COPY --from=builder /build/target/release/hivecyber-worker /usr/local/bin/hivecyber-worker
# Opt-in egress-firewalled entrypoint (run as root + --cap-add=NET_ADMIN). Ver docs/egress.md.
COPY docker/egress-entrypoint.sh /usr/local/bin/egress-entrypoint.sh
RUN chmod +x /usr/local/bin/egress-entrypoint.sh

# Run unprivileged; the worker sandbox drops privileges further per exploit tool.
RUN useradd --create-home --uid 1000 hive
USER hive
WORKDIR /home/hive
ENV HIVECYBER_HOME=/home/hive/.hivecyber

ENTRYPOINT ["hivecyber"]
CMD ["doctor"]
