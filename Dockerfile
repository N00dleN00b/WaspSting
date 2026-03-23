# ── WaspSting Dockerfile ──────────────────────────────────────────────────────
# Multi-stage build: keeps final image small (~120 MB)
# Base: python:3.11-slim (no bloat, no GUI tools)
# Optional Ollama AI: use docker-compose.yml instead of this file directly
#
# Build:   docker build -t waspsting .
# Run:     docker run --rm -it waspsting --help
# Bounty:  docker run --rm -it waspsting --target https://target.com --mode recon --confirm
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build deps (only needed at build time)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: final runtime image ─────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="WaspSting" \
      org.opencontainers.image.description="Authorized Pentest Documentation & Analysis Tool" \
      org.opencontainers.image.authors="N00dleN00b" \
      org.opencontainers.image.source="https://github.com/N00dleN00b/waspsting" \
      org.opencontainers.image.licenses="MIT"

# Runtime system deps
# git  — required for SAST (repo cloning)
# curl — used by some recon checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Create non-root user for safety
RUN useradd -m -u 1000 waspsting
WORKDIR /app

# Copy application source
COPY --chown=waspsting:waspsting . .

# Output directory — mounted as a volume so reports persist after container exits
RUN mkdir -p /app/output && chown waspsting:waspsting /app/output
VOLUME ["/app/output"]

# Switch to non-root
USER waspsting

# Make waspsting runnable as a command
ENTRYPOINT ["python3", "waspsting.py"]
CMD ["--help"]