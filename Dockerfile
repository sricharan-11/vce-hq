# syntax=docker/dockerfile:1.6
# ══════════════════════════════════════════════════════════════════════
#  Stage 1 — Builder: compile wheels (sqlite-vec, bcrypt, cryptography…)
# ══════════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only what pip needs to resolve dependencies first (better layer cache).
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build into an isolated prefix we can copy into the runtime image.
RUN pip install --prefix=/install --no-cache-dir .


# ══════════════════════════════════════════════════════════════════════
#  Stage 2 — Runtime: minimal image, non-root user, healthcheck ready
# ══════════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VCE_HOST=0.0.0.0 \
    VCE_PORT=8000 \
    VCE_DATA_DIR=/app/data \
    PATH=/install/bin:$PATH \
    PYTHONPATH=/install/lib/python3.12/site-packages

# curl → healthcheck; tini → clean PID 1 signal forwarding for uvicorn.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 vce \
    && useradd  --system --uid 1000 --gid vce --home /app --shell /usr/sbin/nologin vce

WORKDIR /app

# Pull the pre-built dependencies from the builder stage.
COPY --from=builder /install /install

# Application code + static frontend.
COPY --chown=vce:vce src/       /app/src/
COPY --chown=vce:vce frontend/  /app/frontend/
COPY --chown=vce:vce pyproject.toml README.md /app/

# Persistent tenant data lives here — mount a volume on this path.
RUN mkdir -p "$VCE_DATA_DIR" && chown -R vce:vce /app

USER vce

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=20s \
    CMD curl -fsS "http://localhost:${VCE_PORT}/health" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "exec python -m uvicorn vce_hq.api.app:create_app --factory --host ${VCE_HOST} --port ${VCE_PORT}"]
