# syntax=docker/dockerfile:1

# ---- build stage: compile the app + deps into an isolated venv --------------------------
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

# ---- runtime stage: no compilers, no pip cache, non-root ---------------------------------
FROM python:3.12-slim AS runtime
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIGIL_RULES_DIR=/app/rules \
    VIGIL_DATABASE_URL=sqlite+aiosqlite:////app/data/vigilsiem.db

RUN groupadd --system --gid 10001 vigil \
    && useradd --system --uid 10001 --gid vigil --no-create-home --shell /usr/sbin/nologin vigil \
    && mkdir -p /app/data && chown vigil:vigil /app/data

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root rules ./rules
COPY --chown=root:root scripts ./scripts

USER 10001:10001
EXPOSE 8000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

# Secrets (VIGIL_JWT_SECRET, VIGIL_ADMIN_PASSWORD_HASH) are injected at runtime, never baked in.
# The app does its own trusted-proxy handling, so uvicorn's proxy-header rewriting is disabled.
ENTRYPOINT ["uvicorn", "--factory", "vigilsiem.api.app:create_app", \
            "--host", "0.0.0.0", "--port", "8000", \
            "--no-server-header", "--no-proxy-headers"]
