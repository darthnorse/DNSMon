# syntax=docker/dockerfile:1
#
# Multi-stage:
#   - frontend-builder: produces frontend/build/
#   - production: minimal runtime image (default for CI / docker-publish)
#   - test: extends production with pytest + backend/tests/ + pyproject.toml
#
# Local dev (`docker compose up`) builds `test` so `docker exec dnsmon-app pytest`
# works out of the box. CI's docker-publish workflow targets `production`.

# Build frontend once on native platform (output is architecture-independent)
FROM --platform=$BUILDPLATFORM node:20-slim AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---------- production: shipped to GHCR by .github/workflows/docker-publish.yml
FROM python:3.13-slim AS production

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend, then strip the tests/ subdir from the production image.
COPY backend/ ./backend/
RUN rm -rf ./backend/tests/

COPY --from=frontend-builder /app/frontend/build/ ./frontend/build/

RUN mkdir -p /app/config && chown -R appuser:appuser /app

USER appuser

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health').read()"

EXPOSE 8000

CMD ["python", "-m", "backend.main"]

# ---------- test: production + pytest + backend/tests/
FROM production AS test
USER root
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY backend/tests/ ./backend/tests/
COPY pyproject.toml ./
RUN chown -R appuser:appuser /app
USER appuser
