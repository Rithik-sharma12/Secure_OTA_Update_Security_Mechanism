FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-slim

LABEL maintainer="OTA Framework Team"
LABEL description="Secure OTA Update Server"

# Security: create non-root user
RUN groupadd --gid 1000 ota && \
    useradd --uid 1000 --gid 1000 --no-create-home --shell /bin/false ota

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application code
COPY server/ ./server/
COPY security/ ./security/
COPY cli/ ./cli/

# Create required directories
RUN mkdir -p uploads/firmware keys certs logs \
    && chown -R ota:ota /app

USER ota

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "4", "--log-level", "info", "--no-access-log"]
