# Secure_OTA Docker Deployment Guide

This guide provides source-build and Docker Hub pull workflows for running Secure_OTA on college systems.

## 1. What Is Containerized

Two runtime services are containerized:
- `ota_ide` (Next.js control plane) on port `3000`
- `gateway` (FastAPI edge gateway) on port `5000`

Persistent runtime data is stored in Docker volumes:
- `gateway_cache` -> gateway firmware cache and manifest state
- `gateway_keys` -> gateway signing keys
- `ota_ide_db` -> OTA_IDE local auth/session database

## 2. Prerequisites

- Docker Engine
- Docker Compose plugin (`docker compose`)

## 3. Local Build and Run (from source)

1. Copy env template:

```powershell
Copy-Item .env.docker.example .env.docker
```

2. Edit `.env.docker` and set secure values for:
- `OTA_ADMIN_PASSWORD`
- `OTA_GATEWAY_API_KEY`

3. Build and start:

```powershell
docker compose --env-file .env.docker up -d --build
```

4. Check service status:

```powershell
docker compose ps
```

5. Open UI:
- `http://localhost:3000`
- Gateway: `http://localhost:5000/healthz`

## 4. Publish Images to Docker Hub

Run from repository root after Docker login:

```powershell
docker login

docker build -t <dockerhub-user>/secure-ota-gateway:latest ./src/implementation
docker push <dockerhub-user>/secure-ota-gateway:latest

docker build -t <dockerhub-user>/secure-ota-ide:latest ./CODE/OTA_IDE
docker push <dockerhub-user>/secure-ota-ide:latest
```

Optional tag strategy:

```powershell
docker tag <dockerhub-user>/secure-ota-gateway:latest <dockerhub-user>/secure-ota-gateway:v1.0.0
docker push <dockerhub-user>/secure-ota-gateway:v1.0.0

docker tag <dockerhub-user>/secure-ota-ide:latest <dockerhub-user>/secure-ota-ide:v1.0.0
docker push <dockerhub-user>/secure-ota-ide:v1.0.0
```

## 5. Deploy by Pulling from Docker Hub

1. Copy env template and set Docker Hub user:

```powershell
Copy-Item .env.docker.example .env.docker
```

Set in `.env.docker`:
- `DOCKERHUB_USER=<dockerhub-user>`
- `IMAGE_TAG=latest` (or a pinned tag)

2. Pull and run:

```powershell
docker compose -f docker-compose.hub.yml --env-file .env.docker pull
docker compose -f docker-compose.hub.yml --env-file .env.docker up -d
```

3. Verify:

```powershell
docker compose -f docker-compose.hub.yml --env-file .env.docker ps
```

## 6. Update Existing Deployment

```powershell
docker compose -f docker-compose.hub.yml --env-file .env.docker pull
docker compose -f docker-compose.hub.yml --env-file .env.docker up -d
```

## 7. Stop and Remove

Local build stack:

```powershell
docker compose --env-file .env.docker down
```

Docker Hub stack:

```powershell
docker compose -f docker-compose.hub.yml --env-file .env.docker down
```

To also remove persisted data:

```powershell
docker compose -f docker-compose.hub.yml --env-file .env.docker down -v
```

## 8. Important Notes

- Serial COM flashing from inside containers is not guaranteed on shared college systems.
- For first-time board provisioning, host-based serial flashing is recommended.
- Gateway and OTA_IDE integration works through internal compose DNS (`http://gateway:5000`).
- If password includes `#`, keep it quoted in env files.
