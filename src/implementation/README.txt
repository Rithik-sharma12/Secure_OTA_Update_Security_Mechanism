# Secure Heterogeneous OTA Implementation Guide

This folder contains the backend runtime used by OTA IDE for live OTA telemetry, release state, and deployment simulation.

## Files
1. `edge_gateway.py` - Primary backend service for OTA runtime APIs.
2. `device_simulator.py` - Simulates IoT devices sending heartbeat and consuming firmware manifest/download APIs.
3. `server.py` - Legacy standalone OTA server prototype.
4. `integration_smoke_test.py` - End-to-end integration checker for backend + frontend + auth middleware.

## Backend Deployment

### Step 1: Create Virtual Environment (Recommended Location)
Create the virtual environment inside this folder at `src/implementation/.venv`:

```powershell
Set-Location C:\Users\Rithik Sharma\Desktop\OTA_IOT\src\implementation
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 3: Start the OTA Gateway Backend (FastAPI)

FastAPI native command:

```powershell
uvicorn edge_gateway:app --host 0.0.0.0 --port 5000
```

Or run the script directly:

```powershell
python edge_gateway.py
```

The backend runs at `http://localhost:5000` and exposes:

- `GET /healthz`
- `GET /api/dashboard`
- `POST /api/heartbeat`
- `GET /releases/latest/manifest`
- `GET /releases/download/<filename>`
- `POST /api/releases`
- `POST /api/deployments`
- `POST /api/pipeline/run`

Before running write APIs in production, set:

- `OTA_GATEWAY_API_KEY` (gateway write/auth key)
- `OTA_GATEWAY_RELEASE_ARTIFACT` (absolute path to a real `.bin` firmware artifact, for release creation without explicit `sourceFilePath`)

### Step 4: Start Device Simulators (Optional)

```powershell
python device_simulator.py ESP32
python device_simulator.py STM32F103
```

## Full Integration Test (Frontend + Backend + API + Middleware)

Make sure OTA IDE is running on `http://localhost:3000`, then run:

```powershell
set OTA_TEST_ADMIN_USERNAME=<your-admin-username>
set OTA_TEST_ADMIN_PASSWORD=<your-admin-password>
set OTA_TEST_FIRMWARE_PATH=C:\Users\Rithik Sharma\Desktop\OTA_IOT\CODE\frimware_code\.pio\build\esp32dev\firmware.bin
python integration_smoke_test.py
```

The script validates:

1. Backend health and release creation.
2. Heartbeat ingestion and dashboard payload.
3. Manifest publication and firmware metadata.
4. Frontend auth login and session middleware.
5. Authorized runtime snapshot integration between frontend API and backend gateway.

## Security Notes

- Set `OTA_GATEWAY_API_KEY` to protect write APIs (`/api/releases`, `/api/deployments`, `/api/pipeline/run`, `/api/trigger_sync`).
- Set `EDGE_GATEWAY_API_KEY` in OTA IDE environment to match when gateway write/read key enforcement is enabled.
