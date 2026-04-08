import json
import hashlib
import time
import socket
import threading
import os
from flask import Flask, jsonify, request, send_file, render_template_string
import requests

# CONFIGURATION
# -------------------------------------------------------------------------
GATEWAY_PORT = 5000  # Standard Flask port
FIRMWARE_CACHE_DIR = 'gateway_firmware_cache'
# -------------------------------------------------------------------------

app = Flask(__name__)

# In-memory State
DEVICES_DB = {}
SYSTEM_ALERTS = []

if not os.path.exists(FIRMWARE_CACHE_DIR):
    os.makedirs(FIRMWARE_CACHE_DIR)

# --- Helper: Get Raspberry Pi System Info ---
def get_pi_status():
    status = {"ip": "Unknown", "temp": "Unknown", "load": "Unknown"}
    try:
        # Get IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        status["ip"] = s.getsockname()[0]
        s.close()
        
        # Get Temp (Linux/Pi specific)
        if os.path.exists("/sys/class/thermal/thermal_zone0/temp"):
            with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
                status["temp"] = f"{round(float(f.read()) / 1000, 1)}°C"
        else:
            status["temp"] = "N/A (Not Pi)"
            
        status["load"] = str(os.getloadavg()[0]) if hasattr(os, "getloadavg") else "0.0"
    except Exception as e:
        status["ip"] = "127.0.0.1 (Dev Mode)"
        status["temp"] = "N/A"
        status["load"] = "0.0"
    return status

# --- Core: Heartbeat Receiver (ASH Monitor) ---
@app.route('/api/heartbeat', methods=['POST'])
def receive_heartbeat():
    data = request.json
    device_id = data.get('device_id')
    
    if device_id:
        current_time = time.strftime('%H:%M:%S')
        ash_score = data.get('ash_score', 0)
        previous_score = DEVICES_DB.get(device_id, {}).get('ash_score', 100)
        
        # Analyze drastic drops
        if previous_score > 40 and ash_score <= 40:
            TIMEOUT = 20 # seconds
            alert = f"[{current_time}] CRITICAL: Device {device_id} entered QUARANTINE."
            SYSTEM_ALERTS.insert(0, alert)
            
        DEVICES_DB[device_id] = {
            "type": data.get('device_type', 'Unknown'),
            "version": data.get('current_version', '0.0.0'),
            "ash_score": ash_score,
            "status": data.get('status', 'Unknown'),
            "last_seen": current_time,
            "ip": request.remote_addr,
            "logs": data.get('logs', [])
        }
        return jsonify({"command": "ack", "gateway_time": current_time}), 200
    return jsonify({"error": "Missing device_id"}), 400

# --- Core: Proxy / Cache for Firmware (Bandwidth Saving) ---
# Devices ask the Pi for updates, Pi checks GitHub, Caches it, Serves it.

@app.route('/releases/latest/manifest', methods=['GET'])
def get_manifest():
    """
    Acts as a proxy. 
    1. Checks GitHub for latest release. 
    2. Caches manifest locally.
    3. Serves to local device.
    """
    # For simulation purposes, we serve a local mock manifest.
    # In production, this would request https://api.github.com/...
    
    mock_manifest_path = os.path.join(FIRMWARE_CACHE_DIR, 'manifest.json')
    if os.path.exists(mock_manifest_path):
        return send_file(mock_manifest_path)
    else:
        # Create a dummy one if not exists for demo
        dummy = {
            "version": "1.0.0",
            "filename": "firmware_v1.0.0.bin",
            "sha256": "dummy_hash",
            "size": 1024,
            "signature": "mock_ed25519_signature_placeholder",
            "min_hw_rev": "1.0"
        }
        with open(mock_manifest_path, 'w') as f:
            json.dump(dummy, f)
        return send_file(mock_manifest_path)

@app.route('/releases/download/<filename>', methods=['GET'])
def download_firmware(filename):
    file_path = os.path.join(FIRMWARE_CACHE_DIR, filename)
    
    # If file doesn't exist locally, try to download from GitHub (Simulated logic)
    if not os.path.exists(file_path):
        # SIMULATION: Generate a dummy file
        with open(file_path, 'wb') as f:
            # Generate fake binary content for simulation
            # In real system: requests.get(github_release_asset_url)
            f.write(f"Binary content for {filename}".encode())
            
    return send_file(file_path)

# --- UI: Master Dashboard ---
@app.route('/')
def dashboard_ui():
    # Serve the static HTML file
    # We assume 'src/index.html' is in the parent directory relative to this script
    # Adjust path if necessary based on where you run the script from
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return send_file(os.path.join(project_root, 'index.html'))

@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_data():
    """
    API endpoint for the frontend to poll.
    Returns current devices, alerts, and Pi status.
    """
    pi_stats = get_pi_status()
    
    # Transform DEVICES_DB to list for easier consumption
    devices_list = []
    ash_distribution = []
    
    for dev_id, info in DEVICES_DB.items():
        devices_list.append({
            "id": dev_id,
            "arch": info.get('type', 'Unknown'), # Mapping 'type' to 'arch' for UI
            "fw": info.get('version', '0.0.0'),
            "ash": info.get('ash_score', 0),
            "status": info.get('status', 'offline'),
            "last_seen": info.get('last_seen', ''),
            "ram": "N/A" # Placeholder
        })
        
        ash_distribution.append({
            "id": dev_id,
            "score": info.get('ash_score', 0),
            "status": info.get('status', 'unknown')
        })

    return jsonify({
        "pi_stats": pi_stats,
        "devices": devices_list,
        "ash_devices": ash_distribution,
        "alerts": SYSTEM_ALERTS, 
        # Using the same structure as the UI expects for events/releases (or keeping them mock for now if backend doesn't track them)
        "events": [], # Backend could track these later
        "releases": [] # Backend could track these later
    })

@app.route('/api/trigger_sync', methods=['POST'])
def trigger_sync():
    # Simulation: Just update the local manifest version to v2.0.0
    mock_manifest_path = os.path.join(FIRMWARE_CACHE_DIR, 'manifest.json')
    
    new_version = "2.0.0"
    content = f"Binary content for v{new_version}".encode()
    filename = f"firmware_{new_version}.bin"
    sha256 = hashlib.sha256(content).hexdigest()
    
    manifest = {
        "version": new_version,
        "filename": filename,
        "sha256": sha256,
        "size": len(content),
        "signature": "mock_ed25519_signature_placeholder",
        "min_hw_rev": "1.0"
    }

    with open(mock_manifest_path, 'w') as f:
        json.dump(manifest, f)
        
    SYSTEM_ALERTS.insert(0, f"GITHUB SYNC: Pulled new version {new_version}")
    return "Sync Started", 200

if __name__ == '__main__':
    print(f"[*] Starting Edge Gateway Monitor on port {GATEWAY_PORT}...")
    # On Pi, host='0.0.0.0' is crucial to be visible on network
    app.run(host='0.0.0.0', port=GATEWAY_PORT, debug=False)