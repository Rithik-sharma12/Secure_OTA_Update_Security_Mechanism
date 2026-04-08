import json
import hashlib
import time
from flask import Flask, jsonify, request, send_file, render_template_string
import os

# Configuration
HOST = '0.0.0.0'
PORT = 5000
FIRMWARE_DIR = 'firmware_repo'
DEVICES_DB = {}  # In-memory DB for demo: {device_id: {type, version, ash_score, last_seen, status}}

app = Flask(__name__)

# Ensure firmware directory exists
if not os.path.exists(FIRMWARE_DIR):
    os.makedirs(FIRMWARE_DIR)

# Mock Firmware & Manifest generation (In real life, triggered by Git Tag)
def generate_mock_firmware(version="1.0.0"):
    content = f"Firmware Version {version} - Secure Code".encode('utf-8')
    filename = f"firmware_v{version}.bin"
    filepath = os.path.join(FIRMWARE_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(content)
    
    # Calculate SHA256
    sha256 = hashlib.sha256(content).hexdigest()
    
    # Create Manifest
    manifest = {
        "version": version,
        "filename": filename,
        "sha256": sha256,
        "size": len(content),
        "signature": "mock_ed25519_signature_placeholder", # In real implementation, plug in Ed25519 signing here
        "min_hw_rev": "1.0"
    }
    
    with open(os.path.join(FIRMWARE_DIR, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=4)
        
    return manifest

# initialize with v1.0.0
generate_mock_firmware("1.0.0")

@app.route('/')
def home():
    return "SentinelOTA Server Running. Use /dashboard to view device status."

# --- OTA Endpoints ( Simulating GitHub Releases ) ---

@app.route('/releases/latest/manifest', methods=['GET'])
def get_manifest():
    """Device checks this endpoint to see updates"""
    try:
        return send_file(os.path.join(FIRMWARE_DIR, 'manifest.json'))
    except FileNotFoundError:
        return jsonify({"error": "No manifest found"}), 404

@app.route('/releases/download/<filename>', methods=['GET'])
def download_firmware(filename):
    """Device downloads the binary here"""
    try:
        filepath = os.path.join(FIRMWARE_DIR, filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
        else:
            return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- ASH & Monitoring Endpoints ---

@app.route('/api/heartbeat', methods=['POST'])
def receive_heartbeat():
    """
    Devices send their status here.
    Payload: {
        "device_id": "ESP32_001",
        "device_type": "ESP32",
        "current_version": "1.0.0",
        "ash_score": 100,
        "status": "Healthy", # or "Upgrading", "Quarantined"
        "logs": ["Boot successful"]
    }
    """
    data = request.json
    device_id = data.get('device_id')
    
    if device_id:
        DEVICES_DB[device_id] = {
            "type": data.get('device_type', 'Unknown'),
            "version": data.get('current_version', '0.0.0'),
            "ash_score": data.get('ash_score', 0),
            "status": data.get('status', 'Unknown'),
            "last_seen": time.strftime('%Y-%m-%d %H:%M:%S'),
            "logs": data.get('logs', [])
        }
        return jsonify({"command": "ack"}), 200
    return jsonify({"error": "Missing device_id"}), 400

# --- Dashboard Interface ---

@app.route('/dashboard')
def dashboard():
    """Simple HTML Dashboard to view Heterogeneous Device Status"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SentinelOTA Security Dashboard</title>
        <meta http-equiv="refresh" content="5"> <!-- Auto refresh every 5s -->
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #f4f4f9; color: #333; padding: 20px; }
            h1 { color: #2c3e50; }
            .stats { display: flex; gap: 20px; margin-bottom: 20px; }
            .card { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); flex: 1; }
            table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #34495e; color: white; }
            tr:hover { background-color: #f1f1f1; }
            .score-high { color: green; font-weight: bold; }
            .score-med { color: orange; font-weight: bold; }
            .score-low { color: red; font-weight: bold; }
            .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.85em; }
            .bg-green { background: #d4edda; color: #155724; }
            .bg-red { background: #f8d7da; color: #721c24; }
            .bg-blue { background: #cce5ff; color: #004085; }
        </style>
    </head>
    <body>
        <h1>SentinelOTA Monitor</h1>
        <div class="stats">
            <div class="card">
                <h3>Total Devices</h3>
                <p style="font-size: 2em; margin: 0;">{{ total_devices }}</p>
            </div>
            <div class="card">
                <h3>Security Alerts</h3>
                <p style="font-size: 2em; margin: 0; color: red;">{{ alerts }}</p>
            </div>
            <div class="card">
                <h3>System Status</h3>
                <p style="font-size: 2em; margin: 0; color: green;">Active</p>
            </div>
        </div>

        <h2>Heterogeneous Device Fleet</h2>
        <table>
            <thead>
                <tr>
                    <th>Device ID</th>
                    <th>Type</th>
                    <th>Firmware</th>
                    <th>ASH Score (Health)</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>
                {% for id, dev in devices.items() %}
                <tr>
                    <td>{{ id }}</td>
                    <td>{{ dev.type }}</td>
                    <td>{{ dev.version }}</td>
                    <td class="{% if dev.ash_score > 70 %}score-high{% elif dev.ash_score > 40 %}score-med{% else %}score-low{% endif %}">
                        {{ dev.ash_score }} / 100
                    </td>
                    <td>
                        <span class="badge {% if dev.status == 'Healthy' %}bg-green{% elif dev.status == 'Quarantined' %}bg-red{% else %}bg-blue{% endif %}">
                            {{ dev.status }}
                        </span>
                    </td>
                    <td>{{ dev.last_seen }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <div style="margin-top: 20px; padding: 10px; background: #e9ecef; border-radius: 5px;">
            <h3>Control Panel</h3>
            <form action="/trigger_update" method="post" style="display:inline;">
                <input type="text" name="version" placeholder="v2.0.0" value="2.0.0" style="padding: 5px;">
                <button type="submit" style="padding: 5px 10px; cursor: pointer;">Release New Firmware</button>
            </form>
            <p><small>Simulates a 'git tag' push to the repository.</small></p>
        </div>
    </body>
    </html>
    """
    alerts = sum(1 for d in DEVICES_DB.values() if d['ash_score'] < 50)
    return render_template_string(html, devices=DEVICES_DB, total_devices=len(DEVICES_DB), alerts=alerts)

@app.route('/trigger_update', methods=['POST'])
def trigger_update():
    v = request.form.get('version', '2.0.0')
    generate_mock_firmware(v)
    return f"Released Version {v}. <a href='/dashboard'>Back to Dashboard</a>"

if __name__ == '__main__':
    print(f"Server starting on http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=True)
