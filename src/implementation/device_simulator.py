import requests
import time
import hashlib
import random
import sys
import json

# Configuration
SERVER_URL = "http://localhost:5000"
DEVICE_TYPE = "ESP32"  # Change to "STM32" or "AVR" for other instances
CHECK_INTERVAL = 5  # Seconds between polls
DEVICE_ID = f"{DEVICE_TYPE}_{random.randint(1000, 9999)}"

# ASH Configuration
ASH_MAX = 100
ASH_THRESHOLD_QUARANTINE = 40
ASH_PENALTY_HASH_MISMATCH = 20
ASH_PENALTY_OFFLINE = 1
ASH_REWARD_SUCCESS = 10

class SentinelDevice:
    def __init__(self, device_id, device_type):
        self.id = device_id
        self.type = device_type
        self.current_version = "1.0.0"
        self.ash_score = 100
        self.status = "Healthy"
        self.quarantined = False
        self.logs = []
        
        print(f"[*] Device {self.id} ({self.type}) Online. Firmware: {self.current_version}")

    def log(self, message):
        timestamp = time.strftime('%H:%M:%S')
        entry = f"[{timestamp}] {message}"
        print(entry)
        self.logs.append(entry)
        if len(self.logs) > 10: self.logs.pop(0)

    def update_ash(self, points):
        """Update Anomaly-Scored Heartbeat"""
        self.ash_score += points
        if self.ash_score > ASH_MAX: self.ash_score = ASH_MAX
        if self.ash_score < 0: self.ash_score = 0
        
        if self.ash_score < ASH_THRESHOLD_QUARANTINE and not self.quarantined:
            self.quarantined = True
            self.status = "Quarantined"
            self.log("!!! ASH CRITICAL: ENTROPY TOO HIGH. ENTERING QUARANTINE !!!")
        elif self.ash_score >= ASH_THRESHOLD_QUARANTINE and self.quarantined:
            self.quarantined = False
            self.status = "Healthy"
            self.log("ASH Score recovered. Exiting quarantine.")

    def send_heartbeat(self):
        """Send status to monitoring dashboard"""
        try:
            payload = {
                "device_id": self.id,
                "device_type": self.type,
                "current_version": self.current_version,
                "ash_score": self.ash_score,
                "status": self.status,
                "logs": self.logs
            }
            requests.post(f"{SERVER_URL}/api/heartbeat", json=payload, timeout=1)
        except requests.exceptions.RequestException:
            # print("Server unreachable...")
            pass

    def check_for_updates(self):
        if self.quarantined:
            self.log("Skipping update check (Quarantined)")
            return

        self.log(f"Polling {SERVER_URL}/releases/latest/manifest...")
        try:
            # 1. Fetch Manifest
            resp = requests.get(f"{SERVER_URL}/releases/latest/manifest", timeout=2)
            if resp.status_code != 200:
                self.log(f"Failed to check manifest: {resp.status_code}")
                return

            manifest = resp.json()
            remote_version = manifest['version']
            
            # 2. Semantic Version Check (Simple String Compare for demo)
            if remote_version == self.current_version:
                # self.log("Already up to date.")
                return 
            
            self.log(f"New version found: {remote_version}. Starting TCV Pipeline...")
            self.status = "Updating..."
            self.send_heartbeat()

            # 3. Download Binary
            bin_url = f"{SERVER_URL}/releases/download/{manifest['filename']}"
            bin_resp = requests.get(bin_url)
            
            if bin_resp.status_code != 200:
                self.log("Download failed.")
                self.update_ash(-5)
                return

            firmware_data = bin_resp.content

            # 4. Hash Verification
            computed_hash = hashlib.sha256(firmware_data).hexdigest()
            if computed_hash != manifest['sha256']:
                self.log("!!! ALERT: Hash Mismatch! Potential Man-in-the-Middle Attack.")
                self.update_ash(-ASH_PENALTY_HASH_MISMATCH)
                self.status = "Healthy"
                return
            
            self.log(f"Hash Verified ({computed_hash[:8]}...).")

            # 5. Mock Signature Verification
            # In real scenario: ed25519.verify(manifest['signature'], firmware_data, pub_key)
            if manifest['signature'] == "mock_ed25519_signature_placeholder":
                self.log("Signature Verified.")
            else:
                 self.log("!!! ALERT: Invalid Signature!")
                 self.update_ash(-50)
                 return

            # 6. Install (Simulated)
            self.log(f"Installing v{remote_version}...")
            time.sleep(2) # Simulating flash write
            self.current_version = remote_version
            self.log(f"Success! Updated to v{remote_version}")
            self.update_ash(ASH_REWARD_SUCCESS)
            self.status = "Healthy"

        except Exception as e:
            self.log(f"Update error: {str(e)}")
            self.update_ash(-1)

    def run(self):
        while True:
            self.send_heartbeat()
            self.check_for_updates()
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        DEVICE_TYPE = sys.argv[1]
    
    # Create random ID based on input type
    dev_id = f"{DEVICE_TYPE}_{random.randint(1000, 9999)}"
    
    device = SentinelDevice(dev_id, DEVICE_TYPE)
    
    # Introduce random fault scenario for demo purposes
    if "FAULTY" in DEVICE_TYPE:
        # Start a faulty device to show ASH decreasing
        print("SIMULATING FAULTY NETWORK/ATTACK SCENARIO")
    
    try:
        device.run()
    except KeyboardInterrupt:
        print("\nDevice shutting down.")
