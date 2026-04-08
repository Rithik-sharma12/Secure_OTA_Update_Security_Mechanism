# Secure Heterogeneous OTA Implementation Guide

This folder contains a fully functional simulation of the **Secure Heterogeneous OTA Update Mechanism**.

## Files
1.  **`server.py`**: Acts as the GitHub Releases server + Security Dashboard.
2.  **`device_simulator.py`**: Simulates an IoT device (ESP32, STM32, etc.) running the ASH and LG-OTA algorithms.

## How to Run the Demo

### Step 1: Install Dependencies
Open a terminal in the `src/implementation` folder:
```powershell
pip install -r requirements.txt
```

### Step 2: Start the Server (Dashboard)
Open Terminal 1:
```powershell
python src/server.py
```
*   This starts the Dashboard at `http://localhost:5000/dashboard`
*   It serves firmware updates.

### Step 3: Start IoT Devices
Open Terminal 2 (Simulate an ESP32):
```powershell
python src/device_simulator.py ESP32
```

Open Terminal 3 (Simulate an STM32):
```powershell
python src/device_simulator.py STM32
```

Open Terminal 4 (Simulate an ATTACKED device):
```powershell
# This device will have issues verifying hashes effectively in a real scenario, 
# or you can manually modify the code to fail checks to see the ASH score drop.
python src/device_simulator.py FAULTY_SENSOR
```

### Step 4: Interact
1.  Go to `http://localhost:5000/dashboard`.
2.  You will see your devices listed with their **ASH Score**.
3.  Use the form at the bottom to "Release New Firmware" (e.g., v2.0.0).
4.  Watch the terminals as devices detect the update, verify the hash, and install it.
5.  Watch the Dashboard as versions update and ASH scores increase (rewarding success).

## Key Features Implemented
*   **Heterogeneity:** You can spawn devices with different names/types.
*   **ASH (Anomaly-Scored Heartbeat):** The score logic is in `device_simulator.py`.
*   **TCV Pipeline:** The `check_for_updates` function implements the tiered checks (Manifest -> Hash -> Signature).
