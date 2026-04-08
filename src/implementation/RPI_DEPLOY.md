# Deploying SentinelOTA Monitor on Raspberry Pi Zero 2 W

Your idea is **highly relevant** and represents a standard "Edge Gateway" architecture in IoT. 
The Raspberry Pi Zero 2 W acts as the local "Master" that monitors the health (ASH Scores) of all "Slave" devices, caches firmware updates to save bandwidth, and alerts you to security threats.

## 1. Setup the Raspberry Pi

1.  **Flash OS:** Install *Raspberry Pi OS Lite* (Headless) on an SD card.
2.  **Connect Network:** Ensure the Pi is on the same Wi-Fi network as your ESP32/IoT devices.
3.  **SSH In:** Connect to your Pi: `ssh pi@raspberrypi.local`

## 2. Deploy the Monitor Code

1.  **Transfer Files:** Copy `edge_gateway.py` and `requirements.txt` to the Pi (using SCP or creating them manually).
    ```bash
    mkdir ota_gateway
    cd ota_gateway
    # (Copy files here)
    ```

2.  **Install Dependencies:**
    ```bash
    sudo apt-get update
    sudo apt-get install python3-pip
    pip3 install flask requests
    ```

3.  **Run the Gateway:**
    ```bash
    python3 edge_gateway.py
    ```
    *   The Monitor is now running at `http://<PI_IP_ADDRESS>:5000`.

## 3. Configuring Slave Devices (ESP32/STM32)

You need to tell your slave devices to report to the Pi instead of `localhost`.

1.  Open `device_simulator.py` (or your actual C/Arduino code).
2.  Change the `SERVER_URL` config:

    **Old:**
    ```python
    SERVER_URL = "http://localhost:5000"
    ```
    
    **New (Example):**
    ```python
    SERVER_URL = "http://192.168.1.100:5000"  # Replace with your Pi's actual IP
    ```
3.  Run the device code. It will now send Heartbeats to the Pi.

## 4. Why this is Relevant (Academic/Architecture Justification)

1.  **Bandwidth Optimization (Caching):**
    *   *Problem:* If you have 100 sensors, downloading the same 1MB update 100 times wastes 100MB of data.
    *   *Solution:* The Pi downloads it **once** from GitHub, and serves it 100 times locally.

2.  **Security (Local Trust Anchor):**
    *   The Pi can perform "Deep Packet Inspection" or stronger validation on the firmware before passing it to the constrained slaves.
    *   It acts as a firewall. If a device behaves badly (ASH score drops), the Pi can block it from the network completely.

3.  **Observability:**
    *   Microcontrollers don't have screens. The Pi provides a unified "Mission Control" dashboard to visualize the fleet's status.
