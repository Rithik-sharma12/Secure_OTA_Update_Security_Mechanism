# Secure OTA (Over-The-Air) Update Framework for IoT Devices with GitHub-Integrated Version Control

**Project Report**

---

## 1. Introduction

### Abstraction
We are putting chips in everything now—from smart locks to industrial sensors—but keeping them secure after they leave the factory is turning into a genuine headache. You need remote updates (OTA) to patch bugs, obviously. The problem is, most of the "standard" ways to do this are either absurdly expensive per device or require computing power that a tiny microcontroller just doesn't have. Existing solutions often feel like trying to run Windows on a calculator; they demand heavy cryptography like RSA-4096 that eats up memory these little chips can't spare. Plus, there’s this weird disconnect where your code lives in Git, but your updates live in some totally separate database basically inviting human error. 

This project is our attempt to fix that mess. We call it **LG-OTA (Lightweight GitHub-Integrated OTA)**. The idea is pretty simple: why pay for servers when GitHub is already free and global? We’re using GitHub Releases as our backend and swapping out the heavy crypto for Ed25519, which is strictly lighter where it counts but arguably just as secure. It keeps the whole pipeline connected directly to your version control tags, so you aren't manually dragging files around.

### Scope
We aren't trying to solve OTA for full-blown computers or smartphones here. The focus is strictly on the constrained stuff—the devices that have maybe 2 KB of RAM left after running their actual code. Think ESP8266, ATmega328P, or the smaller STM32s. The framework we built covers a few key areas:
*   **Infrastructure:** Ditching paid clouds to use GitHub's public API.
*   **Safety Net:** A 5-layer verification setup, including this "Anomaly-Scored Heartbeat" idea we came up with to track device health.
*   **Workflow:** Making sure a Git tag actually equals a firmware version.
*   **Constraints:** Designing everything to run on hardware that would struggle to load a modern webpage.

---

## 2. Literature Review

Looking through the recent research, it’s clear we aren't the only ones worried about this. There’s been a lot of work on secure OTA, but honestly, most of it hits the same wall: it works in a lab, but it’s too heavy or expensive for the real world.

For instance, **Formanek (2025)** put together a really solid architecture for ESP32s that handled multiple protocols well. It reduced lag, sure, but it didn't really solve the "who pays for the server" problem, and it felt a bit locked into the ESP ecosystem. Then you have **Sanchez-Gomez (2021)**, who went the blockchain route with Hyperledger and IPFS. It’s an incredibly secure design, theoretically. But trying to run a blockchain client on an 8-bit microcontroller? That’s a tough sell. It’s just too complex.

**Amirkhanova (2026)** had a practical approach using AES-GCM for encrypted MQTT data. It’s fast and secure. The issue there is mostly about management—how do you automate that for ten thousand devices without losing your mind? **Peter (2021)** tried to align everything with IETF standards (SUIT), which is the "correct" way to do it, but the paper was a bit light on how you actually build it for production. 

On the crypto side, **Ukpebor (2018)** and **Yavuz (2023)** have shown that lightweight algorithms (like KATAN32 or LiteQSign) can be drastically more efficient than the standards we use today. Yavuz showed energy savings of nearly 70x, which is wild. But again, these are mostly isolated benchmarks rather than full system deployments.

**The Gap:** It feels like everyone is essentially picking two out of three: Security, Low Cost, or Simplicity. Most existing solutions either assume you have an AWS budget, assume you have a powerful processor, or they ignore how messy version control gets in real life. We are trying to hit all three.

---

## 3. Analysis

### Problem Statement
When you strip it down, secure updates effectively fail for cheap devices because of three things:
1.  **The "Cloud Tax":** Services like AWS IoT or Azure Device Update differ, but they generally charge you per device or per message. That’s fine for a $1000 smart fridge, but for a $5 sensor? It kills the margins.
2.  **Resource Hoarding:** You have standard security protocols asking for RSA signatures. Verifying those can take 64 KB of RAM. If your entire chip only has 32 KB, you’re dead in the water.
3.  **The "Copy-Paste" Gap:** There is often no hard link between "v1.0" in your code repository and the binary file sitting on your update server. Someone has to manually upload it. That’s where bugs happen.

### Existing System
*   **Cloud OTA:** Good but expensive.
*   **Crypto:** Usually RSA-2048/4096. It’s the industry standard, but it’s heavy.
*   **Rollback:** Often relies on specific hardware counters, which cheap chips might not even have.

### Proposed System (LG-OTA)
*   **Infrastructure:** GitHub Releases. It’s free, fast, and everywhere.
*   **Crypto:** Ed25519. It uses tiny 32-byte keys and simpler math, so verification takes about 1.5 KB of RAM.
*   **Workflow:** We let CI/CD do the work. You tag a release, and the firmware gets built and signed automatically.
*   **Defense:** We added a real-time check called "Anomaly-Scored Heartbeat" (ASH) to catch weird behavior before it bricks the device.

### System Analysis
*   **Feasibility:** Since we got the RAM requirement down to ~2 KB, this should technically work on almost anything that can talk to the internet.
*   **Operation:**
    1.  Device wakes up, asks GitHub "What's the latest tag?"
    2.  If there's a new version, it checks if it's actually an upgrade (SVG).
    3.  Downloads a tiny text file (Manifest) first to check integrity.
    4.  Streams the binary in small chunks (so we don't blow up the RAM).
    5.  Verifies the signature.
    6.  Installs and—this is key—tests itself before committing.

---

## 4. Design

### Architecture
We basically cut out the middleman. Instead of a custom server sitting between the developer and the device, the device just talks straight to the repo.

**The Pieces:**
1.  **The Developer:** Pushes code to GitHub. A script (GitHub Actions) kicks in, builds the binary, signs it with a private key that never leaves the secure environment, and posts it as a Release.
2.  **GitHub:** Acts as our free, high-performance file server.
3.  **The Device:** It’s dumb but careful. It polls for updates, verifies everything five different ways, and manages its own health score.

### Manifest Design (`manifest.json`)
We use a simple JSON file to tell the device what to expect. It looks something like this:
```json
{
    "version": "2.0.0",
    "sha256": "a1b2c3d... (the file hash)",
    "size": 524288,
    "min_hw_rev": "1.0",
    "signature": "..." // This is the proof that *we* sent it
}
```

---

## 5. Implementation

### New Algorithm: LG-OTA
The core engine here is what we call **Tiered Crypto Verification (TCV)**. The logic is: don't do the hard math unless you have to.

#### 5-Stage Verification Pipeline
1.  **Connectivity & Rate Check:** Detailed check on internet connection and internal "health score." If the device has been acting weird (score < 40), it quarantines itself and refuses to update. Safer to stay on old firmware than risk a brick.
2.  **Manifest Check:** Grab the JSON. Does it have all the fields? Does the version make sense?
3.  **Stream & Hash:** Download the binary in tiny 512-byte chunks. We calculate the hash as we go. If the final hash doesn't match the manifest, delete everything immediately.
4.  **The Signature:** This is the big gate. We verify the Ed25519 signature of the manifest. This proves that the hash we just checked actually came from us, not a hacker.
5.  **Safe Install:** Flash the update to a secondary partition. Reboot. Run a self-test. If the WiFi fails or the sensor doesn't respond, we automatically roll back to the old version.

#### Anomaly-Scored Heartbeat (ASH)
This is probably my favorite part. It’s a health score (0-100) that lives on the device.
*   **Start:** 100.
*   **Penalties:** If a hash mismatches, dock 20 points. If a signature fails, that's huge—dock 30 points.
*   **Recovery:** A successful update earns you 10 points back.
*   **The Point:** If a device is under attack or failing repeatedly, the score drops until it "locks down," preventing a boot loop or a brute-force attack.

#### How It Compares

| Parameter | The Big Guys (AWS/Azure) | Us (LG-OTA) |
| :--- | :--- | :--- |
| **Cost** | You pay per device/message | **$0** (Thanks, GitHub) |
| **RAM Needed** | 64 KB+ | **~2 KB** |
| **Crypto** | RSA (Old reliable, but heavy) | **Ed25519** (Modern, fast, light) |

### Code Implementation Concepts
We wrote the device side in C++ (standard for Arduino/ESP), keeping dependencies minimal. For testing, since we didn't want to spam GitHub's API while debugging, we wrote a little Python Flask server (`server.py`) that pretends to be GitHub. It serves up the manifest and binaries just like the real API would.

---

## 6. Conclusion

So, did it work? I think so. The **LG-OTA Framework** basically proves that you don't need a massive budget to secure a $2 microchip. By offloading the storage to GitHub and switching to Ed25519, we managed to build something that fits on an 8-bit chip but still has modern security features like anti-rollback and signature verification. It bridges that gap between "secure but expensive" and "cheap but vulnerable." Is it perfect? No—GitHub has rate limits, and you need internet access—but for the vast majority of cheap IoT deployments, it’s a massive step up.

### References
1.  Formanek, L. (2025). *Advanced System for Remote Updates on ESP32-Based Devices*.
2.  Sanchez-Gomez, J. (2021). *Holistic IoT Architecture for Secure Lightweight Communication*.
3.  Amirkhanova, G. (2026). *A Lightweight, End-to-End Encrypted Data Pipeline for IIoT*.
4.  Peter, C. S. (2021). *iOTA: An Approach to Secure Over-The-Air Updates*.
5.  NIST & OWASP IoT Security Guidelines.
6.  *ESP32 OTA Firmware Update with GitHub*. Available: https://iotbhai.io/esp32-ota-firmware-update-github/
