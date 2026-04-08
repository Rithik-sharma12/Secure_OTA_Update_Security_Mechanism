# Poster Content: Secure Over-The-Air Update Framework for IoT

## 1. Project Title
**Secure Heterogeneous OTA Update Mechanism**

## 2. Problem Statement
The core issue we're tackling is that securing cheap IoT devices is disproportionately expensive and difficult. Most standard security protocols require heavy processing power and memory (often 64KB+ RAM) that small microcontrollers simply don't have. On top of that, maintaining a dedicated update server costs money that kills the margins for low-cost sensors. There is also a disconnect in the workflow—developers tag code in version control, but then have to manually upload binaries to a separate server, which just invites human error and security gaps.

## 3. Objectives
*   To enable secure digital signatures on hardware with extremely limited memory (even devices with just 2KB of free RAM).
*   To eliminate the need for paid cloud infrastructure by repurposing public repositories as the update backend.
*   To create a verification pipeline that filters out bad updates efficiently before running energy-intensive cryptography.
*   To implement a mechanism that prevents attackers from downgrading devices to older, vulnerable firmware versions.
*   To give devices a way to self-monitor for suspicious update behavior and quarantine themselves if necessary.

## 4. Scope
*   **Target Hardware:** Low-power, 8-bit to 32-bit microcontrollers (like the ESP8266 or basic ARM implementations).
*   **Focus:** Authenticity and integrity of the firmware update process.
*   **Environment:** Serverless deployments where the code repository acts as the single source of truth.
*   **Exclusion:** We aren't encrypting the firmware payload itself, focusing instead on ensuring the code hasn't been tampered with.

## 5. Existing System & Literature Review
Looking at current research, most solutions seem to pick one extreme. Some, like the standard cloud IoT services, offer great security but come with high recurring costs and heavy compute requirements. Others try complex approaches like blockchain, which is fascinating theoretically but realistically too heavy for a simple light switch. Lightweight encryption attempts exist (like using AES-GCM), but they often lack a cohesive system for managing versions automatically. Essentially, there's a gap for something that is free to host, simple to integrate, and secure enough for the real world.

## 6. Proposed Methodology
Our approach forces the device to be smarter about how it spends its energy. Instead of just trying to verify a massive signature upfront, we use a **Multi-Stage Integrity Verification** pipeline. The device minimizes risk by running cheap checks first—like verifying the manifest structure and file size—before committing to the complex math of cryptographic signatures. We also integrated a **Behavioral Health Metric**, which is basically a credit score for the device's state; if updates keep failing or look suspicious, the score drops, and the device eventually refuses to listen to the network to protect itself.

## 7. Overall Architecture
1.  **Release Trigger:** The developer simply tags a new version in the version control system (e.g., v2.0).
2.  **Automated Signing:** A continuous integration script automatically builds the code and signs it with a secure key.
3.  **Distribution:** The signed artifacts are published to the public repository's release section.
4.  **Device Polling:** The IoT device checks this repository directly.
5.  **Validation:** The device downloads a small metadata file (manifest) first. If that looks good, it streams the firmware in small chunks, verifying the integrity as it goes.

## 8. List of Modules
1.  **Automated Release Pipeline:** Handles the building and signing of firmware when code is tagged.
2.  **Device-Side Update Agent:** The logic running on the microcontroller that manages network polling and downloading.
3.  **Cryptographic Verification Module:** Optimized low-memory implementations of Ed25519 signatures and SHA-256 hashing.
4.  **Security Policy Engine:** Manages the health score and enforces version anti-rollback rules.
5.  **Manifest Generation Utility:** Creates the signed JSON metadata that validates the firmware package.

## 9. Technology Stack
*   **Hardware Platform:** ESP32 / ESP8266 (compatible with other constrained architectures).
*   **Versioning Backend:** Public Git Repository Releases API.
*   **Core Logic:** C/C++ (optimized for embedded environments).
*   **Cryptography:** Ed25519 (for Edwards-curve digital signatures) and SHA-256 (for integrity hashing).
*   **Automation:** YAML-based Continuous Integration workflows.

## 10. Expected Outcome
We expect to demonstrate that you don't need a massive budget or powerful chips to have secure updates. The system allows a device with minimal RAM to reject malicious or corrupted firmware effectively. Crucially, it brings the infrastructure cost down to zero by leveraging existing developer tools, making secure OTA accessible for even the cheapest IoT projects.

## 11. Novelty
The real shift here is treating the **Version Control System** as the actual robust backend for the hardware, removing the need for a middleman server. Additionally, moving away from a binary "pass/fail" security check to a **heuristic scoring model** (the health metric) allows the device to detect patterns of attacks over time, rather than just reacting to a single bad packet.

## 12. Team Members & Guide
**Team Members:**
*   Rithik Sharma
*   [Name 2]
*   [Name 3]

**Guide:**
*   [Guide Name]
*   [Designation]
