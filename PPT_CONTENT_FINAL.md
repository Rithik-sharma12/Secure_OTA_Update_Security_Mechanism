# Presentation Script & Slides: Secure Heterogeneous OTA Update Mechanism

**Target Audience:** Expert Mentor / Evaluation Panel**Goal:** To prove that existing OTA solutions are viable only for high-end devices, and that *this* specific implementation solves the security gap for low-end hardware.

---

## Slide 1: Title Slide

**Project Title:** Secure Heterogeneous OTA Update Mechanism**Subtitle:** Bringing Defense-Grade Security to Resource-Constrained IoT**Team Members:**

-   Rithik Sharma
-   Priyankaa Devi S 
-   Ritesh V

**Opening Hook (Speaker Notes):**"Good morning. We are here to address a critical vulnerability in the IoT ecosystem: the inability to securely update low-cost devices. We propose a mechanism that brings enterprise-grade security to the smallest microcontrollers without the enterprise-grade cost."

---

## Slide 2: The Problem Statement (The "Security Gap")

**Headline:** The "Update Paradox" in IoT**Core Issues:**

1.  **The Resource Wall:** Standard secure protocols (RSA-4096, TLS 1.3) require heavy memory (~64KB RAM). Low-cost chips (AVR, low-end ARM) often have less than 4KB total. *They are physically incapable of running standard security.*
2.  **The Economic Trap:** Cloud OTA services (AWS IoT, Azure) charge per-device. For a $5 sensor, a monthly fee destroys the business model, leading vendors to abandon updates entirely.
3.  **The "Air Gap" Utility:** Developers push code to Git, but manually upload binaries to servers. This human step is where version mismatches and unsigned binaries slip through.

**Speaker Note:** "We face a paradox: the devices that need updates the most—cheap, mass-produced sensors—are the ones that can't afford the processing power or the cloud subscription to receive them."

---

## Slide 3: Existing Systems & Their Flaws

**Current Approaches:**

1.  **Hyperscale Cloud (AWS/Azure):**
    -   *Drawback:* Requires an OS (Linux/FreeRTOS) and substantial RAM. High recurring cost.
2.  **Manual/Custom Servers:**
    -   *Drawback:* High maintenance. Single point of failure. Security relies entirely on the developer's ability to patch their own server.
3.  **Blockchain/De-Centralized:**
    -   *Drawback:* Computational overhead is massive. A verified blockchain transaction costs more energy than the device's entire battery life.

**Speaker Note:** "Existing solutions are built for smartphones and gateways, not for the billions of tiny sensors that make up the real IoT edge."

---

## Slide 4: Our Proposed Solution (The Core Idea)

**Concept:** Serverless, Git-Native OTA**The Big Idea:**Eliminate the dedicated OTA server entirely. Use the **Source Code Repository (GitHub)** as the single source of truth for both code *and* compiled firmware.

**Key Innovations:**

1.  **Zero-Infrastructure:** Leverages GitHub Releases API (Global CDN, 99.9% Uptime, Free).
2.  **CI/CD Integration:** Security is automated. A Git tag triggers the build and signing process in the cloud, not on a developer's laptop.
3.  **Heterogeneity:** Designed to work across different architectures (ESP32, STM32, AVR) using a unified manifest format.

---

## Slide 5: Implementation I - The Architecture

*(Describe the flow diagram here)***The "Push-to-Deploy" Pipeline:**

1.  **Trigger:** Developer pushes `git tag v2.0`.
2.  **Action:** GitHub Actions runner spins up.
3.  **Build & Sign:** Code is compiled. The binary is signed with a **Private Key (Ed25519)** stored in repository secrets.
4.  **Release:** `firmware.bin` and `manifest.json` are published to GitHub Releases.
5.  **Poll:** Device wakes up, checks the API, and initiates the secure download.

**Speaker Note:** "We moved the complexity *off* the device and *into* the CI/CD pipeline. The device doesn't need to be smart; it just needs to be able to verify a signature."

---

## Slide 6: Implementation II - The Algorithm (LG-OTA)

**Algorithm:** Lightweight GitHub-Integrated OTA (LG-OTA)**Mechanism: Tiered Crypto Verification (TCV)**Instead of running expensive crypto immediately, we run a gauntlet of cheap checks:

1.  **Tier 1: Connectivity & Rate Limit** (Cost: 0 RAM)
2.  **Tier 2: Manifest Integrity** (Cost: 100 bytes) - Is the JSON valid?
3.  **Tier 3: Semantic Version Gating (SVG)** (Cost: 50 bytes) - Prevents Rollback. "Is v2.0 > v1.0?"
4.  **Tier 4: Streaming Hash Check** (Cost: 32 bytes) - Verifies the file wasn't corrupted in transit.
5.  **Tier 5: Ed25519 Signature Verification** (Cost: ~1.5KB) - The final cryptographic proof.

**Impact:** 95% of attacks or errors are caught before Tier 5, saving massive amounts of energy and battery.

---

## Slide 7: Implementation III - Anomaly-Scored Heartbeat (ASH)

**Novelty:** Behavioral Security

-   **Concept:** The device maintains a local "Health Score" (0-100).
-   **Behavior:**
    -   Good Update = +10 Points
    -   Failed Hash = -20 Points
    -   Invalid Signature = -50 Points (Immediate Threat)
-   **Quarantine Mode:** If Score < 40, the device rejects *all* network packets for a set duration.

**Why it matters:** It prevents "Battery Draining Attacks" where an attacker floods a device with bad updates to exhaust its battery.

---

## Slide 8: Critical Advantage Over Existing Systems

Feature

AWS/Azure IoT

Custom Server

**Our Implementation (LG-OTA)**

**Cost**

$$$ (Monthly)

$$ (Maintenance)

**Zero (Free Tier)**

**RAM Req.**

> 64 KB

Variable

**< 2 KB**

**Security**

Transport Layer (TLS)

Application Layer

**Payload Layer (Signed Binary)**

**Rollback**

Complex Config

Often Missing

**Native Semantic Gating**

**Workflow**

Disconnected

Manual

**Git-Native (Automated)**

---

## Slide 9: Conclusion

**Summary:**We have built a framework that democratizes IoT security. By stripping away the heavy requirements of traditional OTA and replacing them with a smart, tiered verification algorithm, we allow even the cheapest devices to stay secure.

**Key Takeaway:**"Better security doesn't always need more power. It needs better architecture. Our project proves that a $2 chip can be just as secure as a $200 smartphone."

**Future Scope:**

-   Porting the TCV pipeline to RISC-V.
-   Adding "Delta Updates" to further reduce data usage.

---

**Advice for Q&A:**

-   *If asked about encryption:* "We focus on **Integrity** (signing), not **Confidentiality** (encryption), because open-source firmware is our primary use case."
-   *If asked about GitHub reliance:* "The architecture is modular; GitHub can be swapped for GitLab or any S3-compatible bucket, but GitHub offers the best zero-cost entry point."