# FORM 2

**THE PATENTS ACT 1970**(39 of 1970)**&****The Patents Rules, 2003**

## COMPLETE SPECIFICATION

(See section 10 and rule 13)

### 1. TITLE OF THE INVENTION

**SYSTEM AND METHOD FOR SECURE, LIGHTWEIGHT OVER-THE-AIR (OTA) FIRMWARE UPDATES FOR RESOURCE-CONSTRAINED IOT DEVICES USING DISTRIBUTED VERSION CONTROL INFRASTRUCTURE**

### 2. APPLICANT (1)

-   **Name:** Rithik Sharma
-   **Nationality:** Indian
-   **Address:** [Insert Address, City, State, Pin Code]

### 2. APPLICANT (2)

-   **Name:** Priyankaa Devi S
-   **Nationality:** Indian
-   **Address:** [Insert Address, City, State, Pin Code]

### 2. APPLICANT (3)

-   **Name:** Ritesh V
-   **Nationality:** Indian
-   **Address:** [Insert Address, City, State, Pin Code]

### 3. PREAMBLE TO THE DESCRIPTION

**COMPLETE**The following specification particularly describes the invention and the manner in which it is to be performed.

---

### 4. DESCRIPTION

**Field of Invention**Broadly speaking, this work sits at the intersection of IoT security and embedded systems. To be more specific, we are looking at a method for handling Over-The-Air firmware updates—OTA, as it is commonly known—for microcontrollers that are pretty severely constrained when it comes to resources. We are talking about devices like 8-bit or 32-bit MCUs that really struggle with memory. The goal here is to manage these updates without leaning on dedicated cloud infrastructure, instead relying on a tiered verification process and observing behavioral anomalies to keep things secure.

**Background of the Invention**It is fairly obvious that the explosion of Internet of Things devices has created a significant security headache. The main issue is simply: how do you update the firmware on these cheap devices once they are out in the wild? The solutions we have right now tend to fall short in a few ways. For one, there is the economic angle; commercial OTA services often charge per device or per message, which effectively kills the margin on a low-cost sensor. Then you have the resource problem. Standard security protocols, like RSA-4096 signature verification, need a substantial amount of RAM—often more than 64KB. That is just not feasible on a cost-effective microcontroller like an ESP8266 or an AVR. And finally, there is this disconnect in the workflow. You rarely see a direct cryptographic link between the source code in Git and the actual binary that gets deployed, which invites version mismatches and rollback vulnerabilities. Typically, securing these updates means you either have to pay for better hardware or you compromise on security. We arguably need a system that offers defense-grade security on minimal hardware, and ideally without the recurring costs.

**Objects of the Invention**The primary thing we are trying to achieve is a secure OTA mechanism that works effectively on devices with as little as 2KB of available RAM. Another objective is to basically eliminate the infrastructure costs by using public Version Control System release APIs—like GitHub Releases—as the distribution backend. We also want to implement what we call a "Tiered Crypto Verification" algorithm. The idea is to filter out malicious updates using cheap checks before we commit to the computationally heavy cryptography. And finally, we are introducing an "Anomaly-Scored Heartbeat" mechanism. This allows a device to essentially self-quarantine based on a health score derived from its own update behavior.

**Summary of the Invention**What we are proposing is a framework we call "Lightweight GitHub-Integrated Over-The-Air" or LG-OTA. The system basically involves a cloud-based CI pipeline that builds and signs firmware automatically when a version tag is created. The device then polls the repository directly.

The device itself runs a 5-stage verification pipeline. First, it checks its "Anomaly Score" to see if it is healthy enough to proceed; this costs practically zero RAM. Second, it validates the manifest integrity, just checking the JSON structure. Third, we use Semantic Version Gating to prevent rollbacks. Fourth, it verifies the binary integrity by hashing it in small chunks as it downloads, so we don't overflow the memory. And fifth, only then does it verify the Ed25519 signature. If any of these stages fail, the device lowers its health score. If that score drops below a critical threshold, the device enters a quarantine mode to protect itself from battery exhaustion.

**Detailed Description of the Invention**The architecture here essentially removes the intermediate application server. The IoT device acts as a client that queries the version control host directly. The "Release" entity in the VCS serves as the container for both the firmware binary and a "Manifest" file.

For the manifest, we use a JSON document containing the version, hash, size, and signature. Since this file is small, the device can parse it and validate the metadata before it spends energy downloading the full binary.

The "Tiered Crypto Verification" algorithm is really about solving the RAM constraint. We split verification into stages of increasing cost. Stage 1 checks the health score. Stage 2 looks at the metadata and checks if the version is actually an upgrade. Stage 3 handles the streaming integrity, updating the hash incrementally so the full file is never loaded into RAM. Stage 4 is the signature check. By doing it this way, only valid manifests ever reach the heavy crypto function, which reduces the attack surface for Denial-of-Service attacks.

Then there is the "Anomaly-Scored Heartbeat." The device keeps a persistent integer, from 0 to 100, representing its health. A successful update adds points, while errors or tampering attempts subtract them. If the score falls below a threshold, say 40, the device stops polling for updates for a while. It is a way for the device to protect itself.

---

### 5. CLAIMS

**I/We claim:**

1.  A method for performing secure Over-The-Air (OTA) firmware updates on resource-constrained microcontrollers, characterized by a Tiered Crypto Verification (TCV) pipeline that validates version semantics and file integrity prior to executing cryptographic signature verification.
    
2.  The method of claim 1, wherein the update infrastructure utilizes a public Version Control System (VCS) releases API as the sole distribution backend, eliminating the need for a dedicated intermediate update server.
    
3.  A system for device self-protection comprising an "Anomaly-Scored Heartbeat" (ASH) mechanism, wherein the device autonomously modifies a stored health score based on the outcome of update attempts and enters a quarantine state if said score falls below a defined threshold to prevent battery exhaustion attacks.
    
4.  The method of claim 1, utilizing Ed25519 digital signatures and SHA-256 hashing performed in a streaming manner to minimize Random Access Memory (RAM) usage, allowing secure updates on devices with less than 4KB of available RAM.
    

---

### 6. DATE AND SIGNATURE

**Dated this ..................... day of ..................... 2026**

**(Signatures)**

1.  ______________________ (Rithik Sharma)
2.  ______________________ (Priyankaa Devi S)
3.  ______________________ (Ritesh V)

---

### 7. ABSTRACT OF THE INVENTION

**SECURE HETEROGENEOUS OTA UPDATE MECHANISM: A SYSTEM AND METHOD FOR LIGHTWEIGHT FIRMWARE UPDATES ON RESOURCE-CONSTRAINED IOT DEVICES**

This invention presents a secure Over-The-Air firmware update mechanism tailored for resource-constrained IoT devices. The proposed system leverages public Version Control Systems, like GitHub Releases, as a free distribution backend. To work within strict RAM limits (often less than 2KB), the solution employs a "Tiered Crypto Verification" algorithm. This essentially validates update metadata and semantic versioning before attempting the more expensive cryptographic operations. Additionally, the system includes an "Anomaly-Scored Heartbeat" mechanism that monitors update behavior. It assigns a dynamic health score to the device, punishing deviations with score penalties that can eventually trigger a self-quarantine mode. This helps protect the device from persistent attacks or battery draining attempts, ensuring defense-grade security without the need for expensive hardware.