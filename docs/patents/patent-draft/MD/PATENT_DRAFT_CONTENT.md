# PATENT APPLICATION CONTENT GENERATOR

**Project:** Secure Heterogeneous OTA Update Mechanism (LG-OTA)
**Applicants/Inventors:** Rithik Sharma, Priyankaa Devi S, Ritesh V.

---

## FORM 1: APPLICATION FOR GRANT OF PATENT

**1. Name of the Applicant(s):**
1.  Rithik Sharma
2.  Priyankaa Devi S
3.  Ritesh V

**2. Category of Applicant:**
Natural Person

**3. Title of the Invention:**
SYSTEM AND METHOD FOR SECURE, LIGHTWEIGHT OVER-THE-AIR (OTA) FIRMWARE UPDATES FOR RESOURCE-CONSTRAINED IOT DEVICES USING DISTRIBUTED VERSION CONTROL INFRASTRUCTURE

**4. Address for Service:**
[Insert your Correspondence Address / College Address here]
Email: [Insert Email]
Mobile: [Insert Mobile]

**7. Declarations:**
(i) Declaration by the inventor(s):
We, the above named inventor(s) are the true & first inventor(s) for this invention and declare that the applicant(s) herein is our assignee or legal representative.
(iii) Declaration by the applicant(s):
We, the applicant(s) hereby declare that we are in possession of the above mentioned invention.

---

## FORM 2: PROVISIONAL/COMPLETE SPECIFICATION

**1. TITLE OF THE INVENTION**
SYSTEM AND METHOD FOR SECURE, LIGHTWEIGHT OVER-THE-AIR (OTA) FIRMWARE UPDATES FOR RESOURCE-CONSTRAINED IOT DEVICES USING DISTRIBUTED VERSION CONTROL INFRASTRUCTURE

**2. PREAMBLE TO THE DESCRIPTION**
The following specification particularly describes the invention and the manner in which it is to be performed.

**3. DESCRIPTION**

**Field of Invention**
The present invention relates generally to the field of Internet of Things (IoT) security and embedded systems. More specifically, it relates to a system and method for securely delivering Over-The-Air (OTA) firmware updates to resource-constrained microcontrollers (e.g., 8-bit or 32-bit MCUs with limited RAM) without requiring dedicated cloud infrastructure, utilizing a novel tiered verification process and behavioral anomaly detection.

**Background of the Invention**
The rapid proliferation of Internet of Things (IoT) devices has created a significant security challenge: how to update firmware on low-cost devices after deployment. Existing solutions suffer from three primary deficiencies:
1.  **Economic Viability:** Commercial OTA services charge per-device or per-message fees, rendering them financially unviable for low-margin sensors.
2.  **Resource Constraints:** Standard security protocols (such as RSA-4096 signature verification) require substantial Random Access Memory (RAM), often exceeding 64KB, which is unavailable on cost-effective microcontrollers like the ESP8266, AVR, or low-end STM32 series.
3.  **Workflow Disconnect:** There is often no direct cryptographic linkage between the source code version control system (e.g., Git) and the deployed binary, leading to version mismatches and potential rollback vulnerabilities.

Conventionally, securing these updates requires either lifting the hardware specifications (increasing cost) or compromising on security (using weak or no encryption). There is a need for a system that provides defense-grade security on minimal hardware without recurring infrastructure costs.

**Objects of the Invention**
The primary object of the present invention is to provide a secure OTA mechanism that operates effectively on devices with as little as 2KB of available RAM.
Another object is to eliminate infrastructure costs by utilizing public Version Control System (VCS) release APIs (e.g., GitHub Releases) as the distribution backend.
A further object is to implement a "Tiered Crypto Verification" (TCV) algorithm that filters malicious updates using low-cost checks before attempting computationally expensive cryptographic verification.
Yet another object is to introduce an "Anomaly-Scored Heartbeat" (ASH) mechanism that allows a device to self-quarantine based on a localized health score derived from update behavior.

**Summary of the Invention**
The present invention discloses a "Lightweight GitHub-Integrated Over-The-Air" (LG-OTA) framework. The system comprises a cloud-based continuous integration pipeline that automatically builds and signs firmware using Ed25519 cryptography upon the creation of a version tag. The constrained IoT device polls the version control repository directly.

The device implements a novel 5-stage verification pipeline:
1.  **Connectivity & Health Check:** Verifies the device's internal "Anomaly Score" is above a safety threshold.
2.  **Manifest Integrity:** Validates a lightweight JSON metadata file for structure and limits.
3.  **Semantic Version Gating (SVG):** Software-based logic to prevent rollback attacks (downgrades) without dedicated hardware counters.
4.  **Streamed Hashing:** Verifies the integrity of the binary in small chunks during download to prevent RAM overflow.
5.  **Cryptographic Verification:** Verifies the Ed25519 signature of the manifest against a public key burned into the device.

If any stage fails, the device degrades its "ASH" score. If the score drops below a critical threshold (e.g., 40/100), the device enters a self-quarantine mode to prevent battery exhaustion attacks.

**Detailed Description of the Invention**
The invention will now be described with reference to its core algorithms and architecture.

*Architecture:*
The system removes the intermediate application server. The IoT device acts as a client directly querying the API of a version control host (e.g., GitHub). The "Release" entity in the VCS serves as the rigid container for the firmware binary and a "Manifest" file.

*Manifest Structure:*
A JSON document containing: `{ version, sha256_hash, file_size, min_hardware_revision, ed25519_signature }`. This file is downloaded first. Its small size allows the device to parse and validate metadata before committing energy to download the full binary.

*Algorithm 1: Tiered Crypto Verification (TCV)*
To solve the RAM constraint, the verification is split into stages of increasing computational cost:
-   **Stage 1 (Network/State):** The device checks its current Anomaly Score. Cost: near zero.
-   **Stage 2 (Metadata):** The manifest is parsed. If the version is not an upgrade (checked via SVG), the process aborts. Cost: ~100 bytes RAM.
-   **Stage 3 (Streaming Integrity):** The binary is downloaded in 512-byte chunks. A SHA-256 context is updated incrementally. The full file is never loaded into RAM. Cost: ~200 bytes RAM.
-   **Stage 4 (Signature):** Only valid, hash-verified, version-correct manifests are passed to the Ed25519 verify function. This reduces the attack surface for Denial-of-Service (DoS) attacks targeting the heavy crypto functions.

*Algorithm 2: Anomaly-Scored Heartbeat (ASH)*
The device maintains a persistent integer (0-100) representing its "Health".
-   Successful update: +10 points.
-   Network error: -1 point.
-   Hash mismatch: -20 points (Potential MITM or corruption).
-   Signature failure: -30 points (Active tampering attempt).
If the score falls below a "Quarantine Threshold" (e.g., 40), the device stops polling for updates for a backoff period, protecting its battery life from infinite loop attacks.

*Algorithm 3: Semantic Version Gating (SVG)*
The device parses the semantic version string (Major.Minor.Patch) and enforces monotonic progression. It rejects any update where the remote version is mathematically less than or equal to the current version, thereby preventing rollback attacks where an attacker tries to reinstall vulnerable old firmware.

**4. CLAIMS**
1.  A method for performing secure Over-The-Air (OTA) firmware updates on resource-constrained microcontrollers, characterized by a Tiered Crypto Verification (TCV) pipeline that validates version semantics and file integrity prior to executing cryptographic signature verification.
2.  The method of claim 1, wherein the update infrastructure utilizes a public Version Control System (VCS) releases API as the sole distribution backend.
3.  A system for device self-protection comprising an "Anomaly-Scored Heartbeat" (ASH) mechanism, wherein the device autonomously modifies a stored health score based on the outcome of update attempts and enters a quarantine state if said score falls below a defined threshold.
4.  The method of claim 1, utilizing Ed25519 digital signatures and SHA-256 hashing performed in a streaming manner to minimize Random Access Memory (RAM) usage.

**5. DATE AND SIGNATURE**
Dated this [Date] day of [Month], 2026.

(Signature)
Rithik Sharma
(Applicant)

---

## FORM 5: DECLARATION AS TO INVENTORSHIP

**1. Name of the Applicant(s):**
Rithik Sharma, Priyankaa Devi S, Ritesh V.

**2. Declaration:**
We hereby declare that the true and first inventor(s) of the invention disclosed in the complete specification filed in pursuance of the application numbered [Leave Blank for Now] dated [Date] is/are:

**3. Name, Address and Nationality of Inventor(s):**
1.  **Name:** Rithik Sharma
    **Nationality:** Indian
    **Address:** [Your Address]
2.  **Name:** Priyankaa Devi S
    **Nationality:** Indian
    **Address:** [Address]
3.  **Name:** Ritesh V
    **Nationality:** Indian
    **Address:** [Address]

**4. Date and Signature:**
Dated this [Date] day of [Month], 2026.

(Signatures of all inventors)

---

## FORM 3: STATEMENT AND UNDERTAKING

**1. Name of the Applicant(s):**
Rithik Sharma, Priyankaa Devi S, Ritesh V.

**2. Application Number:** [Leave Blank]

**3. Undertaking:**
We who have made this application No. [Leave Blank] dated [Date] alone/jointly with [None] hereby declare that we have not made any application for the same/substantially the same invention outside India.

**4. Date and Signature:**
Dated this [Date] day of [Month], 2026.

(Signature of Applicant)

---

## FORM 9: REQUEST FOR PUBLICATION

**1. Name of the Applicant(s):** Rithik Sharma, Priyankaa Devi S, Ritesh V.
**2. To the Controller of Patents:** We hereby request for early publication of our application for patent.

**Date and Signature:**
(Signature)

---

## FORM 18: REQUEST FOR EXAMINATION

**1. Name of the Applicant(s):** Rithik Sharma, Priyankaa Devi S, Ritesh V.
**2. Statement:** We hereby request that our application for patent no. [Leave Blank] dated [Date] be examined under sections 12 and 13 of the Act.

**Date and Signature:**
(Signature)
