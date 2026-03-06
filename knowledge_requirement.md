# Comprehensive OTA (Over-The-Air) Updates for IoT Devices: Security Standards and Implementation Guide

**Document Date:** March 6, 2026
**Classification:** Technical Reference
**Scope:** Secure OTA Update Architecture, Cryptography, Standards, and Best Practices

---

## Table of Contents

1. [Secure OTA Best Practices](#1-secure-ota-best-practices)
2. [Cryptographic Requirements](#2-cryptographic-requirements)
3. [NIST IoT Security Guidelines](#3-nist-iot-security-guidelines)
4. [OWASP IoT Top 10 Vulnerabilities](#4-owasp-iot-top-10-vulnerabilities)
5. [Common OTA Frameworks and Standards](#5-common-ota-frameworks-and-standards)
6. [Code Signing and Certificate Management](#6-code-signing-and-certificate-management)
7. [Rollback Protection Mechanisms](#7-rollback-protection-mechanisms)
8. [Secure Boot and Verified Boot](#8-secure-boot-and-verified-boot)
9. [Update Distribution and Delivery Security](#9-update-distribution-and-delivery-security)
10. [Device Authentication and Authorization](#10-device-authentication-and-authorization)

---

## 1. Secure OTA Best Practices

### 1.1 Core Principles

**Confidentiality, Integrity, and Availability (CIA Triad)**
- **Confidentiality:** Encrypt update packages in transit and at rest
- **Integrity:** Implement cryptographic verification (digital signatures, MACs)
- **Availability:** Ensure redundant distribution channels and graceful degradation

### 1.2 OTA Architecture Components

#### Update Server Infrastructure
- **Geographically distributed servers** for load balancing and redundancy
- **API Gateway** with rate limiting (recommend: 100-1000 req/s per device)
- **Storage**: Encrypted storage with access controls (AES-256 for encryption keys)
- **Audit logging**: All update activities with tamper-proof logging
- **Version management**: Track all firmware versions released

#### Device-Side Components
- **Update Agent**: Responsible for download, verification, installation
- **Bootloader**: Validates firmware before execution
- **Secure storage**: Protected partition for sensitive keys
- **Recovery mechanism**: Ability to restore previous version if needed

### 1.3 Update Process Workflow

```
1. Discovery Phase
   - Device requests available updates (signed request)
   - Server responds with metadata (version, size, hashes)

2. Download Phase
   - Establish TLS 1.3+ connection (minimum TLS 1.2)
   - Download firmware package with authentication
   - Implement resumable downloads with checksum verification

3. Verification Phase
   - Verify digital signature using device's root certificate
   - Validate manifest integrity
   - Check rollback protection tokens

4. Installation Phase
   - Stage update to dedicated partition
   - Atomic commit operation
   - Minimal downtime required

5. Validation Phase
   - Boot to new firmware
   - Perform self-checks
   - Commit or rollback based on validation results
```

### 1.4 Security Best Practices

| Best Practice | Implementation | Risk Mitigated |
|---|---|---|
| **Staged Rollout** | Deploy to 1% → 5% → 25% → 100% | Widespread device failure |
| **Delta Updates** | Send only changed binary blocks | Bandwidth/storage constraints |
| **Dependency Analysis** | Track firmware compatibility | Breaking changes |
| **Canary Deployments** | Test with small device subset first | Unforeseen issues |
| **A/B Update Partitioning** | Keep previous version available | Complete bricking |
| **Update Scheduling** | Off-peak hours, user coordination | Service disruption |
| **Rollback Strategy** | Automatic rollback on failure | Stuck in broken state |
| **Forensics Capture** | Log update failures in detail | Post-incident analysis |

### 1.5 Update Metadata Requirements

**Minimum metadata fields:**
```json
{
  "version": "2.1.5",
  "releaseDate": "2026-03-06T00:00:00Z",
  "targetDevices": ["model-x", "model-y"],
  "fileSize": 2097152,
  "fileHash": "sha256_hash_of_firmware",
  "dependencies": {
    "bootloader": ">=1.0.0",
    "hardware": "rev_c"
  },
  "signatures": [
    {
      "algorithm": "RSA-SHA256",
      "keyId": "prod-signing-key-2026",
      "value": "base64_encoded_signature"
    }
  ],
  "releaseNotes": "Security fixes and performance improvements",
  "criticalityLevel": "high|medium|low",
  "estimatedDownloadTime": 300,
  "expectedDowntimeDuration": 60
}
```

---

## 2. Cryptographic Requirements

### 2.1 Asymmetric Cryptography (Code Signing)

**Algorithm Requirements:**

| Algorithm | Key Size | Use Case | Status |
|---|---|---|---|
| **RSA** | 2048-bit minimum, 4096-bit recommended | Digital signatures, firmware signing | NIST approved until 2030 |
| **ECDSA** | P-256 (secp256r1) minimum, P-384 recommended | Memory-constrained devices | NIST approved |
| **EdDSA** | Ed25519 (256-bit), Ed448 (456-bit) | High security, fast verification | NIST approved |

**Recommended:** EdDSA (Ed25519) for new deployments due to superior security and performance

### 2.2 Symmetric Cryptography

**Encryption Standards:**

| Purpose | Algorithm | Mode | Key Size | IV/Nonce |
|---|---|---|---|---|
| **Firmware Encryption** | AES | GCM | 256-bit | 128-bit random |
| **Session Encryption** | AES | GCM | 256-bit | 128-bit random per message |
| **Key Derivation** | PBKDF2/Argon2 | - | 256-bit output | 128-bit random salt |

**Implementation Details:**
- **AES-256-GCM:** Provides authenticated encryption with integrity
- **Key derivation:** Use PBKDF2 with ≥100,000 iterations or Argon2id with memory=65536

### 2.3 Hash Functions

| Purpose | Algorithm | Output Size | Notes |
|---|---|---|---|
| **Firmware Integrity** | SHA-256 | 256-bit | NIST FIPS 180-4 compliant |
| **Rollback Counter Hash** | SHA-256 | 256-bit | For version verification |
| **Update Manifest Hash** | SHA-256 | 256-bit | Recommended minimum |
| **File Tree Hash** | SHA-256 | 256-bit | For delta update verification |

**Deprecated:** MD5, SHA-1 (use only for legacy systems, not new deployments)

### 2.4 Elliptic Curve Parameters

**NIST Approved Curves:**
```
P-256 (secp256r1):
  - Prime field: 2^256 - 2^224 + 2^192 + 2^128 - 1
  - Security strength: ~128 bits
  - Suitable for IoT devices

P-384 (secp384r1):
  - Prime field: 2^384 - 2^128 - 2^96 + 2^32 - 1
  - Security strength: ~192 bits
  - For high-security devices

Curve25519/Ed25519:
  - Montgomery curve form
  - 128-bit security strength
  - Faster than P-256 in software
  - Recommended for IoT
```

### 2.5 Key Derivation Functions (KDF)

**PBKDF2 Parameters:**
```
PBKDF2-HMAC-SHA256:
  - Iterations: Minimum 100,000 (prefer 250,000+)
  - Salt: 128-bit (16 bytes) random, unique per key
  - Output length: 256 bits (32 bytes)
  - Time: ~100-200ms on IoT device
```

**Argon2 Parameters (Modern Alternative):**
```
Argon2id:
  - Memory: 65,536 KiB (64 MiB) for desktop, 16-32 MiB for IoT
  - Iterations/Time Cost: 3
  - Parallelism: 4 threads
  - Salt: 128-bit (16 bytes) random
  - Output length: 256 bits (32 bytes)
```

### 2.6 Perfect Forward Secrecy (PFS)

**TLS Configuration:**
```
Minimum: TLS 1.3 (preferred) or TLS 1.2 with PFS ciphers

Recommended Cipher Suites:
  - TLS 1.3: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
  - TLS 1.2: ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384

Avoid:
  - Static RSA key exchange (no PFS)
  - NULL ciphers
  - Export-grade ciphers
  - RC4, DES
```

### 2.7 Cryptographic Key Storage

**Device Key Storage Requirements:**
- **Hardware Security Module (HSM):** Preferred for production
- **Trusted Execution Environment (TEE):** ARM TrustZone, Intel SGX
- **Secure Element (SE):** CC EAL 5+ certified
- **Encrypted Flash:** AES-256 encryption with key derived from device secret

**Key Hierarchy:**
```
Root Key (burned in device bootloader)
    ↓
Device Master Key (stored in TEE/HSM)
    ├── Signing Key (firmware signing verification)
    ├── Update Encryption Key (firmware decryption)
    └── Authentication Key (device-to-server)
```

---

## 3. NIST IoT Security Guidelines

### 3.1 NIST Cybersecurity Framework (CSF)

**Framework Structure:** Identify → Protect → Detect → Respond → Recover

**Application to OTA:**

#### Identify (Asset Management)
- Maintain inventory of all firmware versions deployed
- Document device capabilities and constraints
- Identify critical devices requiring faster security patching

#### Protect (Technical Controls)
- Implement end-to-end encryption (TLS 1.3)
- Deploy access controls on update servers
- Use digital signatures for all firmware
- Implement secure boot

#### Detect (Monitoring)
- Monitor update success/failure rates
- Alert on suspicious download patterns
- Track unauthorized update attempts
- Log all cryptographic operations

#### Respond (Incident Management)
- Pre-staged rollback procedures
- Communication plan for security updates
- Device quarantine capabilities
- Forensic data collection

#### Recover (Resilience)
- Maintain backup firmware repositories
- Practice regular rollback procedures
- Ensure recovery procedures are documented and tested

### 3.2 NIST SP 800-53 Security Controls (Relevant to OTA)

| Control | Requirements | Implementation |
|---|---|---|
| **SI-3 (Malware Protection)** | Detect and remove malicious code | Firmware integrity verification |
| **SI-7 (Information System Monitoring)** | Monitor for unauthorized modifications | File integrity checking with AIDE/TRIPWIRE |
| **CM-3 (Configuration Control)** | Document and approve changes | Change management for firmware versions |
| **CM-5 (Access Restrictions)** | Enforce least privilege | Role-based access to update servers |
| **SC-7 (Boundary Protection)** | Protect network boundaries | Firewall rules for update traffic |
| **SI-2 (Flaw Remediation)** | Timely patching process | Staged update rollout mechanism |

### 3.3 NIST SP 800-82 Guide to Industrial Control Systems Security

**Applicable to IoT/ICS Devices:**

1. **Defense in Depth**
   - Multiple layers of security controls
   - No single point of failure
   - Layered verification (signature + manifest + rollback check)

2. **Least Privilege**
   - Update agent runs with minimal permissions
   - Service accounts with restricted capabilities
   - Hardware-enforced memory protection

3. **Secure Configuration**
   - Hardened default configurations
   - Minimal enabled services
   - Configuration templates for deployment

4. **Continuous Monitoring**
   - Real-time update status tracking
   - Anomaly detection in download patterns
   - Device communication analysis

### 3.4 NIST Post-Quantum Cryptography

**Timeline for Implementation:**
- 2024-2025: Transition planning begins
- 2025-2026: Pilot implementations
- 2026-2030: Full deployment target

**Recommended PQC Algorithms (NIST SP 800-338):**

```
Digital Signatures:
  - ML-DSA (Lattice-based)
  - SLH-DSA (Hash-based)
  - CRYSTALS-Kyber (Key Encapsulation)

Key Encapsulation:
  - ML-KEM (Lattice-based)
  - Classic McEliece (Code-based)

Hybrid Approach (Current Recommendation):
  - Pair classical ECC with PQC for interim security
  - Example: ECDSA + ML-DSA dual signing
```

---

## 4. OWASP IoT Top 10 Vulnerabilities

### 4.1 Mapping OWASP Top 10 to OTA Updates

| Rank | Vulnerability | OTA Impact | Mitigation |
|---|---|---|---|
| **I1** | Weak Passwords/Authentication | Unauthorized update access | Device certificate pinning, mutual TLS |
| **I2** | Insecure Network Services | Man-in-the-middle attacks | TLS 1.3, HSTS headers |
| **I3** | Insecure Firmware | Compromised updates | Code signing, secure boot |
| **I4** | Lack of Transport Encryption | Data interception | End-to-end encryption (AES-256) |
| **I5** | Use of Outdated Components | Known vulnerabilities | Regular dependency updates |
| **I6** | Inadequate Security Logging | Undetected breaches | Audit trails, tamper-proof logs |
| **I7** | Weak Cryptography | Cryptanalytic attacks | NIST-approved algorithms |
| **I8** | Lack of Device Management | Unpatched devices | Comprehensive OTA platform |
| **I9** | Insecure Default Settings | Exploitation | Secure defaults, hardening |
| **I10** | Inadequate Physical Security | Hardware tampering | TPM integration, physical seals |

### 4.2 OTA-Specific Attack Scenarios and Defenses

#### Attack: Firmware Injection
```
Attacker Goal: Replace firmware with malicious version
Attack Vector: MITM attack on update download
Defense Mechanisms:
  1. Digital signature verification (RSA-4096 or Ed25519)
  2. TLS certificate pinning
  3. Manifest integrity checking
  4. Cryptographic freshness tokens (timestamp + nonce)
```

#### Attack: Rollback Attack
```
Attacker Goal: Force device to use known-vulnerable firmware
Attack Vector: Replay older firmware version
Defense Mechanisms:
  1. Monotonic counter (hardware-backed)
  2. Secure timestamp (authenticated)
  3. Version number in secure storage
  4. Anti-rollback token signed by server
```

#### Attack: Firmware Extraction
```
Attacker Goal: Steal proprietary firmware code
Attack Vector: Extract from device or update stream
Defense Mechanisms:
  1. Firmware encryption with AES-256-GCM
  2. Confidential computing (SGX, TrustZone)
  3. Obfuscation/code protection
  4. DRM (Digital Rights Management) for sensitive assets
```

#### Attack: Update Server Compromise
```
Attacker Goal: Distribute malicious updates
Attack Vector: Compromise update server backend
Defense Mechanisms:
  1. Code signing with offline root key
  2. Update signing delegation to HSM
  3. Multiple approval steps (approval chain)
  4. Automated quality gates before release
```

#### Attack: Replay Attacks
```
Attacker Goal: Replay valid update packets
Attack Vector: Packet capture and replay
Defense Mechanisms:
  1. Session tokens with expiration
  2. Sequence numbers/nonces in communications
  3. Authenticated encryption (AES-GCM)
  4. Request-response correlation
```

### 4.3 CVSS Scoring for OTA Vulnerabilities

**Example: Unsigned Firmware Update**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL
  - Attack Vector: Network (AV:N)
  - Attack Complexity: Low (AC:L)
  - Privileges Required: None (PR:N)
  - User Interaction: None (UI:N)
  - Confidentiality Impact: High (C:H)
  - Integrity Impact: High (I:H)
  - Availability Impact: High (A:H)
```

---

## 5. Common OTA Frameworks and Standards

### 5.1 Google OTA Update System (Android/ChromeOS)

**Framework Architecture:**
```
Update Server
    ↓
Client API
    ├── Metadata Request (device state, build version)
    ├── Update Check Response (manifest, delta data)
    └── Verification & Installation
```

**Key Components:**

1. **Delta Encoding**
   - Generates diff between old and new firmware
   - Reduces bandwidth by 50-90% for incremental updates
   - Tools: `bsdiff`, `courgette`

2. **Metadata Format**
   ```xml
   <response server="productionserver">
     <app appid="{appid}">
       <updatecheck status="ok">
         <manifest version="1.0">
           <packages>
             <package name="update.bin"
                      hash="sha256:..."
                      size="2097152"
                      required="true"/>
           </packages>
           <actions>
             <action event="postinstall"
                     sha256="{...}"
                     MetadataSignatureRsaPublicKey="{...}"/>
           </actions>
         </manifest>
       </updatecheck>
     </app>
   </response>
   ```

3. **Security Features**
   - RSA-2048 minimum for signatures (Chrome uses RSA-4096)
   - Staged rollout: 1% → 5% → 10% → 50% → 100%
   - Automatic rollback on failed verification

4. **Payload Signing**
   ```
   Hash: SHA-256(firmware)
   Signature: RSA-4096-Sign(Hash, private_key)
   Verification: RSA-4096-Verify(Signature, Hash, public_key)
   ```

### 5.2 AWS IoT Device Management (Fleet Provisioning & Jobs)

**Architecture:**

```
AWS IoT Core
    ├── Device Advisor (Testing & Validation)
    ├── Job Service (Update Distribution)
    └── Device Shadow (State Management)

Update Flow:
  1. Create Job on AWS Console
  2. IoT Jobs Service queues update for devices
  3. Devices poll for jobs via MQTT/HTTPS
  4. Download firmware from S3 (pre-signed URLs)
  5. Report execution status back to AWS
```

**Key Components:**

1. **Manifest Structure**
   ```json
   {
     "awsIotJobId": "job-123456",
     "targets": ["arn:aws:iot:region:account:thing/device-id"],
     "targetSelection": "SNAPSHOT|CONTINUOUS",
     "documentParameters": {
       "action": "download",
       "url": "https://s3.amazonaws.com/bucket/firmware.bin",
       "sha256": "...",
       "checksum": "..."
     },
     "abortConfig": {
       "criteriaList": [
         {
           "failureType": "FAILED|REJECTED|TIMED_OUT",
           "action": "CANCEL",
           "thresholdPercentage": 10.0
         }
       ]
     }
   }
   ```

2. **Security Model**
   - Device certificates with AWS IoT
   - Pre-signed S3 URLs (limited lifetime, ~15 minutes)
   - TLS 1.2/1.3 for all connections
   - Mutual TLS authentication

3. **Integration with KMS**
   ```
   AWS KMS encrypts firmware at rest
   Encryption Key: Customer Managed Keys (CMK)
   S3 Server-Side Encryption: AES-256 or KMS
   In-Transit: TLS 1.3 with KMS encryption
   ```

4. **Job Execution Flow**
   ```
   Status Transitions:
   QUEUED → IN_PROGRESS → SUCCEEDED/FAILED/REJECTED

   Device Reports:
   - queued_timestamp
   - started_timestamp
   - completed_timestamp
   - result: {"code": 0/1, "message": "..."}
   - statusDetails: {"additionalDetails": "..."}
   ```

### 5.3 Microsoft Azure Device Update Service

**Architecture:**

```
Azure Update Service
    ├── Content Management
    ├── Distribution (Delivery Optimization/OU)
    └── Compliance Tracking

Update Handler:
  1. Metadata fetch (manifest)
  2. File download (from CDN or peer-to-peer)
  3. Handler execution (update script)
  4. Result reporting
```

**Key Components:**

1. **Update Manifest Structure**
   ```json
   {
     "updateId": {
       "provider": "Contoso",
       "name": "FirmwareV2",
       "version": "1.0"
     },
     "compatibility": [
       {
         "deviceProperties": {
           "manufacturer": "Contoso",
           "model": "IoTDevice"
         }
       }
     ],
     "instructions": {
       "steps": [
         {
           "type": "inline",
           "handler": "microsoft/swupdate:1",
           "files": ["firmware.swu"],
           "handlerProperties": {
             "installedCriteria": "1.0"
           }
         }
       ]
     },
     "files": {
       "firmware.swu": {
         "fileName": "firmware.swu",
         "sizeInBytes": 2097152,
         "hashes": {
           "sha256": "..."
         }
       }
     }
   }
   ```

2. **Delivery Optimization**
   - Peer-to-peer delivery (reduce server load)
   - Bandwidth throttling capabilities
   - Network-aware download (LTE vs WiFi)

3. **Update Handlers**
   ```
   - SWUpdate: Linux-based update manager
   - UEFI Firmware Update Handler
   - Apt package handler (Debian/Ubuntu)
   - Custom handlers via SDK
   ```

4. **Security Features**
   - Installed Criteria: Version check for idempotency
   - Signature verification at Azure level
   - Device authentication via certificates/tokens

### 5.4 IETF SUIT (Software Updates for Internet of Things)

**RFC 9019 - Software Updates for Internet of Things**

**Key Features:**

1. **Manifest Structure**
   ```
   SUIT Manifest:
     - manifest-version
     - manifest-sequence-number (rollback prevention)
     - common-parameters
       - dependencies
       - relative-offset
       - components
     - authentication-wrapper
     - signed-structure
       - condition
       - instruction
   ```

2. **Authentication**
   ```
   CBOR Object Signing and Encryption (COSE):
     - COSE_Sign1: Single signer (Ed25519 recommended)
     - Envelope protection: HMAC-based integrity
   ```

3. **Manifest Example**
   ```
   Manifest {
     version: 1,
     sequence-number: 42,
     common: {
       components: [
         {
           component-identifier: "main-firmware"
         }
       ]
     },
     install-sequence: [
       {
         condition: "image-not-match",
         condition-parameters: {...},
         instruction: "fetch",
         instruction-parameters: {...}
       },
       {
         condition: "image-match",
         instruction: "install"
       }
     ]
   }
   ```

4. **Advantages Over Alternatives**
   - Minimal payload overhead
   - Designed for constrained IoT devices
   - Language-agnostic (CBOR-based)
   - Strong cryptographic foundations

### 5.5 Open Source Alternatives

#### Linux Secure Boot (UEFI/Shim)
```
Signed by Microsoft Key Store
    ↓
Shim (EFI application)
    ↓
GRUB2 Bootloader
    ↓
Linux Kernel (signed)
    ↓
Root filesystem (verified with dm-verity)
```

#### U-Boot (Embedded Linux)
```
SPL (Secondary Program Loader) - Minimal
    ↓
U-Boot (Full bootloader) - Signed FIT image
    ↓
Kernel + Initrd - Signed together
    ↓
Filesystem verification
```

#### RAUC (Robust Auto Update Controller)
```
Slot-Based Update System:
  - Partition A (active)
  - Partition B (staging)

Atomic installation:
  1. Write to inactive partition
  2. Verify cryptographic signature
  3. Update boot variables
  4. Reboot to new partition
  5. Post-boot verification

Features:
  - Delta updates
  - Streaming updates
  - Network handling during update
  - Custom update handlers
```

---

## 6. Code Signing and Certificate Management

### 6.1 Code Signing Process

**End-to-End Signing Workflow:**

```
Step 1: Build Firmware
  └─ Compile source code → Firmware binary

Step 2: Generate Signature
  └─ Private Key + Hash(Firmware) → Signature
     (Private key stored in HSM/offline)

Step 3: Create Manifest
  └─ Firmware + Signature + Metadata → Manifest

Step 4: Publish Update
  └─ Upload to CDN/update servers with manifest

Step 5: Device Verification
  └─ Device retrieves public key (certificate)
  └─ Verifies: RSA-Verify(Signature, Hash, PublicKey)
```

### 6.2 Certificate Management

**Certificate Types:**

| Type | Purpose | Lifetime | Key Size | Usage |
|---|---|---|---|---|
| **Root CA** | Sign intermediate CAs | 10-20 years | RSA-4096 | Offline, airgapped |
| **Intermediate CA** | Sign device/server certs | 5-10 years | RSA-2048+ | HSM stored |
| **Firmware Signing** | Sign firmware packages | 3-5 years | RSA-2048+/EdDSA | HSM stored |
| **TLS Server** | HTTPS for download | 1-2 years | RSA-2048+/ECDSA-P256+ | Server certificate |
| **Device Client** | mTLS authentication | 1-3 years | RSA-2048+/ECDSA | Per-device |

### 6.3 Certificate Chain of Trust

```
Root CA Certificate (offline)
    ↓
Intermediate CA Certificate (HSM)
    ├─ Firmware Signing Certificate
    ├─ TLS Server Certificate
    └─ Device Certificate Template
```

### 6.4 X.509 Certificate Structure

**Example Firmware Signing Certificate:**

```
Certificate:
  Version: 3
  Serial Number: 0x1A2B3C4D5E6F
  Signature Algorithm: sha256WithRSAEncryption
  Issuer: CN=ScentinelOTA Intermediate CA, O=YourOrg, C=US
  Subject: CN=FirmwareSigningKey-2026, O=YourOrg, C=US
  Validity:
    Not Before: 2026-01-01 00:00:00 UTC
    Not After: 2029-12-31 23:59:59 UTC
  Public Key:
    Algorithm: rsaEncryption
    Modulus: (2048 bits)
    Exponent: 65537
  X509v3 Extensions:
    X509v3 Key Usage: critical
      Digital Signature
    X509v3 Extended Key Usage:
      Firmware Code Signing
    X509v3 Subject Key Identifier:
      12:34:56:78:9A:BC:DE:F0
    Authority Key Identifier:
      keyid:AB:CD:EF:01:23:45:67:89
```

### 6.5 Key Lifecycle Management

**Key Generation:**
```
1. Generate private key in HSM (not exportable)
2. Export public key certificate
3. Create backup of key material (encrypted, split)
4. Document key generation process
5. Witness signatures on key generation
```

**Key Rotation:**
```
Timeline:
  - RSA-2048: Rotate every 1-2 years
  - RSA-4096: Rotate every 3-5 years
  - EdDSA: Rotate every 3-5 years

Process:
  1. Generate new key pair
  2. Create new certificate with new key
  3. Overlapping validity period (3-6 months)
  4. Update devices to accept new certificate
  5. Deprecate old certificate after transition
  6. Archive old keys for 7+ years
```

**Key Compromise Response:**
```
Immediate Actions:
  1. Revoke compromised certificate (CRL/OCSP)
  2. Generate new key and certificate
  3. Sign all future updates with new key
  4. Notify all customers
  5. Provide recovery/remediation procedure

Recovery:
  1. Emergency update with new signing key
  2. Devices update certificate store
  3. Validate deployment status
  4. Post-mortem analysis and documentation
```

### 6.6 Hardware Security Module (HSM) Requirements

**HSM Selection Criteria:**

| Requirement | Specification |
|---|---|
| **Certification** | FIPS 140-2 Level 3+, CC EAL 4+ |
| **Key Storage** | Hardware-protected, tamper-evident |
| **Key Backup** | Secret sharing (Shamir), encrypted export |
| **Performance** | RSA-2048 signing: <100ms |
| **MTBF** | >100,000 hours |
| **Availability** | Redundant HSM setup, hot-swappable |
| **Audit Trail** | All operations logged, tamper-proof |

**Recommended HSM Products:**
- Thales Luna HSM
- Gemalto/SafeNet Proteccio
- AWS CloudHSM
- Azure Dedicated HSM
- Yubico HSM (cost-effective for small deployments)

### 6.7 Certificate Pinning

**Implementation Strategies:**

```
Strategy 1: Public Key Pinning
  - Pin SHA-256 hash of public key
  - Survives certificate renewal
  - More flexible for rotation

Strategy 2: Certificate Pinning
  - Pin exact certificate
  - Require exact certificate match
  - Breaks on certificate renewal

Strategy 3: Certificate Pinning with Backup
  - Pin current certificate
  - Pin backup certificate
  - Allows seamless rotation

Implementation (Device):
  1. Store pinned public key in firmware
  2. On TLS handshake, verify received key
  3. If mismatch, reject connection
  4. Log failure and alert
  5. Support fallback mechanism for recovery
```

---

## 7. Rollback Protection Mechanisms

### 7.1 Rollback Attack Definition

**Threat Model:**
```
Attacker's Goal: Force device to use known-vulnerable firmware
Attack Vector: Replay previously valid firmware version
Motivation: Exploit known security vulnerability
Example Scenario:
  - Device running firmware v2.1.5 (latest)
  - Attacker intercepts/replays firmware v2.0.1 (known vulnerable)
  - Device rolls back if rollback protection is weak
  - Attacker can exploit v2.0.1 vulnerability
```

### 7.2 Monotonic Counter Mechanism

**Hardware Implementation (Recommended):**

```
Non-Volatile Counter Storage:
  - Located in secure storage (TEE, TPM, or OTP region)
  - Incremented with each update
  - Cannot be decremented (write-once or append-only)
  - Protected from tampering

Operation:
  1. Current firmware version = 5, Counter = 5
  2. Update manifest specifies version 6, counter = 6
  3. Verification: manifest_counter >= device_counter
  4. If valid: Install and increment counter to 6
  5. If invalid (e.g., version 4, counter = 4): Reject

Implementation Details:
  - OTP (One-Time Programmable): Cells burned once
  - Flash wear leveling: Track counter across blocks
  - Atomic operations: No partial updates
  - Backup counters: Redundancy for critical systems
```

**Counter Overflow Handling:**

```
Counter Bit Width: 32-bit or 64-bit
Max Values:
  - 32-bit: 4,294,967,295 increments
  - 64-bit: 18,446,744,073,709,551,615 increments

Strategy if Counter Nears Limit:
  1. Check: if (counter + 1) == MAX_VALUE
  2. If approaching limit: Require manual intervention
  3. Alternative: Use version string comparison (v99.99.99)
  4. Device locks until counter reset procedure
```

### 7.3 Secure Timestamp Mechanism

**Server-Based Timestamp Validation:**

```
Protocol Flow:
  1. Device requests: GET /update/check
     Headers: Device-ID, current_version, timestamp

  2. Server responds:
     {
       "version": "2.1.5",
       "timestamp": "2026-03-06T10:30:00Z",
       "server_signature": "RSA-Sign(version + timestamp)",
       "timestamp_signature": "SignTimestamp(timestamp, server_key)"
     }

  3. Device verification:
     - Verify RSA signature (authenticate server)
     - Verify timestamp is within acceptable range:
       |current_device_time - server_timestamp| < 600 seconds (10 min)
     - Compare version: new_version > current_version

  4. Accept update only if all checks pass
```

**Timestamp Authority (TSA) Integration:**

```
For high-security deployments:
  1. Device requests timestamp from trusted TSA
  2. TSA provides cryptographically signed timestamp
  3. Device uses TSA timestamp for rollback check
  4. Server cannot fake timestamps (TSA-verified)

Standard: RFC 3161 Time-Stamp Protocol
  - TSA signs timestamp with its private key
  - Verifiable by any device with TSA public certificate
```

### 7.4 Anti-Rollback Token System

**Token-Based Rollback Protection:**

```
Token Structure:
  {
    "device_id": "device-1234",
    "version": "2.1.5",
    "issued_timestamp": "2026-03-06T10:00:00Z",
    "expiration": "2026-03-07T10:00:00Z",
    "counter": 42,
    "nonce": "random_128_bits",
    "signature": "HMAC-SHA256(token_data, server_secret_key)"
  }

Token Validation:
  1. Parse token and extract fields
  2. Verify signature: HMAC-SHA256(data) == provided_signature
  3. Check expiration: now < expiration_timestamp
  4. Verify counter: received_counter >= stored_counter
  5. Compare version: new_version >= min_allowed_version
  6. Accept update if all checks pass

Advantages:
  - Flexible version constraints
  - Time-based expiration
  - Per-device tracking
  - Audit trail in token
```

### 7.5 Combination Approach (Defense-in-Depth)

**Recommended Rollback Protection Stack:**

```
Layer 1: Hardware Monotonic Counter (most critical)
  └─ Incremented with each successful update
  └─ Cannot be reset or decremented

Layer 2: Secure Timestamp Validation
  └─ Server-provided, cryptographically signed timestamp
  └─ Device verifies freshness

Layer 3: Version Comparison
  └─ New version must be >= current version
  └─ Sequence number in firmware header

Layer 4: Manifest Anti-Rollback Token
  └─ Server-issued token prevents replaying old manifests
  └─ Token includes version constraint and expiration

Failure Mode Analysis:
  - Compromise of single layer: Backed by other layers
  - Time-based attack: Blocked by monotonic counter
  - Token replay: Blocked by timestamp/expiration
  - Firmware downgrade: Blocked by version comparison
```

### 7.6 Implementation in SUIT Manifests

**SUIT Manifest Anti-Rollback Field:**

```
SUIT_Manifest = {
  manifest-version: 1,
  manifest-sequence-number: 42,  <-- Rollback protection
  common: {
    component-identifier: [h'device/firmware'],
    image-digest: [
      digest-algorithm-id: 6,  (SHA-256)
      digest-bytes: h'...'
    ]
  },
  install: [
    {
      condition-type: SUIT_Condition_Minimum_Battery,
      condition-data: 20
    },
    {
      condition-type: SUIT_Condition_Image_Not_Match,
      condition-data: h'...'
    },
    {
      instruction-type: SUIT_Instruction_Install
    }
  ]
}

Sequence Number Validation:
  incoming_sequence_number > stored_sequence_number
  → Accept update

  incoming_sequence_number <= stored_sequence_number
  → Reject update (rollback attempt)
```

---

## 8. Secure Boot and Verified Boot

### 8.1 Secure Boot Architecture

**Overview:**
```
Secure Boot: Ensures bootloader and kernel integrity before execution
Verified Boot: Continuous verification throughout device runtime
Combined: Unbroken chain of trust from power-on to OS
```

### 8.2 Boot Process Flow (ARM with TrustZone)

```
1. Power-on
   └─ ROM Code (immutable, hardened)

2. BootROM Execution
   └─ Read OTP-stored root key hash
   └─ Read SPL (Secondary Program Loader) from flash
   └─ Verify SPL signature: RSA/ECDSA
   └─ If invalid: Halt or boot recovery mode
   └─ If valid: Execute SPL

3. SPL Execution (Minimal bootloader)
   └─ Initialize DRAM, clocks
   └─ Read full bootloader (U-Boot) from flash
   └─ Verify U-Boot signature
   └─ Execute U-Boot

4. U-Boot Execution
   └─ Read FIT (Flat Image Tree) image
   └─ Parse FIT header (contains kernel + devicetree + initrd)
   └─ Verify FIT signatures (RSA-2048 minimum)
   └─ Read kernel into memory
   └─ Verify kernel signature
   └─ Create device tree
   └─ Execute kernel (jump to entry point)

5. Kernel Boot
   └─ Initialize memory management
   └─ Mount root filesystem
   └─ Verify filesystem (dm-verity or IMA)
   └─ Execute init process
   └─ Device ready for use
```

### 8.3 Key Storage and Chain of Trust

**Key Hierarchy:**

```
OTP Region (immutable)
  └─ Root Key Hash (SHA-256 hash of root signing key)
      └─ Used to verify bootloader signature only
      └─ Stored in OTP at manufacturing time

Bootloader Public Key
  └─ Signature: Signed by root key
  └─ Used to verify kernel signature
  └─ May be stored in bootloader or OTP

Kernel Public Key
  └─ Signature: Signed by bootloader key
  └─ Used to verify device tree signature
  └─ Embedded in kernel binary
```

**OTP (One-Time Programmable) Usage:**

```
Advantages:
  - Cannot be modified after programming
  - Immune to software attacks
  - Survives firmware updates
  - Permanent installation on device

Disadvantages:
  - No recovery if key is compromised
  - Expensive to manufacture variants
  - Limited storage (typically 32-256 bytes)

Best Practice:
  - Store only root key hash in OTP
  - Allow key rotation through attestation mechanism
  - Update keys via secure firmware update process
```

### 8.4 Signature Verification

**FIT (Flat Image Tree) Format (U-Boot):**

```
FIT Image Structure:
  ├─ Image Header
  ├─ Device Tree Description
  │  ├─ Images
  │  │  ├─ kernel-1 (compressed, signed)
  │  │  ├─ ramdisk-1 (signed)
  │  │  └─ fdt-1 (device tree, signed)
  │  └─ Configurations
  │     └─ config-1 (specifies: kernel-1, ramdisk-1, fdt-1)
  └─ Data Section
     ├─ Kernel binary
     ├─ Ramdisk image
     └─ Device tree binary

Verification Flow:
  1. Parse FIT header
  2. Locate configuration: config-1
  3. For each referenced image (kernel, ramdisk, fdt):
     a. Extract image data
     b. Compute hash: SHA-256(image_data)
     c. Extract signature from image node
     d. Verify: RSA-Verify(signature, hash, public_key)
     e. If any verification fails: Halt
  4. Load verified images into memory
  5. Execute kernel entry point
```

**Example FIT Manifest (DTS):**

```
/dts-v1/;

/ {
  description = "Linux Kernel and Device Tree";
  #address-cells = <1>;

  images {
    kernel-1 {
      description = "Linux Kernel";
      data = /incbin/("vmlinux.gz");
      type = "kernel";
      arch = "arm";
      os = "linux";
      compression = "gzip";
      load = <0x80000000>;
      entry = <0x80000000>;
      hash-1 {
        algo = "sha256";
      };
      signature-1 {
        algo = "rsa2048";
        key-name-hint = "kernel";
      };
    };

    fdt-1 {
      description = "Device Tree";
      data = /incbin/("device-tree.dtb");
      type = "flat_dt";
      arch = "arm";
      compression = "none";
      hash-1 {
        algo = "sha256";
      };
      signature-1 {
        algo = "rsa2048";
        key-name-hint = "fdt";
      };
    };
  };

  configurations {
    config-1 {
      description = "Boot Linux kernel with device tree";
      kernel = "kernel-1";
      fdt = "fdt-1";
      signature-1 {
        algo = "rsa2048";
        key-name-hint = "config";
        sign-images = "fdt", "kernel";
      };
    };
  };
};
```

### 8.5 Verified Boot (Android)

**Android Verified Boot 2.0 (AVB):**

```
Partition Structure:
  ┌─ Boot Partition (signed)
  │  ├─ Bootloader
  │  ├─ Kernel
  │  └─ Ramdisk
  ├─ System Partition (signed, hash tree)
  │ ├─ Filesystem image
  │ └─ Verity hash tree
  ├─ Vendor Partition (signed, hash tree)
  ├─ Product Partition (signed, hash tree)
  └─ Vbmeta Partition (verification metadata)

Vbmeta Partition Contents:
  {
    "magic": "AVB0",
    "version": 1,
    "auxiliary_data_block_size": 4096,
    "authentication_data_block_size": 4096,
    "algorithm_type": "SHA256_RSA4096",
    "hash_offset": 256,
    "hash_size": 32,
    "signature_offset": 288,
    "signature_size": 512,
    "public_key_offset": 800,
    "public_key_size": 270,
    "public_key_metadata_offset": 1070,
    "public_key_metadata_size": 100,
    "descriptors": [
      {
        "type": "HASH_DESCRIPTOR",
        "partition_name": "boot",
        "salt": "...",
        "digest": "..."
      },
      {
        "type": "HASHTREE_DESCRIPTOR",
        "partition_name": "system",
        "root_digest": "...",
        "tree_digest": "...",
        "algorithm": "sha256"
      }
    ]
  }

Verification Process:
  1. Load vbmeta partition
  2. Verify vbmeta signature (RSA-4096)
  3. For each descriptor:
     a. If HASH_DESCRIPTOR: Verify partition hash
     b. If HASHTREE_DESCRIPTOR: Set up dm-verity
  4. Mount filesystems with dm-verity
  5. Continuous verification during runtime
```

### 8.6 dm-verity (Device Mapper Verity)

**Hash Tree Structure:**

```
Filesystem Layout:
  ├─ Data Blocks (4KB each)
  ├─ Hash Tree:
  │  ├─ Level 0 (leaf nodes): Hash(each data block)
  │  ├─ Level 1 (intermediate): Hash(Level 0 hashes)
  │  ├─ Level N: Hash(Level N-1 hashes)
  │  └─ Root Hash: Single hash value

Verification on Read:
  1. Application requests block N from filesystem
  2. Kernel reads block N
  3. Compute hash of block: hash_N = SHA256(block_N_data)
  4. Retrieve stored hash_N from hash tree
  5. Compare: if hash_N == stored_hash_N: Allow access
  6. If mismatch: Block I/O, trigger error handler

Hash Tree Depth:
  For 4GB filesystem with 4KB blocks:
  - Blocks: 1,048,576 (2^20)
  - Level 1: 2,048 hashes (2^11) = 8KB
  - Level 2: 16 hashes = 64 bytes
  - Root hash: 32 bytes (SHA-256)
```

**dm-verity Device Mapper Setup:**

```
Device Mapper Configuration:
  verity,sha256 /dev/vda
           /dev/vdb
           0
           4096
           1048576
           1
           sha256
           445123456789abcdef
           # root_digest

Where:
  - /dev/vda: Data device (filesystem)
  - /dev/vdb: Hash device (hash tree)
  - 0: Data device offset
  - 4096: Hash device offset
  - 1048576: Data blocks
  - 1: Version (can be 0 or 1)
  - sha256: Algorithm
  - 445123456789abcdef: Root hash for verification
```

### 8.7 TPM (Trusted Platform Module) Integration

**TPM 2.0 Usage in Secure Boot:**

```
PCR (Platform Configuration Register) Extension:
  PCR[0]: CRTM (Core Root of Trust Measurement) - firmware
  PCR[1]: Host Platform Configuration - UEFI settings
  PCR[2]: UEFI Option ROMs
  PCR[3]: UEFI Option ROM Configuration
  PCR[4]: UEFI Boot Manager Code and Boot Attempts
  PCR[5]: UEFI GPT/Partition Table
  PCR[6]: UEFI Firmware Configuration (unused in BIOS)
  PCR[7]: Secure Boot State, certificates, and keys

Extension Operation:
  PCR_new = SHA256(PCR_old || measurement_data)

Example Flow:
  1. Power-on: PCR[0] = 0 (initial)
  2. Bootloader measures kernel: PCR[0] = SHA256(0 || kernel_hash)
  3. Kernel measures ramdisk: PCR[0] = SHA256(PCR[0] || ramdisk_hash)
  4. Application can seal secrets: Encrypt(secret, PCR_digest)
     Secret only accessible if exact same boot chain

Remote Attestation:
  1. Device computes PCR values
  2. TPM signs PCR values: Signature = Sign(PCR_0||PCR_1||...||PCR_7)
  3. Device sends: PCR values + TPM signature + certificate
  4. Remote verifies: Verify signature, check PCR values
  5. Attestation challenge: Nonce in request, used in signature
```

---

## 9. Update Distribution and Delivery Security

### 9.1 Content Delivery Network (CDN) Security

**CDN Architecture:**

```
Update Server (Origin)
    ├─ S3/Cloud Storage (encrypted at rest)
    └─ CDN Edge Servers (globally distributed)
       ├─ Region 1: Download from regional edge
       ├─ Region 2: Download from regional edge
       └─ Region N: Download from regional edge

Security Considerations:
  1. Origin server communicates with CDN over secure channel
  2. CDN caches verified content only
  3. Edge servers serve cached content to clients
  4. Devices verify content signature (same as if from origin)
  5. CDN cannot modify content (all signatures client-verified)
```

**CDN Provider Security Comparison:**

| Provider | Security Features | DDoS Protection | Caching | Cost |
|---|---|---|---|---|
| **CloudFlare** | mTLS origin, encryption, DDoS | Yes | Edge | $200-5000/mo |
| **Akamai** | DDoS, WAF, origin encryption | Yes | Extensive | $1000+/mo |
| **AWS CloudFront** | Origin access identity, encryption | Yes | Global | Pay-per-GB |
| **Fastly** | VCL customization, instant purge | Yes | Efficient | Pay-per-Gbps |

### 9.2 TLS Configuration for Firmware Distribution

**Recommended TLS Configuration:**

```
Protocol: TLS 1.3 (minimum TLS 1.2)

Cipher Suites (in preference order):
  1. TLS_AES_256_GCM_SHA384
  2. TLS_CHACHA20_POLY1305_SHA256
  3. TLS_AES_128_GCM_SHA256

Certificate Configuration:
  - Type: ECDSA (P-256) or RSA-3072+
  - Certificate pinning: Pin public key or certificate
  - OCSP stapling: Include in TLS handshake
  - HSTS header: Enforce HTTPS for 1 year minimum

HSTS Header Example:
  Strict-Transport-Security: max-age=31536000; includeSubDomains

Perfect Forward Secrecy:
  - Use ephemeral ECDH (ECDHE) or DH (DHE)
  - Session tickets: Disabled or encrypted with rotating key
  - Session resumption: Only via PSK with fresh handshake
```

**Client-Side TLS Validation (Device):**

```
Verification Steps:
  1. DNS resolution: Verify DNS over HTTPS (DoH) if possible
  2. Certificate validation:
     a. Check certificate expiration
     b. Verify certificate chain to trusted root
     c. Verify certificate hostname matches domain
     d. Check certificate revocation (CRL or OCSP)
     e. Apply certificate pinning if configured
  3. Cipher suite negotiation:
     a. Ensure TLS 1.3 or TLS 1.2 with PFS
     b. Reject weak ciphers
  4. Handshake verification:
     a. Verify server finished message
     b. Complete key derivation
  5. Connection ready: Download firmware

Error Handling:
  - Certificate validation failure: Abort, log error, alert
  - Hostname mismatch: Abort (not a MITM, verify configuration)
  - Cipher suite mismatch: Abort, try fallback server
  - Connection timeout: Retry with exponential backoff
```

### 9.3 Secure Download Protocol

**HTTP Headers for Firmware Download:**

```
Request Headers (Device Sends):
  GET /firmware/v2.1.5/device-model-x.bin HTTP/1.1
  Host: updates.example.com
  Authorization: Bearer device-token-jwt
  User-Agent: DeviceModel-X/OS-1.0
  Device-ID: device-uuid-1234567890
  Current-Version: 2.0.1
  Accept-Encoding: identity (no compression)
  Accept: application/octet-stream
  Connection: close

Response Headers (Server Sends):
  HTTP/1.1 200 OK
  Content-Type: application/octet-stream
  Content-Length: 2097152
  Content-MD5: base64-md5-hash  (deprecated, use signature)
  Cache-Control: no-cache, no-store, must-revalidate
  Pragma: no-cache
  Expires: Thu, 01 Jan 1970 00:00:00 GMT
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Strict-Transport-Security: max-age=31536000
  Content-Security-Policy: default-src 'none'
  X-Firmware-Signature: base64-firmware-signature
  X-Firmware-Hash: sha256-hash-of-content
  ETag: "firmware-v2.1.5-etag-12345"
  Last-Modified: Tue, 04 Mar 2026 12:00:00 GMT

Body: Binary firmware image
```

**Download Integrity Verification:**

```
Protocol Flow:
  1. Device sends download request with authentication
  2. Server responds with firmware binary + headers
  3. Device receives chunks and stores in staging partition
  4. After complete download:
     a. Compute SHA-256 hash of downloaded file
     b. Compare with X-Firmware-Hash header
     c. If mismatch: Discard, retry or fail
     d. If match: Continue to signature verification
  5. Extract signature from X-Firmware-Signature header
  6. Verify signature: RSA/EdDSA-Verify(signature, hash, public_key)
  7. If valid: Proceed with installation
  8. If invalid: Discard, alert, abort
```

### 9.4 Bandwidth Optimization

**Delta Updates (Binary Differencing):**

```
Traditional Update (Full):
  - Download: 2 GB firmware
  - Time: 30-60 minutes on 4G LTE
  - Cost: High bandwidth usage

Delta Update:
  - Compute difference: diff(firmware_v2.0.1, firmware_v2.1.5)
  - Difference size: ~50-100 MB (2-5% of full size)
  - Download: 50-100 MB
  - Time: 3-10 minutes on 4G LTE
  - Cost: 20-50x reduction

Implementation:
  1. Server pre-computes binary diffs for each version pair
  2. Device requests available deltas
  3. Server responds with smallest applicable delta
  4. Device downloads delta
  5. Device applies patch: Reconstruct new firmware from old + delta
  6. Verify reconstructed firmware hash
  7. Install new firmware

Delta Tools:
  - bsdiff/bspatch: Linux, BSD, efficient
  - Binary patch (Google): Used in Chrome
  - rdiff (librsync): Rsync-based differencing
  - xdelta3: Language-agnostic, highly efficient
```

**Compression:**

```
Compression Benefits:
  - Reduce bandwidth: 40-60% reduction typical
  - Reduce storage: Compressed in transit only
  - Cost savings: Pay per gigabyte transferred

Compression Methods:
  - gzip: Widely supported, moderate compression
  - bzip2: Better compression, slower
  - xz: Best compression, slow compression/decompression
  - zstd: Good compression, fast, modern choice

Recommendation:
  - Use zstd for new deployments
  - gzip for compatibility
  - Avoid compression for already-compressed content (images, video)

TLS Encryption vs Compression:
  - Compression is before TLS encryption
  - No information leak (header is encrypted)
  - Minimal padding needed (TLS record headers)
```

### 9.5 Resumable Downloads

**HTTP Range Requests:**

```
Initial Request:
  GET /firmware/v2.1.5/device-model-x.bin HTTP/1.1
  Range: bytes=0-1000000

Server Response (206 Partial Content):
  HTTP/1.1 206 Partial Content
  Content-Range: bytes 0-1000000/2097152
  Content-Length: 1000001
  Accept-Ranges: bytes
  [1000001 bytes of data]

Download Interrupted at byte 1500000:
  GET /firmware/v2.1.5/device-model-x.bin HTTP/1.1
  Range: bytes=1500000-2097151

Server Response:
  HTTP/1.1 206 Partial Content
  Content-Range: bytes 1500000-2097151/2097152
  Content-Length: 597152
  Accept-Ranges: bytes
  [597152 bytes of data]

Verification After Resume:
  1. Combine downloaded chunks
  2. Verify overall file hash
  3. Proceed with installation
```

### 9.6 Mirror and Fallback Strategy

**Multi-Server Failover:**

```
Primary Update Servers:
  1. updates.example.com (primary)
  2. updates-backup.example.com (backup)
  3. cdn-edge-1.example.com (regional CDN 1)
  4. cdn-edge-2.example.com (regional CDN 2)

Device Download Strategy:
  1. Attempt server 1 (primary)
     If successful: Complete
     If timeout: Retry up to 3 times
     If failure: Move to server 2

  2. Attempt server 2 (backup)
     If successful: Complete
     If failure: Move to server 3

  3. Attempt server 3 (regional CDN)
     If successful: Complete
     If failure: Move to server 4

  4. Attempt server 4 (regional CDN)
     If successful: Complete
     If failure: Abort update, retry later

Retry Logic:
  - Exponential backoff: 5s, 10s, 30s, 60s, 300s
  - Max retries: 5-10 per server
  - Total timeout: 30-60 minutes
  - Log all failures for analysis

Server Selection:
  - Geolocation-based: Route to nearest CDN
  - Load-based: Choose server with lowest latency
  - Reputation-based: Track success rates per server
```

---

## 10. Device Authentication and Authorization

### 10.1 Device Identity and Provisioning

**Device Certificate-Based Identity:**

```
Manufacturing Process:
  1. Generate unique device private key (in HSM)
  2. Request device certificate from CA
  3. Certificate signed by Intermediate CA
  4. Install certificate and private key in device
  5. Key stored in secure element / TEE
  6. Certificate stored in device memory or TEE

Device Certificate Contents:
  Subject CN=device-uuid-12345, O=YourOrg, C=US
  Serial: Unique per device
  Validity: 3-5 years
  Public Key: RSA-2048+ or ECDSA-P256+
  Extensions:
    - Device model
    - Hardware version
    - Manufacturing date
    - Device capabilities
    - Update permissions
```

**Zero-Touch Provisioning (ZTP):**

```
Process:
  1. Device boots for first time (factory state)
  2. Attempts to connect to provisioning server
  3. Server validates device claim (MAC address, serial)
  4. Server provisions device certificate
  5. Device installs certificate and establishes identity
  6. Device now can download OTA updates

Security Considerations:
  - Provision over secure channel (TLS)
  - Validate device ownership (serial number database)
  - Rate limiting on provisioning endpoint
  - Audit trail of all provisioned devices
  - Certificate pinning for provisioning server
```

### 10.2 Mutual TLS (mTLS) Authentication

**mTLS Handshake for Firmware Download:**

```
Connection Establishment:
  1. Device initiates TLS connection to update server
  2. Server sends its certificate and requests client certificate
  3. Device sends its device certificate (with subject = device-uuid)
  4. Server validates device certificate:
     a. Verify signature (issued by trusted CA)
     b. Verify certificate chain
     c. Verify expiration
     d. Check revocation status (CRL/OCSP)
  5. Device validates server certificate:
     a. Verify signature
     b. Verify hostname
     c. Apply certificate pinning if configured
  6. Both parties derive shared session keys
  7. Encrypted channel established

Implementation (Python):
  import ssl
  context = ssl.create_default_context()
  context.load_cert_chain('device-cert.pem', 'device-key.pem')
  context.verify_mode = ssl.CERT_REQUIRED
  context.check_hostname = True

  connection = context.wrap_socket(sock, server_hostname=hostname)
```

### 10.3 Device Authorization for Updates

**Authorization Model:**

```
Based on Device Attributes:
  1. Device ID: Unique identifier from certificate
  2. Device Model: From certificate subject
  3. Current Firmware Version: Reported by device
  4. Hardware Version: From certificate
  5. Device Group/Cohort: Administrative assignment
  6. Update Permission Level: Admin, standard, or restricted

Authorization Rules:
  - Model "A" can update to firmware >= v1.0.0
  - Model "B" cannot update to firmware with feature X
  - Devices in cohort "canary" can receive beta updates
  - Devices outside maintenance window cannot update
  - Devices with low battery (<20%) cannot update

Implementation:
  1. Device sends authorization request:
     {
       "device_id": "device-uuid-12345",
       "device_model": "model-x",
       "current_version": "2.0.1",
       "hardware_version": "rev_c",
       "battery_level": 85,
       "certificate": "device-certificate-pem"
     }

  2. Server validates:
     a. Device certificate is valid and trusted
     b. Device identity matches certificate
     c. Requested firmware is applicable to device model
     d. Device meets prerequisites (battery, network, time)
     e. Device is authorized for requested firmware

  3. Server responds:
     {
       "authorized": true,
       "firmware_version": "2.1.5",
       "firmware_url": "https://updates.example.com/fw/v2.1.5",
       "firmware_hash": "sha256:...",
       "firmware_signature": "base64:...",
       "installation_deadline": "2026-03-20T00:00:00Z"
     }
```

### 10.4 Device-to-Server Authentication

**Token-Based Authentication (JWT):**

```
JWT Structure:
  Header: {
    "alg": "RS256",
    "kid": "firmware-signing-key-2026",
    "typ": "JWT"
  }

  Payload: {
    "device_id": "device-uuid-12345",
    "device_model": "model-x",
    "iat": 1709769600,  (issued at)
    "exp": 1709859600,  (expiration: 1 hour)
    "nonce": "random-nonce-12345",
    "scope": "firmware:download",
    "version": "2.0.1"
  }

  Signature: RS256(Header || Payload, private_key)

Device sends in Authorization header:
  Authorization: Bearer <JWT>

Server Validates:
  1. Decode JWT: Split on '.' characters
  2. Verify signature: RSA-Verify(signature, header.payload, public_key)
  3. Validate expiration: now < exp
  4. Check nonce: Matches expected value
  5. Verify scope: Contains 'firmware:download'
  6. Check device_id: Matches certificate CN
```

**OAuth 2.0 Device Flow (for IoT):**

```
Also known as Device Authorization Grant (RFC 8628)

Flow:
  1. Device requests device code: POST /device_authorization
     {
       "client_id": "device-client-id",
       "scope": "firmware:download"
     }

  2. Server responds:
     {
       "device_code": "ABC123DEF456GHI789",
       "user_code": "WXYZ-1234",
       "verification_uri": "https://updates.example.com/activate",
       "expires_in": 1800,  (30 minutes)
       "interval": 5  (poll interval in seconds)
     }

  3. Device polls for token: POST /token
     {
       "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
       "device_code": "ABC123DEF456GHI789",
       "client_id": "device-client-id"
     }

  4. Server responds (initially pending):
     {
       "error": "authorization_pending",
       "error_description": "Device is not yet authorized"
     }

  5. After user authorization (on web):
     {
       "access_token": "eyJ0eXAiOiJKV1QiLCJhbGci...",
       "token_type": "Bearer",
       "expires_in": 3600
     }

  6. Device uses access token:
     GET /firmware/latest
     Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGci...
```

### 10.5 Rate Limiting and Throttling

**Server-Side Rate Limiting:**

```
Per-Device Rate Limit:
  - Max 1 update check per minute per device
  - Max 3 failed auth attempts per hour
  - Max 1 firmware download per 24 hours (per device model)

Global Rate Limit:
  - Max 10,000 concurrent connections
  - Max 1 million requests per minute across all devices
  - Max 100 Gbps total bandwidth

Implementation (Token Bucket Algorithm):
  Device bucket:
     Capacity: 10 tokens
     Refill rate: 1 token per 60 seconds

  On request:
     If tokens >= cost:
        Consume tokens
        Process request
     Else:
        Deny request (429 Too Many Requests)
        Return: Retry-After header with seconds

Redis Implementation:
  KEY: "rate_limit:device:{device_id}"
  VALUE: {
    "tokens": 10,
    "last_refill": timestamp,
    "capacity": 10,
    "refill_rate": 1/60
  }
  EXPIRE: 3600 seconds (1 hour)
```

### 10.6 Device Communication Audit and Logging

**Audit Trail Requirements:**

```
Log Fields for Every OTA Communication:
  - Timestamp (UTC, ISO 8601)
  - Device ID (anonymized if needed)
  - Device Model
  - Current Firmware Version
  - Target Firmware Version
  - Update Status: success/failed/rejected
  - Failure Reason (if applicable)
  - IP Address (anonymized: last octet masked)
  - User Agent
  - HTTP Status Code
  - Bytes Downloaded
  - Download Duration
  - Signature Verification: passed/failed
  - Certificate Used (key ID)
  - Server Name (hostname)
  - Error Details (for forensics)

Log Storage:
  - Use tamper-proof logging system (e.g., AWS CloudTrail)
  - Encrypt logs in transit and at rest
  - Retain logs for minimum 7 years (compliance)
  - Archive to cold storage after 1 year
  - Implement access controls on logs

Example Log Entry (JSON):
  {
    "timestamp": "2026-03-06T10:30:45.123Z",
    "device_id": "sha256:abc123def456",
    "device_model": "model-x",
    "current_version": "2.0.1",
    "target_version": "2.1.5",
    "status": "success",
    "ip_address": "192.168.1.x",
    "bytes_downloaded": 2097152,
    "duration_seconds": 45,
    "http_status": 200,
    "signature_verification": "passed",
    "key_id": "prod-signing-key-2026",
    "server_hostname": "updates.example.com",
    "user_agent": "DeviceModel-X/1.0",
    "checksum_match": true,
    "installation_status": "pending"
  }
```

### 10.7 Revocation and Certificate Management

**Certificate Revocation List (CRL):**

```
CRL Structure:
  Version: 2
  Issuer: CN=ScentinelOTA Intermediate CA, O=YourOrg, C=US
  Last Update: 2026-03-06T00:00:00Z
  Next Update: 2026-03-13T00:00:00Z

  Revoked Certificates:
    Serial: 0x1A2B3C4D5E6F
      Revocation Date: 2026-03-05T10:00:00Z
      Reason: keyCompromise
    Serial: 0x9F8E7D6C5B4A
      Revocation Date: 2026-03-04T15:30:00Z
      Reason: superseded

  Signature: sha256WithRSAEncryption
```

**OCSP (Online Certificate Status Protocol):**

```
Request:
  {
    "certID": {
      "hashAlgorithm": "sha256",
      "issuerNameHash": "...",
      "issuerKeyHash": "...",
      "serialNumber": "0x1A2B3C4D5E6F"
    },
    "nonce": "random-12345"
  }

Response:
  {
    "responseStatus": "successful",
    "responseBytes": {
      "responseType": "id-ad-ocsp",
      "response": {
        "certID": "...",
        "certStatus": "good|revoked|unknown",
        "thisUpdate": "2026-03-06T10:00:00Z",
        "nextUpdate": "2026-03-13T10:00:00Z",
        "signature": "..."
      }
    }
  }

Device Verification (Option 1 - CRL):
  1. Download CRL from server
  2. Verify CRL signature
  3. Check if device certificate serial is in revoked list
  4. Cache CRL (with expiration)

Device Verification (Option 2 - OCSP Stapling):
  1. Server includes OCSP response in TLS handshake
  2. Device verifies OCSP response signature
  3. No additional network request needed
  4. More efficient for IoT devices
```

---

## Summary Table: OTA Security Checklist

| Component | Best Practice | Implementation | Verification |
|---|---|---|---|
| **Asymmetric Crypto** | EdDSA (Ed25519) or RSA-2048+ | Sign all firmware with HSM-stored key | Signature validation on every boot |
| **Symmetric Crypto** | AES-256-GCM | Encrypt firmware at rest and in transit | Hash verification before installation |
| **Authentication** | mTLS with device certificates | Device cert in TEE/HSM | Verify certificate chain and expiration |
| **Authorization** | Role-based access (RBAC) | Device model/version constraints | Audit log all authorization decisions |
| **Encryption** | TLS 1.3 minimum | All server communications encrypted | HSTS headers, certificate pinning |
| **Rollback Prevention** | Monotonic counter + timestamp | Hardware counter + signed timestamp | Reject if counter decrements |
| **Secure Boot** | Hardware-verified boot chain | Root key in OTP, verify all stages | PCR extensions with TPM |
| **Update Distribution** | CDN with multi-server failover | Regional distribution, DDoS protection | Monitor download success rates |
| **Code Signing** | RSA-4096 or EdDSA, signed by offline key | Offline root key, HSM-backed intermediate | Verify signature before every execution |
| **Audit Trail** | Tamper-proof centralized logging | Encrypt logs, store immutably | Monthly log analysis, alerting |

---

## References and Standards

### NIST Publications
- NIST Cybersecurity Framework (CSF)
- NIST SP 800-53: Security and Privacy Controls for Information Systems
- NIST SP 800-82: Guide to Industrial Control Systems (ICS) Security
- NIST SP 800-131A: Transitions: Recommendation for Transitioning to Post-Quantum Cryptography
- NIST FIPS 140-2: Security Requirements for Cryptographic Modules

### IETF RFCs
- RFC 9019: SUIT (Software Updates for Internet of Things)
- RFC 8949: Concise Binary Object Representation (CBOR)
- RFC 8949: COSE (CBOR Object Signing and Encryption)
- RFC 3161: Time-Stamp Protocol (TSP)
- RFC 5652: Cryptographic Message Syntax (CMS)
- RFC 6960: Online Certificate Status Protocol (OCSP)
- RFC 8628: OAuth 2.0 Device Authorization Grant

### OWASP
- OWASP IoT Top 10
- OWASP Firmware Security Testing Methodology
- OWASP API Security

### Industry Standards
- TCG TPM 2.0 Specification
- ARM TrustZone Documentation
- Android Verified Boot 2.0 (AVB)
- U-Boot FIT Image Documentation

---

**Document Prepared:** March 6, 2026
**Last Updated:** March 6, 2026
**Classification:** Technical Reference Document
**Intended Use:** OTA Security Architecture and Implementation Guidance
# OTA Security Implementation Code Examples

## 1. Firmware Signature Verification (Python)

### RSA-SHA256 Signature Verification

```python
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class FirmwareSignatureVerifier:
    def __init__(self, public_key_path):
        """Initialize with public key path"""
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def verify_firmware(self, firmware_path, signature_path):
        """Verify firmware signature"""
        # Read firmware binary
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()

        # Read signature
        with open(signature_path, 'rb') as f:
            signature = f.read()

        # Compute SHA-256 hash
        firmware_hash = hashlib.sha256(firmware_data).digest()

        try:
            # Verify signature
            self.public_key.verify(
                signature,
                firmware_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("✓ Signature verification successful")
            return True
        except Exception as e:
            print(f"✗ Signature verification failed: {e}")
            return False

    def get_firmware_hash(self, firmware_path):
        """Get SHA-256 hash of firmware"""
        with open(firmware_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()


# Usage Example
verifier = FirmwareSignatureVerifier('public_key.pem')
is_valid = verifier.verify_firmware('firmware.bin', 'firmware.bin.sig')
print(f"Firmware Hash: {verifier.get_firmware_hash('firmware.bin')}")
```

### EdDSA (Ed25519) Signature Verification

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import hashlib

class FirmwareEdDSAVerifier:
    def __init__(self, public_key_path):
        """Initialize with Ed25519 public key"""
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def verify_firmware(self, firmware_path, signature_path):
        """Verify firmware with Ed25519 signature"""
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()

        with open(signature_path, 'rb') as f:
            signature = f.read()

        try:
            self.public_key.verify(signature, firmware_data)
            print("✓ EdDSA signature verification successful")
            return True
        except Exception as e:
            print(f"✗ EdDSA signature verification failed: {e}")
            return False


# Generate Ed25519 key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Save keys
with open('ed25519_private.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'password')
    ))
```

---

## 2. AES-256-GCM Encryption for Firmware

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import os

class FirmwareEncryption:
    def __init__(self):
        self.key_size = 32  # 256-bit
        self.nonce_size = 12  # 96-bit (GCM recommendation)

    def derive_key(self, password, salt=None):
        """Derive AES-256 key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=100000,  # Minimum recommended
        )

        key = kdf.derive(password.encode() if isinstance(password, str) else password)
        return key, salt

    def encrypt_firmware(self, firmware_path, output_path, password):
        """Encrypt firmware with AES-256-GCM"""
        # Read firmware
        with open(firmware_path, 'rb') as f:
            plaintext = f.read()

        # Derive key
        key, salt = self.derive_key(password)

        # Generate random nonce
        nonce = os.urandom(self.nonce_size)

        # Encrypt with GCM (provides authentication)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        # Write: salt + nonce + ciphertext
        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        print(f"✓ Firmware encrypted: {output_path}")
        print(f"  Salt (hex): {salt.hex()}")
        print(f"  Nonce (hex): {nonce.hex()}")
        print(f"  Ciphertext size: {len(ciphertext)} bytes")

        return salt, nonce, len(ciphertext)

    def decrypt_firmware(self, encrypted_path, output_path, password):
        """Decrypt firmware"""
        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            ciphertext = f.read()

        # Derive key
        key, _ = self.derive_key(password, salt)

        try:
            # Decrypt
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)

            # Write decrypted firmware
            with open(output_path, 'wb') as f:
                f.write(plaintext)

            print(f"✓ Firmware decrypted: {output_path}")
            return True
        except Exception as e:
            print(f"✗ Decryption failed: {e}")
            return False


# Usage Example
enc = FirmwareEncryption()
enc.encrypt_firmware('firmware.bin', 'firmware.bin.enc', 'secure_password')
enc.decrypt_firmware('firmware.bin.enc', 'firmware.bin.dec', 'secure_password')
```

---

## 3. Device Certificate Generation

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from datetime import datetime, timedelta
import uuid

class DeviceCertificateGenerator:
    def __init__(self, ca_cert_path, ca_key_path, ca_key_password=None):
        """Initialize with CA certificate and key"""
        with open(ca_cert_path, 'rb') as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(ca_key_path, 'rb') as f:
            key_data = f.read()
            self.ca_key = serialization.load_pem_private_key(
                key_data,
                password=ca_key_password.encode() if ca_key_password else None
            )

    def generate_device_certificate(self, device_id=None, model=None,
                                   hardware_version=None, output_dir='./'):
        """Generate a device certificate"""
        if device_id is None:
            device_id = str(uuid.uuid4())

        # Generate RSA key pair (2048-bit minimum for devices)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"device-{device_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YourOrg"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365*3))

        # Add extensions
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Add custom extensions for device metadata
        device_metadata = f"DeviceID={device_id}|Model={model}|HWVer={hardware_version}"
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier((1, 3, 6, 1, 4, 1, 99999, 1)),
                value=device_metadata.encode()
            ),
            critical=False,
        )

        # Sign certificate
        cert = builder.sign(
            private_key=self.ca_key,
            algorithm=hashes.SHA256(),
        )

        # Save certificate and key
        cert_path = f"{output_dir}/device-{device_id}-cert.pem"
        key_path = f"{output_dir}/device-{device_id}-key.pem"

        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b'device_password')
            ))

        print(f"✓ Device certificate generated:")
        print(f"  Device ID: {device_id}")
        print(f"  Certificate: {cert_path}")
        print(f"  Private Key: {key_path}")

        return cert, private_key, device_id


# Usage Example
gen = DeviceCertificateGenerator('ca-cert.pem', 'ca-key.pem', 'ca_password')
cert, key, device_id = gen.generate_device_certificate(
    model="model-x",
    hardware_version="rev_c"
)
```

---

## 4. TLS Configuration for Firmware Download

```python
import ssl
import socket
from urllib.request import urlopen

class SecureFirmwareDownloader:
    def __init__(self, ca_cert_path, client_cert_path, client_key_path):
        """Initialize secure downloader with certificates"""
        self.ca_cert_path = ca_cert_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path

    def create_ssl_context(self):
        """Create TLS 1.3 context with security settings"""
        context = ssl.create_default_context()

        # TLS 1.3 minimum
        context.minimum_version = ssl.TLSVersion.TLSv1_3

        # Load CA certificate for server verification
        context.load_verify_locations(self.ca_cert_path)

        # Load client certificate for mutual TLS
        context.load_cert_chain(
            certfile=self.client_cert_path,
            keyfile=self.client_key_path,
            password=lambda: b'device_password'
        )

        # Strong cipher suites only
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')

        # Enable certificate pinning (optional)
        # context.check_hostname = True
        # context.verify_mode = ssl.CERT_REQUIRED

        return context

    def download_firmware(self, url, output_path,
                         chunk_size=8192, timeout=30):
        """Download firmware with resumable capability"""
        context = self.create_ssl_context()

        try:
            # Check for resume capability
            req = urllib.request.Request(url)
            req.add_header('Range', 'bytes=0-0')

            with urlopen(req, context=context, timeout=timeout) as response:
                supports_range = response.headers.get('Accept-Ranges') == 'bytes'

            # Download with resume support
            bytes_downloaded = 0

            with urlopen(url, context=context, timeout=timeout) as response:
                with open(output_path, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        bytes_downloaded += len(chunk)

            print(f"✓ Firmware downloaded: {output_path}")
            print(f"  Bytes downloaded: {bytes_downloaded}")
            return True

        except Exception as e:
            print(f"✗ Download failed: {e}")
            return False

    def pin_certificate(self, certificate_hash):
        """Pin certificate by SHA-256 hash"""
        # This would be implemented in a subclass
        # Stores expected certificate hash for verification
        self.pinned_hash = certificate_hash


# Usage Example
downloader = SecureFirmwareDownloader(
    ca_cert_path='ca-cert.pem',
    client_cert_path='device-cert.pem',
    client_key_path='device-key.pem'
)
downloader.download_firmware(
    url='https://updates.example.com/firmware/v2.1.5.bin',
    output_path='firmware.bin'
)
```

---

## 5. JWT Device Authentication

```python
import jwt
import json
from datetime import datetime, timedelta
import uuid

class JWTDeviceAuth:
    def __init__(self, private_key_path, public_key_path, algorithm='RS256'):
        """Initialize JWT handler with device keys"""
        with open(private_key_path, 'rb') as f:
            self.private_key = f.read()

        with open(public_key_path, 'rb') as f:
            self.public_key = f.read()

        self.algorithm = algorithm

    def generate_device_token(self, device_id, device_model, scope='firmware:download'):
        """Generate JWT token for device authentication"""
        now = datetime.utcnow()

        payload = {
            'device_id': device_id,
            'device_model': device_model,
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(hours=1)).timestamp()),
            'nonce': str(uuid.uuid4()),
            'scope': scope,
            'version': '2.0.1'
        }

        token = jwt.encode(
            payload,
            self.private_key,
            algorithm=self.algorithm
        )

        return token

    def verify_device_token(self, token):
        """Verify JWT token from device"""
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm]
            )

            # Verify expiration
            if payload['exp'] < datetime.utcnow().timestamp():
                print("✗ Token expired")
                return None

            print("✓ Token verified successfully")
            return payload

        except jwt.InvalidTokenError as e:
            print(f"✗ Token verification failed: {e}")
            return None


# Usage Example
auth = JWTDeviceAuth('device-key.pem', 'device-cert.pem')

# Generate token
token = auth.generate_device_token(
    device_id='device-uuid-12345',
    device_model='model-x'
)
print(f"Generated token: {token}")

# Verify token
payload = auth.verify_device_token(token)
if payload:
    print(f"Device ID: {payload['device_id']}")
    print(f"Scope: {payload['scope']}")
```

---

## 6. Rollback Protection (Monotonic Counter)

```python
import struct
import hashlib

class RollbackProtection:
    def __init__(self, counter_file='rollback_counter.bin'):
        """Initialize rollback protection"""
        self.counter_file = counter_file
        self.counter = self.load_counter()

    def load_counter(self):
        """Load monotonic counter from storage"""
        try:
            with open(self.counter_file, 'rb') as f:
                data = f.read(8)
                if len(data) == 8:
                    return struct.unpack('>Q', data)[0]  # Big-endian 64-bit
        except:
            pass
        return 0

    def save_counter(self, value):
        """Save counter to non-volatile storage"""
        with open(self.counter_file, 'wb') as f:
            f.write(struct.pack('>Q', value))

    def verify_update(self, manifest):
        """Verify update manifest against rollback protection"""
        manifest_version = manifest.get('version')
        manifest_counter = manifest.get('counter')
        manifest_timestamp = manifest.get('timestamp')

        # Verify sequence number
        if manifest_counter <= self.counter:
            print(f"✗ Rollback attempt detected!")
            print(f"  Current counter: {self.counter}")
            print(f"  Manifest counter: {manifest_counter}")
            return False

        # Verify version is greater than current
        if manifest_version <= self.load_current_version():
            print(f"✗ Version downgrade detected: {manifest_version}")
            return False

        print("✓ Rollback protection check passed")
        return True

    def commit_update(self, new_counter):
        """Commit update and increment counter"""
        self.counter = new_counter
        self.save_counter(new_counter)
        print(f"✓ Counter incremented to: {new_counter}")

    def load_current_version(self):
        """Load current firmware version"""
        # This would read from device firmware header
        return 202  # Version 2.0.1 as integer


# Usage Example
rollback_protection = RollbackProtection()

manifest = {
    'version': '2.1.5',
    'counter': 42,
    'timestamp': '2026-03-06T10:30:00Z'
}

if rollback_protection.verify_update(manifest):
    # Installation successful
    rollback_protection.commit_update(42)
```

---

## 7. Firmware Hash Verification

```python
import hashlib
import hmac

class FirmwareIntegrity:
    def __init__(self):
        self.hash_algorithm = hashlib.sha256

    def compute_hash(self, firmware_path):
        """Compute SHA-256 hash of firmware"""
        hash_obj = self.hash_algorithm()

        with open(firmware_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def compute_hmac(self, firmware_path, secret_key):
        """Compute HMAC-SHA256 for firmware authentication"""
        hmac_obj = hmac.new(
            secret_key.encode() if isinstance(secret_key, str) else secret_key,
            digestmod=self.hash_algorithm
        )

        with open(firmware_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hmac_obj.update(chunk)

        return hmac_obj.hexdigest()

    def verify_firmware_integrity(self, firmware_path, expected_hash):
        """Verify firmware hash matches expected value"""
        computed_hash = self.compute_hash(firmware_path)

        if computed_hash.lower() == expected_hash.lower():
            print(f"✓ Firmware integrity verified")
            print(f"  Hash: {computed_hash}")
            return True
        else:
            print(f"✗ Firmware integrity check failed!")
            print(f"  Expected: {expected_hash}")
            print(f"  Computed: {computed_hash}")
            return False

    def create_manifest_hash(self, manifest_dict):
        """Create hash of update manifest"""
        manifest_json = json.dumps(manifest_dict, sort_keys=True)
        return self.hash_algorithm(manifest_json.encode()).hexdigest()


# Usage Example
import json
integrity = FirmwareIntegrity()

# Compute hash
firmware_hash = integrity.compute_hash('firmware.bin')
print(f"Firmware SHA-256: {firmware_hash}")

# Verify integrity
manifest = {
    'version': '2.1.5',
    'hash': firmware_hash,
    'size': 2097152
}

integrity.verify_firmware_integrity('firmware.bin', firmware_hash)

# Create manifest hash
manifest_hash = integrity.create_manifest_hash(manifest)
print(f"Manifest hash: {manifest_hash}")
```

---

## 8. Device Provisioning (Zero-Touch)

```python
import requests
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class ZeroTouchProvisioning:
    def __init__(self, provisioning_server_url, ca_cert_path):
        """Initialize ZTP client"""
        self.server_url = provisioning_server_url
        self.ca_cert_path = ca_cert_path

    def get_device_info(self):
        """Get device metadata for provisioning"""
        return {
            'mac_address': '00:1A:2B:3C:4D:5E',  # From NIC
            'serial_number': 'DEVICE-SN-12345',  # From OTP/Secure storage
            'model': 'model-x',
            'hardware_version': 'rev_c',
            'firmware_version': '1.0.0'
        }

    def request_certificate(self):
        """Request device certificate from provisioning server"""
        device_info = self.get_device_info()

        # Generate temporary CSR (Certificate Signing Request)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        csr_data = {
            'device_info': device_info,
            'public_key': private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }

        try:
            response = requests.post(
                f"{self.server_url}/api/v1/provision/certificate",
                json=csr_data,
                verify=self.ca_cert_path,
                timeout=30
            )

            if response.status_code == 200:
                cert_response = response.json()

                # Save certificate and key
                with open('device-cert.pem', 'wb') as f:
                    f.write(cert_response['certificate'].encode())

                with open('device-key.pem', 'wb') as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))

                print("✓ Certificate provisioned successfully")
                return True
            else:
                print(f"✗ Provisioning failed: {response.status_code}")
                return False

        except Exception as e:
            print(f"✗ Provisioning error: {e}")
            return False


# Usage Example
provisioner = ZeroTouchProvisioning(
    provisioning_server_url='https://provision.example.com',
    ca_cert_path='ca-cert.pem'
)
provisioner.request_certificate()
```

---

## 9. OTA Update State Machine

```python
from enum import Enum
from datetime import datetime

class UpdateState(Enum):
    IDLE = "idle"
    CHECKING = "checking"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    STAGING = "staging"
    INSTALLING = "installing"
    VALIDATING = "validating"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLBACK = "rollback"

class OTAUpdateStateMachine:
    def __init__(self):
        self.current_state = UpdateState.IDLE
        self.previous_state = None
        self.error_message = None
        self.timestamps = {}
        self.firmware_path = None

    def transition(self, new_state):
        """Transition to new state"""
        self.previous_state = self.current_state
        self.current_state = new_state
        self.timestamps[new_state] = datetime.utcnow()

        print(f"State transition: {self.previous_state.value} → {new_state.value}")

        # Log state transition
        self._log_transition()

    def check_for_updates(self):
        """Check for available updates"""
        self.transition(UpdateState.CHECKING)
        # Query update server
        return {'version': '2.1.5', 'available': True}

    def download_firmware(self):
        """Download firmware"""
        if self.current_state != UpdateState.CHECKING:
            self.set_error("Invalid state for download")
            return False

        self.transition(UpdateState.DOWNLOADING)
        # Perform download
        return True

    def verify_firmware(self):
        """Verify firmware signature and hash"""
        if self.current_state != UpdateState.DOWNLOADING:
            self.set_error("Invalid state for verification")
            return False

        self.transition(UpdateState.VERIFYING)
        # Perform verification
        return True

    def stage_firmware(self):
        """Stage firmware in inactive partition"""
        if self.current_state != UpdateState.VERIFYING:
            self.set_error("Invalid state for staging")
            return False

        self.transition(UpdateState.STAGING)
        # Copy to inactive partition
        return True

    def install_firmware(self):
        """Install staged firmware"""
        if self.current_state != UpdateState.STAGING:
            self.set_error("Invalid state for installation")
            return False

        self.transition(UpdateState.INSTALLING)
        # Switch boot partition
        return True

    def validate_installation(self):
        """Validate installation after boot"""
        if self.current_state != UpdateState.INSTALLING:
            self.set_error("Invalid state for validation")
            return False

        self.transition(UpdateState.VALIDATING)
        # Perform self-checks
        return True

    def mark_success(self):
        """Mark update as successful"""
        if self.current_state != UpdateState.VALIDATING:
            self.set_error("Invalid state for success")
            return False

        self.transition(UpdateState.SUCCESS)
        print("✓ Update completed successfully")
        return True

    def mark_failed(self, error_msg):
        """Mark update as failed"""
        self.error_message = error_msg
        self.transition(UpdateState.FAILED)
        print(f"✗ Update failed: {error_msg}")

    def rollback_firmware(self):
        """Rollback to previous firmware"""
        self.transition(UpdateState.ROLLBACK)
        print("Rolling back to previous firmware version...")
        self.transition(UpdateState.IDLE)

    def set_error(self, error_msg):
        """Set error message"""
        self.error_message = error_msg
        self.transition(UpdateState.FAILED)

    def _log_transition(self):
        """Log state transition for audit trail"""
        log_entry = {
            'timestamp': self.timestamps[self.current_state].isoformat(),
            'from_state': self.previous_state.value,
            'to_state': self.current_state.value,
            'error': self.error_message
        }
        print(f"Audit: {json.dumps(log_entry)}")

    def get_status(self):
        """Get current update status"""
        return {
            'state': self.current_state.value,
            'previous_state': self.previous_state.value if self.previous_state else None,
            'error': self.error_message,
            'progress_timestamps': {
                k.value: v.isoformat()
                for k, v in self.timestamps.items()
            }
        }


# Usage Example
ota_state = OTAUpdateStateMachine()

try:
    ota_state.check_for_updates()
    ota_state.download_firmware()
    ota_state.verify_firmware()
    ota_state.stage_firmware()
    ota_state.install_firmware()
    ota_state.validate_installation()
    ota_state.mark_success()
except Exception as e:
    ota_state.mark_failed(str(e))
    ota_state.rollback_firmware()

print(json.dumps(ota_state.get_status(), indent=2))
```

---

## 10. Audit Logging

```python
import json
import logging
from datetime import datetime
from pathlib import Path

class OTAAuditLogger:
    def __init__(self, log_file='ota_audit.log'):
        """Initialize audit logger"""
        self.log_file = log_file
        self.setup_logger()

    def setup_logger(self):
        """Setup structured logging"""
        self.logger = logging.getLogger('OTA_Audit')
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler(self.log_file)
        handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)

    def log_update_event(self, event_type, device_id, device_model,
                         firmware_version, status, details=None):
        """Log OTA update event"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'device_id': device_id,
            'device_model': device_model,
            'firmware_version': firmware_version,
            'status': status,
            'details': details or {}
        }

        self.logger.info(json.dumps(event))

    def log_security_event(self, event_type, device_id, severity,
                          reason, ip_address=None):
        """Log security-related event"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': f'SECURITY_{event_type}',
            'device_id': device_id,
            'severity': severity,
            'reason': reason,
            'ip_address': ip_address,
            'anonymized': True
        }

        self.logger.warning(json.dumps(event))

    def log_signature_verification(self, device_id, firmware_hash,
                                  signature_valid, key_id):
        """Log signature verification result"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'SIGNATURE_VERIFICATION',
            'device_id': device_id,
            'firmware_hash': firmware_hash,
            'signature_valid': signature_valid,
            'key_id': key_id
        }

        self.logger.info(json.dumps(event))


# Usage Example
audit_logger = OTAAuditLogger()

audit_logger.log_update_event(
    event_type='UPDATE_CHECK',
    device_id='device-uuid-12345',
    device_model='model-x',
    firmware_version='2.0.1',
    status='success',
    details={'available_version': '2.1.5'}
)

audit_logger.log_security_event(
    event_type='UNAUTHORIZED_ACCESS',
    device_id='device-uuid-67890',
    severity='high',
    reason='Invalid certificate',
    ip_address='192.168.x.x'
)

audit_logger.log_signature_verification(
    device_id='device-uuid-12345',
    firmware_hash='abc123def456...',
    signature_valid=True,
    key_id='prod-signing-key-2026'
)
```

---

**Code Examples Repository**
These examples provide starting points for implementing OTA security.
All code should be thoroughly tested and reviewed before production deployment.
# OTA Security: Quick Reference Guide & Checklists

## Executive Summary

This document provides quick reference materials for implementing and validating OTA security for IoT devices.

---

## Section 1: Security Decision Tree

### Choose Your OTA Architecture

```
START: Building OTA System?
  │
  ├─ Is this a large-scale consumer IoT device? (millions deployed)
  │  YES → Use cloud OTA service (Google, AWS, Azure)
  │        Benefits: Managed, scalable, battle-tested
  │        See: Section 5.1-5.3 in main guide
  │
  ├─ Is this embedded Linux (gateway, edge device)?
  │  YES → Use RAUC or swupdate
  │        Benefits: Flexible, open-source, mature
  │        See: U-Boot FIT images in Section 8.4
  │
  ├─ Is this a constrained IoT device (8-64 MB RAM)?
  │  YES → Use SUIT manifests (RFC 9019)
  │        Benefits: Minimal overhead, CBOR-based
  │        See: Section 5.4
  │
  └─ Custom/proprietary platform?
     YES → Design custom OTA framework
            Must implement ALL items in main guide
            Use SUIT or Google OTA as reference
```

### Choose Your Signing Algorithm

```
START: Select Digital Signature Algorithm
  │
  ├─ High-security banking/healthcare?
  │  YES → RSA-4096 with offline root key in HSM
  │        Processing time: ~100-500ms
  │
  ├─ IoT device (memory-constrained)?
  │  YES → EdDSA (Ed25519)
  │        Processing time: ~10-50ms
  │        Security: 128-bit equivalent strength
  │
  ├─ Legacy system requiring compatibility?
  │  YES → RSA-2048 minimum
  │        NOT recommended for new systems
  │        Deprecated after 2030 per NIST
  │
  └─ Mobile/web application?
     YES → ECDSA (P-256) or EdDSA
            Speed: 50-100ms
            Certificate size: Small
```

### Choose Your Encryption Method

```
START: Select Firmware Encryption
  │
  ├─ Need confidentiality + authentication?
  │  YES → AES-256-GCM
  │        ✓ Provides both properties in one algorithm
  │        ✓ NIST approved
  │        ✓ Widely implemented
  │
  ├─ Very constrained device (8-bit MCU)?
  │  YES → Consider ChaCha20-Poly1305 or
  │        AES-128-GCM (weaker but faster)
  │        Note: Monitor cryptanalytic progress
  │
  └─ Already using other encryption?
     → Must be: NIST-approved, authenticated encryption
               Do NOT use: ECB, CBC without HMAC, custom crypto
```

### Choose Your Authentication Method

```
START: Select Device Authentication
  │
  ├─ Device has certificate infrastructure?
  │  YES → Use mTLS (Mutual TLS) with device certificates
  │        ✓ Industry standard
  │        ✓ Hardware certificate storage available
  │
  ├─ Device provisioned but no cert infrastructure?
  │  YES → Use JWT tokens with shared keys
  │        ✓ Lightweight
  │        ✓ Can use device ID + nonce
  │
  ├─ Many disparate devices, limited provisioning?
  │  YES → Use OAuth 2.0 Device Flow (RFC 8628)
  │        ✓ User authorization required
  │        ✓ Suitable for consumer IoT
  │
  └─ Offline devices requiring autonomous auth?
     YES → Pre-shared secrets stored in device
            Rotate regularly (every 90-180 days)
            Monitor for key compromise
```

---

## Section 2: Implementation Checklists

### Phase 1: Planning & Architecture (Week 1-2)

- [ ] Define security requirements
  - [ ] Specify threat model (who are attackers?)
  - [ ] Identify critical assets (firmware, private keys)
  - [ ] Document risk tolerance

- [ ] Select OTA architecture
  - [ ] Choose platform (cloud, embedded, custom)
  - [ ] Document scalability requirements
  - [ ] Plan for device heterogeneity

- [ ] Cryptographic algorithm selection
  - [ ] Choose signing algorithm (RSA, ECDSA, EdDSA)
  - [ ] Choose encryption algorithm (AES, ChaCha20)
  - [ ] Choose hash algorithm (SHA-256+)
  - [ ] Document all selections with justification

- [ ] Create detailed OTA design document
  - [ ] Update flow diagram
  - [ ] Security architecture diagram
  - [ ] Component specifications
  - [ ] Key management plan

### Phase 2: Key Management Infrastructure (Week 3-4)

- [ ] Procurement
  - [ ] Evaluate and select HSM vendor
  - [ ] Plan physical security (vaults, access controls)
  - [ ] Procure backup/redundancy systems
  - [ ] Budget for key backup storage

- [ ] Root CA Setup
  - [ ] Generate root key pair (4096-bit RSA or Ed448)
  - [ ] Create root certificate (20-year validity)
  - [ ] Store in airgapped, offline environment
  - [ ] Create key backup (Shamir secret sharing)
  - [ ] Document witness signatures

- [ ] HSM Configuration
  - [ ] Install and initialize HSM
  - [ ] Configure user roles and access controls
  - [ ] Test HSM operations (signing, key generation)
  - [ ] Implement audit logging
  - [ ] Schedule regular maintenance

### Phase 3: Certificate Infrastructure (Week 5-6)

- [ ] Intermediate CA Setup
  - [ ] Generate intermediate CA key pair (2048-4096 bit RSA)
  - [ ] Create intermediate CA certificate
  - [ ] Set validity to 5-10 years
  - [ ] Enable audit logging in HSM

- [ ] Firmware Signing Certificate
  - [ ] Generate signing key pair
  - [ ] Create certificate with appropriate extensions
  - [ ] Test signing workflow
  - [ ] Document key location (HSM details)

- [ ] TLS Server Certificate
  - [ ] Purchase or generate server certificate
  - [ ] Apply certificate pinning in devices
  - [ ] Test HSTS header configuration
  - [ ] Implement OCSP stapling

- [ ] Device Certificate Template
  - [ ] Create certificate template for device provisioning
  - [ ] Define device certificate extensions
  - [ ] Test device certificate generation process
  - [ ] Plan for certificate renewal (before expiry)

### Phase 4: Development & Testing (Week 7-12)

- [ ] Update Server Development
  - [ ] Implement API endpoints (check, download, status)
  - [ ] Add authentication/authorization logic
  - [ ] Implement rate limiting (>100 req/s per device)
  - [ ] Add comprehensive logging
  - [ ] Implement error handling and recovery

- [ ] Device Agent Development
  - [ ] Implement update checking logic
  - [ ] Add signature verification
  - [ ] Implement rollback protection
  - [ ] Add staged installation support
  - [ ] Test with various failure scenarios

- [ ] Testing
  - [ ] Unit tests for all crypto functions
  - [ ] Integration tests (full update flow)
  - [ ] Security tests (invalid signatures, replay attacks)
  - [ ] Stress tests (many devices, large updates)
  - [ ] Recovery tests (network failure, power loss)

### Phase 5: Security Validation (Week 13-14)

- [ ] Code Review
  - [ ] Security-focused code review by external team
  - [ ] Check for hardcoded credentials/keys
  - [ ] Verify error messages don't leak information
  - [ ] Review cryptographic library choices

- [ ] Penetration Testing
  - [ ] Test for unsigned firmware acceptance
  - [ ] Test for replay attacks
  - [ ] Test for rollback attacks
  - [ ] Test for MITM vulnerability
  - [ ] Test server-side authorization

- [ ] Compliance Verification
  - [ ] FIPS 140-2 validation (if required)
  - [ ] Common Criteria evaluation (if required)
  - [ ] Industry standard compliance (NIST, OWASP)

### Phase 6: Deployment (Week 15-16)

- [ ] Production Preparation
  - [ ] Finalize update server infrastructure
  - [ ] Configure CDN for firmware distribution
  - [ ] Implement monitoring and alerting
  - [ ] Create incident response procedures

- [ ] Staged Deployment
  - [ ] Deploy to 1% of device fleet
  - [ ] Monitor for issues (24 hours)
  - [ ] Expand to 5% (24 hours)
  - [ ] Expand to 25% (48 hours)
  - [ ] Expand to 100%

- [ ] Documentation
  - [ ] Create operations manual
  - [ ] Document troubleshooting procedures
  - [ ] Create disaster recovery playbook
  - [ ] Brief support team

---

## Section 3: Security Configuration Templates

### Firmware Signing Configuration

```
Algorithm:        RSA-2048 minimum, RSA-4096 recommended, EdDSA-Ed25519
Hash:            SHA-256
Signing Key:     Stored in FIPS 140-2 Level 3+ HSM
Key Validity:    3-5 years
Signature Mode:  PKCS#1 v1.5 (RSA) or PureEd25519 (EdDSA)
Verification:    On device bootloader and update agent
```

### TLS Configuration

```
Protocol:        TLS 1.3 (minimum TLS 1.2)
Certificate:     ECDSA P-256+ or RSA-2048+
Cipher Suite:    TLS_AES_256_GCM_SHA384 (preferred)
PFS:             Enabled (ECDHE recommended)
Session Tickets: Disabled or encrypted with rotation
HSTS:            max-age=31536000; includeSubDomains
Certificate Pin: Yes (SHA-256 public key pin)
OCSP Stapling:   Yes
```

### Key Derivation Configuration

```
Algorithm:       PBKDF2-HMAC-SHA256 or Argon2id
PBKDF2:
  Iterations:   100,000 minimum (250,000+ recommended)
  Salt:         128-bit random, unique per key
  Output:       256-bit
Argon2id:
  Memory:       65,536 KiB (desktop), 16-32 MiB (IoT)
  Time:         3 iterations
  Parallelism:  4 threads
  Salt:         128-bit random
  Output:       256-bit
```

### Device Provisioning Configuration

```
Provisioning Method:     Zero-Touch (ZTP)
Transport:               TLS 1.3+ over HTTPS
Authentication:          Device serial number validation
Certificate Type:        X.509 v3
Certificate Validity:    3-5 years
Key Storage:             TEE/SE/Secure Element
Device ID:               UUID or SHA-256(serial+mac)
Provisioning Server CA:  Pinned in device firmware
```

---

## Section 4: Cryptographic Algorithm Quick Reference

### Approved Algorithms (NIST SP 800-131A)

```
SIGNING (Digital Signatures)
├─ RSA
│  ├─ Minimum: 2048-bit (transitioning out)
│  ├─ Recommended: 3072-bit or 4096-bit
│  └─ Status: Approved, reviewed regularly
├─ ECDSA
│  ├─ Minimum: P-256 (secp256r1)
│  ├─ Recommended: P-384 or P-521
│  └─ Status: Approved
└─ EdDSA
   ├─ Ed25519 (128-bit security)
   ├─ Ed448 (224-bit security)
   └─ Status: Approved, RECOMMENDED for new systems

ENCRYPTION (Symmetric)
├─ AES (Block Cipher)
│  ├─ Key Size: 128, 192, 256-bit
│  ├─ Mode: GCM (authenticated encryption)
│  └─ Status: Approved, use 256-bit minimum
├─ ChaCha20-Poly1305
│  ├─ Key Size: 256-bit
│  └─ Status: Not NIST-approved but widely trusted
└─ AES-256-GCM STRONGLY RECOMMENDED

HASHING (Cryptographic Hash Functions)
├─ SHA-256 (FIPS 180-4)
│  ├─ Output: 256-bit
│  └─ Status: Approved, minimum for new systems
├─ SHA-384 (FIPS 180-4)
│  ├─ Output: 384-bit
│  └─ Status: Approved, high security
├─ SHA-3-256
│  ├─ Output: 256-bit
│  └─ Status: Approved, considered more secure
└─ SHA-1: DEPRECATED (except legacy)

KEY DERIVATION
├─ PBKDF2
│  ├─ Minimum: 100,000 iterations
│  ├─ Recommended: 250,000+ iterations
│  └─ Status: Approved
├─ Argon2id
│  ├─ Recommended settings for IoT included above
│  └─ Status: Not NIST-approved but stronger than PBKDF2
└─ PBKDF2 for compatibility, Argon2id for new systems
```

### Deprecated/Non-Recommended Algorithms

```
DO NOT USE:
├─ MD5 (Cryptographically broken)
├─ SHA-1 (Collision resistance broken, do not use)
├─ RSA < 2048-bit (Insufficient key size)
├─ ECDSA < P-256 (Insufficient key size)
├─ DES / 3DES (Insufficient key size)
├─ AES in ECB mode (No authentication)
├─ AES-CBC without authenticated MAC
├─ RC4 (Biased random number generator)
├─ Custom/proprietary cryptography (likely broken)
└─ Any non-NIST-approved algorithm for regulated systems
```

---

## Section 5: Failure Mode Analysis

### What If Firmware Signing Key Is Compromised?

```
Severity: CRITICAL
Detection Time: Varies (days to weeks)
Impact Scope: All future firmware versions

Response Actions:
1. IMMEDIATE (within 1 hour)
   ├─ Revoke signing certificate (publish CRL)
   ├─ Generate new signing key
   ├─ Notify security team and leadership
   └─ Activate incident response team

2. SHORT-TERM (within 24 hours)
   ├─ Sign emergency update with new key
   ├─ Prepare updated public certificates
   ├─ Create device update to accept new key
   └─ Coordinate with all distribution channels

3. MEDIUM-TERM (within 1 week)
   ├─ Deploy updated public key to all devices
   ├─ Verify firmware integrity on all devices
   ├─ Perform forensics on compromised key
   └─ Update certificate management procedures

4. LONG-TERM (within 1 month)
   ├─ Publish post-mortem analysis
   ├─ Implement additional controls (HSM backup)
   ├─ Rotate all related keys
   └─ Update security training
```

### What If Update Server Is Compromised?

```
Severity: CRITICAL
Detection Time: Hours to days
Impact Scope: All connected devices at risk

Mitigations in Place:
1. Code Signing: Server cannot forge valid signatures
   ├─ All firmware requires valid signature
   ├─ Signature verification in bootloader/device
   └─ Offline key prevents server compromise

2. Rollback Protection: Cannot force downgrade
   ├─ Monotonic counter on device
   ├─ Secure timestamp validation
   └─ Anti-rollback tokens

3. Rate Limiting: Limits attack scope
   ├─ Max 1 update per device per 24 hours
   ├─ Max 3 failed attempts before lockout
   └─ Throttled downloads

If Compromise Occurs:
1. Revoke server certificate immediately
2. Replace server with backup infrastructure
3. Audit all firmware served in past 30 days
4. Notify all customers of potential impact
5. Verify firmware integrity on all devices
```

### What If Device Certificate Is Compromised?

```
Severity: HIGH (single device)
Detection Time: Immediate (if monitoring)
Impact Scope: Single device

Response:
1. Revoke device certificate (add to CRL)
2. Device will fail authentication at next check
3. Manual intervention required at device location
4. Device receives new certificate
5. Update CRL distribution frequency during incident
```

### What If Network Connection Fails During Update?

```
Severity: MEDIUM
Detection Time: Immediate
Impact Scope: Single device, temporary

Handling:
1. Update agent detects connection loss
2. Staged firmware in inactive partition preserved
3. Rollback to previous firmware (no state loss)
4. Device resumes normal operation
5. Retry update at next scheduled check (24 hours)
6. Support resumable downloads for large files
   ├─ HTTP Range requests
   ├─ Checkpoint at 50% downloaded
   └─ Resume from checkpoint on reconnection
```

### What If Device Power Loss During Installation?

```
Severity: LOW (due to A/B partitioning)
Detection Time: On next boot
Impact Scope: Single device, temporary

Handling (A/B Partitioning):
1. Firmware update staged in inactive partition (A)
2. Power loss during staging: No impact on B
3. Boot continues with B (previous version)
4. At next update check: Resume staging
5. On next successful boot: Can retry installation

Handling (No A/B, Single Partition):
1. CRITICAL RISK - can brick device
2. Recovery options:
   ├─ Serial console + bootloader interface
   ├─ Emergency recovery firmware (different server)
   └─ Device return for reprogramming
3. STRONGLY RECOMMEND A/B partitioning
```

---

## Section 6: Compliance Checklist

### NIST Cybersecurity Framework (CSF)

```
IDENTIFY
├─ [ ] Maintain firmware version inventory
├─ [ ] Document device capabilities and constraints
├─ [ ] Identify critical devices (healthcare, automotive)
└─ [ ] Create device groups by update priority

PROTECT
├─ [ ] Implement TLS 1.3 for all communications
├─ [ ] Deploy digital signatures on firmware
├─ [ ] Enforce device authentication (mTLS)
├─ [ ] Implement secure boot (bootloader verification)
├─ [ ] Rate limiting on update endpoints
├─ [ ] Access controls on update servers
└─ [ ] Encryption at rest (AES-256)

DETECT
├─ [ ] Monitor update success/failure rates
├─ [ ] Alert on failed signature verification
├─ [ ] Track update deployment status
├─ [ ] Monitor for replay attacks
├─ [ ] Alert on rate limit violations
└─ [ ] Track certificate validity expiry

RESPOND
├─ [ ] Pre-staged rollback procedures
├─ [ ] Incident response plan (security update)
├─ [ ] Communication protocol (customer notification)
├─ [ ] Device quarantine capabilities
└─ [ ] Forensics data collection procedures

RECOVER
├─ [ ] Backup firmware repositories
├─ [ ] Test rollback procedures quarterly
├─ [ ] Disaster recovery plan (update server)
└─ [ ] Business continuity plan
```

### OWASP IoT Top 10 Alignment

```
I1: Weak Passwords/Authentication
    ✓ Mitigation: mTLS, device certificates, JWT tokens

I2: Insecure Network Services
    ✓ Mitigation: TLS 1.3, HTTPS only, certificate pinning

I3: Insecure Firmware
    ✓ Mitigation: Code signing, signature verification, secure boot

I4: Lack of Transport Encryption
    ✓ Mitigation: AES-256-GCM, TLS 1.3, perfect forward secrecy

I5: Use of Outdated Components
    ✓ Mitigation: Regular security updates, OTA capability

I6: Inadequate Security Logging
    ✓ Mitigation: Tamper-proof audit logging, centralized logs

I7: Weak Cryptography
    ✓ Mitigation: NIST-approved algorithms, strong key sizes

I8: Lack of Device Management
    ✓ Mitigation: Comprehensive OTA platform, status tracking

I9: Insecure Default Settings
    ✓ Mitigation: Secure defaults, hardened configurations

I10: Inadequate Physical Security
    ✓ Mitigation: TPM, TEE, secure boot, hardware protection
```

### Data Protection Regulations

```
GDPR (General Data Protection Regulation)
├─ [ ] Data processing agreement with third parties
├─ [ ] Encryption of personal data in transit (TLS 1.3)
├─ [ ] Encryption at rest (AES-256)
├─ [ ] Access controls on firmware updates
└─ [ ] Data retention policy (minimum 7 years for logs)

CCPA (California Consumer Privacy Act)
├─ [ ] Privacy notice for data collection
├─ [ ] Device tracking with consumer consent
├─ [ ] Opt-out mechanisms
└─ [ ] Data deletion procedures

HIPAA (Healthcare devices)
├─ [ ] Audit logging for all access
├─ [ ] Encryption AES-256 for PHI in transit
├─ [ ] Device authentication (certificate-based)
├─ [ ] Secure deletion of data after update
└─ [ ] Incident response procedures

PCI DSS (Payment Card Industry)
├─ [ ] TLS 1.2+ for cardholder data
├─ [ ] Access controls and authentication
├─ [ ] Vulnerability scanning/penetration testing
├─ [ ] Secure configuration standards
└─ [ ] Audit logging and monitoring
```

---

## Section 7: Performance and Bandwidth Considerations

### Update Size Optimization

```
Full Firmware Update:
├─ Typical Size: 100 MB - 2 GB
├─ Download Time (4G LTE): 10 minutes - 1 hour
├─ Bandwidth Cost: High

Delta Update (Recommended):
├─ Average Reduction: 50-90% smaller than full update
├─ Example: 2GB → 100-200 MB
├─ Download Time (4G LTE): 2-10 minutes
├─ Bandwidth Cost: 10-20x lower

Compression (Optional):
├─ Method: zstd or gzip
├─ Typical Reduction: 30-50% of original
├─ Can be combined with delta (80-95% total reduction)

Storage on Device:
├─ Minimum: Firmware size + staged copy = 2x
├─ A/B Partitioning: 2x storage minimum
├─ Recommend: 3x for safety margin
```

### Network Considerations

```
Minimum Bandwidth:
├─ LTE: 1 Mbps (adequate for mobile devices)
├─ 4G: 5 Mbps (good experience)
├─ WiFi: 10 Mbps (fast updates)
├─ Satellite: 0.5 Mbps (slow but possible)

Retry Strategy:
├─ Exponential backoff: 5s, 10s, 30s, 60s, 300s
├─ Max total timeout: 30-60 minutes
├─ Resume capability: HTTP Range requests
├─ Fallback servers: Multi-region CDN

Rate Limiting:
├─ Per device: 1 update per 24 hours (staggered)
├─ Global: 100 Gbps typical CDN capacity
├─ Concurrent: 10,000 devices simultaneously
└─ Peaks: Staged rollout (1% → 5% → 25% → 100%)
```

---

## Section 8: Troubleshooting Guide

### Device Reports Signature Verification Failure

```
Troubleshooting Steps:

1. Check device public key:
   └─ Verify key matches what's in device firmware
   └─ Check key expiration date
   └─ Verify key format (PEM, DER, etc.)

2. Check server signature:
   └─ Verify signature file format
   └─ Confirm signature algorithm matches device expectations
   └─ Check for base64 encoding issues

3. Check firmware file:
   └─ Confirm file not corrupted during download
   └─ Verify SHA-256 hash of downloaded file
   └─ Check for partial/incomplete download

4. Check time sync:
   └─ Verify device system time accuracy
   └─ Check for time-based signature validation
   └─ Sync device clock if necessary

5. Resolution:
   └─ Update device public key (publish new cert)
   └─ Re-sign firmware with correct key
   └─ Re-download firmware from server
```

### Update Hangs During Download

```
Troubleshooting Steps:

1. Check network connectivity:
   └─ Ping update server
   └─ Check device network interface (WiFi signal strength)
   └─ Verify DNS resolution

2. Check bandwidth:
   └─ Monitor actual download speed
   └─ Calculate expected time to completion
   └─ Check for network congestion

3. Check server status:
   └─ Verify server is responding to requests
   └─ Check server load and available bandwidth
   └─ Verify CDN edge server responsiveness

4. Check timeout settings:
   └─ Increase download timeout if network is slow
   └─ Implement resumable downloads
   └─ Allow retry mechanism

5. Resolution:
   └─ Switch to delta updates (smaller files)
   └─ Improve network signal (move closer to WiFi)
   └─ Schedule update for off-peak hours
```

### Device Refuses Update (Rollback Protection Active)

```
Troubleshooting Steps:

1. Check version number:
   └─ Verify new version > current version
   └─ Check for version number typo
   └─ Confirm version format matches expected

2. Check monotonic counter:
   └─ Retrieve current counter value from device
   └─ Verify manifest counter > current counter
   └─ Check counter storage (OTP, secure storage)

3. Check rollback protection tokens:
   └─ Verify token expiration
   └─ Check token signature
   └─ Confirm timestamp within acceptable range

4. Manual Override (Engineering Only):
   └─ Connect via serial console
   └─ Reset counter (if supported)
   └─ Deploy update with bypass (test only)

5. Resolution:
   └─ Increment version number correctly
   └─ Ensure counter properly updated after each update
   └─ Verify server time synchronization
```

---

**Quick Reference Last Updated:** March 6, 2026
**Version:** 1.0
