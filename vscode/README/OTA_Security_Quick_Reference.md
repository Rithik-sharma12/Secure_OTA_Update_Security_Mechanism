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
