# Chapter 4: Implementation of Secure_OTA

## 4.1 Chapter Objective and Scope

In this chapter, the implementation of Secure_OTA is documented as the realization phase of the secure over-the-air firmware update architecture defined previously. The implemented system was structured as a modular, system-level composition in which the control plane, gateway, and firmware agent were developed as separable units and were subsequently integrated through authenticated HTTP interfaces, signed release metadata, and policy-governed device behavior.

Within the implementation scope, four target outcomes were addressed: authenticated operator access, secure release publication with integrity metadata, policy-aware update execution on constrained devices, and continuous runtime observability through heartbeat telemetry. The implementation narrative was intentionally centered on executable logic, interface behavior, state transitions, and operational guarantees, while design-level intent was treated only as traceability context.

A process-oriented realization strategy was adopted so that each module could be validated independently before cross-module integration was finalized. By this strategy, defects in route contracts, session handling, artifact publication, and device verification logic could be isolated to bounded subsystems. As a result, integration risk was reduced, and the reproducibility of implementation outcomes was improved for academic verification.

## 4.2 Implementation Environment and Prerequisites

The implementation environment was defined with strict runtime versions so that build behavior, dependency resolution, and test outcomes could be reproduced with minimal variance. Version precision was treated as an implementation requirement rather than a documentation accessory, because cross-runtime drift was observed to affect API and cryptographic behavior in prior iterations.

A local-first execution model was used for development and integration. In this model, all control-plane services, gateway orchestration logic, and firmware build tasks were executed on a single workstation, while device-facing behavior was validated through physical targets and simulator-assisted flows. By this setup, interface-level debugging and telemetry inspection were simplified during rapid iteration.

A prerequisite-oriented startup sequence was followed before integration tests were executed. Environment variables were provisioned first, gateway signing material was initialized next, control-plane authentication state was then validated, and only after these checks were completed were release/deployment flows exercised. Example 4.1 illustrates this prerequisite chain in operational order.

### 4.2.1 Hardware and host setup

The host platform was configured as a Windows 64-bit workstation, on which both the control plane and gateway were executed. The primary embedded target was configured as esp32dev, while additional board profiles for ESP32-S3 and ESP32-C3 were retained for compatibility and extension paths. Logical fleet representation was also maintained for ESP8266, ATmega328P, and STM32F103 in orchestration and compatibility metadata.

During implementation, hardware assumptions were explicitly constrained to serial-first onboarding and manifest-driven update execution. Initial firmware flashing was performed through serial transport, after which network OTA behavior was exercised under controlled connectivity conditions. By this staged approach, first-boot uncertainty and OTA bootstrap dependency loops were avoided.

Resource-sensitive behavior was considered at the target-device layer. It was assumed that memory headroom on embedded nodes would be limited, and therefore streaming and block-wise processing patterns were prioritized during secure package verification and flash writing. This assumption influenced both firmware logic and the design of gateway-side payload metadata.

### 4.2.2 Software stack and exact versions

The software stack and exact versions used during implementation are summarized below. These versions were recorded directly from project manifests and active runtime environments.

| Layer | Technology | Version/Configuration |
| --- | --- | --- |
| Control plane runtime | Node.js | 24.12.0 |
| Package manager | pnpm | 10.33.0 |
| Web framework | Next.js | 16.2.0 |
| UI runtime | React | 19.2.4 |
| Language | TypeScript | 5.7.3 |
| UI/tooling | Tailwind CSS | 4.2.0 |
| Local data store | nedb-promises | 6.2.3 |
| Gateway runtime | Python | 3.14.2 |
| API framework | FastAPI | 0.135.3 |
| ASGI server | Uvicorn | 0.40.0 |
| Cryptography | cryptography | 46.0.7 |
| HTTP client (test/sim) | requests | 2.33.1 |
| Firmware build tool | PlatformIO | 6.1.19 |
| Firmware framework | Arduino framework | via PlatformIO espressif32 |
| Firmware JSON parsing | ArduinoJson | ^7.0.0 |

Version pinning was applied primarily to stabilize three risk areas: API serialization behavior, cryptographic library semantics, and frontend build compatibility. It was observed that integration regressions were disproportionately introduced when only minor version changes were introduced without synchronized validation.

A dual-tool firmware workflow was present in the implementation environment. PlatformIO was used as the primary firmware build system, while serial upload orchestration in the control plane expected Arduino CLI availability via ARDUINO_CLI_PATH. This coexistence was tolerated for development continuity; however, convergence to a single canonical toolchain is recommended for production reproducibility.

### 4.2.3 Pre-configuration and operational prerequisites

Before module execution, control-plane environment variables were provisioned for host binding, admin bootstrap identity, session TTL, local datastore location, gateway URL, and optional runtime command controls. Gateway-side environment variables were configured for cache directories, key directories, signing-key identity, API key enforcement, and default release artifact behavior.

Gateway signing material was initialized at startup by load-or-create behavior. When key files were absent, Ed25519 private/public material was generated and persisted; when key files were present, they were loaded and reused. By this mechanism, release signatures were made deterministic with respect to active key identity, and verifier distribution through the public-key endpoint was enabled.

At firmware level, pre-configuration was performed through header macros covering Wi-Fi identity, backend location, API key usage, device identity, and optional secure OTA fields (AES key and public key). Example 4.1: if secure fields were not provisioned, a fallback path to plain OTA transfer was automatically selected by firmware logic, while policy controls and heartbeat telemetry remained active.

## 4.3 Realization of Core Modules

### 4.3.1 Module A: OTA_IDE control plane realization

The control plane was implemented in CODE/OTA_IDE using the Next.js App Router and a security-first API wrapper. Through the withSecureApi middleware pattern, local datastore initialization, bootstrap-admin assurance, optional route authentication, and API request logging were performed consistently across route handlers. By this centralization, per-route security divergence was reduced, and operational traces were made uniformly available.

Session management was realized through password-based authentication, server-generated session tokens, and HttpOnly cookie transport. Password material was processed using scrypt, and session tokens were persisted only as SHA-256 hashes in storage. Exposure of bearer credentials to browser scripts was thereby reduced, while server-side request authorization remained compatible with both cookie and controlled header workflows where required.

Runtime visualization was implemented through a snapshot-aggregation route that queried gateway dashboard and manifest endpoints, normalized heterogeneous fields, and emitted frontend-safe models for devices, releases, pipeline stages, events, keys, certificates, and deployments. A serial upload subsystem was also implemented as an asynchronous job pipeline, through which compile/upload states and logs were streamed to the UI. Example 4.2: a queued serial job was created, moved to compiling, transitioned to uploading, and then was terminated as success/failed with log-backed status evidence.

Figure 4.1 (illustrative placement): A runtime snapshot panel should be inserted to show synchronized fleet state, release metadata, and deployment telemetry after authenticated aggregation. In this figure, evidence should be provided that UI rendering was fed by normalized middleware payloads rather than direct component-level gateway calls.

### 4.3.2 Module B: FastAPI edge gateway realization

The gateway was implemented in src/implementation/edge_gateway.py as the orchestration and telemetry core. Route groups were realized for health probing, heartbeat ingestion, release listing/creation, deployment listing/creation, pipeline rerun, sync trigger, manifest serving, public-key serving, and binary download. Write endpoints were protected through API key enforcement when a gateway key was configured.

Release creation was realized as a deterministic transaction-like sequence: version normalization, duplicate detection, artifact resolution, payload hashing, signature generation, firmware cache write, manifest generation, pipeline synthesis, event insertion, and persisted state update. Lightweight JSON files were intentionally used for runtime persistence so that local-first operation and transparent inspection could be maintained without introducing database infrastructure overhead.

Cryptographic signing was performed with Ed25519 private key material loaded at startup, and signature output was encoded for manifest transport. Deployment logic was implemented with ASH-aware policy enforcement so that low-health targets were blocked and logged while eligible targets were advanced. Example 4.3: when a release publish request was accepted, a firmware_vX.Y.Z.bin file was written, manifest fields (sha256, signature, keyId) were produced, and the corresponding release/pipeline/event records were inserted into gateway state.

Figure 4.2 (illustrative placement): A route and signing-flow diagram should be inserted to show request entry at release creation, signing invocation, state file updates, and endpoint exposure for manifest/public-key/download retrieval.

Small code snippet reference 4.1 (appendix-linked): The sign_firmware_payload stage should be cited to show payload signing and manifest-ready encoding.

### 4.3.3 Module C: Firmware update agent realization

The firmware agent was implemented in CODE/frimware_code/esp32_ota_main/esp32_ota_main.ino as a periodic decision engine supporting pull-based backend OTA and push-based ArduinoOTA. In loop execution, update polling, heartbeat transmission, and local health-policy handling were performed repeatedly under bounded intervals. Persistent policy state was retained in Preferences/NVS to preserve behavior across reboots.

Manifest-driven update selection was realized through semantic parsing and anti-rollback logic. If remote version parity was observed, normal execution was continued; if a downgrade condition was detected, installation was blocked; if a newer version was detected and health policy allowed execution, update transfer was initiated. By this gate sequence, unnecessary flash cycles and downgrade risk were reduced.

The secure path was implemented as staged verification: header parsing, AES-256-CBC block decryption, PKCS7 validation, SHA-256 accumulation, signature verification, and flash finalization. If secure prerequisites were absent or secure checks failed, fallback to plain stream-based OTA write was attempted. Example 4.4: when secure validation failed at padding or signature stage, update abort behavior was triggered, health penalties were applied, and fallback logic was entered according to runtime configuration.

Figure 4.3 (illustrative placement): A serial trace and verification timeline should be inserted to illustrate manifest poll, secure-stage milestones, flash finalization, reboot, and post-update heartbeat confirmation.

Small code snippet reference 4.2 (appendix-linked): The block-wise secure package loop should be cited to demonstrate decrypt-verify-write behavior under constrained memory.

### 4.3.4 Inter-module integration realization

Inter-module integration was realized over authenticated HTTP and structured JSON interfaces. Gateway APIs were consumed by control-plane runtime routes for snapshot and operational actions, while firmware clients consumed manifest/download endpoints and published heartbeat telemetry. At the orchestration layer, release metadata, device state, and deployment records were connected by shared identifiers and normalized status mappings.

A publish-to-observe loop was implemented as the primary integration path. In this loop, release publication generated manifest/signature artifacts, devices polled and evaluated those artifacts under version and policy controls, heartbeat data was returned to the gateway, and aggregated runtime state was rendered in the control plane. By this loop, deployment progress and policy outcomes were made observable without requiring direct device shell access.

Failure behavior was integrated as first-class logic rather than exceptional behavior. If gateway routes were unreachable, degraded snapshot responses were produced; if deployment policy thresholds were violated, explicit blocked states were emitted; if firmware validation failed, retries and health penalties were applied before future cycles were attempted. Example 4.5: when a device entered quarantine due to low ASH, deployment attempts were blocked by gateway policy and were reflected in both deployment logs and control-plane status indicators.

## 4.4 Deviations, Challenges, and Internal Testing

### 4.4.1 Significant implementation deviations

A notable deviation from a fully centralized command path was introduced by retaining local runtime action state for selected non-critical operations (for example, auxiliary report/configuration flows), while direct gateway coupling was preserved for release, manifest, telemetry, and deployment data. By this partitioning, critical OTA control paths were stabilized while iterative UI feature work was allowed to progress.

A second deviation was introduced at the firmware tooling layer. Although PlatformIO was established as the primary build mechanism, serial upload orchestration in control-plane routes was bound to Arduino CLI conventions. This duality was accepted for development continuity; however, it was recognized that a single canonical upload/build chain should be enforced for production-grade reproducibility.

A third deviation was observed in evolving API response contracts during iterative development, particularly where legacy token-oriented checks coexisted with cookie-session behavior in selected test or utility contexts. Contract normalization was treated as an ongoing hardening task so that integration scripts, route handlers, and frontend consumers remained aligned.

### 4.4.2 Key implementation challenges and resolutions

A primary challenge was encountered in maintaining strict session security while preserving practical integration behavior. Cookie-based session transport with HttpOnly storage was adopted to reduce script-level token exposure, and route-level authorization was centralized through middleware wrappers. By this approach, session handling consistency was increased across protected APIs.

A second challenge was encountered in constrained-device cryptographic verification. Full-buffer verification was determined to be memory-inefficient for ESP-class runtime conditions, and therefore block-wise decrypt and hash-update logic was adopted with strict padding checks and explicit abort handling. Corrupted image commitment risk was thereby reduced while verification fidelity was retained.

A third challenge was encountered under unstable network conditions where repeated transient failures could drive policy state toward premature update suppression. This condition was mitigated through explicit reward/penalty balancing, quarantine threshold handling, and recovery behavior tied to health restoration. As a result, update reliability and safety policy were balanced more effectively in long-running operation.

### 4.4.3 Internal testing during realization

Internal verification was performed continuously at component and integration levels. Gateway behavior was validated through health, release, manifest, deployment, and key-distribution checks. Control-plane middleware behavior was validated through session-gated route access and normalized snapshot responses. Firmware behavior was validated through anti-rollback checks, secure-path verification outcomes, and fallback execution under induced failure conditions.

An end-to-end integration script in src/implementation/integration_smoke_test.py was used to exercise backend and frontend API flows in sequence, including release publication, heartbeat ingest, manifest retrieval, and authenticated runtime snapshot access. Rapid interface-level evidence and regression alerts were thereby obtained when route contracts or response schemas evolved.

Evidence artifacts were captured as implementation outputs rather than final evaluation claims. These artifacts included authenticated dashboard snapshots after heartbeat ingest, release responses containing manifest signature metadata, and serial traces showing secure verification and reboot completion. Figure 4.4 (illustrative placement) may be used to present one consolidated integration trace from publish to post-update heartbeat.

## 4.5 Chapter Summary and Transition

In the implementation phase, Secure_OTA was realized as a modular OTA security platform in which a Next.js control plane, a FastAPI orchestration gateway, and a policy-aware embedded update agent were integrated through authenticated and signed interfaces. Core functional requirements for release publication, manifest distribution, secure verification, telemetry aggregation, and operator observability were implemented and cross-linked.

Reproducibility was improved through explicit environment versioning, deterministic route behavior, and persisted runtime state artifacts. Safety and integrity goals were reinforced through anti-rollback enforcement, ASH-governed execution policy, and cryptographic verification stages. Remaining hardening opportunities were documented in relation to toolchain unification and contract stabilization across evolving integration surfaces.

In the next chapter, formal testing and evaluation outcomes will be presented. Functional correctness, interface reliability, security behavior under representative conditions, and observed operational limitations will be analyzed in detail to quantify implementation performance against project objectives.
