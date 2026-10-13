# OTA IDE - GITHUB INSPIRATION REFERENCES & ARCHITECTURE

## GITHUB PROJECTS PROVIDING DESIGN INSPIRATION

### 1. **ESP_OTA_Dashboard** (ErfanDL)
**Repository**: https://github.com/ErfanDL/ESP_OTA_Dashboard
**Use For**: OTA Dashboard UI patterns, device fleet visualization

**Key Features to Adapt**:
- Web-based OTA server with Node.js backend
- Device status display with real-time updates
- Firmware upload interface
- Device management table with sorting/filtering
- Health status indicators
- Library integration example (Arduino)

**Architectural Patterns to Learn**:
- Express.js REST API structure
- WebSocket real-time updates
- Frontend dashboard with Bootstrap
- SQLite database for device storage
- SPIFFS file management

**Applicable Code Patterns**:
```typescript
// Adapt their device registration flow
POST /api/devices/register
{
  deviceId: string;
  firmwareVersion: string;
  platform: string;
  healthScore: number;
}

// Adapt their heartbeat mechanism
POST /api/devices/:id/heartbeat
{
  status: 'online' | 'offline';
  healthScore: number;
  lastUpdate: timestamp;
}
```

---

### 2. **OTA Hub DIY Example** (Hard-Stuff)
**Repository**: https://github.com/Hard-Stuff/OTA-Hub-diy-example_project
**Use For**: GitHub Releases integration, lightweight OTA architecture

**Key Features to Adapt**:
- Direct GitHub Releases integration (no custom server)
- Client-side update checking
- Manifest-based firmware delivery
- Version comparison logic
- CI/CD automation via GitHub Actions
- Support for public & private repositories

**Architectural Patterns to Learn**:
- GitHub API REST client patterns
- Release asset handling
- Semantic version comparison
- PlatformIO CI/CD integration
- Bearer token authentication

**Applicable Code Patterns**:
```typescript
// Adapt their release checking flow
async getLatestRelease(repo: string): Promise<Release> {
  const url = `https://api.github.com/repos/${repo}/releases/latest`;
  return fetch(url).then(r => r.json());
}

// Adapt their manifest structure
{
  version: 'X.Y.Z',
  sha256: 'hex_string',
  size: number,
  target_boards: ['esp32', 'esp8266'],
  signature: 'base64_string'
}
```

---

### 3. **Infineon ModusToolbox OTA** (Infineon)
**Repository**: https://github.com/Infineon/mtb-example-btsdk-ota-firmware-upgrade
**Use For**: Enterprise OTA design patterns, secure signing workflows

**Key Features to Adapt**:
- Secure signed upgrade images
- Windows peer tools for OTA
- Build system integration
- Bootloader coordination
- Safe dual-partition switching
- Rollback mechanisms

**Architectural Patterns to Learn**:
- Build-time signing integration
- Bootloader communication
- Partition management
- Safe firmware activation
- Recovery mechanisms

---

### 4. **Mongoose Web Framework** (Cesanta)
**Repository**: https://github.com/cesanta/mongoose
**Use For**: Embedded web UI patterns, OTA dashboard design

**Key Features to Adapt**:
- Professional dashboard UI patterns
- Real-time WebSocket updates
- Device configuration interfaces
- Settings panels
- Status indicators
- Chart visualizations

**UI Pattern Examples**:
- Settings panels with grouped sections
- Status LED indicators
- Progress bars for uploads
- Form validation patterns
- Data table with filtering/sorting

---

### 5. **VS Code Extension Templates**
**Repository**: https://github.com/microsoft/vscode-extension-samples
**Use For**: IDE extension patterns, UI component design

**Key Features to Adapt**:
- Sidebar navigation patterns
- Tree view components
- WebView panels
- Command palette integration
- Settings configuration
- Context menus

**Applicable Patterns**:
- Hierarchical navigation trees
- Multi-panel layouts
- Real-time data updates
- Status bar integrations

---

### 6. **GitHub Desktop** (GitHub/Desktop)
**Repository**: https://github.com/desktop/desktop
**Use For**: Professional Electron application architecture

**Key Features to Adapt**:
- React + TypeScript setup
- Electron main process architecture
- IPC communication patterns
- State management
- Git integration
- UI component library

**Architectural Patterns**:
- Component composition
- State store organization
- Service layer abstraction
- Error handling

---

## SYSTEM ARCHITECTURE DIAGRAMS

### 1. Application Architecture (Electron + React)

```
┌─────────────────────────────────────────────────────────────┐
│                    OTA IDE Application                       │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Renderer Process (React)                             │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │ Dashboard │ Build │ Sign │ Release │ Devices │  │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │ State Management (Zustand)                      │   │   │
│  │  │ ├─ App Store (settings, project)               │   │   │
│  │  │ ├─ Device Store (fleet, health)                │   │   │
│  │  │ ├─ Event Store (logs, timeline)                │   │   │
│  │  │ └─ Build Store (build status, artifacts)       │   │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │ Services & API Clients                          │   │   │
│  │  │ ├─ GitHub Service (Octokit)                    │   │   │
│  │  │ ├─ Build Service (PlatformIO)                  │   │   │
│  │  │ ├─ Crypto Service (tweetnacl)                  │   │   │
│  │  │ ├─ Device Service (REST/WebSocket)             │   │   │
│  │  │ └─ Validation Service (manifest, firmware)     │   │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
│            ↕ IPC (Inter-Process Communication) ↕             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Main Process (Node.js)                              │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │ IPC Handlers                                    │   │   │
│  │  │ ├─ File Operations (read, write, select)       │   │   │
│  │  │ ├─ Process Management (build, compile)         │   │   │
│  │  │ ├─ GitHub API                                  │   │   │
│  │  │ ├─ Cryptography (signing, key storage)         │   │   │
│  │  │ └─ System Integration (OS keychain, config)    │   │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  │  ┌────────────────────────────────────────────────┐   │   │
│  │  │ System Services                                 │   │   │
│  │  │ ├─ PlatformIO CLI (child_process)              │   │   │
│  │  │ ├─ Git CLI (child_process)                     │   │   │
│  │  │ ├─ OS Keychain (keytar)                        │   │   │
│  │  │ ├─ File System (fs module)                     │   │   │
│  │  │ └─ Config Store (electron-store)               │   │   │
│  │  └────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         ↓                    ↓                    ↓
    ┌────────────┐     ┌────────────┐     ┌─────────────┐
    │  GitHub    │     │ PlatformIO │     │ OS Keychain │
    │  REST API  │     │    CLI     │     │  / Config   │
    └────────────┘     └────────────┘     └─────────────┘
```

---

### 2. Build & Release Pipeline Flow

```
┌─────────────────────────────────────────────────────────────┐
│                  Build & Release Pipeline                    │
└─────────────────────────────────────────────────────────────┘

   ┌──────────────┐
   │ Version Input│
   └──────┬───────┘
          ↓
   ┌──────────────────────┐
   │  1. Validate Version  │ (Semantic version check)
   │  (X.Y.Z format)       │
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │  2. Run PlatformIO   │
   │     Compilation      │ (Compile all 4 platforms)
   │                      │ ├─ ATmega328P
   │                      │ ├─ ESP8266
   │                      │ ├─ ESP32
   │                      │ └─ STM32F103
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │  3. Compute SHA-256  │ (One per platform)
   │     Checksums        │
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │  4. Build manifest.  │ (JSON structure)
   │     json             │ ├─ version
   │                      │ ├─ sha256
   │                      │ ├─ size
   │                      │ ├─ target_boards
   │                      │ └─ release_date
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │  5. Ed25519 Sign     │ (Private key from keychain)
   │     Manifest         │
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │  6. Verify Signature │ (Validate immediately)
   │                      │
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │  7. Create GitHub    │ (API call)
   │     Release          │
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │  8. Upload Assets    │ (firmware binaries +
   │                      │   manifest.json)
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │  9. Publish Release  │ (Mark as published)
   │                      │
   └──────┬───────────────┘
          ↓
   ┌──────────────────────┐
   │ ✓ Pipeline Complete  │ (Ready for deployment)
   └──────────────────────┘
```

---

### 3. Device Update & Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│            Device Update & Verification Pipeline             │
└─────────────────────────────────────────────────────────────┘

   Device Polling Cycle (Every N seconds)
   
   ┌──────────────────────────┐
   │ Stage 0: Health Check    │ (Read health score from NVS)
   │ ├─ Health score < 40?    │
   │ └─ Yes → Skip, Exit      │ (Quarantine mode)
   └──────┬───────────────────┘
          ↓ (No, continue)
   
   ┌──────────────────────────┐
   │ Stage 1: Version Check   │ (GitHub API query)
   │ ├─ Fetch latest release  │
   │ ├─ Compare version tag   │
   │ └─ Newer? → Continue     │ (No newer = +1 to score)
   └──────┬───────────────────┘
          ↓ (Newer version found)
   
   ┌──────────────────────────┐
   │ Stage 2: Manifest        │ (Download & validate)
   │         Validation       │ ├─ Check required fields
   │                          │ ├─ Verify version matches
   │                          │ └─ Check file size <= max
   └──────┬───────────────────┘ (Failure → -10 to score)
          ↓ (Valid)
   
   ┌──────────────────────────┐
   │ Stage 3: Firmware        │ (Download in chunks)
   │         Download &       │ ├─ Read in 512-byte chunks
   │         Checksum         │ ├─ Stream SHA-256 update
   │                          │ └─ Compare final checksum
   └──────┬───────────────────┘ (Mismatch → -20 to score)
          ↓ (Checksum OK)
   
   ┌──────────────────────────┐
   │ Stage 4: Signature       │ (Ed25519 verification)
   │         Verification     │ ├─ Load public key from flash
   │                          │ ├─ Verify Ed25519 signature
   │                          │ └─ Signed by developer?
   └──────┬───────────────────┘ (Failure → -30 to score)
          ↓ (Signature valid)
   
   ┌──────────────────────────┐
   │ Stage 5: Safe            │ (Dual-partition switching)
   │         Installation     │ ├─ Already in secondary partition
   │         & Self-Test      │ ├─ Boot into new firmware
   │                          │ ├─ Run self-test
   │                          │ └─ Test passed? Commit new version
   └──────┬───────────────────┘ (Failure → -25 to score)
          ↓
   
   ┌──────────────────────────┐
   │ ✓ Update Complete        │ (+10 to score)
   │ New firmware active      │ Version stored, ready for next cycle
   └──────────────────────────┘
```

---

### 4. State Management & Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    State Management                          │
└─────────────────────────────────────────────────────────────┘

┌─ App Store ─────────────────────────────────────────────────┐
│ ├─ projectPath: string                                       │
│ ├─ projectVersion: string                                    │
│ ├─ githubToken: string                                       │
│ ├─ githubRepo: { owner, name }                               │
│ ├─ buildTimeout: number                                      │
│ ├─ devicePollingInterval: number                             │
│ └─ Methods: setProjectPath(), setGithubToken(), etc.        │
└──────────────────────────────────────────────────────────────┘

┌─ Device Store ──────────────────────────────────────────────┐
│ ├─ devices: Device[]                                         │
│ ├─ selectedDevices: string[] (IDs)                           │
│ ├─ deviceFilter: { platform?, status?, healthRange? }        │
│ ├─ deviceSort: { field, direction }                          │
│ └─ Methods: addDevice(), updateDevice(), setFilter(), etc.  │
└──────────────────────────────────────────────────────────────┘

┌─ Event Store ───────────────────────────────────────────────┐
│ ├─ events: DeviceEvent[]                                     │
│ ├─ eventFilter: { type?, deviceId?, timeRange? }             │
│ ├─ eventSort: { field, direction }                           │
│ └─ Methods: addEvent(), filterEvents(), getEventStats()     │
└──────────────────────────────────────────────────────────────┘

┌─ Build Store ───────────────────────────────────────────────┐
│ ├─ buildStatus: 'idle' | 'building' | 'success' | 'failed'  │
│ ├─ buildProgress: { platform: string, progress: number }[]  │
│ ├─ buildArtifacts: { platform, binary, size }[]              │
│ ├─ buildLogs: string                                         │
│ ├─ buildHistory: BuildResult[]                               │
│ └─ Methods: startBuild(), updateProgress(), cancelBuild()   │
└──────────────────────────────────────────────────────────────┘

                          ↓ (Data subscriptions)
                    
┌─────────────────────────────────────────────────────────────┐
│              UI Components (React)                           │
│ ├─ useAppStore() hook in Dashboard                          │
│ ├─ useDeviceStore() hook in Device pages                    │
│ ├─ useEventStore() hook in Event pages                      │
│ └─ useBuildStore() hook in Build pages                      │
└─────────────────────────────────────────────────────────────┘
```

---

### 5. IPC Communication Pattern

```
┌─────────────────────────────────────────────────────────────┐
│              IPC Channel Communication                       │
└─────────────────────────────────────────────────────────────┘

Renderer Process (React)          Main Process (Node.js)
─────────────────────────         ──────────────────────

┌──────────────────┐              ┌──────────────────┐
│  User Action     │              │                  │
└────────┬─────────┘              │                  │
         │                        │                  │
         │ window.ipc.invoke()    │                  │
         │─────────────────────→  │ ipcMain.handle()│
         │ 'build:run'            │                  │
         │ { config... }          │ execFile()       │
         │                        │─────────────────→│
         │                        │ PlatformIO CLI   │
         │                        │←─────────────────│
         │                        │ stdout events    │
         │                        │                  │
         │←─────────────────────  │ stream to UI     │
         │ event: 'build:progress'│ mainWindow.      │
         │ { current, total }     │ webContents.send()
         │                        │                  │
         │←─────────────────────  │                  │
         │ Result                 │                  │
         │ { success, artifacts } │                  │
         │                        │                  │
         ↓                        ↓

Receive → Update State → Re-render UI
```

---

### 6. GitHub Releases Integration

```
┌─────────────────────────────────────────────────────────────┐
│           GitHub Releases Integration Flow                   │
└─────────────────────────────────────────────────────────────┘

IDE App
   ↓
1. Fetch Latest Release
   API: GET /repos/{owner}/{repo}/releases/latest
   ┌─────────────────────────────┐
   │ Release Object              │
   ├─ tag_name: "v1.0.0"         │
   ├─ assets: [                 │
   │   { name: "firmware.bin" }, │
   │   { name: "manifest.json" } │
   │ ]                           │
   └─────────────────────────────┘
   ↓
2. Compare Local vs Remote Version
   Local: "0.9.0" < Remote: "1.0.0" → Update Available
   ↓
3. Download manifest.json
   Extract: version, sha256, signature, target_boards
   ↓
4. Verify Signature
   Ed25519 verification (device-side or gateway)
   ↓
5. Download Firmware Binary
   Stream in chunks, compute checksum
   ↓
6. Install Firmware
   Write to secondary partition, reboot, self-test
   ↓
7. Report Status (optional)
   POST /api/releases/{tag}/feedback
   { deviceId, status, healthScore, duration }
```

---

### 7. Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               Security & Cryptography Layer                  │
└─────────────────────────────────────────────────────────────┘

IDE (Developer Machine)
├─ Private Key Storage
│  ├─ macOS: Keychain
│  ├─ Windows: Credential Manager
│  ├─ Linux: Secret Service
│  └─ Encrypted File (fallback)
│  └─ NEVER in plaintext
│
├─ Signing Process
│  ├─ Read private key from keychain
│  ├─ Create manifest (version, sha256, size)
│  ├─ Ed25519 sign manifest
│  ├─ Return signature (never expose private key)
│  └─ Store in manifest.json
│
└─ Public Key Distribution
   ├─ Extract public key (32 bytes, hex or PEM)
   ├─ Compile into device firmware
   └─ Device uses for signature verification

Device (ATmega328P / ESP8266 / ESP32 / STM32F103)
├─ Public Key Storage (Program Flash)
│  └─ Immutable after programming
│
├─ Signature Verification
│  ├─ Load manifest.json
│  ├─ Extract signature (Base64 → bytes)
│  ├─ Load public key from flash
│  ├─ Ed25519 verify (1.5 KB RAM peak)
│  └─ Proceed if valid, reject if invalid
│
└─ Health Score & Quarantine
   ├─ -30 points for signature failure
   ├─ Detect 3+ failures in 1 hour
   ├─ Enter quarantine < 40 points
   └─ Require manual reset to recover

Threat Model Addressed
├─ Man-in-the-middle: TLS + Ed25519 signature
├─ Firmware tampering: SHA-256 checksum + signature
├─ Rollback attacks: Version number comparison
├─ Repeated attacks: Health score penalties
└─ Key compromise: Rotation + firmware update needed
```

---

## COMPONENT ARCHITECTURE

```
OTA IDE/
├─ components/
│  ├─ Layout/
│  │  ├─ TopBar.tsx
│  │  ├─ Sidebar.tsx
│  │  ├─ TabBar.tsx
│  │  └─ StatusBar.tsx
│  │
│  ├─ Dashboard/
│  │  ├─ ProjectSummary.tsx
│  │  ├─ DeviceFleetOverview.tsx
│  │  ├─ ActivityTimeline.tsx
│  │  └─ QuickStats.tsx
│  │
│  ├─ Build/
│  │  ├─ BuildConfig.tsx
│  │  ├─ BuildProgress.tsx
│  │  ├─ BuildResults.tsx
│  │  └─ BuildHistory.tsx
│  │
│  ├─ Sign/
│  │  ├─ KeyManager.tsx
│  │  ├─ ManifestBuilder.tsx
│  │  ├─ ManifestPreview.tsx
│  │  └─ SigningStatus.tsx
│  │
│  ├─ Release/
│  │  ├─ GitHubConnection.tsx
│  │  ├─ ReleaseForm.tsx
│  │  ├─ AssetUploader.tsx
│  │  └─ ReleaseHistory.tsx
│  │
│  ├─ Devices/
│  │  ├─ DeviceTable.tsx
│  │  ├─ DeviceRow.tsx
│  │  ├─ StatusIndicators.tsx
│  │  └─ HealthScoreBar.tsx
│  │
│  ├─ Events/
│  │  ├─ EventTimeline.tsx
│  │  ├─ EventCard.tsx
│  │  ├─ EventFilters.tsx
│  │  └─ EventExport.tsx
│  │
│  ├─ Health/
│  │  ├─ HealthScoreCard.tsx
│  │  ├─ HealthTrendChart.tsx
│  │  ├─ FleetHealthOverview.tsx
│  │  └─ HealthExplanation.tsx
│  │
│  ├─ Quarantine/
│  │  ├─ QuarantineBoard.tsx
│  │  ├─ QuarantineDetail.tsx
│  │  ├─ RecoveryControls.tsx
│  │  └─ RecoveryLog.tsx
│  │
│  └─ Common/
│     ├─ Button.tsx
│     ├─ Input.tsx
│     ├─ Modal.tsx
│     ├─ Table.tsx
│     ├─ Chart.tsx
│     └─ LoadingSpinner.tsx
│
├─ services/
│  ├─ buildService.ts
│  ├─ cryptoService.ts
│  ├─ githubService.ts
│  ├─ deviceService.ts
│  ├─ healthScoreService.ts
│  ├─ validationService.ts
│  ├─ reportingService.ts
│  ├─ diagnosticsService.ts
│  ├─ simulatorService.ts
│  └─ keyManagementService.ts
│
├─ stores/
│  ├─ appStore.ts
│  ├─ deviceStore.ts
│  ├─ eventStore.ts
│  ├─ buildStore.ts
│  └─ deploymentStore.ts
│
├─ utils/
│  ├─ versionComparison.ts
│  ├─ checksumCalculation.ts
│  ├─ dateFormatting.ts
│  ├─ errorHandling.ts
│  └─ validation.ts
│
├─ hooks/
│  ├─ useAppStore.ts
│  ├─ useDeviceStore.ts
│  ├─ useFetch.ts
│  ├─ useDebounce.ts
│  └─ usePersistentState.ts
│
├─ styles/
│  ├─ globals.css
│  ├─ tailwind.config.ts
│  ├─ design-tokens.ts
│  └─ animations.css
│
├─ types/
│  ├─ index.ts
│  ├─ device.ts
│  ├─ firmware.ts
│  ├─ manifest.ts
│  ├─ event.ts
│  └─ github.ts
│
└─ ipc/
   ├─ channels.ts
   ├─ handlers.ts
   └─ preload.ts
```

---

## DATABASE SCHEMA (If Using SQLite)

```sql
-- Devices Table
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  firmware_version TEXT NOT NULL,
  health_score INTEGER DEFAULT 100,
  status TEXT DEFAULT 'offline',
  last_seen TIMESTAMP,
  ip_address TEXT,
  last_update_time TIMESTAMP,
  failed_attempts_24h INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Device Events Table
CREATE TABLE device_events (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  type TEXT NOT NULL,
  description TEXT,
  score_change INTEGER,
  details JSON,
  FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- Build History Table
CREATE TABLE build_history (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status TEXT,
  duration_seconds INTEGER,
  artifacts JSON,
  logs TEXT
);

-- Release History Table
CREATE TABLE releases (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL UNIQUE,
  github_release_id INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  published_at TIMESTAMP,
  status TEXT,
  notes TEXT,
  assets JSON
);

-- Deployments Table
CREATE TABLE deployments (
  id TEXT PRIMARY KEY,
  release_id TEXT NOT NULL,
  start_time TIMESTAMP,
  end_time TIMESTAMP,
  target_devices INTEGER,
  successful_devices INTEGER,
  failed_devices INTEGER,
  strategy TEXT,
  status TEXT,
  FOREIGN KEY (release_id) REFERENCES releases(id)
);

-- Health Score History
CREATE TABLE health_score_history (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  timestamp TIMESTAMP,
  score INTEGER,
  FOREIGN KEY (device_id) REFERENCES devices(id)
);
```

---

## RECOMMENDED DEVELOPMENT WORKFLOW

```
1. Setup Phase (Week 1)
   ├─ Initialize project structure
   ├─ Configure build system (Vite + Electron)
   ├─ Set up state management (Zustand)
   └─ Establish coding standards (ESLint, Prettier)

2. Feature Development (Weeks 2-16)
   ├─ Implement by epic (parallel development)
   ├─ Write unit tests as you go
   ├─ Daily code reviews
   └─ Weekly integration testing

3. Testing Phase (Week 17)
   ├─ Run full test suite
   ├─ Performance testing
   ├─ Security audit
   └─ User acceptance testing

4. Release Phase (Week 18)
   ├─ Create distribution packages
   ├─ Write release notes
   ├─ Tag v1.0.0 in Git
   └─ Publish on GitHub releases
```

---

## CONTINUOUS INTEGRATION SETUP

```yaml
# .github/workflows/build-and-test.yml
name: Build & Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: npm ci
      
      - name: Lint
        run: npm run lint
      
      - name: Build
        run: npm run build
      
      - name: Unit tests
        run: npm run test:unit
      
      - name: Integration tests
        run: npm run test:integration
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
      
      - name: Build Electron app
        run: npm run build:electron
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
```

---

This architecture provides a solid foundation for building the Secure Heterogeneous OTA Update Mechanism IDE. The design emphasizes separation of concerns, security by default, and user experience while maintaining scalability and extensibility for future enhancements.