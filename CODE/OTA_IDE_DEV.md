# Secure Heterogeneous OTA Update Mechanism - Custom IDE Development

## PROJECT VISION
Build a specialized, full-featured GUI IDE for managing, signing, releasing, and monitoring Secure Heterogeneous OTA firmware updates across four target hardware platforms (ATmega328P, ESP8266, ESP32, STM32F103) with zero-cost infrastructure using GitHub Releases as the distribution backend.

---

## COMPREHENSIVE FEATURE SPECIFICATION

### TIER 1: CORE MANAGEMENT FEATURES

#### 1.1 Project Dashboard & Overview
**Purpose**: Central hub showing complete project and deployment status at a glance

**UI Components**:
- **Project Summary Card**: Display project name, current version, last update time, total devices
- **Repository Status**: GitHub repo connection status, branch info, latest commit, remote URL
- **Device Fleet Overview**:
  - Total devices count by platform (ATmega328P, ESP8266, ESP32, STM32F103)
  - Color-coded health status (Green: Healthy, Yellow: Warning, Red: Quarantined)
  - Real-time connected devices indicator
  - Map visualization of device geographical distribution (if location data available)
- **Recent Activity Timeline**: Last 10 events (releases created, devices updated, quarantines triggered)
- **Quick Stats**:
  - Update success rate (%)
  - Average update time (seconds)
  - Devices in quarantine count
  - Failed update attempts (last 24h)

**Functionality**:
- Auto-refresh every 5 seconds for real-time data
- Click any stat to drill down into detailed view
- Export dashboard data as PDF/CSV

---

#### 1.2 Firmware Build & Compilation Management
**Purpose**: Compile firmware from source for all four target platforms with single-click action

**UI Components**:
- **Build Configuration Panel**:
  - Target platform selector (checkboxes for ATmega328P, ESP8266, ESP32, STM32F103)
  - PlatformIO environment selector (debug/release builds)
  - Custom build flags input field
  - Source directory path selector (browse & verify)
  - Output directory configuration

- **Build Queue Display**:
  - Current builds list with progress bars per platform
  - Queue time estimates
  - Cancel button for active/queued builds
  - Build log viewer (scrollable, syntax-highlighted)

- **Build Results Panel**:
  - Binary output files list with file sizes
  - Compilation warnings/errors count and expandable list
  - Memory footprint per platform (Flash used/available, RAM used/available)
  - Build time duration
  - Success/failure status badge

**Functionality**:
- Validate `platformio.ini` before build start
- Detect missing libraries automatically and suggest installation
- Stream real-time compiler output to user
- Create downloadable build artifacts archive
- Store build history (last 20 builds with timestamps)
- Version string auto-extraction from source (git tag or version.h)

**Integration**:
- Directly call `platformio run -e esp32,esp8266,stm32,atmega328p` CLI
- Parse and display `platformio.ini` environment configs
- Detect build failures and highlight problematic lines in logs

---

#### 1.3 Cryptographic Signing Pipeline
**Purpose**: Generate secure Ed25519 signatures for firmware manifests

**UI Components**:
- **Key Management Panel**:
  - Display current public key (as hex string, first 16 chars visible + "...")
  - Key fingerprint display (SHA256 hash first 8 chars)
  - Key generation button
  - Key import dialog (paste private key - shown only once on paste)
  - Key rotation warning (if key older than 90 days)
  - Key expiration countdown (if configured)

- **Manifest Generation Interface**:
  - Auto-populated fields:
    - Version string (from build or manual entry)
    - Firmware checksum (SHA-256 computed from binary)
    - File size (auto-calculated)
    - Release date (current timestamp)
  - Manual input fields:
    - Minimum hardware revision
    - Target boards list (multi-select: atmega328p, esp8266, esp32, stm32f103)
    - Critical update flag (checkbox)
    - Rollback safe flag (checkbox)
  - Preview JSON manifest before signing
  - Sign button (shows spinning indicator during signing)

- **Signature Verification Display**:
  - Show computed Ed25519 signature (Base64 encoded)
  - Signature validity indicator (✓ Valid / ✗ Invalid)
  - Re-verify button
  - Copy signature to clipboard button

**Functionality**:
- Generate Ed25519 key pair if none exists (prompt user to store securely)
- Compute SHA-256 checksum incrementally from binary file
- Construct manifest JSON with all required fields
- Sign manifest using Ed25519 private key (private key never leaves IDE)
- Validate signature immediately against public key
- Show warnings if:
  - Version string doesn't match semantic versioning (X.Y.Z format)
  - Target boards list is empty
  - File size exceeds 2 MB (warning only, not error)

**Security Considerations**:
- Private key stored in OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- Private key never printed to logs or UI
- Signing happens locally in-process
- Public key embedded in firmware at compile time (developer must manually copy to source)

---

#### 1.4 GitHub Releases Manager
**Purpose**: Create and manage releases on GitHub with signed firmware and manifests

**UI Components**:
- **GitHub Connection Panel**:
  - Repository owner/name input fields
  - Access token input (masked, password-style)
  - "Test Connection" button with status indicator
  - Connection status display (✓ Connected / ✗ Failed)
  - Last successful connection timestamp

- **Release Creation Form**:
  - Version tag input (validates X.Y.Z format)
  - Release title auto-populated from version (editable)
  - Release notes input (markdown editor with preview)
  - Pre-release checkbox
  - Draft checkbox
  - "Create Release" button

- **Asset Upload Interface**:
  - Drag-and-drop zone for firmware binary and manifest.json files
  - File list showing uploaded assets:
    - Firmware binary (shows platform, size, checksum)
    - manifest.json (shows validation status)
  - Upload progress bars for each file
  - "Upload Assets" button

- **Release History List**:
  - Table showing last 20 releases:
    - Version tag
    - Release date
    - Asset count
    - Download count (from GitHub API)
    - Status badge (Draft/Pre-release/Stable)
  - Click to expand release details
  - Edit/delete buttons for draft releases
  - Copy asset download URL button

**Functionality**:
- Validate GitHub personal access token (scope: repo)
- Auto-fetch repository info to populate owner/name from git remote
- Validate release assets before upload:
  - Check manifest.json is valid JSON
  - Verify manifest signature matches embedded public key
  - Check firmware binary matches checksum in manifest
- Handle GitHub API rate limiting gracefully (show countdown timer)
- Auto-retry failed uploads (exponential backoff, max 3 attempts)
- Display asset download URLs after successful upload
- Generate shareable release link

---

#### 1.5 Manifest & Configuration Builder
**Purpose**: Create and validate manifest.json files with full control

**UI Components**:
- **Visual Manifest Editor**:
  - Form-based fields for each manifest property:
    - version: Semantic version input
    - sha256: Read-only (computed from binary)
    - size: Read-only (computed from binary)
    - min_hw_rev: Input field (e.g., "1.0")
    - target_boards: Multi-select checkboxes (atmega328p, esp8266, esp32, stm32f103)
    - signature: Read-only (computed after signing)
    - release_date: Date/time picker
    - critical: Toggle checkbox
    - rollback_safe: Toggle checkbox
  
- **Raw JSON Editor**:
  - Code editor with JSON syntax highlighting
  - JSON validation indicator (✓ Valid / ✗ Invalid)
  - Error messages pointing to invalid fields
  - "Format JSON" button (auto-indent)
  - Copy to clipboard button

- **Manifest Preview**:
  - Display manifest as formatted JSON
  - Highlight signature field
  - Show which platforms will accept this firmware
  - Display file size and checksum

- **Template Manager**:
  - Save current manifest as reusable template
  - Load template dropdown
  - Delete template button
  - Show template description/notes

**Functionality**:
- Validate manifest structure against project schema
- Compute SHA-256 from selected firmware binary file
- Auto-detect target boards from firmware compilation info
- Check for version duplicates in GitHub releases
- Warn if critical flag set but rollback_safe is false
- Export manifest as JSON file
- Import manifest from JSON file with validation
- Show errors inline (red underline on invalid fields)

---

### TIER 2: DEVICE MONITORING & MANAGEMENT

#### 2.1 Device Fleet Dashboard
**Purpose**: Monitor connected devices, their health scores, and update status

**UI Components**:
- **Device List View**:
  - Table with columns:
    - Device ID/Name (sortable)
    - Platform type (ATmega328P / ESP8266 / ESP32 / STM32F103)
    - Current firmware version
    - Health score (0-100 with color gradient: green→yellow→red)
    - Last seen timestamp
    - Status badge (Online/Offline/Quarantined)
  - Rows expandable to show:
    - Device IP address
    - Last successful update time
    - Failed update attempts (24h)
    - Recent events log (last 10)
  - Filter by: Platform, Status, Health Score range, Last seen range
  - Sort by: Health score, Last seen, Version, Device ID

- **Device Status Indicators**:
  - Online indicator (green dot, updates every 30 seconds)
  - Health score bar (horizontal bar chart, color-coded)
  - Update available badge
  - Quarantine warning (flashing red)
  - Update progress bar (during active update)

- **Device Health Visualization**:
  - Histogram showing health score distribution across fleet
  - Trend chart (last 7 days) showing average fleet health
  - Event count by type pie chart (successful updates, failures, quarantines)

**Functionality**:
- Poll device status endpoints every 30 seconds (configurable)
- Display real-time health score changes
- Show device event history (scrollable list):
  - Timestamp
  - Event type (Update attempted, Update failed, Signature mismatch, Quarantine entered, etc.)
  - Score change delta
- Export device list as CSV
- Bulk select devices for multi-device operations

---

#### 2.2 Device Event Logger & History
**Purpose**: Track all device events chronologically with detailed information

**UI Components**:
- **Event Timeline**:
  - Chronological list of all device events
  - Events grouped by device (with device name header)
  - Color-coded by event type:
    - Green: Successful update, Health restored
    - Yellow: Version check (no update needed), Minor warnings
    - Red: Failed update, Signature mismatch, Quarantine
    - Orange: Rollback triggered, Download interrupted
  
- **Event Detail Card** (on click):
  - Event timestamp (with timezone)
  - Event type and description
  - Device ID and platform
  - Health score before/after
  - Relevant data:
    - For updates: firmware version attempted, checksum, file size
    - For failures: error message, stage failed (1-5)
    - For quarantine: reason, previous score
  - Related events link (chain of events leading to this)

- **Event Filter Panel**:
  - Filter by: Device ID, Event type, Time range, Health impact (only negative, only positive)
  - Search by: Device ID, error message, firmware version
  - Preset filters: Last 24h, Last week, Last month, All time

- **Event Export**:
  - Export visible events as CSV/JSON
  - Date range selector
  - Include/exclude columns selector

**Functionality**:
- Stream device event data in real-time (WebSocket or polling)
- Parse and colorize event messages
- Link related events (e.g., quarantine entry followed by manual reset)
- Show event statistics:
  - Total events (24h, 7d, all time)
  - Event distribution pie chart
  - Most common errors
  - Most active devices
- Detect event patterns:
  - Flag devices with 3+ failures in 1h
  - Identify signature mismatches
  - Highlight rollback events

---

#### 2.3 Health Score Visualization & Analysis
**Purpose**: Display and interpret device health scores with historical trends

**UI Components**:
- **Individual Device Health Card**:
  - Large health score display (0-100) with color gradient background
  - Health status text (Healthy / Warning / Critical / Quarantined)
  - Score change indicator (↑/↓ with percentage from last 24h)
  - Recent event feed (last 5 events affecting score)
  - Score breakdown chart showing contributions by event type
  - Historical score graph (7-day trend line chart)

- **Fleet Health Overview**:
  - Average health score (across all devices)
  - Health distribution histogram
  - Devices by status pie chart:
    - Healthy (score 60-100)
    - Warning (score 40-59)
    - Critical (score 0-39)
    - Quarantined
  - Trend indicator (fleet health trend)

- **Health Score Explanation Panel**:
  - Show scoring rules (reference table from project):
    - +10 for successful update
    - +1 for successful poll
    - -1 for network error
    - -20 for checksum mismatch
    - -30 for signature failure
    - -25 for self-test failure
    - -15 for version mismatch
  - Explanation: "Why is device X at 45? 2 failed attempts (-40), 1 successful poll (+1)"
  - Quarantine threshold explanation (40 points)

- **Health Alerts**:
  - Devices reaching warning threshold (score < 60)
  - Devices in quarantine
  - Devices with negative trends
  - Alert notification badge (count)

**Functionality**:
- Calculate health score changes in real-time
- Detect suspicious patterns:
  - 3+ failures in 1 hour → flag as under attack
  - Repeated signature failures → flag key mismatch
  - Consistent checksum mismatches → flag corruption
- Generate health reports (PDF summary)
- Show quarantine countdown/reason
- Recommend actions for at-risk devices

---

#### 2.4 Quarantine Management Interface
**Purpose**: Manage devices in quarantine and recovery operations

**UI Components**:
- **Quarantine Status Board**:
  - List of all quarantined devices:
    - Device ID/Name
    - Quarantine entry time
    - Reason (what triggered quarantine)
    - Current health score
    - Last event timestamp
  - Sort by: Entry time (newest first), Health score, Device ID

- **Quarantine Detail Card** (expand each device):
  - Quarantine reason (e.g., "Health score fell below 40")
  - Trigger event details (what caused quarantine)
  - Recent events before quarantine (show chain leading to quarantine)
  - Recovery options:
    - Manual reset button (requires confirmation)
    - Investigate button (opens event log for device)
    - Create support ticket button (pre-fill device info)

- **Bulk Recovery Controls**:
  - Select multiple quarantined devices (checkboxes)
  - Bulk reset button (with confirmation dialog showing how many devices)
  - Filter quarantined devices by reason
  - Mass reset confirmation dialog:
    - Show count of devices to reset
    - Show all device IDs that will be reset
    - Require explicit confirmation

- **Recovery Log**:
  - Audit trail of all manual resets
  - Reset timestamp, operator, devices affected
  - Post-reset health score
  - Follow-up status (did device recover?)

**Functionality**:
- Detect and alert on devices entering quarantine
- Provide one-click manual reset (score → 100, quarantine → cleared)
- Track reset history per device
- Auto-suggestions:
  - "Device X has 5 failed signature checks in a row. Public key may be outdated."
  - "Device Y in quarantine 4 hours. Recommend investigation."
- Support notes (add notes to quarantine reason for future reference)
- Export quarantine report (devices, reasons, recovery times)

---

### TIER 3: AUTOMATION & GITHUB INTEGRATION

#### 3.1 GitHub Actions Workflow Manager
**Purpose**: Manage and monitor CI/CD workflows that automate signing and releasing

**UI Components**:
- **Workflow Configuration Panel**:
  - Display current GitHub Actions workflow file (`.github/workflows/ota-release.yml`)
  - Show workflow structure:
    - Trigger: On version tag push
    - Steps: Compile, Sign, Release
    - Secrets used: Private key reference
  - Edit workflow file button (opens in text editor)
  - Validate workflow syntax button
  - Deploy workflow button (updates .github/workflows/ in repo)

- **Workflow Execution Monitor**:
  - Last 10 workflow runs in table:
    - Tag/version that triggered run
    - Run timestamp
    - Status (Success/Failed/In Progress)
    - Duration (total time)
    - Artifacts count (firmwares + manifests)
  - Click to expand run details:
    - Individual step status (Compile ESP8266, Compile ESP32, etc.)
    - Step duration
    - Step logs (scroll-able, code-highlighted)
    - Artifacts generated
    - Status badge display

- **Workflow Logs Viewer**:
  - Real-time streaming logs during active workflow runs
  - Color-coded output (errors in red, warnings in yellow)
  - Searchable logs
  - Copy logs button
  - Download logs as text file

- **Secrets Manager**:
  - List GitHub Actions secrets (without exposing values):
    - Secret name
    - Last updated timestamp
    - Type (key, token, etc.)
  - Add/update secret dialog:
    - Secret name input
    - Secret value input (masked, password-style)
    - "Update in GitHub" button (sends to GitHub API)
    - Warning: "Private key will be stored in GitHub encrypted secrets"
  
- **Workflow Debugging**:
  - Manual trigger workflow button (for testing)
  - Input version tag for manual trigger
  - Show estimated run time
  - Cancel running workflow button

**Functionality**:
- Fetch workflow history from GitHub API (paginated)
- Parse YAML workflow file to show human-readable structure
- Stream real-time workflow logs via GitHub API polling
- Validate workflow syntax against GitHub schema
- Suggest workflow optimizations
- Create workflow file from template if not exists
- Handle workflow failures gracefully:
  - Show which step failed
  - Provide troubleshooting suggestions
  - Retry failed runs

---

#### 3.2 Automated Build Pipeline
**Purpose**: Streamline the full build → sign → release workflow

**UI Components**:
- **Pipeline Status Dashboard**:
  - Current pipeline stage indicator (visual flowchart):
    - Build → Sign → Release (arrows showing progression)
    - Each stage shows status (In Progress, Completed, Failed)
    - Colored indicators (🟢 done, 🔵 in progress, 🔴 failed)

- **One-Click Build & Release Button**:
  - Prominent "Build & Release Version X.Y.Z" button
  - Requires version input before running
  - Shows estimated total time (sum of all stages)
  - Cancel button during execution
  - Progress indicators for each sub-task:
    - Compiling for ATmega328P: ████░░ 60%
    - Compiling for ESP8266: ████████ 100%
    - Computing checksums: ████░░░░ 40%
    - Signing manifests: ░░░░░░░░ 0%
    - Creating GitHub release: ░░░░░░░░ 0%

- **Pipeline Execution Summary**:
  - After completion, show summary:
    - Total time
    - Build outputs (binary sizes per platform)
    - GitHub release URL
    - Download URLs for each platform
    - Status (✓ Success / ✗ Failed at stage X)
  
- **Rollback/Cleanup Controls**:
  - Delete release button (if something went wrong)
  - Re-run pipeline button (re-execute with same inputs)
  - Keep artifacts locally checkbox (for manual inspection)

**Functionality**:
- Execute full pipeline in sequence without user intervention
- Detect failures at each stage and halt with error message
- Provide stage-specific error recovery:
  - Build failed? Show compiler error with line number
  - Signing failed? Check private key validity
  - GitHub upload failed? Check token, rate limits, network
- Store pipeline execution history
- Export pipeline logs
- Estimate time per stage based on historical data

---

#### 3.3 Version & Release Tagging
**Purpose**: Manage semantic versioning and GitHub release tags

**UI Components**:
- **Version Management Panel**:
  - Current version display (read-only, from git tag or version.h)
  - Next version suggestion (auto-increment patch for patch releases)
  - Version input fields:
    - Major version (number)
    - Minor version (number)
    - Patch version (number)
    - Pre-release suffix (optional, e.g., "rc1", "beta2")
  - Validation indicator (✓ Valid format / ✗ Invalid)
  - Generate tag preview (shows "v2.1.0-rc1")

- **Release Notes Editor**:
  - Markdown editor with syntax highlighting
  - Preview pane (shows rendered markdown)
  - Template button (pre-fill with common sections):
    - ## What's New
    - ## Bug Fixes
    - ## Breaking Changes
    - ## Installation Instructions
  - Character count
  - Auto-save to local draft

- **Tag Creation & Management**:
  - Create tag button (local git tag + push to GitHub)
  - Recent tags list:
    - Tag name
    - Commit hash (short)
    - Tag date
    - Associated release info (if published)
  - Tag deletion button (local and remote)
  - Lightweight vs Annotated tag options

- **Version History Timeline**:
  - Visual timeline of past versions:
    - Version number
    - Release date
    - Platform support indicator (✓ for each platform)
    - Download count
    - Install success rate
    - Click to view release details

**Functionality**:
- Validate semantic versioning format (X.Y.Z with optional prerelease)
- Prevent duplicate versions (check GitHub releases)
- Auto-extract version from git tag if exists
- Generate changelog from commit messages since last tag
- Warn if attempting to release with uncommitted changes
- Suggest version bump based on changes (breaking/feature/fix)
- Create local git tag and push to remote

---

### TIER 4: ADVANCED FEATURES & INTEGRATIONS

#### 4.1 Update Deployment & Scheduling
**Purpose**: Schedule and track firmware rollout to device fleet

**UI Components**:
- **Deployment Wizard**:
  - Step 1: Select release version (dropdown from available releases)
  - Step 2: Select target devices
    - Filter by: Platform, Health score (min), Geography (if available)
    - Select all / Deselect all buttons
    - Show device count and health statistics
  - Step 3: Schedule deployment
    - Immediate deployment radio button
    - Scheduled deployment radio button with:
      - Date/time picker
      - Timezone selector
      - Recurrence options (one-time, recurring)
  - Step 4: Rollout strategy
    - All at once (risky) radio button
    - Canary deployment (N% of devices) with percentage slider
    - Staged rollout with:
      - Stage 1: N devices
      - Stage 2: N devices (on success)
      - Stage 3: Remaining devices (on success)
    - Manual approval option (require approval between stages)
  - Step 5: Notifications
    - Email on completion checkbox
    - Email on failure checkbox
    - Slack webhook URL (optional)
  - Review & Deploy button

- **Deployment Progress Monitor**:
  - Real-time progress bar (X of Y devices updated)
  - Devices by status:
    - Completed: N devices (with success rate %)
    - In Progress: N devices
    - Pending: N devices
    - Failed: N devices
  - Device-level status list (expandable):
    - Device ID
    - Update status (Pending/In Progress/Completed/Failed)
    - Progress bar (download %, signature check %, installation %)
    - Last status timestamp
  - Cancel deployment button (stops sending new updates, doesn't abort in-progress)
  - Pause deployment button (halt sending new updates, resumable)

- **Deployment History**:
  - Past deployments table:
    - Version deployed
    - Deployment start time
    - Duration (total time to complete)
    - Devices targeted / successful
    - Success rate %
    - Status (Completed/Partially Completed/Failed)
  - Click to view deployment details:
    - Device-by-device breakdown
    - Failures analysis
    - Timeline of deployment stages
    - Rollback option (if applicable)

**Functionality**:
- Validate device selection before deployment
- Auto-calculate estimated deployment time
- Detect problematic devices (low health score) and warn
- Implement canary deployment logic (monitor first batch before deploying to rest)
- Support staged rollout with success gates
- Rollback recent deployment if failure rate exceeds threshold
- Send notifications on stage completion/failure
- Handle network issues gracefully (retry failed device updates)

---

#### 4.2 Security & Key Management
**Purpose**: Secure storage and management of cryptographic keys

**UI Components**:
- **Key Storage Configuration**:
  - Key storage location selector:
    - OS Keychain (macOS)
    - Windows Credential Manager (Windows)
    - Secret Service (Linux)
    - Encrypted file (fallback)
  - Key storage status display:
    - Storage backend: "[System Keychain]"
    - Keys stored: N private keys
    - Last accessed: [timestamp]

- **Key Lifecycle Management**:
  - Generate new key pair button:
    - Show 32-byte public key
    - Generate option
    - Prompt to save public key to file
    - Warn: "Private key cannot be recovered. Save it securely."
  - Import existing key button:
    - Paste private key (hex or PEM format)
    - Validate format
    - Confirm import (overwrites existing)
  - Rotate key button:
    - Generate new key
    - Mark old key as deprecated
    - Provide migration guide for firmware updates

- **Key Usage Audit**:
  - Display when key was last used
  - Count of signatures created with this key
  - List of firmwares signed with this key
  - Export audit log

- **Security Warnings**:
  - Alert if key older than 90 days (recommend rotation)
  - Alert if private key file not encrypted
  - Alert if key was used in automated system (CI/CD)
  - Alert if key backup not performed

**Functionality**:
- Generate Ed25519 key pairs
- Store private key securely (never in plaintext files)
- Export public key in multiple formats (hex, PEM, Base64)
- Import keys from PEM/hex formats
- Validate key pair consistency (public + private)
- Rotate keys with rollover support
- Track key usage for audit purposes
- Integrate with OS-level key storage where available

---

#### 4.3 Health Check & Diagnostics
**Purpose**: Diagnose system issues and validate configuration

**UI Components**:
- **System Health Check Panel**:
  - Run diagnostics button
  - Diagnostic results checklist:
    - ✓ Git repository accessible
    - ✓ PlatformIO installed and working
    - ✓ GitHub API token valid
    - ✓ Private key accessible
    - ✓ Public key matches embedded key
    - ✓ Compilation environment (latest PlatformIO version)
    - ✓ Network connectivity to GitHub
    - ✓ Sufficient disk space
    - Each with timestamp of last check

- **Configuration Validator**:
  - Validate platformio.ini syntax
  - Check all target boards are defined
  - Verify build output paths
  - Validate manifest schema
  - Check public key in firmware source
  - Validate GitHub workflow file syntax

- **Dependency Checker**:
  - PlatformIO version (show installed vs required)
  - Python version (if applicable)
  - Git version
  - Network access (GitHub, api.github.com)
  - Disk space available (warn if < 1 GB)
  - Required libraries/packages

- **Self-Repair Options**:
  - "Install missing dependencies" button
  - "Download and install PlatformIO" button
  - "Reset configuration to defaults" button
  - "Clear cache and rebuild" button

**Functionality**:
- Automated diagnostic test suite
- Report each check result (pass/fail/warning)
- Suggest fixes for common issues
- Store diagnostic history
- Export diagnostic report as JSON/PDF

---

#### 4.4 Settings & Configuration
**Purpose**: Centralized settings for IDE behavior and integrations

**UI Components**:
- **GitHub Settings**:
  - Repository owner (auto-detected from git remote)
  - Repository name (auto-detected from git remote)
  - GitHub token (masked input)
  - Test connection button
  - API endpoint URL (for GitHub Enterprise support)

- **Build Settings**:
  - Source directory path
  - Output directory path
  - Build timeout (seconds)
  - Parallel build jobs (number)
  - Keep build artifacts checkbox
  - Compiler warnings level (all/most/some/none)

- **Signing Settings**:
  - Private key file location (read-only, system keychain)
  - Auto-sign checkbox (sign immediately after build)
  - Signature algorithm (currently Ed25519, read-only)

- **Device Monitoring Settings**:
  - Device polling interval (seconds)
  - Device timeout threshold (seconds of inactivity → offline)
  - Health score update frequency
  - Alert thresholds:
    - Quarantine threshold (default: 40)
    - Warning threshold (default: 60)
  - Notification settings:
    - Email notifications enabled checkbox
    - Slack webhook URL
    - Alert on critical events checkbox

- **Display Settings**:
  - Theme selector (Light / Dark)
  - Auto-refresh interval for dashboards
  - Chart update frequency
  - Data retention period (how long to keep old events)

- **Advanced Settings**:
  - Debug logging enabled checkbox
  - Log level selector (Debug/Info/Warn/Error)
  - Enable beta features checkbox
  - Telemetry collection checkbox (opt-in)
  - Backup settings button (export as JSON)
  - Restore settings button (import from JSON)

**Functionality**:
- Validate all settings on save
- Persist settings to local config file (JSON or YAML)
- Provide sensible defaults for all settings
- Reset to defaults button (with confirmation)
- Show setting descriptions/tooltips
- Search/filter settings by keyword

---

#### 4.5 Reporting & Analytics
**Purpose**: Generate reports and analyze trends

**UI Components**:
- **Report Generator**:
  - Report type selector (dropdown):
    - Fleet health summary
    - Update success/failure analysis
    - Device performance benchmarks
    - Security audit trail
  - Date range picker (start/end date)
  - Format selector (PDF / Excel / CSV / JSON)
  - Generate report button
  - Report preview (before download)

- **Analytics Dashboard**:
  - **Update Success Metrics**:
    - Total updates deployed (all time / this month / this week)
    - Update success rate (%)
    - Average update duration (seconds)
    - Update failures by stage (pie chart):
      - Stage 1: Connectivity (%)
      - Stage 2: Manifest validation (%)
      - Stage 3: Checksum (%)
      - Stage 4: Signature (%)
      - Stage 5: Installation (%)

  - **Device Performance**:
    - Devices per platform (bar chart)
    - Platform success rate comparison (bar chart)
    - Average health score by platform (bar chart)
    - Device uptime statistics (line chart over time)

  - **Security Metrics**:
    - Signature failures count (trend)
    - Checksum mismatches count (trend)
    - Quarantine events count (trend)
    - Most common failure types (top 5)

  - **Usage Statistics**:
    - Most deployed firmware version
    - Average time between releases
    - Rollback frequency
    - Manual reset frequency

- **Custom Report Builder**:
  - Metric selector (checkboxes for metrics to include)
  - Time period selector
  - Grouping options (by platform, by device, by time period)
  - Chart type selector (line, bar, pie, table)
  - Export button

**Functionality**:
- Query historical data from device logs
- Compute statistics and trends
- Generate charts and visualizations
- Export reports in multiple formats
- Schedule recurring report generation (email daily/weekly summary)
- Compare metrics across time periods
- Identify anomalies and trends

---

### TIER 5: TESTING & VALIDATION

#### 5.1 Firmware Validation & Testing
**Purpose**: Validate firmware before release

**UI Components**:
- **Pre-Release Validation Checklist**:
  - ✓ All platforms compiled successfully
  - ✓ Firmware checksums computed
  - ✓ Manifest JSON valid
  - ✓ Manifest signature valid
  - ✓ Version matches GitHub tag
  - ✓ Release notes provided
  - ✓ No uncommitted changes in source
  - Each with details on click

- **Firmware Binary Inspector**:
  - File size
  - MD5 / SHA-256 checksum
  - Memory footprint (flash, RAM)
  - Build date/time
  - Compiler version
  - Source commit hash (if embedded)

- **Manifest Validation**:
  - JSON schema validation
  - Required fields present
  - Field value ranges valid
  - Signature verification
  - Version format validation
  - Platform list validation

- **Test Scenarios**:
  - Run simulation tests button (requires mock server)
  - Test scenarios:
    - Clean update (happy path)
    - Corrupted checksum (verify rejection)
    - Invalid signature (verify rejection)
    - Older version (verify rejection)
    - Missing manifest (verify rejection)
    - Network failure during download (verify recovery)
  - Results: Pass/Fail for each scenario

**Functionality**:
- Validate firmware structure
- Check manifest against schema
- Verify signatures
- Compile and run test scenarios
- Generate test report
- Warn on potential issues (large firmware, slow signature verification, etc.)

---

#### 5.2 Mock Device Simulator
**Purpose**: Simulate device behavior without real hardware

**UI Components**:
- **Simulator Configuration**:
  - Number of devices to simulate (slider: 1-100)
  - Platform distribution (pie chart / percentage inputs):
    - ATmega328P: X%
    - ESP8266: X%
    - ESP32: X%
    - STM32F103: X%
  - Initial health scores (random in range slider)
  - Network reliability setting (0-100%)

- **Simulator Control Panel**:
  - Start simulation button
  - Stop simulation button
  - Pause simulation button
  - Reset all devices button
  - Inject failure scenario dropdown:
    - Network outage
    - Signature mismatch (single device)
    - Checksum corruption (single device)
    - Multiple failures (3 devices)
  - Inject failure button

- **Simulator Real-Time Display**:
  - Simulated device list (same as real fleet dashboard)
  - Simulated event timeline
  - Simulated device health scores updating
  - Statistics overlay showing:
    - Simulation time (virtual clock)
    - Update success rate so far
    - Current failure count
    - Events generated per second

**Functionality**:
- Simulate device polling behavior
- Simulate update process (all 5 stages)
- Simulate network failures
- Simulate signature/checksum failures
- Track health score changes
- Generate synthetic event data
- Export simulator results for analysis

---

### TIER 6: USER INTERFACE & UX

#### 6.1 Main Application Window
**Purpose**: Professional, intuitive interface for all IDE features

**Layout Structure**:
- **Top Bar**:
  - Project name and path
  - Current version badge
  - GitHub repo status indicator
  - Global search bar (search devices, events, releases)
  - Settings gear icon
  - Help icon
  - Notifications bell (with unread count)

- **Left Sidebar** (collapsible):
  - Navigation menu:
    - 📊 Dashboard
    - 🔨 Build & Sign
    - 📤 Release
    - 📱 Devices
    - 📋 Events
    - ⚙️ Settings
    - ? Help & Docs
  - Active menu item highlighted
  - Collapsible indicator

- **Main Content Area**:
  - Tab system for open modules
  - Tab close buttons (x)
  - Tab scroll arrows (if more than 6 tabs)
  - Breadcrumb navigation (Home > Devices > Device-ID)

- **Status Bar** (bottom):
  - GitHub connection status
  - Last sync timestamp
  - Device count connected
  - Notifications/alerts summary

**Design Principles**:
- Clean, minimal design (inspired by VS Code, GitHub interface)
- Consistent color scheme (GitHub light/dark themes)
- Accessible color contrast (WCAG AA minimum)
- Icons for quick scanning
- Tooltips on hover for clarity
- Progressive disclosure (hide advanced options by default)

---

#### 6.2 Color Scheme & Design System
**Purpose**: Consistent, professional visual language

**Color Palette**:
- Primary: GitHub blue (#0969da)
- Success: Green (#1a7f37)
- Warning: Yellow (#d29922)
- Danger: Red (#cf222e)
- Neutral: Gray (#57606a)
- Background: White (#ffffff) or Dark (#0d1117)
- Text: Dark gray (#24292f) or Light gray (#e6edf3)

**Components**:
- Buttons: Solid background, hover state (darker shade), active state (darker + underline)
- Inputs: Border on focus, error state (red border + error message below)
- Cards: Subtle shadow, border, padding
- Modals: Dark overlay (60% opacity), centered card, close button
- Alerts/Notifications: Colored left border, icon, message, optional close button
- Tables: Alternating row colors (subtle), hover highlight, sortable headers

---

#### 6.3 Navigation & Workflows
**Purpose**: Intuitive user journeys for common tasks

**Common Workflows**:
1. **Create and Release a New Firmware Version**:
   - Dashboard → Build & Sign → Select platforms → Build
   - → Sign with private key → Create manifest → Review & Deploy
   - → Create GitHub release → Deploy to devices

2. **Monitor Device Fleet Health**:
   - Dashboard → Devices → View fleet health → Drill into at-risk devices
   - → Quarantine management (if needed)

3. **Investigate Device Failure**:
   - Devices → Click device → View events timeline → Identify failure cause
   - → Check related firmware version → Review error logs

4. **Emergency Rollback**:
   - Release management → View deployment history → Select failed deployment
   - → Create rollback release → Deploy previous version to affected devices

---

### TIER 7: DOCUMENTATION & HELP

#### 7.1 Integrated Help System
**Purpose**: In-app guidance without leaving IDE

**UI Components**:
- **Help Sidebar** (toggle from top menu):
  - Search help articles
  - Topics tree:
    - Getting Started
    - Build & Compilation
    - Signing & Security
    - Releases & Deployment
    - Device Management
    - Troubleshooting
    - API Reference
  - Article display in sidebar
  - Links to external docs

- **Context-Sensitive Help**:
  - Question mark icon next to form fields
  - Hover to show brief explanation
  - Click to open detailed help article

- **Tutorial Mode**:
  - Interactive step-by-step guides
  - Highlight relevant UI elements
  - Show next step when current step complete

**Functionality**:
- Search across all documentation
- Syntax highlighting for code examples
- Screenshots/GIFs for visual guidance
- Links to relevant sections

---

#### 7.2 Keyboard Shortcuts & Command Palette
**Purpose**: Power user features for efficiency

**UI Components**:
- **Command Palette** (Ctrl+K / Cmd+K):
  - Fuzzy search for any action
  - Grouped by category
  - Show keyboard shortcut for each command
  - Recent commands at top

- **Keyboard Shortcuts Reference** (Ctrl+Shift+? / Cmd+Shift+?):
  - Table of all shortcuts
  - Grouped by context
  - Searchable
  - Printable

**Common Shortcuts**:
- Ctrl/Cmd + B: Build firmware
- Ctrl/Cmd + Shift + S: Sign manifest
- Ctrl/Cmd + Shift + R: Create GitHub release
- Ctrl/Cmd + D: Open device dashboard
- Ctrl/Cmd + L: Open event log
- Ctrl/Cmd + K: Command palette

---

## TECHNOLOGY STACK RECOMMENDATIONS

### Frontend
- **Framework**: React or Vue 3 (component-based)
- **UI Library**: shadcn/ui (headless, accessible components)
- **Charts**: Recharts or Chart.js (interactive data visualization)
- **Code Editor**: Monaco Editor (VS Code editor component)
- **State Management**: Zustand or Jotai (lightweight)
- **HTTP Client**: axios or fetch API
- **Real-time**: WebSocket or Server-Sent Events (SSE)

### Backend
- **Runtime**: Node.js with Electron (desktop app) or web-based
- **Framework**: Express.js or Fastify (lightweight, efficient)
- **Process Management**: child_process module (call PlatformIO CLI)
- **File System**: fs module for local file handling
- **Cryptography**: tweetnacl.js or libsodium (Ed25519 signing)
- **GitHub API**: Octokit.js (official GitHub library)

### Desktop Application
- **Electron** (cross-platform: Windows, macOS, Linux)
- **Electron Forge** for packaging and distribution
- **electron-store** for local configuration/settings

### Build & Packaging
- **Build Tool**: Vite (fast, modern)
- **Package Manager**: pnpm or npm
- **Docker**: Optional, for containerized deployment

---

## FEATURE DEVELOPMENT ROADMAP (PHASED)

### Phase 1: MVP (4-6 weeks)
- ✅ Project Dashboard
- ✅ Build & Compilation Management
- ✅ Cryptographic Signing Pipeline
- ✅ GitHub Releases Manager
- ✅ Manifest Builder

### Phase 2: Device Management (3-4 weeks)
- ✅ Device Fleet Dashboard
- ✅ Event Logger & History
- ✅ Health Score System
- ✅ Quarantine Management
- ✅ Basic Monitoring

### Phase 3: Automation (2-3 weeks)
- ✅ GitHub Actions Workflow Manager
- ✅ Automated Build Pipeline
- ✅ Version & Release Tagging

### Phase 4: Advanced Features (3-4 weeks)
- ✅ Update Deployment & Scheduling
- ✅ Security & Key Management
- ✅ Diagnostics & Health Check
- ✅ Settings & Configuration

### Phase 5: Analytics & Reporting (2-3 weeks)
- ✅ Reporting & Analytics
- ✅ Mock Device Simulator
- ✅ Firmware Validation

### Phase 6: Polish & Production (2-3 weeks)
- ✅ UI/UX refinement
- ✅ Help system & documentation
- ✅ Testing & bug fixes
- ✅ Performance optimization
- ✅ Security audit

---

## SUCCESS CRITERIA

1. **Functionality**: All 45+ features fully implemented and tested
2. **Usability**: Intuitive navigation, no more than 3 clicks to reach any feature
3. **Performance**: UI responds within 100ms, data loads within 1 second
4. **Reliability**: 99.5% uptime, zero data loss
5. **Security**: Private keys never exposed, cryptographic operations verified
6. **Documentation**: Complete user guide, API docs, video tutorials
7. **Cross-platform**: Runs on Windows, macOS, Linux
8. **Integration**: Seamlessly works with GitHub API and PlatformIO
9. **Accessibility**: WCAG AA compliant, keyboard shortcuts available
10. **Scalability**: Supports 1000+ devices without performance degradation

---

## ESTIMATED TIMELINE

- **Total Development**: 16-22 weeks
- **Testing**: 2-3 weeks (parallel with development)
- **Documentation**: 1-2 weeks (parallel with development)
- **Beta Release**: After Phase 3 (8-10 weeks)
- **Full Release**: After Phase 6 (16-22 weeks)

---

## CONCLUSION

The Secure Heterogeneous OTA Update Mechanism IDE is a comprehensive platform for managing firmware updates across four hardware platforms with enterprise-grade security, zero-cost infrastructure, and intuitive user experience. This specification provides a complete blueprint for implementation, with phased development allowing for early MVP release and iterative refinement based on user feedback.

The IDE consolidates all aspects of the OTA update process—from build automation and cryptographic signing to device monitoring and health management—into a single, integrated application, eliminating manual steps, reducing errors, and providing operators with complete visibility into their device fleet's security posture and update status.