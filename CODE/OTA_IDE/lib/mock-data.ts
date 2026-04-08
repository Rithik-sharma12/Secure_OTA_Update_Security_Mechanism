import { Device, Event, Release, Asset, Pipeline, PipelineStage, Manifest, Key, Certificate, Deployment } from './types';

const FIXED_BASE_TIME = new Date('2026-04-08T12:00:00Z').getTime();
const minute = 60 * 1000;
const hour = 60 * minute;
const day = 24 * hour;

const fixedDate = (offsetMs: number) => new Date(FIXED_BASE_TIME + offsetMs);

// Mock Devices
export const mockDevices: Device[] = [
  {
    id: 'dev-001',
    name: 'Arduino Pro Mini 1',
    type: 'ATmega328P',
    status: 'online',
    firmwareVersion: '2.3.1',
    latestVersion: '2.4.0',
    lastSync: fixedDate(-5 * minute),
    location: 'Building A - Lab 1',
    health: 'excellent',
    cpuUsage: 24,
    memoryUsage: 45,
    uptime: 720, // 30 days
    signalStrength: 95,
  },
  {
    id: 'dev-002',
    name: 'ESP8266 Module',
    type: 'ESP8266',
    status: 'online',
    firmwareVersion: '3.1.2',
    latestVersion: '3.1.2',
    lastSync: fixedDate(-2 * minute),
    location: 'Building B - IoT Hub',
    health: 'good',
    cpuUsage: 42,
    memoryUsage: 68,
    uptime: 480,
    signalStrength: 78,
  },
  {
    id: 'dev-003',
    name: 'ESP32 Main Controller',
    type: 'ESP32',
    status: 'updating',
    firmwareVersion: '1.5.0',
    latestVersion: '1.6.0',
    lastSync: fixedDate(-30 * 1000),
    location: 'Building C - Control Center',
    health: 'fair',
    cpuUsage: 65,
    memoryUsage: 72,
    uptime: 240,
    signalStrength: 92,
  },
  {
    id: 'dev-004',
    name: 'STM32F103 Sensor',
    type: 'STM32F103',
    status: 'offline',
    firmwareVersion: '1.2.0',
    latestVersion: '1.3.0',
    lastSync: fixedDate(-2 * day),
    location: 'Building D - Warehouse',
    health: 'poor',
    cpuUsage: 0,
    memoryUsage: 0,
    uptime: 0,
  },
  {
    id: 'dev-005',
    name: 'Arduino Mega 2560',
    type: 'ATmega328P',
    status: 'online',
    firmwareVersion: '2.3.1',
    latestVersion: '2.4.0',
    lastSync: fixedDate(-10 * minute),
    location: 'Building A - Lab 2',
    health: 'excellent',
    cpuUsage: 18,
    memoryUsage: 52,
    uptime: 360,
  },
];

// Mock Events
export const mockEvents: Event[] = [
  {
    id: 'evt-001',
    timestamp: fixedDate(-5 * minute),
    type: 'firmware_update',
    severity: 'success',
    title: 'Firmware Update Successful',
    description: 'Device dev-001 successfully updated to version 2.3.1',
    deviceId: 'dev-001',
  },
  {
    id: 'evt-002',
    timestamp: fixedDate(-15 * minute),
    type: 'deployment',
    severity: 'info',
    title: 'Deployment Started',
    description: 'Deploying firmware v1.6.0 to 3 devices',
  },
  {
    id: 'evt-003',
    timestamp: fixedDate(-30 * minute),
    type: 'error',
    severity: 'error',
    title: 'Update Failed',
    description: 'Device dev-004 failed to update: Connection timeout',
    deviceId: 'dev-004',
  },
  {
    id: 'evt-004',
    timestamp: fixedDate(-60 * minute),
    type: 'warning',
    severity: 'warning',
    title: 'High CPU Usage',
    description: 'Device dev-003 CPU usage exceeded 80%',
    deviceId: 'dev-003',
  },
  {
    id: 'evt-005',
    timestamp: fixedDate(-120 * minute),
    type: 'info',
    severity: 'info',
    title: 'Device Online',
    description: 'Device dev-002 came back online',
    deviceId: 'dev-002',
  },
];

// Mock Releases
export const mockReleases: Release[] = [
  {
    id: 'rel-001',
    version: '2.4.0',
    releaseDate: fixedDate(-1 * day),
    description: 'Major update with performance improvements and bug fixes',
    assets: [
      { id: 'ast-001', name: 'firmware-2.4.0-atmega.bin', size: 28672, checksum: 'abc123', createdAt: fixedDate(-1 * day) },
      { id: 'ast-002', name: 'firmware-2.4.0-esp8266.bin', size: 426304, checksum: 'def456', createdAt: fixedDate(-1 * day + 30 * minute) },
    ],
    compatible: ['ATmega328P', 'ESP8266'],
    changelog: '- Fixed memory leak in WiFi driver\n- Improved performance by 15%\n- Added new command set',
    downloadCount: 1245,
    status: 'published',
  },
  {
    id: 'rel-002',
    version: '1.6.0',
    releaseDate: fixedDate(-2 * day),
    description: 'ESP32 firmware with enhanced security features',
    assets: [
      { id: 'ast-003', name: 'firmware-1.6.0-esp32.bin', size: 512000, checksum: 'ghi789', createdAt: fixedDate(-2 * day + 15 * minute) },
    ],
    compatible: ['ESP32'],
    changelog: '- Added TLS 1.3 support\n- Enhanced encryption\n- Improved boot time',
    downloadCount: 892,
    status: 'published',
  },
  {
    id: 'rel-003',
    version: '2.3.1',
    releaseDate: fixedDate(-3 * day),
    description: 'Maintenance release with minor fixes',
    assets: [
      { id: 'ast-004', name: 'firmware-2.3.1-atmega.bin', size: 27648, checksum: 'jkl012', createdAt: fixedDate(-3 * day + 45 * minute) },
    ],
    compatible: ['ATmega328P'],
    changelog: '- Fixed serial communication issue\n- Stability improvements',
    downloadCount: 567,
    status: 'published',
  },
];

// Mock Pipeline
export const mockPipeline: Pipeline = {
  id: 'pipe-001',
  releaseId: 'rel-001',
  createdAt: fixedDate(-2 * hour),
  stages: [
    {
      id: 'stage-001',
      name: 'build',
      status: 'success',
      startTime: fixedDate(-2 * hour),
      endTime: fixedDate(-108 * minute),
      logs: '[INFO] Building firmware v2.4.0...\n[INFO] Compilation successful\n[INFO] Binary size: 28672 bytes',
      duration: 720,
    },
    {
      id: 'stage-002',
      name: 'test',
      status: 'success',
      startTime: fixedDate(-108 * minute),
      endTime: fixedDate(-90 * minute),
      logs: '[INFO] Running test suite...\n[PASS] Unit tests (145/145)\n[PASS] Integration tests (28/28)\n[INFO] Code coverage: 94%',
      duration: 1080,
    },
    {
      id: 'stage-003',
      name: 'deploy',
      status: 'running',
      startTime: fixedDate(-90 * minute),
      logs: '[INFO] Deploying to 5 devices...\n[INFO] Deployed to dev-001 ✓\n[INFO] Deployed to dev-002 ✓\n[INFO] Deploying to dev-003...',
      duration: 900,
    },
    {
      id: 'stage-004',
      name: 'verify',
      status: 'pending',
      logs: '',
    },
  ],
  status: 'running',
  totalDuration: 0,
};

// Mock Manifest
export const mockManifest: Manifest = {
  id: 'mani-001',
  releaseId: 'rel-001',
  entries: [
    {
      device: 'ATmega328P',
      version: '2.4.0',
      checksum: 'abc123def456',
      size: 28672,
      url: 'https://cdn.example.com/firmware/atmega/2.4.0.bin',
    },
    {
      device: 'ESP8266',
      version: '2.4.0',
      checksum: 'ghi789jkl012',
      size: 426304,
      url: 'https://cdn.example.com/firmware/esp8266/2.4.0.bin',
    },
  ],
  createdAt: fixedDate(-45 * minute),
  signature: 'sig_1a2b3c4d5e6f7g8h',
};

// Mock Keys
export const mockKeys: Key[] = [
  {
    id: 'key-001',
    name: 'Signing Key 2024',
    type: 'ECDSA',
    keySize: 256,
    createdAt: fixedDate(-90 * day),
    expiresAt: fixedDate(275 * day),
    active: true,
  },
  {
    id: 'key-002',
    name: 'Legacy Signing Key',
    type: 'RSA',
    keySize: 2048,
    createdAt: fixedDate(-365 * day),
    expiresAt: fixedDate(-100 * day),
    active: false,
  },
  {
    id: 'key-003',
    name: 'Encryption Key A',
    type: 'AES',
    keySize: 256,
    createdAt: fixedDate(-60 * day),
    active: true,
  },
];

// Mock Certificates
export const mockCertificates: Certificate[] = [
  {
    id: 'cert-001',
    name: 'OTA IDE Server Cert',
    issuer: 'Let\'s Encrypt',
    subject: 'CN=ota.example.com',
    validFrom: fixedDate(-30 * day),
    validTo: fixedDate(335 * day),
    fingerprint: 'SHA256:1a2b3c4d5e6f7g8h9i0j',
  },
  {
    id: 'cert-002',
    name: 'Firmware Signing Cert',
    issuer: 'Internal CA',
    subject: 'CN=firmware-signer.example.com',
    validFrom: fixedDate(-180 * day),
    validTo: fixedDate(185 * day),
    fingerprint: 'SHA256:9k8l7m6n5o4p3q2r1s0t',
  },
];

// Mock Deployments
export const mockDeployments: Deployment[] = [
  {
    id: 'deploy-001',
    releaseId: 'rel-001',
    deviceIds: ['dev-001', 'dev-002', 'dev-003', 'dev-005'],
    status: 'in-progress',
    startedAt: fixedDate(-30 * minute),
    successCount: 2,
    failureCount: 0,
    logs: '[12:45] Starting deployment to 4 devices\n[12:46] Device dev-001: ✓ Complete\n[12:47] Device dev-002: ✓ Complete\n[12:48] Device dev-003: In progress (65%)',
  },
  {
    id: 'deploy-002',
    releaseId: 'rel-002',
    deviceIds: ['dev-003'],
    status: 'success',
    startedAt: fixedDate(-120 * minute),
    completedAt: fixedDate(-90 * minute),
    successCount: 1,
    failureCount: 0,
    logs: '[11:00] Starting deployment\n[11:02] Device dev-003: ✓ Complete',
  },
];

// Helper functions
export function getDeviceById(id: string) {
  return mockDevices.find(d => d.id === id);
}

export function getEventsByDeviceId(deviceId: string) {
  return mockEvents.filter(e => e.deviceId === deviceId);
}

export function getEventsByType(type: string) {
  return mockEvents.filter(e => e.type === type);
}

export function getReleaseById(id: string) {
  return mockReleases.find(r => r.id === id);
}

export function getDeploymentsByReleaseId(releaseId: string) {
  return mockDeployments.filter(d => d.releaseId === releaseId);
}

export function getOnlineDevices() {
  return mockDevices.filter(d => d.status === 'online');
}

export function getOfflineDevices() {
  return mockDevices.filter(d => d.status === 'offline');
}

export function getDevicesNeedingUpdate() {
  return mockDevices.filter(d => d.firmwareVersion !== d.latestVersion);
}
