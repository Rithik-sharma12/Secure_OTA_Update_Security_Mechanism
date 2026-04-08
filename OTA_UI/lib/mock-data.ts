// Hardware architecture types
export type Architecture = 'ATmega328P' | 'ESP8266/ESP32' | 'STM32' | 'nRF52840'
export type EventType = 'success' | 'error' | 'warning' | 'info' | 'quarantine'
export type DeviceStatus = 'online' | 'pending' | 'quarantined'

// Device interface
export interface Device {
  id: string
  name: string
  architecture: Architecture
  status: DeviceStatus
  healthScore: number
  firmwareVersion: string
  currentRelease: string
  targetRelease: string
  lastSeen: Date
  location: string
  serialNumber: string
}

// Release interface
export interface Release {
  version: string
  tag: string
  releaseDate: Date
  signature: string
  signatureVerified: boolean
  rolloutPercentage: number
  releaseNotes: string
  fileSize: number
  checksum: string
}

// Event log interface
export interface EventLog {
  id: string
  timestamp: Date
  type: EventType
  device: string
  message: string
  details?: string
}

// Pipeline stage
export interface PipelineStage {
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  duration?: number
  output?: string
}

// Mock Devices (50 devices across all architectures)
const architectures: Architecture[] = ['ATmega328P', 'ESP8266/ESP32', 'STM32', 'nRF52840']
const locations = ['Warehouse A', 'Factory B', 'Lab C', 'Remote Site D', 'Distribution E', 'Field Site F']

function generateMockDevices(): Device[] {
  const devices: Device[] = []
  const baseDate = new Date()

  for (let i = 0; i < 50; i++) {
    const arch = architectures[i % 4]
    const isQuarantined = Math.random() > 0.9
    const isPending = Math.random() > 0.85

    devices.push({
      id: `DEV-${String(i + 1).padStart(4, '0')}`,
      name: `IoT Device ${i + 1}`,
      architecture: arch,
      status: isQuarantined ? 'quarantined' : isPending ? 'pending' : 'online',
      healthScore: isQuarantined ? Math.random() * 30 : Math.random() * 100,
      firmwareVersion: `v${Math.floor(Math.random() * 2) + 1}.${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 10)}`,
      currentRelease: `2024.01.${String(Math.floor(Math.random() * 31) + 1).padStart(2, '0')}`,
      targetRelease: `2024.02.${String(Math.floor(Math.random() * 28) + 1).padStart(2, '0')}`,
      lastSeen: new Date(baseDate.getTime() - Math.random() * 7 * 24 * 60 * 60 * 1000),
      location: locations[i % locations.length],
      serialNumber: `SN-${Math.random().toString(36).substring(2, 10).toUpperCase()}`,
    })
  }

  return devices
}

// Mock Releases (8 releases)
const mockReleases: Release[] = [
  {
    version: '2024.02.15',
    tag: 'v2024.02.15',
    releaseDate: new Date('2024-02-15'),
    signature: 'ed25519_sig_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
    signatureVerified: true,
    rolloutPercentage: 85,
    releaseNotes: 'Security patches and performance improvements',
    fileSize: 256000,
    checksum: 'sha256_abc123def456',
  },
  {
    version: '2024.02.01',
    tag: 'v2024.02.01',
    releaseDate: new Date('2024-02-01'),
    signature: 'ed25519_sig_b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7',
    signatureVerified: true,
    rolloutPercentage: 95,
    releaseNotes: 'Critical security update',
    fileSize: 248000,
    checksum: 'sha256_def456ghi789',
  },
  {
    version: '2024.01.20',
    tag: 'v2024.01.20',
    releaseDate: new Date('2024-01-20'),
    signature: 'ed25519_sig_c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8',
    signatureVerified: true,
    rolloutPercentage: 100,
    releaseNotes: 'Network connectivity improvements',
    fileSize: 244000,
    checksum: 'sha256_ghi789jkl012',
  },
  {
    version: '2024.01.10',
    tag: 'v2024.01.10',
    releaseDate: new Date('2024-01-10'),
    signature: 'ed25519_sig_d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9',
    signatureVerified: true,
    rolloutPercentage: 100,
    releaseNotes: 'Memory optimization and bug fixes',
    fileSize: 240000,
    checksum: 'sha256_jkl012mno345',
  },
  {
    version: '2023.12.28',
    tag: 'v2023.12.28',
    releaseDate: new Date('2023-12-28'),
    signature: 'ed25519_sig_e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0',
    signatureVerified: true,
    rolloutPercentage: 100,
    releaseNotes: 'Initial release',
    fileSize: 236000,
    checksum: 'sha256_mno345pqr678',
  },
]

// Mock Event Logs (60 events)
function generateMockEventLogs(): EventLog[] {
  const events: EventLog[] = []
  const baseDate = new Date()
  const eventMessages = {
    success: [
      'Device successfully updated',
      'Signature verification passed',
      'Firmware flashed successfully',
      'Device health check passed',
    ],
    error: [
      'Update failed: corrupted firmware',
      'Signature verification failed',
      'Device timeout during update',
      'Memory insufficient for update',
    ],
    warning: [
      'Update in progress (slow connection)',
      'Device health score declining',
      'Unusual network activity detected',
      'Update queued - high device load',
    ],
    info: [
      'Device online',
      'Scheduled update initiated',
      'Health score recalculated',
      'Device location updated',
    ],
    quarantine: [
      'Device quarantined - failed health check',
      'Device isolated - suspicious activity',
      'Device under review - TCV failed',
      'Device suspended - rollback required',
    ],
  }

  for (let i = 0; i < 60; i++) {
    const types: EventType[] = ['success', 'error', 'warning', 'info', 'quarantine']
    const type = types[Math.floor(Math.random() * types.length)]
    const messages = eventMessages[type]
    const message = messages[Math.floor(Math.random() * messages.length)]

    events.push({
      id: `EVT-${String(i + 1).padStart(5, '0')}`,
      timestamp: new Date(baseDate.getTime() - Math.random() * 30 * 24 * 60 * 60 * 1000),
      type,
      device: `DEV-${String(Math.floor(Math.random() * 50) + 1).padStart(4, '0')}`,
      message,
      details: `${type === 'error' ? 'Error Code: ' : ''}${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
    })
  }

  return events.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
}

// Mock Pipeline Stages
export const mockPipelineStages: PipelineStage[] = [
  {
    name: 'Git Tag Detection',
    status: 'completed',
    duration: 2,
    output: 'Tag v2024.02.15 detected on main branch',
  },
  {
    name: 'Compilation',
    status: 'completed',
    duration: 45,
    output: 'Building for 4 architectures...\nATmega328P: OK\nESP8266/ESP32: OK\nSTM32: OK\nnRF52840: OK',
  },
  {
    name: 'Binary Signing',
    status: 'completed',
    duration: 8,
    output: 'Signing with Ed25519 key... Signature: a1b2c3d4e5f6g7h8',
  },
  {
    name: 'Hash Verification',
    status: 'completed',
    duration: 3,
    output: 'SHA256: abc123def456...\nVerified: OK',
  },
  {
    name: 'Release Publishing',
    status: 'running',
    duration: 12,
    output: 'Publishing to GitHub releases...\nUploading binaries: 86% complete',
  },
  {
    name: 'Manifest Generation',
    status: 'pending',
    output: 'Waiting for publishing to complete...',
  },
]

// Mock Manifest JSON
export const mockManifest = {
  version: '2024.02.15',
  buildDate: '2024-02-15T10:30:00Z',
  architectures: {
    ATmega328P: {
      filename: 'firmware-atmega.bin',
      size: 32256,
      checksum: 'sha256_abc123',
    },
    'ESP8266/ESP32': {
      filename: 'firmware-esp32.bin',
      size: 65536,
      checksum: 'sha256_def456',
    },
    STM32: {
      filename: 'firmware-stm32.bin',
      size: 98304,
      checksum: 'sha256_ghi789',
    },
    nRF52840: {
      filename: 'firmware-nrf52.bin',
      size: 120000,
      checksum: 'sha256_jkl012',
    },
  },
  signature: 'ed25519_sig_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
  releaseNotes: 'Security patches and performance improvements',
  minimumDeviceHealth: 40,
  rolloutStrategy: 'progressive',
  rolloutStages: [
    { percentage: 10, duration: '1h' },
    { percentage: 50, duration: '4h' },
    { percentage: 100, duration: '24h' },
  ],
}

// Export all mock data
export const mockDevices = generateMockDevices()
export const mockEventLogs = generateMockEventLogs()

// Calculate statistics
export const mockStatistics = {
  totalDevices: mockDevices.length,
  onlineDevices: mockDevices.filter(d => d.status === 'online').length,
  pendingUpdates: mockDevices.filter(d => d.status === 'pending').length,
  quarantinedDevices: mockDevices.filter(d => d.status === 'quarantined').length,
  avgHealthScore: Math.round(
    mockDevices.reduce((sum, d) => sum + d.healthScore, 0) / mockDevices.length
  ),
  updateCompletionRate: Math.round(
    (mockDevices.filter(d => d.currentRelease === d.targetRelease).length / mockDevices.length) * 100
  ),
  tcvPassRate: 92,
}

export const architectureColors: Record<Architecture, string> = {
  'ATmega328P': '#FF6B35',
  'ESP8266/ESP32': '#0A84FF',
  'STM32': '#A855F7',
  'nRF52840': '#F59E0B',
}

export const architectureBg: Record<Architecture, string> = {
  'ATmega328P': 'bg-orange-500/20',
  'ESP8266/ESP32': 'bg-blue-500/20',
  'STM32': 'bg-purple-500/20',
  'nRF52840': 'bg-yellow-500/20',
}

export const architectureText: Record<Architecture, string> = {
  'ATmega328P': 'text-orange-600 dark:text-orange-400',
  'ESP8266/ESP32': 'text-blue-600 dark:text-blue-400',
  'STM32': 'text-purple-600 dark:text-purple-400',
  'nRF52840': 'text-yellow-600 dark:text-yellow-400',
}
