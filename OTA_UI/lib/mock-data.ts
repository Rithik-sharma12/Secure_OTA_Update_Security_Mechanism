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

function generateMockDevices(): Device[] {
  void architectures
  return []
}

// Mock Releases (8 releases)
export const mockReleases: Release[] = []

// Mock Event Logs (60 events)
function generateMockEventLogs(): EventLog[] {
  return []
}

// Mock Pipeline Stages
export const mockPipelineStages: PipelineStage[] = []

// Mock Manifest JSON
export const mockManifest = {
  version: '0',
  buildDate: new Date(0).toISOString(),
  architectures: {
    ATmega328P: {
      filename: '0',
      size: 0,
      checksum: '0',
    },
    'ESP8266/ESP32': {
      filename: '0',
      size: 0,
      checksum: '0',
    },
    STM32: {
      filename: '0',
      size: 0,
      checksum: '0',
    },
    nRF52840: {
      filename: '0',
      size: 0,
      checksum: '0',
    },
  },
  signature: '0',
  releaseNotes: '0',
  minimumDeviceHealth: 0,
  rolloutStrategy: '0',
  rolloutStages: [
    { percentage: 0, duration: '0' },
    { percentage: 0, duration: '0' },
    { percentage: 0, duration: '0' },
  ],
}

// Export all mock data
export const mockDevices = generateMockDevices()
export const mockEventLogs = generateMockEventLogs()

// Calculate statistics
export const mockStatistics = {
  totalDevices: 0,
  onlineDevices: 0,
  pendingUpdates: 0,
  quarantinedDevices: 0,
  avgHealthScore: 0,
  updateCompletionRate: 0,
  tcvPassRate: 0,
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
