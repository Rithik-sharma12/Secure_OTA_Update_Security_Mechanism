import { mockDevices, mockEventLogs, mockReleases, mockStatistics, mockPipelineStages, mockManifest } from './mock-data'

// Hook to get all devices
export function useDevices() {
  return mockDevices
}

// Hook to get a specific device
export function useDevice(id: string) {
  return mockDevices.find(d => d.id === id)
}

// Hook to filter devices by architecture
export function useDevicesByArchitecture(architecture: string) {
  return mockDevices.filter(d => d.architecture === architecture)
}

// Hook to get devices by status
export function useDevicesByStatus(status: string) {
  return mockDevices.filter(d => d.status === status)
}

// Hook to get all event logs
export function useLogs() {
  return mockEventLogs
}

// Hook to get logs filtered by type
export function useLogsByType(type: string) {
  return mockEventLogs.filter(l => l.type === type)
}

// Hook to get logs for a specific device
export function useLogsForDevice(deviceId: string) {
  return mockEventLogs.filter(l => l.device === deviceId)
}

// Hook to get all releases
export function useReleases() {
  return mockReleases
}

// Hook to get a specific release
export function useRelease(version: string) {
  return mockReleases.find(r => r.version === version)
}

// Hook to get statistics
export function useStatistics() {
  return mockStatistics
}

// Hook to get pipeline stages
export function usePipeline() {
  return mockPipelineStages
}

// Hook to get manifest
export function useManifest() {
  return mockManifest
}

// Health score categories
export function getHealthCategory(score: number): 'critical' | 'warning' | 'good' | 'excellent' {
  if (score < 30) return 'critical'
  if (score < 60) return 'warning'
  if (score < 80) return 'good'
  return 'excellent'
}

// Format date for display
export function formatDate(date: Date): string {
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}

// Format bytes to human readable
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}
