// Device Types
export type DeviceType = 'ATmega328P' | 'ESP8266' | 'ESP32' | 'STM32F103';
export type DeviceStatus = 'online' | 'offline' | 'updating' | 'error' | 'standby';
export type HealthStatus = 'excellent' | 'good' | 'fair' | 'poor' | 'critical';

export interface Device {
  id: string;
  name: string;
  type: DeviceType;
  status: DeviceStatus;
  firmwareVersion: string;
  latestVersion: string;
  lastSync: Date;
  location: string;
  health: HealthStatus;
  cpuUsage: number;
  memoryUsage: number;
  uptime: number; // in hours
  signalStrength?: number;
}

// Event Types
export type EventSeverity = 'info' | 'warning' | 'error' | 'success' | 'debug';
export type EventType = 'firmware_update' | 'deployment' | 'error' | 'warning' | 'info' | 'security';

export interface Event {
  id: string;
  timestamp: Date;
  type: EventType;
  severity: EventSeverity;
  title: string;
  description: string;
  deviceId?: string;
  metadata?: Record<string, any>;
}

// Release Types
export interface Asset {
  id: string;
  name: string;
  size: number;
  checksum: string;
  createdAt: Date;
}

export interface Release {
  id: string;
  version: string;
  releaseDate: Date;
  description: string;
  assets: Asset[];
  compatible: DeviceType[];
  changelog: string;
  downloadCount: number;
  status: 'draft' | 'published' | 'archived';
}

// Pipeline Types
export type PipelineStageName = 'build' | 'test' | 'deploy' | 'verify';
export type StageStatus = 'pending' | 'running' | 'success' | 'failed' | 'skipped';

export interface PipelineStage {
  id: string;
  name: PipelineStageName;
  status: StageStatus;
  startTime?: Date;
  endTime?: Date;
  logs: string;
  duration?: number;
}

export interface Pipeline {
  id: string;
  releaseId: string;
  createdAt: Date;
  stages: PipelineStage[];
  status: StageStatus;
  totalDuration: number;
}

// Manifest Types
export interface ManifestEntry {
  device: DeviceType;
  version: string;
  checksum: string;
  size: number;
  url: string;
}

export interface Manifest {
  id: string;
  releaseId: string;
  entries: ManifestEntry[];
  createdAt: Date;
  signature?: string;
}

// Security Types
export interface Key {
  id: string;
  name: string;
  type: 'RSA' | 'ECDSA' | 'AES';
  keySize: number;
  createdAt: Date;
  expiresAt?: Date;
  active: boolean;
}

export interface Certificate {
  id: string;
  name: string;
  issuer: string;
  subject: string;
  validFrom: Date;
  validTo: Date;
  fingerprint: string;
}

// Metrics Types
export interface Metric {
  timestamp: Date;
  value: number;
  device?: string;
}

export interface MetricsData {
  cpu: Metric[];
  memory: Metric[];
  temperature: Metric[];
  bandwidth: Metric[];
}

// Dashboard Types
export interface DashboardMetric {
  label: string;
  value: string;
  change: number;
  trend: 'up' | 'down' | 'stable';
  icon: string;
}

// Deployment Types
export interface Deployment {
  id: string;
  releaseId: string;
  deviceIds: string[];
  status: 'pending' | 'in-progress' | 'success' | 'failed' | 'partial';
  startedAt: Date;
  completedAt?: Date;
  successCount: number;
  failureCount: number;
  logs: string;
}
