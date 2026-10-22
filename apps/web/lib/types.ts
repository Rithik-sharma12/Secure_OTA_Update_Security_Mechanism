// Device Types
/** 'Unknown' when the device reported an architecture the console does not recognise. */
export type DeviceType = 'ATmega328P' | 'ESP8266' | 'ESP32' | 'STM32F103' | 'Unknown';
export type DeviceStatus = 'online' | 'offline' | 'updating' | 'error' | 'standby';
export type HealthStatus = 'excellent' | 'good' | 'fair' | 'poor' | 'critical';

export interface Device {
  id: string;
  name: string;
  type: DeviceType;
  status: DeviceStatus;
  firmwareVersion: string;
  latestVersion: string;
  /** Last heartbeat the gateway recorded; null when it has none. */
  lastSync: Date | null;
  /** Empty when the device never reported one. */
  location: string;
  health: HealthStatus;
  cpuUsage: number;
  memoryUsage: number;
  /** Seconds since boot, as the firmware reports it. */
  uptime: number;
  /** Raw ASH (adaptive security health) score, 0-100, as the device reported it. */
  ash: number;
  /** Status text the device sent with its last heartbeat. */
  reportedStatus: string;
  signalStrength?: number;
  /** LAN address the device last reported. */
  ip?: string;
  /** 'token' when the device authenticates with its own token, 'fleet' for the shared key. */
  authMode?: string;
  /** True while a freshly installed image is on probation (health gate). */
  rollbackPending?: boolean;
  /** Last OTA progress report the device sent (POST /api/devices/{id}/ota/status). */
  ota?: { phase: string; version: string; progress: number | null; detail: string | null; at: string | null };
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
  /** Architectures the gateway will serve this release to. Empty means all. */
  compatible: string[];
  changelog: string;
  downloadCount: number;
  status: 'draft' | 'published' | 'archived';
  archivedAt?: Date;
  /** True when the artifact is an encrypted package. */
  securePackage?: boolean;
}

// Pipeline Types
/** Stage names come from the gateway as-is: artifact, store, sign, verify. */
export type PipelineStageName = string;
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
/** The gateway's signed manifest for its newest published release, unmodified. */
export interface Manifest {
  version: string;
  filename: string;
  sha256: string;
  size: number;
  signature: string;
  signatureAlgorithm: string;
  signatureKeyId: string;
  generatedAt: Date | null;
  url: string;
  compatible: string[];
  imageSha256?: string;
  securePackage?: boolean;
  /** The manifest exactly as the gateway served it. */
  raw: Record<string, unknown>;
}

// Security Types
export interface Key {
  id: string;
  name: string;
  /** Algorithm as the gateway reports it, e.g. Ed25519. */
  type: string;
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
  /** Absent when the record has no validity window (a bare public key). */
  validTo?: Date;
  fingerprint: string;
}

/** Public half of the gateway's signing key (GET /releases/latest/public-key). */
export interface SigningPublicKey {
  algorithm: string;
  keyId: string;
  fingerprint: string;
  publicKeyPem: string;
}

/** Raw ASH score per device, as GET /api/dashboard returns it. */
export interface AshDevice {
  id: string;
  score: number;
  status: string;
}

/** Host stats the gateway reports about the machine it runs on. */
export interface GatewayHostStats {
  ip: string;
  temp: string;
  load: string;
}

// Deployment Types
/** Statuses exactly as the gateway records them (gateway/deployment.py). */
export type DeploymentStatus = 'pending' | 'in_progress' | 'success' | 'failed' | 'partial' | 'cancelled';
export type DeploymentTargetState = 'pending' | 'confirmed' | 'failed' | 'cancelled';

export interface DeploymentTarget {
  state: DeploymentTargetState;
  reason: string | null;
  fromVersion: string | null;
  confirmedAt: Date | null;
}

export interface Deployment {
  id: string;
  releaseId: string;
  version: string;
  deviceIds: string[];
  targets: Record<string, DeploymentTarget>;
  status: DeploymentStatus;
  startedAt: Date;
  completedAt?: Date;
  deadline?: Date;
  successCount: number;
  failureCount: number;
  pendingCount: number;
  cancelledCount: number;
  retryOf?: string;
  logs: string;
}
