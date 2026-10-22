import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/auth';
import { gatewayHeaders, gatewayUrl } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * One read of everything the console shows, taken from the gateway.
 *
 * Values are passed through as the gateway reports them. When the gateway has
 * nothing (no release, no manifest, no last-seen time) the field is empty or
 * null; nothing here substitutes a plausible default.
 */

type GatewayDevice = {
  id?: string;
  arch?: string;
  fw?: string;
  ash?: number;
  status?: string;
  last_seen?: string;
  logs?: string[];
  cpuUsage?: number;
  memoryUsage?: number;
  uptime?: number;
  location?: string;
  signalStrength?: number;
  ip?: string;
  rollbackPending?: boolean;
  authMode?: string;
  ota?: { phase?: string; version?: string; progress?: number | null; detail?: string | null; at?: string };
};

type GatewayDashboard = {
  pi_stats?: Record<string, unknown>;
  devices?: GatewayDevice[];
  ash_devices?: Array<Record<string, unknown>>;
  alerts?: string[];
  events?: Array<Record<string, unknown>>;
  releases?: Array<Record<string, unknown>>;
  pipeline?: Record<string, unknown> | null;
  keys?: Array<Record<string, unknown>>;
  certificates?: Array<Record<string, unknown>>;
  deployments?: Array<Record<string, unknown>>;
};

const REQUEST_TIMEOUT_MS = 4000;

/**
 * Devices heartbeat every 15 s or so. One that has been silent for two
 * minutes is shown offline, whatever status text it sent last.
 */
const OFFLINE_AFTER_MS = 2 * 60 * 1000;

/** The gateway's old default for a device that sent no location. Not a place. */
const LEGACY_PLACEHOLDER_LOCATION = 'Edge Gateway Network';

const EVENT_TYPES = new Set(['firmware_update', 'deployment', 'error', 'warning', 'info', 'security']);
const EVENT_SEVERITIES = new Set(['info', 'warning', 'error', 'success', 'debug']);
const RELEASE_STATUSES = new Set(['draft', 'published', 'archived']);
const STAGE_STATUSES = new Set(['pending', 'running', 'success', 'failed', 'skipped']);
const DEPLOYMENT_STATUSES = new Set(['pending', 'in_progress', 'success', 'failed', 'partial', 'cancelled']);
const TARGET_STATES = new Set(['pending', 'confirmed', 'failed', 'cancelled']);

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

/** ISO string for a real timestamp, null for a missing or unparseable one. */
function isoOrNull(value: unknown): string | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  if (typeof value === 'string' && !value.trim()) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function pick(value: unknown, allowed: Set<string>, fallback: string) {
  const normalized = String(value ?? '').toLowerCase();
  return allowed.has(normalized) ? normalized : fallback;
}

function mapDeviceType(value: string | undefined) {
  const normalized = (value || '').toUpperCase();
  if (normalized.includes('ESP8266')) return 'ESP8266';
  if (normalized.includes('ESP32')) return 'ESP32';
  if (normalized.includes('STM32')) return 'STM32F103';
  if (normalized.includes('ATMEGA') || normalized.includes('AVR')) return 'ATmega328P';
  return 'Unknown';
}

function mapDeviceStatus(value: string | undefined, lastSync: string | null, nowMs: number) {
  if (!lastSync || nowMs - new Date(lastSync).getTime() > OFFLINE_AFTER_MS) return 'offline';
  const normalized = (value || '').toLowerCase();
  if (normalized.includes('updat')) return 'updating';
  if (normalized.includes('quarant') || normalized.includes('error') || normalized.includes('critical')) return 'error';
  if (normalized.includes('off')) return 'offline';
  if (normalized.includes('online') || normalized.includes('healthy')) return 'online';
  return 'standby';
}

function mapHealth(ash: number) {
  if (ash >= 85) return 'excellent';
  if (ash >= 65) return 'good';
  if (ash >= 45) return 'fair';
  if (ash >= 25) return 'poor';
  return 'critical';
}

function lastSeenIso(lastSeen: string | undefined): string | null {
  if (!lastSeen) return null;
  // Very old gateways stored a bare HH:MM:SS. That has no date, so it cannot
  // say when the device was last seen.
  if (/^\d{2}:\d{2}:\d{2}$/.test(lastSeen)) return null;
  return isoOrNull(lastSeen);
}

function simpleHash(value: string) {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(16);
}

function logSeverity(logLine: string): 'info' | 'warning' | 'error' | 'success' {
  const normalized = logLine.toLowerCase();
  if (/(error|failed|fail|panic|quarant|denied|invalid)/.test(normalized)) return 'error';
  if (/(warn|retry|timeout|degraded|slow)/.test(normalized)) return 'warning';
  if (/(success|updated|connected|ready|healthy|listening)/.test(normalized)) return 'success';
  return 'info';
}

type Fetched<T> = { data: T | null; status: number | null; error: string | null };

async function fetchGateway<T>(path: string): Promise<Fetched<T>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${gatewayUrl}${path}`, {
      headers: gatewayHeaders(),
      cache: 'no-store',
      signal: controller.signal,
    });
    if (!response.ok) {
      return { data: null, status: response.status, error: `${path} returned ${response.status}` };
    }
    return { data: (await response.json()) as T, status: response.status, error: null };
  } catch (error) {
    return { data: null, status: null, error: error instanceof Error ? error.message : `Unable to load ${path}` };
  } finally {
    clearTimeout(timeout);
  }
}

export async function GET(request: Request) {
  const auth = await authenticateRequest(request);
  if (!auth) {
    return NextResponse.json({ ok: false, error: 'Unauthorized request. Please login again.' }, { status: 401 });
  }

  const [dashboardResult, manifestResult, deploymentsResult, publicKeyResult] = await Promise.all([
    fetchGateway<GatewayDashboard>('/api/dashboard'),
    fetchGateway<Record<string, unknown>>('/releases/latest/manifest'),
    // Read separately: this endpoint expires deployments past their deadline,
    // so its statuses are current where the dashboard copy may not be.
    fetchGateway<{ deployments?: Array<Record<string, unknown>> }>('/api/deployments'),
    fetchGateway<Record<string, unknown>>('/releases/latest/public-key'),
  ]);

  const dashboard = dashboardResult.data;
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();

  // ── Devices ──────────────────────────────────────────────────
  const gatewayDevices = (dashboard?.devices || []).filter((device) => typeof device.id === 'string' && device.id);
  const manifestRaw = manifestResult.data;

  const devices = gatewayDevices.map((device) => {
    const ash = typeof device.ash === 'number' ? device.ash : 0;
    const firmwareVersion = device.fw || 'unknown';
    const lastSync = lastSeenIso(device.last_seen);
    const location = (device.location || '').trim();

    return {
      id: String(device.id),
      name: String(device.id),
      type: mapDeviceType(device.arch),
      status: mapDeviceStatus(device.status, lastSync, nowMs),
      reportedStatus: String(device.status || ''),
      firmwareVersion,
      // Replaced below with the newest release this device's architecture can run.
      latestVersion: firmwareVersion,
      lastSync,
      location: location === LEGACY_PLACEHOLDER_LOCATION ? '' : location,
      health: mapHealth(ash),
      ash,
      cpuUsage: typeof device.cpuUsage === 'number' ? device.cpuUsage : 0,
      memoryUsage: typeof device.memoryUsage === 'number' ? device.memoryUsage : 0,
      uptime: typeof device.uptime === 'number' ? device.uptime : 0,
      signalStrength: typeof device.signalStrength === 'number' ? device.signalStrength : undefined,
      ip: device.ip || undefined,
      authMode: device.authMode || undefined,
      rollbackPending: Boolean(device.rollbackPending),
      ota: device.ota?.phase
        ? {
            phase: device.ota.phase,
            version: device.ota.version || '',
            progress: typeof device.ota.progress === 'number' ? device.ota.progress : null,
            detail: device.ota.detail || null,
            at: device.ota.at || null,
          }
        : undefined,
    };
  });

  const ashDevices = (dashboard?.ash_devices || []).map((entry) => ({
    id: String(entry.id || ''),
    score: Number(entry.score ?? 0),
    status: String(entry.status || ''),
  })).filter((entry) => entry.id);

  const piStatsRaw = dashboard?.pi_stats ? asRecord(dashboard.pi_stats) : null;
  const piStats = piStatsRaw
    ? { ip: String(piStatsRaw.ip ?? ''), temp: String(piStatsRaw.temp ?? ''), load: String(piStatsRaw.load ?? '') }
    : null;

  // ── Releases ─────────────────────────────────────────────────
  const releases = (dashboard?.releases || []).map((release, index) => {
    const item = asRecord(release);
    const assets = Array.isArray(item.assets) ? item.assets : [];
    return {
      id: String(item.id || `release-${index + 1}`),
      version: String(item.version || ''),
      releaseDate: isoOrNull(item.releaseDate || item.createdAt),
      description: String(item.description || ''),
      assets: assets.map((asset, assetIndex) => {
        const record = asRecord(asset);
        return {
          id: String(record.id || `asset-${index + 1}-${assetIndex + 1}`),
          name: String(record.name || record.filename || ''),
          size: Number(record.size || 0),
          checksum: String(record.checksum || record.sha256 || ''),
          createdAt: isoOrNull(record.createdAt),
        };
      }),
      compatible: Array.isArray(item.compatible) ? item.compatible.map((value) => String(value)) : [],
      changelog: String(item.changelog || ''),
      downloadCount: Number(item.downloadCount || 0),
      status: pick(item.status, RELEASE_STATUSES, 'published'),
      archivedAt: isoOrNull(item.archivedAt),
      securePackage: typeof item.securePackage === 'boolean' ? item.securePackage : undefined,
    };
  });

  // Newest published release each device could install (releases are newest
  // first; an empty `compatible` list means every architecture, as on the gateway).
  devices.forEach((device) => {
    const offered = releases.find(
      (release) =>
        release.status === 'published' &&
        (release.compatible.length === 0 || release.compatible.includes(device.type))
    );
    if (offered?.version) device.latestVersion = offered.version;
  });

  // ── Manifest (as served; 404 means nothing is published) ─────
  const manifest = manifestRaw
    ? {
        version: String(manifestRaw.version || ''),
        filename: String(manifestRaw.filename || ''),
        sha256: String(manifestRaw.sha256 || ''),
        size: Number(manifestRaw.size || 0),
        signature: String(manifestRaw.signature || ''),
        signatureAlgorithm: String(manifestRaw.signatureAlgorithm || ''),
        signatureKeyId: String(manifestRaw.signatureKeyId || ''),
        generatedAt: isoOrNull(manifestRaw.generated_at),
        url: String(manifestRaw.downloadUrl || manifestRaw.url || ''),
        compatible: Array.isArray(manifestRaw.compatible) ? manifestRaw.compatible.map(String) : [],
        imageSha256: typeof manifestRaw.imageSha256 === 'string' ? manifestRaw.imageSha256 : undefined,
        securePackage: manifestRaw.securePackage === true ? true : undefined,
        raw: manifestRaw,
      }
    : null;

  // ── Events ───────────────────────────────────────────────────
  const gatewayEvents = (dashboard?.events || []).flatMap((event, index) => {
    const item = asRecord(event);
    const timestamp = isoOrNull(item.timestamp || item.createdAt);
    if (!timestamp) return [];
    return [{
      id: String(item.id || `gateway-event-${index + 1}`),
      timestamp,
      type: pick(item.type, EVENT_TYPES, 'info'),
      severity: pick(item.severity, EVENT_SEVERITIES, 'info'),
      title: String(item.title || item.type || 'Gateway event'),
      description: String(item.description || item.message || ''),
      deviceId: item.deviceId ? String(item.deviceId) : undefined,
    }];
  });

  // Alerts are stored as "[<iso time>] message". Without that prefix there is
  // no time to show, so the alert is listed in `alerts` only.
  const alerts = (dashboard?.alerts || []).map(String);
  const alertEvents = alerts.flatMap((line) => {
    const match = /^\[([^\]]+)\]\s*(.*)$/.exec(line);
    const timestamp = match ? isoOrNull(match[1]) : null;
    if (!match || !timestamp) return [];
    const message = match[2];
    return [{
      id: `alert-${simpleHash(line)}`,
      timestamp,
      type: 'warning',
      severity: /critical|quarantine|attack|fail/i.test(message) ? 'error' : 'warning',
      title: 'Gateway alert',
      description: message,
    }];
  });

  const deviceEvents = gatewayDevices.flatMap((device) => {
    const deviceId = String(device.id);
    const timestamp = lastSeenIso(device.last_seen);
    if (!timestamp) return [];
    const ash = typeof device.ash === 'number' ? device.ash : 0;
    const cpu = Number.isFinite(Number(device.cpuUsage)) ? Number(device.cpuUsage) : 0;
    const memory = Number.isFinite(Number(device.memoryUsage)) ? Number(device.memoryUsage) : 0;
    const uptime = Number.isFinite(Number(device.uptime)) ? Math.max(Number(device.uptime), 0) : 0;
    const rssi = typeof device.signalStrength === 'number' ? `${device.signalStrength} dBm` : 'n/a';

    const heartbeat = {
      id: `heartbeat-${deviceId}-${simpleHash(`${timestamp}-${ash}-${cpu}-${memory}-${rssi}`)}`,
      timestamp,
      type: 'info',
      severity: ash <= 40 ? 'error' : ash <= 60 ? 'warning' : 'success',
      title: `Device heartbeat: ${deviceId}`,
      description: `FW ${String(device.fw || 'unknown')} | ASH ${ash}/100 | CPU ${cpu.toFixed(1)}% | MEM ${memory.toFixed(1)}% | Uptime ${Math.floor(uptime)}s | RSSI ${rssi}`,
      deviceId,
    };

    const logs = (Array.isArray(device.logs) ? device.logs : [])
      .slice(-12)
      .map((entry) => String(entry).trim())
      .filter(Boolean)
      .map((entry, logIndex) => ({
        id: `device-log-${deviceId}-${simpleHash(`${timestamp}-${entry}-${logIndex}`)}`,
        timestamp,
        type: 'info',
        severity: logSeverity(entry),
        title: `Device log: ${deviceId}`,
        description: entry,
        deviceId,
      }));

    return [heartbeat, ...logs];
  });

  const events = [...gatewayEvents, ...alertEvents, ...deviceEvents].sort(
    (left, right) => new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
  );

  // ── Pipeline ─────────────────────────────────────────────────
  const pipelineRecord = dashboard?.pipeline ? asRecord(dashboard.pipeline) : null;
  const pipeline = pipelineRecord
    ? {
        id: String(pipelineRecord.id || ''),
        releaseId: String(pipelineRecord.releaseId || ''),
        createdAt: isoOrNull(pipelineRecord.createdAt),
        stages: (Array.isArray(pipelineRecord.stages) ? pipelineRecord.stages : []).map((stage, index) => {
          const item = asRecord(stage);
          return {
            id: String(item.id || `stage-${index + 1}`),
            name: String(item.name || `stage ${index + 1}`),
            status: pick(item.status, STAGE_STATUSES, 'pending'),
            startTime: isoOrNull(item.startTime) ?? undefined,
            endTime: isoOrNull(item.endTime) ?? undefined,
            logs: String(item.logs || ''),
            duration: item.duration !== undefined ? Number(item.duration) : undefined,
          };
        }),
        status: pick(pipelineRecord.status, STAGE_STATUSES, 'pending'),
        totalDuration: Number(pipelineRecord.totalDuration || 0),
      }
    : null;

  // ── Signing key ──────────────────────────────────────────────
  const keys = (dashboard?.keys || []).map((key, index) => {
    const item = asRecord(key);
    return {
      id: String(item.id || `key-${index + 1}`),
      name: String(item.name || ''),
      type: String(item.type || ''),
      keySize: Number(item.keySize || 0),
      createdAt: isoOrNull(item.createdAt),
      expiresAt: isoOrNull(item.expiresAt) ?? undefined,
      active: item.active === undefined ? true : Boolean(item.active),
    };
  });

  const certificates = (dashboard?.certificates || []).map((certificate, index) => {
    const item = asRecord(certificate);
    return {
      id: String(item.id || `cert-${index + 1}`),
      name: String(item.name || ''),
      issuer: String(item.issuer || ''),
      subject: String(item.subject || ''),
      validFrom: isoOrNull(item.validFrom),
      validTo: isoOrNull(item.validTo),
      fingerprint: String(item.fingerprint || ''),
    };
  });

  const publicKeyRaw = publicKeyResult.data;
  const signingKey = publicKeyRaw && typeof publicKeyRaw.publicKeyPem === 'string'
    ? {
        algorithm: String(publicKeyRaw.algorithm || ''),
        keyId: String(publicKeyRaw.keyId || ''),
        fingerprint: String(publicKeyRaw.fingerprint || ''),
        publicKeyPem: publicKeyRaw.publicKeyPem,
      }
    : null;

  // ── Deployments, with per-device targets ─────────────────────
  const rawDeployments = deploymentsResult.data?.deployments ?? dashboard?.deployments ?? [];
  const deployments = rawDeployments.flatMap((deployment) => {
    const item = asRecord(deployment);
    const startedAt = isoOrNull(item.startedAt);
    if (!item.id || !startedAt) return [];
    const targets = Object.fromEntries(
      Object.entries(asRecord(item.targets)).map(([deviceId, target]) => {
        const record = asRecord(target);
        return [
          deviceId,
          {
            state: pick(record.state, TARGET_STATES, 'pending'),
            reason: record.reason ? String(record.reason) : null,
            fromVersion: record.fromVersion ? String(record.fromVersion) : null,
            confirmedAt: isoOrNull(record.confirmedAt),
          },
        ];
      })
    );
    return [{
      id: String(item.id),
      releaseId: String(item.releaseId || ''),
      version: String(item.version || ''),
      deviceIds: Array.isArray(item.deviceIds) ? item.deviceIds.map(String) : Object.keys(targets),
      targets,
      status: pick(item.status, DEPLOYMENT_STATUSES, 'pending'),
      startedAt,
      completedAt: isoOrNull(item.completedAt) ?? undefined,
      deadline: isoOrNull(item.deadline) ?? undefined,
      successCount: Number(item.successCount || 0),
      failureCount: Number(item.failureCount || 0),
      pendingCount: Number(item.pendingCount || 0),
      cancelledCount: Number(item.cancelledCount || 0),
      retryOf: item.retryOf ? String(item.retryOf) : undefined,
      logs: String(item.logs || ''),
    }];
  });

  // A 404 manifest only means nothing is published yet; it is not a fault.
  const manifestError = manifestResult.status === 404 ? null : manifestResult.error;
  const reachable = Boolean(dashboard) || manifestResult.status !== null;
  const ok = Boolean(dashboard) && !manifestError;
  const rawErrors = Array.from(new Set([dashboardResult.error, manifestError].filter(Boolean) as string[]));
  const errorMessage = !reachable
    ? `Can't reach the gateway at ${gatewayUrl}. Start it (scripts/start-gateway.cmd) and this page will update on its own.`
    : rawErrors.join(' | ') || null;

  return NextResponse.json({
    ok,
    generatedAt: nowIso,
    connection: { gatewayUrl, reachable, error: errorMessage },
    devices,
    ashDevices,
    piStats,
    alerts,
    events,
    releases,
    manifest,
    pipeline,
    keys,
    certificates,
    signingKey,
    deployments,
  });
}
