import { NextResponse } from 'next/server';
import { authenticateRequest } from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

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
};

type GatewayEvent = Record<string, unknown>;
type GatewayRelease = Record<string, unknown>;
type GatewayPipeline = Record<string, unknown>;
type GatewayKey = Record<string, unknown>;
type GatewayCertificate = Record<string, unknown>;
type GatewayDeployment = Record<string, unknown>;

type GatewayDashboard = {
  devices?: GatewayDevice[];
  alerts?: string[];
  events?: GatewayEvent[];
  releases?: GatewayRelease[];
  pipeline?: GatewayPipeline | null;
  keys?: GatewayKey[];
  certificates?: GatewayCertificate[];
  deployments?: GatewayDeployment[];
};

type ManifestPayload = {
  version?: string;
  filename?: string;
  sha256?: string;
  size?: number;
  signature?: string;
  url?: string;
};

const REQUEST_TIMEOUT_MS = 4000;

const ALLOWED_EVENT_TYPES = new Set(['firmware_update', 'deployment', 'error', 'warning', 'info', 'security']);
const ALLOWED_EVENT_SEVERITIES = new Set(['info', 'warning', 'error', 'success', 'debug']);
const ALLOWED_RELEASE_STATUSES = new Set(['draft', 'published', 'archived']);
const ALLOWED_PIPELINE_STAGE_NAMES = new Set(['build', 'test', 'deploy', 'verify']);
const ALLOWED_PIPELINE_STAGE_STATUSES = new Set(['pending', 'running', 'success', 'failed', 'skipped']);
const ALLOWED_KEY_TYPES = new Set(['RSA', 'ECDSA', 'AES']);
const ALLOWED_DEPLOYMENT_STATUSES = new Set(['pending', 'in-progress', 'success', 'failed', 'partial']);

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function asDateIso(value: unknown) {
  const parsed = new Date(typeof value === 'string' || typeof value === 'number' ? value : Date.now());
  return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

function asEventType(value: unknown) {
  const normalized = String(value || 'info').toLowerCase();
  return ALLOWED_EVENT_TYPES.has(normalized) ? normalized : 'info';
}

function asEventSeverity(value: unknown) {
  const normalized = String(value || 'info').toLowerCase();
  return ALLOWED_EVENT_SEVERITIES.has(normalized) ? normalized : 'info';
}

function asReleaseStatus(value: unknown) {
  const normalized = String(value || 'published').toLowerCase();
  return ALLOWED_RELEASE_STATUSES.has(normalized) ? normalized : 'published';
}

function asPipelineStageName(value: unknown) {
  const normalized = String(value || 'deploy').toLowerCase();
  return ALLOWED_PIPELINE_STAGE_NAMES.has(normalized) ? normalized : 'deploy';
}

function asPipelineStageStatus(value: unknown) {
  const normalized = String(value || 'pending').toLowerCase();
  return ALLOWED_PIPELINE_STAGE_STATUSES.has(normalized) ? normalized : 'pending';
}

function asKeyType(value: unknown) {
  const normalized = String(value || 'RSA').toUpperCase();
  return ALLOWED_KEY_TYPES.has(normalized) ? normalized : 'RSA';
}

function asDeploymentStatus(value: unknown) {
  const normalized = String(value || 'pending').toLowerCase();
  return ALLOWED_DEPLOYMENT_STATUSES.has(normalized) ? normalized : 'pending';
}

function mapDeviceType(value: string | undefined) {
  const normalized = (value || '').toUpperCase();
  if (normalized.includes('ESP8266')) return 'ESP8266';
  if (normalized.includes('ESP32')) return 'ESP32';
  if (normalized.includes('STM32')) return 'STM32F103';
  if (normalized.includes('ATMEGA') || normalized.includes('AVR')) return 'ATmega328P';
  return 'ESP32';
}

function mapDeviceStatus(value: string | undefined) {
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

function toIsoFromLastSeen(lastSeen: string | undefined) {
  if (!lastSeen) {
    return new Date().toISOString();
  }

  const timeOnly = /^\d{2}:\d{2}:\d{2}$/.test(lastSeen);
  if (timeOnly) {
    const now = new Date();
    const [hour, minute, second] = lastSeen.split(':').map((value) => Number(value));
    now.setHours(hour, minute, second, 0);
    return now.toISOString();
  }

  const parsed = new Date(lastSeen);
  if (Number.isNaN(parsed.getTime())) {
    return new Date().toISOString();
  }

  return parsed.toISOString();
}

function simpleHash(value: string) {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(i);
    hash |= 0;
  }

  return Math.abs(hash).toString(16);
}

async function fetchJson<T>(url: string): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      cache: 'no-store',
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`${url} returned ${response.status}`);
    }

    return (await response.json()) as T;
  } finally {
    clearTimeout(timeout);
  }
}

export async function GET(request: Request) {
  const auth = await authenticateRequest(request);
  if (!auth) {
    return NextResponse.json(
      {
        ok: false,
        error: 'Unauthorized request. Please login again.',
      },
      { status: 401 }
    );
  }

  const gatewayUrl = process.env.EDGE_GATEWAY_URL || 'http://localhost:5000';
  const gatewayApiKey = process.env.EDGE_GATEWAY_API_KEY;

  let dashboard: GatewayDashboard | null = null;
  let manifestPayload: ManifestPayload | null = null;
  let dashboardError: string | null = null;
  let manifestError: string | null = null;

  try {
    const url = `${gatewayUrl}/api/dashboard`;
    dashboard = await fetchJson<GatewayDashboard>(
      gatewayApiKey ? `${url}?api_key=${encodeURIComponent(gatewayApiKey)}` : url
    );
  } catch (error) {
    dashboardError = error instanceof Error ? error.message : 'Unable to load gateway dashboard data.';
  }

  try {
    const url = `${gatewayUrl}/releases/latest/manifest`;
    manifestPayload = await fetchJson<ManifestPayload>(
      gatewayApiKey ? `${url}?api_key=${encodeURIComponent(gatewayApiKey)}` : url
    );
  } catch (error) {
    manifestError = error instanceof Error ? error.message : 'Unable to load firmware manifest.';
  }

  const devices = (dashboard?.devices || []).map((device, index) => {
    const ash = typeof device.ash === 'number' ? device.ash : 0;
    const deviceType = mapDeviceType(device.arch);
    const firmwareVersion = device.fw || 'unknown';

    return {
      id: device.id || `unknown-device-${index + 1}`,
      name: device.id || 'Unnamed device',
      type: deviceType,
      status: mapDeviceStatus(device.status),
      firmwareVersion,
      latestVersion: manifestPayload?.version || firmwareVersion,
      lastSync: toIsoFromLastSeen(device.last_seen),
      location: device.location || 'Edge Gateway Network',
      health: mapHealth(ash),
      cpuUsage: typeof device.cpuUsage === 'number' ? device.cpuUsage : 0,
      memoryUsage: typeof device.memoryUsage === 'number' ? device.memoryUsage : 0,
      uptime: typeof device.uptime === 'number' ? device.uptime : 0,
      signalStrength: typeof device.signalStrength === 'number' ? device.signalStrength : undefined,
    };
  });

  const compatibility = Array.from(new Set(devices.map((device) => device.type)));
  const manifestVersion = manifestPayload?.version || 'unknown';
  const nowIso = new Date().toISOString();

  const releasesFromDashboard = (dashboard?.releases || []).map((release, index) => {
    const item = asRecord(release);
    const assetsRaw = Array.isArray(item.assets) ? item.assets : [];

    return {
      id: String(item.id || `gateway-release-${index + 1}`),
      version: String(item.version || manifestVersion),
      releaseDate: asDateIso(item.releaseDate || item.createdAt || nowIso),
      description: String(item.description || 'Gateway release telemetry'),
      assets: assetsRaw.map((asset, assetIndex) => {
        const assetRecord = asRecord(asset);
        return {
          id: String(assetRecord.id || `gateway-asset-${index + 1}-${assetIndex + 1}`),
          name: String(assetRecord.name || assetRecord.filename || 'firmware.bin'),
          size: Number(assetRecord.size || 0),
          checksum: String(assetRecord.checksum || assetRecord.sha256 || 'n/a'),
          createdAt: asDateIso(assetRecord.createdAt || nowIso),
        };
      }),
      compatible: Array.isArray(item.compatible)
        ? item.compatible.map((value) => mapDeviceType(String(value))).filter(Boolean)
        : compatibility.length > 0
          ? compatibility
          : ['ESP32'],
      changelog: String(item.changelog || ''),
      downloadCount: Number(item.downloadCount || 0),
      status: asReleaseStatus(item.status),
    };
  });

  const releases = releasesFromDashboard.length > 0
    ? releasesFromDashboard
    : manifestPayload
      ? [
          {
            id: `release-${manifestVersion.replace(/[^\w.-]/g, '-')}`,
            version: manifestVersion,
            releaseDate: nowIso,
            description: 'Release inferred from live manifest payload.',
            assets: manifestPayload.filename
              ? [
                  {
                    id: `asset-${manifestPayload.filename}`,
                    name: manifestPayload.filename,
                    size: typeof manifestPayload.size === 'number' ? manifestPayload.size : 0,
                    checksum: manifestPayload.sha256 || 'n/a',
                    createdAt: nowIso,
                  },
                ]
              : [],
            compatible: compatibility.length > 0 ? compatibility : ['ESP32'],
            changelog: 'Manifest-only release snapshot.',
            downloadCount: 0,
            status: 'published',
          },
        ]
      : [];

  const manifest = manifestPayload
    ? {
        id: `manifest-${manifestVersion.replace(/[^\w.-]/g, '-')}`,
        releaseId: releases[0]?.id || 'manifest-release',
        entries:
          compatibility.length > 0
            ? compatibility.map((deviceType) => ({
                device: deviceType,
                version: manifestVersion,
                checksum: manifestPayload?.sha256 || 'n/a',
                size: typeof manifestPayload?.size === 'number' ? manifestPayload.size : 0,
                url: manifestPayload?.url || `/releases/download/${manifestPayload?.filename || ''}`,
              }))
            : [
                {
                  device: 'ESP32',
                  version: manifestVersion,
                  checksum: manifestPayload?.sha256 || 'n/a',
                  size: typeof manifestPayload?.size === 'number' ? manifestPayload.size : 0,
                  url: manifestPayload?.url || `/releases/download/${manifestPayload?.filename || ''}`,
                },
              ],
        createdAt: nowIso,
        signature: manifestPayload.signature,
      }
    : null;

  const gatewayEvents = (dashboard?.events || []).map((event, index) => {
    const item = asRecord(event);
    return {
      id: String(item.id || `gateway-event-${index + 1}`),
      timestamp: asDateIso(item.timestamp || item.createdAt || nowIso),
      type: asEventType(item.type),
      severity: asEventSeverity(item.severity),
      title: String(item.title || item.type || 'Gateway Event'),
      description: String(item.description || item.message || 'Gateway emitted an event.'),
      deviceId: item.deviceId ? String(item.deviceId) : undefined,
    };
  });

  const alertEvents = (dashboard?.alerts || []).map((message, index) => ({
    id: `alert-${index}-${simpleHash(message)}`,
    timestamp: nowIso,
    type: 'warning',
    severity: /critical|quarantine|attack|fail/i.test(message) ? 'error' : 'warning',
    title: 'Gateway Alert',
    description: message,
  }));

  const events = [...gatewayEvents, ...alertEvents].sort((left, right) => {
    return new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
  });

  const pipelineRecord = dashboard?.pipeline ? asRecord(dashboard.pipeline) : null;
  const pipeline = pipelineRecord
    ? {
        id: String(pipelineRecord.id || 'gateway-pipeline'),
        releaseId: String(pipelineRecord.releaseId || releases[0]?.id || 'gateway-release'),
        createdAt: asDateIso(pipelineRecord.createdAt || nowIso),
        stages: (Array.isArray(pipelineRecord.stages) ? pipelineRecord.stages : []).map((stage, index) => {
          const item = asRecord(stage);
          return {
            id: String(item.id || `gateway-stage-${index + 1}`),
            name: asPipelineStageName(item.name),
            status: asPipelineStageStatus(item.status),
            startTime: item.startTime ? asDateIso(item.startTime) : undefined,
            endTime: item.endTime ? asDateIso(item.endTime) : undefined,
            logs: String(item.logs || ''),
            duration: item.duration !== undefined ? Number(item.duration) : undefined,
          };
        }),
        status: asPipelineStageStatus(pipelineRecord.status),
        totalDuration: Number(pipelineRecord.totalDuration || 0),
      }
    : null;

  const keys = (dashboard?.keys || []).map((key, index) => {
    const item = asRecord(key);
    return {
      id: String(item.id || `gateway-key-${index + 1}`),
      name: String(item.name || `Gateway Key ${index + 1}`),
      type: asKeyType(item.type),
      keySize: Number(item.keySize || 256),
      createdAt: asDateIso(item.createdAt || nowIso),
      expiresAt: item.expiresAt ? asDateIso(item.expiresAt) : undefined,
      active: item.active === undefined ? true : Boolean(item.active),
    };
  });

  const certificates = (dashboard?.certificates || []).map((certificate, index) => {
    const item = asRecord(certificate);
    return {
      id: String(item.id || `gateway-cert-${index + 1}`),
      name: String(item.name || `Gateway Certificate ${index + 1}`),
      issuer: String(item.issuer || 'Unknown Issuer'),
      subject: String(item.subject || 'Unknown Subject'),
      validFrom: asDateIso(item.validFrom || nowIso),
      validTo: asDateIso(item.validTo || nowIso),
      fingerprint: String(item.fingerprint || 'n/a'),
    };
  });

  const deployments = (dashboard?.deployments || []).map((deployment, index) => {
    const item = asRecord(deployment);
    return {
      id: String(item.id || `gateway-deployment-${index + 1}`),
      releaseId: String(item.releaseId || releases[0]?.id || 'gateway-release'),
      deviceIds: Array.isArray(item.deviceIds) ? item.deviceIds.map((deviceId) => String(deviceId)) : [],
      status: asDeploymentStatus(item.status),
      startedAt: asDateIso(item.startedAt || nowIso),
      completedAt: item.completedAt ? asDateIso(item.completedAt) : undefined,
      successCount: Number(item.successCount || 0),
      failureCount: Number(item.failureCount || 0),
      logs: String(item.logs || ''),
    };
  });

  const reachable = Boolean(dashboard || manifestPayload);
  const ok = Boolean(dashboard && manifestPayload);
  const errorMessage = [dashboardError, manifestError].filter(Boolean).join(' | ') || null;

  return NextResponse.json({
    ok,
    generatedAt: nowIso,
    connection: {
      gatewayUrl,
      reachable,
      error: errorMessage,
    },
    devices,
    events,
    releases,
    manifest,
    pipeline,
    keys,
    certificates,
    deployments,
  });
}
