'use client';

import React from 'react';
import { isLiveConnected, subscribeToGatewayChanges } from '@/lib/live-updates';
import { apiFetch, clearAuthSession } from '@/lib/client-auth';
import type {
  AshDevice,
  Certificate,
  Deployment,
  DeploymentTarget,
  Device,
  Event,
  GatewayHostStats,
  Key,
  Manifest,
  Pipeline,
  Release,
  SigningPublicKey,
} from '@/lib/types';
import { logger, errorTracker } from '@/lib/logger';

type RuntimeConnection = {
  gatewayUrl: string;
  reachable: boolean;
  error?: string | null;
};

type RuntimeSnapshot = {
  ok: boolean;
  generatedAt: string;
  connection: RuntimeConnection;
  devices: Device[];
  /** Raw ASH score per device, straight from the gateway. */
  ashDevices: AshDevice[];
  /** Host stats of the machine the gateway runs on; null when not reported. */
  piStats: GatewayHostStats | null;
  /** Gateway alert lines, newest first. */
  alerts: string[];
  events: Event[];
  releases: Release[];
  manifest: Manifest | null;
  pipeline: Pipeline | null;
  keys: Key[];
  certificates: Certificate[];
  /** Public half of the gateway's signing key; null when it could not be read. */
  signingKey: SigningPublicKey | null;
  deployments: Deployment[];
};

const emptySnapshot: RuntimeSnapshot = {
  ok: false,
  generatedAt: new Date(0).toISOString(),
  connection: {
    gatewayUrl: '',
    reachable: false,
    error: 'No runtime data loaded.',
  },
  devices: [],
  ashDevices: [],
  piStats: null,
  alerts: [],
  events: [],
  releases: [],
  manifest: null,
  pipeline: null,
  keys: [],
  certificates: [],
  signingKey: null,
  deployments: [],
};

/** A Date for a real timestamp, null for a missing or unparseable one. */
function asDateOrNull(value: unknown): Date | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/** For fields the server only sends when it has a real timestamp. */
function asDate(value: unknown): Date {
  return asDateOrNull(value) ?? new Date(0);
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function normalizeSnapshot(raw: unknown): RuntimeSnapshot {
  if (!raw || typeof raw !== 'object') {
    return emptySnapshot;
  }

  const payload = raw as Record<string, unknown>;

  const devices = asList(payload.devices).map((device) => {
    const item = asRecord(device);
    return {
      id: String(item.id || ''),
      name: String(item.name || item.id || ''),
      type: String(item.type || 'Unknown') as Device['type'],
      status: String(item.status || 'offline') as Device['status'],
      reportedStatus: String(item.reportedStatus || ''),
      firmwareVersion: String(item.firmwareVersion || 'unknown'),
      latestVersion: String(item.latestVersion || item.firmwareVersion || 'unknown'),
      lastSync: asDateOrNull(item.lastSync),
      location: String(item.location || ''),
      health: String(item.health || 'critical') as Device['health'],
      ash: Number(item.ash || 0),
      cpuUsage: Number(item.cpuUsage || 0),
      memoryUsage: Number(item.memoryUsage || 0),
      uptime: Number(item.uptime || 0),
      signalStrength: item.signalStrength !== undefined ? Number(item.signalStrength) : undefined,
      ip: typeof item.ip === 'string' ? item.ip : undefined,
      authMode: typeof item.authMode === 'string' ? item.authMode : undefined,
      rollbackPending: Boolean(item.rollbackPending),
      ota: item.ota && typeof item.ota === 'object' ? (item.ota as Device['ota']) : undefined,
    } satisfies Device;
  });

  const ashDevices = asList(payload.ashDevices).map((entry) => {
    const item = asRecord(entry);
    return { id: String(item.id || ''), score: Number(item.score || 0), status: String(item.status || '') };
  });

  const piRaw = payload.piStats ? asRecord(payload.piStats) : null;
  const piStats = piRaw ? { ip: String(piRaw.ip || ''), temp: String(piRaw.temp || ''), load: String(piRaw.load || '') } : null;

  const events = asList(payload.events).map((event) => {
    const item = asRecord(event);
    return {
      id: String(item.id || ''),
      timestamp: asDate(item.timestamp),
      type: String(item.type || 'info') as Event['type'],
      severity: String(item.severity || 'info') as Event['severity'],
      title: String(item.title || 'Event'),
      description: String(item.description || ''),
      deviceId: item.deviceId ? String(item.deviceId) : undefined,
    } satisfies Event;
  });

  const releases = asList(payload.releases).map((release) => {
    const item = asRecord(release);
    return {
      id: String(item.id || ''),
      version: String(item.version || ''),
      releaseDate: asDate(item.releaseDate),
      description: String(item.description || ''),
      assets: asList(item.assets).map((asset) => {
        const assetItem = asRecord(asset);
        return {
          id: String(assetItem.id || ''),
          name: String(assetItem.name || ''),
          size: Number(assetItem.size || 0),
          checksum: String(assetItem.checksum || ''),
          createdAt: asDate(assetItem.createdAt),
        };
      }),
      compatible: asList(item.compatible).map((value) => String(value)),
      changelog: String(item.changelog || ''),
      downloadCount: Number(item.downloadCount || 0),
      status: String(item.status || 'published') as Release['status'],
      archivedAt: asDateOrNull(item.archivedAt) ?? undefined,
      securePackage: typeof item.securePackage === 'boolean' ? item.securePackage : undefined,
    } satisfies Release;
  });

  const manifestRaw = payload.manifest ? asRecord(payload.manifest) : null;
  const manifest = manifestRaw
    ? ({
        version: String(manifestRaw.version || ''),
        filename: String(manifestRaw.filename || ''),
        sha256: String(manifestRaw.sha256 || ''),
        size: Number(manifestRaw.size || 0),
        signature: String(manifestRaw.signature || ''),
        signatureAlgorithm: String(manifestRaw.signatureAlgorithm || ''),
        signatureKeyId: String(manifestRaw.signatureKeyId || ''),
        generatedAt: asDateOrNull(manifestRaw.generatedAt),
        url: String(manifestRaw.url || ''),
        compatible: asList(manifestRaw.compatible).map(String),
        imageSha256: typeof manifestRaw.imageSha256 === 'string' ? manifestRaw.imageSha256 : undefined,
        securePackage: manifestRaw.securePackage === true ? true : undefined,
        raw: asRecord(manifestRaw.raw),
      } satisfies Manifest)
    : null;

  const pipelineRaw = payload.pipeline ? asRecord(payload.pipeline) : null;
  const pipeline = pipelineRaw
    ? ({
        id: String(pipelineRaw.id || ''),
        releaseId: String(pipelineRaw.releaseId || ''),
        createdAt: asDate(pipelineRaw.createdAt),
        stages: asList(pipelineRaw.stages).map((stage) => {
          const item = asRecord(stage);
          return {
            id: String(item.id || ''),
            name: String(item.name || ''),
            status: String(item.status || 'pending') as Pipeline['stages'][number]['status'],
            startTime: asDateOrNull(item.startTime) ?? undefined,
            endTime: asDateOrNull(item.endTime) ?? undefined,
            logs: String(item.logs || ''),
            duration: item.duration !== undefined ? Number(item.duration) : undefined,
          };
        }),
        status: String(pipelineRaw.status || 'pending') as Pipeline['status'],
        totalDuration: Number(pipelineRaw.totalDuration || 0),
      } satisfies Pipeline)
    : null;

  const keys = asList(payload.keys).map((key) => {
    const item = asRecord(key);
    return {
      id: String(item.id || ''),
      name: String(item.name || ''),
      type: String(item.type || ''),
      keySize: Number(item.keySize || 0),
      createdAt: asDate(item.createdAt),
      expiresAt: asDateOrNull(item.expiresAt) ?? undefined,
      active: item.active === undefined ? true : Boolean(item.active),
    } satisfies Key;
  });

  const certificates = asList(payload.certificates).map((certificate) => {
    const item = asRecord(certificate);
    return {
      id: String(item.id || ''),
      name: String(item.name || ''),
      issuer: String(item.issuer || ''),
      subject: String(item.subject || ''),
      validFrom: asDate(item.validFrom),
      validTo: asDateOrNull(item.validTo) ?? undefined,
      fingerprint: String(item.fingerprint || ''),
    } satisfies Certificate;
  });

  const signingRaw = payload.signingKey ? asRecord(payload.signingKey) : null;
  const signingKey = signingRaw && typeof signingRaw.publicKeyPem === 'string'
    ? {
        algorithm: String(signingRaw.algorithm || ''),
        keyId: String(signingRaw.keyId || ''),
        fingerprint: String(signingRaw.fingerprint || ''),
        publicKeyPem: signingRaw.publicKeyPem,
      }
    : null;

  const deployments = asList(payload.deployments).map((deployment) => {
    const item = asRecord(deployment);
    const targets: Record<string, DeploymentTarget> = {};
    Object.entries(asRecord(item.targets)).forEach(([deviceId, target]) => {
      const record = asRecord(target);
      targets[deviceId] = {
        state: String(record.state || 'pending') as DeploymentTarget['state'],
        reason: record.reason ? String(record.reason) : null,
        fromVersion: record.fromVersion ? String(record.fromVersion) : null,
        confirmedAt: asDateOrNull(record.confirmedAt),
      };
    });
    return {
      id: String(item.id || ''),
      releaseId: String(item.releaseId || ''),
      version: String(item.version || ''),
      deviceIds: asList(item.deviceIds).map((value) => String(value)),
      targets,
      status: String(item.status || 'pending') as Deployment['status'],
      startedAt: asDate(item.startedAt),
      completedAt: asDateOrNull(item.completedAt) ?? undefined,
      deadline: asDateOrNull(item.deadline) ?? undefined,
      successCount: Number(item.successCount || 0),
      failureCount: Number(item.failureCount || 0),
      pendingCount: Number(item.pendingCount || 0),
      cancelledCount: Number(item.cancelledCount || 0),
      retryOf: item.retryOf ? String(item.retryOf) : undefined,
      logs: String(item.logs || ''),
    } satisfies Deployment;
  });

  const connectionRaw = payload.connection as Record<string, unknown> | undefined;

  return {
    ok: Boolean(payload.ok),
    generatedAt: String(payload.generatedAt || new Date().toISOString()),
    connection: {
      gatewayUrl: String(connectionRaw?.gatewayUrl || ''),
      reachable: Boolean(connectionRaw?.reachable),
      error: connectionRaw?.error ? String(connectionRaw.error) : null,
    },
    devices,
    ashDevices,
    piStats,
    alerts: asList(payload.alerts).map(String),
    events,
    releases,
    manifest,
    pipeline,
    keys,
    certificates,
    signingKey,
    deployments,
  };
}

/**
 * Several components (sidebar, top bar, status bar, the page) mount this hook
 * at once. Concurrent loads share one request instead of each firing its own.
 */
let inflightSnapshot: Promise<Response> | null = null;

function fetchSnapshotShared(): Promise<Response> {
  if (!inflightSnapshot) {
    inflightSnapshot = apiFetch('/api/runtime/snapshot', { cache: 'no-store' }).finally(() => {
      inflightSnapshot = null;
    });
  }
  // Each caller reads the body, so hand out clones of the one response.
  return inflightSnapshot.then((response) => response.clone());
}

/** While the live stream is up, polling only backstops it at this interval. */
const LIVE_BACKSTOP_POLL_MS = 30_000;

export function useRuntimeSnapshot(pollMs = 5000) {
  const [snapshot, setSnapshot] = React.useState<RuntimeSnapshot>(emptySnapshot);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const loadSnapshot = React.useCallback(async () => {
    try {
      const response = await fetchSnapshotShared();
      if (!response.ok) {
        if (response.status === 401) {
          logger.warn('RuntimeData', 'Authentication required. Redirecting to login.', { status: response.status });
          // Attempt to clear any client-side session remnants and redirect
          await clearAuthSession(); // This will also call /api/auth/logout
          window.location.href = '/login'; // Force a full page reload
          return; // Stop further processing
        }
        const errorMsg = `Runtime API returned ${response.status}`;
        logger.error('RuntimeData', errorMsg, { status: response.status });
        throw new Error(errorMsg);
      }

      const payload = normalizeSnapshot(await response.json());
      setSnapshot(payload);
      setError(payload.connection.error || null);
    } catch (loadError) {
      const message = loadError instanceof Error ? loadError.message : `Unable to fetch runtime data: ${String(loadError)}`;
      setError(message);
      setSnapshot((current) => ({
        ...current,
        ok: false,
        connection: {
          ...current.connection,
          reachable: false,
          error: message,
        },
      }));
      logger.error('RuntimeData', 'Error loading runtime snapshot', loadError);
      errorTracker.track(loadError, 'RuntimeData:LoadSnapshot');
    } finally {
      setIsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadSnapshot();
    let lastLoad = Date.now();

    // Push: reload as soon as the gateway reports a change.
    const unsubscribe = subscribeToGatewayChanges(() => {
      lastLoad = Date.now();
      void loadSnapshot();
    });

    // Pull: the normal cadence when the stream is down, a slow backstop when up.
    const intervalId = window.setInterval(() => {
      const due = isLiveConnected() ? Math.max(pollMs, LIVE_BACKSTOP_POLL_MS) : pollMs;
      if (Date.now() - lastLoad >= due - 50) {
        lastLoad = Date.now();
        void loadSnapshot();
      }
    }, pollMs);

    return () => {
      unsubscribe();
      window.clearInterval(intervalId);
    };
  }, [loadSnapshot, pollMs]);

  return {
    snapshot,
    isLoading,
    error,
    refresh: loadSnapshot,
  };
}

export type { RuntimeSnapshot };
