'use client';

import React from 'react';
import { apiFetch } from '@/lib/client-auth';
import type {
  Certificate,
  Deployment,
  Device,
  Event,
  Key,
  Manifest,
  Pipeline,
  Release,
} from '@/lib/types';

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
  events: Event[];
  releases: Release[];
  manifest: Manifest | null;
  pipeline: Pipeline | null;
  keys: Key[];
  certificates: Certificate[];
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
  events: [],
  releases: [],
  manifest: null,
  pipeline: null,
  keys: [],
  certificates: [],
  deployments: [],
};

function asDate(value: unknown) {
  const parsed = new Date(value as string);
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
}

function asPipelineStageName(value: unknown): Pipeline['stages'][number]['name'] {
  const normalized = String(value || 'deploy').toLowerCase();
  return normalized === 'build' || normalized === 'test' || normalized === 'deploy' || normalized === 'verify'
    ? normalized
    : 'deploy';
}

function asPipelineStageStatus(value: unknown): Pipeline['stages'][number]['status'] {
  const normalized = String(value || 'pending').toLowerCase();
  return normalized === 'pending' || normalized === 'running' || normalized === 'success' || normalized === 'failed' || normalized === 'skipped'
    ? normalized
    : 'pending';
}

function asKeyType(value: unknown): Key['type'] {
  const normalized = String(value || 'RSA').toUpperCase();
  return normalized === 'RSA' || normalized === 'ECDSA' || normalized === 'AES' ? normalized : 'RSA';
}

function asDeploymentStatus(value: unknown): Deployment['status'] {
  const normalized = String(value || 'pending').toLowerCase();
  return normalized === 'pending' || normalized === 'in-progress' || normalized === 'success' || normalized === 'failed' || normalized === 'partial'
    ? normalized
    : 'pending';
}

function normalizeSnapshot(raw: unknown): RuntimeSnapshot {
  if (!raw || typeof raw !== 'object') {
    return emptySnapshot;
  }

  const payload = raw as Record<string, unknown>;

  const devices = Array.isArray(payload.devices)
    ? payload.devices.map((device) => {
        const item = device as Record<string, unknown>;
        return {
          id: String(item.id || ''),
          name: String(item.name || item.id || 'Unnamed device'),
          type: String(item.type || 'ESP32') as Device['type'],
          status: String(item.status || 'standby') as Device['status'],
          firmwareVersion: String(item.firmwareVersion || 'unknown'),
          latestVersion: String(item.latestVersion || item.firmwareVersion || 'unknown'),
          lastSync: asDate(item.lastSync),
          location: String(item.location || 'Unknown location'),
          health: String(item.health || 'good') as Device['health'],
          cpuUsage: Number(item.cpuUsage || 0),
          memoryUsage: Number(item.memoryUsage || 0),
          uptime: Number(item.uptime || 0),
          signalStrength: item.signalStrength !== undefined ? Number(item.signalStrength) : undefined,
        } satisfies Device;
      })
    : [];

  const events = Array.isArray(payload.events)
    ? payload.events.map((event) => {
        const item = event as Record<string, unknown>;
        return {
          id: String(item.id || ''),
          timestamp: asDate(item.timestamp),
          type: String(item.type || 'info') as Event['type'],
          severity: String(item.severity || 'info') as Event['severity'],
          title: String(item.title || 'Event'),
          description: String(item.description || ''),
          deviceId: item.deviceId ? String(item.deviceId) : undefined,
        } satisfies Event;
      })
    : [];

  const releases = Array.isArray(payload.releases)
    ? payload.releases.map((release) => {
        const item = release as Record<string, unknown>;
        const assetsRaw = Array.isArray(item.assets) ? item.assets : [];

        return {
          id: String(item.id || ''),
          version: String(item.version || 'unknown'),
          releaseDate: asDate(item.releaseDate),
          description: String(item.description || ''),
          assets: assetsRaw.map((asset) => {
            const assetItem = asset as Record<string, unknown>;
            return {
              id: String(assetItem.id || ''),
              name: String(assetItem.name || ''),
              size: Number(assetItem.size || 0),
              checksum: String(assetItem.checksum || 'n/a'),
              createdAt: asDate(assetItem.createdAt),
            };
          }),
          compatible: (Array.isArray(item.compatible) ? item.compatible : []).map((value) => String(value)) as Release['compatible'],
          changelog: String(item.changelog || ''),
          downloadCount: Number(item.downloadCount || 0),
          status: String(item.status || 'published') as Release['status'],
        } satisfies Release;
      })
    : [];

  const manifestRaw = payload.manifest as Record<string, unknown> | null | undefined;
  const manifest = manifestRaw
    ? ({
        id: String(manifestRaw.id || 'manifest-live'),
        releaseId: String(manifestRaw.releaseId || 'release-live'),
        entries: (Array.isArray(manifestRaw.entries) ? manifestRaw.entries : []).map((entry) => {
          const item = entry as Record<string, unknown>;
          return {
            device: String(item.device || 'ESP32') as Manifest['entries'][number]['device'],
            version: String(item.version || 'unknown'),
            checksum: String(item.checksum || 'n/a'),
            size: Number(item.size || 0),
            url: String(item.url || ''),
          };
        }),
        createdAt: asDate(manifestRaw.createdAt),
        signature: manifestRaw.signature ? String(manifestRaw.signature) : undefined,
      } satisfies Manifest)
    : null;

  const pipelineRaw = payload.pipeline as Record<string, unknown> | null | undefined;
  const pipeline = pipelineRaw
    ? ({
        id: String(pipelineRaw.id || 'pipeline-live'),
        releaseId: String(pipelineRaw.releaseId || 'release-live'),
        createdAt: asDate(pipelineRaw.createdAt),
        stages: (Array.isArray(pipelineRaw.stages) ? pipelineRaw.stages : []).map((stage) => {
          const item = stage as Record<string, unknown>;
          return {
            id: String(item.id || ''),
            name: asPipelineStageName(item.name),
            status: asPipelineStageStatus(item.status),
            startTime: item.startTime ? asDate(item.startTime) : undefined,
            endTime: item.endTime ? asDate(item.endTime) : undefined,
            logs: String(item.logs || ''),
            duration: item.duration !== undefined ? Number(item.duration) : undefined,
          };
        }),
        status: asPipelineStageStatus(pipelineRaw.status),
        totalDuration: Number(pipelineRaw.totalDuration || 0),
      } satisfies Pipeline)
    : null;

  const keys = Array.isArray(payload.keys)
    ? payload.keys.map((key) => {
        const item = key as Record<string, unknown>;
        return {
          id: String(item.id || ''),
          name: String(item.name || 'Unnamed key'),
          type: asKeyType(item.type),
          keySize: Number(item.keySize || 0),
          createdAt: asDate(item.createdAt),
          expiresAt: item.expiresAt ? asDate(item.expiresAt) : undefined,
          active: item.active === undefined ? true : Boolean(item.active),
        } satisfies Key;
      })
    : [];

  const certificates = Array.isArray(payload.certificates)
    ? payload.certificates.map((certificate) => {
        const item = certificate as Record<string, unknown>;
        return {
          id: String(item.id || ''),
          name: String(item.name || 'Unnamed certificate'),
          issuer: String(item.issuer || 'Unknown issuer'),
          subject: String(item.subject || 'Unknown subject'),
          validFrom: asDate(item.validFrom),
          validTo: asDate(item.validTo),
          fingerprint: String(item.fingerprint || 'n/a'),
        } satisfies Certificate;
      })
    : [];

  const deployments = Array.isArray(payload.deployments)
    ? payload.deployments.map((deployment) => {
        const item = deployment as Record<string, unknown>;
        return {
          id: String(item.id || ''),
          releaseId: String(item.releaseId || ''),
          deviceIds: (Array.isArray(item.deviceIds) ? item.deviceIds : []).map((value) => String(value)),
          status: asDeploymentStatus(item.status),
          startedAt: asDate(item.startedAt),
          completedAt: item.completedAt ? asDate(item.completedAt) : undefined,
          successCount: Number(item.successCount || 0),
          failureCount: Number(item.failureCount || 0),
          logs: String(item.logs || ''),
        } satisfies Deployment;
      })
    : [];

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
    events,
    releases,
    manifest,
    pipeline,
    keys,
    certificates,
    deployments,
  };
}

export function useRuntimeSnapshot(pollMs = 5000) {
  const [snapshot, setSnapshot] = React.useState<RuntimeSnapshot>(emptySnapshot);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const loadSnapshot = React.useCallback(async () => {
    try {
      const response = await apiFetch('/api/runtime/snapshot', { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`Runtime API returned ${response.status}`);
      }

      const payload = normalizeSnapshot(await response.json());
      setSnapshot(payload);
      setError(payload.connection.error || null);
    } catch (loadError) {
      const message = loadError instanceof Error ? loadError.message : 'Unable to fetch runtime data.';
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
    } finally {
      setIsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadSnapshot();

    const intervalId = window.setInterval(() => {
      void loadSnapshot();
    }, pollMs);

    return () => {
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
