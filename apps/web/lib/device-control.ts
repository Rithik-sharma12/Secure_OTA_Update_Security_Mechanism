'use client';

import { apiFetch } from '@/lib/client-auth';

/**
 * Dashboard -> gateway -> device, over the internet.
 *
 * Every call goes to this dashboard's own API (session cookie), which adds
 * the gateway key server-side. The gateway hands commands to the device in
 * its next heartbeat response, so effects land within ~15 s of the click.
 */

export type DeviceCommandType = 'update' | 'check_update' | 'reboot' | 'identify';

export type DeviceCommand = {
  id: string;
  type: DeviceCommandType;
  status: 'queued' | 'delivered' | 'succeeded' | 'failed' | 'expired' | 'cancelled';
  createdAt: string;
  deliveredAt: string | null;
  completedAt: string | null;
  result: string | null;
};

export type DeploymentTarget = {
  state: 'pending' | 'confirmed' | 'failed' | 'cancelled';
  reason: string | null;
  fromVersion: string | null;
  phase?: string;
  progress?: number | null;
  phaseDetail?: string | null;
};

export type Deployment = {
  id: string;
  version: string;
  status: string;
  targets: Record<string, DeploymentTarget>;
  pendingCount: number;
  successCount: number;
  failureCount: number;
};

export type DeviceDetail = {
  id: string;
  device: (Record<string, unknown> & {
    fw?: string;
    ota?: { phase: string; version: string; progress: number | null; detail: string | null; at: string };
    otaHistory?: Array<{ phase: string; version: string; progress: number | null; detail: string | null; at: string }>;
    authMode?: string;
    arch?: string;
    ash?: number;
    status?: string;
    last_seen?: string;
    ip?: string;
    signalStrength?: number;
    rollbackPending?: boolean;
  }) | null;
  credentials: { registered: boolean; revoked?: boolean; registeredAt?: string };
  commands: DeviceCommand[];
};

async function request<T>(input: string, init: RequestInit = {}): Promise<T> {
  const response = await apiFetch(input, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) },
    cache: 'no-store',
  });
  const payload = (await response.json().catch(() => null)) as (T & { ok?: boolean; error?: string }) | null;
  if (!response.ok || !payload || payload.ok === false) {
    throw new Error(payload?.error || `Request failed (${response.status})`);
  }
  return payload;
}

export async function queueDeviceCommand(deviceId: string, type: DeviceCommandType, params: Record<string, unknown> = {}) {
  const payload = await request<{ command: DeviceCommand }>(`/api/devices/${encodeURIComponent(deviceId)}/commands`, {
    method: 'POST',
    body: JSON.stringify({ type, params }),
  });
  return payload.command;
}

export async function deployToDevices(deviceIds: string[], releaseId?: string) {
  const payload = await request<{ deployment: Deployment }>('/api/deployments', {
    method: 'POST',
    body: JSON.stringify({ deviceIds, releaseId }),
  });
  return payload.deployment;
}

export async function removeDevice(deviceId: string) {
  await request(`/api/devices/${encodeURIComponent(deviceId)}`, { method: 'DELETE' });
}

export async function getDeviceDetail(deviceId: string) {
  return request<DeviceDetail>(`/api/devices/${encodeURIComponent(deviceId)}`);
}

export async function registerDevice(deviceId: string, deviceType?: string) {
  return request<{ deviceId: string; token: string; rotated: boolean; gatewayUrl: string }>('/api/devices/register', {
    method: 'POST',
    body: JSON.stringify({ deviceId, deviceType }),
  });
}

/** Poll a command until the device reports back or `timeoutMs` passes. */
export async function waitForCommand(deviceId: string, commandId: string, timeoutMs = 60_000, onTick?: (c: DeviceCommand) => void) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const detail = await getDeviceDetail(deviceId);
    const command = detail.commands.find((entry) => entry.id === commandId);
    if (command) {
      onTick?.(command);
      if (!['queued', 'delivered'].includes(command.status)) return command;
    }
    if (Date.now() > deadline) return command ?? null;
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
}

// ── Fleet deployments ──────────────────────────────────────────────────

export type FleetDeployment = Deployment & {
  releaseId: string;
  startedAt: string;
  completedAt: string | null;
  deadline: string;
  cancelledCount?: number;
  retryOf?: string;
  deviceIds: string[];
};

export async function listDeployments() {
  const payload = await request<{ deployments: FleetDeployment[] }>('/api/deployments');
  return payload.deployments;
}

export async function cancelDeployment(deploymentId: string) {
  return request<{ deployment: FleetDeployment; cancelled: number }>(`/api/deployments/${encodeURIComponent(deploymentId)}/cancel`, {
    method: 'POST',
  });
}

export async function retryDeployment(deploymentId: string) {
  const payload = await request<{ deployment: FleetDeployment }>(`/api/deployments/${encodeURIComponent(deploymentId)}/retry`, {
    method: 'POST',
  });
  return payload.deployment;
}

// ── History ────────────────────────────────────────────────────────────

export type TelemetryPoint = {
  t: string;
  samples: number;
  ash: number | null;
  ashMin: number | null;
  rssi: number | null;
  memory: number | null;
  cpu: number | null;
  uptime: number | null;
  fw: string | null;
};

export type TelemetrySeries = {
  deviceId: string;
  hours: number;
  bucketSeconds: number;
  rawSamples: number;
  points: TelemetryPoint[];
  retentionDays: number;
};

export async function getTelemetry(deviceId: string, hours: number, points = 240) {
  return request<TelemetrySeries>(`/api/devices/${encodeURIComponent(deviceId)}/telemetry?hours=${hours}&points=${points}`);
}

export type AuditEntry = {
  id: number;
  timestamp: string;
  actor: string;
  sourceIp: string | null;
  method: string;
  path: string;
  status: number;
  action: string | null;
  detail: string | null;
  deviceId: string | null;
};

export async function getAudit(filters: { limit?: number; beforeId?: number; deviceId?: string; actor?: string; action?: string } = {}) {
  const query = new URLSearchParams();
  if (filters.limit) query.set('limit', String(filters.limit));
  if (filters.beforeId) query.set('before_id', String(filters.beforeId));
  if (filters.deviceId) query.set('device_id', filters.deviceId);
  if (filters.actor) query.set('actor', filters.actor);
  if (filters.action) query.set('action', filters.action);
  return request<{ entries: AuditEntry[]; nextBeforeId: number | null }>(`/api/audit?${query.toString()}`);
}
