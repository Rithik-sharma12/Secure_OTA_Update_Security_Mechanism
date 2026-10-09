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
  state: 'pending' | 'confirmed' | 'failed';
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
    authMode?: string;
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
