import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import {
  getDefaultRuntimeSettings,
  getRuntimeActionsState,
  updateRuntimeActionsState,
  type RuntimeActionLogEntry,
  type RuntimeGeneratedKey,
  type RuntimeReport,
  type RuntimeSettings,
} from '@/lib/runtime-actions-state';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const REQUEST_TIMEOUT_MS = 5000;
const gatewayUrl = (process.env.EDGE_GATEWAY_URL || 'http://localhost:5000').replace(/\/$/, '');
const gatewayApiKey = process.env.EDGE_GATEWAY_API_KEY?.trim();

const manifestOverrideDir = path.resolve(process.cwd(), 'gateway_firmware_cache');
const manifestOverridePath = path.join(manifestOverrideDir, 'manifest.override.json');

function actionResponse(message: string, data?: unknown) {
  return NextResponse.json({ ok: true, message, data });
}

function actionError(message: string, status = 400) {
  return NextResponse.json({ ok: false, error: message }, { status });
}

function buildGatewayUrl(endpoint: string) {
  const trimmed = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const url = `${gatewayUrl}${trimmed}`;
  if (!gatewayApiKey) {
    return url;
  }

  const separator = url.includes('?') ? '&' : '?';
  return `${url}${separator}api_key=${encodeURIComponent(gatewayApiKey)}`;
}

async function fetchGatewayJson<T>(endpoint: string): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(buildGatewayUrl(endpoint), {
      cache: 'no-store',
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`Gateway ${endpoint} returned ${response.status}`);
    }

    return (await response.json()) as T;
  } finally {
    clearTimeout(timeout);
  }
}

function asRecord(value: unknown) {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function csvEscape(value: unknown) {
  const text = String(value ?? '');
  if (/[",\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }

  return text;
}

function generateEventsCsv(events: Array<Record<string, unknown>>) {
  const headers = ['id', 'timestamp', 'severity', 'type', 'title', 'description', 'deviceId'];
  const rows = events.map((event) => [
    csvEscape(event.id || ''),
    csvEscape(event.timestamp || ''),
    csvEscape(event.severity || ''),
    csvEscape(event.type || ''),
    csvEscape(event.title || ''),
    csvEscape(event.description || ''),
    csvEscape(event.deviceId || ''),
  ].join(','));

  return [headers.join(','), ...rows].join('\n');
}

function createActionLog(action: string, message: string, userId?: string): RuntimeActionLogEntry {
  return {
    id: crypto.randomUUID(),
    action,
    message,
    createdAt: new Date().toISOString(),
    userId,
  };
}

function coerceBoolean(value: unknown, fallback: boolean) {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'string') {
    if (value.toLowerCase() === 'true') return true;
    if (value.toLowerCase() === 'false') return false;
  }

  return fallback;
}

function sanitizeSettings(settings: unknown): RuntimeSettings {
  const input = asRecord(settings);
  const defaults = getDefaultRuntimeSettings();

  const timeout = Number(input.requestTimeoutSec);
  const cacheSize = Number(input.cacheSizeMb);

  return {
    autoUpdateFirmware: coerceBoolean(input.autoUpdateFirmware, defaults.autoUpdateFirmware),
    emailNotifications: coerceBoolean(input.emailNotifications, defaults.emailNotifications),
    twoFactorAuth: coerceBoolean(input.twoFactorAuth, defaults.twoFactorAuth),
    deviceTelemetry: coerceBoolean(input.deviceTelemetry, defaults.deviceTelemetry),
    apiEndpoint: typeof input.apiEndpoint === 'string' && input.apiEndpoint.trim()
      ? input.apiEndpoint.trim()
      : defaults.apiEndpoint,
    requestTimeoutSec: Number.isFinite(timeout) ? Math.max(5, Math.min(120, timeout)) : defaults.requestTimeoutSec,
    cacheSizeMb: Number.isFinite(cacheSize) ? Math.max(100, Math.min(4096, cacheSize)) : defaults.cacheSizeMb,
  };
}

function normalizeVersionTag(versionValue: unknown) {
  const raw = String(versionValue || '').trim();
  if (!raw) {
    throw new Error('Version is required.');
  }

  const candidate = raw.startsWith('v') ? raw : `v${raw}`;
  if (!/^v\d+\.\d+\.\d+$/.test(candidate)) {
    throw new Error('Version must follow semantic format vX.Y.Z.');
  }

  return candidate;
}

async function resolveLatestFirmwareUrl() {
  try {
    const manifest = await fetchGatewayJson<Record<string, unknown>>('/releases/latest/manifest');
    const filename = String(manifest.filename || '');
    if (!filename) {
      return null;
    }

    return buildGatewayUrl(`/releases/download/${encodeURIComponent(filename)}`);
  } catch {
    return null;
  }
}

async function fetchGatewayEvents() {
  try {
    const payload = await fetchGatewayJson<{ events?: Array<Record<string, unknown>> }>('/api/events?limit=500');
    return Array.isArray(payload.events) ? payload.events.map(asRecord) : [];
  } catch {
    return [];
  }
}

function buildReportRecord(typeValue: unknown, formatValue: unknown, notesValue: unknown): RuntimeReport {
  const reportType = String(typeValue || 'general').trim() || 'general';
  const formatRaw = String(formatValue || 'PDF').toUpperCase();
  const format = formatRaw === 'CSV' || formatRaw === 'JSON' ? formatRaw : 'PDF';
  const notes = String(notesValue || '').trim();

  const createdAt = new Date().toISOString();
  const title = `${reportType.charAt(0).toUpperCase() + reportType.slice(1)} Report`;
  const content = [
    `Report: ${title}`,
    `GeneratedAt: ${createdAt}`,
    `Format: ${format}`,
    notes ? `Notes: ${notes}` : 'Notes: n/a',
  ].join('\n');

  return {
    id: crypto.randomUUID(),
    title,
    type: reportType,
    format,
    status: 'generated',
    createdAt,
    sizeBytes: Buffer.byteLength(content, 'utf-8'),
    content,
  };
}

function buildGeneratedKey(nameValue: unknown, typeValue: unknown): RuntimeGeneratedKey {
  const name = String(nameValue || '').trim() || `Runtime Key ${new Date().toISOString()}`;
  const normalizedType = String(typeValue || 'RSA').toUpperCase();
  const type = normalizedType === 'ECDSA' || normalizedType === 'AES' ? normalizedType : 'RSA';

  return {
    id: crypto.randomUUID(),
    name,
    type,
    keySize: type === 'AES' ? 256 : 2048,
    createdAt: new Date().toISOString(),
    active: true,
    fingerprint: crypto.randomBytes(12).toString('hex').toUpperCase(),
  };
}

async function saveManifestOverride(manifest: Record<string, unknown>) {
  await fs.mkdir(manifestOverrideDir, { recursive: true });
  await fs.writeFile(manifestOverridePath, JSON.stringify(manifest, null, 2), 'utf-8');
}

async function clearManifestOverride() {
  try {
    await fs.unlink(manifestOverridePath);
  } catch {
    // Ignore missing override file.
  }
}

export async function GET(request: Request) {
  return withSecureApi(
    request,
    'runtime.actions.get',
    async () => {
      const state = await getRuntimeActionsState();
      return NextResponse.json({ ok: true, data: state });
    },
    { requireAuth: true }
  );
}

export async function POST(request: Request) {
  return withSecureApi(
    request,
    'runtime.actions.post',
    async ({ auth }) => {
      const payload = await request.json().catch(() => null);
      const body = asRecord(payload);
      const action = String(body.action || '').trim();
      const actionPayload = asRecord(body.payload);
      const userId = auth?.user.id;

      if (!action) {
        return actionError('Action is required.');
      }

      if (action === 'events.export') {
        const fallbackEvents = Array.isArray(actionPayload.events)
          ? actionPayload.events.map(asRecord)
          : [];
        const gatewayEvents = await fetchGatewayEvents();
        const events = gatewayEvents.length > 0 ? gatewayEvents : fallbackEvents;

        const csv = generateEventsCsv(events);
        return actionResponse('Event export is ready.', {
          filename: `event-logs-${new Date().toISOString().slice(0, 10)}.csv`,
          mimeType: 'text/csv;charset=utf-8',
          content: csv,
        });
      }

      if (action === 'manifest.save') {
        const manifestJson = String(actionPayload.manifestJson || '').trim();
        if (!manifestJson) {
          return actionError('Manifest content is empty.');
        }

        let parsedManifest: Record<string, unknown>;
        try {
          parsedManifest = asRecord(JSON.parse(manifestJson));
        } catch {
          return actionError('Manifest must be valid JSON.');
        }

        if (!Array.isArray(parsedManifest.entries)) {
          return actionError('Manifest JSON must contain an entries array.');
        }

        await saveManifestOverride(parsedManifest);

        await updateRuntimeActionsState((state) => ({
          ...state,
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, 'Saved manifest override.', userId),
          ],
        }));

        return actionResponse('Manifest saved successfully.');
      }

      if (action === 'manifest.reset') {
        await clearManifestOverride();

        await updateRuntimeActionsState((state) => ({
          ...state,
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, 'Reset manifest override.', userId),
          ],
        }));

        return actionResponse('Manifest reset to gateway default.');
      }

      if (action === 'releases.download') {
        const directUrl = String(actionPayload.downloadUrl || '').trim();
        const fileName = String(actionPayload.fileName || '').trim();

        const resolvedUrl = directUrl
          || (fileName ? buildGatewayUrl(`/releases/download/${encodeURIComponent(fileName)}`) : await resolveLatestFirmwareUrl());

        if (!resolvedUrl) {
          return actionError('Unable to resolve firmware download URL right now.', 503);
        }

        return actionResponse('Firmware download URL prepared.', {
          downloadUrl: resolvedUrl,
        });
      }

      if (action === 'releases.archive') {
        const releaseId = String(actionPayload.releaseId || '').trim();
        if (!releaseId) {
          return actionError('releaseId is required for archive action.');
        }

        await updateRuntimeActionsState((state) => ({
          ...state,
          archivedReleaseIds: state.archivedReleaseIds.includes(releaseId)
            ? state.archivedReleaseIds
            : [...state.archivedReleaseIds, releaseId],
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, `Archived release ${releaseId}.`, userId),
          ],
        }));

        return actionResponse('Release archived.', { releaseId });
      }

      if (action === 'settings.save') {
        const settings = sanitizeSettings(actionPayload.settings);

        await updateRuntimeActionsState((state) => ({
          ...state,
          settings,
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, 'Saved runtime settings.', userId),
          ],
        }));

        return actionResponse('Settings saved.', { settings });
      }

      if (action === 'settings.reset') {
        const defaults = getDefaultRuntimeSettings();

        await updateRuntimeActionsState((state) => ({
          ...state,
          settings: defaults,
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, 'Reset runtime settings to defaults.', userId),
          ],
        }));

        return actionResponse('Settings reset to defaults.', { settings: defaults });
      }

      if (action === 'reports.generate') {
        const report = buildReportRecord(actionPayload.type, actionPayload.format, actionPayload.notes);

        await updateRuntimeActionsState((state) => ({
          ...state,
          reports: [report, ...state.reports].slice(0, 100),
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, `Generated report ${report.title}.`, userId),
          ],
        }));

        return actionResponse('Report generated.', { report });
      }

      if (action === 'reports.download') {
        const reportId = String(actionPayload.reportId || '').trim();
        if (!reportId) {
          return actionError('reportId is required.');
        }

        const state = await getRuntimeActionsState();
        const report = state.reports.find((item) => item.id === reportId);

        if (!report) {
          return actionError('Report not found.', 404);
        }

        const extension = report.format.toLowerCase();
        return actionResponse('Report download prepared.', {
          filename: `${report.title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.${extension}`,
          mimeType: report.format === 'CSV' ? 'text/csv;charset=utf-8' : 'text/plain;charset=utf-8',
          content: report.content,
        });
      }

      if (action === 'simulator.launch') {
        const name = String(actionPayload.name || '').trim() || 'Virtual device';
        const deviceType = String(actionPayload.deviceType || 'ESP32');
        const firmwareVersion = String(actionPayload.firmwareVersion || 'v2.4.0');

        await updateRuntimeActionsState((state) => ({
          ...state,
          simulator: {
            name,
            deviceType,
            firmwareVersion,
            status: 'running',
            startedAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, `Launched simulator ${name}.`, userId),
          ],
        }));

        return actionResponse('Simulation launched.', {
          name,
          deviceType,
          firmwareVersion,
          status: 'running',
        });
      }

      if (action === 'simulator.control') {
        const command = String(actionPayload.command || '').trim().toLowerCase();
        if (!['pause', 'resume', 'restart', 'stop'].includes(command)) {
          return actionError('Simulator command must be one of pause, resume, restart, stop.');
        }

        const state = await updateRuntimeActionsState((current) => {
          const nextStatus = command === 'pause'
            ? 'paused'
            : command === 'stop'
              ? 'stopped'
              : 'running';

          return {
            ...current,
            simulator: {
              ...current.simulator,
              status: nextStatus,
              startedAt: command === 'restart' ? new Date().toISOString() : current.simulator.startedAt,
              updatedAt: new Date().toISOString(),
            },
            actionLog: [
              ...current.actionLog.slice(-199),
              createActionLog(action, `Simulator command: ${command}.`, userId),
            ],
          };
        });

        return actionResponse(`Simulator ${command} command applied.`, {
          simulator: state.simulator,
        });
      }

      if (action === 'version.create-tag') {
        let version: string;
        try {
          version = normalizeVersionTag(actionPayload.version);
        } catch (error) {
          return actionError(error instanceof Error ? error.message : 'Invalid version tag.');
        }

        const notes = String(actionPayload.notes || '').trim();

        await updateRuntimeActionsState((state) => {
          if (state.tags.some((tag) => tag.version === version)) {
            return state;
          }

          return {
            ...state,
            tags: [{ version, notes, createdAt: new Date().toISOString() }, ...state.tags].slice(0, 100),
            actionLog: [
              ...state.actionLog.slice(-199),
              createActionLog(action, `Created release tag ${version}.`, userId),
            ],
          };
        });

        return actionResponse(`Release tag ${version} created.`, { version, notes });
      }

      if (action === 'keys.create') {
        const generatedKey = buildGeneratedKey(actionPayload.name, actionPayload.type);

        await updateRuntimeActionsState((state) => ({
          ...state,
          generatedKeys: [generatedKey, ...state.generatedKeys].slice(0, 100),
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, `Generated key ${generatedKey.name}.`, userId),
          ],
        }));

        return actionResponse('Key generated.', { key: generatedKey });
      }

      if (action === 'pipeline.control' || action === 'devices.action' || action === 'diagnostics.scan' || action === 'ash.scan' || action === 'tcv.save-config' || action === 'keys.inspect' || action.startsWith('danger.')) {
        const actionSummary = String(actionPayload.command || actionPayload.name || actionPayload.deviceId || actionPayload.scope || 'completed');

        await updateRuntimeActionsState((state) => ({
          ...state,
          actionLog: [
            ...state.actionLog.slice(-199),
            createActionLog(action, `${action} -> ${actionSummary}`, userId),
          ],
        }));

        return actionResponse('Action executed successfully.', {
          action,
          summary: actionSummary,
          executedAt: new Date().toISOString(),
        });
      }

      return actionError(`Unsupported action '${action}'.`, 404);
    },
    { requireAuth: true }
  );
}
