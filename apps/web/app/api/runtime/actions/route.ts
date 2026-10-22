import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import type { UserRole } from '@/lib/auth';
import { gatewayHeaders, gatewayUrl, proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * The few console actions that are not a plain gateway proxy.
 *
 * Every action here does real work against the gateway. Anything else is
 * refused with 400 rather than answered with a success it did not earn.
 *
 *   events.export    CSV of the gateway's event log
 *   reports.export   CSV or JSON of devices, deployments or the audit trail
 *   pipeline.rerun   re-verify a release's cached artifact (POST /api/pipeline/run)
 */

const REQUEST_TIMEOUT_MS = 8000;

function actionResponse(message: string, data?: unknown) {
  return NextResponse.json({ ok: true, message, data });
}

function actionError(message: string, status = 400) {
  return NextResponse.json({ ok: false, error: message }, { status });
}

async function fetchGatewayJson<T>(endpoint: string): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    // The fleet key goes in a header from this server only; it is never put
    // in a URL a browser could see.
    const response = await fetch(`${gatewayUrl}${endpoint}`, {
      headers: gatewayHeaders(),
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
  const text = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function toCsv(headers: string[], rows: Array<Record<string, unknown>>) {
  return [headers.join(','), ...rows.map((row) => headers.map((header) => csvEscape(row[header])).join(','))].join('\n');
}

const DATASETS = {
  devices: {
    headers: ['id', 'arch', 'fw', 'status', 'ash', 'last_seen', 'ip', 'signalStrength', 'cpuUsage', 'memoryUsage', 'uptime', 'authMode', 'rollbackPending'],
    async load() {
      const payload = await fetchGatewayJson<{ devices?: unknown[] }>('/api/dashboard');
      return (payload.devices || []).map(asRecord);
    },
  },
  deployments: {
    headers: ['id', 'version', 'releaseId', 'status', 'startedAt', 'completedAt', 'deadline', 'successCount', 'failureCount', 'pendingCount', 'cancelledCount', 'deviceIds'],
    async load() {
      const payload = await fetchGatewayJson<{ deployments?: unknown[] }>('/api/deployments');
      return (payload.deployments || []).map(asRecord).map((row) => ({
        ...row,
        deviceIds: Array.isArray(row.deviceIds) ? row.deviceIds.join(' ') : '',
      }));
    },
  },
  audit: {
    headers: ['id', 'timestamp', 'actor', 'sourceIp', 'method', 'path', 'status', 'action', 'detail', 'deviceId'],
    async load() {
      const payload = await fetchGatewayJson<{ entries?: unknown[] }>('/api/audit?limit=1000');
      return (payload.entries || []).map(asRecord);
    },
  },
} as const;

type DatasetName = keyof typeof DATASETS;

/**
 * Per-action authorisation. Exports of what a viewer can already see are open
 * to viewers; the audit trail names accounts and addresses, so it is
 * operator-only (as GET /api/audit is). Re-running the pipeline is an
 * operator action.
 */
const VIEWER_ACTIONS = new Set(['events.export', 'reports.export']);
const OPERATOR_ACTIONS = new Set(['pipeline.rerun']);

function rolePermitsAction(role: UserRole, action: string): boolean {
  if (role === 'admin' || role === 'operator') {
    return VIEWER_ACTIONS.has(action) || OPERATOR_ACTIONS.has(action);
  }
  return VIEWER_ACTIONS.has(action);
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

      if (!action) {
        return actionError('Action is required.');
      }

      if (!VIEWER_ACTIONS.has(action) && !OPERATOR_ACTIONS.has(action)) {
        return actionError(`Unsupported action '${action}'. The console has no backend for it.`, 400);
      }

      if (!rolePermitsAction(auth!.user.role, action)) {
        return actionError(`Your account does not have permission to run '${action}'.`, 403);
      }

      if (action === 'events.export') {
        let events: Array<Record<string, unknown>>;
        try {
          const payload = await fetchGatewayJson<{ events?: unknown[] }>('/api/events?limit=500');
          events = (payload.events || []).map(asRecord);
        } catch (error) {
          return actionError(error instanceof Error ? error.message : 'Could not read events from the gateway.', 502);
        }
        return actionResponse('Event export is ready.', {
          filename: `event-logs-${new Date().toISOString().slice(0, 10)}.csv`,
          mimeType: 'text/csv;charset=utf-8',
          content: toCsv(['id', 'timestamp', 'severity', 'type', 'title', 'description', 'deviceId'], events),
        });
      }

      if (action === 'reports.export') {
        const dataset = String(actionPayload.dataset || '') as DatasetName;
        if (!(dataset in DATASETS)) {
          return actionError('dataset must be one of devices, deployments, audit.');
        }
        const format = String(actionPayload.format || 'CSV').toUpperCase();
        if (format !== 'CSV' && format !== 'JSON') {
          return actionError('format must be CSV or JSON.');
        }
        if (dataset === 'audit' && auth!.user.role === 'viewer') {
          return actionError('The audit trail is available to operators and admins.', 403);
        }

        let rows: Array<Record<string, unknown>>;
        try {
          rows = await DATASETS[dataset].load();
        } catch (error) {
          return actionError(error instanceof Error ? error.message : 'Could not read data from the gateway.', 502);
        }

        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
        const content = format === 'CSV'
          ? toCsv([...DATASETS[dataset].headers], rows)
          : JSON.stringify({ dataset, exportedAt: new Date().toISOString(), rows }, null, 2);
        return actionResponse(`${rows.length} ${dataset} row(s) exported.`, {
          filename: `${dataset}-${stamp}.${format.toLowerCase()}`,
          mimeType: format === 'CSV' ? 'text/csv;charset=utf-8' : 'application/json;charset=utf-8',
          content,
          rowCount: rows.length,
        });
      }

      // pipeline.rerun
      const releaseId = String(actionPayload.releaseId || '').trim();
      if (releaseId && !/^[A-Za-z0-9_.-]{1,96}$/.test(releaseId)) {
        return actionError('Invalid releaseId.');
      }
      const response = await proxyGatewayJson('Pipeline', '/api/pipeline/run', {
        method: 'POST',
        body: { releaseId: releaseId || null },
        auth,
      });
      if (!response.ok) return response;
      const result = asRecord(await response.json());
      const pipeline = asRecord(result.pipeline);
      const passed = pipeline.status === 'success';
      return NextResponse.json(
        {
          ok: true,
          message: passed ? 'Re-verification passed.' : 'Re-verification failed. See the stage logs.',
          data: { pipeline },
        },
        { status: 200 }
      );
    },
    { requireAuth: true }
  );
}
