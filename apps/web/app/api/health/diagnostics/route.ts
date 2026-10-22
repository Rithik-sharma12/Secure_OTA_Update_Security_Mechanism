import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { isClerkConfigured } from '@/lib/auth';
import { webhookTargetUrl } from '@/lib/background-worker';
import { gatewayHeaders, gatewayUrl } from '@/lib/gateway-proxy';
import { checkSupabaseConnection } from '@/lib/supabase';
import { checkMirrorTables } from '@/lib/supabase-sync';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const TIMEOUT_MS = 5000;

type CheckStatus = 'ok' | 'warning' | 'error' | 'off';

type Check = {
  id: string;
  name: string;
  status: CheckStatus;
  detail: string;
  latencyMs?: number;
};

async function timedFetch(path: string, withKey: boolean) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const started = Date.now();
  try {
    const response = await fetch(`${gatewayUrl}${path}`, {
      headers: withKey ? gatewayHeaders() : {},
      cache: 'no-store',
      signal: controller.signal,
    });
    const body = (await response.json().catch(() => null)) as Record<string, unknown> | null;
    return { status: response.status, body, latencyMs: Date.now() - started, error: null as string | null };
  } catch (error) {
    const aborted = error instanceof Error && error.name === 'AbortError';
    return {
      status: 0,
      body: null,
      latencyMs: Date.now() - started,
      error: aborted ? `No answer within ${TIMEOUT_MS / 1000} s.` : 'Connection failed.',
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Checks the console can actually run from this server, each measured when
 * the request is made. Nothing here is sampled or stored, so there is no
 * history to chart: run it again to see the current state.
 */
export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/health/diagnostics',
    async () => {
      const checks: Check[] = [];

      const health = await timedFetch('/healthz', false);
      if (health.status === 200 && health.body?.ok) {
        const devices = Number(health.body.deviceCount ?? 0);
        const releases = Number(health.body.releaseCount ?? 0);
        checks.push({
          id: 'gateway',
          name: 'Gateway reachable',
          status: 'ok',
          detail: `${gatewayUrl}/healthz answered. ${devices} device(s), ${releases} release(s) on record.`,
          latencyMs: health.latencyMs,
        });
      } else {
        checks.push({
          id: 'gateway',
          name: 'Gateway reachable',
          status: 'error',
          detail: health.error
            ? `${gatewayUrl}/healthz: ${health.error}`
            : `${gatewayUrl}/healthz returned ${health.status}.`,
          latencyMs: health.latencyMs,
        });
      }

      let hostStats: { ip: string; temp: string; load: string } | null = null;
      if (health.status === 200) {
        const dashboard = await timedFetch('/api/dashboard', true);
        if (dashboard.status === 200) {
          checks.push({
            id: 'gateway-key',
            name: 'Gateway fleet key',
            status: 'ok',
            detail: "The console's EDGE_GATEWAY_API_KEY is accepted by the gateway.",
            latencyMs: dashboard.latencyMs,
          });
          const stats = dashboard.body?.pi_stats as Record<string, unknown> | undefined;
          if (stats) {
            hostStats = { ip: String(stats.ip ?? ''), temp: String(stats.temp ?? ''), load: String(stats.load ?? '') };
          }
        } else {
          checks.push({
            id: 'gateway-key',
            name: 'Gateway fleet key',
            status: 'error',
            detail:
              dashboard.status === 401 || dashboard.status === 403
                ? "The gateway refused the console's key. EDGE_GATEWAY_API_KEY must match the gateway's OTA_GATEWAY_API_KEY."
                : dashboard.error || `/api/dashboard returned ${dashboard.status}.`,
            latencyMs: dashboard.latencyMs,
          });
        }
      }

      const supabase = await checkSupabaseConnection();
      if (!supabase.configured) {
        checks.push({ id: 'supabase', name: 'Supabase', status: 'off', detail: 'Not configured. Accounts are stored locally.' });
      } else if (!supabase.connected) {
        checks.push({ id: 'supabase', name: 'Supabase', status: 'error', detail: supabase.error || 'Configured but not reachable.' });
      } else {
        const mirror = await checkMirrorTables();
        const missing = mirror.enabled
          ? Object.entries(mirror.tables).filter(([, value]) => value !== true).map(([name]) => name)
          : [];
        checks.push({
          id: 'supabase',
          name: 'Supabase',
          status: missing.length > 0 ? 'warning' : 'ok',
          detail: missing.length > 0
            ? `Connected. Missing mirror table(s): ${missing.join(', ')}.`
            : mirror.enabled
              ? 'Connected. Mirror tables are present.'
              : 'Connected. No service key, so mirror tables were not checked.',
        });
      }

      const clerk = isClerkConfigured();
      checks.push({
        id: 'clerk',
        name: 'Clerk sign-in',
        status: clerk ? 'ok' : 'off',
        detail: clerk ? 'Publishable and secret keys are set.' : 'Not configured. The console uses its own accounts.',
      });

      const webhookUrl = webhookTargetUrl();
      checks.push({
        id: 'webhooks',
        name: 'Outbound webhooks',
        status: webhookUrl ? 'ok' : 'off',
        detail: webhookUrl
          ? 'WEBHOOK_URL is set; queued events are delivered to it.'
          : 'WEBHOOK_URL is not set; nothing is delivered.',
      });

      return NextResponse.json({ ok: true, checkedAt: new Date().toISOString(), gatewayUrl, checks, hostStats });
    },
    { requireAuth: true }
  );
}
