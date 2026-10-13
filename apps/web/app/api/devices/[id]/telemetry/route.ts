import { withSecureApi } from '@/lib/api-security';
import { DEVICE_ID_PATTERN, invalidDeviceId, proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Heartbeat history (health, signal, memory, firmware) bucketed for charts. */
export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  return withSecureApi(
    request,
    '/api/devices/[id]/telemetry',
    async () => {
      const { id } = await context.params;
      if (!DEVICE_ID_PATTERN.test(id)) return invalidDeviceId();
      const url = new URL(request.url);
      const hours = Math.min(Math.max(Number(url.searchParams.get('hours')) || 24, 0.25), 24 * 7);
      const points = Math.min(Math.max(Number(url.searchParams.get('points')) || 240, 10), 1000);
      return proxyGatewayJson('Telemetry', `/api/devices/${encodeURIComponent(id)}/telemetry?hours=${hours}&points=${points}`);
    },
    { requireAuth: true }
  );
}
