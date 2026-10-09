import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { DEVICE_ID_PATTERN, invalidDeviceId, proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Context = { params: Promise<{ id: string }> };

/** Device record, its credential status (never the token) and its command history. */
export async function GET(request: Request, context: Context) {
  return withSecureApi(
    request,
    '/api/devices/[id]',
    async () => {
      const { id } = await context.params;
      if (!DEVICE_ID_PATTERN.test(id)) return invalidDeviceId();
      return proxyGatewayJson('Devices', `/api/devices/${encodeURIComponent(id)}`);
    },
    { requireAuth: true }
  );
}

/**
 * Forget a device on the gateway: record, queued commands and token. A board
 * still running with the fleet key reappears on its next heartbeat.
 */
export async function DELETE(request: Request, context: Context) {
  return withSecureApi(
    request,
    '/api/devices/[id]',
    async () => {
      const { id } = await context.params;
      if (!DEVICE_ID_PATTERN.test(id)) return invalidDeviceId();
      return proxyGatewayJson('Devices', `/api/devices/${encodeURIComponent(id)}`, { method: 'DELETE' });
    },
    { requireRole: OPERATOR_ROLES }
  );
}
