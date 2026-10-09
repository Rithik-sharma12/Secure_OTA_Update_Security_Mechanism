import { NextResponse } from 'next/server';
import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { DEVICE_ID_PATTERN, deviceGatewayUrl, invalidDeviceId, proxyGatewayJson } from '@/lib/gateway-proxy';
import { logger } from '@/lib/logger';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Issue a per-device token for USB provisioning.
 *
 * The token is returned to the operator's browser exactly once, which passes
 * it to the local agent on 127.0.0.1, which writes it to the board over USB.
 * From then on the board authenticates as itself instead of with the shared
 * fleet key. Re-registering rotates the token; the old one stops working.
 */
export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/devices/register',
    async ({ auth }) => {
      const body = (await request.json().catch(() => ({}))) as { deviceId?: unknown; deviceType?: unknown; label?: unknown };
      const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
      if (!DEVICE_ID_PATTERN.test(deviceId)) return invalidDeviceId();

      const proxied = await proxyGatewayJson('DeviceRegister', '/api/devices/register', {
        method: 'POST',
        body: {
          deviceId,
          deviceType: typeof body.deviceType === 'string' ? body.deviceType : undefined,
          label: typeof body.label === 'string' ? body.label.slice(0, 64) : undefined,
        },
      });
      if (!proxied.ok) return proxied;

      const data = (await proxied.json()) as { token?: string; rotated?: boolean; deviceType?: string | null };
      logger.info('DeviceRegister', `Device token ${data.rotated ? 'rotated' : 'issued'} for ${deviceId}`, {
        userId: auth?.user.id,
      });
      return NextResponse.json(
        {
          ok: true,
          deviceId,
          deviceType: data.deviceType ?? null,
          token: data.token,
          rotated: Boolean(data.rotated),
          // Where the board should send heartbeats. Empty when the server
          // does not know its public address; the operator types it instead.
          gatewayUrl: deviceGatewayUrl,
        },
        { headers: { 'Cache-Control': 'no-store' } }
      );
    },
    { requireRole: OPERATOR_ROLES }
  );
}
