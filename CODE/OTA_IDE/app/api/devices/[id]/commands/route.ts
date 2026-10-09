import { NextResponse } from 'next/server';
import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { DEVICE_ID_PATTERN, invalidDeviceId, proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type Context = { params: Promise<{ id: string }> };

/** Kept in step with COMMAND_TYPES in src/implementation/gateway/commands.py. */
const COMMAND_TYPES = new Set(['update', 'check_update', 'reboot', 'identify']);

export async function GET(request: Request, context: Context) {
  return withSecureApi(
    request,
    '/api/devices/[id]/commands',
    async () => {
      const { id } = await context.params;
      if (!DEVICE_ID_PATTERN.test(id)) return invalidDeviceId();
      return proxyGatewayJson('DeviceCommands', `/api/devices/${encodeURIComponent(id)}/commands`);
    },
    { requireAuth: true }
  );
}

/**
 * Queue a command for a device anywhere on the internet. The gateway cannot
 * reach the device; it hands the command over in the response to the
 * device's next heartbeat (every ~15 s) and the device reports the result.
 */
export async function POST(request: Request, context: Context) {
  return withSecureApi(
    request,
    '/api/devices/[id]/commands',
    async ({ auth }) => {
      const { id } = await context.params;
      if (!DEVICE_ID_PATTERN.test(id)) return invalidDeviceId();

      const body = (await request.json().catch(() => ({}))) as { type?: unknown; params?: unknown };
      const type = typeof body.type === 'string' ? body.type : '';
      if (!COMMAND_TYPES.has(type)) {
        return NextResponse.json(
          { ok: false, error: `Unsupported command. Use one of: ${[...COMMAND_TYPES].join(', ')}.` },
          { status: 400 }
        );
      }
      const params = body.params && typeof body.params === 'object' ? body.params : {};
      return proxyGatewayJson('DeviceCommands', `/api/devices/${encodeURIComponent(id)}/commands`, {
        method: 'POST',
        body: { type, params },
        auth,
      });
    },
    { requireRole: OPERATOR_ROLES }
  );
}
