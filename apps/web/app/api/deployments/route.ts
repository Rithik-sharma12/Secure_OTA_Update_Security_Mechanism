import { NextResponse } from 'next/server';
import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { DEVICE_ID_PATTERN, proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  return withSecureApi(request, '/api/deployments', async () => proxyGatewayJson('Deployments', '/api/deployments'), {
    requireAuth: true,
  });
}

/**
 * Assign a release to devices. The gateway refuses incompatible
 * architectures, quarantined devices and downgrades per target, then queues
 * an `update` command so each pending device starts within one heartbeat.
 * A target is confirmed only when the device reports the new version.
 */
export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/deployments',
    async ({ auth }) => {
      const body = (await request.json().catch(() => ({}))) as { releaseId?: unknown; deviceIds?: unknown };
      const releaseId = typeof body.releaseId === 'string' && body.releaseId.trim() ? body.releaseId.trim() : undefined;

      let deviceIds: string[] | undefined;
      if (body.deviceIds !== undefined) {
        if (!Array.isArray(body.deviceIds) || body.deviceIds.length === 0 || body.deviceIds.length > 500) {
          return NextResponse.json({ ok: false, error: 'deviceIds must be a non-empty list (max 500).' }, { status: 400 });
        }
        deviceIds = body.deviceIds.map(String);
        if (!deviceIds.every((id) => DEVICE_ID_PATTERN.test(id))) {
          return NextResponse.json({ ok: false, error: 'One of the device ids is not valid.' }, { status: 400 });
        }
      }

      return proxyGatewayJson('Deployments', '/api/deployments', {
        method: 'POST',
        body: { releaseId, deviceIds },
        auth,
      });
    },
    { requireRole: OPERATOR_ROLES }
  );
}
