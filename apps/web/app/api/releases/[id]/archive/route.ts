import { NextResponse } from 'next/server';
import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELEASE_ID = /^[A-Za-z0-9_.-]{1,96}$/;

/**
 * Stop offering a release to devices. The gateway keeps the record and the
 * binary, excludes it from manifests and deployments, and records who did it.
 */
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  return withSecureApi(
    request,
    '/api/releases/[id]/archive',
    async ({ auth }) => {
      const { id } = await context.params;
      if (!RELEASE_ID.test(id)) {
        return NextResponse.json({ ok: false, error: 'Invalid release id.' }, { status: 400 });
      }
      return proxyGatewayJson('Releases', `/api/releases/${encodeURIComponent(id)}/archive`, { method: 'POST', auth });
    },
    { requireRole: OPERATOR_ROLES }
  );
}
