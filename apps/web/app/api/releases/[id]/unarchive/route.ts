import { NextResponse } from 'next/server';
import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const RELEASE_ID = /^[A-Za-z0-9_.-]{1,96}$/;

/**
 * Offer an archived release to devices again. Recorded in the gateway audit trail.
 */
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  return withSecureApi(
    request,
    '/api/releases/[id]/unarchive',
    async ({ auth }) => {
      const { id } = await context.params;
      if (!RELEASE_ID.test(id)) {
        return NextResponse.json({ ok: false, error: 'Invalid release id.' }, { status: 400 });
      }
      return proxyGatewayJson('Releases', `/api/releases/${encodeURIComponent(id)}/unarchive`, { method: 'POST', auth });
    },
    { requireRole: OPERATOR_ROLES }
  );
}
