import { NextResponse } from 'next/server';
import { OPERATOR_ROLES, withSecureApi } from '@/lib/api-security';
import { proxyGatewayJson } from '@/lib/gateway-proxy';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const DEPLOYMENT_ID = /^deployment-[a-f0-9]{6,32}$/;

/** New deployment of the same release for the targets that failed or were cancelled. */
export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  return withSecureApi(
    request,
    '/api/deployments/[id]/retry',
    async ({ auth }) => {
      const { id } = await context.params;
      if (!DEPLOYMENT_ID.test(id)) {
        return NextResponse.json({ ok: false, error: 'Invalid deployment id.' }, { status: 400 });
      }
      return proxyGatewayJson('Deployments', `/api/deployments/${id}/retry`, { method: 'POST', auth });
    },
    { requireRole: OPERATOR_ROLES }
  );
}
