import { NextResponse } from 'next/server';
import { revokeRequestToken } from '@/lib/auth';
import { withSecureApi } from '@/lib/api-security';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/auth/logout',
    async () => {
      await revokeRequestToken(request);
      return NextResponse.json({ ok: true });
    },
    { requireAuth: true }
  );
}
