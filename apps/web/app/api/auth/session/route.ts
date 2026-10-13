import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/auth/session',
    async ({ auth }) => {
      return NextResponse.json({
        ok: true,
        user: auth?.user,
      });
    },
    { requireAuth: true }
  );
}
