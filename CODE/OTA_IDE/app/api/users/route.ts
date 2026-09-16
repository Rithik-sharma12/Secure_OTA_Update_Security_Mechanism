import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { createUser, listUsers } from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Admin-only: the role is enforced by withSecureApi before these handlers run.
const ADMIN_ONLY = { requireRole: ['admin'] } as const;

export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/users',
    async () => NextResponse.json({ ok: true, users: await listUsers() }),
    ADMIN_ONLY
  );
}

export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/users',
    async () => {
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;

      const user = await createUser({
        username: body.username,
        password: body.password,
        role: body.role,
        isActive: body.isActive,
      });

      return NextResponse.json({ ok: true, user }, { status: 201 });
    },
    ADMIN_ONLY
  );
}
