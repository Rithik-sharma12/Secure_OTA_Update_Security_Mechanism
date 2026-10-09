import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { deleteUser, updateUser } from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const ADMIN_ONLY = { requireRole: ['admin'] } as const;

/**
 * Update another account's username, role, active flag, or password.
 *
 * The self-lockout and last-admin rules live in `updateUser`, not here, so
 * they hold no matter which caller reaches them.
 */
export async function PATCH(request: Request, context: { params: Promise<{ id: string }> }) {
  return withSecureApi(
    request,
    '/api/users/[id]',
    async ({ auth }) => {
      const { id } = await context.params;
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;

      const user = await updateUser(
        id,
        {
          username: body.username,
          role: body.role,
          isActive: body.isActive,
          password: body.password,
        },
        auth!.user.id
      );

      return NextResponse.json({ ok: true, user });
    },
    ADMIN_ONLY
  );
}

export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }) {
  return withSecureApi(
    request,
    '/api/users/[id]',
    async ({ auth }) => {
      const { id } = await context.params;
      const user = await deleteUser(id, auth!.user.id);

      return NextResponse.json({ ok: true, user });
    },
    ADMIN_ONLY
  );
}
