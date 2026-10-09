import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { getManagedUser, updateOwnCredentials } from '@/lib/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * The signed-in account, as itself. Always scoped to the session making the
 * request — there is no `?userId=` here, so no account can read another's
 * profile through this route regardless of role.
 */
export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/profile',
    async ({ auth }) => {
      const user = await getManagedUser(auth!.user.id);

      return NextResponse.json({
        ok: true,
        user,
        session: {
          expiresAt: new Date(auth!.session.expiresAt).toISOString(),
          issuedAt: auth!.session.createdAt ?? null,
        },
      });
    },
    { requireAuth: true }
  );
}

/** Change your own username or password. Requires the current password. */
export async function PATCH(request: Request) {
  return withSecureApi(
    request,
    '/api/profile',
    async ({ auth }) => {
      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;

      const user = await updateOwnCredentials(auth!, {
        username: body.username,
        currentPassword: body.currentPassword,
        newPassword: body.newPassword,
      });

      return NextResponse.json({ ok: true, user });
    },
    { requireAuth: true }
  );
}
