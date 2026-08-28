import { NextResponse } from 'next/server';
import { z } from 'zod';
import { withSecureApi } from '@/lib/api-security';
import { getHostAccessState, grantAccess, revokeAccess } from '@/lib/host-access';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const grantSchema = z.object({
  resourceType: z.enum(['serial', 'network']),
  resourceId: z.string().trim().min(1).max(64),
  label: z.string().trim().max(120).optional(),
});

const revokeSchema = z.object({
  grantId: z.string().trim().min(1),
});

export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/host/access',
    async ({ auth }) => {
      const userId = auth!.user.id;
      const state = await getHostAccessState(userId);
      return NextResponse.json({ ok: true, ...state });
    },
    { requireAuth: true }
  );
}

export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/host/access',
    async ({ auth }) => {
      const userId = auth!.user.id;
      const body = grantSchema.parse(await request.json());

      const grant = await grantAccess({
        userId,
        grantedBy: auth!.user.username,
        resourceType: body.resourceType,
        resourceId: body.resourceId,
        label: body.label,
      });

      return NextResponse.json({ ok: true, grant });
    },
    { requireAuth: true }
  );
}

export async function DELETE(request: Request) {
  return withSecureApi(
    request,
    '/api/host/access',
    async ({ auth }) => {
      const userId = auth!.user.id;
      const body = revokeSchema.parse(await request.json());
      const revoked = await revokeAccess(userId, body.grantId);

      if (!revoked) {
        return NextResponse.json(
          { ok: false, error: 'No matching grant to revoke.' },
          { status: 404 }
        );
      }

      return NextResponse.json({ ok: true });
    },
    { requireAuth: true }
  );
}
