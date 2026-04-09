import { NextResponse } from 'next/server';
import { z } from 'zod';
import { loginWithPassword } from '@/lib/auth';
import { withSecureApi } from '@/lib/api-security';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const loginSchema = z.object({
  username: z.string().trim().min(3).max(64),
  password: z.string().min(6).max(128),
});

export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/auth/login',
    async () => {
      const payload = loginSchema.parse(await request.json());
      const session = await loginWithPassword(payload.username, payload.password);

      if (!session) {
        return NextResponse.json(
          {
            ok: false,
            error: 'Invalid username or password.',
          },
          { status: 401 }
        );
      }

      return NextResponse.json({
        ok: true,
        token: session.token,
        expiresAt: session.expiresAt,
        user: session.user,
      });
    },
    { requireAuth: false }
  );
}
