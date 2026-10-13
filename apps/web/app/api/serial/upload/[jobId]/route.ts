import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { getUploadJobSnapshot } from '@/lib/serial-upload-jobs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(
  request: Request,
  context: { params: Promise<{ jobId: string }> }
) {
  return withSecureApi(
    request,
    '/api/serial/upload/[jobId]',
    async () => {
      const { jobId } = await context.params;
      const sinceSequence = Number(new URL(request.url).searchParams.get('since') || 0);

      const snapshot = await getUploadJobSnapshot(jobId, Number.isFinite(sinceSequence) ? sinceSequence : 0);
      if (!snapshot) {
        return NextResponse.json(
          {
            ok: false,
            error: 'Upload job not found.',
          },
          { status: 404 }
        );
      }

      return NextResponse.json({
        ok: true,
        ...snapshot,
      });
    },
    { requireAuth: true }
  );
}
