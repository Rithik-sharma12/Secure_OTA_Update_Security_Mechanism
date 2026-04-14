import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { webhooksDb, type WebhookStatus } from '@/lib/db';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const ALLOWED_STATUSES: ReadonlySet<WebhookStatus> = new Set(['PENDING', 'COMPLETED', 'FAILED']);

function parseStatus(rawValue: string | null): WebhookStatus | null {
  if (!rawValue) {
    return null;
  }

  const normalized = rawValue.toUpperCase();
  if (!ALLOWED_STATUSES.has(normalized as WebhookStatus)) {
    return null;
  }

  return normalized as WebhookStatus;
}

function parseLimit(rawValue: string | null) {
  const numeric = Number(rawValue);
  if (!Number.isFinite(numeric)) {
    return 100;
  }

  return Math.max(1, Math.min(500, Math.floor(numeric)));
}

export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/webhooks',
    async () => { // initializeWorkflowDatabases is now called in instrumentation.ts
      const url = new URL(request.url);
      const status = parseStatus(url.searchParams.get('status'));
      const limit = parseLimit(url.searchParams.get('limit'));

      const query: Record<string, unknown> = {};
      if (status) {
        query.status = status;
      }

      const data = await webhooksDb.find(query).sort({ updatedAt: -1 }).limit(limit);

      return NextResponse.json({
        ok: true,
        success: true,
        data,
      });
    },
    { requireAuth: true }
  );
}
