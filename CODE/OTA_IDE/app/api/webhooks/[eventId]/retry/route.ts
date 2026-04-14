import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { auditDb, webhooksDb } from '@/lib/db';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type RouteContext = {
  params: Promise<{
    eventId: string;
  }>;
};

export async function POST(request: Request, context: RouteContext) {
  return withSecureApi(
    request,
    '/api/webhooks/retry',
    async () => { // initializeWorkflowDatabases is now called in instrumentation.ts
      const { eventId: rawEventId } = await context.params;
      const eventId = decodeURIComponent(rawEventId || '').trim();

      if (!eventId) {
        return NextResponse.json(
          { ok: false, success: false, error: 'eventId is required.' },
          { status: 400 }
        );
      }

      const webhook = await webhooksDb.findOne({ eventId });
      if (!webhook) {
        return NextResponse.json(
          { ok: false, success: false, error: 'Webhook not found.' },
          { status: 404 }
        );
      }

      if (webhook.status === 'PENDING') {
        return NextResponse.json(
          { ok: false, success: false, error: 'Webhook is already pending retry.' },
          { status: 409 }
        );
      }

      await webhooksDb.update(
        { _id: webhook._id },
        {
          $set: {
            status: 'PENDING',
            attempts: 0,
            nextRetryAt: new Date(),
          },
          $unset: {
            failedAt: true,
            completedAt: true,
            error: true,
            lastError: true,
          },
        }
      );

      await auditDb.insert({
        action: 'WEBHOOK_MANUAL_RETRY',
        resourceId: eventId,
        timestamp: new Date(),
      });

      return NextResponse.json({
        ok: true,
        success: true,
        message: 'Webhook queued for retry.',
      });
    },
    { requireAuth: true }
  );
}
