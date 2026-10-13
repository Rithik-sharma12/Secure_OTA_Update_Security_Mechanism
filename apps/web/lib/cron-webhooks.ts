import { NextResponse } from 'next/server';
import { processPendingWebhooks } from '@/lib/background-worker';
import { logger } from '@/lib/logger';

export const dynamic = 'force-dynamic';

function isAuthorizedCronRequest(request: Request) {
  const authHeader = request.headers.get('authorization');
  const cronSecret = process.env.CRON_SECRET?.trim();

  if (!cronSecret) { // CRON_SECRET must be set in production
    logger.error('CronWorker', 'CRON_SECRET environment variable is not set. Unauthorized access will be denied.');
    return false; // Deny access if secret is not configured
  }

  return authHeader === `Bearer ${cronSecret}`;
}

export async function GET(request: Request) {
  if (!isAuthorizedCronRequest(request)) {
    logger.warn('CronWorker', 'Unauthorized attempt to trigger worker endpoint');
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const processedCount = await processPendingWebhooks();
    return NextResponse.json({ success: true, processed: processedCount });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown worker error';
    logger.error('CronWorker', 'Worker execution encountered a fatal error', error);
    return NextResponse.json({ success: false, error: message }, { status: 500 });
  }
}
