import { webhooksDb, auditDb, initializeWorkflowDatabases } from '@/lib/db';
import { logger } from '@/lib/logger';

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5000;

export async function processPendingWebhooks() {
  await initializeWorkflowDatabases();

  const now = new Date();
  
  // 1. Poll the database for webhooks that are PENDING and due for processing
  const pendingWebhooks = await webhooksDb.find({
    status: 'PENDING',
    nextRetryAt: { $lte: now }
  }).sort({ createdAt: 1 }).limit(10); // Batch limit to prevent memory overflow

  if (pendingWebhooks.length === 0) {
    return 0;
  }

  logger.info('BackgroundWorker', `Processing ${pendingWebhooks.length} pending webhooks`);
  let processedCount = 0;

  // 2. Iterate and process (could be parallelized with Promise.allSettled for high throughput)
  for (const webhook of pendingWebhooks) {
    try {
      logger.debug('BackgroundWorker', `Delivering webhook ${webhook.eventId} (Attempt ${webhook.attempts + 1})`);
      
      // Target URL ideally comes from user config, defaulting to an echo test URL for now
      const targetUrl = process.env.WEBHOOK_URL || 'https://httpbin.org/post';
      
      const response = await fetch(targetUrl, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'X-Webhook-Event-Id': webhook.eventId,
        },
        body: JSON.stringify({
          id: webhook.eventId,
          type: webhook.type,
          data: webhook.payload,
          timestamp: new Date().toISOString()
        }),
      });

      if (!response.ok) {
        throw new Error(`Webhook failed with target status: ${response.status}`);
      }

      // 3. Success: Mark outbox item as COMPLETED
      await webhooksDb.update(
        { _id: webhook._id },
        { $set: { status: 'COMPLETED', completedAt: new Date() } }
      );
      processedCount++;

      await auditDb.insert({ action: 'WEBHOOK_DELIVERED', resourceId: webhook.eventId, timestamp: new Date() });

    } catch (error: unknown) {
      logger.error('BackgroundWorker', `Webhook delivery failed for ${webhook.eventId}`, error);

      const errorMessage = (error instanceof Error) ? error.message : String(error);
      
      const attempts = webhook.attempts + 1;
      if (attempts >= MAX_RETRIES) {
        // 4a. Failure: Max retries reached, mark as FAILED (Dead Letter Queue logic)
        await webhooksDb.update(
          { _id: webhook._id },
          { $set: { status: 'FAILED', error: errorMessage, failedAt: new Date() } }
        );
        await auditDb.insert({ action: 'WEBHOOK_FAILED', resourceId: webhook.eventId, timestamp: new Date() });
      } else {
        // 4b. Retry: Schedule next retry using Exponential Backoff (5s, 10s, 20s...)
        const backoffDelay = RETRY_DELAY_MS * Math.pow(2, attempts - 1);
        const nextRetryAt = new Date(Date.now() + backoffDelay);
        
        await webhooksDb.update(
          { _id: webhook._id },
          { $set: { attempts, nextRetryAt, lastError: errorMessage } }
        );
      }
    }
  }

  return processedCount;
}