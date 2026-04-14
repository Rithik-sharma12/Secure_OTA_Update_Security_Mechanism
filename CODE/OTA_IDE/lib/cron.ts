import cron from 'node-cron';
import { processPendingWebhooks } from '@/lib/background-worker';
import { logger } from '@/lib/logger';

let isInitialized = false;

export function initCronJobs() {
  // Prevent multiple initializations in development due to Hot Module Replacement (HMR)
  if (isInitialized) return;
  isInitialized = true;

  // Conditionally disable cron jobs in development mode
  if (process.env.NODE_ENV === 'development') {
    logger.info('InternalCron', 'Internal cron jobs are disabled in development mode.');
    return;
  }

  logger.info('InternalCron', 'Initializing internal node-cron jobs...');

  // Schedule the background worker to run every minute
  cron.schedule('* * * * *', async () => {
    logger.debug('InternalCron', 'Running scheduled background worker...');
    try {
      const processedCount = await processPendingWebhooks();
      if (processedCount > 0) logger.info('InternalCron', `Processed ${processedCount} webhooks`);
    } catch (error) {
      logger.error('InternalCron', 'Failed to run background worker', error);
    }
  });
}