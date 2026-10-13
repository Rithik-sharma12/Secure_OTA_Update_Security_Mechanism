export const runtime = 'nodejs';

export async function register() {
  // Ensure this only runs on the Node.js runtime and not in the Edge runtime
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { initializeWorkflowDatabases } = await import('./lib/db');
    // Dynamically import the cron manager so it doesn't leak into edge/client environments
    const { initCronJobs } = await import('./lib/cron');
    initCronJobs();
    await initializeWorkflowDatabases(); // Initialize all databases once at startup
  }
}