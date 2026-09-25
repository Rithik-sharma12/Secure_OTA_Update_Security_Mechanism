const baseUrl = process.env.SUPABASE_CHECK_URL || 'http://localhost:3000/api/health/supabase';

try {
  const response = await fetch(baseUrl);
  const body = await response.json();

  console.log(JSON.stringify(body, null, 2));
  process.exitCode = body.connected ? 0 : 1;
} catch (error) {
  console.error(`Supabase health check failed: ${error.message}`);
  process.exitCode = 1;
}