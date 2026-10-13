/**
 * Every API route must authenticate its own caller.
 *
 * proxy.ts only enforces sign-in when Clerk is configured. In Supabase and
 * local-account deployments it lets every request through, so a route that
 * forgot to call authenticateRequest (or withSecureApi, which calls it) would
 * be open to anyone. This test makes that a build failure instead of a
 * finding in the next review.
 */

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const API_DIR = path.resolve(__dirname, '..', 'app', 'api');

// Routes that are public on purpose, or that check a shared secret instead of
// a user session. Adding to this list should be a deliberate review decision.
const PUBLIC_ROUTES: Record<string, string> = {
  'auth/login/route.ts': 'issues the session',
  'auth/logout/route.ts': 'clears the caller’s own session cookie',
  'health/supabase/route.ts': 'health probe, reports no data',
  'cron/webhooks/route.ts': 'CRON_SECRET bearer, checked in lib/cron-webhooks.ts',
};

const AUTH_MARKERS = [/\bauthenticateRequest\s*\(/, /\bwithSecureApi\s*\(/];

function routeFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return routeFiles(full);
    return entry.name === 'route.ts' ? [full] : [];
  });
}

describe('API route authentication', () => {
  const files = routeFiles(API_DIR);

  it('finds the API routes', () => {
    expect(files.length).toBeGreaterThan(10);
  });

  for (const file of files) {
    const relative = path.relative(API_DIR, file).split(path.sep).join('/');
    it(`${relative} authenticates its caller`, () => {
      if (relative in PUBLIC_ROUTES) return;
      const source = fs.readFileSync(file, 'utf8');
      expect(
        AUTH_MARKERS.some((marker) => marker.test(source)),
        `${relative} calls neither authenticateRequest() nor withSecureApi()`
      ).toBe(true);
    });
  }

  it('lists no public route that no longer exists', () => {
    for (const relative of Object.keys(PUBLIC_ROUTES)) {
      expect(fs.existsSync(path.join(API_DIR, relative)), relative).toBe(true);
    }
  });
});
