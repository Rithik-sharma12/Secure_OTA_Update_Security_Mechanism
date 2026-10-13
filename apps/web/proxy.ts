import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
import type { NextFetchEvent, NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

/**
 * Next 16 request proxy (formerly middleware.ts).
 *
 * Pages: everything except the public ones below needs a Clerk session; a
 * signed-out visitor is sent to /login (not Clerk's hosted page), which
 * returns them to where they were after signing in.
 *
 * API routes: Clerk middleware must run so `auth()` works inside route
 * handlers, but it does not reject them here. Every /api route is already
 * guarded by withSecureApi (401 JSON the UI understands, plus role checks),
 * and a few must stay reachable without a browser session: the session probe
 * the login page uses, health checks, and the CRON_SECRET-guarded worker.
 * `auth.protect()` would answer those with a 404 page instead.
 */

const isPublicPage = createRouteMatcher([
  '/',
  '/login(.*)',
  '/sso-callback(.*)',
  '/privacy',
  '/terms',
]);

// Routes that authenticate by other means. Cron uses CRON_SECRET; a Clerk
// session check here would turn every scheduled run into a 404.
const isPublicApiRoute = createRouteMatcher([
  '/api/auth/(.*)',
  '/api/health/(.*)',
  '/api/cron/(.*)',
]);
const isApi = createRouteMatcher(['/api/(.*)', '/trpc/(.*)']);

const authorizedParties = (process.env.CLERK_AUTHORIZED_PARTIES || process.env.OTA_DASHBOARD_PUBLIC_URL || '')
  .split(',')
  .map((value) => value.trim().replace(/\/$/, ''))
  .filter(Boolean);

// Clerk rejects a session token whose timestamps are more than 5 s away from
// this machine's clock. A PC clock a few seconds slow is common (Windows only
// resyncs occasionally) and makes every fresh token look "issued in the
// future": the sign-in succeeds at Clerk, the app never sees it, and the
// browser bounces between /login and the dashboard. Allow a wider window;
// CLERK_CLOCK_SKEW_MS overrides it (0-300000).
const clockSkewInMs = (() => {
  const value = Number(process.env.CLERK_CLOCK_SKEW_MS);
  return Number.isFinite(value) && value >= 0 && value <= 300_000 ? value : 60_000;
})();

const protectedMiddleware = clerkMiddleware(
  async (auth, request) => {
    if (isApi(request) || isPublicPage(request) || isPublicApiRoute(request)) return;
    await auth.protect();
  },
  {
    signInUrl: '/login',
    signUpUrl: '/login',
    clockSkewInMs,
    // In production, list the dashboard origin(s) so a session token minted
    // for another site on the same parent domain is not accepted here.
    ...(authorizedParties.length > 0 ? { authorizedParties } : {}),
  }
);

export default function proxy(request: NextRequest, event: NextFetchEvent) {
  // Without Clerk, sessions come from Supabase or the local user store and
  // this proxy cannot check them. Every route under app/api therefore checks
  // its own caller (authenticateRequest / withSecureApi / a shared secret);
  // tests/api-route-auth.test.ts fails the build if a route does not.
  if (!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || !process.env.CLERK_SECRET_KEY) {
    return NextResponse.next();
  }
  return protectedMiddleware(request, event);
}

export const config = {
  matcher: [
    // Skip Next internals and static files (anything with an extension).
    '/((?!_next|.*\\..*).*)',
    '/(api|trpc)(.*)',
    '/__clerk/:path*',
  ],
};
