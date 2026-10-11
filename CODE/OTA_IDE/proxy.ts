import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
import type { NextFetchEvent, NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

const isProtectedRoute = createRouteMatcher([
  '/dashboard(.*)',
  '/devices(.*)',
  '/releases(.*)',
  '/deployments(.*)',
  '/audit(.*)',
  '/profile(.*)',
  '/settings(.*)',
  '/api/(.*)',
]);

// Routes that authenticate by other means. Cron uses CRON_SECRET; a Clerk
// session check here would turn every scheduled run into a 404.
const isPublicApiRoute = createRouteMatcher([
  '/api/auth/(.*)',
  '/api/health/(.*)',
  '/api/cron/(.*)',
]);

const protectedMiddleware = clerkMiddleware(async (auth, request) => {
  if (
    isProtectedRoute(request) &&
    !isPublicApiRoute(request)
  ) {
    await auth.protect();
  }
});

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
    '/((?!_next|.*\\..*).*)',
    '/(api|trpc)(.*)',
    '/__clerk/:path*',
  ],
};
