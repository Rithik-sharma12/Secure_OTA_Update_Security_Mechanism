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

const isPublicApiRoute = createRouteMatcher([
  '/api/auth/(.*)',
  '/api/health/(.*)',
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
