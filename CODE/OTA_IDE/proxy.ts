import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';

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

export default clerkMiddleware(async (auth, request) => {
  if (
    process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY &&
    isProtectedRoute(request) &&
    !isPublicApiRoute(request)
  ) {
    await auth.protect();
  }
});

export const config = {
  matcher: [
    '/((?!_next|.*\\..*).*)',
    '/(api|trpc)(.*)',
    '/__clerk/:path*',
  ],
};
