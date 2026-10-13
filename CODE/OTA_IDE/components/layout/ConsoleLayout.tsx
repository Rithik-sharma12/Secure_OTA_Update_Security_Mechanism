'use client';

import { ConsoleWallpaper } from '@/components/brand/LiveWallpaper';
import React from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { Toaster } from '@/components/ui/sonner';
import TopNav, { MobileTabBar } from '@/components/layout/TopNav';
import StatusBar from '@/components/layout/StatusBar';
import { ErrorBoundary } from '@/components/error/ErrorBoundary';
import { ErrorFallback } from '@/components/error/ErrorFallback';
import { logger } from '@/lib/logger';
import { apiFetch, clearAuthSession, persistAuthSession, type StoredAuthUser } from '@/lib/client-auth';
import { CurrentUserProvider } from '@/lib/use-current-user';

function DashboardShell({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [isCheckingAuth, setIsCheckingAuth] = React.useState(true);
  // The account this session actually belongs to, straight from the
  // validation below — what the role-aware UI reads, rather than localStorage.
  const [currentUser, setCurrentUser] = React.useState<StoredAuthUser | null>(null);

  React.useEffect(() => {
    let isMounted = true;

    // Right after sign-in (especially Google/GitHub) the new session can
    // take a moment to reach the server, so retry briefly before deciding
    // the visitor is signed out. A 401 that persists sends them to /login,
    // which explains what is wrong instead of looping back here.
    const validateSession = async () => {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          const response = await apiFetch('/api/auth/session', { cache: 'no-store' });
          const payload = (await response.json().catch(() => ({}))) as {
            ok?: boolean;
            user?: StoredAuthUser;
          };

          if (response.ok && payload.ok && payload.user) {
            persistAuthSession(payload.user);
            if (isMounted) {
              setCurrentUser(payload.user);
              setIsCheckingAuth(false);
            }
            return;
          }
        } catch {
          // network error: retry
        }
        if (!isMounted) return;
        await new Promise((resolve) => setTimeout(resolve, 700 * (attempt + 1)));
      }

      if (!isMounted) return;
      await clearAuthSession();
      const here = `${window.location.pathname}${window.location.search}`;
      router.replace(`/login?next=${encodeURIComponent(here)}`);
    };

    void validateSession();

    return () => {
      isMounted = false;
    };
  }, [router]);

  if (isCheckingAuth) {
    return (
      <div className="ds-root flex min-h-svh items-center justify-center bg-background px-4">
        <div className="flex flex-col items-center gap-4 text-sm text-foreground/70">
          <span className="ota-spinner" aria-hidden="true" />
          Checking your access…
        </div>
      </div>
    );
  }

  return (
    // ds-root exposes the ember/carbon tokens (--ember, --type-*, .ota-brand)
    // to the whole console, alongside the shadcn tokens globals.css maps onto
    // the same palette.
    //
    // The design replaces the left sidebar with a horizontal group nav, so
    // Sidebar and TopBar are no longer mounted; TopNav carries the groups, the
    // sub-nav, density and sign-out.
    <CurrentUserProvider user={currentUser}>
      {/* ota-shell/ota-frame: on desktop the console floats as one rounded
          frame (Settings → Appearance → Layout can switch to full width). */}
      <div className="ds-root ota-shell min-h-svh bg-background">
      <div className="ota-frame flex min-h-svh flex-col bg-background lg:min-h-0">
        <TopNav />

        {/* app-canvas is the design's console ground: carbon, the backdrop
            photo blended to ember, and a radial scrim. Content is centred in
            a 1152px column to match. */}
        <main className="app-canvas min-h-0 flex-1 overflow-y-auto overflow-x-hidden">
          {/* Strength is chosen in Settings → Appearance (medium by default). */}
          <ConsoleWallpaper />
          {/* Keyed by path so each page plays its entrance once per visit. */}
          <div key={pathname} className="ota-page mx-auto w-full max-w-[1152px] px-4 pb-28 pt-5 sm:px-6 md:pb-7 md:pt-7 2xl:max-w-[1360px]">
            {children}
          </div>
        </main>

        <div className="hidden md:block">
          <StatusBar />
        </div>
        <MobileTabBar />
        <Toaster position="bottom-right" richColors closeButton />
      </div>
      </div>
    </CurrentUserProvider>
  );
}

export default function ConsoleLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ErrorBoundary
      onError={(error, errorInfo) => {
        logger.error('DashboardLayout', 'Component error occurred', error, {
          componentStack: errorInfo.componentStack,
        });
      }}
      fallback={(error, reset) => (
        <DashboardShell>
          <ErrorFallback error={error} resetError={reset} />
        </DashboardShell>
      )}
    >
      <DashboardShell>{children}</DashboardShell>
    </ErrorBoundary>
  );
}
