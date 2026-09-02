'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import Sidebar from '@/components/layout/Sidebar';
import TopBar from '@/components/layout/TopBar';
import StatusBar from '@/components/layout/StatusBar';
import { ErrorBoundary } from '@/components/error/ErrorBoundary';
import { ErrorFallback } from '@/components/error/ErrorFallback';
import { logger } from '@/lib/logger';
import { apiFetch, clearAuthSession, persistAuthSession, type StoredAuthUser } from '@/lib/client-auth';

function DashboardShell({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [isSidebarOpen, setIsSidebarOpen] = React.useState(true);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = React.useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = React.useState(true);

  React.useEffect(() => {
    let isMounted = true;

    const validateSession = async () => {
      try {
        const response = await apiFetch('/api/auth/session');
        const payload = (await response.json()) as {
          ok?: boolean;
          user?: StoredAuthUser;
        };

        if (!response.ok || !payload.ok || !payload.user) {
          await clearAuthSession();
          router.replace('/login');
          return;
        }

        persistAuthSession(payload.user);
        if (isMounted) {
          setIsCheckingAuth(false);
        }
      } catch {
        await clearAuthSession();
        router.replace('/login');
      }
    };

    void validateSession();

    return () => {
      isMounted = false;
    };
  }, [router]);

  if (isCheckingAuth) {
    return (
      <div className="flex min-h-svh items-center justify-center bg-background px-4">
        <div className="rounded-lg border border-border/50 bg-card px-6 py-4 text-sm text-foreground/80">
          Validating platform access...
        </div>
      </div>
    );
  }

  return (
    // ds-root exposes the ember/carbon tokens (--ember, --type-*, .ota-brand)
    // to the whole console, alongside the shadcn tokens globals.css maps onto
    // the same palette.
    <div className="ds-root flex min-h-svh flex-col bg-background md:flex-row">
      <Sidebar
        isOpen={isSidebarOpen}
        onToggle={() => setIsSidebarOpen((current) => !current)}
        mobileOpen={isMobileSidebarOpen}
        onMobileOpenChange={setIsMobileSidebarOpen}
      />

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <TopBar onMenuClick={() => setIsMobileSidebarOpen(true)} />

        {/* app-canvas is the design's console ground: carbon, the backdrop
            photo blended to ember, and a radial scrim. Content is centred in a
            1152px column to match. */}
        <main className="app-canvas flex-1 overflow-y-auto overflow-x-hidden">
          <div className="mx-auto w-full max-w-[1152px] px-4 py-5 sm:px-6 lg:px-6 lg:py-7">
            {children}
          </div>
        </main>

        <StatusBar />
      </div>
    </div>
  );
}

export default function DashboardLayout({
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
