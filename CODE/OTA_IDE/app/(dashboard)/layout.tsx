'use client';

import React from 'react';
import Sidebar from '@/components/layout/Sidebar';
import TopBar from '@/components/layout/TopBar';
import StatusBar from '@/components/layout/StatusBar';
import { ErrorBoundary } from '@/components/error/ErrorBoundary';
import { ErrorFallback } from '@/components/error/ErrorFallback';
import { logger } from '@/lib/logger';

function DashboardShell({
  children,
}: {
  children: React.ReactNode;
}) {
  const [isSidebarOpen, setIsSidebarOpen] = React.useState(true);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = React.useState(false);

  return (
    <div className="flex min-h-svh flex-col bg-background md:flex-row">
      <Sidebar
        isOpen={isSidebarOpen}
        onToggle={() => setIsSidebarOpen((current) => !current)}
        mobileOpen={isMobileSidebarOpen}
        onMobileOpenChange={setIsMobileSidebarOpen}
      />

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <TopBar onMenuClick={() => setIsMobileSidebarOpen(true)} />

        <main className="flex-1 overflow-y-auto overflow-x-hidden">
          <div className="p-3 sm:p-4 lg:p-6">
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
