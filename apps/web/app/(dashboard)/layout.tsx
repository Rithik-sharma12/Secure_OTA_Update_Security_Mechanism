import type { Metadata } from 'next';
import ConsoleLayout from '@/components/layout/ConsoleLayout';
import { AuthProvider } from '@/components/auth/AuthProvider';

/**
 * Every page in this group is the signed-in operator console: private, and
 * never meant for search results. The interactive shell (auth check, nav,
 * live wallpaper) is a client component; this server layout only adds the
 * metadata a client layout cannot export.
 */
export const metadata: Metadata = {
  title: { default: 'Console', template: '%s · SecureOTA console' },
  robots: { index: false, follow: false, nocache: true, googleBot: { index: false, follow: false } },
};

export default function DashboardGroupLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <ConsoleLayout>{children}</ConsoleLayout>
    </AuthProvider>
  );
}
