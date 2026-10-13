import type { Metadata } from 'next';
import { AuthProvider } from '@/components/auth/AuthProvider';

/** OAuth return page: transient, never indexed or followed. */
export const metadata: Metadata = {
  title: 'Signing in',
  robots: { index: false, follow: false },
};

export default function SsoCallbackLayout({ children }: { children: React.ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}
