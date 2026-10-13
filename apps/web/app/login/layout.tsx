import type { Metadata } from 'next';
import { BASE_OPEN_GRAPH } from '@/lib/site';
import { AuthProvider } from '@/components/auth/AuthProvider';
import './login.css';

/**
 * The sign-in screen is a gateway, not content: keep it out of search
 * results but let crawlers follow its links back to the landing page.
 */
export const metadata: Metadata = {
  title: 'Sign in',
  description: 'Sign in to the SecureOTA console to flash boards, publish signed releases and deploy updates to your fleet.',
  alternates: { canonical: '/login' },
  robots: { index: false, follow: true },
  openGraph: { ...BASE_OPEN_GRAPH, url: '/login', title: 'Sign in · SecureOTA' },
};

export default function LoginLayout({ children }: { children: React.ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}
