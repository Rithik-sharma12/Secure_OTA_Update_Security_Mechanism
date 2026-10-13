import type { Metadata } from 'next';
import Link from 'next/link';

// Next.js already adds <meta name="robots" content="noindex"> to 404s.
export const metadata: Metadata = {
  title: 'Page not found',
};

/** A real 404 (status 404, noindex) that still points people somewhere useful. */
export default function NotFound() {
  return (
    <main className="ds-root flex min-h-svh flex-col items-center justify-center gap-5 bg-background px-6 text-center">
      <p className="type-micro-cap" style={{ color: 'var(--ember)' }}>
        404
      </p>
      <h1 className="text-3xl font-semibold tracking-tight text-foreground">This page does not exist</h1>
      <p className="max-w-md text-foreground/70">
        The link may be old, or the page may have moved. These are the places most people are looking for:
      </p>
      <nav aria-label="Helpful links" className="flex flex-wrap justify-center gap-3">
        <Link href="/" className="ds-cta inline-flex min-h-[44px] items-center rounded-lg px-5" style={{ textDecoration: 'none' }}>
          SecureOTA home
        </Link>
        <Link href="/login" className="ds-ghost inline-flex min-h-[44px] items-center rounded-lg px-5" style={{ textDecoration: 'none' }}>
          Sign in to the console
        </Link>
      </nav>
    </main>
  );
}
