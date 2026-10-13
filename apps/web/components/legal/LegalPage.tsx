import Link from 'next/link';
import type { ReactNode } from 'react';
import Logo from '@/components/brand/Logo';
import { CONTACT_EMAIL, LEGAL_LAST_UPDATED, SOURCE_REPOSITORY } from '@/lib/site';

/** Shared frame for the Privacy Policy and the Terms and Conditions. */
export function LegalPage({ title, intro, children }: { title: string; intro: ReactNode; children: ReactNode }) {
  return (
    <div className="ds-root legal">
      <header className="legal-header">
        <div className="legal-container legal-header-row">
          <Link href="/" aria-label="SecureOTA home" style={{ textDecoration: 'none' }}>
            <Logo size={28} wordmarkSize={18} />
          </Link>
          <nav aria-label="Legal" className="legal-nav">
            <Link href="/privacy">Privacy policy</Link>
            <Link href="/terms">Terms and conditions</Link>
            <Link href="/login">Sign in</Link>
          </nav>
        </div>
      </header>

      <main id="legal-main" className="legal-container legal-body">
        <p className="legal-updated">Last updated {LEGAL_LAST_UPDATED}</p>
        <h1>{title}</h1>
        <div className="legal-intro">{intro}</div>
        {children}
      </main>

      <footer className="legal-footer">
        <div className="legal-container">
          <span>SecureOTA</span>
          <Link href="/">Home</Link>
          <Link href="/privacy">Privacy policy</Link>
          <Link href="/terms">Terms and conditions</Link>
        </div>
      </footer>
    </div>
  );
}

/** How to reach the operator: the configured e-mail, or the public issue tracker. */
export function ContactLine() {
  if (CONTACT_EMAIL) {
    return (
      <>
        e-mail <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
      </>
    );
  }
  return (
    <>
      open an issue at <a href={`${SOURCE_REPOSITORY}/issues`} rel="noopener">{`${SOURCE_REPOSITORY.replace('https://', '')}/issues`}</a>
    </>
  );
}
