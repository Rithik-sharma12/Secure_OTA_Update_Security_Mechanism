'use client';

import React from 'react';
import Link from 'next/link';
import { Menu, X } from 'lucide-react';
import Logo from '@/components/brand/Logo';

const LINKS = [
  { href: '#start', id: 'start', label: 'Get started' },
  { href: '#simulator', id: 'simulator', label: 'Watch an update' },
  { href: '#features', id: 'features', label: 'Features' },
  { href: '#security', id: 'security', label: 'Security' },
];

/**
 * Sticky header: turns solid once the hero scrolls away, shows reading
 * progress as an ember line, and underlines the section in view.
 */
export function LandingHeader() {
  const [scrolled, setScrolled] = React.useState(false);
  const [progress, setProgress] = React.useState(0);
  const [active, setActive] = React.useState<string | null>(null);
  const [open, setOpen] = React.useState(false);

  React.useEffect(() => {
    let frame = 0;
    const onScroll = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const max = document.documentElement.scrollHeight - window.innerHeight;
        setScrolled(window.scrollY > 24);
        setProgress(max > 0 ? Math.min(1, window.scrollY / max) : 0);
      });
    };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('scroll', onScroll);
    };
  }, []);

  React.useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  React.useEffect(() => {
    const sections = LINKS.map((link) => document.getElementById(link.id)).filter(Boolean) as HTMLElement[];
    if (sections.length === 0 || typeof IntersectionObserver === 'undefined') return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: '-35% 0px -55% 0px', threshold: [0, 0.25, 0.5] }
    );
    sections.forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, []);

  return (
    <header className="lp-header" data-scrolled={scrolled || open ? 'true' : 'false'}>
      <div className="lp-container lp-header-inner">
        <Link href="/" aria-label="SecureOTA home" style={{ textDecoration: 'none' }}>
          <Logo size={32} wordmarkSize={21} />
        </Link>
        <button
          type="button"
          className="lp-menu-button"
          aria-label={open ? 'Close menu' : 'Open menu'}
          aria-expanded={open}
          aria-controls="lp-nav"
          onClick={() => setOpen((value) => !value)}
        >
          {open ? <X size={20} /> : <Menu size={20} />}
        </button>
        <nav id="lp-nav" className="lp-nav" data-open={open ? 'true' : 'false'} aria-label="Sections">
          {LINKS.map((link) => (
            <a
              key={link.id}
              href={link.href}
              className="lp-navlink"
              data-active={active === link.id ? 'true' : 'false'}
              onClick={() => setOpen(false)}
            >
              {link.label}
            </a>
          ))}
          <Link href="/login" className="ds-cta lp-btn lp-btn-sm" style={{ marginLeft: 10 }}>
            Open the console
          </Link>
        </nav>
      </div>
      <div className="lp-progress" style={{ transform: `scaleX(${progress})` }} aria-hidden="true" />
    </header>
  );
}
