import { AmbientWallpaper } from '@/components/brand/LiveWallpaper';
import fs from 'node:fs';
import path from 'node:path';
import Link from 'next/link';
import { ArrowRight, Cpu } from 'lucide-react';
import Logo from '@/components/brand/Logo';
import { DefenseStack } from '@/components/landing/DefenseStack';
import { FeatureGrid } from '@/components/landing/FeatureGrid';
import { GetStarted } from '@/components/landing/GetStarted';
import { HeroBackdrop } from '@/components/landing/HeroBackdrop';
import { LandingHeader } from '@/components/landing/LandingHeader';
import { Reveal } from '@/components/landing/Reveal';
import { UpdateSimulator } from '@/components/landing/UpdateSimulator';
import type { Metadata } from 'next';
import { BASE_OPEN_GRAPH, SITE_DESCRIPTION, SITE_NAME, SITE_TITLE, SITE_URL, SOURCE_REPOSITORY } from '@/lib/site';
import './landing.css';

// Public marketing surface. This route previously did `redirect('/login')`, so
// the app had no unauthenticated entry point at all; the design's CTAs
// ("Open the console" / "Sign in to the console") now carry that job.
export const revalidate = 60;

export const metadata: Metadata = {
  title: { absolute: SITE_TITLE },
  description: SITE_DESCRIPTION,
  alternates: { canonical: '/' },
  other: {
    'google-site-verification': 'ot1Vz4NP_A5oXLJT37QxjAyFwDlWwMwOrDyGXDpYDgE',
  },
  openGraph: { ...BASE_OPEN_GRAPH, url: '/', title: SITE_TITLE, description: SITE_DESCRIPTION },
};

/**
 * Structured data describing what this page actually is: the website, and
 * the open-source software it presents. No ratings, prices or organisation
 * details are claimed because none exist to cite.
 */
const structuredData = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'WebSite',
      '@id': `${SITE_URL}/#website`,
      url: `${SITE_URL}/`,
      name: SITE_NAME,
      description: SITE_DESCRIPTION,
      inLanguage: 'en',
    },
    {
      '@type': 'SoftwareSourceCode',
      '@id': `${SITE_URL}/#software`,
      name: SITE_NAME,
      description:
        'Secure over-the-air firmware update platform for ESP32 devices: signed releases, on-device verification, health-gated rollback and a web console.',
      codeRepository: SOURCE_REPOSITORY,
      programmingLanguage: ['TypeScript', 'Python', 'C++'],
      runtimePlatform: ['Next.js', 'FastAPI', 'ESP32 (Arduino)'],
      url: `${SITE_URL}/`,
    },
  ],
};

/** JSON-LD, serialised so no value can close the script tag early. */
function jsonLd(value: unknown) {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
}




/**
 * The hero video is optional: drop hero-loop.webm and/or hero-loop.mp4 into
 * public/brand/ (see docs/design/HERO_VIDEO_PROMPT.md) and it is picked up on
 * the next revalidation. Without them the animated canvas carries the hero
 * alone and no request is made for a file that does not exist.
 */
function heroVideoSources(): Array<{ src: string; type: string }> {
  const dir = path.join(process.cwd(), 'public', 'brand');
  return [
    { file: 'hero-loop.webm', type: 'video/webm' },
    { file: 'hero-loop.mp4', type: 'video/mp4' },
  ]
    .filter((entry) => {
      try {
        return fs.statSync(path.join(dir, entry.file)).isFile();
      } catch {
        return false;
      }
    })
    .map((entry) => ({ src: `/brand/${entry.file}`, type: entry.type }));
}

// Release targets the gateway and the publish form accept (see
// DEVICE_TYPES in components/dashboard/publish-firmware-card.tsx).
const BOARDS = ['ESP32', 'ESP8266', 'STM32F103', 'ATmega328P'];

/**
 * Product facts shown under the hero. Each one is a property of the code
 * (firmware OTA_HEALTH_GATE_TIMEOUT_SECONDS, the secure package format, the
 * heartbeat command channel), not a usage number, so nothing here can go
 * stale or be invented.
 */
const FACTS = [
  { value: '120 s', label: 'for a new build to prove itself. Miss it and the board reverts.' },
  { value: 'RSA‑2048 + AES‑256', label: 'signed, encrypted packages, checked on the board before a byte is written.' },
  { value: 'Outbound only', label: 'boards call the gateway on their heartbeat. No port forwarding on site.' },
];

function SectionHeading({ eyebrow, title, lead }: { eyebrow: string; title: string; lead?: string }) {
  return (
    <Reveal>
      <div className="lp-eyebrow">{eyebrow}</div>
      <h2 className="lp-h2">{title}</h2>
      {lead && <p className="lp-lead">{lead}</p>}
    </Reveal>
  );
}

export default async function LandingPage() {
  const videoSources = heroVideoSources();

  return (
    <div className="ds-root lp">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd(structuredData) }} />
      {/* Live wallpaper behind every section; .lp isolates it above the page ground. */}
      <AmbientWallpaper fixed intensity={0.55} zIndex={-1} />
      <a href="#ota-main" className="sr-only focus:not-sr-only" style={{ position: 'absolute', left: 8, top: 8, zIndex: 99, padding: '10px 16px', background: 'var(--ember)', color: '#fff', borderRadius: 8 }}>
        Skip to main content
      </a>

      <LandingHeader />

      <main id="ota-main">
        {/* ── Hero ─────────────────────────────────────────────────────── */}
        <section className="lp-hero" aria-labelledby="lp-hero-title">
          <HeroBackdrop videoSources={videoSources} />
          <div className="lp-container">
            <div className="lp-hero-copy">
              <Reveal>
                <div className="lp-hero-badges">
                  <span className="lp-chip">
                    <span className="lp-dot" aria-hidden="true" /> Firmware delivery for ESP32 fleets
                  </span>
                </div>
              </Reveal>
              <Reveal delay={80}>
                <h1 id="lp-hero-title">Update every board in the field. Never drive out to unbrick one.</h1>
              </Reveal>
              <Reveal delay={160}>
                <p className="lp-lead" style={{ marginTop: 0, fontSize: 18 }}>
                  Flash a board over USB once. From then on, SecureOTA ships signed firmware to it over the internet
                  and shows every stage as it happens. If the new build cannot reach your gateway within 120 seconds,
                  the board boots its previous firmware on its own.
                </p>
              </Reveal>
              <Reveal delay={240}>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <Link href="/login" className="ds-cta lp-btn">
                    Open the console <ArrowRight size={18} />
                  </Link>
                  <a href="#start" className="ds-ghost lp-btn">
                    See the setup
                  </a>
                </div>
              </Reveal>
              <Reveal delay={320}>
                <dl className="lp-stats">
                  {FACTS.map((fact) => (
                    <div key={fact.value}>
                      <dt className="lp-stat-value">{fact.value}</dt>
                      <dd className="lp-stat-label">{fact.label}</dd>
                    </div>
                  ))}
                </dl>
              </Reveal>
            </div>
          </div>
        </section>

        {/* ── Get started ──────────────────────────────────────────────── */}
        <section id="start" className="lp-section">
          <div className="lp-container">
            <SectionHeading
              eyebrow="Get started"
              title="One USB session per board. Every update after that is remote."
              lead="Four steps. The first three run once per board. The fourth is every release you ship after that."
            />
            <Reveal delay={120}>
              <GetStarted />
            </Reveal>
          </div>
        </section>

        {/* ── Simulator ────────────────────────────────────────────────── */}
        <section id="simulator" className="lp-section" style={{ background: 'linear-gradient(180deg, rgba(var(--lp-panel-rgb),0) 0%, rgba(var(--lp-panel-rgb),.55) 50%, rgba(var(--lp-panel-rgb),0) 100%)' }}>
          <div className="lp-container">
            <SectionHeading
              eyebrow="Watch an update"
              title="Press Deploy. Watch the board protect itself."
              lead="Run a clean update, a tampered image and a broken build. In all three, the board ends on firmware that works."
            />
            <Reveal delay={120}>
              <UpdateSimulator />
            </Reveal>
          </div>
        </section>

        {/* ── Boards ───────────────────────────────────────────────────── */}
        <section className="lp-boards" aria-labelledby="lp-boards-title">
          <div className="lp-container">
            <p id="lp-boards-title" className="lp-boards-title">
              Release targets. Over-the-internet updates with health-gated rollback run on ESP32.
            </p>
            <ul className="lp-boards-list">
              {BOARDS.map((board) => (
                <li key={board}>
                  <Cpu size={18} color="var(--amber)" aria-hidden="true" /> {board}
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* ── Features ─────────────────────────────────────────────────── */}
        <section id="features" className="lp-section">
          <div className="lp-container">
            <SectionHeading
              eyebrow="What you get"
              title="Run the whole fleet from one console."
              lead="Each card opens the console page that does the job."
            />
            <FeatureGrid />
          </div>
        </section>

        {/* ── Security ─────────────────────────────────────────────────── */}
        <section id="security" className="lp-section">
          <div className="lp-container">
            <SectionHeading
              eyebrow="Security"
              title="Try to break it."
              lead="Pick an attack. See the layer that stops it. Pick a layer to read exactly what it checks."
            />
            <Reveal delay={120}>
              <DefenseStack />
            </Reveal>
          </div>
        </section>

        {/* ── Final call to action ─────────────────────────────────────── */}
        <section className="lp-section" style={{ paddingTop: 24 }}>
          <div className="lp-container">
            <Reveal>
              <div className="lp-final">
                <div className="lp-eyebrow" style={{ color: '#ffd9bd' }}>
                  Your first board
                </div>
                <h2 className="lp-h2" style={{ maxWidth: '18ch' }}>
                  Plug in one board. Ship every update after it from your desk.
                </h2>
                <p className="lp-lead" style={{ color: 'rgba(255,255,255,.82)' }}>
                  Sign in, run the agent, flash the board. It reports its first heartbeat as soon as it joins Wi-Fi.
                </p>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 28 }}>
                  <Link href="/login" className="ds-cta lp-btn">
                    Open the console <ArrowRight size={18} />
                  </Link>
                  <a href="/agent/secureota_agent.py" download className="ds-ghost lp-btn">
                    Download the agent
                  </a>
                </div>
              </div>
            </Reveal>
          </div>
        </section>
      </main>

      <footer className="lp-footer">
        <div className="lp-container" style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <Logo size={24} showWordmark={false} />
          <span>SecureOTA. Signed firmware delivery for IoT fleets.</span>
          <nav aria-label="Footer" style={{ marginLeft: 'auto', display: 'flex', gap: 18, flexWrap: 'wrap' }}>
            <a href="#security">Security</a>
            <a href={SOURCE_REPOSITORY} rel="noopener">Source code</a>
            <Link href="/privacy">Privacy policy</Link>
            <Link href="/terms">Terms and conditions</Link>
            <Link href="/login">Sign in</Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
