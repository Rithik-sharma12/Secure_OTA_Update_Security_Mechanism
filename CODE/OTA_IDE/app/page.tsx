import fs from 'node:fs';
import path from 'node:path';
import Link from 'next/link';
import { ArrowRight, Cpu } from 'lucide-react';
import Logo from '@/components/brand/Logo';
import { CountUp } from '@/components/landing/CountUp';
import { DefenseStack } from '@/components/landing/DefenseStack';
import { FeatureGrid } from '@/components/landing/FeatureGrid';
import { GetStarted } from '@/components/landing/GetStarted';
import { HeroBackdrop } from '@/components/landing/HeroBackdrop';
import { LandingHeader } from '@/components/landing/LandingHeader';
import { Reveal } from '@/components/landing/Reveal';
import { RotatingWord } from '@/components/landing/RotatingWord';
import { UpdateSimulator } from '@/components/landing/UpdateSimulator';
import './landing.css';

// Public marketing surface. This route previously did `redirect('/login')`, so
// the app had no unauthenticated entry point at all; the design's CTAs
// ("Open the console" / "Sign in to the console") now carry that job.
export const revalidate = 60;




/**
 * Real fleet numbers, server-side.
 *
 * The design mock bound these to simulated state and carried a "data are
 * simulated" disclaimer. Publishing invented device counts on a public page
 * would be the same class of mistake the gateway forbids internally, so these
 * come from the live gateway instead — and fall back to an em dash when it
 * cannot be reached, rather than to a plausible-looking number.
 */
async function getFleetStats(): Promise<{ devices: string; releases: string }> {
  const base = process.env.EDGE_GATEWAY_URL || 'http://localhost:5000';
  const key = process.env.EDGE_GATEWAY_API_KEY;
  const url = key
    ? `${base}/api/dashboard?api_key=${encodeURIComponent(key)}`
    : `${base}/api/dashboard`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(url, { signal: controller.signal, next: { revalidate: 60 } });
    clearTimeout(timer);
    if (!res.ok) return { devices: '—', releases: '—' };

    const data = (await res.json()) as {
      devices?: unknown[];
      releases?: unknown[];
    };
    return {
      devices: Array.isArray(data.devices) ? String(data.devices.length) : '—',
      releases: Array.isArray(data.releases) ? String(data.releases.length) : '—',
    };
  } catch {
    return { devices: '—', releases: '—' };
  }
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

const BOARDS = ['ESP32', 'ESP32-S3', 'ESP32-C3', 'ESP8266', 'STM32F103', 'ATmega328P'];

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
  const stats = await getFleetStats();
  const videoSources = heroVideoSources();

  return (
    <div className="ds-root lp">
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
                    <span className="lp-dot" data-pulse="true" aria-hidden="true" /> Signed · Verified · Self-healing
                  </span>
                  <span className="lp-chip">ESP32 fleets over the internet</span>
                </div>
              </Reveal>
              <Reveal delay={80}>
                <h1 id="lp-hero-title">
                  <span className="lp-sr">Update every board, anywhere, without bricking it.</span>
                  <span aria-hidden="true">
                    Update every board, anywhere — without{' '}
                    <RotatingWord words={['bricking it', 'guesswork', 'port forwarding', 'a site visit']} />
                  </span>
                </h1>
              </Reveal>
              <Reveal delay={160}>
                <p className="lp-lead" style={{ marginTop: 0, fontSize: 18 }}>
                  Flash and set up a board over USB once. From then on SecureOTA delivers signed firmware to it over
                  the internet, shows you every step live, and the board rolls itself back if an update goes wrong.
                </p>
              </Reveal>
              <Reveal delay={240}>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <Link href="/login" className="ds-cta lp-btn">
                    Open the console <ArrowRight size={18} />
                  </Link>
                  <a href="#start" className="ds-ghost lp-btn">
                    Get started in 4 steps
                  </a>
                </div>
              </Reveal>
              <Reveal delay={320}>
                <div className="lp-stats">
                  <div>
                    <div className="lp-stat-value">
                      <CountUp value={stats.devices} />
                    </div>
                    <div className="lp-stat-label">boards under management</div>
                  </div>
                  <div>
                    <div className="lp-stat-value">
                      <CountUp value={stats.releases} />
                    </div>
                    <div className="lp-stat-label">signed releases published</div>
                  </div>
                  <div>
                    <div className="lp-stat-value">
                      <CountUp value="120" />s
                    </div>
                    <div className="lp-stat-label">to prove an update, or roll back</div>
                  </div>
                </div>
              </Reveal>
            </div>
          </div>
          <a href="#start" className="lp-scroll-cue">
            Scroll
            <i aria-hidden="true" />
          </a>
        </section>

        {/* ── Get started ──────────────────────────────────────────────── */}
        <section id="start" className="lp-section">
          <div className="lp-container">
            <SectionHeading
              eyebrow="Get started"
              title="From a board on your desk to updates over the internet."
              lead="Four steps, about five minutes. The first three happen once per board; the fourth is every release after that."
            />
            <Reveal delay={120}>
              <GetStarted />
            </Reveal>
          </div>
        </section>

        {/* ── Simulator ────────────────────────────────────────────────── */}
        <section id="simulator" className="lp-section" style={{ background: 'linear-gradient(180deg, rgba(33,33,33,0) 0%, rgba(33,33,33,.55) 50%, rgba(33,33,33,0) 100%)' }}>
          <div className="lp-container">
            <SectionHeading
              eyebrow="Watch an update"
              title="See what happens when you press Deploy."
              lead="Run a normal update, then try a tampered image and a broken build. The board protects itself in both."
            />
            <Reveal delay={120}>
              <UpdateSimulator />
            </Reveal>
          </div>
        </section>

        {/* ── Boards ───────────────────────────────────────────────────── */}
        <div className="lp-marquee" aria-label="Board profiles">
          <div className="lp-marquee-track">
            {[...BOARDS, ...BOARDS].map((board, index) => (
              <span key={`${board}-${index}`} className="lp-marquee-item" aria-hidden={index >= BOARDS.length}>
                <Cpu size={20} color="var(--amber)" /> {board}
              </span>
            ))}
          </div>
        </div>

        {/* ── Features ─────────────────────────────────────────────────── */}
        <section id="features" className="lp-section">
          <div className="lp-container">
            <SectionHeading
              eyebrow="What you can do"
              title="Everything a fleet needs after the first flash."
              lead="Each card opens the part of the console that does it."
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
              lead="Pick an attack and see which layer stops it. Pick a layer to read what it does."
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
                  Ready when your board is
                </div>
                <h2 className="lp-h2" style={{ maxWidth: '18ch' }}>
                  Plug in a board. Ship your next update from anywhere.
                </h2>
                <p className="lp-lead" style={{ color: 'rgba(255,255,255,.82)' }}>
                  Sign in, start the agent, and your first board is reporting in minutes.
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
          <span>SecureOTA · secure firmware delivery for heterogeneous IoT fleets</span>
          <span style={{ marginLeft: 'auto', display: 'flex', gap: 18 }}>
            <a href="#start">Get started</a>
            <a href="#security">Security</a>
            <Link href="/login">Sign in</Link>
          </span>
        </div>
      </footer>
    </div>
  );
}
