import Link from 'next/link';
import Logo from '@/components/brand/Logo';

// Public marketing surface. This route previously did `redirect('/login')`, so
// the app had no unauthenticated entry point at all; the design's CTAs
// ("Open the console" / "Sign in to the console") now carry that job.
export const revalidate = 60;

const CONTAINER = 'mx-auto w-full max-w-[1152px] px-6';

const stages = [
  {
    n: '1',
    name: 'Artifact',
    copy: 'Your build output is captured whole — bytes, source commit and target architecture — and nothing is mutated after this point.',
  },
  {
    n: '2',
    name: 'Store',
    copy: 'The image lands immutable at a content address. The digest computed here is the digest every device checks against.',
  },
  {
    n: '3',
    name: 'Sign',
    copy: 'An Ed25519 key in the vault signs the manifest. The private half never leaves the vault; the console only ever holds results.',
  },
  {
    n: '4',
    name: 'Verify',
    copy: 'The trust anchor. If the signature does not chain back to an active key, the release is never created and no device is told about it.',
  },
];

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

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <div
        className="tabular"
        style={{ font: '600 30px/1.1 var(--font-display)', color: '#fff' }}
      >
        {value}
      </div>
      <div className="type-caption" style={{ color: 'var(--on-dark-muted)' }}>
        {label}
      </div>
    </div>
  );
}

export default async function LandingPage() {
  const stats = await getFleetStats();

  return (
    <div
      className="ds-root"
      style={{
        minHeight: '100vh',
        backgroundColor: '#0d0d0d',
        backgroundImage:
          'linear-gradient(160deg,rgba(13,13,13,.97) 0%,rgba(13,13,13,.86) 40%,rgba(58,8,0,.72) 100%),linear-gradient(0deg,#ff2803,#ff2803),url("/brand/landing-bg.jpg")',
        backgroundBlendMode: 'normal,color,normal',
        backgroundSize: 'cover,cover,cover',
        backgroundPosition: 'center,center,center',
        backgroundAttachment: 'fixed',
      }}
    >
      <a
        href="#ota-main"
        className="sr-only focus:not-sr-only"
        style={{
          position: 'absolute',
          left: 8,
          top: 8,
          zIndex: 99,
          padding: '10px 16px',
          background: 'var(--ember)',
          color: '#fff',
          borderRadius: 8,
        }}
      >
        Skip to main content
      </a>

      {/* ── Header ────────────────────────────────────────────────────── */}
      <header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 20,
          display: 'flex',
          alignItems: 'center',
          gap: 20,
          padding: '0 32px',
          minHeight: 68,
          borderBottom: '1px solid rgba(255,255,255,.10)',
          background: 'rgba(13,13,13,.82)',
          backdropFilter: 'blur(8px)',
        }}
      >
        <Logo size={32} wordmarkSize={21} />

        <nav
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 26,
            marginLeft: 'auto',
            flexWrap: 'wrap',
            justifyContent: 'flex-end',
          }}
        >
          <a href="#how" className="ds-navlink type-body-md">
            How it works
          </a>
          <a href="#gates" className="ds-navlink type-body-md">
            Trust gates
          </a>
          <a href="#fleet" className="ds-navlink type-body-md">
            Fleet health
          </a>
          <Link
            href="/login"
            className="ds-cta"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              minHeight: 44,
              padding: '0 20px',
              borderRadius: 8,
              textDecoration: 'none',
            }}
          >
            Open the Console
          </Link>
        </nav>
      </header>

      <main id="ota-main" style={{ scrollMarginTop: 80 }}>
        {/* ── Hero ────────────────────────────────────────────────────── */}
        <section
          className={CONTAINER}
          style={{
            padding: '96px 24px 72px',
            display: 'flex',
            flexDirection: 'column',
            gap: 28,
            alignItems: 'flex-start',
          }}
        >
          <div className="type-micro-cap" style={{ color: 'var(--amber)' }}>
            Signed · Verified · Health-gated
          </div>

          <h1
            className="type-display-large"
            style={{ margin: 0, color: '#fff', maxWidth: '20ch' }}
          >
            Ship firmware without{' '}
            <span
              style={{
                background: 'var(--highlight-keyword)',
                color: 'var(--highlight-keyword-ink)',
                padding: '0 10px',
                borderRadius: 4,
                boxShadow: 'var(--shadow-3-glow)',
              }}
            >
              bricking
            </span>{' '}
            the fleet.
          </h1>

          <p
            className="type-body-lg"
            style={{ margin: 0, color: 'var(--on-dark-muted)', maxWidth: '60ch' }}
          >
            Every binary is signed before it leaves your machine and verified by the bootloader
            before it runs. The device reports the version it is actually running — SecureOTA never
            marks an update successful on the device’s behalf.
          </p>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link
              href="/login"
              className="ds-cta"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                minHeight: 52,
                padding: '0 26px',
                borderRadius: 8,
                textDecoration: 'none',
              }}
            >
              Open the Console
            </Link>
            <a
              href="#how"
              className="ds-ghost"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                minHeight: 52,
                padding: '0 24px',
                borderRadius: 8,
              }}
            >
              See the Four Stages
            </a>
          </div>

          <div
            style={{
              display: 'flex',
              gap: 38,
              flexWrap: 'wrap',
              paddingTop: 22,
              borderTop: '1px solid rgba(255,255,255,.10)',
              width: '100%',
              maxWidth: 720,
            }}
          >
            <Stat value={stats.devices} label="devices under management" />
            <Stat value={stats.releases} label="signed releases published" />
            <Stat value="0" label="unsigned images ever shipped" />
          </div>
        </section>

        {/* ── How it works ────────────────────────────────────────────── */}
        <section
          id="how"
          className={CONTAINER}
          style={{
            padding: '24px 24px 72px',
            display: 'flex',
            flexDirection: 'column',
            gap: 22,
            scrollMarginTop: 88,
          }}
        >
          <div className="ds-reveal">
            <div
              className="type-micro-cap"
              style={{ color: 'var(--amber)', marginBottom: 10 }}
            >
              The pipeline
            </div>
            <h2 className="type-heading-lg" style={{ margin: 0, color: '#fff' }}>
              Four stages, none skippable.
            </h2>
          </div>

          <div
            className="ds-reveal-stagger"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit,minmax(240px,1fr))',
              gap: 14,
            }}
          >
            {stages.map((st) => (
              <div
                key={st.n}
                style={{
                  padding: 24,
                  borderRadius: 12,
                  border: '1px solid rgba(255,255,255,.12)',
                  background: 'rgba(33,33,33,.72)',
                  boxShadow: 'var(--glow-edge-inset)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                }}
              >
                <div
                  className="type-micro-cap tabular"
                  style={{ color: 'var(--on-dark-muted)' }}
                >
                  Stage {st.n}
                </div>
                <div className="type-heading-sm" style={{ color: '#fff' }}>
                  {st.name}
                </div>
                <p
                  className="type-caption"
                  style={{ margin: 0, color: 'var(--on-dark-muted)', textWrap: 'pretty' }}
                >
                  {st.copy}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Trust gates ─────────────────────────────────────────────── */}
        <section
          id="gates"
          className={`${CONTAINER} ds-reveal-stagger`}
          style={{
            padding: '0 24px 72px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit,minmax(300px,1fr))',
            gap: 16,
            scrollMarginTop: 88,
          }}
        >
          <div
            style={{
              padding: 32,
              borderRadius: 18,
              border: '1px solid var(--hairline-glow)',
              backgroundColor: '#3a0800',
              backgroundImage:
                'linear-gradient(152deg,rgba(13,13,13,.34) 0%,rgba(13,13,13,.72) 52%,rgba(13,13,13,.86) 100%),var(--gradient-panel)',
              boxShadow: 'var(--shadow-panel)',
              display: 'flex',
              flexDirection: 'column',
              gap: 12,
            }}
          >
            <div className="type-micro-cap" style={{ color: '#ffd9bd' }}>
              TCV engine
            </div>
            <h2 className="type-heading-md" style={{ margin: 0, color: '#fff' }}>
              Trust, compatibility, version.
            </h2>
            <p className="type-body-md" style={{ margin: 0, color: '#fff', textWrap: 'pretty' }}>
              Three gates run before a device is offered a binary: does the signature chain back to
              an active key, does the image match this architecture and bootloader, and is the
              version a forward move inside the rollback window. A red gate skips the device — it
              does not retry blindly.
            </p>
          </div>

          <div
            style={{
              padding: 32,
              borderRadius: 18,
              border: '1px solid rgba(255,255,255,.12)',
              background: 'rgba(33,33,33,.72)',
              boxShadow: 'var(--glow-edge-inset)',
              display: 'flex',
              flexDirection: 'column',
              gap: 12,
            }}
          >
            <div className="type-micro-cap" style={{ color: 'var(--amber)' }}>
              Host access
            </div>
            <h2 className="type-heading-md" style={{ margin: 0, color: '#fff' }}>
              Locked until you grant it.
            </h2>
            <p
              className="type-body-md"
              style={{ margin: 0, color: 'var(--on-dark-muted)', textWrap: 'pretty' }}
            >
              COM ports and the local network stay closed until an operator grants them. Grants
              expire after 60 minutes, name who issued them, and every issue and revoke is written
              to the audit trail. Flashing refuses to open a port on a grant it does not hold.
            </p>
          </div>
        </section>

        {/* ── Fleet health ────────────────────────────────────────────── */}
        <section
          id="fleet"
          className={`${CONTAINER} ds-reveal`}
          style={{
            padding: '0 24px 96px',
            display: 'flex',
            flexDirection: 'column',
            gap: 18,
            scrollMarginTop: 88,
          }}
        >
          <div>
            <div
              className="type-micro-cap"
              style={{ color: 'var(--amber)', marginBottom: 10 }}
            >
              ASH · Aggregate system health
            </div>
            <h2 className="type-heading-lg" style={{ margin: 0, color: '#fff' }}>
              A board that fails its boot check is excluded, not retried.
            </h2>
          </div>

          <p
            className="type-body-lg"
            style={{ margin: 0, color: 'var(--on-dark-muted)', maxWidth: '66ch' }}
          >
            Devices score themselves on boot failures, heap fragmentation and missed heartbeats.
            Below 40 they are quarantined out of every rollout until they hold a healthy boot for
            two cycles — and they keep reporting, so you watch recovery instead of guessing at it.
          </p>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', paddingTop: 8 }}>
            <Link
              href="/login"
              className="ds-cta"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                minHeight: 52,
                padding: '0 26px',
                borderRadius: 8,
                textDecoration: 'none',
              }}
            >
              Sign in to the Console
            </Link>
          </div>
        </section>
      </main>

      {/* ── Footer ──────────────────────────────────────────────────────── */}
      <footer
        style={{
          borderTop: '1px solid rgba(255,255,255,.10)',
          background: 'rgba(13,13,13,.72)',
        }}
      >
        <div
          className={CONTAINER}
          style={{
            padding: '26px 24px',
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            flexWrap: 'wrap',
          }}
        >
          <Logo size={24} showWordmark={false} />
          <span className="type-caption" style={{ color: 'var(--on-dark-muted)' }}>
            SecureOTA console · gateway API v3
          </span>
        </div>
      </footer>
    </div>
  );
}
