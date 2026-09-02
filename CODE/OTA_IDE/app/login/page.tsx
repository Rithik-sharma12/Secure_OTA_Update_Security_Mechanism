'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { Activity, FileCheck2, KeyRound, Loader2, ShieldCheck, User2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { apiFetch, persistAuthSession, type StoredAuthUser } from '@/lib/client-auth';
import Logo from '@/components/brand/Logo';

// The design's trust chain. The signature trace draws down the rail and each
// waypoint stamps a verified tick as it passes; `delay` is when that waypoint
// lights, timed against the 2.1s trace.
const chain = [
  {
    icon: FileCheck2,
    title: 'Signed at the source',
    description: 'Ed25519 over sha256(image) before the binary leaves your machine.',
    delay: '0.45s',
  },
  {
    icon: ShieldCheck,
    title: 'Verified on the device',
    description: 'The bootloader refuses an image whose digest does not match the manifest.',
    delay: '1.15s',
  },
  {
    icon: Activity,
    title: 'Confirmed by heartbeat',
    description: 'A release resolves only when the device itself reports the target version.',
    delay: '1.85s',
  },
];

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null);

  React.useEffect(() => {
    let isMounted = true;

    const validateSession = async () => {
      try {
        const response = await apiFetch('/api/auth/session');
        if (!response.ok) {
          return;
        }

        const payload = (await response.json()) as {
          ok?: boolean;
          user?: StoredAuthUser;
        };

        if (payload.ok && payload.user && isMounted) {
          persistAuthSession(payload.user);
          router.replace('/dashboard');
        }
      } catch {
        // Ignore session check errors on the login page.
      }
    };

    void validateSession();

    return () => {
      isMounted = false;
    };
  }, [router]);

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      // Anything in front of the app (Cloudflare, a reverse proxy) answers with
      // an HTML page when the origin is restarting or a policy blocks the
      // request. Parsing that as JSON throws "Unexpected token '<'", which tells
      // the operator nothing — detect it and report what actually happened.
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        setErrorMessage(
          response.status === 502 || response.status === 503 || response.status === 504
            ? 'Server is starting up or temporarily unreachable. Wait a few seconds and try again.'
            : `Unexpected ${response.status} response from the server. If this persists, check that the gateway and dashboard containers are running.`
        );
        return;
      }

      const payload = (await response.json()) as {
        success?: boolean;
        data?: {
          user?: StoredAuthUser;
        };
        error?: string | { message?: string };
      };

      const user = payload.data?.user;
      const apiError =
        typeof payload.error === 'string'
          ? payload.error
          : payload.error?.message;

      if (!response.ok || !payload.success || !user) {
        setErrorMessage(apiError || 'Login failed. Please verify credentials.');
        return;
      }

      persistAuthSession(user);
      router.replace('/dashboard');
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Unable to login right now.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="ds-root grid min-h-svh w-full lg:grid-cols-[1.05fr_0.95fr]">
      {/* Brand / value panel */}
      <div
        className="relative hidden overflow-hidden lg:flex lg:flex-col lg:justify-between"
        style={{
          padding: 'clamp(24px,3.4vh,44px) clamp(28px,3.6vw,52px)',
          gap: 'clamp(14px,2.4vh,30px)',
          borderRight: '1px solid rgba(255,255,255,.08)',
          backgroundColor: '#0d0d0d',
          backgroundImage:
            'linear-gradient(105deg,rgba(13,13,13,.95) 0%,rgba(13,13,13,.80) 46%,rgba(58,8,0,.66) 100%),linear-gradient(0deg,#ff2803,#ff2803),url("/brand/login-bg.jpg")',
          backgroundBlendMode: 'normal,color,normal',
          backgroundSize: 'cover,cover,cover',
          backgroundPosition: 'center,center,center',
          backgroundRepeat: 'no-repeat',
        }}
      >
        <div className="relative z-10">
          <Logo size={40} wordmarkSize={24} />
        </div>

        <div
          className="relative z-10 flex min-h-0 max-w-[520px] flex-col"
          style={{ gap: 'clamp(12px,1.9vh,24px)' }}
        >
          <div className="type-micro-cap" style={{ color: 'var(--amber)' }}>
            Signed · Verified · Health-gated
          </div>

          <h1
            style={{
              margin: 0,
              font: '600 clamp(30px,4.4vh,52px)/1.1 var(--font-display)',
              letterSpacing: 'var(--tracking-display)',
              color: '#fff',
              textWrap: 'balance',
            }}
          >
            Update the fleet without{' '}
            <span
              style={{
                background: 'var(--highlight-keyword)',
                color: 'var(--highlight-keyword-ink)',
                padding: '0 8px',
                borderRadius: 4,
                boxShadow: 'var(--shadow-3-glow)',
              }}
            >
              bricking
            </span>{' '}
            it.
          </h1>

          <p
            style={{
              margin: 0,
              font: '400 clamp(13px,1.75vh,17px)/1.6 var(--font-ui)',
              color: 'var(--on-dark-muted)',
              maxWidth: '44ch',
              textWrap: 'pretty',
            }}
          >
            Every binary is signed before it leaves your machine and verified on the device before
            it boots. The device reports back — the console never claims success on its behalf.
          </p>

          {/* Trust chain. The rail is a static hairline with the ember trace
              drawn over it; both are decorative, so the SVG is aria-hidden and
              the list below carries the meaning. */}
          <div
            className="relative flex flex-col pt-0.5"
            style={{ gap: 'clamp(11px,1.7vh,20px)' }}
          >
            <svg
              width="2"
              height="188"
              viewBox="0 0 2 188"
              aria-hidden="true"
              style={{ position: 'absolute', left: 19, top: 14, overflow: 'visible' }}
            >
              <line x1="1" y1="0" x2="1" y2="188" stroke="rgba(255,255,255,.12)" strokeWidth="2" />
              <line
                x1="1"
                y1="0"
                x2="1"
                y2="188"
                stroke="#ff9742"
                strokeWidth="2"
                strokeLinecap="round"
                strokeDasharray="188"
                strokeDashoffset="188"
                style={{
                  ['--ota-len' as string]: '188',
                  animation: 'ota-trace 2.1s var(--ease-standard) .25s forwards',
                  filter: 'drop-shadow(0 0 6px rgba(255,151,66,.9))',
                }}
              />
            </svg>

            {chain.map((item) => (
              <div key={item.title} className="relative z-10 flex items-start gap-4">
                <span
                  className="relative inline-flex shrink-0 items-center justify-center"
                  style={{
                    width: 38,
                    height: 38,
                    borderRadius: 10,
                    border: '1px solid rgba(255,255,255,.12)',
                    background: 'rgba(13,13,13,.92)',
                    color: 'var(--amber)',
                    animation: `ota-chip .5s var(--ease-standard) ${item.delay} forwards`,
                  }}
                >
                  <item.icon className="h-5 w-5" />
                  <span
                    aria-hidden="true"
                    className="inline-flex items-center justify-center"
                    style={{
                      position: 'absolute',
                      right: -5,
                      bottom: -5,
                      width: 16,
                      height: 16,
                      borderRadius: '50%',
                      background: 'var(--ember)',
                      color: '#fff',
                      font: '700 10px/1 var(--font-ui)',
                      opacity: 0,
                      animation: `ota-verify .45s var(--ease-emphasis) ${item.delay} forwards`,
                    }}
                  >
                    ✓
                  </span>
                </span>
                <span className="flex flex-col gap-1 pt-[3px]">
                  <span className="type-body-strong" style={{ color: '#fff' }}>
                    {item.title}
                  </span>
                  <span
                    className="type-caption"
                    style={{
                      color: 'var(--on-dark-muted)',
                      maxWidth: '42ch',
                      textWrap: 'pretty',
                    }}
                  >
                    {item.description}
                  </span>
                </span>
              </div>
            ))}
          </div>
        </div>

        <div
          className="relative z-10 type-caption"
          style={{ color: 'rgba(255,255,255,.5)' }}
        >
          Protected environment · access is authenticated and audited.
        </div>
      </div>

      {/* Sign-in panel */}
      <div className="flex items-center justify-center bg-background px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <Logo size={40} wordmarkSize={20} />
          </div>

          <div className="mb-8 space-y-1.5">
            <h2 className="text-2xl font-semibold tracking-tight text-foreground">Welcome back</h2>
            <p className="text-sm text-foreground/60">
              Sign in to the operations console to manage devices and releases.
            </p>
          </div>

          <form className="space-y-5" onSubmit={handleLogin}>
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground" htmlFor="username">
                Username
              </label>
              <div className="relative">
                <User2 className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground/40" />
                <Input
                  id="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                  placeholder="Enter admin username"
                  className="pl-9"
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground" htmlFor="password">
                Password
              </label>
              <div className="relative">
                <KeyRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground/40" />
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  placeholder="Enter admin password"
                  className="pl-9"
                  required
                />
              </div>
            </div>

            {errorMessage && (
              <p className="rounded-lg border border-chart-4/40 bg-chart-4/10 px-3 py-2 text-sm text-chart-4">
                {errorMessage}
              </p>
            )}

            <Button
              type="submit"
              className="h-11 w-full bg-primary text-base hover:bg-primary/90"
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Signing in…
                </>
              ) : (
                'Sign in'
              )}
            </Button>
          </form>

          <div className="mt-8 flex items-start gap-2 rounded-lg border border-border/50 bg-muted/20 px-3 py-2.5">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-chart-1" />
            <p className="text-xs leading-relaxed text-foreground/60">
              Credentials come from OTA_ADMIN_USERNAME and OTA_ADMIN_PASSWORD. No default login is
              seeded in production mode.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
