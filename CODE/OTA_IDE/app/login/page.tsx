'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { Activity, FileCheck2, KeyRound, Loader2, ShieldCheck, User2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { apiFetch, persistAuthSession, type StoredAuthUser } from '@/lib/client-auth';
import Image from 'next/image';
import Link from 'next/link';
import Logo from '@/components/brand/Logo';
import { ThemeToggle } from '@/components/theme-toggle';
import { ClerkSignInPanel } from '@/components/auth/ClerkSignInPanel';
import { clerkEnabled, postLoginPath } from '@/lib/post-login';

// The design's trust chain. The signature trace draws down the rail and each
// waypoint stamps a verified tick as it passes; `delay` is when that waypoint
// lights, timed against the 2.1s trace.
const chain = [
  {
    icon: FileCheck2,
    title: 'Signed on publish',
    description: 'The gateway signs every release with its Ed25519 key. Secure packages also carry an RSA-2048 signature over the version and image digest.',
    delay: '0.45s',
  },
  {
    icon: ShieldCheck,
    title: 'Verified on the board',
    description: 'The board checks the SHA-256 and the signature before it writes a byte, and refuses any older version.',
    delay: '1.15s',
  },
  {
    icon: Activity,
    title: 'Confirmed by heartbeat',
    description: 'A deployment counts as done only when the board itself reports the new version.',
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
          router.replace(postLoginPath());
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
      router.replace(postLoginPath());
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Unable to login right now.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="ds-root ota-login">

      <div className="ota-login-toolbar">
        <ThemeToggle compact />
      </div>

      <div className="ota-login-stage">
        {/* Media card: the connected-city photo with an ambient glow around it,
            the brand and the trust chain over it. A banner on small screens. */}
        <aside className="ota-login-media" aria-label="About SecureOTA">
          <div className="ota-login-glow" aria-hidden="true" />
          <div className="ota-login-card">
            <Image
              src="/brand/login-bg.jpg"
              alt=""
              fill
              priority
              sizes="(max-width: 1023px) 100vw, 640px"
              className="ota-login-photo"
            />
            <div className="ota-login-card-shade" aria-hidden="true" />
            <div className="ota-login-card-top">
              <span className="ota-login-chip">Signed · Verified · Health-gated</span>
            </div>
            <div className="ota-login-card-body">
              <Logo size={40} wordmarkSize={24} tone="light" />
              <p className="ota-login-headline">
                Update the fleet without <span>bricking</span> it.
              </p>
              <ul className="ota-login-chain">
                {chain.map((item) => (
                  <li key={item.title} style={{ ['--d' as string]: item.delay }}>
                    <span className="ota-login-chain-icon" aria-hidden="true">
                      <item.icon className="h-4 w-4" />
                      <span className="ota-login-chain-tick">✓</span>
                    </span>
                    <span>
                      <strong>{item.title}</strong>
                      <small>{item.description}</small>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </aside>

        {/* Sign-in form: the page's main content. */}
        <main className="ota-login-form">
          <div className="ota-login-form-head">
            <h1>Welcome back</h1>
            <p>Sign in to the SecureOTA console to manage devices and releases.</p>
          </div>

          {clerkEnabled ? (
            <ClerkSignInPanel />
          ) : (
            <>
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
                    placeholder="Enter your username"
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
                    placeholder="Enter your password"
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
                <p className="text-xs leading-relaxed text-foreground/75">
                  Local accounts are managed by an admin in Settings → Users.
                </p>
              </div>
            </>
          )}
        </main>
      </div>

      <p className="ota-login-foot">
        Access is authenticated and audited. <Link href="/privacy">Privacy policy</Link> ·{' '}
        <Link href="/terms">Terms and conditions</Link>
      </p>
    </div>
  );
}
