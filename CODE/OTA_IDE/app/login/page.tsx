'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { KeyRound, Loader2, Lock, Radio, ShieldCheck, User2, Wifi } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { apiFetch, persistAuthSession, type StoredAuthUser } from '@/lib/client-auth';

const highlights = [
  {
    icon: ShieldCheck,
    title: 'Signed, verified firmware',
    description: 'Ed25519 manifests and RSA-verified packages gate every release before a device flashes it.',
  },
  {
    icon: Radio,
    title: 'Serial and OTA delivery',
    description: 'Flash over a granted COM port or push wirelessly to devices discovered on your network.',
  },
  {
    icon: Lock,
    title: 'Explicit host access',
    description: 'Physical ports and the local network stay locked until an operator grants access.',
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
    <div className="grid min-h-svh w-full lg:grid-cols-2">
      {/* Brand / value panel */}
      <div className="relative hidden overflow-hidden bg-slate-950 lg:flex lg:flex-col lg:justify-between">
        <div
          className="pointer-events-none absolute inset-0 opacity-70"
          style={{
            background:
              'radial-gradient(60% 60% at 20% 15%, rgba(56,189,248,0.20) 0%, rgba(15,23,42,0) 60%), radial-gradient(50% 50% at 90% 90%, rgba(129,140,248,0.18) 0%, rgba(15,23,42,0) 55%)',
          }}
        />
        <div className="relative z-10 p-10">
          <div className="flex items-center gap-3">
            <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-sky-400 to-indigo-500 shadow-lg shadow-sky-500/20">
              <Wifi className="h-6 w-6 text-slate-950" />
            </span>
            <div>
              <p className="text-lg font-semibold tracking-tight text-white">SecureOTA</p>
              <p className="text-xs text-slate-400">Heterogeneous firmware delivery platform</p>
            </div>
          </div>
        </div>

        <div className="relative z-10 max-w-lg px-10">
          <h1 className="text-3xl font-semibold leading-tight text-white">
            Ship firmware to the field without shipping the risk.
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-slate-400">
            Sign in to manage device fleets, publish signed releases, and control exactly which
            hardware ports and networks the platform is allowed to touch.
          </p>

          <div className="mt-8 space-y-4">
            {highlights.map((item) => (
              <div key={item.title} className="flex gap-3">
                <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-white/5">
                  <item.icon className="h-5 w-5 text-sky-300" />
                </span>
                <div>
                  <p className="text-sm font-medium text-white">{item.title}</p>
                  <p className="text-xs leading-relaxed text-slate-400">{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 p-10 text-xs text-slate-500">
          Protected environment · access is authenticated and audited.
        </div>
      </div>

      {/* Sign-in panel */}
      <div className="flex items-center justify-center bg-background px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-400 to-indigo-500">
              <Wifi className="h-5 w-5 text-slate-950" />
            </span>
            <p className="text-lg font-semibold tracking-tight text-foreground">SecureOTA</p>
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
