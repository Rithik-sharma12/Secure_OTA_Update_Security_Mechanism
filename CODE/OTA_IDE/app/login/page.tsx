'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { apiFetch, persistAuthSession, type StoredAuthUser } from '@/lib/client-auth';

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
    <div className="min-h-svh bg-background px-4 py-10">
      <div className="mx-auto flex min-h-[80vh] w-full max-w-md items-center">
        <Card className="w-full glass border-border/50">
          <CardHeader>
            <CardTitle className="text-2xl">Secure OTA Login</CardTitle>
            <CardDescription>
              Authenticate to access device flashing, serial monitor uploads, and protected runtime controls.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={handleLogin}>
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground" htmlFor="username">
                  Username
                </label>
                <Input
                  id="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                  placeholder="Enter admin username"
                  required
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground" htmlFor="password">
                  Password
                </label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  placeholder="Enter admin password"
                  required
                />
              </div>

              {errorMessage && (
                <p className="rounded-md border border-chart-4/40 bg-chart-4/10 px-3 py-2 text-sm text-chart-4">
                  {errorMessage}
                </p>
              )}

              <Button type="submit" className="w-full bg-primary hover:bg-primary/90" disabled={isSubmitting}>
                {isSubmitting ? 'Signing in...' : 'Sign In'}
              </Button>

              <p className="text-xs text-foreground/60">
                Use credentials configured by OTA_ADMIN_USERNAME and OTA_ADMIN_PASSWORD. No default login is seeded in production mode.
              </p>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
