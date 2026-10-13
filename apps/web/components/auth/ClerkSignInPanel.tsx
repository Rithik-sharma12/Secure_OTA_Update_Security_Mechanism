'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { SignUpButton, useAuth, useClerk, useSignIn, useUser } from '@clerk/nextjs';
import { Github, KeyRound, Loader2, LogOut, MailCheck, RefreshCw, ShieldCheck, User2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { go, postLoginPath, rememberPostLoginPath } from '@/lib/post-login';
import { apiFetch, persistAuthSession, type StoredAuthUser } from '@/lib/client-auth';

/**
 * Sign-in with Clerk, built on the Core 3 `useSignIn()` API (@clerk/nextjs 7).
 *
 *   email + password ─▶ signIn.password()
 *        │ status 'complete'                     ─▶ signIn.finalize()
 *        │ status 'needs_client_trust'            ─▶ e-mailed code (new device)
 *        │ status 'needs_second_factor'           ─▶ authenticator app or e-mailed code
 *   Google / GitHub  ─▶ signIn.sso() ─▶ provider ─▶ /sso-callback (HandleSSOCallback)
 *
 * Only rendered when NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY is set, so these hooks
 * always have a <ClerkProvider> above them (see app/layout.tsx).
 */

type Step = 'credentials' | 'code';
type CodeKind = 'email' | 'totp';
type Provider = 'oauth_google' | 'oauth_github';

function messageOf(error: unknown, fallback: string) {
  if (!error) return fallback;
  const clerk = error as { longMessage?: string; message?: string; errors?: Array<{ longMessage?: string; message?: string }> };
  return clerk.errors?.[0]?.longMessage || clerk.errors?.[0]?.message || clerk.longMessage || clerk.message || fallback;
}

/** Clerk refuses a new sign-in while a session exists ("You're already signed in"). */
function isSessionExists(error: unknown) {
  const clerk = error as { code?: string; errors?: Array<{ code?: string }> } | null;
  return clerk?.code === 'session_exists' || clerk?.errors?.some((item) => item.code === 'session_exists') === true;
}

type Confirm = 'checking' | 'failed';

/**
 * Shown when Clerk already has a session in this browser. The app only lets
 * someone in once its own API accepts that session, so ask it, then continue;
 * if it refuses, say why instead of offering a form Clerk would reject.
 */
function SignedInPanel() {
  const router = useRouter();
  const { signOut } = useClerk();
  const { user } = useUser();
  const [state, setState] = React.useState<Confirm>('checking');
  const [attempt, setAttempt] = React.useState(0);
  const [leaving, setLeaving] = React.useState(false);

  React.useEffect(() => {
    let cancelled = false;
    const confirm = async () => {
      // A freshly minted session can take a moment to reach the server.
      for (let tries = 0; tries < 3 && !cancelled; tries += 1) {
        try {
          const response = await apiFetch('/api/auth/session', { cache: 'no-store' });
          const payload = (await response.json().catch(() => ({}))) as { ok?: boolean; user?: StoredAuthUser };
          if (response.ok && payload.ok && payload.user) {
            persistAuthSession(payload.user);
            if (!cancelled) router.replace(postLoginPath());
            return;
          }
        } catch {
          // network hiccup: retry below
        }
        await new Promise((resolve) => setTimeout(resolve, 900 * (tries + 1)));
      }
      if (!cancelled) setState('failed');
    };
    setState('checking');
    void confirm();
    return () => {
      cancelled = true;
    };
  }, [attempt, router]);

  const who = user?.primaryEmailAddress?.emailAddress || user?.username || user?.fullName || 'your account';

  if (state === 'checking') {
    return (
      <div className="flex flex-col items-center gap-3 py-6 text-center text-sm text-foreground/75" role="status">
        <Loader2 className="h-6 w-6 animate-spin text-primary" />
        <p>
          Signed in as <strong className="text-foreground">{who}</strong>. Opening the console…
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-chart-4/40 bg-chart-4/10 px-4 py-3 text-sm text-foreground/85">
        <p className="font-semibold text-foreground">You are signed in as {who}, but the console could not confirm the session.</p>
        <p className="mt-1.5 text-foreground/75">
          The most common cause is a computer clock that is a few seconds off. Turn on
          &ldquo;Set time automatically&rdquo; and press &ldquo;Sync now&rdquo; in Windows Settings → Time &amp; language,
          then try again.
        </p>
      </div>
      <Button type="button" className="h-11 w-full text-base" onClick={() => setAttempt((value) => value + 1)}>
        <RefreshCw className="mr-2 h-4 w-4" /> Try again
      </Button>
      <Button
        type="button"
        variant="outline"
        className="h-11 w-full text-base"
        disabled={leaving}
        onClick={() => {
          setLeaving(true);
          void signOut({ redirectUrl: '/login' });
        }}
      >
        {leaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <LogOut className="mr-2 h-4 w-4" />}
        Sign out and use another account
      </Button>
    </div>
  );
}

export function ClerkSignInPanel() {
  const { isLoaded, isSignedIn } = useAuth();
  if (!isLoaded) {
    return (
      <div className="flex justify-center py-8" role="status" aria-label="Loading sign-in">
        <Loader2 className="h-6 w-6 animate-spin text-primary" />
      </div>
    );
  }
  if (isSignedIn) return <SignedInPanel />;
  return <SignInForm />;
}

function SignInForm() {
  const router = useRouter();
  const { signIn, fetchStatus } = useSignIn();
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [code, setCode] = React.useState('');
  const [step, setStep] = React.useState<Step>('credentials');
  const [codeKind, setCodeKind] = React.useState<CodeKind>('email');
  const [busy, setBusy] = React.useState<'password' | 'code' | 'resend' | Provider | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);

  const finish = async () => {
    const { error: finalizeError } = await signIn.finalize({
      navigate: ({ session, decorateUrl }) => {
        // A pending session task (e.g. forced password reset) must be handled
        // before the app is usable; Clerk's hosted task pages do that.
        if (session?.currentTask) {
          setError(`Your account needs attention first: ${session.currentTask.key}. Complete it in the Clerk prompt.`);
          return;
        }
        go(decorateUrl(postLoginPath()), (path) => router.replace(path));
      },
    });
    if (finalizeError) setError(messageOf(finalizeError, 'Could not start your session.'));
  };

  /** Moves the flow forward based on what Clerk says it still needs. */
  const advance = async () => {
    switch (signIn.status) {
      case 'complete':
        await finish();
        return;
      case 'needs_client_trust': {
        // Clerk's device trust: a correct password from a new device is not
        // enough, the account owner confirms with an e-mailed code.
        const { error: sendError } = await signIn.mfa.sendEmailCode();
        if (sendError) throw sendError;
        setCodeKind('email');
        setStep('code');
        setNotice(`New device. We e-mailed a code to ${email || 'your address'}.`);
        return;
      }
      case 'needs_second_factor': {
        const factors = signIn.supportedSecondFactors.map((factor) => factor.strategy);
        if (factors.includes('totp')) {
          setCodeKind('totp');
          setStep('code');
          setNotice('Enter the 6-digit code from your authenticator app.');
          return;
        }
        if (factors.includes('email_code')) {
          const { error: sendError } = await signIn.mfa.sendEmailCode();
          if (sendError) throw sendError;
          setCodeKind('email');
          setStep('code');
          setNotice('We e-mailed you a verification code.');
          return;
        }
        setError('Your account uses a second factor this page does not support yet (phone or backup code).');
        return;
      }
      case 'needs_new_password':
        setError('A password reset is required for this account. Use "Forgot password" in the sign-up dialog.');
        return;
      default:
        setError('Additional verification is required. Try signing in with Google or GitHub.');
    }
  };

  const onPassword = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy('password');
    setError(null);
    setNotice(null);
    try {
      const { error: passwordError } = await signIn.password({ identifier: email.trim(), password });
      if (isSessionExists(passwordError)) {
        go(postLoginPath(), (path) => router.replace(path));
        return;
      }
      if (passwordError) {
        setError(messageOf(passwordError, 'Email or password is incorrect.'));
        return;
      }
      await advance();
    } catch (err) {
      setError(messageOf(err, 'Unable to sign in right now.'));
    } finally {
      setBusy(null);
    }
  };

  const onCode = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy('code');
    setError(null);
    try {
      const { error: verifyError } =
        codeKind === 'totp'
          ? await signIn.mfa.verifyTOTP({ code: code.trim() })
          : await signIn.mfa.verifyEmailCode({ code: code.trim() });
      if (verifyError) {
        setError(messageOf(verifyError, 'That code is not valid.'));
        return;
      }
      await advance();
    } catch (err) {
      setError(messageOf(err, 'Unable to verify the code.'));
    } finally {
      setBusy(null);
    }
  };

  const resend = async () => {
    setBusy('resend');
    setError(null);
    const { error: sendError } = await signIn.mfa.sendEmailCode();
    setBusy(null);
    if (sendError) setError(messageOf(sendError, 'Could not send a new code.'));
    else setNotice('A new code is on its way.');
  };

  const startOver = async () => {
    await signIn.reset();
    setStep('credentials');
    setCode('');
    setNotice(null);
    setError(null);
  };

  const onSocial = async (strategy: Provider) => {
    setBusy(strategy);
    setError(null);
    rememberPostLoginPath();
    const { error: ssoError } = await signIn.sso({
      strategy,
      // Where the provider sends the browser back; HandleSSOCallback finishes
      // the sign-in (or sign-up for a first-time Google/GitHub user) there.
      redirectCallbackUrl: '/sso-callback',
      redirectUrl: postLoginPath(),
    });
    // On success the browser is already leaving for the provider.
    if (isSessionExists(ssoError)) {
      go(postLoginPath(), (path) => router.replace(path));
      return;
    }
    if (ssoError) {
      setError(messageOf(ssoError, 'Unable to continue with social sign-in.'));
      setBusy(null);
    }
  };

  const loading = fetchStatus === 'fetching';

  if (step === 'code') {
    return (
      <form className="space-y-5" onSubmit={onCode}>
        <div className="flex items-start gap-2 rounded-lg border border-border/50 bg-muted/20 px-3 py-2.5 text-sm text-foreground/80">
          <MailCheck className="mt-0.5 h-4 w-4 shrink-0 text-chart-1" />
          <span>{notice}</span>
        </div>
        <div className="space-y-2">
          <label className="text-sm font-medium text-foreground" htmlFor="clerk-code">
            Verification code
          </label>
          <Input
            id="clerk-code"
            value={code}
            onChange={(event) => setCode(event.target.value.replace(/\s/g, ''))}
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            maxLength={8}
            required
            autoFocus
          />
        </div>
        {error && <p className="rounded-lg border border-chart-4/40 bg-chart-4/10 px-3 py-2 text-sm text-chart-4">{error}</p>}
        <Button type="submit" className="h-11 w-full bg-primary text-base hover:bg-primary/90" disabled={busy !== null || code.length < 6}>
          {busy === 'code' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
          Verify and sign in
        </Button>
        <div className="flex justify-between text-sm text-foreground/75">
          <button type="button" className="hover:underline" onClick={() => void startOver()}>
            Use a different account
          </button>
          {codeKind === 'email' && (
            <button type="button" className="hover:underline" onClick={() => void resend()} disabled={busy !== null}>
              {busy === 'resend' ? 'Sending…' : 'Resend code'}
            </button>
          )}
        </div>
      </form>
    );
  }

  return (
    <>
      <div className="space-y-3">
        <Button type="button" variant="outline" className="h-11 w-full text-base" onClick={() => void onSocial('oauth_google')} disabled={busy !== null || loading}>
          {busy === 'oauth_google' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <span className="mr-2 text-base font-semibold">G</span>}
          Continue with Google
        </Button>
        <Button type="button" variant="outline" className="h-11 w-full text-base" onClick={() => void onSocial('oauth_github')} disabled={busy !== null || loading}>
          {busy === 'oauth_github' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Github className="mr-2 h-4 w-4" />}
          Continue with GitHub
        </Button>
      </div>

      <div className="my-6 flex items-center gap-3 text-xs text-foreground/65">
        <div className="h-px flex-1 bg-border" />
        <span>OR CONTINUE WITH EMAIL</span>
        <div className="h-px flex-1 bg-border" />
      </div>

      <form className="space-y-5" onSubmit={onPassword}>
        <div className="space-y-2">
          <label className="text-sm font-medium text-foreground" htmlFor="clerk-email">
            Email
          </label>
          <div className="relative">
            <User2 className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground/40" />
            <Input id="clerk-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" placeholder="you@example.com" className="pl-9" required />
          </div>
        </div>
        <div className="space-y-2">
          <label className="text-sm font-medium text-foreground" htmlFor="clerk-password">
            Password
          </label>
          <div className="relative">
            <KeyRound className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground/40" />
            <Input id="clerk-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" placeholder="Your password" className="pl-9" required />
          </div>
        </div>
        {error && <p className="rounded-lg border border-chart-4/40 bg-chart-4/10 px-3 py-2 text-sm text-chart-4">{error}</p>}
        <Button type="submit" className="h-11 w-full bg-primary text-base hover:bg-primary/90" disabled={busy !== null || loading}>
          {busy === 'password' ? (
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
          New accounts start as viewers. An admin raises the role in Settings → Users, or sets
          <code className="mx-1">role</code>in the user&apos;s Clerk public metadata.
        </p>
      </div>

      <div className="mt-4 text-center text-sm text-foreground/75">
        Need an account?{' '}
        <SignUpButton mode="modal" forceRedirectUrl={postLoginPath()}>
          <button type="button" className="font-semibold text-[color:var(--app-link)] underline-offset-2 hover:underline">
            Sign up
          </button>
        </SignUpButton>
      </div>

      {/* Bot protection (Smart CAPTCHA) mounts here when Clerk asks for it. */}
      <div id="clerk-captcha" />
    </>
  );
}
