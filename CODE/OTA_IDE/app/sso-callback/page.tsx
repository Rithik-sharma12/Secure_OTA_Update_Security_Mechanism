'use client';

import { useRouter } from 'next/navigation';
import { HandleSSOCallback } from '@clerk/nextjs';
import { go, recallPostLoginPath } from '@/lib/post-login';

/**
 * Google / GitHub return here. HandleSSOCallback finishes the sign-in — or,
 * for someone signing in with a provider for the first time, transfers it to
 * a sign-up — then calls one of these.
 */
export default function SsoCallbackPage() {
  const router = useRouter();
  return (
    <div className="flex min-h-svh items-center justify-center bg-background text-sm text-foreground/60">
      Finishing sign-in…
      <HandleSSOCallback
        navigateToApp={({ session, decorateUrl }) => {
          const destination = session?.currentTask ? '/login?task=1' : recallPostLoginPath();
          go(decorateUrl(destination), (path) => router.replace(path));
        }}
        navigateToSignIn={() => router.replace('/login?sso=more-info')}
        navigateToSignUp={() => router.replace('/login?sso=sign-up')}
      />
      <div id="clerk-captcha" />
    </div>
  );
}
