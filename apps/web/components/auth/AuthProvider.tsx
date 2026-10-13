import { ClerkProvider } from '@clerk/nextjs';

/**
 * Clerk's prebuilt pieces (sign-up dialog, UserButton menu) in the
 * ember/carbon palette, so they read as part of the console.
 */
const clerkAppearance = {
  // CSS variables, so the dialog follows the light/dark switch live.
  variables: {
    colorPrimary: '#ff2803',
    colorDanger: '#d42000',
    colorBackground: 'var(--card)',
    colorForeground: 'var(--foreground)',
    colorMutedForeground: 'var(--muted-foreground)',
    colorMuted: 'var(--muted)',
    colorInput: 'var(--input)',
    colorInputForeground: 'var(--foreground)',
    colorNeutral: 'var(--foreground)',
    colorBorder: 'var(--border)',
    borderRadius: '10px',
    fontFamily: 'var(--font-source-sans), system-ui, sans-serif',
  },
  // Clerk derives the footer shade from colorBackground with color-mix(),
  // which does not resolve a CSS variable, so the modal footer came out
  // transparent. Paint the card and footer explicitly.
  elements: {
    cardBox: { backgroundColor: 'var(--card)' },
    footer: { background: 'linear-gradient(var(--muted), var(--muted)), var(--card)' },
  },
} as const
/**
 * Clerk for the parts of the site that have accounts: /login, /sso-callback
 * and the console. Kept off the public landing page, which has no account UI.
 * Without a publishable key (local-account mode) it renders children as-is.
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  if (!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY) return <>{children}</>;
  return (
    <ClerkProvider
      // Our own pages, not Clerk's hosted Account Portal.
      signInUrl="/login"
      signUpUrl="/login"
      afterSignOutUrl="/login"
      signInFallbackRedirectUrl="/dashboard"
      signUpFallbackRedirectUrl="/dashboard"
      appearance={clerkAppearance}
    >
      {children}
    </ClerkProvider>
  );
}
