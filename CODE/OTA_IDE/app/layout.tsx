import type { Metadata, Viewport } from 'next'
import { Geist, Geist_Mono, Montserrat, Poppins, Source_Sans_3 } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
import { ClerkProvider } from '@clerk/nextjs'
import { ThemeProvider } from '@/components/theme-provider'
import './globals.css'

const _geist = Geist({ subsets: ["latin"] });
const _geistMono = Geist_Mono({ subsets: ["latin"] });

// Ember/carbon design system faces. Montserrat carries display and UI-caps,
// Source Sans 3 the body, Poppins the `secureota` wordmark. Exposed as CSS
// variables that app/design-system.css reads via --font-display / --font-ui /
// --font-brand. Only the weights the type scale actually uses are requested.
const montserrat = Montserrat({
  subsets: ['latin'],
  weight: ['600', '700'],
  variable: '--font-montserrat',
  display: 'swap',
});
const sourceSans = Source_Sans_3({
  subsets: ['latin'],
  weight: ['400', '600'],
  variable: '--font-source-sans',
  display: 'swap',
});
const poppins = Poppins({
  subsets: ['latin'],
  weight: ['600'],
  variable: '--font-poppins',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'SECUREOTA: A SECURE HETEROGENEOUS OTA UPDATE MECHANISM FOR RESOURCE-CONSTRAINED IOT DEVICES',
  description: 'Secure OTA firmware delivery for heterogeneous IoT device fleets',
  icons: {
    // Only /icon.svg is referenced. The previous entries pointed at
    // /icon-light-32x32.png, /icon-dark-32x32.png and /apple-icon.png, none of
    // which exist in public/ — every tab requested three 404s and fell back to
    // a blank favicon. Add the raster variants back here when the files exist.
    icon: [
      {
        url: '/icon.svg',
        type: 'image/svg+xml',
      },
    ],
  },
}

// themeColor belongs on the viewport export in the App Router; putting it in
// metadata is deprecated and warns at build time.
export const viewport: Viewport = {
  themeColor: '#020617',
}

/**
 * Clerk's prebuilt pieces (sign-up dialog, UserButton menu) in the
 * ember/carbon palette, so they read as part of the console.
 */
const clerkAppearance = {
  variables: {
    colorPrimary: '#ff2803',
    colorDanger: '#ff2803',
    colorBackground: '#181818',
    colorForeground: '#ffffff',
    colorMutedForeground: 'rgba(255,255,255,0.72)',
    colorMuted: '#212121',
    colorInput: '#0d0d0d',
    colorInputForeground: '#ffffff',
    colorNeutral: '#f0f0ee',
    colorBorder: 'rgba(255,255,255,0.12)',
    borderRadius: '10px',
    fontFamily: 'var(--font-source-sans), system-ui, sans-serif',
  },
} as const

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  const app = (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} storageKey="ota-ide-theme">
      {children}
    </ThemeProvider>
  )

  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${montserrat.variable} ${sourceSans.variable} ${poppins.variable} min-h-svh overflow-x-hidden font-sans antialiased bg-background text-foreground`}
      >
        {process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ? (
          <ClerkProvider
            // Our own pages, not Clerk's hosted Account Portal.
            signInUrl="/login"
            signUpUrl="/login"
            afterSignOutUrl="/login"
            signInFallbackRedirectUrl="/dashboard"
            signUpFallbackRedirectUrl="/dashboard"
            appearance={clerkAppearance}
          >
            {app}
          </ClerkProvider>
        ) : (
          app
        )}
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
