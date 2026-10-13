import type { Metadata, Viewport } from 'next'
import { Montserrat, Poppins, Source_Sans_3 } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
import { ThemeProvider } from '@/components/theme-provider'
import { ACCENT_BOOT_SCRIPT } from '@/lib/accent-config'
import { BASE_OPEN_GRAPH, SITE_DESCRIPTION, SITE_NAME, SITE_TITLE, SITE_URL } from '@/lib/site'
import './globals.css'

// Geist / Geist Mono were imported here but never applied (their classNames
// were unused), yet each still added a preloaded font file to every page.

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
  // Absolute URLs (canonical, Open Graph images) resolve against this.
  metadataBase: new URL(SITE_URL),
  title: {
    default: SITE_TITLE,
    template: `%s · ${SITE_NAME}`,
  },
  description: SITE_DESCRIPTION,
  applicationName: SITE_NAME,
  // No site-wide canonical: each indexable page declares its own, so private
  // and sign-in pages never point search engines at the home page.
  openGraph: {
    ...BASE_OPEN_GRAPH,
    title: SITE_TITLE,
    description: SITE_DESCRIPTION,
    url: '/',
    // app/opengraph-image.tsx supplies the image.
  },
  twitter: {
    card: 'summary_large_image',
    title: SITE_TITLE,
    description: SITE_DESCRIPTION,
  },
  formatDetection: { telephone: false, email: false, address: false },
  icons: {
    // Generated from pics/logo-secureota.png (transparent, trimmed).
    icon: [
      { url: '/favicon.ico', sizes: 'any' },
      { url: '/icon-48.png', type: 'image/png', sizes: '48x48' },
      { url: '/icon.png', type: 'image/png', sizes: '192x192' },
    ],
    apple: [{ url: '/apple-icon.png', sizes: '180x180' }],
  },
}

// themeColor belongs on the viewport export in the App Router; putting it in
// metadata is deprecated and warns at build time.
export const viewport: Viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#f6f4f1' },
    { media: '(prefers-color-scheme: dark)', color: '#0d0d0d' },
  ],
}


export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  const app = (
    <ThemeProvider
      attribute="class"
      themes={['light', 'dark']}
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
      storageKey="ota-ide-theme"
    >
      {children}
    </ThemeProvider>
  )

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Applies the saved colour theme and layout before first paint. */}
        <script dangerouslySetInnerHTML={{ __html: ACCENT_BOOT_SCRIPT }} />
      </head>
      <body
        className={`${montserrat.variable} ${sourceSans.variable} ${poppins.variable} min-h-svh overflow-x-hidden font-sans antialiased bg-background text-foreground`}
      >
        {/* Clerk is mounted by the layouts that need it (sign-in, SSO
            callback, console), not here: the public landing page has no
            account UI, and loading Clerk there cost ~200 KB of script. */}
        {app}
        {/* Vercel Analytics only works when hosted on Vercel. Self-hosted
            (Docker + Cloudflare tunnel) it requested /_vercel/insights/script.js
            on every page and got a 404 logged to the console. */}
        {process.env.NODE_ENV === 'production' && process.env.VERCEL === '1' && <Analytics />}
      </body>
    </html>
  )
}
