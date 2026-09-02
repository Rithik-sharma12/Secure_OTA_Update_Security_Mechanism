import type { Metadata, Viewport } from 'next'
import { Geist, Geist_Mono, Montserrat, Poppins, Source_Sans_3 } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
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
  title: 'SecureOTA — Firmware Management Control Center',
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

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${montserrat.variable} ${sourceSans.variable} ${poppins.variable} min-h-svh overflow-x-hidden font-sans antialiased bg-background text-foreground`}
      >
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} storageKey="ota-ide-theme">
          {children}
        </ThemeProvider>
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
