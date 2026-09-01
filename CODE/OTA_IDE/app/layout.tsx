import type { Metadata, Viewport } from 'next'
import { Geist, Geist_Mono } from 'next/font/google'
import { Analytics } from '@vercel/analytics/next'
import { ThemeProvider } from '@/components/theme-provider'
import './globals.css'

const _geist = Geist({ subsets: ["latin"] });
const _geistMono = Geist_Mono({ subsets: ["latin"] });

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
      <body className="min-h-svh overflow-x-hidden font-sans antialiased bg-background text-foreground">
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={false} storageKey="ota-ide-theme">
          {children}
        </ThemeProvider>
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
