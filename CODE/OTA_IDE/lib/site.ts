/**
 * Public identity of the site, used for metadata, canonical URLs, the
 * sitemap, robots.txt and structured data.
 *
 * SITE_URL is the canonical origin search engines should see. It comes from
 * NEXT_PUBLIC_SITE_URL (or OTA_DASHBOARD_PUBLIC_URL, which proxy.ts already
 * uses), and falls back to the hostname the Cloudflare tunnel publishes
 * (cloudflared/config.yml). Always https, never a trailing slash.
 */
function normalise(url: string) {
  const trimmed = url.trim().replace(/\/+$/, '');
  return trimmed.replace(/^http:\/\/(?!localhost|127\.0\.0\.1)/, 'https://');
}

export const SITE_URL = normalise(
  process.env.NEXT_PUBLIC_SITE_URL || process.env.OTA_DASHBOARD_PUBLIC_URL || 'https://ota.nyx-ctf.tech'
);

export const SITE_NAME = 'SecureOTA';

export const SITE_TITLE = 'SecureOTA: secure OTA firmware updates for ESP32 IoT fleets';

export const SITE_DESCRIPTION =
  'Flash ESP32 boards over USB from the browser, then ship signed, verified firmware updates over the internet. Every board checks the signature, reports each stage and rolls back on its own if a new build fails.';

/**
 * Who runs this deployment, for the Privacy Policy and Terms. Set these in
 * the environment before launch; the fallbacks keep the pages truthful
 * (the issue tracker is a real, public way to reach the team).
 */
export const LEGAL_ENTITY = process.env.NEXT_PUBLIC_LEGAL_ENTITY?.trim() || 'the SecureOTA project team';
export const CONTACT_EMAIL = process.env.NEXT_PUBLIC_CONTACT_EMAIL?.trim() || '';
export const GOVERNING_LAW = process.env.NEXT_PUBLIC_GOVERNING_LAW?.trim() || 'India';
/** Date the legal pages were last changed. Update it with any edit to them. */
export const LEGAL_LAST_UPDATED = '13 October 2026';

/** Public source code, linked from the landing page and structured data. */
export const SOURCE_REPOSITORY = 'https://github.com/Rithik-sharma12/Secure_OTA_Update_Security_Mechanism';

/** Pages that exist for signed-in operators only; never indexed. */
export const PRIVATE_PATH_PREFIXES = [
  '/dashboard',
  '/devices',
  '/event-logs',
  '/deployments',
  '/pipeline',
  '/releases',
  '/manifest',
  '/code',
  '/tcv-engine',
  '/ash-monitor',
  '/key-vault',
  '/audit',
  '/profile',
  '/settings',
  '/diagnostics',
  '/dead-letter',
  '/reports',
  '/simulator',
  '/examples',
  '/help',
  '/about',
  '/version',
  '/terminal',
  '/sso-callback',
] as const;

/**
 * Open Graph fields every page shares. Next.js replaces (does not merge) a
 * parent's openGraph object when a page sets its own, so pages spread this.
 */
export const BASE_OPEN_GRAPH = {
  type: 'website' as const,
  siteName: SITE_NAME,
  locale: 'en_US',
};
