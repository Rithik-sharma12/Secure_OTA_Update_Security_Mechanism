import type { MetadataRoute } from 'next';
import { SITE_URL } from '@/lib/site';

/**
 * Crawl rules. The landing page is the only public content. Console pages
 * are not disallowed here on purpose: they send signed-out visitors to the
 * sign-in page and carry `noindex`, and a crawler must be able to fetch a
 * page to see its noindex. API routes return JSON for the app, not pages.
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: '*', allow: '/', disallow: ['/api/'] }],
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}
