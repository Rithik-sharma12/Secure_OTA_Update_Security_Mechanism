import type { MetadataRoute } from 'next';
import { SITE_URL } from '@/lib/site';

/**
 * Only canonical, public, indexable URLs: the landing page and the two legal
 * pages. The sign-in page is noindex and everything else needs an account.
 */
export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: `${SITE_URL}/`,
      changeFrequency: 'weekly',
      priority: 1,
    },
    { url: `${SITE_URL}/privacy`, changeFrequency: 'yearly', priority: 0.3 },
    { url: `${SITE_URL}/terms`, changeFrequency: 'yearly', priority: 0.3 },
  ];
}
