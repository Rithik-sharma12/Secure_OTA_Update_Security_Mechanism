/**
 * Colour themes ("accents"). Light/dark is handled by next-themes; the
 * accent is a second, independent choice stored per browser and applied as
 * `data-accent` on <html>. app/themes.css holds the CSS for each one; the
 * values below are the same colours as literals for canvas and chart code,
 * which cannot read CSS variables. Server-safe (no hooks) so the root layout
 * can use the boot script.
 */

export type Accent = 'ember' | 'ocean' | 'emerald' | 'rose' | 'mono' | 'crimson' | 'sunset';

type AccentDef = {
  label: string;
  /** Main accent, secondary accent, deep accent (text/links on light). */
  main: string;
  second: string;
  deep: string;
  /** Same as rgb triplets, for rgba(). */
  mainRgb: string;
  secondRgb: string;
};

export const ACCENTS: Record<Accent, AccentDef> = {
  ember: { label: 'Ember', main: '#ff2803', second: '#ff9742', deep: '#c02000', mainRgb: '255, 40, 3', secondRgb: '255, 151, 66' },
  ocean: { label: 'Ocean', main: '#3b82f6', second: '#22d3ee', deep: '#1d4ed8', mainRgb: '59, 130, 246', secondRgb: '34, 211, 238' },
  emerald: { label: 'Emerald', main: '#10b981', second: '#a3e635', deep: '#047857', mainRgb: '16, 185, 129', secondRgb: '163, 230, 53' },
  rose: { label: 'Rose', main: '#f43f5e', second: '#fb923c', deep: '#be123c', mainRgb: '244, 63, 94', secondRgb: '251, 146, 60' },
  mono: { label: 'Graphite', main: '#e5e5e5', second: '#a3a3a3', deep: '#404040', mainRgb: '229, 229, 229', secondRgb: '163, 163, 163' },
  crimson: { label: 'Crimson', main: '#e60023', second: '#ff6b81', deep: '#b8001c', mainRgb: '230, 0, 35', secondRgb: '255, 107, 129' },
  sunset: { label: 'Sunset', main: '#f97316', second: '#f59e0b', deep: '#c2410c', mainRgb: '249, 115, 22', secondRgb: '245, 158, 11' },
};

export const ACCENT_KEYS = Object.keys(ACCENTS) as Accent[];
export const ACCENT_STORAGE_KEY = 'ota-accent';

/**
 * Inline script for <head>: applies the stored accent and layout before the
 * first paint, so a themed console never flashes the default colour.
 * Retired themes (for example violet and indigo) fail the pattern below and
 * fall back to the default. Kept tiny and
 * dependency-free; it only reads localStorage and sets data attributes.
 */
export const ACCENT_BOOT_SCRIPT = `(function(){try{var a=localStorage.getItem('${ACCENT_STORAGE_KEY}');if(a&&/^(${ACCENT_KEYS.join('|')})$/.test(a))document.documentElement.dataset.accent=a;var l=localStorage.getItem('ota-layout');if(l==='full'||l==='framed')document.documentElement.dataset.layout=l;var s=localStorage.getItem('ota-surface');if(s==='solid'||s==='glass')document.documentElement.dataset.surface=s;}catch(e){}})();`;

