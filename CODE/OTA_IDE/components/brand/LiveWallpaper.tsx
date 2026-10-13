'use client';

import React from 'react';
import { useTheme } from 'next-themes';
import { whenPageIdle } from '@/components/landing/motion';
import { PALETTES, SCENE_ORDER, createScene, paletteFromAccent, type Palette, type Scene, type SceneName } from './wallpaper-scenes';
import { ACCENTS, useAccent } from '@/lib/accent';

/**
 * "Live wallpaper": a moving background drawn in code. Four scenes, inspired
 * by the reference clips but original artwork:
 *
 *   warp    — stars rushing past as light streaks (hyperspace tunnel)
 *   globe   — a dotted planet with data arcs travelling between hubs
 *   network — drifting nodes joining up, sparks running along the links
 *   trails  — glowing energy streaks sweeping across
 *
 * "Cycle" (the default) cross-fades from one scene to the next every ~24 s,
 * like a live wallpaper. A soft aurora always sits underneath. Colours come
 * in Ember (the brand) or Cyber blue (closer to the references).
 *
 * Kept efficient: reduced resolution, ~30 fps, pauses when the tab is hidden
 * or the layer is off-screen, and a single still frame for visitors whose
 * system asks to reduce motion. Everything is a per-browser choice in
 * Settings → Appearance.
 */

const EVENT = 'ota-live-wallpaper-change';
const KEYS = {
  enabled: 'ota-live-wallpaper',
  strength: 'ota-live-wallpaper-strength',
  style: 'ota-live-wallpaper-style',
  color: 'ota-live-wallpaper-color',
} as const;

/** A tiny per-browser setting that every wallpaper on the page listens to. */
function useStoredChoice<T extends string>(key: string, allowed: readonly T[], fallback: T): [T, (value: T) => void] {
  const [value, setValue] = React.useState<T>(fallback);
  React.useEffect(() => {
    const read = () => {
      try {
        const stored = window.localStorage.getItem(key) as T | null;
        setValue(stored && allowed.includes(stored) ? stored : fallback);
      } catch {
        setValue(fallback);
      }
    };
    read();
    window.addEventListener(EVENT, read);
    window.addEventListener('storage', read);
    return () => {
      window.removeEventListener(EVENT, read);
      window.removeEventListener('storage', read);
    };
    // allowed is a module constant at every call site
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, fallback]);
  const update = React.useCallback(
    (next: T) => {
      try {
        window.localStorage.setItem(key, next);
      } catch {
        /* storage unavailable: applies to this page only */
      }
      setValue(next);
      window.dispatchEvent(new Event(EVENT));
    },
    [key]
  );
  return [value, update];
}

const ON_OFF = ['on', 'off'] as const;

/** On/off switch, shared by every wallpaper on the page. */
export function useLiveWallpaper(): [boolean, (on: boolean) => void] {
  const [value, setValue] = useStoredChoice(KEYS.enabled, ON_OFF, 'on');
  return [value !== 'off', React.useCallback((on: boolean) => setValue(on ? 'on' : 'off'), [setValue])];
}

export type WallpaperStrength = 'subtle' | 'medium' | 'strong';
/** Opacity per strength on console pages. Cards stay solid at every level. */
export const WALLPAPER_STRENGTH: Record<WallpaperStrength, { label: string; opacity: number }> = {
  subtle: { label: 'Subtle', opacity: 0.18 },
  medium: { label: 'Medium', opacity: 0.38 },
  strong: { label: 'Strong', opacity: 0.7 },
};
const STRENGTHS = Object.keys(WALLPAPER_STRENGTH) as WallpaperStrength[];
export function useWallpaperStrength() {
  return useStoredChoice<WallpaperStrength>(KEYS.strength, STRENGTHS, 'medium');
}

export type WallpaperStyle = 'cycle' | SceneName | 'orbs' | 'video';
export const WALLPAPER_STYLES: Record<WallpaperStyle, string> = {
  cycle: 'Cycle all',
  warp: 'Hyperspace',
  globe: 'Globe',
  network: 'Network',
  trails: 'Energy trails',
  orbs: 'Glass orbs',
  video: 'Your video',
};

/**
 * Your own background clip. Drop files with these exact names into
 * CODE/OTA_IDE/public/backgrounds/ (see the README there):
 *   loop.webm  VP9/AV1, preferred   loop.mp4  H.264 fallback   loop.jpg  still poster
 */
export const VIDEO_SOURCES = [
  { src: '/backgrounds/loop.webm', type: 'video/webm' },
  { src: '/backgrounds/loop.mp4', type: 'video/mp4' },
] as const;
export const VIDEO_POSTER = '/backgrounds/loop.jpg';

/** Which of the video files exist (checked once per page with HEAD requests). */
export function useBackgroundVideo() {
  const [state, setState] = React.useState<{ sources: Array<{ src: string; type: string }>; poster: string | null } | null>(null);
  React.useEffect(() => {
    let cancelled = false;
    const exists = (url: string) =>
      fetch(url, { method: 'HEAD', cache: 'force-cache' })
        .then((res) => res.ok)
        .catch(() => false);
    Promise.all([...VIDEO_SOURCES.map((v) => exists(v.src)), exists(VIDEO_POSTER)]).then((found) => {
      if (cancelled) return;
      setState({
        sources: VIDEO_SOURCES.filter((_, i) => found[i]).map((v) => ({ ...v })),
        poster: found[VIDEO_SOURCES.length] ? VIDEO_POSTER : null,
      });
    });
    return () => {
      cancelled = true;
    };
  }, []);
  return state;
}
const STYLES = Object.keys(WALLPAPER_STYLES) as WallpaperStyle[];
export function useWallpaperStyle() {
  return useStoredChoice<WallpaperStyle>(KEYS.style, STYLES, 'cycle');
}

export type WallpaperColor = 'theme' | 'ember' | 'cyber';
export const WALLPAPER_COLORS: Record<WallpaperColor, string> = { theme: 'Match theme', ember: 'Ember', cyber: 'Cyber blue' };
const COLORS = Object.keys(WALLPAPER_COLORS) as WallpaperColor[];
export function useWallpaperColor() {
  return useStoredChoice<WallpaperColor>(KEYS.color, COLORS, 'theme');
}

// ── Canvas ────────────────────────────────────────────────────────────────

const SCENE_MS = 24000;
const FADE_MS = 2500;


export function LiveWallpaper({
  intensity = 0.25,
  tone = 'auto',
  fixed = false,
  density = 1,
  zIndex = 0,
  style,
  color,
  className = '',
}: {
  /** Opacity of the whole layer, 0–1. */
  intensity?: number;
  /** 'dark' keeps the dark palette regardless of theme (for dark panels). */
  tone?: 'auto' | 'dark';
  /** Cover the viewport (position: fixed) instead of the parent element. */
  fixed?: boolean;
  /** Scales how many stars, dots and nodes are drawn. */
  density?: number;
  zIndex?: number;
  /** Scene to show; defaults to the visitor's choice (cycle). */
  style?: WallpaperStyle;
  /** Palette; defaults to the visitor's choice (ember). */
  color?: WallpaperColor;
  className?: string;
}) {
  const canvasRef = React.useRef<HTMLCanvasElement>(null);
  const { resolvedTheme } = useTheme();
  const [chosenStyle] = useWallpaperStyle();
  const [chosenColor] = useWallpaperColor();
  const [accent] = useAccent();
  // Theme, accent and scene come from this browser's storage, which the
  // server can't see: render the (purely decorative) layers after mount so
  // the server HTML and the first client render always match.
  const [mounted, setMounted] = React.useState(false);
  React.useEffect(() => setMounted(true), []);
  const light = tone === 'auto' && resolvedTheme === 'light';
  const requested = style ?? chosenStyle;
  const video = useBackgroundVideo();
  const wantsVideo = requested === 'video';
  const videoReady = wantsVideo && video !== null && video.sources.length > 0;
  // "Your video" with no files falls back to the animated scenes.
  const orbs = requested === 'orbs';
  const sceneChoice: 'cycle' | SceneName = requested === 'video' || requested === 'orbs' ? 'cycle' : requested;
  const colorChoice = color ?? chosenColor;
  const reducedMotion =
    typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

  React.useEffect(() => {
    if (videoReady || orbs) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const accentDef = ACCENTS[accent];
    const palette: Palette =
      colorChoice === 'theme'
        ? accent === 'ember'
          ? PALETTES.ember[light ? 'light' : 'dark']
          : paletteFromAccent(accentDef.main, accentDef.second, accentDef.deep, light)
        : PALETTES[colorChoice][light ? 'light' : 'dark'];
    // Data-saver users and reduced-motion users get one still frame. Smaller
    // devices get fewer particles and a lower frame rate.
    const nav = navigator as Navigator & { deviceMemory?: number; connection?: { saveData?: boolean } };
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches || Boolean(nav.connection?.saveData);
    const lowEnd = (nav.hardwareConcurrency || 8) <= 4 || (nav.deviceMemory ?? 8) <= 4;
    const frameMs = lowEnd ? 50 : 33;
    const sceneDensity = lowEnd ? density * 0.6 : density;
    // Soft shapes do not need full resolution.
    const SCALE = Math.min(window.devicePixelRatio || 1, 1.5) * 0.65;

    const order: SceneName[] = sceneChoice === 'cycle' ? SCENE_ORDER : [sceneChoice];
    const scenes = new Map<SceneName, Scene>();
    const sceneFor = (name: SceneName) => {
      let scene = scenes.get(name);
      if (!scene) {
        scene = createScene(name, palette, sceneDensity);
        scene.resize(width, height);
        scenes.set(name, scene);
      }
      return scene;
    };

    let width = 0;
    let height = 0;
    let frame = 0;
    let visible = true;
    let lastDraw = 0;
    let clock = 0; // ms of animation time actually shown (pauses with the tab)
    const pointer = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5 };

    const layout = () => {
      const host = fixed ? null : canvas.parentElement;
      width = fixed ? window.innerWidth : host?.clientWidth || 0;
      height = fixed ? window.innerHeight : host?.clientHeight || 0;
      canvas.width = Math.max(1, Math.round(width * SCALE));
      canvas.height = Math.max(1, Math.round(height * SCALE));
      ctx.setTransform(SCALE, 0, 0, SCALE, 0, 0);
      scenes.forEach((scene) => scene.resize(width, height));
    };

    const draw = (dt: number) => {
      clock += dt;
      pointer.x += (pointer.tx - pointer.x) * 0.04;
      pointer.y += (pointer.ty - pointer.y) * 0.04;

      ctx.globalCompositeOperation = 'source-over';
      ctx.globalAlpha = 1;
      ctx.clearRect(0, 0, width, height);

      // Which scene, and are we mid cross-fade into the next one?
      const slot = Math.floor(clock / SCENE_MS);
      const into = clock - slot * SCENE_MS;
      const current = order[slot % order.length];
      const next = order[(slot + 1) % order.length];
      const fading = order.length > 1 && into > SCENE_MS - FADE_MS;
      const mix = fading ? (into - (SCENE_MS - FADE_MS)) / FADE_MS : 0;

      ctx.globalCompositeOperation = palette.light ? 'source-over' : 'lighter';
      ctx.globalAlpha = 1 - mix;
      sceneFor(current).draw(ctx, dt, clock, pointer);
      if (fading) {
        ctx.globalAlpha = mix;
        sceneFor(next).draw(ctx, dt, clock, pointer);
      }
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = 'source-over';
    };

    const loop = (now: number) => {
      frame = requestAnimationFrame(loop);
      if (now - lastDraw < frameMs) return; // ~30 fps, ~20 on small devices
      const dt = Math.min(80, lastDraw ? now - lastDraw : 16);
      lastDraw = now;
      draw(dt);
    };

    const start = () => {
      cancelAnimationFrame(frame);
      if (reduced) {
        // One composed still: advance the scene a little so it is not empty.
        for (let i = 0; i < 40; i += 1) draw(33);
      } else if (visible && !document.hidden) {
        lastDraw = 0;
        frame = requestAnimationFrame(loop);
      }
    };

    // Decorative: start only after the page has loaded and gone idle, so it
    // never delays the first paint or the first click.
    let started = false;
    const cancelIdle = whenPageIdle(() => {
      started = true;
      layout();
      start();
    });

    const onResize = () => {
      if (!started) return;
      layout();
      start();
    };
    const resize = new ResizeObserver(onResize);
    if (!fixed && canvas.parentElement) resize.observe(canvas.parentElement);
    if (fixed) window.addEventListener('resize', onResize);
    const io = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      if (started) start();
    });
    io.observe(canvas);
    const onVisibility = () => started && start();
    document.addEventListener('visibilitychange', onVisibility);
    // The scenes accept a pointer position, but it stays centred: nothing on
    // the page follows the cursor.

    return () => {
      cancelIdle();
      cancelAnimationFrame(frame);
      resize.disconnect();
      io.disconnect();
      window.removeEventListener('resize', onResize);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [mounted, light, fixed, density, sceneChoice, colorChoice, accent, videoReady, orbs]);

  // The soft aurora glows are plain CSS gradients moved with transforms: the
  // compositor animates them on the GPU for free. Drawing them on the canvas
  // meant four full-screen gradient fills per frame, the costliest part.
  if (!mounted) return null;
  const glowColors =
    colorChoice === 'theme' && accent !== 'ember'
      ? paletteFromAccent(ACCENTS[accent].main, ACCENTS[accent].second, ACCENTS[accent].deep, light).glows
      : PALETTES[colorChoice === 'theme' ? 'ember' : colorChoice][light ? 'light' : 'dark'].glows;
  const layer: React.CSSProperties = {
    position: fixed ? 'fixed' : 'absolute',
    inset: 0,
    width: '100%',
    height: '100%',
    pointerEvents: 'none',
    opacity: intensity,
    zIndex,
  };
  return (
    <>
      <div
        aria-hidden="true"
        className={`ota-aurora ${light ? 'ota-aurora-light' : ''}`}
        style={{
          ...layer,
          ['--g1' as string]: glowColors[0],
          ['--g2' as string]: glowColors[1],
          ['--g3' as string]: glowColors[2],
          ['--g4' as string]: glowColors[3],
        }}
      >
        <span />
        <span />
        <span />
        <span />
      </div>
      {orbs ? (
        // Glossy glass spheres drifting slowly (pure CSS, GPU-composited).
        <div aria-hidden="true" className={`ota-orbs ${light ? 'ota-orbs-light' : ''} ${className}`} style={layer}>
          {Array.from({ length: 7 }, (_, i) => (
            <span key={i} />
          ))}
        </div>
      ) : videoReady ? (
        reducedMotion && video?.poster ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={video.poster} alt="" aria-hidden="true" className={className} style={{ ...layer, objectFit: 'cover' }} />
        ) : (
          <video
            key={video!.sources.map((v) => v.src).join()}
            aria-hidden="true"
            className={className}
            style={{ ...layer, objectFit: 'cover' }}
            autoPlay={!reducedMotion}
            muted
            loop
            playsInline
            preload="metadata"
            poster={video?.poster ?? undefined}
          >
            {video!.sources.map((source) => (
              <source key={source.src} src={source.src} type={source.type} />
            ))}
          </video>
        )
      ) : (
        <canvas ref={canvasRef} aria-hidden="true" className={className} style={layer} />
      )}
    </>
  );
}

/** The wallpaper, unless this browser switched it off in Settings. */
export function AmbientWallpaper(props: React.ComponentProps<typeof LiveWallpaper>) {
  const [enabled] = useLiveWallpaper();
  return enabled ? <LiveWallpaper {...props} /> : null;
}

/** Console background: follows the on/off switch, strength, style and colour. */
export function ConsoleWallpaper() {
  const [enabled] = useLiveWallpaper();
  const [strength] = useWallpaperStrength();
  if (!enabled) return null;
  return <LiveWallpaper fixed intensity={WALLPAPER_STRENGTH[strength].opacity} density={0.8} />;
}
