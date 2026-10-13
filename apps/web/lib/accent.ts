'use client';

import React from 'react';

import { ACCENTS, ACCENT_STORAGE_KEY, type Accent } from '@/lib/accent-config';

export { ACCENTS, ACCENT_KEYS, type Accent } from '@/lib/accent-config';

const EVENT = 'ota-accent-change';

export function readAccent(): Accent {
  try {
    const stored = window.localStorage.getItem(ACCENT_STORAGE_KEY) as Accent | null;
    if (stored && stored in ACCENTS) return stored;
  } catch {
    /* storage unavailable */
  }
  return 'ember';
}

/** Current accent, kept in sync across components and tabs. */
export function useAccent(): [Accent, (accent: Accent) => void] {
  const [accent, setAccentState] = React.useState<Accent>('ember');
  React.useEffect(() => {
    const read = () => setAccentState(readAccent());
    read();
    window.addEventListener(EVENT, read);
    window.addEventListener('storage', read);
    return () => {
      window.removeEventListener(EVENT, read);
      window.removeEventListener('storage', read);
    };
  }, []);
  const setAccent = React.useCallback((next: Accent) => {
    try {
      window.localStorage.setItem(ACCENT_STORAGE_KEY, next);
    } catch {
      /* this page only */
    }
    document.documentElement.dataset.accent = next;
    setAccentState(next);
    window.dispatchEvent(new Event(EVENT));
  }, []);
  return [accent, setAccent];
}

// ── Console layout (framed card vs full width) ────────────────────────────

export type ConsoleLayoutMode = 'framed' | 'full';
const LAYOUT_KEY = 'ota-layout';

export function useConsoleLayoutMode(): [ConsoleLayoutMode, (mode: ConsoleLayoutMode) => void] {
  const [mode, setModeState] = React.useState<ConsoleLayoutMode>('framed');
  React.useEffect(() => {
    const read = () => {
      try {
        setModeState(window.localStorage.getItem(LAYOUT_KEY) === 'full' ? 'full' : 'framed');
      } catch {
        setModeState('framed');
      }
    };
    read();
    window.addEventListener(EVENT, read);
    return () => window.removeEventListener(EVENT, read);
  }, []);
  const setMode = React.useCallback((next: ConsoleLayoutMode) => {
    try {
      window.localStorage.setItem(LAYOUT_KEY, next);
    } catch {
      /* this page only */
    }
    document.documentElement.dataset.layout = next;
    setModeState(next);
    window.dispatchEvent(new Event(EVENT));
  }, []);
  return [mode, setMode];
}

// ── Surfaces (frosted glass or solid) ─────────────────────────────────────

export type SurfaceMode = 'glass' | 'solid';
const SURFACE_KEY = 'ota-surface';

/** Frosted-glass cards (default) or solid ones: easier on slow GPUs and for reading. */
export function useSurfaceMode(): [SurfaceMode, (mode: SurfaceMode) => void] {
  const [mode, setModeState] = React.useState<SurfaceMode>('glass');
  React.useEffect(() => {
    const read = () => {
      try {
        setModeState(window.localStorage.getItem(SURFACE_KEY) === 'solid' ? 'solid' : 'glass');
      } catch {
        setModeState('glass');
      }
    };
    read();
    window.addEventListener(EVENT, read);
    return () => window.removeEventListener(EVENT, read);
  }, []);
  const setMode = React.useCallback((next: SurfaceMode) => {
    try {
      window.localStorage.setItem(SURFACE_KEY, next);
    } catch {
      /* this page only */
    }
    document.documentElement.dataset.surface = next;
    setModeState(next);
    window.dispatchEvent(new Event(EVENT));
  }, []);
  return [mode, setMode];
}
