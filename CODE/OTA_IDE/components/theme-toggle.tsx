'use client';

import React from 'react';
import { useTheme } from 'next-themes';
import { Monitor, Moon, Sun } from 'lucide-react';

const OPTIONS = [
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
  { value: 'system', label: 'Match system', Icon: Monitor },
] as const;

/**
 * Light / dark / system switch.
 *
 * A three-way segmented control rather than a single toggle, so "follow my
 * OS" stays reachable after someone has picked a side. next-themes stores the
 * choice in localStorage and applies it before first paint (no flash).
 *
 * Renders a same-size placeholder until mounted: the server cannot know the
 * stored choice, and guessing would flash the wrong pressed state.
 */
export function ThemeToggle({ className = '', compact = false }: { className?: string; compact?: boolean }) {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = React.useState(false);
  React.useEffect(() => setMounted(true), []);

  return (
    <div
      role="radiogroup"
      aria-label="Colour theme"
      className={`inline-flex items-center gap-0.5 rounded-lg border p-0.5 ${className}`}
      style={{ borderColor: 'var(--app-line)', background: 'var(--app-surface2)' }}
    >
      {OPTIONS.map(({ value, label, Icon }) => {
        const active = mounted && theme === value;
        return (
          <button
            key={value}
            type="button"
            role="radio"
            aria-checked={active}
            aria-label={label}
            title={label}
            onClick={() => setTheme(value)}
            className="inline-flex items-center justify-center rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            style={{
              width: compact ? 28 : 32,
              height: compact ? 28 : 32,
              background: active ? 'var(--app-inv-bg)' : 'transparent',
              color: active ? 'var(--app-inv-ink)' : 'var(--app-ink2)',
            }}
          >
            <Icon size={compact ? 14 : 15} aria-hidden="true" />
          </button>
        );
      })}
    </div>
  );
}
