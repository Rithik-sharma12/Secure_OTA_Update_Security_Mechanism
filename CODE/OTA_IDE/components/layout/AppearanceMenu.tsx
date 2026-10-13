'use client';

import React from 'react';
import { useTheme } from 'next-themes';
import { Check, LayoutPanelTop, Monitor, Moon, Palette, Sun } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { ACCENTS, ACCENT_KEYS, useAccent, useConsoleLayoutMode, useSurfaceMode } from '@/lib/accent';
import { useGuidedMode } from '@/lib/use-guided-mode';

/**
 * One header button for everything visual: light/dark/system, the colour
 * theme, framed or full-width layout, and Guided/Dense density. Each choice
 * is saved in this browser and applies instantly.
 */

const MODES = [
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
  { value: 'system', label: 'System', Icon: Monitor },
] as const;

function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: ReadonlyArray<{ value: T; label: string; Icon?: React.ComponentType<{ className?: string }> }>;
  onChange: (value: T) => void;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="grid gap-1 rounded-xl p-1" style={{ gridTemplateColumns: `repeat(${options.length}, 1fr)`, background: 'var(--app-surface2)', border: '1px solid var(--app-line)' }}>
      {options.map(({ value: v, label: l, Icon }) => {
        const on = v === value;
        return (
          <button
            key={v}
            type="button"
            role="radio"
            aria-checked={on}
            onClick={() => onChange(v)}
            className="inline-flex min-h-[32px] items-center justify-center gap-1.5 rounded-lg px-2 text-xs font-semibold transition-colors"
            style={{
              background: on ? 'var(--app-inv-bg)' : 'transparent',
              color: on ? 'var(--app-inv-ink)' : 'var(--app-ink2)',
            }}
          >
            {Icon && <Icon className="h-3.5 w-3.5" />}
            {l}
          </button>
        );
      })}
    </div>
  );
}

export function AppearanceMenu() {
  const { theme, setTheme } = useTheme();
  const [accent, setAccent] = useAccent();
  const [layout, setLayout] = useConsoleLayoutMode();
  const [surface, setSurface] = useSurfaceMode();
  const [guided, setGuided] = useGuidedMode();
  const [mounted, setMounted] = React.useState(false);
  React.useEffect(() => setMounted(true), []);

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button type="button" className="ota-iconbtn gloss-iconbtn" aria-label="Appearance: theme, colours and layout" title="Appearance">
          <Palette className="h-[18px] w-[18px]" />
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="max-h-[80dvh] w-[min(320px,92vw)] space-y-4 overflow-y-auto p-4">
        <div className="space-y-2">
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Mode</p>
          {mounted && (
            <Segmented
              label="Colour mode"
              value={(theme as 'light' | 'dark' | 'system') ?? 'system'}
              options={MODES}
              onChange={(value) => setTheme(value)}
            />
          )}
        </div>

        <div className="space-y-2">
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Colour theme</p>
          <div role="radiogroup" aria-label="Colour theme" className="grid grid-cols-3 gap-2">
            {ACCENT_KEYS.map((key) => {
              const def = ACCENTS[key];
              const on = key === accent;
              return (
                <button
                  key={key}
                  type="button"
                  role="radio"
                  aria-checked={on}
                  onClick={() => setAccent(key)}
                  className="group flex flex-col items-center gap-1.5 rounded-xl p-2 text-[11px] font-medium transition-colors"
                  style={{
                    border: `1px solid ${on ? def.main : 'var(--app-line)'}`,
                    background: on ? `rgba(${def.mainRgb}, 0.12)` : 'transparent',
                    color: 'var(--app-ink)',
                  }}
                >
                  <span
                    className="relative flex h-7 w-7 items-center justify-center rounded-full"
                    style={{ background: `linear-gradient(135deg, ${def.second}, ${def.main})`, boxShadow: `0 0 14px -4px ${def.main}` }}
                  >
                    {on && <Check className="h-3.5 w-3.5" style={{ color: '#181818' }} />}
                  </span>
                  {def.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="space-y-2">
          <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            <LayoutPanelTop className="h-3.5 w-3.5" /> Layout
          </p>
          <Segmented
            label="Console layout"
            value={layout}
            options={[
              { value: 'framed', label: 'Framed' },
              { value: 'full', label: 'Full width' },
            ]}
            onChange={setLayout}
          />
          <Segmented
            label="Card surfaces"
            value={surface}
            options={[
              { value: 'glass', label: 'Glass' },
              { value: 'solid', label: 'Solid' },
            ]}
            onChange={setSurface}
          />
          <Segmented
            label="Console density"
            value={guided ? 'guided' : 'dense'}
            options={[
              { value: 'guided', label: 'Guided' },
              { value: 'dense', label: 'Dense' },
            ]}
            onChange={(value) => setGuided(value === 'guided')}
          />
        </div>
        <p className="text-[11px] leading-relaxed text-muted-foreground">
          Background animation, scene and strength are in Settings → Appearance.
        </p>
      </PopoverContent>
    </Popover>
  );
}
