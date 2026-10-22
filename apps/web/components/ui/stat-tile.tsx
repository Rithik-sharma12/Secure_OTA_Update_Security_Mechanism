import React from 'react';
import { cn } from '@/lib/utils';

/**
 * One summary number, the same way on every page:
 *
 *   [icon] LABEL
 *   42            <- the value, large and tabular
 *   short hint    <- what the number means or what to do
 *
 * Tone is carried by a 3px rule on the left edge and the icon colour, never
 * by a tinted block behind the number, and always paired with the label so
 * colour is not the only cue. Tones map to the theme's semantic chart roles:
 * good = chart-1, warn = chart-3, bad = chart-4.
 */

export type StatTone = 'neutral' | 'good' | 'warn' | 'bad';

const TONE_RULE: Record<StatTone, string> = {
  neutral: 'before:bg-border',
  good: 'before:bg-chart-1',
  warn: 'before:bg-chart-3',
  bad: 'before:bg-chart-4',
};

const TONE_TEXT: Record<StatTone, string> = {
  neutral: 'text-muted-foreground',
  good: 'text-chart-1',
  warn: 'text-chart-3',
  bad: 'text-chart-4',
};

export type StatTileProps = {
  label: string;
  value: React.ReactNode;
  /** Small text after the value, for example a unit or "of 12". */
  suffix?: React.ReactNode;
  hint?: React.ReactNode;
  icon?: React.ComponentType<{ className?: string }>;
  tone?: StatTone;
  className?: string;
};

export function StatTile({ label, value, suffix, hint, icon: Icon, tone = 'neutral', className }: StatTileProps) {
  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-lg border border-border/60 bg-card/70 px-4 py-3.5',
        "before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:content-['']",
        TONE_RULE[tone],
        className
      )}
    >
      <div className="flex items-center gap-2">
        {Icon && <Icon className={cn('h-4 w-4 shrink-0', TONE_TEXT[tone])} />}
        <p className="truncate text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
      </div>
      <p className="mt-2 flex items-baseline gap-1.5">
        <span className="text-2xl font-semibold tabular-nums leading-none text-foreground">{value}</span>
        {suffix && <span className="text-sm text-muted-foreground">{suffix}</span>}
      </p>
      {hint && <p className="mt-1.5 truncate text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

/** Responsive row of tiles: 2 across on phones, up to `columns` on wide screens. */
export function StatGrid({
  columns = 4,
  className,
  children,
}: {
  columns?: 2 | 3 | 4 | 5 | 6;
  className?: string;
  children: React.ReactNode;
}) {
  const wide = {
    2: 'sm:grid-cols-2',
    3: 'sm:grid-cols-3',
    4: 'sm:grid-cols-2 lg:grid-cols-4',
    5: 'sm:grid-cols-3 lg:grid-cols-5',
    6: 'sm:grid-cols-3 lg:grid-cols-6',
  }[columns];
  return <div className={cn('grid grid-cols-2 gap-3', wide, className)}>{children}</div>;
}
