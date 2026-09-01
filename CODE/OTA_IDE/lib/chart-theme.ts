/**
 * Chart theme.
 *
 * Recharts writes most colors straight onto SVG presentation attributes
 * (`fill`, `stroke`), which do not resolve `var(--…)`. So the token values have
 * to exist here as literals. This module is the single place they live — before
 * it existed the same hexes were pasted across dashboard, diagnostics and
 * tcv-engine and drifted out of sync with the palette.
 *
 * These MUST stay equal to the `--chart-*` tokens in app/globals.css. The
 * semantic mapping is load-bearing across the app (Sidebar uses `bg-chart-1`
 * for Online and `bg-chart-4` for Offline; the login uses `text-chart-1` and
 * `text-chart-4`), so change a value here only alongside globals.css, and never
 * reorder the roles.
 */

/** Categorical ramp — matches `--chart-1` … `--chart-5`. */
export const chartColors = {
  /** success / online */
  success: '#34d399',
  /** informational / primary series */
  info: '#38bdf8',
  /** warning / updating / in-flight */
  warning: '#fbbf24',
  /** error / offline / failed */
  error: '#fb7185',
  /** supplementary series */
  accent: '#a78bfa',
} as const;

/** Positional alias for series that carry no semantic meaning. */
export const chartSeries = [
  chartColors.info,
  chartColors.accent,
  chartColors.warning,
  chartColors.success,
  chartColors.error,
] as const;

/** Neutral chrome — grid lines and axes on the slate ground. */
export const chartAxis = {
  grid: 'rgba(148,163,184,0.14)',
  stroke: 'rgba(148,163,184,0.55)',
  tick: { fontSize: '12px' },
} as const;

/**
 * Tooltip surface. Mirrors the `.glass` elevation primitive: slate-900 at high
 * opacity, hairline border, layered shadow, radius stepped down from
 * `--radius` (0.75rem) so it nests concentrically inside a card.
 */
export const chartTooltipStyle = {
  backgroundColor: 'rgba(15,23,42,0.94)',
  border: '1px solid rgba(148,163,184,0.24)',
  borderRadius: '0.625rem',
  boxShadow: '0 2px 4px rgba(2,6,23,0.45), 0 16px 40px -16px rgba(2,6,23,0.75)',
} as const;

/** Tooltip label color — `--foreground`. */
export const chartTooltipLabelStyle = {
  color: '#f8fafc',
} as const;
