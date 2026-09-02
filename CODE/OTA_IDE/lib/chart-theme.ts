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
 *
 * The ember/carbon design system admits no hue outside its ramp, and encodes
 * status as ok -> neutral white, warn -> amber, error -> ember. There is
 * deliberately no green. The remaining series are separated by lightness
 * (bone -> mid neutral -> amber -> ember -> deep ember) so they stay
 * distinguishable under deuteranopia and protanopia; always pair them with a
 * non-color cue.
 */

/** Categorical ramp — matches `--chart-1` … `--chart-5`. */
export const chartColors = {
  /** success / online — neutral, per the design's ok state */
  success: '#f0f0ee',
  /** baseline / informational series */
  info: '#c9c6c1',
  /** warning / updating / in-flight */
  warning: '#ff9742',
  /** error / offline / failed */
  error: '#ff2803',
  /** supplementary series */
  accent: '#c02000',
} as const;

/** Positional alias for series that carry no semantic meaning. */
export const chartSeries = [
  chartColors.info,
  chartColors.warning,
  chartColors.success,
  chartColors.error,
  chartColors.accent,
] as const;

/** Neutral chrome — grid lines and axes, matching --app-line / --app-ink2. */
export const chartAxis = {
  grid: 'rgba(255,255,255,0.12)',
  stroke: 'rgba(255,255,255,0.72)',
  tick: { fontSize: '12px' },
} as const;

/**
 * Tooltip surface. Mirrors the design's card treatment: coal at high opacity,
 * the app hairline, the inset top highlight over a wide cast shadow, and a
 * radius stepped down from --radius (12px) so it nests concentrically.
 */
export const chartTooltipStyle = {
  backgroundColor: 'rgba(33,33,33,0.94)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: '10px',
  boxShadow: 'rgba(0,0,0,0.55) 0 24px 60px -20px, inset 0 1px 0 rgba(255,255,255,0.14)',
} as const;

/** Tooltip label color — --app-ink. */
export const chartTooltipLabelStyle = {
  color: '#ffffff',
} as const;
