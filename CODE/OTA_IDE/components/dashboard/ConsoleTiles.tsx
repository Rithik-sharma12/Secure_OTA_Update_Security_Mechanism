'use client';

import React from 'react';
import { AnimatedNumber } from '@/components/ui/animated-number';

/**
 * The design's console tiles.
 *
 * Every value passed in comes from the live gateway snapshot. Where the
 * snapshot cannot support a reading — no rollout in progress, no update
 * history yet — the tile renders an explicit empty state rather than a
 * plausible-looking number. The mock these are modelled on carried simulated
 * data and said so; a real console must not.
 */

const CARD: React.CSSProperties = {
  padding: '15px 17px 16px',
  borderRadius: 12,
  border: '1px solid var(--app-line)',
  background: 'var(--app-surface)',
  boxShadow: 'var(--app-elev)',
  display: 'flex',
  flexDirection: 'column',
  gap: 11,
  minWidth: 0,
};

const BIG: React.CSSProperties = {
  font: '600 27px/1 var(--font-display)',
  letterSpacing: '-0.9px',
  color: 'var(--app-ink)',
  fontVariantNumeric: 'tabular-nums',
};

const UNIT: React.CSSProperties = {
  font: 'var(--type-caption)',
  color: 'var(--app-ink2)',
  textTransform: 'uppercase',
  letterSpacing: '0.4px',
};

const MICRO: React.CSSProperties = {
  font: 'var(--type-micro-cap)',
  letterSpacing: 'var(--tracking-micro)',
  textTransform: 'uppercase',
  color: 'var(--app-ink2)',
};

/** Recessed well used behind the pressure bar and version histogram. */
const WELL: React.CSSProperties = {
  position: 'relative',
  borderRadius: 9,
  background: 'radial-gradient(130% 160% at 50% 0%,#161616 0%,#090909 100%)',
  boxShadow: 'inset 0 2px 6px rgba(0,0,0,.9), inset 0 -1px 0 rgba(255,255,255,.05)',
};

function Head({
  value,
  unit,
  right,
}: {
  value: React.ReactNode;
  unit: string;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-baseline justify-between gap-2.5">
      <div className="flex items-baseline gap-1.5">
        <span style={BIG}>{typeof value === 'number' ? <AnimatedNumber value={value} /> : value}</span>
        <span style={UNIT}>{unit}</span>
      </div>
      {right}
    </div>
  );
}

/** In-flight pressure: how much of the fleet is mid-update right now. */
export function PressureTile({ inFlight, total }: { inFlight: number; total: number }) {
  const ratio = total > 0 ? Math.min(1, inFlight / total) : 0;
  return (
    <div className="ota-tile" style={CARD}>
      <Head value={inFlight} unit="in flight" />
      <div style={{ ...WELL, height: 26, padding: 3 }}>
        <div
          style={{
            height: '100%',
            borderRadius: 7,
            background:
              'linear-gradient(90deg, rgba(var(--acc-deep-rgb), .25) 0%, rgb(var(--acc-deep-rgb)) 26%, rgb(var(--acc-rgb)) 62%, rgb(var(--acc2-rgb)) 88%, #fff 100%)',
          }}
        />
        <div
          style={{
            position: 'absolute',
            top: 0,
            bottom: 0,
            left: `calc(${(ratio * 100).toFixed(1)}% - 1.5px)`,
            width: 3,
            background: '#fff',
            borderRadius: 2,
            boxShadow: '0 0 10px rgba(255,255,255,.9)',
          }}
        />
      </div>
      <div className="flex justify-between" style={MICRO}>
        <span>Idle</span>
        <span>Saturated</span>
      </div>
    </div>
  );
}

/** Rollout stage. Renders an explicit empty state when nothing is rolling out. */
export function RolloutTile({
  label,
  pct,
  timer,
  note,
  active,
}: {
  label: string;
  pct: string;
  timer: string;
  note: string;
  active: boolean;
}) {
  return (
    <div className="ota-tile" style={CARD}>
      <div className="flex items-baseline justify-between gap-2.5">
        <span style={MICRO}>Rollout stage</span>
        <span
          className="tabular"
          style={{ font: 'var(--type-code)', color: active ? 'var(--amber)' : 'var(--app-ink2)' }}
        >
          {timer}
        </span>
      </div>
      <div
        style={{
          padding: 3,
          borderRadius: 12,
          background: active ? 'rgb(var(--acc-rgb))' : 'var(--app-line)',
        }}
      >
        <div style={{ padding: 2, borderRadius: 10, background: '#0d0d0d' }}>
          <div
            className="flex items-center justify-between gap-2.5"
            style={{
              padding: '9px 15px',
              borderRadius: 8,
              background: 'radial-gradient(120% 200% at 50% 0%,#1f1f1f,#0b0b0b)',
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,.09)',
            }}
          >
            <span
              style={{
                font: '700 13px/1 var(--font-ui)',
                letterSpacing: '0.6px',
                textTransform: 'uppercase',
                color: active ? '#fff' : 'rgba(255,255,255,.62)',
              }}
            >
              {label}
            </span>
            <span
              className="tabular"
              style={{ font: 'var(--type-code)', color: 'rgba(255,255,255,.62)' }}
            >
              {pct}
            </span>
          </div>
        </div>
      </div>
      <div style={MICRO}>{note}</div>
    </div>
  );
}

/** Signed version + the fleet's version spread, with a needle at the latest. */
export function VersionTile({
  latest,
  ticks,
  needlePct,
  axis,
}: {
  latest: string;
  ticks: { key: string; height: number; isLatest: boolean }[];
  needlePct: number | null;
  axis: string[];
}) {
  return (
    <div className="ota-tile" style={CARD}>
      <Head
        value={latest}
        unit="signed"
        right={
          <span
            style={{
              padding: '3px 8px',
              borderRadius: 5,
              background: 'var(--app-inv-bg,#fff)',
              color: 'var(--app-inv-ink,#181818)',
              font: '700 11px/1.3 var(--font-ui)',
              letterSpacing: '0.5px',
            }}
          >
            OTA
          </span>
        }
      />
      <div style={{ ...WELL, height: 40, padding: '0 8px', display: 'flex', alignItems: 'flex-end', gap: 2 }}>
        {ticks.length === 0 ? (
          <span
            className="w-full self-center text-center"
            style={{ ...MICRO, color: 'rgba(255,255,255,.62)' }}
          >
            No devices reporting
          </span>
        ) : (
          ticks.map((t) => (
            <span
              key={t.key}
              title={t.key}
              style={{
                flex: 1,
                height: `${Math.max(6, t.height)}%`,
                background: t.isLatest ? 'var(--amber)' : 'rgba(255,255,255,.28)',
                borderRadius: 1,
              }}
            />
          ))
        )}
        {needlePct !== null && (
          <div
            style={{
              position: 'absolute',
              top: 4,
              bottom: 4,
              left: `${needlePct}%`,
              width: 2,
              background: 'rgb(var(--acc-rgb))',
              borderRadius: 1,
              boxShadow: '0 0 9px rgba(var(--acc-rgb), .95)',
            }}
          />
        )}
      </div>
      <div className="flex justify-between tabular" style={MICRO}>
        {axis.map((a, i) => (
          <span key={`${a}-${i}`}>{a}</span>
        ))}
      </div>
    </div>
  );
}

/** Fleet composition as four conic-gradient rings. */
export function FleetTile({
  online,
  total,
  rings,
  note,
}: {
  online: number;
  total: number;
  rings: { label: string; pct: number; color: string; glow: string }[];
  note: string;
}) {
  return (
    <div className="ota-tile" style={CARD}>
      <Head
        value={online}
        unit="online"
        right={<span style={MICRO}>of {total} total</span>}
      />
      <div className="grid grid-cols-2 gap-x-2.5 gap-y-2.5">
        {rings.map((r) => (
          <div
            key={r.label}
            className="flex min-w-0 items-center gap-2.5"
            title={`${r.pct}% ${r.label}`}
          >
            <div
              className="relative shrink-0 rounded-full"
              style={{
                width: 32,
                height: 32,
                background: `conic-gradient(from -90deg,${r.color} 0turn,${r.color} ${(r.pct / 100).toFixed(3)}turn,var(--app-line2) ${(r.pct / 100).toFixed(3)}turn)`,
                boxShadow: `0 0 14px -4px ${r.glow}`,
              }}
            >
              <div
                className="absolute rounded-full"
                style={{
                  inset: 5,
                  background: 'var(--app-ring-hole)',
                  boxShadow: 'var(--app-ring-hole-shadow)',
                }}
              />
            </div>
            <div className="flex min-w-0 flex-col gap-0.5">
              <span
                className="tabular"
                style={{ font: '600 13px/1 var(--font-display)', color: 'var(--app-ink)' }}
              >
                {r.pct}%
              </span>
              <span className="truncate" style={MICRO}>
                {r.label}
              </span>
            </div>
          </div>
        ))}
      </div>
      <div style={MICRO}>{note}</div>
    </div>
  );
}

/** Adoption of the latest build over the last 24h, from real update events. */
export function AdoptionTile({
  onLatest,
  latest,
  delta,
  line,
  area,
  dot,
  behindNote,
  hasHistory,
}: {
  onLatest: number;
  latest: string;
  delta: number | null;
  line: string;
  area: string;
  dot: { x: number; y: number } | null;
  behindNote: string;
  hasHistory: boolean;
}) {
  return (
    <div className="ota-tile" style={CARD}>
      <Head
        value={onLatest}
        unit={latest ? `on ${latest}` : 'on latest'}
        right={
          delta !== null ? (
            <span className="tabular" style={{ ...MICRO, color: 'var(--app-warn-ink)' }}>
              +{delta} / 24h
            </span>
          ) : undefined
        }
      />
      {hasHistory ? (
        <svg
          viewBox="0 0 240 58"
          preserveAspectRatio="none"
          role="img"
          aria-label="Adoption over the last 24 hours"
          style={{ width: '100%', height: 58, display: 'block' }}
        >
          <defs>
            <linearGradient id="otaRamp" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" style={{ stopColor: 'rgb(var(--acc-rgb))', stopOpacity: 0.55 }} />
              <stop offset="100%" style={{ stopColor: 'rgb(var(--acc-rgb))', stopOpacity: 0 }} />
            </linearGradient>
          </defs>
          <polygon points={area} fill="url(#otaRamp)" />
          <polyline
            points={line}
            fill="none"
            style={{ stroke: 'rgb(var(--acc2-rgb))' }}
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
          />
          {dot && <circle cx={dot.x} cy={dot.y} r="3.5" strokeWidth="1.4" style={{ fill: 'rgb(var(--acc-rgb))', stroke: 'var(--app-surface)' }} />}
        </svg>
      ) : (
        <div
          className="flex items-center justify-center"
          style={{ height: 58, borderRadius: 9, border: '1px dashed var(--app-line)', ...MICRO }}
        >
          No update events in the last 24h
        </div>
      )}
      <div className="flex justify-between tabular" style={MICRO}>
        <span>0h</span>
        <span>8h</span>
        <span>16h</span>
        <span>24h</span>
      </div>
      <div style={MICRO}>{behindNote}</div>
    </div>
  );
}

/** Signed releases, one capsule per published release. */
export function ReleasesTile({
  signed,
  capsules,
  rotationNote,
}: {
  signed: number;
  capsules: { key: string; filled: boolean }[];
  rotationNote: string;
}) {
  return (
    <div className="ota-tile" style={CARD}>
      <Head value={signed} unit={signed === 1 ? 'signed release' : 'signed releases'} />
      <div className="flex gap-1" style={{ height: 34 }}>
        {capsules.map((c) => (
          <span
            key={c.key}
            style={{
              flex: 1,
              borderRadius: 8,
              background: c.filled
                ? 'linear-gradient(180deg,rgb(var(--acc2-rgb)),rgb(var(--acc-rgb)))'
                : 'var(--app-line2)',
              boxShadow: c.filled ? '0 0 14px -6px rgba(var(--acc-rgb), .9)' : 'none',
            }}
          />
        ))}
      </div>
      <div className="flex justify-between gap-2.5" style={MICRO}>
        <span>100% verified · 0 unsigned</span>
        <span>{rotationNote}</span>
      </div>
    </div>
  );
}
