'use client';

import React from 'react';
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { chartAxis, chartColors, chartTooltipLabelStyle, chartTooltipStyle } from '@/lib/chart-theme';
import type { TelemetryPoint } from '@/lib/device-control';

/**
 * Three small multiples rather than one chart with three y-scales: health
 * (0-100), Wi-Fi signal (dBm) and memory (%) have unrelated units, and a
 * dual/triple axis would invite comparing lines that share nothing.
 *
 * Each panel is one series, so the panel title names it and no legend box is
 * needed. Firmware changes are drawn as labelled vertical rules on every panel,
 * which is the question these charts usually answer: "did the update change
 * how the board behaves?"
 */

type Metric = {
  key: 'ash' | 'rssi' | 'memory';
  title: string;
  unit: string;
  domain: [number | 'auto', number | 'auto'];
  threshold?: { value: number; label: string };
};

const METRICS: Metric[] = [
  { key: 'ash', title: 'Health score (ASH)', unit: '', domain: [0, 100], threshold: { value: 40, label: 'Quarantine 40' } },
  { key: 'rssi', title: 'Wi-Fi signal', unit: ' dBm', domain: [-100, -20] },
  { key: 'memory', title: 'Heap used', unit: '%', domain: [0, 100] },
];

function shortTime(iso: string, spanHours: number) {
  const date = new Date(iso);
  return spanHours > 24
    ? date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + date.toLocaleTimeString([], { hour: '2-digit' })
    : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function TelemetryCharts({ points, hours }: { points: TelemetryPoint[]; hours: number }) {
  // Where the reported firmware changes between consecutive buckets.
  const upgrades = React.useMemo(() => {
    const marks: Array<{ t: string; fw: string }> = [];
    for (let i = 1; i < points.length; i += 1) {
      if (points[i].fw && points[i - 1].fw && points[i].fw !== points[i - 1].fw) {
        marks.push({ t: points[i].t, fw: points[i].fw as string });
      }
    }
    return marks;
  }, [points]);

  if (points.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-muted-foreground">
        No heartbeats recorded in this window. History starts when the device next checks in.
      </p>
    );
  }

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      {METRICS.map((metric) => {
        const latest = [...points].reverse().find((point) => point[metric.key] !== null)?.[metric.key];
        return (
          <figure key={metric.key} className="rounded-lg border border-border/60 bg-muted/10 p-3">
            <figcaption className="mb-2 flex items-baseline justify-between gap-2">
              <span className="text-sm font-medium text-foreground">{metric.title}</span>
              <span className="text-xs text-muted-foreground">
                latest {latest === undefined || latest === null ? '—' : `${latest}${metric.unit}`}
              </span>
            </figcaption>
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={points} margin={{ top: 8, right: 8, bottom: 0, left: -12 }}>
                <CartesianGrid stroke={chartAxis.grid} vertical={false} />
                <XAxis
                  dataKey="t"
                  stroke={chartAxis.stroke}
                  tick={chartAxis.tick}
                  tickFormatter={(value: string) => shortTime(value, hours)}
                  minTickGap={40}
                />
                <YAxis
                  stroke={chartAxis.stroke}
                  tick={chartAxis.tick}
                  domain={metric.domain}
                  allowDecimals={false}
                  tickFormatter={(value: number) => String(Math.round(value))}
                  width={44}
                />
                <Tooltip
                  contentStyle={chartTooltipStyle}
                  labelStyle={chartTooltipLabelStyle}
                  itemStyle={{ color: '#ffffff' }}
                  labelFormatter={(value) => new Date(String(value)).toLocaleString()}
                  formatter={(value, _name, item) => {
                    const point = (item as { payload?: TelemetryPoint }).payload;
                    return [`${value}${metric.unit}${point?.fw ? `  ·  fw v${point.fw}` : ''}`, metric.title];
                  }}
                  cursor={{ stroke: chartAxis.stroke, strokeWidth: 1 }}
                />
                {metric.threshold && (
                  <ReferenceLine
                    y={metric.threshold.value}
                    stroke={chartColors.error}
                    strokeDasharray="4 4"
                    label={{ value: metric.threshold.label, position: 'insideBottomRight', fill: '#c9c6c1', fontSize: 11 }}
                  />
                )}
                {upgrades.map((mark) => (
                  <ReferenceLine
                    key={`${metric.key}-${mark.t}`}
                    x={mark.t}
                    stroke={chartColors.warning}
                    label={{ value: `v${mark.fw}`, position: 'insideTopRight', fill: '#c9c6c1', fontSize: 11 }}
                  />
                ))}
                <Line
                  type="monotone"
                  dataKey={metric.key}
                  stroke={chartColors.info}
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, stroke: '#212121', strokeWidth: 2 }}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </figure>
        );
      })}
    </div>
  );
}
