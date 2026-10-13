'use client';

import React from 'react';

/**
 * A number that glides to its new value instead of jumping, so live figures
 * (devices online, deployments in flight) read as changing rather than
 * flickering. Instant for visitors who ask their system to reduce motion.
 */
export function AnimatedNumber({ value, duration = 700, format }: { value: number; duration?: number; format?: (n: number) => string }) {
  const [shown, setShown] = React.useState(value);
  const fromRef = React.useRef(value);

  React.useEffect(() => {
    const from = fromRef.current;
    if (from === value) return;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) {
      fromRef.current = value;
      setShown(value);
      return;
    }
    let frame = 0;
    const start = performance.now();
    const decimals = Number.isInteger(value) && Number.isInteger(from) ? 0 : 1;
    const tick = (now: number) => {
      // rAF's timestamp is the frame start, which can be slightly earlier than
      // performance.now() above; clamp so the first frame never extrapolates
      // backwards (that briefly showed negative counts).
      const t = Math.min(1, Math.max(0, (now - start) / duration));
      const eased = 1 - Math.pow(1 - t, 3);
      const next = from + (value - from) * eased;
      setShown(Number(next.toFixed(decimals)));
      if (t < 1) frame = requestAnimationFrame(tick);
      else fromRef.current = value;
    };
    frame = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(frame);
      fromRef.current = value;
    };
  }, [value, duration]);

  return <span className="tabular">{format ? format(shown) : shown}</span>;
}
