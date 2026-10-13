'use client';

import React from 'react';
import { useInView, useReducedMotion } from './motion';

/** Counts up to `value` when scrolled into view. Non-numeric values render as-is. */
export function CountUp({ value, duration = 1400 }: { value: string; duration?: number }) {
  const ref = React.useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, '0px');
  const reduced = useReducedMotion();
  const target = /^\d+$/.test(value) ? Number(value) : null;
  const [shown, setShown] = React.useState(target === null ? value : '0');

  React.useEffect(() => {
    if (target === null) {
      setShown(value);
      return;
    }
    if (!inView) return;
    if (reduced || target === 0) {
      setShown(String(target));
      return;
    }
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setShown(String(Math.round(target * eased)));
      if (t < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [inView, reduced, target, value, duration]);

  return <span ref={ref}>{shown}</span>;
}
