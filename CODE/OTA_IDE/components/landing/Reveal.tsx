'use client';

import React from 'react';
import { useInView } from './motion';

/**
 * Fades and lifts its children in the first time they scroll into view.
 * Server-rendered as visible (`data-shown` is only set to false after
 * hydration), so without JavaScript nothing is hidden.
 */
export function Reveal({
  children,
  delay = 0,
  as: Tag = 'div',
  className = '',
  style,
}: {
  children: React.ReactNode;
  delay?: number;
  as?: 'div' | 'section' | 'li' | 'header';
  className?: string;
  style?: React.CSSProperties;
}) {
  const ref = React.useRef<HTMLDivElement>(null);
  const [hydrated, setHydrated] = React.useState(false);
  const inView = useInView(ref);
  React.useEffect(() => setHydrated(true), []);
  const shown = !hydrated || inView;
  return React.createElement(
    Tag,
    {
      ref,
      className: `lp-reveal ${className}`,
      'data-shown': shown ? 'true' : 'false',
      style: { ...style, ['--lp-delay' as string]: `${delay}ms` },
    },
    children
  );
}
