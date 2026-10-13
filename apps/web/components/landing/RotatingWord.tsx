'use client';

import React from 'react';
import { useReducedMotion } from './motion';

/**
 * The hero's highlighted keyword, cycling through what SecureOTA prevents.
 * Screen readers get the full sentence once (see the sr-only text in the
 * hero), so this is aria-hidden and purely visual.
 */
export function RotatingWord({ words, interval = 2600 }: { words: string[]; interval?: number }) {
  const reduced = useReducedMotion();
  const [index, setIndex] = React.useState(0);

  React.useEffect(() => {
    if (reduced) return;
    const timer = window.setInterval(() => setIndex((value) => (value + 1) % words.length), interval);
    return () => window.clearInterval(timer);
  }, [reduced, words.length, interval]);

  // Reserve the width of the longest word so the line never reflows.
  const longest = words.reduce((a, b) => (b.length > a.length ? b : a), '');
  return (
    <span className="lp-word" aria-hidden="true">
      <span style={{ visibility: 'hidden' }}>{longest}</span>
      <span key={index} data-state="enter">
        {words[index]}
      </span>
    </span>
  );
}
