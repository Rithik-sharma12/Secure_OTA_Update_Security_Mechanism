'use client';

import React from 'react';

/**
 * Layout wrapper kept for the landing sections. It used to fade content in
 * on scroll; the product's design rules rule out scroll animation, so it now
 * renders its children as they are. `delay` is accepted and ignored so call
 * sites need no change.
 */
export function Reveal({
  children,
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
  return React.createElement(Tag, { className, style }, children);
}
