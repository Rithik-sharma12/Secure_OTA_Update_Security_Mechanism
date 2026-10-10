'use client';

import React from 'react';

/** True when the reader asked the OS for reduced motion. Updates live. */
export function useReducedMotion() {
  const [reduced, setReduced] = React.useState(false);
  React.useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReduced(query.matches);
    update();
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  return reduced;
}

/** True once `ref` has scrolled into view (stays true). */
export function useInView<T extends Element>(ref: React.RefObject<T | null>, rootMargin = '0px 0px -12% 0px') {
  const [inView, setInView] = React.useState(false);
  React.useEffect(() => {
    const node = ref.current;
    if (!node || inView) return;
    if (typeof IntersectionObserver === 'undefined') {
      setInView(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setInView(true);
          observer.disconnect();
        }
      },
      { rootMargin }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [ref, rootMargin, inView]);
  return inView;
}

/** Writes the pointer position into --px/--py on the element (for .lp-spot). */
export function trackPointer(event: React.PointerEvent<HTMLElement>) {
  const target = event.currentTarget;
  const rect = target.getBoundingClientRect();
  target.style.setProperty('--px', `${event.clientX - rect.left}px`);
  target.style.setProperty('--py', `${event.clientY - rect.top}px`);
}
