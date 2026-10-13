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

/**
 * Runs `callback` once the page has finished loading and the main thread is
 * idle, so decorative animation never competes with the first render or
 * with the first interactions. Returns a cancel function.
 */
export function whenPageIdle(callback: () => void, timeout = 2500): () => void {
  let cancelled = false;
  let idleId: number | undefined;
  let timer: number | undefined;
  const run = () => {
    if (cancelled) return;
    const w = window as Window & { requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => number };
    if (w.requestIdleCallback) idleId = w.requestIdleCallback(() => !cancelled && callback(), { timeout });
    else timer = window.setTimeout(() => !cancelled && callback(), 200);
  };
  if (document.readyState === 'complete') run();
  else window.addEventListener('load', run, { once: true });
  return () => {
    cancelled = true;
    window.removeEventListener('load', run);
    const w = window as Window & { cancelIdleCallback?: (id: number) => void };
    if (idleId !== undefined) w.cancelIdleCallback?.(idleId);
    if (timer !== undefined) window.clearTimeout(timer);
  };
}
