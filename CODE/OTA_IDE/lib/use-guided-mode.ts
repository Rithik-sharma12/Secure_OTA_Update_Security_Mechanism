'use client';

import React from 'react';

const KEY = 'ota-console-density';
const EVENT = 'ota-density-change';

/**
 * Guided / Dense density preference.
 *
 * Guided shows the onboarding panel on the dashboard; Dense hides it. Stored
 * per browser in localStorage, which can throw outright in a private window or
 * when site data is blocked, so every access is guarded and the app renders
 * correctly with no stored value.
 *
 * A custom event keeps every mounted consumer in sync within the tab —
 * `storage` only fires in *other* tabs, so it cannot do this on its own.
 */
export function useGuidedMode(): [boolean, (guided: boolean) => void] {
  // Default to Guided, and read the stored value after mount so server and
  // client markup agree on the first paint.
  const [guided, setGuidedState] = React.useState(true);

  React.useEffect(() => {
    const read = () => {
      try {
        const stored = window.localStorage.getItem(KEY);
        if (stored === 'dense') setGuidedState(false);
        else if (stored === 'guided') setGuidedState(true);
      } catch {
        // Private window or blocked site data — keep the default.
      }
    };

    read();
    window.addEventListener(EVENT, read);
    return () => window.removeEventListener(EVENT, read);
  }, []);

  const setGuided = React.useCallback((next: boolean) => {
    setGuidedState(next);
    try {
      window.localStorage.setItem(KEY, next ? 'guided' : 'dense');
    } catch {
      // Preference simply does not persist; the toggle still works this session.
    }
    window.dispatchEvent(new Event(EVENT));
  }, []);

  return [guided, setGuided];
}
