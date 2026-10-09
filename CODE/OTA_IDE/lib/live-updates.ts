'use client';

/**
 * One shared EventSource per tab on /api/stream.
 *
 * Every component that wants to know "the gateway changed" subscribes here
 * instead of opening its own connection. Events are coalesced: a burst of
 * heartbeats produces one callback ~400 ms after the last of them.
 *
 * `isLiveConnected()` lets pollers slow down while the stream is healthy and
 * fall back to their normal cadence when it is not (proxy that buffers SSE,
 * gateway restarting, browser offline). EventSource reconnects on its own.
 */

type Listener = () => void;

const listeners = new Set<Listener>();
const statusListeners = new Set<(connected: boolean) => void>();
let source: EventSource | null = null;
let connected = false;
let debounceTimer: ReturnType<typeof setTimeout> | null = null;

const COALESCE_MS = 400;

function setConnected(value: boolean) {
  if (connected === value) return;
  connected = value;
  statusListeners.forEach((listener) => listener(value));
}

function notify() {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    debounceTimer = null;
    listeners.forEach((listener) => listener());
  }, COALESCE_MS);
}

function ensureSource() {
  if (source || typeof window === 'undefined' || typeof EventSource === 'undefined') return;
  source = new EventSource('/api/stream');
  source.addEventListener('hello', () => setConnected(true));
  source.addEventListener('state', () => {
    setConnected(true);
    notify();
  });
  // The server ends each stream after a few minutes; EventSource reconnects.
  source.addEventListener('bye', () => setConnected(false));
  source.onerror = () => setConnected(false);
}

function releaseSourceIfUnused() {
  if (listeners.size === 0 && statusListeners.size === 0 && source) {
    source.close();
    source = null;
    setConnected(false);
  }
}

export function subscribeToGatewayChanges(listener: Listener): () => void {
  listeners.add(listener);
  ensureSource();
  return () => {
    listeners.delete(listener);
    releaseSourceIfUnused();
  };
}

export function subscribeToLiveStatus(listener: (connected: boolean) => void): () => void {
  statusListeners.add(listener);
  ensureSource();
  listener(connected);
  return () => {
    statusListeners.delete(listener);
    releaseSourceIfUnused();
  };
}

export function isLiveConnected() {
  return connected;
}
