import { apiFetch } from '@/lib/client-auth';
import { logger, errorTracker } from '@/lib/logger';

export type RuntimeActionResult<T = unknown> = {
  ok: boolean;
  message?: string;
  error?: string;
  data?: T;
};

export type RuntimeDownloadPayload = {
  filename?: string;
  mimeType?: string;
  content?: string;
};

async function parseJsonSafe(response: Response) {
  try {
    return await response.json();
  } catch {
    logger.warn('RuntimeActions', 'Failed to parse JSON response from runtime action', { status: response.status, url: response.url });
    errorTracker.track(new Error('JSON_PARSE_FAILED'), 'RuntimeActions:JsonParse');
    return null; // Return null if JSON parsing fails
  }
}

export async function executeRuntimeAction<T = unknown>(action: string, payload: Record<string, unknown> = {}) {
  const response = await apiFetch('/api/runtime/actions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ action, payload }),
  });

  const body = (await parseJsonSafe(response)) as RuntimeActionResult<T> | null;

  if (!response.ok || !body?.ok) {
    const errorMsg = body?.error || body?.message || `Action '${action}' failed.`;
    logger.error('RuntimeActions', `Runtime action '${action}' failed`, { action, responseStatus: response.status, errorBody: body });
    errorTracker.track(new Error(errorMsg), `RuntimeActions:Execute:${action}`);
    throw new Error(errorMsg);
  }

  return body;
}

export function downloadRuntimePayload(payload: RuntimeDownloadPayload) {
  if (typeof window === 'undefined') {
    return;
  }

  const content = payload.content ?? '';
  const mimeType = payload.mimeType || 'text/plain;charset=utf-8';
  const filename = payload.filename || `download-${Date.now()}.txt`;

  saveBlob(new Blob([content], { type: mimeType }), filename);
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/**
 * Download a release's firmware binary through the console's own server
 * route. The server fetches it from the gateway with the fleet key; the key
 * never reaches the browser.
 */
export async function downloadReleaseFile(filename: string) {
  const response = await apiFetch(`/api/firmware/download?file=${encodeURIComponent(filename)}`, { cache: 'no-store' });
  if (!response.ok) {
    const body = (await parseJsonSafe(response)) as { error?: string } | null;
    throw new Error(body?.error || `Download failed (${response.status}).`);
  }
  saveBlob(await response.blob(), filename);
}
