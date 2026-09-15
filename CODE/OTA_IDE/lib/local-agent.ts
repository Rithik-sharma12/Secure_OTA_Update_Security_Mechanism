'use client';

/**
 * Client for the SecureOTA local agent (CODE/agent/secureota_agent.py).
 *
 * The agent runs on the computer viewing the dashboard and exposes that
 * machine's COM ports on loopback. Because the browser makes the calls, a
 * dashboard served from the cloud still reaches the user's own USB devices —
 * with real port names (COM7), no permission picker, and esptool doing the
 * write. Chrome treats http://127.0.0.1 as a secure context, so an HTTPS page
 * may call it; the agent answers the private-network CORS preflight.
 */

export const AGENT_BASE_URL = 'http://127.0.0.1:17317';
const AGENT_TOKEN_KEY = 'secureota_agent_token';
const HEALTH_TIMEOUT_MS = 1500;

export type AgentInfo = {
  version: string;
  platform: string;
  esptool: boolean;
  tokenRequired: boolean;
};

export type AgentPort = {
  path: string;
  description: string;
  manufacturer: string | null;
  serialNumber: string | null;
  vendorId: string | null;
  productId: string | null;
};

export type AgentJob = {
  id: string;
  status: 'queued' | 'running' | 'success' | 'failed';
  progress: number;
  error: string | null;
  chip: string | null;
  port: string;
  address: string;
  log: string[];
  logLength: number;
  elapsed: number;
};

export function getAgentToken() {
  try {
    return localStorage.getItem(AGENT_TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function setAgentToken(token: string) {
  try {
    if (token) localStorage.setItem(AGENT_TOKEN_KEY, token);
    else localStorage.removeItem(AGENT_TOKEN_KEY);
  } catch {
    // storage unavailable; token only lives for this call
  }
}

function headers(extra: Record<string, string> = {}) {
  const token = getAgentToken();
  return token ? { ...extra, 'X-Agent-Token': token } : extra;
}

/**
 * Chrome's Local Network Access policy: an HTTPS page may only call a
 * loopback http:// address when the request declares it, and the first such
 * request triggers a one-time "allow this site to access your local network"
 * permission prompt. Without the flag the call is denied silently.
 * Not in lib.dom yet, hence the widened type.
 */
const LOOPBACK_INIT = { targetAddressSpace: 'loopback' } as unknown as RequestInit;

async function agentFetch(path: string, init: RequestInit = {}, timeoutMs?: number) {
  const controller = new AbortController();
  const timer = timeoutMs ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    return await fetch(`${AGENT_BASE_URL}${path}`, {
      ...LOOPBACK_INIT,
      ...init,
      headers: headers((init.headers as Record<string, string>) || {}),
      signal: controller.signal,
      cache: 'no-store',
    });
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** null when no agent is running on this computer. */
export async function detectAgent(): Promise<AgentInfo | null> {
  try {
    const response = await agentFetch('/health', {}, HEALTH_TIMEOUT_MS);
    if (!response.ok) return null;
    const payload = (await response.json()) as Partial<AgentInfo> & { ok?: boolean };
    if (!payload.ok) return null;
    return {
      version: String(payload.version || '?'),
      platform: String(payload.platform || ''),
      esptool: Boolean(payload.esptool),
      tokenRequired: Boolean(payload.tokenRequired),
    };
  } catch {
    return null;
  }
}

export async function listAgentPorts(): Promise<AgentPort[]> {
  const response = await agentFetch('/ports', {}, 5000);
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error || `Agent port scan failed (${response.status})`);
  }
  const payload = (await response.json()) as { ports?: AgentPort[] };
  return payload.ports || [];
}

export async function startAgentFlash(options: {
  port: string;
  address: number;
  file: Blob;
  filename: string;
  baud?: number;
  erase?: boolean;
}): Promise<string> {
  const form = new FormData();
  form.set('file', options.file, options.filename);
  form.set('port', options.port);
  form.set('address', `0x${options.address.toString(16)}`);
  form.set('baud', String(options.baud ?? 460800));
  form.set('erase', options.erase ? 'true' : 'false');
  const response = await agentFetch('/flash', { method: 'POST', body: form });
  const payload = (await response.json().catch(() => null)) as { ok?: boolean; jobId?: string; error?: string } | null;
  if (!response.ok || !payload?.ok || !payload.jobId) {
    throw new Error(payload?.error || `Agent refused the flash (${response.status})`);
  }
  return payload.jobId;
}

export async function getAgentJob(jobId: string, since = 0): Promise<AgentJob> {
  const response = await agentFetch(`/jobs/${encodeURIComponent(jobId)}?since=${since}`, {}, 5000);
  const payload = (await response.json().catch(() => null)) as { ok?: boolean; job?: AgentJob; error?: string } | null;
  if (!response.ok || !payload?.ok || !payload.job) {
    throw new Error(payload?.error || `Agent job lookup failed (${response.status})`);
  }
  return payload.job;
}

/**
 * Stream serial output through the agent. Returns a stop function.
 * Uses fetch + ReadableStream rather than EventSource so the token header
 * can be sent.
 */
export function openAgentMonitor(
  port: string,
  baud: number,
  onLine: (line: string) => void,
  onEnd: (error?: string) => void
): () => void {
  const controller = new AbortController();

  (async () => {
    try {
      const response = await fetch(
        `${AGENT_BASE_URL}/monitor?port=${encodeURIComponent(port)}&baud=${baud}`,
        { ...LOOPBACK_INIT, headers: headers(), signal: controller.signal, cache: 'no-store' }
      );
      if (!response.ok || !response.body) {
        const payload = await response.json().catch(() => null);
        onEnd(payload?.error || `Agent monitor failed (${response.status})`);
        return;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let pending = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        pending += decoder.decode(value, { stream: true });
        // SSE frames are separated by a blank line.
        let boundary = pending.indexOf('\n\n');
        while (boundary >= 0) {
          const frame = pending.slice(0, boundary);
          pending = pending.slice(boundary + 2);
          let event = 'message';
          let data = '';
          for (const raw of frame.split('\n')) {
            if (raw.startsWith('event:')) event = raw.slice(6).trim();
            else if (raw.startsWith('data:')) data += raw.slice(5).trim();
          }
          if (event === 'line' || event === 'open') {
            try {
              onLine(event === 'open' ? `[monitor] ${JSON.parse(data)}` : JSON.parse(data));
            } catch {
              onLine(data);
            }
          }
          boundary = pending.indexOf('\n\n');
        }
      }
      onEnd();
    } catch (error) {
      if (controller.signal.aborted) onEnd();
      else onEnd(error instanceof Error ? error.message : String(error));
    }
  })();

  return () => controller.abort();
}
