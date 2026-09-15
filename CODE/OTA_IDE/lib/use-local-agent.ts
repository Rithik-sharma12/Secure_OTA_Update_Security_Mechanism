'use client';

import React from 'react';
import { type AgentInfo, type AgentPort, detectAgent, listAgentPorts } from '@/lib/local-agent';

const AGENT_POLL_MS = 3000;
const AGENT_RETRY_MS = 5000;

/**
 * Track the local COM agent and the ports it sees.
 *
 * `agent` is null until an agent answers on loopback; while one is connected
 * `ports` refreshes every few seconds so plug/unplug shows up without a click.
 * `checked` flips true after the first probe so callers can tell "no agent"
 * apart from "still looking".
 */
export function useLocalAgent(enabled = true) {
  const [agent, setAgent] = React.useState<AgentInfo | null>(null);
  const [ports, setPorts] = React.useState<AgentPort[]>([]);
  const [checked, setChecked] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    const info = await detectAgent();
    setAgent(info);
    setChecked(true);
    if (!info) {
      setPorts([]);
      return { info, ports: [] as AgentPort[] };
    }
    try {
      const found = await listAgentPorts();
      setPorts(found);
      setError(null);
      return { info, ports: found };
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return { info, ports: [] as AgentPort[] };
    }
  }, []);

  React.useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    let timer: number | undefined;

    const tick = async () => {
      const result = await refresh();
      if (cancelled) return;
      timer = window.setTimeout(tick, result.info ? AGENT_POLL_MS : AGENT_RETRY_MS);
    };
    void tick();

    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [enabled, refresh]);

  return { agent, ports, checked, error, refresh };
}
