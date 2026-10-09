'use client';

import React from 'react';
import Link from 'next/link';
import { Check, Copy, Download } from 'lucide-react';
import { trackPointer, useInView, useReducedMotion } from './motion';

const STEP_MS = 7000;

const AGENT_COMMAND = 'python secureota_agent.py';

type Step = {
  title: string;
  sub: string;
  render: () => React.ReactNode;
};

function Terminal({ title, lines }: { title: string; lines: Array<{ text: string; kind?: 'cmd' | 'ok' | 'bad' }> }) {
  return (
    <div className="lp-terminal">
      <div className="lp-terminal-bar">
        <i />
        <i />
        <i />
        <span style={{ marginLeft: 8 }}>{title}</span>
      </div>
      <div className="lp-terminal-body lp-typed">
        {lines.map((line, index) => (
          <span key={line.text} className="lp-line" data-kind={line.kind} style={{ ['--i' as string]: index }}>
            {line.kind === 'cmd' ? '$ ' : ''}
            {line.text}
          </span>
        ))}
      </div>
    </div>
  );
}

function CopyCommand() {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      type="button"
      className="lp-copy"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(AGENT_COMMAND);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1800);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? <Check size={15} /> : <Copy size={15} />}
      {copied ? 'Copied' : 'Copy command'}
    </button>
  );
}

const STEPS: Step[] = [
  {
    title: 'Start the local agent',
    sub: 'Lets this page reach the USB ports on your computer.',
    render: () => (
      <>
        <Terminal
          title="Terminal — your computer"
          lines={[
            { text: AGENT_COMMAND, kind: 'cmd' },
            { text: 'SecureOTA agent v1.1.0 listening on http://127.0.0.1:17317' },
            { text: 'esptool : found', kind: 'ok' },
            { text: 'ports   : COM7 (Silicon Labs CP210x)', kind: 'ok' },
            { text: 'Leave this window open while using the dashboard.' },
          ]}
        />
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <CopyCommand />
          <a className="lp-copy" href="/agent/secureota_agent.py" download style={{ textDecoration: 'none' }}>
            <Download size={15} /> Download the agent
          </a>
        </div>
        <p className="lp-sim-label" style={{ margin: 0 }}>
          Only needs Python. It installs pyserial and esptool on first run and listens on 127.0.0.1 only.
        </p>
      </>
    ),
  },
  {
    title: 'Flash over USB',
    sub: 'Devices → Flash over USB. Pick the port and the release.',
    render: () => (
      <>
        <div className="lp-field">
          <span>Port</span>
          <b>COM7 · Silicon Labs CP210x</b>
        </div>
        <div className="lp-field">
          <span>Image</span>
          <b>Release v2.6.0 · ESP32 · 0x10000</b>
        </div>
        <div className="lp-meter" data-animate="true" style={{ ['--w' as string]: '100%' }}>
          <i />
        </div>
        <Terminal
          title="esptool via the agent"
          lines={[
            { text: 'Chip is ESP32-D0WD-V3 (revision v3.1)' },
            { text: 'Writing at 0x00010000... (100 %)' },
            { text: 'Hash of data verified.', kind: 'ok' },
            { text: 'Hard resetting via RTS pin...' },
          ]}
        />
      </>
    ),
  },
  {
    title: 'Provision the board',
    sub: 'Wi-Fi, gateway and its own token — written over the cable.',
    render: () => (
      <>
        <div className="lp-field">
          <span>Board</span>
          <b>esp32-a1b2c3d4e5f6 · v2.6.0</b>
        </div>
        <div className="lp-field">
          <span>Wi-Fi</span>
          <b>Lab-Network · ••••••••</b>
        </div>
        <div className="lp-field">
          <span>Gateway</span>
          <b>https://gw.example.com</b>
        </div>
        <div className="lp-field">
          <span>Device token</span>
          <b>issued for this board only</b>
        </div>
        <Terminal
          title="Serial · 115200"
          lines={[
            { text: 'SOTA:PROVISION {…}', kind: 'cmd' },
            { text: 'SOTA:OK provisioned; rebooting', kind: 'ok' },
            { text: '[WiFi] Connected. IP: 10.0.0.42' },
            { text: '[HB] heartbeat accepted', kind: 'ok' },
          ]}
        />
      </>
    ),
  },
  {
    title: 'Deploy over the internet',
    sub: 'Deployments → choose boards → Deploy. Watch them confirm.',
    render: () => (
      <>
        {[
          { id: 'esp32-a1b2c3d4e5f6', w: '100%', label: 'confirmed', d: 0 },
          { id: 'esp32-0011223344aa', w: '72%', label: 'downloading 75%', d: 300 },
          { id: 'esp32-55667788ccdd', w: '38%', label: 'downloading 25%', d: 600 },
        ].map((row) => (
          <div key={row.id} style={{ display: 'grid', gap: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }} className="lp-sim-label">
              <span style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{row.id}</span>
              <span>{row.label}</span>
            </div>
            <div className="lp-meter" data-animate="true" style={{ ['--w' as string]: row.w, ['--d' as string]: `${row.d}ms` }}>
              <i />
            </div>
          </div>
        ))}
        <p className="lp-sim-label" style={{ margin: 0 }}>
          No port forwarding: boards pick the job up in their next heartbeat, report each stage, and roll back on their
          own if the new build cannot reach the gateway.
        </p>
        <Link href="/login" className="ds-cta lp-btn lp-btn-sm" style={{ alignSelf: 'flex-start' }}>
          Open the console
        </Link>
      </>
    ),
  },
];

/**
 * Four-step onboarding, auto-advancing like a story while nobody is
 * interacting with it. Hover, focus or a click pins the current step.
 * Implemented as a WAI-ARIA tab list (arrow keys move between steps).
 */
export function GetStarted() {
  const [active, setActive] = React.useState(0);
  const [pinned, setPinned] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);
  const inView = useInView(ref, '0px 0px -25% 0px');
  const reduced = useReducedMotion();
  const running = inView && !pinned && !reduced;

  React.useEffect(() => {
    if (!running) return;
    const timer = window.setTimeout(() => setActive((value) => (value + 1) % STEPS.length), STEP_MS);
    return () => window.clearTimeout(timer);
  }, [running, active]);

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp' && event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
    event.preventDefault();
    const delta = event.key === 'ArrowDown' || event.key === 'ArrowRight' ? 1 : -1;
    const next = (active + delta + STEPS.length) % STEPS.length;
    setActive(next);
    setPinned(true);
    document.getElementById(`lp-step-tab-${next}`)?.focus();
  };

  return (
    <div
      ref={ref}
      className="lp-steps"
      onMouseEnter={() => setPinned(true)}
      onMouseLeave={() => setPinned(false)}
      style={{ ['--lp-step-ms' as string]: `${STEP_MS}ms` }}
    >
      <div role="tablist" aria-label="Getting started" aria-orientation="vertical" onKeyDown={onKeyDown} style={{ display: 'grid', gap: 6 }}>
        {STEPS.map((step, index) => (
          <button
            key={step.title}
            id={`lp-step-tab-${index}`}
            role="tab"
            type="button"
            aria-selected={active === index}
            aria-controls={`lp-step-panel-${index}`}
            tabIndex={active === index ? 0 : -1}
            className="lp-step-tab"
            onClick={() => {
              setActive(index);
              setPinned(true);
            }}
            onFocus={() => setPinned(true)}
          >
            <span className="lp-step-num">{index + 1}</span>
            <span>
              <strong>{step.title}</strong>
              <span className="lp-step-sub">{step.sub}</span>
            </span>
            <span key={`${active}-${running}`} className="lp-step-bar" data-run={running ? 'true' : 'false'} aria-hidden="true" />
          </button>
        ))}
      </div>

      <div
        key={active}
        id={`lp-step-panel-${active}`}
        role="tabpanel"
        aria-labelledby={`lp-step-tab-${active}`}
        className="lp-card lp-spot lp-stage"
        onPointerMove={trackPointer}
      >
        <div className="lp-eyebrow">Step {active + 1} of 4</div>
        <h3 style={{ margin: 0, font: 'var(--type-heading-md)' }}>{STEPS[active].title}</h3>
        {STEPS[active].render()}
      </div>
    </div>
  );
}
