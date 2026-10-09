'use client';

import React from 'react';
import { Pause, Play, RotateCcw } from 'lucide-react';
import { useReducedMotion } from './motion';

/**
 * A scripted, client-only walk through one over-the-air update, so a
 * visitor can see what the platform does before signing in. It talks to no
 * device and no gateway, and says so.
 *
 * Three scenarios show the three outcomes that matter: a clean install, an
 * image altered in transit (refused before anything is written), and a
 * build that installs but cannot reach the gateway (rolled back by the
 * health gate).
 */

type Scenario = 'normal' | 'tampered' | 'broken';
type StepState = 'idle' | 'active' | 'done' | 'failed' | 'skipped';

const STEPS = [
  { key: 'assign', label: 'Deployment assigned', note: 'Queued for the next heartbeat' },
  { key: 'manifest', label: 'Signed manifest checked', note: 'Version, board and size' },
  { key: 'download', label: 'Image downloaded', note: 'Progress reported at 25 / 50 / 75 %' },
  { key: 'digest', label: 'SHA-256 matches the manifest', note: 'Catches any changed byte' },
  { key: 'signature', label: 'Signature verified', note: 'Only the release key can produce it' },
  { key: 'write', label: 'Written to the spare partition', note: 'Running firmware untouched' },
  { key: 'reboot', label: 'Reboot into the new image', note: 'On probation' },
  { key: 'health', label: 'Health gate', note: 'Wi-Fi + accepted heartbeat within 120 s' },
  { key: 'confirmed', label: 'Confirmed on the dashboard', note: 'Only the device can say so' },
] as const;

type Script = Array<{ step: number; state: StepState; log: string; kind?: 'ok' | 'bad'; led: 'idle' | 'busy' | 'ok' | 'bad'; version?: string; ms: number }>;

function buildScript(scenario: Scenario): Script {
  const script: Script = [
    { step: 0, state: 'done', log: 'dashboard → deployment v2.6.0 assigned to esp32-a1b2c3d4e5f6', led: 'idle', ms: 700 },
    { step: 1, state: 'active', log: '[HB] gateway: update_available (target 2.6.0)', led: 'busy', ms: 700 },
    { step: 1, state: 'done', log: 'manifest: ESP32, 1.21 MB, signature present', kind: 'ok', led: 'busy', ms: 600 },
    { step: 2, state: 'active', log: '[Update] downloading… 25%', led: 'busy', ms: 650 },
    { step: 2, state: 'active', log: '[Update] downloading… 50%', led: 'busy', ms: 650 },
    { step: 2, state: 'active', log: '[Update] downloading… 75%', led: 'busy', ms: 650 },
    { step: 2, state: 'done', log: '[Update] 1,240 KB received', kind: 'ok', led: 'busy', ms: 500 },
  ];
  if (scenario === 'tampered') {
    script.push({ step: 3, state: 'failed', log: '[Update] ERROR: image does not match the manifest sha256', kind: 'bad', led: 'bad', ms: 900 });
    script.push({ step: 4, state: 'skipped', log: 'nothing written — v2.5.0 keeps running; deployment marked failed', kind: 'ok', led: 'ok', version: '2.5.0', ms: 0 });
    return script;
  }
  script.push({ step: 3, state: 'done', log: '[Update] sha256 matches', kind: 'ok', led: 'busy', ms: 600 });
  script.push({ step: 4, state: 'done', log: '[Update] signature verified', kind: 'ok', led: 'busy', ms: 700 });
  script.push({ step: 5, state: 'done', log: '[Update] written to ota_1, boot partition switched', kind: 'ok', led: 'busy', ms: 700 });
  script.push({ step: 6, state: 'done', log: '[OTA] rebooting into v2.6.0', led: 'busy', version: '2.6.0', ms: 900 });
  script.push({ step: 7, state: 'active', log: '[Gate] v2.6.0 on probation: 120 s to reach the gateway', led: 'busy', version: '2.6.0', ms: 1100 });
  if (scenario === 'broken') {
    script.push({ step: 7, state: 'failed', log: '[Gate] no accepted heartbeat in time — rolling back', kind: 'bad', led: 'bad', version: '2.6.0', ms: 1000 });
    script.push({ step: 8, state: 'skipped', log: 'bootloader restored v2.5.0; dashboard shows "rolled back"', kind: 'ok', led: 'ok', version: '2.5.0', ms: 0 });
    return script;
  }
  script.push({ step: 7, state: 'done', log: '[Gate] heartbeat accepted — image marked valid', kind: 'ok', led: 'ok', version: '2.6.0', ms: 700 });
  script.push({ step: 8, state: 'done', log: 'deployment confirmed: device reports v2.6.0', kind: 'ok', led: 'ok', version: '2.6.0', ms: 0 });
  return script;
}

const SCENARIOS: Array<{ id: Scenario; label: string }> = [
  { id: 'normal', label: 'Normal update' },
  { id: 'tampered', label: 'Tampered image' },
  { id: 'broken', label: 'Broken build' },
];

export function UpdateSimulator() {
  const reduced = useReducedMotion();
  const [scenario, setScenario] = React.useState<Scenario>('normal');
  const [cursor, setCursor] = React.useState(-1); // index into the script; -1 = not started
  const [playing, setPlaying] = React.useState(false);
  const logRef = React.useRef<HTMLDivElement>(null);

  const script = React.useMemo(() => buildScript(scenario), [scenario]);
  const finished = cursor >= script.length - 1;

  React.useEffect(() => {
    if (!playing) return;
    if (finished) {
      setPlaying(false);
      return;
    }
    const delay = cursor < 0 ? 200 : reduced ? 120 : script[cursor].ms;
    const timer = window.setTimeout(() => setCursor((value) => value + 1), delay);
    return () => window.clearTimeout(timer);
  }, [playing, cursor, finished, script, reduced]);

  React.useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: reduced ? 'auto' : 'smooth' });
  }, [cursor, reduced]);

  const states: StepState[] = STEPS.map(() => 'idle');
  let led: Script[number]['led'] = 'idle';
  let version = '2.5.0';
  for (let i = 0; i <= cursor && i < script.length; i += 1) {
    const entry = script[i];
    states[entry.step] = entry.state;
    if (entry.state === 'skipped') {
      for (let k = entry.step; k < STEPS.length; k += 1) if (states[k] === 'idle') states[k] = 'skipped';
    }
    led = entry.led;
    if (entry.version) version = entry.version;
  }
  const log = script.slice(0, Math.max(0, cursor + 1));
  const outcome = finished ? (scenario === 'normal' ? 'Installed and confirmed' : scenario === 'tampered' ? 'Refused before flashing' : 'Rolled back automatically') : null;

  const start = (next?: Scenario) => {
    if (next) setScenario(next);
    setCursor(-1);
    setPlaying(true);
  };

  return (
    <div className="lp-sim">
      <div className="lp-card" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 18 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 12, justifyContent: 'space-between' }}>
          <div className="lp-segmented" role="group" aria-label="Scenario">
            {SCENARIOS.map((entry) => (
              <button key={entry.id} type="button" aria-pressed={scenario === entry.id} onClick={() => start(entry.id)}>
                {entry.label}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {!playing ? (
              <button type="button" className="ds-cta lp-btn lp-btn-sm" onClick={() => (finished || cursor < 0 ? start() : setPlaying(true))}>
                {finished ? <RotateCcw size={16} /> : <Play size={16} />}
                {finished ? 'Replay' : cursor < 0 ? 'Deploy v2.6.0' : 'Resume'}
              </button>
            ) : (
              <button type="button" className="ds-ghost lp-btn lp-btn-sm" onClick={() => setPlaying(false)}>
                <Pause size={16} /> Pause
              </button>
            )}
          </div>
        </div>

        <ol className="lp-pipeline" aria-label="Update stages">
          {STEPS.map((step, index) => (
            <li key={step.key} className="lp-pipe-step" data-state={states[index]}>
              <span className="lp-pipe-icon" aria-hidden="true">
                {states[index] === 'done' ? '✓' : states[index] === 'failed' ? '✕' : index + 1}
              </span>
              <span>
                {step.label}
                <br />
                <small>{step.note}</small>
              </span>
              <span className="lp-sr">{states[index]}</span>
            </li>
          ))}
        </ol>
      </div>

      <div className="lp-card lp-board">
        <div className="lp-board-chip" data-led={led}>
          <span className="lp-led" aria-hidden="true" />
          <div className="lp-board-core">
            <div>
              ESP32
              <small>running v{version}</small>
            </div>
          </div>
        </div>
        <div aria-live="polite" style={{ minHeight: 26, font: 'var(--type-body-strong)', color: outcome ? '#fff' : 'var(--on-dark-muted)' }}>
          {outcome ?? (cursor < 0 ? 'Pick a scenario and press Deploy.' : 'Updating…')}
        </div>
        <div className="lp-terminal">
          <div className="lp-terminal-bar">
            <i />
            <i />
            <i />
            <span style={{ marginLeft: 8 }}>Device log</span>
          </div>
          <div ref={logRef} className="lp-terminal-body lp-log">
            {log.length === 0 && <span className="lp-line">waiting for a deployment…</span>}
            {log.map((entry, index) => (
              <span key={`${scenario}-${index}`} className="lp-line" data-kind={entry.kind}>
                {entry.log}
              </span>
            ))}
          </div>
        </div>
        <p className="lp-sim-label" style={{ margin: 0 }}>
          Interactive simulation — no real device or gateway is contacted. The stages and messages mirror the SecureOTA
          firmware.
        </p>
      </div>
    </div>
  );
}
