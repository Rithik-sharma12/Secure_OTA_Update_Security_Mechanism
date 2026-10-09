'use client';

import React from 'react';

/**
 * The protection layers as a clickable stack. Pick an attack and the layer
 * that stops it lights up; pick a layer to read what it does.
 */

const LAYERS = [
  {
    id: 'tokens',
    name: 'Per-device tokens',
    detail:
      'Each board authenticates with a token issued to it alone. A token pulled out of one board’s flash cannot report for, or receive commands meant for, any other board.',
  },
  {
    id: 'signature',
    name: 'Signed firmware',
    detail:
      'Release packages are signed at build time and the signature is checked on the board before the boot partition changes. Manifests from the gateway carry their own Ed25519 signature.',
  },
  {
    id: 'digest',
    name: 'SHA-256 bound to the manifest',
    detail:
      'The board compares the image it received with the digest the manifest promised for that exact version, so a valid but different build cannot be swapped in.',
  },
  {
    id: 'version',
    name: 'Anti-rollback versions',
    detail: 'The gateway only offers strictly newer builds and the board refuses a lower version even if one is pushed at it.',
  },
  {
    id: 'encryption',
    name: 'Encrypted, authenticated status',
    detail: 'Status broadcasts are AES-256 encrypted and HMAC-SHA256 tagged, with a counter kept across reboots so an old packet cannot be replayed.',
  },
  {
    id: 'gate',
    name: 'Health gate with rollback',
    detail: 'A new image must reach the gateway within 120 s of booting, or the bootloader brings back the previous firmware without anyone touching the board.',
  },
  {
    id: 'audit',
    name: 'Audit trail',
    detail: 'Every change through the gateway is recorded with who made it and from where — including the requests that were refused.',
  },
];

const ATTACKS = [
  { id: 'swap', label: 'Swap the firmware file', stops: 'digest', result: 'The SHA-256 does not match the manifest. Nothing is written; the board keeps running.' },
  { id: 'forge', label: 'Forge a release', stops: 'signature', result: 'Without the release key the signature cannot verify, so the board refuses to boot into it.' },
  { id: 'downgrade', label: 'Push an old, buggy version', stops: 'version', result: 'Anti-rollback: the gateway will not offer it and the board will not accept it.' },
  { id: 'impersonate', label: 'Pretend to be another board', stops: 'tokens', result: 'The stolen token only works for the board it was issued to.' },
  { id: 'replay', label: 'Replay an old status packet', stops: 'encryption', result: 'The packet counter has moved on; the replay is discarded.' },
  { id: 'brick', label: 'Ship a build that cannot connect', stops: 'gate', result: 'It fails its health gate and the board rolls itself back.' },
];

export function DefenseStack() {
  const [selected, setSelected] = React.useState('signature');
  const [attack, setAttack] = React.useState<string | null>(null);
  const [hitKey, setHitKey] = React.useState(0);
  const current = LAYERS.find((layer) => layer.id === selected) ?? LAYERS[0];
  const currentAttack = ATTACKS.find((entry) => entry.id === attack);

  return (
    <div className="lp-defense">
      <div className="lp-layers" role="group" aria-label="Protection layers">
        {LAYERS.map((layer, index) => (
          <button
            // Remount the struck layer on each new attack so the shake replays.
            key={currentAttack?.stops === layer.id ? `${layer.id}-${hitKey}` : layer.id}
            type="button"
            className="lp-layer"
            aria-pressed={selected === layer.id}
            data-hit={currentAttack?.stops === layer.id ? 'true' : 'false'}
            onClick={() => {
              setSelected(layer.id);
              setAttack(null);
            }}
          >
            <span className="lp-layer-idx">{String(index + 1).padStart(2, '0')}</span>
            {layer.name}
          </button>
        ))}
      </div>

      <div className="lp-card" style={{ padding: 28, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="lp-eyebrow">Try to break it</div>
        <div className="lp-attacks" role="group" aria-label="Attacks" style={{ marginTop: 0 }}>
          {ATTACKS.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className="lp-attack"
              aria-pressed={attack === entry.id}
              onClick={() => {
                setAttack(entry.id);
                setSelected(entry.stops);
                setHitKey((value) => value + 1);
              }}
            >
              {entry.label}
            </button>
          ))}
        </div>
        <div aria-live="polite" style={{ borderTop: '1px solid rgba(255,255,255,.1)', paddingTop: 16, display: 'grid', gap: 10 }}>
          {currentAttack && (
            <p style={{ margin: 0, font: 'var(--type-body-strong)', color: '#fff' }}>
              Stopped by <span style={{ color: 'var(--amber)' }}>{current.name}</span>. {currentAttack.result}
            </p>
          )}
          <h3 style={{ margin: 0, font: 'var(--type-heading-sm)' }}>{current.name}</h3>
          <p style={{ margin: 0, font: 'var(--type-body-md)', color: 'var(--on-dark-muted)', textWrap: 'pretty' }}>{current.detail}</p>
        </div>
      </div>
    </div>
  );
}
