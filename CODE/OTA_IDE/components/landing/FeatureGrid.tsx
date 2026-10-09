'use client';

import React from 'react';
import Link from 'next/link';
import { Activity, ArrowRight, Globe, History, KeyRound, Rocket, ShieldCheck } from 'lucide-react';
import { Reveal } from './Reveal';
import { trackPointer } from './motion';

const FEATURES = [
  {
    icon: Globe,
    title: 'Reach boards anywhere',
    copy: 'Restart, identify or update a board from the browser. Commands ride back on its heartbeat, so it works behind home routers and campus NAT.',
    href: '/devices',
  },
  {
    icon: KeyRound,
    title: 'Set up over the cable',
    copy: 'Flash a release and hand the board its Wi-Fi, gateway address and its own token through the COM port. One binary fits every board.',
    href: '/devices',
  },
  {
    icon: ShieldCheck,
    title: 'Updates that undo themselves',
    copy: 'A new image has 120 seconds to prove it can reach the gateway. If it cannot, the board boots the previous firmware on its own.',
    href: '/deployments',
  },
  {
    icon: Rocket,
    title: 'Roll out to the fleet',
    copy: 'Pick a release and a set of boards. Watch each one download, reboot and confirm, then retry only the ones that failed.',
    href: '/deployments',
  },
  {
    icon: Activity,
    title: 'Live health and history',
    copy: 'Health score, Wi-Fi signal and memory per board over the last week, with every firmware change marked. Pages update as it happens.',
    href: '/devices',
  },
  {
    icon: History,
    title: 'A record of every change',
    copy: 'Who deployed, restarted or removed what, from where, and what the gateway refused. Nothing changes without a name on it.',
    href: '/audit',
  },
];

export function FeatureGrid() {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
        gap: 16,
        marginTop: 44,
      }}
    >
      {FEATURES.map((feature, index) => {
        const Icon = feature.icon;
        return (
          <Reveal key={feature.title} delay={(index % 3) * 90} style={{ height: '100%' }}>
            <Link
              href={`/login?next=${encodeURIComponent(feature.href)}`}
              className="lp-card lp-spot lp-feature"
              onPointerMove={trackPointer}
            >
              <span className="lp-feature-icon" aria-hidden="true">
                <Icon size={20} />
              </span>
              <h3>{feature.title}</h3>
              <p>{feature.copy}</p>
              <span className="lp-more">
                Try it <ArrowRight size={14} />
              </span>
            </Link>
          </Reveal>
        );
      })}
    </div>
  );
}
