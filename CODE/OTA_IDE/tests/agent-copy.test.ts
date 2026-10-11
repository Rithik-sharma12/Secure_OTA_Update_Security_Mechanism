/**
 * The local agent exists twice: CODE/agent/secureota_agent.py is the source
 * (go-online.sh runs it), and public/agent/secureota_agent.py is the copy the
 * dashboard offers for download. They must not drift, or users download an
 * agent that behaves differently from the one the docs and scripts describe.
 *
 * After editing the agent:  cp ../agent/secureota_agent.py public/agent/
 */

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

describe('downloadable agent', () => {
  it('matches CODE/agent/secureota_agent.py', () => {
    const source = fs.readFileSync(path.resolve(__dirname, '..', '..', 'agent', 'secureota_agent.py'));
    const served = fs.readFileSync(path.resolve(__dirname, '..', 'public', 'agent', 'secureota_agent.py'));
    expect(served.equals(source)).toBe(true);
  });
});
