import { describe, expect, it } from 'vitest';
import { findInstalledCoreVersion } from '@/lib/toolchain';

describe('findInstalledCoreVersion', () => {
  it('reads the arduino-cli >= 0.35 {platforms: [...]} shape', () => {
    const json = JSON.stringify({ platforms: [{ id: 'arduino:avr', installed_version: '1.8.6' }, { id: 'esp32:esp32', installed_version: '2.0.17' }] });
    expect(findInstalledCoreVersion(json, 'esp32:esp32')).toBe('2.0.17');
  });

  it('reads the older bare-array shape', () => {
    const json = JSON.stringify([{ ID: 'esp32:esp32', Installed: '3.3.8' }]);
    expect(findInstalledCoreVersion(json, 'esp32:esp32')).toBe('3.3.8');
  });

  it('returns null when the core is missing or the output is not JSON', () => {
    expect(findInstalledCoreVersion(JSON.stringify({ platforms: [] }), 'esp32:esp32')).toBeNull();
    expect(findInstalledCoreVersion('Error: not json', 'esp32:esp32')).toBeNull();
  });
});
