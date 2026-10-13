import fs from 'node:fs/promises';
import path from 'node:path';
import { ImageResponse } from 'next/og';
import { SITE_NAME } from '@/lib/site';

/**
 * The card shown when the site is shared (Open Graph / X). Generated once at
 * build time from the real logo; no external fonts or services.
 */
export const alt = 'SecureOTA: signed, verified firmware updates for ESP32 fleets';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default async function OpenGraphImage() {
  const logo = await fs.readFile(path.join(process.cwd(), 'public/brand/logo-secureota.png'));
  const logoSrc = `data:image/png;base64,${logo.toString('base64')}`;

  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '72px 80px',
          background: 'radial-gradient(120% 90% at 85% 20%, #3a0a00 0%, #0d0d0d 60%)',
          color: '#ffffff',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 22 }}>
          <img src={logoSrc} width={88} height={88} alt="" />
          <div style={{ display: 'flex', fontSize: 52, fontWeight: 700, letterSpacing: -1 }}>
            <span>secure</span>
            <span style={{ color: '#ff2803' }}>ota</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
          <div style={{ fontSize: 66, fontWeight: 700, lineHeight: 1.08, letterSpacing: -1.5, maxWidth: 980 }}>
            Update every board, anywhere, without bricking it.
          </div>
          <div style={{ fontSize: 30, color: 'rgba(255,255,255,0.72)', maxWidth: 980 }}>
            Signed, verified over-the-air firmware for ESP32 fleets, with automatic rollback.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 14, fontSize: 24, color: '#ff9742' }}>
          <span>Signed</span>
          <span style={{ color: 'rgba(255,255,255,0.4)' }}>·</span>
          <span>Verified on the device</span>
          <span style={{ color: 'rgba(255,255,255,0.4)' }}>·</span>
          <span>Health-gated rollback</span>
          <span style={{ marginLeft: 'auto', color: 'rgba(255,255,255,0.55)' }}>{SITE_NAME}</span>
        </div>
      </div>
    ),
    size
  );
}
