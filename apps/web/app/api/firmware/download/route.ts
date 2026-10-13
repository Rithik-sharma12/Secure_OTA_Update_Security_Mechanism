import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { logger } from '@/lib/logger';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const gatewayUrl = (process.env.EDGE_GATEWAY_URL || 'http://localhost:5000').replace(/\/$/, '');
const gatewayApiKey = process.env.EDGE_GATEWAY_API_KEY?.trim();

const FETCH_TIMEOUT_MS = 60_000;
const DEVICE_TYPE_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;

type GatewayManifest = {
  version?: string;
  filename?: string;
  sha256?: string;
  size?: number;
  securePackage?: boolean;
};

/**
 * The gateway answers a manifest miss with a structured `detail`, so the
 * dashboard can name the architectures that *do* have firmware instead of
 * only saying this one has none.
 */
type GatewayErrorDetail = {
  message?: string;
  deviceType?: string;
  version?: string;
  publishedDeviceTypes?: string[];
};

async function readGatewayDetail(response: Response): Promise<GatewayErrorDetail> {
  try {
    const payload = (await response.json()) as { detail?: GatewayErrorDetail | string };
    const detail = payload?.detail;
    if (typeof detail === 'string') return { message: detail };
    return detail && typeof detail === 'object' ? detail : {};
  } catch {
    // Non-JSON body (a proxy error page, say) — nothing to add.
    return {};
  }
}

/**
 * Fetch the newest published firmware binary for a device architecture.
 *
 * Used by the in-browser Web Serial flasher: the browser cannot read the
 * gateway directly (it is on the compose network, and the public tunnel is for
 * devices), so this route resolves the per-architecture manifest and streams
 * the cached .bin back with its version and checksum in headers. The binary is
 * the OTA app image, so it belongs at the app partition offset (0x10000), not 0x0.
 */
export async function GET(request: Request) {
  return withSecureApi(
    request,
    '/api/firmware/download',
    async () => {
      const deviceType = (new URL(request.url).searchParams.get('device_type') || 'ESP32').trim();
      if (!DEVICE_TYPE_PATTERN.test(deviceType)) {
        return NextResponse.json({ ok: false, error: 'Invalid device_type.' }, { status: 400 });
      }

      const imageKind = new URL(request.url).searchParams.get('image') === 'factory' ? 'factory' : 'app';

      const headers: Record<string, string> = {};
      if (gatewayApiKey) {
        headers['x-api-key'] = gatewayApiKey;
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

      try {
        // Factory image: the merged first-flash image for a blank board,
        // written at 0x0. The gateway serves it to the operator key only.
        if (imageKind === 'factory') {
          const factoryResponse = await fetch(
            `${gatewayUrl}/api/releases/factory?device_type=${encodeURIComponent(deviceType)}`,
            { headers, signal: controller.signal, cache: 'no-store' }
          );
          if (!factoryResponse.ok) {
            const detail = await readGatewayDetail(factoryResponse);
            return NextResponse.json(
              {
                ok: false,
                error:
                  detail.message ||
                  `Gateway factory image request failed (${factoryResponse.status}).`,
              },
              { status: factoryResponse.status === 404 ? 404 : 502 }
            );
          }
          const bytes = await factoryResponse.arrayBuffer();
          const version = factoryResponse.headers.get('X-Firmware-Version') || '';
          const filename = factoryResponse.headers.get('X-Firmware-Filename') || `firmware_v${version}_factory.bin`;
          logger.info('FirmwareDownload', `Served factory image ${filename} (${bytes.byteLength} bytes) for ${deviceType}`);
          return new NextResponse(bytes, {
            status: 200,
            headers: {
              'Content-Type': 'application/octet-stream',
              'Content-Length': String(bytes.byteLength),
              'Content-Disposition': `attachment; filename="${filename}"`,
              'Cache-Control': 'no-store',
              'X-Image-Kind': 'factory',
              'X-Firmware-Version': version,
              'X-Firmware-Filename': filename,
              'X-Firmware-Sha256': factoryResponse.headers.get('X-Firmware-Sha256') || '',
              'X-Latest-Version': factoryResponse.headers.get('X-Latest-Version') || version,
            },
          });
        }

        const manifestResponse = await fetch(
          `${gatewayUrl}/releases/latest/manifest?device_type=${encodeURIComponent(deviceType)}`,
          { headers, signal: controller.signal, cache: 'no-store' }
        );

        if (manifestResponse.status === 404) {
          const detail = await readGatewayDetail(manifestResponse);
          const published = (detail.publishedDeviceTypes || []).filter(Boolean);
          const alternatives = published.length > 0
            ? ` Published releases target ${published.join(', ')}.`
            : '';
          return NextResponse.json(
            {
              ok: false,
              error: `No firmware has been published for ${deviceType} yet.${alternatives} Publish a release on the Releases page, or choose a local .bin file.`,
              publishedDeviceTypes: published,
            },
            { status: 404 }
          );
        }
        if (!manifestResponse.ok) {
          const detail = await readGatewayDetail(manifestResponse);
          return NextResponse.json(
            {
              ok: false,
              error: detail.message || `Gateway manifest request failed (${manifestResponse.status}).`,
              publishedDeviceTypes: (detail.publishedDeviceTypes || []).filter(Boolean),
            },
            { status: 502 }
          );
        }

        const manifest = (await manifestResponse.json()) as GatewayManifest;
        // An encrypted OTA package is for the board's own update path; written
        // over USB it would put ciphertext in flash and the board would not
        // boot. The factory image is the USB route.
        if (manifest.securePackage) {
          return NextResponse.json(
            {
              ok: false,
              error:
                `v${manifest.version} is an encrypted OTA package and cannot be flashed over USB. ` +
                'Use Set up a new board (factory image) to bring a board up, then it updates over the air.',
            },
            { status: 409 }
          );
        }
        const filename = String(manifest.filename || '').trim();
        // Same shape the gateway's safe_cache_path accepts: a bare file name.
        if (!filename || filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
          return NextResponse.json({ ok: false, error: 'Gateway manifest has no usable filename.' }, { status: 502 });
        }

        const binaryResponse = await fetch(
          `${gatewayUrl}/releases/download/${encodeURIComponent(filename)}`,
          { headers, signal: controller.signal, cache: 'no-store' }
        );
        if (!binaryResponse.ok || !binaryResponse.body) {
          return NextResponse.json(
            { ok: false, error: `Gateway could not serve ${filename} (${binaryResponse.status}).` },
            { status: 502 }
          );
        }

        const bytes = await binaryResponse.arrayBuffer();
        logger.info('FirmwareDownload', `Served ${filename} (${bytes.byteLength} bytes) for ${deviceType} web flash`);

        return new NextResponse(bytes, {
          status: 200,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Content-Length': String(bytes.byteLength),
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Cache-Control': 'no-store',
            'X-Image-Kind': 'app',
            'X-Firmware-Version': String(manifest.version || ''),
            'X-Firmware-Filename': filename,
            'X-Firmware-Sha256': String(manifest.sha256 || ''),
          },
        });
      } catch (error) {
        const aborted = error instanceof Error && error.name === 'AbortError';
        const message = aborted
          ? 'Gateway download timed out.'
          : `Could not reach the gateway at ${gatewayUrl}.`;
        logger.error('FirmwareDownload', message, error);
        return NextResponse.json({ ok: false, error: message }, { status: 502 });
      } finally {
        clearTimeout(timeout);
      }
    },
    { requireAuth: true }
  );
}
