import { NextResponse } from 'next/server';
import { withSecureApi } from '@/lib/api-security';
import { logger } from '@/lib/logger';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const gatewayUrl = (process.env.EDGE_GATEWAY_URL || 'http://localhost:5000').replace(/\/$/, '');
const gatewayApiKey = process.env.EDGE_GATEWAY_API_KEY?.trim();

// Matches the gateway's own ceiling (see routes/releases.py MAX_UPLOAD_BYTES).
const MAX_UPLOAD_BYTES = 32 * 1024 * 1024;
const UPLOAD_TIMEOUT_MS = 60_000;

const VERSION_PATTERN = /^\d+(\.\d+)*$/;

/**
 * Publish a firmware release from the dashboard.
 *
 * The browser posts the compiled .bin as multipart form data; this route
 * authenticates the dashboard session, then forwards the binary to the
 * gateway's /api/releases/upload with the shared gateway API key attached.
 * The browser never holds the gateway key.
 */
export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/firmware/publish',
    async () => {
      let form: FormData;
      try {
        form = await request.formData();
      } catch {
        return NextResponse.json(
          { ok: false, error: 'Expected a multipart form upload.' },
          { status: 400 }
        );
      }

      const file = form.get('file');
      if (!(file instanceof File)) {
        return NextResponse.json(
          { ok: false, error: 'Select a compiled firmware .bin file to publish.' },
          { status: 400 }
        );
      }

      if (!file.name.toLowerCase().endsWith('.bin')) {
        return NextResponse.json(
          { ok: false, error: `"${file.name}" is not a .bin file. Upload the compiled firmware binary.` },
          { status: 400 }
        );
      }

      if (file.size === 0) {
        return NextResponse.json(
          { ok: false, error: 'The selected firmware file is empty.' },
          { status: 400 }
        );
      }

      if (file.size > MAX_UPLOAD_BYTES) {
        return NextResponse.json(
          { ok: false, error: `Firmware exceeds the ${MAX_UPLOAD_BYTES / (1024 * 1024)} MB limit.` },
          { status: 413 }
        );
      }

      const rawVersion = String(form.get('version') || '').trim().replace(/^v/i, '');
      if (!VERSION_PATTERN.test(rawVersion)) {
        return NextResponse.json(
          { ok: false, error: 'Version must be numeric and dot-separated, for example 2.5.0.' },
          { status: 400 }
        );
      }

      const outbound = new FormData();
      outbound.set('file', file, file.name);
      outbound.set('version', rawVersion);
      outbound.set('description', String(form.get('description') || '').trim() || 'Firmware release uploaded from the OTA dashboard.');
      outbound.set('changelog', String(form.get('changelog') || '').trim() || 'Security and reliability updates.');
      outbound.set('compatible', String(form.get('compatible') || '').trim());

      const headers: Record<string, string> = {};
      if (gatewayApiKey) {
        headers['x-api-key'] = gatewayApiKey;
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), UPLOAD_TIMEOUT_MS);

      try {
        const response = await fetch(`${gatewayUrl}/api/releases/upload`, {
          method: 'POST',
          body: outbound,
          headers,
          signal: controller.signal,
        });

        const text = await response.text();
        let parsed: unknown = null;
        try {
          parsed = text ? JSON.parse(text) : null;
        } catch {
          parsed = null;
        }

        if (!response.ok) {
          const detail =
            (parsed as { detail?: string } | null)?.detail ||
            (parsed as { error?: string } | null)?.error ||
            text.slice(0, 300) ||
            `Gateway responded ${response.status}`;

          logger.error('FirmwarePublish', `Gateway rejected release ${rawVersion}`, detail);
          return NextResponse.json({ ok: false, error: detail }, { status: response.status });
        }

        const data = parsed as {
          release?: { version?: string };
          manifest?: { filename?: string; sha256?: string; size?: number };
        } | null;

        logger.info(
          'FirmwarePublish',
          `Published firmware v${rawVersion} (${file.size} bytes) from ${file.name}`
        );

        return NextResponse.json({
          ok: true,
          message: `Firmware v${rawVersion} published. Devices will pick it up on their next check.`,
          release: data?.release,
          manifest: data?.manifest,
        });
      } catch (error) {
        const aborted = error instanceof Error && error.name === 'AbortError';
        const message = aborted
          ? 'Upload to the gateway timed out.'
          : `Could not reach the gateway at ${gatewayUrl}.`;

        logger.error('FirmwarePublish', message, error);
        return NextResponse.json({ ok: false, error: message }, { status: 502 });
      } finally {
        clearTimeout(timeout);
      }
    },
    { requireAuth: true }
  );
}
