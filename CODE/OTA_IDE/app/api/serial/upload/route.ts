import { NextResponse } from 'next/server';
import { z } from 'zod';
import { withSecureApi } from '@/lib/api-security';
import { startSerialUpload } from '@/lib/serial-upload-jobs';
import { isAccessGranted } from '@/lib/host-access';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const uploadSchema = z.object({
  filePath: z.string().trim().min(1),
  boardType: z.enum(['ATmega328P', 'ESP8266', 'ESP32', 'STM32F103']),
  comPort: z.string().trim().min(3).max(16),
  baudRate: z.string().trim().min(3).max(16),
  // Baked into ota_config.h at compile time for WiFi-capable boards. 32 is the
  // IEEE 802.11 SSID limit; 64 the WPA passphrase limit. The password is not
  // trimmed — leading and trailing spaces are legal in a WPA passphrase.
  wifiSsid: z.string().trim().max(32).optional(),
  wifiPassword: z.string().max(64).optional(),
});

export async function POST(request: Request) {
  return withSecureApi(
    request,
    '/api/serial/upload',
    async ({ auth }) => {
      const payload = uploadSchema.parse(await request.json());
      const userId = auth?.user.id;

      if (!userId) {
        return NextResponse.json(
          {
            ok: false,
            error: 'User session is missing.',
          },
          { status: 401 }
        );
      }

      // Consent gate: flashing over a physical COM port requires an explicit,
      // unexpired grant on that exact port. Detection alone is not permission.
      const portGranted = await isAccessGranted(userId, 'serial', payload.comPort);
      if (!portGranted) {
        return NextResponse.json(
          {
            ok: false,
            error: `Access to ${payload.comPort.toUpperCase()} has not been granted. Grant it under Host Access, then retry the flash.`,
            requiresGrant: { resourceType: 'serial', resourceId: payload.comPort },
          },
          { status: 403 }
        );
      }

      const uploadJob = await startSerialUpload({
        ...payload,
        userId,
      });

      return NextResponse.json({
        ok: true,
        jobId: uploadJob.jobId,
        status: uploadJob.status,
        progress: uploadJob.progress,
      });
    },
    { requireAuth: true }
  );
}
