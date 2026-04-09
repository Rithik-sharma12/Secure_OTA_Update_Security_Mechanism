import { NextResponse } from 'next/server';
import { z } from 'zod';
import { withSecureApi } from '@/lib/api-security';
import { startSerialUpload } from '@/lib/serial-upload-jobs';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const uploadSchema = z.object({
  filePath: z.string().trim().min(1),
  boardType: z.enum(['ATmega328P', 'ESP8266', 'ESP32', 'STM32F103']),
  comPort: z.string().trim().min(3).max(16),
  baudRate: z.string().trim().min(3).max(16),
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
