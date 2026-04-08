import { execFileSync } from 'node:child_process';
import { platform } from 'node:os';
import { NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

type SerialPortPayload = {
  path: string;
  manufacturer: string | null;
  serialNumber: string | null;
  vendorId: string | null;
  productId: string | null;
  description: string;
};

export async function GET() {
  try {
    if (platform() !== 'win32') {
      return NextResponse.json({
        ok: true,
        detected: false,
        count: 0,
        ports: [],
        error: 'Automatic COM detection is currently supported on Windows hosts only.',
      });
    }

    const rawOutput = execFileSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        "Get-CimInstance Win32_SerialPort | Select-Object DeviceID, Name, Description, PNPDeviceID | ConvertTo-Json -Depth 4 -Compress",
      ],
      {
        encoding: 'utf8',
        windowsHide: true,
        timeout: 5000,
      }
    );

    const parsed = rawOutput.trim() ? JSON.parse(rawOutput) : [];
    const records = Array.isArray(parsed) ? parsed : [parsed];

    const mappedPorts: SerialPortPayload[] = records
      .filter((record) => record && typeof record === 'object')
      .map((record: any) => {
        const path = String(record.DeviceID || '').trim();
        const descriptionParts = [
          record.Name ? String(record.Name) : null,
          record.Description ? String(record.Description) : null,
          record.PNPDeviceID ? `PNP ${String(record.PNPDeviceID)}` : null,
        ].filter(Boolean);

        return {
          path,
          manufacturer: record.Description ? String(record.Description) : null,
          serialNumber: record.PNPDeviceID ? String(record.PNPDeviceID) : null,
          vendorId: null,
          productId: null,
          description: descriptionParts.length > 0 ? descriptionParts.join(' · ') : 'Windows serial device',
        };
      })
      .filter((port) => port.path.length > 0)
      .sort((left, right) => left.path.localeCompare(right.path, undefined, { numeric: true, sensitivity: 'base' }));

    return NextResponse.json({
      ok: true,
      detected: mappedPorts.length > 0,
      count: mappedPorts.length,
      ports: mappedPorts,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unable to enumerate serial ports.';

    return NextResponse.json(
      {
        ok: false,
        detected: false,
        count: 0,
        ports: [],
        error: message,
      },
      { status: 500 }
    );
  }
}