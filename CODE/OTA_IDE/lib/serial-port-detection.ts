import { execFileSync } from 'node:child_process';
import { platform } from 'node:os';

export type DetectedSerialPort = {
  path: string;
  manufacturer: string | null;
  serialNumber: string | null;
  vendorId: string | null;
  productId: string | null;
  description: string;
  pnpDeviceId: string | null;
};

export type DetectSerialPortsResult = {
  supported: boolean;
  detected: boolean;
  count: number;
  ports: DetectedSerialPort[];
  error?: string;
};

function parsePnPIdentifier(pnpDeviceId: string | null) {
  if (!pnpDeviceId) {
    return { vendorId: null, productId: null };
  }

  const vendorMatch = pnpDeviceId.match(/VID_([0-9A-F]{4})/i);
  const productMatch = pnpDeviceId.match(/PID_([0-9A-F]{4})/i);

  return {
    vendorId: vendorMatch ? vendorMatch[1].toUpperCase() : null,
    productId: productMatch ? productMatch[1].toUpperCase() : null,
  };
}

function normalizePortPath(pathValue: string) {
  return pathValue.trim().replace(/^\\\\\.\\/, '').toUpperCase();
}

function buildDescription(record: {
  name: string | null;
  description: string | null;
  manufacturer: string | null;
  pnpDeviceId: string | null;
}) {
  const parts = [
    record.name,
    record.description,
    record.manufacturer,
    record.pnpDeviceId ? `PNP ${record.pnpDeviceId}` : null,
  ].filter(Boolean);

  if (parts.length === 0) {
    return 'Connected USB serial device';
  }

  return parts.join(' · ');
}

export function detectConnectedSerialPorts(): DetectSerialPortsResult {
  if (platform() !== 'win32') {
    return {
      supported: false,
      detected: false,
      count: 0,
      ports: [],
      error: 'Automatic COM detection is currently supported on Windows hosts only.',
    };
  }

  try {
    const rawOutput = execFileSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        "$ports = Get-CimInstance Win32_SerialPort | Where-Object { $_.DeviceID -match '^COM\\d+$' -and $_.PNPDeviceID -match '^(USB|FTDIBUS)\\\\' }; $ports | Select-Object DeviceID, Name, Description, Manufacturer, PNPDeviceID | ConvertTo-Json -Depth 4 -Compress",
      ],
      {
        encoding: 'utf8',
        windowsHide: true,
        timeout: 5000,
      }
    );

    const parsed = rawOutput.trim() ? JSON.parse(rawOutput) : [];
    const records = Array.isArray(parsed) ? parsed : [parsed];

    const mapped = records
      .filter((record) => record && typeof record === 'object')
      .map((record) => {
        const row = record as {
          DeviceID?: string;
          Name?: string;
          Description?: string;
          Manufacturer?: string;
          PNPDeviceID?: string;
        };

        const path = String(row.DeviceID || '').trim();
        const normalized = normalizePortPath(path);
        const pnpDeviceId = row.PNPDeviceID ? String(row.PNPDeviceID) : null;
        const identifiers = parsePnPIdentifier(pnpDeviceId);

        return {
          path: normalized,
          manufacturer: row.Manufacturer ? String(row.Manufacturer) : null,
          serialNumber: pnpDeviceId,
          vendorId: identifiers.vendorId,
          productId: identifiers.productId,
          pnpDeviceId,
          description: buildDescription({
            name: row.Name ? String(row.Name) : null,
            description: row.Description ? String(row.Description) : null,
            manufacturer: row.Manufacturer ? String(row.Manufacturer) : null,
            pnpDeviceId,
          }),
        } satisfies DetectedSerialPort;
      })
      .filter((port) => port.path.length > 0)
      .sort((left, right) => left.path.localeCompare(right.path, undefined, { numeric: true, sensitivity: 'base' }));

    return {
      supported: true,
      detected: mapped.length > 0,
      count: mapped.length,
      ports: mapped,
    };
  } catch (error) {
    return {
      supported: true,
      detected: false,
      count: 0,
      ports: [],
      error: error instanceof Error ? error.message : 'Unable to scan connected COM devices.',
    };
  }
}

export function normalizeComPortName(pathValue: string) {
  return normalizePortPath(pathValue);
}

export function isConnectedComPort(pathValue: string, ports: DetectedSerialPort[]) {
  const target = normalizePortPath(pathValue);
  return ports.some((port) => normalizePortPath(port.path) === target);
}
