import net from 'node:net';

export type DiscoveredHost = {
  ip: string;
  openPorts: number[];
  latencyMs: number;
  likelyRole: string;
};

export type NetworkScanResult = {
  cidr: string;
  scannedHosts: number;
  probedPorts: number[];
  found: DiscoveredHost[];
  durationMs: number;
};

// Ports that an ESP-class OTA device tends to answer on: 3232 is the ArduinoOTA
// listener, 80/8080 a status/web endpoint, 8266 the common ESP8266 OTA port.
const defaultProbePorts = [3232, 80, 8266, 8080];
const connectTimeoutMs = Number(process.env.OTA_SCAN_TIMEOUT_MS || 400);
const scanConcurrency = Number(process.env.OTA_SCAN_CONCURRENCY || 48);

function classifyRole(openPorts: number[]): string {
  if (openPorts.includes(3232) || openPorts.includes(8266)) {
    return 'OTA-capable device';
  }
  if (openPorts.includes(80) || openPorts.includes(8080)) {
    return 'HTTP endpoint';
  }
  return 'Responding host';
}

function probePort(ip: string, port: number): Promise<number | null> {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const socket = new net.Socket();
    let settled = false;

    const finish = (open: boolean) => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve(open ? Date.now() - startedAt : null);
    };

    socket.setTimeout(connectTimeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));

    try {
      socket.connect(port, ip);
    } catch {
      finish(false);
    }
  });
}

async function probeHost(ip: string, ports: number[]): Promise<DiscoveredHost | null> {
  const results = await Promise.all(ports.map((port) => probePort(ip, port)));
  const openPorts: number[] = [];
  let bestLatency = Number.POSITIVE_INFINITY;

  results.forEach((latency, index) => {
    if (latency !== null) {
      openPorts.push(ports[index]);
      bestLatency = Math.min(bestLatency, latency);
    }
  });

  if (openPorts.length === 0) {
    return null;
  }

  return {
    ip,
    openPorts,
    latencyMs: Number.isFinite(bestLatency) ? bestLatency : 0,
    likelyRole: classifyRole(openPorts),
  };
}

function enumerateHosts(cidr: string): string[] {
  const [ip, prefixRaw] = cidr.split('/');
  const prefix = Number(prefixRaw || 24);
  const octets = ip.split('.').map((part) => Number(part));

  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n))) {
    throw new Error(`Invalid subnet: ${cidr}`);
  }

  // Only /24 (or narrower) sweeps are allowed — a wider range is thousands of
  // sockets and is refused rather than silently hammering the LAN.
  if (prefix < 24) {
    throw new Error('Network scan is limited to /24 subnets or smaller.');
  }

  const mask = prefix >= 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  const base = (((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) & mask) >>> 0;
  const hostCount = prefix >= 31 ? 2 : (2 ** (32 - prefix)) - 2;

  const hosts: string[] = [];
  for (let i = 1; i <= hostCount; i += 1) {
    const addr = (base + i) >>> 0;
    hosts.push(
      [(addr >>> 24) & 0xff, (addr >>> 16) & 0xff, (addr >>> 8) & 0xff, addr & 0xff].join('.')
    );
  }
  return hosts;
}

export async function scanNetwork(cidr: string, ports: number[] = defaultProbePorts): Promise<NetworkScanResult> {
  const startedAt = Date.now();
  const hosts = enumerateHosts(cidr);
  const found: DiscoveredHost[] = [];

  // Fixed-size worker pool over the host list keeps the socket count bounded no
  // matter how large the subnet.
  let cursor = 0;
  async function worker() {
    while (cursor < hosts.length) {
      const index = cursor;
      cursor += 1;
      const result = await probeHost(hosts[index], ports);
      if (result) {
        found.push(result);
      }
    }
  }

  const workerCount = Math.min(scanConcurrency, hosts.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));

  found.sort((left, right) =>
    left.ip.localeCompare(right.ip, undefined, { numeric: true, sensitivity: 'base' })
  );

  return {
    cidr,
    scannedHosts: hosts.length,
    probedPorts: ports,
    found,
    durationMs: Date.now() - startedAt,
  };
}
