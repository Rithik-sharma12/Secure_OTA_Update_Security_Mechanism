import os from 'node:os';
import { accessGrantsStore, type AccessGrantRecord } from '@/lib/local-database';
import { detectConnectedSerialPorts, normalizeComPortName } from '@/lib/serial-port-detection';

export type GrantResourceType = 'serial' | 'network';

export type AccessGrant = {
  id: string;
  userId: string;
  resourceType: GrantResourceType;
  resourceId: string;
  label: string;
  grantedBy: string;
  grantedAt: string;
  expiresAt: number | null;
  active: boolean;
};

export type LocalNetwork = {
  cidr: string;
  address: string;
  netmask: string;
  interfaceName: string;
};

/**
 * How long a grant stays valid. Access to real hardware should not be permanent
 * and silent — an operator re-consents at least daily. Override with
 * OTA_ACCESS_GRANT_TTL_HOURS; 0 disables expiry.
 */
const grantTtlHours = Number(process.env.OTA_ACCESS_GRANT_TTL_HOURS ?? 12);

function normalizeResourceId(resourceType: GrantResourceType, resourceId: string): string {
  const trimmed = resourceId.trim();
  if (resourceType === 'serial') {
    return normalizeComPortName(trimmed);
  }
  return trimmed.toLowerCase();
}

function toGrant(record: AccessGrantRecord): AccessGrant {
  const expired = record.expiresAt !== null && record.expiresAt <= Date.now();
  return {
    id: String(record._id),
    userId: record.userId,
    resourceType: record.resourceType,
    resourceId: record.resourceId,
    label: record.label,
    grantedBy: record.grantedBy,
    grantedAt: record.grantedAt,
    expiresAt: record.expiresAt,
    active: !record.revoked && !expired,
  };
}

export async function listGrants(userId: string): Promise<AccessGrant[]> {
  const records = await accessGrantsStore.find({ userId, revoked: false });
  return records
    .map(toGrant)
    .filter((grant) => grant.active)
    .sort((left, right) => right.grantedAt.localeCompare(left.grantedAt));
}

export async function isAccessGranted(
  userId: string,
  resourceType: GrantResourceType,
  resourceId: string
): Promise<boolean> {
  const normalized = normalizeResourceId(resourceType, resourceId);
  const records = await accessGrantsStore.find({
    userId,
    resourceType,
    resourceId: normalized,
    revoked: false,
  });

  return records.some((record) => record.expiresAt === null || record.expiresAt > Date.now());
}

export async function grantAccess(input: {
  userId: string;
  grantedBy: string;
  resourceType: GrantResourceType;
  resourceId: string;
  label?: string;
}): Promise<AccessGrant> {
  const resourceId = normalizeResourceId(input.resourceType, input.resourceId);
  if (!resourceId) {
    throw new Error('A resource identifier is required to grant access.');
  }

  const expiresAt = grantTtlHours > 0 ? Date.now() + grantTtlHours * 3600_000 : null;

  // Re-granting the same resource refreshes the existing record rather than
  // stacking duplicates, so the grant list stays one row per resource.
  await accessGrantsStore.remove(
    { userId: input.userId, resourceType: input.resourceType, resourceId },
    { multi: true }
  );

  const record = await accessGrantsStore.insert({
    userId: input.userId,
    resourceType: input.resourceType,
    resourceId,
    label: input.label?.trim() || resourceId,
    grantedBy: input.grantedBy,
    grantedAt: new Date().toISOString(),
    expiresAt,
    revoked: false,
  });

  return toGrant(record);
}

export async function revokeAccess(userId: string, grantId: string): Promise<boolean> {
  const affected = await accessGrantsStore.update(
    { _id: grantId, userId },
    { $set: { revoked: true } },
    { multi: false }
  );
  return affected > 0;
}

/**
 * The primary /24 IPv4 network this host sits on. Used to scope a network
 * access grant and to seed the discovery sweep. Skips loopback and virtual
 * Docker/WSL bridges where possible by preferring the first non-internal IPv4.
 */
export function getLocalNetworks(): LocalNetwork[] {
  const interfaces = os.networkInterfaces();
  const networks: LocalNetwork[] = [];

  for (const [interfaceName, addresses] of Object.entries(interfaces)) {
    if (!addresses) {
      continue;
    }
    for (const addr of addresses) {
      if (addr.family !== 'IPv4' || addr.internal) {
        continue;
      }
      const cidr = addr.cidr || `${addr.address}/24`;
      networks.push({
        cidr: toNetworkCidr(cidr),
        address: addr.address,
        netmask: addr.netmask,
        interfaceName,
      });
    }
  }

  return networks;
}

/** Collapse a host CIDR (192.168.1.42/24) to its network address (192.168.1.0/24). */
export function toNetworkCidr(cidr: string): string {
  const [ip, prefixRaw] = cidr.split('/');
  const prefix = Number(prefixRaw || 24);
  const octets = ip.split('.').map((part) => Number(part));
  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n))) {
    return cidr;
  }

  const mask = prefix >= 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  const ipInt = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const netOctets = [
    (network >>> 24) & 0xff,
    (network >>> 16) & 0xff,
    (network >>> 8) & 0xff,
    network & 0xff,
  ];
  return `${netOctets.join('.')}/${prefix}`;
}

export async function getHostAccessState(userId: string) {
  const detection = detectConnectedSerialPorts();
  const networks = getLocalNetworks();
  const grants = await listGrants(userId);

  const grantedSerial = new Set(
    grants.filter((g) => g.resourceType === 'serial').map((g) => g.resourceId)
  );
  const grantedNetwork = new Set(
    grants.filter((g) => g.resourceType === 'network').map((g) => g.resourceId)
  );

  return {
    serial: {
      supported: detection.supported,
      error: detection.error,
      ports: detection.ports.map((port) => ({
        ...port,
        granted: grantedSerial.has(normalizeComPortName(port.path)),
      })),
    },
    networks: networks.map((network) => ({
      ...network,
      granted: grantedNetwork.has(network.cidr.toLowerCase()),
    })),
    grants,
  };
}
