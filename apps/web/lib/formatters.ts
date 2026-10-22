const utcDateFormatter = new Intl.DateTimeFormat('en-US', {
  timeZone: 'UTC',
  year: 'numeric',
  month: 'short',
  day: 'numeric',
});

const utcMonthShortFormatter = new Intl.DateTimeFormat('en-US', {
  timeZone: 'UTC',
  month: 'short',
});

const utcDateTimeFormatter = new Intl.DateTimeFormat('en-US', {
  timeZone: 'UTC',
  year: 'numeric',
  month: 'numeric',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit',
  hour12: true,
});

const utcTimeFormatter = new Intl.DateTimeFormat('en-US', {
  timeZone: 'UTC',
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit',
  hour12: true,
});

const numberFormatter = new Intl.NumberFormat('en-US');

export function formatUtcDate(value: Date | string | number) {
  return utcDateFormatter.format(new Date(value));
}

export function formatUtcMonthShort(value: Date | string | number) {
  return utcMonthShortFormatter.format(new Date(value));
}

export function formatUtcDateTime(value: Date | string | number) {
  return utcDateTimeFormatter.format(new Date(value));
}

export function formatUtcTime(value: Date | string | number) {
  return utcTimeFormatter.format(new Date(value));
}

export function formatNumber(value: number) {
  return numberFormatter.format(value);
}
export function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** Uptime the firmware reports, in seconds, as "3d 4h", "2h 15m" or "45s". */
export function formatUptime(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) return '0s';
  const s = Math.floor(seconds);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${s % 60}s`;
  return `${s}s`;
}
