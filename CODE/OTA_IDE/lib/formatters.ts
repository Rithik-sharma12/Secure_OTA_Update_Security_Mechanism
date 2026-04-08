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