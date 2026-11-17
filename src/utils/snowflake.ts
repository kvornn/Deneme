import type { SnowflakeInfo } from '../types/intel';

export const DISCORD_EPOCH = 1420070400000n;
const MAX_UINT64 = (1n << 64n) - 1n;

export function isValidSnowflake(raw: string): boolean {
  const cleaned = raw.trim();
  if (!/^\d{17,20}$/.test(cleaned)) {
    return false;
  }
  try {
    const val = BigInt(cleaned);
    if (val < 4194304n || val > MAX_UINT64) {
      return false;
    }
    const timestampMs = Number((val >> 22n) + DISCORD_EPOCH);
    if (!Number.isFinite(timestampMs)) {
      return false;
    }
    // Must be on or after Discord Epoch (2015-01-01) and not absurdly far in future
    return timestampMs >= Number(DISCORD_EPOCH) && timestampMs <= Date.now() + 365 * 24 * 60 * 60 * 1000;
  } catch {
    return false;
  }
}

export function calculateAge(createdAtMs: number, referenceMs: number = Date.now()): {
  years: number;
  months: number;
  days: number;
  totalDays: number;
} {
  const diffMs = Math.max(0, referenceMs - createdAtMs);
  const totalDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  const start = new Date(createdAtMs);
  const end = new Date(Math.max(createdAtMs, referenceMs));

  let years = end.getUTCFullYear() - start.getUTCFullYear();
  let months = end.getUTCMonth() - start.getUTCMonth();
  let days = end.getUTCDate() - start.getUTCDate();

  if (days < 0) {
    months -= 1;
    const prevMonth = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), 0));
    days += prevMonth.getUTCDate();
  }
  if (months < 0) {
    years -= 1;
    months += 12;
  }

  return {
    years: Math.max(0, years),
    months: Math.max(0, months),
    days: Math.max(0, days),
    totalDays,
  };
}

export function decodeSnowflake(raw: string, referenceMs: number = Date.now()): SnowflakeInfo | null {
  const cleaned = raw.trim();
  if (!isValidSnowflake(cleaned)) {
    return null;
  }

  const snowflake = BigInt(cleaned);
  const timestampMs = Number((snowflake >> 22n) + DISCORD_EPOCH);
  const workerId = Number((snowflake & 0x3e0000n) >> 17n);
  const processId = Number((snowflake & 0x1f000n) >> 12n);
  const increment = Number(snowflake & 0xfffn);
  const binary64 = snowflake.toString(2).padStart(64, '0');

  return {
    id: cleaned,
    timestampMs,
    createdAtIso: new Date(timestampMs).toISOString(),
    workerId,
    processId,
    increment,
    binary64,
    accountAge: calculateAge(timestampMs, referenceMs),
  };
}

export function formatTurkishDate(isoString: string): string {
  try {
    return new Intl.DateTimeFormat('tr-TR', {
      year: 'numeric',
      month: 'long',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    }).format(new Date(isoString));
  } catch {
    return isoString;
  }
}
