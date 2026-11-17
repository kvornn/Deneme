import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  keyPrefix: string;
  message?: string;
  violationWeight?: number;
}

interface RateBucket {
  timestamps: number[];
}

interface IpViolationState {
  score: number;
  windowStart: number;
  blockedUntil: number;
}

const buckets = new Map<string, RateBucket>();
const ipViolations = new Map<string, IpViolationState>();

const VIOLATION_WINDOW_MS = 10 * 60 * 1000;
const VIOLATION_THRESHOLD = 8;
const IP_BLOCK_DURATION_MS = 20 * 60 * 1000;

// Periodically prune expired buckets and IP blocks to prevent memory exhaustion under DDoS
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets.entries()) {
    if (bucket.timestamps.length === 0 || now - bucket.timestamps[bucket.timestamps.length - 1] > 30 * 60 * 1000) {
      buckets.delete(key);
    }
  }
  for (const [ip, state] of ipViolations.entries()) {
    if (state.blockedUntil <= now && now - state.windowStart > VIOLATION_WINDOW_MS) {
      ipViolations.delete(ip);
    }
  }
}, 5 * 60 * 1000).unref();

export function getClientIp(req: Request): string {
  // Rely on Express trust proxy (req.ip) so attackers cannot spoof leftmost X-Forwarded-For headers
  if (req.ip && req.ip.trim()) {
    return req.ip.trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

const RESERVED_USERNAMES = new Set([
  'admin',
  'admin_root',
  'administrator',
  'root',
  'system',
  'sistem',
  'yonetici',
  'sistem_yoneticisi',
  'sistemyoneticisi',
  'sentarika',
  'moderator',
  'mod',
  'staff',
  'support',
  'destek',
  'owner',
  'kurucu',
  'superadmin',
]);

export function isReservedUsername(username: string): boolean {
  const clean = username.trim().toLowerCase();
  if (!clean) return false;
  if (RESERVED_USERNAMES.has(clean)) return true;
  return (
    clean.startsWith('admin_') ||
    clean.startsWith('admin.') ||
    clean.startsWith('admin-') ||
    clean.startsWith('sistem_') ||
    clean.startsWith('sentarika_')
  );
}

export function isIpTemporarilyBlocked(ip: string): { blocked: boolean; retryAfterSec: number } {
  const state = ipViolations.get(ip);
  if (!state) return { blocked: false, retryAfterSec: 0 };
  const now = Date.now();
  if (state.blockedUntil > now) {
    return { blocked: true, retryAfterSec: Math.max(1, Math.ceil((state.blockedUntil - now) / 1000)) };
  }
  return { blocked: false, retryAfterSec: 0 };
}

export function recordIpViolation(ip: string, weight = 1) {
  const now = Date.now();
  let state = ipViolations.get(ip);
  if (!state || now - state.windowStart > VIOLATION_WINDOW_MS) {
    state = { score: 0, windowStart: now, blockedUntil: 0 };
    ipViolations.set(ip, state);
  }
  state.score += Math.max(1, weight);
  if (state.score >= VIOLATION_THRESHOLD) {
    state.blockedUntil = now + IP_BLOCK_DURATION_MS;
  }
}

export function ipShieldMiddleware(req: Request, res: Response, next: NextFunction) {
  const ip = getClientIp(req);
  const status = isIpTemporarilyBlocked(ip);
  if (status.blocked) {
    res.setHeader('Retry-After', String(status.retryAfterSec));
    res.status(429).json({
      error: 'Güvenlik kalkanı: Çok fazla şüpheli veya aşırı istek nedeniyle IP adresiniz geçici olarak engellendi.',
      retryAfterSec: status.retryAfterSec,
    });
    return;
  }
  next();
}

export function createRateLimiter(options: RateLimitOptions) {
  return (req: Request, res: Response, next: NextFunction) => {
    const ip = getClientIp(req);
    const key = `${options.keyPrefix}:${ip}`;
    const now = Date.now();
    const cutoff = now - options.windowMs;

    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { timestamps: [] };
      buckets.set(key, bucket);
    }

    bucket.timestamps = bucket.timestamps.filter((ts) => ts > cutoff);

    if (bucket.timestamps.length >= options.maxRequests) {
      recordIpViolation(ip, options.violationWeight ?? 1);
      const oldest = bucket.timestamps[0];
      const retryAfterSec = Math.max(1, Math.ceil((oldest + options.windowMs - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
      res.setHeader('X-RateLimit-Remaining', '0');
      res.status(429).json({
        error: options.message || 'Çok fazla istek gönderildi. Lütfen kısa süre bekleyip tekrar deneyin.',
        retryAfterSec,
      });
      return;
    }

    bucket.timestamps.push(now);
    res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, options.maxRequests - bucket.timestamps.length)));
    next();
  };
}

export function resetRateLimitKey(keyPrefix: string, ip: string): void {
  buckets.delete(`${keyPrefix}:${ip}`);
}

export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  // allow-popups keeps Firebase Google Sign-In popup communication intact
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader(
    'Content-Security-Policy',
    "object-src 'none'; base-uri 'self'; form-action 'self'; script-src 'self' 'unsafe-inline' https://apis.google.com https://www.gstatic.com https://accounts.google.com",
  );
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

function stripDangerousKeys(value: unknown, depth = 0): void {
  if (!value || typeof value !== 'object' || depth > 20) return;
  if (Array.isArray(value)) {
    for (const item of value) stripDangerousKeys(item, depth + 1);
    return;
  }
  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      delete obj[key];
      continue;
    }
    stripDangerousKeys(obj[key], depth + 1);
  }
}

export function sanitizeRequestBodyMiddleware(req: Request, _res: Response, next: NextFunction) {
  if (req.body && typeof req.body === 'object') {
    stripDangerousKeys(req.body);
  }
  next();
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  if (!salt || !keyHex) return false;
  try {
    const expected = Buffer.from(keyHex, 'hex');
    const actual = crypto.scryptSync(password, salt, 64);
    if (expected.length !== actual.length) return false;
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

export function generateThirtyDigitKey(): string {
  let digits = '';
  for (let i = 0; i < 30; i++) {
    digits += String(crypto.randomInt(0, 10));
  }
  return digits;
}

export function hashAdminKey(key: string): string {
  return crypto.createHash('sha256').update(key, 'utf8').digest('hex');
}

export function verifyAdminKey(candidateKey: string, storedSha256Hex: string): boolean {
  const cleaned = candidateKey.trim();
  if (!/^\d{30}$/.test(cleaned)) return false;
  try {
    const candidateHash = Buffer.from(hashAdminKey(cleaned), 'hex');
    const storedHash = Buffer.from(storedSha256Hex, 'hex');
    if (candidateHash.length !== storedHash.length) return false;
    return crypto.timingSafeEqual(candidateHash, storedHash);
  } catch {
    return false;
  }
}

export interface SessionPayload {
  userId: string;
  role: string;
  exp: number;
  epoch?: string;
  adminGrant?: boolean;
  adminEpoch?: string;
}

export function signSessionToken(payload: SessionPayload, secret: string): string {
  const data = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

export function verifySessionToken(token: string, secret: string): SessionPayload | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  if (!data || !sig) return null;
  try {
    const expectedSig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
    const sigBuf = Buffer.from(sig, 'utf8');
    const expBuf = Buffer.from(expectedSig, 'utf8');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8')) as SessionPayload;
    if (!parsed || typeof parsed.userId !== 'string' || typeof parsed.role !== 'string' || typeof parsed.exp !== 'number') {
      return null;
    }
    if (Date.now() > parsed.exp) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function verifyAdminSessionClaim(payload: SessionPayload | null, expectedAdminEpoch: string): boolean {
  if (!payload) return false;
  if (payload.userId !== 'admin_root') return false;
  if (payload.role !== 'Admin') return false;
  if (payload.adminGrant !== true) return false;
  if (!payload.adminEpoch || payload.adminEpoch !== expectedAdminEpoch) return false;
  return true;
}

const SENSITIVE_PATH_RE =
  /^\/(data|server|\.git|\.env|\.aistudio|\.dockerignore|dockerfile|render\.yaml|package\.json|package-lock\.json|tsconfig\.json|vite\.config|firebase-blueprint\.json|firebase-applet-config\.json|firestore\.rules|eslint\.config)/i;
const SENSITIVE_EXT_RE = /\.(key|log|bak|sql|env|rules)$/i;

export function isSensitiveHttpPath(rawPath: string): boolean {
  let decoded = rawPath;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return true;
  }
  if (decoded.includes('..') || decoded.includes('\0') || decoded.includes('\\')) {
    return true;
  }
  const normalized = decoded.replace(/\/+/g, '/').replace(/^\/(?:\.\/)+/, '/');
  if (SENSITIVE_PATH_RE.test(normalized) || SENSITIVE_EXT_RE.test(normalized)) {
    return true;
  }
  return false;
}

export function sanitizeString(val: unknown, maxLen = 500): string {
  if (typeof val !== 'string') return '';
  return val.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim().slice(0, maxLen);
}

export function sanitizeExtraObject(obj: unknown): Record<string, string> {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    const cleanKey = sanitizeString(k, 100);
    if (!cleanKey) continue;
    out[cleanKey] = sanitizeString(typeof v === 'string' ? v : String(v ?? ''), 1500);
  }
  return out;
}
