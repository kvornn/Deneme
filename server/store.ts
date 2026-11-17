import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type {
  AdminUserRow,
  BlockedRegistrationAttempt,
  DatasetCategory,
  DatasetMeta,
  FieldMapping,
  IntelRecord,
  PublicUser,
  QueryAuditLog,
  RoleConfigMap,
  RolePermissions,
  StandardRole,
  UserRole,
} from '../src/types/intel.ts';
import { reNormalizeDatasetRecords } from '../src/utils/parser.ts';
import { buildSearchIndex, filterDatabaseRecords, type SearchIndex } from '../src/utils/search.ts';
import {
  hashAdminKey,
  hashPassword,
  isReservedUsername,
  verifyPassword,
} from './security.ts';

export interface StoredUser {
  id: string;
  email: string;
  username: string;
  displayName: string;
  passwordHash: string;
  googleUid?: string | null;
  role: StandardRole;
  emailVerified: boolean;
  banned: boolean;
  banReason: string;
  dailyUsed: number;
  usageDate: string;
  lastLoginAt: string | null;
  lastLoginIp: string | null;
  createdAt: string;
  acceptedTermsAt: string;
}

interface SecuritySecrets {
  sessionSecret: string;
  adminKeyHash: string;
  userTokenEpoch?: string;
  adminTokenEpoch?: string;
}

const DEFAULT_DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(process.cwd(), 'data'));

// Permanent 30-digit Admin Key SHA-256 hash (plaintext key is NEVER embedded in source code)
export const PERMANENT_ADMIN_KEY_HASH =
  '770e522311c4240efde91d07dd7035157c06776bcd48c7964a35530a6d2abca4';

// Deterministic server-side session HMAC fallback so signed sessions survive Cloud Run cold starts
const STABLE_SESSION_FALLBACK = crypto
  .createHmac('sha256', 'sentarika-archive-session-key-v1')
  .update(PERMANENT_ADMIN_KEY_HASH)
  .digest('hex');

const DEFAULT_ADMIN_TOKEN_EPOCH = 'adm_v1';

export const ADMIN_PERMISSIONS: RolePermissions = {
  dailyQueryLimit: 999999,
  canIdLookup: true,
  canBulkLookup: true,
  canEmailOsint: true,
  canViewUnmasked: true,
  canExport: false,
};

const DEFAULT_ROLES: RoleConfigMap = {
  Üye: {
    dailyQueryLimit: 25,
    canIdLookup: true,
    canBulkLookup: false,
    canEmailOsint: true,
    canViewUnmasked: true,
    canExport: false,
  },
  Destekçi: {
    dailyQueryLimit: 200,
    canIdLookup: true,
    canBulkLookup: true,
    canEmailOsint: true,
    canViewUnmasked: true,
    canExport: false,
  },
  İşletme: {
    dailyQueryLimit: 2500,
    canIdLookup: true,
    canBulkLookup: true,
    canEmailOsint: true,
    canViewUnmasked: true,
    canExport: false,
  },
};

function todayKey(): string {
  return new Date().toISOString().slice(0, 10);
}

function ensureDir(dirPath: string) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

function sanitizeShardName(datasetId: string): string {
  return datasetId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 120) || 'dataset';
}

function readJsonFile<T>(filePath: string, fallback: T): T {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function writeJsonFile(filePath: string, data: unknown) {
  ensureDir(path.dirname(filePath));
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

// Streamed chunked NDJSON writer prevents V8 giant-string OOM crashes on massive datasets
function writeNdjsonRecords(filePath: string, records: IntelRecord[]): number {
  ensureDir(path.dirname(filePath));
  const tmp = `${filePath}.tmp`;
  const fd = fs.openSync(tmp, 'w', 0o600);
  let totalBytes = 0;
  try {
    const CHUNK = 2000;
    for (let i = 0; i < records.length; i += CHUNK) {
      const slice = records.slice(i, i + CHUNK);
      let block = '';
      for (let j = 0; j < slice.length; j++) {
        block += `${JSON.stringify(slice[j])}\n`;
      }
      totalBytes += Buffer.byteLength(block, 'utf8');
      fs.writeSync(fd, block, undefined, 'utf8');
    }
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
  return totalBytes;
}

function appendNdjsonRecords(filePath: string, records: IntelRecord[]): number {
  if (records.length === 0) return 0;
  ensureDir(path.dirname(filePath));
  const fd = fs.openSync(filePath, 'a', 0o600);
  let addedBytes = 0;
  try {
    const CHUNK = 2000;
    for (let i = 0; i < records.length; i += CHUNK) {
      const slice = records.slice(i, i + CHUNK);
      let block = '';
      for (let j = 0; j < slice.length; j++) {
        block += `${JSON.stringify(slice[j])}\n`;
      }
      addedBytes += Buffer.byteLength(block, 'utf8');
      fs.writeSync(fd, block, undefined, 'utf8');
    }
  } finally {
    fs.closeSync(fd);
  }
  return addedBytes;
}

function readNdjsonRecords(filePath: string): IntelRecord[] {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, 'utf8');
  if (!raw) return [];
  const out: IntelRecord[] = [];
  let start = 0;
  const len = raw.length;
  while (start < len) {
    let end = raw.indexOf('\n', start);
    if (end === -1) end = len;
    const line = raw.slice(start, end).trim();
    start = end + 1;
    if (!line) continue;
    try {
      const parsed = JSON.parse(line) as IntelRecord;
      if (parsed && typeof parsed === 'object' && parsed.id) {
        out.push(parsed);
      }
    } catch {
      // Skip corrupted trailing line safely
    }
  }
  return out;
}

export class ServerStore {
  private readonly dataDir: string;
  private readonly usersFile: string;
  private readonly rolesFile: string;
  private readonly datasetsFile: string;
  private readonly legacyRecordsFile: string;
  private readonly logsFile: string;
  private readonly blockedAttemptsFile: string;
  private readonly secretsFile: string;
  private readonly adminKeyFile: string;

  private users: StoredUser[] = [];
  private roles: RoleConfigMap = structuredClone(DEFAULT_ROLES);
  private datasets: DatasetMeta[] = [];
  private records: IntelRecord[] = [];
  private queryLogs: QueryAuditLog[] = [];
  private blockedAttempts: BlockedRegistrationAttempt[] = [];
  private deletedDatasetIds = new Set<string>();
  private searchIndex: SearchIndex | null = null;
  private secrets!: SecuritySecrets;
  private adminDailyUsed = 0;
  private adminUsageDate = todayKey();

  constructor(customDataDir?: string) {
    this.dataDir = customDataDir ? path.resolve(customDataDir) : DEFAULT_DATA_DIR;
    this.usersFile = path.join(this.dataDir, 'users.json');
    this.rolesFile = path.join(this.dataDir, 'roles.json');
    this.datasetsFile = path.join(this.dataDir, 'datasets.json');
    this.legacyRecordsFile = path.join(this.dataDir, 'records.json');
    this.logsFile = path.join(this.dataDir, 'query_logs.json');
    this.blockedAttemptsFile = path.join(this.dataDir, 'blocked_attempts.json');
    this.secretsFile = path.join(this.dataDir, 'secrets.json');
    this.adminKeyFile = path.join(this.dataDir, 'admin.key');

    ensureDir(this.dataDir);
    this.initSecrets();
    this.users = readJsonFile<StoredUser[]>(this.usersFile, []);
    this.roles = readJsonFile<RoleConfigMap>(this.rolesFile, structuredClone(DEFAULT_ROLES));
    this.datasets = readJsonFile<DatasetMeta[]>(this.datasetsFile, []).map((d) => ({
      ...d,
      category: d.category || 'both',
    }));
    this.loadAllRecords();
    this.queryLogs = readJsonFile<QueryAuditLog[]>(this.logsFile, []);
    this.blockedAttempts = readJsonFile<BlockedRegistrationAttempt[]>(this.blockedAttemptsFile, []);

    if (!fs.existsSync(this.rolesFile)) {
      writeJsonFile(this.rolesFile, this.roles);
    }
  }

  private getDatasetShardPath(datasetId: string): string {
    return path.join(this.dataDir, `ds_${sanitizeShardName(datasetId)}.ndjson`);
  }

  private loadAllRecords() {
    const loaded: IntelRecord[] = [];
    let migratedFromLegacy = false;

    for (const ds of this.datasets) {
      const shardPath = this.getDatasetShardPath(ds.id);
      if (fs.existsSync(shardPath)) {
        const shardRecs = readNdjsonRecords(shardPath);
        for (let i = 0; i < shardRecs.length; i++) {
          loaded.push(shardRecs[i]);
        }
      }
    }

    // Backwards-compatible migration from monolithic data/records.json if present
    if (fs.existsSync(this.legacyRecordsFile)) {
      const legacy = readJsonFile<IntelRecord[]>(this.legacyRecordsFile, []);
      if (Array.isArray(legacy) && legacy.length > 0) {
        const existingShardIds = new Set(loaded.map((r) => r.datasetId));
        const byDs = new Map<string, IntelRecord[]>();
        for (const r of legacy) {
          if (!r || !r.datasetId || existingShardIds.has(r.datasetId)) continue;
          const bucket = byDs.get(r.datasetId);
          if (bucket) bucket.push(r);
          else byDs.set(r.datasetId, [r]);
        }
        for (const [dsId, recs] of byDs.entries()) {
          writeNdjsonRecords(this.getDatasetShardPath(dsId), recs);
          for (let i = 0; i < recs.length; i++) {
            loaded.push(recs[i]);
          }
          migratedFromLegacy = true;
        }
      }
      if (migratedFromLegacy || loaded.length > 0) {
        writeJsonFile(this.legacyRecordsFile, []);
      }
    }

    this.records = loaded;
  }

  private initSecrets() {
    const envAdminKey = process.env.ADMIN_ACCESS_KEY?.trim();
    const envSessionSecret = process.env.SESSION_SECRET?.trim();
    const resolvedAdminHash =
      envAdminKey && /^\d{30}$/.test(envAdminKey) ? hashAdminKey(envAdminKey) : PERMANENT_ADMIN_KEY_HASH;

    const existing = fs.existsSync(this.secretsFile)
      ? readJsonFile<SecuritySecrets | null>(this.secretsFile, null)
      : null;

    const resolvedSessionSecret = envSessionSecret || STABLE_SESSION_FALLBACK;
    const userTokenEpoch = existing?.userTokenEpoch || 'usr_v1';
    const adminTokenEpoch = existing?.adminTokenEpoch || DEFAULT_ADMIN_TOKEN_EPOCH;

    this.secrets = {
      sessionSecret: resolvedSessionSecret,
      adminKeyHash: resolvedAdminHash,
      userTokenEpoch,
      adminTokenEpoch,
    };

    if (
      !existing ||
      existing.sessionSecret !== this.secrets.sessionSecret ||
      existing.adminKeyHash !== this.secrets.adminKeyHash ||
      existing.userTokenEpoch !== this.secrets.userTokenEpoch ||
      existing.adminTokenEpoch !== this.secrets.adminTokenEpoch
    ) {
      writeJsonFile(this.secretsFile, this.secrets);
    }

    if (envAdminKey && /^\d{30}$/.test(envAdminKey)) {
      fs.writeFileSync(this.adminKeyFile, `${envAdminKey}\n`, { encoding: 'utf8', mode: 0o600 });
    }
  }

  getSessionSecret(): string {
    return this.secrets.sessionSecret;
  }

  getAdminKeyHash(): string {
    return this.secrets.adminKeyHash;
  }

  getUserTokenEpoch(): string {
    return this.secrets.userTokenEpoch || 'usr_v1';
  }

  getAdminTokenEpoch(): string {
    return this.secrets.adminTokenEpoch || DEFAULT_ADMIN_TOKEN_EPOCH;
  }

  kickAllUsers(clearAccounts = false): { kickedCount: number } {
    const prevCount = this.users.length;
    this.secrets.userTokenEpoch = crypto.randomBytes(8).toString('hex');
    writeJsonFile(this.secretsFile, this.secrets);
    if (clearAccounts) {
      this.users = [];
      writeJsonFile(this.usersFile, this.users);
    }
    return { kickedCount: prevCount };
  }

  getRoleConfigs(): RoleConfigMap {
    return structuredClone(this.roles);
  }

  updateRoleConfig(role: StandardRole, nextPerms: Partial<RolePermissions>): RoleConfigMap {
    const current = this.roles[role];
    if (!current) throw new Error('Geçersiz rol.');

    this.roles[role] = {
      dailyQueryLimit:
        typeof nextPerms.dailyQueryLimit === 'number' && Number.isFinite(nextPerms.dailyQueryLimit)
          ? Math.max(0, Math.min(1000000, Math.floor(nextPerms.dailyQueryLimit)))
          : current.dailyQueryLimit,
      canIdLookup: typeof nextPerms.canIdLookup === 'boolean' ? nextPerms.canIdLookup : current.canIdLookup,
      canBulkLookup: typeof nextPerms.canBulkLookup === 'boolean' ? nextPerms.canBulkLookup : current.canBulkLookup,
      canEmailOsint: typeof nextPerms.canEmailOsint === 'boolean' ? nextPerms.canEmailOsint : current.canEmailOsint,
      canViewUnmasked: true,
      canExport: false,
    };
    writeJsonFile(this.rolesFile, this.roles);
    return this.getRoleConfigs();
  }

  getPermissionsForRole(role: UserRole): RolePermissions {
    if (role === 'Admin') return ADMIN_PERMISSIONS;
    const base = this.roles[role] || this.roles.Üye;
    return { ...base, canViewUnmasked: true, canExport: false };
  }

  toPublicUser(user: StoredUser): PublicUser {
    const today = todayKey();
    const dailyUsed = user.usageDate === today ? user.dailyUsed : 0;
    return {
      id: user.id,
      email: user.email,
      username: user.username,
      displayName: user.displayName || user.username,
      role: user.role,
      emailVerified: Boolean(user.emailVerified),
      authProvider: user.googleUid ? 'google' : 'password',
      banned: user.banned,
      banReason: user.banReason,
      dailyUsed,
      usageDate: today,
      lastLoginAt: user.lastLoginAt || null,
      createdAt: user.createdAt,
      permissions: this.getPermissionsForRole(user.role),
    };
  }

  getAdminPublicProfile(): PublicUser {
    const today = todayKey();
    if (this.adminUsageDate !== today) {
      this.adminUsageDate = today;
      this.adminDailyUsed = 0;
    }
    return {
      id: 'admin_root',
      email: '',
      username: 'Sistem Yöneticisi',
      displayName: 'Sistem Yöneticisi',
      role: 'Admin',
      emailVerified: true,
      banned: false,
      banReason: '',
      dailyUsed: this.adminDailyUsed,
      usageDate: today,
      lastLoginAt: new Date().toISOString(),
      createdAt: new Date(0).toISOString(),
      permissions: ADMIN_PERMISSIONS,
    };
  }

  suggestUsername(email: string, displayName: string): string {
    const rawBase = (displayName || email.split('@')[0] || 'uye')
      .toLowerCase()
      .replace(/[^a-z0-9_.-]+/g, '_')
      .replace(/^[._-]+|[._-]+$/g, '')
      .slice(0, 22);
    const safeBase = rawBase.length >= 3 && !isReservedUsername(rawBase) ? rawBase : `uye_${rawBase || 'user'}`;
    if (!this.users.some((u) => u.username.toLowerCase() === safeBase.toLowerCase())) {
      return safeBase;
    }
    for (let i = 1; i <= 999; i++) {
      const candidate = `${safeBase.slice(0, 26)}_${i}`;
      if (!isReservedUsername(candidate) && !this.users.some((u) => u.username.toLowerCase() === candidate.toLowerCase())) {
        return candidate;
      }
    }
    return `uye_${Date.now().toString().slice(-6)}`;
  }

  registerUserDirect(
    email: string,
    username: string,
    password: string,
    clientIp: string,
    googleUid?: string | null,
    displayName?: string,
  ): PublicUser {
    const normEmail = email.trim().toLowerCase();
    const cleanUser = username.trim();

    if (isReservedUsername(cleanUser)) {
      throw new Error('Bu kullanıcı adı sistem tarafından ayrılmıştır.');
    }
    if (this.users.some((u) => u.email.toLowerCase() === normEmail)) {
      throw new Error('Bu e-posta adresi ile zaten bir hesap kayıtlı.');
    }
    if (googleUid && this.users.some((u) => u.googleUid === googleUid)) {
      throw new Error('Bu Google hesabı zaten bir kullanıcıya bağlı.');
    }
    if (this.users.some((u) => u.username.toLowerCase() === cleanUser.toLowerCase())) {
      throw new Error('Bu kullanıcı adı zaten alınmış.');
    }

    const now = new Date().toISOString();
    const created: StoredUser = {
      id: `usr_${crypto.randomUUID()}`,
      email: normEmail,
      username: cleanUser,
      displayName: displayName?.trim() || cleanUser,
      passwordHash: hashPassword(password),
      googleUid: googleUid || null,
      role: 'Üye',
      emailVerified: true,
      banned: false,
      banReason: '',
      dailyUsed: 0,
      usageDate: todayKey(),
      lastLoginAt: now,
      lastLoginIp: clientIp,
      createdAt: now,
      acceptedTermsAt: now,
    };

    this.users.push(created);
    writeJsonFile(this.usersFile, this.users);
    return this.toPublicUser(created);
  }

  loginWithGoogle(uid: string, email: string, clientIp: string): PublicUser | null {
    const normEmail = email.trim().toLowerCase();
    const user = this.users.find(
      (u) => (uid && u.googleUid === uid) || u.email.toLowerCase() === normEmail,
    );
    if (!user) return null;

    if (!user.googleUid && uid) {
      user.googleUid = uid;
    }
    user.emailVerified = true;
    user.lastLoginAt = new Date().toISOString();
    user.lastLoginIp = clientIp;
    writeJsonFile(this.usersFile, this.users);
    return this.toPublicUser(user);
  }

  adminApproveEmail(userId: string): PublicUser {
    const user = this.users.find((u) => u.id === userId);
    if (!user) throw new Error('Kullanıcı bulunamadı.');
    user.emailVerified = true;
    writeJsonFile(this.usersFile, this.users);
    return this.toPublicUser(user);
  }

  authenticateUser(
    username: string,
    password: string,
    clientIp: string,
  ): { user: PublicUser } | null {
    const clean = username.trim().toLowerCase();
    const user = this.users.find((u) => u.username.toLowerCase() === clean);
    if (!user) return null;
    if (!verifyPassword(password, user.passwordHash)) return null;

    user.emailVerified = true;
    user.lastLoginAt = new Date().toISOString();
    user.lastLoginIp = clientIp;
    writeJsonFile(this.usersFile, this.users);
    return { user: this.toPublicUser(user) };
  }

  updateUserProfile(userId: string, displayName: string): PublicUser {
    if (userId === 'admin_root') return this.getAdminPublicProfile();
    const user = this.users.find((u) => u.id === userId);
    if (!user) throw new Error('Kullanıcı bulunamadı.');
    user.displayName = displayName.trim() || user.username;
    writeJsonFile(this.usersFile, this.users);
    return this.toPublicUser(user);
  }

  getUserById(userId: string): PublicUser | null {
    if (userId === 'admin_root') return this.getAdminPublicProfile();
    const found = this.users.find((u) => u.id === userId && u.id !== 'admin_root');
    return found ? this.toPublicUser(found) : null;
  }

  listAllUsersForAdmin(): AdminUserRow[] {
    return this.users
      .map((u) => ({
        ...this.toPublicUser(u),
        lastLoginIp: u.lastLoginIp || null,
      }))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  updateUserRole(userId: string, role: StandardRole): PublicUser {
    const user = this.users.find((u) => u.id === userId);
    if (!user) throw new Error('Kullanıcı bulunamadı.');
    user.role = role;
    writeJsonFile(this.usersFile, this.users);
    return this.toPublicUser(user);
  }

  setUserBan(userId: string, banned: boolean, banReason = ''): PublicUser {
    const user = this.users.find((u) => u.id === userId);
    if (!user) throw new Error('Kullanıcı bulunamadı.');
    user.banned = banned;
    user.banReason = banned ? banReason.trim() || 'Yönetici tarafından yasaklandı.' : '';
    writeJsonFile(this.usersFile, this.users);
    return this.toPublicUser(user);
  }

  consumeQueryQuota(userId: string): { allowed: boolean; remaining: number; limit: number } {
    const today = todayKey();
    if (userId === 'admin_root') {
      if (this.adminUsageDate !== today) {
        this.adminUsageDate = today;
        this.adminDailyUsed = 0;
      }
      this.adminDailyUsed += 1;
      return { allowed: true, remaining: 999999, limit: 999999 };
    }

    const user = this.users.find((u) => u.id === userId);
    if (!user) return { allowed: false, remaining: 0, limit: 0 };

    if (user.usageDate !== today) {
      user.usageDate = today;
      user.dailyUsed = 0;
    }

    const perms = this.getPermissionsForRole(user.role);
    if (user.dailyUsed >= perms.dailyQueryLimit) {
      return { allowed: false, remaining: 0, limit: perms.dailyQueryLimit };
    }

    user.dailyUsed += 1;
    writeJsonFile(this.usersFile, this.users);
    return {
      allowed: true,
      remaining: Math.max(0, perms.dailyQueryLimit - user.dailyUsed),
      limit: perms.dailyQueryLimit,
    };
  }

  appendQueryAuditLog(entry: Omit<QueryAuditLog, 'id' | 'timestamp'>) {
    const log: QueryAuditLog = {
      id: `qlog_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      ...entry,
      timestamp: new Date().toISOString(),
    };
    this.queryLogs.unshift(log);
    this.queryLogs = this.queryLogs.slice(0, 200);
    writeJsonFile(this.logsFile, this.queryLogs);
  }

  getQueryAuditLogs(): QueryAuditLog[] {
    return this.queryLogs;
  }

  appendBlockedAttempt(entry: Omit<BlockedRegistrationAttempt, 'id' | 'timestamp'>) {
    const record: BlockedRegistrationAttempt = {
      id: `blk_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      ...entry,
      timestamp: new Date().toISOString(),
    };
    this.blockedAttempts.unshift(record);
    this.blockedAttempts = this.blockedAttempts.slice(0, 200);
    writeJsonFile(this.blockedAttemptsFile, this.blockedAttempts);
  }

  getBlockedAttempts(): BlockedRegistrationAttempt[] {
    return this.blockedAttempts;
  }

  getDatasets(): DatasetMeta[] {
    return [...this.datasets].sort((a, b) => b.importedAt.localeCompare(a.importedAt));
  }

  getRecords(categoryFilter?: DatasetCategory): IntelRecord[] {
    if (!categoryFilter) return this.records;
    const allowedIds = new Set(
      this.datasets
        .filter((d) => d.category === categoryFilter || d.category === 'both' || !d.category)
        .map((d) => d.id),
    );
    return this.records.filter((r) => allowedIds.has(r.datasetId));
  }

  getStats(): { totalDatasets: number; totalRecords: number; totalUsers: number } {
    return {
      totalDatasets: this.datasets.length,
      totalRecords: this.records.length,
      totalUsers: this.users.length,
    };
  }

  getTotalDataBytes(): number {
    let total = 0;
    for (const ds of this.datasets) {
      if (typeof ds.sizeBytes === 'number' && ds.sizeBytes > 0) {
        total += ds.sizeBytes;
      } else if (ds.recordCount > 0) {
        const shardPath = this.getDatasetShardPath(ds.id);
        if (fs.existsSync(shardPath)) {
          total += fs.statSync(shardPath).size;
        } else {
          total += ds.recordCount * 180;
        }
      }
    }
    return total;
  }

  getSearchIndex(): SearchIndex {
    if (!this.searchIndex) {
      this.searchIndex = buildSearchIndex(this.records);
    }
    return this.searchIndex;
  }

  getDatasetById(datasetId: string): DatasetMeta | null {
    return this.datasets.find((d) => d.id === datasetId) || null;
  }

  getDatasetRecordsPaginated(
    datasetId: string,
    rawSearch = '',
    page = 1,
    limit = 50,
  ): { meta: DatasetMeta | null; total: number; records: IntelRecord[] } {
    const meta = this.getDatasetById(datasetId);
    if (!meta) return { meta: null, total: 0, records: [] };
    const matched = filterDatabaseRecords(this.records, rawSearch, datasetId);
    const safeLimit = Math.max(1, Math.min(200, limit));
    const safePage = Math.max(1, page);
    const start = (safePage - 1) * safeLimit;
    return {
      meta,
      total: matched.length,
      records: matched.slice(start, start + safeLimit),
    };
  }

  private recomputeDatasetStats(datasetId: string, knownSizeBytes?: number): DatasetMeta | null {
    const dsIdx = this.datasets.findIndex((d) => d.id === datasetId);
    if (dsIdx < 0) return null;
    const dsRecords = this.records.filter((r) => r.datasetId === datasetId);
    const colSet = new Set<string>(this.datasets[dsIdx].columns || []);
    for (const r of dsRecords.slice(0, 200)) {
      for (const k of Object.keys(r.extra || {})) colSet.add(k);
    }
    const shardPath = this.getDatasetShardPath(datasetId);
    const diskBytes =
      knownSizeBytes !== undefined
        ? knownSizeBytes
        : fs.existsSync(shardPath)
          ? fs.statSync(shardPath).size
          : this.datasets[dsIdx].sizeBytes;
    const updatedMeta: DatasetMeta = {
      ...this.datasets[dsIdx],
      recordCount: dsRecords.length,
      columns: Array.from(colSet).slice(0, 50),
      sizeBytes: diskBytes,
    };
    this.datasets[dsIdx] = updatedMeta;
    return updatedMeta;
  }

  addDataset(meta: DatasetMeta, newRecords: IntelRecord[]) {
    this.deletedDatasetIds.delete(meta.id);
    this.datasets = this.datasets.filter((d) => d.id !== meta.id);
    this.records = this.records.filter((r) => r.datasetId !== meta.id);

    const writtenBytes = writeNdjsonRecords(this.getDatasetShardPath(meta.id), newRecords);
    const finalizedMeta: DatasetMeta = {
      ...meta,
      recordCount: newRecords.length,
      sizeBytes: meta.sizeBytes > 0 ? meta.sizeBytes : writtenBytes,
    };

    this.datasets.unshift(finalizedMeta);
    for (let i = 0; i < newRecords.length; i++) {
      this.records.push(newRecords[i]);
    }
    this.searchIndex = null;

    writeJsonFile(this.datasetsFile, this.datasets);
  }

  appendDatasetBatch(datasetId: string, batchRecords: IntelRecord[]): DatasetMeta {
    const dsIdx = this.datasets.findIndex((d) => d.id === datasetId);
    if (dsIdx < 0) throw new Error('Veri deposu bulunamadı.');

    const currentMeta = this.datasets[dsIdx];
    const baseOffset = currentMeta.recordCount;
    const prepared = batchRecords.map((r, i) => ({
      ...r,
      id: r.id || `${datasetId}_${baseOffset + i}`,
      datasetId,
      datasetName: currentMeta.name,
    }));

    for (let i = 0; i < prepared.length; i++) {
      this.records.push(prepared[i]);
    }
    const addedBytes = appendNdjsonRecords(this.getDatasetShardPath(datasetId), prepared);

    const colSet = new Set<string>(currentMeta.columns || []);
    for (const r of prepared.slice(0, 50)) {
      for (const k of Object.keys(r.extra || {})) colSet.add(k);
    }

    const updatedMeta: DatasetMeta = {
      ...currentMeta,
      recordCount: currentMeta.recordCount + prepared.length,
      columns: Array.from(colSet).slice(0, 50),
      sizeBytes: currentMeta.sizeBytes + addedBytes,
    };
    this.datasets[dsIdx] = updatedMeta;
    this.searchIndex = null;

    writeJsonFile(this.datasetsFile, this.datasets);
    return updatedMeta;
  }

  updateDataset(
    datasetId: string,
    updates: {
      name?: string;
      mapping?: FieldMapping;
      reNormalize?: boolean;
      appendRecords?: IntelRecord[];
    },
  ): DatasetMeta {
    const dsIdx = this.datasets.findIndex((d) => d.id === datasetId);
    if (dsIdx < 0) throw new Error('Veri deposu bulunamadı.');

    const currentMeta = this.datasets[dsIdx];
    const nextName = updates.name?.trim() || currentMeta.name;
    let dsRecords = this.records.filter((r) => r.datasetId === datasetId);

    if (updates.name && updates.name.trim()) {
      dsRecords = dsRecords.map((r) => ({ ...r, datasetName: nextName }));
    }

    if (Array.isArray(updates.appendRecords) && updates.appendRecords.length > 0) {
      const prepared = updates.appendRecords.map((r, i) => ({
        ...r,
        id: r.id || `${datasetId}_add_${Date.now()}_${i}`,
        datasetId,
        datasetName: nextName,
      }));
      for (let i = 0; i < prepared.length; i++) {
        dsRecords.push(prepared[i]);
      }
    }

    const nextMapping = updates.mapping || currentMeta.mapping;
    let nextColumns = currentMeta.columns;

    if (updates.reNormalize || updates.mapping) {
      const renorm = reNormalizeDatasetRecords(
        dsRecords,
        currentMeta.mapping,
        nextMapping,
        datasetId,
        nextName,
      );
      dsRecords = renorm.records;
      const mergedCols = new Set<string>([...currentMeta.columns, ...renorm.columns]);
      nextColumns = Array.from(mergedCols).slice(0, 50);
    }

    this.records = this.records.filter((r) => r.datasetId !== datasetId);
    for (let i = 0; i < dsRecords.length; i++) {
      this.records.push(dsRecords[i]);
    }
    const writtenBytes = writeNdjsonRecords(this.getDatasetShardPath(datasetId), dsRecords);

    const updatedMeta: DatasetMeta = {
      ...currentMeta,
      name: nextName,
      mapping: nextMapping,
      columns: nextColumns,
      recordCount: dsRecords.length,
      sizeBytes: writtenBytes,
    };
    this.datasets[dsIdx] = updatedMeta;
    this.searchIndex = null;

    writeJsonFile(this.datasetsFile, this.datasets);
    return updatedMeta;
  }

  addDatasetRecord(datasetId: string, rec: Omit<IntelRecord, 'id' | 'datasetId' | 'datasetName'>): {
    dataset: DatasetMeta;
    record: IntelRecord;
  } {
    const ds = this.getDatasetById(datasetId);
    if (!ds) throw new Error('Veri deposu bulunamadı.');
    const created: IntelRecord = {
      ...rec,
      id: `${datasetId}_m_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      datasetId,
      datasetName: ds.name,
    };
    this.records.push(created);
    const addedBytes = appendNdjsonRecords(this.getDatasetShardPath(datasetId), [created]);
    const updatedMeta = this.recomputeDatasetStats(datasetId, ds.sizeBytes + addedBytes)!;
    this.searchIndex = null;
    writeJsonFile(this.datasetsFile, this.datasets);
    return { dataset: updatedMeta, record: created };
  }

  updateDatasetRecord(
    datasetId: string,
    recordId: string,
    patch: Partial<Omit<IntelRecord, 'id' | 'datasetId' | 'datasetName'>>,
  ): { dataset: DatasetMeta; record: IntelRecord } {
    const idx = this.records.findIndex((r) => r.id === recordId && r.datasetId === datasetId);
    if (idx < 0) throw new Error('Kayıt bulunamadı.');
    const current = this.records[idx];
    const updated: IntelRecord = {
      ...current,
      discordId: patch.discordId !== undefined ? patch.discordId : current.discordId,
      email: patch.email !== undefined ? patch.email : current.email,
      username: patch.username !== undefined ? patch.username : current.username,
      source: patch.source !== undefined ? patch.source : current.source,
      ip: patch.ip !== undefined ? patch.ip : current.ip,
      phone: patch.phone !== undefined ? patch.phone : current.phone,
      notes: patch.notes !== undefined ? patch.notes : current.notes,
      extra: patch.extra !== undefined ? patch.extra : current.extra,
    };
    this.records[idx] = updated;
    const dsRecords = this.records.filter((r) => r.datasetId === datasetId);
    const writtenBytes = writeNdjsonRecords(this.getDatasetShardPath(datasetId), dsRecords);
    const updatedMeta = this.recomputeDatasetStats(datasetId, writtenBytes)!;
    this.searchIndex = null;
    writeJsonFile(this.datasetsFile, this.datasets);
    return { dataset: updatedMeta, record: updated };
  }

  deleteDatasetRecord(datasetId: string, recordId: string): DatasetMeta {
    const before = this.records.length;
    this.records = this.records.filter((r) => !(r.id === recordId && r.datasetId === datasetId));
    if (this.records.length === before) throw new Error('Kayıt bulunamadı.');
    const dsRecords = this.records.filter((r) => r.datasetId === datasetId);
    const writtenBytes = writeNdjsonRecords(this.getDatasetShardPath(datasetId), dsRecords);
    const updatedMeta = this.recomputeDatasetStats(datasetId, writtenBytes);
    if (!updatedMeta) throw new Error('Veri deposu bulunamadı.');
    this.searchIndex = null;
    writeJsonFile(this.datasetsFile, this.datasets);
    return updatedMeta;
  }

  deleteDataset(datasetId: string): boolean {
    const before = this.datasets.length;
    this.datasets = this.datasets.filter((d) => d.id !== datasetId);
    if (this.datasets.length === before) return false;
    this.deletedDatasetIds.add(datasetId);
    this.records = this.records.filter((r) => r.datasetId !== datasetId);
    this.searchIndex = null;
    const shardPath = this.getDatasetShardPath(datasetId);
    if (fs.existsSync(shardPath)) {
      fs.unlinkSync(shardPath);
    }
    writeJsonFile(this.datasetsFile, this.datasets);
    return true;
  }

  getRawUserById(userId: string): StoredUser | null {
    return this.users.find((u) => u.id === userId) || null;
  }

  getUsersCount(): number {
    return this.users.length;
  }

  upsertHydratedUser(stored: StoredUser): PublicUser {
    const safeRole: StandardRole =
      stored.role === 'Destekçi' || stored.role === 'İşletme' ? stored.role : 'Üye';
    const safeId =
      stored.id && stored.id !== 'admin_root' && stored.id.startsWith('usr_')
        ? stored.id
        : `usr_${stored.googleUid || crypto.randomUUID()}`;
    const safeUsername = isReservedUsername(stored.username)
      ? `uye_${(stored.googleUid || crypto.randomUUID()).slice(0, 8)}`
      : stored.username;
    const safeUser: StoredUser = {
      ...stored,
      id: safeId,
      username: safeUsername,
      role: safeRole,
    };

    const idx = this.users.findIndex(
      (u) =>
        (safeUser.googleUid && u.googleUid === safeUser.googleUid) ||
        u.email.toLowerCase() === safeUser.email.toLowerCase(),
    );
    if (idx >= 0) {
      this.users[idx] = { ...this.users[idx], ...safeUser, id: this.users[idx].id };
    } else {
      this.users.push(safeUser);
    }
    writeJsonFile(this.usersFile, this.users);
    return this.toPublicUser(safeUser);
  }

  getCloudSnapshot() {
    return {
      users: structuredClone(this.users),
      roles: this.getRoleConfigs(),
      datasets: this.getDatasets(),
      records: this.records,
      queryLogs: [...this.queryLogs],
      blockedAttempts: [...this.blockedAttempts],
      deletedDatasetIds: Array.from(this.deletedDatasetIds),
    };
  }

  restoreFromCloudSnapshot(snapshot: {
    users?: StoredUser[];
    roles?: Partial<RoleConfigMap>;
    datasets?: DatasetMeta[];
    records?: IntelRecord[];
  }): { restoredUsers: number; restoredDatasets: number; restoredRecords: number } {
    let restoredUsers = 0;
    let restoredDatasets = 0;
    let restoredRecords = 0;

    if (snapshot.roles) {
      for (const roleName of ['Üye', 'Destekçi', 'İşletme'] as StandardRole[]) {
        if (snapshot.roles[roleName]) {
          this.updateRoleConfig(roleName, snapshot.roles[roleName]!);
        }
      }
    }

    if (Array.isArray(snapshot.users)) {
      for (const incoming of snapshot.users) {
        if (!incoming?.email || !incoming?.username || !incoming?.passwordHash) continue;
        if (incoming.id === 'admin_root' || isReservedUsername(incoming.username)) continue;
        const safeRole: StandardRole =
          incoming.role === 'Destekçi' || incoming.role === 'İşletme' ? incoming.role : 'Üye';
        const safeId =
          incoming.id && incoming.id !== 'admin_root' && incoming.id.startsWith('usr_')
            ? incoming.id
            : `usr_${incoming.googleUid || crypto.randomUUID()}`;
        const exists = this.users.some(
          (u) =>
            (incoming.googleUid && u.googleUid === incoming.googleUid) ||
            u.email.toLowerCase() === incoming.email.toLowerCase(),
        );
        if (!exists) {
          this.users.push({ ...incoming, id: safeId, role: safeRole });
          restoredUsers += 1;
        }
      }
      if (restoredUsers > 0) {
        writeJsonFile(this.usersFile, this.users);
      }
    }

    if (Array.isArray(snapshot.datasets) && Array.isArray(snapshot.records)) {
      const existingDsIds = new Set(this.datasets.map((d) => d.id));
      const newDatasets = snapshot.datasets.filter(
        (d) => d?.id && !existingDsIds.has(d.id) && !this.deletedDatasetIds.has(d.id),
      );
      if (newDatasets.length > 0) {
        const addedDsIds = new Set(newDatasets.map((d) => d.id));
        const byDs = new Map<string, IntelRecord[]>();
        for (const r of snapshot.records) {
          if (!r?.datasetId || !addedDsIds.has(r.datasetId)) continue;
          const bucket = byDs.get(r.datasetId);
          if (bucket) bucket.push(r);
          else byDs.set(r.datasetId, [r]);
          this.records.push(r);
          restoredRecords += 1;
        }
        for (const ds of newDatasets) {
          const recs = byDs.get(ds.id) || [];
          writeNdjsonRecords(this.getDatasetShardPath(ds.id), recs);
          this.datasets.unshift(ds);
        }
        this.searchIndex = null;
        restoredDatasets = newDatasets.length;
        writeJsonFile(this.datasetsFile, this.datasets);
      }
    }

    return { restoredUsers, restoredDatasets, restoredRecords };
  }
}
