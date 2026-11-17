import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import type { Request, Response, NextFunction } from 'express';
import {
  createRateLimiter,
  getClientIp,
  ipShieldMiddleware,
  isReservedUsername,
  isSensitiveHttpPath,
  recordIpViolation,
  resetRateLimitKey,
  sanitizeExtraObject,
  sanitizeRequestBodyMiddleware,
  sanitizeString,
  securityHeadersMiddleware,
  signSessionToken,
  verifyAdminKey,
  verifyAdminSessionClaim,
  verifySessionToken,
  type SessionPayload,
} from './server/security.ts';
import { checkDisposableEmail } from './server/disposable.ts';
import { verifyFirebaseGoogleToken } from './server/googleAuth.ts';
import {
  loadRolesFromFirestoreWithToken,
  loadUserFromFirestoreWithToken,
  syncUserToFirestoreWithToken,
  touchUserUsageInFirestoreWithToken,
} from './server/firestoreBridge.ts';
import { ServerStore } from './server/store.ts';
import { runEmailOsint } from './server/emailOsint.ts';
import { decodeSnowflake, isValidSnowflake } from './src/utils/snowflake.ts';
import { classifyRecordDatabaseType, filterDatabaseRecords, runBulkLookup, searchRecords } from './src/utils/search.ts';
import { createSyntheticTestDataset } from './src/utils/storage.ts';
import type { DatasetCategory, DatasetMeta, FieldMapping, IntelRecord, PublicUser, StandardRole } from './src/types/intel.ts';

interface AuthedRequest extends Request {
  currentUser?: PublicUser;
  sessionPayload?: SessionPayload;
}

const PORT = Number(process.env.PORT || 3000);
const distDir = path.resolve(process.cwd(), 'dist');
const isProduction =
  process.env.NODE_ENV === 'production' ||
  (process.env.npm_lifecycle_event === 'start' && fs.existsSync(path.join(distDir, 'index.html')));
const ROOT_ADMIN_EMAIL = (process.env.ROOT_ADMIN_EMAIL || 'anonimhesap6506@gmail.com').trim().toLowerCase();

const store = new ServerStore();
const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(securityHeadersMiddleware);

// Block direct HTTP access to internal server directories, keys, database files, or path traversal
const EXTRA_SENSITIVE_RE = /^\/(@fs|@id|server\.ts)/i;
app.use((req, res, next) => {
  let normalizedPath = req.path;
  try {
    normalizedPath = path.posix.normalize(decodeURIComponent(req.path).replace(/\\+/g, '/').replace(/\/+/g, '/'));
  } catch {
    res.status(404).end();
    return;
  }
  const isViteDevConfigImport =
    !isProduction && normalizedPath === '/firebase-applet-config.json' && Object.prototype.hasOwnProperty.call(req.query, 'import');
  const prodOnlyBlocked =
    isProduction &&
    (/^\/(@vite|node_modules)\b/i.test(normalizedPath) ||
      normalizedPath === '/firebase-applet-config.json' ||
      (/^\/src\//i.test(normalizedPath) && !/^\/src\/assets\//i.test(normalizedPath)));
  if ((!isViteDevConfigImport && isSensitiveHttpPath(req.path)) || EXTRA_SENSITIVE_RE.test(normalizedPath) || prodOnlyBlocked) {
    res.status(404).end();
    return;
  }
  next();
});

const globalApiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 120,
  keyPrefix: 'api-global',
  violationWeight: 1,
  message: 'Hız sınırı aşıldı (DDoS / Flood koruması). Lütfen 1 dakika içinde tekrar deneyin.',
});

const authLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000,
  maxRequests: 20,
  keyPrefix: 'auth-login',
  violationWeight: 2,
  message: 'Çok fazla oturum veya doğrulama denemesi. Güvenlik için 5 dakika bekleyin.',
});

const adminKeyLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 15,
  keyPrefix: 'admin-key',
  violationWeight: 3,
  message: 'Çok fazla hatalı yönetici anahtarı denemesi. Erişim geçici olarak kilitlendi.',
});

const searchLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 45,
  keyPrefix: 'query-search',
  violationWeight: 1,
  message: 'Sorgu hız sınırı aşıldı. Lütfen kısa süre bekleyip tekrar deneyin.',
});

const osintLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  maxRequests: 20,
  keyPrefix: 'query-osint',
  violationWeight: 1,
  message: 'OSINT tarama hız sınırı aşıldı. Lütfen 1 dakika içinde tekrar deneyin.',
});

function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  const token = header?.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (!token) {
    res.status(401).json({ error: 'Oturum açmanız gerekiyor.' });
    return;
  }
  const payload = verifySessionToken(token, store.getSessionSecret());
  if (!payload) {
    res.status(401).json({ error: 'Oturum geçersiz veya süresi dolmuş. Lütfen yeniden giriş yapın.' });
    return;
  }
  if (payload.userId === 'admin_root') {
    if (!verifyAdminSessionClaim(payload, store.getAdminTokenEpoch())) {
      recordIpViolation(getClientIp(req), 3);
      res.status(401).json({ error: 'Yönetici oturum yetkisi doğrulanamadı.' });
      return;
    }
  } else if (payload.epoch !== store.getUserTokenEpoch()) {
    res.status(401).json({ error: 'Oturumunuz yönetici tarafından sonlandırıldı. Lütfen yeniden giriş yapın.' });
    return;
  }
  const user = store.getUserById(payload.userId);
  if (!user) {
    res.status(401).json({ error: 'Hesap bulunamadı.' });
    return;
  }
  if (!user.emailVerified && user.role !== 'Admin') {
    res.status(403).json({ error: 'Hesap doğrulaması tamamlanmamış.' });
    return;
  }
  if (user.banned) {
    res.status(403).json({ error: `Hesabınız yasaklandı: ${user.banReason || 'Yönetici kararı'}` });
    return;
  }
  req.currentUser = user;
  req.sessionPayload = payload;
  next();
}

function requireAdmin(req: AuthedRequest, res: Response, next: NextFunction) {
  requireAuth(req, res, () => {
    if (
      req.currentUser?.id !== 'admin_root' ||
      req.currentUser?.role !== 'Admin' ||
      !verifyAdminSessionClaim(req.sessionPayload || null, store.getAdminTokenEpoch())
    ) {
      recordIpViolation(getClientIp(req), 2);
      res.status(403).json({ error: 'Bu işlem yalnızca Admin hesabı tarafından yapılabilir.' });
      return;
    }
    next();
  });
}

app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});
app.use('/api', ipShieldMiddleware, globalApiLimiter);
// Enforce Admin authentication BEFORE accepting large dataset/snapshot JSON bodies (within Cloud Run 32MB ceiling)
app.use('/api/datasets', requireAdmin, express.json({ limit: '24mb' }), sanitizeRequestBodyMiddleware);
app.use('/api/admin/datasets', requireAdmin, express.json({ limit: '24mb' }), sanitizeRequestBodyMiddleware);
app.use('/api/admin/firestore/import-snapshot', requireAdmin, express.json({ limit: '24mb' }), sanitizeRequestBodyMiddleware);
app.use(express.json({ limit: '256kb' }));
app.use(sanitizeRequestBodyMiddleware);

// --- Public Health (no internal database counts or identity leaked) ---
app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

// --- Auth: Google Account Registration & Google/Username Sign-In ---
app.post('/api/auth/register', authLimiter, (_req, res) => {
  res.status(403).json({
    error: 'Doğrudan e-posta yazarak kayıt kapalıdır. Lütfen Google Hesabı ile kayıt olun.',
  });
});

app.post('/api/auth/google', authLimiter, async (req, res) => {
  const idToken = typeof req.body?.idToken === 'string' ? req.body.idToken : '';
  if (!idToken) {
    res.status(400).json({ error: 'Google kimlik belirteci zorunludur.' });
    return;
  }

  try {
    const identity = await verifyFirebaseGoogleToken(idToken);
    const domainCheck = await checkDisposableEmail(identity.email);
    if (domainCheck.isDisposable || !domainCheck.validMx) {
      const reason =
        domainCheck.reason ||
        'Geçici veya geçersiz alan adına sahip e-posta hesapları kabul edilmiyor.';
      store.appendBlockedAttempt({
        email: identity.email,
        username: identity.displayName || 'google_user',
        domain: identity.email.split('@')[1] || '',
        reason,
        detector: domainCheck.detector,
        ip: getClientIp(req),
      });
      res.status(400).json({ error: reason });
      return;
    }

    let existing = store.loginWithGoogle(identity.uid, identity.email, getClientIp(req));
    if (!existing) {
      const [hydrated, cloudRoles] = await Promise.all([
        loadUserFromFirestoreWithToken(idToken, identity.uid),
        loadRolesFromFirestoreWithToken(idToken),
      ]);
      if (cloudRoles) {
        for (const roleName of ['Üye', 'Destekçi', 'İşletme'] as StandardRole[]) {
          if (cloudRoles[roleName]) {
            store.updateRoleConfig(roleName, cloudRoles[roleName]!);
          }
        }
      }
      if (hydrated) {
        store.upsertHydratedUser(hydrated);
        existing = store.loginWithGoogle(identity.uid, identity.email, getClientIp(req));
      }
    }
    if (existing) {
      if (existing.banned) {
        res.status(403).json({ error: `Hesabınız yasaklandı: ${existing.banReason || 'Yönetici kararı'}` });
        return;
      }
      const rawExisting = store.getRawUserById(existing.id);
      if (rawExisting) {
        void touchUserUsageInFirestoreWithToken(idToken, rawExisting);
      }
      const token = signSessionToken(
        {
          userId: existing.id,
          role: existing.role,
          exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
          epoch: store.getUserTokenEpoch(),
        },
        store.getSessionSecret(),
      );
      res.json({ status: 'authenticated', token, user: existing });
      return;
    }

    const suggestedUsername = store.suggestUsername(identity.email, identity.displayName);
    res.json({
      status: 'needs_profile',
      email: identity.email,
      displayName: identity.displayName,
      suggestedUsername,
    });
  } catch (err) {
    recordIpViolation(getClientIp(req), 1);
    res.status(401).json({ error: err instanceof Error ? err.message : 'Google doğrulaması başarısız.' });
  }
});

app.post('/api/auth/google-register', authLimiter, async (req, res) => {
  const idToken = typeof req.body?.idToken === 'string' ? req.body.idToken : '';
  const username = sanitizeString(req.body?.username, 40);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const acceptedTerms = req.body?.acceptedTerms === true;

  if (!idToken) {
    res.status(400).json({ error: 'Google kimlik belirteci zorunludur.' });
    return;
  }
  if (!acceptedTerms) {
    res.status(400).json({ error: 'Kayıt olmak için Yasal Beyan ve Sorumluluk Reddi şartlarını onaylamalısınız.' });
    return;
  }
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    res.status(400).json({ error: 'Kullanıcı adı 3-32 karakter arasında olmalı (harf, rakam, _, ., -).' });
    return;
  }
  if (isReservedUsername(username)) {
    res.status(400).json({ error: 'Bu kullanıcı adı sistem tarafından ayrılmıştır. Başka bir kullanıcı adı seçin.' });
    return;
  }
  if (password.length < 8 || password.length > 128) {
    res.status(400).json({ error: 'Şifre en az 8 karakter uzunluğunda olmalıdır.' });
    return;
  }

  try {
    const identity = await verifyFirebaseGoogleToken(idToken);
    const domainCheck = await checkDisposableEmail(identity.email);
    if (domainCheck.isDisposable || !domainCheck.validMx) {
      const reason =
        domainCheck.reason ||
        'Geçici veya geçersiz alan adına sahip e-posta hesapları kabul edilmiyor.';
      store.appendBlockedAttempt({
        email: identity.email,
        username,
        domain: identity.email.split('@')[1] || '',
        reason,
        detector: domainCheck.detector,
        ip: getClientIp(req),
      });
      res.status(400).json({ error: reason });
      return;
    }

    const user = store.registerUserDirect(
      identity.email,
      username,
      password,
      getClientIp(req),
      identity.uid,
      identity.displayName || username,
    );
    const rawUser = store.getRawUserById(user.id);
    if (rawUser) {
      void syncUserToFirestoreWithToken(idToken, rawUser);
    }
    const token = signSessionToken(
      {
        userId: user.id,
        role: user.role,
        exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
        epoch: store.getUserTokenEpoch(),
      },
      store.getSessionSecret(),
    );
    res.status(201).json({ token, user });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Google ile kayıt başarısız.';
    res.status(409).json({ error: msg });
  }
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  const username = sanitizeString(req.body?.username ?? req.body?.identifier, 40);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  if (!username || !password) {
    res.status(400).json({ error: 'Kullanıcı adı ve şifre zorunludur.' });
    return;
  }

  const authRes = store.authenticateUser(username, password, getClientIp(req));
  if (!authRes) {
    recordIpViolation(getClientIp(req), 1);
    const hint =
      store.getUsersCount() === 0
        ? " Sunucu yeniden başlatıldıysa lütfen 'Google Hesabı ile Giriş Yap' seçeneğini kullanın."
        : '';
    res.status(401).json({ error: `Kullanıcı adı veya şifre hatalı.${hint}` });
    return;
  }
  if (authRes.user.banned) {
    res.status(403).json({ error: `Hesabınız yasaklandı: ${authRes.user.banReason || 'Yönetici kararı'}` });
    return;
  }

  const token = signSessionToken(
    {
      userId: authRes.user.id,
      role: authRes.user.role,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
      epoch: store.getUserTokenEpoch(),
    },
    store.getSessionSecret(),
  );
  res.json({ token, user: authRes.user });
});

app.post('/api/auth/admin-login', adminKeyLimiter, (req, res) => {
  const key = typeof req.body?.key === 'string' ? req.body.key.trim() : '';
  if (!verifyAdminKey(key, store.getAdminKeyHash())) {
    recordIpViolation(getClientIp(req), 2);
    res.status(401).json({ error: '30 haneli yönetici anahtarı geçersiz.' });
    return;
  }

  resetRateLimitKey('admin-key', getClientIp(req));
  const user = store.getAdminPublicProfile();
  const token = signSessionToken(
    {
      userId: user.id,
      role: user.role,
      adminGrant: true,
      adminEpoch: store.getAdminTokenEpoch(),
      exp: Date.now() + 24 * 60 * 60 * 1000,
    },
    store.getSessionSecret(),
  );
  res.json({ token, user });
});

app.post('/api/auth/admin-google-login', adminKeyLimiter, (_req, res) => {
  res.status(403).json({
    error: 'Admin girişi gizlilik nedeniyle hesapsız olarak yalnızca 30 haneli anahtar ile yapılır.',
  });
});

app.post('/api/admin/cloud-authorize', requireAdmin, async (req, res) => {
  const idToken = typeof req.body?.idToken === 'string' ? req.body.idToken : '';
  if (!idToken) {
    res.status(400).json({ error: 'Kimlik doğrulama belirteci zorunludur.' });
    return;
  }
  try {
    const identity = await verifyFirebaseGoogleToken(idToken);
    if (!identity.emailVerified || identity.email !== ROOT_ADMIN_EMAIL) {
      res.status(403).json({ error: 'Seçilen hesap bu bulut kasası için yetkili değil.' });
      return;
    }
    res.json({ authorized: true });
  } catch {
    res.status(401).json({ error: 'Bulut yetkilendirmesi doğrulanamadı.' });
  }
});

app.get('/api/auth/me', requireAuth, (req: AuthedRequest, res) => {
  const isAdmin = req.currentUser!.role === 'Admin';
  res.json({
    user: req.currentUser,
    stats: isAdmin ? store.getStats() : { totalDatasets: 0, totalRecords: 0, totalUsers: 0 },
  });
});

function sanitizeRecordsForRole(records: IntelRecord[], isAdmin: boolean): IntelRecord[] {
  if (isAdmin) {
    return records.map((r) => ({
      ...r,
      dbType: classifyRecordDatabaseType(r),
    }));
  }
  return records.map((r) => ({
    ...r,
    dbType: classifyRecordDatabaseType(r),
    datasetId: '',
    datasetName: '',
    source:
      r.source && r.datasetName && r.source.trim().toLowerCase() === r.datasetName.trim().toLowerCase()
        ? ''
        : r.source,
  }));
}

// --- ID Lookup (Automatically scans ALL uploaded records + full transitive correlation, uncensored) ---
app.post('/api/search', requireAuth, searchLimiter, (req: AuthedRequest, res) => {
  const user = req.currentUser!;
  if (!user.permissions.canIdLookup) {
    res.status(403).json({ error: `Rolünüz (${user.role}) ID sorgulama yetkisine sahip değil.` });
    return;
  }

  const query = sanitizeString(req.body?.query, 40);
  if (!query || !isValidSnowflake(query)) {
    res.status(400).json({ error: 'Lütfen geçerli bir 17-20 haneli Discord ID girin.' });
    return;
  }

  const quota = store.consumeQueryQuota(user.id);
  if (!quota.allowed) {
    res.status(429).json({
      error: `Günlük sorgu hakkınız (${quota.limit}) dolmuştur. Kota artışı için yöneticiyle iletişime geçin.`,
    });
    return;
  }

  const allRecords = store.getRecords();
  const rawResult = searchRecords(allRecords, query, 'discord_id', true, allRecords, store.getSearchIndex());
  const isAdmin = user.role === 'Admin';

  store.appendQueryAuditLog({
    userId: user.id,
    username: user.username,
    queryType: 'id_lookup',
    target: query,
    matchCount: rawResult.primaryMatches.length + rawResult.relatedMatches.length,
    ip: getClientIp(req),
  });

  const storeStats = store.getStats();
  res.json({
    result: {
      ...rawResult,
      primaryMatches: sanitizeRecordsForRole(rawResult.primaryMatches, isAdmin),
      relatedMatches: sanitizeRecordsForRole(rawResult.relatedMatches, isAdmin),
      maskedByPolicy: false,
      scanMetrics: {
        scannedRecords: allRecords.length,
        scannedDatasets: storeStats.totalDatasets,
        scannedBytes: store.getTotalDataBytes(),
      },
    },
    user: store.getUserById(user.id),
  });
});

app.post('/api/bulk-search', requireAuth, osintLimiter, (req: AuthedRequest, res) => {
  const user = req.currentUser!;
  if (!user.permissions.canBulkLookup) {
    res.status(403).json({ error: `Rolünüz (${user.role}) toplu sorgulama özelliğine erişemiyor.` });
    return;
  }

  const rawInput = sanitizeString(req.body?.rawInput, 25000);
  if (!rawInput) {
    res.status(400).json({ error: 'Taranacak en az bir Discord ID girmelisiniz.' });
    return;
  }

  const quota = store.consumeQueryQuota(user.id);
  if (!quota.allowed) {
    res.status(429).json({ error: `Günlük sorgu hakkınız (${quota.limit}) dolmuştur.` });
    return;
  }

  const rows = runBulkLookup(store.getRecords(), rawInput, store.getSearchIndex()).slice(0, 500);
  const isAdmin = user.role === 'Admin';

  store.appendQueryAuditLog({
    userId: user.id,
    username: user.username,
    queryType: 'bulk_lookup',
    target: `${rows.length} Discord ID`,
    matchCount: rows.filter((r) => r.matches.length > 0).length,
    ip: getClientIp(req),
  });

  res.json({
    rows: rows.map((row) => ({
      ...row,
      matches: sanitizeRecordsForRole(row.matches, isAdmin),
    })),
    maskedByPolicy: false,
    user: store.getUserById(user.id),
  });
});

app.post('/api/osint/email', requireAuth, osintLimiter, async (req: AuthedRequest, res) => {
  const user = req.currentUser!;
  if (!user.permissions.canEmailOsint) {
    res.status(403).json({ error: `Rolünüz (${user.role}) E-posta OSINT modülünü kullanma yetkisine sahip değil.` });
    return;
  }

  const email = sanitizeString(req.body?.email, 180);
  const lang = req.body?.lang === 'en' ? 'en' : 'tr';
  if (!email) {
    res.status(400).json({ error: 'E-posta adresi boş olamaz.' });
    return;
  }

  const quota = store.consumeQueryQuota(user.id);
  if (!quota.allowed) {
    res.status(429).json({ error: `Günlük sorgu hakkınız (${quota.limit}) dolmuştur.` });
    return;
  }

  const allRecords = store.getRecords();
  const report = await runEmailOsint(email, allRecords, lang, store.getSearchIndex());
  const isAdmin = user.role === 'Admin';

  store.appendQueryAuditLog({
    userId: user.id,
    username: user.username,
    queryType: 'email_osint',
    target: email,
    matchCount: report.localMatches.length,
    ip: getClientIp(req),
  });

  res.json({
    report: {
      ...report,
      localMatches: sanitizeRecordsForRole(report.localMatches, isAdmin),
    },
    maskedByPolicy: false,
    user: store.getUserById(user.id),
  });
});

// --- Admin-Only Routes: Datasets, Database Browser, Users, Bans, Roles ---
app.post('/api/datasets', requireAdmin, (req, res) => {
  const meta = req.body?.meta as DatasetMeta | undefined;
  const rawRecords = Array.isArray(req.body?.records) ? req.body.records : null;

  if (!meta || !rawRecords || rawRecords.length === 0) {
    res.status(400).json({ error: 'Geçerli veri seti üst verisi ve en az 1 kayıt gereklidir.' });
    return;
  }

  const datasetId = sanitizeString(meta.id, 80) || `ds_${Date.now()}`;
  const datasetName = sanitizeString(meta.name, 120) || 'Yüklenen Veri Seti';
  const category: DatasetCategory = 'both';

  const cleanRecords: IntelRecord[] = rawRecords.map((r: Record<string, unknown>, idx: number) => ({
    id: sanitizeString(r.id, 120) || `${datasetId}_${idx}`,
    datasetId,
    datasetName,
    discordId: sanitizeString(r.discordId, 32),
    email: sanitizeString(r.email, 180),
    username: sanitizeString(r.username, 80),
    source: sanitizeString(r.source, 120),
    ip: sanitizeString(r.ip, 64),
    phone: sanitizeString(r.phone, 40),
    notes: sanitizeString(r.notes, 2000),
    extra: sanitizeExtraObject(r.extra),
  }));

  const cleanMeta: DatasetMeta = {
    id: datasetId,
    name: datasetName,
    category,
    format: ['json', 'csv', 'ndjson', 'text', 'synthetic'].includes(meta.format) ? meta.format : 'text',
    recordCount: cleanRecords.length,
    columns: Array.isArray(meta.columns) ? meta.columns.slice(0, 50).map((c) => sanitizeString(c, 60)) : [],
    mapping: meta.mapping,
    importedAt: new Date().toISOString(),
    sizeBytes: typeof meta.sizeBytes === 'number' ? meta.sizeBytes : 0,
  };

  store.addDataset(cleanMeta, cleanRecords);
  res.status(201).json({ dataset: store.getDatasetById(datasetId) || cleanMeta, stats: store.getStats() });
});

app.post('/api/admin/datasets/:id/append-batch', requireAdmin, (req, res) => {
  const datasetId = sanitizeString(req.params.id, 100);
  const rawRecords = Array.isArray(req.body?.records) ? req.body.records : null;
  if (!rawRecords || rawRecords.length === 0) {
    res.status(400).json({ error: 'Eklenecek geçerli kayıt kümesi gereklidir.' });
    return;
  }
  const existing = store.getDatasetById(datasetId);
  if (!existing) {
    res.status(404).json({ error: 'Veri deposu bulunamadı.' });
    return;
  }

  const baseOffset = existing.recordCount;
  const cleanBatch: IntelRecord[] = rawRecords.map((r: Record<string, unknown>, idx: number) => ({
    id: sanitizeString(r.id, 120) || `${datasetId}_${baseOffset + idx}`,
    datasetId,
    datasetName: existing.name,
    discordId: sanitizeString(r.discordId, 32),
    email: sanitizeString(r.email, 180),
    username: sanitizeString(r.username, 80),
    source: sanitizeString(r.source, 120),
    ip: sanitizeString(r.ip, 64),
    phone: sanitizeString(r.phone, 40),
    notes: sanitizeString(r.notes, 2000),
    extra: sanitizeExtraObject(r.extra),
  }));

  const updated = store.appendDatasetBatch(datasetId, cleanBatch);
  res.json({ dataset: updated, stats: store.getStats() });
});

app.post('/api/datasets/synthetic', requireAdmin, (_req, res) => {
  const { meta, records } = createSyntheticTestDataset();
  store.addDataset({ ...meta, category: 'both' }, records);
  res.status(201).json({ dataset: meta, stats: store.getStats() });
});

app.delete('/api/datasets/:id', requireAdmin, (req, res) => {
  const id = sanitizeString(req.params.id, 100);
  const removed = store.deleteDataset(id);
  if (!removed) {
    res.status(404).json({ error: 'Veri seti bulunamadı.' });
    return;
  }
  res.json({ ok: true, stats: store.getStats() });
});

app.get('/api/admin/verify', requireAdmin, (req, res) => {
  const nonce = sanitizeString(req.query.nonce, 64);
  if (!/^[a-zA-Z0-9_-]{16,64}$/.test(nonce)) {
    res.status(400).json({ error: 'Geçersiz doğrulama kodu.' });
    return;
  }
  res.json({ verified: true, role: 'Admin', nonce });
});

app.get('/api/admin/overview', requireAdmin, (_req, res) => {
  res.json({
    users: store.listAllUsersForAdmin(),
    roles: store.getRoleConfigs(),
    datasets: store.getDatasets(),
    queryLogs: store.getQueryAuditLogs(),
    blockedAttempts: store.getBlockedAttempts(),
    recordsSample: store.getRecords().slice(0, 150),
    stats: store.getStats(),
  });
});

app.get('/api/admin/database/records', requireAdmin, (req, res) => {
  const q = sanitizeString(req.query.q, 120);
  const datasetId = sanitizeString(req.query.datasetId, 80);
  const filtered = filterDatabaseRecords(store.getRecords(), q, datasetId || undefined);
  res.json({ total: filtered.length, records: filtered.slice(0, 200) });
});

app.get('/api/admin/datasets/:id/records', requireAdmin, (req, res) => {
  const datasetId = sanitizeString(req.params.id, 100);
  const q = sanitizeString(req.query.q, 120);
  const page = Number(req.query.page || 1);
  const limit = Number(req.query.limit || 40);
  const data = store.getDatasetRecordsPaginated(datasetId, q, page, limit);
  if (!data.meta) {
    res.status(404).json({ error: 'Veri deposu bulunamadı.' });
    return;
  }
  res.json(data);
});

app.patch('/api/admin/datasets/:id', requireAdmin, (req, res) => {
  const datasetId = sanitizeString(req.params.id, 100);
  try {
    const rawName = req.body?.name !== undefined ? sanitizeString(req.body.name, 120) : undefined;
    const rawMapping = req.body?.mapping && typeof req.body.mapping === 'object'
      ? (req.body.mapping as FieldMapping)
      : undefined;
    const reNormalize = req.body?.reNormalize === true;
    const rawAppend = Array.isArray(req.body?.appendRecords) ? req.body.appendRecords : undefined;

    const appendRecords: IntelRecord[] | undefined = rawAppend
      ? rawAppend.map((r: Record<string, unknown>, idx: number) => ({
          id: sanitizeString(r.id, 120) || `${datasetId}_app_${Date.now()}_${idx}`,
          datasetId,
          datasetName: rawName || 'Dataset',
          discordId: sanitizeString(r.discordId, 32),
          email: sanitizeString(r.email, 180),
          username: sanitizeString(r.username, 80),
          source: sanitizeString(r.source, 120),
          ip: sanitizeString(r.ip, 64),
          phone: sanitizeString(r.phone, 40),
          notes: sanitizeString(r.notes, 2000),
          extra: sanitizeExtraObject(r.extra),
        }))
      : undefined;

    const dataset = store.updateDataset(datasetId, {
      name: rawName || undefined,
      mapping: rawMapping,
      reNormalize,
      appendRecords,
    });
    res.json({ dataset, stats: store.getStats() });
  } catch (err) {
    res.status(404).json({ error: err instanceof Error ? err.message : 'Veri deposu güncellenemedi.' });
  }
});

app.post('/api/admin/datasets/:id/records', requireAdmin, (req, res) => {
  const datasetId = sanitizeString(req.params.id, 100);
  try {
    const b = req.body || {};
    const result = store.addDatasetRecord(datasetId, {
      discordId: sanitizeString(b.discordId, 32),
      email: sanitizeString(b.email, 180),
      username: sanitizeString(b.username, 80),
      source: sanitizeString(b.source, 120),
      ip: sanitizeString(b.ip, 64),
      phone: sanitizeString(b.phone, 40),
      notes: sanitizeString(b.notes, 2000),
      extra: sanitizeExtraObject(b.extra),
    });
    res.status(201).json({ ...result, stats: store.getStats() });
  } catch (err) {
    res.status(404).json({ error: err instanceof Error ? err.message : 'Kayıt eklenemedi.' });
  }
});

app.patch('/api/admin/datasets/:id/records/:recordId', requireAdmin, (req, res) => {
  const datasetId = sanitizeString(req.params.id, 100);
  const recordId = sanitizeString(req.params.recordId, 140);
  try {
    const b = req.body || {};
    const result = store.updateDatasetRecord(datasetId, recordId, {
      discordId: b.discordId !== undefined ? sanitizeString(b.discordId, 32) : undefined,
      email: b.email !== undefined ? sanitizeString(b.email, 180) : undefined,
      username: b.username !== undefined ? sanitizeString(b.username, 80) : undefined,
      source: b.source !== undefined ? sanitizeString(b.source, 120) : undefined,
      ip: b.ip !== undefined ? sanitizeString(b.ip, 64) : undefined,
      phone: b.phone !== undefined ? sanitizeString(b.phone, 40) : undefined,
      notes: b.notes !== undefined ? sanitizeString(b.notes, 2000) : undefined,
      extra: b.extra !== undefined ? sanitizeExtraObject(b.extra) : undefined,
    });
    res.json({ ...result, stats: store.getStats() });
  } catch (err) {
    res.status(404).json({ error: err instanceof Error ? err.message : 'Kayıt güncellenemedi.' });
  }
});

app.delete('/api/admin/datasets/:id/records/:recordId', requireAdmin, (req, res) => {
  const datasetId = sanitizeString(req.params.id, 100);
  const recordId = sanitizeString(req.params.recordId, 140);
  try {
    const dataset = store.deleteDatasetRecord(datasetId, recordId);
    res.json({ ok: true, dataset, stats: store.getStats() });
  } catch (err) {
    res.status(404).json({ error: err instanceof Error ? err.message : 'Kayıt silinemedi.' });
  }
});

app.patch('/api/admin/roles/:role', requireAdmin, (req, res) => {
  const roleParam = decodeURIComponent(req.params.role) as StandardRole;
  if (!['Üye', 'Destekçi', 'İşletme'].includes(roleParam)) {
    res.status(400).json({ error: 'Geçersiz rol adı.' });
    return;
  }
  const roles = store.updateRoleConfig(roleParam, req.body || {});
  res.json({ roles });
});

app.post('/api/admin/users/kick-all', requireAdmin, (req, res) => {
  const clearAccounts = req.body?.clearAccounts === true;
  const result = store.kickAllUsers(clearAccounts);
  res.json({ ok: true, kickedCount: result.kickedCount, clearAccounts });
});

app.get('/api/admin/firestore/export-snapshot', requireAdmin, (_req, res) => {
  res.json(store.getCloudSnapshot());
});

app.post('/api/admin/firestore/import-snapshot', requireAdmin, (req, res) => {
  const body = req.body || {};
  const result = store.restoreFromCloudSnapshot({
    users: Array.isArray(body.users) ? body.users : undefined,
    roles: body.roles && typeof body.roles === 'object' ? body.roles : undefined,
    datasets: Array.isArray(body.datasets) ? body.datasets : undefined,
    records: Array.isArray(body.records) ? body.records : undefined,
  });
  res.json({ ok: true, ...result, stats: store.getStats() });
});

app.patch('/api/admin/users/:id', requireAdmin, (req, res) => {
  const userId = sanitizeString(req.params.id, 100);
  try {
    let updated: PublicUser | null = null;
    if (req.body?.approveEmail === true) {
      updated = store.adminApproveEmail(userId);
    }
    if (req.body?.role !== undefined) {
      const targetRole = req.body.role as StandardRole;
      if (!['Üye', 'Destekçi', 'İşletme'].includes(targetRole)) {
        res.status(400).json({ error: 'Geçersiz rol seçimi.' });
        return;
      }
      updated = store.updateUserRole(userId, targetRole);
    }
    if (typeof req.body?.banned === 'boolean') {
      const reason = sanitizeString(req.body?.banReason, 240);
      updated = store.setUserBan(userId, req.body.banned, reason);
    }
    if (!updated) {
      res.status(400).json({ error: 'Güncellenecek alan belirtilmedi.' });
      return;
    }
    res.json({ user: updated });
  } catch (err) {
    res.status(404).json({ error: err instanceof Error ? err.message : 'Kullanıcı güncellenemedi.' });
  }
});

app.get('/api/snowflake/:id', requireAuth, (req, res) => {
  const id = sanitizeString(req.params.id, 30);
  if (!isValidSnowflake(id)) {
    res.status(400).json({ error: 'Geçersiz Discord Snowflake ID.' });
    return;
  }
  res.json({ snowflake: decodeSnowflake(id) });
});

// Global safe error handler — never leaks stack traces, file paths, or admin details
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err && typeof err === 'object' && 'type' in err && (err as { type?: string }).type === 'entity.parse.failed') {
    res.status(400).json({ error: 'Geçersiz JSON istek gövdesi.' });
    return;
  }
  res.status(500).json({ error: 'İstek işlenirken sunucu hatası oluştu.' });
});

async function startServer() {
  if (!isProduction) {
    // Vite 8 @vite/client attempts an unconditional HMR WebSocket connection even when
    // server.hmr=false & server.ws=false in middlewareMode, causing console/runtime rejections
    // behind Cloud Run/iFrame proxies (@vite/client:234). Serve a clean no-WS dev shim instead.
    app.get('/@vite/client', (_req, res) => {
      res.type('application/javascript').send(`
const sheetsMap = new Map();
export function updateStyle(id, content) {
  let style = sheetsMap.get(id);
  if (!style) {
    style = document.createElement('style');
    style.setAttribute('type', 'text/css');
    style.setAttribute('data-vite-dev-id', id);
    style.textContent = content;
    document.head.appendChild(style);
  } else if (style.textContent !== content) {
    style.textContent = content;
  }
  sheetsMap.set(id, style);
}
export function removeStyle(id) {
  const style = sheetsMap.get(id);
  if (style) {
    style.remove();
    sheetsMap.delete(id);
  }
}
export function createHotContext() {
  return {
    data: {},
    accept() {},
    dispose() {},
    prune() {},
    decline() {},
    invalidate() {},
    on() {},
    off() {},
    send() {},
  };
}
export function injectQuery(url) {
  return url;
}
export class ErrorOverlay {
  close() {}
}
`);
    });
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true, hmr: false, ws: false },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir, { dotfiles: 'ignore' }));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Sentarika Archive] Sunucu http://0.0.0.0:${PORT} adresinde baslatildi`);
  });
}

startServer().catch((err) => {
  console.error('Sunucu baslatilamadi:', err instanceof Error ? err.message : 'Bilinmeyen hata');
  process.exit(1);
});
