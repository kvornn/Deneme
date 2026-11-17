import { initializeApp, getApps } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup } from 'firebase/auth';
import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocFromServer,
  getDocs,
  getFirestore,
  query,
  serverTimestamp,
  where,
  writeBatch,
  type Firestore,
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';
import type {
  BlockedRegistrationAttempt,
  DatasetMeta,
  IntelRecord,
  QueryAuditLog,
  RoleConfigMap,
  StandardRole,
} from '../types/intel';

const app = getApps().length > 0 ? getApps()[0] : initializeApp(firebaseConfig);
export const db: Firestore = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}

void testConnection();

export interface ServerCloudUser {
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

export interface CloudBackupSnapshot {
  users: ServerCloudUser[];
  roles: RoleConfigMap;
  datasets: DatasetMeta[];
  records: IntelRecord[];
  queryLogs: QueryAuditLog[];
  blockedAttempts: BlockedRegistrationAttempt[];
  deletedDatasetIds?: string[];
}

const ROLE_DOC_ID: Record<StandardRole, 'uye' | 'destekci' | 'isletme'> = {
  Üye: 'uye',
  Destekçi: 'destekci',
  İşletme: 'isletme',
};

function sanitizeChunkId(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128) || 'doc_0';
}

let cloudVerifiedUid: string | null = null;

export function isCloudRootAdminConnected(): boolean {
  const u = auth.currentUser;
  return Boolean(u && u.emailVerified && cloudVerifiedUid && u.uid === cloudVerifiedUid);
}

export async function verifyExistingCloudSession(
  authorizeOnServer: (idToken: string) => Promise<{ authorized: boolean }>,
): Promise<boolean> {
  const u = auth.currentUser;
  if (!u || !u.emailVerified) {
    cloudVerifiedUid = null;
    return false;
  }
  if (cloudVerifiedUid === u.uid) return true;
  try {
    const idToken = await u.getIdToken();
    const res = await authorizeOnServer(idToken);
    if (res.authorized) {
      cloudVerifiedUid = u.uid;
      return true;
    }
  } catch {
    // Non-authorized Firebase user silently ignored
  }
  cloudVerifiedUid = null;
  return false;
}

export async function connectAdminGoogleAccount(
  authorizeOnServer: (idToken: string) => Promise<{ authorized: boolean }>,
): Promise<{ uid: string; authorized: boolean }> {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  const cred = await signInWithPopup(auth, provider);
  if (!cred.user.emailVerified) {
    throw new Error('Doğrulanmış bir hesap seçilmelidir.');
  }
  const idToken = await cred.user.getIdToken(true);
  const res = await authorizeOnServer(idToken);
  if (!res.authorized) {
    throw new Error('Seçilen hesap bu bulut kasası için yetkili değil.');
  }
  cloudVerifiedUid = cred.user.uid;
  return { uid: cred.user.uid, authorized: true };
}

function buildSafeRecordChunks(
  datasetId: string,
  records: IntelRecord[],
): Array<{ chunkId: string; datasetId: string; chunkIndex: number; totalChunks: number; records: IntelRecord[] }> {
  const dsId = sanitizeChunkId(datasetId);
  const MAX_RECORDS = 250;
  const MAX_BYTES = 420_000;

  const grouped: IntelRecord[][] = [];
  let current: IntelRecord[] = [];
  let currentBytes = 0;

  for (const r of records) {
    const clean: IntelRecord = {
      id: r.id.slice(0, 120),
      datasetId: dsId,
      datasetName: (r.datasetName || 'Dataset').slice(0, 120),
      discordId: (r.discordId || '').slice(0, 32),
      email: (r.email || '').slice(0, 180),
      username: (r.username || '').slice(0, 80),
      source: (r.source || '').slice(0, 120),
      ip: (r.ip || '').slice(0, 64),
      phone: (r.phone || '').slice(0, 40),
      notes: (r.notes || '').slice(0, 1500),
      extra: r.extra || {},
    };
    const estBytes = JSON.stringify(clean).length;
    if (current.length > 0 && (current.length >= MAX_RECORDS || currentBytes + estBytes > MAX_BYTES)) {
      grouped.push(current);
      current = [];
      currentBytes = 0;
    }
    current.push(clean);
    currentBytes += estBytes;
  }
  if (current.length > 0 || grouped.length === 0) {
    grouped.push(current);
  }

  const totalChunks = grouped.length;
  return grouped.map((slice, idx) => ({
    chunkId: sanitizeChunkId(`${dsId}_c_${idx}`),
    datasetId: dsId,
    chunkIndex: idx,
    totalChunks,
    records: slice,
  }));
}

export async function deleteDatasetFromFirestore(datasetId: string): Promise<void> {
  if (!isCloudRootAdminConnected()) return;
  const dsId = sanitizeChunkId(datasetId);
  try {
    const chunksSnap = await getDocs(query(collection(db, 'dataset_chunks'), where('datasetId', '==', dsId)));
    const docsToDelete = chunksSnap.docs.map((d) => d.ref);
    for (let i = 0; i < docsToDelete.length; i += 200) {
      const batch = writeBatch(db);
      for (const ref of docsToDelete.slice(i, i + 200)) {
        batch.delete(ref);
      }
      await batch.commit();
    }
    await deleteDoc(doc(db, 'datasets', dsId));
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, `datasets/${dsId}`);
  }
}

export async function clearAllMembersFromFirestore(): Promise<void> {
  if (!isCloudRootAdminConnected()) return;
  try {
    const usersSnap = await getDocs(collection(db, 'users'));
    for (const d of usersSnap.docs) {
      await deleteDoc(doc(db, 'users', d.id, 'private', 'info')).catch(() => {});
      await deleteDoc(d.ref);
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.DELETE, 'users');
  }
}

async function pushRolesToFirestore(roles: RoleConfigMap): Promise<number> {
  let written = 0;
  try {
    const roleBatch = writeBatch(db);
    for (const roleName of ['Üye', 'Destekçi', 'İşletme'] as StandardRole[]) {
      const cfg = roles[roleName];
      if (!cfg) continue;
      const roleId = ROLE_DOC_ID[roleName];
      roleBatch.set(doc(db, 'roles', roleId), {
        roleName,
        dailyQueryLimit: Math.max(0, Math.min(1000000, Math.floor(cfg.dailyQueryLimit))),
        canIdLookup: Boolean(cfg.canIdLookup),
        canBulkLookup: Boolean(cfg.canBulkLookup),
        canEmailOsint: Boolean(cfg.canEmailOsint),
        updatedAt: serverTimestamp(),
      });
      written += 1;
    }
    await roleBatch.commit();
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, 'roles');
  }
  return written;
}

async function pushUsersToFirestore(users: ServerCloudUser[]): Promise<number> {
  let written = 0;
  try {
    for (let i = 0; i < users.length; i += 100) {
      const slice = users.slice(i, i + 100);
      const existingCreatedMap = new Map<string, unknown>();
      await Promise.all(
        slice.map(async (u) => {
          const uid = sanitizeChunkId(u.googleUid || u.id);
          const snap = await getDoc(doc(db, 'users', uid));
          if (snap.exists()) {
            existingCreatedMap.set(uid, snap.data().createdAt);
          }
        }),
      );
      const userBatch = writeBatch(db);
      for (const u of slice) {
        const uid = sanitizeChunkId(u.googleUid || u.id);
        userBatch.set(doc(db, 'users', uid), {
          id: u.id.slice(0, 128),
          uid,
          username: u.username.slice(0, 32),
          displayName: (u.displayName || u.username).slice(0, 80),
          role: u.role,
          emailVerified: Boolean(u.emailVerified),
          banned: Boolean(u.banned),
          banReason: (u.banReason || '').slice(0, 240),
          dailyUsed: Math.max(0, Math.floor(u.dailyUsed || 0)),
          usageDate: (u.usageDate || '').slice(0, 16),
          createdAt: existingCreatedMap.get(uid) ?? serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        userBatch.set(doc(db, 'users', uid, 'private', 'info'), {
          uid,
          email: u.email.slice(0, 180),
          passwordHash: u.passwordHash.slice(0, 300),
          lastLoginIp: (u.lastLoginIp || '').slice(0, 64),
          lastLoginAt: (u.lastLoginAt || '').slice(0, 64),
          acceptedTermsAt: (u.acceptedTermsAt || '').slice(0, 64),
          updatedAt: serverTimestamp(),
        });
        written += 2;
      }
      await userBatch.commit();
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, 'users');
  }
  return written;
}

const pushedAuditLogIds = new Set<string>();

async function pushAuditLogsToFirestore(
  queryLogs: QueryAuditLog[],
  blockedAttempts: BlockedRegistrationAttempt[],
): Promise<number> {
  let written = 0;
  try {
    const candidates = [
      ...queryLogs.slice(0, 20).map((q) => ({
        docId: sanitizeChunkId(q.id),
        payload: {
          logType: 'query' as const,
          summary: `${q.queryType}: ${q.target} (${q.matchCount})`.slice(0, 300),
          actor: q.username.slice(0, 120),
          ip: q.ip.slice(0, 64),
          eventTime: q.timestamp.slice(0, 64),
        },
      })),
      ...blockedAttempts.slice(0, 20).map((b) => ({
        docId: sanitizeChunkId(b.id),
        payload: {
          logType: 'blocked_attempt' as const,
          summary: `${b.detector}: ${b.email} (${b.reason})`.slice(0, 300),
          actor: b.username.slice(0, 120),
          ip: b.ip.slice(0, 64),
          eventTime: b.timestamp.slice(0, 64),
        },
      })),
    ].filter((c) => !pushedAuditLogIds.has(c.docId));

    if (candidates.length > 0) {
      const existingFlags = await Promise.all(
        candidates.map(async (c) => (await getDoc(doc(db, 'audit_logs', c.docId))).exists()),
      );
      const auditBatch = writeBatch(db);
      candidates.forEach((c, idx) => {
        pushedAuditLogIds.add(c.docId);
        if (!existingFlags[idx]) {
          auditBatch.set(doc(db, 'audit_logs', c.docId), {
            ...c.payload,
            createdAt: serverTimestamp(),
          });
          written += 1;
        }
      });
      if (written > 0) {
        await auditBatch.commit();
      }
    }
  } catch (err) {
    handleFirestoreError(err, OperationType.WRITE, 'audit_logs');
  }
  return written;
}

export interface AutoSyncResult {
  connected: boolean;
  restoredDatasets: number;
  restoredRecords: number;
  restoredUsers: number;
  uploadedDatasets: number;
  deletedDatasets: number;
}

export async function autoSyncCloudWithServer(
  exportSnapshot: () => Promise<CloudBackupSnapshot>,
  importSnapshot: (
    patch: Partial<Omit<CloudBackupSnapshot, 'roles'>> & { roles?: Partial<RoleConfigMap> },
  ) => Promise<{
    restoredUsers: number;
    restoredDatasets: number;
    restoredRecords: number;
  }>,
  options: { restoreMissing?: boolean; pushRoles?: boolean; forceDatasetIds?: string[] } = {},
): Promise<AutoSyncResult> {
  if (!isCloudRootAdminConnected()) {
    return {
      connected: false,
      restoredDatasets: 0,
      restoredRecords: 0,
      restoredUsers: 0,
      uploadedDatasets: 0,
      deletedDatasets: 0,
    };
  }

  const restoreMissing = options.restoreMissing ?? true;
  const pushRoles = options.pushRoles ?? false;
  const forceSet = new Set((options.forceDatasetIds || []).map(sanitizeChunkId));

  let serverSnap = await exportSnapshot();
  const deletedSet = new Set((serverSnap.deletedDatasetIds || []).map(sanitizeChunkId));
  const serverDsIds = new Set(serverSnap.datasets.map((d) => sanitizeChunkId(d.id)));

  // 1. Inspect existing Firestore datasets & roles
  const fsDatasetsSnap = await getDocs(collection(db, 'datasets')).catch((e) =>
    handleFirestoreError(e, OperationType.LIST, 'datasets'),
  );
  const fsDatasetMap = new Map<string, DatasetMeta>();
  for (const d of fsDatasetsSnap.docs) {
    const data = d.data();
    const id = sanitizeChunkId(String(data.id || d.id));
    fsDatasetMap.set(id, {
      id,
      name: String(data.name || 'Dataset'),
      category: (data.category as DatasetMeta['category']) || 'both',
      format: (data.format as DatasetMeta['format']) || 'text',
      recordCount: Number(data.recordCount || 0),
      columns: Array.isArray(data.columns) ? data.columns.map(String) : [],
      mapping: {
        discordIdField: 'discordId',
        emailField: 'email',
        usernameField: 'username',
        sourceField: 'source',
        ipField: 'ip',
        phoneField: 'phone',
        notesField: 'notes',
      },
      importedAt: String(data.importedAt || new Date().toISOString()),
      sizeBytes: Number(data.sizeBytes || 0),
    });
  }

  let restoredDatasets = 0;
  let restoredRecords = 0;
  let restoredUsers = 0;

  // 2. Auto-Restore missing datasets/users/roles from Firestore onto the live server (e.g. after free host restart)
  if (restoreMissing) {
    const missingDatasets: DatasetMeta[] = [];
    for (const [dsId, meta] of fsDatasetMap.entries()) {
      if (!serverDsIds.has(dsId) && !deletedSet.has(dsId)) {
        missingDatasets.push(meta);
      }
    }

    // Check roles from Firestore on initial boot sync
    let restoredRoles: Partial<RoleConfigMap> | undefined;
    if (!pushRoles) {
      const rolesSnap = await getDocs(collection(db, 'roles')).catch((e) =>
        handleFirestoreError(e, OperationType.LIST, 'roles'),
      );
      if (!rolesSnap.empty) {
        const parsedRoles: Partial<RoleConfigMap> = {};
        for (const d of rolesSnap.docs) {
          const data = d.data();
          const name = data.roleName as StandardRole;
          if (name === 'Üye' || name === 'Destekçi' || name === 'İşletme') {
            parsedRoles[name] = {
              dailyQueryLimit: Number(data.dailyQueryLimit ?? 25),
              canIdLookup: Boolean(data.canIdLookup),
              canBulkLookup: Boolean(data.canBulkLookup),
              canEmailOsint: Boolean(data.canEmailOsint),
              canViewUnmasked: true,
              canExport: false,
            };
          }
        }
        if (Object.keys(parsedRoles).length > 0) {
          restoredRoles = parsedRoles;
        }
      }
    }

    // Check missing users from Firestore
    const serverEmails = new Set(serverSnap.users.map((u) => u.email.toLowerCase()));
    const fsUsersSnap = await getDocs(collection(db, 'users')).catch((e) =>
      handleFirestoreError(e, OperationType.LIST, 'users'),
    );
    const missingUsers: ServerCloudUser[] = [];
    for (const d of fsUsersSnap.docs) {
      const u = d.data();
      const privSnap = await getDocFromServer(doc(db, 'users', d.id, 'private', 'info')).catch(() => null);
      const p = privSnap?.data() || {};
      const email = String(p.email || '').toLowerCase();
      if (!email || !p.passwordHash || serverEmails.has(email)) continue;
      missingUsers.push({
        id: String(u.id || `usr_${d.id}`),
        email,
        username: String(u.username),
        displayName: String(u.displayName || u.username),
        passwordHash: String(p.passwordHash),
        googleUid: String(u.uid || d.id),
        role: (u.role as StandardRole) || 'Üye',
        emailVerified: Boolean(u.emailVerified),
        banned: Boolean(u.banned),
        banReason: String(u.banReason || ''),
        dailyUsed: Number(u.dailyUsed || 0),
        usageDate: String(u.usageDate || new Date().toISOString().slice(0, 10)),
        lastLoginAt: p.lastLoginAt ? String(p.lastLoginAt) : null,
        lastLoginIp: p.lastLoginIp ? String(p.lastLoginIp) : null,
        createdAt: new Date().toISOString(),
        acceptedTermsAt: String(p.acceptedTermsAt || new Date().toISOString()),
      });
    }

    if (missingUsers.length > 0 || restoredRoles) {
      const res = await importSnapshot({
        users: missingUsers,
        roles: restoredRoles,
      });
      restoredUsers += res.restoredUsers;
    }

    for (const ds of missingDatasets) {
      const qSnap = await getDocs(query(collection(db, 'dataset_chunks'), where('datasetId', '==', ds.id))).catch((e) =>
        handleFirestoreError(e, OperationType.LIST, 'dataset_chunks'),
      );
      const sorted = qSnap.docs
        .map((c) => c.data())
        .sort((a, b) => Number(a.chunkIndex || 0) - Number(b.chunkIndex || 0));
      const dsRecords: IntelRecord[] = [];
      for (const ch of sorted) {
        if (Array.isArray(ch.records)) {
          for (const rec of ch.records) {
            dsRecords.push(rec as IntelRecord);
          }
        }
      }
      const res = await importSnapshot({
        datasets: [ds],
        records: dsRecords,
      });
      restoredDatasets += res.restoredDatasets;
      restoredRecords += res.restoredRecords;
    }

    if (missingDatasets.length > 0 || missingUsers.length > 0 || restoredRoles) {
      serverSnap = await exportSnapshot();
    }
  }

  // 3. Remove tombstoned datasets from Firestore
  let deletedDatasets = 0;
  for (const delId of deletedSet) {
    if (fsDatasetMap.has(delId)) {
      await deleteDatasetFromFirestore(delId);
      deletedDatasets += 1;
    }
  }

  // 4. Push roles (when edited or if Firestore has none yet)
  if (pushRoles) {
    await pushRolesToFirestore(serverSnap.roles);
  } else {
    const rolesSnap = await getDocs(collection(db, 'roles')).catch(() => null);
    if (rolesSnap && rolesSnap.empty) {
      await pushRolesToFirestore(serverSnap.roles);
    }
  }

  // 5. Push users & audit logs
  if (serverSnap.users.length > 0) {
    await pushUsersToFirestore(serverSnap.users);
  }
  await pushAuditLogsToFirestore(serverSnap.queryLogs, serverSnap.blockedAttempts);

  // 6. Push new or modified datasets (bounded for Firebase Spark free tier) and clean up stale chunks
  const MAX_FREE_FIRESTORE_RECORDS_PER_DATASET = 12500;
  let uploadedDatasets = 0;
  const datasetsToUpload = serverSnap.datasets.filter((ds) => {
    if (ds.recordCount > MAX_FREE_FIRESTORE_RECORDS_PER_DATASET) return false;
    const cleanId = sanitizeChunkId(ds.id);
    const existing = fsDatasetMap.get(cleanId);
    return (
      !existing ||
      existing.recordCount !== ds.recordCount ||
      existing.name !== ds.name ||
      existing.sizeBytes !== ds.sizeBytes ||
      existing.importedAt !== ds.importedAt ||
      forceSet.has(cleanId)
    );
  });

  if (datasetsToUpload.length > 0) {
    try {
      for (let i = 0; i < datasetsToUpload.length; i += 100) {
        const slice = datasetsToUpload.slice(i, i + 100);
        const dsBatch = writeBatch(db);
        for (const ds of slice) {
          const dsId = sanitizeChunkId(ds.id);
          dsBatch.set(doc(db, 'datasets', dsId), {
            id: dsId,
            name: ds.name.slice(0, 120),
            category: ds.category || 'both',
            format: ds.format,
            recordCount: Math.max(0, Math.floor(ds.recordCount)),
            columns: (ds.columns || []).slice(0, 50).map((c) => String(c).slice(0, 60)),
            importedAt: (ds.importedAt || '').slice(0, 64),
            sizeBytes: Math.max(0, Math.floor(ds.sizeBytes || 0)),
            updatedAt: serverTimestamp(),
          });
        }
        await dsBatch.commit();
      }
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, 'datasets');
    }

    const byDataset = new Map<string, IntelRecord[]>();
    const uploadIds = new Set(datasetsToUpload.map((d) => sanitizeChunkId(d.id)));
    for (const r of serverSnap.records) {
      const dsId = sanitizeChunkId(r.datasetId);
      if (!uploadIds.has(dsId)) continue;
      const list = byDataset.get(dsId);
      if (list) list.push(r);
      else byDataset.set(dsId, [r]);
    }

    const chunkEntries: ReturnType<typeof buildSafeRecordChunks> = [];
    const newChunkCountByDs = new Map<string, number>();
    for (const ds of datasetsToUpload) {
      const dsId = sanitizeChunkId(ds.id);
      const recs = byDataset.get(dsId) || [];
      const built = buildSafeRecordChunks(dsId, recs);
      newChunkCountByDs.set(dsId, built.length);
      chunkEntries.push(...built);
    }

    try {
      for (let i = 0; i < chunkEntries.length; i += 15) {
        const batchSlice = chunkEntries.slice(i, i + 15);
        const chunkBatch = writeBatch(db);
        for (const ch of batchSlice) {
          chunkBatch.set(doc(db, 'dataset_chunks', ch.chunkId), {
            datasetId: ch.datasetId,
            chunkIndex: ch.chunkIndex,
            totalChunks: ch.totalChunks,
            records: ch.records,
            updatedAt: serverTimestamp(),
          });
        }
        await chunkBatch.commit();
      }

      // Remove stale trailing chunks when an edited dataset shrank in chunk count
      for (const ds of datasetsToUpload) {
        const dsId = sanitizeChunkId(ds.id);
        if (!fsDatasetMap.has(dsId)) continue;
        const expectedTotal = newChunkCountByDs.get(dsId) ?? 1;
        const existingChunksSnap = await getDocs(
          query(collection(db, 'dataset_chunks'), where('datasetId', '==', dsId)),
        );
        const staleRefs = existingChunksSnap.docs
          .filter((d) => Number(d.data().chunkIndex ?? -1) >= expectedTotal)
          .map((d) => d.ref);
        for (let i = 0; i < staleRefs.length; i += 200) {
          const delBatch = writeBatch(db);
          for (const ref of staleRefs.slice(i, i + 200)) {
            delBatch.delete(ref);
          }
          await delBatch.commit();
        }
      }
    } catch (err) {
      handleFirestoreError(err, OperationType.WRITE, 'dataset_chunks');
    }

    uploadedDatasets = datasetsToUpload.length;
  }

  return {
    connected: true,
    restoredDatasets,
    restoredRecords,
    restoredUsers,
    uploadedDatasets,
    deletedDatasets,
  };
}
