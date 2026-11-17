import fs from 'node:fs';
import path from 'node:path';
import type { StoredUser } from './store.ts';
import type { StandardRole } from '../src/types/intel.ts';

interface FirebaseConfig {
  projectId: string;
  firestoreDatabaseId: string;
}

let cachedConfig: FirebaseConfig | null = null;

function getConfig(): FirebaseConfig {
  if (cachedConfig) return cachedConfig;
  const raw = fs.readFileSync(path.resolve(process.cwd(), 'firebase-applet-config.json'), 'utf8');
  const parsed = JSON.parse(raw) as Partial<FirebaseConfig>;
  if (!parsed.projectId || !parsed.firestoreDatabaseId) {
    throw new Error('Firebase Firestore yapılandırması eksik.');
  }
  cachedConfig = {
    projectId: parsed.projectId,
    firestoreDatabaseId: parsed.firestoreDatabaseId,
  };
  return cachedConfig;
}

function getDocsBaseUrl(): string {
  const { projectId, firestoreDatabaseId } = getConfig();
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(firestoreDatabaseId)}/documents`;
}

function getCommitUrl(): string {
  const { projectId, firestoreDatabaseId } = getConfig();
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(firestoreDatabaseId)}/documents:commit`;
}

function getDocResourceName(docPath: string): string {
  const { projectId, firestoreDatabaseId } = getConfig();
  return `projects/${projectId}/databases/${firestoreDatabaseId}/documents/${docPath}`;
}

type FirestoreValue =
  | { stringValue: string }
  | { integerValue: string }
  | { booleanValue: boolean };

function strVal(v: string): FirestoreValue {
  return { stringValue: v };
}

function intVal(v: number): FirestoreValue {
  return { integerValue: String(Math.max(0, Math.floor(v))) };
}

function boolVal(v: boolean): FirestoreValue {
  return { booleanValue: Boolean(v) };
}

function readStr(fields: Record<string, Record<string, unknown>> | undefined, key: string, fallback = ''): string {
  const val = fields?.[key]?.stringValue;
  return typeof val === 'string' ? val : fallback;
}

function readBool(fields: Record<string, Record<string, unknown>> | undefined, key: string, fallback = false): boolean {
  const val = fields?.[key]?.booleanValue;
  return typeof val === 'boolean' ? val : fallback;
}

function readInt(fields: Record<string, Record<string, unknown>> | undefined, key: string, fallback = 0): number {
  const val = fields?.[key]?.integerValue;
  if (typeof val === 'string' || typeof val === 'number') {
    const n = Number(val);
    return Number.isFinite(n) ? n : fallback;
  }
  return fallback;
}

export async function syncUserToFirestoreWithToken(idToken: string, user: StoredUser): Promise<boolean> {
  if (!user.googleUid || !idToken) return false;
  const uid = user.googleUid;
  const userDocPath = `users/${uid}`;
  const privateDocPath = `users/${uid}/private/info`;

  const body = {
    writes: [
      {
        update: {
          name: getDocResourceName(userDocPath),
          fields: {
            id: strVal(user.id.slice(0, 128)),
            uid: strVal(uid.slice(0, 128)),
            username: strVal(user.username.slice(0, 32)),
            displayName: strVal((user.displayName || user.username).slice(0, 80)),
            role: strVal(user.role),
            emailVerified: boolVal(true),
            banned: boolVal(Boolean(user.banned)),
            banReason: strVal((user.banReason || '').slice(0, 240)),
            dailyUsed: intVal(user.dailyUsed || 0),
            usageDate: strVal((user.usageDate || '').slice(0, 16)),
          },
        },
        updateTransforms: [
          { fieldPath: 'createdAt', setToServerValue: 'REQUEST_TIME' },
          { fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' },
        ],
      },
      {
        update: {
          name: getDocResourceName(privateDocPath),
          fields: {
            uid: strVal(uid.slice(0, 128)),
            email: strVal(user.email.slice(0, 180)),
            passwordHash: strVal(user.passwordHash.slice(0, 300)),
            lastLoginIp: strVal((user.lastLoginIp || '').slice(0, 64)),
            lastLoginAt: strVal((user.lastLoginAt || '').slice(0, 64)),
            acceptedTermsAt: strVal((user.acceptedTermsAt || '').slice(0, 64)),
          },
        },
        updateTransforms: [{ fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' }],
      },
    ],
  };

  try {
    const resp = await fetch(getCommitUrl(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(6000),
    });
    return resp.ok;
  } catch {
    return false;
  }
}

export async function loadUserFromFirestoreWithToken(idToken: string, uid: string): Promise<StoredUser | null> {
  if (!idToken || !uid || !/^[a-zA-Z0-9_-]{1,128}$/.test(uid)) return null;
  const base = getDocsBaseUrl();
  const headers = { Authorization: `Bearer ${idToken}` };

  try {
    const [userRes, privRes] = await Promise.all([
      fetch(`${base}/users/${encodeURIComponent(uid)}`, { headers, signal: AbortSignal.timeout(5000) }),
      fetch(`${base}/users/${encodeURIComponent(uid)}/private/info`, { headers, signal: AbortSignal.timeout(5000) }),
    ]);

    if (!userRes.ok || !privRes.ok) return null;

    const userDoc = (await userRes.json()) as { fields?: Record<string, Record<string, unknown>>; createTime?: string };
    const privDoc = (await privRes.json()) as { fields?: Record<string, Record<string, unknown>> };
    const uf = userDoc.fields;
    const pf = privDoc.fields;
    if (!uf || !pf) return null;

    const roleRaw = readStr(uf, 'role', 'Üye');
    const role: StandardRole =
      roleRaw === 'Destekçi' || roleRaw === 'İşletme' ? roleRaw : 'Üye';

    const email = readStr(pf, 'email').toLowerCase();
    const username = readStr(uf, 'username');
    const passwordHash = readStr(pf, 'passwordHash');
    if (!email || !username || !passwordHash) return null;

    const rawId = readStr(uf, 'id', `usr_${uid}`);
    const safeId = rawId && rawId !== 'admin_root' && rawId.startsWith('usr_') ? rawId : `usr_${uid}`;

    return {
      id: safeId,
      email,
      username,
      displayName: readStr(uf, 'displayName', username),
      passwordHash,
      googleUid: uid,
      role,
      emailVerified: readBool(uf, 'emailVerified', true),
      banned: readBool(uf, 'banned', false),
      banReason: readStr(uf, 'banReason', ''),
      dailyUsed: readInt(uf, 'dailyUsed', 0),
      usageDate: readStr(uf, 'usageDate', new Date().toISOString().slice(0, 10)),
      lastLoginAt: readStr(pf, 'lastLoginAt') || null,
      lastLoginIp: readStr(pf, 'lastLoginIp') || null,
      createdAt: userDoc.createTime || new Date().toISOString(),
      acceptedTermsAt: readStr(pf, 'acceptedTermsAt') || new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

export async function touchUserUsageInFirestoreWithToken(idToken: string, user: StoredUser): Promise<boolean> {
  if (!user.googleUid || !idToken) return false;
  const uid = user.googleUid;
  const userDocPath = `users/${uid}`;
  const privateDocPath = `users/${uid}/private/info`;

  const body = {
    writes: [
      {
        update: {
          name: getDocResourceName(userDocPath),
          fields: {
            displayName: strVal((user.displayName || user.username).slice(0, 80)),
            dailyUsed: intVal(user.dailyUsed || 0),
            usageDate: strVal((user.usageDate || '').slice(0, 16)),
          },
        },
        updateMask: { fieldPaths: ['displayName', 'dailyUsed', 'usageDate'] },
        updateTransforms: [{ fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' }],
      },
      {
        update: {
          name: getDocResourceName(privateDocPath),
          fields: {
            lastLoginAt: strVal((user.lastLoginAt || '').slice(0, 64)),
          },
        },
        updateMask: { fieldPaths: ['lastLoginAt'] },
        updateTransforms: [{ fieldPath: 'updatedAt', setToServerValue: 'REQUEST_TIME' }],
      },
    ],
  };

  try {
    const resp = await fetch(getCommitUrl(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${idToken}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    return resp.ok;
  } catch {
    return false;
  }
}

export async function loadRolesFromFirestoreWithToken(
  idToken: string,
): Promise<Partial<Record<StandardRole, { dailyQueryLimit: number; canIdLookup: boolean; canBulkLookup: boolean; canEmailOsint: boolean }>> | null> {
  if (!idToken) return null;
  const base = getDocsBaseUrl();
  const headers = { Authorization: `Bearer ${idToken}` };
  const map: Array<{ id: string; role: StandardRole }> = [
    { id: 'uye', role: 'Üye' },
    { id: 'destekci', role: 'Destekçi' },
    { id: 'isletme', role: 'İşletme' },
  ];

  try {
    const results = await Promise.all(
      map.map(async ({ id, role }) => {
        const res = await fetch(`${base}/roles/${id}`, { headers, signal: AbortSignal.timeout(4000) });
        if (!res.ok) return null;
        const doc = (await res.json()) as { fields?: Record<string, Record<string, unknown>> };
        if (!doc.fields) return null;
        return {
          role,
          cfg: {
            dailyQueryLimit: readInt(doc.fields, 'dailyQueryLimit', 25),
            canIdLookup: readBool(doc.fields, 'canIdLookup', true),
            canBulkLookup: readBool(doc.fields, 'canBulkLookup', false),
            canEmailOsint: readBool(doc.fields, 'canEmailOsint', true),
          },
        };
      }),
    );

    const out: Partial<
      Record<StandardRole, { dailyQueryLimit: number; canIdLookup: boolean; canBulkLookup: boolean; canEmailOsint: boolean }>
    > = {};
    let count = 0;
    for (const item of results) {
      if (item) {
        out[item.role] = item.cfg;
        count += 1;
      }
    }
    return count > 0 ? out : null;
  } catch {
    return null;
  }
}

