import type {
  AdminUserRow,
  BlockedRegistrationAttempt,
  BulkQueryRow,
  DatasetMeta,
  EmailOsintReport,
  IntelRecord,
  PublicUser,
  QueryAuditLog,
  RoleConfigMap,
  RolePermissions,
  SearchResult,
  StandardRole,
} from '../types/intel';

const TOKEN_STORAGE_KEY = 'sentarika_session_token';

export function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string | null) {
  try {
    if (token) localStorage.setItem(TOKEN_STORAGE_KEY, token);
    else localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Ignore storage errors
  }
}

export function parseSessionTokenClaims(
  token: string | null,
): { userId: string; role: string; exp: number; adminGrant?: boolean; adminEpoch?: string } | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0]) return null;
  try {
    const b64 = parts[0].replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    const json = atob(b64 + pad);
    const parsed = JSON.parse(json) as {
      userId?: unknown;
      role?: unknown;
      exp?: unknown;
      adminGrant?: unknown;
      adminEpoch?: unknown;
    };
    if (typeof parsed.userId !== 'string' || typeof parsed.role !== 'string' || typeof parsed.exp !== 'number') {
      return null;
    }
    return {
      userId: parsed.userId,
      role: parsed.role,
      exp: parsed.exp,
      adminGrant: parsed.adminGrant === true,
      adminEpoch: typeof parsed.adminEpoch === 'string' ? parsed.adminEpoch : undefined,
    };
  } catch {
    return null;
  }
}

export function isTokenConsistentWithUser(token: string | null, user: PublicUser | null): boolean {
  if (!token || !user) return false;
  const claims = parseSessionTokenClaims(token);
  if (!claims || Date.now() > claims.exp) return false;
  if (claims.userId !== user.id || claims.role !== user.role) return false;
  if (user.role === 'Admin') {
    if (user.id !== 'admin_root' || claims.adminGrant !== true || !claims.adminEpoch) {
      return false;
    }
  }
  return true;
}

export function freezePublicUser(user: PublicUser): PublicUser {
  if (!user || typeof user !== 'object') return user;
  if (user.permissions && typeof user.permissions === 'object') {
    Object.freeze(user.permissions);
  }
  return Object.freeze(user);
}

export class ApiError extends Error {
  status: number;
  data: Record<string, unknown>;
  constructor(message: string, status: number, data: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

const nativeFetch: typeof window.fetch = window.fetch.bind(window);

async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await nativeFetch(path, { ...options, headers, cache: 'no-store' });
  const data = (await res.json().catch(() => ({}))) as { error?: string } & Record<string, unknown>;
  if (!res.ok) {
    throw new ApiError(data.error || `İstek başarısız oldu (HTTP ${res.status}).`, res.status, data);
  }
  return data as T;
}

export async function apiGetHealth(): Promise<{ ok: boolean }> {
  return apiRequest('/api/health');
}

export type GoogleAuthResponse =
  | { status: 'authenticated'; token: string; user: PublicUser }
  | { status: 'needs_profile'; email: string; displayName: string; suggestedUsername: string };

export async function apiGoogleAuth(idToken: string): Promise<GoogleAuthResponse> {
  const res = await apiRequest<GoogleAuthResponse>('/api/auth/google', {
    method: 'POST',
    body: JSON.stringify({ idToken }),
  });
  if (res.status === 'authenticated') {
    if (!isTokenConsistentWithUser(res.token, res.user) || res.user.role === 'Admin') {
      throw new ApiError('Oturum doğrulaması tutarsız.', 403, {});
    }
    return { ...res, user: freezePublicUser(res.user) };
  }
  return res;
}

export async function apiGoogleRegister(payload: {
  idToken: string;
  username: string;
  password: string;
  acceptedTerms: boolean;
}): Promise<{ token: string; user: PublicUser }> {
  const res = await apiRequest<{ token: string; user: PublicUser }>('/api/auth/google-register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (!isTokenConsistentWithUser(res.token, res.user) || res.user.role === 'Admin') {
    throw new ApiError('Oturum doğrulaması tutarsız.', 403, {});
  }
  return { token: res.token, user: freezePublicUser(res.user) };
}

export async function apiLogin(payload: {
  username: string;
  password: string;
}): Promise<{ token: string; user: PublicUser }> {
  const res = await apiRequest<{ token: string; user: PublicUser }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (!isTokenConsistentWithUser(res.token, res.user) || res.user.role === 'Admin') {
    throw new ApiError('Oturum doğrulaması tutarsız.', 403, {});
  }
  return { token: res.token, user: freezePublicUser(res.user) };
}

export async function apiAdminLogin(key: string): Promise<{ token: string; user: PublicUser }> {
  const res = await apiRequest<{ token: string; user: PublicUser }>('/api/auth/admin-login', {
    method: 'POST',
    body: JSON.stringify({ key }),
  });
  if (!isTokenConsistentWithUser(res.token, res.user) || res.user.role !== 'Admin') {
    throw new ApiError('Yönetici oturumu doğrulanamadı.', 403, {});
  }
  return { token: res.token, user: freezePublicUser(res.user) };
}

export async function apiAdminGoogleLogin(idToken: string): Promise<{ token: string; user: PublicUser }> {
  const res = await apiRequest<{ token: string; user: PublicUser }>('/api/auth/admin-google-login', {
    method: 'POST',
    body: JSON.stringify({ idToken }),
  });
  if (!isTokenConsistentWithUser(res.token, res.user) || res.user.role !== 'Admin') {
    throw new ApiError('Google yönetici oturumu doğrulanamadı.', 403, {});
  }
  return { token: res.token, user: freezePublicUser(res.user) };
}

export async function apiAdminCloudAuthorize(idToken: string): Promise<{ authorized: boolean }> {
  return apiRequest<{ authorized: boolean }>('/api/admin/cloud-authorize', {
    method: 'POST',
    body: JSON.stringify({ idToken }),
  });
}

export async function apiGetMe(): Promise<{
  user: PublicUser;
  stats: { totalDatasets: number; totalRecords: number; totalUsers: number };
}> {
  const res = await apiRequest<{
    user: PublicUser;
    stats: { totalDatasets: number; totalRecords: number; totalUsers: number };
  }>('/api/auth/me');
  const token = getStoredToken();
  if (!isTokenConsistentWithUser(token, res.user)) {
    setStoredToken(null);
    throw new ApiError('Oturum bütünlüğü doğrulanamadı.', 401, {});
  }
  return { user: freezePublicUser(res.user), stats: res.stats };
}

export async function apiSearch(query: string): Promise<{ result: SearchResult; user: PublicUser }> {
  return apiRequest('/api/search', {
    method: 'POST',
    body: JSON.stringify({ query }),
  });
}

export async function apiBulkSearch(rawInput: string): Promise<{
  rows: BulkQueryRow[];
  maskedByPolicy: boolean;
  user: PublicUser;
}> {
  return apiRequest('/api/bulk-search', {
    method: 'POST',
    body: JSON.stringify({ rawInput }),
  });
}

export async function apiEmailOsint(
  email: string,
  lang: 'tr' | 'en' = 'tr',
): Promise<{
  report: EmailOsintReport;
  maskedByPolicy: boolean;
  user: PublicUser;
}> {
  return apiRequest('/api/osint/email', {
    method: 'POST',
    body: JSON.stringify({ email, lang }),
  });
}

export async function apiUploadDataset(
  meta: DatasetMeta,
  records: IntelRecord[],
): Promise<{ dataset: DatasetMeta; stats: { totalDatasets: number; totalRecords: number; totalUsers: number } }> {
  return apiRequest('/api/datasets', {
    method: 'POST',
    body: JSON.stringify({ meta, records }),
  });
}

export async function apiAppendDatasetBatch(
  datasetId: string,
  records: IntelRecord[],
): Promise<{ dataset: DatasetMeta; stats: { totalDatasets: number; totalRecords: number; totalUsers: number } }> {
  return apiRequest(`/api/admin/datasets/${encodeURIComponent(datasetId)}/append-batch`, {
    method: 'POST',
    body: JSON.stringify({ records }),
  });
}

export async function apiLoadSyntheticDataset(): Promise<{
  dataset: DatasetMeta;
  stats: { totalDatasets: number; totalRecords: number; totalUsers: number };
}> {
  return apiRequest('/api/datasets/synthetic', { method: 'POST' });
}

export async function apiDeleteDataset(id: string): Promise<{
  ok: boolean;
  stats: { totalDatasets: number; totalRecords: number; totalUsers: number };
}> {
  return apiRequest(`/api/datasets/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export async function apiAdminGetDatasetRecords(
  datasetId: string,
  q = '',
  page = 1,
  limit = 40,
): Promise<{ meta: DatasetMeta; total: number; records: IntelRecord[] }> {
  const params = new URLSearchParams();
  if (q) params.set('q', q);
  params.set('page', String(page));
  params.set('limit', String(limit));
  return apiRequest(`/api/admin/datasets/${encodeURIComponent(datasetId)}/records?${params.toString()}`);
}

export async function apiAdminUpdateDataset(
  datasetId: string,
  payload: {
    name?: string;
    mapping?: import('../types/intel').FieldMapping;
    reNormalize?: boolean;
    appendRecords?: IntelRecord[];
  },
): Promise<{ dataset: DatasetMeta; stats: { totalDatasets: number; totalRecords: number; totalUsers: number } }> {
  return apiRequest(`/api/admin/datasets/${encodeURIComponent(datasetId)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export async function apiAdminAddDatasetRecord(
  datasetId: string,
  record: {
    discordId: string;
    email: string;
    username: string;
    source: string;
    ip: string;
    phone: string;
    notes: string;
    extra?: Record<string, string>;
  },
): Promise<{ dataset: DatasetMeta; record: IntelRecord; stats: { totalDatasets: number; totalRecords: number; totalUsers: number } }> {
  return apiRequest(`/api/admin/datasets/${encodeURIComponent(datasetId)}/records`, {
    method: 'POST',
    body: JSON.stringify(record),
  });
}

export async function apiAdminUpdateDatasetRecord(
  datasetId: string,
  recordId: string,
  patch: Partial<{
    discordId: string;
    email: string;
    username: string;
    source: string;
    ip: string;
    phone: string;
    notes: string;
    extra: Record<string, string>;
  }>,
): Promise<{ dataset: DatasetMeta; record: IntelRecord; stats: { totalDatasets: number; totalRecords: number; totalUsers: number } }> {
  return apiRequest(
    `/api/admin/datasets/${encodeURIComponent(datasetId)}/records/${encodeURIComponent(recordId)}`,
    {
      method: 'PATCH',
      body: JSON.stringify(patch),
    },
  );
}

export async function apiAdminDeleteDatasetRecord(
  datasetId: string,
  recordId: string,
): Promise<{ ok: boolean; dataset: DatasetMeta; stats: { totalDatasets: number; totalRecords: number; totalUsers: number } }> {
  return apiRequest(
    `/api/admin/datasets/${encodeURIComponent(datasetId)}/records/${encodeURIComponent(recordId)}`,
    { method: 'DELETE' },
  );
}

export async function apiVerifyAdmin(nonce: string): Promise<{ verified: boolean; role: string; nonce: string }> {
  return apiRequest(`/api/admin/verify?nonce=${encodeURIComponent(nonce)}`);
}

export async function apiAdminOverview(): Promise<{
  users: AdminUserRow[];
  roles: RoleConfigMap;
  datasets: DatasetMeta[];
  queryLogs: QueryAuditLog[];
  blockedAttempts: BlockedRegistrationAttempt[];
  recordsSample: IntelRecord[];
  stats: { totalDatasets: number; totalRecords: number; totalUsers: number };
}> {
  return apiRequest('/api/admin/overview');
}

export async function apiAdminDatabaseRecords(
  q: string,
  datasetId?: string,
): Promise<{ total: number; records: IntelRecord[] }> {
  const params = new URLSearchParams();
  if (q) params.set('q', q);
  if (datasetId) params.set('datasetId', datasetId);
  return apiRequest(`/api/admin/database/records?${params.toString()}`);
}

export async function apiUpdateRoleConfig(
  role: StandardRole,
  perms: Partial<RolePermissions>,
): Promise<{ roles: RoleConfigMap }> {
  return apiRequest(`/api/admin/roles/${encodeURIComponent(role)}`, {
    method: 'PATCH',
    body: JSON.stringify(perms),
  });
}

export async function apiUpdateUser(
  userId: string,
  payload: { role?: StandardRole; banned?: boolean; banReason?: string; approveEmail?: boolean },
): Promise<{ user: PublicUser }> {
  return apiRequest(`/api/admin/users/${encodeURIComponent(userId)}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}

export async function apiAdminKickAllUsers(
  clearAccounts = false,
): Promise<{ ok: boolean; kickedCount: number; clearAccounts: boolean }> {
  return apiRequest('/api/admin/users/kick-all', {
    method: 'POST',
    body: JSON.stringify({ clearAccounts }),
  });
}

export async function apiAdminExportCloudSnapshot(): Promise<import('./firestoreSync').CloudBackupSnapshot> {
  return apiRequest('/api/admin/firestore/export-snapshot');
}

export async function apiAdminImportCloudSnapshot(
  snapshot: Partial<Omit<import('./firestoreSync').CloudBackupSnapshot, 'roles'>> & {
    roles?: Partial<RoleConfigMap>;
  },
): Promise<{
  ok: boolean;
  restoredUsers: number;
  restoredDatasets: number;
  restoredRecords: number;
  stats: { totalDatasets: number; totalRecords: number; totalUsers: number };
}> {
  return apiRequest('/api/admin/firestore/import-snapshot', {
    method: 'POST',
    body: JSON.stringify(snapshot),
  });
}
