export interface SnowflakeInfo {
  id: string;
  timestampMs: number;
  createdAtIso: string;
  workerId: number;
  processId: number;
  increment: number;
  binary64: string;
  accountAge: {
    years: number;
    months: number;
    days: number;
    totalDays: number;
  };
}

export interface FieldMapping {
  discordIdField: string | null;
  emailField: string | null;
  usernameField: string | null;
  sourceField: string | null;
  ipField: string | null;
  phoneField: string | null;
  notesField: string | null;
}

export type DatasetCategory = 'id_lookup' | 'email_osint' | 'both';

export interface DatasetMeta {
  id: string;
  name: string;
  category: DatasetCategory;
  format: 'json' | 'csv' | 'ndjson' | 'text' | 'synthetic';
  recordCount: number;
  columns: string[];
  mapping: FieldMapping;
  importedAt: string;
  sizeBytes: number;
}

export type DatabaseSourceType = 'leak' | 'sizinti' | 'public_info';

export interface IntelRecord {
  id: string;
  datasetId: string;
  datasetName: string;
  dbType?: DatabaseSourceType;
  discordId: string;
  email: string;
  username: string;
  source: string;
  ip: string;
  phone: string;
  notes: string;
  extra: Record<string, string>;
}

export type QuerySearchMode = 'auto' | 'discord_id' | 'email' | 'username' | 'any';

export interface SearchResult {
  query: string;
  detectedType: 'discord_id' | 'email' | 'username' | 'general';
  snowflake: SnowflakeInfo | null;
  primaryMatches: IntelRecord[];
  relatedMatches: IntelRecord[];
  durationMs: number;
  maskedByPolicy?: boolean;
  scanMetrics?: {
    scannedRecords: number;
    scannedDatasets: number;
    scannedBytes: number;
  };
}

export interface BulkQueryRow {
  input: string;
  validSnowflake: boolean;
  snowflake: SnowflakeInfo | null;
  matches: IntelRecord[];
}

export interface QueryHistoryItem {
  id: string;
  query: string;
  detectedType: 'discord_id' | 'email' | 'username' | 'general';
  matchCount: number;
  timestamp: string;
}

export type UserRole = 'Üye' | 'Destekçi' | 'İşletme' | 'Admin';
export type StandardRole = 'Üye' | 'Destekçi' | 'İşletme';

export interface RolePermissions {
  dailyQueryLimit: number;
  canIdLookup: boolean;
  canBulkLookup: boolean;
  canEmailOsint: boolean;
  canViewUnmasked: boolean;
  canExport: boolean;
}

export type RoleConfigMap = Record<StandardRole, RolePermissions>;

export interface PublicUser {
  id: string;
  email: string;
  username: string;
  displayName: string;
  role: UserRole;
  emailVerified: boolean;
  authProvider?: 'google' | 'password';
  banned: boolean;
  banReason: string;
  dailyUsed: number;
  usageDate: string;
  lastLoginAt: string | null;
  createdAt: string;
  permissions: RolePermissions;
}

export interface AdminUserRow extends PublicUser {
  lastLoginIp: string | null;
}

export interface QueryAuditLog {
  id: string;
  userId: string;
  username: string;
  queryType: 'id_lookup' | 'email_osint' | 'bulk_lookup';
  target: string;
  matchCount: number;
  ip: string;
  timestamp: string;
}

export interface BlockedRegistrationAttempt {
  id: string;
  email: string;
  username: string;
  domain: string;
  reason: string;
  detector: string;
  ip: string;
  timestamp: string;
}

export interface EmailOsintSourceResult {
  source: string;
  status: 'found' | 'not_found' | 'error' | 'info';
  summary: string;
  details: Record<string, string | string[]>;
}

export interface EmailOsintReport {
  email: string;
  domain: string;
  isValidSyntax: boolean;
  isDisposable: boolean;
  mailProvider: string;
  mxRecords: { exchange: string; priority: number }[];
  spfRecord: string | null;
  dmarcRecord: string | null;
  rdap: {
    registrar: string | null;
    createdDate: string | null;
    expiryDate: string | null;
  } | null;
  externalChecks: EmailOsintSourceResult[];
  localMatches: IntelRecord[];
  pivotLinks: { label: string; url: string }[];
  checkedAt: string;
  durationMs: number;
}

export type ActiveTab = 'lookup' | 'email_osint' | 'bulk' | 'profile' | 'admin' | 'legal' | 'history';
