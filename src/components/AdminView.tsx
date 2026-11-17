import { useCallback, useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import {
  Database,
  Sliders,
  Users,
  Upload,
  Trash2,
  Ban,
  CheckCircle2,
  AlertCircle,
  Table2,
  Search,
  MailCheck,
  ShieldAlert,
  UserX,
  Cloud,
  Pencil,
  Download,
  FileUp,
  Lock,
} from 'lucide-react';
import { DatasetEditorModal } from './DatasetEditorModal';
import type {
  AdminUserRow,
  BlockedRegistrationAttempt,
  DatasetMeta,
  IntelRecord,
  QueryAuditLog,
  RoleConfigMap,
  RolePermissions,
  StandardRole,
} from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import {
  ApiError,
  apiAdminCloudAuthorize,
  apiAdminDatabaseRecords,
  apiAdminExportCloudSnapshot,
  apiAdminImportCloudSnapshot,
  apiAdminKickAllUsers,
  apiAdminOverview,
  apiDeleteDataset,
  apiLoadSyntheticDataset,
  apiUpdateRoleConfig,
  apiUpdateUser,
} from '../utils/api';
import {
  clearAllMembersFromFirestore,
  connectAdminGoogleAccount,
  deleteDatasetFromFirestore,
  isCloudRootAdminConnected,
  type CloudBackupSnapshot,
} from '../utils/firestoreSync';
import { formatTurkishDate } from '../utils/snowflake';

interface AdminViewProps {
  onOpenImport: () => void;
  onStatsChanged: () => Promise<void>;
  onUnauthorizedAdmin: () => void;
  refreshSignal?: number;
  cloudSyncStatus?: 'idle' | 'syncing' | 'synced' | 'needs_google' | 'error';
  cloudSyncDetail?: string | null;
  onRequestCloudSync?: (opts?: {
    pushRoles?: boolean;
    restoreMissing?: boolean;
    forceDatasetIds?: string[];
  }) => Promise<void>;
}

const STANDARD_ROLES: StandardRole[] = ['Üye', 'Destekçi', 'İşletme'];

export function AdminView({
  onOpenImport,
  onStatsChanged,
  onUnauthorizedAdmin,
  refreshSignal = 0,
  cloudSyncStatus = 'idle',
  cloudSyncDetail = null,
  onRequestCloudSync,
}: AdminViewProps) {
  const { lang, t } = useI18n();
  const [adminVerified, setAdminVerified] = useState(false);
  const [subTab, setSubTab] = useState<'datasets' | 'roles' | 'users' | 'database'>('datasets');
  const [datasets, setDatasets] = useState<DatasetMeta[]>([]);
  const [roles, setRoles] = useState<RoleConfigMap | null>(null);
  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [blockedAttempts, setBlockedAttempts] = useState<BlockedRegistrationAttempt[]>([]);
  const [queryLogs, setQueryLogs] = useState<QueryAuditLog[]>([]);
  const [dbRecords, setDbRecords] = useState<IntelRecord[]>([]);
  const [dbTotal, setDbTotal] = useState(0);
  const [dbSearch, setDbSearch] = useState('');
  const [dbDatasetFilter, setDbDatasetFilter] = useState('');
  const [dbLoading, setDbLoading] = useState(false);

  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [banTargetId, setBanTargetId] = useState<string | null>(null);
  const [banReason, setBanReason] = useState('');
  const [kickConfirmOpen, setKickConfirmOpen] = useState(false);
  const [cloudConnected, setCloudConnected] = useState<boolean>(() => isCloudRootAdminConnected());
  const [cloudBusy, setCloudBusy] = useState(false);
  const [vaultBusy, setVaultBusy] = useState(false);
  const restoreInputRef = useRef<HTMLInputElement | null>(null);
  const [editingDataset, setEditingDataset] = useState<DatasetMeta | null>(null);

  const queryTypeLabel = (qt: QueryAuditLog['queryType']) => {
    if (qt === 'id_lookup') return t('ID Sorgu', 'ID Lookup');
    if (qt === 'email_osint') return t('E-posta OSINT', 'Email OSINT');
    return t('Toplu Sorgu', 'Bulk Lookup');
  };

  const loadOverview = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiAdminOverview();
      setAdminVerified(true);
      setDatasets(data.datasets);
      setRoles(data.roles);
      setUsers(data.users);
      setBlockedAttempts(data.blockedAttempts || []);
      setQueryLogs(data.queryLogs);
      setDbRecords(data.recordsSample);
      setDbTotal(data.stats.totalRecords);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setAdminVerified(false);
        onUnauthorizedAdmin();
        return;
      }
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Yönetici verileri alınamadı.', 'Failed to load admin data.') });
    } finally {
      setLoading(false);
    }
  }, [t, onUnauthorizedAdmin]);

  useEffect(() => {
    loadOverview();
  }, [loadOverview, refreshSignal]);

  const handleLoadSynthetic = async () => {
    setFeedback(null);
    try {
      await apiLoadSyntheticDataset();
      await Promise.all([loadOverview(), onStatsChanged()]);
      void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({ type: 'ok', text: t('Sentetik test veri seti başarıyla eklendi.', 'Synthetic test dataset added successfully.') });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Yükleme başarısız.', 'Upload failed.') });
    }
  };

  const handleDeleteDataset = async (id: string) => {
    setFeedback(null);
    try {
      await apiDeleteDataset(id);
      await Promise.all([loadOverview(), onStatsChanged()]);
      void deleteDatasetFromFirestore(id).catch(() => {});
      setFeedback({ type: 'ok', text: t('Veri deposu silindi.', 'Dataset deleted.') });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Silme işlemi başarısız.', 'Delete failed.') });
    }
  };

  const handleRoleFieldChange = (
    role: StandardRole,
    key: keyof RolePermissions,
    value: number | boolean,
  ) => {
    if (!roles) return;
    setRoles({
      ...roles,
      [role]: {
        ...roles[role],
        [key]: value,
      },
    });
  };

  const handleSaveRole = async (role: StandardRole) => {
    if (!roles) return;
    setFeedback(null);
    try {
      const res = await apiUpdateRoleConfig(role, roles[role]);
      setRoles(res.roles);
      void onRequestCloudSync?.({ pushRoles: true, restoreMissing: false });
      setFeedback({ type: 'ok', text: t(`${role} rolünün yetki ve hakları güncellendi.`, `Permissions for ${role} updated.`) });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Rol kaydedilemedi.', 'Failed to save role.') });
    }
  };

  const handleChangeUserRole = async (userId: string, nextRole: StandardRole) => {
    setFeedback(null);
    try {
      const res = await apiUpdateUser(userId, { role: nextRole });
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, ...res.user } : u)));
      void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({ type: 'ok', text: t(`${res.user.username} kullanıcısının rolü ${nextRole} yapıldı.`, `User ${res.user.username} role set to ${nextRole}.`) });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Kullanıcı güncellenemedi.', 'Failed to update user.') });
    }
  };

  const handleApproveEmail = async (userId: string) => {
    setFeedback(null);
    try {
      const res = await apiUpdateUser(userId, { approveEmail: true });
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, ...res.user } : u)),
      );
      void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({ type: 'ok', text: t(`${res.user.username} e-posta adresi onaylandı.`, `Email approved for ${res.user.username}.`) });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Onaylama başarısız.', 'Approval failed.') });
    }
  };

  const handleConfirmBan = async (userId: string, banned: boolean) => {
    setFeedback(null);
    try {
      const res = await apiUpdateUser(userId, {
        banned,
        banReason: banned ? banReason : '',
      });
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, ...res.user } : u)));
      setBanTargetId(null);
      setBanReason('');
      void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({
        type: 'ok',
        text: banned
          ? t(`${res.user.username} yasaklandı.`, `${res.user.username} has been banned.`)
          : t(`${res.user.username} kullanıcısının yasağı kaldırıldı.`, `Ban lifted for ${res.user.username}.`),
      });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('İşlem başarısız.', 'Action failed.') });
    }
  };

  const handleKickAllUsers = async (clearAccounts: boolean) => {
    setFeedback(null);
    try {
      const res = await apiAdminKickAllUsers(clearAccounts);
      setKickConfirmOpen(false);
      await Promise.all([loadOverview(), onStatsChanged()]);
      if (clearAccounts) {
        void clearAllMembersFromFirestore().catch(() => {});
      }
      setFeedback({
        type: 'ok',
        text: clearAccounts
          ? t(
              `Tüm üye hesapları (${res.kickedCount}) ve aktif oturumlar temizlendi. Yalnızca Admin aktif kaldı.`,
              `All member accounts (${res.kickedCount}) and active sessions were cleared. Only Admin remains.`,
            )
          : t(
              'Tüm kullanıcı oturumları sonlandırıldı. Yalnızca Admin oturumu aktif kaldı.',
              'All non-admin user sessions were terminated. Only Admin remains active.',
            ),
      });
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('İşlem başarısız.', 'Action failed.') });
    }
  };

  const handleConnectCloudAdmin = async () => {
    setFeedback(null);
    setCloudBusy(true);
    try {
      const res = await connectAdminGoogleAccount(apiAdminCloudAuthorize);
      setCloudConnected(res.authorized);
      await onRequestCloudSync?.({ restoreMissing: true });
      await Promise.all([loadOverview(), onStatsChanged()]);
      setFeedback({
        type: 'ok',
        text: t(
          'Gizli bulut eşitlemesi etkinleştirildi (kimlik e-postası gizli tutuldu).',
          'Hidden cloud sync enabled (owner email kept private).',
        ),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Bulut bağlantısı doğrulanamadı.', 'Cloud authorization failed.'),
      });
    } finally {
      setCloudBusy(false);
    }
  };

  const handleDownloadBackup = async () => {
    setFeedback(null);
    setVaultBusy(true);
    try {
      const snapshot = await apiAdminExportCloudSnapshot();
      const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentarika-vault-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setFeedback({
        type: 'ok',
        text: t(
          `Tam sistem yedeği indirildi (${snapshot.datasets.length} depo, ${snapshot.records.length} kayıt, ${snapshot.users.length} üye).`,
          `Full portable vault backup downloaded (${snapshot.datasets.length} datasets, ${snapshot.records.length} records, ${snapshot.users.length} members).`,
        ),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Yedek dosyası oluşturulamadı.', 'Failed to export backup.'),
      });
    } finally {
      setVaultBusy(false);
    }
  };

  const handleRestoreBackup = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setFeedback(null);
    setVaultBusy(true);
    try {
      const rawText = await file.text();
      const parsed = JSON.parse(rawText) as Partial<CloudBackupSnapshot> & { roles?: Partial<RoleConfigMap> };
      if (!parsed || typeof parsed !== 'object' || (!parsed.datasets && !parsed.records && !parsed.users && !parsed.roles)) {
        throw new Error(t('Geçersiz yedek JSON formatı.', 'Invalid vault backup JSON format.'));
      }
      const res = await apiAdminImportCloudSnapshot(parsed);
      await Promise.all([loadOverview(), onStatsChanged()]);
      void onRequestCloudSync?.({ restoreMissing: false });
      setFeedback({
        type: 'ok',
        text: t(
          `Yedekten geri yüklendi: +${res.restoredDatasets} depo, +${res.restoredRecords} kayıt, +${res.restoredUsers} üye.`,
          `Restored from vault: +${res.restoredDatasets} datasets, +${res.restoredRecords} records, +${res.restoredUsers} members.`,
        ),
      });
    } catch (err) {
      setFeedback({
        type: 'err',
        text: err instanceof Error ? err.message : t('Yedek geri yüklenemedi.', 'Failed to restore backup.'),
      });
    } finally {
      setVaultBusy(false);
    }
  };

  const handleFilterDatabase = async (e?: FormEvent, nextDatasetId?: string) => {
    e?.preventDefault();
    setDbLoading(true);
    try {
      const targetDs = nextDatasetId !== undefined ? nextDatasetId : dbDatasetFilter;
      const res = await apiAdminDatabaseRecords(dbSearch.trim(), targetDs);
      setDbRecords(res.records);
      setDbTotal(res.total);
    } catch (err) {
      setFeedback({ type: 'err', text: err instanceof Error ? err.message : t('Veritabanı kayıtları yüklenemedi.', 'Failed to load database records.') });
    } finally {
      setDbLoading(false);
    }
  };

  if (!adminVerified) {
    return (
      <div className="flex h-40 items-center justify-center rounded-xl border border-slate-200 bg-white text-xs text-slate-500 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
        {t('Yönetici yetkisi sunucu tarafından doğrulanıyor...', 'Verifying administrator authorization with server...')}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <section className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
        <div>
          <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
            {t('Admin Yönetim Merkezi', 'Admin Control Center')}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            {t(
              'Kategorili veri depolarını yükleyin, kullanıcıların giriş/doğrulama bilgilerini ve tüm veritabanı kayıtlarını inceleyin.',
              'Upload categorized datasets, monitor user IP/verification details, and browse all database records.',
            )}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80">
          <button
            type="button"
            onClick={() => setSubTab('datasets')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'datasets'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <Database className="h-3.5 w-3.5" />
            <span>{t('Depolar', 'Datasets')} ({datasets.length})</span>
          </button>
          <button
            type="button"
            onClick={() => setSubTab('users')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'users'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <Users className="h-3.5 w-3.5" />
            <span>{t('Kullanıcılar', 'Users')} ({users.length})</span>
          </button>
          <button
            type="button"
            onClick={() => setSubTab('database')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'database'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <Table2 className="h-3.5 w-3.5" />
            <span>{t('Veritabanı', 'Database')}</span>
          </button>
          <button
            type="button"
            onClick={() => setSubTab('roles')}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
              subTab === 'roles'
                ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
            }`}
          >
            <Sliders className="h-3.5 w-3.5" />
            <span>{t('Rol Hakları', 'Role Permissions')}</span>
          </button>
        </div>
      </section>

      {feedback && (
        <div
          role="status"
          className={`flex items-center gap-2 rounded-lg border p-3 text-xs ${
            feedback.type === 'ok'
              ? 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-300'
              : 'border-red-200 bg-red-50 text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300'
          }`}
        >
          {feedback.type === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0" /> : <AlertCircle className="h-4 w-4 shrink-0" />}
          <span>{feedback.text}</span>
        </div>
      )}

      {loading ? (
        <div className="h-40 animate-pulse rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]" />
      ) : (
        <>
          {subTab === 'datasets' && (
            <div className="space-y-4">
              <div
                data-testid="accountless-persistence-card"
                className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white px-5 py-4 dark:border-slate-800 dark:bg-[#111827]"
              >
                <div className="flex items-start gap-2.5 text-xs">
                  <Lock className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-semibold text-slate-900 dark:text-slate-100">
                        {t(
                          'Hesapsız Kalıcılık & Taşınabilir Yedek Kasası',
                          'Accountless Persistence & Portable Vault',
                        )}
                      </p>
                      <span className="rounded bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-600 dark:text-emerald-400">
                        {t('3 Ortak · E-postasız Erişim', '3 Partners · Zero Email')}
                      </span>
                    </div>
                    <p className="mt-1 max-w-2xl text-slate-500 dark:text-slate-400">
                      {cloudSyncStatus === 'syncing'
                        ? t(
                            'Arka plan eşitlemesi çalışıyor...',
                            'Background sync in progress...',
                          )
                        : isCloudRootAdminConnected() || cloudConnected
                          ? cloudSyncDetail ||
                            t(
                              'Admin erişimi yalnızca 30 haneli paylaşımlı anahtar ile hesapsız çalışır (e-postanız gizlidir). Sunucu diskinde NDJSON parçalama aktiftir; ayrıca hesap gerekmeden tam yedek alıp geri yükleyebilirsiniz.',
                              'Admin access works accountlessly via the 30-digit shared key (no email exposed). Disk NDJSON sharding is active, plus 1-click portable vault export/restore.',
                            )
                          : t(
                              'Admin erişimi hesapsızdır ve yönetici e-postası hiçbir yerde görünmez. Tüm ortaklar 30 haneli anahtarla girip sunucu diskinde saklanan verilere erişir veya hesap gerekmeden taşınabilir JSON yedek indirip geri yükleyebilir.',
                              'Admin access is accountless and hides owner email everywhere. All partners use the 30-digit key and can download/restore full JSON vault backups with zero account.',
                            )}
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <input
                    ref={restoreInputRef}
                    type="file"
                    accept=".json,application/json"
                    onChange={handleRestoreBackup}
                    className="hidden"
                  />
                  <button
                    type="button"
                    data-testid="download-vault-btn"
                    disabled={vaultBusy}
                    onClick={handleDownloadBackup}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 whitespace-nowrap"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>{t('Tam Yedek İndir (.json)', 'Download Full Vault (.json)')}</span>
                  </button>
                  <button
                    type="button"
                    data-testid="restore-vault-btn"
                    disabled={vaultBusy}
                    onClick={() => restoreInputRef.current?.click()}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-100 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 whitespace-nowrap"
                  >
                    <FileUp className="h-3.5 w-3.5" />
                    <span>{t('Yedekten Geri Yükle', 'Restore Vault')}</span>
                  </button>
                  {isCloudRootAdminConnected() || cloudConnected ? (
                    <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1.5 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400 whitespace-nowrap">
                      <Cloud className="h-3.5 w-3.5" />
                      <span>{t('Gizli Bulut Bağlı', 'Private Cloud Active')}</span>
                    </span>
                  ) : (
                    <button
                      type="button"
                      data-testid="firestore-connect-btn"
                      disabled={cloudBusy}
                      onClick={handleConnectCloudAdmin}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-blue-300/80 bg-blue-50/70 px-3 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-100 disabled:opacity-50 dark:border-blue-800/80 dark:bg-blue-950/30 dark:text-blue-300 whitespace-nowrap"
                    >
                      <Cloud className="h-3.5 w-3.5" />
                      <span>{t('Gizli Bulut Eşitle (Opsiyonel)', 'Sync Private Cloud (Optional)')}</span>
                    </button>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-end gap-2.5">
                <button
                  type="button"
                  onClick={handleLoadSynthetic}
                  className="rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700"
                >
                  {t('Sentetik Test Verisi Yükle', 'Load Synthetic Test Data')}
                </button>
                <button
                  type="button"
                  onClick={onOpenImport}
                  className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700"
                >
                  <Upload className="h-3.5 w-3.5" />
                  <span>{t('Yeni Veri Deposu Yükle', 'Upload New Dataset')}</span>
                </button>
              </div>

              {datasets.length === 0 ? (
                <div className="rounded-xl border border-slate-200 bg-white p-10 text-center text-sm text-slate-500 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
                  {t('Henüz sunucuda yüklü veri deposu yok.', 'No datasets uploaded to the server yet.')}
                </div>
              ) : (
                <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-4 py-3 font-semibold">{t('Depo Adı', 'Dataset Name')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Kapsam', 'Indexing')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Biçim', 'Format')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('Kayıt', 'Records')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Eklenme Tarihi', 'Added At')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('İşlem', 'Action')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {datasets.map((ds) => (
                          <tr key={ds.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-4 py-3 font-semibold text-slate-900 dark:text-slate-100">{ds.name}</td>
                            <td className="px-4 py-3 font-medium text-emerald-600 dark:text-emerald-400">
                              {t('Otomatik (Tüm Sorgular)', 'Automatic (All Queries)')}
                            </td>
                            <td className="px-4 py-3 font-mono uppercase text-slate-600 dark:text-slate-300">{ds.format}</td>
                            <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-800 dark:text-slate-200">
                              {ds.recordCount.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')}
                            </td>
                            <td className="px-4 py-3 text-slate-500 dark:text-slate-400">
                              {formatTurkishDate(ds.importedAt)}
                            </td>
                            <td className="px-4 py-3 text-right whitespace-nowrap">
                              <div className="inline-flex items-center gap-1.5">
                                <button
                                  type="button"
                                  onClick={() => setEditingDataset(ds)}
                                  aria-label={`${t('Düzenle', 'Edit')}: ${ds.name}`}
                                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-blue-600 hover:bg-blue-50 dark:border-slate-700 dark:text-blue-400 dark:hover:bg-blue-950/40"
                                >
                                  <Pencil className="h-3 w-3" />
                                  <span>{t('Düzenle', 'Edit')}</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteDataset(ds.id)}
                                  aria-label={`${t('Sil', 'Delete')}: ${ds.name}`}
                                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-red-600 hover:bg-red-50 dark:border-slate-700 dark:text-red-400 dark:hover:bg-red-950/40"
                                >
                                  <Trash2 className="h-3 w-3" />
                                  <span>{t('Sil', 'Delete')}</span>
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {subTab === 'users' && (
            <div className="space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white px-5 py-3.5 dark:border-slate-800 dark:bg-[#111827]">
                <div className="text-xs text-slate-600 dark:text-slate-400">
                  {t(
                    'Tüm üye oturumlarını sonlandırabilir veya üye hesaplarını temizleyip yalnızca Admin hesabını bırakabilirsiniz.',
                    'Terminate all active member sessions or clear member accounts so only Admin remains.',
                  )}
                </div>
                {kickConfirmOpen ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => handleKickAllUsers(false)}
                      className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs font-semibold text-amber-800 hover:bg-amber-100 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300"
                    >
                      {t('Sadece Oturumları At', 'Kick Active Sessions')}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleKickAllUsers(true)}
                      className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-700"
                    >
                      {t('Üyeleri Sil ve At', 'Delete & Kick All')}
                    </button>
                    <button
                      type="button"
                      onClick={() => setKickConfirmOpen(false)}
                      className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                    >
                      {t('İptal', 'Cancel')}
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    data-testid="kick-all-users-btn"
                    onClick={() => setKickConfirmOpen(true)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-1.5 text-xs font-semibold text-red-700 hover:bg-red-100 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300 dark:hover:bg-red-950/50"
                  >
                    <UserX className="h-3.5 w-3.5" />
                    <span>{t('Tüm Kullanıcıları At', 'Kick All Users')}</span>
                  </button>
                )}
              </div>

              <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
                {users.length === 0 ? (
                  <div className="p-10 text-center text-sm text-slate-500 dark:text-slate-400">
                    {t('Henüz kayıtlı üye bulunmuyor.', 'No registered members yet.')}
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-4 py-3 font-semibold">{t('Kullanıcı / Profil', 'User / Profile')}</th>
                          <th className="px-4 py-3 font-semibold">{t('E-posta & Doğrulama', 'Email & Verification')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Son Giriş Bilgisi', 'Last Login Info')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Rol', 'Role')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('Kota', 'Quota')}</th>
                          <th className="px-4 py-3 font-semibold">{t('Durum', 'Status')}</th>
                          <th className="px-4 py-3 text-right font-semibold">{t('Yönetim', 'Manage')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {users.map((u) => (
                          <tr key={u.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-4 py-3 align-top">
                              <div className="font-semibold text-slate-900 dark:text-slate-100">
                                {u.displayName || u.username}
                              </div>
                              <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                                @{u.username}
                              </div>
                            </td>
                            <td className="px-4 py-3 align-top">
                              <div className="font-mono text-slate-700 dark:text-slate-200">{u.email}</div>
                              {u.emailVerified ? (
                                <div className="mt-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
                                  {u.authProvider === 'google'
                                    ? t('Google Hesabı (Doğrulandı)', 'Google Account (Verified)')
                                    : t('E-posta Doğrulandı', 'Email Verified')}
                                </div>
                              ) : (
                                <div className="mt-1 flex flex-wrap items-center gap-2">
                                  <span className="font-mono text-[11px] text-amber-600 dark:text-amber-400">
                                    {t('Onay Bekliyor', 'Pending')}
                                  </span>
                                  <button
                                    type="button"
                                    onClick={() => handleApproveEmail(u.id)}
                                    className="inline-flex items-center gap-1 rounded border border-emerald-300 bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700 hover:bg-emerald-100 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
                                  >
                                    <MailCheck className="h-3 w-3" />
                                    <span>{t('Onayla', 'Approve')}</span>
                                  </button>
                                </div>
                              )}
                            </td>
                            <td className="px-4 py-3 align-top font-mono text-[11px] text-slate-600 dark:text-slate-400">
                              <div>IP: {u.lastLoginIp || '—'}</div>
                              <div>{u.lastLoginAt ? formatTurkishDate(u.lastLoginAt) : t('Henüz giriş yok', 'No login yet')}</div>
                            </td>
                            <td className="px-4 py-3 align-top">
                              <select
                                aria-label={`${u.username} ${t('rolü', 'role')}`}
                                value={u.role}
                                onChange={(e) => handleChangeUserRole(u.id, e.target.value as StandardRole)}
                                className="rounded-md border border-slate-300 bg-slate-50 px-2 py-1 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                              >
                                {STANDARD_ROLES.map((r) => (
                                  <option key={r} value={r}>
                                    {r}
                                  </option>
                                ))}
                              </select>
                            </td>
                            <td className="px-4 py-3 align-top text-right font-mono tabular-nums text-slate-700 dark:text-slate-300">
                              {u.dailyUsed} / {u.permissions.dailyQueryLimit}
                            </td>
                            <td className="px-4 py-3 align-top">
                              {u.banned ? (
                                <span className="font-medium text-red-600 dark:text-red-400">
                                  {t('Yasaklı', 'Banned')} ({u.banReason || 'Ban'})
                                </span>
                              ) : (
                                <span className="font-medium text-emerald-700 dark:text-emerald-400">{t('Aktif', 'Active')}</span>
                              )}
                            </td>
                            <td className="px-4 py-3 align-top text-right whitespace-nowrap">
                              {u.banned ? (
                                <button
                                  type="button"
                                  onClick={() => handleConfirmBan(u.id, false)}
                                  className="rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-emerald-700 hover:bg-emerald-50 dark:border-slate-700 dark:text-emerald-400 dark:hover:bg-emerald-950/30"
                                >
                                  {t('Yasağı Kaldır', 'Unban')}
                                </button>
                              ) : banTargetId === u.id ? (
                                <div className="inline-flex items-center gap-1.5">
                                  <input
                                    type="text"
                                    value={banReason}
                                    onChange={(e) => setBanReason(e.target.value)}
                                    placeholder={t('Ban sebebi', 'Ban reason')}
                                    className="w-32 rounded border border-slate-300 bg-slate-50 px-2 py-1 text-[11px] dark:border-slate-700 dark:bg-slate-900"
                                  />
                                  <button
                                    type="button"
                                    onClick={() => handleConfirmBan(u.id, true)}
                                    className="rounded bg-red-600 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-red-700"
                                  >
                                    {t('Onayla', 'Confirm')}
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setBanTargetId(null);
                                      setBanReason('');
                                    }}
                                    className="rounded border border-slate-300 px-2 py-1 text-[11px] dark:border-slate-700"
                                  >
                                    {t('İptal', 'Cancel')}
                                  </button>
                                </div>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => setBanTargetId(u.id)}
                                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-red-600 hover:bg-red-50 dark:border-slate-700 dark:text-red-400 dark:hover:bg-red-950/40"
                                >
                                  <Ban className="h-3 w-3" />
                                  <span>{t('Yasakla', 'Ban')}</span>
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <section className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
                <div className="border-b border-slate-200 px-5 py-4 dark:border-slate-800">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-amber-500" />
                    <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {t('Engellenen Temp-Mail / Kayıt Denemeleri', 'Blocked Temp-Mail / Registration Attempts')} ({blockedAttempts.length})
                    </h3>
                  </div>
                  <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                    {t(
                      'Tek kullanımlık (disposable) e-posta veya geçersiz MX kaydı nedeniyle reddedilen tüm kayıt girişimleri IP adresleriyle birlikte kaydedilir.',
                      'All registration attempts rejected due to disposable email domains or invalid MX records, logged with IP addresses.',
                    )}
                  </p>
                </div>

                {blockedAttempts.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                    {t('Henüz engellenmiş temp-mail veya geçersiz kayıt denemesi yok.', 'No blocked temp-mail or invalid registration attempts yet.')}
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-4 py-2.5 font-semibold">{t('Denenen E-posta', 'Attempted Email')}</th>
                          <th className="px-4 py-2.5 font-semibold">{t('Kullanıcı Adı', 'Username')}</th>
                          <th className="px-4 py-2.5 font-semibold">{t('Alan Adı', 'Domain')}</th>
                          <th className="px-4 py-2.5 font-semibold">{t('Tespit Katmanı & Sebep', 'Detector & Reason')}</th>
                          <th className="px-4 py-2.5 font-semibold">IP</th>
                          <th className="px-4 py-2.5 font-semibold">{t('Zaman', 'Time')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {blockedAttempts.map((b) => (
                          <tr key={b.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-4 py-2.5 font-mono text-red-600 dark:text-red-400">{b.email}</td>
                            <td className="px-4 py-2.5 font-mono text-slate-800 dark:text-slate-200">@{b.username}</td>
                            <td className="px-4 py-2.5 font-mono text-slate-700 dark:text-slate-300">{b.domain}</td>
                            <td className="px-4 py-2.5 text-slate-700 dark:text-slate-300">
                              <span className="mr-1.5 font-mono text-[11px] font-semibold uppercase text-amber-600 dark:text-amber-400">
                                [{b.detector}]
                              </span>
                              <span>{b.reason}</span>
                            </td>
                            <td className="px-4 py-2.5 font-mono text-[11px] text-slate-600 dark:text-slate-400">{b.ip}</td>
                            <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400">
                              {formatTurkishDate(b.timestamp)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </div>
          )}

          {subTab === 'database' && (
            <div className="space-y-6">
              <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {t('Veritabanı Kayıt Gezgini', 'Database Record Explorer')} ({dbTotal.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')} {t('kayıt', 'records')})
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {t(
                        'Tüm veri depolarındaki ham kayıtları ID, e-posta, kullanıcı adı veya not alanına göre filtreleyin.',
                        'Filter raw records across all datasets by ID, email, username, or notes.',
                      )}
                    </p>
                  </div>
                  <form onSubmit={(e) => handleFilterDatabase(e)} className="flex flex-wrap items-center gap-2">
                    <select
                      aria-label={t('Depo filtresi', 'Dataset filter')}
                      value={dbDatasetFilter}
                      onChange={(e) => {
                        setDbDatasetFilter(e.target.value);
                        void handleFilterDatabase(undefined, e.target.value);
                      }}
                      className="rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                    >
                      <option value="">{t('Tüm Depolar', 'All Datasets')}</option>
                      {datasets.map((ds) => (
                        <option key={ds.id} value={ds.id}>
                          {ds.name}
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      value={dbSearch}
                      onChange={(e) => setDbSearch(e.target.value)}
                      placeholder={t('Kayıt içinde ara...', 'Search records...')}
                      className="rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                    />
                    <button
                      type="submit"
                      disabled={dbLoading}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                    >
                      <Search className="h-3.5 w-3.5" />
                      <span>{t('Filtrele', 'Filter')}</span>
                    </button>
                  </form>
                </div>

                <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  {dbRecords.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                      {t('Eşleşen veritabanı kaydı bulunamadı.', 'No matching database records found.')}
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-3 py-2.5 font-semibold">Discord ID</th>
                          <th className="px-3 py-2.5 font-semibold">{t('E-posta', 'Email')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Kullanıcı Adı', 'Username')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Kaynak / Depo', 'Source / Dataset')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('IP / Ek', 'IP / Extra')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {dbRecords.slice(0, 100).map((r) => (
                          <tr key={r.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-3 py-2 font-mono text-blue-600 dark:text-blue-400">{r.discordId || '—'}</td>
                            <td className="px-3 py-2 font-mono text-slate-800 dark:text-slate-200">{r.email || '—'}</td>
                            <td className="px-3 py-2 text-slate-700 dark:text-slate-300">{r.username || '—'}</td>
                            <td className="px-3 py-2 text-slate-600 dark:text-slate-400">
                              {r.source} <span className="text-[11px] opacity-75">({r.datasetName})</span>
                            </td>
                            <td className="px-3 py-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                              {r.ip || r.notes || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </section>

              <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
                <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {t('Son Sorgu Denetim Kayıtları', 'Recent Query Audit Logs')} ({queryLogs.length})
                </h3>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  {t(
                    'Kullanıcıların panelde gerçekleştirdiği son ID Lookup, E-posta OSINT ve Toplu Sorgu işlemleri.',
                    'Recent ID Lookup, Email OSINT, and Bulk Lookup operations executed by panel users.',
                  )}
                </p>

                <div className="mt-4 overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                  {queryLogs.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-500 dark:text-slate-400">
                      {t('Henüz sorgu denetim kaydı oluşmadı.', 'No query audit logs yet.')}
                    </div>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                        <tr>
                          <th className="px-3 py-2.5 font-semibold">{t('Kullanıcı', 'User')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Modül', 'Module')}</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Hedef', 'Target')}</th>
                          <th className="px-3 py-2.5 text-right font-semibold">{t('Sonuç', 'Matches')}</th>
                          <th className="px-3 py-2.5 font-semibold">IP</th>
                          <th className="px-3 py-2.5 font-semibold">{t('Zaman', 'Time')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                        {queryLogs.slice(0, 60).map((log) => (
                          <tr key={log.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                            <td className="px-3 py-2 font-semibold text-slate-900 dark:text-slate-100">{log.username}</td>
                            <td className="px-3 py-2 text-slate-700 dark:text-slate-300">
                              {queryTypeLabel(log.queryType)}
                            </td>
                            <td className="px-3 py-2 font-mono text-slate-800 dark:text-slate-200">{log.target}</td>
                            <td className="px-3 py-2 text-right font-mono tabular-nums text-slate-700 dark:text-slate-300">
                              {log.matchCount}
                            </td>
                            <td className="px-3 py-2 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                              {log.ip}
                            </td>
                            <td className="px-3 py-2 text-slate-500 dark:text-slate-400">
                              {formatTurkishDate(log.timestamp)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </section>
            </div>
          )}

          {subTab === 'roles' && roles && (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {STANDARD_ROLES.map((roleName) => {
                const cfg = roles[roleName];
                return (
                  <div
                    key={roleName}
                    className="flex flex-col justify-between rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]"
                  >
                    <div className="space-y-4">
                      <div className="border-b border-slate-200 pb-3 dark:border-slate-800">
                        <h3 className="font-display text-base font-bold text-slate-900 dark:text-slate-100">
                          {roleName} {t('Rolü', 'Role')}
                        </h3>
                        <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                          {roleName === 'Üye'
                            ? t('Yeni kayıt olan standart kullanıcılar', 'Standard newly registered users')
                            : roleName === 'Destekçi'
                              ? t('Gelişmiş özelliklere erişen destekçiler', 'Supporters with extended features')
                              : t('Yüksek kotalı kurumsal/işletme hesapları', 'High-quota business accounts')}
                        </p>
                      </div>

                      <div>
                        <label
                          htmlFor={`quota-${roleName}`}
                          className="block text-xs font-medium text-slate-700 dark:text-slate-300"
                        >
                          {t('Günlük Sorgu Hakkı', 'Daily Query Quota')}
                        </label>
                        <input
                          id={`quota-${roleName}`}
                          type="number"
                          min={0}
                          max={1000000}
                          value={cfg.dailyQueryLimit}
                          onChange={(e) =>
                            handleRoleFieldChange(roleName, 'dailyQueryLimit', Math.max(0, Number(e.target.value) || 0))
                          }
                          className="mt-1.5 w-full rounded-lg border border-slate-300 bg-slate-50 px-3 py-2 font-mono text-sm text-slate-900 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                        />
                      </div>

                      <div className="space-y-2.5 text-xs">
                        {(
                          [
                            ['canIdLookup', t('Discord ID Sorgulama', 'Discord ID Lookup')],
                            ['canEmailOsint', t('E-posta OSINT Modülü', 'Email OSINT Module')],
                            ['canBulkLookup', t('Toplu ID Tarama', 'Bulk ID Lookup')],
                          ] as [keyof RolePermissions, string][]
                        ).map(([permKey, label]) => (
                          <label key={permKey} className="flex cursor-pointer items-center justify-between gap-2">
                            <span className="text-slate-700 dark:text-slate-300">{label}</span>
                            <input
                              type="checkbox"
                              checked={Boolean(cfg[permKey])}
                              onChange={(e) => handleRoleFieldChange(roleName, permKey, e.target.checked)}
                              className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 dark:border-slate-600 dark:bg-slate-800"
                            />
                          </label>
                        ))}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleSaveRole(roleName)}
                      className="mt-5 w-full rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-blue-700"
                    >
                      {roleName} {t('Haklarını Kaydet', 'Save Permissions')} ({lang.toUpperCase()})
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      <DatasetEditorModal
        dataset={editingDataset}
        onClose={() => setEditingDataset(null)}
        onDatasetChanged={async (datasetId) => {
          await Promise.all([loadOverview(), onStatsChanged()]);
          void onRequestCloudSync?.({ restoreMissing: false, forceDatasetIds: [datasetId] });
        }}
      />
    </div>
  );
}
