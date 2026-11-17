import { lazy, Suspense, useEffect, useState, useCallback, useRef } from 'react';
import { onAuthStateChanged } from 'firebase/auth';
import type {
  ActiveTab,
  DatasetMeta,
  IntelRecord,
  PublicUser,
  QueryHistoryItem,
  SearchResult,
} from './types/intel';
import { I18nProvider, useI18n } from './i18n/I18nContext';
import { AuthGate } from './components/AuthGate';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { LookupView } from './components/LookupView';
import { EmailOsintView } from './components/EmailOsintView';
import { BulkLookupView } from './components/BulkLookupView';
import { ProfileView } from './components/ProfileView';
import { LegalDisclaimerView } from './components/LegalDisclaimerView';
import { HistoryView } from './components/HistoryView';
import {
  ApiError,
  apiAdminCloudAuthorize,
  apiAdminExportCloudSnapshot,
  apiAdminImportCloudSnapshot,
  apiAppendDatasetBatch,
  apiGetHealth,
  apiGetMe,
  apiSearch,
  apiUploadDataset,
  apiVerifyAdmin,
  freezePublicUser,
  getStoredToken,
  isTokenConsistentWithUser,
  setStoredToken,
} from './utils/api';
import {
  auth as firebaseAuth,
  autoSyncCloudWithServer,
  isCloudRootAdminConnected,
  verifyExistingCloudSession,
} from './utils/firestoreSync';

const AdminView = lazy(() =>
  import('./components/AdminView').then((m) => ({ default: m.AdminView })),
);
const ImportModal = lazy(() =>
  import('./components/ImportModal').then((m) => ({ default: m.ImportModal })),
);

function createChallengeNonce(): string {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function AppShell() {
  const { t } = useI18n();
  const [activeTab, setActiveTab] = useState<ActiveTab>('lookup');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [datasetRevision, setDatasetRevision] = useState(0);

  const [isDark, setIsDark] = useState(true);

  const [currentUser, setCurrentUser] = useState<PublicUser | null>(null);
  const [serverAdminVerified, setServerAdminVerified] = useState(false);
  const [stats, setStats] = useState({ totalDatasets: 0, totalRecords: 0, totalUsers: 0 });
  const [authChecked, setAuthChecked] = useState(false);
  const [cloudSyncStatus, setCloudSyncStatus] = useState<'idle' | 'syncing' | 'synced' | 'needs_google' | 'error'>('idle');
  const [cloudSyncDetail, setCloudSyncDetail] = useState<string | null>(null);
  const syncInFlightRef = useRef(false);
  const bootSyncedRef = useRef(false);

  const [history, setHistory] = useState<QueryHistoryItem[]>([]);

  const [query, setQuery] = useState('');
  const [searchResult, setSearchResult] = useState<SearchResult | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [pivotedEmail, setPivotedEmail] = useState<string | null>(null);

  useEffect(() => {
    const root = document.documentElement;
    if (isDark) root.classList.add('dark');
    else root.classList.remove('dark');
  }, [isDark]);

  const handleLogout = useCallback(() => {
    setStoredToken(null);
    setCurrentUser(null);
    setServerAdminVerified(false);
    setSearchResult(null);
    setHistory([]);
    setStats({ totalDatasets: 0, totalRecords: 0, totalUsers: 0 });
    setActiveTab('lookup');
    setImportOpen(false);
  }, []);

  const verifyServerAdmin = useCallback(async (): Promise<boolean> => {
    const nonce = createChallengeNonce();
    const res = await apiVerifyAdmin(nonce);
    return res.verified === true && res.role === 'Admin' && res.nonce === nonce;
  }, []);

  const refreshStats = useCallback(async () => {
    try {
      const token = getStoredToken();
      if (token) {
        const me = await apiGetMe();
        if (!isTokenConsistentWithUser(token, me.user)) {
          handleLogout();
          return;
        }
        if (me.user.role === 'Admin') {
          const verified = await verifyServerAdmin();
          if (!verified) {
            handleLogout();
            return;
          }
          setServerAdminVerified(true);
        } else {
          setServerAdminVerified(false);
        }
        setCurrentUser(freezePublicUser(me.user));
        setStats(me.stats);
      } else {
        setServerAdminVerified(false);
        await apiGetHealth();
      }
    } catch {
      handleLogout();
    } finally {
      setAuthChecked(true);
    }
  }, [handleLogout, verifyServerAdmin]);

  useEffect(() => {
    refreshStats();
  }, [refreshStats]);

  const handleAuthenticated = async (token: string, user: PublicUser) => {
    if (!isTokenConsistentWithUser(token, user)) {
      handleLogout();
      return;
    }
    setStoredToken(token);
    setActiveTab('lookup');
    setSearchResult(null);
    setSearchError(null);
    if (user.role === 'Admin') {
      try {
        const [verified, me] = await Promise.all([verifyServerAdmin(), apiGetMe()]);
        if (!verified || !isTokenConsistentWithUser(token, me.user)) {
          handleLogout();
          return;
        }
        setServerAdminVerified(true);
        setCurrentUser(freezePublicUser(me.user));
        setStats(me.stats);
      } catch {
        handleLogout();
      }
    } else {
      setServerAdminVerified(false);
      setCurrentUser(freezePublicUser(user));
    }
  };

  const isVerifiedAdmin = Boolean(
    serverAdminVerified &&
      currentUser &&
      currentUser.role === 'Admin' &&
      currentUser.id === 'admin_root' &&
      isTokenConsistentWithUser(getStoredToken(), currentUser),
  );

  // Immediately terminate tampered client sessions if role/tab is forced without an authentic admin_root token
  useEffect(() => {
    if (!currentUser) return;
    const token = getStoredToken();
    const consistent = isTokenConsistentWithUser(token, currentUser);
    if (!consistent || (currentUser.role === 'Admin' && !serverAdminVerified) || (activeTab === 'admin' && !isVerifiedAdmin) || (importOpen && !isVerifiedAdmin)) {
      handleLogout();
    }
  }, [currentUser, activeTab, importOpen, serverAdminVerified, isVerifiedAdmin, handleLogout]);

  const runCloudSync = useCallback(
    async (opts: { restoreMissing?: boolean; pushRoles?: boolean; forceDatasetIds?: string[] } = {}) => {
      if (!isVerifiedAdmin) return;
      if (!isCloudRootAdminConnected()) {
        setCloudSyncStatus('needs_google');
        return;
      }
      if (syncInFlightRef.current) return;
      syncInFlightRef.current = true;
      setCloudSyncStatus('syncing');
      try {
        const res = await autoSyncCloudWithServer(
          apiAdminExportCloudSnapshot,
          apiAdminImportCloudSnapshot,
          opts,
        );
        if (res.restoredDatasets > 0 || res.restoredUsers > 0) {
          await refreshStats();
          setDatasetRevision((r) => r + 1);
          setCloudSyncDetail(
            t(
              `Buluttan otomatik geri yüklendi (+${res.restoredDatasets} depo, +${res.restoredUsers} üye).`,
              `Auto-restored from cloud (+${res.restoredDatasets} datasets, +${res.restoredUsers} users).`,
            ),
          );
        } else if (res.uploadedDatasets > 0) {
          setCloudSyncDetail(
            t(
              `Yeni veriler buluta otomatik yedeklendi (+${res.uploadedDatasets} depo).`,
              `New datasets auto-backed up to cloud (+${res.uploadedDatasets}).`,
            ),
          );
        } else {
          setCloudSyncDetail(
            t(
              'Tüm depolar, üyeler ve rol yetkileri arka planda otomatik korunur; sunucu yeniden başlasa dahi silinmez.',
              'All datasets, members, and role permissions are backed up & restored automatically across server restarts.',
            ),
          );
        }
        setCloudSyncStatus('synced');
      } catch {
        setCloudSyncStatus('error');
      } finally {
        syncInFlightRef.current = false;
      }
    },
    [isVerifiedAdmin, refreshStats, t],
  );

  useEffect(() => {
    if (!isVerifiedAdmin) {
      bootSyncedRef.current = false;
      setCloudSyncStatus('idle');
      setCloudSyncDetail(null);
      return;
    }
    const unsub = onAuthStateChanged(firebaseAuth, () => {
      void (async () => {
        const connected = await verifyExistingCloudSession(apiAdminCloudAuthorize);
        if (connected) {
          if (!bootSyncedRef.current) {
            bootSyncedRef.current = true;
            void runCloudSync({ restoreMissing: true });
          }
        } else {
          setCloudSyncStatus('needs_google');
        }
      })();
    });
    return () => unsub();
  }, [isVerifiedAdmin, runCloudSync]);

  const handleRunSearch = async (overrideQuery?: string) => {
    const activeQ = (overrideQuery !== undefined ? overrideQuery : query).trim();
    if (overrideQuery !== undefined) {
      setQuery(overrideQuery);
      setActiveTab('lookup');
    }
    if (!activeQ) {
      setSearchResult(null);
      setSearchError(null);
      return;
    }

    setSearching(true);
    setSearchError(null);
    try {
      const res = await apiSearch(activeQ);
      setSearchResult(res.result);
      setCurrentUser(freezePublicUser(res.user));

      const histItem: QueryHistoryItem = {
        id: `hist_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        query: activeQ,
        detectedType: res.result.detectedType,
        matchCount: res.result.primaryMatches.length + res.result.relatedMatches.length,
        timestamp: new Date().toISOString(),
      };
      setHistory((prev) => [histItem, ...prev.slice(0, 99)]);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        handleLogout();
        return;
      }
      setSearchError(err instanceof Error ? err.message : t('Sorgulama başarısız oldu.', 'Query failed.'));
    } finally {
      setSearching(false);
    }
  };

  const handlePivotEmail = (email: string) => {
    setPivotedEmail(email);
    setActiveTab('email_osint');
  };

  const handleImportComplete = async (
    meta: DatasetMeta,
    newRecords: IntelRecord[],
    onProgress?: (uploaded: number, total: number) => void,
  ) => {
    const BATCH_SIZE = 4000;
    const total = newRecords.length;
    const firstBatch = newRecords.slice(0, BATCH_SIZE);
    let lastRes = await apiUploadDataset({ ...meta, recordCount: firstBatch.length }, firstBatch);
    onProgress?.(firstBatch.length, total);

    for (let offset = BATCH_SIZE; offset < total; offset += BATCH_SIZE) {
      const slice = newRecords.slice(offset, offset + BATCH_SIZE);
      lastRes = await apiAppendDatasetBatch(meta.id, slice);
      onProgress?.(Math.min(total, offset + slice.length), total);
    }

    setStats(lastRes.stats);
    setDatasetRevision((r) => r + 1);
    void runCloudSync({ restoreMissing: false });
  };

  if (!authChecked) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 dark:bg-[#0B0F17]">
        <div className="text-sm text-slate-500 dark:text-slate-400">
          {t('Oturum doğrulanıyor...', 'Verifying session...')}
        </div>
      </div>
    );
  }

  if (!currentUser) {
    return (
      <AuthGate
        onAuthenticated={handleAuthenticated}
        isDark={isDark}
        onToggleTheme={() => setIsDark((d) => !d)}
      />
    );
  }

  const isAdmin = isVerifiedAdmin;

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900 dark:bg-[#0B0F17] dark:text-slate-100">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        currentUser={currentUser}
        isVerifiedAdmin={isAdmin}
        totalRecords={stats.totalRecords}
        totalDatasets={stats.totalDatasets}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        onLogout={handleLogout}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          activeTab={activeTab}
          isDark={isDark}
          onToggleTheme={() => setIsDark((d) => !d)}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
        />

        <main className="mx-auto w-full max-w-6xl flex-1 p-4 sm:p-6 lg:p-8">
          {activeTab === 'lookup' && (
            <LookupView
              currentUser={currentUser}
              query={query}
              onQueryChange={setQuery}
              result={searchResult}
              searching={searching}
              searchError={searchError}
              onRunSearch={handleRunSearch}
              onPivotEmail={handlePivotEmail}
            />
          )}

          {activeTab === 'email_osint' && (
            <EmailOsintView
              currentUser={currentUser}
              initialEmail={pivotedEmail}
              onConsumeInitialEmail={() => setPivotedEmail(null)}
              onUserUpdate={(u) => setCurrentUser(freezePublicUser(u))}
              onPivotQuery={(q) => handleRunSearch(q)}
              onUnauthorized={handleLogout}
            />
          )}

          {activeTab === 'bulk' && (
            <BulkLookupView
              currentUser={currentUser}
              onInspectId={(id) => handleRunSearch(id)}
              onUserUpdate={(u) => setCurrentUser(freezePublicUser(u))}
              onUnauthorized={handleLogout}
            />
          )}

          {activeTab === 'profile' && <ProfileView currentUser={currentUser} isVerifiedAdmin={isAdmin} />}

          {activeTab === 'admin' && isAdmin && (
            <Suspense
              fallback={
                <div className="h-40 animate-pulse rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]" />
              }
            >
              <AdminView
                onOpenImport={() => {
                  if (isAdmin && activeTab === 'admin') setImportOpen(true);
                }}
                onStatsChanged={refreshStats}
                onUnauthorizedAdmin={handleLogout}
                refreshSignal={datasetRevision}
                cloudSyncStatus={cloudSyncStatus}
                cloudSyncDetail={cloudSyncDetail}
                onRequestCloudSync={runCloudSync}
              />
            </Suspense>
          )}

          {activeTab === 'history' && (
            <HistoryView
              history={history}
              onRerunQuery={(q) => handleRunSearch(q)}
            />
          )}

          {activeTab === 'legal' && <LegalDisclaimerView />}
        </main>
      </div>

      {isAdmin && activeTab === 'admin' && importOpen && (
        <Suspense fallback={null}>
          <ImportModal
            open={importOpen}
            onClose={() => setImportOpen(false)}
            onImportComplete={handleImportComplete}
          />
        </Suspense>
      )}
    </div>
  );
}

export default function App() {
  return (
    <I18nProvider>
      <AppShell />
    </I18nProvider>
  );
}
