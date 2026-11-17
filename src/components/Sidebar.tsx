import { Search, MailSearch, Layers, ShieldCheck, Scale, History, User, LogOut, X } from 'lucide-react';
import type { ActiveTab, PublicUser } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';

interface SidebarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  currentUser: PublicUser;
  isVerifiedAdmin?: boolean;
  totalRecords: number;
  totalDatasets: number;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onLogout: () => void;
}

export function Sidebar({
  activeTab,
  onSelectTab,
  currentUser,
  isVerifiedAdmin = false,
  totalRecords,
  totalDatasets,
  mobileOpen,
  onCloseMobile,
  onLogout,
}: SidebarProps) {
  const { lang, t } = useI18n();
  const isAdmin = isVerifiedAdmin && currentUser.id === 'admin_root' && currentUser.role === 'Admin';
  const navItems: { id: ActiveTab; label: string; icon: typeof Search; visible: boolean }[] = [
    { id: 'lookup', label: t('ID Sorgu', 'ID Lookup'), icon: Search, visible: true },
    { id: 'email_osint', label: t('E-posta OSINT', 'Email OSINT'), icon: MailSearch, visible: true },
    { id: 'bulk', label: t('Toplu Sorgu', 'Bulk Lookup'), icon: Layers, visible: currentUser.permissions.canBulkLookup || isAdmin },
    { id: 'profile', label: t('Profilim', 'My Profile'), icon: User, visible: true },
    { id: 'admin', label: t('Admin Paneli', 'Admin Panel'), icon: ShieldCheck, visible: isAdmin },
    { id: 'history', label: t('Sorgu Geçmişi', 'Query History'), icon: History, visible: true },
    { id: 'legal', label: t('Yasal Beyan', 'Legal Disclaimer'), icon: Scale, visible: true },
  ];

  const handlePick = (tab: ActiveTab) => {
    onSelectTab(tab);
    onCloseMobile();
  };

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-slate-950/60 backdrop-blur-xs lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        aria-label={t('Ana menü', 'Main navigation')}
        className={`fixed inset-y-0 left-0 z-40 flex w-64 shrink-0 flex-col border-r border-slate-200 bg-white transition-transform duration-200 dark:border-slate-800 dark:bg-[#0F1521] lg:sticky lg:top-0 lg:h-screen lg:overflow-y-auto lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-slate-200 px-5 dark:border-slate-800">
          <span className="font-display text-base font-bold tracking-tight text-slate-900 dark:text-slate-100 whitespace-nowrap shrink-0">
            Sentarika Archive
          </span>
          <button
            type="button"
            onClick={onCloseMobile}
            aria-label={t('Menüyü kapat', 'Close menu')}
            className="rounded-md p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100 lg:hidden"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          {navItems
            .filter((item) => item.visible)
            .map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handlePick(item.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`flex w-full items-center gap-3 rounded-lg px-3.5 py-2.5 text-sm font-medium transition-colors whitespace-nowrap ${
                    isActive
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800/70 dark:hover:text-white'
                  }`}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
        </nav>

        <div className="border-t border-slate-200 p-4 dark:border-slate-800 space-y-3">
          <div className="space-y-1 text-xs">
            <div className="flex items-center justify-between gap-2">
              <button
                type="button"
                onClick={() => handlePick('profile')}
                className="font-semibold text-slate-900 hover:text-blue-600 dark:text-slate-100 dark:hover:text-blue-400 truncate"
              >
                {currentUser.username}
              </button>
              <span className="font-medium text-blue-600 dark:text-blue-400 shrink-0">{currentUser.role}</span>
            </div>
            <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
              <span>{t('Günlük Kota', 'Daily Quota')}</span>
              <span className="font-mono tabular-nums text-slate-800 dark:text-slate-200" data-testid="sidebar-quota">
                {isAdmin
                  ? t('Sınırsız', 'Unlimited')
                  : `${currentUser.dailyUsed} / ${currentUser.permissions.dailyQueryLimit}`}
              </span>
            </div>
            {isAdmin && (
              <div className="flex items-center justify-between text-slate-500 dark:text-slate-400">
                <span>{t('Depo · Kayıt', 'Datasets · Records')}</span>
                <span className="font-mono tabular-nums text-slate-800 dark:text-slate-200" data-testid="sidebar-record-count">
                  {totalDatasets} · {totalRecords.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')}
                </span>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={onLogout}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
          >
            <LogOut className="h-3.5 w-3.5" />
            <span>{t('Çıkış Yap', 'Sign Out')}</span>
          </button>
        </div>
      </aside>
    </>
  );
}
