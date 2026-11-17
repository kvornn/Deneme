import { Menu, Moon, Sun, Languages } from 'lucide-react';
import type { ActiveTab } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';

interface TopBarProps {
  activeTab: ActiveTab;
  isDark: boolean;
  onToggleTheme: () => void;
  onOpenMobileMenu: () => void;
}

export function TopBar({
  activeTab,
  isDark,
  onToggleTheme,
  onOpenMobileMenu,
}: TopBarProps) {
  const { lang, toggleLang, t } = useI18n();

  const tabTitles: Record<ActiveTab, string> = {
    lookup: t('ID Sorgu', 'ID Lookup'),
    email_osint: t('E-posta OSINT', 'Email OSINT'),
    bulk: t('Toplu Sorgu', 'Bulk Lookup'),
    profile: t('Profilim', 'My Profile'),
    admin: t('Admin Paneli', 'Admin Panel'),
    history: t('Sorgu Geçmişi', 'Query History'),
    legal: t('Yasal Beyan', 'Legal Disclaimer'),
  };

  return (
    <header className="flex h-16 shrink-0 items-center justify-between gap-4 border-b border-slate-200 bg-white px-4 dark:border-slate-800 dark:bg-[#0F1521] sm:px-6">
      <div className="flex items-center gap-3 min-w-0">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label={t('Menüyü aç', 'Open menu')}
          className="rounded-md p-2 text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white lg:hidden"
        >
          <Menu className="h-5 w-5" />
        </button>
        <div className="flex items-center gap-2 text-sm truncate">
          <span className="hidden text-slate-500 dark:text-slate-400 sm:inline">{t('Panel', 'Panel')}</span>
          <span className="hidden text-slate-400 dark:text-slate-600 sm:inline" aria-hidden="true">/</span>
          <h1 className="font-display text-base font-semibold text-slate-900 dark:text-slate-100 truncate">
            {tabTitles[activeTab]}
          </h1>
        </div>
      </div>

      <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
        <button
          type="button"
          onClick={toggleLang}
          data-testid="topbar-lang-toggle"
          aria-label={t('İngilizceye geç', 'Switch to Turkish')}
          className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2.5 text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-200 dark:hover:bg-slate-800 whitespace-nowrap shrink-0"
        >
          <Languages className="h-3.5 w-3.5" />
          <span>{lang.toUpperCase()}</span>
        </button>

        <button
          type="button"
          onClick={onToggleTheme}
          aria-label={isDark ? t('Açık temaya geç', 'Switch to light theme') : t('Koyu temaya geç', 'Switch to dark theme')}
          className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-slate-50 text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-200 dark:hover:bg-slate-800 shrink-0"
        >
          {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>
    </header>
  );
}
