import { UserCheck, Shield, Clock } from 'lucide-react';
import type { PublicUser } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { formatTurkishDate } from '../utils/snowflake';

interface ProfileViewProps {
  currentUser: PublicUser;
  isVerifiedAdmin?: boolean;
}

export function ProfileView({ currentUser, isVerifiedAdmin = false }: ProfileViewProps) {
  const { t } = useI18n();
  const isAdmin = isVerifiedAdmin && currentUser.id === 'admin_root' && currentUser.role === 'Admin';
  const displayedRole = isAdmin ? 'Admin' : currentUser.role === 'Admin' ? 'Üye' : currentUser.role;
  const limit = currentUser.permissions.dailyQueryLimit;
  const usagePct = isAdmin ? 0 : limit > 0 ? Math.min(100, Math.round((currentUser.dailyUsed / limit) * 100)) : 100;

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 pb-5 dark:border-slate-800">
          <div className="flex items-center gap-3.5">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 font-display text-lg font-bold text-blue-600 dark:border-slate-700 dark:bg-slate-900 dark:text-blue-400">
              {currentUser.username.slice(0, 2).toUpperCase()}
            </div>
            <div>
              <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
                {currentUser.username}
              </h2>
              <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                <span className="font-semibold text-blue-600 dark:text-blue-400">{displayedRole}</span>
                <span aria-hidden="true">·</span>
                <span className={currentUser.emailVerified ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}>
                  {isAdmin
                    ? t('30 Haneli Anahtar (Hesapsız)', '30-Digit Key (Accountless)')
                    : currentUser.emailVerified
                      ? currentUser.authProvider === 'google'
                        ? t('Google Hesabı Doğrulandı', 'Google Account Verified')
                        : t('Hesap Doğrulandı', 'Account Verified')
                      : t('Doğrulama Bekliyor', 'Pending Verification')}
                </span>
              </div>
            </div>
          </div>

          <div className="text-left text-xs text-slate-500 dark:text-slate-400 sm:text-right">
            <div>
              {t('Kayıt:', 'Joined:')}{' '}
              <span className="font-mono">{formatTurkishDate(currentUser.createdAt)}</span>
            </div>
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900/50">
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <UserCheck className="h-3.5 w-3.5 text-blue-500" />
              <span>{isAdmin ? t('Erişim Gizliliği', 'Access Privacy') : t('Kayıtlı E-posta', 'Registered Email')}</span>
            </div>
            <div className="mt-1.5 break-all font-mono text-xs font-medium text-slate-900 dark:text-slate-100">
              {isAdmin
                ? t('Gizli (Hesapsız Paylaşımlı Anahtar)', 'Hidden (Accountless Shared Key)')
                : currentUser.email || '—'}
            </div>
          </div>

          <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900/50">
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <Clock className="h-3.5 w-3.5 text-blue-500" />
              <span>{t('Son Oturum', 'Last Session')}</span>
            </div>
            <div className="mt-1.5 font-mono text-xs text-slate-900 dark:text-slate-100">
              {currentUser.lastLoginAt ? formatTurkishDate(currentUser.lastLoginAt) : t('Şu an aktif', 'Active now')}
            </div>
          </div>

          <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900/50">
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
              <Shield className="h-3.5 w-3.5 text-blue-500" />
              <span>{t('Günlük Sorgu Kotası', 'Daily Query Quota')}</span>
            </div>
            <div className="mt-1.5 font-mono text-sm font-semibold tabular-nums text-slate-900 dark:text-slate-100">
              {isAdmin
                ? t('Sınırsız Yetki', 'Unlimited Access')
                : `${currentUser.dailyUsed} / ${limit} ${t('sorgu', 'queries')}`}
            </div>
            {!isAdmin && (
              <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
                <div className="h-full bg-blue-600 transition-all" style={{ width: `${usagePct}%` }} />
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
        <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
          {t('Rol Yetkileri', 'Role Permissions')} ({currentUser.role})
        </h3>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
          {t(
            'Mevcut rolünüze tanımlanan sorgu ve erişim izinleri aşağıda listelenir.',
            'Query and access permissions assigned to your current role are listed below.',
          )}
        </p>

        <dl className="mt-4 divide-y divide-slate-200 text-xs dark:divide-slate-800">
          {[
            [t('Discord ID Sorgulama', 'Discord ID Lookup'), currentUser.permissions.canIdLookup],
            [t('E-posta OSINT Modülü', 'Email OSINT Module'), currentUser.permissions.canEmailOsint],
            [t('Toplu ID Tarama', 'Bulk ID Lookup'), currentUser.permissions.canBulkLookup],
          ].map(([label, allowed]) => (
            <div key={String(label)} className="flex items-center justify-between py-2.5">
              <dt className="text-slate-700 dark:text-slate-300">{label}</dt>
              <dd
                className={`font-semibold ${
                  allowed ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500'
                }`}
              >
                {allowed ? t('Açık', 'Enabled') : t('Kapalı', 'Disabled')}
              </dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  );
}
