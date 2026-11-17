import { useState } from 'react';
import { Layers, AlertCircle } from 'lucide-react';
import type { BulkQueryRow, PublicUser } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { ApiError, apiBulkSearch } from '../utils/api';
import { formatTurkishDate } from '../utils/snowflake';

interface BulkLookupViewProps {
  currentUser: PublicUser;
  onInspectId: (id: string) => void;
  onUserUpdate: (u: PublicUser) => void;
  onUnauthorized?: () => void;
}

export function BulkLookupView({
  currentUser,
  onInspectId,
  onUserUpdate,
  onUnauthorized,
}: BulkLookupViewProps) {
  const { t } = useI18n();
  const [rawInput, setRawInput] = useState('');
  const [rows, setRows] = useState<BulkQueryRow[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = currentUser.role === 'Admin';
  const canBulk = currentUser.permissions.canBulkLookup || isAdmin;

  const handleBulkScan = async () => {
    if (!rawInput.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiBulkSearch(rawInput);
      setRows(res.rows);
      onUserUpdate(res.user);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized?.();
        return;
      }
      setError(err instanceof Error ? err.message : t('Toplu tarama başarısız oldu.', 'Bulk scan failed.'));
    } finally {
      setLoading(false);
    }
  };

  if (!canBulk) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-8 text-center dark:border-slate-800 dark:bg-[#111827]">
        <AlertCircle className="mx-auto h-7 w-7 text-amber-500" />
        <h2 className="mt-3 font-display text-base font-semibold text-slate-900 dark:text-slate-100">
          {t('Toplu Sorgu Özelliği Rolünüzde Kapalı', 'Bulk Lookup Disabled for Your Role')}
        </h2>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          {t(
            `Mevcut rolünüz (${currentUser.role}) toplu ID tarama yetkisine sahip değildir.`,
            `Your current role (${currentUser.role}) does not include bulk ID scanning.`,
          )}
        </p>
      </div>
    );
  }

  const matchedCount = rows ? rows.filter((r) => r.matches.length > 0).length : 0;
  const validCount = rows ? rows.filter((r) => r.validSnowflake).length : 0;

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
        <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
          {t('Toplu Discord ID Tarama', 'Bulk Discord ID Lookup')}
        </h2>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          {t(
            'Birden fazla Discord ID değerini alt alta veya virgülle ayırarak yapıştırın; tümünün Snowflake tarihlerini ve eşleşmelerini tek tabloda görün.',
            'Paste multiple Discord IDs separated by new lines or commas to inspect all Snowflake dates and exposure matches.',
          )}
        </p>

        <div className="mt-4 space-y-3">
          <label htmlFor="bulk-ids-input" className="sr-only">
            {t('Toplu Discord ID listesi', 'Bulk Discord ID list')}
          </label>
          <textarea
            id="bulk-ids-input"
            rows={5}
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
            placeholder={'104567890123456789\n452910384756192012\n803511102246789120'}
            className="w-full rounded-lg border border-slate-300 bg-slate-50 p-3 font-mono text-xs text-slate-900 placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
          />
          <div className="flex flex-wrap items-center justify-end gap-3">
            <button
              type="button"
              disabled={loading}
              onClick={handleBulkScan}
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
            >
              <Layers className="h-3.5 w-3.5" />
              <span>{loading ? t('Taranıyor...', 'Scanning...') : t('Toplu Tara', 'Run Bulk Scan')}</span>
            </button>
          </div>
        </div>

        {error && (
          <div role="alert" className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </section>

      {rows && (
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
            <span className="tabular-nums font-semibold text-slate-900 dark:text-slate-100">
              {rows.length} {t('ID tarandı', 'IDs scanned')}
            </span>
            <span aria-hidden="true">·</span>
            <span className="tabular-nums">{validCount} {t('geçerli Snowflake', 'valid Snowflake')}</span>
            <span aria-hidden="true">·</span>
            <span className="tabular-nums">{matchedCount} {t('kayıtta eşleşti', 'matched')}</span>
          </div>

          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                  <tr>
                    <th className="px-4 py-3 font-semibold whitespace-nowrap">Discord ID</th>
                    <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Snowflake Durumu', 'Snowflake Status')}</th>
                    <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Oluşturulma Tarihi', 'Creation Date')}</th>
                    <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Eşleşen E-postalar', 'Matched Emails')}</th>
                    <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Kullanıcı / Kaynak', 'Username / Source')}</th>
                    <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('IP / Telefon / Ek Bilgiler', 'IP / Phone / Extra Details')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  {rows.map((row) => {
                    const emails = Array.from(new Set(row.matches.map((m) => m.email.trim()).filter(Boolean)));
                    const userSources = Array.from(
                      new Set(
                        row.matches
                          .map((m) => {
                            const u = m.username.trim();
                            const s = m.source.trim();
                            if (!u && !s) return '';
                            return `${u || '—'}${s ? ` (${s})` : ''}`;
                          })
                          .filter(Boolean),
                      ),
                    );
                    const ips = Array.from(new Set(row.matches.map((m) => m.ip.trim()).filter(Boolean)));
                    const phones = Array.from(new Set(row.matches.map((m) => m.phone.trim()).filter(Boolean)));
                    const notes = Array.from(new Set(row.matches.map((m) => m.notes.trim()).filter(Boolean)));
                    const extraMap = new Map<string, Set<string>>();
                    for (const m of row.matches) {
                      for (const [k, rawV] of Object.entries(m.extra || {})) {
                        const key = k.trim();
                        const val = String(rawV || '').trim();
                        if (!key || !val) continue;
                        let set = extraMap.get(key);
                        if (!set) {
                          set = new Set<string>();
                          extraMap.set(key, set);
                        }
                        set.add(val);
                      }
                    }
                    const extraPairs = Array.from(extraMap.entries()).map(([k, set]) => [k, Array.from(set).join(', ')] as const);
                    const hasAnyExtra = ips.length > 0 || phones.length > 0 || notes.length > 0 || extraPairs.length > 0;

                    return (
                      <tr key={row.input} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                        <td className="px-4 py-3 align-top font-mono whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => onInspectId(row.input)}
                            className="font-medium text-blue-600 hover:underline dark:text-blue-400"
                          >
                            {row.input}
                          </button>
                        </td>
                        <td className="px-4 py-3 align-top whitespace-nowrap">
                          {row.validSnowflake ? (
                            <span className="font-medium text-emerald-700 dark:text-emerald-400">
                              {t('Geçerli', 'Valid')} (
                              {row.matches.length > 0
                                ? `${row.matches.length} ${t('kayıt', 'records')}`
                                : t('Kayıt yok', 'No records')}
                              )
                            </span>
                          ) : (
                            <span className="font-medium text-red-600 dark:text-red-400">{t('Geçersiz ID', 'Invalid ID')}</span>
                          )}
                        </td>
                        <td className="px-4 py-3 align-top whitespace-nowrap text-slate-600 dark:text-slate-300">
                          {row.snowflake ? formatTurkishDate(row.snowflake.createdAtIso) : '—'}
                        </td>
                        <td className="px-4 py-3 align-top font-mono text-slate-800 dark:text-slate-200">
                          {emails.length > 0 ? emails.join(', ') : '—'}
                        </td>
                        <td className="px-4 py-3 align-top text-slate-600 dark:text-slate-300">
                          {userSources.length > 0 ? userSources.join(', ') : '—'}
                        </td>
                        <td className="px-4 py-3 align-top text-slate-600 dark:text-slate-300">
                          {hasAnyExtra ? (
                            <div className="space-y-1">
                              {ips.length > 0 && (
                                <div className="font-mono">
                                  <span className="text-slate-400">IP: </span>
                                  <span>{ips.join(', ')}</span>
                                </div>
                              )}
                              {phones.length > 0 && (
                                <div className="font-mono">
                                  <span className="text-slate-400">{t('Tel:', 'Phone:')} </span>
                                  <span>{phones.join(', ')}</span>
                                </div>
                              )}
                              {notes.length > 0 && (
                                <div className="max-w-xs break-words text-slate-600 dark:text-slate-400">
                                  {notes.join(' · ')}
                                </div>
                              )}
                              {extraPairs.length > 0 && (
                                <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                                  {extraPairs.map(([k, v]) => (
                                    <span key={k}>
                                      <span className="font-medium text-slate-600 dark:text-slate-300">{k}:</span>{' '}
                                      <span className="font-mono">{v}</span>
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          ) : (
                            '—'
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
