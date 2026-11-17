import { useEffect, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import type { DatabaseSourceType, IntelRecord } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { classifyRecordDatabaseType } from '../utils/search';

interface RecordTableProps {
  records: IntelRecord[];
  showDatasetName?: boolean;
  onPivotQuery: (query: string) => void;
  onPivotEmail?: (email: string) => void;
  testId?: string;
}

const DB_TYPE_STYLES: Record<DatabaseSourceType, { tr: string; en: string; cls: string }> = {
  leak: {
    tr: 'Leak',
    en: 'Leak',
    cls: 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  },
  sizinti: {
    tr: 'Sızıntı',
    en: 'Breach',
    cls: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  },
  public_info: {
    tr: 'Public Info',
    en: 'Public Info',
    cls: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  },
};

const PAGE_STEP = 100;

export function RecordTable({
  records,
  showDatasetName = false,
  onPivotQuery,
  onPivotEmail,
  testId,
}: RecordTableProps) {
  const { lang, t } = useI18n();
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [visibleCount, setVisibleCount] = useState(PAGE_STEP);

  useEffect(() => {
    setVisibleCount(PAGE_STEP);
  }, [records]);

  const handleCopy = async (key: string, value: string) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1400);
    } catch {
      // Ignore clipboard errors
    }
  };

  const shownRecords = records.length > visibleCount ? records.slice(0, visibleCount) : records;
  const remaining = Math.max(0, records.length - shownRecords.length);

  return (
    <div
      data-testid={testId}
      className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]"
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
            <tr>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">Discord ID</th>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('E-posta Adresi', 'Email Address')}</th>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Kullanıcı Adı', 'Username')}</th>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Kaynak / Tür', 'Source / Type')}</th>
              <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Ek Bilgiler (IP / Tel / Alanlar)', 'Additional Fields (IP / Phone / Extra)')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {shownRecords.map((rec) => {
              const extraEntries = Object.entries(rec.extra);
              const dbType = classifyRecordDatabaseType(rec);
              const typeMeta = DB_TYPE_STYLES[dbType];

              return (
                <tr
                  key={rec.id}
                  className="transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-800/30"
                >
                  <td className="px-4 py-3 align-top font-mono whitespace-nowrap">
                    {rec.discordId ? (
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => onPivotQuery(rec.discordId)}
                          title={t('Bu Discord ID ile sorgula', 'Lookup this Discord ID')}
                          className="font-medium text-blue-600 hover:underline dark:text-blue-400"
                        >
                          {rec.discordId}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleCopy(`${rec.id}-id`, rec.discordId)}
                          aria-label={`Copy Discord ID: ${rec.discordId}`}
                          className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                        >
                          {copiedKey === `${rec.id}-id` ? (
                            <Check className="h-3.5 w-3.5 text-emerald-500" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>

                  <td className="px-4 py-3 align-top font-mono whitespace-nowrap">
                    {rec.email ? (
                      <div className="flex items-center gap-1.5">
                        {onPivotEmail ? (
                          <button
                            type="button"
                            onClick={() => onPivotEmail(rec.email)}
                            title={t('Bu e-postayı E-posta OSINT modülünde tara', 'Scan this email in Email OSINT')}
                            className="font-medium text-slate-900 hover:text-blue-600 hover:underline dark:text-slate-100 dark:hover:text-blue-400"
                          >
                            {rec.email}
                          </button>
                        ) : (
                          <span className="font-medium text-slate-900 dark:text-slate-100">{rec.email}</span>
                        )}
                        <button
                          type="button"
                          onClick={() => handleCopy(`${rec.id}-email`, rec.email)}
                          aria-label={`Copy email: ${rec.email}`}
                          className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                        >
                          {copiedKey === `${rec.id}-email` ? (
                            <Check className="h-3.5 w-3.5 text-emerald-500" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>

                  <td className="px-4 py-3 align-top whitespace-nowrap text-slate-800 dark:text-slate-200">
                    {rec.username ? (
                      <button
                        type="button"
                        onClick={() => handleCopy(`${rec.id}-user`, rec.username)}
                        title={t('Kullanıcı adını kopyala', 'Copy username')}
                        className="font-medium hover:text-blue-600 dark:hover:text-blue-400"
                      >
                        {rec.username}
                      </button>
                    ) : (
                      <span className="text-slate-400">—</span>
                    )}
                  </td>

                  <td className="px-4 py-3 align-top text-slate-600 dark:text-slate-300">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-medium text-slate-900 dark:text-slate-100">{rec.source || '—'}</span>
                      <span
                        className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${typeMeta.cls}`}
                      >
                        {lang === 'tr' ? typeMeta.tr : typeMeta.en}
                      </span>
                    </div>
                    {showDatasetName && rec.datasetName && (
                      <div className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                        {rec.datasetName}
                      </div>
                    )}
                  </td>

                  <td className="px-4 py-3 align-top text-slate-600 dark:text-slate-300">
                    <div className="space-y-1">
                      {rec.ip && (
                        <div className="font-mono">
                          <span className="text-slate-400">IP: </span>
                          <span>{rec.ip}</span>
                        </div>
                      )}
                      {rec.phone && (
                        <div className="font-mono">
                          <span className="text-slate-400">{t('Tel:', 'Phone:')} </span>
                          <span>{rec.phone}</span>
                        </div>
                      )}
                      {rec.notes && (
                        <div className="max-w-xs text-slate-600 dark:text-slate-400">{rec.notes}</div>
                      )}
                      {extraEntries.length > 0 && (
                        <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                          {extraEntries.map(([k, v]) => (
                            <span key={k}>
                              <span className="font-medium text-slate-600 dark:text-slate-300">{k}:</span>{' '}
                              <span className="font-mono">{v}</span>
                            </span>
                          ))}
                        </div>
                      )}
                      {!rec.ip && !rec.phone && !rec.notes && extraEntries.length === 0 && (
                        <span className="text-slate-400">—</span>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {remaining > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200 bg-slate-50/80 px-4 py-2.5 text-xs dark:border-slate-800 dark:bg-slate-900/50">
          <span className="text-slate-600 dark:text-slate-400 tabular-nums">
            {t(
              `Toplam ${records.length} kaydın ${shownRecords.length} tanesi gösteriliyor`,
              `Showing ${shownRecords.length} of ${records.length} records`,
            )}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setVisibleCount((prev) => prev + PAGE_STEP)}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1 text-[11px] font-semibold text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
            >
              +{Math.min(PAGE_STEP, remaining)} {t('Daha Göster', 'Show More')}
            </button>
            <button
              type="button"
              onClick={() => setVisibleCount(records.length)}
              className="rounded-md border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-[11px] font-semibold text-blue-700 hover:bg-blue-500/20 dark:text-blue-300"
            >
              {t(`Tümünü Göster (${records.length})`, `Show All (${records.length})`)}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
