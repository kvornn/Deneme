import { History, ArrowUpRight } from 'lucide-react';
import type { QueryHistoryItem } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { formatTurkishDate } from '../utils/snowflake';

interface HistoryViewProps {
  history: QueryHistoryItem[];
  onRerunQuery: (query: string) => void;
}

export function HistoryView({ history, onRerunQuery }: HistoryViewProps) {
  const { t } = useI18n();

  const typeNames: Record<QueryHistoryItem['detectedType'], string> = {
    discord_id: 'Discord ID',
    email: t('E-posta', 'Email'),
    username: t('Kullanıcı Adı', 'Username'),
    general: t('Genel', 'General'),
  };

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
        <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
          {t('Yerel Sorgu Geçmişi', 'Local Query History')}
        </h2>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          {t(
            'Son gerçekleştirdiğiniz aramalar yalnızca bu tarayıcı oturumunda tutulur.',
            'Your recent lookups are kept only for this browser session.',
          )}
        </p>
      </section>

      {history.length === 0 ? (
        <div className="rounded-xl border border-slate-200 bg-white p-10 text-center dark:border-slate-800 dark:bg-[#111827]">
          <History className="mx-auto h-8 w-8 text-slate-400" />
          <p className="mt-3 text-sm font-medium text-slate-800 dark:text-slate-200">
            {t('Henüz sorgu geçmişi bulunmuyor.', 'No query history yet.')}
          </p>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {t('ID Sorgu sekmesinden yaptığınız aramalar burada listelenecektir.', 'Queries from ID Lookup will appear here.')}
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-[#111827]">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400">
                <tr>
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Sorgu Metni', 'Query')}</th>
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Tür', 'Type')}</th>
                  <th className="px-4 py-3 text-right font-semibold whitespace-nowrap">{t('Eşleşme', 'Matches')}</th>
                  <th className="px-4 py-3 font-semibold whitespace-nowrap">{t('Tarih', 'Timestamp')}</th>
                  <th className="px-4 py-3 text-right font-semibold whitespace-nowrap">{t('İşlem', 'Action')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {history.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono font-medium text-slate-900 dark:text-slate-100">
                      {item.query}
                    </td>
                    <td className="px-4 py-3 text-slate-600 dark:text-slate-300">
                      {typeNames[item.detectedType]}
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-800 dark:text-slate-200">
                      {item.matchCount}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-slate-500 dark:text-slate-400">
                      {formatTurkishDate(item.timestamp)}
                    </td>
                    <td className="px-4 py-3 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onRerunQuery(item.query)}
                        className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-blue-600 hover:bg-blue-50 dark:border-slate-700 dark:text-blue-400 dark:hover:bg-slate-800"
                      >
                        <span>{t('Tekrar Sorgula', 'Run Again')}</span>
                        <ArrowUpRight className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
