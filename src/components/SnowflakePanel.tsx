import { useState } from 'react';
import { Check, Copy, ChevronDown, ChevronUp } from 'lucide-react';
import type { SnowflakeInfo } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { formatTurkishDate } from '../utils/snowflake';

interface SnowflakePanelProps {
  snowflake: SnowflakeInfo;
}

export function SnowflakePanel({ snowflake }: SnowflakePanelProps) {
  const { lang, t } = useI18n();
  const [copiedId, setCopiedId] = useState(false);
  const [showBinary, setShowBinary] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(snowflake.id);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 1500);
    } catch {
      // Ignore clipboard failures in restricted environments
    }
  };

  const ageText =
    lang === 'tr'
      ? `${snowflake.accountAge.years} yıl, ${snowflake.accountAge.months} ay, ${snowflake.accountAge.days} gün`
      : `${snowflake.accountAge.years} yrs, ${snowflake.accountAge.months} mos, ${snowflake.accountAge.days} days`;

  return (
    <section
      aria-label={t('Discord Snowflake Teknik Analizi', 'Discord Snowflake Technical Analysis')}
      className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-4 dark:border-slate-800">
        <div>
          <h2 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
            {t('Discord Snowflake Teknik Çözümlemesi', 'Discord Snowflake Technical Analysis')}
          </h2>
          <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
            {t(
              '64-bit zaman damgası ve iç düğüm parametreleri (matematiksel çözümleme)',
              '64-bit timestamp and internal node parameters (mathematical decoding)',
            )}
          </p>
        </div>

        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs font-medium text-slate-800 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-200 dark:hover:bg-slate-800 whitespace-nowrap"
        >
          <span>{snowflake.id}</span>
          {copiedId ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5 text-slate-400" />}
        </button>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <div className="text-xs text-slate-500 dark:text-slate-400">{t('Oluşturulma Tarihi', 'Creation Date')}</div>
          <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
            {formatTurkishDate(snowflake.createdAtIso)}
          </div>
          <div className="mt-0.5 font-mono text-xs text-slate-500 dark:text-slate-400">
            {snowflake.createdAtIso}
          </div>
        </div>

        <div>
          <div className="text-xs text-slate-500 dark:text-slate-400">{t('Hesap Yaşı', 'Account Age')}</div>
          <div className="mt-1 text-sm font-semibold tabular-nums text-slate-900 dark:text-slate-100">
            {ageText}
          </div>
          <div className="mt-0.5 font-mono text-xs text-slate-500 dark:text-slate-400">
            {t('Toplam', 'Total')} {snowflake.accountAge.totalDays.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')}{' '}
            {t('gün', 'days')}
          </div>
        </div>

        <div>
          <div className="text-xs text-slate-500 dark:text-slate-400">{t('İşçi ve Süreç Kimliği', 'Worker & Process ID')}</div>
          <div className="mt-1 font-mono text-sm font-semibold tabular-nums text-slate-900 dark:text-slate-100">
            Worker {snowflake.workerId} · Process {snowflake.processId}
          </div>
          <div className="mt-0.5 font-mono text-xs text-slate-500 dark:text-slate-400">
            Unix ms: {snowflake.timestampMs}
          </div>
        </div>

        <div>
          <div className="text-xs text-slate-500 dark:text-slate-400">{t('Sıra Artışı (Increment)', 'Sequence Increment')}</div>
          <div className="mt-1 font-mono text-sm font-semibold tabular-nums text-slate-900 dark:text-slate-100">
            #{snowflake.increment}
          </div>
          <button
            type="button"
            onClick={() => setShowBinary((v) => !v)}
            aria-expanded={showBinary}
            className="mt-1 inline-flex items-center gap-1 text-xs font-medium text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
          >
            <span>{t('64-bit İkili Döküm', '64-bit Binary Breakdown')}</span>
            {showBinary ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

      {showBinary && (
        <div className="mt-4 border-t border-slate-200 pt-3 dark:border-slate-800">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs">
            <span className="text-slate-500 dark:text-slate-400">{t('Zaman (42b):', 'Time (42b):')}</span>
            <span className="text-blue-600 dark:text-blue-400">{snowflake.binary64.slice(0, 42)}</span>
            <span className="text-slate-500 dark:text-slate-400">{t('İşçi (5b):', 'Worker (5b):')}</span>
            <span className="text-emerald-600 dark:text-emerald-400">{snowflake.binary64.slice(42, 47)}</span>
            <span className="text-slate-500 dark:text-slate-400">{t('Süreç (5b):', 'Process (5b):')}</span>
            <span className="text-amber-600 dark:text-amber-400">{snowflake.binary64.slice(47, 52)}</span>
            <span className="text-slate-500 dark:text-slate-400">{t('Sıra (12b):', 'Seq (12b):')}</span>
            <span className="text-slate-700 dark:text-slate-200">{snowflake.binary64.slice(52)}</span>
          </div>
        </div>
      )}
    </section>
  );
}
