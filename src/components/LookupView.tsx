import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Search, AlertCircle, UserRound, Filter, Database, RotateCcw, Gauge, Timer, HardDrive } from 'lucide-react';
import type { DatabaseSourceType, IntelRecord, PublicUser, SearchResult } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { SnowflakePanel } from './SnowflakePanel';
import { RecordTable } from './RecordTable';
import { formatTurkishDate } from '../utils/snowflake';
import { classifyRecordDatabaseType, formatByteVolume } from '../utils/search';

interface LookupViewProps {
  currentUser: PublicUser;
  query: string;
  onQueryChange: (q: string) => void;
  result: SearchResult | null;
  searching: boolean;
  searchError: string | null;
  onRunSearch: (overrideQuery?: string) => void;
  onPivotEmail: (email: string) => void;
}

type DbTypeFilter = 'all' | DatabaseSourceType;
type MatchScopeFilter = 'all' | 'primary' | 'related';
type FieldPresenceFilter = 'all' | 'has_email' | 'has_contact' | 'has_extra';

export function LookupView({
  currentUser,
  query,
  onQueryChange,
  result,
  searching,
  searchError,
  onRunSearch,
  onPivotEmail,
}: LookupViewProps) {
  const { lang, t } = useI18n();
  const isAdmin = currentUser.role === 'Admin';
  const [resultFilterText, setResultFilterText] = useState('');
  const [resultDbTypeFilter, setResultDbTypeFilter] = useState<DbTypeFilter>('all');
  const [resultScopeFilter, setResultScopeFilter] = useState<MatchScopeFilter>('all');
  const [resultFilterType, setResultFilterType] = useState<FieldPresenceFilter>('all');
  const [resultSourceFilter, setResultSourceFilter] = useState('all');
  const [resultExtraKeyFilter, setResultExtraKeyFilter] = useState('all');

  const resetAllFilters = () => {
    setResultFilterText('');
    setResultDbTypeFilter('all');
    setResultScopeFilter('all');
    setResultFilterType('all');
    setResultSourceFilter('all');
    setResultExtraKeyFilter('all');
  };

  useEffect(() => {
    resetAllFilters();
  }, [result]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    resetAllFilters();
    onRunSearch();
  };

  const allMatchedRecords = useMemo(
    () => (result ? [...result.primaryMatches, ...result.relatedMatches] : []),
    [result],
  );

  const dbTypeCounts = useMemo(() => {
    const counts: Record<DatabaseSourceType, number> = {
      leak: 0,
      sizinti: 0,
      public_info: 0,
    };
    for (const rec of allMatchedRecords) {
      counts[classifyRecordDatabaseType(rec)] += 1;
    }
    return counts;
  }, [allMatchedRecords]);

  const uniqueUsernames = useMemo(
    () => Array.from(new Set(allMatchedRecords.map((r) => r.username).filter(Boolean))),
    [allMatchedRecords],
  );
  const uniqueEmails = useMemo(
    () => Array.from(new Set(allMatchedRecords.map((r) => r.email).filter(Boolean))),
    [allMatchedRecords],
  );
  const uniqueSources = useMemo(
    () => Array.from(new Set(allMatchedRecords.map((r) => r.source).filter(Boolean))),
    [allMatchedRecords],
  );
  const uniquePhonesAndIps = useMemo(
    () =>
      Array.from(
        new Set(
          allMatchedRecords
            .flatMap((r) => [r.phone, r.ip])
            .map((v) => v.trim())
            .filter(Boolean),
        ),
      ),
    [allMatchedRecords],
  );

  const extraFieldsSummary = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const rec of allMatchedRecords) {
      for (const [k, rawVal] of Object.entries(rec.extra || {})) {
        const key = k.trim();
        const val = String(rawVal || '').trim();
        if (!key || !val) continue;
        let bucket = map.get(key);
        if (!bucket) {
          bucket = new Set<string>();
          map.set(key, bucket);
        }
        bucket.add(val);
      }
    }
    return Array.from(map.entries()).map(([key, values]) => ({
      key,
      values: Array.from(values),
    }));
  }, [allMatchedRecords]);

  const uniqueNotes = useMemo(
    () => Array.from(new Set(allMatchedRecords.map((r) => r.notes.trim()).filter(Boolean))),
    [allMatchedRecords],
  );

  const filterRecordList = useMemo(() => {
    const q = resultFilterText.trim().toLowerCase();
    return (list: IntelRecord[]) =>
      list.filter((r) => {
        const dbType = classifyRecordDatabaseType(r);
        if (resultDbTypeFilter !== 'all' && dbType !== resultDbTypeFilter) return false;
        if (resultFilterType === 'has_email' && !r.email.trim()) return false;
        if (resultFilterType === 'has_contact' && !r.ip.trim() && !r.phone.trim()) return false;
        if (
          resultFilterType === 'has_extra' &&
          !r.notes.trim() &&
          Object.values(r.extra || {}).every((v) => !String(v || '').trim())
        ) {
          return false;
        }
        if (resultSourceFilter !== 'all' && r.source !== resultSourceFilter) return false;
        if (resultExtraKeyFilter !== 'all') {
          const hasKey = Object.entries(r.extra || {}).some(
            ([k, v]) => k.trim() === resultExtraKeyFilter && String(v || '').trim() !== '',
          );
          if (!hasKey) return false;
        }
        if (!q) return true;
        const dbLabel =
          dbType === 'leak' ? 'leak' : dbType === 'sizinti' ? 'sızıntı sizinti breach' : 'public info osint açık';
        return (
          dbLabel.includes(q) ||
          r.discordId.toLowerCase().includes(q) ||
          r.email.toLowerCase().includes(q) ||
          r.username.toLowerCase().includes(q) ||
          r.source.toLowerCase().includes(q) ||
          (isAdmin && r.datasetName.toLowerCase().includes(q)) ||
          r.ip.toLowerCase().includes(q) ||
          r.phone.toLowerCase().includes(q) ||
          r.notes.toLowerCase().includes(q) ||
          Object.entries(r.extra || {}).some(
            ([k, v]) => k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q),
          )
        );
      });
  }, [
    resultFilterText,
    resultDbTypeFilter,
    resultFilterType,
    resultSourceFilter,
    resultExtraKeyFilter,
    isAdmin,
  ]);

  const filteredPrimary = useMemo(() => {
    if (!result || resultScopeFilter === 'related') return [];
    return filterRecordList(result.primaryMatches);
  }, [result, resultScopeFilter, filterRecordList]);

  const filteredRelated = useMemo(() => {
    if (!result || resultScopeFilter === 'primary') return [];
    return filterRecordList(result.relatedMatches);
  }, [result, resultScopeFilter, filterRecordList]);

  const totalFilteredCount = filteredPrimary.length + filteredRelated.length;
  const hasActiveFilters =
    resultFilterText.trim() !== '' ||
    resultDbTypeFilter !== 'all' ||
    resultScopeFilter !== 'all' ||
    resultFilterType !== 'all' ||
    resultSourceFilter !== 'all' ||
    resultExtraKeyFilter !== 'all';

  return (
    <div className="space-y-6">
      <section
        aria-label={t('Discord ID Sorgu Formu', 'Discord ID Lookup Form')}
        className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6"
      >
        <div className="max-w-3xl">
          <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
            {t('Discord ID Sorgulama', 'Discord ID Lookup')}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            {t(
              '17-20 haneli Discord ID girin; sistem yüklü tüm dosyalardaki eşleşen tüm bilgileri, sızıntıları ve çapraz bağlantıları sansürsüz olarak getirir.',
              'Enter a 17–20 digit Discord ID to scan all uploaded files, decode Snowflake timestamps, and retrieve all uncensored cross-linked records.',
            )}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-5 flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <label htmlFor="osint-search-input" className="sr-only">
              Discord ID
            </label>
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              id="osint-search-input"
              type="text"
              inputMode="numeric"
              value={query}
              onChange={(e) => onQueryChange(e.target.value)}
              placeholder={t('Örn. 104567890123456789 (17-20 haneli Discord ID)', 'e.g. 104567890123456789 (17–20 digit Discord ID)')}
              className="w-full rounded-lg border border-slate-300 bg-slate-50 py-2.5 pl-10 pr-4 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:bg-slate-950"
            />
          </div>
          <button
            type="submit"
            disabled={searching}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-6 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <Search className="h-4 w-4" />
            <span>{searching ? t('Aranıyor...', 'Searching...') : t('Sorgula', 'Lookup')}</span>
          </button>
        </form>

        {searchError && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{searchError}</span>
          </div>
        )}
      </section>

      {result && (
        <div className="space-y-6">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
              <span className="font-semibold text-slate-900 dark:text-slate-100">
                {t('Hedef ID:', 'Target ID:')} <span className="font-mono">{result.query}</span>
              </span>
              <span aria-hidden="true">·</span>
              <span className="tabular-nums">
                {result.primaryMatches.length} {t('birincil eşleşme', 'direct matches')}
              </span>
              <span aria-hidden="true">·</span>
              <span className="tabular-nums">
                {result.relatedMatches.length} {t('bağlantılı kayıt', 'linked records')}
              </span>
            </div>

            <div
              data-testid="lookup-performance-metrics"
              aria-label={t('Sorgu Performans Metriği', 'Query Performance Metrics')}
              className="flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-xl border border-slate-200/70 bg-white/45 px-3.5 py-2 text-[11px] text-slate-600 backdrop-blur-sm dark:border-slate-800/70 dark:bg-slate-900/35 dark:text-slate-300"
            >
              <div className="inline-flex items-center gap-1.5 font-semibold text-slate-800 dark:text-slate-200">
                <Gauge className="h-3.5 w-3.5 text-blue-500" />
                <span>{t('Performans Metriği', 'Performance')}</span>
              </div>
              <span className="hidden h-3 w-px bg-slate-300/70 dark:bg-slate-700/70 sm:inline-block" aria-hidden="true" />
              <div className="inline-flex items-center gap-1.5 tabular-nums">
                <Timer className="h-3.5 w-3.5 text-emerald-500" />
                <span className="text-slate-500 dark:text-slate-400">{t('Süre:', 'Time:')}</span>
                <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                  {result.durationMs} ms
                </span>
              </div>
              <span className="hidden h-3 w-px bg-slate-300/70 dark:bg-slate-700/70 sm:inline-block" aria-hidden="true" />
              <div className="inline-flex items-center gap-1.5 tabular-nums">
                <HardDrive className="h-3.5 w-3.5 text-indigo-500" />
                <span className="text-slate-500 dark:text-slate-400">{t('Taranan Hacim:', 'Scanned Volume:')}</span>
                <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                  {(result.scanMetrics?.scannedRecords ?? allMatchedRecords.length).toLocaleString(
                    lang === 'tr' ? 'tr-TR' : 'en-US',
                  )}{' '}
                  {t('kayıt', 'records')} · {formatByteVolume(result.scanMetrics?.scannedBytes ?? 0)}
                  {result.scanMetrics?.scannedDatasets
                    ? ` · ${result.scanMetrics.scannedDatasets} ${t('dosya', 'datasets')}`
                    : ''}
                </span>
              </div>
            </div>
          </div>

          <section
            aria-label={t('Discord Hesap Profili Özeti', 'Discord Account Profile Summary')}
            data-testid="discord-profile-summary"
            className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]"
          >
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-blue-600 dark:border-slate-700 dark:bg-slate-900 dark:text-blue-400">
                  <UserRound className="h-5 w-5" />
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-display text-base font-bold text-slate-900 dark:text-slate-100">
                      {uniqueUsernames[0] || `${t('Discord Kullanıcısı', 'Discord User')} (${result.query.slice(-6)})`}
                    </h3>
                    <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                      #{result.query}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                    {result.snowflake
                      ? `${t('Oluşturulma:', 'Created:')} ${formatTurkishDate(result.snowflake.createdAtIso)} (${result.snowflake.accountAge.years} ${t('yıl', 'yr')}, ${result.snowflake.accountAge.months} ${t('ay', 'mo')})`
                      : t('Snowflake bilgisi çözümlendi', 'Snowflake decoded')}
                  </p>
                </div>
              </div>

              <div className="text-xs font-semibold">
                {allMatchedRecords.length > 0 ? (
                  <span className="text-amber-600 dark:text-amber-400">
                    {allMatchedRecords.length}{' '}
                    {t('Kayıtta Sızıntı / Eşleşme Tespit Edildi', 'Breach / Exposure Records Detected')}
                  </span>
                ) : (
                  <span className="text-emerald-600 dark:text-emerald-400">
                    {t('Sızıntı / Eşleşme Tespit Edilmedi', 'No Exposure Records Detected')}
                  </span>
                )}
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 text-xs sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <div className="text-slate-500 dark:text-slate-400">
                  {t('Görülen Kullanıcı Adları', 'Observed Usernames')}
                </div>
                <div className="mt-1 font-mono text-slate-900 dark:text-slate-100">
                  {uniqueUsernames.length > 0 ? uniqueUsernames.join(', ') : t('Kayıt yok', 'None')}
                </div>
              </div>
              <div>
                <div className="text-slate-500 dark:text-slate-400">
                  {t('Bağlantılı E-postalar', 'Linked Emails')} ({uniqueEmails.length})
                </div>
                <div className="mt-1 font-mono text-slate-900 dark:text-slate-100">
                  {uniqueEmails.length > 0 ? uniqueEmails.join(', ') : t('Kayıt yok', 'None')}
                </div>
              </div>
              <div>
                <div className="text-slate-500 dark:text-slate-400">
                  {t('Tespit Edilen IP & Telefonlar', 'Detected IPs & Phones')} ({uniquePhonesAndIps.length})
                </div>
                <div className="mt-1 font-mono text-slate-900 dark:text-slate-100">
                  {uniquePhonesAndIps.length > 0 ? uniquePhonesAndIps.join(', ') : t('Kayıt yok', 'None')}
                </div>
              </div>
              <div>
                <div className="text-slate-500 dark:text-slate-400">
                  {t('Tespit Edilen Kaynaklar', 'Detected Sources')} ({uniqueSources.length})
                </div>
                <div className="mt-1 font-mono text-slate-900 dark:text-slate-100">
                  {uniqueSources.length > 0 ? uniqueSources.join(', ') : t('Kayıt yok', 'None')}
                </div>
              </div>
            </div>

            {(extraFieldsSummary.length > 0 || uniqueNotes.length > 0) && (
              <div
                data-testid="dynamic-extra-summary"
                className="mt-4 border-t border-slate-200 pt-4 dark:border-slate-800"
              >
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  {t(
                    'Sistemdeki Tüm Dosyalardan Toplanan Ek Alanlar & Bilgiler',
                    'All Dynamic Extra Fields & Attributes Across System Files',
                  )}{' '}
                  ({extraFieldsSummary.length + (uniqueNotes.length > 0 ? 1 : 0)})
                </div>
                <div className="mt-2.5 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2 lg:grid-cols-3">
                  {extraFieldsSummary.map((field) => (
                    <div
                      key={field.key}
                      className="rounded-lg border border-slate-200/80 bg-slate-50/70 px-3 py-2 dark:border-slate-800 dark:bg-slate-900/50"
                    >
                      <div className="text-[11px] font-semibold text-slate-600 dark:text-slate-400">
                        {field.key}
                      </div>
                      <div className="mt-0.5 break-all font-mono text-slate-900 dark:text-slate-100">
                        {field.values.join(', ')}
                      </div>
                    </div>
                  ))}
                  {uniqueNotes.length > 0 && (
                    <div className="rounded-lg border border-slate-200/80 bg-slate-50/70 px-3 py-2 dark:border-slate-800 dark:bg-slate-900/50 sm:col-span-2 lg:col-span-3">
                      <div className="text-[11px] font-semibold text-slate-600 dark:text-slate-400">
                        {t('Notlar / Ham Bilgiler', 'Notes / Additional Context')}
                      </div>
                      <div className="mt-0.5 break-words font-mono text-slate-900 dark:text-slate-100">
                        {uniqueNotes.join(' · ')}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </section>

          {result.snowflake && <SnowflakePanel snowflake={result.snowflake} />}

          {allMatchedRecords.length > 0 && (
            <section
              aria-label={t('Gelişmiş Arama Filtreleri', 'Advanced Search Filters')}
              data-testid="advanced-lookup-filters"
              className="space-y-3 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-[#111827]"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/80 pb-3 dark:border-slate-800">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-900 dark:text-slate-100">
                  <Database className="h-4 w-4 text-blue-500" />
                  <span>{t('Gelişmiş Sonuç Filtresi', 'Advanced Result Filter')}</span>
                  <span className="font-mono text-[11px] font-normal text-slate-500 dark:text-slate-400 tabular-nums">
                    ({t('Gösterilen:', 'Showing:')} {totalFilteredCount} / {allMatchedRecords.length})
                  </span>
                </div>

                {hasActiveFilters && (
                  <button
                    type="button"
                    onClick={resetAllFilters}
                    className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-700 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
                  >
                    <RotateCcw className="h-3 w-3" />
                    <span>{t('Filtreleri Sıfırla', 'Reset Filters')}</span>
                  </button>
                )}
              </div>

              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    {t('Veritabanı Türü:', 'Database Type:')}
                  </span>
                  <div
                    role="group"
                    aria-label={t('Veritabanı türüne göre filtrele', 'Filter by database type')}
                    className="inline-flex flex-wrap gap-1 rounded-lg bg-slate-100 p-1 dark:bg-slate-900/90"
                  >
                    {(
                      [
                        ['all', t('Tümü', 'All'), allMatchedRecords.length, 'active-blue'],
                        ['leak', 'Leak', dbTypeCounts.leak, 'active-rose'],
                        ['sizinti', t('Sızıntı', 'Breach'), dbTypeCounts.sizinti, 'active-amber'],
                        ['public_info', 'Public Info', dbTypeCounts.public_info, 'active-emerald'],
                      ] as const
                    ).map(([key, label, count, accent]) => {
                      const active = resultDbTypeFilter === key;
                      const activeCls =
                        accent === 'active-rose'
                          ? 'bg-rose-600 text-white shadow-xs'
                          : accent === 'active-amber'
                            ? 'bg-amber-600 text-white shadow-xs'
                            : accent === 'active-emerald'
                              ? 'bg-emerald-600 text-white shadow-xs'
                              : 'bg-blue-600 text-white shadow-xs';
                      return (
                        <button
                          key={key}
                          type="button"
                          aria-pressed={active}
                          data-testid={`db-type-filter-${key}`}
                          onClick={() => setResultDbTypeFilter(key)}
                          className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors whitespace-nowrap ${
                            active
                              ? activeCls
                              : 'text-slate-600 hover:bg-white/70 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white'
                          }`}
                        >
                          <span>{label}</span>
                          <span
                            className={`font-mono text-[10px] tabular-nums ${
                              active ? 'text-white/90' : 'text-slate-400 dark:text-slate-500'
                            }`}
                          >
                            ({count})
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="relative flex-1 min-w-[220px] max-w-sm">
                  <label htmlFor="result-keyword-filter" className="sr-only">
                    {t('Sonuçlarda anlık anahtar kelime ara', 'Filter results by keyword')}
                  </label>
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                  <input
                    id="result-keyword-filter"
                    type="text"
                    value={resultFilterText}
                    onChange={(e) => setResultFilterText(e.target.value)}
                    placeholder={t(
                      'Anlık ara: e-posta, IP, telefon, HWID, kaynak, not...',
                      'Instant filter: email, IP, phone, HWID, source, notes...',
                    )}
                    className="w-full rounded-lg border border-slate-300 bg-slate-50 py-1.5 pl-8 pr-3 font-mono text-xs text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:focus:bg-slate-950"
                  />
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-slate-600 dark:text-slate-300">
                <div className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400">
                  <Filter className="h-3.5 w-3.5 text-blue-500" />
                  <span>{t('Detaylı Süzgeç:', 'Refinements:')}</span>
                </div>

                <div className="inline-flex flex-wrap rounded-lg bg-slate-100 p-0.5 dark:bg-slate-800/80">
                  {(
                    [
                      ['all', t('Tüm İçerik', 'All Fields')],
                      ['has_email', t('E-postalı', 'With Email')],
                      ['has_contact', t('IP / Telefonlu', 'With IP / Phone')],
                      ['has_extra', t('Ek Alan / Notlu', 'With Extra / Notes')],
                    ] as const
                  ).map(([key, label]) => (
                    <button
                      key={key}
                      type="button"
                      aria-pressed={resultFilterType === key}
                      onClick={() => setResultFilterType(key)}
                      className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors whitespace-nowrap ${
                        resultFilterType === key
                          ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                          : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>

                <select
                  aria-label={t('Eşleşme kapsamına göre filtrele', 'Filter by match scope')}
                  value={resultScopeFilter}
                  onChange={(e) => setResultScopeFilter(e.target.value as MatchScopeFilter)}
                  className="rounded-lg border border-slate-300 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-800 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                >
                  <option value="all">{t('Tüm Eşleşmeler (Doğrudan + Çapraz)', 'All Matches (Direct + Linked)')}</option>
                  <option value="primary">{t('Sadece Doğrudan Discord ID', 'Direct Discord ID Only')}</option>
                  <option value="related">{t('Sadece Çapraz Bağlantılar', 'Cross-Linked Only')}</option>
                </select>

                {uniqueSources.length > 0 && (
                  <select
                    aria-label={t('Kaynağa göre filtrele', 'Filter by source')}
                    value={resultSourceFilter}
                    onChange={(e) => setResultSourceFilter(e.target.value)}
                    className="rounded-lg border border-slate-300 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-800 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                  >
                    <option value="all">{t('Tüm Kaynaklar', 'All Sources')}</option>
                    {uniqueSources.map((src) => (
                      <option key={src} value={src}>
                        {src}
                      </option>
                    ))}
                  </select>
                )}

                {extraFieldsSummary.length > 0 && (
                  <select
                    aria-label={t('Dinamik ek alana göre filtrele', 'Filter by dynamic attribute')}
                    value={resultExtraKeyFilter}
                    onChange={(e) => setResultExtraKeyFilter(e.target.value)}
                    className="rounded-lg border border-slate-300 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-800 focus:border-blue-500 focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200"
                  >
                    <option value="all">
                      {lang === 'tr' ? 'Tüm Ek Alanlar' : 'All Extra Attributes'}
                    </option>
                    {extraFieldsSummary.map((field) => (
                      <option key={field.key} value={field.key}>
                        {field.key} ({field.values.length})
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </section>
          )}

          {resultScopeFilter !== 'related' && (
            <section aria-label={t('Doğrudan Eşleşmeler', 'Direct Matches')} className="space-y-3">
              <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('Doğrudan Discord ID Eşleşmeleri', 'Direct Discord ID Matches')} ({filteredPrimary.length})
              </h3>
              {filteredPrimary.length > 0 ? (
                <RecordTable
                  records={filteredPrimary}
                  showDatasetName={isAdmin}
                  onPivotQuery={(q) => onRunSearch(q)}
                  onPivotEmail={onPivotEmail}
                  testId="primary-matches-table"
                />
              ) : (
                <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white p-5 text-sm text-slate-600 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                  <div>
                    <p className="font-medium text-slate-800 dark:text-slate-200">
                      {result.primaryMatches.length > 0
                        ? t('Uygulanan filtreyle eşleşen doğrudan kayıt bulunamadı.', 'No direct matches match the active filter.')
                        : t('Bu Discord ID için eşleşen kayıt bulunamadı.', 'No matching records found for this Discord ID.')}
                    </p>
                    <p className="mt-0.5 text-xs">
                      {result.primaryMatches.length > 0
                        ? t('Filtre metnini veya veritabanı türü seçimini temizleyebilirsiniz.', 'Clear the filter input or database type toggle to view all matches.')
                        : t('Herhangi bir sızıntı veya ihlal kaydı tespit edilmedi.', 'No breach or leak exposure was detected.')}
                    </p>
                  </div>
                </div>
              )}
            </section>
          )}

          {resultScopeFilter !== 'primary' && (filteredRelated.length > 0 || (result.relatedMatches.length > 0 && hasActiveFilters)) && (
            <section aria-label={t('Bağlantılı Kayıtlar', 'Connected Records')} className="space-y-3">
              <div>
                <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {t('Bağlantılı Sızıntılar ve Çapraz Eşleşmeler', 'Connected Exposures & Cross-Matches')} ({filteredRelated.length})
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {t(
                    'Bu Discord ID ile ilişkili e-posta, telefon, IP veya kullanıcı adı üzerinden bağlaşan tüm diğer kayıtlar',
                    'All additional records connected via shared emails, phone numbers, IPs, or usernames linked to this Discord ID',
                  )}
                </p>
              </div>
              {filteredRelated.length > 0 ? (
                <RecordTable
                  records={filteredRelated}
                  showDatasetName={isAdmin}
                  onPivotQuery={(q) => onRunSearch(q)}
                  onPivotEmail={onPivotEmail}
                  testId="related-matches-table"
                />
              ) : (
                <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-white p-5 text-sm text-slate-600 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                  <div>
                    <p className="font-medium text-slate-800 dark:text-slate-200">
                      {t('Uygulanan filtreyle eşleşen bağlantılı kayıt bulunamadı.', 'No linked records match the active filter.')}
                    </p>
                    <p className="mt-0.5 text-xs">
                      {t('Veritabanı türü veya anahtar kelime filtresini sıfırlayarak tüm bağlantılı kayıtları görebilirsiniz.', 'Reset the database type or keyword filter to see all connected records.')}
                    </p>
                  </div>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  );
}
