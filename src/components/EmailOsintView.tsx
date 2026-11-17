import { useEffect, useState, type FormEvent } from 'react';
import { MailSearch, ExternalLink, AlertCircle, CheckCircle2, Info } from 'lucide-react';
import type { EmailOsintReport, PublicUser } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import { ApiError, apiEmailOsint } from '../utils/api';
import { RecordTable } from './RecordTable';

interface EmailOsintViewProps {
  currentUser: PublicUser;
  initialEmail?: string | null;
  onConsumeInitialEmail?: () => void;
  onUserUpdate: (u: PublicUser) => void;
  onPivotQuery: (q: string) => void;
  onUnauthorized?: () => void;
}

export function EmailOsintView({
  currentUser,
  initialEmail,
  onConsumeInitialEmail,
  onUserUpdate,
  onPivotQuery,
  onUnauthorized,
}: EmailOsintViewProps) {
  const { lang, t } = useI18n();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<EmailOsintReport | null>(null);

  const isAdmin = currentUser.role === 'Admin';

  const runScanForEmail = async (targetEmail: string) => {
    const trimmed = targetEmail.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiEmailOsint(trimmed, lang);
      setReport(res.report);
      onUserUpdate(res.user);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized?.();
        return;
      }
      setError(err instanceof Error ? err.message : t('E-posta OSINT taraması başarısız oldu.', 'Email OSINT scan failed.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialEmail && currentUser.permissions.canEmailOsint) {
      setEmail(initialEmail);
      onConsumeInitialEmail?.();
      void runScanForEmail(initialEmail);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialEmail]);

  const handleScan = async (e: FormEvent) => {
    e.preventDefault();
    await runScanForEmail(email);
  };

  if (!currentUser.permissions.canEmailOsint) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-8 text-center dark:border-slate-800 dark:bg-[#111827]">
        <AlertCircle className="mx-auto h-7 w-7 text-amber-500" />
        <h2 className="mt-3 font-display text-base font-semibold text-slate-900 dark:text-slate-100">
          {t('E-posta OSINT Yetkisi Kapalı', 'Email OSINT Access Disabled')}
        </h2>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          {t(
            `Mevcut rolünüz (${currentUser.role}) için E-posta OSINT modülü yönetici tarafından devre dışı bırakılmıştır.`,
            `Email OSINT is disabled for your current role (${currentUser.role}) by the administrator.`,
          )}
        </p>
      </div>
    );
  }

  const foundCount = report ? report.externalChecks.filter((c) => c.status === 'found').length : 0;

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827] sm:p-6">
        <div className="max-w-3xl">
          <h2 className="font-display text-lg font-bold text-slate-900 dark:text-slate-100">
            {t('E-posta OSINT ve Eşzamanlı Çoklu Kaynak Tarama', 'Email OSINT & Simultaneous Multi-Source Lookup')}
          </h2>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
            {t(
              'DNS / MX / SPF / DMARC ve RDAP altyapısının yanında XposedOrNot, LeakCheck, Hudson Rock Cavalier, ProxyNova COMB, Proton/OpenPGP, Gravatar, GitHub ve açık sızıntı indekslerinde eşzamanlı tarama yapar.',
              'Simultaneously queries XposedOrNot, LeakCheck, Hudson Rock Cavalier, ProxyNova COMB, Proton/OpenPGP, Gravatar, GitHub, plus DNS / MX / SPF / DMARC & RDAP infrastructure.',
            )}
          </p>
        </div>

        <form onSubmit={handleScan} className="mt-5 flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <label htmlFor="email-osint-input" className="sr-only">
              {t('Sorgulanacak E-posta Adresi', 'Email Address to Scan')}
            </label>
            <MailSearch className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              id="email-osint-input"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={t('ornek@gmail.com veya analiz edilecek e-posta adresi...', 'example@gmail.com or target email address...')}
              className="w-full rounded-lg border border-slate-300 bg-slate-50 py-2.5 pl-10 pr-4 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-6 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <MailSearch className="h-4 w-4" />
            <span>{loading ? t('Eşzamanlı Taranıyor...', 'Scanning...') : t('OSINT Taraması Başlat', 'Run OSINT Scan')}</span>
          </button>
        </form>

        {error && (
          <div role="alert" className="mt-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </section>

      {report && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              {t('Hedef:', 'Target:')} <span className="font-mono">{report.email}</span>
            </span>
            <span aria-hidden="true">·</span>
            <span>{report.mailProvider}</span>
            <span aria-hidden="true">·</span>
            <span>
              {report.isDisposable
                ? t('Geçici / Tek Kullanımlık Alan Adı', 'Disposable Domain')
                : t('Standart Alan Adı', 'Standard Domain')}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-semibold text-blue-600 dark:text-blue-400">
              {foundCount} / {report.externalChecks.length} {t('canlı kaynakta eşleşme', 'live sources matched')}
            </span>
            <span aria-hidden="true">·</span>
            <span className="font-mono tabular-nums">{report.durationMs} ms</span>
          </div>

          <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t('Alan Adı ve Posta Sunucusu Altyapısı', 'Domain & Mail Infrastructure')} ({report.domain})
            </h3>
            <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <div className="text-xs text-slate-500 dark:text-slate-400">{t('Posta Sağlayıcısı', 'Mail Provider')}</div>
                <div className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {report.mailProvider}
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-500 dark:text-slate-400">{t('MX Kayıtları', 'MX Records')}</div>
                <div className="mt-1 font-mono text-xs text-slate-800 dark:text-slate-200">
                  {report.mxRecords.length > 0
                    ? report.mxRecords.slice(0, 3).map((m) => `${m.priority} ${m.exchange}`).join(', ')
                    : t('MX kaydı yok', 'No MX records')}
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-500 dark:text-slate-400">{t('SPF / DMARC Güvenliği', 'SPF / DMARC Security')}</div>
                <div className="mt-1 text-xs text-slate-800 dark:text-slate-200">
                  <div>SPF: {report.spfRecord ? t('Tanımlı', 'Configured') : t('Bulunamadı', 'Missing')}</div>
                  <div>DMARC: {report.dmarcRecord ? t('Tanımlı', 'Configured') : t('Bulunamadı', 'Missing')}</div>
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-500 dark:text-slate-400">{t('RDAP Alan Adı Kaydı', 'RDAP Domain Record')}</div>
                <div className="mt-1 text-xs text-slate-800 dark:text-slate-200">
                  {report.rdap ? (
                    <>
                      <div>{report.rdap.registrar || t('Belirtilmemiş', 'Not specified')}</div>
                      {report.rdap.createdDate && (
                        <div className="font-mono text-slate-500 dark:text-slate-400">
                          {t('Kayıt:', 'Registered:')} {report.rdap.createdDate.slice(0, 10)}
                        </div>
                      )}
                    </>
                  ) : (
                    <span className="text-slate-500 dark:text-slate-400">{t('RDAP bilgisi alınamadı', 'RDAP unavailable')}</span>
                  )}
                </div>
              </div>
            </div>
          </section>

          <section className="space-y-3">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t('Eşzamanlı Açık Kaynak & Ücretsiz Sızıntı İndeksleri', 'Simultaneous Free OSINT & Breach APIs')} ({report.externalChecks.length})
            </h3>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
              {report.externalChecks.map((chk) => (
                <div
                  key={chk.source}
                  className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-[#111827]"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-display text-xs font-semibold text-slate-900 dark:text-slate-100">
                      {chk.source}
                    </span>
                    {chk.status === 'found' ? (
                      <CheckCircle2 className="h-4 w-4 text-amber-500 shrink-0" />
                    ) : chk.status === 'error' ? (
                      <AlertCircle className="h-4 w-4 text-slate-400 shrink-0" />
                    ) : (
                      <Info className="h-4 w-4 text-emerald-500 shrink-0" />
                    )}
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-slate-600 dark:text-slate-300">
                    {chk.summary}
                  </p>
                  {Object.keys(chk.details).length > 0 && (
                    <div className="mt-3 space-y-2 border-t border-slate-200 pt-2.5 text-[11px] dark:border-slate-800">
                      {Object.entries(chk.details).map(([k, v]) => (
                        <div key={k} className="break-all font-mono text-slate-600 dark:text-slate-400">
                          <div className="font-semibold text-slate-700 dark:text-slate-300">{k}:</div>
                          {Array.isArray(v) ? (
                            <ul className="mt-0.5 space-y-0.5 pl-2">
                              {v.map((item, idx) => (
                                <li key={`${k}-${idx}`} className="leading-snug">
                                  {item}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <div>{v}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>

          <section className="space-y-3">
            <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t('İlişkili Kayıt Eşleşmeleri', 'Matched Exposure Records')} ({report.localMatches.length})
            </h3>
            {report.localMatches.length > 0 ? (
              <div className="space-y-3">
                {(() => {
                  const linkedIds = Array.from(new Set(report.localMatches.map((r) => r.discordId).filter(Boolean)));
                  const linkedUsers = Array.from(new Set(report.localMatches.map((r) => r.username).filter(Boolean)));
                  const linkedContacts = Array.from(
                    new Set(report.localMatches.flatMap((r) => [r.phone, r.ip]).filter(Boolean)),
                  );
                  const linkedSources = Array.from(new Set(report.localMatches.map((r) => r.source).filter(Boolean)));
                  const linkedNotes = Array.from(new Set(report.localMatches.map((r) => r.notes.trim()).filter(Boolean)));
                  const extraMap = new Map<string, Set<string>>();
                  for (const r of report.localMatches) {
                    for (const [k, rawV] of Object.entries(r.extra || {})) {
                      const key = k.trim();
                      const val = String(rawV || '').trim();
                      if (!key || !val) continue;
                      let bucket = extraMap.get(key);
                      if (!bucket) {
                        bucket = new Set<string>();
                        extraMap.set(key, bucket);
                      }
                      bucket.add(val);
                    }
                  }
                  const linkedExtra = Array.from(extraMap.entries()).map(([k, set]) => ({
                    key: k,
                    values: Array.from(set),
                  }));
                  if (
                    linkedIds.length === 0 &&
                    linkedUsers.length === 0 &&
                    linkedContacts.length === 0 &&
                    linkedSources.length === 0 &&
                    linkedNotes.length === 0 &&
                    linkedExtra.length === 0
                  ) {
                    return null;
                  }
                  return (
                    <div className="space-y-3 rounded-xl border border-slate-200 bg-white p-4 text-xs dark:border-slate-800 dark:bg-[#111827]">
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                        <div>
                          <div className="text-slate-500 dark:text-slate-400">Discord ID ({linkedIds.length})</div>
                          <div className="mt-1 font-mono text-blue-600 dark:text-blue-400">
                            {linkedIds.length > 0 ? linkedIds.join(', ') : '—'}
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-500 dark:text-slate-400">{t('Kullanıcı Adları', 'Usernames')} ({linkedUsers.length})</div>
                          <div className="mt-1 font-mono text-slate-900 dark:text-slate-100">
                            {linkedUsers.length > 0 ? linkedUsers.join(', ') : '—'}
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-500 dark:text-slate-400">{t('IP & Telefonlar', 'IPs & Phones')} ({linkedContacts.length})</div>
                          <div className="mt-1 font-mono text-slate-900 dark:text-slate-100">
                            {linkedContacts.length > 0 ? linkedContacts.join(', ') : '—'}
                          </div>
                        </div>
                        <div>
                          <div className="text-slate-500 dark:text-slate-400">{t('Kaynaklar', 'Sources')} ({linkedSources.length})</div>
                          <div className="mt-1 font-mono text-slate-900 dark:text-slate-100">
                            {linkedSources.length > 0 ? linkedSources.join(', ') : '—'}
                          </div>
                        </div>
                      </div>
                      {(linkedExtra.length > 0 || linkedNotes.length > 0) && (
                        <div className="border-t border-slate-200 pt-3 dark:border-slate-800">
                          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                            {t('Toplanan Tüm Ek Alanlar & Notlar', 'All Collected Extra Attributes & Notes')}
                          </div>
                          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
                            {linkedExtra.map((item) => (
                              <div
                                key={item.key}
                                className="rounded-lg border border-slate-200/80 bg-slate-50/70 px-3 py-1.5 dark:border-slate-800 dark:bg-slate-900/50"
                              >
                                <span className="font-semibold text-slate-600 dark:text-slate-400">{item.key}: </span>
                                <span className="break-all font-mono text-slate-900 dark:text-slate-100">
                                  {item.values.join(', ')}
                                </span>
                              </div>
                            ))}
                            {linkedNotes.length > 0 && (
                              <div className="rounded-lg border border-slate-200/80 bg-slate-50/70 px-3 py-1.5 dark:border-slate-800 dark:bg-slate-900/50 sm:col-span-2 lg:col-span-3">
                                <span className="font-semibold text-slate-600 dark:text-slate-400">{t('Notlar:', 'Notes:')} </span>
                                <span className="break-words font-mono text-slate-900 dark:text-slate-100">
                                  {linkedNotes.join(' · ')}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })()}
                <RecordTable
                  records={report.localMatches}
                  showDatasetName={isAdmin}
                  onPivotQuery={onPivotQuery}
                  onPivotEmail={(em) => void runScanForEmail(em)}
                  testId="email-osint-matches-table"
                />
              </div>
            ) : (
              <div className="rounded-xl border border-slate-200 bg-white p-5 text-xs text-slate-600 dark:border-slate-800 dark:bg-[#111827] dark:text-slate-400">
                {t('Bu e-posta adresine ait ek bir kayıt eşleşmesi bulunamadı.', 'No additional matched records found for this email.')}
              </div>
            )}
          </section>

          {report.pivotLinks.length > 0 && (
            <section className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-800 dark:bg-[#111827]">
              <h3 className="font-display text-sm font-semibold text-slate-900 dark:text-slate-100">
                {t('Ücretsiz Dış OSINT Portalları (QuadNet & Açık Kaynaklar)', 'Free External OSINT Portals (QuadNet & Open Sources)')}
              </h3>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                {t(
                  'Ek doğrulama için QuadNet, HaveIBeenPwned, LeakCheck, Epieos ve diğer OSINT araçlarında doğrudan sorgu açın',
                  'Launch direct searches across QuadNet, HaveIBeenPwned, LeakCheck, Epieos, and additional OSINT portals',
                )}
              </p>
              <div className="mt-3 flex flex-wrap gap-2.5">
                {report.pivotLinks.map((link) => (
                  <a
                    key={link.label}
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-800 transition-colors hover:border-blue-500 hover:text-blue-600 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-200 dark:hover:text-blue-400"
                  >
                    <span>{link.label}</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
