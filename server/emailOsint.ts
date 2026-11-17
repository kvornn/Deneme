import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import type { EmailOsintReport, EmailOsintSourceResult, IntelRecord } from '../src/types/intel.ts';
import { searchRecords, type SearchIndex } from '../src/utils/search.ts';
import { checkDisposableEmail } from './disposable.ts';

type Lang = 'tr' | 'en';

function detectMailProvider(mxHosts: string[], domain: string, lang: Lang): string {
  const joined = mxHosts.join(' ').toLowerCase();
  if (joined.includes('google') || joined.includes('gmail-smtp-in')) return 'Google / Gmail';
  if (joined.includes('outlook') || joined.includes('protection.outlook.com')) return 'Microsoft 365 / Outlook';
  if (joined.includes('protonmail') || joined.includes('proton.ch')) return 'Proton Mail';
  if (joined.includes('yandex')) return 'Yandex Mail';
  if (joined.includes('icloud') || joined.includes('me.com')) return 'Apple iCloud Mail';
  if (joined.includes('yahoodns')) return 'Yahoo Mail';
  if (joined.includes('zoho')) return 'Zoho Mail';
  if (joined.includes('fastmail')) return 'Fastmail';
  if (mxHosts.length > 0) return lang === 'tr' ? `Özel / Diğer (${mxHosts[0]})` : `Custom / Other (${mxHosts[0]})`;
  if (domain === 'example.test' || domain === 'demo.invalid') {
    return lang === 'tr' ? 'RFC-2606 Test Alan Adı' : 'RFC-2606 Test Domain';
  }
  return lang === 'tr' ? 'MX Kaydı Bulunamadı' : 'No MX Record Found';
}

async function fetchWithTimeout(
  url: string,
  headers: Record<string, string> = {},
  timeoutMs = 5000,
): Promise<Response> {
  return fetch(url, {
    headers: {
      'User-Agent': 'Sentarika-Archive-OSINT/1.0',
      Accept: 'application/json, text/plain;q=0.9',
      ...headers,
    },
    signal: AbortSignal.timeout(timeoutMs),
  });
}

async function checkXposedOrNot(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'XposedOrNot Sızıntı İndeksi' : 'XposedOrNot Breach Index';
  try {
    const url = `https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`;
    const res = await fetchWithTimeout(url, {}, 5200);
    if (res.status === 404) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'XposedOrNot genel indeksinde kayıtlı sızıntı bulunamadı.'
            : 'No breaches found in XposedOrNot public index.',
        details: {},
      };
    }
    if (!res.ok) {
      return {
        source: srcName,
        status: 'error',
        summary: `HTTP ${res.status}`,
        details: {},
      };
    }

    const data = (await res.json()) as {
      BreachesSummary?: { site?: string };
      BreachMetrics?: { risk?: Array<{ risk_label?: string; risk_score?: number }> } | null;
      ExposedBreaches?: {
        breaches_details?: Array<{
          breach?: string;
          domain?: string;
          xposed_date?: string;
          xposed_data?: string;
          xposed_records?: number;
          password_risk?: string;
        }>;
      } | null;
      ExposedPastes?: unknown;
    };

    const detailsList = data.ExposedBreaches?.breaches_details || [];
    const summarySites = (data.BreachesSummary?.site || '')
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean);

    if (detailsList.length === 0 && summarySites.length === 0) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'XposedOrNot genel indeksinde kayıtlı sızıntı bulunamadı.'
            : 'No breaches found in XposedOrNot public index.',
        details: {},
      };
    }

    const totalCount = Math.max(detailsList.length, summarySites.length);
    const exposedTypes = new Set<string>();
    const formattedBreaches = detailsList.slice(0, 15).map((b) => {
      if (b.xposed_data) {
        b.xposed_data
          .split(';')
          .map((x) => x.trim())
          .filter(Boolean)
          .forEach((x) => exposedTypes.add(x));
      }
      const parts = [b.breach || b.domain || ''];
      if (b.xposed_date) parts.push(`(${b.xposed_date})`);
      if (b.xposed_data) parts.push(`[${b.xposed_data}]`);
      return parts.filter(Boolean).join(' ');
    });

    const risk = data.BreachMetrics?.risk?.[0];
    const details: Record<string, string | string[]> = {};
    if (risk?.risk_label) {
      details[lang === 'tr' ? 'riskSkoru' : 'riskScore'] = `${risk.risk_label} (${risk.risk_score ?? 0}/100)`;
    }
    if (exposedTypes.size > 0) {
      details[lang === 'tr' ? 'sizdirilanVeriTurleri' : 'exposedDataTypes'] = Array.from(exposedTypes);
    }
    if (formattedBreaches.length > 0) {
      details[lang === 'tr' ? 'ihlalDetaylari' : 'breachDetails'] = formattedBreaches;
    } else if (summarySites.length > 0) {
      details[lang === 'tr' ? 'ihlalKaynaklari' : 'breaches'] = summarySites.slice(0, 20);
    }

    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `${totalCount} adet doğrulanmış veri ihlalinde tespit edildi.`
          : `Detected in ${totalCount} public data breaches.`,
      details,
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'Servise zaman aşımı nedeniyle ulaşılamadı.' : 'Service timed out.',
      details: {},
    };
  }
}

async function checkLeakCheckPublic(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'LeakCheck Genel Sızıntı DB' : 'LeakCheck Public Breach DB';
  try {
    const res = await fetchWithTimeout(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`,
      {},
      5000,
    );
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    const data = (await res.json()) as {
      success?: boolean;
      found?: number;
      fields?: string[];
      sources?: Array<{ name?: string; date?: string }>;
      error?: string;
    };
    const found = Number(data.found || 0);
    if (!data.success || found === 0) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'LeakCheck genel veri tabanında eşleşme bulunamadı.'
            : 'No matches found in LeakCheck public database.',
        details: {},
      };
    }
    const sourceList = (data.sources || [])
      .slice(0, 20)
      .map((s) => (s.date ? `${s.name || 'Kaynak'} (${s.date})` : String(s.name || 'Kaynak')));
    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `${found.toLocaleString('tr-TR')} sızıntı kaydı tespit edildi.`
          : `Found in ${found.toLocaleString('en-US')} leaked records.`,
      details: {
        ...(sourceList.length > 0 ? { [lang === 'tr' ? 'kaynaklar' : 'sources']: sourceList } : {}),
        ...(data.fields?.length ? { [lang === 'tr' ? 'sizdirilanAlanlar' : 'exposedFields']: data.fields } : {}),
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'LeakCheck servisine ulaşılamadı.' : 'Could not reach LeakCheck.',
      details: {},
    };
  }
}

async function checkHudsonRock(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = 'Hudson Rock Infostealer DB';
  try {
    const res = await fetchWithTimeout(
      `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${encodeURIComponent(email)}`,
      {},
      5000,
    );
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    const data = (await res.json()) as {
      message?: string;
      stealers?: Array<{
        date_compromised?: string;
        stealer_family?: string;
        computer_name?: string;
        operating_system?: string;
        malware_path?: string;
        antiviruses?: string[];
        ip?: string;
        top_logins?: string[];
        top_passwords?: string[];
        total_user_services?: number;
        total_corporate_services?: number;
      }>;
    };
    const stealers = Array.isArray(data.stealers) ? data.stealers : [];
    if (stealers.length === 0) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'Infostealer zararlı yazılım kayıtlarında bu e-posta görülmedi.'
            : 'No infostealer compromises associated with this email.',
        details: {},
      };
    }

    const isPresent = (val?: string) => Boolean(val && val !== 'Not Found');
    const logs = stealers.slice(0, 5).map((s, idx) => {
      const parts: string[] = [`#${idx + 1}`];
      if (s.date_compromised) parts.push(s.date_compromised.slice(0, 10));
      if (isPresent(s.stealer_family)) parts.push(`Stealer: ${s.stealer_family}`);
      if (isPresent(s.computer_name)) parts.push(`PC: ${s.computer_name}`);
      if (isPresent(s.operating_system)) parts.push(`OS: ${s.operating_system}`);
      if (isPresent(s.ip)) parts.push(`IP: ${s.ip}`);
      if (isPresent(s.malware_path)) parts.push(`Path: ${s.malware_path}`);
      if (Array.isArray(s.antiviruses) && s.antiviruses.length > 0) {
        parts.push(`AV: ${s.antiviruses.join(', ')}`);
      }
      if (typeof s.total_user_services === 'number') {
        parts.push(`UserSvc: ${s.total_user_services}`);
      }
      if (typeof s.total_corporate_services === 'number' && s.total_corporate_services > 0) {
        parts.push(`CorpSvc: ${s.total_corporate_services}`);
      }
      return parts.join(' | ');
    });

    const topLogins = Array.from(new Set(stealers.flatMap((s) => s.top_logins || []).filter(Boolean))).slice(0, 10);
    const topPasswords = Array.from(new Set(stealers.flatMap((s) => s.top_passwords || []).filter(Boolean))).slice(0, 10);

    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `${stealers.length} infostealer cihaz kaydında bu e-posta tespit edildi.`
          : `Detected in ${stealers.length} infostealer compromise logs.`,
      details: {
        [lang === 'tr' ? 'cihazKayitlari' : 'compromiseLogs']: logs,
        ...(topLogins.length > 0 ? { [lang === 'tr' ? 'iliskiliHesaplar' : 'topLogins']: topLogins } : {}),
        ...(topPasswords.length > 0 ? { [lang === 'tr' ? 'sifreOrnekleri' : 'topPasswords']: topPasswords } : {}),
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'Hudson Rock API zaman aşımı.' : 'Hudson Rock API timed out.',
      details: {},
    };
  }
}

async function checkProxyNovaComb(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'ProxyNova COMB Sızıntı İndeksi' : 'ProxyNova COMB Breach Index';
  try {
    const res = await fetchWithTimeout(
      `https://api.proxynova.com/comb?query=${encodeURIComponent(email)}`,
      {},
      5000,
    );
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    const data = (await res.json()) as { count?: number; lines?: string[] };
    const normalizedEmail = email.trim().toLowerCase();
    const rawLines = Array.isArray(data.lines) ? data.lines.map((l) => String(l).trim()).filter(Boolean) : [];
    // ProxyNova splits on '@' and returns domain/substring matches up to 10,000.
    // Keep strictly exact matches for the queried email so unrelated addresses never inflate results.
    const exactLines = rawLines.filter((line) => {
      const lower = line.toLowerCase();
      return lower === normalizedEmail || lower.startsWith(`${normalizedEmail}:`) || lower.startsWith(`${normalizedEmail};`);
    });

    if (exactLines.length === 0) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'Bu e-posta adresi için COMB arşivinde birebir eşleşen kayıt bulunamadı.'
            : 'No exact matching records found for this email in COMB archive.',
        details: {},
      };
    }

    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `COMB sızıntı arşivinde birebir eşleşen ${exactLines.length} kayıt bulundu.`
          : `Found ${exactLines.length} exact matching record(s) in COMB breach archive.`,
      details: {
        [lang === 'tr' ? 'birebirEslesenSayisi' : 'exactMatchCount']: String(exactLines.length),
        [lang === 'tr' ? 'kayitlar' : 'records']: exactLines,
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'ProxyNova COMB indeksine ulaşılamadı.' : 'Could not reach ProxyNova COMB index.',
      details: {},
    };
  }
}

async function checkProtonPgp(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'Proton / PGP Anahtar Dizini' : 'Proton / PGP Key Directory';
  try {
    const res = await fetchWithTimeout(
      `https://api.protonmail.ch/pks/lookup?op=index&search=${encodeURIComponent(email)}`,
      {},
      4200,
    );
    if (res.status === 404) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'Proton PGP anahtar sunucusunda kayıt bulunamadı.'
            : 'No key registered in Proton PGP directory.',
        details: {},
      };
    }
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    const text = await res.text();
    const pubLine = text.split('\n').find((l) => l.startsWith('pub:'));
    if (!pubLine) {
      return {
        source: srcName,
        status: 'not_found',
        summary: lang === 'tr' ? 'PGP anahtarı bulunamadı.' : 'No PGP key found.',
        details: {},
      };
    }
    const parts = pubLine.split(':');
    const createdTs = Number(parts[4] || 0);
    const createdIso = createdTs > 0 ? new Date(createdTs * 1000).toISOString().slice(0, 10) : '—';
    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `Doğrulanmış Proton / PGP açık anahtarı bulundu (Oluşturulma: ${createdIso}).`
          : `Verified Proton / PGP public key found (Created: ${createdIso}).`,
      details: {
        fingerprint: parts[1] || '',
        [lang === 'tr' ? 'olusturulma' : 'created']: createdIso,
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'Proton anahtar dizinine ulaşılamadı.' : 'Could not reach Proton keyserver.',
      details: {},
    };
  }
}

async function checkOpenPgp(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = 'OpenPGP Keyserver';
  try {
    const res = await fetchWithTimeout(
      `https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(email)}`,
      {},
      4000,
    );
    if (res.status === 404) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'OpenPGP genel anahtar sunucusunda kayıtlı anahtar yok.'
            : 'No public key found on keys.openpgp.org.',
        details: {},
      };
    }
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: {} };
    }
    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? 'OpenPGP üzerinde bu e-postaya bağlı herkese açık PGP anahtarı mevcut.'
          : 'Public PGP key is registered on OpenPGP for this email.',
      details: {
        url: `https://keys.openpgp.org/search?q=${encodeURIComponent(email)}`,
      },
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'OpenPGP sunucusu yanıt vermedi.' : 'OpenPGP server did not respond.',
      details: {},
    };
  }
}

async function checkGravatar(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'Gravatar Genel Profili' : 'Gravatar Public Profile';
  const hash = crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex');
  const md5 = crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex');
  try {
    const res = await fetchWithTimeout(`https://en.gravatar.com/${hash}.json`, {}, 4200);
    if (res.status === 404) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'Bu e-posta ile eşleşen Gravatar profili bulunamadı.'
            : 'No public Gravatar profile matched this email.',
        details: { sha256: hash, md5 },
      };
    }
    if (!res.ok) {
      return { source: srcName, status: 'error', summary: `HTTP ${res.status}`, details: { sha256: hash } };
    }
    const data = (await res.json()) as {
      entry?: Array<{
        displayName?: string;
        preferredUsername?: string;
        profileUrl?: string;
        currentLocation?: string;
        aboutMe?: string;
        emails?: Array<{ value?: string }>;
        phoneNumbers?: Array<{ value?: string; type?: string }>;
        accounts?: Array<{ shortname?: string; url?: string; username?: string }>;
        urls?: Array<{ title?: string; value?: string }>;
      }>;
    };
    const entry = data.entry?.[0];
    if (!entry) {
      return {
        source: srcName,
        status: 'not_found',
        summary: lang === 'tr' ? 'Gravatar profili boş döndü.' : 'Gravatar profile empty.',
        details: { sha256: hash, md5 },
      };
    }

    const details: Record<string, string | string[]> = {
      [lang === 'tr' ? 'gorunenAd' : 'displayName']: entry.displayName || '—',
      [lang === 'tr' ? 'kullaniciAdi' : 'username']: entry.preferredUsername || '—',
      profilUrl: entry.profileUrl || `https://gravatar.com/${hash}`,
    };
    if (entry.currentLocation) {
      details[lang === 'tr' ? 'konumAdres' : 'location'] = entry.currentLocation;
    }
    if (entry.aboutMe) {
      details[lang === 'tr' ? 'hakkimda' : 'bio'] = entry.aboutMe;
    }
    if (Array.isArray(entry.emails) && entry.emails.length > 0) {
      const ems = entry.emails.map((e) => e.value).filter(Boolean) as string[];
      if (ems.length > 0) details[lang === 'tr' ? 'epostalar' : 'emails'] = ems;
    }
    if (Array.isArray(entry.phoneNumbers) && entry.phoneNumbers.length > 0) {
      const phones = entry.phoneNumbers.map((p) => (p.type ? `${p.type}: ${p.value}` : p.value || '')).filter(Boolean);
      if (phones.length > 0) details[lang === 'tr' ? 'telefonlar' : 'phones'] = phones;
    }
    if (Array.isArray(entry.accounts) && entry.accounts.length > 0) {
      const accs = entry.accounts.map((a) => `${a.shortname || 'web'}: ${a.url || a.username || ''}`).filter(Boolean);
      if (accs.length > 0) details[lang === 'tr' ? 'sosyalHesaplar' : 'linkedAccounts'] = accs;
    }
    if (Array.isArray(entry.urls) && entry.urls.length > 0) {
      const urls = entry.urls.map((u) => (u.title ? `${u.title}: ${u.value}` : u.value || '')).filter(Boolean);
      if (urls.length > 0) details[lang === 'tr' ? 'baglantilar' : 'urls'] = urls;
    }

    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `Gravatar profili tespit edildi: ${entry.displayName || entry.preferredUsername || 'Profil Mevcut'}`
          : `Gravatar profile found: ${entry.displayName || entry.preferredUsername || 'Available'}`,
      details,
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'Gravatar API servisine ulaşılamadı.' : 'Could not reach Gravatar API.',
      details: { sha256: hash },
    };
  }
}

async function checkGitHub(email: string, lang: Lang): Promise<EmailOsintSourceResult> {
  const srcName = lang === 'tr' ? 'GitHub Genel Arama' : 'GitHub Public Search';
  try {
    const [usersRes, commitsRes] = await Promise.all([
      fetchWithTimeout(`https://api.github.com/search/users?q=${encodeURIComponent(`${email} in:email`)}`, {}, 4500),
      fetchWithTimeout(
        `https://api.github.com/search/commits?q=${encodeURIComponent(`author-email:${email}`)}&per_page=5`,
        { Accept: 'application/vnd.github+json' },
        4500,
      ).catch(() => null),
    ]);

    if (!usersRes.ok) {
      return {
        source: srcName,
        status: 'error',
        summary: `HTTP ${usersRes.status}`,
        details: {},
      };
    }

    const userData = (await usersRes.json()) as {
      total_count?: number;
      items?: Array<{ login: string; html_url: string }>;
    };

    const commitData = commitsRes?.ok
      ? ((await commitsRes.json()) as {
          total_count?: number;
          items?: Array<{
            html_url?: string;
            repository?: { full_name?: string };
            commit?: { author?: { name?: string; email?: string } };
          }>;
        })
      : null;

    const userItems = userData.items || [];
    const commitItems = commitData?.items || [];

    if ((!userData.total_count || userItems.length === 0) && (!commitData?.total_count || commitItems.length === 0)) {
      return {
        source: srcName,
        status: 'not_found',
        summary:
          lang === 'tr'
            ? 'Herkese açık GitHub profillerinde veya commit kayıtlarında bu e-posta eşleşmedi.'
            : 'No public GitHub profiles or commits matched this email.',
        details: {},
      };
    }

    // Enrich up to 5 matched GitHub profiles with full public metadata (email, location/address, company, blog, bio, twitter)
    const fullProfiles = await Promise.all(
      userItems.slice(0, 5).map(async (u) => {
        try {
          const profRes = await fetchWithTimeout(
            `https://api.github.com/users/${encodeURIComponent(u.login)}`,
            {},
            3500,
          );
          if (!profRes.ok) return { login: u.login, html_url: u.html_url };
          return (await profRes.json()) as {
            login: string;
            html_url: string;
            name?: string | null;
            email?: string | null;
            location?: string | null;
            company?: string | null;
            blog?: string | null;
            bio?: string | null;
            twitter_username?: string | null;
            public_repos?: number;
          };
        } catch {
          return { login: u.login, html_url: u.html_url };
        }
      }),
    );

    const formattedProfiles = fullProfiles.map((p) => {
      const fields: string[] = [`${p.login} (${p.html_url})`];
      if ('name' in p && p.name) fields.push(`${lang === 'tr' ? 'Ad' : 'Name'}: ${p.name}`);
      if ('email' in p && p.email) fields.push(`${lang === 'tr' ? 'Açık E-posta' : 'Public Email'}: ${p.email}`);
      if ('location' in p && p.location) fields.push(`${lang === 'tr' ? 'Konum/Adres' : 'Location'}: ${p.location}`);
      if ('company' in p && p.company) fields.push(`${lang === 'tr' ? 'Şirket' : 'Company'}: ${p.company}`);
      if ('blog' in p && p.blog) fields.push(`Web: ${p.blog}`);
      if ('twitter_username' in p && p.twitter_username) fields.push(`X/Twitter: @${p.twitter_username}`);
      if ('bio' in p && p.bio) fields.push(`Bio: ${p.bio}`);
      return fields.join(' | ');
    });

    const details: Record<string, string | string[]> = {};
    if (formattedProfiles.length > 0) {
      details[lang === 'tr' ? 'profiller' : 'profiles'] = formattedProfiles;
    }
    if (commitItems.length > 0) {
      details[lang === 'tr' ? 'acikCommitler' : 'publicCommits'] = commitItems.slice(0, 5).map((c) => {
        const repo = c.repository?.full_name || 'repo';
        const author = c.commit?.author?.name || '';
        const commitEmail = c.commit?.author?.email || '';
        return `${repo} — ${author} <${commitEmail}> (${c.html_url || ''})`;
      });
    }

    const totalMatched = Math.max(userData.total_count || 0, commitData?.total_count || 0);
    return {
      source: srcName,
      status: 'found',
      summary:
        lang === 'tr'
          ? `${totalMatched} açık GitHub eşleşmesi bulundu${userItems[0] ? ` (${userItems[0].login})` : ''}.`
          : `Matched ${totalMatched} public GitHub result(s)${userItems[0] ? ` (${userItems[0].login})` : ''}.`,
      details,
    };
  } catch {
    return {
      source: srcName,
      status: 'error',
      summary: lang === 'tr' ? 'GitHub API zaman aşımı.' : 'GitHub API timed out.',
      details: {},
    };
  }
}

async function checkRdap(domain: string): Promise<{
  registrar: string | null;
  createdDate: string | null;
  expiryDate: string | null;
} | null> {
  if (!domain || domain.endsWith('.test') || domain.endsWith('.invalid') || domain.endsWith('.local')) {
    return null;
  }
  try {
    const res = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {}, 4000);
    if (!res.ok) return null;
    const data = (await res.json()) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown[] }>;
    };
    const created = data.events?.find((e) => e.eventAction === 'registration')?.eventDate || null;
    const expiry = data.events?.find((e) => e.eventAction === 'expiration')?.eventDate || null;
    let registrar: string | null = null;
    const regEntity = data.entities?.find((en) => en.roles?.includes('registrar'));
    if (regEntity && Array.isArray(regEntity.vcardArray) && Array.isArray(regEntity.vcardArray[1])) {
      const fnEntry = (regEntity.vcardArray[1] as unknown[][]).find((row) => row[0] === 'fn');
      if (fnEntry && typeof fnEntry[3] === 'string') {
        registrar = fnEntry[3];
      }
    }
    return { registrar, createdDate: created, expiryDate: expiry };
  } catch {
    return null;
  }
}

export async function runEmailOsint(
  rawEmail: string,
  localRecords: IntelRecord[],
  lang: Lang = 'tr',
  prebuiltIndex?: SearchIndex,
): Promise<EmailOsintReport> {
  const started = performance.now();
  const email = rawEmail.trim().toLowerCase();
  const isValidSyntax = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
  const domain = email.includes('@') ? email.split('@')[1] || '' : '';

  const correlated = email ? searchRecords(localRecords, email, 'email', true, localRecords, prebuiltIndex) : null;
  const localMatchesMap = new Map<string, IntelRecord>();
  if (correlated) {
    for (const r of [...correlated.primaryMatches, ...correlated.relatedMatches]) {
      localMatchesMap.set(r.id, r);
    }
  }
  const localMatches = Array.from(localMatchesMap.values());

  if (!isValidSyntax || !domain) {
    return {
      email,
      domain,
      isValidSyntax: false,
      isDisposable: false,
      mailProvider: lang === 'tr' ? 'Geçersiz E-posta Biçimi' : 'Invalid Email Format',
      mxRecords: [],
      spfRecord: null,
      dmarcRecord: null,
      rdap: null,
      externalChecks: [],
      localMatches,
      pivotLinks: [],
      checkedAt: new Date().toISOString(),
      durationMs: Number((performance.now() - started).toFixed(2)),
    };
  }

  // Run all DNS checks, multi-layer temp-mail detection, and 8 free public OSINT APIs simultaneously
  const [
    mxRes,
    txtRes,
    dmarcRes,
    disposableRes,
    rdap,
    xon,
    leakCheck,
    hudsonRock,
    comb,
    protonPgp,
    openPgp,
    gravatar,
    github,
  ] = await Promise.all([
    dns.resolveMx(domain).catch(() => []),
    dns.resolveTxt(domain).catch(() => []),
    dns.resolveTxt(`_dmarc.${domain}`).catch(() => []),
    checkDisposableEmail(email).catch(() => null),
    checkRdap(domain),
    checkXposedOrNot(email, lang),
    checkLeakCheckPublic(email, lang),
    checkHudsonRock(email, lang),
    checkProxyNovaComb(email, lang),
    checkProtonPgp(email, lang),
    checkOpenPgp(email, lang),
    checkGravatar(email, lang),
    checkGitHub(email, lang),
  ]);

  const isDisposable = Boolean(disposableRes?.isDisposable);

  const mxRecords = [...mxRes]
    .sort((a, b) => a.priority - b.priority)
    .map((m) => ({ exchange: m.exchange, priority: m.priority }));

  const flatTxt = txtRes.map((chunks) => chunks.join(''));
  const spfRecord = flatTxt.find((t) => t.toLowerCase().startsWith('v=spf1')) || null;

  const flatDmarc = dmarcRes.map((chunks) => chunks.join(''));
  const dmarcRecord = flatDmarc.find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null;

  const mailProvider = detectMailProvider(
    mxRecords.map((m) => m.exchange),
    domain,
    lang,
  );

  const encodedEmail = encodeURIComponent(email);
  const encodedDomain = encodeURIComponent(domain);

  const pivotLinks = [
    { label: 'QuadNet OSINT', url: `https://quadnet.xyz/?q=${encodedEmail}` },
    { label: 'Have I Been Pwned', url: `https://haveibeenpwned.com/account/${encodedEmail}` },
    { label: 'LeakCheck', url: `https://leakcheck.io/` },
    { label: 'Epieos OSINT', url: `https://epieos.com/?q=${encodedEmail}` },
    { label: 'Hudson Rock Cavalier', url: `https://www.hudsonrock.com/free-tools` },
    { label: 'BreachDirectory', url: `https://breachdirectory.org/` },
    { label: 'IntelX Search', url: `https://intelx.io/?s=${encodedEmail}` },
    { label: 'DeHashed', url: `https://dehashed.com/search?query=${encodedEmail}` },
    { label: 'Hunter.io Domain', url: `https://hunter.io/search/${encodedDomain}` },
    { label: 'MXToolbox DNS/MX', url: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${encodedDomain}` },
  ];

  return {
    email,
    domain,
    isValidSyntax: true,
    isDisposable,
    mailProvider,
    mxRecords,
    spfRecord,
    dmarcRecord,
    rdap,
    externalChecks: [xon, leakCheck, hudsonRock, comb, protonPgp, openPgp, gravatar, github],
    localMatches,
    pivotLinks,
    checkedAt: new Date().toISOString(),
    durationMs: Math.max(1, Number((performance.now() - started).toFixed(2))),
  };
}
