import dns from 'node:dns/promises';

export const DISPOSABLE_DOMAINS = new Set([
  '10mail.org',
  '10minutemail.com',
  '10minutemail.net',
  '10minutemail.org',
  '1secmail.com',
  '1secmail.net',
  '1secmail.org',
  '20minutemail.com',
  '20minutemail.it',
  '33mail.com',
  'anonbox.net',
  'armyspy.com',
  'binkmail.com',
  'bobmail.info',
  'burnermail.io',
  'chammy.info',
  'crazymailing.com',
  'cuvox.de',
  'dayrep.com',
  'devnullmail.com',
  'discard.email',
  'discardmail.com',
  'discardmail.de',
  'disposable.com',
  'disposableaddress.com',
  'disposableemailaddresses.com',
  'disposableinbox.com',
  'disposablemail.com',
  'dispostable.com',
  'dodgit.com',
  'dpptd.com',
  'dropmail.me',
  'e4ward.com',
  'einrot.com',
  'emailfake.com',
  'emailias.com',
  'emailondeck.com',
  'emailtemporal.org',
  'esiix.com',
  'etempmail.com',
  'fakemail.fr',
  'fakemail.net',
  'fakemailgenerator.com',
  'filzmail.com',
  'fleckens.hu',
  'generator.email',
  'getairmail.com',
  'getnada.com',
  'gishpuppy.com',
  'gmailnator.com',
  'grr.la',
  'guerrillamail.biz',
  'guerrillamail.com',
  'guerrillamail.de',
  'guerrillamail.info',
  'guerrillamail.net',
  'guerrillamail.org',
  'guerrillamailblock.com',
  'gustr.com',
  'haltospam.com',
  'harakirimail.com',
  'hidemail.de',
  'incognitomail.org',
  'inboxbear.com',
  'inboxkitten.com',
  'internxt.com',
  'jourrapide.com',
  'kasmail.com',
  'klzlk.com',
  'knowledgemd.com',
  'laafd.com',
  'linshi-email.com',
  'lookugly.com',
  'luxusmail.org',
  'mail.gw',
  'mail.tm',
  'mailcatch.com',
  'maildrop.cc',
  'mailinator.com',
  'mailinator.net',
  'mailinator.org',
  'mailinator2.com',
  'mailnesia.com',
  'mailnull.com',
  'meltmail.com',
  'minimail.eu',
  'mintemail.com',
  'minuteinbox.com',
  'moakt.cc',
  'moakt.co',
  'moakt.com',
  'moakt.ws',
  'mohmal.com',
  'mohmal.im',
  'mohmal.in',
  'mohmal.tech',
  'mt2014.com',
  'mytemp.email',
  'nada.email',
  'nada.ltd',
  'neverbox.com',
  'no-spam.ws',
  'nowmymail.com',
  'objectmail.com',
  'obobbo.com',
  'oneoffemail.com',
  'onewaymail.com',
  'pokemail.net',
  'pookmail.com',
  'proxymail.eu',
  'rcpt.at',
  'recode.me',
  'recursor.net',
  'regbypass.com',
  'rhyta.com',
  'rteet.com',
  'safe-mail.net',
  'saynotospams.com',
  'selfdestructingmail.com',
  'sendspamhere.com',
  'sharklasers.com',
  'shiftmail.com',
  'shitmail.me',
  'skeefmail.com',
  'slopsbox.com',
  'smailpro.com',
  'smellfear.com',
  'snakemail.com',
  'soodonims.com',
  'spam4.me',
  'spamavert.com',
  'spambog.com',
  'spambog.de',
  'spambog.ru',
  'spambox.us',
  'spamcannon.com',
  'spamcon.org',
  'spamcorptastic.com',
  'spamcowboy.com',
  'spamday.com',
  'spamex.com',
  'spamfree24.org',
  'spamgourmet.com',
  'spamherelots.com',
  'spamhereplease.com',
  'spamhole.com',
  'spaml.com',
  'spammotel.com',
  'spamobox.com',
  'spamspot.com',
  'spamthis.co.uk',
  'supergreatmail.com',
  'superrito.com',
  'suremail.info',
  'teewars.org',
  'teleworm.us',
  'temp-inbox.com',
  'temp-mail.com',
  'temp-mail.de',
  'temp-mail.io',
  'temp-mail.org',
  'tempail.com',
  'tempemail.net',
  'tempinbox.com',
  'tempmail.com',
  'tempmail.de',
  'tempmail.it',
  'tempmail.net',
  'tempmail.org',
  'tempmail.plus',
  'tempmailaddress.com',
  'tempmailer.com',
  'tempmailo.com',
  'tempomail.fr',
  'temporaryemail.net',
  'temporaryforwarding.com',
  'temporaryinbox.com',
  'tempr.email',
  'thankyou2010.com',
  'thisisnotmyrealemail.com',
  'throwawaymail.com',
  'tmail.ws',
  'tmailor.com',
  'tmpmail.net',
  'tmpmail.org',
  'trash-mail.com',
  'trash2009.com',
  'trashemail.de',
  'trashmail.com',
  'trashmail.de',
  'trashmail.me',
  'trashmail.net',
  'trashymail.com',
  'txcct.com',
  'tyldd.com',
  'uggsrock.com',
  'upliftnow.com',
  'venompen.com',
  'veryrealemail.com',
  'viditag.com',
  'viewcastmedia.com',
  'vjuum.com',
  'webm4il.info',
  'wegwerfmail.de',
  'wegwerfmail.net',
  'wegwerfmail.org',
  'wh4f.org',
  'whyspam.me',
  'willselfdestruct.com',
  'wwjmp.com',
  'wuzup.net',
  'xents.com',
  'xojxe.com',
  'yapped.net',
  'yep.it',
  'yogamaven.com',
  'yoggm.com',
  'yopmail.com',
  'yopmail.fr',
  'yopmail.net',
  'yuurok.com',
  'zehnminutenmail.de',
  'zippymail.info',
  'zoemail.org',
]);

const DISPOSABLE_MX_KEYWORDS = [
  'mailinator',
  'guerrillamail',
  '1secmail',
  'yopmail',
  'tempmail',
  'temp-mail',
  'trashmail',
  'maildrop',
  'harakirimail',
  'discard.email',
  'wegwerfmail',
  'burnermail',
  'moakt',
  'mohmal',
  'dropmail',
  'mail.tm',
  'mail.gw',
  'spambog',
  'emailondeck',
  'fakemail',
  'sharklasers',
  'spam4.me',
  'tmailor',
];

export type DisposableDetector =
  | 'blocklist'
  | 'mx-pattern'
  | 'debounce-api'
  | 'kickbox-api'
  | 'reserved-domain'
  | 'no-mx'
  | 'clean';

export interface DisposableCheckResult {
  isDisposable: boolean;
  validMx: boolean;
  mxHosts: string[];
  detector: DisposableDetector;
  reason?: string;
}

const domainCache = new Map<string, { expiresAt: number; isDisposable: boolean; detector: DisposableDetector }>();

export function isDomainInDisposableBlocklist(domain: string): boolean {
  const clean = domain.trim().toLowerCase();
  if (!clean) return false;
  if (DISPOSABLE_DOMAINS.has(clean)) return true;
  const parts = clean.split('.');
  for (let i = 1; i < parts.length - 1; i += 1) {
    const parent = parts.slice(i).join('.');
    if (DISPOSABLE_DOMAINS.has(parent)) return true;
  }
  return false;
}

async function checkRemoteDisposableApis(
  email: string,
  domain: string,
): Promise<{ isDisposable: boolean; detector: DisposableDetector } | null> {
  const cached = domainCache.get(domain);
  if (cached && cached.expiresAt > Date.now()) {
    return { isDisposable: cached.isDisposable, detector: cached.detector };
  }

  const [debounceRes, kickboxRes] = await Promise.all([
    fetch(`https://disposable.debounce.io/?email=${encodeURIComponent(email)}`, {
      signal: AbortSignal.timeout(2600),
    })
      .then((r) => (r.ok ? (r.json() as Promise<{ disposable?: string | boolean }>) : null))
      .catch(() => null),
    fetch(`https://open.kickbox.com/v1/disposable/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(2600),
    })
      .then((r) => (r.ok ? (r.json() as Promise<{ disposable?: boolean }>) : null))
      .catch(() => null),
  ]);

  let isDisposable = false;
  let detector: DisposableDetector = 'clean';

  if (debounceRes && (debounceRes.disposable === true || debounceRes.disposable === 'true')) {
    isDisposable = true;
    detector = 'debounce-api';
  } else if (kickboxRes && kickboxRes.disposable === true) {
    isDisposable = true;
    detector = 'kickbox-api';
  }

  domainCache.set(domain, {
    expiresAt: Date.now() + 10 * 60 * 1000,
    isDisposable,
    detector,
  });

  return { isDisposable, detector };
}

export async function checkDisposableEmail(
  email: string,
  options: { skipNetwork?: boolean } = {},
): Promise<DisposableCheckResult> {
  const norm = email.trim().toLowerCase();
  const domain = norm.split('@')[1] || '';

  if (!domain) {
    return {
      isDisposable: false,
      validMx: false,
      mxHosts: [],
      detector: 'no-mx',
      reason: 'Geçersiz e-posta alan adı.',
    };
  }

  if (domain.endsWith('.test') || domain.endsWith('.invalid') || domain.endsWith('.local') || domain.endsWith('.example')) {
    return {
      isDisposable: true,
      validMx: false,
      mxHosts: [],
      detector: 'reserved-domain',
      reason: 'Test veya geçersiz alan adları kayıt için kabul edilmiyor.',
    };
  }

  if (isDomainInDisposableBlocklist(domain)) {
    return {
      isDisposable: true,
      validMx: false,
      mxHosts: [],
      detector: 'blocklist',
      reason: `Geçici / tek kullanımlık e-posta servisi (${domain}) engellendi.`,
    };
  }

  if (options.skipNetwork) {
    return {
      isDisposable: false,
      validMx: true,
      mxHosts: [],
      detector: 'clean',
    };
  }

  const [mxRecords, remoteResult] = await Promise.all([
    dns.resolveMx(domain).catch(() => []),
    checkRemoteDisposableApis(norm, domain).catch(() => null),
  ]);

  const mxHosts = mxRecords.map((m) => m.exchange.toLowerCase());
  const validMx = mxHosts.length > 0;

  if (mxHosts.some((host) => DISPOSABLE_MX_KEYWORDS.some((kw) => host.includes(kw)))) {
    return {
      isDisposable: true,
      validMx,
      mxHosts,
      detector: 'mx-pattern',
      reason: `Alan adı geçici e-posta (Temp Mail) MX altyapısı kullandığı için engellendi (${domain}).`,
    };
  }

  if (remoteResult?.isDisposable) {
    return {
      isDisposable: true,
      validMx,
      mxHosts,
      detector: remoteResult.detector,
      reason: `Geçici / tek kullanımlık e-posta servisi (${domain}) canlı doğrulama ile engellendi.`,
    };
  }

  if (!validMx) {
    return {
      isDisposable: false,
      validMx: false,
      mxHosts: [],
      detector: 'no-mx',
      reason: `${domain} alan adında geçerli posta (MX) sunucusu bulunamadı.`,
    };
  }

  return {
    isDisposable: false,
    validMx: true,
    mxHosts,
    detector: 'clean',
  };
}
