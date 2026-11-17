import fs from 'node:fs';
import path from 'node:path';

interface FirebaseClientConfig {
  projectId: string;
  apiKey: string;
}

export interface VerifiedGoogleIdentity {
  uid: string;
  email: string;
  displayName: string;
  emailVerified: boolean;
}

let cachedConfig: FirebaseClientConfig | null = null;

function getFirebaseConfig(): FirebaseClientConfig {
  if (cachedConfig) return cachedConfig;
  const configPath = path.resolve(process.cwd(), 'firebase-applet-config.json');
  const raw = fs.readFileSync(configPath, 'utf8');
  const parsed = JSON.parse(raw) as Partial<FirebaseClientConfig>;
  if (!parsed.projectId || !parsed.apiKey) {
    throw new Error('Firebase yapılandırması eksik.');
  }
  cachedConfig = {
    projectId: parsed.projectId,
    apiKey: parsed.apiKey,
  };
  return cachedConfig;
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function verifyFirebaseGoogleToken(idToken: string): Promise<VerifiedGoogleIdentity> {
  const cleanToken = idToken.trim();
  if (!cleanToken) {
    throw new Error('Google kimlik doğrulama belirteci boş.');
  }

  const config = getFirebaseConfig();
  const claims = decodeJwtPayload(cleanToken);
  if (!claims) {
    throw new Error('Geçersiz Google kimlik belirteci biçimi.');
  }

  const expectedIss = `https://securetoken.google.com/${config.projectId}`;
  const expMs = typeof claims.exp === 'number' ? claims.exp * 1000 : 0;
  if (claims.aud !== config.projectId || claims.iss !== expectedIss || !claims.sub || expMs <= Date.now()) {
    throw new Error('Google oturum belirteci geçersiz veya süresi dolmuş.');
  }

  const lookupUrl = `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(config.apiKey)}`;
  const resp = await fetch(lookupUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken: cleanToken }),
    signal: AbortSignal.timeout(8000),
  });

  if (!resp.ok) {
    throw new Error('Google kimlik doğrulama servisi belirteci reddetti.');
  }

  const data = (await resp.json()) as {
    users?: Array<{
      localId?: string;
      email?: string;
      emailVerified?: boolean;
      displayName?: string;
    }>;
  };

  const account = data.users?.[0];
  if (!account || !account.localId || !account.email) {
    throw new Error('Google hesap bilgileri doğrulanamadı.');
  }

  if (!account.emailVerified) {
    throw new Error('Google hesabınızın e-posta adresi doğrulanmamış.');
  }

  return {
    uid: account.localId,
    email: account.email.trim().toLowerCase(),
    displayName: (account.displayName || '').trim(),
    emailVerified: Boolean(account.emailVerified),
  };
}
