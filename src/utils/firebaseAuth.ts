import { initializeApp, getApps } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup } from 'firebase/auth';
import firebaseConfig from '../../firebase-applet-config.json';

function getFirebaseAuth() {
  const app = getApps().length > 0 ? getApps()[0] : initializeApp(firebaseConfig);
  return getAuth(app);
}

export interface GooglePopupResult {
  idToken: string;
  email: string;
  displayName: string;
  uid: string;
}

export async function signInWithGooglePopup(lang: 'tr' | 'en' = 'tr'): Promise<GooglePopupResult> {
  const auth = getFirebaseAuth();
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });

  try {
    const credential = await signInWithPopup(auth, provider);
    const idToken = await credential.user.getIdToken(true);
    const email = (credential.user.email || '').trim().toLowerCase();
    const displayName = (credential.user.displayName || '').trim();
    const uid = credential.user.uid;

    if (!idToken || !email) {
      throw new Error(
        lang === 'tr'
          ? 'Google hesabından geçerli e-posta bilgisi alınamadı.'
          : 'Could not retrieve a valid email address from the Google account.',
      );
    }

    return { idToken, email, displayName, uid };
  } catch (err: unknown) {
    const code = (err as { code?: string })?.code || '';
    if (code === 'auth/popup-closed-by-user' || code === 'auth/cancelled-popup-request') {
      throw new Error(
        lang === 'tr'
          ? 'Google oturum açma penceresi kapatıldı.'
          : 'Google sign-in popup was closed.',
      );
    }
    if (code === 'auth/popup-blocked') {
      throw new Error(
        lang === 'tr'
          ? 'Tarayıcı açılır pencereyi engelledi. Lütfen popup izni verip tekrar deneyin.'
          : 'The browser blocked the sign-in popup. Please allow popups and try again.',
      );
    }
    throw err instanceof Error
      ? err
      : new Error(lang === 'tr' ? 'Google ile giriş başarısız oldu.' : 'Google sign-in failed.');
  }
}
