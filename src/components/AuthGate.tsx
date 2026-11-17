import { useState, type FormEvent } from 'react';
import { ShieldAlert, KeyRound, LogIn, UserPlus, Moon, Sun, AlertCircle, X, Languages, CheckCircle2 } from 'lucide-react';
import type { PublicUser } from '../types/intel';
import { useI18n } from '../i18n/I18nContext';
import {
  apiAdminLogin,
  apiGoogleAuth,
  apiGoogleRegister,
  apiLogin,
} from '../utils/api';
import { signInWithGooglePopup } from '../utils/firebaseAuth';

interface AuthGateProps {
  onAuthenticated: (token: string, user: PublicUser) => void;
  isDark: boolean;
  onToggleTheme: () => void;
}

function GoogleLogo() {
  return (
    <svg className="h-4 w-4 shrink-0" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17Z"
      />
      <path
        fill="#34A853"
        d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.11-6.72-4.96H1.29v3.14C3.26 21.3 7.31 24 12 24Z"
      />
      <path
        fill="#FBBC05"
        d="M5.28 14.24c-.24-.72-.38-1.49-.38-2.24s.14-1.52.38-2.24V6.62H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.38l3.99-3.14Z"
      />
      <path
        fill="#EA4335"
        d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.62l3.99 3.14c.95-2.85 3.6-4.96 6.72-4.96Z"
      />
    </svg>
  );
}

export function AuthGate({ onAuthenticated, isDark, onToggleTheme }: AuthGateProps) {
  const { lang, toggleLang, t } = useI18n();
  const [mode, setMode] = useState<'login' | 'register' | 'google_setup'>('login');
  const [loginUsername, setLoginUsername] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [acceptedTerms, setAcceptedTerms] = useState(false);

  const [pendingGoogle, setPendingGoogle] = useState<{
    idToken: string;
    email: string;
    displayName: string;
  } | null>(null);

  const [adminModalOpen, setAdminModalOpen] = useState(false);
  const [adminKey, setAdminKey] = useState('');
  const [adminError, setAdminError] = useState<string | null>(null);
  const [adminLoading, setAdminLoading] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const handleGoogleContinue = async () => {
    setError(null);
    setGoogleLoading(true);
    try {
      const popup = await signInWithGooglePopup(lang);
      const res = await apiGoogleAuth(popup.idToken);
      if (res.status === 'authenticated') {
        onAuthenticated(res.token, res.user);
        return;
      }
      setPendingGoogle({
        idToken: popup.idToken,
        email: res.email,
        displayName: res.displayName,
      });
      setUsername(res.suggestedUsername);
      setPassword('');
      setAcceptedTerms(false);
      setMode('google_setup');
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Google oturumu açılamadı.', 'Google sign-in failed.'));
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (mode === 'login') {
        const res = await apiLogin({ username: loginUsername.trim(), password });
        onAuthenticated(res.token, res.user);
      } else if (mode === 'google_setup' && pendingGoogle) {
        const res = await apiGoogleRegister({
          idToken: pendingGoogle.idToken,
          username,
          password,
          acceptedTerms,
        });
        onAuthenticated(res.token, res.user);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t('İşlem başarısız.', 'Operation failed.'));
    } finally {
      setLoading(false);
    }
  };

  const handleAdminSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setAdminError(null);
    setAdminLoading(true);
    try {
      const res = await apiAdminLogin(adminKey);
      onAuthenticated(res.token, res.user);
    } catch (err) {
      setAdminError(err instanceof Error ? err.message : t('Yönetici girişi başarısız.', 'Admin login failed.'));
    } finally {
      setAdminLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col bg-slate-50 text-slate-900 dark:bg-[#0B0F17] dark:text-slate-100">
      <header className="flex h-16 items-center justify-between gap-3 border-b border-slate-200 bg-white px-3.5 dark:border-slate-800 dark:bg-[#0F1521] sm:px-6">
        <span className="truncate font-display text-base font-bold tracking-tight text-slate-900 dark:text-slate-100 sm:text-lg">
          Sentarika Archive
        </span>
        <div className="flex shrink-0 items-center gap-1.5 sm:gap-2.5">
          <button
            type="button"
            onClick={toggleLang}
            data-testid="auth-lang-toggle"
            aria-label={t('İngilizceye geç', 'Switch to Turkish')}
            className="inline-flex h-8 items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-200 dark:hover:bg-slate-800 sm:h-9 sm:gap-1.5 sm:px-2.5"
          >
            <Languages className="h-3.5 w-3.5" />
            <span>{lang.toUpperCase()}</span>
          </button>
          <button
            type="button"
            onClick={onToggleTheme}
            aria-label={isDark ? t('Açık temaya geç', 'Switch to light theme') : t('Koyu temaya geç', 'Switch to dark theme')}
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800/70 dark:text-slate-200 dark:hover:bg-slate-800 sm:h-9 sm:w-9"
          >
            {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <button
            type="button"
            onClick={() => {
              setAdminError(null);
              setAdminModalOpen(true);
            }}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-2.5 text-xs font-semibold text-slate-800 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700 whitespace-nowrap sm:h-9 sm:gap-2 sm:px-3.5"
          >
            <KeyRound className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400" />
            <span>{t('Admin Girişi', 'Admin Login')}</span>
          </button>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col justify-center gap-8 px-4 py-10 lg:flex-row lg:items-stretch">
        <section className="flex flex-1 flex-col justify-between rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-[#111827] sm:p-8">
          <div className="space-y-4">
            <h1 className="font-display text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 sm:text-3xl">
              {t('Sentarika Archive — Discord ID & OSINT Paneli', 'Sentarika Archive — Discord ID & OSINT Panel')}
            </h1>
            <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">
              {t(
                'Kayıt işlemleri yalnızca Google hesabınızla doğrulanır: Google hesabınızı seçip kullanıcı adınızı ve şifrenizi belirleyerek hemen katılabilirsiniz. Mevcut hesabınıza Google hesabınızla veya belirlediğiniz kullanıcı adı ve şifreyle giriş yapabilirsiniz. Geçici (temp-mail) e-posta girişimleri engellenir ve her yeni hesap ',
                'Registration is verified exclusively with your Google Account: choose your Google Account, set your username and password, and join immediately. Existing members can sign in with Google or their username and password. Disposable email domains are blocked automatically, and every new account starts with the ',
              )}
              <strong className="font-semibold text-slate-900 dark:text-slate-200">
                {t('Üye', 'Member')}
              </strong>
              {t(' rolüyle başlar.', ' role.')}
            </p>
          </div>

          <div className="mt-6 rounded-lg border border-amber-200 bg-amber-50/70 p-4 text-xs leading-relaxed text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/25 dark:text-amber-200">
            <div className="flex items-center gap-2 font-semibold">
              <ShieldAlert className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <span>{t('Yasal Beyan ve Sorumluluk Reddi', 'Legal Disclaimer & Liability Notice')}</span>
            </div>
            <p className="mt-1.5">
              {t(
                'Bu platform yalnızca bir bilginin sızdırılmış/paylaşılmış kayıtlarda yer alıp almadığını sunmak amacıyla hizmet verir. Kullanıcının sorguladığı verilerle ne yapacağı, bunları nasıl kullanacağı veya paylaşacağı platformumuzu hiçbir şekilde bağlamaz; doğabilecek hiçbir sonuçtan sorumluluk kabul edilmez.',
                'This platform solely indicates whether an identifier appears in exposed or public breach records. How users utilize or share queried outputs is entirely their own responsibility; the platform assumes zero liability.',
              )}
            </p>
          </div>
        </section>

        <section className="w-full rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-[#111827] sm:p-8 lg:w-[420px] shrink-0">
          <div className="flex rounded-lg bg-slate-100 p-1 dark:bg-slate-800/80">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setPendingGoogle(null);
                setError(null);
              }}
              className={`flex-1 rounded-md py-2 text-xs font-semibold transition-colors ${
                mode === 'login'
                  ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
              }`}
            >
              {t('Giriş Yap', 'Sign In')}
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setPendingGoogle(null);
                setError(null);
              }}
              className={`flex-1 rounded-md py-2 text-xs font-semibold transition-colors ${
                mode === 'register' || mode === 'google_setup'
                  ? 'bg-white text-slate-900 shadow-xs dark:bg-slate-700 dark:text-white'
                  : 'text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white'
              }`}
            >
              {t('Kayıt Ol (Üye)', 'Register (Member)')}
            </button>
          </div>

          {mode === 'login' && (
            <>
              <div className="mt-5">
                <button
                  type="button"
                  data-testid="google-signin-button"
                  onClick={handleGoogleContinue}
                  disabled={googleLoading || loading}
                  className="inline-flex w-full items-center justify-center gap-2.5 rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-800 shadow-2xs transition-colors hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800"
                >
                  <GoogleLogo />
                  <span>
                    {googleLoading
                      ? t('Google hesabı bağlanıyor...', 'Connecting Google Account...')
                      : t('Google Hesabı ile Giriş Yap', 'Sign in with Google')}
                  </span>
                </button>

                <div className="my-4 flex items-center gap-3">
                  <div className="h-px flex-1 bg-slate-200 dark:bg-slate-800" />
                  <span className="text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    {t('veya şifre ile', 'or with password')}
                  </span>
                  <div className="h-px flex-1 bg-slate-200 dark:bg-slate-800" />
                </div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label htmlFor="login-username" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    {t('Kullanıcı Adı', 'Username')}
                  </label>
                  <input
                    id="login-username"
                    type="text"
                    required
                    minLength={3}
                    maxLength={32}
                    autoComplete="username"
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    placeholder={t('kullanici_adi', 'username')}
                    className="mt-1.5 w-full rounded-lg border border-slate-300 bg-slate-50 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  />
                </div>

                <div>
                  <label htmlFor="auth-password" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                    {t('Şifre', 'Password')}
                  </label>
                  <input
                    id="auth-password"
                    type="password"
                    required
                    minLength={8}
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={t('En az 8 karakter', 'At least 8 characters')}
                    className="mt-1.5 w-full rounded-lg border border-slate-300 bg-slate-50 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                  />
                </div>

                {error && (
                  <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                    <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{error}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading || googleLoading}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
                >
                  <LogIn className="h-4 w-4" />
                  <span>{loading ? t('İşleniyor...', 'Processing...') : t('Giriş Yap', 'Sign In')}</span>
                </button>
              </form>
            </>
          )}

          {mode === 'register' && (
            <div className="mt-5 space-y-4">
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-xs leading-relaxed text-slate-600 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-300">
                <p className="font-semibold text-slate-900 dark:text-slate-100">
                  {t('Google Hesabı ile Güvenli Kayıt', 'Secure Registration with Google Account')}
                </p>
                <p className="mt-1.5">
                  {t(
                    'Yeni üyeliklerde elle e-posta yazılmaz. Google hesabınızı seçtikten hemen sonra kullanıcı adınızı ve şifrenizi belirleyerek doğrulama kodu beklemeden panele giriş yapabilirsiniz.',
                    'Manual email entry is disabled. Select your Google Account, then set your username and password to enter immediately without verification codes.',
                  )}
                </p>
              </div>

              {error && (
                <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="button"
                data-testid="google-signin-button"
                onClick={handleGoogleContinue}
                disabled={googleLoading || loading}
                className="inline-flex w-full items-center justify-center gap-2.5 rounded-lg border border-slate-300 bg-white px-4 py-3 text-sm font-semibold text-slate-800 shadow-2xs transition-colors hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800"
              >
                <GoogleLogo />
                <span>
                  {googleLoading
                    ? t('Google hesabı bağlanıyor...', 'Connecting Google Account...')
                    : t('Google Hesabı ile Kayıt Ol', 'Register with Google Account')}
                </span>
              </button>
            </div>
          )}

          {mode === 'google_setup' && pendingGoogle && (
            <form onSubmit={handleSubmit} className="mt-5 space-y-4">
              <div className="rounded-lg border border-emerald-200 bg-emerald-50/70 p-3 text-xs text-emerald-900 dark:border-emerald-900/50 dark:bg-emerald-950/30 dark:text-emerald-200">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-semibold">
                    <CheckCircle2 className="h-4 w-4 shrink-0" />
                    <span>{t('Google Hesabı Seçildi', 'Google Account Selected')}</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleGoogleContinue}
                    className="text-[11px] font-medium underline hover:opacity-80"
                  >
                    {t('Değiştir', 'Switch')}
                  </button>
                </div>
                <p className="mt-1 font-mono text-[11px]">{pendingGoogle.email}</p>
              </div>

              <div>
                <label htmlFor="google-username" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  {t('Kullanıcı Adınızı Belirleyin', 'Choose Your Username')}
                </label>
                <input
                  id="google-username"
                  type="text"
                  required
                  minLength={3}
                  maxLength={32}
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={t('kullanici_adi', 'username')}
                  className="mt-1.5 w-full rounded-lg border border-slate-300 bg-slate-50 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                />
              </div>

              <div>
                <label htmlFor="google-password" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  {t('Hesap Şifrenizi Belirleyin', 'Set Account Password')}
                </label>
                <input
                  id="google-password"
                  type="password"
                  required
                  minLength={8}
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t('En az 8 karakter', 'At least 8 characters')}
                  className="mt-1.5 w-full rounded-lg border border-slate-300 bg-slate-50 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                />
              </div>

              <label className="flex cursor-pointer items-start gap-2.5 text-xs text-slate-600 dark:text-slate-400">
                <input
                  type="checkbox"
                  checked={acceptedTerms}
                  onChange={(e) => setAcceptedTerms(e.target.checked)}
                  className="mt-0.5 h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500 dark:border-slate-600 dark:bg-slate-800"
                />
                <span>
                  {t(
                    'Platformun yalnızca sızdırılma durumu kontrolü sunduğunu ve kullanıcı eylemlerinden sorumluluk kabul etmediğini belirten Yasal Beyanı onaylıyorum.',
                    'I accept the Legal Disclaimer confirming the platform only reports exposure status and assumes no liability for user actions.',
                  )}
                </span>
              </label>

              {error && (
                <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={loading || googleLoading}
                className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-700 disabled:opacity-50"
              >
                <UserPlus className="h-4 w-4" />
                <span>{loading ? t('İşleniyor...', 'Processing...') : t('Hesabı Oluştur ve Giriş Yap', 'Create Account & Sign In')}</span>
              </button>
            </form>
          )}
        </section>
      </main>

      {adminModalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="admin-login-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4 backdrop-blur-xs"
        >
          <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-[#111827]">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 dark:border-slate-800">
              <h2 id="admin-login-title" className="font-display text-base font-semibold text-slate-900 dark:text-slate-100">
                {t('Admin Anahtarı ile Giriş', 'Admin Key Sign In')}
              </h2>
              <button
                type="button"
                onClick={() => setAdminModalOpen(false)}
                aria-label={t('Admin giriş penceresini kapat', 'Close admin sign in')}
                className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleAdminSubmit} className="mt-4 space-y-4">
              <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-400">
                {t(
                  'Veri deposu yükleme, veritabanını inceleme, kullanıcı doğrulama/yasaklama ve rol haklarını yönetme yetkisi yalnızca 30 haneli anahtara sahip Admin hesabındadır.',
                  'Uploading datasets, inspecting the database, verifying/banning users, and managing role permissions are strictly restricted to the 30-digit Admin key.',
                )}
              </p>

              <div>
                <label htmlFor="admin-key-input" className="block text-xs font-medium text-slate-700 dark:text-slate-300">
                  {t('30 Haneli Yönetici Anahtarı', '30-Digit Admin Key')}
                </label>
                <input
                  id="admin-key-input"
                  type="password"
                  required
                  value={adminKey}
                  onChange={(e) => setAdminKey(e.target.value)}
                  placeholder={t('30 haneli sayısal anahtarı yapıştırın', 'Paste the 30-digit numeric key')}
                  className="mt-1.5 w-full rounded-lg border border-slate-300 bg-slate-50 px-3.5 py-2.5 font-mono text-sm text-slate-900 placeholder:font-sans placeholder:text-slate-400 focus:border-blue-500 focus:bg-white focus:outline-none dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                />
              </div>

              {adminError && (
                <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{adminError}</span>
                </div>
              )}

              <div className="flex items-center justify-end gap-2.5">
                <button
                  type="button"
                  onClick={() => setAdminModalOpen(false)}
                  className="rounded-lg border border-slate-200 px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                >
                  {t('İptal', 'Cancel')}
                </button>
                <button
                  type="submit"
                  disabled={adminLoading}
                  className="rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
                >
                  {adminLoading ? t('Doğrulanıyor...', 'Verifying...') : t('Yönetici Girişi Yap', 'Sign In as Admin')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
