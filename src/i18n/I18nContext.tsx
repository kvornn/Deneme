import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

export type Language = 'tr' | 'en';

interface I18nContextValue {
  lang: Language;
  setLang: (next: Language) => void;
  toggleLang: () => void;
  t: (tr: string, en: string) => string;
}

const LANG_STORAGE_KEY = 'sentarika_lang';

function detectInitialLanguage(): Language {
  try {
    const saved = localStorage.getItem(LANG_STORAGE_KEY);
    if (saved === 'tr' || saved === 'en') return saved;
  } catch {
    // Ignore storage access errors
  }
  if (typeof navigator !== 'undefined') {
    const navLang = (navigator.language || '').toLowerCase();
    return navLang.startsWith('tr') ? 'tr' : 'en';
  }
  return 'tr';
}

const I18nContext = createContext<I18nContextValue>({
  lang: 'tr',
  setLang: () => {},
  toggleLang: () => {},
  t: (tr) => tr,
});

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Language>(detectInitialLanguage);

  const setLang = (next: Language) => {
    setLangState(next);
    try {
      localStorage.setItem(LANG_STORAGE_KEY, next);
    } catch {
      // Ignore storage errors
    }
  };

  const toggleLang = () => {
    setLang(lang === 'tr' ? 'en' : 'tr');
  };

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = lang;
    }
  }, [lang]);

  const t = (tr: string, en: string) => (lang === 'tr' ? tr : en);

  return (
    <I18nContext.Provider value={{ lang, setLang, toggleLang, t }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n(): I18nContextValue {
  return useContext(I18nContext);
}
