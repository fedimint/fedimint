import i18n from 'i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from 'react-i18next';
import { useTranslation } from 'react-i18next';

export const i18nProvider = (namespace: Array<any>) => {
  const resources = namespace.reduce((acc, lng) => {
  return {
    ...acc,
    [lng['key']]: { translation: lng['translation'] },
  }
}, {})

  i18n.use(LanguageDetector).use(initReactI18next).init({
    debug: true,
    resources,
    fallbackLng: 'en',
  });
};

export { useTranslation };
