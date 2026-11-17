import { ShieldAlert } from 'lucide-react';
import { useI18n } from '../i18n/I18nContext';

export function LegalDisclaimerView() {
  const { t } = useI18n();

  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-[#111827] sm:p-8">
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-6 w-6 text-amber-500 shrink-0" />
          <h2 className="font-display text-xl font-bold text-slate-900 dark:text-slate-100">
            {t('Yasal Beyan ve Sorumluluk Reddi', 'Legal Disclaimer & Liability Notice')}
          </h2>
        </div>

        <div className="mt-5 space-y-4 text-sm leading-relaxed text-slate-700 dark:text-slate-300">
          <p>
            <strong>{t('1. Hizmetin Amacı:', '1. Purpose of Service:')}</strong>{' '}
            {t(
              'Sentarika Archive, yalnızca bir hesabın veya kimlik bilgisinin sızdırılmış ya da kamuya açık kayıtlarda yer alıp almadığını ("sızdırıldı / sızdırılmadı" durumunu) kontrol etmek ve teknik OSINT doğrulaması yapmak amacıyla sunulmaktadır.',
              'Sentarika Archive is provided solely to verify whether an account or identifier appears in leaked or public records ("exposed / not exposed") and to perform technical OSINT verification.',
            )}
          </p>
          <p>
            <strong>{t('2. Sorumluluk Reddi:', '2. Disclaimer of Liability:')}</strong>{' '}
            {t(
              'Kullanıcının sorguladığı verilerle ne yaptığı, bu bilgileri nasıl kullandığı, sakladığı veya paylaştığı platform yönetimini kesinlikle bağlamaz. Kullanıcıların gerçekleştirdiği işlemlerden doğabilecek hiçbir hukuki, idari veya cezai sonuçtan platform sorumluluk kabul etmez.',
              'How users handle, store, use, or distribute queried information does not bind the platform in any way. The platform assumes zero legal, administrative, or civil liability for any actions taken by its users.',
            )}
          </p>
          <p>
            <strong>{t('3. Güvenlik ve Kötüye Kullanım Önlemleri:', '3. Security & Anti-Abuse Measures:')}</strong>{' '}
            {t(
              'Platform, otomatik istek saldırılarına (DDoS / Flood) karşı hız sınırlama, oturum doğrulama ve kota denetimi ile korunmaktadır. Hız sınırlarını aşmaya çalışan, kötüye kullanım tespit edilen veya kurallara aykırı davranan kullanıcı hesapları yönetici tarafından kalıcı olarak yasaklanır.',
              'The platform enforces rate limiting, session verification, and daily quota controls against automated abuse (DDoS / floods). Accounts violating rules or attempting abuse may be permanently banned by administrators.',
            )}
          </p>
          <p>
            <strong>{t('4. Yetki ve Erişim Sınırları:', '4. Role & Access Boundaries:')}</strong>{' '}
            {t(
              'Standart kullanıcı rolleri (Üye, Destekçi, İşletme) yalnızca yönetici tarafından tanımlanan kota ve modül sınırları dahilinde sorgulama yapabilir.',
              'Standard user roles (Member, Supporter, Business) operate strictly within the quotas and module permissions configured by the administrator.',
            )}
          </p>
        </div>
      </section>
    </div>
  );
}
