export type LegalPage = "privacy" | "terms" | "security" | "support";
export type LegalLanguage = "tr" | "en";

interface LegalSection {
  heading: string;
  paragraphs: readonly string[];
}

interface LegalAction {
  href: string;
  label: string;
}

interface LegalPageCopy {
  title: string;
  introduction: string;
  sections: readonly LegalSection[];
  actions?: readonly LegalAction[];
}

interface LegalCopy {
  languageLabel: string;
  languageSwitchLabel: string;
  githubRepositoryLabel: string;
  navigationLabel: string;
  themeLabel: string;
  themeHelp: string;
  footerLabel: string;
  privacyLabel: string;
  termsLabel: string;
  securityLabel: string;
  supportLabel: string;
  pages: Record<LegalPage, LegalPageCopy>;
}

const GITHUB_REPOSITORY_URL = "https://github.com/muwat0/useMeter";
const GITHUB_ICON_HTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.48 2 2 6.59 2 12.26c0 4.53 2.87 8.37 6.84 9.73.5.1.68-.22.68-.49v-1.7c-2.78.62-3.37-1.21-3.37-1.21-.45-1.18-1.11-1.5-1.11-1.5-.91-.64.07-.63.07-.63 1 .08 1.53 1.05 1.53 1.05.9 1.59 2.35 1.13 2.92.86.09-.67.35-1.13.64-1.39-2.22-.26-4.56-1.15-4.56-5.09 0-1.12.39-2.04 1.03-2.76-.1-.26-.45-1.31.1-2.73 0 0 .84-.28 2.75 1.05a9.15 9.15 0 0 1 5.01 0c1.91-1.33 2.75-1.05 2.75-1.05.55 1.42.2 2.47.1 2.73.64.72 1.03 1.64 1.03 2.76 0 3.95-2.35 4.82-4.59 5.08.36.32.68.95.68 1.91v2.83c0 .27.18.6.69.49A10.28 10.28 0 0 0 22 12.26C22 6.59 17.52 2 12 2Z"/></svg>';

export const LEGAL_PAGE_PREFERENCE_SCRIPT = `(() => {
  const root = document.documentElement;
  const query = new URLSearchParams(window.location.search);
  const hasExplicitLanguage = query.has("lang");
  const requestedLanguage = query.get("lang");
  let savedLanguage = null;
  try { savedLanguage = window.localStorage.getItem("usage_lang"); } catch {}
  const language = hasExplicitLanguage
    ? (requestedLanguage === "en" ? "en" : "tr")
    : (savedLanguage === "tr" || savedLanguage === "en"
      ? savedLanguage
      : ((window.navigator.language || "").toLowerCase().startsWith("tr") ? "tr" : "en"));
  if (!hasExplicitLanguage && root.lang !== language) {
    const url = new URL(window.location.href);
    url.searchParams.set("lang", language);
    window.location.replace(url.toString());
    return;
  }
  try { window.localStorage.setItem("usage_lang", language); } catch {}
  let mode = "dark";
  try { if (window.localStorage.getItem("usage_mode") === "light") mode = "light"; } catch {}
  root.dataset.theme = mode;
  const accentColors = {
    amber: "#ff9849",
    emerald: "#10b981",
    cyan: "#06b6d4",
    violet: "#a855f7",
    slate: "#38bdf8"
  };
  try {
    const accent = accentColors[window.localStorage.getItem("usage_accent") || ""];
    if (accent) root.style.setProperty("--accent", accent);
  } catch {}
  window.addEventListener("DOMContentLoaded", () => {
    const toggle = document.getElementById("theme-toggle");
    if (!(toggle instanceof HTMLInputElement)) return;
    toggle.checked = mode === "light";
    toggle.addEventListener("change", () => {
      mode = toggle.checked ? "light" : "dark";
      root.dataset.theme = mode;
      try { window.localStorage.setItem("usage_mode", mode); } catch {}
    });
  });
})();`;

const LEGAL_COPY: Record<LegalLanguage, LegalCopy> = {
  tr: {
    languageLabel: "Dil seçimi",
    languageSwitchLabel: "Dili İngilizceye çevir",
    githubRepositoryLabel: "GitHub deposu",
    navigationLabel: "Yasal ve destek sayfaları",
    themeLabel: "Aydınlık tema",
    themeHelp: "Aydınlık temaya geç",
    footerLabel: "Bilgi sayfaları",
    privacyLabel: "Gizlilik",
    termsLabel: "Kullanım Koşulları",
    securityLabel: "Güvenlik",
    supportLabel: "Destek",
    pages: {
      privacy: {
        title: "Gizlilik",
        introduction: "useMeter kendi altyapınızda çalışır. Uygulama verilerinin saklandığı yer ve sunucuya, veritabanına ve yedeklere kimlerin erişebildiği dağıtımı yöneten operatöre bağlıdır.",
        sections: [
          {
            heading: "Saklanan veriler",
            paragraphs: [
              "Örneğiniz kullanıcı hesaplarını, bağlı sağlayıcı kimlik bilgilerini, tercihler ve kullanım anlık görüntüleri gibi uygulama verilerini yerel SQLite veritabanında saklar. Sunucu operatörü veritabanı dosyalarını ve yedeklerini korumaktan sorumludur.",
              "Sağlayıcı API anahtarları ve OAuth sırları AES-256-GCM ile şifrelenerek saklanır. Şifreleme anahtarı USAGE_MASTER_KEY değerinden türetilir. Bu, veritabanındaki tüm alanların veya yedeklerin şifreli olduğu anlamına gelmez; dosya ve yedek erişimini ayrıca koruyun.",
              "Parolalar Argon2id ile hash'lenir; oturum belirteçlerinin kendisi yerine hash'leri saklanır.",
            ],
          },
          {
            heading: "Saklama ve silme",
            paragraphs: [
              "Kullanım anlık görüntüleri varsayılan olarak 7 gün boyunca dönen bir geçmişte tutulur. En güncel anlık görüntü ve son başarılı anlık görüntü, kimlik bilgisi veya kullanıcı silinene ya da yeni bir anlık görüntüyle değiştirilene kadar 7 günden uzun süre saklanabilir. Sunucu operatörü SNAPSHOT_RETENTION_DAYS ayarıyla varsayılan süreyi değiştirebilir.",
              "Kimlik bilgisi veya hesap silme işlemleri ilişkili uygulama verilerini veritabanından siler. Daha önce alınmış yedekler uygulama veritabanından ayrı olarak operatörün yedek saklama ve silme uygulamalarına tabidir; uygulama içindeki silme işlemi yedeklerdeki veriyi hemen silmez.",
            ],
          },
          {
            heading: "Sağlayıcı istekleri ve veri paylaşımı",
            paragraphs: [
              "Kullanım verisi toplamak için kendi örneğiniz, bağladığınız sağlayıcıların API uç noktalarına istek gönderir; isteklere sağlayıcının verdiği erişim belirteci veya API anahtarı kimlik doğrulama bilgisi olarak eklenebilir. Sağlayıcılar bu istekleri kendi gizlilik ve kullanım koşullarına göre işler.",
            ],
          },
        ],
      },
      terms: {
        title: "Kullanım Koşulları",
        introduction: "useMeter, kendi sunucunuzda çalıştırmanız için kaynak kodu yayımlanan bir yazılım projesidir; merkezi olarak barındırılan bir kota veya faturalandırma hizmeti değildir.",
        sections: [
          {
            heading: "Garanti verilmez",
            paragraphs: [
              "Yazılım, yürürlükteki hukukun izin verdiği ölçüde açık veya zımni herhangi bir garanti olmaksızın, olduğu gibi sunulur. Her dağıtımın güvenliğini, kullanılabilirliğini, doğruluğunu veya belirli bir amaca uygunluğunu garanti etmiyoruz.",
              "Kaynak kodunun kullanımı, değiştirilmesi ve yeniden dağıtılması, kaynak deposuna eşlik eden lisans koşullarına tabidir. Bu bilgilendirme metni yeni bir lisans vermez veya mevcut lisansın kapsamını genişletmez.",
            ],
          },
          {
            heading: "Kota ve faturalandırma bilgileri",
            paragraphs: [
              "useMeter resmi veya bağlayıcı bir faturalandırma kaydı değildir. Görüntülenen değerler sağlayıcının erişilebilir kıldığı verilere dayanır; gecikebilir, eksik olabilir, değişebilir veya kullanılamayabilir. Faturalandırma ve plan kararları için sağlayıcının kendi kayıtlarını ve koşullarını esas alın.",
            ],
          },
          {
            heading: "Hesap ve kimlik bilgileri",
            paragraphs: [
              "Kendi örneğinizin güvenliğini, USAGE_MASTER_KEY değerinin ve yedeklerin korunmasını, sağlayıcı kimlik bilgilerinin yetkili kullanımını ve hesabınızdan yapılan işlemleri siz yönetirsiniz. Yalnızca kullanma yetkiniz olan sağlayıcı hesaplarını bağlayın; erişimi artık gerekmeyen kimlik bilgilerini silin.",
            ],
          },
        ],
      },
      security: {
        title: "Güvenlik",
        introduction: "useMeter'ın güvenliği, yazılım kontrolleri ile kendi sunucu ve işletim ortamınızın güvenliğine birlikte bağlıdır.",
        sections: [
          {
            heading: "Teknik kontroller",
            paragraphs: [
              "Sağlayıcı kimlik bilgisi sırları veritabanında AES-256-GCM ile şifrelenir. Kullanıcı parolaları Argon2id ile hash'lenir ve oturum belirteçleri veritabanında hash biçiminde tutulur. Kullanıcı verileri sahip kimliğiyle sınırlandırılır; kimlik bilgisi veya hesap silme işlemleri ilişkili kayıtları veritabanı kısıtlarıyla temizler.",
              "Şifreleme için kullanılan USAGE_MASTER_KEY, bu örneği çalıştıran operatörün sorumluluğundadır. Anahtarı ve sunucu/veritabanı yedeklerini erişim kontrollü biçimde saklayın. Anahtarın kaybı saklanan kimlik bilgilerini okunamaz hâle getirebilir; anahtara veya sunucuya erişim sahibi operatör gizli verilere erişebilir.",
            ],
          },
          {
            heading: "Güvenlik açığı bildirimi",
            paragraphs: [
              "Güvenlik açığı şüphenizi sorumlu biçimde bildirmek için örneği işleten Murat'a murat@muwat.org adresinden e-posta gönderebilirsiniz. Bu, en iyi çaba esaslı bir iletişim kanalıdır; izleme veya yanıt süresi garantisi yoktur. Etkilenen bileşeni, yeniden üretim adımlarını ve olası etkiyi paylaşın; gerçek kullanıcı verilerine erişmeyin, hizmeti aksatmayın ve düzeltme için makul süre tanımadan ayrıntıları kamuya açıklamayın.",
            ],
          },
        ],
        actions: [
          { href: "mailto:murat@muwat.org", label: "Güvenlik bildirimi için e-posta" },
        ],
      },
      support: {
        title: "Destek",
        introduction: "useMeter kendi sunucunuzda çalışır; örnek, ağ, yedek ve yapılandırma desteği öncelikle dağıtımı yöneten kişiye aittir. Proje desteği için e-posta birincil iletişim kanalıdır; en iyi çaba esaslıdır ve yanıt veya çözüm süresi garantisi yoktur.",
        sections: [
          {
            heading: "Hata bildirimi ve yardım",
            paragraphs: [
              "Sorun bildirirken useMeter sürümünü, ilgili sağlayıcıyı, beklenen ve gerçekleşen davranışı ve hassas olmayan hata ayrıntılarını ekleyin. Parola, API anahtarı, OAuth belirteci, e-posta veya kişisel kullanım verisi paylaşmayın.",
              "Proje desteği için murat@muwat.org adresine e-posta gönderin. GitHub sorunları deposuna erişiminiz varsa GitHub sorunlarını da kullanabilirsiniz; bu özel depo herkese açık bir topluluk destek kanalı değildir.",
            ],
          },
        ],
        actions: [
          { href: "mailto:murat@muwat.org", label: "Birincil destek: e-posta" },
          { href: "https://github.com/muwat0/useMeter/issues", label: "GitHub sorunları (depo erişimi gerekir)" },
        ],
      },
    },
  },
  en: {
    languageLabel: "Language selection",
    languageSwitchLabel: "Switch to Turkish",
    githubRepositoryLabel: "GitHub repository",
    navigationLabel: "Legal and support pages",
    themeLabel: "Light theme",
    themeHelp: "Switch to light theme",
    footerLabel: "Information pages",
    privacyLabel: "Privacy",
    termsLabel: "Terms",
    securityLabel: "Security",
    supportLabel: "Support",
    pages: {
      privacy: {
        title: "Privacy",
        introduction: "useMeter runs on infrastructure you control. Where application data is stored and who can access the server, database, and backups depend on the operator of that deployment.",
        sections: [
          {
            heading: "Data stored",
            paragraphs: [
              "Your instance stores user accounts, connected provider credentials, and application data such as preferences and usage snapshots in its local SQLite database. The server operator is responsible for protecting database files and backups.",
              "Provider API keys and OAuth secrets are encrypted at rest using AES-256-GCM. The encryption key is derived from USAGE_MASTER_KEY. This does not mean every database field or backup is encrypted; protect file and backup access separately.",
              "Passwords are hashed with Argon2id, and session token hashes are stored instead of the session tokens themselves.",
            ],
          },
          {
            heading: "Retention and deletion",
            paragraphs: [
              "Usage snapshots are kept in a rolling history of 7 days by default. The latest snapshot and the last successful snapshot may remain for longer than 7 days until replaced by a newer snapshot or the credential or user is deleted. The server operator can change the default period with SNAPSHOT_RETENTION_DAYS.",
              "Deleting a credential or account removes associated application data from the database. Previously created backups are separate and subject to the operator's backup retention and deletion practices; deleting data in the application does not immediately delete it from backups.",
            ],
          },
          {
            heading: "Provider requests and sharing",
            paragraphs: [
              "To collect usage data, your instance sends requests to the API endpoints of providers you connect; a provider-issued access token or API key may be included as authentication. Providers process those requests under their own privacy notices and terms.",
            ],
          },
        ],
      },
      terms: {
        title: "Terms of Use",
        introduction: "useMeter is a software project published as source code for you to run on your own infrastructure; it is not a centrally hosted quota or billing service.",
        sections: [
          {
            heading: "No warranty",
            paragraphs: [
              "The software is provided as is, without express or implied warranties, to the extent permitted by applicable law. We do not guarantee the security, availability, accuracy, or fitness for a particular purpose of any deployment.",
              "Use, modification, and redistribution of the source code are subject to the license terms accompanying the source repository. This notice does not grant a new license or expand the scope of an existing license.",
            ],
          },
          {
            heading: "Quota and billing information",
            paragraphs: [
              "useMeter is not an authoritative billing record. Displayed values depend on data made available by each provider and may be delayed, incomplete, changed, or unavailable. Rely on the provider's own records and terms for billing and plan decisions.",
            ],
          },
          {
            heading: "Accounts and credentials",
            paragraphs: [
              "You are responsible for securing your instance, protecting USAGE_MASTER_KEY and backups, using provider credentials only as authorized, and activity performed through your account. Connect only provider accounts you are authorized to use, and remove credentials when they are no longer needed.",
            ],
          },
        ],
      },
      security: {
        title: "Security",
        introduction: "useMeter security depends on both the software controls and the security of the server and operating environment you manage.",
        sections: [
          {
            heading: "Technical controls",
            paragraphs: [
              "Provider credential secrets are encrypted in the database using AES-256-GCM. User passwords are hashed with Argon2id, and session tokens are stored as hashes. User data is scoped by owner identity; deleting credentials or accounts removes related records through database constraints.",
              "The operator running an instance is responsible for USAGE_MASTER_KEY, which is used to derive the encryption key. Store the key and server/database backups with restricted access. Losing the key can make stored credentials unreadable; an operator with access to the key or server may access sensitive data.",
            ],
          },
          {
            heading: "Responsible disclosure",
            paragraphs: [
              "To report a suspected vulnerability responsibly, email Murat, the operator of this instance, at murat@muwat.org. This is a best-effort contact with no monitoring or response-time guarantee. Include the affected component, reproduction steps, and potential impact. Do not access real user data or disrupt services, and allow a reasonable time for remediation before public disclosure.",
            ],
          },
        ],
        actions: [
          { href: "mailto:murat@muwat.org", label: "Email for security reports" },
        ],
      },
      support: {
        title: "Support",
        introduction: "useMeter runs on your own server; deployment, networking, backups, and configuration are primarily the responsibility of the person operating that instance. Email is the primary project-support contact; it is best-effort, with no guaranteed response or resolution time.",
        sections: [
          {
            heading: "Bug reports and help",
            paragraphs: [
              "When reporting an issue, include the useMeter version, relevant provider, expected and actual behavior, and non-sensitive error details. Do not share passwords, API keys, OAuth tokens, email addresses, or personal usage data.",
              "For project support, email murat@muwat.org. You can also use GitHub issues if you have access to the repository; this private repository is not a public community-support channel.",
            ],
          },
        ],
        actions: [
          { href: "mailto:murat@muwat.org", label: "Primary support: email" },
          { href: "https://github.com/muwat0/useMeter/issues", label: "GitHub issues (repository access required)" },
        ],
      },
    },
  },
};


function renderNavigation(page: LegalPage, language: LegalLanguage, copy: LegalCopy): string {
  const links: readonly [LegalPage, string][] = [
    ["privacy", copy.privacyLabel],
    ["terms", copy.termsLabel],
    ["security", copy.securityLabel],
    ["support", copy.supportLabel],
  ];
  return links.map(([path, label]) =>
    `<a href="/${path}?lang=${language}"${path === page ? ' aria-current="page"' : ""}>${label}</a>`,
  ).join("");
}

export function renderLegalPageHtml(options: { page: LegalPage; lang?: LegalLanguage }): string {
  const language = options.lang ?? "tr";
  const copy = LEGAL_COPY[language];
  const page = copy.pages[options.page];
  const alternateLanguage: LegalLanguage = language === "tr" ? "en" : "tr";
  const languageFlag = language === "tr" ? "🇹🇷" : "🇬🇧";
  const sections = page.sections.map(section => `
      <section class="content-section">
        <h2>${section.heading}</h2>
        ${section.paragraphs.map(paragraph => `<p>${paragraph}</p>`).join("")}
      </section>`).join("");
  const actions = page.actions?.length
    ? `<div class="actions">${page.actions.map(action => `<a class="action-link" href="${action.href}">${action.label}<span aria-hidden="true"> ↗</span></a>`).join("")}</div>`
    : "";

  return `<!doctype html>
<html lang="${language}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="color-scheme" content="dark light">
  <title>${page.title} · useMeter</title>
  <script>${LEGAL_PAGE_PREFERENCE_SCRIPT}</script>
  <style>
    :root { color-scheme: dark; --page-bg:#090a0d; --surface:#111318; --border:#252a34; --muted:#171a21; --text:#f4f4f6; --text-muted:#a2a8b5; --accent:#ff9849; --accent-soft:rgba(255,152,73,.12); }
    :root[data-theme="light"],:root:has(#theme-toggle:checked) { color-scheme:light; --page-bg:#f7f8fb; --surface:#fff; --border:#e1e5ec; --muted:#f1f3f7; --text:#172033; --text-muted:#5e687a; --accent:#c45112; --accent-soft:rgba(196,81,18,.1); }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; display:flex; flex-direction:column; background:var(--page-bg); color:var(--text); font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; line-height:1.6; transition:background-color .18s ease,color .18s ease; }
    a { color:inherit; }
    .topbar { border-bottom:1px solid var(--border); background:var(--surface); }
    .topbar-inner { width:min(100% - 40px,1040px); min-height:68px; margin:0 auto; display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:20px; }
    .brand { color:var(--text); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:18px; font-weight:800; letter-spacing:.04em; text-decoration:none; white-space:nowrap; }
    .brand-group { display:flex; align-items:center; gap:10px; }
    .github-link { width:36px; height:36px; display:inline-flex; align-items:center; justify-content:center; border:1px solid var(--border); border-radius:9px; background:var(--surface); color:var(--text-muted); text-decoration:none; transition:color .18s,border-color .18s; }
    .github-link:hover,.github-link:focus-visible { border-color:var(--accent); color:var(--text); }
    .github-link:focus-visible { outline:2px solid var(--accent); outline-offset:3px; }
    .brand-accent { color:var(--accent); }
    .controls { display:flex; align-items:center; flex-wrap:wrap; justify-content:flex-end; gap:8px; }
    .control { min-height:36px; display:inline-flex; align-items:center; justify-content:center; gap:7px; padding:6px 10px; border:1px solid var(--border); border-radius:9px; background:var(--surface); color:var(--text-muted); font:inherit; font-size:12px; font-weight:650; text-decoration:none; cursor:pointer; }
    .control:hover,.control:focus-visible,.page-nav a:hover,.page-nav a:focus-visible,.action-link:hover,.action-link:focus-visible { border-color:var(--accent); color:var(--text); }
    .control:focus-visible,.page-nav a:focus-visible,.action-link:focus-visible { outline:2px solid var(--accent); outline-offset:3px; }
    .theme-switch { position:relative; }
    .theme-switch input { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; clip-path:inset(50%); }
    .theme-switch:has(input:focus-visible) { outline:2px solid var(--accent); outline-offset:3px; }
    main { flex:1; width:min(100% - 40px,760px); margin:0 auto; padding:clamp(38px,7vw,76px) 0 64px; }
    .eyebrow { margin:0 0 14px; color:var(--accent); font-size:11px; font-weight:750; letter-spacing:.12em; text-transform:uppercase; }
    h1 { margin:0; max-width:15ch; font-size:clamp(36px,7vw,58px); line-height:1.05; letter-spacing:-.045em; }
    .introduction { margin:22px 0 38px; color:var(--text-muted); font-size:clamp(16px,2.4vw,19px); line-height:1.7; }
    .content-section { padding:25px 0; border-top:1px solid var(--border); }
    h2 { margin:0 0 12px; font-size:19px; line-height:1.35; letter-spacing:-.015em; }
    .content-section p { margin:10px 0 0; color:var(--text-muted); font-size:15px; line-height:1.8; }
    .content-section p:first-of-type { margin-top:0; }
    .actions { display:flex; flex-wrap:wrap; gap:10px; padding:24px 0 6px; }
    .action-link { min-height:42px; display:inline-flex; align-items:center; padding:9px 13px; border:1px solid var(--border); border-radius:10px; background:var(--surface); color:var(--accent); font-size:13px; font-weight:700; text-decoration:none; }
    .page-footer { border-top:1px solid var(--border); }
    .footer-inner { width:min(100% - 40px,1040px); min-height:66px; margin:0 auto; display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:12px 24px; padding:14px 0; color:var(--text-muted); font-size:12px; }
    .page-nav { display:flex; flex-wrap:wrap; gap:8px 18px; }
    .page-nav a { color:var(--text-muted); text-decoration:none; }
    .page-nav a[aria-current="page"] { color:var(--text); font-weight:700; }
    @media (max-width:560px) { .topbar-inner,.footer-inner { width:min(100% - 28px,1040px); } .topbar-inner { min-height:62px; gap:10px; } .theme-label { display:none; } main { width:min(100% - 32px,760px); padding-top:40px; } .footer-inner { align-items:flex-start; flex-direction:column; } }
    @media (prefers-reduced-motion:reduce) { *,*::before,*::after { scroll-behavior:auto !important; transition:none !important; } }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand-group">
        <a class="brand" href="/" aria-label="useMeter">use<span class="brand-accent">Meter</span></a>
        <a class="github-link" href="${GITHUB_REPOSITORY_URL}" aria-label="${copy.githubRepositoryLabel}" title="${copy.githubRepositoryLabel}">${GITHUB_ICON_HTML}</a>
      </div>
      <div class="controls">
        <label class="control theme-switch" title="${copy.themeHelp}">
          <input id="theme-toggle" type="checkbox" aria-label="${copy.themeHelp}">
          <span aria-hidden="true">☼</span><span class="theme-label">${copy.themeLabel}</span>
        </label>
        <nav aria-label="${copy.languageLabel}">
          <a class="control" href="/${options.page}?lang=${alternateLanguage}" lang="${alternateLanguage}" hreflang="${alternateLanguage}" aria-label="${copy.languageSwitchLabel}" title="${copy.languageSwitchLabel}">
            <span aria-hidden="true">${languageFlag}</span><span>${language.toUpperCase()}</span>
          </a>
        </nav>
      </div>
    </div>
  </header>
  <main>
    <p class="eyebrow">useMeter · ${copy.navigationLabel}</p>
    <h1>${page.title}</h1>
    <p class="introduction">${page.introduction}</p>
    ${sections}
    ${actions}
  </main>
  <footer class="page-footer">
    <div class="footer-inner">
      <span>${copy.footerLabel}</span>
      <nav class="page-nav" aria-label="${copy.navigationLabel}">${renderNavigation(options.page, language, copy)}</nav>
    </div>
  </footer>
</body>
</html>`;
}
