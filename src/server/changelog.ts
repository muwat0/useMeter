import { APP_VERSION } from "../version";
import { LEGAL_PAGE_PREFERENCE_SCRIPT } from "./legal-pages";

export type ChangelogLanguage = "tr" | "en";
export type ChangeCategory = "added" | "fixed" | "security" | "changed" | "operations";

export interface ChangeEntry {
  category: ChangeCategory;
  titleTr: string;
  titleEn: string;
  descriptionTr?: string;
  descriptionEn?: string;
}

export interface ReleaseEntry {
  version: string;
  dateTr: string;
  dateEn: string;
  tagUrl?: string;
  commitHash?: string;
  isLatest?: boolean;
  summaryTr: string;
  summaryEn: string;
  changes: readonly ChangeEntry[];
}

export const CHANGELOG_RELEASES: readonly ReleaseEntry[] = [
  {
    version: "v1.0.0",
    dateTr: "12 Kasım 2026",
    dateEn: "November 12, 2026",
    tagUrl: "https://github.com/muwat0/useMeter/releases/tag/v1.0.0",
    commitHash: "0026977",
    isLatest: true,
    summaryTr: "İlk kararlı genel sürüm: Dış REST API (PAT), çok kanallı bildirim motoru, 17 sağlayıcı adaptörü, AES-256-GCM şifreli kasa ve SemVer sürüm takip sistemi.",
    summaryEn: "Initial stable production release: External REST API (PAT), multi-channel notification engine, 17 provider adapters, AES-256-GCM encrypted vault, and SemVer release tagging.",
    changes: [
      {
        category: "added",
        titleTr: "Dış REST API ve Kişisel Erişim Anahtarları (PAT)",
        titleEn: "External REST API & Personal Access Tokens (PAT)",
        descriptionTr: "Waybar, Polybar, tmux ve terminal script'leri için optimize edilmiş /api/v1/summary, /api/v1/usage ve /api/v1/poll uç noktaları; SHA-256 hash'li token yönetimi.",
        descriptionEn: "Optimized /api/v1/summary, /api/v1/usage, and /api/v1/poll endpoints with SHA-256 hashed token management for desktop status bars (Waybar, Polybar, tmux) and automation.",
      },
      {
        category: "added",
        titleTr: "Çok Kanallı Kota ve Sıfırlanma Bildirimleri",
        titleEn: "Multi-Channel Quota & Reset Notification System",
        descriptionTr: "ntfy mobil push, Telegram Botu, Discord Webhook ve genel JSON Webhook kanalları üzerinden %50-%95 eşik uyarıları, kota tükenmesi ve kayan pencere sıfırlanma alarmları.",
        descriptionEn: "Real-time alerts via ntfy mobile push, Telegram Bot, Discord Webhook, and JSON Webhooks for percentage thresholds (50%–95%), exhaustion, and rolling quota resets.",
      },
      {
        category: "added",
        titleTr: "17 Yapay Zekâ Sağlayıcı Adaptörü",
        titleEn: "17 Normalized AI Provider Adapters",
        descriptionTr: "Claude, OpenAI Codex, Google Antigravity & Gemini, GitHub Copilot, Cursor, OpenRouter, DeepSeek, Kimi Code ve daha fazlası için aktif kota ve bakiye telemetrisi.",
        descriptionEn: "Active polling and unified telemetry for Claude, OpenAI Codex, Google Antigravity & Gemini, GitHub Copilot, Cursor, OpenRouter, DeepSeek, Kimi Code, and more.",
      },
      {
        category: "added",
        titleTr: "Çok Kullanıcılı Mimari & Oturum Kimlik Doğrulaması",
        titleEn: "Multi-Tenant Architecture & Session Authentication",
        descriptionTr: "Argon2id parola hashleme, durumlu oturum yönetimi, güvenli davet bağlantılarıyla onboarding ve tam kiracı izolasyonu.",
        descriptionEn: "Argon2id password hashing, stateful session tokens, secure invitation-based onboarding, and strict per-user tenant isolation.",
      },
      {
        category: "added",
        titleTr: "Modern React Panosu & Gruvbox Temaları",
        titleEn: "Modern React Dashboard & Gruvbox Themes",
        descriptionTr: "Gruvbox Material Hard Dark ve Light temaları, hassas bakiye gizleme modu, sürükle-bırak kart sıralaması ve Türkçe / İngilizce tam yerelleştirme.",
        descriptionEn: "Gruvbox Material Hard Dark and Light themes, sensitive balance privacy mode, drag-and-drop card ordering, and full Turkish / English localization.",
      },
      {
        category: "security",
        titleTr: "AES-256-GCM ile Veritabanı Şifreleme (Şema v2)",
        titleEn: "AES-256-GCM Encrypted Vault at Rest (Schema v2)",
        descriptionTr: "Tüm sağlayıcı kimlik bilgileri, API anahtarları ve OAuth token metadata'sı SQLite üzerinde AES-256-GCM zarflarıyla fail-closed şifrelenir.",
        descriptionEn: "All stored provider secrets, API keys, and OAuth metadata envelopes are encrypted at rest inside SQLite with AES-256-GCM authenticated encryption.",
      },
      {
        category: "security",
        titleTr: "Sertleştirilmiş Güvenlik Çevresi",
        titleEn: "Hardened Security Perimeter & Headers",
        descriptionTr: "Sıkı Content Security Policy (CSP), HTTP Strict Transport Security (HSTS) ve varsayılan same-origin CORS politikası.",
        descriptionEn: "Strict Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), and same-origin CORS origin validation.",
      },
      {
        category: "security",
        titleTr: "Sınırlı Hız Koruması (Rate Limiting)",
        titleEn: "Bounded Token-Bucket Rate Limiting",
        descriptionTr: "Kimlik doğrulama, genel kayıt, dış API okumaları ve manuel yoklama uç noktalarında bellek içi hız sınırlama koruması.",
        descriptionEn: "In-memory token-bucket rate limiting applied across login, public registration, external API reads, and manual poll endpoints.",
      },
      {
        category: "fixed",
        titleTr: "Split-Horizon DNS & ntfy Yerel Yönlendirmesi",
        titleEn: "Split-Horizon DNS & ntfy Loopback Routing",
        descriptionTr: "Docker konteynerinden yerel split-horizon loopback adreslerine erişim, orijinal Host/SNI başlığı korunarak Docker ağ geçidine yönlendirildi.",
        descriptionEn: "Container requests resolving to split-horizon loopback addresses are transparently routed to the Docker host gateway while preserving original host/SNI headers.",
      },
      {
        category: "fixed",
        titleTr: "Discord Webhook Görünür Metin ve Token Budama Onarımı",
        titleEn: "Discord Webhook Visible Content Text & Token Fix",
        descriptionTr: "Salt embed önizlemesi kapalı kanallarda mesajların kaybolmaması için görünür content metni eklendi; webhook URL'sindeki 35 karakterlik hasarlı budama kaldırıldı.",
        descriptionEn: "Added visible content text for channels with restricted embed previews, and removed the 35-character URL truncation defect.",
      },
      {
        category: "fixed",
        titleTr: "OpenRouter Deprecated Kota Filtrelemesi",
        titleEn: "OpenRouter Deprecated Quota Telemetry Filtering",
        descriptionTr: "Resmî olarak kullanımdan kaldırılmış -1 request limit satırının panoda gösterilmesi engellendi; harcanan USD bakiyesi netleştirildi.",
        descriptionEn: "Suppressed officially deprecated -1 legacy rate-limit telemetry and aligned spending display with active prepaid balances.",
      },
      {
        category: "operations",
        titleTr: "SemVer Docker İmaj ve Geri Dönüş Standardı",
        titleEn: "SemVer Docker Image & Rollback Standard",
        descriptionTr: "Yayın imajları doğrudan usemeter:vX.Y.Z olarak etiketlenir; her dağıtımda usemeter:rollback-pre-vX.Y.Z ile anında geri dönüş güvencesi sağlanır.",
        descriptionEn: "Release images are tagged as usemeter:vX.Y.Z with instant rollback pins (usemeter:rollback-pre-vX.Y.Z) and permanent historical version retention.",
      },
      {
        category: "operations",
        titleTr: "Otomatik SQLite WAL Yedekleme & Geri Yükleme Tatbikatı",
        titleEn: "Automated SQLite WAL Backup & Restore Drills",
        descriptionTr: "Canlı veritabanını kilitlemeden SQLite VACUUM INTO ile WAL-tutarlı anlık görüntü alan systemd servisi ve izole restore drill doğrulaması.",
        descriptionEn: "Host-local systemd automated WAL-consistent SQLite snapshots via SQLite VACUUM INTO with offline restore drill verification.",
      },
    ],
  },
  {
    version: "v0.9.0",
    dateTr: "16 Ekim 2026",
    dateEn: "October 16, 2026",
    tagUrl: "https://github.com/muwat0/useMeter/commit/c5889b6",
    commitHash: "c5889b6",
    summaryTr: "Gizlilik modu, yasal bilgi sayfaları, host sağlık izleme servisi ve OpenRouter canlı telemetri entegrasyonu.",
    summaryEn: "Sensitive balance privacy masking, legal information pages, host health monitoring service, and OpenRouter telemetry.",
    changes: [
      {
        category: "added",
        titleTr: "Hassas Bakiye Gizlilik Modu (Göz İkonu)",
        titleEn: "Sensitive Balance Privacy Mode",
        descriptionTr: "Pano başlığındaki göz ikonuyla tüm parasal tutarlar •••••• olarak maskelenir; yüzde kotaları görünür kalır ve tercih tarayıcıda kalıcı saklanır.",
        descriptionEn: "Header eye toggle masks monetary amounts as •••••• while keeping percentage quotas readable; preference persists in localStorage.",
      },
      {
        category: "added",
        titleTr: "Yasal ve Destek Bilgi Sayfaları",
        titleEn: "Legal & Support Information Pages",
        descriptionTr: "Gizlilik (/privacy), Kullanım Koşulları (/terms), Güvenlik (/security) ve Destek (/support) sayfaları SSR HTML olarak eklendi.",
        descriptionEn: "Server-rendered /privacy, /terms, /security, and /support pages added with shared theme and language switching.",
      },
      {
        category: "fixed",
        titleTr: "Açık Tema Düğmesi Senkronizasyonu",
        titleEn: "Light Theme Switcher Synchronization",
        descriptionTr: "Açık temada statik kalan 'Light theme' etiketi, ikon ve aria öznitelikleri iki yönlü senkronize edildi.",
        descriptionEn: "Synchronized next-action label, icon, and accessibility attributes in both directions across all locales.",
      },
      {
        category: "operations",
        titleTr: "usemeter-monitor Host İzleme Servisi",
        titleEn: "usemeter-monitor Host Operational Service",
        descriptionTr: "Disk doluluk oranı (%90+) veya /health yanıtı bozulduğunda operatöre anında e-posta uyarısı ileten bağımsız Python servisi.",
        descriptionEn: "Host-local Python service checking disk usage (>=90%) and /health endpoint, triggering operator alert emails upon incidents.",
      },
    ],
  },
  {
    version: "v0.8.0",
    dateTr: "27 Eylül 2026",
    dateEn: "September 27, 2026",
    tagUrl: "https://github.com/muwat0/useMeter/commit/4277c8e",
    commitHash: "4277c8e",
    summaryTr: "Kimi Code adaptörü, düzenleme modunda kalıcı hesap silme ve AES-256-GCM v2 şema geçiş mimarisi.",
    summaryEn: "Kimi Code provider adapter, permanent account deletion in edit mode, and AES-256-GCM schema v2 migration.",
    changes: [
      {
        category: "added",
        titleTr: "Moonshot Kimi Code Sağlayıcı Adaptörü",
        titleEn: "Moonshot Kimi Code Provider Adapter",
        descriptionTr: "Kimi Code 5 saatlik kayan pencere ve 7 günlük kota telemetrisi ayrıştırıcı adaptörü.",
        descriptionEn: "Official Kimi Code usage parser for 5-hour rolling and 7-day quota windows.",
      },
      {
        category: "added",
        titleTr: "Düzenleme Modunda Hesap Kaldırma",
        titleEn: "Account Removal in Edit Mode",
        descriptionTr: "Pano üzerinden bağlı hesapların ve geçmiş kullanım snapshot'larının tek tıkla kalıcı silinmesi.",
        descriptionEn: "Permanent deletion of connected credentials and associated usage snapshots directly from the dashboard.",
      },
      {
        category: "security",
        titleTr: "İki Aşamalı Şema v2 Kasa Geçişi",
        titleEn: "Two-Phase Schema v2 Vault Migration",
        descriptionTr: "Kesintisiz ve güvenli şifreleme geçişi sağlayan çift okuyuculu (dual-reader) geçiş protokolü.",
        descriptionEn: "Dual-reader transitional release enabling safe zero-downtime v1 -> v2 encrypted metadata migration.",
      },
    ],
  },
];

const GITHUB_REPO_URL = "https://github.com/muwat0/useMeter";

const CATEGORY_LABELS: Record<ChangelogLanguage, Record<ChangeCategory, { label: string; class: string }>> = {
  tr: {
    added: { label: "Eklendi", class: "badge-added" },
    fixed: { label: "Düzeltildi", class: "badge-fixed" },
    security: { label: "Güvenlik", class: "badge-security" },
    changed: { label: "Değişiklik", class: "badge-changed" },
    operations: { label: "Altyapı & Ops", class: "badge-ops" },
  },
  en: {
    added: { label: "Added", class: "badge-added" },
    fixed: { label: "Fixed", class: "badge-fixed" },
    security: { label: "Security", class: "badge-security" },
    changed: { label: "Change", class: "badge-changed" },
    operations: { label: "Operations", class: "badge-ops" },
  },
};

export function renderChangelogPageHtml(options: { lang?: ChangelogLanguage }): string {
  const lang = options.lang ?? "tr";
  const isTr = lang === "tr";
  const alternateLanguage: ChangelogLanguage = isTr ? "en" : "tr";
  const languageFlag = isTr ? "🇹🇷" : "🇬🇧";

  const t = {
    title: isTr ? "Sürüm Notları (Changelog)" : "Release Notes (Changelog)",
    eyebrow: isTr ? "useMeter · Sürüm Notları" : "useMeter · Release Notes",
    lead: isTr
      ? "useMeter'daki en son yenilikler, özellikler ve düzeltmelerden haberdar olun! İlk günden bugüne dek yapay zekâ kotalarınızı güvenle yönetebilmeniz için sürekli geliştiriyoruz."
      : "Stay up to date with the latest changes to useMeter! From the first commit to the latest release, we are continuously refining your self-hosted AI quota hub.",
    backToDashboard: isTr ? "← Panoya Dön" : "← Back to Dashboard",
    allReleasesGitHub: isTr ? "GitHub Sürümleri ↗" : "GitHub Releases ↗",
    reportIssue: isTr ? "Hata Bildir ↗" : "Report an Issue ↗",
    latestBadge: isTr ? "En Güncel Sürüm" : "Latest Release",
    releaseLabel: isTr ? "Sürüm" : "Release",
    themeLabel: isTr ? "Açık tema" : "Light theme",
    darkThemeLabel: isTr ? "Koyu tema" : "Dark theme",
    themeHelp: isTr ? "Açık temaya geç" : "Switch to light theme",
    darkThemeHelp: isTr ? "Koyu temaya geç" : "Switch to dark theme",
    footerText: isTr ? "Bilgi ve destek sayfaları" : "Information and support pages",
    privacy: isTr ? "Gizlilik" : "Privacy",
    terms: isTr ? "Kullanım Koşulları" : "Terms",
    security: isTr ? "Güvenlik" : "Security",
    support: isTr ? "Destek" : "Support",
    changelog: isTr ? "Sürüm Notları" : "Changelog",
    feedbackNotice: isTr
      ? "Bir hata veya beklenmedik durumla karşılaşırsanız lütfen GitHub üzerinden bildirin."
      : "If you encounter any issues, please report them on the GitHub issues page.",
  };

  const releasesHtml = CHANGELOG_RELEASES.map(rel => {
    const date = isTr ? rel.dateTr : rel.dateEn;
    const summary = isTr ? rel.summaryTr : rel.summaryEn;
    const isCurrentActive = rel.version === `v${APP_VERSION}`;

    const changesHtml = rel.changes
      .map(change => {
        const cat = CATEGORY_LABELS[lang][change.category];
        const title = isTr ? change.titleTr : change.titleEn;
        const desc = isTr ? change.descriptionTr : change.descriptionEn;

        return `
          <div class="change-item">
            <div class="badge-col">
              <span class="badge ${cat.class}">${cat.label}</span>
            </div>
            <div class="change-body">
              <div class="change-title">${title}</div>
              ${desc ? `<div class="change-desc">${desc}</div>` : ""}
            </div>
          </div>
        `;
      })
      .join("");

    return `
      <article class="release-card${rel.isLatest ? " release-latest" : ""}" id="${rel.version}">
        <div class="release-header">
          <div class="release-title-row">
            <h2 class="release-version">${rel.version}</h2>
            ${rel.isLatest ? `<span class="badge badge-latest">${t.latestBadge}</span>` : ""}
            ${isCurrentActive && !rel.isLatest ? `<span class="badge badge-active">${rel.version} (Active)</span>` : ""}
          </div>
          <div class="release-meta">
            <time class="release-date">${date}</time>
            <span class="meta-separator">•</span>
            ${rel.tagUrl ? `<a href="${rel.tagUrl}" class="meta-link" target="_blank" rel="noreferrer">GitHub Release ↗</a>` : ""}
            ${rel.commitHash ? `<span class="meta-separator">•</span><span class="meta-commit">#${rel.commitHash}</span>` : ""}
          </div>
        </div>

        <p class="release-summary">${summary}</p>

        <div class="changes-list">
          ${changesHtml}
        </div>
      </article>
    `;
  }).join("");

  return `<!doctype html>
<html lang="${lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta name="color-scheme" content="dark light">
  <title>${t.title} · useMeter</title>
  <script>${LEGAL_PAGE_PREFERENCE_SCRIPT}</script>
  <style>
    :root {
      color-scheme: dark;
      --page-bg: #090a0d;
      --surface: #111318;
      --surface-elevated: #161a22;
      --border: #252a34;
      --border-accent: rgba(255, 152, 73, 0.4);
      --muted: #171a21;
      --text: #f4f4f6;
      --text-muted: #a2a8b5;
      --text-subtle: #6c7280;
      --accent: #ff9849;
      --accent-soft: rgba(255, 152, 73, 0.12);

      --badge-added-bg: rgba(16, 185, 129, 0.12);
      --badge-added-text: #34d399;
      --badge-added-border: rgba(16, 185, 129, 0.3);

      --badge-fixed-bg: rgba(245, 158, 11, 0.12);
      --badge-fixed-text: #fbbf24;
      --badge-fixed-border: rgba(245, 158, 11, 0.3);

      --badge-sec-bg: rgba(244, 63, 94, 0.12);
      --badge-sec-text: #fb7185;
      --badge-sec-border: rgba(244, 63, 94, 0.3);

      --badge-changed-bg: rgba(168, 85, 247, 0.12);
      --badge-changed-text: #c084fc;
      --badge-changed-border: rgba(168, 85, 247, 0.3);

      --badge-ops-bg: rgba(59, 130, 246, 0.12);
      --badge-ops-text: #60a5fa;
      --badge-ops-border: rgba(59, 130, 246, 0.3);
    }
    :root[data-theme="light"], :root:has(#theme-toggle:checked) {
      color-scheme: light;
      --page-bg: #f7f8fb;
      --surface: #ffffff;
      --surface-elevated: #f1f3f7;
      --border: #e1e5ec;
      --border-accent: rgba(196, 81, 18, 0.4);
      --muted: #f1f3f7;
      --text: #172033;
      --text-muted: #5e687a;
      --text-subtle: #8b95a5;
      --accent: #c45112;
      --accent-soft: rgba(196, 81, 18, 0.1);

      --badge-added-bg: rgba(16, 185, 129, 0.1);
      --badge-added-text: #047857;
      --badge-added-border: rgba(16, 185, 129, 0.3);

      --badge-fixed-bg: rgba(245, 158, 11, 0.1);
      --badge-fixed-text: #b45309;
      --badge-fixed-border: rgba(245, 158, 11, 0.3);

      --badge-sec-bg: rgba(244, 63, 94, 0.1);
      --badge-sec-text: #be123c;
      --badge-sec-border: rgba(244, 63, 94, 0.3);

      --badge-changed-bg: rgba(168, 85, 247, 0.1);
      --badge-changed-text: #7e22ce;
      --badge-changed-border: rgba(168, 85, 247, 0.3);

      --badge-ops-bg: rgba(59, 130, 246, 0.1);
      --badge-ops-text: #1d4ed8;
      --badge-ops-border: rgba(59, 130, 246, 0.3);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      background: var(--page-bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      line-height: 1.6;
      transition: background-color .18s ease, color .18s ease;
    }
    a { color: inherit; text-decoration: none; }

    /* Top Bar */
    .topbar { border-bottom: 1px solid var(--border); background: var(--surface); }
    .topbar-inner {
      width: min(100% - 40px, 980px);
      min-height: 68px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
    }
    .brand {
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 18px;
      font-weight: 800;
      letter-spacing: .04em;
    }
    .brand-accent { color: var(--accent); }
    .controls { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
    .control {
      min-height: 36px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
      padding: 6px 12px;
      border: 1px solid var(--border);
      border-radius: 9px;
      background: var(--surface);
      color: var(--text-muted);
      font: inherit;
      font-size: 12px;
      font-weight: 650;
      cursor: pointer;
      transition: border-color .18s, color .18s;
    }
    .control:hover, .control:focus-visible { border-color: var(--accent); color: var(--text); }
    .control:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
    .theme-switch { position: relative; }
    .theme-switch input { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); }

    /* Main Container */
    main {
      flex: 1;
      width: min(100% - 40px, 860px);
      margin: 0 auto;
      padding: clamp(32px, 5vw, 64px) 0 80px;
    }

    /* Zen-style Hero Section */
    .hero { margin-bottom: 48px; }
    .eyebrow {
      margin: 0 0 10px;
      color: var(--accent);
      font-size: 12px;
      font-weight: 750;
      letter-spacing: .08em;
      text-transform: uppercase;
    }
    h1 {
      margin: 0 0 16px;
      font-size: clamp(36px, 6vw, 52px);
      line-height: 1.1;
      letter-spacing: -.035em;
      font-weight: 850;
    }
    .lead {
      margin: 0 0 24px;
      color: var(--text-muted);
      font-size: clamp(15px, 2vw, 17px);
      line-height: 1.65;
      max-width: 65ch;
    }
    .action-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }
    .action-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 14px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: var(--surface);
      color: var(--text);
      font-size: 13px;
      font-weight: 650;
      transition: border-color .18s, background .18s, transform .15s;
    }
    .action-btn:hover {
      border-color: var(--accent);
      background: var(--surface-elevated);
      transform: translateY(-1px);
    }
    .action-btn-primary {
      background: var(--accent);
      color: #090a0d;
      border-color: var(--accent);
    }
    .action-btn-primary:hover {
      background: #ffaa66;
      border-color: #ffaa66;
      color: #090a0d;
    }

    /* Zen Browser Style Release Cards */
    .timeline {
      display: flex;
      flex-direction: column;
      gap: 40px;
    }
    .release-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: clamp(24px, 4vw, 36px);
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      transition: border-color .2s ease;
    }
    .release-latest {
      border-color: var(--border-accent);
      box-shadow: 0 6px 32px rgba(255, 152, 73, 0.08);
    }

    /* Card Header */
    .release-header {
      padding-bottom: 18px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
    }
    .release-title-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
    }
    .release-version {
      margin: 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: clamp(24px, 3.5vw, 32px);
      font-weight: 850;
      letter-spacing: -.02em;
    }
    .release-meta {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--text-muted);
    }
    .release-date { font-weight: 550; }
    .meta-separator { color: var(--text-subtle); opacity: 0.6; }
    .meta-link {
      color: var(--accent);
      font-weight: 600;
      transition: text-decoration .15s;
    }
    .meta-link:hover { text-decoration: underline; }
    .meta-commit {
      font-family: ui-monospace, monospace;
      font-size: 12px;
      color: var(--text-subtle);
    }

    .release-summary {
      margin: 0 0 24px;
      font-size: 15px;
      line-height: 1.6;
      color: var(--text-muted);
    }

    /* Zen-style Pill Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 3px 9px;
      border-radius: 7px;
      font-size: 11px;
      font-weight: 750;
      letter-spacing: .04em;
      text-transform: uppercase;
      line-height: 1.2;
      white-space: nowrap;
    }
    .badge-latest {
      background: var(--accent-soft);
      color: var(--accent);
      border: 1px solid var(--accent);
    }
    .badge-active {
      background: var(--muted);
      color: var(--text-muted);
      border: 1px solid var(--border);
    }
    .badge-added {
      background: var(--badge-added-bg);
      color: var(--badge-added-text);
      border: 1px solid var(--badge-added-border);
    }
    .badge-fixed {
      background: var(--badge-fixed-bg);
      color: var(--badge-fixed-text);
      border: 1px solid var(--badge-fixed-border);
    }
    .badge-security {
      background: var(--badge-sec-bg);
      color: var(--badge-sec-text);
      border: 1px solid var(--badge-sec-border);
    }
    .badge-changed {
      background: var(--badge-changed-bg);
      color: var(--badge-changed-text);
      border: 1px solid var(--badge-changed-border);
    }
    .badge-ops {
      background: var(--badge-ops-bg);
      color: var(--badge-ops-text);
      border: 1px solid var(--badge-ops-border);
    }

    /* Change Item Rows (Zen Browser Signature List) */
    .changes-list {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .change-item {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 16px;
      align-items: baseline;
      padding: 10px 12px;
      border-radius: 10px;
      background: rgba(255,255,255,0.015);
      border: 1px solid transparent;
      transition: background .15s ease, border-color .15s ease;
    }
    .change-item:hover {
      background: var(--surface-elevated);
      border-color: var(--border);
    }
    .badge-col {
      display: flex;
      align-items: center;
    }
    .change-body {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .change-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--text);
      line-height: 1.4;
    }
    .change-desc {
      font-size: 13.5px;
      color: var(--text-muted);
      line-height: 1.55;
    }

    /* Notice callout */
    .feedback-box {
      margin-top: 48px;
      padding: 20px 24px;
      border-radius: 14px;
      background: var(--surface);
      border: 1px dashed var(--border);
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      font-size: 13.5px;
      color: var(--text-muted);
    }

    /* Footer */
    .page-footer { border-top: 1px solid var(--border); background: var(--surface); }
    .footer-inner {
      width: min(100% - 40px, 980px);
      min-height: 66px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px 24px;
      padding: 16px 0;
      color: var(--text-muted);
      font-size: 12px;
    }
    .footer-left {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .page-nav { display: flex; flex-wrap: wrap; gap: 8px 18px; }
    .page-nav a { color: var(--text-muted); text-decoration: none; transition: color .15s; }
    .page-nav a:hover, .page-nav a:focus-visible { color: var(--text); }
    .page-nav a[aria-current="page"] { color: var(--accent); font-weight: 700; }
    .version-tag {
      font-family: ui-monospace, monospace;
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 5px;
      background: var(--muted);
      border: 1px solid var(--border);
    }

    /* Responsive */
    @media (max-width: 680px) {
      .change-item {
        grid-template-columns: 1fr;
        gap: 6px;
      }
      .topbar-inner, .footer-inner { width: min(100% - 28px, 980px); }
      .theme-label { display: none; }
      main { width: min(100% - 28px, 860px); }
      .footer-inner { align-items: flex-start; flex-direction: column; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { transition: none !important; transform: none !important; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <a class="brand" href="/" aria-label="useMeter">use<span class="brand-accent">Meter</span></a>
      <div class="controls">
        <label class="control theme-switch" title="${t.themeHelp}" data-light-label="${t.themeLabel}" data-light-help="${t.themeHelp}" data-dark-label="${t.darkThemeLabel}" data-dark-help="${t.darkThemeHelp}">
          <input id="theme-toggle" type="checkbox" aria-label="${t.themeHelp}">
          <span class="theme-icon" aria-hidden="true">☼</span><span class="theme-label">${t.themeLabel}</span>
        </label>
        <nav aria-label="Language selection">
          <a class="control" href="/changelog?lang=${alternateLanguage}" lang="${alternateLanguage}" hreflang="${alternateLanguage}" title="${alternateLanguage.toUpperCase()}">
            <span aria-hidden="true">${languageFlag}</span><span>${lang.toUpperCase()}</span>
          </a>
        </nav>
      </div>
    </div>
  </header>

  <main>
    <section class="hero">
      <p class="eyebrow">${t.eyebrow}</p>
      <h1>${t.changelog}</h1>
      <p class="lead">${t.lead}</p>
      <div class="action-row">
        <a href="/" class="action-btn action-btn-primary">${t.backToDashboard}</a>
        <a href="${GITHUB_REPO_URL}/releases" class="action-btn" target="_blank" rel="noreferrer">${t.allReleasesGitHub}</a>
        <a href="${GITHUB_REPO_URL}/issues" class="action-btn" target="_blank" rel="noreferrer">${t.reportIssue}</a>
      </div>
    </section>

    <div class="timeline">
      ${releasesHtml}
    </div>

    <div class="feedback-box">
      <span>${t.feedbackNotice}</span>
      <a href="${GITHUB_REPO_URL}/issues" class="action-btn" target="_blank" rel="noreferrer">${t.reportIssue}</a>
    </div>
  </main>

  <footer class="page-footer">
    <div class="footer-inner">
      <div class="footer-left">
        <span>${t.footerText}</span>
        <span class="version-tag">v${APP_VERSION}</span>
      </div>
      <nav class="page-nav" aria-label="Information links">
        <a href="/privacy?lang=${lang}">${t.privacy}</a>
        <a href="/terms?lang=${lang}">${t.terms}</a>
        <a href="/security?lang=${lang}">${t.security}</a>
        <a href="/support?lang=${lang}">${t.support}</a>
        <a href="/changelog?lang=${lang}" aria-current="page">${t.changelog}</a>
      </nav>
    </div>
  </footer>
</body>
</html>`;
}
