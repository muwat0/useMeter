import './styles.css';
import { StrictMode, useState, useEffect, useCallback, useRef, useMemo, type FormEvent, type DragEvent } from 'react';
import { createRoot } from 'react-dom/client';

// ── Types ──
interface UsageAmount {
  unit: 'percent' | 'usd' | 'credits';
  used?: number;
  remaining?: number;
  limit?: number;
}
interface UsageWindow {
  resetsAt?: number;
  duration?: string;
}
interface UsageLimit {
  id: string;
  label: string;
  amount: UsageAmount;
  window?: UsageWindow;
  status?: string;
  notes?: string[];
}
interface Report {
  provider: string;
  credentialId?: string;
  accountLabel?: string;
  health?: string;
  stale?: boolean;
  source?: string;
  error?: string;
  status?: string;
  statusMessage?: string;
  fetchedAt?: number;
  lastGoodFetchedAt?: number;
  limits: UsageLimit[];
  metadata?: Record<string, unknown>;
  accent?: string;
  createdAt?: number;
}
interface BootstrapUser {
  id: string;
  email: string;
  role: string;
}
interface BootstrapData {
  reports: Report[];
  user: BootstrapUser | null;
}

// ── Theme Accents ──
const THEME_ACCENTS: Record<string, { accent: string; accentHover: string; accentSoft: string }> = {
  amber: { accent: '#ff9849', accentHover: '#ea7c2b', accentSoft: 'rgba(255, 152, 73, 0.12)' },
  emerald: { accent: '#10b981', accentHover: '#059669', accentSoft: 'rgba(16, 185, 129, 0.12)' },
  cyan: { accent: '#06b6d4', accentHover: '#0891b2', accentSoft: 'rgba(6, 182, 212, 0.12)' },
  violet: { accent: '#a855f7', accentHover: '#9333ea', accentSoft: 'rgba(168, 85, 247, 0.12)' },
  slate: { accent: '#38bdf8', accentHover: '#0284c7', accentSoft: 'rgba(56, 189, 248, 0.12)' },
};
const ACCENT_KEYS = ['amber', 'emerald', 'cyan', 'violet', 'slate'] as const;
const ACCENT_COLORS: Record<string, string> = {
  amber: '#ff9849', emerald: '#10b981', cyan: '#06b6d4', violet: '#a855f7', slate: '#38bdf8',
};

// ── I18N ──
const I18N: Record<string, Record<string, string>> = {
  tr: {
    flag: "🇹🇷", title: "useMeter", subtitle: "Multi-Provider Quota & Balance Hub",
    refresh: "Yenile", addAccountText: "Hesap Bağla",
    summaryActive: "Aktif Hesaplar:", summaryBalance: "Toplam Ön Ödemeli Bakiye:",
    summaryExhausted: "Kilitli/Biten Kota:", autoSync: "Otomatik Yenileme:",
    editModeActive: "✏️ Düzenleme Modu Aktif", editModeTitle: "Kart Düzenleme Modu",
    settingsTitle: "Ayarlar", themeTitle: "Koyu / Aydınlık Mod",
    deleteAccount: "Hesabı Kaldır", editLabel: "Etiketi Düzenle",
    save: "Kaydet", saveAndPoll: "Kaydet ve Sorgula", cancel: "İptal",
    noAccounts: 'Henüz kayıtlı bir AI hesabı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.',
    lastUpdate: "Son Güncelleme", deleteConfirm: "Bu hesabın kimlik bilgisi ve kaydedilmiş kullanım geçmişi kalıcı olarak silinecek. Bu işlem geri alınamaz. Devam etmek istiyor musunuz?", deleteFailed: "Hesap kaldırılamadı. Lütfen tekrar deneyin.",
    resetsIn: "Sıfırlanma", rightsAvailable: "Hak Mevcut",
    modalTitle: "AI Hesabı Bağla", modalSubtitle: "OAuth veya doğrudan API anahtarıyla kota takibi kurun.",
    tabOAuth: "OAuth ile Oturum Aç", tabManual: "Manuel API Key",
    oauthDesc: "Resmi sağlayıcı girişine yönlendirilirsiniz. Token\u2019lar yerel veritabanında AES-256-GCM ile şifrelenir.",
    googleTitle: "Antigravity (Google AI Pro)", googleDesc: "Gemini ve Claude & GPT model havuzu kotaları",
    codexTitle: "OpenAI ChatGPT / Codex", codexDesc: "Plus / Pro 5 saatlik ve haftalık kotalar",
    claudeTitle: "Anthropic Claude Pro/Max", claudeDesc: "5h oturum ve haftalık Opus/Sonnet kotaları",
    loginBtn: "Oturum Aç →", deviceWait: "OpenAI Onayı Bekleniyor:",
    deviceDesc: "Yeni sekmede açılan OpenAI sayfasına bu kodu girin. Onaylandığı an bu pencere kendiliğinden kapanacaktır.",
    reopenLink: "Onay Sayfasını Yeniden Aç ↗",
    copilotTitle: "GitHub Copilot", copilotDesc: "Completions ve Chat kotaları",
    cursorTitle: "Cursor (Pro/Ultra)", cursorDesc: "Hızlı istekler ve on-demand kullanım",
    xaiTitle: "xAI Grok", xaiDesc: "Grok-2/3 model kotaları",
    kimiTitle: "Kimi Code (Moonshot)", kimiDesc: "Kimi K1.5 ve context kotaları",
    geminiCliTitle: "Google Gemini CLI", geminiCliDesc: "Code Assist & Gemini 2.5/3 Pro kotaları",
    openrouterTitle: "OpenRouter", openrouterDesc: "Otomatik PKCE ile API anahtarı ve bakiye",
    zaiTitle: "Zhipu AI (GLM / BigModel)", zaiDesc: "GLM-4 model kredileri ve bakiyesi",
    devinTitle: "Devin AI", devinDesc: "Cognition Devin kota ve oturum takibi",
    devinManualAction: "Manuel token",
    devinDocsLink: "Devin CLI manuel kimlik doğrulama yönergeleri ↗",
    copyCode: "Kodu Kopyala", codeCopied: "Kopyalandı!",
    deviceWaitGeneric: "Yetkilendirme Bekleniyor:",
    deviceDescGeneric: "Açılan doğrulama sayfasına bu kodu girin. Onaylandığı an panel otomatik olarak güncellenecektir.",
    oauthWaiting: "{provider} yetkilendirmesi bekleniyor...",
    oauthFailed: "Yetkilendirme başarısız",
    oauthRequestFailure: "Yetkilendirme isteği başarısız oldu",
    oauthPollFailure: "Yetkilendirme durumu kontrol edilemedi",
    oauthNetworkFailure: "Bağlantı hatası",
    oauthTimeout: "Yetkilendirme isteği zaman aşımına uğradı",
    manualOAuthUrlInstructions: "{provider} yetkilendirmesinden sonra localhost sayfasının açılamaması barındırılan sunucularda beklenir. Hata sekmesinin adres çubuğundaki URL'nin tamamını kopyalayıp aşağıya yapıştırın.",
    manualOAuthCodeInstructions: "{provider} yetkilendirmesini açılan sekmede tamamlayın, ardından gösterilen tek kullanımlık kodu kopyalayıp aşağıya yapıştırın.",
    manualOAuthUrlPlaceholder: "Tam callback URL'sini buraya yapıştırın",
    manualOAuthCodePlaceholder: "Tek kullanımlık yetkilendirme kodu",
    manualOAuthUrlLabel: "Tam callback URL'si",
    manualOAuthCodeLabel: "Tek kullanımlık kod",
    manualOAuthSubmit: "Yetkilendirmeyi Tamamla",
    manualOAuthSubmitting: "Tamamlanıyor...",
    manualOAuthFailure: "Yetkilendirme girdisi doğrulanamadı veya tamamlanamadı. Kopyaladığınız değeri kontrol edip yeniden deneyin.",
    manualOAuthNetworkFailure: "Yetkilendirme girdisi gönderilemedi. Bağlantınızı kontrol edip yeniden deneyin.",
    oauthSessionNotFound: "Yetkilendirme oturumu bulunamadı veya süresi doldu",
    oauthExpired: "Yetkilendirme süresi doldu. Yeniden başlayın.",
    oauthRetrying: "İstek hız sınırına ulaştı; {seconds} saniye sonra yeniden denenecek.",
    oauthCapacity: "OAuth oturum sınırına ulaşıldı. Lütfen etkin bir oturum kapanana kadar bekleyip yeniden deneyin.",
    oauthFinalizationRestart: "Yerel sorgulama kapasitesi dolduğu için yetkilendirme tamamlanamadı. Yeni bir yetkilendirme başlatın; önceki yanıt yeniden kullanılamaz.",
    oauthRestart: "Yeniden Başlat",
    provider: "Sağlayıcı", accountLabel: "Hesap Adı / Etiket",
    accountLabelPlaceholder: "Örn: Kişisel Pro, İş Hesabı",
    accountAccent: "Kart Vurgu Rengi", cardAccent: "Kart Vurgusu",
    accentDefault: "Varsayılan (Tema Rengi)", credentialType: "Kimlik Türü",
    apiKey: "API Anahtarı", oauthToken: "OAuth Access Token",
    secretLabel: "Secret / Token", themeAccent: "Vurgu Rengi", close: "Kapat",
    groupSelect: "Gruplama", groupNone: "Gruplama Yok", groupProvider: "Sağlayıcıya Göre",
    editDisabledGrouped: "Gruplama etkinken düzenleme modu kullanılamaz",
    sortCustom: "Özel Sıralama", sortDateAdded: "Eklenme Tarihi",
    sortHighest: "En Yüksek Kalan", sortLowest: "En Düşük Kalan",
    syncStatusJustNow: "Son kontrol: az önce",
    syncStatusSec: "Son kontrol: {n} sn önce", syncStatusMin: "Son kontrol: {n} dk önce",
    pollingError: "Sorgulama Hatası", subscriptionError: "Abonelik Gerekli veya Süresi Dolmuş",
    permissionError: "Bu Servis İçin Yetkiniz Yok", rateLimitError: "İstek Hız Sınırı Aşıldı",
    networkError: "Bağlantı Hatası", authError: "Yetkilendirme Hatası / Token Geçersiz",
    statusStale: "Eski Veri", staleBadge: "Eski Veri",
    staleNotice: "Önbelleğe alınmış kotalar gösteriliyor",
    lastSuccessfulUpdate: "Son başarılı güncelleme:", initialUnavailable: "Kullanım verisi henüz alınamadı",
    accountConnectedNoQuota: "Hesap bağlandı; sağlayıcı kota verisi bildirmiyor",
    logoutText: "Çıkış", logoutTitle: "Oturumu Kapat",
    adminLink: "Yönetim", adminTitle: "Yönetim Paneli",
    editModeNotice: "✏️ Düzenleme Modu Aktif",
  },
  en: {
    flag: "🇬🇧", title: "useMeter", subtitle: "Multi-Provider Quota & Balance Hub",
    refresh: "Refresh", addAccountText: "Add Account",
    summaryActive: "Active Accounts:", summaryBalance: "Total Prepaid Balance:",
    summaryExhausted: "Exhausted Quotas:", autoSync: "Auto-refresh:",
    editModeActive: "✏️ Edit Mode Active", editModeTitle: "Card Edit Mode",
    settingsTitle: "Settings", themeTitle: "Dark / Light Mode",
    deleteAccount: "Remove Account", editLabel: "Edit Label",
    save: "Save", saveAndPoll: "Save & Poll", cancel: "Cancel",
    noAccounts: 'No AI accounts connected yet. Click <b>+ Connect Account</b> to add one.',
    lastUpdate: "Updated", deleteConfirm: "This account's credential and saved usage history will be permanently deleted. This cannot be undone. Continue?", deleteFailed: "The account could not be removed. Please try again.",
    resetsIn: "Resets in", rightsAvailable: "Available",
    modalTitle: "Connect AI Account", modalSubtitle: "Track quotas and credits via OAuth or direct API key.",
    tabOAuth: "Login with OAuth", tabManual: "Manual API Key",
    oauthDesc: "Redirect to official authorization. Tokens are encrypted locally via AES-256-GCM.",
    googleTitle: "Antigravity (Google AI Pro)", googleDesc: "Gemini and Claude & GPT shared quota pools",
    codexTitle: "OpenAI ChatGPT / Codex", codexDesc: "Plus / Pro 5-hour rolling & weekly quotas",
    claudeTitle: "Anthropic Claude Pro/Max", claudeDesc: "5h session and weekly Opus/Sonnet quotas",
    loginBtn: "Login →", deviceWait: "Waiting for OpenAI Approval:",
    deviceDesc: "Enter the code on the OpenAI confirmation page. The dashboard will automatically update.",
    reopenLink: "Re-open Authorization Page ↗",
    copilotTitle: "GitHub Copilot", copilotDesc: "Completions & Chat quotas",
    cursorTitle: "Cursor (Pro/Ultra)", cursorDesc: "Fast requests & on-demand usage",
    xaiTitle: "xAI Grok", xaiDesc: "Grok-2/3 model quotas",
    kimiTitle: "Kimi Code (Moonshot)", kimiDesc: "Kimi K1.5 & context quotas",
    geminiCliTitle: "Google Gemini CLI", geminiCliDesc: "Code Assist & Gemini 2.5/3 Pro quotas",
    openrouterTitle: "OpenRouter", openrouterDesc: "Automatic PKCE key exchange & balance",
    zaiTitle: "Zhipu AI (GLM / BigModel)", zaiDesc: "GLM-4 model credits & balance",
    devinTitle: "Devin AI", devinDesc: "Cognition Devin quota & session tracking",
    devinManualAction: "Manual token",
    devinDocsLink: "Devin CLI manual authentication instructions ↗",
    copyCode: "Copy Code", codeCopied: "Copied!",
    deviceWaitGeneric: "Authorization Pending:",
    deviceDescGeneric: "Enter this code on the verification page. The dashboard will update automatically.",
    oauthWaiting: "Waiting for {provider} authorization...",
    oauthFailed: "Authorization failed",
    oauthCapacity: "OAuth session capacity has been reached. Wait for an active session to close, then try again.",
    oauthNetworkFailure: "Network connection failed",
    oauthTimeout: "Authorization request timed out",
    manualOAuthUrlInstructions: "After {provider} authorization, the localhost page may fail to load on a hosted server; this is expected. Copy the entire URL from the error tab's address bar and paste it below.",
    manualOAuthCodeInstructions: "Complete {provider} authorization in the opened tab, then copy the displayed one-time code and paste it below.",
    manualOAuthUrlPlaceholder: "Paste the full callback URL here",
    manualOAuthCodePlaceholder: "One-time authorization code",
    manualOAuthUrlLabel: "Full callback URL",
    manualOAuthCodeLabel: "One-time code",
    manualOAuthSubmit: "Complete authorization",
    manualOAuthSubmitting: "Completing...",
    manualOAuthFailure: "The authorization input could not be verified or completed. Check the copied value and try again.",
    manualOAuthNetworkFailure: "The authorization input could not be submitted. Check your connection and try again.",
    oauthRequestFailure: "Authorization request failed",
    oauthPollFailure: "Could not check authorization status",
    oauthSessionNotFound: "Authorization session was not found or has expired",
    oauthExpired: "Authorization expired. Start again.",
    oauthRetrying: "Polling is rate limited; retrying in {seconds} seconds.",
    oauthFinalizationRestart: "Authorization could not be completed because local polling capacity is full. Start a new authorization; the previous response cannot be reused.",
    oauthRestart: "Start Again",
    provider: "Provider", accountLabel: "Account Label",
    accountLabelPlaceholder: "e.g. Personal Pro, Work Key",
    accountAccent: "Card Accent Color", cardAccent: "Card Accent",
    accentDefault: "Default (Theme Color)", credentialType: "Credential Type",
    apiKey: "API Key", oauthToken: "OAuth Access Token",
    secretLabel: "Secret / Token", themeAccent: "Accent Color", close: "Close",
    groupSelect: "Grouping", groupNone: "No Grouping", groupProvider: "By Provider",
    editDisabledGrouped: "Edit mode is disabled while grouped",
    sortCustom: "Custom Order", sortDateAdded: "Date Added",
    sortHighest: "Highest Available", sortLowest: "Lowest Available",
    syncStatusJustNow: "Last checked: just now",
    syncStatusSec: "Last checked: {n}s ago", syncStatusMin: "Last checked: {n}m ago",
    pollingError: "Polling Error", subscriptionError: "Subscription Required or Inactive",
    permissionError: "Permission Denied for This Service", rateLimitError: "Rate Limit Exceeded",
    networkError: "Connection Error", authError: "Authentication Error / Invalid Token",
    statusStale: "Stale", staleBadge: "Stale", staleNotice: "Showing cached limits",
    lastSuccessfulUpdate: "Last successful update:", initialUnavailable: "Usage data not yet available",
    accountConnectedNoQuota: "Account connected; provider reports no quota data",
    logoutText: "Sign Out", logoutTitle: "Sign out",
    adminLink: "Admin", adminTitle: "Admin Panel",
    editModeNotice: "✏️ Edit Mode Active",
  },
};

// ── Helpers ──
function t(key: string, lang: string): string {
  return I18N[lang]?.[key] || I18N['tr']?.[key] || key;
}

function formatProviderTitle(provider: string): string {
  const p = (provider || '').toLowerCase();
  if (p === 'antigravity' || p === 'google-antigravity' || p === 'google') return 'Antigravity';
  if (p === 'openai-codex' || p === 'codex') return 'OpenAI Codex';
  if (p === 'openrouter') return 'OpenRouter';
  if (p === 'deepseek') return 'DeepSeek';
  if (p === 'anthropic' || p === 'claude') return 'Anthropic Claude';
  if (p === 'cursor') return 'Cursor';
  if (p === 'github-copilot' || p === 'copilot') return 'GitHub Copilot';
  if (p === 'xai-oauth' || p === 'grok' || p === 'xai') return 'xAI Grok';
  if (p === 'zai' || p === 'zhipu' || p === 'glm') return 'Zhipu AI (GLM)';
  if (p === 'minimax-code' || p === 'minimax') return 'MiniMax Code';
  if (p === 'cline-pass' || p === 'clinepass') return 'Cline Pass';
  if (p === 'devin') return 'Devin';
  if (p === 'umans') return 'Umans';
  if (p === 'google-gemini-cli' || p === 'gemini-cli') return 'Gemini CLI';
  if (p === 'kimi-code' || p === 'kimi' || p === 'moonshot') return 'Kimi Code';
  if (p === 'opencode-go') return 'OpenCode Go';
  if (p === 'alibaba-token-plan') return 'Alibaba Qwen';
  return provider.charAt(0).toUpperCase() + provider.slice(1);
}

function sanitizeErrorMessage(msg: string): string {
  if (!msg) return '';
  let clean = String(msg);
  clean = clean.replace(/ya29\.[a-zA-Z0-9_-]+/g, '[REDACTED_TOKEN]');
  clean = clean.replace(/sk-[a-zA-Z0-9_-]+/g, '[REDACTED_KEY]');
  clean = clean.replace(/gho_[a-zA-Z0-9_]+/g, '[REDACTED_TOKEN]');
  clean = clean.replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, 'Bearer [REDACTED]');
  clean = clean.replace(/[a-f0-9]{32,64}/gi, '[REDACTED_HASH]');
  return clean;
}

function translateErrorText(text: string): string {
  return String(text)
    .replaceAll('aboneliği aktif değil veya süresi dolmuş', 'subscription is inactive or expired')
    .replaceAll('abonelik aktif değil veya süresi dolmuş', 'subscription is inactive or expired')
    .replaceAll('aboneliği aktif değil', 'subscription is inactive')
    .replaceAll('süresi dolmuş', 'expired')
    .replaceAll('abonelik gerekli', 'subscription required')
    .replaceAll('abonelik', 'subscription')
    .replaceAll('yetkili değil', 'unauthorized')
    .replaceAll('yetkisiz', 'unauthorized')
    .replaceAll('geçersiz', 'invalid')
    .replaceAll('hata', 'error')
    .replaceAll('sorgulama', 'query');
}

function getLocalizedReportError(report: Report, lang: string): string | null {
  const err = report.error || (report.health === 'error' ? (report.statusMessage || 'Error') : null);
  if (!err) return null;
  const raw = sanitizeErrorMessage(err);
  const lower = raw.toLowerCase();
  if (lower.includes('rate limit') || lower.includes('429')) return t('rateLimitError', lang);
  if (lower.includes('subscription') || lower.includes('aboneli') || lower.includes('subscription_required')) return t('subscriptionError', lang);
  if (lower.includes('permission_denied') || lower.includes('permission denied') || lower.includes('403')) return t('permissionError', lang);
  if (lower.includes('unauthorized') || lower.includes('401') || lower.includes('invalid_grant') || lower.includes('token expired') || lower.includes('auth')) return t('authError', lang);
  if (lower.includes('fetch') || lower.includes('network') || lower.includes('econnrefused') || lower.includes('timeout')) return t('networkError', lang);
  return t('pollingError', lang) + ': ' + translateErrorText(raw).slice(0, 60);
}

function translateLimitLabel(label: string | undefined, id: string | undefined, lang: string): string {
  const str = String(label || id || '');
  const lid = String(id || '');
  if (lang === 'tr') {
    const trMap: Record<string, string> = {
      fast_requests: 'Cursor Hızlı İstek Kotası', gemini_5h: 'Gemini: 5 Saatlik Limit',
      gemini_weekly: 'Gemini: Haftalık Limit', claude_gpt_5h: 'Claude & GPT: 5 Saatlik Limit',
      claude_gpt_weekly: 'Claude & GPT: Haftalık Limit', primary_window: '5 Saatlik Kayan Kota',
      primary: '5 Saatlik Kayan Kota', secondary_window: 'Haftalık / Uzun Dönem Kotası',
      secondary: 'Haftalık / Uzun Dönem Kotası', reset_credits: 'Kota Sıfırlama Hakkı (Usage Reset)',
      premium_interactions: 'Premium İstekler (Claude 3.7 / o3-mini)', chat_quota: 'Copilot Chat Kotası',
      grok_credits: 'xAI Grok Kullanım Kotası', account_balance: 'Hesap Net Bakiyesi',
      total_credits: 'Hesap Net Bakiyesi', key_usage: 'API Anahtar Harcaması',
      rate_limit: 'İstek Hız Sınırı', balance_usd: 'Kullanılabilir Bakiye (USD)',
      '5h': '5 Saatlik Kayan Kota', '7d': 'Haftalık Genel Kota',
      'kimi-code-5h': '5 Saatlik Kota', 'kimi-code-7d': 'Haftalık Kota',
      'kimi-code-monthly': 'Aylık Kota',
    };
    return trMap[lid] || str;
  }
  const enMap: Record<string, string> = {
    fast_requests: 'Cursor Fast Requests Quota', gemini_5h: 'Gemini: 5-Hour Limit',
    gemini_weekly: 'Gemini: Weekly Limit', claude_gpt_5h: 'Claude & GPT: 5-Hour Limit',
    claude_gpt_weekly: 'Claude & GPT: Weekly Limit', primary_window: '5-Hour Rolling Quota',
    primary: '5-Hour Rolling Quota', secondary_window: 'Weekly / Long-Term Quota',
    secondary: 'Weekly / Long-Term Quota', reset_credits: 'Usage Reset Allowance',
    premium_interactions: 'Premium Requests (Claude 3.7 / o3-mini)', chat_quota: 'Copilot Chat Quota',
    grok_credits: 'xAI Grok Usage Quota', account_balance: 'Account Net Balance',
    total_credits: 'Account Net Balance', key_usage: 'API Key Spending',
    rate_limit: 'Rate Limit', balance_usd: 'Available Balance (USD)',
    '5h': '5-Hour Rolling Quota', '7d': 'Weekly Quota',
    'kimi-code-5h': '5-Hour Quota', 'kimi-code-7d': 'Weekly Quota',
    'kimi-code-monthly': 'Monthly Quota',
  };
  if (enMap[lid]) return enMap[lid];
  return str.replaceAll('Cursor Hızlı İstek Kotası', 'Cursor Fast Requests Quota')
    .replaceAll('5 Saatlik Kayan Kota', '5-Hour Rolling Quota')
    .replaceAll('Haftalık / Uzun Dönem Kotası', 'Weekly / Long-Term Quota')
    .replaceAll('Haftalık Genel Kota', 'Weekly Quota')
    .replaceAll('Kota Sıfırlama Hakkı (Usage Reset)', 'Usage Reset Allowance')
    .replaceAll('Hesap Net Bakiyesi', 'Account Net Balance')
    .replaceAll('Kullanılabilir Bakiye', 'Available Balance')
    .replaceAll('İstek Hız Sınırı', 'Rate Limit');
}

function translateNote(note: string, lang: string): string {
  const str = String(note || '');
  if (lang === 'tr') return str;
  return str.replace(/^Kod kullanımı:\s*%(\d+(?:\.\d+)?)$/, 'Code usage: $1%')
    .replace('Kullanılan:', 'Used:').replace('Kalan:', 'Remaining:')
    .replaceAll('istek', 'requests')
    .replaceAll('Son Geçerlilik:', 'Expires:')
    .replaceAll('Toplam Yüklenen:', 'Total Loaded:')
    .replaceAll('Toplam Harcanan:', 'Total Spent:')
    .replaceAll('Nakit Yüklenen:', 'Topped Up Cash:')
    .replaceAll('Hediye/Promosyon:', 'Granted/Promo:')
    .replaceAll('Hesap kullanım dışı', 'Account inactive')
    .replaceAll('Hesap aktif', 'Account active')
    .replaceAll('adet kullanılabilir reset hakkı', 'available reset credit(s)')
    .replaceAll('Sınırsız Plan', 'Unlimited Plan')
    .replaceAll('Free tier hesabı', 'Free tier account');
}

function detectInitialLang(): string {
  const saved = localStorage.getItem('usage_lang');
  if (saved === 'tr' || saved === 'en') return saved;
  const bl = (navigator.language || '').toLowerCase();
  return bl.startsWith('tr') ? 'tr' : 'en';
}

function getReportScore(report: Report): number {
  for (const l of report.limits || []) {
    if (l.amount?.unit === 'usd' && typeof l.amount.remaining === 'number') return l.amount.remaining * 10;
    if (l.amount?.unit === 'percent' && typeof l.amount.remaining === 'number') return l.amount.remaining;
  }
  return 0;
}

function sortReports(reports: Report[], sortKey: string): Report[] {
  const list = [...reports];
  if (sortKey === 'custom') {
    const saved = localStorage.getItem('usage_custom_order');
    if (saved) {
      try {
        const order: string[] = JSON.parse(saved);
        list.sort((a, b) => {
          const idA = a.credentialId || a.provider;
          const idB = b.credentialId || b.provider;
          const idxA = order.indexOf(idA);
          const idxB = order.indexOf(idB);
          if (idxA === -1 && idxB === -1) return 0;
          if (idxA === -1) return 1;
          if (idxB === -1) return -1;
          return idxA - idxB;
        });
        return list;
      } catch { /* ignore */ }
    }
  } else if (sortKey === 'date_added') {
    const hasValid = list.some(r => typeof r.createdAt === 'number' && r.createdAt > 0);
    if (hasValid) list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    return list;
  } else if (sortKey === 'highest_available') {
    list.sort((a, b) => getReportScore(b) - getReportScore(a));
  } else if (sortKey === 'lowest_available') {
    list.sort((a, b) => getReportScore(a) - getReportScore(b));
  }
  return list;
}

function getCardKey(r: Report): string { return r.credentialId || r.provider; }

function getCleanLabel(r: Report): string {
  const providerTitle = formatProviderTitle(r.provider);
  const metaEmail = r.metadata && (r.metadata['email'] || r.metadata['login'] || r.metadata['username'] || r.metadata['accountId'] || r.metadata['userId']);
  let cleanLabel = (r.accountLabel || 'Default').replace(/^Google \((.*)\)$/, '$1');
  if ((!cleanLabel || cleanLabel.toLowerCase() === providerTitle.toLowerCase() || cleanLabel.toLowerCase() === (r.provider || '').toLowerCase() || cleanLabel === 'Default') && metaEmail) {
    cleanLabel = String(metaEmail);
  }
  return cleanLabel;
}

// ── AccountCard ──
function AccountCard({ r, lang, isEditMode, editingCardId, currentGroup, onStartEditLabel, onCancelEditLabel, onSaveLabel, onSaveAccent, onDeleteAccount, onDragStart, onDragOver, onDragLeave, onDrop, onDragEnd }: {
  r: Report; lang: string; isEditMode: boolean; editingCardId: string | null;
  currentGroup: string;
  onStartEditLabel: (key: string) => void; onCancelEditLabel: () => void;
  onSaveLabel: (key: string, label: string) => void; onSaveAccent: (key: string, accent: string) => void;
  onDeleteAccount: (id: string) => void;
  onDragStart: (e: DragEvent<HTMLDivElement>, id: string) => void;
  onDragOver: (e: DragEvent<HTMLDivElement>) => void;
  onDragLeave: (e: DragEvent<HTMLDivElement>) => void;
  onDrop: (e: DragEvent<HTMLDivElement>, id: string) => void;
  onDragEnd: (e: DragEvent<HTMLDivElement>) => void;
}) {
  const cardKey = getCardKey(r);
  const providerTitle = formatProviderTitle(r.provider);
  const cleanLabel = getCleanLabel(r);
  const cardAccent = r.accent || 'default';
  const canDrag = isEditMode && currentGroup === 'none';

  const hasLimits = Array.isArray(r.limits) && r.limits.length > 0;
  const isStale = Boolean(r.stale || r.health === 'stale' || r.source === 'stale' || (Boolean(r.error) && hasLimits));
  const isFirstError = Boolean((r.health === 'error' || r.error) && !isStale && !hasLimits);
  const isHealthyNoQuota = !hasLimits && !r.error && !r.stale && r.health === 'healthy' && r.source === 'live';
  const cardStatus = isStale ? 'stale' : (isFirstError ? 'error' : 'healthy');

  const successTimestamp = (isStale && r.lastGoodFetchedAt) ? r.lastGoodFetchedAt : r.fetchedAt;
  const timeStr = successTimestamp ? new Date(successTimestamp).toLocaleTimeString() : '';
  const updateLabel = isStale ? t('lastSuccessfulUpdate', lang) : (t('lastUpdate', lang) + ':');

  const editBorderClass = isEditMode ? ' is-edit-mode cursor-grab active:cursor-grabbing' : ' hover:border-zinc-700';

  const planNote = (r.limits || []).flatMap(l => l.notes || []).find(n => String(n).toLowerCase().startsWith('plan:'));
  const rawPlan = (r.metadata?.['planType'] as string) || (planNote ? planNote.replace(/^Plan:\s*/i, '').trim() : '');
  const planName = rawPlan ? rawPlan.toUpperCase() : '';

  const rawError = getLocalizedReportError(r, lang);

  const labelInputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (editingCardId === cardKey && labelInputRef.current) {
      labelInputRef.current.focus();
      labelInputRef.current.select();
    }
  }, [editingCardId, cardKey]);

  return (
    <div
      data-card-id={cardKey} data-status={cardStatus} data-accent={cardAccent}
      className={`account-card border${editBorderClass} rounded-2xl p-5 space-y-4 transition-all shadow-sm relative`}
      draggable={canDrag}
      onDragStart={canDrag ? (e) => onDragStart(e, cardKey) : undefined}
      onDragOver={canDrag ? onDragOver : undefined}
      onDragLeave={canDrag ? onDragLeave : undefined}
      onDrop={canDrag ? (e) => onDrop(e, cardKey) : undefined}
      onDragEnd={canDrag ? onDragEnd : undefined}
    >
      {/* Header */}
      <div className="flex justify-between items-start">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="account-card-title font-bold text-base tracking-tight">{providerTitle}</h2>
            {planName && <span className="px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-wider rounded-md bg-appAccentSoft text-appAccent border border-appAccent/30 shadow-xs">{planName}</span>}
            {/* Label display */}
            {isEditMode ? (
              editingCardId === cardKey ? (
                <div className="flex items-center gap-1.5 mt-1" draggable={false} onMouseDown={e => e.stopPropagation()}>
                  <input ref={labelInputRef} type="text" defaultValue={cleanLabel}
                    className="text-xs px-2.5 py-1 bg-appMuted border border-appAccent rounded-md text-appText outline-none w-36"
                    onKeyDown={e => { if (e.key === 'Enter') onSaveLabel(cardKey, (e.target as HTMLInputElement).value); if (e.key === 'Escape') onCancelEditLabel(); }} />
                  <button type="button" onClick={() => { if (labelInputRef.current) onSaveLabel(cardKey, labelInputRef.current.value); }}
                    className="px-2 py-1 text-xs bg-appAccent text-zinc-950 font-semibold rounded-md hover:bg-appAccentHover">✓</button>
                  <button type="button" onClick={onCancelEditLabel}
                    className="px-2 py-1 text-xs bg-appMuted text-appTextMuted rounded-md hover:text-appText">✕</button>
                </div>
              ) : (
                <div className="flex items-center gap-2 mt-1" draggable={false} onMouseDown={e => e.stopPropagation()}>
                  <span className="account-card-badge text-xs font-semibold px-2.5 py-0.5 rounded-md">{cleanLabel}</span>
                  <button type="button" onClick={() => onStartEditLabel(cardKey)}
                    className="text-[11px] font-medium text-appAccent hover:underline flex items-center gap-1">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                    <span>{t('editLabel', lang)}</span>
                  </button>
                </div>
              )
            ) : (
              <span className="account-card-badge text-xs font-semibold px-2.5 py-0.5 rounded-md">{cleanLabel}</span>
            )}
            {/* Stale badge */}
            {isStale && (
              <span className="bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] font-medium px-1.5 py-0.5 rounded flex items-center gap-1 shrink-0" title={t('staleNotice', lang)}>
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                <span>{t('staleBadge', lang)}</span>
              </span>
            )}
          </div>
          <span className="text-xs text-appTextMuted block mt-1.5">{updateLabel} {timeStr}</span>
        </div>
      </div>

      {/* Status notices */}
      {isStale && (
        <div role="status" aria-live="polite" className="bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs px-3 py-2 rounded-xl flex items-start gap-2.5">
          <svg className="w-4 h-4 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <div className="flex-1 space-y-0.5 min-w-0">
            <div className="font-medium flex items-center justify-between gap-2 flex-wrap">
              <span>{t('staleNotice', lang)}</span>
              <span className="text-[11px] text-amber-400/80 font-normal">{t('lastSuccessfulUpdate', lang)} {timeStr}</span>
            </div>
            {rawError && <span className="text-[11px] text-amber-400/90 block truncate">{rawError}</span>}
          </div>
        </div>
      )}
      {isFirstError && (
        <div className="bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs px-3 py-2 rounded-xl flex items-center gap-2">
          <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span className="truncate">{rawError || t('initialUnavailable', lang)}</span>
        </div>
      )}
      {isHealthyNoQuota && (
        <div role="status" className="bg-appMuted/60 border border-appBorder text-appTextMuted text-xs px-3 py-2 rounded-xl flex items-center gap-2">
          <svg className="w-4 h-4 shrink-0 text-appTextMuted" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          <span>{t('accountConnectedNoQuota', lang)}</span>
        </div>
      )}

      {/* Limits */}
      {hasLimits && (
        <div className="space-y-2.5">
        {(r.limits || []).map((l, idx) => {
          const cleanLimitLabel = translateLimitLabel(l.label, l.id, lang);
          const cleanNotes = (l.notes || []).filter(n => !String(n).toLowerCase().includes('model') && !String(n).toLowerCase().startsWith('plan:'));

          let valueEl: React.ReactNode = null;
          let barEl: React.ReactNode = null;

          if (l.amount.unit === 'percent') {
            const used = l.amount.used || 0;
            const isCritical = used >= 90;
            const barColor = isCritical ? 'bg-rose-500' : 'account-card-bar-fill';
            valueEl = <span className="account-card-value font-bold text-sm">{used.toFixed(1)}%</span>;
            barEl = (
              <div className="w-full account-card-bar-track h-1.5 rounded-full overflow-hidden mt-2">
                <div className={`${barColor} h-full transition-all duration-300`} style={{ width: `${Math.min(100, used)}%` }} />
              </div>
            );
          } else if (l.amount.unit === 'usd') {
            const rem = l.amount.remaining ?? 0;
            valueEl = <span className="account-card-value font-bold text-sm">${rem.toFixed(2)}</span>;
          } else if (l.amount.unit === 'credits') {
            const rem = l.amount.remaining ?? 0;
            const labelText = lang === 'tr' ? `${rem} Hak Mevcut` : `${rem} Available`;
            valueEl = <span className="account-card-badge font-semibold text-xs px-2.5 py-0.5 rounded-md">{labelText}</span>;
          }

          let countdownEl: React.ReactNode = null;
          if (l.window?.resetsAt) {
            const diffMin = Math.max(0, Math.round((l.window.resetsAt - Date.now()) / 60000));
            const hours = Math.floor(diffMin / 60);
            const mins = diffMin % 60;
            const timeLabel = lang === 'tr'
              ? (hours > 0 ? `${hours}sa ${mins}dk` : `${mins}dk`)
              : (hours > 0 ? `${hours}h ${mins}m` : `${mins}m`);
            countdownEl = (
              <span className="text-xs text-appTextMuted flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-appTextMuted/70" />{t('resetsIn', lang)}: {timeLabel}
              </span>
            );
          }

          return (
            <div key={l.id || idx} className="account-card-box border rounded-xl p-3.5 space-y-1.5">
              <div className="flex justify-between items-center">
                <span className="text-sm font-semibold text-appText tracking-tight">{cleanLimitLabel}</span>
                {valueEl}
              </div>
              {barEl}
              <div className="flex justify-between items-center pt-1">{countdownEl}</div>
              {cleanNotes.map((n, ni) => <span key={ni} className="text-xs text-appTextMuted block mt-0.5">{translateNote(n, lang)}</span>)}
            </div>
          );
        })}
        </div>
      )}

      {/* Edit mode accent picker */}
      {isEditMode && (
        <div className="pt-2 border-t border-appBorder/50 flex flex-wrap items-center justify-between gap-2 text-xs" draggable={false} onMouseDown={e => e.stopPropagation()}>
          <span className="text-[11px] font-semibold text-appTextMuted">{t('cardAccent', lang)}:</span>
          <div className="flex flex-wrap items-center justify-end gap-x-3 gap-y-2">
            <div className="flex items-center gap-1.5">
              <button type="button" onClick={() => onSaveAccent(cardKey, 'default')} title={t('accentDefault', lang)}
                className={`w-4 h-4 rounded-full border border-appBorder bg-transparent relative flex items-center justify-center ${(!cardAccent || cardAccent === 'default') ? 'ring-2 ring-appAccent ring-offset-1 ring-offset-appSurface' : ''}`}>
                <span className="w-1.5 h-1.5 rounded-full bg-appTextMuted/40" />
              </button>
              {ACCENT_KEYS.map(ak => (
                <button key={ak} type="button" onClick={() => onSaveAccent(cardKey, ak)} title={ak.charAt(0).toUpperCase() + ak.slice(1)}
                  className={`w-4 h-4 rounded-full ${cardAccent === ak ? 'ring-2 ring-white ring-offset-1 ring-offset-appSurface' : ''}`}
                  style={{ backgroundColor: ACCENT_COLORS[ak] }} />
              ))}
            </div>
            {r.credentialId && (
              <button type="button" draggable={false}
                onClick={e => { e.preventDefault(); e.stopPropagation(); onDeleteAccount(r.credentialId!); }}
                onMouseDown={e => e.stopPropagation()}
                onDragStart={e => { e.preventDefault(); e.stopPropagation(); }}
                className="font-semibold text-rose-400 hover:text-rose-300 hover:underline whitespace-nowrap">
                {t('deleteAccount', lang)}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── OAuth Provider SVGs ──
const OAUTH_PROVIDERS: { id: string; titleKey: string; descKey: string; handler: string; svg: React.ReactNode }[] = [
  { id: 'google', titleKey: 'googleTitle', descKey: 'googleDesc', handler: 'google', svg: <svg viewBox="0 0 24 24" width="18" height="18"><path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.17z"/><path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.34 24 12 24z"/><path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.17 0 9.99 0 12s.45 3.83 1.25 5.42l4.03-3.15z"/><path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.34 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/></svg> },
  { id: 'codex', titleKey: 'codexTitle', descKey: 'codexDesc', handler: 'codex-device', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" className="text-emerald-400"><path d="M22.28 9.82a6 6 0 0 0-.52-4.91 6.05 6.05 0 0 0-6.51-2.9A6.06 6.06 0 0 0 4.98 4.18a5.98 5.98 0 0 0-4 2.9 6.05 6.05 0 0 0 .74 7.1 6 6 0 0 0 .51 4.91 6.05 6.05 0 0 0 6.52 2.9A5.98 5.98 0 0 0 13.26 24a6.06 6.06 0 0 0 5.77-4.2 6 6 0 0 0 4-2.9 6.06 6.06 0 0 0-.75-7.08z"/></svg> },
  { id: 'claude', titleKey: 'claudeTitle', descKey: 'claudeDesc', handler: 'claude', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" className="text-amber-500"><path d="M13.2 2h-2.4v7.3L5.64 4.14 3.94 5.84l5.16 5.16H2v2.4h7.1l-5.16 5.16 1.7 1.7 5.16-5.16V22h2.4v-7.1l5.16 5.16 1.7-1.7-5.16-5.16H22v-2.4h-7.3l5.16-5.16-1.7-1.7-5.16 5.16V2z"/></svg> },
  { id: 'copilot', titleKey: 'copilotTitle', descKey: 'copilotDesc', handler: 'copilot-device', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" className="text-purple-400"><path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844a9.59 9.59 0 012.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0022 12.017C22 6.484 17.522 2 12 2z"/></svg> },
  { id: 'cursor', titleKey: 'cursorTitle', descKey: 'cursorDesc', handler: 'cursor', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" className="text-cyan-400"><path d="M4 2l16 10-7.5 2-4.5 8L4 2z"/></svg> },
  { id: 'xai', titleKey: 'xaiTitle', descKey: 'xaiDesc', handler: 'xai-device', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" className="text-slate-100"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg> },
  { id: 'kimi', titleKey: 'kimiTitle', descKey: 'kimiDesc', handler: 'kimi-device', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" className="text-indigo-400"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 14.5v-3.2l3.4 3.2h2.6l-4.5-4.2 4.2-4.8h-2.5l-3.2 3.7V7.5H11v9h2z"/></svg> },
  { id: 'gemini-cli', titleKey: 'geminiCliTitle', descKey: 'geminiCliDesc', handler: 'gemini-cli', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" className="text-blue-400"><path d="M12 3 2.5 8 12 13l9.5-5L12 3Z"/><path d="M5 10v6l7 4 7-4v-6M21.5 8v7"/></svg> },
  { id: 'zai', titleKey: 'zaiTitle', descKey: 'zaiDesc', handler: 'zai', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" className="text-cyan-400"><path d="M4 6h16L4 18h16"/></svg> },
  { id: 'openrouter', titleKey: 'openrouterTitle', descKey: 'openrouterDesc', handler: 'openrouter', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" className="text-teal-400"><circle cx="12" cy="12" r="3"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="5" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 6.5l8 3M9 14.5l8 3M6.5 7v10M17.5 7v10"/></svg> },
  { id: 'devin', titleKey: 'devinTitle', descKey: 'devinDesc', handler: 'devin', svg: <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" className="text-emerald-300"><path d="M4 4h7v7H4V4zm9 0h7v7h-7V4zm-9 9h7v7H4v-7zm9 0h7v7h-7v-7z"/></svg> },
];


// ── Provider Hints ──
interface ProviderHint {
  placeholder: string;
  help: string;
  type: string;
  docsUrl?: string;
  docsLabelKey?: string;
}

function getProviderHint(p: string, lang: string): ProviderHint {
  const hints: Record<string, { placeholder: (l: string) => string; help: (l: string) => string; type: string; docsUrl?: string; docsLabelKey?: string }> = {
    'antigravity': { placeholder: l => l === 'tr' ? 'ya29... veya OAuth Token' : 'ya29... or OAuth Token', help: l => l === 'tr' ? 'Google OAuth Access Token veya Refresh Token' : 'Google OAuth Access Token or Refresh Token', type: 'oauth' },
    'openai-codex': { placeholder: () => 'OpenAI Access Token (eyJ...)', help: l => l === 'tr' ? 'OpenAI Bearer Access Token' : 'OpenAI Bearer Access Token', type: 'oauth' },
    'github-copilot': { placeholder: l => l === 'tr' ? 'gho_... veya GitHub Personal Token' : 'gho_... or GitHub Personal Token', help: l => l === 'tr' ? 'GitHub Copilot yetkili erişim tokenı' : 'GitHub Copilot authorization token', type: 'oauth' },
    'cursor': { placeholder: l => l === 'tr' ? 'WorkosCursorSessionToken veya access token' : 'WorkosCursorSessionToken or access token', help: l => l === 'tr' ? 'Cursor oturum tokenı veya çerezi' : 'Cursor session token or cookie', type: 'oauth' },
    'openrouter': { placeholder: l => l === 'tr' ? 'sk-or-v1-... API Anahtarı' : 'sk-or-v1-... API Key', help: l => l === 'tr' ? 'OpenRouter API Anahtarı' : 'OpenRouter API Key', type: 'api_key' },
    'deepseek': { placeholder: l => l === 'tr' ? 'sk-... DeepSeek API Anahtarı' : 'sk-... DeepSeek API Key', help: l => l === 'tr' ? 'DeepSeek Platform API Anahtarı' : 'DeepSeek Platform API Key', type: 'api_key' },
    'xai-oauth': { placeholder: l => l === 'tr' ? 'xAI OAuth Bearer Token veya API Anahtarı' : 'xAI OAuth Bearer Token or API Key', help: l => l === 'tr' ? 'xAI Grok CLI OAuth Tokenı' : 'xAI Grok CLI OAuth Token', type: 'oauth' },
    'zai': { placeholder: l => l === 'tr' ? 'Zhipu API Anahtarı veya OAuth Token' : 'Zhipu API Key or OAuth Token', help: l => l === 'tr' ? 'Zhipu AI / GLM erişim anahtarı' : 'Zhipu AI / GLM access key or token', type: 'oauth' },
    'anthropic': { placeholder: l => l === 'tr' ? 'sk-ant-... veya Claude OAuth Token' : 'sk-ant-... or Claude OAuth Token', help: l => l === 'tr' ? 'Anthropic API Anahtarı veya Claude Code Tokenı' : 'Anthropic API Key or Claude Code Token', type: 'oauth' },
    'devin': { placeholder: l => l === 'tr' ? 'Mevcut Devin CLI oturum tokenı' : 'Existing Devin CLI session token', help: l => l === 'tr' ? 'Yalnızca zaten sahip olduğunuz uyumlu Devin CLI oturum tokenını (devin-session-token$) yapıştırın. cog_ V3 API kişisel erişim tokenları (PAT) desteklenmez.' : 'Paste a compatible Devin CLI session token (devin-session-token$) only if you already have one. cog_ V3 API personal access tokens (PATs) are not supported.', type: 'oauth', docsUrl: 'https://docs.devin.ai/cli/troubleshooting', docsLabelKey: 'devinDocsLink' },
    'minimax-code': { placeholder: l => l === 'tr' ? 'MiniMax API Key veya Token' : 'MiniMax API Key or Token', help: l => l === 'tr' ? 'MiniMax Code token plan erişim anahtarı' : 'MiniMax Code token-plan access key', type: 'api_key' },
    'cline-pass': { placeholder: () => 'ClinePass API Key', help: l => l === 'tr' ? 'Cline kullanım kotası API anahtarı' : 'Cline usage quota API key', type: 'api_key' },
    'umans': { placeholder: () => 'Umans API Key', help: l => l === 'tr' ? 'Umans Code kullanım API anahtarı' : 'Umans Code usage API key', type: 'api_key' },
    'google-gemini-cli': { placeholder: () => 'Google OAuth Access Token', help: l => l === 'tr' ? 'Gemini CLI OAuth erişim tokenı' : 'Gemini CLI OAuth access token', type: 'oauth' },
    'kimi-code': { placeholder: () => 'Kimi Code OAuth Token', help: l => l === 'tr' ? 'Kimi Code abonelik OAuth tokenı' : 'Kimi Code subscription OAuth token', type: 'oauth' },
    'opencode-go': { placeholder: () => 'OpenCode Go API Key', help: l => l === 'tr' ? 'Aktif OpenCode Go aboneliği API anahtarı' : 'API key for an active OpenCode Go subscription', type: 'api_key' },
    'alibaba-token-plan': { placeholder: l => l === 'tr' ? 'Alibaba Token Plan Key / Cookie' : 'Alibaba Token Plan Key / Cookie', help: l => l === 'tr' ? 'Bailian/Qwen token plan anahtarı veya konsol oturumu' : 'Bailian/Qwen token-plan key or console session', type: 'api_key' },
  };
  const h = hints[p];
  if (h) return { placeholder: h.placeholder(lang), help: h.help(lang), type: h.type, docsUrl: h.docsUrl, docsLabelKey: h.docsLabelKey };
  return { placeholder: lang === 'tr' ? 'Secret veya API Anahtarı' : 'Secret or API Key', help: lang === 'tr' ? 'Sağlayıcı erişim anahtarı' : 'Provider access credential', type: 'api_key' };
}

const MANUAL_PROVIDERS = [
  { value: 'antigravity', label: 'Antigravity (Google AI Pro)' },
  { value: 'openai-codex', label: 'OpenAI ChatGPT / Codex' },
  { value: 'github-copilot', label: 'GitHub Copilot' },
  { value: 'cursor', label: 'Cursor' },
  { value: 'anthropic', label: 'Anthropic Claude' },
  { value: 'openrouter', label: 'OpenRouter' },
  { value: 'deepseek', label: 'DeepSeek' },
  { value: 'xai-oauth', label: 'xAI Grok' },
  { value: 'zai', label: 'Zhipu AI (GLM)' },
  { value: 'minimax-code', label: 'MiniMax Code' },
  { value: 'cline-pass', label: 'Cline Pass' },
  { value: 'devin', label: 'Devin' },
  { value: 'umans', label: 'Umans' },
  { value: 'google-gemini-cli', label: 'Gemini CLI' },
  { value: 'kimi-code', label: 'Kimi Code' },
  { value: 'opencode-go', label: 'OpenCode Go' },
  { value: 'alibaba-token-plan', label: 'Alibaba Qwen' },
];

// ── Dashboard Component ──
function Dashboard() {
  const bootstrapEl = document.getElementById('usemeter-bootstrap');
  const bootstrap: BootstrapData = bootstrapEl ? JSON.parse(bootstrapEl.textContent || '{}') : { reports: [], user: null };
  const user = bootstrap.user;

  const [lang, setLang] = useState(detectInitialLang);
  const [mode, setMode] = useState(() => localStorage.getItem('usage_mode') || 'dark');
  const [accent, setAccent] = useState(() => localStorage.getItem('usage_accent') || 'amber');
  const [currentSort, setSort] = useState(() => localStorage.getItem('usage_sort') || 'custom');
  const [currentGroup, setGroup] = useState(() => localStorage.getItem('usage_group') || 'none');
  const [isEditMode, setEditMode] = useState(false);
  const [editingCardId, setEditingCardId] = useState<string | null>(null);
  const [reports, setReports] = useState<Report[]>(bootstrap.reports || []);
  const [lastPolledAt, setLastPolledAt] = useState(Date.now());
  const [syncText, setSyncText] = useState(() => t('syncStatusJustNow', detectInitialLang()));

  // Modal state
  const [showSettings, setShowSettings] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [modalTab, setModalTab] = useState<'oauth' | 'manual'>('oauth');

  // OAuth state
  const [oauthPanel, setOauthPanel] = useState<'list' | 'device' | 'browser'>('list');
  const [deviceCode, setDeviceCode] = useState('');
  const [deviceBadge, setDeviceBadge] = useState('OAuth');
  const [deviceAuthLink, setDeviceAuthLink] = useState('');
  const [browserAuthText, setBrowserAuthText] = useState('');
  const [browserAuthLink, setBrowserAuthLink] = useState('');
  const [manualOAuthCallback, setManualOAuthCallback] = useState(false);
  const [manualOAuthInputType, setManualOAuthInputType] = useState<'url' | 'code' | null>(null);
  const [manualOAuthProviderName, setManualOAuthProviderName] = useState('');
  const [manualOAuthRedirectUri, setManualOAuthRedirectUri] = useState('');
  const [manualOAuthSessionId, setManualOAuthSessionId] = useState('');
  const [manualOAuthInput, setManualOAuthInput] = useState('');
  const [manualOAuthSubmitting, setManualOAuthSubmitting] = useState(false);
  const [manualOAuthError, setManualOAuthError] = useState('');
  const [copyBtnText, setCopyBtnText] = useState(() => t('copyCode', detectInitialLang()));
  const oauthSessionRef = useRef<string | null>(null);
  const oauthInitiateAbortRef = useRef<AbortController | null>(null);
  const oauthTimerRef = useRef<number | null>(null);
  const oauthAbortRef = useRef<AbortController | null>(null);
  const oauthRunIdRef = useRef(0);
  const oauthRestartRef = useRef<(() => void) | null>(null);
  const [oauthNotice, setOauthNotice] = useState('');
  const [oauthFailed, setOauthFailed] = useState(false);
  const [oauthRestartRequired, setOauthRestartRequired] = useState(false);

  // Manual form state
  const [manualProvider, setManualProvider] = useState('antigravity');
  const [manualSaving, setManualSaving] = useState(false);

  // Drag state
  const draggedRef = useRef<string | null>(null);

  // Poll spinner
  const [pollSpinning, setPollSpinning] = useState(false);

  // ── Apply mode ──
  useEffect(() => {
    const isDark = mode === 'dark';
    document.documentElement.classList.toggle('dark', isDark);
    document.documentElement.classList.toggle('light', !isDark);
    localStorage.setItem('usage_mode', mode);
  }, [mode]);
  // ── OAuth unmount cleanup ──
  useEffect(() => {
    return () => {
      oauthRunIdRef.current += 1;
      clearOAuthTimer();
      cancelTrackedOAuthSession();
      if (oauthAbortRef.current) {
        oauthAbortRef.current.abort();
        oauthAbortRef.current = null;
      }
    };
  }, []);


  // ── Apply accent ──
  useEffect(() => {
    localStorage.setItem('usage_accent', accent);
    const pal = THEME_ACCENTS[accent] || THEME_ACCENTS['amber'];
    const root = document.documentElement;
    root.style.setProperty('--color-accent', pal.accent);
    root.style.setProperty('--color-accent-hover', pal.accentHover);
    root.style.setProperty('--color-accent-soft', pal.accentSoft);
  }, [accent]);

  // ── Sync status timer ──
  useEffect(() => {
    const interval = setInterval(() => {
      const elapsedSec = Math.max(0, Math.floor((Date.now() - lastPolledAt) / 1000));
      if (elapsedSec < 5) setSyncText(t('syncStatusJustNow', lang));
      else if (elapsedSec < 60) setSyncText(t('syncStatusSec', lang).replace('{n}', String(elapsedSec)));
      else setSyncText(t('syncStatusMin', lang).replace('{n}', String(Math.floor(elapsedSec / 60))));
    }, 1000);
    return () => clearInterval(interval);
  }, [lastPolledAt, lang]);

  // ── Polling ──
  const loadUsage = useCallback(async () => {
    try {
      const [dataRes, credsRes] = await Promise.all([
        fetch('/api/data'),
        fetch('/api/credentials').catch(() => null),
      ]);
      if (dataRes.ok) {
        const dataJson = await dataRes.json();
        let newReports: Report[] = dataJson.data || [];
        if (credsRes && credsRes.ok) {
          try {
            const credsJson = await credsRes.json();
            const credsList: Array<{ id: string; createdAt?: number; accent?: string }> = credsJson.data || [];
            const credsMap: Record<string, typeof credsList[number]> = {};
            credsList.forEach(c => { credsMap[c.id] = c; });
            newReports = newReports.map(r => {
              const cr = r.credentialId ? credsMap[r.credentialId] : undefined;
              const dbAccent = cr?.accent || r.accent || 'default';
              return { ...r, createdAt: r.createdAt || cr?.createdAt, accent: dbAccent };
            });
          } catch { /* ignore */ }
        }
        setReports(newReports);
        setLastPolledAt(Date.now());
      }
    } catch (err) {
      console.warn('Silent live sync failure:', err);
    }
  }, []);

  useEffect(() => {
    const interval = setInterval(loadUsage, 10000);
    return () => clearInterval(interval);
  }, [loadUsage]);

  // ── Computed summary ──
  const { activeCount, totalBalance, exhaustedCount } = useMemo(() => {
    let totalBal = 0;
    let exhausted = 0;
    for (const r of reports) {
      for (const l of r.limits || []) {
        if (l.amount?.unit === 'usd' && typeof l.amount.remaining === 'number') {
          const id = String(l.id || '');
          if (id.includes('balance') || id.includes('credits')) totalBal += l.amount.remaining;
        }
        if (l.status === 'exhausted') exhausted++;
      }
    }
    return { activeCount: reports.length, totalBalance: totalBal, exhaustedCount: exhausted };
  }, [reports]);

  // ── Sorted/grouped reports ──
  const effectiveSort = isEditMode ? 'custom' : currentSort;
  const sortedReports = useMemo(() => sortReports(reports, effectiveSort), [reports, effectiveSort]);

  const groupedReports = useMemo(() => {
    if (currentGroup !== 'provider') return null;
    const groups: Record<string, Report[]> = {};
    sortedReports.forEach(r => {
      const p = r.provider || 'other';
      if (!groups[p]) groups[p] = [];
      groups[p].push(r);
    });
    return groups;
  }, [sortedReports, currentGroup]);

  // ── Handlers ──
  function toggleLang() {
    const newLang = lang === 'tr' ? 'en' : 'tr';
    setLang(newLang);
    localStorage.setItem('usage_lang', newLang);
  }

  function toggleEditMode() {
    if (currentGroup !== 'none') return;
    setEditMode(prev => {
      if (!prev) {
        setSort('custom');
        localStorage.setItem('usage_sort', 'custom');
      }
      setEditingCardId(null);
      return !prev;
    });
  }

  function handleGroupChange(val: string) {
    const g = val === 'provider' ? 'provider' : 'none';
    setGroup(g);
    localStorage.setItem('usage_group', g);
    if (g !== 'none' && isEditMode) {
      setEditMode(false);
      setEditingCardId(null);
    }
  }

  function handleSortChange(val: string) {
    if (isEditMode) return;
    const allowed = ['custom', 'date_added', 'highest_available', 'lowest_available'];
    const s = allowed.includes(val) ? val : 'custom';
    setSort(s);
    localStorage.setItem('usage_sort', s);
  }

  async function pollNow() {
    setPollSpinning(true);
    try {
      await fetch('/api/poll', { method: 'POST' });
      await loadUsage();
    } finally {
      setPollSpinning(false);
    }
  }

  async function logoutUser() {
    try { await fetch('/api/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
    window.location.href = '/login';
  }

  // ── Label/accent save ──
  async function saveAccountLabel(cardKey: string, newLabel: string) {
    const trimmed = (newLabel || '').trim();
    if (!cardKey || !trimmed) { setEditingCardId(null); return; }
    try {
      const res = await fetch('/api/credentials/' + encodeURIComponent(cardKey), {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountLabel: trimmed }),
      });
      const json = await res.json();
      if (json.success) {
        setReports(prev => prev.map(r => (r.credentialId || r.provider) === cardKey ? { ...r, accountLabel: trimmed } : r));
      }
    } catch (err) { console.error('Failed to update account label:', err); }
    finally { setEditingCardId(null); }
  }

  async function saveAccountAccent(cardKey: string, accentKey: string) {
    if (!cardKey) return;
    const targetAccent = (!accentKey || accentKey === 'null' || accentKey === 'default') ? 'default' : accentKey;
    setReports(prev => prev.map(r => (r.credentialId || r.provider) === cardKey ? { ...r, accent: targetAccent } : r));
    try {
      const res = await fetch('/api/credentials/' + encodeURIComponent(cardKey), {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accent: targetAccent }),
      });
      const json = await res.json();
      if (!json.success) console.warn('Failed to persist accent:', json.error);
    } catch (err) { console.error('Failed to update accent:', err); }
  }

  const deleteAccount = useCallback(async (id: string) => {
    if (!id || !window.confirm(t('deleteConfirm', lang))) return;
    try {
      const response = await fetch('/api/credentials/' + encodeURIComponent(id), { method: 'DELETE' });
      const result = await response.json() as { success?: boolean };
      if (!response.ok || result.success !== true) {
        window.alert(t('deleteFailed', lang));
        return;
      }

      setReports(prev => prev.filter(r => r.credentialId !== id));
      setEditingCardId(prev => prev === id ? null : prev);
      if (draggedRef.current === id) draggedRef.current = null;
      try {
        const savedOrder = localStorage.getItem('usage_custom_order');
        if (savedOrder) {
          const order: unknown = JSON.parse(savedOrder);
          if (Array.isArray(order)) {
            localStorage.setItem('usage_custom_order', JSON.stringify(order.filter(key => key !== id)));
          }
        }
      } catch { /* ignore invalid or unavailable local ordering */ }
      await loadUsage();
    } catch {
      window.alert(t('deleteFailed', lang));
    }
  }, [lang, loadUsage]);


  // ── Drag handlers ──
  function onDragStart(e: DragEvent<HTMLDivElement>, id: string) {
    if (!isEditMode || currentGroup !== 'none') return;
    if (currentSort !== 'custom') {
      setSort('custom');
      localStorage.setItem('usage_sort', 'custom');
    }
    draggedRef.current = id;
    e.dataTransfer.effectAllowed = 'move';
    e.currentTarget.classList.add('opacity-40');
  }
  function onDragOver(e: DragEvent<HTMLDivElement>) {
    if (!isEditMode || currentGroup !== 'none') return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    e.currentTarget.classList.add('drag-over');
  }
  function onDragLeave(e: DragEvent<HTMLDivElement>) {
    e.currentTarget.classList.remove('drag-over');
  }
  function onDrop(e: DragEvent<HTMLDivElement>, targetId: string) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
    const draggedId = draggedRef.current;
    if (!isEditMode || currentGroup !== 'none' || !draggedId || draggedId === targetId) return;
    setReports(prev => {
      const fromIdx = prev.findIndex(r => (r.credentialId || r.provider) === draggedId);
      const toIdx = prev.findIndex(r => (r.credentialId || r.provider) === targetId);
      if (fromIdx === -1 || toIdx === -1) return prev;
      const next = [...prev];
      const [moved] = next.splice(fromIdx, 1);
      next.splice(toIdx, 0, moved);
      const customOrder = next.map(r => r.credentialId || r.provider);
      localStorage.setItem('usage_custom_order', JSON.stringify(customOrder));
      return next;
    });
  }
  function onDragEnd(e: DragEvent<HTMLDivElement>) {
    draggedRef.current = null;
    e.currentTarget.classList.remove('opacity-40', 'drag-over');
  }

  // ── OAuth flow handlers ──
  const DEFAULT_OAUTH_EXPIRES_IN_SEC = 600;
  const OAUTH_REQUEST_TIMEOUT_MS = 12000;

  function clearOAuthTimer() {
    if (oauthTimerRef.current !== null) {
      window.clearTimeout(oauthTimerRef.current);
      oauthTimerRef.current = null;
    }
  }

  function cancelOAuthSession(sessionId: string) {
    void fetch(`/api/oauth/sessions/${encodeURIComponent(sessionId)}`, {
      method: 'DELETE',
      keepalive: true,
    }).catch(() => {});
  }

  function cancelTrackedOAuthSession() {
    const sessionId = oauthSessionRef.current;
    oauthSessionRef.current = null;
    if (sessionId) cancelOAuthSession(sessionId);
  }

  function cancelOAuth() {
    oauthRunIdRef.current += 1;
    cancelTrackedOAuthSession();
    clearOAuthTimer();
    if (oauthAbortRef.current) {
      oauthAbortRef.current.abort();
      oauthAbortRef.current = null;
    }
    oauthRestartRef.current = null;
    setOauthPanel('list');
    setOauthNotice('');
    setOauthFailed(false);
    setOauthRestartRequired(false);
    setDeviceCode('');
    setDeviceBadge('OAuth');
    setDeviceAuthLink('');
    setBrowserAuthText('');
    setBrowserAuthLink('');
    setManualOAuthCallback(false);
    setManualOAuthInputType(null);
    setManualOAuthProviderName('');
    setManualOAuthRedirectUri('');
    setManualOAuthSessionId('');
    setManualOAuthInput('');
    setManualOAuthSubmitting(false);
    setManualOAuthError('');
  }

  function failOAuth(message: string, runId: number, restartRequired = false) {
    if (runId !== oauthRunIdRef.current) return;
    oauthRunIdRef.current += 1;
    cancelTrackedOAuthSession();
    clearOAuthTimer();
    if (oauthAbortRef.current) {
      oauthAbortRef.current.abort();
      oauthAbortRef.current = null;
    }
    setOauthFailed(true);
    setOauthRestartRequired(restartRequired);
    setOauthNotice(message);
    if (restartRequired) {
      setManualOAuthCallback(false);
      setManualOAuthInputType(null);
      setManualOAuthSessionId('');
      setManualOAuthInput('');
      setManualOAuthSubmitting(false);
      setManualOAuthError('');
    }
  }

  function finishOAuth(runId: number) {
    if (runId !== oauthRunIdRef.current) return;
    oauthRunIdRef.current += 1;
    oauthSessionRef.current = null;
    clearOAuthTimer();
    if (oauthAbortRef.current) {
      oauthAbortRef.current.abort();
      oauthAbortRef.current = null;
    }
    closeAddModal();
    void loadUsage();
  }

  async function readOAuthJson(res: Response): Promise<Record<string, unknown> | null> {
    const value: unknown = await res.json().catch(() => null);
    return value && typeof value === 'object' && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  }

  function oauthMessage(key: string, detail?: string) {
    const message = t(key, lang);
    return detail ? `${message}: ${detail}` : message;
  }

  function oauthResponseMessage(key: string, body: Record<string, unknown> | null) {
    if (body?.['errorCode'] === 'OAUTH_CAPACITY') return t('oauthCapacity', lang);
    const detail = typeof body?.['error'] === 'string' ? body['error'].trim() : '';
    return oauthMessage(key, detail || undefined);
  }

  function oauthExpiry(data: Record<string, unknown>, fallbackSeconds = DEFAULT_OAUTH_EXPIRES_IN_SEC): number {
    const raw = data['expiresIn'] ?? data['expires_in'];
    if (raw !== undefined && raw !== null) {
      const expiresIn = Number(raw);
      if (Number.isFinite(expiresIn) && expiresIn > 0) {
        return Date.now() + Math.max(0, expiresIn * 1000);
      }
    }
    return Date.now() + fallbackSeconds * 1000;
  }

  function retryDelayMs(res: Response, body: Record<string, unknown> | null) {
    const retryAfter = res.headers.get('Retry-After');
    if (retryAfter) {
      const seconds = Number(retryAfter);
      if (Number.isFinite(seconds) && seconds >= 0) return Math.max(1000, seconds * 1000);
      const retryAt = Date.parse(retryAfter);
      if (Number.isFinite(retryAt)) return Math.max(1000, retryAt - Date.now());
    }
    const bodySeconds = Number(body?.['retryAfter']);
    return Number.isFinite(bodySeconds) && bodySeconds >= 0
      ? Math.max(1000, bodySeconds * 1000)
      : null;
  }

  function showRetryNotice(delayMs: number) {
    setOauthNotice(t('oauthRetrying', lang).replace('{seconds}', String(Math.ceil(delayMs / 1000))));
  }

  function scheduleOAuthPoll(runId: number, poll: () => Promise<void>, delayMs: number, expiresAt: number) {
    if (runId !== oauthRunIdRef.current) return;
    clearOAuthTimer();
    const remainingMs = Math.max(0, expiresAt - Date.now());
    if (remainingMs <= 0) {
      failOAuth(t('oauthExpired', lang), runId);
      return;
    }
    const waitMs = Math.min(delayMs, remainingMs);
    oauthTimerRef.current = window.setTimeout(() => {
      oauthTimerRef.current = null;
      if (runId !== oauthRunIdRef.current) return;
      if (Date.now() >= expiresAt) {
        failOAuth(t('oauthExpired', lang), runId);
        return;
      }
      void poll();
    }, waitMs);
  }

  function closeAddModal() {
    cancelOAuth();
    setShowModal(false);
  }

  async function startBrowserOAuth(endpoint: string, providerName: string) {
    cancelOAuth();
    const runId = oauthRunIdRef.current;
    oauthRestartRef.current = () => { void startBrowserOAuth(endpoint, providerName); };
    setOauthPanel('browser');
    setBrowserAuthText(t('oauthWaiting', lang).replace('{provider}', providerName));
    setBrowserAuthLink('');
    setDeviceAuthLink('');
    setDeviceCode('');
    setDeviceBadge('OAuth');
    setOauthFailed(false);
    setOauthRestartRequired(false);
    setOauthNotice('');
    setManualOAuthCallback(false);
    setManualOAuthInputType(null);
    setManualOAuthProviderName('');
    setManualOAuthRedirectUri('');
    setManualOAuthSessionId('');
    setManualOAuthInput('');
    setManualOAuthSubmitting(false);
    setManualOAuthError('');
    const initiateController = new AbortController();
    oauthInitiateAbortRef.current = initiateController;
    let initiateTimedOut = false;
    const initiateTimer = window.setTimeout(() => {
      initiateTimedOut = true;
      initiateController.abort();
    }, OAUTH_REQUEST_TIMEOUT_MS);

    try {
      const res = await fetch(`/api/oauth/${endpoint}/initiate`, {
        method: 'POST',
        signal: initiateController.signal,
      });
      const json = await readOAuthJson(res);
      const data = json?.['data'] && typeof json['data'] === 'object' && !Array.isArray(json['data'])
        ? json['data'] as Record<string, unknown>
        : null;
      const sessionId = typeof data?.['sessionId'] === 'string' ? data['sessionId'] : '';
      if (runId !== oauthRunIdRef.current) {
        if (sessionId) cancelOAuthSession(sessionId);
        return;
      }
      if (!res.ok || !json || json['success'] !== true) {
        if (sessionId) oauthSessionRef.current = sessionId;
        failOAuth(oauthResponseMessage('oauthRequestFailure', json), runId);
        return;
      }
      if (!data) {
        failOAuth(t('oauthRequestFailure', lang), runId);
        return;
      }
      if (sessionId) oauthSessionRef.current = sessionId;
      const authUrl = typeof data['authUrl'] === 'string' ? data['authUrl'] : '';
      if (!authUrl || !sessionId) {
        failOAuth(t('oauthRequestFailure', lang), runId);
        return;
      }
      const manualCallback = data['manualCallback'] === true;
      const manualInput = data['manualInput'] === 'url' || data['manualInput'] === 'code'
        ? data['manualInput']
        : null;
      if (manualCallback && !manualInput) {
        failOAuth(t('oauthRequestFailure', lang), runId);
        return;
      }
      setManualOAuthCallback(manualCallback);
      setManualOAuthInputType(manualCallback ? manualInput : null);
      setManualOAuthRedirectUri(manualCallback && typeof data['redirectUri'] === 'string' ? data['redirectUri'] : '');
      setManualOAuthSessionId(manualCallback ? sessionId : '');
      setManualOAuthProviderName(manualCallback ? providerName : '');
      setBrowserAuthLink(authUrl);
      window.open(authUrl, '_blank');
      const expiresAt = oauthExpiry(data);

      const pollStatus = async () => {
        if (runId !== oauthRunIdRef.current) return;
        if (Date.now() >= expiresAt) {
          failOAuth(t('oauthExpired', lang), runId);
          return;
        }

        const remainingFlowMs = expiresAt - Date.now();
        const requestTimeoutMs = Math.min(OAUTH_REQUEST_TIMEOUT_MS, Math.max(100, remainingFlowMs));
        const pollController = new AbortController();
        oauthAbortRef.current = pollController;
        let didTimeout = false;
        const pollTimer = window.setTimeout(() => {
          didTimeout = true;
          pollController.abort();
        }, requestTimeoutMs);

        try {
          const statusRes = await fetch(`/api/oauth/status/${encodeURIComponent(sessionId)}`, {
            signal: pollController.signal,
          });
          const statusJson = await readOAuthJson(statusRes);
          if (runId !== oauthRunIdRef.current) return;
          if (statusRes.status === 429) {
            const retryMs = retryDelayMs(statusRes, statusJson);
            if (retryMs !== null) {
              showRetryNotice(retryMs);
              scheduleOAuthPoll(runId, pollStatus, retryMs, expiresAt);
              return;
            }
          }
          if (!statusRes.ok) {
            failOAuth(oauthResponseMessage(statusRes.status === 404 ? 'oauthSessionNotFound' : 'oauthPollFailure', statusJson), runId);
            return;
          }
          if (statusJson?.['status'] === 'complete') {
            finishOAuth(runId);
          } else if (statusJson?.['status'] === 'error') {
            const restartRequired = statusJson['restartRequired'] === true;
            failOAuth(
              restartRequired ? t('oauthFinalizationRestart', lang) : oauthResponseMessage('oauthFailed', statusJson),
              runId,
              restartRequired,
            );
          } else if (statusJson?.['status'] === 'pending') {
            setOauthNotice('');
            scheduleOAuthPoll(runId, pollStatus, 2000, expiresAt);
          } else {
            failOAuth(t('oauthPollFailure', lang), runId);
          }
        } catch (err) {
          if (runId !== oauthRunIdRef.current) return;
          if (pollController.signal.aborted) {
            if (Date.now() >= expiresAt) {
              failOAuth(t('oauthExpired', lang), runId);
            } else if (didTimeout) {
              failOAuth(t('oauthTimeout', lang), runId);
            }
            return;
          }
          failOAuth(oauthMessage('oauthNetworkFailure', err instanceof Error ? err.message : String(err)), runId);
        } finally {
          window.clearTimeout(pollTimer);
          if (oauthAbortRef.current === pollController) {
            oauthAbortRef.current = null;
          }
        }
      };

      if (expiresAt <= Date.now()) {
        failOAuth(t('oauthExpired', lang), runId);
      } else {
        scheduleOAuthPoll(runId, pollStatus, 2000, expiresAt);
      }
    } catch (err) {
      if (runId !== oauthRunIdRef.current) return;
      if (initiateController.signal.aborted && initiateTimedOut) {
        failOAuth(t('oauthTimeout', lang), runId);
        return;
      }
      failOAuth(oauthMessage('oauthNetworkFailure', err instanceof Error ? err.message : String(err)), runId);
    } finally {
      window.clearTimeout(initiateTimer);
      if (oauthInitiateAbortRef.current === initiateController) {
        oauthInitiateAbortRef.current = null;
      }
    }
  }

  async function submitManualOAuthCallback(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const sessionId = manualOAuthSessionId;
    const callbackInput = manualOAuthInput;
    if (
      manualOAuthSubmitting
      || !manualOAuthCallback
      || !manualOAuthInputType
      || !sessionId
      || oauthSessionRef.current !== sessionId
      || !callbackInput.trim()
    ) return;

    const runId = oauthRunIdRef.current;
    const controller = new AbortController();
    let didTimeout = false;
    setManualOAuthSubmitting(true);
    setManualOAuthError('');
    oauthAbortRef.current = controller;
    const timeout = window.setTimeout(() => {
      didTimeout = true;
      controller.abort();
    }, OAUTH_REQUEST_TIMEOUT_MS);

    try {
      const res = await fetch('/api/oauth/manual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, callbackInput }),
        signal: controller.signal,
      });
      const json = await readOAuthJson(res);
      if (runId !== oauthRunIdRef.current || sessionId !== manualOAuthSessionId) return;
      if (res.status === 429 && json?.['restartRequired'] === true) {
        failOAuth(t('oauthFinalizationRestart', lang), runId, true);
        return;
      }
      if (!res.ok || !json || json['success'] !== true) {
        setManualOAuthError(t('manualOAuthFailure', lang));
        return;
      }
      finishOAuth(runId);
    } catch {
      if (runId === oauthRunIdRef.current && sessionId === manualOAuthSessionId) {
        setManualOAuthError(
          t(didTimeout ? 'oauthTimeout' : 'manualOAuthNetworkFailure', lang),
        );
      }
    } finally {
      window.clearTimeout(timeout);
      if (oauthAbortRef.current === controller) oauthAbortRef.current = null;
      if (runId === oauthRunIdRef.current && sessionId === manualOAuthSessionId) {
        setManualOAuthSubmitting(false);
      }
    }
  }

  async function startOAuthPoll(
    endpoint: string,
    badgeName: string,
    pollEndpoint: string,
    bodyKeys: string[],
    panel: 'device' | 'browser' = 'device',
  ) {
    cancelOAuth();
    const runId = oauthRunIdRef.current;
    oauthRestartRef.current = () => { void startOAuthPoll(endpoint, badgeName, pollEndpoint, bodyKeys, panel); };
    setOauthPanel(panel);
    setOauthFailed(false);
    setOauthRestartRequired(false);
    setOauthNotice('');
    setBrowserAuthLink('');
    setDeviceAuthLink('');
    setDeviceCode('');
    if (panel === 'device') {
      setDeviceBadge(badgeName);
    } else {
      setDeviceBadge('OAuth');
      setBrowserAuthText(t('oauthWaiting', lang).replace('{provider}', badgeName));
    }
    setManualOAuthInputType(null);
    setManualOAuthProviderName('');
    setManualOAuthRedirectUri('');
    setManualOAuthSessionId('');
    setManualOAuthInput('');
    setManualOAuthSubmitting(false);
    setManualOAuthError('');

    const initiateController = new AbortController();
    oauthInitiateAbortRef.current = initiateController;
    let initiateTimedOut = false;
    const initiateTimer = window.setTimeout(() => {
      initiateTimedOut = true;
      initiateController.abort();
    }, OAUTH_REQUEST_TIMEOUT_MS);

    try {
      const res = await fetch(`/api/oauth/${endpoint}/initiate`, {
        method: 'POST',
        signal: initiateController.signal,
      });
      const json = await readOAuthJson(res);
      const data = json?.['data'] && typeof json['data'] === 'object' && !Array.isArray(json['data'])
        ? json['data'] as Record<string, unknown>
        : null;
      const sessionId = typeof data?.['sessionId'] === 'string' ? data['sessionId'] : '';
      if (runId !== oauthRunIdRef.current) {
        if (sessionId) cancelOAuthSession(sessionId);
        return;
      }
      if (!res.ok || !json || json['success'] !== true) {
        if (sessionId) oauthSessionRef.current = sessionId;
        failOAuth(oauthResponseMessage('oauthRequestFailure', json), runId);
        return;
      }
      if (!data) {
        failOAuth(t('oauthRequestFailure', lang), runId);
        return;
      }
      if (sessionId) oauthSessionRef.current = sessionId;
      const missingBodyKey = bodyKeys.find(key => {
        const value = data[key];
        return value === undefined || value === null || (typeof value === 'string' && !value.trim());
      });
      const authUrlValue = panel === 'browser'
        ? data['authUrl']
        : data['verificationUrl'] || data['verificationUri'];
      const authUrl = typeof authUrlValue === 'string' ? authUrlValue : '';
      if (!sessionId || missingBodyKey || !authUrl || (panel === 'device' && typeof data['userCode'] !== 'string')) {
        failOAuth(t('oauthRequestFailure', lang), runId);
        return;
      }
      const body: Record<string, unknown> = {};
      for (const key of bodyKeys) body[key] = data[key];
      if (panel === 'device') {
        setDeviceCode(data['userCode'] as string);
        setDeviceAuthLink(authUrl);
        if (typeof data['userCode'] === 'string' && data['userCode'].trim()) {
          try { await navigator.clipboard.writeText(data['userCode']); } catch { /* ignore */ }
        }
      } else {
        setBrowserAuthLink(authUrl);
      }
      if (runId !== oauthRunIdRef.current) return;
      window.open(authUrl, '_blank');

      const rawInterval = Number(data['interval']);
      let intervalMs = Number.isFinite(rawInterval) && rawInterval > 0 ? rawInterval * 1000 : 5000;
      const expiresAt = oauthExpiry(data);

      const poll = async () => {
        if (runId !== oauthRunIdRef.current) return;
        if (Date.now() >= expiresAt) {
          failOAuth(t('oauthExpired', lang), runId);
          return;
        }

        const remainingFlowMs = expiresAt - Date.now();
        const requestTimeoutMs = Math.min(OAUTH_REQUEST_TIMEOUT_MS, Math.max(100, remainingFlowMs));
        const pollController = new AbortController();
        oauthAbortRef.current = pollController;
        let didTimeout = false;
        const pollTimer = window.setTimeout(() => {
          didTimeout = true;
          pollController.abort();
        }, requestTimeoutMs);

        try {
          const pollRes = await fetch(`/api/oauth/${pollEndpoint}/poll`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: pollController.signal,
          });
          const pollJson = await readOAuthJson(pollRes);
          if (runId !== oauthRunIdRef.current) return;
          if (pollRes.status === 429 && pollJson?.['restartRequired'] === true) {
            failOAuth(t('oauthFinalizationRestart', lang), runId, true);
            return;
          }
          if (pollRes.status === 429) {
            const retryMs = retryDelayMs(pollRes, pollJson);
            if (retryMs !== null) {
              showRetryNotice(retryMs);
              scheduleOAuthPoll(runId, poll, retryMs, expiresAt);
              return;
            }
          }
          if (!pollRes.ok) {
            failOAuth(oauthResponseMessage(pollRes.status === 404 ? 'oauthSessionNotFound' : 'oauthPollFailure', pollJson), runId);
            return;
          }
          if (pollJson?.['status'] === 'complete') {
            finishOAuth(runId);
          } else if (pollJson?.['status'] === 'error') {
            failOAuth(oauthResponseMessage('oauthFailed', pollJson), runId);
          } else if (pollJson?.['status'] === 'slow_down') {
            const serverInterval = Number(pollJson['interval']);
            intervalMs = Math.max(
              intervalMs + 5000,
              Number.isFinite(serverInterval) && serverInterval > 0 ? serverInterval * 1000 : 0,
            );
            showRetryNotice(intervalMs);
            scheduleOAuthPoll(runId, poll, intervalMs, expiresAt);
          } else if (pollJson?.['status'] === 'pending') {
            setOauthNotice('');
            scheduleOAuthPoll(runId, poll, intervalMs, expiresAt);
          } else {
            failOAuth(t('oauthPollFailure', lang), runId);
          }
        } catch (err) {
          if (runId !== oauthRunIdRef.current) return;
          if (pollController.signal.aborted) {
            if (Date.now() >= expiresAt) {
              failOAuth(t('oauthExpired', lang), runId);
            } else if (didTimeout) {
              failOAuth(t('oauthTimeout', lang), runId);
            }
            return;
          }
          failOAuth(oauthMessage('oauthNetworkFailure', err instanceof Error ? err.message : String(err)), runId);
        } finally {
          window.clearTimeout(pollTimer);
          if (oauthAbortRef.current === pollController) {
            oauthAbortRef.current = null;
          }
        }
      };

      if (expiresAt <= Date.now()) {
        failOAuth(t('oauthExpired', lang), runId);
      } else {
        scheduleOAuthPoll(runId, poll, intervalMs, expiresAt);
      }
    } catch (err) {
      if (runId !== oauthRunIdRef.current) return;
      if (initiateController.signal.aborted && initiateTimedOut) {
        failOAuth(t('oauthTimeout', lang), runId);
        return;
      }
      failOAuth(oauthMessage('oauthNetworkFailure', err instanceof Error ? err.message : String(err)), runId);
    } finally {
      window.clearTimeout(initiateTimer);
      if (oauthInitiateAbortRef.current === initiateController) {
        oauthInitiateAbortRef.current = null;
      }
    }
  }

  function handleOAuthProviderClick(handler: string) {
    if (handler === 'google') startBrowserOAuth('google', t('googleTitle', lang));
    else if (handler === 'claude') startBrowserOAuth('claude', t('claudeTitle', lang));
    else if (handler === 'gemini-cli') startBrowserOAuth('gemini-cli', t('geminiCliTitle', lang));
    else if (handler === 'zai') startBrowserOAuth('zai', t('zaiTitle', lang));
    else if (handler === 'cursor') startOAuthPoll('cursor', 'Cursor', 'cursor', ['uuid', 'verifier'], 'browser');
    else if (handler === 'openrouter') startBrowserOAuth('openrouter', t('openrouterTitle', lang));
    else if (handler === 'devin') {
      cancelOAuth();
      setManualProvider('devin');
      setModalTab('manual');
    }
    else if (handler === 'codex-device') startOAuthPoll('codex', 'OpenAI', 'codex', ['deviceAuthId', 'userCode']);
    else if (handler === 'copilot-device') startOAuthPoll('copilot', 'GitHub Copilot', 'copilot', ['deviceCode']);
    else if (handler === 'xai-device') startOAuthPoll('xai', 'xAI Grok', 'xai', ['deviceCode']);
    else if (handler === 'kimi-device') startOAuthPoll('kimi', 'Kimi Code', 'kimi', ['deviceCode', 'deviceId']);
  }

  async function copyDeviceCode() {
    try {
      await navigator.clipboard.writeText(deviceCode);
      setCopyBtnText(lang === 'tr' ? 'Kopyalandı!' : 'Copied!');
      setTimeout(() => setCopyBtnText(t('copyCode', lang)), 2000);
    } catch (err) { console.warn('Clipboard copy failed:', err); }
  }

  // ── Manual save ──
  async function handleManualSave(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const formData = new FormData(form);
    setManualSaving(true);
    try {
      const body = {
        provider: formData.get('provider') as string,
        accountLabel: formData.get('accountLabel') as string,
        credentialType: formData.get('credentialType') as string,
        secret: formData.get('secret') as string,
        accent: (formData.get('accent') as string) || null,
      };
      const res = await fetch('/api/credentials', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const json = await res.json();
      if (!res.ok || !json.success) {
        alert((lang === 'tr' ? 'Doğrulama Hatası: ' : 'Validation Error: ') + (json.error || 'Unknown error'));
        return;
      }
      closeAddModal();
      (form.querySelector('input[name="secret"]') as HTMLInputElement).value = '';
      void loadUsage();
    } catch (err) {
      alert((lang === 'tr' ? 'Bağlantı Hatası: ' : 'Connection Error: ') + err);
    } finally { setManualSaving(false); }
  }

  const hint = getProviderHint(manualProvider, lang);

  // ── Render ──
  const editBtnDisabled = currentGroup !== 'none';
  const flagText = I18N[lang]?.['flag'] || '🇹🇷';

  return (
    <>
      {/* Header */}
      <header className="border-b border-appBorder bg-appSurface/80 backdrop-blur-md px-4 sm:px-6 py-3 sticky top-0 z-20 transition-colors">
        <div className="max-w-screen-2xl mx-auto flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-wider text-appText text-lg font-mono">use<span className="text-appAccent">Meter</span></span>
              <span id="syncLiveDot" className="w-2 h-2 rounded-full bg-emerald-500 ring-4 ring-emerald-500/20" title={syncText} />
            </div>
            <div className="hidden sm:block h-4 w-px bg-appBorder" />
            <span id="headerSyncStatus" className="text-xs text-appTextMuted tracking-tight font-medium">{syncText}</span>
          </div>

          <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap justify-end">
            {/* Edit */}
            <button onClick={toggleEditMode} id="editModeBtn" title={t(editBtnDisabled ? 'editDisabledGrouped' : 'editModeTitle', lang)} disabled={editBtnDisabled}
              className={`h-9 w-9 rounded-lg border border-appBorder transition flex items-center justify-center text-sm ${editBtnDisabled ? 'opacity-40 cursor-not-allowed' : ''} ${isEditMode ? 'bg-appAccent text-zinc-950' : 'bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent'}`}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
            </button>
            {/* Group */}
            <select id="groupSelect" value={currentGroup} onChange={e => handleGroupChange(e.target.value)}
              className="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent transition outline-none cursor-pointer">
              <option value="none">{t('groupNone', lang)}</option>
              <option value="provider">{t('groupProvider', lang)}</option>
            </select>
            {/* Sort */}
            <select id="sortSelect" value={currentSort} onChange={e => handleSortChange(e.target.value)} disabled={isEditMode}
              className={`h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent transition outline-none cursor-pointer ${isEditMode ? 'opacity-50 cursor-not-allowed' : ''}`}>
              <option value="custom">{t('sortCustom', lang)}</option>
              <option value="date_added">{t('sortDateAdded', lang)}</option>
              <option value="highest_available">{t('sortHighest', lang)}</option>
              <option value="lowest_available">{t('sortLowest', lang)}</option>
            </select>
            {/* Settings */}
            <button onClick={() => setShowSettings(true)} id="settingsBtn" title={t('settingsTitle', lang)}
              className="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            </button>
            {/* Dark/Light */}
            <button onClick={() => setMode(m => m === 'dark' ? 'light' : 'dark')} id="lightDarkBtn" title={t('themeTitle', lang)}
              className="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
              <span>{mode === 'dark' ? '☀️' : '🌙'}</span>
            </button>
            {/* Lang */}
            <button onClick={toggleLang} id="langBtn"
              className="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent/50 transition flex items-center gap-1.5 sm:gap-2">
              <span className="text-base">{flagText}</span>
              <span>{lang.toUpperCase()}</span>
            </button>
            {/* Poll */}
            <button onClick={pollNow} id="pollBtn"
              className="h-9 px-3 sm:px-3.5 rounded-lg text-xs font-semibold bg-appMuted hover:bg-appBorder text-appText transition flex items-center gap-1.5 sm:gap-2 border border-appBorder">
              {pollSpinning && <svg className="animate-spin w-4 h-4 text-appAccent" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>}
              <span>{t('refresh', lang)}</span>
            </button>
            {/* Add account */}
            <button onClick={() => setShowModal(true)}
              className="h-9 px-3.5 sm:px-4 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition flex items-center gap-1.5 shadow-sm">
              <span>+</span><span>{t('addAccountText', lang)}</span>
            </button>
            {/* User/admin/logout */}
            {user && (
              <div className="flex items-center gap-2 border-l border-appBorder pl-2 sm:pl-2.5">
                {user.role === 'admin' && (
                  <a href="/admin" id="adminPanelBtn" title={t('adminTitle', lang)}
                    className="h-9 px-2.5 sm:px-3 rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 transition flex items-center gap-1.5 text-xs font-semibold font-mono">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>{t('adminLink', lang)}</span>
                  </a>
                )}
                <span className="text-xs text-appTextMuted hidden md:inline-block max-w-[150px] truncate" title={user.email}>{user.email}</span>
                <button type="button" onClick={logoutUser} id="logoutBtn" title={t('logoutTitle', lang)}
                  className="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-rose-400 hover:border-rose-500/50 transition flex items-center gap-1.5 text-xs font-semibold cursor-pointer">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                  <span>{t('logoutText', lang)}</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Summary */}
      <section className="border-b border-appBorder bg-appSurface/30 px-4 sm:px-6 py-3.5">
        <div className="max-w-screen-2xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs font-medium">
          <div className="flex items-center gap-4 sm:gap-6 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-appTextMuted">{t('summaryActive', lang)}</span>
              <span id="statActiveCount" className="font-bold text-appText text-sm">{activeCount}</span>
            </div>
            <div className="flex items-center gap-2 border-l border-appBorder pl-4 sm:pl-6">
              <span className="text-appTextMuted">{t('summaryBalance', lang)}</span>
              <span id="statTotalBalance" className="font-bold text-emerald-500 text-sm">${totalBalance.toFixed(2)}</span>
            </div>
            <div className="flex items-center gap-2 border-l border-appBorder pl-4 sm:pl-6">
              <span className="text-appTextMuted">{t('summaryExhausted', lang)}</span>
              <span id="statExhaustedCount" className="font-bold text-appText text-sm">{exhaustedCount}</span>
            </div>
          </div>
          <div className="text-xs text-appTextMuted flex items-center gap-2">
            {isEditMode && <span id="editModeNotice" className="text-appAccent font-semibold animate-pulse">{t('editModeActive', lang)}</span>}
            <span>{t('autoSync', lang)}</span>
            <span className="text-appAccent font-semibold">10s</span>
          </div>
        </div>
      </section>

      {/* Main */}
      <main className="flex-1 max-w-screen-2xl w-full mx-auto p-4 sm:p-6 space-y-6">
        <div id="cardsGrid" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {reports.length === 0 ? (
            <div className="col-span-full py-24 text-center text-appTextMuted text-sm" dangerouslySetInnerHTML={{ __html: t('noAccounts', lang) }} />
          ) : groupedReports ? (
            Object.keys(groupedReports).sort().map(p => (
              <React.Fragment key={p}>
                <div className="col-span-full pt-4 first:pt-0 pb-1.5 border-b border-appBorder flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-appText tracking-tight">{formatProviderTitle(p)}</span>
                    <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-appMuted text-appTextMuted border border-appBorder">{groupedReports[p].length}</span>
                  </div>
                </div>
                {groupedReports[p].map(r => (
                  <AccountCard key={getCardKey(r)} r={r} lang={lang} isEditMode={isEditMode} editingCardId={editingCardId}
                    currentGroup={currentGroup}
                    onStartEditLabel={setEditingCardId} onCancelEditLabel={() => setEditingCardId(null)}
                    onSaveLabel={saveAccountLabel} onSaveAccent={saveAccountAccent} onDeleteAccount={deleteAccount}
                    onDragStart={onDragStart} onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop} onDragEnd={onDragEnd} />
                ))}
              </React.Fragment>
            ))
          ) : (
            sortedReports.map(r => (
              <AccountCard key={getCardKey(r)} r={r} lang={lang} isEditMode={isEditMode} editingCardId={editingCardId}
                currentGroup={currentGroup}
                onStartEditLabel={setEditingCardId} onCancelEditLabel={() => setEditingCardId(null)}
                onSaveLabel={saveAccountLabel} onSaveAccent={saveAccountAccent} onDeleteAccount={deleteAccount}
                onDragStart={onDragStart} onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop} onDragEnd={onDragEnd} />
            ))
          )}
        </div>
      </main>

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={e => { if (e.target === e.currentTarget) setShowSettings(false); }}>
          <div className="bg-appSurface border border-appBorder rounded-2xl max-w-md w-full max-h-[90vh] overflow-y-auto p-5 sm:p-6 space-y-5 shadow-2xl transition-colors">
            <div className="flex justify-between items-center pb-3 border-b border-appBorder">
              <h3 className="font-bold text-appText text-base">{t('settingsTitle', lang)}</h3>
              <button onClick={() => setShowSettings(false)} className="text-appTextMuted hover:text-appText text-lg p-1">✕</button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-appTextMuted mb-2.5">{t('themeAccent', lang)}</label>
                <div className="grid grid-cols-5 gap-2.5">
                  {ACCENT_KEYS.map(ak => (
                    <button key={ak} onClick={() => setAccent(ak)} id={`themeOpt_${ak}`}
                      className="flex flex-col items-center gap-1.5 p-2 rounded-xl border bg-appMuted/50 hover:border-appAccent transition"
                      style={{ borderColor: ak === accent ? 'var(--color-accent)' : 'var(--color-border)' }}>
                      <span className="w-6 h-6 rounded-full" style={{ backgroundColor: ACCENT_COLORS[ak] }} />
                      <span className="text-[11px] font-medium text-appText">{ak.charAt(0).toUpperCase() + ak.slice(1)}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex justify-end pt-3 border-t border-appBorder">
              <button onClick={() => setShowSettings(false)} className="px-4 py-2 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition">{t('close', lang)}</button>
            </div>
          </div>
        </div>
      )}

      {/* Add Account Modal */}
      {showModal && (
        <div id="modal" className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={e => { if (e.target === e.currentTarget) closeAddModal(); }}>
          <div className="bg-appSurface border border-appBorder rounded-2xl max-w-lg w-full max-h-[90vh] overflow-y-auto p-5 sm:p-6 space-y-5 shadow-2xl transition-colors">
            <div className="flex justify-between items-center pb-3 border-b border-appBorder">
              <div>
                <h3 className="font-bold text-appText text-base">{t('modalTitle', lang)}</h3>
                <p className="text-xs text-appTextMuted mt-0.5">{t('modalSubtitle', lang)}</p>
              </div>
              <button onClick={closeAddModal} className="text-appTextMuted hover:text-appText text-lg p-1">✕</button>
            </div>

            {/* Tab switcher */}
            <div className="flex p-1 bg-appMuted rounded-xl border border-appBorder text-xs">
              <button onClick={() => setModalTab('oauth')} id="tabOAuth"
                className={`flex-1 py-2 font-semibold rounded-lg transition ${modalTab === 'oauth' ? 'bg-appSurface text-appText shadow-sm' : 'text-appTextMuted hover:text-appText'}`}>
                {t('tabOAuth', lang)}
              </button>
              <button onClick={() => setModalTab('manual')} id="tabManual"
                className={`flex-1 py-2 font-semibold rounded-lg transition ${modalTab === 'manual' ? 'bg-appSurface text-appText shadow-sm' : 'text-appTextMuted hover:text-appText'}`}>
                {t('tabManual', lang)}
              </button>
            </div>

            {/* OAuth tab */}
            {modalTab === 'oauth' && (
              <div className="space-y-3.5">
                <p className="text-xs text-appTextMuted leading-relaxed">{t('oauthDesc', lang)}</p>
                {oauthPanel === 'list' && (
                  <div id="oauthProvidersList" className="space-y-2 max-h-[48vh] overflow-y-auto pr-1">
                    {OAUTH_PROVIDERS.map(op => (
                      <button key={op.id} onClick={() => handleOAuthProviderClick(op.handler)}
                        className="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0">{op.svg}</div>
                          <div>
                            <div className="text-xs font-semibold text-appText group-hover:text-appAccent transition">{t(op.titleKey, lang)}</div>
                            <div className="text-[11px] text-appTextMuted">{t(op.descKey, lang)}</div>
                          </div>
                        </div>
                        <span className="text-xs font-semibold text-appAccent shrink-0">{t(op.handler === 'devin' ? 'devinManualAction' : 'loginBtn', lang)}</span>
                      </button>
                    ))}
                  </div>
                )}
                {oauthPanel === 'device' && (
                  <div id="deviceAuthPanel" className="p-4 rounded-xl bg-appMuted border border-appAccent/40 space-y-3.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-appText">{oauthFailed ? t('oauthFailed', lang) : t('deviceWaitGeneric', lang)}</span>
                      <span className="text-xs px-2.5 py-0.5 rounded-full bg-appAccentSoft text-appAccent font-semibold tracking-wide">{deviceBadge}</span>
                    </div>
                    {deviceCode ? (
                      <div className="flex items-center gap-2 bg-appSurface border border-appBorder rounded-lg p-2.5">
                        <code className="flex-1 font-mono text-base font-bold tracking-widest text-center text-appAccent select-all">{deviceCode}</code>
                        <button type="button" onClick={copyDeviceCode} className="px-3 py-1.5 text-xs font-semibold rounded-md bg-appMuted hover:bg-appBorder text-appText transition flex items-center gap-1.5">
                          <span>📋</span><span>{copyBtnText}</span>
                        </button>
                      </div>
                    ) : (
                      <div className="flex items-center justify-center p-2.5 text-xs text-appTextMuted">
                        {!oauthFailed && <div className="w-4 h-4 border-2 border-appAccent border-t-transparent rounded-full animate-spin shrink-0 mr-2" />}
                        <span>{oauthFailed ? t('oauthFailed', lang) : t('oauthWaiting', lang).replace('{provider}', deviceBadge)}</span>
                      </div>
                    )}
                    <p className="text-xs text-appTextMuted leading-relaxed">{t('deviceDescGeneric', lang)}</p>
                    {oauthNotice && (
                      <div role={oauthFailed ? 'alert' : 'status'} className={`text-xs px-3 py-2 rounded-xl flex items-center gap-2 ${oauthFailed ? 'bg-rose-500/10 border border-rose-500/20 text-rose-400 font-medium' : 'bg-appSurface border border-appBorder text-appTextMuted'}`}>
                        <span className="break-all">{oauthNotice}</span>
                      </div>
                    )}
                    <div className="flex items-center justify-between pt-1">
                      {Boolean(deviceAuthLink && deviceAuthLink !== '#') ? (
                        <a href={deviceAuthLink} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs font-semibold text-appAccent hover:underline">{t('reopenLink', lang)}</a>
                      ) : <span />}
                      {oauthRestartRequired && oauthRestartRef.current && (
                        <button type="button" onClick={() => oauthRestartRef.current?.()} className="text-xs font-semibold text-appAccent hover:underline">{t('oauthRestart', lang)}</button>
                      )}
                      <button type="button" onClick={cancelOAuth} className="text-xs text-appTextMuted hover:text-appText transition font-medium">{t('cancel', lang)}</button>
                    </div>
                  </div>
                )}
                {oauthPanel === 'browser' && (
                  <div id="browserAuthPanel" className="p-4 rounded-xl bg-appMuted border border-appAccent/40 space-y-3">
                    <div className="flex items-center gap-3">
                      {!oauthFailed && <div className="w-4 h-4 border-2 border-appAccent border-t-transparent rounded-full animate-spin shrink-0" />}
                      <span className="text-xs font-semibold text-appText">{oauthFailed ? t('oauthFailed', lang) : browserAuthText}</span>
                    </div>
                    {manualOAuthCallback && manualOAuthInputType ? (
                      <>
                        <p className="text-xs text-appTextMuted leading-relaxed">
                          {t(manualOAuthInputType === 'url' ? 'manualOAuthUrlInstructions' : 'manualOAuthCodeInstructions', lang)
                            .replace('{provider}', manualOAuthProviderName)}
                        </p>
                        <form onSubmit={submitManualOAuthCallback} className="space-y-2.5">
                          <label htmlFor="manualOAuthInput" className="block text-xs font-semibold text-appTextMuted">
                            {manualOAuthProviderName} · {t(manualOAuthInputType === 'url' ? 'manualOAuthUrlLabel' : 'manualOAuthCodeLabel', lang)}
                          </label>
                          <textarea
                            id="manualOAuthInput"
                            value={manualOAuthInput}
                            onChange={e => {
                              setManualOAuthInput(e.target.value);
                              setManualOAuthError('');
                            }}
                            placeholder={manualOAuthInputType === 'url'
                              ? manualOAuthRedirectUri || t('manualOAuthUrlPlaceholder', lang)
                              : t('manualOAuthCodePlaceholder', lang)}
                            autoComplete="off"
                            spellCheck={false}
                            rows={2}
                            required
                            className="w-full resize-y bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none"
                          />
                          {manualOAuthError && <div role="alert" className="text-xs text-rose-400">{manualOAuthError}</div>}
                          <button
                            type="submit"
                            disabled={manualOAuthSubmitting || !manualOAuthInput.trim()}
                            className="w-full rounded-lg bg-appAccent px-3 py-2 text-xs font-semibold text-white disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {manualOAuthSubmitting ? t('manualOAuthSubmitting', lang) : t('manualOAuthSubmit', lang)}
                          </button>
                        </form>
                      </>
                    ) : (
                      <p className="text-xs text-appTextMuted leading-relaxed">{lang === 'tr' ? 'Açılan sekmede yetkilendirmeyi tamamlayın.' : 'Complete authorization in the opened tab.'}</p>
                    )}
                    {oauthNotice && (
                      <div role={oauthFailed ? 'alert' : 'status'} className={`text-xs px-3 py-2 rounded-xl flex items-center gap-2 ${oauthFailed ? 'bg-rose-500/10 border border-rose-500/20 text-rose-400 font-medium' : 'bg-appSurface border border-appBorder text-appTextMuted'}`}>
                        <span className="break-all">{oauthNotice}</span>
                      </div>
                    )}
                    <div className="flex items-center justify-between pt-1">
                      {Boolean(browserAuthLink && browserAuthLink !== '#') ? (
                        <a href={browserAuthLink} target="_blank" rel="noreferrer" className="text-xs font-semibold text-appAccent hover:underline">{t('reopenLink', lang)}</a>
                      ) : <span />}
                      {oauthRestartRequired && oauthRestartRef.current && (
                        <button type="button" onClick={() => oauthRestartRef.current?.()} className="text-xs font-semibold text-appAccent hover:underline">{t('oauthRestart', lang)}</button>
                      )}
                      <button type="button" onClick={cancelOAuth} className="text-xs text-appTextMuted hover:text-appText transition font-medium">{t('cancel', lang)}</button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Manual tab */}
            {modalTab === 'manual' && (
              <form onSubmit={handleManualSave} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('provider', lang)}</label>
                  <select name="provider" value={manualProvider} onChange={e => setManualProvider(e.target.value)}
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none cursor-pointer">
                    {MANUAL_PROVIDERS.map(mp => <option key={mp.value} value={mp.value}>{mp.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('accountLabel', lang)}</label>
                  <input type="text" name="accountLabel" placeholder={t('accountLabelPlaceholder', lang)} required
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('accountAccent', lang)}</label>
                  <select name="accent" className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none cursor-pointer">
                    <option value="">{t('accentDefault', lang)}</option>
                    <option value="amber">Amber</option><option value="emerald">Emerald</option>
                    <option value="cyan">Cyan</option><option value="violet">Violet</option><option value="slate">Slate</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('credentialType', lang)}</label>
                  <select name="credentialType" defaultValue={hint.type}
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none">
                    <option value="api_key">{t('apiKey', lang)}</option>
                    <option value="oauth">{t('oauthToken', lang)}</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('secretLabel', lang)}</label>
                  <input type="password" name="secret" placeholder={hint.placeholder} required
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
                  <p className="text-[11px] text-appTextMuted mt-1">{hint.help}</p>
                  {hint.docsUrl && hint.docsLabelKey && (
                    <a href={hint.docsUrl} target="_blank" rel="noopener noreferrer"
                      className="inline-block text-[11px] text-appAccent hover:underline mt-1">
                      {t(hint.docsLabelKey, lang)}
                    </a>
                  )}
                </div>
                <div className="flex justify-end gap-2.5 pt-3 border-t border-appBorder">
                  <button type="button" onClick={closeAddModal} className="px-4 py-2 rounded-lg text-xs font-semibold bg-appMuted hover:bg-appBorder text-appText transition">{t('cancel', lang)}</button>
                  <button type="submit" disabled={manualSaving} className="px-5 py-2 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition whitespace-nowrap">
                    {manualSaving ? (lang === 'tr' ? 'Doğrulanıyor...' : 'Verifying...') : t('saveAndPoll', lang)}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </>
  );
}

// ── Mount ──
import React from 'react';

const appEl = document.getElementById('app');
if (appEl) {
  createRoot(appEl).render(
    <StrictMode>
      <Dashboard />
    </StrictMode>
  );
}
