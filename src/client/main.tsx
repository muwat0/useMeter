import './styles.css';
import { StrictMode, useState, useEffect, useCallback, useRef, useMemo, type FormEvent, type DragEvent } from 'react';
import { createRoot } from 'react-dom/client';
import {
  findCatalogEntry,
  getProviderCatalog,
  type ProviderCatalogEntry,
  type ProviderQuotaKind,
  type ProviderSupportTier,
} from '../core/providers/catalog';

// ── Types ──
interface UsageAmount {
  unit: 'percent' | 'usd' | 'credits' | 'requests' | 'tokens';
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
interface PatTokenItem {
  id: string;
  name: string;
  tokenPrefix: string;
  createdAt: number;
  lastUsedAt: number | null;
  expiresAt: number | null;
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
    privacyHideTitle: "Hassas Bilgileri ve Bakiyeleri Gizle",
    privacyShowTitle: "Hassas Bilgileri ve Bakiyeleri Göster",
    accountSecurityTitle: "Hesap Güvenliği", passwordChangeTitle: "Parolayı Değiştir",
    currentPasswordLabel: "Mevcut parola", newPasswordLabel: "Yeni parola",
    confirmNewPasswordLabel: "Yeni parolayı doğrula",
    passwordPolicyHelp: "Parola en az 12 Unicode karakteri ve kod birimi içermeli; en fazla 256 karakteri, kod birimini ve UTF-8 baytını aşmamalı.",
    passwordMismatch: "Yeni parolalar eşleşmiyor.",
    passwordChangeSubmit: "Parolayı Değiştir", passwordChanging: "Değiştiriliyor...",
    passwordChangeSuccess: "Parolanız değiştirildi. Bu oturum açık kalacak.",
    accountDeletionTitle: "useMeter Hesabını Sil",
    accountDeletionWarning: "Bu işlem useMeter hesabınızı ve burada saklanan bağlı sağlayıcı kimlik bilgileri ile kullanım geçmişini kalıcı olarak siler. Sağlayıcıların kendi hesapları etkilenmez. Bu işlem geri alınamaz.",
    accountDeletionConfirm: "useMeter hesabımın ve useMeter'da saklanan verilerin kalıcı olarak silineceğini anlıyorum.",
    accountDeletionSubmit: "useMeter Hesabını Kalıcı Olarak Sil",
    accountDeleting: "Hesap siliniyor...",
    accountErrorInvalidCredentials: "Mevcut parola doğru değil.",
    accountErrorWeakPassword: "Parola güvenlik gereksinimlerini karşılamıyor.",
    accountErrorUnauthenticated: "Oturumunuz sona erdi. Yeniden giriş yapın.",
    accountErrorInvalidResetToken: "Parola sıfırlama bağlantısı geçersiz, süresi dolmuş veya kullanılmış. Yeni bağlantı isteyin.",
    accountErrorLastAdmin: "Son yönetici hesabı silinemez. Önce başka bir yönetici ekleyin.",
    accountErrorRecoveryUnavailable: "Parola kurtarma şu anda kullanılamıyor. Lütfen daha sonra tekrar deneyin.",
    accountErrorRateLimited: "Çok fazla deneme yapıldı. Lütfen biraz bekleyip yeniden deneyin.",
    accountErrorGeneral: "İşlem tamamlanamadı. Lütfen tekrar deneyin.",
    accountErrorRequired: "Lütfen tüm zorunlu alanları doldurun.",
    patSectionTitle: "API & Dış Erişim (Kişisel Erişim Anahtarları)",
    patSectionDesc: "Terminal script'leri, Waybar, tmux veya cURL ile kullanım verilerinize erişmek için API anahtarları oluşturun.",
    patCreateBtn: "Yeni Anahtar Oluştur",
    patCreating: "Oluşturuluyor...",
    patNameLabel: "Anahtar Adı",
    patNamePlaceholder: "ör. Waybar Widget, Dizüstü Terminal",
    patExpiryLabel: "Geçerlilik Süresi",
    patExpiry30Days: "30 Gün",
    patExpiry90Days: "90 Gün",
    patExpiry1Year: "1 Yıl",
    patExpiryNever: "Süresiz (Ömür Boyu)",
    patNewTokenWarning: "Bu anahtarı bir daha göremezsiniz! Lütfen şimdi kopyalayıp güvenli bir yere kaydedin.",
    patCopyBtn: "Kopyala",
    patCopied: "Kopyalandı!",
    patCurlExample: "cURL ile Kullanım Örneği:",
    patListTitle: "Aktif Anahtarlarınız",
    patNoTokens: "Henüz oluşturulmuş bir API anahtarınız bulunmuyor.",
    patCreatedDate: "Oluşturulma:",
    patLastUsed: "Son kullanım:",
    patNeverUsed: "Hiç kullanılmadı",
    patExpires: "Bitiş:",
    patNeverExpires: "Süresiz",
    patRevokeBtn: "Kaldır",
    patRevokeConfirm: "Bu API anahtarını iptal etmek istediğinize emin misiniz? Bu anahtarı kullanan script'lerin erişimi hemen kesilecektir.",
    notifSectionTitle: "Kota ve Sıfırlanma Bildirimleri",
    notifSectionDesc: "Kotalarınız tükendiğinde (%100), uyarı eşiğine ulaştığında veya pencere sıfırlandığında anlık bildirim alın.",
    notifEnabledLabel: "Bildirimleri Etkinleştir",
    notifChannelLabel: "Bildirim Kanalı",
    notifChannelNtfy: "ntfy (Anlık Mobil / Masaüstü)",
    notifChannelTelegram: "Telegram Bot",
    notifChannelDiscord: "Discord Webhook",
    notifChannelWebhook: "Özel Webhook (JSON POST)",
    notifNtfyUrlLabel: "ntfy Konu URL'si",
    notifNtfyUrlPlaceholder: "https://ntfy.sh/benim_gizli_konum",
    notifNtfyTokenLabel: "Yetkilendirme Belirteci (İsteğe bağlı)",
    notifNtfyTokenPlaceholder: "tk_...",
    notifTgBotTokenLabel: "Telegram Bot Token",
    notifTgBotTokenPlaceholder: "123456789:ABCdefGHI...",
    notifTgChatIdLabel: "Telegram Chat ID",
    notifTgChatIdPlaceholder: "123456789",
    notifWebhookUrlLabel: "Webhook URL'si",
    notifDiscordUrlLabel: "Discord Webhook URL'si",
    notifThresholdLabel: "Uyarı Eşiği (%)",
    notifThresholdDesc: "Kullanım bu yüzdeye ulaştığında bildirim gönderilir.",
    notifTriggerWarning: "Uyarı eşiğine (%{pct}) ulaşıldığında bildir",
    notifTriggerExhausted: "Kota tamamen tükendiğinde (%100) bildir",
    notifTriggerReset: "Kota sıfırlandığında / hak yenilendiğinde bildir (OpenAI 5h vb.)",
    notifSaveBtn: "Bildirim Ayarlarını Kaydet",
    notifSaving: "Kaydediliyor...",
    notifSaved: "Bildirim ayarları kaydedildi.",
    notifTestBtn: "Test Bildirimi Gönder",
    notifTesting: "Gönderiliyor...",
    notifTestSuccess: "Test bildirimi başarıyla iletildi!",
    notifTestFailed: "Test bildirimi gönderilemedi: ",
    deleteAccount: "Hesabı Kaldır", editLabel: "Etiketi Düzenle",

    save: "Kaydet", saveAndPoll: "Kaydet ve Sorgula", cancel: "İptal",
    noAccounts: 'Henüz kayıtlı bir AI hesabı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.',
    lastUpdate: "Son Güncelleme", deleteConfirm: "Bu hesabın kimlik bilgisi ve kaydedilmiş kullanım geçmişi kalıcı olarak silinecek. Bu işlem geri alınamaz. Devam etmek istiyor musunuz?", deleteFailed: "Hesap kaldırılamadı. Lütfen tekrar deneyin.",
    resetsIn: "Sıfırlanma", rightsAvailable: "Hak Mevcut",
    requestsUnit: "istek", tokensUnit: "token",
    usageRemaining: "{n} {unit} kaldı", usageUsedOfLimit: "{used} / {limit} {unit} kullanıldı",
    usageUsed: "{n} {unit} kullanıldı", usageLimit: "{n} {unit} limit",
    modalTitle: "AI Hesabı Bağla", modalSubtitle: "OAuth veya doğrudan API anahtarıyla kota takibi kurun.",
    tabOAuth: "OAuth ile Oturum Aç", tabManual: "Manuel API Key",
    oauthDesc: "Resmi sağlayıcı girişine yönlendirilirsiniz. Token\u2019lar yerel veritabanında AES-256-GCM ile şifrelenir.",
    googleTitle: "Antigravity (Google AI Pro)", googleDesc: "Loopback URL yapıştırma veya yöneticiye ait Web OAuth istemcisiyle barındırılan callback",
    codexTitle: "OpenAI ChatGPT / Codex", codexDesc: "Plus / Pro 5 saatlik ve haftalık kotalar",
    claudeTitle: "Anthropic Claude Pro/Max", claudeDesc: "5h oturum ve haftalık Opus/Sonnet kotaları",
    loginBtn: "Oturum Aç →", deviceWait: "OpenAI Onayı Bekleniyor:",
    deviceDesc: "Yeni sekmede açılan OpenAI sayfasına bu kodu girin. Onaylandığı an bu pencere kendiliğinden kapanacaktır.",
    reopenLink: "Onay Sayfasını Yeniden Aç ↗",
    copilotTitle: "GitHub Copilot", copilotDesc: "Completions ve Chat kotaları",
    cursorTitle: "Cursor (Pro/Ultra)", cursorDesc: "Hızlı istekler ve on-demand kullanım",
    xaiTitle: "xAI Grok", xaiDesc: "OAuth ile bildirilen kullanım yüzdesi",
    kimiTitle: "Kimi Code (Moonshot)", kimiDesc: "Hesap bağlandı; sağlayıcı kota bildirmiyor",
    geminiCliTitle: "Google Gemini CLI", geminiCliDesc: "Code Assist & Gemini 2.5/3 Pro kotaları",
    openrouterTitle: "OpenRouter", openrouterDesc: "Tarayıcı OAuth'u otomatik tamamlanır; kod yapıştırma gerekmez. API anahtarıyla bakiye desteği.",
    zaiTitle: "Zhipu AI (GLM / BigModel)", zaiDesc: "Z.ai kota penceresi (%)",
    devinTitle: "Devin AI", devinDesc: "Uyumlu CLI oturum tokenı; barındırılan yönlendirme deneysel",
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
    accountSecurityTitle: "Account Security", passwordChangeTitle: "Change Password",
    currentPasswordLabel: "Current password", newPasswordLabel: "New password",
    confirmNewPasswordLabel: "Confirm new password",
    privacyHideTitle: "Hide Sensitive Info & Balances",
    privacyShowTitle: "Show Sensitive Info & Balances",
    passwordPolicyHelp: "Use at least 12 Unicode characters and code units; the password must not exceed 256 characters, code units, or UTF-8 bytes.",
    passwordMismatch: "The new passwords do not match.",
    passwordChangeSubmit: "Change Password", passwordChanging: "Changing...",
    passwordChangeSuccess: "Your password was changed. This session will remain signed in.",
    accountDeletionTitle: "Delete useMeter Account",
    accountDeletionWarning: "This permanently deletes your useMeter account, linked provider credentials stored in useMeter, and usage history. Your provider accounts themselves are not affected. This cannot be undone.",
    accountDeletionConfirm: "I understand that my useMeter account and data stored in useMeter will be permanently deleted.",
    accountDeletionSubmit: "Permanently Delete useMeter Account",
    accountDeleting: "Deleting account...",
    accountErrorInvalidCredentials: "The current password is incorrect.",
    accountErrorWeakPassword: "The password does not meet the security requirements.",
    accountErrorUnauthenticated: "Your session has expired. Please sign in again.",
    accountErrorInvalidResetToken: "This password-reset link is invalid, expired, or already used. Request a new link.",
    accountErrorLastAdmin: "The last administrator account cannot be deleted. Add another administrator first.",
    accountErrorRecoveryUnavailable: "Password recovery is currently unavailable. Please try again later.",
    accountErrorRateLimited: "Too many attempts. Wait a little and try again.",
    accountErrorGeneral: "The operation could not be completed. Please try again.",
    accountErrorRequired: "Please complete all required fields.",
    patSectionTitle: "API & External Access (Personal Access Tokens)",
    patSectionDesc: "Generate API tokens to access your usage data from terminal scripts, Waybar, tmux, or cURL.",
    patCreateBtn: "Generate New Token",
    patCreating: "Generating...",
    patNameLabel: "Token Name",
    patNamePlaceholder: "e.g. Waybar Widget, Laptop Terminal",
    patExpiryLabel: "Expiration",
    patExpiry30Days: "30 Days",
    patExpiry90Days: "90 Days",
    patExpiry1Year: "1 Year",
    patExpiryNever: "No Expiration",
    patNewTokenWarning: "Make sure to copy your personal access token now. You won't be able to see it again!",
    patCopyBtn: "Copy",
    patCopied: "Copied!",
    patCurlExample: "cURL Example:",
    patListTitle: "Your Active Tokens",
    patNoTokens: "No API tokens created yet.",
    patCreatedDate: "Created:",
    patLastUsed: "Last used:",
    patNeverUsed: "Never used",
    patExpires: "Expires:",
    patNeverExpires: "Never",
    patRevokeBtn: "Revoke",
    patRevokeConfirm: "Are you sure you want to revoke this API token? Any scripts using it will immediately lose access.",
    notifSectionTitle: "Quota & Reset Notifications",
    notifSectionDesc: "Receive real-time alerts when quotas are exhausted (100%), reach warning thresholds, or reset.",
    notifEnabledLabel: "Enable Notifications",
    notifChannelLabel: "Notification Channel",
    notifChannelNtfy: "ntfy (Mobile & Desktop Push)",
    notifChannelTelegram: "Telegram Bot",
    notifChannelDiscord: "Discord Webhook",
    notifChannelWebhook: "Custom Webhook (JSON POST)",
    notifNtfyUrlLabel: "ntfy Topic URL",
    notifNtfyUrlPlaceholder: "https://ntfy.sh/my_secret_topic",
    notifNtfyTokenLabel: "Access Token (Optional)",
    notifNtfyTokenPlaceholder: "tk_...",
    notifTgBotTokenLabel: "Telegram Bot Token",
    notifTgBotTokenPlaceholder: "123456789:ABCdefGHI...",
    notifTgChatIdLabel: "Telegram Chat ID",
    notifTgChatIdPlaceholder: "123456789",
    notifWebhookUrlLabel: "Webhook URL",
    notifDiscordUrlLabel: "Discord Webhook URL",
    notifThresholdLabel: "Warning Threshold (%)",
    notifThresholdDesc: "Alert sent when quota usage reaches this percentage.",
    notifTriggerWarning: "Notify when reaching warning threshold (%{pct})",
    notifTriggerExhausted: "Notify when quota is completely exhausted (100%)",
    notifTriggerReset: "Notify when quota resets / capacity is regenerated (OpenAI 5h, etc.)",
    notifSaveBtn: "Save Notification Settings",
    notifSaving: "Saving...",
    notifSaved: "Notification settings saved.",
    notifTestBtn: "Send Test Notification",
    notifTesting: "Sending...",
    notifTestSuccess: "Test notification sent successfully!",
    notifTestFailed: "Failed to send test notification: ",
    deleteAccount: "Remove Account", editLabel: "Edit Label",
    save: "Save", saveAndPoll: "Save & Poll", cancel: "Cancel",
    noAccounts: 'No AI accounts connected yet. Click <b>+ Connect Account</b> to add one.',
    lastUpdate: "Updated", deleteConfirm: "This account's credential and saved usage history will be permanently deleted. This cannot be undone. Continue?", deleteFailed: "The account could not be removed. Please try again.",
    resetsIn: "Resets in", rightsAvailable: "Available",
    requestsUnit: "requests", tokensUnit: "tokens",
    usageRemaining: "{n} {unit} remaining", usageUsedOfLimit: "{used} / {limit} {unit} used",
    usageUsed: "{n} {unit} used", usageLimit: "{n} {unit} limit",
    modalTitle: "Connect AI Account", modalSubtitle: "Track quotas and credits via OAuth or direct API key.",
    tabOAuth: "Login with OAuth", tabManual: "Manual API Key",
    oauthDesc: "Redirect to official authorization. Tokens are encrypted locally via AES-256-GCM.",
    googleTitle: "Antigravity (Google AI Pro)", googleDesc: "Loopback URL paste or hosted callback with an operator-owned Web OAuth client",
    codexTitle: "OpenAI ChatGPT / Codex", codexDesc: "Plus / Pro 5-hour rolling & weekly quotas",
    claudeTitle: "Anthropic Claude Pro/Max", claudeDesc: "5h session and weekly Opus/Sonnet quotas",
    loginBtn: "Login →", deviceWait: "Waiting for OpenAI Approval:",
    deviceDesc: "Enter the code on the OpenAI confirmation page. The dashboard will automatically update.",
    reopenLink: "Re-open Authorization Page ↗",
    copilotTitle: "GitHub Copilot", copilotDesc: "Completions & Chat quotas",
    cursorTitle: "Cursor (Pro/Ultra)", cursorDesc: "Fast requests & on-demand usage",
    xaiTitle: "xAI Grok", xaiDesc: "OAuth-reported usage percentage",
    kimiTitle: "Kimi Code (Moonshot)", kimiDesc: "Account connected; provider reports no quota data",
    geminiCliTitle: "Google Gemini CLI", geminiCliDesc: "Code Assist & Gemini 2.5/3 Pro quotas",
    openrouterTitle: "OpenRouter", openrouterDesc: "Browser OAuth completes automatically; no code paste needed. API key balance is also supported.",
    zaiTitle: "Zhipu AI (GLM / BigModel)", zaiDesc: "Z.ai usage-window percentages",
    devinTitle: "Devin AI", devinDesc: "Compatible CLI session token; hosted redirect is experimental",
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

function formatCountUsage(amount: UsageAmount, lang: string): string | null {
  if (amount.unit !== 'requests' && amount.unit !== 'tokens') return null;
  const unit = t(amount.unit === 'requests' ? 'requestsUnit' : 'tokensUnit', lang);
  const numberFormat = new Intl.NumberFormat(lang === 'tr' ? 'tr-TR' : 'en-US');
  if (typeof amount.remaining === 'number' && Number.isFinite(amount.remaining)) {
    return t('usageRemaining', lang).replace('{n}', numberFormat.format(amount.remaining)).replace('{unit}', unit);
  }
  if (typeof amount.used === 'number' && Number.isFinite(amount.used)
    && typeof amount.limit === 'number' && Number.isFinite(amount.limit)) {
    return t('usageUsedOfLimit', lang)
      .replace('{used}', numberFormat.format(amount.used))
      .replace('{limit}', numberFormat.format(amount.limit))
      .replace('{unit}', unit);
  }
  if (typeof amount.used === 'number' && Number.isFinite(amount.used)) {
    return t('usageUsed', lang).replace('{n}', numberFormat.format(amount.used)).replace('{unit}', unit);
  }
  if (typeof amount.limit === 'number' && Number.isFinite(amount.limit)) {
    return t('usageLimit', lang).replace('{n}', numberFormat.format(amount.limit)).replace('{unit}', unit);
  }
  return null;
}

const SUPPORT_TIER_BADGE_STYLES: Record<ProviderSupportTier, string> = {
  live_verified: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25',
  connection_verified: 'bg-sky-500/10 text-sky-400 border-sky-500/25',
  synthetic_only: 'bg-amber-500/10 text-amber-400 border-amber-500/25',
};

function supportTierLabel(tier: ProviderSupportTier, lang: string): string {
  if (tier === 'live_verified') return lang === 'tr' ? 'Canlı Telemetri Doğrulandı' : 'Live Verified';
  if (tier === 'connection_verified') return lang === 'tr' ? 'Yalnız Bağlantı Doğrulandı' : 'Connection Verified Only';
  return lang === 'tr' ? 'Deneysel / Sentetik' : 'Experimental / Synthetic';
}

function quotaKindLabel(kind: ProviderQuotaKind, lang: string): string {
  if (kind === 'window_percent') return lang === 'tr' ? 'Kota penceresi (%)' : 'Quota windows (%)';
  if (kind === 'balance_usd') return lang === 'tr' ? 'USD bakiye' : 'USD balance';
  return lang === 'tr' ? 'Token / kredi / istek sayacı' : 'Token / credit / request counter';
}

function ProviderSupportDetails({ entry, lang }: { entry: ProviderCatalogEntry; lang: string }) {
  const language = lang === 'tr' ? 'tr' : 'en';
  return (
    <div className="mt-2 space-y-1.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <span data-support-tier={entry.supportTier}
          className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold ${SUPPORT_TIER_BADGE_STYLES[entry.supportTier]}`}>
          {supportTierLabel(entry.supportTier, lang)}
        </span>
        <span data-quota-kind={entry.quotaKind}
          className="inline-flex items-center rounded-full border border-appBorder bg-appSurface/70 px-2 py-0.5 text-[10px] font-medium text-appTextMuted">
          {quotaKindLabel(entry.quotaKind, lang)}
        </span>
      </div>
      <p className="text-[11px] leading-relaxed text-appTextMuted">{entry.helpHint[language]}</p>
    </div>
  );
}

interface AccountApiResponse {
  success?: boolean;
  errorCode?: string;
}

function isPasswordWithinPolicy(value: string): boolean {
  const unicodeCharacters = Array.from(value).length;
  const codeUnits = value.length;
  const utf8Bytes = new TextEncoder().encode(value).byteLength;
  return unicodeCharacters >= 12 && codeUnits >= 12
    && unicodeCharacters <= 256 && codeUnits <= 256 && utf8Bytes <= 256;
}

function accountErrorMessageKey(status: number, errorCode?: string): string {
  switch (errorCode) {
    case 'INVALID_CREDENTIALS': return 'accountErrorInvalidCredentials';
    case 'WEAK_PASSWORD': return 'accountErrorWeakPassword';
    case 'UNAUTHENTICATED': return 'accountErrorUnauthenticated';
    case 'INVALID_RESET_TOKEN': return 'accountErrorInvalidResetToken';
    case 'LAST_ADMIN': return 'accountErrorLastAdmin';
    case 'RECOVERY_UNAVAILABLE': return 'accountErrorRecoveryUnavailable';
    case 'RATE_LIMITED': return 'accountErrorRateLimited';
    default:
      if (status === 401) return 'accountErrorUnauthenticated';
      if (status === 429) return 'accountErrorRateLimited';
      return 'accountErrorGeneral';
  }
}
function formatProviderTitle(provider: string): string {
  const entry = findCatalogEntry(provider);
  return entry?.displayName.en ?? (provider.charAt(0).toUpperCase() + provider.slice(1));
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
function AccountCard({ r, lang, isEditMode, editingCardId, currentGroup, hideSensitives, onStartEditLabel, onCancelEditLabel, onSaveLabel, onSaveAccent, onDeleteAccount, onDragStart, onDragOver, onDragLeave, onDrop, onDragEnd }: {
  r: Report; lang: string; isEditMode: boolean; editingCardId: string | null;
  currentGroup: string;
  hideSensitives: boolean;
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
                  <span className="account-card-badge text-xs font-semibold px-2.5 py-0.5 rounded-md">{hideSensitives ? '••••••••' : cleanLabel}</span>
                  <button type="button" onClick={() => onStartEditLabel(cardKey)}
                    className="text-[11px] font-medium text-appAccent hover:underline flex items-center gap-1">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                    <span>{t('editLabel', lang)}</span>
                  </button>
                </div>
              )
            ) : (
              <span className="account-card-badge text-xs font-semibold px-2.5 py-0.5 rounded-md">{hideSensitives ? '••••••••' : cleanLabel}</span>
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
            const used = l.amount.used;
            if (typeof used === 'number' && Number.isFinite(used)) {
              const isCritical = used >= 90;
              const barColor = isCritical ? 'bg-rose-500' : 'account-card-bar-fill';
              valueEl = <span className="account-card-value font-bold text-sm">{used.toFixed(1)}%</span>;
              barEl = (
                <div className="w-full account-card-bar-track h-1.5 rounded-full overflow-hidden mt-2">
                  <div className={`${barColor} h-full transition-all duration-300`} style={{ width: `${Math.min(100, used)}%` }} />
                </div>
              );
            }
          } else if (l.amount.unit === 'usd') {
            const usdValue = r.provider === 'openrouter' && l.id === 'key_usage'
              ? l.amount.used
              : l.amount.remaining;
            if (typeof usdValue === 'number' && Number.isFinite(usdValue)) {
              valueEl = <span className="account-card-value font-bold text-sm tracking-wide">{hideSensitives ? '••••••' : `$${usdValue.toFixed(2)}`}</span>;
            }
          } else if (l.amount.unit === 'credits') {
            const rem = l.amount.remaining;
            if (typeof rem === 'number' && Number.isFinite(rem)) {
              const labelText = lang === 'tr' ? `${rem} Hak Mevcut` : `${rem} Available`;
              valueEl = <span className="account-card-badge font-semibold text-xs px-2.5 py-0.5 rounded-md">{hideSensitives ? '••••••' : labelText}</span>;
            }
          } else {
            const quantityText = formatCountUsage(l.amount, lang);
            if (quantityText) {
              valueEl = <span className="account-card-value font-bold text-sm">{hideSensitives ? '••••••' : quantityText}</span>;
            }
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
              {cleanNotes.map((n, ni) => {
                const translated = translateNote(n, lang);
                const displayText = hideSensitives ? translated.replace(/\$[\d,]+(?:\.\d+)?/g, '$••••') : translated;
                return <span key={ni} className="text-xs text-appTextMuted block mt-0.5">{displayText}</span>;
              })}
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
  type: 'api_key' | 'oauth';
  docsUrl?: string;
  docsLabelKey?: string;
}

interface ProviderCredentialHint {
  placeholder: Readonly<{ en: string; tr: string }>;
  help: Readonly<{ en: string; tr: string }>;
  type: ProviderHint['type'];
  docsUrl?: string;
  docsLabelKey?: string;
}

const PROVIDER_CREDENTIAL_HINTS: Record<string, ProviderCredentialHint> = {
  antigravity: {
    placeholder: { en: 'Google OAuth access or refresh token', tr: 'Google OAuth erişim veya yenileme tokenı' },
    help: { en: 'Paste a Google OAuth token only when using manual credentials.', tr: 'Manuel kimlik bilgisi kullanıyorsanız Google OAuth tokenı yapıştırın.' },
    type: 'oauth',
  },
  'openai-codex': {
    placeholder: { en: 'OpenAI Codex OAuth access token', tr: 'OpenAI Codex OAuth erişim tokenı' },
    help: { en: 'Use an OpenAI OAuth access token.', tr: 'OpenAI OAuth erişim tokenı kullanın.' },
    type: 'oauth',
  },
  'github-copilot': {
    placeholder: { en: 'GitHub Copilot OAuth token', tr: 'GitHub Copilot OAuth tokenı' },
    help: { en: 'Use a compatible GitHub authorization token.', tr: 'Uyumlu bir GitHub yetkilendirme tokenı kullanın.' },
    type: 'oauth',
  },
  cursor: {
    placeholder: { en: 'WorkosCursorSessionToken or access token', tr: 'WorkosCursorSessionToken veya erişim tokenı' },
    help: { en: 'Use a compatible Cursor session token or cookie.', tr: 'Uyumlu Cursor oturum tokenı veya çerezi kullanın.' },
    type: 'oauth',
  },
  openrouter: {
    placeholder: { en: 'sk-or-v1-... API key', tr: 'sk-or-v1-... API anahtarı' },
    help: { en: 'OpenRouter API key.', tr: 'OpenRouter API anahtarı.' },
    type: 'api_key',
  },
  deepseek: {
    placeholder: { en: 'sk-... DeepSeek API key', tr: 'sk-... DeepSeek API anahtarı' },
    help: { en: 'DeepSeek Platform API key.', tr: 'DeepSeek Platform API anahtarı.' },
    type: 'api_key',
  },
  'xai-oauth': {
    placeholder: { en: 'xAI OAuth access token', tr: 'xAI OAuth erişim tokenı' },
    help: { en: 'Use an xAI OAuth token; API keys are not accepted by this adapter.', tr: 'xAI OAuth tokenı kullanın; bu adaptör API anahtarlarını kabul etmez.' },
    type: 'oauth',
  },
  zai: {
    placeholder: { en: 'Zhipu / Z.ai bearer token', tr: 'Zhipu / Z.ai bearer tokenı' },
    help: { en: 'Use a compatible Zhipu / Z.ai bearer credential.', tr: 'Uyumlu bir Zhipu / Z.ai bearer kimlik bilgisi kullanın.' },
    type: 'oauth',
  },
  anthropic: {
    placeholder: { en: 'Claude Code OAuth access token', tr: 'Claude Code OAuth erişim tokenı' },
    help: { en: 'Use a compatible Claude Code OAuth token; Anthropic API keys are not accepted.', tr: 'Uyumlu bir Claude Code OAuth tokenı kullanın; Anthropic API anahtarları kabul edilmez.' },
    type: 'oauth',
  },
  devin: {
    placeholder: { en: 'Existing Devin CLI session token', tr: 'Mevcut Devin CLI oturum tokenı' },
    help: {
      en: 'Only a compatible existing Devin CLI session token is supported; cog_ V3 PATs are unsupported. Hosted redirect is experimental.',
      tr: 'Yalnızca mevcut uyumlu Devin CLI oturum tokenı desteklenir; cog_ V3 PAT desteklenmez. Barındırılan yönlendirme deneyseldir.',
    },
    type: 'oauth',
    docsUrl: 'https://docs.devin.ai/cli/troubleshooting',
    docsLabelKey: 'devinDocsLink',
  },
  'minimax-code': {
    placeholder: { en: 'MiniMax Code API key', tr: 'MiniMax Code API anahtarı' },
    help: { en: 'Access key for a MiniMax Code token plan.', tr: 'MiniMax Code token planı için erişim anahtarı.' },
    type: 'api_key',
  },
  'cline-pass': {
    placeholder: { en: 'Cline Pass API key', tr: 'Cline Pass API anahtarı' },
    help: { en: 'Cline usage quota API key.', tr: 'Cline kullanım kota API anahtarı.' },
    type: 'api_key',
  },
  umans: {
    placeholder: { en: 'Umans API key', tr: 'Umans API anahtarı' },
    help: { en: 'Umans Code usage API key.', tr: 'Umans Code kullanım API anahtarı.' },
    type: 'api_key',
  },
  'google-gemini-cli': {
    placeholder: { en: 'Google Gemini CLI OAuth access token', tr: 'Google Gemini CLI OAuth erişim tokenı' },
    help: { en: 'Use a Gemini CLI OAuth token.', tr: 'Gemini CLI OAuth tokenı kullanın.' },
    type: 'oauth',
  },
  'kimi-code': {
    placeholder: { en: 'Kimi Code OAuth token', tr: 'Kimi Code OAuth tokenı' },
    help: { en: 'Use a Kimi Code subscription OAuth token; standard API keys are not accepted.', tr: 'Kimi Code abonelik OAuth tokenı kullanın; standart API anahtarları kabul edilmez.' },
    type: 'oauth',
  },
  'opencode-go': {
    placeholder: { en: 'OpenCode Go API key', tr: 'OpenCode Go API anahtarı' },
    help: { en: 'API key for an active OpenCode Go subscription.', tr: 'Aktif OpenCode Go aboneliğine ait API anahtarı.' },
    type: 'api_key',
  },
  'alibaba-token-plan': {
    placeholder: { en: 'Alibaba/Qwen token-plan API key and session cookie', tr: 'Alibaba/Qwen token-plan API anahtarı ve oturum çerezi' },
    help: { en: 'Use a supported token-plan key and the required console session cookie.', tr: 'Desteklenen token-plan anahtarı ile gerekli konsol oturum çerezini kullanın.' },
    type: 'api_key',
  },
};

function getProviderHint(p: string, lang: string): ProviderHint {
  const entry = findCatalogEntry(p);
  const language = lang === 'tr' ? 'tr' : 'en';
  const credentialHint = entry ? PROVIDER_CREDENTIAL_HINTS[entry.id] : undefined;
  return {
    placeholder: credentialHint?.placeholder[language] ?? (language === 'tr' ? 'Secret veya API Anahtarı' : 'Secret or API Key'),
    help: credentialHint?.help[language] ?? entry?.helpHint[language] ?? (language === 'tr' ? 'Sağlayıcı erişim kimlik bilgisi' : 'Provider access credential'),
    type: credentialHint?.type ?? 'api_key',
    docsUrl: credentialHint?.docsUrl,
    docsLabelKey: credentialHint?.docsLabelKey,
  };
}

const MANUAL_PROVIDERS = getProviderCatalog();

// ── Dashboard Component ──
function Dashboard() {
  const bootstrapEl = document.getElementById('usemeter-bootstrap');
  const bootstrap: BootstrapData = bootstrapEl ? JSON.parse(bootstrapEl.textContent || '{}') : { reports: [], user: null };
  const user = bootstrap.user;

  const [lang, setLang] = useState(detectInitialLang);
  const [mode, setMode] = useState(() => localStorage.getItem('usage_mode') || 'dark');
  const successTextClass = mode === 'dark' ? 'text-emerald-400' : 'text-emerald-700';
  const dangerTextClass = mode === 'dark' ? 'text-rose-400' : 'text-rose-700';
  const dangerStrongTextClass = mode === 'dark' ? 'text-rose-300' : 'text-rose-800';
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
  const [changeCurrentPassword, setChangeCurrentPassword] = useState('');
  const [changeNewPassword, setChangeNewPassword] = useState('');
  const [changeConfirmPassword, setChangeConfirmPassword] = useState('');
  const [changePasswordSubmitting, setChangePasswordSubmitting] = useState(false);
  const [changePasswordMessage, setChangePasswordMessage] = useState<string | null>(null);
  const [changePasswordSucceeded, setChangePasswordSucceeded] = useState(false);
  const [deleteAccountPassword, setDeleteAccountPassword] = useState('');
  const [deleteAccountConfirmed, setDeleteAccountConfirmed] = useState(false);
  const [deleteAccountSubmitting, setDeleteAccountSubmitting] = useState(false);
  const [deleteAccountMessage, setDeleteAccountMessage] = useState<string | null>(null);


  // Personal Access Tokens state
  const [patTokens, setPatTokens] = useState<PatTokenItem[]>([]);
  const [patNewName, setPatNewName] = useState('');
  const [patNewExpiresDays, setPatNewExpiresDays] = useState<number | null>(90);
  const [patCreating, setPatCreating] = useState(false);
  const [patCreateError, setPatCreateError] = useState<string | null>(null);
  const [patCreatedRawToken, setPatCreatedRawToken] = useState<string | null>(null);
  const [patCopied, setPatCopied] = useState(false);

  // Notification settings state
  interface NotifState {
    enabled: boolean;
    channel: "ntfy" | "telegram" | "webhook" | "discord";
    url: string;
    token: string;
    botToken: string;
    chatId: string;
    warningThresholdPercent: number;
    notifyOnWarning: boolean;
    notifyOnExhausted: boolean;
    notifyOnReset: boolean;
  }
  const [notifState, setNotifState] = useState<NotifState>({
    enabled: false,
    channel: "ntfy",
    url: "",
    token: "",
    botToken: "",
    chatId: "",
    warningThresholdPercent: 80,
    notifyOnWarning: true,
    notifyOnExhausted: true,
    notifyOnReset: true,
  });
  const [notifSaving, setNotifSaving] = useState(false);
  const [notifTesting, setNotifTesting] = useState(false);
  const [notifFeedback, setNotifFeedback] = useState<{ success: boolean; message: string } | null>(null);
  const accountDeletedRef = useRef(false);
  const settingsFeedbackGenerationRef = useRef(0);

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

  // Privacy mode (mask sensitive credentials & balances)
  const [hideSensitives, setHideSensitives] = useState<boolean>(() => {
    try {
      return localStorage.getItem('usage_hide_sensitive') === 'true';
    } catch {
      return false;
    }
  });
  const toggleHideSensitives = useCallback(() => {
    setHideSensitives(prev => {
      const next = !prev;
      try {
        localStorage.setItem('usage_hide_sensitive', String(next));
      } catch {}
      return next;
    });
  }, []);

  // ── Apply mode and document language ──
  useEffect(() => {
    const isDark = mode === 'dark';
    document.documentElement.classList.toggle('dark', isDark);
    document.documentElement.classList.toggle('light', !isDark);
    document.documentElement.lang = lang;
    localStorage.setItem('usage_mode', mode);
  }, [mode, lang]);
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
      if (accountDeletedRef.current) return;
      const elapsedSec = Math.max(0, Math.floor((Date.now() - lastPolledAt) / 1000));
      if (elapsedSec < 5) setSyncText(t('syncStatusJustNow', lang));
      else if (elapsedSec < 60) setSyncText(t('syncStatusSec', lang).replace('{n}', String(elapsedSec)));
      else setSyncText(t('syncStatusMin', lang).replace('{n}', String(Math.floor(elapsedSec / 60))));
    }, 1000);
    return () => clearInterval(interval);
  }, [lastPolledAt, lang]);

  // ── Polling ──
  const loadUsage = useCallback(async () => {
    if (accountDeletedRef.current) return;
    try {
      const [dataRes, credsRes] = await Promise.all([
        fetch('/api/data'),
        fetch('/api/credentials').catch(() => null),
      ]);
      if (accountDeletedRef.current) return;
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
        if (accountDeletedRef.current) return;
        setReports(prev => accountDeletedRef.current ? prev : newReports);
        setLastPolledAt(Date.now());
      }
    } catch (err) {
      if (!accountDeletedRef.current) console.warn('Silent live sync failure:', err);
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
    if (accountDeletedRef.current) return;
    setPollSpinning(true);
    try {
      await fetch('/api/poll', { method: 'POST' });
      await loadUsage();
    } finally {
      if (!accountDeletedRef.current) setPollSpinning(false);
    }
  }
  async function logoutUser() {
    try { await fetch('/api/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
    window.location.href = '/login';
  }
  function closeSettings() {
    settingsFeedbackGenerationRef.current += 1;
    setShowSettings(false);
    setChangeCurrentPassword('');
    setChangeNewPassword('');
    setChangeConfirmPassword('');
    setChangePasswordMessage(null);
    setChangePasswordSucceeded(false);
    setDeleteAccountPassword('');
    setDeleteAccountConfirmed(false);
    setDeleteAccountMessage(null);
    setPatCreatedRawToken(null);
    setPatCreateError(null);
    setPatCopied(false);
    setPatNewName('');
    setNotifFeedback(null);
  }

  async function loadPatTokens() {
    try {
      const res = await fetch('/api/tokens');
      if (res.ok) {
        const json = (await res.json()) as { success: boolean; tokens?: PatTokenItem[] };
        if (json.success && Array.isArray(json.tokens)) {
          setPatTokens(json.tokens);
        }
      }
    } catch {
      // ignore
    }
  }

  async function createPatToken(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (patCreating || !patNewName.trim()) return;
    setPatCreating(true);
    setPatCreateError(null);
    try {
      const res = await fetch('/api/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: patNewName.trim(), expiresInDays: patNewExpiresDays }),
      });
      const json = (await res.json()) as { success: boolean; error?: string; rawToken?: string };
      if (!res.ok || !json.success) {
        setPatCreateError(json.error || t('accountErrorGeneral', lang));
        return;
      }
      if (json.rawToken) {
        setPatCreatedRawToken(json.rawToken);
        setPatNewName('');
        await loadPatTokens();
      }
    } catch {
      setPatCreateError(t('accountErrorGeneral', lang));
    } finally {
      setPatCreating(false);
    }
  }

  async function revokePatToken(id: string) {
    if (!window.confirm(t('patRevokeConfirm', lang))) return;
    try {
      const res = await fetch(`/api/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' });
      if (res.ok) {
        await loadPatTokens();
      }
    } catch {
      // ignore
    }
  }

  async function copyPatToken(tokenText: string) {
    try {
      await navigator.clipboard.writeText(tokenText);
      setPatCopied(true);
      setTimeout(() => setPatCopied(false), 2500);
    } catch {
      // fallback
    }
  }

  function openSettings() {
    setShowSettings(true);
    loadPatTokens();
    loadNotificationConfig();
  }

  async function loadNotificationConfig() {
    try {
      const res = await fetch('/api/notifications/config');
      if (res.ok) {
        const json = (await res.json()) as { success: boolean; config?: any };
        if (json.success && json.config) {
          const c = json.config;
          setNotifState(prev => ({
            ...prev,
            enabled: Boolean(c.enabled),
            channel: c.channel || "ntfy",
            url: c.config?.url || "",
            chatId: c.config?.chatId || "",
            warningThresholdPercent: c.warningThresholdPercent ?? 80,
            notifyOnWarning: c.notifyOnWarning !== false,
            notifyOnExhausted: c.notifyOnExhausted !== false,
            notifyOnReset: c.notifyOnReset !== false,
          }));
        }
      }
    } catch {
      // ignore
    }
  }

  async function saveNotificationConfig(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (notifSaving) return;
    setNotifSaving(true);
    setNotifFeedback(null);

    let channelConfig: any = { channel: notifState.channel };
    if (notifState.channel === "telegram") {
      channelConfig.botToken = notifState.botToken;
      channelConfig.chatId = notifState.chatId;
    } else if (notifState.channel === "ntfy") {
      channelConfig.url = notifState.url;
      if (notifState.token) channelConfig.token = notifState.token;
    } else {
      channelConfig.url = notifState.url;
    }

    try {
      const res = await fetch('/api/notifications/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled: notifState.enabled,
          channel: notifState.channel,
          config: channelConfig,
          warningThresholdPercent: notifState.warningThresholdPercent,
          notifyOnWarning: notifState.notifyOnWarning,
          notifyOnExhausted: notifState.notifyOnExhausted,
          notifyOnReset: notifState.notifyOnReset,
        }),
      });
      const json = (await res.json()) as { success: boolean; error?: string };
      if (!res.ok || !json.success) {
        setNotifFeedback({ success: false, message: json.error || t('accountErrorGeneral', lang) });
      } else {
        setNotifFeedback({ success: true, message: t('notifSaved', lang) });
        await loadNotificationConfig();
      }
    } catch {
      setNotifFeedback({ success: false, message: t('accountErrorGeneral', lang) });
    } finally {
      setNotifSaving(false);
    }
  }

  async function sendTestNotification() {
    if (notifTesting) return;
    setNotifTesting(true);
    setNotifFeedback(null);

    let channelConfig: any = { channel: notifState.channel };
    if (notifState.channel === "telegram") {
      channelConfig.botToken = notifState.botToken;
      channelConfig.chatId = notifState.chatId;
    } else if (notifState.channel === "ntfy") {
      channelConfig.url = notifState.url;
      if (notifState.token) channelConfig.token = notifState.token;
    } else {
      channelConfig.url = notifState.url;
    }

    try {
      const res = await fetch('/api/notifications/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          channel: notifState.channel,
          config: channelConfig,
        }),
      });
      const json = (await res.json()) as { success: boolean; error?: string };
      if (!res.ok || !json.success) {
        setNotifFeedback({ success: false, message: t('notifTestFailed', lang) + (json.error || "") });
      } else {
        setNotifFeedback({ success: true, message: t('notifTestSuccess', lang) });
      }
    } catch {
      setNotifFeedback({ success: false, message: t('notifTestFailed', lang) + "Network error" });
    } finally {
      setNotifTesting(false);
    }
  }


  async function changePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (changePasswordSubmitting || accountDeletedRef.current) return;
    setChangePasswordMessage(null);
    setChangePasswordSucceeded(false);
    if (!changeCurrentPassword) {
      setChangePasswordMessage('accountErrorRequired');
      return;
    }

    if (!isPasswordWithinPolicy(changeNewPassword)) {
      setChangePasswordMessage('accountErrorWeakPassword');
      return;
    }
    if (changeNewPassword !== changeConfirmPassword) {
      setChangePasswordMessage('passwordMismatch');
      return;
    }

    const feedbackGeneration = settingsFeedbackGenerationRef.current;
    setChangePasswordSubmitting(true);
    try {
      const response = await fetch('/api/auth/password/change', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: changeCurrentPassword, newPassword: changeNewPassword }),
      });
      const result = await response.json().catch(() => null) as AccountApiResponse | null;
      if (accountDeletedRef.current || feedbackGeneration !== settingsFeedbackGenerationRef.current) return;
      if (!response.ok || result?.success !== true) {
        setChangePasswordMessage(accountErrorMessageKey(response.status, result?.errorCode));
        return;
      }

      setChangeCurrentPassword('');
      setChangeNewPassword('');
      setChangeConfirmPassword('');
      setChangePasswordSucceeded(true);
      setChangePasswordMessage('passwordChangeSuccess');
    } catch {
      if (!accountDeletedRef.current && feedbackGeneration === settingsFeedbackGenerationRef.current) {
        setChangePasswordMessage('accountErrorGeneral');
      }
    } finally {
      if (!accountDeletedRef.current) setChangePasswordSubmitting(false);
    }
  }

  async function deleteUseMeterAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (deleteAccountSubmitting || accountDeletedRef.current) return;
    if (!deleteAccountConfirmed) return;
    const feedbackGeneration = settingsFeedbackGenerationRef.current;
    setDeleteAccountMessage(null);
    setDeleteAccountSubmitting(true);
    try {
      const response = await fetch('/api/auth/account', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: deleteAccountPassword }),
      });
      const result = await response.json().catch(() => null) as AccountApiResponse | null;
      if (!response.ok || result?.success !== true) {
        if (!accountDeletedRef.current && feedbackGeneration === settingsFeedbackGenerationRef.current) {
          setDeleteAccountMessage(accountErrorMessageKey(response.status, result?.errorCode));
        }
        return;
      }

      setDeleteAccountPassword('');
      setDeleteAccountConfirmed(false);
      accountDeletedRef.current = true;
      window.location.replace('/login');
    } catch {
      if (!accountDeletedRef.current && feedbackGeneration === settingsFeedbackGenerationRef.current) {
        setDeleteAccountMessage('accountErrorGeneral');
      }
    } finally {
      if (!accountDeletedRef.current) setDeleteAccountSubmitting(false);
    }
  }


  // ── Label/accent save ──
  async function saveAccountLabel(cardKey: string, newLabel: string) {
    if (accountDeletedRef.current) return;
    const trimmed = (newLabel || '').trim();
    if (!cardKey || !trimmed) { setEditingCardId(null); return; }
    try {
      const res = await fetch('/api/credentials/' + encodeURIComponent(cardKey), {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountLabel: trimmed }),
      });
      const json = await res.json();
      if (accountDeletedRef.current) return;
      if (json.success) {
        setReports(prev => accountDeletedRef.current ? prev : prev.map(r => (r.credentialId || r.provider) === cardKey ? { ...r, accountLabel: trimmed } : r));
      }
    } catch (err) { console.error('Failed to update account label:', err); }
    finally { if (!accountDeletedRef.current) setEditingCardId(null); }
  }

  async function saveAccountAccent(cardKey: string, accentKey: string) {
    if (accountDeletedRef.current) return;
    if (!cardKey) return;
    const targetAccent = (!accentKey || accentKey === 'null' || accentKey === 'default') ? 'default' : accentKey;
    setReports(prev => accountDeletedRef.current ? prev : prev.map(r => (r.credentialId || r.provider) === cardKey ? { ...r, accent: targetAccent } : r));
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
    if (accountDeletedRef.current || !id || !window.confirm(t('deleteConfirm', lang))) return;
    try {
      const response = await fetch('/api/credentials/' + encodeURIComponent(id), { method: 'DELETE' });
      const result = await response.json() as { success?: boolean };
      if (accountDeletedRef.current) return;
      if (!response.ok || result.success !== true) {
        window.alert(t('deleteFailed', lang));
        return;
      }

      setReports(prev => accountDeletedRef.current ? prev : prev.filter(r => r.credentialId !== id));
      setEditingCardId(prev => accountDeletedRef.current ? prev : prev === id ? null : prev);
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
      if (!accountDeletedRef.current) window.alert(t('deleteFailed', lang));
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

  function handleOAuthProviderClick(handler: string, providerId: string) {
    const entry = findCatalogEntry(providerId);
    const providerName = entry?.displayName[lang === 'tr' ? 'tr' : 'en'] ?? providerId;
    if (handler === 'google') startBrowserOAuth('google', providerName);
    else if (handler === 'claude') startBrowserOAuth('claude', providerName);
    else if (handler === 'gemini-cli') startBrowserOAuth('gemini-cli', providerName);
    else if (handler === 'zai') startBrowserOAuth('zai', providerName);
    else if (handler === 'cursor') startOAuthPoll('cursor', providerName, 'cursor', ['uuid', 'verifier'], 'browser');
    else if (handler === 'openrouter') startBrowserOAuth('openrouter', providerName);
    else if (handler === 'devin') {
      cancelOAuth();
      setManualProvider('devin');
      setModalTab('manual');
    }
    else if (handler === 'codex-device') startOAuthPoll('codex', providerName, 'codex', ['deviceAuthId', 'userCode']);
    else if (handler === 'copilot-device') startOAuthPoll('copilot', providerName, 'copilot', ['deviceCode']);
    else if (handler === 'xai-device') startOAuthPoll('xai', providerName, 'xai', ['deviceCode']);
    else if (handler === 'kimi-device') startOAuthPoll('kimi', providerName, 'kimi', ['deviceCode', 'deviceId']);
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
  const manualProviderEntry = findCatalogEntry(manualProvider);

  // ── Render ──
  const editBtnDisabled = currentGroup !== 'none';
  const flagText = I18N[lang]?.['flag'] || '🇹🇷';

  return (
    <>
      {/* Header */}
      <header className="border-b border-appBorder bg-appSurface/80 backdrop-blur-md px-4 sm:px-6 py-3 sticky top-0 z-20 transition-colors">
        <div className="max-w-screen-2xl mx-auto min-w-0 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 sm:gap-3">
          <div className="min-w-0 flex items-center gap-2.5 sm:gap-3">
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-wider text-appText text-lg font-mono">use<span className="text-appAccent">Meter</span></span>
              <a href="https://github.com/muwat0/useMeter" aria-label={lang === 'tr' ? 'GitHub deposu' : 'GitHub repository'} title={lang === 'tr' ? 'GitHub deposu' : 'GitHub repository'}
                className="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center focus-visible:ring-2 focus-visible:ring-appAccent focus-visible:ring-offset-2 focus-visible:ring-offset-appSurface">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.48 2 2 6.59 2 12.26c0 4.53 2.87 8.37 6.84 9.73.5.1.68-.22.68-.49v-1.7c-2.78.62-3.37-1.21-3.37-1.21-.45-1.18-1.11-1.5-1.11-1.5-.91-.64.07-.63.07-.63 1 .08 1.53 1.05 1.53 1.05.9 1.59 2.35 1.13 2.92.86.09-.67.35-1.13.64-1.39-2.22-.26-4.56-1.15-4.56-5.09 0-1.12.39-2.04 1.03-2.76-.1-.26-.45-1.31.1-2.73 0 0 .84-.28 2.75 1.05a9.15 9.15 0 0 1 5.01 0c1.91-1.33 2.75-1.05 2.75-1.05.55 1.42.2 2.47.1 2.73.64.72 1.03 1.64 1.03 2.76 0 3.95-2.35 4.82-4.59 5.08.36.32.68.95.68 1.91v2.83c0 .27.18.6.69.49A10.28 10.28 0 0 0 22 12.26C22 6.59 17.52 2 12 2Z"/></svg>
              </a>
            </div>
            <div className="hidden sm:block h-4 w-px bg-appBorder" />
            <span id="headerSyncStatus" className="min-w-0 truncate text-xs text-appTextMuted tracking-tight font-medium">{syncText}</span>
          </div>

          <div className="min-w-0 w-full sm:w-auto flex items-center gap-1.5 sm:gap-2 flex-wrap justify-start sm:justify-end">
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
            <button onClick={openSettings} id="settingsBtn" title={t('settingsTitle', lang)}
              className="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            </button>
            {/* Privacy Toggle (Eye) */}
            <button type="button" onClick={toggleHideSensitives} id="privacyModeBtn"
              title={t(hideSensitives ? 'privacyShowTitle' : 'privacyHideTitle', lang)}
              aria-label={t(hideSensitives ? 'privacyShowTitle' : 'privacyHideTitle', lang)}
              className={`h-9 w-9 rounded-lg border transition flex items-center justify-center text-sm ${hideSensitives ? 'bg-appAccent/15 text-appAccent border-appAccent/40' : 'border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent'}`}>
              {hideSensitives ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/>
                  <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/>
                  <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/>
                  <line x1="2" x2="22" y1="2" y2="22"/>
                </svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              )}
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
                <span className="text-xs text-appTextMuted hidden md:inline-block max-w-[150px] truncate" title={user.email}>{hideSensitives ? '••••••••' : user.email}</span>
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
              <span id="statTotalBalance" className="font-bold text-emerald-500 text-sm">{hideSensitives ? '••••••' : `$${totalBalance.toFixed(2)}`}</span>
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
                    currentGroup={currentGroup} hideSensitives={hideSensitives}
                    onStartEditLabel={setEditingCardId} onCancelEditLabel={() => setEditingCardId(null)}
                    onSaveLabel={saveAccountLabel} onSaveAccent={saveAccountAccent} onDeleteAccount={deleteAccount}
                    onDragStart={onDragStart} onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop} onDragEnd={onDragEnd} />
                ))}
              </React.Fragment>
            ))
          ) : (
            sortedReports.map(r => (
              <AccountCard key={getCardKey(r)} r={r} lang={lang} isEditMode={isEditMode} editingCardId={editingCardId}
                currentGroup={currentGroup} hideSensitives={hideSensitives}
                onStartEditLabel={setEditingCardId} onCancelEditLabel={() => setEditingCardId(null)}
                onSaveLabel={saveAccountLabel} onSaveAccent={saveAccountAccent} onDeleteAccount={deleteAccount}
                onDragStart={onDragStart} onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop} onDragEnd={onDragEnd} />
            ))
          )}
        </div>
      </main>
      <footer className="mt-auto border-t border-appBorder px-4 sm:px-6 py-4">
        <div className="max-w-screen-2xl mx-auto flex flex-wrap items-center justify-between gap-3">
          <span className="text-[11px] text-appTextMuted">{lang === 'tr' ? 'Bilgi ve destek' : 'Information & support'}</span>
          <nav aria-label={lang === 'tr' ? 'Yasal ve destek bağlantıları' : 'Legal and support links'} className="flex flex-wrap gap-x-5 gap-y-2 text-xs text-appTextMuted">
            <a href={`/privacy?lang=${lang}`} className="hover:text-appText transition">{lang === 'tr' ? 'Gizlilik' : 'Privacy'}</a>
            <a href={`/terms?lang=${lang}`} className="hover:text-appText transition">{lang === 'tr' ? 'Kullanım Koşulları' : 'Terms'}</a>
            <a href={`/security?lang=${lang}`} className="hover:text-appText transition">{lang === 'tr' ? 'Güvenlik' : 'Security'}</a>
            <a href={`/support?lang=${lang}`} className="hover:text-appText transition">{lang === 'tr' ? 'Destek' : 'Support'}</a>
          </nav>
        </div>
      </footer>

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={e => { if (e.target === e.currentTarget) closeSettings(); }}>
          <div className="bg-appSurface border border-appBorder rounded-2xl max-w-lg w-full max-h-[90vh] overflow-y-auto p-5 sm:p-6 space-y-5 shadow-2xl transition-colors">
            <div className="flex justify-between items-center pb-3 border-b border-appBorder">
              <h3 className="font-bold text-appText text-base">{t('settingsTitle', lang)}</h3>
              <button onClick={closeSettings} className="text-appTextMuted hover:text-appText text-lg p-1">✕</button>
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
            {/* Personal Access Tokens (API Keys) */}
            <section className="space-y-3.5 border-t border-appBorder pt-4">
              <div>
                <h4 className="text-sm font-bold text-appText">{t('patSectionTitle', lang)}</h4>
                <p className="text-xs text-appTextMuted mt-1">{t('patSectionDesc', lang)}</p>
              </div>

              {/* Token Creation Form */}
              <form onSubmit={createPatToken} className="space-y-3 bg-appMuted/40 border border-appBorder/80 rounded-xl p-3.5">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="patName" className="block text-xs font-semibold text-appTextMuted mb-1">{t('patNameLabel', lang)}</label>
                    <input id="patName" type="text" maxLength={100} required placeholder={t('patNamePlaceholder', lang)}
                      value={patNewName} onChange={e => { setPatNewName(e.target.value); setPatCreateError(null); }}
                      className="w-full bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none" />
                  </div>
                  <div>
                    <label htmlFor="patExpiry" className="block text-xs font-semibold text-appTextMuted mb-1">{t('patExpiryLabel', lang)}</label>
                    <select id="patExpiry" value={patNewExpiresDays === null ? 'never' : String(patNewExpiresDays)}
                      onChange={e => setPatNewExpiresDays(e.target.value === 'never' ? null : Number(e.target.value))}
                      className="w-full bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none">
                      <option value="30">{t('patExpiry30Days', lang)}</option>
                      <option value="90">{t('patExpiry90Days', lang)}</option>
                      <option value="365">{t('patExpiry1Year', lang)}</option>
                      <option value="never">{t('patExpiryNever', lang)}</option>
                    </select>
                  </div>
                </div>

                {patCreateError && (
                  <div role="alert" className={`rounded-lg border px-3 py-2 text-xs border-rose-500/30 bg-rose-500/10 ${dangerTextClass}`}>
                    {patCreateError}
                  </div>
                )}

                <button type="submit" disabled={patCreating || !patNewName.trim()}
                  className="rounded-lg bg-appAccent px-3.5 py-2 text-xs font-semibold text-zinc-950 transition hover:bg-appAccentHover disabled:opacity-50 disabled:cursor-not-allowed">
                  {patCreating ? t('patCreating', lang) : t('patCreateBtn', lang)}
                </button>
              </form>

              {/* Newly Created Token Display (Only shown once!) */}
              {patCreatedRawToken && (
                <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-3.5 space-y-2.5">
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-400 font-bold text-xs">✓ {t('patNewTokenWarning', lang)}</span>
                  </div>
                  <div className="flex items-center gap-2 bg-appSurface border border-emerald-500/30 rounded-lg p-2 font-mono text-xs">
                    <input type="text" readOnly value={patCreatedRawToken} className="w-full bg-transparent text-emerald-300 outline-none select-all text-[11px]" />
                    <button type="button" onClick={() => copyPatToken(patCreatedRawToken)}
                      className="px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 font-medium text-xs whitespace-nowrap transition">
                      {patCopied ? t('patCopied', lang) : t('patCopyBtn', lang)}
                    </button>
                  </div>
                  <div className="space-y-1">
                    <span className="text-[11px] text-appTextMuted font-medium">{t('patCurlExample', lang)}</span>
                    <pre className="p-2 rounded bg-zinc-950/80 text-[11px] font-mono text-zinc-300 overflow-x-auto border border-zinc-800">
                      <code>{`curl -H "Authorization: Bearer ${patCreatedRawToken}" ${window.location.origin}/api/v1/summary`}</code>
                    </pre>
                  </div>
                </div>
              )}

              {/* Existing Tokens List */}
              <div className="space-y-2">
                <span className="text-xs font-semibold text-appTextMuted">{t('patListTitle', lang)}</span>
                {patTokens.length === 0 ? (
                  <p className="text-xs text-appTextMuted/70 italic py-1">{t('patNoTokens', lang)}</p>
                ) : (
                  <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                    {patTokens.map(tok => (
                      <div key={tok.id} className="flex items-center justify-between p-2.5 rounded-lg border border-appBorder bg-appMuted/30 hover:border-appAccent/50 transition">
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-appText">{tok.name}</span>
                            <span className="font-mono text-[10px] text-appTextMuted bg-appSurface px-1.5 py-0.5 rounded border border-appBorder">{tok.tokenPrefix}</span>
                          </div>
                          <div className="flex items-center gap-3 text-[10px] text-appTextMuted">
                            <span>{t('patCreatedDate', lang)} {new Date(tok.createdAt).toLocaleDateString()}</span>
                            <span>•</span>
                            <span>{t('patLastUsed', lang)} {tok.lastUsedAt ? new Date(tok.lastUsedAt).toLocaleDateString() : t('patNeverUsed', lang)}</span>
                            <span>•</span>
                            <span>{t('patExpires', lang)} {tok.expiresAt ? new Date(tok.expiresAt).toLocaleDateString() : t('patNeverExpires', lang)}</span>
                          </div>
                        </div>
                        <button type="button" onClick={() => revokePatToken(tok.id)}
                          className="px-2.5 py-1 text-[11px] font-medium text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 rounded transition border border-rose-500/20">
                          {t('patRevokeBtn', lang)}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </section>
            {/* Quota & Reset Notifications */}
            <section className="space-y-3.5 border-t border-appBorder pt-4">
              <div>
                <h4 className="text-sm font-bold text-appText">{t('notifSectionTitle', lang)}</h4>
                <p className="text-xs text-appTextMuted mt-1">{t('notifSectionDesc', lang)}</p>
              </div>

              <form onSubmit={saveNotificationConfig} className="space-y-3 bg-appMuted/40 border border-appBorder/80 rounded-xl p-3.5">
                {/* Enable toggle */}
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={notifState.enabled}
                    onChange={e => {
                      setNotifState(prev => ({ ...prev, enabled: e.target.checked }));
                      setNotifFeedback(null);
                    }}
                    className="h-4 w-4 rounded border-appBorder accent-appAccent"
                  />
                  <span className="text-xs font-bold text-appText">{t('notifEnabledLabel', lang)}</span>
                </label>

                {/* Channel select */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-appTextMuted mb-1">{t('notifChannelLabel', lang)}</label>
                    <select
                      value={notifState.channel}
                      onChange={e => {
                        setNotifState(prev => ({ ...prev, channel: e.target.value as any }));
                        setNotifFeedback(null);
                      }}
                      className="w-full bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none"
                    >
                      <option value="ntfy">{t('notifChannelNtfy', lang)}</option>
                      <option value="telegram">{t('notifChannelTelegram', lang)}</option>
                      <option value="discord">{t('notifChannelDiscord', lang)}</option>
                      <option value="webhook">{t('notifChannelWebhook', lang)}</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-appTextMuted mb-1">
                      {t('notifThresholdLabel', lang)} ({notifState.warningThresholdPercent}%)
                    </label>
                    <input
                      type="range"
                      min="50"
                      max="95"
                      step="5"
                      value={notifState.warningThresholdPercent}
                      onChange={e => {
                        setNotifState(prev => ({ ...prev, warningThresholdPercent: Number(e.target.value) }));
                        setNotifFeedback(null);
                      }}
                      className="w-full accent-appAccent h-2 bg-appSurface rounded-lg cursor-pointer"
                    />
                  </div>
                </div>

                {/* Channel specific inputs */}
                {notifState.channel === 'ntfy' && (
                  <div className="space-y-2">
                    <div>
                      <label className="block text-xs font-semibold text-appTextMuted mb-1">{t('notifNtfyUrlLabel', lang)}</label>
                      <input
                        type="url"
                        placeholder={t('notifNtfyUrlPlaceholder', lang)}
                        value={notifState.url}
                        onChange={e => {
                          setNotifState(prev => ({ ...prev, url: e.target.value }));
                          setNotifFeedback(null);
                        }}
                        className="w-full bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-appTextMuted mb-1">{t('notifNtfyTokenLabel', lang)}</label>
                      <input
                        type="password"
                        placeholder={t('notifNtfyTokenPlaceholder', lang)}
                        value={notifState.token}
                        onChange={e => {
                          setNotifState(prev => ({ ...prev, token: e.target.value }));
                          setNotifFeedback(null);
                        }}
                        className="w-full bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none font-mono"
                      />
                    </div>
                  </div>
                )}

                {notifState.channel === 'telegram' && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-appTextMuted mb-1">{t('notifTgBotTokenLabel', lang)}</label>
                      <input
                        type="password"
                        placeholder={t('notifTgBotTokenPlaceholder', lang)}
                        value={notifState.botToken}
                        onChange={e => {
                          setNotifState(prev => ({ ...prev, botToken: e.target.value }));
                          setNotifFeedback(null);
                        }}
                        className="w-full bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-appTextMuted mb-1">{t('notifTgChatIdLabel', lang)}</label>
                      <input
                        type="text"
                        placeholder={t('notifTgChatIdPlaceholder', lang)}
                        value={notifState.chatId}
                        onChange={e => {
                          setNotifState(prev => ({ ...prev, chatId: e.target.value }));
                          setNotifFeedback(null);
                        }}
                        className="w-full bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none font-mono"
                      />
                    </div>
                  </div>
                )}

                {(notifState.channel === 'discord' || notifState.channel === 'webhook') && (
                  <div>
                    <label className="block text-xs font-semibold text-appTextMuted mb-1">
                      {notifState.channel === 'discord' ? t('notifDiscordUrlLabel', lang) : t('notifWebhookUrlLabel', lang)}
                    </label>
                    <input
                      type="url"
                      placeholder="https://..."
                      value={notifState.url}
                      onChange={e => {
                        setNotifState(prev => ({ ...prev, url: e.target.value }));
                        setNotifFeedback(null);
                      }}
                      className="w-full bg-appSurface border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none font-mono"
                    />
                  </div>
                )}

                {/* Trigger checkboxes */}
                <div className="space-y-1.5 pt-1">
                  <label className="flex items-center gap-2 cursor-pointer text-xs text-appText">
                    <input
                      type="checkbox"
                      checked={notifState.notifyOnWarning}
                      onChange={e => setNotifState(prev => ({ ...prev, notifyOnWarning: e.target.checked }))}
                      className="h-3.5 w-3.5 rounded border-appBorder accent-appAccent"
                    />
                    <span>{t('notifTriggerWarning', lang).replace('{pct}', String(notifState.warningThresholdPercent))}</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-xs text-appText">
                    <input
                      type="checkbox"
                      checked={notifState.notifyOnExhausted}
                      onChange={e => setNotifState(prev => ({ ...prev, notifyOnExhausted: e.target.checked }))}
                      className="h-3.5 w-3.5 rounded border-appBorder accent-appAccent"
                    />
                    <span>{t('notifTriggerExhausted', lang)}</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-xs text-appText">
                    <input
                      type="checkbox"
                      checked={notifState.notifyOnReset}
                      onChange={e => setNotifState(prev => ({ ...prev, notifyOnReset: e.target.checked }))}
                      className="h-3.5 w-3.5 rounded border-appBorder accent-appAccent"
                    />
                    <span>{t('notifTriggerReset', lang)}</span>
                  </label>
                </div>

                {/* Feedback */}
                {notifFeedback && (
                  <div
                    role="alert"
                    className={`rounded-lg border px-3 py-2 text-xs ${
                      notifFeedback.success
                        ? `border-emerald-500/30 bg-emerald-500/10 ${successTextClass}`
                        : `border-rose-500/30 bg-rose-500/10 ${dangerTextClass}`
                    }`}
                  >
                    {notifFeedback.message}
                  </div>
                )}

                {/* Action buttons */}
                <div className="flex flex-wrap gap-2 pt-1">
                  <button
                    type="submit"
                    disabled={notifSaving}
                    className="rounded-lg bg-appAccent px-3.5 py-2 text-xs font-semibold text-zinc-950 transition hover:bg-appAccentHover disabled:opacity-50"
                  >
                    {notifSaving ? t('notifSaving', lang) : t('notifSaveBtn', lang)}
                  </button>
                  <button
                    type="button"
                    onClick={sendTestNotification}
                    disabled={notifTesting}
                    className="rounded-lg border border-appBorder bg-appSurface px-3.5 py-2 text-xs font-semibold text-appText transition hover:border-appAccent disabled:opacity-50"
                  >
                    {notifTesting ? t('notifTesting', lang) : t('notifTestBtn', lang)}
                  </button>
                </div>
              </form>
            </section>
            <section className="space-y-3.5 border-t border-appBorder pt-4">
              <h4 className="text-sm font-bold text-appText">{t('accountSecurityTitle', lang)}</h4>
              <form id="changePasswordForm" onSubmit={changePassword} noValidate className="space-y-3">
                <div>
                  <label htmlFor="currentPassword" className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('currentPasswordLabel', lang)}</label>
                  <input id="currentPassword" name="currentPassword" type="password" autoComplete="current-password" required
                    value={changeCurrentPassword} onChange={e => {
                      setChangeCurrentPassword(e.target.value);
                      setChangePasswordMessage(null);
                      setChangePasswordSucceeded(false);
                    }}
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
                </div>
                <div>
                  <label htmlFor="newPassword" className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('newPasswordLabel', lang)}</label>
                  <input id="newPassword" name="newPassword" type="password" autoComplete="new-password" minLength={12} maxLength={256} required
                    value={changeNewPassword} onChange={e => {
                      setChangeNewPassword(e.target.value);
                      setChangePasswordMessage(null);
                      setChangePasswordSucceeded(false);
                    }}
                    aria-describedby="passwordPolicyHelp"
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
                  <p id="passwordPolicyHelp" className="text-[11px] text-appTextMuted mt-1">{t('passwordPolicyHelp', lang)}</p>
                </div>
                <div>
                  <label htmlFor="confirmNewPassword" className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('confirmNewPasswordLabel', lang)}</label>
                  <input id="confirmNewPassword" name="confirmNewPassword" type="password" autoComplete="new-password" minLength={12} maxLength={256} required
                    value={changeConfirmPassword} onChange={e => {
                      setChangeConfirmPassword(e.target.value);
                      setChangePasswordMessage(null);
                      setChangePasswordSucceeded(false);
                    }}
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
                </div>
                {changePasswordMessage && (
                  <div id="changePasswordStatus" role={changePasswordSucceeded ? 'status' : 'alert'}
                    className={`rounded-lg border px-3 py-2 text-xs ${changePasswordSucceeded
                      ? `border-emerald-500/30 bg-emerald-500/10 ${successTextClass}`
                      : `border-rose-500/30 bg-rose-500/10 ${dangerTextClass}`}`}>
                    {t(changePasswordMessage, lang)}
                  </div>
                )}
                <button id="changePasswordSubmit" type="submit" disabled={changePasswordSubmitting}
                  className="w-full rounded-lg bg-appAccent px-4 py-2.5 text-xs font-semibold text-zinc-950 transition hover:bg-appAccentHover disabled:cursor-not-allowed disabled:opacity-50">
                  {changePasswordSubmitting ? t('passwordChanging', lang) : t('passwordChangeSubmit', lang)}
                </button>
              </form>
            </section>

            <section className="space-y-3.5 border-t border-rose-500/30 pt-4">
              <div>
                <h4 className={`text-sm font-bold ${dangerTextClass}`}>{t('accountDeletionTitle', lang)}</h4>
                <p id="accountDeletionWarning" className={`mt-1.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2.5 text-xs leading-relaxed ${dangerStrongTextClass}`}>
                  {t('accountDeletionWarning', lang)}
                </p>
              </div>
              <form id="deleteUseMeterAccountForm" onSubmit={deleteUseMeterAccount} className="space-y-3">
                <div>
                  <label htmlFor="deleteAccountPassword" className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('currentPasswordLabel', lang)}</label>
                  <input id="deleteAccountPassword" name="password" type="password" autoComplete="current-password" required
                    value={deleteAccountPassword}
                    onChange={e => {
                      setDeleteAccountPassword(e.target.value);
                      setDeleteAccountMessage(null);
                    }}
                    aria-describedby="accountDeletionWarning"
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
                </div>
                <label htmlFor="confirmDeleteUseMeterAccount" className="flex items-start gap-2.5 rounded-lg border border-appBorder bg-appMuted/50 p-3 text-xs leading-relaxed text-appText cursor-pointer">
                  <input id="confirmDeleteUseMeterAccount" name="confirmDeletion" type="checkbox" required checked={deleteAccountConfirmed}
                    onChange={e => {
                      setDeleteAccountConfirmed(e.target.checked);
                      setDeleteAccountMessage(null);
                    }}
                    className="mt-0.5 h-4 w-4 shrink-0 accent-rose-500" />
                  <span>{t('accountDeletionConfirm', lang)}</span>
                </label>
                {deleteAccountMessage && (
                  <div id="deleteUseMeterAccountStatus" role="alert" className={`rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs ${dangerTextClass}`}>
                    {t(deleteAccountMessage, lang)}
                  </div>
                )}
                <button id="deleteUseMeterAccountSubmit" type="submit" disabled={deleteAccountSubmitting || !deleteAccountConfirmed}
                  className={`w-full rounded-lg border border-rose-500/50 bg-rose-500/10 px-4 py-2.5 text-xs font-semibold ${dangerTextClass} transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-50`}>
                  {deleteAccountSubmitting ? t('accountDeleting', lang) : t('accountDeletionSubmit', lang)}
                </button>
              </form>
            </section>
            <div className="flex justify-end pt-3 border-t border-appBorder">
              <button onClick={closeSettings} className="px-4 py-2 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition">{t('close', lang)}</button>
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
                    {OAUTH_PROVIDERS.map(op => {
                      const entry = findCatalogEntry(op.id);
                      const language = lang === 'tr' ? 'tr' : 'en';
                      return (
                        <button key={op.id} onClick={() => handleOAuthProviderClick(op.handler, op.id)}
                          className="w-full flex items-center justify-between p-3 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
                          <div className="flex items-center gap-3 min-w-0">
                            <div className="w-8 h-8 rounded-lg bg-appMuted flex items-center justify-center p-1.5 border border-appBorder shrink-0">{op.svg}</div>
                            <div className="min-w-0">
                              <div className="text-xs font-semibold text-appText group-hover:text-appAccent transition">{entry?.displayName[language] ?? t(op.titleKey, lang)}</div>
                              <div className="text-[11px] text-appTextMuted">{t(op.descKey, lang)}</div>
                              {entry && <ProviderSupportDetails entry={entry} lang={lang} />}
                            </div>
                          </div>
                          <span className="text-xs font-semibold text-appAccent shrink-0">{t(op.handler === 'devin' ? 'devinManualAction' : 'loginBtn', lang)}</span>
                        </button>
                      );
                    })}
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
                    {MANUAL_PROVIDERS.map(mp => {
                      const language = lang === 'tr' ? 'tr' : 'en';
                      return (
                        <option key={mp.id} value={mp.id}>
                          {mp.displayName[language]} — {supportTierLabel(mp.supportTier, lang)} · {quotaKindLabel(mp.quotaKind, lang)}
                        </option>
                      );
                    })}
                  </select>
                  {manualProviderEntry && <ProviderSupportDetails entry={manualProviderEntry} lang={lang} />}
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
                  <select key={manualProvider} name="credentialType" defaultValue={hint.type}
                    className="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none">
                    <option value="api_key">{t('apiKey', lang)}</option>
                    <option value="oauth">{t('oauthToken', lang)}</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-appTextMuted mb-1.5">{t('secretLabel', lang)}</label>
                  <input key={manualProvider} type="password" name="secret" placeholder={hint.placeholder} required
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
