const RECOVERY_PAGE_I18N = {
  tr: {
    requestTitle: "Parolanızı mı unuttunuz?",
    requestSubtitle: "Hesabınıza bağlı e-posta adresini girin. Hesap varsa kurtarma bağlantısı gönderilir.",
    resetTitle: "Yeni parola belirleyin",
    resetSubtitle: "Hesabınıza yeniden erişmek için yeni bir parola oluşturun.",
    emailLabel: "E-posta adresi",
    emailPlaceholder: "name@example.com",
    requestSubmit: "Kurtarma Bağlantısı Gönder",
    requestSubmitting: "Gönderiliyor...",
    requestSuccess: "Bu e-posta adresiyle bir hesap varsa parola kurtarma talimatları gönderilecektir. Gelen kutunuzu ve spam klasörünüzü kontrol edin.",
    requestUnavailable: "Parola kurtarma şu anda kullanılamıyor. Lütfen daha sonra tekrar deneyin.",
    requestRateLimited: "Çok fazla deneme yapıldı. Lütfen biraz bekleyip yeniden deneyin.",
    resetPasswordLabel: "Yeni parola",
    confirmPasswordLabel: "Yeni parolayı doğrula",
    passwordPolicyHelp: "Parola en az 12 Unicode karakteri ve kod birimi içermeli; en fazla 256 karakteri, kod birimini ve UTF-8 baytını aşmamalı.",
    passwordMismatch: "Yeni parolalar eşleşmiyor.",
    weakPassword: "Parola güvenlik gereksinimlerini karşılamıyor.",
    resetSubmit: "Parolayı Sıfırla",
    resetSubmitting: "Kaydediliyor...",
    resetSuccess: "Parolanız sıfırlandı. Yeni parolanızla giriş yapabilirsiniz.",
    invalidReset: "Bu parola sıfırlama bağlantısı geçersiz, süresi dolmuş veya kullanılmış.",
    requestNewLink: "Yeni kurtarma bağlantısı isteyin",
    signIn: "Giriş Yap",
    generalError: "İşlem tamamlanamadı. Lütfen tekrar deneyin.",
    accountAccess: "GÜVENLİ HESAP ERİŞİMİ",
    themeLabel: "Temayı değiştir",
    languageLabel: "Dili değiştir",
    legalPrivacy: "Gizlilik",
    legalTerms: "Kullanım Koşulları",
    legalSecurity: "Güvenlik",
    legalSupport: "Destek",
  },
  en: {
    requestTitle: "Forgot your password?",
    requestSubtitle: "Enter the email address for your account. If an account exists, recovery instructions will be sent.",
    resetTitle: "Choose a new password",
    resetSubtitle: "Create a new password to regain access to your account.",
    emailLabel: "Email address",
    emailPlaceholder: "name@example.com",
    requestSubmit: "Send Recovery Link",
    requestSubmitting: "Sending...",
    requestSuccess: "If an account exists for this email address, password-recovery instructions will be sent. Check your inbox and spam folder.",
    requestUnavailable: "Password recovery is currently unavailable. Please try again later.",
    requestRateLimited: "Too many attempts. Wait a little and try again.",
    resetPasswordLabel: "New password",
    confirmPasswordLabel: "Confirm new password",
    passwordPolicyHelp: "Use at least 12 Unicode characters and code units; the password must not exceed 256 characters, code units, or UTF-8 bytes.",
    passwordMismatch: "The new passwords do not match.",
    weakPassword: "The password does not meet the security requirements.",
    resetSubmit: "Reset Password",
    resetSubmitting: "Saving...",
    resetSuccess: "Your password has been reset. You can now sign in with the new password.",
    invalidReset: "This password-reset link is invalid, expired, or already used.",
    requestNewLink: "Request a new recovery link",
    signIn: "Sign In",
    generalError: "The operation could not be completed. Please try again.",
    accountAccess: "SECURE ACCOUNT ACCESS",
    themeLabel: "Toggle theme",
    languageLabel: "Change language",
    legalPrivacy: "Privacy",
    legalTerms: "Terms",
    legalSecurity: "Security",
    legalSupport: "Support",
  },
} as const;

type RecoveryTextKey = keyof typeof RECOVERY_PAGE_I18N.tr;

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function scriptSafeJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

export function renderAccountRecoveryPageHtml(options: {
  mode: "request" | "reset";
  recoveryConfigured: boolean;
}): string {
  const isRequest = options.mode === "request";
  const recoveryConfigured = options.recoveryConfigured;
  const text = (key: RecoveryTextKey): string => escapeHtml(RECOVERY_PAGE_I18N.tr[key]);
  const title = text(isRequest ? "requestTitle" : "resetTitle");
  const serializedTranslations = scriptSafeJson(RECOVERY_PAGE_I18N);
  const clientScript = isRequest
    ? `(() => {
  const translations = ${serializedTranslations};
  const recoveryConfigured = ${recoveryConfigured ? "true" : "false"};
  let language = "tr";
  let theme = "dark";

  function readPreference(key) {
    try { return window.localStorage.getItem(key); } catch { return null; }
  }

  function savePreference(key, value) {
    try { window.localStorage.setItem(key, value); } catch { /* preference storage is optional */ }
  }

  function translate(key) {
    return (translations[language] && translations[language][key]) || translations.tr[key];
  }

  function applyLanguage() {
    document.documentElement.lang = language;
    document.querySelectorAll("[data-i18n]").forEach((element) => {
      const key = element.getAttribute("data-i18n");
      if (key) element.textContent = translate(key);
    });
    document.querySelectorAll("[data-i18n-title]").forEach((element) => {
      const key = element.getAttribute("data-i18n-title");
      if (key) {
        element.setAttribute("aria-label", translate(key));
        element.setAttribute("title", translate(key));
      }
    });
    document.title = translate("requestTitle") + " | useMeter";
    const flag = document.getElementById("languageFlag");
    const label = document.getElementById("languageCode");
    if (flag) flag.textContent = language === "tr" ? "🇹🇷" : "🇬🇧";
    if (label) label.textContent = language.toUpperCase();
  }

  function applyTheme() {
    document.documentElement.classList.toggle("light", theme === "light");
    document.documentElement.classList.toggle("dark", theme !== "light");
    const icon = document.getElementById("themeIcon");
    if (icon) icon.textContent = theme === "light" ? "☾" : "☼";
  }

  function showStatus(key, kind) {
    const status = document.getElementById("recoveryStatus");
    if (!status) return;
    status.hidden = false;
    status.className = "status " + (kind === "success" ? "status-success" : "status-error");
    status.textContent = translate(key);
  }

  function responseErrorKey(response, payload) {
    const code = payload && typeof payload.errorCode === "string" ? payload.errorCode : "";
    if (code === "RECOVERY_UNAVAILABLE" || response.status === 503) return "requestUnavailable";
    if (code === "RATE_LIMITED" || response.status === 429) return "requestRateLimited";
    return "generalError";
  }

  function initialize() {
    const savedLanguage = readPreference("usage_lang");
    const browserLanguage = (navigator.language || "").toLowerCase();
    language = savedLanguage === "tr" || savedLanguage === "en"
      ? savedLanguage
      : browserLanguage.startsWith("tr") ? "tr" : "en";
    theme = readPreference("usage_mode") === "light" ? "light" : "dark";
    applyLanguage();
    applyTheme();

    const form = document.getElementById("recoveryRequestForm");
    const email = document.getElementById("recoveryEmail");
    const button = document.getElementById("recoveryRequestSubmit");
    const unavailable = document.getElementById("recoveryUnavailableNotice");
    if (!recoveryConfigured && unavailable) unavailable.hidden = false;
    if (button) button.disabled = !recoveryConfigured;

    document.getElementById("languageToggle")?.addEventListener("click", () => {
      language = language === "tr" ? "en" : "tr";
      savePreference("usage_lang", language);
      applyLanguage();
    });
    document.getElementById("themeToggle")?.addEventListener("click", () => {
      theme = theme === "light" ? "dark" : "light";
      savePreference("usage_mode", theme);
      applyTheme();
    });
    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!recoveryConfigured || !email || !button) {
        showStatus("requestUnavailable", "error");
        return;
      }
      const address = email.value.trim();
      if (!address || !email.checkValidity()) {
        email.reportValidity();
        return;
      }
      button.disabled = true;
      button.textContent = translate("requestSubmitting");
      const status = document.getElementById("recoveryStatus");
      if (status) status.hidden = true;
      try {
        const response = await fetch("/api/auth/password/reset-request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: address }),
        });
        const payload = await response.json().catch(() => null);
        if (response.status === 202 && payload && payload.success === true) {
          showStatus("requestSuccess", "success");
        } else {
          showStatus(responseErrorKey(response, payload), "error");
        }
      } catch {
        showStatus("generalError", "error");
      } finally {
        button.disabled = !recoveryConfigured;
        button.textContent = translate("requestSubmit");
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();`
    : `(() => {
  let resetToken = new URLSearchParams(window.location.hash.slice(1)).get("token") || "";
  window.history.replaceState(null, "", window.location.pathname);
  const translations = ${serializedTranslations};
  let language = "tr";
  let theme = "dark";

  function readPreference(key) {
    try { return window.localStorage.getItem(key); } catch { return null; }
  }

  function savePreference(key, value) {
    try { window.localStorage.setItem(key, value); } catch { /* preference storage is optional */ }
  }

  function translate(key) {
    return (translations[language] && translations[language][key]) || translations.tr[key];
  }

  function applyLanguage() {
    document.documentElement.lang = language;
    document.querySelectorAll("[data-i18n]").forEach((element) => {
      const key = element.getAttribute("data-i18n");
      if (key) element.textContent = translate(key);
    });
    document.querySelectorAll("[data-i18n-title]").forEach((element) => {
      const key = element.getAttribute("data-i18n-title");
      if (key) {
        element.setAttribute("aria-label", translate(key));
        element.setAttribute("title", translate(key));
      }
    });
    document.title = translate("resetTitle") + " | useMeter";
    const flag = document.getElementById("languageFlag");
    const label = document.getElementById("languageCode");
    if (flag) flag.textContent = language === "tr" ? "🇹🇷" : "🇬🇧";
    if (label) label.textContent = language.toUpperCase();
  }

  function applyTheme() {
    document.documentElement.classList.toggle("light", theme === "light");
    document.documentElement.classList.toggle("dark", theme !== "light");
    const icon = document.getElementById("themeIcon");
    if (icon) icon.textContent = theme === "light" ? "☾" : "☼";
  }

  function showStatus(key, kind) {
    const status = document.getElementById("recoveryStatus");
    if (!status) return;
    status.hidden = false;
    status.className = "status " + (kind === "success" ? "status-success" : "status-error");
    status.textContent = translate(key);
  }

  function showInvalidLink() {
    const form = document.getElementById("recoveryResetForm");
    const invalid = document.getElementById("invalidResetLink");
    if (form) form.hidden = true;
    if (invalid) invalid.hidden = false;
  }

  function responseErrorKey(response, payload) {
    const code = payload && typeof payload.errorCode === "string" ? payload.errorCode : "";
    if (code === "INVALID_RESET_TOKEN") return "invalidReset";
    if (code === "WEAK_PASSWORD") return "weakPassword";
    if (code === "RATE_LIMITED" || response.status === 429) return "requestRateLimited";
    if (code === "RECOVERY_UNAVAILABLE" || response.status === 503) return "requestUnavailable";
    return "generalError";
  }

  function passwordWithinPolicy(value) {
    const unicodeCharacters = Array.from(value).length;
    const codeUnits = value.length;
    const utf8Bytes = new TextEncoder().encode(value).byteLength;
    return unicodeCharacters >= 12 && codeUnits >= 12
      && unicodeCharacters <= 256 && codeUnits <= 256 && utf8Bytes <= 256;
  }

  function initialize() {
    const savedLanguage = readPreference("usage_lang");
    const browserLanguage = (navigator.language || "").toLowerCase();
    language = savedLanguage === "tr" || savedLanguage === "en"
      ? savedLanguage
      : browserLanguage.startsWith("tr") ? "tr" : "en";
    theme = readPreference("usage_mode") === "light" ? "light" : "dark";
    applyLanguage();
    applyTheme();

    document.getElementById("languageToggle")?.addEventListener("click", () => {
      language = language === "tr" ? "en" : "tr";
      savePreference("usage_lang", language);
      applyLanguage();
    });
    document.getElementById("themeToggle")?.addEventListener("click", () => {
      theme = theme === "light" ? "dark" : "light";
      savePreference("usage_mode", theme);
      applyTheme();
    });

    const form = document.getElementById("recoveryResetForm");
    const password = document.getElementById("resetNewPassword");
    const confirmation = document.getElementById("resetConfirmPassword");
    const button = document.getElementById("recoveryResetSubmit");
    const successPanel = document.getElementById("resetSuccessPanel");
    if (!resetToken) {
      showInvalidLink();
      showStatus("invalidReset", "error");
      return;
    }
    if (password) password.disabled = false;
    if (confirmation) confirmation.disabled = false;
    if (button) button.disabled = false;

    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!password || !confirmation || !button || !passwordWithinPolicy(password.value)) {
        showStatus("weakPassword", "error");
        password?.focus();
        return;
      }
      if (password.value !== confirmation.value) {
        showStatus("passwordMismatch", "error");
        confirmation.focus();
        return;
      }
      button.disabled = true;
      button.textContent = translate("resetSubmitting");
      const status = document.getElementById("recoveryStatus");
      if (status) status.hidden = true;
      try {
        const response = await fetch("/api/auth/password/reset-confirm", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: resetToken, newPassword: password.value }),
        });
        const payload = await response.json().catch(() => null);
        if (response.ok && payload && payload.success === true) {
          resetToken = "";
          password.value = "";
          confirmation.value = "";
          if (form) form.hidden = true;
          if (successPanel) successPanel.hidden = false;
          return;
        }
        const errorKey = responseErrorKey(response, payload);
        showStatus(errorKey, "error");
        if (errorKey === "invalidReset") {
          resetToken = "";
          password.value = "";
          confirmation.value = "";
          showInvalidLink();
        }
      } catch {
        showStatus("generalError", "error");
      } finally {
        if (button && resetToken) {
          button.disabled = false;
          button.textContent = translate("resetSubmit");
        }
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();`;

  const requestUnavailableNotice = isRequest && !recoveryConfigured;
  const content = isRequest
    ? `
        <p class="subtitle" data-i18n="requestSubtitle">${text("requestSubtitle")}</p>
        <div id="recoveryUnavailableNotice" class="status status-error" role="status"${requestUnavailableNotice ? "" : " hidden"} data-i18n="requestUnavailable">${text("requestUnavailable")}</div>
        <form id="recoveryRequestForm" class="form" method="post" action="/forgot-password">
          <div class="field">
            <label for="recoveryEmail" data-i18n="emailLabel">${text("emailLabel")}</label>
            <input id="recoveryEmail" name="email" type="email" autocomplete="email" required placeholder="${text("emailPlaceholder")}" />
          </div>
          <div id="recoveryStatus" class="status" role="status" aria-live="polite" hidden></div>
          <button id="recoveryRequestSubmit" class="primary-button" type="submit" disabled data-i18n="requestSubmit">${text("requestSubmit")}</button>
        </form>
        <p class="back-link"><a href="/login" data-i18n="signIn">${text("signIn")}</a></p>`
    : `
        <p class="subtitle" data-i18n="resetSubtitle">${text("resetSubtitle")}</p>
        <div id="invalidResetLink" class="invalid-link" hidden>
          <p data-i18n="invalidReset">${text("invalidReset")}</p>
          <a href="/forgot-password" class="text-link" data-i18n="requestNewLink">${text("requestNewLink")}</a>
        </div>
        <form id="recoveryResetForm" class="form" method="post" action="/reset-password" novalidate>
          <div class="field">
            <label for="resetNewPassword" data-i18n="resetPasswordLabel">${text("resetPasswordLabel")}</label>
            <input id="resetNewPassword" name="newPassword" type="password" autocomplete="new-password" minlength="12" maxlength="256" required disabled aria-describedby="passwordPolicyHelp" />
            <p id="passwordPolicyHelp" class="field-help" data-i18n="passwordPolicyHelp">${text("passwordPolicyHelp")}</p>
          </div>
          <div class="field">
            <label for="resetConfirmPassword" data-i18n="confirmPasswordLabel">${text("confirmPasswordLabel")}</label>
            <input id="resetConfirmPassword" name="confirmPassword" type="password" autocomplete="new-password" minlength="12" maxlength="256" required disabled />
          </div>
          <div id="recoveryStatus" class="status" role="status" aria-live="polite" hidden></div>
          <button id="recoveryResetSubmit" class="primary-button" type="submit" disabled data-i18n="resetSubmit">${text("resetSubmit")}</button>
        </form>
        <div id="resetSuccessPanel" class="success-panel" hidden>
          <p class="status status-success" data-i18n="resetSuccess">${text("resetSuccess")}</p>
          <a href="/login" class="text-link" data-i18n="signIn">${text("signIn")}</a>
        </div>
        <p class="back-link"><a href="/login" data-i18n="signIn">${text("signIn")}</a></p>`;

  return `<!doctype html>
<html lang="tr" class="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <script>${clientScript}</script>
  <title>${title} | useMeter</title>
  <style>
    :root { color-scheme: dark; --page-bg:#090a0d; --surface:#111318; --border:#1f232b; --muted:#171a21; --text:#f4f4f6; --text-muted:#8e95a5; --accent:#ff9849; --accent-hover:#ea7c2b; --danger:#fb7185; }
    html.light { color-scheme: light; --page-bg:#f8fafc; --surface:#fff; --border:#e2e8f0; --muted:#f1f5f9; --text:#0f172a; --text-muted:#64748b; --accent:#ea580c; --accent-hover:#c2410c; --danger:#e11d48; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; display:flex; flex-direction:column; background:var(--page-bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; -webkit-font-smoothing:antialiased; }
    .topbar { height:64px; display:flex; align-items:center; justify-content:space-between; padding:0 max(20px,calc((100vw - 1120px)/2)); border-bottom:1px solid var(--border); background:color-mix(in srgb,var(--surface) 88%,transparent); }
    .brand { color:var(--text); font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:18px; font-weight:800; letter-spacing:.04em; text-decoration:none; }
    .brand-accent { color:var(--accent); }
    .controls { display:flex; gap:8px; align-items:center; }
    .control { min-width:38px; height:36px; padding:0 10px; border:1px solid var(--border); border-radius:9px; background:var(--surface); color:var(--text); font:inherit; font-size:12px; font-weight:600; cursor:pointer; }
    .control:hover { border-color:var(--accent); }
    main { flex:1; min-height:calc(100vh - 112px); display:grid; place-items:center; padding:40px 16px; }
    .card { width:min(100%,440px); position:relative; overflow:hidden; border:1px solid var(--border); border-radius:18px; background:var(--surface); padding:30px; box-shadow:0 20px 55px rgba(0,0,0,.22); }
    .card::before { content:""; position:absolute; inset:0 0 auto; height:3px; background:linear-gradient(90deg,transparent,var(--accent),transparent); opacity:.8; }
    .mark { width:42px; height:42px; display:grid; place-items:center; margin-bottom:18px; border:1px solid color-mix(in srgb,var(--accent) 30%,var(--border)); border-radius:12px; background:color-mix(in srgb,var(--accent) 12%,var(--surface)); color:var(--accent); }
    .mark svg { width:20px; height:20px; }
    .eyebrow { margin:0 0 8px; color:var(--accent); font-size:10px; font-weight:800; letter-spacing:.12em; }
    h1 { margin:0; font-size:22px; line-height:1.25; letter-spacing:-.02em; }
    .subtitle { margin:9px 0 22px; color:var(--text-muted); font-size:13px; line-height:1.65; }
    .form { display:grid; gap:17px; }
    .field { display:grid; gap:7px; }
    label { color:var(--text-muted); font-size:12px; font-weight:650; }
    input { width:100%; min-height:42px; border:1px solid var(--border); border-radius:9px; background:var(--muted); color:var(--text); padding:10px 12px; font:inherit; font-size:14px; outline:none; }
    input:focus { border-color:var(--accent); box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 18%,transparent); }
    input:disabled { opacity:.55; cursor:not-allowed; }
    .field-help { margin:0; color:var(--text-muted); font-size:11px; line-height:1.5; }
    .primary-button { width:100%; min-height:42px; border:0; border-radius:9px; background:var(--accent); color:#17120d; padding:10px 14px; font-size:13px; font-weight:750; cursor:pointer; transition:background .15s ease,opacity .15s ease; }
    .primary-button:hover:not(:disabled) { background:var(--accent-hover); }
    .primary-button:disabled { opacity:.55; cursor:not-allowed; }
    .status { margin:0; padding:11px 12px; border:1px solid var(--border); border-radius:10px; font-size:12px; line-height:1.55; }
    .status-success { border-color:rgba(16,185,129,.35); background:rgba(16,185,129,.1); color:#34d399; }
    html.light .status-success { color:#047857; }
    .status-error,.invalid-link { border-color:color-mix(in srgb,var(--danger) 35%,var(--border)); background:color-mix(in srgb,var(--danger) 9%,var(--surface)); color:var(--danger); }
    .invalid-link { margin:0 0 16px; padding:12px; border:1px solid; border-radius:10px; font-size:12px; line-height:1.55; }
    .invalid-link p { margin:0 0 8px; }
    .text-link,.back-link a { color:var(--accent); font-size:12px; font-weight:700; text-decoration:none; }
    .text-link:hover,.back-link a:hover { text-decoration:underline; }
    .success-panel { margin-top:14px; }
    .back-link { margin:22px 0 0; padding-top:16px; border-top:1px solid var(--border); text-align:center; }
    .legal-footer { border-top:1px solid var(--border); padding:15px 16px 18px; text-align:center; }
    .legal-footer nav { display:flex; flex-wrap:wrap; justify-content:center; gap:8px 18px; }
    .legal-footer a { color:var(--text-muted); font-size:11px; font-weight:650; text-decoration:none; }
    .legal-footer a:hover { color:var(--accent); text-decoration:underline; }
    [hidden] { display:none !important; }
    :focus-visible { outline:2px solid var(--accent); outline-offset:3px; }
    @media (max-width:480px) { .card { padding:25px 21px; } .topbar { padding:0 16px; } }
    @media (prefers-reduced-motion:reduce) { *,*::before,*::after { scroll-behavior:auto !important; transition:none !important; } }
  </style>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/login" aria-label="useMeter">use<span class="brand-accent">Meter</span></a>
    <div class="controls">
      <button id="themeToggle" class="control" type="button" data-i18n-title="themeLabel" aria-label="${text("themeLabel")}" title="${text("themeLabel")}"><span id="themeIcon" aria-hidden="true">☼</span></button>
      <button id="languageToggle" class="control" type="button" data-i18n-title="languageLabel" aria-label="${text("languageLabel")}" title="${text("languageLabel")}"><span id="languageFlag" aria-hidden="true">🇹🇷</span> <span id="languageCode">TR</span></button>
    </div>
  </header>
  <main>
    <section class="card" aria-labelledby="pageTitle">
      <div class="mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3"/></svg></div>
      <p class="eyebrow" data-i18n="accountAccess">${text("accountAccess")}</p>
      <h1 id="pageTitle" data-i18n="${isRequest ? "requestTitle" : "resetTitle"}">${title}</h1>
      ${content}
    </section>
  </main>
  <footer class="legal-footer">
    <nav aria-label="Information and support links">
      <a href="/privacy" data-i18n="legalPrivacy">Gizlilik</a>
      <a href="/terms" data-i18n="legalTerms">Kullanım Koşulları</a>
      <a href="/security" data-i18n="legalSecurity">Güvenlik</a>
      <a href="/support" data-i18n="legalSupport">Destek</a>
    </nav>
  </footer>
</body>
</html>`;
}
