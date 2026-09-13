import { Hono } from "hono";
import { cors } from "hono/cors";
import type { StorageVault } from "../core/storage/vault";
import type { PollerEngine } from "../core/poller/poller";
import type { ProviderRegistry } from "../core/providers/registry";
import type { InputCredential } from "../types";
import {
  initiateCodexDeviceAuth,
  pollCodexDeviceAuth,
  exchangeCodexToken,
} from "../core/oauth/codex-device";
import {
  initiateGoogleAuth,
  exchangeGoogleCode,
  listenForGoogleCallback,
} from "../core/oauth/google";
import {
  initiateClaudeAuth,
  exchangeClaudeCode,
  listenForClaudeCallback,
} from "../core/oauth/claude";

interface PendingOAuthSession {
  provider: string;
  status: "pending" | "complete" | "error";
  error?: string;
  accountLabel?: string;
}

export function createServer(vault: StorageVault, poller: PollerEngine, _registry: ProviderRegistry): Hono {
  const app = new Hono();
  const pendingOAuth = new Map<string, PendingOAuthSession>();

  app.use("*", cors());

  // Health
  app.get("/health", c => {
    return c.json({
      status: "ok",
      integrity: vault.checkIntegrity(),
      pollerRunning: poller.isRunning(),
    });
  });

  // API: Get latest usage
  app.get("/api/usage", c => {
    const latest = vault.getLatestUsage();
    return c.json({ success: true, data: latest });
  });

  // API: Trigger poll now
  app.post("/api/poll", async c => {
    const reports = await poller.pollAll();
    return c.json({ success: true, count: reports.length, data: reports });
  });

  // API: List credentials (masked)
  app.get("/api/credentials", c => {
    const creds = vault.listCredentials();
    const masked = creds.map(cr => {
      const s = cr.secret;
      const maskedSecret = s.length > 8 ? `${s.slice(0, 4)}...${s.slice(-4)}` : "********";
      return {
        id: cr.id,
        provider: cr.provider,
        accountLabel: cr.accountLabel,
        credentialType: cr.credentialType,
        maskedSecret,
        createdAt: cr.createdAt,
      };
    });
    return c.json({ success: true, data: masked });
  });

  // API: Add manual credential
  app.post("/api/credentials", async c => {
    try {
      const body = (await c.req.json()) as InputCredential;
      if (!body.provider || !body.accountLabel || !body.secret) {
        return c.json({ success: false, error: "Tüm alanlar zorunludur." }, 400);
      }

      const saved = vault.saveCredential(body);
      poller.pollCredential(saved).catch(() => {});

      return c.json({
        success: true,
        data: {
          id: saved.id,
          provider: saved.provider,
          accountLabel: saved.accountLabel,
        },
      });
    } catch (err) {
      return c.json({ success: false, error: String(err) }, 500);
    }
  });

  // API: Delete credential
  app.delete("/api/credentials/:id", c => {
    const id = c.req.param("id");
    const ok = vault.deleteCredential(id);
    return c.json({ success: ok });
  });

  // OAuth: Codex Device Auth - Initiate
  app.post("/api/oauth/codex/initiate", async c => {
    try {
      const result = await initiateCodexDeviceAuth();
      return c.json({ success: true, data: result });
    } catch (err) {
      return c.json({ success: false, error: String(err) }, 500);
    }
  });

  // OAuth: Codex Device Auth - Poll & Exchange
  app.post("/api/oauth/codex/poll", async c => {
    try {
      const body = (await c.req.json()) as { deviceAuthId: string; userCode: string; label?: string };
      const pollRes = await pollCodexDeviceAuth(body.deviceAuthId, body.userCode);

      if (pollRes.status === "pending") {
        return c.json({ status: "pending" });
      }

      if (pollRes.status === "error") {
        return c.json({ status: "error", error: pollRes.message });
      }

      const tokenResult = await exchangeCodexToken(pollRes.authorizationCode, pollRes.codeVerifier);
      const accountLabel = body.label || tokenResult.email || "ChatGPT Codex";

      const saved = vault.saveCredential({
        provider: "openai-codex",
        accountLabel,
        credentialType: "oauth",
        secret: tokenResult.accessToken,
        metadata: {
          refreshToken: tokenResult.refreshToken,
          accountId: tokenResult.accountId,
          email: tokenResult.email,
          planType: tokenResult.planType,
        },
      });

      poller.pollCredential(saved).catch(() => {});

      return c.json({
        status: "complete",
        data: { id: saved.id, accountLabel: saved.accountLabel },
      });
    } catch (err) {
      return c.json({ status: "error", error: String(err) }, 500);
    }
  });

  // OAuth: Google (Antigravity / Gemini) - Initiate
  app.post("/api/oauth/google/initiate", c => {
    try {
      const { authUrl, verifier, state } = initiateGoogleAuth();
      const sessionId = state;

      pendingOAuth.set(sessionId, { provider: "google-antigravity", status: "pending" });

      listenForGoogleCallback(state)
        .then(async code => {
          const tokens = await exchangeGoogleCode(code, verifier);
          const label = tokens.email ? `Google (${tokens.email})` : "Google Gemini";

          const saved = vault.saveCredential({
            provider: "google-antigravity",
            accountLabel: label,
            credentialType: "oauth",
            secret: tokens.accessToken,
            metadata: {
              refreshToken: tokens.refreshToken,
              email: tokens.email,
            },
          });

          poller.pollCredential(saved).catch(() => {});
          pendingOAuth.set(sessionId, { provider: "google-antigravity", status: "complete", accountLabel: label });
        })
        .catch(err => {
          pendingOAuth.set(sessionId, { provider: "google-antigravity", status: "error", error: String(err) });
        });

      return c.json({ success: true, data: { authUrl, sessionId } });
    } catch (err) {
      return c.json({ success: false, error: String(err) }, 500);
    }
  });

  // OAuth: Claude - Initiate
  app.post("/api/oauth/claude/initiate", c => {
    try {
      const { authUrl, verifier, state } = initiateClaudeAuth();
      const sessionId = state;

      pendingOAuth.set(sessionId, { provider: "anthropic", status: "pending" });

      listenForClaudeCallback(state)
        .then(async code => {
          const tokens = await exchangeClaudeCode(code, verifier);
          const label = "Claude Pro/Max";

          const saved = vault.saveCredential({
            provider: "anthropic",
            accountLabel: label,
            credentialType: "oauth",
            secret: tokens.accessToken,
            metadata: {
              refreshToken: tokens.refreshToken,
            },
          });

          poller.pollCredential(saved).catch(() => {});
          pendingOAuth.set(sessionId, { provider: "anthropic", status: "complete", accountLabel: label });
        })
        .catch(err => {
          pendingOAuth.set(sessionId, { provider: "anthropic", status: "error", error: String(err) });
        });

      return c.json({ success: true, data: { authUrl, sessionId } });
    } catch (err) {
      return c.json({ success: false, error: String(err) }, 500);
    }
  });

  // OAuth: Check pending session status (Google & Claude)
  app.get("/api/oauth/status/:sessionId", c => {
    const sessionId = c.req.param("sessionId");
    const session = pendingOAuth.get(sessionId);
    if (!session) return c.json({ status: "not_found" }, 404);
    return c.json(session);
  });

  // UI: Dashboard
  app.get("/", c => {
    return c.html(renderDashboardHtml());
  });

  return app;
}

function renderDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="tr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Usage & Quota Tracker</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            bg: 'var(--color-bg)',
            surface: 'var(--color-surface)',
            surfaceBorder: 'var(--color-border)',
            accent: 'var(--color-accent)',
            accentHover: 'var(--color-accent-hover)',
            accentBg: 'var(--color-accent-bg)'
          }
        }
      }
    }
  </script>
  <style>
    :root {
      --color-bg: #0a0a0b;
      --color-surface: #121215;
      --color-border: #27272a;
      --color-accent: #ff9849;
      --color-accent-hover: #ea7c2b;
      --color-accent-bg: rgba(255, 152, 73, 0.15);
    }
    body { background-color: var(--color-bg); color: #f4f4f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  </style>
</head>
<body class="min-h-screen flex flex-col transition-colors duration-300">
  <!-- Top Navigation -->
  <header class="border-b border-surfaceBorder bg-surface/60 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-10">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded-lg bg-accentBg border border-accent/40 flex items-center justify-center text-accent font-bold">
        ⚡
      </div>
      <div>
        <h1 class="font-bold text-lg leading-none" data-i18n="title">AI Usage Tracker</h1>
        <span class="text-xs text-zinc-500" data-i18n="subtitle">Multi-Provider Quota & Balance Hub</span>
      </div>
    </div>
    <div class="flex items-center gap-3">
      <!-- Theme Selector Dropdown -->
      <div class="relative">
        <select id="themeSelect" onchange="changeTheme(this.value)" class="bg-zinc-900 border border-surfaceBorder rounded-md px-2.5 py-1.5 text-xs text-zinc-300 outline-none focus:border-accent cursor-pointer">
          <option value="amber">⚡ Amber</option>
          <option value="emerald">🌿 Emerald</option>
          <option value="cyan">🌊 Cyan</option>
          <option value="violet">🔮 Violet</option>
          <option value="slate">❄️ Slate</option>
        </select>
      </div>

      <!-- Language Switcher Toggle -->
      <button onclick="toggleLang()" id="langBtn" class="px-2.5 py-1.5 rounded-md text-xs font-semibold bg-zinc-900 border border-surfaceBorder text-zinc-300 hover:border-accent transition flex items-center gap-1.5">
        <span>🌐</span>
        <span id="langLabel">TR</span>
      </button>

      <!-- Refresh Button -->
      <button onclick="pollNow()" id="pollBtn" class="px-3 py-1.5 rounded-md text-xs font-medium bg-zinc-800 hover:bg-zinc-700 transition flex items-center gap-1.5 text-zinc-200">
        <span id="pollSpinner" class="hidden animate-spin">⟳</span>
        <span data-i18n="refresh">Yenile</span>
      </button>

      <!-- Connect Account Button -->
      <button onclick="openModal()" class="px-3.5 py-1.5 rounded-md text-xs font-semibold bg-accent hover:bg-accentHover text-zinc-950 transition" data-i18n="addAccount">
        + Hesap Bağla
      </button>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
    <!-- Quick Status Cards Grid -->
    <div id="cardsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
      <div class="col-span-full py-12 text-center text-zinc-500 animate-pulse" data-i18n="loading">
        Kullanım verileri yükleniyor...
      </div>
    </div>
  </main>

  <!-- Add Credential / OAuth Modal -->
  <div id="modal" class="fixed inset-0 bg-black/70 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
    <div class="bg-surface border border-surfaceBorder rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl">
      <div class="flex justify-between items-center">
        <h3 class="font-semibold text-zinc-100" data-i18n="modalTitle">AI Hesabı Bağla</h3>
        <button onclick="closeModal()" class="text-zinc-500 hover:text-zinc-300 text-sm">✕</button>
      </div>

      <!-- Tab Buttons -->
      <div class="flex border-b border-surfaceBorder">
        <button onclick="switchTab('oauth')" id="tabOAuth" class="flex-1 pb-2.5 text-xs font-semibold border-b-2 border-accent text-accent" data-i18n="tabOAuth">
          ⚡ Oturum Açarak Bağlan (OAuth)
        </button>
        <button onclick="switchTab('manual')" id="tabManual" class="flex-1 pb-2.5 text-xs font-semibold border-b-2 border-transparent text-zinc-400 hover:text-zinc-200" data-i18n="tabManual">
          🔑 Manuel API Key / Token
        </button>
      </div>

      <!-- OAuth Section -->
      <div id="oauthSection" class="space-y-4">
        <p class="text-xs text-zinc-400" data-i18n="oauthDesc">Tek tıkla resmi oturum açma penceresine yönlendirilirsiniz. Token'lar yerel kasada şifrelenir.</p>
        
        <div class="grid grid-cols-1 gap-2.5">
          <!-- Google / Gemini Button -->
          <button onclick="startGoogleOAuth()" class="flex items-center justify-between p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-accent hover:bg-zinc-800/80 transition group">
            <div class="flex items-center gap-3">
              <span class="text-xl">🌐</span>
              <div class="text-left">
                <div class="text-xs font-semibold text-zinc-100 group-hover:text-accent transition" data-i18n="googleTitle">Google Gemini / Cloud Code</div>
                <div class="text-[10px] text-zinc-500" data-i18n="googleDesc">Gemini 3 Flash, 2.5 Pro model kotaları</div>
              </div>
            </div>
            <span class="text-xs font-medium text-accent" data-i18n="loginBtn">Giriş Yap →</span>
          </button>

          <!-- OpenAI / Codex Button -->
          <button onclick="startCodexOAuth()" class="flex items-center justify-between p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-accent hover:bg-zinc-800/80 transition group">
            <div class="flex items-center gap-3">
              <span class="text-xl">🤖</span>
              <div class="text-left">
                <div class="text-xs font-semibold text-zinc-100 group-hover:text-accent transition" data-i18n="codexTitle">OpenAI ChatGPT / Codex</div>
                <div class="text-[10px] text-zinc-500" data-i18n="codexDesc">Plus / Pro 5 saatlik kayan kotalar</div>
              </div>
            </div>
            <span class="text-xs font-medium text-accent" data-i18n="loginBtn">Giriş Yap →</span>
          </button>

          <!-- Anthropic Claude Button -->
          <button onclick="startClaudeOAuth()" class="flex items-center justify-between p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-accent hover:bg-zinc-800/80 transition group">
            <div class="flex items-center gap-3">
              <span class="text-xl">🔮</span>
              <div class="text-left">
                <div class="text-xs font-semibold text-zinc-100 group-hover:text-accent transition" data-i18n="claudeTitle">Anthropic Claude Pro/Max</div>
                <div class="text-[10px] text-zinc-500" data-i18n="claudeDesc">5h oturum ve haftalık Opus/Sonnet kotaları</div>
              </div>
            </div>
            <span class="text-xs font-medium text-accent" data-i18n="loginBtn">Giriş Yap →</span>
          </button>
        </div>

        <!-- Codex Device Code Active State Panel -->
        <div id="codexDevicePanel" class="hidden p-4 rounded-lg bg-zinc-900/90 border border-accent/40 space-y-3">
          <div class="text-xs font-medium text-zinc-200" data-i18n="deviceWait">OpenAI Cihaz Onayı Bekleniyor:</div>
          <div class="flex items-center gap-2">
            <span class="text-xs text-zinc-400" data-i18n="confirmCode">Onay Kodu:</span>
            <span id="codexUserCode" class="text-base font-mono font-bold tracking-wider text-accent bg-zinc-800 px-2 py-0.5 rounded">...</span>
          </div>
          <p class="text-[11px] text-zinc-400" data-i18n="deviceDesc">
            Açılan OpenAI sayfasında kodu onaylayın. Panel otomatik olarak tamamlanacaktır.
          </p>
          <a id="codexAuthLink" href="#" target="_blank" class="inline-block text-xs font-semibold text-accent hover:underline" data-i18n="reopenLink">
            Sayfayı Tekrar Aç ↗
          </a>
        </div>
      </div>

      <!-- Manual API Key Form Section -->
      <form id="manualSection" onsubmit="handleManualSave(event)" class="hidden space-y-4">
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1" data-i18n="provider">Sağlayıcı</label>
          <select id="providerSelect" class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none">
            <option value="openrouter">OpenRouter (API Key)</option>
            <option value="deepseek">DeepSeek (API Key)</option>
            <option value="anthropic">Anthropic (OAuth Token / API Key)</option>
            <option value="openai-codex">OpenAI Codex (OAuth Token)</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1" data-i18n="accountLabel">Hesap Adı / Etiket</label>
          <input type="text" id="accountLabel" placeholder="Örn: Kişisel Pro, İş Hesabı" required class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none" />
        </div>
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1" data-i18n="credentialType">Kimlik Türü</label>
          <select id="credentialType" class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none">
            <option value="api_key" data-i18n="apiKey">API Anahtarı</option>
            <option value="oauth" data-i18n="oauthToken">OAuth Access Token</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1" data-i18n="secretLabel">Secret / Token</label>
          <input type="password" id="secretValue" placeholder="sk-... veya bearer token" required class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none" />
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button type="button" onclick="closeModal()" class="px-4 py-2 rounded-md text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300" data-i18n="cancel">İptal</button>
          <button type="submit" class="px-4 py-2 rounded-md text-xs font-semibold bg-accent hover:bg-accentHover text-zinc-950" data-i18n="saveAndPoll">Kaydet ve Sorgula</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    // Theme presets
    const THEMES = {
      amber: {
        bg: '#0a0a0b',
        surface: '#121215',
        border: '#27272a',
        accent: '#ff9849',
        accentHover: '#ea7c2b',
        accentBg: 'rgba(255, 152, 73, 0.15)'
      },
      emerald: {
        bg: '#000000',
        surface: '#09090b',
        border: '#18181b',
        accent: '#10b981',
        accentHover: '#059669',
        accentBg: 'rgba(16, 185, 129, 0.15)'
      },
      cyan: {
        bg: '#05070e',
        surface: '#0b0f19',
        border: '#1e293b',
        accent: '#06b6d4',
        accentHover: '#0891b2',
        accentBg: 'rgba(6, 182, 212, 0.15)'
      },
      violet: {
        bg: '#0c0a14',
        surface: '#141021',
        border: '#2e2640',
        accent: '#a855f7',
        accentHover: '#9333ea',
        accentBg: 'rgba(168, 85, 247, 0.15)'
      },
      slate: {
        bg: '#0f172a',
        surface: '#1e293b',
        border: '#334155',
        accent: '#38bdf8',
        accentHover: '#0284c7',
        accentBg: 'rgba(56, 189, 248, 0.15)'
      }
    };

    // i18n Dictionary
    const I18N = {
      tr: {
        title: "AI Usage Tracker",
        subtitle: "Multi-Provider Quota & Balance Hub",
        refresh: "Yenile",
        addAccount: "+ Hesap Bağla",
        loading: "Kullanım verileri yükleniyor...",
        noAccounts: "Henüz kayıtlı bir AI sağlayıcısı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.",
        lastUpdate: "Son Güncelleme",
        deleteConfirm: "Bu hesabı kaldırmak istediğinizden emin misiniz?",
        resetsIn: "Sıfırlanma",
        rights: "Hak",
        modalTitle: "AI Hesabı Bağla",
        tabOAuth: "⚡ Oturum Açarak Bağlan (OAuth)",
        tabManual: "🔑 Manuel API Key / Token",
        oauthDesc: "Tek tıkla resmi oturum açma penceresine yönlendirilirsiniz. Token'lar yerel kasada şifrelenir.",
        googleTitle: "Google Gemini / Cloud Code",
        googleDesc: "Gemini 3 Flash, 2.5 Pro model kotaları",
        codexTitle: "OpenAI ChatGPT / Codex",
        codexDesc: "Plus / Pro 5 saatlik kayan kotalar",
        claudeTitle: "Anthropic Claude Pro/Max",
        claudeDesc: "5h oturum ve haftalık Opus/Sonnet kotaları",
        loginBtn: "Giriş Yap →",
        deviceWait: "OpenAI Cihaz Onayı Bekleniyor:",
        confirmCode: "Onay Kodu:",
        deviceDesc: "Açılan OpenAI sayfasında kodu onaylayın. Panel otomatik olarak tamamlanacaktır.",
        reopenLink: "Sayfayı Tekrar Aç ↗",
        provider: "Sağlayıcı",
        accountLabel: "Hesap Adı / Etiket",
        accountLabelPlaceholder: "Örn: Kişisel Pro, İş Hesabı",
        credentialType: "Kimlik Türü",
        apiKey: "API Anahtarı",
        oauthToken: "OAuth Access Token",
        secretLabel: "Secret / Token",
        cancel: "İptal",
        saveAndPoll: "Kaydet ve Sorgula"
      },
      en: {
        title: "AI Usage Tracker",
        subtitle: "Multi-Provider Quota & Balance Hub",
        refresh: "Refresh",
        addAccount: "+ Connect Account",
        loading: "Loading usage metrics...",
        noAccounts: "No AI accounts connected yet. Click <b>+ Connect Account</b> to add one.",
        lastUpdate: "Last Updated",
        deleteConfirm: "Are you sure you want to remove this account?",
        resetsIn: "Resets in",
        rights: "Resets",
        modalTitle: "Connect AI Account",
        tabOAuth: "⚡ Login to Connect (OAuth)",
        tabManual: "🔑 Manual API Key / Token",
        oauthDesc: "Redirect to official login in one click. Tokens are AES-encrypted locally.",
        googleTitle: "Google Gemini / Cloud Code",
        googleDesc: "Gemini 3 Flash, 2.5 Pro model quotas",
        codexTitle: "OpenAI ChatGPT / Codex",
        codexDesc: "Plus / Pro 5-hour rolling quotas",
        claudeTitle: "Anthropic Claude Pro/Max",
        claudeDesc: "5h session and weekly Opus/Sonnet quotas",
        loginBtn: "Login →",
        deviceWait: "Waiting for OpenAI Device Approval:",
        confirmCode: "Verification Code:",
        deviceDesc: "Confirm the code on the OpenAI page. The dashboard will automatically update.",
        reopenLink: "Re-open Authorization Page ↗",
        provider: "Provider",
        accountLabel: "Account Name / Label",
        accountLabelPlaceholder: "e.g. Personal Pro, Work Account",
        credentialType: "Credential Type",
        apiKey: "API Key",
        oauthToken: "OAuth Access Token",
        secretLabel: "Secret / Token",
        cancel: "Cancel",
        saveAndPoll: "Save & Poll"
      }
    };

    let currentLang = localStorage.getItem('usage_lang') || 'tr';
    let currentTheme = localStorage.getItem('usage_theme') || 'amber';
    let cachedReports = [];

    function t(key) {
      return (I18N[currentLang] && I18N[currentLang][key]) || (I18N['tr'][key]) || key;
    }

    function applyTheme(themeKey) {
      const p = THEMES[themeKey] || THEMES.amber;
      const root = document.documentElement;
      root.style.setProperty('--color-bg', p.bg);
      root.style.setProperty('--color-surface', p.surface);
      root.style.setProperty('--color-border', p.border);
      root.style.setProperty('--color-accent', p.accent);
      root.style.setProperty('--color-accent-hover', p.accentHover);
      root.style.setProperty('--color-accent-bg', p.accentBg);
      currentTheme = themeKey;
      localStorage.setItem('usage_theme', themeKey);
      document.getElementById('themeSelect').value = themeKey;
    }

    function changeTheme(themeKey) {
      applyTheme(themeKey);
    }

    function applyI18n() {
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.innerHTML = t(key);
      });
      document.getElementById('langLabel').innerText = currentLang.toUpperCase();
      document.getElementById('accountLabel').placeholder = t('accountLabelPlaceholder');
      if (cachedReports.length) renderCards(cachedReports);
    }

    function toggleLang() {
      currentLang = currentLang === 'tr' ? 'en' : 'tr';
      localStorage.setItem('usage_lang', currentLang);
      applyI18n();
    }

    function openModal() { document.getElementById('modal').classList.remove('hidden'); document.getElementById('modal').classList.add('flex'); }
    function closeModal() { document.getElementById('modal').classList.add('hidden'); document.getElementById('modal').classList.remove('flex'); document.getElementById('codexDevicePanel').classList.add('hidden'); }

    function switchTab(tab) {
      const isOAuth = tab === 'oauth';
      document.getElementById('oauthSection').classList.toggle('hidden', !isOAuth);
      document.getElementById('manualSection').classList.toggle('hidden', isOAuth);

      document.getElementById('tabOAuth').className = isOAuth 
        ? 'flex-1 pb-2.5 text-xs font-semibold border-b-2 border-accent text-accent'
        : 'flex-1 pb-2.5 text-xs font-semibold border-b-2 border-transparent text-zinc-400 hover:text-zinc-200';

      document.getElementById('tabManual').className = !isOAuth 
        ? 'flex-1 pb-2.5 text-xs font-semibold border-b-2 border-accent text-accent'
        : 'flex-1 pb-2.5 text-xs font-semibold border-b-2 border-transparent text-zinc-400 hover:text-zinc-200';
    }

    async function loadUsage() {
      try {
        const res = await fetch('/api/usage');
        const json = await res.json();
        cachedReports = json.data || [];
        renderCards(cachedReports);
      } catch (err) {
        document.getElementById('cardsGrid').innerHTML = '<div class="col-span-full text-center text-red-400">Veriler yüklenirken hata oluştu.</div>';
      }
    }

    async function pollNow() {
      const spinner = document.getElementById('pollSpinner');
      spinner.classList.remove('hidden');
      try {
        await fetch('/api/poll', { method: 'POST' });
        await loadUsage();
      } finally {
        spinner.classList.add('hidden');
      }
    }

    // Start OpenAI Codex Device Auth Flow
    async function startCodexOAuth() {
      try {
        const res = await fetch('/api/oauth/codex/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) { alert('Codex error: ' + json.error); return; }

        const { userCode, verificationUrl, deviceAuthId, interval } = json.data;
        document.getElementById('codexUserCode').innerText = userCode;
        document.getElementById('codexAuthLink').href = verificationUrl;
        document.getElementById('codexDevicePanel').classList.remove('hidden');

        window.open(verificationUrl, '_blank');

        const pollTimer = setInterval(async () => {
          const pollRes = await fetch('/api/oauth/codex/poll', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ deviceAuthId, userCode, label: 'ChatGPT Codex' })
          });
          const pollJson = await pollRes.json();

          if (pollJson.status === 'complete') {
            clearInterval(pollTimer);
            closeModal();
            pollNow();
          } else if (pollJson.status === 'error') {
            clearInterval(pollTimer);
            alert('Giriş başarısız: ' + pollJson.error);
          }
        }, (interval || 5) * 1000);
      } catch (err) {
        alert('Hata: ' + err);
      }
    }

    // Start Google / Gemini OAuth Flow
    async function startGoogleOAuth() {
      try {
        const res = await fetch('/api/oauth/google/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) { alert('Google error: ' + json.error); return; }

        const { authUrl, sessionId } = json.data;
        window.open(authUrl, '_blank');

        const pollTimer = setInterval(async () => {
          const statusRes = await fetch('/api/oauth/status/' + sessionId);
          const statusJson = await statusRes.json();

          if (statusJson.status === 'complete') {
            clearInterval(pollTimer);
            closeModal();
            pollNow();
          } else if (statusJson.status === 'error') {
            clearInterval(pollTimer);
            alert('Google girişi başarısız: ' + statusJson.error);
          }
        }, 2000);
      } catch (err) {
        alert('Hata: ' + err);
      }
    }

    // Start Claude OAuth Flow
    async function startClaudeOAuth() {
      try {
        const res = await fetch('/api/oauth/claude/initiate', { method: 'POST' });
        const json = await res.json();
        if (!json.success) { alert('Claude error: ' + json.error); return; }

        const { authUrl, sessionId } = json.data;
        window.open(authUrl, '_blank');

        const pollTimer = setInterval(async () => {
          const statusRes = await fetch('/api/oauth/status/' + sessionId);
          const statusJson = await statusRes.json();

          if (statusJson.status === 'complete') {
            clearInterval(pollTimer);
            closeModal();
            pollNow();
          } else if (statusJson.status === 'error') {
            clearInterval(pollTimer);
            alert('Claude girişi başarısız: ' + statusJson.error);
          }
        }, 2000);
      } catch (err) {
        alert('Hata: ' + err);
      }
    }

    async function handleManualSave(e) {
      e.preventDefault();
      const body = {
        provider: document.getElementById('providerSelect').value,
        accountLabel: document.getElementById('accountLabel').value,
        credentialType: document.getElementById('credentialType').value,
        secret: document.getElementById('secretValue').value
      };
      await fetch('/api/credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      closeModal();
      document.getElementById('secretValue').value = '';
      setTimeout(pollNow, 500);
    }

    function renderCards(reports) {
      const container = document.getElementById('cardsGrid');
      if (!reports.length) {
        container.innerHTML = '<div class="col-span-full py-16 text-center text-zinc-500">' + t('noAccounts') + '</div>';
        return;
      }

      container.innerHTML = reports.map(r => {
        const limitsHtml = (r.limits || []).map(l => {
          let valueHtml = '';
          let barHtml = '';

          if (l.amount.unit === 'percent') {
            const used = l.amount.used || 0;
            const barColor = used >= 90 ? 'bg-red-500' : used >= 75 ? 'bg-yellow-500' : 'bg-emerald-500';
            valueHtml = '<span class="font-bold text-sm">' + used.toFixed(1) + '%</span>';
            barHtml = '<div class="w-full bg-zinc-800 h-1.5 rounded-full overflow-hidden mt-1.5"><div class="' + barColor + ' h-full transition-all duration-500" style="width: ' + Math.min(100, used) + '%"></div></div>';
          } else if (l.amount.unit === 'usd') {
            const rem = l.amount.remaining ?? 0;
            valueHtml = '<span class="font-bold text-sm text-emerald-400">$' + rem.toFixed(2) + '</span>';
          } else if (l.amount.unit === 'credits') {
            const rem = l.amount.remaining ?? 0;
            const badgeBg = rem > 0 ? 'bg-accent/20 text-accent border border-accent/40' : 'bg-zinc-800 text-zinc-500 border border-zinc-700';
            valueHtml = '<span class="font-bold text-xs ' + badgeBg + ' px-2 py-0.5 rounded-md">🔄 ' + rem + ' ' + t('rights') + '</span>';
          }

          let countdownHtml = '';
          if (l.window && l.window.resetsAt) {
            const diffMin = Math.max(0, Math.round((l.window.resetsAt - Date.now()) / 60000));
            const hours = Math.floor(diffMin / 60);
            const mins = diffMin % 60;
            const label = hours > 0 ? (hours + 'h ' + mins + 'm') : (mins + 'm');
            countdownHtml = '<span class="text-[10px] text-zinc-400 bg-zinc-800/80 px-1.5 py-0.5 rounded">' + t('resetsIn') + ': ' + label + '</span>';
          }

          const notesHtml = (l.notes || []).map(n => '<span class="text-[10px] text-zinc-500 block">' + n + '</span>').join('');

          return '<div class="bg-zinc-900/60 border border-zinc-800/80 rounded-lg p-3 space-y-1">' +
                 '  <div class="flex justify-between items-center">' +
                 '    <span class="text-xs font-medium text-zinc-300">' + l.label + '</span>' +
                 '    ' + valueHtml +
                 '  </div>' +
                 barHtml +
                 '  <div class="flex justify-between items-center pt-1">' +
                 countdownHtml +
                 '  </div>' +
                 notesHtml +
                 '</div>';
        }).join('');

        return '<div class="bg-surface border border-surfaceBorder rounded-xl p-5 space-y-4 hover:border-zinc-700 transition">' +
               '  <div class="flex justify-between items-start">' +
               '    <div>' +
               '      <div class="flex items-center gap-2">' +
               '        <h2 class="font-semibold text-zinc-100 capitalize">' + r.provider + '</h2>' +
               '        <span class="text-[10px] px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400 border border-zinc-700">' + (r.accountLabel || 'Default') + '</span>' +
               '      </div>' +
               '      <span class="text-[10px] text-zinc-500">' + t('lastUpdate') + ': ' + new Date(r.fetchedAt).toLocaleTimeString() + '</span>' +
               '    </div>' +
               '    <button data-id="' + (r.credentialId || '') + '" onclick="deleteAccount(this.dataset.id)" title="Hesabı Kaldır" class="text-zinc-600 hover:text-red-400 text-xs p-1 rounded hover:bg-zinc-800 transition">✕</button>' +
               '  </div>' +
               '  <div class="space-y-2.5">' + limitsHtml + '</div>' +
               '</div>';
      }).join('');
    }

    async function deleteAccount(id) {
      if (!id || !confirm(t('deleteConfirm'))) return;
      await fetch('/api/credentials/' + id, { method: 'DELETE' });
      await loadUsage();
    }

    // Init theme and lang
    applyTheme(currentTheme);
    applyI18n();
    loadUsage();
    setInterval(loadUsage, 10000);
  </script>
</body>
</html>`;
}
