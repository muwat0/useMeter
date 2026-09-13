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
  <title>AI Usage Tracker — Telemetry & Quota Hub</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            appBg: 'var(--color-bg)',
            appSurface: 'var(--color-surface)',
            appBorder: 'var(--color-border)',
            appMuted: 'var(--color-muted)',
            appAccent: 'var(--color-accent)',
            appAccentHover: 'var(--color-accent-hover)',
            appAccentSoft: 'var(--color-accent-soft)',
            appText: 'var(--color-text)',
            appTextMuted: 'var(--color-text-muted)'
          }
        }
      }
    }
  </script>
  <style>
    :root {
      --color-bg: #090a0d;
      --color-surface: #111318;
      --color-border: #1f232b;
      --color-muted: #171a21;
      --color-text: #f4f4f6;
      --color-text-muted: #858b98;
      --color-accent: #ff9849;
      --color-accent-hover: #ea7c2b;
      --color-accent-soft: rgba(255, 152, 73, 0.12);
      --card-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
    }
    html.light {
      --color-bg: #f8fafc;
      --color-surface: #ffffff;
      --color-border: #e2e8f0;
      --color-muted: #f1f5f9;
      --color-text: #0f172a;
      --color-text-muted: #64748b;
      --color-accent: #ea580c;
      --color-accent-hover: #c2410c;
      --color-accent-soft: rgba(234, 88, 12, 0.1);
      --card-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05);
    }
    body {
      background-color: var(--color-bg);
      color: var(--color-text);
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Inter", "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    .font-mono-num {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-variant-numeric: tabular-nums;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col transition-colors duration-200 text-sm">
  <!-- Top Control Bar -->
  <header class="border-b border-appBorder bg-appSurface/80 backdrop-blur-md px-6 py-3.5 sticky top-0 z-20 transition-colors">
    <div class="max-w-7xl mx-auto flex items-center justify-between">
      <div class="flex items-center gap-3">
        <!-- Logo Icon -->
        <div class="w-8 h-8 rounded border border-appAccent/40 bg-appAccentSoft flex items-center justify-center text-appAccent">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
          </svg>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <h1 class="font-bold tracking-tight text-appText leading-none text-base" data-i18n="title">AI Usage Tracker</h1>
            <span class="inline-flex items-center gap-1 text-[10px] font-mono-num uppercase tracking-wider text-emerald-500 bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.2 rounded">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span> live
            </span>
          </div>
          <span class="text-[11px] text-appTextMuted tracking-tight" data-i18n="subtitle">Multi-Provider Quota & Balance Hub</span>
        </div>
      </div>

      <!-- Controls Right -->
      <div class="flex items-center gap-2 sm:gap-3">
        <!-- Theme Accent Palette Picker -->
        <div class="hidden sm:flex items-center border border-appBorder rounded-lg p-0.5 bg-appMuted/60">
          <button onclick="changeTheme('amber')" title="Amber" class="w-5 h-5 rounded-md bg-[#ff9849] hover:scale-110 transition-transform m-0.5" id="themeDot_amber"></button>
          <button onclick="changeTheme('emerald')" title="Emerald" class="w-5 h-5 rounded-md bg-[#10b981] hover:scale-110 transition-transform m-0.5" id="themeDot_emerald"></button>
          <button onclick="changeTheme('cyan')" title="Cyan" class="w-5 h-5 rounded-md bg-[#06b6d4] hover:scale-110 transition-transform m-0.5" id="themeDot_cyan"></button>
          <button onclick="changeTheme('violet')" title="Violet" class="w-5 h-5 rounded-md bg-[#a855f7] hover:scale-110 transition-transform m-0.5" id="themeDot_violet"></button>
          <button onclick="changeTheme('slate')" title="Slate" class="w-5 h-5 rounded-md bg-[#38bdf8] hover:scale-110 transition-transform m-0.5" id="themeDot_slate"></button>
        </div>

        <!-- Dark / Light Mode Toggle Button -->
        <button onclick="toggleLightDark()" id="lightDarkBtn" title="Koyu / Aydınlık Mod" class="w-8 h-8 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent/50 transition flex items-center justify-center">
          <span id="lightDarkIcon">☀️</span>
        </button>

        <!-- Language Switcher Toggle with Flag -->
        <button onclick="toggleLang()" id="langBtn" class="h-8 px-2.5 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-medium hover:border-appAccent/50 transition flex items-center gap-1.5 font-mono-num">
          <span id="langFlag" class="text-sm">🇹🇷</span>
          <span id="langLabel">TR</span>
        </button>

        <!-- Manual Poll Button -->
        <button onclick="pollNow()" id="pollBtn" class="h-8 px-3 rounded-lg text-xs font-medium bg-appMuted hover:bg-appBorder text-appText transition flex items-center gap-1.5 border border-appBorder">
          <svg id="pollSpinner" class="hidden animate-spin w-3.5 h-3.5 text-appAccent" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path>
          </svg>
          <span data-i18n="refresh">Yenile</span>
        </button>

        <!-- Connect Account Button -->
        <button onclick="openModal()" class="h-8 px-3.5 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition flex items-center gap-1.5 shadow-sm" data-i18n="addAccount">
          <span>+</span>
          <span>Hesap Bağla</span>
        </button>
      </div>
    </div>
  </header>

  <!-- Summary Stats Strip -->
  <section class="border-b border-appBorder bg-appSurface/30 px-6 py-3">
    <div class="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs">
      <div class="flex items-center gap-6">
        <div class="flex items-center gap-2">
          <span class="text-appTextMuted" data-i18n="summaryActive">Aktif Hesaplar:</span>
          <span id="statActiveCount" class="font-mono-num font-bold text-appText">0</span>
        </div>
        <div class="flex items-center gap-2 border-l border-appBorder pl-6">
          <span class="text-appTextMuted" data-i18n="summaryBalance">Toplam Ön Ödemeli Bakiye:</span>
          <span id="statTotalBalance" class="font-mono-num font-bold text-emerald-500">$0.00</span>
        </div>
        <div class="flex items-center gap-2 border-l border-appBorder pl-6">
          <span class="text-appTextMuted" data-i18n="summaryExhausted">Kilitli/Biten Kota:</span>
          <span id="statExhaustedCount" class="font-mono-num font-bold text-appText">0</span>
        </div>
      </div>
      <div class="text-[11px] text-appTextMuted flex items-center gap-2 font-mono-num">
        <span data-i18n="autoSync">Canlı Senkronizasyon:</span>
        <span class="text-appAccent">10s</span>
      </div>
    </div>
  </section>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
    <div id="cardsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
      <div class="col-span-full py-20 text-center text-appTextMuted" data-i18n="loading">
        Kullanım verileri yükleniyor...
      </div>
    </div>
  </main>

  <!-- Add Credential / OAuth Modal -->
  <div id="modal" class="fixed inset-0 bg-black/60 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
    <div class="bg-appSurface border border-appBorder rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl transition-colors">
      <div class="flex justify-between items-center pb-2 border-b border-appBorder">
        <div>
          <h3 class="font-bold text-appText text-sm" data-i18n="modalTitle">AI Hesabı Bağla</h3>
          <p class="text-[11px] text-appTextMuted mt-0.5" data-i18n="modalSubtitle">OAuth veya doğrudan API anahtarıyla kota takibi kurun.</p>
        </div>
        <button onclick="closeModal()" class="text-appTextMuted hover:text-appText text-base p-1">✕</button>
      </div>

      <!-- Segmented Tab Switcher -->
      <div class="flex p-1 bg-appMuted rounded-lg border border-appBorder text-xs">
        <button onclick="switchTab('oauth')" id="tabOAuth" class="flex-1 py-1.5 font-medium rounded-md bg-appSurface text-appText shadow-sm transition" data-i18n="tabOAuth">
          OAuth ile Oturum Aç
        </button>
        <button onclick="switchTab('manual')" id="tabManual" class="flex-1 py-1.5 font-medium rounded-md text-appTextMuted hover:text-appText transition" data-i18n="tabManual">
          Manuel API Key
        </button>
      </div>

      <!-- OAuth Flow Options -->
      <div id="oauthSection" class="space-y-3">
        <p class="text-xs text-appTextMuted" data-i18n="oauthDesc">Resmi sağlayıcı girişine yönlendirilirsiniz. Token'lar yerel veritabanında AES-256-GCM ile şifrelenir.</p>

        <div class="space-y-2">
          <!-- Google Card -->
          <button onclick="startGoogleOAuth()" class="w-full flex items-center justify-between p-3.5 rounded-lg border border-appBorder bg-appMuted/30 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-7 h-7 rounded bg-white/10 flex items-center justify-center text-sm font-bold text-blue-400">G</div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="googleTitle">Google Gemini / Cloud Code</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="googleDesc">Gemini 3 Flash, 2.5 Pro model kotaları</div>
              </div>
            </div>
            <span class="text-xs font-mono-num text-appAccent">Oturum Aç →</span>
          </button>

          <!-- OpenAI Codex Card -->
          <button onclick="startCodexOAuth()" class="w-full flex items-center justify-between p-3.5 rounded-lg border border-appBorder bg-appMuted/30 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-7 h-7 rounded bg-white/10 flex items-center justify-center text-sm font-bold text-emerald-400">O</div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="codexTitle">OpenAI ChatGPT / Codex</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="codexDesc">Plus / Pro 5 saatlik ve haftalık kotalar</div>
              </div>
            </div>
            <span class="text-xs font-mono-num text-appAccent">Oturum Aç →</span>
          </button>

          <!-- Anthropic Claude Card -->
          <button onclick="startClaudeOAuth()" class="w-full flex items-center justify-between p-3.5 rounded-lg border border-appBorder bg-appMuted/30 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3">
              <div class="w-7 h-7 rounded bg-white/10 flex items-center justify-center text-sm font-bold text-amber-400">A</div>
              <div>
                <div class="text-xs font-semibold text-appText group-hover:text-appAccent transition" data-i18n="claudeTitle">Anthropic Claude Pro/Max</div>
                <div class="text-[11px] text-appTextMuted" data-i18n="claudeDesc">5h oturum ve haftalık Opus/Sonnet kotaları</div>
              </div>
            </div>
            <span class="text-xs font-mono-num text-appAccent">Oturum Aç →</span>
          </button>
        </div>

        <!-- Codex Device Code Active State Panel -->
        <div id="codexDevicePanel" class="hidden p-4 rounded-lg bg-appMuted border border-appAccent/40 space-y-3">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-appText" data-i18n="deviceWait">OpenAI Onayı Bekleniyor:</span>
            <span id="codexUserCode" class="text-xs font-mono-num font-bold tracking-widest text-appAccent bg-appSurface border border-appAccent/30 px-2 py-0.5 rounded">...</span>
          </div>
          <p class="text-[11px] text-appTextMuted leading-relaxed" data-i18n="deviceDesc">
            Yeni sekmede açılan OpenAI sayfasına bu kodu girin. Onaylandığı an bu pencere kendiliğinden kapanacaktır.
          </p>
          <a id="codexAuthLink" href="#" target="_blank" class="inline-flex items-center gap-1 text-xs font-medium text-appAccent hover:underline" data-i18n="reopenLink">
            Onay Sayfasını Yeniden Aç ↗
          </a>
        </div>
      </div>

      <!-- Manual API Key Form Section -->
      <form id="manualSection" onsubmit="handleManualSave(event)" class="hidden space-y-3.5">
        <div>
          <label class="block text-[11px] font-medium text-appTextMuted mb-1" data-i18n="provider">Sağlayıcı</label>
          <select id="providerSelect" class="w-full bg-appMuted border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none">
            <option value="openrouter">OpenRouter (API Key)</option>
            <option value="deepseek">DeepSeek (API Key)</option>
            <option value="anthropic">Anthropic (OAuth Token / API Key)</option>
            <option value="openai-codex">OpenAI Codex (OAuth Token)</option>
          </select>
        </div>
        <div>
          <label class="block text-[11px] font-medium text-appTextMuted mb-1" data-i18n="accountLabel">Hesap Adı / Etiket</label>
          <input type="text" id="accountLabel" placeholder="Örn: Kişisel Pro, İş Hesabı" required class="w-full bg-appMuted border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none" />
        </div>
        <div>
          <label class="block text-[11px] font-medium text-appTextMuted mb-1" data-i18n="credentialType">Kimlik Türü</label>
          <select id="credentialType" class="w-full bg-appMuted border border-appBorder rounded-lg px-3 py-2 text-xs text-appText focus:border-appAccent outline-none">
            <option value="api_key" data-i18n="apiKey">API Anahtarı</option>
            <option value="oauth" data-i18n="oauthToken">OAuth Access Token</option>
          </select>
        </div>
        <div>
          <label class="block text-[11px] font-medium text-appTextMuted mb-1" data-i18n="secretLabel">Secret / Token</label>
          <input type="password" id="secretValue" placeholder="sk-... veya bearer token" required class="w-full bg-appMuted border border-appBorder rounded-lg px-3 py-2 text-xs text-appText font-mono-num focus:border-appAccent outline-none" />
        </div>
        <div class="flex justify-end gap-2 pt-2 border-t border-appBorder">
          <button type="button" onclick="closeModal()" class="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-appMuted hover:bg-appBorder text-appText transition" data-i18n="cancel">İptal</button>
          <button type="submit" class="px-4 py-1.5 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition" data-i18n="saveAndPoll">Kaydet ve Sorgula</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Client Script -->
  <script>
    const THEME_ACCENTS = {
      amber: { accent: '#ff9849', accentHover: '#ea7c2b', accentSoft: 'rgba(255, 152, 73, 0.12)' },
      emerald: { accent: '#10b981', accentHover: '#059669', accentSoft: 'rgba(16, 185, 129, 0.12)' },
      cyan: { accent: '#06b6d4', accentHover: '#0891b2', accentSoft: 'rgba(6, 182, 212, 0.12)' },
      violet: { accent: '#a855f7', accentHover: '#9333ea', accentSoft: 'rgba(168, 85, 247, 0.12)' },
      slate: { accent: '#38bdf8', accentHover: '#0284c7', accentSoft: 'rgba(56, 189, 248, 0.12)' }
    };

    const I18N = {
      tr: {
        flag: "🇹🇷",
        title: "AI Usage Tracker",
        subtitle: "Multi-Provider Quota & Balance Hub",
        refresh: "Yenile",
        addAccount: "Hesap Bağla",
        summaryActive: "Aktif Hesaplar:",
        summaryBalance: "Toplam Ön Ödemeli Bakiye:",
        summaryExhausted: "Kilitli/Biten Kota:",
        autoSync: "Canlı Senkronizasyon:",
        loading: "Kullanım verileri yükleniyor...",
        noAccounts: "Henüz kayıtlı bir AI hesabı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.",
        lastUpdate: "Son Güncelleme",
        deleteConfirm: "Bu hesabı kaldırmak istediğinizden emin misiniz?",
        resetsIn: "Sıfırlanma",
        rights: "Hak",
        modalTitle: "AI Hesabı Bağla",
        modalSubtitle: "OAuth veya doğrudan API anahtarıyla kota takibi kurun.",
        tabOAuth: "OAuth ile Oturum Aç",
        tabManual: "Manuel API Key",
        oauthDesc: "Resmi sağlayıcı girişine yönlendirilirsiniz. Token'lar yerel veritabanında AES-256-GCM ile şifrelenir.",
        googleTitle: "Google Gemini / Cloud Code",
        googleDesc: "Gemini 3 Flash, 2.5 Pro model kotaları",
        codexTitle: "OpenAI ChatGPT / Codex",
        codexDesc: "Plus / Pro 5 saatlik ve haftalık kotalar",
        claudeTitle: "Anthropic Claude Pro/Max",
        claudeDesc: "5h oturum ve haftalık Opus/Sonnet kotaları",
        deviceWait: "OpenAI Onayı Bekleniyor:",
        deviceDesc: "Yeni sekmede açılan OpenAI sayfasına bu kodu girin. Onaylandığı an bu pencere kendiliğinden kapanacaktır.",
        reopenLink: "Onay Sayfasını Yeniden Aç ↗",
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
        flag: "🇬🇧",
        title: "AI Usage Tracker",
        subtitle: "Multi-Provider Quota & Balance Hub",
        refresh: "Refresh",
        addAccount: "Connect Account",
        summaryActive: "Active Accounts:",
        summaryBalance: "Total Prepaid Balance:",
        summaryExhausted: "Exhausted Quotas:",
        autoSync: "Live Telemetry:",
        loading: "Loading usage metrics...",
        noAccounts: "No AI accounts connected yet. Click <b>+ Connect Account</b> to add one.",
        lastUpdate: "Updated",
        deleteConfirm: "Are you sure you want to remove this account?",
        resetsIn: "Resets in",
        rights: "Resets",
        modalTitle: "Connect AI Account",
        modalSubtitle: "Track quotas and credits via OAuth or direct API key.",
        tabOAuth: "Login with OAuth",
        tabManual: "Manual API Key",
        oauthDesc: "Redirect to official authorization. Tokens are encrypted locally via AES-256-GCM.",
        googleTitle: "Google Gemini / Cloud Code",
        googleDesc: "Gemini 3 Flash, 2.5 Pro model quotas",
        codexTitle: "OpenAI ChatGPT / Codex",
        codexDesc: "Plus / Pro 5-hour rolling & weekly quotas",
        claudeTitle: "Anthropic Claude Pro/Max",
        claudeDesc: "5h session and weekly Opus/Sonnet quotas",
        deviceWait: "Waiting for OpenAI Approval:",
        deviceDesc: "Enter the code on the OpenAI confirmation page. The dashboard will automatically update.",
        reopenLink: "Re-open Authorization Page ↗",
        provider: "Provider",
        accountLabel: "Account Label",
        accountLabelPlaceholder: "e.g. Personal Pro, Work Key",
        credentialType: "Credential Type",
        apiKey: "API Key",
        oauthToken: "OAuth Access Token",
        secretLabel: "Secret / Token",
        cancel: "Cancel",
        saveAndPoll: "Save & Poll"
      }
    };

    let currentLang = localStorage.getItem('usage_lang') || 'tr';
    let currentMode = localStorage.getItem('usage_mode') || 'dark';
    let currentAccent = localStorage.getItem('usage_accent') || 'amber';
    let cachedReports = [];

    function t(key) {
      return (I18N[currentLang] && I18N[currentLang][key]) || (I18N['tr'][key]) || key;
    }

    function applyLightDarkMode(mode) {
      currentMode = mode;
      localStorage.setItem('usage_mode', mode);
      const isDark = mode === 'dark';
      document.documentElement.classList.toggle('dark', isDark);
      document.documentElement.classList.toggle('light', !isDark);
      document.getElementById('lightDarkIcon').innerText = isDark ? '☀️' : '🌙';
    }

    function toggleLightDark() {
      applyLightDarkMode(currentMode === 'dark' ? 'light' : 'dark');
    }

    function applyAccent(accentKey) {
      currentAccent = accentKey;
      localStorage.setItem('usage_accent', accentKey);
      const pal = THEME_ACCENTS[accentKey] || THEME_ACCENTS.amber;
      const root = document.documentElement;
      root.style.setProperty('--color-accent', pal.accent);
      root.style.setProperty('--color-accent-hover', pal.accentHover);
      root.style.setProperty('--color-accent-soft', pal.accentSoft);

      // Highlight active dot
      Object.keys(THEME_ACCENTS).forEach(k => {
        const dot = document.getElementById('themeDot_' + k);
        if (dot) {
          dot.style.outline = k === accentKey ? '2px solid var(--color-text)' : 'none';
          dot.style.outlineOffset = '1px';
        }
      });
    }

    function changeTheme(accentKey) {
      applyAccent(accentKey);
    }

    function applyI18n() {
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.innerHTML = t(key);
      });
      document.getElementById('langFlag').innerText = I18N[currentLang].flag;
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
        ? 'flex-1 py-1.5 font-medium rounded-md bg-appSurface text-appText shadow-sm transition'
        : 'flex-1 py-1.5 font-medium rounded-md text-appTextMuted hover:text-appText transition';

      document.getElementById('tabManual').className = !isOAuth
        ? 'flex-1 py-1.5 font-medium rounded-md bg-appSurface text-appText shadow-sm transition'
        : 'flex-1 py-1.5 font-medium rounded-md text-appTextMuted hover:text-appText transition';
    }

    async function loadUsage() {
      try {
        const res = await fetch('/api/usage');
        const json = await res.json();
        cachedReports = json.data || [];
        updateSummary(cachedReports);
        renderCards(cachedReports);
      } catch (err) {
        document.getElementById('cardsGrid').innerHTML = '<div class="col-span-full text-center text-red-500 py-12">Telemetry load failed.</div>';
      }
    }

    function updateSummary(reports) {
      document.getElementById('statActiveCount').innerText = reports.length;
      let totalBal = 0;
      let exhausted = 0;

      reports.forEach(r => {
        (r.limits || []).forEach(l => {
          if (l.amount && l.amount.unit === 'usd' && typeof l.amount.remaining === 'number') {
            if (l.id.includes('balance') || l.id.includes('credits')) totalBal += l.amount.remaining;
          }
          if (l.status === 'exhausted') exhausted++;
        });
      });

      document.getElementById('statTotalBalance').innerText = '$' + totalBal.toFixed(2);
      document.getElementById('statExhaustedCount').innerText = exhausted;
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
            alert('Google error: ' + statusJson.error);
          }
        }, 2000);
      } catch (err) {
        alert('Error: ' + err);
      }
    }

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
            alert('Claude error: ' + statusJson.error);
          }
        }, 2000);
      } catch (err) {
        alert('Error: ' + err);
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
        container.innerHTML = '<div class="col-span-full py-20 text-center text-appTextMuted">' + t('noAccounts') + '</div>';
        return;
      }

      container.innerHTML = reports.map(r => {
        const limitsHtml = (r.limits || []).map(l => {
          let valueHtml = '';
          let barHtml = '';

          if (l.amount.unit === 'percent') {
            const used = l.amount.used || 0;
            const barColor = used >= 90 ? 'bg-rose-500' : used >= 75 ? 'bg-amber-500' : 'bg-emerald-500';
            valueHtml = '<span class="font-mono-num font-bold text-xs text-appText">' + used.toFixed(1) + '%</span>';
            barHtml = '<div class="w-full bg-appBorder h-1 rounded-full overflow-hidden mt-1.5"><div class="' + barColor + ' h-full transition-all duration-300" style="width: ' + Math.min(100, used) + '%"></div></div>';
          } else if (l.amount.unit === 'usd') {
            const rem = l.amount.remaining ?? 0;
            valueHtml = '<span class="font-mono-num font-bold text-xs text-emerald-500">$' + rem.toFixed(2) + '</span>';
          } else if (l.amount.unit === 'credits') {
            const rem = l.amount.remaining ?? 0;
            const badgeCls = rem > 0 
              ? 'bg-appAccentSoft text-appAccent border border-appAccent/30' 
              : 'bg-appMuted text-appTextMuted border border-appBorder';
            valueHtml = '<span class="font-mono-num font-semibold text-[11px] ' + badgeCls + ' px-1.5 py-0.5 rounded">' + rem + ' ' + t('rights') + '</span>';
          }

          let countdownHtml = '';
          if (l.window && l.window.resetsAt) {
            const diffMin = Math.max(0, Math.round((l.window.resetsAt - Date.now()) / 60000));
            const hours = Math.floor(diffMin / 60);
            const mins = diffMin % 60;
            const label = hours > 0 ? (hours + 'h ' + mins + 'm') : (mins + 'm');
            countdownHtml = '<span class="text-[10px] text-appTextMuted font-mono-num flex items-center gap-1"><span class="w-1 h-1 rounded-full bg-appTextMuted"></span>' + t('resetsIn') + ': ' + label + '</span>';
          }

          const notesHtml = (l.notes || []).map(n => '<span class="text-[10px] text-appTextMuted block font-mono-num">' + n + '</span>').join('');

          return '<div class="bg-appMuted/40 border border-appBorder rounded-lg p-3 space-y-1">' +
                 '  <div class="flex justify-between items-center">' +
                 '    <span class="text-xs font-medium text-appText tracking-tight">' + l.label + '</span>' +
                 '    ' + valueHtml +
                 '  </div>' +
                 barHtml +
                 '  <div class="flex justify-between items-center pt-0.5">' +
                 countdownHtml +
                 '  </div>' +
                 notesHtml +
                 '</div>';
        }).join('');

        return '<div class="bg-appSurface border border-appBorder rounded-xl p-4 sm:p-5 space-y-3.5 transition-colors shadow-sm">' +
               '  <div class="flex justify-between items-start">' +
               '    <div>' +
               '      <div class="flex items-center gap-2">' +
               '        <h2 class="font-bold text-appText text-sm tracking-tight capitalize">' + r.provider + '</h2>' +
               '        <span class="text-[10px] font-mono-num px-2 py-0.5 rounded bg-appMuted text-appTextMuted border border-appBorder">' + (r.accountLabel || 'Default') + '</span>' +
               '      </div>' +
               '      <span class="text-[10px] text-appTextMuted font-mono-num block mt-1">' + t('lastUpdate') + ': ' + new Date(r.fetchedAt).toLocaleTimeString() + '</span>' +
               '    </div>' +
               '    <button data-id="' + (r.credentialId || '') + '" onclick="deleteAccount(this.dataset.id)" title="Hesabı Kaldır" class="text-appTextMuted hover:text-rose-500 text-xs p-1 rounded hover:bg-appMuted transition">✕</button>' +
               '  </div>' +
               '  <div class="space-y-2">' + limitsHtml + '</div>' +
               '</div>';
      }).join('');
    }

    async function deleteAccount(id) {
      if (!id || !confirm(t('deleteConfirm'))) return;
      await fetch('/api/credentials/' + id, { method: 'DELETE' });
      await loadUsage();
    }

    // Initialize Preferences
    applyLightDarkMode(currentMode);
    applyAccent(currentAccent);
    applyI18n();
    loadUsage();
    setInterval(loadUsage, 10000);
  </script>
</body>
</html>`;
}
