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

      // Exchange code for tokens
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

      // Start background callback listener on port 51121
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

      // Start background callback listener on port 54545
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
            bg: '#0a0a0b',
            surface: '#121215',
            surfaceBorder: '#27272a',
            accent: '#ff9849',
            accentHover: '#ea7c2b'
          }
        }
      }
    }
  </script>
  <style>
    body { background-color: #0a0a0b; color: #f4f4f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  </style>
</head>
<body class="min-h-screen flex flex-col">
  <!-- Top Navigation -->
  <header class="border-b border-surfaceBorder bg-surface/50 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-10">
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded-lg bg-accent/20 border border-accent/40 flex items-center justify-center text-accent font-bold">
        ⚡
      </div>
      <div>
        <h1 class="font-bold text-lg leading-none">AI Usage Tracker</h1>
        <span class="text-xs text-zinc-500">Multi-Provider Quota & Balance Hub</span>
      </div>
    </div>
    <div class="flex items-center gap-3">
      <button onclick="pollNow()" id="pollBtn" class="px-3 py-1.5 rounded-md text-xs font-medium bg-zinc-800 hover:bg-zinc-700 transition flex items-center gap-1.5 text-zinc-200">
        <span id="pollSpinner" class="hidden animate-spin">⟳</span>
        Yenile
      </button>
      <button onclick="openModal()" class="px-3 py-1.5 rounded-md text-xs font-medium bg-accent hover:bg-accentHover text-zinc-950 transition font-semibold">
        + Hesap Bağla
      </button>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
    <!-- Quick Status Cards Grid -->
    <div id="cardsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
      <div class="col-span-full py-12 text-center text-zinc-500 animate-pulse">
        Kullanım verileri yükleniyor...
      </div>
    </div>
  </main>

  <!-- Add Credential / OAuth Modal -->
  <div id="modal" class="fixed inset-0 bg-black/70 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
    <div class="bg-surface border border-surfaceBorder rounded-xl max-w-lg w-full p-6 space-y-5">
      <div class="flex justify-between items-center">
        <h3 class="font-semibold text-zinc-100">AI Hesabı Bağla</h3>
        <button onclick="closeModal()" class="text-zinc-500 hover:text-zinc-300">✕</button>
      </div>

      <!-- Tab Buttons -->
      <div class="flex border-b border-surfaceBorder">
        <button onclick="switchTab('oauth')" id="tabOAuth" class="flex-1 pb-2.5 text-xs font-semibold border-b-2 border-accent text-accent">
          ⚡ Oturum Açarak Bağlan (OAuth)
        </button>
        <button onclick="switchTab('manual')" id="tabManual" class="flex-1 pb-2.5 text-xs font-semibold border-b-2 border-transparent text-zinc-400 hover:text-zinc-200">
          🔑 Manuel API Key / Token
        </button>
      </div>

      <!-- OAuth Section -->
      <div id="oauthSection" class="space-y-4">
        <p class="text-xs text-zinc-400">Tek tıkla resmi oturum açma penceresine yönlendirilirsiniz. Token'lar yerel kasada şifrelenir.</p>
        
        <div class="grid grid-cols-1 gap-2.5">
          <!-- Google / Gemini Button -->
          <button onclick="startGoogleOAuth()" class="flex items-center justify-between p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800/80 transition">
            <div class="flex items-center gap-3">
              <span class="text-lg">🌐</span>
              <div class="text-left">
                <div class="text-xs font-semibold text-zinc-100">Google Gemini / Cloud Code</div>
                <div class="text-[10px] text-zinc-500">Gemini 3 Flash, 2.5 Pro model kotaları</div>
              </div>
            </div>
            <span class="text-xs font-medium text-accent">Giriş Yap →</span>
          </button>

          <!-- OpenAI / Codex Button -->
          <button onclick="startCodexOAuth()" class="flex items-center justify-between p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800/80 transition">
            <div class="flex items-center gap-3">
              <span class="text-lg">🤖</span>
              <div class="text-left">
                <div class="text-xs font-semibold text-zinc-100">OpenAI ChatGPT / Codex</div>
                <div class="text-[10px] text-zinc-500">Plus / Pro 5 saatlik kayan kotalar</div>
              </div>
            </div>
            <span class="text-xs font-medium text-accent">Giriş Yap →</span>
          </button>

          <!-- Anthropic Claude Button -->
          <button onclick="startClaudeOAuth()" class="flex items-center justify-between p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800/80 transition">
            <div class="flex items-center gap-3">
              <span class="text-lg">🔮</span>
              <div class="text-left">
                <div class="text-xs font-semibold text-zinc-100">Anthropic Claude Pro/Max</div>
                <div class="text-[10px] text-zinc-500">5h oturum ve haftalık Opus/Sonnet kotaları</div>
              </div>
            </div>
            <span class="text-xs font-medium text-accent">Giriş Yap →</span>
          </button>
        </div>

        <!-- Codex Device Code Active State Panel -->
        <div id="codexDevicePanel" class="hidden p-4 rounded-lg bg-zinc-900/90 border border-accent/40 space-y-3">
          <div class="text-xs font-medium text-zinc-200">OpenAI Cihaz Onayı Bekleniyor:</div>
          <div class="flex items-center gap-2">
            <span class="text-xs text-zinc-400">Onay Kodu:</span>
            <span id="codexUserCode" class="text-base font-mono font-bold tracking-wider text-accent bg-zinc-800 px-2 py-0.5 rounded">...</span>
          </div>
          <p class="text-[11px] text-zinc-400">
            Açılan OpenAI sayfasında kodu onaylayın. Panel otomatik olarak tamamlanacaktır.
          </p>
          <a id="codexAuthLink" href="#" target="_blank" class="inline-block text-xs font-semibold text-accent hover:underline">
            Sayfayı Tekrar Aç ↗
          </a>
        </div>
      </div>

      <!-- Manual API Key Form Section -->
      <form id="manualSection" onsubmit="handleManualSave(event)" class="hidden space-y-4">
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1">Sağlayıcı</label>
          <select id="providerSelect" class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none">
            <option value="openrouter">OpenRouter (API Key)</option>
            <option value="deepseek">DeepSeek (API Key)</option>
            <option value="anthropic">Anthropic (OAuth Token / API Key)</option>
            <option value="openai-codex">OpenAI Codex (OAuth Token)</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1">Hesap Adı / Etiket</label>
          <input type="text" id="accountLabel" placeholder="Örn: Kişisel Pro, İş Hesabı" required class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none" />
        </div>
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1">Kimlik Türü</label>
          <select id="credentialType" class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none">
            <option value="api_key">API Anahtarı</option>
            <option value="oauth">OAuth Access Token</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1">Secret / Token</label>
          <input type="password" id="secretValue" placeholder="sk-... veya bearer token" required class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none" />
        </div>
        <div class="flex justify-end gap-2 pt-2">
          <button type="button" onclick="closeModal()" class="px-4 py-2 rounded-md text-xs font-medium bg-zinc-800 hover:bg-zinc-700 text-zinc-300">İptal</button>
          <button type="submit" class="px-4 py-2 rounded-md text-xs font-medium bg-accent hover:bg-accentHover text-zinc-950 font-semibold">Kaydet ve Sorgula</button>
        </div>
      </form>
    </div>
  </div>

  <script>
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
        renderCards(json.data || []);
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
        if (!json.success) { alert('Codex başlatılamadı: ' + json.error); return; }

        const { userCode, verificationUrl, deviceAuthId, interval } = json.data;
        document.getElementById('codexUserCode').innerText = userCode;
        document.getElementById('codexAuthLink').href = verificationUrl;
        document.getElementById('codexDevicePanel').classList.remove('hidden');

        window.open(verificationUrl, '_blank');

        // Start polling in background
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
        if (!json.success) { alert('Google başlatılamadı: ' + json.error); return; }

        const { authUrl, sessionId } = json.data;
        window.open(authUrl, '_blank');

        // Poll session status
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
        if (!json.success) { alert('Claude başlatılamadı: ' + json.error); return; }

        const { authUrl, sessionId } = json.data;
        window.open(authUrl, '_blank');

        // Poll session status
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
        container.innerHTML = '<div class="col-span-full py-16 text-center text-zinc-500">Henüz kayıtlı bir AI sağlayıcısı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.</div>';
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
          }

          let countdownHtml = '';
          if (l.window && l.window.resetsAt) {
            const diffMin = Math.max(0, Math.round((l.window.resetsAt - Date.now()) / 60000));
            const hours = Math.floor(diffMin / 60);
            const mins = diffMin % 60;
            const label = hours > 0 ? (hours + 's ' + mins + 'dk') : (mins + 'dk');
            countdownHtml = '<span class="text-[10px] text-zinc-400 bg-zinc-800/80 px-1.5 py-0.5 rounded">' + (l.window.resetLabel || 'Sıfırlanma') + ': ' + label + '</span>';
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
               '      <span class="text-[10px] text-zinc-500">Son Güncelleme: ' + new Date(r.fetchedAt).toLocaleTimeString() + '</span>' +
               '    </div>' +
               '    <button data-id="' + (r.credentialId || '') + '" onclick="deleteAccount(this.dataset.id)" title="Hesabı Kaldır" class="text-zinc-600 hover:text-red-400 text-xs p-1 rounded hover:bg-zinc-800 transition">✕</button>' +
               '  </div>' +
               '  <div class="space-y-2.5">' + limitsHtml + '</div>' +
               '</div>';
      }).join('');
    }
    async function deleteAccount(id) {
      if (!id || !confirm('Bu hesabı kaldırmak istediğinizden emin misiniz?')) return;
      await fetch('/api/credentials/' + id, { method: 'DELETE' });
      await loadUsage();
    }

    loadUsage();
    setInterval(loadUsage, 10000); // 10s live sync
  </script>
</body>
</html>`;
}
