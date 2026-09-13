import { Hono } from "hono";
import { cors } from "hono/cors";
import type { StorageVault } from "../core/storage/vault";
import type { PollerEngine } from "../core/poller/poller";
import type { ProviderRegistry } from "../core/providers/registry";
import type { InputCredential } from "../types";

export function createServer(vault: StorageVault, poller: PollerEngine, _registry: ProviderRegistry): Hono {
  const app = new Hono();

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
    const masked = creds.map(c => {
      const s = c.secret;
      const maskedSecret = s.length > 8 ? `${s.slice(0, 4)}...${s.slice(-4)}` : "********";
      return {
        id: c.id,
        provider: c.provider,
        accountLabel: c.accountLabel,
        credentialType: c.credentialType,
        maskedSecret,
        createdAt: c.createdAt,
      };
    });
    return c.json({ success: true, data: masked });
  });

  // API: Add credential
  app.post("/api/credentials", async c => {
    try {
      const body = (await c.req.json()) as InputCredential;
      if (!body.provider || !body.accountLabel || !body.secret) {
        return c.json({ success: false, error: "Tüm alanlar zorunludur." }, 400);
      }

      const saved = vault.saveCredential(body);
      // Trigger initial poll for this credential in background
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
        + Hesap Ekle
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

  <!-- Add Credential Modal -->
  <div id="modal" class="fixed inset-0 bg-black/70 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
    <div class="bg-surface border border-surfaceBorder rounded-xl max-w-md w-full p-6 space-y-4">
      <div class="flex justify-between items-center">
        <h3 class="font-semibold text-zinc-100">Yeni AI Sağlayıcısı Ekle</h3>
        <button onclick="closeModal()" class="text-zinc-500 hover:text-zinc-300">✕</button>
      </div>
      <form onsubmit="handleSave(event)" class="space-y-4">
        <div>
          <label class="block text-xs font-medium text-zinc-400 mb-1">Sağlayıcı</label>
          <select id="providerSelect" class="w-full bg-zinc-900 border border-surfaceBorder rounded-md px-3 py-2 text-sm text-zinc-200 focus:border-accent outline-none">
            <option value="openrouter">OpenRouter (API Key)</option>
            <option value="deepseek">DeepSeek (API Key)</option>
            <option value="anthropic">Anthropic Claude (OAuth Token)</option>
            <option value="openai-codex">OpenAI ChatGPT / Codex (OAuth Token)</option>
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
    function closeModal() { document.getElementById('modal').classList.add('hidden'); document.getElementById('modal').classList.remove('flex'); }

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

    async function handleSave(e) {
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
        container.innerHTML = '<div class="col-span-full py-16 text-center text-zinc-500">Henüz kayıtlı bir AI sağlayıcısı bulunmuyor. Yukarıdaki <b>+ Hesap Ekle</b> butonuyla ekleyebilirsiniz.</div>';
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
            countdownHtml = '<span class="text-[10px] text-zinc-400 bg-zinc-800/80 px-1.5 py-0.5 rounded">Sıfırlanma: ' + label + '</span>';
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
               '  </div>' +
               '  <div class="space-y-2.5">' + limitsHtml + '</div>' +
               '</div>';
      }).join('');
    }

    loadUsage();
    setInterval(loadUsage, 10000); // 10s live sync
  </script>
</body>
</html>`;
}
