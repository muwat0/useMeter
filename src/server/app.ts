import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import type { StorageVault } from "../core/storage/vault";
import type { PollerEngine } from "../core/poller/poller";
import type { ProviderRegistry } from "../core/providers/registry";
import type { InputCredential, UsageReport } from "../types";
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
import { syncCredentialsFromOmp } from "../core/omp-sync";

interface VaultStorageExtension {
  updateCredential?(id: string, updates: { accountLabel?: string; accent?: string | null }): boolean;
  updateCredentialAccent?(id: string, accent: string | null): boolean;
  updateCredentialMetadata?(id: string, metadata: Record<string, unknown>): boolean;
}

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

  const handleUsage = (c: Context) => {
    const latest = vault.getLatestUsage();
    const credentials = new Map(vault.listCredentials().map(credential => [credential.id, credential]));
    const data = latest.map(report => {
      const credential = report.credentialId ? credentials.get(report.credentialId) : undefined;
      return {
        ...report,
        createdAt: credential?.createdAt,
        accent: credential?.accent || "default",
      };
    });
    return c.json({ success: true, data });
  };
  app.get("/api/usage", handleUsage);
  app.get("/api/data", handleUsage);

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
        maskedSecret,
        createdAt: cr.createdAt,
        accent: cr.accent || "default",
      };
    });
    return c.json({ success: true, data: masked });
  });

  // API: Add manual credential
  app.post("/api/credentials", async c => {
    try {
      const body = (await c.req.json()) as InputCredential & { accent?: string | null };
      if (!body.provider || !body.accountLabel || !body.secret) {
        return c.json({ success: false, error: "Tüm alanlar zorunludur." }, 400);
      }

      if (body.accent) {
        body.metadata = { ...(body.metadata || {}), accent: body.accent };
      }

      const saved = vault.saveCredential(body);
      poller.pollCredential(saved).catch(() => {});

      return c.json({
        success: true,
        data: {
          id: saved.id,
          provider: saved.provider,
          accountLabel: saved.accountLabel,
          accent: body.accent || null,
        },
      });
    } catch (err) {
      return c.json({ success: false, error: String(err) }, 500);
    }
  });

  // API: Update credential (label and/or accent)
  app.patch("/api/credentials/:id", async c => {
    try {
      const id = c.req.param("id");
      const body = (await c.req.json()) as { accountLabel?: string; accent?: string | null };

      let updated = false;
      const v = vault as unknown as VaultStorageExtension;
      if (typeof v.updateCredential === "function") {
        updated = Boolean(v.updateCredential(id, body));
      } else {
        if (body.accountLabel && typeof vault.updateCredentialLabel === "function") {
          updated = vault.updateCredentialLabel(id, body.accountLabel);
        }
        if (body.accent !== undefined && typeof v.updateCredentialAccent === "function") {
          updated = Boolean(v.updateCredentialAccent(id, body.accent)) || updated;
        } else if (body.accent !== undefined && typeof v.updateCredentialMetadata === "function") {
          updated = Boolean(v.updateCredentialMetadata(id, { accent: body.accent })) || updated;
        }
      }

      return c.json({ success: true, updated });
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

      pendingOAuth.set(sessionId, { provider: "antigravity", status: "pending" });

      listenForGoogleCallback(state)
        .then(async code => {
          const tokens = await exchangeGoogleCode(code, verifier);
          const label = tokens.email || "Antigravity";

          const saved = vault.saveCredential({
            provider: "antigravity",
            accountLabel: label,
            credentialType: "oauth",
            secret: tokens.accessToken,
            metadata: {
              refreshToken: tokens.refreshToken,
              email: tokens.email,
            },
          });

          poller.pollCredential(saved).catch(() => {});
          pendingOAuth.set(sessionId, { provider: "antigravity", status: "complete", accountLabel: label });
        })
        .catch(err => {
          pendingOAuth.set(sessionId, { provider: "antigravity", status: "error", error: String(err) });
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

  // UI: Dashboard (Server-Side Rendered on First Paint)
  app.get("/", c => {
    const latest = vault.getLatestUsage();
    const creds = vault.listCredentials();
    const credsMap = new Map(creds.map(cr => [cr.id, cr]));
    const enriched: (UsageReport & { createdAt?: number; accent?: string | null })[] = latest.map(r => {
      const cr = r.credentialId ? credsMap.get(r.credentialId) : undefined;
      const accent = cr?.accent || "default";
      return {
        ...r,
        createdAt: cr?.createdAt,
        accent,
      };
    });
    return c.html(renderDashboardHtml(enriched));
  });
  // API: Sync all credentials from OMP agent.db
  app.post("/api/omp/sync", async c => {
    try {
      const syncRes = syncCredentialsFromOmp(vault);
      // Trigger background poll for all accounts
      poller.pollAll().catch(() => {});
      return c.json({ success: true, total: syncRes.total, imported: syncRes.imported });
    } catch (err) {
      return c.json({ success: false, error: String(err) }, 500);
    }
  });

  return app;
}

function formatProviderTitle(provider: string): string {
  const p = (provider || "").toLowerCase();
  if (p === "antigravity" || p === "google-antigravity" || p === "google") return "Antigravity";
  if (p === "openai-codex" || p === "codex") return "OpenAI Codex";
  if (p === "openrouter") return "OpenRouter";
  if (p === "deepseek") return "DeepSeek";
  if (p === "anthropic" || p === "claude") return "Anthropic Claude";
  if (p === "cursor") return "Cursor";
  if (p === "github-copilot" || p === "copilot") return "GitHub Copilot";
  if (p === "xai-oauth" || p === "grok" || p === "xai") return "xAI Grok";
  if (p === "zai" || p === "zhipu" || p === "glm") return "Zhipu AI (GLM)";
  if (p === "minimax-code" || p === "minimax") return "MiniMax Code";
  if (p === "cline-pass" || p === "clinepass") return "Cline Pass";
  if (p === "devin") return "Devin";
  if (p === "umans") return "Umans";
  if (p === "google-gemini-cli" || p === "gemini-cli") return "Gemini CLI";
  if (p === "kimi-code" || p === "kimi" || p === "moonshot") return "Kimi Code";
  if (p === "opencode-go") return "OpenCode Go";
  if (p === "alibaba-token-plan") return "Alibaba Qwen";
  return provider.charAt(0).toUpperCase() + provider.slice(1);
}

function renderDashboardHtml(initialReports: (UsageReport & { createdAt?: number; accent?: string | null })[] = []): string {
  let initialTotalBal = 0;
  let initialExhausted = 0;

  for (const r of initialReports) {
    for (const l of r.limits || []) {
      if (l.amount && l.amount.unit === "usd" && typeof l.amount.remaining === "number") {
        if (l.id.includes("balance") || l.id.includes("credits")) initialTotalBal += l.amount.remaining;
      }
      if (l.status === "exhausted") initialExhausted++;
    }
  }

  const initialCardsHtml = initialReports.length === 0
    ? `<div class="col-span-full py-24 text-center text-appTextMuted text-sm" data-i18n="noAccounts">Henüz kayıtlı bir AI hesabı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.</div>`
    : initialReports.map(r => {
        const limitsHtml = (r.limits || []).map(l => {
          let valueHtml = "";
          let barHtml = "";

          if (l.amount.unit === "percent") {
            const used = l.amount.used || 0;
            const barColor = used >= 90 ? "bg-rose-500" : used >= 75 ? "bg-amber-500" : "bg-emerald-500";
            valueHtml = `<span class="font-bold text-sm text-appText">${used.toFixed(1)}%</span>`;
            barHtml = `<div class="w-full bg-appBorder h-1.5 rounded-full overflow-hidden mt-2"><div class="${barColor} h-full transition-all duration-300" style="width: ${Math.min(100, used)}%"></div></div>`;
          } else if (l.amount.unit === "usd") {
            const rem = l.amount.remaining ?? 0;
            valueHtml = `<span class="font-bold text-sm text-emerald-500">$${rem.toFixed(2)}</span>`;
          } else if (l.amount.unit === "credits") {
            const rem = l.amount.remaining ?? 0;
            const badgeCls = rem > 0 
              ? "account-card-accent-badge" 
              : "bg-appMuted text-appTextMuted border border-appBorder";
            valueHtml = `<span class="font-semibold text-xs ${badgeCls} px-2.5 py-0.5 rounded-md">${rem} Hak Mevcut</span>`;
          }

          let countdownHtml = "";
          if (l.window && l.window.resetsAt) {
            const diffMin = Math.max(0, Math.round((l.window.resetsAt - Date.now()) / 60000));
            const hours = Math.floor(diffMin / 60);
            const mins = diffMin % 60;
            const timeLabel = hours > 0 ? `${hours}sa ${mins}dk` : `${mins}dk`;
            countdownHtml = `<span class="text-xs text-appTextMuted flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-appTextMuted/70"></span>Sıfırlanma: ${timeLabel}</span>`;
          }

          const cleanNotes = (l.notes || []).filter(n => !String(n).toLowerCase().includes("model"));
          const notesHtml = cleanNotes.map(n => `<span class="text-xs text-appTextMuted block mt-0.5">${n}</span>`).join("");

          return `
            <div class="bg-appMuted/40 border border-appBorder rounded-xl p-3.5 space-y-1.5">
              <div class="flex justify-between items-center">
                <span class="text-sm font-semibold text-appText tracking-tight">${l.label}</span>
                ${valueHtml}
              </div>
              ${barHtml}
              <div class="flex justify-between items-center pt-1">
                ${countdownHtml}
              </div>
              ${notesHtml}
            </div>
          `;
        }).join("");

        const cleanLabel = (r.accountLabel || "Default").replace(/^Google \((.*)\)$/, "$1");
        const cardAccent = r.accent || "";

        return `
          <div data-card-id="${r.credentialId || r.provider}" data-accent="${cardAccent}" class="account-card bg-appSurface border border-appBorder rounded-2xl p-5 space-y-4 transition-all shadow-sm">
            <div class="flex justify-between items-start">
              <div>
                <div class="flex items-center gap-2.5">
                  <h2 class="font-bold text-appText text-base tracking-tight">${formatProviderTitle(r.provider)}</h2>
                  <span class="text-xs font-semibold px-2.5 py-0.5 rounded-md bg-appMuted text-appTextMuted border border-appBorder">${cleanLabel}</span>
                </div>
                <span class="text-xs text-appTextMuted block mt-1.5" data-i18n="lastUpdate">Son Güncelleme: ${new Date(r.fetchedAt).toLocaleTimeString()}</span>
              </div>
              <button data-id="${r.credentialId || ""}" onclick="deleteAccount(this.dataset.id)" title="Remove Account" data-i18n-title="deleteAccount" class="text-appTextMuted hover:text-rose-500 text-sm p-1.5 rounded-lg hover:bg-appMuted transition">✕</button>
            </div>
            <div class="space-y-2.5">${limitsHtml}</div>
          </div>
        `;
      }).join("");

  const initialJson = JSON.stringify(initialReports).replace(/</g, "\\u003c");

  return `<!DOCTYPE html>
<html lang="tr" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Usage Tracker — Multi-Provider Quota & Balance Hub</title>
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
      --color-text-muted: #8e95a5;
      --color-accent: #ff9849;
      --color-accent-hover: #ea7c2b;
      --color-accent-soft: rgba(255, 152, 73, 0.12);
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
    }
    body {
      background-color: var(--color-bg);
      color: var(--color-text);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      -webkit-font-smoothing: antialiased;
      font-variant-numeric: tabular-nums;
    }
    .drag-over {
      outline: 2px dashed var(--color-accent) !important;
      outline-offset: 4px;
    }
    .account-card {
      --card-accent: var(--color-accent);
      --card-accent-hover: var(--color-accent-hover);
      --card-accent-soft: var(--color-accent-soft);
    }
    .account-card[data-accent="amber"] {
      --card-accent: #ff9849;
      --card-accent-hover: #ea7c2b;
      --card-accent-soft: rgba(255, 152, 73, 0.14);
    }
    .account-card[data-accent="emerald"] {
      --card-accent: #10b981;
      --card-accent-hover: #059669;
      --card-accent-soft: rgba(16, 185, 129, 0.14);
    }
    .account-card[data-accent="cyan"] {
      --card-accent: #06b6d4;
      --card-accent-hover: #0891b2;
      --card-accent-soft: rgba(6, 182, 212, 0.14);
    }
    .account-card[data-accent="violet"] {
      --card-accent: #a855f7;
      --card-accent-hover: #9333ea;
      --card-accent-soft: rgba(168, 85, 247, 0.14);
    }
    .account-card[data-accent="slate"] {
      --card-accent: #38bdf8;
      --card-accent-hover: #0284c7;
      --card-accent-soft: rgba(56, 189, 248, 0.14);
    }
    .account-card-accent-badge {
      background-color: var(--card-accent-soft);
      color: var(--card-accent);
      border: 1px solid var(--card-accent);
    }
  </style>
</head>
<body class="min-h-screen flex flex-col transition-colors duration-200 text-sm overflow-x-hidden">
  <!-- Top Control Bar (Clean Engineering Wordmark, Zero Slop) -->
  <header class="border-b border-appBorder bg-appSurface/80 backdrop-blur-md px-4 sm:px-6 py-4 sticky top-0 z-20 transition-colors">
    <div class="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3">
      <!-- Minimalist Clean Logo & Plain-Language Sync Status -->
      <div class="flex items-center gap-2.5 sm:gap-3">
        <div class="flex items-center gap-2">
          <span class="font-extrabold tracking-wider text-appText text-lg font-mono">USAGE</span>
          <span id="syncLiveDot" class="w-2 h-2 rounded-full bg-emerald-500 ring-4 ring-emerald-500/20" title="Last checked: just now" data-i18n-title="syncStatusJustNow"></span>
        </div>
        <div class="hidden sm:block h-4 w-px bg-appBorder"></div>
        <span id="headerSyncStatus" class="text-xs text-appTextMuted tracking-tight font-medium" data-i18n="syncStatusJustNow">Son kontrol: az önce</span>
        <span class="sr-only" data-i18n="title">AI Usage Tracker</span>
      </div>

      <!-- Controls Right -->
      <div class="flex items-center gap-2 sm:gap-2.5 flex-wrap">
        <!-- Edit Mode Button -->
        <button onclick="toggleEditMode()" id="editModeBtn" title="Card Edit Mode" data-i18n-title="editModeTitle" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 20h9"></path>
            <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
          </svg>
        </button>

        <!-- Grouping Dropdown -->
        <select id="groupSelect" onchange="changeGroup(this.value)" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent transition outline-none cursor-pointer">
          <option value="none" data-i18n="groupNone">Gruplama Yok</option>
          <option value="provider" data-i18n="groupProvider">Sağlayıcıya Göre</option>
        </select>

        <!-- Sorting Dropdown -->
        <select id="sortSelect" onchange="changeSort(this.value)" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent transition outline-none cursor-pointer">
          <option value="custom" data-i18n="sortCustom">Özel Sıralama</option>
          <option value="date_added" data-i18n="sortDateAdded">Eklenme Tarihi</option>
          <option value="highest_available" data-i18n="sortHighest">En Yüksek Kalan</option>
          <option value="lowest_available" data-i18n="sortLowest">En Düşük Kalan</option>
        </select>

        <!-- Settings Modal Trigger -->
        <button onclick="openSettingsModal()" id="settingsBtn" title="Settings" data-i18n-title="settingsTitle" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </button>

        <!-- Dark / Light Mode Toggle Button -->
        <button onclick="toggleLightDark()" id="lightDarkBtn" title="Dark / Light Mode" data-i18n-title="themeTitle" class="h-9 w-9 rounded-lg border border-appBorder bg-appSurface text-appTextMuted hover:text-appText hover:border-appAccent transition flex items-center justify-center text-sm">
          <span id="lightDarkIcon">☀️</span>
        </button>

        <!-- Language Switcher Toggle with Flag -->
        <button onclick="toggleLang()" id="langBtn" class="h-9 px-2.5 sm:px-3 rounded-lg border border-appBorder bg-appSurface text-appText text-xs font-semibold hover:border-appAccent/50 transition flex items-center gap-1.5 sm:gap-2">
          <span id="langFlag" class="text-base">🇹🇷</span>
          <span id="langLabel">TR</span>
        </button>

        <!-- Manual Poll Button -->
        <button onclick="pollNow()" id="pollBtn" class="h-9 px-3 sm:px-3.5 rounded-lg text-xs font-semibold bg-appMuted hover:bg-appBorder text-appText transition flex items-center gap-1.5 sm:gap-2 border border-appBorder">
          <svg id="pollSpinner" class="hidden animate-spin w-4 h-4 text-appAccent" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path>
          </svg>
          <span data-i18n="refresh">Yenile</span>
        </button>

        <!-- Connect Account Button -->
        <button onclick="openModal()" class="h-9 px-3.5 sm:px-4 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition flex items-center gap-1.5 shadow-sm">
          <span>+</span>
          <span data-i18n="addAccountText">Hesap Bağla</span>
        </button>
      </div>
    </div>
  </header>

  <!-- Summary Stats Strip -->
  <section class="border-b border-appBorder bg-appSurface/30 px-4 sm:px-6 py-3.5">
    <div class="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs font-medium">
      <div class="flex items-center gap-4 sm:gap-6 flex-wrap">
        <div class="flex items-center gap-2">
          <span class="text-appTextMuted" data-i18n="summaryActive">Aktif Hesaplar:</span>
          <span id="statActiveCount" class="font-bold text-appText text-sm">${initialReports.length}</span>
        </div>
        <div class="flex items-center gap-2 border-l border-appBorder pl-4 sm:pl-6">
          <span class="text-appTextMuted" data-i18n="summaryBalance">Toplam Ön Ödemeli Bakiye:</span>
          <span id="statTotalBalance" class="font-bold text-emerald-500 text-sm">$${initialTotalBal.toFixed(2)}</span>
        </div>
        <div class="flex items-center gap-2 border-l border-appBorder pl-4 sm:pl-6">
          <span class="text-appTextMuted" data-i18n="summaryExhausted">Kilitli/Biten Kota:</span>
          <span id="statExhaustedCount" class="font-bold text-appText text-sm">${initialExhausted}</span>
        </div>
      </div>
      <div class="text-xs text-appTextMuted flex items-center gap-2">
        <span id="editModeNotice" class="hidden text-appAccent font-semibold animate-pulse" data-i18n="editModeActive">✏️ Düzenleme Modu Aktif</span>
        <span data-i18n="autoSync">Otomatik Yenileme:</span>
        <span class="text-appAccent font-semibold">10s</span>
      </div>
    </div>
  </section>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">
    <div id="cardsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
      ${initialCardsHtml}
    </div>
  </main>

  <!-- Settings Modal (Theme Accent Picker & Preferences) -->
  <div id="settingsModal" class="fixed inset-0 bg-black/60 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
    <div class="bg-appSurface border border-appBorder rounded-2xl max-w-md w-full max-h-[90vh] overflow-y-auto p-5 sm:p-6 space-y-5 shadow-2xl transition-colors">
      <div class="flex justify-between items-center pb-3 border-b border-appBorder">
        <h3 class="font-bold text-appText text-base" data-i18n="settingsTitle">Ayarlar</h3>
        <button onclick="closeSettingsModal()" title="Close" data-i18n-title="close" class="text-appTextMuted hover:text-appText text-lg p-1">✕</button>
      </div>

      <div class="space-y-4">
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-2.5" data-i18n="themeAccent">Vurgu Rengi</label>
          <div class="grid grid-cols-5 gap-2.5">
            <button onclick="changeTheme('amber')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_amber">
              <span class="w-6 h-6 rounded-full bg-[#ff9849]"></span>
              <span class="text-[11px] font-medium text-appText">Amber</span>
            </button>
            <button onclick="changeTheme('emerald')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_emerald">
              <span class="w-6 h-6 rounded-full bg-[#10b981]"></span>
              <span class="text-[11px] font-medium text-appText">Emerald</span>
            </button>
            <button onclick="changeTheme('cyan')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_cyan">
              <span class="w-6 h-6 rounded-full bg-[#06b6d4]"></span>
              <span class="text-[11px] font-medium text-appText">Cyan</span>
            </button>
            <button onclick="changeTheme('violet')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_violet">
              <span class="w-6 h-6 rounded-full bg-[#a855f7]"></span>
              <span class="text-[11px] font-medium text-appText">Violet</span>
            </button>
            <button onclick="changeTheme('slate')" class="flex flex-col items-center gap-1.5 p-2 rounded-xl border border-appBorder bg-appMuted/50 hover:border-appAccent transition" id="themeOpt_slate">
              <span class="w-6 h-6 rounded-full bg-[#38bdf8]"></span>
              <span class="text-[11px] font-medium text-appText">Slate</span>
            </button>
          </div>
        </div>
        <!-- OMP Integration Section in Settings -->
        <div class="pt-3 border-t border-appBorder space-y-2">
          <label class="block text-xs font-semibold text-appTextMuted" data-i18n="ompSectionTitle">OMP (Oh My Pi) Entegrasyonu</label>
          <p class="text-xs text-appTextMuted leading-relaxed" data-i18n="ompSectionDesc">OMP veritabanındaki (agent.db) tüm aktif AI hesaplarını (Antigravity, Codex, Cursor, Copilot, Grok, ZAI) tek tıkla içeri aktarın.</p>
          <button onclick="syncFromOmp()" id="syncOmpBtn" class="w-full py-2.5 px-4 rounded-xl border border-appBorder bg-appMuted hover:border-appAccent text-appText text-xs font-semibold flex items-center justify-center gap-2 transition">
            <span>⚡</span>
            <span id="syncOmpBtnText" data-i18n="syncOmpBtn">OMP Hesaplarını Eşitle</span>
          </button>
        </div>
      </div>

      <div class="flex justify-end pt-3 border-t border-appBorder">
        <button onclick="closeSettingsModal()" class="px-4 py-2 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition" data-i18n="close">Kapat</button>
      </div>
    </div>
  </div>

  <!-- Add Credential / OAuth Modal -->
  <div id="modal" class="fixed inset-0 bg-black/60 backdrop-blur-sm hidden items-center justify-center z-50 p-4">
    <div class="bg-appSurface border border-appBorder rounded-2xl max-w-lg w-full max-h-[90vh] overflow-y-auto p-5 sm:p-6 space-y-5 shadow-2xl transition-colors">
      <div class="flex justify-between items-center pb-3 border-b border-appBorder">
        <div>
          <h3 class="font-bold text-appText text-base" data-i18n="modalTitle">AI Hesabı Bağla</h3>
          <p class="text-xs text-appTextMuted mt-0.5" data-i18n="modalSubtitle">OAuth veya doğrudan API anahtarıyla kota takibi kurun.</p>
        </div>
        <button onclick="closeModal()" title="Close" data-i18n-title="close" class="text-appTextMuted hover:text-appText text-lg p-1">✕</button>
      </div>

      <!-- Segmented Tab Switcher -->
      <div class="flex p-1 bg-appMuted rounded-xl border border-appBorder text-xs">
        <button onclick="switchTab('oauth')" id="tabOAuth" class="flex-1 py-2 font-semibold rounded-lg bg-appSurface text-appText shadow-sm transition" data-i18n="tabOAuth">
          OAuth ile Oturum Aç
        </button>
        <button onclick="switchTab('manual')" id="tabManual" class="flex-1 py-2 font-semibold rounded-lg text-appTextMuted hover:text-appText transition" data-i18n="tabManual">
          Manuel API Key
        </button>
      </div>

      <!-- OAuth Flow Options with Crisp Brand Marks -->
      <div id="oauthSection" class="space-y-3.5">
        <p class="text-xs text-appTextMuted leading-relaxed" data-i18n="oauthDesc">Resmi sağlayıcı girişine yönlendirilirsiniz. Token'lar yerel veritabanında AES-256-GCM ile şifrelenir.</p>

        <div class="space-y-2.5">
          <!-- Antigravity (Google Multicolor Mark) -->
          <button onclick="startGoogleOAuth()" class="w-full flex items-center justify-between p-3.5 sm:p-4 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3.5">
              <div class="w-9 h-9 rounded-lg bg-appMuted flex items-center justify-center p-2 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="20" height="20" role="img" aria-label="Google">
                  <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.17z"/>
                  <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.34 24 12 24z"/>
                  <path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.17 0 9.99 0 12s.45 3.83 1.25 5.42l4.03-3.15z"/>
                  <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.34 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/>
                </svg>
              </div>
              <div>
                <div class="text-sm font-semibold text-appText group-hover:text-appAccent transition" data-i18n="googleTitle">Antigravity (Google AI Pro)</div>
                <div class="text-xs text-appTextMuted mt-0.5" data-i18n="googleDesc">Gemini ve Claude & GPT model havuzu kotaları</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- OpenAI Codex (Official Knot Spiral Mark) -->
          <button onclick="startCodexOAuth()" class="w-full flex items-center justify-between p-3.5 sm:p-4 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3.5">
              <div class="w-9 h-9 rounded-lg bg-appMuted flex items-center justify-center p-2 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" class="text-emerald-400" role="img" aria-label="OpenAI">
                  <path d="M22.28 9.82a6 6 0 0 0-.52-4.91 6.05 6.05 0 0 0-6.51-2.9A6.06 6.06 0 0 0 4.98 4.18a5.98 5.98 0 0 0-4 2.9 6.05 6.05 0 0 0 .74 7.1 6 6 0 0 0 .51 4.91 6.05 6.05 0 0 0 6.52 2.9A5.98 5.98 0 0 0 13.26 24a6.06 6.06 0 0 0 5.77-4.2 6 6 0 0 0 4-2.9 6.06 6.06 0 0 0-.75-7.08zm-9.02 12.61a4.48 4.48 0 0 1-2.88-1.04l.14-.08 4.78-2.76a.8.8 0 0 0 .39-.68v-6.74l2.02 1.17a.07.07 0 0 1 .04.05v5.58a4.5 4.5 0 0 1-4.49 4.5zm-9.66-4.13a4.47 4.47 0 0 1-.54-3.01l.15.08 4.78 2.76a.77.77 0 0 0 .78 0l5.84-3.37v2.33a.08.08 0 0 1-.03.06l-4.84 2.8a4.5 4.5 0 0 1-6.14-1.65zM2.34 7.9a4.49 4.49 0 0 1 2.37-1.98V11.6a.77.77 0 0 0 .39.68l5.81 3.35-2.02 1.17a.08.08 0 0 1-.07 0l-4.83-2.79A4.5 4.5 0 0 1 2.34 7.9zm16.6 3.85L13.1 8.38l2.02-1.16a.08.08 0 0 1 .07 0l4.83 2.79a4.5 4.5 0 0 1-.68 8.1V12.44a.8.8 0 0 0-.4-.69zm2.01-3.02l-.14-.09-4.78-2.78a.78.78 0 0 0-.78 0L9.4 9.23V6.9a.07.07 0 0 1 .03-.06l4.83-2.79a4.5 4.5 0 0 1 6.68 4.66zM8.31 12.86l-2.02-1.16a.08.08 0 0 1-.04-.06V6.07a4.5 4.5 0 0 1 7.38-3.45l-.14.08-4.78 2.76a.8.8 0 0 0-.4.68v6.72zm1.14-1.63l2.55-1.47 2.55 1.47v2.94l-2.55 1.47-2.55-1.47z"/>
                </svg>
              </div>
              <div>
                <div class="text-sm font-semibold text-appText group-hover:text-appAccent transition" data-i18n="codexTitle">OpenAI ChatGPT / Codex</div>
                <div class="text-xs text-appTextMuted mt-0.5" data-i18n="codexDesc">Plus / Pro 5 saatlik ve haftalık kotalar</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent" data-i18n="loginBtn">Oturum Aç →</span>
          </button>

          <!-- Anthropic Claude (Official Asterisk Mark) -->
          <button onclick="startClaudeOAuth()" class="w-full flex items-center justify-between p-3.5 sm:p-4 rounded-xl border border-appBorder bg-appMuted/40 hover:border-appAccent hover:bg-appAccentSoft transition group text-left">
            <div class="flex items-center gap-3.5">
              <div class="w-9 h-9 rounded-lg bg-appMuted flex items-center justify-center p-2 border border-appBorder shrink-0" aria-hidden="true">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor" class="text-amber-500" role="img" aria-label="Anthropic Claude">
                  <path d="M13.2 2h-2.4v7.3L5.64 4.14 3.94 5.84l5.16 5.16H2v2.4h7.1l-5.16 5.16 1.7 1.7 5.16-5.16V22h2.4v-7.1l5.16 5.16 1.7-1.7-5.16-5.16H22v-2.4h-7.3l5.16-5.16-1.7-1.7-5.16 5.16V2z"/>
                </svg>
              </div>
              <div>
                <div class="text-sm font-semibold text-appText group-hover:text-appAccent transition" data-i18n="claudeTitle">Anthropic Claude Pro/Max</div>
                <div class="text-xs text-appTextMuted mt-0.5" data-i18n="claudeDesc">5h oturum ve haftalık Opus/Sonnet kotaları</div>
              </div>
            </div>
            <span class="text-xs font-semibold text-appAccent" data-i18n="loginBtn">Oturum Aç →</span>
          </button>
        </div>

        <!-- Codex Device Code Active State Panel -->
        <div id="codexDevicePanel" class="hidden p-4 rounded-xl bg-appMuted border border-appAccent/40 space-y-3">
          <div class="flex items-center justify-between">
            <span class="text-xs font-semibold text-appText" data-i18n="deviceWait">OpenAI Onayı Bekleniyor:</span>
            <span id="codexUserCode" class="text-sm font-bold tracking-widest text-appAccent bg-appSurface border border-appAccent/30 px-3 py-1 rounded-md">...</span>
          </div>
          <p class="text-xs text-appTextMuted leading-relaxed" data-i18n="deviceDesc">
            Yeni sekmede açılan OpenAI sayfasına bu kodu girin. Onaylandığı an bu pencere kendiliğinden kapanacaktır.
          </p>
          <a id="codexAuthLink" href="#" target="_blank" class="inline-flex items-center gap-1 text-xs font-semibold text-appAccent hover:underline" data-i18n="reopenLink">
            Onay Sayfasını Yeniden Aç ↗
          </a>
        </div>
      </div>

      <!-- Manual API Key Form Section -->
      <form id="manualSection" onsubmit="handleManualSave(event)" class="hidden space-y-4">
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="provider">Sağlayıcı</label>
          <select id="providerSelect" onchange="updateSecretHelp(this.value)" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none cursor-pointer">
            <option value="antigravity">Antigravity (Google AI Pro)</option>
            <option value="openai-codex">OpenAI ChatGPT / Codex</option>
            <option value="github-copilot">GitHub Copilot</option>
            <option value="cursor">Cursor</option>
            <option value="anthropic">Anthropic Claude</option>
            <option value="openrouter">OpenRouter</option>
            <option value="deepseek">DeepSeek</option>
            <option value="xai-oauth">xAI Grok</option>
            <option value="zai">Zhipu AI (GLM)</option>
            <option value="minimax-code">MiniMax Code</option>
            <option value="cline-pass">Cline Pass</option>
            <option value="devin">Devin</option>
            <option value="umans">Umans</option>
            <option value="google-gemini-cli">Gemini CLI</option>
            <option value="kimi-code">Kimi Code</option>
            <option value="opencode-go">OpenCode Go</option>
            <option value="alibaba-token-plan">Alibaba Qwen</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="accountLabel">Hesap Adı / Etiket</label>
          <input type="text" id="accountLabel" placeholder="Örn: Kişisel Pro, İş Hesabı" data-i18n-placeholder="accountLabelPlaceholder" required class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
        </div>
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="accountAccent">Kart Vurgu Rengi</label>
          <select id="accountAccentSelect" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none cursor-pointer">
            <option value="" data-i18n="accentDefault">Varsayılan (Tema Rengi)</option>
            <option value="amber">Amber</option>
            <option value="emerald">Emerald</option>
            <option value="cyan">Cyan</option>
            <option value="violet">Violet</option>
            <option value="slate">Slate</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="credentialType">Kimlik Türü</label>
          <select id="credentialType" class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none">
            <option value="api_key" data-i18n="apiKey">API Anahtarı</option>
            <option value="oauth" data-i18n="oauthToken">OAuth Access Token</option>
          </select>
        </div>
        <div>
          <label class="block text-xs font-semibold text-appTextMuted mb-1.5" data-i18n="secretLabel">Secret / Token</label>
          <input type="password" id="secretValue" placeholder="Bearer token veya API anahtarı" required class="w-full bg-appMuted border border-appBorder rounded-lg px-3.5 py-2.5 text-sm text-appText focus:border-appAccent outline-none" />
          <p id="secretHelpText" class="text-[11px] text-appTextMuted mt-1">Google OAuth Access Token veya Refresh Token</p>
        </div>
        <div class="flex justify-end gap-2.5 pt-3 border-t border-appBorder">
          <button type="button" onclick="closeModal()" class="px-4 py-2 rounded-lg text-xs font-semibold bg-appMuted hover:bg-appBorder text-appText transition" data-i18n="cancel">İptal</button>
          <button type="submit" class="px-4.5 py-2 rounded-lg text-xs font-semibold bg-appAccent hover:bg-appAccentHover text-zinc-950 transition" data-i18n="saveAndPoll">Kaydet ve Sorgula</button>
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
        addAccountText: "Hesap Bağla",
        summaryActive: "Aktif Hesaplar:",
        summaryBalance: "Toplam Ön Ödemeli Bakiye:",
        summaryExhausted: "Kilitli/Biten Kota:",
        autoSync: "Otomatik Yenileme:",
        editModeActive: "✏️ Düzenleme Modu Aktif",
        editModeTitle: "Kart Düzenleme Modu",
        settingsTitle: "Ayarlar",
        themeTitle: "Koyu / Aydınlık Mod",
        deleteAccount: "Hesabı Kaldır",
        editLabel: "Etiketi Düzenle",
        save: "Kaydet",
        cancel: "İptal",
        noAccounts: "Henüz kayıtlı bir AI hesabı bulunmuyor. Yukarıdaki <b>+ Hesap Bağla</b> butonuyla ekleyebilirsiniz.",
        lastUpdate: "Son Güncelleme",
        deleteConfirm: "Bu hesabı kaldırmak istediğinizden emin misiniz?",
        resetsIn: "Sıfırlanma",
        rightsAvailable: "Hak Mevcut",
        modalTitle: "AI Hesabı Bağla",
        modalSubtitle: "OAuth veya doğrudan API anahtarıyla kota takibi kurun.",
        tabOAuth: "OAuth ile Oturum Aç",
        tabManual: "Manuel API Key",
        oauthDesc: "Resmi sağlayıcı girişine yönlendirilirsiniz. Token'lar yerel veritabanında AES-256-GCM ile şifrelenir.",
        googleTitle: "Antigravity (Google AI Pro)",
        googleDesc: "Gemini ve Claude & GPT model havuzu kotaları",
        codexTitle: "OpenAI ChatGPT / Codex",
        codexDesc: "Plus / Pro 5 saatlik ve haftalık kotalar",
        claudeTitle: "Anthropic Claude Pro/Max",
        claudeDesc: "5h oturum ve haftalık Opus/Sonnet kotaları",
        loginBtn: "Oturum Aç →",
        deviceWait: "OpenAI Onayı Bekleniyor:",
        deviceDesc: "Yeni sekmede açılan OpenAI sayfasına bu kodu girin. Onaylandığı an bu pencere kendiliğinden kapanacaktır.",
        reopenLink: "Onay Sayfasını Yeniden Aç ↗",
        provider: "Sağlayıcı",
        accountLabel: "Hesap Adı / Etiket",
        accountLabelPlaceholder: "Örn: Kişisel Pro, İş Hesabı",
        accountAccent: "Kart Vurgu Rengi",
        cardAccent: "Kart Vurgusu",
        accentDefault: "Varsayılan (Tema Rengi)",
        credentialType: "Kimlik Türü",
        apiKey: "API Anahtarı",
        oauthToken: "OAuth Access Token",
        secretLabel: "Secret / Token",
        themeAccent: "Vurgu Rengi",
        close: "Kapat",
        groupSelect: "Gruplama",
        groupNone: "Gruplama Yok",
        groupProvider: "Sağlayıcıya Göre",
        editDisabledGrouped: "Gruplama etkinken düzenleme modu kullanılamaz",
        sortCustom: "Özel Sıralama",
        sortDateAdded: "Eklenme Tarihi",
        sortHighest: "En Yüksek Kalan",
        sortLowest: "En Düşük Kalan",
        ompSectionTitle: "OMP (Oh My Pi) Entegrasyonu",
        ompSectionDesc: "OMP veritabanındaki (agent.db) tüm aktif AI hesaplarını (Antigravity, Codex, Cursor, Copilot, Grok, ZAI) tek tıkla içeri aktarın.",
        syncOmpBtn: "OMP Hesaplarını Eşitle",
        syncing: "Eşitleniyor...",
        syncSuccess: "Eşitleme Tamamlandı",
        accountsImported: "hesap aktarıldı",
        syncStatusJustNow: "Son kontrol: az önce",
        syncStatusSec: "Son kontrol: {n} sn önce",
        syncStatusMin: "Son kontrol: {n} dk önce",
        pollingError: "Sorgulama Hatası",
        authError: "Yetkilendirme Hatası (Token Geçersiz)",
        rateLimitError: "İstek Hız Sınırı Aşıldı",
        networkError: "Bağlantı Hatası"
      },
      en: {
        flag: "🇬🇧",
        title: "AI Usage Tracker",
        subtitle: "Multi-Provider Quota & Balance Hub",
        refresh: "Refresh",
        addAccountText: "Connect Account",
        summaryActive: "Active Accounts:",
        summaryBalance: "Total Prepaid Balance:",
        summaryExhausted: "Exhausted Quotas:",
        autoSync: "Auto-refresh:",
        editModeActive: "✏️ Edit Mode Active",
        editModeTitle: "Card Edit Mode",
        settingsTitle: "Settings",
        themeTitle: "Dark / Light Mode",
        deleteAccount: "Remove Account",
        editLabel: "Edit Label",
        save: "Save",
        cancel: "Cancel",
        noAccounts: "No AI accounts connected yet. Click <b>+ Connect Account</b> to add one.",
        lastUpdate: "Updated",
        deleteConfirm: "Are you sure you want to remove this account?",
        resetsIn: "Resets in",
        rightsAvailable: "Available",
        modalTitle: "Connect AI Account",
        modalSubtitle: "Track quotas and credits via OAuth or direct API key.",
        tabOAuth: "Login with OAuth",
        tabManual: "Manual API Key",
        oauthDesc: "Redirect to official authorization. Tokens are encrypted locally via AES-256-GCM.",
        googleTitle: "Antigravity (Google AI Pro)",
        googleDesc: "Gemini and Claude & GPT shared quota pools",
        codexTitle: "OpenAI ChatGPT / Codex",
        codexDesc: "Plus / Pro 5-hour rolling & weekly quotas",
        claudeTitle: "Anthropic Claude Pro/Max",
        claudeDesc: "5h session and weekly Opus/Sonnet quotas",
        loginBtn: "Login →",
        deviceWait: "Waiting for OpenAI Approval:",
        deviceDesc: "Enter the code on the OpenAI confirmation page. The dashboard will automatically update.",
        reopenLink: "Re-open Authorization Page ↗",
        provider: "Provider",
        accountLabel: "Account Label",
        accountLabelPlaceholder: "e.g. Personal Pro, Work Key",
        accountAccent: "Card Accent Color",
        cardAccent: "Card Accent",
        accentDefault: "Default (Theme Color)",
        credentialType: "Credential Type",
        apiKey: "API Key",
        oauthToken: "OAuth Access Token",
        secretLabel: "Secret / Token",
        themeAccent: "Accent Color",
        close: "Close",
        groupSelect: "Grouping",
        groupNone: "No Grouping",
        groupProvider: "By Provider",
        editDisabledGrouped: "Edit mode is disabled while grouped",
        sortCustom: "Custom (Drag & Drop)",
        sortDateAdded: "Date Added",
        sortHighest: "Highest Available",
        sortLowest: "Lowest Available",
        ompSectionTitle: "OMP (Oh My Pi) Integration",
        ompSectionDesc: "Import all active AI accounts from OMP database (agent.db) in one click.",
        syncOmpBtn: "Sync Accounts from OMP",
        syncing: "Syncing...",
        syncSuccess: "Sync Complete",
        accountsImported: "account(s) imported",
        syncStatusJustNow: "Last checked: just now",
        syncStatusSec: "Last checked: {n}s ago",
        syncStatusMin: "Last checked: {n}m ago",
        pollingError: "Polling Error",
        authError: "Authentication Error (Token Invalid)",
        rateLimitError: "Rate Limit Exceeded",
        networkError: "Connection Error"
      }
    };

    function detectInitialLang() {
      const saved = localStorage.getItem('usage_lang');
      if (saved === 'tr' || saved === 'en') return saved;
      const browserLang = (navigator.language || navigator.userLanguage || '').toLowerCase();
      return browserLang.startsWith('tr') ? 'tr' : 'en';
    }

    let currentLang = detectInitialLang();
    let currentMode = localStorage.getItem('usage_mode') || 'dark';
    let currentAccent = localStorage.getItem('usage_accent') || 'amber';
    let currentSort = localStorage.getItem('usage_sort') || 'custom';
    let currentGroup = localStorage.getItem('usage_group') || 'none';
    let isEditMode = false;
    let editingCardId = null;
    let draggedCardId = null;
    let cachedReports = ${initialJson};
    let lastPolledAt = Date.now();

    function t(key) {
      return (I18N[currentLang] && I18N[currentLang][key]) || (I18N['tr'][key]) || key;
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function formatProviderTitle(provider) {
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

    function sanitizeErrorMessage(msg) {
      if (!msg) return '';
      let clean = String(msg);
      clean = clean.replace(/ya29\.[a-zA-Z0-9_-]+/g, '[REDACTED_TOKEN]');
      clean = clean.replace(/sk-[a-zA-Z0-9_-]+/g, '[REDACTED_KEY]');
      clean = clean.replace(/gho_[a-zA-Z0-9_]+/g, '[REDACTED_TOKEN]');
      clean = clean.replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, 'Bearer [REDACTED]');
      clean = clean.replace(/[a-f0-9]{32,64}/gi, '[REDACTED_HASH]');
      return clean;
    }

    function getLocalizedReportError(report) {
      const err = report.error || (report.status === 'error' ? (report.statusMessage || report.message || 'Error') : null);
      if (!err) return null;
      const raw = sanitizeErrorMessage(err);
      const lower = raw.toLowerCase();
      if (lower.includes('rate limit') || lower.includes('429')) {
        return t('rateLimitError');
      }
      if (lower.includes('unauthorized') || lower.includes('401') || lower.includes('invalid_grant') || lower.includes('token expired') || lower.includes('auth')) {
        return t('authError');
      }
      if (lower.includes('fetch') || lower.includes('network') || lower.includes('econnrefused') || lower.includes('timeout')) {
        return t('networkError');
      }
      return t('pollingError') + ': ' + raw.slice(0, 60);
    }

    function translateLimitLabel(label, id) {
      const str = String(label || id || '');
      if (currentLang === 'tr') {
        const trMap = {
          'gemini_5h': 'Gemini: 5 Saatlik Limit',
          'gemini_weekly': 'Gemini: Haftalık Limit',
          'claude_gpt_5h': 'Claude & GPT: 5 Saatlik Limit',
          'claude_gpt_weekly': 'Claude & GPT: Haftalık Limit',
          'primary_window': '5 Saatlik Kayan Kota',
          'secondary_window': 'Haftalık Kota',
          'reset_credits': 'Kota Sıfırlama Hakkı (Usage Reset)',
          'account_balance': 'Hesap Net Bakiyesi',
          'key_usage': 'API Anahtar Harcaması',
          'rate_limit': 'İstek Hız Sınırı',
          'balance_usd': 'Kullanılabilir Bakiye (USD)',
          '5h': '5 Saatlik Kayan Kota',
          '7d': 'Haftalık Genel Kota'
        };
        return trMap[id] || str;
      }

      const enMap = {
        'gemini_5h': 'Gemini: 5-Hour Limit',
        'gemini_weekly': 'Gemini: Weekly Limit',
        'claude_gpt_5h': 'Claude & GPT: 5-Hour Limit',
        'claude_gpt_weekly': 'Claude & GPT: Weekly Limit',
        'primary_window': '5-Hour Rolling Quota',
        'secondary_window': 'Weekly Quota',
        'reset_credits': 'Usage Reset Rights',
        'account_balance': 'Account Net Balance',
        'key_usage': 'API Key Usage',
        'rate_limit': 'Rate Limit',
        'balance_usd': 'Available Balance (USD)',
        '5h': '5-Hour Rolling Quota',
        '7d': 'Weekly Quota'
      };
      if (enMap[id]) return enMap[id];

      return str
        .replaceAll('5 Saatlik Kayan Kota', '5-Hour Rolling Quota')
        .replaceAll('Haftalık / Uzun Dönem Kotası', 'Weekly Quota')
        .replaceAll('Haftalık Kota', 'Weekly Quota')
        .replaceAll('Kayan Kota', 'Rolling Quota')
        .replaceAll('Kota Sıfırlama Hakkı (Usage Reset)', 'Usage Reset Rights')
        .replaceAll('Hesap Net Bakiyesi', 'Account Net Balance')
        .replaceAll('Kullanılabilir Bakiye', 'Available Balance')
        .replaceAll('İstek Hız Sınırı', 'Rate Limit');
    }

    function translateNote(note) {
      const str = String(note || '');
      if (currentLang === 'tr') return str;
      return str
        .replaceAll('Son Geçerlilik:', 'Expires:')
        .replaceAll('Toplam Yüklenen:', 'Total Loaded:')
        .replaceAll('Toplam Harcanan:', 'Total Spent:')
        .replaceAll('Nakit Yüklenen:', 'Topped Up:')
        .replaceAll('Hediye/Promosyon:', 'Granted/Promo:')
        .replaceAll('Hesap kullanım dışı', 'Account inactive')
        .replaceAll('Hesap aktif', 'Account active')
        .replaceAll('Aralık:', 'Interval:')
        .replaceAll('adet kullanılabilir reset hakkı', 'available reset credit(s)');
    }

    function applyLightDarkMode(mode) {
      currentMode = mode;
      localStorage.setItem('usage_mode', mode);
      const isDark = mode === 'dark';
      document.documentElement.classList.toggle('dark', isDark);
      document.documentElement.classList.toggle('light', !isDark);
      const icon = document.getElementById('lightDarkIcon');
      if (icon) icon.innerText = isDark ? '☀️' : '🌙';
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

      Object.keys(THEME_ACCENTS).forEach(k => {
        const btn = document.getElementById('themeOpt_' + k);
        if (btn) {
          btn.style.borderColor = k === accentKey ? 'var(--color-accent)' : 'var(--color-border)';
        }
      });
    }

    function changeTheme(accentKey) {
      applyAccent(accentKey);
    }

    function updateSyncStatus() {
      const statusEl = document.getElementById('headerSyncStatus');
      const dotEl = document.getElementById('syncLiveDot');
      if (!statusEl) return;
      const elapsedSec = Math.max(0, Math.floor((Date.now() - lastPolledAt) / 1000));
      let text = '';
      if (elapsedSec < 5) {
        text = t('syncStatusJustNow');
      } else if (elapsedSec < 60) {
        text = t('syncStatusSec').replace('{n}', elapsedSec);
      } else {
        const min = Math.floor(elapsedSec / 60);
        text = t('syncStatusMin').replace('{n}', min);
      }
      statusEl.innerText = text;
      if (dotEl) dotEl.title = text;
    }

    function updateEditButtonState() {
      const btn = document.getElementById('editModeBtn');
      if (!btn) return;
      if (currentGroup !== 'none') {
        btn.disabled = true;
        btn.classList.add('opacity-40', 'cursor-not-allowed');
        btn.title = t('editDisabledGrouped');
      } else {
        btn.disabled = false;
        btn.classList.remove('opacity-40', 'cursor-not-allowed');
        btn.title = t('editModeTitle');
      }
    }

    function applyI18n() {
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (key && key !== 'loading') {
          el.innerHTML = t(key);
        }
      });
      document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (key) el.title = t(key);
      });
      document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (key) el.placeholder = t(key);
      });
      const flagEl = document.getElementById('langFlag');
      if (flagEl && I18N[currentLang]) flagEl.innerText = I18N[currentLang].flag;
      const labelEl = document.getElementById('langLabel');
      if (labelEl) labelEl.innerText = currentLang.toUpperCase();
      const accInput = document.getElementById('accountLabel');
      if (accInput) accInput.placeholder = t('accountLabelPlaceholder');
      updateSyncStatus();
      updateEditButtonState();
      if (cachedReports.length) renderCards(cachedReports);
    }

    function toggleLang() {
      currentLang = currentLang === 'tr' ? 'en' : 'tr';
      localStorage.setItem('usage_lang', currentLang);
      applyI18n();
    }

    // Modal controls
    function openModal() {
      document.getElementById('modal').classList.remove('hidden');
      document.getElementById('modal').classList.add('flex');
      updateSecretHelp();
    }
    function closeModal() {
      document.getElementById('modal').classList.add('hidden');
      document.getElementById('modal').classList.remove('flex');
      document.getElementById('codexDevicePanel').classList.add('hidden');
    }

    function updateSecretHelp(provider) {
      const p = provider || (document.getElementById('providerSelect') ? document.getElementById('providerSelect').value : 'antigravity');
      const input = document.getElementById('secretValue');
      const help = document.getElementById('secretHelpText');
      const typeSelect = document.getElementById('credentialType');

      const hints = {
        'antigravity': {
          placeholder: 'ya29... veya OAuth Token',
          help: currentLang === 'tr' ? 'Google OAuth Access Token veya Refresh Token' : 'Google OAuth Access Token or Refresh Token',
          type: 'oauth'
        },
        'openai-codex': {
          placeholder: 'OpenAI Access Token (eyJ...)',
          help: currentLang === 'tr' ? 'OpenAI Bearer Access Token' : 'OpenAI Bearer Access Token',
          type: 'oauth'
        },
        'github-copilot': {
          placeholder: 'gho_... veya GitHub Personal Token',
          help: currentLang === 'tr' ? 'GitHub Copilot yetkili erişim tokenı' : 'GitHub Copilot authorization token',
          type: 'oauth'
        },
        'cursor': {
          placeholder: 'Cursor Access Token veya WorkosCursorSessionToken',
          help: currentLang === 'tr' ? 'Cursor oturum tokenı veya çerezi' : 'Cursor session token or cookie',
          type: 'oauth'
        },
        'anthropic': {
          placeholder: 'sk-ant-... veya OAuth Token',
          help: currentLang === 'tr' ? 'Anthropic API Anahtarı veya Claude Code Tokenı' : 'Anthropic API Key or Claude Code Token',
          type: 'oauth'
        },
        'openrouter': {
          placeholder: 'sk-or-v1-...',
          help: currentLang === 'tr' ? 'OpenRouter API Anahtarı' : 'OpenRouter API Key',
          type: 'api_key'
        },
        'deepseek': {
          placeholder: 'sk-...',
          help: currentLang === 'tr' ? 'DeepSeek Platform API Anahtarı' : 'DeepSeek Platform API Key',
          type: 'api_key'
        },
        'xai-oauth': {
          placeholder: 'xAI Access Token',
          help: currentLang === 'tr' ? 'xAI Grok CLI OAuth Tokenı' : 'xAI Grok CLI OAuth Token',
          type: 'oauth'
        },
        'zai': {
          placeholder: 'Zhipu API Key veya Token',
          help: currentLang === 'tr' ? 'Zhipu AI / GLM erişim anahtarı' : 'Zhipu AI / GLM access key or token',
          type: 'oauth'
        },
        'minimax-code': {
          placeholder: 'MiniMax API Key veya Token',
          help: currentLang === 'tr' ? 'MiniMax Code token plan erişim anahtarı' : 'MiniMax Code token-plan access key',
          type: 'api_key'
        },
        'cline-pass': {
          placeholder: 'ClinePass API Key',
          help: currentLang === 'tr' ? 'Cline kullanım kotası API anahtarı' : 'Cline usage quota API key',
          type: 'api_key'
        },
        'devin': {
          placeholder: 'Devin Session Token',
          help: currentLang === 'tr' ? 'Devin oturum tokenı' : 'Devin session token',
          type: 'oauth'
        },
        'umans': {
          placeholder: 'Umans API Key',
          help: currentLang === 'tr' ? 'Umans Code kullanım API anahtarı' : 'Umans Code usage API key',
          type: 'api_key'
        },
        'google-gemini-cli': {
          placeholder: 'Google OAuth Access Token',
          help: currentLang === 'tr' ? 'Gemini CLI OAuth erişim tokenı' : 'Gemini CLI OAuth access token',
          type: 'oauth'
        },
        'kimi-code': {
          placeholder: 'Kimi Code OAuth Token',
          help: currentLang === 'tr' ? 'Kimi Code abonelik OAuth tokenı; standart Moonshot API key kabul edilmez' : 'Kimi Code subscription OAuth token; standard Moonshot API keys are not accepted',
          type: 'oauth'
        },
        'opencode-go': {
          placeholder: 'OpenCode Go API Key',
          help: currentLang === 'tr' ? 'Aktif OpenCode Go aboneliği API anahtarı' : 'API key for an active OpenCode Go subscription',
          type: 'api_key'
        },
        'alibaba-token-plan': {
          placeholder: 'Alibaba Token Plan Key / Cookie',
          help: currentLang === 'tr' ? 'Bailian/Qwen token plan anahtarı veya konsol oturumu' : 'Bailian/Qwen token-plan key or console session',
          type: 'api_key'
        }
      };
      const h = hints[p] || {
        placeholder: 'Secret veya API Anahtarı',
        help: currentLang === 'tr' ? 'Sağlayıcı erişim anahtarı' : 'Provider access credential',
        type: 'api_key'
      };
      if (input) input.placeholder = h.placeholder;
      if (help) help.innerText = h.help;
      if (typeSelect) typeSelect.value = h.type;
    }

    function openSettingsModal() { document.getElementById('settingsModal').classList.remove('hidden'); document.getElementById('settingsModal').classList.add('flex'); }
    function closeSettingsModal() { document.getElementById('settingsModal').classList.add('hidden'); document.getElementById('settingsModal').classList.remove('flex'); }

    async function syncFromOmp() {
      const btnText = document.getElementById('syncOmpBtnText');
      if (btnText) btnText.innerText = t('syncing');
      try {
        const res = await fetch('/api/omp/sync', { method: 'POST' });
        const json = await res.json();
        if (json.success) {
          alert(t('syncSuccess') + ': ' + (json.total || 0) + ' ' + t('accountsImported'));
          closeSettingsModal();
          await pollNow();
        } else {
          alert('OMP Sync Error: ' + (json.error || 'Failed'));
        }
      } catch (err) {
        alert('OMP Sync Error: ' + err);
      } finally {
        if (btnText) btnText.innerText = t('syncOmpBtn');
      }
    }

    function toggleEditMode() {
      if (currentGroup !== 'none') return;
      isEditMode = !isEditMode;
      editingCardId = null;
      const btn = document.getElementById('editModeBtn');
      const notice = document.getElementById('editModeNotice');
      if (btn) {
        btn.classList.toggle('bg-appAccent', isEditMode);
        btn.classList.toggle('text-zinc-950', isEditMode);
        btn.classList.toggle('bg-appSurface', !isEditMode);
        btn.classList.toggle('text-appTextMuted', !isEditMode);
      }
      if (notice) {
        notice.classList.toggle('hidden', !isEditMode);
      }
      renderCards(cachedReports);
    }

    function changeGroup(groupKey) {
      currentGroup = groupKey === 'provider' ? 'provider' : 'none';
      localStorage.setItem('usage_group', currentGroup);
      const select = document.getElementById('groupSelect');
      if (select) select.value = currentGroup;
      if (currentGroup !== 'none' && isEditMode) {
        isEditMode = false;
        editingCardId = null;
      }
      updateEditButtonState();
      renderCards(cachedReports);
    }

    function changeSort(sortKey) {
      const allowed = ['custom', 'date_added', 'highest_available', 'lowest_available'];
      currentSort = allowed.includes(sortKey) ? sortKey : 'custom';
      localStorage.setItem('usage_sort', currentSort);
      const select = document.getElementById('sortSelect');
      if (select) select.value = currentSort;
      renderCards(cachedReports);
    }

    function switchTab(tab) {
      const isOAuth = tab === 'oauth';
      document.getElementById('oauthSection').classList.toggle('hidden', !isOAuth);
      document.getElementById('manualSection').classList.toggle('hidden', isOAuth);

      document.getElementById('tabOAuth').className = isOAuth
        ? 'flex-1 py-2 font-semibold rounded-lg bg-appSurface text-appText shadow-sm transition'
        : 'flex-1 py-2 font-semibold rounded-lg text-appTextMuted hover:text-appText transition';

      document.getElementById('tabManual').className = !isOAuth
        ? 'flex-1 py-2 font-semibold rounded-lg bg-appSurface text-appText shadow-sm transition'
        : 'flex-1 py-2 font-semibold rounded-lg text-appTextMuted hover:text-appText transition';
    }

    async function loadUsage() {
      try {
        const [dataRes, credsRes] = await Promise.all([
          fetch('/api/data'),
          fetch('/api/credentials').catch(() => null)
        ]);
        if (dataRes.ok) {
          const dataJson = await dataRes.json();
          let reports = dataJson.data || [];
          if (credsRes && credsRes.ok) {
            try {
              const credsJson = await credsRes.json();
              const credsList = credsJson.data || [];
              const credsMap = {};
              credsList.forEach(c => { credsMap[c.id] = c; });
              reports = reports.map(r => {
                const cr = r.credentialId ? credsMap[r.credentialId] : null;
                return {
                  ...r,
                  createdAt: r.createdAt || (cr ? cr.createdAt : undefined),
                  accent: r.accent || (cr ? cr.accent : undefined)
                };
              });
            } catch {}
          }
          cachedReports = reports;
          lastPolledAt = Date.now();
          updateSyncStatus();
          updateSummary(cachedReports);
          renderCards(cachedReports);
        }
      } catch (err) {
        console.warn('Silent live sync failure:', err);
      }
    }

    function updateSummary(reports) {
      if (!Array.isArray(reports)) return;
      const countEl = document.getElementById('statActiveCount');
      if (countEl) countEl.innerText = reports.length;
      let totalBal = 0;
      let exhausted = 0;

      reports.forEach(r => {
        if (!r) return;
        (r.limits || []).forEach(l => {
          if (!l || !l.amount) return;
          if (l.amount.unit === 'usd' && typeof l.amount.remaining === 'number') {
            const id = String(l.id || '');
            if (id.includes('balance') || id.includes('credits')) totalBal += l.amount.remaining;
          }
          if (l.status === 'exhausted') exhausted++;
        });
      });

      const balEl = document.getElementById('statTotalBalance');
      if (balEl) balEl.innerText = '$' + totalBal.toFixed(2);
      const exhEl = document.getElementById('statExhaustedCount');
      if (exhEl) exhEl.innerText = exhausted;
    }

    async function pollNow() {
      const spinner = document.getElementById('pollSpinner');
      if (spinner) spinner.classList.remove('hidden');
      try {
        await fetch('/api/poll', { method: 'POST' });
        await loadUsage();
      } finally {
        if (spinner) spinner.classList.add('hidden');
      }
    }

    // OAuth handlers
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
        secret: document.getElementById('secretValue').value,
        accent: document.getElementById('accountAccentSelect').value || null
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

    function startEditingLabel(cardKey) {
      editingCardId = cardKey;
      renderCards(cachedReports);
      const input = document.getElementById('editLabelInput_' + cardKey);
      if (input) {
        input.focus();
        input.select();
      }
    }

    function cancelEditingLabel() {
      editingCardId = null;
      renderCards(cachedReports);
    }

    async function saveAccountLabel(cardKey, newLabel) {
      const trimmed = (newLabel || '').trim();
      if (!cardKey || !trimmed) {
        editingCardId = null;
        renderCards(cachedReports);
        return;
      }
      try {
        const res = await fetch('/api/credentials/' + encodeURIComponent(cardKey), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accountLabel: trimmed })
        });
        const json = await res.json();
        if (json.success) {
          const rep = cachedReports.find(r => (r.credentialId || r.provider) === cardKey);
          if (rep) rep.accountLabel = trimmed;
        }
      } catch (err) {
        console.error('Failed to update account label:', err);
      } finally {
        editingCardId = null;
        renderCards(cachedReports);
      }
    }

    async function saveAccountAccent(cardKey, accentKey) {
      if (!cardKey) return;
      try {
        const res = await fetch('/api/credentials/' + encodeURIComponent(cardKey), {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accent: accentKey })
        });
        const json = await res.json();
        if (json.success) {
          const rep = cachedReports.find(r => (r.credentialId || r.provider) === cardKey);
          if (rep) rep.accent = accentKey;
        }
      } catch (err) {
        console.error('Failed to update account accent:', err);
      } finally {
        renderCards(cachedReports);
      }
    }

    // Drag & Drop handlers
    function handleDragStart(e, id) {
      if (!isEditMode || currentGroup !== 'none' || currentSort !== 'custom') return;
      draggedCardId = id;
      e.dataTransfer.effectAllowed = 'move';
      e.currentTarget.classList.add('opacity-40');
    }

    function handleDragOver(e) {
      if (!isEditMode || currentGroup !== 'none' || currentSort !== 'custom') return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      e.currentTarget.classList.add('drag-over');
    }

    function handleDragLeave(e) {
      e.currentTarget.classList.remove('drag-over');
    }

    function handleDrop(e, targetId) {
      e.preventDefault();
      e.currentTarget.classList.remove('drag-over');
      if (!isEditMode || currentGroup !== 'none' || currentSort !== 'custom' || !draggedCardId || draggedCardId === targetId) return;

      const fromIdx = cachedReports.findIndex(r => (r.credentialId || r.provider) === draggedCardId);
      const toIdx = cachedReports.findIndex(r => (r.credentialId || r.provider) === targetId);
      if (fromIdx === -1 || toIdx === -1) return;

      const [moved] = cachedReports.splice(fromIdx, 1);
      cachedReports.splice(toIdx, 0, moved);

      const customOrder = cachedReports.map(r => r.credentialId || r.provider);
      localStorage.setItem('usage_custom_order', JSON.stringify(customOrder));

      currentSort = 'custom';
      localStorage.setItem('usage_sort', 'custom');
      const sortSelect = document.getElementById('sortSelect');
      if (sortSelect) sortSelect.value = 'custom';

      renderCards(cachedReports);
    }

    function handleDragEnd(e) {
      draggedCardId = null;
      document.querySelectorAll('#cardsGrid > div').forEach(el => {
        el.classList.remove('opacity-40', 'drag-over');
      });
    }

    function getReportScore(report) {
      let score = 0;
      for (const l of report.limits || []) {
        if (l.amount?.unit === 'usd' && typeof l.amount.remaining === 'number') {
          return l.amount.remaining * 10;
        }
        if (l.amount?.unit === 'percent' && typeof l.amount.remaining === 'number') {
          return l.amount.remaining;
        }
      }
      return score;
    }

    function sortReports(reports, sortKey) {
      const list = [...reports];
      if (sortKey === 'custom') {
        const saved = localStorage.getItem('usage_custom_order');
        if (saved) {
          try {
            const order = JSON.parse(saved);
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
          } catch {}
        }
      } else if (sortKey === 'date_added') {
        const hasValidCreatedAt = list.some(r => typeof r.createdAt === 'number' && r.createdAt > 0);
        if (hasValidCreatedAt) {
          list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
        }
        return list;
      } else if (sortKey === 'highest_available') {
        list.sort((a, b) => getReportScore(b) - getReportScore(a));
      } else if (sortKey === 'lowest_available') {
        list.sort((a, b) => getReportScore(a) - getReportScore(b));
      }
      return list;
    }

    function renderCardHtml(r) {
      const cardKey = r.credentialId || r.provider;
      const cleanLabel = (r.accountLabel || 'Default').replace(/^Google \((.*)\)$/, '$1');
      const providerTitle = formatProviderTitle(r.provider);
      const cardAccent = r.accent || '';

      const canDrag = isEditMode && currentGroup === 'none' && currentSort === 'custom';
      const dragAttrs = canDrag
        ? ' draggable="true" ondragstart="handleDragStart(event, this.dataset.cardId)" ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" ondrop="handleDrop(event, this.dataset.cardId)" ondragend="handleDragEnd(event)"'
        : '';

      const editBorderClass = isEditMode
        ? ' border-dashed border-appAccent/50 cursor-grab active:cursor-grabbing hover:border-appAccent'
        : ' border-appBorder hover:border-zinc-700';

      const errorMsg = getLocalizedReportError(r);
      const errorHtml = errorMsg ? (
        '<div class="bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs px-3 py-2 rounded-xl flex items-center gap-2">' +
        '  <svg class="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
        '  <span class="truncate">' + escapeHtml(errorMsg) + '</span>' +
        '</div>'
      ) : '';

      const limitsHtml = (r.limits || []).map(l => {
        let valueHtml = '';
        let barHtml = '';

        if (l.amount.unit === 'percent') {
          const used = l.amount.used || 0;
          const barColor = used >= 90 ? 'bg-rose-500' : used >= 75 ? 'bg-amber-500' : 'bg-emerald-500';
          valueHtml = '<span class="font-bold text-sm text-appText">' + used.toFixed(1) + '%</span>';
          barHtml = '<div class="w-full bg-appBorder h-1.5 rounded-full overflow-hidden mt-2"><div class="' + barColor + ' h-full transition-all duration-300" style="width: ' + Math.min(100, used) + '%"></div></div>';
        } else if (l.amount.unit === 'usd') {
          const rem = l.amount.remaining ?? 0;
          valueHtml = '<span class="font-bold text-sm text-emerald-500">$' + rem.toFixed(2) + '</span>';
        } else if (l.amount.unit === 'credits') {
          const rem = l.amount.remaining ?? 0;
          const labelText = currentLang === 'tr' ? (rem + ' Hak Mevcut') : (rem + ' Available');
          valueHtml = '<span class="account-card-accent-badge font-semibold text-xs px-2.5 py-0.5 rounded-md">' + labelText + '</span>';
        }

        let countdownHtml = '';
        if (l.window && l.window.resetsAt) {
          const diffMin = Math.max(0, Math.round((l.window.resetsAt - Date.now()) / 60000));
          const hours = Math.floor(diffMin / 60);
          const mins = diffMin % 60;
          const timeLabel = currentLang === 'tr'
            ? (hours > 0 ? (hours + 'sa ' + mins + 'dk') : (mins + 'dk'))
            : (hours > 0 ? (hours + 'h ' + mins + 'm') : (mins + 'm'));
          countdownHtml = '<span class="text-xs text-appTextMuted flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-appTextMuted/70"></span>' + t('resetsIn') + ': ' + timeLabel + '</span>';
        }

        const cleanLabel = translateLimitLabel(l.label, l.id);
        const cleanNotes = (l.notes || []).filter(n => !String(n).toLowerCase().includes('model'));
        const notesHtml = cleanNotes.map(n => '<span class="text-xs text-appTextMuted block mt-0.5">' + translateNote(n) + '</span>').join('');

        return '<div class="bg-appMuted/40 border border-appBorder rounded-xl p-3.5 space-y-1.5">' +
               '  <div class="flex justify-between items-center">' +
               '    <span class="text-sm font-semibold text-appText tracking-tight">' + cleanLabel + '</span>' +
               '    ' + valueHtml +
               '  </div>' +
               barHtml +
               '  <div class="flex justify-between items-center pt-1">' +
               countdownHtml +
               '  </div>' +
               notesHtml +
               '</div>';
      }).join('');

      let labelDisplayHtml = '';
      if (isEditMode) {
        if (editingCardId === cardKey) {
          labelDisplayHtml =
            '<div class="flex items-center gap-1.5 mt-1" draggable="false" onmousedown="event.stopPropagation()">' +
            '  <input type="text" id="editLabelInput_' + cardKey + '" data-key="' + cardKey + '" value="' + escapeHtml(cleanLabel) + '" class="text-xs px-2.5 py-1 bg-appMuted border border-appAccent rounded-md text-appText outline-none w-36" onkeydown="if(event.key===&quot;Enter&quot;)saveAccountLabel(this.dataset.key, this.value); if(event.key===&quot;Escape&quot;)cancelEditingLabel();" />' +
            '  <button type="button" data-key="' + cardKey + '" onclick="saveAccountLabel(this.dataset.key, document.getElementById(&quot;editLabelInput_&quot; + this.dataset.key).value)" class="px-2 py-1 text-xs bg-appAccent text-zinc-950 font-semibold rounded-md hover:bg-appAccentHover" data-i18n-title="save">✓</button>' +
            '  <button type="button" onclick="cancelEditingLabel()" class="px-2 py-1 text-xs bg-appMuted text-appTextMuted rounded-md hover:text-appText" data-i18n-title="cancel">✕</button>' +
            '</div>';
        } else {
          labelDisplayHtml =
            '<div class="flex items-center gap-2 mt-1" draggable="false" onmousedown="event.stopPropagation()">' +
            '  <span class="text-xs font-semibold px-2.5 py-0.5 rounded-md bg-appMuted text-appTextMuted border border-appBorder">' + escapeHtml(cleanLabel) + '</span>' +
            '  <button type="button" data-key="' + cardKey + '" onclick="startEditingLabel(this.dataset.key)" class="text-[11px] font-medium text-appAccent hover:underline flex items-center gap-1">' +
            '    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>' +
            '    <span>' + t('editLabel') + '</span>' +
            '  </button>' +
            '</div>';
        }
      } else {
        labelDisplayHtml = '<span class="text-xs font-semibold px-2.5 py-0.5 rounded-md bg-appMuted text-appTextMuted border border-appBorder">' + escapeHtml(cleanLabel) + '</span>';
      }

      let editAccentHtml = '';
      if (isEditMode) {
        const a = r.accent || '';
        editAccentHtml =
          '<div class="pt-2 border-t border-appBorder/50 flex items-center justify-between text-xs" draggable="false" onmousedown="event.stopPropagation()">' +
          '  <span class="text-[11px] font-semibold text-appTextMuted">' + t('cardAccent') + ':</span>' +
          '  <div class="flex items-center gap-1.5">' +
          '    <button type="button" data-key="' + cardKey + '" onclick="saveAccountAccent(this.dataset.key, null)" title="' + t('accentDefault') + '" class="w-4 h-4 rounded-full border border-appBorder bg-transparent relative flex items-center justify-center ' + (!a ? 'ring-2 ring-appAccent' : '') + '"><span class="w-1.5 h-1.5 rounded-full bg-appTextMuted/40"></span></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="amber" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Amber" class="w-4 h-4 rounded-full bg-[#ff9849] ' + (a === 'amber' ? 'ring-2 ring-white' : '') + '"></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="emerald" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Emerald" class="w-4 h-4 rounded-full bg-[#10b981] ' + (a === 'emerald' ? 'ring-2 ring-white' : '') + '"></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="cyan" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Cyan" class="w-4 h-4 rounded-full bg-[#06b6d4] ' + (a === 'cyan' ? 'ring-2 ring-white' : '') + '"></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="violet" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Violet" class="w-4 h-4 rounded-full bg-[#a855f7] ' + (a === 'violet' ? 'ring-2 ring-white' : '') + '"></button>' +
          '    <button type="button" data-key="' + cardKey + '" data-accent="slate" onclick="saveAccountAccent(this.dataset.key, this.dataset.accent)" title="Slate" class="w-4 h-4 rounded-full bg-[#38bdf8] ' + (a === 'slate' ? 'ring-2 ring-white' : '') + '"></button>' +
          '  </div>' +
          '</div>';
      }

      return '<div data-card-id="' + cardKey + '" data-accent="' + cardAccent + '" class="account-card bg-appSurface border ' + editBorderClass + ' rounded-2xl p-5 space-y-4 transition-all shadow-sm relative"' + dragAttrs + '>' +
             '  <div class="flex justify-between items-start">' +
             '    <div>' +
             '      <div class="flex items-center gap-2.5 flex-wrap">' +
             '        <h2 class="font-bold text-appText text-base tracking-tight">' + providerTitle + '</h2>' +
             (!isEditMode ? labelDisplayHtml : '') +
             '      </div>' +
             (isEditMode ? labelDisplayHtml : '') +
             '      <span class="text-xs text-appTextMuted block mt-1.5">' + t('lastUpdate') + ': ' + new Date(r.fetchedAt).toLocaleTimeString() + '</span>' +
             '    </div>' +
             '    <button data-id="' + (r.credentialId || '') + '" onclick="deleteAccount(this.dataset.id)" title="' + t('deleteAccount') + '" data-i18n-title="deleteAccount" class="text-appTextMuted hover:text-rose-500 text-sm p-1.5 rounded-lg hover:bg-appMuted transition">✕</button>' +
             '  </div>' +
             errorHtml +
             '  <div class="space-y-2.5">' + limitsHtml + '</div>' +
             editAccentHtml +
             '</div>';
    }

    function renderCards(reports) {
      const container = document.getElementById('cardsGrid');
      if (!container) return;
      if (!reports.length) {
        container.innerHTML = '<div class="col-span-full py-24 text-center text-appTextMuted text-sm">' + t('noAccounts') + '</div>';
        return;
      }

      const sortedList = sortReports(reports, currentSort);

      if (currentGroup === 'provider') {
        const groups = {};
        sortedList.forEach(r => {
          const p = r.provider || 'other';
          if (!groups[p]) groups[p] = [];
          groups[p].push(r);
        });

        let html = '';
        Object.keys(groups).sort().forEach(p => {
          const groupReports = groups[p];
          const providerTitle = formatProviderTitle(p);
          html +=
            '<div class="col-span-full pt-4 first:pt-0 pb-1.5 border-b border-appBorder flex items-center justify-between">' +
            '  <div class="flex items-center gap-2">' +
            '    <span class="font-bold text-sm text-appText tracking-tight">' + providerTitle + '</span>' +
            '    <span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-appMuted text-appTextMuted border border-appBorder">' + groupReports.length + '</span>' +
            '  </div>' +
            '</div>';
          html += groupReports.map(renderCardHtml).join('');
        });
        container.innerHTML = html;
      } else {
        container.innerHTML = sortedList.map(renderCardHtml).join('');
      }
    }

    async function deleteAccount(id) {
      if (!id || !confirm(t('deleteConfirm'))) return;
      await fetch('/api/credentials/' + id, { method: 'DELETE' });
      await loadUsage();
    }

    // Initialize
    applyLightDarkMode(currentMode);
    applyAccent(currentAccent);
    const sortSelect = document.getElementById('sortSelect');
    if (sortSelect) sortSelect.value = currentSort;
    const groupSelect = document.getElementById('groupSelect');
    if (groupSelect) groupSelect.value = currentGroup;
    applyI18n();
    updateEditButtonState();
    setInterval(loadUsage, 10000);
    setInterval(updateSyncStatus, 1000);
  </script>
</body>
</html>`;
}
