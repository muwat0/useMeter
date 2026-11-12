import type { AlertEvent, ChannelConfig } from "../../types";
import dns from "node:dns/promises";
import fs from "node:fs";
import net from "node:net";

export interface DispatcherOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

function getContainerGateway(): string | null {
  try {
    const route = fs.readFileSync("/proc/net/route", "utf8");
    for (const line of route.split("\n")) {
      const parts = line.trim().split(/\s+/);
      if (parts[1] === "00000000" && parts[2]) {
        const hex = parts[2];
        const o1 = parseInt(hex.slice(6, 8), 16);
        const o2 = parseInt(hex.slice(4, 6), 16);
        const o3 = parseInt(hex.slice(2, 4), 16);
        const o4 = parseInt(hex.slice(0, 2), 16);
        return `${o1}.${o2}.${o3}.${o4}`;
      }
    }
  } catch {}
  return null;
}

export async function resolveDispatcherTarget(rawUrl: string): Promise<{ targetUrl: string; hostHeader?: string }> {
  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname;

    if (net.isIP(hostname)) {
      if ((hostname === "127.0.0.1" || hostname === "::1" || hostname.startsWith("127.")) && (fs.existsSync("/.dockerenv") || process.env["DOCKER_CONTAINER"])) {
        const gw = process.env["HOST_GATEWAY"] || getContainerGateway();
        if (gw) {
          parsed.hostname = gw;
          return { targetUrl: parsed.toString() };
        }
      }
      return { targetUrl: rawUrl };
    }

    const addresses = await dns.lookup(hostname, { all: true }).catch(() => []);
    const isLoopback = addresses.some(a => a.address === "127.0.0.1" || a.address === "::1" || a.address.startsWith("127."));

    if (isLoopback && (fs.existsSync("/.dockerenv") || process.env["DOCKER_CONTAINER"] || process.env["NODE_ENV"] === "production")) {
      const gw = process.env["HOST_GATEWAY"] || getContainerGateway();
      if (gw) {
        parsed.hostname = gw;
        return {
          targetUrl: parsed.toString(),
          hostHeader: hostname,
        };
      }
    }
  } catch {}
  return { targetUrl: rawUrl };
}

export class NotificationDispatcher {
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(options: DispatcherOptions = {}) {
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
  }

  async dispatch(config: ChannelConfig, event: AlertEvent): Promise<{ success: boolean; error?: string }> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);

    try {
      switch (config.channel) {
        case "ntfy":
          return await this.#dispatchNtfy(config, event, controller.signal);
        case "telegram":
          return await this.#dispatchTelegram(config, event, controller.signal);
        case "discord":
          return await this.#dispatchDiscord(config, event, controller.signal);
        case "webhook":
          return await this.#dispatchWebhook(config, event, controller.signal);
        default:
          return { success: false, error: "Unsupported notification channel" };
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, error: msg || "Failed to dispatch notification" };
    } finally {
      clearTimeout(timeout);
    }
  }

  async #dispatchNtfy(config: { url: string; token?: string }, event: AlertEvent, signal: AbortSignal) {
    if (!config.url || !config.url.startsWith("http")) {
      return { success: false, error: "Invalid ntfy URL" };
    }

    let priority = "3"; // default
    let tags = "robot";
    let titlePrefix = "[useMeter]";

    if (event.type === "exhausted") {
      priority = "5"; // max/urgent
      tags = "warning,rotating_light";
      titlePrefix = "[useMeter] QUOTA EXHAUSTED";
    } else if (event.type === "warning") {
      priority = "4"; // high
      tags = "warning";
      titlePrefix = "[useMeter] QUOTA WARNING";
    } else if (event.type === "recovered") {
      priority = "3";
      tags = "white_check_mark,arrows_counterclockwise";
      titlePrefix = "[useMeter] QUOTA RESET";
    } else if (event.type === "test") {
      priority = "3";
      tags = "bell,test_tube";
      titlePrefix = "[useMeter] Test Notification";
    }

    const title = `${titlePrefix}: ${event.accountLabel} (${event.provider})`;
    const body = this.#formatTextBody(event);

    const { targetUrl, hostHeader } = await resolveDispatcherTarget(config.url);
    const headers: Record<string, string> = {
      Title: title,
      Priority: priority,
      Tags: tags,
      "User-Agent": "useMeter/1.0 (+https://usemeter.example.com)",
    };
    if (hostHeader) headers["Host"] = hostHeader;
    if (config.token) headers["Authorization"] = `Bearer ${config.token}`;

    const res = await this.#fetch(targetUrl, {
      method: "POST",
      headers,
      body,
      signal,
    });

    if (!res.ok) {
      return { success: false, error: `ntfy responded with HTTP ${res.status}` };
    }
    return { success: true };
  }

  async #dispatchTelegram(config: { botToken: string; chatId: string }, event: AlertEvent, signal: AbortSignal) {
    if (!config.botToken || !config.chatId) {
      return { success: false, error: "Telegram botToken and chatId are required" };
    }

    const text = this.#formatMarkdownTelegram(event);
    const url = `https://api.telegram.org/bot${config.botToken}/sendMessage`;
    const { targetUrl, hostHeader } = await resolveDispatcherTarget(url);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "useMeter/1.0 (+https://usemeter.example.com)",
    };
    if (hostHeader) headers["Host"] = hostHeader;

    const res = await this.#fetch(targetUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({
        chat_id: config.chatId,
        text,
        parse_mode: "Markdown",
        disable_web_page_preview: true,
      }),
      signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      return { success: false, error: `Telegram error ${res.status}: ${errText.slice(0, 100)}` };
    }
    return { success: true };
  }

  async #dispatchDiscord(config: { url: string }, event: AlertEvent, signal: AbortSignal) {
    if (!config.url || !config.url.startsWith("http")) {
      return { success: false, error: "Invalid Discord webhook URL" };
    }

    if (config.url.includes("discord.com/api/webhooks/") || config.url.includes("discordapp.com/api/webhooks/")) {
      const afterWebhooks = config.url.split("/webhooks/")[1]?.split("?")[0];
      const parts = afterWebhooks?.split("/").filter(Boolean);
      if (!parts || parts.length < 2 || parts[1].includes("...")) {
        return {
          success: false,
          error: "Invalid Discord webhook URL: must include both webhook ID and token (e.g. https://discord.com/api/webhooks/{id}/{token})",
        };
      }
    }

    let color = 0x3b82f6; // blue
    let title = `useMeter: ${event.accountLabel}`;
    let content: string = "🔔 **useMeter Test Notification:** Your webhook integration is working successfully!";

    if (event.type === "exhausted") {
      color = 0xef4444; // red
      title = `🚨 QUOTA EXHAUSTED: ${event.accountLabel} (${event.provider})`;
      content = `🚨 **useMeter Alert:** Quota for **${event.accountLabel}** (${event.provider}) is completely exhausted!`;
    } else if (event.type === "warning") {
      color = 0xf59e0b; // amber
      title = `⚠️ QUOTA WARNING: ${event.accountLabel} (${event.provider})`;
      content = `⚠️ **useMeter Warning:** Quota for **${event.accountLabel}** (${event.provider}) reached ${event.currentValueFormatted}.`;
    } else if (event.type === "recovered") {
      color = 0x10b981; // green
      title = `✅ QUOTA RESET: ${event.accountLabel} (${event.provider})`;
      content = `✅ **useMeter Notice:** Quota for **${event.accountLabel}** (${event.provider}) has been reset / restored.`;
    } else if (event.type === "test") {
      color = 0x8b5cf6; // violet
      title = `🔔 useMeter Test Notification`;
      content = `🔔 **useMeter Test Notification:** Your webhook integration is working successfully!`;
    }

    const embed = {
      title,
      description: this.#formatTextBody(event),
      color,
      timestamp: new Date(event.timestamp).toISOString(),
      footer: { text: "useMeter AI Usage Tracker" },
    };

    const { targetUrl, hostHeader } = await resolveDispatcherTarget(config.url);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "useMeter/1.0 (+https://usemeter.example.com)",
    };
    if (hostHeader) headers["Host"] = hostHeader;

    const res = await this.#fetch(targetUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({
        content,
        embeds: [embed],
      }),
      signal,
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      return { success: false, error: `Discord webhook HTTP ${res.status}: ${errText.slice(0, 100)}` };
    }
    return { success: true };
  }

  async #dispatchWebhook(config: { url: string }, event: AlertEvent, signal: AbortSignal) {
    if (!config.url || !config.url.startsWith("http")) {
      return { success: false, error: "Invalid webhook URL" };
    }

    // Auto-detect Discord webhook URLs pasted under generic Webhook channel
    if (config.url.includes("discord.com/api/webhooks/") || config.url.includes("discordapp.com/api/webhooks/")) {
      return await this.#dispatchDiscord(config, event, signal);
    }

    const { targetUrl, hostHeader } = await resolveDispatcherTarget(config.url);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "useMeter/1.0 (+https://usemeter.example.com)",
    };
    if (hostHeader) headers["Host"] = hostHeader;

    const res = await this.#fetch(targetUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({
        event: "quota_alert",
        alert: event,
        timestamp: event.timestamp,
      }),
      signal,
    });

    if (!res.ok) {
      return { success: false, error: `Webhook returned HTTP ${res.status}` };
    }
    return { success: true };
  }

  #formatTextBody(event: AlertEvent): string {
    const lines = [
      `Account: ${event.accountLabel}`,
      `Provider: ${event.provider}`,
      `Metric: ${event.metric}`,
      `Status: ${event.currentValueFormatted}`,
    ];
    if (event.thresholdFormatted) {
      lines.push(`Warning Threshold: ${event.thresholdFormatted}`);
    }
    if (event.resetLabel) {
      lines.push(`Reset / Regeneration: ${event.resetLabel}`);
    } else if (event.resetsAt) {
      lines.push(`Reset: ${new Date(event.resetsAt).toLocaleTimeString()}`);
    }
    return lines.join("\n");
  }

  #formatMarkdownTelegram(event: AlertEvent): string {
    let emoji = "ℹ️";
    let header = "*useMeter Notification*";
    if (event.type === "exhausted") {
      emoji = "🚨";
      header = "*QUOTA EXHAUSTED!*";
    } else if (event.type === "warning") {
      emoji = "⚠️";
      header = "*QUOTA WARNING*";
    } else if (event.type === "recovered") {
      emoji = "✅";
      header = "*QUOTA RESET / CAPACITY RESTORED*";
    } else if (event.type === "test") {
      emoji = "🔔";
      header = "*useMeter Test Notification*";
    }

    const lines = [
      `${emoji} ${header}`,
      `*Account:* \`${event.accountLabel}\``,
      `*Provider:* \`${event.provider}\``,
      `*Metric:* ${event.metric}`,
      `*Usage:* *${event.currentValueFormatted}*`,
    ];
    if (event.thresholdFormatted) {
      lines.push(`*Threshold:* ${event.thresholdFormatted}`);
    }
    if (event.resetLabel) {
      lines.push(`*Reset:* ${event.resetLabel}`);
    } else if (event.resetsAt) {
      lines.push(`*Reset:* ${new Date(event.resetsAt).toLocaleTimeString()}`);
    }
    return lines.join("\n");
  }
}
