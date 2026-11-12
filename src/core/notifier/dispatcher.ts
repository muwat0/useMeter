import type { AlertEvent, ChannelConfig } from "../../types";

export interface DispatcherOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
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
      titlePrefix = "[useMeter] KOTA TÜKENDİ";
    } else if (event.type === "warning") {
      priority = "4"; // high
      tags = "warning";
      titlePrefix = "[useMeter] KOTA UYARISI";
    } else if (event.type === "recovered") {
      priority = "3";
      tags = "white_check_mark,arrows_counterclockwise";
      titlePrefix = "[useMeter] KOTA SIFIRLANDI / YENİLENDİ";
    } else if (event.type === "test") {
      priority = "3";
      tags = "bell,test_tube";
      titlePrefix = "[useMeter] Test Bildirimi";
    }

    const title = `${titlePrefix}: ${event.accountLabel} (${event.provider})`;
    const body = this.#formatTextBody(event);

    const headers: Record<string, string> = {
      Title: title,
      Priority: priority,
      Tags: tags,
    };
    if (config.token) {
      headers["Authorization"] = `Bearer ${config.token}`;
    }

    const res = await this.#fetch(config.url, {
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

    const res = await this.#fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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

    let color = 0x3b82f6; // blue
    let title = `useMeter: ${event.accountLabel}`;

    if (event.type === "exhausted") {
      color = 0xef4444; // red
      title = `🚨 KOTA TÜKENDİ: ${event.accountLabel} (${event.provider})`;
    } else if (event.type === "warning") {
      color = 0xf59e0b; // amber
      title = `⚠️ KOTA UYARISI: ${event.accountLabel} (${event.provider})`;
    } else if (event.type === "recovered") {
      color = 0x10b981; // green
      title = `✅ KOTA SIFIRLANDI: ${event.accountLabel} (${event.provider})`;
    } else if (event.type === "test") {
      color = 0x8b5cf6; // violet
      title = `🔔 useMeter Test Bildirimi`;
    }

    const embed = {
      title,
      description: this.#formatTextBody(event),
      color,
      timestamp: new Date(event.timestamp).toISOString(),
      footer: { text: "useMeter AI Usage Tracker" },
    };

    const res = await this.#fetch(config.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ embeds: [embed] }),
      signal,
    });

    if (!res.ok) {
      return { success: false, error: `Discord webhook HTTP ${res.status}` };
    }
    return { success: true };
  }

  async #dispatchWebhook(config: { url: string }, event: AlertEvent, signal: AbortSignal) {
    if (!config.url || !config.url.startsWith("http")) {
      return { success: false, error: "Invalid webhook URL" };
    }

    const res = await this.#fetch(config.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
      `Hesap: ${event.accountLabel}`,
      `Sağlayıcı: ${event.provider}`,
      `Metrik: ${event.metric}`,
      `Mevcut Durum: ${event.currentValueFormatted}`,
    ];
    if (event.thresholdFormatted) {
      lines.push(`Uyarı Eşiği: ${event.thresholdFormatted}`);
    }
    if (event.resetLabel) {
      lines.push(`Sıfırlanma / Yenilenme: ${event.resetLabel}`);
    } else if (event.resetsAt) {
      lines.push(`Sıfırlanma: ${new Date(event.resetsAt).toLocaleTimeString()}`);
    }
    return lines.join("\n");
  }

  #formatMarkdownTelegram(event: AlertEvent): string {
    let emoji = "ℹ️";
    let header = "useMeter Bildirimi";
    if (event.type === "exhausted") {
      emoji = "🚨";
      header = "*KOTA TÜKENDİ!*";
    } else if (event.type === "warning") {
      emoji = "⚠️";
      header = "*KOTA UYARISI*";
    } else if (event.type === "recovered") {
      emoji = "✅";
      header = "*KOTA SIFIRLANDI / HAK TANIMLANDI*";
    } else if (event.type === "test") {
      emoji = "🔔";
      header = "*useMeter Test Bildirimi*";
    }

    const lines = [
      `${emoji} ${header}`,
      `*Hesap:* \`${event.accountLabel}\``,
      `*Sağlayıcı:* \`${event.provider}\``,
      `*Metrik:* ${event.metric}`,
      `*Kullanım:* *${event.currentValueFormatted}*`,
    ];
    if (event.thresholdFormatted) {
      lines.push(`*Uyarı Eşiği:* ${event.thresholdFormatted}`);
    }
    if (event.resetLabel) {
      lines.push(`*Sıfırlanma:* ${event.resetLabel}`);
    } else if (event.resetsAt) {
      lines.push(`*Sıfırlanma:* ${new Date(event.resetsAt).toLocaleTimeString()}`);
    }
    return lines.join("\n");
  }
}
