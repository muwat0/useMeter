import type { AlertEvent, UsageLimit, UsageReport } from "../../types";
import type { StorageVault } from "../storage/vault";
import type { NotificationDispatcher } from "./dispatcher";

export interface EvaluatorOptions {
  cooldownMs?: number; // default 4 hours
  now?: () => number;
}

export class AlertEvaluator {
  readonly #vault: StorageVault;
  readonly #dispatcher: NotificationDispatcher;
  readonly #cooldownMs: number;
  readonly #now: () => number;

  constructor(vault: StorageVault, dispatcher: NotificationDispatcher, options: EvaluatorOptions = {}) {
    this.#vault = vault;
    this.#dispatcher = dispatcher;
    this.#cooldownMs = options.cooldownMs ?? 4 * 60 * 60 * 1000;
    this.#now = options.now ?? (() => Date.now());
  }

  /**
   * Evaluates a fresh usage report against the user's notification configuration.
   * Emits alerts on state transitions (normal -> warning -> exhausted -> recovered)
   * and dispatches notifications asynchronously.
   */
  async evaluateReport(report: UsageReport): Promise<AlertEvent[]> {
    if (!report.ownerId || !report.credentialId) return [];

    const notifConfig = this.#vault.getNotificationConfig(report.ownerId);
    if (!notifConfig || !notifConfig.enabled) return [];

    const emittedEvents: AlertEvent[] = [];
    const now = this.#now();
    const thresholdFraction = notifConfig.warningThresholdPercent / 100;

    for (const limit of report.limits) {
      const metricId = limit.id || limit.label;
      const priorState = this.#vault.getAlertState(report.ownerId, report.credentialId, metricId);

      const { currentState, currentValue, currentValueFormatted, thresholdFormatted } = this.#evaluateLimit(
        limit,
        thresholdFraction,
      );

      const oldState = priorState?.lastState ?? "normal";
      let eventType: AlertEvent["type"] | null = null;

      if (currentState === "exhausted") {
        if (oldState !== "exhausted" && notifConfig.notifyOnExhausted) {
          eventType = "exhausted";
        }
      } else if (currentState === "warning") {
        if (oldState === "normal" && notifConfig.notifyOnWarning) {
          eventType = "warning";
        } else if (oldState === "warning" && priorState && now - priorState.lastNotifiedAt >= this.#cooldownMs) {
          eventType = "warning";
        }
      } else if (currentState === "normal") {
        if ((oldState === "warning" || oldState === "exhausted") && notifConfig.notifyOnReset) {
          eventType = "recovered";
        }
      }

      if (eventType) {
        const event: AlertEvent = {
          userId: report.ownerId,
          provider: report.provider,
          accountLabel: report.accountLabel || report.provider,
          metric: limit.label,
          metricId,
          currentValue,
          currentValueFormatted,
          threshold: thresholdFraction,
          thresholdFormatted,
          resetsAt: limit.window?.resetsAt,
          resetLabel: limit.window?.resetLabel,
          type: eventType,
          timestamp: now,
        };

        emittedEvents.push(event);

        // Update state in SQLite
        this.#vault.saveAlertState(
          report.ownerId,
          report.credentialId,
          metricId,
          currentState,
          currentValue,
          now,
        );

        // Dispatch async without blocking
        this.#dispatcher.dispatch(notifConfig.config, event).catch(() => {});
      } else if (currentState !== oldState) {
        // State changed without notification (e.g. user turned off notifyOnWarning)
        this.#vault.saveAlertState(
          report.ownerId,
          report.credentialId,
          metricId,
          currentState,
          currentValue,
          priorState?.lastNotifiedAt ?? now,
        );
      }
    }

    return emittedEvents;
  }

  #evaluateLimit(
    limit: UsageLimit,
    thresholdFraction: number,
  ): {
    currentState: "normal" | "warning" | "exhausted";
    currentValue: number;
    currentValueFormatted: string;
    thresholdFormatted: string;
  } {
    // 1. Fraction / percentage based limits (e.g. usedFraction: 0.85)
    if (typeof limit.amount.usedFraction === "number") {
      const frac = limit.amount.usedFraction;
      const pct = Math.round(frac * 100);
      const threshPct = Math.round(thresholdFraction * 100);
      let currentState: "normal" | "warning" | "exhausted" = "normal";

      if (frac >= 1.0 || limit.status === "exhausted") {
        currentState = "exhausted";
      } else if (frac >= thresholdFraction || limit.status === "warning") {
        currentState = "warning";
      }

      return {
        currentState,
        currentValue: frac,
        currentValueFormatted: `%${pct}`,
        thresholdFormatted: `%${threshPct}`,
      };
    }

    // 2. USD balance based (e.g. OpenRouter, DeepSeek)
    if (limit.amount.unit === "usd" && typeof limit.amount.remaining === "number") {
      const remaining = limit.amount.remaining;
      const totalLimit = limit.amount.limit ?? (remaining + (limit.amount.used ?? 0));
      let currentState: "normal" | "warning" | "exhausted" = "normal";

      if (remaining <= 0) {
        currentState = "exhausted";
      } else if (totalLimit > 0) {
        const usedFraction = 1 - remaining / totalLimit;
        if (usedFraction >= thresholdFraction) {
          currentState = "warning";
        }
      } else if (remaining <= 2.0) {
        currentState = "warning";
      }

      return {
        currentState,
        currentValue: remaining,
        currentValueFormatted: `$${remaining.toFixed(2)} kalan`,
        thresholdFormatted: `Eşik: %${Math.round(thresholdFraction * 100)}`,
      };
    }

    // Default: Check limit.status
    let currentState: "normal" | "warning" | "exhausted" = "normal";
    if (limit.status === "exhausted") currentState = "exhausted";
    else if (limit.status === "warning") currentState = "warning";

    return {
      currentState,
      currentValue: limit.amount.used ?? 0,
      currentValueFormatted: `${limit.amount.used ?? 0} ${limit.amount.unit}`,
      thresholdFormatted: `%${Math.round(thresholdFraction * 100)}`,
    };
  }
}
