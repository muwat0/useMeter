import type { ProviderAdapter } from "./adapter";
import { OpenRouterAdapter } from "./openrouter";
import { DeepSeekAdapter } from "./deepseek";
import { ClaudeAdapter } from "./claude";
import { CodexAdapter } from "./codex";
import { GoogleAntigravityAdapter } from "./google-antigravity";
import { CopilotAdapter } from "./copilot";
import { CursorAdapter } from "./cursor";
import { XaiAdapter } from "./xai";
import { ZaiAdapter } from "./zai";

export class ProviderRegistry {
  readonly #adapters: ProviderAdapter[] = [];

  register(adapter: ProviderAdapter): void {
    this.#adapters.push(adapter);
  }

  find(provider: string): ProviderAdapter | undefined {
    return this.#adapters.find(a => a.supports(provider));
  }

  all(): readonly ProviderAdapter[] {
    return this.#adapters;
  }
}

export function createDefaultRegistry(): ProviderRegistry {
  const registry = new ProviderRegistry();
  registry.register(new OpenRouterAdapter());
  registry.register(new DeepSeekAdapter());
  registry.register(new ClaudeAdapter());
  registry.register(new CodexAdapter());
  registry.register(new GoogleAntigravityAdapter());
  registry.register(new CopilotAdapter());
  registry.register(new CursorAdapter());
  registry.register(new XaiAdapter());
  registry.register(new ZaiAdapter());
  return registry;
}
