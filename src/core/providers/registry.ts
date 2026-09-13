import type { ProviderAdapter } from "./adapter";
import { OpenRouterAdapter } from "./openrouter";
import { DeepSeekAdapter } from "./deepseek";
import { ClaudeAdapter } from "./claude";
import { CodexAdapter } from "./codex";

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
  return registry;
}
