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
import { MiniMaxAdapter } from "./minimax-code";
import { ClinePassAdapter } from "./cline-pass";
import { DevinAdapter } from "./devin";
import { UmansAdapter } from "./umans";
import { GoogleGeminiCliAdapter } from "./google-gemini-cli";
import { KimiCodeAdapter } from "./kimi-code";
import { OpenCodeGoAdapter } from "./opencode-go";
import { AlibabaTokenPlanAdapter } from "./alibaba-token-plan";

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
  registry.register(new MiniMaxAdapter());
  registry.register(new ClinePassAdapter());
  registry.register(new DevinAdapter());
  registry.register(new UmansAdapter());
  registry.register(new GoogleGeminiCliAdapter());
  registry.register(new KimiCodeAdapter());
  registry.register(new OpenCodeGoAdapter());
  registry.register(new AlibabaTokenPlanAdapter());
  return registry;
}
