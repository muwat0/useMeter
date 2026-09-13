import type { StoredCredential, UsageReport } from "../../types";

export interface FetchContext {
  fetch?: typeof fetch;
  signal?: AbortSignal;
}

export interface ProviderAdapter {
  readonly id: string;
  supports(provider: string): boolean;
  fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport>;
  parseHeaders?(headers: Headers, credential?: StoredCredential, now?: number): UsageReport | null;
}
