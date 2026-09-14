import type { StoredCredential, UsageReport } from "../../types";

export interface FetchContext {
  fetch?: typeof fetch;
  signal?: AbortSignal;
  onTokenRefresh?: (newSecret: string, metadataUpdates?: Record<string, unknown>, newAccountLabel?: string) => void;
}

export interface ProviderAdapter {
  readonly id: string;
  supports(provider: string): boolean;
  fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport>;
  parseHeaders?(headers: Headers, credential?: StoredCredential, now?: number): UsageReport | null;
}
