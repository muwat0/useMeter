import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport } from "../../types";

interface DeepSeekBalanceInfo {
  currency?: string;
  total_balance?: string;
  granted_balance?: string;
  topped_up_balance?: string;
}

interface DeepSeekBalanceResponse {
  is_available?: boolean;
  balance_infos?: DeepSeekBalanceInfo[];
}

export class DeepSeekAdapter implements ProviderAdapter {
  readonly id = "deepseek";

  supports(provider: string): boolean {
    return provider.toLowerCase() === "deepseek";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const now = Date.now();
    const limits: UsageLimit[] = [];

    const response = await fetchImpl("https://api.deepseek.com/user/balance", {
      headers: {
        Authorization: `Bearer ${credential.secret}`,
        "Content-Type": "application/json",
      },
      signal: ctx?.signal,
    });

    if (!response.ok) {
      throw new Error(`DeepSeek bakiye sorgusu başarısız: HTTP ${response.status} ${response.statusText}`);
    }

    const data = (await response.json()) as DeepSeekBalanceResponse;
    const isAvailable = data.is_available ?? false;

    for (const info of data.balance_infos ?? []) {
      const total = parseFloat(info.total_balance ?? "0");
      const granted = parseFloat(info.granted_balance ?? "0");
      const toppedUp = parseFloat(info.topped_up_balance ?? "0");
      const currency = info.currency || "USD";

      limits.push({
        id: `balance_${currency.toLowerCase()}`,
        label: `Kullanılabilir Bakiye (${currency})`,
        amount: {
          remaining: total,
          unit: "usd",
        },
        status: !isAvailable || total <= 0 ? "exhausted" : total < 2 ? "warning" : "ok",
        notes: [
          `Nakit Yüklenen: ${toppedUp.toFixed(2)} ${currency}`,
          `Hediye/Promosyon: ${granted.toFixed(2)} ${currency}`,
          isAvailable ? "Hesap aktif" : "Hesap kullanım dışı",
        ],
      });
    }

    return {
      provider: "deepseek",
      credentialId: credential.id,
      accountLabel: credential.accountLabel,
      fetchedAt: now,
      limits,
      raw: data,
    };
  }
}
