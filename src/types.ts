export type UsageUnit = "percent" | "tokens" | "requests" | "credits" | "usd";

export type UsageStatus = "ok" | "warning" | "exhausted" | "unknown";

export type CredentialType = "api_key" | "oauth" | "cookie";

export interface UsageWindow {
  id: string;             // örn: "5h", "7d", "monthly"
  label: string;          // örn: "5 Saatlik Kayan Pencere"
  durationMs?: number;
  resetsAt?: number;      // Epoch ms
  resetLabel?: string;    // "resets", "regen"
}

export interface UsageAmount {
  used?: number;
  limit?: number;
  remaining?: number;
  usedFraction?: number;  // 0.0 - 1.0 (1.0 = tüketildi)
  unit: UsageUnit;
}

export interface UsageLimit {
  id: string;
  label: string;
  amount: UsageAmount;
  window?: UsageWindow;
  status: UsageStatus;
  notes?: string[];
}

export interface UsageReport {
  provider: string;
  credentialId?: string;
  accountLabel?: string;
  fetchedAt: number;
  limits: UsageLimit[];
  raw?: unknown;
}

export interface StoredCredential {
  id: string;
  provider: string;
  accountLabel: string;
  credentialType: CredentialType;
  secret: string; // Plaintext when decrypted
  metadata?: Record<string, unknown>;
  createdAt: number;
  updatedAt: number;
}

export interface InputCredential {
  provider: string;
  accountLabel: string;
  credentialType: CredentialType;
  secret: string;
  metadata?: Record<string, unknown>;
}

export interface AlertEvent {
  provider: string;
  accountLabel: string;
  metric: string;
  currentValue: number;
  threshold: number;
  resetsAt?: number;
  type: "warning" | "exhausted" | "recovered";
}
