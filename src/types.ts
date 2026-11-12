export type UserRole = "admin" | "user";

export interface User {
  id: string;
  email: string;
  role: UserRole;
  createdAt: number;
  updatedAt: number;
}

export interface AdminUserView extends User {
  credentialCount: number;
  activeSessionCount: number;
}

export interface AdminSystemStats {
  totalUsers: number;
  totalCredentials: number;
  totalSnapshots: number;
  activeSessions: number;
  pollerRunning: boolean;
  allowRegistration: boolean;
  databaseSizeBytes: number;
  integrity: boolean;
  providerCounts: Record<string, number>;
}

export interface Session {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: number;
  createdAt: number;
}

export type AuthErrorCode =
  | "INVALID_CREDENTIALS"
  | "EMAIL_EXISTS"
  | "WEAK_PASSWORD"
  | "INVALID_EMAIL"
  | "UNAUTHENTICATED"
  | "FORBIDDEN"
  | "INVALID_INVITATION"
  | "INVITATION_EXPIRED"
  | "INVITATION_REVOKED"
  | "INVITATION_USED"
  | "INVALID_RESET_TOKEN"
  | "RECOVERY_UNAVAILABLE"
  | "RATE_LIMITED"
  | "LAST_ADMIN"
  | "TOKEN_LIMIT_REACHED"
  | "INVALID_TOKEN"
  | "INTERNAL_ERROR";

export type InvitationStatus = "pending" | "accepted" | "revoked" | "expired";

export interface Invitation {
  id: string;
  email: string;
  tokenHash: string;
  createdBy: string;
  expiresAt: number;
  acceptedAt: number | null;
  revokedAt: number | null;
  createdAt: number;
}

export interface InvitationView {
  id: string;
  email: string;
  createdBy: string;
  status: InvitationStatus;
  expiresAt: number;
  acceptedAt: number | null;
  revokedAt: number | null;
  createdAt: number;
}

export interface CreateInvitationResult {
  invitation: InvitationView;
  token: string;
}

export interface PersonalAccessToken {
  id: string;
  userId: string;
  name: string;
  tokenHash: string;
  tokenPrefix: string;
  createdAt: number;
  lastUsedAt: number | null;
  expiresAt: number | null;
}

export interface PersonalAccessTokenView {
  id: string;
  name: string;
  tokenPrefix: string;
  createdAt: number;
  lastUsedAt: number | null;
  expiresAt: number | null;
}

export interface CreatePersonalAccessTokenResult {
  token: PersonalAccessTokenView;
  rawToken: string;
}
export type AuthResult<T> =
  | { success: true; data: T }
  | { success: false; error: AuthErrorCode; message: string };

export interface AuthSuccess {
  user: User;
  token: string;
  session: Session;
}

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

export type UsageReportHealth = "healthy" | "stale" | "error";
export type UsageReportSource = "live" | "stale" | "error";

export interface UsageReport {
  ownerId?: string;
  provider: string;
  credentialId?: string;
  accountLabel?: string;
  fetchedAt: number;
  limits: UsageLimit[];
  error?: string;
  raw?: unknown;
  health?: UsageReportHealth;
  stale?: boolean;
  lastGoodFetchedAt?: number;
  source?: UsageReportSource;
}

export interface CredentialRef {
  id: string;
  ownerId: string;
  provider: string;
  accountLabel: string;
}

export type CardAccent = "default" | "amber" | "emerald" | "cyan" | "violet" | "slate";

export interface StoredCredential {
  id: string;
  ownerId: string;
  provider: string;
  accountLabel: string;
  accent?: CardAccent;
  credentialType: CredentialType;
  secret: string; // Plaintext when decrypted
  metadata?: Record<string, unknown>;
  createdAt: number;
  updatedAt: number;
}

export interface InputCredential {
  ownerId?: string;
  provider: string;
  accountLabel: string;
  accent?: CardAccent;
  credentialType: CredentialType;
  secret: string;
  metadata?: Record<string, unknown>;
}

export type NotificationChannelType = "ntfy" | "telegram" | "webhook" | "discord";

export interface NtfyConfig {
  channel: "ntfy";
  url: string; // e.g. "https://ntfy.sh/my-topic" or custom ntfy instance
  token?: string; // Optional auth token
}

export interface TelegramConfig {
  channel: "telegram";
  botToken: string;
  chatId: string;
}

export interface WebhookConfig {
  channel: "webhook";
  url: string;
}

export interface DiscordConfig {
  channel: "discord";
  url: string;
}

export type ChannelConfig = NtfyConfig | TelegramConfig | WebhookConfig | DiscordConfig;

export interface UserNotificationConfig {
  userId: string;
  enabled: boolean;
  channel: NotificationChannelType;
  config: ChannelConfig;
  warningThresholdPercent: number; // e.g. 80 for 80%
  notifyOnWarning: boolean;
  notifyOnExhausted: boolean;
  notifyOnReset: boolean;
  updatedAt: number;
}

export interface UserNotificationConfigView {
  enabled: boolean;
  channel: NotificationChannelType;
  config: {
    channel: NotificationChannelType;
    url?: string;
    chatId?: string;
    hasBotToken?: boolean;
    hasToken?: boolean;
  };
  warningThresholdPercent: number;
  notifyOnWarning: boolean;
  notifyOnExhausted: boolean;
  notifyOnReset: boolean;
  updatedAt: number;
}

export interface AlertState {
  userId: string;
  credentialId: string;
  metric: string;
  lastState: "normal" | "warning" | "exhausted";
  lastNotifiedAt: number;
  lastValue: number;
}

export interface AlertEvent {
  userId?: string;
  provider: string;
  accountLabel: string;
  metric: string;
  metricId?: string;
  currentValue: number;
  currentValueFormatted: string;
  threshold: number;
  thresholdFormatted?: string;
  resetsAt?: number;
  resetLabel?: string;
  type: "warning" | "exhausted" | "recovered" | "test";
  timestamp: number;
}
