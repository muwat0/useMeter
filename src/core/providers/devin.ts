import { gunzipSync } from "node:zlib";
import type { FetchContext, ProviderAdapter } from "./adapter";
import type { StoredCredential, UsageLimit, UsageReport, UsageStatus, UsageWindow } from "../../types";

const PROVIDER = "devin";
const BASE_URL = "https://server.codeium.com";
const STATUS_PATH = "/exa.seat_management_pb.SeatManagementService/GetUserStatus";
const SESSION_PREFIX = "devin-session-token$";
const DAY_MS = 24 * 60 * 60 * 1_000;
const WEEK_MS = 7 * DAY_MS;

const TIER_LABELS: Record<string, string> = {
  "1": "Teams",
  "2": "Pro",
  "3": "Enterprise Saas",
  "4": "Hybrid",
  "5": "Enterprise Self Hosted",
  "6": "Waitlist Pro",
  "7": "Teams Ultimate",
  "8": "Pro Ultimate",
  "9": "Trial",
  "10": "Enterprise Self Serve",
  "11": "Enterprise Saas Pooled",
  "12": "Devin Enterprise",
  "14": "Devin Teams",
  "15": "Devin Teams V2",
  "16": "Devin Pro",
  "17": "Devin Max",
  "18": "Max",
  "19": "Devin Free",
  "20": "Devin Trial",
};

type WireValue = bigint | Uint8Array;

interface PlanData {
  planName?: string;
  tier?: string;
  billingStrategy?: string | number;
  monthlyPromptCredits?: number;
  monthlyFlowCredits?: number;
  monthlyFlexCredits?: number;
  hideDailyQuota?: boolean;
  hideWeeklyQuota?: boolean;
  orgId?: string;
  orgName?: string;
}

interface StatusData {
  email?: string;
  userId?: string;
  teamId?: string;
  tier?: string;
  plan?: PlanData;
  planStart?: number;
  planEnd?: number;
  usedPromptCredits?: number;
  availablePromptCredits?: number;
  usedFlowCredits?: number;
  availableFlowCredits?: number;
  usedFlexCredits?: number;
  availableFlexCredits?: number;
  dailyRemaining?: number;
  dailyReset?: number;
  weeklyRemaining?: number;
  weeklyReset?: number;
  overageMicros?: number;
}

function field(value: Record<string, unknown>, ...names: string[]): unknown {
  for (const name of names) {
    if (name in value) return value[name];
  }
  return undefined;
}

function toNumber(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "bigint") {
    const num = Number(value);
    return Number.isSafeInteger(num) ? num : undefined;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const num = Number(value.trim());
    return Number.isFinite(num) ? num : undefined;
  }
  return undefined;
}

function epochMs(value: unknown): number | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const rec = value as Record<string, unknown>;
    const seconds = toNumber(field(rec, "seconds"));
    if (seconds === undefined) return undefined;
    const nanos = toNumber(field(rec, "nanos", "nanoseconds")) ?? 0;
    const result = seconds * 1_000 + nanos / 1_000_000;
    return Number.isFinite(result) && result > 0 ? result : undefined;
  }
  if (typeof value === "string" && /[T-]/.test(value)) {
    const result = Date.parse(value);
    return Number.isFinite(result) && result > 0 ? result : undefined;
  }
  const num = toNumber(value);
  if (num === undefined || num <= 0) return undefined;
  const result = Math.abs(num) < 100_000_000_000 ? num * 1_000 : num;
  return Number.isFinite(result) ? result : undefined;
}

function normalizeToken(secret: string): string {
  const token = secret.trim();
  if (!token) throw new Error("Devin session token is missing");
  try {
    const parsed: unknown = JSON.parse(token);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
      const rec = parsed as Record<string, unknown>;
      const nested = field(rec, "accessToken", "access_token", "apiKey", "token", "secret");
      if (typeof nested === "string" && nested.trim().length > 0) {
        return normalizeToken(nested);
      }
    }
  } catch {
    // Treat raw token string as valid
  }
  return token.startsWith(SESSION_PREFIX) ? token : `${SESSION_PREFIX}${token}`;
}

function encodeVarint(value: bigint): number[] {
  const bytes: number[] = [];
  let current = value < 0n ? value + (1n << 64n) : value;
  do {
    let byte = Number(current & 0x7fn);
    current >>= 7n;
    if (current !== 0n) byte |= 0x80;
    bytes.push(byte);
  } while (current !== 0n);
  return bytes;
}

function appendField(out: number[], number: number, value: string): void {
  const bytes = new TextEncoder().encode(value);
  out.push(...encodeVarint(BigInt(number * 8 + 2)), ...encodeVarint(BigInt(bytes.length)), ...bytes);
}

function encodeMetadata(token: string): Uint8Array {
  const metadata: number[] = [];
  appendField(metadata, 1, "devin-cli");
  appendField(metadata, 7, "3000.6.2");
  appendField(metadata, 28, "chisel");
  appendField(metadata, 12, "chisel");
  appendField(metadata, 2, "3000.6.2");
  appendField(metadata, 3, token);
  appendField(metadata, 4, "en");
  appendField(metadata, 5, process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "windows" : "linux");
  appendField(metadata, 21, "");
  const request: number[] = [
    ...encodeVarint(10n),
    ...encodeVarint(BigInt(metadata.length)),
    ...metadata,
  ];
  return new Uint8Array(request);
}

function readVarint(bytes: Uint8Array, offset: { value: number }): bigint {
  let result = 0n;
  let shift = 0n;
  for (let count = 0; count < 10; count += 1) {
    if (offset.value >= bytes.length) throw new Error("truncated protobuf varint");
    const byte = bytes[offset.value++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return result;
    shift += 7n;
  }
  throw new Error("invalid protobuf varint");
}

function readBytes(bytes: Uint8Array, offset: { value: number }): Uint8Array {
  const length = readVarint(bytes, offset);
  if (length > BigInt(bytes.length - offset.value)) throw new Error("truncated protobuf field");
  const end = offset.value + Number(length);
  const value = bytes.slice(offset.value, end);
  offset.value = end;
  return value;
}

function decodeFields(bytes: Uint8Array): Map<number, WireValue> {
  const values = new Map<number, WireValue>();
  const offset = { value: 0 };
  while (offset.value < bytes.length) {
    const key = readVarint(bytes, offset);
    const number = Number(key >> 3n);
    const wireType = Number(key & 7n);
    if (!Number.isInteger(number) || number <= 0) throw new Error("invalid protobuf field number");
    if (wireType === 0) {
      values.set(number, readVarint(bytes, offset));
    } else if (wireType === 2) {
      values.set(number, readBytes(bytes, offset));
    } else if (wireType === 1) {
      if (offset.value + 8 > bytes.length) throw new Error("truncated protobuf fixed64 field");
      offset.value += 8;
    } else if (wireType === 5) {
      if (offset.value + 4 > bytes.length) throw new Error("truncated protobuf fixed32 field");
      offset.value += 4;
    } else {
      throw new Error(`unsupported protobuf wire type ${wireType}`);
    }
  }
  return values;
}

function wireString(fields: Map<number, WireValue>, number: number): string | undefined {
  const value = fields.get(number);
  if (!(value instanceof Uint8Array)) return undefined;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    return undefined;
  }
}

function wireNumber(fields: Map<number, WireValue>, number: number): number | undefined {
  const value = fields.get(number);
  if (typeof value !== "bigint") return undefined;
  const result = Number(value);
  return Number.isFinite(result) ? result : undefined;
}

function wireMessage(fields: Map<number, WireValue>, number: number): Map<number, WireValue> | undefined {
  const value = fields.get(number);
  return value instanceof Uint8Array ? decodeFields(value) : undefined;
}

function tierLabel(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim().length > 0) {
    const trimmed = value.trim();
    if (/^\d+$/.test(trimmed)) return TIER_LABELS[trimmed];
    return trimmed
      .replace(/^TEAMS_TIER_/, "")
      .toLowerCase()
      .split("_")
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(" ");
  }
  const num = toNumber(value);
  return num === undefined ? undefined : TIER_LABELS[String(num)];
}

function parsePlan(value: unknown): PlanData | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const rec = value as Record<string, unknown>;
  const rawPlanName = field(rec, "planName", "plan_name");
  const rawTier = field(rec, "teamsTier", "teams_tier", "tier");
  const rawOrgId = field(rec, "orgId", "org_id");
  const rawOrgName = field(rec, "accountDisplayName", "account_display_name");
  const rawHideDaily = field(rec, "hideDailyQuota", "hide_daily_quota");
  const rawHideWeekly = field(rec, "hideWeeklyQuota", "hide_weekly_quota");

  return {
    planName: typeof rawPlanName === "string" && rawPlanName.trim().length > 0 ? rawPlanName.trim() : undefined,
    tier: tierLabel(rawTier),
    billingStrategy: field(rec, "billingStrategy", "billing_strategy") as string | number | undefined,
    monthlyPromptCredits: toNumber(field(rec, "monthlyPromptCredits", "monthly_prompt_credits")),
    monthlyFlowCredits: toNumber(field(rec, "monthlyFlowCredits", "monthly_flow_credits")),
    monthlyFlexCredits: toNumber(field(rec, "monthlyFlexCreditPurchaseAmount", "monthly_flex_credit_purchase_amount")),
    hideDailyQuota: typeof rawHideDaily === "boolean" ? rawHideDaily : undefined,
    hideWeeklyQuota: typeof rawHideWeekly === "boolean" ? rawHideWeekly : undefined,
    orgId: typeof rawOrgId === "string" && rawOrgId.trim().length > 0 ? rawOrgId.trim() : undefined,
    orgName: typeof rawOrgName === "string" && rawOrgName.trim().length > 0 ? rawOrgName.trim() : undefined,
  };
}

function parseJsonResponse(root: unknown): StatusData | undefined {
  if (typeof root !== "object" || root === null || Array.isArray(root)) return undefined;
  const recRoot = root as Record<string, unknown>;
  const rawUser = field(recRoot, "userStatus", "user_status");
  if (typeof rawUser !== "object" || rawUser === null || Array.isArray(rawUser)) return undefined;
  const recUser = rawUser as Record<string, unknown>;

  const rawPlanStatus = field(recUser, "planStatus", "plan_status");
  if (typeof rawPlanStatus !== "object" || rawPlanStatus === null || Array.isArray(rawPlanStatus)) return undefined;
  const recPlanStatus = rawPlanStatus as Record<string, unknown>;

  const rawPlan = parsePlan(field(recRoot, "planInfo", "plan_info")) ?? parsePlan(field(recPlanStatus, "planInfo", "plan_info"));
  const rawDevin = rawPlan ? field(field(recRoot, "planInfo", "plan_info") as Record<string, unknown>, "devinInfo", "devin_info") : undefined;
  if (rawPlan && typeof rawDevin === "object" && rawDevin !== null && !Array.isArray(rawDevin)) {
    const devinRec = rawDevin as Record<string, unknown>;
    const orgId = field(devinRec, "orgId", "org_id");
    const orgName = field(devinRec, "accountDisplayName", "account_display_name");
    if (typeof orgId === "string" && orgId.trim().length > 0) rawPlan.orgId ??= orgId.trim();
    if (typeof orgName === "string" && orgName.trim().length > 0) rawPlan.orgName ??= orgName.trim();
  }

  const rawEmail = field(recUser, "email");
  const rawUserId = field(recUser, "userId", "user_id");
  const rawTeamId = field(recUser, "teamId", "team_id");
  const dailyResetMs = epochMs(field(recPlanStatus, "dailyQuotaResetAtUnix", "daily_quota_reset_at_unix"));
  const weeklyResetMs = epochMs(field(recPlanStatus, "weeklyQuotaResetAtUnix", "weekly_quota_reset_at_unix"));

  return {
    email: typeof rawEmail === "string" && rawEmail.trim().length > 0 ? rawEmail.trim() : undefined,
    userId: typeof rawUserId === "string" && rawUserId.trim().length > 0 ? rawUserId.trim() : undefined,
    teamId: typeof rawTeamId === "string" && rawTeamId.trim().length > 0 ? rawTeamId.trim() : undefined,
    tier: tierLabel(field(recUser, "teamsTier", "teams_tier")),
    plan: rawPlan,
    planStart: epochMs(field(recPlanStatus, "planStart", "plan_start")),
    planEnd: epochMs(field(recPlanStatus, "planEnd", "plan_end")),
    usedPromptCredits: toNumber(field(recPlanStatus, "usedPromptCredits", "used_prompt_credits")),
    availablePromptCredits: toNumber(field(recPlanStatus, "availablePromptCredits", "available_prompt_credits")),
    usedFlowCredits: toNumber(field(recPlanStatus, "usedFlowCredits", "used_flow_credits")),
    availableFlowCredits: toNumber(field(recPlanStatus, "availableFlowCredits", "available_flow_credits")),
    usedFlexCredits: toNumber(field(recPlanStatus, "usedFlexCredits", "used_flex_credits")),
    availableFlexCredits: toNumber(field(recPlanStatus, "availableFlexCredits", "available_flex_credits")),
    dailyRemaining: toNumber(field(recPlanStatus, "dailyQuotaRemainingPercent", "daily_quota_remaining_percent")),
    dailyReset: dailyResetMs !== undefined ? dailyResetMs / 1_000 : undefined,
    weeklyRemaining: toNumber(field(recPlanStatus, "weeklyQuotaRemainingPercent", "weekly_quota_remaining_percent")),
    weeklyReset: weeklyResetMs !== undefined ? weeklyResetMs / 1_000 : undefined,
    overageMicros: toNumber(field(recPlanStatus, "overageBalanceMicros", "overage_balance_micros")),
  };
}

function parseProtoResponse(bytes: Uint8Array): StatusData | undefined {
  const root = decodeFields(bytes);
  const user = wireMessage(root, 1);
  if (!user) return undefined;
  const status = wireMessage(user, 13);
  if (!status) return undefined;

  const planMessage = wireMessage(root, 2) ?? wireMessage(status, 1);
  const devin = planMessage ? wireMessage(planMessage, 33) : undefined;
  const plan: PlanData | undefined = planMessage
    ? {
        planName: wireString(planMessage, 2),
        tier: tierLabel(wireNumber(planMessage, 1)),
        billingStrategy: wireNumber(planMessage, 35),
        monthlyPromptCredits: wireNumber(planMessage, 12),
        monthlyFlowCredits: wireNumber(planMessage, 13),
        monthlyFlexCredits: wireNumber(planMessage, 14),
        hideDailyQuota: wireNumber(planMessage, 36) === 1,
        hideWeeklyQuota: wireNumber(planMessage, 37) === 1,
        orgId: devin ? wireString(devin, 4) : undefined,
        orgName: devin ? wireString(devin, 8) : undefined,
      }
    : undefined;

  const startMsg = wireMessage(status, 2);
  const endMsg = wireMessage(status, 3);

  return {
    email: wireString(user, 7),
    userId: wireString(user, 36),
    teamId: wireString(user, 5),
    tier: tierLabel(wireNumber(user, 10)),
    plan,
    planStart: startMsg ? epochMs({ seconds: wireNumber(startMsg, 1), nanos: wireNumber(startMsg, 2) }) : undefined,
    planEnd: endMsg ? epochMs({ seconds: wireNumber(endMsg, 1), nanos: wireNumber(endMsg, 2) }) : undefined,
    usedPromptCredits: wireNumber(status, 6),
    availablePromptCredits: wireNumber(status, 8),
    usedFlowCredits: wireNumber(status, 5),
    availableFlowCredits: wireNumber(status, 9),
    usedFlexCredits: wireNumber(status, 7),
    availableFlexCredits: wireNumber(status, 4),
    dailyRemaining: wireNumber(status, 14),
    dailyReset: wireNumber(status, 17),
    weeklyRemaining: wireNumber(status, 15),
    weeklyReset: wireNumber(status, 18),
    overageMicros: wireNumber(status, 16),
  };
}

function calculateUsageStatus(fraction: number | undefined): UsageStatus {
  if (fraction === undefined) return "unknown";
  if (fraction >= 1) return "exhausted";
  if (fraction >= 0.9) return "warning";
  return "ok";
}

function creditLimit(
  id: string,
  label: string,
  limit: number | undefined,
  used: number | undefined,
  remaining: number | undefined,
  window: UsageWindow
): UsageLimit | undefined {
  const normalizedUsed = Math.max(0, used ?? 0);
  const normalizedRemaining = Math.max(0, remaining ?? 0);
  if (limit === undefined && normalizedUsed === 0 && normalizedRemaining === 0) {
    return undefined;
  }
  const usedFraction = limit !== undefined && limit > 0 ? normalizedUsed / limit : undefined;
  return {
    id: `devin:credits:${id}`,
    label,
    amount: {
      used: normalizedUsed,
      remaining: normalizedRemaining,
      ...(limit !== undefined && limit > 0 ? { limit } : {}),
      ...(usedFraction !== undefined ? { usedFraction, remainingFraction: Math.max(0, 1 - usedFraction) } : {}),
      unit: "credits",
    },
    window,
    status: calculateUsageStatus(usedFraction),
  };
}

function isGenericDevinLabel(label: string | undefined): boolean {
  if (!label) return true;
  const normalized = label.trim().toLowerCase();
  return normalized === "" || normalized === "devin" || normalized === "default" || normalized === "devin ai";
}

function buildReport(data: StatusData, credential: StoredCredential): UsageReport {
  const plan = data.plan;
  const window: UsageWindow = {
    id: "monthly",
    label: "Plan Period",
    ...(data.planStart !== undefined && data.planEnd !== undefined && data.planEnd > data.planStart
      ? { durationMs: data.planEnd - data.planStart }
      : {}),
    ...(data.planEnd !== undefined && data.planEnd > 0 ? { resetsAt: data.planEnd } : {}),
  };

  const limits: UsageLimit[] = [];
  const prompt = creditLimit("prompt", "Prompt Credits", plan?.monthlyPromptCredits, data.usedPromptCredits, data.availablePromptCredits, window);
  const flow = creditLimit("flow", "Flow Credits", plan?.monthlyFlowCredits, data.usedFlowCredits, data.availableFlowCredits, window);
  const flex = creditLimit("flex", "Flex Credits", plan?.monthlyFlexCredits, data.usedFlexCredits, data.availableFlexCredits, window);

  if (prompt) limits.push(prompt);
  if (flow) limits.push(flow);
  if (flex) limits.push(flex);

  const isQuota = plan?.billingStrategy === 2 || plan?.billingStrategy === "QUOTA" || plan?.billingStrategy === "quota";
  const addQuota = (
    id: "daily" | "weekly",
    label: string,
    remaining: number | undefined,
    reset: number | undefined,
    hidden: boolean | undefined,
    durationMs: number
  ) => {
    if (hidden || (!isQuota && !(reset && reset > 0))) return;
    const safeRemaining = Math.max(0, Math.min(100, remaining ?? 0));
    const used = 100 - safeRemaining;
    const fraction = used / 100;
    limits.push({
      id: `devin:quota:${id}`,
      label,
      amount: {
        used,
        limit: 100,
        remaining: safeRemaining,
        usedFraction: fraction,
        unit: "percent",
      },
      window: {
        id: id === "daily" ? "1d" : "7d",
        label,
        durationMs,
        ...(reset && reset > 0 ? { resetsAt: reset * 1_000 } : {}),
      },
      status: calculateUsageStatus(fraction),
    });
  };

  addQuota("daily", "Daily Quota", data.dailyRemaining, data.dailyReset, plan?.hideDailyQuota, DAY_MS);
  addQuota("weekly", "Weekly Quota", data.weeklyRemaining, data.weeklyReset, plan?.hideWeeklyQuota, WEEK_MS);

  if (limits.length === 0) {
    throw new Error("Devin usage response contained no plan credits or quota windows");
  }

  const discoveredIdentity = data.email || data.userId || plan?.orgName || plan?.orgId;
  const resolvedLabel = !isGenericDevinLabel(credential.accountLabel)
    ? credential.accountLabel
    : (discoveredIdentity && discoveredIdentity.trim().length > 0 ? discoveredIdentity.trim() : credential.accountLabel);

   return {
     provider: PROVIDER,
     credentialId: credential.id,
    accountLabel: resolvedLabel,
    fetchedAt: Date.now(),
    limits,
  };
}

async function decodeResponse(response: Response): Promise<StatusData> {
  const bytes = new Uint8Array(await response.arrayBuffer());
  const candidates: Uint8Array[] = [bytes];
  try {
    candidates.push(new Uint8Array(gunzipSync(bytes)));
  } catch {
    // Not gzipped
  }

  for (const candidate of candidates) {
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(candidate).trim();
      if (text.startsWith("{") || text.startsWith("[")) {
        const parsed = parseJsonResponse(JSON.parse(text));
        if (parsed) return parsed;
      }
    } catch {
      // Not JSON; try protobuf
    }
    try {
      const parsed = parseProtoResponse(candidate);
      if (parsed) return parsed;
    } catch {
      // Try next candidate
    }
  }

  throw new Error("Devin usage response could not be parsed as JSON or protobuf");
}

export class DevinAdapter implements ProviderAdapter {
  readonly id = PROVIDER;

  supports(provider: string): boolean {
    const p = provider.toLowerCase();
    return p === PROVIDER || p === "devin-agent";
  }

  async fetchUsage(credential: StoredCredential, ctx?: FetchContext): Promise<UsageReport> {
    const fetchImpl = ctx?.fetch ?? fetch;
    const token = normalizeToken(credential.secret);
    const response = await fetchImpl(`${BASE_URL}${STATUS_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/proto",
        "connect-protocol-version": "1",
        accept: "*/*",
      },
      body: encodeMetadata(token) as unknown as BodyInit,
      signal: ctx?.signal,
    });

    if (!response.ok) {
      let detail = "";
      try {
        const message = (await response.text()).trim().replace(/\s+/g, " ").slice(0, 160);
        if (message) detail = `: ${message}`;
      } catch {
        // Status code alone is informative if body is unreadable
      }
      throw new Error(`Devin kullanım sorgusu başarısız: HTTP ${response.status}${detail}`);
    }

    const data = await decodeResponse(response);
    const report = buildReport(data, credential);
    const discoveredIdentity = data.email || data.userId || data.plan?.orgName || data.plan?.orgId;
    if (discoveredIdentity && discoveredIdentity.trim().length > 0 && isGenericDevinLabel(credential.accountLabel)) {
      const resolvedLabel = discoveredIdentity.trim();
      credential.accountLabel = resolvedLabel;
      if (ctx?.onTokenRefresh) {
        ctx.onTokenRefresh(credential.secret, { ...(credential.metadata || {}), ...(data.email ? { email: data.email } : {}), ...(data.userId ? { userId: data.userId } : {}) }, resolvedLabel);
      }
    }
    return report;
  }
}
