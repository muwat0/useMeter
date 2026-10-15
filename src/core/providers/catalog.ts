export type ProviderSupportTier = "live_verified" | "connection_verified" | "synthetic_only";

export type ProviderAuthMode =
  | "oauth_device"
  | "oauth_loopback_paste"
  | "oauth_callback"
  | "api_key"
  | "session_cookie";

export type ProviderQuotaKind = "window_percent" | "balance_usd" | "token_credits";

export interface ProviderCatalogEntry {
  readonly id: string;
  readonly displayName: Readonly<{ en: string; tr: string }>;
  readonly aliases: readonly string[];
  readonly authModes: readonly ProviderAuthMode[];
  readonly supportTier: ProviderSupportTier;
  readonly quotaKind: ProviderQuotaKind;
  readonly helpHint: Readonly<{ en: string; tr: string }>;
}

function freezeCatalog<const T extends readonly ProviderCatalogEntry[]>(entries: T): T {
  for (const entry of entries) {
    Object.freeze(entry.displayName);
    Object.freeze(entry.aliases);
    Object.freeze(entry.authModes);
    Object.freeze(entry.helpHint);
    Object.freeze(entry);
  }
  return Object.freeze(entries);
}

export const PROVIDER_CATALOG = freezeCatalog([
  {
    id: "openrouter",
    displayName: { en: "OpenRouter", tr: "OpenRouter" },
    aliases: [],
    authModes: ["oauth_loopback_paste", "api_key"],
    supportTier: "synthetic_only",
    quotaKind: "balance_usd",
    helpHint: {
      en: "Connect with an OpenRouter API key or complete the PKCE flow by pasting its one-time code. Balance and credit data depend on the provider response.",
      tr: "OpenRouter API anahtarıyla bağlanın veya PKCE akışında verilen tek kullanımlık kodu yapıştırın. Bakiye ve kredi verileri sağlayıcı yanıtına bağlıdır.",
    },
  },
  {
    id: "deepseek",
    displayName: { en: "DeepSeek", tr: "DeepSeek" },
    aliases: [],
    authModes: ["api_key"],
    supportTier: "synthetic_only",
    quotaKind: "balance_usd",
    helpHint: {
      en: "Use a DeepSeek Platform API key. Balance fields depend on the account and provider response.",
      tr: "DeepSeek Platform API anahtarı kullanın. Bakiye alanları hesaba ve sağlayıcı yanıtına bağlıdır.",
    },
  },
  {
    id: "anthropic",
    displayName: { en: "Anthropic Claude", tr: "Anthropic Claude" },
    aliases: ["claude"],
    authModes: ["oauth_loopback_paste"],
    supportTier: "synthetic_only",
    quotaKind: "window_percent",
    helpHint: {
      en: "Use a compatible Claude Code OAuth token or complete the browser flow and paste the callback response. Anthropic API keys are not compatible with this usage endpoint.",
      tr: "Uyumlu bir Claude Code OAuth tokenı kullanın veya tarayıcı akışını tamamlayıp callback yanıtını yapıştırın. Anthropic API anahtarları bu kullanım uç noktasıyla uyumlu değildir.",
    },
  },
  {
    id: "openai-codex",
    displayName: { en: "OpenAI ChatGPT / Codex", tr: "OpenAI ChatGPT / Codex" },
    aliases: ["codex", "chatgpt"],
    authModes: ["oauth_device"],
    supportTier: "live_verified",
    quotaKind: "window_percent",
    helpHint: {
      en: "Use the OpenAI device-authorization flow. The live-verified status covers observed Codex usage-window telemetry, not every plan or quota surface.",
      tr: "OpenAI cihaz yetkilendirme akışını kullanın. Canlı doğrulama, gözlenen Codex kullanım penceresi telemetrisini kapsar; her planı veya kota yüzeyini kapsamaz.",
    },
  },
  {
    id: "antigravity",
    displayName: { en: "Antigravity (Google AI Pro)", tr: "Antigravity (Google AI Pro)" },
    aliases: ["google-antigravity", "google", "gemini"],
    authModes: ["oauth_loopback_paste", "oauth_callback"],
    supportTier: "synthetic_only",
    quotaKind: "window_percent",
    helpHint: {
      en: "Hosted setup without operator-owned Google Web OAuth credentials uses the embedded desktop client and requires pasting the full loopback callback URL. Configure an operator-owned Web client and its exact public HTTPS callback URI for hosted callback completion.",
      tr: "Yöneticiye ait Google Web OAuth kimlik bilgileri olmadan barındırılan kurulum, gömülü masaüstü istemcisini kullanır ve tam loopback callback URL'sinin yapıştırılmasını gerektirir. Barındırılan callback'i tamamlamak için yöneticiye ait Web istemcisini ve tam public HTTPS callback URI'sini yapılandırın.",
    },
  },
  {
    id: "github-copilot",
    displayName: { en: "GitHub Copilot", tr: "GitHub Copilot" },
    aliases: ["copilot"],
    authModes: ["oauth_device"],
    supportTier: "live_verified",
    quotaKind: "window_percent",
    helpHint: {
      en: "Use GitHub device authorization. Reported quota and seat fields depend on the GitHub account and Copilot plan.",
      tr: "GitHub cihaz yetkilendirmesini kullanın. Bildirilen kota ve koltuk alanları GitHub hesabına ve Copilot planına bağlıdır.",
    },
  },
  {
    id: "cursor",
    displayName: { en: "Cursor", tr: "Cursor" },
    aliases: [],
    authModes: ["oauth_device", "session_cookie"],
    supportTier: "live_verified",
    quotaKind: "window_percent",
    helpHint: {
      en: "Use the browser OAuth flow or a compatible Cursor session cookie/token. Live verification covers observed usage-window telemetry.",
      tr: "Tarayıcı OAuth akışını veya uyumlu Cursor oturum çerezini/tokenını kullanın. Canlı doğrulama, gözlenen kullanım penceresi telemetrisini kapsar.",
    },
  },
  {
    id: "xai-oauth",
    displayName: { en: "xAI Grok", tr: "xAI Grok" },
    aliases: ["xai", "grok"],
    authModes: ["oauth_device"],
    supportTier: "live_verified",
    quotaKind: "window_percent",
    helpHint: {
      en: "Use the xAI OAuth device flow or a compatible xAI OAuth access token; an xAI API key is not a substitute for this endpoint's OAuth credential.",
      tr: "xAI OAuth cihaz akışını veya uyumlu xAI OAuth erişim tokenını kullanın; xAI API anahtarı bu uç noktanın OAuth kimlik bilgisinin yerine geçmez.",
    },
  },
  {
    id: "zai",
    displayName: { en: "Zhipu AI (GLM / Z.ai)", tr: "Zhipu AI (GLM / Z.ai)" },
    aliases: ["zhipu", "glm"],
    authModes: ["oauth_loopback_paste", "api_key"],
    supportTier: "synthetic_only",
    quotaKind: "window_percent",
    helpHint: {
      en: "Complete the Z.ai/Zhipu OAuth flow and paste the registered callback URL, or provide a compatible bearer credential. Returned quota windows depend on the account.",
      tr: "Z.ai/Zhipu OAuth akışını tamamlayıp kayıtlı callback URL'sini yapıştırın veya uyumlu bir bearer kimlik bilgisi girin. Dönen kota pencereleri hesaba bağlıdır.",
    },
  },
  {
    id: "minimax-code",
    displayName: { en: "MiniMax Code", tr: "MiniMax Code" },
    aliases: ["minimax"],
    authModes: ["api_key"],
    supportTier: "synthetic_only",
    quotaKind: "window_percent",
    helpHint: {
      en: "Provide a MiniMax Code access key for a token-plan account. The reported windows and reset details depend on the provider response.",
      tr: "Token planı hesabı için MiniMax Code erişim anahtarı girin. Bildirilen pencereler ve sıfırlanma bilgileri sağlayıcı yanıtına bağlıdır.",
    },
  },
  {
    id: "cline-pass",
    displayName: { en: "Cline Pass", tr: "Cline Pass" },
    aliases: ["clinepass"],
    authModes: ["api_key"],
    supportTier: "synthetic_only",
    quotaKind: "window_percent",
    helpHint: {
      en: "Use a Cline Pass usage API key. The adapter reports percentage-based windows; it does not report a monetary balance or token-credit balance.",
      tr: "Cline Pass kullanım API anahtarını kullanın. Adaptör yüzde tabanlı pencereleri bildirir; parasal bakiye veya token-kredi bakiyesi bildirmez.",
    },
  },
  {
    id: "devin",
    displayName: { en: "Devin", tr: "Devin" },
    aliases: ["devin-agent"],
    authModes: ["oauth_callback", "session_cookie"],
    supportTier: "synthetic_only",
    quotaKind: "token_credits",
    helpHint: {
      en: "Only an existing compatible Devin CLI session token is supported; cog_ V3 personal access tokens are unsupported. Hosted OAuth redirect compatibility is experimental and unverified.",
      tr: "Yalnızca mevcut ve uyumlu Devin CLI oturum tokenı desteklenir; cog_ V3 kişisel erişim tokenları desteklenmez. Barındırılan OAuth yönlendirme uyumluluğu deneyseldir ve doğrulanmamıştır.",
    },
  },
  {
    id: "umans",
    displayName: { en: "Umans", tr: "Umans" },
    aliases: [],
    authModes: ["api_key"],
    supportTier: "synthetic_only",
    quotaKind: "token_credits",
    helpHint: {
      en: "Use an Umans Code usage API key. The adapter reports provider request counters and available plan data, not a USD balance.",
      tr: "Umans Code kullanım API anahtarını kullanın. Adaptör sağlayıcı istek sayaçlarını ve varsa plan verilerini bildirir; USD bakiyesi bildirmez.",
    },
  },
  {
    id: "google-gemini-cli",
    displayName: { en: "Google Gemini CLI", tr: "Google Gemini CLI" },
    aliases: ["gemini-cli"],
    authModes: ["oauth_loopback_paste"],
    supportTier: "synthetic_only",
    quotaKind: "window_percent",
    helpHint: {
      en: "Complete the Gemini CLI OAuth flow and paste the full registered loopback callback URL. This adapter is separate from Antigravity and has not been live-verified.",
      tr: "Gemini CLI OAuth akışını tamamlayıp kayıtlı loopback callback URL'sinin tamamını yapıştırın. Bu adaptör Antigravity'den ayrıdır ve canlı doğrulanmamıştır.",
    },
  },
  {
    id: "kimi-code",
    displayName: { en: "Kimi Code (Moonshot)", tr: "Kimi Code (Moonshot)" },
    aliases: ["kimi", "kimi_code", "moonshot"],
    authModes: ["oauth_device"],
    supportTier: "connection_verified",
    quotaKind: "window_percent",
    helpHint: {
      en: "Connection verified only: the account connected, but no quota data was observed. A neutral no-quota result does not establish membership, plan, or region; standard API keys are not accepted by this usage endpoint.",
      tr: "Yalnızca bağlantı doğrulandı: hesap bağlandı ancak kota verisi gözlenmedi. Kota bildirmeyen nötr sonuç üyeliği, planı veya bölgeyi göstermez; standart API anahtarları bu kullanım uç noktası tarafından kabul edilmez.",
    },
  },
  {
    id: "opencode-go",
    displayName: { en: "OpenCode Go", tr: "OpenCode Go" },
    aliases: ["opencode_go", "opencode"],
    authModes: ["api_key"],
    supportTier: "synthetic_only",
    quotaKind: "window_percent",
    helpHint: {
      en: "Provide an API key for an active OpenCode Go subscription. Plan and reset fields depend on the provider response.",
      tr: "Aktif OpenCode Go aboneliğine ait API anahtarını girin. Plan ve sıfırlanma alanları sağlayıcı yanıtına bağlıdır.",
    },
  },
  {
    id: "alibaba-token-plan",
    displayName: { en: "Alibaba Qwen", tr: "Alibaba Qwen" },
    aliases: ["alibaba_token_plan", "alibabatokenplan", "qwen-token-plan", "qwencloud-token-plan", "bailian-token-plan"],
    authModes: ["api_key", "session_cookie"],
    supportTier: "synthetic_only",
    quotaKind: "window_percent",
    helpHint: {
      en: "Use a supported Alibaba/Qwen token-plan API key with the required console session cookie. OAuth credentials are not supported; plan and expiry fields depend on the provider response.",
      tr: "Gerekli konsol oturum çereziyle desteklenen Alibaba/Qwen token-plan API anahtarını kullanın. OAuth kimlik bilgileri desteklenmez; plan ve sona erme alanları sağlayıcı yanıtına bağlıdır.",
    },
  },
] as const satisfies readonly ProviderCatalogEntry[]);

export function getProviderCatalog(): readonly ProviderCatalogEntry[] {
  return PROVIDER_CATALOG;
}

export function findCatalogEntry(idOrAlias: string): ProviderCatalogEntry | undefined {
  const normalized = idOrAlias.trim().toLowerCase();
  if (!normalized) return undefined;
  return PROVIDER_CATALOG.find(entry =>
    entry.id === normalized || entry.aliases.some(alias => alias === normalized),
  );
}
