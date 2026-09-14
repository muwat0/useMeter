# SPEC.md — useMeter: AI Kota, Bakiye ve Kullanım Takip Sistemi Teknik Şartnamesi

- **Versiyon:** 1.0.0
- **Tarih:** 2026-09-13
- **Referanslar:** [CONTEXT.md](../CONTEXT.md), [ADR-0001](adr/0001-self-hosted-bff-architecture.md), [ADR-0002](adr/0002-dual-engine-tracking-model.md), [ADR-0003](adr/0003-multi-tenant-session-authentication.md), [ADR-0004](adr/0004-security-perimeter-and-invitation-onboarding.md), [ADR-0005](adr/0005-nondestructive-stale-usage-state.md)
- **Kabul Edilen ADR'ler:** [ADR-0001](adr/0001-self-hosted-bff-architecture.md), [ADR-0002](adr/0002-dual-engine-tracking-model.md), [ADR-0003](adr/0003-multi-tenant-session-authentication.md), [ADR-0004](adr/0004-security-perimeter-and-invitation-onboarding.md), [ADR-0005](adr/0005-nondestructive-stale-usage-state.md)
---

## 1. Sisteme Genel Bakış

Bu sistem; geliştiricilerin ve yetkili kullanıcıların birden fazla AI sağlayıcısı üzerindeki (OpenRouter, DeepSeek, OpenAI Codex, Anthropic Claude, Google Antigravity, Cursor vb.) anlık bakiyelerini ($), kalan kullanım kotalarını (%) ve sıfırlanma sayaçlarını (`resetsAt`) izlemelerini sağlayan **özel çok kullanıcılı (private multi-user SaaS)** bir servis katmanıdır.

Sistem, tek bir kullanıcının yerel masaüstü paneli olmaktan çıkarak kullanıcı bazlı kimlik doğrulama, satır düzeyinde kiracı izolasyonu (`ownerId`), oturum güvenliği ve yetkilendirilmiş API erişimi ilkeleriyle çalışır.

---

## 2. Kullanıcı Kimlik Doğrulama ve Oturum Yönetimi (Authentication & Session Lifecycle)

### Temel İlkeler ve Kurallar
1. **Kullanıcı Hesabı (User Identity):** Sisteme e-posta ve parola çifti ile kaydolunur (`register`) ve giriş yapılır (`login`).
   - **E-posta Kuralları:** `trim().toLowerCase()` ile kanonikleştirilir. Büyük/küçük harf duyarsız benzersizdir (case-insensitively unique).
   - **Parola Kuralları:** Minimum 12 karakter, maksimum 256 UTF-8 karakter/kod birimi. Deterministik girdi doğrulaması uygulanır.
   - **Parola Hashleme:** Bun çalışma zamanının yerel `Bun.password` Argon2id algoritması kullanılır (`algorithm: "argon2id"`).
2. **Oturum Modeli (Session Security):**
   - Oturumlar durum bilgili (stateful) sunucu oturumlarıdır; durumu istemcide taşıyan JWT kullanılmaz.
   - Giriş başarılı olduğunda istemciye `auth_session` çerezinde **32 baytlık kriptografik olarak güvenli rastgele opak belirteç (opaque token)** döndürülür (`crypto.getRandomValues`).
   - **Kalıcılık:** Veritabanında oturum belirtecinin açık hali ASLA saklanmaz; yalnızca SHA-256 hash özeti (`token_hash`) saklanır.
   - **Geçerlilik Süresi (TTL):** Oturumlar oluşturulduğu andan itibaren 30 gün geçerlidir (`2592000` saniye). Çıkış yapıldığında (`logout`) oturum kaydı veritabanından silinir.
3. **Çerez Politikası (Cookie Posture):**
   - `Name`: `auth_session`
   - `HttpOnly`: `true` (JavaScript üzerinden okunamaz, XSS'e karşı korumalı).
   - `SameSite`: `Lax` (CSRF koruması sağlar, üst düzey gezinmelerde çalışır).
   - `Path`: `/`
   - `Secure`: Production veya HTTPS ortamlarında `true`.
4. **Zaman Aşımı ve Hata İzolasyonu (Security Enumeration Defense):**
   - `login` işleminde geçersiz e-posta veya yanlış parola durumunda aynı genel etki alanı hatası (`Invalid email or password`) fırlatılır; saldırganın sistemde bir e-postanın kayıtlı olup olmadığını öğrenmesine (user enumeration) izin verilmez.

### Kimlik Doğrulama Servis Arayüzü (`AuthService`)
```typescript
export interface User {
  id: string;
  email: string;
  createdAt: number;
  updatedAt: number;
}

export interface Session {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: number;
  createdAt: number;
  lastUsedAt: number;
}

export interface AuthService {
  register(email: string, password: string): Promise<{ user: User; sessionToken: string }>;
  login(email: string, password: string): Promise<{ user: User; sessionToken: string }>;
  authenticate(token: string): Promise<User | null>;
  logout(token: string): Promise<void>;
}
```

## 3. Modül Mimarisi ve Dikiş Noktaları (Deep Modules & Seams)

Sistem, John Ousterhout'un *"Derin Modül (Deep Module)"* felsefesine uygun olarak tasarlanmıştır. Her modül, küçük ve yalın bir genel arayüz (public interface) arkasında karmaşık mantığı (şifreleme, ağ geri çekilmeleri, veri dönüşümleri) hapseder.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          UYGULAMA ÇEKİRDEĞİ                            │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ 1. Storage Vault  │ 2. Poller Daemon  │ 3. Ingress Proxy               │
│ (Şifreli SQLite)  │ (Jitter + Lock)   │ (Header Yakalayıcı)            │
├───────────────────┴───────────────────┴────────────────────────────────┤
│                     4. Provider Adapters Seam                          │
│                     fetchUsage(credential) -> Report                   │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ • DeepSeek        │ • OpenRouter      │ • Anthropic Claude             │
│ • OpenAI Codex    │ • Antigravity     │ • Cursor                       │
├───────────────────┴───────────────────┴────────────────────────────────┤
│ 5. Notification Engine (Telegram / ntfy / Discord)                     │
├────────────────────────────────────────────────────────────────────────┤
│ 6. HTTP API & SSE Gateway (Hono) -> React Dashboard UI                │
└────────────────────────────────────────────────────────────────────────┘
```

### Modül 1: Sağlayıcı Adaptör Dikiş Noktası (`src/core/providers/`)
Tüm sağlayıcılar tek bir dikiş noktası (seam interface) üzerinden sisteme bağlanır:

```typescript
export type UsageUnit = "percent" | "tokens" | "requests" | "credits" | "usd";
export type UsageStatus = "ok" | "warning" | "exhausted" | "unknown";

export interface UsageLimit {
  id: string;               // örn: "5h", "weekly_sonnet", "balance_usd"
  label: string;            // örn: "5 Saatlik Kayan Pencere"
  amount: {
    used?: number;
    limit?: number;
    remaining?: number;
    usedFraction?: number;  // 0.0 - 1.0 (1.0 = tükendi)
    unit: UsageUnit;
  };
  window?: {
    id: string;             // "5h", "7d", "monthly"
    durationMs?: number;
    resetsAt?: number;      // Epoch ms
    resetLabel?: string;    // "resets" / "regen"
  };
  status: UsageStatus;
  notes?: string[];
}

export type UsageReportHealth = "healthy" | "stale" | "error";
export type UsageReportSource = "live" | "stale" | "error";

export interface UsageReport {
  ownerId?: string;
  provider: string;
  credentialId?: string;
  accountId?: string;
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

export interface ProviderAdapter {
  id: string;
  supports(provider: string): boolean;
  fetchUsage(credential: StoredCredential, context: FetchContext): Promise<UsageReport>;
  parseHeaders?(headers: Headers, now?: number): UsageReport | null;
}
```

- **Derinlik:** Çağıran katman sağlayıcının OAuth mu, token mı yoksa özel bir dahili JSON mu kullandığını bilmez; sadece `fetchUsage(cred)` çağırır ve normalize `UsageReport` alır.

---

### Modül 2: Güvenli Kasa ve Veri Katmanı (`src/core/storage/`)
SQLite veritabanı (WAL modunda) üzerinde çalışır. Yabancı anahtarlar (`PRAGMA foreign_keys = ON;`) ve indeksler aktiftir.
Hassas sağlayıcı alanları (API key, OAuth refresh token) **AES-256-GCM** ile şifrelenir.

Tüm kimlik ve kullanım sorguları, arka plan yoklayıcısının açıkça tanımlanmış tek dahili metodu (`listAllCredentialsInternal`) hariç, zorunlu olarak **`ownerId`** parametresi gerektirir.

```typescript
export interface StorageVault {
  // Çok Kiracılı Kimlik Yönetimi
  saveCredential(cred: InputCredential, ownerId: string): Promise<StoredCredential>;
  listCredentials(ownerId: string, provider?: string): Promise<StoredCredential[]>;
  getCredential(id: string, ownerId: string): Promise<StoredCredential | null>;
  deleteCredential(id: string, ownerId: string): Promise<boolean>;

  // Yalnızca Dahili Arka Plan Yoklayıcı İçin (Internal Poller Daemon Only)
  listAllCredentialsInternal(): Promise<StoredCredential[]>;

  // Kullanım Geçmişi ve Anlık Durum (Kullanıcı İzolasyonlu)
  saveUsageSnapshot(report: UsageReport, ownerId: string): Promise<void>;
  getLatestUsage(ownerId: string): Promise<UsageReport[]>;
  getUsageHistory(ownerId: string, query: HistoryQuery): Promise<UsageHistoryRow[]>;

  // Eski Veri Sahiplenme (Migration)
  claimLegacyCredentials(newOwnerId: string): Promise<{ claimedCredentials: number; claimedSnapshots: number }>;

  // Sağlık Kontrolü
  checkIntegrity(): Promise<boolean>;
}
```

#### Veritabanı Şeması (SQLite)
```sql
-- Kullanıcılar Tablosu
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users(email);

-- Oturumlar Tablosu
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Sağlayıcı Kimlik Bilgileri Tablosu
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    owner_id TEXT, -- NULL ise eski tek kullanıcılı sistemden devrolacak kayıt
    provider TEXT NOT NULL,
    account_label TEXT NOT NULL,
    credential_type TEXT NOT NULL, -- 'api_key', 'oauth', 'cookie'
    encrypted_secret TEXT NOT NULL,
    iv TEXT NOT NULL,
    tag TEXT NOT NULL,
    metadata JSON,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_credentials_owner_provider ON credentials(owner_id, provider);
CREATE INDEX IF NOT EXISTS idx_credentials_owner_id ON credentials(owner_id);

-- Kullanım Anlık Görüntüleri Tablosu
CREATE TABLE IF NOT EXISTS usage_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT, -- NULL ise eski kayıttan sahiplenilecek
    credential_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    window_id TEXT NOT NULL,
    used_fraction REAL,
    remaining REAL,
    unit TEXT NOT NULL,
    resets_at INTEGER,
    status TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_usage_owner_recorded ON usage_snapshots(owner_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_cred_recorded ON usage_snapshots(credential_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_provider ON usage_snapshots(provider, recorded_at DESC);
```

-- Davetiyeler Tablosu
CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE, -- Yönetici tarafından zorunlu atanan hedef e-posta
    token_hash TEXT NOT NULL UNIQUE,     -- 32-bayt ham token'ın tek yönlü SHA-256 hash'i
    created_by TEXT NOT NULL,           -- Davetiyeyi oluşturan admin user ID
    expires_at INTEGER NOT NULL,        -- 24 saatlik süre sonu (Epoch ms)
    accepted_at INTEGER,                -- Kullanıldığı zaman damgası (Epoch ms)
    revoked_at INTEGER,                 -- İptal edildiği zaman damgası (Epoch ms)
    created_at INTEGER NOT NULL,        -- Oluşturulma zamanı (Epoch ms)
    FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON invitations(created_by);

#### Eski Verilerin Atomik Sahiplenilmesi (First-User Legacy Claim)
Tek kullanıcılı sürümden gelen ve `owner_id` değeri `NULL` olan tüm kayıtlar, sisteme kaydolan ilk gerçek kullanıcı (`users` tablosundaki ilk kayıt) tarafından tek bir SQLite transaction'ı içinde atomik olarak sahiplenilir:
```sql
-- İlk kullanıcı kaydında otomatik işletilir:
UPDATE credentials SET owner_id = :firstUserId WHERE owner_id IS NULL;
UPDATE usage_snapshots SET owner_id = :firstUserId WHERE owner_id IS NULL;
```
Bu işlemden sonra veya sisteme sonradan kaydolan kullanıcılar için sahipsiz kayıt kalmaz; diğer kullanıcılar yalnızca kendi ekledikleri kimlik bilgilerini ve kotalarını görür.

### Modül 3: Aktif Yoklayıcı Daemon (`src/core/poller/`)
Arka planda periyodik olarak çalışan zamanlayıcıdır.

```typescript
export interface PollerEngine {
  start(): void;
  stop(): void;
  pollAllInternal(): Promise<UsageReport[]>;
  pollOwner(ownerId: string, credentialId?: string): Promise<UsageReport[]>;
  onReport(callback: (report: UsageReport, ownerId?: string) => void): void;
}
```

- **Genel Daemon vs Kullanıcı Odaklı Manuel Tetikleme:**
  1. **Arka Plan Yoklayıcı Daemon:** Sunucu sürecinde 7/24 çalışır. `listAllCredentialsInternal()` çağırarak kayıtlı tüm kimlik bilgilerini sırayla ve jitter ile günceller.
  2. **Kullanıcı Tetiklemeli Manuel Yenileme (`POST /api/refresh`):** Yalnızca aktif oturum sahibi kullanıcının `ownerId` değerine ait kimlikleri yoklar. Bir kullanıcının diğer kullanıcıların hesaplarını yoklaması veya kotalarını tetiklemesi engellenir.
- **Mekanizma:**
  1. Base interval: `5 dakika`.
  2. Her sağlayıcı/hesap için ±%25 rastgele gecikme (jitter) eklenir.
  3. `SingleFlight` haritası ile aynı kimlik için eşzamanlı mükerrer istekler birleştirilir.
  4. **Yıkıcı Olmayan Hata Yönetimi ve Durum Makinesi (Non-destructive Stale State Machine):**
     Yoklama başarısız olduğunda sistem telemetriyi silmez; son başarılı durumu (`lastGood`) korur:
     - **İlk Başarılı Yoklama:** `health: "healthy"`, `stale: false`, `source: "live"`, `lastGoodFetchedAt: fetchedAt`, `limits: [...]`.
     - **Sonraki Ağ / Sağlayıcı Hatası:** Son başarılı limitler (`lastGood.limits`) korunur; rapor `health: "stale"`, `stale: true`, `source: "stale"`, `lastGoodFetchedAt: lastGood.fetchedAt`, `error: message` olarak güncellenir.
     - **İlk Seferde Hata (Geçmiş Veri Yok):** `health: "error"`, `stale: false`, `source: "error"`, `limits: []`, `lastGoodFetchedAt: undefined`, `error: message`.
     - **Yeniden Başarılı Yoklama:** Sistem otomatik olarak `health: "healthy"`, `stale: false`, `source: "live"` durumuna döner, `error` temizlenir.
     - **Sağlayıcı Kota Tükenmesi Ayrımı:** Sağlayıcının `%100` kota doluluğu dönmesi (HTTP 200) bir yoklama arızası değil, normal bir telemetri verisidir (`health: "healthy"` kalır).
     - **Güvenlik Sınırı:** Ham upstream hata gövdeleri veya hassas istek verileri anlık görüntülerde veya rapor nesnelerinde ASLA saklanmaz.
  5. 429 veya geçici hata alındığında exponential backoff (15s, 30s, 60s) devreye girer.
---

### Modül 4: Pasif Vekil Geçit (`src/core/proxy/`)
OpenAI uyumlu istekleri yakalayan isteğe bağlı yerel middleware katmanıdır.

- **Uç Nokta:** `POST /v1/chat/completions`
- **İşleyiş:**
  1. İstemciden gelen isteği orijinal upstream sağlayıcıya iletir (streaming destekli).
  2. Dönen HTTP yanıt başlıklarını (`anthropic-ratelimit-unified-*`, `x-codex-*`, `x-ratelimit-*`) eşzamanlı olarak `adapter.parseHeaders()` fonksiyonuna verir.
  3. Eğer kota doluluğu `%100` (veya eşik üstü) ise anında `StorageVault` güncellenir ve SSE ile frontend'e basılır.

---

### Modül 5: Alarm Motoru (`src/core/notifier/`)
Eşik aşımlarında harici kanallara asenkron sinyal gönderir:

```typescript
export interface AlertEvent {
  provider: string;
  accountLabel: string;
  metric: string;        // "5h_quota", "balance_usd"
  currentValue: number;  // 0.92 veya 1.50
  threshold: number;     // 0.90 veya 2.00
  resetsAt?: number;
  type: "warning" | "exhausted" | "recovered";
}

export interface Notifier {
  send(event: AlertEvent): Promise<void>;
}
```
- **Desteklenen Kanallar:**
  1. **ntfy:** `POST https://ntfy.muwat.org/<topic>` (Sıfır bağımlılık, anında bildirim).
  2. **Telegram Bot:** `sendMessage` API'si üzerinden Markdown formatlı kart.
  3. **Discord Webhook:** Renkli embed mesajı.

---

### Modül 6: HTTP API & Arayüz Katmanı (`src/server/`)

Hono çerçevesi ile sunulan REST ve Server-Sent Events (SSE) rotaları. Tüm panel ve veri uç noktaları oturum doğrulaması (`auth_session` cookie) gerektirir; açık/anonim erişime kapalıdır.

#### Açık (Public) Rotalar:
- `POST /api/auth/register` → Yeni kullanıcı kaydı oluşturur, oturum çerezi atar (`auth_session`).
- `POST /api/auth/login` → Kullanıcı girişi yapar, oturum çerezi atar.
- `POST /api/auth/logout` → Aktif oturumu geçersiz kılar ve çerezi siler.
- `GET /health` → Sistem durumu ve SQLite bütünlük kontrolü (hassas veri içermez).
- `GET /invite/:token` → Davetiye kabul sayfası (token geçerliliği denetlenir, atanmış e-posta salt okunur kilitli gösterilir).
- `POST /api/invitations/:token/accept` → Davetiyeyi kabul ederek yeni kullanıcı oluşturma (public registration kapalı olsa dahi çalışır).

#### Korumalı (Protected) Rotalar (Geçerli Oturum Çerezi Zorunlu):
- `GET /` → Canlı Web Dashboard arayüzü (oturum yoksa `/login` yönlendirmesi).
- `GET /api/me` → Oturum açmış kullanıcının temel bilgileri (`id`, `email`).
- `GET /api/usage` → Oturum açmış kullanıcının (`ownerId`) sağlayıcı bakiye ve kota listesi.
- `GET /api/usage/:id/history` → Oturum açmış kullanıcının belirli bir hesabına ait trend verisi.
- `POST /api/credentials` → Kullanıcıya ait yeni sağlayıcı kimliği kaydetme (`ownerId` oturumdan alınır).
- `DELETE /api/credentials/:id` → Kullanıcıya ait kimliği silme (yalnızca sahibi silebilir).
- `POST /api/refresh` → Kullanıcının kendi hesaplarını anında manuel yenilemesi (Force refresh).
- `GET /api/events` → SSE akışı (Dashboard açıkken kullanıcının kendi kotalarına ait canlı güncellemeler).

#### Yönetici (Admin) Rotaları (`user.role === "admin"` Zorunlu, Yetkisizler 403):
- `GET /admin` → Canlı Sistem Yönetici Paneli (kullanıcı tablosu, sistem istatistikleri, sağlayıcı dağılımı).
- `GET /api/admin/stats` → Sistem genel telemetrisi (toplam kullanıcı, aktif oturum, DB boyutu, sağlayıcı hesap sayıları).
- `GET /api/admin/users` → Sistemdeki tüm kullanıcıların listesi (hesap ve aktif oturum sayılarıyla).
- `PATCH /api/admin/users/:id/role` → Kullanıcı rolünü güncelleme (`admin` / `user`). Son yönetici düşürülemez.
- `DELETE /api/admin/users/:id` → Kullanıcıyı silme (ilişkili verileri cascade silinir; yönetici kendi hesabını veya son yöneticiyi silemez).
- `GET /api/admin/settings` → Sistem ayarlarını sorgulama (`registrationAllowed`).
- `PATCH /api/admin/settings/registration` → Genel dış kayıtları açma veya kapatma.
- `GET /api/admin/invitations` → Sistemdeki tüm davetiyeleri listeleme (ham token_hash gizlenir).
- `POST /api/admin/invitations` → Yeni tek kullanımlık davetiye üretme (hedef `email` zorunlu, 24 saat geçerli).
- `DELETE /api/admin/invitations/:id` → Aktif bir davetiyeyi iptal etme (`revoked_at`).

---

## 4. Güvenlik Çevresi Mimarisi (`src/server/security.ts`)

Sistem, tarayıcı ve ağ düzeyindeki saldırılara karşı katmanlı bir güvenlik çevresi (`security perimeter`) ile korunmaktadır.

### 4.1. Yanıt Güvenlik Başlıkları & CSP
Tüm HTTP yanıtlarına standart güvenlik başlıkları uygulanır:

```typescript
export const MINIMAL_SSR_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");
```

- **Başlıklar:**
  - `X-Frame-Options: DENY` (Clickjacking koruması).
  - `X-Content-Type-Options: nosniff` (MIME sniffing engeli).
  - `Referrer-Policy: strict-origin-when-cross-origin`.
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (Yalnızca `secure: true` veya HTTPS üretim ortamlarında).
- **CSP Tasarım Kararı ve Kısıt:** useMeter'ın sunucu taraflı HTML üretimi (SSR), gömülü tema/dil scriptleri ve Tailwind CDN kullanımını bozmamak için `'unsafe-inline'` direktifleri kasıtlı olarak tercih edilmiştir. Template motoru nonce enjekte etmediği için gerçekte var olmayan nonce/hash korumaları iddia edilmez.

### 4.2. CORS İzin Listesi ve Güvenli Köken Çözümleme
- **Ortam Değişkenleri:** `CORS_ALLOWED_ORIGINS` veya `USEMETER_ALLOWED_ORIGINS` (virgülle veya boşlukla ayrılmış origin listesi).
- **Aynı Köken Varsayılanı (Same-Origin Default):** Değişken tanımlanmamışsa sistem yalnızca gelen isteğin kendi kökenine (`requestOrigin`) izin verir.
- **Kimlikli İsteklerde Joker Karakter Yasağı:** `allowCredentials: true` (`auth_session` çerezi) geçerli olduğunda RFC 6454 gereği `*` (wildcard) kesinlikle reddedilir (`false`).

### 4.3. Güvenli İstemci IP Çözümlemesi (`TRUST_PROXY`)
- **Varsayılan Davranış:** `trustProxy` kapalıdır (`false`). İstemci tarafından gönderilen `X-Forwarded-For` veya `X-Real-IP` başlıkları IP sahteciliği (spoofing) ve rate-limit atlatma risklerine karşı **kesinlikle yok sayılır**; doğrudan soket uzak adresi kullanılır.
- **Ters Vekil Desteği:** Sistem Nginx, Caddy veya Cloudflare arkasında çalışıyorsa `TRUST_PROXY=true` veya `TRUST_PROXY=1` tanımlanmalıdır. Bu durumda `X-Forwarded-For` zincirindeki en soldaki (istemciye ait) geçerli IP adresi güvenle ayıklanır.

### 4.4. Sınırlandırılmış Bellek-İçi Hız Sınırlayıcı (Bounded In-Memory RateLimiter)
Bellek sızıntılarını önlemek için en fazla 10.000 benzersiz anahtar tutan (`maxKeys: 10000`), kayan pencere (sliding window) ve deterministik zaman dikişi (`now()` seam) ile çalışan hız sınırlayıcı:
- **Kimlik Doğrulama (`auth`):** `5 istek / dakika / IP` (`POST /api/auth/login`, `POST /api/auth/register`).
- **Manuel Kota Yoklama (`manualPoll`):** `1 istek / 30 saniye / kullanıcı + credential` (`POST /api/refresh`).
- **OAuth Cihaz Akışı Yoklama (`oauthDevicePoll`):** `30 istek / dakika / kullanıcı + flow`.
- **Hata Yanıtı:** Limit aşıldığında HTTP `429 Too Many Requests` ve `Retry-After` başlığı döndürülür.

---

## 5. Yönetici Davetiye Sistemi ve Kullanıcı Kabulü (Admin Invitation Onboarding)

Genel kayıtların kapalı olduğu özel kurulumlarda güvenli kullanıcı katılımını sağlar.

### 5.1. Davetiye Yaşam Döngüsü ve Kuralları
1. **Yalnızca Yönetici Üretimi:** Davetiyeleri yalnızca `admin` rolündeki kullanıcılar oluşturabilir (`POST /api/admin/invitations`).
2. **Kriptografik Token ve Tek Yönlü Hash:**
   - İstemciye 32 baytlık rastgele güvenli dize (`crypto.getRandomValues`) verilir (`token`).
   - Veritabanında (`invitations` tablosu) ham token ASLA saklanmaz; yalnızca `sha256(token)` özeti (`token_hash`) saklanır.
3. **Tek Kullanımlık ve 24 Saat Geçerlilik:**
   - Her davetiye 24 saat (`86400000` ms) sonra zaman aşımına uğrar (`expired`).
   - Bir kez kabul edilen davetiye `accepted_at` ile işaretlenir ve tekrar kullanılamaz.
   - Yönetici davetiyeyi dilediğinde iptal edebilir (`DELETE /api/admin/invitations/:id` -> `revoked_at`).
4. **Zorunlu E-posta Kilidi (Strict Email Binding):**
   - Davetiye üretilirken yöneticinin geçerli bir hedef e-posta adresi belirtmesi zorunludur (`email`); anonim veya e-postasız serbest davetiye üretilemez.
   - Kabul formunda (`/invite/:token`) e-posta alanı salt okunur olarak kilitlenir ve kayıt işlemi doğrudan bu e-posta ile tamamlanır (`COLLATE NOCASE`).
5. **Dış Kayıt Kapatma Politikasını Aşma (Registration Bypass):**
   - Yönetici sistem ayarlarından dış kayıtları kapatmış olsa bile (`isRegistrationAllowed() === false`), geçerli bir davetiye token'ı sunan kullanıcı başarıyla kaydolur.
6. **E-posta Gönderim Sınırı (No SMTP Boundary):**
   - useMeter bünyesinde hiçbir SMTP sunucusu veya giden e-posta iletim altyapısı bulunmaz.
   - Yönetici oluşturulan davet bağlantısını (`/invite/:token`) panodan kopyalar ve kullanıcıya harici güvenli yollarla iletir.
