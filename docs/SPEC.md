# SPEC.md — AI Kota, Bakiye ve Kullanım Takip Sistemi Teknik Şartnamesi

- **Versiyon:** 1.0.0
- **Tarih:** 2026-09-13
- **Referanslar:** [CONTEXT.md](../CONTEXT.md), [ADR-0001](adr/0001-self-hosted-bff-architecture.md), [ADR-0002](adr/0002-dual-engine-tracking-model.md)

---

## 1. Sisteme Genel Bakış

Bu sistem; geliştiricilerin ve yapay zeka kullanıcılarının birden fazla AI sağlayıcısı üzerindeki (OpenRouter, DeepSeek, OpenAI Codex, Anthropic Claude, Google Antigravity, Cursor vb.) anlık bakiyelerini ($), kalan kullanım kotalarını (%) ve sıfırlanma sayaçlarını (resetsAt) tek bir self-hosted panel üzerinden gerçek zamanlı izlemelerini sağlayan hafif bir servis katmanıdır.

---

## 2. Modül Mimarisi ve Dikiş Noktaları (Deep Modules & Seams)

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

export interface UsageReport {
  provider: string;
  accountId?: string;
  accountLabel?: string;
  fetchedAt: number;
  limits: UsageLimit[];
  raw?: unknown;
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
SQLite veri tabanı üzerinde çalışır. Hassas alanlar (API key, OAuth refresh token) **AES-256-GCM** ile şifrelenir.

```typescript
export interface StorageVault {
  // Kimlik Yönetimi
  saveCredential(cred: InputCredential): Promise<StoredCredential>;
  listCredentials(provider?: string): Promise<StoredCredential[]>;
  deleteCredential(id: string): Promise<boolean>;

  // Kullanım Geçmişi ve Anlık Durum
  saveUsageSnapshot(report: UsageReport): Promise<void>;
  getLatestUsage(): Promise<UsageReport[]>;
  getUsageHistory(query: HistoryQuery): Promise<UsageHistoryRow[]>;

  // Sağlık Kontrolü
  checkIntegrity(): Promise<boolean>;
}
```

#### Veritabanı Şeması (SQLite)
```sql
CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    account_label TEXT NOT NULL,
    credential_type TEXT NOT NULL, -- 'api_key', 'oauth', 'cookie'
    encrypted_secret TEXT NOT NULL,
    iv TEXT NOT NULL,
    tag TEXT NOT NULL,
    metadata JSON,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    window_id TEXT NOT NULL,
    used_fraction REAL,
    remaining REAL,
    unit TEXT NOT NULL,
    resets_at INTEGER,
    status TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,
    FOREIGN KEY(credential_id) REFERENCES credentials(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_usage_cred_recorded ON usage_snapshots(credential_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_provider ON usage_snapshots(provider, recorded_at DESC);
```

---

### Modül 3: Aktif Yoklayıcı Daemon (`src/core/poller/`)
Arka planda periyodik olarak çalışan zamanlayıcıdır.

```typescript
export interface PollerEngine {
  start(): void;
  stop(): void;
  pollNow(credentialId?: string): Promise<UsageReport[]>;
  onReport(callback: (report: UsageReport) => void): void;
}
```

- **Mekanizma:**
  1. Base interval: `5 dakika`.
  2. Her sağlayıcı/hesap için ±%25 rastgele gecikme (jitter) eklenir.
  3. `SingleFlight` haritası ile aynı kimlik için eşzamanlı mükerrer istekler birleştirilir.
  4. 429 veya geçici hata alındığında exponential backoff (15s, 30s, 60s) devreye girer; son geçerli veri (`lastGood`) korunur.

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

Hono çerçevesi ile sunulan REST ve Server-Sent Events (SSE) rotaları:

- `GET /api/usage` → Tüm sağlayıcıların güncel bakiye ve kota listesi.
- `GET /api/usage/:id/history` → Belirli bir hesabın son 24 saat / 7 günlük trend verisi.
- `POST /api/credentials` → Yeni anahtar/token kaydı (sunucuda şifrelenir).
- `DELETE /api/credentials/:id` → Kimlik silme.
- `POST /api/poll` → Tüm kotaları anında manuel yenileme (Force refresh).
- `GET /api/events` → SSE akışı (Dashboard açıkken kota değiştikçe anında UI güncellemesi).
- `GET /health` → Sistem durumu ve SQLite bütünlük kontrolü.
