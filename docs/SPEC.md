# SPEC.md — useMeter: AI Kota, Bakiye ve Kullanım Takip Sistemi Teknik Şartnamesi

- **Versiyon:** 1.0.0
- **Tarih:** 2026-09-13
- **Referanslar:** [CONTEXT.md](../CONTEXT.md), [ADR-0001](adr/0001-self-hosted-bff-architecture.md), [ADR-0002](adr/0002-dual-engine-tracking-model.md), [ADR-0003](adr/0003-multi-tenant-session-authentication.md), [ADR-0004](adr/0004-security-perimeter-and-invitation-onboarding.md), [ADR-0005](adr/0005-nondestructive-stale-usage-state.md)
- **Kabul Edilen ADR'ler:** [ADR-0001](adr/0001-self-hosted-bff-architecture.md), [ADR-0002](adr/0002-dual-engine-tracking-model.md), [ADR-0003](adr/0003-multi-tenant-session-authentication.md), [ADR-0004](adr/0004-security-perimeter-and-invitation-onboarding.md), [ADR-0005](adr/0005-nondestructive-stale-usage-state.md)
---

## 1. Sisteme Genel Bakış

Sistem, birden fazla AI sağlayıcısının anlık bakiyelerini, kota pencerelerini ve sıfırlanma zamanlarını izler. Depoda **17 kanonik sağlayıcı adaptörü** bulunur; bunların gerçek dünyadaki kanıt düzeyleri birbirinden ayrıdır.

Sistem, tek bir kullanıcının yerel masaüstü paneli olmaktan çıkarak kullanıcı bazlı kimlik doğrulama, satır düzeyinde kiracı izolasyonu (`ownerId`), oturum güvenliği ve yetkilendirilmiş API erişimi ilkeleriyle çalışır.

### 1.1 Sağlayıcı desteği, kanıt düzeyi ve telemetri türü

`live_verified`, gerçek sağlayıcıdan geçerli telemetri gözlendiğini; `connection_verified`, gerçek hesap bağlantısının başarılı olduğunu ancak kota telemetrisinin gözlenmediğini; `synthetic_only`, yalnızca adaptör/sentetik davranışın mevcut olduğunu belirtir. Hiçbiri her plan, bölge veya yetkilendirme yolunun desteklendiği garantisi değildir.

| Sağlayıcı (kanonik ID) | Kanıt düzeyi | Kimlik doğrulama modları | Telemetri türü |
| --- | --- | --- | --- |
| OpenRouter (`openrouter`) | `synthetic_only` | `oauth_loopback_paste`, `api_key` | `balance_usd` |
| DeepSeek (`deepseek`) | `synthetic_only` | `api_key` | `balance_usd` |
| Anthropic Claude (`anthropic`) | `synthetic_only` | `oauth_loopback_paste` | `window_percent` |
| OpenAI ChatGPT / Codex (`openai-codex`) | `live_verified` | `oauth_device` | `window_percent` |
| Antigravity (`antigravity`) | `synthetic_only` | `oauth_loopback_paste`, `oauth_callback` | `window_percent` |
| GitHub Copilot (`github-copilot`) | `live_verified` | `oauth_device` | `window_percent` |
| Cursor (`cursor`) | `live_verified` | `oauth_device`, `session_cookie` | `window_percent` |
| xAI Grok (`xai-oauth`) | `live_verified` | `oauth_device` | `window_percent` |
| Zhipu AI / GLM / Z.ai (`zai`) | `synthetic_only` | `oauth_loopback_paste`, `api_key` | `window_percent` |
| MiniMax Code (`minimax-code`) | `synthetic_only` | `api_key` | `window_percent` |
| Cline Pass (`cline-pass`) | `synthetic_only` | `api_key` | `window_percent` |
| Devin (`devin`) | `synthetic_only` | `oauth_callback`, `session_cookie` | `token_credits` |
| Umans (`umans`) | `synthetic_only` | `api_key` | `token_credits` |
| Google Gemini CLI (`google-gemini-cli`) | `synthetic_only` | `oauth_loopback_paste` | `window_percent` |
| Kimi Code (`kimi-code`) | `connection_verified` | `oauth_device` | `window_percent` |
| OpenCode Go (`opencode-go`) | `synthetic_only` | `api_key` | `window_percent` |
| Alibaba Qwen (`alibaba-token-plan`) | `synthetic_only` | `api_key`, `session_cookie` | `window_percent` |

`window_percent` yüzde tabanlı kota pencerelerini, `balance_usd` parasal bakiyeyi, `token_credits` ise sağlayıcının bildirdiği token/kredi/istek sayaçlarını belirtir. Kimi için bilinen nötr sonuç **“Hesap bağlandı; sağlayıcı kota bildirmiyor”** biçimindedir; bu, ücretli plan veya bölge hakkında çıkarım değildir. Devin `cog_` V3 PAT'lerini desteklemez ve barındırılan OAuth yönlendirmesi deneysel/doğrulanmamıştır. Antigravity'nin gömülü masaüstü OAuth istemcisi tam loopback callback URL'sinin elle yapıştırılmasını gerektirir; otomatik barındırılan callback için operatörün kendi Google OAuth Web istemcisi ve eşleşen HTTPS URI'si gerekir.

Kanonik katalog `GET /api/providers/catalog` üzerinden kimlik doğrulama olmadan okunabilir; yanıt yalnızca sağlayıcı metadata'sı içerir, sır veya token içermez. İstemci bağlantıdan önce kanıt düzeyini ve telemetri türünü gösterir.

---

## 2. Kimlik Doğrulama ve Hesap Yaşam Döngüsü

### Kimlik ve parola

- E-posta `trim().toLowerCase()` ile kanonikleştirilir ve `users.email` alanında `COLLATE NOCASE` benzersizliğiyle saklanır.
- Yeni parolalarda aynı doğrulayıcı en az 12 Unicode karakteri **ve** en az 12 JavaScript kod birimini; en fazla 256 Unicode karakterini, 256 kod birimini ve 256 UTF-8 baytını şart koşar.
- Parolalar Bun `Bun.password` Argon2id ile hash'lenir (`memoryCost: 65536`, `timeCost: 2`). Geçersiz e-posta/parola ile bilinmeyen kullanıcı için giriş yanıtı aynı genel kimlik doğrulama hatasını verir.

### Sunucu oturumları ve çerez

- Oturumlar durum bilgili SQLite kayıtlarıdır; istemciye JWT verilmez. Oturum belirteci 32 rastgele bayttan üretilmiş opak metindir; kasada yalnız SHA-256 `token_hash` saklanır.
- Çerez adı `usage_session`'dır; `HttpOnly`, `SameSite=Lax`, `Path=/` ve production/HTTPS ortamında `Secure` nitelikleri kullanılır. Oturum 30 gün (`2,592,000` saniye) geçerlidir.
- `logout` yalnız o belirteci siler. Parola değişikliği işlemi yapan etkin oturumu korur ve aynı kullanıcının diğer oturumlarını atomik biçimde siler. Kurtarma parolasının başarılı yenilenmesi kullanıcının tüm oturumlarını siler ve kendiliğinden oturum açmaz.

### Parola değiştirme, kurtarma ve hesap silme

Kasa, geri döndürülemez SQL yazısından hemen önce doğrulama bağını yine kontrol eder. Parola değiştirme; etkin kullanıcı oturumu ve mevcut parola gerektirir, yeni parola ortak parola kuralından geçer. Hashleme sırasında parola veya oturum değişmiş/iptal edilmişse eski istek yazamaz. Başarılı değişiklik tüm reset kayıtlarını iptal eder ve kullanıcının bekleyen sağlayıcı yetkilendirme girişimlerini/sağlayıcı işleri iptal eder.

Parola kurtarma, sunucuda kullanıcı varlığını araştırmadan önce her geçerli e-posta isteğini aynı sınırlı kuyruğa alır. Bilinmeyen e-posta için posta gönderilmez. İstek yanıtı bilinen/bilinmeyen kullanıcı ve arka plan teslimat hatası için aynı `202 {success:true}` yanıtıdır. Posta yapılandırılmamışsa veya kuyruk doluysa tüm hesaplar için `503 RECOVERY_UNAVAILABLE`; istek/onarım hız sınırı aşıldığında `429 RATE_LIMITED` ve `Retry-After` döner. Kurtarma isteği pahalı parola hash'i çalıştırmaz.

Her kullanıcı için en yeni tek reset belirteci geçerlidir; belirteç 32 rastgele bayttır, veritabanında yalnız SHA-256 özeti bulunur, süresi 15 dakikadır ve tek kullanım içindir. Yeni bir istek önceki belirteci geçersiz kılar. Başarılı tüketim; token özeti, sona erme zamanı ve token verildiğindeki parola hash'ini transaction içinde yeniden doğrular; parola değişimi, bütün kullanıcı oturumlarının ve reset belirteçlerinin iptali aynı transaction'dadır. Henüz geçerli olan belirteç, posta hizmeti daha sonra yapılandırmadan çıkarılsa bile onaylanabilir. Reset bağlantısı zorunlu kanonik HTTPS origin'i üzerinde `/reset-password#token=...` biçimindedir; token query string'e veya sunucu API yanıtına konmaz.

Reset token'ın sahibi hedef kullanıcıyı belirler; istekle birlikte başka kullanıcıya ait bir oturum çerezi sunulması yalnız token sahibinin parolasını/oturumlarını değiştirir, çerezi veya verileri etkilemez. API yanıtı token sahibinin kimliğini döndürmez.

Öz-silme geçerli etkin oturum ve mevcut parolayı ister. Kullanıcının son yönetici olması transaction içindeki korumayla silme reddedilir. Başarılı silme user satırını kaldırır; SQLite FK cascade ile oturumlar, kimlik bilgileri, kullanım anlık görüntüleri, reset belirteçleri ve kullanıcının oluşturduğu davetiyeler silinir. Bekleyen OAuth/poller işleri iptal edilir; diğer sahiplerin verileri değişmez. Yönetici silme uç noktası aynı hedef-sahip iş temizliğini kullanır, ancak yönetici kendi hesabını yönetim uç noktasından silmez.

### Servis ve posta sınırları

- `AuthService` parola değişikliği, reset isteği/onayı, hesap silme ve `stopPasswordRecovery()` işlemlerini sunar. Uygulama kurtarma postasını yalnız `RECOVERY_MAIL_SOCKET` boş değilse enjekte edilen Unix-socket mailer üzerinden yollar; boş değer kurtarma isteğini kapatır, sahte/log-only teslimat kullanmaz.
- Kuyrukta aynı anda en fazla 2 aktif iş ve 32 bekleyen iş vardır. Bekleyen iş 30 saniye sonra düşürülür; posta gönderimi 5 saniyede abort edilir; otomatik retry yoktur. Bu sayılar kod sabitleridir, konfigürasyon anahtarı değildir.
- Mail bridge yalnız alıcı e-posta adresi ve 64 küçük harfli hex token kabul eder. Canonical public origin ve gönderici host tarafında yapılandırılır; bridge token'ı `/reset-password#token=...` bağlantısına koyar ve host `/usr/sbin/sendmail`'i shell olmadan çağırır. Yerel sentetik sendmail smoke testi gerçek posta teslimini veya DKIM'i kanıtlamaz.

### HTTP API (hesap yaşam döngüsü)

| Uç nokta | İstek | Başarı | Temel hatalar |
| --- | --- | --- | --- |
| `POST /api/auth/password/change` | `{currentPassword,newPassword}` | `200 {success:true}`; aynı oturum korunur | yanlış mevcut parola `401 INVALID_CREDENTIALS`; zayıf parola/girdi `400 WEAK_PASSWORD`; oturum yetkisizse `401 UNAUTHENTICATED`; hız sınırı `429 RATE_LIMITED` |
| `POST /api/auth/password/reset-request` | `{email}` | yapılandırılmış mailerda `202 {success:true}` | geçersiz e-posta `400 INVALID_EMAIL`; yapılandırılmamış/dolu kuyruk `503 RECOVERY_UNAVAILABLE`; hız sınırı `429 RATE_LIMITED` |
| `POST /api/auth/password/reset-confirm` | `{token,newPassword}` | `200 {success:true}`; yeni çerez atılmaz | geçersiz/kullanılmış/süresi dolmuş token `400 INVALID_RESET_TOKEN`; zayıf parola `400 WEAK_PASSWORD`; hız sınırı `429 RATE_LIMITED` |
| `DELETE /api/auth/account` | `{password}` | `200 {success:true}` ve mevcut çerez süresi dolmuş olarak ayarlanır | yanlış parola `401 INVALID_CREDENTIALS`; geçersiz oturum `401 UNAUTHENTICATED`; son admin `409 LAST_ADMIN`; hız sınırı `429 RATE_LIMITED` |

Yeni public sayfalar `GET /forgot-password` ve `GET /reset-password`'dır. Reset token URL fragment'inden yüklenir ve sayfa geçmişi hemen temizler; reset sayfasında harici script, stylesheet, font veya görsel yoktur ve `Referrer-Policy: no-referrer` uygulanır. API mutasyonları aynı-köken denetiminden geçer. Başarılı olmayan hesap yaşam döngüsü yanıtları `{success:false,error,errorCode}` biçimindedir; istemci yerelleştirmeyi `errorCode` üzerinden yapar.

### Genel kullanıma açık bilgilendirme sayfaları

Giriş gerektirmeyen `/privacy`, `/terms`, `/security` ve `/support` sayfaları gizlilik, kullanım koşulları, güvenlik bildirimi ve topluluk desteği bilgilerini sunar. Sayfalar Türkçe ve İngilizce gösterilebilir (`?lang=tr` veya `?lang=en`); kendi iç stilleri dışında harici kaynak yüklemez ve `no-referrer` ile kısıtlayıcı bir içerik güvenliği ilkesi kullanır.



### Yerel hesap yaşam döngüsü yüzey doğrulaması (canlı teslimat kanıtı değildir)

Hesap yaşam döngüsü, bellek içi SQLite `StorageVault`, gerçek `AuthService`/Hono route'ları ve derlenmiş React yüzeyiyle 1280×913 ve 720×965 headless görünüm alanlarında test edilmiştir. Posta göndericisi ve sağlayıcı adaptörü sentetiktir; dış sağlayıcıya, ağ mail sunucusuna veya gerçek kullanıcıya istek gönderilmemiştir.

- EN/TR parola değiştirme, yanlış mevcut parola, eşleşmeyen parola, geçerli değişiklik, mevcut oturumun korunması ve diğer oturumların iptali çalıştı.
- EN/TR reset isteği bilinen/bilinmeyen hesaplar için aynı genel yanıtı verdi. Token fragment'ten alındıktan sonra adres çubuğu geçmişi temizlendi; token DOM, browser storage veya `window` yüzeyine bırakılmadı. Reset tüm eski oturumları iptal etti, otomatik giriş yapmadı, replay ve yeniden yüklenmiş kullanılmış bağlantı reddedildi.
- Settings panelini kapatıp yeniden açınca parola alanları ve silme onayı sıfırlandı; silme onayı olmadan işlem başlatılamadı. Son-yönetici silme denemesi reddedildi ve yönetici oturumu korundu.
- Düzenli kullanıcının onaylı öz-silmesi sonrası kendi oturumu `401` oldu ve kendi credential/geçmişi temizlendi; diğer sahibin credential, geçmiş ve oturumu değişmeden kaldı.
- Reset sayfası harici kaynak yüklemedi; browser console hatası gözlenmedi.

Bu headless kanıt, gerçek mail kutusuna teslimatı, MTA kabulünü, DKIM imzasını, production host socket izinlerini veya canlı deploy'u doğrulamaz.

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
│ • 17 canonical providers; see evidence matrix in §1.1                     │
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

Kullanıcı kimliği ve kullanım verisi sorguları `ownerId` ile sınırlandırılır. Daemon yalnızca açıkça dahili (`Internal`) kasametotlarıyla tüm credential referanslarını okuyabilir. `StorageVault`, Bun SQLite üzerinde senkron çalışan bir modüldür; sahibi verilen temel arayüzler şunlardır:

```typescript
saveCredential(ownerId: string, input: InputCredential): StoredCredential
listCredentials(ownerId: string, provider?: string): StoredCredential[]
getCredential(ownerId: string, id: string): StoredCredential | null
deleteCredential(ownerId: string, id: string): boolean
saveUsageSnapshot(ownerId: string, report: UsageReport): boolean
getLatestUsage(ownerId: string): UsageReport[]
```

Bir kullanıcının kimlik bilgisi silindiğinde ilgili kullanım anlık görüntüleri SQLite `ON DELETE CASCADE` ile silinir. Kullanıcı öz-silmesi aynı şekilde kullanıcıya FK ile bağlı oturum, kimlik bilgisi, kullanım kaydı, reset belirteci ve oluşturduğu davetiyeleri cascade ile kaldırır.


#### Veritabanı Şeması (SQLite)

```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    account_label TEXT NOT NULL,
    accent TEXT NOT NULL DEFAULT 'default',
    credential_type TEXT NOT NULL,
    encrypted_secret TEXT NOT NULL,
    iv TEXT NOT NULL,
    tag TEXT NOT NULL,
    metadata TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credentials_owner_id ON credentials(owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_owner_prov_label
    ON credentials(owner_id, provider, account_label);

CREATE TABLE IF NOT EXISTS usage_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    account_label TEXT NOT NULL,
    report_json TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_cred_time
    ON usage_snapshots(credential_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshots_owner_time
    ON usage_snapshots(owner_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshots_owner_cred_time
    ON usage_snapshots(owner_id, credential_id, fetched_at DESC);

CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    accepted_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON invitations(token_hash);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON invitations(created_by);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    password_hash_at_issue TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
```

`password_reset_tokens` user başına tek satırla latest-token kuralını uygular. Reset token'ın açık hali saklanmaz; kayıt kullanıcı silme cascade'ine ve parola değişimi/reset tüketimindeki atomik iptale tabidir. Bu tablo eklenmesi credential metadata `PRAGMA user_version` değerini değiştirmez.

#### Eski Verilerin Atomik Sahiplenilmesi (First-User Legacy Claim)
Tek kullanıcılı sürümden gelen ve `owner_id` değeri `NULL` olan tüm kayıtlar, sisteme kaydolan ilk gerçek kullanıcı (`users` tablosundaki ilk kayıt) tarafından tek bir SQLite transaction'ı içinde atomik olarak sahiplenilir:
```sql
-- İlk kullanıcı kaydında otomatik işletilir:
UPDATE credentials SET owner_id = :firstUserId WHERE owner_id IS NULL;
UPDATE usage_snapshots SET owner_id = :firstUserId WHERE owner_id IS NULL;
```
Bu işlemden sonra veya sisteme sonradan kaydolan kullanıcılar için sahipsiz kayıt kalmaz; diğer kullanıcılar yalnızca kendi ekledikleri kimlik bilgilerini ve kotalarını görür.

#### UsageHistoryRetention: Kullanım Geçmişi Saklama Politikası

`usage_snapshots` geçmişini saklama süresi varsayılan **7 gündür**. `SNAPSHOT_RETENTION_DAYS`, pozitif güvenli bir tam sayı ile bu süreyi değiştirir. Saklama penceresi dışında kalan kayıtlar uygulama başlangıcındaki ilk temizlikte ve ardından saatlik çalışan arka plan işinde değerlendirilir.

Pencere sonu `cutoff = now - retentionDays * 86_400_000` olarak hesaplanır; `fetched_at >= cutoff` olan tüm anlık görüntüler korunur. Storage işlemi `now`, retention penceresi ve hesaplanan `cutoff` değerlerinin epoch-milisaniye safe integer aralığında olduğunu veritabanına dokunmadan önce doğrular. Her credential için ayrıca en fazla iki `ProtectedUsageSnapshot` anchor'ı tutulur:

- **En yeni kayıt:** başarı/sağlık durumundan bağımsız olarak `fetched_at DESC, id DESC` sıralamasındaki ilk kayıt.
- **En son başarılı kayıt:** `StorageVault` last-good okuyucusunun aynı sınıflandırmasına göre ilk başarılı kayıt. Truthy `error`, `health`/`source` değerleri `error` veya `stale`, ya da yalnızca boolean `stale: true` kaydı başarılı olmaktan çıkarır. Eski raporlarda alanların eksik olması ve `error` alanının `null`, `false`, `0` veya boş metin olması başarıyla uyumludur; sağlıklı bir kota-tükenmiş rapor da başarılı sayılır.
- Bozuk JSON veya JSON `null` içeren eski raporlar son-başarılı snapshot sayılmaz; bozuk bir rapor credential'ın en yeni-any anchor'ı olarak yine de korunabilir.

İki anchor aynı satıra işaret ederse yalnızca bir kez korunur. Eşit `fetched_at` değerlerinde daha büyük snapshot ID kazanır; daha sonra eklenen ama daha eski `fetched_at` taşıyan bir satır en yeni/son başarılı seçiminin önüne geçmez. Bu kurallar her kullanıcı ve credential için ayrı uygulanır.

Her çalışma başlangıçta tek bir `MAX(id)` watermark'ı alır ve anchor kümesini bu watermark'a kadar bir kez hesaplar. Yalnızca `id <= watermark`, `fetched_at < cutoff` olan ve anchor kümesinde bulunmayan `usage_snapshots` satırları silinebilir. Yeni çalışma sırasında eklenen satırlar, `fetched_at` değeri eski olsa bile, sonraki çalışmaya bırakılır. Silme en çok 1.000 satırlık commit edilmiş transaction'lar halinde yapılır ve transaction'lar arasında event loop'a kontrol verilir. Bu temizlik kullanıcı, credential, davetiye, kimlik bilgisi veya token metadata kayıtlarını silmez.

Rutin retention bir `VACUUM` çalıştırmaz. Silinen sayfalar SQLite tarafından veritabanı içinde yeniden kullanılabilir; bu nedenle aktif DB dosyasının boyutu kendiliğinden küçülmek zorunda değildir.

### Modül 3: Aktif Yoklayıcı Daemon (`src/core/poller/`)
Arka planda periyodik olarak çalışan zamanlayıcıdır.

```typescript
export interface PollerOptions {
  intervalMs?: number;       // Varsayılan: 300_000 ms
  pollTimeoutMs?: number;    // Varsayılan: 30_000 ms, deneme başına
  maxConcurrentGlobal?: number;       // Varsayılan: 4 / süreç
  maxConcurrentPerProvider?: number;  // Varsayılan: 1
  minProviderIntervalMs?: number;     // Varsayılan: 4_000 ms
  maxQueuedJobs?: number;             // Varsayılan: 256
  admissionTimeoutMs?: number;        // Varsayılan: 30_000 ms
}

export interface PollerEngine {
  start(): void;
  stop(): void;
  pollAllInternal(): Promise<UsageReport[]>;
  pollOwner(ownerId: string, credentialId?: string): Promise<UsageReport[]>;
  onReport(callback: (report: UsageReport, ownerId?: string) => void): void;
}
```

Yoklayıcı ayarları `PollerOptions` ile verilir. `src/index.ts`, `POLL_TIMEOUT_MS` değerini `pollTimeoutMs`'e aktarır (varsayılan `30000` ms; sonlu pozitif tam sayı ve en çok `2147483647`). Deadline; daemon/manual yoklama ve manuel/OAuth/device staged doğrulamasındaki tek bir sağlayıcı denemesi içindir; tüm sweep'i veya HTTP isteğini kapsamaz. `POLL_MAX_CONCURRENT_GLOBAL` (4), `POLL_MAX_CONCURRENT_PER_PROVIDER` (1), `POLL_MIN_PROVIDER_INTERVAL_MS` (4000), `POLL_MAX_QUEUED_JOBS` (256) ve `POLL_ADMISSION_TIMEOUT_MS` (30000) aynı adlı seçenekleri yapılandırır. Eşzamanlılık ve kuyruk boyutu pozitif safe integer; interval `0..2147483647`, admission timeout `1..2147483647` pozitif tam sayı olmalıdır. Değişkenler ayarlanmamışsa varsayılanlar kullanılır; geçersiz değer başlatmada reddedilir. Bunlar süreç içi sınırlardır; çoklu süreçler arasında koordinasyon veya sağlayıcı API limit garantisi değildir.

- **Genel Daemon vs Kullanıcı Odaklı Manuel Tetikleme:**
  1. **Arka Plan Yoklayıcı Daemon:** Sunucu sürecinde çalışır; `listAllCredentialsInternal()` ile tüm kayıtlı credential refs'i toplar, sonra bounded shared provider pool üzerinden dispatch eder.
  2. **Kullanıcı Tetiklemeli Manuel Yenileme (`POST /api/refresh`):** Yalnızca aktif oturum sahibi kullanıcının `ownerId` değerine ait kimlikleri yoklar. Bir kullanıcının diğer kullanıcıların hesaplarını yoklaması veya kotalarını tetiklemesi engellenir.
**Mekanizma:**
- **Sweep cadence:** Base interval `5 dakika`; başlangıçta tam daemon yoklaması başlar. Devam eden sweep'e gelen periyodik tetikleme onunla birleşir; sonraki tick'ler kuyruklanmaz.
- **Ortak dispatch kapasitesi:** Daemon, kullanıcı manuel yenilemesi ve staged credential doğrulaması canonical provider ID'ye göre ortak admission pool kullanır. Varsayılan genel aktif deneme sınırı 4, sağlayıcı başına 1'dir. Her sağlayıcı dispatch başlangıcı arasında varsayılan en az 4000 ms vardır. Hazır başka sağlayıcı bu aralıkta ilerleyebilir; cooldown veya kuyrukta bekleme aktif kapasite tüketmez. Aralık tüm upstream HTTP çağrılarına değil, sağlayıcı denemesi başlatılmasına uygulanır.
- **Bounded waiting:** Paylaşılan bekleme kuyruğunun varsayılan kapasitesi 256 iş ve bir işin dispatch için bekleme deadline'ı 30 saniyedir; her provider group için sweep producer sayısı en çok 17 ile sınırlıdır. Aynı credential işi yalnız aynı credential ID ve owner scope içinde birleştirilir. Kuyruğa alınmış credential dispatch öncesi aynı owner/id ile yeniden okunur; başarılı reauth yeni token'ı kullanır, silinmiş kayıt atlanır. Dispatch edilmiş eski işlerin token/snapshot yazmaları epoch/ownership kontrolünden geçer.
- **İptal ve kapasite yanıtı:** Dışarıdan iptal bekleyen işi hemen kuyruktan çıkarır; her provider attempt ayrıca `POLL_TIMEOUT_MS` deadline'ına ve çağıran sinyaline bağlıdır. Adapter abort'u görmezden gelirse upstream işi sürebilir fakat geç yanıt/callback yazamaz. Queue full veya admission timeout HTTP `429`, `Retry-After: 30`, `errorCode: "POLLER_CAPACITY"` üretir; yerel admission reddi yeni provider hata/stale snapshot oluşturmaz. Süresi dolmuş/iptal edilmiş/yabancı OAuth session kontrolleri capacity kararından önce gelir. Staged OAuth kodu redemption sonrasında bu capacity hatasını alırsa session terminalleşir ve `restartRequired: true` ile yeni authorization/session gerekir. Normal upstream HTTP 429 bu yerel işaret değildir; provider retry/stale davranışını izler.
- **Deterministic latest result:** Aynı `fetched_at` timestamp'li snapshot'larda en yüksek insertion ID en yeni kabul edilir. Böylece timestamp eşitliğinde sonraki başarılı snapshot eski hata snapshot'ının önüne geçer; owner-scoped ve dahili latest/last-good seçimleri aynı kuralı izler.
- **Yıkıcı Olmayan Hata Yönetimi ve Durum Makinesi (Non-destructive Stale State Machine):**
  Yoklama başarısız olduğunda sistem telemetriyi silmez; son başarılı durumu (`lastGood`) korur:
  - **İlk Başarılı Yoklama:** `health: "healthy"`, `stale: false`, `source: "live"`, `lastGoodFetchedAt: fetchedAt`, `limits: [...]`.
  - **Sonraki Ağ / Sağlayıcı Hatası:** Son başarılı limitler (`lastGood.limits`) korunur; rapor `health: "stale"`, `stale: true`, `source: "stale"`, `lastGoodFetchedAt: lastGood.fetchedAt`, `error: message` olarak güncellenir.
  - **İlk Seferde Hata (Geçmiş Veri Yok):** `health: "error"`, `stale: false`, `source: "error"`, `limits: []`, `lastGoodFetchedAt: undefined`, `error: message`.
  - **Yeniden Başarılı Yoklama:** Sistem otomatik olarak `health: "healthy"`, `stale: false`, `source: "live"` durumuna döner, `error` temizlenir.
  - **Sağlayıcı Kota Tükenmesi Ayrımı:** Sağlayıcının `%100` kota doluluğu dönmesi (HTTP 200) bir yoklama arızası değil, normal bir telemetri verisidir (`health: "healthy"` kalır).
  - **Güvenlik Sınırı:** Ham upstream hata gövdeleri veya hassas istek verileri anlık görüntülerde veya rapor nesnelerinde ASLA saklanmaz.
  - **Codex / xAI OAuth Oturum Yenileme:** Kullanım uç noktası HTTP `401` döndürürse ve kayıtlı bir refresh token varsa adaptör bir kez token yeniler, erişim token'ını ve varsa dönen yeni refresh token'ı kasa geri çağrısıyla kaydeder, ardından kullanım sorgusunu bir kez tekrarlar. Yeni refresh token dönmezse mevcut token korunur. HTTP `403`, diğer hatalar veya refresh token bulunmaması yenileme başlatmaz; yenileme ya da tekrar sorgusu başarısız olduğunda yukarıdaki stale/error kuralları uygulanır. Yenileme istekleri de enjekte edilen `fetch` ve `AbortSignal` kullanır.
  - **Codex / xAI Güvenli Yeniden Bağlama:** OAuth aday kimliği `validateAndSaveCredential` ile bellekte doğrulanır; başarılı doğrulamadan önce mevcut kayıt değiştirilmez. Başarısız ilk bağlantı kayıt oluşturmaz; başarısız yeniden bağlantı mevcut token'ları, kart rengini ve kullanım geçmişini korur. Başarılı bağlantı aynı sahip, sağlayıcı ve hesap etiketi için mevcut kimliği günceller ve doğrulama raporunu kaydeder; ikinci bir ilk kullanım sorgusu yapılmaz.
  - **Kuyrukta Bekleyen Kimliklerin Tazeliği:** Daemon ve kullanıcı yoklamaları sağlayıcı çağrısı başlamadan önce kimliği aynı sahip/id ile kasadan yeniden okur. Kuyruk oluşturulduktan sonra başarılı yeniden yetkilendirme yapılmışsa yeni token'lar kullanılır; silinmiş kimlikler atlanır. Zaten başlamış eski yoklamaların token/snapshot yazıları epoch kontrolüyle reddedilmeye devam eder.
  - **Manuel Değiştirme vs OAuth Yeniden Bağlama:** `validateAndSaveCredential(ownerId, input, metadataMode)` çağıranları açıkça `replace` veya `preserve` seçer. Manuel credential POST'u `replace` kullanır: eski hesabın refresh token, OAuth client, proje/e-posta/hesap metadata'sı yeni token'a taşınmaz; adayın doğrulama sırasında ürettiği metadata kullanılır. OAuth yeniden bağlamaları `preserve` kullanır: doğrulanmış aday metadata'sı güncel kayıtla birleştirilir ve aynı hesap akışında verilmemiş refresh bilgileri korunur. İki modda da başarısız doğrulama eski kimliği ve geçmişini değiştirmez; kart rengi ve kayıt kimliği korunur.
  - **Google Refresh İstemci Kökeni:** Credential metadata'sındaki tam client ID/secret çifti refresh token'ın kaynak istemcisidir. Bu çiftin bulunmadığı eski kayıtlar gömülü istemciye aittir; sonradan yapılandırılan operator-owned Web istemcisi bu kayıtların refresh istemcisini değiştirmez.
  - **Sağlayıcı denemesi deadline ve iptal:** Daemon/kullanıcı yoklaması ve staged kimlik bilgisi doğrulaması (manuel kimlik bilgisi ve OAuth/device doğrulama akışları) deadline ile sınırlandırılmış, varsa çağıran iptal sinyaliyle birleştirilmiş bir `AbortSignal` alır. `POLL_TIMEOUT_MS` dolunca veya çağıran iptal edince poller bu etkin sinyali iptal eder ve `Promise.race` ile sağlayıcı bekleyişini bitirir. Adapter iptali yok sayarsa upstream işi arka planda sürebilir, ancak geç tamamlanan sonuçlar ve token callback'leri artık yazma yetkisine sahip değildir. İsteğe bağlı alt isteklerde olağan hatalar mevcut best-effort davranışını korur; abort bu hatalarda yutulmaz ve retry beklemesi iptale duyarlıdır. Deadline/çağıran iptali normal yoklamada stale/error durum makinesini kullanır; staged doğrulama aday kimlik bilgisini veya snapshot'ı kaydetmeden başarısız olur. Başarılı yazıdan önce monotonic deadline kontrolü, `beforeCommit` sağlandığında ayrıca store-backed yetki kontrolü yapılır. Senkron commit'e kabul, geri alınamaz yazı sınırıdır: deadline içinde kabul edilip tamamlanan commit SQL senkron işi deadline'ı aşsa da başarı döndürür; gerçek storage hataları yayılır. Deadline sonrasında henüz kabul edilmemiş başarılı yazı reddedilir.
- **Geçici provider hataları:** 429 veya geçici hata alındığında exponential backoff (15s, 30s, 60s) devreye girer. Bu provider yanıtları yerel admission rejection'dan farklıdır.

#### Yoklama ve şifreleme CPU azaltımı; yerel sentetik ölçüm

`crypto.ts` özel modül durumunda yalnızca mevcut effective master secret için türetilmiş anahtarı tutar. Her encrypt/decrypt çağrısı mevcut production master-key guard'ını yine çalıştırır; trimmed secret değişirse yeni scrypt derivation yapılır. Bu, her işlemde tekrarlanan senkron scrypt maliyetini azaltır; anahtar çağırana açılmaz, şifreli veri formatı/IV/salt/tag ve key-rotation davranışı değişmez.

Aynı payload ile 100 yerel sentetik decrypt ölçümü cache öncesi 2433 ms, sonrası 1.666 ms sürdü. Ayrı 500 sentetik credential ölçümünde (250 owner, kişi başı 2 credential, 8 sahte provider fixture, her fake çağrıda 80 ms delay, dispatch aralığı 4000 ms) sağlıklı sweep 248.228 s sürdü: 500 çağrı, peak 4 global / provider başına 1, minimum ölçülen dispatch aralığı 4000.0276 ms, 500 healthy, 0 stale/error, maksimum last-good yaşı 248.145 s, RSS 66 MiB, CPU user 1047 ms / system 422 ms. Her 50. fake istek deadline'a kadar 30 saniye takılan fault koşusunda 326.232 s: 500 çağrı, peak 4/1, minimum aralık 4000.3558 ms, 490 healthy / 10 stale / 0 first-error, seeded 50 stale quota state korunmuş, maksimum last-good yaşı 386.290 s, RSS 68 MiB, CPU user 1637 ms / system 704 ms.

Bunlar yerel süreçte sahte adapterlarla alınmış ölçümlerdir; gerçek provider çağrısı, VM/production yükü, 500 gerçek kullanıcı, upstream limit/429/challenge güvenliği, free-tier veya reklam hazırlığı kanıtı değildir. Poll attempt içinde adapter birden çok HTTP isteği/refresh yapabilir. Fault sweep beş dakikayı geçtiğinde sonraki tick devam eden sweep'e katılır; bir sonraki nominal tick daha sonra yeniden gelebilir. Bu yüzden her beş dakikada tazelik veya çok kullanıcılı kapasite iddiası çıkarılamaz.

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
  1. **ntfy:** `POST https://ntfy.example.com/<topic>` (Sıfır bağımlılık, anında bildirim).
  2. **Telegram Bot:** `sendMessage` API'si üzerinden Markdown formatlı kart.
  3. **Discord Webhook:** Renkli embed mesajı.

---

### Modül 6: HTTP API & Arayüz Katmanı (`src/server/`)

Hono ile sunulan REST rotaları ve server-rendered/authenticated React paneli. Login/register/recovery sayfaları ve açıkça listelenen davetiye/callback rotaları public'tir; kullanıcı verisi ve panel API'leri `usage_session` oturumu gerektirir.

#### Açık (Public) Rotalar
- `GET /login`, `GET /register`, `GET /forgot-password`, `GET /reset-password` → Giriş, kayıt ve parola kurtarma sayfaları.
- `POST /api/auth/register` → Açık kayıt politikası izin veriyorsa kullanıcı oluşturur ve `usage_session` çerezi atar.
- `POST /api/auth/login` → Başarılı girişte `usage_session` çerezi atar.
- `POST /api/auth/logout` → Gönderilmiş oturum belirtecini siler ve çerezi süresi dolmuş olarak döndürür.
- `POST /api/auth/password/reset-request` → `{email}` alır; yapılandırılmış mailer ve kullanılabilir kuyrukta bilinen/bilinmeyen adreslere aynı HTTP `202 {success:true}` yanıtını verir. Mailer yapılandırılmamışsa veya sınırlı kuyruk doluysa `503 RECOVERY_UNAVAILABLE` döndürür. Hesap/teslimat durumu yanıtla açıklanmaz.
- `POST /api/auth/password/reset-confirm` → `{token,newPassword}` alır; geçerli belirteci atomik olarak tüketir ve `200 {success:true}` döndürür. Oturum çerezi atmaz; geçersiz, süresi dolmuş veya replay belirteç `400 INVALID_RESET_TOKEN` olur.
- `GET /health` → Durum ve SQLite bütünlük kontrolü.
- `GET /invite/:token`, `GET /invite`, `POST /api/invitations/:token/accept` → Yönetici davetiye kabul akışı.

#### Oturum Korumalı Rotalar
- `GET /` → Dashboard; `GET /api/auth/me` → Aktif kullanıcının temel bilgileri.
- `GET /api/usage`, `GET /api/data` → Kullanıcının owner-scoped güncel kota raporları (`/api/data`, usage yanıtının uyumlu alias'ıdır).
- `POST /api/poll`, `POST /api/credentials/:id/poll` → Kullanıcıya ait hesapları veya bir credential'ı yoklar; her kalıcı yoklama yazısı commit öncesi request oturumunu doğrular.
- `POST /api/credentials`, `PATCH /api/credentials/:id`, `DELETE /api/credentials/:id` → Yalnız oturum sahibinin credential'larını oluşturur, günceller veya siler.
- `POST /api/auth/password/change` → `{currentPassword,newPassword}` alır; `200 {success:true}` ile başarılıdır, geçerli oturumu koruyup diğer oturumları iptal eder. Yanlış mevcut parola `401 INVALID_CREDENTIALS`, zayıf yeni parola `400 WEAK_PASSWORD`, sonradan geçersiz kalan oturum `401 UNAUTHENTICATED` olur.
- `DELETE /api/auth/account` → `{password}` alır; başarılı yanıtta mevcut çerezi siler. Yanlış parola `401 INVALID_CREDENTIALS`, son yönetici `409 LAST_ADMIN`, geçersiz oturum `401 UNAUTHENTICATED` olur.
- Sağlayıcı OAuth başlatma, durum, cihaz yoklama, manuel tamamlama ve owner-bound session iptali rotaları.

#### Yönetici (Admin) Rotaları (`user.role === "admin"`; yetkisizler 403)
- `GET /admin` → Sistem yönetici paneli.
- `GET /api/admin/stats`, `GET /api/admin/users`, `PATCH /api/admin/users/:id/role`, `DELETE /api/admin/users/:id` → Sistem telemetrisi ve yönetici kullanıcı yönetimi. Admin yönetim endpoint'i kendini silemez; last-admin koruması vardır.
- `GET /api/admin/settings`, `PATCH /api/admin/settings/registration` → Kayıt politikası.
- `GET /api/admin/invitations`, `POST /api/admin/invitations`, `DELETE /api/admin/invitations/:id` → Davetiye yönetimi.


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
  - `Referrer-Policy`: normal panel `strict-origin-when-cross-origin`; recovery pages override to `no-referrer`.
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains` (Yalnızca `secure: true` veya HTTPS üretim ortamlarında).
- **CSP Tasarım Kararı ve Kısıt:** useMeter'ın sunucu taraflı HTML üretimi (SSR), gömülü tema/dil scriptleri ve Tailwind CDN kullanımını bozmamak için `'unsafe-inline'` direktifleri kasıtlı olarak tercih edilmiştir. Template motoru nonce enjekte etmediği için gerçekte var olmayan nonce/hash korumaları iddia edilmez.

### 4.2. CORS İzin Listesi ve Güvenli Köken Çözümleme
- **Ortam Değişkenleri:** `CORS_ALLOWED_ORIGINS` veya `USEMETER_ALLOWED_ORIGINS` (virgülle veya boşlukla ayrılmış origin listesi).
- **Aynı Köken Varsayılanı (Same-Origin Default):** Değişken tanımlanmamışsa sistem yalnızca gelen isteğin kendi kökenine (`requestOrigin`) izin verir.
- **Kimlikli İsteklerde Joker Karakter Yasağı:** `allowCredentials: true` (`usage_session` çerezi) geçerli olduğunda RFC 6454 gereği `*` (wildcard) kesinlikle reddedilir (`false`).

### 4.3. Güvenli İstemci IP Çözümlemesi (`TRUST_PROXY`)
- **Varsayılan Davranış:** `trustProxy` kapalıdır (`false`). İstemci tarafından gönderilen `X-Forwarded-For` veya `X-Real-IP` başlıkları IP sahteciliği (spoofing) ve rate-limit atlatma risklerine karşı **kesinlikle yok sayılır**; doğrudan soket uzak adresi kullanılır.
- **Ters Vekil Desteği:** Sistem Nginx, Caddy veya Cloudflare arkasında çalışıyorsa `TRUST_PROXY=true` veya `TRUST_PROXY=1` tanımlanmalıdır. Bu durumda `X-Forwarded-For` zincirindeki en soldaki (istemciye ait) geçerli IP adresi güvenle ayıklanır.

### 4.4. Sınırlandırılmış Bellek-İçi Hız Sınırlayıcı (Bounded In-Memory RateLimiter)
RateLimiter en fazla 10.000 anahtar tutar, kayan pencere uygular ve deterministik `now()` dikiş noktasını destekler:
- **Kimlik Doğrulama (`auth`):** `5/dakika/IP` (`POST /api/auth/login`).
- **Kayıt/Katılım (`registration`):** `5/dakika/IP`; kayıt ve davetiye kabulü aynı IP kovasını kullanır.
- **Manuel Yoklama (`manualPoll`):** `1/30 saniye/kullanıcı+credential`; `POST /api/poll` için kullanıcı başına tüm credential kovası kullanılır.
- **OAuth Cihaz Yoklama (`oauthDevicePoll`):** `30/dakika/kullanıcı+akış`.
- **Parola Değiştirme (`passwordChange`):** `3/15 dakika/kullanıcı+IP`.
- **Parola Kurtarma İsteği (`passwordResetRequest`):** `5/saat/IP` ve ayrıca `5/saat/SHA-256(normalized email)`.
- **Reset Onayı (`passwordResetConfirm`):** `5/15 dakika/IP`.
- **Öz-Silme (`accountDelete`):** `3/15 dakika/kullanıcı+IP`.

Yeni parola/hesap rotalarında hız sınırı pahalı parola doğrulaması/hashlemesinden önce uygulanır. Aşımda HTTP `429` ve `Retry-After` başlığı döner; API istemcileri `RATE_LIMITED` kodunu kullanır.

#### 4.4.1. Sınırlı OAuth Girişim Yaşam Döngüsü

- `src/core/oauth/session-store.ts` içindeki ortak `OAuthSessionStore`, web/device girişimlerini ve henüz sağlayıcı yanıtı bekleyen rezervasyonları kapsar. Kullanıcı başına **5**, sunucu örneği başına toplam **1000** dolu slot; aktif girişimler kapasite için tahliye edilmez. Bu sınır istek/dakika hız sınırından ayrıdır.
- Kapasite sağlayıcı initiate isteği veya callback listener açılmadan önce ayrılır. Dolulukta HTTP **429**, `Retry-After: 60`, `errorCode: "OAUTH_CAPACITY"` döner. Başlatma hatası/iptali rezervasyonu bırakır; istek bağlantısı yanıt gelmeden kesilirse upstream çalışma da session signal ile iptal edilir.
- Pending süre üst sınırı **10 dakika**; device akışlarında sağlayıcının daha kısa süresi korunur, uzun süre 600 saniyeye kırpılır ve etkin `expiresIn` istemciye döner. Bu deadline, tek kullanımlık commit admission'a kadar pending oturumu sınırlar.
- Başarı/hata sonucu terminalleştiğinde **60 saniye** tutulur. Commit admission'a ulaşmadan süresi dolan pending girişimin terminal sonucu orijinal deadline + 60 saniyede kaldırılır; admitted synchronous commit ise tamamlanma/hata ile terminalleşir ve bu sonucu o andan itibaren 60 saniye tutar. Unref'li otomatik timer temizliği istek olmadan da çalışır ve store boşalınca durur.
- Device binding sağlayıcı + code/UUID + sahip ile sınırlandırılır. Bilinmeyen, başka kullanıcıya ait, expired, cancelled veya replay binding upstream poll yapılmadan aynı 404 ile reddedilir. Aynı sahibin devam eden poll'una ikinci istek `pending` döner; tekrar token exchange/kayıt yapılmaz.
- Her başarılı initiate yanıtı bir `sessionId` içerir. Sahip `DELETE /api/oauth/sessions/:sessionId` ile pending veya terminal slotu silebilir (200); yabancı/bilinmeyen slot 404. Pending çalışma admission öncesinde iptal edilebilir; `cancel()` admitted senkron commit'i geri alamaz. Bu kısa çağrı yığını başka bir HTTP isteğine yield etmez ve dışarıdan uzun ömürlü iptal istisnası oluşturmaz. Google/Devin state, PKCE, frozen client ve tek kullanım korumaları sürer; terminal yanıtlarda veya public projeksiyonlarda verifier/token/client secret gösterilmez.
- İptal/expiry signal'ı OAuth initiate/poll/exchange/profile isteklerine, loopback listener'a ve aday usage validation'a aktarılır. Sağlayıcı I/O ve aday doğrulaması bittikten sonra `beforeCommit` tek kullanımlık `admitCommit()` kontrolüyle yalnızca aynı current, owner-bound, claimed, pending ve süresi dolmamış session'ı hemen core commit öncesinde kabul eder; admission sonrası SQL/epoch/snapshot yazılarına kadar `await` veya provider I/O yoktur. Bu uzun ömürlü lease değildir: kabul edilmiş aynı senkron yazıyı OAuth pending expiry/cancel geriye dönük başarısız kılamaz; `complete`/`fail` admission'ı temizleyip normal 60 saniyelik terminal sonucu başlatır. Poller'ın ayrı monotonic attempt deadline'ı yine commit öncesinde denetlenir; o kapı reddederse SQL başlamaz ve failure normal biçimde terminalleşir. Admission öncesi expiry hiçbir aday credential/snapshot yazmaz.
- Google/Kimi validation token yenilemeleri de aynı enjekte edilmiş `fetch`/session signal'ını kullanır. İptal, token/metadata mutasyonu veya refresh callback'i öncesi reddedilir; iptal edilmiş yenileme normal erişim token'ına fallback veya ikinci usage isteği başlatmaz.
- Parola değişikliği, reset, öz-silme veya admin silmesi hedef kullanıcının bekleyen OAuth girişimlerini ve poller/provider işlerini iptal eder. Request/session owner yetkisi her `await` sonrasında kalıcı credential veya yoklama yazısından hemen önce doğrulanır; iptal edilmiş isteğin geç callback'i/token refresh'i yazamaz. `admitCommit()` ile kabul edilmiş senkron yazma geriye dönük iptal edilmez.
- Callback teardown sadece kendi captured server örneğini kapatır; eski timer/abort daha yeni aynı-port listener'ı kapatamaz. Bu, diğer loopback-only sağlayıcıların hosted callback uyumluluğunu çözmüş sayılmaz.
- Browser modal close/back/restart/error ve unmount bilinen session'ı owner-scoped DELETE ile iptal eder. Initiate yanıtı henüz gelmediyse HTTP isteği kısa 12 saniyelik istemci deadline'ıyla devam eder: geç gelen eski-run yanıtındaki sessionId silinir, yeni akış/UI etkilenmez. Poll/manual istekleri anında abort edilir; unmount generation ve poll timer'ını temizler. EN/TR kapasite, expiry, retry ve hata mesajları yerelleştirilir.
- Test saati tek `ServerOptions.oauthNow` seam'idir; eski Google-only clock/map'ler kaldırılmıştır. Devin/Cursor usage validation'da keşfedilen kimlik adı provider-label modu ile kalıcılaşır; manuel kullanıcı etiketleri input-bound kalır.

#### 4.4.2. Hosted Manuel OAuth Tamamlama

- Claude, Gemini CLI ve Z.ai embedded istemcilerinin kayıtlı loopback redirect URI'leri korunur; sunucuda fixed-port listener açılmaz. Kullanıcı tarayıcıdaki tam dönüş URL'sini kendi girişimine teslim eder. Claude ayrıca state taşıyan `code#state` girdisini kabul eder.
- OpenRouter [birinci parti headless S256 PKCE](https://openrouter.ai/docs/guides/overview/auth/oauth) kullanır: callback_url yok, kod tek kullanımlık/10 dakika, state headless modda dönmez. Ham opaque code yalnız bu sahibi/PKCE'si bağlı OpenRouter girişimi için kabul edilir.
- Ortak authenticated `POST /api/oauth/manual` gövdesi `{sessionId, callbackInput}`; provider/redirect/verifier session'dan seçilir. Eski Google-only manual route ve kullanılmayan provider listener export'ları kaldırılmıştır. Google embedded URL paste ve isteğe bağlı custom Web public callback davranışı korunur.
- URL modu exact origin/path/state, code XOR error ve duplicate-param kontrolü yapar; pasted URI fetch edilmez. State üretimi CSPRNG UUID'dir. Owner/claim/replay/expiry/abort/beforeCommit ile P0-2 güvenliği devam eder; iki kullanıcının aynı provider girişimi birbirinin listener'ını kapatamaz.
- Manuel endpoint'te owner'ı bilinen terminal girişim HTTP `400` döner; süresi dolmuş girişimde mevcut hata kodu `Authorization session expired` olur. Bilinmeyen veya başka kullanıcıya ait `sessionId` HTTP `404` döner.
- Başarısız exchange/validation mevcut credential, metadata, accent ve snapshot geçmişini korur. EN/TR manual URL/code formu provider'a uygun yönerge sunar; başarıdan sonra terminal receipt okunabilir kalır ve dashboard güncellenir. Sentetik exchange testleri, gerçek sağlayıcı hesap veya kota uyumluluğu kanıtı değildir.




### 4.5. Durağan Veri Şifreleme (At-Rest Metadata Encryption) ve İki Aşamalı Dağıtım Sözleşmesi

Sağlayıcı kimlik bilgilerine ait `metadata` sütunu (OAuth `refreshToken`, kullanıcı adı, erişim kapsamları vb.) veritabanı düzeyinde şifrelenir.

1. **Şifreli Zarf Formatı (Envelope Format):**
   - Şifrelenmiş metadata, SQLite `credentials.metadata` metin sütununda şu sürüm etiketli JSON zarfı olarak saklanır:
     ```json
     {"$vault":1,"ciphertext":"<hex>","iv":"<24-hex>","tag":"<32-hex>"}
     ```
   - Algoritma: **AES-256-GCM** (ana anahtar `USAGE_MASTER_KEY` üzerinden scrypt ile türetilir).
   - Her yazma işleminde 12 baytlık (24 hex karakter) kriptografik olarak bağımsız rastgele IV (`randomBytes`) üretilir; aynı metadata tekrar yazılsa bile şifreli metin ve IV her seferinde farklılaşır.

2. **Bellek-İçi Arayüz Uyumu (In-Memory Contract):**
   - `StorageVault` public metodları (`saveCredential`, `updateCredentialTokens`, `listCredentials`, `getCredential`) bellek içinde `StoredCredential.metadata` alanını şifresi çözülmüş nesne (`Record<string, unknown>`) olarak sunmaya devam eder; çağıran katmanlarda değişiklik gerekmez.

3. **Çift Okuyucu (Dual-Reader) & Hata İzolasyonu (Fail-Closed):**
   - Okuyucu hem eski düz metin JSON verilerini hem de `$vault: 1` zarfını şeffaf biçimde okur.
   - Anahtar uyuşmazlığı, bozuk şifreli metin veya geçersiz zarf durumunda sistem sessizce `undefined` dönmez; işlemi anında durdurur (fail-closed) ve düz metin verileri günlüklere sızdırmaz.

4. **Yazma Politikası:**
   - `CREDENTIAL_METADATA_ENCRYPTION` ortam değişkeni tanımlı değilken ve şema `PRAGMA user_version = 1` iken (Aşama 1 uyumluluk sürümü) yeni yazmalar geriye dönük uyumlu düz metin JSON olarak kaydedilir.
   - `CREDENTIAL_METADATA_ENCRYPTION=enabled` tanımlandığında VEYA veritabanı şeması zaten `user_version >= 2` olduğunda tüm yeni yazmalar (`saveCredential`, `saveCredentialInternal`, `updateCredentialTokens`) zorunlu olarak şifreli zarf yazar.

5. **Atomik ve İdempotent Şema Göçü (v1 -> v2 Migration):**
   - Ortam değişkeni `CREDENTIAL_METADATA_ENCRYPTION=enabled` iken ve veritabanı `user_version < 2` ise, `StorageVault` başlatılırken otomatik olarak göç tetiklenir (`migrateCredentialMetadata()`).
   - Göç tek bir SQLite anlık işleminde (`transaction.immediate()`) çalışır; mevcut tüm şifresiz `metadata` satırları zarfa dönüştürülür ve `PRAGMA user_version = 2;` atanır.
   - Göç sırasında kimlik kayıtlarının `created_at`, `updated_at`, `owner_id`, `secret`, `iv`, `tag` alanları ve ilişkili `usage_snapshots` kayıtları KESİNLİKLE değiştirilmez.
   - Ayrıştırma veya şifreleme hatasında işlem tamamen geri alınır; kısmi satır güncellemesi veya veritabanı sürüm artışı engellenir.

6. **İki Aşamalı Üretim Dağıtımı ve Geri Dönüş Güvencesi (Rollout & Rollback Contract):**
   - **Aşama 1 (Reader-Only Staging):** `vault.ts` çift okuyucu yeteneğini içeren imaj dağıtılır; ortam değişkeni henüz eklenmez, Kimi boş kota veya arayüz değişiklikleri bu aşamada canlıya alınmaz. Veritabanı `user_version = 1` kalır. Uyumlu imaj etiketlenir ve taze yedek alınır.
   - **Aşama 2 (Full Release & Migration):** `CREDENTIAL_METADATA_ENCRYPTION=enabled` tanımlanmış tam sürüm dağıtılır; veritabanı `user_version = 2` düzeyine göç eder ve tüm yeni OAuth token'ları (Kimi dahil) şifreli saklanır.
   - **Geri Dönüş (Rollback):** Aşama 2'den Aşama 1 imajına geri dönülmesi gerekirse, Aşama 1 imajı içindeki çift okuyucu `user_version = 2` zarflarını doğrudan çözebilir; eski veritabanı yedeğinin geri yüklenmesine gerek kalmaz, veri kaybı veya kota kesintisi yaşanmaz.

7. **SQLite WAL Plaintext Kalıntısı ve Checkpoint Planı (Infra Notice):**
   - SQLite WAL modunda çalışan sistemlerde, göç öncesi düz metin satır sayfaları veritabanının `-wal` dosyasında bir süre daha kalabilir.
   - Sistem yöneticisi Aşama 2 dağıtımından hemen sonra ve eski yedekleri emekliye ayırmadan önce `PRAGMA wal_checkpoint(TRUNCATE);` komutunu çalıştırmalı veya konteynerin kontrollü yeniden başlatılmasıyla WAL dosyasının sıfırlanmasını sağlamalıdır.
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
7. **Sınırlı ve Ucuz Davet Kabulü:**
   - Public kabul endpoint'i, genel kayıtla ortak `registration` hız sınırına tabidir; aşımda HTTP 429 ve `Retry-After` döner. Davet kabulü, kayıt kapatma ayarından bağımsızdır; hız sınırından bağımsız değildir.
   - `AuthService.acceptInvitation`, token hash'iyle davetin varlığını, kabul/iptal durumunu ve süresini pahalı parola hashing'inden önce kontrol eder. Geçersiz, süresi dolmuş, iptal edilmiş veya tekrar kullanılan davetler aynı genel hatayla reddedilir.
   - Ön kontrol yalnız maliyet optimizasyonudur. Parola hash'i üretildikten sonra `acceptInvitationAtomic` aynı geçerlilik koşullarını transaction içinde yeniden doğrular; arada iptal/expiry veya eşzamanlı kabul ikinci kullanıcı oluşturamaz.

## 6. Operasyonel Yedekleme, İzleme ve Sentetik Yük Tatbikatı

### 6.1. Otomatik güvenli SQLite yedeği

- `deploy/backup/usemeter-backup.service` ve `.timer`, `murat` kullanıcısının **systemd user manager**'ı altında her gün 03:30 UTC civarında çalışır; root servis veya root shell gerektirmez.
- `usemeter-backup.sh`, canlı veritabanı için `StorageVault` başlatmadan bir defalık Compose/Bun süreciyle doğrudan SQLite `VACUUM INTO` kullanır. WAL içindeki commit edilmiş verileri tutarlı bir snapshot olarak alır; `usage.db` dosyasını tek başına kopyalamaz ve kaynak üzerinde açıkça `wal_checkpoint` ya da in-place `VACUUM` çalıştırmaz. SQLite WAL kilitlemesini yönetir ve kaynak veritabanının mantıksal içeriğini korur.
- Snapshot şeması tam olarak `PRAGMA user_version = 2`, `quick_check = 'ok'` ve `integrity_check = 'ok'` olmalıdır. Host yedeği `murat` sahibinde, `0600` modunda; yedek dizini `0700` modundadır (`umask 077`). Yedek, doğrulama bitmeden adlandırılmış kalıcı dosya olarak yayımlanmaz.
- Retention bütün son 7 günlük dosyaları, ardından yaş 28 günü geçmeyen her ISO haftanın en yeni dosyasını korur; daha eskileri kaldırır. Prune yalnızca yeni yedek restore-drill'i geçtiğinde çalışır.

### 6.2. İzole restore-drill

`usemeter-restore-drill.sh BACKUP_FILE` adayı `--network none`, salt okunur kök dosya sistemi ve salt okunur bind mount ile ayrı container içinde doğrular. Bu container üretim volume'unu **bağlamaz**, `src/index.ts`, `StorageVault`, migration, poller veya provider çalıştırmaz. Adayı salt-okunur/query-only SQLite bağlantısıyla açar; şema sürümünü, `quick_check`, `integrity_check`, credential/snapshot sayılarını ve her şifreli metadata zarfının `$vault: 1` yapısını denetler. Tatbikat gerçek bir canlı geri yükleme veya master-key ile credential decrypt testi değildir; üretim DB'sinin üzerine yazma yolu yoktur.

### 6.3. Admin metrikleri ve eşikler

`GET /api/admin/metrics` yalnızca mevcut admin yetkilendirmesinden sonra erişilir. Yanıt; ana DB ve WAL fiziksel boyutlarını, filesystem boş alan/kullanım oranını, SQLite free-page sayısını, snapshot ve aktif credential toplamlarını, quick integrity health'i, poller çalışma/sweep durumunu, son sweep süresini ve ardışık başarısız/degraded sweep sayısını taşır. Thresholds:

- Disk kullanımı `>= 90%` → `DISK_USAGE_HIGH`.
- Poller durdurulmuş → `POLLER_STOPPED`; ardışık en az 3 bozuk/başarısız sweep → `POLLER_FAILURES_CONSECUTIVE`.
- Integrity başarısız → `DATABASE_INTEGRITY_FAILED`.
- Mail socket yapılandırılmış ama bağlanılamıyor → `MAIL_BRIDGE_UNAVAILABLE`; socket yapılandırılmamışsa `disabled`.

Mail bridge probu sadece Unix socket'e bağlanıp bağlantıyı kapatır; e-posta içeriği/token göndermez ve sendmail çalıştırmaz. Alert kodları admin yanıtında görünür; harici e-posta/webhook bildirim hedefi bu sözleşmenin parçası değildir. Public `/health` mevcut küçük readiness/integrity cevabını korur.

### 6.4. Sentetik eşzamanlı yük testi

`deploy/bench/synthetic-load-test.ts`, `/health`, `/api/data`, `/api/providers/catalog`, `/forgot-password` ve `/privacy` rotalarına sentetik GET trafiği gönderir. Varsayılan senaryo 1.000 istek/50 eşzamanlı worker'dır; concurrency 50–100 ile sınırlıdır. p50/p95/p99 gecikme, throughput, HTTP status/error oranı ve başlangıç/tepe/son RSS ölçülür; beklenen hata oranı `%0`'dır.

Yalnız `http://127.0.0.1` hedefi kabul edilir; redirect takip edilmez, proxy ortam değişkenleri varsa çalışma reddedilir. En az iki ayrı sentetik staging kullanıcısına ait session cookie gereklidir; `/api/auth/me` ön kontrolüyle kullanıcıların farklı olduğu doğrulanır ve cookie/user ID çıktıya yazılmaz. Harness kullanıcı oluşturmaz, sağlayıcı adaptörlerini çağırmaz ve loopback dışına bağlanmaz. Benchmark production gerçek kullanıcı cookie'leriyle çalıştırılmaz; RSS ölçümü olası bellek sızıntısını tek başına kanıtlamaz veya çürütmez.
