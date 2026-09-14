# ADR-0003: Özel Çok Kullanıcılı Mimari, Argon2id ve Sunucu Taraflı Opak Oturum Yönetimi

- **Durum:** Kabul Edildi
- **Tarih:** 2026-09-14
- **Karar Vericiler:** Murat
- **İlgili Belgeler:** [CONTEXT.md](../../CONTEXT.md), [docs/SPEC.md](../SPEC.md), [ADR-0001](0001-self-hosted-bff-architecture.md), [ADR-0002](0002-dual-engine-tracking-model.md)

---

## 1. Bağlam ve Problem Tanımı

Sistem başlangıçta tek kullanıcılı, yerel masaüstü veya tekil self-hosted sunucu ortamı için tasarlanmıştı (ADR-0001). Ancak kullanım senaryosu genişleyerek, güvenilir birden fazla kullanıcının (örneğin aile bireyleri, çalışma arkadaşları veya ortak altyapıyı paylaşan mühendisler) aynı sunucu örneği üzerinde kendi AI hesap kotalarını ve bakiyelerini birbirlerinden tamamen izole biçimde takip edebileceği **özel çok kullanıcılı (private multi-user SaaS)** bir servis katmanına evrilmiştir.

Bu geçişle birlikte aşağıdaki kritik mimari ihtiyaçlar doğmuştur:
1. **Kimlik Doğrulama Mekanizması:** Harici üçüncü taraf servislere veya OAuth sağlayıcılarına (Google, GitHub vb.) bağımlı kalmadan, sıfır harici ağ bağımlılığıyla çalışabilen güvenli bir kimlik doğrulama katmanı.
2. **Oturum Yönetimi:** JWT (JSON Web Token) gibi istemci taraflı durumsuz token'lar ile sunucu taraflı opak oturumlar arasındaki güvenlik ve iptal (revocation) takası.
3. **Veri İzolasyonu ve Çok Kiracılık (Multi-Tenancy):** SQLite veritabanı üzerinde her kullanıcının kimlik bilgilerini ve kullanım verilerini diğer kullanıcılardan kesin olarak ayıran satır düzeyinde kiracı izolasyonu (`ownerId`).
4. **Mevcut Verilerin Korunması ve Göç (Legacy Migration):** Tek kullanıcılı dönemden kalan ve bir sahibi bulunmayan (`owner_id IS NULL`) kimlik bilgilerinin ve kullanım kayıtlarının veri kaybı yaşanmadan yeni mimariye aktarılması.
5. **Güvenlik Sınırları ve Çerez Politikası:** Web paneli ve veri API'lerinin kamuya açık olmaması, yetkilendirme zorunluluğu ve CSRF/XSS tehditlerine karşı tarayıcı çerezi duruşu.

---

## 2. Değerlendirilen Alternatifler

### Alternatif A: İstemci Taraflı Durumsuz JWT (Stateless JWT)
- **Gerekçe:** Sunucuda oturum tablosu tutmayı gerektirmez; yatay ölçekleme kolaydır.
- **Red Nedenleri:**
  - **İptal Edilemezlik:** Kullanıcı çıkış yaptığında (`logout`) veya bir oturum çalındığında, token süresi dolana kadar sunucu tarafında anında ve kesin olarak iptal edilemez. İptal listesi (blacklist/denylist) tutulduğunda ise durumsuzluğun getirdiği tüm avantajlar kaybolur.
  - **Gizli Anahtar Sızıntı Riski:** JWT imzalama anahtarı sızdığında tüm kullanıcılar adına sahte token üretilebilir.
  - **Gereksiz Karmaşıklık:** Tek SQLite veritabanı ile çalışan BFF mimarisinde veritabanı sorgusu zaten mikro-saniye düzeyindedir; durumsuzluğun pratik bir avantajı yoktur.

### Alternatif B: Harici Kimlik Sağlayıcıları ile Giriş (Social / Third-Party OAuth)
- **Gerekçe:** Kullanıcının parola hatırlama ihtiyacını ortadan kaldırır.
- **Red Nedenleri:**
  - **Dış Bağımlılık ve Çevrimdışı Çalışabilirlik:** Sistemin temel ilkelerinden biri sıfır harici API bağımlılığı ve yerel ağda/çevrimdışı bile çalışabilmesidir. Google/GitHub OAuth zorunluluğu bu ilkeyi bozar.
  - **Karmaşık Kurulum:** Self-hosted kuran her kullanıcının Google Cloud Console veya GitHub Developer ayarlarından OAuth Client ID/Secret üretmesini gerektirir; kurulum sürtünmesini devasa artırır.
  - *Not:* AI sağlayıcılarına (OpenAI, Google Antigravity, Claude) kota sorgulamak için yapılan OAuth bağlantıları ile sistemin kendi kullanıcı girişi birbirinden tamamen bağımsızdır.

### Alternatif C: Parola + Sunucu Taraflı 32 Baytlık Opak Oturum Belirteci (Seçilen)
- Kullanıcı e-posta ve parola ile kaydolur/giriş yapar.
- Parolalar Bun'ın yerel Argon2id motoru ile hash'lenir.
- Oturum açıldığında istemciye 32 baytlık kriptografik rastgele bir opak dize (`auth_session`) çerezi atanır.
- Veritabanında yalnızca token'ın SHA-256 özeti saklanır.
- Çıkış anında oturum satırı silinerek anında ve kesin iptal sağlanır.

---

## 3. Alınan Kararlar

### 1. Parola Güvenliği: Bun.password Argon2id
- Kullanıcı parolaları Bun çalışma zamanının yerleşik `Bun.password` Argon2id algoritmasıyla şifrelenir (`algorithm: "argon2id"`).
- Parolalar minimum 12 karakter, maksimum 256 UTF-8 karakter/kod birimi olarak sınırlandırılır ve deterministik doğrulamadan geçirilir.
- E-postalar sistem genelinde `trim().toLowerCase()` kuralıyla kanonikleştirilir ve büyük/küçük harf duyarsız tekildir (`COLLATE NOCASE UNIQUE`).
- Giriş başarısızlıklarında saldırganın sistemde bir e-postanın kayıtlı olup olmadığını anlamasını engellemek için genel hata mesajı (`Invalid email or password`) fırlatılır (User Enumeration Koruması).

### 2. Durum Bilgili Opak Oturumlar ve SHA-256 Özetleme
- İstemciye verilen oturum belirteci 32 baytlık kriptografik rastgele baytlardan (`crypto.getRandomValues`) türetilir.
- Veritabanı `sessions` tablosunda token'ın düz metin hali ASLA tutulmaz; yalnızca tek yönlü **SHA-256 hash'i (`token_hash`)** saklanır. Böylece veritabanı anlık yedeği veya sızıntısı durumunda dahi aktif oturumlar taklit edilemez.
- Oturum yaşam süresi (TTL) **30 gündür** (`2592000` saniye).
- Kullanıcı çıkış yaptığında (`logout`) veritabanındaki oturum kaydı anında silinir.

### 3. Çerez Politikası ve CSRF/XSS Koruması
Oturum belirteci istemciye `Set-Cookie` başlığıyla iletilir:
- `HttpOnly: true` → Tarayıcı içi JavaScript (XSS saldırıları) belirtece erişemez.
- `SameSite: Lax` → Üçüncü taraf sitelerden tetiklenen sahte istekleri (CSRF) engellerken, kullanıcının doğrudan link tıklayarak siteye gelmesinde oturumun korunmasını sağlar.
- `Path: /` → Uygulama genelinde geçerlidir.
- `Secure: true` → HTTPS ve production ortamlarında zorunludur.

### 4. SQLite Satır Düzeyinde Kiracı İzolasyonu (Tenant Boundary)
- `credentials` ve `usage_snapshots` tablolarına `owner_id` (foreign key -> `users.id`) kolonu eklenmiştir.
- `PRAGMA foreign_keys = ON;` ile referans bütünlüğü zorunlu kılınmıştır.
- `(owner_id, provider)` ve `(owner_id, recorded_at)` üzerinde indeksler tanımlanmıştır.
- **Veri Erişim Sözleşmesi:** Uygulama katmanındaki tüm veri okuma, güncelleme ve silme API'leri zorunlu olarak `ownerId` parametresi alır. Hiçbir kullanıcı başka bir kullanıcının kimlik bilgilerini, kotalarını veya anlık raporlarını göremez/yönetemez.
- **Korumalı Yüzey:** Dashboard sayfası (`GET /`) ve tüm veri uç noktaları (`/api/usage`, `/api/credentials`, `/api/refresh`) geçerli bir oturum zorunlu kılar; kamuya açık anonim veri erişimi kesinlikle yasaktır.

### 5. Eski Verilerin Atomik Sahiplenilmesi (First-User Legacy Claim)
Tek kullanıcılı sürümden çok kullanıcılı mimariye geçerken:
- Mevcut kimlik bilgileri ve kullanım anlık görüntüleri silinmez (`owner_id` değeri başlangıçta `NULL` kalır).
- Sisteme kaydolan ilk gerçek (non-system) kullanıcı (`users` tablosundaki ilk kayıt), tek bir veritabanı transaction'ı içinde sahipsiz tüm kayıtları atomik olarak sahiplenir:
  ```sql
  UPDATE credentials SET owner_id = :firstUserId WHERE owner_id IS NULL;
  UPDATE usage_snapshots SET owner_id = :firstUserId WHERE owner_id IS NULL;
  ```
- Bu işlemden sonra sistemde sahipsiz kayıt kalmaz; daha sonra kaydolan kullanıcılar bu eski verileri asla göremez.

### 6. Genel Arka Plan Daemon vs Sahip Odaklı Manuel Tetikleme
- **Arka Plan Yoklayıcı (Poller Daemon):** 7/24 çalışan arka plan servisi, tüm sağlayıcı hesaplarının kotalarını güncel tutabilmek için açıkça tanımlanmış tek dahili metot olan `listAllCredentialsInternal()` ile tüm kimlikleri okur ve günceller. Bu işlem sunucu içi dahili bir süreçtir; dış HTTP API'lere açık değildir.
- **Kullanıcı Tetiklemeli Manuel Yenileme (`POST /api/refresh`):** Kullanıcının web panelinden başlattığı yenileme istekleri zorunlu olarak yalnızca oturum açmış kullanıcının sahip olduğu (`ownerId`) kimlik bilgileriyle sınırlıdır.

### 7. Kapsam Dışı Bırakılan Unsurlar (Explicit Out-of-Scope)
Aşağıdaki kurumsal/kamusal SaaS özellikleri bilinçli olarak kapsam dışı bırakılmıştır:
- Çoklu roller / Yetkilendirme matrisi (RBAC).
- Organizasyonlar, ekipler veya kullanıcılar arası hesap paylaşımı.
- Parola sıfırlama (password reset) ve e-posta doğrulama e-postaları (harici SMTP gerektirmemek için).
- Ücretlendirme, abonelik ve faturalandırma katmanları (Stripe vb.).

---

## 4. Sonuçlar ve Takaslar

### Kazanımlar (Pros)
1. **Tam İzolasyon:** Her kullanıcı yalnızca kendi AI hesaplarını ve kotalarını görür.
2. **Kusursuz İptal Güvenliği:** Sunucu taraflı oturum tablosu sayesinde çıkış yapıldığında oturum saniyesinde sonlanır.
3. **Sıfır Dış Bağımlılık:** Harici kimlik sağlayıcısı veya harici e-posta servisi gerekmez; Bun yerel yetenekleriyle tamamen izole çalışır.
4. **Sıfır Veri Kaybı:** Tek kullanıcılı sistemden gelen geçmiş kotalar ve tanımlı kimlikler ilk kullanıcıya devredilerek korunur.
5. **Saldırı Direnci:** `HttpOnly` + `SameSite: Lax` çerezleri XSS ve CSRF risklerini asgariye indirir.

### Ödünler (Cons)
1. Her kimlik doğrulama isteğinde `sessions` tablosuna bir indeksli okuma yapılır (SQLite bellek önbelleğinde < 0.1 ms).
2. Süresi dolmuş oturum satırlarının periyodik olarak temizlenmesi gerekir (basit zamanlayıcı veya oturum açma sırasında temizlik).
