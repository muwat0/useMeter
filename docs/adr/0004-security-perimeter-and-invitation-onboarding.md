# ADR-0004: Güvenlik Çevresi, Ters Vekil Güveni ve Yönetici Davetiyesi ile Kontrollü Katılım

- **Durum:** Kabul Edildi
- **Tarih:** 2026-09-15
- **Karar Vericiler:** Murat
- **İlgili Belgeler:** [CONTEXT.md](../../CONTEXT.md), [docs/SPEC.md](../SPEC.md), [ADR-0001](0001-self-hosted-bff-architecture.md), [ADR-0002](0002-dual-engine-tracking-model.md), [ADR-0003](0003-multi-tenant-session-authentication.md)

---

## 1. Bağlam ve Problem Tanımı

useMeter çok kullanıcılı özel SaaS modeline (ADR-0003) geçtikten sonra, self-hosted dağıtımlarda (örneğin ev sunucuları, VPS'ler, bulut sunucuları veya yerel ağ geçitleri) uygulamanın internete veya paylaşımlı ağlara açılması ihtiyacı doğmuştur. Bu durum aşağıdaki somut güvenlik gereksinimlerini gündeme getirmiştir:

1. **Ağ ve Tarayıcı Tehditleri:** Clickjacking, MIME türü sahteciliği (MIME-sniffing), yetkisiz iframe gömmeleri ve XSS saldırılarına karşı standart yanıt başlıkları ve Content Security Policy (CSP) duruşunun netleştirilmesi.
2. **Kökenler Arası Kaynak Paylaşımı (CORS):** Harici origin'lerden gelen API isteklerinin denetlenmesi ve kimlikli (`auth_session` çerezli) isteklerde joker karakter (`*`) istismarının önlenmesi.
3. **Ters Vekil (Reverse Proxy) IP Tespiti:** Sistemin Nginx, Caddy veya Cloudflare arkasında çalışması durumunda hız sınırlarının istemci yerine vekil IP'sine uygulanmaması, ancak doğrudan erişimlerde sahte `X-Forwarded-For` başlıklarıyla IP sahteciliğine (spoofing) izin verilmemesi.
4. **Hizmet Reddi ve Kaba Kuvvet Koruması:** Kimlik doğrulama, manuel kota sorgulama ve OAuth cihaz akışı uç noktalarında DoS ve kaba kuvvet saldırılarını önleyen bellek içi hız sınırlayıcı (rate limiter) gereksinimi.
5. **Kontrollü Kullanıcı Katılımı (Onboarding):** Genel dış kayıtların (`registrationAllowed = false`) kapatıldığı özel/kurumsal ortamlarda yöneticinin belirlediği kullanıcılara güvenli, süreli ve tek kullanımlık kayıt imkânı sunulması.
6. **Sıfır Dış Bağımlılık İlkesi (No SMTP):** Self-hosted kullanım kolaylığını korumak için davetiye sisteminin harici SMTP sunucusu, e-posta sağlayıcısı veya API anahtarı zorunluluğu getirmemesi.

---

## 2. Değerlendirilen Alternatifler

### Alternatif A: Harici E-posta (SMTP) Bağımlı Davetiye Sistemi
- **Gerekçe:** Geleneksel SaaS ürünlerinde davetiyelerin kullanıcının e-posta adresine doğrudan link olarak postalanması.
- **Red Nedenleri:**
  - **Kurulum Sürtünmesi:** Self-hosted kuran kullanıcının SMTP sunucusu (Postfix/Dovecot), TLS sertifikası veya harici işlemci (Resend, SendGrid, Amazon SES) yapılandırmasını zorunlu kılar; hafif BFF felsefesini bozar.
  - **Kırılganlık:** Port 25 blokajları, SPF/DKIM/DMARC ayar zorlukları veya spam filtreleri yüzünden davetiyelerin ulaşamaması destek yükü oluşturur.
  - **Karar:** Sistem bünyesinde SMTP katmanı kurulmaz; yönetici oluşturulan davet bağlantısını (`/invite/:token`) panodan kopyalar ve kullanıcıya güvendiği kanaldan (Signal, Telegram, şirket içi chat vb.) kendisi iletir.

### Alternatif B: Dağıtık / Redis Tabanlı Hız Sınırlama
- **Gerekçe:** Çoklu sunucu/küme (cluster) mimarilerinde merkezi hız sayacı tutma.
- **Red Nedenleri:**
  - useMeter bağımsız çalışan tekil bir Bun süreci ve yerel SQLite kasası üzerinde çalışır (ADR-0001).
  - Redis veya harici KV deposu eklemek operasyonel karmaşıklığı gereksiz artırır.
  - **Karar:** Deterministik saat dikişi (`now()` injection seam) ve maksimum 10.000 anahtar tavanlı kayan pencere (sliding window) kullanan bellek içi `RateLimiter` uygulanır.

### Alternatif C: Nonce/Hash Tabanlı Katı CSP
- **Gerekçe:** XSS riskini en aza indiren en katı CSP standardı.
- **Red Nedenleri:**
  - useMeter sunucu taraflı HTML üretimi (SSR), gömülü tema/dil JavaScript kodları ve CDN üzerinden yüklenen Tailwind CSS motoru kullanmaktadır.
  - Nonce veya dinamik hash üretimi mevcut hafif SSR şablon mimarisinde devasa refactor gerektirir ve önbellek/render akışlarını karmaşıklaştırır.
  - **Karar:** `script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com` ve `style-src 'self' 'unsafe-inline'` içeren pragmatik `MINIMAL_SSR_CSP` uygulanır; dokümantasyonda asla overclaim (gerçekte olmayan nonce koruması iddiası) yapılmaz.

---

## 3. Alınan Kararlar

### 1. Standart Yanıt Güvenlik Başlıkları
`src/server/security.ts` modülü üzerinden tüm yanıtlara global olarak enjekte edilir:
- `X-Frame-Options: DENY` (Tüm sayfalarda iframe içine gömülmeyi engeller).
- `X-Content-Type-Options: nosniff` (MIME sniffing saldırılarını engeller).
- `Referrer-Policy: strict-origin-when-cross-origin` (Harici yönlendirmelerde gizlilik korur).
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` (Gereksiz tarayıcı yeteneklerini kapatır).
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (Yalnızca HTTPS veya `secure: true` ortamlarında 1 yıllık HSTS uygular).

### 2. Pragmatik Content Security Policy (CSP)
- Mevcut SSR ve Tailwind gereksinimlerine tam uyumlu `MINIMAL_SSR_CSP` politikası tanımlanmıştır:
  ```text
  default-src 'self';
  script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com;
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self'
  ```
- Nonce veya dinamik script hash'i iddia edilmez; `'unsafe-inline'` kullanımı bilinçli bir SSR uyumluluk takasıdır.

### 3. Güvenli CORS Politikası ve Kimlikli Joker Karakter Yasağı
- İzin verilen kökenler `CORS_ALLOWED_ORIGINS` veya `USEMETER_ALLOWED_ORIGINS` ortam değişkenleriyle belirlenir.
- Değişken boşsa **aynı köken varsayılanı (same-origin)** geçerlidir; dış kökenlere CORS başlığı basılmaz.
- useMeter oturum çerezleri (`auth_session`) kullandığından (`allowCredentials: true`), RFC 6454 standardı uyarınca joker karakter (`*`) kullanımı **kesinlikle reddedilir** (`isOriginAllowed` -> `false`).

### 4. Sıkı Ters Vekil Güveni (`TRUST_PROXY`)
- Varsayılan olarak `trustProxy = false` durumundadır. İstemcinin gönderdiği `X-Forwarded-For` veya `X-Real-IP` başlıkları IP sahteciliğine (spoofing) karşı yok sayılır; doğrudan soket uzak adresi kullanılır.
- Sistem güvenilir bir ters vekil (Nginx/Cloudflare) arkasında çalıştığında `TRUST_PROXY=true` veya `TRUST_PROXY=1` ayarı ile `X-Forwarded-For` başlığındaki en soldaki (istemciye ait) IP güvenle çözümlenir.

### 5. Sınırlandırılmış Bellek-İçi Hız Sınırlayıcı (RateLimiter)
- En fazla 10.000 benzersiz anahtar tutan (`maxKeys: 10000`) ve kayan pencere (sliding window) kullanan hafif bellek-içi hız sınırlayıcı devreye alınmıştır.
- Standart politikalar:
  - `auth`: `5 istek / dakika / IP` (`/api/auth/login`, `/api/auth/register`)
  - `manualPoll`: `1 istek / 30 saniye / kullanıcı + credential` (`/api/refresh`)
  - `oauthDevicePoll`: `30 istek / dakika / kullanıcı + flow`
- Aşımlarda `429 Too Many Requests` ve `Retry-After` yanıtı verilir.

### 6. Yönetici Davetiye Sistemi ve Tek Kullanımlık Katılım (Invitation Onboarding)
- **Yalnızca Yönetici Yetkisi:** Davetiyeleri yalnızca `admin` rolündeki kullanıcılar üretebilir (`POST /api/admin/invitations`).
- **Kriptografik Token Güvenliği:**
  - İstemciye 32 baytlık rastgele güvenli dize (`crypto.getRandomValues`) verilir.
  - Veritabanında (`invitations` tablosu) token'ın ham hali ASLA tutulmaz; yalnızca tek yönlü **SHA-256 hash'i (`token_hash`)** saklanır.
- **24 Saat Geçerlilik ve Tek Kullanım:**
  - Davetiyeler 24 saat (`86.400.000` ms) sonra zaman aşımına uğrar (`expired`).
  - Bir kez kabul edilen davetiye `accepted_at` ile kilitlenir; ikinci kez kullanılamaz.
  - Yönetici dilediğinde davetiyeyi tek tıkla iptal edebilir (`DELETE /api/admin/invitations/:id` -> `revoked_at`).
- **Zorunlu E-posta Kilidi (Strict Email Binding):** Davetiye üretilirken yönetici tarafından geçerli bir hedef e-posta adresi belirtilmesi zorunludur; useMeter bünyesinde anonim veya e-postasız serbest davetiye bulunmaz. Kabul formunda e-posta alanı salt-okunur olarak kilitlenir ve kayıt sırasında hesap doğrudan bu e-posta ile büyük/küçük harf duyarsız (`COLLATE NOCASE`) olarak oluşturulur.
- **Kayıt Kapalıyken Katılım (Registration Policy Bypass):** Sistemde genel dış kayıtlar kapatılmış olsa dahi (`isRegistrationAllowed() === false`), geçerli bir davetiye token'ı taşıyan kullanıcılar başarıyla kaydolabilir.
- **E-posta İletim Sınırı (No SMTP Boundary):** useMeter bünyesinde hiçbir e-posta iletim mekanizması bulunmaz. Yönetici panelden bağlantıyı kopyalar ve kullanıcıya harici güvenli yollardan iletir.

---

## 4. Güvenlik ve Tehdit Modeli Takasları (Threat Tradeoffs)

| Alan | Seçilen Yaklaşım | Tercih Nedeni | Bilinen Takas / Risk Kısıtı |
|---|---|---|---|
| **CSP** | `'unsafe-inline'` içeren pragmatik SSR CSP | Mevcut sunucu taraflı HTML, tema scriptleri ve Tailwind CDN uyumluluğu | Nonce seviyesinde tam script izolasyonu sağlanamaz; ancak clickjacking ve veri kaçırma (data exfiltration) önlenir. |
| **CORS** | Katı izin listesi, kimlikli istekte `*` yasağı | Yetkisiz sitelerin kullanıcının `auth_session` çereziyle oturum çalmasını engelleme | Dış kökenden API tüketecek meşru araçların açıkça `CORS_ALLOWED_ORIGINS` içine yazılması gerekir. |
| **IP Tespiti** | Varsayılan `TRUST_PROXY=false` | İstemcilerin sahte `X-Forwarded-For` ile hız sınırlarını aşmasını engelleme | Ters vekil arkasında çalışan kurulumlarda `TRUST_PROXY=true` ortam değişkeni unutulursa tüm istekler vekilin yerel IP'sine sayılır. |
| **Hız Sınırlama** | Bellek-içi kayan pencere (tavan: 10k anahtar) | Sıfır harici servis (Redis) bağımlılığı, mikro-saniye gecikme | Sunucu yeniden başladığında sayaçlar sıfırlanır; tekil Bun süreci için geçerlidir. |
| **Davetiye Token** | 32-bayt rastgele dize + DB'de SHA-256 | Veritabanı sızıntısında açık davetiye token'larının ele geçirilmesini engelleme | Yönetici oluşturduğu bağlantıyı kaybettiğinde hash'ten token geri döndürülemez; yeni davetiye üretilmelidir. |
| **İletişim** | Manuel bağlantı kopyalama (No SMTP) | Kurulum sürtünmesini sıfıra indirme, spam/reputasyon risklerini yok etme | Yöneticinin bağlantıyı güvenli bir iletişim kanalı üzerinden kullanıcıya manuel iletmesi gerekir. |

---

## 5. Sonuçlar ve Gelecek Uyarlamalar

- Sistem, harici bir ağa açıldığında veya yerel ağda birden fazla kullanıcıya hizmet verdiğinde standart web saldırılarına karşı korunur hale getirilmiştir.
- Gelecekte SSR şablon motoru derleme aşamasında inline scriptleri ayıklar veya statik bir SPA ayrımına gidilirse, CSP politikası `'unsafe-inline'` bağımlılığından kurtarılarak nonce veya hash temelli katı modele yükseltilebilir.
- Çoklu sunucu dağıtımı hedeflenmediği sürece bellek-içi hız sınırlayıcı ve veritabanı düzeyindeki davetiye takibi mimari açıdan yeterli ve yalındır.
