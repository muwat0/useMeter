# CONTEXT.md — useMeter: AI Kota, Bakiye ve Kullanım Takip Sistemi (Ubiquitous Language)

Bu belge, sistem genelinde kullanılan temel etki alanı (domain) kavramlarının ve iş kurallarının kanonik sözlüğüdür. Tüm modüller, dokümanlar, API uç noktaları ve veritabanı şemaları buradaki terminolojiye uymak zorundadır.

---

## 1. Temel Etki Alanı Varlıkları (Core Entities)

### Kullanıcı (User)
Uygulamanın web arayüzüne ve API'lerine erişmek için kimlik doğrulayan bağımsız hesap sahibi (login identity).
- **Kimlik Belirteci:** Sistem genelinde benzersiz, canonical (küçük harfe dönüştürülmüş ve kırpılmış / `trim().toLowerCase()`) e-posta adresi.
- **Parola:** Bun yerel Argon2id algoritması ile hash'lenmiş şifre özeti.
- **Rol ve Sınır:** Sistemdeki kiracı (tenant) sınırını belirler. İki rol vardır: `admin` ve `user`.

### Yönetici Kullanıcı (Admin User)
Sistem genelinde kullanıcıları ve sistem telemetrisini yönetme yetkisine sahip kullanıcı (`role: "admin"`).
- **İlk Kullanıcı Kuralı:** Sisteme ilk kaydolan kullanıcı (aynı zamanda eski verileri sahiplenen kişi) otomatik olarak `admin` rolü alır. Sonraki kullanıcılar `user` rolüyle kaydolur.
- **Yetki Alanı:** Kullanıcıları listeleme, rolleri değiştirme (yönetici atama/yetki alma), kullanıcı silme (ilişkili hesap ve kayıtların silinmesiyle birlikte) ve sistem genel telemetrisini (toplam kullanıcı, aktif oturum, DB boyutu, sağlayıcı dağılımı) izleme.
- **Güvenlik Kısıtı:** Yönetici yönetim uç noktasından kendi hesabını silemez; sistemdeki son yönetici sıradan kullanıcıya düşürülemez veya silinemez. Ayrı, mevcut parola ve etkin oturum gerektiren öz-silme akışı, başka bir yönetici kalıyorsa yöneticiler için de kullanılabilir. Normal kullanıcılar yönetici paneline (`/admin`) ve uç noktalarına (`/api/admin/*`) erişemez (HTTP 403 Forbidden).

### Sağlayıcı Hesabı / Harici Hesap (Provider Account)
Bir yapay zeka sağlayıcısı nezdinde (OpenAI, Anthropic, Google Cloud, Cursor vb.) tanımlı olan harici abonelik veya kimlik bilgisi kaydı.
- **Kritik Ayrım:** Uygulama Kullanıcısı (`User`) ile Sağlayıcı Hesabı (`Provider Account`) kesinlikle aynı kavramlar DEĞİLDİR. Bir Uygulama Kullanıcısı sisteme kaydolup oturum açar; ardından kendi paneline birden fazla AI Sağlayıcı Hesabı (API anahtarı veya OAuth bağlantısı) ekler.
- **Sahiplik:** Her Sağlayıcı Hesabı tam olarak bir Uygulama Kullanıcısına (`ownerId`) aittir.

### Oturum (Session)
Kimliği doğrulanmış bir kullanıcının web paneline ve korumalı API'lere erişimini sağlayan durum bilgisi.
- **Oturum Belirteci (Session Token):** İstemciye HTTP çerezi (`usage_session`) içinde gönderilen 32 baytlık kriptografik olarak güvenli opak rastgele dize (opaque token).
- **Kalıcılık ve Güvenlik:** Veritabanında oturum belirtecinin açık hali ASLA saklanmaz; yalnızca SHA-256 hash özeti (`token_hash`) saklanır.
- **Geçerlilik Süresi (TTL):** 30 gündür (2.592.000 saniye). Süresi dolan veya sonlandırılan (logout) oturumlar anında yetkisiz hale gelir.

### Parola Değişikliği (Password Change)
Kullanıcının mevcut parolasını ve etkin oturumunu doğrulayarak giriş parolasını değiştirmesi. Başarılı değişiklik işlemini yapan oturumu korur; kullanıcının diğer oturumlarını ve bekleyen Parola Kurtarma Girişimlerini atomik olarak geçersiz kılar. Bekleyen sağlayıcı yetkilendirmeleri iptal edilir; geciken kimlik bilgisi veya yoklama yazıları eski doğrulama yetkisiyle kayıt oluşturamaz.

### Parola Kurtarma Girişimi (Password Recovery Attempt)
Kullanıcının e-posta adresine gerçek posta yoluyla ulaştırılan, parola yenileme yetkisi. Oturum, Davetiye veya Sağlayıcı Yetkilendirme Girişimi değildir. Kullanıcı başına yalnızca en yeni girişim geçerlidir; 15 dakika sonra sona erer ve bir kez tüketilebilir. Veritabanında yalnız token özeti saklanır. Başarılı tüketim parola yenileme ve kullanıcının tüm Oturumlarının iptaliyle atomiktir; kurtarma otomatik giriş yapmaz. Token hangi hesabın yenileneceğini belirler; aynı istekteki başka bir hesabın tarayıcı çerezi veya verisi etkilenmez. Kamuya açık istek, hesabın varlığını veya posta teslimat sonucunu açıklamaz. Posta hizmeti yapılandırılmadığında yeni kurtarma istekleri kapalıdır; önceden verilmiş geçerli bir girişim yine tüketilebilir.

### Kullanıcı Öz-Silme (Self-Service Account Deletion)
Etkin Oturum ve mevcut parola ile Kullanıcının kendi uygulama hesabını kalıcı olarak silmesi. Kullanıcıya ait Oturumlar, Kimlik Bilgileri, Kullanım Anlık Görüntüleri, Kurtarma Girişimleri ve oluşturduğu Davetiyeler birlikte silinir. Başka bir yönetici kalmadıysa yönetici hesabı silinemez. Bekleyen sağlayıcı yetkilendirmeleri ve geciken yoklama/kimlik bilgisi yazıları eski mülkiyet yetkisiyle veri oluşturamaz. Önceden alınmış yedeklerin ayrı saklama politikası vardır; canlı silme yedeklerin silindiği anlamına gelmez.

### Geri Alınmış Yazma Yetkisi (Revoked Mutation Authority)
Parola veya Oturum doğrulaması ile kalıcı değişiklik arasındaki süre içinde değişen yetkinin eski doğrulama sonucuyla kullanılmaması kuralı. Parola, oturum ve reset belirteci geçerliliği geri döndürülemez atomik yazmadan hemen önce yeniden doğrulanır; kabul edilmiş senkron yazma geriye dönük başarısız sayılmaz.

### Sağlayıcı Yetkilendirme Girişimi (Provider Authorization Attempt)
Bir Uygulama Kullanıcısının belirli bir Sağlayıcı Hesabını bağlamak için başlattığı, kısa ömürlü ve tek kullanımlık yetkilendirme süreci.
- Kullanıcının panel erişim Oturumu değildir; kalıcı Kimlik Bilgisi kaydı da değildir.
- Tek bir Kullanıcıya ve Sağlayıcıya bağlıdır. Başarılı doğrulama sonunda Kimlik Bilgisi oluşturabilir veya aynı hesabın mevcut kimliğini güncelleyebilir; başarısız, iptal edilmiş veya süresi dolmuş girişim kalıcı hesap verisini değiştirmez.
- **Manuel Tamamlama:** Sağlayıcının tarayıcıda döndürdüğü yetkilendirme yanıtının Kullanıcı tarafından kendi girişimine teslim edilmesi. Yanıt yalnız ilgili Kullanıcı/girişim bağında ve tek kez tüketilir; farklı bir kullanıcının girişimini tamamlayamaz.



### Sağlayıcı Doğrulama ve Destek Düzeyi (Provider Verification & Support Tier)
Bir sağlayıcıya bağlanabilmenin, gerçek kullanım verisi alabilmenin ve uygulamanın kendi akışlarını sentetik verilerle sınamanın farklı kanıtlar olduğunu belirten sınıflandırma.
- **Canlı Telemetri Doğrulandı (Live Telemetry Verified):** Gerçek sağlayıcı yanıtından geçerli, normalize bakiye/kota/kullanım verisi gözlenmiştir. Bu kanıt, her yetkilendirme yolunun veya her planın denendiği anlamına gelmez; ilgili bağlantı yolu ve doğrulama kapsamı ayrıca belirtilir.
- **Yalnız Bağlantı Doğrulandı (Connection Verified Only):** Gerçek hesabın bağlandığı gözlenmiştir; sağlayıcı kullanım verisi bildirmemişse veya kota yanıtı henüz gözlenmemişse telemetri doğrulanmış sayılmaz. Boş veri, üyelik bulunmadığı veya kotanın tükendiği sonucu değildir.
- **Canlı Doğrulanmadı (Not Live Verified):** Uygulama ve adaptör kodu bulunabilir, sentetik testler geçebilir; bunlar gerçek sağlayıcı bağlantısı veya telemetri kanıtı yerine geçmez. “Topluluk tarafından destekleniyor” ya da hizmet garantisi anlamı yüklenmez.
- **Deneysel Uyumluluk (Experimental Compatibility):** Belgelenmemiş sağlayıcı davranışı, doğrulanmamış callback/istemci uyumluluğu veya benzeri sınırlamadır; kanıt düzeyinden ayrı bir uyarıdır. Gerçek kota tükenmesi sağlıklı telemetridir; hata veya doğrulanmamış destek sınıfı değildir.

Kanonik destek matrisi, `src/core/providers/catalog.ts` içindeki 17 adaptör için aşağıdaki sınıflandırmadır. `live_verified` gerçek sağlayıcı telemetrisi, `connection_verified` yalnızca başarılı gerçek bağlantı, `synthetic_only` ise gerçek sağlayıcı doğrulaması bulunmadığı anlamına gelir.

| Kanonik sağlayıcı kimliği | Destek düzeyi | Kimlik doğrulama modları | Kota türü |
| --- | --- | --- | --- |
| `openrouter` | `synthetic_only` | `oauth_loopback_paste`, `api_key` | `balance_usd` |
| `deepseek` | `synthetic_only` | `api_key` | `balance_usd` |
| `anthropic` | `synthetic_only` | `oauth_loopback_paste` | `window_percent` |
| `openai-codex` | `live_verified` | `oauth_device` | `window_percent` |
| `antigravity` | `synthetic_only` | `oauth_loopback_paste`, `oauth_callback` | `window_percent` |
| `github-copilot` | `live_verified` | `oauth_device` | `window_percent` |
| `cursor` | `live_verified` | `oauth_device`, `session_cookie` | `window_percent` |
| `xai-oauth` | `live_verified` | `oauth_device` | `window_percent` |
| `zai` | `synthetic_only` | `oauth_loopback_paste`, `api_key` | `window_percent` |
| `minimax-code` | `synthetic_only` | `api_key` | `window_percent` |
| `cline-pass` | `synthetic_only` | `api_key` | `window_percent` |
| `devin` | `synthetic_only` | `oauth_callback`, `session_cookie` | `token_credits` |
| `umans` | `synthetic_only` | `api_key` | `token_credits` |
| `google-gemini-cli` | `synthetic_only` | `oauth_loopback_paste` | `window_percent` |
| `kimi-code` | `connection_verified` | `oauth_device` | `window_percent` |
| `opencode-go` | `synthetic_only` | `api_key` | `window_percent` |
| `alibaba-token-plan` | `synthetic_only` | `api_key`, `session_cookie` | `window_percent` |

`window_percent` yüzde tabanlı kota penceresi; `balance_usd` dolar bakiyesi; `token_credits` token, kredi veya istek sayaçlarını ifade eder. Kimi'nin doğrulanmış nötr sonucu “Hesap bağlandı; sağlayıcı kota bildirmiyor”dur; boş/eksik kota yanıtı hesap üyeliği, planı veya bölgesi hakkında kanıt değildir. Devin `cog_` V3 PAT'lerini desteklemez ve hosted OAuth yönlendirmesi deneysel/doğrulanmamıştır. Antigravity, gömülü masaüstü OAuth istemcisinde loopback callback URL'sinin elle yapıştırılmasını; otomatik hosted callback'te ise operatörün kendi Google OAuth Web istemcisini ve tam HTTPS callback URI'sini gerektirir. Matris kimlik doğrulaması olmadan `GET /api/providers/catalog` ile sunulur ve sır/token içermez.

### Kiracı Sınırı ve Mülkiyet İzolasyonu (Tenant Boundary & Ownership Isolation)
Veritabanı satır düzeyinde uygulanan mülkiyet kuralı. Her kimlik bilgisi (`credential`) ve kullanım kaydı (`usage_snapshot`) bir `owner_id` yabancı anahtarına (foreign key) bağlanmak zorundadır. Kullanıcılar yalnızca kendi `ownerId` değerleriyle eşleşen kayıtları listeleyebilir, güncelleyebilir veya silebilir.

### Eski Kayıt Sahiplenme (Legacy Account Claiming)
Sistemin tek kullanıcılı self-hosted modundan çok kullanıcılı SaaS mimarisine geçişi sırasında mevcut olan sahipsiz (`owner_id IS NULL`) kimlik bilgilerinin ve geçmiş anlık görüntülerin veri kaybı olmadan korunması ve sisteme ilk kaydolan gerçek (non-system) kullanıcıya atomik bir işlemle atanması kuralıdır. Sonradan kaydolan kullanıcılar bu eski verileri asla göremez.


### Davetiye (Invitation)
Yalnızca yöneticiler (`admin`) tarafından üretilen, yeni bir kullanıcının sisteme kontrollü katılımını sağlayan tek kullanımlık yetkilendirme kaydı.
- **Davetiye Belirteci (Invitation Token & Token Hash):** İstemciye ve davet bağlantısına (`/invite/:token`) verilen 32 baytlık kriptografik rastgele ham dize (`crypto.getRandomValues`). Veritabanında güvenlik gereği ham token ASLA saklanmaz; yalnızca tek yönlü SHA-256 hash özeti (`token_hash`) saklanır.
- **Geçerlilik Süresi (TTL):** Üretildiği andan itibaren 24 saattir (86.400 saniye). Süresi dolmuş (`expired`), kullanılmış (`accepted`) veya iptal edilmiş (`revoked`) davetiyeler geçersizdir.
- **Zorunlu E-posta Bağlayıcılığı (Strict Email Binding):** Davetiye oluşturulurken yönetici tarafından geçerli bir hedef e-posta adresi (`email`) verilmesi zorunludur; useMeter bünyesinde anonim veya e-postasız serbest davetiye bulunmaz. Davetiye kabul edildiğinde yeni kullanıcı hesabı doğrudan bu kanonik e-posta adresi ile oluşturulur (`COLLATE NOCASE`).
- **Dış Kayıt Politikasını Aşma (Registration Bypass):** Sistem genelinde genel kayıtlar kapatılmış olsa dahi (`isRegistrationAllowed() === false`), geçerli bir davetiye belirteci taşıyan kullanıcılar sisteme başarıyla kaydolabilir.
- **Manuel Davet Teslimi (Manual Invitation Delivery):** Yönetici oluşturulan davet bağlantısını (`/invite/:token`) panodan kopyalar ve kullanıcıya harici güvenli kanallardan kendisi iletir. Parola Kurtarma Girişiminin posta teslimi ayrı bir iş akışıdır; davetiyenin otomatik gönderileceği anlamına gelmez.
### Sağlayıcı (Provider)
Yapay zeka modellerini veya API altyapısını sunan bağımsız servis kuruluşu (örn. `openai`, `anthropic`, `openrouter`, `deepseek`, `google`, `cursor`). Her sağlayıcının kendine özgü kimlik doğrulama, hız sınırı (rate limit) ve kota politikası vardır.

### Kimlik Bilgisi (Credential)
Bir sağlayıcıya erişmek ve veri sorgulamak için kullanılan yetkilendirme anahtarı veya oturum verisi. Her kimlik bilgisi bir `ownerId` sahibi taşır. Üç türü vardır:
- **API Anahtarı (API Key):** Statik token (örn. `sk-...`).
- **OAuth Belgesi (OAuth Token):** Belirli süre geçerli `access_token` ve onu yenileyen `refresh_token` çifti.
- **Oturum Çerezi (Session Cookie):** Web arayüzünden elde edilen geçici oturum anahtarı (örn. `WorkosCursorSessionToken`).
### Bakiye (Balance)
Ön ödemeli (prepaid) veya kredili hesaplarda harcanabilir net parasal tutar. Dolar (`USD`), Kredi (`Credits`) veya yerel para birimi cinsinden ifade edilir. Yalnızca bakiye usulü çalışan servislerde (örn. OpenRouter, DeepSeek) geçerlidir.

### Harcama / Tüketim (Spend / Cost)
Sonradan ödemeli (postpaid) veya faturalı hesaplarda belirli bir zaman aralığında (günlük, aylık, fatura dönemi) harcanmış kümülatif tutar. Kalan parayı değil, faturaya yansıyacak borcu ifade eder.

### Kota Penceresi (Quota Window)
Bir hız sınırının veya kullanım hakkının sıfırlandığı döngüsel zaman aralığı:
- **5 Saatlik Kayan Pencere (`5h`):** Son 5 saatteki kullanımı hesaplayan dinamik kayan pencere (örn. Claude Code, OpenAI Codex).
- **Haftalık Kayan Pencere (`7d`):** 7 günlük kümülatif model sınırı (örn. Claude Opus/Sonnet haftalık sınırı).
- **Aylık Fatura Penceresi (`monthly`):** Ayın 1'inde veya fatura kesim tarihinde sıfırlanan sabit pencere.
- **Dakikalık Hız Penceresi (`1m`):** RPM (dakikadaki istek) ve TPM (dakikadaki token) sınırları.

### Kullanım Limiti (Usage Limit)
Belirli bir hesap ve kota penceresi için anlık tüketim durumunu gösteren ölçüm kaydı:
- **Kullanım Oranı (`usedFraction`):** `0.0` (boş) ile `1.0` (tam dolu) arasındaki ondalık oran. `1.0` ve üzeri kota aşımını gösterir.
- **Sıfırlanma Zamanı (`resetsAt`):** Kotanın tamamen veya kademeli olarak yeniden açılacağı Unix zaman damgası (milisaniye).
- **Durum (`Status`):** `ok` (güvenli), `warning` (örneğin %90 ve üzeri doluluk), `exhausted` (tükenmiş / blokeli).

### Kullanım Raporu (Usage Report)
Bir hesabın belirli bir andaki tüm limitlerini, varsa bakiyesini, sağlık durumunu ve metaverilerini içeren normalize edilmiş durum özeti.

### Kullanım Raporu Sağlık Durumu (Usage Report Health)
Kullanım verisinin güncelliğini ve güvenilirliğini tanımlayan üç durumlu gösterge:
- **Sağlıklı (`healthy`):** Sağlayıcı API'si başarıyla sorgulandı (`source: "live"`), limitler ve bakiyeler günceldir (`stale: false`).
- **Bayat / Korumalı (`stale`):** Daha önce en az bir kez başarılı sorgulanmış bir hesabın güncel sorgusu ağ/sağlayıcı hatası (timeout, 5xx, DNS vb.) nedeniyle başarısız olduğunda devreye girer. Son başarılı limitler (`lastGood`) korunur, `stale: true` ve `source: "stale"` olarak işaretlenir; güncel hata mesajı ve son başarılı zaman damgası (`lastGoodFetchedAt`) raporda tutulur.
- **Hatalı (`error`):** Hesap henüz ilk kez sorgulanırken veya geçmişte hiç başarılı sorgusu bulunmazken hata aldığında oluşur (`source: "error"`, `stale: false`). Limitler boştur (`limits: []`) ve hata detayı gösterilir.

### Yıkıcı Olmayan Son Başarılı Durum Koruması (Non-destructive Last-Good Telemetry)
Geçici ağ kesintilerinde veya sağlayıcı çökmelerinde önceden bilinen kota limitlerinin sıfırlanmasını veya panodan kaybolmasını engelleyen dayanıklılık mekanizması. Sistem, kiracı izolasyonu (`ownerId` + `credentialId`) sınırları dahilinde son başarılı anlık görüntüyü korur; arayüzde kehribar (amber) renkli uyarı rozeti ve "Son başarılı güncelleme" zamanıyla birlikte limitleri göstermeye devam eder.

### Kullanım Geçmişi Saklama Süresi (Usage History Retention)
Kullanım anlık görüntülerinin geçmiş incelemeler için tutulduğu zaman aralığı. Sürenin dışındaki geçmiş kayıtlar temizlenebilir; her hesabın güncel anlık görüntüsü ve son başarılı anlık görüntüsü bu süreden bağımsız olarak korunur. Böylece geçmiş temizliği panodaki güncel durumu veya yıkıcı olmayan son başarılı veri korumasını ortadan kaldırmaz.

### Korunan Kullanım Anlık Görüntüsü (Protected Usage Snapshot)
Bir hesaba ait en güncel durumu veya son başarılı durumu temsil ettiği için geçmiş temizliğinden muaf olan kullanım kaydı. Aynı rapor zamanını paylaşan kayıtlar arasında son kaydedilen görüntü önceliklidir. Henüz başarılı yoklaması bulunmayan hesap için yalnız güncel görüntü korunur; gerçek kota tükenmesi başarılı telemetri sayılır.

### Sağlayıcı Kota Tükenmesi vs İletişim / Yoklama Hatası (Provider Exhaustion vs Polling Failure)
Sistem bu iki durumu kesin çizgilerle birbirinden ayırır:
1. **Sağlayıcı Kota Tükenmesi (Provider Quota Exhaustion):** Sağlayıcı API'si geçerli ve başarılı bir HTTP yanıtı (HTTP 200) dönmüş, ancak kullanıcının kotasının dolduğunu (`usedFraction >= 1.0` veya `status: "exhausted"`) bildirmiştir. Bu durum bir hata DEĞİLDİR; telemetri açısından **Sağlıklı (`healthy`)** ve canlı (`live`) bir veridir.
2. **Yoklama / Ağ Hatası (Polling / Transport Failure):** Sağlayıcı uç noktasına erişilememesi (DNS hatası, HTTP 500/502/503/504, bağlantı zaman aşımı, geçersiz yanıt formatı) durumudur. Sistem bunu telemetri arızası kabul eder; geçmiş veri varsa **Bayat (`stale`)**, yoksa **Hatalı (`error`)** durumuna geçer.

### Ham Veri Gizliliği (No Raw Payload Exposure)
Kullanım anlık görüntüleri ve API yanıtları, upstream sağlayıcıdan dönen ham istek/yanıt gövdelerini, hassas başlıkları, gizli anahtarları veya yetkilendirme belirteçlerini ASLA veritabanı anlık görüntülerinde veya istemci yanıtlarında açık olarak saklamaz veya yayınlamaz.

---

## 2. Takip ve Veri Toplama Mekanizmaları

### Aktif Yoklayıcı (Poller Daemon)
Arka planda belirli periyotlarla (örn. 5–15 dakikada bir) sağlayıcıların resmi veya dahili bakiye/kota uç noktalarını doğrudan çağıran zamanlanmış arka plan iş parçacığı.
- **Dahili Yetki (Internal Poller):** Arka plan yoklayıcısı tüm sağlayıcı hesaplarının kotasını güncel tutabilmek için açıkça tanımlanmış dahili bir metot (`listAllCredentialsInternal`) ile tüm kimlikleri okur.
- **Kullanıcı Tetiklemesi vs Daemon:** Kullanıcıların web panelinden veya API üzerinden başlattığı manuel yenileme istekleri (`POST /api/refresh`) zorunlu olarak yalnızca oturum açmış kullanıcının sahip olduğu (`ownerId`) kimlik bilgileriyle sınırlıdır.

### Pasif Geçit (Ingress Proxy)
Kullanıcının yerel istemcilerinden (IDE, CLI, botlar) çıkan LLM isteklerinin arasına giren ve upstream sağlayıcıdan dönen HTTP yanıt başlıklarındaki (`x-ratelimit-*`, `anthropic-ratelimit-unified-*`) hız ve kota verilerini sıfır ek maliyetle yakalayan vekil sunucu.

### Tek-Uçuş Kilidi (Single-Flight Lock)
Aynı hesap için aynı anda birden fazla eşzamanlı kota sorgusunun veya OAuth token yenileme isteğinin yapılmasını engelleyen, ilk isteğin sonucunu bekleyenleri birleştiren concurrency koruması.

### Rastgele Dağıtım (Jittered Interval)
Tüm hesapların aynı anda sorgulanarak sağlayıcı tarafından IP bazlı rate-limit (`HTTP 429`) engeline takılmasını önlemek amacıyla sorgu aralıklarına eklenen ±%25'lik rastgele zaman sapması.

---

## 3. Alarm ve Bildirim Kuralları

### Eşik Alarmı (Threshold Alert)
Bir kullanım limiti kritik eşiği aştığında (örn. 5 saatlik pencere `%85` dolduğunda) veya bakiye kritik tutarın altına indiğinde (örn. `$2.00` kaldığında) harici kanallara (Telegram, ntfy, Discord) iletilen bildirim.

### Sıfırlanma Bildirimi (Reset Notification)
Kotası tükenmiş bir hesabın sıfırlanma zamanı (`resetsAt`) dolup yeniden kullanılabilir hale geldiğinde kullanıcıya gönderilen "Kota Açıldı" bildirimi.

---

## 4. Güvenlik Çevresi ve Trafik Denetimi (Security Perimeter)

### Yanıt Güvenlik Başlıkları (Response Security Headers)
Tarayıcı tarafındaki saldırıları (Clickjacking, MIME-sniffing, XSS, bilgi sızıntısı) önlemek amacıyla tüm HTTP yanıtlarına global olarak enjekte edilen güvenlik başlıkları kümesi:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
- `Strict-Transport-Security (HSTS)`: Yalnızca güvenli HTTPS veya `secure=true` ortamlarında (`max-age=31536000; includeSubDomains`).

### İçerik Güvenlik Politikası (Content Security Policy - CSP)
Sunucu taraflı HTML (SSR), gömülü tema scriptleri, inline stiller ve Tailwind CDN ile tam uyumlu çalışan pragmatik CSP politikasıdır.
- **Kasıtlı Tercih:** Mevcut şablon motoru nonce üretmediğinden `script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com` ve `style-src 'self' 'unsafe-inline'` direktifleri kasıtlı olarak kullanılır; nonce seviyesinde katı CSP iddiasında bulunulmaz.
- **Kısıtlamalar:** `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`, `connect-src 'self'`.

### Kökenler Arası Kaynak Paylaşımı İzin Listesi (CORS Allowlist)
Ortam değişkenleri (`CORS_ALLOWED_ORIGINS` veya `USEMETER_ALLOWED_ORIGINS`) üzerinden virgülle ayrılmış güvenli origin listesi.
- **Varsayılan:** Boş bırakıldığında yalnızca aynı kökene (same-origin) izin verilir; harici kökenlere CORS başlığı basılmaz.
- **Kimlikli İstek Koruması (No Credentialed Wildcard):** `allowCredentials: true` (`auth_session` çerezleri) durumunda joker karakter `*` kesinlikle reddedilir (`false`).

### Vekil Sunucu Güveni (Proxy Trust)
İstemcinin gerçek IP adresinin tespitinde ters vekil sunucu (Nginx, Caddy, Cloudflare) başlıklarının (`X-Forwarded-For`, `X-Real-IP`) güvenilirliğini belirleyen ayar (`TRUST_PROXY=1` veya `true`).
- **Kapalı (Varsayılan):** İstemcinin ilettiği forwarding başlıkları IP sahteciliğine (spoofing) karşı yok sayılır; doğrudan soket uzak adresi kullanılır.
- **Açık:** `X-Forwarded-For` zincirindeki en soldaki (istemciye ait) geçerli IP adresi ayıklanır.

### Sınırlandırılmış İstek Sıklığı Sınırı (Bounded Rate Limiting)
Hizmet reddi (DoS) ve kaba kuvvet (brute-force) saldırılarını engellemek için kayan pencere (sliding window) esasıyla çalışan bellek içi hız sınırlayıcısı:
- **Kimlik Doğrulama / Kayıt:** `5 istek / dakika / IP`
- **Manuel Kota Yoklama:** `1 istek / 30 saniye / kullanıcı + kimlik bilgisi`
- **OAuth Cihaz Akışı Yoklama:** `30 istek / dakika / kullanıcı + akış`
- **Bellek Koruması:** `maxKeys: 10000` sınırı ve periyodik temizlik (sweep) ile bellek sızıntıları önlenir.
