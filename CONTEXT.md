# CONTEXT.md — AI Kota, Bakiye ve Kullanım Takip Sistemi (Ubiquitous Language)

Bu belge, sistem genelinde kullanılan temel etki alanı (domain) kavramlarının ve iş kurallarının kanonik sözlüğüdür. Tüm modüller, dokümanlar, API uç noktaları ve veritabanı şemaları buradaki terminolojiye uymak zorundadır.

---

## 1. Temel Etki Alanı Varlıkları (Core Entities)

### Sağlayıcı (Provider)
Yapay zeka modellerini veya API altyapısını sunan bağımsız servis kuruluşu (örn. `openai`, `anthropic`, `openrouter`, `deepseek`, `google`, `cursor`). Her sağlayıcının kendine özgü kimlik doğrulama, hız sınırı (rate limit) ve kota politikası vardır.

### Kimlik Bilgisi (Credential)
Bir sağlayıcıya erişmek ve veri sorgulamak için kullanılan yetkilendirme anahtarı veya oturum verisi. Üç türü vardır:
- **API Anahtarı (API Key):** Statik token (örn. `sk-...`).
- **OAuth Belgesi (OAuth Token):** Belirli süre geçerli `access_token` ve onu yenileyen `refresh_token` çifti.
- **Oturum Çerezi (Session Cookie):** Web arayüzünden elde edilen geçici oturum anahtarı (örn. `WorkosCursorSessionToken`).

### Hesap (Account)
Bir sağlayıcı nezdinde kullanıcının sahip olduğu tekil abonelik veya faturalandırma birimi. Bir sağlayıcı altında birden fazla hesap bulunabilir (örn. birden fazla ChatGPT Plus hesabı veya farklı Google Cloud projeleri).

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
Bir hesabın belirli bir andaki tüm limitlerini, varsa bakiyesini ve metaverilerini içeren normalize edilmiş anlık durum özeti.

---

## 2. Takip ve Veri Toplama Mekanizmaları

### Aktif Yoklayıcı (Poller)
Arka planda belirli periyotlarla (örn. 5–15 dakikada bir) sağlayıcıların resmi veya dahili bakiye/kota uç noktalarını doğrudan çağıran zamanlanmış iş parçacığı (daemon).

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
