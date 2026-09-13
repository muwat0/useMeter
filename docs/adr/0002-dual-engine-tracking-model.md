# ADR-0002: Çift Hatlı (Hibrit) Kota ve Bakiye Takip Motoru

- **Durum:** Kabul Edildi
- **Tarih:** 2026-09-13
- **Karar Vericiler:** Murat

---

## 1. Bağlam ve Problem Tanımı
Yapay zeka servislerinin kota ve bakiye verilerini toplamak için iki farklı yöntem bulunmaktadır:
1. **Aktif Sorgulama (Active Polling):** Sunucunun periyodik olarak sağlayıcının bakiye/kota uç noktalarına istek atması.
2. **Pasif Başlık Yakalama (Passive Header Interception):** Kullanıcının normal model çağrıları (inference) sırasında sağlayıcıdan dönen HTTP yanıt başlıklarını (response headers) dinlemesi.

Her iki yöntemin de tek başına kullanıldığında kritik eksiklikleri vardır:
- **Salt Aktif Polling:** Sık çalıştırılırsa sağlayıcıların kullanım uç noktalarındaki IP hız sınırına (`HTTP 429`) takılır; seyrek çalıştırılırsa kullanıcının yoğun kodlama anında kotayı aniden tüketmesini 5-15 dakika boyunca fark edemez (gecikmeli alarm).
- **Salt Pasif Yakalama:** Kullanıcı model çağrısı yapmadığı sürece güncellenmez; 5 saatlik kayan pencerenin ne zaman sıfırlandığı veya hesapta kalan net dolar bakiyesi bilinemez.

---

## 2. Karar

Sistemde **Çift Hatlı (Hibrit) Takip Motoru** uygulanacaktır:

### Hat A: Aktif Yoklayıcı (Active Poller)
- **Görev:** Net nakit bakiyelerini, hesap plan tiplerini ve durağan kota durumlarını çekmek.
- **Çalışma Aralığı:** 5–15 dakika arasında ayarlanabilir temel periyot.
- **Kritik Korumalar:**
  1. **Rastgele Dağıtım (Jitter):** Hesapların sorgulama aralıklarına **±%25 rastgele sapma** eklenir. Birden fazla hesabın aynı milisaniyede aynı sağlayıcıya hücum etmesi engellenir.
  2. **Tek-Uçuş Kilidi (Single-Flight Promise Coalescing):** Bir hesap için halihazırda yürüyen bir sorgu varken gelen yeni talepler bekletilir; mükerrer ağ çağrısı yapılmaz.
  3. **Hata Sonrası Geri Çekilme (Backoff):** Bir endpoint 429 veya 500 dönerse, o hesap için sorgulama aralığı geçici olarak uzatılır ve son başarılı veri (stale cache) gösterilmeye devam eder.

### Hat B: Pasif Geçit (Ingress Proxy Middleware)
- **Görev:** Model çağrılarından anlık kota tüketimini sıfır ek ağ maliyetiyle yakalamak.
- **Çalışma Şekli:** Sistem, yerel ağda OpenAI uyumlu bir ters vekil sunucu (reverse proxy) açar (`http://localhost:port/v1/chat/completions`). Kullanıcının IDE'si (Cursor, Zed), CLI araçları (OMP) veya botları (n8n, Ayzek) isteklerini bu geçit üzerinden yönlendirir.
- **Yakalanan Başlıklar:**
  - `anthropic-ratelimit-unified-5h-utilization`, `anthropic-ratelimit-unified-5h-reset`
  - `x-codex-primary-used-percent`, `x-codex-primary-reset-after-seconds`
  - `x-ratelimit-remaining-tokens`, `x-ratelimit-remaining-requests`
- **Tetikleme Mantığı:** Yanıt başlığında kota doluluğu `%100` (veya `%90+`) görüldüğü anda, aktif cron döngüsü beklenmeden anında yerel durum güncellenir ve alarm motoru tetiklenir.

---

## 3. Sonuçlar ve Takaslar

### Kazanımlar (Pros)
- **Anında Müdahale:** Kullanıcı kotayı tükettiği saniyede sistem haberdar olur; 5 dakikalık cron gecikmesi yaşanmaz.
- **Durağan Durum Doğruluğu:** İstek atılmayan saatlerde de 5 saatlik kayan pencerelerin açılış zamanı (`resetsAt`) tam doğrulukla geri sayar.
- **Sıfır Ek Maliyet:** Pasif hat için hiçbir ek API veya token harcaması yapılmaz; mevcut trafiğin üstbilgisi okunur.
- **İsteğe Bağlılık (Modülerlik):** Pasif geçit zorunlu değildir; vekil sunucuyu kullanmak istemeyen kullanıcılar sadece Aktif Poller ile de temel bakiye/kota takibini yürütebilir.

### Ödünler / Yükler (Cons)
- Mimariye proxy middleware katmanı eklenmesini gerektirir.
- İstemcilerin (IDE, CLI) base URL ayarlarının yerel vekil sunucuya yönlendirilmesi gerekir (pasif hattan tam verim alabilmek için).
