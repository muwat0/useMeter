# ADR-0001: Self-Hosted Backend-for-Frontend (BFF) ve SQLite Mimari Tercihi

- **Durum:** Kabul Edildi
- **Tarih:** 2026-09-13
- **Karar Vericiler:** Murat

---

## 1. Bağlam ve Problem Tanımı
Kullanıcının farklı AI servislerindeki (OpenRouter, DeepSeek, OpenAI, Anthropic, Cursor, Google Antigravity vb.) kalan bakiye, kredi ve kota kullanımını tek bir ekranda toplayan bir web uygulaması tasarlanmaktadır.

Bu sistem tasarlanırken iki temel mimari ikilem mevcuttur:
1. **İstemci Mimarisi:** Sadece tarayıcıda çalışan statik bir web sayfası (Pure Frontend / SPA) mı, yoksa bir sunucu katmanı içeren Backend-for-Frontend (BFF) mi?
2. **Hizmet Modeli:** Kamuya açık çok kullanıcılı bir SaaS mi, yoksa kişisel/izole bir Self-Hosted uygulama mı?

---

## 2. Değerlendirilen Alternatifler ve Kısıtlar

### Alternatif A: Saf Frontend (Pure SPA / PWA)
- **Kısıt 1 (CORS Kesin Engeli):** OpenAI, Anthropic, Google Cloud, Cursor ve ChatGPT API uç noktaları tarayıcıdan gelen çapraz kaynak (`cross-origin`) isteklerine izin vermez (`Access-Control-Allow-Origin` başlığı dönmez). Tarayıcı istekleri ağ düzeyinde bloke eder.
- **Kısıt 2 (Güvenlik Açığı):** Kullanıcının hassas API anahtarları (`sk-admin-...`), OAuth `refresh_token`ları ve oturum çerezleri tarayıcının `localStorage` veya `IndexedDB` alanında saklanmak zorunda kalır. Bu durum XSS veya zararlı tarayıcı eklentileri karşısında kritik güvenlik zafiyeti yaratır.
- **Kısıt 3 (Arka Plan Sürekliliğinin Yokluğu):** Tarayıcı sekmesi kapatıldığında sorgulama durur. 5 saatlik kayan pencerelerin takibi, sıfırlanma sayaçları ve kota %90 olduğunda Telegram/ntfy alarmları çalışamaz.

### Alternatif B: Kamuya Açık Çok Kullanıcılı SaaS
- **Kısıt 1 (IP Tabanlı Blokaj):** Yüzlerce kullanıcının Claude ve ChatGPT `/usage` sorguları merkezi bir SaaS sunucusunun tek bir çıkış IP'sinden gittiğinde, sağlayıcıların Cloudflare WAF ve IP rate-limiter motorları (`HTTP 429`) tüm servisi kilitler.
- **Kısıt 2 (Hukuki ve Güvenlik Yükü):** Başka kullanıcıların hassas anahtarlarını barındırmak KVKK/GDPR ve veri ihlali riskleri doğurur.

---

## 3. Karar

1. **Self-Hosted Dağıtım:** Uygulama, kullanıcının kendi donanımında (yerel masaüstü, Linux VPS, GCP e2-micro veya Docker) çalışacak şekilde tasarlanacaktır. Her kullanıcı kendi ev/sunucu IP'sinden sorgu yapacağı için sağlayıcıların IP engellerine takılma riski sıfırlanır.
2. **Backend-for-Frontend (BFF) Katmanı:**
   - **Çalışma Zamanı (Runtime):** **Bun / Node.js (TypeScript)**.
   - **Web Çerçevesi:** **Hono**. Küçük boyutlu, web standartlarına tam uyumlu, sıfır dış bağımlılıklı, yüksek performanslı ve Server-Sent Events (SSE) / WebSocket desteği güçlüdür.
   - **Veri Tabanı ve Güvenlik:** **SQLite (WAL modunda)**. Harici bir veri tabanı sunucusu (PostgreSQL/MySQL) gerektirmez; tek bir dosya ile yedeklenir. Hassas kimlik bilgileri (API key, OAuth refresh token) veritabanında **AES-256-GCM** ile şifrelenerek saklanır.
3. **Kullanıcı Arayüzü (Frontend):**
   - **Teknoloji:** **Vite + React + Tailwind CSS**.
   - **İletişim:** Backend ile yerel REST ve SSE/WebSocket üzerinden haberleşir; tarayıcı asla doğrudan AI sağlayıcılarına istek atmaz.

---

## 4. Sonuçlar ve Takaslar

### Kazanımlar (Pros)
- **Sıfır CORS Sorunu:** Sunucu-sunucu (Server-to-Server) iletişimde CORS kısıtı yoktur.
- **Yüksek Güvenlik:** API anahtarları asla tarayıcıya iletilmez; sunucu tarafında şifreli kasada tutulur.
- **7/24 Kesintisiz Takip:** Tarayıcı kapalıyken bile arka plan daemon'ı kotaları izler, geçmiş trendleri kaydeder ve eşik aşımında bildirim (Telegram/ntfy) gönderir.
- **Düşük Kaynak Tüketimi:** Hono + SQLite kombinasyonu boşta < 30 MB RAM tüketir; kullanıcının mevcut ev/sunucu altyapısında ek maliyet oluşturmaz.

### Ödünler / Yükler (Cons)
- Kullanıcının uygulamayı Docker veya yerel servis olarak çalıştırmasını gerektirir (tek tıkla açılan statik HTML sayfası kadar zahmetsiz değildir).
