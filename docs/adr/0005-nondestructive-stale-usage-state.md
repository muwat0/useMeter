# ADR-0005: Yıkıcı Olmayan Bayat ve Bozulmuş Kullanım Durumu Yönetimi (Non-Destructive Stale and Degraded Usage State)

- **Durum:** Kabul Edildi
- **Tarih:** 2026-09-15
- **Karar Vericiler:** Murat
- **İlgili Belgeler:** [CONTEXT.md](../../CONTEXT.md), [docs/SPEC.md](../SPEC.md), [ADR-0001](0001-self-hosted-bff-architecture.md), [ADR-0002](0002-dual-engine-tracking-model.md), [ADR-0003](0003-multi-tenant-session-authentication.md), [ADR-0004](0004-security-perimeter-and-invitation-onboarding.md)

---

## 1. Bağlam ve Problem Tanımı

useMeter; geliştiricilerin ve ekiplerin birden fazla yapay zekâ sağlayıcısındaki (Anthropic, OpenAI, Google Cloud, DeepSeek, Cursor vb.) kota ve bakiye durumlarını gerçek zamanlı ve periyodik olarak izleyen bir sistemdir.

Önceki mimaride, periyodik veya manuel bir yoklama (`fetchUsage`) ağ kesintisi, sağlayıcı API zaman aşımı, HTTP 5xx hatası veya rate limit (`HTTP 429`) nedeniyle başarısız olduğunda sistem **yıkıcı (destructive)** bir hata raporu üretiyordu:
1. **Veri Kaybı ve Kör Nokta:** Mevcut kota limitleri (`limits: []`) tamamen siliniyor veya sıfırlanıyordu. Kullanıcı, sağlayıcının geçici bir 30 saniyelik ağ kesintisi sırasında daha önceden bilinen kotalarını (%75 doluluk, kalan bakiye vb.) göremiyor, panoda boş/hatalı kartlarla karşılaşıyordu.
2. **Kavram Karmaşası (Kota Tükenmesi vs İletişim Hatası):** Sağlayıcının resmi olarak "kotan bitti" (%100 exhaustion) yanıtı dönmesi ile sağlayıcı sunucusuna erişilememesi (DNS/timeout/502) aynı kırmızı hata kartında harmanlanıyor; telemetri sağlığı ile gerçek kullanım tükenmesi ayırt edilemiyordu.
3. **Kullanıcı Güvensizliği:** Geçici bir ağ dalgalanmasında arayüzün aniden kırmızıya dönmesi ve verilerin yok olması, sistemin sürekli çöktüğü algısını yaratıyordu.

Bu durum, son başarılı telemetrinin korunmasını ve arayüzde açıkça "bayat/önbellekteki veri" olarak etiketlenmesini sağlayan sağlam bir durum makinesi gerektirmiştir.

---

## 2. Değerlendirilen Alternatifler

### Alternatif A: Hatada Salt Boş Rapor Döndürmek (Önceki Yıkıcı Yaklaşım)
- **Gerekçe:** Hata anında en yalın davranış; son veri güvenilmez sayılarak panoda hiçbir limit gösterilmez.
- **Red Nedenleri:**
  - Sağlayıcıların geçici 500/503 veya ağ zaman aşımları yaygındır. Her geçici hatada kota çubuklarının kaybolması kullanıcı deneyimini bozar.
  - Saatlik/günlük kota pencerelerinin sıfırlanma sayaçları (`resetsAt`) panodan kaybolur; kullanıcı ne zaman tekrar kota açılacağını göremez.

### Alternatif B: Hatayı Sessizce Yutmak ve Hiç Rapor Üretmemek
- **Gerekçe:** Yoklama başarısız olursa son geçerli durum veritabanında olduğu gibi kalır, yeni anlık görüntü yazılmaz.
- **Red Nedenleri:**
  - Kullanıcı sağlayıcıda bir problem olduğunu (örneğin API anahtarının iptal edildiğini veya sağlayıcının çöktüğünü) fark edemez.
  - Verinin ne kadar süredir güncellenemediği bilinemez; sistem "yalancı yeşil" (false healthy) durumuna düşer.

### Alternatif C: Üç Durumlu Sağlık Modeli ve Yıkıcı Olmayan Son Başarılı Durum Koruması (Seçilen)
- **Gerekçe:** Başarısız yoklamada önceki başarılı limitler (`lastGood`) korunur, ancak rapor açıkça `health: "stale"`, `stale: true`, `source: "stale"` olarak işaretlenir. Hata mesajı ve son başarılı zaman damgası (`lastGoodFetchedAt`) saklanır.
- **Sonuç:** Kullanıcı hem kotalarını görmeye devam eder hem de verinin anlık değil önbellekten geldiğini ve arkasındaki geçici hatayı kehribar (amber) renkli bir uyarı ile anlar.

---

## 3. Alınan Kararlar

### 1. Ayrık Sağlık Taksonomisi (`UsageReportHealth` ve `UsageReportSource`)
`src/types.ts` sözleşmesine açık ve kesin durumlar eklenmiştir:
- `UsageReportHealth`: `"healthy" | "stale" | "error"`
- `UsageReportSource`: `"live" | "stale" | "error"`

```typescript
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
```

### 2. Dört Durumlu Durum Makinesi (State Machine Transitions)
Yoklayıcı katmanı (`PollerEngine`), her kimlik bilgisi için son başarılı raporu kiracı izolasyonu (`ownerId` + `credentialId`) çerçevesinde takip eder:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                             BAŞLANGIÇ                                  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                    İlk Yoklama      │
             ┌───────────────────────┴───────────────────────┐
             │ Başarılı                                      │ Başarısız
             ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│        HEALTHY          │                     │          ERROR          │
│ source: "live"          │                     │ source: "error"         │
│ stale: false            │                     │ stale: false            │
│ limits: [güncel veriler]│                     │ limits: []              │
│ lastGoodFetchedAt: t1   │                     │ lastGoodFetchedAt: yok  │
│ error: undefined        │                     │ error: "hata detayı"    │
└────────────┬────────────┘                     └────────────┬────────────┘
             │                                               │
             │ Yoklama Hatası                                │ Başarılı Yoklama
             ▼                                               ▼
┌─────────────────────────┐                     ┌─────────────────────────┐
│         STALE           │ ◄── Yoklama Hatası  │        HEALTHY          │
│ source: "stale"         │ ─────────────────── │ (Tekrar sağlıklı döner) │
│ stale: true             │                     └─────────────────────────┘
│ limits: [t1 limitleri]  │                                  ▲
│ lastGoodFetchedAt: t1   │                                  │
│ error: "yeni hata"      │ ─────────────────────────────────┘
└─────────────────────────┘         Yeniden Başarılı Yoklama
```

1. **İlk Başarılı Yoklama (`healthy`):** Rapor `health: "healthy"`, `stale: false`, `source: "live"`, `lastGoodFetchedAt: fetchedAt` olarak üretilir ve son başarılı durum (`lastGood`) güncellenir.
2. **Sonraki Ağ / Sağlayıcı Hatası (`stale`):** Geçerli bir `lastGood` varsa, limitler silinmez (`limits = lastGood.limits`). Rapor `health: "stale"`, `stale: true`, `source: "stale"`, `lastGoodFetchedAt: lastGood.fetchedAt` olarak işaretlenir; aktif hata mesajı `error` alanına yazılır.
3. **İlk Seferde Hata (`error`):** Daha önce başarılı bir telemetri kaydedilmemişse, korunacak limit bulunmadığından rapor `health: "error"`, `stale: false`, `source: "error"`, `limits: []` olur.
4. **Hatanın Düzelmesi (Self-Healing):** Sonraki yoklama başarılı olduğunda sistem doğrudan `healthy` durumuna döner; `stale` bayrağı `false` olur ve `error` temizlenir.

### 3. Sağlayıcı Kota Tükenmesi ile İletişim Hatalarının Kesin Ayrımı
- **Kota Tükenmesi (Exhaustion):** Sağlayıcı API'si başarıyla yanıt vermiş (HTTP 200) ve kotanın dolduğunu (`usedFraction >= 1.0` veya `status: "exhausted"`) bildirmiştir. Bu bir yoklama hatası DEĞİLDİR; telemetri açısından **`health: "healthy"`** ve canlı veridir. Kart normal render edilir, kota çubuğu dolu görünür.
- **Yoklama Hatası (Transport / API Failure):** Ağ zaman aşımı, HTTP 500/502/503/504 veya geçersiz JSON yanıtları telemetri arızasıdır; `stale` veya `error` akışını tetikler.

### 4. Veritabanı ve Kiracı İzolasyonu (Storage Vault)
- `StorageVault` anlık görüntü kaydederken ve `getLatestUsage` çağrısında `health`, `stale`, `lastGoodFetchedAt`, `source` ve `error` alanlarını SQLite JSON/kolon düzeyinde korur.
- Son başarılı rapor çözümlemesi daima aynı `ownerId` ve `credentialId` ile sınırlıdır; farklı kullanıcıların veya hesapların verileri birbirine asla karışmaz.

### 5. Kullanıcı Arayüzü Sunumu (UI Contract)
- **Sağlıklı (`healthy`):** Normal kart görünümü. Canlı yeşil göstergeler.
- **Bayat / Korumalı (`stale`):**
  - Kartın üstünde kehribar (amber) renkli dikkat rozeti ve hata metni.
  - "Önbellekteki veri — Son başarılı: DD.MM.YYYY HH:mm" bilgilendirme şeridi.
  - Mevcut limitler, barlar ve sıfırlanma sayaçları (`resetsAt`) eksiksiz ve interaktif olarak gösterilmeye devam eder.
- **İlk Hata (`error`):** Kırmızı hata bandı, boş limit alanı ve sağlayıcıya bağlanma hata açıklaması.

### 6. Güvenlik Sınırı: Ham Yanıt İzolasyonu (No Raw Payload Exposure)
- Upstream sağlayıcıdan dönen ham hata yığınları (stack traces), yetkilendirme başlıkları veya ham HTTP yanıt gövdeleri anlık görüntülerde veya istemciye dönen raporlarda ASLA saklanmaz veya sızdırılmaz. Yalnızca sterilize edilmiş etki alanı hata mesajları taşınır.

---

## 4. Takaslar ve Sonuçlar

| Yaklaşım | Avantaj | Takas / Risk | Alınan Önlem |
|---|---|---|---|
| **Son Başarılıyı Koruma (`stale`)** | Ağ kesintilerinde kotaların ekrandan silinmesini engeller; reset sayaçları görünür kalır. | Kullanıcı ekrandaki kotayı anlık zannedip harcama yapabilir. | Kart üzerine belirgin kehribar (amber) uyarı ve "Son başarılı güncelleme" zaman damgası yerleştirilir. |
| **Ayrık Sağlık Sınıflandırması** | Gerçek kota tükenmesi ile altyapı arızaları birbirine karışmaz. | Tür sisteminde ve arayüzde ek alanlar (`health`, `source`, `stale`, `lastGoodFetchedAt`) yönetilir. | `src/types.ts` altında sıkı TypeScript tipleri ile standardize edilmiştir. |
| **Bellek-İçi + Veritabanı Fallback** | Yoklayıcı yeniden başlasa bile veritabanındaki son başarılı anlık görüntüden kurtarma yapılabilir. | Eski anlık görüntünün deserialization maliyeti. | Yalnızca hata durumunda ve tekil hesap bazında çalışır; ek yük ihmal edilebilirdir. |
| **Ham Veri Yalıtımı** | API anahtarı veya hassas sağlayıcı verisi sızıntısı riski sıfırlanır. | Detaylı ham sağlayıcı hata gövdesi frontend'de doğrudan görünmez. | Hatalar sunucu tarafında kategorize edilip yerelleştirilerek kullanıcı dostu mesajlara dönüştürülür. |

---

## 5. Doğrulama ve Kabul Kriterleri

1. **Birim ve Entegrasyon Testleri:** Test süitinde (`tests/poller.test.ts`, `tests/storage.test.ts`, `tests/server.test.ts`) non-destructive stale akışları, ilk hata durumları, self-healing dönüşümleri ve kiracı izolasyonu doğrulanmıştır.
2. **Arayüz Kontrolü:** SSR render ve istemci kart render katmanında amber rozet, son güncelleme tarihi ve korunan kota barları gözlemlenmiştir.
3. **Dokümantasyon Uyumu:** `CONTEXT.md`, `docs/SPEC.md` ve `AGENTS.md` bu karara tam uyumlu olarak güncellenmiştir.
