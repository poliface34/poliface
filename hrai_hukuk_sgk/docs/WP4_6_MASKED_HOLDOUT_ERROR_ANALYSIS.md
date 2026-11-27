# WP-4.6 — Mevcut HOLDOUT İçin Maskelenmiş ve Toplulaştırılmış Hata Analizi

**Durum:** `PARTIALLY_COMPLETED` — yalnız toplam düzeyde; kategori/kusur dağılımı `UNAVAILABLE`.
**Kasa:** `HOLDOUT-WP45-V1.2-30-SEALED-20261126` → `CONSUMED` / `CONTAMINATED` (`CONSUMED_BLINDNESS_COMPROMISED`).
**Kullanım sınırı:** Bu belge yalnız yeni `DEV/VALIDATION` vakalarının hazırlanmasına girdi olabilir. Bu bulgulara bakarak kod, prompt, retrieval, reranking, puanlama veya rubric değişikliği yapılmaz. HOLDOUT vaka kimliği, vaka metni, model cevabı ve vaka bazlı kök neden bu belgede yoktur.

## 1. Kaynaklar ve Yöntem

| Kaynak | Durum |
|---|---|
| PR #4 açıklaması (`d1dd8ef` dönemi) ve 27.11.2026 devir notu: HOLDOUT `91.39`, `0` FATAL, `4` MAJOR, `27/30` PASS; 100 vaka `97.04` / `97.17`, `Recall@5 = 0.7667`, `Recall@10 = 0.7867`, `MRR = 0.6209` | `UNVERIFIED_CLAIM` (koşu raporu ve kalıcı ledger yok) |
| `DEV + VALIDATION` (70 vaka) ölçümü: `99.47`, `Recall@5 = 0.9490`, `Recall@10 = 0.9796`, `MRR = 0.8335` | WP-4.6'da izole akışla yeniden üretildi |
| HOLDOUT koşusunun vaka düzeyi raporu (kategori, kusur kodu) | `UNAVAILABLE` |

Mevcut HOLDOUT **yeniden puanlanmadı** ve dosyası ayrıştırılmadı. Aşağıdaki türetilmiş değerler yalnız yukarıdaki toplam sayılardan aritmetik olarak çıkarılmıştır.

## 2. Toplam Bulgular

| Alan | Değer | Kaynak / Not |
|---|---|---|
| Vaka | 30 | Kayıt defteri `case_count` |
| `FATAL` | 0 | Bildirilen |
| `MAJOR` kusur | 4 | Bildirilen; hangi vakalarda/kategorilerde olduğu `UNAVAILABLE` |
| PASS altı vaka | 3 | Bildirilen (`27/30`); band dağılımı (`PARTIAL_REVIEW` / `FAIL_SCORE` / `FAIL_MAJOR`) `UNAVAILABLE` |
| Ortalama | 91.39 | Bildirilen |
| Risk sınıfı | Yüksek (MAJOR); kritik (FATAL) yok | K-02 tanımı: MAJOR vetosu eşikten bağımsız `FAIL_MAJOR` üretir |

## 3. Türetilmiş Genel Eğilim (yaklaşık)

Varsayım: 100 vakalık endeksler vaka başına eşit ağırlıklı ortalamadır, yani `100 × hepsi = 70 × DEV/VAL + 30 × HOLDOUT`. Genel ortalama için bu varsayım tutarlıdır: türetilen HOLDOUT ortalaması `91.37`, bildirilen `91.39` ile örtüşür. Retrieval metriklerinin uygulanabilir vaka kümesi farklıysa değerler kayabilir.

| Metrik | DEV+VAL | 100 vaka | Türetilen HOLDOUT (yaklaşık) | Fark |
|---|---:|---:|---:|---:|
| Genel skor | 99.47 | 97.04 | ≈ 91.4 | ≈ −8 |
| `Recall@5` | 0.9490 | 0.7667 | ≈ 0.34 | ≈ −0.61 |
| `Recall@10` | 0.9796 | 0.7867 | ≈ 0.34 | ≈ −0.64 |
| `MRR` | 0.8335 | 0.6209 | ≈ 0.13 | ≈ −0.71 |

**Eğilim:** En büyük genelleme açığı **retrieval** tarafındadır. DEV/VAL üzerinde kalibre edilen retrieval, görülmemiş vakalarda beklenen maddeleri ilk 5–10 sonuçta çoğunlukla bulamamıştır. Buna karşın 0 FATAL, zamansal ve atıf güvenlik kapılarının (yanlış/mülga kaynak blokajı) görülmemiş vakalarda da tuttuğunu gösterir. 100 vakalık boyut skorlarında da en düşük alan `RETRIEVAL_EFFECTIVENESS = 78.00` idi. Bu ikinci gözlem tutarlıdır, ancak boyut skorları HOLDOUT için ayrıştırılmadı.

**Yorum sınırı:** DEV/VAL ile HOLDOUT arasındaki fark, DEV/VAL'e aşırı uyumun (overfitting) güçlü bir işaretidir. Aynı zamanda HOLDOUT körlüğü bozulduğu için bu fark bile bağımsız genelleme ölçüsü sayılmaz.

## 4. Yeni DEV/VALIDATION Vakaları İçin Girdi (HOLDOUT'a bakmadan)

- Retrieval çeşitliliği: aynı hukuki sonuca farklı terminolojiyle (işveren/işçi dili, kısaltmalar, eski/yeni madde numaraları) ulaşan sorgular.
- Madde başına birden fazla paraphrase ve konu dışı ama sözcük olarak benzer çeldirici içtihatlar.
- Retrieval metriklerinin kategori bazında raporlanması (yeni DEV/VAL'de), böylece açık tek bir endekste gizlenmez.
- Kalibrasyonun DEV'de yapılıp yalnız VAL'de ölçülmesi; VAL'e bakarak ayar yapılmaması.

## 5. Kullanılmayan / Üretilmeyen Bilgiler

- HOLDOUT vaka kimlikleri, metinleri, model cevapları, vaka bazlı kök nedenler: kullanılmadı.
- MAJOR kusurların kategori ve `DefectCode` dağılımı: hiçbir erişilebilir kayıtta yok. Elde etmek için HOLDOUT'un yeniden puanlanması gerekir; bu yasak olduğundan üretilmedi.
