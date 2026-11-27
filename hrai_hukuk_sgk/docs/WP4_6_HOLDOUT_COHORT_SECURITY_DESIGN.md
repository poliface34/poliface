# WP-4.6 — Yeni Bağımsız HOLDOUT Kohortu İçin Güvenlik ve Operasyon Tasarımı

**Durum:** Tasarım `COMPLETED`; erişim denetimi kodu (`holdout_governance.py`) hazır ve testli. Kohort hazırlığı ve emanetçi kaydı `REQUIRES_SEPARATE_APPROVAL`. Bu çalışmada yeni HOLDOUT verisi **oluşturulmadı** ve depoya eklenmedi.
**Kural:** Yeni kohort hazırlanmadan kör doğrulama `PASS` sonucu üretilemez.

## 1. Roller ve Görev Ayrılığı

| Rol | Sorumluluk | Erişim |
|---|---|---|
| Kohort hazırlayıcı (bağımsız hukukçu ekibi) | Vakaları ve cevap anahtarlarını yazar | Kohort içeriği; geliştirme deposuna yazma yetkisi **yok** |
| Emanetçi (custodian) | Kasayı saklar, erişim isteklerini imzalar | Kasa anahtarı ve imza anahtarı; motor koduna katkı **yok** |
| Denetçi operatör | Kör koşuyu yürütür | Tek seferlik grant; HOLDOUT içeriğini görmez (maskeli rapor) |
| Geliştirme ekibi ve geliştirme ajanları | Motoru geliştirir | Kohort içeriğine, cevap anahtarına ve maskesiz sonuçlara erişim **yok** |
| Depo sahibi | Kasa ve emanetçi kaydını onaylar | Kayıt defteri değişikliği onayı |

Bir kişi aynı kohort için hem hazırlayıcı/emanetçi hem geliştirici olamaz. Emanetçi ile cevap anahtarı onaycısı da aynı kişi olamaz.

## 2. Hazırlama

1. Vakalar mevcut 30 vakalık setten ve DEV/VAL'den bağımsız yazılır. Sızıntı kontrolü (O-01 4-gram Jaccard ≤ 0.55, küme ayrımı) **emanetçi ortamında** çalıştırılır. Geliştiricilere yalnız "geçti/kaldı" bilgisi döner.
2. Dağılım hedefi ve kategori kapsamı önceden yazılı olarak sabitlenir; sonradan değiştirilmez.
3. Cevap anahtarları bağımsız hukukçu onay sürecinden geçer (bkz. imza paketi tasarımı).

## 3. Saklama

- Kohort dosyası depo **dışında** tutulur: erişim kontrollü ayrı depo veya şifreli arşiv (`age`/`gpg`; anahtar KMS/HSM'de). Geliştirme deposunda yalnız özetler bulunur.
- Saklama yeri veri yerleşimi açısından KVKK değerlendirmesine tabidir (`kvkk_data_residency_approved = false` iken kişisel veri içeren vaka kullanılmaz; vakalar anonim/sentetik kişi verisiyle yazılır).

## 4. Mühürleme

1. Emanetçi `file_sha256` (ham bayt) ve `case_set_sha256` (`compute_holdout_case_set_sha256`: vaka kimliğine göre sıralı kanonik özet) değerlerini hesaplar.
2. Manifest: `vault_id`, `dataset_version`, `case_count`, iki özet, hazırlayıcılar (takma adlı), tarih. Manifest emanetçi anahtarıyla imzalanır.
3. Kayıt defterine (`holdout_vault_registry.json`) yeni kasa `SEALED_AVAILABLE`, `max_authorized_runs = 1` ile **depo sahibi onaylı** bir commit ile eklenir. Emanetçi gerçek kimlik doğrulamasından sonra açık anahtarıyla eklenir. Test/sentetik anahtar eklenemez.

## 5. Yetkili Tek Seferlik Erişim

1. Denetçi, `FINAL_BLIND_VERIFICATION` amaçlı bir erişim isteği hazırlar; emanetçi isteği Ed25519 veya RSA-PSS-SHA256 ile imzalar (≤ 24 saat geçerli, tek nonce).
2. `HoldoutAccessGate.authorize` CI dışında, depo dışındaki kalıcı ledger ile çalışır. Sınır ve tekrar kontrolü atomiktir; grant kaydı imzayı taşır.
3. `VAULT_READ` → `RUN_STARTED` (yalnız `blind_holdout_mode=True` ve kayıtlı vaka kümesi) → `RUN_COMPLETED`. Her adımda ledger zinciri, grant imzaları, kasa durumu, sürüm, emanetçi yetkisi ve iptal durumu yeniden doğrulanır.
4. Gerekirse `revoke_grant` ile grant geri alınır. Erişim hakkı iade edilmez.

## 6. Kontrollü Değerlendirme Ortamı

- Geçici, ağ çıkışı kısıtlı, CI dışı bir çalışma ortamı. Motor commit'i ve bağımlılıklar koşu manifestinde sabitlenir.
- Kohort dosyası yalnız koşu süresince ortama çözülür, sonra silinir. Ortamın günlükleri maskesiz içerik yazmaz.
- Koşudan sonra ledger başı (`seq`, `record_hash`) harici olarak sabitlenir (imzalı checkpoint / WORM depo).

## 7. Maskeli Sonuç Raporu

Yayımlanan rapor yalnız toplu değerleri içerir: vaka sayısı, ortalama, FATAL/MAJOR sayısı, PASS oranı, kategori bazlı skor ve veto (n ≥ 5 olan kategoriler), retrieval metrikleri, koşu manifesti özeti ve ledger başı. Vaka kimlikleri `HOLDOUT-MASKED-nnn` biçiminde maskelenir. Vaka metni, cevap ve vaka bazlı kök neden paylaşılmaz.

## 8. Tüketim

Koşu tamamlanınca kasa `CONSUMED_BLINDNESS_COMPROMISED` (veya sonraki sürümde `CONSUMED_AFTER_BLIND_RUN`) durumuna alınır, `max_authorized_runs = 0` olur. Sonuçlara bakarak motor değiştirilirse bir sonraki kör doğrulama için yeni kohort gerekir.

## 9. Kodla Karşılanan Kontroller (test kanıtı)

| Kontrol | Test |
|---|---|
| CI'da erişim yok | `test_holdout_governance_wp46_v106::test_04` |
| Ledger yok / bozuk / okunamaz | `::test_07`, `::test_08`, `test_holdout_ledger_v2_wp46_v106::test_02` |
| Eş zamanlı erişimde tek grant | `test_holdout_governance_wp46_v106::test_09` |
| İmza / zaman / tekrar | `::test_10`, `test_holdout_ledger_v2_wp46_v106::test_05`, `::test_06` |
| Sayaç ve statü tutarlılığı | `test_holdout_ledger_v2_wp46_v106::test_03`, `::test_04` |
| Sürüm ve dosya özeti | `test_holdout_ledger_v2_wp46_v106::test_08` |
| Grant ve emanetçi iptali | `test_holdout_ledger_v2_wp46_v106::test_10`, `::test_11` |
| Yalnız kör koşu, maskeli rapor | `test_holdout_governance_wp46_v106::test_11`, `::test_12` |
