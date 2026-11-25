# hrAI `@HukukSGK` — `v1.0.5.1` (Katı ITU-T X.690 DER SET/SET OF & Sıkı ASN.1 Karakter Dizisi Kanonikliği, L5/L6 Özerk Norm Katmanları, 5070 Sayılı Kanun NES & CAdES/XAdES ve `hrAI` Marka Geçişi)

`@HukukSGK`, **hrAI** (**www.insenai.com.tr**) platformunun (**`@hrAI`** koordinatörü altında görev yapan) **Türkiye İş Hukuku & Sosyal Güvenlik Mevzuatı** uzman yapay zekâ ajanıdır.
Bağımsız incelemeden geçerek teknik kabul alan **`v1.0.5`** (ve dondurulmuş `v1.0.2c.6`–`v1.0.4.5`) temelleri üzerine kurulu **`v1.0.5.1`** sürümü; onaylanmış mimariyi, **`engine/esign5070/xmldsig.py`** dosyasını (**`SHA-256: b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85`** — bayt düzeyinde birebir `byte-identical`), L1–L4 `74/74` resmî çekirdeğini, L5/L6 özerk norm mimarisini ve tüm OpenSSL 3 kriptografik/CA zinciri doğrulamalarını eksiksiz koruyarak bağımsız denetim düzeltmelerini uygular:

1. **Düzeltme 1 — Katı ITU-T X.690 DER Kanonikliği ([`engine/esign5070/x509_metadata.py`](engine/esign5070/x509_metadata.py)):**
   - **Şema bağlamlı DER `SET` ve `SET OF` / `SET OF CHOICE` X.690 kanonik sıralaması & RFC 5280 `GeneralName` doğrulaması:** Şeması bilinen `SET` yapılarında (`ORAddress.PersonalName` dâhil) X.690 §11.5 / X.680 §8.6 kanonik `(sınıf, etiket numarası)` artan sırası (yinelenen etiket yasağıyla), şeması bilinen `SET OF` / `SET OF CHOICE` yapılarında (`Name` RDN, `SubjectAltName`/`IssuerAltName` `directoryName`, `ORAddress.ExtensionAttributes`, `SubjectDirectoryAttributes` `2.5.29.9`) X.690 §11.6 tam DER TLV artan oktet sırası fail-closed doğrulanır; şeması bilinmeyen özel uzantılarda etiket tekrarından tahmine gidilmez, hem §11.5 hem §11.6 kurallarını ihlal eden `0x31` kapsayıcıları reddedilir. `SubjectAltName`/`IssuerAltName` içindeki tüm 9 `GeneralName` alternatifinin P/C-bit kuralları (`0x80`/`0x83`/`0x84`/`0x85` ve `0xA1`/`0xA2`/`0xA6`/`0xA7`/`0xA8` fail-closed ret) ve `otherName` (`0xA0`), `x400Address` (`0xA3`), `directoryName` (`0xA4`), `ediPartyName` (`0xA5`) ASN.1 şemaları eksiksiz doğrulanır.
   - **Tür bazlı sıkı ASN.1 karakter dizisi çözümlemesi (kayıplı fallback ve `latin-1` yok):** `UTF8String` (`0x0C`), `PrintableString` (`0x13`, X.680 Tablo 10), `NumericString` (`0x12`), `IA5String` (`0x16`), `VisibleString` (`0x1A`), `BMPString` (`0x1E`, 2-bayt UCS-2 BMP, UTF-16 surrogate yasağı) ve `UniversalString` (`0x1C`, 4-bayt UTF-32-BE) katı kurallarla çözümlenir; eski T.61/Videotex/ISO-2022 etiketleri (`TeletexString`/`T61String` `0x14`, `VideotexString` `0x15`, `GraphicString` `0x19`, `GeneralString` `0x1B`) ile geçersiz bayt, yapısal ilkel tür (`X.690 §10.2`), NUL (`0x00`) veya bilinmeyen etiketler `DerParseError` ile fail-closed reddedilir ve kısmi metadata üretilmez.
   - **W3C C14N / XMLDSig ve OpenSSL 3 dokunulmazlığı:** [`engine/esign5070/xmldsig.py`](engine/esign5070/xmldsig.py) dosyası `v1.0.4.4`/`v1.0.4.5`/`v1.0.5` ile **%100 bayt düzeyinde özdeştir** (`b16207b5fb71d7c0d0372838411c7795459ac460c2ff232766ae230b9cbacf85`); tüm OpenSSL 3 imza/CA/OCSP/CRL/TSA doğrulamaları korunmuştur.
2. **Düzeltme 2 — Geriye Uyumlu `hrAI` Marka Geçişi:**
   - **Ürün:** `hrAI` | **Koordinatör:** `@hrAI` | **Uzman:** `@HukukSGK` | **Web:** `www.insenai.com.tr` (`https://www.insenai.com.tr`)
   - **Paket ve Kök Dizin:** `hrai_hukuk_sgk_v1.0.5.1.zip` (`hrai_hukuk_sgk/`) | **HTTP `User-Agent`:** `hrAI-HukukSGK/1.0.5.1 (SourceAcquisition)`
   - Yeni `v1.0.5.1` servis, şema ve governance kimlikleri (`HRAI_CADES_XADES_5070_VERIFIER_V1051`, `HRAI_SSCD_CONTROL_EVIDENCE_VERIFIER_V1051`, `HRAI-L5-*`, `HRAI-L6-*`, `HRAI-AUD-*`, `HRAI-L5-L6-AUTONOMOUS-NORMS-AUDIT-LOG`, `CHK-RELEASE-1.0.5.1-20261124`) `hrAI` kimliğiyle üretilirken tarihsel `CALISORA-*` kayıtları (`CALISORA-HUKUK-01`, `CALISORA-LEDGER-SEALER-01`, `CALISORA-HOLIDAY-CALENDAR-ATTESTATION-LEDGER`, `CALISORA_*` ortam değişkenleri), geçmiş denetim kimlikleri (`AUD-20261120-*`) ve sabit test kimlikleri geriye uyumluluk için korunur.
3. **L5 Kurumsal İK Prosedürleri & L6 Özerk Normlar Mimarisi ([`engine/autonomous_norms.py`](engine/autonomous_norms.py)) — Değiştirilmeden Korundu:**
   - Resmî L1–L4 mevzuat çekirdeğinden (`74/74` dokunulmadı) kesin ayrıştırılmış **5 L5 Kurumsal İK Prosedürü** (`rag_kb/05_ik_prosedurleri/`, `10` kural) ve **4 ayrı L6 Özerk Norm Modülü** (`rag_kb/06_tis_sozlesme_ve_isyeri_uygulamalari/`, `9` kural).
   - **Tekil `priority: 8` yasağı**, zorunlu 7 kural alanı, `REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION` kabul edilmemiş şablon güvencesi ve bağımsız [`config/autonomous_norms_audit_log.json`](config/autonomous_norms_audit_log.json) defteri korunmuştur.
4. **Regresyon Korunumu ve Fail-Closed Üretim / 5070 / KVKK Kapıları:**
   - Mevcut `230` testin tamamı korunmuş, üzerine kapsamlı `v1.0.5.1` DER SET/SET OF, sıkı ASN.1 karakter dizisi, pozitif sınır sertifikaları ve `hrAI` marka geçişi test paketi ([`tests/test_v1051_der_set_strings_and_hrai.py`](tests/test_v1051_der_set_strings_and_hrai.py)) eklenmiştir.
   - Canlı dış servisler, KVKK m.9 değerlendirmesi ve harici hukuk müşaviri imzası doğrulanmadan **`production_use_authorized: false`**, **`qualified_e_signature_5070_production_ready: false`**, **`qualified_e_signature_5070_equivalent: false`** ve **`NOT_CONFIGURED`** kilitleri kesinlikle kapalı kalır.

Ayrıntılı mimari dokümanlar:
- [`docs/v1.0.5.1_hrai_der_canonicality_and_brand_transition.md`](docs/v1.0.5.1_hrai_der_canonicality_and_brand_transition.md)
- [`docs/v1.0.5_kadroai_der_and_l5_l6_architecture.md`](docs/v1.0.5_kadroai_der_and_l5_l6_architecture.md)
- [`docs/v1.0.4_law5070_nes_cades_xades_architecture.md`](docs/v1.0.4_law5070_nes_cades_xades_architecture.md)
- [`docs/v1.0.3_gcp_production_trust_root_architecture.md`](docs/v1.0.3_gcp_production_trust_root_architecture.md)

---

## L1–L4 Resmî Çekirdek (`74/74`) ve Ayrık L5/L6 Özerk Norm Envanteri

| Katman | Toplam Kayıt | Tam Doğrulanmış / Durum | İnceleme / Kabul Bekleyen | Mülga |
|---|---:|---:|---:|---:|
| **Resmî Mevzuat Kaynakları** (`config/legal_sources_registry.json`) | **30** | **28** (`VERIFIED`) | **1** (`GIB-TEBLIG-332-20251231`) | **1** (`RG-9368-20241228`) |
| **L4 — Yargıtay İçtihatları** (`config/yargitay_precedents.json`) | **5** | **4** (`VERIFIED`) | **1** (`YIBBGK-2021-8-2026-1`) | **0** |
| **L1 — Temel Kanun Bilgi Kartları** (`rag_kb/01_kanunlar/` — 9 dosya) | **25** | **25** (`VERIFIED`) | **0** | **0** |
| **L2 — Yönetmelik Bilgi Kartları** (`rag_kb/02_yonetmelikler/` — 6 dosya) | **7** | **7** (`VERIFIED`) | **0** | **0** |
| **L3 — Tebliğ, CK & SGK Kartları** (`rag_kb/03_teblig_ve_genelgeler/` — 7 dosya) | **7** | **6** (`VERIFIED`) | **1** (`CARD-GIB-332-2026-TARIFE`) | **0** |
| **Resmî L1–L4 Denetim Defteri Toplamı** (`config/verification_audit_log.json`) | **74** | **70** | **3** | **1** |
| **L5 — Kurumsal İK Prosedürleri** (`rag_kb/05_ik_prosedurleri/` — 5 dosya) | **5 modül / 10 kural** | **0** (bağlayıcı kabul yok) | **5 modül** (`REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION`) | **0** |
| **L6 — Özerk Normlar** (`rag_kb/06_tis_sozlesme_ve_isyeri_uygulamalari/` — 4 dosya) | **4 modül / 9 kural** | **0** (bağlayıcı kabul yok) | **4 modül** (`REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION`) | **0** |
| **Bağımsız L5/L6 Denetim Defteri** (`config/autonomous_norms_audit_log.json`) | **9 modül / 19 kural** | **0** (kurum kabulü bekliyor) | **9 modül** | **0** |

- **JSON Schema Draft 2020-12:** **`13`** şema (`11` L1–L4/Güven Kökü/5070 şeması + `2` L5/L6 özerk norm şeması).
- **Yapılandırma Dosyaları (`config/`):** Toplam **`9`** JSON dosyası (`6` adedi özel Draft 2020-12 şemayla doğrulanan kayıt/yapılandırma dosyası + `3` adedi motor ve denetim doğrulayıcılarıyla doğrulanan `knowledge_taxonomy.json`, `verification_audit_log.json` ve `autonomous_norms_audit_log.json`).
- **Arşivli Dinî Bayram Takvimi & Hash Zinciri:** `TR-UBGT-RELIGIOUS-HOLIDAY-CALENDAR-2024-2027` (`v1.0.5.1`, sürüm checkpoint'i `CHK-RELEASE-1.0.5.1-20261124`).

---

## Bağımsız Test, Canlı Prob ve Doğrulama Komutları

```bash
# 1. Tam tek süreçli regresyon paketi (mevcut 230 test + 14 yeni v1.0.5.1 DER/hrAI/çapraz-doğrulama testi = 244 test)
python3 -m unittest discover -s tests -v

# 2. İsteğe bağlı sabit sürümlü çapraz-doğrulama bağımlılıkları (hrAI çalışma zamanı yalnızca stdlib kullanır)
pip install -r tests/requirements-crossval.txt

# 3. Tek komutluk bağımsız X.509/ASN.1 çapraz doğrulama aracı (strict: 4 parser + eşik; offline: yalnızca hrAI)
python3 -m tests.cross_validate_x509 --mode strict
python3 -m tests.cross_validate_x509 --mode offline

# 4. Gerçek canlı dış servis yapılandırma probu (5 durumlu dürüst 5070 + GCP/TSA/WORM + KVKK probu)
python3 -W error -m engine.trust_root.integration_probe
```
