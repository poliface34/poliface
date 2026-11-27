# WP-4.6 — Onayçı Kayıtları İçin Tek Kaynak Mimari Tasarımı

**Durum:** Tasarım `COMPLETED`; uygulama ve geçiş `REQUIRES_SEPARATE_APPROVAL`.
**Sınır:** `config/authorized_approvers.json` WP-1 kapsamında korunur ve bu çalışmada değiştirilmedi. SHA-256 değeri `9bfd8ffb…539c` testle sabitlendi (`tests/test_holdout_ledger_v2_wp46_v106.py::test_15`). Hiçbir gerçek hukukçu kimliği, anahtarı veya onayı oluşturulmadı.

## 1. Mevcut Durum: Üç Ayrı Güven Kaynağı

| Kaynak | Konum | Kullanan | Biçim |
|---|---|---|---|
| A. `config/authorized_approvers.json` | Depo, WP-1 korumalı | `legal_reasoning.py`, `tools_router.py`, `knowledge_card_validator.py`, `trust_root/integration_probe.py` (takvim/hukuki onay ve denetim mühürleyici) | JSON, `approver_id` anahtarlı sözlük, şema `1.0.5.1` |
| B. `TrustedLegalApproverRegistry` | `engine/evaluation/legal_signoff.py` | Yalnız K-01 cevap anahtarı onay doğrulaması | Bellekte kurulan dataclass; **dosyadan yükleyici yok** |
| C. HOLDOUT emanetçi kaydı | `engine/evaluation/governance/holdout_vault_registry.json` | `HoldoutAccessGate` | JSON `custodians` listesi (şu an boş) |

## 2. A ile B Arasındaki Farklar

| Alan | A (`authorized_approvers.json`) | B (`TrustedLegalApproverRecord`) | Etki |
|---|---|---|---|
| Rol | `role` (`EXTERNAL_LEGAL_COUNSEL`, `AUDIT_LEDGER_CHECKPOINT_SIGNER`) | `approver_role` ∈ {`INDEPENDENT_LABOR_LAW_COUNSEL`, `SENIOR_SOCIAL_SECURITY_COUNSEL`, `EXTERNAL_LEGAL_COUNSEL`} | Mühürleyici rolü B'de geçersiz; alan adı farklı |
| Algoritma | `key_algorithm` | `algorithm` | Alan adı farklı |
| Baro sicili | **Yok** | `bar_association_ref` zorunlu (boşsa `MISSING_BAR_ASSOCIATION_REF`) | A'dan B'ye doğrudan eşleme yapılamaz |
| Kayıt durumu | `PENDING_PRODUCTION_KEY_ENROLLMENT` | `ENROLLED` olmalı | A'daki kayıtların hiçbiri B'de onay veremez (beklenen, doğru davranış) |
| Kapsam | `HOLIDAY_CALENDAR_LEGAL_APPROVAL:2024-2030`, `AUDIT_CHECKPOINT_SEAL` | Varsayılan `EVALUATION_ANSWER_KEY_APPROVAL`, `LEGAL_FATAL_OVERRIDE` | A'da değerlendirme onayı kapsamı yok |
| Açık anahtar | `null` (henüz kayıt yok) | PEM zorunlu, parmak izi eşleşmeli | — |
| İptal gerekçesi | `"NONE"` metni | `None` | Normalizasyon gerekir |
| Yalnız A'da | `display_name`, `key_trust_tier`, `key_management_mode`, `environment_restrictions`, `qualified_e_signature_5070_equivalent` | — | B'ye taşınmalı (ortam kısıtı ve 5070 iddiası doğrulamada kullanılmalı) |
| Kalıcılık | Dosya (WP-1 manifestiyle değil, politika ile korunuyor) | Yok | B için denetlenebilir kaynak yok |

## 3. Önerilen Mimari: Tek Kayıt Defteri, Kapsam Bazlı Yetki

**Tek otorite:** Tüm imzalayıcılar (hukukçu, mühürleyici servis, HOLDOUT emanetçisi) tek bir **güven defterinde** tutulur. Önerilen konum, WP-1 onayıyla şema `2.0`'a yükseltilmiş `config/authorized_approvers.json` dosyasıdır. B ve C bu dosyadan türetilen **salt-okunur görünümler** olur.

### 3.1. Veri Modeli (şema `2.0`, öneri)

```json
{
  "schema_version": "2.0",
  "registry_version": "<monoton artan>",
  "test_sandbox_keys_allowed_in_production": false,
  "signers": {
    "<signer_id>": {
      "signer_id": "...",
      "signer_kind": "LEGAL_COUNSEL | AUDIT_SEALER_SERVICE | HOLDOUT_CUSTODIAN",
      "roles": ["INDEPENDENT_LABOR_LAW_COUNSEL"],
      "status": "ACTIVE | SUSPENDED | REVOKED",
      "enrollment_status": "PENDING_IDENTITY_VERIFICATION | PENDING_PRODUCTION_KEY_ENROLLMENT | ENROLLED",
      "identity_verification": {
        "method": "BAR_REGISTRY_LOOKUP+DOCUMENT+VIDEO_CALL",
        "bar_association_ref": "<baro adı / sicil no — takma adlı referans>",
        "evidence_bundle_sha256": "<depo dışı kanıt paketinin özeti>",
        "verified_by": ["<doğrulayıcı-1>", "<doğrulayıcı-2>"],
        "verified_at_utc": "...",
        "next_reverification_due_utc": "..."
      },
      "independence_declaration_sha256": "<imzalı beyan özeti>",
      "keys": [
        {
          "key_id": "...", "key_version": "v1", "algorithm": "ED25519 | RSA-PSS-SHA256",
          "public_key_pem": "...", "public_key_fingerprint_sha256": "...",
          "key_management_mode": "EXTERNAL_KMS_HSM_REQUIRED",
          "valid_from_utc": "...", "valid_until_utc": "...",
          "status": "ACTIVE | RETIRED | REVOKED",
          "revoked_at_utc": null, "revocation_reason": null
        }
      ],
      "authorized_scopes": ["EVALUATION_ANSWER_KEY_APPROVAL", "LEGAL_FATAL_OVERRIDE"],
      "environment_restrictions": ["PRODUCTION", "STAGING"],
      "qualified_e_signature_5070_equivalent": false
    }
  }
}
```

- Anahtarlar **liste** olarak tutulur. Böylece rotasyon sonrası eski anahtarlar geçmiş imzaların doğrulanması için kalır; HOLDOUT ledger imza doğrulaması bunu zorunlu kılar.
- Kişisel veri en aza indirilir (KVKK): depoda yalnız takma adlı `signer_id`, baro referansı ve kanıt paketinin özeti bulunur. Kimlik belgeleri depo dışında, erişim kontrollü kanıt deposunda tutulur.

### 3.2. Doğrulama Kuralları (yükleyici)

- Şema kesin doğrulanır; bilinmeyen alan reddedilir.
- `ENROLLED` olmayan, açık anahtarı veya parmak izi tutarsız kayıt imza yetkisi alamaz.
- Kapsam kontrolü işlem bazlıdır: takvim onayı, cevap anahtarı onayı, FATAL override, denetim mühürü ve HOLDOUT emanetçiliği ayrı kapsamlardır. Aynı kişi HOLDOUT emanetçisi ve cevap anahtarı onaycısı **olamaz** (görev ayrılığı).
- `test_sandbox_keys_allowed_in_production = false` iken test anahtarı parmak izi listesiyle eşleşen kayıt yüklenemez.
- Defterin kendisi `AUDIT_CHECKPOINT_SEAL` kapsamlı mühürleyici anahtarla imzalanır (ayrık imza dosyası). İmza doğrulanamazsa defter yüklenmez (fail-closed).

## 4. Geçiş Planı

| Faz | İş | Dosya değişikliği | Onay |
|---|---|---|---|
| 0 | Bu tasarım ve fark analizi | Yok | Tamamlandı |
| 1 | `load_trusted_legal_approver_registry(path)`: A'yı (v1) okuyup B'ye eşleyen salt-okunur adaptör; mevcut kayıtların hepsi `APPROVER_NOT_ENROLLED` vermeli (eşdeğerlik testi) | Yalnız yeni kod + test | Gerekir (kapsam dışı kod) |
| 2 | Şema `2.0` dosyası; WP-1 manifestinin ve korumalı dosya sabitlemesinin güncellenmesi | `config/authorized_approvers.json` | **WP-1 değişikliği: ayrıca onay** |
| 3 | Tüketicilerin (takvim, router, kart doğrulayıcı, probe, K-01, HOLDOUT kapısı) tek yükleyiciye geçmesi | Kod | Gerekir |
| 4 | Bellekte elle `TrustedLegalApproverRegistry` kurulması yalnız testlerde kalır | Kod | Gerekir |

**Geriye dönük uyumluluk:** Yükleyici `schema_version` `1.0.5.1` ve `2.0` biçimlerini okur. v1 alanları (`role`, `key_algorithm`, tek anahtar) v2'ye deterministik olarak eşlenir. Eksik zorunlu alanlar (ör. `bar_association_ref`) kaydı `ENROLLED` dışı bırakır.

## 5. Kimlik ve Yetki Doğrulama Süreci

1. **Başvuru:** Hukukçu bağımsızlık ve çıkar çatışması beyanını imzalar (proje, işveren ilişkisi, ücret yapısı, son 3 yıl ilişkileri).
2. **Baro sicili:** İlgili baronun avukat listesi / TBB avukat bilgi sorgusu üzerinden sicil ve aktif üyelik doğrulanır. Sorgu ekran görüntüsü veya baro yazısı kanıt paketine eklenir.
3. **Kimlik eşleşmesi:** Kimlik belgesi ve canlı görüntülü görüşme ile kimlik ve sicil eşleştirilir. İki ayrı doğrulayıcı imzalar (dört göz).
4. **Uzmanlık:** İş ve sosyal güvenlik hukuku deneyimi beyanı ve kanıtı; rol buna göre atanır.
5. **Kayıt:** Kanıt paketi depo dışında saklanır; özeti deftere yazılır. Yeniden doğrulama yıllık veya baro durum değişikliğinde yapılır.

## 6. Anahtar Yaşam Döngüsü

| Aşama | Prosedür |
|---|---|
| Oluşturma | Anahtar hukukçunun kontrolündeki donanımda (FIPS 140-2/3 donanım belirteci) veya KMS/HSM'de (`production_trust_root_config.json`: GCP Cloud KMS HSM, `europe-west3`; alternatif PKCS#11 HSM) **dışa aktarılamaz** biçimde üretilir. Özel anahtar depoya, CI'a veya geliştirici makinesine girmez. |
| Kayıt töreni | Açık anahtar ve parmak izi iki ayrı kanaldan (ör. imzalı e-posta + görüntülü görüşmede sesli teyit) doğrulanır; tören kaydı kanıt paketine girer. |
| Saklama | KMS/HSM erişimi kişiye özel, MFA'lı; denetim günlükleri açık. |
| Rotasyon | En geç 12 ayda bir; yeni `key_id`/`key_version` eklenir, eskisi `RETIRED` olur (geçmiş imzalar geçerliliğini korur). |
| İptal | Kompromi şüphesinde `REVOKED` + `KEY_COMPROMISE`. O anahtarla verilmiş **tüm** onaylar `KEY_COMPROMISED_APPROVAL_INVALID` olur ve ilgili vakalar yeniden onaya düşer. |
| Yenileme | Geçerlilik bitmeden yeni anahtar kaydı; pencere dışındaki imzalar `SIGNATURE_OUTSIDE_KEY_VALIDITY_WINDOW`. |
| Yeniden onay | Cevap anahtarı değiştiğinde (`STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED`) veya anahtar kompromisinde `SUPERSEDE_REAPPROVE` zarfı gerekir. |

## 7. Dış Bağımlılıklar

- KMS/HSM hesabı ve politikaları (GCP projesi, IAM, anahtar halkası).
- Baro sicil doğrulama kanalı ve kanıt deposu (KVKK uyumlu, erişim kontrollü).
- Bağımsız hukukçu(lar) ile sözleşme ve beyan süreci.
- WP-1 değişiklik onayı (faz 2).
