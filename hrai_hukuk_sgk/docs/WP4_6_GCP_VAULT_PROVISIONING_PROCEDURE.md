# WP-4.6 — GCP Vault Provisioning Procedure

**Belge türü:** Gelecekte uygulanacak prosedür taslağı. **Bu branch'te hiçbir adım uygulanmadı.** Her adım kurumsal onay ve iki kişili yürütme gerektirir.

> **Durum ayrımı:** `PREPARATION_COMPLETE ≠ VAULT_PROVISIONED ≠ MIGRATION_VERIFIED`. Bu belge yalnız **hazırlık** kapsamındadır. Hazırlığın tamamlanması HOLDOUT'un kasaya taşındığı veya güvenli biçimde saklandığı anlamına gelmez.

**Mevcut gerçek durum** (kaynak: `engine/evaluation/governance/holdout_vault_migration_status.json`, şema `hrai.holdout_vault_migration_status.v1`):

| Alan | Değer |
|---|---|
| GCP project | `NOT_CREATED` |
| Vault bucket | `NOT_PROVISIONED` |
| KMS key | `NOT_CREATED` |
| Data region | `UNDECIDED` |
| KVKK review | `PENDING` |
| Custodian | `CORPORATE_CLOUD_ADMIN_ROLE_PENDING_NAMED_OWNER` (emanetçi modeli `kurumsal_bulut`; gerçek kişi adı yok) |
| Vault migration | `NOT_STARTED` |
| Restore verification | `NOT_STARTED` |
| Migration verification | `NOT_VERIFIED` |
| HOLDOUT statüsü | `CONSUMED` + `CONTAMINATED`, `max_authorized_runs = 0` (değişmedi) |
| Üretim gate'leri | `production_use_authorized=false`, `qualified_e_signature_5070_production_ready=false`, `qualified_e_signature_5070_equivalent=false`, `kvkk_data_residency_approved=false`, `test_sandbox_keys_allowed_in_production=false`, 5070 sağlayıcı `NOT_CONFIGURED`, resmî hukuk benchmark `UNVERIFIED_ZERO_APPROVED_KEYS` |

Durum dosyasının yükleyicisi (`load_vault_migration_status`) bu değerler dışındaki her "tamamlandı" iddiasını fail-closed reddeder; bir adımın gerçekleştiğini kaydetmek kanıt alanlı, gözden geçirilmiş bir şema değişikliği gerektirir.

## 0. Ön koşullar (hepsi açık)

| # | Ön koşul | Durum |
|---|---|---|
| P-1 | Veri bölgesi kararı ve KVKK değerlendirmesi | `UNDECIDED` / `PENDING` |
| P-2 | Kurumsal bulut yöneticisi, yetkili emanetçi ve yedek emanetçinin **gerçek kişi** olarak atanması | `PENDING_NAMED_OWNER` |
| P-3 | Saklama süresi (retention) ve Bucket Lock onayı | Açık |
| P-4 | KMS koruma seviyesi (HSM/SOFTWARE/EXTERNAL) ve rotasyon politikası | Açık |
| P-5 | Faturalama hesabı ve organizasyon/klasör yerleşimi | Açık |
| P-6 | WP-1 korumalı CI iş akışı değişikliği (paket hariç tutma) | Depo sahibince onaylandı ve hazırlık branch'ine uygulandı (2026-11-27); ana dala birleştirme ayrı karar |

Ön koşullar kapanmadan hiçbir kaynak oluşturulmaz.

## 1. Proje

1. Kurumsal bulut yöneticisi ayrı bir GCP projesi oluşturur (ad kurumsal isimlendirme standardına göre; bu belgede seçilmedi).
2. Organizasyon politikaları uygulanır: UBLA zorunlu, Public Access Prevention zorunlu, servis hesabı anahtarı oluşturma yasak, kaynak konumu kısıtı (P-1 sonrasında).
3. Gerekli API'ler: Cloud Storage, Cloud KMS, Cloud Logging. Gereksiz API açılmaz.

## 2. KMS

1. Seçilen bölgede key ring oluşturulur.
2. CMEK anahtarı: amaç `ENCRYPT_DECRYPT`, koruma seviyesi P-4'e göre, rotasyon süresi P-4'e göre.
3. Checkpoint imza anahtarı: amaç `ASYMMETRIC_SIGN`, algoritma `EC_SIGN_ED25519` (veya `RSA_SIGN_PSS_3072_SHA256`).
4. Cloud Storage hizmet ajanına yalnız CMEK anahtarı üzerinde `roles/cloudkms.cryptoKeyEncrypterDecrypter` verilir.
5. Doğrulama: `CloudKMSKeyProvider.validate_cmek_key` ve `validate_signing_key` gerçek istemciyle çalıştırılır; sonuç kanıt olarak saklanır.

## 3. Bucket

1. Kasa bucket'ı seçilen bölgede, UBLA açık, PAP `enforced`, Object Versioning açık, varsayılan KMS anahtarı = CMEK.
2. Retention Policy P-3'e göre ayarlanır. **Bucket Lock geri alınamaz**; yalnız depo sahibi ve kurumsal bulut yöneticisinin yazılı onayından sonra kilitlenir.
3. Ayrı bir checkpoint/log bucket'ı aynı kontrollerle oluşturulur.
4. Doğrulama: `GCSHoldoutVaultAdapter.verify_bucket_policy` (konum, UBLA, PAP, versioning, CMEK, retention, lock, `allUsers`/`allAuthenticatedUsers` bağlaması yok).

## 4. IAM

Custodian Responsibility Matrix'e göre rol bağlamaları yapılır. İnsanlara kalıcı nesne okuma rolü verilmez; okuma yalnız grant süresince, koşullu IAM (IAM Conditions, süre sınırlı) ile.

## 5. Audit Logs

Storage ve KMS için Data Access logları açılır; log sink kilitli log bucket'ına yönlendirilir. `GCSHoldoutVaultAdapter.verify_audit_trail` için okuma yetkisi yalnız emanetçi rolündedir.

## 6. Kayıt

Provisioning tamamlandığında durum dosyası **doğrudan düzenlenmez**: kanıt alanları (kaynak adları, doğrulama çıktılarının SHA-256'sı, onaylayanların rolleri, harici checkpoint kimliği) içeren yeni şema sürümü gözden geçirilerek eklenir. Ancak bundan sonra durum `VAULT_PROVISIONED` olabilir. `VAULT_PROVISIONED`, `MIGRATION_VERIFIED` anlamına gelmez.

## 7. Bu branch'te yapılmayanlar

GCP projesi, bucket, KMS anahtarı, servis hesabı, kimlik bilgisi, IAM bağlaması, log sink: **hiçbiri oluşturulmadı** (`NOT_CREATED` / `NOT_PROVISIONED`). Veri bölgesi `UNDECIDED`.
