# WP-4.6 — GCP HOLDOUT Vault Architecture

**Belge türü:** Hedef mimari önerisi (onaylanmamış, kurulmamış). **Tarih:** 2026-11-27. **Branch:** `feat/wp46-gcp-holdout-vault-preparation`.

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

## 1. Amaç

Tüketilmiş (`CONSUMED` + `CONTAMINATED`) 30 vakalık HOLDOUT kasası ve ileride hazırlanacak bağımsız kohortlar için geliştirme deposundan ayrı, erişimi kayıtlı ve değiştirilemez bir saklama alanı tasarlamak. Tüketilmiş kasa bu mimariye taşınsa bile **bağımsız benchmark veya optimizasyon amacıyla yeniden kullanılamaz**; amaç yalnız denetim (AUDIT_ONLY) ve kanıt korumasıdır.

## 2. Mevcut durum ve hedef mimari ayrımı

| Konu | Mevcut durum (gerçek) | Önerilen hedef (kurulmadı) |
|---|---|---|
| Saklama yeri | HOLDOUT dosyası Git çalışma ağacında ve geçmişinde (public depo) | Google Cloud Storage, ayrı GCP projesi |
| Bucket | `NOT_PROVISIONED` | Private bucket, Uniform bucket-level access, Public Access Prevention `enforced` |
| Şifreleme | Yok (düz dosya) | Cloud KMS CMEK (bucket varsayılan anahtarı; anahtar kasa ile aynı konumda) |
| Erişim | Depoyu okuyabilen herkes | IAM least privilege; insan erişimi yalnız iki kişili onaylı grant ile |
| Kayıt | Ledger v2 (yerel, depo dışı JSONL) | Ledger v2 + Cloud Audit Logs (Data Access) + imzalı harici checkpoint |
| Değiştirilemezlik | Git geçmişi | Object Versioning + Retention Policy + Bucket Lock (WORM) |
| Bütünlük | Arşiv manifesti (SHA-256, Git blob) | SHA-256 migration manifesti + KMS imzalı arşiv checkpoint'i |
| Paketler/CI | Hariç tutma aracı CI iş akışında etkin (WP-1 korumalı dosya değişikliği depo sahibinin 2026-11-27 onayıyla uygulandı); kasa dosyası Git ağacında ve geçmişinde duruyor | Hiçbir paket ve CI artifact'inde kasa dosyası yok |

## 3. Hedef bileşenler (öneri)

1. **Ayrı GCP projesi** (geliştirme/üretim projelerinden bağımsız), organizasyon politikaları: `constraints/storage.uniformBucketLevelAccess`, `constraints/storage.publicAccessPrevention`, `constraints/iam.disableServiceAccountKeyCreation`, `constraints/gcp.resourceLocations` (bölge kararı verildikten sonra).
2. **GCS kasa bucket'ı:** private, UBLA açık, PAP `enforced`, Object Versioning açık, Retention Policy (süre kurumsal karar), Bucket Lock (retention kilidi geri alınamaz; ayrı onay gerektirir), varsayılan CMEK anahtarı.
3. **Cloud KMS:** (a) CMEK anahtarı `ENCRYPT_DECRYPT`, koruma seviyesi kurumsal karar (HSM önerilir); (b) checkpoint imza anahtarı `ASYMMETRIC_SIGN` (`EC_SIGN_ED25519` veya `RSA_SIGN_PSS_3072/4096_SHA256`; Ledger v2 algoritmalarıyla uyumlu). Anahtar rotasyonu ve imha koruması (destroy scheduled duration) kurumsal karar.
4. **IAM:** servis hesabı anahtarı üretilmez (Workload Identity Federation / kısa ömürlü kimlik). Geliştirme ekibi ve CI için kasa bucket'ında hiçbir rol yok. Ayrıntı: Custodian Responsibility Matrix.
5. **Cloud Audit Logs:** Storage ve KMS için Data Access (`DATA_READ`, `DATA_WRITE`, `ADMIN_READ`) logları açık; loglar ayrı, kilitli bir log bucket'ına yönlendirilir (saklama süresi kurumsal karar).
6. **SHA-256 migration manifesti** (`hrai.holdout_vault_migration_manifest.v1`): `vault_id`, `object_name`, `sha256`, `size_bytes`, `git_blob_sha1`, `kms_key_name`; değerler tarihsel referansla birebir aynı olmalıdır (ikame yasak).
7. **İmzalı arşiv checkpoint'i** (`hrai.holdout_ledger_external_checkpoint.v1`): Ledger v2 baş kaydının (`seq`, `record_hash`, `record_count`) KMS anahtarıyla imzalanmış özeti; WORM bucket'ta saklanır.

## 4. Yazılım bileşenleri (bu branch'te hazırlanan)

Konum: `engine/evaluation/holdout_vault.py` (mevcut `holdout_governance.py` yanında; yeni paket veya soyutlama katmanı açılmadı).

| Bileşen | Görev | Gerçek bağlantı |
|---|---|---|
| `GCSHoldoutVaultAdapter` | Bucket politika kontrolü, aktarım, kaynak/hedef SHA-256 ve metadata karşılaştırması, audit log doğrulaması | `NOT_CONFIGURED` (istemci enjekte edilmedikçe her işlem reddedilir) |
| `CloudKMSKeyProvider` | CMEK ve imza anahtarı **referans** doğrulaması (ad biçimi, konum, amaç, durum, koruma seviyesi, algoritma) | `NOT_CONFIGURED`; anahtar oluşturmaz |
| `VaultManifestValidator` | Migration manifestinin tarihsel SHA-256/boyut/Git blob ile tutarlılığı, kendi özeti, alan kümesi | Yerel |
| `VaultRestoreVerifier` | Belirli nesne sürümünü depo dışı geçici dizine geri yükleyip SHA-256/boyut karşılaştırması (içerik ayrıştırılmaz) | `NOT_CONFIGURED` |
| `VaultAccessGrantValidator` | Ledger v2 grant'inin geçerliliği, iptal, tek kullanım, erişim sınırı, iki kişili onay, harici checkpoint ile sabitlenme | Yerel ledger |
| `create_ledger_checkpoint` / `verify_ledger_checkpoint` | Harici checkpoint üretimi (imzalayıcı enjekte edilir) ve doğrulaması (imza, append-only önek, sıra) | İmzalayıcı enjekte edilmedikçe yok |
| `authorize_holdout_deletion` / `authorize_git_history_rewrite` | Kasa doğrulanmadan silme ve geçmiş yeniden yazımını reddeder; doğrulansa bile yalnız "sahip kararına uygun" döner | Yerel |
| `ci/release_package_policy.py` | Kasa dosyalarını yol üzerinden ZIP/CI artifact'lerinden hariç tutar, WP-1 `ci.deterministic_zip` ile deterministik üretir, isim ve kayıtlı SHA-256 ile doğrular | Yerel |

Tüm hatalar `VaultOperationRefused` (kod: `VAULT_NOT_CONFIGURED`, `VAULT_HASH_MISMATCH`, `VAULT_BUCKET_POLICY_INVALID`, `VAULT_KMS_KEY_INVALID`, `VAULT_SEPARATION_OF_DUTIES_VIOLATION`, `VAULT_RESTORE_FAILED`, `VAULT_AUDIT_LOG_INCOMPLETE`, `VAULT_CHECKPOINT_INVALID`, `VAULT_HOLDOUT_DELETION_FORBIDDEN`, `VAULT_GIT_HISTORY_REWRITE_FORBIDDEN` …) ile fail-closed sonuçlanır. Aktarım sonucu en fazla `UPLOADED_PENDING_RESTORE_VERIFICATION` olabilir; adaptör hiçbir zaman "VERIFIED" üretmez.

## 5. Ledger v2 ↔ GCS kasası entegrasyonu

Mevcut `hrai.holdout_access_ledger.v2` şeması ve `HoldoutAccessGate` davranışı **değiştirilmedi**. Entegrasyon şu katmanlarla eklenir:

1. **Grant doğrulaması:** Kasadan geri yükleme yalnız `HoldoutAccessGate.authorize` ile verilmiş, ledger'da `ACCESS_GRANTED` olarak bulunan grant ile yapılır. `VaultAccessGrantValidator`, gate'in `_check_grant_still_valid` kontrolünü (kasa durumu, sürüm, emanetçi geçerliliği, tüm imzaların yeniden doğrulanması) yeniden kullanır.
2. **İmzalı erişim kaydı:** Grant isteği emanetçinin Ed25519/RSA-PSS-SHA256 imzasını taşır (mevcut). Kasa okuması `record_vault_read` ile `VAULT_READ` olayı olarak kaydedilir; ikinci okuma `DENY_GRANT_ALREADY_USED`.
3. **Hash zinciri:** RFC 8785 kanonik kayıt özeti + `previous_record_hash` (mevcut).
4. **Harici checkpoint:** Belirli aralıklarla ve her grant'ten sonra ledger başı imzalanır ve WORM bucket'a yazılır. Grant, kendisinden sonra alınmış bir checkpoint ile sabitlenmeden kullanılamaz.
5. **Checkpoint imza doğrulaması:** `verify_ledger_checkpoint` imzayı, ledger'ın checkpoint önekini hâlâ içerdiğini (kesme/yeniden yazım tespiti) ve sıranın geri gitmediğini doğrular.
6. **İptal edilmiş grant kontrolü:** `GRANT_REVOKED` olayı olan grant reddedilir.
7. **Erişim sınırı:** `access_number ≤ max_authorized_runs`; tüketilmiş kasada `max_authorized_runs = 0` olduğundan hiçbir grant verilemez (mevcut).
8. **Append-only:** Ledger O_EXCL genesis, O_APPEND+fsync, dosya kilidi (mevcut); harici checkpoint ek güvence sağlar.
9. **WORM gereksinimi:** Checkpoint ve audit log bucket'ları Retention Policy + Bucket Lock ile korunmalıdır (kurulmadı).

Cloud KMS `asymmetricSign` entegrasyonu: Ed25519 için KMS ham veriyi imzalar (RFC 8785 kanonik baytlar doğrudan verilir); RSA-PSS için KMS SHA-256 özetini imzalar. İmzalayıcı `Callable[[dict], str]` olarak enjekte edilir; bu branch'te gerçek KMS imzalayıcısı yoktur.

## 6. Bu belgenin söylemediği şeyler

- GCP projesi, bucket, KMS anahtarı, servis hesabı veya kimlik bilgisi oluşturulmadı.
- HOLDOUT taşınmadı, silinmedi, yeniden adlandırılmadı; Git geçmişi değiştirilmedi.
- Veri bölgesi seçilmedi (`UNDECIDED`).
