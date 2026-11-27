# WP-4.6 — HOLDOUT Migration and Restore Verification Procedure

**Belge türü:** Gelecekte uygulanacak prosedür taslağı. **Taşıma başlamadı (`NOT_STARTED`), geri yükleme doğrulaması başlamadı (`NOT_STARTED`).**

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

## 1. Kapsam ve sınırlar

- Taşınacak nesne: kayıt defterindeki `HOLDOUT-WP45-V1.2-30-SEALED-20261126` kasa dosyası. Kimlik yalnız metadata ile belirlenir: kayıt defteri `file_relpath`, `file_sha256 = b809245f…5730f`, arşiv manifesti `git_blob_sha1 = 542fa53d…6dd2`, `size_bytes = 78895`.
- Taşıma, kasanın statüsünü değiştirmez: `CONSUMED` + `CONTAMINATED`, `max_authorized_runs = 0`, yalnız `AUDIT_ONLY`.
- HOLDOUT içeriği hiçbir adımda açılmaz, görüntülenmez, ayrıştırılmaz veya yeniden puanlanmaz; yalnız bayt düzeyinde aktarılır ve SHA-256 ile karşılaştırılır.
- Taşıma, kasa `VAULT_PROVISIONED` olmadan başlayamaz.

## 2. Taşıma adımları (iki kişili)

1. **Manifest hazırlığı:** `build_vault_manifest` ile tek girdili manifest; `VaultManifestValidator(load_historical_holdout_reference())` ile doğrulanır. Tarihsel SHA-256 dışında bir değer reddedilir (`VAULT_HASH_MISMATCH`).
2. **Kaynak bütünlüğü:** Kaynak dosya Git'ten (`git cat-file` ile blob `542fa53d…`) emanetçi ortamına çıkarılır; çalışma ağacı kopyası kullanılmaz. Kaynak SHA-256 manifestle eşleşmezse yükleme yapılmaz.
3. **Ön kontroller:** `verify_bucket_policy` (UBLA, PAP, versioning, CMEK, retention, lock, konum) ve `validate_cmek_key`.
4. **Yükleme:** `GCSHoldoutVaultAdapter.transfer(..., requester_id, approvals)`; iki farklı kişi/rol onayı zorunlu. Sonuç yalnız `UPLOADED_PENDING_RESTORE_VERIFICATION` olabilir.
5. **Hedef metadata karşılaştırması:** Nesne sürümü (generation), boyut, CMEK anahtarı ve kaydedilen SHA-256 kaynakla eşleşmeli. GCS'nin sunucu tarafı CRC32C/MD5 değerleri de kaydedilir.
6. **Ledger kaydı:** Taşıma ve onaylar ledger'a ve harici checkpoint'e işlenir.

## 3. Geri yükleme doğrulaması

1. Ayrı bir kişi (yedek emanetçi), farklı bir kimlikle `VaultRestoreVerifier.verify(entry, generation)` çalıştırır; nesne depo dışındaki geçici bir dizine indirilir, SHA-256 ve boyut karşılaştırılır, geçici dosya silinir. İçerik ayrıştırılmaz.
2. `verify_audit_trail` ile yalnız izinli yazar/okuyucu principal'lerin erişimi olduğu, silme olayı olmadığı ve yükleme + geri yükleme kayıtlarının bulunduğu doğrulanır.
3. Harici checkpoint (`verify_ledger_checkpoint`) ile ledger'ın yeniden yazılmadığı doğrulanır.

## 4. Durum geçişleri

| Aşama | Gerekli kanıt | Sonuç durum |
|---|---|---|
| Hazırlık (bu branch) | Kod, testler, belgeler | `PREPARATION_COMPLETE` (yalnız hazırlık) |
| Provisioning | Provisioning prosedürü §6 kanıtları | `VAULT_PROVISIONED` |
| Taşıma | §2 çıktıları + ledger + checkpoint | Taşıma yapıldı, **doğrulanmadı** |
| Geri yükleme doğrulaması | §3 çıktıları, bağımsız kişi | `MIGRATION_VERIFIED` (ayrı şema sürümüyle kayıt) |

`derive_migration_state()` dosyanın depoda veya pakette bulunup bulunmamasına bakmaz; HOLDOUT dosyasının yokluğu hiçbir zaman taşıma kanıtı değildir.

## 5. Depodaki kopyanın akıbeti

- `MIGRATION_VERIFIED` öncesinde depodaki HOLDOUT dosyası **silinemez** ve **yeniden adlandırılamaz** (`authorize_holdout_deletion` → `VAULT_HOLDOUT_DELETION_FORBIDDEN`).
- `MIGRATION_VERIFIED` sonrasında bile kod yalnız `ELIGIBLE_PENDING_OWNER_DECISION` döner; silme ayrı, depo sahibi onaylı bir değişikliktir.
- Git geçmişinin yeniden yazımı kod ile hiçbir zaman yetkilendirilmez (`VAULT_GIT_HISTORY_REWRITE_FORBIDDEN`); Public Repository Historical Exposure Risk Assessment'taki ayrı karar sürecine tabidir.

## 6. Hata halinde

Herhangi bir uyuşmazlıkta işlem durur (fail-closed), kısmi yüklenen nesne sürümü silinmez (retention), olay ledger'a ve olay kaydına işlenir; yeniden deneme yeni onay gerektirir.
