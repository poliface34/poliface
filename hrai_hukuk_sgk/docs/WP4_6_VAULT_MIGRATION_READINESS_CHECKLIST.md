# WP-4.6 — Vault Migration Readiness Checklist

**Belge türü:** Hazırlık kontrol listesi. Etiketler: `PASS`, `PARTIAL`, `BLOCKED`, `NOT_STARTED`, `NOT_APPLICABLE`.

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

## 1. Hazırlık (bu branch)

| # | Madde | Durum | Kanıt |
|---|---|---|---|
| H-1 | Ayrı hazırlık branch'i | `PASS` | `feat/wp46-gcp-holdout-vault-preparation` (taban `4cca273`) |
| H-2 | Public depo görünürlüğü doğrulandı | `PASS` | Public Repository Historical Exposure Risk Assessment §1 (PUBLIC) |
| H-3 | Tarihsel HOLDOUT erişim riski raporlandı | `PASS` | Aynı belge §2–§5 |
| H-4 | Paket hariç tutma aracı (`ci/release_package_policy.py`) | `PASS` | `ci/tests/test_release_package_policy.py` (yerel), deterministik çift build + extract + isim/kayıtlı SHA-256 kontrolü |
| H-5 | Yeni ZIP'lerde HOLDOUT yok (araçla üretilen) | `PASS` (yerel) | Hariç tutma raporu; `PACKAGE_EXCLUSION_MANIFEST.json` |
| H-6 | GitHub Actions CI'ın aracı kullanması ve artifact kontrolü | `BLOCKED` | `.github/workflows/ci-assurance.yml`, `ci/tests/test_wp1_ci_assurance.py`, `.github/CODEOWNERS` WP-1 korumalı; önerilen değişiklik `ci/proposed/wp46_wp1_protected_ci_package_exclusion.patch` depo sahibi onayı bekliyor |
| H-7 | Test_16 içerik okumadan yeniden düzenlendi | `PASS` | `tests/test_holdout_ledger_v2_wp46_v106.py::test_16_…` (okuma guard'ı, hits = 0) |
| H-8 | GCP adaptör tasarımı + mock testler | `PASS` | `engine/evaluation/holdout_vault.py`, `tests/test_holdout_vault_preparation_wp46_v106.py` |
| H-9 | GCP projesi henüz oluşturulmadı | `PASS` (açıkça kayıtlı) | Durum dosyası `NOT_CREATED` |
| H-10 | Veri bölgesi `UNDECIDED` | `PASS` | Durum dosyası; Region and KVKK Assessment |
| H-11 | Emanetçi rolü tanımlı, kişi adı yok | `PASS` | Custodian Responsibility Matrix; `named_custodians = []` |
| H-12 | Ledger v2 entegrasyon tasarımı ve test arayüzü | `PASS` | Architecture §5; checkpoint ve grant validator testleri |
| H-13 | WP-1 korumalı dosyalar değişmedi | `PASS` | Immutability doğrulaması + `git diff` (korumalı dosyalarda değişiklik yok) |
| H-14 | Üretim gate'leri kapalı | `PASS` | Integration probe + durum dosyası |

## 2. Provisioning (gelecek)

| # | Madde | Durum |
|---|---|---|
| V-1 | Bölge kararı ve KVKK onayı | `NOT_STARTED` (`UNDECIDED` / `PENDING`) |
| V-2 | Rol sahiplerinin gerçek kişi olarak atanması | `NOT_STARTED` |
| V-3 | GCP projesi | `NOT_STARTED` (`NOT_CREATED`) |
| V-4 | KMS CMEK + imza anahtarı | `NOT_STARTED` (`NOT_CREATED`) |
| V-5 | Bucket (UBLA, PAP, versioning, retention, Bucket Lock, CMEK) | `NOT_STARTED` (`NOT_PROVISIONED`) |
| V-6 | IAM ve Audit Logs | `NOT_STARTED` |
| V-7 | Gerçek istemcilerin adaptöre bağlanması | `NOT_STARTED` (`NOT_CONFIGURED`) |

## 3. Taşıma ve doğrulama (gelecek)

| # | Madde | Durum |
|---|---|---|
| M-1 | Migration manifesti ve iki kişili yükleme | `NOT_STARTED` |
| M-2 | Bağımsız geri yükleme doğrulaması | `NOT_STARTED` |
| M-3 | Audit trail ve harici checkpoint doğrulaması | `NOT_STARTED` |
| M-4 | Durum şemasının kanıt alanlarıyla güncellenmesi | `NOT_STARTED` |
| M-5 | Depodaki kopya için silme kararı | `NOT_APPLICABLE` (yalnız `MIGRATION_VERIFIED` sonrası; ayrı sahip kararı) |
| M-6 | Git geçmişi kararı | `NOT_APPLICABLE` (kod ile yetkilendirilemez; ayrı risk kararı) |

## 4. Özet

Bu branch en fazla `PREPARATION_COMPLETE` seviyesine ulaşabilir ve H-6 nedeniyle hazırlık **PARTIAL**'dır. `VAULT_PROVISIONED` ve `MIGRATION_VERIFIED` başlamamıştır.
