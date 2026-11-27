# WP-4.6 — HOLDOUT Custodian Responsibility Matrix

**Belge türü:** Yetki matrisi önerisi. Emanetçi modeli `kurumsal_bulut` olarak kararlaştırıldı. **Gerçek kişi adı belirlenmedi; bu belgede isim uydurulmamıştır.** Rol sahipleri atanana kadar durum `CORPORATE_CLOUD_ADMIN_ROLE_PENDING_NAMED_OWNER`.

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

## 1. Roller

| Rol | Sorumluluk | Kasa içeriğine erişim | GCP rolleri (öneri, kurulmadı) |
|---|---|---|---|
| Kurumsal bulut yöneticisi | Altyapı, IAM, KMS, bucket politikaları, log sink | **Yok** (nesne okuma rolü yok) | `roles/storage.admin` *kasa nesnelerine okuma hariç* özel rol, `roles/cloudkms.admin` (anahtar materyaline erişim yok), `roles/logging.configWriter` |
| Yetkili emanetçi | HOLDOUT erişim grant'lerinin kontrolü ve imzalanması; checkpoint'lerin gözden geçirilmesi | Yalnız grant süresince, koşullu IAM ile, kayıtlı | Koşullu `roles/storage.objectViewer` (süre sınırlı), `roles/logging.privateLogViewer` |
| Yedek emanetçi | İş sürekliliği; birincil emanetçi yokken kontrollü yedek yetki | Birincil emanetçi ile aynı koşullar; kullanımı ayrıca kaydedilir | Varsayılan olarak devre dışı; acil durum prosedürüyle etkinleşir |
| Geliştirme ekibi (insan ve ajanlar) | Motor geliştirme | **Yok** | Kasa projesinde rol yok |
| CI (GitHub Actions) | Derleme ve testler | **Yok** | Kasa projesinde rol yok; Workload Identity bağlaması yok |
| Hukukçu değerlendirici | Ayrıca yetkilendirilmiş ve kayıt altına alınmış inceleme | Yalnız ilgili grant kapsamında, maskeli/kontrollü ortamda | Doğrudan rol yok; emanetçi aracılığıyla |
| Depo sahibi | Kasa ve emanetçi kaydının onayı, Bucket Lock ve silme kararları | Yok | Yok (karar mercii) |

## 2. Görev ayrılığı kuralları

1. Bir kişi kendi erişim talebini onaylayamaz (`_check_two_person_rule`: talep eden onaylayanlar arasında olamaz).
2. Kasa işlemleri (yükleme, geri yükleme okuması, silme uygunluğu) **iki farklı kişinin**, **iki farklı rolden** onayını gerektirir.
3. Grant'i imzalayan emanetçi aynı grant'in operatörü (talep edeni) olamaz (`VaultAccessGrantValidator`).
4. Kurumsal bulut yöneticisi emanetçi rolünü aynı anda taşıyamaz.
5. Geliştirici veya geliştirme ajanı emanetçi, yedek emanetçi veya hukukçu değerlendirici olamaz.
6. Emanetçi kaydı yalnız gerçek kimlik ve yetki doğrulamasından sonra, depo sahibinin ayrı onayıyla `holdout_vault_registry.json` dosyasına eklenir; sentetik veya test anahtarı eklenemez (mevcut politika).

## 3. İki kişili onay akışı (öneri)

| İşlem | Talep eden | Onay 1 | Onay 2 |
|---|---|---|---|
| Kasa yükleme (migration) | Kurumsal bulut yöneticisi | Yetkili emanetçi | Depo sahibi |
| Geri yükleme testi | Yetkili emanetçi | Yedek emanetçi | Kurumsal bulut yöneticisi |
| Denetim amaçlı okuma | Hukukçu değerlendirici / denetçi | Yetkili emanetçi | Yedek emanetçi veya depo sahibi |
| Depodaki HOLDOUT'un silinmesi (yalnız `MIGRATION_VERIFIED` sonrası) | Depo sahibi | Yetkili emanetçi | Kurumsal bulut yöneticisi |
| Bucket Lock | Kurumsal bulut yöneticisi | Depo sahibi | Yetkili emanetçi |

Kod düzeyinde `OperatorApproval(approver_id, role, approved_action)` kayıtları kullanılır; kimlik doğrulaması kodun dışında (kurumsal IdP) yapılır. Bu belge herhangi bir hukukçu onayı, imza veya yasal kabul üretmez.
