# WP-4.6 — GCP Region and KVKK Assessment

**Belge türü:** Değerlendirme çerçevesi. **Veri bölgesi seçilmedi: `UNDECIDED`. KVKK incelemesi: `PENDING`.** Bu belge Frankfurt, Belçika, Hollanda veya başka herhangi bir bölgeyi varsayılan olarak önermez veya seçmez.

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

## 1. Karar sorusu

HOLDOUT kasası (ve gelecekteki bağımsız kohortlar) hangi GCP bölgesinde/bölgelerinde saklanabilir; bu saklama 6698 sayılı KVKK ve kurumsal politikalar açısından hangi koşullarla kabul edilebilir?

## 2. Değerlendirme başlıkları

| # | Başlık | Değerlendirilecek sorular | Sorumlu (rol) | Durum |
|---|---|---|---|---|
| R-1 | KVKK ve yurt dışına veri aktarımı | Kasa kişisel veri içeriyor mu (vakalar anonim/sentetik mi)? İçeriyorsa KVKK m.9 kapsamında aktarım dayanağı (yeterlilik kararı, uygun güvenceler/standart sözleşme, bağlayıcı şirket kuralları, arızi aktarım) ve bildirim yükümlülükleri nelerdir? Yurt içi bölge zorunluluğu var mı? | Kurumsal hukuk / KVKK sorumlusu | `PENDING` |
| R-2 | Kurumsal veri sınıflandırması | Kasa hangi sınıfta (gizli / hizmete özel / kişisel veri içeren)? Sınıfın gerektirdiği şifreleme ve erişim seviyesi nedir? | Bilgi güvenliği | `PENDING` |
| R-3 | Veri yerleşimi gereklilikleri | Sözleşmesel veya mevzuat kaynaklı yerleşim zorunluluğu var mı? Tek bölge mi, çift bölge mi, çoklu bölge mi? `constraints/gcp.resourceLocations` hangi değerle kısıtlanmalı? | Kurumsal hukuk + bulut yöneticisi | `PENDING` |
| R-4 | Saklama süresi | Denetim kanıtı olarak ne kadar saklanmalı? Bucket Lock ile kilitlenecek süre ve süre sonunda imha prosedürü | Depo sahibi + hukuk | `PENDING` |
| R-5 | Kurumsal bilgi güvenliği politikası | Şifreleme anahtarı yönetimi (HSM/EKM), erişim gözden geçirme sıklığı, olay müdahalesi | Bilgi güvenliği | `PENDING` |
| R-6 | GCP bölgesel hizmet ve KMS kullanılabilirliği | Aday bölgede Cloud Storage, Cloud KMS (HSM dahil), istenen imza algoritmaları, Bucket Lock ve gerekli log hizmetleri mevcut mu? Anahtar ve bucket aynı konumda olabilir mi? | Bulut yöneticisi | `PENDING` |
| R-7 | Yedekleme ve felaket kurtarma | Çift bölge/çoklu bölge ihtiyacı, ikinci bir kasa kopyası, RPO/RTO, anahtar kaybı senaryosu (CMEK imha koruması) | Bulut yöneticisi + depo sahibi | `PENDING` |
| R-8 | Veri erişim loglarının saklanması | Audit loglarının konumu ve süresi, logların kişisel veri içerip içermediği (principal e-postaları), log bucket kilidi | Bilgi güvenliği + KVKK sorumlusu | `PENDING` |

## 3. Karar kaydı şablonu

Karar verildiğinde şu alanlarla ayrı bir karar kaydı oluşturulur (bu branch'te boş):

- Seçilen konum tipi ve konum(lar): **boş**
- KVKK dayanağı ve belge referansı: **boş**
- Onaylayan roller (en az iki): **boş**
- Tarih: **boş**

Karar kaydı oluşmadan `data_region` durum alanı `UNDECIDED` kalır; adaptör `UNDECIDED` konumla her işlemi reddeder (`VAULT_NOT_CONFIGURED`). `kvkk_data_residency_approved = false` değişmez.
