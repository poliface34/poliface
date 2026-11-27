# WP-4.6 — Public Repository Historical Exposure Risk Assessment

**Belge türü:** Risk değerlendirmesi ve karar dosyası. **Hiçbir düzeltici işlem yapılmadı:** Git geçmişi temizlenmedi, depo görünürlüğü değiştirilmedi, PR/branch'lere dokunulmadı. Değerlendirme yalnız metadata ile yapıldı (Git nesne kimliği, dosya yolu, commit bilgisi, boyut, mevcut SHA-256 manifesti, GitHub API metadata'sı). **HOLDOUT içeriği açılmadı ve bu belgeye aktarılmadı.**

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

## 1. Depo görünürlüğü (doğrulandı, 2026-11-27)

| Kontrol | Sonuç |
|---|---|
| GitHub API (`search/repositories`, `repo:poliface34/poliface`) | `private: false`, `visibility: "public"` |
| Kimlik doğrulamasız `GET api.github.com/repos/poliface34/poliface` | HTTP 200 (herkese açık) |
| Fork / yıldız / izleyici sayısı | 0 / 0 / 0 (gözlem anı; geçmişte silinmiş fork'lar bu sayıda görünmez) |

Beklenen değer `public_check` idi; **gerçek görünürlük PUBLIC'tir.**

## 2. HOLDOUT dosyasının metadata'sı

| Alan | Değer |
|---|---|
| Kasa | `HOLDOUT-WP45-V1.2-30-SEALED-20261126` (`CONSUMED` + `CONTAMINATED`, `max_authorized_runs = 0`) |
| Güncel konum | `hrai_hukuk_sgk/` altında, kayıt defterindeki `file_relpath` (değişmedi, silinmedi, yeniden adlandırılmadı) |
| Git blob | `542fa53d2d86dfebd88207d5231cf876859e6dd2`, 78 895 bayt (`git cat-file -s`) |
| SHA-256 (arşiv manifesti ve kayıt defteri) | `b809245fa04ee6de2daf4189c115ba03860b1bd54213dfc88b86ce7a1625730f` |
| İlk ve tek commit | `1d95a8b9462b79a337a3ee6f54d5ab8e2c2ce8bd` (2026-11-26T14:35:59Z); sonrasında hiç değiştirilmedi |
| İçeren commit sayısı | 8 (`1d95a8b` → `4cca273`, PR #4 zinciri) |

## 3. Dosyayı içeren ve içermeyen referanslar

| Referans | HOLDOUT blob'u var mı |
|---|---|
| `feat/v1.0.6-wp4-agent-intelligence` (`4cca273`) | **Var** |
| `claude/project-thread-0j7bfc` (`4cca273`) | **Var** |
| `refs/pull/4/head` (+ GitHub'ın `refs/pull/4/merge` birleştirme ref'i) | **Var** (salt okunur PR ref'leri; sahibi silemez) |
| `feat/wp46-gcp-holdout-vault-preparation` (bu çalışma; `4cca273` tabanlı) | **Var** — aynı Git nesnesi; yeni blob veya kopya oluşturulmadı, ancak yeni bir public ref aynı nesneye işaret eder |
| `main`, `release/v1.0.5.1`, `feat/v1.0.6-wp1-ci-assurance`, `feat/v1.0.6-wp2-trust-chain-adapters`, `claude/project-thread-13uq24`, PR #1–#3 ref'leri, `v1.0.5.1` etiketi | Yok |
| Dondurulmuş arşivler `kadroai_hukuk_sgk.zip`, `hrai_hukuk_sgk_v1.0.5.1.zip` | Yok (ZIP içerik listesinde eşleşen ad: 0) |

Ayrıca arşiv manifestine göre HOLDOUT kök neden ifşası içeren spec sürümü (`813202c`) ve HOLDOUT'u maskesiz değerlendiren test sürümü (`d1dd8ef`) Git geçmişindedir.

## 4. Erişim kanalları ve riskler

| # | Kanal | Değerlendirme | Kalıcılık |
|---|---|---|---|
| E-1 | Tarihsel Git nesneleri | Public depo klonlayan/fetch eden herkes blob'a erişebilir. Commit SHA ile doğrudan görüntüleme (web, raw) mümkündür. | Kalıcı kabul edilmeli |
| E-2 | Fork ve önbellek kopyaları | Şu an fork yok. GitHub'da fork'lar ağ nesnelerini paylaşır; silinmiş bir fork veya yeniden yazılmış geçmişteki nesneler GitHub tarafında SHA ile erişilebilir kalabilir. Üçüncü taraf arşivler/indeksleyiciler (kod arama, yazılım arşivleri, tarayıcılar) bilinmez. | Kontrol dışı |
| E-3 | GitHub otomatik kaynak arşivleri | Branch/commit için "Download ZIP"/tarball (codeload) HOLDOUT'u içerir. Bu, projenin deterministik ZIP politikasının **dışındadır** ve depo public kaldıkça engellenemez. | Ref yaşadıkça |
| E-4 | Önceki ZIP ve CI artifact'leri | 1d95a8b'den itibaren 15 CI koşusu (run #24–#38) GitHub runner'larında HOLDOUT içeren aktif ZIP'i üretti ve açtı. İş akışında artifact yükleme adımı yok; kontrol edilen koşularda artifact sayısı 0 (örn. 46021319175). Loglar unittest çıktısını `/dev/null`'a yönlendirir; içerik loglanmadı (arşiv manifesti kaydı). Public depoda Actions logları herkese açıktır (varsayılan saklama 90 gün). Dondurulmuş sürüm ZIP'leri HOLDOUT içermez. | Runner geçici; loglar süreli |
| E-5 | Public PR ve branch erişimi | PR #4 (Draft) dosya farkı web arayüzünde HOLDOUT içeriğini gösterir. `refs/pull/4/*` sahibi tarafından silinemez. | PR yaşadıkça; geçmiş yeniden yazılsa bile GitHub Support gerekir |
| E-6 | Bu çalışmanın branch'i | Yeni branch aynı blob'a ek bir public ref ekler (yeni içerik veya kopya yok). Hazırlanan paket politikası bu branch'ten üretilen yeni ZIP/CI artifact'lerine dosyayı koymaz (CI iş akışı değişikliği onaylandı ve bu branch'e uygulandı). | Branch yaşadıkça |

**Sonuç:** HOLDOUT içeriği 2026-11-26'dan beri public olarak erişilebilir durumdadır ve bu erişim geriye dönük olarak geri alınamaz. Bu, kasanın zaten kayıtlı `CONTAMINATED` statüsüyle tutarlıdır; görünürlük, kasanın körlüğünü ayrıca ve kalıcı olarak ortadan kaldırmıştır. Harici kasa bu kohortun körlüğünü geri getirmez; yalnız denetim kanıtını korur ve gelecekteki kohortlar için doğru düzeni kurar.

## 5. Karar seçenekleri (depo sahibinin kararı; hiçbiri uygulanmadı)

| Seçenek | Etki | Maliyet / risk |
|---|---|---|
| A. Mevcut durumu kabul et; HOLDOUT'u depoda (geçmişte) bırak, yeni paket/CI'dan hariç tut | Denetim zinciri (commit SHA'ları, arşiv manifesti) bozulmaz | Public erişim sürer (zaten tüketilmiş kasa) |
| B. Depoyu private yap | Gelecek anonim erişimi azaltır; codeload/PR görünümü kapanır | Geçmiş kopyaları geri almaz; CI/fork/işbirliği etkileri; ayrı karar |
| C. Git geçmişini yeniden yaz (+ GitHub Support ile PR ref/önbellek temizliği) | Depodan blob'u kaldırmaya çalışır | Geri alınamaz; tüm commit SHA'ları ve PR'lar değişir; arşiv manifesti ve kanıt zinciri kırılır; dış kopyalar yine kalır |
| D. Gelecek kohortlar için kural: hiçbir HOLDOUT verisi depoya girmez; yalnız kasada | Tekrarı önler | Düşük; hazırlanan mimariyle uyumlu |

**Öneri (karar değil):** A + D; B ayrı bir görünürlük kararı olarak değerlendirilebilir. C, kanıt zincirini bozduğu ve dış kopyaları silmediği için önerilmez. Geçmişin yeniden yazımı kod ile yetkilendirilemez (`authorize_git_history_rewrite` her durumda reddeder).

## 6. Açık işlemler

- Depo görünürlüğü kararı: **açık** (değiştirilmedi).
- Git geçmişi kararı: **açık** (değiştirilmedi).
- PR #3 ve PR #4: **dokunulmadı**.
