# WP-4.6 — PR #3 (WP-2) ve PR #4 (WP-4) Entegrasyon Riski ve Birleşik Test Planı

**Durum:** Analiz ve ön deneme `COMPLETED`; birleşik entegrasyon testi uygulaması ve merge `REQUIRES_SEPARATE_APPROVAL`.
**Sınır:** PR #3 ve PR #4 birleştirilmedi, PR #3'e dokunulmadı. Ön deneme yalnız bu oturumun geçici çalışma kopyasında yapılan, commit edilmemiş ve push edilmemiş bir `git merge --no-commit` ile yürütüldü.

## 1. Kapsam

| PR | Head | Taban | Değişiklik |
|---|---|---|---|
| #3 (WP-2) | `c28bbd1` | `main` `562a57b` | 10 dosya, +4820: `engine/trust_chain/*` (adapter, `EvidenceRegistry`, `answer_linker`, kurumsal/içtihat/resmî adaptörler, modeller), `engine/tools_router.py` (+56), `tests/test_trust_chain_adapters_wp2_v106.py` (12 test) |
| #4 (WP-4) | `f0c8cf8` (+ WP-4.6 devamı) | `main` `562a57b` | 50+ dosya: `engine/knowledge_base`, `engine/rag`, `engine/answer`, `engine/evaluation`, testler, spec'ler |

## 2. Arayüz Uyumluluğu

PR #4, PR #3'e doğrudan bağımlı değildir. Bağlantı yapısal bir protokolle kurulur:

```python
class TrustChainEvidenceAdapterProtocol(Protocol):   # engine/knowledge_base/models.py
    def get(self, evidence_id: str) -> Any: ...
    def verify_integrity(self, *, require_raw_content: bool = True) -> tuple[bool, dict[str, Any]]: ...
    def get_raw_bytes(self, evidence_id: str) -> bytes | None: ...
```

| Protokol üyesi | PR #3 `EvidenceRegistry` | Uyum |
|---|---|---|
| `get(evidence_id)` | `-> EvidenceRecord | None` | Uyumlu |
| `verify_integrity(*, require_raw_content=True)` | `-> tuple[bool, dict]` | Uyumlu |
| `get_raw_bytes(evidence_id)` | `-> bytes | None` | Uyumlu |

**Veri modeli** (`EvidenceLinker` ve `BitemporalVersionManager`'ın `getattr` ile okuduğu alanlar):

| Alan | `EvidenceRecord`'da | Not |
|---|---|---|
| `is_verified_authority` | Var (property: durum, içerik eşleşmesi, özet, hata yok) | Uyumlu |
| `content_sha256` | Var | Uyumlu |
| `record_sha256` | Var | Uyumlu |
| `transport_mode`, `live_verified` | Var | Uyumlu |
| `registry_head_sha256` | **Yok** (yalnız bağlantılı cevap nesnesinde var) | **Risk R-2:** başarılı bağlamada `registry_head_sha256 = None` olur; izlenebilirlik eksik kalır. Hata vermez çünkü `getattr` varsayılanı kullanılır. |

## 3. Varsayılan `None` Davranışı

`trust_chain_adapter=None` (varsayılan) iken `EvidenceLinker` her parçayı yerel denetim kaydıyla bağlar (`transport_mode = LOCAL_AUDIT_BACKED_NO_TRUST_CHAIN`). PR #4'ün tüm testleri bu modda çalışır. Adaptör verildiğinde yalnız `evidence_id` taşıyan parçalar güven zinciri yolundan (Case 1) geçer.

## 4. Ön Deneme Sonuçları (geçici çalışma kopyası, `f0c8cf8` + `c28bbd1`)

| Kontrol | Sonuç | Kayıt |
|---|---|---|
| Metin düzeyi birleştirme | **Çakışma yok** (PR #3'ün 10 dosyası PR #4'ün dosyalarıyla kesişmiyor; `tools_router.py` yalnız PR #3'te değişmiş) | — |
| Birleşik regresyon, 4 sıralama | **328/328** (316 PR #4 + 12 PR #3), `default` ve `reverse` ilk koşuda; iki karışık sıralama ikinci koşuda geçti | `pr3_pr4_local_merge_4order_*.log` |
| İlk koşudaki tek hata | `shuffle_seed_20261124`'te `test_10_ast_subprocess_isolation…`: `/tmp` altında yeni `calisora_sign_*` dizini. Neden: aynı anda başka bir test sürecini (WP-4.6 testleri) aynı makinede çalıştırmam; paylaşılan `/tmp`'ye imza geçici dizini yazdı. Tek başına yeniden koşuda iki karışık sıralama da geçti. | Aynı |
| RAG + gerçek `EvidenceRegistry` (boş) duman testi | Protokol üyeleri mevcut; `verify_integrity` = `True`; normatif sonuçlar adaptörsüz ile **aynı** (10 parça); 22 bağlamanın tümü `LOCAL_AUDIT_BACKED_NO_TRUST_CHAIN` | Bu belge |

**Bulgu R-1 (yüksek):** Bilgi tabanı corpus'undaki (`wp42_extended_corpus.json`) parçaların hiçbiri `evidence_id` taşımıyor. Bu yüzden PR #3 adaptörü bağlansa bile güven zinciri yolu (Case 1) gerçek veriyle hiç çalışmıyor. Entegrasyon şu an yalnız "çökmeme" düzeyinde doğrulanmış durumda; kanıt bağlama düzeyinde doğrulanmadı.

**Bulgu R-3 (orta):** Test paketleri geçici dizinleri sistem genelindeki `/tmp`'de oluşturur ve `test_10` sistem geneli bir "yeni dizin yok" kontrolü yapar. Aynı makinede paralel test koşuları sahte hata üretir. CI tek süreçli olduğundan CI'da etkisi yoktur.

## 5. Riskler

| Kod | Risk | Olasılık / Etki | Azaltım |
|---|---|---|---|
| R-1 | Corpus parçalarında `evidence_id` yok; güven zinciri yolu uçtan uca çalışmıyor | Kesin / Yüksek | Corpus'a doğrulanmış `evidence_id` bağlama işi (WP-2 kayıtları üretildikten sonra); test planı T-3..T-5 |
| R-2 | `registry_head_sha256` başarılı bağlamada `None` | Kesin / Orta | Linker `verify_integrity` raporundaki `head_sha256`'yı kullanmalı veya `EvidenceRecord`'a alan eklenmeli (karar gerekir) |
| R-3 | Paylaşılan `/tmp` ile paralel koşu sahte hatası | Düşük (CI'da yok) | Testleri `TMPDIR` izole edilmiş süreçlerde koşturmak |
| R-4 | `tools_router.py` iki PR'da farklı yönlerde gelişebilir (PR #3 `build_evidence_linked_answer` ekliyor; PR #4 ise router'ı değiştirmiyor) | Düşük / Orta | Merge sırasında router testlerinin ikisi birden koşulmalı |
| R-5 | PR #3 `EvidenceRegistry` bellek içi `ContentStore` varsayılanı; üretimde kalıcı depo gerekir | Orta / Yüksek | `FileSystemContentStore` + WORM; ayrı iş |
| R-6 | Ayrı ayrı yeşil iki PR'ın birleşimi için CI koşusu yok | Kesin / Orta | Birleşik dalda CI (aşağıdaki plan) |

## 6. Birleşik Entegrasyon Test Planı

Ön koşul: depo sahibinin onayıyla, iki PR'ın birleşimini içeren **geçici bir entegrasyon dalı** (ör. `integration/wp2-wp4-trial`). Bu dal merge edilmez; yalnız CI koşusu için açılır.

| No | Test | Beklenen |
|---|---|---|
| T-1 | Tam regresyon, 4 sıralama, CI ortam değişkenleriyle | 328+/328+ geçer, skip yok |
| T-2 | Protokol uyumu: `isinstance` yerine statik `typing` kontrolü + üye imzaları | `EvidenceRegistry` protokolü karşılar |
| T-3 | Doğrulanmış (`VERIFIED_TEST_TRANSPORT`) bir `EvidenceRecord` ile bir corpus parçasını `evidence_id` üzerinden bağlama | Bağlama `raw_content_verified = True`, `record_sha256` dolu |
| T-4 | İçerik özeti uyuşmazlığı | Parça karantinaya alınır (`quarantined_evidence_mismatches`) |
| T-5 | `verify_integrity` başarısız (zincir tahrifatı) | Tüm Case 1 bağlamaları `TRUST_CHAIN_VERIFY_INTEGRITY_FAILED` |
| T-6 | `BitemporalVersionManager`: doğrulanmamış kanıtla belge sürümü kaydı | `TRUST_CHAIN_EVIDENCE_UNVERIFIED` |
| T-7 | `HukukSGKToolRouter(evidence_registry=…)` + `build_evidence_linked_answer` ile WP-4 cevap motorunun birlikte çağrılması | Cevap, kanıt bağlantılarıyla döner; FATAL/MAJOR kapıları değişmez |
| T-8 | DEV/VAL değerlendirmesi adaptörlü ve adaptörsüz | Skorlar aynı veya yalnız kanıt bağlama alanlarında farklı; HOLDOUT kullanılmaz |
| T-9 | `registry_head_sha256` izlenebilirliği (R-2 kararından sonra) | Başarılı bağlamada `None` olmaz |

T-3..T-9 için PR #3'ün test yardımcıları (`_make_ok_transport`) kullanılabilir. Gerçek ağ erişimi gerekmez.
