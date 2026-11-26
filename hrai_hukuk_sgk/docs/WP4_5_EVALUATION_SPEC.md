# `WP4_5_EVALUATION_SPEC.md` — hrAI `@HukukSGK` WP-4.5 Evaluation Teknik Şartnamesi ve Veri Modeli

**Belge Kodu:** `WP4-5-EVALUATION-SPEC`  
**Revizyon:** `v1.1`  
**Sürüm Hedefi:** `v1.0.6` — **WP-4 (`HukukSGK Agent Intelligence`) / Aşama `WP-4.5`**  
**Önceki Aşamalar:** [`WP4_1_AGENT_CORE_SPEC.md`](WP4_1_AGENT_CORE_SPEC.md) · [`WP4_2_LEGAL_KNOWLEDGE_BASE_SPEC.md`](WP4_2_LEGAL_KNOWLEDGE_BASE_SPEC.md) · [`WP4_3_RAG_ENGINE_SPEC.md`](WP4_3_RAG_ENGINE_SPEC.md) · [`WP4_4_ANSWER_ENGINE_SPEC.md`](WP4_4_ANSWER_ENGINE_SPEC.md) · [Draft PR #4 (`65d2d6b`)](https://github.com/poliface34/poliface/pull/4)  
**Ürün / Koordinatör / Uzman / Web:** `hrAI` / `@hrAI` / `@HukukSGK` / `www.insenai.com.tr`  
**Durum:** `APPROVED_WP4_5_DESIGN_SPEC`  

**Zorunlu Proje ve Yönetişim Sınırları:**
1. [`tools_router.py`](../engine/tools_router.py) entegrasyonu yapılmayacak; [`engine/rag/`](../engine/rag/__init__.py) (WP-4.3) ve [`engine/answer/`](../engine/answer/__init__.py) (WP-4.4) kodları korunacaktır.
2. [PR #3 (WP-2)](https://github.com/poliface34/poliface/pull/3) (`c28bbd162af9d69b5bd0e15c48e13abf26fcf5c9`) ve Draft PR #4 merge edilmeyecektir; etiket/sürüm çıkılmayacaktır.
3. WP-1 CI sabitleri (`schemas/` = `13` `.schema.json`, `config/` = `9` `.json`, sıfır 3. parti çalışma zamanı bağımlılığı — yalnızca Python 3.12 stdlib, donmuş `v1.0.5`, `v1.0.5.1` ve [`xmldsig.py`](../engine/esign5070/xmldsig.py) `b16207b5...` değişmezliği) korunacaktır.
4. Üretim (`production_use_authorized=false`), 5070 sayılı Kanun (`qualified_e_signature_5070_equivalent=false`) ve KVKK m.9 (`kvkk_data_residency_approved=false`) kapıları kapalı kalacaktır.

---

## 1. Amaç ve Değerlendirme İlkeleri

WP-4.2 (`Legal Knowledge Base`), WP-4.3 (`RAG Engine`) ve WP-4.4 (`Answer Engine`) katmanları sonrasında `@HukukSGK` ajanının gerçek İnsan Kaynakları (İK) ve Sosyal Güvenlik (SGK) vakalarındaki hukuki doğruluğunu, zamansal güvenilirliğini, risk eskalasyonu hassasiyetini ve atıf bütünlüğünü ölçmek amacıyla **risk-ağırlıklı, sızıntı korumalı ve bağımsız hukuk onaylı** bir değerlendirme altyapısı uygulanır.

**Üç Temel İlke:**
1. **Sahte `100/100` Hedefi Yerine Ölümcül Hata Veto Sistemi:** Yanlış madde atfı, geriye yürütme, uydurma içtihat/URL, yetkisiz net TL hesabı veya kapalı kapı ihlali gibi `FATAL` hatalar ile küçük biçimsel üslup farklılıkları aynı puan düzleminde ele alınmaz. Her `FATAL` ihlal vaka puanını doğrudan `0.0`'a düşürür (`FAIL_FATAL`) ve kabul geçişini bloke eder.
2. **Bağımsız Hukuki İnceleme Zorunluluğu (`Answer-Key Governance`):** Cevap anahtarları hukuk değerlendiricisi onayı olmadan resmî başarı endeksine dahil edilmez; onay sonrası tek bir alan değişse bile önceki hukuk onayı kriptografik olarak geçersiz sayılır.
3. **Veri Sızıntısı Olmayan Küme Ayrımı ve Şeffaf Hata Tanısı:** 100 vaka `DEV` / `VALIDATION` / `HOLDOUT` kümelerine senaryo ailesi (`cluster_id`) ve metin benzerliği sınırıyla ayrılır; tüm başarısızlıklar kök neden katmanına (`KB_CORPUS_GAP`, `RAG_RETRIEVAL_MISS`, `TEMPORAL_BOUNDARY_MISS`, `ABSTENTION_OVER_TRIGGER`, `RISK_THRESHOLD_MISMATCH`, `CITATION_FAILURE`, `REASONING_EXCEPTION_MISS`) işlenir.

---

## 2. Uçtan Uca Değerlendirme Mimarisi

```text
[100 Vaka Veri Seti: DEV(40) / VALIDATION(30) / HOLDOUT(30)]
   │
   ├─> [Anti-Leakage Kontrolu: cluster_id izole + Jaccard <= 0.55]
   │
   ├─> [Hukuk Onay Kapisi: answer_key_sha256]
   │      ├─ APPROVED_FOR_BENCHMARK ──> Resmi Hukuk Onayli Kume
   │      └─ PENDING / STALE ──────────> Onaysiz / Taslak Kume (Resmi Endekse Girmez)
   │
   ├─> [Deterministic EvaluationRunner (WP-4.3 RAG + WP-4.4 Answer)]
   │
   ├─> [8 Boyutlu Skorlayici (0.0 .. 100.0)]
   │
   └─> [FATAL Tetikleyici Kontrolu (Otomatik + Hukukcu Override)]
          ├─ Evet ─> Vaka Puani = 0.0 (FAIL_FATAL + Veto)
          └─ Hayir ─> MAJOR (-25..-40, Tavan 65.0) / MODERATE (-10..-15) / MINOR (-1..-5)
                         │
                         ▼
         [Cift Katmanli Rapor: Resmi Endeks vs Muhendislik Tanisi]
```

---

## 3. Sekiz Ölçüm Alanı ve Ağırlık Dağılımı

| # | Ölçüm Alanı (`dimension_id`) | Ağırlık (`w_d`) | Ölçülen Teknik ve Hukuki Kriterler | Kaynak Veri |
|---|---|---:|---|---|
| 1 | **Zamansal Doğruluk** (`TEMPORAL_ACCURACY`) | **18** | Olay tarihi (`as_of_date`) ↔ yürürlük aralığı; `7555`, `7499`, `7566`/`10766`, `7036` kesim tarihleri; mülga/gelecek normun yalnızca `historical_context` (`effective_on_date=false`) içinde tutulması. | `temporal_audit`, `legal_bases`, `historical_context` |
| 2 | **Atıf Bütünlüğü** (`CITATION_INTEGRITY`) | **16** | Tüm `AnswerClaimRecord` kayıtlarının `CitationWhitelist` içinde olması; kanıtsız iddia, hayalet karar/kanun, çıplak URL, `CK != CBK` ihlalinin sıfır olması; `AnswerAuditTrace` ↔ `RetrievalTraceBundle` SHA-256 eşleşmesi. | `citation_audit`, `claims`, `audit_trace` |
| 3 | **Hukuki Doğruluk** (`LEGAL_CORRECTNESS`) | **16** | Nihai statü (`status`) ve hukuki sonucun mevzuata/ölçütlere uyumu; yetkisiz TL hesabı olmaması; `Av. K. m.35` ve kapalı kapı sınırlarının korunması. | `status`, `eight_sections.hukuki_sonuc`, `governance_gates` |
| 4 | **Kaynak Doğruluğu** (`SOURCE_ACCURACY`) | **14** | Zorunlu kanun, madde (`required_provision_ids`) ve kararların (`required_precedent_ids`) aktif dayanaklarda yer alması; yasaklı veya `PENDING_REVIEW` kaynağın sızmaması. | `legal_bases`, `claims` |
| 5 | **Risk Tespiti** (`RISK_DETECTION`) | **12** | Risk düzeyi (`LOW`..`CRITICAL`) doğruluğu; yüksek/kritik vakalarda `counsel_escalation_required=true` ve `payroll_handoff_allowed=false` kilidinin açılması. | `risks`, `human_approval`, `eight_sections.risk` |
| 6 | **Abstention Doğruluğu** (`ABSTENTION_ACCURACY`) | **10** | Eksik tarih/olgu, doğrulanmamış kaynak veya alan dışı sorularda varsayımsız durma; tam verili vakada gereksiz durmama (*false abstention*). | `status`, `missing_information`, `confidence_status` |
| 7 | **Hukuki Yorum & Norm Hiyerarşisi** (`INTERPRETATION_HIERARCHY`) | **8** | İstisna hükümleri, Anayasa/Kanun/CK/Yönetmelik/TİS norm hiyerarşisi, içtihadın kanun katmanına yükseltilmemesi ve L5/L6 kabul edilmemiş şablon sınırı. | `eight_sections.hukuki_degerlendirme`, `istisnalar`, `precedent_assessments` |
| 8 | **Retrieval Başarısı** (`RETRIEVAL_EFFECTIVENESS`) | **6** | RAG kovalarının beklenen `required_source_ids` ve `required_provision_ids` hedeflerini geri getirme başarısı (`Provision Recall@K`, `Source Hit Rate`). | `normative_bucket`, `interpretation_bucket`, `precedent_bucket` |

> **Ağırlık Toplamı:** `18 + 16 + 16 + 14 + 12 + 10 + 8 + 6 = 100`.

---

## 4. `FATAL` Sınıflandırması — Ölçülebilir Tetikleme Koşulları ve Yetki Ayrımı

- **`F-1` Yanlış Madde / Whitelist Dışı İddia (`FATAL_WRONG_ARTICLE_OR_SOURCE_CITED`, `FATAL_UNWHITELISTED_CLAIM`):**
  `expected_published_blocked == False` iken `WRONG_ARTICLE_OR_PROVISION_CITED` / `UNWHITELISTED_CITATION_BLOCKER`; veya `published_answer_blocked == False` iken aktif iddianın `CitationWhitelist` dışında olması, `forbidden_provision_ids` ile kesişmesi veya `AnswerAuditTrace` SHA-256 iz bağının kopması.
- **`F-2` Geriye Yürütme / Mülga Düzenleme (`FATAL_RETROACTIVE_LAW_APPLICATION`, `FATAL_REPEALED_STATUTE_AS_CURRENT`):**
  Tarih dışı veya `forbidden_source_ids` içindeki mülga/gelecek hükmün `effective_on_date == True` ile aktif `legal_bases` içinde sunulması, aktif iddiada `effective_on_date == False` yer alması veya pozitif vakada `TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED` / `EXPIRED_OR_REPEALED_STATUTE` / `ARTICLE_NOT_EFFECTIVE_ON_DATE` oluşması *(yalnızca `historical_context` içindeki gösterim muafdır)*.
- **`F-3` Uydurma Karar / URL / `PENDING_REVIEW` / İçtihat Katman İhlali (`FATAL_FABRICATED_PRECEDENT_OR_URL`, `FATAL_PENDING_REVIEW_AS_DEFINITIVE`, `FATAL_PRECEDENT_AS_STATUTE`):**
  Uydurma karar/kanun/çıplak URL veya `CK != CBK` hatası sızması (veya olumsuz enjeksiyonun durdurulamaması); `PENDING_REVIEW`/`UNVERIFIED` kaynağın aktif sunulması; içtihadın `STATUTORY_EVIDENCE` katmanına yükseltilmesi.
- **`F-4` Yetkisiz Bordro Hesabı (`FATAL_UNAUTHORIZED_PAYROLL_CALC`):**
  `published_answer_blocked == False` iken `@HukukSGK` yanıtında net/brüt hesaplanmış ödeme TL tutarı üretilmesi veya bordro enjeksiyonunun durdurulamaması.
- **`F-5` Kapalı Yönetişim Kapısı İhlali (`FATAL_GOVERNANCE_GATE_BREACH`):**
  `production_use_authorized`, `qualified_e_signature_5070_*` veya `kvkk_data_residency_approved` bayraklarından birinin `False` dışı olması, metinle `"true"` beyanının bloklanamaması veya `xmldsig.py`/`schemas`/`config` sabitlerinin bozulması.

### Yetki Ayrımı (`AUTO_DETERMINISTIC` vs `INDEPENDENT_LEGAL_REVIEWER`)
- `AUTO_DETERMINISTIC`: `F-1..F-5` ve `unacceptable_failure_modes` kuralları tarafından otomatik kesilir; mühendis tarafından silinemez veya affedilemez.
- `INDEPENDENT_LEGAL_REVIEWER`: Makine kontrolünden geçen bir vakada bağımsız hukukçu maddi hukuk hatası saptarsa gerekçeli `LEGAL_FATAL_OVERRIDE` ile vakayı `FAIL_FATAL` (`0.0`) yapabilir. İkisi `fatal_auto_count` ve `fatal_reviewer_count` olarak ayrı raporlanır.

---

## 5. Matematiksel Puanlama Formülü ve Eksik Ölçüm Politikası

- **Boyut Aralığı (`[0.0, 100.0]`):** `S_d = max(0.0, min(100.0, 100.0 - sum(p_i for i in defects(d))))`
- **Şiddet Ceza Değerleri (Düşülecek Kesinti Miktarları):**
  - `FATAL`: `-100.0` (ilgili boyut `0.0`, vaka nihai puanı `final_case_score = 0.0`, `FAIL_FATAL`)
  - `MAJOR`: `-25.0..-40.0` (en az 1 `MAJOR` ve 0 `FATAL` varsa `final_case_score = min(65.0, raw_weighted_score)`, `FAIL_MAJOR`)
  - `MODERATE`: `-10.0..-15.0`
  - `MINOR`: `-1.0..-5.0` *(tek vakada maks. `-5.0`; yalnızca küçük biçimsel/ifade farkları, asla veto/tavan tetiklemez)*
- **Ağırlıklı Ham Skor:** `raw_weighted_score = sum(w_d * S_d for d in D_eval) / sum(w_d for d in D_eval)`
- **Eksik Ölçümler:**
  - `NOT_APPLICABLE`: Beklentisi boş olup ikincil hatası bulunmayan boyutlar varsayılan `NEUTRAL_IF_NOT_APPLICABLE` politikasıyla `S_d = 100.0` (veya `renormalize_na_weights=True` ile ağırlık yeniden ölçekleme) şeklinde işaretlenir (`evaluated_dimension_ids` ve `na_dimension_ids` raporda izlenir).
  - `MEASUREMENT_UNAVAILABLE`: Beklenen çıktı/iz alanı eksik veya sistem çökmüşse `N/A` verilmez; doğrudan `S_d = 0.0` (`MAJOR_MISSING_EVALUATION_SIGNAL`) ile cezalandırılır.

---

## 6. Bağımsız Hukuk Onayı ve `answer_key_sha256` Kilidi

- `answer_key_sha256`, `{case_id, category, split, cluster_id, difficulty, title, query_text, as_of_date, facts, scenario_type, precedent_application_rationale, include_historical, competing_norm_spec, adversarial_injections, ground_truth, expected_outcome}` kanonik JSON yapısından üretilir.
- Herhangi bir alan değiştiğinde `computed != approved_answer_key_sha256` saptanır; önceki `APPROVED_FOR_BENCHMARK` onayı otomatik geçersiz sayılır (`EvaluationIntegrityError`) ve yeni bağımsız hukuk imzası alınana kadar resmî endekse giremez.

---

## 7. Veri Seti Ayrımı (`DEV` 40 / `VALIDATION` 30 / `HOLDOUT` 30) ve Anti-Leakage

| Kategori | Toplam | `DEV` | `VALIDATION` | `HOLDOUT` |
|---|---:|---:|---:|---:|
| `CAT_IS_KANUNU_SOZLESME` | **25** | 10 | 8 | 7 |
| `CAT_SOSYAL_GUVENLIK_SGK` | **20** | 8 | 6 | 6 |
| `CAT_UCRET_SURE_IZIN` | **15** | 6 | 4 | 5 |
| `CAT_ISG_6331` | **10** | 4 | 3 | 3 |
| `CAT_KVKK_6698` | **10** | 4 | 3 | 3 |
| `CAT_ISTEN_AYRILIS_DISIPLIN` | **10** | 4 | 3 | 3 |
| `CAT_ICTIHAT_YARGITAY_DANISTAY` | **10** | 4 | 3 | 3 |
| **TOPLAM** | **100** | **40** | **30** | **30** |

**Anti-Leakage 4 Kontrol:** (1) Aynı `cluster_id` birden fazla `split`'e bölünemez (`CROSS_SPLIT_CLUSTER_LEAKAGE`); (2) Kümeler arası soru metinlerinde birebir eşleşme yasaktır ve 4-gram Jaccard benzerliği `<= 0.55` olmalıdır (`CROSS_SPLIT_NEAR_DUPLICATE_LEAKAGE`); (3) Olgu-tarih-madde parmak izi farklı kümelerde tekrar edemez; (4) `HOLDOUT` ifadeleri `intent.py`/`reranker.py` içine ezber kural olarak konulamaz.

---

## 8. Çift Katmanlı Raporlama

- `official_benchmark_metrics`: **Yalnızca `APPROVED_FOR_BENCHMARK` + geçerli hash** vakalardan hesaplanır (`approved == 0` iken `official_approved_weighted_index = null`, `official_status = "UNVERIFIED_ZERO_APPROVED_KEYS"`, `official_pass_eligible = false`).
- `engineering_diagnostic_metrics`: Onaysız/taslak vakalar dahil tüm değerlendirmeyi (`diagnostic_all_weighted_index`, `split_summaries`, `dimension_averages`, `fatal_auto_count`, `fatal_reviewer_count`, `category_summaries`, `CorpusGapDiagnosticReport`) resmî sonuçtan ayrı biçimde raporlar.
- `approval_coverage` ve `leakage_audit` alanları onay oranını (`legal_review_approval_rate`), küme kapsamını ve sızıntı denetimini şeffaf gösterir.

---

## 9. Mimari Yerleşim

- Belge: [`hrai_hukuk_sgk/docs/WP4_5_EVALUATION_SPEC.md`](WP4_5_EVALUATION_SPEC.md)
- Paket: `hrai_hukuk_sgk/engine/evaluation/` (`__init__.py`, `models.py`, `rubric.py`, `dataset_loader.py`, `runner.py`, `datasets/eval_100_hr_sgk_cases.json`)
- Testler: `hrai_hukuk_sgk/tests/test_evaluation_wp45_v106.py`
