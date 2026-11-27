# WP-4.6 — Bağımsız Hukukçu İnceleme ve İmza Paketi Tasarımı (100 Vaka)

**Durum:** Tasarım ve boşluk analizi `COMPLETED`; uygulama `REQUIRES_SEPARATE_APPROVAL`; gerçek onay `BLOCKED` (gerçek hukukçu katılımı yok).
**Sınır:** `legal_signoff.py` ve imza doğrulama çekirdeği yeniden yazılmadı. Hiçbir onaylı vaka, hukukçu kimliği veya sentetik onay üretilmedi. Resmî durum `UNVERIFIED_ZERO_APPROVED_KEYS` (`0/100`).

## 1. Mevcut Kodun Analizi (`engine/evaluation/legal_signoff.py`)

| Yetenek | Mevcut | Kanıt |
|---|---|---|
| Ayrık imzalı zarf (`SignedAnswerKeyApprovalEnvelope`), RFC 8785 JCS yükü | Var | `build_answer_key_signoff_payload` |
| Ed25519 / RSA-PSS-SHA256 doğrulama; salt 16, PKCS#1 v1.5, bit çevirme, yanlış anahtar reddi | Var | `verify_asymmetric_signature`; `tests/test_evaluation_wp45_v106.py` negatif vektörleri |
| Satır içi `APPROVED_FOR_BENCHMARK` reddi | Var | `dataset_loader.py` |
| Cevap anahtarı özetine bağlama, değişiklikte `STALE_KEY_MODIFIED_REAPPROVAL_REQUIRED` | Var | `_verify_single_envelope` |
| `REVOKE`, `SUPERSEDE_REAPPROVE`, `KEY_COMPROMISE` | Var | `verify_detached_legal_signoffs` |
| O-04 çift göz FATAL override (`second_reviewer_id != first_reviewer_id`) | Var | aynı |
| Nonce tekrar reddi (tek doğrulama çağrısı içinde) | Var | `seen_nonces` |
| Onaylı vaka sayımı ve resmî durum | Var | `runner.py` (`SIGNOFF_VERIFIED_APPROVED` sayımı, `UNVERIFIED_ZERO_APPROVED_KEYS`) |

### 1.1. Eksikler

| # | Eksik | Risk | Öneri |
|---|---|---|---|
| G-1 | Defter dosyadan yüklenmiyor; `TrustedLegalApproverRegistry` yalnız bellekte kuruluyor | Denetlenebilir güven kaynağı yok | Tek kaynak yükleyici (bkz. onayçı tasarımı) |
| G-2 | Zarf deposu (envelope store) yok: zarflar çağırana parametre olarak veriliyor; kalıcı, append-only depo ve yükleyici yok | Zarf seçici sunulabilir (iptal zarfı atlanabilir) | Hash zincirli, append-only JSONL zarf deposu; HOLDOUT ledger desenini yeniden kullanır |
| G-3 | Eylem kümesinde `REJECT`, `REQUEST_CORRECTION`, `RE_REVIEW` yok | Ret ve düzeltme talebi kayıt altına alınamıyor | Yeni eylemler (yalnız durum kaydı; onay sayısını artırmaz) |
| G-4 | Bağımsızlık / çıkar çatışması beyanı zarfta yok | Bağımsızlık kanıtlanamıyor | Zarfa `independence_declaration_sha256` alanı |
| G-5 | `signed_at_utc` şimdiki zamana göre denetlenmiyor (gelecek tarihli imza yalnız anahtar penceresiyle sınırlı) | Geriye/ileriye tarihli imza | Güvenilir zaman damgası (RFC 3161 TSA) veya zarf deposu kayıt zamanı ile karşılaştırma |
| G-6 | `dataset_version` imzalı yükte var, ancak beklenen sürümle karşılaştırılmıyor | Başka sürüm için verilmiş onay kullanılabilir | Doğrulamada beklenen `dataset_version` zorunlu |
| G-7 | Nonce tekrar kontrolü yalnız tek çağrı kapsamında | Depo yokken çağrılar arası tekrar | G-2 ile çözülür |
| G-8 | Gösterilen kaynak paketinin özeti zarfa bağlı değil | Hukukçunun neyi incelediği kanıtlanamıyor | Zarfa `review_packet_sha256` |

G-3, G-4, G-6 ve G-8 imzalı yük şemasını değiştirir; bu nedenle yeni şema sürümü (`HRAI_WP46_LEGAL_SIGNOFF_V2`) olarak eklenmeli, `V1` doğrulaması değiştirilmeden korunmalıdır.

## 2. Vaka İnceleme Paketi (hukukçuya gösterilen)

Her vaka için deterministik, JCS kanonik bir **inceleme paketi** üretilir ve özeti (`review_packet_sha256`) zarfa bağlanır:

| Bölüm | İçerik |
|---|---|
| Kimlik | `case_id`, `dataset_version`, `split` (yalnız DEV/VAL ve gelecekte yeni HOLDOUT; mevcut HOLDOUT hukukçu incelemesi ayrıca karara bağlanır) |
| Soru ve olgular | Kullanıcı sorusu, yapılandırılmış olgular, `as_of_date` (olay tarihi) |
| Beklenen cevap anahtarı | Kanonik JSON ve `answer_key_sha256` |
| Kaynaklar | `legal_sources_registry.json` girdileri: kanun/yönetmelik no, madde, Resmî Gazete tarih/sayı, yürürlük başlangıç/bitiş, mülga durumu, resmî URL, içerik özeti (`content_sha256`) |
| İçtihat | `yargitay_precedents.json` girdileri, doğrulama durumu ve bağlayıcılık sınıfı |
| Zamansal not | `as_of_date` tarihinde yürürlükte olan/olmayan hükümler |
| Rubric | Uygulanabilir boyutlar ve FATAL/MAJOR tanımları (değiştirilemez) |
| Model cevabı | Varsayılan olarak **gösterilmez** (cevap anahtarı incelemesi bağımsız olmalı). Yalnız FATAL override itirazında ayrı paket olarak gösterilir. |

## 3. Durum Makinesi

```
PENDING_REVIEW ──APPROVE──────────────► APPROVED (sayılır)
      │  ├──REJECT─────────────────────► REJECTED (sayılmaz; anahtar yeniden yazılır)
      │  └──REQUEST_CORRECTION─────────► CORRECTION_REQUESTED ──(anahtar düzeltildi)──► PENDING_REVIEW
APPROVED ──REVOKE──────────────────────► REVOKED (sayılmaz)
APPROVED ──(anahtar değişti)───────────► STALE_REAPPROVAL_REQUIRED ──SUPERSEDE_REAPPROVE──► APPROVED
APPROVED ──(imzalayan anahtar KEY_COMPROMISE)──► INVALID_KEY_COMPROMISED ──SUPERSEDE_REAPPROVE──► APPROVED
herhangi ──RE_REVIEW (ikinci hukukçu)──► IN_SECOND_REVIEW ──► APPROVED / REJECTED
```

## 4. İmzalı Değerlendirme Zarfı (V2 önerisi)

V1 alanlarına ek olarak: `review_packet_sha256`, `independence_declaration_sha256`, `decision` (`APPROVE`/`REJECT`/`REQUEST_CORRECTION`/`RE_REVIEW`/`REVOKE`/`SUPERSEDE_REAPPROVE`), `decision_rationale` (zorunlu, boş olamaz), `reviewed_sources` (kaynak kimlikleri listesi), `timestamp_token_b64` (RFC 3161, isteğe bağlı ama üretimde zorunlu).

İmza koşulları değişmez:
- **Ed25519:** RFC 8032 PureEd25519, RFC 8785 JCS, UTF-8 ham bayt, prehash yok.
- **RSA-PSS:** RFC 8017, ≥ 2048 bit, SHA-256, MGF1-SHA256, salt 32, PSS.

Bu imzalar 5070 sayılı Kanun kapsamında güvenli elektronik imza / NES **değildir** (`qualified_e_signature_5070_equivalent = false`).

## 5. Doğrulama ve Sayım

Bir vaka yalnız şu koşullarda **onaylı** sayılır:
1. Zarf deposu zinciri geçerli; vaka için en son geçerli karar `APPROVE` veya `SUPERSEDE_REAPPROVE`.
2. İmzalayan `ENROLLED`, `ACTIVE`, doğru rol ve kapsamda; anahtar penceresi içinde; anahtar kompromize değil.
3. `answer_key_sha256` güncel anahtarla, `dataset_version` beklenen sürümle, `review_packet_sha256` yeniden üretilen paketle eşleşir.
4. Bağımsızlık beyanı özeti defterdeki beyanla eşleşir.

`approved_count = |{vaka : koşul 1–4}|`. Resmî benchmark kabulü için **100/100** gerekir. Altında `UNVERIFIED_ZERO_APPROVED_KEYS` (0) veya `BELOW_APPROVAL_COVERAGE` kalır. FATAL override yalnız O-04 çift göz akışıyla etkili olur.

## 6. Audit Trail

- Tüm zarflar (ret, düzeltme talebi ve iptal dahil) append-only depoda kalır; silme API'si yoktur.
- Depo başı her inceleme turundan sonra `AUDIT_CHECKPOINT_SEAL` anahtarıyla imzalanır.
- Her koşu manifesti, kullanılan zarf deposu başını (`seq`, `record_hash`) içerir.

## 7. Test Altyapısı

Mevcut testler, geçici anahtarlarla pozitif/negatif imza vektörlerini, iptali, yeniden onayı ve O-04 akışını doğrular (`tests/test_evaluation_wp45_v106.py`). Bu anahtarlar hiçbir defterde kalıcı değildir ve onay sayısına girmez. V2 uygulandığında aynı desenle eklenecek testler şunlardır: G-2 zarf deposu tahrifatı, G-3 durum geçişleri, G-5 zaman damgası, G-6 sürüm uyuşmazlığı, G-8 paket özeti uyuşmazlığı.
