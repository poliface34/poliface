# WP-4.6 — Production ve Resmî Onay İçin Eksik Kanıt Listesi ve Sorumluluk Matrisi

**Durum:** Liste `COMPLETED`. Gate'lerin hiçbiri açılmadı. Bu belge yalnız eksik kanıtları ve sorumlulukları tanımlar; uygunluk beyanı değildir.

## 1. Kapalı Kalan Değerler (doğrulandı)

| Değer | Durum | Kaynak |
|---|---|---|
| `production_use_authorized` | `false` | `config/autonomous_norms_audit_log.json`, `knowledge_taxonomy.json`, integration probe |
| `qualified_e_signature_5070_production_ready` | `false` | `config/esign_5070_config.json`, probe |
| `qualified_e_signature_5070_equivalent` | `false` | `config/authorized_approvers.json`, probe |
| `kvkk_data_residency_approved` | `false` | probe |
| `test_sandbox_keys_allowed_in_production` | `false` | `config/authorized_approvers.json`, `knowledge_taxonomy.json` |
| 5070 sağlayıcı / `deployment_status` | `NOT_CONFIGURED` | `esign_5070_config.json`, `production_trust_root_config.json` |
| Resmî benchmark | `UNVERIFIED_ZERO_APPROVED_KEYS` (`0/100`) | `engine/evaluation/models.py`, runner |

## 2. Eksik Kanıtlar

### 2.1. Resmî Hukuk Benchmark'ı
| # | Eksik kanıt | Neden gerekli |
|---|---|---|
| L-1 | Kimliği ve baro sicili doğrulanmış bağımsız hukukçu(lar) ve bağımsızlık beyanları | K-01 |
| L-2 | Hukukçu anahtarlarının KMS/HSM'de üretilip deftere kaydı (WP-1 değişikliği) | K-01 |
| L-3 | 100/100 vaka için imzalı, güncel cevap anahtarına bağlı onay zarfları | Resmî endeks |
| L-4 | Yeni bağımsız HOLDOUT kohortu ve tek seferlik kör koşu kaydı (ledger başı mühürlü) | Kör genelleme kanıtı |

### 2.2. 5070 Sayılı Elektronik İmza Kanunu
| # | Eksik kanıt |
|---|---|
| E-1 | BTK yetkili ESHS ile sözleşme ve NES sertifika zinciri |
| E-2 | Canlı OCSP/CRL ve bağımsız RFC 3161 TSA doğrulaması |
| E-3 | Hukuki görüş: hangi işlemlerin NES gerektirdiği. Ed25519 / RSA-PSS imzaları NES yerine geçmez. |

### 2.3. KVKK Veri Yerleşimi
| # | Eksik kanıt |
|---|---|
| K-1 | Veri envanteri ve işleme amaçları (değerlendirme vakaları, hukukçu kimlik kanıtları, ledger'lar) |
| K-2 | Yurt dışı aktarım değerlendirmesi (m.9; GCP `europe-west3` kullanımı) ve gerekiyorsa taahhütname/standart sözleşme |
| K-3 | Saklama/imha politikası ve aydınlatma metinleri |
| K-4 | VERBİS kaydı durumu |

### 2.4. Bilgi Güvenliği
| # | Eksik kanıt |
|---|---|
| S-1 | KMS/HSM anahtar politikaları, IAM ve erişim gözden geçirme kayıtları |
| S-2 | Gizli anahtar yönetimi ve CI'da gizli bilgi bulunmadığının sürekli taraması (mevcut özel anahtar taraması yalnız `PRIVATE KEY` metni arar) |
| S-3 | Sızma testi ve tehdit modeli (özellikle prompt enjeksiyonu, kaynak sahteciliği) |
| S-4 | Bağımlılık ve tedarik zinciri taraması (SBOM) |

### 2.5. Audit Trail
| # | Eksik kanıt |
|---|---|
| A-1 | Ledger başlarının (HOLDOUT ledger'ı, zarf deposu, `EvidenceRegistry`) `AUDIT_CHECKPOINT_SEAL` anahtarıyla düzenli mühürlenmesi |
| A-2 | WORM depolama (GCS Bucket Lock) ve saklama süresi |
| A-3 | Mühürleyici servis anahtarının HSM kaydı (`CALISORA-LEDGER-SEALER-01` şu an `PENDING`) |

### 2.6. Operasyonel Uygunluk
| # | Eksik kanıt |
|---|---|
| O-1 | İzleme ve alarm, olay müdahale prosedürü |
| O-2 | Hukukçuya yönlendirme (escalation) SLA'sı ve sorumlu kişi |
| O-3 | Sürüm ve geri alma prosedürü, değişiklik onay kaydı |
| O-4 | Kullanıcıya yönelik sınırlama beyanları (hukuki danışmanlık yerine geçmez) |
| O-5 | PR #3 + PR #4 birleşik entegrasyon testi (bkz. entegrasyon planı) |

## 3. Sorumluluk Matrisi (RACI)

R = yapan, A = onaylayan / hesap veren, C = danışılan, I = bilgilendirilen.

| Alan | Depo sahibi / ürün | Bağımsız hukukçu | Güvenlik / altyapı | KVKK sorumlusu / DPO | ESHS / TSA sağlayıcı | Geliştirme (Claude dahil) |
|---|---|---|---|---|---|---|
| L-1..L-3 Hukuk onayı | A | R | C (anahtar) | C | — | I (araç desteği) |
| L-4 Yeni HOLDOUT kohortu | A | R (hazırlık) | R (saklama) | C | — | I (erişim yok) |
| E-1..E-3 5070 | A | C | R | C | R | I |
| K-1..K-4 KVKK | A | C | C | R | — | C |
| S-1..S-4 Güvenlik | A | — | R | C | — | C |
| A-1..A-3 Audit trail | A | — | R | I | C (TSA) | C (kod) |
| O-1..O-5 Operasyon | A | C | R | I | — | R (O-5 test) |
| Gate değerlerinin açılması | **A (ayrı açık onay)** | C | C | C | C | — |

Gate değerleri yalnız ilgili tüm kanıtlar tamamlandıktan ve depo sahibi ayrıca açık onay verdikten sonra değiştirilebilir. Geliştirme tarafı hiçbir gate'i kendiliğinden açamaz.
