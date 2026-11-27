# WP-4.7: Public depo karar matrisi (A/B/C/D)

**Belge türü:** Kurumsal karar dosyası. **Hiçbir seçenek uygulanmadı.** Depo görünürlüğü değiştirilmedi, Git geçmişi yeniden yazılmadı, hiçbir PR, branch veya ref silinmedi ya da kapatılmadı. Değerlendirme yalnız metadata ile yapıldı: dosya yolu, Git blob kimliği, boyut, kayıtlı SHA-256 ve GitHub API metadata'sı. HOLDOUT içeriği açılmadı.

> **Önemli sınır:** Bu rapor, HOLDOUT dosyasının **kişisel veri veya gizli bilgi içerip içermediğini belirleyemez.** Bunu belirlemek dosyanın açılmasını gerektirir; WP-4.6/WP-4.7 kuralları bunu yasaklar. Sınıflandırma, yetkili bir emanetçi tarafından ayrı ve kayıtlı bir erişimle (HOLDOUT_ACCESS_ALLOWED=true, CI dışı, ledger kaydıyla) yapılmalıdır. O sınıflandırma yapılana kadar aşağıdaki değerlendirme, **içeriğin hassas olabileceği** ihtiyatlı varsayımına dayanır.

Bağlam (WP-4.6 risk değerlendirmesinden, `WP4_6_PUBLIC_REPOSITORY_HISTORICAL_EXPOSURE_RISK_ASSESSMENT.md`):

- Depo **PUBLIC**.
- Kasa `HOLDOUT-WP45-V1.2-30-SEALED-20261126`: blob `542fa53d2d86dfebd88207d5231cf876859e6dd2`, 78 895 bayt, SHA-256 `b809245f…730f`. Durumu `CONSUMED` + `CONTAMINATED`, `max_authorized_runs=0`.
- Blob şu ref'lerden erişilebilir:
  - `feat/v1.0.6-wp4-agent-intelligence`
  - `claude/project-thread-0j7bfc`
  - `refs/pull/4/head` ve `refs/pull/4/merge`
  - `feat/wp46-gcp-holdout-vault-preparation`
  - WP-4.7 ile push edilen `feat/wp47-holdout-access-hardening`. Bu push aynı Git nesnesine işaret eden bir public ref daha ekler. Yeni bir blob veya kopya oluşturmaz.
- `main`, `release/v1.0.5.1`, WP-1 ve WP-2 branch'leri ile dondurulmuş ZIP'ler bu blob'u içermez.

## Seçenekler

### A. Public kalsın, geçmiş olduğu gibi kalsın

| Boyut | Değerlendirme |
|---|---|
| Güvenlik etkisi | İfşa sürer: blob, commit geçmişi ve PR ref'leri üzerinden herkese açık kalır. Yeni ZIP ve CI artifact'leri hariç tutma politikasıyla temizdir, ancak geçmişteki ifşa kapanmaz. HOLDOUT zaten `CONSUMED/CONTAMINATED` olduğundan değerlendirme körlüğü açısından ek kayıp yoktur. Kişisel veya gizli veri riski içerik sınıflandırılmadan ölçülemez. |
| Operasyonel etki | En düşük: iş akışı, PR'lar, CI ve dış bağlantılar değişmez. |
| Geri alınabilirlik | Her an B, C veya D'ye geçilebilir. Ancak geçen her gün, ifşanın kopyalanmış veya önbelleğe alınmış olma olasılığını artırır. |
| GitHub fork/cache etkisi | Mevcut ve gelecekteki fork'lar, klonlar, GitHub arama dizini ve üçüncü taraf arşivleri blob'u taşımaya devam edebilir. |
| Gerekli kurumsal karar | İçerik sınıflandırması "kişisel/gizli veri yok" çıkarsa riskin yazılı kabulü. Sınıflandırma yapılmadan A seçilmesi önerilmez. |

### B. Depo geçici olarak private yapılsın

| Boyut | Değerlendirme |
|---|---|
| Güvenlik etkisi | Yeni anonim erişimi hemen keser. Daha önce alınmış klonları, fork'ları veya önbellekleri geri getirmez. Public bir depoyu private yapmak, public fork'ları kendi ağlarında public bırakabilir (GitHub fork ağı kuralları). Gözlem anında fork sayısı 0 idi; geçmişte silinmiş fork'lar bu sayıda görünmez. |
| Operasyonel etki | Orta: dış katkıcıların ve anonim okuyucuların erişimi kesilir. Actions dakika kotası ve özellikleri plan kurallarına göre değişebilir (ör. private depoda ücretsiz dakika sınırı). Bazı ruleset ve CODEOWNERS davranışları plana bağlıdır, yeniden doğrulanması gerekir. Rozet ve bağlantılar kırılabilir. |
| Geri alınabilirlik | Teknik olarak geri alınabilir (yeniden public yapılabilir). Ancak private süresince yıldız ve izleyici gibi bazı sosyal metadata kalıcı olarak kaybolabilir. |
| GitHub fork/cache etkisi | Mevcut public fork'lar ve dış önbellekler etkilenmez. GitHub'ın kendi önbelleğindeki ham dosya ve "cached view" kopyaları için GitHub Support talebi gerekebilir. |
| Gerekli kurumsal karar | Depo sahibi ve kurum yönetimi kararı. Açık kaynak/şeffaflık taahhüdüyle çelişip çelişmediğinin değerlendirilmesi. Plan maliyeti onayı. |

### C. Geçmiş temizlensin ve PR/branch ref'leri ele alınsın

| Boyut | Değerlendirme |
|---|---|
| Güvenlik etkisi | Blob'un GitHub'daki **erişilebilir** ref'lerden kaldırılmasını hedefler. Tek başına yeterli değildir: `refs/pull/4/*` ref'lerini depo sahibi silemez. Bunlar ve sahipsiz (unreachable) nesneler ile önbellekteki görünümler için GitHub Support'tan "sensitive data removal" talebi gerekir. Dışarıdaki klon ve fork'lar temizlenemez. |
| Operasyonel etki | **Yüksek:** etkilenen 8 commit ve sonraki tüm commit kimlikleri değişir. PR #4 zinciri, WP-4.6 ve WP-4.7 branch'leri yeniden oluşturulmalıdır. İnceleme yorumlarının bağlamı, CI run ve commit bağlantıları ile raporlardaki commit SHA atıfları geçersizleşir. Tüm katkıcıların yerel klonlarını yeniden alması gerekir. WP-1 değişmezlik manifesti ve dondurulmuş ZIP'ler bu blob'u içermediği için doğrudan etkilenmez, ancak commit atıfları yeniden doğrulanmalıdır. |
| Geri alınabilirlik | **Geri alınamaz** (force-push ile eski geçmiş public ref'lerden kalkar; yerel yedek tutulsa bile public tarafta eski kimlikler geri getirilemez). WP-4.6/WP-4.7 değişmez kuralı "Git geçmişini rewrite etme" bu seçeneği şu an açıkça yasaklar. |
| GitHub fork/cache etkisi | Fork'lar ve dış önbellekler temizlenmez. Support talebi kabul edilse bile süre ve kapsam GitHub'a bağlıdır. |
| Gerekli kurumsal karar | Yazılı yönetim onayı, iki kişi kuralı (`authorize_git_history_rewrite` şu an her durumda reddeder), KVKK/hukuk değerlendirmesi, bir bakım penceresi ve tüm açık PR'ların yeniden planlanması. Kişisel veri tespit edilirse KVKK kapsamında ihlal değerlendirmesi de gerekebilir. |

### D. Yeni public ref üretimi durdurulsun, mevcut geçmiş riski kabul edilsin

| Boyut | Değerlendirme |
|---|---|
| Güvenlik etkisi | İfşa yüzeyini büyütmeyi durdurur. Yeni branch'ler blob'u içermeyen bir tabandan (ör. `main` veya HOLDOUT'suz yeniden kurulmuş bir dal) açılır. Kasaya taşıma sonrasında dosya çalışma ağacından ayrı onayla kaldırılır. Mevcut geçmişteki ifşa kapanmaz. |
| Operasyonel etki | Orta-düşük: geçmiş değişmez. Ancak WP-4 zincirinin `main`'e hangi biçimde gireceği yeniden tasarlanmalıdır, çünkü PR #4'ü olduğu gibi merge etmek blob'u `main` geçmişine kalıcı olarak taşır. Seçenekler: HOLDOUT'suz yeni bir dal ya da squash ile tek commit. Squash, dosya ağaçta olduğu sürece blob'u yine içerir. |
| Geri alınabilirlik | Geri alınabilir. İleride C'ye geçişi engellemez, ancak her yeni ref C'nin maliyetini artırır. |
| GitHub fork/cache etkisi | Mevcut durumla aynıdır. Yeni fork'lar mevcut ref'lerden blob'u almaya devam edebilir. |
| Gerekli kurumsal karar | Kalan riskin yazılı kabulü, `main`'e giriş biçiminin seçimi ve WP-4.6 kasa taşımasının takvimi. |

## Bu belgenin kapsamı dışında kalanlar

- İçerik sınıflandırması (kişisel/gizli veri var mı): **belirlenemedi** (yukarıdaki sınır).
- Hiçbir seçenek uygulanmadı. Görünürlük, geçmiş, ref'ler, PR'lar ve fork'lar değişmedi.
- Teknik öneri (bağlayıcı değil): önce yetkili emanetçinin içerik sınıflandırması, ardından sonuca göre karar verilmesi. Hassas veri yoksa D, varsa B ile birlikte C için hukuki ve teknik değerlendirme. Karar verilene kadar PR #4'ün `main`'e merge edilmemesi önerilir, çünkü merge blob'u `main` geçmişine taşır ve C'nin maliyetini en çok artıran adımdır.
