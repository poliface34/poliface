# WP-4.7: HOLDOUT erişim sertleştirmesi ve entegrasyon hazırlığı

**Kapsam:** Kod, test ve dokümantasyon. GCP kaynağı oluşturulmadı. Veri taşınmadı. Depo görünürlüğü, Git geçmişi, production gate'leri, benchmark eşikleri ve test beklentileri değişmedi. PR açılmadı, merge yapılmadı. WP-1 korumalı dosyalardan yalnız `ci/release_package_policy.py`, depo sahibinin ayrı onayıyla değiştirildi (§4).

## 1. En erken katman koruması: `HOLDOUT_ACCESS_ALLOWED=false`

`engine/holdout_access_guard.py` modülü bir CPython audit hook'u (PEP 578) kurar. `engine/__init__.py` içindeki ilk import'tur. `tests/__init__.py` de `engine`'i import eder. Böylece hiçbir test, araç veya motor kodu bir dosyaya dokunmadan önce koruma devrededir.

| Özellik | Davranış |
|---|---|
| Korunan yollar | Yalnız kayıt defteri metadata'sından gelir (`vaults[].file_relpath` → realpath). Korunan dosya açılmaz, okunmaz, hash'lenmez. |
| Engellenen olaylar | `open` (builtins/io/os/pathlib/zipfile/shutil iç çağrıları dahil), `os.remove`, `os.rename`, `os.truncate`, `os.link`, `os.symlink`, `shutil.copyfile`, `shutil.move`. Ayrıca argv'si korunan dosyayı anan `subprocess.Popen`. |
| İzin | Yalnız `HOLDOUT_ACCESS_ALLOWED` tam olarak `true` ise **ve** hiçbir CI işareti yoksa (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, …). CI'da koşulsuz ret. |
| Kayıt | Yalnız (olay adı, dosya adı veya sabit gerekçe). İçerik asla kaydedilmez. |
| Fail-closed | Kayıt defteri yok, bozuk, boş veya yol dışarı taşıyorsa `engine` import edilemez. Adı korunan bir dosyayla eşleşip çözülemeyen yol engellenir. |
| Bilinen sınırlar | `engine`'i import etmeyen ayrı süreçler, audit olaylarını atlayan C eklentileri ve koruma kurulmadan önce oluşturulmuş hard link'ler süreç içi korumanın dışındadır. Bu yüzden korunan dosyayı anan `subprocess` çağrıları reddedilir. |

Ek düzeltme: `holdout_governance.assert_no_unauthorised_holdout_bytes` içinde `except OSError: return` bulunuyordu. Koruma ret verdiğinde bu blok reddi "okunamayan dosya" sayıp yutuyordu (fail-open örüntüsü). Artık `HoldoutFileAccessBlocked` her zaman yeniden fırlatılıyor. Bu durum yeni test_05 ile yakalandı.

## 2. Statik erişim incelemesi

Yalnız yol ve kayıt defteri metadata'sı kullanıldı.

| Yol | Önceki durum | WP-4.7 sonrası |
|---|---|---|
| `tests/test_esign_5070_v104.py::test_13` (özel anahtar taraması) | Depo ağacını `rglob` ile gezip her dosyayı metin olarak açıyordu; HOLDOUT dahil | `tests/repo_scan_support.repository_scan_files`: kasa yolu, açmadan önce yol ile atlanır. Atlanan nesne metadata ile sabitlenir (Git blob + boyut veya paket hariç tutma manifesti). Aynı tarama rutini sentetik fixture'da çalıştırılır (yerleştirilmiş işaret bulunur). Uzantı filtreleri ve kapsam aynıdır. |
| `tests/test_trust_root_v103.py::test_10` | Aynı | Aynı düzeltme |
| `tests/test_verification_engine.py::test_zero_private_keys_anywhere_in_repository_and_configs` | Aynı | Aynı düzeltme; `scanned_files >= 45` korunur |
| `holdout_vault.verify_holdout_git_metadata` | `git ls-files`/`git status` dosya yolunu argüman olarak alıyordu (git, dosyayı hash'lemek için açabilir) | Yol argümanı yok: `git ls-files -s -z` çıktısı Python'da süzülür, boyut `os.stat` ile alınır. `git status` kaldırıldı. |
| `dataset_loader.load_evaluation_dataset` (grant'sız açık yol) | `assert_no_unauthorised_holdout_bytes` dosyayı hash'liyordu | Koruma açmadan engeller; ret yutulmaz |
| `dataset_loader` grant yolu (`record_vault_read`) | Grant + ledger | Değişmedi. Gerçek kasada ayrıca HOLDOUT_ACCESS_ALLOWED=true ve CI dışı gerekir; sentetik kasalar etkilenmez. |
| WP-1 `ci/tests/test_wp1_ci_assurance.py::test_04` | WP-4.6'dan beri paket politikasından geçer | Değişmedi (korumalı) |
| `ci/release_package_policy.py` + `ci-assurance.yml` | Kasa yol ile hariç tutulur, artifact'ler hash ile denetlenir | Depo sahibinin onayıyla paketleme ve artifact sürecine de aynı koruma kuruldu (§4); `ci-assurance.yml` değişmedi. |
| `test_holdout_vault_preparation_wp46_v106::test_14` | Yol `resolve` ile karşılaştırılıp atlanır | Değişmedi |

## 3. Test ve doğrulama sonuçları (yerel)

| Kontrol | Sonuç |
|---|---|
| Yeni `tests/test_holdout_access_guard_wp47_v106.py` | 10 test PASS. Gerçek kasa yoluna yalnız okuma API'leri denenir ve iki bağımsız katman kuruludur (motor koruması + test içi ikinci audit hook). Yıkıcı API'ler sentetik korunan dosyada denenir. Dosya metadata'sı değişmez. |
| Kaynak ağaç, 4 sıralama | 357/357 × 4 PASS (347 + 10 yeni test). Tamamlanan HOLDOUT açılışı: **0**. Reddedilen deneme 52; tamamı yeni koruma testinin kasıtlı denemeleri (13 × 4). |
| Paket modu (temiz çıkarım), 4 sıralama | 357/357 × 4 PASS. Tamamlanan açılış 0. |
| WP-2 deneme birleşimi (yerel, push edilmedi), 4 sıralama | Çakışma yok; 369/369 × 4 PASS (357 + WP-2'nin 12 testi). Tamamlanan açılış 0. |
| WP-1 değişmezlik | `verify_immutability` PASS. Manifest SHA-256 `818089a7…fdf8`, `config/authorized_approvers.json` `9bfd8ffb…539c` (değişmedi). |
| WP-1 `ci/tests`, 4 sıralama | 19/19 × 4 PASS (16 + 3 yeni); HOLDOUT erişimi ve denemesi 0 |
| Deterministik ZIP | İki build aynı SHA-256 (`--verify-reproducible`), parite doğrulandı, kasa hariç, `migration_state=NOT_VERIFIED` |
| CI artifact denetimi | `verify-artifacts` PASS, kasa dosyası yok |
| strict / offline / probe | strict PASSED (exit 0), offline NOT_PERFORMED (exit 0), probe exit 0, gate'ler kapalı |

## 4. WP-1 korumalı dosya değişikliği (depo sahibi onayıyla uygulandı)

`ci/release_package_policy.py`, WP-4.6'da (f031956) CODEOWNERS listesine eklendi. WP-4.7 sırasında bu dosyaya yapılan ilk değişiklik onaysız olduğu için geri alındı ve ayrı öneri olarak sunuldu. Depo sahibi öneriyi onayladı; değişiklik aynı içerikle uygulandı. Değişiklik şunları yapar:

- `install_source_access_guard(source_dir)`: koruma modülünü dosya yoluyla yükler (`engine` paketi import edilmez) ve paketleme/artifact sürecinde kurar.
- `build_package` ve `verify-artifacts` başlamadan önce korumayı kurar. Böylece değiştirilmemiş WP-1 ZIP oluşturucusu dahil hiçbir kod kasa dosyasını açamaz. Şu an bu süreç yalnız yol ile hariç tutma ve hash denetimi ile korunuyor.
- Yeni korumasız test dosyası `ci/tests/test_package_policy_access_guard_wp47.py` (3 test) sentetik ağaçla kurulumu, fail-closed davranışını ve `verify-artifacts` CLI'ını doğrular. WP-1 `ci/tests` 19/19 × 4 PASS. `ci-assurance.yml` değişmedi.

## 5. WP-2 (PR #3) ve WP-4 (PR #4) entegrasyon bağımlılıkları

| Konu | Durum |
|---|---|
| Ortak taban | Her ikisi `main` @ `562a57b`. WP-2 head `c28bbd1`, WP-4'ün atası değildir. WP-4.6/WP-4.7 dalları WP-4 head `4cca273` üzerine kuruludur. |
| Dosya çakışması | Yok. WP-2'nin 10 dosyası ile WP-4/4.6/4.7 değişiklikleri kesişmiyor. Yerel deneme birleşimi çakışmasız. |
| Test etkileşimi | Birleşik ağaçta 369/369 × 4 PASS. WP-2 testleri depo genelinde dosya taramadığı için korumayla çakışmıyor. |
| Fonksiyonel bulgular (WP-4.6 planından, açık) | R-1: corpus parçalarında `evidence_id` yok, bu yüzden güven zinciri yolu gerçek veriyle çalışmıyor. R-2: başarılı bağlamada `registry_head_sha256` değeri `None`. Ayrıntı: `WP4_6_PR3_PR4_INTEGRATION_RISK_AND_TEST_PLAN.md`. |
| HOLDOUT geçmişi | WP-2 HOLDOUT blob'unu içermez. PR #4'ün merge edilmesi blob'u `main` geçmişine taşır (bkz. `WP4_7_PUBLIC_REPOSITORY_DECISION_MATRIX.md`). |
| WP-1 korumalı dosyalar | WP-4.6 f031956 (onaylı) CI'ı paket politikasına geçirdi; WP-4.7 (onaylı) politikaya koruma kurulumunu ekledi. WP-2 bu dosyalara dokunmaz. |

**Önerilen merge sırası** (uygulanmadı, yalnız öneri):

1. Public depo kararı (A/B/C/D) ve yetkili emanetçinin içerik sınıflandırması. C seçilirse geçmiş yazımı, PR #4 merge edilmeden önce yapılmalıdır.
2. PR #3 (WP-2) `main`'e. Bağımsızdır, CI temizdir, HOLDOUT içermez.
3. WP-4.6 ve WP-4.7 dalları WP-4 dalına (PR #4'e). Ardından `main` (WP-2 dahil) PR #4'e alınır ve tam CI (4 sıralama, paket modu, artifact denetimi) çalıştırılır.
4. R-1 ve R-2 düzeltmeleri, PR #3 ile PR #4 birleşimi üzerinde, ayrı iş paketi olarak.
5. PR #4'ün `main`'e merge'ü yalnız 1. adım kararından ve kasa taşıma planının onayından sonra. Production gate'leri her aşamada kapalı kalır.
