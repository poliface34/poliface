"""Deterministic Legal Reasoning & HR Scenario Evaluation Engine for CALISORA @HukukSGK (v1.0.3)."""

from __future__ import annotations

from datetime import date, timedelta
import json
from pathlib import Path
from typing import Any

from .attestation_verifier import (
    PARSER_VERSION,
    SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
    verify_signed_calendar_attestation,
)
from .models import (
    VALID_DISCOVERING_AUTHORITY_STATUSES,
    VALID_SCENARIO_TYPES,
    HumanApprovalRequirement,
    LegalBasisItem,
    LegalKnowledgeCard,
    LegalScenarioEvaluation,
    LegalSourceRecord,
    MissingInfoItem,
    NormConflictResolution,
    NormReference,
    PrecedentApplicationAssessment,
    PrecedentRecord,
    RiskItem,
)
from .norm_hierarchy import evaluate_precedent_application, resolve_norm_conflict
from .source_validator import (
    DISALLOWED_VERIFIERS,
    is_specific_official_url,
    parse_iso_date,
    resolve_effective_article,
)

STANDARD_DISCLAIMER = (
    "Bu değerlendirme, doğrulanmış resmî mevzuat kayıtları ve uygulanabilir mevzuat bilgi kartlarına dayalı "
    "kurumsal İK/SGK ön incelemesidir; Avukatlık Kanunu m.35 kapsamında kesin hukuki mütalaa veya avukatlık "
    "danışmanlığı yerine geçmez. Nihai hukuki işlem ve dava stratejisi için yetkili şirket avukatının onayı zorunludur."
)

OFFICIAL_HOLIDAY_CALENDAR_DOMAINS: set[str] = {
    "vakithesaplama.diyanet.gov.tr",
    "diyanet.gov.tr",
    "kurul.diyanet.gov.tr",
    "resmigazete.gov.tr",
    "mevzuat.gov.tr",
    "mevzuat.adalet.gov.tr",
}

# Diyanet İşleri Başkanlığı resmi takvimine göre tam gün dini bayramlar (2429 s. Kanun m.2/B)
# Kapsam: 2024–2027 yılları arşivlenmiş gerçek Diyanet HTML belgelerinden SHA-256 + katı ayrıştırıcı ile teknik doğrulanmıştır.
TURKISH_RELIGIOUS_FULL_HOLIDAYS: dict[int, dict[tuple[int, int], str]] = {
    2024: {
        (4, 10): "Ramazan Bayramı 1. Gün",
        (4, 11): "Ramazan Bayramı 2. Gün",
        (4, 12): "Ramazan Bayramı 3. Gün",
        (6, 16): "Kurban Bayramı 1. Gün",
        (6, 17): "Kurban Bayramı 2. Gün",
        (6, 18): "Kurban Bayramı 3. Gün",
        (6, 19): "Kurban Bayramı 4. Gün",
    },
    2025: {
        (3, 30): "Ramazan Bayramı 1. Gün",
        (3, 31): "Ramazan Bayramı 2. Gün",
        (4, 1): "Ramazan Bayramı 3. Gün",
        (6, 6): "Kurban Bayramı 1. Gün",
        (6, 7): "Kurban Bayramı 2. Gün",
        (6, 8): "Kurban Bayramı 3. Gün",
        (6, 9): "Kurban Bayramı 4. Gün",
    },
    2026: {
        (3, 20): "Ramazan Bayramı 1. Gün",
        (3, 21): "Ramazan Bayramı 2. Gün",
        (3, 22): "Ramazan Bayramı 3. Gün",
        (5, 27): "Kurban Bayramı 1. Gün",
        (5, 28): "Kurban Bayramı 2. Gün",
        (5, 29): "Kurban Bayramı 3. Gün",
        (5, 30): "Kurban Bayramı 4. Gün",
    },
    2027: {
        (3, 9): "Ramazan Bayramı 1. Gün",
        (3, 10): "Ramazan Bayramı 2. Gün",
        (3, 11): "Ramazan Bayramı 3. Gün",
        (5, 16): "Kurban Bayramı 1. Gün",
        (5, 17): "Kurban Bayramı 2. Gün",
        (5, 18): "Kurban Bayramı 3. Gün",
        (5, 19): "Kurban Bayramı 4. Gün",
    },
}

TURKISH_RELIGIOUS_HALF_DAY_EVES: dict[int, dict[tuple[int, int], str]] = {
    2024: {
        (4, 9): "Ramazan Bayramı Arifesi (13:00 sonrası yarım gün)",
        (6, 15): "Kurban Bayramı Arifesi (13:00 sonrası yarım gün)",
    },
    2025: {
        (3, 29): "Ramazan Bayramı Arifesi (13:00 sonrası yarım gün)",
        (6, 5): "Kurban Bayramı Arifesi (13:00 sonrası yarım gün)",
    },
    2026: {
        (3, 19): "Ramazan Bayramı Arifesi (13:00 sonrası yarım gün)",
        (5, 26): "Kurban Bayramı Arifesi (13:00 sonrası yarım gün)",
    },
    2027: {
        (3, 8): "Ramazan Bayramı Arifesi (13:00 sonrası yarım gün)",
        (5, 15): "Kurban Bayramı Arifesi (13:00 sonrası yarım gün)",
    },
}

TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA: dict[str, Any] = {
    "calendar_id": "TR-UBGT-RELIGIOUS-HOLIDAY-CALENDAR-2024-2027",
    "calendar_version": "1.0.5.1",
    "verification_status": "TECHNICAL_VERIFIED_PENDING_LEGAL_ATTESTATION",
    "technical_verification_status": "TECHNICAL_VERIFIED",
    "legal_attestation_status": "PENDING_SIGNED_EXTERNAL_ATTESTATION",
    "ledger_trust_anchor_status": "CHAIN_INTEGRITY_ONLY_NO_EXTERNAL_TRUST_ANCHOR",
    "production_use_authorized": False,
    "qualified_e_signature_5070_equivalent": False,
    "signature_legal_notice": SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
    "parser_version": PARSER_VERSION,
    "authorized_approvers_path": "config/authorized_approvers.json",
    "attestation_ledger_path": "config/calendar_attestation_ledger.json",
    "statutory_basis": "2429 Sayılı Ulusal Bayram ve Genel Tatiller Hakkında Kanun m.1-2 (5892 ve 6752 sayılı Kanun değişiklikleri dâhil)",
    "official_source_authority": "T.C. Diyanet İşleri Başkanlığı — Vakit Hesaplama Resmî Dinî Günler Listesi",
    "official_source_urls": {
        "2024": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=151",
        "2025": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=152",
        "2026": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=153",
        "2027": "https://vakithesaplama.diyanet.gov.tr/icerik.php?icerik=154",
        "law_2429_reference": "https://vakithesaplama.diyanet.gov.tr/2429_kanun.php",
    },
    "archived_snapshots": {
        "2024": {
            "snapshot_id": "SNAP-DIYANET-2024-V1",
            "snapshot_version": "v1",
            "snapshot_path": "evidence/holiday_snapshots/diyanet_2024_v1.html",
            "source_document_sha256": "fc7f54298ef94893049145314bc00bbf9f02ac0eec5bf57592e224f7f5788958",
            "first_verified_at_utc": "2026-11-21T02:22:49Z",
        },
        "2025": {
            "snapshot_id": "SNAP-DIYANET-2025-V1",
            "snapshot_version": "v1",
            "snapshot_path": "evidence/holiday_snapshots/diyanet_2025_v1.html",
            "source_document_sha256": "05c7886bbbed3fcb11aedbcf024d8e6a81ee0e568d90c2e870390496300351da",
            "first_verified_at_utc": "2026-11-21T02:22:49Z",
        },
        "2026": {
            "snapshot_id": "SNAP-DIYANET-2026-V1",
            "snapshot_version": "v1",
            "snapshot_path": "evidence/holiday_snapshots/diyanet_2026_v1.html",
            "source_document_sha256": "cd7f14617212cf67df5bc7598a34ada56e8ff7f81aa4d2a30e4133c7c50d729b",
            "first_verified_at_utc": "2026-11-21T02:22:49Z",
        },
        "2027": {
            "snapshot_id": "SNAP-DIYANET-2027-V1",
            "snapshot_version": "v1",
            "snapshot_path": "evidence/holiday_snapshots/diyanet_2027_v1.html",
            "source_document_sha256": "e1ba5c8f0b45f4dc58a32a5ed359afc8481c441997d3a9d37eeced0fc2f2bbad",
            "first_verified_at_utc": "2026-11-21T02:22:49Z",
        },
    },
    "coverage_start_year": min(TURKISH_RELIGIOUS_FULL_HOLIDAYS.keys()),
    "coverage_end_year": max(TURKISH_RELIGIOUS_FULL_HOLIDAYS.keys()),
    "covered_years": sorted(TURKISH_RELIGIOUS_FULL_HOLIDAYS.keys()),
    "verified_at": "2026-11-21",
    "verified_by": "CALISORA-HUKUK-01",
    "uncovered_year_policy": "BLOCK_AND_ESCALATE_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE",
    "half_day_eve_legal_rule_status": "PENDING_LEGAL_COUNSEL_RULE_CONFIRMATION",
}


def _load_default_approvers_registry(project_root: Path | None = None) -> dict[str, Any] | None:
    base = project_root if project_root is not None else Path(__file__).resolve().parent.parent
    p = base / "config" / "authorized_approvers.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return None


def _load_default_attestation_ledger(project_root: Path | None = None) -> dict[str, Any] | None:
    base = project_root if project_root is not None else Path(__file__).resolve().parent.parent
    p = base / "config" / "calendar_attestation_ledger.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return None

VALID_HALF_DAY_EVE_LEGAL_RULES: set[str] = {
    "UNVERIFIED_REQUIRE_LEGAL_REVIEW",
    "COUNT_AS_WORKING_DAY",
    "EXCLUDE_AS_NON_WORKING_DAY",
}

WEEKDAY_NAME_TO_INT: dict[str, int] = {
    "MONDAY": 0,
    "PAZARTESI": 0,
    "PAZARTESİ": 0,
    "MON": 0,
    "PZT": 0,
    "TUESDAY": 1,
    "SALI": 1,
    "TUE": 1,
    "WEDNESDAY": 2,
    "CARSAMBA": 2,
    "ÇARŞAMBA": 2,
    "WED": 2,
    "THURSDAY": 3,
    "PERSEMBE": 3,
    "PERŞEMBE": 3,
    "THU": 3,
    "FRIDAY": 4,
    "CUMA": 4,
    "FRI": 4,
    "SATURDAY": 5,
    "CUMARTESI": 5,
    "CUMARTESİ": 5,
    "SAT": 5,
    "CMT": 5,
    "SUNDAY": 6,
    "PAZAR": 6,
    "SUN": 6,
    "PZR": 6,
}

INT_TO_WEEKDAY_NAME: dict[int, str] = {
    0: "MONDAY",
    1: "TUESDAY",
    2: "WEDNESDAY",
    3: "THURSDAY",
    4: "FRIDAY",
    5: "SATURDAY",
    6: "SUNDAY",
}

INT_TO_TR_WEEKDAY: dict[int, str] = {
    0: "Pazartesi",
    1: "Salı",
    2: "Çarşamba",
    3: "Perşembe",
    4: "Cuma",
    5: "Cumartesi",
    6: "Pazar",
}


def _parse_weekday_value(val: int | str) -> int | None:
    """Parse ISO weekday integer (0=Mon..6=Sun) or EN/TR weekday name into 0..6."""
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if 0 <= val <= 6 else None
    if isinstance(val, str):
        clean = val.strip().upper()
        if clean in WEEKDAY_NAME_TO_INT:
            return WEEKDAY_NAME_TO_INT[clean]
        if clean.isdigit() and 0 <= int(clean) <= 6:
            return int(clean)
    return None


def _resolve_weekly_rest_days(
    weekly_rest_day: int | str | None = 6,
    legally_verified_weekly_rest_days: set[int] | list[int | str] | tuple[int | str, ...] | None = None,
) -> tuple[set[int], list[str]]:
    """Resolve legally designated weekly rest day(s) (4857 m.46 hafta tatili).

    NOTE: Contractual 5-day workweek non-working Saturdays (akdi tatil / saturday_is_working_day=False)
    are strictly distinguished from statutory weekly rest days and NEVER added automatically here.
    """
    invalid: list[str] = []
    if legally_verified_weekly_rest_days is not None:
        resolved: set[int] = set()
        if not isinstance(legally_verified_weekly_rest_days, (list, tuple, set)):
            return {6}, [str(legally_verified_weekly_rest_days)]
        for raw in legally_verified_weekly_rest_days:
            parsed = _parse_weekday_value(raw)
            if parsed is not None:
                resolved.add(parsed)
            else:
                invalid.append(str(raw))
        if not resolved:
            invalid.append("EMPTY_LEGALLY_VERIFIED_WEEKLY_REST_DAYS")
            return {6}, invalid
        return resolved, invalid

    if weekly_rest_day is None:
        return {6}, []
    parsed_single = _parse_weekday_value(weekly_rest_day)
    if parsed_single is None:
        return {6}, [str(weekly_rest_day)]
    return {parsed_single}, []


def validate_external_yearly_holiday_calendar(
    year: int,
    record: Any,
    *,
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_cryptographic_attestation: bool = True,
    require_signed_ledger_checkpoint: bool = True,
    used_nonces: set[str] | None = None,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    external_trust_anchor_provider: Any | None = None,
    expected_app_project_id: str | None = None,
) -> dict[str, Any]:
    """Strictly validate a single calendar year's externally supplied Turkish religious holiday record (2429 s. Kanun m.2/B).

    Requires ALL of:
      - Provenance metadata: specific official HTTPS URL (`official_source_url`), valid ISO `verified_at`,
        non-disallowed `verified_by`, non-empty `calendar_version`.
      - Ramazan Bayramı full dates: `ramazan_start_date` (in `year`) and `ramazan_end_date` (exact 3 consecutive days).
      - Kurban Bayramı full dates: `kurban_start_date` (in `year`) and `kurban_end_date` (exact 4 consecutive days),
        disjoint and >= 50 days apart from Ramazan Bayramı.
      - Half-day arife dates: `ramazan_arife_date` (`ramazan_start_date - 1 day`) and
        `kurban_arife_date` (`kurban_start_date - 1 day`), non-overlapping with full bayram days.
      - When `require_cryptographic_attestation=True` (DEFAULT for all external uncovered years):
        Stage 1 (safe project_root-contained archived/supplied source snapshot SHA-256 + strict 9-slot Turkish
        parser + OCR gate) AND Stage 2 (authorized approver identity/temporal/scope/revocation/environment +
        Ed25519/RSA-PSS-SHA256 signature over spec-exact RFC 8785 canonical JSON with record_id & nonce +
        externally anchored tamper-evident hash-chained ledger).
    """
    errors: list[str] = []
    error_codes: list[str] = []
    if not isinstance(record, dict):
        return {
            "year": year,
            "valid": False,
            "full_days_valid": False,
            "arife_dates_valid": False,
            "provenance_valid": False,
            "technical_source_valid": False,
            "legal_attestation_valid": False,
            "production_use_authorized": False,
            "error_codes": ["INVALID_EXTERNAL_CALENDAR_RECORD"],
            "errors": [f"{year} yılı harici takvim kaydı JSON nesnesi (dict) olmalıdır."],
            "full_holidays": {},
            "half_day_eves": {},
            "provenance": {},
            "attestation_verification": None,
            "qualified_e_signature_5070_equivalent": False,
            "signature_legal_notice": SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
        }

    if "year" in record:
        raw_yr = record["year"]
        if isinstance(raw_yr, bool) or not isinstance(raw_yr, int) or raw_yr != year:
            errors.append(f"Takvim kaydındaki year={raw_yr!r} beklenen yıl ({year}) ile uyuşmuyor.")

    # 1. Provenance metadata validation
    prov_errors: list[str] = []
    raw_url = record.get("official_source_url")
    url_ok, url_reason = is_specific_official_url(
        str(raw_url or ""),
        allowed_domains=OFFICIAL_HOLIDAY_CALENDAR_DOMAINS,
    )
    if not url_ok:
        prov_errors.append(f"{year} yılı official_source_url geçersiz/eksik: {url_reason}")

    raw_verified_at = record.get("verified_at")
    if parse_iso_date(str(raw_verified_at or "")) is None:
        prov_errors.append(f"{year} yılı verified_at geçerli ISO tarih (YYYY-MM-DD) değildir: {raw_verified_at!r}.")

    raw_verified_by = str(record.get("verified_by") or "").strip()
    if len(raw_verified_by) < 3 or raw_verified_by.upper() in DISALLOWED_VERIFIERS:
        prov_errors.append(f"{year} yılı verified_by geçerli bir doğrulayan kimliği değildir: {raw_verified_by!r}.")

    raw_cal_ver = str(record.get("calendar_version") or "").strip()
    if not raw_cal_ver:
        prov_errors.append(f"{year} yılı calendar_version zorunludur ve boş olamaz.")

    raw_status = record.get("verification_status")
    allowed_statuses = (
        {"VERIFIED"}
        if require_cryptographic_attestation
        else {"VERIFIED", "TECHNICAL_VERIFIED_PENDING_LEGAL_ATTESTATION"}
    )
    if raw_status is not None and str(raw_status).strip().upper() not in allowed_statuses:
        prov_errors.append(
            f"{year} yılı takvim kaydı verification_status='{raw_status}' olup beklenen statülerden ({sorted(allowed_statuses)}) biri değildir."
        )

    provenance_valid = len(prov_errors) == 0
    errors.extend(prov_errors)

    # 2. Ramazan Bayramı full dates (3 consecutive days per 2429 s. Kanun m.2/B)
    full_errors: list[str] = []
    ram_start = parse_iso_date(str(record.get("ramazan_start_date") or ""))
    ram_end = parse_iso_date(str(record.get("ramazan_end_date") or ""))
    ram_days: dict[date, str] = {}
    if ram_start is None or ram_end is None:
        full_errors.append(f"{year} yılı için ramazan_start_date ve ramazan_end_date (YYYY-MM-DD) zorunludur.")
    else:
        if ram_start.year != year:
            full_errors.append(f"{year} yılı ramazan_start_date ({ram_start.isoformat()}) {year} yılına ait olmalıdır.")
        if (ram_end - ram_start).days != 2:
            full_errors.append(
                f"{year} yılı Ramazan Bayramı tam gün süresi 2429 s. Kanun m.2/B gereği 3 ardışık gün olmalıdır "
                f"(bulunan: {ram_start.isoformat()}..{ram_end.isoformat()})."
            )
        else:
            for offset in range(3):
                ram_days[ram_start + timedelta(days=offset)] = f"Ramazan Bayramı {offset + 1}. Gün"

    # 3. Kurban Bayramı full dates (4 consecutive days per 2429 s. Kanun m.2/B)
    kurb_start = parse_iso_date(str(record.get("kurban_start_date") or ""))
    kurb_end = parse_iso_date(str(record.get("kurban_end_date") or ""))
    kurb_days: dict[date, str] = {}
    if kurb_start is None or kurb_end is None:
        full_errors.append(f"{year} yılı için kurban_start_date ve kurban_end_date (YYYY-MM-DD) zorunludur.")
    else:
        if kurb_start.year != year:
            full_errors.append(f"{year} yılı kurban_start_date ({kurb_start.isoformat()}) {year} yılına ait olmalıdır.")
        if (kurb_end - kurb_start).days != 3:
            full_errors.append(
                f"{year} yılı Kurban Bayramı tam gün süresi 2429 s. Kanun m.2/B gereği 4 ardışık gün olmalıdır "
                f"(bulunan: {kurb_start.isoformat()}..{kurb_end.isoformat()})."
            )
        else:
            for offset in range(4):
                kurb_days[kurb_start + timedelta(days=offset)] = f"Kurban Bayramı {offset + 1}. Gün"

    if ram_days and kurb_days:
        overlap = set(ram_days.keys()) & set(kurb_days.keys())
        if overlap:
            full_errors.append(
                f"{year} yılı Ramazan ve Kurban Bayramı tarihleri çakışamaz: {[d.isoformat() for d in sorted(overlap)]}."
            )
        if ram_start and kurb_start and abs((kurb_start - ram_start).days) < 50:
            full_errors.append(
                f"{year} yılı Ramazan ({ram_start.isoformat()}) ve Kurban ({kurb_start.isoformat()}) başlangıçları "
                f"arasında gerçekçi Hicrî takvim aralığı (>= 50 gün) bulunmamaktadır."
            )

    full_days_valid = len(full_errors) == 0 and len(ram_days) == 3 and len(kurb_days) == 4
    errors.extend(full_errors)

    # 4. Half-day arife dates (Ramazan & Kurban Arifesi — immediately preceding day, 13:00+ half-day)
    arife_errors: list[str] = []
    ram_arife = parse_iso_date(str(record.get("ramazan_arife_date") or ""))
    kurb_arife = parse_iso_date(str(record.get("kurban_arife_date") or ""))
    arife_map: dict[date, str] = {}

    if ram_arife is None:
        arife_errors.append(f"{year} yılı ramazan_arife_date (YYYY-MM-DD) zorunludur.")
    elif ram_start is not None and (ram_start - ram_arife).days != 1:
        arife_errors.append(
            f"{year} yılı ramazan_arife_date ({ram_arife.isoformat()}), ramazan_start_date ({ram_start.isoformat()}) "
            f"tarihinden tam 1 gün önce olmalıdır."
        )
    else:
        arife_map[ram_arife] = "Ramazan Bayramı Arifesi (13:00 sonrası yarım gün)"

    if kurb_arife is None:
        arife_errors.append(f"{year} yılı kurban_arife_date (YYYY-MM-DD) zorunludur.")
    elif kurb_start is not None and (kurb_start - kurb_arife).days != 1:
        arife_errors.append(
            f"{year} yılı kurban_arife_date ({kurb_arife.isoformat()}), kurban_start_date ({kurb_start.isoformat()}) "
            f"tarihinden tam 1 gün önce olmalıdır."
        )
    else:
        arife_map[kurb_arife] = "Kurban Bayramı Arifesi (13:00 sonrası yarım gün)"

    if ram_arife and kurb_arife and ram_arife == kurb_arife:
        arife_errors.append(f"{year} yılı Ramazan ve Kurban arife tarihleri aynı gün olamaz.")

    all_full_days = {**ram_days, **kurb_days}
    for adt in arife_map:
        if adt in all_full_days:
            arife_errors.append(
                f"{year} yılı arife tarihi ({adt.isoformat()}) tam gün bayram tarihiyle çakışamaz."
            )

    arife_dates_valid = len(arife_errors) == 0 and len(arife_map) == 2
    errors.extend(arife_errors)

    # 5. v1.0.2c.6 Two-Stage Cryptographic Attestation & Real Source Content Verification
    att_res: dict[str, Any] | None = None
    technical_source_valid = not require_cryptographic_attestation
    legal_attestation_valid = not require_cryptographic_attestation
    production_use_authorized = False

    if require_cryptographic_attestation:
        eff_approvers = (
            approvers_registry
            if approvers_registry is not None
            else _load_default_approvers_registry(project_root)
        )
        eff_ledger = (
            attestation_ledger
            if attestation_ledger is not None
            else _load_default_attestation_ledger(project_root)
        )
        att_res = verify_signed_calendar_attestation(
            year,
            record,
            approvers_registry=eff_approvers,
            attestation_ledger=eff_ledger,
            project_root=project_root,
            runtime_environment=runtime_environment,
            used_nonces=used_nonces,
            expected_checkpoint_head_hash=expected_checkpoint_head_hash,
            expected_checkpoint_entry_count=expected_checkpoint_entry_count,
            expected_chain_digest_sha256=expected_chain_digest_sha256,
            require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
            external_trust_anchor_provider=external_trust_anchor_provider,
            expected_app_project_id=expected_app_project_id,
        )
        technical_source_valid = bool(att_res["technical_source_verification"]["valid"])
        legal_attestation_valid = bool(att_res["legal_counsel_attestation"]["valid"])
        production_use_authorized = bool(att_res["production_use_authorized"])
        error_codes.extend(att_res["error_codes"])
        errors.extend(att_res["errors"])

    valid = len(errors) == 0 and len(error_codes) == 0
    legal_att_block = record.get("legal_attestation") if isinstance(record.get("legal_attestation"), dict) else {}
    return {
        "year": year,
        "valid": valid,
        "full_days_valid": full_days_valid,
        "arife_dates_valid": arife_dates_valid,
        "provenance_valid": provenance_valid,
        "technical_source_valid": technical_source_valid,
        "legal_attestation_valid": legal_attestation_valid,
        "production_use_authorized": production_use_authorized,
        "error_codes": sorted(set(error_codes)),
        "errors": errors,
        "full_holidays": all_full_days if valid else {},
        "half_day_eves": arife_map if valid else {},
        "provenance": {
            "official_source_url": str(raw_url).strip() if raw_url else None,
            "verified_at": str(raw_verified_at).strip() if raw_verified_at else None,
            "verified_by": raw_verified_by or None,
            "calendar_version": raw_cal_ver or None,
            "source_document_sha256": str(record.get("source_document_sha256") or "").strip().lower() or None,
            "snapshot_id": record.get("snapshot_id"),
            "approver_id": legal_att_block.get("approver_id"),
            "algorithm": legal_att_block.get("algorithm"),
            "key_id": legal_att_block.get("key_id"),
            "key_version": legal_att_block.get("key_version"),
            "ledger_entry_id": legal_att_block.get("ledger_entry_id"),
            "production_use_authorized": production_use_authorized,
        },
        "attestation_verification": att_res,
        "qualified_e_signature_5070_equivalent": False,
        "signature_legal_notice": SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
    }


def _extract_validated_external_calendars(
    external_verified_calendars: dict[int | str, Any] | None,
    *,
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_cryptographic_attestation: bool = True,
    require_signed_ledger_checkpoint: bool = True,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    external_trust_anchor_provider: Any | None = None,
    expected_app_project_id: str | None = None,
) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    """Validate each externally supplied yearly calendar independently with shared cross-year nonce replay tracking.

    Returns `(valid_by_year, all_results_by_year)`.
    """
    valid_by_year: dict[int, dict[str, Any]] = {}
    all_results: dict[int, dict[str, Any]] = {}
    if not isinstance(external_verified_calendars, dict):
        return valid_by_year, all_results

    parsed_items: list[tuple[int, Any]] = []
    for raw_key, raw_rec in external_verified_calendars.items():
        if isinstance(raw_key, bool):
            continue
        if isinstance(raw_key, int):
            yr = raw_key
        elif isinstance(raw_key, str) and raw_key.strip().isdigit():
            yr = int(raw_key.strip())
        else:
            continue
        parsed_items.append((yr, raw_rec))

    parsed_items.sort(key=lambda pair: pair[0])
    used_nonces: set[str] = set()
    for yr, raw_rec in parsed_items:
        res = validate_external_yearly_holiday_calendar(
            yr,
            raw_rec,
            approvers_registry=approvers_registry,
            attestation_ledger=attestation_ledger,
            project_root=project_root,
            runtime_environment=runtime_environment,
            require_cryptographic_attestation=require_cryptographic_attestation,
            require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
            used_nonces=used_nonces,
            expected_checkpoint_head_hash=expected_checkpoint_head_hash,
            expected_checkpoint_entry_count=expected_checkpoint_entry_count,
            expected_chain_digest_sha256=expected_chain_digest_sha256,
            external_trust_anchor_provider=external_trust_anchor_provider,
            expected_app_project_id=expected_app_project_id,
        )
        all_results[yr] = res
        if res["valid"]:
            valid_by_year[yr] = res
    return valid_by_year, all_results


def get_holiday_calendar_coverage_info(
    year: int,
    *,
    external_verified_calendars: dict[int | str, Any] | None = None,
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_signed_ledger_checkpoint: bool = True,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
) -> dict[str, Any]:
    """Return explicit coverage status, two-stage verification statuses, and official source provenance for a calendar year."""
    builtin_full = year in TURKISH_RELIGIOUS_FULL_HOLIDAYS
    builtin_eves = year in TURKISH_RELIGIOUS_HALF_DAY_EVES
    if builtin_full and builtin_eves:
        snap_info = TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["archived_snapshots"].get(str(year), {})
        return {
            "year": year,
            "religious_holidays_covered": True,
            "half_day_eves_covered": True,
            "calendar_complete_for_m26": True,
            "coverage_source": "BUILTIN_OFFICIAL_CALENDAR",
            "blocker_code": None,
            "error_codes": [],
            "technical_verification_status": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["technical_verification_status"],
            "legal_attestation_status": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["legal_attestation_status"],
            "production_use_authorized": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["production_use_authorized"],
            "qualified_e_signature_5070_equivalent": False,
            "coverage_start_year": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["coverage_start_year"],
            "coverage_end_year": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["coverage_end_year"],
            "official_source_url": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["official_source_urls"].get(str(year)),
            "source_document_sha256": snap_info.get("source_document_sha256"),
            "snapshot_path": snap_info.get("snapshot_path"),
            "calendar_version": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"],
            "verified_at": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["verified_at"],
            "verified_by": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["verified_by"],
            "validation_errors": [],
        }

    valid_ext, all_ext = _extract_validated_external_calendars(
        external_verified_calendars,
        approvers_registry=approvers_registry,
        attestation_ledger=attestation_ledger,
        project_root=project_root,
        runtime_environment=runtime_environment,
        require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
        expected_checkpoint_head_hash=expected_checkpoint_head_hash,
        expected_checkpoint_entry_count=expected_checkpoint_entry_count,
        expected_chain_digest_sha256=expected_chain_digest_sha256,
    )
    if year in valid_ext:
        prov = valid_ext[year]["provenance"]
        return {
            "year": year,
            "religious_holidays_covered": True,
            "half_day_eves_covered": True,
            "calendar_complete_for_m26": True,
            "coverage_source": "EXTERNALLY_VERIFIED_CALENDAR",
            "blocker_code": None,
            "error_codes": [],
            "technical_verification_status": "TECHNICAL_VERIFIED",
            "legal_attestation_status": "SIGNED_LEGAL_ATTESTATION_VERIFIED",
            "production_use_authorized": bool(valid_ext[year]["production_use_authorized"]),
            "qualified_e_signature_5070_equivalent": False,
            "coverage_start_year": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["coverage_start_year"],
            "coverage_end_year": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["coverage_end_year"],
            "official_source_url": prov["official_source_url"],
            "source_document_sha256": prov.get("source_document_sha256"),
            "snapshot_path": None,
            "calendar_version": prov["calendar_version"],
            "verified_at": prov["verified_at"],
            "verified_by": prov["verified_by"],
            "validation_errors": [],
        }

    ext_res = all_ext.get(year)
    return {
        "year": year,
        "religious_holidays_covered": False,
        "half_day_eves_covered": False,
        "calendar_complete_for_m26": False,
        "coverage_source": "UNCOVERED",
        "blocker_code": "HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE",
        "error_codes": ext_res["error_codes"] if ext_res else ["HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE"],
        "technical_verification_status": (
            "TECHNICAL_VERIFIED" if (ext_res and ext_res.get("technical_source_valid")) else "TECHNICAL_FAILED"
        ),
        "legal_attestation_status": "ATTESTATION_REJECTED_OR_MISSING",
        "production_use_authorized": False,
        "qualified_e_signature_5070_equivalent": False,
        "coverage_start_year": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["coverage_start_year"],
        "coverage_end_year": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["coverage_end_year"],
        "official_source_url": None,
        "source_document_sha256": None,
        "snapshot_path": None,
        "calendar_version": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["calendar_version"],
        "verified_at": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["verified_at"],
        "verified_by": None,
        "validation_errors": ext_res["errors"] if ext_res else [],
    }


def get_turkish_ubgt_holidays(
    year: int,
    *,
    require_verified_religious_calendar: bool = False,
    external_verified_calendars: dict[int | str, Any] | None = None,
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_signed_ledger_checkpoint: bool = True,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    prevalidated_external_calendars: dict[int, dict[str, Any]] | None = None,
) -> dict[date, str]:
    """Return full-day statutory Turkish UBGT holidays (2429 s. Kanun) for a given calendar year.

    IMPORTANT: Verified religious holidays (Ramazan & Kurban Bayramı) are populated from the built-in
    archived Diyanet table (2024–2027) OR from a cryptographically attested per-year entry in
    `external_verified_calendars`. When `require_verified_religious_calendar=True`, requesting an
    uncovered/unverified year raises ValueError with `HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE`.
    """
    if prevalidated_external_calendars is not None:
        valid_ext = prevalidated_external_calendars
        all_ext = prevalidated_external_calendars
    else:
        valid_ext, all_ext = _extract_validated_external_calendars(
            external_verified_calendars,
            approvers_registry=approvers_registry,
            attestation_ledger=attestation_ledger,
            project_root=project_root,
            runtime_environment=runtime_environment,
            require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
            expected_checkpoint_head_hash=expected_checkpoint_head_hash,
            expected_checkpoint_entry_count=expected_checkpoint_entry_count,
            expected_chain_digest_sha256=expected_chain_digest_sha256,
        )
    year_covered = (year in TURKISH_RELIGIOUS_FULL_HOLIDAYS) or (year in valid_ext)

    if require_verified_religious_calendar and not year_covered:
        ext_detail = ""
        if year in all_ext and all_ext[year]["errors"]:
            ext_detail = f" Doğrulama hataları: {'; '.join(all_ext[year]['errors'])}"
        raise ValueError(
            f"HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE: {year} yılı doğrulanmış Diyanet dinî bayram takvimi "
            f"kapsamı ({TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA['coverage_start_year']}–"
            f"{TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA['coverage_end_year']}) dışındadır ve geçerli "
            f"bir imzalı yıllık harici takvim kaydı sunulmamıştır.{ext_detail}"
        )

    holidays: dict[date, str] = {
        date(year, 1, 1): "1 Ocak — Yılbaşı",
        date(year, 4, 23): "23 Nisan — Ulusal Egemenlik ve Çocuk Bayramı",
        date(year, 5, 19): "19 Mayıs — Atatürk'ü Anma, Gençlik ve Spor Bayramı",
        date(year, 8, 30): "30 Ağustos — Zafer Bayramı",
        date(year, 10, 29): "29 Ekim — Cumhuriyet Bayramı (Ulusal Bayram)",
    }
    if year >= 2009:
        holidays[date(year, 5, 1)] = "1 Mayıs — Emek ve Dayanışma Günü (5892 s. Kanun)"
    if year >= 2017:
        holidays[date(year, 7, 15)] = "15 Temmuz — Demokrasi ve Millî Birlik Günü (6752 s. Kanun)"

    def _merge_holiday(d: date, label: str) -> None:
        if d in holidays:
            if label not in holidays[d]:
                holidays[d] = f"{holidays[d]} + {label}"
        else:
            holidays[d] = label

    for (month, day), label in TURKISH_RELIGIOUS_FULL_HOLIDAYS.get(year, {}).items():
        _merge_holiday(date(year, month, day), label)

    if year not in TURKISH_RELIGIOUS_FULL_HOLIDAYS:
        for ext_res in valid_ext.values():
            for d, label in ext_res["full_holidays"].items():
                if d.year == year:
                    _merge_holiday(d, label)

    return holidays


def get_turkish_half_day_eves(
    year: int,
    *,
    require_verified_religious_calendar: bool = False,
    external_verified_calendars: dict[int | str, Any] | None = None,
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_signed_ledger_checkpoint: bool = True,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    prevalidated_external_calendars: dict[int, dict[str, Any]] | None = None,
) -> dict[date, str]:
    """Return half-day official holiday eves (13:00 sonrası tatil — 2429 s. Kanun).

    Combines fixed 28 Ekim eve with built-in archived 2024–2027 religious arife dates AND any
    cryptographically attested yearly records supplied via `external_verified_calendars`.
    """
    if prevalidated_external_calendars is not None:
        valid_ext = prevalidated_external_calendars
        all_ext = prevalidated_external_calendars
    else:
        valid_ext, all_ext = _extract_validated_external_calendars(
            external_verified_calendars,
            approvers_registry=approvers_registry,
            attestation_ledger=attestation_ledger,
            project_root=project_root,
            runtime_environment=runtime_environment,
            require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
            expected_checkpoint_head_hash=expected_checkpoint_head_hash,
            expected_checkpoint_entry_count=expected_checkpoint_entry_count,
            expected_chain_digest_sha256=expected_chain_digest_sha256,
        )
    year_covered = (year in TURKISH_RELIGIOUS_HALF_DAY_EVES) or (year in valid_ext)

    if require_verified_religious_calendar and not year_covered:
        ext_detail = ""
        if year in all_ext and all_ext[year]["errors"]:
            ext_detail = f" Doğrulama hataları: {'; '.join(all_ext[year]['errors'])}"
        raise ValueError(
            f"HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE: {year} yılı doğrulanmış Diyanet arife (yarım gün) "
            f"takvimi kapsamı ({TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA['coverage_start_year']}–"
            f"{TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA['coverage_end_year']}) dışındadır ve geçerli "
            f"bir imzalı yıllık harici takvim kaydı sunulmamıştır.{ext_detail}"
        )

    eves: dict[date, str] = {
        date(year, 10, 28): "28 Ekim — Cumhuriyet Bayramı Arifesi (13:00 sonrası yarım gün)",
    }
    for (month, day), label in TURKISH_RELIGIOUS_HALF_DAY_EVES.get(year, {}).items():
        eves[date(year, month, day)] = label

    if year not in TURKISH_RELIGIOUS_HALF_DAY_EVES:
        for ext_res in valid_ext.values():
            for d, label in ext_res["half_day_eves"].items():
                if d.year == year:
                    if d in eves and label not in eves[d]:
                        eves[d] = f"{eves[d]} + {label}"
                    else:
                        eves[d] = label
    return eves


def get_turkish_ubgt_calendar_report(
    year: int,
    *,
    external_verified_calendars: dict[int | str, Any] | None = None,
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_signed_ledger_checkpoint: bool = True,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
) -> dict[str, Any]:
    """Return full UBGT + religious holiday breakdown along with explicit coverage completeness and provenance."""
    valid_ext, _ = _extract_validated_external_calendars(
        external_verified_calendars,
        approvers_registry=approvers_registry,
        attestation_ledger=attestation_ledger,
        project_root=project_root,
        runtime_environment=runtime_environment,
        require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
        expected_checkpoint_head_hash=expected_checkpoint_head_hash,
        expected_checkpoint_entry_count=expected_checkpoint_entry_count,
        expected_chain_digest_sha256=expected_chain_digest_sha256,
    )
    cov = get_holiday_calendar_coverage_info(
        year,
        external_verified_calendars=external_verified_calendars,
        approvers_registry=approvers_registry,
        attestation_ledger=attestation_ledger,
        project_root=project_root,
        runtime_environment=runtime_environment,
        require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
        expected_checkpoint_head_hash=expected_checkpoint_head_hash,
        expected_checkpoint_entry_count=expected_checkpoint_entry_count,
        expected_chain_digest_sha256=expected_chain_digest_sha256,
    )
    all_hols = get_turkish_ubgt_holidays(
        year,
        require_verified_religious_calendar=False,
        prevalidated_external_calendars=valid_ext,
    )
    if year in TURKISH_RELIGIOUS_FULL_HOLIDAYS:
        rel_dates = {
            date(year, m, d).isoformat(): label
            for (m, d), label in sorted(TURKISH_RELIGIOUS_FULL_HOLIDAYS[year].items())
        }
    elif year in valid_ext:
        rel_dates = {
            d.isoformat(): label
            for d, label in sorted(valid_ext[year]["full_holidays"].items())
            if d.year == year
        }
    else:
        rel_dates = {}
    eves = {
        d.isoformat(): label
        for d, label in sorted(
            get_turkish_half_day_eves(
                year,
                require_verified_religious_calendar=False,
                prevalidated_external_calendars=valid_ext,
            ).items()
        )
    }
    return {
        **cov,
        "full_day_ubgt_holidays": {d.isoformat(): label for d, label in sorted(all_hols.items())},
        "religious_full_holidays": rel_dates,
        "half_day_eves": eves,
        "calendar_metadata": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA,
    }


def _is_turkish_working_day(
    day: date,
    *,
    weekly_rest_day: int | str = 6,
    legally_verified_weekly_rest_days: set[int] | list[int | str] | tuple[int | str, ...] | None = None,
    saturday_is_working_day: bool = True,
    extra_holidays: set[date] | None = None,
    exclude_half_day_eves: bool = False,
    external_verified_calendars: dict[int | str, Any] | None = None,
    prevalidated_external_calendars: dict[int, dict[str, Any]] | None = None,
    holiday_cache: dict[int, dict[date, str]] | None = None,
    eve_cache: dict[int, dict[date, str]] | None = None,
) -> tuple[bool, str | None]:
    """Determine if a date is a working day for 4857 m.26 purposes.

    Excludes ONLY legally designated weekly rest day(s) (default Sunday, 4857 m.46) and statutory UBGT holidays
    (2429 s. Kanun) + extra_holidays (and optionally half-day eves when `exclude_half_day_eves=True`).
    A 5-day workplace schedule (`saturday_is_working_day=False`) makes Saturday a contractual non-working day
    (akdi tatil), NOT a statutory weekly rest day, and therefore does NOT exclude Saturday from 4857 m.26
    working days unless Saturday is legally verified as `weekly_rest_day` or in `legally_verified_weekly_rest_days`.
    """
    _ = saturday_is_working_day  # Kept in signature for backward compatibility; contractual 5-day off does not exclude Saturday
    rest_days, _ = _resolve_weekly_rest_days(weekly_rest_day, legally_verified_weekly_rest_days)
    if day.weekday() in rest_days:
        return False, f"{INT_TO_TR_WEEKDAY[day.weekday()]} (Hukuken Belirlenen Hafta Tatili)"
    if holiday_cache is not None:
        if day.year not in holiday_cache:
            holiday_cache[day.year] = get_turkish_ubgt_holidays(
                day.year,
                external_verified_calendars=external_verified_calendars,
                prevalidated_external_calendars=prevalidated_external_calendars,
            )
        year_holidays = holiday_cache[day.year]
    else:
        year_holidays = get_turkish_ubgt_holidays(
            day.year,
            external_verified_calendars=external_verified_calendars,
            prevalidated_external_calendars=prevalidated_external_calendars,
        )
    if day in year_holidays:
        return False, year_holidays[day]
    if extra_holidays and day in extra_holidays:
        return False, "Ek Resmî / Genel Tatil Günü"
    if exclude_half_day_eves:
        if eve_cache is not None:
            if day.year not in eve_cache:
                eve_cache[day.year] = get_turkish_half_day_eves(
                    day.year,
                    external_verified_calendars=external_verified_calendars,
                    prevalidated_external_calendars=prevalidated_external_calendars,
                )
            year_eves = eve_cache[day.year]
        else:
            year_eves = get_turkish_half_day_eves(
                day.year,
                external_verified_calendars=external_verified_calendars,
                prevalidated_external_calendars=prevalidated_external_calendars,
            )
        if day in year_eves:
            return False, year_eves[day]
    return True, None


def _business_days_between(
    start_dt: date,
    end_dt: date,
    *,
    weekly_rest_day: int | str = 6,
    legally_verified_weekly_rest_days: set[int] | list[int | str] | tuple[int | str, ...] | None = None,
    saturday_is_working_day: bool = True,
    extra_holidays: set[date] | None = None,
    exclude_half_day_eves: bool = False,
    external_verified_calendars: dict[int | str, Any] | None = None,
    prevalidated_external_calendars: dict[int, dict[str, Any]] | None = None,
) -> int:
    """Count Turkish working days strictly after start_dt up to and including end_dt (excluding statutory weekly rest day(s) and UBGT holidays; 5-day contractual Saturday off is NOT excluded)."""
    if end_dt <= start_dt:
        return 0
    days = 0
    cur = start_dt
    cache: dict[int, dict[date, str]] = {}
    e_cache: dict[int, dict[date, str]] = {}
    while cur < end_dt:
        cur = date.fromordinal(cur.toordinal() + 1)
        is_work, _ = _is_turkish_working_day(
            cur,
            weekly_rest_day=weekly_rest_day,
            legally_verified_weekly_rest_days=legally_verified_weekly_rest_days,
            saturday_is_working_day=saturday_is_working_day,
            extra_holidays=extra_holidays,
            exclude_half_day_eves=exclude_half_day_eves,
            external_verified_calendars=external_verified_calendars,
            prevalidated_external_calendars=prevalidated_external_calendars,
            holiday_cache=cache,
            eve_cache=e_cache,
        )
        if is_work:
            days += 1
    return days


def add_turkish_working_days(
    start_dt: date,
    num_working_days: int,
    *,
    weekly_rest_day: int | str = 6,
    legally_verified_weekly_rest_days: set[int] | list[int | str] | tuple[int | str, ...] | None = None,
    saturday_is_working_day: bool = True,
    extra_holidays: set[date] | None = None,
    exclude_half_day_eves: bool = False,
    external_verified_calendars: dict[int | str, Any] | None = None,
    prevalidated_external_calendars: dict[int, dict[str, Any]] | None = None,
) -> date:
    """Return the exact final valid working day after adding num_working_days Turkish working days to start_dt."""
    if num_working_days <= 0:
        return start_dt
    added = 0
    cur = start_dt
    cache: dict[int, dict[date, str]] = {}
    e_cache: dict[int, dict[date, str]] = {}
    while added < num_working_days:
        cur = date.fromordinal(cur.toordinal() + 1)
        is_work, _ = _is_turkish_working_day(
            cur,
            weekly_rest_day=weekly_rest_day,
            legally_verified_weekly_rest_days=legally_verified_weekly_rest_days,
            saturday_is_working_day=saturday_is_working_day,
            extra_holidays=extra_holidays,
            exclude_half_day_eves=exclude_half_day_eves,
            external_verified_calendars=external_verified_calendars,
            prevalidated_external_calendars=prevalidated_external_calendars,
            holiday_cache=cache,
            eve_cache=e_cache,
        )
        if is_work:
            added += 1
    return cur


def _add_one_calendar_year(start_dt: date) -> date:
    """Add exactly 1 calendar year per TBK m.92/1-3 (Feb 29 -> Feb 28 in non-leap year)."""
    target_year = start_dt.year + 1
    try:
        return date(target_year, start_dt.month, start_dt.day)
    except ValueError:
        return date(target_year, 2, 28)


def evaluate_m26_forfeiture_deadlines(
    discovery_date_s: Any,
    act_date_s: Any,
    action_date_s: Any,
    *,
    discovering_authority_status: str = "UNKNOWN",
    employee_gained_material_benefit: bool | None = None,
    saturday_is_working_day: bool = True,
    weekly_rest_day: int | str = 6,
    legally_verified_weekly_rest_days: set[int] | list[int | str] | tuple[int | str, ...] | None = None,
    additional_public_holidays: list[str] | None = None,
    religious_calendar_externally_verified: bool = False,
    external_verified_holiday_calendars: dict[int | str, Any] | None = None,
    half_day_eve_legal_rule: str = "UNVERIFIED_REQUIRE_LEGAL_REVIEW",
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_signed_ledger_checkpoint: bool = True,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    external_trust_anchor_provider: Any | None = None,
    expected_app_project_id: str | None = None,
) -> dict[str, Any]:
    """Deterministically evaluate 4857 m.26 dual forfeiture deadlines with two-stage cryptographic holiday calendar attestation and half-day arife legal review gating."""
    auth_status = str(discovering_authority_status or "UNKNOWN").upper().strip()
    if auth_status not in VALID_DISCOVERING_AUTHORITY_STATUSES:
        auth_status = "UNKNOWN"

    raw_half_day_rule = str(half_day_eve_legal_rule or "UNVERIFIED_REQUIRE_LEGAL_REVIEW").upper().strip()
    invalid_half_day_rule = raw_half_day_rule not in VALID_HALF_DAY_EVE_LEGAL_RULES
    norm_half_day_rule = raw_half_day_rule if not invalid_half_day_rule else "UNVERIFIED_REQUIRE_LEGAL_REVIEW"

    rest_days, invalid_rest_days = _resolve_weekly_rest_days(weekly_rest_day, legally_verified_weekly_rest_days)
    rest_day_names = [INT_TO_WEEKDAY_NAME[d] for d in sorted(rest_days)]

    extra_holiday_dates: set[date] = set()
    invalid_extra_holidays: list[str] = []
    if isinstance(additional_public_holidays, list):
        for raw_d in additional_public_holidays:
            parsed = parse_iso_date(str(raw_d))
            if parsed is not None:
                extra_holiday_dates.add(parsed)
            else:
                invalid_extra_holidays.append(str(raw_d))

    valid_ext_cals, all_ext_cal_results = _extract_validated_external_calendars(
        external_verified_holiday_calendars,
        approvers_registry=approvers_registry,
        attestation_ledger=attestation_ledger,
        project_root=project_root,
        runtime_environment=runtime_environment,
        require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
        expected_checkpoint_head_hash=expected_checkpoint_head_hash,
        expected_checkpoint_entry_count=expected_checkpoint_entry_count,
        expected_chain_digest_sha256=expected_chain_digest_sha256,
        external_trust_anchor_provider=external_trust_anchor_provider,
        expected_app_project_id=expected_app_project_id,
    )
    trusted_prevalidated_ext: dict[int, dict[str, Any]] = (
        valid_ext_cals if (religious_calendar_externally_verified is True and valid_ext_cals) else {}
    )

    disc_dt = parse_iso_date(str(discovery_date_s)) if discovery_date_s else None
    act_dt = parse_iso_date(str(act_date_s)) if act_date_s else None
    action_dt = parse_iso_date(str(action_date_s)) if action_date_s else None

    missing_items: list[MissingInfoItem] = []
    risks: list[RiskItem] = []
    requires_escalation = False

    if not discovery_date_s or disc_dt is None:
        requires_escalation = True
        missing_items.append(
            MissingInfoItem(
                "discovery_date",
                "4857 m.26 kapsamındaki 6 iş günlük hak düşürücü sürenin hesabı için feshe yetkili makamın olayı öğrenme tarihi (YYYY-MM-DD) zorunludur.",
                "Yetkili makam/disiplin kurulu olay öğrenme tutanağı veya teftiş raporu",
            )
        )
    if not act_date_s or act_dt is None:
        requires_escalation = True
        missing_items.append(
            MissingInfoItem(
                "act_date",
                "4857 m.26/1 kapsamındaki fiil tarihinden itibaren 1 yıllık üst hak düşürücü sürenin ayrı doğrulanması için fiil tarihi (YYYY-MM-DD) zorunludur.",
                "Olayın gerçekleşme tarihini belgeleyen tutanak, log veya denetim kaydı",
            )
        )
    if not action_date_s or action_dt is None:
        requires_escalation = True
        missing_items.append(
            MissingInfoItem(
                "planned_termination_date",
                "4857 m.26 süre hesabı için planlanan/gerçekleşen fesih bildirimi tarihi (YYYY-MM-DD) gereklidir.",
                "Tarihli fesih bildirimi / noter-KEP tevdi belgesi",
            )
        )

    if auth_status != "AUTHORIZED_DISMISSAL_BODY":
        requires_escalation = True
        missing_items.append(
            MissingInfoItem(
                "discovering_authority_status",
                (
                    f"Olayı öğrenen makamın feshe yetkili organ olduğu teyit edilmemiştir "
                    f"(durum='{auth_status}'). Yargıtay yerleşik uygulamasına göre 6 iş günü feshe yetkili makamın "
                    f"(yönetim/disiplin kurulu veya yetkili işveren vekili) öğrenmesiyle başlar."
                ),
                "İmza sirküleri / disiplin yönetmeliği yetki tablosu ve yetkili organ öğrenme tutanağı",
            )
        )
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="M26_SURE_VEYA_OGRENME_MAKAMI_BELIRSIZLIGI",
                description=(
                    f"4857 m.26 kapsamında öğrenme makamının fesih yetkisi doğrulanmadığı ('{auth_status}') için "
                    f"6 iş günlük sürenin başlangıç tarihi kesinleştirilememektedir; otomatik olumlu sonuç üretilemez."
                ),
                legal_consequence="Yetkili makamın olayı daha erken öğrendiği ispatlanırsa haklı fesih hakkı düşmüş sayılır; hukuk müşaviri incelemesi zorunludur.",
            )
        )
    elif missing_items:
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="M26_SURE_VEYA_OGRENME_MAKAMI_BELIRSIZLIGI",
                description="4857 m.26 süre denetimi için öğrenme tarihi, fiil tarihi veya fesih tarihinden en az biri eksik/geçersiz olduğundan otomatik onay verilemez.",
                legal_consequence="Eksik tarihle yapılan m.25/II fesihlerinde hak düşürücü süre aşımı riski nedeniyle hukuk müşaviri onayı zorunludur.",
            )
        )

    if invalid_rest_days:
        requires_escalation = True
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="M26_GECERSIZ_HAFTA_TATILI_TANIMI",
                description=f"weekly_rest_day / legally_verified_weekly_rest_days içinde geçersiz hafta tatili değeri bulundu: {invalid_rest_days}.",
                legal_consequence="Hukuken belirlenen hafta tatili günü netleştirilmeden 6 iş günü hesabı kesinleştirilemez; hukuk müşaviri teyidi gerekir.",
            )
        )
    elif len(rest_days) >= 3:
        requires_escalation = True
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="M26_OLAGANDISI_HAFTA_TATILI_GUN_SAYISI",
                description=f"Hukuken belirlenen hafta tatili gün sayısı ({len(rest_days)}: {rest_day_names}) olağandışıdır; TİS/sözleşme dayanağı teyit edilmelidir.",
                legal_consequence="4857 m.46 kapsamındaki hafta tatili dışında kalan çalışılmayan günler (akdi tatil) m.26 hesabında iş günü sayılır.",
            )
        )

    if invalid_extra_holidays:
        requires_escalation = True
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="M26_GECERSIZ_TATIL_TARIHI",
                description=f"additional_public_holidays içinde geçersiz tarih(ler) bulundu: {invalid_extra_holidays}.",
                legal_consequence="Tatillerin doğru dışlanamaması 6 iş günü hesabını bozabilir.",
            )
        )

    if invalid_half_day_rule:
        requires_escalation = True
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="M26_GECERSIZ_YARIM_GUN_KURALI",
                description=(
                    f"half_day_eve_legal_rule için geçersiz değer verildi: '{raw_half_day_rule}'. "
                    f"Geçerli değerler: {sorted(VALID_HALF_DAY_EVE_LEGAL_RULES)}."
                ),
                legal_consequence="Yarım gün tatil kuralı doğrulanmadan 6 iş günü hesabı kesinleştirilemez; hukuk müşaviri incelemesi gerekir.",
            )
        )

    # Chronological consistency checks
    chronology_error = False
    if act_dt and disc_dt and act_dt > disc_dt:
        chronology_error = True
    if disc_dt and action_dt and action_dt < disc_dt:
        chronology_error = True
    if act_dt and action_dt and action_dt < act_dt:
        chronology_error = True
    if chronology_error:
        requires_escalation = True
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="M26_TARIH_KRONOLOJI_CELISKISI",
                description=(
                    f"4857 m.26 tarihleri arasında kronolojik çelişki var: "
                    f"fiil={act_dt}, öğrenme={disc_dt}, fesih={action_dt} (fiil <= öğrenme <= fesih olmalıdır)."
                ),
                legal_consequence="Kronolojik çelişki giderilmeden hak düşürücü süre hesabı güvenilir kabul edilemez; hukuk müşaviri teyidi gerekir.",
            )
        )

    # Track A: 6 working days from discovery_date
    # Rules:
    #   1) Statutory weekly rest day(s) & UBGT holidays excluded; 5-day contractual off Saturday is STILL counted!
    #   2) Uncovered religious holiday calendar years (outside 2024-2027) are NEVER unlocked by synthetic/unsigned
    #      JSON or arbitrary verified_by names. Every uncovered year MUST independently pass Stage 1 (real archived
    #      source snapshot SHA-256 + strict 9-slot Turkish parser + OCR gate) AND Stage 2 (authorized approver
    #      identity/temporal/scope/revocation/environment + Ed25519/RSA-PSS-SHA256 signature over RFC 8785 canonical
    #      JSON with record_id & nonce + untampered hash-chained attestation ledger with signed checkpoint)!
    #   3) Half-day official eves (28 Ekim & Ramazan/Kurban Bayramı arifesi 13:00 sonrası — both built-in AND
    #      externally verified years) NEVER produce an assumed result unless half_day_eve_legal_rule is
    #      explicitly confirmed by legal review!
    working_days_elapsed: int | None = None
    six_day_deadline: date | None = None
    six_day_status = "UNVERIFIED_MISSING_OR_INVALID_DATE"
    excluded_holidays_in_window: list[dict[str, str]] = []
    half_day_eves_in_window: list[dict[str, str]] = []
    active_half_day_eves_in_window: list[dict[str, str]] = []
    contractual_non_working_saturdays_counted: list[str] = []
    religious_calendar_unverified = False
    holiday_calendar_coverage_complete = False
    holiday_calendar_coverage_status = "UNVERIFIED_MISSING_OR_INVALID_DATE"
    technical_source_verification_status = "UNVERIFIED_MISSING_OR_INVALID_DATE"
    legal_attestation_status = "UNVERIFIED_MISSING_OR_INVALID_DATE"
    calendar_production_use_authorized = False
    uncovered_calendar_years: list[int] = []
    externally_verified_calendar_years: list[int] = []
    unverified_calendar_years: list[int] = []
    external_calendar_validation_errors: dict[str, list[str]] = {}
    external_calendar_error_codes: dict[str, list[str]] = {}
    externally_verified_calendar_provenance: dict[str, dict[str, Any]] = {}
    calendar_blocker_codes: list[str] = []
    provisional_days_no_religious: int | None = None
    provisional_deadline_no_religious: str | None = None
    half_day_eve_assessment: dict[str, Any] = {
        "half_day_eve_legal_rule": norm_half_day_rule,
        "arife_dates_verified": False,
        "active_half_day_eves": [],
        "requires_legal_review": False,
        "outcome_differs_by_half_day_rule": False,
        "deadline_if_counted_as_working_day": None,
        "deadline_if_excluded_as_non_working_day": None,
        "days_elapsed_if_counted_as_working_day": None,
        "days_elapsed_if_excluded_as_non_working_day": None,
    }

    if 5 in rest_days:
        saturday_m26_counting_rule = "EXCLUDED_AS_LEGALLY_VERIFIED_WEEKLY_REST_DAY"
    elif not saturday_is_working_day:
        saturday_m26_counting_rule = "COUNTED_AS_WORKING_DAY_CONTRACTUAL_OFF_NOT_STATUTORY_WEEKLY_REST"
    else:
        saturday_m26_counting_rule = "COUNTED_AS_WORKING_DAY_STANDARD"

    if disc_dt and action_dt and not chronology_error:
        deadline_counting_eves = add_turkish_working_days(
            disc_dt,
            6,
            weekly_rest_day=weekly_rest_day,
            legally_verified_weekly_rest_days=legally_verified_weekly_rest_days,
            saturday_is_working_day=saturday_is_working_day,
            extra_holidays=extra_holiday_dates or None,
            exclude_half_day_eves=False,
            prevalidated_external_calendars=trusted_prevalidated_ext,
        )
        days_counting_eves = _business_days_between(
            disc_dt,
            action_dt,
            weekly_rest_day=weekly_rest_day,
            legally_verified_weekly_rest_days=legally_verified_weekly_rest_days,
            saturday_is_working_day=saturday_is_working_day,
            extra_holidays=extra_holiday_dates or None,
            exclude_half_day_eves=False,
            prevalidated_external_calendars=trusted_prevalidated_ext,
        )
        deadline_excluding_eves = add_turkish_working_days(
            disc_dt,
            6,
            weekly_rest_day=weekly_rest_day,
            legally_verified_weekly_rest_days=legally_verified_weekly_rest_days,
            saturday_is_working_day=saturday_is_working_day,
            extra_holidays=extra_holiday_dates or None,
            exclude_half_day_eves=True,
            prevalidated_external_calendars=trusted_prevalidated_ext,
        )
        days_excluding_eves = _business_days_between(
            disc_dt,
            action_dt,
            weekly_rest_day=weekly_rest_day,
            legally_verified_weekly_rest_days=legally_verified_weekly_rest_days,
            saturday_is_working_day=saturday_is_working_day,
            extra_holidays=extra_holiday_dates or None,
            exclude_half_day_eves=True,
            prevalidated_external_calendars=trusted_prevalidated_ext,
        )

        scan_end = max(action_dt, deadline_excluding_eves)
        cur = disc_dt
        hol_cache: dict[int, dict[date, str]] = {}
        eve_cache: dict[int, dict[date, str]] = {}
        years_scanned: set[int] = {disc_dt.year, action_dt.year}
        while cur < scan_end:
            cur = date.fromordinal(cur.toordinal() + 1)
            years_scanned.add(cur.year)
            if cur.year not in hol_cache:
                hol_cache[cur.year] = get_turkish_ubgt_holidays(
                    cur.year,
                    prevalidated_external_calendars=trusted_prevalidated_ext,
                )
            if cur.year not in eve_cache:
                eve_cache[cur.year] = get_turkish_half_day_eves(
                    cur.year,
                    prevalidated_external_calendars=trusted_prevalidated_ext,
                )
            y_hols = hol_cache[cur.year]
            y_eves = eve_cache[cur.year]
            is_holiday = False
            if cur in y_hols:
                is_holiday = True
                excluded_holidays_in_window.append({"date": cur.isoformat(), "name": y_hols[cur]})
            elif cur in extra_holiday_dates:
                is_holiday = True
                excluded_holidays_in_window.append({"date": cur.isoformat(), "name": "Ek Resmî / Genel Tatil Günü"})
            if cur in y_eves:
                eve_item = {"date": cur.isoformat(), "name": y_eves[cur]}
                half_day_eves_in_window.append(eve_item)
                if cur.weekday() not in rest_days and not is_holiday:
                    active_half_day_eves_in_window.append(eve_item)
            if not saturday_is_working_day and cur.weekday() == 5 and 5 not in rest_days and not is_holiday:
                contractual_non_working_saturdays_counted.append(cur.isoformat())

        uncovered_calendar_years = sorted(
            y
            for y in years_scanned
            if y not in TURKISH_RELIGIOUS_FULL_HOLIDAYS or y not in TURKISH_RELIGIOUS_HALF_DAY_EVES
        )

        arife_missing_in_external = False
        for y in uncovered_calendar_years:
            if religious_calendar_externally_verified is True and y in valid_ext_cals:
                externally_verified_calendar_years.append(y)
                externally_verified_calendar_provenance[str(y)] = valid_ext_cals[y]["provenance"]
            else:
                unverified_calendar_years.append(y)
                y_errs: list[str] = []
                y_codes: list[str] = []
                if religious_calendar_externally_verified is not True:
                    y_errs.append(
                        f"{y} yılı için religious_calendar_externally_verified=True harici hukuki doğrulama onayı verilmemiştir."
                    )
                if y in all_ext_cal_results:
                    res_y = all_ext_cal_results[y]
                    y_errs.extend(res_y["errors"])
                    y_codes.extend(res_y.get("error_codes", []))
                    if not res_y["arife_dates_valid"]:
                        arife_missing_in_external = True
                else:
                    arife_missing_in_external = True
                    if isinstance(additional_public_holidays, list):
                        if len(additional_public_holidays) == 0:
                            y_errs.append(
                                f"{y} yılı için additional_public_holidays boş liste olarak verilmiştir; boş liste takvim blokajını kaldırmaz."
                            )
                        else:
                            y_errs.append(
                                f"{y} yılı için yalnızca düz additional_public_holidays listesi verilmiştir; Ramazan (3 gün + arife), Kurban (4 gün + arife), arşivlenmiş kaynak özeti ve kriptografik hukuk müşaviri imzası içeren external_verified_holiday_calendars kaydı zorunludur."
                            )
                    else:
                        y_errs.append(
                            f"{y} yılı için external_verified_holiday_calendars içinde doğrulanmış ve imzalanmış yıllık takvim kaydı (Ramazan/Kurban + arife + kaynak SHA-256 + yetkili onaylayan dijital imzası + denetim zinciri kaydı) bulunmamaktadır."
                        )
                external_calendar_validation_errors[str(y)] = y_errs
                if y_codes:
                    external_calendar_error_codes[str(y)] = sorted(set(y_codes))

        externally_verified_ok = bool(
            uncovered_calendar_years
            and religious_calendar_externally_verified is True
            and not unverified_calendar_years
            and not invalid_extra_holidays
        )

        if uncovered_calendar_years and not externally_verified_ok:
            # Gate 1: Out-of-coverage year(s) NEVER assumed complete -> HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE blocker!
            religious_calendar_unverified = True
            holiday_calendar_coverage_complete = False
            holiday_calendar_coverage_status = "INCOMPLETE_UNCOVERED_YEARS"
            technical_source_verification_status = "TECHNICAL_FAILED_OR_INCOMPLETE"
            legal_attestation_status = "ATTESTATION_REJECTED_OR_MISSING"
            calendar_production_use_authorized = False
            calendar_blocker_codes.append("HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE")
            for yr_codes in external_calendar_error_codes.values():
                for c in yr_codes:
                    if c not in calendar_blocker_codes:
                        calendar_blocker_codes.append(c)
            requires_escalation = True
            six_day_status = "BLOCKED_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE"
            working_days_elapsed = None
            six_day_deadline = None
            provisional_days_no_religious = days_counting_eves
            provisional_deadline_no_religious = deadline_counting_eves.isoformat()
            blocked_years = unverified_calendar_years or uncovered_calendar_years
            err_summary_parts = [
                f"{yr}: {' '.join(errs)}"
                for yr, errs in sorted(external_calendar_validation_errors.items())
            ]
            err_detail = f" Detay: {' | '.join(err_summary_parts)}" if err_summary_parts else ""

            half_day_eve_assessment = {
                "half_day_eve_legal_rule": "UNVERIFIED_REQUIRE_LEGAL_REVIEW",
                "arife_dates_verified": not arife_missing_in_external,
                "active_half_day_eves": active_half_day_eves_in_window,
                "requires_legal_review": True if arife_missing_in_external else bool(
                    active_half_day_eves_in_window and norm_half_day_rule == "UNVERIFIED_REQUIRE_LEGAL_REVIEW"
                ),
                "outcome_differs_by_half_day_rule": False,
                "deadline_if_counted_as_working_day": None,
                "deadline_if_excluded_as_non_working_day": None,
                "days_elapsed_if_counted_as_working_day": None,
                "days_elapsed_if_excluded_as_non_working_day": None,
            }

            missing_items.append(
                MissingInfoItem(
                    "verified_religious_holiday_calendar",
                    (
                        f"Değerlendirilen yıl(lar) ({blocked_years}) doğrulanmış resmî Diyanet dinî bayram "
                        f"takvimi kapsamı ({TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA['coverage_start_year']}–"
                        f"{TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA['coverage_end_year']}) dışındadır ve "
                        f"iki aşamalı kaynak+kriptografik doğrulama tamamlanmamıştır. Her kapsam dışı yıl için bağımsız olarak "
                        f"arşivlenmiş resmî kaynak belgesi (SHA-256 + 9 slot içerik eşleşmesi) ve yetkili hukuk müşaviri "
                        f"kriptografik imzası (Ed25519 / RSA-PSS-SHA256 + değiştirilemez denetim zinciri) zorunludur.{err_detail}"
                    ),
                    "T.C. Diyanet İşleri Başkanlığı arşivli resmî dinî günler takvimi (SHA-256) ve yetkili hukuk müşaviri imzalı onayı",
                )
            )
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE",
                    description=(
                        f"4857 m.26 süre hesabında yer alan {blocked_years} yılı/yılları için dahili ({TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA['coverage_start_year']}–"
                        f"{TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA['coverage_end_year']}) veya iki aşamalı (arşivli kaynak + imzalı hukuk onayı) "
                        f"harici dinî bayram + arife takvim doğrulaması tamamlanmadığından kesin m.26 süre sonucu üretilmemiştir.{err_detail}"
                    ),
                    legal_consequence=(
                        "Kapsam dışı yıllardaki Ramazan/Kurban Bayramı tam gün veya arife günlerinin gerçek resmî kaynak ve "
                        "kriptografik onay olmadan kabul edilmesi 6 iş günlük hak düşürücü süreyi hatalı hesaplayabilir; "
                        "hukuk müşaviri eskalasyonu zorunludur."
                    ),
                )
            )
            if "AUDIT_CHAIN_TAMPERING_DETECTED" in calendar_blocker_codes:
                risks.append(
                    RiskItem(
                        risk_level="CRITICAL",
                        category="AUDIT_CHAIN_TAMPERING_DETECTED",
                        description=(
                            f"{blocked_years} yılı harici takvim denetim zincirinde bütünlük/hash zinciri veya "
                            f"imzalı checkpoint/WORM çapa ihlali tespit edilmiştir.{err_detail}"
                        ),
                        legal_consequence=(
                            "Değiştirilmiş veya kırılmış denetim zincirine dayalı hiçbir hukuki onay kabul edilemez; "
                            "derhal bilgi güvenliği ve hukuk müşaviri incelemesi zorunludur."
                        ),
                    )
                )
            if "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT" in calendar_blocker_codes:
                risks.append(
                    RiskItem(
                        risk_level="CRITICAL",
                        category="SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT",
                        description=(
                            f"{blocked_years} yılı harici takvim kaydında proje kökü dışına çıkan dosya yolu "
                            f"(path traversal / mutlak yol / symlink kaçışı) tespit edilip engellenmiştir.{err_detail}"
                        ),
                        legal_consequence=(
                            "Proje kökü dışındaki dosyalara erişen takvim kayıtları güvenlik ihlali nedeniyle "
                            "reddedilir; derhal bilgi güvenliği ve hukuk müşaviri incelemesi zorunludur."
                        ),
                    )
                )
            # If full days were supplied for an uncovered year while arife dates were missing/invalid, also explicitly engage the arife legal review gate!
            if any(
                (y in all_ext_cal_results and all_ext_cal_results[y]["full_days_valid"] and not all_ext_cal_results[y]["arife_dates_valid"])
                for y in blocked_years
            ):
                missing_items.append(
                    MissingInfoItem(
                        "half_day_eve_legal_rule",
                        (
                            f"{blocked_years} yılı harici takvim kaydında tam gün bayram tarihleri bulunmasına karşın "
                            f"Ramazan/Kurban arife (yarım gün) tarihleri doğrulanamamıştır; arife tarihleri eksiksiz doğrulanmadan "
                            f"ve hukuk müşaviri onayı olmadan UNVERIFIED_REQUIRE_LEGAL_REVIEW kapısı geçilemez."
                        ),
                        "Doğrulanmış Ramazan/Kurban arife tarihleri ve 4857 m.26 yarım gün kuralı hukuk müşaviri onayı",
                    )
                )
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI",
                        description=(
                            f"{blocked_years} yılı harici takviminde tam gün tatiller verilmiş ancak yarım gün arife "
                            f"tarihleri doğrulanmamıştır; UNVERIFIED_REQUIRE_LEGAL_REVIEW kapısı devrededir."
                        ),
                        legal_consequence="Doğrulanmamış arife tarihleriyle m.26 süresi kesinleştirilemez; hukuk müşaviri incelemesi zorunludur.",
                    )
                )
        else:
            holiday_calendar_coverage_complete = True
            if uncovered_calendar_years:
                holiday_calendar_coverage_status = "EXTERNALLY_VERIFIED_FOR_UNCOVERED_YEAR"
                technical_source_verification_status = "TECHNICAL_VERIFIED"
                legal_attestation_status = "SIGNED_LEGAL_ATTESTATION_VERIFIED"
                calendar_production_use_authorized = all(
                    bool(valid_ext_cals[y]["production_use_authorized"]) for y in externally_verified_calendar_years
                )
            else:
                holiday_calendar_coverage_status = "VERIFIED_OFFICIAL_CALENDAR_COVERAGE"
                technical_source_verification_status = TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA[
                    "technical_verification_status"
                ]
                legal_attestation_status = TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["legal_attestation_status"]
                calendar_production_use_authorized = bool(
                    TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA["production_use_authorized"]
                )

            outcome_differs = (action_dt > deadline_counting_eves) != (action_dt > deadline_excluding_eves)
            half_day_eve_assessment = {
                "half_day_eve_legal_rule": norm_half_day_rule,
                "arife_dates_verified": True,
                "active_half_day_eves": active_half_day_eves_in_window,
                "requires_legal_review": bool(
                    active_half_day_eves_in_window and norm_half_day_rule == "UNVERIFIED_REQUIRE_LEGAL_REVIEW"
                ),
                "outcome_differs_by_half_day_rule": bool(active_half_day_eves_in_window and outcome_differs),
                "deadline_if_counted_as_working_day": deadline_counting_eves.isoformat(),
                "deadline_if_excluded_as_non_working_day": deadline_excluding_eves.isoformat(),
                "days_elapsed_if_counted_as_working_day": days_counting_eves,
                "days_elapsed_if_excluded_as_non_working_day": days_excluding_eves,
            }

            if active_half_day_eves_in_window and norm_half_day_rule == "UNVERIFIED_REQUIRE_LEGAL_REVIEW":
                # Gate 2: Half-day official eves (28 Ekim / Bayram Arifesi 13:00 sonrası) require legal review; NEVER assume!
                requires_escalation = True
                eve_labels = ", ".join(f"{e['date']} ({e['name']})" for e in active_half_day_eves_in_window)
                if action_dt > deadline_excluding_eves:
                    six_day_status = "EXCEEDED_UNDER_BOTH_HALF_DAY_INTERPRETATIONS"
                    working_days_elapsed = None
                    six_day_deadline = None
                    risks.append(
                        RiskItem(
                            risk_level="CRITICAL",
                            category="HAK_DUSURUCU_SURE_ASIMI_M26",
                            description=(
                                f"4857 m.26 kapsamındaki 6 iş günlük hak düşürücü süre, yarım gün arife ({eve_labels}) "
                                f"ister iş günü sayılsın ({deadline_counting_eves.isoformat()}, {days_counting_eves} gün) "
                                f"ister tatil olarak dışlansın ({deadline_excluding_eves.isoformat()}, {days_excluding_eves} gün) "
                                f"her iki yorumda da aşılmıştır (fesih={action_dt.isoformat()})."
                            ),
                            legal_consequence="Haklı fesih hakkı her iki hukuki yorumda da düşmüştür; kıdem/ihbar tazminatı ve işe iade riski doğar.",
                        )
                    )
                    risks.append(
                        RiskItem(
                            risk_level="MEDIUM",
                            category="M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI",
                            description=(
                                f"Pencerede yer alan yarım gün genel tatil ({eve_labels}) için m.26 iş günü kuralı "
                                f"hukuki incelemeyle doğrulanmamıştır; her iki yorumda da süre aşımı oluşmakla birlikte "
                                f"kesin gün sayısı hukuk müşavirince teyit edilmelidir."
                            ),
                            legal_consequence="Dava savunmasında kesin gün hesabının yarım gün arife uygulamasına göre netleştirilmesi gerekir.",
                        )
                    )
                else:
                    six_day_status = "PENDING_LEGAL_REVIEW_HALF_DAY_HOLIDAY_EVE"
                    working_days_elapsed = None
                    six_day_deadline = None
                    missing_items.append(
                        MissingInfoItem(
                            "half_day_eve_legal_rule",
                            (
                                f"4857 m.26 6 iş günlük süre penceresinde yarım gün genel tatil ({eve_labels}) "
                                f"bulunmaktadır. Yarım gün tatilin iş günü sayılıp sayılmayacağı (COUNT_AS_WORKING_DAY vs. "
                                f"EXCLUDE_AS_NON_WORKING_DAY) hukuki incelemeyle doğrulanmadan varsayımla sonuç üretilemez "
                                f"(iş günü sayılırsa son gün={deadline_counting_eves.isoformat()} [{days_counting_eves} gün]; "
                                f"dışlanırsa son gün={deadline_excluding_eves.isoformat()} [{days_excluding_eves} gün])."
                            ),
                            "2429 s. Kanun yarım gün arife tatillerinin 4857 m.26 hesabındaki etkisine dair hukuk müşaviri onayı",
                        )
                    )
                    risks.append(
                        RiskItem(
                            risk_level="HIGH",
                            category="M26_YARIM_GUN_TATIL_HUKUKI_INCELEME_GEREKLI",
                            description=(
                                f"4857 m.26 süre penceresinde yarım gün genel tatil ({eve_labels}) yer almakta olup "
                                f"yarım gün tatillerinin m.26 hesabındaki etkisi hukuki incelemeyle henüz doğrulanmamıştır. "
                                f"Varsayımla sonuç üretilmemiştir (sayılırsa son gün={deadline_counting_eves.isoformat()} "
                                f"[{days_counting_eves} gün], dışlanırsa son gün={deadline_excluding_eves.isoformat()} "
                                f"[{days_excluding_eves} gün], sınır sonucu farkı={'EVET' if outcome_differs else 'HAYIR'})."
                            ),
                            legal_consequence=(
                                "Yarım gün arife gününün iş günü sayılıp sayılmamasına ilişkin Yargıtay/doktrin yaklaşımı "
                                "sınır günlerinde hak düşürücü sürenin dolup dolmadığını doğrudan değiştirebilir; "
                                "hukuk müşaviri teyidi olmadan otomatik onay veya ret üretilmez."
                            ),
                        )
                    )
            else:
                # Either no active half-day eve in window, OR legal counsel explicitly confirmed half_day_eve_legal_rule
                use_excl = bool(active_half_day_eves_in_window and norm_half_day_rule == "EXCLUDE_AS_NON_WORKING_DAY")
                six_day_deadline = deadline_excluding_eves if use_excl else deadline_counting_eves
                working_days_elapsed = days_excluding_eves if use_excl else days_counting_eves

                if action_dt > six_day_deadline:
                    six_day_status = "EXCEEDED"
                    requires_escalation = True
                    risks.append(
                        RiskItem(
                            risk_level="CRITICAL",
                            category="HAK_DUSURUCU_SURE_ASIMI_M26",
                            description=(
                                f"4857 m.26 kapsamındaki 6 iş günlük hak düşürücü süre aşılmıştır "
                                f"(öğrenme={disc_dt.isoformat()}, son geçerli gün={six_day_deadline.isoformat()}, "
                                f"fesih={action_dt.isoformat()}, geçen iş günü={working_days_elapsed}, "
                                f"hafta tatili={rest_day_names}, dışlanan UBGT sayısı={len(excluded_holidays_in_window)})."
                            ),
                            legal_consequence="Haklı fesih hakkı düşmüştür; fesih haksız sayılarak kıdem/ihbar tazminatı ve işe iade riski doğar.",
                        )
                    )
                else:
                    six_day_status = (
                        "WITHIN_LIMIT"
                        if auth_status == "AUTHORIZED_DISMISSAL_BODY"
                        else "WITHIN_LIMIT_PENDING_AUTHORITY_VERIFICATION"
                    )

    # Track B: 1 calendar year upper limit from act_date + Track C: material gain exception (4857 m.26/1 son cümle)
    one_year_deadline: date | None = None
    one_year_status = "UNVERIFIED_MISSING_OR_INVALID_DATE"

    if act_dt and action_dt and not chronology_error:
        one_year_deadline = _add_one_calendar_year(act_dt)
        if action_dt <= one_year_deadline:
            one_year_status = "WITHIN_LIMIT"
        else:
            if employee_gained_material_benefit is True:
                one_year_status = "WAIVED_BY_MATERIAL_GAIN_EXCEPTION_M26_1_SON"
                risks.append(
                    RiskItem(
                        risk_level="MEDIUM",
                        category="M26_MADDI_MENFAAT_ISTISNASI_ISPAT_YUKU",
                        description=(
                            f"Fiil tarihinden ({act_dt.isoformat()}) itibaren 1 yıllık üst süre ({one_year_deadline.isoformat()}) "
                            f"aşılmıştır; 4857 m.26/1 son cümle uyarınca işçinin olayda maddi çıkar sağlaması halinde "
                            f"1 yıllık üst süre uygulanmaz (ancak 6 iş günlük öğrenme süresi aynen devam eder)."
                        ),
                        legal_consequence="İşçinin somut maddi çıkar sağladığının ispat yükü işverendedir; ispatlanamazsa 1 yıllık hak düşürücü süre aşımından fesih haksız sayılır.",
                    )
                )
            elif employee_gained_material_benefit is False:
                one_year_status = "EXCEEDED"
                requires_escalation = True
                risks.append(
                    RiskItem(
                        risk_level="CRITICAL",
                        category="BIR_YILLIK_UST_SURE_ASIMI_M26",
                        description=(
                            f"4857 m.26/1 kapsamındaki fiil tarihinden ({act_dt.isoformat()}) itibaren 1 yıllık üst "
                            f"hak düşürücü süre ({one_year_deadline.isoformat()}) aşılmıştır (fesih={action_dt.isoformat()}) "
                            f"ve işçinin maddi çıkar sağlama istisnası bulunmamaktadır."
                        ),
                        legal_consequence="6 iş günlük öğrenme süresi dolmamış olsa dahi 1 yıllık üst hak düşürücü süre nedeniyle haklı fesih hakkı düşmüştür.",
                    )
                )
            else:
                one_year_status = "EXCEEDED_MATERIAL_GAIN_EXCEPTION_UNVERIFIED"
                requires_escalation = True
                missing_items.append(
                    MissingInfoItem(
                        "employee_gained_material_benefit",
                        (
                            f"Fiil tarihinden ({act_dt.isoformat()}) itibaren 1 yıllık üst süre ({one_year_deadline.isoformat()}) "
                            f"geçmiştir. 4857 m.26/1 son cümle istisnasının uygulanabilmesi için işçinin olayda somut maddi çıkar "
                            f"sağlayıp sağlamadığı belgelenmelidir."
                        ),
                        "İç denetim / mali inceleme raporu (maddi çıkar tespiti)",
                    )
                )
                risks.append(
                    RiskItem(
                        risk_level="CRITICAL",
                        category="BIR_YILLIK_UST_SURE_ASIMI_M26",
                        description=(
                            f"Fiil tarihinden ({act_dt.isoformat()}) itibaren 1 yıllık üst süre ({one_year_deadline.isoformat()}) "
                            f"aşılmış olup maddi çıkar istisnası teyit edilmemiştir."
                        ),
                        legal_consequence="Maddi çıkar istisnası ispatlanmadıkça 4857 m.26/1 gereği haklı fesih hakkı düşmüştür; hukuk müşaviri onayı zorunludur.",
                    )
                )

    return {
        "discovery_date": disc_dt.isoformat() if disc_dt else None,
        "act_date": act_dt.isoformat() if act_dt else None,
        "action_date": action_dt.isoformat() if action_dt else None,
        "discovering_authority_status": auth_status,
        "weekly_rest_days": rest_day_names,
        "saturday_is_working_day": saturday_is_working_day,
        "saturday_m26_counting_rule": saturday_m26_counting_rule,
        "contractual_non_working_saturdays_counted": contractual_non_working_saturdays_counted,
        "working_days_since_discovery": working_days_elapsed,
        "six_working_day_deadline_date": six_day_deadline.isoformat() if six_day_deadline else None,
        "six_working_day_status": six_day_status,
        "excluded_holidays_in_window": excluded_holidays_in_window,
        "half_day_holiday_eves_in_window": half_day_eves_in_window,
        "religious_holiday_calendar_unverified": religious_calendar_unverified,
        "holiday_calendar_coverage_complete": holiday_calendar_coverage_complete,
        "holiday_calendar_coverage_status": holiday_calendar_coverage_status,
        "technical_source_verification_status": technical_source_verification_status,
        "legal_attestation_status": legal_attestation_status,
        "calendar_production_use_authorized": calendar_production_use_authorized,
        "qualified_e_signature_5070_equivalent": False,
        "signature_legal_notice": SIGNATURE_5070_NON_EQUIVALENCE_NOTICE,
        "uncovered_calendar_years": uncovered_calendar_years,
        "externally_verified_calendar_years": externally_verified_calendar_years,
        "unverified_calendar_years": unverified_calendar_years,
        "external_calendar_validation_errors": external_calendar_validation_errors,
        "external_calendar_error_codes": external_calendar_error_codes,
        "externally_verified_calendar_provenance": externally_verified_calendar_provenance,
        "calendar_blocker_codes": calendar_blocker_codes,
        "provisional_working_days_without_religious_holidays": provisional_days_no_religious,
        "provisional_deadline_without_religious_holidays": provisional_deadline_no_religious,
        "holiday_calendar_metadata": TURKISH_RELIGIOUS_HOLIDAY_CALENDAR_METADATA,
        "half_day_eve_legal_rule": norm_half_day_rule,
        "half_day_eve_assessment": half_day_eve_assessment,
        "one_year_deadline_date": one_year_deadline.isoformat() if one_year_deadline else None,
        "one_year_limit_status": one_year_status,
        "employee_gained_material_benefit": employee_gained_material_benefit,
        "chronology_error": chronology_error,
        "requires_counsel_escalation": requires_escalation,
        "_missing_items": missing_items,
        "_risks": risks,
    }


def _add_verified_basis(
    bases: list[LegalBasisItem],
    source_registry: dict[str, LegalSourceRecord],
    knowledge_cards: dict[str, LegalKnowledgeCard],
    precedent_registry: dict[str, PrecedentRecord],
    as_of_date: str,
    source_id: str,
    note: str,
    card_id: str | None = None,
    precedent_id: str | None = None,
    article_ref: str | None = None,
    historical_context: list[LegalBasisItem] | None = None,
    risks: list[RiskItem] | None = None,
    escalation_flags: list[str] | None = None,
) -> bool:
    """Route a legal basis strictly by historical effectiveness:
      - VERIFIED & effective on as_of_date -> legal_bases (effective_on_date=True)
      - Known effective window excludes as_of_date -> historical_context (effective_on_date=False), NEVER legal_bases
      - Missing/unverified source or undeterminable effective window -> escalate (YURURLUK_DURUMU_BELIRLENEMEYEN_KAYNAK), NEVER legal_bases
    """

    def _record_undetermined(reason: str) -> bool:
        if escalation_flags is not None:
            escalation_flags.append(f"UNDETERMINED_EFFECTIVENESS:{source_id}")
        if risks is not None:
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="YURURLUK_DURUMU_BELIRLENEMEYEN_KAYNAK",
                    description=f"'{source_id}' kaynağının {as_of_date} tarihindeki yürürlük durumu belirlenemedi: {reason}",
                    legal_consequence="Yürürlük durumu kesinleştirilemeyen kaynak güncel dayanak olarak sunulamaz; hukuk müşaviri incelemesi zorunludur.",
                )
            )
        return False

    t_dt = parse_iso_date(as_of_date)
    if t_dt is None:
        return _record_undetermined(f"Geçersiz tarih biçimi: '{as_of_date}'.")

    src = source_registry.get(source_id)
    if src is None:
        return _record_undetermined("Kaynak kayıt defterinde bulunamadı.")

    if src.verification_status not in {"VERIFIED", "SUPERSEDED"}:
        return _record_undetermined(
            f"Kaynak doğrulama statüsü '{src.verification_status}' (tam metin doğrulaması tamamlanmamış)."
        )

    # Resolve source/article effective window
    if article_ref:
        art_res = resolve_effective_article(src, article_ref, as_of_date)
        eff_from_s = art_res.get("effective_from")
        eff_to_s = art_res.get("effective_to")
        eff_from = parse_iso_date(str(eff_from_s)) if eff_from_s else None
        eff_to = parse_iso_date(str(eff_to_s)) if eff_to_s else None
    else:
        eff_from_s = src.effective_from
        eff_to_s = src.effective_to
        eff_from = parse_iso_date(eff_from_s)
        eff_to = parse_iso_date(eff_to_s)

    if eff_from is None or eff_to is None or eff_from > eff_to:
        return _record_undetermined(
            f"Geçersiz veya belirsiz yürürlük tarih aralığı ('{eff_from_s}' .. '{eff_to_s}')."
        )

    # Optional knowledge card effectiveness verification
    verified_card_id: str | None = None
    card_eff_from: date | None = None
    card_eff_to: date | None = None
    if card_id:
        card = knowledge_cards.get(card_id)
        if card is not None:
            if card.verification_status != "VERIFIED":
                return _record_undetermined(
                    f"Bağlı bilgi kartı '{card_id}' doğrulama statüsü '{card.verification_status}'."
                )
            ev = card.effective_validity if isinstance(card.effective_validity, dict) else {}
            if ev.get("effective_date_verified") is not True:
                return _record_undetermined(
                    f"Bağlı bilgi kartı '{card_id}' için effective_date_verified=True doğrulanmamış."
                )
            card_eff_from = parse_iso_date(str(ev.get("effective_from", "")))
            card_eff_to = parse_iso_date(str(ev.get("effective_to", "")))
            if card_eff_from is None or card_eff_to is None or card_eff_from > card_eff_to:
                return _record_undetermined(
                    f"Bağlı bilgi kartı '{card_id}' yürürlük tarih aralığı geçersiz."
                )
            verified_card_id = card.card_id

    # Effective window intersection (source/article + card if present)
    win_from = max(eff_from, card_eff_from) if card_eff_from else eff_from
    win_to = min(eff_to, card_eff_to) if card_eff_to else eff_to
    if win_from > win_to:
        return _record_undetermined(
            f"Kaynak ({eff_from.isoformat()}..{eff_to.isoformat()}) ve kart ({card_eff_from}..{card_eff_to}) yürürlük pencereleri çelişiyor."
        )

    legal_ref = f"{src.legal_reference} ({article_ref})" if article_ref else src.legal_reference

    # Optional precedent verification & historical date check
    verified_prec_id: str | None = None
    historical_prec_item: LegalBasisItem | None = None
    if precedent_id:
        prec = precedent_registry.get(precedent_id)
        if prec is not None:
            if prec.verification_status == "VERIFIED":
                prec_dt = parse_iso_date(prec.decision_date)
                if prec_dt is None:
                    return _record_undetermined(
                        f"Bağlı içtihat '{precedent_id}' karar tarihi ('{prec.decision_date}') geçersiz."
                    )
                if t_dt < prec_dt:
                    historical_prec_item = LegalBasisItem(
                        source_id=src.source_id,
                        card_id=verified_card_id,
                        precedent_id=prec.precedent_id,
                        legal_reference=f"{legal_ref} — {prec.precedent_id}",
                        verification_status=src.verification_status,
                        effective_on_date=False,
                        note=(
                            f"[TARİHSEL BAĞLAM — İçtihat karar tarihi ({prec.decision_date}) olay tarihinden ({as_of_date}) "
                            f"sonradır; geriye dönük güncel dayanak gibi sunulamaz] {note}"
                        ),
                    )
                else:
                    verified_prec_id = prec.precedent_id
            else:
                return _record_undetermined(
                    f"Bağlı içtihat '{precedent_id}' doğrulama statüsü '{prec.verification_status}'."
                )

    is_effective = src.verification_status == "VERIFIED" and (win_from <= t_dt <= win_to)
    if not is_effective:
        if historical_context is not None:
            reason_tag = (
                f"MÜLGA / SUPERSEDED ({win_from.isoformat()}..{win_to.isoformat()})"
                if src.verification_status == "SUPERSEDED"
                else f"{as_of_date} tarihinde yürürlükte değil (yürürlük penceresi: {win_from.isoformat()}..{win_to.isoformat()})"
            )
            historical_context.append(
                LegalBasisItem(
                    source_id=src.source_id,
                    card_id=verified_card_id,
                    precedent_id=verified_prec_id or (historical_prec_item.precedent_id if historical_prec_item else None),
                    legal_reference=legal_ref,
                    verification_status=src.verification_status,
                    effective_on_date=False,
                    note=f"[TARİHSEL BAĞLAM — {reason_tag}] {note}",
                )
            )
        return False

    bases.append(
        LegalBasisItem(
            source_id=src.source_id,
            card_id=verified_card_id,
            precedent_id=verified_prec_id,
            legal_reference=legal_ref,
            verification_status=src.verification_status,
            effective_on_date=True,
            note=note,
        )
    )
    if historical_prec_item is not None and historical_context is not None:
        historical_context.append(historical_prec_item)
    return True


def _finalize_evaluation(
    scenario_type: str,
    as_of_date: str,
    summary: str,
    bases: list[LegalBasisItem],
    counter_arguments: list[str],
    risks: list[RiskItem],
    missing_info: list[MissingInfoItem],
    recommended_actions: list[str],
    structured_findings: dict[str, Any],
    force_counsel_escalation: bool = False,
    allow_payroll_handoff_when_clean: bool = False,
    norm_conflict_resolution: NormConflictResolution | None = None,
    precedent_application_assessment: PrecedentApplicationAssessment | None = None,
    historical_context: list[LegalBasisItem] | None = None,
    escalation_flags: list[str] | None = None,
) -> LegalScenarioEvaluation:
    """Deterministically compute decision_badge and HumanApprovalRequirement from risks, missing info, basis effectiveness, and escalation triggers."""
    hist_list = list(historical_context or ())
    if escalation_flags:
        force_counsel_escalation = True

    if not bases:
        force_counsel_escalation = True
        if not any(r.category == "OLAY_TARIHINDE_YURURLUKTE_DAYANAK_YOK" for r in risks):
            risks.append(
                RiskItem(
                    risk_level="CRITICAL",
                    category="OLAY_TARIHINDE_YURURLUKTE_DAYANAK_YOK",
                    description=(
                        f"{as_of_date} olay tarihinde doğrulanmış ve yürürlükte olan güncel bir hukuki dayanak "
                        f"bulunamamıştır (tarihsel bağlam kaydı={len(hist_list)})."
                    ),
                    legal_consequence="Olay tarihindeki mülga/tarihsel mevzuat rejimi için hukuk müşaviri incelemesi zorunludur; otomatik onay verilemez.",
                )
            )
    elif hist_list and not any(
        r.category in {"TARIHSEL_MEVZUAT_REJIMI_INCELEME_GEREKLILIGI", "MADDE_YURURLUK_TARIHI_7036_M3"}
        for r in risks
    ):
        hist_refs = ", ".join(h.source_id for h in hist_list)
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="TARIHSEL_MEVZUAT_REJIMI_INCELEME_GEREKLILIGI",
                description=(
                    f"{as_of_date} olay tarihinde senaryoya ilişkin bazı hükümler ({hist_refs}) yürürlükte olmadığı için "
                    f"güncel dayanaklar dışına alınarak historical_context bölümüne ayrılmıştır."
                ),
                legal_consequence="Olay tarihindeki tarihsel mevzuat metni hukuk incelemesinden geçmeden otomatik bordro devri yapılmamalıdır.",
            )
        )

    if not counter_arguments:
        counter_arguments.append(
            "Somut olaya özgü yazılı belgeler, tanık beyanları ve işyeri uygulaması yargılamada karşı görüş doğurabilir."
        )
    if not risks:
        risks.append(
            RiskItem(
                risk_level="LOW",
                category="GENEL_ISPAT_RISKI",
                description="İş hukukunda belge ve yazılı ispat yükü ağırlıklı olarak işveren üzerindedir.",
                legal_consequence="Belge eksikliği halinde işçinin beyanı ve fiili çalışma olgusu esas alınabilir.",
            )
        )

    risk_levels = {r.risk_level for r in risks}
    has_critical = "CRITICAL" in risk_levels
    has_high = "HIGH" in risk_levels
    has_medium = "MEDIUM" in risk_levels
    has_missing = bool(missing_info)

    counsel_req = bool(
        force_counsel_escalation
        or has_critical
        or (norm_conflict_resolution is not None and norm_conflict_resolution.requires_counsel_escalation)
        or (precedent_application_assessment is not None and precedent_application_assessment.requires_counsel_escalation)
    )

    approval_reasons: list[str] = []
    if counsel_req:
        decision_badge = "YUKSEK_RISK_AVUKAT_ESKALASYONU"
        approval_level = "MANDATORY_LEGAL_COUNSEL_APPROVAL"
        approval_reasons.append("Yüksek dava/ceza riski, yürürlük belirsizliği veya norm/içtihat çatışması nedeniyle şirket avukatı onayı zorunludur.")
    elif has_high:
        decision_badge = "USUL_EKSIGI_DUZELTME_GEREKLI"
        approval_level = "MANDATORY_LEGAL_COUNSEL_APPROVAL"
        counsel_req = True
        approval_reasons.append("Yüksek (HIGH) hukuki/usul riski giderilmeden işlem yapılmamalıdır; hukuk müşaviri onayı gerekir.")
    elif has_missing:
        decision_badge = "EKSIK_BILGI_TAMAMLANMALI"
        approval_level = "SENIOR_HR_AND_LEGAL_REVIEW"
        approval_reasons.append(f"{len(missing_info)} adet eksik bilgi/belge tamamlanmadan nihai karar verilemez.")
    elif has_medium:
        decision_badge = "USUL_EKSIGI_DUZELTME_GEREKLI"
        approval_level = "SENIOR_HR_AND_LEGAL_REVIEW"
        approval_reasons.append("Orta (MEDIUM) düzeyde usul/ispat riski bulunduğu için İK yöneticisi ve hukuk incelemesi gerekir.")
    else:
        decision_badge = "UYGUN_ON_DEGERLENDIRME"
        approval_level = "HR_OPERATIONS_VERIFICATION"
        approval_reasons.append("Ön değerlendirme mevzuata uygundur; belgelerin özlük dosyasında doğrulanması ve insan onayı gerekir.")

    if has_missing and decision_badge != "EKSIK_BILGI_TAMAMLANMALI":
        approval_reasons.append(f"Ayrıca {len(missing_info)} adet eksik bilgi/belge teyit edilmelidir.")

    payroll_handoff_allowed = bool(
        allow_payroll_handoff_when_clean
        and decision_badge == "UYGUN_ON_DEGERLENDIRME"
        and bool(bases)
        and not counsel_req
        and not has_missing
        and not has_critical
        and not has_high
    )

    human_approval = HumanApprovalRequirement(
        required=True,  # Zero-trust governance: human review/approval is always explicit
        approval_level=approval_level,
        counsel_escalation_required=counsel_req,
        payroll_handoff_allowed=payroll_handoff_allowed,
        reasons=tuple(approval_reasons),
        external_counsel_signoff_status="PENDING_SIGNED_EXTERNAL_ATTESTATION",
    )

    return LegalScenarioEvaluation(
        scenario_type=scenario_type,
        as_of_date=as_of_date,
        decision_badge=decision_badge,
        assessment_summary=summary,
        legal_bases=tuple(bases),
        historical_context=tuple(hist_list),
        counter_arguments=tuple(counter_arguments),
        risks=tuple(risks),
        missing_information=tuple(missing_info),
        human_approval=human_approval,
        recommended_actions=tuple(recommended_actions),
        structured_findings=structured_findings,
        norm_conflict_resolution=norm_conflict_resolution,
        precedent_application_assessment=precedent_application_assessment,
        disclaimer=STANDARD_DISCLAIMER,
    )


def _eval_termination_validity(
    facts: dict[str, Any],
    as_of_date: str,
    sources: dict[str, LegalSourceRecord],
    precedents: dict[str, PrecedentRecord],
    cards: dict[str, LegalKnowledgeCard],
    *,
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_signed_ledger_checkpoint: bool = True,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    external_trust_anchor_provider: Any | None = None,
    expected_app_project_id: str | None = None,
) -> LegalScenarioEvaluation:
    bases: list[LegalBasisItem] = []
    historical: list[LegalBasisItem] = []
    eff_escalations: list[str] = []
    counters: list[str] = []
    risks: list[RiskItem] = []
    missing: list[MissingInfoItem] = []
    actions: list[str] = []
    force_esc = False
    prec_assessment: PrecedentApplicationAssessment | None = None
    m26_assessment: dict[str, Any] | None = None

    reason_type = str(facts.get("termination_reason_type", "UNKNOWN")).upper()
    total_emp = facts.get("workplace_total_employees")
    if total_emp is None:
        total_emp = facts.get("company_size")
    tenure_months = facts.get("tenure_months")
    contract_type = str(facts.get("contract_term_type", "UNKNOWN")).upper()
    written_notice = facts.get("written_notice_with_clear_reason")
    defense_status = str(facts.get("written_defense_status", "UNKNOWN")).upper()
    if defense_status == "UNKNOWN" and facts.get("defense_taken_before_termination") is not None:
        defense_status = "OBTAINED_WRITTEN" if bool(facts.get("defense_taken_before_termination")) else "NOT_TAKEN"
    cba_requires_defense = bool(facts.get("cba_requires_written_defense_for_all_terminations", False))
    last_resort_checked = facts.get("last_resort_checked")
    discovery_date_s = facts.get("discovery_date")
    act_date_s = facts.get("act_date") if facts.get("act_date") is not None else facts.get("incident_date")
    action_date_s = facts.get("planned_termination_date") or as_of_date
    is_union_rep = bool(facts.get("is_union_representative", False))

    raw_planned = facts.get("planned_termination_date")
    m109_eval_date = str(raw_planned) if (raw_planned and parse_iso_date(str(raw_planned)) is not None) else as_of_date

    raw_channel = str(facts.get("notification_channel", "UNKNOWN") or "UNKNOWN").upper().strip()
    channel_aliases = {
        "WRITTEN": "WRITTEN_HAND_OR_NOTARY",
        "WRITTEN_HAND_OR_NOTARY": "WRITTEN_HAND_OR_NOTARY",
        "NOTARY": "WRITTEN_HAND_OR_NOTARY",
        "PHYSICAL_WRITTEN": "WRITTEN_HAND_OR_NOTARY",
        "KEP": "KEP_ONLY",
        "KEP_ONLY": "KEP_ONLY",
        "ELECTRONIC_KEP": "KEP_ONLY",
        "ORAL": "ORAL_OR_DE_FACTO",
        "ORAL_OR_DE_FACTO": "ORAL_OR_DE_FACTO",
        "DE_FACTO": "ORAL_OR_DE_FACTO",
        "EMAIL": "EMAIL_OR_SMS",
        "SMS": "EMAIL_OR_SMS",
        "WHATSAPP": "EMAIL_OR_SMS",
        "EMAIL_OR_SMS": "EMAIL_OR_SMS",
        "UNKNOWN": "UNKNOWN",
    }
    notification_channel = channel_aliases.get(raw_channel, "UNKNOWN")
    non_written_channel = notification_channel in {"KEP_ONLY", "ORAL_OR_DE_FACTO", "EMAIL_OR_SMS"}
    written_form_missing_or_invalid = (written_notice is False) or non_written_channel
    kep_channel_detail = (
        " (7555 s. Kanun m.23 uyarınca KEP yalnızca işçinin yazılı kabulüyle fesih dışındaki bildirimlerde kullanılabilir; "
        "iş sözleşmesinin feshi sonucunu doğuracak bildirimler KEP üzerinden yapılamaz, her hâlde yazılı yapılır.)"
        if notification_channel == "KEP_ONLY"
        else ""
    )

    m25_reason_types = {
        "JUST_CAUSE_M25_II",
        "JUST_CAUSE_M25_I_B",
        "JUST_CAUSE_M25_I_A",
        "JUST_CAUSE_M25_III",
        "JUST_CAUSE_M25_IV",
    }
    non_job_sec_notice_types = {"NOTICE_TERMINATION_M17_NON_JOB_SECURITY", "EMPLOYER_NOTICE_M17"}

    # High-risk protected categories
    protected_flags = [
        ("is_collective_dismissal", "Toplu işçi çıkarma (4857 m.29 — 30 gün önceden İŞKUR/sendika bildirimi zorunlu)"),
        ("is_union_representative", "İşyeri sendika temsilcisi güvencesi (6356 m.24 — haklı neden ve açık-yazılı sebep geçerlilik şartı)"),
        ("alleged_union_reason", "Sendikal nedenle fesih iddiası (6356 m.25 — en az 1 yıllık ücret tutarında sendikal tazminat)"),
        ("is_pregnant_or_maternity", "Gebelik/analık izni dönemi feshi (ayrımcılık / geçersiz fesih yüksek dava riski)"),
        ("post_work_accident_termination", "İş kazası sonrası fesih (yüksek kötüniyet/geçersizlik ve rücu riski)"),
    ]

    # Resolve 4857 m.109 historical version by event/notice date (pre-2025-07-24 vs. post-2025-07-24 Law No. 7555 m.23)
    m4857_src = sources.get("MEVZUAT-4857")
    m109_7555_effective = False
    m109_pre_7555_effective = False
    if m4857_src is not None and parse_iso_date(m109_eval_date) is not None:
        m109_post_res = resolve_effective_article(m4857_src, "Madde 109", m109_eval_date)
        m109_pre_res = resolve_effective_article(m4857_src, "Madde 109 (7555 Öncesi İlk Metin)", m109_eval_date)
        m109_7555_effective = bool(m109_post_res.get("is_effective"))
        m109_pre_7555_effective = bool(m109_pre_res.get("is_effective"))

    m109_version_applied = "NOT_APPLICABLE_BILATERAL_IKALE"
    m109_written_termination_mandatory = False

    # Attach regime-appropriate verified bases (with strict historical_context routing!)
    if reason_type in {"MUTUAL_TERMINATION_IKALE"}:
        _add_verified_basis(
            bases, sources, cards, precedents, as_of_date, "MEVZUAT-6098",
            "İkale (bozma sözleşmesi) irade uyuşması ve fesih sonrası ibraname 1 ay bekleme + banka ödeme şartı (TBK m.420).",
            card_id="CARD-6098-M420", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
        )
        _add_verified_basis(
            bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
            "İkale sözleşmesinin işveren feshine dönüşmesi halinde 4857 m.18 iş güvencesi ve işe iade sonuçları.",
            card_id="CARD-4857-M18", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
        )
    else:
        if reason_type == "EMPLOYEE_RESIGNATION":
            _add_verified_basis(
                bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
                "İşçinin süreli fesih (istifa) bildirimi ve ihbar öneli (4857 m.17).",
                card_id="CARD-4857-M17", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
            )
        else:
            _add_verified_basis(
                bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
                "İş güvencesi kapsamı ve geçerli fesih rejimi (4857 m.18).",
                card_id="CARD-4857-M18", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
            )
            if reason_type in {"VALID_REASON_M18", "UNKNOWN"} or reason_type in non_job_sec_notice_types:
                _add_verified_basis(
                    bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
                    "İş güvencesi kapsamındaki geçerli fesihlerde yazılı fesih bildirimi ve savunma şartı (4857 m.19).",
                    card_id="CARD-4857-M19", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
                )
            if reason_type in non_job_sec_notice_types:
                _add_verified_basis(
                    bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
                    "Süreli fesih ve bildirim süreleri (4857 m.17).",
                    card_id="CARD-4857-M17", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
                )
            if reason_type in m25_reason_types:
                _add_verified_basis(
                    bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
                    "İşverenin haklı nedenle derhal fesih halleri (4857 m.25).",
                    card_id="CARD-4857-M25", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
                )
            if reason_type == "JUST_CAUSE_M25_II":
                _add_verified_basis(
                    bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
                    "6 iş günü (hafta tatili & UBGT hariç; 5 günlük işyerinde akdi Cumartesi dahil) / 1 yıl üst hak düşürücü süre ve maddi menfaat istisnası (4857 m.26).",
                    card_id="CARD-4857-M26", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
                )

        # Attach event-date-appropriate 4857 m.109 version (pre- vs. post-24.07.2025 Law No. 7555 m.23)
        if m109_7555_effective:
            m109_version_applied = "POST_7555_M23_MANDATORY_WRITTEN_TERMINATION_2025_07_24_ONWARDS"
            m109_written_termination_mandatory = True
            _add_verified_basis(
                bases, sources, cards, precedents, m109_eval_date, "MEVZUAT-4857",
                "7555 s. Kanun m.23 ile değişik 4857 m.109 (yürürlük 24.07.2025): İş sözleşmesinin feshi sonucunu doğuracak bildirimler her hâlde yazılı yapılır (KEP ile fesih yapılamaz).",
                article_ref="Madde 109",
                historical_context=historical, risks=risks, escalation_flags=eff_escalations,
            )
            _add_verified_basis(
                bases, sources, cards, precedents, m109_eval_date, "RG-7555-20250724",
                "7555 s. Kanun m.23 ve m.27/1-d (RG 24.07.2025 / 32965): 4857 m.109 yazılı/KEP bildirim değişikliği yayımı tarihinde yürürlüğe girmiştir.",
                article_ref="Madde 23",
                historical_context=historical, risks=risks, escalation_flags=eff_escalations,
            )
        elif m109_pre_7555_effective:
            m109_version_applied = "PRE_7555_ORIGINAL_M109_2003_06_10_TO_2025_07_23"
            m109_written_termination_mandatory = False
            _add_verified_basis(
                bases, sources, cards, precedents, m109_eval_date, "MEVZUAT-4857",
                "4857 m.109 ilk metin (10.06.2003–23.07.2025, 7555 m.23 öncesi): Kanunda öngörülen bildirimlerin yazılı ve imza karşılığı yapılması yükümlülüğü.",
                article_ref="Madde 109 (7555 Öncesi İlk Metin)",
                historical_context=historical, risks=risks, escalation_flags=eff_escalations,
            )
        else:
            m109_version_applied = "PRE_4857_NOT_EFFECTIVE"
            m109_written_termination_mandatory = False
            _add_verified_basis(
                bases, sources, cards, precedents, m109_eval_date, "MEVZUAT-4857",
                "4857 m.109 ilk metin (olay tarihinde yürürlükte değil).",
                article_ref="Madde 109 (7555 Öncesi İlk Metin)",
                historical_context=historical, risks=risks, escalation_flags=eff_escalations,
            )

    # Zero-trust missing info checks (job security threshold facts)
    if total_emp is None:
        missing.append(MissingInfoItem("workplace_total_employees", "30 işçi iş güvencesi eşiğinin tespiti için aynı işkolundaki tüm işyerleri toplam çalışan sayısı gereklidir.", "SGK aylık MUHSGK toplam çalışan listesi"))
    if tenure_months is None:
        missing.append(MissingInfoItem("tenure_months", "6 aylık kıdem (iş güvencesi) ve 1 yıllık kıdem (kıdem tazminatı) eşiği bilinmiyor.", "SGK hizmet dökümü ve işe giriş bildirgesi"))
    if contract_type not in {"INDEFINITE", "FIXED_TERM"}:
        missing.append(MissingInfoItem("contract_term_type", "Belirsiz/belirli süreli sözleşme türü iş güvencesi kapsamını belirler.", "İmzalı iş sözleşmesi"))

    job_security_applies: bool | None = None
    if total_emp is not None and tenure_months is not None and contract_type in {"INDEFINITE", "FIXED_TERM"}:
        job_security_applies = bool(int(total_emp) >= 30 and float(tenure_months) >= 6.0 and contract_type == "INDEFINITE")

    # Protected flags trigger mandatory escalation
    for flag_key, desc in protected_flags:
        if facts.get(flag_key) is True:
            force_esc = True
            if flag_key == "is_collective_dismissal":
                _add_verified_basis(
                    bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
                    "Toplu işçi çıkarma prosedürü (4857 m.29).",
                    card_id="CARD-4857-M29", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
                )
            if flag_key in {"is_union_representative", "alleged_union_reason"}:
                _add_verified_basis(
                    bases, sources, cards, precedents, as_of_date, "MEVZUAT-6356",
                    "Sendika temsilcisi ve sendikal fesih güvencesi (6356 m.24-25).",
                    card_id="CARD-6356-M24" if flag_key == "is_union_representative" else "CARD-6356-M25",
                    historical_context=historical, risks=risks, escalation_flags=eff_escalations,
                )
            risks.append(
                RiskItem(
                    risk_level="CRITICAL",
                    category="KORUMALI_FESIH_KATEGORISI",
                    description=desc,
                    legal_consequence="Fesih geçersizliği, sendikal tazminat/ayrımcılık tazminatı ve idari para cezası riski.",
                )
            )

    # 4857 m.19/1 statutory validity condition vs. 4857 m.109 (pre- vs. post-24.07.2025 Law No. 7555 m.23) strict separation
    written_notice_regime = (
        "POST_7555_M109_MANDATORY_WRITTEN_TERMINATION_OBLIGATION"
        if m109_7555_effective
        else "PRE_7555_M109_STATUTORY_WRITTEN_AND_PROOF_OBLIGATION"
    )
    m19_1_validity_applies = False

    def _emit_post_7555_m109_violation(context_prefix: str) -> None:
        nonlocal force_esc
        force_esc = True
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="M109_7555_YAZILI_FESIH_BILDIRIMI_IHLALI",
                description=(
                    f"{context_prefix} 24.07.2025 tarihinde yürürlüğe giren 7555 sayılı Kanun m.23 ile değişik "
                    f"4857 m.109 ('İş sözleşmesinin feshi sonucunu doğuracak bildirimler her hâlde yazılı yapılır') "
                    f"emredici kanuni yazılı bildirim yükümlülüğü ihlal edilmiştir{kep_channel_detail}."
                ),
                legal_consequence=(
                    "7555 m.23 sonrası kanunun açık yazılı fesih bildirimi emrine aykırılık nedeniyle feshin geçerlilik/şekil "
                    "şartına aykırılığı (doktrinde geçerlilik şartı görüşü dahil), fesih tarihi/sebebinin ve m.26 süre uyumunun "
                    "ispatlanamaması, kıdem-ihbar-işe iade riski doğar; hukuk müşaviri onayı zorunludur."
                ),
            )
        )

    if is_union_rep and reason_type not in {"MUTUAL_TERMINATION_IKALE", "EMPLOYEE_RESIGNATION"}:
        written_notice_regime = "STISK_M24_UNION_REP_WRITTEN_VALIDITY_CONDITION"
        if written_form_missing_or_invalid:
            force_esc = True
            risks.append(
                RiskItem(
                    risk_level="CRITICAL",
                    category="SENDIKA_TEMSILCISI_YAZILI_SEBEP_IHLALI_6356_M24",
                    description=f"6356 m.24 uyarınca işyeri sendika temsilcisinin sözleşmesi haklı neden ve sebebin açık-kesin yazılı bildirimi olmaksızın feshedilemez{kep_channel_detail}.",
                    legal_consequence="Fesih kesin geçersiz sayılır; temsilcilik süresince ücret ve diğer haklar ödenir.",
                )
            )
            if m109_7555_effective:
                _emit_post_7555_m109_violation("İşyeri sendika temsilcisinin feshinde 6356 m.24 geçerlilik şartına ek olarak")
        elif written_notice is None:
            missing.append(MissingInfoItem("written_notice_with_clear_reason", "6356 m.24 uyarınca işyeri sendika temsilcisinin feshinde sebebin açık ve kesin şekilde yazılı bildirimi geçerlilik şartıdır.", "Açık haklı sebep içeren yazılı fesih bildirimi"))

    elif reason_type == "VALID_REASON_M18":
        if job_security_applies is True:
            written_notice_regime = "M19_1_STATUTORY_VALIDITY_CONDITION"
            m19_1_validity_applies = True
            if written_form_missing_or_invalid:
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="SEKIL_SARTI_IHLALI_M19",
                        description=f"İş güvencesi kapsamındaki geçerli fesihte 4857 m.19/1 uyarınca yazılı bildirim ve açık-kesin sebep geçerlilik şartı ihlal edilmiştir{kep_channel_detail}.",
                        legal_consequence="Fesih m.19/1 geçerlilik şartı noksanlığından doğrudan geçersiz sayılır (işe iade riski).",
                    )
                )
                if m109_7555_effective:
                    _emit_post_7555_m109_violation("4857 m.19/1 geçerlilik şartına ek olarak")
            elif written_notice is None:
                missing.append(MissingInfoItem("written_notice_with_clear_reason", "İş güvencesi kapsamındaki geçerli fesihte 4857 m.19/1 uyarınca açık ve kesin sebep içeren yazılı bildirim geçerlilik şartıdır.", "İmzalı/tebliğli yazılı fesih bildirim taslağı"))
        elif job_security_applies is False:
            if m109_7555_effective:
                written_notice_regime = "POST_7555_M109_MANDATORY_WRITTEN_TERMINATION_OBLIGATION"
                if written_form_missing_or_invalid:
                    _emit_post_7555_m109_violation("İş güvencesi kapsamı dışında olduğundan 4857 m.19/1 geçerlilik şartı uygulanmaz; ancak")
                elif written_notice is None:
                    missing.append(
                        MissingInfoItem(
                            "written_notice_with_clear_reason",
                            "İş güvencesi dışında 4857 m.19/1 geçerlilik şartı uygulanmasa da, 24.07.2025 yürürlüklü 7555 m.23 ile değişik 4857 m.109 uyarınca fesih bildiriminin (KEP değil) her hâlde yazılı yapılması kanuni zorunluluktur.",
                            "İmza/tutanak karşılığı veya noter (7201 s. Kanun) yazılı fesih bildirimi",
                        )
                    )
            else:
                written_notice_regime = "PRE_7555_M109_STATUTORY_WRITTEN_AND_PROOF_OBLIGATION"
                if written_form_missing_or_invalid:
                    risks.append(
                        RiskItem(
                            risk_level="MEDIUM",
                            category="YAZILI_BILDIRIM_ISPAT_YUKU_M109",
                            description="İş güvencesi kapsamı dışında olduğundan 4857 m.19/1 geçerlilik şartı uygulanmaz; ancak 7555 m.23 öncesi yürürlükteki 4857 m.109 ilk metni gereği yazılı bildirim yükümlülüğüne uyulmaması fesih tarihinin ve sebebinin ispatını ağır şekilde güçleştirir.",
                            legal_consequence="7555 öncesi dönemde fesih m.19/1 nedeniyle kendiliğinden geçersiz sayılmaz; ancak kötüniyet tazminatı, ihbar öneli ve alacak davalarında ispat yükü işveren aleyhine sonuç doğurur.",
                        )
                    )
                elif written_notice is None:
                    missing.append(MissingInfoItem("written_notice_with_clear_reason", "İş güvencesi dışında 4857 m.19/1 geçerlilik şartı uygulanmasa da, 7555 öncesi 4857 m.109 yazılı bildirim yükümlülüğü ve ispat güvenliği için yazılı tebliğ teyit edilmelidir.", "Yazılı fesih bildirimi / imza karşılığı tebliğ belgesi"))
        else:
            written_notice_regime = "PENDING_JOB_SECURITY_SCOPE_CHECK"
            if written_form_missing_or_invalid:
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="YAZILI_BILDIRIM_EKSIGI_M19_VEYA_M109",
                        description="Yazılı ve açık sebepli fesih bildirimi yoktur; çalışan iş güvencesi kapsamındaysa 4857 m.19/1 geçerlilik şartı ihlali, kapsam dışındaysa olay tarihine göre 4857 m.109 yazılı bildirim yükümlülüğü ihlali doğar.",
                        legal_consequence="30 işçi/6 ay eşiği sağlanıyorsa fesih m.19/1 nedeniyle doğrudan geçersiz sayılabilir.",
                    )
                )
                if m109_7555_effective:
                    _emit_post_7555_m109_violation("İş güvencesi kapsamı henüz netleşmemiş olsa dahi")
            elif written_notice is None:
                missing.append(MissingInfoItem("written_notice_with_clear_reason", "İş güvencesi kapsamı netleşmediğinden 4857 m.19/1 (geçerlilik şartı) ve olay tarihindeki 4857 m.109 yazılı bildirim rejimi bakımından yazılı fesih bildirimi teyit edilmelidir.", "İmzalı/tebliğli yazılı fesih bildirim taslağı"))

    elif reason_type in non_job_sec_notice_types:
        if job_security_applies is True:
            written_notice_regime = "M19_1_STATUTORY_VALIDITY_CONDITION"
            m19_1_validity_applies = True
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="IS_GUVENCESI_KAPSAMINDA_M18_M19_ZORUNLULUGU",
                    description="Çalışan 4857 m.18 iş güvencesi kapsamındadır; yalnızca m.17 ihbar süresine uyularak geçerli sebep ve m.19/1 yazılı açık gerekçe olmaksızın fesih yapılamaz.",
                    legal_consequence="Geçerli sebep ve m.19 usulü bulunmadığından işe iade davasında doğrudan geçersizlik riski.",
                )
            )
            if written_form_missing_or_invalid:
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="SEKIL_SARTI_IHLALI_M19",
                        description=f"İş güvencesi kapsamındaki işçide 4857 m.19/1 yazılı ve açık-kesin sebep geçerlilik şartı eksiktir{kep_channel_detail}.",
                        legal_consequence="Fesih m.19/1 şekil şartından doğrudan geçersiz sayılır.",
                    )
                )
                if m109_7555_effective:
                    _emit_post_7555_m109_violation("4857 m.19/1 geçerlilik şartına ek olarak")
            elif written_notice is None:
                missing.append(MissingInfoItem("written_notice_with_clear_reason", "İş güvencesi kapsamındaki işçide 4857 m.19/1 uyarınca yazılı ve açık sebepli bildirim zorunludur.", "Yazılı ve açık sebepli fesih bildirimi"))
        elif job_security_applies is False:
            if m109_7555_effective:
                written_notice_regime = "POST_7555_M109_MANDATORY_WRITTEN_TERMINATION_OBLIGATION"
                if written_form_missing_or_invalid:
                    _emit_post_7555_m109_violation("İş güvencesi dışındaki 4857 m.17 süreli fesihte 4857 m.19/1 geçerlilik şartı uygulanmaz; ancak")
                elif written_notice is None:
                    missing.append(
                        MissingInfoItem(
                            "written_notice_with_clear_reason",
                            "İş güvencesi dışındaki 4857 m.17 süreli fesihte 24.07.2025 yürürlüklü 7555 m.23 ile değişik 4857 m.109 uyarınca fesih bildiriminin (KEP değil) yazılı yapılması zorunludur.",
                            "İmza/tutanak karşılığı veya noter (7201 s. Kanun) yazılı fesih/ihbar bildirimi",
                        )
                    )
            else:
                written_notice_regime = "PRE_7555_M109_STATUTORY_WRITTEN_AND_PROOF_OBLIGATION"
                if written_form_missing_or_invalid:
                    risks.append(
                        RiskItem(
                            risk_level="MEDIUM",
                            category="YAZILI_BILDIRIM_ISPAT_YUKU_M109",
                            description="İş güvencesi dışındaki m.17 süreli fesihte 4857 m.19/1 geçerlilik şartı uygulanmaz; ancak 7555 öncesi yürürlükteki 4857 m.109 yazılı bildirim yükümlülüğüne uyulmaması ihbar süresi başlangıcı ve fesih tarihi yönünden işveren aleyhine ispat sonucu doğurur.",
                            legal_consequence="7555 öncesi dönemde fesih m.19/1 uyarınca kendiliğinden geçersiz sayılmaz; fakat ihbar öneli ve fesih tarihi işveren aleyhine yorumlanarak ihbar tazminatı riski doğabilir.",
                        )
                    )
                elif written_notice is None:
                    missing.append(MissingInfoItem("written_notice_with_clear_reason", "İş güvencesi dışındaki 4857 m.17 süreli fesihte 7555 öncesi 4857 m.109 yazılı bildirim ve ihbar öneli başlangıcı ispatı için yazılı tebliğ teyit edilmelidir.", "İmza karşılığı yazılı fesih/ihbar bildirimi"))
        else:
            written_notice_regime = "PENDING_JOB_SECURITY_SCOPE_CHECK"
            if m109_7555_effective and written_form_missing_or_invalid:
                _emit_post_7555_m109_violation("İş güvencesi kapsamı henüz teyit edilmemiş olsa dahi")
            elif written_notice is None:
                missing.append(MissingInfoItem("written_notice_with_clear_reason", "İş güvencesi kapsamı teyit edilmeden yazılı bildirim durumu netleştirilmelidir.", "Yazılı fesih bildirimi"))

    elif reason_type in m25_reason_types:
        if m109_7555_effective:
            written_notice_regime = "M25_POST_7555_M109_MANDATORY_WRITTEN_TERMINATION_NOT_M19_VALIDITY"
            if written_form_missing_or_invalid:
                _emit_post_7555_m109_violation(
                    "4857 m.25 kapsamındaki haklı nedenle derhal fesihte 4857 m.19/1 geçerlilik şartı otomatik olarak uygulanmaz "
                    "(bu nedenle m.19/1 ihlali üretilmez); ancak"
                )
            elif written_notice is None:
                missing.append(
                    MissingInfoItem(
                        "written_notice_with_clear_reason",
                        "4857 m.25 haklı nedenle derhal fesihlerde 4857 m.19/1 geçerlilik şartı uygulanmamakla birlikte, 24.07.2025 yürürlüklü 7555 m.23 ile değişik 4857 m.109 uyarınca fesih bildiriminin (KEP değil) her hâlde yazılı yapılması kanuni zorunluluktur.",
                        "İmza/tutanak karşılığı veya noter (7201 s. Kanun) yazılı fesih bildirimi (4857 m.109 — KEP ile fesih yapılamaz)",
                    )
                )
        else:
            written_notice_regime = "M25_PRE_7555_M109_STATUTORY_WRITTEN_AND_PROOF_NOT_M19_VALIDITY"
            if written_form_missing_or_invalid:
                risks.append(
                    RiskItem(
                        risk_level="MEDIUM",
                        category="YAZILI_BILDIRIM_ISPAT_YUKU_M109",
                        description=(
                            "4857 m.25 kapsamındaki haklı nedenle derhal fesihlerde 4857 m.19/1 yazılılık geçerlilik şartı "
                            "otomatik olarak uygulanmaz (fesih sırf yazılı olmaması sebebiyle m.19/1 ihlali sayılmaz); "
                            "ancak 7555 m.23 öncesi yürürlükteki 4857 m.109 ilk metni gereği yazılı bildirim yükümlülüğüne "
                            "uyulmaması fesih sebebinin, tarihinin ve m.26 süre uyumunun ispatında işveren aleyhine ciddi hukuki risk doğurur."
                        ),
                        legal_consequence="7555 öncesi dönemde haklı fesih sebebinin, fesih tarihinin ve m.26 6 iş günü uyumunun ispat yükü işverendedir; yazılı bildirim yoksa yargılamada feshin haksız sayılması riski artar.",
                    )
                )
            elif written_notice is None:
                missing.append(
                    MissingInfoItem(
                        "written_notice_with_clear_reason",
                        "4857 m.25 haklı nedenle derhal fesihlerde 4857 m.19/1 geçerlilik şartı uygulanmamakla birlikte, 7555 öncesi 4857 m.109 yazılı bildirim yükümlülüğü ile fesih tarihinin/sebebinin ispatı için yazılı tebliğ durumu teyit edilmelidir.",
                        "Noter veya imza/tutanak karşılığı yazılı fesih bildirimi (4857 m.109)",
                    )
                )

    elif reason_type == "MUTUAL_TERMINATION_IKALE":
        written_notice_regime = "TBK_BILATERAL_CONTRACT_WRITTEN_PROOF_NOT_M19"
        if written_notice is None:
            missing.append(MissingInfoItem("written_notice_with_clear_reason", "İkale tek taraflı fesih olmayıp TBK kapsamında iki taraflı bozma sözleşmesidir (4857 m.19/1 değil); karşılıklı imzalı yazılı ikale metni teyit edilmelidir.", "Karşılıklı imzalı yazılı ikale sözleşmesi"))
        elif written_notice is False:
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="IKALE_YAZILI_SOZLESME_ISPAT_RISKI",
                    description="İkale 4857 m.19/1 kapsamına girmez; ancak yazılı ve karşılıklı imzalı ikale sözleşmesi bulunmadan irade uyuşması ve makul yarar ispatlanamaz.",
                    legal_consequence="Yazılı ikale sözleşmesi yoksa sona erme işveren feshine dönüşerek işe iade ve tazminat riski doğurur.",
                )
            )
    elif reason_type == "EMPLOYEE_RESIGNATION":
        if m109_7555_effective:
            written_notice_regime = "POST_7555_M109_EMPLOYEE_RESIGNATION_WRITTEN_OBLIGATION_NOT_M19"
            if written_form_missing_or_invalid:
                _emit_post_7555_m109_violation("İşçinin istifasında 4857 m.19/1 uygulanmaz; ancak")
                counters.append(
                    "Karşı görüş: 7555 m.23 ile değişik 4857 m.109 metnindeki 'iş sözleşmesinin feshi sonucunu doğuracak bildirimler her hâlde yazılı yapılır' hükmünün işçi istifalarını da kapsadığı ileri sürülebileceğinden yazılı ve ıslak imzalı istifa dilekçesi olmadan sözlü/eylemli/KEP istifa iddiası işverenin haksız feshi olarak nitelendirilebilir."
                )
            elif written_notice is None:
                missing.append(MissingInfoItem("written_notice_with_clear_reason", "İşçi istifası 4857 m.19/1 kapsamında değildir; ancak 24.07.2025 yürürlüklü 7555 m.23 ile değişik 4857 m.109 uyarınca yazılı ve imzalı istifa dilekçesi teyit edilmelidir.", "İşçinin kendi el yazısı/imzalı istifa dilekçesi"))
        else:
            written_notice_regime = "PRE_7555_M109_EMPLOYEE_RESIGNATION_PROOF_NOT_M19"
            if written_form_missing_or_invalid:
                risks.append(
                    RiskItem(
                        risk_level="MEDIUM",
                        category="ISTIFA_YAZILI_ISPAT_RISKI_M109",
                        description="İşçinin istifasında 4857 m.19/1 uygulanmaz; ancak 7555 öncesi 4857 m.109 kapsamında yazılı ve imzalı istifa dilekçesi bulunmaması istifa iradesinin kanıtlanmasını güçleştirir.",
                        legal_consequence="Sözlü istifa iddiası ispatlanamazsa sona erme işverenin haksız feshi olarak değerlendirilebilir.",
                    )
                )
            elif written_notice is None:
                missing.append(MissingInfoItem("written_notice_with_clear_reason", "İşçi istifası 4857 m.19/1 kapsamında değildir; ancak 4857 m.109 ve ispat güvenliği için işçinin imzalı istifa dilekçesi teyit edilmelidir.", "İşçinin kendi el yazısı/imzalı istifa dilekçesi"))
    else:
        written_notice_regime = "PENDING_TERMINATION_TYPE_CLASSIFICATION"
        if m109_7555_effective and written_form_missing_or_invalid:
            _emit_post_7555_m109_violation("Fesih türü henüz sınıflandırılmamış olsa dahi")
        elif written_notice is None:
            missing.append(MissingInfoItem("written_notice_with_clear_reason", "Fesih türü netleşmediğinden yazılı bildirim ve açık sebep durumu teyit edilmelidir.", "Yazılı fesih bildirimi taslağı"))

    # Defense rules, YIBBGK-2017-9-2018-10 + Employee-favorable TİS check, and 4857 m.26 forfeiture deadline engine
    if reason_type == "VALID_REASON_M18":
        if job_security_applies is not False:
            if defense_status == "UNKNOWN":
                missing.append(MissingInfoItem("written_defense_status", "4857 m.19/2 uyarınca iş güvencesi kapsamındaki davranış/verim fesihlerinde yazılı savunma alınması zorunludur.", "Tarihli ve imzalı yazılı savunma istem/cevap tutanağı"))
            elif defense_status == "NOT_TAKEN":
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="SAVUNMA_EKSIGI_M19_2",
                        description="İş güvencesi kapsamındaki belirsiz süreli sözleşmede davranış/performansa dayalı geçerli fesihte işçinin savunması alınmamış.",
                        legal_consequence="4857 m.19/2 emredici usul kuralı ihlali nedeniyle işe iade davasında doğrudan geçersizlik riski.",
                    )
                )
            if last_resort_checked is False:
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="SON_CARE_ILKESI_IHLALI",
                        description="Feshin son çare olması (ultima ratio — başka pozisyon/eğitim/iyileştirme) değerlendirilmemiş.",
                        legal_consequence="Geçerli sebep ispatlanamayarak işe iade kabul edilebilir.",
                    )
                )
            elif last_resort_checked is None:
                missing.append(MissingInfoItem("last_resort_checked", "Son çare ilkesi (boş kadro/performans gelişim planı) araştırılmalıdır.", "Performans gelişim planı ve açık pozisyon inceleme tutanağı"))
        elif cba_requires_defense and defense_status != "VERIFIED":
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="TIS_ISCI_LEHINE_SAVUNMA_GARANTISI",
                    description="İş güvencesi kapsamı dışında olunsa dahi işçi lehine TİS/sözleşme hükmü yazılı savunma zorunluluğu öngördüğü halde savunma doğrulanmamıştır.",
                    legal_consequence="Sözleşmesel/TİS usul kuralı ihlali nedeniyle fesih geçersizliği ve tazminat riski.",
                )
            )

    elif reason_type == "JUST_CAUSE_M25_I_B":
        _add_verified_basis(
            bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
            "4857 m.25/I-b sağlık feshinde kanuni savunma zorunluluğu aranmaz (YİBBGK 2797 s. Kanun m.45); ancak işçi lehine TİS/sözleşme güvencesi ayrıca denetlenir.",
            card_id="CARD-4857-M19", precedent_id="YIBBGK-2017-9-2018-10",
            historical_context=historical, risks=risks, escalation_flags=eff_escalations,
        )
        comp_cba = (
            NormReference("TİS / İş Sözleşmesi (Tüm Fesihlerde Yazılı Savunma Garantisi)", "CBA_CONTRACT_AND_HR_PROCEDURE")
            if cba_requires_defense
            else None
        )
        prec_assessment = evaluate_precedent_application(
            precedent=precedents["YIBBGK-2017-9-2018-10"],
            interpreted_source=sources["MEVZUAT-4857"],
            as_of_date=as_of_date,
            scope_match_status="IN_SCOPE",
            competing_norm=comp_cba,
            mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE",
            favors_employee_side="COMPETING_NORM" if cba_requires_defense else "NEUTRAL",
            dispute_context="4857 m.25/I-b sağlık nedeniyle derhal fesihte yazılı savunma şartı incelemesi",
        )
        if cba_requires_defense and defense_status != "VERIFIED":
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="TIS_ISCI_LEHINE_SAVUNMA_GARANTISI",
                    description="YİBBGK E. 2017/9, K. 2018/10 kanuni tabanda savunma aramasa da, işçi lehine TİS hükmü yazılı savunma zorunluluğu getirdiği için TİS geçerlidir ve savunma alınmamıştır.",
                    legal_consequence="Sözleşmesel/TİS usul kuralı ihlali nedeniyle feshin geçersizliği riski.",
                )
            )
        counters.append(
            "Karşı görüş: Sağlık kurulu raporunun kesintisiz ihbar + 6 hafta eşiğinin doğru hesaplanmadığı veya iş kazası/meslek hastalığı bağlantısı bulunduğu ileri sürülebilir; ayrıca TİS/sözleşmede işçi lehine savunma şartı varsa YİBBGK bunu bertaraf etmez."
        )

    elif reason_type == "JUST_CAUSE_M25_II":
        raw_auth = facts.get("discovering_authority_status")
        if raw_auth is None and facts.get("discovering_authority_verified") is True:
            raw_auth = "AUTHORIZED_DISMISSAL_BODY"
        elif raw_auth is None and facts.get("discovering_authority_verified") is False:
            raw_auth = "UNCERTAIN"

        raw_ext_cals = (
            facts.get("external_verified_holiday_calendars")
            if facts.get("external_verified_holiday_calendars") is not None
            else facts.get("verified_holiday_calendars")
        )
        m26_raw = evaluate_m26_forfeiture_deadlines(
            discovery_date_s=discovery_date_s,
            act_date_s=act_date_s,
            action_date_s=action_date_s,
            discovering_authority_status=str(raw_auth or "UNKNOWN"),
            employee_gained_material_benefit=facts.get("employee_gained_material_benefit"),
            saturday_is_working_day=bool(facts.get("saturday_is_working_day", True)),
            weekly_rest_day=facts.get("weekly_rest_day", 6),
            legally_verified_weekly_rest_days=facts.get("legally_verified_weekly_rest_days"),
            additional_public_holidays=facts.get("additional_public_holidays"),
            religious_calendar_externally_verified=bool(facts.get("religious_calendar_externally_verified", False)),
            external_verified_holiday_calendars=raw_ext_cals,
            half_day_eve_legal_rule=str(
                facts.get("half_day_eve_legal_rule", "UNVERIFIED_REQUIRE_LEGAL_REVIEW")
                or "UNVERIFIED_REQUIRE_LEGAL_REVIEW"
            ),
            approvers_registry=approvers_registry,
            attestation_ledger=attestation_ledger,
            project_root=project_root,
            runtime_environment=runtime_environment,
            require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
            expected_checkpoint_head_hash=expected_checkpoint_head_hash,
            expected_checkpoint_entry_count=expected_checkpoint_entry_count,
            expected_chain_digest_sha256=expected_chain_digest_sha256,
            external_trust_anchor_provider=external_trust_anchor_provider,
            expected_app_project_id=expected_app_project_id,
        )
        missing.extend(m26_raw.pop("_missing_items"))
        risks.extend(m26_raw.pop("_risks"))
        if m26_raw["requires_counsel_escalation"]:
            force_esc = True
        m26_assessment = m26_raw

        if cba_requires_defense and defense_status != "VERIFIED":
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="TIS_ISCI_LEHINE_SAVUNMA_GARANTISI",
                    description="4857 m.25/II feshinde kanuni savunma şartı bulunmasa da işçi lehine TİS/disiplin prosedürü savunma öngördüğü halde savunma alınmamıştır.",
                    legal_consequence="TİS usul kuralı ihlali nedeniyle fesih geçersizliği riski.",
                )
            )
        counters.append(
            "Karşı görüş: İşçi, feshe konu eylemin haklı fesih ağırlığında olmadığını (ölçülülük ilkesi), feshe yetkili makamın olayı daha erken öğrendiğini (6 iş günü aşımı), Cumartesi gününün akdi tatil değil TİS/sözleşme ile hukuken belirlenmiş hafta tatili olduğunu (4857 m.46), 1 yıllık üst sürenin dolduğunu veya maddi çıkar unsuru bulunmadığını ileri sürebilir."
        )

    elif reason_type == "MUTUAL_TERMINATION_IKALE":
        if facts.get("reasonable_benefit_provided") is not True:
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="IKALE_MAKUL_YARAR_EKSIGI",
                    description="İşveren teklifli ikalede kıdem+ihbar dışında ilave 'makul yarar' (ek tazminat/ücret) sağlandığı belgelenmemiş.",
                    legal_consequence="İkale sözleşmesi yargılamada geçersiz sayılıp işveren feshine dönüşebilir (işe iade riski).",
                )
            )
        counters.append(
            "Karşı görüş: İşçi ikale teklifinin işverenden geldiğini, iradesinin sakatlandığını veya makul yarar sağlanmadığını iddia ederek işe iade davası açabilir."
        )

    counters.append(
        "Karşı görüş: Belirli süreli sözleşme yapılmış olsa dahi objektif neden (4857 m.11) yoksa sözleşme baştan belirsiz süreli sayılarak iş güvencesi kapsamına girebilir; 30 işçi eşiğinde aynı işkolundaki diğer işyerleri ve alt işveren muvazaası dikkate alınabilir."
    )
    actions.extend(
        [
            (
                "24.07.2025 yürürlüklü 7555 s. Kanun m.23 ile değişik 4857 m.109 (ve iş güvencesi kapsamında 4857 m.19/1) uyarınca fesih bildirimini KEP üzerinden değil, imza/tutanak karşılığı veya noter (7201 s. Kanun) aracılığıyla yazılı tebliğ ederek özlük dosyasına ekleyin."
                if m109_7555_effective
                else "Fesih türüne ve olay tarihindeki 4857 m.19/1 veya 7555 öncesi 4857 m.109 rejimine uygun yazılı tebliğ belgesini özlük dosyasına ekleyin."
            ),
            "SGK işten ayrılış kodunu gerçek fesih sebebiyle birebir uyumlu seçin (10 günlük bildirim süresi).",
            "Kıdem/ihbar kuruş hesabı için yalnızca hukuki uygunluk onaylandıktan sonra @ÜcretBordro ajanına devredin.",
        ]
    )

    summary = (
        f"Fesih geçerliliği ön değerlendirmesi ({reason_type}): "
        f"İş güvencesi kapsamı={'EVET' if job_security_applies is True else ('HAYIR' if job_security_applies is False else 'TEYİT BEKLİYOR')}, "
        f"yazılı bildirim rejimi={written_notice_regime}, m.109 sürümü={m109_version_applied}, "
        f"tespit edilen risk={len(risks)}, eksik bilgi={len(missing)}."
    )
    return _finalize_evaluation(
        scenario_type="TERMINATION_VALIDITY",
        as_of_date=as_of_date,
        summary=summary,
        bases=bases,
        historical_context=historical,
        escalation_flags=eff_escalations,
        counter_arguments=counters,
        risks=risks,
        missing_info=missing,
        recommended_actions=actions,
        structured_findings={
            "termination_reason_type": reason_type,
            "job_security_applies": job_security_applies,
            "written_notice_regime": written_notice_regime,
            "m19_1_validity_condition_applies": m19_1_validity_applies,
            "m109_version_applied": m109_version_applied,
            "m109_7555_effective": m109_7555_effective,
            "m109_written_termination_mandatory": m109_written_termination_mandatory,
            "m109_evaluation_date": m109_eval_date,
            "notification_channel": notification_channel,
            "cba_defense_override_checked": cba_requires_defense,
            "m26_deadline_assessment": m26_assessment,
        },
        force_counsel_escalation=force_esc,
        allow_payroll_handoff_when_clean=True,
        precedent_application_assessment=prec_assessment,
    )


def _eval_reinstatement_claim(
    facts: dict[str, Any],
    as_of_date: str,
    sources: dict[str, LegalSourceRecord],
    precedents: dict[str, PrecedentRecord],
    cards: dict[str, LegalKnowledgeCard],
) -> LegalScenarioEvaluation:
    bases: list[LegalBasisItem] = []
    historical: list[LegalBasisItem] = []
    eff_escalations: list[str] = []
    counters: list[str] = []
    risks: list[RiskItem] = []
    missing: list[MissingInfoItem] = []
    actions: list[str] = []
    force_esc = False

    total_emp = facts.get("workplace_total_employees")
    tenure_months = facts.get("tenure_months")
    is_underground_miner = bool(facts.get("is_underground_miner", False))
    contract_type = str(facts.get("contract_term_type", "UNKNOWN")).upper()
    is_employer_rep = facts.get("is_employer_representative_m18_end")
    notice_date_s = facts.get("termination_notice_date") or as_of_date
    mediation_applied_s = facts.get("mediation_application_date")

    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
        "İş güvencesi şartları (30 işçi, 6 ay kıdem, yer altı maden istisnası — 4857 m.18).",
        card_id="CARD-4857-M18", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )
    m7036_eff = _add_verified_basis(
        bases, sources, cards, precedents, notice_date_s, "MEVZUAT-7036",
        "İşe iade davasında 1 aylık hak düşürücü sürede dava şartı arabuluculuk (7036 m.3 — yürürlük 01.01.2018).",
        card_id="CARD-7036-M03", article_ref="Madde 3",
        historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )

    if total_emp is None:
        missing.append(MissingInfoItem("workplace_total_employees", "30 işçi eşiği tespit edilmelidir.", "Aynı işkolundaki tüm işyerleri SGK çalışan listesi"))
    if tenure_months is None and not is_underground_miner:
        missing.append(MissingInfoItem("tenure_months", "6 ay kıdem şartı (yer altı maden işçisi hariç) teyit edilmelidir.", "SGK hizmet dökümü"))
    if contract_type not in {"INDEFINITE", "FIXED_TERM"}:
        missing.append(MissingInfoItem("contract_term_type", "Belirsiz süreli sözleşme şartı teyit edilmelidir.", "İmzalı iş sözleşmesi"))
    if is_employer_rep is None:
        missing.append(MissingInfoItem("is_employer_representative_m18_end", "4857 m.18/son işveren vekili kapsam dışılığı teyit edilmelidir.", "İmza sirküleri ve görev tanımı (işe alma/çıkarma yetkisi)"))

    eligible: bool | None = None
    if total_emp is not None and (tenure_months is not None or is_underground_miner) and contract_type in {"INDEFINITE", "FIXED_TERM"} and is_employer_rep is not None:
        tenure_ok = is_underground_miner or float(tenure_months) >= 6.0
        eligible = bool(int(total_emp) >= 30 and tenure_ok and contract_type == "INDEFINITE" and not bool(is_employer_rep))

    days_elapsed: int | None = None
    if mediation_applied_s and notice_date_s:
        n_dt = parse_iso_date(str(notice_date_s))
        m_dt = parse_iso_date(str(mediation_applied_s))
        if n_dt and m_dt:
            days_elapsed = (m_dt - n_dt).days
            if days_elapsed > 31:
                risks.append(
                    RiskItem(
                        risk_level="MEDIUM",
                        category="BIR_AYLIK_SURE_ITIRAZI",
                        description=f"Fesih tebliğinden arabuluculuk başvurusuna kadar {days_elapsed} gün geçmiş (1 aylık hak düşürücü süre aşımı savunması doğabilir).",
                        legal_consequence="Süre aşımı kanıtlanırsa dava usulden reddedilebilir; ancak tebliğ tarihi uyuşmazlığı sıklıkla yaşanır.",
                    )
                )

    if eligible is True:
        force_esc = True
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="ISE_IADE_MALI_RISK",
                description="Çalışan 4857 m.18 iş güvencesi kapsamındadır; feshin geçersizliği halinde 4 aya kadar boşta geçen süre ücreti ve 4–8 ay iş güvencesi tazminatı doğar.",
                legal_consequence="İşveren aleyhine yüksek tazminat, SGK geriye dönük prim bildirgesi ve yargılama gideri riski.",
            )
        )

    if not m7036_eff:
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="MADDE_YURURLUK_TARIHI_7036_M3",
                description=f"Fesih bildirimi tarihi ({notice_date_s}) 01.01.2018 öncesinde olduğundan 7036 m.3 dava şartı arabuluculuk o tarihte henüz yürürlükte değildir.",
                legal_consequence="Olay tarihinde yürürlükte olan eski doğrudan İş Mahkemesi dava usulü dikkate alınmalıdır.",
            )
        )

    counters.extend(
        [
            "Karşı görüş: İşveren vekili istisnası (4857 m.18/son) dar yorumlanır; yalnızca unvanın 'müdür' olması yetmez, işyerinin bütününü sevk ve idare ile işe alma/çıkarma yetkisinin fiilen birlikte bulunması aranır.",
            "Karşı görüş: Fesih bildirimi işçiye usulüne uygun tebliğ edilmemişse 1 aylık hak düşürücü sürenin başlamadığı ileri sürülebilir; grup şirketleri veya aynı işkolundaki şubeler 30 işçi hesabında birleştirilebilir.",
        ]
    )
    actions.extend(
        [
            "Arabuluculuk süreci ve dava stratejisi için dosyayı derhal şirket avukatına devredin (dava/cevap dilekçesi yazımı avukat yetkisindedir).",
            "Fesih bildirimi tebliğ belgesi, savunma tutanağı, performans kayıtları ve açık kadro taramasını avukat incelemesine hazırlayın.",
        ]
    )

    summary = (
        f"İşe iade ön değerlendirmesi: İş güvencesi uygunluğu="
        f"{'UYGUN (KAPSAMDA)' if eligible is True else ('KAPSAM DIŞI' if eligible is False else 'EKSİK BİLGİ')}, "
        f"7036 m.3 zorunlu arabuluculuk yürürlükte={'EVET' if m7036_eff else 'HAYIR'}."
    )
    return _finalize_evaluation(
        scenario_type="REINSTATEMENT_CLAIM",
        as_of_date=as_of_date,
        summary=summary,
        bases=bases,
        historical_context=historical,
        escalation_flags=eff_escalations,
        counter_arguments=counters,
        risks=risks,
        missing_info=missing,
        recommended_actions=actions,
        structured_findings={
            "reinstatement_eligible": eligible,
            "mandatory_mediation_7036_m3_effective": m7036_eff,
            "days_from_notice_to_mediation": days_elapsed,
        },
        force_counsel_escalation=force_esc,
        allow_payroll_handoff_when_clean=False,
    )


def _eval_severance_and_notice(
    facts: dict[str, Any],
    as_of_date: str,
    sources: dict[str, LegalSourceRecord],
    precedents: dict[str, PrecedentRecord],
    cards: dict[str, LegalKnowledgeCard],
) -> LegalScenarioEvaluation:
    bases: list[LegalBasisItem] = []
    historical: list[LegalBasisItem] = []
    eff_escalations: list[str] = []
    counters: list[str] = []
    risks: list[RiskItem] = []
    missing: list[MissingInfoItem] = []
    actions: list[str] = []
    force_esc = False

    tenure_months = facts.get("tenure_months")
    reason_type = str(facts.get("termination_reason_type", "UNKNOWN")).upper()
    notice_given = facts.get("notice_period_worked_or_given")
    sgk_letter_verified = facts.get("sgk_retirement_letter_verified")
    has_pre_18_insurance = bool(facts.get("has_pre_18_insurance_days", False))
    first_ins_date_s = facts.get("first_insurance_registration_date")

    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "MEVZUAT-1475",
        "Kıdem tazminatı hak kazanma şartları ve 1 yıl kıdem eşiği (1475 m.14).",
        card_id="CARD-1475-M14", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )
    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
        "Bildirim (ihbar) süreleri: 2 / 4 / 6 / 8 hafta (4857 m.17).",
        card_id="CARD-4857-M17", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )

    if tenure_months is None:
        missing.append(MissingInfoItem("tenure_months", "1 yıl kıdem tazminatı şartı ve 4857 m.17 ihbar süresi kademesi (2/4/6/8 hafta) için toplam kıdem ayı gereklidir.", "SGK hizmet dökümü ve işe giriş-çıkış tarihleri"))

    notice_weeks: int | None = None
    has_one_year: bool | None = None
    if tenure_months is not None:
        tm = float(tenure_months)
        has_one_year = tm >= 12.0
        if tm < 6.0:
            notice_weeks = 2
        elif tm < 18.0:
            notice_weeks = 4
        elif tm < 36.0:
            notice_weeks = 6
        else:
            notice_weeks = 8

    severance_entitled: str = "UNDETERMINED"
    notice_entitled: str = "UNDETERMINED"

    if reason_type in {"EMPLOYER_VALID_OR_NOTICE_M17_M18"}:
        severance_entitled = "ENTITLED" if has_one_year is True else ("NOT_ENTITLED_UNDER_1_YEAR" if has_one_year is False else "UNDETERMINED")
        notice_entitled = "NOT_ENTITLED_NOTICE_WORKED" if notice_given is True else ("ENTITLED_IF_NOT_WORKED" if notice_given is False else "VERIFY_NOTICE_PERIOD")
        if notice_given is None:
            missing.append(MissingInfoItem("notice_period_worked_or_given", "İhbar süresinin fiilen kullandırılıp kullandırılmadığı teyit edilmelidir.", "İmzalı ihbar öneli tebliğ yazısı / iş arama izni kayıtları"))
    elif reason_type in {"EMPLOYER_JUST_CAUSE_M25_I_OR_III", "EMPLOYEE_JUST_CAUSE_M24", "RETIREMENT_1475_M14", "MILITARY_SERVICE", "MARRIAGE_FEMALE_1_YEAR", "DEATH"}:
        severance_entitled = "ENTITLED" if has_one_year is True else ("NOT_ENTITLED_UNDER_1_YEAR" if has_one_year is False else "UNDETERMINED")
        notice_entitled = "NOT_ENTITLED_BY_LAW"
    elif reason_type == "EMPLOYER_JUST_CAUSE_M25_II":
        severance_entitled = "NOT_ENTITLED_IF_PROVEN"
        notice_entitled = "NOT_ENTITLED_IF_PROVEN"
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="HAKLI_FESIH_ISPAT_RISKI",
                description="4857 m.25/II haklı feshi ispatlanamazsa veya 6 iş günü süresi kaçırılmışsa işveren kıdem ve ihbar tazminatına mahkûm edilebilir.",
                legal_consequence="Kıdem tazminatı (en yüksek mevduat faizi) + ihbar tazminatı + yargılama giderleri.",
            )
        )
    elif reason_type == "EMPLOYEE_RESIGNATION_WITHOUT_JUST_CAUSE":
        severance_entitled = "NOT_ENTITLED"
        notice_entitled = "EMPLOYER_MAY_CLAIM_IF_NO_NOTICE"
    elif reason_type == "MUTUAL_TERMINATION_IKALE":
        severance_entitled = "CONTRACTUAL_IKALE_PACKAGE"
        notice_entitled = "CONTRACTUAL_IKALE_PACKAGE"
        _add_verified_basis(
            bases, sources, cards, precedents, as_of_date, "MEVZUAT-6098",
            "İkale sonrası ibraname TBK m.420 (1 ay bekleme, yazılı, banka ödemesi).",
            card_id="CARD-6098-M420", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
        )
    else:
        missing.append(MissingInfoItem("termination_reason_type", "Kıdem ve ihbar hakkı fesih sebebine göre belirlenir.", "Fesih bildirim yazısı / istifa dilekçesi / SGK yazısı"))

    retirement_cohort: str | None = None
    if reason_type == "RETIREMENT_1475_M14":
        if sgk_letter_verified is not True:
            missing.append(MissingInfoItem("sgk_retirement_letter_verified", "1475 m.14/1-5 uyarınca 'Kıdem Tazminatına Esas Yazı' SGK'dan alınarak doğrulanmalıdır.", "Resmî SGK Kıdem Tazminatına Esas Yazısı"))
        if first_ins_date_s:
            f_dt = parse_iso_date(str(first_ins_date_s))
            if f_dt:
                if f_dt < date(1999, 9, 8):
                    retirement_cohort = "PRE_1999_09_08 (15 yıl sigortalılık + 3600 gün)"
                elif f_dt <= date(2008, 4, 30):
                    retirement_cohort = "1999_09_08_TO_2008_04_30 (25 yıl + 4500 gün veya 7000 gün)"
                else:
                    retirement_cohort = "POST_2008_05_01 (5510 kademeli 5400 / 7200 gün)"
        else:
            missing.append(MissingInfoItem("first_insurance_registration_date", "3 dönemli emeklilik/prim şartı ayrımı için ilk uzun vadeli (MYÖ) sigorta giriş tarihi gerekir (staj/çıraklık hariç).", "e-Devlet / SGK uzun vadeli tescil ve hizmet dökümü"))
        if has_pre_18_insurance:
            _add_verified_basis(
                bases, sources, cards, precedents, as_of_date, "MEVZUAT-5510",
                "5510 m.38/2: 18 yaş öncesi sigortalılık süresi 18 yaş ikmalinde başlar (01.04.1981 öncesi istisna saklı), ancak 18 yaş öncesi uzun vadeli (MYÖ) prim günleri toplam gün sayısına DAHİL EDİLİR.",
                card_id="CARD-1475-M14", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
            )

    counters.extend(
        [
            "Karşı görüş: İşçi istifa etmiş görünse dahi ücret/fazla mesai ödenmemesi, SGK priminin eksik bildirilmesi veya mobbing gibi 4857 m.24 haklı fesih sebeplerinin varlığını ileri sürerek kıdem tazminatı talep edebilir.",
            "Karşı görüş: İhbar süreleri (4857 m.17) nispi emredicidir; iş sözleşmesi veya TİS'te daha uzun ihbar süresi öngörülmüşse işçi lehine artırılmış süre uygulanır. Ayrıca staj/çıraklık girişleri 1475 m.14 sigortalılık başlangıcı sayılmaz.",
        ]
    )
    actions.extend(
        [
            "Hukuki hak kazanımı teyit edildikten sonra kıdem tavanı, giydirilmiş brüt ücret ve damga/gelir vergisi kuruş hesaplarını @ÜcretBordro ajanına devredin.",
            "Ödemelerin tamamını banka aracılığıyla yapın; ibraname alınacaksa TBK m.420 uyarınca fesih tarihinden en az 1 ay geçmesini bekleyin.",
        ]
    )

    summary = (
        f"Kıdem & İhbar hukuki ön değerlendirmesi ({reason_type}): "
        f"Kıdem={severance_entitled}, İhbar={notice_entitled}, "
        f"kanuni asgari ihbar süresi={f'{notice_weeks} hafta' if notice_weeks else 'belirlenemedi'}."
    )
    return _finalize_evaluation(
        scenario_type="SEVERANCE_AND_NOTICE",
        as_of_date=as_of_date,
        summary=summary,
        bases=bases,
        historical_context=historical,
        escalation_flags=eff_escalations,
        counter_arguments=counters,
        risks=risks,
        missing_info=missing,
        recommended_actions=actions,
        structured_findings={
            "severance_entitlement": severance_entitled,
            "notice_entitlement": notice_entitled,
            "statutory_minimum_notice_weeks": notice_weeks,
            "retirement_cohort": retirement_cohort,
            "payroll_calculation_delegated_to": "@UcretBordro",
        },
        force_counsel_escalation=force_esc,
        allow_payroll_handoff_when_clean=True,
    )


def _eval_overtime_compliance(
    facts: dict[str, Any],
    as_of_date: str,
    sources: dict[str, LegalSourceRecord],
    precedents: dict[str, PrecedentRecord],
    cards: dict[str, LegalKnowledgeCard],
) -> LegalScenarioEvaluation:
    bases: list[LegalBasisItem] = []
    historical: list[LegalBasisItem] = []
    eff_escalations: list[str] = []
    counters: list[str] = []
    risks: list[RiskItem] = []
    missing: list[MissingInfoItem] = []
    actions: list[str] = []
    force_esc = False

    annual_overtime_hours = facts.get("projected_annual_overtime_hours")
    daily_total_hours = facts.get("daily_total_hours")
    written_consent = facts.get("written_overtime_consent_in_file")
    consent_withdrawn = bool(facts.get("consent_withdrawal_notice_given", False))
    work_category = str(facts.get("work_category", "GENERAL")).upper()  # GENERAL | NIGHT_WORK_M69_EXEMPT_SECTOR | UNDERGROUND_MINING | OTHER_REG_M7_PROHIBITED
    is_m42_m43 = bool(facts.get("is_m42_m43_emergency_or_mandatory", False))
    is_prohibited_worker = bool(facts.get("is_reg_m8_prohibited_worker", False))  # <18, pregnant/nursing, part-time, health-restricted

    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
        "4857 m.41 fazla çalışma (yıllık 270 saat, %50 zamlı ücret, yer altı maden 37,5 saat/%100 özel kuralı — 6552 & 6645 değişikliği).",
        card_id="CARD-4857-M41", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )
    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "YONETMELIK-FAZLA-CALISMA-20040406",
        "Fazla Çalışma Yönetmeliği m.4/son, m.7 yasaklı işler, m.8 yasaklı çalışanlar, m.9 yazılı onay/özlük dosyası/30 gün geri alma.",
        card_id="CARD-YON-FAZLA-CALISMA", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )

    if is_prohibited_worker:
        force_esc = True
        risks.append(
            RiskItem(
                risk_level="CRITICAL",
                category="YASAKLI_CALISANA_FAZLA_CALISMA_M8",
                description="Fazla Çalışma Yönetmeliği m.8 kapsamındaki (18 yaş altı, gebe/yeni doğum/emziren, kısmi süreli veya sağlık engelli) çalışana fazla çalışma yaptırılamaz.",
                legal_consequence="4857 m.102 idari para cezası, İSG sorumluluğu ve işçiye haklı fesih imkânı.",
            )
        )

    if work_category == "UNDERGROUND_MINING":
        if not is_m42_m43:
            force_esc = True
            risks.append(
                RiskItem(
                    risk_level="CRITICAL",
                    category="YER_ALTI_MADEN_OLAGAN_FAZLA_CALISMA_YASAGI",
                    description="4857 m.41/9 uyarınca yer altında maden işlerinde olağan fazla çalışma yapılamaz; yalnızca 4857 m.42 (zorunlu) ve m.43 (olağanüstü) hallerde haftalık 37,5 saati aşan çalışma en az %100 zamlı ödenir.",
                    legal_consequence="Kanuni yasak ihlali, İPC ve ağır İSG sorumluluğu.",
                )
            )
        else:
            actions.append("4857 m.41/9-10 ve Yönetmelik m.4/son uyarınca haftalık 37,5 saati aşan zorunlu/olağanüstü çalışma için en az %100 zamlı ücret hesaplanmak üzere @ÜcretBordro'ya aktarın.")

    elif work_category == "OTHER_REG_M7_PROHIBITED":
        force_esc = True
        risks.append(
            RiskItem(
                risk_level="CRITICAL",
                category="YONETMELIK_M7_YASAKLI_IS_ESKALASYONU",
                description="Sağlık kuralları gereği günde en çok 7,5 saat çalışılan işler veya su altı gibi maden dışı Yönetmelik m.7 yasaklı işlerde genel bir 4857 m.42-43 otomatik istisnası yazılı değildir.",
                legal_consequence="Otomatik onay verilemez; fiili uygulama öncesi hukuk müşaviri incelemesi zorunludur.",
            )
        )

    elif work_category == "NIGHT_WORK_M69_EXEMPT_SECTOR":
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="GECE_CALISMASI_M69_VS_YONETMELIK_M7_AYRIMI",
                description="4857 m.69/3 yazılı onay istisnası (turizm, özel güvenlik, sağlık hizmeti, petrol) YALNIZCA gece 7,5 saat sınırına ilişkindir; Fazla Çalışma Yönetmeliği m.7 kapsamındaki fazla çalışma yasaklarını otomatik kaldırmaz.",
                legal_consequence="Gece çalışmasında 7,5 saati aşan süreler haftalık 45 saat aşılmasa bile ayrıca değerlendirilir ve m.7 yasağı ihlal edilirse İPC doğar.",
            )
        )

    # Consent checks (ordinary overtime only; m.42-43 exempt; does NOT block normal 45h work)
    if not is_m42_m43 and work_category in {"GENERAL", "NIGHT_WORK_M69_EXEMPT_SECTOR"}:
        if written_consent is None:
            missing.append(MissingInfoItem("written_overtime_consent_in_file", "4857 m.41/7 ve Yönetmelik m.9 uyarınca yazılı fazla çalışma onayının özlük dosyasında saklandığı teyit edilmelidir.", "İmzalı fazla çalışma onay belgesi (özlük dosyası)"))
        elif written_consent is False:
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="YAZILI_ONAY_EKSIGI_M41_YON_M9",
                    description="Olağan fazla çalışma için işçinin yazılı onayı alınmamış (normal 45 saatlik çalışma devam edebilir; ancak yazılı onay olmadan olağan fazla çalışma zorlanamaz).",
                    legal_consequence="İşçinin fazla çalışmaya katılmaması devamsızlık/haklı fesih sebebi yapılamaz; İPC riski doğar.",
                )
            )
        if consent_withdrawn:
            risks.append(
                RiskItem(
                    risk_level="MEDIUM",
                    category="ONAY_GERI_ALMA_30_GUN_YON_M9",
                    description="İşçi Yönetmelik m.9/2 uyarınca fazla çalışma onayını geri alma bildiriminde bulunmuş; 30 gün önceden yazılı bildirim şartının tamamlanmasıyla fazla çalışma yükümlülüğü sona erer.",
                    legal_consequence="30 gün sonunda işçiye olağan fazla çalışma yaptırılamaz.",
                )
            )

    if annual_overtime_hours is None:
        missing.append(MissingInfoItem("projected_annual_overtime_hours", "Yıllık 270 saat fazla çalışma yasal tavanının (4857 m.41/8) kontrolü gereklidir.", "Yıllık kümülatif puantaj ve fazla mesai takip cetveli"))
    elif float(annual_overtime_hours) > 270.0:
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="YILLIK_270_SAAT_TAVAN_ASIMI",
                description=f"Yıllık {annual_overtime_hours} saat fazla çalışma 4857 m.41/8 kapsamındaki mutlak emredici 270 saat tavanını aşmaktadır.",
                legal_consequence="4857 m.102 İPC riski ve işçi açısından haklı fesih sebebi doğabilir; ancak fiilen yapılan tüm fazla çalışma ücretleri eksiksiz ödenmelidir.",
            )
        )

    if daily_total_hours is not None and float(daily_total_hours) > 11.0:
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="GUNLUK_11_SAAT_TAVAN_ASIMI",
                description=f"Günlük {daily_total_hours} saat toplam çalışma, 4857 m.63 ve Çalışma Süreleri Yönetmeliği m.4 kapsamındaki 11 saat sınırını aşmaktadır.",
                legal_consequence="İSG riski, İPC ve haftalık 45 saat dolmasa dahi 11 saati aşan sürenin zamlı fazla çalışma ücreti ödenmesi yükümlülüğü.",
            )
        )

    counters.extend(
        [
            "Karşı görüş: İş sözleşmesinde 'fazla çalışma ücretin içindedir' hükmü bulunsa bile yalnızca yıllık 270 saat sınırına kadar ve işçinin ücreti asgari ücretin makul üzerinde (yüksek ücret) olduğunda geçerlidir; 270 saati aşan kısım her halde ayrıca ödenir.",
            "Karşı görüş: İşçinin yazılı onayı olmadan fiilen fazla çalışma yapması halinde onay eksikliği işvereni ücret ödeme borcundan kurtarmaz; ayrıca puantaj/PDKS kayıtları imzasızsa tanık beyanıyla fazla çalışma ispatlanabilir.",
        ]
    )
    actions.extend(
        [
            "Yazılı fazla çalışma onayını özlük dosyasında saklayın ve 30 gün önceden geri alma bildirimlerini kayıt altına alın.",
            "İşçinin talebiyle serbest zaman kullanılacaksa (1 saat fazla çalışma = 1 saat 30 dakika) 6 ay içinde yazılı taleple kullandırın.",
        ]
    )

    summary = (
        f"Fazla çalışma uygunluk değerlendirmesi (kategori={work_category}, "
        f"yıllık_saat={annual_overtime_hours if annual_overtime_hours is not None else 'BİLİNMİYOR'}): "
        f"Risk={len(risks)}, eksik bilgi={len(missing)}."
    )
    return _finalize_evaluation(
        scenario_type="OVERTIME_COMPLIANCE",
        as_of_date=as_of_date,
        summary=summary,
        bases=bases,
        historical_context=historical,
        escalation_flags=eff_escalations,
        counter_arguments=counters,
        risks=risks,
        missing_info=missing,
        recommended_actions=actions,
        structured_findings={
            "work_category": work_category,
            "is_m42_m43": is_m42_m43,
            "annual_overtime_limit_hours": 270,
            "underground_mining_weekly_threshold_hours": 37.5 if work_category == "UNDERGROUND_MINING" else None,
        },
        force_counsel_escalation=force_esc,
        allow_payroll_handoff_when_clean=True,
    )


def _eval_annual_leave_compliance(
    facts: dict[str, Any],
    as_of_date: str,
    sources: dict[str, LegalSourceRecord],
    precedents: dict[str, PrecedentRecord],
    cards: dict[str, LegalKnowledgeCard],
) -> LegalScenarioEvaluation:
    bases: list[LegalBasisItem] = []
    historical: list[LegalBasisItem] = []
    eff_escalations: list[str] = []
    counters: list[str] = []
    risks: list[RiskItem] = []
    missing: list[MissingInfoItem] = []
    actions: list[str] = []
    norm_res: NormConflictResolution | None = None

    tenure_years = facts.get("tenure_years")
    age = facts.get("employee_age")
    is_underground = bool(facts.get("is_underground_miner", False))
    contract_days = facts.get("contract_or_cba_leave_days")
    largest_split_block = facts.get("largest_split_block_days")
    pay_in_lieu_during_employment = bool(facts.get("pay_in_lieu_while_employed", False))
    signed_leave_book = facts.get("signed_leave_register_verified")

    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
        "Yıllık ücretli izin süreleri (14/20/26 gün, <=18/>=50 yaş 20 gün, yer altı +4 gün, 10 gün blok bölünme — 4857 m.53-59).",
        card_id="CARD-4857-M53", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )
    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "YONETMELIK-YILLIK-IZIN-20040303",
        "Yıllık Ücretli İzin Yönetmeliği — izin kayıt belgesi ve kullandırma usulü.",
        card_id="CARD-YON-YILLIK-IZIN", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )

    if tenure_years is None:
        missing.append(MissingInfoItem("tenure_years", "1 yıl hak kazanma eşiği ve 14/20/26 gün kademesi için kıdem yılı gereklidir.", "SGK hizmet dökümü ve işe giriş tarihi"))
    if age is None:
        missing.append(MissingInfoItem("employee_age", "18 yaş ve altı / 50 yaş ve üstü en az 20 gün kuralı (4857 m.53/5) için yaş bilgisi gereklidir.", "Kimlik / özlük doğum tarihi kaydı"))

    statutory_min_days: int | None = None
    if tenure_years is not None:
        ty = float(tenure_years)
        if ty < 1.0:
            statutory_min_days = 0
        else:
            if ty <= 5.0:
                statutory_min_days = 14
            elif ty < 15.0:
                statutory_min_days = 20
            else:
                statutory_min_days = 26
            if age is not None and (int(age) <= 18 or int(age) >= 50):
                statutory_min_days = max(statutory_min_days, 20)
            if is_underground:
                statutory_min_days += 4

    effective_leave_days = statutory_min_days
    if contract_days is not None and statutory_min_days is not None and statutory_min_days > 0:
        c_days = int(contract_days)
        law_ref = NormReference(f"4857 Sayılı İş Kanunu m.53 (Asgari {statutory_min_days} Gün)", "STATUTORY_LAW", source_id="MEVZUAT-4857")
        cba_ref = NormReference(f"TİS / İş Sözleşmesi ({c_days} Gün Yıllık İzin)", "CBA_CONTRACT_AND_HR_PROCEDURE")
        if c_days > statutory_min_days:
            norm_res = resolve_norm_conflict(law_ref, cba_ref, mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE", favors_employee_side="NORM_B")
            effective_leave_days = c_days
        elif c_days < statutory_min_days:
            norm_res = resolve_norm_conflict(law_ref, cba_ref, mandatory_type="RELATIVE_EMPLOYEE_FAVORABLE", favors_employee_side="NORM_A")
            effective_leave_days = statutory_min_days
            risks.append(
                RiskItem(
                    risk_level="HIGH",
                    category="ASGARI_YILLIK_IZIN_ALTINA_INILMESI",
                    description=f"Sözleşme/prosedürdeki {c_days} gün, 4857 m.53 nispi emredici asgari {statutory_min_days} gün tabanının altındadır ve kesin hükümsüzdür.",
                    legal_consequence="Kanuni asgari süre uygulanır; eksik kullandırma İPC ve alacak riski doğurur.",
                )
            )

    if pay_in_lieu_during_employment:
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="CALISIRKEN_IZIN_PARAYA_CEVRILME_YASAGI_M53_M59",
                description="4857 m.53/2 ve m.59 uyarınca yıllık izin hakkından vazgeçilemez ve iş sözleşmesi devam ederken izin ücreti ödenerek kullandırma yükümlülüğü ortadan kaldırılamaz.",
                legal_consequence="Yapılan ödeme dinlenme hakkını ortadan kaldırmaz; fesih anında izin alacağı ve 4857 m.103 İPC riski doğar.",
            )
        )

    if largest_split_block is not None and int(largest_split_block) < 10 and (statutory_min_days or 0) >= 14:
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="ON_GUN_BOLUNME_SARTI_IHLALI_M56",
                description=f"En uzun izin parçası {largest_split_block} gün; 4857 m.56/3 uyarınca izin bölünürken bir bölümünün en az 10 gün olması zorunludur.",
                legal_consequence="4857 m.103 kapsamında idari para cezası ve usulsüz izin kullandırma riski.",
            )
        )

    if signed_leave_book is False:
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="YILLIK_IZIN_ISPAT_YUKU_YON_M20",
                description="İmzalı yıllık izin defteri veya eşdeğer belge bulunmamaktadır.",
                legal_consequence="Yıllık iznin kullandırıldığının ispat yükü işverene aittir; yazılı/imzalı belge yoksa fesih sonrası yıllık izin ücreti doğar.",
            )
        )
    elif signed_leave_book is None:
        missing.append(MissingInfoItem("signed_leave_register_verified", "Kullandırılan yıllık izinlerin ıslak/elektronik imzalı izin kayıt belgesiyle belgelenmesi gerekir.", "İmzalı Yıllık İzin Defteri / İzin Talep Formu"))

    counters.extend(
        [
            "Karşı görüş: Aynı işverenin farklı işyerlerindeki veya fasılalı hizmet süreleri 4857 m.54 uyarınca kıdem yılı hesabında birleştirilebilir; bu durum çalışanın izin kademesini (ör. 14'ten 20 güne) yükseltebilir.",
            "Karşı görüş: Ulusal bayram, hafta tatili ve genel tatil günleri yıllık izin süresinden sayılmaz (4857 m.56/5); izin defterinde bu günlerin düşülmemesi eksik kullandırma iddiasına yol açar.",
        ]
    )
    actions.extend(
        [
            "Yıllık izinleri bir bölümü en az 10 gün olacak şekilde kullandırıp çalışanın imzasıyla yıllık izin defterine kaydedin.",
            "Hafta tatili ve UBGT günlerini yıllık izin süresinden hariç tutun.",
        ]
    )

    summary = (
        f"Yıllık ücretli izin değerlendirmesi: Kanuni asgari={statutory_min_days} gün, "
        f"uygulanacak süre={effective_leave_days} gün, risk={len(risks)}, eksik bilgi={len(missing)}."
    )
    return _finalize_evaluation(
        scenario_type="ANNUAL_LEAVE_COMPLIANCE",
        as_of_date=as_of_date,
        summary=summary,
        bases=bases,
        historical_context=historical,
        escalation_flags=eff_escalations,
        counter_arguments=counters,
        risks=risks,
        missing_info=missing,
        recommended_actions=actions,
        structured_findings={
            "statutory_minimum_leave_days": statutory_min_days,
            "effective_leave_days": effective_leave_days,
            "minimum_split_block_days": 10,
        },
        force_counsel_escalation=False,
        allow_payroll_handoff_when_clean=True,
        norm_conflict_resolution=norm_res,
    )


def _eval_sgk_exit_code_and_unemployment(
    facts: dict[str, Any],
    as_of_date: str,
    sources: dict[str, LegalSourceRecord],
    precedents: dict[str, PrecedentRecord],
    cards: dict[str, LegalKnowledgeCard],
) -> LegalScenarioEvaluation:
    bases: list[LegalBasisItem] = []
    historical: list[LegalBasisItem] = []
    eff_escalations: list[str] = []
    counters: list[str] = []
    risks: list[RiskItem] = []
    missing: list[MissingInfoItem] = []
    actions: list[str] = []
    force_esc = False

    exit_code = str(facts.get("proposed_sgk_exit_code", "")).strip()
    true_reason = str(facts.get("actual_termination_reason", "UNKNOWN")).upper()
    term_date_s = facts.get("termination_date")
    filing_date_s = facts.get("sgk_filing_date") or as_of_date
    last_120_continuous = facts.get("last_120_days_service_contract")
    unemp_days_3y = facts.get("unemployment_premium_days_last_3_years")

    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "MEVZUAT-5510",
        "5510 m.9 (10 günlük işten ayrılış bildirgesi) ve m.102 İPC yaptırımları.",
        card_id="CARD-5510-M08-M09", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )
    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "MEVZUAT-5510",
        "5510 m.102 süresinde bildirim yapılmaması halinde idari para cezası.",
        card_id="CARD-5510-M102", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )
    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "MEVZUAT-4447",
        "4447 m.50-51 işsizlik ödeneği şartları (son 120 gün + son 3 yılda 600 gün + kusursuz işsizlik; Kod 22 tek başına kesin ret değildir).",
        card_id="CARD-4447-M50-M51", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )
    _add_verified_basis(
        bases, sources, cards, precedents, as_of_date, "YONETMELIK-SSIY-20100512",
        "SSİY işten ayrılış bildirimi ve 10 gün içinde iptal/düzeltme usulü.",
        card_id="CARD-SSIY-M11-M14", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
    )

    if not exit_code:
        missing.append(MissingInfoItem("proposed_sgk_exit_code", "Bildirilecek SGK işten ayrılış kodu belirtilmelidir.", "SGK İşten Ayrılış Bildirgesi taslağı"))

    # Legacy Code 29 check
    if exit_code == "29":
        risks.append(
            RiskItem(
                risk_level="HIGH",
                category="YURURLUKTEN_KALDIRILMIS_KOD_29",
                description="Eski genel 'Kod 29' kaldırılmış olup 4857 m.25/II fesihleri 42–50 arasındaki spesifik alt kodlarla bildirilmelidir.",
                legal_consequence="Hatalı/geçersiz SGK işten ayrılış bildirgesi ve işçi kişilik hakları tazminat riski.",
            )
        )

    # Consistency check: actual reason vs proposed code
    code_mismatch = False
    if true_reason == "EMPLOYER_VALID_OR_NOTICE_M17_M18" and exit_code in {"03", "42", "43", "44", "45", "46", "47", "48", "49", "50"}:
        code_mismatch = True
    elif true_reason == "EMPLOYEE_RESIGNATION" and exit_code == "04":
        code_mismatch = True

    if code_mismatch:
        force_esc = True
        risks.append(
            RiskItem(
                risk_level="CRITICAL",
                category="SGK_CIKIS_KODU_UYUMSUZLUGU",
                description=f"Gerçek sona erme sebebi ({true_reason}) ile bildirilecek SGK çıkış kodu ('{exit_code}') birbiriyle çelişmektedir.",
                legal_consequence="İşçinin işsizlik ödeneğinden mahrum kalması halinde işverenden tazminat talebi, İŞKUR/SGK incelemesi ve m.102 İPC riski.",
            )
        )

    # 10-day filing deadline check (5510 m.9)
    days_to_file: int | None = None
    if not term_date_s:
        missing.append(MissingInfoItem("termination_date", "5510 m.9 kapsamındaki 10 günlük SGK bildirim süresinin hesabı için işten çıkış tarihi gereklidir.", "Fesih / işten çıkış tarihli tutanak"))
    else:
        t_dt = parse_iso_date(str(term_date_s))
        f_dt = parse_iso_date(str(filing_date_s))
        if t_dt and f_dt:
            days_to_file = (f_dt - t_dt).days
            if days_to_file > 10:
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="SGK_10_GUN_BILDIRIM_ASIMI_M9_M102",
                        description=f"İşten çıkış tarihinden ({term_date_s}) bildirim tarihine ({filing_date_s}) kadar {days_to_file} gün geçmiş; 5510 m.9 kapsamındaki 10 günlük süre aşılmıştır.",
                        legal_consequence="5510 m.102/1-j uyarınca idari para cezası doğar; 10 gün geçtiği için e-Bildirge üzerinden tek taraflı kod düzeltmesi de mümkün olmayıp SGK müdürlüğüne belgeli başvuru gerekir.",
                    )
                )

    # Code 22 substantive review rule (NEVER absolute auto-denial!)
    unemployment_assessment = "UNDETERMINED"
    if exit_code == "22":
        risks.append(
            RiskItem(
                risk_level="MEDIUM",
                category="KOD_22_ESAS_INCELEME_GEREKLILIGI",
                description="SGK çıkış kodu 22 (Diğer Nedenler / İkale) tek başına kesin işsizlik ödeneği ret kararı üretmez; gerçek sona erme sebebi, destekleyici belgeler ve 4447 m.51 şartları İŞKUR'ca birlikte değerlendirilir.",
                legal_consequence="Gerçekte işveren feshine dayanan bir çıkışın Kod 22 ile bildirilmesi halinde işçi düzeltme/tazminat talep edebilir.",
            )
        )
        unemployment_assessment = "SUBSTANTIVE_REVIEW_REQUIRED_NOT_AUTO_DENIED"
    elif last_120_continuous is None or unemp_days_3y is None:
        if last_120_continuous is None:
            missing.append(MissingInfoItem("last_120_days_service_contract", "4447 m.51 son 120 gün hizmet akdine tabi olma şartı teyit edilmelidir.", "SGK son 4 aylık hizmet dökümü"))
        if unemp_days_3y is None:
            missing.append(MissingInfoItem("unemployment_premium_days_last_3_years", "4447 m.51 son 3 yılda en az 600 gün işsizlik primi şartı teyit edilmelidir.", "SGK son 3 yıllık prim dökümü"))
    else:
        if bool(last_120_continuous) and int(unemp_days_3y) >= 600 and exit_code in {"04", "05", "12", "15", "17", "18", "23", "24", "25", "27", "28", "31", "32", "33", "34"}:
            unemployment_assessment = "LIKELY_ELIGIBLE_IF_APPLIED_WITHIN_30_DAYS"
        else:
            unemployment_assessment = "NOT_ELIGIBLE_OR_REQUIRES_ISKUR_REVIEW"

    counters.extend(
        [
            "Karşı görüş: SGK çıkış kodu 22 bildirilen ikale/diğer nedenli çıkışlarda, feshin gerçekte işverenin baskısı veya geçerli/haklı olmayan nedenle gerçekleştiği ispatlanırsa işçi hem işe iade hem de mahrum kalınan işsizlik ödeneği yönünden hak iddia edebilir.",
            "Karşı görüş: 4857 m.25/II alt kodlarıyla (42–50) bildirim yapılması halinde işçi iş bulmakta zorlandığını ve gerçeğe aykırı kod bildirildiğini ileri sürerek kod düzeltme ve manevi tazminat talebinde bulunabilir.",
        ]
    )
    actions.extend(
        [
            "SGK işten ayrılış bildirgesini 5510 m.9 gereği 10 gün içinde gerçek sona erme sebebine uygun kodla verin.",
            "Hatalı kod tespiti varsa 10 gün içinde sistemden, 10 gün sonrası ise destekleyici belgelerle (mahkeme/arabuluculuk tutanağı, fesih yazısı) SGK müdürlüğüne başvurarak düzeltme yaptırın.",
        ]
    )

    summary = (
        f"SGK çıkış kodu & işsizlik ödeneği değerlendirmesi (kod='{exit_code or 'EKSİK'}', sebep={true_reason}): "
        f"10 gün bildirim={f'{days_to_file} gün' if days_to_file is not None else 'BİLİNMİYOR'}, "
        f"işsizlik ödeneği={unemployment_assessment}."
    )
    return _finalize_evaluation(
        scenario_type="SGK_EXIT_CODE_AND_UNEMPLOYMENT",
        as_of_date=as_of_date,
        summary=summary,
        bases=bases,
        historical_context=historical,
        escalation_flags=eff_escalations,
        counter_arguments=counters,
        risks=risks,
        missing_info=missing,
        recommended_actions=actions,
        structured_findings={
            "proposed_sgk_exit_code": exit_code,
            "days_to_sgk_filing": days_to_file,
            "code_reason_mismatch": code_mismatch,
            "unemployment_benefit_assessment": unemployment_assessment,
        },
        force_counsel_escalation=force_esc,
        allow_payroll_handoff_when_clean=True,
    )


def _eval_employee_favorable_norm_comparison(
    facts: dict[str, Any],
    as_of_date: str,
    sources: dict[str, LegalSourceRecord],
    precedents: dict[str, PrecedentRecord],
    cards: dict[str, LegalKnowledgeCard],
) -> LegalScenarioEvaluation:
    bases: list[LegalBasisItem] = []
    historical: list[LegalBasisItem] = []
    eff_escalations: list[str] = []
    counters: list[str] = []
    risks: list[RiskItem] = []
    missing: list[MissingInfoItem] = []
    actions: list[str] = []
    force_esc = False
    norm_res: NormConflictResolution | None = None
    prec_res: PrecedentApplicationAssessment | None = None

    na_raw = facts.get("norm_a")
    nb_raw = facts.get("norm_b")
    mandatory_type = str(facts.get("mandatory_type", "RELATIVE_EMPLOYEE_FAVORABLE"))
    favors_side = str(facts.get("favors_employee_side", "UNKNOWN"))
    treaty_nature = str(facts.get("treaty_provision_nature", "UNSPECIFIED"))
    precedent_id = facts.get("precedent_id")
    interpreted_source_id = facts.get("interpreted_source_id")
    scope_match = str(facts.get("scope_match_status", "UNCERTAIN"))
    app_rationale = str(facts.get("application_rationale", ""))

    # Collect verified effective bases from referenced sources; strictly route non-effective to historical_context and escalate non-verified/non-effective
    explicit_source_referenced = False
    for raw_n in (na_raw, nb_raw):
        if isinstance(raw_n, dict) and raw_n.get("source_id"):
            explicit_source_referenced = True
            sid = str(raw_n["source_id"])
            src_obj = sources.get(sid)
            if src_obj is not None and src_obj.verification_status != "VERIFIED":
                force_esc = True
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="DOGRULANMAMIS_VEYA_MULGA_NORM_KAYNAGI",
                        description=(
                            f"Karşılaştırılan '{sid}' kaynağının doğrulama statüsü '{src_obj.verification_status}' "
                            "olduğundan kesin doğrulanmış dayanak olarak kabul edilemez."
                        ),
                        legal_consequence="Tam metin doğrulaması tamamlanmamış veya mülga kaynak üzerinden hukuki sonuç üretilemez; hukuk müşaviri teyidi zorunludur.",
                    )
                )
                if src_obj.verification_status == "SUPERSEDED":
                    _add_verified_basis(
                        bases, sources, cards, precedents, as_of_date, sid,
                        f"Karşılaştırılan mülga norm kaynağı ({raw_n.get('norm_layer')}).",
                        historical_context=historical, risks=risks, escalation_flags=eff_escalations,
                    )
            else:
                ok_eff = _add_verified_basis(
                    bases, sources, cards, precedents, as_of_date, sid,
                    f"Karşılaştırılan norm kaynağı ({raw_n.get('norm_layer')}).",
                    historical_context=historical, risks=risks, escalation_flags=eff_escalations,
                )
                if not ok_eff and src_obj is not None:
                    force_esc = True
                    risks.append(
                        RiskItem(
                            risk_level="HIGH",
                            category="OLAY_TARIHINDE_YURURLUKTE_OLMAYAN_NORM_KAYNAGI",
                            description=(
                                f"Karşılaştırılan '{sid}' kaynağı {as_of_date} tarihinde yürürlükte değildir "
                                f"(yürürlük penceresi: {src_obj.effective_from}..{src_obj.effective_to}); tarihsel bağlama alınmıştır."
                            ),
                            legal_consequence="Olay tarihinde yürürlükte olmayan hüküm güncel dayanak yapılamaz; hukuk müşaviri onayı gerekir.",
                        )
                    )

    if not bases and not explicit_source_referenced and not precedent_id:
        _add_verified_basis(
            bases, sources, cards, precedents, as_of_date, "MEVZUAT-4857",
            "İş hukukunda nispi/mutlak emredicilik ve çalışan lehine yorum çerçevesi.",
            card_id="CARD-4857-M17", historical_context=historical, risks=risks, escalation_flags=eff_escalations,
        )

    if precedent_id:
        prec = precedents.get(str(precedent_id))
        src = sources.get(str(interpreted_source_id)) if interpreted_source_id else None
        if prec is None or src is None:
            missing.append(
                MissingInfoItem(
                    "precedent_id/interpreted_source_id",
                    "İçtihat uygulama değerlendirmesi için kayıt defterinde bulunan precedent_id ve interpreted_source_id gereklidir.",
                    "Doğrulanmış Yargıtay karar kaydı ve yorumlanan kanun referansı",
                )
            )
        else:
            comp_norm = (
                NormReference(
                    title=nb_raw["title"],
                    norm_layer=nb_raw["norm_layer"],
                    precedent_level=nb_raw.get("precedent_level", "NONE"),
                    source_id=nb_raw.get("source_id"),
                )
                if isinstance(nb_raw, dict)
                else None
            )
            prec_favor_map = {
                "NORM_A": "UNDERLYING_STATUTE",
                "NORM_B": "COMPETING_NORM",
                "UNDERLYING_STATUTE": "UNDERLYING_STATUTE",
                "COMPETING_NORM": "COMPETING_NORM",
                "NEUTRAL": "NEUTRAL",
                "UNKNOWN": "UNKNOWN",
            }
            prec_res = evaluate_precedent_application(
                precedent=prec,
                interpreted_source=src,
                as_of_date=as_of_date,
                scope_match_status=scope_match,
                competing_norm=comp_norm,
                mandatory_type=mandatory_type,
                favors_employee_side=prec_favor_map.get(favors_side, "UNKNOWN"),
                dispute_context=str(facts.get("dispute_context", "")),
                application_rationale=app_rationale,
                treaty_provision_nature=treaty_nature,
            )
            norm_res = prec_res.underlying_norm_resolution
            _add_verified_basis(
                bases, sources, cards, precedents, as_of_date, src.source_id,
                f"İçtihat uygulama değerlendirmesi ({prec.precedent_id}, {prec_res.binding_nature}).",
                precedent_id=prec.precedent_id if prec.verification_status == "VERIFIED" else None,
                historical_context=historical, risks=risks, escalation_flags=eff_escalations,
            )
            if prec_res.requires_counsel_escalation:
                force_esc = True
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="ICTIHAT_UYGULAMA_ESKALASYONU",
                        description=prec_res.explanation,
                        legal_consequence="İçtihadın kapsamı, gerekçesi veya dayanak kanun çatışması hukuk müşavirince netleştirilmeden işlem yapılmamalıdır.",
                    )
                )
    else:
        if not isinstance(na_raw, dict) or not isinstance(nb_raw, dict):
            missing.append(
                MissingInfoItem(
                    "norm_a/norm_b",
                    "Çalışan lehine hak karşılaştırması için norm_a ve norm_b nesneleri zorunludur.",
                    "Karşılaştırılacak mevzuat ve TİS/sözleşme/prosedür hükümleri",
                )
            )
        else:
            norm_a = NormReference(
                title=na_raw["title"],
                norm_layer=na_raw["norm_layer"],
                precedent_level=na_raw.get("precedent_level", "NONE"),
                source_id=na_raw.get("source_id"),
            )
            norm_b = NormReference(
                title=nb_raw["title"],
                norm_layer=nb_raw["norm_layer"],
                precedent_level=nb_raw.get("precedent_level", "NONE"),
                source_id=nb_raw.get("source_id"),
            )
            norm_res = resolve_norm_conflict(
                norm_a=norm_a,
                norm_b=norm_b,
                mandatory_type=mandatory_type,
                favors_employee_side=favors_side,
                treaty_provision_nature=treaty_nature,
            )
            if norm_res.requires_counsel_escalation:
                force_esc = True
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="NORM_CATISMASI_ESKALASYONU",
                        description=norm_res.explanation,
                        legal_consequence=f"Kural ({norm_res.rule_applied}) gereği otomatik çözüm yerine hukuk müşaviri onayı zorunludur.",
                    )
                )
            elif norm_res.rule_applied == "RELATIVE_MANDATORY_EMPLOYEE_UNFAVORABLE_LOWER_NORM_VOID":
                risks.append(
                    RiskItem(
                        risk_level="HIGH",
                        category="ISCI_ALEYHINE_ALT_NORM_HUKUMSUZLUGU",
                        description=norm_res.explanation,
                        legal_consequence="İşçi aleyhine sözleşme/prosedür maddesi kesin hükümsüzdür; uygulanması halinde alacak ve İPC riski doğar.",
                    )
                )

    counters.extend(
        [
            "Karşı görüş: İşçi lehine yorum (yararlılık) ilkesi yalnızca nispi emredici hükümlerde geçerlidir; SGK tavanı, TBK m.420 1 ay kuralı, mahkeme görevi veya 270 saat fazla çalışma sınırı gibi mutlak emredici kamu düzeni kuralları sözleşmeyle değiştirilemez.",
            "Karşı görüş: Anayasa m.90/5 kapsamında temel hak antlaşmasının asgari standart mı yoksa doğrudan esas kural mı olduğu ve genel uluslararası antlaşmaların kanunla lex specialis ilişkisi yargılamada farklı yorumlanabilir.",
        ]
    )
    actions.extend(
        [
            "Norm çatışmasında üst normun emredicilik türünü (mutlak/nispi/yedek) ve TİS/sözleşme metnini yazılı dosyaya ekleyin.",
            "Eskalasyon bayrağı oluştuysa uygulama öncesi şirket avukatının yazılı onayını alın.",
        ]
    )

    outcome_label = (
        prec_res.effective_outcome
        if prec_res is not None
        else (norm_res.rule_applied if norm_res is not None else "EKSİK BİLGİ")
    )
    summary = f"Çalışan lehine hak / norm çatışması değerlendirmesi: Sonuç={outcome_label}."
    return _finalize_evaluation(
        scenario_type="EMPLOYEE_FAVORABLE_NORM_COMPARISON",
        as_of_date=as_of_date,
        summary=summary,
        bases=bases,
        historical_context=historical,
        escalation_flags=eff_escalations,
        counter_arguments=counters,
        risks=risks,
        missing_info=missing,
        recommended_actions=actions,
        structured_findings={
            "outcome_rule": outcome_label,
            "mandatory_type": mandatory_type,
            "treaty_provision_nature": treaty_nature,
        },
        force_counsel_escalation=force_esc,
        allow_payroll_handoff_when_clean=True,
        norm_conflict_resolution=norm_res,
        precedent_application_assessment=prec_res,
    )


def evaluate_hr_legal_scenario(
    scenario_type: str,
    facts: dict[str, Any],
    as_of_date: str,
    source_registry: dict[str, LegalSourceRecord],
    precedent_registry: dict[str, PrecedentRecord],
    knowledge_cards: dict[str, LegalKnowledgeCard],
    *,
    approvers_registry: dict[str, Any] | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    project_root: Path | None = None,
    runtime_environment: str = "PRODUCTION",
    require_signed_ledger_checkpoint: bool = True,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    external_trust_anchor_provider: Any | None = None,
    expected_app_project_id: str | None = None,
) -> LegalScenarioEvaluation:
    """Evaluate a real HR legal scenario deterministically with separated basis, counter-arguments, risks, missing info, and human approval."""
    if scenario_type not in VALID_SCENARIO_TYPES:
        raise ValueError(f"Desteklenmeyen senaryo türü: '{scenario_type}'. Geçerli türler: {sorted(VALID_SCENARIO_TYPES)}")
    if parse_iso_date(as_of_date) is None:
        raise ValueError(f"Geçersiz as_of_date (YYYY-MM-DD beklenir): '{as_of_date}'")
    if not isinstance(facts, dict):
        raise ValueError("'facts' alanı sözlük (dict) olmalıdır.")

    if scenario_type == "TERMINATION_VALIDITY":
        return _eval_termination_validity(
            facts,
            as_of_date,
            source_registry,
            precedent_registry,
            knowledge_cards,
            approvers_registry=approvers_registry,
            attestation_ledger=attestation_ledger,
            project_root=project_root,
            runtime_environment=runtime_environment,
            require_signed_ledger_checkpoint=require_signed_ledger_checkpoint,
            expected_checkpoint_head_hash=expected_checkpoint_head_hash,
            expected_checkpoint_entry_count=expected_checkpoint_entry_count,
            expected_chain_digest_sha256=expected_chain_digest_sha256,
            external_trust_anchor_provider=external_trust_anchor_provider,
            expected_app_project_id=expected_app_project_id,
        )

    evaluators = {
        "REINSTATEMENT_CLAIM": _eval_reinstatement_claim,
        "SEVERANCE_AND_NOTICE": _eval_severance_and_notice,
        "OVERTIME_COMPLIANCE": _eval_overtime_compliance,
        "ANNUAL_LEAVE_COMPLIANCE": _eval_annual_leave_compliance,
        "SGK_EXIT_CODE_AND_UNEMPLOYMENT": _eval_sgk_exit_code_and_unemployment,
        "EMPLOYEE_FAVORABLE_NORM_COMPARISON": _eval_employee_favorable_norm_comparison,
    }
    return evaluators[scenario_type](facts, as_of_date, source_registry, precedent_registry, knowledge_cards)
