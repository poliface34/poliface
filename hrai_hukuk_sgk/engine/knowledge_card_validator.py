"""Deterministic validator, loader, and temporal search engine for Legal Knowledge Cards (v1.0.2a).

Enforces:
1. Separate Source Verification (`source_verification`) AND Legal Interpretation Verification (`legal_interpretation_verification`),
2. Mandatory verified article-level effective date before `VERIFIED` status,
3. Mandatory central audit log cross-reference (`config/verification_audit_log.json`) for every knowledge card.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .models import (
    VALID_MANDATORY_TYPES,
    VALID_VERIFIER_ROLES,
    LegalKnowledgeCard,
    LegalSourceRecord,
    PrecedentRecord,
    RegistryValidationReport,
    VerificationFlag,
)
from .source_validator import (
    AUDIT_LOG_ID_RE,
    DISALLOWED_VERIFIERS,
    VERIFIER_ID_RE,
    is_specific_official_url,
    parse_iso_date,
)

CARD_ID_RE = re.compile(r"^CARD-[A-Z0-9\-_]{3,50}$")
TOKEN_RE = re.compile(r"[a-zçğıöşü0-9]+", re.IGNORECASE)
VALID_CARD_STATUSES: set[str] = {
    "VERIFIED",
    "DRAFT",
    "PENDING_EFFECTIVE_DATE_CHECK",
    "PENDING_LEGAL_REVIEW",
    "SUPERSEDED",
}
REQUIRED_LEGAL_REVIEW_ASPECTS: set[str] = {
    "ARTICLE_TEXT",
    "EFFECTIVE_DATES",
    "EXCEPTIONS",
    "PERIODS_AND_THRESHOLDS",
}
SECONDARY_LEGISLATION_NORM_LAYERS: set[str] = {
    "PRESIDENTIAL_DECREE",
    "PRESIDENTIAL_DECISION",
    "REGULATION",
    "COMMUNIQUE_AND_SGK_CIRCULAR",
}


def _tr_lower(text: str) -> str:
    return text.replace("İ", "i").replace("I", "ı").lower()


def load_central_audit_index(audit_log_path: str | Path) -> dict[str, dict[str, Any]]:
    """Load config/verification_audit_log.json indexed by audit_log_id."""
    raw = json.loads(Path(audit_log_path).read_text(encoding="utf-8"))
    index: dict[str, dict[str, Any]] = {}
    for entry in raw.get("entries", []):
        aid = entry.get("audit_log_id")
        if aid:
            index[str(aid)] = entry
    return index


def validate_knowledge_card_file(
    raw_data: dict[str, Any],
    source_registry: dict[str, LegalSourceRecord],
    precedent_registry: dict[str, PrecedentRecord],
    file_label: str = "knowledge_card_file",
    central_audit_index: dict[str, dict[str, Any]] | None = None,
) -> RegistryValidationReport:
    """Validate an actionable legal knowledge card JSON file against registries, dual verification, and central audit log."""
    flags: list[VerificationFlag] = []
    if not isinstance(raw_data, dict):
        flags.append(
            VerificationFlag(
                code="INVALID_CARD_FILE_ROOT",
                severity="BLOCKER",
                message=f"'{file_label}' kökü JSON nesnesi olmalıdır.",
            )
        )
        return RegistryValidationReport(file_label, False, 0, 0, flags)

    file_source_id = raw_data.get("source_id")
    if file_source_id not in source_registry:
        flags.append(
            VerificationFlag(
                code="BROKEN_FILE_SOURCE_ID",
                severity="BLOCKER",
                message=f"'{file_label}' için source_id='{file_source_id}' mevzuat kayıt defterinde yok.",
                evidence=str(file_source_id),
            )
        )

    cards = raw_data.get("cards")
    if not isinstance(cards, list) or not cards:
        flags.append(
            VerificationFlag(
                code="EMPTY_CARDS_LIST",
                severity="BLOCKER",
                message=f"'{file_label}' içinde en az bir bilgi kartı olmalıdır.",
            )
        )
        return RegistryValidationReport(file_label, False, 0, 0, flags)

    seen_ids: set[str] = set()
    verified_count = 0

    for idx, card in enumerate(cards):
        cid = str(card.get("card_id", f"index-{idx}"))
        if not CARD_ID_RE.match(cid):
            flags.append(
                VerificationFlag(
                    code="INVALID_CARD_ID",
                    severity="BLOCKER",
                    message=f"Geçersiz card_id biçimi: '{cid}'.",
                    evidence=cid,
                )
            )
        elif cid in seen_ids:
            flags.append(
                VerificationFlag(
                    code="DUPLICATE_CARD_ID",
                    severity="BLOCKER",
                    message=f"Mükerrer card_id tespit edildi: '{cid}'.",
                    evidence=cid,
                )
            )
        seen_ids.add(cid)

        src_id = card.get("source_id")
        parent_source = source_registry.get(src_id) if isinstance(src_id, str) else None
        if parent_source is None:
            flags.append(
                VerificationFlag(
                    code="BROKEN_CARD_SOURCE_ID",
                    severity="BLOCKER",
                    message=f"'{cid}' kartının source_id='{src_id}' değeri resmî kaynak defterinde yok.",
                    evidence=f"{cid}->{src_id}",
                )
            )

        # Legal basis separation: original vs consolidated vs amendment history
        basis = card.get("legal_basis")
        if not isinstance(basis, dict):
            flags.append(
                VerificationFlag(
                    code="MISSING_LEGAL_BASIS",
                    severity="BLOCKER",
                    message=f"'{cid}' kartında legal_basis bloğu eksik.",
                    evidence=cid,
                )
            )
        else:
            if not str(basis.get("original_publication_ref", "")).strip():
                flags.append(
                    VerificationFlag(
                        code="MISSING_ORIGINAL_PUBLICATION_REF",
                        severity="BLOCKER",
                        message=f"'{cid}' kartında ilk yayımlanan metin referansı eksik.",
                        evidence=cid,
                    )
                )
            cons_url = str(basis.get("consolidated_text_url", ""))
            url_ok, url_reason = is_specific_official_url(cons_url)
            if not url_ok:
                flags.append(
                    VerificationFlag(
                        code="INVALID_CONSOLIDATED_URL",
                        severity="BLOCKER",
                        message=f"'{cid}' kartının konsolide URL'si geçersiz: {url_reason}",
                        evidence=cons_url,
                    )
                )
            amendments = basis.get("amendment_history")
            if not isinstance(amendments, list):
                flags.append(
                    VerificationFlag(
                        code="INVALID_AMENDMENT_HISTORY",
                        severity="BLOCKER",
                        message=f"'{cid}' kartında amendment_history liste olmalıdır.",
                        evidence=cid,
                    )
                )
            else:
                for a_idx, amend in enumerate(amendments):
                    if (
                        not isinstance(amend, dict)
                        or not str(amend.get("amending_law_no", "")).strip()
                        or not str(amend.get("official_gazette_no", "")).strip()
                        or parse_iso_date(amend.get("publication_date")) is None
                        or parse_iso_date(amend.get("effective_from")) is None
                        or len(str(amend.get("summary", "")).strip()) < 5
                    ):
                        flags.append(
                            VerificationFlag(
                                code="INVALID_AMENDMENT_HISTORY_ENTRY",
                                severity="BLOCKER",
                                message=f"'{cid}' kartının amendment_history[{a_idx}] kaydı eksik veya geçersiz tarihli.",
                                evidence=f"{cid}.amendment_history[{a_idx}]",
                            )
                        )

        # Related precedents must exist & be VERIFIED
        for pid in card.get("related_precedent_ids", []):
            prec = precedent_registry.get(pid)
            if prec is None:
                flags.append(
                    VerificationFlag(
                        code="BROKEN_CARD_PRECEDENT_ID",
                        severity="BLOCKER",
                        message=f"'{cid}' kartındaki içtihat referansı '{pid}' kayıt defterinde yok.",
                        evidence=f"{cid}->{pid}",
                    )
                )
            elif prec.verification_status != "VERIFIED":
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_CARD_PRECEDENT",
                        severity="BLOCKER",
                        message=f"'{cid}' kartındaki '{pid}' içtihadı VERIFIED değil (durum={prec.verification_status}).",
                        evidence=f"{cid}->{pid}",
                    )
                )

        status = card.get("verification_status")
        if status not in VALID_CARD_STATUSES:
            flags.append(
                VerificationFlag(
                    code="INVALID_CARD_STATUS",
                    severity="BLOCKER",
                    message=f"'{cid}' için geçersiz verification_status: '{status}'.",
                    evidence=cid,
                )
            )
        if status == "VERIFIED" and parent_source is not None and parent_source.verification_status != "VERIFIED":
            flags.append(
                VerificationFlag(
                    code="INACTIVE_PARENT_SOURCE_ON_VERIFIED_CARD",
                    severity="BLOCKER",
                    message=(
                        f"'{cid}' kartının bağlı olduğu '{src_id}' kaynağı VERIFIED değil "
                        f"(durum={parent_source.verification_status}); kart VERIFIED olamaz."
                    ),
                    evidence=f"{cid}->{src_id}",
                )
            )

        # v1.0.2b.1: Secondary legislation (L2 Regulation / L3 Circular & Communique / Presidential Decree & Decision) MUST declare statutory_subordination
        if parent_source is not None and parent_source.norm_layer in SECONDARY_LEGISLATION_NORM_LAYERS:
            sub = card.get("statutory_subordination")
            if (
                not isinstance(sub, dict)
                or not isinstance(sub.get("concretizes_statutory_provisions"), list)
                or not sub.get("concretizes_statutory_provisions")
                or sub.get("cannot_override_parent_law") is not True
                or len(str(sub.get("hierarchy_note", "")).strip()) < 15
            ):
                flags.append(
                    VerificationFlag(
                        code="MISSING_OR_INVALID_STATUTORY_SUBORDINATION",
                        severity="BLOCKER",
                        message=(
                            f"'{cid}' ikincil mevzuat kartı ({parent_source.norm_layer}) için geçerli "
                            f"statutory_subordination (concretizes_statutory_provisions, "
                            f"cannot_override_parent_law=True, hierarchy_note>=15) zorunludur."
                        ),
                        evidence=cid,
                    )
                )

        # Effective validity check
        eff = card.get("effective_validity")
        if not isinstance(eff, dict):
            flags.append(
                VerificationFlag(
                    code="MISSING_EFFECTIVE_VALIDITY",
                    severity="BLOCKER",
                    message=f"'{cid}' kartında effective_validity bloğu eksik.",
                    evidence=cid,
                )
            )
        else:
            eff_from = parse_iso_date(eff.get("effective_from"))
            eff_to = parse_iso_date(eff.get("effective_to"))
            if eff_from is None or eff_to is None or eff_from > eff_to:
                flags.append(
                    VerificationFlag(
                        code="INVALID_CARD_EFFECTIVE_DATES",
                        severity="BLOCKER",
                        message=f"'{cid}' kartında geçersiz yürürlük aralığı: {eff.get('effective_from')}..{eff.get('effective_to')}.",
                        evidence=cid,
                    )
                )
            elif parent_source is not None:
                parent_from = parse_iso_date(parent_source.effective_from)
                if parent_from is not None and eff_from < parent_from:
                    flags.append(
                        VerificationFlag(
                            code="CARD_EFFECTIVE_BEFORE_PARENT_SOURCE",
                            severity="BLOCKER",
                            message=(
                                f"'{cid}' kartının effective_from ({eff_from}) değeri üst kaynağın "
                                f"effective_from ({parent_from}) tarihinden önce olamaz."
                            ),
                            evidence=f"{cid}->{src_id}",
                        )
                    )
            if status == "VERIFIED" and eff.get("effective_date_verified") is not True:
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_EFFECTIVE_DATE_ON_VERIFIED_CARD",
                        severity="BLOCKER",
                        message=(
                            f"'{cid}' kartı yürürlük tarihi doğrulanmadan (effective_date_verified=False) "
                            f"VERIFIED durumuna alınamaz."
                        ),
                        evidence=cid,
                    )
                )
            if (
                eff.get("effective_date_verified") is True
                and parent_source is not None
                and parent_source.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}
            ):
                flags.append(
                    VerificationFlag(
                        code="EFFECTIVE_DATE_VERIFIED_ON_NON_VERIFIED_PARENT",
                        severity="BLOCKER",
                        message=(
                            f"'{cid}' kartının üst kaynağı '{src_id}' tam doğrulanmamışken "
                            f"(durum={parent_source.verification_status}) effective_date_verified=true olamaz."
                        ),
                        evidence=f"{cid}->{src_id}",
                    )
                )

        # v1.0.2a DUAL VERIFICATION CONTROL 1: Source Verification
        src_ver = card.get("source_verification")
        if not isinstance(src_ver, dict):
            flags.append(
                VerificationFlag(
                    code="MISSING_SOURCE_VERIFICATION",
                    severity="BLOCKER",
                    message=f"'{cid}' kartında ayrı kaynak doğrulama bloğu (source_verification) eksik.",
                    evidence=cid,
                )
            )
        else:
            if src_ver.get("source_id") != src_id:
                flags.append(
                    VerificationFlag(
                        code="SOURCE_VERIFICATION_ID_MISMATCH",
                        severity="BLOCKER",
                        message=f"'{cid}' source_verification.source_id ile kart source_id uyuşmuyor.",
                        evidence=cid,
                    )
                )
            src_aid = str(src_ver.get("source_audit_log_id", ""))
            if not AUDIT_LOG_ID_RE.match(src_aid):
                flags.append(
                    VerificationFlag(
                        code="INVALID_SOURCE_AUDIT_LOG_ID",
                        severity="BLOCKER",
                        message=f"'{cid}' için geçersiz source_audit_log_id: '{src_aid}'.",
                        evidence=cid,
                    )
                )
            elif central_audit_index is not None and src_aid not in central_audit_index:
                flags.append(
                    VerificationFlag(
                        code="MISSING_SOURCE_CENTRAL_AUDIT_ENTRY",
                        severity="BLOCKER",
                        message=f"'{cid}' kartının dayandığı '{src_aid}' merkezi denetim kaydında bulunamadı.",
                        evidence=src_aid,
                    )
                )
            if status == "VERIFIED" and src_ver.get("status") != "VERIFIED":
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_SOURCE_ON_VERIFIED_CARD",
                        severity="BLOCKER",
                        message=f"'{cid}' kartı source_verification.status != 'VERIFIED' iken VERIFIED olamaz.",
                        evidence=cid,
                    )
                )
            parent_fetch_ok = (
                parent_source is not None
                and parent_source.verification_status == "VERIFIED"
                and (
                    parent_source.verification_audit is None
                    or parent_source.verification_audit.document_fetch_status == "FETCHED_AND_MATCHED"
                )
            )
            if src_ver.get("status") == "VERIFIED" and parent_source is not None and not parent_fetch_ok:
                flags.append(
                    VerificationFlag(
                        code="SOURCE_VERIFICATION_CLAIMED_ON_NON_VERIFIED_PARENT",
                        severity="BLOCKER",
                        message=(
                            f"'{cid}' kartında source_verification.status='VERIFIED' beyan edilmiş ancak üst kaynak "
                            f"'{src_id}' tam doğrulanmış değil (durum={parent_source.verification_status})."
                        ),
                        evidence=f"{cid}->{src_id}",
                        remediation="Üst kaynak tam doğrulanana kadar source_verification.status='PENDING' yapın.",
                    )
                )

        # v1.0.2a DUAL VERIFICATION CONTROL 2: Legal Interpretation Verification
        leg_ver = card.get("legal_interpretation_verification")
        if not isinstance(leg_ver, dict):
            flags.append(
                VerificationFlag(
                    code="MISSING_LEGAL_INTERPRETATION_VERIFICATION",
                    severity="BLOCKER",
                    message=f"'{cid}' kartında ayrı hukuki yorum doğrulama bloğu (legal_interpretation_verification) eksik.",
                    evidence=cid,
                )
            )
        else:
            rev_id = str(leg_ver.get("reviewer_id", "")).strip()
            if rev_id.upper() in DISALLOWED_VERIFIERS or not VERIFIER_ID_RE.match(rev_id):
                flags.append(
                    VerificationFlag(
                        code="INVALID_LEGAL_REVIEWER_ID",
                        severity="BLOCKER",
                        message=f"'{cid}' hukuki inceleme kaydında geçersiz reviewer_id: '{rev_id}'.",
                        evidence=cid,
                    )
                )
            if leg_ver.get("reviewer_role") not in VALID_VERIFIER_ROLES:
                flags.append(
                    VerificationFlag(
                        code="INVALID_LEGAL_REVIEWER_ROLE",
                        severity="BLOCKER",
                        message=f"'{cid}' hukuki inceleme kaydında geçersiz reviewer_role: '{leg_ver.get('reviewer_role')}'.",
                        evidence=cid,
                    )
                )
            if parse_iso_date(leg_ver.get("reviewed_at")) is None:
                flags.append(
                    VerificationFlag(
                        code="INVALID_LEGAL_REVIEW_DATE",
                        severity="BLOCKER",
                        message=f"'{cid}' hukuki inceleme tarihi geçersiz: '{leg_ver.get('reviewed_at')}'.",
                        evidence=cid,
                    )
                )
            aspects = set(leg_ver.get("checked_aspects", []) or [])
            missing_aspects = REQUIRED_LEGAL_REVIEW_ASPECTS - aspects
            if missing_aspects:
                flags.append(
                    VerificationFlag(
                        code="INCOMPLETE_LEGAL_REVIEW_ASPECTS",
                        severity="BLOCKER",
                        message=f"'{cid}' hukuki incelemesinde zorunlu kontrol başlıkları eksik: {sorted(missing_aspects)}.",
                        evidence=cid,
                    )
                )
            if status == "VERIFIED" and leg_ver.get("status") != "VERIFIED":
                flags.append(
                    VerificationFlag(
                        code="UNVERIFIED_LEGAL_INTERPRETATION_ON_VERIFIED_CARD",
                        severity="BLOCKER",
                        message=(
                            f"'{cid}' kartı hukuki yorum doğrulaması (legal_interpretation_verification.status='VERIFIED') "
                            f"tamamlanmadan VERIFIED durumuna alınamaz."
                        ),
                        evidence=cid,
                    )
                )
            if leg_ver.get("status") == "VERIFIED" and (
                (isinstance(src_ver, dict) and src_ver.get("status") != "VERIFIED")
                or (parent_source is not None and parent_source.verification_status != "VERIFIED")
            ):
                flags.append(
                    VerificationFlag(
                        code="LEGAL_INTERPRETATION_VERIFIED_WITHOUT_VERIFIED_SOURCE",
                        severity="BLOCKER",
                        message=(
                            f"'{cid}' kartında kaynak doğrulaması tamamlanmamışken "
                            f"legal_interpretation_verification.status='VERIFIED' olamaz."
                        ),
                        evidence=f"{cid}->{src_id}",
                        remediation="Kaynak doğrulaması tamamlanana kadar legal_interpretation_verification.status='PENDING_LEGAL_REVIEW' yapın.",
                    )
                )

        if card.get("norm_character") not in VALID_MANDATORY_TYPES:
            flags.append(
                VerificationFlag(
                    code="INVALID_NORM_CHARACTER",
                    severity="BLOCKER",
                    message=f"'{cid}' için geçersiz norm_character: '{card.get('norm_character')}'.",
                    evidence=cid,
                )
            )

        for list_field in ("exceptions", "required_documents", "risks"):
            val = card.get(list_field)
            if not isinstance(val, list) or not val:
                flags.append(
                    VerificationFlag(
                        code="MISSING_CARD_SECTION",
                        severity="BLOCKER",
                        message=f"'{cid}' kartında '{list_field}' boş olamaz.",
                        evidence=f"{cid}.{list_field}",
                    )
                )

        if card.get("primary_specialist") != "@HukukSGK":
            flags.append(
                VerificationFlag(
                    code="INVALID_PRIMARY_SPECIALIST",
                    severity="BLOCKER",
                    message=f"'{cid}' için primary_specialist '@HukukSGK' olmalıdır.",
                    evidence=cid,
                )
            )

        disclaimer = _tr_lower(str(card.get("disclaimer", "")))
        if "mütalaa" not in disclaimer and "danışmanlık" not in disclaimer:
            flags.append(
                VerificationFlag(
                    code="MISSING_LEGAL_DISCLAIMER",
                    severity="BLOCKER",
                    message=f"'{cid}' kartı hukuki mütalaa olmadığına dair zorunlu şerh içermelidir.",
                    evidence=cid,
                )
            )

        # Card audit trail + CENTRAL AUDIT LOG CROSS-CHECK (P0 fix)
        audit = card.get("verification_audit")
        if not isinstance(audit, dict):
            flags.append(
                VerificationFlag(
                    code="MISSING_VERIFICATION_AUDIT",
                    severity="BLOCKER",
                    message=f"'{cid}' kartında verification_audit denetim kaydı eksik.",
                    evidence=cid,
                )
            )
        else:
            vid = str(audit.get("verifier_id", "")).strip()
            if vid.upper() in DISALLOWED_VERIFIERS or not VERIFIER_ID_RE.match(vid):
                flags.append(
                    VerificationFlag(
                        code="INVALID_AUDIT_VERIFIER",
                        severity="BLOCKER",
                        message=f"'{cid}' denetim kaydında geçersiz verifier_id: '{audit.get('verifier_id')}'.",
                        evidence=cid,
                    )
                )
            if audit.get("verifier_role") not in VALID_VERIFIER_ROLES:
                flags.append(
                    VerificationFlag(
                        code="INVALID_AUDIT_ROLE",
                        severity="BLOCKER",
                        message=f"'{cid}' denetim kaydında geçersiz verifier_role: '{audit.get('verifier_role')}'.",
                        evidence=cid,
                    )
                )
            aid = str(audit.get("audit_log_id", ""))
            if not AUDIT_LOG_ID_RE.match(aid):
                flags.append(
                    VerificationFlag(
                        code="INVALID_AUDIT_LOG_ID",
                        severity="BLOCKER",
                        message=f"'{cid}' denetim kaydında geçersiz audit_log_id: '{aid}'.",
                        evidence=cid,
                    )
                )
            elif central_audit_index is not None:
                central_entry = central_audit_index.get(aid)
                if central_entry is None:
                    flags.append(
                        VerificationFlag(
                            code="MISSING_CENTRAL_AUDIT_LOG_ENTRY",
                            severity="BLOCKER",
                            message=(
                                f"'{cid}' kartının denetim kimliği '{aid}' merkezi verification_audit_log.json "
                                f"kayıt defterinde bulunamadı."
                            ),
                            evidence=f"{cid}:{aid}",
                            remediation="Her bilgi kartı için merkezi verification_audit_log.json dosyasına karşılık gelen denetim kaydını ekleyin.",
                        )
                    )
                elif (
                    central_entry.get("record_type") != "KNOWLEDGE_CARD"
                    or central_entry.get("record_id") != cid
                    or central_entry.get("verifier_id") != vid
                ):
                    flags.append(
                        VerificationFlag(
                            code="CENTRAL_AUDIT_LOG_MISMATCH",
                            severity="BLOCKER",
                            message=(
                                f"'{cid}' için merkezi denetim kaydı '{aid}' alanları kart metaverisiyle "
                                f"uyuşmuyor (record_type/record_id/verifier_id)."
                            ),
                            evidence=f"{cid}:{aid}",
                        )
                    )
                elif (
                    central_entry.get("record_verification_status") is not None
                    and central_entry.get("record_verification_status") != status
                ):
                    flags.append(
                        VerificationFlag(
                            code="CENTRAL_AUDIT_STATUS_MISMATCH",
                            severity="BLOCKER",
                            message=(
                                f"'{cid}' kartının verification_status='{status}' değeri merkezi denetim kaydındaki "
                                f"record_verification_status='{central_entry.get('record_verification_status')}' ile uyuşmuyor."
                            ),
                            evidence=f"{cid}:{aid}",
                            remediation="Kart doğrulama statüsü ile merkezi verification_audit_log.json kaydını eşitleyin.",
                        )
                    )

        if status == "VERIFIED":
            verified_count += 1

    has_blocker = any(f.severity == "BLOCKER" for f in flags)
    return RegistryValidationReport(
        registry_name=file_label,
        valid=not has_blocker,
        total_records=len(cards),
        verified_count=verified_count,
        flags=flags,
    )


def load_knowledge_cards(
    kb_dir: str | Path,
    source_registry: dict[str, LegalSourceRecord],
    precedent_registry: dict[str, PrecedentRecord],
    strict: bool = True,
    audit_log_path: str | Path | None = None,
) -> dict[str, LegalKnowledgeCard]:
    """Load and strictly validate all JSON knowledge card packs against registries and central audit log."""
    root = Path(kb_dir)
    all_cards: dict[str, LegalKnowledgeCard] = {}
    if not root.exists():
        return all_cards

    central_audit_index = load_central_audit_index(audit_log_path) if audit_log_path is not None else None

    autonomous_norm_dirs = {"05_ik_prosedurleri", "06_tis_sozlesme_ve_isyeri_uygulamalari"}
    for json_path in sorted(root.rglob("*.json")):
        rel_parts = json_path.relative_to(root).parts
        if rel_parts and rel_parts[0] in autonomous_norm_dirs:
            continue
        raw = json.loads(json_path.read_text(encoding="utf-8"))
        report = validate_knowledge_card_file(
            raw,
            source_registry=source_registry,
            precedent_registry=precedent_registry,
            file_label=json_path.name,
            central_audit_index=central_audit_index,
        )
        if strict and not report.valid:
            msgs = "; ".join(f"{f.code}: {f.message}" for f in report.flags if f.severity == "BLOCKER")
            raise ValueError(f"Bilgi kartı doğrulaması başarısız ({json_path.name}): {msgs}")

        law_title = raw.get("law_title", "")
        for c in raw.get("cards", []):
            cid = c["card_id"]
            if strict and cid in all_cards:
                raise ValueError(f"Kütüphane genelinde mükerrer card_id: '{cid}'")
            all_cards[cid] = LegalKnowledgeCard(
                card_id=cid,
                source_id=c["source_id"],
                law_no=str(c["law_no"]),
                law_title=law_title,
                article_ref=c["article_ref"],
                topic=c["topic"],
                legal_basis=c["legal_basis"],
                scope_of_application=c["scope_of_application"],
                exceptions=tuple(c["exceptions"]),
                required_documents=tuple(c["required_documents"]),
                related_precedent_ids=tuple(c.get("related_precedent_ids", [])),
                precedent_note=c["precedent_note"],
                effective_validity=c["effective_validity"],
                norm_character=c["norm_character"],
                risks=tuple(c["risks"]),
                primary_specialist=c["primary_specialist"],
                collaborating_specialists=tuple(c.get("collaborating_specialists", [])),
                disclaimer=c["disclaimer"],
                verification_status=c["verification_status"],
                source_verification=c["source_verification"],
                legal_interpretation_verification=c["legal_interpretation_verification"],
                verification_audit=c["verification_audit"],
                application_scenarios=tuple(c.get("application_scenarios", [])),
                data_category_controls=tuple(c.get("data_category_controls", [])),
                special_calculation_rules=dict(c.get("special_calculation_rules", {})),
                statutory_subordination=c.get("statutory_subordination"),
                keywords=tuple(c.get("keywords", [])),
            )
    return all_cards


def query_knowledge_cards(
    cards: dict[str, LegalKnowledgeCard],
    query: str,
    as_of_date: str,
    law_no: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Query verified knowledge cards filtered by article-level effective date and dual verification status."""
    target_dt = parse_iso_date(as_of_date)
    if target_dt is None:
        raise ValueError(f"Geçersiz as_of_date: '{as_of_date}'")

    q_tokens = {tok for tok in TOKEN_RE.findall(_tr_lower(query)) if len(tok) >= 3 or tok.isdigit()}
    effective_matches: list[tuple[int, LegalKnowledgeCard]] = []
    not_yet_or_expired: list[dict[str, Any]] = []

    for card in cards.values():
        if law_no and card.law_no != str(law_no):
            continue
        haystack = " ".join(
            [
                card.card_id,
                card.law_no,
                card.law_title,
                card.article_ref,
                card.topic,
                card.scope_of_application,
                *card.keywords,
            ]
        )
        h_tokens = {tok for tok in TOKEN_RE.findall(_tr_lower(haystack)) if len(tok) >= 3 or tok.isdigit()}
        score = len(q_tokens & h_tokens)
        if card.law_no in query:
            score += 4
        if score <= 0:
            continue

        eff = card.effective_validity
        eff_from = parse_iso_date(eff.get("effective_from"))
        eff_to = parse_iso_date(eff.get("effective_to"))
        in_window = eff_from is not None and eff_to is not None and eff_from <= target_dt <= eff_to
        dual_verified = (
            card.verification_status == "VERIFIED"
            and eff.get("effective_date_verified") is True
            and card.source_verification.get("status") == "VERIFIED"
            and card.legal_interpretation_verification.get("status") == "VERIFIED"
        )
        if dual_verified and in_window:
            effective_matches.append((score, card))
        else:
            not_yet_or_expired.append(
                {
                    "card_id": card.card_id,
                    "law_no": card.law_no,
                    "article_ref": card.article_ref,
                    "effective_from": eff.get("effective_from"),
                    "effective_to": eff.get("effective_to"),
                    "verification_status": card.verification_status,
                }
            )

    effective_matches.sort(key=lambda x: (-x[0], x[1].card_id))
    return {
        "effective_cards": [c.to_dict() for _, c in effective_matches],
        "not_effective_on_date_cards": not_yet_or_expired,
    }


def validate_central_audit_log(
    raw_audit_log: dict[str, Any],
    source_registry: dict[str, LegalSourceRecord],
    precedent_registry: dict[str, PrecedentRecord],
    knowledge_cards: dict[str, LegalKnowledgeCard],
    *,
    project_root: Path | None = None,
    attestation_ledger: dict[str, Any] | None = None,
    approvers_registry: dict[str, Any] | None = None,
    expected_checkpoint_head_hash: str | None = None,
    expected_checkpoint_entry_count: int | None = None,
    expected_chain_digest_sha256: str | None = None,
    require_production_trust_anchor: bool = False,
) -> RegistryValidationReport:
    """Validate central verification_audit_log.json, safe-contained 2024–2027 holiday snapshots, two-stage integrity, and externally anchored attestation ledger."""
    flags: list[VerificationFlag] = []
    entries = raw_audit_log.get("entries")
    summary = raw_audit_log.get("summary")
    if not isinstance(entries, list) or not isinstance(summary, dict):
        flags.append(
            VerificationFlag(
                code="INVALID_AUDIT_LOG_STRUCTURE",
                severity="BLOCKER",
                message="verification_audit_log.json içinde 'summary' nesnesi ve 'entries' listesi zorunludur.",
            )
        )
        return RegistryValidationReport("verification_audit_log", False, 0, 0, flags)

    by_aid: dict[str, dict[str, Any]] = {}
    for entry in entries:
        aid = str(entry.get("audit_log_id", ""))
        if not aid or aid in by_aid:
            flags.append(
                VerificationFlag(
                    code="DUPLICATE_OR_MISSING_AUDIT_LOG_ID",
                    severity="BLOCKER",
                    message=f"Merkezi denetim defterinde eksik veya mükerrer audit_log_id: '{aid}'.",
                    evidence=aid,
                )
            )
            continue
        by_aid[aid] = entry

        rec_type = entry.get("record_type")
        rec_status = entry.get("record_verification_status")
        if rec_type in {"LEGAL_SOURCE", "YARGITAY_PRECEDENT"}:
            if rec_status == "VERIFIED" and entry.get("document_fetch_status") != "FETCHED_AND_MATCHED":
                flags.append(
                    VerificationFlag(
                        code="AUDIT_LOG_VERIFIED_WITHOUT_FULL_TEXT",
                        severity="BLOCKER",
                        message=(
                            f"Merkezi denetim kaydı '{aid}' ({entry.get('record_id')}) "
                            f"document_fetch_status='{entry.get('document_fetch_status')}' iken "
                            f"record_verification_status='VERIFIED' olamaz."
                        ),
                        evidence=aid,
                    )
                )

    def _check_binding(
        expected_type: str,
        rec_id: str,
        aid: str | None,
        actual_status: str,
        actual_fetch: str | None = None,
    ) -> None:
        if not aid or aid not in by_aid:
            flags.append(
                VerificationFlag(
                    code="MISSING_CENTRAL_AUDIT_LOG_ENTRY",
                    severity="BLOCKER",
                    message=f"{expected_type} '{rec_id}' için merkezi denetim kaydı '{aid}' eksik.",
                    evidence=f"{rec_id}:{aid}",
                )
            )
            return
        entry = by_aid[aid]
        if entry.get("record_type") != expected_type or entry.get("record_id") != rec_id:
            flags.append(
                VerificationFlag(
                    code="CENTRAL_AUDIT_LOG_MISMATCH",
                    severity="BLOCKER",
                    message=f"Merkezi denetim kaydı '{aid}' record_type/record_id değerleri '{rec_id}' ile uyuşmuyor.",
                    evidence=f"{rec_id}:{aid}",
                )
            )
        if entry.get("record_verification_status") != actual_status:
            flags.append(
                VerificationFlag(
                    code="CENTRAL_AUDIT_STATUS_MISMATCH",
                    severity="BLOCKER",
                    message=(
                        f"{expected_type} '{rec_id}' için kayıt statüsü '{actual_status}' iken "
                        f"denetim defterinde '{entry.get('record_verification_status')}' görünüyor."
                    ),
                    evidence=f"{rec_id}:{aid}",
                )
            )
        if actual_fetch is not None and entry.get("document_fetch_status") != actual_fetch:
            flags.append(
                VerificationFlag(
                    code="CENTRAL_AUDIT_FETCH_STATUS_MISMATCH",
                    severity="BLOCKER",
                    message=(
                        f"{expected_type} '{rec_id}' için document_fetch_status '{actual_fetch}' iken "
                        f"denetim defterinde '{entry.get('document_fetch_status')}' görünüyor."
                    ),
                    evidence=f"{rec_id}:{aid}",
                )
            )

    for src in source_registry.values():
        _check_binding(
            "LEGAL_SOURCE",
            src.source_id,
            src.verification_audit.audit_log_id if src.verification_audit else None,
            src.verification_status,
            src.verification_audit.document_fetch_status if src.verification_audit else None,
        )
    for prec in precedent_registry.values():
        _check_binding(
            "YARGITAY_PRECEDENT",
            prec.precedent_id,
            prec.verification_audit.audit_log_id if prec.verification_audit else None,
            prec.verification_status,
            prec.verification_audit.document_fetch_status if prec.verification_audit else None,
        )
    for card in knowledge_cards.values():
        _check_binding(
            "KNOWLEDGE_CARD",
            card.card_id,
            card.verification_audit.get("audit_log_id"),
            card.verification_status,
        )

    expected_counts = {
        "total_audited_records": len(source_registry) + len(precedent_registry) + len(knowledge_cards),
        "legal_sources_count": len(source_registry),
        "verified_legal_sources_count": sum(1 for s in source_registry.values() if s.verification_status == "VERIFIED"),
        "pending_legal_sources_count": sum(
            1 for s in source_registry.values() if s.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}
        ),
        "superseded_legal_sources_count": sum(
            1 for s in source_registry.values() if s.verification_status in {"SUPERSEDED", "REPEALED"}
        ),
        "yargitay_precedents_count": len(precedent_registry),
        "verified_yargitay_precedents_count": sum(
            1 for p in precedent_registry.values() if p.verification_status == "VERIFIED"
        ),
        "pending_yargitay_precedents_count": sum(
            1 for p in precedent_registry.values() if p.verification_status in {"PENDING_REVIEW", "UNVERIFIED"}
        ),
        "knowledge_cards_count": len(knowledge_cards),
        "verified_knowledge_cards_count": sum(1 for c in knowledge_cards.values() if c.verification_status == "VERIFIED"),
        "pending_knowledge_cards_count": sum(
            1
            for c in knowledge_cards.values()
            if c.verification_status in {"PENDING_LEGAL_REVIEW", "PENDING_EFFECTIVE_DATE_CHECK", "DRAFT"}
        ),
        "fetched_and_matched_documents_count": sum(
            1
            for s in source_registry.values()
            if s.verification_audit and s.verification_audit.document_fetch_status == "FETCHED_AND_MATCHED"
        )
        + sum(
            1
            for p in precedent_registry.values()
            if p.verification_audit and p.verification_audit.document_fetch_status == "FETCHED_AND_MATCHED"
        ),
        "pending_ocr_or_live_text_count": sum(
            1
            for s in source_registry.values()
            if s.verification_audit and s.verification_audit.document_fetch_status != "FETCHED_AND_MATCHED"
        )
        + sum(
            1
            for p in precedent_registry.values()
            if p.verification_audit and p.verification_audit.document_fetch_status != "FETCHED_AND_MATCHED"
        ),
    }
    expected_counts["fully_verified_records_count"] = (
        expected_counts["verified_legal_sources_count"]
        + expected_counts["verified_yargitay_precedents_count"]
        + expected_counts["verified_knowledge_cards_count"]
    )
    expected_counts["pending_verification_records_count"] = (
        expected_counts["pending_legal_sources_count"]
        + expected_counts["pending_yargitay_precedents_count"]
        + expected_counts["pending_knowledge_cards_count"]
    )
    expected_counts["superseded_records_count"] = expected_counts["superseded_legal_sources_count"]

    if len(entries) != expected_counts["total_audited_records"]:
        flags.append(
            VerificationFlag(
                code="AUDIT_LOG_SUMMARY_MISMATCH",
                severity="BLOCKER",
                message=f"Denetim defteri kayıt sayısı ({len(entries)}) beklenen toplamla ({expected_counts['total_audited_records']}) uyuşmuyor.",
                evidence="entries",
            )
        )
    for field_name, exp_val in expected_counts.items():
        actual_val = summary.get(field_name)
        if actual_val != exp_val:
            flags.append(
                VerificationFlag(
                    code="AUDIT_LOG_SUMMARY_MISMATCH",
                    severity="BLOCKER",
                    message=f"summary.{field_name}={actual_val} beklenen değerle ({exp_val}) uyuşmuyor.",
                    evidence=field_name,
                )
            )

    cal_audit = raw_audit_log.get("holiday_calendar_audit")
    if cal_audit is None:
        flags.append(
            VerificationFlag(
                code="MISSING_HOLIDAY_CALENDAR_AUDIT",
                severity="BLOCKER",
                message="Merkezi verification_audit_log.json içinde 'holiday_calendar_audit' bölümü zorunludur ve silinemez.",
                evidence="holiday_calendar_audit",
                remediation="Doğrulanmış Diyanet dinî bayram takvimi kapsam, kaynak URL ve yıllık doğrulama kayıtlarını holiday_calendar_audit altında tanımlayın.",
            )
        )
    elif not isinstance(cal_audit, dict):
        flags.append(
            VerificationFlag(
                code="INVALID_HOLIDAY_CALENDAR_AUDIT",
                severity="BLOCKER",
                message="holiday_calendar_audit bir JSON nesnesi olmalıdır.",
                evidence="holiday_calendar_audit",
            )
        )
    else:
        from datetime import date as _date
        from .attestation_verifier import (
            resolve_safe_project_path,
            verify_attestation_ledger,
            verify_holiday_source_snapshot,
            verify_signed_calendar_attestation,
        )
        from .legal_reasoning import (
            OFFICIAL_HOLIDAY_CALENDAR_DOMAINS,
            TURKISH_RELIGIOUS_FULL_HOLIDAYS,
            TURKISH_RELIGIOUS_HALF_DAY_EVES,
            validate_external_yearly_holiday_calendar,
        )
        from .source_validator import DISALLOWED_VERIFIERS, is_specific_official_url

        root = project_root if project_root is not None else Path(__file__).resolve().parent.parent

        req_cal_fields = (
            "calendar_id",
            "calendar_version",
            "verification_status",
            "statutory_basis",
            "official_source_authority",
            "official_source_urls",
            "coverage_start_year",
            "coverage_end_year",
            "covered_years",
            "yearly_records",
            "verified_at",
            "verified_by",
            "uncovered_year_policy",
            "half_day_eve_legal_rule_status",
        )
        missing_cal = [k for k in req_cal_fields if not cal_audit.get(k)]
        if missing_cal:
            flags.append(
                VerificationFlag(
                    code="INCOMPLETE_HOLIDAY_CALENDAR_AUDIT",
                    severity="BLOCKER",
                    message=f"holiday_calendar_audit içinde zorunlu alan(lar) eksik: {missing_cal}.",
                    evidence="holiday_calendar_audit",
                )
            )

        if cal_audit.get("qualified_e_signature_5070_equivalent") is True:
            flags.append(
                VerificationFlag(
                    code="INVALID_5070_EQUIVALENCE_CLAIM",
                    severity="BLOCKER",
                    message="Ed25519 / RSA-PSS-SHA256 doğrulaması 5070 sayılı Elektronik İmza Kanunu kapsamındaki güvenli elektronik imza ile eşdeğer beyan edilemez.",
                    evidence="holiday_calendar_audit.qualified_e_signature_5070_equivalent",
                )
            )

        top_status = str(cal_audit.get("verification_status") or "").strip().upper()
        top_verified_at_ok = parse_iso_date(str(cal_audit.get("verified_at") or "")) is not None
        if not top_verified_at_ok:
            flags.append(
                VerificationFlag(
                    code="INVALID_HOLIDAY_CALENDAR_VERIFIED_DATE",
                    severity="BLOCKER",
                    message=f"holiday_calendar_audit.verified_at geçerli ISO tarih değil: '{cal_audit.get('verified_at')}'.",
                    evidence="holiday_calendar_audit.verified_at",
                )
            )

        top_verified_by = str(cal_audit.get("verified_by") or "").strip()
        top_verifier_ok = len(top_verified_by) >= 3 and top_verified_by.upper() not in DISALLOWED_VERIFIERS
        if not top_verifier_ok:
            flags.append(
                VerificationFlag(
                    code="INVALID_HOLIDAY_CALENDAR_VERIFIER",
                    severity="BLOCKER",
                    message=f"holiday_calendar_audit.verified_by geçerli bir doğrulayan bilgisi değildir: '{top_verified_by}'.",
                    evidence="holiday_calendar_audit.verified_by",
                )
            )

        top_version_ok = bool(str(cal_audit.get("calendar_version") or "").strip())
        if top_status in {"VERIFIED", "TECHNICAL_VERIFIED_PENDING_LEGAL_ATTESTATION"} and (
            not top_verified_at_ok or not top_verifier_ok or not top_version_ok
        ):
            flags.append(
                VerificationFlag(
                    code="HOLIDAY_CALENDAR_VERIFIED_WITHOUT_PROVENANCE",
                    severity="BLOCKER",
                    message="holiday_calendar_audit kaynak/doğrulama tarihi/doğrulayan/sürüm bilgileri eksik veya geçersizken doğrulanmış statü kabul edilemez.",
                    evidence="holiday_calendar_audit.verification_status",
                )
            )

        # Load authorized approvers & tamper-evident attestation ledger safely inside project_root
        eff_approvers = approvers_registry
        if eff_approvers is None:
            appr_rel = cal_audit.get("authorized_approvers_path") or "config/authorized_approvers.json"
            appr_safe, appr_err_code, appr_err_msg = resolve_safe_project_path(appr_rel, project_root=root)
            if appr_err_code is not None:
                flags.append(
                    VerificationFlag(
                        code=appr_err_code,
                        severity="BLOCKER",
                        message=f"holiday_calendar_audit.authorized_approvers_path güvenlik ihlali: {appr_err_msg}",
                        evidence="holiday_calendar_audit.authorized_approvers_path",
                    )
                )
            elif appr_safe is not None and appr_safe.is_file():
                eff_approvers = json.loads(appr_safe.read_text(encoding="utf-8"))

        eff_ledger = attestation_ledger
        if eff_ledger is None:
            led_rel = cal_audit.get("attestation_ledger_path") or "config/calendar_attestation_ledger.json"
            led_safe, led_err_code, led_err_msg = resolve_safe_project_path(led_rel, project_root=root)
            if led_err_code is not None:
                flags.append(
                    VerificationFlag(
                        code=led_err_code,
                        severity="BLOCKER",
                        message=f"holiday_calendar_audit.attestation_ledger_path güvenlik ihlali: {led_err_msg}",
                        evidence="holiday_calendar_audit.attestation_ledger_path",
                    )
                )
            elif led_safe is not None and led_safe.is_file():
                eff_ledger = json.loads(led_safe.read_text(encoding="utf-8"))

        top_claims_legal_complete_early = (
            top_status == "VERIFIED"
            or str(cal_audit.get("legal_attestation_status") or "").upper() == "SIGNED_LEGAL_ATTESTATION_VERIFIED"
            or cal_audit.get("production_use_authorized") is True
        )
        declared_anchor_status = str(cal_audit.get("ledger_trust_anchor_status") or "").strip().upper()

        ledger_entries_by_id: dict[str, dict[str, Any]] = {}
        if not isinstance(eff_ledger, dict):
            flags.append(
                VerificationFlag(
                    code="AUDIT_CHAIN_TAMPERING_DETECTED",
                    severity="BLOCKER",
                    message="Değiştirilemez takvim doğrulama zinciri (calendar_attestation_ledger.json) bulunamadı veya okunamadı.",
                    evidence="holiday_calendar_audit.attestation_ledger_path",
                )
            )
        else:
            led_report = verify_attestation_ledger(
                eff_ledger,
                approvers_registry=eff_approvers,
                runtime_environment="PRODUCTION",
                expected_checkpoint_head_hash=expected_checkpoint_head_hash,
                expected_checkpoint_entry_count=expected_checkpoint_entry_count,
                expected_chain_digest_sha256=expected_chain_digest_sha256,
                require_signed_checkpoints=True,
            )
            if (
                not led_report["mathematical_chain_intact"]
                or "AUDIT_CHAIN_TAMPERING_DETECTED" in led_report["error_codes"]
                or "UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER" in led_report["error_codes"]
            ):
                if "UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER" in led_report["error_codes"]:
                    flags.append(
                        VerificationFlag(
                            code="UNTRUSTED_SELF_DECLARED_ANCHOR_IN_LEDGER",
                            severity="BLOCKER",
                            message=f"Denetim defterinde güvenilmez öz-çapa alanı tespit edildi: {'; '.join(led_report['errors'])}",
                            evidence="calendar_attestation_ledger",
                        )
                    )
                flags.append(
                    VerificationFlag(
                        code="AUDIT_CHAIN_TAMPERING_DETECTED",
                        severity="BLOCKER",
                        message=f"Takvim doğrulama hash zinciri bütünlük kontrolünden geçemedi: {'; '.join(led_report['errors'])}",
                        evidence="calendar_attestation_ledger",
                    )
                )
            if (
                require_production_trust_anchor
                or top_claims_legal_complete_early
                or declared_anchor_status == "EXTERNALLY_VERIFIED_IMMUTABLE"
            ) and not led_report["externally_verified_immutable"]:
                flags.append(
                    VerificationFlag(
                        code="EXTERNAL_TRUST_ANCHOR_REQUIRED",
                        severity="BLOCKER",
                        message=(
                            f"Takvim denetim zinciri harici güven kökü (imzalı checkpoint veya WORM/TSA çapa) ile "
                            f"doğrulanmamıştır (durum={led_report['trust_anchor_status']}); üretim yetkisi veya "
                            f"EXTERNALLY_VERIFIED_IMMUTABLE statüsü verilemez."
                        ),
                        evidence="calendar_attestation_ledger",
                    )
                )
            for le in eff_ledger.get("entries", []):
                if isinstance(le, dict) and le.get("entry_id"):
                    ledger_entries_by_id[str(le["entry_id"])] = le

        # Consistency across covered_years, coverage_start_year, coverage_end_year
        covered_years = cal_audit.get("covered_years")
        start_yr = cal_audit.get("coverage_start_year")
        end_yr = cal_audit.get("coverage_end_year")
        valid_years_list: list[int] = []
        if (
            not isinstance(covered_years, list)
            or not covered_years
            or any(isinstance(y, bool) or not isinstance(y, int) for y in covered_years)
            or len(set(covered_years)) != len(covered_years)
            or covered_years != sorted(covered_years)
        ):
            flags.append(
                VerificationFlag(
                    code="HOLIDAY_CALENDAR_YEAR_RANGE_MISMATCH",
                    severity="BLOCKER",
                    message=f"holiday_calendar_audit.covered_years artan ve benzersiz tamsayı yıllardan oluşmalıdır: {covered_years!r}.",
                    evidence="holiday_calendar_audit.covered_years",
                )
            )
        else:
            valid_years_list = list(covered_years)
            expected_range = list(range(valid_years_list[0], valid_years_list[-1] + 1))
            if (
                isinstance(start_yr, bool)
                or isinstance(end_yr, bool)
                or start_yr != valid_years_list[0]
                or end_yr != valid_years_list[-1]
                or valid_years_list != expected_range
            ):
                flags.append(
                    VerificationFlag(
                        code="HOLIDAY_CALENDAR_YEAR_RANGE_MISMATCH",
                        severity="BLOCKER",
                        message=(
                            f"covered_years ({valid_years_list}), coverage_start_year ({start_yr}) ve "
                            f"coverage_end_year ({end_yr}) arasında tutarsızlık/boşluk var."
                        ),
                        evidence="holiday_calendar_audit.covered_years",
                    )
                )

        # Bidirectional consistency between covered_years and official_source_urls
        urls = cal_audit.get("official_source_urls")
        if not isinstance(urls, dict):
            flags.append(
                VerificationFlag(
                    code="MISSING_HOLIDAY_CALENDAR_OFFICIAL_URL",
                    severity="BLOCKER",
                    message="holiday_calendar_audit.official_source_urls bir JSON nesnesi olmalıdır.",
                    evidence="holiday_calendar_audit.official_source_urls",
                )
            )
        else:
            url_year_keys = {int(k) for k in urls.keys() if isinstance(k, str) and k.isdigit() and len(k) == 4}
            if valid_years_list:
                extra_url_years = sorted(url_year_keys - set(valid_years_list))
                if extra_url_years:
                    flags.append(
                        VerificationFlag(
                            code="HOLIDAY_CALENDAR_URL_CONSISTENCY_MISMATCH",
                            severity="BLOCKER",
                            message=(
                                f"official_source_urls içinde covered_years ({valid_years_list}) listesinde bulunmayan "
                                f"çelişkili yıl anahtarı/anahtarları var: {extra_url_years}."
                            ),
                            evidence="holiday_calendar_audit.official_source_urls",
                        )
                    )
                for yr in valid_years_list:
                    yr_url = str(urls.get(str(yr)) or "")
                    url_ok, url_reason = is_specific_official_url(
                        yr_url,
                        allowed_domains=OFFICIAL_HOLIDAY_CALENDAR_DOMAINS,
                    )
                    if not url_ok:
                        flags.append(
                            VerificationFlag(
                                code="MISSING_HOLIDAY_CALENDAR_OFFICIAL_URL",
                                severity="BLOCKER",
                                message=f"holiday_calendar_audit kapsamındaki {yr} yılı için geçerli resmî HTTPS kaynak URL'si eksik/geçersiz: {url_reason}",
                                evidence=f"holiday_calendar_audit.official_source_urls.{yr}",
                            )
                        )
                        if top_status in {"VERIFIED", "TECHNICAL_VERIFIED_PENDING_LEGAL_ATTESTATION"}:
                            flags.append(
                                VerificationFlag(
                                    code="HOLIDAY_CALENDAR_VERIFIED_WITHOUT_PROVENANCE",
                                    severity="BLOCKER",
                                    message=f"{yr} yılı resmî kaynak URL'si eksik/geçersizken holiday_calendar_audit doğrulanmış kabul edilemez.",
                                    evidence=f"holiday_calendar_audit.official_source_urls.{yr}",
                                )
                            )

        # Per-year full-day & half-day coverage + archived snapshot Stage 1 + two-stage + ledger + runtime engine sync checks
        yearly_records = cal_audit.get("yearly_records")
        all_years_production_attested = bool(valid_years_list)
        if not isinstance(yearly_records, dict):
            all_years_production_attested = False
            flags.append(
                VerificationFlag(
                    code="MISSING_HOLIDAY_CALENDAR_YEARLY_RECORD",
                    severity="BLOCKER",
                    message="holiday_calendar_audit.yearly_records her kapsanan yıl için tam gün ve yarım gün doğrulama kaydı içermelidir.",
                    evidence="holiday_calendar_audit.yearly_records",
                )
            )
        elif valid_years_list:
            rec_year_keys = {int(k) for k in yearly_records.keys() if isinstance(k, str) and k.isdigit() and len(k) == 4}
            extra_rec_years = sorted(rec_year_keys - set(valid_years_list))
            if extra_rec_years:
                flags.append(
                    VerificationFlag(
                        code="HOLIDAY_CALENDAR_YEAR_RANGE_MISMATCH",
                        severity="BLOCKER",
                        message=f"yearly_records içinde covered_years ({valid_years_list}) dışında çelişkili yıl(lar) var: {extra_rec_years}.",
                        evidence="holiday_calendar_audit.yearly_records",
                    )
                )

            for yr in valid_years_list:
                yr_rec = yearly_records.get(str(yr))
                if not isinstance(yr_rec, dict):
                    all_years_production_attested = False
                    flags.append(
                        VerificationFlag(
                            code="MISSING_HOLIDAY_CALENDAR_YEARLY_RECORD",
                            severity="BLOCKER",
                            message=f"holiday_calendar_audit.yearly_records içinde {yr} yılı kaydı eksik.",
                            evidence=f"holiday_calendar_audit.yearly_records.{yr}",
                        )
                    )
                    continue

                yr_check = validate_external_yearly_holiday_calendar(
                    yr,
                    yr_rec,
                    require_cryptographic_attestation=False,
                )
                yr_status = str(yr_rec.get("verification_status") or "").strip().upper()
                if yr_status in {"VERIFIED", "TECHNICAL_VERIFIED_PENDING_LEGAL_ATTESTATION"} and not yr_check["provenance_valid"]:
                    flags.append(
                        VerificationFlag(
                            code="HOLIDAY_CALENDAR_VERIFIED_WITHOUT_PROVENANCE",
                            severity="BLOCKER",
                            message=f"yearly_records.{yr} kaynak URL/doğrulama tarihi/doğrulayan/sürüm bilgisi eksik veya geçersizken doğrulanmış kabul edilemez.",
                            evidence=f"holiday_calendar_audit.yearly_records.{yr}",
                        )
                    )
                if not yr_check["valid"]:
                    flags.append(
                        VerificationFlag(
                            code="HOLIDAY_CALENDAR_YEARLY_COVERAGE_INCOMPLETE",
                            severity="BLOCKER",
                            message=f"yearly_records.{yr} tam/yarım gün takvim doğrulamasından geçemedi: {'; '.join(yr_check['errors'])}",
                            evidence=f"holiday_calendar_audit.yearly_records.{yr}",
                        )
                    )
                if (
                    yr_rec.get("full_day_coverage_verified") is not True
                    or yr_rec.get("half_day_coverage_verified") is not True
                    or yr_rec.get("full_day_religious_holidays_count") != 7
                    or yr_rec.get("half_day_religious_eves_count") != 2
                ):
                    flags.append(
                        VerificationFlag(
                            code="HOLIDAY_CALENDAR_YEARLY_COVERAGE_INCOMPLETE",
                            severity="BLOCKER",
                            message=(
                                f"yearly_records.{yr} için tam gün (7 gün, full_day_coverage_verified=true) ve "
                                f"yarım gün arife (2 gün, half_day_coverage_verified=true) kapsam doğrulaması eksiksiz olmalıdır."
                            ),
                            evidence=f"holiday_calendar_audit.yearly_records.{yr}",
                        )
                    )
                if isinstance(urls, dict) and urls.get(str(yr)) and yr_rec.get("official_source_url") != urls.get(str(yr)):
                    flags.append(
                        VerificationFlag(
                            code="HOLIDAY_CALENDAR_URL_CONSISTENCY_MISMATCH",
                            severity="BLOCKER",
                            message=(
                                f"yearly_records.{yr}.official_source_url ('{yr_rec.get('official_source_url')}') "
                                f"ile official_source_urls.{yr} ('{urls.get(str(yr))}') uyuşmuyor."
                            ),
                            evidence=f"holiday_calendar_audit.yearly_records.{yr}.official_source_url",
                        )
                    )

                # Stage 1: Real archived source snapshot SHA-256 + 9-slot Turkish parser match + safe project_root containment
                snap_chk = verify_holiday_source_snapshot(yr, yr_rec, project_root=root)
                if not snap_chk["valid"]:
                    if "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT" in snap_chk["error_codes"]:
                        snap_code = "SOURCE_SNAPSHOT_PATH_OUTSIDE_PROJECT_ROOT"
                    elif snap_chk["error_codes"]:
                        snap_code = snap_chk["error_codes"][0]
                    else:
                        snap_code = "SOURCE_SNAPSHOT_MISSING_OR_MISMATCH"
                    flags.append(
                        VerificationFlag(
                            code=snap_code,
                            severity="BLOCKER",
                            message=f"yearly_records.{yr} arşivli resmî kaynak belgesi doğrulaması başarısız: {'; '.join(snap_chk['errors'])}",
                            evidence=f"holiday_calendar_audit.yearly_records.{yr}.snapshot_path",
                        )
                    )

                # Immutable snapshot revision history check
                rev_hist = yr_rec.get("revision_history")
                if (
                    not isinstance(rev_hist, list)
                    or not rev_hist
                    or rev_hist[-1].get("snapshot_id") != yr_rec.get("snapshot_id")
                    or rev_hist[-1].get("source_document_sha256") != yr_rec.get("source_document_sha256")
                ):
                    flags.append(
                        VerificationFlag(
                            code="SOURCE_SNAPSHOT_MISSING_OR_MISMATCH",
                            severity="BLOCKER",
                            message=f"yearly_records.{yr} için değişmez revision_history kaydı eksik veya son sürüm snapshot_id/SHA-256 ile uyuşmuyor.",
                            evidence=f"holiday_calendar_audit.yearly_records.{yr}.revision_history",
                        )
                    )

                # Attestation ledger binding for technical snapshot
                led_id = str(yr_rec.get("ledger_entry_id") or "")
                led_entry = ledger_entries_by_id.get(led_id)
                if led_entry is None:
                    flags.append(
                        VerificationFlag(
                            code="AUDIT_CHAIN_TAMPERING_DETECTED",
                            severity="BLOCKER",
                            message=f"yearly_records.{yr} ledger_entry_id='{led_id}' takvim doğrulama zincirinde bulunamadı.",
                            evidence=f"holiday_calendar_audit.yearly_records.{yr}.ledger_entry_id",
                        )
                    )
                else:
                    lp = led_entry.get("payload") or {}
                    if (
                        lp.get("year") != yr
                        or lp.get("snapshot_id") != yr_rec.get("snapshot_id")
                        or lp.get("source_document_sha256") != yr_rec.get("source_document_sha256")
                    ):
                        flags.append(
                            VerificationFlag(
                                code="AUDIT_CHAIN_TAMPERING_DETECTED",
                                severity="BLOCKER",
                                message=f"yearly_records.{yr} snapshot_id/SHA-256 değerleri hash zincirindeki '{led_id}' kaydıyla uyuşmuyor.",
                                evidence=f"holiday_calendar_audit.yearly_records.{yr}.ledger_entry_id",
                            )
                        )

                # Stage 2 integrity: reject premature VERIFIED / SIGNED_LEGAL_ATTESTATION_VERIFIED / production_use_authorized=True without real cryptographic legal attestation!
                claims_legal_complete = (
                    yr_status == "VERIFIED"
                    or str(yr_rec.get("legal_attestation_status") or "").upper() == "SIGNED_LEGAL_ATTESTATION_VERIFIED"
                    or yr_rec.get("production_use_authorized") is True
                )
                if claims_legal_complete:
                    signed_chk = verify_signed_calendar_attestation(
                        yr,
                        yr_rec,
                        approvers_registry=eff_approvers,
                        attestation_ledger=eff_ledger,
                        project_root=root,
                        runtime_environment="PRODUCTION",
                        expected_checkpoint_head_hash=expected_checkpoint_head_hash,
                        expected_checkpoint_entry_count=expected_checkpoint_entry_count,
                        expected_chain_digest_sha256=expected_chain_digest_sha256,
                    )
                    if not (signed_chk["valid"] and signed_chk["production_use_authorized"]):
                        all_years_production_attested = False
                        flags.append(
                            VerificationFlag(
                                code="TWO_STAGE_VERIFICATION_INCOMPLETE",
                                severity="BLOCKER",
                                message=(
                                    f"yearly_records.{yr} için tam hukuki doğrulama/üretim yetkisi (VERIFIED / production_use_authorized=true) "
                                    f"beyan edilmiş ancak yetkili hukuk müşavirinin kriptografik imzalı onayı doğrulanamamıştır: {'; '.join(signed_chk['errors'])}"
                                ),
                                evidence=f"holiday_calendar_audit.yearly_records.{yr}",
                            )
                        )
                else:
                    all_years_production_attested = False

                # Runtime engine table cross-check (both full-day and half-day tables)
                engine_full = TURKISH_RELIGIOUS_FULL_HOLIDAYS.get(yr)
                engine_eves = TURKISH_RELIGIOUS_HALF_DAY_EVES.get(yr)
                if not engine_full or not engine_eves:
                    flags.append(
                        VerificationFlag(
                            code="HOLIDAY_CALENDAR_ENGINE_SYNC_MISMATCH",
                            severity="BLOCKER",
                            message=f"Denetim defterinde kapsanan {yr} yılı çalışma zamanı motorunun tam gün veya yarım gün takviminde eksik.",
                            evidence=f"holiday_calendar_audit.covered_years.{yr}",
                        )
                    )
                elif yr_check["valid"]:
                    engine_full_dates = {_date(yr, m, d) for (m, d) in engine_full.keys()}
                    engine_eve_dates = {_date(yr, m, d) for (m, d) in engine_eves.keys()}
                    if engine_full_dates != set(yr_check["full_holidays"].keys()) or engine_eve_dates != set(
                        yr_check["half_day_eves"].keys()
                    ):
                        flags.append(
                            VerificationFlag(
                                code="HOLIDAY_CALENDAR_ENGINE_SYNC_MISMATCH",
                                severity="BLOCKER",
                                message=f"yearly_records.{yr} tam/yarım gün tarihleri çalışma zamanı motor takvimiyle birebir eşleşmiyor.",
                                evidence=f"holiday_calendar_audit.yearly_records.{yr}",
                            )
                        )

            engine_years = sorted(set(TURKISH_RELIGIOUS_FULL_HOLIDAYS.keys()) | set(TURKISH_RELIGIOUS_HALF_DAY_EVES.keys()))
            if valid_years_list != engine_years:
                flags.append(
                    VerificationFlag(
                        code="HOLIDAY_CALENDAR_ENGINE_SYNC_MISMATCH",
                        severity="BLOCKER",
                        message=f"holiday_calendar_audit.covered_years ({valid_years_list}) ile motor dahili takvim yılları ({engine_years}) uyuşmuyor.",
                        evidence="holiday_calendar_audit.covered_years",
                    )
                )

        # Top-level two-stage integrity check
        top_claims_legal_complete = (
            top_status == "VERIFIED"
            or str(cal_audit.get("legal_attestation_status") or "").upper() == "SIGNED_LEGAL_ATTESTATION_VERIFIED"
            or cal_audit.get("production_use_authorized") is True
        )
        if top_claims_legal_complete and not all_years_production_attested:
            flags.append(
                VerificationFlag(
                    code="TWO_STAGE_VERIFICATION_INCOMPLETE",
                    severity="BLOCKER",
                    message=(
                        "holiday_calendar_audit tüm kapsanan yıllar için yetkili hukuk müşavirinin kriptografik imzalı "
                        "üretim onayı doğrulanmadan VERIFIED veya production_use_authorized=true yapılamaz."
                    ),
                    evidence="holiday_calendar_audit.verification_status",
                )
            )

        if cal_audit.get("uncovered_year_policy") != "BLOCK_AND_ESCALATE_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE":
            flags.append(
                VerificationFlag(
                    code="INVALID_UNCOVERED_YEAR_POLICY",
                    severity="BLOCKER",
                    message="holiday_calendar_audit.uncovered_year_policy mutlaka BLOCK_AND_ESCALATE_HOLIDAY_CALENDAR_COVERAGE_INCOMPLETE olmalıdır.",
                    evidence="holiday_calendar_audit.uncovered_year_policy",
                )
            )

    has_blocker = any(f.severity == "BLOCKER" for f in flags)
    return RegistryValidationReport(
        registry_name="verification_audit_log",
        valid=not has_blocker,
        total_records=len(entries),
        verified_count=expected_counts["fully_verified_records_count"],
        flags=flags,
    )

