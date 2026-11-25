"""Evidence-backed legal answer linker and end-to-end traceability auditor (hrAI @HukukSGK v1.0.6 WP2.6).

Includes PR #3 Finding 3 remediation:
  - `verify_answer_traceability()` explicitly verifies `answer.registry_head_sha256` against
    `registry`'s current `head_sha256` (`EXACT_HEAD_MATCH`) and requires full raw-content archive
    verification (`require_raw_content=True`) by default.
  - If the registry has grown after the answer was generated (`HISTORICAL_SNAPSHOT_REGISTRY_GREW`),
    default strict mode (`allow_registry_growth=False`) FAILS CLOSED; explicit historical-ancestor
    audit mode (`allow_registry_growth=True`) verifies `answer.registry_head_sha256` is an authentic
    earlier chain entry and reports `answer_bound_to_older_snapshot=True`.
  - Unknown or forked `registry_head_sha256` (`UNKNOWN_OR_FORKED_REGISTRY_HEAD`) ALWAYS fails closed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .evidence_registry import EvidenceRegistry
from .models import (
    HEAD_STATUS_EXACT_MATCH,
    HEAD_STATUS_HISTORICAL_GREW,
    HEAD_STATUS_UNKNOWN_OR_FORKED,
    TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE,
    TRUST_CHAIN_VERSION,
    AnswerEvidenceLink,
    AnswerLinkageError,
    EvidenceLinkedAnswer,
    TrustChainError,
    canonical_sha256,
    parse_strict_iso_date,
)


def _compute_answer_sha256(
    *,
    query: str,
    as_of_date: str,
    generated_at_utc: str,
    answer_text: str,
    evidence_links: tuple[AnswerEvidenceLink, ...],
    historical_disclosure_text: str | None,
    registry_head_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "trust_chain_version": TRUST_CHAIN_VERSION,
            "query": query,
            "as_of_date": as_of_date,
            "generated_at_utc": generated_at_utc,
            "answer_text": answer_text,
            "evidence_links": [lnk.to_dict() for lnk in evidence_links],
            "historical_disclosure_text": historical_disclosure_text,
            "registry_head_sha256": registry_head_sha256,
        }
    )


class EvidenceBackedLegalAnswerBuilder:
    """Binds `@HukukSGK` legal answers to content- and SHA-256-verified EvidenceRegistry records (fail-closed)."""

    def __init__(self, registry: EvidenceRegistry) -> None:
        if not isinstance(registry, EvidenceRegistry):
            raise AnswerLinkageError("INVALID_REGISTRY", "Geçerli bir EvidenceRegistry örneği zorunludur.")
        self._registry = registry

    def build_answer(
        self,
        *,
        query: str,
        answer_text: str,
        evidence_ids: list[str] | tuple[str, ...],
        as_of_date: str,
        require_live_verified: bool = False,
        allow_historical_superseded: bool = False,
        historical_disclosure_text: str | None = None,
        router_payload: dict[str, Any] | None = None,
    ) -> EvidenceLinkedAnswer:
        """Bind a legal answer to verified evidence IDs with full raw-content, effective-date & tamper enforcement."""
        if not isinstance(query, str) or len(query.strip()) < 3:
            raise AnswerLinkageError("INVALID_QUERY", "Hukuki sorgu ('query') en az 3 karakter olmalıdır.")
        if not isinstance(answer_text, str) or len(answer_text.strip()) < 5:
            raise AnswerLinkageError("INVALID_ANSWER_TEXT", "Hukuki cevap metni ('answer_text') boş olamaz.")

        try:
            target_date = parse_strict_iso_date(as_of_date, "as_of_date")
        except TrustChainError as exc:
            raise AnswerLinkageError(exc.error_code, exc.message) from exc

        reg_ok, reg_rep = self._registry.verify_integrity(require_raw_content=True)
        if not reg_ok:
            raise AnswerLinkageError(
                "EVIDENCE_REGISTRY_INTEGRITY_FAILED",
                f"Bütünlüğü veya ham belge arşivi doğrulanmamış kanıt defterinden hukuki cevap bağlanamaz: "
                f"{reg_rep['errors']}",
            )

        if not evidence_ids:
            raise AnswerLinkageError(
                "NO_EVIDENCE_IDS_PROVIDED",
                "Kanıta dayalı hukuki cevap için en az bir doğrulanmış evidence_id zorunludur.",
            )

        seen: set[str] = set()
        unique_ids: list[str] = []
        for eid in evidence_ids:
            if not isinstance(eid, str) or not eid.strip():
                raise AnswerLinkageError("INVALID_EVIDENCE_ID", f"Geçersiz evidence_id: {eid!r}")
            clean_id = eid.strip()
            if clean_id not in seen:
                seen.add(clean_id)
                unique_ids.append(clean_id)

        links: list[AnswerEvidenceLink] = []
        any_historical = False
        for eid in unique_ids:
            rec = self._registry.get(eid)
            if rec is None or not rec.is_verified_authority:
                raise AnswerLinkageError(
                    "EVIDENCE_NOT_FOUND_OR_UNVERIFIED",
                    f"Belirtilen kanıt kaydı bulunamadı veya doğrulanmamış: {eid!r}",
                )

            if require_live_verified and not rec.live_verified:
                raise AnswerLinkageError(
                    "LIVE_VERIFICATION_REQUIRED",
                    f"Canlı HTTPS doğrulaması zorunlu modda test/sahte taşıyıcı kanıtı ({eid}) reddedildi.",
                )

            eff_dt = parse_strict_iso_date(rec.effective_date, "effective_date")
            if target_date < eff_dt:
                raise AnswerLinkageError(
                    "EVIDENCE_NOT_YET_EFFECTIVE",
                    f"Kanıt ({eid}) yürürlük tarihi ({rec.effective_date}) değerlendirme tarihinden ({as_of_date}) sonradır.",
                )

            is_superseded = self._registry.is_superseded(eid)
            superseding = self._registry.get_superseding_record(eid)
            superseded_as_of_date = False
            if superseding is not None:
                sup_eff = parse_strict_iso_date(superseding.effective_date, "superseding.effective_date")
                superseded_as_of_date = sup_eff <= target_date

            repealed_as_of_date = False
            if rec.expiry_or_repeal_date is not None:
                exp_dt = parse_strict_iso_date(rec.expiry_or_repeal_date, "expiry_or_repeal_date")
                repealed_as_of_date = target_date > exp_dt

            if superseded_as_of_date or repealed_as_of_date:
                any_historical = True
                if not allow_historical_superseded or not (historical_disclosure_text and historical_disclosure_text.strip()):
                    raise AnswerLinkageError(
                        "SUPERSEDED_OR_REPEALED_EVIDENCE_REQUIRES_HISTORICAL_DISCLOSURE",
                        f"Kanıt ({eid}) {as_of_date} tarihi itibarıyla mülga veya daha yeni bir sürümle "
                        "değiştirilmiştir; açık tarihsel bildirim (historical_disclosure_text) olmadan bağlanamaz.",
                    )

            links.append(
                AnswerEvidenceLink(
                    evidence_id=rec.evidence_id,
                    source_key=rec.source_key,
                    adapter_type=rec.adapter_type,
                    title=rec.title,
                    source_url=rec.source_url,
                    final_url=rec.final_url,
                    acquired_at_utc=rec.acquired_at_utc,
                    publication_date=rec.publication_date,
                    effective_date=rec.effective_date,
                    expiry_or_repeal_date=rec.expiry_or_repeal_date,
                    version_number=rec.version_number,
                    supersedes_evidence_id=rec.supersedes_evidence_id,
                    is_current_version=not is_superseded,
                    is_superseded=is_superseded,
                    content_sha256=rec.content_sha256,
                    record_sha256=rec.record_sha256,
                    transport_mode=rec.transport_mode,
                    live_verified=rec.live_verified,
                    content_verified=rec.content_verified,
                )
            )

        links_tuple = tuple(links)
        generated_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        disclosure_norm = (
            historical_disclosure_text.strip()
            if (historical_disclosure_text and historical_disclosure_text.strip())
            else None
        )
        reg_head = str(reg_rep["head_sha256"])
        answer_sha = _compute_answer_sha256(
            query=query.strip(),
            as_of_date=as_of_date.strip(),
            generated_at_utc=generated_at_utc,
            answer_text=answer_text.strip(),
            evidence_links=links_tuple,
            historical_disclosure_text=disclosure_norm,
            registry_head_sha256=reg_head,
        )
        answer_id = f"ANS-HUKUKSGK-{answer_sha[:14].upper()}"

        return EvidenceLinkedAnswer(
            answer_id=answer_id,
            trust_chain_version=TRUST_CHAIN_VERSION,
            query=query.strip(),
            as_of_date=as_of_date.strip(),
            generated_at_utc=generated_at_utc,
            answer_text=answer_text.strip(),
            evidence_ids=tuple(unique_ids),
            evidence_links=links_tuple,
            all_evidence_verified=True,
            all_evidence_live_verified=all(lnk.live_verified for lnk in links_tuple),
            historical_disclosure_included=bool(any_historical and disclosure_norm),
            historical_disclosure_text=disclosure_norm,
            registry_head_sha256=reg_head,
            answer_sha256=answer_sha,
            router_payload=router_payload,
            production_use_authorized=False,
            qualified_e_signature_5070_equivalent=False,
            kvkk_data_residency_approved=False,
            legal_boundary_notice=TRUST_CHAIN_LEGAL_BOUNDARY_NOTICE,
        )


def verify_answer_traceability(
    answer: EvidenceLinkedAnswer,
    registry: EvidenceRegistry,
    *,
    allow_registry_growth: bool = False,
    require_raw_content: bool = True,
) -> tuple[bool, dict[str, Any]]:
    """Independently verify end-to-end traceability from `answer` back to `registry`, including registry head binding."""
    errors: list[str] = []
    reg_ok, reg_rep = registry.verify_integrity(require_raw_content=require_raw_content)
    if not reg_ok:
        errors.append(f"EvidenceRegistry bütünlük doğrulaması başarısız: {reg_rep['errors']}")

    # PR #3 Finding 3: Explicit answer.registry_head_sha256 vs current registry head verification!
    current_head = str(reg_rep["head_sha256"])
    head_idx = registry.record_index_by_sha256(answer.registry_head_sha256)
    if answer.registry_head_sha256 == current_head:
        head_status = HEAD_STATUS_EXACT_MATCH
        bound_to_older = False
    elif head_idx is not None:
        head_status = HEAD_STATUS_HISTORICAL_GREW
        bound_to_older = True
        if not allow_registry_growth:
            errors.append(
                f"REGISTRY_HEAD_MISMATCH_HISTORICAL_SNAPSHOT: cevap eski registry head değerine "
                f"({answer.registry_head_sha256}) bağlıdır; güncel registry head ({current_head}) değişmiştir."
            )
    else:
        head_status = HEAD_STATUS_UNKNOWN_OR_FORKED
        bound_to_older = False
        errors.append(
            f"REGISTRY_HEAD_UNKNOWN_OR_FORKED: cevabın bağlı olduğu registry_head_sha256 "
            f"({answer.registry_head_sha256}) mevcut registry zincirinde bulunamadı (güncel: {current_head})."
        )

    recomp_sha = _compute_answer_sha256(
        query=answer.query,
        as_of_date=answer.as_of_date,
        generated_at_utc=answer.generated_at_utc,
        answer_text=answer.answer_text,
        evidence_links=answer.evidence_links,
        historical_disclosure_text=answer.historical_disclosure_text,
        registry_head_sha256=answer.registry_head_sha256,
    )
    if recomp_sha != answer.answer_sha256:
        errors.append(f"answer_sha256 tahrifatı tespit edildi ({recomp_sha} != {answer.answer_sha256}).")

    expected_answer_id = f"ANS-HUKUKSGK-{recomp_sha[:14].upper()}"
    if answer.answer_id != expected_answer_id:
        errors.append(f"answer_id tahrifatı tespit edildi ({answer.answer_id!r} != {expected_answer_id!r}).")

    if not answer.evidence_links:
        errors.append("Cevap hiçbir kanıt bağlantısı içermiyor.")

    if tuple(lnk.evidence_id for lnk in answer.evidence_links) != answer.evidence_ids:
        errors.append("answer.evidence_ids ile answer.evidence_links kimlik listesi uyuşmuyor.")

    if not answer.all_evidence_verified:
        errors.append("answer.all_evidence_verified False olarak işaretlenmiş.")

    if answer.all_evidence_live_verified != all(lnk.live_verified for lnk in answer.evidence_links):
        errors.append("answer.all_evidence_live_verified bağlı kanıtların live_verified durumuyla uyuşmuyor.")

    if answer.production_use_authorized or answer.qualified_e_signature_5070_equivalent or answer.kvkk_data_residency_approved:
        errors.append("Kapalı üretim/5070/KVKK bayrakları ihlal edilmiş.")

    traced: list[dict[str, Any]] = []
    for lnk in answer.evidence_links:
        rec = registry.get(lnk.evidence_id)
        if rec is None or not rec.is_verified_authority:
            errors.append(f"Bağlı kanıt ({lnk.evidence_id}) defterde bulunamadı veya geçersiz.")
            continue
        if head_idx is not None:
            rec_idx = registry.record_index_by_id(lnk.evidence_id)
            if rec_idx is None or rec_idx > head_idx:
                errors.append(
                    f"EVIDENCE_POSTDATES_ANSWER_REGISTRY_HEAD: bağlı kanıt ({lnk.evidence_id}) "
                    f"cevabın bağlı olduğu registry_head_sha256 konumundan sonra eklenmiş."
                )
        for field_name in (
            "source_key",
            "adapter_type",
            "source_url",
            "final_url",
            "acquired_at_utc",
            "publication_date",
            "effective_date",
            "expiry_or_repeal_date",
            "version_number",
            "supersedes_evidence_id",
            "content_sha256",
            "record_sha256",
            "transport_mode",
            "live_verified",
            "content_verified",
        ):
            if getattr(lnk, field_name) != getattr(rec, field_name):
                errors.append(
                    f"Kanıt ({lnk.evidence_id}) '{field_name}' alanı defter kaydıyla uyuşmuyor "
                    f"({getattr(lnk, field_name)!r} != {getattr(rec, field_name)!r})."
                )
        traced.append(
            {
                "evidence_id": rec.evidence_id,
                "adapter_type": rec.adapter_type,
                "source_key": rec.source_key,
                "version_number": rec.version_number,
                "source_url": rec.source_url,
                "acquired_at_utc": rec.acquired_at_utc,
                "publication_date": rec.publication_date,
                "effective_date": rec.effective_date,
                "content_sha256": rec.content_sha256,
                "record_sha256": rec.record_sha256,
                "content_verified": rec.content_verified,
            }
        )

    valid = len(errors) == 0
    return valid, {
        "valid": valid,
        "answer_id": answer.answer_id,
        "registry_head_status": head_status,
        "answer_registry_head_sha256": answer.registry_head_sha256,
        "current_registry_head_sha256": current_head,
        "answer_bound_to_older_snapshot": bound_to_older,
        "full_content_archive_verified": bool(reg_rep.get("full_content_archive_verified", False)),
        "traced_evidence_count": len(traced),
        "traceability_chain": traced,
        "errors": errors,
    }
