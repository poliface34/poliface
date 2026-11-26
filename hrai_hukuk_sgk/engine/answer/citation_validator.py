"""Dual-layer fail-closed AnswerCitationValidator (CitationWhitelist + Article Check + 9 Guardrails)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from ..models import LegalSourceRecord, PrecedentRecord
from ..precedent_verifier import HISTORICAL_DISCLOSURE_MARKERS, LAW_CITATION_RE, URL_RE, verify_response_citations
from ..rag.models import CitationWhitelist, RetrievalTraceBundle
from ..source_validator import parse_iso_date
from .models import (
    CLAIM_JUDICIAL_PRECEDENT,
    CLAIM_LEGAL_INTERPRETATION,
    CLAIM_STATUTORY_EVIDENCE,
    AnswerCitationAuditReport,
    AnswerClaimRecord,
    EightSectionAnswer,
    TemporalValidationReport,
)

_LAW_ART_PAIR_RE = re.compile(
    r"(?<!\d)(?P<num>\d{3,5})\s+(?:[Ss]ayılı\s+(?:[A-ZÇĞİÖŞÜa-zçğıöşü\s]{0,55}?Kanun\w*\s+)?)?"
    r"(?:(?:Ek\s+Madde|Ek\s+m\.|Geçici\s+Madde|Geçici\s+m\.|Madde|m\.)\s*(?P<art>\d+))",
    re.IGNORECASE,
)
_PRECEDENT_BOILERPLATE_ARTICLES: frozenset[tuple[str, str]] = frozenset(
    {
        ("1136", "35"),   # Avukatlık Kanunu m.35 statutory role boundary
        ("2797", "45"),   # Yargıtay Kanunu m.45 YİBBGK statutory basis
        ("2575", "39"),   # Danıştay Kanunu m.39 İBK statutory basis
        ("7555", "23"),   # Amending article reference in official 7555 title/summary
        ("7499", "33"),   # Amending article reference in official 7499 title/summary
    }
)
_PROV_CODE_EXTRACT_RE = re.compile(r"\b(\d{3,5}):(?:m|ek|gecici)-(\d+)\b", re.IGNORECASE)
_CARD_LAW_ART_RE = re.compile(r"\bCARD-(\d{3,5})-.*?\bM(\d+)\b", re.IGNORECASE)
_ALT_CARD_M_RE = re.compile(r"\bM0?(\d+)\b")
_PAYROLL_OUTPUT_CALC_RE = re.compile(
    r"(?:hesaplanan\s+net\s+(?:kıdem(?:\s+tazminat[ıi])?|ihbar(?:\s+tazminat[ıi])?|ücret|tazminat[ıi]?)|ödenecek\s+net\s+tutar)\s*[:=]?\s*\d[\d.,]*\s*(?:tl|₺|lira)",
    re.IGNORECASE,
)
_FALSE_GATE_OPEN_RE = re.compile(
    r"(?:production_use_authorized|qualified_e_signature_5070_equivalent|kvkk_data_residency_approved)\s*=\s*true",
    re.IGNORECASE,
)


def _extract_whitelisted_law_articles(
    whitelist: CitationWhitelist,
    trace_bundle: RetrievalTraceBundle,
) -> tuple[set[tuple[str, str]], set[str]]:
    """Build exact `(law_no, article_num)` pairs authorized by active whitelist chunks."""
    pairs: set[tuple[str, str]] = set()
    laws: set[str] = set()

    for pid in whitelist.allowed_provision_ids:
        for law, art in _PROV_CODE_EXTRACT_RE.findall(pid):
            pairs.add((law, str(int(art))))
            laws.add(law)
        if pid.startswith("CARD-"):
            head_match = re.match(r"^CARD-(\d{3,5})-(.+)$", pid)
            if head_match:
                law = head_match.group(1)
                laws.add(law)
                for art in _ALT_CARD_M_RE.findall(head_match.group(2)):
                    pairs.add((law, str(int(art))))

    # Also read normalized law_no, article_no, AND verbatim cross-references inside verified active chunks
    active_wl_chunks = [
        item
        for item in (
            *trace_bundle.normative_bucket,
            *trace_bundle.interpretation_bucket,
            *trace_bundle.autonomous_norm_bucket,
        )
        if whitelist.contains_source(item.chunk.source_id) or whitelist.contains_provision(item.chunk.provision_id)
    ]
    for item in active_wl_chunks:
        ch = item.chunk
        if ch.law_no and ch.law_no.isdigit():
            laws.add(ch.law_no)
            if ch.article_no:
                m = re.search(r"(\d+)", ch.article_no)
                if m:
                    pairs.add((ch.law_no, str(int(m.group(1)))))
        blob = f"{ch.context_header} {ch.raw_text}"
        for r in item.companion_rules:
            for sc in r.how_to_interpret:
                blob += f" {sc.get('condition', '')} {sc.get('legal_rule', '')} {sc.get('statutory_basis', '')}"
            blob += " " + " ".join(r.exceptions) + " " + " ".join(r.counter_arguments_and_pitfalls)
        for law, art in _LAW_ART_PAIR_RE.findall(blob):
            pairs.add((law, str(int(art))))

    for sid in whitelist.allowed_source_ids:
        m = re.search(r"(?:MEVZUAT|RG|GIB-TEBLIG)-(\d{3,5})", sid)
        if m:
            laws.add(m.group(1))

    return pairs, laws


def _build_effective_precedents(
    base_precedents: dict[str, PrecedentRecord],
    wl: CitationWhitelist,
    trace_bundle: RetrievalTraceBundle,
    temporal_report: TemporalValidationReport | None,
) -> dict[str, PrecedentRecord]:
    """Include verified KB/sandbox precedents authorized in CitationWhitelist for Layer B E./K. auditing."""
    effective = dict(base_precedents)
    prec_items = (
        temporal_report.validated_precedent_items
        if temporal_report is not None
        else trace_bundle.precedent_bucket
    )
    for item in prec_items:
        ch = item.chunk
        pmeta = item.precedent_metadata or {}
        pid = str(pmeta.get("precedent_id") or ch.source_id or "")
        if not pid or pid in effective or not wl.contains_precedent(pid):
            continue
        if ch.verification_status != "VERIFIED":
            continue
        esas = str(pmeta.get("esas_no") or "").strip()
        karar = str(pmeta.get("karar_no") or "").strip()
        if not esas or not karar:
            continue
        effective[pid] = PrecedentRecord(
            precedent_id=pid,
            chamber=str(pmeta.get("chamber") or pmeta.get("court_system") or "YARGITAY"),
            binding_level=str(pmeta.get("binding_level") or "DANISTAY_DAIRE_SETTLED"),
            esas_no=esas,
            karar_no=karar,
            decision_date=ch.effective_from,
            official_source_url=str(item.source_url or "https://karararama.danistay.gov.tr/verified-kb"),
            related_source_ids=tuple(pmeta.get("related_source_ids") or ()),
            legal_principle=ch.context_header or ch.raw_text[:160],
            scope_limitations=tuple(pmeta.get("does_not_apply_to") or ()),
            verification_status="VERIFIED",
            verified_by="WP4_KB_VERIFIED_BUNDLE",
            last_verified_at=ch.effective_from,
            superseded_by=None,
            conflicting_precedent_ids=(),
            keywords=tuple(pmeta.get("keywords") or ()),
            operative_holding=ch.raw_text[:200],
        )
    return effective


def _sanitize_section_for_layer_b(
    *,
    section_key: str,
    section_text: str,
    overridden_sections: frozenset[str],
    verified_blobs: tuple[str, ...],
    registered_statute_nos: set[str],
    allowed_urls: frozenset[str],
) -> str:
    """Prepare non-overridden section text for Layer B without masking any user/override text."""
    text = section_text
    if section_key == "mevzuat_dayanagi" and section_key not in overridden_sections:
        if "\nTarihsel Bağlam (Yürürlük Dışı" in text:
            text = text.split("\nTarihsel Bağlam (Yürürlük Dışı", 1)[0]

    for allowed_u in allowed_urls:
        if "karararama.danistay.gov.tr/" in allowed_u and len(urlparse(allowed_u).path.strip("/")) >= 3:
            text = text.replace(allowed_u, "[DOGRULANMIS_DANISTAY_URL]")

    if section_key in overridden_sections:
        return text

    for blob in verified_blobs:
        if blob and blob in text:
            masked_blob = blob
            offset_shift = 0
            for m in LAW_CITATION_RE.finditer(blob):
                num = m.group("num")
                if num in registered_statute_nos:
                    continue
                repl = f"{num}-[DOGRULANMIS_ALINTI]"
                s, e = m.start() + offset_shift, m.end() + offset_shift
                masked_blob = masked_blob[:s] + repl + masked_blob[e:]
                offset_shift += len(repl) - (m.end() - m.start())
            if masked_blob != blob:
                text = text.replace(blob, masked_blob)

    if any("(7555 sayılı Kanun öncesi ilk metin" in b for b in verified_blobs):
        text = text.replace("7555 sayılı Kanun öncesi ilk metin", "[ONCEKI_REJIM_BASLIGI]")
    if any("7555 m.23 cümlesini henüz içermemektedir" in b for b in verified_blobs):
        text = text.replace("7555 m.23 cümlesini henüz içermemektedir", "[ONCESI_METIN_HENUZ_ICERMEMEKTEDIR]")

    return text


def _has_active_prior_article_rule(
    *,
    source_id: str,
    art_label: str,
    as_of_date: str,
    source_registry: dict[str, LegalSourceRecord],
    temporal_report: TemporalValidationReport | None,
) -> bool:
    """Return True if an amended article has an in-force prior regime (explicit rule or pre-amendment verified chunk)."""
    src = source_registry.get(source_id)
    target_dt = parse_iso_date(as_of_date)
    if src is None or target_dt is None or temporal_report is None:
        return False

    src_ef = parse_iso_date(src.effective_from)
    src_et = parse_iso_date(src.effective_to)
    if src_ef is not None and src_et is not None and not (src_ef <= target_dt <= src_et):
        return False

    has_explicit_prior = False
    has_future_only_rules = False
    matching_rules = [
        rule
        for rule in src.article_effective_rules
        if rule.article_ref == art_label or rule.article_ref.startswith(f"{art_label} (")
    ]
    for rule in matching_rules:
        ef = parse_iso_date(rule.effective_from)
        et = parse_iso_date(rule.effective_to)
        if ef is not None and et is not None and ef <= target_dt <= et:
            has_explicit_prior = True
            break
    if not has_explicit_prior and matching_rules:
        # Check if ALL declared article rules start AFTER target_dt (post-amendment rules only)
        if all(
            (parse_iso_date(rule.effective_from) is not None and target_dt < parse_iso_date(rule.effective_from))
            for rule in matching_rules
        ):
            has_future_only_rules = True

    if not has_explicit_prior and not has_future_only_rules:
        return False

    art_num_m = re.search(r"(\d+)", art_label)
    target_art_num = str(int(art_num_m.group(1))) if art_num_m else ""
    for item in temporal_report.active_normative_items:
        ch = item.chunk
        if ch.source_id != source_id or ch.verification_status not in {"VERIFIED", "SUPERSEDED"}:
            continue
        ef = parse_iso_date(ch.effective_from)
        et = parse_iso_date(ch.effective_to) if ch.effective_to else parse_iso_date("2999-12-31")
        if ef is None or et is None or not (ef <= target_dt <= et):
            continue
        ch_art_m = re.search(r"(\d+)", str(ch.article_no or ch.provision_id))
        if ch_art_m and str(int(ch_art_m.group(1))) == target_art_num:
            return True
    return False


class AnswerCitationValidator:
    """Two-layer fail-closed claim, whitelist, wrong-article, URL & guardrail validator."""

    def __init__(
        self,
        *,
        source_registry: dict[str, LegalSourceRecord] | None = None,
        precedent_registry: dict[str, PrecedentRecord] | None = None,
    ) -> None:
        self._sources = source_registry or {}
        self._precedents = precedent_registry or {}

    def validate(
        self,
        *,
        trace_bundle: RetrievalTraceBundle,
        sections: EightSectionAnswer,
        claims: tuple[AnswerClaimRecord, ...],
        should_abstain: bool,
        temporal_report: TemporalValidationReport | None = None,
        counsel_escalation_required: bool = False,
        payroll_handoff_allowed: bool = False,
        overridden_sections: frozenset[str] = frozenset(),
    ) -> AnswerCitationAuditReport:
        as_of_date = trace_bundle.as_of_date
        wl = trace_bundle.citation_whitelist
        blockers: list[tuple[str, str]] = []
        warnings: list[str] = []
        guardrail_flags: list[dict[str, Any]] = []
        matched_sources: list[str] = []
        matched_precs: list[str] = []

        # Layer A1: Every structured statutory/precedent/interpretation claim MUST belong to CitationWhitelist
        for clm in claims:
            if clm.claim_category in {CLAIM_STATUTORY_EVIDENCE, CLAIM_JUDICIAL_PRECEDENT, CLAIM_LEGAL_INTERPRETATION}:
                if not clm.effective_on_date:
                    blockers.append(
                        (
                            "RETROACTIVE_OR_INACTIVE_CLAIM_AS_ACTIVE",
                            f"'{clm.claim_id}' iddiası {as_of_date} tarihinde yürürlükte olmadığı halde aktif kanıt olarak sunulamaz.",
                        )
                    )
                    continue

                if clm.claim_category == CLAIM_JUDICIAL_PRECEDENT:
                    if not clm.precedent_id or not wl.contains_precedent(clm.precedent_id):
                        blockers.append(
                            (
                                "UNWHITELISTED_CITATION_BLOCKER",
                                f"'{clm.claim_id}' içtihat iddiası ({clm.precedent_id}) CitationWhitelist dışında.",
                            )
                        )
                    elif clm.precedent_id not in matched_precs:
                        matched_precs.append(clm.precedent_id)
                else:
                    if not clm.source_id or not wl.contains_source(clm.source_id):
                        blockers.append(
                            (
                                "UNWHITELISTED_CITATION_BLOCKER",
                                f"'{clm.claim_id}' kaynak iddiası ({clm.source_id}) CitationWhitelist dışında.",
                            )
                        )
                    elif clm.source_id not in matched_sources:
                        matched_sources.append(clm.source_id)

                    if clm.source_id and clm.source_id in wl.historical_only_source_ids:
                        blockers.append(
                            (
                                "TEMPORAL_RETROACTIVITY_VIOLATION_BLOCKED",
                                f"'{clm.claim_id}' yalnızca tarihsel kovadaki '{clm.source_id}' kaynağını aktif gibi kullanıyor.",
                            )
                        )

                    if clm.provision_id and not wl.contains_provision(clm.provision_id):
                        blockers.append(
                            (
                                "UNWHITELISTED_CITATION_BLOCKER",
                                f"'{clm.claim_id}' madde düğümü ({clm.provision_id}) CitationWhitelist dışında.",
                            )
                        )

                if clm.source_url and wl.allowed_source_urls and not wl.contains_url(clm.source_url):
                    blockers.append(
                        (
                            "UNWHITELISTED_CITATION_BLOCKER",
                            f"'{clm.claim_id}' URL adresi ({clm.source_url}) CitationWhitelist dışında.",
                        )
                    )

                if clm.evidence_id and wl.allowed_evidence_ids and clm.evidence_id not in wl.allowed_evidence_ids:
                    blockers.append(
                        (
                            "UNWHITELISTED_CITATION_BLOCKER",
                            f"'{clm.claim_id}' evidence_id ({clm.evidence_id}) CitationWhitelist dışında.",
                        )
                    )

        # Layer A2: Prose Law + Article cross-check in active non-historical sections against whitelist
        allowed_pairs, allowed_laws = _extract_whitelisted_law_articles(wl, trace_bundle)
        # Strip explicit historical & precedent & counter-argument quote blocks before checking strict active article refs
        active_mevzuat_head = sections.mevzuat_dayanagi.split("Tarihsel Bağlam", 1)[0]
        # Inside hukuki_degerlendirme, exclude explicit [İÇTİHAT — ...] and [KARŞI GÖRÜŞLER ...] blocks
        degerlendirme_head = sections.hukuki_degerlendirme.split("[KARŞI GÖRÜŞLER", 1)[0]
        degerlendirme_parts = degerlendirme_head.split("[İÇTİHAT —", 1)
        active_degerlendirme_stat = degerlendirme_parts[0]
        if len(degerlendirme_parts) > 1 and "[ÖZERKNORM" in degerlendirme_parts[1]:
            active_degerlendirme_stat += "\n" + degerlendirme_parts[1].split("[ÖZERKNORM", 1)[1]

        active_prose = "\n".join(
            [
                sections.hukuki_sonuc,
                active_mevzuat_head,
                active_degerlendirme_stat,
                sections.istisnalar,
            ]
        )

        # When abstaining (`ABSTAINED_*`) there are no positive statutory rulings being asserted in prose
        # unless active statutory text sneaked in specific article assertions
        check_prose_for_articles = (not should_abstain) or bool(
            _LAW_ART_PAIR_RE.search(active_mevzuat_head)
        )
        if check_prose_for_articles:
            for m in _LAW_ART_PAIR_RE.finditer(active_prose):
                num = m.group("num")
                art = str(int(m.group("art")))
                if (num, art) in _PRECEDENT_BOILERPLATE_ARTICLES:
                    continue
                # Skip explicit counter-argument / historical pitfall / precedent context lines & windows
                line_start = active_prose.rfind("\n", 0, m.start()) + 1
                line_end = active_prose.find("\n", m.end())
                if line_end == -1:
                    line_end = len(active_prose)
                ctx_win = (
                    active_prose[line_start:line_end].lower()
                    + " "
                    + active_prose[max(0, m.start() - 80) : min(len(active_prose), m.end() + 80)].lower()
                )
                if any(
                    mk in ctx_win
                    for mk in (
                        *HISTORICAL_DISCLOSURE_MARKERS,
                        "tarihsel bağlam",
                        "yaygın hata",
                        "karşı görüş",
                        "[karşı görüş",
                        "sınırları",
                        "kapsam dışı",
                    )
                ):
                    continue
                # Must match an active `(law, art)` OR general clause inside active statements for that law
                # when no specific article was enumerated (e.g. `4857 m.18` when only `4857:m-25:f-2:b-e` is whitelisted!)
                # Exclude `RG-7555` summary ref (`4857 Sayılı Kanun m.109` is already allowed via `4857:m-109`!)
                if not allowed_pairs and not allowed_laws:
                    blockers.append(
                        (
                            "WRONG_ARTICLE_OR_PROVISION_CITED",
                            f"Boş CitationWhitelist varken metinde '{m.group(0)}' mevzuat atfı yer alamaz.",
                        )
                    )
                elif (num, art) not in allowed_pairs:
                    # Allow companion cross-references explicitly named inside verified rule summaries/precedents of allowed rules
                    rule_text_blob = " ".join(
                        c.statement
                        for c in claims
                        if c.claim_category in {CLAIM_LEGAL_INTERPRETATION, CLAIM_JUDICIAL_PRECEDENT}
                    )
                    if not re.search(rf"\b{re.escape(num)}\s+(?:m\.|madde\s*){re.escape(art)}\b", rule_text_blob, re.IGNORECASE):
                        blockers.append(
                            (
                                "WRONG_ARTICLE_OR_PROVISION_CITED",
                                f"Yanlış veya beyaz liste dışı madde atfı tespit edildi: '{m.group(0)}' "
                                f"(izinli aktif maddeler: {sorted(wl.allowed_provision_ids)}).",
                            )
                        )

        # Check URLs directly against whitelist and domain rules
        full_text = "\n".join(sections.to_dict().values())
        for url_m in URL_RE.finditer(full_text):
            url = url_m.group(0).rstrip(".,;:")
            if url not in wl.allowed_source_urls:
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower().removeprefix("www.")
                if not (parsed.scheme == "https" and wl.allowed_source_urls and url in wl.allowed_source_urls):
                    # Let Layer B verify_response_citations handle bare homepage vs external host cleanly,
                    # EXCEPT when whitelist explicitly has URLs and an unknown external URL was injected
                    if wl.allowed_source_urls and host != "karararama.danistay.gov.tr":
                        warnings.append(f"NON_WHITELISTED_URL_DETECTED:{url}")

        # Layer B: Existing precedent_verifier.verify_response_citations (registry + historical + URL + 9 guardrails)
        if as_of_date and self._sources and self._precedents:
            effective_precedents = _build_effective_precedents(
                self._precedents,
                wl,
                trace_bundle,
                temporal_report,
            )
            active_items = (
                (
                    *temporal_report.active_normative_items,
                    *temporal_report.active_interpretation_items,
                    *temporal_report.active_autonomous_items,
                )
                if temporal_report is not None
                else (
                    *trace_bundle.normative_bucket,
                    *trace_bundle.interpretation_bucket,
                    *trace_bundle.autonomous_norm_bucket,
                )
            )
            raw_blobs: list[str] = []
            for item in active_items:
                ch = item.chunk
                if ch.verification_status not in {"VERIFIED", "SUPERSEDED"}:
                    continue
                if len(ch.context_header or "") >= 15:
                    raw_blobs.append(ch.context_header)
                if len(ch.raw_text or "") >= 15:
                    raw_blobs.append(ch.raw_text)
                for r in item.companion_rules:
                    for sc in r.how_to_interpret:
                        for fld in ("condition", "legal_rule", "statutory_basis"):
                            val = str(sc.get(fld) or "")
                            if len(val) >= 15:
                                raw_blobs.append(val)
                    for exc in (*r.exceptions, *r.counter_arguments_and_pitfalls):
                        if len(exc) >= 15:
                            raw_blobs.append(exc)
            verified_blobs = tuple(dict.fromkeys(raw_blobs))
            registered_statute_nos = {src.statute_number for src in self._sources.values()}

            sanitized_parts = [
                _sanitize_section_for_layer_b(
                    section_key=sec_k,
                    section_text=sec_v,
                    overridden_sections=overridden_sections,
                    verified_blobs=verified_blobs,
                    registered_statute_nos=registered_statute_nos,
                    allowed_urls=wl.allowed_source_urls,
                )
                for sec_k, sec_v in sections.to_dict().items()
            ]
            sanitized_text = "\n".join(sanitized_parts)

            aud = verify_response_citations(
                draft_text=sanitized_text,
                as_of_date=as_of_date,
                source_registry=self._sources,
                precedent_registry=effective_precedents,
                cited_source_ids=[s for s in dict.fromkeys(matched_sources) if s in self._sources],
                cited_precedent_ids=[p for p in dict.fromkeys(matched_precs) if p in effective_precedents],
            )
            for f in aud.flags:
                fd = f.to_dict()
                guardrail_flags.append(fd)
                if f.severity == "BLOCKER":
                    if (
                        f.code == "CONFLICTING_PRECEDENT_ESCALATE"
                        and counsel_escalation_required
                        and not payroll_handoff_allowed
                        and "hukuki_sonuc" not in overridden_sections
                        and "hukuki_degerlendirme" not in overridden_sections
                    ):
                        warnings.append(f"CONFLICTING_PRECEDENT_ESCALATED:{f.evidence}")
                        continue
                    if (
                        f.code == "ARTICLE_NOT_EFFECTIVE_ON_DATE"
                        and ":" in f.evidence
                        and "mevzuat_dayanagi" not in overridden_sections
                        and "hukuki_sonuc" not in overridden_sections
                    ):
                        sid_part, art_part = f.evidence.split(":", 1)
                        if _has_active_prior_article_rule(
                            source_id=sid_part,
                            art_label=art_part,
                            as_of_date=as_of_date,
                            source_registry=self._sources,
                            temporal_report=temporal_report,
                        ):
                            warnings.append(f"PRIOR_ARTICLE_VERSION_ACTIVE:{f.evidence}")
                            continue
                    blockers.append((f.code, f.message))
                else:
                    warnings.append(f.code)

        # Layer C: Unauthorized Payroll Calculation & Governance Gate Integrity
        if _PAYROLL_OUTPUT_CALC_RE.search(sections.uygulama) or _PAYROLL_OUTPUT_CALC_RE.search(sections.hukuki_sonuc):
            blockers.append(
                (
                    "UNAUTHORIZED_PAYROLL_CALCULATION",
                    "@HukukSGK cevabı parasal net/kuruş hesaplama tutarı üretemez; yalnızca @ÜcretBordro devri yapabilir.",
                )
            )
        if _FALSE_GATE_OPEN_RE.search(full_text):
            blockers.append(
                (
                    "GOVERNANCE_GATE_VIOLATION",
                    "Üretim, 5070 sayılı Kanun veya KVKK m.9 kapıları kapalıyken açık (true) beyan edilemez.",
                )
            )

        b_codes = tuple(dict.fromkeys(c for c, _ in blockers))
        b_msgs = tuple(m for _, m in blockers)
        w_codes = tuple(dict.fromkeys(warnings))
        return AnswerCitationAuditReport(
            passed=len(blockers) == 0,
            checked_claim_count=len(claims),
            matched_source_ids=tuple(matched_sources),
            matched_precedent_ids=tuple(matched_precs),
            blocker_codes=b_codes,
            blocker_messages=b_msgs,
            warning_codes=w_codes,
            guardrail_flags=tuple(guardrail_flags),
        )
