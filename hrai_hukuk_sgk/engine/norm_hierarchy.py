"""Deterministic Turkish Constitutional Norm Hierarchy & Judicial Precedent Application Model (v1.0.2b.2).

Separates:
1. Pure normative hierarchy under Turkish Constitutional Law (Anayasa m.11, m.90/5, m.104, m.124):
   - CONSTITUTION (1) — Anayasa (supreme; NO international treaty shares rank 1)
   - INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS (2) — Anayasa m.90/5 son cümle (prevails over statute on conflict)
   - STATUTORY_LAW (3) & INTERNATIONAL_TREATY_GENERAL (3) — Anayasa m.90/5 cümle 1 (general ratified treaties/ILO have statutory force; conflict with statute escalates for lex specialis/lex posterior/m.90 review)
   - PRESIDENTIAL_DECREE (4) — Cumhurbaşkanlığı Kararnamesi (CBK)
   - PRESIDENTIAL_DECISION (5) — Cumhurbaşkanı Kararı (CK)
   - REGULATION (6) — Yönetmelik
   - COMMUNIQUE_AND_SGK_CIRCULAR (7) — Tebliğ ve SGK Genelgesi
   - CBA_CONTRACT_AND_HR_PROCEDURE (8) — TİS / İş Sözleşmesi / İşyeri Uygulaması / İK Prosedürü

2. Judicial Interpretation & Precedent Application Model (2797 s. Kanun m.45):
   - YARGITAY_PRECEDENT is NOT a legislative norm layer and NEVER wins/loses by numeric rank against TİS/contracts/statutes.
   - Precedent-vs-precedent comparisons use internal judicial authority (YİBBGK [2797 m.45] > HGK > Daire).
   - Precedent-vs-norm conflicts MUST be evaluated via evaluate_precedent_application(), examining the underlying
     interpreted statute, scope limitations (applies_to/does_not_apply_to), post-decision amendments, and mandatory character.
"""

from __future__ import annotations

import re

from .models import (
    ALL_CONFLICT_EVALUATION_LAYERS,
    JUDICIAL_INTERPRETATION_LAYERS,
    NORM_LAYER_PRIORITY,
    PRECEDENT_BINDING_RANK,
    VALID_MANDATORY_TYPES,
    VALID_TREATY_PROVISION_NATURES,
    AmendmentRecord,
    LegalSourceRecord,
    NormConflictResolution,
    NormReference,
    PrecedentApplicationAssessment,
    PrecedentRecord,
)
from .source_validator import parse_iso_date

VALID_SCOPE_MATCH_STATUSES: set[str] = {"IN_SCOPE", "OUT_OF_SCOPE", "UNCERTAIN"}
VALID_PRECEDENT_FAVOR_SIDES: set[str] = {"UNDERLYING_STATUTE", "COMPETING_NORM", "NEUTRAL", "UNKNOWN"}
MIN_PERSUASIVE_RATIONALE_LEN = 25

_ARTICLE_TOKEN_RE = re.compile(
    r"(?:(?P<prefix>ek|geçici|gecici)\s+)?(?:madde|md\.?|m\.)\s*(?P<start>\d+)(?:\s*[-–]\s*(?P<end>\d+))?",
    re.IGNORECASE,
)
_OTHER_STATUTE_CODE_RE = re.compile(r"\b(?:hmk|ttk|tbk|tck|cmk|iik|vuk|gvk|\d{4})\b", re.IGNORECASE)


def _extract_article_keys(text: str) -> set[str]:
    """Extract normalized article identifiers (e.g. 'm-25', 'ek-3', 'gecici-8') from Turkish statutory text."""
    keys: set[str] = set()
    low = text.replace("İ", "i").replace("I", "ı").lower()
    for match in _ARTICLE_TOKEN_RE.finditer(low):
        prefix = (match.group("prefix") or "").strip()
        start_num = int(match.group("start"))
        end_str = match.group("end")
        norm_prefix = "ek" if prefix == "ek" else ("gecici" if prefix in {"geçici", "gecici"} else "m")
        if end_str:
            end_num = int(end_str)
            if start_num <= end_num <= start_num + 20:
                for n in range(start_num, end_num + 1):
                    keys.add(f"{norm_prefix}-{n}")
            else:
                keys.add(f"{norm_prefix}-{start_num}")
                keys.add(f"{norm_prefix}-{end_num}")
        else:
            keys.add(f"{norm_prefix}-{start_num}")
    return keys


def _precedent_article_keys_for_source(precedent: PrecedentRecord, interpreted_source: LegalSourceRecord) -> set[str]:
    """Extract the specific articles of interpreted_source that the precedent interprets."""
    statute_no = (interpreted_source.statute_number or "").strip().lower()
    keys: set[str] = set()

    detail = precedent.scope_limitations_detail
    if isinstance(detail, dict) and isinstance(detail.get("statutory_anchors"), list):
        for raw_anchor in detail["statutory_anchors"]:
            anchor = str(raw_anchor).strip()
            anchor_low = anchor.replace("İ", "i").replace("I", "ı").lower()
            statute_tokens = {t.lower() for t in _OTHER_STATUTE_CODE_RE.findall(anchor_low)}
            if statute_no and statute_no in statute_tokens:
                keys.update(_extract_article_keys(anchor))
            elif not statute_tokens:
                keys.update(_extract_article_keys(anchor))

    if keys:
        return keys

    # Fallback for precedents without structured statutory_anchors: scan legal_principle + scope_limitations
    for field_text in (precedent.legal_principle, precedent.scope_limitations):
        if not field_text:
            continue
        if statute_no and statute_no in field_text.lower():
            # Match clauses explicitly referencing this statute number
            for seg in re.split(r"[;.]", field_text):
                if statute_no in seg.lower():
                    keys.update(_extract_article_keys(seg))
    return keys


def _amendment_affects_precedent_articles(
    precedent: PrecedentRecord,
    interpreted_source: LegalSourceRecord,
    amend: AmendmentRecord,
) -> bool:
    """Return True if a post-decision amendment affects an article interpreted by the precedent (or if uncertain)."""
    amend_keys: set[str] = set()
    for art in amend.affected_articles:
        amend_keys.update(_extract_article_keys(str(art)))
    prec_keys = _precedent_article_keys_for_source(precedent, interpreted_source)

    # Zero-trust conservative fallback: if either side lacks parseable specific articles, escalate!
    if not amend_keys or not prec_keys:
        return True
    return bool(prec_keys & amend_keys)



def resolve_norm_conflict(
    norm_a: NormReference,
    norm_b: NormReference,
    mandatory_type: str = "RELATIVE_EMPLOYEE_FAVORABLE",
    favors_employee_side: str = "UNKNOWN",
    treaty_provision_nature: str = "UNSPECIFIED",
) -> NormConflictResolution:
    """Resolve conflict between two legal norms under Anayasa m.11 & m.90/5, or two Yargıtay precedents under 2797 m.45."""
    if norm_a.norm_layer not in ALL_CONFLICT_EVALUATION_LAYERS:
        raise ValueError(f"Geçersiz norm_a katmanı: '{norm_a.norm_layer}'")
    if norm_b.norm_layer not in ALL_CONFLICT_EVALUATION_LAYERS:
        raise ValueError(f"Geçersiz norm_b katmanı: '{norm_b.norm_layer}'")
    if mandatory_type not in VALID_MANDATORY_TYPES:
        raise ValueError(f"Geçersiz mandatory_type: '{mandatory_type}'")
    if favors_employee_side not in {"NORM_A", "NORM_B", "NEUTRAL", "UNKNOWN"}:
        raise ValueError(f"Geçersiz favors_employee_side: '{favors_employee_side}'")
    if treaty_provision_nature not in VALID_TREATY_PROVISION_NATURES:
        raise ValueError(f"Geçersiz treaty_provision_nature: '{treaty_provision_nature}'")

    a_is_prec = norm_a.norm_layer in JUDICIAL_INTERPRETATION_LAYERS
    b_is_prec = norm_b.norm_layer in JUDICIAL_INTERPRETATION_LAYERS

    # Case 1: Precedent vs. Precedent -> internal judicial binding hierarchy (2797 s. Kanun m.45)
    if a_is_prec and b_is_prec:
        rank_a = PRECEDENT_BINDING_RANK.get(norm_a.precedent_level, 99)
        rank_b = PRECEDENT_BINDING_RANK.get(norm_b.precedent_level, 99)

        if rank_a < rank_b:
            rule = (
                "PRECEDENT_HIERARCHY_YIBBGK_SUPREMACY"
                if norm_a.precedent_level == "STATUTORY_BINDING_YIBBGK"
                else "PRECEDENT_HIERARCHY_HIGHER_BENCH"
            )
            basis_note = (
                "2797 sayılı Yargıtay Kanunu m.45 uyarınca bağlayıcı içtihadı birleştirme etkisiyle"
                if norm_a.precedent_level == "STATUTORY_BINDING_YIBBGK"
                else "yargısal içtihat hiyerarşisinde"
            )
            return NormConflictResolution(
                winning_side="NORM_A",
                winning_norm=norm_a,
                losing_norm=norm_b,
                rule_applied=rule,
                mandatory_type=mandatory_type,
                requires_counsel_escalation=False,
                explanation=(
                    f"'{norm_a.title}' ({norm_a.precedent_level}), {basis_note} "
                    f"'{norm_b.title}' ({norm_b.precedent_level}) kararından üstündür ve esas alınır."
                ),
            )
        if rank_b < rank_a:
            rule = (
                "PRECEDENT_HIERARCHY_YIBBGK_SUPREMACY"
                if norm_b.precedent_level == "STATUTORY_BINDING_YIBBGK"
                else "PRECEDENT_HIERARCHY_HIGHER_BENCH"
            )
            basis_note = (
                "2797 sayılı Yargıtay Kanunu m.45 uyarınca bağlayıcı içtihadı birleştirme etkisiyle"
                if norm_b.precedent_level == "STATUTORY_BINDING_YIBBGK"
                else "yargısal içtihat hiyerarşisinde"
            )
            return NormConflictResolution(
                winning_side="NORM_B",
                winning_norm=norm_b,
                losing_norm=norm_a,
                rule_applied=rule,
                mandatory_type=mandatory_type,
                requires_counsel_escalation=False,
                explanation=(
                    f"'{norm_b.title}' ({norm_b.precedent_level}), {basis_note} "
                    f"'{norm_a.title}' ({norm_a.precedent_level}) kararından üstündür ve esas alınır."
                ),
            )
        return NormConflictResolution(
            winning_side="UNRESOLVED_ESCALATE",
            winning_norm=None,
            losing_norm=None,
            rule_applied="CONFLICTING_SAME_LEVEL_PRECEDENTS_ESCALATE",
            mandatory_type=mandatory_type,
            requires_counsel_escalation=True,
            explanation=(
                f"Aynı yargısal düzeydeki iki içtihat ('{norm_a.title}' ve '{norm_b.title}') "
                f"arasında çatışma vardır; otomatik çözüm yapılamaz, şirket avukatına eskalasyon zorunludur."
            ),
        )

    # Case 2: Precedent vs. Legislative / Contractual Norm -> NEVER compare by numeric rank!
    if a_is_prec != b_is_prec:
        prec_norm = norm_a if a_is_prec else norm_b
        other_norm = norm_b if a_is_prec else norm_a
        return NormConflictResolution(
            winning_side="UNRESOLVED_ESCALATE",
            winning_norm=None,
            losing_norm=None,
            rule_applied="PRECEDENT_NOT_LEGISLATIVE_NORM_EVALUATE_UNDERLYING_STATUTE_AND_SCOPE",
            mandatory_type=mandatory_type,
            requires_counsel_escalation=True,
            explanation=(
                f"'{prec_norm.title}' (Yargıtay içtihadı) kanun veya yönetmelik gibi genel bir mevzuat katmanı değildir; "
                f"'{other_norm.title}' ({other_norm.norm_layer}) ile doğrudan sayısal katman sıralamasına göre çatışma çözülemez. "
                f"YİBBGK kararlarının bağlayıcılığı 2797 sayılı Kanun m.45'teki içtihadı birleştirme etkisinden doğar. "
                f"İçtihadın yorumladığı dayanak kanun hükmü, kararın kapsam sınırları (applies_to/does_not_apply_to) ve "
                f"somut uyuşmazlık birlikte evaluate_precedent_application aracıyla değerlendirilmelidir."
            ),
        )

    # Case 3: Pure Normative Layers (CONSTITUTION .. CBA_CONTRACT_AND_HR_PROCEDURE)
    layer_a = norm_a.norm_layer
    layer_b = norm_b.norm_layer
    prio_a = NORM_LAYER_PRIORITY[layer_a]
    prio_b = NORM_LAYER_PRIORITY[layer_b]

    # Case 3a: Constitution supremacy (Anayasa m.11 — supreme over ALL treaties, statutes, and lower norms)
    if (layer_a == "CONSTITUTION") != (layer_b == "CONSTITUTION"):
        const_side, const_norm, lower_norm = (
            ("NORM_A", norm_a, norm_b) if layer_a == "CONSTITUTION" else ("NORM_B", norm_b, norm_a)
        )
        return NormConflictResolution(
            winning_side=const_side,
            winning_norm=const_norm,
            losing_norm=lower_norm,
            rule_applied="CONSTITUTION_SUPREMACY_ANAYASA_M11",
            mandatory_type=mandatory_type,
            requires_counsel_escalation=False,
            explanation=(
                f"Anayasa m.11 uyarınca '{const_norm.title}' (CONSTITUTION) en üstün hukuk normudur; "
                f"uluslararası sözleşmeler (ILO dahil), kanunlar ve alt normlar Anayasa ile aynı basamakta değildir "
                f"ve '{lower_norm.title}' ({lower_norm.norm_layer}) Anayasa hükmünün önüne geçemez."
            ),
        )

    # Case 3b: Anayasa m.90/5 son cümle — Fundamental-rights international treaty vs. Statutory Law (or general treaty)
    if {layer_a, layer_b} in (
        {"INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS", "STATUTORY_LAW"},
        {"INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS", "INTERNATIONAL_TREATY_GENERAL"},
    ):
        treaty_side, treaty_norm, stat_side, stat_norm = (
            ("NORM_A", norm_a, "NORM_B", norm_b)
            if layer_a == "INTERNATIONAL_TREATY_FUNDAMENTAL_RIGHTS"
            else ("NORM_B", norm_b, "NORM_A", norm_a)
        )
        if mandatory_type == "RELATIVE_EMPLOYEE_FAVORABLE" and favors_employee_side == stat_side:
            # v1.0.2c hardening: never assume domestic law is preserved without verifying treaty_provision_nature!
            if treaty_provision_nature == "MINIMUM_STANDARD_FLOOR":
                return NormConflictResolution(
                    winning_side=stat_side,
                    winning_norm=stat_norm,
                    losing_norm=treaty_norm,
                    rule_applied="ANAYASA_M90_MORE_FAVORABLE_DOMESTIC_STATUTE_PRESERVED",
                    mandatory_type=mandatory_type,
                    requires_counsel_escalation=False,
                    explanation=(
                        f"'{treaty_norm.title}' hükmü asgari koruma standardı (MINIMUM_STANDARD_FLOOR) niteliğinde olduğundan, "
                        f"bu asgari tabanın üzerinde çalışan lehine daha yüksek koruma sağlayan '{stat_norm.title}' "
                        f"({stat_norm.norm_layer}) hükmü korunur ve uygulanır."
                    ),
                )
            if treaty_provision_nature == "UNSPECIFIED":
                return NormConflictResolution(
                    winning_side="UNRESOLVED_ESCALATE",
                    winning_norm=None,
                    losing_norm=None,
                    rule_applied="ANAYASA_M90_TREATY_NATURE_REVIEW_REQUIRED",
                    mandatory_type=mandatory_type,
                    requires_counsel_escalation=True,
                    explanation=(
                        f"'{treaty_norm.title}' (Anayasa m.90/son temel hak antlaşması) ile '{stat_norm.title}' arasındaki "
                        f"ilişkide, antlaşma hükmünün asgari koruma tabanı mı (MINIMUM_STANDARD_FLOOR) yoksa doğrudan "
                        f"çatışan kesin düzenleme mi (DIRECT_SUBSTANTIVE_RULE) olduğu belirtilmeden (UNSPECIFIED) "
                        f"daha elverişli iç hukuk varsayımı otomatik yapılamaz; hukuk müşaviri incelemesi gerekir."
                    ),
                )
            # DIRECT_SUBSTANTIVE_RULE: Anayasa m.90/son directly mandates the treaty provision
            return NormConflictResolution(
                winning_side=treaty_side,
                winning_norm=treaty_norm,
                losing_norm=stat_norm,
                rule_applied="ANAYASA_M90_SON_FUNDAMENTAL_RIGHTS_TREATY_PREVAILS",
                mandatory_type=mandatory_type,
                requires_counsel_escalation=False,
                explanation=(
                    f"'{treaty_norm.title}' doğrudan esas kural (DIRECT_SUBSTANTIVE_RULE) niteliğinde olduğundan, "
                    f"Anayasa m.90/5 son cümle uyarınca '{stat_norm.title}' ({stat_norm.norm_layer}) ile çatışmada "
                    f"temel haklara ilişkin uluslararası antlaşma hükmü esas alınır."
                ),
            )
        return NormConflictResolution(
            winning_side=treaty_side,
            winning_norm=treaty_norm,
            losing_norm=stat_norm,
            rule_applied="ANAYASA_M90_SON_FUNDAMENTAL_RIGHTS_TREATY_PREVAILS",
            mandatory_type=mandatory_type,
            requires_counsel_escalation=False,
            explanation=(
                f"Anayasa m.90/5 son cümle uyarınca usulüne göre yürürlüğe konulmuş temel hak ve özgürlüklere ilişkin "
                f"'{treaty_norm.title}' ile '{stat_norm.title}' ({stat_norm.norm_layer}) aynı konuda farklı hükümler "
                f"içerdiğinden uluslararası antlaşma hükmü esas alınır."
            ),
        )

    # Case 3c: Anayasa m.90/5 cümle 1 — General international treaty vs. Statutory Law (same statutory rank!)
    if {layer_a, layer_b} == {"INTERNATIONAL_TREATY_GENERAL", "STATUTORY_LAW"}:
        return NormConflictResolution(
            winning_side="UNRESOLVED_ESCALATE",
            winning_norm=None,
            losing_norm=None,
            rule_applied="ANAYASA_M90_STATUTORY_EQUIVALENT_TREATY_CONFLICT_ESCALATE",
            mandatory_type=mandatory_type,
            requires_counsel_escalation=True,
            explanation=(
                f"Anayasa m.90/5 cümle 1 uyarınca usulüne göre yürürlüğe konulmuş genel uluslararası antlaşmalar "
                f"kanun hükmündedir ve kanunla eşit basamaktadır ('{norm_a.title}' vs. '{norm_b.title}'). "
                f"Temel hak ve özgürlüklere ilişkin (m.90/son) nitelik taşımadıkça kanuna karşı otomatik üstünlük tanınamaz; "
                f"özel hüküm (lex specialis), sonraki tarih (lex posterior) ve m.90/son kapsamı hukuk müşavirince incelenmelidir."
            ),
        )

    # Case 3d: Same normative layer -> requires lex specialis / lex posterior counsel review
    if prio_a == prio_b:
        return NormConflictResolution(
            winning_side="UNRESOLVED_ESCALATE",
            winning_norm=None,
            losing_norm=None,
            rule_applied="SAME_LAYER_CONFLICT_REQUIRES_COUNSEL",
            mandatory_type=mandatory_type,
            requires_counsel_escalation=True,
            explanation=(
                f"Aynı norm katmanındaki ({norm_a.norm_layer}) '{norm_a.title}' ve '{norm_b.title}' "
                f"düzenlemeleri arasında çatışma vardır; özel hüküm / sonraki tarih incelemesi için hukuk müşaviri onayı gerekir."
            ),
        )

    # Case 4: Different legislative/contractual hierarchy levels
    if prio_a < prio_b:
        higher_side, lower_side = "NORM_A", "NORM_B"
        higher_norm, lower_norm = norm_a, norm_b
    else:
        higher_side, lower_side = "NORM_B", "NORM_A"
        higher_norm, lower_norm = norm_b, norm_a

    # 4a. Absolute mandatory rule (public order / SGK ceiling / TBK m.420 / statutory max limits)
    if mandatory_type == "ABSOLUTE_MANDATORY":
        return NormConflictResolution(
            winning_side=higher_side,
            winning_norm=higher_norm,
            losing_norm=lower_norm,
            rule_applied="ABSOLUTE_MANDATORY_HIGHER_NORM_PREVAILS",
            mandatory_type=mandatory_type,
            requires_counsel_escalation=False,
            explanation=(
                f"'{higher_norm.title}' ({higher_norm.norm_layer}) mutlak emredici nitelikte olduğundan "
                f"alt norm olan '{lower_norm.title}' ({lower_norm.norm_layer}) işçi lehine görünse dahi uygulanamaz."
            ),
        )

    # 4b. Relative mandatory rule (nispi emredici: employee-favorable lower CBA/contract/procedure allowed)
    if mandatory_type == "RELATIVE_EMPLOYEE_FAVORABLE":
        if lower_norm.norm_layer == "CBA_CONTRACT_AND_HR_PROCEDURE" and favors_employee_side == lower_side:
            return NormConflictResolution(
                winning_side=lower_side,
                winning_norm=lower_norm,
                losing_norm=higher_norm,
                rule_applied="RELATIVE_MANDATORY_EMPLOYEE_FAVORABLE_LOWER_NORM_PREVAILS",
                mandatory_type=mandatory_type,
                requires_counsel_escalation=False,
                explanation=(
                    f"Nispi emredici kural ve işçi lehine yorum (yararlılık) ilkesi gereği; "
                    f"'{higher_norm.title}' asgari tabanının üzerinde işçi lehine hak tanıyan "
                    f"'{lower_norm.title}' geçerlidir ve uygulanır."
                ),
            )
        if favors_employee_side == higher_side:
            return NormConflictResolution(
                winning_side=higher_side,
                winning_norm=higher_norm,
                losing_norm=lower_norm,
                rule_applied="RELATIVE_MANDATORY_EMPLOYEE_UNFAVORABLE_LOWER_NORM_VOID",
                mandatory_type=mandatory_type,
                requires_counsel_escalation=False,
                explanation=(
                    f"'{lower_norm.title}' ({lower_norm.norm_layer}) düzenlemesi, nispi emredici üst norm "
                    f"'{higher_norm.title}' ({higher_norm.norm_layer}) hükmünün altına inerek işçi aleyhine "
                    f"sonuç doğurduğundan kesin hükümsüzdür; üst norm uygulanır."
                ),
            )
        return NormConflictResolution(
            winning_side=higher_side,
            winning_norm=higher_norm,
            losing_norm=lower_norm,
            rule_applied="RELATIVE_MANDATORY_DEFAULT_HIGHER_NORM",
            mandatory_type=mandatory_type,
            requires_counsel_escalation=favors_employee_side == "UNKNOWN",
            explanation=(
                f"İşçi lehine olma durumu net teyit edilemediğinden ({favors_employee_side}) "
                f"üst norm '{higher_norm.title}' esas alınır."
            ),
        )

    # 4c. Dispositive rule (yedek hukuk kuralı)
    return NormConflictResolution(
        winning_side=lower_side,
        winning_norm=lower_norm,
        losing_norm=higher_norm,
        rule_applied="DISPOSITIVE_SPECIFIC_LOWER_NORM_PREVAILS",
        mandatory_type=mandatory_type,
        requires_counsel_escalation=False,
        explanation=(
            f"'{higher_norm.title}' yedek (tamamlayıcı) hukuk kuralı olduğundan taraflarca veya "
            f"özel düzenleme ile belirlenen '{lower_norm.title}' uygulanır."
        ),
    )


def evaluate_precedent_application(
    precedent: PrecedentRecord,
    interpreted_source: LegalSourceRecord,
    as_of_date: str,
    scope_match_status: str = "UNCERTAIN",
    competing_norm: NormReference | None = None,
    mandatory_type: str = "RELATIVE_EMPLOYEE_FAVORABLE",
    favors_employee_side: str = "UNKNOWN",
    dispute_context: str = "",
    application_rationale: str = "",
    treaty_provision_nature: str = "UNSPECIFIED",
) -> PrecedentApplicationAssessment:
    """Evaluate a Yargıtay precedent as judicial interpretation of an underlying statute (2797 s. Kanun m.45),
    NOT as a legislative hierarchy tier.

    Checks:
    1. Precedent verification_status == VERIFIED (blocks PENDING_REVIEW / SUPERSEDED / CONFLICTING / UNVERIFIED),
    2. Statutory anchor alignment (interpreted_source in precedent.related_source_ids & effective on as_of_date),
    3. Binding nature (2797 s. Kanun m.45 YİBBGK unification effect vs. persuasive HGK/Chamber guidance) +
       mandatory application_rationale gate for non-YİBBGK persuasive decisions (HGK / Chamber),
    4. Scope limitations match (IN_SCOPE / OUT_OF_SCOPE / UNCERTAIN),
    5. Post-decision statutory amendments on interpreted_source up to as_of_date,
    6. Competing norm resolution via the UNDERLYING STATUTE (preserving employee-favorable TİS/contract over relative-mandatory statutory floors).
    """
    target_dt = parse_iso_date(as_of_date)
    if target_dt is None:
        raise ValueError(f"Geçersiz as_of_date (YYYY-MM-DD beklenir): '{as_of_date}'")
    if scope_match_status not in VALID_SCOPE_MATCH_STATUSES:
        raise ValueError(f"Geçersiz scope_match_status: '{scope_match_status}'")
    if mandatory_type not in VALID_MANDATORY_TYPES:
        raise ValueError(f"Geçersiz mandatory_type: '{mandatory_type}'")
    if favors_employee_side not in VALID_PRECEDENT_FAVOR_SIDES:
        raise ValueError(f"Geçersiz favors_employee_side: '{favors_employee_side}'")
    if treaty_provision_nature not in VALID_TREATY_PROVISION_NATURES:
        raise ValueError(f"Geçersiz treaty_provision_nature: '{treaty_provision_nature}'")

    clean_rationale = application_rationale.strip()

    # Gate 1: Verification gate (never apply PENDING_REVIEW / SUPERSEDED / CONFLICTING / UNVERIFIED)
    if precedent.verification_status != "VERIFIED":
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=False,
            effective_outcome="ESCALATE_TO_LEGAL_COUNSEL",
            binding_nature="UNVERIFIED_OR_BLOCKED",
            binding_basis=(
                f"İçtihat doğrulama statüsü '{precedent.verification_status}' olduğundan "
                f"(tam metin/hukuki doğrulama tamamlanmadığı veya aşıldığı/çelişkili olduğu için) uygulanamaz."
            ),
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status="NOT_REACHED_UNVERIFIED_PRECEDENT",
            requires_counsel_escalation=True,
            explanation=(
                f"'{precedent.precedent_id}' içtihadı VERIFIED değildir (durum={precedent.verification_status}); "
                f"somut uyuşmazlıkta bağlayıcı veya kesin dayanak olarak uygulanamaz."
            ),
        )

    # Gate 2: Statutory anchor & effective date gate
    if interpreted_source.source_id not in precedent.related_source_ids:
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=False,
            effective_outcome="PRECEDENT_NOT_APPLICABLE",
            binding_nature="UNVERIFIED_OR_BLOCKED",
            binding_basis="Dayanak kanun bağlantısı (related_source_ids) eşleşmiyor.",
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status="NOT_REACHED_ANCHOR_MISMATCH",
            requires_counsel_escalation=True,
            explanation=(
                f"'{precedent.precedent_id}' içtihadı '{interpreted_source.source_id}' kaynağını yorumlamak üzere "
                f"bağlanmamıştır (ilgili kaynaklar: {', '.join(precedent.related_source_ids)}). "
                f"Yargıtay içtihadı yalnızca yorumladığı dayanak kanun kapsamında değerlendirilebilir."
            ),
        )

    src_from = parse_iso_date(interpreted_source.effective_from)
    src_to = parse_iso_date(interpreted_source.effective_to)
    if (
        interpreted_source.verification_status != "VERIFIED"
        or src_from is None
        or src_to is None
        or not (src_from <= target_dt <= src_to)
    ):
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=False,
            effective_outcome="ESCALATE_TO_LEGAL_COUNSEL",
            binding_nature="UNVERIFIED_OR_BLOCKED",
            binding_basis="Yorumlanan dayanak kanun olay tarihinde yürürlükte veya VERIFIED değil.",
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status="NOT_REACHED_STATUTE_INACTIVE",
            requires_counsel_escalation=True,
            explanation=(
                f"Dayanak kaynak '{interpreted_source.source_id}' {as_of_date} tarihinde yürürlükte/VERIFIED olmadığından "
                f"'{precedent.precedent_id}' içtihadı doğrudan uygulanamaz."
            ),
        )

    # Gate 3: Binding nature (2797 s. Kanun m.45 vs persuasive) & mandatory rationale gate for HGK/Chamber
    if precedent.binding_level == "STATUTORY_BINDING_YIBBGK":
        binding_nature = "BINDING_JUDICIAL_UNIFICATION_2797_M45"
        binding_basis = (
            "2797 sayılı Yargıtay Kanunu m.45 uyarınca benzer hukuki konularda Yargıtay Genel Kurullarını, "
            "dairelerini ve adliye mahkemelerini bağlayıcı İçtihadı Birleştirme Kararıdır; ancak kanun veya "
            "yönetmelik gibi bağımsız bir mevzuat katmanı değildir."
        )
        rationale_status = (
            "PROVIDED_YIBBGK_RATIONALE" if clean_rationale else "STATUTORY_BINDING_YIBBGK_2797_M45_DEFAULT"
        )
    else:
        binding_nature = "PERSUASIVE_JUDICIAL_INTERPRETATION"
        binding_basis = (
            f"'{precedent.binding_level}' düzeyinde yargısal içtihattır; 2797 sayılı Kanun m.45 kapsamında "
            f"bağlayıcı YİBBGK kararı veya genel mevzuat normu değildir, yol gösterici niteliktedir."
        )
        if len(clean_rationale) < MIN_PERSUASIVE_RATIONALE_LEN:
            return PrecedentApplicationAssessment(
                precedent_id=precedent.precedent_id,
                interpreted_source_id=interpreted_source.source_id,
                as_of_date=as_of_date,
                precedent_applicable_to_statute=False,
                effective_outcome="ESCALATE_TO_LEGAL_COUNSEL",
                binding_nature=binding_nature,
                binding_basis=binding_basis,
                scope_match_status=scope_match_status,
                application_rationale=clean_rationale,
                rationale_requirement_status="MISSING_PERSUASIVE_PRECEDENT_RATIONALE",
                requires_counsel_escalation=True,
                explanation=(
                    f"'{precedent.precedent_id}' ({precedent.binding_level}) 2797 sayılı Kanun m.45 kapsamında bağlayıcı "
                    f"YİBBGK kararı değil, ikna edici/yol gösterici niteliktedir. Kararın somut uyuşmazlıkta neden esas "
                    f"alındığını açıklayan gerekçe (application_rationale >= {MIN_PERSUASIVE_RATIONALE_LEN} karakter: "
                    f"olgusal benzerlik, yerleşik içtihat istikrarı ve karşıt daire görüşü bulunmadığı teyidi) "
                    f"sunulmadan otomatik sonuç üretilemez; hukuk müşaviri incelemesi zorunludur."
                ),
            )
        rationale_status = (
            "PROVIDED_BUT_ISOLATED_CHAMBER_REQUIRES_COUNSEL"
            if precedent.binding_level == "CHAMBER_ISOLATED"
            else "PROVIDED_PERSUASIVE_RATIONALE"
        )

    # Gate 4: Scope limitations gate
    if scope_match_status == "OUT_OF_SCOPE":
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=False,
            effective_outcome="PRECEDENT_NOT_APPLICABLE",
            binding_nature=binding_nature,
            binding_basis=binding_basis,
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status=rationale_status,
            requires_counsel_escalation=False,
            explanation=(
                f"Somut uyuşmazlık '{precedent.precedent_id}' kararının bağlayıcılık kapsamı dışında (OUT_OF_SCOPE) "
                f"kaldığından bu içtihat olaya uygulanmaz. Kapsam sınırı: {precedent.scope_limitations}"
            ),
        )

    if scope_match_status == "UNCERTAIN":
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=False,
            effective_outcome="ESCALATE_TO_LEGAL_COUNSEL",
            binding_nature=binding_nature,
            binding_basis=binding_basis,
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status=rationale_status,
            requires_counsel_escalation=True,
            explanation=(
                f"Somut uyuşmazlığın '{precedent.precedent_id}' kararının kapsam sınırları (applies_to / does_not_apply_to) "
                f"içine girip girmediği kesinleştirilmeden (UNCERTAIN) içtihat otomatik uygulanamaz; hukuk müşaviri incelemesi gerekir."
            ),
        )

    # Gate 5: Post-decision statutory amendments affecting the interpreted articles on interpreted_source
    decision_dt = parse_iso_date(precedent.decision_date)
    post_amendments: list[str] = []
    if decision_dt is not None:
        for amend in interpreted_source.amendment_history:
            amend_dt = parse_iso_date(amend.effective_from)
            if (
                amend_dt is not None
                and decision_dt < amend_dt <= target_dt
                and _amendment_affects_precedent_articles(precedent, interpreted_source, amend)
            ):
                post_amendments.append(
                    f"{amend.amending_law_no} ({amend.effective_from}: {', '.join(amend.affected_articles)})"
                )
    if post_amendments:
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=False,
            effective_outcome="ESCALATE_TO_LEGAL_COUNSEL",
            binding_nature=binding_nature,
            binding_basis=binding_basis,
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status=rationale_status,
            post_decision_amendments=tuple(post_amendments),
            requires_counsel_escalation=True,
            explanation=(
                f"Dayanak kaynak '{interpreted_source.source_id}' üzerinde '{precedent.precedent_id}' karar tarihinden "
                f"({precedent.decision_date}) sonra yürürlüğe giren kanun değişikliği tespit edildi: "
                f"{'; '.join(post_amendments)}. Değişiklik sonrası içtihadın güncelliği hukuk müşavirince teyit edilmelidir."
            ),
        )

    # Gate 6: Resolution against optional competing norm via the UNDERLYING STATUTE (never via fake precedent tier!)
    ctx_suffix = f" [Uyuşmazlık bağlamı: {dispute_context}]" if dispute_context.strip() else ""
    if competing_norm is None:
        needs_esc = precedent.binding_level == "CHAMBER_ISOLATED"
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=True,
            effective_outcome=(
                "ESCALATE_TO_LEGAL_COUNSEL" if needs_esc else "UNDERLYING_STATUTE_WITH_PRECEDENT_PREVAILS"
            ),
            binding_nature=binding_nature,
            binding_basis=binding_basis,
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status=rationale_status,
            requires_counsel_escalation=needs_esc,
            explanation=(
                f"'{precedent.precedent_id}', yorumladığı '{interpreted_source.legal_reference}' hükmü kapsamında "
                f"ve belirlenen kapsam sınırları içinde uygulanabilir ({binding_nature}; gerekçe={rationale_status}).{ctx_suffix}"
            ),
        )

    if competing_norm.norm_layer in JUDICIAL_INTERPRETATION_LAYERS:
        raise ValueError(
            "competing_norm başka bir Yargıtay içtihadı olamaz; iki içtihat karşılaştırması için resolve_norm_conflict() kullanın."
        )

    statute_ref = NormReference(
        title=f"{interpreted_source.legal_reference} ({precedent.precedent_id} yargısal yorumuyla)",
        norm_layer=interpreted_source.norm_layer,
        source_id=interpreted_source.source_id,
    )
    favor_map = {
        "UNDERLYING_STATUTE": "NORM_A",
        "COMPETING_NORM": "NORM_B",
        "NEUTRAL": "NEUTRAL",
        "UNKNOWN": "UNKNOWN",
    }
    underlying_res = resolve_norm_conflict(
        norm_a=statute_ref,
        norm_b=competing_norm,
        mandatory_type=mandatory_type,
        favors_employee_side=favor_map[favors_employee_side],
        treaty_provision_nature=treaty_provision_nature,
    )

    if underlying_res.winning_side == "NORM_B":
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=True,
            effective_outcome="COMPETING_NORM_PREVAILS",
            binding_nature=binding_nature,
            binding_basis=binding_basis,
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status=rationale_status,
            underlying_norm_resolution=underlying_res,
            requires_counsel_escalation=underlying_res.requires_counsel_escalation,
            explanation=(
                f"'{precedent.precedent_id}' dayanak '{interpreted_source.legal_reference}' hükmünün kanuni sınırını "
                f"yorumlamakla birlikte bağımsız mevzuat katmanı değildir. Dayanak kanun ile '{competing_norm.title}' "
                f"({competing_norm.norm_layer}) arasındaki normlar hiyerarşisi değerlendirmesinde "
                f"({underlying_res.rule_applied}) '{competing_norm.title}' geçerlidir ve uygulanır.{ctx_suffix}"
            ),
        )

    if underlying_res.winning_side == "NORM_A":
        needs_esc = underlying_res.requires_counsel_escalation or precedent.binding_level == "CHAMBER_ISOLATED"
        return PrecedentApplicationAssessment(
            precedent_id=precedent.precedent_id,
            interpreted_source_id=interpreted_source.source_id,
            as_of_date=as_of_date,
            precedent_applicable_to_statute=True,
            effective_outcome=(
                "ESCALATE_TO_LEGAL_COUNSEL" if needs_esc else "UNDERLYING_STATUTE_WITH_PRECEDENT_PREVAILS"
            ),
            binding_nature=binding_nature,
            binding_basis=binding_basis,
            scope_match_status=scope_match_status,
            application_rationale=clean_rationale,
            rationale_requirement_status=rationale_status,
            underlying_norm_resolution=underlying_res,
            requires_counsel_escalation=needs_esc,
            explanation=(
                f"Dayanak '{interpreted_source.legal_reference}' hükmü ile '{competing_norm.title}' "
                f"({competing_norm.norm_layer}) karşılaştırmasında ({underlying_res.rule_applied}) üst norm olan "
                f"dayanak kanun, '{precedent.precedent_id}' ({binding_nature}; gerekçe={rationale_status}) yorumu doğrultusunda esas alınır.{ctx_suffix}"
            ),
        )

    return PrecedentApplicationAssessment(
        precedent_id=precedent.precedent_id,
        interpreted_source_id=interpreted_source.source_id,
        as_of_date=as_of_date,
        precedent_applicable_to_statute=True,
        effective_outcome="ESCALATE_TO_LEGAL_COUNSEL",
        binding_nature=binding_nature,
        binding_basis=binding_basis,
        scope_match_status=scope_match_status,
        application_rationale=clean_rationale,
        rationale_requirement_status=rationale_status,
        underlying_norm_resolution=underlying_res,
        requires_counsel_escalation=True,
        explanation=(
            f"Dayanak '{interpreted_source.legal_reference}' ile '{competing_norm.title}' arasındaki çatışma "
            f"otomatik çözülemedi ({underlying_res.rule_applied}); şirket avukatına eskalasyon gerekir.{ctx_suffix}"
        ),
    )
