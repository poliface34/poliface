"""Autonomous Norm Layers (L5 Corporate HR Procedures & L6 CBA / Contracts / Internal Regs / Workplace Practices) for hrAI @HukukSGK v1.0.5.1.

Strict Legal & Architectural Boundaries (Karar 2):
  1. L5 & L6 are strictly separated from the official L1-L4 statutory/judicial verification core (74/74).
  2. NO single flat `priority: 8` supremacy rule is used across L5/L6. Every rule MUST declare all 7 fields:
       - `norm_type`
       - `legal_basis_ids`
       - `source_document_id`
       - `adoption_status`
       - `employee_favorable_check`
       - `conflict_resolution`
       - `human_review_required`
  3. Reference templates (`REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION`) are NEVER presented or enforced
     as binding active company policy (`binding_company_policy=False`, `human_review_required=True`).
  4. Collective Bargaining Agreements (TİS, Law 6356 m.36), Individual Employment Contracts, Workplace
     Internal Regulations, Corporate HR Procedures, and Established Workplace Practices are NEVER
     collapsed into each other.
  5. Employee-favorability evaluation strictly respects the statutory floor nature of each rule:
       - `ABSOLUTE_MANDATORY`: cannot be altered even in favor of the employee (`STATUTORY_ABSOLUTE_PREVAILS`),
       - `RELATIVE_MANDATORY_FLOOR`: employee-favorable improvement permitted; derogation below floor invalid,
       - `SUPPLEMENTARY_DEFAULT`: lawful contractual / CBA / practice variation permitted within statutory limits.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
from typing import Any

from .models import LegalKnowledgeCard, LegalSourceRecord, PrecedentRecord

AUTONOMOUS_NORMS_VERSION = "1.0.5.1"

VALID_ADOPTION_STATUSES: frozenset[str] = frozenset(
    {
        "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION",
        "COMPANY_ADOPTED_PENDING_COUNSEL_REVIEW",
        "COMPANY_ADOPTED_COUNSEL_VERIFIED",
        "SUPERSEDED",
    }
)

VALID_NORM_TYPES: frozenset[str] = frozenset(
    {
        "STATUTORY_ABSOLUTE_MANDATORY",
        "STATUTORY_RELATIVE_MANDATORY",
        "STATUTORY_SUPPLEMENTARY",
        "COLLECTIVE_BARGAINING_AGREEMENT",
        "INDIVIDUAL_EMPLOYMENT_CONTRACT",
        "CORPORATE_HR_PROCEDURE",
        "WORKPLACE_INTERNAL_REGULATION",
        "ESTABLISHED_WORKPLACE_PRACTICE",
    }
)

VALID_STATUTORY_FLOOR_NATURES: frozenset[str] = frozenset(
    {
        "ABSOLUTE_MANDATORY",
        "RELATIVE_MANDATORY_FLOOR",
        "SUPPLEMENTARY_DEFAULT",
    }
)

REQUIRED_RULE_FIELDS: tuple[str, ...] = (
    "norm_type",
    "legal_basis_ids",
    "source_document_id",
    "adoption_status",
    "employee_favorable_check",
    "conflict_resolution",
    "human_review_required",
)

EXPECTED_L6_SOURCE_KINDS: frozenset[str] = frozenset(
    {
        "COLLECTIVE_BARGAINING_AGREEMENT",
        "INDIVIDUAL_EMPLOYMENT_CONTRACT",
        "WORKPLACE_INTERNAL_REGULATION",
        "ESTABLISHED_WORKPLACE_PRACTICE",
    }
)

_TOKEN_RE = re.compile(r"[a-zçğıöşü0-9]+", re.IGNORECASE)


def _tr_lower(text: str) -> str:
    return text.replace("İ", "i").replace("I", "ı").lower()


@dataclass(frozen=True)
class AutonomousNormRule:
    """Validated L5/L6 autonomous norm rule carrying all 7 mandatory legal-modeling fields."""

    rule_id: str
    layer_id: str
    module_id: str
    title: str
    rule_summary: str
    norm_type: str
    legal_basis_ids: tuple[str, ...]
    source_document_id: str
    adoption_status: str
    employee_favorable_check: dict[str, Any]
    conflict_resolution: dict[str, Any]
    human_review_required: bool
    autonomous_source_kind: str | None = None

    @property
    def is_binding_company_policy(self) -> bool:
        return self.adoption_status == "COMPANY_ADOPTED_COUNSEL_VERIFIED"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["legal_basis_ids"] = list(self.legal_basis_ids)
        d["is_binding_company_policy"] = self.is_binding_company_policy
        return d


@dataclass(frozen=True)
class AutonomousNormModule:
    """Validated L5 Corporate HR Procedure or L6 Autonomous Norm module."""

    layer_id: str
    module_id: str
    source_document_id: str
    title: str
    scope_summary: str
    adoption_status: str
    template_only_not_binding_company_policy: bool
    no_flat_priority_supremacy: bool
    primary_statutory_basis_ids: tuple[str, ...]
    rules: tuple[AutonomousNormRule, ...]
    file_path: str
    autonomous_source_kind: str | None = None
    disclaimer: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer_id": self.layer_id,
            "module_id": self.module_id,
            "source_document_id": self.source_document_id,
            "autonomous_source_kind": self.autonomous_source_kind,
            "title": self.title,
            "scope_summary": self.scope_summary,
            "adoption_status": self.adoption_status,
            "template_only_not_binding_company_policy": self.template_only_not_binding_company_policy,
            "no_flat_priority_supremacy": self.no_flat_priority_supremacy,
            "primary_statutory_basis_ids": list(self.primary_statutory_basis_ids),
            "rules": [r.to_dict() for r in self.rules],
            "file_path": self.file_path,
            "disclaimer": self.disclaimer,
        }


@dataclass(frozen=True)
class AutonomousNormConflictDecision:
    """Deterministic conflict & employee-favorability verdict for L5/L6 autonomous norms."""

    permitted: bool
    outcome: str
    prevailing_norm: str
    binding_company_policy: bool
    human_review_required: bool
    statutory_floor_nature: str
    rule_norm_type: str
    competing_norm_type: str | None
    error_codes: tuple[str, ...]
    warnings: tuple[str, ...]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["error_codes"] = list(self.error_codes)
        d["warnings"] = list(self.warnings)
        return d


def _verified_anchor_ids(
    source_registry: dict[str, LegalSourceRecord],
    knowledge_cards: dict[str, LegalKnowledgeCard],
    precedent_registry: dict[str, PrecedentRecord] | None = None,
) -> set[str]:
    anchors: set[str] = set()
    for sid, src in source_registry.items():
        if getattr(src, "verification_status", None) == "VERIFIED":
            anchors.add(sid)
    for cid, card in knowledge_cards.items():
        if getattr(card, "verification_status", None) == "VERIFIED":
            anchors.add(cid)
    if precedent_registry:
        for pid, prec in precedent_registry.items():
            if getattr(prec, "verification_status", None) == "VERIFIED":
                anchors.add(pid)
    return anchors


def _validate_and_parse_module(
    json_path: Path,
    *,
    expected_layer_id: str,
    verified_anchors: set[str],
    strict: bool = True,
) -> AutonomousNormModule:
    raw = json.loads(json_path.read_text(encoding="utf-8"))
    errors: list[str] = []

    if not isinstance(raw, dict):
        raise ValueError(f"Özerk norm dosyası kök nesnesi geçersiz: {json_path.name}")
    if raw.get("layer_id") != expected_layer_id:
        errors.append(f"{json_path.name}: beklenen layer_id={expected_layer_id}, bulunan={raw.get('layer_id')!r}")
    if raw.get("product_brand") != "hrAI" or raw.get("coordinator_agent") != "@hrAI" or raw.get("specialist_agent") != "@HukukSGK":
        errors.append(f"{json_path.name}: hrAI/@hrAI/@HukukSGK marka alanları zorunludur.")
    if raw.get("no_flat_priority_supremacy") is not True:
        errors.append(f"{json_path.name}: no_flat_priority_supremacy=true zorunludur (tekil priority:8 yasağı).")

    adoption = str(raw.get("adoption_status") or "")
    if adoption not in VALID_ADOPTION_STATUSES:
        errors.append(f"{json_path.name}: geçersiz adoption_status={adoption!r}")
    tpl_only = bool(raw.get("template_only_not_binding_company_policy", False))
    if adoption == "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION" and not tpl_only:
        errors.append(f"{json_path.name}: kabul edilmemiş şablon için template_only_not_binding_company_policy=true zorunludur.")

    mod_id = str(raw.get("procedure_id") if expected_layer_id == "L5_HR_PROCEDURES" else raw.get("module_id") or "")
    src_doc_id = str(raw.get("source_document_id") or "")
    if not mod_id or not src_doc_id:
        errors.append(f"{json_path.name}: module_id/procedure_id ve source_document_id zorunludur.")

    src_kind = raw.get("autonomous_source_kind")
    if expected_layer_id == "L6_CBA_CONTRACTS_AND_WORKPLACE_PRACTICES":
        if src_kind not in EXPECTED_L6_SOURCE_KINDS:
            errors.append(f"{json_path.name}: geçersiz autonomous_source_kind={src_kind!r}")

    primary_ids = tuple(str(x) for x in (raw.get("primary_statutory_basis_ids") or ()) if str(x).strip())
    if not primary_ids:
        errors.append(f"{json_path.name}: primary_statutory_basis_ids boş olamaz.")
    for bid in primary_ids:
        if bid not in verified_anchors:
            errors.append(f"{json_path.name}: doğrulanmamış veya kayıtsız dayanak ID: '{bid}'")

    raw_rules = raw.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        errors.append(f"{json_path.name}: en az bir kural ('rules') zorunludur.")
        raw_rules = []

    parsed_rules: list[AutonomousNormRule] = []
    seen_rule_ids: set[str] = set()
    for r in raw_rules:
        if not isinstance(r, dict):
            errors.append(f"{json_path.name}: kural nesnesi sözlük olmalıdır.")
            continue
        rid = str(r.get("rule_id") or "")
        if not rid or rid in seen_rule_ids:
            errors.append(f"{json_path.name}: eksik veya mükerrer rule_id={rid!r}")
        seen_rule_ids.add(rid)

        for req_f in REQUIRED_RULE_FIELDS:
            if req_f not in r:
                errors.append(f"{json_path.name}/{rid}: zorunlu kural alanı eksik: '{req_f}'")

        ntype = str(r.get("norm_type") or "")
        if ntype not in VALID_NORM_TYPES:
            errors.append(f"{json_path.name}/{rid}: geçersiz norm_type={ntype!r}")

        r_adoption = str(r.get("adoption_status") or "")
        if r_adoption not in VALID_ADOPTION_STATUSES:
            errors.append(f"{json_path.name}/{rid}: geçersiz adoption_status={r_adoption!r}")

        human_rev = r.get("human_review_required")
        if not isinstance(human_rev, bool):
            errors.append(f"{json_path.name}/{rid}: human_review_required boolean olmalıdır.")
        elif r_adoption != "COMPANY_ADOPTED_COUNSEL_VERIFIED" and human_rev is not True:
            errors.append(f"{json_path.name}/{rid}: onaylanmamış şablon için human_review_required=true zorunludur.")

        basis_ids = tuple(str(x) for x in (r.get("legal_basis_ids") or ()) if str(x).strip())
        if not basis_ids:
            errors.append(f"{json_path.name}/{rid}: legal_basis_ids boş olamaz.")
        for bid in basis_ids:
            if bid not in verified_anchors:
                errors.append(f"{json_path.name}/{rid}: doğrulanmamış veya kayıtsız legal_basis_id='{bid}'")

        efc = r.get("employee_favorable_check")
        if not isinstance(efc, dict) or efc.get("statutory_floor_nature") not in VALID_STATUTORY_FLOOR_NATURES:
            errors.append(f"{json_path.name}/{rid}: geçersiz employee_favorable_check bloğu.")
        else:
            if efc["statutory_floor_nature"] == "ABSOLUTE_MANDATORY" and efc.get("can_derogate_against_employee") is True:
                errors.append(f"{json_path.name}/{rid}: ABSOLUTE_MANDATORY kuralda işçi aleyhine sapma izinli olamaz.")

        cr = r.get("conflict_resolution")
        if not isinstance(cr, dict) or not cr.get("strategy") or not cr.get("rationale"):
            errors.append(f"{json_path.name}/{rid}: geçersiz conflict_resolution bloğu.")

        parsed_rules.append(
            AutonomousNormRule(
                rule_id=rid,
                layer_id=expected_layer_id,
                module_id=mod_id,
                title=str(r.get("title") or ""),
                rule_summary=str(r.get("rule_summary") or ""),
                norm_type=ntype,
                legal_basis_ids=basis_ids,
                source_document_id=str(r.get("source_document_id") or src_doc_id),
                adoption_status=r_adoption,
                employee_favorable_check=dict(efc) if isinstance(efc, dict) else {},
                conflict_resolution=dict(cr) if isinstance(cr, dict) else {},
                human_review_required=bool(human_rev),
                autonomous_source_kind=str(src_kind) if src_kind else None,
            )
        )

    if strict and errors:
        raise ValueError("Özerk norm doğrulaması başarısız: " + " | ".join(errors))

    return AutonomousNormModule(
        layer_id=expected_layer_id,
        module_id=mod_id,
        source_document_id=src_doc_id,
        title=str(raw.get("title") or ""),
        scope_summary=str(raw.get("scope_summary") or ""),
        adoption_status=adoption,
        template_only_not_binding_company_policy=tpl_only,
        no_flat_priority_supremacy=bool(raw.get("no_flat_priority_supremacy", False)),
        primary_statutory_basis_ids=primary_ids,
        rules=tuple(parsed_rules),
        file_path=str(json_path),
        autonomous_source_kind=str(src_kind) if src_kind else None,
        disclaimer=str(raw.get("disclaimer") or ""),
    )


def load_l5_hr_procedures(
    kb_dir: str | Path,
    source_registry: dict[str, LegalSourceRecord],
    knowledge_cards: dict[str, LegalKnowledgeCard],
    precedent_registry: dict[str, PrecedentRecord] | None = None,
    *,
    strict: bool = True,
) -> dict[str, AutonomousNormModule]:
    """Load and validate all L5 Corporate HR Procedure modules from `rag_kb/05_ik_prosedurleri/`."""
    l5_dir = Path(kb_dir) / "05_ik_prosedurleri"
    anchors = _verified_anchor_ids(source_registry, knowledge_cards, precedent_registry)
    modules: dict[str, AutonomousNormModule] = {}
    if not l5_dir.is_dir():
        if strict:
            raise ValueError(f"L5 klasörü bulunamadı: {l5_dir}")
        return modules
    for jp in sorted(l5_dir.glob("*.json")):
        mod = _validate_and_parse_module(jp, expected_layer_id="L5_HR_PROCEDURES", verified_anchors=anchors, strict=strict)
        if strict and mod.module_id in modules:
            raise ValueError(f"Mükerrer L5 procedure_id: {mod.module_id}")
        modules[mod.module_id] = mod
    return modules


def load_l6_cba_contract_practices(
    kb_dir: str | Path,
    source_registry: dict[str, LegalSourceRecord],
    knowledge_cards: dict[str, LegalKnowledgeCard],
    precedent_registry: dict[str, PrecedentRecord] | None = None,
    *,
    strict: bool = True,
) -> dict[str, AutonomousNormModule]:
    """Load and validate all L6 CBA/Contract/Internal Regulation/Workplace Practice modules from `rag_kb/06_*`."""
    l6_dir = Path(kb_dir) / "06_tis_sozlesme_ve_isyeri_uygulamalari"
    anchors = _verified_anchor_ids(source_registry, knowledge_cards, precedent_registry)
    modules: dict[str, AutonomousNormModule] = {}
    if not l6_dir.is_dir():
        if strict:
            raise ValueError(f"L6 klasörü bulunamadı: {l6_dir}")
        return modules
    seen_kinds: set[str] = set()
    for jp in sorted(l6_dir.glob("*.json")):
        mod = _validate_and_parse_module(
            jp,
            expected_layer_id="L6_CBA_CONTRACTS_AND_WORKPLACE_PRACTICES",
            verified_anchors=anchors,
            strict=strict,
        )
        if strict and mod.module_id in modules:
            raise ValueError(f"Mükerrer L6 module_id: {mod.module_id}")
        modules[mod.module_id] = mod
        if mod.autonomous_source_kind:
            seen_kinds.add(mod.autonomous_source_kind)
    if strict and seen_kinds != EXPECTED_L6_SOURCE_KINDS:
        missing = sorted(EXPECTED_L6_SOURCE_KINDS - seen_kinds)
        raise ValueError(
            f"L6 modülleri TİS, bireysel sözleşme, iç yönetmelik ve işyeri uygulamasını ayrı içermelidir; eksik: {missing}"
        )
    return modules


def evaluate_autonomous_norm_conflict(
    rule: AutonomousNormRule | dict[str, Any],
    *,
    proposed_change_direction: str,
    competing_norm_type: str | None = None,
    statutory_floor_nature: str | None = None,
    cba_expressly_forbids_individual_improvement: bool = False,
    written_employee_consent_4857_m22: bool = False,
) -> AutonomousNormConflictDecision:
    """Deterministically evaluate L5/L6 autonomous norm conflicts & employee-favorability without flat `priority: 8`.

    Parameters:
      - `proposed_change_direction`:
          * `"EMPLOYEE_FAVORABLE"` — raises rights/protections above the floor,
          * `"BELOW_STATUTORY_FLOOR"` — attempts to weaken or bypass a statutory floor,
          * `"EMPLOYER_UNILATERAL_DOWNGRADE"` — unilateral employer reduction of an existing right/practice,
          * `"SUPPLEMENTARY_VARIATION"` — lawful arrangement in a supplementary (default) statutory space.
      - `competing_norm_type`: optional competing autonomous source (e.g., `"COLLECTIVE_BARGAINING_AGREEMENT"`,
        `"INDIVIDUAL_EMPLOYMENT_CONTRACT"`, `"WORKPLACE_INTERNAL_REGULATION"`, `"CORPORATE_HR_PROCEDURE"`,
        `"ESTABLISHED_WORKPLACE_PRACTICE"`).
    """
    if isinstance(rule, dict):
        r_norm_type = str(rule.get("norm_type") or "")
        r_adoption = str(rule.get("adoption_status") or "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION")
        efc = rule.get("employee_favorable_check") or {}
        r_human = bool(rule.get("human_review_required", True))
    else:
        r_norm_type = rule.norm_type
        r_adoption = rule.adoption_status
        efc = rule.employee_favorable_check
        r_human = rule.human_review_required

    floor_nature = str(statutory_floor_nature or efc.get("statutory_floor_nature") or "ABSOLUTE_MANDATORY").upper().strip()
    direction = str(proposed_change_direction or "").upper().strip()
    comp_norm = str(competing_norm_type).upper().strip() if competing_norm_type else None

    binding = r_adoption == "COMPANY_ADOPTED_COUNSEL_VERIFIED"
    errors: list[str] = []
    warnings: list[str] = []
    human_review = bool(r_human or not binding)

    if not binding:
        warnings.append(
            f"UNADOPTED_REFERENCE_TEMPLATE_NOT_ACTIVE_POLICY: Kayıt '{r_adoption}' durumundadır; "
            "şirket tarafından kabul edilip hukuk müşavirince onaylanmadan yürürlükteki şirket politikası gibi uygulanamaz."
        )

    # 1. Statutory ABSOLUTE MANDATORY floor — cannot be altered even in favor of employee (public order / statutory ceiling/form)
    if floor_nature == "ABSOLUTE_MANDATORY":
        if direction in ("BELOW_STATUTORY_FLOOR", "EMPLOYER_UNILATERAL_DOWNGRADE", "EMPLOYEE_FAVORABLE", "SUPPLEMENTARY_VARIATION"):
            # Exception: pure internal operational enhancement strictly above/compliant with KVKK/ISG without altering statutory rule
            if direction == "EMPLOYEE_FAVORABLE" and efc.get("applicable") is True and efc.get("can_improve_for_employee") is True:
                return AutonomousNormConflictDecision(
                    permitted=True,
                    outcome="PERMITTED_ADDITIONAL_SAFEGUARD_STATUTORY_FLOOR_PRESERVED",
                    prevailing_norm=r_norm_type,
                    binding_company_policy=binding,
                    human_review_required=True,
                    statutory_floor_nature=floor_nature,
                    rule_norm_type=r_norm_type,
                    competing_norm_type=comp_norm,
                    error_codes=(),
                    warnings=tuple(warnings),
                    rationale="Mutlak emredici yasal yükümlülük korunmak kaydıyla ek çalışan/veri güvencesi sağlanabilir; ancak kurum içi onay ve hukuk müşaviri incelemesi zorunludur.",
                )
            errors.append("ABSOLUTE_MANDATORY_CANNOT_BE_ALTERED")
            return AutonomousNormConflictDecision(
                permitted=False,
                outcome="REJECTED_STATUTORY_ABSOLUTE_PREVAILS",
                prevailing_norm="STATUTORY_ABSOLUTE_MANDATORY",
                binding_company_policy=binding,
                human_review_required=True,
                statutory_floor_nature=floor_nature,
                rule_norm_type=r_norm_type,
                competing_norm_type=comp_norm,
                error_codes=tuple(errors),
                warnings=tuple(warnings),
                rationale=(
                    "İlgili kanun hükmü mutlak emredicidir (ABSOLUTE_MANDATORY); ne TİS ne bireysel sözleşme "
                    "ne de kurumsal İK prosedürü bu yasal kuralı işçi lehine veya aleyhine bertaraf edemez."
                ),
            )

    # 2. Statutory RELATIVE MANDATORY floor — derogation below floor is ALWAYS invalid!
    if floor_nature == "RELATIVE_MANDATORY_FLOOR" and direction == "BELOW_STATUTORY_FLOOR":
        errors.append("DEROGATION_BELOW_STATUTORY_FLOOR_INVALID")
        return AutonomousNormConflictDecision(
            permitted=False,
            outcome="REJECTED_DEROGATION_BELOW_STATUTORY_FLOOR",
            prevailing_norm="STATUTORY_RELATIVE_MANDATORY",
            binding_company_policy=binding,
            human_review_required=True,
            statutory_floor_nature=floor_nature,
            rule_norm_type=r_norm_type,
            competing_norm_type=comp_norm,
            error_codes=tuple(errors),
            warnings=tuple(warnings),
            rationale="Nispi emredici kanuni asgari tabanın altına inen L5/L6 düzenlemesi geçersizdir; kanuni taban uygulanır.",
        )

    # 3. Non-reducible inter-autonomous norm conflict rules (NEVER flat priority: 8!)
    # 3a. Collective Bargaining Agreement (TİS — 6356 m.36) vs Individual Employment Contract
    if {r_norm_type, comp_norm} == {"COLLECTIVE_BARGAINING_AGREEMENT", "INDIVIDUAL_EMPLOYMENT_CONTRACT"}:
        if direction == "EMPLOYEE_FAVORABLE" and comp_norm == "INDIVIDUAL_EMPLOYMENT_CONTRACT":
            if cba_expressly_forbids_individual_improvement:
                errors.append("CBA_EXPRESSLY_FORBIDS_INDIVIDUAL_DEVIATION_6356_M36")
                return AutonomousNormConflictDecision(
                    permitted=False,
                    outcome="CBA_PREVAILS_EXPRESS_PROHIBITION_6356_M36",
                    prevailing_norm="COLLECTIVE_BARGAINING_AGREEMENT",
                    binding_company_policy=binding,
                    human_review_required=True,
                    statutory_floor_nature=floor_nature,
                    rule_norm_type=r_norm_type,
                    competing_norm_type=comp_norm,
                    error_codes=tuple(errors),
                    warnings=tuple(warnings),
                    rationale="6356 m.36 uyarınca TİS bireysel sözleşmeyle işçi lehine dahi olsa sapmayı açıkça yasakladığında TİS hükmü uygulanır.",
                )
            return AutonomousNormConflictDecision(
                permitted=True,
                outcome="INDIVIDUAL_CONTRACT_MORE_FAVORABLE_PREVAILS_6356_M36",
                prevailing_norm="INDIVIDUAL_EMPLOYMENT_CONTRACT",
                binding_company_policy=binding,
                human_review_required=True,
                statutory_floor_nature=floor_nature,
                rule_norm_type=r_norm_type,
                competing_norm_type=comp_norm,
                error_codes=(),
                warnings=tuple(warnings),
                rationale="6356 m.36/1 uyarınca TİS açıkça yasaklamadığı sürece bireysel iş sözleşmesindeki TİS'ten daha işçi lehine hüküm geçerlidir.",
            )
        # Individual contract less favorable than TİS -> TİS directly replaces it (6356 m.36)!
        errors.append("CBA_OVERRIDES_LESS_FAVORABLE_INDIVIDUAL_CONTRACT_6356_M36")
        return AutonomousNormConflictDecision(
            permitted=False,
            outcome="CBA_DIRECTLY_REPLACES_LESS_FAVORABLE_CONTRACT_6356_M36",
            prevailing_norm="COLLECTIVE_BARGAINING_AGREEMENT",
            binding_company_policy=binding,
            human_review_required=True,
            statutory_floor_nature=floor_nature,
            rule_norm_type=r_norm_type,
            competing_norm_type=comp_norm,
            error_codes=tuple(errors),
            warnings=tuple(warnings),
            rationale="6356 m.36 uyarınca TİS'e aykırı ve işçi aleyhine olan bireysel iş sözleşmesi hükmünün yerini doğrudan TİS hükmü alır.",
        )

    # 3b. Unilateral employer downgrade via HR Procedure / Internal Regulation against Established Workplace Practice or Contract
    if direction == "EMPLOYER_UNILATERAL_DOWNGRADE":
        if not written_employee_consent_4857_m22:
            errors.append("ESSENTIAL_CHANGE_4857_M22_WRITTEN_CONSENT_REQUIRED")
            return AutonomousNormConflictDecision(
                permitted=False,
                outcome="REJECTED_UNILATERAL_DOWNGRADE_4857_M22",
                prevailing_norm=r_norm_type,
                binding_company_policy=binding,
                human_review_required=True,
                statutory_floor_nature=floor_nature,
                rule_norm_type=r_norm_type,
                competing_norm_type=comp_norm,
                error_codes=tuple(errors),
                warnings=tuple(warnings),
                rationale=(
                    "4857 m.22 uyarınca yerleşik işyeri uygulaması, bireysel sözleşme veya sözleşme eki iç yönetmelikteki "
                    "çalışma koşulları işverenin tek taraflı İK prosedürüyle işçi aleyhine daraltılamaz; yazılı bildirim ve "
                    "6 iş günü içinde işçinin yazılı kabulü zorunludur."
                ),
            )
        return AutonomousNormConflictDecision(
            permitted=True,
            outcome="PERMITTED_WITH_4857_M22_WRITTEN_CONSENT_AND_COUNSEL_REVIEW",
            prevailing_norm=comp_norm or r_norm_type,
            binding_company_policy=binding,
            human_review_required=True,
            statutory_floor_nature=floor_nature,
            rule_norm_type=r_norm_type,
            competing_norm_type=comp_norm,
            error_codes=(),
            warnings=tuple(warnings),
            rationale="4857 m.22 yazılı rıza beyan edilmiş olmakla birlikte kanuni taban, TİS ve muvazaa/baskı denetimi için hukuk müşaviri incelemesi zorunludur.",
        )

    # 4. Employee-favorable improvement on RELATIVE_MANDATORY_FLOOR or SUPPLEMENTARY_DEFAULT
    if direction == "EMPLOYEE_FAVORABLE" and floor_nature in ("RELATIVE_MANDATORY_FLOOR", "SUPPLEMENTARY_DEFAULT"):
        return AutonomousNormConflictDecision(
            permitted=True,
            outcome="PERMITTED_EMPLOYEE_FAVORABLE_ABOVE_FLOOR",
            prevailing_norm=comp_norm or r_norm_type,
            binding_company_policy=binding,
            human_review_required=human_review,
            statutory_floor_nature=floor_nature,
            rule_norm_type=r_norm_type,
            competing_norm_type=comp_norm,
            error_codes=(),
            warnings=tuple(warnings),
            rationale=(
                f"{floor_nature} niteliğindeki hükümde kanuni asgari tabanın üzerinde işçi lehine düzenleme geçerlidir."
            ),
        )

    # 5. Lawful variation in SUPPLEMENTARY_DEFAULT space (recognizing not every statute is immutable!)
    if direction == "SUPPLEMENTARY_VARIATION" and floor_nature == "SUPPLEMENTARY_DEFAULT":
        return AutonomousNormConflictDecision(
            permitted=True,
            outcome="PERMITTED_SUPPLEMENTARY_VARIATION_WITHIN_STATUTORY_LIMITS",
            prevailing_norm=comp_norm or r_norm_type,
            binding_company_policy=binding,
            human_review_required=human_review,
            statutory_floor_nature=floor_nature,
            rule_norm_type=r_norm_type,
            competing_norm_type=comp_norm,
            error_codes=(),
            warnings=tuple(warnings),
            rationale=(
                "İlgili kanun hükmü tamamlayıcı (SUPPLEMENTARY_DEFAULT) nitelikte olduğundan, emredici tabanlara ve "
                "varsa TİS sınırlarına aykırı olmamak kaydıyla sözleşme veya işyeri uygulamasıyla farklı düzenleme yapılabilir."
            ),
        )

    # Default fail-closed escalation
    errors.append("AUTONOMOUS_NORM_CONFLICT_REQUIRES_COUNSEL_REVIEW")
    return AutonomousNormConflictDecision(
        permitted=False,
        outcome="ESCALATE_TO_LEGAL_COUNSEL",
        prevailing_norm="LEGAL_COUNSEL_REVIEW_REQUIRED",
        binding_company_policy=binding,
        human_review_required=True,
        statutory_floor_nature=floor_nature,
        rule_norm_type=r_norm_type,
        competing_norm_type=comp_norm,
        error_codes=tuple(errors),
        warnings=tuple(warnings),
        rationale="Norm çatışması veya emredicilik niteliği otomatik kesin hükme bağlanamadı; hukuk müşaviri incelemesi zorunludur.",
    )


def lookup_autonomous_norm_guidance(
    query: str,
    l5_modules: dict[str, AutonomousNormModule],
    l6_modules: dict[str, AutonomousNormModule],
    *,
    layer: str | None = None,
    norm_type: str | None = None,
    top_k: int = 5,
) -> dict[str, Any]:
    """Search L5 & L6 autonomous norm templates with mandatory non-adoption & counsel-review guardrails."""
    q_tokens = {t for t in _TOKEN_RE.findall(_tr_lower(str(query or ""))) if len(t) >= 2}
    layer_filter = str(layer).upper().strip() if layer else None
    nt_filter = str(norm_type).upper().strip() if norm_type else None

    pool: list[AutonomousNormModule] = []
    if layer_filter in (None, "ALL", "L5", "L5_HR_PROCEDURES"):
        pool.extend(l5_modules.values())
    if layer_filter in (None, "ALL", "L6", "L6_CBA_CONTRACTS_AND_WORKPLACE_PRACTICES"):
        pool.extend(l6_modules.values())

    scored: list[tuple[int, AutonomousNormRule, AutonomousNormModule]] = []
    for mod in pool:
        for rule in mod.rules:
            if nt_filter and rule.norm_type != nt_filter:
                continue
            haystack = _tr_lower(
                " ".join(
                    [
                        mod.title,
                        mod.scope_summary,
                        rule.rule_id,
                        rule.title,
                        rule.rule_summary,
                        rule.norm_type,
                        " ".join(rule.legal_basis_ids),
                    ]
                )
            )
            score = sum(1 for tok in q_tokens if tok in haystack) if q_tokens else 1
            if score > 0:
                scored.append((score, rule, mod))

    scored.sort(key=lambda item: (-item[0], item[1].rule_id))
    matches = [
        {
            "score": sc,
            "layer_id": r.layer_id,
            "module_id": r.module_id,
            "module_title": m.title,
            "autonomous_source_kind": r.autonomous_source_kind,
            "rule": r.to_dict(),
            "template_only_notice": (
                "REFERANS ŞABLON — KURUM KABULÜ BEKLİYOR: Bu kural yürürlükteki şirket politikası/TİS yerine geçmez."
                if not r.is_binding_company_policy
                else None
            ),
        }
        for sc, r, m in scored[: max(1, int(top_k))]
    ]
    return {
        "product_brand": "hrAI",
        "coordinator_agent": "@hrAI",
        "specialist_agent": "@HukukSGK",
        "product_website": "https://www.insenai.com.tr",
        "schema_version": AUTONOMOUS_NORMS_VERSION,
        "query": query,
        "l5_module_count": len(l5_modules),
        "l6_module_count": len(l6_modules),
        "match_count": len(matches),
        "all_builtin_templates_pending_company_adoption": all(
            not m["rule"]["is_binding_company_policy"] for m in matches
        ),
        "matches": matches,
    }


def validate_autonomous_norms_audit_log(
    audit_data: dict[str, Any],
    l5_modules: dict[str, AutonomousNormModule],
    l6_modules: dict[str, AutonomousNormModule],
) -> dict[str, Any]:
    """Independently validate `config/autonomous_norms_audit_log.json` against loaded L5 (5) & L6 (4) modules."""
    errors: list[str] = []
    if not isinstance(audit_data, dict):
        return {"valid": False, "errors": ["Özerk norm denetim defteri JSON nesnesi olmalıdır."]}
    if audit_data.get("product_brand") != "hrAI" or audit_data.get("schema_version") != AUTONOMOUS_NORMS_VERSION:
        errors.append("Özerk norm denetim defteri hrAI v1.0.5.1 marka/sürüm başlığı taşımalıdır.")
    if audit_data.get("l1_l4_official_core_untouched") is not True:
        errors.append("l1_l4_official_core_untouched=true zorunludur.")

    entries = audit_data.get("entries")
    if not isinstance(entries, list):
        errors.append("entries alanı liste olmalıdır.")
        entries = []

    by_mod = {str(e.get("module_id") or ""): e for e in entries if isinstance(e, dict)}
    all_mods = {**l5_modules, **l6_modules}

    if len(l5_modules) != 5:
        errors.append(f"L5 modül sayısı 5 olmalıdır (bulunan: {len(l5_modules)}).")
    if len(l6_modules) != 4:
        errors.append(f"L6 modül sayısı 4 olmalıdır (bulunan: {len(l6_modules)}).")

    for mid, mod in all_mods.items():
        ent = by_mod.get(mid)
        if ent is None:
            errors.append(f"Denetim defterinde eksik modül kaydı: '{mid}'")
            continue
        if ent.get("layer_id") != mod.layer_id:
            errors.append(f"Modül '{mid}' layer_id uyuşmuyor.")
        if ent.get("source_document_id") != mod.source_document_id:
            errors.append(f"Modül '{mid}' source_document_id uyuşmuyor.")
        if ent.get("adoption_status") != mod.adoption_status:
            errors.append(f"Modül '{mid}' adoption_status uyuşmuyor.")
        if int(ent.get("rule_count", -1)) != len(mod.rules):
            errors.append(f"Modül '{mid}' rule_count uyuşmuyor.")
        if ent.get("adoption_status") == "REFERENCE_TEMPLATE_PENDING_COMPANY_ADOPTION":
            if ent.get("template_only_not_binding_company_policy") is not True:
                errors.append(f"Modül '{mid}' için template_only_not_binding_company_policy=true zorunludur.")

    extra = sorted(set(by_mod) - set(all_mods))
    if extra:
        errors.append(f"Denetim defterinde eşleşmeyen fazla modül kayıtları: {extra}")

    summary = audit_data.get("summary") or {}
    total_rules = sum(len(m.rules) for m in all_mods.values())
    if summary.get("l5_module_count") != len(l5_modules):
        errors.append("summary.l5_module_count uyuşmuyor.")
    if summary.get("l6_module_count") != len(l6_modules):
        errors.append("summary.l6_module_count uyuşmuyor.")
    if summary.get("total_autonomous_modules") != len(all_mods):
        errors.append("summary.total_autonomous_modules uyuşmuyor.")
    if summary.get("total_autonomous_rules") != total_rules:
        errors.append("summary.total_autonomous_rules uyuşmuyor.")
    if summary.get("company_adopted_binding_count") != 0:
        errors.append("Yerleşik referans şablonlar için company_adopted_binding_count 0 olmalıdır.")

    return {
        "valid": len(errors) == 0,
        "l5_module_count": len(l5_modules),
        "l6_module_count": len(l6_modules),
        "total_autonomous_modules": len(all_mods),
        "total_autonomous_rules": total_rules,
        "errors": errors,
    }
